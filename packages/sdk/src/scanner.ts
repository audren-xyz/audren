/**
 * Indexer-free ordinary Solana RPC (`getMultipleAccounts`) 2-pass sync & historical witness
 * reconstruction with privacy-preserving defaults (`privacyMode: 'strict'`):
 *
 *   1. `SubtreeRootPage` fast sync (`126 KB` / 1M notes vs `32.3 MB` of sealed `SubtreePage`s).
 *   2. Default `'strict'` mode fetches full `10,240 B` `MemoPage`s in uniform 100-account batches
 *      (never revealing view-tag hits via `dataSlice` -> single-page re-fetch), fetches
 *      `SubtreePage`s covering newly synced leaves uniformly on incremental syncs (`<= 25` pages /
 *      `<= 25` subtrees), and uses deterministic wallet-keyed decoy selection
 *      (`SHA256(viewSk || "audren/v1/decoy" || epochBucket)`) with a fixed uniform batch count
 *      independent of hit count on large catch-ups (`> 25` pages) so repeated syncs cannot be
 *      intersected.
 *   3. Opt-in `'fast'` mode (for bandwidth-constrained cold recovery over self-hosted/trusted RPCs)
 *      uses `MemoPage` SoA `dataSlice` (`[0..3,328]`) on large catch-ups (`> 25` pages), while
 *      still fetching full `MemoPage`s directly on small incremental syncs (`<= 25` pages).
 *   4. Optional `birthdaySlot` binary search on `64 B` page headers (`closedSlot < birthdaySlot`).
 *   5. `reconstructWitness()` decoy-pads `SubtreePage` fetches across active lanes up to
 *      `min(16, totalSubtrees)` and shuffles them so spending never issues a pinpoint single-page
 *      fetch.
 *
 * Pass 1 ingests tree subroots, memos, and frontier leaves across ALL active lanes first so every
 * owned note is present in `store.notes`. Pass 2 ALWAYS executes unconditionally on every sync
 * (even after a transient Pass 1D `SubtreePage` miss — preventing a Pass 1D -> Pass 2 drop oracle),
 * streaming ALL new `NullifierPage`s up to `laneHdr.nfCount` in uniform 100-account batches
 * (zero early-exit when 0 unspent notes exist or after the last unspent note is spent), matching
 * against an `O(owned_unspent_notes)` map and discarding stranger prefixes immediately.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import {
  AUDREN_PROGRAM_ID,
  MEMO_NOTES_PER_PAGE,
  MEMO_PAGE_HEADER_LEN,
  MEMO_PAGE_LEN,
  MEMO_PAGE_SCAN_SLICE_LEN,
  NF_PAGE_HEADER_LEN,
  NF_PER_PAGE,
  NUM_LANES,
  SUBROOTS_PER_PAGE,
  SUBTREE_LEAVES,
} from './constants.ts';
import { checkMemoViewTag, tryDecryptAndVerifyMemoEntry } from './crypto.ts';
import type { FullViewingKey } from './keys.ts';
import {
  decodeLaneHeader,
  decodeMemoPage,
  decodeMemoPageHeader,
  decodeMemoPageScanSlice,
  decodeNullifierPageHeader,
  decodePoolState,
  decodeRootCheckpoint,
  decodeSubtreePage,
  decodeSubtreeRootPage,
  type DecodedLaneHeader,
  type DecodedMemoPage,
  type DecodedPoolState,
  type DecodedRootCheckpoint,
} from './layout.ts';
import {
  deriveCheckpointPdaSync,
  deriveLanePdaSync,
  deriveMemoPdaSync,
  deriveNfPagePdaSync,
  derivePoolPdaSync,
  deriveSubrootPdaSync,
  deriveSubtreePdaSync,
} from './pda.ts';
import { computeSubtree256Root, frFromBeBytesStrict, frToBeBytes } from './poseidon.ts';
import {
  buildHistoricalWitness4Ary,
  type CompactWalletStore,
  type MerklePath4Ary,
} from './store.ts';

const RPC_BATCH_CHUNK = 100;
const utf8Encoder = new TextEncoder();
const DECOY_DOMAIN_BYTES = utf8Encoder.encode('audren/v1/decoy');

/** Maximum new `MemoPage`s fetched as an incremental sync (`<= ~256 KB`). */
export const INCREMENTAL_FULL_MEMO_PAGE_THRESHOLD = 25;
/** Maximum newly synced `SubtreePage`s fetched uniformly on incremental sync in `'strict'` mode. */
export const INCREMENTAL_UNIFORM_SUBTREE_THRESHOLD = 25;
/** Minimum sealed `SubtreePage` anonymity set size when decoy-padding in `'strict'` mode. */
export const STRICT_DECOY_SEALED_SUBTREE_TARGET = 16;

export type SyncPrivacyMode = 'strict' | 'fast';

function randomUniformInt(bound: number): number {
  if (!Number.isInteger(bound) || bound <= 0) {
    throw new RangeError(`bound must be a positive integer, got ${bound}`);
  }
  if (bound === 1) return 0;
  const maxUnbiased = Math.floor(0x1_0000_0000 / bound) * bound;
  const buf = new Uint32Array(1);
  for (;;) {
    globalThis.crypto.getRandomValues(buf);
    const v = buf[0]!;
    if (v < maxUnbiased) return v % bound;
  }
}

function randomUniformBigInt(bound: bigint): bigint {
  if (bound <= 0n) throw new RangeError(`bound must be positive, got ${bound}`);
  if (bound === 1n) return 0n;
  if (bound <= 0x1_0000_0000n) return BigInt(randomUniformInt(Number(bound)));
  const maxU64Plus1 = 1n << 64n;
  const maxUnbiased = (maxU64Plus1 / bound) * bound;
  const buf = new Uint32Array(2);
  for (;;) {
    globalThis.crypto.getRandomValues(buf);
    const v = (BigInt(buf[0]!) << 32n) | BigInt(buf[1]!);
    if (v < maxUnbiased) return v % bound;
  }
}

/**
 * Derive a deterministic wallet-keyed decoy index in `0..<bound` from
 * `SHA256(viewSk || "audren/v1/decoy" || epochBucket_le8 || counter_le4)`.
 * Ensures repeated syncs within the same epoch bucket request the exact same decoy set
 * (eliminating multi-sync set-intersection attacks).
 */
function deterministicDecoyIndex(
  viewSk: Uint8Array,
  epochBucket: bigint,
  counter: number,
  bound: bigint,
): bigint {
  const input = new Uint8Array(32 + DECOY_DOMAIN_BYTES.byteLength + 8 + 4);
  input.set(viewSk, 0);
  input.set(DECOY_DOMAIN_BYTES, 32);
  const dv = new DataView(input.buffer);
  dv.setBigUint64(32 + DECOY_DOMAIN_BYTES.byteLength, epochBucket, true);
  dv.setUint32(32 + DECOY_DOMAIN_BYTES.byteLength + 8, counter >>> 0, true);
  const digest = sha256(input);
  const val = new DataView(digest.buffer, digest.byteOffset, digest.byteLength).getBigUint64(0, true);
  return val % bound;
}

function shuffleInPlace<T>(items: T[]): void {
  for (let i = items.length - 1; i > 0; i--) {
    const j = randomUniformInt(i + 1);
    const tmp = items[i]!;
    items[i] = items[j]!;
    items[j] = tmp;
  }
}

export interface AccountBatchFetchOptions {
  dataSlice?: { offset: number; length: number };
}

export type AccountBatchFetcher = (
  addresses: readonly string[],
  options?: AccountBatchFetchOptions,
) => Promise<(Uint8Array | null)[]>;

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Ordinary Solana JSON-RPC `getMultipleAccounts` batch fetcher (chunks by 100 accounts, supports `dataSlice`). */
export function createSolanaRpcBatchFetcher(
  rpcUrl: string,
  commitment: 'confirmed' | 'finalized' = 'confirmed',
): AccountBatchFetcher {
  return async (addresses: readonly string[], options?: AccountBatchFetchOptions) => {
    const out: (Uint8Array | null)[] = new Array(addresses.length).fill(null);
    const rpcCfg: Record<string, unknown> = { encoding: 'base64', commitment };
    if (options?.dataSlice) {
      rpcCfg.dataSlice = {
        offset: options.dataSlice.offset,
        length: options.dataSlice.length,
      };
    }
    for (let off = 0; off < addresses.length; off += RPC_BATCH_CHUNK) {
      const chunk = addresses.slice(off, off + RPC_BATCH_CHUNK);
      const res = await fetch(rpcUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'getMultipleAccounts',
          params: [chunk, rpcCfg],
        }),
      });
      if (!res.ok) throw new Error(`Solana RPC getMultipleAccounts HTTP ${res.status}`);
      const json = (await res.json()) as {
        result?: { value: Array<{ data: [string, string] } | null> };
        error?: { message?: string };
      };
      if (json.error) throw new Error(`Solana RPC error: ${json.error.message ?? 'unknown'}`);
      const values = json.result?.value ?? [];
      for (let i = 0; i < chunk.length; i++) {
        const acc = values[i];
        out[off + i] = acc?.data?.[0] ? base64ToBytes(acc.data[0]) : null;
      }
    }
    return out;
  };
}

/** Fetch `PoolState` + all active `LaneTreeState` headers in 2 batched RPC calls. */
export async function fetchPoolAndLanes(
  fetchBatch: AccountBatchFetcher,
  poolId = 0,
  programId = AUDREN_PROGRAM_ID,
): Promise<{ pool: DecodedPoolState; lanes: DecodedLaneHeader[] }> {
  const poolPda = derivePoolPdaSync(poolId, programId).address;
  const [poolRaw] = await fetchBatch([poolPda]);
  if (!poolRaw) throw new Error(`PoolState account missing at ${poolPda}`);
  const pool = decodePoolState(poolRaw);

  const lanePdas: string[] = [];
  for (let l = 0; l < pool.activeLanes; l++) {
    lanePdas.push(deriveLanePdaSync(poolId, l, programId).address);
  }
  const laneRaws = await fetchBatch(lanePdas);
  const lanes = laneRaws.map((raw, l) => {
    if (!raw) throw new Error(`LaneTreeState #${l} missing`);
    return decodeLaneHeader(raw);
  });
  return { pool, lanes };
}

interface MemoHitCandidate {
  laneId: number;
  memoSeq: bigint;
  slot: number;
  leafIdx: bigint;
}

/**
 * Incrementally sync `CompactWalletStore` across all active lanes via ordinary `getMultipleAccounts`
 * calls using 2-pass sync (`SubtreeRootPage` fast sync + privacy-first `'strict'` full-`MemoPage`
 * batches & deterministic wallet-keyed decoy-padded `SubtreePage` fetches, or explicit opt-in
 * `'fast'` SoA `dataSlice` on `> 25` pages + optional `birthdaySlot` header binary search +
 * unconditional zero-early-exit `NullifierPage` streaming).
 */
export async function syncCompactStoreWithRpc(params: {
  store: CompactWalletStore;
  fvk: FullViewingKey;
  fetchBatch: AccountBatchFetcher;
  programId?: string;
  birthdaySlot?: bigint | number;
  latestCheckpoint?: DecodedRootCheckpoint;
  privacyMode?: SyncPrivacyMode;
  decoyEpochBucket?: bigint;
}): Promise<{ pool: DecodedPoolState; lanes: DecodedLaneHeader[]; discoveredNotes: number }> {
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const poolId = params.store.poolId;
  const privacyMode: SyncPrivacyMode = params.privacyMode ?? 'strict';
  const birthdaySlot =
    params.birthdaySlot !== undefined ? BigInt(params.birthdaySlot) : params.store.birthdaySlot;
  const { pool, lanes } = await fetchPoolAndLanes(params.fetchBatch, poolId, programId);

  const subSize = BigInt(SUBTREE_LEAVES);
  const srSize = BigInt(SUBROOTS_PER_PAGE);
  const memoSize = BigInt(MEMO_NOTES_PER_PAGE);
  const nfSize = BigInt(NF_PER_PAGE);

  // =========================================================================
  // PASS 1A: Fast-sync finalized level-4 subroots via `SubtreeRootPage`
  // =========================================================================
  const srRequests: Array<{ laneId: number; rootPageSeq: bigint; finalizedCount: bigint; addr: string }> = [];
  for (const laneHdr of lanes) {
    const l = laneHdr.laneId;
    const laneState = params.store.lanes[l]!;
    const finalizedCount = laneHdr.nextLeaf / subSize;
    if (finalizedCount > BigInt(laneState.finalizedSubroots.length)) {
      const startSr = BigInt(laneState.finalizedSubroots.length) / srSize;
      const endSr = (finalizedCount - 1n) / srSize;
      for (let rp = startSr; rp <= endSr; rp++) {
        srRequests.push({
          laneId: l,
          rootPageSeq: rp,
          finalizedCount,
          addr: deriveSubrootPdaSync(poolId, l, rp, programId).address,
        });
      }
    }
  }

  const fallbackSubtreeSeqs = new Map<number, Set<bigint>>();
  for (let off = 0; off < srRequests.length; off += RPC_BATCH_CHUNK) {
    const chunk = srRequests.slice(off, off + RPC_BATCH_CHUNK);
    const raws = await params.fetchBatch(chunk.map((r) => r.addr));
    for (let i = 0; i < chunk.length; i++) {
      const req = chunk[i]!;
      const raw = raws[i];
      if (raw) {
        params.store.ingestSubrootPages({
          laneId: req.laneId,
          subrootPages: [{ rootPageSeq: req.rootPageSeq, raw }],
          finalizedCount: req.finalizedCount,
        });
      } else {
        // Fallback for mocks that omit SubtreeRootPage: derive finalized subroots from SubtreePage.
        let set = fallbackSubtreeSeqs.get(req.laneId);
        if (!set) {
          set = new Set<bigint>();
          fallbackSubtreeSeqs.set(req.laneId, set);
        }
        const base = req.rootPageSeq * srSize;
        const end = base + srSize < req.finalizedCount ? base + srSize : req.finalizedCount;
        for (let s = base; s < end; s++) set.add(s);
      }
    }
  }

  // =========================================================================
  // PASS 1B: Optional `birthdaySlot` binary search on `64 B` `MemoPage` headers
  // =========================================================================
  if (birthdaySlot > 0n) {
    const bsStates: Array<{ laneId: number; nextLeaf: bigint; lo: bigint; hi: bigint }> = [];
    for (const laneHdr of lanes) {
      const l = laneHdr.laneId;
      const laneState = params.store.lanes[l]!;
      if (laneHdr.nextLeaf > 0n && laneState.nextMemoLeaf === 0n) {
        const targetMemoMax = (laneHdr.nextLeaf - 1n) / memoSize;
        if (targetMemoMax > 2n) {
          bsStates.push({ laneId: l, nextLeaf: laneHdr.nextLeaf, lo: 0n, hi: targetMemoMax + 1n });
        }
      }
    }
    while (bsStates.some((s) => s.lo < s.hi)) {
      const active = bsStates.filter((s) => s.lo < s.hi);
      const mids = active.map((s) => (s.lo + s.hi) >> 1n);
      const addrs = active.map(
        (s, i) => deriveMemoPdaSync(poolId, s.laneId, mids[i]!, programId).address,
      );
      const raws = await params.fetchBatch(addrs, {
        dataSlice: { offset: 0, length: MEMO_PAGE_HEADER_LEN },
      });
      for (let i = 0; i < active.length; i++) {
        const st = active[i]!;
        const mid = mids[i]!;
        const raw = raws[i];
        if (raw && raw.byteLength >= MEMO_PAGE_HEADER_LEN) {
          const hdr = decodeMemoPageHeader(raw);
          if (hdr.count === MEMO_NOTES_PER_PAGE && hdr.closedSlot > 0n && hdr.closedSlot < birthdaySlot) {
            st.lo = mid + 1n;
          } else {
            st.hi = mid;
          }
        } else {
          st.hi = mid;
        }
      }
    }
    for (const st of bsStates) {
      if (st.lo > 0n) {
        const skipTo = st.lo * memoSize;
        params.store.lanes[st.laneId]!.nextMemoLeaf = skipTo < st.nextLeaf ? skipTo : st.nextLeaf;
      }
    }
  }

  // Compute total new MemoPages and newly synced SubtreePages across all active lanes (post-Pass 1B)
  const scanStartLeafByLane = new Map<number, bigint>();
  let totalNewMemoPages = 0n;
  let totalNewSubtrees = 0n;
  for (const laneHdr of lanes) {
    const l = laneHdr.laneId;
    const startLeaf = params.store.lanes[l]!.nextMemoLeaf;
    scanStartLeafByLane.set(l, startLeaf);
    if (laneHdr.nextLeaf > 0n && startLeaf < laneHdr.nextLeaf) {
      const startMemo = startLeaf / memoSize;
      const targetMemoMax = (laneHdr.nextLeaf - 1n) / memoSize;
      totalNewMemoPages += targetMemoMax - startMemo + 1n;
      const startSub = startLeaf / subSize;
      const endSub = (laneHdr.nextLeaf - 1n) / subSize;
      totalNewSubtrees += endSub - startSub + 1n;
    }
  }

  const isIncrementalMemoSync = totalNewMemoPages <= BigInt(INCREMENTAL_FULL_MEMO_PAGE_THRESHOLD);
  // In `'strict'` mode we NEVER use `dataSlice` + targeted hit re-fetch for MemoPages.
  // Even in opt-in `'fast'` mode, small incremental syncs (`<= 25` pages) fetch full MemoPages directly.
  const useMemoDataSlice = privacyMode === 'fast' && !isIncrementalMemoSync;
  const fetchNewSubtreesUniformly =
    privacyMode === 'strict' &&
    isIncrementalMemoSync &&
    totalNewSubtrees <= BigInt(INCREMENTAL_UNIFORM_SUBTREE_THRESHOLD);

  // =========================================================================
  // PASS 1C: Fetch `MemoPage`s across ALL active lanes in uniform 100-account batches
  // =========================================================================
  const hitsByLane = new Map<number, MemoHitCandidate[]>();
  const scannedWatermarkByLane = new Map<number, bigint>();
  const inlineFullMemos = new Map<string, DecodedMemoPage>();
  const neededFullMemos = new Map<string, { laneId: number; memoSeq: bigint; addr: string }>();

  const memoQueue: Array<{ laneId: number; memoSeq: bigint; nextLeaf: bigint; addr: string }> = [];
  for (const laneHdr of lanes) {
    const l = laneHdr.laneId;
    const startLeaf = scanStartLeafByLane.get(l) ?? params.store.lanes[l]!.nextMemoLeaf;
    scannedWatermarkByLane.set(l, startLeaf);
    hitsByLane.set(l, []);
    if (laneHdr.nextLeaf === 0n || startLeaf >= laneHdr.nextLeaf) continue;
    const startMemo = startLeaf / memoSize;
    const targetMemoMax = (laneHdr.nextLeaf - 1n) / memoSize;
    for (let m = startMemo; m <= targetMemoMax; m++) {
      memoQueue.push({
        laneId: l,
        memoSeq: m,
        nextLeaf: laneHdr.nextLeaf,
        addr: deriveMemoPdaSync(poolId, l, m, programId).address,
      });
    }
  }

  const stoppedMemoLanes = new Set<number>();
  for (let off = 0; off < memoQueue.length; off += RPC_BATCH_CHUNK) {
    const chunk = memoQueue.slice(off, off + RPC_BATCH_CHUNK);
    if (chunk.every((item) => stoppedMemoLanes.has(item.laneId))) continue;
    const chunkAddrs = chunk.map((item) => item.addr);
    const raws = useMemoDataSlice
      ? await params.fetchBatch(chunkAddrs, {
          dataSlice: { offset: 0, length: MEMO_PAGE_SCAN_SLICE_LEN },
        })
      : await params.fetchBatch(chunkAddrs);

    for (let i = 0; i < chunk.length; i++) {
      const item = chunk[i]!;
      if (stoppedMemoLanes.has(item.laneId)) continue;
      const raw = raws[i];
      if (!raw) {
        stoppedMemoLanes.add(item.laneId);
        continue;
      }
      if (!useMemoDataSlice && raw.byteLength !== MEMO_PAGE_LEN) {
        throw new Error(`Invalid full MemoPage account (len=${raw.byteLength})`);
      }
      const scan = decodeMemoPageScanSlice(raw);
      let cursor = scannedWatermarkByLane.get(item.laneId)!;
      const pageBase = item.memoSeq * memoSize;
      const startSlot = cursor > pageBase ? Number(cursor - pageBase) : 0;
      const maxForSnapshot = Math.min(
        MEMO_NOTES_PER_PAGE,
        item.nextLeaf > pageBase ? Number(item.nextLeaf - pageBase) : 0,
      );
      const limitSlot = Math.min(scan.count, maxForSnapshot);

      if (
        startSlot === 0 &&
        birthdaySlot > 0n &&
        scan.count === MEMO_NOTES_PER_PAGE &&
        scan.closedSlot > 0n &&
        scan.closedSlot < birthdaySlot
      ) {
        cursor = pageBase + BigInt(limitSlot);
        scannedWatermarkByLane.set(item.laneId, cursor);
        if (scan.count < maxForSnapshot) {
          stoppedMemoLanes.add(item.laneId);
        }
        continue;
      }

      const laneHits = hitsByLane.get(item.laneId)!;
      let pageMatched = false;
      for (let slot = startSlot; slot < limitSlot; slot++) {
        if (checkMemoViewTag(params.fvk.viewSk, scan.viewTags[slot]!, scan.ephemeralPks[slot]!)) {
          pageMatched = true;
          laneHits.push({
            laneId: item.laneId,
            memoSeq: item.memoSeq,
            slot,
            leafIdx: pageBase + BigInt(slot),
          });
        }
      }
      if (pageMatched) {
        const memoKey = `${item.laneId}:${item.memoSeq.toString()}`;
        if (scan.hasCiphertexts && raw.byteLength === MEMO_PAGE_LEN) {
          inlineFullMemos.set(memoKey, decodeMemoPage(raw));
        } else if (!neededFullMemos.has(memoKey)) {
          neededFullMemos.set(memoKey, {
            laneId: item.laneId,
            memoSeq: item.memoSeq,
            addr: item.addr,
          });
        }
      }
      cursor = pageBase + BigInt(limitSlot);
      scannedWatermarkByLane.set(item.laneId, cursor);
      if (scan.count < maxForSnapshot) {
        stoppedMemoLanes.add(item.laneId);
      }
    }
  }

  // =========================================================================
  // PASS 1D: Fetch full `MemoPage`s (fast-mode >25 pages only) & `SubtreePage`s
  // =========================================================================
  const fetchedFullMemos = new Map<string, DecodedMemoPage>(inlineFullMemos);
  const fullMemoList = [...neededFullMemos.entries()];
  for (let off = 0; off < fullMemoList.length; off += RPC_BATCH_CHUNK) {
    const chunk = fullMemoList.slice(off, off + RPC_BATCH_CHUNK);
    const raws = await params.fetchBatch(chunk.map(([, req]) => req.addr));
    for (let i = 0; i < chunk.length; i++) {
      const [key] = chunk[i]!;
      const raw = raws[i];
      if (raw) fetchedFullMemos.set(key, decodeMemoPage(raw));
    }
  }

  // Determine `SubtreePage`s needed across all active lanes:
  //   - In `'strict'` incremental sync (`<= 25` MemoPages & `<= 25` newly synced SubtreePages),
  //     fetch all SubtreePages covering newly synced leaves uniformly so hits are never revealed.
  //   - In `'strict'` large catch-up (`> 25` MemoPages or `> 25` SubtreePages), ALWAYS fetch a
  //     fixed uniform batch count of sealed `SubtreePage`s (multiples of 16, minimum 16 even on
  //     0 hits) using deterministic wallet-keyed decoy selection `SHA256(viewSk || "audren/v1/decoy" || epochBucket)`
  //     so repeated syncs cannot be intersected and 0-hit vs 1..16-hit syncs are indistinguishable.
  const neededSubtrees = new Map<string, { laneId: number; subSeq: bigint; addr: string }>();
  const uniformNewSubtreeKeys = new Set<string>();
  const addNeededSubtree = (laneId: number, subSeq: bigint): boolean => {
    const key = `${laneId}:${subSeq.toString()}`;
    if (neededSubtrees.has(key)) return false;
    neededSubtrees.set(key, {
      laneId,
      subSeq,
      addr: deriveSubtreePdaSync(poolId, laneId, subSeq, programId).address,
    });
    return true;
  };

  if (fetchNewSubtreesUniformly) {
    for (const laneHdr of lanes) {
      const l = laneHdr.laneId;
      const startLeaf = scanStartLeafByLane.get(l) ?? params.store.lanes[l]!.nextMemoLeaf;
      if (laneHdr.nextLeaf > 0n && startLeaf < laneHdr.nextLeaf) {
        const startSub = startLeaf / subSize;
        const endSub = (laneHdr.nextLeaf - 1n) / subSize;
        for (let s = startSub; s <= endSub; s++) {
          addNeededSubtree(l, s);
          uniformNewSubtreeKeys.add(`${l}:${s.toString()}`);
        }
      }
    }
  }

  let hasHitCorrelatedSealedSubtree = false;
  for (const laneHdr of lanes) {
    const l = laneHdr.laneId;
    const laneState = params.store.lanes[l]!;
    const finalizedCount = laneHdr.nextLeaf / subSize;
    const frontierRem = Number(laneHdr.nextLeaf % subSize);

    if (frontierRem > 0) {
      addNeededSubtree(l, finalizedCount);
    }
    const hits = hitsByLane.get(l);
    if (hits) {
      for (const hit of hits) {
        const hitSubSeq = hit.leafIdx / subSize;
        addNeededSubtree(l, hitSubSeq);
        if (hitSubSeq < finalizedCount && !uniformNewSubtreeKeys.has(`${l}:${hitSubSeq.toString()}`)) {
          hasHitCorrelatedSealedSubtree = true;
        }
      }
    }
    for (const note of params.store.notes) {
      if (note.laneId === l && !note.frozenIntraSiblings) {
        const noteSubSeq = note.leafIndex / subSize;
        if (noteSubSeq < finalizedCount) {
          addNeededSubtree(l, noteSubSeq);
          if (!uniformNewSubtreeKeys.has(`${l}:${noteSubSeq.toString()}`)) {
            hasHitCorrelatedSealedSubtree = true;
          }
        }
      }
    }
    if (
      finalizedCount > 0n &&
      laneState.frontierLeaves.length > 0 &&
      laneState.frontierSubSeq === finalizedCount - 1n
    ) {
      addNeededSubtree(l, finalizedCount - 1n);
    }
    const fb = fallbackSubtreeSeqs.get(l);
    if (fb) {
      for (const s of fb) addNeededSubtree(l, s);
    }
  }

  // Deterministic wallet-keyed decoy padding for `'strict'` large catch-up (`> 25` pages)
  const isLargeStrictCatchup =
    privacyMode === 'strict' &&
    !fetchNewSubtreesUniformly &&
    (totalNewMemoPages > BigInt(INCREMENTAL_FULL_MEMO_PAGE_THRESHOLD) ||
      totalNewSubtrees > BigInt(INCREMENTAL_UNIFORM_SUBTREE_THRESHOLD) ||
      hasHitCorrelatedSealedSubtree);

  if (isLargeStrictCatchup) {
    const finalizedByLane = new Map<number, bigint>();
    let totalSealedSubtrees = 0n;
    for (const laneHdr of lanes) {
      const fc = laneHdr.nextLeaf / subSize;
      finalizedByLane.set(laneHdr.laneId, fc);
      totalSealedSubtrees += fc;
    }

    if (totalSealedSubtrees > 0n) {
      let currentSealedCount = 0;
      for (const req of neededSubtrees.values()) {
        if (req.subSeq < (finalizedByLane.get(req.laneId) ?? 0n)) {
          currentSealedCount++;
        }
      }

      // Fixed uniform batch size independent of hit count: multiples of 16 (min 16 even on 0 hits)
      const batchUnit = STRICT_DECOY_SEALED_SUBTREE_TARGET;
      const batches = Math.max(1, Math.ceil(currentSealedCount / batchUnit));
      const desiredBig = BigInt(batches * batchUnit);
      const targetSealed = Number(
        totalSealedSubtrees < desiredBig ? totalSealedSubtrees : desiredBig,
      );

      if (currentSealedCount < targetSealed) {
        if (totalSealedSubtrees <= BigInt(targetSealed)) {
          for (const laneHdr of lanes) {
            const fc = finalizedByLane.get(laneHdr.laneId) ?? 0n;
            for (let s = 0n; s < fc; s++) {
              if (addNeededSubtree(laneHdr.laneId, s)) {
                currentSealedCount++;
              }
            }
          }
        } else {
          const epochBucket =
            params.decoyEpochBucket ??
            totalSealedSubtrees / BigInt(STRICT_DECOY_SEALED_SUBTREE_TARGET);
          let counter = 0;
          while (currentSealedCount < targetSealed) {
            let g = deterministicDecoyIndex(
              params.fvk.viewSk,
              epochBucket,
              counter++,
              totalSealedSubtrees,
            );
            for (const laneHdr of lanes) {
              const fc = finalizedByLane.get(laneHdr.laneId) ?? 0n;
              if (g < fc) {
                if (addNeededSubtree(laneHdr.laneId, g)) {
                  currentSealedCount++;
                }
                break;
              }
              g -= fc;
            }
          }
        }
      }
    }
  }

  const fetchedSubtrees = new Map<string, Uint8Array[]>();
  const subList = [...neededSubtrees.entries()];
  // Sort by PDA Base58 address (SHA-256 output): pseudorandom uniform order AND 100% deterministic
  // across repeated syncs so neither position nor batch diffs leak hit locations.
  subList.sort((a, b) => (a[1].addr < b[1].addr ? -1 : a[1].addr > b[1].addr ? 1 : 0));
  for (let off = 0; off < subList.length; off += RPC_BATCH_CHUNK) {
    const chunk = subList.slice(off, off + RPC_BATCH_CHUNK);
    const raws = await params.fetchBatch(chunk.map(([, req]) => req.addr));
    for (let i = 0; i < chunk.length; i++) {
      const [key] = chunk[i]!;
      const raw = raws[i];
      if (raw) fetchedSubtrees.set(key, decodeSubtreePage(raw).leaves);
    }
  }

  let discoveredNotes = 0;
  for (const laneHdr of lanes) {
    const l = laneHdr.laneId;
    const laneState = params.store.lanes[l]!;
    const oldFrontierSubSeq = laneState.frontierSubSeq;
    const oldFrontierLeaves = laneState.frontierLeaves;
    const finalizedCount = laneHdr.nextLeaf / subSize;
    const frontierRem = Number(laneHdr.nextLeaf % subSize);

    // Populate any fallback finalized subroots & freeze previously-unfrozen notes in fetched sealed pages
    const fb = fallbackSubtreeSeqs.get(l);
    if (fb) {
      const sortedFb = [...fb].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      for (const s of sortedFb) {
        const leaves = fetchedSubtrees.get(`${l}:${s.toString()}`);
        if (leaves && leaves.length === SUBTREE_LEAVES) {
          const frLeaves = leaves.map((b) => frFromBeBytesStrict(b));
          const subroot = frToBeBytes(computeSubtree256Root(frLeaves, SUBTREE_LEAVES));
          const seqNum = Number(s);
          while (laneState.finalizedSubroots.length < seqNum) {
            laneState.finalizedSubroots.push(new Uint8Array(32));
          }
          laneState.finalizedSubroots[seqNum] = subroot;
        }
      }
    }

    // Verify all view-tag candidates for this lane in ascending leaf order
    let verifiedWatermark = scannedWatermarkByLane.get(l) ?? laneState.nextMemoLeaf;
    const hits = hitsByLane.get(l) ?? [];
    for (const hit of hits) {
      const memoPage = fetchedFullMemos.get(`${l}:${hit.memoSeq.toString()}`);
      const subSeq = hit.leafIdx / subSize;
      const subSlot = Number(hit.leafIdx % subSize);
      const subLeaves =
        fetchedSubtrees.get(`${l}:${subSeq.toString()}`) ??
        (subSeq === oldFrontierSubSeq ? oldFrontierLeaves : undefined);

      if (!memoPage || hit.slot >= memoPage.entries.length || !subLeaves || subSlot >= subLeaves.length) {
        // Cap nextMemoLeaf watermark on transient RPC miss (never skip Pass 2!).
        if (hit.leafIdx < verifiedWatermark) verifiedWatermark = hit.leafIdx;
        break;
      }
      const entry = memoPage.entries[hit.slot]!;
      const cmBe = subLeaves[subSlot]!;
      const dec = tryDecryptAndVerifyMemoEntry(
        params.fvk,
        entry.viewTag,
        entry.ephemeralPk,
        entry.ciphertext,
        cmBe,
      );
      if (dec) {
        if (
          params.store.recordVerifiedMemo({
            fvk: params.fvk,
            laneId: l,
            leafIdx: hit.leafIdx,
            decrypted: dec,
            cmBe,
          })
        ) {
          discoveredNotes++;
        }
      }
    }
    if (verifiedWatermark > laneState.nextMemoLeaf) {
      laneState.nextMemoLeaf = verifiedWatermark;
    }

    // Freeze owned notes for every fetched sealed SubtreePage on this lane
    for (const [key, req] of neededSubtrees) {
      if (req.laneId !== l) continue;
      const leaves = fetchedSubtrees.get(key);
      if (leaves && leaves.length === SUBTREE_LEAVES) {
        params.store.freezeOwnedNotesInSubtreePage(l, req.subSeq, leaves);
      }
    }

    // Retain at most 1 just-sealed page (`prevSealedSubSeq`/`prevSealedLeaves`) for pre-seal checkpoints
    if (finalizedCount > 0n) {
      const latestSealedSeq = finalizedCount - 1n;
      const latestSealedLeaves = fetchedSubtrees.get(`${l}:${latestSealedSeq.toString()}`);
      if (latestSealedLeaves && latestSealedLeaves.length === SUBTREE_LEAVES) {
        laneState.prevSealedSubSeq = latestSealedSeq;
        laneState.prevSealedLeaves = latestSealedLeaves.map((b) => new Uint8Array(b));
      } else if (
        oldFrontierSubSeq === latestSealedSeq &&
        oldFrontierLeaves.length > 0 &&
        laneState.prevSealedSubSeq !== latestSealedSeq
      ) {
        laneState.prevSealedSubSeq = oldFrontierSubSeq;
        laneState.prevSealedLeaves = oldFrontierLeaves;
      }
    }

    // Update live unsealed frontier
    if (frontierRem > 0) {
      const frontierLeaves = fetchedSubtrees.get(`${l}:${finalizedCount.toString()}`);
      if (frontierLeaves && frontierLeaves.length >= frontierRem) {
        laneState.frontierSubSeq = finalizedCount;
        laneState.frontierLeaves = frontierLeaves.slice(0, frontierRem).map((b) => new Uint8Array(b));
      }
    } else if (finalizedCount >= laneState.frontierSubSeq) {
      laneState.frontierSubSeq = finalizedCount;
      laneState.frontierLeaves = [];
    }
  }

  if (params.latestCheckpoint) {
    params.store.pruneSealedBeforeCheckpoint(params.latestCheckpoint);
  }

  // =========================================================================
  // PASS 2: ALWAYS stream ALL new `NullifierPage`s unconditionally (ZERO oracle!)
  // =========================================================================
  // Even if Pass 1D experienced a transient `SubtreePage` miss, Pass 2 MUST STILL fetch every
  // `NullifierPage` uniformly so an adversarial RPC cannot drop a `SubtreePage` and observe
  // whether Pass 2 was skipped. If any lane had an unverified miss, we hold `nextNfIndex`
  // locally so missed notes are re-checked on the next healthy sync without losing spend tracking.
  const allLanesCaughtUp = lanes.every(
    (h) => params.store.lanes[h.laneId]!.nextMemoLeaf >= h.nextLeaf,
  );
  const savedNextNfIndex = new Map<number, bigint>();
  for (const laneHdr of lanes) {
    savedNextNfIndex.set(laneHdr.laneId, params.store.lanes[laneHdr.laneId]!.nextNfIndex);
  }

  // Optional birthdaySlot binary search on `64 B` NullifierPage headers for fresh wallets
  // (runs uniformly regardless of owned-note balance so RPC cannot infer first receipt).
  if (birthdaySlot > 0n) {
    const nfBsStates: Array<{ laneId: number; nfCount: bigint; lo: bigint; hi: bigint }> = [];
    for (const laneHdr of lanes) {
      const l = laneHdr.laneId;
      const laneState = params.store.lanes[l]!;
      if (laneHdr.nfCount > 0n && laneState.nextNfIndex === 0n) {
        const targetNfMax = (laneHdr.nfCount - 1n) / nfSize;
        if (targetNfMax > 2n) {
          nfBsStates.push({ laneId: l, nfCount: laneHdr.nfCount, lo: 0n, hi: targetNfMax + 1n });
        }
      }
    }
    while (nfBsStates.some((s) => s.lo < s.hi)) {
      const active = nfBsStates.filter((s) => s.lo < s.hi);
      const mids = active.map((s) => (s.lo + s.hi) >> 1n);
      const addrs = active.map(
        (s, i) => deriveNfPagePdaSync(poolId, s.laneId, mids[i]!, programId).address,
      );
      const raws = await params.fetchBatch(addrs, {
        dataSlice: { offset: 0, length: NF_PAGE_HEADER_LEN },
      });
      for (let i = 0; i < active.length; i++) {
        const st = active[i]!;
        const mid = mids[i]!;
        const raw = raws[i];
        if (raw && raw.byteLength >= NF_PAGE_HEADER_LEN) {
          const hdr = decodeNullifierPageHeader(raw);
          if (hdr.count === NF_PER_PAGE && hdr.closedSlot > 0n && hdr.closedSlot < birthdaySlot) {
            st.lo = mid + 1n;
          } else {
            st.hi = mid;
          }
        } else {
          st.hi = mid;
        }
      }
    }
    for (const st of nfBsStates) {
      if (st.lo > 0n) {
        const skipTo = st.lo * nfSize;
        params.store.lanes[st.laneId]!.nextNfIndex = skipTo < st.nfCount ? skipTo : st.nfCount;
      }
    }
  }

  // Stream ALL new NullifierPages up to `laneHdr.nfCount` in uniform 100-account batches.
  // NEVER skip when 0 unspent notes exist, NEVER skip on Pass 1D miss, and NEVER break early
  // when the last unspent note is marked spent — stranger prefixes are discarded immediately.
  const nfQueue: Array<{ laneId: number; pageSeq: bigint; maxNfIndex: bigint; addr: string }> = [];
  for (const laneHdr of lanes) {
    const l = laneHdr.laneId;
    const laneState = params.store.lanes[l]!;
    if (laneHdr.nfCount === 0n || laneState.nextNfIndex >= laneHdr.nfCount) continue;
    const startNf = laneState.nextNfIndex / nfSize;
    const targetNfMax = (laneHdr.nfCount - 1n) / nfSize;
    for (let n = startNf; n <= targetNfMax; n++) {
      nfQueue.push({
        laneId: l,
        pageSeq: n,
        maxNfIndex: laneHdr.nfCount,
        addr: deriveNfPagePdaSync(poolId, l, n, programId).address,
      });
    }
  }

  const stoppedNfLanes = new Set<number>();
  for (let off = 0; off < nfQueue.length; off += RPC_BATCH_CHUNK) {
    const chunk = nfQueue.slice(off, off + RPC_BATCH_CHUNK);
    if (chunk.every((item) => stoppedNfLanes.has(item.laneId))) continue;
    const raws = await params.fetchBatch(chunk.map((q) => q.addr));
    for (let i = 0; i < chunk.length; i++) {
      const item = chunk[i]!;
      if (stoppedNfLanes.has(item.laneId)) continue;
      const raw = raws[i];
      if (!raw) {
        stoppedNfLanes.add(item.laneId);
        continue;
      }
      const hdr = decodeNullifierPageHeader(raw);
      const pageBase = item.pageSeq * nfSize;
      const expectedCap = Math.min(
        NF_PER_PAGE,
        item.maxNfIndex > pageBase ? Number(item.maxNfIndex - pageBase) : 0,
      );
      params.store.ingestNullifierPage({
        laneId: item.laneId,
        pageSeq: item.pageSeq,
        raw,
        maxNfIndex: item.maxNfIndex,
      });
      if (hdr.count < expectedCap) {
        stoppedNfLanes.add(item.laneId);
      }
    }
  }

  // If Pass 1D had a transient miss on any lane, hold `nextNfIndex` so notes discovered on retry
  // will still be checked against these NullifierPages without advancing past their spends.
  if (!allLanesCaughtUp) {
    for (const [l, prevIdx] of savedNextNfIndex) {
      params.store.lanes[l]!.nextNfIndex = prevIdx;
    }
  }

  return { pool, lanes, discoveredNotes };
}

/**
 * Stateless witness reconstruction for `(laneId, leafIdx)` at `RootCheckpoint(ckptSlotIdx)`.
 *
 * In default `'strict'` mode, NEVER issues a single-page pinpoint fetch right before spending:
 * pads `SubtreePage` fetches with decoy sealed `SubtreePage`s (or active-lane `SubtreePage`s when
 * fewer than 16 sealed pages exist) across all active lanes up to `min(16, totalSubtrees)`,
 * includes active-lane `SubtreeRootPage`s when needed, and shuffles the batch before fetching.
 */
export async function reconstructWitness(params: {
  fetchBatch: AccountBatchFetcher;
  poolId: number;
  ckptSlotIdx: number;
  laneId: number;
  leafIdx: bigint;
  programId?: string;
  privacyMode?: SyncPrivacyMode;
  viewSk?: Uint8Array;
}): Promise<{ ckpt: DecodedRootCheckpoint; superRoot: bigint; path: MerklePath4Ary }> {
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const privacyMode: SyncPrivacyMode = params.privacyMode ?? 'strict';
  const subSize = BigInt(SUBTREE_LEAVES);

  const ckptAddr = deriveCheckpointPdaSync(params.poolId, params.ckptSlotIdx, programId).address;
  const [ckptRaw] = await params.fetchBatch([ckptAddr]);
  if (!ckptRaw) throw new Error(`RootCheckpoint #${params.ckptSlotIdx} missing`);
  const ckpt = decodeRootCheckpoint(ckptRaw);

  const ckptCount = ckpt.laneCounts[params.laneId]!;
  if (params.leafIdx >= ckptCount) throw new Error('leafIdx >= checkpoint lane count');

  const targetPageIdx = params.leafIdx / subSize;
  const frontierPageIdx = ckptCount / subSize;
  const frontierRem = Number(ckptCount % subSize);
  const neededSrPages = Math.ceil(Number(frontierPageIdx) / SUBROOTS_PER_PAGE);

  const targetSrAddrs: string[] = [];
  const srAddrSet = new Set<string>();
  for (let rp = 0; rp < neededSrPages; rp++) {
    const addr = deriveSubrootPdaSync(params.poolId, params.laneId, BigInt(rp), programId).address;
    targetSrAddrs.push(addr);
    srAddrSet.add(addr);
  }

  if (privacyMode === 'strict' && neededSrPages > 0) {
    for (let l = 0; l < NUM_LANES; l++) {
      if (l === params.laneId) continue;
      const laneSealed = ckpt.laneCounts[l]! / subSize;
      if (laneSealed === 0n) continue;
      const laneSrPages = Math.min(neededSrPages, Math.ceil(Number(laneSealed) / SUBROOTS_PER_PAGE));
      for (let rp = 0; rp < laneSrPages; rp++) {
        srAddrSet.add(deriveSubrootPdaSync(params.poolId, l, BigInt(rp), programId).address);
      }
    }
  }

  const targetSubAddr = deriveSubtreePdaSync(
    params.poolId,
    params.laneId,
    targetPageIdx,
    programId,
  ).address;
  const needDistinctFrontier = frontierRem > 0 && frontierPageIdx !== targetPageIdx;
  const frontierSubAddr = needDistinctFrontier
    ? deriveSubtreePdaSync(params.poolId, params.laneId, frontierPageIdx, programId).address
    : null;

  const subAddrSet = new Set<string>([targetSubAddr]);
  if (frontierSubAddr) subAddrSet.add(frontierSubAddr);

  if (privacyMode === 'strict') {
    const sealedByLane: bigint[] = [];
    const totalByLane: bigint[] = [];
    let totalSealed = 0n;
    let totalSubtrees = 0n;
    for (let l = 0; l < NUM_LANES; l++) {
      const cnt = ckpt.laneCounts[l]!;
      const sealed = cnt / subSize;
      const total = cnt > 0n ? (cnt + subSize - 1n) / subSize : 0n;
      sealedByLane.push(sealed);
      totalByLane.push(total);
      totalSealed += sealed;
      totalSubtrees += total;
    }

    const decoyCap = BigInt(STRICT_DECOY_SEALED_SUBTREE_TARGET);
    const targetBatch = Number(totalSubtrees < decoyCap ? totalSubtrees : decoyCap);

    if (subAddrSet.size < targetBatch) {
      if (totalSubtrees <= decoyCap) {
        for (let l = 0; l < NUM_LANES; l++) {
          for (let s = 0n; s < totalByLane[l]!; s++) {
            subAddrSet.add(deriveSubtreePdaSync(params.poolId, l, s, programId).address);
          }
        }
      } else {
        const useSealedPool = totalSealed >= decoyCap;
        const poolCounts = useSealedPool ? sealedByLane : totalByLane;
        const poolTotal = useSealedPool ? totalSealed : totalSubtrees;
        const epochBucket = poolTotal / decoyCap;
        let counter = 0;
        while (subAddrSet.size < targetBatch) {
          let g =
            params.viewSk && params.viewSk.byteLength === 32
              ? deterministicDecoyIndex(params.viewSk, epochBucket, counter++, poolTotal)
              : randomUniformBigInt(poolTotal);
          for (let l = 0; l < NUM_LANES; l++) {
            const c = poolCounts[l]!;
            if (g < c) {
              subAddrSet.add(deriveSubtreePdaSync(params.poolId, l, g, programId).address);
              break;
            }
            g -= c;
          }
        }
      }
    }
  }

  const addrs = [...srAddrSet, ...subAddrSet];
  if (addrs.length > 1) {
    shuffleInPlace(addrs);
  }

  const raws = await params.fetchBatch(addrs);
  const rawByAddr = new Map<string, Uint8Array | null>();
  for (let i = 0; i < addrs.length; i++) {
    rawByAddr.set(addrs[i]!, raws[i] ?? null);
  }

  const finalizedRoots: bigint[] = [];
  for (let rp = 0; rp < neededSrPages; rp++) {
    const srRaw = rawByAddr.get(targetSrAddrs[rp]!);
    if (!srRaw) throw new Error(`SubtreeRootPage #${rp} missing`);
    const sr = decodeSubtreeRootPage(srRaw);
    for (const r of sr.roots) {
      if (finalizedRoots.length === Number(frontierPageIdx)) break;
      finalizedRoots.push(frFromBeBytesStrict(r));
    }
  }

  const targetSubRaw = rawByAddr.get(targetSubAddr);
  if (!targetSubRaw) throw new Error(`SubtreePage #${targetPageIdx} missing`);
  const targetLeaves = decodeSubtreePage(targetSubRaw).leaves.map((b) => frFromBeBytesStrict(b));

  let frontierLeaves: bigint[] | undefined;
  if (frontierRem > 0) {
    if (frontierSubAddr) {
      const fRaw = rawByAddr.get(frontierSubAddr);
      if (!fRaw) throw new Error(`Frontier SubtreePage #${frontierPageIdx} missing`);
      frontierLeaves = decodeSubtreePage(fRaw).leaves.map((b) => frFromBeBytesStrict(b));
    } else {
      frontierLeaves = targetLeaves;
    }
  }

  const path = buildHistoricalWitness4Ary({
    laneId: params.laneId,
    targetLeafIdx: params.leafIdx,
    ckptLaneRoots: ckpt.laneRoots.map((b) => frFromBeBytesStrict(b)),
    ckptLaneLeafCount: ckptCount,
    finalizedSubtreeRoots: finalizedRoots,
    targetPageLeaves: targetLeaves,
    frontierPageLeaves: frontierLeaves,
  });
  return { ckpt, superRoot: frFromBeBytesStrict(ckpt.superRoot), path };
}
