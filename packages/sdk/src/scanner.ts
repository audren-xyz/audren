/**
 * Indexer-free ordinary Solana RPC (`getMultipleAccounts`) 2-pass sync & historical witness
 * reconstruction using all three on-chain scaling primitives:
 *   1. `SubtreeRootPage` fast sync (`126 KB` / 1M notes vs `32.3 MB` of sealed `SubtreePage`s)
 *   2. `MemoPage` Structure-of-Arrays `dataSlice` (`3,872 B` header + view_tags + ephemeral_pks,
 *      fetching full `10,144 B` pages only on `1/65,536` view-tag matches)
 *   3. Optional `birthdaySlot` binary search on `64 B` page headers (`closedSlot < birthdaySlot`)
 *
 * Pass 1 ingests tree subroots, memos, and frontier leaves across ALL active lanes first so every
 * owned note is present in `store.notes`. Pass 2 streams `NullifierPage`s in bounded chunks against
 * an `O(owned_unspent_notes)` prefix map and discards stranger prefixes immediately (zero growth).
 */

import {
  AUDREN_PROGRAM_ID,
  MEMO_NOTES_PER_PAGE,
  MEMO_PAGE_HEADER_LEN,
  MEMO_PAGE_LEN,
  MEMO_PAGE_SCAN_SLICE_LEN,
  NF_PAGE_HEADER_LEN,
  NF_PER_PAGE,
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
 * calls using 2-pass sync (`SubtreeRootPage` fast sync + `MemoPage` SoA `dataSlice` + optional
 * `birthdaySlot` header binary search + zero-stranger-prefix `NullifierPage` streaming).
 */
export async function syncCompactStoreWithRpc(params: {
  store: CompactWalletStore;
  fvk: FullViewingKey;
  fetchBatch: AccountBatchFetcher;
  programId?: string;
  birthdaySlot?: bigint | number;
  latestCheckpoint?: DecodedRootCheckpoint;
}): Promise<{ pool: DecodedPoolState; lanes: DecodedLaneHeader[]; discoveredNotes: number }> {
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const poolId = params.store.poolId;
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

  // =========================================================================
  // PASS 1C: `MemoPage` SoA `dataSlice` scan (`3,872 B` header + viewTags + epks)
  // =========================================================================
  const hitsByLane = new Map<number, MemoHitCandidate[]>();
  const scannedWatermarkByLane = new Map<number, bigint>();
  const inlineFullMemos = new Map<string, DecodedMemoPage>();
  const neededFullMemos = new Map<string, { laneId: number; memoSeq: bigint; addr: string }>();

  for (const laneHdr of lanes) {
    const l = laneHdr.laneId;
    const laneState = params.store.lanes[l]!;
    let cursor = laneState.nextMemoLeaf;
    scannedWatermarkByLane.set(l, cursor);
    if (laneHdr.nextLeaf === 0n || cursor >= laneHdr.nextLeaf) continue;

    const startMemo = cursor / memoSize;
    const targetMemoMax = (laneHdr.nextLeaf - 1n) / memoSize;
    const laneHits: MemoHitCandidate[] = [];
    hitsByLane.set(l, laneHits);

    let laneStopped = false;
    for (let mStart = startMemo; mStart <= targetMemoMax && !laneStopped; mStart += BigInt(RPC_BATCH_CHUNK)) {
      const mEnd =
        mStart + BigInt(RPC_BATCH_CHUNK) - 1n < targetMemoMax
          ? mStart + BigInt(RPC_BATCH_CHUNK) - 1n
          : targetMemoMax;
      const chunkSeqs: bigint[] = [];
      const chunkAddrs: string[] = [];
      for (let m = mStart; m <= mEnd; m++) {
        chunkSeqs.push(m);
        chunkAddrs.push(deriveMemoPdaSync(poolId, l, m, programId).address);
      }

      const raws = await params.fetchBatch(chunkAddrs, {
        dataSlice: { offset: 0, length: MEMO_PAGE_SCAN_SLICE_LEN },
      });
      for (let i = 0; i < chunkSeqs.length; i++) {
        const m = chunkSeqs[i]!;
        const raw = raws[i];
        if (!raw) {
          laneStopped = true;
          break;
        }
        const scan = decodeMemoPageScanSlice(raw);
        const pageBase = m * memoSize;
        const startSlot = cursor > pageBase ? Number(cursor - pageBase) : 0;
        const maxForSnapshot = Math.min(
          MEMO_NOTES_PER_PAGE,
          laneHdr.nextLeaf > pageBase ? Number(laneHdr.nextLeaf - pageBase) : 0,
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
          if (scan.count < maxForSnapshot) {
            laneStopped = true;
            break;
          }
          continue;
        }

        let pageMatched = false;
        for (let slot = startSlot; slot < limitSlot; slot++) {
          if (checkMemoViewTag(params.fvk.viewSk, scan.viewTags[slot]!, scan.ephemeralPks[slot]!)) {
            pageMatched = true;
            laneHits.push({
              laneId: l,
              memoSeq: m,
              slot,
              leafIdx: pageBase + BigInt(slot),
            });
          }
        }
        if (pageMatched) {
          const memoKey = `${l}:${m.toString()}`;
          if (scan.hasCiphertexts && raw.byteLength === MEMO_PAGE_LEN) {
            inlineFullMemos.set(memoKey, decodeMemoPage(raw));
          } else if (!neededFullMemos.has(memoKey)) {
            neededFullMemos.set(memoKey, {
              laneId: l,
              memoSeq: m,
              addr: chunkAddrs[i]!,
            });
          }
        }
        cursor = pageBase + BigInt(limitSlot);
        if (scan.count < maxForSnapshot) {
          laneStopped = true;
          break;
        }
      }
    }
    scannedWatermarkByLane.set(l, cursor);
  }

  // =========================================================================
  // PASS 1D: Fetch ONLY matched full `MemoPage`s, live frontiers, and required `SubtreePage`s
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

  // Determine the minimal set of `SubtreePage`s needed across all lanes:
  //   1. Live unsealed frontier (`frontierRem > 0`)
  //   2. Historical pages containing a view-tag match
  //   3. Sealed pages containing an existing owned note whose 12 siblings are not frozen yet
  //   4. Previous active frontier page that just sealed (so `prevSealedLeaves` covers pre-seal ckpts)
  //   5. Fallback pages only if a mock returned null for `SubtreeRootPage`
  const neededSubtrees = new Map<string, { laneId: number; subSeq: bigint; addr: string }>();
  const addNeededSubtree = (laneId: number, subSeq: bigint) => {
    const key = `${laneId}:${subSeq.toString()}`;
    if (!neededSubtrees.has(key)) {
      neededSubtrees.set(key, {
        laneId,
        subSeq,
        addr: deriveSubtreePdaSync(poolId, laneId, subSeq, programId).address,
      });
    }
  };

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
        addNeededSubtree(l, hit.leafIdx / subSize);
      }
    }
    for (const note of params.store.notes) {
      if (note.laneId === l && !note.frozenIntraSiblings) {
        const noteSubSeq = note.leafIndex / subSize;
        if (noteSubSeq < finalizedCount) addNeededSubtree(l, noteSubSeq);
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

  const fetchedSubtrees = new Map<string, Uint8Array[]>();
  const subList = [...neededSubtrees.entries()];
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
        // Do not advance nextMemoLeaf past an unverified view-tag candidate on transient RPC miss.
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
  // PASS 2: Stream `NullifierPage`s across ALL active lanes (O(owned_unspent_notes) RAM!)
  // =========================================================================
  const allLanesCaughtUp = lanes.every(
    (h) => params.store.lanes[h.laneId]!.nextMemoLeaf >= h.nextLeaf,
  );
  if (allLanesCaughtUp) {
    if (!params.store.notes.some((n) => !n.spent)) {
      // Zero unspent owned notes across all lanes: advance watermarks with zero NullifierPage fetches.
      for (const laneHdr of lanes) {
        const laneState = params.store.lanes[laneHdr.laneId]!;
        if (laneHdr.nfCount > laneState.nextNfIndex) {
          laneState.nextNfIndex = laneHdr.nfCount;
        }
      }
    } else {
      // Optional birthdaySlot binary search on `64 B` NullifierPage headers for fresh wallets
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
            params.store.lanes[st.laneId]!.nextNfIndex =
              skipTo < st.nfCount ? skipTo : st.nfCount;
          }
        }
      }

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
        if (!params.store.notes.some((n) => !n.spent)) {
          for (const laneHdr of lanes) {
            if (!stoppedNfLanes.has(laneHdr.laneId)) {
              const ls = params.store.lanes[laneHdr.laneId]!;
              if (laneHdr.nfCount > ls.nextNfIndex) ls.nextNfIndex = laneHdr.nfCount;
            }
          }
          break;
        }
        const chunk = nfQueue.slice(off, off + RPC_BATCH_CHUNK);
        const raws = await params.fetchBatch(chunk.map((q) => q.addr));
        for (let i = 0; i < chunk.length; i++) {
          const item = chunk[i]!;
          if (stoppedNfLanes.has(item.laneId)) continue;
          const raw = raws[i];
          if (!raw) {
            stoppedNfLanes.add(item.laneId);
            continue;
          }
          params.store.ingestNullifierPage({
            laneId: item.laneId,
            pageSeq: item.pageSeq,
            raw,
            maxNfIndex: item.maxNfIndex,
          });
        }
      }
    }
  }

  return { pool, lanes, discoveredNotes };
}

/** Stateless witness reconstruction for `(laneId, leafIdx)` at `RootCheckpoint(ckptSlotIdx)`. */
export async function reconstructWitness(params: {
  fetchBatch: AccountBatchFetcher;
  poolId: number;
  ckptSlotIdx: number;
  laneId: number;
  leafIdx: bigint;
  programId?: string;
}): Promise<{ ckpt: DecodedRootCheckpoint; superRoot: bigint; path: MerklePath4Ary }> {
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const ckptAddr = deriveCheckpointPdaSync(params.poolId, params.ckptSlotIdx, programId).address;
  const [ckptRaw] = await params.fetchBatch([ckptAddr]);
  if (!ckptRaw) throw new Error(`RootCheckpoint #${params.ckptSlotIdx} missing`);
  const ckpt = decodeRootCheckpoint(ckptRaw);

  const ckptCount = ckpt.laneCounts[params.laneId]!;
  if (params.leafIdx >= ckptCount) throw new Error('leafIdx >= checkpoint lane count');

  const targetPageIdx = params.leafIdx / BigInt(SUBTREE_LEAVES);
  const frontierPageIdx = ckptCount / BigInt(SUBTREE_LEAVES);
  const frontierRem = Number(ckptCount % BigInt(SUBTREE_LEAVES));
  const neededSrPages = Math.ceil(Number(frontierPageIdx) / SUBROOTS_PER_PAGE);

  const addrs: string[] = [];
  for (let rp = 0; rp < neededSrPages; rp++) {
    addrs.push(deriveSubrootPdaSync(params.poolId, params.laneId, BigInt(rp), programId).address);
  }
  const targetSubAddr = deriveSubtreePdaSync(
    params.poolId,
    params.laneId,
    targetPageIdx,
    programId,
  ).address;
  addrs.push(targetSubAddr);
  const needDistinctFrontier = frontierRem > 0 && frontierPageIdx !== targetPageIdx;
  if (needDistinctFrontier) {
    addrs.push(
      deriveSubtreePdaSync(params.poolId, params.laneId, frontierPageIdx, programId).address,
    );
  }

  const raws = await params.fetchBatch(addrs);
  let cursor = 0;
  const finalizedRoots: bigint[] = [];
  for (let rp = 0; rp < neededSrPages; rp++) {
    const srRaw = raws[cursor++];
    if (!srRaw) throw new Error(`SubtreeRootPage #${rp} missing`);
    const sr = decodeSubtreeRootPage(srRaw);
    for (const r of sr.roots) {
      if (finalizedRoots.length === Number(frontierPageIdx)) break;
      finalizedRoots.push(frFromBeBytesStrict(r));
    }
  }
  const targetSubRaw = raws[cursor++];
  if (!targetSubRaw) throw new Error(`SubtreePage #${targetPageIdx} missing`);
  const targetLeaves = decodeSubtreePage(targetSubRaw).leaves.map((b) => frFromBeBytesStrict(b));

  let frontierLeaves: bigint[] | undefined;
  if (frontierRem > 0) {
    if (needDistinctFrontier) {
      const fRaw = raws[cursor++];
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
