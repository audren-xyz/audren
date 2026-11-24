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
  EPOCH_RING_LEN,
  LANE_DEPTH_4ARY,
  MAX_ROOT_EPOCH_INTERVAL,
  MEMO_NOTES_PER_PAGE,
  MEMO_PAGE_HEADER_LEN,
  MEMO_PAGE_LEN,
  MEMO_PAGE_SCAN_SLICE_LEN,
  NF_PAGE_HEADER_LEN,
  NF_PER_PAGE,
  NUM_LANES,
  ROOT_RING_EPOCH,
  ROOT_RING_SLOT,
  SLOT_RING_LEN,
  SUBROOTS_PER_PAGE,
  SUBTREE_LEAVES,
  SUBTREE_LEVELS_4ARY,
  ZERO_HASHES_4ARY,
} from './constants.ts';
import {
  checkMemoViewTag,
  tryDecryptAndVerifyMemoEntry,
  type DecryptedMemo,
} from './crypto.ts';
import type { FullViewingKey } from './keys.ts';
import {
  MAX_LEAVES_PER_LANE,
  decodeGlobalRootHistory,
  decodeLaneHeader,
  decodeMemoPage,
  decodeMemoPageHeader,
  decodeMemoPageScanSlice,
  decodeNullifierPageHeader,
  decodePoolState,
  decodeSubtreePage,
  decodeSubtreeRootPage,
  selectRootSnapshotForNotes,
  type DecodedGlobalRootHistory,
  type DecodedLaneHeader,
  type DecodedMemoPage,
  type DecodedPoolState,
  type RootSnapshotChoice,
} from './layout.ts';
import {
  deriveLanePdaSync,
  deriveMemoPdaSync,
  deriveNfPagePdaSync,
  derivePoolPdaSync,
  deriveRootsPdaSync,
  deriveSubrootPdaSync,
  deriveSubtreePdaSync,
} from './pda.ts';
import {
  computeSubtree256Root,
  computeSuperRoot4Ary,
  frFromBeBytesStrict,
  frToBeBytes,
  poseidon4,
} from './poseidon.ts';
import {
  buildHistoricalWitness4Ary,
  computeMerkleRoot4Ary,
  extractIntraSubtreeSiblings,
  type CompactWalletStore,
  type MerklePath4Ary,
} from './store.ts';

const RPC_BATCH_CHUNK = 100;
const utf8Encoder = new TextEncoder();
const DECOY_DOMAIN_BYTES = utf8Encoder.encode('audren/v1/decoy');
const DECOY_SCOPE_SYNC_BYTES = utf8Encoder.encode('sync');
const DECOY_SCOPE_WITNESS_PREFIX = utf8Encoder.encode('witness');
const DECOY_ORDER_LABEL_BYTES = utf8Encoder.encode('order');

/** Maximum new `MemoPage`s fetched as an incremental sync (`<= ~256 KB`). */
export const INCREMENTAL_FULL_MEMO_PAGE_THRESHOLD = 25;
/** Maximum newly synced `SubtreePage`s fetched uniformly on incremental sync in `'strict'` mode. */
export const INCREMENTAL_UNIFORM_SUBTREE_THRESHOLD = 25;
/** Minimum sealed `SubtreePage` anonymity set size when decoy-padding in `'strict'` mode. */
export const STRICT_DECOY_SEALED_SUBTREE_TARGET = 16;
/** Sealed-subtree count divisor for deterministic decoy epoch buckets (synced with Rust SDK). */
export const DECOY_EPOCH_BUCKET_SIZE = 64;
/** Maximum pages fetched per pass in a single `syncCompactStoreWithRpc` call (prevents untrusted-RPC OOM/hang). */
export const MAX_SYNC_PAGES_PER_CALL = 4_096;
/** Maximum total `SubtreeRootPage`s fetched in a single `reconstructWitness` call (`4,096 * 300 = 1.22M` subtrees). */
export const MAX_WITNESS_SR_PAGES = 4_096;
/** Maximum total sealed subtrees scanned by `selectHrwSealedDecoys` (`262,144 * 256 = 67M` notes). */
export const MAX_HRW_SEALED_SUBTREES = 262_144;

function computeLaneRootFromSubrootsAndFrontier(
  finalizedSubroots: readonly bigint[],
  frontierLeaves?: readonly bigint[],
  frontierRem = 0,
): bigint {
  let levelNodes: bigint[] = [...finalizedSubroots];
  if (frontierRem > 0) {
    if (!frontierLeaves || frontierLeaves.length < frontierRem) {
      throw new Error('Missing frontier SubtreePage leaves');
    }
    levelNodes.push(computeSubtree256Root(frontierLeaves, frontierRem));
  }
  if (levelNodes.length === 0) {
    return ZERO_HASHES_4ARY[LANE_DEPTH_4ARY]!;
  }
  for (let h = SUBTREE_LEVELS_4ARY; h < LANE_DEPTH_4ARY; h++) {
    const zeroAtH = ZERO_HASHES_4ARY[h]!;
    const nextLen = Math.ceil(levelNodes.length / 4);
    const nextLevel = new Array<bigint>(nextLen);
    for (let g = 0; g < nextLen; g++) {
      const base = g * 4;
      nextLevel[g] = poseidon4(
        base < levelNodes.length ? levelNodes[base]! : zeroAtH,
        base + 1 < levelNodes.length ? levelNodes[base + 1]! : zeroAtH,
        base + 2 < levelNodes.length ? levelNodes[base + 2]! : zeroAtH,
        base + 3 < levelNodes.length ? levelNodes[base + 3]! : zeroAtH,
      );
    }
    levelNodes = nextLevel;
  }
  return levelNodes[0]!;
}

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

function compareBytes32(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < 32; i++) {
    const diff = a[i]! - b[i]!;
    if (diff !== 0) return diff;
  }
  return 0;
}

function makeWitnessDecoyScope(targetLaneId: number, targetPageSeq: bigint): Uint8Array {
  const out = new Uint8Array(DECOY_SCOPE_WITNESS_PREFIX.byteLength + 1 + 8);
  out.set(DECOY_SCOPE_WITNESS_PREFIX, 0);
  out[DECOY_SCOPE_WITNESS_PREFIX.byteLength] = targetLaneId & 0xff;
  new DataView(out.buffer).setBigUint64(DECOY_SCOPE_WITNESS_PREFIX.byteLength + 1, targetPageSeq, true);
  return out;
}

function assertU64OrSafeInt(v: bigint | number, label: string): bigint {
  if (typeof v === 'bigint') {
    if (v < 0n || v > U64_MAX) {
      throw new RangeError(`${label} must be a u64 bigint in 0..=2^64-1, got ${String(v)}`);
    }
    return v;
  }
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) {
    return BigInt(v);
  }
  throw new RangeError(
    `${label} must be a non-negative safe integer or u64 bigint, got ${String(v)}`,
  );
}

const DEC_UINT_RE = /^\d+$/;

function computeSubtreeOrderKey(
  viewSk: Uint8Array,
  scope: Uint8Array,
  epochBucket: bigint,
  addrBytes: Uint8Array,
): Uint8Array {
  if (!(viewSk instanceof Uint8Array) || viewSk.byteLength !== 32) {
    throw new RangeError(`viewSk must be a 32-byte Uint8Array, got ${viewSk instanceof Uint8Array ? viewSk.byteLength : String(viewSk)}`);
  }
  if (!(scope instanceof Uint8Array)) {
    throw new RangeError(`scope must be a Uint8Array, got ${String(scope)}`);
  }
  if (!(addrBytes instanceof Uint8Array) || addrBytes.byteLength !== 32) {
    throw new RangeError(`addrBytes must be a 32-byte Uint8Array, got ${addrBytes instanceof Uint8Array ? addrBytes.byteLength : String(addrBytes)}`);
  }
  if (typeof epochBucket !== 'bigint' || epochBucket < 0n || epochBucket > U64_MAX) {
    throw new RangeError(`epochBucket must be a u64 bigint, got ${String(epochBucket)}`);
  }
  const buf = new Uint8Array(
    32 + DECOY_DOMAIN_BYTES.byteLength + scope.byteLength + 8 + DECOY_ORDER_LABEL_BYTES.byteLength + 32,
  );
  let off = 0;
  buf.set(viewSk, off);
  off += 32;
  buf.set(DECOY_DOMAIN_BYTES, off);
  off += DECOY_DOMAIN_BYTES.byteLength;
  buf.set(scope, off);
  off += scope.byteLength;
  new DataView(buf.buffer).setBigUint64(off, epochBucket, true);
  off += 8;
  buf.set(DECOY_ORDER_LABEL_BYTES, off);
  off += DECOY_ORDER_LABEL_BYTES.byteLength;
  buf.set(addrBytes, off);
  return sha256(buf);
}

/**
 * Deterministic Rendezvous (Highest Random Weight) sealed `SubtreePage` decoy selection matching
 * `crates/client/src/scanner.rs::select_hrw_sealed_decoys` bit-for-bit:
 *
 *   `score = SHA256(viewSk[32] || "audren/v1/decoy" || scope || epochBucket_le8 || laneId || pageSeq_le8)`
 *
 * Selects the top-`K` highest-scoring candidates not in `alreadySelected` so `+1` sealed subtree
 * growth within an epoch bucket preserves `~(K - 1) / K` (usually `K / K`) of decoys instead of
 * scrambling modulo indices.
 */
export function selectHrwSealedDecoys(params: {
  viewSk: Uint8Array;
  scope: Uint8Array;
  epochBucket: bigint;
  sealedByLane: ReadonlyArray<{ laneId: number; sealedCount: bigint }>;
  alreadySelected: ReadonlySet<string>;
  targetSealed: number;
}): Array<{ laneId: number; pageSeq: bigint }> {
  if (!params || typeof params !== 'object') {
    throw new RangeError('selectHrwSealedDecoys params must be an object');
  }
  const { viewSk, scope, epochBucket, sealedByLane, alreadySelected, targetSealed } = params;
  if (!(viewSk instanceof Uint8Array) || viewSk.byteLength !== 32) {
    throw new RangeError(
      `viewSk must be a 32-byte Uint8Array, got ${viewSk instanceof Uint8Array ? viewSk.byteLength : String(viewSk)}`,
    );
  }
  if (!(scope instanceof Uint8Array)) {
    throw new RangeError(`scope must be a Uint8Array, got ${String(scope)}`);
  }
  if (typeof epochBucket !== 'bigint' || epochBucket < 0n || epochBucket > U64_MAX) {
    throw new RangeError(`epochBucket must be a u64 bigint, got ${String(epochBucket)}`);
  }
  if (!Array.isArray(sealedByLane)) {
    throw new RangeError('sealedByLane must be an array');
  }
  if (!Number.isInteger(targetSealed) || targetSealed < 0) {
    throw new RangeError(`targetSealed must be a non-negative integer, got ${String(targetSealed)}`);
  }
  let totalSealed = 0n;
  let alreadySealedCount = 0;
  for (const entry of sealedByLane) {
    if (!entry || typeof entry !== 'object') {
      throw new RangeError('sealedByLane entries must be objects');
    }
    const { laneId, sealedCount } = entry;
    if (!Number.isInteger(laneId) || laneId < 0 || laneId >= NUM_LANES) {
      throw new RangeError(`sealedByLane laneId must be 0..${NUM_LANES - 1}, got ${String(laneId)}`);
    }
    if (typeof sealedCount !== 'bigint' || sealedCount < 0n) {
      throw new RangeError(`sealedCount must be a non-negative bigint, got ${String(sealedCount)}`);
    }
    totalSealed += sealedCount;
    if (totalSealed > BigInt(MAX_HRW_SEALED_SUBTREES)) {
      throw new RangeError(
        `Total sealed subtrees (${totalSealed}) exceeds HRW operational bound (${MAX_HRW_SEALED_SUBTREES})`,
      );
    }
    for (const key of alreadySelected) {
      if (typeof key !== 'string') continue;
      const sep = key.indexOf(':');
      if (sep <= 0) continue;
      const laneStr = key.slice(0, sep);
      const seqStr = key.slice(sep + 1);
      if (!DEC_UINT_RE.test(laneStr) || !DEC_UINT_RE.test(seqStr)) continue;
      const kLane = Number(laneStr);
      if (kLane === laneId) {
        const kSeq = BigInt(seqStr);
        if (kSeq < sealedCount) alreadySealedCount++;
      }
    }
  }
  const cappedTarget = Number(
    totalSealed < BigInt(targetSealed) ? totalSealed : BigInt(targetSealed),
  );
  const need = cappedTarget - alreadySealedCount;
  if (need <= 0) return [];

  if (totalSealed <= BigInt(cappedTarget)) {
    const out: Array<{ laneId: number; pageSeq: bigint }> = [];
    for (const { laneId, sealedCount } of sealedByLane) {
      for (let s = 0n; s < sealedCount; s++) {
        if (!alreadySelected.has(`${laneId}:${s.toString()}`)) {
          out.push({ laneId, pageSeq: s });
        }
      }
    }
    return out;
  }

  const preimageLen = 32 + DECOY_DOMAIN_BYTES.byteLength + scope.byteLength + 8 + 1 + 8;
  const preimage = new Uint8Array(preimageLen);
  const dv = new DataView(preimage.buffer);
  let off = 0;
  preimage.set(viewSk, off);
  off += 32;
  preimage.set(DECOY_DOMAIN_BYTES, off);
  off += DECOY_DOMAIN_BYTES.byteLength;
  preimage.set(scope, off);
  off += scope.byteLength;
  dv.setBigUint64(off, epochBucket, true);
  off += 8;
  const laneOff = off;
  const seqOff = off + 1;

  // Bounded top-`need` list kept sorted descending by `(score, -laneId, -pageSeq)` so `top[need - 1]`
  // is the current threshold.
  const top: Array<{ score: Uint8Array; laneId: number; pageSeq: bigint }> = [];
  const beats = (
    scoreA: Uint8Array,
    laneA: number,
    seqA: bigint,
    b: { score: Uint8Array; laneId: number; pageSeq: bigint },
  ): boolean => {
    const cmp = compareBytes32(scoreA, b.score);
    if (cmp !== 0) return cmp > 0;
    if (laneA !== b.laneId) return laneA < b.laneId;
    return seqA < b.pageSeq;
  };

  for (const { laneId, sealedCount } of sealedByLane) {
    preimage[laneOff] = laneId & 0xff;
    for (let s = 0n; s < sealedCount; s++) {
      if (alreadySelected.has(`${laneId}:${s.toString()}`)) continue;
      dv.setBigUint64(seqOff, s, true);
      const score = sha256(preimage);
      if (top.length === need && !beats(score, laneId, s, top[need - 1]!)) {
        continue;
      }
      let insertAt = top.length;
      while (insertAt > 0 && beats(score, laneId, s, top[insertAt - 1]!)) {
        insertAt--;
      }
      top.splice(insertAt, 0, { score, laneId, pageSeq: s });
      if (top.length > need) {
        top.pop();
      }
    }
  }

  return top.map(({ laneId, pageSeq }) => ({ laneId, pageSeq }));
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
      const json: unknown = await res.json();
      if (!json || typeof json !== 'object' || Array.isArray(json)) {
        throw new Error('Solana RPC getMultipleAccounts returned invalid JSON-RPC response');
      }
      const rpcResp = json as {
        result?: { value?: unknown } | null;
        error?: { message?: unknown } | unknown;
      };
      if (rpcResp.error !== undefined && rpcResp.error !== null) {
        const msg =
          typeof rpcResp.error === 'object' &&
          'message' in rpcResp.error &&
          (rpcResp.error as { message?: unknown }).message !== undefined
            ? String((rpcResp.error as { message?: unknown }).message)
            : String(rpcResp.error);
        throw new Error(`Solana RPC error: ${msg}`);
      }
      const values =
        rpcResp.result && typeof rpcResp.result === 'object' ? rpcResp.result.value : undefined;
      if (!Array.isArray(values) || values.length !== chunk.length) {
        throw new Error(
          `Solana RPC getMultipleAccounts invalid result.value (expected ${chunk.length} entries, got ${Array.isArray(values) ? values.length : String(values)})`,
        );
      }
      for (let i = 0; i < chunk.length; i++) {
        const acc = values[i];
        if (acc === null) {
          out[off + i] = null;
          continue;
        }
        if (
          !acc ||
          typeof acc !== 'object' ||
          !Array.isArray((acc as { data?: unknown }).data) ||
          typeof (acc as { data: unknown[] }).data[0] !== 'string'
        ) {
          throw new Error(`Solana RPC getMultipleAccounts invalid account entry at index ${i}`);
        }
        const b64 = (acc as { data: [string, unknown] }).data[0];
        out[off + i] = b64 ? base64ToBytes(b64) : null;
      }
    }
    return out;
  };
}

/**
 * Fetch `PoolState` + all `NUM_LANES` (16) `LaneTreeState` headers atomically in ONE
 * 17-account `getMultipleAccounts` RPC batch (eliminating `InitLane` expansion snapshot skew
 * and saving 1 RPC round-trip on every sync).
 */
export async function fetchPoolAndLanes(
  fetchBatch: AccountBatchFetcher,
  poolId = 0,
  programId = AUDREN_PROGRAM_ID,
): Promise<{ pool: DecodedPoolState; lanes: DecodedLaneHeader[] }> {
  const poolPda = derivePoolPdaSync(poolId, programId).address;
  const batchAddrs: string[] = [poolPda];
  for (let l = 0; l < NUM_LANES; l++) {
    batchAddrs.push(deriveLanePdaSync(poolId, l, programId).address);
  }
  const raws = await fetchBatch(batchAddrs);
  if (raws.length !== batchAddrs.length) {
    throw new Error(
      `Phase 0 batch response length mismatch (expected ${batchAddrs.length}, got ${raws.length})`,
    );
  }
  const poolRaw = raws[0];
  if (!poolRaw) throw new Error(`PoolState account missing at ${poolPda}`);
  const pool = decodePoolState(poolRaw);
  if (pool.poolId !== poolId) {
    throw new Error(`PoolState poolId mismatch (expected ${poolId}, got ${pool.poolId})`);
  }

  const lanes: DecodedLaneHeader[] = [];
  for (let l = 0; l < pool.activeLanes; l++) {
    const raw = raws[1 + l];
    if (!raw) throw new Error(`LaneTreeState #${l} missing`);
    const hdr = decodeLaneHeader(raw);
    if (hdr.laneId !== l) {
      throw new Error(`LaneTreeState #${l} laneId mismatch (got ${hdr.laneId})`);
    }
    if (hdr.poolId !== poolId) {
      throw new Error(`LaneTreeState #${l} poolId mismatch (expected ${poolId}, got ${hdr.poolId})`);
    }
    lanes.push(hdr);
  }
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
  latestRootHistory?: DecodedGlobalRootHistory | RootSnapshotChoice;
  privacyMode?: SyncPrivacyMode;
  decoyEpochBucket?: bigint;
}): Promise<{ pool: DecodedPoolState; lanes: DecodedLaneHeader[]; discoveredNotes: number }> {
  if (!params || typeof params !== 'object') {
    throw new RangeError('syncCompactStoreWithRpc params must be an object');
  }
  if (!params.store || typeof params.store !== 'object' || !Array.isArray(params.store.lanes)) {
    throw new RangeError('syncCompactStoreWithRpc requires a valid CompactWalletStore');
  }
  if (
    !params.fvk ||
    typeof params.fvk !== 'object' ||
    !(params.fvk.viewSk instanceof Uint8Array) ||
    params.fvk.viewSk.byteLength !== 32 ||
    !(params.fvk.spendPk instanceof Uint8Array) ||
    params.fvk.spendPk.byteLength !== 32 ||
    !(params.fvk.nk instanceof Uint8Array) ||
    params.fvk.nk.byteLength !== 32
  ) {
    throw new RangeError(
      'syncCompactStoreWithRpc requires fvk with 32-byte Uint8Array viewSk, spendPk, and nk',
    );
  }
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const poolId = params.store.poolId;
  const privacyMode: SyncPrivacyMode =
    params.privacyMode === undefined ? 'strict' : params.privacyMode;
  if (privacyMode !== 'strict' && privacyMode !== 'fast') {
    throw new RangeError(`Invalid privacyMode: ${String(privacyMode)}`);
  }
  const birthdaySlot =
    params.birthdaySlot !== undefined
      ? assertU64OrSafeInt(params.birthdaySlot, 'birthdaySlot')
      : assertU64OrSafeInt(params.store.birthdaySlot, 'store.birthdaySlot');
  if (
    params.decoyEpochBucket !== undefined &&
    (typeof params.decoyEpochBucket !== 'bigint' ||
      params.decoyEpochBucket < 0n ||
      params.decoyEpochBucket > U64_MAX)
  ) {
    throw new RangeError(`Invalid decoyEpochBucket: ${String(params.decoyEpochBucket)}`);
  }
  if (params.store.lanes.length !== NUM_LANES) {
    throw new Error(`Invalid CompactWalletStore: expected ${NUM_LANES} lanes`);
  }
  if (params.latestRootHistory !== undefined) {
    if (!params.latestRootHistory || typeof params.latestRootHistory !== 'object') {
      throw new RangeError('latestRootHistory must be a GlobalRootHistory or RootSnapshotChoice');
    }
    if ('slotRing' in params.latestRootHistory || 'stableLaneCounts' in params.latestRootHistory) {
      validateGlobalRootHistory(params.latestRootHistory as DecodedGlobalRootHistory, poolId);
    } else {
      validateRootSnapshotChoice(params.latestRootHistory);
    }
  }
  const { pool, lanes } = await fetchPoolAndLanes(params.fetchBatch, poolId, programId);

  const subSize = BigInt(SUBTREE_LEAVES);
  const srSize = BigInt(SUBROOTS_PER_PAGE);
  const memoSize = BigInt(MEMO_NOTES_PER_PAGE);
  const nfSize = BigInt(NF_PER_PAGE);

  // =========================================================================
  // PASS 1A: Fast-sync finalized level-4 subroots via `SubtreeRootPage`
  //          (lazy RPC_BATCH_CHUNK windowing, contiguous buffering, zero
  //          early store mutation, strict header & canonical-Fr validation).
  // =========================================================================
  interface SrCursor {
    laneId: number;
    nextSr: bigint;
    endSr: bigint;
    finalizedCount: bigint;
    stopped: boolean;
  }
  const srCursors: SrCursor[] = [];
  const pass1aNewSubroots = new Map<number, Uint8Array[]>();
  for (const laneHdr of lanes) {
    const l = laneHdr.laneId;
    const laneState = params.store.lanes[l]!;
    pass1aNewSubroots.set(l, []);
    const finalizedCount = laneHdr.nextLeaf / subSize;
    const existingLen = BigInt(laneState.finalizedSubroots.length);
    if (finalizedCount > existingLen) {
      srCursors.push({
        laneId: l,
        nextSr: existingLen / srSize,
        endSr: (finalizedCount - 1n) / srSize,
        finalizedCount,
        stopped: false,
      });
    }
  }

  let srPagesFetched = 0;
  while (srPagesFetched < MAX_SYNC_PAGES_PER_CALL) {
    const chunk: Array<{ cursor: SrCursor; rootPageSeq: bigint; addr: string }> = [];
    for (const cursor of srCursors) {
      while (
        !cursor.stopped &&
        cursor.nextSr <= cursor.endSr &&
        chunk.length < RPC_BATCH_CHUNK &&
        srPagesFetched + chunk.length < MAX_SYNC_PAGES_PER_CALL
      ) {
        const rp = cursor.nextSr;
        cursor.nextSr = rp + 1n;
        chunk.push({
          cursor,
          rootPageSeq: rp,
          addr: deriveSubrootPdaSync(poolId, cursor.laneId, rp, programId).address,
        });
      }
      if (
        chunk.length >= RPC_BATCH_CHUNK ||
        srPagesFetched + chunk.length >= MAX_SYNC_PAGES_PER_CALL
      ) {
        break;
      }
    }
    if (chunk.length === 0) break;
    srPagesFetched += chunk.length;
    const raws = await params.fetchBatch(chunk.map((r) => r.addr));
    for (let i = 0; i < chunk.length; i++) {
      const { cursor, rootPageSeq } = chunk[i]!;
      if (cursor.stopped) continue;
      const raw = raws[i];
      const pass1aBuf = pass1aNewSubroots.get(cursor.laneId)!;
      const curLen = BigInt(
        params.store.lanes[cursor.laneId]!.finalizedSubroots.length + pass1aBuf.length,
      );
      const base = rootPageSeq * srSize;
      const expectedOnPage = Number(
        cursor.finalizedCount - base < srSize ? cursor.finalizedCount - base : srSize,
      );
      if (!raw) {
        cursor.stopped = true;
        continue;
      }
      const dec = decodeSubtreeRootPage(raw);
      if (dec.poolId !== poolId || dec.laneId !== cursor.laneId || dec.rootPageSeq !== rootPageSeq) {
        throw new Error(
          `SubtreeRootPage header mismatch (expected pool=${poolId}, lane=${cursor.laneId}, seq=${rootPageSeq})`,
        );
      }
      for (let k = 0; k < dec.roots.length; k++) {
        frFromBeBytesStrict(dec.roots[k]!);
      }
      const startInPage = curLen > base ? Number(curLen - base) : 0;
      const avail = Math.min(dec.count, expectedOnPage);
      if (avail < startInPage) {
        cursor.stopped = true;
        continue;
      }
      for (let k = startInPage; k < avail; k++) {
        pass1aBuf.push(new Uint8Array(dec.roots[k]!));
      }
      if (dec.count < expectedOnPage) {
        cursor.stopped = true;
      }
    }
  }

  const lookupVerifiedSubroot = (laneId: number, subSeq: bigint): Uint8Array | undefined => {
    const existing = params.store.lanes[laneId]!.finalizedSubroots;
    const existingLen = BigInt(existing.length);
    if (subSeq < existingLen) {
      return existing[Number(subSeq)];
    }
    const buf = pass1aNewSubroots.get(laneId);
    const off = subSeq - existingLen;
    if (buf && off >= 0n && off < BigInt(buf.length)) {
      return buf[Number(off)];
    }
    return undefined;
  };

  // =========================================================================
  // PASS 1B: Optional `birthdaySlot` binary search on `64 B` `MemoPage` headers
  //          (deferred commit so Pass 1D misses preserve zero store mutation).
  // =========================================================================
  const scanStartLeafByLane = new Map<number, bigint>();
  for (const laneHdr of lanes) {
    scanStartLeafByLane.set(laneHdr.laneId, params.store.lanes[laneHdr.laneId]!.nextMemoLeaf);
  }
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
      const mids = active.map((s) => s.lo + ((s.hi - s.lo) >> 1n));
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
        if (raw) {
          const hdr = decodeMemoPageHeader(raw);
          if (hdr.poolId !== poolId || hdr.laneId !== st.laneId || hdr.pageSeq !== mid) {
            throw new Error(
              `MemoPage header mismatch (expected pool=${poolId}, lane=${st.laneId}, seq=${mid})`,
            );
          }
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
        scanStartLeafByLane.set(st.laneId, skipTo < st.nextLeaf ? skipTo : st.nextLeaf);
      }
    }
  }

  // Compute total new MemoPages and newly synced SubtreePages across all active lanes (post-Pass 1B)
  let totalNewMemoPages = 0n;
  let totalNewSubtrees = 0n;
  for (const laneHdr of lanes) {
    const l = laneHdr.laneId;
    const startLeaf = scanStartLeafByLane.get(l) ?? params.store.lanes[l]!.nextMemoLeaf;
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
  // PASS 1C: Lazily stream `MemoPage`s across ALL active lanes in 100-account windows
  // =========================================================================
  interface MemoCursor {
    laneId: number;
    nextMemo: bigint;
    endMemo: bigint;
    nextLeaf: bigint;
    stopped: boolean;
  }
  const hitsByLane = new Map<number, MemoHitCandidate[]>();
  const scannedWatermarkByLane = new Map<number, bigint>();
  const inlineFullMemos = new Map<string, DecodedMemoPage>();
  const neededFullMemos = new Map<string, { laneId: number; memoSeq: bigint; addr: string }>();
  const memoCursors: MemoCursor[] = [];

  for (const laneHdr of lanes) {
    const l = laneHdr.laneId;
    const startLeaf = scanStartLeafByLane.get(l) ?? params.store.lanes[l]!.nextMemoLeaf;
    scannedWatermarkByLane.set(l, startLeaf);
    hitsByLane.set(l, []);
    if (laneHdr.nextLeaf === 0n || startLeaf >= laneHdr.nextLeaf) continue;
    memoCursors.push({
      laneId: l,
      nextMemo: startLeaf / memoSize,
      endMemo: (laneHdr.nextLeaf - 1n) / memoSize,
      nextLeaf: laneHdr.nextLeaf,
      stopped: false,
    });
  }

  let memoPagesFetched = 0;
  while (memoPagesFetched < MAX_SYNC_PAGES_PER_CALL) {
    const chunk: Array<{ cursor: MemoCursor; memoSeq: bigint; addr: string }> = [];
    for (const cursor of memoCursors) {
      while (
        !cursor.stopped &&
        cursor.nextMemo <= cursor.endMemo &&
        chunk.length < RPC_BATCH_CHUNK &&
        memoPagesFetched + chunk.length < MAX_SYNC_PAGES_PER_CALL
      ) {
        const m = cursor.nextMemo;
        cursor.nextMemo = m + 1n;
        chunk.push({
          cursor,
          memoSeq: m,
          addr: deriveMemoPdaSync(poolId, cursor.laneId, m, programId).address,
        });
      }
      if (
        chunk.length >= RPC_BATCH_CHUNK ||
        memoPagesFetched + chunk.length >= MAX_SYNC_PAGES_PER_CALL
      ) {
        break;
      }
    }
    if (chunk.length === 0) break;
    memoPagesFetched += chunk.length;
    const chunkAddrs = chunk.map((item) => item.addr);
    const raws = useMemoDataSlice
      ? await params.fetchBatch(chunkAddrs, {
          dataSlice: { offset: 0, length: MEMO_PAGE_SCAN_SLICE_LEN },
        })
      : await params.fetchBatch(chunkAddrs);

    for (let i = 0; i < chunk.length; i++) {
      const item = chunk[i]!;
      const cursor = item.cursor;
      if (cursor.stopped) continue;
      const raw = raws[i];
      if (!raw) {
        cursor.stopped = true;
        continue;
      }
      if (!useMemoDataSlice && (!(raw instanceof Uint8Array) || raw.byteLength !== MEMO_PAGE_LEN)) {
        throw new Error(
          `Invalid full MemoPage account (len=${raw instanceof Uint8Array ? raw.byteLength : String(raw)})`,
        );
      }
      const scan = decodeMemoPageScanSlice(raw);
      if (
        scan.poolId !== poolId ||
        scan.laneId !== cursor.laneId ||
        scan.pageSeq !== item.memoSeq
      ) {
        throw new Error(
          `MemoPage header mismatch (expected pool=${poolId}, lane=${cursor.laneId}, seq=${item.memoSeq})`,
        );
      }
      let wm = scannedWatermarkByLane.get(cursor.laneId)!;
      const pageBase = item.memoSeq * memoSize;
      const startSlot = wm > pageBase ? Number(wm - pageBase) : 0;
      const maxForSnapshot = Math.min(
        MEMO_NOTES_PER_PAGE,
        cursor.nextLeaf > pageBase ? Number(cursor.nextLeaf - pageBase) : 0,
      );
      const limitSlot = Math.min(scan.count, maxForSnapshot);

      if (
        startSlot === 0 &&
        birthdaySlot > 0n &&
        scan.count === MEMO_NOTES_PER_PAGE &&
        scan.closedSlot > 0n &&
        scan.closedSlot < birthdaySlot
      ) {
        wm = pageBase + BigInt(limitSlot);
        scannedWatermarkByLane.set(cursor.laneId, wm);
        if (scan.count < maxForSnapshot) {
          cursor.stopped = true;
        }
        continue;
      }

      const laneHits = hitsByLane.get(cursor.laneId)!;
      let pageMatched = false;
      for (let slot = startSlot; slot < limitSlot; slot++) {
        if (checkMemoViewTag(params.fvk.viewSk, scan.viewTags[slot]!, scan.ephemeralPks[slot]!)) {
          pageMatched = true;
          laneHits.push({
            laneId: cursor.laneId,
            memoSeq: item.memoSeq,
            slot,
            leafIdx: pageBase + BigInt(slot),
          });
        }
      }
      if (pageMatched) {
        const memoKey = `${cursor.laneId}:${item.memoSeq.toString()}`;
        if (scan.hasCiphertexts && raw.byteLength === MEMO_PAGE_LEN) {
          inlineFullMemos.set(memoKey, decodeMemoPage(raw));
        } else if (!neededFullMemos.has(memoKey)) {
          neededFullMemos.set(memoKey, {
            laneId: cursor.laneId,
            memoSeq: item.memoSeq,
            addr: item.addr,
          });
        }
      }
      wm = pageBase + BigInt(limitSlot);
      scannedWatermarkByLane.set(cursor.laneId, wm);
      if (scan.count < maxForSnapshot) {
        cursor.stopped = true;
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
      const [key, req] = chunk[i]!;
      const raw = raws[i];
      if (raw) {
        const dec = decodeMemoPage(raw);
        if (dec.poolId !== poolId || dec.laneId !== req.laneId || dec.pageSeq !== req.memoSeq) {
          throw new Error(
            `MemoPage header mismatch (expected pool=${poolId}, lane=${req.laneId}, seq=${req.memoSeq})`,
          );
        }
        fetchedFullMemos.set(key, dec);
      }
    }
  }

  // Determine `SubtreePage`s needed across all active lanes:
  //   - In `'strict'` incremental sync (`<= 25` MemoPages & `<= 25` newly synced SubtreePages),
  //     fetch all SubtreePages covering newly synced leaves uniformly so hits are never revealed.
  //   - In `'strict'` large catch-up (`> 25` MemoPages or `> 25` SubtreePages) OR whenever an
  //     older unfrozen/hit sealed subtree outside the uniform window is requested, ALWAYS fetch a
  //     fixed uniform batch count of sealed `SubtreePage`s (multiples of 16, minimum 16 even on
  //     0 hits) using Rendezvous (HRW) decoy selection so repeated syncs and `+1` subtree growth
  //     cannot be intersected and 0-hit vs 1..16-hit syncs are indistinguishable.
  const neededSubtrees = new Map<
    string,
    { laneId: number; subSeq: bigint; addr: string; addrBytes: Uint8Array }
  >();
  const uniformNewSubtreeKeys = new Set<string>();
  const addNeededSubtree = (laneId: number, subSeq: bigint): boolean => {
    const key = `${laneId}:${subSeq.toString()}`;
    if (neededSubtrees.has(key)) return false;
    const pda = deriveSubtreePdaSync(poolId, laneId, subSeq, programId);
    neededSubtrees.set(key, {
      laneId,
      subSeq,
      addr: pda.address,
      addrBytes: pda.addressBytes,
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
  const finalizedByLane = new Map<number, bigint>();
  const frontierRemByLane = new Map<number, number>();
  const sealedByLaneList: Array<{ laneId: number; sealedCount: bigint }> = [];
  let totalSealedSubtrees = 0n;

  for (const laneHdr of lanes) {
    const l = laneHdr.laneId;
    const laneState = params.store.lanes[l]!;
    const finalizedCount = laneHdr.nextLeaf / subSize;
    const frontierRem = Number(laneHdr.nextLeaf % subSize);
    finalizedByLane.set(l, finalizedCount);
    frontierRemByLane.set(l, frontierRem);
    sealedByLaneList.push({ laneId: l, sealedCount: finalizedCount });
    totalSealedSubtrees += finalizedCount;

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
  }

  const epochBucket = params.decoyEpochBucket ?? 0n;

  // Rendezvous (HRW) wallet-keyed decoy padding for `'strict'` mode:
  // Always pad BOTH large catch-ups (`!fetchNewSubtreesUniformly && totalNewMemoPages > 0`) AND
  // incremental syncs that touch any historical sealed subtree outside the uniform window
  // (`hasHitCorrelatedSealedSubtree`, e.g., freezing an older unfrozen note).
  const shouldDecoyPad =
    privacyMode === 'strict' &&
    totalSealedSubtrees > 0n &&
    (hasHitCorrelatedSealedSubtree || (!fetchNewSubtreesUniformly && totalNewMemoPages > 0n));

  if (shouldDecoyPad) {
    if (totalSealedSubtrees > BigInt(MAX_HRW_SEALED_SUBTREES)) {
      throw new RangeError(
        `Total sealed subtrees (${totalSealedSubtrees}) exceeds HRW operational bound (${MAX_HRW_SEALED_SUBTREES})`,
      );
    }
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
      const decoys = selectHrwSealedDecoys({
        viewSk: params.fvk.viewSk,
        scope: DECOY_SCOPE_SYNC_BYTES,
        epochBucket,
        sealedByLane: sealedByLaneList,
        alreadySelected: new Set(neededSubtrees.keys()),
        targetSealed,
      });
      for (const d of decoys) {
        addNeededSubtree(d.laneId, d.pageSeq);
      }
    }
  }

  const fetchedSubtrees = new Map<string, { leaves: Uint8Array[]; frLeaves: bigint[] }>();
  const subListWithKeys = [...neededSubtrees.entries()].map(([key, req]) => ({
    key,
    req,
    orderKey: computeSubtreeOrderKey(
      params.fvk.viewSk,
      DECOY_SCOPE_SYNC_BYTES,
      epochBucket,
      req.addrBytes,
    ),
  }));
  // Sort by deterministic wallet-keyed hash matching Rust `scanner.rs` byte-for-byte.
  subListWithKeys.sort((a, b) => compareBytes32(a.orderKey, b.orderKey));

  // Privacy & integrity invariant (R2-C1): uniformly validate EVERY fetched SubtreePage (both
  // hits AND decoys) for exact header `(poolId, laneId, pageSeq)`, strict canonical Fr on ALL
  // `0..count` leaves, and exact Poseidon root parity against Pass 1A's verified SubtreeRootPage
  // BEFORE any store mutation and BEFORE Pass 2 executes.
  let anyPass1dSubtreeMissing = false;
  for (let off = 0; off < subListWithKeys.length; off += RPC_BATCH_CHUNK) {
    const chunk = subListWithKeys.slice(off, off + RPC_BATCH_CHUNK);
    const raws = await params.fetchBatch(chunk.map((item) => item.req.addr));
    for (let i = 0; i < chunk.length; i++) {
      const item = chunk[i]!;
      const raw = raws[i];
      if (!raw) {
        anyPass1dSubtreeMissing = true;
        continue;
      }
      const sub = decodeSubtreePage(raw);
      if (
        sub.poolId !== poolId ||
        sub.laneId !== item.req.laneId ||
        sub.pageSeq !== item.req.subSeq
      ) {
        throw new Error(
          `SubtreePage header mismatch (expected pool=${poolId}, lane=${item.req.laneId}, seq=${item.req.subSeq})`,
        );
      }
      const frLeaves = sub.leaves.map((b) => frFromBeBytesStrict(b));
      const fc = finalizedByLane.get(item.req.laneId) ?? 0n;
      const expectedMinLeaves =
        item.req.subSeq < fc ? SUBTREE_LEAVES : (frontierRemByLane.get(item.req.laneId) ?? 0);
      if (sub.leaves.length < expectedMinLeaves) {
        anyPass1dSubtreeMissing = true;
        continue;
      } else if (item.req.subSeq < fc) {
        const expectedSubrootBe = lookupVerifiedSubroot(item.req.laneId, item.req.subSeq);
        if (!expectedSubrootBe) {
          anyPass1dSubtreeMissing = true;
          continue;
        }
        const expectedSubrootFr = frFromBeBytesStrict(expectedSubrootBe);
        if (computeSubtree256Root(frLeaves, SUBTREE_LEAVES) !== expectedSubrootFr) {
          throw new Error('SubtreePage root mismatch against SubtreeRootPage');
        }
      }
      if (item.req.subSeq >= fc) {
        // Cap live-advancing frontier SubtreePage to Phase 0 `frontierRem` so unverified trailing
        // leaves beyond `laneHdr.nextLeaf` are never exposed to memo verification or committed.
        fetchedSubtrees.set(item.key, {
          leaves: sub.leaves.slice(0, expectedMinLeaves),
          frLeaves: frLeaves.slice(0, expectedMinLeaves),
        });
      } else {
        fetchedSubtrees.set(item.key, { leaves: sub.leaves, frLeaves });
      }
    }
  }

  // Cryptographic lane-root verification: before verifying memos or committing Pass 1A/1D state
  // to `store`, verify EVERY active lane with `nextLeaf > 0` by rolling up
  // `allFinalizedSubroots[..finalizedCount]` + `frontierFrLeaves[..frontierRem]` against Phase 0
  // `LaneTreeState.currentRoot`. If Pass 1A stopped short of `finalizedCount` (transient RPC lag),
  // withhold committing Pass 1A/1D for this sync cycle rather than committing unverified leaves.
  let anyPass1aIncomplete = false;
  for (const laneHdr of lanes) {
    const l = laneHdr.laneId;
    const finalizedCount = laneHdr.nextLeaf / subSize;
    const frontierRem = Number(laneHdr.nextLeaf % subSize);
    if (finalizedCount === 0n && frontierRem === 0) continue;

    const expectedLaneRootFr = frFromBeBytesStrict(laneHdr.currentRoot);
    const existingSubroots = params.store.lanes[l]!.finalizedSubroots;
    const pass1aBuf = pass1aNewSubroots.get(l) ?? [];
    const totalAvailable = BigInt(existingSubroots.length + pass1aBuf.length);
    if (totalAvailable < finalizedCount) {
      anyPass1aIncomplete = true;
      continue;
    }

    let frontierFrSlice: bigint[] | undefined;
    if (frontierRem > 0) {
      const frontierFetched = fetchedSubtrees.get(`${l}:${finalizedCount.toString()}`);
      if (!frontierFetched || frontierFetched.frLeaves.length < frontierRem) {
        anyPass1dSubtreeMissing = true;
        continue;
      }
      frontierFrSlice = frontierFetched.frLeaves.slice(0, frontierRem);
    }

    const fcNum = Number(finalizedCount);
    const allFinalizedFr = new Array<bigint>(fcNum);
    const takeExisting = Math.min(existingSubroots.length, fcNum);
    for (let k = 0; k < takeExisting; k++) {
      allFinalizedFr[k] = frFromBeBytesStrict(existingSubroots[k]!);
    }
    for (let k = takeExisting; k < fcNum; k++) {
      allFinalizedFr[k] = frFromBeBytesStrict(pass1aBuf[k - existingSubroots.length]!);
    }

    const computedLaneRootFr = computeLaneRootFromSubrootsAndFrontier(
      allFinalizedFr,
      frontierFrSlice,
      frontierRem,
    );
    if (computedLaneRootFr !== expectedLaneRootFr) {
      throw new Error(`Lane #${l} root mismatch against LaneTreeState.currentRoot`);
    }
  }

  let discoveredNotes = 0;
  const pendingVerifiedMemos: Array<{
    laneId: number;
    leafIdx: bigint;
    decrypted: DecryptedMemo;
    cmBe: Uint8Array;
  }> = [];
  const pendingWatermarks: Array<{ laneId: number; verifiedWatermark: bigint }> = [];

  for (const laneHdr of lanes) {
    const l = laneHdr.laneId;
    const laneState = params.store.lanes[l]!;
    const oldFrontierSubSeq = laneState.frontierSubSeq;
    const oldFrontierLeaves = laneState.frontierLeaves;

    // Verify all view-tag candidates for this lane in ascending leaf order into a temporary buffer;
    // `store` is ONLY mutated below when `!anyPass1dSubtreeMissing` so any dropped Pass 1D page
    // (hit OR decoy) leaves `store` and `discoveredNotes` 100% untouched.
    let verifiedWatermark = scannedWatermarkByLane.get(l) ?? laneState.nextMemoLeaf;
    const hits = hitsByLane.get(l) ?? [];
    for (const hit of hits) {
      const memoPage = fetchedFullMemos.get(`${l}:${hit.memoSeq.toString()}`);
      const subSeq = hit.leafIdx / subSize;
      const subSlot = Number(hit.leafIdx % subSize);
      const subLeaves =
        fetchedSubtrees.get(`${l}:${subSeq.toString()}`)?.leaves ??
        (subSeq === oldFrontierSubSeq ? oldFrontierLeaves : undefined);

      if (
        !memoPage ||
        hit.slot >= memoPage.entries.length ||
        !subLeaves ||
        subSlot >= subLeaves.length
      ) {
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
        pendingVerifiedMemos.push({
          laneId: l,
          leafIdx: hit.leafIdx,
          decrypted: dec,
          cmBe,
        });
      }
    }
    pendingWatermarks.push({ laneId: l, verifiedWatermark });
  }

  // Privacy & atomicity invariant: if ANY Pass 1A `SubtreeRootPage` stopped short of
  // `finalizedCount` OR ANY Pass 1D `SubtreePage` fetch returned `null` (or truncated) —
  // whether for a hit page OR a decoy/batch page — uniformly withhold ALL Pass 1A/1B/1D store
  // mutations (`finalizedSubroots`, `notes`, `discoveredNotes`, `nextMemoLeaf`, note freezing,
  // and frontier updates) across ALL lanes. Precompute ALL frozen intra-subtree witnesses BEFORE
  // mutating `store` so a validation error can NEVER leave partially mutated store state!
  const pass1Incomplete = anyPass1dSubtreeMissing || anyPass1aIncomplete;
  if (!pass1Incomplete) {
    if (pendingVerifiedMemos.length > 0) {
      frFromBeBytesStrict(params.fvk.spendPk);
      frFromBeBytesStrict(params.fvk.nk);
    }

    const precomputedExistingFreezes: Array<{
      noteIndex: number;
      siblingsBe: Uint8Array[][];
      positions: number[];
    }> = [];
    for (let ni = 0; ni < params.store.notes.length; ni++) {
      const note = params.store.notes[ni]!;
      if (note.frozenIntraSiblings) continue;
      const subSeq = note.leafIndex / subSize;
      const fc = finalizedByLane.get(note.laneId) ?? 0n;
      if (subSeq >= fc) continue;
      const fetched = fetchedSubtrees.get(`${note.laneId}:${subSeq.toString()}`);
      if (fetched && fetched.frLeaves.length === SUBTREE_LEAVES) {
        const offset = Number(note.leafIndex % subSize);
        if (
          offset < fetched.leaves.length &&
          compareBytes32(fetched.leaves[offset]!, note.commitment) === 0
        ) {
          const { siblings, positions } = extractIntraSubtreeSiblings(
            fetched.frLeaves,
            SUBTREE_LEAVES,
            offset,
          );
          precomputedExistingFreezes.push({
            noteIndex: ni,
            siblingsBe: siblings.map((lvl) => lvl.map((x) => frToBeBytes(x))),
            positions,
          });
        }
      }
    }

    const precomputedNewFreezes = new Map<
      string,
      { siblingsBe: Uint8Array[][]; positions: number[] }
    >();
    for (const m of pendingVerifiedMemos) {
      const subSeq = m.leafIdx / subSize;
      const fc = finalizedByLane.get(m.laneId) ?? 0n;
      if (subSeq >= fc) continue;
      const fetched = fetchedSubtrees.get(`${m.laneId}:${subSeq.toString()}`);
      if (fetched && fetched.frLeaves.length === SUBTREE_LEAVES) {
        const offset = Number(m.leafIdx % subSize);
        if (
          offset < fetched.leaves.length &&
          compareBytes32(fetched.leaves[offset]!, m.cmBe) === 0
        ) {
          const { siblings, positions } = extractIntraSubtreeSiblings(
            fetched.frLeaves,
            SUBTREE_LEAVES,
            offset,
          );
          precomputedNewFreezes.set(`${m.laneId}:${m.leafIdx.toString()}`, {
            siblingsBe: siblings.map((lvl) => lvl.map((x) => frToBeBytes(x))),
            positions,
          });
        }
      }
    }

    // All validations & precomputations succeeded: commit atomically to `store`.
    for (const laneHdr of lanes) {
      const l = laneHdr.laneId;
      const newRoots = pass1aNewSubroots.get(l);
      if (newRoots && newRoots.length > 0) {
        params.store.lanes[l]!.finalizedSubroots.push(...newRoots);
      }
    }

    for (const f of precomputedExistingFreezes) {
      const note = params.store.notes[f.noteIndex]!;
      note.frozenIntraSiblings = f.siblingsBe;
      note.frozenIntraPositions = f.positions;
    }

    for (const m of pendingVerifiedMemos) {
      if (
        params.store.recordVerifiedMemo({
          fvk: params.fvk,
          laneId: m.laneId,
          leafIdx: m.leafIdx,
          decrypted: m.decrypted,
          cmBe: m.cmBe,
        })
      ) {
        discoveredNotes++;
        const frozen = precomputedNewFreezes.get(`${m.laneId}:${m.leafIdx.toString()}`);
        if (frozen) {
          const added = params.store.notes[params.store.notes.length - 1]!;
          added.frozenIntraSiblings = frozen.siblingsBe;
          added.frozenIntraPositions = frozen.positions;
        }
      }
    }

    for (const { laneId, verifiedWatermark } of pendingWatermarks) {
      const laneState = params.store.lanes[laneId]!;
      if (verifiedWatermark > laneState.nextMemoLeaf) {
        laneState.nextMemoLeaf = verifiedWatermark;
      }
    }

    for (const laneHdr of lanes) {
      const l = laneHdr.laneId;
      const laneState = params.store.lanes[l]!;
      const oldFrontierSubSeq = laneState.frontierSubSeq;
      const oldFrontierLeaves = laneState.frontierLeaves;
      const finalizedCount = laneHdr.nextLeaf / subSize;
      const frontierRem = Number(laneHdr.nextLeaf % subSize);
      const finalizedSubrootsLen = BigInt(laneState.finalizedSubroots.length);

      // Retain at most 1 just-sealed page (`prevSealedSubSeq`/`prevSealedLeaves`) for pre-seal root snapshots
      // (monotonicity-guarded so lagging RPC replicas never regress `prevSealedSubSeq`).
      if (finalizedCount > 0n) {
        const latestSealedSeq = finalizedCount - 1n;
        const prevSealedAdvances =
          (laneState.prevSealedSubSeq === null || latestSealedSeq >= laneState.prevSealedSubSeq) &&
          finalizedCount >= oldFrontierSubSeq &&
          finalizedCount >= finalizedSubrootsLen;
        if (prevSealedAdvances) {
          const latestSealedLeaves = fetchedSubtrees.get(
            `${l}:${latestSealedSeq.toString()}`,
          )?.leaves;
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
      }

      // Update live unsealed frontier (monotonicity-guarded against lagging RPC replicas).
      if (frontierRem > 0) {
        const frontierAdvances =
          finalizedCount >= finalizedSubrootsLen &&
          (finalizedCount > laneState.frontierSubSeq ||
            (finalizedCount === laneState.frontierSubSeq &&
              frontierRem > laneState.frontierLeaves.length));
        if (frontierAdvances) {
          const frontierLeaves = fetchedSubtrees.get(`${l}:${finalizedCount.toString()}`)?.leaves;
          if (frontierLeaves && frontierLeaves.length >= frontierRem) {
            laneState.frontierSubSeq = finalizedCount;
            laneState.frontierLeaves = frontierLeaves
              .slice(0, frontierRem)
              .map((b) => new Uint8Array(b));
          }
        }
      } else if (
        finalizedCount > laneState.frontierSubSeq &&
        finalizedCount >= finalizedSubrootsLen
      ) {
        laneState.frontierSubSeq = finalizedCount;
        laneState.frontierLeaves = [];
      }
    }
  }

  if (!pass1Incomplete && params.latestRootHistory !== undefined) {
    params.store.pruneSealedBeforeSnapshot(params.latestRootHistory);
  }

  // =========================================================================
  // PASS 2: ALWAYS stream ALL new `NullifierPage`s unconditionally (ZERO oracle!)
  // =========================================================================
  // Even if Pass 1D experienced a transient `SubtreePage` miss, Pass 2 MUST STILL fetch every
  // `NullifierPage` uniformly so an adversarial RPC cannot drop a `SubtreePage` and observe
  // whether Pass 2 was skipped. If ANY Pass 1A/1D page was missing OR any lane had an
  // unverified miss, we guarantee unconditional rollback of `nextNfIndex` across ALL lanes on
  // BOTH normal return and error exits.
  const allLanesCaughtUp =
    !pass1Incomplete &&
    lanes.every((h) => params.store.lanes[h.laneId]!.nextMemoLeaf >= h.nextLeaf);
  const savedNextNfIndex = new Map<number, bigint>();
  for (const laneHdr of lanes) {
    savedNextNfIndex.set(laneHdr.laneId, params.store.lanes[laneHdr.laneId]!.nextNfIndex);
  }

  try {
    const nfStartIdxByLane = new Map<number, bigint>();
    for (const laneHdr of lanes) {
      nfStartIdxByLane.set(laneHdr.laneId, params.store.lanes[laneHdr.laneId]!.nextNfIndex);
    }

    // Optional birthdaySlot binary search on `64 B` NullifierPage headers for fresh wallets
    // (runs uniformly regardless of owned-note balance so RPC cannot infer first receipt;
    // keeps working start index local so Pass 2 errors never leak mutated `nextNfIndex`).
    if (birthdaySlot > 0n) {
      const nfBsStates: Array<{ laneId: number; nfCount: bigint; lo: bigint; hi: bigint }> = [];
      for (const laneHdr of lanes) {
        const l = laneHdr.laneId;
        const startIdx = nfStartIdxByLane.get(l) ?? params.store.lanes[l]!.nextNfIndex;
        if (laneHdr.nfCount > 0n && startIdx === 0n) {
          const targetNfMax = (laneHdr.nfCount - 1n) / nfSize;
          if (targetNfMax > 2n) {
            nfBsStates.push({ laneId: l, nfCount: laneHdr.nfCount, lo: 0n, hi: targetNfMax + 1n });
          }
        }
      }
      while (nfBsStates.some((s) => s.lo < s.hi)) {
        const active = nfBsStates.filter((s) => s.lo < s.hi);
        const mids = active.map((s) => s.lo + ((s.hi - s.lo) >> 1n));
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
          if (raw) {
            const hdr = decodeNullifierPageHeader(raw);
            if (hdr.poolId !== poolId || hdr.laneId !== st.laneId || hdr.pageSeq !== mid) {
              throw new Error(
                `NullifierPage header mismatch (expected pool=${poolId}, lane=${st.laneId}, seq=${mid})`,
              );
            }
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
          nfStartIdxByLane.set(st.laneId, skipTo < st.nfCount ? skipTo : st.nfCount);
        }
      }
    }

    // Lazily stream ALL new NullifierPages up to `laneHdr.nfCount` in uniform 100-account windows.
    // NEVER skip when 0 unspent notes exist, NEVER skip on Pass 1D miss, and NEVER break early
    // when the last unspent note is marked spent — stranger prefixes are discarded immediately.
    interface NfCursor {
      laneId: number;
      nextNf: bigint;
      endNf: bigint;
      maxNfIndex: bigint;
      stopped: boolean;
    }
    const nfCursors: NfCursor[] = [];
    for (const laneHdr of lanes) {
      const l = laneHdr.laneId;
      const startIdx = nfStartIdxByLane.get(l) ?? params.store.lanes[l]!.nextNfIndex;
      if (laneHdr.nfCount === 0n || startIdx >= laneHdr.nfCount) continue;
      nfCursors.push({
        laneId: l,
        nextNf: startIdx / nfSize,
        endNf: (laneHdr.nfCount - 1n) / nfSize,
        maxNfIndex: laneHdr.nfCount,
        stopped: false,
      });
    }

    let nfPagesFetched = 0;
    while (nfPagesFetched < MAX_SYNC_PAGES_PER_CALL) {
      const chunk: Array<{ cursor: NfCursor; pageSeq: bigint; addr: string }> = [];
      for (const cursor of nfCursors) {
        while (
          !cursor.stopped &&
          cursor.nextNf <= cursor.endNf &&
          chunk.length < RPC_BATCH_CHUNK &&
          nfPagesFetched + chunk.length < MAX_SYNC_PAGES_PER_CALL
        ) {
          const n = cursor.nextNf;
          cursor.nextNf = n + 1n;
          chunk.push({
            cursor,
            pageSeq: n,
            addr: deriveNfPagePdaSync(poolId, cursor.laneId, n, programId).address,
          });
        }
        if (
          chunk.length >= RPC_BATCH_CHUNK ||
          nfPagesFetched + chunk.length >= MAX_SYNC_PAGES_PER_CALL
        ) {
          break;
        }
      }
      if (chunk.length === 0) break;
      nfPagesFetched += chunk.length;
      const raws = await params.fetchBatch(chunk.map((q) => q.addr));
      for (let i = 0; i < chunk.length; i++) {
        const item = chunk[i]!;
        const cursor = item.cursor;
        if (cursor.stopped) continue;
        const raw = raws[i];
        if (!raw) {
          cursor.stopped = true;
          continue;
        }
        const hdr = decodeNullifierPageHeader(raw);
        if (
          hdr.poolId !== poolId ||
          hdr.laneId !== cursor.laneId ||
          hdr.pageSeq !== item.pageSeq
        ) {
          throw new Error(
            `NullifierPage header mismatch (expected pool=${poolId}, lane=${cursor.laneId}, seq=${item.pageSeq})`,
          );
        }
        const pageBase = item.pageSeq * nfSize;
        const expectedCap = Math.min(
          NF_PER_PAGE,
          cursor.maxNfIndex > pageBase ? Number(cursor.maxNfIndex - pageBase) : 0,
        );
        params.store.ingestNullifierPage({
          laneId: cursor.laneId,
          pageSeq: item.pageSeq,
          raw,
          maxNfIndex: cursor.maxNfIndex,
        });
        if (hdr.count < expectedCap) {
          cursor.stopped = true;
        }
      }
    }

    if (allLanesCaughtUp) {
      for (const [l, startIdx] of nfStartIdxByLane) {
        const laneState = params.store.lanes[l]!;
        if (startIdx > laneState.nextNfIndex) {
          laneState.nextNfIndex = startIdx;
        }
      }
    }
  } finally {
    // If Pass 1 was incomplete on any lane, unconditionally restore `nextNfIndex` on BOTH
    // normal return and error exits so notes discovered on retry are never skipped past their spends.
    if (!allLanesCaughtUp) {
      for (const [l, prevIdx] of savedNextNfIndex) {
        params.store.lanes[l]!.nextNfIndex = prevIdx;
      }
    }
  }

  return { pool, lanes, discoveredNotes };
}

const U32_MAX = 0xffff_ffff;
const U64_MAX = 0xffff_ffff_ffff_ffffn;
const ZERO_LANE_ROOT_BE = frToBeBytes(ZERO_HASHES_4ARY[LANE_DEPTH_4ARY]!);

function isAllZero32(b: unknown): boolean {
  if (!(b instanceof Uint8Array) || b.byteLength !== 32) return true;
  for (let i = 0; i < 32; i++) {
    if (b[i] !== 0) return false;
  }
  return true;
}

function verifyRootSnapshotIntegrity(
  superRoot: Uint8Array,
  laneRoots: ReadonlyArray<Uint8Array>,
): void {
  if (!(superRoot instanceof Uint8Array) || superRoot.byteLength !== 32 || isAllZero32(superRoot)) {
    throw new Error('GlobalRootHistory superRoot must not be all-zero');
  }
  if (!Array.isArray(laneRoots) || laneRoots.length !== NUM_LANES) {
    throw new RangeError(`Root snapshot must have ${NUM_LANES} laneRoots`);
  }
  const superRootFr = frFromBeBytesStrict(superRoot);
  const laneRootsFr = laneRoots.map((b, l) => {
    if (!(b instanceof Uint8Array) || b.byteLength !== 32) {
      throw new RangeError(`Root snapshot laneRoots[${l}] must be 32 bytes`);
    }
    return frFromBeBytesStrict(b);
  });
  if (computeSuperRoot4Ary(laneRootsFr) !== superRootFr) {
    throw new Error('Reconstructed Merkle root mismatch');
  }
}

/**
 * Strictly validate a decoded `GlobalRootHistory` before trusting any root or lane count from an
 * untrusted RPC: enforces u32 `poolId`, ring cursor/count and ring-array bounds, `epochInterval`,
 * `stableSlot <= latestSlot`, `stableEpochId === stableSlot / epochInterval`, `NUM_LANES` arrays,
 * `0..=MAX_LEAVES_PER_LANE` counts, `stableLaneCounts[l] <= latestLaneCounts[l]`, non-zero
 * `latest`/`stable` super-roots, ring cursor `superRoot` & `slot` equality, full canonical BN254
 * `Fr` + 4-ary super-root integrity for BOTH `latest` and `stable` snapshots, zero-count
 * `ZERO_HASHES_4ARY[18]` lane roots, and equal-count lane-root equality.
 */
export function validateGlobalRootHistory(history: DecodedGlobalRootHistory, poolId: number): void {
  if (!Number.isInteger(poolId) || poolId < 0 || poolId > U32_MAX) {
    throw new RangeError(`Invalid poolId ${String(poolId)}`);
  }
  if (!history || typeof history !== 'object') {
    throw new RangeError('GlobalRootHistory must be an object');
  }
  if (
    !Number.isInteger(history.poolId) ||
    history.poolId < 0 ||
    history.poolId > U32_MAX ||
    history.poolId !== poolId
  ) {
    throw new Error(
      `GlobalRootHistory header mismatch (expected pool=${poolId}, got pool=${String(history.poolId)})`,
    );
  }
  if (
    !Number.isInteger(history.slotCount) ||
    history.slotCount < 1 ||
    history.slotCount > SLOT_RING_LEN ||
    !Number.isInteger(history.slotCursor) ||
    history.slotCursor < 0 ||
    history.slotCursor >= history.slotCount ||
    !Number.isInteger(history.epochCount) ||
    history.epochCount < 1 ||
    history.epochCount > EPOCH_RING_LEN ||
    !Number.isInteger(history.epochCursor) ||
    history.epochCursor < 0 ||
    history.epochCursor >= history.epochCount ||
    !Array.isArray(history.slotRing) ||
    history.slotRing.length < history.slotCount ||
    !Array.isArray(history.epochRing) ||
    history.epochRing.length < history.epochCount
  ) {
    throw new Error('GlobalRootHistory ring cursor or count out of bounds');
  }
  if (
    typeof history.epochInterval !== 'bigint' ||
    history.epochInterval < 1n ||
    history.epochInterval > MAX_ROOT_EPOCH_INTERVAL
  ) {
    throw new RangeError(
      `GlobalRootHistory epochInterval out of range: ${String(history.epochInterval)}`,
    );
  }
  if (
    typeof history.latestSlot !== 'bigint' ||
    history.latestSlot < 0n ||
    history.latestSlot > U64_MAX ||
    typeof history.stableSlot !== 'bigint' ||
    history.stableSlot < 0n ||
    history.stableSlot > U64_MAX ||
    typeof history.stableEpochId !== 'bigint' ||
    history.stableEpochId < 0n ||
    history.stableEpochId > U64_MAX
  ) {
    throw new RangeError('GlobalRootHistory slot/epoch header fields must be u64 bigints');
  }
  if (history.stableSlot > history.latestSlot) {
    throw new Error(
      `GlobalRootHistory stableSlot (${history.stableSlot}) exceeds latestSlot (${history.latestSlot})`,
    );
  }
  if (history.stableEpochId !== history.stableSlot / history.epochInterval) {
    throw new Error(
      `GlobalRootHistory stableEpochId mismatch (expected ${history.stableSlot / history.epochInterval}, got ${history.stableEpochId})`,
    );
  }
  if (
    !Array.isArray(history.latestLaneRoots) ||
    history.latestLaneRoots.length !== NUM_LANES ||
    !Array.isArray(history.stableLaneRoots) ||
    history.stableLaneRoots.length !== NUM_LANES ||
    !Array.isArray(history.latestLaneCounts) ||
    history.latestLaneCounts.length !== NUM_LANES ||
    !Array.isArray(history.stableLaneCounts) ||
    history.stableLaneCounts.length !== NUM_LANES
  ) {
    throw new RangeError(`GlobalRootHistory must have ${NUM_LANES} lanes`);
  }
  for (let l = 0; l < NUM_LANES; l++) {
    const lr = history.latestLaneRoots[l];
    const sr = history.stableLaneRoots[l];
    if (!(lr instanceof Uint8Array) || lr.byteLength !== 32) {
      throw new RangeError(`GlobalRootHistory latestLaneRoots[${l}] must be 32 bytes`);
    }
    if (!(sr instanceof Uint8Array) || sr.byteLength !== 32) {
      throw new RangeError(`GlobalRootHistory stableLaneRoots[${l}] must be 32 bytes`);
    }
    const lc = history.latestLaneCounts[l];
    if (typeof lc !== 'bigint' || lc < 0n || lc > MAX_LEAVES_PER_LANE) {
      throw new RangeError(`GlobalRootHistory latestLaneCounts[${l}] out of range: ${String(lc)}`);
    }
    const sc = history.stableLaneCounts[l];
    if (typeof sc !== 'bigint' || sc < 0n || sc > MAX_LEAVES_PER_LANE) {
      throw new RangeError(`GlobalRootHistory stableLaneCounts[${l}] out of range: ${String(sc)}`);
    }
    if (sc > lc) {
      throw new Error(
        `GlobalRootHistory stableLaneCounts[${l}] (${sc}) exceeds latestLaneCounts[${l}] (${lc})`,
      );
    }
  }
  if (
    !(history.latestSuperRoot instanceof Uint8Array) ||
    history.latestSuperRoot.byteLength !== 32 ||
    isAllZero32(history.latestSuperRoot)
  ) {
    throw new Error('GlobalRootHistory latestSuperRoot must be a non-zero 32-byte root');
  }
  if (
    !(history.stableSuperRoot instanceof Uint8Array) ||
    history.stableSuperRoot.byteLength !== 32 ||
    isAllZero32(history.stableSuperRoot)
  ) {
    throw new Error('GlobalRootHistory stableSuperRoot must be a non-zero 32-byte root');
  }
  const latestEntry = history.slotRing[history.slotCursor];
  if (
    !latestEntry ||
    typeof latestEntry !== 'object' ||
    !(latestEntry.superRoot instanceof Uint8Array) ||
    latestEntry.superRoot.byteLength !== 32 ||
    compareBytes32(latestEntry.superRoot, history.latestSuperRoot) !== 0
  ) {
    throw new Error('GlobalRootHistory slotRing[slotCursor] superRoot mismatch');
  }
  if (typeof latestEntry.slot !== 'bigint' || latestEntry.slot !== history.latestSlot) {
    throw new Error('GlobalRootHistory slotRing[slotCursor] slot mismatch');
  }
  const stableEntry = history.epochRing[history.epochCursor];
  if (
    !stableEntry ||
    typeof stableEntry !== 'object' ||
    !(stableEntry.superRoot instanceof Uint8Array) ||
    stableEntry.superRoot.byteLength !== 32 ||
    compareBytes32(stableEntry.superRoot, history.stableSuperRoot) !== 0
  ) {
    throw new Error('GlobalRootHistory epochRing[epochCursor] superRoot mismatch');
  }
  if (typeof stableEntry.slot !== 'bigint' || stableEntry.slot !== history.stableSlot) {
    throw new Error('GlobalRootHistory epochRing[epochCursor] slot mismatch');
  }
  verifyRootSnapshotIntegrity(history.latestSuperRoot, history.latestLaneRoots);
  verifyRootSnapshotIntegrity(history.stableSuperRoot, history.stableLaneRoots);
  for (let l = 0; l < NUM_LANES; l++) {
    const lc = history.latestLaneCounts[l]!;
    const sc = history.stableLaneCounts[l]!;
    const lr = history.latestLaneRoots[l]!;
    const sr = history.stableLaneRoots[l]!;
    if ((lc === 0n) !== (compareBytes32(lr, ZERO_LANE_ROOT_BE) === 0)) {
      throw new Error(
        `GlobalRootHistory latestLaneRoots[${l}] must equal ZERO_HASHES_4ARY[18] iff count is 0`,
      );
    }
    if ((sc === 0n) !== (compareBytes32(sr, ZERO_LANE_ROOT_BE) === 0)) {
      throw new Error(
        `GlobalRootHistory stableLaneRoots[${l}] must equal ZERO_HASHES_4ARY[18] iff count is 0`,
      );
    }
    if ((sc === lc) !== (compareBytes32(sr, lr) === 0)) {
      throw new Error(
        `GlobalRootHistory stableLaneRoots[${l}] must equal latestLaneRoots[${l}] iff counts match`,
      );
    }
  }
}

/**
 * Strictly validate a `RootSnapshotChoice`: runtime shape, ring kind/index bounds, u64 `slot`,
 * non-zero canonical BN254 `Fr` `superRoot` & `laneRoots`, `computeSuperRoot4Ary(laneRoots) === superRoot`,
 * `laneCounts[l]` in `0n..=MAX_LEAVES_PER_LANE`, and `laneCounts[l] === 0n <=> laneRoots[l] === ZERO_HASHES_4ARY[18]`.
 */
export function validateRootSnapshotChoice(snapshot: RootSnapshotChoice): void {
  if (!snapshot || typeof snapshot !== 'object') {
    throw new RangeError('RootSnapshotChoice must be an object');
  }
  if (snapshot.ringKind === ROOT_RING_SLOT) {
    if (!Number.isInteger(snapshot.ringIdx) || snapshot.ringIdx < 0 || snapshot.ringIdx >= SLOT_RING_LEN) {
      throw new RangeError(
        `Invalid RootSnapshotChoice ringIdx=${String(snapshot.ringIdx)} for ROOT_RING_SLOT`,
      );
    }
  } else if (snapshot.ringKind === ROOT_RING_EPOCH) {
    if (!Number.isInteger(snapshot.ringIdx) || snapshot.ringIdx < 0 || snapshot.ringIdx >= EPOCH_RING_LEN) {
      throw new RangeError(
        `Invalid RootSnapshotChoice ringIdx=${String(snapshot.ringIdx)} for ROOT_RING_EPOCH`,
      );
    }
  } else {
    throw new RangeError(`Invalid RootSnapshotChoice ringKind=${String(snapshot.ringKind)}`);
  }
  if (typeof snapshot.slot !== 'bigint' || snapshot.slot < 0n || snapshot.slot > U64_MAX) {
    throw new RangeError(`Invalid RootSnapshotChoice slot=${String(snapshot.slot)}`);
  }
  if (
    !(snapshot.superRoot instanceof Uint8Array) ||
    snapshot.superRoot.byteLength !== 32 ||
    isAllZero32(snapshot.superRoot)
  ) {
    throw new RangeError('RootSnapshotChoice superRoot must be a non-zero 32-byte root');
  }
  if (
    !Array.isArray(snapshot.laneRoots) ||
    snapshot.laneRoots.length !== NUM_LANES ||
    !Array.isArray(snapshot.laneCounts) ||
    snapshot.laneCounts.length !== NUM_LANES
  ) {
    throw new RangeError(`RootSnapshotChoice must have ${NUM_LANES} lanes`);
  }
  for (let l = 0; l < NUM_LANES; l++) {
    const lr = snapshot.laneRoots[l];
    if (!(lr instanceof Uint8Array) || lr.byteLength !== 32) {
      throw new RangeError(`RootSnapshotChoice laneRoots[${l}] must be 32 bytes`);
    }
    const c = snapshot.laneCounts[l];
    if (typeof c !== 'bigint' || c < 0n || c > MAX_LEAVES_PER_LANE) {
      throw new RangeError(`RootSnapshotChoice laneCounts[${l}] out of range: ${String(c)}`);
    }
  }
  verifyRootSnapshotIntegrity(snapshot.superRoot, snapshot.laneRoots);
  for (let l = 0; l < NUM_LANES; l++) {
    if ((snapshot.laneCounts[l]! === 0n) !== (compareBytes32(snapshot.laneRoots[l]!, ZERO_LANE_ROOT_BE) === 0)) {
      throw new Error(
        `RootSnapshotChoice laneRoots[${l}] must equal ZERO_HASHES_4ARY[18] iff count is 0`,
      );
    }
  }
}

/**
 * Fetch and strictly validate `GlobalRootHistory` using a `finalized`-first + `confirmed`-fallback
 * strategy:
 * - Reads `finalized` first for maximum reorg-proof proving stability (`ROOT_RING_EPOCH` when
 *   covered, else `ROOT_RING_SLOT`).
 * - Seamlessly falls back to `confirmed` when a freshly deposited note in `requiredNotes` is not
 *   yet included in the `finalized` root history (enabling instant 0-slot spendability).
 */
export async function fetchGlobalRootHistory(params: {
  poolId?: number;
  programId?: string;
  fetchFinalized?: AccountBatchFetcher;
  fetchConfirmed?: AccountBatchFetcher;
  rpcUrl?: string;
  requiredNotes?: ReadonlyArray<{ laneId: number; leafIndex: bigint }>;
}): Promise<{
  history: DecodedGlobalRootHistory;
  snapshot: RootSnapshotChoice;
  commitment: 'finalized' | 'confirmed';
}> {
  const poolId = params.poolId ?? 0;
  if (!Number.isInteger(poolId) || poolId < 0 || poolId > U32_MAX) {
    throw new RangeError(`Invalid poolId ${poolId}`);
  }
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const requiredNotes = params.requiredNotes ?? [];
  for (const n of requiredNotes) {
    if (!Number.isInteger(n.laneId) || n.laneId < 0 || n.laneId >= NUM_LANES) {
      throw new RangeError(`Invalid requiredNotes laneId ${n.laneId}`);
    }
    if (typeof n.leafIndex !== 'bigint' || n.leafIndex < 0n) {
      throw new RangeError(`Invalid requiredNotes leafIndex ${String(n.leafIndex)}`);
    }
  }

  const fetchFinalized =
    params.fetchFinalized ??
    (params.rpcUrl ? createSolanaRpcBatchFetcher(params.rpcUrl, 'finalized') : undefined);
  const fetchConfirmed =
    params.fetchConfirmed ??
    (params.rpcUrl ? createSolanaRpcBatchFetcher(params.rpcUrl, 'confirmed') : undefined);
  if (!fetchFinalized && !fetchConfirmed) {
    throw new Error('fetchGlobalRootHistory requires rpcUrl or fetchFinalized/fetchConfirmed');
  }

  const rootsAddr = deriveRootsPdaSync(poolId, programId).address;
  const decodeAndSelect = (raw: Uint8Array): { history: DecodedGlobalRootHistory; snapshot: RootSnapshotChoice | null } => {
    const history = decodeGlobalRootHistory(raw);
    validateGlobalRootHistory(history, poolId);
    const snapshot = selectRootSnapshotForNotes(history, requiredNotes);
    return { history, snapshot };
  };

  let finalizedHistory: DecodedGlobalRootHistory | null = null;
  let finalizedSlotFallback: {
    history: DecodedGlobalRootHistory;
    snapshot: RootSnapshotChoice;
  } | null = null;
  if (fetchFinalized) {
    const [raw] = await fetchFinalized([rootsAddr]);
    if (raw) {
      const { history, snapshot } = decodeAndSelect(raw);
      finalizedHistory = history;
      if (snapshot) {
        if (snapshot.ringKind === ROOT_RING_EPOCH) {
          return { history, snapshot, commitment: 'finalized' };
        }
        finalizedSlotFallback = { history, snapshot };
      }
    }
  }

  if (fetchConfirmed) {
    const [raw] = await fetchConfirmed([rootsAddr]);
    if (!raw) {
      if (finalizedSlotFallback) {
        return { ...finalizedSlotFallback, commitment: 'finalized' };
      }
      throw new Error(`GlobalRootHistory missing at ${rootsAddr}`);
    }
    const { history: confirmedHistory, snapshot: confirmedSnapshot } = decodeAndSelect(raw);
    if (!confirmedSnapshot) {
      if (finalizedSlotFallback) {
        return { ...finalizedSlotFallback, commitment: 'finalized' };
      }
      throw new Error('Required notes not yet included in GlobalRootHistory');
    }
    if (finalizedHistory) {
      let confirmedNotBehind =
        confirmedHistory.epochInterval === finalizedHistory.epochInterval &&
        confirmedHistory.latestSlot >= finalizedHistory.latestSlot &&
        confirmedHistory.stableSlot >= finalizedHistory.stableSlot;
      let confirmedStrictlyAhead = confirmedHistory.latestSlot > finalizedHistory.latestSlot;
      for (let l = 0; l < NUM_LANES; l++) {
        const confLatest = confirmedHistory.latestLaneCounts[l]!;
        const finLatest = finalizedHistory.latestLaneCounts[l]!;
        const confStable = confirmedHistory.stableLaneCounts[l]!;
        const finStable = finalizedHistory.stableLaneCounts[l]!;
        const confLatestRoot = confirmedHistory.latestLaneRoots[l]!;
        const finLatestRoot = finalizedHistory.latestLaneRoots[l]!;
        const confStableRoot = confirmedHistory.stableLaneRoots[l]!;
        const finStableRoot = finalizedHistory.stableLaneRoots[l]!;
        if (
          confLatest < finLatest ||
          confStable < finStable ||
          (confLatest === finLatest && compareBytes32(confLatestRoot, finLatestRoot) !== 0) ||
          (confStable === finStable && compareBytes32(confStableRoot, finStableRoot) !== 0) ||
          (confStable === finLatest && compareBytes32(confStableRoot, finLatestRoot) !== 0) ||
          (confLatest === finStable && compareBytes32(confLatestRoot, finStableRoot) !== 0)
        ) {
          confirmedNotBehind = false;
        }
        if (confLatest > finLatest) {
          confirmedStrictlyAhead = true;
        }
      }
      if (finalizedSlotFallback) {
        const finChoice = finalizedSlotFallback.snapshot;
        const confirmedSlotEntry = confirmedHistory.slotRing[finChoice.ringIdx];
        const slotEntryEvicted =
          !confirmedSlotEntry ||
          compareBytes32(confirmedSlotEntry.superRoot, finChoice.superRoot) !== 0;
        const upgradeToConfirmed =
          confirmedNotBehind &&
          confirmedStrictlyAhead &&
          (confirmedSnapshot.ringKind === ROOT_RING_EPOCH ||
            (confirmedSnapshot.ringKind === ROOT_RING_SLOT &&
              (confirmedSnapshot.slot > finChoice.slot ||
                confirmedSnapshot.ringIdx !== finChoice.ringIdx ||
                slotEntryEvicted)));
        if (upgradeToConfirmed) {
          return {
            history: confirmedHistory,
            snapshot: confirmedSnapshot,
            commitment: 'confirmed',
          };
        }
        return { ...finalizedSlotFallback, commitment: 'finalized' };
      }
      if (!confirmedNotBehind) {
        throw new Error('Confirmed GlobalRootHistory lags behind finalized snapshot');
      }
    }
    return {
      history: confirmedHistory,
      snapshot: confirmedSnapshot,
      commitment: 'confirmed',
    };
  }

  if (finalizedSlotFallback) {
    return { ...finalizedSlotFallback, commitment: 'finalized' };
  }

  throw new Error(
    finalizedHistory
      ? 'Required notes not yet included in finalized GlobalRootHistory'
      : `GlobalRootHistory missing at ${rootsAddr}`,
  );
}

export interface ReconstructedWitnessResult {
  roots: DecodedGlobalRootHistory | null;
  snapshot: RootSnapshotChoice;
  rootRingKind: number;
  rootRingIdx: number;
  superRoot: bigint;
  snapshotSlot: bigint;
  laneRoots: Uint8Array[];
  laneCounts: bigint[];
  path: MerklePath4Ary;
}

/**
 * Stateless witness reconstruction for `(laneId, leafIdx)` against `GlobalRootHistory`
 * (`deriveRootsPdaSync(poolId)`).
 *
 * Supports multi-note snapshot selection (`allInputNotes` or pre-selected `rootSnapshot`) so
 * 2-input `Transact` / `ExecViaEscrow` and multi-instruction batches all prove against the exact
 * same `(rootRingKind, rootRingIdx, superRoot)`.
 *
 * In default `'strict'` mode, eliminates `laneId` and pinpoint-spend correlation:
 * - Requires a 32-byte `viewSk` (preventing fresh-key retry intersection).
 * - Fetches ALL active lanes' `SubtreeRootPage`s uniformly (never capped by `neededSrPages`).
 * - Fetches ALL active lanes' unsealed frontier `SubtreePage`s uniformly (never only `params.laneId`).
 * - Fetches `min(16, totalSealed)` sealed `SubtreePage`s via Rendezvous (HRW) hashing scoped to
 *   `("witness" || laneId || targetPageSeq_le8, epochBucket=0)` so spending two different notes
 *   in the same epoch uses independent decoy sets while retries of the same note stay identical.
 * - Shuffles the combined batch, fetches in 100-account chunks, and uniformly validates EVERY
 *   fetched page (both target AND decoy/non-target lanes) so an adversarial RPC dropping half the
 *   batch cannot learn which lane or page is the user's.
 * - Verifies `computeMerkleRoot4Ary(path, targetLeaf) === superRoot` before returning.
 */
export async function reconstructWitness(params: {
  fetchBatch: AccountBatchFetcher;
  poolId: number;
  laneId: number;
  leafIdx: bigint;
  allInputNotes?: ReadonlyArray<{ laneId: number; leafIndex: bigint }>;
  rootSnapshot?: RootSnapshotChoice;
  rootHistory?: DecodedGlobalRootHistory;
  programId?: string;
  privacyMode?: SyncPrivacyMode;
  viewSk?: Uint8Array;
  decoyEpochBucket?: bigint;
}): Promise<ReconstructedWitnessResult> {
  if (!params || typeof params !== 'object') {
    throw new RangeError('reconstructWitness params must be an object');
  }
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const privacyMode: SyncPrivacyMode =
    params.privacyMode === undefined ? 'strict' : params.privacyMode;
  if (privacyMode !== 'strict' && privacyMode !== 'fast') {
    throw new RangeError(`Invalid privacyMode: ${String(privacyMode)}`);
  }
  if (!Number.isInteger(params.poolId) || params.poolId < 0 || params.poolId > U32_MAX) {
    throw new RangeError(`Invalid poolId ${params.poolId}`);
  }
  if (!Number.isInteger(params.laneId) || params.laneId < 0 || params.laneId >= NUM_LANES) {
    throw new RangeError(`Invalid laneId ${params.laneId}`);
  }
  if (typeof params.leafIdx !== 'bigint' || params.leafIdx < 0n) {
    throw new RangeError(`Invalid leafIdx ${String(params.leafIdx)}`);
  }
  if (params.allInputNotes) {
    for (const n of params.allInputNotes) {
      if (!Number.isInteger(n.laneId) || n.laneId < 0 || n.laneId >= NUM_LANES) {
        throw new RangeError(`Invalid allInputNotes laneId ${n.laneId}`);
      }
      if (typeof n.leafIndex !== 'bigint' || n.leafIndex < 0n) {
        throw new RangeError(`Invalid allInputNotes leafIndex ${String(n.leafIndex)}`);
      }
    }
  }
  if (params.rootSnapshot !== undefined) {
    validateRootSnapshotChoice(params.rootSnapshot);
  }
  if (privacyMode === 'strict') {
    if (!(params.viewSk instanceof Uint8Array) || params.viewSk.byteLength !== 32) {
      throw new RangeError(
        "reconstructWitness requires a 32-byte Uint8Array viewSk in 'strict' mode (use privacyMode: 'fast' for trusted/local RPCs)",
      );
    }
  }
  if (
    params.decoyEpochBucket !== undefined &&
    (typeof params.decoyEpochBucket !== 'bigint' ||
      params.decoyEpochBucket < 0n ||
      params.decoyEpochBucket > U64_MAX)
  ) {
    throw new RangeError(`Invalid decoyEpochBucket: ${String(params.decoyEpochBucket)}`);
  }

  const subSize = BigInt(SUBTREE_LEAVES);
  const srSize = BigInt(SUBROOTS_PER_PAGE);

  let roots: DecodedGlobalRootHistory | null = params.rootHistory ?? null;
  let chosen: RootSnapshotChoice;
  const notesToCover: Array<{ laneId: number; leafIndex: bigint }> = [
    { laneId: params.laneId, leafIndex: params.leafIdx },
    ...(params.allInputNotes ?? []),
  ];

  if (params.rootSnapshot !== undefined) {
    if (params.rootHistory !== undefined) {
      validateGlobalRootHistory(params.rootHistory, params.poolId);
    }
    chosen = params.rootSnapshot;
    for (const n of notesToCover) {
      if (n.leafIndex >= chosen.laneCounts[n.laneId]!) {
        throw new Error('leafIdx >= snapshot lane count');
      }
    }
  } else {
    if (params.rootHistory === undefined) {
      const rootsAddr = deriveRootsPdaSync(params.poolId, programId).address;
      const [rootsRaw] = await params.fetchBatch([rootsAddr]);
      if (!rootsRaw) throw new Error(`GlobalRootHistory missing at ${rootsAddr}`);
      roots = decodeGlobalRootHistory(rootsRaw);
    }
    validateGlobalRootHistory(roots as DecodedGlobalRootHistory, params.poolId);
    const selected = selectRootSnapshotForNotes(roots as DecodedGlobalRootHistory, notesToCover);
    if (!selected) {
      throw new Error('leafIdx >= GlobalRootHistory lane count');
    }
    chosen = selected;
  }

  const snapCount = chosen.laneCounts[params.laneId]!;
  if (params.leafIdx >= snapCount) throw new Error('leafIdx >= snapshot lane count');

  const snapLaneRootsFr = chosen.laneRoots.map((b) => frFromBeBytesStrict(b));
  const superRoot = frFromBeBytesStrict(chosen.superRoot);
  if (computeSuperRoot4Ary(snapLaneRootsFr) !== superRoot) {
    throw new Error('Reconstructed Merkle root mismatch');
  }

  const targetPageIdx = params.leafIdx / subSize;
  const targetOffset = Number(params.leafIdx % subSize);
  const frontierPageIdx = snapCount / subSize;
  const frontierRem = Number(snapCount % subSize);
  const neededSrPages = Math.ceil(Number(frontierPageIdx) / SUBROOTS_PER_PAGE);
  if (neededSrPages > MAX_WITNESS_SR_PAGES) {
    throw new RangeError(
      `Root snapshot requires ${neededSrPages} SubtreeRootPages (exceeds witness bound ${MAX_WITNESS_SR_PAGES})`,
    );
  }

  if (privacyMode === 'strict') {
    let totalSrPages = 0;
    let totalSealedBound = 0n;
    for (let l = 0; l < NUM_LANES; l++) {
      const laneSealed = chosen.laneCounts[l]! / subSize;
      totalSealedBound += laneSealed;
      if (laneSealed > 0n) {
        totalSrPages += Math.ceil(Number(laneSealed) / SUBROOTS_PER_PAGE);
      }
    }
    if (totalSrPages > MAX_WITNESS_SR_PAGES) {
      throw new RangeError(
        `Root snapshot requires ${totalSrPages} SubtreeRootPages across active lanes (exceeds witness bound ${MAX_WITNESS_SR_PAGES})`,
      );
    }
    if (totalSealedBound > BigInt(MAX_HRW_SEALED_SUBTREES)) {
      throw new RangeError(
        `Root snapshot total sealed subtrees (${totalSealedBound}) exceeds HRW bound (${MAX_HRW_SEALED_SUBTREES})`,
      );
    }
  }

  const targetSrAddrs: string[] = [];
  const srExpected = new Map<string, { laneId: number; rootPageSeq: bigint; expectedMin: number }>();
  for (let rp = 0; rp < neededSrPages; rp++) {
    const rpBig = BigInt(rp);
    const rem = frontierPageIdx - rpBig * srSize;
    const expectedMin = Number(rem < srSize ? rem : srSize);
    const addr = deriveSubrootPdaSync(params.poolId, params.laneId, rpBig, programId).address;
    targetSrAddrs.push(addr);
    srExpected.set(addr, { laneId: params.laneId, rootPageSeq: rpBig, expectedMin });
  }

  const targetSubAddr = deriveSubtreePdaSync(
    params.poolId,
    params.laneId,
    targetPageIdx,
    programId,
  ).address;
  const targetExpectedMin = targetPageIdx < frontierPageIdx ? SUBTREE_LEAVES : frontierRem;
  const needDistinctFrontier = frontierRem > 0 && frontierPageIdx !== targetPageIdx;
  const frontierSubAddr = needDistinctFrontier
    ? deriveSubtreePdaSync(params.poolId, params.laneId, frontierPageIdx, programId).address
    : null;

  const subExpected = new Map<string, { laneId: number; pageSeq: bigint; expectedMin: number }>();
  subExpected.set(targetSubAddr, {
    laneId: params.laneId,
    pageSeq: targetPageIdx,
    expectedMin: targetExpectedMin,
  });
  if (frontierSubAddr) {
    subExpected.set(frontierSubAddr, {
      laneId: params.laneId,
      pageSeq: frontierPageIdx,
      expectedMin: frontierRem,
    });
  }

  if (privacyMode === 'strict') {
    const sealedByLane: Array<{ laneId: number; sealedCount: bigint }> = [];
    const alreadySealed = new Set<string>();
    if (targetPageIdx < frontierPageIdx) {
      alreadySealed.add(`${params.laneId}:${targetPageIdx.toString()}`);
    }
    let totalSealed = 0n;

    for (let l = 0; l < NUM_LANES; l++) {
      const cnt = chosen.laneCounts[l]!;
      const laneSealed = cnt / subSize;
      const laneFrontierRem = Number(cnt % subSize);
      sealedByLane.push({ laneId: l, sealedCount: laneSealed });
      totalSealed += laneSealed;

      // Uniformly fetch ALL active lanes' SubtreeRootPages (never capped by `neededSrPages`)
      if (laneSealed > 0n) {
        const laneSrPages = Math.ceil(Number(laneSealed) / SUBROOTS_PER_PAGE);
        for (let rp = 0; rp < laneSrPages; rp++) {
          const rpBig = BigInt(rp);
          const rem = laneSealed - rpBig * srSize;
          const expectedMin = Number(rem < srSize ? rem : srSize);
          const addr = deriveSubrootPdaSync(params.poolId, l, rpBig, programId).address;
          if (!srExpected.has(addr)) {
            srExpected.set(addr, { laneId: l, rootPageSeq: rpBig, expectedMin });
          }
        }
      }

      // Uniformly fetch ALL active lanes' unsealed frontier SubtreePages (zero laneId leak)
      if (laneFrontierRem > 0) {
        const addr = deriveSubtreePdaSync(params.poolId, l, laneSealed, programId).address;
        if (!subExpected.has(addr)) {
          subExpected.set(addr, {
            laneId: l,
            pageSeq: laneSealed,
            expectedMin: laneFrontierRem,
          });
        }
      }
    }

    if (totalSealed > 0n) {
      const targetSealed = Number(
        totalSealed < BigInt(STRICT_DECOY_SEALED_SUBTREE_TARGET)
          ? totalSealed
          : BigInt(STRICT_DECOY_SEALED_SUBTREE_TARGET),
      );
      const epochBucket = params.decoyEpochBucket ?? 0n;
      const decoys = selectHrwSealedDecoys({
        viewSk: params.viewSk!,
        scope: makeWitnessDecoyScope(params.laneId, targetPageIdx),
        epochBucket,
        sealedByLane,
        alreadySelected: alreadySealed,
        targetSealed,
      });
      for (const d of decoys) {
        const addr = deriveSubtreePdaSync(params.poolId, d.laneId, d.pageSeq, programId).address;
        if (!subExpected.has(addr)) {
          subExpected.set(addr, {
            laneId: d.laneId,
            pageSeq: d.pageSeq,
            expectedMin: SUBTREE_LEAVES,
          });
        }
      }
    }
  }

  const addrs = [...srExpected.keys(), ...subExpected.keys()];
  if (addrs.length > 1) {
    shuffleInPlace(addrs);
  }

  const rawByAddr = new Map<string, Uint8Array | null>();
  for (let off = 0; off < addrs.length; off += RPC_BATCH_CHUNK) {
    const chunk = addrs.slice(off, off + RPC_BATCH_CHUNK);
    const raws = await params.fetchBatch(chunk);
    for (let i = 0; i < chunk.length; i++) {
      rawByAddr.set(chunk[i]!, raws[i] ?? null);
    }
  }

  // Privacy & integrity invariant (R1-C1 + R2-C2): uniformly validate EVERY requested page
  // (both target AND decoy/non-target lanes in 'strict' mode) for presence, header, count,
  // strict canonical BN254 Fr on ALL `0..count` entries, sealed subtree root parity, and
  // per-lane Merkle root parity against `chosen.laneRoots` before extracting target witness data.
  const decodedSrFrByAddr = new Map<string, bigint[]>();
  const decodedSrFrByKey = new Map<string, bigint[]>();
  const decodedSubFrByAddr = new Map<string, bigint[]>();
  const decodedSubFrByKey = new Map<string, bigint[]>();
  for (const addr of addrs) {
    const srExp = srExpected.get(addr);
    if (srExp) {
      const srRaw = rawByAddr.get(addr);
      if (!srRaw) throw new Error('SubtreeRootPage missing');
      const sr = decodeSubtreeRootPage(srRaw);
      if (
        sr.poolId !== params.poolId ||
        sr.laneId !== srExp.laneId ||
        sr.rootPageSeq !== srExp.rootPageSeq
      ) {
        throw new Error('SubtreeRootPage header mismatch');
      }
      if (sr.count < srExp.expectedMin) {
        throw new Error('SubtreeRootPage truncated');
      }
      const rootsFr = sr.roots.map((b) => frFromBeBytesStrict(b));
      decodedSrFrByAddr.set(addr, rootsFr);
      decodedSrFrByKey.set(`${srExp.laneId}:${srExp.rootPageSeq.toString()}`, rootsFr);
      continue;
    }
    const subExp = subExpected.get(addr);
    if (subExp) {
      const subRaw = rawByAddr.get(addr);
      if (!subRaw) throw new Error('SubtreePage missing');
      const sub = decodeSubtreePage(subRaw);
      if (
        sub.poolId !== params.poolId ||
        sub.laneId !== subExp.laneId ||
        sub.pageSeq !== subExp.pageSeq
      ) {
        throw new Error('SubtreePage header mismatch');
      }
      if (sub.count < subExp.expectedMin) {
        throw new Error('SubtreePage truncated');
      }
      const leavesFr = sub.leaves.map((b) => frFromBeBytesStrict(b));
      decodedSubFrByAddr.set(addr, leavesFr);
      decodedSubFrByKey.set(`${subExp.laneId}:${subExp.pageSeq.toString()}`, leavesFr);
    }
  }

  if (privacyMode === 'strict') {
    // (b) Verify EVERY fetched sealed SubtreePage (target AND decoy) against its SubtreeRootPage entry.
    for (const subExp of subExpected.values()) {
      const laneSealed = chosen.laneCounts[subExp.laneId]! / subSize;
      if (subExp.pageSeq < laneSealed) {
        const leavesFr = decodedSubFrByKey.get(`${subExp.laneId}:${subExp.pageSeq.toString()}`);
        const srSeq = subExp.pageSeq / srSize;
        const srSlot = Number(subExp.pageSeq % srSize);
        const srRootsFr = decodedSrFrByKey.get(`${subExp.laneId}:${srSeq.toString()}`);
        if (
          !leavesFr ||
          leavesFr.length < SUBTREE_LEAVES ||
          !srRootsFr ||
          srSlot >= srRootsFr.length
        ) {
          throw new Error('Reconstructed Merkle root mismatch');
        }
        if (computeSubtree256Root(leavesFr, SUBTREE_LEAVES) !== srRootsFr[srSlot]) {
          throw new Error('Reconstructed Merkle root mismatch');
        }
      }
    }

    // (c) Verify EVERY lane's rolled-up root (all 16 lanes) matches `chosen.laneRoots[l]`.
    for (let l = 0; l < NUM_LANES; l++) {
      const cnt = chosen.laneCounts[l]!;
      if (cnt === 0n) {
        if (snapLaneRootsFr[l] !== ZERO_HASHES_4ARY[LANE_DEPTH_4ARY]) {
          throw new Error('Reconstructed Merkle root mismatch');
        }
        continue;
      }
      const laneSealed = cnt / subSize;
      const laneFrontierRem = Number(cnt % subSize);
      const laneSrPages = Math.ceil(Number(laneSealed) / SUBROOTS_PER_PAGE);
      const laneFinalizedRoots: bigint[] = [];
      for (let rp = 0; rp < laneSrPages; rp++) {
        const srRootsFr = decodedSrFrByKey.get(`${l}:${rp}`);
        if (!srRootsFr) throw new Error('SubtreeRootPage missing');
        for (const r of srRootsFr) {
          if (laneFinalizedRoots.length === Number(laneSealed)) break;
          laneFinalizedRoots.push(r);
        }
      }
      if (laneFinalizedRoots.length !== Number(laneSealed)) {
        throw new Error('SubtreeRootPage missing finalized roots');
      }
      const laneFrontierLeaves =
        laneFrontierRem > 0
          ? decodedSubFrByKey.get(`${l}:${laneSealed.toString()}`)
          : undefined;
      const computedLaneRoot = computeLaneRootFromSubrootsAndFrontier(
        laneFinalizedRoots,
        laneFrontierLeaves,
        laneFrontierRem,
      );
      if (computedLaneRoot !== snapLaneRootsFr[l]) {
        throw new Error('Reconstructed Merkle root mismatch');
      }
    }
  }

  const finalizedRoots: bigint[] = [];
  for (let rp = 0; rp < neededSrPages; rp++) {
    const srRootsFr = decodedSrFrByAddr.get(targetSrAddrs[rp]!);
    if (!srRootsFr) throw new Error('SubtreeRootPage missing');
    for (const r of srRootsFr) {
      if (finalizedRoots.length === Number(frontierPageIdx)) break;
      finalizedRoots.push(r);
    }
  }
  if (finalizedRoots.length !== Number(frontierPageIdx)) {
    throw new Error('SubtreeRootPage missing finalized roots');
  }

  const targetLeaves = decodedSubFrByAddr.get(targetSubAddr);
  if (!targetLeaves) throw new Error('SubtreePage missing');
  if (targetLeaves.length < targetExpectedMin || targetOffset >= targetExpectedMin) {
    throw new Error('SubtreePage truncated');
  }

  let frontierLeaves: bigint[] | undefined;
  if (frontierRem > 0) {
    if (frontierSubAddr) {
      frontierLeaves = decodedSubFrByAddr.get(frontierSubAddr);
      if (!frontierLeaves) throw new Error('SubtreePage missing');
    } else {
      frontierLeaves = targetLeaves;
    }
    if (frontierLeaves.length < frontierRem) {
      throw new Error('SubtreePage truncated');
    }
  }

  const path = buildHistoricalWitness4Ary({
    laneId: params.laneId,
    targetLeafIdx: params.leafIdx,
    laneRoots: snapLaneRootsFr,
    laneLeafCount: snapCount,
    finalizedSubtreeRoots: finalizedRoots,
    targetPageLeaves: targetLeaves,
    frontierPageLeaves: frontierLeaves,
  });
  if (computeMerkleRoot4Ary(path, targetLeaves[targetOffset]!) !== superRoot) {
    throw new Error('Reconstructed Merkle root mismatch');
  }
  return {
    roots,
    snapshot: chosen,
    rootRingKind: chosen.ringKind,
    rootRingIdx: chosen.ringIdx,
    superRoot,
    snapshotSlot: chosen.slot,
    laneRoots: chosen.laneRoots,
    laneCounts: chosen.laneCounts,
    path,
  };
}
