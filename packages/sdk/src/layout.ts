/**
 * Zero-copy Audren account decoders matching `crates/audren-core/src/layout.rs` byte-for-byte.
 */

import {
  EPOCH_RING_LEN,
  LANE_DEPTH_4ARY,
  LANE_MAGIC,
  LANE_STATE_LEN,
  LN_OFF_BUMP,
  LN_OFF_CURRENT_ROOT,
  LN_OFF_LANE_ID,
  LN_OFF_NEXT_LEAF,
  LN_OFF_NF_COUNT,
  LN_OFF_POOL_ID,
  LN_OFF_RENT_BUMP,
  LN_OFF_VERSION,
  MAX_ROOT_EPOCH_INTERVAL,
  MEMO_CT_LEN,
  MEMO_MAGIC,
  MEMO_NOTES_PER_PAGE,
  MEMO_PAGE_HEADER_LEN,
  MEMO_PAGE_LEN,
  MEMO_PAGE_SCAN_SLICE_LEN,
  MM_OFF_BUMP,
  MM_OFF_CIPHERTEXTS,
  MM_OFF_CLOSED_SLOT,
  MM_OFF_COUNT,
  MM_OFF_CREATED_SLOT,
  MM_OFF_EPHEMERAL_PKS,
  MM_OFF_LANE_ID,
  MM_OFF_PAGE_SEQ,
  MM_OFF_POOL_ID,
  MM_OFF_VIEW_TAGS,
  NF_OFF_BUMP,
  NF_OFF_CLOSED_SLOT,
  NF_OFF_COUNT,
  NF_OFF_CREATED_SLOT,
  NF_OFF_LANE_ID,
  NF_OFF_PAGE_SEQ,
  NF_OFF_POOL_ID,
  NF_OFF_PREFIXES,
  NF_PAGE_HEADER_LEN,
  NF_PAGE_LEN,
  NF_PAGE_MAGIC,
  NF_PER_PAGE,
  NF_PREFIX_LEN,
  NUM_LANES,
  PL_OFF_ACTIVE_LANES,
  PL_OFF_AUTHORITY,
  PL_OFF_BUMP,
  PL_OFF_NF_RENT_FEE,
  PL_OFF_NOTE_RENT_FEE,
  PL_OFF_PAUSED,
  PL_OFF_PENDING_AUTHORITY,
  PL_OFF_POOL_ID,
  PL_OFF_ROOT_EPOCH_INTERVAL,
  PL_OFF_VAULT_AUTH_BUMP,
  PL_OFF_VERSION,
  POOL_MAGIC,
  POOL_STATE_LEN,
  PROTOCOL_VERSION,
  ROOTS_MAGIC,
  ROOT_ENTRY_LEN,
  ROOT_HISTORY_LEN,
  ROOT_RING_EPOCH,
  ROOT_RING_SLOT,
  RT_OFF_BUMP,
  RT_OFF_EPOCH_COUNT,
  RT_OFF_EPOCH_CURSOR,
  RT_OFF_EPOCH_INTERVAL,
  RT_OFF_EPOCH_RING,
  RT_OFF_GROUP_ROOTS,
  RT_OFF_LATEST_LANE_COUNTS,
  RT_OFF_LATEST_LANE_ROOTS,
  RT_OFF_LATEST_SLOT,
  RT_OFF_LATEST_SUPER_ROOT,
  RT_OFF_POOL_ID,
  RT_OFF_SAME_SLOT_BUMPED,
  RT_OFF_SLOT_COUNT,
  RT_OFF_SLOT_CURSOR,
  RT_OFF_SLOT_RING,
  RT_OFF_STABLE_EPOCH_ID,
  RT_OFF_STABLE_LANE_COUNTS,
  RT_OFF_STABLE_LANE_ROOTS,
  RT_OFF_STABLE_SLOT,
  RT_OFF_STABLE_SUPER_ROOT,
  RT_OFF_VERSION,
  SB_OFF_BUMP,
  SB_OFF_COUNT,
  SB_OFF_LANE_ID,
  SB_OFF_LEAVES,
  SB_OFF_PAGE_SEQ,
  SB_OFF_POOL_ID,
  SLOT_RING_LEN,
  SR_OFF_BUMP,
  SR_OFF_COUNT,
  SR_OFF_LANE_ID,
  SR_OFF_POOL_ID,
  SR_OFF_ROOTS,
  SR_OFF_ROOT_PAGE_SEQ,
  SUBROOTS_PER_PAGE,
  SUBROOT_MAGIC,
  SUBROOT_PAGE_LEN,
  SUBTREE_LEAVES,
  SUBTREE_MAGIC,
  SUBTREE_PAGE_LEN,
  ZERO_HASHES_4ARY,
} from './constants.ts';
import { base58Encode } from './pda.ts';

/** Maximum note commitments per lane (`4^18 = 2^36 = 68,719,476,736`). */
export const MAX_LEAVES_PER_LANE = 1n << 36n;

const U64_MAX = 0xffff_ffff_ffff_ffffn;

function bigintToBe32(x: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = x;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

const ZERO_LANE_ROOT_BE = bigintToBe32(ZERO_HASHES_4ARY[LANE_DEPTH_4ARY]!);

const asciiDecoder = new TextDecoder('ascii');

function checkMagic(data: Uint8Array, expected: string): boolean {
  if (!(data instanceof Uint8Array) || data.byteLength < 8) return false;
  return asciiDecoder.decode(data.subarray(0, 8)) === expected;
}

export interface DecodedPoolState {
  version: number;
  bump: number;
  paused: boolean;
  activeLanes: number;
  poolId: number;
  rootEpochInterval: bigint;
  authority: string;
  authorityBytes: Uint8Array;
  vaultAuthBump: number;
  noteRentFee: bigint;
  nfRentFee: bigint;
  pendingAuthority: Uint8Array;
}

export interface DecodedLaneHeader {
  version: number;
  laneId: number;
  bump: number;
  rentBump: number;
  poolId: number;
  nextLeaf: bigint;
  nfCount: bigint;
  currentRoot: Uint8Array;
}

export interface RootEntry {
  superRoot: Uint8Array;
  slot: bigint;
}

export interface RootSnapshotChoice {
  ringKind: number;
  ringIdx: number;
  slot: bigint;
  superRoot: Uint8Array;
  laneRoots: Uint8Array[];
  laneCounts: bigint[];
}

export interface DecodedGlobalRootHistory {
  version: number;
  bump: number;
  slotCursor: number;
  poolId: number;
  epochCursor: number;
  slotCount: number;
  epochCount: number;
  sameSlotBumped: boolean;
  latestSlot: bigint;
  stableEpochId: bigint;
  stableSlot: bigint;
  epochInterval: bigint;
  groupRoots: Uint8Array[];
  latestSuperRoot: Uint8Array;
  latestLaneRoots: Uint8Array[];
  latestLaneCounts: bigint[];
  stableSuperRoot: Uint8Array;
  stableLaneRoots: Uint8Array[];
  stableLaneCounts: bigint[];
  slotRing: RootEntry[];
  epochRing: RootEntry[];
}

export interface DecodedSubtreePage {
  laneId: number;
  bump: number;
  count: number;
  poolId: number;
  pageSeq: bigint;
  leaves: Uint8Array[];
}

export interface DecodedSubtreeRootPage {
  laneId: number;
  bump: number;
  count: number;
  poolId: number;
  rootPageSeq: bigint;
  roots: Uint8Array[];
}

export interface DecodedMemoEntry {
  viewTag: Uint8Array;
  ephemeralPk: Uint8Array;
  ciphertext: Uint8Array;
}

export interface DecodedMemoPage {
  laneId: number;
  bump: number;
  count: number;
  poolId: number;
  pageSeq: bigint;
  createdSlot: bigint;
  closedSlot: bigint;
  entries: DecodedMemoEntry[];
}

export interface DecodedMemoPageHeader {
  laneId: number;
  bump: number;
  count: number;
  poolId: number;
  pageSeq: bigint;
  createdSlot: bigint;
  closedSlot: bigint;
}

export interface DecodedMemoPageScanSlice extends DecodedMemoPageHeader {
  viewTags: Uint8Array[];
  ephemeralPks: Uint8Array[];
  hasCiphertexts: boolean;
}

export interface DecodedNullifierPageHeader {
  laneId: number;
  bump: number;
  count: number;
  poolId: number;
  pageSeq: bigint;
  createdSlot: bigint;
  closedSlot: bigint;
}

export interface DecodedNullifierPage {
  laneId: number;
  bump: number;
  count: number;
  poolId: number;
  pageSeq: bigint;
  createdSlot: bigint;
  closedSlot: bigint;
  prefixes: Uint8Array[];
}

export function decodePoolState(data: Uint8Array): DecodedPoolState {
  if (!(data instanceof Uint8Array) || data.byteLength !== POOL_STATE_LEN || !checkMagic(data, POOL_MAGIC)) {
    throw new Error(`Invalid PoolState account (len=${data instanceof Uint8Array ? data.byteLength : String(data)})`);
  }
  const version = data[PL_OFF_VERSION]!;
  if (version !== PROTOCOL_VERSION) {
    throw new Error(`Invalid PoolState version=${version} (expected ${PROTOCOL_VERSION})`);
  }
  const pausedRaw = data[PL_OFF_PAUSED]!;
  if (pausedRaw > 1) {
    throw new Error(`Invalid PoolState paused=${pausedRaw} (expected 0 or 1)`);
  }
  const activeLanes = data[PL_OFF_ACTIVE_LANES]!;
  if (activeLanes > NUM_LANES) {
    throw new Error(`Invalid PoolState activeLanes=${activeLanes} (max ${NUM_LANES})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const rootEpochInterval = dv.getBigUint64(PL_OFF_ROOT_EPOCH_INTERVAL, true);
  if (rootEpochInterval < 1n || rootEpochInterval > MAX_ROOT_EPOCH_INTERVAL) {
    throw new Error(
      `Invalid PoolState rootEpochInterval=${rootEpochInterval} (expected 1..=${MAX_ROOT_EPOCH_INTERVAL})`,
    );
  }
  const authorityBytes = data.slice(PL_OFF_AUTHORITY, PL_OFF_AUTHORITY + 32);
  return {
    version,
    bump: data[PL_OFF_BUMP]!,
    paused: pausedRaw !== 0,
    activeLanes,
    poolId: dv.getUint32(PL_OFF_POOL_ID, true),
    rootEpochInterval,
    authority: base58Encode(authorityBytes),
    authorityBytes,
    vaultAuthBump: data[PL_OFF_VAULT_AUTH_BUMP]!,
    noteRentFee: dv.getBigUint64(PL_OFF_NOTE_RENT_FEE, true),
    nfRentFee: dv.getBigUint64(PL_OFF_NF_RENT_FEE, true),
    pendingAuthority: data.slice(PL_OFF_PENDING_AUTHORITY, PL_OFF_PENDING_AUTHORITY + 32),
  };
}

export function decodeLaneHeader(data: Uint8Array): DecodedLaneHeader {
  if (!(data instanceof Uint8Array) || data.byteLength !== LANE_STATE_LEN || !checkMagic(data, LANE_MAGIC)) {
    throw new Error(`Invalid LaneTreeState account (len=${data instanceof Uint8Array ? data.byteLength : String(data)})`);
  }
  const version = data[LN_OFF_VERSION]!;
  if (version !== PROTOCOL_VERSION) {
    throw new Error(`Invalid LaneTreeState version=${version} (expected ${PROTOCOL_VERSION})`);
  }
  const laneId = data[LN_OFF_LANE_ID]!;
  if (laneId >= NUM_LANES) {
    throw new Error(`Invalid LaneTreeState laneId=${laneId} (max ${NUM_LANES - 1})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const nextLeaf = dv.getBigUint64(LN_OFF_NEXT_LEAF, true);
  if (nextLeaf > MAX_LEAVES_PER_LANE) {
    throw new Error(`Invalid LaneTreeState nextLeaf=${nextLeaf} (max ${MAX_LEAVES_PER_LANE})`);
  }
  return {
    version,
    laneId,
    bump: data[LN_OFF_BUMP]!,
    rentBump: data[LN_OFF_RENT_BUMP]!,
    poolId: dv.getUint32(LN_OFF_POOL_ID, true),
    nextLeaf,
    nfCount: dv.getBigUint64(LN_OFF_NF_COUNT, true),
    currentRoot: data.slice(LN_OFF_CURRENT_ROOT, LN_OFF_CURRENT_ROOT + 32),
  };
}

function isAllZero32(b: unknown): boolean {
  if (!(b instanceof Uint8Array) || b.byteLength !== 32) return true;
  for (let i = 0; i < 32; i++) if (b[i] !== 0) return false;
  return true;
}

function bytesEqual32(a: unknown, b: unknown): boolean {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.byteLength !== 32 || b.byteLength !== 32) return false;
  for (let i = 0; i < 32; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function decodeSlotRingEntry(data: Uint8Array, idx: number): RootEntry {
  if (!(data instanceof Uint8Array) || data.byteLength !== ROOT_HISTORY_LEN || !checkMagic(data, ROOTS_MAGIC)) {
    throw new Error(`Invalid GlobalRootHistory account (len=${data instanceof Uint8Array ? data.byteLength : String(data)})`);
  }
  if (!Number.isInteger(idx) || idx < 0 || idx >= SLOT_RING_LEN) {
    throw new RangeError(`Invalid slotRing index=${idx} (max ${SLOT_RING_LEN - 1})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const off = RT_OFF_SLOT_RING + idx * ROOT_ENTRY_LEN;
  return {
    superRoot: data.slice(off, off + 32),
    slot: dv.getBigUint64(off + 32, true),
  };
}

export function decodeEpochRingEntry(data: Uint8Array, idx: number): RootEntry {
  if (!(data instanceof Uint8Array) || data.byteLength !== ROOT_HISTORY_LEN || !checkMagic(data, ROOTS_MAGIC)) {
    throw new Error(`Invalid GlobalRootHistory account (len=${data instanceof Uint8Array ? data.byteLength : String(data)})`);
  }
  if (!Number.isInteger(idx) || idx < 0 || idx >= EPOCH_RING_LEN) {
    throw new RangeError(`Invalid epochRing index=${idx} (max ${EPOCH_RING_LEN - 1})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const off = RT_OFF_EPOCH_RING + idx * ROOT_ENTRY_LEN;
  return {
    superRoot: data.slice(off, off + 32),
    slot: dv.getBigUint64(off + 32, true),
  };
}

export function decodeGlobalRootHistory(data: Uint8Array): DecodedGlobalRootHistory {
  if (!(data instanceof Uint8Array) || data.byteLength !== ROOT_HISTORY_LEN || !checkMagic(data, ROOTS_MAGIC)) {
    throw new Error(`Invalid GlobalRootHistory account (len=${data instanceof Uint8Array ? data.byteLength : String(data)})`);
  }
  const version = data[RT_OFF_VERSION]!;
  if (version !== PROTOCOL_VERSION) {
    throw new Error(`Invalid GlobalRootHistory version=${version} (expected ${PROTOCOL_VERSION})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const slotCursor = dv.getUint16(RT_OFF_SLOT_CURSOR, true);
  const epochCursor = dv.getUint16(RT_OFF_EPOCH_CURSOR, true);
  const slotCount = dv.getUint16(RT_OFF_SLOT_COUNT, true);
  const epochCount = dv.getUint16(RT_OFF_EPOCH_COUNT, true);
  const sameSlotBumpedRaw = data[RT_OFF_SAME_SLOT_BUMPED]!;
  const epochInterval = dv.getBigUint64(RT_OFF_EPOCH_INTERVAL, true);

  if (slotCount < 1 || slotCount > SLOT_RING_LEN) {
    throw new Error(
      `Invalid GlobalRootHistory slotCount=${slotCount} (expected 1..=${SLOT_RING_LEN})`,
    );
  }
  if (slotCursor >= slotCount) {
    throw new Error(
      `Invalid GlobalRootHistory slotCursor=${slotCursor} >= slotCount=${slotCount}`,
    );
  }
  if (epochCount < 1 || epochCount > EPOCH_RING_LEN) {
    throw new Error(
      `Invalid GlobalRootHistory epochCount=${epochCount} (expected 1..=${EPOCH_RING_LEN})`,
    );
  }
  if (epochCursor >= epochCount) {
    throw new Error(
      `Invalid GlobalRootHistory epochCursor=${epochCursor} >= epochCount=${epochCount}`,
    );
  }
  if (sameSlotBumpedRaw > 1) {
    throw new Error(`Invalid GlobalRootHistory sameSlotBumped=${sameSlotBumpedRaw} (max 1)`);
  }
  if (epochInterval < 1n || epochInterval > MAX_ROOT_EPOCH_INTERVAL) {
    throw new Error(
      `Invalid GlobalRootHistory epochInterval=${epochInterval} (expected 1..=${MAX_ROOT_EPOCH_INTERVAL})`,
    );
  }

  const groupRoots: Uint8Array[] = [];
  for (let g = 0; g < 4; g++) {
    groupRoots.push(data.slice(RT_OFF_GROUP_ROOTS + g * 32, RT_OFF_GROUP_ROOTS + (g + 1) * 32));
  }

  const latestLaneRoots: Uint8Array[] = [];
  const latestLaneCounts: bigint[] = [];
  const stableLaneRoots: Uint8Array[] = [];
  const stableLaneCounts: bigint[] = [];
  for (let i = 0; i < NUM_LANES; i++) {
    latestLaneRoots.push(
      data.slice(RT_OFF_LATEST_LANE_ROOTS + i * 32, RT_OFF_LATEST_LANE_ROOTS + (i + 1) * 32),
    );
    const lc = dv.getBigUint64(RT_OFF_LATEST_LANE_COUNTS + i * 8, true);
    if (lc > MAX_LEAVES_PER_LANE) {
      throw new Error(
        `Invalid GlobalRootHistory latestLaneCounts[${i}]=${lc} (max ${MAX_LEAVES_PER_LANE})`,
      );
    }
    latestLaneCounts.push(lc);

    stableLaneRoots.push(
      data.slice(RT_OFF_STABLE_LANE_ROOTS + i * 32, RT_OFF_STABLE_LANE_ROOTS + (i + 1) * 32),
    );
    const sc = dv.getBigUint64(RT_OFF_STABLE_LANE_COUNTS + i * 8, true);
    if (sc > MAX_LEAVES_PER_LANE) {
      throw new Error(
        `Invalid GlobalRootHistory stableLaneCounts[${i}]=${sc} (max ${MAX_LEAVES_PER_LANE})`,
      );
    }
    stableLaneCounts.push(sc);
  }

  const slotRing: RootEntry[] = [];
  for (let s = 0; s < SLOT_RING_LEN; s++) {
    const off = RT_OFF_SLOT_RING + s * ROOT_ENTRY_LEN;
    slotRing.push({
      superRoot: data.slice(off, off + 32),
      slot: dv.getBigUint64(off + 32, true),
    });
  }

  const epochRing: RootEntry[] = [];
  for (let e = 0; e < EPOCH_RING_LEN; e++) {
    const off = RT_OFF_EPOCH_RING + e * ROOT_ENTRY_LEN;
    epochRing.push({
      superRoot: data.slice(off, off + 32),
      slot: dv.getBigUint64(off + 32, true),
    });
  }

  return {
    version: data[RT_OFF_VERSION]!,
    bump: data[RT_OFF_BUMP]!,
    slotCursor,
    poolId: dv.getUint32(RT_OFF_POOL_ID, true),
    epochCursor,
    slotCount,
    epochCount,
    sameSlotBumped: sameSlotBumpedRaw !== 0,
    latestSlot: dv.getBigUint64(RT_OFF_LATEST_SLOT, true),
    stableEpochId: dv.getBigUint64(RT_OFF_STABLE_EPOCH_ID, true),
    stableSlot: dv.getBigUint64(RT_OFF_STABLE_SLOT, true),
    epochInterval,
    groupRoots,
    latestSuperRoot: data.slice(RT_OFF_LATEST_SUPER_ROOT, RT_OFF_LATEST_SUPER_ROOT + 32),
    latestLaneRoots,
    latestLaneCounts,
    stableSuperRoot: data.slice(RT_OFF_STABLE_SUPER_ROOT, RT_OFF_STABLE_SUPER_ROOT + 32),
    stableLaneRoots,
    stableLaneCounts,
    slotRing,
    epochRing,
  };
}

/**
 * Select the best witness snapshot from `GlobalRootHistory` covering every `(laneId, leafIndex)`
 * note to spend.
 *
 * Prefers the long-lived `stable` epoch snapshot (`ROOT_RING_EPOCH = 1`) whenever ALL notes are
 * covered by `stableLaneCounts` (maximizing shared anonymity set & proving stability), and falls
 * back to `latest` (`ROOT_RING_SLOT = 0`) when ANY note is newer than `stableLaneCounts` for
 * instant 0-slot spendability.
 */
export function selectRootSnapshotForNotes(
  history: DecodedGlobalRootHistory,
  notes: ReadonlyArray<{ laneId: number; leafIndex: bigint }>,
): RootSnapshotChoice | null {
  if (!history || typeof history !== 'object' || !Array.isArray(notes)) {
    return null;
  }
  for (const n of notes) {
    if (
      !n ||
      typeof n !== 'object' ||
      !Number.isInteger(n.laneId) ||
      n.laneId < 0 ||
      n.laneId >= NUM_LANES ||
      typeof n.leafIndex !== 'bigint' ||
      n.leafIndex < 0n
    ) {
      return null;
    }
  }
  if (
    !Number.isInteger(history.epochCount) ||
    history.epochCount < 1 ||
    history.epochCount > EPOCH_RING_LEN ||
    !Number.isInteger(history.epochCursor) ||
    history.epochCursor < 0 ||
    history.epochCursor >= history.epochCount ||
    !Number.isInteger(history.slotCount) ||
    history.slotCount < 1 ||
    history.slotCount > SLOT_RING_LEN ||
    !Number.isInteger(history.slotCursor) ||
    history.slotCursor < 0 ||
    history.slotCursor >= history.slotCount ||
    !Array.isArray(history.epochRing) ||
    history.epochRing.length < history.epochCount ||
    !Array.isArray(history.slotRing) ||
    history.slotRing.length < history.slotCount
  ) {
    return null;
  }
  if (
    !(history.stableSuperRoot instanceof Uint8Array) ||
    history.stableSuperRoot.byteLength !== 32 ||
    isAllZero32(history.stableSuperRoot) ||
    !(history.latestSuperRoot instanceof Uint8Array) ||
    history.latestSuperRoot.byteLength !== 32 ||
    isAllZero32(history.latestSuperRoot) ||
    typeof history.stableSlot !== 'bigint' ||
    history.stableSlot < 0n ||
    typeof history.latestSlot !== 'bigint' ||
    history.latestSlot < 0n ||
    history.latestSlot > U64_MAX ||
    history.stableSlot > history.latestSlot
  ) {
    return null;
  }

  const stableEntry = history.epochRing[history.epochCursor];
  const latestEntry = history.slotRing[history.slotCursor];
  if (
    !stableEntry ||
    typeof stableEntry !== 'object' ||
    !bytesEqual32(stableEntry.superRoot, history.stableSuperRoot) ||
    typeof stableEntry.slot !== 'bigint' ||
    stableEntry.slot !== history.stableSlot ||
    !latestEntry ||
    typeof latestEntry !== 'object' ||
    !bytesEqual32(latestEntry.superRoot, history.latestSuperRoot) ||
    typeof latestEntry.slot !== 'bigint' ||
    latestEntry.slot !== history.latestSlot
  ) {
    return null;
  }

  if (
    !Array.isArray(history.stableLaneCounts) ||
    history.stableLaneCounts.length !== NUM_LANES ||
    !Array.isArray(history.latestLaneCounts) ||
    history.latestLaneCounts.length !== NUM_LANES ||
    !Array.isArray(history.stableLaneRoots) ||
    history.stableLaneRoots.length !== NUM_LANES ||
    !Array.isArray(history.latestLaneRoots) ||
    history.latestLaneRoots.length !== NUM_LANES
  ) {
    return null;
  }
  for (let l = 0; l < NUM_LANES; l++) {
    const sc = history.stableLaneCounts[l];
    const lc = history.latestLaneCounts[l];
    const sr = history.stableLaneRoots[l];
    const lr = history.latestLaneRoots[l];
    if (
      typeof sc !== 'bigint' ||
      sc < 0n ||
      typeof lc !== 'bigint' ||
      lc < 0n ||
      lc > MAX_LEAVES_PER_LANE ||
      sc > lc ||
      !(sr instanceof Uint8Array) ||
      sr.byteLength !== 32 ||
      !(lr instanceof Uint8Array) ||
      lr.byteLength !== 32
    ) {
      return null;
    }
    if ((lc === 0n) !== bytesEqual32(lr, ZERO_LANE_ROOT_BE)) {
      return null;
    }
    if ((sc === 0n) !== bytesEqual32(sr, ZERO_LANE_ROOT_BE)) {
      return null;
    }
    if ((sc === lc) !== bytesEqual32(sr, lr)) {
      return null;
    }
  }

  if (notes.every((n) => n.leafIndex < history.stableLaneCounts[n.laneId]!)) {
    return {
      ringKind: ROOT_RING_EPOCH,
      ringIdx: history.epochCursor,
      slot: history.stableSlot,
      superRoot: new Uint8Array(history.stableSuperRoot),
      laneRoots: history.stableLaneRoots.map((r) => new Uint8Array(r)),
      laneCounts: [...history.stableLaneCounts],
    };
  }

  if (notes.every((n) => n.leafIndex < history.latestLaneCounts[n.laneId]!)) {
    return {
      ringKind: ROOT_RING_SLOT,
      ringIdx: history.slotCursor,
      slot: history.latestSlot,
      superRoot: new Uint8Array(history.latestSuperRoot),
      laneRoots: history.latestLaneRoots.map((r) => new Uint8Array(r)),
      laneCounts: [...history.latestLaneCounts],
    };
  }

  return null;
}

export function decodeSubtreePage(data: Uint8Array): DecodedSubtreePage {
  if (!(data instanceof Uint8Array) || data.byteLength !== SUBTREE_PAGE_LEN || !checkMagic(data, SUBTREE_MAGIC)) {
    throw new Error(`Invalid SubtreePage account (len=${data instanceof Uint8Array ? data.byteLength : String(data)})`);
  }
  const laneId = data[SB_OFF_LANE_ID]!;
  if (laneId >= NUM_LANES) {
    throw new Error(`Invalid SubtreePage laneId=${laneId} (max ${NUM_LANES - 1})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const count = dv.getUint16(SB_OFF_COUNT, true);
  if (count > SUBTREE_LEAVES) {
    throw new Error(`Invalid SubtreePage count=${count} (max ${SUBTREE_LEAVES})`);
  }
  const leaves: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    leaves.push(data.slice(SB_OFF_LEAVES + i * 32, SB_OFF_LEAVES + (i + 1) * 32));
  }
  return {
    laneId,
    bump: data[SB_OFF_BUMP]!,
    count,
    poolId: dv.getUint32(SB_OFF_POOL_ID, true),
    pageSeq: dv.getBigUint64(SB_OFF_PAGE_SEQ, true),
    leaves,
  };
}

export function decodeSubtreeRootPage(data: Uint8Array): DecodedSubtreeRootPage {
  if (!(data instanceof Uint8Array) || data.byteLength !== SUBROOT_PAGE_LEN || !checkMagic(data, SUBROOT_MAGIC)) {
    throw new Error(`Invalid SubtreeRootPage account (len=${data instanceof Uint8Array ? data.byteLength : String(data)})`);
  }
  const laneId = data[SR_OFF_LANE_ID]!;
  if (laneId >= NUM_LANES) {
    throw new Error(`Invalid SubtreeRootPage laneId=${laneId} (max ${NUM_LANES - 1})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const count = dv.getUint16(SR_OFF_COUNT, true);
  if (count > SUBROOTS_PER_PAGE) {
    throw new Error(`Invalid SubtreeRootPage count=${count} (max ${SUBROOTS_PER_PAGE})`);
  }
  const roots: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    roots.push(data.slice(SR_OFF_ROOTS + i * 32, SR_OFF_ROOTS + (i + 1) * 32));
  }
  return {
    laneId,
    bump: data[SR_OFF_BUMP]!,
    count,
    poolId: dv.getUint32(SR_OFF_POOL_ID, true),
    rootPageSeq: dv.getBigUint64(SR_OFF_ROOT_PAGE_SEQ, true),
    roots,
  };
}

export function decodeMemoPage(data: Uint8Array): DecodedMemoPage {
  if (!(data instanceof Uint8Array) || data.byteLength !== MEMO_PAGE_LEN || !checkMagic(data, MEMO_MAGIC)) {
    throw new Error(`Invalid MemoPage account (len=${data instanceof Uint8Array ? data.byteLength : String(data)})`);
  }
  const laneId = data[MM_OFF_LANE_ID]!;
  if (laneId >= NUM_LANES) {
    throw new Error(`Invalid MemoPage laneId=${laneId} (max ${NUM_LANES - 1})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const count = dv.getUint16(MM_OFF_COUNT, true);
  if (count > MEMO_NOTES_PER_PAGE) {
    throw new Error(`Invalid MemoPage count=${count} (max ${MEMO_NOTES_PER_PAGE})`);
  }
  const entries: DecodedMemoEntry[] = [];
  for (let i = 0; i < count; i++) {
    entries.push({
      viewTag: data.slice(MM_OFF_VIEW_TAGS + i * 2, MM_OFF_VIEW_TAGS + (i + 1) * 2),
      ephemeralPk: data.slice(MM_OFF_EPHEMERAL_PKS + i * 32, MM_OFF_EPHEMERAL_PKS + (i + 1) * 32),
      ciphertext: data.slice(
        MM_OFF_CIPHERTEXTS + i * MEMO_CT_LEN,
        MM_OFF_CIPHERTEXTS + (i + 1) * MEMO_CT_LEN,
      ),
    });
  }
  return {
    laneId,
    bump: data[MM_OFF_BUMP]!,
    count,
    poolId: dv.getUint32(MM_OFF_POOL_ID, true),
    pageSeq: dv.getBigUint64(MM_OFF_PAGE_SEQ, true),
    createdSlot: dv.getBigUint64(MM_OFF_CREATED_SLOT, true),
    closedSlot: dv.getBigUint64(MM_OFF_CLOSED_SLOT, true),
    entries,
  };
}

export function decodeMemoPageHeader(data: Uint8Array): DecodedMemoPageHeader {
  if (!(data instanceof Uint8Array) || data.byteLength < MEMO_PAGE_HEADER_LEN || !checkMagic(data, MEMO_MAGIC)) {
    throw new Error(`Invalid MemoPage header (len=${data instanceof Uint8Array ? data.byteLength : String(data)})`);
  }
  const laneId = data[MM_OFF_LANE_ID]!;
  if (laneId >= NUM_LANES) {
    throw new Error(`Invalid MemoPage laneId=${laneId} (max ${NUM_LANES - 1})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const count = dv.getUint16(MM_OFF_COUNT, true);
  if (count > MEMO_NOTES_PER_PAGE) {
    throw new Error(`Invalid MemoPage count=${count} (max ${MEMO_NOTES_PER_PAGE})`);
  }
  return {
    laneId,
    bump: data[MM_OFF_BUMP]!,
    count,
    poolId: dv.getUint32(MM_OFF_POOL_ID, true),
    pageSeq: dv.getBigUint64(MM_OFF_PAGE_SEQ, true),
    createdSlot: dv.getBigUint64(MM_OFF_CREATED_SLOT, true),
    closedSlot: dv.getBigUint64(MM_OFF_CLOSED_SLOT, true),
  };
}

export function decodeMemoPageScanSlice(data: Uint8Array): DecodedMemoPageScanSlice {
  if (!(data instanceof Uint8Array) || data.byteLength < MEMO_PAGE_SCAN_SLICE_LEN || !checkMagic(data, MEMO_MAGIC)) {
    throw new Error(`Invalid MemoPage scan slice (len=${data instanceof Uint8Array ? data.byteLength : String(data)})`);
  }
  const hdr = decodeMemoPageHeader(data);
  const viewTags: Uint8Array[] = [];
  const ephemeralPks: Uint8Array[] = [];
  for (let i = 0; i < hdr.count; i++) {
    viewTags.push(data.subarray(MM_OFF_VIEW_TAGS + i * 2, MM_OFF_VIEW_TAGS + (i + 1) * 2));
    ephemeralPks.push(
      data.subarray(MM_OFF_EPHEMERAL_PKS + i * 32, MM_OFF_EPHEMERAL_PKS + (i + 1) * 32),
    );
  }
  return {
    ...hdr,
    viewTags,
    ephemeralPks,
    hasCiphertexts: data.byteLength === MEMO_PAGE_LEN,
  };
}

export function decodeNullifierPageHeader(data: Uint8Array): DecodedNullifierPageHeader {
  if (!(data instanceof Uint8Array) || data.byteLength < NF_PAGE_HEADER_LEN || !checkMagic(data, NF_PAGE_MAGIC)) {
    throw new Error(`Invalid NullifierPage header (len=${data instanceof Uint8Array ? data.byteLength : String(data)})`);
  }
  const laneId = data[NF_OFF_LANE_ID]!;
  if (laneId >= NUM_LANES) {
    throw new Error(`Invalid NullifierPage laneId=${laneId} (max ${NUM_LANES - 1})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const count = dv.getUint16(NF_OFF_COUNT, true);
  if (count > NF_PER_PAGE) {
    throw new Error(`Invalid NullifierPage count=${count} (max ${NF_PER_PAGE})`);
  }
  return {
    laneId,
    bump: data[NF_OFF_BUMP]!,
    count,
    poolId: dv.getUint32(NF_OFF_POOL_ID, true),
    pageSeq: dv.getBigUint64(NF_OFF_PAGE_SEQ, true),
    createdSlot: dv.getBigUint64(NF_OFF_CREATED_SLOT, true),
    closedSlot: dv.getBigUint64(NF_OFF_CLOSED_SLOT, true),
  };
}

export function decodeNullifierPage(data: Uint8Array): DecodedNullifierPage {
  if (!(data instanceof Uint8Array) || data.byteLength !== NF_PAGE_LEN || !checkMagic(data, NF_PAGE_MAGIC)) {
    throw new Error(`Invalid NullifierPage account (len=${data instanceof Uint8Array ? data.byteLength : String(data)})`);
  }
  const laneId = data[NF_OFF_LANE_ID]!;
  if (laneId >= NUM_LANES) {
    throw new Error(`Invalid NullifierPage laneId=${laneId} (max ${NUM_LANES - 1})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const count = dv.getUint16(NF_OFF_COUNT, true);
  if (count > NF_PER_PAGE) {
    throw new Error(`Invalid NullifierPage count=${count} (max ${NF_PER_PAGE})`);
  }
  const prefixes: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    prefixes.push(
      data.slice(NF_OFF_PREFIXES + i * NF_PREFIX_LEN, NF_OFF_PREFIXES + (i + 1) * NF_PREFIX_LEN),
    );
  }
  return {
    laneId,
    bump: data[NF_OFF_BUMP]!,
    count,
    poolId: dv.getUint32(NF_OFF_POOL_ID, true),
    pageSeq: dv.getBigUint64(NF_OFF_PAGE_SEQ, true),
    createdSlot: dv.getBigUint64(NF_OFF_CREATED_SLOT, true),
    closedSlot: dv.getBigUint64(NF_OFF_CLOSED_SLOT, true),
    prefixes,
  };
}
