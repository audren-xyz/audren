/**
 * Zero-copy Audren account decoders matching `crates/audren-core/src/layout.rs` byte-for-byte.
 */

import {
  CKPT_LEN,
  CKPT_MAGIC,
  CK_OFF_BUMP,
  CK_OFF_EPOCH_ID,
  CK_OFF_LANE_COUNTS,
  CK_OFF_LANE_ROOTS,
  CK_OFF_POOL_ID,
  CK_OFF_PUBLISHED_SLOT,
  CK_OFF_SLOT_IDX,
  CK_OFF_SUPER_ROOT,
  CK_OFF_VERSION,
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
  MEMO_CT_LEN,
  MEMO_MAGIC,
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
  NF_PREFIX_LEN,
  NUM_LANES,
  PL_OFF_ACTIVE_LANES,
  PL_OFF_AUTHORITY,
  PL_OFF_BUMP,
  PL_OFF_CKPT_INTERVAL,
  PL_OFF_MAX_CKPT_AGE,
  PL_OFF_NF_RENT_FEE,
  PL_OFF_NOTE_RENT_FEE,
  PL_OFF_PAUSED,
  PL_OFF_PENDING_AUTHORITY,
  PL_OFF_POOL_ID,
  PL_OFF_VAULT_AUTH_BUMP,
  PL_OFF_VERSION,
  POOL_MAGIC,
  POOL_STATE_LEN,
  SB_OFF_BUMP,
  SB_OFF_COUNT,
  SB_OFF_LANE_ID,
  SB_OFF_LEAVES,
  SB_OFF_PAGE_SEQ,
  SB_OFF_POOL_ID,
  SR_OFF_BUMP,
  SR_OFF_COUNT,
  SR_OFF_LANE_ID,
  SR_OFF_POOL_ID,
  SR_OFF_ROOTS,
  SR_OFF_ROOT_PAGE_SEQ,
  SUBROOT_MAGIC,
  SUBROOT_PAGE_LEN,
  SUBTREE_MAGIC,
  SUBTREE_PAGE_LEN,
} from './constants.ts';
import { base58Encode } from './pda.ts';

const asciiDecoder = new TextDecoder('ascii');

function checkMagic(data: Uint8Array, expected: string): boolean {
  if (data.byteLength < 8) return false;
  return asciiDecoder.decode(data.subarray(0, 8)) === expected;
}

export interface DecodedPoolState {
  version: number;
  bump: number;
  paused: boolean;
  activeLanes: number;
  poolId: number;
  ckptInterval: bigint;
  maxCkptAge: bigint;
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

export interface DecodedRootCheckpoint {
  version: number;
  bump: number;
  slotIdx: number;
  poolId: number;
  epochId: bigint;
  publishedSlot: bigint;
  superRoot: Uint8Array;
  laneRoots: Uint8Array[];
  laneCounts: bigint[];
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
  if (data.byteLength !== POOL_STATE_LEN || !checkMagic(data, POOL_MAGIC)) {
    throw new Error(`Invalid PoolState account (len=${data.byteLength})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const authorityBytes = data.slice(PL_OFF_AUTHORITY, PL_OFF_AUTHORITY + 32);
  return {
    version: data[PL_OFF_VERSION]!,
    bump: data[PL_OFF_BUMP]!,
    paused: data[PL_OFF_PAUSED]! !== 0,
    activeLanes: data[PL_OFF_ACTIVE_LANES]!,
    poolId: dv.getUint32(PL_OFF_POOL_ID, true),
    ckptInterval: dv.getBigUint64(PL_OFF_CKPT_INTERVAL, true),
    maxCkptAge: dv.getBigUint64(PL_OFF_MAX_CKPT_AGE, true),
    authority: base58Encode(authorityBytes),
    authorityBytes,
    vaultAuthBump: data[PL_OFF_VAULT_AUTH_BUMP]!,
    noteRentFee: dv.getBigUint64(PL_OFF_NOTE_RENT_FEE, true),
    nfRentFee: dv.getBigUint64(PL_OFF_NF_RENT_FEE, true),
    pendingAuthority: data.slice(PL_OFF_PENDING_AUTHORITY, PL_OFF_PENDING_AUTHORITY + 32),
  };
}

export function decodeLaneHeader(data: Uint8Array): DecodedLaneHeader {
  if (data.byteLength !== LANE_STATE_LEN || !checkMagic(data, LANE_MAGIC)) {
    throw new Error(`Invalid LaneTreeState account (len=${data.byteLength})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return {
    version: data[LN_OFF_VERSION]!,
    laneId: data[LN_OFF_LANE_ID]!,
    bump: data[LN_OFF_BUMP]!,
    rentBump: data[LN_OFF_RENT_BUMP]!,
    poolId: dv.getUint32(LN_OFF_POOL_ID, true),
    nextLeaf: dv.getBigUint64(LN_OFF_NEXT_LEAF, true),
    nfCount: dv.getBigUint64(LN_OFF_NF_COUNT, true),
    currentRoot: data.slice(LN_OFF_CURRENT_ROOT, LN_OFF_CURRENT_ROOT + 32),
  };
}

export function decodeRootCheckpoint(data: Uint8Array): DecodedRootCheckpoint {
  if (data.byteLength !== CKPT_LEN || !checkMagic(data, CKPT_MAGIC)) {
    throw new Error(`Invalid RootCheckpoint account (len=${data.byteLength})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const laneRoots: Uint8Array[] = [];
  const laneCounts: bigint[] = [];
  for (let i = 0; i < NUM_LANES; i++) {
    laneRoots.push(data.slice(CK_OFF_LANE_ROOTS + i * 32, CK_OFF_LANE_ROOTS + (i + 1) * 32));
    laneCounts.push(dv.getBigUint64(CK_OFF_LANE_COUNTS + i * 8, true));
  }
  return {
    version: data[CK_OFF_VERSION]!,
    bump: data[CK_OFF_BUMP]!,
    slotIdx: dv.getUint16(CK_OFF_SLOT_IDX, true),
    poolId: dv.getUint32(CK_OFF_POOL_ID, true),
    epochId: dv.getBigUint64(CK_OFF_EPOCH_ID, true),
    publishedSlot: dv.getBigUint64(CK_OFF_PUBLISHED_SLOT, true),
    superRoot: data.slice(CK_OFF_SUPER_ROOT, CK_OFF_SUPER_ROOT + 32),
    laneRoots,
    laneCounts,
  };
}

export function decodeSubtreePage(data: Uint8Array): DecodedSubtreePage {
  if (data.byteLength !== SUBTREE_PAGE_LEN || !checkMagic(data, SUBTREE_MAGIC)) {
    throw new Error(`Invalid SubtreePage account (len=${data.byteLength})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const count = dv.getUint16(SB_OFF_COUNT, true);
  const leaves: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    leaves.push(data.slice(SB_OFF_LEAVES + i * 32, SB_OFF_LEAVES + (i + 1) * 32));
  }
  return {
    laneId: data[SB_OFF_LANE_ID]!,
    bump: data[SB_OFF_BUMP]!,
    count,
    poolId: dv.getUint32(SB_OFF_POOL_ID, true),
    pageSeq: dv.getBigUint64(SB_OFF_PAGE_SEQ, true),
    leaves,
  };
}

export function decodeSubtreeRootPage(data: Uint8Array): DecodedSubtreeRootPage {
  if (data.byteLength !== SUBROOT_PAGE_LEN || !checkMagic(data, SUBROOT_MAGIC)) {
    throw new Error(`Invalid SubtreeRootPage account (len=${data.byteLength})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const count = dv.getUint16(SR_OFF_COUNT, true);
  const roots: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    roots.push(data.slice(SR_OFF_ROOTS + i * 32, SR_OFF_ROOTS + (i + 1) * 32));
  }
  return {
    laneId: data[SR_OFF_LANE_ID]!,
    bump: data[SR_OFF_BUMP]!,
    count,
    poolId: dv.getUint32(SR_OFF_POOL_ID, true),
    rootPageSeq: dv.getBigUint64(SR_OFF_ROOT_PAGE_SEQ, true),
    roots,
  };
}

export function decodeMemoPage(data: Uint8Array): DecodedMemoPage {
  if (data.byteLength !== MEMO_PAGE_LEN || !checkMagic(data, MEMO_MAGIC)) {
    throw new Error(`Invalid MemoPage account (len=${data.byteLength})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const count = dv.getUint16(MM_OFF_COUNT, true);
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
    laneId: data[MM_OFF_LANE_ID]!,
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
  if (data.byteLength < MEMO_PAGE_HEADER_LEN || !checkMagic(data, MEMO_MAGIC)) {
    throw new Error(`Invalid MemoPage header (len=${data.byteLength})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return {
    laneId: data[MM_OFF_LANE_ID]!,
    bump: data[MM_OFF_BUMP]!,
    count: dv.getUint16(MM_OFF_COUNT, true),
    poolId: dv.getUint32(MM_OFF_POOL_ID, true),
    pageSeq: dv.getBigUint64(MM_OFF_PAGE_SEQ, true),
    createdSlot: dv.getBigUint64(MM_OFF_CREATED_SLOT, true),
    closedSlot: dv.getBigUint64(MM_OFF_CLOSED_SLOT, true),
  };
}

export function decodeMemoPageScanSlice(data: Uint8Array): DecodedMemoPageScanSlice {
  if (data.byteLength < MEMO_PAGE_SCAN_SLICE_LEN || !checkMagic(data, MEMO_MAGIC)) {
    throw new Error(`Invalid MemoPage scan slice (len=${data.byteLength})`);
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
  if (data.byteLength < NF_PAGE_HEADER_LEN || !checkMagic(data, NF_PAGE_MAGIC)) {
    throw new Error(`Invalid NullifierPage header (len=${data.byteLength})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return {
    laneId: data[NF_OFF_LANE_ID]!,
    bump: data[NF_OFF_BUMP]!,
    count: dv.getUint16(NF_OFF_COUNT, true),
    poolId: dv.getUint32(NF_OFF_POOL_ID, true),
    pageSeq: dv.getBigUint64(NF_OFF_PAGE_SEQ, true),
    createdSlot: dv.getBigUint64(NF_OFF_CREATED_SLOT, true),
    closedSlot: dv.getBigUint64(NF_OFF_CLOSED_SLOT, true),
  };
}

export function decodeNullifierPage(data: Uint8Array): DecodedNullifierPage {
  if (data.byteLength !== NF_PAGE_LEN || !checkMagic(data, NF_PAGE_MAGIC)) {
    throw new Error(`Invalid NullifierPage account (len=${data.byteLength})`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const count = dv.getUint16(NF_OFF_COUNT, true);
  const prefixes: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    prefixes.push(
      data.slice(NF_OFF_PREFIXES + i * NF_PREFIX_LEN, NF_OFF_PREFIXES + (i + 1) * NF_PREFIX_LEN),
    );
  }
  return {
    laneId: data[NF_OFF_LANE_ID]!,
    bump: data[NF_OFF_BUMP]!,
    count,
    poolId: dv.getUint32(NF_OFF_POOL_ID, true),
    pageSeq: dv.getBigUint64(NF_OFF_PAGE_SEQ, true),
    createdSlot: dv.getBigUint64(NF_OFF_CREATED_SLOT, true),
    closedSlot: dv.getBigUint64(NF_OFF_CLOSED_SLOT, true),
    prefixes,
  };
}
