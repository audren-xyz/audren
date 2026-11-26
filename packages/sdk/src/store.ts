/**
 * Zero-indexer `CompactWalletStore` & 4-ary Depth-20 Merkle witness builder matching
 * `crates/audren-circuits/src/merkle.rs` and `crates/client/src/store.rs` bit-for-bit.
 *
 * Discards every sealed `SubtreePage` (`8,256 B`), `MemoPage` (`10,240 B`), and stranger
 * `NullifierPage` prefix immediately after scanning, persisting only frozen 12-sibling
 * intra-subtree paths (`384 B` per owned note), `32 B` finalized level-4 subroots (`1.28 MB`
 * at 10M pool notes), unsealed frontier tail leaves, and at most one just-sealed page per lane
 * until `GlobalRootHistory.stable` crosses it.
 */

import {
  LANE_DEPTH_4ARY,
  MEMO_NOTES_PER_PAGE,
  MEMO_PAYMENT_ID_LEN,
  NF_PER_PAGE,
  NF_PREFIX_LEN,
  NUM_LANES,
  ROOT_RING_EPOCH,
  ROOT_RING_SLOT,
  SUBROOTS_PER_PAGE,
  SUBTREE_LEAVES,
  SUBTREE_LEVELS_4ARY,
  TOTAL_DEPTH_4ARY,
  ZERO_HASHES_4ARY,
} from './constants.ts';
import { tryDecryptAndVerifyMemoEntry, type DecryptedMemo } from './crypto.ts';
import type { FullViewingKey, SelectiveDisclosureProof } from './keys.ts';
import { fvkRealNullifier, fvkStealthOwner } from './keys.ts';
import {
  MAX_LEAVES_PER_LANE,
  decodeMemoPage,
  decodeNullifierPage,
  decodeSubtreePage,
  decodeSubtreeRootPage,
  selectRootSnapshotForNotes,
  type DecodedGlobalRootHistory,
  type RootSnapshotChoice,
} from './layout.ts';

const MAX_SUBROOTS_PER_LANE = MAX_LEAVES_PER_LANE / BigInt(SUBTREE_LEAVES);
const U32_MAX = 0xffff_ffff;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

class MissingFrontierLeavesError extends Error {
  constructor() {
    super('Missing frontier SubtreePage leaves');
  }
}

function laneCountsEqual(a: readonly bigint[], b: readonly bigint[]): boolean {
  for (let l = 0; l < NUM_LANES; l++) {
    if (a[l] !== b[l]) return false;
  }
  return true;
}
import {
  computeNoteCommitment,
  computeSubtree256Root,
  computeSuperRoot4Ary,
  deriveAssetId,
  frFromBeBytesStrict,
  frToBeBytes,
  poseidon4,
} from './poseidon.ts';
import { validateGlobalRootHistory, validateRootSnapshotChoice } from './scanner.ts';

export interface MerklePath4Ary {
  siblings: bigint[][]; // [20][3]
  positions: number[]; // [20] each in 0..3
}

export function emptyMerklePath4Ary(): MerklePath4Ary {
  return {
    siblings: Array.from({ length: TOTAL_DEPTH_4ARY }, () => [0n, 0n, 0n]),
    positions: new Array<number>(TOTAL_DEPTH_4ARY).fill(0),
  };
}

export function computeMerkleRoot4Ary(path: MerklePath4Ary, leaf: bigint): bigint {
  let cur = leaf;
  for (let h = 0; h < TOTAL_DEPTH_4ARY; h++) {
    const s = path.siblings[h]!;
    const pos = path.positions[h]!;
    let c0: bigint, c1: bigint, c2: bigint, c3: bigint;
    if (pos === 0) {
      [c0, c1, c2, c3] = [cur, s[0]!, s[1]!, s[2]!];
    } else if (pos === 1) {
      [c0, c1, c2, c3] = [s[0]!, cur, s[1]!, s[2]!];
    } else if (pos === 2) {
      [c0, c1, c2, c3] = [s[0]!, s[1]!, cur, s[2]!];
    } else if (pos === 3) {
      [c0, c1, c2, c3] = [s[0]!, s[1]!, s[2]!, cur];
    } else {
      throw new RangeError(`Invalid 4-ary Merkle position at depth ${h}: ${pos}`);
    }
    cur = poseidon4(c0, c1, c2, c3);
  }
  return cur;
}

export function extractIntraSubtreeSiblings(
  pageLeaves: readonly bigint[],
  validLen: number,
  targetOffset: number,
): { siblings: bigint[][]; positions: number[] } {
  if (
    !Number.isInteger(validLen) ||
    !Number.isInteger(targetOffset) ||
    targetOffset < 0 ||
    targetOffset >= validLen ||
    validLen > SUBTREE_LEAVES ||
    pageLeaves.length < validLen
  ) {
    throw new RangeError(
      `Invalid targetOffset=${targetOffset}, validLen=${validLen}, leaves=${pageLeaves.length}`,
    );
  }
  const pageNodes = new Array<bigint>(SUBTREE_LEAVES).fill(0n);
  for (let i = 0; i < validLen; i++) pageNodes[i] = pageLeaves[i]!;

  const siblings: bigint[][] = [];
  const positions: number[] = [];
  let curIdx = targetOffset;
  let curLen = SUBTREE_LEAVES;

  for (let h = 0; h < SUBTREE_LEVELS_4ARY; h++) {
    const groupStart = Math.floor(curIdx / 4) * 4;
    const pos = curIdx % 4;
    positions.push(pos);
    const sib: bigint[] = [];
    for (let k = 0; k < 4; k++) {
      if (k !== pos) sib.push(pageNodes[groupStart + k]!);
    }
    siblings.push(sib);

    const nextLen = curLen >>> 2;
    for (let j = 0; j < nextLen; j++) {
      pageNodes[j] = poseidon4(
        pageNodes[4 * j]!,
        pageNodes[4 * j + 1]!,
        pageNodes[4 * j + 2]!,
        pageNodes[4 * j + 3]!,
      );
    }
    curIdx = Math.floor(curIdx / 4);
    curLen = nextLen;
  }
  return { siblings, positions };
}

export type WitnessLaneSnapshotParams = {
  laneRoots: readonly bigint[];
  laneLeafCount: bigint;
};

export function buildWitnessFromFrozenSubsiblings(
  params: {
    laneId: number;
    targetLeafIdx: bigint;
    intraSiblings: readonly (readonly bigint[])[];
    intraPositions: readonly number[];
    finalizedSubtreeRoots: readonly bigint[];
    frontierPageLeaves?: readonly bigint[];
  } & WitnessLaneSnapshotParams,
): MerklePath4Ary {
  const {
    laneId,
    targetLeafIdx,
    intraSiblings,
    intraPositions,
    laneRoots: snapLaneRoots,
    laneLeafCount: snapLaneLeafCount,
    finalizedSubtreeRoots,
    frontierPageLeaves,
  } = params;
  if (!Number.isInteger(laneId) || laneId < 0 || laneId >= NUM_LANES) {
    throw new RangeError(`Invalid laneId ${laneId}`);
  }
  if (!snapLaneRoots || snapLaneRoots.length !== NUM_LANES) {
    throw new RangeError(`laneRoots must have ${NUM_LANES} entries`);
  }
  if (typeof snapLaneLeafCount !== 'bigint' || snapLaneLeafCount < 0n || snapLaneLeafCount > MAX_LEAVES_PER_LANE) {
    throw new RangeError(`laneLeafCount out of range: ${String(snapLaneLeafCount)}`);
  }
  if (typeof targetLeafIdx !== 'bigint' || targetLeafIdx < 0n || targetLeafIdx >= snapLaneLeafCount) {
    throw new RangeError('targetLeafIdx >= laneLeafCount');
  }

  const path = emptyMerklePath4Ary();
  for (let h = 0; h < SUBTREE_LEVELS_4ARY; h++) {
    path.siblings[h] = [...intraSiblings[h]!];
    path.positions[h] = intraPositions[h]!;
  }

  const targetPageIdx = Number(targetLeafIdx / BigInt(SUBTREE_LEAVES));
  const frontierPageIdx = Number(snapLaneLeafCount / BigInt(SUBTREE_LEAVES));
  const frontierRem = Number(snapLaneLeafCount % BigInt(SUBTREE_LEAVES));

  if (finalizedSubtreeRoots.length < frontierPageIdx) {
    throw new Error(
      `Missing finalizedSubtreeRoots: have ${finalizedSubtreeRoots.length}, need ${frontierPageIdx}`,
    );
  }
  let levelNodes: bigint[] = [];
  for (let p = 0; p < frontierPageIdx; p++) {
    levelNodes.push(finalizedSubtreeRoots[p]!);
  }
  if (frontierRem > 0) {
    if (!frontierPageLeaves || frontierPageLeaves.length < frontierRem) {
      throw new Error('Missing frontierPageLeaves for unsealed snapshot tail');
    }
    levelNodes.push(computeSubtree256Root(frontierPageLeaves, frontierRem));
  }

  let nodeIdx = targetPageIdx;
  for (let h = SUBTREE_LEVELS_4ARY; h < LANE_DEPTH_4ARY; h++) {
    const zeroAtH = ZERO_HASHES_4ARY[h]!;
    const groupStart = Math.floor(nodeIdx / 4) * 4;
    const pos = nodeIdx % 4;
    path.positions[h] = pos;

    const sib: bigint[] = [];
    for (let k = 0; k < 4; k++) {
      if (k !== pos) {
        const childI = groupStart + k;
        sib.push(childI < levelNodes.length ? levelNodes[childI]! : zeroAtH);
      }
    }
    path.siblings[h] = sib;

    const nextLen = Math.ceil(levelNodes.length / 4);
    const nextLevel: bigint[] = [];
    for (let g = 0; g < nextLen; g++) {
      const base = g * 4;
      nextLevel.push(
        poseidon4(
          base < levelNodes.length ? levelNodes[base]! : zeroAtH,
          base + 1 < levelNodes.length ? levelNodes[base + 1]! : zeroAtH,
          base + 2 < levelNodes.length ? levelNodes[base + 2]! : zeroAtH,
          base + 3 < levelNodes.length ? levelNodes[base + 3]! : zeroAtH,
        ),
      );
    }
    levelNodes = nextLevel;
    nodeIdx = Math.floor(nodeIdx / 4);
  }

  const group4 = Math.floor(laneId / 4);
  const pos18 = laneId % 4;
  path.positions[LANE_DEPTH_4ARY] = pos18;
  const sib18: bigint[] = [];
  for (let k = 0; k < 4; k++) {
    if (k !== pos18) sib18.push(snapLaneRoots[group4 * 4 + k]!);
  }
  path.siblings[LANE_DEPTH_4ARY] = sib18;

  const groupHashes = [
    poseidon4(snapLaneRoots[0]!, snapLaneRoots[1]!, snapLaneRoots[2]!, snapLaneRoots[3]!),
    poseidon4(snapLaneRoots[4]!, snapLaneRoots[5]!, snapLaneRoots[6]!, snapLaneRoots[7]!),
    poseidon4(snapLaneRoots[8]!, snapLaneRoots[9]!, snapLaneRoots[10]!, snapLaneRoots[11]!),
    poseidon4(snapLaneRoots[12]!, snapLaneRoots[13]!, snapLaneRoots[14]!, snapLaneRoots[15]!),
  ];
  path.positions[LANE_DEPTH_4ARY + 1] = group4;
  const sib19: bigint[] = [];
  for (let k = 0; k < 4; k++) {
    if (k !== group4) sib19.push(groupHashes[k]!);
  }
  path.siblings[LANE_DEPTH_4ARY + 1] = sib19;

  return path;
}

export function buildHistoricalWitness4Ary(
  params: {
    laneId: number;
    targetLeafIdx: bigint;
    finalizedSubtreeRoots: readonly bigint[];
    targetPageLeaves: readonly bigint[];
    frontierPageLeaves?: readonly bigint[];
  } & WitnessLaneSnapshotParams,
): MerklePath4Ary {
  const snapLaneRoots = params.laneRoots;
  const snapLaneLeafCount = params.laneLeafCount;
  if (typeof snapLaneLeafCount !== 'bigint' || snapLaneLeafCount < 0n || snapLaneLeafCount > MAX_LEAVES_PER_LANE) {
    throw new RangeError(`laneLeafCount out of range: ${String(snapLaneLeafCount)}`);
  }
  if (typeof params.targetLeafIdx !== 'bigint' || params.targetLeafIdx < 0n || params.targetLeafIdx >= snapLaneLeafCount) {
    throw new RangeError(`targetLeafIdx out of range: ${String(params.targetLeafIdx)}`);
  }
  const targetPageIdx = Number(params.targetLeafIdx / BigInt(SUBTREE_LEAVES));
  const targetOffset = Number(params.targetLeafIdx % BigInt(SUBTREE_LEAVES));
  const frontierPageIdx = Number(snapLaneLeafCount / BigInt(SUBTREE_LEAVES));
  const frontierRem = Number(snapLaneLeafCount % BigInt(SUBTREE_LEAVES));
  const validLen = targetPageIdx === frontierPageIdx ? frontierRem : SUBTREE_LEAVES;
  const { siblings, positions } = extractIntraSubtreeSiblings(
    params.targetPageLeaves,
    validLen,
    targetOffset,
  );
  return buildWitnessFromFrozenSubsiblings({
    laneId: params.laneId,
    targetLeafIdx: params.targetLeafIdx,
    intraSiblings: siblings,
    intraPositions: positions,
    laneRoots: snapLaneRoots,
    laneLeafCount: snapLaneLeafCount,
    finalizedSubtreeRoots: params.finalizedSubtreeRoots,
    frontierPageLeaves: params.frontierPageLeaves,
  });
}

// =============================================================================
// CompactWalletStore (JSON-serializable for Browser IndexedDB & Node.js disk)
// =============================================================================

export interface OwnedNote {
  poolId: number;
  laneId: number;
  leafIndex: bigint;
  globalLeafIndex: bigint;
  mint: Uint8Array;
  amount: bigint;
  tweak: Uint8Array;
  blinding: Uint8Array;
  stealthOwner: Uint8Array;
  commitment: Uint8Array;
  nullifier: Uint8Array;
  paymentId: Uint8Array;
  isDynamic: boolean;
  spent: boolean;
  frozenIntraSiblings: Uint8Array[][] | null; // [4][3] 32-byte BE
  frozenIntraPositions: number[] | null; // [4]
}

export interface CompactLaneState {
  finalizedSubroots: Uint8Array[];
  frontierSubSeq: bigint;
  frontierLeaves: Uint8Array[];
  prevSealedSubSeq: bigint | null;
  prevSealedLeaves: Uint8Array[];
  nextMemoLeaf: bigint;
  nextNfIndex: bigint;
}

const HEX_RE = /^[0-9a-fA-F]*$/;
const DEC_UINT_RE = /^\d+$/;

function bytesToHex(b: Uint8Array): string {
  if (!(b instanceof Uint8Array)) {
    throw new RangeError(`Expected Uint8Array, got ${String(b)}`);
  }
  let s = '';
  for (let i = 0; i < b.byteLength; i++) s += b[i]!.toString(16).padStart(2, '0');
  return s;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.byteLength !== b.byteLength) {
    return false;
  }
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function hexToBytesExact(h: unknown, expectedLen: number, label: string): Uint8Array {
  if (typeof h !== 'string' || h.length !== expectedLen * 2 || !HEX_RE.test(h)) {
    throw new Error(
      `Invalid CompactWalletStore JSON ${label}: expected ${expectedLen * 2} hex characters`,
    );
  }
  const out = new Uint8Array(expectedLen);
  for (let i = 0; i < expectedLen; i++) {
    out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function parseU64Decimal(v: unknown, label: string): bigint {
  if (typeof v !== 'string' || !DEC_UINT_RE.test(v)) {
    throw new Error(`Invalid CompactWalletStore JSON ${label}: expected unsigned decimal string`);
  }
  const n = BigInt(v);
  if (n < 0n || n > U64_MAX) {
    throw new Error(`Invalid CompactWalletStore JSON ${label}: out of u64 range`);
  }
  return n;
}

export function exportSelectiveDisclosureProof(note: OwnedNote): SelectiveDisclosureProof {
  if (
    !note ||
    typeof note !== 'object' ||
    !(note.stealthOwner instanceof Uint8Array) ||
    note.stealthOwner.byteLength !== 32 ||
    !(note.mint instanceof Uint8Array) ||
    note.mint.byteLength !== 32 ||
    !(note.blinding instanceof Uint8Array) ||
    note.blinding.byteLength !== 32 ||
    !(note.commitment instanceof Uint8Array) ||
    note.commitment.byteLength !== 32
  ) {
    throw new RangeError('OwnedNote must provide 32-byte Uint8Array stealthOwner, mint, blinding, and commitment');
  }
  return {
    poolId: note.poolId,
    laneId: note.laneId,
    leafIndex: note.leafIndex,
    stealthOwner: new Uint8Array(note.stealthOwner),
    mint: new Uint8Array(note.mint),
    amount: note.amount,
    blinding: new Uint8Array(note.blinding),
    commitment: new Uint8Array(note.commitment),
  };
}

export class CompactWalletStore {
  poolId: number;
  birthdaySlot: bigint;
  lanes: CompactLaneState[];
  notes: OwnedNote[];

  constructor(poolId = 0, birthdaySlot = 0n) {
    if (!Number.isInteger(poolId) || poolId < 0 || poolId > U32_MAX) {
      throw new RangeError(`poolId must be a u32 integer in 0..=${U32_MAX}, got ${String(poolId)}`);
    }
    if (typeof birthdaySlot !== 'bigint' || birthdaySlot < 0n || birthdaySlot > U64_MAX) {
      throw new RangeError(`birthdaySlot must be a u64 bigint, got ${String(birthdaySlot)}`);
    }
    this.poolId = poolId;
    this.birthdaySlot = birthdaySlot;
    this.lanes = Array.from({ length: NUM_LANES }, () => ({
      finalizedSubroots: [],
      frontierSubSeq: 0n,
      frontierLeaves: [],
      prevSealedSubSeq: null,
      prevSealedLeaves: [],
      nextMemoLeaf: 0n,
      nextNfIndex: 0n,
    }));
    this.notes = [];
  }

  unspentNotes(mintHex?: string): OwnedNote[] {
    return this.notes.filter((n) => !n.spent && (!mintHex || bytesToHex(n.mint) === mintHex));
  }

  balancesByMintHex(): Map<string, bigint> {
    const out = new Map<string, bigint>();
    for (const n of this.notes) {
      if (n.spent) continue;
      const k = bytesToHex(n.mint);
      out.set(k, (out.get(k) ?? 0n) + n.amount);
    }
    return out;
  }

  /** Record a decrypted and commitment-verified owned note if not already tracked. */
  recordVerifiedMemo(params: {
    fvk: FullViewingKey;
    laneId: number;
    leafIdx: bigint;
    decrypted: DecryptedMemo;
    cmBe: Uint8Array;
  }): boolean {
    if (!params || typeof params !== 'object') {
      throw new RangeError('recordVerifiedMemo params must be an object');
    }
    const { fvk, laneId, leafIdx, decrypted, cmBe } = params;
    if (!Number.isInteger(laneId) || laneId < 0 || laneId >= NUM_LANES) {
      throw new RangeError(`Invalid laneId ${String(laneId)}`);
    }
    if (typeof leafIdx !== 'bigint' || leafIdx < 0n || leafIdx >= MAX_LEAVES_PER_LANE) {
      throw new RangeError(`Invalid leafIdx ${String(leafIdx)}`);
    }
    if (!(cmBe instanceof Uint8Array) || cmBe.byteLength !== 32) {
      throw new RangeError(
        `cmBe must be a 32-byte Uint8Array, got ${cmBe instanceof Uint8Array ? cmBe.byteLength : String(cmBe)}`,
      );
    }
    if (
      !decrypted ||
      typeof decrypted !== 'object' ||
      !(decrypted.mint instanceof Uint8Array) ||
      decrypted.mint.byteLength !== 32
    ) {
      throw new RangeError('decrypted memo must provide a 32-byte Uint8Array mint');
    }
    if (typeof decrypted.amount !== 'bigint' || decrypted.amount < 0n || decrypted.amount > U64_MAX) {
      throw new RangeError(`decrypted.amount must be a u64 bigint, got ${String(decrypted.amount)}`);
    }
    if (
      decrypted.paymentId !== undefined &&
      (!(decrypted.paymentId instanceof Uint8Array) ||
        decrypted.paymentId.byteLength !== MEMO_PAYMENT_ID_LEN)
    ) {
      throw new RangeError(
        `decrypted.paymentId must be a ${MEMO_PAYMENT_ID_LEN}-byte Uint8Array, got ${decrypted.paymentId instanceof Uint8Array ? decrypted.paymentId.byteLength : String(decrypted.paymentId)}`,
      );
    }
    if (this.notes.some((n) => n.laneId === laneId && n.leafIndex === leafIdx)) {
      return false;
    }
    const globalLeaf = (BigInt(laneId) << 36n) | leafIdx;
    const stealth = fvkStealthOwner(fvk, decrypted.tweak);
    const cmFr = computeNoteCommitment(
      stealth,
      deriveAssetId(decrypted.mint),
      decrypted.amount,
      decrypted.blinding,
    );
    const computedCmBe = frToBeBytes(cmFr);
    for (let i = 0; i < 32; i++) {
      if (computedCmBe[i] !== cmBe[i]) {
        throw new Error('Note commitment mismatch in recordVerifiedMemo');
      }
    }
    const nf = fvkRealNullifier(fvk, cmFr, globalLeaf);
    this.notes.push({
      poolId: this.poolId,
      laneId,
      leafIndex: leafIdx,
      globalLeafIndex: globalLeaf,
      mint: new Uint8Array(decrypted.mint),
      amount: decrypted.amount,
      tweak: frToBeBytes(decrypted.tweak),
      blinding: frToBeBytes(decrypted.blinding),
      stealthOwner: frToBeBytes(stealth),
      commitment: new Uint8Array(cmBe),
      nullifier: nf,
      paymentId: decrypted.paymentId
        ? new Uint8Array(decrypted.paymentId)
        : new Uint8Array(MEMO_PAYMENT_ID_LEN),
      isDynamic: decrypted.isDynamic,
      spent: false,
      frozenIntraSiblings: null,
      frozenIntraPositions: null,
    });
    return true;
  }

  /**
   * Freeze 12-sibling intra-subtree Merkle paths for every owned note in sealed
   * `(laneId, subSeq)` so the `8,256 B` `SubtreePage` can be permanently discarded.
   */
  freezeOwnedNotesInSubtreePage(
    laneId: number,
    subSeq: bigint,
    leaves: readonly Uint8Array[],
  ): void {
    if (!Number.isInteger(laneId) || laneId < 0 || laneId >= NUM_LANES) {
      throw new RangeError(`Invalid laneId ${String(laneId)}`);
    }
    if (typeof subSeq !== 'bigint' || subSeq < 0n || subSeq >= MAX_SUBROOTS_PER_LANE) {
      throw new RangeError(`Invalid subSeq ${String(subSeq)}`);
    }
    if (!Array.isArray(leaves)) {
      throw new RangeError('leaves must be an array of 32-byte Uint8Arrays');
    }
    if (leaves.length !== SUBTREE_LEAVES) return;
    let frLeaves: bigint[] | null = null;
    for (const note of this.notes) {
      if (
        note.laneId === laneId &&
        note.leafIndex / BigInt(SUBTREE_LEAVES) === subSeq &&
        !note.frozenIntraSiblings
      ) {
        const offset = Number(note.leafIndex % BigInt(SUBTREE_LEAVES));
        if (!bytesEqual(leaves[offset]!, note.commitment)) {
          continue;
        }
        if (!frLeaves) frLeaves = leaves.map((b) => frFromBeBytesStrict(b));
        const { siblings, positions } = extractIntraSubtreeSiblings(
          frLeaves,
          SUBTREE_LEAVES,
          offset,
        );
        note.frozenIntraSiblings = siblings.map((lvl) => lvl.map((x) => frToBeBytes(x)));
        note.frozenIntraPositions = positions;
      }
    }
  }

  /**
   * Ingest one or more `SubtreeRootPage` accounts (`9,664 B`, 300 finalized subroots each)
   * without downloading sealed `SubtreePage` accounts for subtrees containing no owned notes.
   *
   * Validates every page in sorted sequence order and enforces strict contiguity (zero
   * zero-filled gaps, zero sparse amplification DoS, zero partial mutation on error) BEFORE
   * writing any subroots into `finalizedSubroots`.
   */
  ingestSubrootPages(params: {
    laneId: number;
    subrootPages: ReadonlyArray<{ rootPageSeq: bigint; raw: Uint8Array }>;
    finalizedCount?: bigint;
  }): void {
    const { laneId, subrootPages, finalizedCount } = params;
    if (!Number.isInteger(laneId) || laneId < 0 || laneId >= NUM_LANES) {
      throw new RangeError(`Invalid laneId ${laneId}`);
    }
    if (finalizedCount !== undefined && typeof finalizedCount !== 'bigint') {
      throw new RangeError(`Invalid finalizedCount=${String(finalizedCount)}`);
    }
    const lane = this.lanes[laneId]!;
    const maxRootsBig =
      finalizedCount !== undefined
        ? finalizedCount < 0n
          ? 0n
          : finalizedCount > MAX_SUBROOTS_PER_LANE
            ? MAX_SUBROOTS_PER_LANE
            : finalizedCount
        : MAX_SUBROOTS_PER_LANE;
    const srPerPageBig = BigInt(SUBROOTS_PER_PAGE);

    const dedupPages = new Map<bigint, ReturnType<typeof decodeSubtreeRootPage>>();
    for (const entry of subrootPages) {
      if (typeof entry.rootPageSeq !== 'bigint' || entry.rootPageSeq < 0n) {
        throw new RangeError(`Invalid SubtreeRootPage rootPageSeq=${String(entry.rootPageSeq)}`);
      }
      const dec = decodeSubtreeRootPage(entry.raw);
      if (
        dec.poolId !== this.poolId ||
        dec.laneId !== laneId ||
        dec.rootPageSeq !== entry.rootPageSeq
      ) {
        throw new Error(
          `SubtreeRootPage header mismatch (expected pool=${this.poolId}, lane=${laneId}, seq=${entry.rootPageSeq}; got pool=${dec.poolId}, lane=${dec.laneId}, seq=${dec.rootPageSeq})`,
        );
      }
      const baseIdxBig = entry.rootPageSeq * srPerPageBig;
      if (baseIdxBig > MAX_SUBROOTS_PER_LANE) {
        throw new RangeError(`SubtreeRootPage rootPageSeq out of range: ${entry.rootPageSeq}`);
      }
      const baseIdx = Number(baseIdxBig);
      for (let i = 0; i < dec.roots.length; i++) {
        frFromBeBytesStrict(dec.roots[i]!);
        const subIdx = baseIdx + i;
        if (
          subIdx < lane.finalizedSubroots.length &&
          !bytesEqual(lane.finalizedSubroots[subIdx]!, dec.roots[i]!)
        ) {
          throw new Error(
            `SubtreeRootPage subroot mismatch against persisted finalizedSubroots at index ${subIdx}`,
          );
        }
      }
      const existing = dedupPages.get(entry.rootPageSeq);
      if (existing) {
        const overlap = Math.min(existing.roots.length, dec.roots.length);
        for (let i = 0; i < overlap; i++) {
          if (!bytesEqual(existing.roots[i]!, dec.roots[i]!)) {
            throw new Error(
              `Conflicting duplicate SubtreeRootPage entries at seq=${entry.rootPageSeq}`,
            );
          }
        }
        if (dec.roots.length > existing.roots.length) {
          dedupPages.set(entry.rootPageSeq, dec);
        }
      } else {
        dedupPages.set(entry.rootPageSeq, dec);
      }
    }
    const sortedSeqs = [...dedupPages.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

    let runningLen = lane.finalizedSubroots.length;
    const validated: Array<{ baseIdx: number; roots: Uint8Array[] }> = [];
    for (const rootPageSeq of sortedSeqs) {
      const dec = dedupPages.get(rootPageSeq)!;
      const baseIdxBig = rootPageSeq * srPerPageBig;
      if (baseIdxBig > MAX_SUBROOTS_PER_LANE) {
        throw new RangeError(`SubtreeRootPage rootPageSeq out of range: ${rootPageSeq}`);
      }
      const baseIdx = Number(baseIdxBig);
      if (baseIdx > runningLen) {
        throw new RangeError(
          `SubtreeRootPage page_seq jump exceeds limit (sequence gap): ${rootPageSeq}`,
        );
      }
      const endIdxBig =
        baseIdxBig + BigInt(dec.roots.length) < maxRootsBig
          ? baseIdxBig + BigInt(dec.roots.length)
          : maxRootsBig;
      if (endIdxBig <= baseIdxBig) continue;
      const writeCnt = Number(endIdxBig - baseIdxBig);
      const roots: Uint8Array[] = [];
      for (let i = 0; i < writeCnt; i++) {
        frFromBeBytesStrict(dec.roots[i]!);
        roots.push(new Uint8Array(dec.roots[i]!));
      }
      const endIdx = Number(endIdxBig);
      if (endIdx > runningLen) runningLen = endIdx;
      validated.push({ baseIdx, roots });
    }

    for (const { baseIdx, roots } of validated) {
      for (let i = 0; i < roots.length; i++) {
        lane.finalizedSubroots[baseIdx + i] = roots[i]!;
      }
    }
  }

  /**
   * Stream a single `NullifierPage` against our `O(owned_unspent_notes)` prefix index,
   * marking matches `spent = true`, advancing `nextNfIndex`, and discarding stranger prefixes.
   */
  ingestNullifierPage(params: {
    laneId: number;
    pageSeq: bigint;
    raw: Uint8Array;
    maxNfIndex?: bigint;
  }): number {
    return this.ingestNullifierPages({
      laneId: params.laneId,
      nfPages: [{ pageSeq: params.pageSeq, raw: params.raw }],
      maxNfIndex: params.maxNfIndex,
    });
  }

  private _validateNullifierPages(params: {
    laneId: number;
    nfPages: ReadonlyArray<{ pageSeq: bigint; raw: Uint8Array }>;
    maxNfIndex?: bigint;
  }): Array<{
    pageBase: bigint;
    startSlot: number;
    limitSlot: number;
    prefixes: Uint8Array[];
  }> {
    const { laneId, nfPages, maxNfIndex } = params;
    if (!Number.isInteger(laneId) || laneId < 0 || laneId >= NUM_LANES) {
      throw new RangeError(`Invalid laneId ${String(laneId)}`);
    }
    if (
      maxNfIndex !== undefined &&
      (typeof maxNfIndex !== 'bigint' || maxNfIndex < 0n || maxNfIndex > U64_MAX)
    ) {
      throw new RangeError(`NullifierPage maxNfIndex out of range: ${String(maxNfIndex)}`);
    }
    if (nfPages.length === 0) return [];
    const lane = this.lanes[laneId]!;

    for (const entry of nfPages) {
      if (typeof entry.pageSeq !== 'bigint' || entry.pageSeq < 0n || entry.pageSeq > U64_MAX) {
        throw new RangeError(`NullifierPage pageSeq out of range: ${String(entry.pageSeq)}`);
      }
    }
    const sortedNfPages = [...nfPages].sort((a, b) =>
      a.pageSeq < b.pageSeq ? -1 : a.pageSeq > b.pageSeq ? 1 : 0,
    );

    let runningNfIndex = lane.nextNfIndex;
    const validated: Array<{
      pageBase: bigint;
      startSlot: number;
      limitSlot: number;
      prefixes: Uint8Array[];
    }> = [];
    for (const { pageSeq, raw } of sortedNfPages) {
      const nfPage = decodeNullifierPage(raw);
      if (nfPage.poolId !== this.poolId || nfPage.laneId !== laneId || nfPage.pageSeq !== pageSeq) {
        throw new Error(
          `NullifierPage header mismatch (expected pool=${this.poolId}, lane=${laneId}, seq=${pageSeq}; got pool=${nfPage.poolId}, lane=${nfPage.laneId}, seq=${nfPage.pageSeq})`,
        );
      }
      const pageBase = pageSeq * BigInt(NF_PER_PAGE);
      if (pageBase + BigInt(nfPage.count) > U64_MAX) {
        throw new RangeError(`NullifierPage pageSeq overflow: ${pageSeq}`);
      }
      if (pageBase > runningNfIndex) {
        throw new RangeError(
          `NullifierPage sequence gap: pageSeq=${pageSeq} starts at ${pageBase} > nextNfIndex=${runningNfIndex}`,
        );
      }
      const startSlot =
        runningNfIndex > pageBase
          ? Number(
              runningNfIndex - pageBase > BigInt(NF_PER_PAGE)
                ? BigInt(NF_PER_PAGE)
                : runningNfIndex - pageBase,
            )
          : 0;
      let limitSlot = nfPage.count;
      if (maxNfIndex !== undefined) {
        const capSlots =
          maxNfIndex > pageBase
            ? Number(
                maxNfIndex - pageBase > BigInt(NF_PER_PAGE)
                  ? BigInt(NF_PER_PAGE)
                  : maxNfIndex - pageBase,
              )
            : 0;
        if (capSlots < limitSlot) limitSlot = capSlots;
      }
      if (limitSlot > startSlot) {
        const endIdx = pageBase + BigInt(limitSlot);
        if (endIdx > runningNfIndex) runningNfIndex = endIdx;
      }
      validated.push({ pageBase, startSlot, limitSlot, prefixes: nfPage.prefixes });
    }
    return validated;
  }

  private _applyValidatedNullifierPages(
    laneId: number,
    validated: ReadonlyArray<{
      pageBase: bigint;
      startSlot: number;
      limitSlot: number;
      prefixes: Uint8Array[];
    }>,
  ): number {
    if (validated.length === 0) return 0;
    const lane = this.lanes[laneId]!;

    // Build an O(owned_unspent_notes) prefix lookup table across ALL lanes.
    const unspentByPrefix = new Map<string, OwnedNote[]>();
    for (const note of this.notes) {
      if (note.spent) continue;
      const prefHex = bytesToHex(note.nullifier.subarray(0, NF_PREFIX_LEN));
      const bucket = unspentByPrefix.get(prefHex);
      if (bucket) {
        bucket.push(note);
      } else {
        unspentByPrefix.set(prefHex, [note]);
      }
    }

    let newlySpent = 0;
    for (const { pageBase, startSlot, limitSlot, prefixes } of validated) {
      for (let slot = startSlot; slot < limitSlot; slot++) {
        if (unspentByPrefix.size > 0) {
          const prefHex = bytesToHex(prefixes[slot]!);
          const matched = unspentByPrefix.get(prefHex);
          if (matched) {
            for (const note of matched) {
              if (!note.spent) {
                note.spent = true;
                newlySpent++;
              }
            }
            unspentByPrefix.delete(prefHex);
          }
        }
        const nextIdx = pageBase + BigInt(slot) + 1n;
        if (nextIdx > lane.nextNfIndex) lane.nextNfIndex = nextIdx;
      }
    }
    return newlySpent;
  }

  /**
   * Stream `NullifierPage`s in ascending sequence order against an `O(owned_unspent_notes)`
   * lookup map (across all lanes), marking matching notes `spent = true`, advancing
   * `nextNfIndex`, and immediately discarding every stranger prefix.
   *
   * Pre-validates every page header, bounds, and strict contiguity (`pageBase <= runningNfIndex`)
   * BEFORE mutating any note or advancing `nextNfIndex`.
   */
  ingestNullifierPages(params: {
    laneId: number;
    nfPages: ReadonlyArray<{ pageSeq: bigint; raw: Uint8Array }>;
    maxNfIndex?: bigint;
  }): number {
    const validated = this._validateNullifierPages(params);
    return this._applyValidatedNullifierPages(params.laneId, validated);
  }

  /**
   * Prune retained `prevSealedLeaves` on any lane whose `GlobalRootHistory.stable` snapshot
   * (or `ROOT_RING_EPOCH` `RootSnapshotChoice`) has crossed past it.
   * Validates `source` strictly (including `poolId` binding for `DecodedGlobalRootHistory`)
   * before pruning any lane, and refuses to prune on `ROOT_RING_SLOT` (`latest`) snapshots so
   * `prevSealedLeaves` needed for offline `stable` witness builds are never wiped prematurely.
   */
  pruneSealedBeforeSnapshot(
    source: DecodedGlobalRootHistory | RootSnapshotChoice,
  ): void {
    if (!source || typeof source !== 'object') {
      throw new RangeError('pruneSealedBeforeSnapshot source must be an object');
    }
    let laneCounts: readonly bigint[];
    if ('slotRing' in source || 'stableLaneCounts' in source) {
      validateGlobalRootHistory(source as DecodedGlobalRootHistory, this.poolId);
      laneCounts = (source as DecodedGlobalRootHistory).stableLaneCounts;
    } else {
      validateRootSnapshotChoice(source);
      if (source.ringKind !== ROOT_RING_EPOCH) {
        return;
      }
      laneCounts = source.laneCounts;
    }
    for (let l = 0; l < NUM_LANES; l++) {
      const lane = this.lanes[l]!;
      const snapFrontierPage = laneCounts[l]! / BigInt(SUBTREE_LEAVES);
      if (lane.prevSealedSubSeq !== null && snapFrontierPage > lane.prevSealedSubSeq) {
        lane.prevSealedSubSeq = null;
        lane.prevSealedLeaves = [];
      }
    }
  }

  ingestLanePages(params: {
    fvk: FullViewingKey;
    laneId: number;
    subtreePages: ReadonlyArray<{ pageSeq: bigint; raw: Uint8Array }>;
    memoPages: ReadonlyArray<{ pageSeq: bigint; raw: Uint8Array }>;
    nfPages: ReadonlyArray<{ pageSeq: bigint; raw: Uint8Array }>;
  }): number {
    if (!params || typeof params !== 'object') {
      throw new RangeError('ingestLanePages params must be an object');
    }
    const { fvk, laneId, subtreePages, memoPages, nfPages } = params;
    if (!Number.isInteger(laneId) || laneId < 0 || laneId >= NUM_LANES) {
      throw new RangeError(`Invalid laneId ${String(laneId)}`);
    }
    if (!Array.isArray(subtreePages)) {
      throw new RangeError('ingestLanePages requires subtreePages array');
    }
    const lane = this.lanes[laneId]!;

    // Phase 1: Pre-validate ALL SubtreePages (headers, counts, canonical BN254 Fr on BOTH sealed
    // and unsealed leaves, and contiguous sealed pageSeq), ALL MemoPages, held frontier leaves,
    // FVK scalars, and ALL NullifierPages BEFORE mutating ANY store state (100% atomic on error).
    const pageLeavesMap = new Map<bigint, { leaves: Uint8Array[]; frLeaves: bigint[] }>();
    for (const { pageSeq, raw } of subtreePages) {
      const dec = decodeSubtreePage(raw);
      if (typeof pageSeq !== 'bigint' || pageSeq < 0n || pageSeq > U64_MAX) {
        throw new RangeError(`SubtreePage pageSeq out of range: ${String(pageSeq)}`);
      }
      if (dec.poolId !== this.poolId || dec.laneId !== laneId || dec.pageSeq !== pageSeq) {
        throw new Error(
          `SubtreePage header mismatch (expected pool=${this.poolId}, lane=${laneId}, seq=${pageSeq}; got pool=${dec.poolId}, lane=${dec.laneId}, seq=${dec.pageSeq})`,
        );
      }
      const frLeaves = dec.leaves.map((b) => frFromBeBytesStrict(b));
      // Enforce append-only prefix immutability against persisted frontier & prevSealed leaves
      if (lane.frontierLeaves.length > 0 && pageSeq === lane.frontierSubSeq) {
        const prefixLen = Math.min(dec.leaves.length, lane.frontierLeaves.length);
        for (let i = 0; i < prefixLen; i++) {
          if (!bytesEqual(dec.leaves[i]!, lane.frontierLeaves[i]!)) {
            throw new Error(
              'SubtreePage frontier prefix mismatch against persisted frontierLeaves',
            );
          }
        }
      }
      if (lane.prevSealedLeaves.length > 0 && lane.prevSealedSubSeq === pageSeq) {
        const prefixLen = Math.min(dec.leaves.length, lane.prevSealedLeaves.length);
        for (let i = 0; i < prefixLen; i++) {
          if (!bytesEqual(dec.leaves[i]!, lane.prevSealedLeaves[i]!)) {
            throw new Error(
              'SubtreePage prefix mismatch against persisted prevSealedLeaves',
            );
          }
        }
      }
      // Enforce immutability against already-persisted `finalizedSubroots[pageSeq]`
      if (dec.leaves.length === SUBTREE_LEAVES && pageSeq < BigInt(lane.finalizedSubroots.length)) {
        const seqNum = Number(pageSeq);
        const subroot = frToBeBytes(computeSubtree256Root(frLeaves, SUBTREE_LEAVES));
        if (!bytesEqual(subroot, lane.finalizedSubroots[seqNum]!)) {
          throw new Error(
            `SubtreePage subroot mismatch against persisted finalizedSubroots at seq=${pageSeq}`,
          );
        }
      }
      const existing = pageLeavesMap.get(pageSeq);
      if (existing) {
        const overlap = Math.min(existing.leaves.length, dec.leaves.length);
        for (let i = 0; i < overlap; i++) {
          if (!bytesEqual(existing.leaves[i]!, dec.leaves[i]!)) {
            throw new Error(`Conflicting duplicate SubtreePage entries at seq=${pageSeq}`);
          }
        }
        if (dec.leaves.length > existing.leaves.length) {
          pageLeavesMap.set(pageSeq, { leaves: dec.leaves, frLeaves });
        }
      } else {
        pageLeavesMap.set(pageSeq, { leaves: dec.leaves, frLeaves });
      }
    }

    if (!Array.isArray(memoPages)) {
      throw new RangeError('ingestLanePages requires memoPages array');
    }
    const memoMap = new Map<bigint, ReturnType<typeof decodeMemoPage>>();
    for (const { pageSeq, raw } of memoPages) {
      const dec = decodeMemoPage(raw);
      if (typeof pageSeq !== 'bigint' || pageSeq < 0n || pageSeq > U64_MAX) {
        throw new RangeError(`MemoPage pageSeq out of range: ${String(pageSeq)}`);
      }
      if (dec.poolId !== this.poolId || dec.laneId !== laneId || dec.pageSeq !== pageSeq) {
        throw new Error(
          `MemoPage header mismatch (expected pool=${this.poolId}, lane=${laneId}, seq=${pageSeq}; got pool=${dec.poolId}, lane=${dec.laneId}, seq=${dec.pageSeq})`,
        );
      }
      const existing = memoMap.get(pageSeq);
      if (!existing || dec.count > existing.count) {
        memoMap.set(pageSeq, dec);
      }
    }

    if (!Array.isArray(nfPages)) {
      throw new RangeError('ingestLanePages requires nfPages array');
    }
    const validatedNfPages = this._validateNullifierPages({ laneId, nfPages });

    const sortedSeqs = [...pageLeavesMap.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    let runningSubrootLen = lane.finalizedSubroots.length;
    const validatedSealed = new Map<bigint, { frLeaves: bigint[]; subroot: Uint8Array }>();
    for (const seq of sortedSeqs) {
      const { leaves, frLeaves } = pageLeavesMap.get(seq)!;
      if (leaves.length < SUBTREE_LEAVES && seq < BigInt(lane.finalizedSubroots.length)) {
        const hasFullHeldCopy =
          (seq === lane.frontierSubSeq && lane.frontierLeaves.length === SUBTREE_LEAVES) ||
          (lane.prevSealedSubSeq === seq && lane.prevSealedLeaves.length === SUBTREE_LEAVES);
        if (!hasFullHeldCopy) {
          throw new Error(
            `Truncated SubtreePage at seq=${seq} cannot be verified against persisted finalizedSubroots`,
          );
        }
      }
      if (leaves.length === SUBTREE_LEAVES) {
        if (seq < 0n || seq >= MAX_SUBROOTS_PER_LANE) {
          throw new RangeError(`SubtreePage pageSeq out of range: ${seq}`);
        }
        const seqNum = Number(seq);
        if (seqNum > runningSubrootLen) {
          throw new RangeError(
            `SubtreePage page_seq jump exceeds limit (sequence gap): ${seq}`,
          );
        }
        const subroot = frToBeBytes(computeSubtree256Root(frLeaves, SUBTREE_LEAVES));
        if (seqNum + 1 > runningSubrootLen) runningSubrootLen = seqNum + 1;
        validatedSealed.set(seq, { frLeaves, subroot });
      }
    }

    const suppliedFrontier = pageLeavesMap.get(lane.frontierSubSeq);
    const heldSealed =
      lane.frontierLeaves.length === SUBTREE_LEAVES &&
      (!suppliedFrontier || suppliedFrontier.leaves.length < SUBTREE_LEAVES);
    const heldFrLeaves = heldSealed
      ? lane.frontierLeaves.map((b) => frFromBeBytesStrict(b))
      : null;

    if (memoMap.size > 0) {
      frFromBeBytesStrict(fvk.spendPk);
      frFromBeBytesStrict(fvk.nk);
    }

    // Phase 2: All inputs validated cleanly — commit memos, subroots, freezes, frontiers, & NFs.
    let discovered = 0;
    for (;;) {
      const leafIdx = lane.nextMemoLeaf;
      if (leafIdx >= MAX_LEAVES_PER_LANE) break;
      const mSeq = leafIdx / BigInt(MEMO_NOTES_PER_PAGE);
      const mSlot = Number(leafIdx % BigInt(MEMO_NOTES_PER_PAGE));
      const mPage = memoMap.get(mSeq);
      if (!mPage || mSlot >= mPage.count) break;

      const sSeq = leafIdx / BigInt(SUBTREE_LEAVES);
      const sSlot = Number(leafIdx % BigInt(SUBTREE_LEAVES));
      const supplied = pageLeavesMap.get(sSeq)?.leaves;
      const bestLeaves =
        sSeq === lane.frontierSubSeq
          ? supplied && supplied.length > lane.frontierLeaves.length
            ? supplied
            : lane.frontierLeaves
          : supplied;
      if (!bestLeaves || sSlot >= bestLeaves.length) break;
      const cmBe = bestLeaves[sSlot]!;

      const entry = mPage.entries[mSlot]!;
      const dec = tryDecryptAndVerifyMemoEntry(
        fvk,
        entry.viewTag,
        entry.ephemeralPk,
        entry.ciphertext,
        cmBe!,
      );
      if (dec) {
        if (
          this.recordVerifiedMemo({
            fvk,
            laneId,
            leafIdx,
            decrypted: dec,
            cmBe: cmBe!,
          })
        ) {
          discovered++;
        }
      }
      lane.nextMemoLeaf = leafIdx + 1n;
    }

    const freezeNotesInPage = (
      seq: bigint,
      rawLeaves: readonly Uint8Array[],
      frLeaves: readonly bigint[],
    ) => {
      for (const note of this.notes) {
        if (
          note.laneId === laneId &&
          note.leafIndex / BigInt(SUBTREE_LEAVES) === seq &&
          !note.frozenIntraSiblings
        ) {
          const offset = Number(note.leafIndex % BigInt(SUBTREE_LEAVES));
          if (!bytesEqual(rawLeaves[offset]!, note.commitment)) {
            continue;
          }
          const { siblings, positions } = extractIntraSubtreeSiblings(
            frLeaves,
            SUBTREE_LEAVES,
            offset,
          );
          note.frozenIntraSiblings = siblings.map((lvl) => lvl.map((x) => frToBeBytes(x)));
          note.frozenIntraPositions = positions;
        }
      }
    };

    if (heldSealed && heldFrLeaves) {
      const heldSeq = lane.frontierSubSeq;
      freezeNotesInPage(heldSeq, lane.frontierLeaves, heldFrLeaves);
      const pageEndLeaf = (heldSeq + 1n) * BigInt(SUBTREE_LEAVES);
      if (lane.nextMemoLeaf >= pageEndLeaf) {
        lane.prevSealedSubSeq = heldSeq;
        lane.prevSealedLeaves = lane.frontierLeaves;
        lane.frontierSubSeq = heldSeq + 1n;
        lane.frontierLeaves = [];
      }
    }

    for (const seq of sortedSeqs) {
      const { leaves } = pageLeavesMap.get(seq)!;
      const memoSubSeq = lane.nextMemoLeaf / BigInt(SUBTREE_LEAVES);
      if (leaves.length === SUBTREE_LEAVES) {
        const seqNum = Number(seq);
        const { frLeaves, subroot } = validatedSealed.get(seq)!;
        lane.finalizedSubroots[seqNum] = subroot;
        freezeNotesInPage(seq, leaves, frLeaves);

        const pageEndLeaf = (seq + 1n) * BigInt(SUBTREE_LEAVES);
        if (lane.nextMemoLeaf >= pageEndLeaf) {
          if (seq >= lane.frontierSubSeq) {
            lane.prevSealedSubSeq = seq;
            lane.prevSealedLeaves = leaves.map((b) => new Uint8Array(b));
            lane.frontierSubSeq = seq + 1n;
            lane.frontierLeaves = [];
          }
        } else if (
          seq === memoSubSeq &&
          seq >= lane.frontierSubSeq &&
          (seq > lane.frontierSubSeq || leaves.length > lane.frontierLeaves.length)
        ) {
          // Hold sealed page leaves until MemoPages finish scanning all 256 leaves in this page
          lane.frontierSubSeq = seq;
          lane.frontierLeaves = leaves.map((b) => new Uint8Array(b));
        }
      } else if (
        seq >= BigInt(lane.finalizedSubroots.length) &&
        seq >= lane.frontierSubSeq &&
        seq <= memoSubSeq &&
        (seq > lane.frontierSubSeq || leaves.length > lane.frontierLeaves.length)
      ) {
        lane.frontierSubSeq = seq;
        lane.frontierLeaves = leaves.map((b) => new Uint8Array(b));
      }
    }

    this._applyValidatedNullifierPages(laneId, validatedNfPages);
    return discovered;
  }

  private _buildSingleWitnessWithSnapshot(
    note: OwnedNote,
    chosen: RootSnapshotChoice,
  ): { superRoot: bigint; path: MerklePath4Ary } {
    const lane = this.lanes[note.laneId]!;
    const snapCount = chosen.laneCounts[note.laneId]!;
    if (typeof snapCount !== 'bigint' || snapCount < 0n || snapCount > MAX_LEAVES_PER_LANE) {
      throw new RangeError(
        `RootSnapshotChoice laneCounts[${note.laneId}] out of range: ${String(snapCount)}`,
      );
    }
    if (note.leafIndex >= snapCount) {
      throw new Error('Note not yet included in root snapshot');
    }
    const targetPage = note.leafIndex / BigInt(SUBTREE_LEAVES);
    const targetOffset = Number(note.leafIndex % BigInt(SUBTREE_LEAVES));
    const frontierPage = snapCount / BigInt(SUBTREE_LEAVES);
    const frontierRem = Number(snapCount % BigInt(SUBTREE_LEAVES));

    const resolveFrontierLeaves = (): Uint8Array[] | null => {
      if (lane.frontierSubSeq === frontierPage && lane.frontierLeaves.length >= frontierRem) {
        return lane.frontierLeaves;
      }
      if (
        lane.prevSealedSubSeq !== null &&
        lane.prevSealedSubSeq === frontierPage &&
        lane.prevSealedLeaves.length >= frontierRem
      ) {
        return lane.prevSealedLeaves;
      }
      return null;
    };

    let intraSiblings: bigint[][];
    let intraPositions: number[];
    if (targetPage < frontierPage) {
      if (!note.frozenIntraSiblings || !note.frozenIntraPositions) {
        throw new Error('Missing frozen intra-subtree siblings for sealed note');
      }
      if (
        note.frozenIntraSiblings.length !== SUBTREE_LEVELS_4ARY ||
        note.frozenIntraPositions.length !== SUBTREE_LEVELS_4ARY
      ) {
        throw new Error('Malformed frozen intra-subtree witness');
      }
      for (const p of note.frozenIntraPositions) {
        if (!Number.isInteger(p) || p < 0 || p > 3) {
          throw new RangeError(`Invalid frozen intra-subtree position: ${p}`);
        }
      }
      intraSiblings = note.frozenIntraSiblings.map((lvl) =>
        lvl.map((b) => frFromBeBytesStrict(b)),
      );
      intraPositions = [...note.frozenIntraPositions];
    } else {
      const fLeaves = resolveFrontierLeaves();
      if (!fLeaves) {
        throw new MissingFrontierLeavesError();
      }
      const fFr = fLeaves.slice(0, frontierRem).map((b) => frFromBeBytesStrict(b));
      const res = extractIntraSubtreeSiblings(fFr, frontierRem, targetOffset);
      intraSiblings = res.siblings;
      intraPositions = res.positions;
    }

    const snapRootsFr = chosen.laneRoots.map((b) => frFromBeBytesStrict(b));
    if (lane.finalizedSubroots.length < Number(frontierPage)) {
      throw new Error('Missing finalized subroots');
    }
    const finalizedFr = lane.finalizedSubroots
      .slice(0, Number(frontierPage))
      .map((b) => frFromBeBytesStrict(b));
    let frontierFr: bigint[] | undefined;
    if (frontierRem > 0) {
      const fLeaves = resolveFrontierLeaves();
      if (!fLeaves) {
        throw new MissingFrontierLeavesError();
      }
      frontierFr = fLeaves.slice(0, frontierRem).map((b) => frFromBeBytesStrict(b));
    }

    const path = buildWitnessFromFrozenSubsiblings({
      laneId: note.laneId,
      targetLeafIdx: note.leafIndex,
      intraSiblings,
      intraPositions,
      laneRoots: snapRootsFr,
      laneLeafCount: snapCount,
      finalizedSubtreeRoots: finalizedFr,
      frontierPageLeaves: frontierFr,
    });
    const superRoot = frFromBeBytesStrict(chosen.superRoot);
    const cm = frFromBeBytesStrict(note.commitment);
    if (
      computeSuperRoot4Ary(snapRootsFr) !== superRoot ||
      computeMerkleRoot4Ary(path, cm) !== superRoot
    ) {
      throw new Error('Reconstructed Merkle root mismatch');
    }
    return { superRoot, path };
  }

  /**
   * Select ONE shared `RootSnapshotChoice` covering ALL `notes` (preferring `stable`
   * `ROOT_RING_EPOCH`, falling back to `latest` `ROOT_RING_SLOT` when any note is newer OR when
   * the local store lacks pre-seal frontier leaves for an older `stable` page) and build offline
   * 4-ary Depth-20 Merkle witnesses for every note against that shared snapshot.
   */
  buildWitnessesForNotes(
    notes: readonly OwnedNote[],
    rootSource: DecodedGlobalRootHistory | RootSnapshotChoice,
  ): {
    snapshot: RootSnapshotChoice;
    superRoot: bigint;
    paths: MerklePath4Ary[];
    rootRingKind: number;
    rootRingIdx: number;
    snapshotSlot: bigint;
  } {
    if (!Array.isArray(notes) || notes.length === 0) {
      throw new RangeError('notes must be a non-empty array');
    }
    for (const note of notes) {
      if (!note || typeof note !== 'object') {
        throw new RangeError('OwnedNote must be an object');
      }
      if (note.poolId !== this.poolId) {
        throw new Error(`Note poolId mismatch (expected ${this.poolId}, got ${note.poolId})`);
      }
      if (!Number.isInteger(note.laneId) || note.laneId < 0 || note.laneId >= NUM_LANES) {
        throw new RangeError(`Invalid laneId ${note.laneId}`);
      }
      if (
        typeof note.leafIndex !== 'bigint' ||
        note.leafIndex < 0n ||
        note.leafIndex >= MAX_LEAVES_PER_LANE
      ) {
        throw new RangeError(`Invalid leafIndex ${String(note.leafIndex)}`);
      }
    }
    if (!rootSource || typeof rootSource !== 'object') {
      throw new RangeError('rootSource must be a GlobalRootHistory or RootSnapshotChoice');
    }

    let chosen: RootSnapshotChoice;
    let history: DecodedGlobalRootHistory | null = null;
    if ('slotRing' in rootSource || 'stableLaneCounts' in rootSource) {
      history = rootSource as DecodedGlobalRootHistory;
      validateGlobalRootHistory(history, this.poolId);
      const selected = selectRootSnapshotForNotes(
        history,
        notes.map((n) => ({ laneId: n.laneId, leafIndex: n.leafIndex })),
      );
      if (!selected) {
        throw new Error(
          notes.length === 1
            ? 'Note not yet included in GlobalRootHistory'
            : 'Notes not yet included in GlobalRootHistory',
        );
      }
      chosen = selected;
    } else {
      validateRootSnapshotChoice(rootSource);
      chosen = rootSource;
    }

    const buildAll = (
      snap: RootSnapshotChoice,
    ): { superRoot: bigint; paths: MerklePath4Ary[] } => {
      const paths: MerklePath4Ary[] = [];
      let superRoot = 0n;
      for (const note of notes) {
        const res = this._buildSingleWitnessWithSnapshot(note, snap);
        superRoot = res.superRoot;
        paths.push(res.path);
      }
      return { superRoot, paths };
    };

    let built: { superRoot: bigint; paths: MerklePath4Ary[] };
    try {
      built = buildAll(chosen);
    } catch (err) {
      if (
        err instanceof MissingFrontierLeavesError &&
        history !== null &&
        chosen.ringKind === ROOT_RING_EPOCH &&
        !laneCountsEqual(history.latestLaneCounts, history.stableLaneCounts) &&
        notes.every((n) => n.leafIndex < history!.latestLaneCounts[n.laneId]!)
      ) {
        const latestChoice: RootSnapshotChoice = {
          ringKind: ROOT_RING_SLOT,
          ringIdx: history.slotCursor,
          slot: history.latestSlot,
          superRoot: history.latestSuperRoot,
          laneRoots: history.latestLaneRoots,
          laneCounts: history.latestLaneCounts,
        };
        built = buildAll(latestChoice);
        chosen = latestChoice;
      } else {
        throw err;
      }
    }

    const touchedLanes = new Set(notes.map((n) => n.laneId));
    for (const laneId of touchedLanes) {
      const lane = this.lanes[laneId]!;
      if (lane.prevSealedSubSeq !== null) {
        const stableFrontierPage = history
          ? history.stableLaneCounts[laneId]! / BigInt(SUBTREE_LEAVES)
          : chosen.ringKind === ROOT_RING_EPOCH
            ? chosen.laneCounts[laneId]! / BigInt(SUBTREE_LEAVES)
            : -1n;
        if (stableFrontierPage > lane.prevSealedSubSeq) {
          lane.prevSealedSubSeq = null;
          lane.prevSealedLeaves = [];
        }
      }
    }

    return {
      snapshot: chosen,
      superRoot: built.superRoot,
      paths: built.paths,
      rootRingKind: chosen.ringKind,
      rootRingIdx: chosen.ringIdx,
      snapshotSlot: chosen.slot,
    };
  }

  buildWitnessForNote(
    note: OwnedNote,
    rootSource: DecodedGlobalRootHistory | RootSnapshotChoice,
  ): {
    superRoot: bigint;
    path: MerklePath4Ary;
    rootRingKind: number;
    rootRingIdx: number;
    snapshotSlot: bigint;
  } {
    const res = this.buildWitnessesForNotes([note], rootSource);
    return {
      superRoot: res.superRoot,
      path: res.paths[0]!,
      rootRingKind: res.rootRingKind,
      rootRingIdx: res.rootRingIdx,
      snapshotSlot: res.snapshotSlot,
    };
  }

  toJSON(): string {
    return JSON.stringify({
      poolId: this.poolId,
      birthdaySlot: this.birthdaySlot.toString(),
      lanes: this.lanes.map((l) => ({
        finalizedSubroots: l.finalizedSubroots.map(bytesToHex),
        frontierSubSeq: l.frontierSubSeq.toString(),
        frontierLeaves: l.frontierLeaves.map(bytesToHex),
        ...(l.prevSealedSubSeq !== null && l.prevSealedLeaves.length > 0
          ? {
              prevSealedSubSeq: l.prevSealedSubSeq.toString(),
              prevSealedLeaves: l.prevSealedLeaves.map(bytesToHex),
            }
          : {}),
        nextMemoLeaf: l.nextMemoLeaf.toString(),
        nextNfIndex: l.nextNfIndex.toString(),
      })),
      notes: this.notes.map((n) => ({
        poolId: n.poolId,
        laneId: n.laneId,
        leafIndex: n.leafIndex.toString(),
        globalLeafIndex: n.globalLeafIndex.toString(),
        mint: bytesToHex(n.mint),
        amount: n.amount.toString(),
        tweak: bytesToHex(n.tweak),
        blinding: bytesToHex(n.blinding),
        stealthOwner: bytesToHex(n.stealthOwner),
        commitment: bytesToHex(n.commitment),
        nullifier: bytesToHex(n.nullifier),
        paymentId: bytesToHex(n.paymentId),
        isDynamic: n.isDynamic,
        spent: n.spent,
        frozenIntraSiblings: n.frozenIntraSiblings
          ? n.frozenIntraSiblings.map((lvl) => lvl.map(bytesToHex))
          : null,
        frozenIntraPositions: n.frozenIntraPositions,
      })),
    });
  }

  static fromJSON(json: string): CompactWalletStore {
    const raw = JSON.parse(json) as Record<string, unknown>;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new Error('Invalid CompactWalletStore JSON');
    }
    if (
      typeof raw.poolId !== 'number' ||
      !Number.isInteger(raw.poolId) ||
      raw.poolId < 0 ||
      raw.poolId > U32_MAX
    ) {
      throw new Error(`Invalid CompactWalletStore JSON poolId=${String(raw.poolId)}`);
    }
    const birthdaySlot = parseU64Decimal(raw.birthdaySlot, 'birthdaySlot');
    if (!Array.isArray(raw.lanes) || raw.lanes.length !== NUM_LANES) {
      throw new Error(
        `Invalid CompactWalletStore JSON: expected ${NUM_LANES} lanes, got ${Array.isArray(raw.lanes) ? raw.lanes.length : typeof raw.lanes}`,
      );
    }
    if (!Array.isArray(raw.notes)) {
      throw new Error('Invalid CompactWalletStore JSON: notes must be an array');
    }
    const store = new CompactWalletStore(raw.poolId, birthdaySlot);
    store.lanes = raw.lanes.map((laneRaw, laneIdx) => {
      if (!laneRaw || typeof laneRaw !== 'object' || Array.isArray(laneRaw)) {
        throw new Error(`Invalid CompactWalletStore JSON lane[${laneIdx}]`);
      }
      const l = laneRaw as Record<string, unknown>;
      if (!Array.isArray(l.finalizedSubroots)) {
        throw new Error(`Invalid CompactWalletStore JSON lane[${laneIdx}].finalizedSubroots`);
      }
      if (BigInt(l.finalizedSubroots.length) > MAX_SUBROOTS_PER_LANE) {
        throw new Error(
          `Invalid CompactWalletStore JSON lane[${laneIdx}].finalizedSubroots exceeds limit`,
        );
      }
      if (!Array.isArray(l.frontierLeaves)) {
        throw new Error(`Invalid CompactWalletStore JSON lane[${laneIdx}].frontierLeaves`);
      }
      if (l.frontierLeaves.length > SUBTREE_LEAVES) {
        throw new Error('Invalid CompactWalletStore JSON: lane leaves exceed SUBTREE_LEAVES');
      }
      if (l.prevSealedLeaves !== undefined && !Array.isArray(l.prevSealedLeaves)) {
        throw new Error(`Invalid CompactWalletStore JSON lane[${laneIdx}].prevSealedLeaves`);
      }
      if (Array.isArray(l.prevSealedLeaves) && l.prevSealedLeaves.length > SUBTREE_LEAVES) {
        throw new Error('Invalid CompactWalletStore JSON: lane leaves exceed SUBTREE_LEAVES');
      }
      const finalizedSubroots = l.finalizedSubroots.map((h, i) => {
        const b = hexToBytesExact(h, 32, `lane[${laneIdx}].finalizedSubroots[${i}]`);
        frFromBeBytesStrict(b);
        return b;
      });
      const frontierLeaves = l.frontierLeaves.map((h, i) => {
        const b = hexToBytesExact(h, 32, `lane[${laneIdx}].frontierLeaves[${i}]`);
        frFromBeBytesStrict(b);
        return b;
      });
      const prevSealedLeaves = Array.isArray(l.prevSealedLeaves)
        ? l.prevSealedLeaves.map((h, i) => {
            const b = hexToBytesExact(h, 32, `lane[${laneIdx}].prevSealedLeaves[${i}]`);
            frFromBeBytesStrict(b);
            return b;
          })
        : [];
      const frontierSubSeq = parseU64Decimal(
        l.frontierSubSeq,
        `lane[${laneIdx}].frontierSubSeq`,
      );
      if (frontierSubSeq > MAX_SUBROOTS_PER_LANE) {
        throw new Error(
          `Invalid CompactWalletStore JSON lane[${laneIdx}].frontierSubSeq out of range`,
        );
      }
      const prevSealedSubSeq =
        l.prevSealedSubSeq !== undefined && l.prevSealedSubSeq !== null
          ? parseU64Decimal(l.prevSealedSubSeq, `lane[${laneIdx}].prevSealedSubSeq`)
          : null;
      if (prevSealedSubSeq !== null && prevSealedSubSeq >= MAX_SUBROOTS_PER_LANE) {
        throw new Error(
          `Invalid CompactWalletStore JSON lane[${laneIdx}].prevSealedSubSeq out of range`,
        );
      }
      const nextMemoLeaf = parseU64Decimal(l.nextMemoLeaf, `lane[${laneIdx}].nextMemoLeaf`);
      if (nextMemoLeaf > MAX_LEAVES_PER_LANE) {
        throw new Error(
          `Invalid CompactWalletStore JSON lane[${laneIdx}].nextMemoLeaf out of range`,
        );
      }
      const nextNfIndex = parseU64Decimal(l.nextNfIndex, `lane[${laneIdx}].nextNfIndex`);
      return {
        finalizedSubroots,
        frontierSubSeq,
        frontierLeaves,
        prevSealedSubSeq,
        prevSealedLeaves,
        nextMemoLeaf,
        nextNfIndex,
      };
    });
    const seenNotes = new Set<string>();
    store.notes = raw.notes.map((noteRaw, noteIdx) => {
      if (!noteRaw || typeof noteRaw !== 'object' || Array.isArray(noteRaw)) {
        throw new Error(`Invalid CompactWalletStore JSON note[${noteIdx}]`);
      }
      const n = noteRaw as Record<string, unknown>;
      if (
        typeof n.poolId !== 'number' ||
        !Number.isInteger(n.poolId) ||
        n.poolId < 0 ||
        n.poolId > U32_MAX
      ) {
        throw new Error(`Invalid CompactWalletStore JSON note[${noteIdx}].poolId=${String(n.poolId)}`);
      }
      if (n.poolId !== raw.poolId) {
        throw new Error(
          `Invalid CompactWalletStore JSON note[${noteIdx}].poolId=${n.poolId} does not match store poolId=${raw.poolId}`,
        );
      }
      if (
        typeof n.laneId !== 'number' ||
        !Number.isInteger(n.laneId) ||
        n.laneId < 0 ||
        n.laneId >= NUM_LANES
      ) {
        throw new Error(`Invalid CompactWalletStore JSON note laneId=${String(n.laneId)}`);
      }
      const leafIndex = parseU64Decimal(n.leafIndex, `note[${noteIdx}].leafIndex`);
      if (leafIndex >= MAX_LEAVES_PER_LANE) {
        throw new Error(`Invalid CompactWalletStore JSON note[${noteIdx}].leafIndex out of range`);
      }
      const noteKey = `${n.laneId}:${leafIndex.toString()}`;
      if (seenNotes.has(noteKey)) {
        throw new Error(
          `Invalid CompactWalletStore JSON: duplicate note at (laneId=${n.laneId}, leafIndex=${leafIndex})`,
        );
      }
      seenNotes.add(noteKey);
      const globalLeafIndex = parseU64Decimal(
        n.globalLeafIndex,
        `note[${noteIdx}].globalLeafIndex`,
      );
      const expectedGlobalLeaf = (BigInt(n.laneId) << 36n) | leafIndex;
      if (globalLeafIndex !== expectedGlobalLeaf) {
        throw new Error(
          `Invalid CompactWalletStore JSON note[${noteIdx}].globalLeafIndex mismatch`,
        );
      }
      const amount = parseU64Decimal(n.amount, `note[${noteIdx}].amount`);
      if (typeof n.isDynamic !== 'boolean') {
        throw new Error(`Invalid CompactWalletStore JSON note[${noteIdx}].isDynamic`);
      }
      if (typeof n.spent !== 'boolean') {
        throw new Error(`Invalid CompactWalletStore JSON note[${noteIdx}].spent`);
      }
      const paymentId =
        n.paymentId === undefined
          ? new Uint8Array(MEMO_PAYMENT_ID_LEN)
          : hexToBytesExact(n.paymentId, MEMO_PAYMENT_ID_LEN, `note[${noteIdx}].paymentId`);

      const hasSibs = n.frozenIntraSiblings !== null && n.frozenIntraSiblings !== undefined;
      const hasPos = n.frozenIntraPositions !== null && n.frozenIntraPositions !== undefined;
      if (hasSibs !== hasPos) {
        throw new Error(
          `Invalid CompactWalletStore JSON note[${noteIdx}]: frozenIntraSiblings and frozenIntraPositions must both be present or both null`,
        );
      }
      let frozenIntraSiblings: Uint8Array[][] | null = null;
      let frozenIntraPositions: number[] | null = null;
      if (hasSibs && hasPos) {
        if (
          !Array.isArray(n.frozenIntraSiblings) ||
          n.frozenIntraSiblings.length !== SUBTREE_LEVELS_4ARY
        ) {
          throw new Error(
            `Invalid CompactWalletStore JSON note[${noteIdx}].frozenIntraSiblings length`,
          );
        }
        frozenIntraSiblings = n.frozenIntraSiblings.map((lvl, h) => {
          if (!Array.isArray(lvl) || lvl.length !== 3) {
            throw new Error(
              `Invalid CompactWalletStore JSON note[${noteIdx}].frozenIntraSiblings[${h}]`,
            );
          }
          return lvl.map((entry, k) => {
            const b = hexToBytesExact(
              entry,
              32,
              `note[${noteIdx}].frozenIntraSiblings[${h}][${k}]`,
            );
            frFromBeBytesStrict(b);
            return b;
          });
        });
        if (
          !Array.isArray(n.frozenIntraPositions) ||
          n.frozenIntraPositions.length !== SUBTREE_LEVELS_4ARY
        ) {
          throw new Error(
            `Invalid CompactWalletStore JSON note[${noteIdx}].frozenIntraPositions length`,
          );
        }
        frozenIntraPositions = n.frozenIntraPositions.map((p, h) => {
          if (typeof p !== 'number' || !Number.isInteger(p) || p < 0 || p > 3) {
            throw new Error(
              `Invalid CompactWalletStore JSON note[${noteIdx}].frozenIntraPositions[${h}]=${String(p)}`,
            );
          }
          return p;
        });
      }
      const tweak = hexToBytesExact(n.tweak, 32, `note[${noteIdx}].tweak`);
      const blinding = hexToBytesExact(n.blinding, 32, `note[${noteIdx}].blinding`);
      const stealthOwner = hexToBytesExact(n.stealthOwner, 32, `note[${noteIdx}].stealthOwner`);
      const commitment = hexToBytesExact(n.commitment, 32, `note[${noteIdx}].commitment`);
      const nullifier = hexToBytesExact(n.nullifier, 32, `note[${noteIdx}].nullifier`);
      frFromBeBytesStrict(tweak);
      frFromBeBytesStrict(blinding);
      frFromBeBytesStrict(stealthOwner);
      frFromBeBytesStrict(commitment);
      frFromBeBytesStrict(nullifier);
      return {
        poolId: n.poolId,
        laneId: n.laneId,
        leafIndex,
        globalLeafIndex,
        mint: hexToBytesExact(n.mint, 32, `note[${noteIdx}].mint`),
        amount,
        tweak,
        blinding,
        stealthOwner,
        commitment,
        nullifier,
        paymentId,
        isDynamic: n.isDynamic,
        spent: n.spent,
        frozenIntraSiblings,
        frozenIntraPositions,
      };
    });
    // Backwards-compatible migration: honor any legacy `seenNfPrefixes` against owned notes,
    // then discard stranger prefixes permanently so RAM & disk stay bounded.
    if (Array.isArray(raw.seenNfPrefixes) && raw.seenNfPrefixes.length > 0) {
      const legacySet = new Set<string>();
      for (const p of raw.seenNfPrefixes) {
        if (typeof p === 'string' && p.length === NF_PREFIX_LEN * 2 && HEX_RE.test(p)) {
          legacySet.add(p.toLowerCase());
        }
      }
      for (const note of store.notes) {
        if (!note.spent) {
          const prefHex = bytesToHex(note.nullifier.subarray(0, NF_PREFIX_LEN));
          if (legacySet.has(prefHex)) note.spent = true;
        }
      }
    }
    return store;
  }
}
