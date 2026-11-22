/**
 * Zero-indexer `CompactWalletStore` & 4-ary Depth-20 Merkle witness builder matching
 * `crates/audren-circuits/src/merkle.rs` and `crates/client/src/store.rs` bit-for-bit.
 *
 * Discards every sealed `SubtreePage` (`8,256 B`) and `MemoPage` (`10,144 B`) immediately after
 * scanning, persisting only frozen 12-sibling intra-subtree paths (`384 B` per owned note),
 * `32 B` finalized level-4 subroots, frontier tail leaves, and `16 B` nullifier prefixes.
 */

import {
  LANE_DEPTH_4ARY,
  MEMO_NOTES_PER_PAGE,
  NF_PER_PAGE,
  NF_PREFIX_LEN,
  NUM_LANES,
  SUBTREE_LEAVES,
  SUBTREE_LEVELS_4ARY,
  TOTAL_DEPTH_4ARY,
  ZERO_HASHES_4ARY,
} from './constants.ts';
import { tryDecryptAndVerifyMemoEntry } from './crypto.ts';
import type { FullViewingKey, SelectiveDisclosureProof } from './keys.ts';
import { fvkRealNullifier, fvkStealthOwner } from './keys.ts';
import {
  decodeMemoPage,
  decodeNullifierPage,
  decodeSubtreePage,
  type DecodedRootCheckpoint,
} from './layout.ts';
import {
  computeNoteCommitment,
  computeSubtree256Root,
  deriveAssetId,
  frFromBeBytesStrict,
  frToBeBytes,
  poseidon4,
} from './poseidon.ts';

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
    } else {
      [c0, c1, c2, c3] = [s[0]!, s[1]!, s[2]!, cur];
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
  if (targetOffset < 0 || targetOffset >= validLen || validLen > SUBTREE_LEAVES) {
    throw new RangeError(`Invalid targetOffset=${targetOffset}, validLen=${validLen}`);
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

export function buildWitnessFromFrozenSubsiblings(params: {
  laneId: number;
  targetLeafIdx: bigint;
  intraSiblings: readonly (readonly bigint[])[];
  intraPositions: readonly number[];
  ckptLaneRoots: readonly bigint[];
  ckptLaneLeafCount: bigint;
  finalizedSubtreeRoots: readonly bigint[];
  frontierPageLeaves?: readonly bigint[];
}): MerklePath4Ary {
  const {
    laneId,
    targetLeafIdx,
    intraSiblings,
    intraPositions,
    ckptLaneRoots,
    ckptLaneLeafCount,
    finalizedSubtreeRoots,
    frontierPageLeaves,
  } = params;
  if (laneId < 0 || laneId >= NUM_LANES) throw new RangeError(`Invalid laneId ${laneId}`);
  if (targetLeafIdx >= ckptLaneLeafCount) {
    throw new RangeError('targetLeafIdx >= ckptLaneLeafCount');
  }

  const path = emptyMerklePath4Ary();
  for (let h = 0; h < SUBTREE_LEVELS_4ARY; h++) {
    path.siblings[h] = [...intraSiblings[h]!];
    path.positions[h] = intraPositions[h]!;
  }

  const targetPageIdx = Number(targetLeafIdx / BigInt(SUBTREE_LEAVES));
  const frontierPageIdx = Number(ckptLaneLeafCount / BigInt(SUBTREE_LEAVES));
  const frontierRem = Number(ckptLaneLeafCount % BigInt(SUBTREE_LEAVES));

  let levelNodes: bigint[] = [];
  for (let p = 0; p < frontierPageIdx; p++) {
    levelNodes.push(finalizedSubtreeRoots[p]!);
  }
  if (frontierRem > 0) {
    if (!frontierPageLeaves || frontierPageLeaves.length < frontierRem) {
      throw new Error('Missing frontierPageLeaves for unsealed checkpoint tail');
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
    if (k !== pos18) sib18.push(ckptLaneRoots[group4 * 4 + k]!);
  }
  path.siblings[LANE_DEPTH_4ARY] = sib18;

  const groupHashes = [
    poseidon4(ckptLaneRoots[0]!, ckptLaneRoots[1]!, ckptLaneRoots[2]!, ckptLaneRoots[3]!),
    poseidon4(ckptLaneRoots[4]!, ckptLaneRoots[5]!, ckptLaneRoots[6]!, ckptLaneRoots[7]!),
    poseidon4(ckptLaneRoots[8]!, ckptLaneRoots[9]!, ckptLaneRoots[10]!, ckptLaneRoots[11]!),
    poseidon4(ckptLaneRoots[12]!, ckptLaneRoots[13]!, ckptLaneRoots[14]!, ckptLaneRoots[15]!),
  ];
  path.positions[LANE_DEPTH_4ARY + 1] = group4;
  const sib19: bigint[] = [];
  for (let k = 0; k < 4; k++) {
    if (k !== group4) sib19.push(groupHashes[k]!);
  }
  path.siblings[LANE_DEPTH_4ARY + 1] = sib19;

  return path;
}

export function buildHistoricalWitness4Ary(params: {
  laneId: number;
  targetLeafIdx: bigint;
  ckptLaneRoots: readonly bigint[];
  ckptLaneLeafCount: bigint;
  finalizedSubtreeRoots: readonly bigint[];
  targetPageLeaves: readonly bigint[];
  frontierPageLeaves?: readonly bigint[];
}): MerklePath4Ary {
  const targetPageIdx = Number(params.targetLeafIdx / BigInt(SUBTREE_LEAVES));
  const targetOffset = Number(params.targetLeafIdx % BigInt(SUBTREE_LEAVES));
  const frontierPageIdx = Number(params.ckptLaneLeafCount / BigInt(SUBTREE_LEAVES));
  const frontierRem = Number(params.ckptLaneLeafCount % BigInt(SUBTREE_LEAVES));
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
    ckptLaneRoots: params.ckptLaneRoots,
    ckptLaneLeafCount: params.ckptLaneLeafCount,
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
  isDynamic: boolean;
  spent: boolean;
  frozenIntraSiblings: Uint8Array[][] | null; // [4][3] 32-byte BE
  frozenIntraPositions: number[] | null; // [4]
}

export interface CompactLaneState {
  finalizedSubroots: Uint8Array[];
  frontierSubSeq: bigint;
  frontierLeaves: Uint8Array[];
  nextMemoLeaf: bigint;
  nextNfIndex: bigint;
}

function bytesToHex(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.byteLength; i++) s += b[i]!.toString(16).padStart(2, '0');
  return s;
}

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length >>> 1);
  for (let i = 0; i < out.byteLength; i++) {
    out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function exportSelectiveDisclosureProof(note: OwnedNote): SelectiveDisclosureProof {
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
  seenNfPrefixes: Set<string>;

  constructor(poolId = 0, birthdaySlot = 0n) {
    this.poolId = poolId;
    this.birthdaySlot = birthdaySlot;
    this.lanes = Array.from({ length: NUM_LANES }, () => ({
      finalizedSubroots: [],
      frontierSubSeq: 0n,
      frontierLeaves: [],
      nextMemoLeaf: 0n,
      nextNfIndex: 0n,
    }));
    this.notes = [];
    this.seenNfPrefixes = new Set<string>();
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

  ingestLanePages(params: {
    fvk: FullViewingKey;
    laneId: number;
    subtreePages: ReadonlyArray<{ pageSeq: bigint; raw: Uint8Array }>;
    memoPages: ReadonlyArray<{ pageSeq: bigint; raw: Uint8Array }>;
    nfPages: ReadonlyArray<{ pageSeq: bigint; raw: Uint8Array }>;
  }): number {
    const { fvk, laneId, subtreePages, memoPages, nfPages } = params;
    if (laneId < 0 || laneId >= NUM_LANES) throw new RangeError(`Invalid laneId ${laneId}`);
    const lane = this.lanes[laneId]!;

    const pageLeavesMap = new Map<bigint, Uint8Array[]>();
    for (const { pageSeq, raw } of subtreePages) {
      const dec = decodeSubtreePage(raw);
      pageLeavesMap.set(pageSeq, dec.leaves);
    }

    const memoMap = new Map<bigint, ReturnType<typeof decodeMemoPage>>();
    for (const { pageSeq, raw } of memoPages) {
      memoMap.set(pageSeq, decodeMemoPage(raw));
    }

    let discovered = 0;
    for (;;) {
      const leafIdx = lane.nextMemoLeaf;
      const mSeq = leafIdx / BigInt(MEMO_NOTES_PER_PAGE);
      const mSlot = Number(leafIdx % BigInt(MEMO_NOTES_PER_PAGE));
      const mPage = memoMap.get(mSeq);
      if (!mPage || mSlot >= mPage.count) break;

      const sSeq = leafIdx / BigInt(SUBTREE_LEAVES);
      const sSlot = Number(leafIdx % BigInt(SUBTREE_LEAVES));
      let cmBe: Uint8Array | undefined;
      const supplied = pageLeavesMap.get(sSeq);
      if (supplied) {
        if (sSlot >= supplied.length) break;
        cmBe = supplied[sSlot];
      } else if (sSeq === lane.frontierSubSeq && sSlot < lane.frontierLeaves.length) {
        cmBe = lane.frontierLeaves[sSlot];
      } else {
        break;
      }

      const entry = mPage.entries[mSlot]!;
      const dec = tryDecryptAndVerifyMemoEntry(
        fvk,
        entry.viewTag,
        entry.ephemeralPk,
        entry.ciphertext,
        cmBe!,
      );
      if (dec) {
        const globalLeaf = (BigInt(laneId) << 36n) | leafIdx;
        const stealth = fvkStealthOwner(fvk, dec.tweak);
        const cmFr = computeNoteCommitment(stealth, deriveAssetId(dec.mint), dec.amount, dec.blinding);
        const nf = fvkRealNullifier(fvk, cmFr, globalLeaf);
        const prefHex = bytesToHex(nf.subarray(0, NF_PREFIX_LEN));
        const alreadySpent = this.seenNfPrefixes.has(prefHex);

        if (!this.notes.some((n) => n.laneId === laneId && n.leafIndex === leafIdx)) {
          this.notes.push({
            poolId: this.poolId,
            laneId,
            leafIndex: leafIdx,
            globalLeafIndex: globalLeaf,
            mint: dec.mint,
            amount: dec.amount,
            tweak: frToBeBytes(dec.tweak),
            blinding: frToBeBytes(dec.blinding),
            stealthOwner: frToBeBytes(stealth),
            commitment: new Uint8Array(cmBe!),
            nullifier: nf,
            isDynamic: dec.isDynamic,
            spent: alreadySpent,
            frozenIntraSiblings: null,
            frozenIntraPositions: null,
          });
          discovered++;
        }
      }
      lane.nextMemoLeaf = leafIdx + 1n;
    }

    const freezeNotesInPage = (seq: bigint, frLeaves: readonly bigint[]) => {
      for (const note of this.notes) {
        if (
          note.laneId === laneId &&
          note.leafIndex / BigInt(SUBTREE_LEAVES) === seq &&
          !note.frozenIntraSiblings
        ) {
          const offset = Number(note.leafIndex % BigInt(SUBTREE_LEAVES));
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

    if (
      lane.frontierLeaves.length === SUBTREE_LEAVES &&
      !pageLeavesMap.has(lane.frontierSubSeq)
    ) {
      const frLeaves = lane.frontierLeaves.map((b) => frFromBeBytesStrict(b));
      freezeNotesInPage(lane.frontierSubSeq, frLeaves);
      const pageEndLeaf = (lane.frontierSubSeq + 1n) * BigInt(SUBTREE_LEAVES);
      if (lane.nextMemoLeaf >= pageEndLeaf) {
        lane.frontierSubSeq = lane.frontierSubSeq + 1n;
        lane.frontierLeaves = [];
      }
    }

    const sortedSeqs = [...pageLeavesMap.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    for (const seq of sortedSeqs) {
      const leaves = pageLeavesMap.get(seq)!;
      const memoSubSeq = lane.nextMemoLeaf / BigInt(SUBTREE_LEAVES);
      if (leaves.length === SUBTREE_LEAVES) {
        const frLeaves = leaves.map((b) => frFromBeBytesStrict(b));
        const subroot = frToBeBytes(computeSubtree256Root(frLeaves, SUBTREE_LEAVES));
        const seqNum = Number(seq);
        while (lane.finalizedSubroots.length < seqNum) {
          lane.finalizedSubroots.push(new Uint8Array(32));
        }
        lane.finalizedSubroots[seqNum] = subroot;
        freezeNotesInPage(seq, frLeaves);

        const pageEndLeaf = (seq + 1n) * BigInt(SUBTREE_LEAVES);
        if (lane.nextMemoLeaf >= pageEndLeaf) {
          if (seq >= lane.frontierSubSeq) {
            lane.frontierSubSeq = seq + 1n;
            lane.frontierLeaves = [];
          }
        } else if (seq === memoSubSeq) {
          // Hold sealed page leaves until MemoPages finish scanning all 256 leaves in this page
          lane.frontierSubSeq = seq;
          lane.frontierLeaves = leaves.map((b) => new Uint8Array(b));
        }
      } else if (seq >= lane.frontierSubSeq && seq <= memoSubSeq) {
        lane.frontierSubSeq = seq;
        lane.frontierLeaves = leaves.map((b) => new Uint8Array(b));
      }
    }

    const sortedNfPages = [...nfPages].sort((a, b) =>
      a.pageSeq < b.pageSeq ? -1 : a.pageSeq > b.pageSeq ? 1 : 0,
    );
    for (const { pageSeq, raw } of sortedNfPages) {
      const nfPage = decodeNullifierPage(raw);
      const pageBase = pageSeq * BigInt(NF_PER_PAGE);
      const startSlot =
        lane.nextNfIndex > pageBase ? Number(lane.nextNfIndex - pageBase) : 0;
      for (let slot = startSlot; slot < nfPage.count; slot++) {
        this.seenNfPrefixes.add(bytesToHex(nfPage.prefixes[slot]!));
        const nextIdx = pageBase + BigInt(slot) + 1n;
        if (nextIdx > lane.nextNfIndex) lane.nextNfIndex = nextIdx;
      }
    }
    for (const note of this.notes) {
      if (!note.spent) {
        const prefHex = bytesToHex(note.nullifier.subarray(0, NF_PREFIX_LEN));
        if (this.seenNfPrefixes.has(prefHex)) note.spent = true;
      }
    }
    return discovered;
  }

  buildWitnessForNote(
    note: OwnedNote,
    ckpt: DecodedRootCheckpoint,
  ): { superRoot: bigint; path: MerklePath4Ary } {
    const lane = this.lanes[note.laneId]!;
    const ckptCount = ckpt.laneCounts[note.laneId]!;
    if (note.leafIndex >= ckptCount) {
      throw new Error('Note not yet included in checkpoint');
    }
    const targetPage = note.leafIndex / BigInt(SUBTREE_LEAVES);
    const targetOffset = Number(note.leafIndex % BigInt(SUBTREE_LEAVES));
    const frontierPage = ckptCount / BigInt(SUBTREE_LEAVES);
    const frontierRem = Number(ckptCount % BigInt(SUBTREE_LEAVES));

    let intraSiblings: bigint[][];
    let intraPositions: number[];
    if (targetPage < frontierPage) {
      if (!note.frozenIntraSiblings || !note.frozenIntraPositions) {
        throw new Error('Missing frozen intra-subtree siblings for sealed note');
      }
      intraSiblings = note.frozenIntraSiblings.map((lvl) =>
        lvl.map((b) => frFromBeBytesStrict(b)),
      );
      intraPositions = [...note.frozenIntraPositions];
    } else {
      if (lane.frontierSubSeq !== frontierPage || lane.frontierLeaves.length < frontierRem) {
        throw new Error('Missing frontier SubtreePage leaves');
      }
      const fFr = lane.frontierLeaves.slice(0, frontierRem).map((b) => frFromBeBytesStrict(b));
      const res = extractIntraSubtreeSiblings(fFr, frontierRem, targetOffset);
      intraSiblings = res.siblings;
      intraPositions = res.positions;
    }

    const ckptRootsFr = ckpt.laneRoots.map((b) => frFromBeBytesStrict(b));
    if (lane.finalizedSubroots.length < Number(frontierPage)) {
      throw new Error('Missing finalized subroots');
    }
    const finalizedFr = lane.finalizedSubroots
      .slice(0, Number(frontierPage))
      .map((b) => frFromBeBytesStrict(b));
    let frontierFr: bigint[] | undefined;
    if (frontierRem > 0) {
      if (lane.frontierSubSeq !== frontierPage || lane.frontierLeaves.length < frontierRem) {
        throw new Error('Missing frontier SubtreePage leaves');
      }
      frontierFr = lane.frontierLeaves.slice(0, frontierRem).map((b) => frFromBeBytesStrict(b));
    }

    const path = buildWitnessFromFrozenSubsiblings({
      laneId: note.laneId,
      targetLeafIdx: note.leafIndex,
      intraSiblings,
      intraPositions,
      ckptLaneRoots: ckptRootsFr,
      ckptLaneLeafCount: ckptCount,
      finalizedSubtreeRoots: finalizedFr,
      frontierPageLeaves: frontierFr,
    });
    const superRoot = frFromBeBytesStrict(ckpt.superRoot);
    const cm = frFromBeBytesStrict(note.commitment);
    if (computeMerkleRoot4Ary(path, cm) !== superRoot) {
      throw new Error('Reconstructed Merkle root mismatch');
    }
    return { superRoot, path };
  }

  toJSON(): string {
    return JSON.stringify({
      poolId: this.poolId,
      birthdaySlot: this.birthdaySlot.toString(),
      lanes: this.lanes.map((l) => ({
        finalizedSubroots: l.finalizedSubroots.map(bytesToHex),
        frontierSubSeq: l.frontierSubSeq.toString(),
        frontierLeaves: l.frontierLeaves.map(bytesToHex),
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
        isDynamic: n.isDynamic,
        spent: n.spent,
        frozenIntraSiblings: n.frozenIntraSiblings
          ? n.frozenIntraSiblings.map((lvl) => lvl.map(bytesToHex))
          : null,
        frozenIntraPositions: n.frozenIntraPositions,
      })),
      seenNfPrefixes: [...this.seenNfPrefixes],
    });
  }

  static fromJSON(json: string): CompactWalletStore {
    const raw = JSON.parse(json) as {
      poolId: number;
      birthdaySlot: string;
      lanes: Array<{
        finalizedSubroots: string[];
        frontierSubSeq: string;
        frontierLeaves: string[];
        nextMemoLeaf: string;
        nextNfIndex: string;
      }>;
      notes: Array<{
        poolId: number;
        laneId: number;
        leafIndex: string;
        globalLeafIndex: string;
        mint: string;
        amount: string;
        tweak: string;
        blinding: string;
        stealthOwner: string;
        commitment: string;
        nullifier: string;
        isDynamic: boolean;
        spent: boolean;
        frozenIntraSiblings: string[][] | null;
        frozenIntraPositions: number[] | null;
      }>;
      seenNfPrefixes: string[];
    };
    const store = new CompactWalletStore(raw.poolId, BigInt(raw.birthdaySlot));
    store.lanes = raw.lanes.map((l) => ({
      finalizedSubroots: l.finalizedSubroots.map(hexToBytes),
      frontierSubSeq: BigInt(l.frontierSubSeq),
      frontierLeaves: l.frontierLeaves.map(hexToBytes),
      nextMemoLeaf: BigInt(l.nextMemoLeaf),
      nextNfIndex: BigInt(l.nextNfIndex),
    }));
    store.notes = raw.notes.map((n) => ({
      poolId: n.poolId,
      laneId: n.laneId,
      leafIndex: BigInt(n.leafIndex),
      globalLeafIndex: BigInt(n.globalLeafIndex),
      mint: hexToBytes(n.mint),
      amount: BigInt(n.amount),
      tweak: hexToBytes(n.tweak),
      blinding: hexToBytes(n.blinding),
      stealthOwner: hexToBytes(n.stealthOwner),
      commitment: hexToBytes(n.commitment),
      nullifier: hexToBytes(n.nullifier),
      isDynamic: n.isDynamic,
      spent: n.spent,
      frozenIntraSiblings: n.frozenIntraSiblings
        ? n.frozenIntraSiblings.map((lvl) => lvl.map(hexToBytes))
        : null,
      frozenIntraPositions: n.frozenIntraPositions,
    }));
    store.seenNfPrefixes = new Set(raw.seenNfPrefixes);
    return store;
  }
}
