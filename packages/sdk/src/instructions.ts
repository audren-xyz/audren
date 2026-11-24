/**
 * Builders for all 9 Audren v1 instructions (`0x00..=0x08`) and exact SHA-256 `ctx_hash`
 * transcripts matching `crates/client/src/instructions.rs` and `program/src/lib.rs` bit-for-bit.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_PUBLIC,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  AUDREN_PROGRAM_ID,
  CLASSIC_TOKEN_PROGRAM_ID,
  CTX_DOMAIN_EXEC_VIA_ESCROW,
  CTX_DOMAIN_ROUTER_ACCOUNTS,
  CTX_DOMAIN_TRANSACT,
  CU_LIMIT_DEPOSIT,
  CU_LIMIT_DEPOSIT_HOOK,
  CU_LIMIT_EXEC_VIA_ESCROW_BASE,
  CU_LIMIT_OPEN_PAGE,
  CU_LIMIT_TRANSACT_FULL_EXIT,
  CU_LIMIT_TRANSACT_PRIVATE,
  CU_LIMIT_TRANSACT_WITHDRAW,
  CU_LIMIT_TRANSACT_WITHDRAW_HOOK,
  DEFAULT_ROOT_EPOCH_INTERVAL,
  DEPOSIT_FLAG_FEE_FROM_AMOUNT,
  DEPOSIT_FLAG_NATIVE_SOL,
  DYN_MEMO_HEAD_LEN,
  EPOCH_RING_LEN,
  EXEC_FLAG_FEE_ON_OUTPUT,
  GROTH16_PROOF_LEN,
  MAX_ROOT_EPOCH_INTERVAL,
  MAX_TX_CU_LIMIT,
  MEMO_CT_LEN,
  MEMO_ENTRY_WIRE_LEN,
  MEMO_NOTES_PER_PAGE,
  NF_PER_PAGE,
  NUM_ESCROW_SHARDS,
  NUM_LANES,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_NULLIFIER,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  ROOT_RING_EPOCH,
  ROOT_RING_SLOT,
  SLOT_RING_LEN,
  SUBROOTS_PER_PAGE,
  SUBTREE_LEAVES,
  SYSTEM_PROGRAM_ID,
  TAG_DEPOSIT,
  TAG_EXEC_VIA_ESCROW,
  TAG_INIT_LANE,
  TAG_INIT_POOL,
  TAG_INIT_ROOT_HISTORY,
  TAG_OPEN_PAGE,
  TAG_SET_PAUSED,
  TAG_TRANSACT,
  TAG_UPDATE_POOL,
  UPDATE_POOL_ACCEPT_AUTHORITY,
  UPDATE_POOL_PARAMS,
  UPDATE_POOL_PROPOSE_AUTHORITY,
  UPDATE_POOL_RENOUNCE_AUTHORITY,
  VK_ID_DEFAULT,
  WITHDRAW_FLAG_UNWRAP_WSOL,
  WSOL_MINT,
} from './constants.ts';
import { MAX_LEAVES_PER_LANE } from './layout.ts';
import {
  base58Decode,
  base58Encode,
  deriveAssociatedTokenAddressSync,
  deriveEscrowPdaSync,
  deriveLanePdaSync,
  deriveLaneRentVaultPdaSync,
  deriveMemoPdaSync,
  deriveNfPagePdaSync,
  deriveNullifierPdaSync,
  derivePoolPdaSync,
  deriveRootsPdaSync,
  deriveSubrootPdaSync,
  deriveSubtreePdaSync,
  deriveUnwrapPdaSync,
  deriveVaultAuthPdaSync,
  toPubkeyBytes,
} from './pda.ts';
import { bytes32ToFrMasked, frToBeBytes } from './poseidon.ts';
import { prepareEscrowAccountsForAudren, type RouterAccountMeta } from './swap.ts';

const utf8Encoder = new TextEncoder();

export interface AudrenInstruction {
  programId: string;
  accounts: RouterAccountMeta[];
  data: Uint8Array;
}

export interface EscrowTokenLeg {
  mint: string;
  vaultAta?: string;
  escrowAta?: string;
  tokenProgram?: string;
}

export type UpdatePoolAction =
  | {
      kind: 'params';
      noteRentFee: bigint;
      nfRentFee: bigint;
    }
  | {
      kind: 'proposeAuthority';
      pendingAuthority: string | Uint8Array;
    }
  | {
      kind: 'acceptAuthority';
    }
  | {
      kind: 'renounceAuthority';
    };

function concat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) {
    if (!(p instanceof Uint8Array)) {
      throw new RangeError(`Expected Uint8Array chunk, got ${String(p)}`);
    }
    len += p.byteLength;
  }
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.byteLength;
  }
  return out;
}

const U8_MAX = 0xff;
const U16_MAX = 0xffff;
const U32_MAX = 0xffff_ffff;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

function assertU8(n: number, label: string): void {
  if (!Number.isInteger(n) || n < 0 || n > U8_MAX) {
    throw new RangeError(`${label} must be a u8 integer in 0..=${U8_MAX}, got ${n}`);
  }
}

function assertU16(n: number, label: string): void {
  if (!Number.isInteger(n) || n < 0 || n > U16_MAX) {
    throw new RangeError(`${label} must be a u16 integer in 0..=${U16_MAX}, got ${n}`);
  }
}

function assertU32(n: number, label: string): void {
  if (!Number.isInteger(n) || n < 0 || n > U32_MAX) {
    throw new RangeError(`${label} must be a u32 integer in 0..=${U32_MAX}, got ${n}`);
  }
}

function assertU64(n: bigint, label: string): void {
  if (typeof n !== 'bigint' || n < 0n || n > U64_MAX) {
    throw new RangeError(`${label} must be a u64 bigint in 0..=2^64-1, got ${String(n)}`);
  }
}

function assertLaneId(n: number, label = 'laneId'): void {
  if (!Number.isInteger(n) || n < 0 || n >= NUM_LANES) {
    throw new RangeError(`${label} must be an integer in 0..${NUM_LANES - 1}, got ${n}`);
  }
}

function assertEscrowShard(n: number): void {
  if (!Number.isInteger(n) || n < 0 || n >= NUM_ESCROW_SHARDS) {
    throw new RangeError(`escrowShard must be an integer in 0..${NUM_ESCROW_SHARDS - 1}, got ${n}`);
  }
}

function assertRootRing(rootRingKind: number, rootRingIdx: number): void {
  if (rootRingKind === ROOT_RING_SLOT) {
    if (!Number.isInteger(rootRingIdx) || rootRingIdx < 0 || rootRingIdx >= SLOT_RING_LEN) {
      throw new RangeError(
        `rootRingIdx must be an integer in 0..${SLOT_RING_LEN - 1} for ROOT_RING_SLOT, got ${rootRingIdx}`,
      );
    }
  } else if (rootRingKind === ROOT_RING_EPOCH) {
    if (!Number.isInteger(rootRingIdx) || rootRingIdx < 0 || rootRingIdx >= EPOCH_RING_LEN) {
      throw new RangeError(
        `rootRingIdx must be an integer in 0..${EPOCH_RING_LEN - 1} for ROOT_RING_EPOCH, got ${rootRingIdx}`,
      );
    }
  } else {
    throw new RangeError(
      `rootRingKind must be ROOT_RING_SLOT (${ROOT_RING_SLOT}) or ROOT_RING_EPOCH (${ROOT_RING_EPOCH}), got ${rootRingKind}`,
    );
  }
}

function assertRootEpochInterval(n: bigint): void {
  assertU64(n, 'rootEpochInterval');
  if (n < 1n || n > MAX_ROOT_EPOCH_INTERVAL) {
    throw new RangeError(
      `rootEpochInterval must be in 1..=${MAX_ROOT_EPOCH_INTERVAL}, got ${n}`,
    );
  }
}

function u16le(n: number, label = 'u16'): Uint8Array {
  assertU16(n, label);
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, n, true);
  return b;
}

function u32le(n: number, label = 'u32'): Uint8Array {
  assertU32(n, label);
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

function u64le(n: bigint, label = 'u64'): Uint8Array {
  assertU64(n, label);
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, true);
  return b;
}

function isAllZero32(b: Uint8Array): boolean {
  if (!(b instanceof Uint8Array) || b.byteLength !== 32) return false;
  for (let i = 0; i < 32; i++) if (b[i] !== 0) return false;
  return true;
}

function assertUint8Array(bytes: Uint8Array, label: string): void {
  if (!(bytes instanceof Uint8Array)) {
    throw new RangeError(`${label} must be a Uint8Array, got ${String(bytes)}`);
  }
}

function assertLen(bytes: Uint8Array, expected: number, label: string): void {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== expected) {
    throw new RangeError(
      `${label} must be a ${expected}-byte Uint8Array, got ${bytes instanceof Uint8Array ? bytes.byteLength : String(bytes)}`,
    );
  }
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

function assertNonNegativeSafeInt(v: number, label: string): number {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0) {
    throw new RangeError(`${label} must be a non-negative safe integer, got ${String(v)}`);
  }
  return v;
}

function pubkeyToB58(pk: string | Uint8Array): string {
  return typeof pk === 'string' ? pk : base58Encode(toPubkeyBytes(pk));
}

function divCeil(a: bigint, b: bigint): bigint {
  return (a + b - 1n) / b;
}

/** Deterministic per-note `LaneRentVault` fee matching `deterministic_note_rent_fee` on-chain. */
export function deterministicNoteRentFee(
  poolNoteRentFeeCap: bigint,
  subRent: bigint,
  srRent: bigint,
  memoRent: bigint,
): bigint {
  assertU64(poolNoteRentFeeCap, 'poolNoteRentFeeCap');
  assertU64(subRent, 'subRent');
  assertU64(srRent, 'srRent');
  assertU64(memoRent, 'memoRent');
  const live =
    divCeil(subRent > 0n ? subRent : 1n, BigInt(SUBTREE_LEAVES)) +
    divCeil(srRent > 0n ? srRent : 1n, BigInt(SUBTREE_LEAVES * SUBROOTS_PER_PAGE)) +
    divCeil(memoRent > 0n ? memoRent : 1n, BigInt(MEMO_NOTES_PER_PAGE));
  return poolNoteRentFeeCap < live ? poolNoteRentFeeCap : live;
}

export interface PageRolloverPlan {
  outSubSeq: number;
  outRootSeq: number;
  outMemoSeq: number;
  nfPageSeq: number;
  nextSubSeq?: number;
  nextRootSeq?: number;
  nextMemoSeq?: number;
  nextNfSeq?: number;
}

/**
 * Compute primary page sequences and atomic rollover page sequences matching
 * `append_leaf_and_memo` and `append_nullifier_prefix` in `program/src/lib.rs` byte-for-byte.
 */
export function computePageRollovers(params: {
  leafCount: bigint | number;
  outputCount: number;
  nfCount: bigint | number;
  spentNullifiers: number;
}): PageRolloverPlan {
  if (!params || typeof params !== 'object') {
    throw new RangeError('computePageRollovers params must be an object');
  }
  const leafCount = assertU64OrSafeInt(params.leafCount, 'leafCount');
  const nfCount = assertU64OrSafeInt(params.nfCount, 'nfCount');
  const outputCount = assertNonNegativeSafeInt(params.outputCount, 'outputCount');
  const spentNullifiers = assertNonNegativeSafeInt(params.spentNullifiers, 'spentNullifiers');

  const subSize = BigInt(SUBTREE_LEAVES);
  const srSize = BigInt(SUBROOTS_PER_PAGE);
  const memoSize = BigInt(MEMO_NOTES_PER_PAGE);
  const nfSize = BigInt(NF_PER_PAGE);

  const outSubSeqBig = leafCount / subSize;
  const outRootSeqBig = outSubSeqBig / srSize;
  const outMemoSeqBig = leafCount / memoSize;
  const nfPageSeqBig = nfCount / nfSize;

  const plan: PageRolloverPlan = {
    outSubSeq: Number(outSubSeqBig),
    outRootSeq: Number(outRootSeqBig),
    outMemoSeq: Number(outMemoSeqBig),
    nfPageSeq: Number(nfPageSeqBig),
  };

  if (outputCount > 0) {
    const lastLeaf = leafCount + BigInt(outputCount - 1);
    const lastSubSeqBig = lastLeaf / subSize;
    const lastRootSeqBig = lastSubSeqBig / srSize;
    const lastMemoSeqBig = lastLeaf / memoSize;
    if (lastSubSeqBig > outSubSeqBig) plan.nextSubSeq = Number(lastSubSeqBig);
    if (lastRootSeqBig > outRootSeqBig) plan.nextRootSeq = Number(lastRootSeqBig);
    if (lastMemoSeqBig > outMemoSeqBig) plan.nextMemoSeq = Number(lastMemoSeqBig);
  }

  if (spentNullifiers > 0) {
    const lastNf = nfCount + BigInt(spentNullifiers - 1);
    const lastNfSeqBig = lastNf / nfSize;
    if (lastNfSeqBig > nfPageSeqBig) plan.nextNfSeq = Number(lastNfSeqBig);
  }

  return plan;
}

/** Auto-`OpenPage` proactive pre-open thresholds (`>= 90%` full, matching on-chain `OpenPage` bounds). */
export const AUTO_OPEN_SUBTREE_REM_THRESHOLD = 26;
export const AUTO_OPEN_MEMO_REM_THRESHOLD = 10;
export const AUTO_OPEN_NF_REM_THRESHOLD = 60;
export const AUTO_OPEN_SUBROOT_SLOT_THRESHOLD = 280;

export interface AutoOpenPageTarget {
  pageKind: number;
  pageSeq: bigint;
  pda: string;
  /** `true` for mandatory rollover pages required by the tx; `false` for proactive `>= 90%` lookaheads (pass `maxPayerDeficit: 0n`). */
  mandatory: boolean;
}

/**
 * Zero-crank Auto-`OpenPage` planner: returns every idempotent `OpenPage` (`Tag 2`) target
 * required for a lane when it is at an exact rollover boundary (`mandatory: true`) OR `>= 90%` full
 * (`mandatory: false`: `subRem <= 26`, `memoRem <= 10`, `nfRem <= 60`, `subrootSlot >= 280`) and
 * the target page PDA is not present in `existingPages`.
 */
export function planAutoOpenPages(params: {
  programId?: string;
  poolId?: number;
  laneId: number;
  nextLeaf: bigint | number;
  nfCount: bigint | number;
  numOutputs: number;
  numNfs: number;
  existingPages?: ReadonlySet<string> | ReadonlyArray<string>;
}): AutoOpenPageTarget[] {
  if (!params || typeof params !== 'object') {
    throw new RangeError('planAutoOpenPages params must be an object');
  }
  const poolId = params.poolId ?? 0;
  assertU32(poolId, 'poolId');
  assertLaneId(params.laneId, 'laneId');
  const nextLeaf = assertU64OrSafeInt(params.nextLeaf, 'nextLeaf');
  const nfCount = assertU64OrSafeInt(params.nfCount, 'nfCount');
  const numOutputs = assertNonNegativeSafeInt(params.numOutputs, 'numOutputs');
  const numNfs = assertNonNegativeSafeInt(params.numNfs, 'numNfs');
  const programId = params.programId ?? AUDREN_PROGRAM_ID;

  const existing: ReadonlySet<string> | null =
    params.existingPages === undefined
      ? null
      : params.existingPages instanceof Set
        ? params.existingPages
        : new Set(params.existingPages);

  const targets: AutoOpenPageTarget[] = [];
  const seenIdx = new Map<string, number>();
  const addCandidate = (pageKind: number, pageSeq: bigint, pda: string, mandatory: boolean) => {
    if (existing?.has(pda)) return;
    const prevIdx = seenIdx.get(pda);
    if (prevIdx !== undefined) {
      if (mandatory) targets[prevIdx]!.mandatory = true;
      return;
    }
    seenIdx.set(pda, targets.length);
    targets.push({ pageKind, pageSeq, pda, mandatory });
  };

  if (numOutputs > 0 && nextLeaf < MAX_LEAVES_PER_LANE) {
    const subSize = BigInt(SUBTREE_LEAVES);
    const srSize = BigInt(SUBROOTS_PER_PAGE);
    const memoSize = BigInt(MEMO_NOTES_PER_PAGE);
    const maxSubPages = MAX_LEAVES_PER_LANE / subSize;
    const maxSrPages = divCeil(maxSubPages, srSize);
    const maxMemoPages = divCeil(MAX_LEAVES_PER_LANE, memoSize);

    const curSubSeq = nextLeaf / subSize;
    const subUsed = Number(nextLeaf % subSize);
    const subRem = SUBTREE_LEAVES - subUsed;
    if (curSubSeq > 0n && subUsed === 0) {
      addCandidate(
        OPEN_PAGE_KIND_SUBTREE,
        curSubSeq,
        deriveSubtreePdaSync(poolId, params.laneId, curSubSeq, programId).address,
        true,
      );
    }
    const subMandatoryNext = subRem < numOutputs;
    if (subMandatoryNext || subRem <= AUTO_OPEN_SUBTREE_REM_THRESHOLD) {
      const nextSubSeq = curSubSeq + 1n;
      if (nextSubSeq < maxSubPages) {
        addCandidate(
          OPEN_PAGE_KIND_SUBTREE,
          nextSubSeq,
          deriveSubtreePdaSync(poolId, params.laneId, nextSubSeq, programId).address,
          subMandatoryNext,
        );
      }
    }

    const curRootSeq = curSubSeq / srSize;
    const subrootSlot = Number(curSubSeq % srSize);
    if (curRootSeq > 0n && subrootSlot === 0) {
      addCandidate(
        OPEN_PAGE_KIND_SUBROOT,
        curRootSeq,
        deriveSubrootPdaSync(poolId, params.laneId, curRootSeq, programId).address,
        true,
      );
    }
    const srMandatoryNext = subMandatoryNext && (curSubSeq + 1n) / srSize > curRootSeq;
    if (srMandatoryNext || subrootSlot >= AUTO_OPEN_SUBROOT_SLOT_THRESHOLD) {
      const nextRootSeq = curRootSeq + 1n;
      if (nextRootSeq < maxSrPages) {
        addCandidate(
          OPEN_PAGE_KIND_SUBROOT,
          nextRootSeq,
          deriveSubrootPdaSync(poolId, params.laneId, nextRootSeq, programId).address,
          srMandatoryNext,
        );
      }
    }

    const curMemoSeq = nextLeaf / memoSize;
    const memoUsed = Number(nextLeaf % memoSize);
    const memoRem = MEMO_NOTES_PER_PAGE - memoUsed;
    if (curMemoSeq > 0n && memoUsed === 0) {
      addCandidate(
        OPEN_PAGE_KIND_MEMO,
        curMemoSeq,
        deriveMemoPdaSync(poolId, params.laneId, curMemoSeq, programId).address,
        true,
      );
    }
    const memoMandatoryNext = memoRem < numOutputs;
    if (memoMandatoryNext || memoRem <= AUTO_OPEN_MEMO_REM_THRESHOLD) {
      const nextMemoSeq = curMemoSeq + 1n;
      if (nextMemoSeq < maxMemoPages) {
        addCandidate(
          OPEN_PAGE_KIND_MEMO,
          nextMemoSeq,
          deriveMemoPdaSync(poolId, params.laneId, nextMemoSeq, programId).address,
          memoMandatoryNext,
        );
      }
    }
  }

  if (numNfs > 0) {
    const nfSize = BigInt(NF_PER_PAGE);
    const curNfSeq = nfCount / nfSize;
    const nfUsed = Number(nfCount % nfSize);
    const nfRem = NF_PER_PAGE - nfUsed;
    if (curNfSeq > 0n && nfUsed === 0) {
      addCandidate(
        OPEN_PAGE_KIND_NULLIFIER,
        curNfSeq,
        deriveNfPagePdaSync(poolId, params.laneId, curNfSeq, programId).address,
        true,
      );
    }
    const nfMandatoryNext = nfRem < numNfs;
    if (nfMandatoryNext || nfRem <= AUTO_OPEN_NF_REM_THRESHOLD) {
      const nextNfSeq = curNfSeq + 1n;
      addCandidate(
        OPEN_PAGE_KIND_NULLIFIER,
        nextNfSeq,
        deriveNfPagePdaSync(poolId, params.laneId, nextNfSeq, programId).address,
        nfMandatoryNext,
      );
    }
  }

  return targets;
}

/**
 * Build idempotent `OpenPage` (`Tag 2`) pre-instructions returned by `planAutoOpenPages` so
 * wallets and relayers keep lanes provisioned with zero external cranking.
 *
 * Proactive (`!mandatory`) lookahead instructions ALWAYS set `maxPayerDeficit = 0n` so
 * `LaneRentVault` bears 100% of rent and TOCTOU drains revert cleanly instead of debiting `payer`.
 * Pass `includeProactive: false` when `LaneRentVault` is known to be underfunded.
 */
export function buildAutoOpenPageInstructions(params: {
  programId?: string;
  payer: string;
  poolId: number;
  laneId: number;
  nextLeaf: bigint | number;
  nfCount: bigint | number;
  numOutputs: number;
  numNfs: number;
  existingPages?: ReadonlySet<string> | ReadonlyArray<string>;
  includeProactive?: boolean;
  mandatoryMaxPayerDeficit?: bigint;
}): AudrenInstruction[] {
  const includeProactive = params.includeProactive ?? true;
  const mandatoryMaxPayerDeficit = params.mandatoryMaxPayerDeficit ?? U64_MAX;
  const targets = planAutoOpenPages({
    programId: params.programId,
    poolId: params.poolId,
    laneId: params.laneId,
    nextLeaf: params.nextLeaf,
    nfCount: params.nfCount,
    numOutputs: params.numOutputs,
    numNfs: params.numNfs,
    existingPages: params.existingPages,
  });
  return targets
    .filter((t) => t.mandatory || includeProactive)
    .map((t) =>
      buildOpenPageInstruction({
        programId: params.programId,
        payer: params.payer,
        pageKind: t.pageKind,
        poolId: params.poolId,
        laneId: params.laneId,
        pageSeq: t.pageSeq,
        maxPayerDeficit: t.mandatory ? mandatoryMaxPayerDeficit : 0n,
      }),
    );
}

/** Convert an `AudrenInstruction` (base58 pubkeys) into a binary `V1Instruction` for `compileV1Message`. */
export function toV1Instruction(ix: AudrenInstruction): {
  programId: Uint8Array;
  accounts: { pubkey: Uint8Array; isSigner: boolean; isWritable: boolean }[];
  data: Uint8Array;
} {
  return {
    programId: base58Decode(ix.programId),
    accounts: ix.accounts.map((a) => ({
      pubkey: base58Decode(a.pubkey),
      isSigner: a.isSigner,
      isWritable: a.isWritable,
    })),
    data: ix.data,
  };
}

const CU_LIMIT_CREATE_ATA_CLASSIC = 30_000;
const CU_LIMIT_CREATE_ATA_TOKEN_2022 = 45_000;
const CU_LIMIT_EXEC_VIA_ESCROW_T22_LEG = 25_000;
/** Compute Unit cost per failed `find_program_address` bump iteration on Solana (`1,500` CU). */
export const CU_PER_PDA_BUMP_ITERATION = 1_500;

function nonNegativeInt(n: number | undefined, label = 'count'): number {
  if (n === undefined) return 0;
  if (typeof n !== 'number' || !Number.isFinite(n) || n < 0) {
    throw new RangeError(`${label} must be a non-negative finite number, got ${String(n)}`);
  }
  return Math.trunc(n);
}

/**
 * Compute extra Compute Unit headroom for non-255 PDA bumps (`sum((255 - bump) * 1_500)`),
 * validating every bump is a `u8` integer in `0..=255` and capping safely at `1,400,000` CU.
 */
export function computeBumpCuMargin(bumps: readonly number[]): number {
  if (!Array.isArray(bumps)) {
    throw new RangeError('bumps must be an array of u8 integers in 0..=255');
  }
  let total = 0;
  for (let i = 0; i < bumps.length; i++) {
    const b = bumps[i]!;
    if (typeof b !== 'number' || !Number.isInteger(b) || b < 0 || b > U8_MAX) {
      throw new RangeError(`bumps[${i}] must be a u8 integer in 0..=${U8_MAX}, got ${String(b)}`);
    }
    total = Math.min(MAX_TX_CU_LIMIT, total + (U8_MAX - b) * CU_PER_PDA_BUMP_ITERATION);
  }
  return total;
}

/** Recommended tight Compute Unit limit for standalone or batched `OpenPage` (`Tag 2`) instructions. */
export function recommendedOpenPageCuLimit(params?: {
  openPageCount?: number;
  bumps?: readonly number[];
}): number {
  const openPages =
    params?.openPageCount === undefined ? 1 : nonNegativeInt(params.openPageCount);
  const bumpMargin = params?.bumps !== undefined ? computeBumpCuMargin(params.bumps) : 0;
  return Math.min(MAX_TX_CU_LIMIT, openPages * CU_LIMIT_OPEN_PAGE + bumpMargin);
}

/** Recommended tight Compute Unit limit for `Deposit` (`Tag 3`) plus any prepended `OpenPage` / ATA setup instructions. */
export function recommendedDepositCuLimit(params?: {
  hasTransferHook?: boolean;
  openPageCount?: number;
  createAtaCount?: number;
  createToken2022AtaCount?: number;
  bumps?: readonly number[];
}): number {
  const base = params?.hasTransferHook ? CU_LIMIT_DEPOSIT_HOOK : CU_LIMIT_DEPOSIT;
  const openPages = nonNegativeInt(params?.openPageCount);
  const classicAtas = nonNegativeInt(params?.createAtaCount);
  const t22Atas = nonNegativeInt(params?.createToken2022AtaCount);
  const bumpMargin = params?.bumps !== undefined ? computeBumpCuMargin(params.bumps) : 0;
  return Math.min(
    MAX_TX_CU_LIMIT,
    base +
      openPages * CU_LIMIT_OPEN_PAGE +
      classicAtas * CU_LIMIT_CREATE_ATA_CLASSIC +
      t22Atas * CU_LIMIT_CREATE_ATA_TOKEN_2022 +
      bumpMargin,
  );
}

/** Recommended tight Compute Unit limit for `Transact` (`Tag 5`) plus any prepended `OpenPage` / ATA setup instructions. */
export function recommendedTransactCuLimit(params: {
  assetMode: number;
  outputMask?: number;
  hasTransferHook?: boolean;
  openPageCount?: number;
  createAtaCount?: number;
  createToken2022AtaCount?: number;
  bumps?: readonly number[];
}): number {
  if (params.assetMode !== ASSET_MODE_PRIVATE && params.assetMode !== ASSET_MODE_PUBLIC) {
    throw new RangeError(`Invalid assetMode ${params.assetMode} (expected 0=PRIVATE or 1=PUBLIC)`);
  }
  const base =
    params.assetMode === ASSET_MODE_PUBLIC
      ? params.hasTransferHook
        ? CU_LIMIT_TRANSACT_WITHDRAW_HOOK
        : params.outputMask === 0
          ? CU_LIMIT_TRANSACT_FULL_EXIT
          : CU_LIMIT_TRANSACT_WITHDRAW
      : CU_LIMIT_TRANSACT_PRIVATE;
  const openPages = nonNegativeInt(params.openPageCount);
  const classicAtas = nonNegativeInt(params.createAtaCount);
  const t22Atas = nonNegativeInt(params.createToken2022AtaCount);
  const bumpMargin = params.bumps !== undefined ? computeBumpCuMargin(params.bumps) : 0;
  return Math.min(
    MAX_TX_CU_LIMIT,
    base +
      openPages * CU_LIMIT_OPEN_PAGE +
      classicAtas * CU_LIMIT_CREATE_ATA_CLASSIC +
      t22Atas * CU_LIMIT_CREATE_ATA_TOKEN_2022 +
      bumpMargin,
  );
}

/** Recommended tight Compute Unit limit for `ExecViaEscrow` (`Tag 6`) plus router CU, optional Token-2022 leg headroom, and any prepended `OpenPage` / ATA setup instructions. */
export function recommendedExecViaEscrowCuLimit(params?: {
  routerCuLimit?: number;
  hasToken2022Leg?: boolean;
  openPageCount?: number;
  createAtaCount?: number;
  createToken2022AtaCount?: number;
  bumps?: readonly number[];
}): number {
  const routerCu = nonNegativeInt(params?.routerCuLimit);
  const t22LegCu = params?.hasToken2022Leg ? CU_LIMIT_EXEC_VIA_ESCROW_T22_LEG : 0;
  const openPages = nonNegativeInt(params?.openPageCount);
  const classicAtas = nonNegativeInt(params?.createAtaCount);
  const t22Atas = nonNegativeInt(params?.createToken2022AtaCount);
  const bumpMargin = params?.bumps !== undefined ? computeBumpCuMargin(params.bumps) : 0;
  return Math.min(
    MAX_TX_CU_LIMIT,
    CU_LIMIT_EXEC_VIA_ESCROW_BASE +
      t22LegCu +
      routerCu +
      openPages * CU_LIMIT_OPEN_PAGE +
      classicAtas * CU_LIMIT_CREATE_ATA_CLASSIC +
      t22Atas * CU_LIMIT_CREATE_ATA_TOKEN_2022 +
      bumpMargin,
  );
}

/**
 * Build a canonical SPL Associated Token Account `CreateIdempotent` (`data = [1]`) instruction
 * supporting both Classic SPL Token and SPL Token-2022 mints.
 */
export function buildCreateAtaIdempotentInstruction(params: {
  payer: string;
  ata: string;
  owner: string;
  mint: string;
  tokenProgram?: string;
}): AudrenInstruction {
  return {
    programId: ASSOCIATED_TOKEN_PROGRAM_ID,
    accounts: [
      { pubkey: params.payer, isSigner: true, isWritable: true },
      { pubkey: params.ata, isSigner: false, isWritable: true },
      { pubkey: params.owner, isSigner: false, isWritable: false },
      { pubkey: params.mint, isSigner: false, isWritable: false },
      { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
      {
        pubkey: params.tokenProgram ?? CLASSIC_TOKEN_PROGRAM_ID,
        isSigner: false,
        isWritable: false,
      },
    ],
    data: new Uint8Array([1]),
  };
}

/** Exact `Transact` (`Tag 5`) `ctx_hash` matching `program/src/lib.rs` bit-for-bit (binds `vkId`). */
export function computeTransactCtxHash(params: {
  programId?: string;
  poolId: number;
  vkId?: number;
  outLaneId: number;
  outputMask: number;
  assetMode: number;
  unwrapWsol: boolean;
  recipient?: string | Uint8Array | null;
  relayerFeeRecipient?: string | Uint8Array | null;
  publicAssetId: Uint8Array;
  publicAmountOut: bigint;
  relayerFeeAmount: bigint;
  memosBytes: Uint8Array;
}): bigint {
  assertLen(params.publicAssetId, 32, 'publicAssetId');
  assertUint8Array(params.memosBytes, 'memosBytes');
  assertU32(params.poolId, 'poolId');
  const vkId = params.vkId ?? VK_ID_DEFAULT;
  assertU8(vkId, 'vkId');
  assertLaneId(params.outLaneId, 'outLaneId');
  if (!Number.isInteger(params.outputMask) || params.outputMask < 0 || params.outputMask > 0b111) {
    throw new RangeError(`outputMask must be an integer in 0..=7, got ${params.outputMask}`);
  }
  if (params.assetMode !== ASSET_MODE_PRIVATE && params.assetMode !== ASSET_MODE_PUBLIC) {
    throw new RangeError(`Invalid assetMode ${params.assetMode} (expected 0=PRIVATE or 1=PUBLIC)`);
  }
  if (params.unwrapWsol && params.assetMode !== ASSET_MODE_PUBLIC) {
    throw new Error('unwrapWsol requires ASSET_MODE_PUBLIC');
  }
  assertU64(params.publicAmountOut, 'publicAmountOut');
  assertU64(params.relayerFeeAmount, 'relayerFeeAmount');
  const programBytes = toPubkeyBytes(params.programId ?? AUDREN_PROGRAM_ID);
  if (params.publicAmountOut > 0n && !params.recipient) {
    throw new Error('recipient is required when publicAmountOut > 0');
  }
  if (params.relayerFeeAmount > 0n && !params.relayerFeeRecipient) {
    throw new Error('relayerFeeRecipient is required when relayerFeeAmount > 0');
  }
  const recBytes =
    params.publicAmountOut > 0n ? toPubkeyBytes(params.recipient!) : new Uint8Array(32);
  const feeRecBytes =
    params.relayerFeeAmount > 0n ? toPubkeyBytes(params.relayerFeeRecipient!) : new Uint8Array(32);
  const preimage = concat(
    utf8Encoder.encode(CTX_DOMAIN_TRANSACT),
    programBytes,
    u32le(params.poolId, 'poolId'),
    new Uint8Array([
      vkId,
      params.outLaneId,
      params.outputMask,
      params.assetMode,
      params.unwrapWsol ? 1 : 0,
    ]),
    recBytes,
    feeRecBytes,
    params.publicAssetId,
    u64le(params.publicAmountOut, 'publicAmountOut'),
    u64le(params.relayerFeeAmount, 'relayerFeeAmount'),
    params.memosBytes,
  );
  return bytes32ToFrMasked(sha256(preimage));
}

/** Exact `router_accounts` hash matching `hash_router_accounts_arena` in `program/src/lib.rs`. */
export function computeRouterAccountsHash(routerAccounts: readonly RouterAccountMeta[]): Uint8Array {
  if (!Array.isArray(routerAccounts)) {
    throw new RangeError('routerAccounts must be an array');
  }
  assertU16(routerAccounts.length, 'routerAccounts.length');
  const parts: Uint8Array[] = [
    utf8Encoder.encode(CTX_DOMAIN_ROUTER_ACCOUNTS),
    u16le(routerAccounts.length, 'routerAccounts.length'),
  ];
  for (const acc of routerAccounts) {
    if (!acc || typeof acc !== 'object') {
      throw new RangeError('Each routerAccounts entry must be an object');
    }
    parts.push(toPubkeyBytes(acc.pubkey));
    parts.push(new Uint8Array([acc.isWritable ? 1 : 0]));
  }
  return sha256(concat(...parts));
}

/**
 * Exact `ExecViaEscrow` (`Tag 6`) `ctx_hash` matching `program/src/lib.rs` bit-for-bit
 * (binds `vkId`, SPL/Token-2022 only, `72 B` `dynMemoMask`).
 *
 * Applies Solana's transaction-wide writability promotion across `escrowPda`,
 * `relayerFeeRecipient`, `extraWritablePubkeys`, and duplicate writable `routerAccounts`
 * before hashing `router_accounts` so PDA/duplicate accounts match on-chain `AccountView::is_writable()`.
 */
export function computeExecCtxHash(params: {
  programId?: string;
  poolId: number;
  vkId?: number;
  outLaneId: number;
  escrowShard: number;
  changeMask: number;
  feeOnOutput: boolean;
  assetIn: Uint8Array;
  amountIn: bigint;
  relayerFeeAmount: bigint;
  relayerFeeRecipient?: string | Uint8Array | null;
  assetOut: Uint8Array;
  minAmountOut: bigint;
  routerProg: string | Uint8Array;
  routerAccounts: readonly RouterAccountMeta[];
  /** Optional writable instruction accounts promoted onto `routerAccounts` matching `buildExecViaEscrowInstruction` & Solana runtime writability merge. */
  payer?: string | Uint8Array | null;
  escrowInAta?: string | Uint8Array | null;
  escrowOutAta?: string | Uint8Array | null;
  vaultInAta?: string | Uint8Array | null;
  vaultOutAta?: string | Uint8Array | null;
  extraWritablePubkeys?: readonly (string | Uint8Array)[];
  outStealthOwner: Uint8Array;
  outBlinding: Uint8Array;
  dynMemoHead: Uint8Array;
  dynMemoMask: Uint8Array;
  routerIxData: Uint8Array;
  changeMemos: Uint8Array;
}): bigint {
  assertLen(params.assetIn, 32, 'assetIn');
  assertLen(params.assetOut, 32, 'assetOut');
  assertLen(params.outStealthOwner, 32, 'outStealthOwner');
  assertLen(params.outBlinding, 32, 'outBlinding');
  assertLen(params.dynMemoHead, DYN_MEMO_HEAD_LEN, 'dynMemoHead');
  assertLen(params.dynMemoMask, MEMO_CT_LEN, 'dynMemoMask');
  assertUint8Array(params.routerIxData, 'routerIxData');
  assertUint8Array(params.changeMemos, 'changeMemos');
  if (!Array.isArray(params.routerAccounts)) {
    throw new RangeError('routerAccounts must be an array');
  }
  assertU32(params.poolId, 'poolId');
  const vkId = params.vkId ?? VK_ID_DEFAULT;
  assertU8(vkId, 'vkId');
  assertLaneId(params.outLaneId, 'outLaneId');
  assertEscrowShard(params.escrowShard);
  if (!Number.isInteger(params.changeMask) || params.changeMask < 0 || params.changeMask > 0b11) {
    throw new RangeError(`changeMask must be an integer in 0..=3, got ${params.changeMask}`);
  }
  assertU64(params.amountIn, 'amountIn');
  assertU64(params.relayerFeeAmount, 'relayerFeeAmount');
  assertU64(params.minAmountOut, 'minAmountOut');
  assertU16(params.routerAccounts.length, 'routerAccounts.length');
  assertU16(params.routerIxData.byteLength, 'routerIxData.byteLength');
  if (params.relayerFeeAmount > 0n && !params.relayerFeeRecipient) {
    throw new Error('relayerFeeRecipient is required when relayerFeeAmount > 0');
  }
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const programBytes = toPubkeyBytes(programId);
  const escrowPda = deriveEscrowPdaSync(params.poolId, params.escrowShard, programId).address;
  const extraWritable: string[] = [];
  if (params.payer) extraWritable.push(pubkeyToB58(params.payer));
  if (params.escrowInAta) extraWritable.push(pubkeyToB58(params.escrowInAta));
  if (params.escrowOutAta) extraWritable.push(pubkeyToB58(params.escrowOutAta));
  if (params.vaultInAta) extraWritable.push(pubkeyToB58(params.vaultInAta));
  if (params.vaultOutAta) extraWritable.push(pubkeyToB58(params.vaultOutAta));
  if (params.relayerFeeAmount > 0n && params.relayerFeeRecipient) {
    extraWritable.push(pubkeyToB58(params.relayerFeeRecipient));
  }
  if (params.extraWritablePubkeys) {
    for (const pk of params.extraWritablePubkeys) {
      extraWritable.push(pubkeyToB58(pk));
    }
  }
  const normalizedRouterAccounts = prepareEscrowAccountsForAudren(
    params.routerAccounts,
    escrowPda,
    extraWritable,
  );
  const routerAccsHash = computeRouterAccountsHash(normalizedRouterAccounts);
  const feeRecBytes =
    params.relayerFeeAmount > 0n ? toPubkeyBytes(params.relayerFeeRecipient!) : new Uint8Array(32);
  const preimage = concat(
    utf8Encoder.encode(CTX_DOMAIN_EXEC_VIA_ESCROW),
    programBytes,
    u32le(params.poolId, 'poolId'),
    new Uint8Array([
      vkId,
      params.outLaneId,
      params.escrowShard,
      params.changeMask,
      params.feeOnOutput ? 1 : 0,
    ]),
    params.assetIn,
    u64le(params.amountIn, 'amountIn'),
    u64le(params.relayerFeeAmount, 'relayerFeeAmount'),
    feeRecBytes,
    params.assetOut,
    u64le(params.minAmountOut, 'minAmountOut'),
    toPubkeyBytes(params.routerProg),
    routerAccsHash,
    params.outStealthOwner,
    params.outBlinding,
    params.dynMemoHead,
    params.dynMemoMask,
    u16le(params.routerIxData.byteLength, 'routerIxData.byteLength'),
    params.routerIxData,
    params.changeMemos,
  );
  return bytes32ToFrMasked(sha256(preimage));
}

// =============================================================================
// 9 Canonical Audren v1 Instruction Builders (0x00..=0x08)
// =============================================================================

/** Tag 0: `InitPool` (4 accounts including `GlobalRootHistory`, 29 B). */
export function buildInitPoolInstruction(params: {
  programId?: string;
  payer: string;
  poolId: number;
  rootEpochInterval?: bigint;
  noteRentFee: bigint;
  nfRentFee: bigint;
}): AudrenInstruction {
  const rootEpochInterval = params.rootEpochInterval ?? DEFAULT_ROOT_EPOCH_INTERVAL;
  assertU32(params.poolId, 'poolId');
  assertRootEpochInterval(rootEpochInterval);
  assertU64(params.noteRentFee, 'noteRentFee');
  assertU64(params.nfRentFee, 'nfRentFee');
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const data = concat(
    new Uint8Array([TAG_INIT_POOL]),
    u32le(params.poolId, 'poolId'),
    u64le(rootEpochInterval, 'rootEpochInterval'),
    u64le(params.noteRentFee, 'noteRentFee'),
    u64le(params.nfRentFee, 'nfRentFee'),
  );
  return {
    programId,
    accounts: [
      { pubkey: params.payer, isSigner: true, isWritable: true },
      { pubkey: derivePoolPdaSync(params.poolId, programId).address, isSigner: false, isWritable: true },
      { pubkey: deriveRootsPdaSync(params.poolId, programId).address, isSigner: false, isWritable: true },
      { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data,
  };
}

/** Tag 1: `InitLane` (9 accounts, 6 B). */
export function buildInitLaneInstruction(params: {
  programId?: string;
  authority: string;
  poolId: number;
  laneId: number;
}): AudrenInstruction {
  assertU32(params.poolId, 'poolId');
  assertLaneId(params.laneId, 'laneId');
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const data = concat(
    new Uint8Array([TAG_INIT_LANE]),
    u32le(params.poolId, 'poolId'),
    new Uint8Array([params.laneId]),
  );
  return {
    programId,
    accounts: [
      { pubkey: params.authority, isSigner: true, isWritable: true },
      { pubkey: derivePoolPdaSync(params.poolId, programId).address, isSigner: false, isWritable: true },
      { pubkey: deriveLanePdaSync(params.poolId, params.laneId, programId).address, isSigner: false, isWritable: true },
      { pubkey: deriveLaneRentVaultPdaSync(params.poolId, params.laneId, programId).address, isSigner: false, isWritable: true },
      { pubkey: deriveSubtreePdaSync(params.poolId, params.laneId, 0n, programId).address, isSigner: false, isWritable: true },
      { pubkey: deriveSubrootPdaSync(params.poolId, params.laneId, 0n, programId).address, isSigner: false, isWritable: true },
      { pubkey: deriveMemoPdaSync(params.poolId, params.laneId, 0n, programId).address, isSigner: false, isWritable: true },
      { pubkey: deriveNfPagePdaSync(params.poolId, params.laneId, 0n, programId).address, isSigner: false, isWritable: true },
      { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data,
  };
}

/** Tag 2: `OpenPage` (6 accounts, 15 B). */
export function buildOpenPageInstruction(params: {
  programId?: string;
  payer: string;
  pageKind: number;
  poolId: number;
  laneId: number;
  pageSeq: bigint;
  /** Maximum lamports `payer` consents to cover if `LaneRentVault` cannot cover full page rent (default `U64_MAX`; pass `0n` for proactive `>= 90%` lookaheads). */
  maxPayerDeficit?: bigint;
}): AudrenInstruction {
  assertU32(params.poolId, 'poolId');
  assertLaneId(params.laneId, 'laneId');
  assertU64(params.pageSeq, 'pageSeq');
  const maxPayerDeficit = params.maxPayerDeficit ?? U64_MAX;
  assertU64(maxPayerDeficit, 'maxPayerDeficit');
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  let pagePda: string;
  if (params.pageKind === OPEN_PAGE_KIND_SUBTREE) {
    pagePda = deriveSubtreePdaSync(params.poolId, params.laneId, params.pageSeq, programId).address;
  } else if (params.pageKind === OPEN_PAGE_KIND_SUBROOT) {
    pagePda = deriveSubrootPdaSync(params.poolId, params.laneId, params.pageSeq, programId).address;
  } else if (params.pageKind === OPEN_PAGE_KIND_MEMO) {
    pagePda = deriveMemoPdaSync(params.poolId, params.laneId, params.pageSeq, programId).address;
  } else if (params.pageKind === OPEN_PAGE_KIND_NULLIFIER) {
    pagePda = deriveNfPagePdaSync(params.poolId, params.laneId, params.pageSeq, programId).address;
  } else {
    throw new RangeError(`Invalid pageKind ${params.pageKind}`);
  }
  const data = concat(
    new Uint8Array([TAG_OPEN_PAGE, params.pageKind]),
    u32le(params.poolId, 'poolId'),
    new Uint8Array([params.laneId]),
    u64le(params.pageSeq, 'pageSeq'),
    u64le(maxPayerDeficit, 'maxPayerDeficit'),
  );
  return {
    programId,
    accounts: [
      { pubkey: params.payer, isSigner: true, isWritable: true },
      { pubkey: derivePoolPdaSync(params.poolId, programId).address, isSigner: false, isWritable: false },
      { pubkey: deriveLanePdaSync(params.poolId, params.laneId, programId).address, isSigner: false, isWritable: false },
      { pubkey: deriveLaneRentVaultPdaSync(params.poolId, params.laneId, programId).address, isSigner: false, isWritable: true },
      { pubkey: pagePda, isSigner: false, isWritable: true },
      { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data,
  };
}

/**
 * Tag 3: Unified `Deposit` (14 fixed accounts with writable `GlobalRootHistory` at `[2]` +
 * optional rollover + optional hook accounts, 185 B).
 *
 * - Set `nativeSol: true` to deposit Native SOL atomically via `SyncNative` into the pool's
 *   canonical WSOL `vault_auth` ATA (`mint` defaults to `WSOL_MINT`, `sourceAccount` defaults to
 *   `depositor`, `tokenProgram` defaults to `CLASSIC_TOKEN_PROGRAM_ID`, `feeFromAmount` optional).
 * - Omit `nativeSol` (or `false`) for Classic SPL / Token-2022 deposits (`mint` and `sourceAccount`
 *   required; `vaultAta` auto-derives the canonical `vault_auth` ATA when omitted).
 */
export function buildDepositInstruction(params: {
  programId?: string;
  depositor: string;
  poolId: number;
  laneId: number;
  subPageSeq: bigint;
  rootPageSeq: bigint;
  memoPageSeq: bigint;
  nativeSol?: boolean;
  feeFromAmount?: boolean;
  mint?: string;
  sourceAccount?: string;
  vaultAta?: string;
  tokenProgram?: string;
  rollover?: { nextSubSeq?: bigint | null; nextMemoSeq?: bigint | null };
  amount: bigint;
  stealthOwner: bigint | Uint8Array;
  blinding: bigint | Uint8Array;
  memo: Uint8Array;
  hookAccounts?: readonly RouterAccountMeta[];
}): AudrenInstruction {
  assertLen(params.memo, MEMO_ENTRY_WIRE_LEN, 'memo');
  assertU32(params.poolId, 'poolId');
  assertLaneId(params.laneId, 'laneId');
  assertU64(params.subPageSeq, 'subPageSeq');
  assertU64(params.rootPageSeq, 'rootPageSeq');
  assertU64(params.memoPageSeq, 'memoPageSeq');
  assertU64(params.amount, 'amount');
  const nativeSol = Boolean(params.nativeSol);
  const feeFromAmount = Boolean(params.feeFromAmount);
  if (feeFromAmount && !nativeSol) {
    throw new Error('feeFromAmount is only valid when nativeSol is true');
  }

  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const vaultAuth = deriveVaultAuthPdaSync(params.poolId, programId).address;

  let mint: string;
  let sourceAccount: string;
  let tokenProgram: string;
  if (nativeSol) {
    mint = params.mint ?? WSOL_MINT;
    if (mint !== WSOL_MINT) {
      throw new Error(`nativeSol deposit requires WSOL_MINT (${WSOL_MINT})`);
    }
    tokenProgram = params.tokenProgram ?? CLASSIC_TOKEN_PROGRAM_ID;
    if (tokenProgram !== CLASSIC_TOKEN_PROGRAM_ID) {
      throw new Error('nativeSol deposit requires CLASSIC_TOKEN_PROGRAM_ID');
    }
    sourceAccount = params.sourceAccount ?? params.depositor;
    if (sourceAccount !== params.depositor) {
      throw new Error('nativeSol deposit requires sourceAccount === depositor');
    }
  } else {
    if (!params.mint) throw new Error('mint is required for SPL / Token-2022 deposit');
    if (!params.sourceAccount) {
      throw new Error('sourceAccount (depositor token account) is required for SPL / Token-2022 deposit');
    }
    mint = params.mint;
    sourceAccount = params.sourceAccount;
    tokenProgram = params.tokenProgram ?? CLASSIC_TOKEN_PROGRAM_ID;
  }

  const vaultAta =
    params.vaultAta ??
    deriveAssociatedTokenAddressSync(vaultAuth, mint, tokenProgram).address;

  const nextSubSeq = params.rollover?.nextSubSeq ?? null;
  const nextMemoSeq = params.rollover?.nextMemoSeq ?? null;
  if (nextSubSeq != null) assertU64(nextSubSeq, 'rollover.nextSubSeq');
  if (nextMemoSeq != null) assertU64(nextMemoSeq, 'rollover.nextMemoSeq');
  const flags =
    (nextSubSeq != null ? 1 : 0) |
    (nextMemoSeq != null ? 2 : 0) |
    (feeFromAmount ? DEPOSIT_FLAG_FEE_FROM_AMOUNT : 0) |
    (nativeSol ? DEPOSIT_FLAG_NATIVE_SOL : 0);

  const stealthBytes =
    typeof params.stealthOwner === 'bigint' ? frToBeBytes(params.stealthOwner) : params.stealthOwner;
  const blindBytes =
    typeof params.blinding === 'bigint' ? frToBeBytes(params.blinding) : params.blinding;
  assertLen(stealthBytes, 32, 'stealthOwner');
  assertLen(blindBytes, 32, 'blinding');

  const data = concat(
    new Uint8Array([TAG_DEPOSIT]),
    u32le(params.poolId),
    new Uint8Array([params.laneId, flags]),
    u64le(params.amount),
    stealthBytes,
    blindBytes,
    params.memo,
  );

  const accounts: RouterAccountMeta[] = [
    { pubkey: params.depositor, isSigner: true, isWritable: true },
    { pubkey: derivePoolPdaSync(params.poolId, programId).address, isSigner: false, isWritable: false },
    { pubkey: deriveRootsPdaSync(params.poolId, programId).address, isSigner: false, isWritable: true },
    { pubkey: vaultAuth, isSigner: false, isWritable: false },
    { pubkey: mint, isSigner: false, isWritable: false },
    { pubkey: sourceAccount, isSigner: false, isWritable: true },
    { pubkey: vaultAta, isSigner: false, isWritable: true },
    { pubkey: tokenProgram, isSigner: false, isWritable: false },
    { pubkey: deriveLanePdaSync(params.poolId, params.laneId, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveLaneRentVaultPdaSync(params.poolId, params.laneId, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveSubtreePdaSync(params.poolId, params.laneId, params.subPageSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveSubrootPdaSync(params.poolId, params.laneId, params.rootPageSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveMemoPdaSync(params.poolId, params.laneId, params.memoPageSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
  ];

  if (nextSubSeq != null) {
    accounts.push({
      pubkey: deriveSubtreePdaSync(params.poolId, params.laneId, nextSubSeq, programId).address,
      isSigner: false,
      isWritable: true,
    });
  }
  if (nextMemoSeq != null) {
    accounts.push({
      pubkey: deriveMemoPdaSync(params.poolId, params.laneId, nextMemoSeq, programId).address,
      isSigner: false,
      isWritable: true,
    });
  }
  if (params.hookAccounts) accounts.push(...params.hookAccounts);
  return { programId, accounts, data };
}

/** Tag 4: `InitRootHistory` (`4 + activeLanes` accounts, 13 B). */
export function buildInitRootHistoryInstruction(params: {
  programId?: string;
  authority: string;
  poolId: number;
  rootEpochInterval?: bigint;
  activeLanes: number;
}): AudrenInstruction {
  const rootEpochInterval = params.rootEpochInterval ?? DEFAULT_ROOT_EPOCH_INTERVAL;
  assertU32(params.poolId, 'poolId');
  assertRootEpochInterval(rootEpochInterval);
  if (!Number.isInteger(params.activeLanes) || params.activeLanes < 0 || params.activeLanes > NUM_LANES) {
    throw new RangeError(`activeLanes must be an integer in 0..=${NUM_LANES}, got ${params.activeLanes}`);
  }
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const data = concat(
    new Uint8Array([TAG_INIT_ROOT_HISTORY]),
    u32le(params.poolId, 'poolId'),
    u64le(rootEpochInterval, 'rootEpochInterval'),
  );
  const accounts: RouterAccountMeta[] = [
    { pubkey: params.authority, isSigner: true, isWritable: true },
    { pubkey: derivePoolPdaSync(params.poolId, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveRootsPdaSync(params.poolId, programId).address, isSigner: false, isWritable: true },
    { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
  ];
  for (let l = 0; l < params.activeLanes; l++) {
    accounts.push({
      pubkey: deriveLanePdaSync(params.poolId, l, programId).address,
      isSigner: false,
      isWritable: false,
    });
  }
  return { programId, accounts, data };
}

/**
 * Tag 5: `Transact` (`380 + num_outputs * 106 B`).
 * Supports `ASSET_MODE_PRIVATE` (0) and `ASSET_MODE_PUBLIC` (1, including `unwrapWsol: true`
 * atomic WSOL -> Native SOL unwrapping and pause-exempt full exits with read-only `roots`).
 */
export function buildTransactInstruction(params: {
  programId?: string;
  payer: string;
  poolId: number;
  vkId?: number;
  rootRingKind: number;
  rootRingIdx: number;
  outLaneId: number;
  outSubSeq: bigint;
  outRootSeq: bigint;
  outMemoSeq: bigint;
  outNfSeq: bigint;
  outputMask: number;
  assetMode: number;
  unwrapWsol?: boolean;
  publicOutflow?: { mint: string; vaultAta?: string; tokenProgram?: string } | null;
  rollover?: { nextSubSeq?: bigint | null; nextMemoSeq?: bigint | null; nextNfSeq?: bigint | null };
  proof192: Uint8Array;
  nf0: Uint8Array;
  nf1: Uint8Array;
  cm0: Uint8Array;
  cm1: Uint8Array;
  cm2: Uint8Array;
  publicAmountOut: bigint;
  relayerFeeAmount: bigint;
  recipient?: string;
  relayerFeeRecipient?: string;
  memosBytes: Uint8Array;
  hookAccounts?: readonly RouterAccountMeta[];
}): AudrenInstruction {
  assertLen(params.proof192, GROTH16_PROOF_LEN, 'proof192');
  assertLen(params.nf0, 32, 'nf0');
  assertLen(params.nf1, 32, 'nf1');
  assertLen(params.cm0, 32, 'cm0');
  assertLen(params.cm1, 32, 'cm1');
  assertLen(params.cm2, 32, 'cm2');
  assertUint8Array(params.memosBytes, 'memosBytes');
  assertU32(params.poolId, 'poolId');
  const vkId = params.vkId ?? VK_ID_DEFAULT;
  assertU8(vkId, 'vkId');
  assertRootRing(params.rootRingKind, params.rootRingIdx);
  assertLaneId(params.outLaneId, 'outLaneId');
  assertU64(params.outSubSeq, 'outSubSeq');
  assertU64(params.outRootSeq, 'outRootSeq');
  assertU64(params.outMemoSeq, 'outMemoSeq');
  assertU64(params.outNfSeq, 'outNfSeq');
  if (!Number.isInteger(params.outputMask) || params.outputMask < 0 || params.outputMask > 0b111) {
    throw new RangeError(`outputMask must be an integer in 0..=7, got ${params.outputMask}`);
  }
  if (params.assetMode !== ASSET_MODE_PRIVATE && params.assetMode !== ASSET_MODE_PUBLIC) {
    throw new RangeError(`Invalid assetMode ${params.assetMode} (expected 0=PRIVATE or 1=PUBLIC)`);
  }
  const unwrapWsol = Boolean(params.unwrapWsol);
  if (unwrapWsol && params.assetMode !== ASSET_MODE_PUBLIC) {
    throw new Error('unwrapWsol requires ASSET_MODE_PUBLIC');
  }
  assertU64(params.publicAmountOut, 'publicAmountOut');
  assertU64(params.relayerFeeAmount, 'relayerFeeAmount');
  if (params.publicAmountOut > 0n && !params.recipient) {
    throw new Error('recipient is required when publicAmountOut > 0');
  }
  if (params.relayerFeeAmount > 0n && !params.relayerFeeRecipient) {
    throw new Error('relayerFeeRecipient is required when relayerFeeAmount > 0');
  }

  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const rSub = params.rollover?.nextSubSeq ?? null;
  const rMemo = params.rollover?.nextMemoSeq ?? null;
  const rNf = params.rollover?.nextNfSeq ?? null;
  if (rSub != null) assertU64(rSub, 'rollover.nextSubSeq');
  if (rMemo != null) assertU64(rMemo, 'rollover.nextMemoSeq');
  if (rNf != null) assertU64(rNf, 'rollover.nextNfSeq');
  const flags =
    (rSub != null ? 1 : 0) |
    (rMemo != null ? 2 : 0) |
    (rNf != null ? 4 : 0) |
    (unwrapWsol ? WITHDRAW_FLAG_UNWRAP_WSOL : 0);

  const data = concat(
    new Uint8Array([TAG_TRANSACT]),
    u32le(params.poolId, 'poolId'),
    new Uint8Array([
      vkId,
      params.outLaneId,
      params.outputMask,
      params.assetMode,
      flags,
      params.rootRingKind,
      params.rootRingIdx,
    ]),
    params.proof192,
    params.nf0,
    params.nf1,
    params.cm0,
    params.cm1,
    params.cm2,
    u64le(params.publicAmountOut),
    u64le(params.relayerFeeAmount),
    params.memosBytes,
  );

  const nf1Meta: RouterAccountMeta = isAllZero32(params.nf1)
    ? { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false }
    : {
        pubkey: deriveNullifierPdaSync(params.poolId, params.nf1, programId).address,
        isSigner: false,
        isWritable: true,
      };

  const accounts: RouterAccountMeta[] = [
    { pubkey: params.payer, isSigner: true, isWritable: true },
    { pubkey: derivePoolPdaSync(params.poolId, programId).address, isSigner: false, isWritable: false },
    {
      pubkey: deriveRootsPdaSync(params.poolId, programId).address,
      isSigner: false,
      isWritable: params.outputMask !== 0,
    },
    { pubkey: deriveNullifierPdaSync(params.poolId, params.nf0, programId).address, isSigner: false, isWritable: true },
    nf1Meta,
    { pubkey: deriveLanePdaSync(params.poolId, params.outLaneId, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveLaneRentVaultPdaSync(params.poolId, params.outLaneId, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveSubtreePdaSync(params.poolId, params.outLaneId, params.outSubSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveSubrootPdaSync(params.poolId, params.outLaneId, params.outRootSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveMemoPdaSync(params.poolId, params.outLaneId, params.outMemoSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveNfPagePdaSync(params.poolId, params.outLaneId, params.outNfSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
  ];

  const rec = params.recipient ?? SYSTEM_PROGRAM_ID;
  const feeRec = params.relayerFeeRecipient ?? SYSTEM_PROGRAM_ID;

  if (params.assetMode === ASSET_MODE_PUBLIC) {
    const outflow =
      params.publicOutflow ??
      (unwrapWsol ? { mint: WSOL_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID } : null);
    if (!outflow) {
      throw new Error('publicOutflow is required for ASSET_MODE_PUBLIC');
    }
    const vaultAuth = deriveVaultAuthPdaSync(params.poolId, programId).address;
    const tokenProgram = outflow.tokenProgram ?? CLASSIC_TOKEN_PROGRAM_ID;
    const vaultAta =
      outflow.vaultAta ??
      deriveAssociatedTokenAddressSync(vaultAuth, outflow.mint, tokenProgram).address;
    accounts.push({ pubkey: vaultAuth, isSigner: false, isWritable: false });
    accounts.push({ pubkey: outflow.mint, isSigner: false, isWritable: false });
    accounts.push({ pubkey: vaultAta, isSigner: false, isWritable: true });
    accounts.push({ pubkey: tokenProgram, isSigner: false, isWritable: false });
    accounts.push({ pubkey: rec, isSigner: false, isWritable: true });
    accounts.push({ pubkey: feeRec, isSigner: false, isWritable: params.relayerFeeAmount > 0n });
    if (unwrapWsol) {
      accounts.push({
        pubkey: deriveUnwrapPdaSync(params.poolId, params.nf0, programId).address,
        isSigner: false,
        isWritable: true,
      });
    }
  }

  if (rSub != null) {
    accounts.push({
      pubkey: deriveSubtreePdaSync(params.poolId, params.outLaneId, rSub, programId).address,
      isSigner: false,
      isWritable: true,
    });
  }
  if (rMemo != null) {
    accounts.push({
      pubkey: deriveMemoPdaSync(params.poolId, params.outLaneId, rMemo, programId).address,
      isSigner: false,
      isWritable: true,
    });
  }
  if (rNf != null) {
    accounts.push({
      pubkey: deriveNfPagePdaSync(params.poolId, params.outLaneId, rNf, programId).address,
      isSigner: false,
      isWritable: true,
    });
  }
  if (params.hookAccounts) accounts.push(...params.hookAccounts);
  return { programId, accounts, data };
}

/**
 * Tag 6: `ExecViaEscrow` (`560 + routerIxData.length + num_changes * 106 B`, SPL/Token-2022 only).
 */
export function buildExecViaEscrowInstruction(params: {
  programId?: string;
  payer: string;
  poolId: number;
  vkId?: number;
  rootRingKind: number;
  rootRingIdx: number;
  outLaneId: number;
  outSubSeq: bigint;
  outRootSeq: bigint;
  outMemoSeq: bigint;
  outNfSeq: bigint;
  escrowShard: number;
  changeMask: number;
  feeOnOutput?: boolean;
  inLeg: EscrowTokenLeg;
  outLeg: EscrowTokenLeg;
  relayerFeeAmount: bigint;
  relayerFeeRecipient?: string | null;
  rollover?: { nextSubSeq?: bigint | null; nextMemoSeq?: bigint | null; nextNfSeq?: bigint | null };
  proof192: Uint8Array;
  nf0: Uint8Array;
  nf1: Uint8Array;
  cm0: Uint8Array;
  cm1: Uint8Array;
  cm2: Uint8Array;
  amountIn: bigint;
  minAmountOut: bigint;
  outStealthOwner: Uint8Array;
  outBlinding: Uint8Array;
  dynMemoHead: Uint8Array;
  dynMemoMask: Uint8Array;
  routerProg: string;
  routerIxData: Uint8Array;
  routerAccounts: readonly RouterAccountMeta[];
  extraWritablePubkeys?: readonly string[];
  changeMemos: Uint8Array;
}): AudrenInstruction {
  assertLen(params.proof192, GROTH16_PROOF_LEN, 'proof192');
  assertLen(params.nf0, 32, 'nf0');
  assertLen(params.nf1, 32, 'nf1');
  assertLen(params.cm0, 32, 'cm0');
  assertLen(params.cm1, 32, 'cm1');
  assertLen(params.cm2, 32, 'cm2');
  assertLen(params.outStealthOwner, 32, 'outStealthOwner');
  assertLen(params.outBlinding, 32, 'outBlinding');
  assertLen(params.dynMemoHead, DYN_MEMO_HEAD_LEN, 'dynMemoHead');
  assertLen(params.dynMemoMask, MEMO_CT_LEN, 'dynMemoMask');
  assertUint8Array(params.routerIxData, 'routerIxData');
  assertUint8Array(params.changeMemos, 'changeMemos');
  if (!Array.isArray(params.routerAccounts)) {
    throw new RangeError('routerAccounts must be an array');
  }
  assertU32(params.poolId, 'poolId');
  const vkId = params.vkId ?? VK_ID_DEFAULT;
  assertU8(vkId, 'vkId');
  assertRootRing(params.rootRingKind, params.rootRingIdx);
  assertLaneId(params.outLaneId, 'outLaneId');
  assertU64(params.outSubSeq, 'outSubSeq');
  assertU64(params.outRootSeq, 'outRootSeq');
  assertU64(params.outMemoSeq, 'outMemoSeq');
  assertU64(params.outNfSeq, 'outNfSeq');
  assertEscrowShard(params.escrowShard);
  if (!Number.isInteger(params.changeMask) || params.changeMask < 0 || params.changeMask > 0b11) {
    throw new RangeError(`changeMask must be an integer in 0..=3, got ${params.changeMask}`);
  }
  assertU64(params.amountIn, 'amountIn');
  assertU64(params.minAmountOut, 'minAmountOut');
  assertU64(params.relayerFeeAmount, 'relayerFeeAmount');
  assertU16(params.routerIxData.byteLength, 'routerIxData.byteLength');
  assertU16(params.routerAccounts.length, 'routerAccounts.length');
  if (params.relayerFeeAmount > 0n && !params.relayerFeeRecipient) {
    throw new Error('relayerFeeRecipient is required when relayerFeeAmount > 0');
  }
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const vaultAuth = deriveVaultAuthPdaSync(params.poolId, programId).address;
  const escrowPda = deriveEscrowPdaSync(params.poolId, params.escrowShard, programId).address;
  const feeOnOutput = Boolean(params.feeOnOutput);
  const rSub = params.rollover?.nextSubSeq ?? null;
  const rMemo = params.rollover?.nextMemoSeq ?? null;
  const rNf = params.rollover?.nextNfSeq ?? null;
  if (rSub != null) assertU64(rSub, 'rollover.nextSubSeq');
  if (rMemo != null) assertU64(rMemo, 'rollover.nextMemoSeq');
  if (rNf != null) assertU64(rNf, 'rollover.nextNfSeq');
  const flags =
    (rSub != null ? 1 : 0) |
    (rMemo != null ? 2 : 0) |
    (rNf != null ? 4 : 0) |
    (feeOnOutput ? EXEC_FLAG_FEE_ON_OUTPUT : 0);

  const data = concat(
    new Uint8Array([TAG_EXEC_VIA_ESCROW]),
    u32le(params.poolId, 'poolId'),
    new Uint8Array([
      vkId,
      params.outLaneId,
      params.escrowShard,
      params.changeMask,
      flags,
      params.rootRingKind,
      params.rootRingIdx,
    ]),
    params.proof192,
    params.nf0,
    params.nf1,
    params.cm0,
    params.cm1,
    params.cm2,
    u64le(params.amountIn),
    u64le(params.minAmountOut),
    u64le(params.relayerFeeAmount),
    params.outStealthOwner,
    params.outBlinding,
    params.dynMemoHead,
    params.dynMemoMask,
    u16le(params.routerIxData.byteLength),
    params.routerIxData,
    params.changeMemos,
  );

  const nf1Meta: RouterAccountMeta = isAllZero32(params.nf1)
    ? { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false }
    : {
        pubkey: deriveNullifierPdaSync(params.poolId, params.nf1, programId).address,
        isSigner: false,
        isWritable: true,
      };

  const inTokenProg = params.inLeg.tokenProgram ?? CLASSIC_TOKEN_PROGRAM_ID;
  const inVaultAta =
    params.inLeg.vaultAta ??
    deriveAssociatedTokenAddressSync(vaultAuth, params.inLeg.mint, inTokenProg).address;
  const inEscrowAta =
    params.inLeg.escrowAta ??
    deriveAssociatedTokenAddressSync(escrowPda, params.inLeg.mint, inTokenProg).address;

  const outTokenProg = params.outLeg.tokenProgram ?? CLASSIC_TOKEN_PROGRAM_ID;
  const outVaultAta =
    params.outLeg.vaultAta ??
    deriveAssociatedTokenAddressSync(vaultAuth, params.outLeg.mint, outTokenProg).address;
  const outEscrowAta =
    params.outLeg.escrowAta ??
    deriveAssociatedTokenAddressSync(escrowPda, params.outLeg.mint, outTokenProg).address;

  const accounts: RouterAccountMeta[] = [
    { pubkey: params.payer, isSigner: true, isWritable: true },
    { pubkey: derivePoolPdaSync(params.poolId, programId).address, isSigner: false, isWritable: false },
    { pubkey: deriveRootsPdaSync(params.poolId, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveNullifierPdaSync(params.poolId, params.nf0, programId).address, isSigner: false, isWritable: true },
    nf1Meta,
    { pubkey: deriveLanePdaSync(params.poolId, params.outLaneId, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveLaneRentVaultPdaSync(params.poolId, params.outLaneId, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveSubtreePdaSync(params.poolId, params.outLaneId, params.outSubSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveSubrootPdaSync(params.poolId, params.outLaneId, params.outRootSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveMemoPdaSync(params.poolId, params.outLaneId, params.outMemoSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveNfPagePdaSync(params.poolId, params.outLaneId, params.outNfSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: escrowPda, isSigner: false, isWritable: true },
    { pubkey: params.routerProg, isSigner: false, isWritable: false },
    { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
    // Input leg
    { pubkey: vaultAuth, isSigner: false, isWritable: false },
    { pubkey: params.inLeg.mint, isSigner: false, isWritable: false },
    { pubkey: inVaultAta, isSigner: false, isWritable: true },
    { pubkey: inEscrowAta, isSigner: false, isWritable: true },
    { pubkey: inTokenProg, isSigner: false, isWritable: false },
  ];

  if (params.relayerFeeAmount > 0n && !feeOnOutput) {
    accounts.push({ pubkey: params.relayerFeeRecipient!, isSigner: false, isWritable: true });
  }

  // Output leg
  accounts.push(
    { pubkey: vaultAuth, isSigner: false, isWritable: false },
    { pubkey: params.outLeg.mint, isSigner: false, isWritable: false },
    { pubkey: outVaultAta, isSigner: false, isWritable: true },
    { pubkey: outEscrowAta, isSigner: false, isWritable: true },
    { pubkey: outTokenProg, isSigner: false, isWritable: false },
  );

  if (params.relayerFeeAmount > 0n && feeOnOutput) {
    accounts.push({ pubkey: params.relayerFeeRecipient!, isSigner: false, isWritable: true });
  }

  if (rSub != null) {
    accounts.push({
      pubkey: deriveSubtreePdaSync(params.poolId, params.outLaneId, rSub, programId).address,
      isSigner: false,
      isWritable: true,
    });
  }
  if (rMemo != null) {
    accounts.push({
      pubkey: deriveMemoPdaSync(params.poolId, params.outLaneId, rMemo, programId).address,
      isSigner: false,
      isWritable: true,
    });
  }
  if (rNf != null) {
    accounts.push({
      pubkey: deriveNfPagePdaSync(params.poolId, params.outLaneId, rNf, programId).address,
      isSigner: false,
      isWritable: true,
    });
  }

  const precedingWritable = accounts.filter((a) => a.isWritable).map((a) => a.pubkey);
  const normalizedRouterAccounts = prepareEscrowAccountsForAudren(
    params.routerAccounts,
    escrowPda,
    params.extraWritablePubkeys
      ? [...precedingWritable, ...params.extraWritablePubkeys]
      : precedingWritable,
  );
  accounts.push(...normalizedRouterAccounts);
  return { programId, accounts, data };
}

/** Tag 7: `SetPaused` (2 accounts, 6 B). */
export function buildSetPausedInstruction(params: {
  programId?: string;
  authority: string;
  poolId: number;
  paused: boolean;
}): AudrenInstruction {
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const data = concat(
    new Uint8Array([TAG_SET_PAUSED]),
    u32le(params.poolId),
    new Uint8Array([params.paused ? 1 : 0]),
  );
  return {
    programId,
    accounts: [
      { pubkey: params.authority, isSigner: true, isWritable: false },
      { pubkey: derivePoolPdaSync(params.poolId, programId).address, isSigner: false, isWritable: true },
    ],
    data,
  };
}

/**
 * Tag 8: `UpdatePool` (2 accounts: `signer(s)`, `pool(w)`).
 * Sub-actions: `params` (22 B: `noteRentFee` + `nfRentFee`), `proposeAuthority` (38 B),
 * `acceptAuthority` (6 B), `renounceAuthority` (6 B, requires `!paused`).
 */
export function buildUpdatePoolInstruction(params: {
  programId?: string;
  signer: string;
  poolId: number;
  action: UpdatePoolAction;
}): AudrenInstruction {
  if (!params || typeof params !== 'object' || !params.action || typeof params.action !== 'object') {
    throw new RangeError('buildUpdatePoolInstruction requires a valid action object');
  }
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  let data: Uint8Array;
  switch (params.action.kind) {
    case 'params':
      data = concat(
        new Uint8Array([TAG_UPDATE_POOL]),
        u32le(params.poolId, 'poolId'),
        new Uint8Array([UPDATE_POOL_PARAMS]),
        u64le(params.action.noteRentFee, 'noteRentFee'),
        u64le(params.action.nfRentFee, 'nfRentFee'),
      );
      break;
    case 'proposeAuthority':
      data = concat(
        new Uint8Array([TAG_UPDATE_POOL]),
        u32le(params.poolId, 'poolId'),
        new Uint8Array([UPDATE_POOL_PROPOSE_AUTHORITY]),
        toPubkeyBytes(params.action.pendingAuthority),
      );
      break;
    case 'acceptAuthority':
      data = concat(
        new Uint8Array([TAG_UPDATE_POOL]),
        u32le(params.poolId, 'poolId'),
        new Uint8Array([UPDATE_POOL_ACCEPT_AUTHORITY]),
      );
      break;
    case 'renounceAuthority':
      data = concat(
        new Uint8Array([TAG_UPDATE_POOL]),
        u32le(params.poolId, 'poolId'),
        new Uint8Array([UPDATE_POOL_RENOUNCE_AUTHORITY]),
      );
      break;
    default:
      throw new RangeError(
        `Unknown UpdatePool action kind: ${String((params.action as { kind?: unknown }).kind)}`,
      );
  }
  return {
    programId,
    accounts: [
      { pubkey: params.signer, isSigner: true, isWritable: false },
      { pubkey: derivePoolPdaSync(params.poolId, programId).address, isSigner: false, isWritable: true },
    ],
    data,
  };
}

/** Tag 8 convenience builder for `UPDATE_POOL_PARAMS` (`22 B`: `noteRentFee`, `nfRentFee`). */
export function buildUpdatePoolParamsInstruction(params: {
  programId?: string;
  authority: string;
  poolId: number;
  noteRentFee: bigint;
  nfRentFee: bigint;
}): AudrenInstruction {
  return buildUpdatePoolInstruction({
    programId: params.programId,
    signer: params.authority,
    poolId: params.poolId,
    action: {
      kind: 'params',
      noteRentFee: params.noteRentFee,
      nfRentFee: params.nfRentFee,
    },
  });
}
