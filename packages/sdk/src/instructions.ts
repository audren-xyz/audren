/**
 * Builders for all 9 Audren instructions (`0x00..=0x08`) and exact SHA-256 `ctx_hash`
 * transcripts matching `crates/client/src/instructions.rs` and `program/src/lib.rs` bit-for-bit.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import {
  ASSET_MODE_SOL,
  ASSET_MODE_SPL,
  AUDREN_PROGRAM_ID,
  CTX_DOMAIN_EXEC_VIA_ESCROW,
  CTX_DOMAIN_JOINSPLIT,
  CTX_DOMAIN_ROUTER_ACCOUNTS,
  DEPOSIT_FLAG_FEE_FROM_AMOUNT,
  DYN_MEMO_HEAD_LEN,
  EXEC_FLAG_FEE_ON_OUTPUT,
  GROTH16_PROOF_LEN,
  MEMO_CT_LEN,
  MEMO_ENTRY_WIRE_LEN,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_NULLIFIER,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  SYSTEM_PROGRAM_ID,
  TAG_DEPOSIT_SOL,
  TAG_DEPOSIT_SPL,
  TAG_EXEC_VIA_ESCROW,
  TAG_INIT_LANE,
  TAG_INIT_POOL,
  TAG_JOINSPLIT,
  TAG_OPEN_PAGE,
  TAG_PUBLISH_CHECKPOINT,
  TAG_SET_PAUSED,
  WITHDRAW_FLAG_UNWRAP_WSOL,
} from './constants.ts';
import {
  deriveCheckpointPdaSync,
  deriveEscrowPdaSync,
  deriveLanePdaSync,
  deriveLaneRentVaultPdaSync,
  deriveMemoPdaSync,
  deriveNfPagePdaSync,
  deriveNullifierPdaSync,
  derivePoolPdaSync,
  deriveSolVaultPdaSync,
  deriveSubrootPdaSync,
  deriveSubtreePdaSync,
  deriveUnwrapPdaSync,
  deriveVaultAuthPdaSync,
  toPubkeyBytes,
} from './pda.ts';
import { bytes32ToFrMasked, frToBeBytes } from './poseidon.ts';
import type { RouterAccountMeta } from './swap.ts';

const utf8Encoder = new TextEncoder();

export interface AudrenInstruction {
  programId: string;
  accounts: RouterAccountMeta[];
  data: Uint8Array;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.byteLength;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.byteLength;
  }
  return out;
}

function u16le(n: number): Uint8Array {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, n, true);
  return b;
}

function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

function u64le(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, true);
  return b;
}

function isAllZero32(b: Uint8Array): boolean {
  for (let i = 0; i < 32; i++) if (b[i] !== 0) return false;
  return true;
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
  const live = divCeil(subRent, 256n) + divCeil(srRent, 256n * 300n) + divCeil(memoRent, 112n);
  return poolNoteRentFeeCap < live ? poolNoteRentFeeCap : live;
}

/** Exact `JoinSplit` `ctx_hash` matching `program/src/lib.rs` bit-for-bit. */
export function computeJoinsplitCtxHash(params: {
  programId?: string;
  poolId: number;
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
  const programBytes = toPubkeyBytes(params.programId ?? AUDREN_PROGRAM_ID);
  const recBytes =
    params.publicAmountOut > 0n
      ? toPubkeyBytes(params.recipient!)
      : new Uint8Array(32);
  const feeRecBytes =
    params.relayerFeeAmount > 0n
      ? toPubkeyBytes(params.relayerFeeRecipient!)
      : new Uint8Array(32);
  const preimage = concat(
    utf8Encoder.encode(CTX_DOMAIN_JOINSPLIT),
    programBytes,
    u32le(params.poolId),
    new Uint8Array([
      params.outLaneId,
      params.outputMask,
      params.assetMode,
      params.unwrapWsol ? 1 : 0,
    ]),
    recBytes,
    feeRecBytes,
    params.publicAssetId,
    u64le(params.publicAmountOut),
    u64le(params.relayerFeeAmount),
    params.memosBytes,
  );
  return bytes32ToFrMasked(sha256(preimage));
}

/** Exact `router_accounts` hash matching `hash_router_accounts_arena` in `program/src/lib.rs`. */
export function computeRouterAccountsHash(routerAccounts: readonly RouterAccountMeta[]): Uint8Array {
  const parts: Uint8Array[] = [
    utf8Encoder.encode(CTX_DOMAIN_ROUTER_ACCOUNTS),
    u16le(routerAccounts.length),
  ];
  for (const acc of routerAccounts) {
    parts.push(toPubkeyBytes(acc.pubkey));
    parts.push(new Uint8Array([acc.isWritable ? 1 : 0]));
  }
  return sha256(concat(...parts));
}

/** Exact `ExecViaEscrow` `ctx_hash` matching `program/src/lib.rs` bit-for-bit. */
export function computeExecCtxHash(params: {
  programId?: string;
  poolId: number;
  outLaneId: number;
  escrowShard: number;
  changeMask: number;
  inKind: number;
  outKind: number;
  feeOnOutput: boolean;
  assetIn: Uint8Array;
  amountIn: bigint;
  relayerFeeAmount: bigint;
  relayerFeeRecipient?: string | Uint8Array | null;
  assetOut: Uint8Array;
  minAmountOut: bigint;
  routerProg: string | Uint8Array;
  routerAccounts: readonly RouterAccountMeta[];
  outStealthOwner: Uint8Array;
  outBlinding: Uint8Array;
  dynMemoHead: Uint8Array;
  dynMask56: Uint8Array;
  routerIxData: Uint8Array;
  changeMemos: Uint8Array;
}): bigint {
  const programBytes = toPubkeyBytes(params.programId ?? AUDREN_PROGRAM_ID);
  const routerAccsHash = computeRouterAccountsHash(params.routerAccounts);
  const feeRecBytes =
    params.relayerFeeAmount > 0n
      ? toPubkeyBytes(params.relayerFeeRecipient!)
      : new Uint8Array(32);
  const preimage = concat(
    utf8Encoder.encode(CTX_DOMAIN_EXEC_VIA_ESCROW),
    programBytes,
    u32le(params.poolId),
    new Uint8Array([
      params.outLaneId,
      params.escrowShard,
      params.changeMask,
      params.inKind,
      params.outKind,
      params.feeOnOutput ? 1 : 0,
    ]),
    params.assetIn,
    u64le(params.amountIn),
    u64le(params.relayerFeeAmount),
    feeRecBytes,
    params.assetOut,
    u64le(params.minAmountOut),
    toPubkeyBytes(params.routerProg),
    routerAccsHash,
    params.outStealthOwner,
    params.outBlinding,
    params.dynMemoHead,
    params.dynMask56,
    u16le(params.routerIxData.byteLength),
    params.routerIxData,
    params.changeMemos,
  );
  return bytes32ToFrMasked(sha256(preimage));
}

// =============================================================================
// 9 Canonical V2 Instruction Builders (0x00..=0x08)
// =============================================================================

export function buildInitPoolInstruction(params: {
  programId?: string;
  payer: string;
  poolId: number;
  ckptInterval: bigint;
  maxCkptAge: bigint;
  noteRentFee: bigint;
  nfRentFee: bigint;
}): AudrenInstruction {
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const data = concat(
    new Uint8Array([TAG_INIT_POOL]),
    u32le(params.poolId),
    u64le(params.ckptInterval),
    u64le(params.maxCkptAge),
    u64le(params.noteRentFee),
    u64le(params.nfRentFee),
  );
  return {
    programId,
    accounts: [
      { pubkey: params.payer, isSigner: true, isWritable: true },
      { pubkey: derivePoolPdaSync(params.poolId, programId).address, isSigner: false, isWritable: true },
      { pubkey: deriveSolVaultPdaSync(params.poolId, programId).address, isSigner: false, isWritable: true },
      { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data,
  };
}

export function buildInitLaneInstruction(params: {
  programId?: string;
  authority: string;
  poolId: number;
  laneId: number;
}): AudrenInstruction {
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const data = concat(new Uint8Array([TAG_INIT_LANE]), u32le(params.poolId), new Uint8Array([params.laneId]));
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

export function buildOpenPageInstruction(params: {
  programId?: string;
  payer: string;
  pageKind: number;
  poolId: number;
  laneId: number;
  pageSeq: bigint;
}): AudrenInstruction {
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
    u32le(params.poolId),
    new Uint8Array([params.laneId]),
    u64le(params.pageSeq),
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

export function buildDepositSolInstruction(params: {
  programId?: string;
  depositor: string;
  poolId: number;
  laneId: number;
  subPageSeq: bigint;
  rootPageSeq: bigint;
  memoPageSeq: bigint;
  nextSubSeq?: bigint | null;
  nextMemoSeq?: bigint | null;
  feeFromAmount?: boolean;
  amount: bigint;
  stealthOwner: bigint | Uint8Array;
  blinding: bigint | Uint8Array;
  memo90: Uint8Array;
}): AudrenInstruction {
  if (params.memo90.byteLength !== MEMO_ENTRY_WIRE_LEN) {
    throw new RangeError(`memo90 must be ${MEMO_ENTRY_WIRE_LEN} bytes`);
  }
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const flags =
    (params.nextSubSeq != null ? 1 : 0) |
    (params.nextMemoSeq != null ? 2 : 0) |
    (params.feeFromAmount ? DEPOSIT_FLAG_FEE_FROM_AMOUNT : 0);
  const stealthBytes =
    typeof params.stealthOwner === 'bigint' ? frToBeBytes(params.stealthOwner) : params.stealthOwner;
  const blindBytes =
    typeof params.blinding === 'bigint' ? frToBeBytes(params.blinding) : params.blinding;

  const data = concat(
    new Uint8Array([TAG_DEPOSIT_SOL]),
    u32le(params.poolId),
    new Uint8Array([params.laneId, flags]),
    u64le(params.amount),
    stealthBytes,
    blindBytes,
    params.memo90,
  );
  const accounts: RouterAccountMeta[] = [
    { pubkey: params.depositor, isSigner: true, isWritable: true },
    { pubkey: derivePoolPdaSync(params.poolId, programId).address, isSigner: false, isWritable: false },
    { pubkey: deriveSolVaultPdaSync(params.poolId, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveLanePdaSync(params.poolId, params.laneId, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveLaneRentVaultPdaSync(params.poolId, params.laneId, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveSubtreePdaSync(params.poolId, params.laneId, params.subPageSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveSubrootPdaSync(params.poolId, params.laneId, params.rootPageSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveMemoPdaSync(params.poolId, params.laneId, params.memoPageSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
  ];
  if (params.nextSubSeq != null) {
    accounts.push({
      pubkey: deriveSubtreePdaSync(params.poolId, params.laneId, params.nextSubSeq, programId).address,
      isSigner: false,
      isWritable: true,
    });
  }
  if (params.nextMemoSeq != null) {
    accounts.push({
      pubkey: deriveMemoPdaSync(params.poolId, params.laneId, params.nextMemoSeq, programId).address,
      isSigner: false,
      isWritable: true,
    });
  }
  return { programId, accounts, data };
}

export function buildDepositSplInstruction(params: {
  programId?: string;
  depositor: string;
  poolId: number;
  mint: string;
  depositorAta: string;
  vaultAta: string;
  tokenProgram: string;
  laneId: number;
  subPageSeq: bigint;
  rootPageSeq: bigint;
  memoPageSeq: bigint;
  nextSubSeq?: bigint | null;
  nextMemoSeq?: bigint | null;
  amount: bigint;
  stealthOwner: bigint | Uint8Array;
  blinding: bigint | Uint8Array;
  memo90: Uint8Array;
  transferHookAccounts?: readonly RouterAccountMeta[];
}): AudrenInstruction {
  if (params.memo90.byteLength !== MEMO_ENTRY_WIRE_LEN) {
    throw new RangeError(`memo90 must be ${MEMO_ENTRY_WIRE_LEN} bytes`);
  }
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const flags = (params.nextSubSeq != null ? 1 : 0) | (params.nextMemoSeq != null ? 2 : 0);
  const stealthBytes =
    typeof params.stealthOwner === 'bigint' ? frToBeBytes(params.stealthOwner) : params.stealthOwner;
  const blindBytes =
    typeof params.blinding === 'bigint' ? frToBeBytes(params.blinding) : params.blinding;

  const data = concat(
    new Uint8Array([TAG_DEPOSIT_SPL]),
    u32le(params.poolId),
    new Uint8Array([params.laneId, flags]),
    u64le(params.amount),
    stealthBytes,
    blindBytes,
    params.memo90,
  );
  const accounts: RouterAccountMeta[] = [
    { pubkey: params.depositor, isSigner: true, isWritable: true },
    { pubkey: derivePoolPdaSync(params.poolId, programId).address, isSigner: false, isWritable: false },
    { pubkey: deriveVaultAuthPdaSync(params.poolId, programId).address, isSigner: false, isWritable: false },
    { pubkey: params.mint, isSigner: false, isWritable: false },
    { pubkey: params.depositorAta, isSigner: false, isWritable: true },
    { pubkey: params.vaultAta, isSigner: false, isWritable: true },
    { pubkey: params.tokenProgram, isSigner: false, isWritable: false },
    { pubkey: deriveLanePdaSync(params.poolId, params.laneId, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveLaneRentVaultPdaSync(params.poolId, params.laneId, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveSubtreePdaSync(params.poolId, params.laneId, params.subPageSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveSubrootPdaSync(params.poolId, params.laneId, params.rootPageSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveMemoPdaSync(params.poolId, params.laneId, params.memoPageSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
  ];
  if (params.nextSubSeq != null) {
    accounts.push({
      pubkey: deriveSubtreePdaSync(params.poolId, params.laneId, params.nextSubSeq, programId).address,
      isSigner: false,
      isWritable: true,
    });
  }
  if (params.nextMemoSeq != null) {
    accounts.push({
      pubkey: deriveMemoPdaSync(params.poolId, params.laneId, params.nextMemoSeq, programId).address,
      isSigner: false,
      isWritable: true,
    });
  }
  if (params.transferHookAccounts) accounts.push(...params.transferHookAccounts);
  return { programId, accounts, data };
}

export function buildPublishCheckpointInstruction(params: {
  programId?: string;
  payer: string;
  poolId: number;
  slotIdx: number;
  activeLanes: number;
}): AudrenInstruction {
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const data = concat(new Uint8Array([TAG_PUBLISH_CHECKPOINT]), u32le(params.poolId));
  const accounts: RouterAccountMeta[] = [
    { pubkey: params.payer, isSigner: true, isWritable: true },
    { pubkey: derivePoolPdaSync(params.poolId, programId).address, isSigner: false, isWritable: false },
    { pubkey: deriveCheckpointPdaSync(params.poolId, params.slotIdx, programId).address, isSigner: false, isWritable: true },
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

export function buildJoinsplitInstruction(params: {
  programId?: string;
  payer: string;
  poolId: number;
  vkId?: number;
  ckptSlotIdx: number;
  outLaneId: number;
  outSubSeq: bigint;
  outRootSeq: bigint;
  outMemoSeq: bigint;
  outNfSeq: bigint;
  outputMask: number;
  assetMode: number;
  unwrapWsol?: boolean;
  splWithdrawAccs?: { mint: string; vaultAta: string; tokenProgram: string } | null;
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
  transferHookAccounts?: readonly RouterAccountMeta[];
}): AudrenInstruction {
  if (params.proof192.byteLength !== GROTH16_PROOF_LEN) {
    throw new RangeError(`proof192 must be ${GROTH16_PROOF_LEN} bytes`);
  }
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const unwrapWsol = Boolean(params.unwrapWsol);
  const rSub = params.rollover?.nextSubSeq ?? null;
  const rMemo = params.rollover?.nextMemoSeq ?? null;
  const rNf = params.rollover?.nextNfSeq ?? null;
  const flags =
    (rSub != null ? 1 : 0) |
    (rMemo != null ? 2 : 0) |
    (rNf != null ? 4 : 0) |
    (unwrapWsol ? WITHDRAW_FLAG_UNWRAP_WSOL : 0);

  const data = concat(
    new Uint8Array([TAG_JOINSPLIT]),
    u32le(params.poolId),
    new Uint8Array([params.vkId ?? 0, params.outLaneId, params.outputMask, params.assetMode, flags]),
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
    { pubkey: deriveCheckpointPdaSync(params.poolId, params.ckptSlotIdx, programId).address, isSigner: false, isWritable: false },
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

  if (params.assetMode === ASSET_MODE_SOL) {
    accounts.push({ pubkey: deriveSolVaultPdaSync(params.poolId, programId).address, isSigner: false, isWritable: true });
    accounts.push({ pubkey: rec, isSigner: false, isWritable: true });
    accounts.push({ pubkey: feeRec, isSigner: false, isWritable: params.relayerFeeAmount > 0n });
  } else if (params.assetMode === ASSET_MODE_SPL) {
    if (!params.splWithdrawAccs) throw new Error('splWithdrawAccs required for ASSET_MODE_SPL');
    accounts.push({ pubkey: deriveVaultAuthPdaSync(params.poolId, programId).address, isSigner: false, isWritable: false });
    accounts.push({ pubkey: params.splWithdrawAccs.mint, isSigner: false, isWritable: false });
    accounts.push({ pubkey: params.splWithdrawAccs.vaultAta, isSigner: false, isWritable: true });
    accounts.push({ pubkey: params.splWithdrawAccs.tokenProgram, isSigner: false, isWritable: false });
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
  if (params.transferHookAccounts) accounts.push(...params.transferHookAccounts);
  return { programId, accounts, data };
}

export function buildExecViaEscrowInstruction(params: {
  programId?: string;
  payer: string;
  poolId: number;
  vkId?: number;
  ckptSlotIdx: number;
  outLaneId: number;
  outSubSeq: bigint;
  outRootSeq: bigint;
  outMemoSeq: bigint;
  outNfSeq: bigint;
  escrowShard: number;
  changeMask: number;
  inKind: number;
  outKind: number;
  feeOnOutput?: boolean;
  inSpl?: { mint: string; vaultAta: string; escrowAta: string; tokenProgram: string } | null;
  outSpl?: { mint: string; vaultAta: string; escrowAta: string; tokenProgram: string } | null;
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
  dynMask56: Uint8Array;
  routerProg: string;
  routerIxData: Uint8Array;
  routerAccounts: readonly RouterAccountMeta[];
  changeMemos: Uint8Array;
}): AudrenInstruction {
  if (
    params.proof192.byteLength !== GROTH16_PROOF_LEN ||
    params.dynMemoHead.byteLength !== DYN_MEMO_HEAD_LEN ||
    params.dynMask56.byteLength !== MEMO_CT_LEN
  ) {
    throw new RangeError('Invalid proof or dynamic memo wire length');
  }
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const feeOnOutput = Boolean(params.feeOnOutput);
  const rSub = params.rollover?.nextSubSeq ?? null;
  const rMemo = params.rollover?.nextMemoSeq ?? null;
  const rNf = params.rollover?.nextNfSeq ?? null;
  const flags =
    (rSub != null ? 1 : 0) |
    (rMemo != null ? 2 : 0) |
    (rNf != null ? 4 : 0) |
    (feeOnOutput ? EXEC_FLAG_FEE_ON_OUTPUT : 0);

  const data = concat(
    new Uint8Array([TAG_EXEC_VIA_ESCROW]),
    u32le(params.poolId),
    new Uint8Array([
      params.vkId ?? 0,
      params.outLaneId,
      params.escrowShard,
      params.changeMask,
      params.inKind,
      params.outKind,
      flags,
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
    params.dynMask56,
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

  const accounts: RouterAccountMeta[] = [
    { pubkey: params.payer, isSigner: true, isWritable: true },
    { pubkey: derivePoolPdaSync(params.poolId, programId).address, isSigner: false, isWritable: false },
    { pubkey: deriveCheckpointPdaSync(params.poolId, params.ckptSlotIdx, programId).address, isSigner: false, isWritable: false },
    { pubkey: deriveNullifierPdaSync(params.poolId, params.nf0, programId).address, isSigner: false, isWritable: true },
    nf1Meta,
    { pubkey: deriveLanePdaSync(params.poolId, params.outLaneId, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveLaneRentVaultPdaSync(params.poolId, params.outLaneId, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveSubtreePdaSync(params.poolId, params.outLaneId, params.outSubSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveSubrootPdaSync(params.poolId, params.outLaneId, params.outRootSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveMemoPdaSync(params.poolId, params.outLaneId, params.outMemoSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveNfPagePdaSync(params.poolId, params.outLaneId, params.outNfSeq, programId).address, isSigner: false, isWritable: true },
    { pubkey: deriveEscrowPdaSync(params.poolId, params.escrowShard, programId).address, isSigner: false, isWritable: true },
    { pubkey: params.routerProg, isSigner: false, isWritable: false },
    { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
  ];

  if (params.inKind === 0) {
    accounts.push({ pubkey: deriveSolVaultPdaSync(params.poolId, programId).address, isSigner: false, isWritable: true });
  } else {
    if (!params.inSpl) throw new Error('inSpl required for SPL input leg');
    accounts.push({ pubkey: deriveVaultAuthPdaSync(params.poolId, programId).address, isSigner: false, isWritable: false });
    accounts.push({ pubkey: params.inSpl.mint, isSigner: false, isWritable: false });
    accounts.push({ pubkey: params.inSpl.vaultAta, isSigner: false, isWritable: true });
    accounts.push({ pubkey: params.inSpl.escrowAta, isSigner: false, isWritable: true });
    accounts.push({ pubkey: params.inSpl.tokenProgram, isSigner: false, isWritable: false });
  }
  if (params.relayerFeeAmount > 0n && !feeOnOutput) {
    accounts.push({ pubkey: params.relayerFeeRecipient!, isSigner: false, isWritable: true });
  }

  if (params.outKind === 0) {
    accounts.push({ pubkey: deriveSolVaultPdaSync(params.poolId, programId).address, isSigner: false, isWritable: true });
  } else {
    if (!params.outSpl) throw new Error('outSpl required for SPL output leg');
    accounts.push({ pubkey: deriveVaultAuthPdaSync(params.poolId, programId).address, isSigner: false, isWritable: false });
    accounts.push({ pubkey: params.outSpl.mint, isSigner: false, isWritable: false });
    accounts.push({ pubkey: params.outSpl.vaultAta, isSigner: false, isWritable: true });
    accounts.push({ pubkey: params.outSpl.escrowAta, isSigner: false, isWritable: true });
    accounts.push({ pubkey: params.outSpl.tokenProgram, isSigner: false, isWritable: false });
  }
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
  accounts.push(...params.routerAccounts);
  return { programId, accounts, data };
}

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
