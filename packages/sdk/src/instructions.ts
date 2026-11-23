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
  DEPOSIT_FLAG_FEE_FROM_AMOUNT,
  DEPOSIT_FLAG_NATIVE_SOL,
  DYN_MEMO_HEAD_LEN,
  EXEC_FLAG_FEE_ON_OUTPUT,
  GROTH16_PROOF_LEN,
  MEMO_CT_LEN,
  MEMO_ENTRY_WIRE_LEN,
  MEMO_NOTES_PER_PAGE,
  NF_PER_PAGE,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_NULLIFIER,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  SUBROOTS_PER_PAGE,
  SUBTREE_LEAVES,
  SYSTEM_PROGRAM_ID,
  TAG_DEPOSIT,
  TAG_EXEC_VIA_ESCROW,
  TAG_INIT_LANE,
  TAG_INIT_POOL,
  TAG_OPEN_PAGE,
  TAG_PUBLISH_CHECKPOINT,
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
import {
  base58Encode,
  deriveAssociatedTokenAddressSync,
  deriveCheckpointPdaSync,
  deriveEscrowPdaSync,
  deriveLanePdaSync,
  deriveLaneRentVaultPdaSync,
  deriveMemoPdaSync,
  deriveNfPagePdaSync,
  deriveNullifierPdaSync,
  derivePoolPdaSync,
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
      ckptInterval: bigint;
      maxCkptAge: bigint;
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

function assertLen(bytes: Uint8Array, expected: number, label: string): void {
  if (bytes.byteLength !== expected) {
    throw new RangeError(`${label} must be ${expected} bytes, got ${bytes.byteLength}`);
  }
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
  const live =
    divCeil(subRent, BigInt(SUBTREE_LEAVES)) +
    divCeil(srRent, BigInt(SUBTREE_LEAVES * SUBROOTS_PER_PAGE)) +
    divCeil(memoRent, BigInt(MEMO_NOTES_PER_PAGE));
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
  const leafCount = BigInt(params.leafCount);
  const nfCount = BigInt(params.nfCount);
  if (leafCount < 0n || nfCount < 0n) {
    throw new RangeError('leafCount and nfCount must be non-negative');
  }
  const outputCount = Math.max(0, Math.trunc(params.outputCount));
  const spentNullifiers = Math.max(0, Math.trunc(params.spentNullifiers));

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
    u32le(params.poolId),
    new Uint8Array([
      params.vkId ?? VK_ID_DEFAULT,
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
  if (params.relayerFeeAmount > 0n && !params.relayerFeeRecipient) {
    throw new Error('relayerFeeRecipient is required when relayerFeeAmount > 0');
  }
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const programBytes = toPubkeyBytes(programId);
  const escrowPda = deriveEscrowPdaSync(params.poolId, params.escrowShard, programId).address;
  const extraWritable: string[] = [];
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
    u32le(params.poolId),
    new Uint8Array([
      params.vkId ?? VK_ID_DEFAULT,
      params.outLaneId,
      params.escrowShard,
      params.changeMask,
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
    params.dynMemoMask,
    u16le(params.routerIxData.byteLength),
    params.routerIxData,
    params.changeMemos,
  );
  return bytes32ToFrMasked(sha256(preimage));
}

// =============================================================================
// 9 Canonical Audren v1 Instruction Builders (0x00..=0x08)
// =============================================================================

/** Tag 0: `InitPool` (3 accounts, 37 B). */
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
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const data = concat(
    new Uint8Array([TAG_INIT_LANE]),
    u32le(params.poolId),
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

/**
 * Tag 3: Unified `Deposit` (13 fixed accounts + optional rollover + optional hook accounts, 185 B).
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

/** Tag 4: `PublishCheckpoint` (`4 + activeLanes` accounts, 5 B). */
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

/**
 * Tag 5: `Transact` (`378 + num_outputs * 106 B`).
 * Supports `ASSET_MODE_PRIVATE` (0) and `ASSET_MODE_PUBLIC` (1, including `unwrapWsol: true`
 * atomic WSOL -> Native SOL unwrapping and pause-exempt full exits).
 */
export function buildTransactInstruction(params: {
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
  if (params.assetMode !== ASSET_MODE_PRIVATE && params.assetMode !== ASSET_MODE_PUBLIC) {
    throw new RangeError(`Invalid assetMode ${params.assetMode} (expected 0=PRIVATE or 1=PUBLIC)`);
  }
  if (params.publicAmountOut > 0n && !params.recipient) {
    throw new Error('recipient is required when publicAmountOut > 0');
  }
  if (params.relayerFeeAmount > 0n && !params.relayerFeeRecipient) {
    throw new Error('relayerFeeRecipient is required when relayerFeeAmount > 0');
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
    new Uint8Array([TAG_TRANSACT]),
    u32le(params.poolId),
    new Uint8Array([
      params.vkId ?? VK_ID_DEFAULT,
      params.outLaneId,
      params.outputMask,
      params.assetMode,
      flags,
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
 * Tag 6: `ExecViaEscrow` (`558 + routerIxData.length + num_changes * 106 B`, SPL/Token-2022 only).
 */
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
  const flags =
    (rSub != null ? 1 : 0) |
    (rMemo != null ? 2 : 0) |
    (rNf != null ? 4 : 0) |
    (feeOnOutput ? EXEC_FLAG_FEE_ON_OUTPUT : 0);

  const data = concat(
    new Uint8Array([TAG_EXEC_VIA_ESCROW]),
    u32le(params.poolId),
    new Uint8Array([
      params.vkId ?? VK_ID_DEFAULT,
      params.outLaneId,
      params.escrowShard,
      params.changeMask,
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
    { pubkey: deriveCheckpointPdaSync(params.poolId, params.ckptSlotIdx, programId).address, isSigner: false, isWritable: false },
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
 * Sub-actions: `params` (38 B), `proposeAuthority` (38 B), `acceptAuthority` (6 B),
 * `renounceAuthority` (6 B, requires `!paused`).
 */
export function buildUpdatePoolInstruction(params: {
  programId?: string;
  signer: string;
  poolId: number;
  action: UpdatePoolAction;
}): AudrenInstruction {
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  let data: Uint8Array;
  switch (params.action.kind) {
    case 'params':
      data = concat(
        new Uint8Array([TAG_UPDATE_POOL]),
        u32le(params.poolId),
        new Uint8Array([UPDATE_POOL_PARAMS]),
        u64le(params.action.ckptInterval),
        u64le(params.action.maxCkptAge),
        u64le(params.action.noteRentFee),
        u64le(params.action.nfRentFee),
      );
      break;
    case 'proposeAuthority':
      data = concat(
        new Uint8Array([TAG_UPDATE_POOL]),
        u32le(params.poolId),
        new Uint8Array([UPDATE_POOL_PROPOSE_AUTHORITY]),
        toPubkeyBytes(params.action.pendingAuthority),
      );
      break;
    case 'acceptAuthority':
      data = concat(
        new Uint8Array([TAG_UPDATE_POOL]),
        u32le(params.poolId),
        new Uint8Array([UPDATE_POOL_ACCEPT_AUTHORITY]),
      );
      break;
    case 'renounceAuthority':
      data = concat(
        new Uint8Array([TAG_UPDATE_POOL]),
        u32le(params.poolId),
        new Uint8Array([UPDATE_POOL_RENOUNCE_AUTHORITY]),
      );
      break;
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
