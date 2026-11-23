import {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_SOL,
  ASSET_MODE_SPL,
  AUDREN_PROGRAM_ID as AUDREN_PROGRAM_ID_STR,
  CHECKPOINT_RING_SLOTS,
  CLASSIC_TOKEN_PROGRAM_ID as CLASSIC_TOKEN_PROGRAM_ID_STR,
  EXEC_FLAG_FEE_ON_OUTPUT,
  EXEC_KIND_SOL,
  EXEC_KIND_SPL,
  MEMO_ENTRY_WIRE_LEN,
  MEMO_NOTES_PER_PAGE,
  NATIVE_SOL_MINT_BYTES,
  NF_PER_PAGE,
  NUM_ESCROW_SHARDS,
  NUM_LANES,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_NULLIFIER,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  PROTOCOL_VERSION,
  SUBROOTS_PER_PAGE,
  SUBTREE_LEAVES,
  TAG_DEPOSIT_SOL,
  TAG_DEPOSIT_SPL,
  TAG_EXEC_VIA_ESCROW,
  TAG_JOINSPLIT,
  TAG_OPEN_PAGE,
  TAG_PUBLISH_CHECKPOINT,
  WITHDRAW_FLAG_UNWRAP_WSOL,
  WSOL_MINT as WSOL_MINT_STR,
  buildOpenPageInstruction,
  buildPublishCheckpointInstruction,
  decodeLaneHeader,
  decodePoolState,
  decodeRootCheckpoint,
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
  tryDecryptAndVerifyMemo90,
  type DecodedLaneHeader,
  type DecodedPoolState,
  type DecodedRootCheckpoint,
  type FullViewingKey,
} from '@audren/sdk'
import {
  SYSTEM_PROGRAM_ID,
  base58Decode,
  base58Encode,
  bytesEqual,
  readU16le,
  readU32le,
  readU64le,
} from './codec'
import type { SolanaAccountMeta, SolanaInstruction } from '../types'

// ============================================================================
// Audren Protocol Constants, PDAs & Wire Parsers
// Verified byte-for-byte against `crates/audren-core` and `program/src/lib.rs`
// ============================================================================

export {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_SOL,
  ASSET_MODE_SPL,
  AUDREN_PROGRAM_ID_STR,
  CHECKPOINT_RING_SLOTS,
  EXEC_FLAG_FEE_ON_OUTPUT,
  EXEC_KIND_SOL,
  EXEC_KIND_SPL,
  MEMO_ENTRY_WIRE_LEN,
  NATIVE_SOL_MINT_BYTES,
  NUM_ESCROW_SHARDS,
  NUM_LANES,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_NULLIFIER,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  PROTOCOL_VERSION,
  TAG_DEPOSIT_SOL,
  TAG_DEPOSIT_SPL,
  TAG_EXEC_VIA_ESCROW,
  TAG_JOINSPLIT,
  TAG_OPEN_PAGE,
  TAG_PUBLISH_CHECKPOINT,
  WITHDRAW_FLAG_UNWRAP_WSOL,
  decodeLaneHeader,
  decodePoolState,
  decodeRootCheckpoint,
  type DecodedLaneHeader,
  type DecodedPoolState,
  type DecodedRootCheckpoint,
}

export const AUDREN_PROGRAM_ID = base58Decode(AUDREN_PROGRAM_ID_STR)
export const MAX_ESCROW_SHARDS = NUM_ESCROW_SHARDS

const toPdaBytes = (derived: { addressBytes: Uint8Array; bump: number }) => ({
  address: derived.addressBytes,
  bump: derived.bump,
})

export const derivePoolPda = (poolId = 0) => toPdaBytes(derivePoolPdaSync(poolId))
export const deriveSolVaultPda = (poolId = 0) => toPdaBytes(deriveSolVaultPdaSync(poolId))
export const deriveVaultAuthPda = (poolId = 0) => toPdaBytes(deriveVaultAuthPdaSync(poolId))
export const deriveLanePda = (poolId: number, laneId: number) =>
  toPdaBytes(deriveLanePdaSync(poolId, laneId))
export const deriveLaneRentVaultPda = (poolId: number, laneId: number) =>
  toPdaBytes(deriveLaneRentVaultPdaSync(poolId, laneId))
export const deriveSubtreePda = (poolId: number, laneId: number, seq: bigint) =>
  toPdaBytes(deriveSubtreePdaSync(poolId, laneId, seq))
export const deriveSubrootPda = (poolId: number, laneId: number, seq: bigint) =>
  toPdaBytes(deriveSubrootPdaSync(poolId, laneId, seq))
export const deriveMemoPda = (poolId: number, laneId: number, seq: bigint) =>
  toPdaBytes(deriveMemoPdaSync(poolId, laneId, seq))
export const deriveNfPagePda = (poolId: number, laneId: number, seq: bigint) =>
  toPdaBytes(deriveNfPagePdaSync(poolId, laneId, seq))
export const deriveCheckpointPda = (poolId: number, slotIdx: number) =>
  toPdaBytes(deriveCheckpointPdaSync(poolId, slotIdx))
export const deriveNullifierPda = (poolId: number, nf32: Uint8Array) =>
  toPdaBytes(deriveNullifierPdaSync(poolId, nf32))
export const deriveEscrowPda = (poolId: number, shardId: number) =>
  toPdaBytes(deriveEscrowPdaSync(poolId, shardId))
export const deriveUnwrapPda = (poolId: number, nf0: Uint8Array) =>
  toPdaBytes(deriveUnwrapPdaSync(poolId, nf0))

function popcount3(mask: number): number {
  return (mask & 1) + ((mask >> 1) & 1) + ((mask >> 2) & 1)
}

function isAllZero32(b: Uint8Array): boolean {
  for (let i = 0; i < 32; i++) if (b[i] !== 0) return false
  return true
}

export function toSolanaInstruction(ix: {
  programId: string
  accounts: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }>
  data: Uint8Array
}): SolanaInstruction {
  return {
    programId: base58Decode(ix.programId),
    accounts: ix.accounts.map((a) => ({
      pubkey: base58Decode(a.pubkey),
      isSigner: a.isSigner,
      isWritable: a.isWritable,
    })),
    data: ix.data,
  }
}

export function buildPublishCheckpointSolanaIx(params: {
  payer: string
  poolId: number
  slotIdx: number
  activeLanes: number
}): SolanaInstruction {
  return toSolanaInstruction(buildPublishCheckpointInstruction(params))
}

export function buildOpenPageSolanaIx(params: {
  payer: string
  pageKind: number
  poolId: number
  laneId: number
  pageSeq: bigint
}): SolanaInstruction {
  return toSolanaInstruction(buildOpenPageInstruction(params))
}

/**
 * Extract active nullifier PDA base58 addresses directly from `JoinSplit` (Tag 6) or
 * `ExecViaEscrow` (Tag 7) account headers: `[3] nf0_pda`, `[4] nf1_pda` (when != SystemProgram).
 */
export function extractNullifierPdas(tag: number, accounts: SolanaAccountMeta[]): string[] {
  if ((tag !== TAG_JOINSPLIT && tag !== TAG_EXEC_VIA_ESCROW) || accounts.length < 12) return []
  const out = [base58Encode(accounts[3]!.pubkey)]
  if (!bytesEqual(accounts[4]!.pubkey, SYSTEM_PROGRAM_ID)) {
    out.push(base58Encode(accounts[4]!.pubkey))
  }
  return out
}

export interface ParsedPageAccounts {
  outSub: string
  outRoot: string
  outMemo: string
  nfPage: string
  nextSub: string | null
  nextMemo: string | null
  nextNf: string | null
}

export interface ParsedJoinSplitMeta extends ParsedPageAccounts {
  poolId: number
  vkId: number
  outLaneId: number
  outputMask: number
  outputCount: number
  assetMode: number
  flags: number
  unwrapWsol: boolean
  opKind: 'transfer' | 'withdraw'
  nf0: Uint8Array
  nf1: Uint8Array
  cm0: Uint8Array
  cm1: Uint8Array
  cm2: Uint8Array
  publicAmountOut: bigint
  relayerFee: bigint
  mint: string | null
  tokenProgram: string | null
  recipientAccount: string | null
  feeRecipient: string | null
  /** Optional `memo[2]` slice (90 B) corresponding to `cm2` when `(outputMask & 4) !== 0`. */
  cm2Memo90: Uint8Array | null
}

/**
 * Parse Tag 6 (`JoinSplit`) wire payload & fixed/outflow/rollover account layout.
 * Wire:
 *   [0] tag(6), [1..5] pool_id, [5] vk_id, [6] out_lane_id, [7] output_mask,
 *   [8] asset_mode, [9] flags, [10..202] proof(192), [202..234] nf0, [234..266] nf1,
 *   [266..298] cm0, [298..330] cm1, [330..362] cm2,
 *   [362..370] public_amount_out, [370..378] relayer_fee_amount, [378..] memos(popcount(output_mask)*90)
 */
export function parseJoinSplitMeta(
  ixData: Uint8Array,
  accounts: SolanaAccountMeta[],
): ParsedJoinSplitMeta | null {
  if (ixData.length < 378 || ixData[0] !== TAG_JOINSPLIT || accounts.length < 12) return null
  const poolId = readU32le(ixData, 1)
  const vkId = ixData[5]!
  const outLaneId = ixData[6]!
  const outputMask = ixData[7]!
  const assetMode = ixData[8]!
  const flags = ixData[9]!
  if (
    outLaneId >= NUM_LANES ||
    (outputMask & ~0x07) !== 0 ||
    assetMode > ASSET_MODE_SPL ||
    (flags & ~(0x07 | WITHDRAW_FLAG_UNWRAP_WSOL)) !== 0
  ) {
    return null
  }
  const outputCount = popcount3(outputMask)
  if (ixData.length !== 378 + outputCount * MEMO_ENTRY_WIRE_LEN) return null

  const unwrapWsol = (flags & WITHDRAW_FLAG_UNWRAP_WSOL) !== 0
  if (unwrapWsol && assetMode !== ASSET_MODE_SPL) return null

  const nf0 = ixData.subarray(202, 234)
  const nf1 = ixData.subarray(234, 266)
  const cm0 = ixData.subarray(266, 298)
  const cm1 = ixData.subarray(298, 330)
  const cm2 = ixData.subarray(330, 362)
  const publicAmountOut = readU64le(ixData, 362)
  const relayerFee = readU64le(ixData, 370)

  if (unwrapWsol && publicAmountOut === 0n) return null
  if (assetMode === ASSET_MODE_PRIVATE && (publicAmountOut !== 0n || relayerFee !== 0n)) {
    return null
  }
  if (assetMode !== ASSET_MODE_PRIVATE && publicAmountOut === 0n) return null

  if (isAllZero32(nf0)) return null
  if (isAllZero32(nf1) && !bytesEqual(accounts[4]!.pubkey, SYSTEM_PROGRAM_ID)) return null
  if (!isAllZero32(nf1) && bytesEqual(accounts[4]!.pubkey, SYSTEM_PROGRAM_ID)) return null
  if (!bytesEqual(accounts[5]!.pubkey, deriveLanePda(poolId, outLaneId).address)) return null
  if (!bytesEqual(accounts[6]!.pubkey, deriveLaneRentVaultPda(poolId, outLaneId).address)) {
    return null
  }
  if (!bytesEqual(accounts[11]!.pubkey, SYSTEM_PROGRAM_ID)) return null

  const outSub = base58Encode(accounts[7]!.pubkey)
  const outRoot = base58Encode(accounts[8]!.pubkey)
  const outMemo = base58Encode(accounts[9]!.pubkey)
  const nfPage = base58Encode(accounts[10]!.pubkey)

  let cm2Memo90: Uint8Array | null = null
  if ((outputMask & 0x04) !== 0) {
    const idx = (outputMask & 1) + ((outputMask >> 1) & 1)
    const off = 378 + idx * MEMO_ENTRY_WIRE_LEN
    cm2Memo90 = ixData.subarray(off, off + MEMO_ENTRY_WIRE_LEN)
  }

  let mint: string | null = null
  let tokenProgram: string | null = null
  let recipientAccount: string | null = null
  let feeRecipient: string | null = null
  let cursor = 12

  if (assetMode === ASSET_MODE_SOL) {
    if (accounts.length < 15) return null
    if (!bytesEqual(accounts[12]!.pubkey, deriveSolVaultPda(poolId).address)) return null
    recipientAccount = base58Encode(accounts[13]!.pubkey)
    feeRecipient = base58Encode(accounts[14]!.pubkey)
    cursor = 15
  } else if (assetMode === ASSET_MODE_SPL) {
    const minAccs = unwrapWsol ? 19 : 18
    if (accounts.length < minAccs) return null
    if (!bytesEqual(accounts[12]!.pubkey, deriveVaultAuthPda(poolId).address)) return null
    mint = base58Encode(accounts[13]!.pubkey)
    tokenProgram = base58Encode(accounts[15]!.pubkey)
    recipientAccount = base58Encode(accounts[16]!.pubkey)
    feeRecipient = base58Encode(accounts[17]!.pubkey)
    if (unwrapWsol) {
      if (mint !== WSOL_MINT_STR || tokenProgram !== CLASSIC_TOKEN_PROGRAM_ID_STR) return null
      if (!bytesEqual(accounts[18]!.pubkey, deriveUnwrapPda(poolId, nf0).address)) return null
    }
    cursor = minAccs
  }

  // Optional atomic rollover accounts (bit 0 = nextSub, bit 1 = nextMemo, bit 2 = nextNf)
  const hasNextSub = (flags & 0x01) !== 0
  const hasNextMemo = (flags & 0x02) !== 0
  const hasNextNf = (flags & 0x04) !== 0
  const rolloverCount = (hasNextSub ? 1 : 0) + (hasNextMemo ? 1 : 0) + (hasNextNf ? 1 : 0)
  if (accounts.length < cursor + rolloverCount) return null
  const nextSub = hasNextSub ? base58Encode(accounts[cursor++]!.pubkey) : null
  const nextMemo = hasNextMemo ? base58Encode(accounts[cursor++]!.pubkey) : null
  const nextNf = hasNextNf ? base58Encode(accounts[cursor++]!.pubkey) : null

  return {
    poolId,
    vkId,
    outLaneId,
    outputMask,
    outputCount,
    assetMode,
    flags,
    unwrapWsol,
    opKind: assetMode === ASSET_MODE_PRIVATE ? 'transfer' : 'withdraw',
    nf0,
    nf1,
    cm0,
    cm1,
    cm2,
    publicAmountOut,
    relayerFee,
    mint,
    tokenProgram,
    recipientAccount,
    feeRecipient,
    cm2Memo90,
    outSub,
    outRoot,
    outMemo,
    nfPage,
    nextSub,
    nextMemo,
    nextNf,
  }
}

/**
 * Mode 1 Relayer Fee Verification (Private `ASSET_MODE_PRIVATE` Transfers):
 * Uses ONLY the hot Worker's read-only `FullViewingKey` (zero spend capability!) to decrypt
 * `memo[2]` AND strictly verify `Poseidon5(DOMAIN_NOTE, stealth, asset_id, amount, blinding) == cm2`.
 */
export function verifyShieldedCm2RelayerFee(
  fvk: FullViewingKey,
  meta: ParsedJoinSplitMeta,
): { mint: string; amount: bigint } | null {
  if (meta.assetMode !== ASSET_MODE_PRIVATE || !meta.cm2Memo90) return null
  const dec = tryDecryptAndVerifyMemo90(fvk, meta.cm2Memo90, meta.cm2)
  if (!dec || dec.amount <= 0n) return null
  const isNativeSol = dec.mint.every((b) => b === 0)
  return {
    mint: isNativeSol ? base58Encode(SYSTEM_PROGRAM_ID) : base58Encode(dec.mint),
    amount: dec.amount,
  }
}

export interface ParsedExecEscrowMeta extends ParsedPageAccounts {
  poolId: number
  vkId: number
  outLaneId: number
  shardId: number
  changeMask: number
  inKind: number
  outKind: number
  flags: number
  feeOnOutput: boolean
  amountIn: bigint
  minAmountOut: bigint
  relayerFee: bigint
  mintIn: string | null // null when EXEC_KIND_SOL
  vaultIn: string
  tokenProgIn: string | null
  mintOut: string | null // null when EXEC_KIND_SOL
  vaultOut: string
  tokenProgOut: string | null
  targetProgramId: string
  feeRecipient: string | null
  feeIsNativeSol: boolean
  feeMint: string | null
  feeTokenProg: string | null
  escrowPda: string
  routerAccountsStartIdx: number
}

/**
 * Parse Tag 7 (`ExecViaEscrow`) wire payload & variable leg/rollover accounts.
 * Wire:
 *   [0] tag(7), [1..5] pool_id, [5] vk_id, [6] out_lane_id, [7] escrow_shard,
 *   [8] change_mask, [9] in_kind, [10] out_kind, [11] flags,
 *   [12..204] proof(192), [204..236] nf0, [236..268] nf1,
 *   [268..300] cm0, [300..332] cm1, [332..364] cm2,
 *   [364..372] amount_in, [372..380] min_amount_out, [380..388] relayer_fee_amount,
 *   [388..420] out_stealth_owner, [420..452] out_blinding,
 *   [452..486] dyn_memo_head(34), [486..542] dyn_mask(56),
 *   [542..544] router_ix_len(u16 LE), [544..544+len] router_ix_data, [...] change_memos
 */
export function parseExecEscrowMeta(
  ixData: Uint8Array,
  accounts: SolanaAccountMeta[],
): ParsedExecEscrowMeta | null {
  if (ixData.length < 544 || ixData[0] !== TAG_EXEC_VIA_ESCROW || accounts.length < 16) return null
  const poolId = readU32le(ixData, 1)
  const vkId = ixData[5]!
  const outLaneId = ixData[6]!
  const shardId = ixData[7]!
  const changeMask = ixData[8]!
  const inKind = ixData[9]!
  const outKind = ixData[10]!
  const flags = ixData[11]!
  if (
    outLaneId >= NUM_LANES ||
    shardId >= NUM_ESCROW_SHARDS ||
    (changeMask & ~0x03) !== 0 ||
    (flags & ~(0x07 | EXEC_FLAG_FEE_ON_OUTPUT)) !== 0 ||
    (inKind !== EXEC_KIND_SOL && inKind !== EXEC_KIND_SPL) ||
    (outKind !== EXEC_KIND_SOL && outKind !== EXEC_KIND_SPL)
  ) {
    return null
  }
  const routerIxLen = readU16le(ixData, 542)
  const changeCount = (changeMask & 1) + ((changeMask >> 1) & 1)
  if (ixData.length !== 544 + routerIxLen + changeCount * MEMO_ENTRY_WIRE_LEN) return null

  const nf0 = ixData.subarray(204, 236)
  const nf1 = ixData.subarray(236, 268)
  if (isAllZero32(nf0)) return null
  if (isAllZero32(nf1) && !bytesEqual(accounts[4]!.pubkey, SYSTEM_PROGRAM_ID)) return null
  if (!isAllZero32(nf1) && bytesEqual(accounts[4]!.pubkey, SYSTEM_PROGRAM_ID)) return null
  if (!bytesEqual(accounts[5]!.pubkey, deriveLanePda(poolId, outLaneId).address)) return null
  if (!bytesEqual(accounts[6]!.pubkey, deriveLaneRentVaultPda(poolId, outLaneId).address)) {
    return null
  }
  if (!bytesEqual(accounts[13]!.pubkey, SYSTEM_PROGRAM_ID)) return null

  const outSub = base58Encode(accounts[7]!.pubkey)
  const outRoot = base58Encode(accounts[8]!.pubkey)
  const outMemo = base58Encode(accounts[9]!.pubkey)
  const nfPage = base58Encode(accounts[10]!.pubkey)

  const feeOnOutput = (flags & EXEC_FLAG_FEE_ON_OUTPUT) !== 0
  const amountIn = readU64le(ixData, 364)
  const minAmountOut = readU64le(ixData, 372)
  const relayerFee = readU64le(ixData, 380)
  if (amountIn === 0n) return null
  if (feeOnOutput && relayerFee === 0n) return null

  const expectedEscrow = deriveEscrowPda(poolId, shardId).address
  if (!bytesEqual(accounts[11]!.pubkey, expectedEscrow)) return null
  const targetProgramId = base58Encode(accounts[12]!.pubkey)

  let cursor = 14
  let mintIn: string | null = null
  let vaultIn: string
  let tokenProgIn: string | null = null
  let feeRecipient: string | null = null

  if (inKind === EXEC_KIND_SOL) {
    if (cursor >= accounts.length) return null
    vaultIn = base58Encode(accounts[cursor++]!.pubkey)
  } else {
    if (cursor + 5 > accounts.length) return null
    cursor += 1 // vault_auth
    mintIn = base58Encode(accounts[cursor++]!.pubkey)
    vaultIn = base58Encode(accounts[cursor++]!.pubkey)
    cursor += 1 // escrow_in_ata
    tokenProgIn = base58Encode(accounts[cursor++]!.pubkey)
  }

  if (relayerFee > 0n && !feeOnOutput) {
    if (cursor >= accounts.length) return null
    feeRecipient = base58Encode(accounts[cursor++]!.pubkey)
  }

  let mintOut: string | null = null
  let vaultOut: string
  let tokenProgOut: string | null = null
  if (outKind === EXEC_KIND_SOL) {
    if (cursor >= accounts.length) return null
    vaultOut = base58Encode(accounts[cursor++]!.pubkey)
  } else {
    if (cursor + 5 > accounts.length) return null
    cursor += 1 // vault_auth
    mintOut = base58Encode(accounts[cursor++]!.pubkey)
    vaultOut = base58Encode(accounts[cursor++]!.pubkey)
    cursor += 1 // escrow_out_ata
    tokenProgOut = base58Encode(accounts[cursor++]!.pubkey)
  }

  if (relayerFee > 0n && feeOnOutput) {
    if (cursor >= accounts.length) return null
    feeRecipient = base58Encode(accounts[cursor++]!.pubkey)
  }

  // Optional atomic rollover accounts (bit 0 = nextSub, bit 1 = nextMemo, bit 2 = nextNf)
  const hasNextSub = (flags & 0x01) !== 0
  const hasNextMemo = (flags & 0x02) !== 0
  const hasNextNf = (flags & 0x04) !== 0
  const rolloverCount = (hasNextSub ? 1 : 0) + (hasNextMemo ? 1 : 0) + (hasNextNf ? 1 : 0)
  // Strictly > 0 router accounts must follow rollover accounts (matches `program/src/lib.rs:2686`).
  if (cursor + rolloverCount >= accounts.length) return null
  const nextSub = hasNextSub ? base58Encode(accounts[cursor++]!.pubkey) : null
  const nextMemo = hasNextMemo ? base58Encode(accounts[cursor++]!.pubkey) : null
  const nextNf = hasNextNf ? base58Encode(accounts[cursor++]!.pubkey) : null

  const feeKind = feeOnOutput ? outKind : inKind
  const feeIsNativeSol = feeKind === EXEC_KIND_SOL

  return {
    poolId,
    vkId,
    outLaneId,
    shardId,
    changeMask,
    inKind,
    outKind,
    flags,
    feeOnOutput,
    amountIn,
    minAmountOut,
    relayerFee,
    mintIn,
    vaultIn,
    tokenProgIn,
    mintOut,
    vaultOut,
    tokenProgOut,
    targetProgramId,
    feeRecipient,
    feeIsNativeSol,
    feeMint: feeOnOutput ? mintOut : mintIn,
    feeTokenProg: feeOnOutput ? tokenProgOut : tokenProgIn,
    escrowPda: base58Encode(expectedEscrow),
    routerAccountsStartIdx: cursor,
    outSub,
    outRoot,
    outMemo,
    nfPage,
    nextSub,
    nextMemo,
    nextNf,
  }
}

export type PageSlotName =
  | 'outSub'
  | 'outRoot'
  | 'outMemo'
  | 'nfPage'
  | 'nextSub'
  | 'nextMemo'
  | 'nextNf'

export interface PageSlotEntry {
  slot: PageSlotName
  pda: string
}

export function listReferencedPageSlots(pages: ParsedPageAccounts): PageSlotEntry[] {
  const slots: PageSlotEntry[] = [
    { slot: 'outSub', pda: pages.outSub },
    { slot: 'outRoot', pda: pages.outRoot },
    { slot: 'outMemo', pda: pages.outMemo },
    { slot: 'nfPage', pda: pages.nfPage },
  ]
  if (pages.nextSub) slots.push({ slot: 'nextSub', pda: pages.nextSub })
  if (pages.nextMemo) slots.push({ slot: 'nextMemo', pda: pages.nextMemo })
  if (pages.nextNf) slots.push({ slot: 'nextNf', pda: pages.nextNf })
  return slots
}

export interface FetchedAccountMeta {
  bytes: Uint8Array
  owner: string
}

export type MissingPagePlanResult =
  | { ok: true; openPageIxs: SolanaInstruction[] }
  | { ok: false; error: string }

function isInitializedAudrenPage(acc: FetchedAccountMeta | null | undefined): boolean {
  return Boolean(acc && acc.owner === AUDREN_PROGRAM_ID_STR && acc.bytes.length > 0)
}

/**
 * Inspect the batched on-chain `LaneTreeState` and primary/rollover page accounts for a
 * `JoinSplit` (Tag 6) or `ExecViaEscrow` (Tag 7) instruction, verify every unopened page PDA
 * matches the exact canonical PDA derived from `(poolId, outLaneId, nextLeaf, nfCount)`
 * (rejecting spoofed PDAs), and return `OpenPage` (Tag 2) instructions to prepend atomically.
 */
export function planMissingOpenPageIxs(params: {
  payerB58: string
  poolId: number
  outLaneId: number
  laneAcc: FetchedAccountMeta | null | undefined
  pages: ParsedPageAccounts
  pageSlots: PageSlotEntry[]
  pageAccs: Array<FetchedAccountMeta | null | undefined>
}): MissingPagePlanResult {
  const { payerB58, poolId, outLaneId, laneAcc, pages, pageSlots, pageAccs } = params
  const missing: PageSlotEntry[] = []
  for (let i = 0; i < pageSlots.length; i++) {
    if (!isInitializedAudrenPage(pageAccs[i])) {
      missing.push(pageSlots[i]!)
    }
  }
  if (missing.length === 0) {
    return { ok: true, openPageIxs: [] }
  }

  if (!laneAcc || laneAcc.owner !== AUDREN_PROGRAM_ID_STR || laneAcc.bytes.length === 0) {
    return {
      ok: false,
      error: `Cannot open missing page(s): LaneTreeState for pool ${poolId} lane ${outLaneId} is not initialized`,
    }
  }

  let hdr: DecodedLaneHeader
  try {
    hdr = decodeLaneHeader(laneAcc.bytes)
  } catch {
    return {
      ok: false,
      error: `Cannot open missing page(s): invalid LaneTreeState for pool ${poolId} lane ${outLaneId}`,
    }
  }
  if (hdr.poolId !== poolId || hdr.laneId !== outLaneId) {
    return {
      ok: false,
      error: `LaneTreeState header mismatch for pool ${poolId} lane ${outLaneId}`,
    }
  }

  const curSub = hdr.nextLeaf / BigInt(SUBTREE_LEAVES)
  const curRoot = curSub / BigInt(SUBROOTS_PER_PAGE)
  const curMemo = hdr.nextLeaf / BigInt(MEMO_NOTES_PER_PAGE)
  const curNf = hdr.nfCount / BigInt(NF_PER_PAGE)

  const deriveKindPda = (pageKind: number, seq: bigint): string => {
    if (pageKind === OPEN_PAGE_KIND_SUBTREE) {
      return base58Encode(deriveSubtreePda(poolId, outLaneId, seq).address)
    }
    if (pageKind === OPEN_PAGE_KIND_SUBROOT) {
      return base58Encode(deriveSubrootPda(poolId, outLaneId, seq).address)
    }
    if (pageKind === OPEN_PAGE_KIND_MEMO) {
      return base58Encode(deriveMemoPda(poolId, outLaneId, seq).address)
    }
    return base58Encode(deriveNfPagePda(poolId, outLaneId, seq).address)
  }

  const seenOpened = new Set<string>()
  const openPageIxs: SolanaInstruction[] = []

  for (const item of missing) {
    let pageKind: number
    let expectedSeq: bigint

    if (item.slot === 'outSub') {
      pageKind = OPEN_PAGE_KIND_SUBTREE
      expectedSeq = curSub
    } else if (item.slot === 'outRoot') {
      pageKind = OPEN_PAGE_KIND_SUBROOT
      expectedSeq = curRoot
    } else if (item.slot === 'outMemo') {
      pageKind = OPEN_PAGE_KIND_MEMO
      expectedSeq = curMemo
    } else if (item.slot === 'nfPage') {
      pageKind = OPEN_PAGE_KIND_NULLIFIER
      expectedSeq = curNf
    } else if (item.slot === 'nextSub') {
      pageKind = OPEN_PAGE_KIND_SUBTREE
      expectedSeq =
        curSub > 0n && pages.outSub === deriveKindPda(OPEN_PAGE_KIND_SUBTREE, curSub - 1n)
          ? curSub
          : curSub + 1n
    } else if (item.slot === 'nextMemo') {
      pageKind = OPEN_PAGE_KIND_MEMO
      expectedSeq =
        curMemo > 0n && pages.outMemo === deriveKindPda(OPEN_PAGE_KIND_MEMO, curMemo - 1n)
          ? curMemo
          : curMemo + 1n
    } else {
      pageKind = OPEN_PAGE_KIND_NULLIFIER
      expectedSeq =
        curNf > 0n && pages.nfPage === deriveKindPda(OPEN_PAGE_KIND_NULLIFIER, curNf - 1n)
          ? curNf
          : curNf + 1n
    }

    const expectedPda = deriveKindPda(pageKind, expectedSeq)
    if (item.pda !== expectedPda) {
      return {
        ok: false,
        error: `Unopened ${item.slot} PDA (${item.pda}) does not match expected canonical PDA (${expectedPda}) for lane ${outLaneId} seq ${expectedSeq.toString()}`,
      }
    }

    if (!seenOpened.has(expectedPda)) {
      seenOpened.add(expectedPda)
      openPageIxs.push(
        buildOpenPageSolanaIx({
          payer: payerB58,
          pageKind,
          poolId,
          laneId: outLaneId,
          pageSeq: expectedSeq,
        }),
      )
    }
  }

  return { ok: true, openPageIxs }
}
