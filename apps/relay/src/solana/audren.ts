import {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_PUBLIC,
  AUDREN_PROGRAM_ID as AUDREN_PROGRAM_ID_STR,
  CHECKPOINT_RING_SLOTS,
  CLASSIC_TOKEN_PROGRAM_ID as CLASSIC_TOKEN_PROGRAM_ID_STR,
  DYN_MEMO_HEAD_LEN,
  EXEC_FLAG_FEE_ON_OUTPUT,
  MEMO_CT_LEN,
  MEMO_ENTRY_WIRE_LEN,
  MEMO_NOTES_PER_PAGE,
  MEMO_PAGE_LEN,
  MEMO_PAGE_SCAN_SLICE_LEN,
  NF_PAGE_LEN,
  NF_PER_PAGE,
  NUM_ESCROW_SHARDS,
  NUM_LANES,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_NULLIFIER,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  PROTOCOL_VERSION,
  SUBROOTS_PER_PAGE,
  SUBROOT_PAGE_LEN,
  SUBTREE_LEAVES,
  SUBTREE_PAGE_LEN,
  TAG_DEPOSIT,
  TAG_EXEC_VIA_ESCROW,
  TAG_INIT_LANE,
  TAG_INIT_POOL,
  TAG_OPEN_PAGE,
  TAG_PUBLISH_CHECKPOINT,
  TAG_SET_PAUSED,
  TAG_TRANSACT,
  TAG_UPDATE_POOL,
  TOKEN_2022_PROGRAM_ID as TOKEN_2022_PROGRAM_ID_STR,
  VK_ID_DEFAULT,
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
  deriveSubrootPdaSync,
  deriveSubtreePdaSync,
  deriveUnwrapPdaSync,
  deriveVaultAuthPdaSync,
  deterministicNoteRentFee,
  pickRandomEscrowShard,
  tryDecryptAndVerifyMemo,
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
  deriveAta,
  readU16le,
  readU32le,
  readU64le,
} from './codec'
import type { SolanaAccountMeta, SolanaInstruction } from '../types'

// ============================================================================
// Audren v1 Protocol Constants, PDAs & Wire Parsers
// Verified byte-for-byte against `crates/audren-core` and `program/src/lib.rs`
// ============================================================================

export {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_PUBLIC,
  AUDREN_PROGRAM_ID_STR,
  CHECKPOINT_RING_SLOTS,
  DYN_MEMO_HEAD_LEN,
  EXEC_FLAG_FEE_ON_OUTPUT,
  MEMO_CT_LEN,
  MEMO_ENTRY_WIRE_LEN,
  MEMO_NOTES_PER_PAGE,
  MEMO_PAGE_LEN,
  MEMO_PAGE_SCAN_SLICE_LEN,
  NF_PAGE_LEN,
  NF_PER_PAGE,
  NUM_ESCROW_SHARDS,
  NUM_LANES,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_NULLIFIER,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  PROTOCOL_VERSION,
  SUBROOTS_PER_PAGE,
  SUBROOT_PAGE_LEN,
  SUBTREE_LEAVES,
  SUBTREE_PAGE_LEN,
  TAG_DEPOSIT,
  TAG_EXEC_VIA_ESCROW,
  TAG_INIT_LANE,
  TAG_INIT_POOL,
  TAG_OPEN_PAGE,
  TAG_PUBLISH_CHECKPOINT,
  TAG_SET_PAUSED,
  TAG_TRANSACT,
  TAG_UPDATE_POOL,
  VK_ID_DEFAULT,
  WITHDRAW_FLAG_UNWRAP_WSOL,
  decodeLaneHeader,
  decodePoolState,
  decodeRootCheckpoint,
  deterministicNoteRentFee,
  pickRandomEscrowShard,
  type DecodedLaneHeader,
  type DecodedPoolState,
  type DecodedRootCheckpoint,
}

// Canonical v1 instruction discriminator aliases (`0x00..=0x08`)
export const IX_TAG_INIT_POOL = TAG_INIT_POOL
export const IX_TAG_INIT_LANE = TAG_INIT_LANE
export const IX_TAG_OPEN_PAGE = TAG_OPEN_PAGE
export const IX_TAG_DEPOSIT = TAG_DEPOSIT
export const IX_TAG_PUBLISH_CHECKPOINT = TAG_PUBLISH_CHECKPOINT
export const IX_TAG_TRANSACT = TAG_TRANSACT
export const IX_TAG_EXEC_VIA_ESCROW = TAG_EXEC_VIA_ESCROW
export const IX_TAG_SET_PAUSED = TAG_SET_PAUSED
export const IX_TAG_UPDATE_POOL = TAG_UPDATE_POOL

export const AUDREN_PROGRAM_ID = base58Decode(AUDREN_PROGRAM_ID_STR)

const toPdaBytes = (derived: { addressBytes: Uint8Array; bump: number }) => ({
  address: derived.addressBytes,
  bump: derived.bump,
})

export const derivePoolPda = (poolId = 0) => toPdaBytes(derivePoolPdaSync(poolId))
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

function isSupportedTokenProgram(programB58: string): boolean {
  return programB58 === CLASSIC_TOKEN_PROGRAM_ID_STR || programB58 === TOKEN_2022_PROGRAM_ID_STR
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
 * Extract active nullifier PDA base58 addresses directly from `Transact` (Tag 5) or
 * `ExecViaEscrow` (Tag 6) account headers: `[3] nf0_pda`, `[4] nf1_pda` (when != SystemProgram).
 */
export function extractNullifierPdas(tag: number, accounts: SolanaAccountMeta[]): string[] {
  if ((tag !== TAG_TRANSACT && tag !== TAG_EXEC_VIA_ESCROW) || accounts.length < 12) return []
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

export interface ParsedTransactMeta extends ParsedPageAccounts {
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
  vaultAta: string | null
  tokenProgram: string | null
  recipientAccount: string | null
  feeRecipient: string | null
  /** Optional `memo[2]` slice (106 B) corresponding to `cm2` when `(outputMask & 4) !== 0`. */
  cm2Memo: Uint8Array | null
}

/**
 * Parse Tag 5 (`Transact`) wire payload & fixed/outflow/rollover account layout.
 * Wire:
 *   [0] tag(5), [1..5] pool_id, [5] vk_id, [6] out_lane_id, [7] output_mask,
 *   [8] asset_mode (0=PRIVATE, 1=PUBLIC), [9] flags (bits 0..2 rollover, bit 3 WITHDRAW_FLAG_UNWRAP_WSOL),
 *   [10..202] proof(192), [202..234] nf0, [234..266] nf1,
 *   [266..298] cm0, [298..330] cm1, [330..362] cm2,
 *   [362..370] public_amount_out, [370..378] relayer_fee_amount, [378..] memos(popcount(output_mask)*106)
 */
export function parseTransactMeta(
  ixData: Uint8Array,
  accounts: SolanaAccountMeta[],
): ParsedTransactMeta | null {
  if (ixData.length < 378 || ixData[0] !== TAG_TRANSACT || accounts.length < 12) return null
  const poolId = readU32le(ixData, 1)
  const vkId = ixData[5]!
  const outLaneId = ixData[6]!
  const outputMask = ixData[7]!
  const assetMode = ixData[8]!
  const flags = ixData[9]!
  if (
    outLaneId >= NUM_LANES ||
    (outputMask & ~0x07) !== 0 ||
    (assetMode !== ASSET_MODE_PRIVATE && assetMode !== ASSET_MODE_PUBLIC) ||
    (flags & ~(0x07 | WITHDRAW_FLAG_UNWRAP_WSOL)) !== 0
  ) {
    return null
  }
  const outputCount = popcount3(outputMask)
  if (ixData.length !== 378 + outputCount * MEMO_ENTRY_WIRE_LEN) return null

  const unwrapWsol = (flags & WITHDRAW_FLAG_UNWRAP_WSOL) !== 0
  if (unwrapWsol && assetMode !== ASSET_MODE_PUBLIC) return null

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
  if (assetMode === ASSET_MODE_PUBLIC && publicAmountOut === 0n) return null

  if (isAllZero32(nf0)) return null
  if (!bytesEqual(accounts[1]!.pubkey, derivePoolPda(poolId).address)) return null
  if (!bytesEqual(accounts[3]!.pubkey, deriveNullifierPda(poolId, nf0).address)) return null
  if (isAllZero32(nf1)) {
    if (!bytesEqual(accounts[4]!.pubkey, SYSTEM_PROGRAM_ID)) return null
  } else {
    if (bytesEqual(nf0, nf1)) return null
    if (!bytesEqual(accounts[4]!.pubkey, deriveNullifierPda(poolId, nf1).address)) return null
  }
  if (!bytesEqual(accounts[5]!.pubkey, deriveLanePda(poolId, outLaneId).address)) return null
  if (!bytesEqual(accounts[6]!.pubkey, deriveLaneRentVaultPda(poolId, outLaneId).address)) {
    return null
  }
  if (!bytesEqual(accounts[11]!.pubkey, SYSTEM_PROGRAM_ID)) return null

  const outSub = base58Encode(accounts[7]!.pubkey)
  const outRoot = base58Encode(accounts[8]!.pubkey)
  const outMemo = base58Encode(accounts[9]!.pubkey)
  const nfPage = base58Encode(accounts[10]!.pubkey)

  let cm2Memo: Uint8Array | null = null
  if ((outputMask & 0x04) !== 0) {
    const idx = (outputMask & 1) + ((outputMask >> 1) & 1)
    const off = 378 + idx * MEMO_ENTRY_WIRE_LEN
    cm2Memo = ixData.subarray(off, off + MEMO_ENTRY_WIRE_LEN)
  }

  let mint: string | null = null
  let vaultAta: string | null = null
  let tokenProgram: string | null = null
  let recipientAccount: string | null = null
  let feeRecipient: string | null = null
  let cursor = 12

  if (assetMode === ASSET_MODE_PUBLIC) {
    const minAccs = unwrapWsol ? 19 : 18
    if (accounts.length < minAccs) return null
    const expectedVaultAuth = deriveVaultAuthPda(poolId).address
    if (!bytesEqual(accounts[12]!.pubkey, expectedVaultAuth)) return null
    const mintBytes = accounts[13]!.pubkey
    const vaultAtaBytes = accounts[14]!.pubkey
    const tokenProgBytes = accounts[15]!.pubkey
    mint = base58Encode(mintBytes)
    tokenProgram = base58Encode(tokenProgBytes)
    if (!isSupportedTokenProgram(tokenProgram)) return null
    const expectedVaultAta = deriveAta(expectedVaultAuth, tokenProgBytes, mintBytes)
    if (!bytesEqual(vaultAtaBytes, expectedVaultAta)) return null
    vaultAta = base58Encode(vaultAtaBytes)
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
    vaultAta,
    tokenProgram,
    recipientAccount,
    feeRecipient,
    cm2Memo,
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
 * the `106 B` `memo[2]` AND strictly verify
 * `Poseidon5(DOMAIN_NOTE, stealth, asset_id, amount, blinding) == cm2`.
 */
export function verifyShieldedCm2RelayerFee(
  fvk: FullViewingKey,
  meta: ParsedTransactMeta,
): { mint: string; amount: bigint } | null {
  if (meta.assetMode !== ASSET_MODE_PRIVATE || !meta.cm2Memo) return null
  const dec = tryDecryptAndVerifyMemo(fvk, meta.cm2Memo, meta.cm2)
  if (!dec || dec.amount <= 0n || isAllZero32(dec.mint)) return null
  return {
    mint: base58Encode(dec.mint),
    amount: dec.amount,
  }
}

export interface ParsedExecEscrowMeta extends ParsedPageAccounts {
  poolId: number
  vkId: number
  outLaneId: number
  shardId: number
  changeMask: number
  outputCount: number
  flags: number
  feeOnOutput: boolean
  amountIn: bigint
  minAmountOut: bigint
  relayerFee: bigint
  mintIn: string
  vaultIn: string
  escrowIn: string
  tokenProgIn: string
  mintOut: string
  vaultOut: string
  escrowOut: string
  tokenProgOut: string
  targetProgramId: string
  feeRecipient: string | null
  feeMint: string
  feeTokenProg: string
  escrowPda: string
  routerAccountsStartIdx: number
}

/**
 * Parse Tag 6 (`ExecViaEscrow`) SPL / Token-2022 wire payload & account layout.
 * Wire (`558 + router_ix_len + popcount(change_mask) * 106 B`):
 *   [0] tag(6), [1..5] pool_id, [5] vk_id, [6] out_lane_id, [7] escrow_shard,
 *   [8] change_mask, [9] flags (bits 0..2 rollover, bit 3 EXEC_FLAG_FEE_ON_OUTPUT),
 *   [10..202] proof(192), [202..234] nf0, [234..266] nf1,
 *   [266..298] cm0, [298..330] cm1, [330..362] cm2,
 *   [362..370] amount_in, [370..378] min_amount_out, [378..386] relayer_fee_amount,
 *   [386..418] out_stealth_owner, [418..450] out_blinding,
 *   [450..484] dyn_memo_head(34), [484..556] dyn_mask_72(72),
 *   [556..558] router_ix_len(u16 LE), [558..558+len] router_ix_data, [...] change_memos(106 B each)
 */
export function parseExecEscrowMeta(
  ixData: Uint8Array,
  accounts: SolanaAccountMeta[],
): ParsedExecEscrowMeta | null {
  const HEADER_LEN = 558
  // Minimum accounts: 14 fixed head + 5 input leg + 5 output leg + >= 1 router account = 25
  if (ixData.length < HEADER_LEN || ixData[0] !== TAG_EXEC_VIA_ESCROW || accounts.length < 25) {
    return null
  }
  const poolId = readU32le(ixData, 1)
  const vkId = ixData[5]!
  const outLaneId = ixData[6]!
  const shardId = ixData[7]!
  const changeMask = ixData[8]!
  const flags = ixData[9]!
  if (
    outLaneId >= NUM_LANES ||
    shardId >= NUM_ESCROW_SHARDS ||
    (changeMask & ~0x03) !== 0 ||
    (flags & ~(0x07 | EXEC_FLAG_FEE_ON_OUTPUT)) !== 0
  ) {
    return null
  }
  const routerIxLen = readU16le(ixData, 556)
  const changeCount = (changeMask & 1) + ((changeMask >> 1) & 1)
  if (ixData.length !== HEADER_LEN + routerIxLen + changeCount * MEMO_ENTRY_WIRE_LEN) return null

  const nf0 = ixData.subarray(202, 234)
  const nf1 = ixData.subarray(234, 266)
  const outBlinding = ixData.subarray(418, 450)
  if (isAllZero32(nf0) || isAllZero32(outBlinding)) return null
  if (!bytesEqual(accounts[1]!.pubkey, derivePoolPda(poolId).address)) return null
  if (!bytesEqual(accounts[3]!.pubkey, deriveNullifierPda(poolId, nf0).address)) return null
  if (isAllZero32(nf1)) {
    if (!bytesEqual(accounts[4]!.pubkey, SYSTEM_PROGRAM_ID)) return null
  } else {
    if (bytesEqual(nf0, nf1)) return null
    if (!bytesEqual(accounts[4]!.pubkey, deriveNullifierPda(poolId, nf1).address)) return null
  }
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
  const amountIn = readU64le(ixData, 362)
  const minAmountOut = readU64le(ixData, 370)
  const relayerFee = readU64le(ixData, 378)
  if (amountIn === 0n) return null
  if (feeOnOutput && relayerFee === 0n) return null

  const expectedVaultAuth = deriveVaultAuthPda(poolId).address
  const expectedEscrow = deriveEscrowPda(poolId, shardId).address
  if (!bytesEqual(accounts[11]!.pubkey, expectedEscrow)) return null
  const targetProgramId = base58Encode(accounts[12]!.pubkey)

  let cursor = 14
  let feeRecipient: string | null = null

  // Input leg (SPL / Token-2022 only; canonical vault_in_ata and escrow_in_ata enforced)
  if (cursor + 5 > accounts.length) return null
  const vaInBytes = accounts[cursor++]!.pubkey
  const mintInBytes = accounts[cursor++]!.pubkey
  const vaultInBytes = accounts[cursor++]!.pubkey
  const escrowInBytes = accounts[cursor++]!.pubkey
  const tokenProgInBytes = accounts[cursor++]!.pubkey
  const tokenProgIn = base58Encode(tokenProgInBytes)
  if (!bytesEqual(vaInBytes, expectedVaultAuth) || !isSupportedTokenProgram(tokenProgIn)) {
    return null
  }
  if (!bytesEqual(vaultInBytes, deriveAta(expectedVaultAuth, tokenProgInBytes, mintInBytes))) {
    return null
  }
  if (!bytesEqual(escrowInBytes, deriveAta(expectedEscrow, tokenProgInBytes, mintInBytes))) {
    return null
  }
  const mintIn = base58Encode(mintInBytes)
  const vaultIn = base58Encode(vaultInBytes)
  const escrowIn = base58Encode(escrowInBytes)

  if (relayerFee > 0n && !feeOnOutput) {
    if (cursor >= accounts.length) return null
    feeRecipient = base58Encode(accounts[cursor++]!.pubkey)
  }

  // Output leg (SPL / Token-2022 only; canonical vault_out_ata and escrow_out_ata enforced)
  if (cursor + 5 > accounts.length) return null
  const vaOutBytes = accounts[cursor++]!.pubkey
  const mintOutBytes = accounts[cursor++]!.pubkey
  const vaultOutBytes = accounts[cursor++]!.pubkey
  const escrowOutBytes = accounts[cursor++]!.pubkey
  const tokenProgOutBytes = accounts[cursor++]!.pubkey
  const tokenProgOut = base58Encode(tokenProgOutBytes)
  if (!bytesEqual(vaOutBytes, expectedVaultAuth) || !isSupportedTokenProgram(tokenProgOut)) {
    return null
  }
  if (!bytesEqual(vaultOutBytes, deriveAta(expectedVaultAuth, tokenProgOutBytes, mintOutBytes))) {
    return null
  }
  if (!bytesEqual(escrowOutBytes, deriveAta(expectedEscrow, tokenProgOutBytes, mintOutBytes))) {
    return null
  }
  const mintOut = base58Encode(mintOutBytes)
  const vaultOut = base58Encode(vaultOutBytes)
  const escrowOut = base58Encode(escrowOutBytes)

  if (relayerFee > 0n && feeOnOutput) {
    if (cursor >= accounts.length) return null
    feeRecipient = base58Encode(accounts[cursor++]!.pubkey)
  }

  // Optional atomic rollover accounts (bit 0 = nextSub, bit 1 = nextMemo, bit 2 = nextNf)
  const hasNextSub = (flags & 0x01) !== 0
  const hasNextMemo = (flags & 0x02) !== 0
  const hasNextNf = (flags & 0x04) !== 0
  const rolloverCount = (hasNextSub ? 1 : 0) + (hasNextMemo ? 1 : 0) + (hasNextNf ? 1 : 0)
  // Strictly 1..=64 router accounts must follow rollover accounts (matches `program/src/lib.rs`).
  const routerCount = accounts.length - (cursor + rolloverCount)
  if (routerCount < 1 || routerCount > 64) return null
  const nextSub = hasNextSub ? base58Encode(accounts[cursor++]!.pubkey) : null
  const nextMemo = hasNextMemo ? base58Encode(accounts[cursor++]!.pubkey) : null
  const nextNf = hasNextNf ? base58Encode(accounts[cursor++]!.pubkey) : null

  return {
    poolId,
    vkId,
    outLaneId,
    shardId,
    changeMask,
    outputCount: changeCount + 1, // change notes + dynamic output note
    flags,
    feeOnOutput,
    amountIn,
    minAmountOut,
    relayerFee,
    mintIn,
    vaultIn,
    escrowIn,
    tokenProgIn,
    mintOut,
    vaultOut,
    escrowOut,
    tokenProgOut,
    targetProgramId,
    feeRecipient,
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
 * `Transact` (Tag 5) or `ExecViaEscrow` (Tag 6) instruction, verify every unopened page PDA
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
  /** Optional running `(nextLeaf, nfCount)` counters for sequential instructions in a batch. */
  laneCounters?: { nextLeaf: bigint; nfCount: bigint }
  /** Optional shared set of page PDAs already scheduled for `OpenPage` in an earlier batch entry. */
  alreadyScheduledPdas?: Set<string>
}): MissingPagePlanResult {
  const {
    payerB58,
    poolId,
    outLaneId,
    laneAcc,
    pages,
    pageSlots,
    pageAccs,
    laneCounters,
    alreadyScheduledPdas,
  } = params
  const missing: PageSlotEntry[] = []
  for (let i = 0; i < pageSlots.length; i++) {
    const slot = pageSlots[i]!
    if (!isInitializedAudrenPage(pageAccs[i]) && !alreadyScheduledPdas?.has(slot.pda)) {
      missing.push(slot)
    }
  }
  if (missing.length === 0) {
    return { ok: true, openPageIxs: [] }
  }

  let nextLeaf: bigint
  let nfCount: bigint
  if (laneCounters) {
    nextLeaf = laneCounters.nextLeaf
    nfCount = laneCounters.nfCount
  } else {
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
    nextLeaf = hdr.nextLeaf
    nfCount = hdr.nfCount
  }

  const curSub = nextLeaf / BigInt(SUBTREE_LEAVES)
  const curRoot = curSub / BigInt(SUBROOTS_PER_PAGE)
  const curMemo = nextLeaf / BigInt(MEMO_NOTES_PER_PAGE)
  const curNf = nfCount / BigInt(NF_PER_PAGE)

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

  const seenOpened = alreadyScheduledPdas ?? new Set<string>()
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

/**
 * Plan deduplicated `OpenPage` (Tag 2) instructions across 1..=4 Audren instructions spanning
 * one or more lanes, advancing simulated `(nextLeaf, nfCount)` per lane as each instruction executes.
 */
export function planBatchMissingOpenPageIxs(params: {
  payerB58: string
  entries: Array<{
    poolId: number
    outLaneId: number
    outputCount: number
    nullifierCount: number
    pages: ParsedPageAccounts
  }>
  fetchedAccounts: Map<string, FetchedAccountMeta | null>
}): MissingPagePlanResult {
  const { payerB58, entries, fetchedAccounts } = params
  const laneCountersByKey = new Map<string, { nextLeaf: bigint; nfCount: bigint }>()
  const alreadyScheduledPdas = new Set<string>()
  const openPageIxs: SolanaInstruction[] = []

  for (const entry of entries) {
    const laneKey = `${entry.poolId}:${entry.outLaneId}`
    const lanePda = base58Encode(deriveLanePda(entry.poolId, entry.outLaneId).address)
    const laneAcc = fetchedAccounts.get(lanePda) ?? null
    const pageSlots = listReferencedPageSlots(entry.pages)
    const pageAccs = pageSlots.map((s) => fetchedAccounts.get(s.pda) ?? null)

    let counters = laneCountersByKey.get(laneKey)
    if (!counters && laneAcc && laneAcc.owner === AUDREN_PROGRAM_ID_STR && laneAcc.bytes.length > 0) {
      try {
        const hdr = decodeLaneHeader(laneAcc.bytes)
        if (hdr.poolId === entry.poolId && hdr.laneId === entry.outLaneId) {
          counters = { nextLeaf: hdr.nextLeaf, nfCount: hdr.nfCount }
          laneCountersByKey.set(laneKey, counters)
        }
      } catch {
        // Handled cleanly inside planMissingOpenPageIxs when any page is actually missing
      }
    }

    const res = planMissingOpenPageIxs({
      payerB58,
      poolId: entry.poolId,
      outLaneId: entry.outLaneId,
      laneAcc,
      pages: entry.pages,
      pageSlots,
      pageAccs,
      laneCounters: counters,
      alreadyScheduledPdas,
    })
    if (!res.ok) return res
    openPageIxs.push(...res.openPageIxs)

    if (counters) {
      counters.nextLeaf += BigInt(entry.outputCount)
      counters.nfCount += BigInt(entry.nullifierCount)
    }
  }

  return { ok: true, openPageIxs }
}
