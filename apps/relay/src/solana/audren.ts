import {
  CLASSIC_TOKEN_PROGRAM_ID_STR,
  SYSTEM_PROGRAM_ID,
  WSOL_MINT_STR,
  base58Decode,
  base58Encode,
  bytesEqual,
  findProgramAddressSync,
  readU64le,
  u32le,
  u64le,
  utf8,
} from './codec'
import type { AudrenOpKind, SolanaAccountMeta, SolanaInstruction } from '../types'

// ============================================================================
// Audren Protocol Constants & PDAs
// Verified byte-for-byte against `program/src/lib.rs` and `crates/audren-core/`
// ============================================================================

export const AUDREN_PROGRAM_ID_STR = 'AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3'
export const AUDREN_PROGRAM_ID = base58Decode(AUDREN_PROGRAM_ID_STR)

export const TAG_OPEN_PAGE = 1
export const TAG_DEPOSIT = 2
export const TAG_TRANSFER = 3
export const TAG_MERGE = 4
export const TAG_EXEC_VIA_ESCROW = 5
export const TAG_SWAP_VIA_ROUTER = TAG_EXEC_VIA_ESCROW
export const TAG_WITHDRAW = 6
export const TAG_OPEN_LANE_PAGE = 12

export const DEPOSIT_FLAG_NATIVE_SOL = 0x01
export const DEPOSIT_FLAG_FEE_FROM_AMOUNT = 0x02

export const EXEC_FLAG_HAS_CHANGE = 0x01
export const EXEC_FLAG_ALLOW_PARTIAL_REFUND = 0x02
export const EXEC_FLAG_FEE_ON_OUTPUT = 0x04

export const WITHDRAW_FLAG_NATIVE_SOL = 0x01
export const WITHDRAW_FLAG_HAS_CHANGE = 0x02
export const WITHDRAW_FLAG_UNWRAP_WSOL = 0x04

export const MAX_APPEND_LANES = 16
export const MAX_ESCROW_SHARDS = 16
export const PAGE_ROLLOVER_THRESHOLD = 28

const PAGE_SEQ_MASK = 0x00ff_ffff_ffff_ffffn

export function laneOfPageId(pageId: bigint): number {
  return Number((pageId >> 56n) & 0xffn)
}

export function seqOfPageId(pageId: bigint): bigint {
  return pageId & PAGE_SEQ_MASK
}

export function pageIdForLane(laneId: number, seq: bigint): bigint {
  return (BigInt(laneId & 0xff) << 56n) | (seq & PAGE_SEQ_MASK)
}

export function opKindFromTag(tag: number): AudrenOpKind | null {
  switch (tag) {
    case TAG_TRANSFER:
      return 'transfer'
    case TAG_MERGE:
      return 'merge'
    case TAG_EXEC_VIA_ESCROW:
      return 'exec_escrow'
    case TAG_WITHDRAW:
      return 'withdraw'
    default:
      return null
  }
}

export function derivePoolPda(poolId = 0) {
  return findProgramAddressSync([utf8('audren_pool'), u32le(poolId)], AUDREN_PROGRAM_ID)
}

export function deriveEpochPagePda(poolId: number, pageId: bigint) {
  return findProgramAddressSync(
    [utf8('audren_page'), u32le(poolId), u64le(pageId)],
    AUDREN_PROGRAM_ID,
  )
}

export function derivePageRentVaultPda(poolId = 0) {
  return findProgramAddressSync([utf8('audren_rent'), u32le(poolId)], AUDREN_PROGRAM_ID)
}

export function deriveLanePda(poolId: number, laneId: number) {
  return findProgramAddressSync(
    [utf8('audren_lane'), u32le(poolId), new Uint8Array([laneId & 0xff])],
    AUDREN_PROGRAM_ID,
  )
}

export function deriveLaneRentVaultPda(poolId: number, laneId: number) {
  return findProgramAddressSync(
    [utf8('audren_lrent'), u32le(poolId), new Uint8Array([laneId & 0xff])],
    AUDREN_PROGRAM_ID,
  )
}

export function deriveVaultAuthPda(poolId = 0) {
  return findProgramAddressSync([utf8('audren_vault'), u32le(poolId)], AUDREN_PROGRAM_ID)
}

export function deriveSolVaultPda(poolId = 0) {
  return findProgramAddressSync([utf8('audren_sol'), u32le(poolId)], AUDREN_PROGRAM_ID)
}

export function deriveEscrowPda(poolId: number, shardId: number) {
  return findProgramAddressSync(
    [utf8('audren_escrow'), u32le(poolId), new Uint8Array([shardId & 0xff])],
    AUDREN_PROGRAM_ID,
  )
}

export const deriveSwapEscrowPda = deriveEscrowPda

export function deriveUnwrapPda(poolId: number, nullifier32: Uint8Array) {
  return findProgramAddressSync(
    [utf8('audren_unwrap'), u32le(poolId), nullifier32],
    AUDREN_PROGRAM_ID,
  )
}

export function decodePoolState(bytes: Uint8Array) {
  if (bytes.length < 48) throw new Error('PoolState too short')
  return {
    mode: bytes[10]!,
    paused: bytes[11] !== 0,
    currentPageId: readU64le(bytes, 16),
    totalNotes: readU64le(bytes, 24),
    totalSpends: readU64le(bytes, 32),
    pageRentFeeLamports: readU64le(bytes, 40),
    activeLanes:
      bytes.length > 116 && bytes[116]! >= 1 ? Math.min(bytes[116]!, MAX_APPEND_LANES) : 1,
  }
}

export function decodeEpochPageHeader(bytes: Uint8Array) {
  if (bytes.length < 24) throw new Error('EpochPage too short')
  const magic = String.fromCharCode(...bytes.subarray(0, 8))
  if (magic !== 'AUDRNPG1') throw new Error('Invalid EpochPage magic')
  return {
    closed: bytes[10] !== 0,
    count: bytes[11]!,
  }
}

export function decodeAppendLaneState(bytes: Uint8Array): {
  laneId: number
  activePageId: bigint
  createdSlot: bigint
} | null {
  if (bytes.length < 32) return null
  const magic = String.fromCharCode(...bytes.subarray(0, 8))
  if (magic !== 'AUDRNLN1') return null
  return {
    laneId: bytes[9]!,
    activePageId: readU64le(bytes, 16),
    createdSlot: readU64le(bytes, 24),
  }
}

export function buildOpenPageIx(params: {
  relayerPubkey: Uint8Array
  poolPda: Uint8Array
  curPagePda: Uint8Array
  nextPagePda: Uint8Array
  rentVaultPda: Uint8Array
}): SolanaInstruction {
  return {
    programId: AUDREN_PROGRAM_ID,
    accounts: [
      { pubkey: params.relayerPubkey, isSigner: true, isWritable: true },
      { pubkey: params.poolPda, isSigner: false, isWritable: true },
      { pubkey: params.curPagePda, isSigner: false, isWritable: true },
      { pubkey: params.nextPagePda, isSigner: false, isWritable: true },
      { pubkey: params.rentVaultPda, isSigner: false, isWritable: true },
      { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data: new Uint8Array([TAG_OPEN_PAGE]),
  }
}

export function buildOpenLanePageIx(params: {
  relayerPubkey: Uint8Array
  poolPda: Uint8Array
  lanePda: Uint8Array
  curPagePda: Uint8Array
  nextPagePda: Uint8Array
  laneRentVaultPda: Uint8Array
  laneId: number
}): SolanaInstruction {
  return {
    programId: AUDREN_PROGRAM_ID,
    accounts: [
      { pubkey: params.relayerPubkey, isSigner: true, isWritable: true },
      { pubkey: params.poolPda, isSigner: false, isWritable: false },
      { pubkey: params.lanePda, isSigner: false, isWritable: true },
      { pubkey: params.curPagePda, isSigner: false, isWritable: true },
      { pubkey: params.nextPagePda, isSigner: false, isWritable: true },
      { pubkey: params.laneRentVaultPda, isSigner: false, isWritable: true },
      { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data: new Uint8Array([TAG_OPEN_LANE_PAGE, params.laneId & 0xff]),
  }
}

/**
 * Extract nullifier PDA base58 addresses directly from Audren instruction accounts:
 *   - Tag 3 (Transfer):      [3] nullifier_pda
 *   - Tag 4 (Merge):         [3] nullifier_1_pda, [4] nullifier_2_pda
 *   - Tag 5 (ExecViaEscrow): [3] nullifier_pda
 *   - Tag 6 (Withdraw):      [3] nullifier_pda
 */
export function extractNullifierPdas(tag: number, accounts: SolanaAccountMeta[]): string[] {
  if (tag === TAG_MERGE) {
    if (accounts.length < 5) return []
    return [base58Encode(accounts[3]!.pubkey), base58Encode(accounts[4]!.pubkey)]
  }
  if (tag === TAG_TRANSFER || tag === TAG_EXEC_VIA_ESCROW || tag === TAG_WITHDRAW) {
    if (accounts.length < 4) return []
    return [base58Encode(accounts[3]!.pubkey)]
  }
  return []
}

export interface ParsedExecEscrowMeta {
  shardId: number
  flags: number
  hasChange: boolean
  allowPartialRefund: boolean
  feeOnOutput: boolean
  amountIn: bigint
  minAmountOut: bigint
  relayerFee: bigint
  mintIn: string
  vaultIn: string
  tokenProgIn: string
  mintOut: string
  vaultOut: string
  tokenProgOut: string
  targetProgramId: string
  feeRecipientAta: string
  feeMint: string
  feeTokenProg: string
  escrowPda: string
}

/**
 * Parse Tag 5 (`ExecViaEscrow`) wire header and fixed account header.
 * Wire:
 *   [0] tag(5), [1] m, [2] shard_id, [3] flags,
 *   [4..12] amount_in, [12..20] min_amount_out, [20..28] relayer_fee, ...
 * Accounts:
 *   [0] payer, [1] pool, [2] out_page, [3] nullifier, [4] rent_vault,
 *   [5] zk_program, [6] system_program, [7] vault_auth,
 *   [8] in_mint, [9] vault_in, [10] token_program_in,
 *   [11] out_mint, [12] vault_out, [13] token_program_out,
 *   [14] target_program_id, [15] fee_recipient_ata, [16..] input_pages + action_accounts
 */
export function parseExecEscrowMeta(
  ixData: Uint8Array,
  accounts: SolanaAccountMeta[],
): ParsedExecEscrowMeta | null {
  if (ixData.length < 162 || ixData[0] !== TAG_EXEC_VIA_ESCROW || accounts.length < 20) return null
  const shardId = ixData[2]!
  if (shardId >= MAX_ESCROW_SHARDS) return null
  const flags = ixData[3]!
  if ((flags & ~0x07) !== 0) return null
  const feeOnOutput = (flags & EXEC_FLAG_FEE_ON_OUTPUT) !== 0
  const mintIn = base58Encode(accounts[8]!.pubkey)
  const tokenProgIn = base58Encode(accounts[10]!.pubkey)
  const mintOut = base58Encode(accounts[11]!.pubkey)
  const tokenProgOut = base58Encode(accounts[13]!.pubkey)
  const escrowPda = base58Encode(deriveEscrowPda(0, shardId).address)
  return {
    shardId,
    flags,
    hasChange: (flags & EXEC_FLAG_HAS_CHANGE) !== 0,
    allowPartialRefund: (flags & EXEC_FLAG_ALLOW_PARTIAL_REFUND) !== 0,
    feeOnOutput,
    amountIn: readU64le(ixData, 4),
    minAmountOut: readU64le(ixData, 12),
    relayerFee: readU64le(ixData, 20),
    mintIn,
    vaultIn: base58Encode(accounts[9]!.pubkey),
    tokenProgIn,
    mintOut,
    vaultOut: base58Encode(accounts[12]!.pubkey),
    tokenProgOut,
    targetProgramId: base58Encode(accounts[14]!.pubkey),
    feeRecipientAta: base58Encode(accounts[15]!.pubkey),
    feeMint: feeOnOutput ? mintOut : mintIn,
    feeTokenProg: feeOnOutput ? tokenProgOut : tokenProgIn,
    escrowPda,
  }
}

export const parseSwapMeta = parseExecEscrowMeta

export interface ParsedWithdrawMeta {
  flags: number
  isNativeSol: boolean
  hasChange: boolean
  unwrapWsol: boolean
  amount: bigint
  relayerFee: bigint
  feeRecipient: string
  mint: string | null
  tokenProgram: string | null
  recipientAccount: string
}

/**
 * Parse Tag 6 (`Withdraw`) wire header and fixed account layout.
 * Wire:
 *   [0] tag(6), [1] m, [2] flags, [3..11] amount, [11..19] relayer_fee, ...
 * Accounts:
 *   [0..6] payer, pool, out_page, nullifier, rent_vault, zk_prog, sys_prog
 *   [7] fee_recipient
 *   Native SOL (bit0=1):        [8] sol_vault, [9] recipient, [10..] input_pages
 *   SPL (bit0=0, bit2=0):       [8] vault_auth, [9] mint, [10] vault_ata, [11] recipient_ata, [12] token_prog, [13..] input_pages
 *   Unwrap WSOL (bit0=0,bit2=1):[8] vault_auth, [9] wsol_mint, [10] vault_wsol_ata, [11] recipient_wallet, [12] classic_token_prog, [13] unwrap_pda, [14..] input_pages
 */
export function parseWithdrawMeta(
  ixData: Uint8Array,
  accounts: SolanaAccountMeta[],
): ParsedWithdrawMeta | null {
  if (ixData.length < 24 || ixData[0] !== TAG_WITHDRAW) return null
  const flags = ixData[2]!
  if ((flags & ~0x07) !== 0) return null
  const isNativeSol = (flags & WITHDRAW_FLAG_NATIVE_SOL) !== 0
  const hasChange = (flags & WITHDRAW_FLAG_HAS_CHANGE) !== 0
  const unwrapWsol = (flags & WITHDRAW_FLAG_UNWRAP_WSOL) !== 0
  if (isNativeSol && unwrapWsol) return null

  const amount = readU64le(ixData, 3)
  const relayerFee = readU64le(ixData, 11)
  if (accounts.length < 11) return null
  const feeRecipient = base58Encode(accounts[7]!.pubkey)

  if (isNativeSol) {
    return {
      flags,
      isNativeSol: true,
      hasChange,
      unwrapWsol: false,
      amount,
      relayerFee,
      feeRecipient,
      mint: null,
      tokenProgram: null,
      recipientAccount: base58Encode(accounts[9]!.pubkey),
    }
  }
  const expectedVaultAuth = deriveVaultAuthPda(0).address
  if (unwrapWsol) {
    if (accounts.length < 15) return null
    if (!bytesEqual(accounts[8]!.pubkey, expectedVaultAuth)) return null
    const mint = base58Encode(accounts[9]!.pubkey)
    const tokenProgram = base58Encode(accounts[12]!.pubkey)
    if (mint !== WSOL_MINT_STR || tokenProgram !== CLASSIC_TOKEN_PROGRAM_ID_STR) return null
    return {
      flags,
      isNativeSol: false,
      hasChange,
      unwrapWsol: true,
      amount,
      relayerFee,
      feeRecipient,
      mint,
      tokenProgram,
      recipientAccount: base58Encode(accounts[11]!.pubkey),
    }
  }
  if (accounts.length < 14) return null
  if (!bytesEqual(accounts[8]!.pubkey, expectedVaultAuth)) return null
  return {
    flags,
    isNativeSol: false,
    hasChange,
    unwrapWsol: false,
    amount,
    relayerFee,
    feeRecipient,
    mint: base58Encode(accounts[9]!.pubkey),
    tokenProgram: base58Encode(accounts[12]!.pubkey),
    recipientAccount: base58Encode(accounts[11]!.pubkey),
  }
}

export function isAudrenVaultOrEscrowOwner(ownerB58: string, poolId = 0): boolean {
  const ownerBytes = base58Decode(ownerB58)
  if (bytesEqual(ownerBytes, deriveVaultAuthPda(poolId).address)) return true
  for (let sid = 0; sid < MAX_ESCROW_SHARDS; sid++) {
    if (bytesEqual(ownerBytes, deriveEscrowPda(poolId, sid).address)) return true
  }
  return false
}
