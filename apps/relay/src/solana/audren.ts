import {
  SYSTEM_PROGRAM_ID,
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
// Audren v1 Protocol Constants & PDAs
// Verified byte-for-byte against `programs/audren/program/src/lib.rs`
// ============================================================================

export const AUDREN_PROGRAM_ID_STR = 'AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3'
export const AUDREN_PROGRAM_ID = base58Decode(AUDREN_PROGRAM_ID_STR)

export const TAG_OPEN_PAGE = 1
export const TAG_DEPOSIT = 2
export const TAG_TRANSFER = 3
export const TAG_MERGE = 4
export const TAG_SWAP_VIA_ROUTER = 5
export const TAG_WITHDRAW = 6
export const TAG_OPEN_LANE_PAGE = 12

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
    case TAG_SWAP_VIA_ROUTER:
      return 'swap'
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

export function deriveSwapEscrowPda(poolId: number, shardId: number) {
  return findProgramAddressSync(
    [utf8('audren_escrow'), u32le(poolId), new Uint8Array([shardId & 0xff])],
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
 *   - Tag 3 (Transfer): [3] nullifier_pda
 *   - Tag 4 (Merge):    [3] nullifier_1_pda, [4] nullifier_2_pda
 *   - Tag 5 (Swap):     [3] nullifier_pda
 *   - Tag 6 (Withdraw): [3] nullifier_pda
 */
export function extractNullifierPdas(tag: number, accounts: SolanaAccountMeta[]): string[] {
  if (tag === TAG_MERGE) {
    if (accounts.length < 5) return []
    return [base58Encode(accounts[3]!.pubkey), base58Encode(accounts[4]!.pubkey)]
  }
  if (tag === TAG_TRANSFER || tag === TAG_SWAP_VIA_ROUTER || tag === TAG_WITHDRAW) {
    if (accounts.length < 4) return []
    return [base58Encode(accounts[3]!.pubkey)]
  }
  return []
}

/**
 * Extract swap metadata from Tag 5 (`SwapViaRouter`).
 * Exact account layout (verified against `apps/audren-web/lib/audren-prover.ts:2278`):
 *   [0] payer, [1] pool, [2] out_page, [3] nullifier, [4] rent_vault,
 *   [5] zk_program, [6] system_program, [7] vault_auth,
 *   [8] in_mint, [9] vault_in, [10] token_program_in,
 *   [11] out_mint, [12] vault_out, [13] token_program_out,
 *   [14] router_program_id, [15..] input_pages + router_accounts
 */
export function parseSwapMeta(
  ixData: Uint8Array,
  accounts: SolanaAccountMeta[],
): {
  shardId: number
  amountIn: bigint
  minAmountOut: bigint
  mintIn: string
  vaultIn: string
  tokenProgIn: string
  mintOut: string
  vaultOut: string
  tokenProgOut: string
  routerProgramId: string
  escrowPda: string
} | null {
  if (ixData.length < 154 || ixData[0] !== TAG_SWAP_VIA_ROUTER || accounts.length < 19) return null
  const shardId = ixData[2]!
  if (shardId >= MAX_ESCROW_SHARDS) return null
  const escrowPda = base58Encode(deriveSwapEscrowPda(0, shardId).address)
  return {
    shardId,
    amountIn: readU64le(ixData, 4),
    minAmountOut: readU64le(ixData, 12),
    mintIn: base58Encode(accounts[8]!.pubkey),
    vaultIn: base58Encode(accounts[9]!.pubkey),
    tokenProgIn: base58Encode(accounts[10]!.pubkey),
    mintOut: base58Encode(accounts[11]!.pubkey),
    vaultOut: base58Encode(accounts[12]!.pubkey),
    tokenProgOut: base58Encode(accounts[13]!.pubkey),
    routerProgramId: base58Encode(accounts[14]!.pubkey),
    escrowPda,
  }
}

export function isAudrenVaultOrEscrowOwner(ownerB58: string, poolId = 0): boolean {
  const ownerBytes = base58Decode(ownerB58)
  if (bytesEqual(ownerBytes, deriveVaultAuthPda(poolId).address)) return true
  for (let sid = 0; sid < MAX_ESCROW_SHARDS; sid++) {
    if (bytesEqual(ownerBytes, deriveSwapEscrowPda(poolId, sid).address)) return true
  }
  return false
}
