import {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_PUBLIC,
  AUDREN_PROGRAM_ID as AUDREN_PROGRAM_ID_STR,
  AUTO_OPEN_MEMO_REM_THRESHOLD,
  AUTO_OPEN_NF_REM_THRESHOLD,
  AUTO_OPEN_SUBROOT_SLOT_THRESHOLD,
  AUTO_OPEN_SUBTREE_REM_THRESHOLD,
  CLASSIC_TOKEN_PROGRAM_ID as CLASSIC_TOKEN_PROGRAM_ID_STR,
  CU_LIMIT_DEPOSIT,
  CU_LIMIT_DEPOSIT_HOOK,
  CU_LIMIT_EXEC_VIA_ESCROW_BASE,
  CU_LIMIT_OPEN_PAGE,
  CU_LIMIT_TRANSACT_FULL_EXIT,
  CU_LIMIT_TRANSACT_PRIVATE,
  CU_LIMIT_TRANSACT_WITHDRAW,
  CU_LIMIT_TRANSACT_WITHDRAW_HOOK,
  DEFAULT_ROOT_EPOCH_INTERVAL,
  DYN_MEMO_HEAD_LEN,
  EPOCH_RING_LEN,
  EXEC_FLAG_FEE_ON_OUTPUT,
  MAX_ROOT_EPOCH_INTERVAL,
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
  OPEN_PAGE_MEMO_LOOKAHEAD_SLOT,
  OPEN_PAGE_WIRE_LEN,
  PROTOCOL_VERSION,
  ROOTS_MAGIC,
  ROOTS_SEED,
  ROOT_ENTRY_LEN,
  ROOT_HISTORY_LEN,
  ROOT_RING_EPOCH,
  ROOT_RING_SLOT,
  ROOT_SNAPSHOT_LEN,
  RT_OFF_BUMP,
  RT_OFF_EPOCH_COUNT,
  RT_OFF_EPOCH_CURSOR,
  RT_OFF_EPOCH_INTERVAL,
  RT_OFF_LATEST_SLOT,
  RT_OFF_POOL_ID,
  RT_OFF_SAME_SLOT_BUMPED,
  RT_OFF_SLOT_COUNT,
  RT_OFF_SLOT_CURSOR,
  RT_OFF_STABLE_EPOCH_ID,
  RT_OFF_STABLE_SLOT,
  RT_OFF_VERSION,
  SLOT_RING_LEN,
  SUBROOTS_PER_PAGE,
  SUBROOT_PAGE_LEN,
  SUBTREE_LEAVES,
  SUBTREE_PAGE_LEN,
  TAG_DEPOSIT,
  TAG_EXEC_VIA_ESCROW,
  TAG_INIT_LANE,
  TAG_INIT_POOL,
  TAG_INIT_ROOT_HISTORY,
  TAG_OPEN_PAGE,
  TAG_SET_PAUSED,
  TAG_TRANSACT,
  TAG_UPDATE_POOL,
  TOKEN_2022_PROGRAM_ID as TOKEN_2022_PROGRAM_ID_STR,
  VK_ID_DEFAULT,
  WITHDRAW_FLAG_UNWRAP_WSOL,
  WSOL_MINT as WSOL_MINT_STR,
  buildOpenPageInstruction,
  decodeEpochRingEntry,
  decodeGlobalRootHistory,
  decodeLaneHeader,
  decodePoolState,
  decodeSlotRingEntry,
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
  deterministicNoteRentFee,
  inspectToken2022UnsafeSelfPay,
  pickRandomEscrowShard,
  planAutoOpenPages,
  recommendedExecViaEscrowCuLimit,
  recommendedTransactCuLimit,
  selectRootSnapshotForNotes,
  tryDecryptAndVerifyMemo,
  type AutoOpenPageTarget,
  type DecodedGlobalRootHistory,
  type DecodedLaneHeader,
  type DecodedPoolState,
  type FullViewingKey,
  type RootEntry,
  type RootSnapshotChoice,
} from '@audren/sdk'
import { TRUSTED_FREEZE_AUTHORITY_MINTS } from '../env'
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
// Audren v1.3.0 Protocol Constants, PDAs & Wire Parsers
// Verified byte-for-byte against `crates/audren-core` and `program/src/lib.rs`
// ============================================================================

export {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_PUBLIC,
  AUDREN_PROGRAM_ID_STR,
  AUTO_OPEN_MEMO_REM_THRESHOLD,
  AUTO_OPEN_NF_REM_THRESHOLD,
  AUTO_OPEN_SUBROOT_SLOT_THRESHOLD,
  AUTO_OPEN_SUBTREE_REM_THRESHOLD,
  CU_LIMIT_DEPOSIT,
  CU_LIMIT_DEPOSIT_HOOK,
  CU_LIMIT_EXEC_VIA_ESCROW_BASE,
  CU_LIMIT_OPEN_PAGE,
  CU_LIMIT_TRANSACT_FULL_EXIT,
  CU_LIMIT_TRANSACT_PRIVATE,
  CU_LIMIT_TRANSACT_WITHDRAW,
  CU_LIMIT_TRANSACT_WITHDRAW_HOOK,
  DEFAULT_ROOT_EPOCH_INTERVAL,
  DYN_MEMO_HEAD_LEN,
  EPOCH_RING_LEN,
  EXEC_FLAG_FEE_ON_OUTPUT,
  MAX_ROOT_EPOCH_INTERVAL,
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
  OPEN_PAGE_MEMO_LOOKAHEAD_SLOT,
  OPEN_PAGE_WIRE_LEN,
  PROTOCOL_VERSION,
  ROOTS_MAGIC,
  ROOTS_SEED,
  ROOT_ENTRY_LEN,
  ROOT_HISTORY_LEN,
  ROOT_RING_EPOCH,
  ROOT_RING_SLOT,
  ROOT_SNAPSHOT_LEN,
  SLOT_RING_LEN,
  SUBROOTS_PER_PAGE,
  SUBROOT_PAGE_LEN,
  SUBTREE_LEAVES,
  SUBTREE_PAGE_LEN,
  TAG_DEPOSIT,
  TAG_EXEC_VIA_ESCROW,
  TAG_INIT_LANE,
  TAG_INIT_POOL,
  TAG_INIT_ROOT_HISTORY,
  TAG_OPEN_PAGE,
  TAG_SET_PAUSED,
  TAG_TRANSACT,
  TAG_UPDATE_POOL,
  VK_ID_DEFAULT,
  WITHDRAW_FLAG_UNWRAP_WSOL,
  decodeEpochRingEntry,
  decodeGlobalRootHistory,
  decodeLaneHeader,
  decodePoolState,
  decodeSlotRingEntry,
  deterministicNoteRentFee,
  pickRandomEscrowShard,
  planAutoOpenPages,
  recommendedExecViaEscrowCuLimit,
  recommendedTransactCuLimit,
  selectRootSnapshotForNotes,
  type AutoOpenPageTarget,
  type DecodedGlobalRootHistory,
  type DecodedLaneHeader,
  type DecodedPoolState,
  type RootEntry,
  type RootSnapshotChoice,
}

// Canonical v1 instruction discriminator aliases (`0x00..=0x08`)
export const IX_TAG_INIT_POOL = TAG_INIT_POOL
export const IX_TAG_INIT_LANE = TAG_INIT_LANE
export const IX_TAG_OPEN_PAGE = TAG_OPEN_PAGE
export const IX_TAG_DEPOSIT = TAG_DEPOSIT
export const IX_TAG_INIT_ROOT_HISTORY = TAG_INIT_ROOT_HISTORY
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
export const deriveRootsPda = (poolId = 0, programId?: string | Uint8Array) =>
  toPdaBytes(deriveRootsPdaSync(poolId, programId))
export const deriveNullifierPda = (poolId: number, nf32: Uint8Array) =>
  toPdaBytes(deriveNullifierPdaSync(poolId, nf32))
export const deriveEscrowPda = (poolId: number, shardId: number) =>
  toPdaBytes(deriveEscrowPdaSync(poolId, shardId))
export const deriveUnwrapPda = (poolId: number, nf0: Uint8Array) =>
  toPdaBytes(deriveUnwrapPdaSync(poolId, nf0))

export interface DecodedGlobalRootHistoryHeader {
  version: number
  bump: number
  slotCursor: number
  poolId: number
  epochCursor: number
  slotCount: number
  epochCount: number
  sameSlotBumped: boolean
  latestSlot: bigint
  stableEpochId: bigint
  stableSlot: bigint
  epochInterval: bigint
}

const ASCII_DECODER = new TextDecoder('ascii')

/**
 * Decode the 64-byte header of a `GlobalRootHistory` (`AUD1RT01`, `10,216 B`) account
 * (works on both full account bytes and 64-byte `dataSlice` fetches).
 */
export function decodeGlobalRootHistoryHeader(data: Uint8Array): DecodedGlobalRootHistoryHeader {
  if (data.byteLength < 64 || ASCII_DECODER.decode(data.subarray(0, 8)) !== ROOTS_MAGIC) {
    throw new Error(`Invalid GlobalRootHistory header (len=${data.byteLength})`)
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const slotCursor = dv.getUint16(RT_OFF_SLOT_CURSOR, true)
  const epochCursor = dv.getUint16(RT_OFF_EPOCH_CURSOR, true)
  const slotCount = dv.getUint16(RT_OFF_SLOT_COUNT, true)
  const epochCount = dv.getUint16(RT_OFF_EPOCH_COUNT, true)
  const sameSlotBumpedRaw = data[RT_OFF_SAME_SLOT_BUMPED]!
  const epochInterval = dv.getBigUint64(RT_OFF_EPOCH_INTERVAL, true)
  if (
    slotCount < 1 ||
    slotCount > SLOT_RING_LEN ||
    slotCursor >= slotCount ||
    epochCount < 1 ||
    epochCount > EPOCH_RING_LEN ||
    epochCursor >= epochCount ||
    sameSlotBumpedRaw > 1 ||
    epochInterval < 1n ||
    epochInterval > MAX_ROOT_EPOCH_INTERVAL
  ) {
    throw new Error('Malformed GlobalRootHistory header counters')
  }
  return {
    version: data[RT_OFF_VERSION]!,
    bump: data[RT_OFF_BUMP]!,
    slotCursor,
    poolId: dv.getUint32(RT_OFF_POOL_ID, true),
    epochCursor,
    slotCount,
    epochCount,
    sameSlotBumped: sameSlotBumpedRaw !== 0,
    latestSlot: dv.getBigUint64(RT_OFF_LATEST_SLOT, true),
    stableEpochId: dv.getBigUint64(RT_OFF_STABLE_EPOCH_ID, true),
    stableSlot: dv.getBigUint64(RT_OFF_STABLE_SLOT, true),
    epochInterval,
  }
}

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

export const CLASSIC_SPL_ATA_LEN = 165
export const TOKEN_2022_BASE_ATA_LEN = 170

const TOKEN_2022_ACCOUNT_TYPE_OFFSET = 165
const TOKEN_2022_ACCOUNT_TYPE_MINT = 1
const TOKEN_2022_TLV_START = 166
const TOKEN_2022_EXT_TRANSFER_FEE_CONFIG = 1
const TOKEN_2022_EXT_DEFAULT_ACCOUNT_STATE = 6
const TOKEN_2022_EXT_NON_TRANSFERABLE = 9
const TOKEN_2022_EXT_TRANSFER_HOOK = 14
const TOKEN_2022_EXT_SCALED_UI_AMOUNT = 25
const TOKEN_2022_EXT_PAUSABLE = 26

export interface MintSafetyInfo {
  safeForSelfPay: boolean
  hasFreezeAuthority: boolean
  hasUntrustedFreezeAuthority: boolean
  hasPausableExt: boolean
  hasMutableTransferFeeAuthority: boolean
  hasUnsafeToken2022Ext: boolean
  /** True when a Token-2022 mint carries a valid `TransferFeeConfig` TLV extension (182 B+ ATAs). */
  hasTransferFeeConfigExt: boolean
  /** Expected byte length of canonical ATAs for this mint (`165 B` Classic SPL, `170 B+` Token-2022). */
  ataByteLen: number
  reason: string | null
}

/**
 * Compute the exact ATA account data length (in bytes) allocated by `spl-associated-token-account`
 * for a Classic SPL or Token-2022 mint:
 *   - Classic SPL: `165 B`
 *   - Token-2022 base (`Account` 165 B + `AccountType` 1 B + `ImmutableOwner` 4 B): `170 B`
 *   - Plus required per-account TLV extensions derived from mint TLV headers:
 *     - `TransferFeeConfig` (1) -> `TransferFeeAmount` (`4 + 8 = +12 B`)
 *     - `NonTransferable` (9)   -> `NonTransferableAccount` (`4 + 0 = +4 B`)
 *     - `TransferHook` (14)     -> `TransferHookAccount` (`4 + 1 = +5 B`)
 *     - `Pausable` (26)         -> `PausableAccount` (`4 + 0 = +4 B`)
 */
export function computeToken2022AtaByteLen(
  tokenProgram: string | null | undefined,
  mintBytes: Uint8Array | null | undefined,
): number {
  if (tokenProgram !== TOKEN_2022_PROGRAM_ID_STR) {
    return CLASSIC_SPL_ATA_LEN
  }
  if (
    !mintBytes ||
    mintBytes.byteLength <= TOKEN_2022_TLV_START ||
    mintBytes[TOKEN_2022_ACCOUNT_TYPE_OFFSET] !== TOKEN_2022_ACCOUNT_TYPE_MINT
  ) {
    return TOKEN_2022_BASE_ATA_LEN
  }
  let hasTransferFee = false
  let hasNonTransferable = false
  let hasTransferHook = false
  let hasPausable = false
  const dv = new DataView(mintBytes.buffer, mintBytes.byteOffset, mintBytes.byteLength)
  let pos = TOKEN_2022_TLV_START
  while (pos + 4 <= mintBytes.byteLength) {
    const extType = dv.getUint16(pos, true)
    if (extType === 0) break
    const extLen = dv.getUint16(pos + 2, true)
    const valStart = pos + 4
    const valEnd = valStart + extLen
    if (valEnd > mintBytes.byteLength) break
    if (extType === TOKEN_2022_EXT_TRANSFER_FEE_CONFIG && extLen >= 108) {
      hasTransferFee = true
    } else if (extType === TOKEN_2022_EXT_NON_TRANSFERABLE) {
      hasNonTransferable = true
    } else if (extType === TOKEN_2022_EXT_TRANSFER_HOOK && extLen >= 64) {
      hasTransferHook = true
    } else if (extType === TOKEN_2022_EXT_PAUSABLE) {
      hasPausable = true
    }
    pos = valEnd
  }
  return (
    TOKEN_2022_BASE_ATA_LEN +
    (hasTransferFee ? 12 : 0) +
    (hasNonTransferable ? 4 : 0) +
    (hasTransferHook ? 5 : 0) +
    (hasPausable ? 4 : 0)
  )
}

/**
 * Return `true` when raw mint bytes belong to a Token-2022 mint carrying a valid `TransferFeeConfig`
 * TLV extension (type `1`, >= 108 B), which causes `spl-associated-token-account` to allocate
 * `182 B` (`ImmutableOwner` + `TransferFeeAmount`) instead of `170 B` for every ATA of this mint.
 */
export function hasToken2022TransferFeeConfigExt(
  tokenProgram: string | null | undefined,
  mintBytes: Uint8Array | null | undefined,
): boolean {
  if (
    tokenProgram !== TOKEN_2022_PROGRAM_ID_STR ||
    !mintBytes ||
    mintBytes.byteLength <= TOKEN_2022_TLV_START ||
    mintBytes[TOKEN_2022_ACCOUNT_TYPE_OFFSET] !== TOKEN_2022_ACCOUNT_TYPE_MINT
  ) {
    return false
  }
  const dv = new DataView(mintBytes.buffer, mintBytes.byteOffset, mintBytes.byteLength)
  let pos = TOKEN_2022_TLV_START
  while (pos + 4 <= mintBytes.byteLength) {
    const extType = dv.getUint16(pos, true)
    if (extType === 0) break
    const extLen = dv.getUint16(pos + 2, true)
    const valStart = pos + 4
    const valEnd = valStart + extLen
    if (valEnd > mintBytes.byteLength) break
    if (extType === TOKEN_2022_EXT_TRANSFER_FEE_CONFIG && extLen >= 108) {
      return true
    }
    pos = valEnd
  }
  return false
}

/**
 * Inspect raw on-chain SPL / Token-2022 mint account bytes to verify whether a non-WSOL mint
 * is safe for relayer self-pay fee settlement:
 *   - Rejects untrusted `FreezeAuthority` (permits only known regulated stablecoins in
 *     `trustedFreezeMints`, defaulting to USDC / USDT / PYUSD / EURC).
 *   - Rejects Token-2022 `Pausable` extension (TLV type `26`).
 *   - Rejects Token-2022 `DefaultAccountState` extension (TLV type `6`) when `Frozen` (`2`) or truncated.
 *   - Rejects Token-2022 `TransferFeeConfig` (TLV type `1`) with a non-zero (mutable)
 *     `transfer_fee_config_authority`.
 *   - Rejects Token-2022 `PermanentDelegate`, `NonTransferable`, active `TransferHook`,
 *     `TransferFeeConfig > 500 bps`, or malformed TLV headers via `inspectToken2022UnsafeSelfPay`.
 */
export function parseMintSafetyInfo(
  mint: string,
  tokenProgram: string,
  mintBytes: Uint8Array | null | undefined,
  trustedFreezeMints: ReadonlySet<string> = TRUSTED_FREEZE_AUTHORITY_MINTS,
): MintSafetyInfo {
  if (mint === WSOL_MINT_STR) {
    return {
      safeForSelfPay: true,
      hasFreezeAuthority: false,
      hasUntrustedFreezeAuthority: false,
      hasPausableExt: false,
      hasMutableTransferFeeAuthority: false,
      hasUnsafeToken2022Ext: false,
      hasTransferFeeConfigExt: false,
      ataByteLen: CLASSIC_SPL_ATA_LEN,
      reason: null,
    }
  }
  const defaultAtaByteLen =
    tokenProgram === TOKEN_2022_PROGRAM_ID_STR ? TOKEN_2022_BASE_ATA_LEN : CLASSIC_SPL_ATA_LEN
  if (!isSupportedTokenProgram(tokenProgram) || !mintBytes || mintBytes.byteLength < 82 || mintBytes[45] !== 1) {
    return {
      safeForSelfPay: false,
      hasFreezeAuthority: false,
      hasUntrustedFreezeAuthority: false,
      hasPausableExt: false,
      hasMutableTransferFeeAuthority: false,
      hasUnsafeToken2022Ext: true,
      hasTransferFeeConfigExt: false,
      ataByteLen: defaultAtaByteLen,
      reason: 'Invalid or uninitialized mint account',
    }
  }
  if (tokenProgram === CLASSIC_TOKEN_PROGRAM_ID_STR && mintBytes.byteLength !== 82) {
    return {
      safeForSelfPay: false,
      hasFreezeAuthority: false,
      hasUntrustedFreezeAuthority: false,
      hasPausableExt: false,
      hasMutableTransferFeeAuthority: false,
      hasUnsafeToken2022Ext: true,
      hasTransferFeeConfigExt: false,
      ataByteLen: CLASSIC_SPL_ATA_LEN,
      reason: 'Invalid classic SPL mint account length',
    }
  }

  // SPL Mint COption<Pubkey> freeze_authority sits at bytes [46..50] (option tag) + [50..82] (pubkey)
  const freezeOpt = readU32le(mintBytes, 46)
  if (freezeOpt !== 0 && freezeOpt !== 1) {
    return {
      safeForSelfPay: false,
      hasFreezeAuthority: true,
      hasUntrustedFreezeAuthority: true,
      hasPausableExt: false,
      hasMutableTransferFeeAuthority: false,
      hasUnsafeToken2022Ext: true,
      hasTransferFeeConfigExt: false,
      ataByteLen: defaultAtaByteLen,
      reason: 'Malformed SPL freeze_authority option tag',
    }
  }
  const hasFreezeAuthority = freezeOpt === 1
  const hasUntrustedFreezeAuthority = hasFreezeAuthority && !trustedFreezeMints.has(mint)

  let hasPausableExt = false
  let hasMutableTransferFeeAuthority = false
  let hasUnsafeToken2022Ext = false
  let hasTransferFeeConfigExt = false

  if (tokenProgram === TOKEN_2022_PROGRAM_ID_STR && mintBytes.byteLength !== 82) {
    if (
      mintBytes.byteLength <= TOKEN_2022_ACCOUNT_TYPE_OFFSET ||
      mintBytes[TOKEN_2022_ACCOUNT_TYPE_OFFSET] !== TOKEN_2022_ACCOUNT_TYPE_MINT ||
      !mintBytes.subarray(82, TOKEN_2022_ACCOUNT_TYPE_OFFSET).every((b) => b === 0)
    ) {
      hasUnsafeToken2022Ext = true
    } else {
      hasUnsafeToken2022Ext = inspectToken2022UnsafeSelfPay(mintBytes)
      const dv = new DataView(mintBytes.buffer, mintBytes.byteOffset, mintBytes.byteLength)
      let pos = TOKEN_2022_TLV_START
      while (pos + 4 <= mintBytes.byteLength) {
        const extType = dv.getUint16(pos, true)
        if (extType === 0) break
        const extLen = dv.getUint16(pos + 2, true)
        const valStart = pos + 4
        const valEnd = valStart + extLen
        if (valEnd > mintBytes.byteLength) {
          hasUnsafeToken2022Ext = true
          break
        }
        if (extType === TOKEN_2022_EXT_PAUSABLE) {
          hasPausableExt = true
        } else if (extType === TOKEN_2022_EXT_DEFAULT_ACCOUNT_STATE) {
          if (extLen < 1 || mintBytes[valStart] === 2) {
            hasUnsafeToken2022Ext = true
          }
        } else if (extType === TOKEN_2022_EXT_SCALED_UI_AMOUNT) {
          hasUnsafeToken2022Ext = true
        } else if (extType === TOKEN_2022_EXT_TRANSFER_HOOK) {
          if (extLen < 64) {
            hasUnsafeToken2022Ext = true
          } else {
            // Bytes [0..32] = authority, [32..64] = program_id (reject if EITHER is non-zero)
            for (let i = 0; i < 64; i++) {
              if (mintBytes[valStart + i] !== 0) {
                hasUnsafeToken2022Ext = true
                break
              }
            }
          }
        } else if (extType === TOKEN_2022_EXT_TRANSFER_FEE_CONFIG) {
          if (extLen < 108) {
            hasUnsafeToken2022Ext = true
          } else {
            hasTransferFeeConfigExt = true
            // Bytes [0..32] of TransferFeeConfig = OptionalNonZeroPubkey transfer_fee_config_authority
            for (let i = 0; i < 32; i++) {
              if (mintBytes[valStart + i] !== 0) {
                hasMutableTransferFeeAuthority = true
                break
              }
            }
          }
        }
        pos = valEnd
      }
    }
  }

  let reason: string | null = null
  if (hasPausableExt) {
    reason = 'Token-2022 mint carries Pausable extension'
  } else if (hasMutableTransferFeeAuthority) {
    reason = 'Token-2022 mint carries mutable transfer_fee_config_authority'
  } else if (hasUntrustedFreezeAuthority) {
    reason = 'Mint carries untrusted FreezeAuthority'
  } else if (hasUnsafeToken2022Ext) {
    reason = 'Token-2022 mint carries extensions excluded from self-pay fee credit'
  }

  return {
    safeForSelfPay: reason === null,
    hasFreezeAuthority,
    hasUntrustedFreezeAuthority,
    hasPausableExt,
    hasMutableTransferFeeAuthority,
    hasUnsafeToken2022Ext,
    hasTransferFeeConfigExt,
    ataByteLen: computeToken2022AtaByteLen(tokenProgram, mintBytes),
    reason,
  }
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

export const OPEN_PAGE_BUMP_PADDING_THRESHOLD = 240
export const OPEN_PAGE_CU_PER_BUMP_RETRY = 1_500

/**
 * Compute bump-aware `OpenPage` (`Tag 2`) Compute Unit limit:
 *   - Keeps the calibrated tight `40_000` CU budget when `bump >= 240` (>99.99% of pages).
 *   - Adds `(240 - bump) * 1_500` CU when `bump < 240` so rare low-bump page PDAs (even `bump = 0`)
 *     never out-of-gas inside Solana's `sol_try_find_program_address` syscall (`1,500` CU/retry).
 */
export function computeOpenPageCuLimitForBump(bump: number): number {
  const clampedBump = Math.max(0, Math.min(255, Math.trunc(bump)))
  return (
    CU_LIMIT_OPEN_PAGE +
    (clampedBump < OPEN_PAGE_BUMP_PADDING_THRESHOLD
      ? (OPEN_PAGE_BUMP_PADDING_THRESHOLD - clampedBump) * OPEN_PAGE_CU_PER_BUMP_RETRY
      : 0)
  )
}

export function deriveOpenPageBumpFromIx(openIx: SolanaInstruction): number {
  if (openIx.data.length !== OPEN_PAGE_WIRE_LEN || openIx.data[0] !== TAG_OPEN_PAGE) {
    return 255
  }
  const pageKind = openIx.data[1]!
  const poolId = readU32le(openIx.data, 2)
  const laneId = openIx.data[6]!
  const pageSeq = readU64le(openIx.data, 7)
  if (pageKind === OPEN_PAGE_KIND_SUBTREE) {
    return deriveSubtreePda(poolId, laneId, pageSeq).bump
  }
  if (pageKind === OPEN_PAGE_KIND_SUBROOT) {
    return deriveSubrootPda(poolId, laneId, pageSeq).bump
  }
  if (pageKind === OPEN_PAGE_KIND_MEMO) {
    return deriveMemoPda(poolId, laneId, pageSeq).bump
  }
  if (pageKind === OPEN_PAGE_KIND_NULLIFIER) {
    return deriveNfPagePda(poolId, laneId, pageSeq).bump
  }
  return 255
}

export function computeOpenPageIxCuLimit(openIx: SolanaInstruction): number {
  return computeOpenPageCuLimitForBump(deriveOpenPageBumpFromIx(openIx))
}

export function buildOpenPageSolanaIx(params: {
  payer: string
  pageKind: number
  poolId: number
  laneId: number
  pageSeq: bigint
  maxPayerDeficit?: bigint
}): SolanaInstruction {
  return toSolanaInstruction(buildOpenPageInstruction(params))
}

function isValidRootRing(rootRingKind: number, rootRingIdx: number): boolean {
  if (rootRingKind === ROOT_RING_SLOT) {
    return rootRingIdx < SLOT_RING_LEN
  }
  if (rootRingKind === ROOT_RING_EPOCH) {
    return rootRingIdx < EPOCH_RING_LEN
  }
  return false
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
  rootRingKind: number
  rootRingIdx: number
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
  /** True when trailing accounts (e.g. Token-2022 TransferHook extra accounts) follow rollover accounts. */
  hasTrailingHookAccounts: boolean
  /** Optional `memo[2]` slice (106 B) corresponding to `cm2` when `(outputMask & 4) !== 0`. */
  cm2Memo: Uint8Array | null
}

/**
 * Parse Tag 5 (`Transact`) v1.3.0 wire payload & fixed/outflow/rollover account layout.
 * Wire (`380 + popcount(output_mask) * 106 B`):
 *   [0] tag(5), [1..5] pool_id, [5] vk_id, [6] out_lane_id, [7] output_mask,
 *   [8] asset_mode (0=PRIVATE, 1=PUBLIC), [9] flags (bits 0..2 rollover, bit 3 WITHDRAW_FLAG_UNWRAP_WSOL),
 *   [10] root_ring_kind (0=SLOT, 1=EPOCH), [11] root_ring_idx (<128 or <89),
 *   [12..204] proof(192), [204..236] nf0, [236..268] nf1,
 *   [268..300] cm0, [300..332] cm1, [332..364] cm2,
 *   [364..372] public_amount_out, [372..380] relayer_fee_amount, [380..] memos(popcount(output_mask)*106)
 */
export function parseTransactMeta(
  ixData: Uint8Array,
  accounts: SolanaAccountMeta[],
): ParsedTransactMeta | null {
  const FIXED_LEN = 380
  if (ixData.length < FIXED_LEN || ixData[0] !== TAG_TRANSACT || accounts.length < 12) return null
  const poolId = readU32le(ixData, 1)
  const vkId = ixData[5]!
  const outLaneId = ixData[6]!
  const outputMask = ixData[7]!
  const assetMode = ixData[8]!
  const flags = ixData[9]!
  const rootRingKind = ixData[10]!
  const rootRingIdx = ixData[11]!
  if (
    outLaneId >= NUM_LANES ||
    (outputMask & ~0x07) !== 0 ||
    (assetMode !== ASSET_MODE_PRIVATE && assetMode !== ASSET_MODE_PUBLIC) ||
    (flags & ~(0x07 | WITHDRAW_FLAG_UNWRAP_WSOL)) !== 0 ||
    !isValidRootRing(rootRingKind, rootRingIdx)
  ) {
    return null
  }
  const outputCount = popcount3(outputMask)
  if (ixData.length !== FIXED_LEN + outputCount * MEMO_ENTRY_WIRE_LEN) return null

  const unwrapWsol = (flags & WITHDRAW_FLAG_UNWRAP_WSOL) !== 0
  if (unwrapWsol && assetMode !== ASSET_MODE_PUBLIC) return null

  const nf0 = ixData.subarray(204, 236)
  const nf1 = ixData.subarray(236, 268)
  const cm0 = ixData.subarray(268, 300)
  const cm1 = ixData.subarray(300, 332)
  const cm2 = ixData.subarray(332, 364)
  const publicAmountOut = readU64le(ixData, 364)
  const relayerFee = readU64le(ixData, 372)

  if (unwrapWsol && publicAmountOut === 0n) return null
  if (assetMode === ASSET_MODE_PRIVATE && (publicAmountOut !== 0n || relayerFee !== 0n)) {
    return null
  }
  if (assetMode === ASSET_MODE_PUBLIC && publicAmountOut === 0n) return null

  if (isAllZero32(nf0)) return null
  if (!bytesEqual(accounts[1]!.pubkey, derivePoolPda(poolId).address)) return null
  if (!bytesEqual(accounts[2]!.pubkey, deriveRootsPda(poolId).address)) return null
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
    const off = FIXED_LEN + idx * MEMO_ENTRY_WIRE_LEN
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
  const hasTrailingHookAccounts = accounts.length > cursor

  return {
    poolId,
    vkId,
    outLaneId,
    outputMask,
    outputCount,
    assetMode,
    flags,
    rootRingKind,
    rootRingIdx,
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
    hasTrailingHookAccounts,
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
  rootRingKind: number
  rootRingIdx: number
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
 * Parse Tag 6 (`ExecViaEscrow`) v1.3.0 SPL / Token-2022 wire payload & account layout.
 * Wire (`560 + router_ix_len + popcount(change_mask) * 106 B`):
 *   [0] tag(6), [1..5] pool_id, [5] vk_id, [6] out_lane_id, [7] escrow_shard,
 *   [8] change_mask, [9] flags (bits 0..2 rollover, bit 3 EXEC_FLAG_FEE_ON_OUTPUT),
 *   [10] root_ring_kind (0=SLOT, 1=EPOCH), [11] root_ring_idx (<128 or <89),
 *   [12..204] proof(192), [204..236] nf0, [236..268] nf1,
 *   [268..300] cm0, [300..332] cm1, [332..364] cm2,
 *   [364..372] amount_in, [372..380] min_amount_out, [380..388] relayer_fee_amount,
 *   [388..420] out_stealth_owner, [420..452] out_blinding,
 *   [452..486] dyn_memo_head(34), [486..558] dyn_mask_72(72),
 *   [558..560] router_ix_len(u16 LE), [560..560+len] router_ix_data, [...] change_memos(106 B each)
 */
export function parseExecEscrowMeta(
  ixData: Uint8Array,
  accounts: SolanaAccountMeta[],
): ParsedExecEscrowMeta | null {
  const HEADER_LEN = 560
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
  const rootRingKind = ixData[10]!
  const rootRingIdx = ixData[11]!
  if (
    outLaneId >= NUM_LANES ||
    shardId >= NUM_ESCROW_SHARDS ||
    (changeMask & ~0x03) !== 0 ||
    (flags & ~(0x07 | EXEC_FLAG_FEE_ON_OUTPUT)) !== 0 ||
    !isValidRootRing(rootRingKind, rootRingIdx)
  ) {
    return null
  }
  const routerIxLen = readU16le(ixData, 558)
  const changeCount = (changeMask & 1) + ((changeMask >> 1) & 1)
  if (ixData.length !== HEADER_LEN + routerIxLen + changeCount * MEMO_ENTRY_WIRE_LEN) return null

  const nf0 = ixData.subarray(204, 236)
  const nf1 = ixData.subarray(236, 268)
  const outBlinding = ixData.subarray(420, 452)
  if (isAllZero32(nf0) || isAllZero32(outBlinding)) return null
  if (!bytesEqual(accounts[1]!.pubkey, derivePoolPda(poolId).address)) return null
  if (!bytesEqual(accounts[2]!.pubkey, deriveRootsPda(poolId).address)) return null
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
  const amountIn = readU64le(ixData, 364)
  const minAmountOut = readU64le(ixData, 372)
  const relayerFee = readU64le(ixData, 380)
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
    rootRingKind,
    rootRingIdx,
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
  /** Number of output notes appended by this instruction (used to gate premature `cur + 1` rollover opens). */
  outputCount?: number
  /** Number of nullifiers spent by this instruction (used to gate premature `cur + 1` rollover opens). */
  nullifierCount?: number
  /** Optional running `(nextLeaf, nfCount)` counters for sequential instructions in a batch. */
  laneCounters?: { nextLeaf: bigint; nfCount: bigint }
  /** Optional shared set of page PDAs already scheduled for `OpenPage` in an earlier batch entry. */
  alreadyScheduledPdas?: Set<string>
  /** Explicit on-chain payer deficit ceiling (`max_payer_deficit: u64`). Defaults to `u64::MAX`. */
  maxPayerDeficit?: bigint
}): MissingPagePlanResult {
  const {
    payerB58,
    poolId,
    outLaneId,
    laneAcc,
    pages,
    pageSlots,
    pageAccs,
    outputCount = 3,
    nullifierCount = 2,
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

    // Gate `cur + 1` rollover opens strictly to lanes genuinely within rollover distance
    // so an attacker setting `flags = 0x07` at leaf 0 / nf 0 can never trigger premature OpenPage rent drain.
    const clampedOut = Math.max(0, Math.min(3, Math.trunc(outputCount)))
    const clampedNf = Math.max(0, Math.min(2, Math.trunc(nullifierCount)))
    if (
      clampedOut === 0 &&
      (item.slot === 'outSub' ||
        item.slot === 'outRoot' ||
        item.slot === 'outMemo' ||
        item.slot === 'nextSub' ||
        item.slot === 'nextMemo')
    ) {
      // Full Exits (`outputCount === 0`) never append leaves or memos — skip all 5 note/memo page opens.
      continue
    }
    if (item.slot === 'nextSub' && expectedSeq > curSub) {
      const subSlot = Number(nextLeaf % BigInt(SUBTREE_LEAVES))
      if (subSlot + clampedOut < SUBTREE_LEAVES - 12) {
        return {
          ok: false,
          error: `Premature rollover OpenPage rejected for nextSub (lane ${outLaneId} leaf offset ${subSlot}/${SUBTREE_LEAVES})`,
        }
      }
    } else if (item.slot === 'nextMemo' && expectedSeq > curMemo) {
      const memoSlot = Number(nextLeaf % BigInt(MEMO_NOTES_PER_PAGE))
      if (memoSlot < Number(OPEN_PAGE_MEMO_LOOKAHEAD_SLOT)) {
        return {
          ok: false,
          error: `Premature rollover OpenPage rejected for nextMemo (lane ${outLaneId} memo offset ${memoSlot}/${MEMO_NOTES_PER_PAGE})`,
        }
      }
    } else if (item.slot === 'nextNf' && expectedSeq > curNf) {
      const nfSlot = Number(nfCount % BigInt(NF_PER_PAGE))
      if (nfSlot + clampedNf < NF_PER_PAGE - 8) {
        return {
          ok: false,
          error: `Premature rollover OpenPage rejected for nextNf (lane ${outLaneId} nf offset ${nfSlot}/${NF_PER_PAGE})`,
        }
      }
    } else if (pageKind === OPEN_PAGE_KIND_SUBROOT && expectedSeq > curRoot) {
      const subrootSlot = Number(curSub % BigInt(SUBROOTS_PER_PAGE))
      if (subrootSlot < 280) {
        return {
          ok: false,
          error: `Premature OpenPage rejected for outRoot (lane ${outLaneId} subroot slot ${subrootSlot}/${SUBROOTS_PER_PAGE})`,
        }
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
          maxPayerDeficit: params.maxPayerDeficit,
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
  maxPayerDeficit?: bigint
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
      outputCount: entry.outputCount,
      nullifierCount: entry.nullifierCount,
      laneCounters: counters,
      alreadyScheduledPdas,
      maxPayerDeficit: params.maxPayerDeficit,
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

export interface ProactiveLookaheadCandidate {
  poolId: number
  laneId: number
  pageKind: number
  pageSeq: bigint
  pda: string
  laneRentVaultPda: string
}

/**
 * Compute proactive `>= 90%` lane occupancy auto-`OpenPage` candidates
 * (`subRem <= 26`, `memoRem <= 10`, `nfRem <= 60`, `subrootSlot >= 280`) across every lane
 * touched by a submission, excluding PDAs already scheduled by exact rollover planning or
 * already observed initialized in `fetchedAccounts`.
 */
export function listProactiveLookaheadCandidates(params: {
  entries: Array<{
    poolId: number
    outLaneId: number
    outputCount: number
    nullifierCount: number
  }>
  fetchedAccounts: Map<string, FetchedAccountMeta | null>
  alreadyScheduledPdas: ReadonlySet<string>
}): ProactiveLookaheadCandidate[] {
  const { entries, fetchedAccounts, alreadyScheduledPdas } = params
  const totalsByLane = new Map<
    string,
    { poolId: number; laneId: number; numOutputs: number; numNfs: number }
  >()
  for (const entry of entries) {
    const key = `${entry.poolId}:${entry.outLaneId}`
    const prev = totalsByLane.get(key)
    if (prev) {
      prev.numOutputs += entry.outputCount
      prev.numNfs += entry.nullifierCount
    } else {
      totalsByLane.set(key, {
        poolId: entry.poolId,
        laneId: entry.outLaneId,
        numOutputs: entry.outputCount,
        numNfs: entry.nullifierCount,
      })
    }
  }

  const out: ProactiveLookaheadCandidate[] = []
  const seen = new Set<string>(alreadyScheduledPdas)

  for (const lane of totalsByLane.values()) {
    const lanePda = base58Encode(deriveLanePda(lane.poolId, lane.laneId).address)
    const laneAcc = fetchedAccounts.get(lanePda)
    if (!laneAcc || laneAcc.owner !== AUDREN_PROGRAM_ID_STR || laneAcc.bytes.length === 0) {
      continue
    }
    let hdr: DecodedLaneHeader
    try {
      hdr = decodeLaneHeader(laneAcc.bytes)
    } catch {
      continue
    }
    if (hdr.poolId !== lane.poolId || hdr.laneId !== lane.laneId) continue

    const targets = planAutoOpenPages({
      poolId: lane.poolId,
      laneId: lane.laneId,
      nextLeaf: hdr.nextLeaf,
      nfCount: hdr.nfCount,
      numOutputs: lane.numOutputs,
      numNfs: lane.numNfs,
      existingPages: seen,
    })
    const laneRentVaultPda = base58Encode(deriveLaneRentVaultPda(lane.poolId, lane.laneId).address)
    for (const target of targets) {
      if (seen.has(target.pda)) continue
      const existingAcc = fetchedAccounts.get(target.pda)
      if (isInitializedAudrenPage(existingAcc)) {
        seen.add(target.pda)
        continue
      }
      seen.add(target.pda)
      out.push({
        poolId: lane.poolId,
        laneId: lane.laneId,
        pageKind: target.pageKind,
        pageSeq: target.pageSeq,
        pda: target.pda,
        laneRentVaultPda,
      })
    }
  }

  return out
}
