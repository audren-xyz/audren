import {
  computeToken2022NetAmount,
  parseToken2022TransferFeeConfig,
} from '@audren/sdk'
import {
  CLASSIC_TOKEN_PROGRAM_ID_STR,
  TOKEN_2022_PROGRAM_ID_STR,
  base58Encode,
  fromBase64,
  isValidPubkey,
  readSplTokenAccountAmount,
  toBase64,
} from './codec'
import {
  CLASSIC_SPL_ATA_LEN,
  MEMO_NOTES_PER_PAGE,
  MEMO_PAGE_LEN,
  NF_PAGE_LEN,
  NF_PER_PAGE,
  SUBROOTS_PER_PAGE,
  SUBROOT_PAGE_LEN,
  SUBTREE_LEAVES,
  SUBTREE_PAGE_LEN,
  TOKEN_2022_BASE_ATA_LEN,
  computeToken2022AtaByteLen,
  decodePoolState,
  derivePoolPda,
  deterministicNoteRentFee,
  hasToken2022TransferFeeConfigExt,
  parseMintSafetyInfo,
  type MintSafetyInfo,
} from './audren'
import type { Cluster } from '../types'

export {
  CLASSIC_SPL_ATA_LEN,
  TOKEN_2022_BASE_ATA_LEN,
  computeToken2022AtaByteLen,
  hasToken2022TransferFeeConfigExt,
  parseMintSafetyInfo,
  type MintSafetyInfo,
}

// ============================================================================
// Solana JSON-RPC Client
// Zero hardcoded mint metadata or rent constants — everything fetched live.
// ============================================================================

export class SolanaRpcJsonError extends Error {
  readonly code?: number
  readonly data?: unknown

  constructor(message: string, code?: number, data?: unknown) {
    super(message)
    this.name = 'SolanaRpcJsonError'
    this.code = code
    this.data = data
  }
}

export async function rpcCall<T>(rpcUrl: string, method: string, params: unknown[]): Promise<T> {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    signal: AbortSignal.timeout(15_000),
  })
  if (!res.ok) {
    throw new Error(`Solana RPC HTTP ${res.status}`)
  }
  const body = (await res.json()) as {
    result?: T
    error?: { message?: string; code?: number; data?: unknown }
  }
  if (body.error) {
    const baseMsg = body.error.message ?? `Solana RPC error ${body.error.code ?? ''}`.trim()
    let dataSuffix = ''
    if (body.error.data !== undefined && body.error.data !== null) {
      try {
        const serialized =
          typeof body.error.data === 'string'
            ? body.error.data
            : JSON.stringify(body.error.data)
        if (serialized && serialized.length > 0 && serialized !== '{}') {
          dataSuffix = ` (${serialized.slice(0, 240)})`
        }
      } catch {
        // Ignore unserializable error data
      }
    }
    throw new SolanaRpcJsonError(`${baseMsg}${dataSuffix}`, body.error.code, body.error.data)
  }
  return body.result as T
}

export async function fetchBalance(rpcUrl: string, addressB58: string): Promise<number> {
  const res = await rpcCall<{ value: number }>(rpcUrl, 'getBalance', [
    addressB58,
    { commitment: 'confirmed' },
  ])
  return res.value
}

export async function fetchAccountBytes(
  rpcUrl: string,
  addressB58: string,
): Promise<{ bytes: Uint8Array; lamports: number; owner: string }> {
  const res = await rpcCall<{
    value: { data: [string, string]; lamports: number; owner: string } | null
  }>(rpcUrl, 'getAccountInfo', [addressB58, { encoding: 'base64', commitment: 'confirmed' }])
  if (!res.value) throw new Error(`Account ${addressB58} not found`)
  return {
    bytes: fromBase64(res.value.data[0]),
    lamports: res.value.lamports,
    owner: res.value.owner,
  }
}

export interface MultipleAccountsContextResult {
  slot: number | null
  accounts: Array<{ bytes: Uint8Array; lamports: number; owner: string } | null>
}

export async function fetchMultipleAccountsWithContext(
  rpcUrl: string,
  addresses: string[],
  opts?: { dataSlice?: { offset: number; length: number }; commitment?: 'processed' | 'confirmed' },
): Promise<MultipleAccountsContextResult> {
  if (addresses.length === 0) return { slot: null, accounts: [] }
  const out: Array<{ bytes: Uint8Array; lamports: number; owner: string } | null> = []
  let contextSlot: number | null = null
  let slotMismatch = false
  for (let offset = 0; offset < addresses.length; offset += 100) {
    const chunk = addresses.slice(offset, offset + 100)
    const res = await rpcCall<{
      context?: { slot?: number }
      value: Array<{ data: [string, string]; lamports: number; owner: string } | null>
    }>(rpcUrl, 'getMultipleAccounts', [
      chunk,
      {
        encoding: 'base64',
        commitment: opts?.commitment ?? 'confirmed',
        ...(opts?.dataSlice ? { dataSlice: opts.dataSlice } : {}),
      },
    ])
    const chunkSlot = typeof res.context?.slot === 'number' ? res.context.slot : null
    if (offset === 0) {
      contextSlot = chunkSlot
    } else if (chunkSlot !== contextSlot) {
      slotMismatch = true
    }
    for (const acc of res.value ?? []) {
      out.push(
        acc
          ? {
              bytes: fromBase64(acc.data[0]),
              lamports: acc.lamports,
              owner: acc.owner,
            }
          : null,
      )
    }
  }
  return { slot: slotMismatch ? null : contextSlot, accounts: out }
}

export async function fetchMultipleAccounts(
  rpcUrl: string,
  addresses: string[],
  opts?: { dataSlice?: { offset: number; length: number }; commitment?: 'processed' | 'confirmed' },
): Promise<Array<{ bytes: Uint8Array; lamports: number; owner: string } | null>> {
  const res = await fetchMultipleAccountsWithContext(rpcUrl, addresses, opts)
  return res.accounts
}

// ----------------------------------------------------------------------------
// Dynamic Mint Metadata (owner token program + decimals straight from chain)
// SPL Mint layout (Classic & Token-2022): byte 44 is immutable `decimals: u8`.
// ----------------------------------------------------------------------------

export interface OnChainMintMeta {
  mint: string
  tokenProgram: string
  decimals: number
  isValidMint: boolean
  /**
   * True when the mint is excluded from relayer self-pay fee credit (Pausable, DefaultAccountState=Frozen,
   * mutable TransferFeeConfig authority, untrusted FreezeAuthority, PermanentDelegate,
   * NonTransferable, active TransferHook, ScaledUiAmount, or TransferFeeConfig > 500 bps).
   */
  hasUnsafeSelfPayExt: boolean
  safety?: MintSafetyInfo
}

export interface OnChainMintMetaWithData {
  meta: OnChainMintMeta
  rawBytes: Uint8Array | null
}

export interface SwapInputTransferFeePlan {
  grossInputAmount: string
  netInputAmount: string
  inputTransferFeeBps: number
  inputTransferFeeAmount: string
  inputTransferFee: { bps: number; maxFee: string } | null
}

interface CachedMintEntry {
  meta: OnChainMintMeta
  rawBytes: Uint8Array | null
  fetchedAt: number
}

const MINT_META_CACHE = new Map<string, CachedMintEntry>()
const MINT_META_T22_TTL_MS = 60_000
export const MINT_META_CACHE_MAX_ENTRIES = 512

function setBoundedMintMetaCache(key: string, entry: CachedMintEntry, now: number): void {
  if (MINT_META_CACHE.has(key)) {
    MINT_META_CACHE.delete(key)
  }
  if (MINT_META_CACHE.size >= MINT_META_CACHE_MAX_ENTRIES) {
    for (const [k, v] of MINT_META_CACHE) {
      if (now - v.fetchedAt >= MINT_META_T22_TTL_MS) {
        MINT_META_CACHE.delete(k)
      }
    }
  }
  while (MINT_META_CACHE.size >= MINT_META_CACHE_MAX_ENTRIES) {
    const oldestKey = MINT_META_CACHE.keys().next().value
    if (oldestKey === undefined) break
    MINT_META_CACHE.delete(oldestKey)
  }
  MINT_META_CACHE.set(key, entry)
}

export function getMintMetaCacheSize(): number {
  return MINT_META_CACHE.size
}

const EPOCH_CACHE = new Map<string, { epoch: bigint; fetchedAt: number }>()
const EPOCH_CACHE_TTL_MS = 60_000

export async function fetchCurrentEpoch(rpcUrl: string): Promise<bigint> {
  const now = Date.now()
  const cached = EPOCH_CACHE.get(rpcUrl)
  if (cached && now - cached.fetchedAt < EPOCH_CACHE_TTL_MS) {
    return cached.epoch
  }
  const info = await rpcCall<{ epoch: number }>(rpcUrl, 'getEpochInfo', [{ commitment: 'confirmed' }])
  const epoch = BigInt(info.epoch)
  EPOCH_CACHE.set(rpcUrl, { epoch, fetchedAt: now })
  return epoch
}

/**
 * Pure helper computing the net balance arriving in `escrow_in_ata` when `ExecViaEscrow`
 * transfers `grossAmount` from `vault_in_ata` -> `escrow_in_ata` prior to the DEX router CPI.
 *
 * Classic SPL and WSOL mints are 100% unchanged (`netInputAmount === grossAmount`).
 * Token-2022 mints with an active `TransferFeeConfig` for `currentEpoch` deduct the exact
 * SPL Token-2022 ceiling transfer fee so DEX swap quotes never over-spend `escrow_in_ata`.
 */
export function computeSwapInputTransferFee(params: {
  tokenProgram: string
  mintData: Uint8Array | null | undefined
  currentEpoch: bigint | number
  grossAmount: bigint
}): SwapInputTransferFeePlan {
  const { tokenProgram, mintData, currentEpoch, grossAmount } = params
  if (tokenProgram !== TOKEN_2022_PROGRAM_ID_STR || !mintData || mintData.byteLength <= 166) {
    return {
      grossInputAmount: grossAmount.toString(),
      netInputAmount: grossAmount.toString(),
      inputTransferFeeBps: 0,
      inputTransferFeeAmount: '0',
      inputTransferFee: null,
    }
  }
  const activeFee = parseToken2022TransferFeeConfig(mintData, currentEpoch)
  if (!activeFee || activeFee.bps <= 0n) {
    return {
      grossInputAmount: grossAmount.toString(),
      netInputAmount: grossAmount.toString(),
      inputTransferFeeBps: 0,
      inputTransferFeeAmount: '0',
      inputTransferFee: null,
    }
  }
  const net = computeToken2022NetAmount(grossAmount, activeFee)
  const deducted = grossAmount > net ? grossAmount - net : 0n
  return {
    grossInputAmount: grossAmount.toString(),
    netInputAmount: net.toString(),
    inputTransferFeeBps: Number(activeFee.bps),
    inputTransferFeeAmount: deducted.toString(),
    inputTransferFee: {
      bps: Number(activeFee.bps),
      maxFee: activeFee.maxFee.toString(),
    },
  }
}

/**
 * Apply an active Token-2022 `TransferFeeConfig` haircut when valuing non-WSOL Token-2022
 * relayer fee receipts at submit time:
 *   - `hops = 2` (default, Mode 1 shielded `cm2`): gross pre-receipt note amount pays both
 *     receipt (withdrawal) and liquidation/swap transfer hops.
 *   - `hops = 1` (Mode 2 / Mode 3 simulated ATA delta): `simulatedFeeUnits = post - pre` is
 *     already net of `1x` on-chain receipt fee, so only `1x` liquidation hop remains.
 * Classic SPL mints pass through unchanged.
 */
export function applyToken2022FeeHaircut(params: {
  tokenProgram: string
  mintData: Uint8Array | null | undefined
  currentEpoch: bigint | number
  grossAmount: bigint
  /** Number of Token-2022 transfer hops to deduct (`2` default for Mode 1, `1` for Mode 2/3). */
  hops?: 1 | 2
}): { netAmount: bigint; activeTransferFeeBps: number; haircutAmount: bigint } {
  const { tokenProgram, mintData, currentEpoch, grossAmount, hops = 2 } = params
  if (
    tokenProgram !== TOKEN_2022_PROGRAM_ID_STR ||
    !mintData ||
    mintData.byteLength <= 166 ||
    grossAmount <= 0n
  ) {
    return { netAmount: grossAmount > 0n ? grossAmount : 0n, activeTransferFeeBps: 0, haircutAmount: 0n }
  }
  const activeFee = parseToken2022TransferFeeConfig(mintData, currentEpoch)
  if (!activeFee || activeFee.bps <= 0n) {
    return { netAmount: grossAmount, activeTransferFeeBps: 0, haircutAmount: 0n }
  }
  const afterOne = computeToken2022NetAmount(grossAmount, activeFee)
  const singleFee = grossAmount > afterOne ? grossAmount - afterOne : 0n
  const totalFee = hops === 1 ? singleFee : singleFee * 2n
  const netAmount = grossAmount > totalFee ? grossAmount - totalFee : 0n
  return {
    netAmount,
    activeTransferFeeBps: Number(activeFee.bps),
    haircutAmount: grossAmount - netAmount,
  }
}

export async function resolveSwapInputTransferFee(
  rpcUrl: string,
  inMeta: OnChainMintMeta,
  inRawBytes: Uint8Array | null,
  grossAmount: bigint,
): Promise<SwapInputTransferFeePlan> {
  if (
    inMeta.tokenProgram !== TOKEN_2022_PROGRAM_ID_STR ||
    !inRawBytes ||
    inRawBytes.byteLength <= 166
  ) {
    return {
      grossInputAmount: grossAmount.toString(),
      netInputAmount: grossAmount.toString(),
      inputTransferFeeBps: 0,
      inputTransferFeeAmount: '0',
      inputTransferFee: null,
    }
  }
  const currentEpoch = await fetchCurrentEpoch(rpcUrl)
  return computeSwapInputTransferFee({
    tokenProgram: inMeta.tokenProgram,
    mintData: inRawBytes,
    currentEpoch,
    grossAmount,
  })
}

export async function fetchMintMetasWithData(
  rpcUrl: string,
  mints: string[],
): Promise<Record<string, OnChainMintMetaWithData>> {
  const now = Date.now()
  const out: Record<string, OnChainMintMetaWithData> = {}
  const missing: string[] = []
  for (const m of mints) {
    const cacheKey = `${rpcUrl}:${m}`
    const cached = MINT_META_CACHE.get(cacheKey)
    const fresh = cached && now - cached.fetchedAt < MINT_META_T22_TTL_MS
    if (fresh) {
      out[m] = { meta: cached.meta, rawBytes: cached.rawBytes }
    } else {
      if (cached) MINT_META_CACHE.delete(cacheKey)
      if (!missing.includes(m)) {
        missing.push(m)
      }
    }
  }

  if (missing.length > 0) {
    const infos = await fetchMultipleAccounts(rpcUrl, missing)
    missing.forEach((mint, idx) => {
      const info = infos[idx]
      const isClassic = info?.owner === CLASSIC_TOKEN_PROGRAM_ID_STR
      const isT22 = info?.owner === TOKEN_2022_PROGRAM_ID_STR
      const bytes = info?.bytes ?? null
      const isValidClassicMint = Boolean(isClassic && bytes && bytes.length === 82 && bytes[45] === 1)
      const isValidT22Mint = Boolean(
        isT22 &&
          bytes &&
          bytes.length >= 82 &&
          bytes[45] === 1 &&
          (bytes.length === 82 ||
            (bytes.length > 165 &&
              bytes[165] === 1 &&
              bytes.subarray(82, 165).every((b) => b === 0))),
      )
      const isValidMint = isValidClassicMint || isValidT22Mint
      const tokenProgram = isT22 ? TOKEN_2022_PROGRAM_ID_STR : CLASSIC_TOKEN_PROGRAM_ID_STR
      const decimals = isValidMint ? bytes![44]! : 0
      const safety = isValidMint
        ? parseMintSafetyInfo(mint, tokenProgram, bytes)
        : {
            safeForSelfPay: false,
            hasFreezeAuthority: false,
            hasUntrustedFreezeAuthority: false,
            hasPausableExt: false,
            hasMutableTransferFeeAuthority: false,
            hasUnsafeToken2022Ext: true,
            hasTransferFeeConfigExt: false,
            ataByteLen: isT22 ? TOKEN_2022_BASE_ATA_LEN : CLASSIC_SPL_ATA_LEN,
            reason: 'Invalid or uninitialized mint account',
          }
      const hasUnsafeSelfPayExt = !safety.safeForSelfPay
      const meta: OnChainMintMeta = {
        mint,
        tokenProgram,
        decimals,
        isValidMint,
        hasUnsafeSelfPayExt,
        safety,
      }
      const rawBytes = isValidMint ? bytes : null
      if (isValidMint) {
        setBoundedMintMetaCache(`${rpcUrl}:${mint}`, { meta, rawBytes, fetchedAt: now }, now)
      }
      out[mint] = { meta, rawBytes }
    })
  }
  return out
}

export async function fetchMintMetas(
  rpcUrl: string,
  mints: string[],
): Promise<Record<string, OnChainMintMeta>> {
  const detailed = await fetchMintMetasWithData(rpcUrl, mints)
  const out: Record<string, OnChainMintMeta> = {}
  for (const [k, v] of Object.entries(detailed)) {
    out[k] = v.meta
  }
  return out
}

// ----------------------------------------------------------------------------
// Live On-Chain Rent Schedule (Zero hardcoded SOL / lamport rent numbers!)
// ----------------------------------------------------------------------------

export interface LiveRentSchedule {
  nullifierRentLamports: bigint
  /** Minimum rent-exempt reserve for 16-byte `LaneRentVault` sentinel PDA (`SENTINEL_LEN = 16`). */
  laneRentVaultReserveLamports?: bigint
  nfPageRentPerNfLamports: bigint
  pageRentPerNoteLamports: bigint
  ataRentLamports: bigint
  baseTxFeeLamports: bigint
  /** Full rent-exemption lamports for each Audren on-chain page type (populated by live RPC fetch). */
  subtreePageRentLamports?: bigint
  subrootPageRentLamports?: bigint
  memoPageRentLamports?: bigint
  nfPageRentLamports?: bigint
  /** Total baseline cost for a default 2-nullifier, 2-output-note swap tx (including base/priority fee buffer). */
  swapBaselineLamports: bigint
  fetchedAt: number
}

const RENT_CACHE = new Map<string, LiveRentSchedule>()
const RENT_CACHE_TTL_MS = 300_000

export function getCachedLiveRentSchedule(rpcUrl: string): LiveRentSchedule | null {
  const cached = RENT_CACHE.get(rpcUrl)
  if (!cached) return null
  return Date.now() - cached.fetchedAt < RENT_CACHE_TTL_MS ? cached : null
}

export function clearLiveRentScheduleCache(): void {
  RENT_CACHE.clear()
}

const NULLIFIER_ACCOUNT_LEN = 0 // On-chain claim_nullifier creates a 0-byte sentinel PDA
const SENTINEL_LEN = 16 // On-chain LaneRentVault 16-byte sentinel account reserve
const SPL_TOKEN_ACCOUNT_LEN = 165

export async function fetchLiveRentSchedule(rpcUrl: string): Promise<LiveRentSchedule> {
  const now = Date.now()
  const cached = RENT_CACHE.get(rpcUrl)
  if (cached && now - cached.fetchedAt < RENT_CACHE_TTL_MS) {
    return cached
  }

  const poolPdaB58 = base58Encode(derivePoolPda(0).address)
  const [nullifierRent, sentinelRent, subRent, srRent, memoRent, nfRent, ataRent, poolAcc] =
    await Promise.all([
      rpcCall<number>(rpcUrl, 'getMinimumBalanceForRentExemption', [NULLIFIER_ACCOUNT_LEN]),
      rpcCall<number>(rpcUrl, 'getMinimumBalanceForRentExemption', [SENTINEL_LEN]),
      rpcCall<number>(rpcUrl, 'getMinimumBalanceForRentExemption', [SUBTREE_PAGE_LEN]),
      rpcCall<number>(rpcUrl, 'getMinimumBalanceForRentExemption', [SUBROOT_PAGE_LEN]),
      rpcCall<number>(rpcUrl, 'getMinimumBalanceForRentExemption', [MEMO_PAGE_LEN]),
      rpcCall<number>(rpcUrl, 'getMinimumBalanceForRentExemption', [NF_PAGE_LEN]),
      rpcCall<number>(rpcUrl, 'getMinimumBalanceForRentExemption', [SPL_TOKEN_ACCOUNT_LEN]),
      fetchAccountBytes(rpcUrl, poolPdaB58).catch(() => null),
    ])

  const clampMin1 = (x: bigint) => (x > 0n ? x : 1n)
  const nullifierLamports = clampMin1(BigInt(nullifierRent))
  const sentinelLamports = clampMin1(BigInt(sentinelRent))
  const ataLamports = BigInt(ataRent)
  const divCeil = (a: bigint, b: bigint) => (a + b - 1n) / b
  const subRentBig = clampMin1(BigInt(subRent))
  const srRentBig = clampMin1(BigInt(srRent))
  const memoRentBig = clampMin1(BigInt(memoRent))
  const nfRentBig = clampMin1(BigInt(nfRent))
  const livePerNote =
    divCeil(subRentBig, BigInt(SUBTREE_LEAVES)) +
    divCeil(srRentBig, BigInt(SUBTREE_LEAVES * SUBROOTS_PER_PAGE)) +
    divCeil(memoRentBig, BigInt(MEMO_NOTES_PER_PAGE))
  const livePerNf = divCeil(nfRentBig, BigInt(NF_PER_PAGE))
  const decodedPool = poolAcc ? decodePoolState(poolAcc.bytes) : null
  const pageRentPerNoteLamports = decodedPool
    ? decodedPool.noteRentFee > 0n
      ? deterministicNoteRentFee(decodedPool.noteRentFee, subRentBig, srRentBig, memoRentBig)
      : 0n
    : livePerNote
  const poolNfFee = decodedPool ? decodedPool.nfRentFee : livePerNf
  const nfPageRentPerNfLamports = poolNfFee < livePerNf ? poolNfFee : livePerNf
  const baseTxFeeLamports = 5_000n

  const schedule: LiveRentSchedule = {
    nullifierRentLamports: nullifierLamports,
    laneRentVaultReserveLamports: sentinelLamports,
    nfPageRentPerNfLamports,
    pageRentPerNoteLamports,
    ataRentLamports: ataLamports,
    baseTxFeeLamports,
    subtreePageRentLamports: subRentBig,
    subrootPageRentLamports: srRentBig,
    memoPageRentLamports: memoRentBig,
    nfPageRentLamports: nfRentBig,
    swapBaselineLamports:
      2n * (nullifierLamports + nfPageRentPerNfLamports) +
      2n * pageRentPerNoteLamports +
      20_000n,
    fetchedAt: now,
  }
  RENT_CACHE.set(rpcUrl, schedule)
  return schedule
}

// ----------------------------------------------------------------------------
// Dynamic Discovery of ALL Relayer SPL + Token-2022 Token Accounts (Zero hardcoding!)
// ----------------------------------------------------------------------------

export interface OwnedTokenAccount {
  ata: string
  mint: string
  tokenProgram: string
  amount: bigint
}

export async function fetchAllOwnedTokenAccounts(
  rpcUrl: string,
  ownerB58: string,
): Promise<OwnedTokenAccount[]> {
  type RawResp = {
    value: Array<{
      pubkey: string
      account: { data: [string, string]; owner: string }
    }>
  }

  const [classicRes, t22Res] = await Promise.all([
    rpcCall<RawResp>(rpcUrl, 'getTokenAccountsByOwner', [
      ownerB58,
      { programId: CLASSIC_TOKEN_PROGRAM_ID_STR },
      { encoding: 'base64', commitment: 'confirmed' },
    ]),
    rpcCall<RawResp>(rpcUrl, 'getTokenAccountsByOwner', [
      ownerB58,
      { programId: TOKEN_2022_PROGRAM_ID_STR },
      { encoding: 'base64', commitment: 'confirmed' },
    ]),
  ])

  const out: OwnedTokenAccount[] = []
  for (const item of [...(classicRes.value ?? []), ...(t22Res.value ?? [])]) {
    const bytes = fromBase64(item.account.data[0])
    if (bytes.length < 72) continue
    const mint = base58Encode(bytes.subarray(0, 32))
    const amount = readSplTokenAccountAmount(bytes)
    out.push({
      ata: item.pubkey,
      mint,
      tokenProgram: item.account.owner,
      amount,
    })
  }
  return out
}

export const ADDRESS_LOOKUP_TABLE_PROGRAM_ID_STR = 'AddressLookupTab1e1111111111111111111111111'
export const MAX_ALT_RESOLVE_COUNT = 8
export const ALT_HEADER_LEN = 56
export const ALT_MAX_ADDRESSES = 256
export const ALT_MAX_DATA_LEN = ALT_HEADER_LEN + ALT_MAX_ADDRESSES * 32

export async function resolveLookupTables(
  rpcUrl: string | null,
  altAddresses: string[],
): Promise<Record<string, string[]>> {
  const lookupTables: Record<string, string[]> = {}
  if (!rpcUrl || !Array.isArray(altAddresses) || altAddresses.length === 0) return lookupTables
  const validCapped: string[] = []
  const seen = new Set<string>()
  for (const raw of altAddresses) {
    if (typeof raw !== 'string') continue
    const addr = raw.trim()
    if (!isValidPubkey(addr) || seen.has(addr)) continue
    seen.add(addr)
    validCapped.push(addr)
    if (validCapped.length >= MAX_ALT_RESOLVE_COUNT) break
  }
  if (validCapped.length === 0) return lookupTables
  const infos = await fetchMultipleAccounts(rpcUrl, validCapped, {
    dataSlice: { offset: 0, length: ALT_MAX_DATA_LEN + 1 },
  })
  validCapped.forEach((altAddr, idx) => {
    const info = infos[idx]
    if (
      !info ||
      info.owner !== ADDRESS_LOOKUP_TABLE_PROGRAM_ID_STR ||
      info.bytes.length < ALT_HEADER_LEN ||
      info.bytes.length > ALT_MAX_DATA_LEN ||
      (info.bytes.length - ALT_HEADER_LEN) % 32 !== 0
    ) {
      return
    }
    const addrs: string[] = []
    for (let off = ALT_HEADER_LEN; off + 32 <= info.bytes.length; off += 32) {
      addrs.push(base58Encode(info.bytes.subarray(off, off + 32)))
    }
    if (addrs.length > 0) lookupTables[altAddr] = addrs
  })
  return lookupTables
}

export interface SimulationAccountPost {
  lamports: number
  owner: string
  bytes: Uint8Array
}

export interface SimulationResult {
  slot: number | null
  err: unknown | null
  logs: string[]
  unitsConsumed: number
  accounts: Array<SimulationAccountPost | null>
}

export async function simulateV1Transaction(
  rpcUrl: string,
  wireBytes: Uint8Array,
  watchAddresses: string[],
  opts?: { commitment?: 'processed' | 'confirmed' },
): Promise<SimulationResult> {
  const res = await rpcCall<{
    context?: { slot?: number }
    value: {
      err: unknown | null
      logs?: string[] | null
      unitsConsumed?: number | null
      accounts?: Array<{
        lamports: number
        owner: string
        data: [string, string]
      } | null> | null
    }
  }>(rpcUrl, 'simulateTransaction', [
    toBase64(wireBytes),
    {
      encoding: 'base64',
      sigVerify: false,
      replaceRecentBlockhash: true,
      commitment: opts?.commitment ?? 'confirmed',
      ...(watchAddresses.length > 0
        ? { accounts: { encoding: 'base64', addresses: watchAddresses } }
        : {}),
    },
  ])

  const val = res.value
  return {
    slot: typeof res.context?.slot === 'number' ? res.context.slot : null,
    err: val.err ?? null,
    logs: val.logs ?? [],
    unitsConsumed: val.unitsConsumed ?? 0,
    accounts: (val.accounts ?? []).map((a) =>
      a
        ? {
            lamports: a.lamports,
            owner: a.owner,
            bytes: fromBase64(a.data[0]),
          }
        : null,
    ),
  }
}

export class TransactionFailedOnChainError extends Error {
  readonly signature: string
  readonly err: unknown
  readonly slot: number

  constructor(signature: string, err: unknown, slot: number) {
    super(`Transaction failed on-chain: ${JSON.stringify(err)}`)
    this.name = 'TransactionFailedOnChainError'
    this.signature = signature
    this.err = err
    this.slot = slot
  }
}

export async function waitForConfirmation(
  rpcUrl: string,
  signature: string,
  maxWaitMs = 30_000,
): Promise<{ slot: number }> {
  const deadline = Date.now() + Math.max(1_000, maxWaitMs)
  for (let attempt = 0; attempt < 36; attempt++) {
    const res = await rpcCall<{
      value: Array<{
        slot: number
        err: unknown
        confirmationStatus?: string
      } | null>
    }>(rpcUrl, 'getSignatureStatuses', [[signature], { searchTransactionHistory: true }])

    const status = res.value[0]
    if (status) {
      if (status.err !== null && status.err !== undefined) {
        throw new TransactionFailedOnChainError(signature, status.err, status.slot)
      }
      if (status.confirmationStatus === 'confirmed' || status.confirmationStatus === 'finalized') {
        return { slot: status.slot }
      }
    }
    const remaining = deadline - Date.now()
    if (remaining <= 0) break
    await new Promise((r) => setTimeout(r, Math.min(700, remaining)))
  }
  throw new Error('Timed out waiting for confirmation')
}

export async function resolveVaultOutDelta(
  rpcUrl: string,
  signature: string,
  vaultOutAta: string,
): Promise<string | null> {
  type TokenBal = { accountIndex: number; uiTokenAmount?: { amount?: string } }
  type TxResp = {
    transaction?: { message?: { accountKeys?: Array<string | { pubkey: string }> } }
    meta?: {
      preTokenBalances?: TokenBal[]
      postTokenBalances?: TokenBal[]
      loadedAddresses?: { writable?: string[]; readonly?: string[] }
    }
  } | null

  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      const tx = await rpcCall<TxResp>(rpcUrl, 'getTransaction', [
        signature,
        { encoding: 'jsonParsed', commitment: 'confirmed', maxSupportedTransactionVersion: 1 },
      ])
      if (tx?.meta && tx.transaction?.message?.accountKeys) {
        const staticKeys = tx.transaction.message.accountKeys.map((k) =>
          typeof k === 'string' ? k : k.pubkey,
        )
        const allKeys = [
          ...staticKeys,
          ...(tx.meta.loadedAddresses?.writable ?? []),
          ...(tx.meta.loadedAddresses?.readonly ?? []),
        ]
        const idx = allKeys.indexOf(vaultOutAta)
        if (idx >= 0) {
          const pre = BigInt(
            tx.meta.preTokenBalances?.find((b) => b.accountIndex === idx)?.uiTokenAmount?.amount ?? '0',
          )
          const post = BigInt(
            tx.meta.postTokenBalances?.find((b) => b.accountIndex === idx)?.uiTokenAmount?.amount ?? '0',
          )
          if (post > pre) return (post - pre).toString()
        }
      }
    } catch {
      // retry once RPC indexes the tx
    }
    await new Promise((r) => setTimeout(r, 400))
  }
  return null
}

export function solscanTxUrl(signature: string, cluster: Cluster): string {
  return cluster === 'mainnet'
    ? `https://solscan.io/tx/${signature}`
    : `https://solscan.io/tx/${signature}?cluster=devnet`
}

export function explorerTxUrl(signature: string, cluster: Cluster): string {
  return cluster === 'mainnet'
    ? `https://explorer.solana.com/tx/${signature}`
    : `https://explorer.solana.com/tx/${signature}?cluster=devnet`
}
