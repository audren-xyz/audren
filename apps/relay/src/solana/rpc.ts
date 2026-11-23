import {
  computeToken2022NetAmount,
  inspectToken2022UnsafeSelfPay,
  parseToken2022TransferFeeConfig,
} from '@audren/sdk'
import {
  CLASSIC_TOKEN_PROGRAM_ID_STR,
  TOKEN_2022_PROGRAM_ID_STR,
  base58Encode,
  fromBase64,
  readSplTokenAccountAmount,
  toBase64,
} from './codec'
import { decodePoolState, derivePoolPda } from './audren'
import type { Cluster } from '../types'

// ============================================================================
// Solana JSON-RPC Client
// Zero hardcoded mint metadata or rent constants — everything fetched live.
// ============================================================================

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
  const body = (await res.json()) as { result?: T; error?: { message?: string; code?: number } }
  if (body.error) {
    throw new Error(body.error.message ?? `Solana RPC error ${body.error.code ?? ''}`)
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

export async function fetchMultipleAccounts(
  rpcUrl: string,
  addresses: string[],
  opts?: { dataSlice?: { offset: number; length: number } },
): Promise<Array<{ bytes: Uint8Array; lamports: number; owner: string } | null>> {
  if (addresses.length === 0) return []
  const out: Array<{ bytes: Uint8Array; lamports: number; owner: string } | null> = []
  for (let offset = 0; offset < addresses.length; offset += 100) {
    const chunk = addresses.slice(offset, offset + 100)
    const res = await rpcCall<{
      value: Array<{ data: [string, string]; lamports: number; owner: string } | null>
    }>(rpcUrl, 'getMultipleAccounts', [
      chunk,
      {
        encoding: 'base64',
        commitment: 'confirmed',
        ...(opts?.dataSlice ? { dataSlice: opts.dataSlice } : {}),
      },
    ])
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
  return out
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
  /** True for Token-2022 mints with extensions unsafe for relayer self-pay credit (PermanentDelegate, NonTransferable, active TransferHook, or high TransferFee). */
  hasUnsafeSelfPayExt: boolean
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
}

interface CachedMintEntry {
  meta: OnChainMintMeta
  rawBytes: Uint8Array | null
  fetchedAt: number
}

const MINT_META_CACHE = new Map<string, CachedMintEntry>()
const MINT_META_T22_TTL_MS = 60_000

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
    }
  }
  const activeFee = parseToken2022TransferFeeConfig(mintData, currentEpoch)
  if (!activeFee || activeFee.bps <= 0n) {
    return {
      grossInputAmount: grossAmount.toString(),
      netInputAmount: grossAmount.toString(),
      inputTransferFeeBps: 0,
      inputTransferFeeAmount: '0',
    }
  }
  const net = computeToken2022NetAmount(grossAmount, activeFee)
  const deducted = grossAmount > net ? grossAmount - net : 0n
  return {
    grossInputAmount: grossAmount.toString(),
    netInputAmount: net.toString(),
    inputTransferFeeBps: Number(activeFee.bps),
    inputTransferFeeAmount: deducted.toString(),
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
    const cached = MINT_META_CACHE.get(`${rpcUrl}:${m}`)
    const isT22 = cached?.meta.tokenProgram === TOKEN_2022_PROGRAM_ID_STR
    const fresh = cached && (!isT22 || now - cached.fetchedAt < MINT_META_T22_TTL_MS)
    if (fresh) {
      out[m] = { meta: cached.meta, rawBytes: cached.rawBytes }
    } else if (!missing.includes(m)) {
      missing.push(m)
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
      const hasUnsafeSelfPayExt = Boolean(
        isValidT22Mint && bytes && inspectToken2022UnsafeSelfPay(bytes),
      )
      const meta: OnChainMintMeta = { mint, tokenProgram, decimals, isValidMint, hasUnsafeSelfPayExt }
      const rawBytes = isValidT22Mint ? bytes : null
      if (isValidMint) {
        MINT_META_CACHE.set(`${rpcUrl}:${mint}`, { meta, rawBytes, fetchedAt: now })
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
  pageRentPerNoteLamports: bigint
  ataRentLamports: bigint
  baseTxFeeLamports: bigint
  /** Total baseline cost for a 1-nullifier, 1-output-note swap tx (before priority fee). */
  swapBaselineLamports: bigint
  fetchedAt: number
}

const RENT_CACHE = new Map<string, LiveRentSchedule>()
const RENT_CACHE_TTL_MS = 300_000

const NULLIFIER_ACCOUNT_LEN = 0 // On-chain claim_nullifier creates a 0-byte sentinel PDA
const SUBTREE_PAGE_LEN = 8_256
const SUBROOT_PAGE_LEN = 9_664
const MEMO_PAGE_LEN = 10_144
const SPL_TOKEN_ACCOUNT_LEN = 165

export async function fetchLiveRentSchedule(rpcUrl: string): Promise<LiveRentSchedule> {
  const now = Date.now()
  const cached = RENT_CACHE.get(rpcUrl)
  if (cached && now - cached.fetchedAt < RENT_CACHE_TTL_MS) {
    return cached
  }

  const poolPdaB58 = base58Encode(derivePoolPda(0).address)
  const [nullifierRent, subRent, srRent, memoRent, ataRent, poolAcc] = await Promise.all([
    rpcCall<number>(rpcUrl, 'getMinimumBalanceForRentExemption', [NULLIFIER_ACCOUNT_LEN]),
    rpcCall<number>(rpcUrl, 'getMinimumBalanceForRentExemption', [SUBTREE_PAGE_LEN]),
    rpcCall<number>(rpcUrl, 'getMinimumBalanceForRentExemption', [SUBROOT_PAGE_LEN]),
    rpcCall<number>(rpcUrl, 'getMinimumBalanceForRentExemption', [MEMO_PAGE_LEN]),
    rpcCall<number>(rpcUrl, 'getMinimumBalanceForRentExemption', [SPL_TOKEN_ACCOUNT_LEN]),
    fetchAccountBytes(rpcUrl, poolPdaB58).catch(() => null),
  ])

  const nullifierLamports = BigInt(nullifierRent)
  const ataLamports = BigInt(ataRent)
  const divCeil = (a: bigint, b: bigint) => (a + b - 1n) / b
  const livePerNote =
    divCeil(BigInt(subRent), 256n) +
    divCeil(BigInt(srRent), 256n * 300n) +
    divCeil(BigInt(memoRent), 112n)
  const poolConfigured = poolAcc ? decodePoolState(poolAcc.bytes).noteRentFee : livePerNote
  const pageRentPerNoteLamports =
    poolConfigured > 0n && poolConfigured < livePerNote ? poolConfigured : livePerNote
  const baseTxFeeLamports = 5_000n

  const schedule: LiveRentSchedule = {
    nullifierRentLamports: nullifierLamports,
    pageRentPerNoteLamports,
    ataRentLamports: ataLamports,
    baseTxFeeLamports,
    swapBaselineLamports: nullifierLamports + pageRentPerNoteLamports + baseTxFeeLamports,
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

export async function resolveLookupTables(
  rpcUrl: string | null,
  altAddresses: string[],
): Promise<Record<string, string[]>> {
  const lookupTables: Record<string, string[]> = {}
  const capped = altAddresses.slice(0, 8)
  if (!rpcUrl || capped.length === 0) return lookupTables
  const infos = await fetchMultipleAccounts(rpcUrl, capped)
  capped.forEach((altAddr, idx) => {
    const info = infos[idx]
    if (!info || info.bytes.length < 56) return
    const addrs: string[] = []
    for (let off = 56; off + 32 <= info.bytes.length; off += 32) {
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
  err: unknown | null
  logs: string[]
  unitsConsumed: number
  accounts: Array<SimulationAccountPost | null>
}

export async function simulateV1Transaction(
  rpcUrl: string,
  wireBytes: Uint8Array,
  watchAddresses: string[],
): Promise<SimulationResult> {
  const res = await rpcCall<{
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
      commitment: 'confirmed',
      ...(watchAddresses.length > 0
        ? { accounts: { encoding: 'base64', addresses: watchAddresses } }
        : {}),
    },
  ])

  const val = res.value
  return {
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

export async function waitForConfirmation(rpcUrl: string, signature: string): Promise<{ slot: number }> {
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
      if (status.err) {
        throw new Error(`Transaction failed on-chain: ${JSON.stringify(status.err)}`)
      }
      if (status.confirmationStatus === 'confirmed' || status.confirmationStatus === 'finalized') {
        return { slot: status.slot }
      }
    }
    await new Promise((r) => setTimeout(r, 700))
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
