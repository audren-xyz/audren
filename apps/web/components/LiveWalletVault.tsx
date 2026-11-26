'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertCircle,
  ArrowDownToLine,
  ArrowLeftRight,
  ArrowUpFromLine,
  ArrowUpRight,
  Check,
  ChevronDown,
  ChevronUp,
  Copy,
  Download,
  Eye,
  EyeOff,
  FileKey2,
  KeyRound,
  Layers,
  Loader2,
  Lock,
  RefreshCw,
  Send,
  ShieldCheck,
  SlidersHorizontal,
  Upload,
  Wallet,
} from 'lucide-react'
import {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_PUBLIC,
  AUDREN_AUDITED_SWAP_ROUTERS,
  AUDREN_DEFAULT_RELAY_URL,
  AUDREN_PROGRAM_ID,
  CLASSIC_TOKEN_PROGRAM_ID,
  CU_LIMIT_EXEC_VIA_ESCROW_BASE,
  CU_LIMIT_OPEN_PAGE,
  CU_LIMIT_TRANSACT_PRIVATE,
  CompactWalletStore,
  MEMO_NOTES_PER_PAGE,
  NUM_ESCROW_SHARDS,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_NULLIFIER,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  PROTOCOL_VERSION,
  ROOT_RING_EPOCH,
  SUBROOTS_PER_PAGE,
  SUBTREE_LEAVES,
  TOKEN_2022_PROGRAM_ID,
  VK_ID_DEFAULT,
  WSOL_MINT,
  AudrenRelayClient,
  AudrenRelayError,
  audrenInstructionToSolana,
  base58Decode,
  base58Encode,
  buildCreateAtaIdempotentInstruction,
  buildDepositInstruction,
  buildExecViaEscrowInstruction,
  buildOpenPageInstruction,
  buildTransactInstruction,
  bytes32ToFrMasked,
  bytesEqual,
  computeExecCtxHash,
  computeNoteCommitment,
  computePageRollovers,
  computeToken2022NetAmount,
  computeTransactCtxHash,
  concatBytes,
  decodePoolState,
  decodeSubtreePage,
  deriveAssetId,
  deriveAssociatedTokenAddressSync,
  deriveDefiSessionKeypair,
  deriveEscrowPdaSync,
  deriveKeysFromSeed,
  deriveLaneRentVaultPdaSync,
  deriveMemoPdaSync,
  deriveNfPagePdaSync,
  deriveStealthOwner,
  deriveSubrootPdaSync,
  deriveSubtreePdaSync,
  deriveVaultAuthPdaSync,
  encryptNoteMemo,
  exportFullViewingKey,
  exportSelectiveDisclosureProof,
  fetchGlobalRootHistory,
  frFromBeBytesStrict,
  frToBeBytes,
  fromBase64,
  fromHex,
  parseAudrenAddress,
  parseToken2022TransferFeeConfig,
  pickRandomEscrowShard,
  pickRandomLaneId,
  planAutoOpenPages,
  prepareDynamicSwapMemo,
  prepareEscrowAccountsForAudren,
  recommendedDepositCuLimit,
  recommendedTransactCuLimit,
  reconstructWitnessesForNotes,
  syncCompactStoreWithRpc,
  toBase64,
  toHex,
  verifySelectiveDisclosureProof,
  type AccountBatchFetcher,
  type AudrenInstruction,
  type AudrenKeys,
  type DecodedGlobalRootHistory,
  type MerklePath4Ary,
  type OwnedNote,
  type RelayAggregatorId,
  type RelayInfoResponse,
  type RelayInstructionPayload,
  type RelaySetupAta,
  type RootSnapshotChoice,
  type SelectiveDisclosureProof,
  type Token2022TransferFee,
} from '@/lib/audren-crypto'
import {
  clearEncryptedCompactStore,
  dummyInputWitness,
  dummyOutputWitness,
  exportEncryptedVaultBackup,
  importEncryptedVaultBackup,
  loadEncryptedCompactStore,
  loadEncryptedMintMeta,
  proveJoinsplitInBrowser,
  saveEncryptedCompactStore,
  saveEncryptedMintMeta,
  warmBrowserWasmProver,
  type AudrenEncryptedBackupFile,
  type JoinSplitInputWitness,
  type JoinSplitOutputWitness,
  type PersistedMintMeta,
} from '@/lib/audren-prover'
import {
  compileKitV0Transaction,
  connectSolanaWallet,
  disconnectSolanaWallet,
  sendAndConfirmSignedTransactions,
  signCompiledTransactionsWithWallet,
  signUtf8MessageWithWallet,
  subscribeSolanaWallets,
  subscribeWalletStandardAccounts,
  type ConnectedSolanaWallet,
  type DiscoveredSolanaWallet,
  type SolanaCluster,
} from '@/lib/solana-wallet'
import {
  AUDREN,
  WELL_KNOWN_TOKENS,
  getPool0LookupTable,
  shortHash,
  solscanAddress,
  solscanTx,
} from '@/lib/protocol'

type VaultTab = 'deposit' | 'send' | 'swap' | 'withdraw' | 'compliance'
type UnlockSource = 'wallet' | 'local' | 'backup' | null

interface PublicTokenBalance {
  ata: string
  mint: string
  amount: string
  decimals: number
  uiAmountString: string
  tokenProgram: string
}

interface TokenMetaEntry {
  symbol: string
  decimals: number
  decimalsKnown: boolean
  tokenProgram?: string
}

interface PoolApiSnapshot {
  error?: string
  initialized?: boolean
  activeLanes?: number
  paused?: boolean
  rootsPda?: string
  rootEpochInterval?: string
  noteRentFee?: string
  deterministicNoteRentFee?: string
  currentSlot?: string
  currentEpoch?: string
  totalNotes?: string
  totalNullifiers?: string
  wsolVaultLamports?: string
  lanes?: Array<{ laneId: number; nextLeaf: string; nfCount: string } | null>
  rootHistory?: {
    slotCursor: number
    epochCursor: number
    slotCount: number
    epochCount: number
    latestSlot: string
    stableSlot: string
    stableEpochId?: string
    epochInterval: string
    latestSuperRoot: string
    stableSuperRoot: string
    latestLaneCounts: string[]
    stableLaneCounts: string[]
  } | null
}

interface PoolSummary {
  initialized: boolean
  hasRootHistory: boolean
  activeLanes: number
  paused: boolean
  rootsPda: string
  rootEpochInterval: bigint
  currentSlot: bigint
  currentEpoch: bigint
  totalNotes: string
  totalNullifiers: string
  wsolVaultLamports: bigint
  latestRootSlot: bigint | null
  stableRootSlot: bigint | null
  stableLaneCounts: bigint[] | null
}

interface ActionReceipt {
  kind: string
  signature: string
  cluster: SolanaCluster
  proverMs?: number
  relayed: boolean
  pending?: boolean
  summary: string
}

const DEPOSIT_NATIVE_SOL = 'native_sol'
const USDC_MAINNET_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
const USDC_DEVNET_MINT = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU'
const RELAY_STORAGE_KEY = 'audren_custom_relay_url'
const MAX_PARALLEL_MERGE_IXS = 4

const U32_MAX = 0xffff_ffff
const U64_MAX = 0xffff_ffff_ffff_ffffn
const STRICT_HEX_64_RE = /^(?:0x)?[0-9a-fA-F]{64}$/

function getSwapQuickOutputs(cluster: SolanaCluster): ReadonlyArray<{ label: string; mint: string }> {
  if (cluster !== 'mainnet') {
    return [
      { label: 'SOL', mint: WSOL_MINT },
      { label: 'USDC', mint: USDC_DEVNET_MINT },
    ]
  }
  return [
    { label: 'SOL', mint: WSOL_MINT },
    { label: 'USDC', mint: USDC_MAINNET_MINT },
    { label: 'USDT', mint: 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB' },
    { label: 'JUP', mint: 'JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN' },
    { label: 'JitoSOL', mint: 'J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn' },
  ]
}

function parseValidDecimals(raw: unknown): number | undefined {
  return typeof raw === 'number' && Number.isInteger(raw) && raw >= 0 && raw <= 18 ? raw : undefined
}

function parseBigIntSafe(raw: string | null | undefined): bigint | null {
  if (typeof raw !== 'string') return null
  const trimmed = raw.trim()
  if (!/^\d+$/.test(trimmed)) return null
  try {
    return BigInt(trimmed)
  } catch {
    return null
  }
}

function formatUserActionError(err: unknown): string {
  if (err instanceof AudrenRelayError) {
    if (err.code === 'DAILY_SPONSOR_BUDGET_REACHED') {
      return 'Sponsored relay daily budget is currently exhausted. Disable Privacy Relayer to submit via Direct Self-Pay, or wait for the daily window reset.'
    }
    if (err.status === 429 && err.retryAfterSec) {
      return `Relayer rate limit reached. Retry in ${err.retryAfterSec}s or switch to Direct Self-Pay.`
    }
    return err.message
  }
  return err instanceof Error ? err.message : String(err)
}

function shuffleWithCsprng<T>(items: T[]): T[] {
  const arr = [...items]
  for (let i = arr.length - 1; i > 0; i--) {
    const rand = new Uint32Array(1)
    crypto.getRandomValues(rand)
    const j = rand[0]! % (i + 1)
    const tmp = arr[i]!
    arr[i] = arr[j]!
    arr[j] = tmp
  }
  return arr
}

const MAX_DIRECT_OPEN_PAGE_DEFICIT = 50_000_000n

function buildMaxWithdrawKey(params: {
  cluster: SolanaCluster
  relayUrl: string
  mint: string
  amountStr: string
  maxSpendableNotePairStr: string
  economyMode: boolean
  unwrapWsol: boolean
  poolPaused: boolean
  missingAtaCount: number
}): string {
  return [
    params.cluster,
    params.relayUrl,
    params.mint,
    params.amountStr,
    params.maxSpendableNotePairStr,
    String(params.economyMode),
    String(params.unwrapWsol),
    String(params.poolPaused),
    String(params.missingAtaCount),
  ].join('|')
}

function clampSlippageBps(raw: number): number {
  if (!Number.isFinite(raw)) return 100
  return Math.min(1500, Math.max(10, Math.trunc(raw)))
}

function computeWithdrawOutputCount(params: {
  amount: bigint
  relayerFee: bigint
  totalIn: bigint
  economyMode: boolean
  poolPaused: boolean
}): number {
  if (params.poolPaused) return 0
  if (!params.economyMode) return 1
  return params.amount + params.relayerFee >= params.totalIn ? 0 : 1
}

const INITIAL_TOKEN_META: Record<string, TokenMetaEntry> = Object.fromEntries(
  Object.entries(WELL_KNOWN_TOKENS).map(([mint, info]) => [
    mint,
    {
      symbol: info.symbol,
      decimals: info.decimals,
      decimalsKnown: true,
      tokenProgram: info.tokenProgram,
    },
  ]),
)

const VALID_AGGREGATORS: readonly RelayAggregatorId[] = ['jupiter', 'bedrock', 'dflow', 'titan', 'okx']

function parseAggregatorId(raw: unknown): RelayAggregatorId {
  if (typeof raw === 'string' && (VALID_AGGREGATORS as readonly string[]).includes(raw)) {
    return raw as RelayAggregatorId
  }
  return 'jupiter'
}

function randomFr(): bigint {
  return bytes32ToFrMasked(crypto.getRandomValues(new Uint8Array(32)))
}

function pickDistinctRandomLanes(activeLanes: number, count: number): number[] {
  const pool = Array.from({ length: activeLanes }, (_, i) => i)
  for (let i = pool.length - 1; i > 0; i--) {
    const j = pickRandomLaneId(i + 1)
    const tmp = pool[i]!
    pool[i] = pool[j]!
    pool[j] = tmp
  }
  return pool.slice(0, Math.min(count, activeLanes))
}

function formatUnits(raw: bigint, decimals: number): string {
  const neg = raw < 0n
  const v = neg ? -raw : raw
  const base = 10n ** BigInt(decimals)
  const whole = v / base
  const frac = (v % base).toString().padStart(decimals, '0').replace(/0+$/, '')
  const body = frac ? `${whole}.${frac.slice(0, 6)}` : whole.toString()
  return neg ? `-${body}` : body
}

function formatUnitsExact(raw: bigint, decimals: number): string {
  const v = raw < 0n ? 0n : raw
  if (decimals <= 0) return v.toString()
  const base = 10n ** BigInt(decimals)
  const whole = v / base
  const frac = (v % base).toString().padStart(decimals, '0').replace(/0+$/, '')
  return frac ? `${whole}.${frac}` : whole.toString()
}

function parseUnits(input: string, decimals: number): bigint | null {
  const clean = input.trim()
  if (!/^\d+(\.\d+)?$/.test(clean)) return null
  const [w, f = ''] = clean.split('.')
  if (f.length > decimals) return null
  return BigInt(w) * 10n ** BigInt(decimals) + BigInt(f.padEnd(decimals, '0') || '0')
}

function isAllowedRelayUrl(raw: string): boolean {
  try {
    const u = new URL(raw)
    if (u.protocol === 'https:') return true
    if (u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1')) return true
    return false
  } catch {
    return false
  }
}

function isValidSolanaPubkey(raw: string): boolean {
  try {
    return base58Decode(raw.trim()).byteLength === 32
  } catch {
    return false
  }
}

function hasToken2022TransferHook(mintData: Uint8Array | null): boolean {
  if (!mintData || mintData.byteLength <= 166 || mintData[165] !== 1) return false
  const dv = new DataView(mintData.buffer, mintData.byteOffset, mintData.byteLength)
  let pos = 166
  while (pos + 4 <= mintData.byteLength) {
    const extType = dv.getUint16(pos, true)
    if (extType === 0) break
    const extLen = dv.getUint16(pos + 2, true)
    const valStart = pos + 4
    const valEnd = valStart + extLen
    if (valEnd > mintData.byteLength) break
    if (extType === 14 && extLen >= 64) {
      for (let i = 32; i < 64; i++) {
        if (mintData[valStart + i] !== 0) return true
      }
    }
    pos = valEnd
  }
  return false
}

async function resolveMintOnChain(
  cluster: SolanaCluster,
  mintStr: string,
  currentEpoch: bigint,
): Promise<{
  tokenProgram: string
  isToken2022: boolean
  decimals: number | null
  transferFee: Token2022TransferFee | null
  hasTransferHook: boolean
}> {
  const wellKnown = WELL_KNOWN_TOKENS[mintStr]
  if (wellKnown && wellKnown.tokenProgram === CLASSIC_TOKEN_PROGRAM_ID) {
    return {
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
      isToken2022: false,
      decimals: wellKnown.decimals,
      transferFee: null,
      hasTransferHook: false,
    }
  }
  const res = await fetch('/api/rpc/accounts', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ cluster, addresses: [mintStr] }),
  })
  const json = (await res.json()) as {
    accounts?: Array<string | null>
    owners?: Array<string | null>
    error?: string
  }
  if (!res.ok || !json.accounts) {
    throw new Error(json.error ?? `Failed to inspect mint ${mintStr}`)
  }
  const owner = json.owners?.[0] ?? null
  const isToken2022 = owner === TOKEN_2022_PROGRAM_ID
  const isValidMintOwner = isToken2022 || owner === CLASSIC_TOKEN_PROGRAM_ID
  const data = isValidMintOwner && json.accounts[0] ? fromBase64(json.accounts[0]) : null
  const decimals = data && data.byteLength >= 45 ? (parseValidDecimals(data[44]) ?? null) : null
  const transferFee = isToken2022 ? parseToken2022TransferFeeConfig(data, currentEpoch) : null
  const hasTransferHook = isToken2022 ? hasToken2022TransferHook(data) : false
  return {
    tokenProgram: isToken2022 ? TOKEN_2022_PROGRAM_ID : CLASSIC_TOKEN_PROGRAM_ID,
    isToken2022,
    decimals,
    transferFee,
    hasTransferHook,
  }
}

function createWorkerBatchFetcher(
  cluster: SolanaCluster,
  commitment: 'confirmed' | 'finalized' = 'confirmed',
): AccountBatchFetcher {
  return async (addresses: readonly string[], options) => {
    const out: (Uint8Array | null)[] = new Array(addresses.length).fill(null)
    const dataSlice = options?.dataSlice
    for (let off = 0; off < addresses.length; off += 100) {
      const chunk = addresses.slice(off, off + 100)
      const res = await fetch('/api/rpc/accounts', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          cluster,
          addresses: chunk,
          commitment,
          ...(dataSlice ? { dataSlice } : {}),
        }),
      })
      const json = (await res.json()) as { accounts?: Array<string | null>; error?: string }
      if (!res.ok || !json.accounts) {
        throw new Error(json.error ?? `RPC batch fetch HTTP ${res.status}`)
      }
      for (let i = 0; i < chunk.length; i++) {
        const b64 = json.accounts[i]
        out[off + i] = b64 ? fromBase64(b64) : null
      }
    }
    return out
  }
}

function popcount3(mask: number): number {
  return ((mask & 1) !== 0 ? 1 : 0) + ((mask & 2) !== 0 ? 1 : 0) + ((mask & 4) !== 0 ? 1 : 0)
}

function sameNote(a: OwnedNote, b: OwnedNote): boolean {
  return a.laneId === b.laneId && a.leafIndex === b.leafIndex
}

function noteKey(n: OwnedNote): string {
  return `${n.laneId}:${n.leafIndex.toString()}`
}

function formatMintBalance(amount: bigint, meta: TokenMetaEntry): string {
  if (!meta.decimalsKnown) return `${amount.toString()} raw units`
  return `${formatUnits(amount, meta.decimals)} ${meta.symbol}`
}

function isNoteEpochSettled(note: OwnedNote, stableLaneCounts?: readonly bigint[] | null): boolean {
  if (!stableLaneCounts || note.laneId < 0 || note.laneId >= stableLaneCounts.length) return true
  const stableCount = stableLaneCounts[note.laneId]
  return stableCount !== undefined && note.leafIndex < stableCount
}

/**
 * Select 1 or 2 unspent notes of the active mint to satisfy `requiredAmount`.
 *
 * Privacy & anti-fragmentation policy:
 * - In default privacy mode (`!economyMode`), whenever `sameMintNotes.length >= 2`,
 *   opportunistically pair the smallest remaining epoch-settled same-mint note into input slot 1
 *   (even if slot 0 alone already covers `requiredAmount`) for free automatic 2 -> 1 consolidation
 *   without dragging a brand-new deposit into the slot ring and downgrading `ROOT_RING_EPOCH`.
 * - Tie-breaks prefer older notes (lower `leafIndex`) so aged notes are consolidated first.
 * - In explicit `economyMode`, prefer a single note when it alone covers `requiredAmount`.
 */
function selectInputNotesForMint(
  sameMintNotes: readonly OwnedNote[],
  requiredAmount: bigint,
  options: {
    economyMode: boolean
    preferredNote?: OwnedNote | null
    stableLaneCounts?: readonly bigint[] | null
  },
): OwnedNote[] | null {
  if (sameMintNotes.length === 0) return null
  const cmpAsc = (a: OwnedNote, b: OwnedNote) => {
    if (a.amount !== b.amount) return a.amount < b.amount ? -1 : 1
    if (a.leafIndex !== b.leafIndex) return a.leafIndex < b.leafIndex ? -1 : 1
    return a.laneId - b.laneId
  }
  const cmpDesc = (a: OwnedNote, b: OwnedNote) => {
    if (a.amount !== b.amount) return a.amount > b.amount ? -1 : 1
    if (a.leafIndex !== b.leafIndex) return a.leafIndex < b.leafIndex ? -1 : 1
    return a.laneId - b.laneId
  }
  const asc = [...sameMintNotes].sort(cmpAsc)
  const desc = [...sameMintNotes].sort(cmpDesc)
  const settledAsc = asc.filter((n) => isNoteEpochSettled(n, options.stableLaneCounts))
  const settledDesc = desc.filter((n) => isNoteEpochSettled(n, options.stableLaneCounts))
  const preferred =
    options.preferredNote && sameMintNotes.some((n) => sameNote(n, options.preferredNote!))
      ? options.preferredNote
      : null

  if (sameMintNotes.length === 1) {
    const only = asc[0]!
    return requiredAmount <= 0n || only.amount >= requiredAmount ? [only] : null
  }

  if (options.economyMode) {
    if (preferred && (requiredAmount <= 0n || preferred.amount >= requiredAmount)) {
      return [preferred]
    }
    if (requiredAmount <= 0n) return [settledDesc[0] ?? desc[0]!]
    const smallestSettledCovering = settledAsc.find((n) => n.amount >= requiredAmount)
    if (smallestSettledCovering) return [smallestSettledCovering]
    const smallestCovering = asc.find((n) => n.amount >= requiredAmount)
    if (smallestCovering) return [smallestCovering]
    if (preferred) {
      const deficit = requiredAmount - preferred.amount
      const settledPartner = settledAsc.find((n) => !sameNote(n, preferred) && n.amount >= deficit)
      if (settledPartner) return [preferred, settledPartner]
      const partner = asc.find((n) => !sameNote(n, preferred) && n.amount >= deficit)
      if (partner) return [preferred, partner]
    }
    if (settledDesc.length >= 2 && settledDesc[0]!.amount + settledDesc[1]!.amount >= requiredAmount) {
      return [settledDesc[0]!, settledDesc[1]!]
    }
    if (desc[0]!.amount + desc[1]!.amount >= requiredAmount) {
      return [desc[0]!, desc[1]!]
    }
    return null
  }

  // Default privacy mode: prefer epoch-settled notes so spends stay in `ROOT_RING_EPOCH`
  // whenever possible, and pair 2 epoch-settled notes for free consolidation.
  const primary =
    preferred ??
    (requiredAmount > 0n
      ? settledAsc.find((n) => n.amount >= requiredAmount) ??
        asc.find((n) => n.amount >= requiredAmount) ??
        settledDesc[0] ??
        desc[0]!
      : settledDesc[0] ?? desc[0]!)
  const primarySettled = isNoteEpochSettled(primary, options.stableLaneCounts)
  const othersAsc = asc.filter((n) => !sameNote(n, primary))
  const settledOthersAsc = settledAsc.filter((n) => !sameNote(n, primary))

  if (requiredAmount <= 0n || primary.amount >= requiredAmount) {
    if (settledOthersAsc.length > 0) {
      return [primary, settledOthersAsc[0]!]
    }
    // Avoid downgrading an epoch-settled primary note into `ROOT_RING_SLOT` purely to sweep a
    // brand-new unsettled note; if `primary` itself is already unsettled, pairing is fine.
    return primarySettled ? [primary] : [primary, othersAsc[0]!]
  }

  const deficit = requiredAmount - primary.amount
  const bestSettledPartner = settledOthersAsc.find((n) => n.amount >= deficit)
  if (bestSettledPartner) return [primary, bestSettledPartner]
  const bestPartner = othersAsc.find((n) => n.amount >= deficit)
  if (bestPartner) return [primary, bestPartner]

  if (settledDesc.length >= 2 && settledDesc[0]!.amount + settledDesc[1]!.amount >= requiredAmount) {
    return [settledDesc[0]!, settledDesc[1]!]
  }
  if (desc[0]!.amount + desc[1]!.amount >= requiredAmount) {
    return [desc[0]!, desc[1]!]
  }
  return null
}

function createZeroDummyOutput(
  assetId: bigint,
  mintBytes: Uint8Array,
): { witness: JoinSplitOutputWitness; memo: Uint8Array } {
  const dummyKeys = deriveKeysFromSeed(crypto.getRandomValues(new Uint8Array(32)))
  const m = encryptNoteMemo(
    dummyKeys.viewPk,
    crypto.getRandomValues(new Uint8Array(32)),
    0n,
    mintBytes,
  )
  const stealthOwner = deriveStealthOwner(dummyKeys.spendPk, m.tweak)
  return {
    witness: { stealthOwner, assetId, amount: 0n, blinding: m.blinding },
    memo: m.memo,
  }
}

function countUniqueTransactionAccounts(
  feePayer: string,
  ixs: readonly AudrenInstruction[],
  hasComputeBudget = true,
): number {
  const unique = new Set<string>([feePayer])
  if (hasComputeBudget) {
    unique.add('ComputeBudget111111111111111111111111111111')
  }
  for (const ix of ixs) {
    unique.add(ix.programId)
    for (const acc of ix.accounts) {
      unique.add(acc.pubkey)
    }
  }
  return unique.size
}

const LANE_RENT_VAULT_RESERVE_FLOOR = 1_002_240n
const PAGE_RENT_FALLBACK_BY_KIND: Record<number, bigint> = {
  [OPEN_PAGE_KIND_SUBTREE]: 58_352_640n,
  [OPEN_PAGE_KIND_SUBROOT]: 68_152_320n,
  [OPEN_PAGE_KIND_MEMO]: 72_161_280n,
  [OPEN_PAGE_KIND_NULLIFIER]: 68_152_320n,
}

async function ensureLanePagesPreIxs(params: {
  cluster: SolanaCluster
  fetcher: AccountBatchFetcher
  payer: string
  laneId: number
  nextLeaf: bigint
  nfCount: bigint
  numOutputs: number
  numNfs: number
  subSeq: bigint
  rootSeq: bigint
  memoSeq: bigint
  nfSeq: bigint
  nextSubSeq?: bigint | null
  nextRootSeq?: bigint | null
  nextMemoSeq?: bigint | null
  nextNfSeq?: bigint | null
  includeOutputs: boolean
}): Promise<AudrenInstruction[]> {
  const {
    cluster,
    fetcher,
    payer,
    laneId,
    nextLeaf,
    nfCount,
    numOutputs,
    numNfs,
    subSeq,
    rootSeq,
    memoSeq,
    nfSeq,
    nextSubSeq,
    nextRootSeq,
    nextMemoSeq,
    nextNfSeq,
    includeOutputs,
  } = params
  const effectiveOutputs = includeOutputs ? Math.max(1, numOutputs) : 0
  const candidates: Array<{ pageKind: number; pageSeq: bigint; pda: string; mandatory: boolean }> = []
  const seen = new Set<string>()
  const addCandidate = (pageKind: number, pageSeq: bigint, pda: string, mandatory: boolean) => {
    if (seen.has(pda)) return
    seen.add(pda)
    candidates.push({ pageKind, pageSeq, pda, mandatory })
  }

  if (includeOutputs) {
    addCandidate(
      OPEN_PAGE_KIND_SUBTREE,
      subSeq,
      deriveSubtreePdaSync(0, laneId, subSeq, AUDREN_PROGRAM_ID).address,
      true,
    )
    addCandidate(
      OPEN_PAGE_KIND_SUBROOT,
      rootSeq,
      deriveSubrootPdaSync(0, laneId, rootSeq, AUDREN_PROGRAM_ID).address,
      true,
    )
    addCandidate(
      OPEN_PAGE_KIND_MEMO,
      memoSeq,
      deriveMemoPdaSync(0, laneId, memoSeq, AUDREN_PROGRAM_ID).address,
      true,
    )
    if (nextSubSeq != null) {
      addCandidate(
        OPEN_PAGE_KIND_SUBTREE,
        nextSubSeq,
        deriveSubtreePdaSync(0, laneId, nextSubSeq, AUDREN_PROGRAM_ID).address,
        true,
      )
    }
    if (nextRootSeq != null) {
      addCandidate(
        OPEN_PAGE_KIND_SUBROOT,
        nextRootSeq,
        deriveSubrootPdaSync(0, laneId, nextRootSeq, AUDREN_PROGRAM_ID).address,
        true,
      )
    }
    if (nextMemoSeq != null) {
      addCandidate(
        OPEN_PAGE_KIND_MEMO,
        nextMemoSeq,
        deriveMemoPdaSync(0, laneId, nextMemoSeq, AUDREN_PROGRAM_ID).address,
        true,
      )
    }
  }
  if (numNfs > 0) {
    addCandidate(
      OPEN_PAGE_KIND_NULLIFIER,
      nfSeq,
      deriveNfPagePdaSync(0, laneId, nfSeq, AUDREN_PROGRAM_ID).address,
      true,
    )
    if (nextNfSeq != null) {
      addCandidate(
        OPEN_PAGE_KIND_NULLIFIER,
        nextNfSeq,
        deriveNfPagePdaSync(0, laneId, nextNfSeq, AUDREN_PROGRAM_ID).address,
        true,
      )
    }
  }

  // Zero-crank Auto-OpenPage: merge >=90% lookahead targets from @audren/sdk with `mandatory` preserved.
  const autoTargets = planAutoOpenPages({
    programId: AUDREN_PROGRAM_ID,
    poolId: 0,
    laneId,
    nextLeaf,
    nfCount,
    numOutputs: effectiveOutputs,
    numNfs,
  })
  for (const t of autoTargets) {
    addCandidate(t.pageKind, t.pageSeq, t.pda, t.mandatory)
  }

  if (candidates.length === 0) return []
  const laneRentVaultPda = deriveLaneRentVaultPdaSync(0, laneId, AUDREN_PROGRAM_ID).address
  const hasOptionalProactive = candidates.some((c) => !c.mandatory)
  const existingPages = new Set<string>()
  let vaultAvail = 0n

  if (hasOptionalProactive) {
    try {
      const resp = await fetch('/api/rpc/accounts', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          cluster,
          addresses: [...candidates.map((c) => c.pda), laneRentVaultPda],
          commitment: 'confirmed',
          dataSlice: { offset: 0, length: 8 },
        }),
      })
      const body = (await resp.json().catch(() => ({}))) as {
        accounts?: Array<string | null>
        lamports?: Array<number | null>
      }
      if (resp.ok && Array.isArray(body.accounts) && body.accounts.length === candidates.length + 1) {
        for (let i = 0; i < candidates.length; i++) {
          if (body.accounts[i]) existingPages.add(candidates[i]!.pda)
        }
        const rawVaultLamports = BigInt(body.lamports?.[candidates.length] ?? 0)
        vaultAvail =
          rawVaultLamports > LANE_RENT_VAULT_RESERVE_FLOOR
            ? rawVaultLamports - LANE_RENT_VAULT_RESERVE_FLOOR
            : 0n
      } else {
        const res = await fetcher(candidates.map((c) => c.pda))
        for (let i = 0; i < candidates.length; i++) {
          if (res[i]) existingPages.add(candidates[i]!.pda)
        }
      }
    } catch {
      const res = await fetcher(candidates.map((c) => c.pda))
      for (let i = 0; i < candidates.length; i++) {
        if (res[i]) existingPages.add(candidates[i]!.pda)
      }
    }
  } else {
    const res = await fetcher(candidates.map((c) => c.pda))
    for (let i = 0; i < candidates.length; i++) {
      if (res[i]) existingPages.add(candidates[i]!.pda)
    }
  }

  const emittedPdas = new Set<string>()
  const ixs: AudrenInstruction[] = []
  for (const c of candidates) {
    if (existingPages.has(c.pda) || emittedPdas.has(c.pda)) continue
    const pageRent = PAGE_RENT_FALLBACK_BY_KIND[c.pageKind] ?? 72_161_280n
    if (!c.mandatory) {
      // Optional >= 90% lookahead: prepend ONLY when LaneRentVault covers full rent (0 payer deficit).
      if (vaultAvail < pageRent) continue
      vaultAvail -= pageRent
    } else {
      vaultAvail = vaultAvail > pageRent ? vaultAvail - pageRent : 0n
    }
    emittedPdas.add(c.pda)
    ixs.push(
      buildOpenPageInstruction({
        poolId: 0,
        laneId,
        pageKind: c.pageKind,
        pageSeq: c.pageSeq,
        payer,
        maxPayerDeficit: c.mandatory ? MAX_DIRECT_OPEN_PAGE_DEFICIT : 0n,
      }),
    )
  }
  return ixs
}

export interface LiveWalletVaultProps {
  onUnsavedEphemeralChange?: (unsaved: boolean) => void
}

export function LiveWalletVault({ onUnsavedEphemeralChange }: LiveWalletVaultProps = {}) {
  const [cluster, setCluster] = useState<SolanaCluster>('devnet')
  const clusterRef = useRef<SolanaCluster>(cluster)
  const [discovered, setDiscovered] = useState<DiscoveredSolanaWallet[]>([])
  const [connected, setConnected] = useState<ConnectedSolanaWallet | null>(null)
  const connectedAddrRef = useRef<string | null>(null)
  const [connecting, setConnecting] = useState(false)

  const [unlockSource, setUnlockSource] = useState<UnlockSource>(null)
  const unlockSourceRef = useRef<UnlockSource>(null)
  const [seedBytes, setSeedBytes] = useState<Uint8Array | null>(null)
  const seedBytesRef = useRef<Uint8Array | null>(null)
  const [keys, setKeys] = useState<AudrenKeys | null>(null)
  const [store, setStore] = useState<CompactWalletStore | null>(null)
  const [birthdayByCluster, setBirthdayByCluster] = useState<Record<SolanaCluster, bigint>>({
    devnet: 0n,
    mainnet: 0n,
  })
  const vaultBirthdaySlot = birthdayByCluster[cluster]
  const [unspentNotes, setUnspentNotes] = useState<OwnedNote[]>([])
  const [syncing, setSyncing] = useState(false)
  const [syncIncomplete, setSyncIncomplete] = useState(false)
  const [strangerView, setStrangerView] = useState(false)

  // Mandatory Mainnet seed backup gate for browser-generated ephemeral vaults
  const [ephemeralBackedUp, setEphemeralBackedUp] = useState(false)
  const [ephemeralSeedRevealed, setEphemeralSeedRevealed] = useState(false)
  const [ephemeralBackupCheckbox, setEphemeralBackupCheckbox] = useState(false)
  const [ephemeralSeedConfirmInput, setEphemeralSeedConfirmInput] = useState('')
  const [ephemeralBackupDownloaded, setEphemeralBackupDownloaded] = useState(false)
  const [resolvingMintDecimals, setResolvingMintDecimals] = useState(false)

  const [poolInfo, setPoolInfo] = useState<PoolSummary | null>(null)
  const [pubSolLamports, setPubSolLamports] = useState<bigint>(0n)
  const [pubTokens, setPubTokens] = useState<PublicTokenBalance[]>([])
  const [tokenMeta, setTokenMeta] = useState<Record<string, TokenMetaEntry>>(INITIAL_TOKEN_META)

  const [tab, setTab] = useState<VaultTab>('deposit')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [busy, setBusy] = useState(false)
  const [statusMsg, setStatusMsg] = useState<string | null>(null)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)
  const [syncError, setSyncError] = useState<string | null>(null)
  const [lastReceipt, setLastReceipt] = useState<ActionReceipt | null>(null)
  const [copiedField, setCopiedField] = useState<string | null>(null)

  const defaultRelay = process.env.NEXT_PUBLIC_AUDREN_RELAY_URL?.trim() || AUDREN_DEFAULT_RELAY_URL
  const [relayUrl, setRelayUrl] = useState<string>(defaultRelay)
  const [relayDraft, setRelayDraft] = useState<string>(defaultRelay)
  const [showRelayConfig, setShowRelayConfig] = useState(false)
  const [useRelayer, setUseRelayer] = useState(true)
  const [economyMode, setEconomyMode] = useState(false)

  // Outcome-first asset selection (token-level by default; raw UTXO override tucked in Advanced)
  const [depositSource, setDepositSource] = useState<string>(DEPOSIT_NATIVE_SOL)
  const [depositAmount, setDepositAmount] = useState<string>('0.05')
  const [feeFromAmount, setFeeFromAmount] = useState<boolean>(false)

  const [selectedMintStr, setSelectedMintStr] = useState<string>(WSOL_MINT)
  const [manualNoteKey, setManualNoteKey] = useState<string>('')
  const [complianceNoteKey, setComplianceNoteKey] = useState<string>('')

  const [sendRecipient, setSendRecipient] = useState<string>('')
  const [sendAmount, setSendAmount] = useState<string>('')
  const [sendFeePreview, setSendFeePreview] = useState<{
    relayerFee: bigint
    billingMode: 'self_paying' | 'sponsored'
    reason: string
    feeShieldedAddress?: string | null
  } | null>(null)

  const [swapOutMint, setSwapOutMint] = useState<string>(USDC_DEVNET_MINT)
  const [swapAmount, setSwapAmount] = useState<string>('')
  const [swapSlippageBps, setSwapSlippageBps] = useState<number>(100)
  const [swapFeeOnOutput, setSwapFeeOnOutput] = useState<boolean>(true)
  const [swapEscrowShard, setSwapEscrowShard] = useState<number | null>(null)
  const [swapQuoteShard, setSwapQuoteShard] = useState<number | null>(null)
  const [swapQuoteNetIn, setSwapQuoteNetIn] = useState<string | null>(null)
  const [swapInputFeeBps, setSwapInputFeeBps] = useState<number>(0)
  const [swapQuoteOut, setSwapQuoteOut] = useState<string | null>(null)
  const [swapQuoteProvider, setSwapQuoteProvider] = useState<RelayAggregatorId | null>(null)
  const [swapQuoteRelayerPubkey, setSwapQuoteRelayerPubkey] = useState<string | null>(null)
  const [swapQuoteLoading, setSwapQuoteLoading] = useState(false)
  const [swapQuoteRaw, setSwapQuoteRaw] = useState<unknown>(null)
  const [swapQuoteKey, setSwapQuoteKey] = useState<string | null>(null)
  const [swapQuoteMintMeta, setSwapQuoteMintMeta] = useState<{
    inputTokenProgram?: string
    inputDecimals?: number
    outputTokenProgram?: string
    outputDecimals?: number
    outputTransferFee?: Token2022TransferFee | null
  } | null>(null)
  const swapQuoteSeqRef = useRef<number>(0)
  const swapQuoteAbortRef = useRef<AbortController | null>(null)
  const sessionEpochRef = useRef<number>(0)
  const vaultEpochRef = useRef<number>(0)
  const syncSeqRef = useRef<number>(0)
  const poolSeqRef = useRef<number>(0)
  const maxSendSeqRef = useRef<number>(0)
  const maxWithdrawSeqRef = useRef<number>(0)
  const verifyReceiptSeqRef = useRef<number>(0)
  const activeMintRef = useRef<string>(WSOL_MINT)
  const pinnedRelayerRef = useRef<{ scope: string; pubkey: string } | null>(null)
  const relayInfoCacheRef = useRef<{ scope: string; fetchedAt: number; info: RelayInfoResponse } | null>(null)

  const getCachedRelayInfo = useCallback(
    async (targetCluster: SolanaCluster, targetRelayUrl: string): Promise<RelayInfoResponse | null> => {
      const scope = `${targetCluster}|${targetRelayUrl}`
      const cached = relayInfoCacheRef.current
      if (cached && cached.scope === scope && Date.now() - cached.fetchedAt < 60_000) {
        return cached.info
      }
      try {
        const client = new AudrenRelayClient(targetRelayUrl)
        const info = await client.getInfo(targetCluster)
        relayInfoCacheRef.current = { scope, fetchedAt: Date.now(), info }
        return info
      } catch {
        return null
      }
    },
    [],
  )

  const [withdrawRecipient, setWithdrawRecipient] = useState<string>('')
  const [withdrawAmount, setWithdrawAmount] = useState<string>('')
  const [unwrapWsol, setUnwrapWsol] = useState<boolean>(true)
  const [recipientNeedsAta, setRecipientNeedsAta] = useState<boolean>(true)
  const [withdrawFeePreview, setWithdrawFeePreview] = useState<{
    relayerFee: bigint
    billingMode: 'self_paying' | 'sponsored'
    reason: string
    feeRecipient?: string | null
  } | null>(null)
  const [quotingMaxWithdraw, setQuotingMaxWithdraw] = useState(false)
  const [quotingMaxSend, setQuotingMaxSend] = useState(false)
  const lastQuotedMaxWithdrawRef = useRef<{
    key: string
    quotedFee: bigint
    billingMode: 'self_paying' | 'sponsored'
  } | null>(null)

  const [sessionIndexByCluster, setSessionIndexByCluster] = useState<Record<SolanaCluster, number>>({
    devnet: 0,
    mainnet: 0,
  })
  const sessionIndex = sessionIndexByCluster[cluster]
  const updateSessionIndex = useCallback(
    (updater: (prev: number) => number) => {
      const target = clusterRef.current
      setSessionIndexByCluster((prev) => {
        const next = Math.max(0, Math.min(10_000, updater(prev[target])))
        if (typeof window !== 'undefined') {
          try {
            window.localStorage.setItem(`audren_defi_session_idx:${target}`, String(next))
          } catch {
            // ignore storage quota errors
          }
        }
        return { ...prev, [target]: next }
      })
    },
    [],
  )
  const [receiptJson, setReceiptJson] = useState<string>('')
  const [receiptVerdict, setReceiptVerdict] = useState<'valid' | 'invalid' | null>(null)
  const [receiptVerdictDetail, setReceiptVerdictDetail] = useState<string | null>(null)
  const [verifyingReceipt, setVerifyingReceipt] = useState(false)
  const [showFvk, setShowFvk] = useState(false)
  const [backupPassphrase, setBackupPassphrase] = useState('')
  const [restoreSeedInput, setRestoreSeedInput] = useState('')
  const [restoreBirthdayInput, setRestoreBirthdayInput] = useState('')
  const [backupStatus, setBackupStatus] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement | null>(null)
  const lockedFileInputRef = useRef<HTMLInputElement | null>(null)

  const connectedAddress = connected?.address ?? null
  const walletScope = unlockSource === 'wallet' && connectedAddress ? connectedAddress : 'local'
  const mainnetEphemeralGateActive =
    cluster === 'mainnet' && unlockSource === 'local' && !ephemeralBackedUp
  const unsavedEphemeralVault = Boolean(keys && unlockSource === 'local' && !ephemeralBackedUp)
  const rootHistoryMigrationInProgress = Boolean(poolInfo?.initialized && !poolInfo.hasRootHistory)

  useEffect(() => {
    onUnsavedEphemeralChange?.(unsavedEphemeralVault)
    return () => {
      onUnsavedEphemeralChange?.(false)
    }
  }, [unsavedEphemeralVault, onUnsavedEphemeralChange])

  useEffect(() => {
    if (!unsavedEphemeralVault || typeof window === 'undefined') return
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault()
      e.returnValue = ''
    }
    window.addEventListener('beforeunload', handleBeforeUnload)
    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload)
    }
  }, [unsavedEphemeralVault])

  useEffect(() => {
    clusterRef.current = cluster
  }, [cluster])

  useEffect(() => {
    let active = true
    if (typeof window === 'undefined') return
    const readSavedIdx = (c: SolanaCluster): number => {
      try {
        const saved = window.localStorage.getItem(`audren_defi_session_idx:${c}`)
        const n = saved && /^\d+$/.test(saved) ? Number(saved) : 0
        return Number.isSafeInteger(n) && n >= 0 ? Math.min(10_000, n) : 0
      } catch {
        return 0
      }
    }
    const nextDevnet = readSavedIdx('devnet')
    const nextMainnet = readSavedIdx('mainnet')
    if (nextDevnet > 0 || nextMainnet > 0) {
      void Promise.resolve().then(() => {
        if (!active) return
        setSessionIndexByCluster({ devnet: nextDevnet, mainnet: nextMainnet })
      })
    }
    return () => {
      active = false
    }
  }, [])

  // Scrub raw master seed bytes from memory if the Vault component unmounts.
  useEffect(() => {
    return () => {
      if (seedBytesRef.current) {
        seedBytesRef.current.fill(0)
        seedBytesRef.current = null
      }
    }
  }, [])

  useEffect(() => {
    connectedAddrRef.current = connectedAddress
  }, [connectedAddress])

  useEffect(() => {
    unlockSourceRef.current = unlockSource
  }, [unlockSource])

  const getTokenMeta = useCallback(
    (mintStr: string): TokenMetaEntry => {
      const cached = tokenMeta[mintStr]
      if (cached) return cached
      const pub = pubTokens.find((t) => t.mint === mintStr)
      if (pub) {
        return {
          symbol: shortHash(mintStr, 4, 4),
          decimals: pub.decimals,
          decimalsKnown: true,
          tokenProgram: pub.tokenProgram,
        }
      }
      return { symbol: shortHash(mintStr, 4, 4), decimals: 6, decimalsKnown: false }
    },
    [tokenMeta, pubTokens],
  )

  const hydrateMintMeta = useCallback(
    (mintStr: string, decimals?: number | null, tokenProgram?: string | null) => {
      const validDec = parseValidDecimals(decimals)
      const validTp =
        tokenProgram === TOKEN_2022_PROGRAM_ID || tokenProgram === CLASSIC_TOKEN_PROGRAM_ID
          ? tokenProgram
          : undefined
      if (validDec === undefined && validTp === undefined) return
      setTokenMeta((prev) => {
        const cur = prev[mintStr]
        const nextKnown = validDec !== undefined ? true : Boolean(cur?.decimalsKnown)
        const nextDec = validDec ?? cur?.decimals ?? 6
        const nextTp = validTp ?? cur?.tokenProgram
        if (
          cur &&
          cur.decimals === nextDec &&
          cur.decimalsKnown === nextKnown &&
          cur.tokenProgram === nextTp
        ) {
          return prev
        }
        return {
          ...prev,
          [mintStr]: {
            symbol: cur?.symbol ?? shortHash(mintStr, 4, 4),
            decimals: nextDec,
            decimalsKnown: nextKnown,
            tokenProgram: nextTp,
          },
        }
      })
    },
    [],
  )

  // Persist learned non-well-known mint metadata encrypted in IndexedDB under this vault's key.
  useEffect(() => {
    if (!keys) return
    const toPersist: Record<string, PersistedMintMeta> = {}
    for (const [mint, entry] of Object.entries(tokenMeta)) {
      if (WELL_KNOWN_TOKENS[mint] || !entry.decimalsKnown) continue
      toPersist[mint] = {
        symbol: entry.symbol,
        name: entry.symbol,
        decimals: entry.decimals,
        tokenProgram: entry.tokenProgram ?? CLASSIC_TOKEN_PROGRAM_ID,
      }
    }
    if (Object.keys(toPersist).length === 0) return
    void saveEncryptedMintMeta(keys, cluster, 0, toPersist, walletScope).catch(() => {})
  }, [keys, cluster, walletScope, tokenMeta])

  const handleResolveMintDecimals = async (mintStr: string) => {
    if (resolvingMintDecimals) return
    const targetCluster = clusterRef.current
    const startVaultEpoch = vaultEpochRef.current
    setResolvingMintDecimals(true)
    setErrorMsg(null)
    try {
      const info = await resolveMintOnChain(targetCluster, mintStr, poolInfo?.currentEpoch ?? 0n)
      if (clusterRef.current !== targetCluster || vaultEpochRef.current !== startVaultEpoch) return
      if (info.decimals === null) {
        throw new Error(`Mint account ${shortHash(mintStr, 6, 4)} could not be decoded on ${targetCluster}`)
      }
      hydrateMintMeta(mintStr, info.decimals, info.tokenProgram)
      setStatusMsg(
        `Resolved on-chain decimals (${info.decimals}) for ${shortHash(mintStr, 6, 4)} on ${targetCluster}.`,
      )
    } catch (err) {
      if (clusterRef.current === targetCluster && vaultEpochRef.current === startVaultEpoch) {
        setErrorMsg(err instanceof Error ? err.message : String(err))
      }
    } finally {
      setResolvingMintDecimals(false)
    }
  }

  const clearSwapQuoteState = useCallback(() => {
    setSwapQuoteOut(null)
    setSwapQuoteRaw(null)
    setSwapQuoteProvider(null)
    setSwapQuoteRelayerPubkey(null)
    setSwapQuoteShard(null)
    setSwapQuoteNetIn(null)
    setSwapInputFeeBps(0)
    setSwapQuoteKey(null)
    setSwapQuoteMintMeta(null)
    setSwapQuoteLoading(false)
  }, [])

  const resetTransientActionState = useCallback(() => {
    swapQuoteAbortRef.current?.abort()
    swapQuoteSeqRef.current += 1
    clearSwapQuoteState()
    maxSendSeqRef.current += 1
    maxWithdrawSeqRef.current += 1
    verifyReceiptSeqRef.current += 1
    setQuotingMaxSend(false)
    setQuotingMaxWithdraw(false)
    setVerifyingReceipt(false)
    setSendFeePreview(null)
    setWithdrawFeePreview(null)
    lastQuotedMaxWithdrawRef.current = null
    setLastReceipt(null)
    setReceiptJson('')
    setReceiptVerdict(null)
    setReceiptVerdictDetail(null)
    setShowFvk(false)
  }, [clearSwapQuoteState])

  const lockWalletVaultState = useCallback((nextStatusMsg: string | null) => {
    sessionEpochRef.current += 1
    vaultEpochRef.current += 1
    unlockSourceRef.current = null
    if (seedBytesRef.current) {
      seedBytesRef.current.fill(0)
      seedBytesRef.current = null
    }
    setKeys(null)
    setSeedBytes(null)
    setUnlockSource(null)
    setStore(null)
    setBirthdayByCluster({ devnet: 0n, mainnet: 0n })
    setEphemeralBackedUp(false)
    setEphemeralSeedRevealed(false)
    setEphemeralBackupCheckbox(false)
    setEphemeralSeedConfirmInput('')
    setEphemeralBackupDownloaded(false)
    setSyncIncomplete(false)
    setUnspentNotes([])
    setSelectedMintStr(WSOL_MINT)
    setManualNoteKey('')
    setComplianceNoteKey('')
    setBackupStatus(null)
    setErrorMsg(null)
    setSyncError(null)
    setStatusMsg(nextStatusMsg)
  }, [])

  useEffect(() => {
    let active = true
    const saved = typeof window !== 'undefined' ? window.localStorage.getItem(RELAY_STORAGE_KEY) : null
    if (saved && isAllowedRelayUrl(saved)) {
      void Promise.resolve().then(() => {
        if (!active) return
        setRelayUrl(saved)
        setRelayDraft(saved)
      })
    }
    const unsub = subscribeSolanaWallets(setDiscovered)
    return () => {
      active = false
      unsub()
    }
  }, [])

  // Proactively warm the dedicated Web Worker Groth16 prover in the background once unlocked
  useEffect(() => {
    if (!keys) return
    void warmBrowserWasmProver().catch(() => {})
  }, [keys])

  // Reset wallet-derived vault session cleanly if the user switches accounts or disconnects
  // inside their browser wallet extension. Keep all side effects outside React state updaters.
  // NEVER wipe ephemeral ('local') or backup-restored ('backup') vaults on external browser wallet changes.
  const connectedWalletName = connected?.name ?? null
  useEffect(() => {
    if (!connectedWalletName) return
    const match = discovered.find((d) => d.name === connectedWalletName)
    if (!match) return
    return subscribeWalletStandardAccounts(match, (next) => {
      const prevAddr = connectedAddrRef.current
      if (!next) {
        if (prevAddr === null) return
        sessionEpochRef.current += 1
        poolSeqRef.current += 1
        if (unlockSourceRef.current === 'wallet') {
          syncSeqRef.current += 1
          setSyncing(false)
        }
        resetTransientActionState()
        connectedAddrRef.current = null
        setConnected(null)
        setPubSolLamports(0n)
        setPubTokens([])
        setDepositSource(DEPOSIT_NATIVE_SOL)
        setWithdrawRecipient((r) => (prevAddr && r === prevAddr ? '' : r))
        if (unlockSourceRef.current === 'wallet') {
          lockWalletVaultState('Browser wallet disconnected. Reconnect to unlock your vault.')
        } else if (unlockSourceRef.current === 'local' || unlockSourceRef.current === 'backup') {
          setErrorMsg(null)
          setStatusMsg('Browser wallet disconnected. Your local shielded vault remains unlocked.')
        } else {
          setErrorMsg(null)
          setStatusMsg(null)
        }
        return
      }

      if (prevAddr === next.address) {
        setConnected(next)
        return
      }

      connectedAddrRef.current = next.address
      sessionEpochRef.current += 1
      poolSeqRef.current += 1
      resetTransientActionState()
      setPubSolLamports(0n)
      setPubTokens([])
      setDepositSource(DEPOSIT_NATIVE_SOL)
      if (prevAddr) {
        if (unlockSourceRef.current === 'wallet') {
          syncSeqRef.current += 1
          setSyncing(false)
          lockWalletVaultState('Wallet account changed. Unlock vault for the active account.')
          setWithdrawRecipient((r) => (r === prevAddr ? '' : r))
        } else {
          setWithdrawRecipient((r) => (r === prevAddr ? '' : r))
          if (unlockSourceRef.current === 'local' || unlockSourceRef.current === 'backup') {
            setStatusMsg('Connected wallet account changed. Your local shielded vault remains unlocked.')
          }
        }
      }
      setConnected(next)
    })
  }, [connectedWalletName, discovered, lockWalletVaultState, resetTransientActionState])

  const copyText = useCallback(async (label: string, text: string): Promise<boolean> => {
    if (typeof navigator === 'undefined' || !navigator.clipboard) {
      setErrorMsg('Clipboard access is unavailable in this browser; select and copy manually.')
      return false
    }
    try {
      await navigator.clipboard.writeText(text)
      setCopiedField(label)
      setTimeout(() => setCopiedField((prev) => (prev === label ? null : prev)), 1800)
      return true
    } catch {
      setErrorMsg('Clipboard copy was blocked by the browser; select and copy the value manually.')
      return false
    }
  }, [])

  const refreshPoolAndBalances = useCallback(
    async (targetCluster: SolanaCluster, ownerAddr: string | null) => {
      const seq = ++poolSeqRef.current
      try {
        const poolRes = await fetch(`/api/pool?cluster=${targetCluster}&poolId=0`)
        if (poolSeqRef.current !== seq || clusterRef.current !== targetCluster) return
        if (poolRes.ok) {
          const pj = (await poolRes.json()) as PoolApiSnapshot
          if (poolSeqRef.current !== seq || clusterRef.current !== targetCluster) return
          setPoolInfo({
            initialized: Boolean(pj.initialized),
            hasRootHistory: Boolean(pj.rootHistory),
            activeLanes: pj.activeLanes ?? 4,
            paused: Boolean(pj.paused),
            rootsPda: pj.rootsPda ?? AUDREN.rootsPda,
            rootEpochInterval: BigInt(pj.rootEpochInterval ?? '32'),
            currentSlot: BigInt(pj.currentSlot ?? '0'),
            currentEpoch: BigInt(pj.currentEpoch ?? '0'),
            totalNotes: pj.totalNotes ?? '0',
            totalNullifiers: pj.totalNullifiers ?? '0',
            wsolVaultLamports: BigInt(pj.wsolVaultLamports ?? '0'),
            latestRootSlot: pj.rootHistory ? BigInt(pj.rootHistory.latestSlot) : null,
            stableRootSlot: pj.rootHistory ? BigInt(pj.rootHistory.stableSlot) : null,
            stableLaneCounts:
              pj.rootHistory && Array.isArray(pj.rootHistory.stableLaneCounts)
                ? pj.rootHistory.stableLaneCounts.map((c) => parseBigIntSafe(c) ?? 0n)
                : null,
          })
        }
      } catch {
        if (poolSeqRef.current !== seq || clusterRef.current !== targetCluster) return
        setPoolInfo(null)
      }

      if (poolSeqRef.current !== seq || clusterRef.current !== targetCluster) return
      if (!ownerAddr) {
        setPubSolLamports(0n)
        setPubTokens([])
        return
      }
      try {
        const balRes = await fetch(
          `/api/wallet/balances?cluster=${targetCluster}&owner=${encodeURIComponent(ownerAddr)}`,
        )
        if (poolSeqRef.current !== seq || clusterRef.current !== targetCluster) return
        if (balRes.ok) {
          const bj = (await balRes.json()) as { solLamports?: string; tokens?: PublicTokenBalance[] }
          if (poolSeqRef.current !== seq || clusterRef.current !== targetCluster) return
          setPubSolLamports(BigInt(bj.solLamports ?? '0'))
          setPubTokens(Array.isArray(bj.tokens) ? bj.tokens : [])
        }
      } catch {
        // Worker RPC secret may not be configured in local static preview
      }
    },
    [],
  )

  useEffect(() => {
    let active = true
    void Promise.resolve().then(() => {
      if (active) {
        return refreshPoolAndBalances(cluster, connectedAddress)
      }
      return undefined
    })
    return () => {
      active = false
    }
  }, [cluster, connectedAddress, refreshPoolAndBalances])

  // Privacy invariant: ONLY resolve unknown public wallet mints (already seen by /api/wallet/balances).
  // NEVER send shielded note mints to /api/tokens/resolve or batch them with public wallet balances!
  // Common shielded mints render directly from bundled WELL_KNOWN_TOKENS with zero network request.
  const publicMintsToResolveKey = useMemo(() => {
    const needed = new Set<string>()
    for (const t of pubTokens) {
      if (!tokenMeta[t.mint]) needed.add(t.mint)
    }
    return Array.from(needed).sort().join(',')
  }, [pubTokens, tokenMeta])

  useEffect(() => {
    if (!publicMintsToResolveKey) return
    let active = true
    const mints = publicMintsToResolveKey.split(',').filter(Boolean)
    fetch('/api/tokens/resolve', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ mints, cluster }),
    })
      .then((r) => (r.ok ? r.json() : null))
      .then(
        (
          data: {
            tokens?: Record<
              string,
              { symbol?: string; decimals?: number | null; tokenProgram?: string }
            >
          } | null,
        ) => {
          if (!active || !data?.tokens) return
          setTokenMeta((prev) => {
            let changed = false
            const next = { ...prev }
            for (const [m, info] of Object.entries(data.tokens ?? {})) {
              const dec = typeof info.decimals === 'number' ? info.decimals : prev[m]?.decimals ?? null
              if (dec === null) continue
              const sym = info.symbol?.trim() || shortHash(m, 4, 4)
              if (
                !prev[m] ||
                !prev[m]!.decimalsKnown ||
                prev[m]!.symbol !== sym ||
                prev[m]!.decimals !== dec ||
                prev[m]!.tokenProgram !== info.tokenProgram
              ) {
                next[m] = {
                  symbol: sym,
                  decimals: dec,
                  decimalsKnown: true,
                  tokenProgram: info.tokenProgram,
                }
                changed = true
              }
            }
            return changed ? next : prev
          })
        },
      )
      .catch(() => {})
    return () => {
      active = false
    }
  }, [publicMintsToResolveKey, cluster])

  const syncVault = useCallback(
    async (
      activeKeys: AudrenKeys,
      targetCluster: SolanaCluster,
      existingStore: CompactWalletStore | null,
      scope: string,
      options?: { birthdaySlot?: bigint; resetStore?: boolean; source?: UnlockSource },
    ) => {
      if (clusterRef.current !== targetCluster) return
      const activeSource = options?.source ?? unlockSourceRef.current
      if (activeSource === 'wallet' && connectedAddrRef.current !== scope) return
      const seq = ++syncSeqRef.current
      const startVaultEpoch = vaultEpochRef.current
      const isCurrent = () =>
        syncSeqRef.current === seq &&
        clusterRef.current === targetCluster &&
        vaultEpochRef.current === startVaultEpoch &&
        (activeSource !== 'wallet' || connectedAddrRef.current === scope)
      setSyncing(true)
      setErrorMsg(null)
      setSyncError(null)
      try {
        let curStore = options?.resetStore ? null : existingStore
        if (!curStore && !options?.resetStore) {
          curStore = await loadEncryptedCompactStore(activeKeys, targetCluster, 0, scope)
          if (!isCurrent()) return
        }
        if (!curStore) {
          curStore = new CompactWalletStore(0, options?.birthdaySlot ?? 0n)
        } else if (options?.birthdaySlot !== undefined && curStore.birthdaySlot === 0n) {
          curStore.birthdaySlot = options.birthdaySlot
        }

        // Clamp birthdaySlot against target cluster's live slot so future or cross-cluster slots
        // (e.g. Devnet ~525M vs Mainnet ~472M) never skip valid memo pages.
        let liveCurrentSlot = 0n
        try {
          const snapRes = await fetch(`/api/pool?cluster=${targetCluster}&poolId=0`)
          if (!isCurrent()) return
          if (snapRes.ok) {
            const snapJson = (await snapRes.json()) as PoolApiSnapshot
            if (!isCurrent()) return
            if (snapJson.currentSlot && /^\d+$/.test(snapJson.currentSlot)) {
              liveCurrentSlot = BigInt(snapJson.currentSlot)
            }
          }
        } catch {
          // Offline preview fallback: skip clamping when pool API is unreachable
        }
        if (!isCurrent()) return
        const effectiveBirthdaySlot =
          liveCurrentSlot > 0n && curStore.birthdaySlot > liveCurrentSlot ? 0n : curStore.birthdaySlot
        if (effectiveBirthdaySlot !== curStore.birthdaySlot) {
          curStore.birthdaySlot = effectiveBirthdaySlot
        }
        setBirthdayByCluster((prev) => ({ ...prev, [targetCluster]: effectiveBirthdaySlot }))

        const savedMintMeta = await loadEncryptedMintMeta(activeKeys, targetCluster, 0, scope)
        if (!isCurrent()) return
        if (Object.keys(savedMintMeta).length > 0) {
          setTokenMeta((prev) => {
            let changed = false
            const next = { ...prev }
            for (const [m, info] of Object.entries(savedMintMeta)) {
              if (WELL_KNOWN_TOKENS[m]) continue
              if (
                !prev[m] ||
                !prev[m]!.decimalsKnown ||
                prev[m]!.decimals !== info.decimals ||
                prev[m]!.tokenProgram !== info.tokenProgram
              ) {
                next[m] = {
                  symbol: prev[m]?.symbol ?? info.symbol,
                  decimals: info.decimals,
                  decimalsKnown: true,
                  tokenProgram: info.tokenProgram,
                }
                changed = true
              }
            }
            return changed ? next : prev
          })
        }

        const fvk = exportFullViewingKey(activeKeys)
        const fetcher = createWorkerBatchFetcher(targetCluster)
        let syncWarning: string | null = null
        let incompleteSync = false
        try {
          const syncRes = await syncCompactStoreWithRpc({
            store: curStore,
            fvk,
            fetchBatch: fetcher,
            birthdaySlot: effectiveBirthdaySlot,
          })
          if (!isCurrent()) return
          incompleteSync = Boolean(syncRes.incomplete)
          await saveEncryptedCompactStore(activeKeys, targetCluster, 0, curStore, scope)
        } catch (syncErr) {
          if (!isCurrent()) return
          syncWarning = syncErr instanceof Error ? syncErr.message : String(syncErr)
        }
        if (!isCurrent()) return

        const unspent = curStore.unspentNotes()
        setStore(curStore)
        setUnspentNotes(unspent)
        setSyncIncomplete(incompleteSync)
        if (unspent.length > 0) {
          const mints = Array.from(new Set(unspent.map((n) => base58Encode(n.mint))))
          setSelectedMintStr((prev) => (mints.includes(prev) ? prev : mints[0]!))
          setManualNoteKey((prev) => (prev && unspent.some((n) => noteKey(n) === prev) ? prev : ''))
          setComplianceNoteKey((prev) =>
            prev && unspent.some((n) => noteKey(n) === prev) ? prev : noteKey(unspent[0]!),
          )
        } else {
          setManualNoteKey('')
          setComplianceNoteKey('')
        }
        if (syncWarning) {
          setSyncError(syncWarning)
          setStatusMsg(null)
        } else if (incompleteSync) {
          setSyncError(null)
          setStatusMsg(
            `Partial sync (${unspent.length} unspent shielded ${unspent.length === 1 ? 'note' : 'notes'} loaded on ${targetCluster}). Click Sync RPC to finish scanning remaining pages.`,
          )
        } else {
          setSyncError(null)
          const slotNote =
            effectiveBirthdaySlot > 0n ? ` · birthday slot #${effectiveBirthdaySlot.toString()}` : ''
          setStatusMsg(
            `Synced ${unspent.length} unspent shielded ${unspent.length === 1 ? 'note' : 'notes'} on ${targetCluster}${slotNote}`,
          )
        }
      } finally {
        if (syncSeqRef.current === seq) {
          setSyncing(false)
        }
      }
    },
    [],
  )

  const handleClusterSwitch = (nextCluster: SolanaCluster) => {
    if (busy || connecting) return
    if (nextCluster === cluster) return
    clusterRef.current = nextCluster
    sessionEpochRef.current += 1
    vaultEpochRef.current += 1
    syncSeqRef.current += 1
    poolSeqRef.current += 1
    setSyncing(false)
    setPoolInfo(null)
    setCluster(nextCluster)
    setStore(null)
    setUnspentNotes([])
    setManualNoteKey('')
    setComplianceNoteKey('')
    setBackupStatus(null)
    setErrorMsg(null)
    setSyncError(null)
    setStatusMsg(null)
    resetTransientActionState()
    setSwapEscrowShard(pickRandomEscrowShard(NUM_ESCROW_SHARDS))
    setSwapOutMint(nextCluster === 'devnet' ? USDC_DEVNET_MINT : USDC_MAINNET_MINT)
    setPubSolLamports(0n)
    setPubTokens([])
    setDepositSource(DEPOSIT_NATIVE_SOL)
    if (unlockSourceRef.current === 'wallet') {
      lockWalletVaultState(null)
    } else if (keys) {
      // Never carry the previous cluster's birthdaySlot across clusters (e.g. Devnet -> Mainnet).
      const nextClusterBirthday = birthdayByCluster[nextCluster]
      void syncVault(keys, nextCluster, null, 'local', {
        birthdaySlot: nextClusterBirthday,
        source: unlockSourceRef.current,
      })
    }
  }

  const handleConnectWallet = async (wallet: DiscoveredSolanaWallet) => {
    if (busy || connecting) return
    setConnecting(true)
    setErrorMsg(null)
    try {
      const conn = await connectSolanaWallet(wallet)
      const prevAddr = connectedAddrRef.current
      const addrChanged = prevAddr !== conn.address
      sessionEpochRef.current += 1
      if (addrChanged) {
        poolSeqRef.current += 1
        resetTransientActionState()
        setPubSolLamports(0n)
        setPubTokens([])
        setDepositSource(DEPOSIT_NATIVE_SOL)
        if (unlockSourceRef.current === 'wallet') {
          syncSeqRef.current += 1
          setSyncing(false)
          lockWalletVaultState('Wallet account changed. Unlock vault for the active account.')
          setWithdrawRecipient((prev) => (prev === prevAddr ? '' : prev))
        } else {
          setWithdrawRecipient((prev) => (prev === prevAddr ? '' : prev))
        }
      }
      connectedAddrRef.current = conn.address
      setConnected(conn)
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setConnecting(false)
    }
  }

  const handleDisconnect = async () => {
    if (busy || connecting) return
    const activeConnected = connected
    setBusy(true)
    sessionEpochRef.current += 1
    if (unlockSourceRef.current === 'wallet') {
      syncSeqRef.current += 1
      setSyncing(false)
    }
    if (connectedAddrRef.current !== null) {
      poolSeqRef.current += 1
    }
    try {
      if (activeConnected) {
        await disconnectSolanaWallet(activeConnected)
      }
      sessionEpochRef.current += 1
      if (unlockSourceRef.current === 'wallet') {
        syncSeqRef.current += 1
        setSyncing(false)
      }
      if (connectedAddrRef.current !== null) {
        poolSeqRef.current += 1
      }
      resetTransientActionState()
      const prevAddr = connectedAddrRef.current ?? activeConnected?.address ?? null
      connectedAddrRef.current = null
      setConnected(null)
      setPubSolLamports(0n)
      setPubTokens([])
      setDepositSource(DEPOSIT_NATIVE_SOL)
      setWithdrawRecipient((r) => (prevAddr && r === prevAddr ? '' : r))
      if (unlockSourceRef.current === 'wallet') {
        lockWalletVaultState(null)
      } else if (unlockSourceRef.current === 'local' || unlockSourceRef.current === 'backup') {
        setErrorMsg(null)
        setStatusMsg('Browser wallet disconnected. Your local shielded vault remains unlocked.')
      } else {
        setErrorMsg(null)
        setStatusMsg(null)
      }
    } finally {
      setBusy(false)
    }
  }

  const unlockFromSeed = useCallback(
    async (
      seed: Uint8Array,
      targetCluster: SolanaCluster,
      source: UnlockSource,
      scope: string,
      options?: { birthdaySlot?: bigint; resetStore?: boolean },
    ): Promise<number | null> => {
      if (clusterRef.current !== targetCluster) return null
      if (source === 'wallet' && connectedAddrRef.current !== scope) return null
      sessionEpochRef.current += 1
      const unlockedVaultEpoch = ++vaultEpochRef.current
      maxSendSeqRef.current += 1
      maxWithdrawSeqRef.current += 1
      verifyReceiptSeqRef.current += 1
      setQuotingMaxSend(false)
      setQuotingMaxWithdraw(false)
      setVerifyingReceipt(false)
      setBackupStatus(null)
      const derived = deriveKeysFromSeed(seed)
      if (seedBytesRef.current && seedBytesRef.current !== seed) {
        seedBytesRef.current.fill(0)
      }
      seedBytesRef.current = seed
      unlockSourceRef.current = source
      setSeedBytes(seed)
      setKeys(derived)
      setUnlockSource(source)
      setLastReceipt(null)
      setEphemeralBackedUp(source !== 'local')
      setEphemeralSeedRevealed(false)
      setEphemeralBackupCheckbox(false)
      setEphemeralSeedConfirmInput('')
      setEphemeralBackupDownloaded(false)
      setSyncIncomplete(false)
      await syncVault(derived, targetCluster, null, scope, { ...options, source })
      return vaultEpochRef.current === unlockedVaultEpoch &&
        clusterRef.current === targetCluster &&
        (source !== 'wallet' || connectedAddrRef.current === scope)
        ? unlockedVaultEpoch
        : null
    },
    [syncVault],
  )

  const handleUnlockWithWalletSignature = async () => {
    if (!connected || busy || connecting) return
    const targetCluster = cluster
    const targetWallet = connected.address
    const startSession = sessionEpochRef.current
    setBusy(true)
    setErrorMsg(null)
    try {
      const msg = `Audren Vault Key Derivation\nCluster: ${targetCluster}\nWallet: ${targetWallet}`
      const sig = await signUtf8MessageWithWallet(connected, msg)
      if (
        clusterRef.current !== targetCluster ||
        connectedAddrRef.current !== targetWallet ||
        sessionEpochRef.current !== startSession
      ) {
        return
      }
      const buf = new ArrayBuffer(sig.byteLength)
      new Uint8Array(buf).set(sig)
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', buf))
      if (
        clusterRef.current !== targetCluster ||
        connectedAddrRef.current !== targetWallet ||
        sessionEpochRef.current !== startSession
      ) {
        return
      }
      setBirthdayByCluster({ devnet: 0n, mainnet: 0n })
      await unlockFromSeed(digest, targetCluster, 'wallet', targetWallet)
    } catch (err) {
      if (
        clusterRef.current === targetCluster &&
        connectedAddrRef.current === targetWallet &&
        sessionEpochRef.current === startSession
      ) {
        setErrorMsg(err instanceof Error ? err.message : String(err))
      }
    } finally {
      setBusy(false)
    }
  }

  const handleCreateLocalVault = async () => {
    if (busy || connecting) return
    const targetCluster = cluster
    setBusy(true)
    setErrorMsg(null)
    try {
      // Capture current cluster slot as birthdaySlot so brand-new ephemeral vaults skip old closed pages
      let capturedBirthday = poolInfo?.currentSlot ?? 0n
      if (capturedBirthday === 0n) {
        try {
          const snap = (await fetch(`/api/pool?cluster=${targetCluster}&poolId=0`).then((r) =>
            r.json(),
          )) as PoolApiSnapshot
          if (snap.currentSlot && /^\d+$/.test(snap.currentSlot)) {
            capturedBirthday = BigInt(snap.currentSlot)
          }
        } catch {
          // Offline preview fallback: birthdaySlot stays 0n
        }
      }
      if (clusterRef.current !== targetCluster) return
      const freshSeed = crypto.getRandomValues(new Uint8Array(32))
      setBirthdayByCluster({
        devnet: targetCluster === 'devnet' ? capturedBirthday : 0n,
        mainnet: targetCluster === 'mainnet' ? capturedBirthday : 0n,
      })
      const unlockedEpoch = await unlockFromSeed(freshSeed, targetCluster, 'local', 'local', {
        birthdaySlot: capturedBirthday,
        resetStore: true,
      })
      if (unlockedEpoch === null) return
      setStatusMsg(
        capturedBirthday > 0n
          ? `Ephemeral local vault created at birthday slot #${capturedBirthday.toString()}. Save an encrypted backup before closing.`
          : 'Ephemeral local vault created. Save an encrypted backup before closing.',
      )
    } catch (err) {
      if (clusterRef.current === targetCluster) {
        setErrorMsg(err instanceof Error ? err.message : String(err))
      }
    } finally {
      setBusy(false)
    }
  }

  const handleRestoreFromHexSeed = async () => {
    if (busy || connecting) return
    const trimmedHex = restoreSeedInput.trim()
    if (!STRICT_HEX_64_RE.test(trimmedHex)) {
      setErrorMsg('Recovery seed must be exactly 64 hexadecimal characters (32 bytes)')
      return
    }
    const overrideTrimmed = restoreBirthdayInput.trim()
    let effectiveBirthday = 0n
    if (overrideTrimmed.length > 0) {
      if (!/^\d+$/.test(overrideTrimmed)) {
        setErrorMsg('Birthday slot override must be a non-negative integer')
        return
      }
      effectiveBirthday = BigInt(overrideTrimmed)
    }
    const targetCluster = cluster
    setBusy(true)
    setErrorMsg(null)
    setBackupStatus(null)
    try {
      const restoredSeed = fromHex(trimmedHex)
      setRestoreSeedInput('')
      setBirthdayByCluster((prev) => ({
        ...prev,
        [targetCluster]: effectiveBirthday,
      }))
      const unlockedEpoch = await unlockFromSeed(restoredSeed, targetCluster, 'backup', 'local', {
        birthdaySlot: effectiveBirthday,
        resetStore: true,
      })
      if (unlockedEpoch === null) return
      setStatusMsg(
        effectiveBirthday > 0n
          ? `Restored Audren vault from 64-hex seed on ${targetCluster} (birthday slot #${effectiveBirthday.toString()}).`
          : `Restored Audren vault from 64-hex seed on ${targetCluster}.`,
      )
    } catch (err) {
      if (clusterRef.current === targetCluster) {
        setErrorMsg(err instanceof Error ? err.message : String(err))
      }
    } finally {
      setBusy(false)
    }
  }

  // Aggregated shielded token balances (primary outcome-first view)
  const totalShieldedByMint = useMemo(() => {
    const map = new Map<string, { total: bigint; count: number }>()
    for (const n of unspentNotes) {
      const m = base58Encode(n.mint)
      const prev = map.get(m)
      map.set(m, { total: (prev?.total ?? 0n) + n.amount, count: (prev?.count ?? 0) + 1 })
    }
    return Array.from(map.entries())
  }, [unspentNotes])

  const activeMintStr = useMemo(() => {
    if (totalShieldedByMint.some(([m]) => m === selectedMintStr)) return selectedMintStr
    return totalShieldedByMint[0]?.[0] ?? WSOL_MINT
  }, [totalShieldedByMint, selectedMintStr])

  useEffect(() => {
    activeMintRef.current = activeMintStr
  }, [activeMintStr])

  const activeMintNotes = useMemo(
    () => unspentNotes.filter((n) => base58Encode(n.mint) === activeMintStr),
    [unspentNotes, activeMintStr],
  )

  const activeMintNotesDesc = useMemo(
    () => [...activeMintNotes].sort((a, b) => (a.amount > b.amount ? -1 : a.amount < b.amount ? 1 : 0)),
    [activeMintNotes],
  )

  const activeMintTotal = useMemo(
    () => activeMintNotes.reduce((s, n) => s + n.amount, 0n),
    [activeMintNotes],
  )

  const manualPreferredNote = useMemo(() => {
    if (!manualNoteKey) return null
    return activeMintNotes.find((n) => noteKey(n) === manualNoteKey) ?? null
  }, [manualNoteKey, activeMintNotes])

  const activeMintMeta = useMemo(() => getTokenMeta(activeMintStr), [getTokenMeta, activeMintStr])
  const activeMintDecimals = activeMintMeta.decimals

  const swapOutMeta = useMemo(() => getTokenMeta(swapOutMint), [getTokenMeta, swapOutMint])

  const complianceNote = useMemo(() => {
    return unspentNotes.find((n) => noteKey(n) === complianceNoteKey) ?? unspentNotes[0] ?? null
  }, [complianceNoteKey, unspentNotes])

  const maxSpendableNotePair = useMemo(() => {
    if (activeMintNotesDesc.length === 0) return 0n
    if (activeMintNotesDesc.length >= 2) {
      return activeMintNotesDesc[0]!.amount + activeMintNotesDesc[1]!.amount
    }
    return activeMintNotesDesc[0]!.amount
  }, [activeMintNotesDesc])

  // Inline BIP-350 Bech32m checksum validation for Send recipient
  const sendRecipientCheck = useMemo(() => {
    const trimmed = sendRecipient.trim()
    if (!trimmed) return { valid: false, error: null as string | null }
    try {
      parseAudrenAddress(trimmed)
      return { valid: true, error: null as string | null }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      if (/checksum/i.test(msg)) {
        return {
          valid: false,
          error: 'Invalid Bech32m checksum in aud1 address: check for typos before sending.',
        }
      }
      return { valid: false, error: msg }
    }
  }, [sendRecipient])

  // Fee-independent input note selection used for live fee quotes (prevents feePreview feedback loops!)
  const stableLaneCounts = poolInfo?.stableLaneCounts ?? null
  const sendInputNotesBase = useMemo(() => {
    if (activeMintNotes.length === 0) return null
    const amt = parseUnits(sendAmount, activeMintDecimals) ?? 0n
    return selectInputNotesForMint(activeMintNotes, amt, {
      economyMode,
      preferredNote: manualPreferredNote,
      stableLaneCounts,
    })
  }, [activeMintNotes, sendAmount, activeMintDecimals, economyMode, manualPreferredNote, stableLaneCounts])

  const withdrawInputNotesBase = useMemo(() => {
    if (activeMintNotes.length === 0) return null
    const amt = parseUnits(withdrawAmount, activeMintDecimals) ?? 0n
    return selectInputNotesForMint(activeMintNotes, amt, {
      economyMode,
      preferredNote: manualPreferredNote,
      stableLaneCounts,
    })
  }, [activeMintNotes, withdrawAmount, activeMintDecimals, economyMode, manualPreferredNote, stableLaneCounts])

  const plannedSendNotes = useMemo(() => {
    if (activeMintNotes.length === 0) return null
    const amt = parseUnits(sendAmount, activeMintDecimals) ?? 0n
    const fee = useRelayer && sendFeePreview ? sendFeePreview.relayerFee : 0n
    return (
      selectInputNotesForMint(activeMintNotes, amt + fee, {
        economyMode,
        preferredNote: manualPreferredNote,
        stableLaneCounts,
      }) ?? sendInputNotesBase
    )
  }, [
    activeMintNotes,
    sendAmount,
    activeMintDecimals,
    useRelayer,
    sendFeePreview,
    economyMode,
    manualPreferredNote,
    stableLaneCounts,
    sendInputNotesBase,
  ])

  const plannedWithdrawNotes = useMemo(() => {
    if (activeMintNotes.length === 0) return null
    const amt = parseUnits(withdrawAmount, activeMintDecimals) ?? 0n
    const fee = useRelayer && withdrawFeePreview ? withdrawFeePreview.relayerFee : 0n
    return (
      selectInputNotesForMint(activeMintNotes, amt + fee, {
        economyMode,
        preferredNote: manualPreferredNote,
        stableLaneCounts,
      }) ?? withdrawInputNotesBase
    )
  }, [
    activeMintNotes,
    withdrawAmount,
    activeMintDecimals,
    useRelayer,
    withdrawFeePreview,
    economyMode,
    manualPreferredNote,
    stableLaneCounts,
    withdrawInputNotesBase,
  ])

  const plannedSwapNotes = useMemo(() => {
    if (activeMintNotes.length === 0) return null
    const amt = parseUnits(swapAmount, activeMintDecimals) ?? 0n
    return selectInputNotesForMint(activeMintNotes, amt, {
      economyMode,
      preferredNote: manualPreferredNote,
      stableLaneCounts,
    })
  }, [activeMintNotes, swapAmount, activeMintDecimals, economyMode, manualPreferredNote, stableLaneCounts])

  // Detect when user entered an amount covered by total shielded balance but requiring >2 notes
  const needsBatchConsolidation = useMemo(() => {
    if (activeMintNotes.length < 3) return false
    const rawStr = tab === 'send' ? sendAmount : tab === 'withdraw' ? withdrawAmount : tab === 'swap' ? swapAmount : ''
    const req = parseUnits(rawStr, activeMintDecimals)
    if (!req || req <= 0n) return false
    const fee =
      tab === 'send' && useRelayer && sendFeePreview
        ? sendFeePreview.relayerFee
        : tab === 'withdraw' && useRelayer && withdrawFeePreview
          ? withdrawFeePreview.relayerFee
          : 0n
    const totalReq = req + fee
    return totalReq > maxSpendableNotePair && totalReq <= activeMintTotal
  }, [
    activeMintNotes.length,
    tab,
    sendAmount,
    withdrawAmount,
    swapAmount,
    activeMintDecimals,
    useRelayer,
    sendFeePreview,
    withdrawFeePreview,
    maxSpendableNotePair,
    activeMintTotal,
  ])

  const currentSwapQuoteKey = `${cluster}|${useRelayer}|${useRelayer ? relayUrl : ''}|${activeMintStr}|${activeMintDecimals}|${swapOutMint}|${swapAmount}|${swapSlippageBps}`
  const swapQuoteMatches = Boolean(
    swapQuoteRaw && swapQuoteOut && swapQuoteKey === currentSwapQuoteKey && !swapQuoteLoading,
  )

  const fetchSwapQuote = useCallback(
    async (
      inMint: string,
      inDecimals: number,
      outMint: string,
      amountStr: string,
      slippage: number,
      targetCluster: SolanaCluster,
      activeRelay: string,
      relayed: boolean,
      shardId: number,
      quoteKey: string,
    ) => {
      swapQuoteAbortRef.current?.abort()
      const seq = ++swapQuoteSeqRef.current
      if (targetCluster !== 'mainnet') {
        clearSwapQuoteState()
        return
      }
      if (!isValidSolanaPubkey(outMint)) {
        clearSwapQuoteState()
        return
      }
      const rawAmt = parseUnits(amountStr, inDecimals)
      if (!rawAmt || rawAmt <= 0n || inMint === outMint) {
        clearSwapQuoteState()
        return
      }
      const safeSlippage = clampSlippageBps(slippage)
      const controller = new AbortController()
      swapQuoteAbortRef.current = controller
      setSwapQuoteLoading(true)
      try {
        if (relayed) {
          const client = new AudrenRelayClient(activeRelay)
          const relayScope = `${targetCluster}|${activeRelay}`
          const pinnedRelayer =
            pinnedRelayerRef.current?.scope === relayScope ? pinnedRelayerRef.current.pubkey : undefined
          const resp = await client.quoteSwap({
            cluster: targetCluster,
            inputMint: inMint,
            outputMint: outMint,
            amount: rawAmt.toString(),
            slippageBps: safeSlippage,
            shardId,
            provider: 'auto',
            includeFee: false,
            ...(pinnedRelayer ? { relayerPubkey: pinnedRelayer } : {}),
          })
          if (seq !== swapQuoteSeqRef.current || controller.signal.aborted) return
          if (typeof resp.relayerPubkey === 'string' && resp.relayerPubkey) {
            pinnedRelayerRef.current = { scope: relayScope, pubkey: resp.relayerPubkey }
          }
          const inMetaResp = resp.mints?.input
          const outMetaResp = resp.mints?.output
          const hydratedInDec = parseValidDecimals(inMetaResp?.decimals)
          const hydratedInTp =
            inMetaResp &&
            (inMetaResp.tokenProgram === TOKEN_2022_PROGRAM_ID ||
              inMetaResp.tokenProgram === CLASSIC_TOKEN_PROGRAM_ID)
              ? inMetaResp.tokenProgram
              : undefined
          const hydratedOutDec = parseValidDecimals(outMetaResp?.decimals)
          const hydratedOutTp =
            outMetaResp &&
            (outMetaResp.tokenProgram === TOKEN_2022_PROGRAM_ID ||
              outMetaResp.tokenProgram === CLASSIC_TOKEN_PROGRAM_ID)
              ? outMetaResp.tokenProgram
              : undefined
          const rawOutTransferFee = resp.outputTransferFee
          const hydratedOutTransferFee: Token2022TransferFee | null =
            rawOutTransferFee &&
            typeof rawOutTransferFee.bps === 'number' &&
            Number.isInteger(rawOutTransferFee.bps) &&
            rawOutTransferFee.bps > 0 &&
            typeof rawOutTransferFee.maxFee === 'string' &&
            /^\d+$/.test(rawOutTransferFee.maxFee)
              ? {
                  bps: BigInt(rawOutTransferFee.bps),
                  maxFee: BigInt(rawOutTransferFee.maxFee),
                  epoch: 0n,
                }
              : null
          hydrateMintMeta(inMint, hydratedInDec, hydratedInTp)
          hydrateMintMeta(outMint, hydratedOutDec, hydratedOutTp)
          if (hydratedInDec !== undefined && hydratedInDec !== inDecimals) {
            setSwapAmount('')
            clearSwapQuoteState()
            setStatusMsg(
              `Synced on-chain decimals (${hydratedInDec}) for ${shortHash(inMint, 4, 4)} (previously ${inDecimals}). Re-enter the swap amount or click Max.`,
            )
            return
          }
          const outAmt =
            typeof resp.quote?.outAmount === 'string'
              ? resp.quote.outAmount
              : typeof resp.outAmount === 'string'
                ? resp.outAmount
                : null
          setSwapQuoteOut(outAmt)
          setSwapQuoteProvider(parseAggregatorId(resp.provider ?? resp.quote?.provider))
          setSwapQuoteRelayerPubkey(typeof resp.relayerPubkey === 'string' ? resp.relayerPubkey : null)
          setSwapQuoteRaw(resp.quote?.rawQuote ?? resp)
          setSwapQuoteShard(shardId)
          setSwapQuoteNetIn(typeof resp.netInputAmount === 'string' ? resp.netInputAmount : rawAmt.toString())
          setSwapInputFeeBps(typeof resp.inputTransferFeeBps === 'number' ? resp.inputTransferFeeBps : 0)
          setSwapQuoteMintMeta({
            inputTokenProgram: hydratedInTp,
            inputDecimals: hydratedInDec,
            outputTokenProgram: hydratedOutTp,
            outputDecimals: hydratedOutDec,
            outputTransferFee: hydratedOutTransferFee,
          })
          setSwapQuoteKey(quoteKey)
        } else {
          const res = await fetch('/api/jupiter/quote', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            signal: controller.signal,
            body: JSON.stringify({
              cluster: targetCluster,
              inputMint: inMint,
              outputMint: outMint,
              amount: rawAmt.toString(),
              slippageBps: safeSlippage,
            }),
          })
          const netInHeader = res.headers.get('x-audren-net-input-amount')
          const feeBpsHeader = res.headers.get('x-audren-input-transfer-fee-bps')
          const inDecHeader = res.headers.get('x-audren-input-decimals')
          const inTpHeader = res.headers.get('x-audren-input-token-program')
          const outDecHeader = res.headers.get('x-audren-output-decimals')
          const outTpHeader = res.headers.get('x-audren-output-token-program')
          const quote = (await res.json()) as Record<string, unknown>
          if (seq !== swapQuoteSeqRef.current || controller.signal.aborted) return
          const hydratedInDec =
            inDecHeader !== null && /^\d+$/.test(inDecHeader)
              ? parseValidDecimals(Number(inDecHeader))
              : undefined
          const hydratedInTp =
            inTpHeader === TOKEN_2022_PROGRAM_ID || inTpHeader === CLASSIC_TOKEN_PROGRAM_ID
              ? inTpHeader
              : undefined
          const hydratedOutDec =
            outDecHeader !== null && /^\d+$/.test(outDecHeader)
              ? parseValidDecimals(Number(outDecHeader))
              : undefined
          const hydratedOutTp =
            outTpHeader === TOKEN_2022_PROGRAM_ID || outTpHeader === CLASSIC_TOKEN_PROGRAM_ID
              ? outTpHeader
              : undefined
          hydrateMintMeta(inMint, hydratedInDec, hydratedInTp)
          hydrateMintMeta(outMint, hydratedOutDec, hydratedOutTp)
          if (hydratedInDec !== undefined && hydratedInDec !== inDecimals) {
            setSwapAmount('')
            clearSwapQuoteState()
            setStatusMsg(
              `Synced on-chain decimals (${hydratedInDec}) for ${shortHash(inMint, 4, 4)} (previously ${inDecimals}). Re-enter the swap amount or click Max.`,
            )
            return
          }
          if (!res.ok) throw new Error(String(quote.error ?? `Quote HTTP ${res.status}`))
          const outAmt = typeof quote.outAmount === 'string' ? quote.outAmount : null
          setSwapQuoteOut(outAmt)
          setSwapQuoteProvider('jupiter')
          setSwapQuoteRelayerPubkey(null)
          setSwapQuoteRaw(quote)
          setSwapQuoteShard(shardId)
          setSwapQuoteNetIn(netInHeader ?? (typeof quote.inAmount === 'string' ? quote.inAmount : rawAmt.toString()))
          setSwapInputFeeBps(feeBpsHeader ? Number(feeBpsHeader) || 0 : 0)
          setSwapQuoteMintMeta({
            inputTokenProgram: hydratedInTp,
            inputDecimals: hydratedInDec,
            outputTokenProgram: hydratedOutTp,
            outputDecimals: hydratedOutDec,
          })
          setSwapQuoteKey(quoteKey)
        }
      } catch {
        if (seq !== swapQuoteSeqRef.current || controller.signal.aborted) return
        clearSwapQuoteState()
      } finally {
        if (seq === swapQuoteSeqRef.current) {
          setSwapQuoteLoading(false)
        }
      }
    },
    [clearSwapQuoteState, hydrateMintMeta],
  )

  useEffect(() => {
    let active = true
    swapQuoteAbortRef.current?.abort()
    swapQuoteSeqRef.current += 1
    // Immediately clear any stale quote whenever swap inputs change so the UI/submit
    // cannot act on a mismatched quote during the debounce or fetch window.
    void Promise.resolve().then(() => {
      if (active) clearSwapQuoteState()
    })
    if (
      tab !== 'swap' ||
      cluster !== 'mainnet' ||
      !swapAmount.trim() ||
      swapEscrowShard === null ||
      activeMintNotes.length === 0
    ) {
      return () => {
        active = false
      }
    }
    const timer = setTimeout(() => {
      void fetchSwapQuote(
        activeMintStr,
        activeMintDecimals,
        swapOutMint,
        swapAmount,
        swapSlippageBps,
        cluster,
        relayUrl,
        useRelayer,
        swapEscrowShard,
        currentSwapQuoteKey,
      )
    }, 350)
    return () => {
      active = false
      clearTimeout(timer)
      swapQuoteAbortRef.current?.abort()
      swapQuoteSeqRef.current += 1
    }
  }, [
    tab,
    activeMintStr,
    activeMintDecimals,
    activeMintNotes.length,
    swapOutMint,
    swapAmount,
    swapSlippageBps,
    cluster,
    relayUrl,
    useRelayer,
    swapEscrowShard,
    currentSwapQuoteKey,
    fetchSwapQuote,
    clearSwapQuoteState,
  ])

  // Live relayer fee preview: strictly primitive, fee-independent dependencies only.
  // Privacy invariants:
  // - Send quote NEVER fires eagerly on tab switch and NEVER transmits private amounts.
  // - Withdraw quote NEVER fires when `withdrawAmount` is empty (zero `?? totalAvail` leak).
  // - Never feeds `feePreview` back into note-selection inputs (zero oscillation loops).
  const activeMintNoteCount = activeMintNotes.length
  const quoteSendInputCount = sendInputNotesBase
    ? sendInputNotesBase.length
    : Math.min(2, activeMintNoteCount)
  const sendQuoteOmitNf1 = economyMode && quoteSendInputCount <= 1
  const quoteWithdrawInputCount = withdrawInputNotesBase
    ? withdrawInputNotesBase.length
    : Math.min(2, activeMintNoteCount)
  const maxSpendableNotePairStr = maxSpendableNotePair.toString()
  const quoteWithdrawTotalStr = withdrawInputNotesBase
    ? withdrawInputNotesBase.reduce((s, n) => s + n.amount, 0n).toString()
    : maxSpendableNotePairStr
  const poolPausedFlag = Boolean(poolInfo?.paused)
  const knownSelfRecipientHasAta =
    Boolean(connectedAddress) &&
    withdrawRecipient.trim() === connectedAddress &&
    pubTokens.some((t) => t.mint === activeMintStr)
  const effectiveRelayedMissingAta =
    useRelayer &&
    !(activeMintStr === WSOL_MINT && unwrapWsol) &&
    !knownSelfRecipientHasAta &&
    recipientNeedsAta
      ? 1
      : 0

  useEffect(() => {
    if ((tab !== 'send' && tab !== 'withdraw') || !useRelayer || activeMintNoteCount === 0) {
      return
    }
    let active = true
    if (tab === 'send') {
      const timer = setTimeout(() => {
        void (async () => {
          const info = await getCachedRelayInfo(cluster, relayUrl)
          if (!active) return
          // M-2: When the relayer has no shielded FVK configured, all private transfers are
          // sponsored at 0 fee regardless of mint or amount. Resolve locally without transmitting
          // the hidden mint or firing keystroke-correlated `/v1/fee-quote` requests.
          if (info && !info.relayerShieldedAddress) {
            setSendFeePreview({
              relayerFee: 0n,
              billingMode: 'sponsored',
              reason: 'Relayer sponsors private transfers under rate limits.',
            })
            return
          }
          const client = new AudrenRelayClient(relayUrl)
          const omitNf1 = sendQuoteOmitNf1
          const relayScope = `${cluster}|${relayUrl}`
          const pinnedRelayer =
            pinnedRelayerRef.current?.scope === relayScope ? pinnedRelayerRef.current.pubkey : undefined
          try {
            const fq = await client.getFeeQuote({
              cluster,
              op: 'transfer',
              ...(info?.relayerShieldedAddress ? { mint: activeMintStr } : {}),
              outputCount: 3,
              omitNf1,
              ...(pinnedRelayer ? { relayerPubkey: pinnedRelayer } : {}),
            })
            if (!active) return
            if (typeof fq.relayerPubkey === 'string' && fq.relayerPubkey) {
              pinnedRelayerRef.current = { scope: relayScope, pubkey: fq.relayerPubkey }
            }
            const validDec = parseValidDecimals(fq.feeDecimals)
            if (fq.feeMint) {
              hydrateMintMeta(fq.feeMint, fq.feeDecimals, fq.feeTokenProgram)
            }
            if (
              fq.feeMint &&
              fq.feeMint === activeMintStr &&
              validDec !== undefined &&
              validDec !== activeMintDecimals
            ) {
              setSendAmount('')
              setSendFeePreview(null)
              setStatusMsg(
                `Synced on-chain decimals (${validDec}) for ${shortHash(activeMintStr, 4, 4)} (previously ${activeMintDecimals}). Re-enter the amount or click Max.`,
              )
              return
            }
            setSendFeePreview({
              relayerFee: BigInt(fq.relayerFee || '0'),
              billingMode: fq.billingMode,
              reason: fq.reason,
              feeShieldedAddress: fq.feeShieldedAddress ?? null,
            })
          } catch {
            if (active) setSendFeePreview(null)
          }
        })()
      }, 250)
      return () => {
        active = false
        clearTimeout(timer)
      }
    }

    // Withdraw tab: strictly require an explicit non-empty positive user-entered amount.
    if (!withdrawAmount.trim()) {
      void Promise.resolve().then(() => {
        if (active) setWithdrawFeePreview(null)
      })
      return () => {
        active = false
      }
    }
    const rawAmt = parseUnits(withdrawAmount, activeMintDecimals)
    if (!rawAmt || rawAmt <= 0n) {
      void Promise.resolve().then(() => {
        if (active) setWithdrawFeePreview(null)
      })
      return () => {
        active = false
      }
    }
    const maxQuoteKey = buildMaxWithdrawKey({
      cluster,
      relayUrl,
      mint: activeMintStr,
      amountStr: withdrawAmount.trim(),
      maxSpendableNotePairStr,
      economyMode,
      unwrapWsol,
      poolPaused: poolPausedFlag,
      missingAtaCount: effectiveRelayedMissingAta,
    })
    if (lastQuotedMaxWithdrawRef.current?.key === maxQuoteKey) {
      return () => {
        active = false
      }
    }
    const totalAvail = BigInt(quoteWithdrawTotalStr || '0')
    const initialOutputCount = computeWithdrawOutputCount({
      amount: rawAmt,
      relayerFee: 0n,
      totalIn: totalAvail,
      economyMode,
      poolPaused: poolPausedFlag,
    })
    const timer = setTimeout(() => {
      const client = new AudrenRelayClient(relayUrl)
      const omitNf1 = economyMode && quoteWithdrawInputCount <= 1
      const unwrapFlag = unwrapWsol && activeMintStr === WSOL_MINT
      const relayScope = `${cluster}|${relayUrl}`
      const pinnedRelayer =
        pinnedRelayerRef.current?.scope === relayScope ? pinnedRelayerRef.current.pubkey : undefined
      client
        .getFeeQuote({
          cluster,
          op: 'withdraw',
          mint: activeMintStr,
          amount: rawAmt.toString(),
          unwrapWsol: unwrapFlag,
          outputCount: initialOutputCount,
          missingAtaCount: effectiveRelayedMissingAta,
          omitNf1,
          ...(pinnedRelayer ? { relayerPubkey: pinnedRelayer } : {}),
        })
        .then(async (fq) => {
          if (!active) return
          const activeRelayer =
            typeof fq.relayerPubkey === 'string' && fq.relayerPubkey ? fq.relayerPubkey : pinnedRelayer
          if (activeRelayer) {
            pinnedRelayerRef.current = { scope: relayScope, pubkey: activeRelayer }
          }
          const validDec = parseValidDecimals(fq.feeDecimals)
          hydrateMintMeta(fq.feeMint || activeMintStr, fq.feeDecimals, fq.feeTokenProgram)
          if (
            (!fq.feeMint || fq.feeMint === activeMintStr) &&
            validDec !== undefined &&
            validDec !== activeMintDecimals
          ) {
            setWithdrawAmount('')
            setWithdrawFeePreview(null)
            lastQuotedMaxWithdrawRef.current = null
            setStatusMsg(
              `Synced on-chain decimals (${validDec}) for ${shortHash(activeMintStr, 4, 4)} (previously ${activeMintDecimals}). Re-enter the amount or click Max.`,
            )
            return
          }
          const fee = BigInt(fq.relayerFee || '0')
          if (
            economyMode &&
            !poolPausedFlag &&
            initialOutputCount === 1 &&
            rawAmt + fee >= totalAvail
          ) {
            try {
              const fq0 = await client.getFeeQuote({
                cluster,
                op: 'withdraw',
                mint: activeMintStr,
                amount: rawAmt.toString(),
                unwrapWsol: unwrapFlag,
                outputCount: 0,
                missingAtaCount: effectiveRelayedMissingAta,
                omitNf1,
                ...(activeRelayer ? { relayerPubkey: activeRelayer } : {}),
              })
              if (!active) return
              const fee0 = BigInt(fq0.relayerFee || '0')
              if (rawAmt + fee0 >= totalAvail) {
                setWithdrawFeePreview({
                  relayerFee: fee0,
                  billingMode: fq0.billingMode,
                  reason: fq0.reason,
                  feeRecipient: fq0.feeRecipient ?? null,
                })
                return
              }
            } catch {
              // Keep initial quote on fallback error
            }
          }
          if (!active) return
          setWithdrawFeePreview({
            relayerFee: fee,
            billingMode: fq.billingMode,
            reason: fq.reason,
            feeRecipient: fq.feeRecipient ?? null,
          })
        })
        .catch(() => {
          if (active) setWithdrawFeePreview(null)
        })
    }, 300)
    return () => {
      active = false
      clearTimeout(timer)
    }
  }, [
    tab,
    useRelayer,
    activeMintNoteCount,
    activeMintStr,
    activeMintDecimals,
    withdrawAmount,
    unwrapWsol,
    economyMode,
    poolPausedFlag,
    effectiveRelayedMissingAta,
    sendQuoteOmitNf1,
    quoteWithdrawInputCount,
    quoteWithdrawTotalStr,
    maxSpendableNotePairStr,
    cluster,
    relayUrl,
    hydrateMintMeta,
    getCachedRelayInfo,
  ])

  const handleClickMaxSend = async () => {
    if (activeMintNotes.length === 0 || maxSpendableNotePair <= 0n) return
    const mySeq = ++maxSendSeqRef.current
    if (!useRelayer) {
      setQuotingMaxSend(false)
      setSendAmount(formatUnitsExact(maxSpendableNotePair, activeMintDecimals))
      return
    }
    const targetCluster = cluster
    const targetMint = activeMintStr
    const startSession = sessionEpochRef.current
    const isCurrent = () =>
      clusterRef.current === targetCluster &&
      sessionEpochRef.current === startSession &&
      maxSendSeqRef.current === mySeq &&
      activeMintRef.current === targetMint
    setQuotingMaxSend(true)
    try {
      const info = await getCachedRelayInfo(targetCluster, relayUrl)
      if (!isCurrent()) return
      // M-2: Sponsored relays without shielded FVK charge 0 fee regardless of mint.
      if (info && !info.relayerShieldedAddress) {
        setSendFeePreview({
          relayerFee: 0n,
          billingMode: 'sponsored',
          reason: 'Relayer sponsors private transfers under rate limits.',
        })
        setSendAmount(formatUnitsExact(maxSpendableNotePair, activeMintDecimals))
        return
      }
      const client = new AudrenRelayClient(relayUrl)
      const maxPairNotes = selectInputNotesForMint(activeMintNotes, maxSpendableNotePair, {
        economyMode,
        preferredNote: manualPreferredNote,
      })
      const omitNf1 = economyMode && (maxPairNotes?.length ?? Math.min(2, activeMintNotes.length)) <= 1
      const relayScope = `${targetCluster}|${relayUrl}`
      const pinnedRelayer =
        pinnedRelayerRef.current?.scope === relayScope ? pinnedRelayerRef.current.pubkey : undefined
      const fq = await client.getFeeQuote({
        cluster: targetCluster,
        op: 'transfer',
        ...(info?.relayerShieldedAddress ? { mint: targetMint } : {}),
        outputCount: 3,
        omitNf1,
        ...(pinnedRelayer ? { relayerPubkey: pinnedRelayer } : {}),
      })
      if (!isCurrent()) return
      if (typeof fq.relayerPubkey === 'string' && fq.relayerPubkey) {
        pinnedRelayerRef.current = { scope: relayScope, pubkey: fq.relayerPubkey }
      }
      const resolvedDecimals = parseValidDecimals(fq.feeDecimals) ?? activeMintDecimals
      if (fq.feeMint) {
        hydrateMintMeta(fq.feeMint, fq.feeDecimals, fq.feeTokenProgram)
      }
      const fee = BigInt(fq.relayerFee || '0')
      setSendFeePreview({
        relayerFee: fee,
        billingMode: fq.billingMode,
        reason: fq.reason,
      })
      const netMax = maxSpendableNotePair > fee ? maxSpendableNotePair - fee : 0n
      setSendAmount(formatUnitsExact(netMax, resolvedDecimals))
    } catch {
      if (!isCurrent()) return
      setSendAmount(formatUnitsExact(maxSpendableNotePair, activeMintDecimals))
    } finally {
      if (maxSendSeqRef.current === mySeq) {
        setQuotingMaxSend(false)
      }
    }
  }

  const handleClickMaxWithdraw = async () => {
    if (activeMintNotes.length === 0 || maxSpendableNotePair <= 0n) return
    const mySeq = ++maxWithdrawSeqRef.current
    if (!useRelayer) {
      setQuotingMaxWithdraw(false)
      lastQuotedMaxWithdrawRef.current = null
      setWithdrawAmount(formatUnitsExact(maxSpendableNotePair, activeMintDecimals))
      return
    }
    const targetCluster = cluster
    const targetMint = activeMintStr
    const startSession = sessionEpochRef.current
    const isCurrent = () =>
      clusterRef.current === targetCluster &&
      sessionEpochRef.current === startSession &&
      maxWithdrawSeqRef.current === mySeq &&
      activeMintRef.current === targetMint
    setQuotingMaxWithdraw(true)
    try {
      const info = await getCachedRelayInfo(targetCluster, relayUrl)
      if (!isCurrent()) return
      const client = new AudrenRelayClient(relayUrl)
      const maxPairNotes = selectInputNotesForMint(activeMintNotes, maxSpendableNotePair, {
        economyMode,
        preferredNote: manualPreferredNote,
      })
      const omitNf1 = economyMode && (maxPairNotes?.length ?? Math.min(2, activeMintNotes.length)) <= 1
      const outputCount = computeWithdrawOutputCount({
        amount: maxSpendableNotePair,
        relayerFee: 0n,
        totalIn: maxSpendableNotePair,
        economyMode,
        poolPaused: poolPausedFlag,
      })
      const relayScope = `${targetCluster}|${relayUrl}`
      const pinnedRelayer =
        pinnedRelayerRef.current?.scope === relayScope ? pinnedRelayerRef.current.pubkey : undefined
      const unwrapFlag = unwrapWsol && targetMint === WSOL_MINT
      const baseSwapFeeBps = BigInt(Math.max(0, Math.trunc(info?.policy?.baseSwapFeeBps ?? 25)))
      const maxSelfPayBps = BigInt(Math.max(1, Math.trunc(info?.policy?.maxSelfPayBps ?? 450)))
      const selfPayMarginBps = BigInt(Math.max(10_000, Math.trunc(info?.policy?.selfPayMarginBps ?? 11_000)))

      // M-2: Solve Max Withdraw fixed-point locally WITHOUT transmitting exact pre-fee
      // `maxSpendableNotePair` to `/v1/fee-quote`!
      //   - For WSOL unwrap (`unwrapFlag`), compute exact fee directly from `/v1/info` rentSchedule + policy (0 `/v1/fee-quote` calls).
      //   - For SPL / Token-2022 mints, query `/v1/fee-quote` with a fixed public reference probe
      //     (1e15 base units) to read the flat rent floor (`neededUnits`), decimals, and allowlist
      //     eligibility, then solve `netMax + fee(netMax) === maxSpendableNotePair` strictly locally.
      let resolvedDecimals = activeMintDecimals
      let finalFee = 0n
      let finalBillingMode: 'self_paying' | 'sponsored' = 'sponsored'
      let finalReason = 'Small or unpriced withdrawal sponsored under relay rate limits.'
      let netMax = maxSpendableNotePair

      const solveLocalFixedPoint = (flatFloorUnits: bigint): {
        net: bigint
        fee: bigint
        selfPaying: boolean
      } => {
        if (flatFloorUnits <= 0n) {
          return { net: maxSpendableNotePair, fee: 0n, selfPaying: false }
        }
        // 1. O(1) percentage-fee regime (`pctFee(net) >= flatFloorUnits`):
        //    For `n0 = floor(total * 10000 / (10000 + bps))`, the maximum feasible `net` with
        //    `net + floor(net * bps / 10000) <= total` is mathematically guaranteed to be
        //    either `n0 + 1` or `n0` (zero linear scan).
        if (baseSwapFeeBps > 0n && baseSwapFeeBps <= maxSelfPayBps) {
          const n0 = (maxSpendableNotePair * 10_000n) / (10_000n + baseSwapFeeBps)
          for (const cand of [n0 + 1n, n0]) {
            if (cand <= 0n) continue
            const pctFee = (cand * baseSwapFeeBps) / 10_000n
            if (
              pctFee >= flatFloorUnits &&
              pctFee < cand &&
              cand + pctFee <= maxSpendableNotePair &&
              (pctFee * 10_000n) / cand <= maxSelfPayBps
            ) {
              return { net: cand, fee: pctFee, selfPaying: true }
            }
          }
        }
        // 2. O(1) flat-floor regime (`pctFee(net) < flatFloorUnits`): `net = total - flatFloorUnits`
        if (maxSpendableNotePair > flatFloorUnits) {
          const candFlatNet = maxSpendableNotePair - flatFloorUnits
          const pctAtFlat = (candFlatNet * baseSwapFeeBps) / 10_000n
          if (
            pctAtFlat <= flatFloorUnits &&
            flatFloorUnits < candFlatNet &&
            (flatFloorUnits * 10_000n) / candFlatNet <= maxSelfPayBps
          ) {
            return { net: candFlatNet, fee: flatFloorUnits, selfPaying: true }
          }
          // 3. O(1) `maxSelfPayBps` cliff band `[threshold, threshold + flatFloorUnits - 1]`:
          //    `maxSpendableNotePair` itself triggers `self_paying` on `/v1/fee-quote`, while
          //    `candFlatNet = total - flatFloorUnits` pays full `flatFloorUnits` on `/v1/submit`
          //    (preserving `quotedMaxFee` for Pause Escape Hatch, missing recipient ATA `setupAtas`,
          //    and economy-mode 0-output residual folding).
          if ((flatFloorUnits * 10_000n) / maxSpendableNotePair <= maxSelfPayBps) {
            return { net: candFlatNet, fee: flatFloorUnits, selfPaying: true }
          }
        }
        return { net: maxSpendableNotePair, fee: 0n, selfPaying: false }
      }

      if (unwrapFlag && info?.rentSchedule) {
        const rs = info.rentSchedule
        const nfCount = omitNf1 ? 1n : 2n
        const nfRent = BigInt(rs.nullifierRentLamports) + BigInt(rs.nfPageRentPerNfLamports ?? '0')
        const noteRent = BigInt(rs.pageRentPerNoteLamports ?? rs.noteRentPerLeafLamports ?? '0')
        const ataRent = BigInt(rs.ataRentLamports)
        const txBase =
          nfCount * nfRent +
          BigInt(outputCount) * noteRent +
          BigInt(effectiveRelayedMissingAta) * ataRent +
          20_000n
        const neededLamports = (txBase * selfPayMarginBps + 9_999n) / 10_000n
        const solved = solveLocalFixedPoint(neededLamports)
        netMax = solved.net
        finalFee = solved.fee
        finalBillingMode = solved.selfPaying ? 'self_paying' : 'sponsored'
        finalReason = solved.selfPaying
          ? 'Self-paying atomic WSOL-unwrap relay fee covers nullifier rent & gas (computed locally from relay schedule).'
          : 'Small action sponsored under relay rate limits.'
      } else {
        // Fixed public probe amount (10^15 base units, independent of user balance) to read
        // exact `minFlatFeeUnits`, decimals, and allowlist eligibility without leaking note size.
        const probeAmount = 1_000_000_000_000_000n
        const fq = await client.getFeeQuote({
          cluster: targetCluster,
          op: 'withdraw',
          mint: targetMint,
          amount: probeAmount.toString(),
          unwrapWsol: unwrapFlag,
          outputCount,
          missingAtaCount: effectiveRelayedMissingAta,
          omitNf1,
          ...(pinnedRelayer ? { relayerPubkey: pinnedRelayer } : {}),
        })
        if (!isCurrent()) return
        const activeRelayer =
          typeof fq.relayerPubkey === 'string' && fq.relayerPubkey ? fq.relayerPubkey : pinnedRelayer
        if (activeRelayer) {
          pinnedRelayerRef.current = { scope: relayScope, pubkey: activeRelayer }
        }
        resolvedDecimals = parseValidDecimals(fq.feeDecimals) ?? activeMintDecimals
        hydrateMintMeta(fq.feeMint || targetMint, fq.feeDecimals, fq.feeTokenProgram)

        let flatFloorUnits = 0n
        if (typeof fq.minFlatFeeUnits === 'string' && /^\d+$/.test(fq.minFlatFeeUnits)) {
          flatFloorUnits = BigInt(fq.minFlatFeeUnits)
        } else if (
          fq.billingMode === 'self_paying' &&
          targetMint === WSOL_MINT &&
          fq.estimatedRelayCostLamports
        ) {
          flatFloorUnits =
            (BigInt(fq.estimatedRelayCostLamports) * selfPayMarginBps + 9_999n) / 10_000n
        } else if (fq.billingMode === 'self_paying' && BigInt(fq.relayerFee || '0') > 0n) {
          const probeFee = BigInt(fq.relayerFee || '0')
          const probePctFee = (probeAmount * baseSwapFeeBps) / 10_000n
          if (probeFee > probePctFee) {
            flatFloorUnits = probeFee
          } else {
            // Fallback for older/third-party relays omitting `minFlatFeeUnits`: step down fixed
            // public buckets independent of user balance; if a step crosses directly into
            // `sponsored` (e.g. narrow `maxSelfPayBps / baseSwapFeeBps <= 10` policy), binary-search
            // `(stepAmt, prevAmt)` to recover the exact flat floor.
            let prevAmt = probeAmount
            let prevFee = probeFee
            let stepAmt = probeAmount / 10n
            let crossedSponsored = false
            for (let step = 0; step < 15 && stepAmt > 0n; step++) {
              const fqStep = await client.getFeeQuote({
                cluster: targetCluster,
                op: 'withdraw',
                mint: targetMint,
                amount: stepAmt.toString(),
                unwrapWsol: unwrapFlag,
                outputCount,
                missingAtaCount: effectiveRelayedMissingAta,
                omitNf1,
                ...(activeRelayer ? { relayerPubkey: activeRelayer } : {}),
              })
              if (!isCurrent()) return
              if (fqStep.billingMode !== 'self_paying') {
                crossedSponsored = true
                let lo = stepAmt
                let hi = prevAmt
                for (let b = 0; b < 8 && hi - lo > 1n; b++) {
                  const mid = lo + (hi - lo) / 2n
                  const fqMid = await client.getFeeQuote({
                    cluster: targetCluster,
                    op: 'withdraw',
                    mint: targetMint,
                    amount: mid.toString(),
                    unwrapWsol: unwrapFlag,
                    outputCount,
                    missingAtaCount: effectiveRelayedMissingAta,
                    omitNf1,
                    ...(activeRelayer ? { relayerPubkey: activeRelayer } : {}),
                  })
                  if (!isCurrent()) return
                  if (fqMid.billingMode === 'self_paying') {
                    const midFee = BigInt(fqMid.relayerFee || '0')
                    const midPct = (mid * baseSwapFeeBps) / 10_000n
                    if (midFee > midPct) {
                      flatFloorUnits = midFee
                      break
                    }
                    hi = mid
                    prevFee = midFee
                  } else {
                    lo = mid
                  }
                }
                if (flatFloorUnits === 0n) {
                  flatFloorUnits = prevFee
                }
                break
              }
              const stepFee = BigInt(fqStep.relayerFee || '0')
              const stepPct = (stepAmt * baseSwapFeeBps) / 10_000n
              if (stepFee > stepPct) {
                flatFloorUnits = stepFee
                break
              }
              prevAmt = stepAmt
              prevFee = stepFee
              stepAmt /= 10n
            }
            if (flatFloorUnits === 0n && !crossedSponsored) {
              flatFloorUnits = 1n
            }
          }
        }

        if (flatFloorUnits > 0n) {
          const solved = solveLocalFixedPoint(flatFloorUnits)
          netMax = solved.net
          finalFee = solved.fee
          finalBillingMode = solved.selfPaying ? 'self_paying' : 'sponsored'
          finalReason = solved.selfPaying
            ? fq.reason
            : 'Small action sponsored under relay rate limits.'
        } else {
          finalBillingMode = 'sponsored'
          finalFee = 0n
          finalReason = fq.reason
          netMax = maxSpendableNotePair
        }
      }

      if (!isCurrent()) return
      const netMaxStr = formatUnitsExact(netMax, resolvedDecimals)
      lastQuotedMaxWithdrawRef.current = {
        key: buildMaxWithdrawKey({
          cluster: targetCluster,
          relayUrl,
          mint: targetMint,
          amountStr: netMaxStr,
          maxSpendableNotePairStr: maxSpendableNotePair.toString(),
          economyMode,
          unwrapWsol,
          poolPaused: poolPausedFlag,
          missingAtaCount: effectiveRelayedMissingAta,
        }),
        quotedFee: finalFee,
        billingMode: finalBillingMode,
      }
      setWithdrawFeePreview({
        relayerFee: finalFee,
        billingMode: finalBillingMode,
        reason: finalReason,
      })
      setWithdrawAmount(netMaxStr)
    } catch {
      if (!isCurrent()) return
      setWithdrawAmount(formatUnitsExact(maxSpendableNotePair, activeMintDecimals))
    } finally {
      if (maxWithdrawSeqRef.current === mySeq) {
        setQuotingMaxWithdraw(false)
      }
    }
  }

  const signAndBroadcastDirect = async (params: {
    mainIxs: AudrenInstruction[]
    openPagePreIxs?: AudrenInstruction[]
    otherPreIxs?: AudrenInstruction[]
    otherPreCuLimit?: number
    mainOnlyCuLimit?: number
    baseCuLimit: number
    combinedCuLimit: number
    lookupTables?: Record<string, string[]>
    expectedSession: number
    targetCluster: SolanaCluster
    onBroadcastStart?: () => void
  }): Promise<{ signature: string; slot: number; pending?: boolean } | null> => {
    const isSessionStillValid = () =>
      sessionEpochRef.current === params.expectedSession &&
      clusterRef.current === params.targetCluster
    if (!connected || !isSessionStillValid()) return null
    const bhRes = await fetch(`/api/rpc/blockhash?cluster=${params.targetCluster}`)
    if (!isSessionStillValid()) return null
    const bh = (await bhRes.json()) as { blockhash?: string; lastValidBlockHeight?: string; error?: string }
    if (!isSessionStillValid()) return null
    if (!bhRes.ok || !bh.blockhash) throw new Error(bh.error ?? 'Failed to fetch recent blockhash')

    const mergedLookupTables: Record<string, string[]> = {
      ...getPool0LookupTable(params.targetCluster),
      ...(params.lookupTables ?? {}),
    }
    const openPages = params.openPagePreIxs ?? []
    const otherPre = params.otherPreIxs ?? []
    const allPre = [...openPages, ...otherPre]
    const combinedIxs = [...allPre, ...params.mainIxs]
    const lastValidBlockHeight = BigInt(bh.lastValidBlockHeight ?? '0')

    let txsToSign: Uint8Array[] | null = null
    if (countUniqueTransactionAccounts(connected.address, combinedIxs) <= 64) {
      try {
        const combinedWire = compileKitV0Transaction({
          feePayer: connected.address,
          recentBlockhash: bh.blockhash,
          lastValidBlockHeight,
          instructions: combinedIxs.map(audrenInstructionToSolana),
          computeUnitLimit: params.combinedCuLimit,
          lookupTables: mergedLookupTables,
        })
        if (combinedWire.byteLength <= 1232) {
          txsToSign = [combinedWire]
        }
      } catch {
        // Fall through to split fallback when idempotent pre-instructions are present
      }
    }

    if (!txsToSign && allPre.length > 0) {
      const otherPreCuLimit = params.otherPreCuLimit ?? otherPre.length * 45_000
      const preCuLimit = Math.min(
        1_400_000,
        openPages.length * CU_LIMIT_OPEN_PAGE + otherPreCuLimit,
      )
      const mainOnlyCuLimit = Math.min(1_400_000, params.mainOnlyCuLimit ?? params.baseCuLimit)
      if (
        countUniqueTransactionAccounts(connected.address, allPre) > 64 ||
        countUniqueTransactionAccounts(connected.address, params.mainIxs) > 64
      ) {
        throw new Error(
          'Direct v0 transaction exceeds the 64-account Solana packet limit even after splitting setup instructions. Enable Privacy Relayer (uses 4,096 B Solana Transaction v1 0x81) or switch to Economy mode (1-input) for compact 1-hop direct swaps.',
        )
      }
      const preWire = compileKitV0Transaction({
        feePayer: connected.address,
        recentBlockhash: bh.blockhash,
        lastValidBlockHeight,
        instructions: allPre.map(audrenInstructionToSolana),
        computeUnitLimit: preCuLimit,
        lookupTables: mergedLookupTables,
      })
      const mainWire = compileKitV0Transaction({
        feePayer: connected.address,
        recentBlockhash: bh.blockhash,
        lastValidBlockHeight,
        instructions: params.mainIxs.map(audrenInstructionToSolana),
        computeUnitLimit: mainOnlyCuLimit,
        lookupTables: mergedLookupTables,
      })
      if (preWire.byteLength > 1232 || mainWire.byteLength > 1232) {
        const offending = Math.max(preWire.byteLength, mainWire.byteLength)
        throw new Error(
          `Direct v0 transaction is ${offending} B (> 1,232 B Solana packet limit) even after splitting setup instructions. Enable Privacy Relayer (uses 4,096 B Solana Transaction v1 0x81) or switch to Economy mode (1-input) for compact 1-hop direct swaps.`,
        )
      }
      txsToSign = [preWire, mainWire]
    }

    if (!txsToSign) {
      let detail = 'exceeds 64 accounts'
      if (countUniqueTransactionAccounts(connected.address, combinedIxs) <= 64) {
        const wire = compileKitV0Transaction({
          feePayer: connected.address,
          recentBlockhash: bh.blockhash,
          lastValidBlockHeight,
          instructions: combinedIxs.map(audrenInstructionToSolana),
          computeUnitLimit: params.combinedCuLimit,
          lookupTables: mergedLookupTables,
        })
        detail = `is ${wire.byteLength} B (> 1,232 B Solana packet limit)`
      }
      throw new Error(
        `Direct v0 transaction ${detail}. Enable Privacy Relayer (uses 4,096 B Solana Transaction v1 0x81) or switch to Economy mode (1-input) for compact 1-hop direct swaps.`,
      )
    }

    if (!isSessionStillValid()) return null
    const signed = await signCompiledTransactionsWithWallet(connected, params.targetCluster, txsToSign)
    if (!isSessionStillValid()) return null
    if (signed.length !== txsToSign.length) throw new Error('Wallet did not sign all transactions')
    params.onBroadcastStart?.()
    const sent = await sendAndConfirmSignedTransactions(params.targetCluster, signed)
    const last = sent[sent.length - 1]
    if (!last) throw new Error('Broadcast returned no signature')
    return { signature: last.signature, slot: last.slot, pending: last.pending }
  }

  const fetchRootSnapshotForNotes = async (
    targetCluster: SolanaCluster,
    notesToSpend: readonly OwnedNote[],
  ): Promise<{
    history: DecodedGlobalRootHistory
    snapshot: RootSnapshotChoice
    commitment: 'finalized' | 'confirmed'
    witnessFetcher: AccountBatchFetcher
  }> => {
    const fetchFinalized = createWorkerBatchFetcher(targetCluster, 'finalized')
    const fetchConfirmed = createWorkerBatchFetcher(targetCluster, 'confirmed')
    const { history, snapshot, commitment } = await fetchGlobalRootHistory({
      poolId: 0,
      programId: AUDREN_PROGRAM_ID,
      fetchFinalized,
      fetchConfirmed,
      requiredNotes: notesToSpend.map((n) => ({ laneId: n.laneId, leafIndex: n.leafIndex })),
    })
    return {
      history,
      snapshot,
      commitment,
      witnessFetcher: commitment === 'finalized' ? fetchFinalized : fetchConfirmed,
    }
  }

  const buildLocalOrRpcWitnesses = async (params: {
    activeStore: CompactWalletStore
    fetcher: AccountBatchFetcher
    history: DecodedGlobalRootHistory
    snapshot: RootSnapshotChoice
    inputNotes: readonly OwnedNote[]
  }): Promise<{
    rootRingKind: number
    rootRingIdx: number
    superRoot: bigint
    paths: MerklePath4Ary[]
  }> => {
    const { activeStore, fetcher, history, snapshot, inputNotes } = params
    try {
      // M-1: Pass full `DecodedGlobalRootHistory` so offline `CompactWalletStore` can fall back
      // from `ROOT_RING_EPOCH` to `ROOT_RING_SLOT` locally without hitting RPC.
      const localBatch = activeStore.buildWitnessesForNotes(inputNotes, history)
      if (localBatch.paths.length === inputNotes.length) {
        return {
          rootRingKind: localBatch.rootRingKind,
          rootRingIdx: localBatch.rootRingIdx,
          superRoot: localBatch.superRoot,
          paths: localBatch.paths,
        }
      }
    } catch {
      // Fall back cleanly to ONE batched decoy-padded RPC reconstruction across all input notes
    }
    const res = await reconstructWitnessesForNotes({
      fetchBatch: fetcher,
      poolId: 0,
      notes: inputNotes.map((n) => ({ laneId: n.laneId, leafIndex: n.leafIndex })),
      rootHistory: history,
      rootSnapshot: snapshot,
      viewSk: keys?.viewSk,
    })
    return {
      rootRingKind: res.rootRingKind,
      rootRingIdx: res.rootRingIdx,
      superRoot: res.superRoot,
      paths: res.paths,
    }
  }

  const handleDeposit = async () => {
    if (busy || connecting || !connected || !keys) return
    if (mainnetEphemeralGateActive) {
      setErrorMsg('Confirm your ephemeral recovery seed backup before depositing on Mainnet.')
      return
    }
    const targetCluster = cluster
    const startSession = sessionEpochRef.current
    const startVaultEpoch = vaultEpochRef.current
    const isSessionActive = () =>
      sessionEpochRef.current === startSession && clusterRef.current === targetCluster
    const isVaultActive = () =>
      vaultEpochRef.current === startVaultEpoch && clusterRef.current === targetCluster
    let broadcastStarted = false
    setBusy(true)
    setErrorMsg(null)
    setStatusMsg(null)
    try {
      const isNativeSol = depositSource === DEPOSIT_NATIVE_SOL
      const targetMint = isNativeSol ? WSOL_MINT : depositSource

      const fetcher = createWorkerBatchFetcher(targetCluster)
      const [poolRaw] = await fetcher([AUDREN.pool0Pda])
      if (!poolRaw) throw new Error(`Pool #0 is not initialized on ${targetCluster} yet`)
      const pool = decodePoolState(poolRaw)
      if (pool.paused) {
        throw new Error('Pool #0 is currently paused; deposits are disabled')
      }
      if (pool.activeLanes === 0) {
        throw new Error(`Pool #0 has no active lanes on ${targetCluster} yet`)
      }
      const poolSnapRes = await fetch(`/api/pool?cluster=${targetCluster}&poolId=0`)
      const poolSnap = (await poolSnapRes.json().catch(() => ({}))) as PoolApiSnapshot
      if (!poolSnapRes.ok || !poolSnap.initialized) {
        throw new Error(
          poolSnap.error ??
            (poolSnapRes.ok
              ? `Pool #0 is not initialized on ${targetCluster} yet`
              : `Failed to fetch Pool #0 snapshot (HTTP ${poolSnapRes.status})`),
        )
      }
      if (!poolSnap.rootHistory) {
        throw new Error('Pool #0 GlobalRootHistory migration in progress; retry shortly')
      }
      if (poolSnap.paused) {
        throw new Error('Pool #0 is currently paused; deposits are disabled')
      }
      if (
        isNativeSol &&
        feeFromAmount &&
        (poolSnap.deterministicNoteRentFee == null || !/^\d+$/.test(poolSnap.deterministicNoteRentFee))
      ) {
        throw new Error('Pool #0 snapshot is missing live deterministic note rent fee; retry before depositing')
      }
      if (!isNativeSol && (poolSnap.currentEpoch == null || !/^\d+$/.test(poolSnap.currentEpoch))) {
        throw new Error('Pool #0 snapshot is missing currentEpoch; retry to read live Token-2022 fees')
      }
      const currentEpoch =
        poolSnap.currentEpoch != null && /^\d+$/.test(poolSnap.currentEpoch)
          ? BigInt(poolSnap.currentEpoch)
          : 0n

      const tok = isNativeSol ? undefined : pubTokens.find((t) => t.mint === targetMint)
      const mintInfo = await resolveMintOnChain(targetCluster, targetMint, currentEpoch)
      if (!isSessionActive()) return
      const decimals = mintInfo.decimals ?? tok?.decimals ?? getTokenMeta(targetMint).decimals
      const amount = parseUnits(depositAmount, decimals)
      if (!amount || amount <= 0n) throw new Error('Enter a valid positive amount')

      const laneId = Number(BigInt(poolSnap.totalNotes ?? '0') % BigInt(pool.activeLanes))
      const targetLane = poolSnap.lanes?.[laneId]
      if (!targetLane) {
        throw new Error(`Pool #0 lane #${laneId} state is unavailable; retry in a moment`)
      }
      const nextLeaf = BigInt(targetLane.nextLeaf)
      const nfCount = BigInt(targetLane.nfCount)
      const subPageSeq = nextLeaf / BigInt(SUBTREE_LEAVES)
      const rootPageSeq = subPageSeq / BigInt(SUBROOTS_PER_PAGE)
      const memoPageSeq = nextLeaf / BigInt(MEMO_NOTES_PER_PAGE)

      const tokenProgram = isNativeSol
        ? CLASSIC_TOKEN_PROGRAM_ID
        : mintInfo.tokenProgram ?? tok?.tokenProgram ?? CLASSIC_TOKEN_PROGRAM_ID
      const vaultAuth = deriveVaultAuthPdaSync(0, AUDREN_PROGRAM_ID).address
      const vaultAta = deriveAssociatedTokenAddressSync(vaultAuth, targetMint, tokenProgram).address

      const openPagePreIxs = await ensureLanePagesPreIxs({
        cluster: targetCluster,
        fetcher,
        payer: connected.address,
        laneId,
        nextLeaf,
        nfCount,
        numOutputs: 1,
        numNfs: 0,
        subSeq: subPageSeq,
        rootSeq: rootPageSeq,
        memoSeq: memoPageSeq,
        nfSeq: 0n,
        includeOutputs: true,
      })
      const [vaultAtaRaw] = await fetcher([vaultAta])
      const ataPreIxs: AudrenInstruction[] = []
      if (!vaultAtaRaw) {
        ataPreIxs.push(
          buildCreateAtaIdempotentInstruction({
            payer: connected.address,
            ata: vaultAta,
            owner: vaultAuth,
            mint: targetMint,
            tokenProgram,
          }),
        )
      }

      const mintBytes = base58Decode(targetMint)
      const detNoteFee =
        isNativeSol && feeFromAmount ? BigInt(poolSnap.deterministicNoteRentFee!) : 0n
      const committedAmount = isNativeSol
        ? feeFromAmount
          ? amount - detNoteFee
          : amount
        : computeToken2022NetAmount(amount, mintInfo.transferFee)
      if (committedAmount <= 0n) {
        throw new Error(
          isNativeSol
            ? `Deposit amount must exceed deterministic note rent fee (${formatUnits(detNoteFee, 9)} SOL)`
            : 'Net deposit amount after Token-2022 TransferFee must be > 0',
        )
      }

      const { tweak, blinding, memo } = encryptNoteMemo(
        keys.viewPk,
        crypto.getRandomValues(new Uint8Array(32)),
        committedAmount,
        mintBytes,
      )
      const stealthOwner = deriveStealthOwner(keys.spendPk, tweak)

      const depositIx = isNativeSol
        ? buildDepositInstruction({
            poolId: 0,
            laneId,
            subPageSeq,
            rootPageSeq,
            memoPageSeq,
            depositor: connected.address,
            nativeSol: true,
            feeFromAmount,
            mint: WSOL_MINT,
            vaultAta,
            tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
            amount,
            stealthOwner,
            blinding,
            memo,
          })
        : buildDepositInstruction({
            poolId: 0,
            laneId,
            subPageSeq,
            rootPageSeq,
            memoPageSeq,
            depositor: connected.address,
            nativeSol: false,
            mint: targetMint,
            sourceAccount:
              tok?.ata ?? deriveAssociatedTokenAddressSync(connected.address, targetMint, tokenProgram).address,
            vaultAta,
            tokenProgram,
            amount,
            stealthOwner,
            blinding,
            memo,
          })

      const depositAtaCu = ataPreIxs.length * (tokenProgram === TOKEN_2022_PROGRAM_ID ? 45_000 : 30_000)
      const depositMainCu = Math.min(
        1_400_000,
        recommendedDepositCuLimit({
          hasTransferHook: mintInfo.hasTransferHook,
          openPageCount: 0,
          createAtaCount: 0,
        }),
      )
      const baseCuLimit = Math.min(1_400_000, depositMainCu + depositAtaCu)
      const combinedCuLimit = Math.min(
        1_400_000,
        recommendedDepositCuLimit({
          hasTransferHook: mintInfo.hasTransferHook,
          openPageCount: openPagePreIxs.length,
          createAtaCount: 0,
        }) + depositAtaCu,
      )

      if (!isSessionActive()) return
      setStatusMsg('Waiting for wallet approval…')
      const res = await signAndBroadcastDirect({
        mainIxs: [depositIx],
        openPagePreIxs,
        otherPreIxs: ataPreIxs,
        otherPreCuLimit: depositAtaCu,
        mainOnlyCuLimit: depositMainCu,
        baseCuLimit,
        combinedCuLimit,
        expectedSession: startSession,
        targetCluster,
        onBroadcastStart: () => {
          broadcastStarted = true
        },
      })

      if (!res || !isVaultActive()) return
      const sym = getTokenMeta(targetMint).symbol
      setLastReceipt({
        kind: isNativeSol
          ? 'Deposit · SOL (Tag 3)'
          : mintInfo.isToken2022
            ? 'Deposit · Token-2022 (Tag 3)'
            : 'Deposit · SPL (Tag 3)',
        signature: res.signature,
        cluster: targetCluster,
        relayed: false,
        pending: res.pending,
        summary: res.pending
          ? `Submitted ${depositAmount} ${sym} deposit to Solana; confirmation timed out at the proxy. Check Solscan and click Sync RPC before retrying.`
          : `Shielded ${depositAmount} ${sym}${mintInfo.isToken2022 ? ' (Token-2022)' : ''} into Pool #0 (instant spend ready)`,
      })
      setStatusMsg(
        res.pending
          ? 'Deposit broadcast submitted (confirmation pending). Syncing CompactWalletStore…'
          : 'Deposit confirmed. Syncing CompactWalletStore…',
      )
      await syncVault(keys, targetCluster, store, walletScope)
      if (!isVaultActive()) return
      await refreshPoolAndBalances(targetCluster, connectedAddrRef.current)
    } catch (err) {
      if (broadcastStarted ? isVaultActive() : isSessionActive()) {
        setErrorMsg(err instanceof Error ? err.message : String(err))
      }
    } finally {
      setBusy(false)
    }
  }

  const handleTransactAction = async (mode: 'send' | 'withdraw') => {
    if (busy || connecting || !keys || !store || activeMintNotes.length === 0) return
    const targetCluster = cluster
    const startSession = sessionEpochRef.current
    const startVaultEpoch = vaultEpochRef.current
    const isSessionActive = () =>
      sessionEpochRef.current === startSession && clusterRef.current === targetCluster
    const isVaultActive = () =>
      vaultEpochRef.current === startVaultEpoch && clusterRef.current === targetCluster
    const isPreSubmitActive = () => (useRelayer ? isVaultActive() : isSessionActive())
    const initialMaxWithdraw = lastQuotedMaxWithdrawRef.current
    let broadcastStarted = false
    setBusy(true)
    setErrorMsg(null)
    setStatusMsg('Loading GlobalRootHistory and building local 4-ary Depth-20 Merkle witness…')
    let sponsoredSkippedRecipientAta = false
    try {
      const mintStr = activeMintStr
      const mintBytes = base58Decode(mintStr)
      const fetcher = createWorkerBatchFetcher(targetCluster)
      const snapRes = await fetch(`/api/pool?cluster=${targetCluster}&poolId=0`)
      const snap = (await snapRes.json().catch(() => ({}))) as PoolApiSnapshot
      if (!snapRes.ok || !snap.initialized) {
        throw new Error(
          snap.error ??
            (snapRes.ok
              ? `Pool #0 is not initialized on ${targetCluster} yet`
              : `Failed to fetch Pool #0 snapshot (HTTP ${snapRes.status})`),
        )
      }
      if (!snap.rootHistory) {
        throw new Error('Pool #0 GlobalRootHistory migration in progress; retry shortly')
      }
      const poolPaused = Boolean(snap.paused)
      if (mode === 'send' && poolPaused) {
        throw new Error('Pool #0 is currently paused; private sends are disabled. Full exits remain open.')
      }
      const activeLanes = snap.activeLanes ?? 0
      if (!Number.isInteger(activeLanes) || activeLanes <= 0) {
        throw new Error(`Pool #0 has no active lanes on ${cluster} yet`)
      }
      if (
        mode === 'withdraw' &&
        !useRelayer &&
        (snap.currentEpoch == null || !/^\d+$/.test(snap.currentEpoch))
      ) {
        throw new Error('Pool #0 snapshot is missing currentEpoch; retry to read live Token-2022 fees')
      }
      const currentEpoch =
        snap.currentEpoch != null && /^\d+$/.test(snap.currentEpoch) ? BigInt(snap.currentEpoch) : 0n
      const localMeta = getTokenMeta(mintStr)
      if (!localMeta.decimalsKnown && !(mode === 'withdraw' && !useRelayer)) {
        throw new Error(
          `On-chain decimals for ${localMeta.symbol} are not resolved yet. Click "Resolve mint decimals" before entering human token amounts.`,
        )
      }
      const wellKnownMint = WELL_KNOWN_TOKENS[mintStr]
      // Privacy invariant: NEVER issue pinpoint `/api/rpc/accounts` mint lookups for Private Send
      // OR for Relayed Withdraw (`useRelayer === true`). In relayed mode, derive `tokenProgram`
      // from bundled `WELL_KNOWN_TOKENS` + the external Privacy Relayer's `/v1/fee-quote` response.
      const mintInfo =
        mode === 'withdraw' && !useRelayer
          ? await resolveMintOnChain(targetCluster, mintStr, currentEpoch)
          : {
              tokenProgram:
                wellKnownMint?.tokenProgram ?? localMeta.tokenProgram ?? CLASSIC_TOKEN_PROGRAM_ID,
              isToken2022:
                (wellKnownMint?.tokenProgram ?? localMeta.tokenProgram) === TOKEN_2022_PROGRAM_ID,
              decimals: wellKnownMint?.decimals ?? localMeta.decimals,
              transferFee: null,
              hasTransferHook: false,
            }
      if (!isPreSubmitActive()) return
      if (mode === 'withdraw' && !useRelayer && mintInfo.decimals !== null) {
        hydrateMintMeta(mintStr, mintInfo.decimals, mintInfo.tokenProgram)
        if (!localMeta.decimalsKnown || mintInfo.decimals !== localMeta.decimals) {
          setWithdrawAmount('')
          lastQuotedMaxWithdrawRef.current = null
          throw new Error(
            `Synced on-chain decimals (${mintInfo.decimals}) for ${localMeta.symbol}. Re-enter the amount or click Max to continue.`,
          )
        }
      }
      const decimals = mintInfo.decimals ?? localMeta.decimals
      const symbol = localMeta.symbol
      const parsedAmount = parseUnits(mode === 'send' ? sendAmount : withdrawAmount, decimals)
      if (!parsedAmount || parsedAmount <= 0n) {
        throw new Error(`Enter a valid positive ${symbol} amount`)
      }
      let amount = parsedAmount

      if (mode === 'send') {
        parseAudrenAddress(sendRecipient.trim())
      }

      const currentWithdrawMaxKey = buildMaxWithdrawKey({
        cluster,
        relayUrl,
        mint: mintStr,
        amountStr: withdrawAmount.trim(),
        maxSpendableNotePairStr: maxSpendableNotePair.toString(),
        economyMode,
        unwrapWsol,
        poolPaused: poolPausedFlag,
        missingAtaCount: effectiveRelayedMissingAta,
      })
      const currentWithdrawMaxKeyLive = buildMaxWithdrawKey({
        cluster,
        relayUrl,
        mint: mintStr,
        amountStr: withdrawAmount.trim(),
        maxSpendableNotePairStr: maxSpendableNotePair.toString(),
        economyMode,
        unwrapWsol,
        poolPaused,
        missingAtaCount: effectiveRelayedMissingAta,
      })
      const wasMaxWithdrawClick =
        mode === 'withdraw' &&
        (initialMaxWithdraw?.key === currentWithdrawMaxKey ||
          initialMaxWithdraw?.key === currentWithdrawMaxKeyLive)
      const quotedMaxFee = wasMaxWithdrawClick ? (initialMaxWithdraw?.quotedFee ?? 0n) : 0n
      const quotedMaxBillingMode = wasMaxWithdrawClick
        ? (initialMaxWithdraw?.billingMode ?? null)
        : null
      const allowCliffMaxSelfPayFold =
        wasMaxWithdrawClick && quotedMaxBillingMode === 'self_paying' && quotedMaxFee > 0n

      // R3-4 Medium #2: When submitting a Max Withdraw that quoted a self-paying fee (including
      // Regime-3 cliff-band balances on 3+ note wallets), select notes covering `amount + quotedMaxFee`
      // upfront so note selection picks the full `maxSpendableNotePair` rather than a smaller pair.
      const initialSelectTarget =
        useRelayer && allowCliffMaxSelfPayFold ? amount + quotedMaxFee : amount
      let inputNotes = selectInputNotesForMint(activeMintNotes, initialSelectTarget, {
        economyMode,
        preferredNote: manualPreferredNote,
        stableLaneCounts,
      })
      if (!inputNotes) {
        throw new Error(
          activeMintNotes.length >= 3 && amount <= activeMintTotal
            ? `Amount spans more than 2 notes (largest pair is ${formatUnits(maxSpendableNotePair, decimals)} ${symbol}). Click "Consolidate notes" to batch up to 4 parallel 2-to-1 merges in one transaction first.`
            : `Amount must be between 0 and ${formatUnits(maxSpendableNotePair, decimals)} ${symbol}`,
        )
      }
      let totalIn = inputNotes.reduce((s, n) => s + n.amount, 0n)
      let omitNf1 = inputNotes.length === 1 && economyMode

      let payerPubkey = connected?.address ?? ''
      let relayerFeeAmount = 0n
      let relayerFeeRecipient: string | null = null
      let feeShieldedAddr: string | null = null
      let needsFeeAtaSetup = false
      let relayerFeeBps = 0
      let relayerFeeRecipientExists = false
      const relayClient = new AudrenRelayClient(relayUrl)

      const isWsolUnwrap = mode === 'withdraw' && mintStr === WSOL_MINT && unwrapWsol
      const assetMode = mode === 'send' ? ASSET_MODE_PRIVATE : ASSET_MODE_PUBLIC
      let tokenProgram = mintInfo.tokenProgram

      const rawRecipient = mode === 'withdraw' ? withdrawRecipient.trim() : null
      if (mode === 'withdraw' && (!rawRecipient || !isValidSolanaPubkey(rawRecipient))) {
        throw new Error('Enter a valid public Solana recipient address')
      }

      const computeBpsRoundingCap = (curTotalIn: bigint, feeBps: number): bigint =>
        feeBps > 0
          ? (((curTotalIn * BigInt(feeBps) + 9_999n) / 10_000n) * BigInt(feeBps + 1)) / 10_000n +
            64n
          : 64n

      const canFoldRoundingResidual = (
        curTotalIn: bigint,
        fee: bigint,
        feeBps: number,
        feeRecipient: string | null,
        feeRecExists: boolean,
      ): boolean => {
        const residual = curTotalIn - amount - fee
        if (residual <= 0n || !feeRecipient) return false
        if (fee === 0n && !feeRecExists && !(allowCliffMaxSelfPayFold && residual >= quotedMaxFee)) {
          return false
        }
        const cap = computeBpsRoundingCap(curTotalIn, feeBps)
        const maxRefFee = fee > quotedMaxFee ? fee : quotedMaxFee
        return residual <= cap || (wasMaxWithdrawClick && residual <= maxRefFee + cap)
      }

      // Privacy invariant: NEVER probe `[recipientPubkey]` against same-origin `/api/rpc/accounts`
      // when using a Privacy Relayer. In relayed mode, rely on `effectiveRelayedMissingAta` +
      // relayer idempotent `setupAtas` so the web host never correlates vault sync with public recipients.
      let missingRecipientAta =
        Boolean(rawRecipient) &&
        assetMode === ASSET_MODE_PUBLIC &&
        !isWsolUnwrap &&
        useRelayer &&
        effectiveRelayedMissingAta === 1

      interface QuotedRelayerFee {
        relayerFee: bigint
        billingMode: 'self_paying' | 'sponsored'
        feeRecipient: string | null
        feeShieldedAddress: string | null
        needsFeeAtaSetup: boolean
        feeBps: number
        feeRecipientExists: boolean
        outputCount: number
      }

      const applyRelayerFeeQuote = (q: QuotedRelayerFee) => {
        relayerFeeAmount = q.relayerFee
        relayerFeeRecipient = q.feeRecipient
        feeShieldedAddr = q.feeShieldedAddress
        needsFeeAtaSetup = q.needsFeeAtaSetup
        relayerFeeBps = q.feeBps
        relayerFeeRecipientExists = q.feeRecipientExists
      }

      let relayerSupportsShieldedSendFee = false
      const quoteRelayerFee = async (
        curOmitNf1: boolean,
        curTotalIn: bigint,
        forcedWithdrawOutputs?: number,
      ): Promise<QuotedRelayerFee> => {
        // M-2: When the relayer has no shielded FVK configured, all private transfers are
        // sponsored at 0 fee regardless of mint or amount. Skip `/v1/fee-quote` so the hidden
        // shielded `mint` is never transmitted to the relayer on submit.
        if (mode === 'send' && !relayerSupportsShieldedSendFee) {
          return {
            relayerFee: 0n,
            billingMode: 'sponsored',
            feeRecipient: null,
            feeShieldedAddress: null,
            needsFeeAtaSetup: false,
            feeBps: 0,
            feeRecipientExists: false,
            outputCount: 3,
          }
        }
        const withdrawOutCount =
          forcedWithdrawOutputs ??
          computeWithdrawOutputCount({
            amount,
            relayerFee: relayerFeeAmount > 0n ? relayerFeeAmount : withdrawFeePreview?.relayerFee ?? 0n,
            totalIn: curTotalIn,
            economyMode,
            poolPaused,
          })
        const fq =
          mode === 'send'
            ? await relayClient.getFeeQuote({
                cluster,
                op: 'transfer',
                mint: mintStr,
                outputCount: 3,
                omitNf1: curOmitNf1,
                relayerPubkey: payerPubkey,
              })
            : await relayClient.getFeeQuote({
                cluster,
                op: 'withdraw',
                mint: mintStr,
                amount: amount.toString(),
                unwrapWsol: isWsolUnwrap,
                outputCount: withdrawOutCount,
                missingAtaCount: missingRecipientAta ? 1 : 0,
                omitNf1: curOmitNf1,
                relayerPubkey: payerPubkey,
              })
        if (
          mode === 'withdraw' &&
          !isWsolUnwrap &&
          (fq.feeTokenProgram === TOKEN_2022_PROGRAM_ID ||
            fq.feeTokenProgram === CLASSIC_TOKEN_PROGRAM_ID)
        ) {
          tokenProgram = fq.feeTokenProgram
        }
        const relayerDecimals = parseValidDecimals(fq.feeDecimals)
        if ((!fq.feeMint || fq.feeMint === mintStr) && isVaultActive()) {
          hydrateMintMeta(mintStr, relayerDecimals, fq.feeTokenProgram)
          if (relayerDecimals !== undefined && relayerDecimals !== decimals) {
            if (mode === 'withdraw') {
              setWithdrawAmount('')
            } else {
              setSendAmount('')
            }
            lastQuotedMaxWithdrawRef.current = null
            throw new Error(
              `Synced on-chain decimals (${relayerDecimals}) for ${symbol} (previously ${decimals}). Re-enter the amount or click Max to continue.`,
            )
          }
        }
        return {
          relayerFee: BigInt(fq.relayerFee || '0'),
          billingMode: fq.billingMode,
          feeRecipient: fq.feeRecipient,
          feeShieldedAddress: fq.feeShieldedAddress,
          needsFeeAtaSetup: Boolean(fq.needsFeeAtaSetup),
          feeBps: typeof fq.feeBps === 'number' ? fq.feeBps : 0,
          feeRecipientExists: Boolean(fq.feeRecipientExists),
          outputCount: mode === 'withdraw' ? withdrawOutCount : 3,
        }
      }

      const reconcileWithdrawEconomyFee = async (
        curOmitNf1: boolean,
        curTotalIn: bigint,
        curQuote: QuotedRelayerFee,
      ): Promise<QuotedRelayerFee> => {
        if (mode !== 'withdraw' || !economyMode || poolPaused) return curQuote
        if (curQuote.outputCount === 0 && amount + curQuote.relayerFee < curTotalIn) {
          if (
            canFoldRoundingResidual(
              curTotalIn,
              curQuote.relayerFee,
              curQuote.feeBps,
              curQuote.feeRecipient,
              curQuote.feeRecipientExists,
            )
          ) {
            const folded: QuotedRelayerFee = { ...curQuote, relayerFee: curTotalIn - amount }
            applyRelayerFeeQuote(folded)
            return folded
          }
          const q1 = await quoteRelayerFee(curOmitNf1, curTotalIn, 1)
          applyRelayerFeeQuote(q1)
          return q1
        }
        if (curQuote.outputCount === 1 && amount + curQuote.relayerFee >= curTotalIn) {
          const q0 = await quoteRelayerFee(curOmitNf1, curTotalIn, 0)
          if (amount + q0.relayerFee >= curTotalIn) {
            applyRelayerFeeQuote(q0)
            return q0
          }
          if (
            canFoldRoundingResidual(
              curTotalIn,
              q0.relayerFee,
              q0.feeBps,
              q0.feeRecipient,
              q0.feeRecipientExists,
            )
          ) {
            const folded: QuotedRelayerFee = { ...q0, relayerFee: curTotalIn - amount }
            applyRelayerFeeQuote(folded)
            return folded
          }
          // Dead-zone `amount + fee0 < curTotalIn <= amount + fee1`: retain `fee1`
          // so we never emit `outputMask = 1` with an underpaid 0-output fee.
          return curQuote
        }
        return curQuote
      }

      let activeQuote: QuotedRelayerFee | null = null
      if (useRelayer) {
        if (!isVaultActive()) return
        setStatusMsg('Querying Privacy Relayer fee quote…')
        const info = await relayClient.getInfo(targetCluster)
        if (!isVaultActive()) return
        if (!info.relayerPubkey) throw new Error(`Relayer at ${relayUrl} has no fee payer for ${targetCluster}`)
        relayerSupportsShieldedSendFee = Boolean(info.relayerShieldedAddress)
        const activePool =
          Array.isArray(info.relayerPubkeys) && info.relayerPubkeys.length > 0
            ? info.relayerPubkeys
            : [info.relayerPubkey]
        const relayScope = `${cluster}|${relayUrl}`
        const pinnedPubkey =
          pinnedRelayerRef.current?.scope === relayScope ? pinnedRelayerRef.current.pubkey : null
        payerPubkey =
          pinnedPubkey && activePool.includes(pinnedPubkey)
            ? pinnedPubkey
            : info.relayerPubkey
        pinnedRelayerRef.current = { scope: relayScope, pubkey: payerPubkey }
        let quotedOmitNf1 = omitNf1
        activeQuote = await quoteRelayerFee(omitNf1, totalIn)
        applyRelayerFeeQuote(activeQuote)
        activeQuote = await reconcileWithdrawEconomyFee(omitNf1, totalIn, activeQuote)

        const getRequiredWithFee = () =>
          amount + (mode === 'send' ? (feeShieldedAddr ? relayerFeeAmount : 0n) : relayerFeeAmount)
        const getNeededOutputCount = () =>
          mode === 'withdraw'
            ? computeWithdrawOutputCount({
                amount,
                relayerFee: relayerFeeAmount,
                totalIn,
                economyMode,
                poolPaused,
              })
            : 3

        for (let pass = 0; pass < 4; pass++) {
          const requiredWithFee = getRequiredWithFee()
          if (totalIn < requiredWithFee) {
            const expanded = selectInputNotesForMint(activeMintNotes, requiredWithFee, {
              economyMode,
              preferredNote: manualPreferredNote,
            })
            if (!expanded) {
              throw new Error(
                mode === 'withdraw'
                  ? `Insufficient note balance to cover withdrawal + relayer fee (${formatUnits(relayerFeeAmount, decimals)} ${symbol}). Click "Max" to auto-fit.`
                  : `Insufficient note balance to cover send + relayer fee (${formatUnits(feeShieldedAddr ? relayerFeeAmount : 0n, decimals)} ${symbol}). Use "Max" to auto-fit.`,
              )
            }
            inputNotes = expanded
            totalIn = inputNotes.reduce((s, n) => s + n.amount, 0n)
          }

          const nextOmitNf1 = inputNotes.length === 1 && economyMode
          omitNf1 = nextOmitNf1
          const neededOutputCount = getNeededOutputCount()
          const needsRequote =
            nextOmitNf1 !== quotedOmitNf1 || neededOutputCount > activeQuote.outputCount

          if (!needsRequote) {
            if (
              mode === 'withdraw' &&
              economyMode &&
              !poolPaused &&
              neededOutputCount < activeQuote.outputCount
            ) {
              activeQuote = await reconcileWithdrawEconomyFee(omitNf1, totalIn, activeQuote)
            }
            if (totalIn >= getRequiredWithFee()) {
              break
            }
            continue
          }

          quotedOmitNf1 = nextOmitNf1
          activeQuote = await quoteRelayerFee(
            omitNf1,
            totalIn,
            mode === 'withdraw' ? neededOutputCount : undefined,
          )
          applyRelayerFeeQuote(activeQuote)
          activeQuote = await reconcileWithdrawEconomyFee(omitNf1, totalIn, activeQuote)

          if (
            totalIn >= getRequiredWithFee() &&
            getNeededOutputCount() <= activeQuote.outputCount &&
            (inputNotes.length === 1 && economyMode) === quotedOmitNf1
          ) {
            break
          }
        }

        if (totalIn < getRequiredWithFee()) {
          throw new Error(
            mode === 'withdraw'
              ? `Insufficient note balance to cover withdrawal + relayer fee (${formatUnits(relayerFeeAmount, decimals)} ${symbol}). Click "Max" to auto-fit.`
              : `Insufficient note balance to cover send + relayer fee (${formatUnits(feeShieldedAddr ? relayerFeeAmount : 0n, decimals)} ${symbol}). Use "Max" to auto-fit.`,
          )
        }

        // Bind submit-time relayer fee and fee recipient against previewed quote and relayer identity.
        if (mode === 'withdraw' && relayerFeeAmount > 0n) {
          const expectedFeeRecipient = isWsolUnwrap
            ? payerPubkey
            : deriveAssociatedTokenAddressSync(payerPubkey, mintStr, tokenProgram).address
          if (!relayerFeeRecipient || relayerFeeRecipient !== expectedFeeRecipient) {
            throw new Error(
              'Relayer returned an unexpected fee recipient that does not match the active relayer fee payer.',
            )
          }
          if (withdrawFeePreview) {
            if (
              withdrawFeePreview.feeRecipient &&
              withdrawFeePreview.feeRecipient !== relayerFeeRecipient
            ) {
              setWithdrawFeePreview({
                relayerFee: relayerFeeAmount,
                billingMode: activeQuote.billingMode,
                reason: 'Fee recipient changed; review and re-submit.',
                feeRecipient: relayerFeeRecipient,
              })
              throw new Error(
                'Relayer fee recipient changed since the fee preview. Review the updated quote and submit again.',
              )
            }
            const maxAllowedFee =
              withdrawFeePreview.relayerFee > 0n
                ? (withdrawFeePreview.relayerFee * 125n) / 100n + 1_000_000n
                : (amount * 5n) / 100n + 10_000_000n
            if (relayerFeeAmount > maxAllowedFee) {
              setWithdrawFeePreview({
                relayerFee: relayerFeeAmount,
                billingMode: activeQuote.billingMode,
                reason: 'Relayer fee increased; review and re-submit.',
                feeRecipient: relayerFeeRecipient,
              })
              throw new Error(
                `Relayer fee increased from ${formatUnits(withdrawFeePreview.relayerFee, decimals)} to ${formatUnits(relayerFeeAmount, decimals)} ${symbol}. Review the updated quote and submit again.`,
              )
            }
          }
        }
        if (mode === 'send' && feeShieldedAddr && relayerFeeAmount > 0n) {
          if (
            sendFeePreview?.feeShieldedAddress &&
            sendFeePreview.feeShieldedAddress !== feeShieldedAddr
          ) {
            setSendFeePreview({
              relayerFee: relayerFeeAmount,
              billingMode: activeQuote.billingMode,
              reason: 'Shielded fee address changed; review and re-submit.',
              feeShieldedAddress: feeShieldedAddr,
            })
            throw new Error(
              'Relayer shielded fee address changed since the preview. Review the updated quote and submit again.',
            )
          }
          if (sendFeePreview) {
            const maxAllowedSendFee =
              sendFeePreview.relayerFee > 0n
                ? (sendFeePreview.relayerFee * 125n) / 100n + 1_000_000n
                : (amount * 5n) / 100n + 10_000_000n
            if (relayerFeeAmount > maxAllowedSendFee) {
              setSendFeePreview({
                relayerFee: relayerFeeAmount,
                billingMode: activeQuote.billingMode,
                reason: 'Relayer fee increased; review and re-submit.',
                feeShieldedAddress: feeShieldedAddr,
              })
              throw new Error(
                `Relayer fee increased from ${formatUnits(sendFeePreview.relayerFee, decimals)} to ${formatUnits(relayerFeeAmount, decimals)} ${symbol}. Review the updated quote and submit again.`,
              )
            }
          }
        }
      } else if (!connected) {
        throw new Error('Enable Privacy Relayer or connect a Solana wallet for Direct Self-Pay')
      }

      const recipientPubkey =
        rawRecipient && assetMode === ASSET_MODE_PUBLIC && !isWsolUnwrap
          ? deriveAssociatedTokenAddressSync(rawRecipient, mintStr, tokenProgram).address
          : rawRecipient

      if (!useRelayer && rawRecipient && recipientPubkey && assetMode === ASSET_MODE_PUBLIC && !isWsolUnwrap) {
        const [recAcc] = await fetcher([recipientPubkey])
        missingRecipientAta = !recAcc
      }

      if (mode === 'withdraw') {
        const residual = totalIn - amount - relayerFeeAmount
        if (poolPaused && residual > 0n) {
          const cap = computeBpsRoundingCap(totalIn, relayerFeeBps)
          const maxRefFee = relayerFeeAmount > quotedMaxFee ? relayerFeeAmount : quotedMaxFee
          const isRoundingOrMaxResidual =
            residual <= cap || (wasMaxWithdrawClick && residual <= maxRefFee + cap)
          if (isRoundingOrMaxResidual) {
            const isSponsoredWithoutMaxSelfPay =
              useRelayer &&
              activeQuote?.billingMode === 'sponsored' &&
              !(wasMaxWithdrawClick && quotedMaxBillingMode === 'self_paying')
            if (isSponsoredWithoutMaxSelfPay) {
              amount += residual
            } else if (
              useRelayer &&
              relayerFeeRecipient &&
              (relayerFeeAmount > 0n ||
                relayerFeeRecipientExists ||
                (allowCliffMaxSelfPayFold && residual >= quotedMaxFee))
            ) {
              relayerFeeAmount += residual
            } else if (!useRelayer || relayerFeeAmount === 0n) {
              amount += residual
            }
          }
        } else if (
          !poolPaused &&
          useRelayer &&
          residual > 0n &&
          (economyMode || (wasMaxWithdrawClick && relayerFeeAmount === 0n)) &&
          canFoldRoundingResidual(
            totalIn,
            relayerFeeAmount,
            relayerFeeBps,
            relayerFeeRecipient,
            relayerFeeRecipientExists,
          )
        ) {
          relayerFeeAmount += residual
        }
      }

      if (mode === 'withdraw' && poolPaused && totalIn - amount - relayerFeeAmount > 0n) {
        throw new Error(
          'Pool #0 is paused: only full note exits (output_mask = 0) are allowed. Click "Max" to withdraw the full note balance.',
        )
      }

      if (inputNotes.length > 1) omitNf1 = false

      const {
        history: rootHistory,
        snapshot: rootSnapshot,
        witnessFetcher,
      } = await fetchRootSnapshotForNotes(cluster, inputNotes)
      const witnessBatch = await buildLocalOrRpcWitnesses({
        activeStore: store,
        fetcher: witnessFetcher,
        history: rootHistory,
        snapshot: rootSnapshot,
        inputNotes,
      })
      const superRoot = witnessBatch.superRoot

      const outLaneId = pickRandomLaneId(activeLanes)
      const outLane = snap.lanes?.[outLaneId]
      if (!outLane) {
        throw new Error(`Pool #0 lane #${outLaneId} state is unavailable; retry in a moment`)
      }
      const outNextLeaf = BigInt(outLane.nextLeaf)
      const outNfCount = BigInt(outLane.nfCount)

      const assetId = deriveAssetId(mintBytes)
      const buildRealInput = (note: OwnedNote, path: MerklePath4Ary): JoinSplitInputWitness => ({
        isDummy: false,
        spendSk: keys.spendSk,
        tweak: frFromBeBytesStrict(note.tweak),
        assetId,
        amount: note.amount,
        blinding: frFromBeBytesStrict(note.blinding),
        merklePath: path,
      })
      const inputs: [JoinSplitInputWitness, JoinSplitInputWitness] = [
        buildRealInput(inputNotes[0]!, witnessBatch.paths[0]!),
        inputNotes[1]
          ? buildRealInput(inputNotes[1]!, witnessBatch.paths[1]!)
          : dummyInputWitness(keys.spendSk, assetId, randomFr()),
      ]

      const outputs: [JoinSplitOutputWitness, JoinSplitOutputWitness, JoinSplitOutputWitness] = [
        dummyOutputWitness(assetId, randomFr()),
        dummyOutputWitness(assetId, randomFr()),
        dummyOutputWitness(assetId, randomFr()),
      ]
      const memos: Uint8Array[] = []
      let outputMask = 0

      if (mode === 'send') {
        const effectiveShieldedFee = feeShieldedAddr ? relayerFeeAmount : 0n
        const rec = parseAudrenAddress(sendRecipient.trim())
        const changeAmt = totalIn - amount - effectiveShieldedFee
        if (changeAmt < 0n) {
          throw new Error(
            `Insufficient note balance to cover send + relayer fee (${formatUnits(effectiveShieldedFee, decimals)} ${symbol}). Use "Max" to auto-fit.`,
          )
        }

        // Uniform outputMask = 0b111: always emit 3 indistinguishable versioned 106 B memos
        // and CSPRNG-shuffle output positions so recipient/change/pad slots are not fixed.
        // Mode 1 shielded relayer fee notes remain in slot 2 (`cm2`) for FVK verification.
        const mRec = encryptNoteMemo(rec.viewPk, crypto.getRandomValues(new Uint8Array(32)), amount, mintBytes)
        const recOwner = deriveStealthOwner(frFromBeBytesStrict(rec.spendPk), mRec.tweak)
        const recSlot = {
          witness: { stealthOwner: recOwner, assetId, amount, blinding: mRec.blinding },
          memo: mRec.memo,
        }

        let changeSlot: { witness: JoinSplitOutputWitness; memo: Uint8Array }
        if (changeAmt > 0n) {
          const mCh = encryptNoteMemo(keys.viewPk, crypto.getRandomValues(new Uint8Array(32)), changeAmt, mintBytes)
          const chOwner = deriveStealthOwner(keys.spendPk, mCh.tweak)
          changeSlot = {
            witness: { stealthOwner: chOwner, assetId, amount: changeAmt, blinding: mCh.blinding },
            memo: mCh.memo,
          }
        } else {
          changeSlot = createZeroDummyOutput(assetId, mintBytes)
        }

        const hasShieldedCm2Fee = effectiveShieldedFee > 0n && Boolean(feeShieldedAddr)
        let thirdSlot: { witness: JoinSplitOutputWitness; memo: Uint8Array }
        if (hasShieldedCm2Fee && feeShieldedAddr) {
          const feeRec = parseAudrenAddress(feeShieldedAddr)
          const mFee = encryptNoteMemo(
            feeRec.viewPk,
            crypto.getRandomValues(new Uint8Array(32)),
            effectiveShieldedFee,
            mintBytes,
          )
          const feeOwner = deriveStealthOwner(frFromBeBytesStrict(feeRec.spendPk), mFee.tweak)
          thirdSlot = {
            witness: { stealthOwner: feeOwner, assetId, amount: effectiveShieldedFee, blinding: mFee.blinding },
            memo: mFee.memo,
          }
        } else {
          thirdSlot = createZeroDummyOutput(assetId, mintBytes)
        }

        const orderedSlots = hasShieldedCm2Fee
          ? [...shuffleWithCsprng([recSlot, changeSlot]), thirdSlot]
          : shuffleWithCsprng([recSlot, changeSlot, thirdSlot])
        outputs[0] = orderedSlots[0]!.witness
        outputs[1] = orderedSlots[1]!.witness
        outputs[2] = orderedSlots[2]!.witness
        memos.push(orderedSlots[0]!.memo, orderedSlots[1]!.memo, orderedSlots[2]!.memo)
        outputMask = 0b111
      } else {
        const changeAmt = totalIn - amount - relayerFeeAmount
        if (changeAmt < 0n) {
          throw new Error(
            `Insufficient note balance to cover withdrawal + relayer fee (${formatUnits(relayerFeeAmount, decimals)} ${symbol}). Click "Max" to auto-fit.`,
          )
        }
        if (changeAmt > 0n) {
          const mCh = encryptNoteMemo(keys.viewPk, crypto.getRandomValues(new Uint8Array(32)), changeAmt, mintBytes)
          const chOwner = deriveStealthOwner(keys.spendPk, mCh.tweak)
          outputs[0] = { stealthOwner: chOwner, assetId, amount: changeAmt, blinding: mCh.blinding }
          outputMask = 1
          memos.push(mCh.memo)
        } else if (!economyMode && !poolPaused) {
          // Default privacy mode on unpaused pools: pad full withdrawals to outputMask = 1
          // so full exits are indistinguishable on-chain from partial withdrawals with change.
          const padCh = createZeroDummyOutput(assetId, mintBytes)
          outputs[0] = padCh.witness
          outputMask = 1
          memos.push(padCh.memo)
        }
      }

      const roll = computePageRollovers({
        leafCount: outNextLeaf,
        outputCount: popcount3(outputMask),
        nfCount: outNfCount,
        spentNullifiers: omitNf1 ? 1 : 2,
      })
      const outSubSeq = BigInt(roll.outSubSeq)
      const outRootSeq = BigInt(roll.outRootSeq)
      const outMemoSeq = BigInt(roll.outMemoSeq)
      const outNfSeq = BigInt(roll.nfPageSeq)
      const nextSubSeq = roll.nextSubSeq !== undefined ? BigInt(roll.nextSubSeq) : null
      const nextRootSeq = roll.nextRootSeq !== undefined ? BigInt(roll.nextRootSeq) : null
      const nextMemoSeq = roll.nextMemoSeq !== undefined ? BigInt(roll.nextMemoSeq) : null
      const nextNfSeq = roll.nextNfSeq !== undefined ? BigInt(roll.nextNfSeq) : null

      const memosConcat = concatBytes(...memos)

      const pubOutAmt = mode === 'withdraw' ? amount : 0n
      const pubFeeAmt = mode === 'withdraw' ? relayerFeeAmount : 0n
      const pubAssetIdBytes = mode === 'withdraw' ? frToBeBytes(assetId) : new Uint8Array(32)

      const ctxHash = computeTransactCtxHash({
        poolId: 0,
        vkId: VK_ID_DEFAULT,
        outLaneId,
        outputMask,
        assetMode,
        unwrapWsol: isWsolUnwrap,
        recipient: recipientPubkey,
        relayerFeeRecipient: pubFeeAmt > 0n ? relayerFeeRecipient : null,
        publicAssetId: pubAssetIdBytes,
        publicAmountOut: pubOutAmt,
        relayerFeeAmount: pubFeeAmt,
        memosBytes: memosConcat,
      })

      if (!isPreSubmitActive()) return
      setStatusMsg('Generating 192-byte BN254 Groth16 proof in Web Worker…')
      const { result, elapsedMs } = await proveJoinsplitInBrowser({
        superRoot,
        txAssetId: assetId,
        publicAssetId: mode === 'withdraw' ? assetId : 0n,
        publicAmountOut: pubOutAmt,
        relayerFeeAmount: pubFeeAmt,
        ctxHash,
        omitNf1,
        inputs,
        outputs,
      })
      if (!isPreSubmitActive()) return

      const vaultAuth = deriveVaultAuthPdaSync(0, AUDREN_PROGRAM_ID).address
      const ix = buildTransactInstruction({
        poolId: 0,
        vkId: VK_ID_DEFAULT,
        rootRingKind: witnessBatch.rootRingKind,
        rootRingIdx: witnessBatch.rootRingIdx,
        outLaneId,
        outSubSeq,
        outRootSeq,
        outMemoSeq,
        outNfSeq,
        rollover: { nextSubSeq, nextMemoSeq, nextNfSeq },
        payer: payerPubkey,
        proof192: result.proof192,
        nf0: result.nf0,
        nf1: result.nf1,
        cm0: result.cm0,
        cm1: result.cm1,
        cm2: result.cm2,
        outputMask,
        assetMode,
        unwrapWsol: isWsolUnwrap,
        publicAmountOut: pubOutAmt,
        relayerFeeAmount: pubFeeAmt,
        memosBytes: memosConcat,
        recipient: recipientPubkey ?? undefined,
        relayerFeeRecipient: pubFeeAmt > 0n ? relayerFeeRecipient ?? undefined : undefined,
        publicOutflow:
          assetMode === ASSET_MODE_PUBLIC
            ? {
                mint: mintStr,
                vaultAta: deriveAssociatedTokenAddressSync(vaultAuth, mintStr, tokenProgram).address,
                tokenProgram,
              }
            : null,
      })

      const hasWithdrawHook =
        assetMode === ASSET_MODE_PUBLIC &&
        !isWsolUnwrap &&
        (mintInfo.hasTransferHook || (useRelayer && tokenProgram === TOKEN_2022_PROGRAM_ID))

      let signature: string
      let receiptPending = false
      if (useRelayer) {
        const setupAtas: RelaySetupAta[] = []
        const hasSelfPayCoverage =
          activeQuote?.billingMode === 'self_paying' ||
          (wasMaxWithdrawClick &&
            quotedMaxBillingMode === 'self_paying' &&
            quotedMaxFee > 0n &&
            pubFeeAmt >= quotedMaxFee)
        if (assetMode === ASSET_MODE_PUBLIC && !isWsolUnwrap) {
          if (missingRecipientAta && pubFeeAmt > 0n && hasSelfPayCoverage && rawRecipient) {
            setupAtas.push({ owner: rawRecipient, mint: mintStr, tokenProgram })
          } else if (missingRecipientAta) {
            sponsoredSkippedRecipientAta = true
          }
          if (pubFeeAmt > 0n && (needsFeeAtaSetup || !relayerFeeRecipientExists)) {
            setupAtas.push({ owner: payerPubkey, mint: mintStr, tokenProgram })
          }
        }
        const relayAtaCu = setupAtas.reduce(
          (sum, ata) => sum + (ata.tokenProgram === TOKEN_2022_PROGRAM_ID ? 45_000 : 30_000),
          0,
        )
        if (!isVaultActive()) return
        setStatusMsg('Submitting zero-signer proof to Privacy Relayer…')
        const sub = await relayClient.submitRelayedInstruction({
          cluster: targetCluster,
          instructionDataB64: toBase64(ix.data),
          accounts: ix.accounts,
          ...(setupAtas.length > 0 ? { setupAtas } : {}),
          computeUnitLimit: Math.min(
            1_400_000,
            recommendedTransactCuLimit({
              assetMode,
              outputMask,
              hasTransferHook: hasWithdrawHook,
              createAtaCount: 0,
            }) + relayAtaCu,
          ),
        })
        signature = sub.signature
      } else {
        const openPagePreIxs = await ensureLanePagesPreIxs({
          cluster: targetCluster,
          fetcher,
          payer: payerPubkey,
          laneId: outLaneId,
          nextLeaf: outNextLeaf,
          nfCount: outNfCount,
          numOutputs: popcount3(outputMask),
          numNfs: omitNf1 ? 1 : 2,
          subSeq: outSubSeq,
          rootSeq: outRootSeq,
          memoSeq: outMemoSeq,
          nfSeq: outNfSeq,
          nextSubSeq,
          nextRootSeq,
          nextMemoSeq,
          nextNfSeq,
          includeOutputs: outputMask !== 0,
        })
        if (!isSessionActive()) return
        const otherPreIxs: AudrenInstruction[] = []
        if (missingRecipientAta && rawRecipient && recipientPubkey) {
          otherPreIxs.push(
            buildCreateAtaIdempotentInstruction({
              payer: payerPubkey,
              ata: recipientPubkey,
              owner: rawRecipient,
              mint: mintStr,
              tokenProgram,
            }),
          )
        }
        const directAtaCu =
          otherPreIxs.length * (tokenProgram === TOKEN_2022_PROGRAM_ID ? 45_000 : 30_000)
        const transactMainCu = Math.min(
          1_400_000,
          recommendedTransactCuLimit({
            assetMode,
            outputMask,
            hasTransferHook: hasWithdrawHook,
            openPageCount: 0,
            createAtaCount: 0,
          }),
        )
        const baseCuLimit = Math.min(1_400_000, transactMainCu + directAtaCu)
        const combinedCuLimit = Math.min(
          1_400_000,
          recommendedTransactCuLimit({
            assetMode,
            outputMask,
            hasTransferHook: hasWithdrawHook,
            openPageCount: openPagePreIxs.length,
            createAtaCount: 0,
          }) + directAtaCu,
        )
        if (!isSessionActive()) return
        setStatusMsg('Waiting for wallet approval…')
        const sent = await signAndBroadcastDirect({
          mainIxs: [ix],
          openPagePreIxs,
          otherPreIxs,
          otherPreCuLimit: directAtaCu,
          mainOnlyCuLimit: transactMainCu,
          baseCuLimit,
          combinedCuLimit,
          expectedSession: startSession,
          targetCluster,
          onBroadcastStart: () => {
            broadcastStarted = true
          },
        })
        if (!sent) return
        signature = sent.signature
        receiptPending = Boolean(sent.pending)
      }

      if (!isVaultActive()) return
      if (mode === 'withdraw') {
        lastQuotedMaxWithdrawRef.current = null
      }
      setLastReceipt({
        kind: mode === 'send' ? 'Transact Private Transfer (Tag 5)' : 'Transact Withdraw (Tag 5)',
        signature,
        cluster: targetCluster,
        proverMs: elapsedMs,
        relayed: useRelayer,
        pending: receiptPending,
        summary: receiptPending
          ? 'Transaction submitted to Solana; confirmation timed out at the proxy. Check Solscan and click Sync RPC before retrying.'
          : mode === 'send'
            ? `Sent ${sendAmount} ${symbol} privately (${inputNotes.length} ${inputNotes.length === 1 ? 'note' : 'notes'} · 192 B Groth16 · ${witnessBatch.rootRingKind === ROOT_RING_EPOCH ? 'epoch' : 'slot'} ring #${witnessBatch.rootRingIdx})`
            : `Withdrew ${withdrawAmount} ${symbol}${isWsolUnwrap ? ' as native SOL' : ''}${inputNotes.length === 2 ? ' (2-note consolidation)' : ''}`,
      })
      setStatusMsg(
        receiptPending
          ? 'Broadcast submitted (confirmation pending). Syncing CompactWalletStore…'
          : 'Confirmed. Syncing CompactWalletStore…',
      )
      await syncVault(keys, targetCluster, store, walletScope)
      if (!isVaultActive()) return
      await refreshPoolAndBalances(targetCluster, connectedAddrRef.current)
    } catch (err) {
      if (useRelayer || broadcastStarted ? isVaultActive() : isSessionActive()) {
        if (err instanceof AudrenRelayError && err.code === 'BROADCAST_AMBIGUOUS' && err.signature) {
          setLastReceipt({
            kind: mode === 'send' ? 'Transact Private Transfer (Tag 5)' : 'Transact Withdraw (Tag 5)',
            signature: err.signature,
            cluster: targetCluster,
            relayed: true,
            pending: true,
            summary:
              'Relayer broadcast outcome is pending confirmation on Solana. Check Solscan and click Sync RPC before retrying so you do not resubmit the same spend.',
          })
          setStatusMsg('Relayed broadcast is pending confirmation. Syncing CompactWalletStore…')
          void syncVault(keys, targetCluster, store, walletScope).catch(() => {})
          return
        }
        const rawMsg = formatUserActionError(err)
        if (
          sponsoredSkippedRecipientAta &&
          /AccountNotInitialized|InvalidAccountData|UninitializedAccount|InvalidAccountOwner|InvalidTokenAccount|6020|0x1784/i.test(
            rawMsg,
          )
        ) {
          setErrorMsg(
            `Recipient token account does not exist yet. Sponsored relays cannot create new recipient token accounts; switch to Direct Self-Pay or withdraw a self-paying amount instead. (${rawMsg})`,
          )
        } else {
          setErrorMsg(rawMsg)
        }
      }
    } finally {
      setBusy(false)
    }
  }

  /**
   * Batch up to 4 parallel 2 -> 1 private `Transact` merges into a single Solana Transaction v1
   * via `submitRelayedInstruction({ instructions })` (or single-prompt multi-tx signing in Direct mode).
   */
  const handleBatchMergeNotes = async (mintStr: string) => {
    if (busy || connecting || !keys || !store) return
    const candidates = unspentNotes
      .filter((n) => base58Encode(n.mint) === mintStr)
      .sort((a, b) => (a.amount < b.amount ? -1 : a.amount > b.amount ? 1 : 0))
    if (candidates.length < 2) return

    const info = getTokenMeta(mintStr)
    const mintBytes = base58Decode(mintStr)
    const targetCluster = cluster
    const startSession = sessionEpochRef.current
    const startVaultEpoch = vaultEpochRef.current
    const isSessionActive = () =>
      sessionEpochRef.current === startSession && clusterRef.current === targetCluster
    const isVaultActive = () =>
      vaultEpochRef.current === startVaultEpoch && clusterRef.current === targetCluster
    const isPreSubmitActive = () => (useRelayer ? isVaultActive() : isSessionActive())
    let broadcastStarted = false
    let confirmedDirectTxs = 0

    setBusy(true)
    setErrorMsg(null)
    try {
      const fetcher = createWorkerBatchFetcher(targetCluster)
      const snapRes = await fetch(`/api/pool?cluster=${targetCluster}&poolId=0`)
      const snap = (await snapRes.json().catch(() => ({}))) as PoolApiSnapshot
      if (!snapRes.ok || !snap.initialized) {
        throw new Error(
          snap.error ??
            (snapRes.ok
              ? `Pool #0 is not initialized on ${targetCluster} yet`
              : `Failed to fetch Pool #0 snapshot (HTTP ${snapRes.status})`),
        )
      }
      if (!snap.rootHistory) {
        throw new Error('Pool #0 GlobalRootHistory migration in progress; retry shortly')
      }
      if (snap.paused) {
        throw new Error('Pool #0 is currently paused; note consolidation is disabled')
      }
      const activeLanes = snap.activeLanes ?? 0
      if (!Number.isInteger(activeLanes) || activeLanes <= 0) {
        throw new Error(`Pool #0 has no active lanes on ${cluster} yet`)
      }
      let decimals = info.decimals

      const relayClient = new AudrenRelayClient(relayUrl)
      let payerPubkey = connected?.address ?? ''
      let relayerFeePerIx = 0n
      let feeShieldedAddr: string | null = null
      let candidateMaxBatch = Math.min(
        MAX_PARALLEL_MERGE_IXS,
        activeLanes,
        Math.floor(candidates.length / 2),
      )
      let initialQuotedOutputs = candidateMaxBatch > 1 ? 2 : 3
      let singleMergeFallbackNote: string | null = null

      if (useRelayer) {
        if (!isVaultActive()) return
        setStatusMsg('Querying Privacy Relayer fee quote…')
        const relayInfo = await relayClient.getInfo(targetCluster)
        if (!isVaultActive()) return
        if (!relayInfo.relayerPubkey) {
          throw new Error(`Relayer at ${relayUrl} has no fee payer for ${targetCluster}`)
        }
        // H-6: Respect `supportedOperations.transfer.maxBatchSize` advertised by `/v1/info`
        // (1 when relayer has no shielded FVK; up to 4 when shielded cm2 fees are enabled).
        const relayMaxBatch =
          typeof relayInfo.supportedOperations?.transfer?.maxBatchSize === 'number' &&
          relayInfo.supportedOperations.transfer.maxBatchSize >= 1
            ? Math.trunc(relayInfo.supportedOperations.transfer.maxBatchSize)
            : relayInfo.relayerShieldedAddress
              ? MAX_PARALLEL_MERGE_IXS
              : 1
        if (candidateMaxBatch > relayMaxBatch) {
          candidateMaxBatch = relayMaxBatch
          initialQuotedOutputs = candidateMaxBatch > 1 ? 2 : 3
          if (relayMaxBatch === 1) {
            singleMergeFallbackNote =
              'Relayer advertises single-merge mode (maxBatchSize = 1); running one 2-to-1 merge.'
          }
        }
        const activePool =
          Array.isArray(relayInfo.relayerPubkeys) && relayInfo.relayerPubkeys.length > 0
            ? relayInfo.relayerPubkeys
            : [relayInfo.relayerPubkey]
        const relayScope = `${targetCluster}|${relayUrl}`
        const pinnedPubkey =
          pinnedRelayerRef.current?.scope === relayScope ? pinnedRelayerRef.current.pubkey : null
        payerPubkey =
          pinnedPubkey && activePool.includes(pinnedPubkey)
            ? pinnedPubkey
            : relayInfo.relayerPubkey
        pinnedRelayerRef.current = { scope: relayScope, pubkey: payerPubkey }
        if (relayInfo.relayerShieldedAddress) {
          const fq = await relayClient.getFeeQuote({
            cluster: targetCluster,
            op: 'transfer',
            mint: mintStr,
            outputCount: initialQuotedOutputs,
            omitNf1: false,
            relayerPubkey: payerPubkey,
          })
          if (!isVaultActive()) return
          hydrateMintMeta(fq.feeMint || mintStr, fq.feeDecimals, fq.feeTokenProgram)
          decimals = parseValidDecimals(fq.feeDecimals) ?? decimals
          relayerFeePerIx = BigInt(fq.relayerFee || '0')
          feeShieldedAddr = fq.feeShieldedAddress
        } else {
          relayerFeePerIx = 0n
          feeShieldedAddr = null
        }
      } else if (!connected) {
        throw new Error('Enable Privacy Relayer or connect a Solana wallet to consolidate notes')
      }

      // Dust-safe greedy pairing: if the two smallest notes cannot cover `feePerIx`,
      // pair the smallest dust note with the largest remaining note so dust never dead-ends.
      const buildValidPairs = (feePerIx: bigint, maxPairs: number): Array<[OwnedNote, OwnedNote]> => {
        const remaining = [...candidates]
        const pairs: Array<[OwnedNote, OwnedNote]> = []
        while (pairs.length < maxPairs && remaining.length >= 2) {
          const smallest = remaining[0]!
          const nextSmallest = remaining[1]!
          if (smallest.amount + nextSmallest.amount > feePerIx) {
            pairs.push([smallest, nextSmallest])
            remaining.splice(0, 2)
          } else {
            const largest = remaining[remaining.length - 1]!
            if (smallest.amount + largest.amount > feePerIx) {
              pairs.push([smallest, largest])
              remaining.pop()
              remaining.shift()
            } else {
              remaining.shift()
            }
          }
        }
        return pairs
      }

      let effectiveShieldedFee = useRelayer && feeShieldedAddr ? relayerFeePerIx : 0n
      // Relayer requires self-paying fees for multi-ix batches (`isSelfPaying === true`).
      // Cap batch size to 1 whenever sponsored / Devnet / unpriced (`effectiveShieldedFee === 0n`).
      const maxBatch = useRelayer && effectiveShieldedFee === 0n ? 1 : candidateMaxBatch
      let validPairs = buildValidPairs(effectiveShieldedFee, maxBatch)
      if (validPairs.length === 0) {
        throw new Error(
          `No ${info.symbol} note pair exceeds the relayer fee (${formatUnits(effectiveShieldedFee, decimals)} ${info.symbol}).`,
        )
      }

      // Single-instruction merges keep uniform 3-output `0b111` padding; re-quote for 3 outputs
      // if we initially quoted `outputCount: 2` for a multi-ix batch that collapsed to 1 pair
      // (skipping when the relayer has no shielded FVK so the hidden mint is never leaked).
      if (useRelayer && feeShieldedAddr && validPairs.length === 1 && initialQuotedOutputs !== 3) {
        const fq3 = await relayClient.getFeeQuote({
          cluster: targetCluster,
          op: 'transfer',
          mint: mintStr,
          outputCount: 3,
          omitNf1: false,
          relayerPubkey: payerPubkey,
        })
        if (!isVaultActive()) return
        relayerFeePerIx = BigInt(fq3.relayerFee || '0')
        feeShieldedAddr = fq3.feeShieldedAddress
        effectiveShieldedFee = feeShieldedAddr ? relayerFeePerIx : 0n
        validPairs = buildValidPairs(effectiveShieldedFee, 1)
        if (validPairs.length === 0) {
          throw new Error(
            `No ${info.symbol} note pair exceeds the relayer fee (${formatUnits(effectiveShieldedFee, decimals)} ${info.symbol}).`,
          )
        }
      }

      // Multi-instruction relayed batches (`2..4` parallel merges) omit dummy `pad1` (`outputMask = 0b101`:
      // `cm0` merged note + `cm2` shielded relayer fee = 2 outputs, matching relayer `MAX_BATCH_OUTPUTS_PER_IX = 2`).
      // Single merges (`validPairs.length === 1`) keep uniform 3-output `0b111` padding.
      const isMultiIxBatch = validPairs.length > 1
      const mergeOutputCount = isMultiIxBatch ? 2 : 3
      const mergeOutputMask = isMultiIxBatch ? 0b101 : 0b111

      const activeInputs = validPairs.flat()
      if (!isPreSubmitActive()) return
      setStatusMsg(
        singleMergeFallbackNote ??
          `Consolidating ${activeInputs.length} ${info.symbol} notes via ${validPairs.length} parallel 2-to-1 ${validPairs.length === 1 ? 'merge' : 'merges'}…`,
      )
      const {
        history: rootHistory,
        snapshot: rootSnapshot,
        witnessFetcher,
      } = await fetchRootSnapshotForNotes(targetCluster, activeInputs)
      if (!isPreSubmitActive()) return

      const witnessBatch = await buildLocalOrRpcWitnesses({
        activeStore: store,
        fetcher: witnessFetcher,
        history: rootHistory,
        snapshot: rootSnapshot,
        inputNotes: activeInputs,
      })

      // Assign distinct random output lanes so every merge in the batch updates disjoint lane pages
      const outLaneIds = pickDistinctRandomLanes(activeLanes, validPairs.length)
      const assetId = deriveAssetId(mintBytes)

      const builtMerges: Array<{
        ix: AudrenInstruction
        outLaneId: number
        outNextLeaf: bigint
        outNfCount: bigint
        outSubSeq: bigint
        outRootSeq: bigint
        outMemoSeq: bigint
        outNfSeq: bigint
        nextSubSeq: bigint | null
        nextRootSeq: bigint | null
        nextMemoSeq: bigint | null
        nextNfSeq: bigint | null
      }> = []

      let totalProverMs = 0
      let totalMergedOut = 0n

      for (let k = 0; k < validPairs.length; k++) {
        const [noteA, noteB] = validPairs[k]!
        const pathA = witnessBatch.paths[2 * k]!
        const pathB = witnessBatch.paths[2 * k + 1]!
        const outLaneId = outLaneIds[k]!
        const outLane = snap.lanes?.[outLaneId]
        if (!outLane) {
          throw new Error(`Pool #0 lane #${outLaneId} state is unavailable; retry in a moment`)
        }
        const outNextLeaf = BigInt(outLane.nextLeaf)
        const outNfCount = BigInt(outLane.nfCount)

        const roll = computePageRollovers({
          leafCount: outNextLeaf,
          outputCount: mergeOutputCount,
          nfCount: outNfCount,
          spentNullifiers: 2,
        })
        const outSubSeq = BigInt(roll.outSubSeq)
        const outRootSeq = BigInt(roll.outRootSeq)
        const outMemoSeq = BigInt(roll.outMemoSeq)
        const outNfSeq = BigInt(roll.nfPageSeq)
        const nextSubSeq = roll.nextSubSeq !== undefined ? BigInt(roll.nextSubSeq) : null
        const nextRootSeq = roll.nextRootSeq !== undefined ? BigInt(roll.nextRootSeq) : null
        const nextMemoSeq = roll.nextMemoSeq !== undefined ? BigInt(roll.nextMemoSeq) : null
        const nextNfSeq = roll.nextNfSeq !== undefined ? BigInt(roll.nextNfSeq) : null

        const mergedAmount = noteA.amount + noteB.amount - effectiveShieldedFee
        totalMergedOut += mergedAmount

        const mSelf = encryptNoteMemo(
          keys.viewPk,
          crypto.getRandomValues(new Uint8Array(32)),
          mergedAmount,
          mintBytes,
        )
        const selfOwner = deriveStealthOwner(keys.spendPk, mSelf.tweak)
        const pad1 = isMultiIxBatch ? null : createZeroDummyOutput(assetId, mintBytes)
        const out1Witness = pad1 ? pad1.witness : dummyOutputWitness(assetId, randomFr())

        let out2Witness: JoinSplitOutputWitness
        let out2Memo: Uint8Array
        if (effectiveShieldedFee > 0n && feeShieldedAddr) {
          const feeRec = parseAudrenAddress(feeShieldedAddr)
          const mFee = encryptNoteMemo(
            feeRec.viewPk,
            crypto.getRandomValues(new Uint8Array(32)),
            effectiveShieldedFee,
            mintBytes,
          )
          out2Witness = {
            stealthOwner: deriveStealthOwner(frFromBeBytesStrict(feeRec.spendPk), mFee.tweak),
            assetId,
            amount: effectiveShieldedFee,
            blinding: mFee.blinding,
          }
          out2Memo = mFee.memo
        } else {
          const pad2 = createZeroDummyOutput(assetId, mintBytes)
          out2Witness = pad2.witness
          out2Memo = pad2.memo
        }

        const memosConcat = pad1
          ? concatBytes(mSelf.memo, pad1.memo, out2Memo)
          : concatBytes(mSelf.memo, out2Memo)
        const ctxHash = computeTransactCtxHash({
          poolId: 0,
          vkId: VK_ID_DEFAULT,
          outLaneId,
          outputMask: mergeOutputMask,
          assetMode: ASSET_MODE_PRIVATE,
          unwrapWsol: false,
          recipient: null,
          relayerFeeRecipient: null,
          publicAssetId: new Uint8Array(32),
          publicAmountOut: 0n,
          relayerFeeAmount: 0n,
          memosBytes: memosConcat,
        })

        if (!isPreSubmitActive()) return
        setStatusMsg(
          `Proving merge ${k + 1} of ${validPairs.length} in Web Worker…`,
        )
        const { result, elapsedMs } = await proveJoinsplitInBrowser({
          superRoot: witnessBatch.superRoot,
          txAssetId: assetId,
          publicAssetId: 0n,
          publicAmountOut: 0n,
          relayerFeeAmount: 0n,
          ctxHash,
          omitNf1: false,
          inputs: [
            {
              isDummy: false,
              spendSk: keys.spendSk,
              tweak: frFromBeBytesStrict(noteA.tweak),
              assetId,
              amount: noteA.amount,
              blinding: frFromBeBytesStrict(noteA.blinding),
              merklePath: pathA,
            },
            {
              isDummy: false,
              spendSk: keys.spendSk,
              tweak: frFromBeBytesStrict(noteB.tweak),
              assetId,
              amount: noteB.amount,
              blinding: frFromBeBytesStrict(noteB.blinding),
              merklePath: pathB,
            },
          ],
          outputs: [
            { stealthOwner: selfOwner, assetId, amount: mergedAmount, blinding: mSelf.blinding },
            out1Witness,
            out2Witness,
          ],
        })
        totalProverMs += elapsedMs

        const ix = buildTransactInstruction({
          poolId: 0,
          vkId: VK_ID_DEFAULT,
          rootRingKind: witnessBatch.rootRingKind,
          rootRingIdx: witnessBatch.rootRingIdx,
          outLaneId,
          outSubSeq,
          outRootSeq,
          outMemoSeq,
          outNfSeq,
          rollover: { nextSubSeq, nextMemoSeq, nextNfSeq },
          payer: payerPubkey,
          proof192: result.proof192,
          nf0: result.nf0,
          nf1: result.nf1,
          cm0: result.cm0,
          cm1: result.cm1,
          cm2: result.cm2,
          outputMask: mergeOutputMask,
          assetMode: ASSET_MODE_PRIVATE,
          unwrapWsol: false,
          publicAmountOut: 0n,
          relayerFeeAmount: 0n,
          memosBytes: memosConcat,
        })

        builtMerges.push({
          ix,
          outLaneId,
          outNextLeaf,
          outNfCount,
          outSubSeq,
          outRootSeq,
          outMemoSeq,
          outNfSeq,
          nextSubSeq,
          nextRootSeq,
          nextMemoSeq,
          nextNfSeq,
        })
      }

      let signature: string
      let mergePending = false
      if (useRelayer) {
        if (!isVaultActive()) return
        const payloads: RelayInstructionPayload[] = builtMerges.map((m) => ({
          instructionDataB64: toBase64(m.ix.data),
          accounts: m.ix.accounts,
        }))
        setStatusMsg(
          `Submitting ${payloads.length} parallel ${payloads.length === 1 ? 'merge' : 'merges'} in 1 Solana Transaction v1 to Privacy Relayer…`,
        )
        const singleMergeCu = recommendedTransactCuLimit({
          assetMode: ASSET_MODE_PRIVATE,
          outputMask: mergeOutputMask,
        })
        const batchCuLimit = Math.min(1_400_000, payloads.length * CU_LIMIT_TRANSACT_PRIVATE)
        const sub =
          payloads.length === 1
            ? await relayClient.submitRelayedInstruction({
                cluster: targetCluster,
                instructionDataB64: payloads[0]!.instructionDataB64,
                accounts: payloads[0]!.accounts,
                computeUnitLimit: singleMergeCu,
              })
            : await relayClient.submitRelayedInstruction({
                cluster: targetCluster,
                instructions: payloads,
                computeUnitLimit: batchCuLimit,
              })
        signature = sub.signature
      } else {
        if (!isSessionActive()) return
        if (!connected) throw new Error('Connect a Solana wallet to sign direct merge transactions')
        const bhRes = await fetch(`/api/rpc/blockhash?cluster=${targetCluster}`)
        if (!isSessionActive()) return
        const bh = (await bhRes.json()) as { blockhash?: string; lastValidBlockHeight?: string; error?: string }
        if (!isSessionActive()) return
        if (!bhRes.ok || !bh.blockhash) throw new Error(bh.error ?? 'Failed to fetch recent blockhash')
        const unsignedTxs: Uint8Array[] = []
        const pool0LookupTables = getPool0LookupTable(targetCluster)
        const lastValidBlockHeight = BigInt(bh.lastValidBlockHeight ?? '0')
        for (const m of builtMerges) {
          const openPagePreIxs = await ensureLanePagesPreIxs({
            cluster: targetCluster,
            fetcher,
            payer: payerPubkey,
            laneId: m.outLaneId,
            nextLeaf: m.outNextLeaf,
            nfCount: m.outNfCount,
            numOutputs: mergeOutputCount,
            numNfs: 2,
            subSeq: m.outSubSeq,
            rootSeq: m.outRootSeq,
            memoSeq: m.outMemoSeq,
            nfSeq: m.outNfSeq,
            nextSubSeq: m.nextSubSeq,
            nextRootSeq: m.nextRootSeq,
            nextMemoSeq: m.nextMemoSeq,
            nextNfSeq: m.nextNfSeq,
            includeOutputs: true,
          })
          if (!isSessionActive()) return
          const baseCu = recommendedTransactCuLimit({
            assetMode: ASSET_MODE_PRIVATE,
            outputMask: mergeOutputMask,
            openPageCount: 0,
          })
          const combinedCu = recommendedTransactCuLimit({
            assetMode: ASSET_MODE_PRIVATE,
            outputMask: mergeOutputMask,
            openPageCount: openPagePreIxs.length,
          })
          const combinedIxs = [...openPagePreIxs, m.ix]
          let combinedWire: Uint8Array | null = null
          if (countUniqueTransactionAccounts(connected.address, combinedIxs) <= 64) {
            try {
              const w = compileKitV0Transaction({
                feePayer: connected.address,
                recentBlockhash: bh.blockhash,
                lastValidBlockHeight,
                instructions: combinedIxs.map(audrenInstructionToSolana),
                computeUnitLimit: combinedCu,
                lookupTables: pool0LookupTables,
              })
              if (w.byteLength <= 1232) combinedWire = w
            } catch {
              // Fall back to separate preceding OpenPage tx
            }
          }
          if (combinedWire) {
            unsignedTxs.push(combinedWire)
          } else if (openPagePreIxs.length > 0) {
            const openWire = compileKitV0Transaction({
              feePayer: connected.address,
              recentBlockhash: bh.blockhash,
              lastValidBlockHeight,
              instructions: openPagePreIxs.map(audrenInstructionToSolana),
              computeUnitLimit: Math.min(1_400_000, openPagePreIxs.length * CU_LIMIT_OPEN_PAGE),
              lookupTables: pool0LookupTables,
            })
            const mainWire = compileKitV0Transaction({
              feePayer: connected.address,
              recentBlockhash: bh.blockhash,
              lastValidBlockHeight,
              instructions: [m.ix].map(audrenInstructionToSolana),
              computeUnitLimit: baseCu,
              lookupTables: pool0LookupTables,
            })
            if (openWire.byteLength > 1232 || mainWire.byteLength > 1232) {
              throw new Error(
                `Direct v0 merge transaction is ${Math.max(openWire.byteLength, mainWire.byteLength)} B (> 1,232 B Solana packet limit). Enable Privacy Relayer (uses 4,096 B Solana Transaction v1 0x81) to execute this consolidation.`,
              )
            }
            unsignedTxs.push(openWire, mainWire)
          } else {
            const w = compileKitV0Transaction({
              feePayer: connected.address,
              recentBlockhash: bh.blockhash,
              lastValidBlockHeight,
              instructions: [m.ix].map(audrenInstructionToSolana),
              computeUnitLimit: baseCu,
              lookupTables: pool0LookupTables,
            })
            throw new Error(
              `Direct v0 merge transaction #${unsignedTxs.length + 1} is ${w.byteLength} B (> 1,232 B Solana packet limit). Enable Privacy Relayer (uses 4,096 B Solana Transaction v1 0x81) to execute this consolidation.`,
            )
          }
        }
        if (!isSessionActive()) return
        setStatusMsg(`Waiting for wallet approval (${unsignedTxs.length} merge ${unsignedTxs.length === 1 ? 'tx' : 'txs'})…`)
        const signed = await signCompiledTransactionsWithWallet(connected, targetCluster, unsignedTxs)
        if (!isSessionActive()) return
        if (signed.length !== unsignedTxs.length) {
          throw new Error('Wallet did not sign all merge transactions')
        }
        broadcastStarted = true
        const sent = await sendAndConfirmSignedTransactions(targetCluster, signed, {
          onProgress: () => {
            confirmedDirectTxs += 1
          },
        })
        const last = sent[sent.length - 1]
        if (!last) throw new Error('Broadcast returned no signature')
        signature = last.signature
        mergePending = Boolean(last.pending)
      }

      if (!isVaultActive()) return
      setLastReceipt({
        kind:
          builtMerges.length > 1
            ? `Transact Batched Merge (${builtMerges.length}x 2->1 · Tag 5)`
            : 'Transact Note Merge 2->1 (Tag 5)',
        signature,
        cluster: targetCluster,
        proverMs: totalProverMs,
        relayed: useRelayer,
        pending: mergePending,
        summary: mergePending
          ? 'Consolidation submitted to Solana; confirmation timed out at the proxy. Check Solscan and click Sync RPC before retrying.'
          : `Consolidated ${activeInputs.length} ${info.symbol} notes into ${builtMerges.length} (${formatMintBalance(totalMergedOut, info)})${useRelayer && builtMerges.length > 1 ? ' in 1 Transaction v1' : ''}`,
      })
      setStatusMsg(
        mergePending
          ? 'Consolidation broadcast submitted (confirmation pending). Syncing CompactWalletStore…'
          : 'Consolidation confirmed. Syncing CompactWalletStore…',
      )
      await syncVault(keys, targetCluster, store, walletScope)
      if (!isVaultActive()) return
      await refreshPoolAndBalances(targetCluster, connectedAddrRef.current)
    } catch (err) {
      if (confirmedDirectTxs > 0 && isVaultActive()) {
        await syncVault(keys, targetCluster, store, walletScope).catch(() => {})
        if (isVaultActive()) {
          await refreshPoolAndBalances(targetCluster, connectedAddrRef.current).catch(() => {})
        }
      }
      if (useRelayer || broadcastStarted ? isVaultActive() : isSessionActive()) {
        if (err instanceof AudrenRelayError && err.code === 'BROADCAST_AMBIGUOUS' && err.signature) {
          setLastReceipt({
            kind: 'Transact Note Merge (Tag 5)',
            signature: err.signature,
            cluster: targetCluster,
            relayed: true,
            pending: true,
            summary:
              'Relayer merge broadcast outcome is pending confirmation on Solana. Check Solscan and click Sync RPC before retrying.',
          })
          setStatusMsg('Relayed consolidation is pending confirmation. Syncing CompactWalletStore…')
          void syncVault(keys, targetCluster, store, walletScope).catch(() => {})
          return
        }
        setErrorMsg(formatUserActionError(err))
      }
    } finally {
      setBusy(false)
    }
  }

  const handleShieldedSwap = async () => {
    if (
      busy ||
      connecting ||
      !keys ||
      !store ||
      cluster !== 'mainnet' ||
      activeMintNotes.length === 0 ||
      !swapQuoteMatches ||
      !swapQuoteRaw ||
      !swapQuoteOut
    ) {
      return
    }
    const targetCluster = cluster
    const startSession = sessionEpochRef.current
    const startVaultEpoch = vaultEpochRef.current
    const isSessionActive = () =>
      sessionEpochRef.current === startSession && clusterRef.current === targetCluster
    const isVaultActive = () =>
      vaultEpochRef.current === startVaultEpoch && clusterRef.current === targetCluster
    const isPreSubmitActive = () => (useRelayer ? isVaultActive() : isSessionActive())
    let broadcastStarted = false
    setBusy(true)
    setErrorMsg(null)
    setStatusMsg('Building isolated Escrow swap route…')
    try {
      const inMintStr = activeMintStr
      const inMintBytes = base58Decode(inMintStr)
      if (!isValidSolanaPubkey(swapOutMint)) {
        throw new Error('Enter a valid output Solana token mint')
      }

      const fetcher = createWorkerBatchFetcher(targetCluster)
      const snapRes = await fetch(`/api/pool?cluster=${cluster}&poolId=0`)
      const snap = (await snapRes.json().catch(() => ({}))) as PoolApiSnapshot
      if (!snapRes.ok || !snap.initialized) {
        throw new Error(
          snap.error ??
            (snapRes.ok
              ? `Pool #0 is not initialized on ${cluster} yet`
              : `Failed to fetch Pool #0 snapshot (HTTP ${snapRes.status})`),
        )
      }
      if (!snap.rootHistory) {
        throw new Error('Pool #0 GlobalRootHistory migration in progress; retry shortly')
      }
      if (snap.paused) {
        throw new Error('Pool #0 is currently paused; shielded swaps are disabled')
      }
      const activeLanes = snap.activeLanes ?? 0
      if (!Number.isInteger(activeLanes) || activeLanes <= 0) {
        throw new Error(`Pool #0 has no active lanes on ${cluster} yet`)
      }
      if (!useRelayer && (snap.currentEpoch == null || !/^\d+$/.test(snap.currentEpoch))) {
        throw new Error('Pool #0 snapshot is missing currentEpoch; retry to read live Token-2022 fees')
      }
      const currentEpoch =
        snap.currentEpoch != null && /^\d+$/.test(snap.currentEpoch) ? BigInt(snap.currentEpoch) : 0n
      const wellKnownIn = WELL_KNOWN_TOKENS[inMintStr]
      const wellKnownOut = WELL_KNOWN_TOKENS[swapOutMint]
      const localInMeta = getTokenMeta(inMintStr)
      const localOutMeta = getTokenMeta(swapOutMint)
      if (!localInMeta.decimalsKnown && !swapQuoteMintMeta?.inputDecimals) {
        throw new Error(
          `On-chain decimals for ${localInMeta.symbol} are not resolved yet. Click "Resolve mint decimals" before swapping.`,
        )
      }

      // Privacy invariant: in Relayed mode (`useRelayer === true`), NEVER issue pinpoint
      // `/api/rpc/accounts` single-mint lookups against the same-origin web host.
      // Derive mint `tokenProgram` & `decimals` from `WELL_KNOWN_TOKENS` + the external
      // Privacy Relayer's `/v1/swap/quote` & `/v1/swap/instructions` responses.
      const [inMintInfo, outMintInfo] = useRelayer
        ? [
            {
              tokenProgram:
                swapQuoteMintMeta?.inputTokenProgram ??
                wellKnownIn?.tokenProgram ??
                localInMeta.tokenProgram ??
                CLASSIC_TOKEN_PROGRAM_ID,
              isToken2022:
                (swapQuoteMintMeta?.inputTokenProgram ??
                  wellKnownIn?.tokenProgram ??
                  localInMeta.tokenProgram) === TOKEN_2022_PROGRAM_ID,
              decimals:
                swapQuoteMintMeta?.inputDecimals ??
                wellKnownIn?.decimals ??
                localInMeta.decimals,
              transferFee: null as Token2022TransferFee | null,
              hasTransferHook: false,
            },
            {
              tokenProgram:
                swapQuoteMintMeta?.outputTokenProgram ??
                wellKnownOut?.tokenProgram ??
                localOutMeta.tokenProgram ??
                CLASSIC_TOKEN_PROGRAM_ID,
              isToken2022:
                (swapQuoteMintMeta?.outputTokenProgram ??
                  wellKnownOut?.tokenProgram ??
                  localOutMeta.tokenProgram) === TOKEN_2022_PROGRAM_ID,
              decimals:
                swapQuoteMintMeta?.outputDecimals ??
                wellKnownOut?.decimals ??
                localOutMeta.decimals,
              transferFee: swapQuoteMintMeta?.outputTransferFee ?? null,
              hasTransferHook: false,
            },
          ]
        : await Promise.all([
            resolveMintOnChain(targetCluster, inMintStr, currentEpoch),
            resolveMintOnChain(targetCluster, swapOutMint, currentEpoch),
          ])
      if (!isPreSubmitActive()) return
      let inTokenProgram = inMintInfo.tokenProgram
      let outTokenProgram = outMintInfo.tokenProgram
      const resolvedInDec = parseValidDecimals(inMintInfo.decimals)
      const resolvedOutDec = parseValidDecimals(outMintInfo.decimals)
      if (resolvedInDec !== undefined) {
        hydrateMintMeta(inMintStr, resolvedInDec, inTokenProgram)
      }
      if (resolvedOutDec !== undefined) {
        hydrateMintMeta(swapOutMint, resolvedOutDec, outTokenProgram)
      }
      if (!useRelayer && resolvedInDec !== undefined && resolvedInDec !== localInMeta.decimals) {
        setSwapAmount('')
        clearSwapQuoteState()
        throw new Error(
          `Synced on-chain decimals (${resolvedInDec}) for ${localInMeta.symbol} (previously ${localInMeta.decimals}). Re-enter the swap amount or click Max to continue.`,
        )
      }
      const inDec = resolvedInDec ?? localInMeta.decimals
      const inSym = localInMeta.symbol
      const safeSlippageBps = clampSlippageBps(swapSlippageBps)

      const amountIn = parseUnits(swapAmount, inDec)
      if (!amountIn || amountIn <= 0n) {
        throw new Error(`Invalid swap input amount (max ${formatUnits(maxSpendableNotePair, inDec)} ${inSym})`)
      }

      let inputNotes = selectInputNotesForMint(activeMintNotes, amountIn, {
        economyMode,
        preferredNote: manualPreferredNote,
        stableLaneCounts,
      })
      if (!inputNotes) {
        throw new Error(
          activeMintNotes.length >= 3 && amountIn <= activeMintTotal
            ? `Swap input spans more than 2 notes (largest pair is ${formatUnits(maxSpendableNotePair, inDec)} ${inSym}). Click "Consolidate notes" first.`
            : `Invalid swap input amount (max ${formatUnits(maxSpendableNotePair, inDec)} ${inSym})`,
        )
      }
      let totalIn = inputNotes.reduce((s, n) => s + n.amount, 0n)
      let omitNf1 = inputNotes.length === 1 && economyMode

      const escrowShard = swapQuoteShard ?? swapEscrowShard ?? pickRandomEscrowShard(NUM_ESCROW_SHARDS)
      const vaultAuth = deriveVaultAuthPdaSync(0, AUDREN_PROGRAM_ID).address
      const escrowPda = deriveEscrowPdaSync(0, escrowShard, AUDREN_PROGRAM_ID).address

      let activeQuoteRaw: unknown = swapQuoteRaw
      let activeQuoteOut: string = swapQuoteOut

      if (!useRelayer) {
        const expectedNetIn = inMintInfo.transferFee
          ? computeToken2022NetAmount(amountIn, inMintInfo.transferFee)
          : amountIn
        if (expectedNetIn <= 0n) {
          throw new Error('Net swap input after Token-2022 TransferFeeConfig must be > 0')
        }
        const quotedIn =
          activeQuoteRaw && typeof activeQuoteRaw === 'object' && 'inAmount' in activeQuoteRaw
            ? String((activeQuoteRaw as { inAmount?: unknown }).inAmount ?? '')
            : ''
        if (quotedIn !== expectedNetIn.toString()) {
          const requoteRes = await fetch('/api/jupiter/quote', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              cluster,
              inputMint: inMintStr,
              outputMint: swapOutMint,
              amount: expectedNetIn.toString(),
              amountIsNet: true,
              slippageBps: safeSlippageBps,
            }),
          })
          const requoted = (await requoteRes.json()) as Record<string, unknown>
          if (!requoteRes.ok || typeof requoted.outAmount !== 'string') {
            throw new Error(String(requoted.error ?? 'Failed to refresh swap quote for resolved input amount'))
          }
          activeQuoteRaw = requoted
          activeQuoteOut = requoted.outAmount
        }
      }

      const relayClient = new AudrenRelayClient(relayUrl)
      let routerProg: string
      let rawRouterAccounts: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }>
      let routerIxData: Uint8Array
      let payerPubkey = connected?.address ?? ''
      let relayerFeeAmount = 0n
      let relayerFeeRecipient: string | null = null
      let relaySetupAtas: RelaySetupAta[] = []
      let directLookupTables: Record<string, string[]> | undefined
      const routeHops =
        activeQuoteRaw &&
        typeof activeQuoteRaw === 'object' &&
        Array.isArray((activeQuoteRaw as { routePlan?: unknown }).routePlan)
          ? (activeQuoteRaw as { routePlan: unknown[] }).routePlan.length
          : 0
      let swapRouterCuLimit = routeHops > 1 ? 600_000 : 350_000
      const computeExecBaseCu = (inTp: string, outTp: string) =>
        Math.max(CU_LIMIT_EXEC_VIA_ESCROW_BASE, 285_000) +
        (inTp === TOKEN_2022_PROGRAM_ID || outTp === TOKEN_2022_PROGRAM_ID ? 25_000 : 0)
      let swapCuLimit = Math.min(
        1_400_000,
        computeExecBaseCu(inTokenProgram, outTokenProgram) + swapRouterCuLimit,
      )
      let winningProvider: RelayAggregatorId = swapQuoteProvider ?? 'jupiter'

      if (useRelayer) {
        const info = await relayClient.getInfo(cluster)
        if (!isVaultActive()) return
        if (!info.relayerPubkey) throw new Error(`Relayer missing fee payer for ${cluster}`)
        const activePool = Array.isArray(info.relayerPubkeys) && info.relayerPubkeys.length > 0
          ? info.relayerPubkeys
          : [info.relayerPubkey]
        payerPubkey =
          swapQuoteRelayerPubkey && activePool.includes(swapQuoteRelayerPubkey)
            ? swapQuoteRelayerPubkey
            : info.relayerPubkey

        const built = await relayClient.buildSwapInstructions(
          {
            provider: winningProvider,
            quoteResponse: activeQuoteRaw,
            inputMint: inMintStr,
            outputMint: swapOutMint,
            cluster: targetCluster,
            shardId: escrowShard,
            includeFee: false,
            relayerPubkey: payerPubkey,
          },
          { allowedRouterPrograms: AUDREN_AUDITED_SWAP_ROUTERS },
        )
        if (!isVaultActive()) return
        winningProvider = built.provider
        if (built.relayerPubkey && activePool.includes(built.relayerPubkey)) {
          payerPubkey = built.relayerPubkey
        }
        if (
          built.tokenProgramIn === TOKEN_2022_PROGRAM_ID ||
          built.tokenProgramIn === CLASSIC_TOKEN_PROGRAM_ID
        ) {
          inTokenProgram = built.tokenProgramIn
        }
        if (
          built.tokenProgramOut === TOKEN_2022_PROGRAM_ID ||
          built.tokenProgramOut === CLASSIC_TOKEN_PROGRAM_ID
        ) {
          outTokenProgram = built.tokenProgramOut
        }
        const resolvedInTp = inTokenProgram
        const resolvedOutTp = outTokenProgram
        setTokenMeta((prev) => {
          let next = prev
          const patchTp = (mint: string, tp: string, fallbackDec: number) => {
            const cur = next[mint]
            if (cur && cur.tokenProgram === tp) return
            next = {
              ...next,
              [mint]: {
                symbol: cur?.symbol ?? shortHash(mint, 4, 4),
                decimals: cur?.decimals ?? fallbackDec,
                decimalsKnown: cur?.decimalsKnown ?? false,
                tokenProgram: tp,
              },
            }
          }
          patchTp(inMintStr, resolvedInTp, inDec)
          patchTp(swapOutMint, resolvedOutTp, outMintInfo.decimals ?? localOutMeta.decimals)
          return next
        })
        routerProg = built.swapInstruction.programId
        rawRouterAccounts = built.swapInstruction.accounts
        routerIxData = fromBase64(built.swapInstruction.data)
        swapCuLimit =
          built.computeUnitLimit ??
          Math.min(1_400_000, computeExecBaseCu(inTokenProgram, outTokenProgram) + swapRouterCuLimit)
        relaySetupAtas = (built.missingAtas ?? []).map((m) => ({
          owner: m.owner,
          mint: m.mint,
          tokenProgram: m.tokenProgram,
        }))

        const baseMissingAtaCount = relaySetupAtas.length
        const baseExtraAtaMints = relaySetupAtas.map((a) => a.mint)
        let needsSwapFeeAtaSetup = false
        const computeSwapOutputCount = (curTotalIn: bigint, curInFee: bigint) => {
          const inputFee = swapFeeOnOutput ? 0n : curInFee
          return 1 + (curTotalIn > amountIn + inputFee || !economyMode ? 1 : 0)
        }

        const quoteExecFee = async (curOmitNf1: boolean, curOutputCount: number) => {
          const feeMint = swapFeeOnOutput ? swapOutMint : inMintStr
          const fq = await relayClient.getFeeQuote({
            cluster,
            op: 'exec_escrow',
            mint: feeMint,
            amount: swapFeeOnOutput ? activeQuoteOut : amountIn.toString(),
            feeOnOutput: swapFeeOnOutput,
            outputCount: curOutputCount,
            missingAtaCount: baseMissingAtaCount,
            ...(baseExtraAtaMints.length > 0 ? { extraAtaMints: baseExtraAtaMints } : {}),
            omitNf1: curOmitNf1,
            relayerPubkey: payerPubkey,
          })
          const validFeeDec = parseValidDecimals(fq.feeDecimals)
          if (isVaultActive()) {
            hydrateMintMeta(fq.feeMint || feeMint, fq.feeDecimals, fq.feeTokenProgram)
            if (
              !swapFeeOnOutput &&
              (!fq.feeMint || fq.feeMint === inMintStr) &&
              validFeeDec !== undefined &&
              validFeeDec !== inDec
            ) {
              setSwapAmount('')
              clearSwapQuoteState()
              throw new Error(
                `Synced on-chain decimals (${validFeeDec}) for ${inSym} (previously ${inDec}). Re-enter the swap amount or click Max to continue.`,
              )
            }
          }
          const fee = BigInt(fq.relayerFee || '0')
          return {
            fee,
            feeRecipient: fq.feeRecipient,
            needsFeeAtaSetup: Boolean(fee > 0n && fq.needsFeeAtaSetup),
            outputCount: curOutputCount,
          }
        }
        const applyExecFee = (q: {
          fee: bigint
          feeRecipient: string | null
          needsFeeAtaSetup: boolean
        }) => {
          relayerFeeAmount = q.fee
          relayerFeeRecipient = q.feeRecipient
          needsSwapFeeAtaSetup = q.needsFeeAtaSetup
        }

        let quotedOutputCount = computeSwapOutputCount(totalIn, 0n)
        applyExecFee(await quoteExecFee(omitNf1, quotedOutputCount))

        // Economy-mode reconciliation for input-side fee: if quoting 2 outputs (before knowing fee)
        // leaves zero change once fee is deducted, speculatively check 1 output without entering a dead-zone.
        if (
          !swapFeeOnOutput &&
          economyMode &&
          quotedOutputCount === 2 &&
          totalIn <= amountIn + relayerFeeAmount
        ) {
          const q1 = await quoteExecFee(omitNf1, 1)
          if (totalIn <= amountIn + q1.fee) {
            applyExecFee(q1)
            quotedOutputCount = 1
          }
        }

        if (!swapFeeOnOutput) {
          let quotedOmitNf1 = omitNf1
          for (let pass = 0; pass < 4; pass++) {
            const requiredWithFee = amountIn + relayerFeeAmount
            if (totalIn < requiredWithFee) {
              const expanded = selectInputNotesForMint(activeMintNotes, requiredWithFee, {
                economyMode,
                preferredNote: manualPreferredNote,
              })
              if (!expanded) {
                throw new Error(
                  `Insufficient note balance for swap + input fee (${formatUnits(relayerFeeAmount, inDec)} ${inSym})`,
                )
              }
              inputNotes = expanded
              totalIn = inputNotes.reduce((s, n) => s + n.amount, 0n)
            }

            const nextOmitNf1 = inputNotes.length === 1 && economyMode
            omitNf1 = nextOmitNf1
            const neededOutputCount = computeSwapOutputCount(totalIn, relayerFeeAmount)
            const needsRequote =
              nextOmitNf1 !== quotedOmitNf1 || neededOutputCount > quotedOutputCount

            if (!needsRequote) {
              if (
                economyMode &&
                neededOutputCount < quotedOutputCount &&
                totalIn <= amountIn + relayerFeeAmount
              ) {
                const q1 = await quoteExecFee(omitNf1, neededOutputCount)
                if (totalIn <= amountIn + q1.fee) {
                  applyExecFee(q1)
                  quotedOutputCount = neededOutputCount
                }
              }
              if (totalIn >= amountIn + relayerFeeAmount) {
                break
              }
              continue
            }

            quotedOmitNf1 = nextOmitNf1
            const nextQ = await quoteExecFee(omitNf1, neededOutputCount)
            applyExecFee(nextQ)
            quotedOutputCount = neededOutputCount

            if (
              economyMode &&
              quotedOutputCount === 2 &&
              totalIn <= amountIn + relayerFeeAmount
            ) {
              const q1 = await quoteExecFee(omitNf1, 1)
              if (totalIn <= amountIn + q1.fee) {
                applyExecFee(q1)
                quotedOutputCount = 1
              }
            }

            if (
              totalIn >= amountIn + relayerFeeAmount &&
              computeSwapOutputCount(totalIn, relayerFeeAmount) <= quotedOutputCount &&
              (inputNotes.length === 1 && economyMode) === quotedOmitNf1
            ) {
              break
            }
          }

          if (totalIn < amountIn + relayerFeeAmount) {
            throw new Error(
              `Insufficient note balance for swap + input fee (${formatUnits(relayerFeeAmount, inDec)} ${inSym})`,
            )
          }
        }

        if (needsSwapFeeAtaSetup) {
          const feeMint = swapFeeOnOutput ? swapOutMint : inMintStr
          const feeTp = swapFeeOnOutput ? outTokenProgram : inTokenProgram
          if (!relaySetupAtas.some((a) => a.owner === payerPubkey && a.mint === feeMint)) {
            relaySetupAtas.push({ owner: payerPubkey, mint: feeMint, tokenProgram: feeTp })
          }
        }
      } else {
        if (!connected) throw new Error('Connect a wallet or enable Privacy Relayer')
        const res = await fetch('/api/jupiter/swap-instructions', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster,
            quoteResponse: activeQuoteRaw,
            poolId: 0,
            shardId: escrowShard,
            inputMint: inMintStr,
            outputMint: swapOutMint,
            tokenProgramIn: inTokenProgram,
            tokenProgramOut: outTokenProgram,
          }),
        })
        const built = (await res.json()) as {
          swapInstruction?: {
            programId: string
            accounts: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }>
            data: string
          }
          lookupTables?: Record<string, string[]>
          computeUnitLimit?: number
          error?: string
        }
        if (!res.ok || !built.swapInstruction) throw new Error(built.error ?? 'Failed to build swap route')
        routerProg = built.swapInstruction.programId
        if (!AUDREN_AUDITED_SWAP_ROUTERS.includes(routerProg)) {
          throw new Error(
            `Blocked unapproved swap router program ${routerProg} (not in AUDREN_AUDITED_SWAP_ROUTERS).`,
          )
        }
        rawRouterAccounts = built.swapInstruction.accounts
        routerIxData = fromBase64(built.swapInstruction.data)
        directLookupTables = built.lookupTables
        if (
          typeof built.computeUnitLimit === 'number' &&
          Number.isInteger(built.computeUnitLimit) &&
          built.computeUnitLimit > 0
        ) {
          swapRouterCuLimit = Math.max(swapRouterCuLimit, built.computeUnitLimit)
        }
      }

      if (inputNotes.length > 1) omitNf1 = false

      const inVaultAta = deriveAssociatedTokenAddressSync(vaultAuth, inMintStr, inTokenProgram).address
      const inEscrowAta = deriveAssociatedTokenAddressSync(escrowPda, inMintStr, inTokenProgram).address
      const outVaultAta = deriveAssociatedTokenAddressSync(vaultAuth, swapOutMint, outTokenProgram).address
      const outEscrowAta = deriveAssociatedTokenAddressSync(escrowPda, swapOutMint, outTokenProgram).address

      // On-chain ExecViaEscrow forbids EXEC_FLAG_FEE_ON_OUTPUT when relayer_fee_amount == 0
      const effectiveFeeOnOutput = swapFeeOnOutput && relayerFeeAmount > 0n
      if (useRelayer && relayerFeeAmount > 0n) {
        const feeMint = effectiveFeeOnOutput ? swapOutMint : inMintStr
        const feeTp = effectiveFeeOnOutput ? outTokenProgram : inTokenProgram
        const expectedSwapFeeAta = deriveAssociatedTokenAddressSync(payerPubkey, feeMint, feeTp).address
        if (!relayerFeeRecipient || relayerFeeRecipient !== expectedSwapFeeAta) {
          throw new Error(
            'Relayer returned an unexpected swap fee recipient that does not match the active relayer ATA.',
          )
        }
      }

      const extraWritablePubkeys = [
        escrowPda,
        payerPubkey,
        inVaultAta,
        inEscrowAta,
        outVaultAta,
        outEscrowAta,
        ...(relayerFeeAmount > 0n && relayerFeeRecipient ? [relayerFeeRecipient] : []),
      ]
      const routerAccounts = prepareEscrowAccountsForAudren(
        rawRouterAccounts,
        escrowPda,
        extraWritablePubkeys,
      )

      const parsedQuoteOut = parseBigIntSafe(activeQuoteOut)
      if (!parsedQuoteOut || parsedQuoteOut <= 0n) {
        throw new Error('Swap quote returned an invalid output amount; refresh quote and retry')
      }
      const grossMinOut = (parsedQuoteOut * BigInt(10_000 - safeSlippageBps)) / 10_000n
      if (grossMinOut <= 0n) {
        throw new Error('Swap output after slippage is too small to settle')
      }
      if (effectiveFeeOnOutput && grossMinOut <= relayerFeeAmount) {
        throw new Error('Swap output after slippage is too small to cover the relayer fee')
      }
      if (useRelayer && relayerFeeAmount > 0n) {
        const feeDenom = effectiveFeeOnOutput ? grossMinOut : amountIn
        if (relayerFeeAmount > feeDenom / 2n) {
          throw new Error(
            'Relayer swap fee exceeds 50% of this swap amount; try a larger amount or switch to Direct Self-Pay.',
          )
        }
      }
      const afterRelayerFee = effectiveFeeOnOutput ? grossMinOut - relayerFeeAmount : grossMinOut
      const netMinOut = computeToken2022NetAmount(afterRelayerFee, outMintInfo.transferFee)
      if (netMinOut <= 0n) {
        throw new Error('Swap output after slippage is too small to cover the relayer fee')
      }
      const minOut = netMinOut

      const {
        history: rootHistory,
        snapshot: rootSnapshot,
        witnessFetcher,
      } = await fetchRootSnapshotForNotes(cluster, inputNotes)
      const witnessBatch = await buildLocalOrRpcWitnesses({
        activeStore: store,
        fetcher: witnessFetcher,
        history: rootHistory,
        snapshot: rootSnapshot,
        inputNotes,
      })
      const superRoot = witnessBatch.superRoot

      const outLaneId = pickRandomLaneId(activeLanes)
      const outLane = snap.lanes?.[outLaneId]
      if (!outLane) {
        throw new Error(`Pool #0 lane #${outLaneId} state is unavailable; retry in a moment`)
      }
      const outNextLeaf = BigInt(outLane.nextLeaf)
      const outNfCount = BigInt(outLane.nfCount)

      const assetIn = deriveAssetId(inMintBytes)
      const outMintBytes = base58Decode(swapOutMint)
      const assetOut = deriveAssetId(outMintBytes)

      const inFee = effectiveFeeOnOutput ? 0n : relayerFeeAmount
      const changeAmt = totalIn - amountIn - inFee
      if (changeAmt < 0n) {
        throw new Error(
          `Insufficient note balance for swap + input fee (${formatUnits(inFee, inDec)} ${inSym})`,
        )
      }

      const outputs: [JoinSplitOutputWitness, JoinSplitOutputWitness, JoinSplitOutputWitness] = [
        dummyOutputWitness(assetIn, randomFr()),
        dummyOutputWitness(assetIn, randomFr()),
        dummyOutputWitness(assetIn, randomFr()),
      ]
      let changeMemos: Uint8Array = new Uint8Array(0)
      let changeMask = 0
      if (changeAmt > 0n) {
        const mCh = encryptNoteMemo(keys.viewPk, crypto.getRandomValues(new Uint8Array(32)), changeAmt, inMintBytes)
        const chOwner = deriveStealthOwner(keys.spendPk, mCh.tweak)
        outputs[0] = { stealthOwner: chOwner, assetId: assetIn, amount: changeAmt, blinding: mCh.blinding }
        changeMask = 1
        changeMemos = mCh.memo
      } else if (!economyMode) {
        const padCh = createZeroDummyOutput(assetIn, inMintBytes)
        outputs[0] = padCh.witness
        changeMask = 1
        changeMemos = padCh.memo
      }

      const roll = computePageRollovers({
        leafCount: outNextLeaf,
        outputCount: 1 + popcount3(changeMask),
        nfCount: outNfCount,
        spentNullifiers: omitNf1 ? 1 : 2,
      })
      const outSubSeq = BigInt(roll.outSubSeq)
      const outRootSeq = BigInt(roll.outRootSeq)
      const outMemoSeq = BigInt(roll.outMemoSeq)
      const outNfSeq = BigInt(roll.nfPageSeq)
      const nextSubSeq = roll.nextSubSeq !== undefined ? BigInt(roll.nextSubSeq) : null
      const nextRootSeq = roll.nextRootSeq !== undefined ? BigInt(roll.nextRootSeq) : null
      const nextMemoSeq = roll.nextMemoSeq !== undefined ? BigInt(roll.nextMemoSeq) : null
      const nextNfSeq = roll.nextNfSeq !== undefined ? BigInt(roll.nextNfSeq) : null

      const dyn = prepareDynamicSwapMemo(keys.viewPk, crypto.getRandomValues(new Uint8Array(32)))
      const outStealthOwner = deriveStealthOwner(keys.spendPk, dyn.tweak)

      const ctxHash = computeExecCtxHash({
        poolId: 0,
        vkId: VK_ID_DEFAULT,
        outLaneId,
        escrowShard,
        changeMask,
        feeOnOutput: effectiveFeeOnOutput,
        assetIn: frToBeBytes(assetIn),
        amountIn,
        relayerFeeAmount,
        relayerFeeRecipient: relayerFeeAmount > 0n ? relayerFeeRecipient : null,
        assetOut: frToBeBytes(assetOut),
        minAmountOut: minOut,
        routerProg,
        routerAccounts,
        payer: payerPubkey,
        escrowInAta: inEscrowAta,
        escrowOutAta: outEscrowAta,
        vaultInAta: inVaultAta,
        vaultOutAta: outVaultAta,
        extraWritablePubkeys,
        outStealthOwner: frToBeBytes(outStealthOwner),
        outBlinding: frToBeBytes(dyn.blinding),
        dynMemoHead: dyn.dynHead34,
        dynMemoMask: dyn.dynMask72,
        routerIxData,
        changeMemos,
      })

      const buildSwapInput = (note: OwnedNote, path: MerklePath4Ary): JoinSplitInputWitness => ({
        isDummy: false,
        spendSk: keys.spendSk,
        tweak: frFromBeBytesStrict(note.tweak),
        assetId: assetIn,
        amount: note.amount,
        blinding: frFromBeBytesStrict(note.blinding),
        merklePath: path,
      })
      const swapInputs: [JoinSplitInputWitness, JoinSplitInputWitness] = [
        buildSwapInput(inputNotes[0]!, witnessBatch.paths[0]!),
        inputNotes[1]
          ? buildSwapInput(inputNotes[1]!, witnessBatch.paths[1]!)
          : dummyInputWitness(keys.spendSk, assetIn, randomFr()),
      ]

      if (!isPreSubmitActive()) return
      setStatusMsg('Generating 192-byte BN254 Groth16 proof in Web Worker…')
      const { result, elapsedMs } = await proveJoinsplitInBrowser({
        superRoot,
        txAssetId: assetIn,
        publicAssetId: assetIn,
        publicAmountOut: amountIn,
        relayerFeeAmount: inFee,
        ctxHash,
        omitNf1,
        inputs: swapInputs,
        outputs,
      })
      if (!isPreSubmitActive()) return

      const ix = buildExecViaEscrowInstruction({
        poolId: 0,
        vkId: VK_ID_DEFAULT,
        rootRingKind: witnessBatch.rootRingKind,
        rootRingIdx: witnessBatch.rootRingIdx,
        outLaneId,
        escrowShard,
        outSubSeq,
        outRootSeq,
        outMemoSeq,
        outNfSeq,
        rollover: { nextSubSeq, nextMemoSeq, nextNfSeq },
        payer: payerPubkey,
        proof192: result.proof192,
        nf0: result.nf0,
        nf1: result.nf1,
        cm0: result.cm0,
        cm1: result.cm1,
        cm2: result.cm2,
        changeMask,
        feeOnOutput: effectiveFeeOnOutput,
        amountIn,
        relayerFeeAmount,
        minAmountOut: minOut,
        outStealthOwner: frToBeBytes(outStealthOwner),
        outBlinding: frToBeBytes(dyn.blinding),
        dynMemoHead: dyn.dynHead34,
        dynMemoMask: dyn.dynMask72,
        changeMemos,
        routerProg,
        routerAccounts,
        extraWritablePubkeys,
        routerIxData,
        inLeg: {
          mint: inMintStr,
          vaultAta: inVaultAta,
          escrowAta: inEscrowAta,
          tokenProgram: inTokenProgram,
        },
        outLeg: {
          mint: swapOutMint,
          vaultAta: outVaultAta,
          escrowAta: outEscrowAta,
          tokenProgram: outTokenProgram,
        },
        relayerFeeRecipient: relayerFeeAmount > 0n ? relayerFeeRecipient : null,
      })

      let signature: string
      let swapPending = false
      if (useRelayer) {
        if (!isVaultActive()) return
        setStatusMsg('Relaying ExecViaEscrow (Tag 6) via Transaction v1 (0x81)…')
        const sub = await relayClient.submitRelayedInstruction({
          cluster: targetCluster,
          instructionDataB64: toBase64(ix.data),
          accounts: ix.accounts,
          ...(relaySetupAtas.length > 0 ? { setupAtas: relaySetupAtas } : {}),
          computeUnitLimit: swapCuLimit,
          vaultOutAta: outVaultAta,
          provider: winningProvider,
        })
        signature = sub.signature
      } else {
        const openPagePreIxs = await ensureLanePagesPreIxs({
          cluster: targetCluster,
          fetcher,
          payer: payerPubkey,
          laneId: outLaneId,
          nextLeaf: outNextLeaf,
          nfCount: outNfCount,
          numOutputs: 1 + popcount3(changeMask),
          numNfs: omitNf1 ? 1 : 2,
          subSeq: outSubSeq,
          rootSeq: outRootSeq,
          memoSeq: outMemoSeq,
          nfSeq: outNfSeq,
          nextSubSeq,
          nextRootSeq,
          nextMemoSeq,
          nextNfSeq,
          includeOutputs: true,
        })
        if (!isSessionActive()) return
        const ataPrep = await fetcher([outVaultAta, outEscrowAta, inEscrowAta])
        if (!isSessionActive()) return
        const ataPreIxs: AudrenInstruction[] = []
        let setupAtaCu = 0
        if (!ataPrep[0]) {
          ataPreIxs.push(
            buildCreateAtaIdempotentInstruction({
              payer: payerPubkey,
              ata: outVaultAta,
              owner: vaultAuth,
              mint: swapOutMint,
              tokenProgram: outTokenProgram,
            }),
          )
          setupAtaCu += outTokenProgram === TOKEN_2022_PROGRAM_ID ? 45_000 : 30_000
        }
        if (!ataPrep[1]) {
          ataPreIxs.push(
            buildCreateAtaIdempotentInstruction({
              payer: payerPubkey,
              ata: outEscrowAta,
              owner: escrowPda,
              mint: swapOutMint,
              tokenProgram: outTokenProgram,
            }),
          )
          setupAtaCu += outTokenProgram === TOKEN_2022_PROGRAM_ID ? 45_000 : 30_000
        }
        if (!ataPrep[2]) {
          ataPreIxs.push(
            buildCreateAtaIdempotentInstruction({
              payer: payerPubkey,
              ata: inEscrowAta,
              owner: escrowPda,
              mint: inMintStr,
              tokenProgram: inTokenProgram,
            }),
          )
          setupAtaCu += inTokenProgram === TOKEN_2022_PROGRAM_ID ? 45_000 : 30_000
        }
        const execMainCu = Math.min(
          1_400_000,
          computeExecBaseCu(inTokenProgram, outTokenProgram) + swapRouterCuLimit,
        )
        const baseCuLimit = Math.min(1_400_000, execMainCu + setupAtaCu)
        const combinedCuLimit = Math.min(
          1_400_000,
          baseCuLimit + openPagePreIxs.length * CU_LIMIT_OPEN_PAGE,
        )
        if (!isSessionActive()) return
        setStatusMsg('Waiting for wallet approval…')
        const sent = await signAndBroadcastDirect({
          mainIxs: [ix],
          openPagePreIxs,
          otherPreIxs: ataPreIxs,
          otherPreCuLimit: setupAtaCu,
          mainOnlyCuLimit: execMainCu,
          baseCuLimit,
          combinedCuLimit,
          lookupTables: directLookupTables,
          expectedSession: startSession,
          targetCluster,
          onBroadcastStart: () => {
            broadcastStarted = true
          },
        })
        if (!sent) return
        signature = sent.signature
        swapPending = Boolean(sent.pending)
      }

      if (!isVaultActive()) return
      setLastReceipt({
        kind: 'ExecViaEscrow Shielded Swap (Tag 6)',
        signature,
        cluster: targetCluster,
        proverMs: elapsedMs,
        relayed: useRelayer,
        pending: swapPending,
        summary: swapPending
          ? 'Swap submitted to Solana; confirmation timed out at the proxy. Check Solscan and click Sync RPC before retrying.'
          : `Swapped ${swapAmount} ${inSym} -> ${getTokenMeta(swapOutMint).symbol} via Escrow #${escrowShard} (${winningProvider})${inputNotes.length === 2 ? ' · 2-note consolidation' : ''}`,
      })
      setSwapEscrowShard(pickRandomEscrowShard(NUM_ESCROW_SHARDS))
      setSwapQuoteShard(null)
      setStatusMsg(
        swapPending
          ? 'Swap broadcast submitted (confirmation pending). Syncing CompactWalletStore…'
          : 'Swap confirmed. Syncing CompactWalletStore…',
      )
      await syncVault(keys, targetCluster, store, walletScope)
      if (!isVaultActive()) return
      await refreshPoolAndBalances(targetCluster, connectedAddrRef.current)
    } catch (err) {
      if (useRelayer || broadcastStarted ? isVaultActive() : isSessionActive()) {
        if (err instanceof AudrenRelayError && err.code === 'BROADCAST_AMBIGUOUS' && err.signature) {
          setLastReceipt({
            kind: 'ExecViaEscrow Shielded Swap (Tag 6)',
            signature: err.signature,
            cluster: targetCluster,
            relayed: true,
            pending: true,
            summary:
              'Relayer swap broadcast outcome is pending confirmation on Solana. Check Solscan and click Sync RPC before retrying.',
          })
          setStatusMsg('Relayed swap is pending confirmation. Syncing CompactWalletStore…')
          void syncVault(keys, targetCluster, store, walletScope).catch(() => {})
          return
        }
        setErrorMsg(formatUserActionError(err))
      }
    } finally {
      setBusy(false)
    }
  }

  const defiSession = useMemo(() => {
    if (!seedBytes) return null
    return deriveDefiSessionKeypair(seedBytes, sessionIndex)
  }, [seedBytes, sessionIndex])

  const fvkExport = useMemo(() => {
    if (!keys) return null
    const fvk = exportFullViewingKey(keys)
    return JSON.stringify(
      {
        protocolVersion: PROTOCOL_VERSION,
        spendPk: toHex(fvk.spendPk),
        nk: toHex(fvk.nk),
        viewSk: toHex(fvk.viewSk),
        viewPk: toHex(fvk.viewPk),
      },
      null,
      2,
    )
  }, [keys])

  const handleGenerateReceipt = () => {
    if (!complianceNote) return
    verifyReceiptSeqRef.current += 1
    setVerifyingReceipt(false)
    const proof = exportSelectiveDisclosureProof(complianceNote)
    const json = JSON.stringify(
      {
        poolId: proof.poolId,
        laneId: proof.laneId,
        leafIndex: proof.leafIndex.toString(),
        stealthOwnerHex: toHex(proof.stealthOwner),
        mint: base58Encode(proof.mint),
        amount: proof.amount.toString(),
        blindingHex: toHex(proof.blinding),
        commitmentHex: toHex(proof.commitment),
      },
      null,
      2,
    )
    setReceiptJson(json)
    setReceiptVerdict(null)
    setReceiptVerdictDetail(null)
  }

  /**
   * Real on-chain Mode 1 Selective Disclosure verification:
   * strictly validates integer & 32-byte field bounds (`0 <= amount <= u64::MAX`),
   * fetches the live `SubtreePage` for `(poolId, laneId, leafIndex)` from Solana RPC,
   * verifies `account.owner === AUDREN_PROGRAM_ID` and header `(poolId, laneId, pageSeq)`
   * with `AUD1SB01` magic, recomputes Poseidon5, and verifies via `@audren/sdk`.
   */
  const handleVerifyReceipt = async () => {
    const mySeq = ++verifyReceiptSeqRef.current
    const targetCluster = cluster
    const startSession = sessionEpochRef.current
    const isCurrent = () =>
      clusterRef.current === targetCluster &&
      sessionEpochRef.current === startSession &&
      verifyReceiptSeqRef.current === mySeq
    setVerifyingReceipt(true)
    setReceiptVerdict(null)
    setReceiptVerdictDetail(null)
    try {
      const parsed: unknown = JSON.parse(receiptJson)
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('Receipt must be a JSON object')
      }
      const p = parsed as Record<string, unknown>

      const parseStrictInt = (raw: unknown, label: string, max: number): number => {
        if (typeof raw === 'number') {
          if (!Number.isInteger(raw) || raw < 0 || raw > max) {
            throw new Error(`Invalid ${label}: must be an integer in 0..=${max}`)
          }
          return raw
        }
        if (typeof raw === 'string' && /^\d+$/.test(raw.trim())) {
          const n = Number(raw.trim())
          if (!Number.isSafeInteger(n) || n < 0 || n > max) {
            throw new Error(`Invalid ${label}: out of range 0..=${max}`)
          }
          return n
        }
        throw new Error(`Invalid ${label}: expected non-negative integer`)
      }

      const parseStrictU64 = (raw: unknown, label: string): bigint => {
        if (typeof raw === 'number') {
          if (!Number.isSafeInteger(raw) || raw < 0) {
            throw new Error(`Invalid ${label}: must be a non-negative integer <= u64::MAX`)
          }
          return BigInt(raw)
        }
        if (typeof raw === 'string' && /^\d+$/.test(raw.trim())) {
          const v = BigInt(raw.trim())
          if (v < 0n || v > U64_MAX) {
            throw new Error(`Invalid ${label}: must be in [0, 2^64 - 1]`)
          }
          return v
        }
        throw new Error(`Invalid ${label}: expected unsigned 64-bit integer string`)
      }

      const parseStrictHex32 = (raw: unknown, label: string): Uint8Array => {
        if (typeof raw !== 'string' || !STRICT_HEX_64_RE.test(raw.trim())) {
          throw new Error(`Invalid ${label}: must be a 64-character hex string (32 bytes)`)
        }
        const bytes = fromHex(raw.trim())
        if (bytes.byteLength !== 32) {
          throw new Error(`Invalid ${label}: expected 32 bytes`)
        }
        return bytes
      }

      const parseMint32 = (rawMint: unknown, rawMintHex: unknown): Uint8Array => {
        if (typeof rawMintHex === 'string') {
          return parseStrictHex32(rawMintHex, 'mintHex')
        }
        if (typeof rawMint !== 'string' || !rawMint.trim()) {
          throw new Error('Invalid mint: expected 64-char hex or 32-byte base58 pubkey')
        }
        const trimmed = rawMint.trim()
        if (STRICT_HEX_64_RE.test(trimmed)) {
          return fromHex(trimmed)
        }
        const decoded = base58Decode(trimmed)
        if (decoded.byteLength !== 32) {
          throw new Error('Invalid mint: must decode to 32 bytes')
        }
        return decoded
      }

      const poolId = parseStrictInt(p.poolId, 'poolId', U32_MAX)
      const laneId = parseStrictInt(p.laneId, 'laneId', 15)
      const leafIndex = parseStrictU64(p.leafIndex, 'leafIndex')
      const amount = parseStrictU64(p.amount, 'amount')
      const stealthOwner = parseStrictHex32(p.stealthOwnerHex ?? p.stealthOwner, 'stealthOwner')
      const blinding = parseStrictHex32(p.blindingHex ?? p.blinding, 'blinding')
      const commitment = parseStrictHex32(p.commitmentHex ?? p.commitment, 'commitment')
      const mint = parseMint32(p.mint, p.mintHex)

      const sdp: SelectiveDisclosureProof = {
        poolId,
        laneId,
        leafIndex,
        stealthOwner,
        mint,
        amount,
        blinding,
        commitment,
      }
      if (!verifySelectiveDisclosureProof(sdp, sdp.commitment)) {
        setReceiptVerdict('invalid')
        setReceiptVerdictDetail('Receipt commitment or field bounds failed local Poseidon5 verification.')
        return
      }

      const subPageSeq = sdp.leafIndex / BigInt(SUBTREE_LEAVES)
      const leafOffset = Number(sdp.leafIndex % BigInt(SUBTREE_LEAVES))
      const subtreePda = deriveSubtreePdaSync(
        sdp.poolId,
        sdp.laneId,
        subPageSeq,
        AUDREN_PROGRAM_ID,
      ).address

      const rpcRes = await fetch('/api/rpc/accounts', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ cluster: targetCluster, addresses: [subtreePda] }),
      })
      if (!isCurrent()) return
      const rpcJson = (await rpcRes.json()) as {
        accounts?: Array<string | null>
        owners?: Array<string | null>
        error?: string
      }
      if (!isCurrent()) return
      if (!rpcRes.ok || !rpcJson.accounts) {
        throw new Error(rpcJson.error ?? `RPC SubtreePage fetch HTTP ${rpcRes.status}`)
      }
      const rawB64 = rpcJson.accounts[0]
      const owner = rpcJson.owners?.[0] ?? null
      if (!rawB64) {
        setReceiptVerdict('invalid')
        setReceiptVerdictDetail(
          `On-chain SubtreePage ${shortHash(subtreePda, 6, 4)} not found on ${targetCluster}.`,
        )
        return
      }
      if (owner !== AUDREN_PROGRAM_ID) {
        setReceiptVerdict('invalid')
        setReceiptVerdictDetail(
          `Account owner mismatch on ${shortHash(subtreePda, 6, 4)}: expected Audren program ${shortHash(AUDREN_PROGRAM_ID, 6, 4)}.`,
        )
        return
      }

      const page = decodeSubtreePage(fromBase64(rawB64))
      if (page.poolId !== sdp.poolId || page.laneId !== sdp.laneId || page.pageSeq !== subPageSeq) {
        setReceiptVerdict('invalid')
        setReceiptVerdictDetail(
          `SubtreePage header mismatch on ${shortHash(subtreePda, 6, 4)} (got pool=${page.poolId}, lane=${page.laneId}, seq=${page.pageSeq.toString()}).`,
        )
        return
      }
      const onChainLeafCommitment = leafOffset < page.count ? page.leaves[leafOffset] : undefined
      if (!onChainLeafCommitment) {
        setReceiptVerdict('invalid')
        setReceiptVerdictDetail(
          `Leaf #${sdp.leafIndex.toString()} does not exist yet on ${targetCluster} SubtreePage ${shortHash(subtreePda, 6, 4)}.`,
        )
        return
      }

      const computedCommitment = frToBeBytes(
        computeNoteCommitment(
          frFromBeBytesStrict(sdp.stealthOwner),
          deriveAssetId(sdp.mint),
          sdp.amount,
          frFromBeBytesStrict(sdp.blinding),
        ),
      )
      const ok =
        bytesEqual(onChainLeafCommitment, computedCommitment) &&
        verifySelectiveDisclosureProof(sdp, onChainLeafCommitment)

      if (!isCurrent()) return
      setReceiptVerdict(ok ? 'valid' : 'invalid')
      setReceiptVerdictDetail(
        ok
          ? `Matched live ${targetCluster} SubtreePage ${shortHash(subtreePda, 6, 4)} (lane #${sdp.laneId} · leaf #${sdp.leafIndex.toString()}).`
          : `Poseidon commitment does not match live ${targetCluster} SubtreePage ${shortHash(subtreePda, 6, 4)} leaf #${leafOffset}.`,
      )
    } catch (err) {
      if (!isCurrent()) return
      setReceiptVerdict('invalid')
      setReceiptVerdictDetail(err instanceof Error ? err.message : 'Malformed receipt JSON')
    } finally {
      if (verifyReceiptSeqRef.current === mySeq) {
        setVerifyingReceipt(false)
      }
    }
  }

  const handleExportBackup = async () => {
    if (!seedBytes || !keys) return
    const targetCluster = cluster
    const startVaultEpoch = vaultEpochRef.current
    setBackupStatus(null)
    try {
      const effectiveBirthday = store?.birthdaySlot ?? vaultBirthdaySlot
      const nextSlots: Record<SolanaCluster, bigint> = {
        ...birthdayByCluster,
        [targetCluster]: effectiveBirthday,
      }
      const file = await exportEncryptedVaultBackup({
        seed: seedBytes,
        audrenAddress: keys.address,
        cluster: targetCluster,
        passphrase: backupPassphrase,
        birthdaySlot: effectiveBirthday,
        birthdaySlots: nextSlots,
      })
      if (vaultEpochRef.current !== startVaultEpoch || clusterRef.current !== targetCluster) return
      const blob = new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `audren-backup-${targetCluster}.json`
      a.click()
      URL.revokeObjectURL(url)
      setEphemeralBackupDownloaded(true)
      setBackupPassphrase('')
      setBackupStatus(
        `Encrypted backup triggered for download (birthday slot #${effectiveBirthday.toString()} · PBKDF2-SHA256 600k + AES-256-GCM). Verify the file saved on disk before confirming Mainnet deposits.`,
      )
    } catch (err) {
      if (vaultEpochRef.current !== startVaultEpoch || clusterRef.current !== targetCluster) return
      setBackupStatus(err instanceof Error ? err.message : String(err))
    }
  }

  const handleImportBackup = async (file: File) => {
    if (busy || connecting) return
    setBusy(true)
    setBackupStatus(null)
    setErrorMsg(null)
    try {
      const parsed = JSON.parse(await file.text()) as AudrenEncryptedBackupFile
      const restored = await importEncryptedVaultBackup(parsed, backupPassphrase)
      const overrideTrimmed = restoreBirthdayInput.trim()
      let effectiveBirthday = restored.birthdaySlot
      if (overrideTrimmed.length > 0) {
        if (!/^\d+$/.test(overrideTrimmed)) {
          throw new Error('Birthday slot override must be a non-negative integer')
        }
        effectiveBirthday = BigInt(overrideTrimmed)
      }
      const restoredSlots: Record<SolanaCluster, bigint> = {
        devnet: restored.birthdaySlots.devnet,
        mainnet: restored.birthdaySlots.mainnet,
        [restored.cluster]: effectiveBirthday,
      }
      const clusterChanged = restored.cluster !== clusterRef.current
      sessionEpochRef.current += 1
      vaultEpochRef.current += 1
      syncSeqRef.current += 1
      setSyncing(false)
      resetTransientActionState()
      setStore(null)
      setUnspentNotes([])
      setSelectedMintStr(WSOL_MINT)
      setManualNoteKey('')
      setComplianceNoteKey('')
      setStatusMsg(null)
      if (clusterChanged) {
        poolSeqRef.current += 1
        setPoolInfo(null)
        setPubSolLamports(0n)
        setPubTokens([])
        setDepositSource(DEPOSIT_NATIVE_SOL)
      }
      clusterRef.current = restored.cluster
      setBirthdayByCluster(restoredSlots)
      setCluster(restored.cluster)
      setSwapOutMint(restored.cluster === 'devnet' ? USDC_DEVNET_MINT : USDC_MAINNET_MINT)
      setSwapEscrowShard(pickRandomEscrowShard(NUM_ESCROW_SHARDS))
      const unlockedEpoch = await unlockFromSeed(restored.seed, restored.cluster, 'backup', 'local', {
        birthdaySlot: effectiveBirthday,
        resetStore: true,
      })
      if (unlockedEpoch === null) return
      setBackupPassphrase('')
      setBackupStatus(
        `Restored Audren vault on ${restored.cluster} (birthday slot #${effectiveBirthday.toString()})`,
      )
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      setBackupStatus(msg)
      setErrorMsg(msg)
    } finally {
      setBusy(false)
    }
  }

  const maxSendNet = useMemo(() => {
    if (activeMintNotes.length === 0) return 0n
    const fee = useRelayer && sendFeePreview ? sendFeePreview.relayerFee : 0n
    return maxSpendableNotePair > fee ? maxSpendableNotePair - fee : 0n
  }, [activeMintNotes.length, maxSpendableNotePair, useRelayer, sendFeePreview])

  const activePlannedNotes =
    tab === 'send' ? plannedSendNotes : tab === 'withdraw' ? plannedWithdrawNotes : tab === 'swap' ? plannedSwapNotes : null

  return (
    <div className="lv-shell">
      <div className="lv-topbar">
        <div className="lv-cluster-switch" role="group" aria-label="Solana cluster">
          <button
            type="button"
            className={`lv-cluster-btn ${cluster === 'devnet' ? 'is-active' : ''}`}
            disabled={busy || connecting}
            onClick={() => handleClusterSwitch('devnet')}
          >
            <span className="lv-cluster-dot is-devnet" />
            Devnet
          </button>
          <button
            type="button"
            className={`lv-cluster-btn ${cluster === 'mainnet' ? 'is-active' : ''}`}
            disabled={busy || connecting}
            onClick={() => handleClusterSwitch('mainnet')}
          >
            <span className="lv-cluster-dot is-mainnet" />
            Mainnet
          </button>
        </div>

        <div className="lv-wallet-bar">
          {poolInfo && (
            <span className="lv-wallet-pill mono">
              Pool #0 · {poolInfo.activeLanes} lanes · {poolInfo.totalNotes} notes
            </span>
          )}
          {connected ? (
            <>
              <span className="lv-wallet-pill mono">
                <Wallet size={13} /> {connected.name} · {shortHash(connected.address, 5, 4)}
              </span>
              <button
                type="button"
                className="lv-mini-btn"
                disabled={busy || connecting}
                onClick={handleDisconnect}
              >
                Disconnect
              </button>
            </>
          ) : (
            <span className="lv-wallet-pill mono">Wallet disconnected</span>
          )}
        </div>
      </div>

      <div className="lv-notice-bar is-warn">
        <AlertCircle size={15} />
        <span style={{ flex: 1 }}>
          <span className="lv-strong">Audren ({AUDREN.releaseTag}):</span> 192 B BN254 Groth16 global 4-ary MASP (17,861 R1CS) ·
          Perpetual Powers of Tau + 2-contribution release-environment Phase-2 ceremony (<code>{shortHash(AUDREN.pkCompressedSha256, 8, 6)}</code>) ·
          Pre-audit release with active program upgrade authority (open for independent security review &amp; community Phase-2 contributions).
        </span>
      </div>

      {rootHistoryMigrationInProgress && (
        <div className="lv-notice-bar is-warn">
          <AlertCircle size={15} />
          <span style={{ flex: 1 }}>
            Pool #0 GlobalRootHistory migration in progress on {cluster}; deposits, sends, swaps, withdrawals, and note merges are paused until initialization completes. Retry shortly.
          </span>
        </div>
      )}

      {poolInfo?.paused && (
        <div className="lv-notice-bar is-warn">
          <AlertCircle size={15} />
          <span style={{ flex: 1 }}>
            Pool #0 is currently paused on {cluster}. New deposits, private sends, and swaps are disabled, while pause-immune full note withdrawals (output_mask = 0) remain open on the Withdraw tab.
          </span>
        </div>
      )}

      {syncIncomplete && keys && (
        <div className="lv-notice-bar is-warn">
          <AlertCircle size={15} />
          <span style={{ flex: 1 }}>
            Partial RPC sync: not all pages finished loading on {cluster}. Click Sync RPC before spending so balances and nullifiers are complete.
          </span>
          <button
            type="button"
            className="lv-mini-btn"
            disabled={syncing || busy || connecting}
            onClick={() => void syncVault(keys, cluster, store, walletScope)}
          >
            <RefreshCw size={12} className={syncing ? 'spin' : ''} /> Retry sync
          </button>
        </div>
      )}

      {!keys ? (
        <div className="lv-connect-sheet">
          <div className="lv-connect-copy">
            <h2>Non-custodial Audren vault.</h2>
            <p>
              Derive your BN254 spend key, X25519 view key, and encrypted <code>CompactWalletStore</code>{' '}
              strictly inside your browser. Zero indexer, zero server-side key custody.
            </p>
            <ul className="lv-connect-steps">
              <li>
                <span className="lv-step-dot">1</span>
                <div>
                  <span className="lv-step-title">Connect any Wallet Standard extension</span>
                  <p>Sign one deterministic message to unlock your Audren vault keys, create an ephemeral local vault, or restore an encrypted backup.</p>
                </div>
              </li>
              <li>
                <span className="lv-step-dot">2</span>
                <div>
                  <span className="lv-step-title">Sync via ordinary Solana RPC</span>
                  <p>Reads <code>SubtreePage</code>, <code>MemoPage</code>, and <code>NullifierPage</code> PDAs in uniform batches; persists compact encrypted state in IndexedDB.</p>
                </div>
              </li>
              <li>
                <span className="lv-step-dot">3</span>
                <div>
                  <span className="lv-step-title">Prove locally in a Web Worker</span>
                  <p>Generates 192 B Groth16 proofs off the main UI thread via <code>/wasm/prover-worker.js</code> and submits via your chosen Privacy Relayer or direct self-pay.</p>
                </div>
              </li>
            </ul>
          </div>

          <div className="lv-connect-actions">
            <div className="lv-wallet-grid">
              {discovered.length > 0 ? (
                discovered.map((w) => (
                  <button
                    key={w.id}
                    type="button"
                    className="lv-wallet-choice"
                    disabled={connecting || busy}
                    onClick={() => handleConnectWallet(w)}
                  >
                    {w.icon && <img src={w.icon} alt="" className="lv-wallet-icon" />}
                    <span className="lv-wallet-choice-text">
                      <span className="lv-wallet-choice-name">{w.name}</span>
                      <span>{connected?.name === w.name ? 'Connected' : 'Wallet Standard'}</span>
                    </span>
                  </button>
                ))
              ) : (
                <div className="lv-empty-action">
                  <p>No Solana browser extension detected (Phantom, Solflare, Backpack). You can still launch a local vault, restore an encrypted backup, or run the no-wallet Sandbox.</p>
                </div>
              )}
            </div>

            <div className="lv-unlock-actions">
              {connected && (
                <>
                  <button
                    type="button"
                    className="btn-primary lv-submit-btn"
                    disabled={busy || connecting}
                    onClick={handleUnlockWithWalletSignature}
                  >
                    {busy ? <Loader2 size={15} className="spin" /> : <KeyRound size={15} />}
                    Unlock vault with {connected.name}
                  </button>
                  <p className="lv-quote-loading">
                    Signing this message derives your Audren vault spending authority from a deterministic Ed25519 signature over the cluster and wallet address (not the site origin). Never sign this prompt on untrusted sites, and export an encrypted backup right after unlocking so you can recover funds if your wallet changes signing behavior.
                  </p>
                </>
              )}
              <button
                type="button"
                className="btn-secondary lv-submit-btn"
                disabled={busy || connecting}
                onClick={handleCreateLocalVault}
              >
                <Lock size={15} /> Create ephemeral local vault
              </button>
            </div>

            <div className="lv-backup-box" style={{ marginTop: '0.5rem' }}>
              <span className="lv-box-title">Restore encrypted backup</span>
              <p>Enter your backup passphrase and select an <code>audren-backup-*.json</code> file. Birthday slot is read automatically from the backup or can be overridden below.</p>
              <div className="lv-backup-row">
                <input
                  type="password"
                  className="lv-input"
                  value={backupPassphrase}
                  onChange={(e) => setBackupPassphrase(e.target.value)}
                  placeholder="Backup passphrase"
                />
                <input
                  type="text"
                  inputMode="numeric"
                  className="lv-input mono"
                  value={restoreBirthdayInput}
                  onChange={(e) => setRestoreBirthdayInput(e.target.value)}
                  placeholder="Birthday slot (optional)"
                />
                <button
                  type="button"
                  className="lv-mini-btn"
                  disabled={busy || connecting || backupPassphrase.length < 8}
                  onClick={() => lockedFileInputRef.current?.click()}
                >
                  <Upload size={13} /> Restore file
                </button>
                <input
                  ref={lockedFileInputRef}
                  type="file"
                  accept="application/json"
                  style={{ display: 'none' }}
                  onChange={(e) => {
                    const f = e.target.files?.[0]
                    e.target.value = ''
                    if (f) void handleImportBackup(f)
                  }}
                />
              </div>
              {backupStatus && <p className="lv-backup-status mono">{backupStatus}</p>}
            </div>

            <div className="lv-backup-box" style={{ marginTop: '0.5rem' }}>
              <span className="lv-box-title">Restore from 64-hex recovery seed</span>
              <p>Paste a raw 32-byte recovery seed (64 hex characters) saved from an ephemeral vault. Uses the optional birthday slot above if entered.</p>
              <div className="lv-backup-row">
                <input
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  className="lv-input mono"
                  value={restoreSeedInput}
                  onChange={(e) => setRestoreSeedInput(e.target.value)}
                  placeholder="64-character hex seed"
                />
                <button
                  type="button"
                  className="lv-mini-btn"
                  disabled={busy || connecting || !STRICT_HEX_64_RE.test(restoreSeedInput.trim())}
                  onClick={() => void handleRestoreFromHexSeed()}
                >
                  <KeyRound size={13} /> Restore seed
                </button>
              </div>
            </div>

            {errorMsg && (
              <div className="lv-error-bar" style={{ marginTop: '0.5rem' }}>
                <AlertCircle size={14} />
                <span>{errorMsg}</span>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="lv-workspace">
          <section className={`lv-card lv-private-card ${strangerView ? 'is-stranger' : ''}`}>
            <div className="lv-card-head">
              <div>
                <span className="lv-ledger-kicker is-ok">
                  {strangerView ? 'What Solana observers see' : 'Shielded balances'}
                </span>
              </div>
              <div className="lv-card-head-right">
                <button
                  type="button"
                  className={`lv-eyes-toggle ${strangerView ? 'is-active' : ''}`}
                  onClick={() => setStrangerView((v) => !v)}
                >
                  {strangerView ? <EyeOff size={13} /> : <Eye size={13} />}
                  {strangerView ? 'Stranger view' : 'Owner view'}
                </button>
                <button
                  type="button"
                  className="lv-mini-btn"
                  disabled={syncing || busy || connecting}
                  onClick={() => {
                    void syncVault(keys, cluster, store, walletScope)
                    void refreshPoolAndBalances(cluster, connectedAddress)
                  }}
                >
                  <RefreshCw size={12} className={syncing ? 'spin' : ''} />
                  {syncing ? 'Syncing…' : 'Sync RPC'}
                </button>
              </div>
            </div>

            <div className="lv-balance-list">
              {totalShieldedByMint.length === 0 ? (
                <div className="lv-balance-row">
                  <div>
                    <span className="lv-row-title">No shielded balance yet</span>
                    <span>Shield SOL or SPL tokens on the right, or share your aud1… receive address</span>
                  </div>
                  <span className="lv-balance-amt mono">0.00</span>
                </div>
              ) : (
                totalShieldedByMint.map(([m, { total, count }]) => {
                  const info = getTokenMeta(m)
                  const isWellKnown = Boolean(WELL_KNOWN_TOKENS[m])
                  const isActive = m === activeMintStr
                  return (
                    <div key={m} className="lv-balance-row">
                      <div>
                        <span className="lv-row-title">
                          {info.symbol}
                          {isActive && totalShieldedByMint.length > 1 ? ' · Active' : ''}
                        </span>
                        <span className="mono">
                          {isWellKnown ? WELL_KNOWN_TOKENS[m]!.name : shortHash(m, 6, 4)}
                          {count >= 3 ? ` · ${count} fragmented notes` : ''}
                        </span>
                      </div>
                      {strangerView ? (
                        <span className="lv-redacted-bar mono">Encrypted 106 B memo</span>
                      ) : (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                          <span className="lv-balance-amt is-pine mono">
                            {formatMintBalance(total, info)}
                          </span>
                          {!info.decimalsKnown && (
                            <button
                              type="button"
                              className="lv-mini-btn"
                              disabled={resolvingMintDecimals || busy}
                              onClick={() => void handleResolveMintDecimals(m)}
                            >
                              {resolvingMintDecimals ? 'Resolving…' : 'Resolve decimals'}
                            </button>
                          )}
                          {totalShieldedByMint.length > 1 && !isActive && (
                            <button
                              type="button"
                              className="lv-mini-btn"
                              onClick={() => {
                                maxSendSeqRef.current += 1
                                maxWithdrawSeqRef.current += 1
                                setQuotingMaxSend(false)
                                setQuotingMaxWithdraw(false)
                                lastQuotedMaxWithdrawRef.current = null
                                setSelectedMintStr(m)
                                setManualNoteKey('')
                                if (m === swapOutMint) {
                                  setSwapOutMint(m === WSOL_MINT ? (cluster === 'devnet' ? USDC_DEVNET_MINT : USDC_MAINNET_MINT) : WSOL_MINT)
                                }
                              }}
                            >
                              Select
                            </button>
                          )}
                          {count >= 3 && (
                            <button
                              type="button"
                              className="lv-mini-btn"
                              disabled={busy || rootHistoryMigrationInProgress}
                              onClick={() => handleBatchMergeNotes(m)}
                            >
                              <Layers size={12} /> Consolidate
                            </button>
                          )}
                        </div>
                      )}
                    </div>
                  )
                })
              )}
            </div>

            <div className="lv-pub-strip">
              <div className="lv-pub-strip-top">
                <div className="lv-pub-val">
                  <span>Public wallet SOL</span>
                  <span className="lv-pub-num mono">{formatUnits(pubSolLamports, 9)} SOL</span>
                </div>
                <div className="lv-pub-val">
                  <span>Shielded assets</span>
                  <span className="lv-pub-num mono">{totalShieldedByMint.length}</span>
                </div>
                <div className="lv-pub-val">
                  <span>Relayer</span>
                  <span className="lv-pub-num mono">{useRelayer ? new URL(relayUrl).host : 'Direct self-pay'}</span>
                </div>
              </div>
            </div>

            <div className="lv-private-foot">
              <div className="lv-addr-row">
                <span className="mono">
                  {cluster === 'mainnet' ? 'Mainnet' : 'Devnet'} aud1 receive address (Bech32m)
                </span>
                {mainnetEphemeralGateActive ? (
                  <>
                    <code className="mono">Back up ephemeral seed first</code>
                    <button
                      type="button"
                      className="lv-copy-chip"
                      disabled
                      title="Back up your ephemeral recovery seed before receiving Mainnet funds"
                    >
                      <Lock size={12} /> Locked
                    </button>
                  </>
                ) : (
                  <>
                    <code className="mono">{shortHash(keys.address, 14, 10)}</code>
                    <button
                      type="button"
                      className="lv-copy-chip"
                      onClick={() => {
                        if (mainnetEphemeralGateActive) return
                        copyText('addr', keys.address)
                      }}
                    >
                      {copiedField === 'addr' ? <Check size={12} /> : <Copy size={12} />}
                      {copiedField === 'addr' ? 'Copied' : 'Copy'}
                    </button>
                  </>
                )}
              </div>
              <div className="lv-custom-relay">
                <div className="lv-custom-relay-head">
                  <label className="lv-toggle-row">
                    <input
                      type="checkbox"
                      checked={useRelayer}
                      onChange={(e) => {
                        maxSendSeqRef.current += 1
                        maxWithdrawSeqRef.current += 1
                        setQuotingMaxSend(false)
                        setQuotingMaxWithdraw(false)
                        lastQuotedMaxWithdrawRef.current = null
                        setUseRelayer(e.target.checked)
                      }}
                    />
                    <span>Route spends through Privacy Relayer (zero user signer on Solana)</span>
                  </label>
                  <button
                    type="button"
                    className="lv-inline-link"
                    onClick={() => setShowRelayConfig((v) => !v)}
                  >
                    {showRelayConfig ? 'Hide relay URL' : 'Use your own relay'}
                  </button>
                </div>
                {showRelayConfig && (
                  <div className="lv-custom-relay-form">
                    <input
                      type="url"
                      className="lv-input mono"
                      value={relayDraft}
                      onChange={(e) => setRelayDraft(e.target.value)}
                      placeholder="https://relay.audren.xyz"
                    />
                    <button
                      type="button"
                      className="lv-mini-btn"
                      onClick={() => {
                        const trimmedRelay = relayDraft.trim()
                        if (isAllowedRelayUrl(trimmedRelay)) {
                          maxSendSeqRef.current += 1
                          maxWithdrawSeqRef.current += 1
                          setQuotingMaxSend(false)
                          setQuotingMaxWithdraw(false)
                          lastQuotedMaxWithdrawRef.current = null
                          relayInfoCacheRef.current = null
                          setRelayDraft(trimmedRelay)
                          setRelayUrl(trimmedRelay)
                          window.localStorage.setItem(RELAY_STORAGE_KEY, trimmedRelay)
                          setShowRelayConfig(false)
                        } else {
                          setErrorMsg('Relay URL must be https:// or http://localhost')
                        }
                      }}
                    >
                      Save relay
                    </button>
                  </div>
                )}
              </div>
            </div>
          </section>

          <section className="lv-card lv-simple-action">
            <div className="lv-verb-tabs" role="tablist">
              {(
                [
                  ['deposit', 'Shield', 'Deposit · Tag 3', ArrowDownToLine],
                  ['send', 'Send', 'Transact · Tag 5', Send],
                  ['swap', 'Swap', 'Escrow · Tag 6', ArrowLeftRight],
                  ['withdraw', 'Withdraw', 'Transact · Tag 5', ArrowUpFromLine],
                  ['compliance', 'Receipts', 'Mode 1/2', FileKey2],
                ] as const
              ).map(([id, title, sub, Icon]) => (
                <button
                  key={id}
                  type="button"
                  role="tab"
                  aria-selected={tab === id}
                  className={`lv-verb-tab ${tab === id ? 'is-active' : ''}`}
                  onClick={() => {
                    setTab(id)
                    setErrorMsg(null)
                    if (id === 'swap') {
                      setSwapEscrowShard((prev) => prev ?? pickRandomEscrowShard(NUM_ESCROW_SHARDS))
                      if (activeMintStr === swapOutMint) {
                        setSwapOutMint(
                          activeMintStr === WSOL_MINT
                            ? cluster === 'devnet'
                              ? USDC_DEVNET_MINT
                              : USDC_MAINNET_MINT
                            : WSOL_MINT,
                        )
                      }
                    }
                  }}
                >
                  <span className="lv-verb-title">
                    <Icon size={13} /> {title}
                  </span>
                  <span className="mono">{sub}</span>
                </button>
              ))}
            </div>

            <div className="lv-simple-body">
              {tab === 'deposit' && (
                <>
                  {mainnetEphemeralGateActive && seedBytes && (
                    <div className="lv-backup-box">
                      <span className="lv-box-title">Back up your ephemeral seed before depositing on Mainnet</span>
                      <p>
                        You unlocked an ephemeral browser-generated vault. Its 32-byte recovery seed lives only in memory and cannot be recovered if you close this tab. Save your seed or download an encrypted backup before depositing Mainnet funds.
                      </p>
                      <div className="lv-backup-row">
                        <button
                          type="button"
                          className="lv-mini-btn"
                          onClick={() => setEphemeralSeedRevealed((v) => !v)}
                        >
                          {ephemeralSeedRevealed ? <EyeOff size={13} /> : <Eye size={13} />}
                          {ephemeralSeedRevealed ? 'Hide seed' : 'Reveal recovery seed'}
                        </button>
                        <button
                          type="button"
                          className="lv-mini-btn"
                          onClick={() => {
                            void copyText('ephemeralSeed', toHex(seedBytes))
                            setEphemeralSeedRevealed(true)
                          }}
                        >
                          {copiedField === 'ephemeralSeed' ? <Check size={13} /> : <Copy size={13} />}
                          {copiedField === 'ephemeralSeed' ? 'Seed copied' : 'Copy recovery seed'}
                        </button>
                        <button
                          type="button"
                          className="lv-mini-btn"
                          onClick={() => setTab('compliance')}
                        >
                          <Download size={13} /> Export encrypted backup
                        </button>
                      </div>
                      {ephemeralSeedRevealed && (
                        <code className="mono" style={{ wordBreak: 'break-all', fontSize: '13px' }}>
                          {toHex(seedBytes)}
                        </code>
                      )}
                      {!ephemeralBackupDownloaded && (
                        <div className="lv-field-block" style={{ marginTop: '6px' }}>
                          <label className="lv-label">
                            Type the last 6 hex characters of your revealed seed to confirm you saved it
                          </label>
                          <input
                            type="text"
                            autoComplete="off"
                            spellCheck={false}
                            maxLength={6}
                            className="lv-input mono"
                            value={ephemeralSeedConfirmInput}
                            onChange={(e) => setEphemeralSeedConfirmInput(e.target.value)}
                            placeholder="Last 6 hex chars (or export encrypted backup)"
                          />
                        </div>
                      )}
                      <label className="lv-toggle-row">
                        <input
                          type="checkbox"
                          checked={ephemeralBackupCheckbox}
                          onChange={(e) => setEphemeralBackupCheckbox(e.target.checked)}
                        />
                        <span>
                          I have saved my recovery seed (or verified the downloaded encrypted backup file on disk) and understand Audren cannot recover lost keys.
                        </span>
                      </label>
                      <button
                        type="button"
                        className="lv-mini-btn"
                        disabled={
                          !ephemeralBackupCheckbox ||
                          (!ephemeralBackupDownloaded &&
                            (!ephemeralSeedRevealed ||
                              ephemeralSeedConfirmInput.trim().toLowerCase() !==
                                toHex(seedBytes).slice(-6).toLowerCase()))
                        }
                        onClick={() => setEphemeralBackedUp(true)}
                      >
                        <ShieldCheck size={13} /> Confirm backup &amp; unlock Mainnet deposits
                      </button>
                    </div>
                  )}

                  <div className="lv-field-block">
                    <label className="lv-label">Asset to shield</label>
                    <select
                      className="lv-select mono"
                      value={depositSource}
                      onChange={(e) => setDepositSource(e.target.value)}
                    >
                      <option value={DEPOSIT_NATIVE_SOL}>SOL ({formatUnits(pubSolLamports, 9)} available)</option>
                      {pubTokens.map((t) => (
                        <option key={t.mint} value={t.mint}>
                          {t.mint === WSOL_MINT ? 'WSOL (SPL)' : getTokenMeta(t.mint).symbol}
                          {t.tokenProgram === TOKEN_2022_PROGRAM_ID ? ' [Token-2022]' : ' [SPL]'} ({t.uiAmountString} available)
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="lv-field-block">
                    <label className="lv-label">Amount</label>
                    <input
                      type="text"
                      inputMode="decimal"
                      className="lv-input lv-amount-big mono"
                      value={depositAmount}
                      onChange={(e) => setDepositAmount(e.target.value)}
                      placeholder="0.05"
                    />
                  </div>
                  <button
                    type="button"
                    className="btn-primary lv-submit-btn"
                    disabled={busy || !connected || mainnetEphemeralGateActive || rootHistoryMigrationInProgress}
                    onClick={handleDeposit}
                  >
                    {busy ? <Loader2 size={15} className="spin" /> : <ArrowDownToLine size={15} />}
                    {!connected
                      ? 'Connect wallet to shield'
                      : mainnetEphemeralGateActive
                        ? 'Confirm seed backup above to enable Mainnet deposit'
                        : depositSource === DEPOSIT_NATIVE_SOL
                          ? 'Shield SOL into global pool'
                          : `Shield ${getTokenMeta(depositSource).symbol} into global pool`}
                  </button>
                </>
              )}

              {(tab === 'send' || tab === 'swap' || tab === 'withdraw') && (
                <>
                  <div className="lv-field-block">
                    <label className="lv-label">Shielded asset</label>
                    <select
                      className="lv-select mono"
                      value={activeMintStr}
                      onChange={(e) => {
                        const nextMint = e.target.value
                        maxSendSeqRef.current += 1
                        maxWithdrawSeqRef.current += 1
                        setQuotingMaxSend(false)
                        setQuotingMaxWithdraw(false)
                        lastQuotedMaxWithdrawRef.current = null
                        setSelectedMintStr(nextMint)
                        setManualNoteKey('')
                        setSwapEscrowShard(pickRandomEscrowShard(NUM_ESCROW_SHARDS))
                        if (nextMint === swapOutMint) {
                          setSwapOutMint(
                            nextMint === WSOL_MINT
                              ? cluster === 'devnet'
                                ? USDC_DEVNET_MINT
                                : USDC_MAINNET_MINT
                              : WSOL_MINT,
                          )
                        }
                      }}
                      disabled={totalShieldedByMint.length === 0}
                    >
                      {totalShieldedByMint.length === 0 ? (
                        <option value={WSOL_MINT}>No shielded balance synced yet</option>
                      ) : (
                        totalShieldedByMint.map(([m, { total }]) => {
                          const info = getTokenMeta(m)
                          return (
                            <option key={m} value={m}>
                              {info.symbol} ({formatMintBalance(total, info)} available)
                            </option>
                          )
                        })
                      )}
                    </select>
                  </div>

                  {activeMintNotes.length > 0 && !activeMintMeta.decimalsKnown && (
                    <div className="lv-notice-bar is-warn">
                      <AlertCircle size={14} />
                      <span style={{ flex: 1 }}>
                        On-chain decimals for mint <code>{shortHash(activeMintStr, 6, 4)}</code> are not cached yet (displayed in raw units to prevent decimal-scale mistakes). Resolve decimals via RPC before entering human token amounts.
                      </span>
                      <button
                        type="button"
                        className="lv-mini-btn"
                        disabled={resolvingMintDecimals || busy}
                        onClick={() => void handleResolveMintDecimals(activeMintStr)}
                      >
                        {resolvingMintDecimals ? 'Resolving…' : 'Resolve mint decimals (queries RPC)'}
                      </button>
                    </div>
                  )}

                  {activePlannedNotes && activePlannedNotes.length > 0 && stableLaneCounts && (
                    <p className="lv-quote-loading mono">
                      {activePlannedNotes.every((n) => isNoteEpochSettled(n, stableLaneCounts))
                        ? 'Witness root: stable epoch ring (ROOT_RING_EPOCH · full anonymity window)'
                        : 'Witness root: fast slot ring (ROOT_RING_SLOT · includes a recent deposit; epoch ring activates in ~10s)'}
                    </p>
                  )}

                  {needsBatchConsolidation && (
                    <div className="lv-notice-bar is-warn">
                      <AlertCircle size={14} />
                      <span style={{ flex: 1 }}>
                        This amount spans more than 2 shielded {activeMintMeta.symbol} notes (largest 2-note spend is{' '}
                        {formatUnits(maxSpendableNotePair, activeMintDecimals)} {activeMintMeta.symbol} of{' '}
                        {formatUnits(activeMintTotal, activeMintDecimals)} {activeMintMeta.symbol} total). Consolidate up to 4 note pairs in 1 batched transaction first.
                      </span>
                      <button
                        type="button"
                        className="lv-mini-btn"
                        disabled={busy || rootHistoryMigrationInProgress}
                        onClick={() => handleBatchMergeNotes(activeMintStr)}
                      >
                        <Layers size={12} /> Consolidate {activeMintNotes.length} notes
                      </button>
                    </div>
                  )}

                  {tab === 'send' && (
                    <>
                      <div className="lv-field-block">
                        <label className="lv-label">Recipient aud1… address (Bech32m)</label>
                        <input
                          type="text"
                          className="lv-input mono"
                          value={sendRecipient}
                          onChange={(e) => setSendRecipient(e.target.value)}
                          placeholder="aud1..."
                        />
                        {sendRecipientCheck.error && (
                          <span className="lv-receipt-verdict is-forged">{sendRecipientCheck.error}</span>
                        )}
                      </div>
                      <div className="lv-field-block">
                        <div className="lv-receipt-head">
                          <label className="lv-label">Amount ({activeMintMeta.symbol})</label>
                          {activeMintNotes.length > 0 && (
                            <button
                              type="button"
                              className="lv-inline-link mono"
                              disabled={quotingMaxSend}
                              onClick={() => void handleClickMaxSend()}
                            >
                              {quotingMaxSend
                                ? 'Quoting max…'
                                : `Max (${formatUnits(maxSendNet, activeMintDecimals)})`}
                            </button>
                          )}
                        </div>
                        <input
                          type="text"
                          inputMode="decimal"
                          className="lv-input lv-amount-big mono"
                          value={sendAmount}
                          onChange={(e) => {
                            maxSendSeqRef.current += 1
                            setQuotingMaxSend(false)
                            setSendAmount(e.target.value)
                          }}
                          placeholder="0.01"
                        />
                      </div>
                      {useRelayer && sendFeePreview && (
                        <div className="lv-quote-card">
                          <div className="lv-quote-head">
                            <span>
                              Relayer fee ·{' '}
                              {sendFeePreview.billingMode === 'self_paying' ? 'Self-paying' : 'Sponsored'}
                            </span>
                          </div>
                          <p className="lv-quote-loading mono">
                            Flat fee: {formatUnits(sendFeePreview.relayerFee, activeMintDecimals)}{' '}
                            {activeMintMeta.symbol} · private amount never sent to relayer
                          </p>
                        </div>
                      )}
                      <button
                        type="button"
                        className="btn-primary lv-submit-btn"
                        disabled={
                          busy ||
                          activeMintNotes.length === 0 ||
                          !activeMintMeta.decimalsKnown ||
                          !sendRecipientCheck.valid ||
                          needsBatchConsolidation ||
                          rootHistoryMigrationInProgress
                        }
                        onClick={() => handleTransactAction('send')}
                      >
                        {busy ? <Loader2 size={15} className="spin" /> : <Send size={15} />}
                        Send {activeMintMeta.symbol} privately
                      </button>
                    </>
                  )}

                  {tab === 'swap' && (
                    <>
                      {cluster !== 'mainnet' && (
                        <div className="lv-notice-bar is-warn">
                          <AlertCircle size={14} />
                          <span style={{ flex: 1 }}>
                            Live DEX swap routing is available on Mainnet only. Switch to Mainnet to quote and execute shielded swaps.
                          </span>
                          <button
                            type="button"
                            className="lv-mini-btn"
                            disabled={busy || connecting}
                            onClick={() => handleClusterSwitch('mainnet')}
                          >
                            Switch to Mainnet
                          </button>
                        </div>
                      )}
                      {!useRelayer && (
                        <div className="lv-notice-bar is-warn">
                          <AlertCircle size={14} />
                          <span style={{ flex: 1 }}>
                            Direct wallet submission uses 1,232 B Solana v0 packets: padded 2-nullifier or multi-hop swaps require Privacy Relayer (4,096 B Transaction v1 0x81), or switch to Economy mode (1-input) in Advanced controls for compact 1-hop direct swaps.
                          </span>
                        </div>
                      )}
                      <div className="lv-field-block">
                        <label className="lv-label">Receive token ({swapOutMeta.symbol})</label>
                        <div className="lv-quick-pills">
                          {getSwapQuickOutputs(cluster)
                            .filter((p) => p.mint !== activeMintStr)
                            .map((p) => (
                              <button
                                key={p.mint}
                                type="button"
                                className={`lv-quick-pill mono ${swapOutMint === p.mint ? 'is-active' : ''}`}
                                onClick={() => {
                                  setSwapOutMint(p.mint)
                                  setSwapEscrowShard(pickRandomEscrowShard(NUM_ESCROW_SHARDS))
                                }}
                              >
                                {p.label}
                              </button>
                            ))}
                        </div>
                        <input
                          type="text"
                          className="lv-input mono"
                          value={swapOutMint}
                          onChange={(e) => {
                            const next = e.target.value
                            setSwapOutMint(next)
                            if (isValidSolanaPubkey(next)) {
                              setSwapEscrowShard(pickRandomEscrowShard(NUM_ESCROW_SHARDS))
                            }
                          }}
                          placeholder="Output Solana token mint"
                        />
                      </div>
                      <div className="lv-field-block">
                        <div className="lv-receipt-head">
                          <label className="lv-label">Swap amount ({activeMintMeta.symbol})</label>
                          {activeMintNotes.length > 0 && (
                            <button
                              type="button"
                              className="lv-inline-link mono"
                              onClick={() =>
                                setSwapAmount(formatUnitsExact(maxSpendableNotePair, activeMintDecimals))
                              }
                            >
                              Max ({formatUnits(maxSpendableNotePair, activeMintDecimals)})
                            </button>
                          )}
                        </div>
                        <input
                          type="text"
                          inputMode="decimal"
                          className="lv-input lv-amount-big mono"
                          value={swapAmount}
                          onChange={(e) => {
                            const next = e.target.value
                            setSwapAmount(next)
                            if (!next.trim()) {
                              swapQuoteAbortRef.current?.abort()
                              swapQuoteSeqRef.current += 1
                              clearSwapQuoteState()
                            }
                          }}
                          placeholder="0.05"
                        />
                      </div>
                      <div className="lv-quote-card">
                        <div className="lv-quote-head">
                          <span>
                            Live escrow quote
                            {swapQuoteProvider ? ` · ${swapQuoteProvider}` : ''}
                          </span>
                          {swapQuoteLoading && <Loader2 size={13} className="spin" />}
                        </div>
                        {swapQuoteMatches && swapQuoteOut && parseBigIntSafe(swapQuoteOut) !== null ? (
                          (() => {
                            const parsedOut = parseBigIntSafe(swapQuoteOut)!
                            const safeSlip = clampSlippageBps(swapSlippageBps)
                            const minGuaranteedGross = (parsedOut * BigInt(10_000 - safeSlip)) / 10_000n
                            const minGuaranteedNet = computeToken2022NetAmount(
                              minGuaranteedGross,
                              swapQuoteMintMeta?.outputTransferFee ?? null,
                            )
                            return (
                              <div className="lv-quote-pair">
                                <div>
                                  <span>Estimated shielded output</span>
                                  <span className="lv-quote-val is-pine mono">
                                    {formatUnits(parsedOut, swapOutMeta.decimals)} {swapOutMeta.symbol}
                                  </span>
                                </div>
                                <div>
                                  <span>Minimum guaranteed ({(safeSlip / 100).toFixed(2)}% max slippage)</span>
                                  <span className="lv-quote-val mono">
                                    {formatUnits(minGuaranteedNet, swapOutMeta.decimals)} {swapOutMeta.symbol}
                                  </span>
                                </div>
                              </div>
                            )
                          })()
                        ) : (
                          <p className="lv-quote-loading">
                            {cluster !== 'mainnet'
                              ? 'Live DEX swap quotes are available on Mainnet only.'
                              : swapQuoteLoading
                                ? 'Fetching live PDA-safe route…'
                                : 'Enter an amount to fetch a live PDA-safe route.'}
                          </p>
                        )}
                        {swapQuoteMatches &&
                          swapInputFeeBps > 0 &&
                          swapQuoteNetIn &&
                          parseBigIntSafe(swapQuoteNetIn) !== null && (
                            <p className="lv-quote-loading mono">
                              Token-2022 input fee ({(swapInputFeeBps / 100).toFixed(2)}%) deducted before route · net input{' '}
                              {formatUnits(parseBigIntSafe(swapQuoteNetIn)!, activeMintDecimals)} {activeMintMeta.symbol}
                            </p>
                          )}
                      </div>
                      <button
                        type="button"
                        className="btn-primary lv-submit-btn"
                        disabled={
                          busy ||
                          cluster !== 'mainnet' ||
                          activeMintNotes.length === 0 ||
                          !activeMintMeta.decimalsKnown ||
                          !swapQuoteMatches ||
                          needsBatchConsolidation ||
                          rootHistoryMigrationInProgress
                        }
                        onClick={handleShieldedSwap}
                      >
                        {busy ? <Loader2 size={15} className="spin" /> : <ArrowLeftRight size={15} />}
                        {cluster !== 'mainnet'
                          ? 'Shielded swap available on Mainnet only'
                          : `Swap ${activeMintMeta.symbol} to ${swapOutMeta.symbol} privately`}
                      </button>
                    </>
                  )}

                  {tab === 'withdraw' && (
                    <>
                      <div className="lv-field-block">
                        <label className="lv-label">Public Solana recipient</label>
                        <input
                          type="text"
                          className="lv-input mono"
                          value={withdrawRecipient}
                          onChange={(e) => {
                            maxWithdrawSeqRef.current += 1
                            setQuotingMaxWithdraw(false)
                            lastQuotedMaxWithdrawRef.current = null
                            setWithdrawRecipient(e.target.value)
                          }}
                          placeholder="Solana public address"
                        />
                      </div>
                      <div className="lv-field-block">
                        <div className="lv-receipt-head">
                          <label className="lv-label">
                            Withdraw amount ({activeMintMeta.symbol}
                            {activeMintStr === WSOL_MINT && unwrapWsol ? ' · native SOL' : ''})
                          </label>
                          {activeMintNotes.length > 0 && (
                            <button
                              type="button"
                              className="lv-inline-link mono"
                              disabled={quotingMaxWithdraw}
                              onClick={() => void handleClickMaxWithdraw()}
                            >
                              {quotingMaxWithdraw ? 'Quoting max…' : `Max (${formatUnits(maxSpendableNotePair, activeMintDecimals)})`}
                            </button>
                          )}
                        </div>
                        <input
                          type="text"
                          inputMode="decimal"
                          className="lv-input lv-amount-big mono"
                          value={withdrawAmount}
                          onChange={(e) => {
                            maxWithdrawSeqRef.current += 1
                            setQuotingMaxWithdraw(false)
                            lastQuotedMaxWithdrawRef.current = null
                            setWithdrawAmount(e.target.value)
                          }}
                          placeholder="0.01"
                        />
                      </div>
                      {useRelayer && !(activeMintStr === WSOL_MINT && unwrapWsol) && !knownSelfRecipientHasAta && (
                        <>
                          <label className="lv-toggle-row">
                            <input
                              type="checkbox"
                              checked={recipientNeedsAta}
                              onChange={(e) => {
                                maxWithdrawSeqRef.current += 1
                                setQuotingMaxWithdraw(false)
                                lastQuotedMaxWithdrawRef.current = null
                                setRecipientNeedsAta(e.target.checked)
                              }}
                            />
                            <span>
                              Create recipient token account if missing (includes ATA rent in relayer fee; zero web-host recipient lookup)
                            </span>
                          </label>
                          {recipientNeedsAta && withdrawFeePreview?.billingMode === 'sponsored' && (
                            <p className="lv-quote-loading">
                              Sponsored relays cannot create a new recipient token account; uncheck if the recipient already has an ATA to unlock self-paying settlement, or switch to Direct Self-Pay.
                            </p>
                          )}
                        </>
                      )}
                      {useRelayer && withdrawFeePreview && (
                        <div className="lv-quote-card">
                          <div className="lv-quote-head">
                            <span>
                              Relayer fee ·{' '}
                              {withdrawFeePreview.billingMode === 'self_paying' ? 'Self-paying' : 'Sponsored'}
                            </span>
                          </div>
                          <p className="lv-quote-loading mono">
                            Fee: {formatUnits(withdrawFeePreview.relayerFee, activeMintDecimals)}{' '}
                            {activeMintMeta.symbol} · {withdrawFeePreview.reason}
                          </p>
                        </div>
                      )}
                      <button
                        type="button"
                        className="btn-primary lv-submit-btn"
                        disabled={
                          busy ||
                          activeMintNotes.length === 0 ||
                          !activeMintMeta.decimalsKnown ||
                          !withdrawRecipient.trim() ||
                          !withdrawAmount.trim() ||
                          needsBatchConsolidation ||
                          rootHistoryMigrationInProgress
                        }
                        onClick={() => handleTransactAction('withdraw')}
                      >
                        {busy ? <Loader2 size={15} className="spin" /> : <ArrowUpFromLine size={15} />}
                        Withdraw {activeMintMeta.symbol}
                      </button>
                    </>
                  )}
                </>
              )}

              {tab !== 'compliance' && (
                <div className="lv-backup-box">
                  <button
                    type="button"
                    className="lv-inline-link"
                    style={{ justifyContent: 'space-between', width: '100%', textDecoration: 'none' }}
                    onClick={() => setShowAdvanced((v) => !v)}
                  >
                    <span className="lv-row-title">
                      <SlidersHorizontal size={13} /> Advanced protocol controls
                    </span>
                    {showAdvanced ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                  </button>

                  {showAdvanced && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', paddingTop: '6px' }}>
                      {tab === 'deposit' && depositSource === DEPOSIT_NATIVE_SOL && (
                        <label className="lv-checkbox-card">
                          <input
                            type="checkbox"
                            checked={feeFromAmount}
                            onChange={(e) => setFeeFromAmount(e.target.checked)}
                          />
                          <div>
                            <span className="lv-checkbox-title">Zero-dust sweep (DEPOSIT_FLAG_FEE_FROM_AMOUNT)</span>
                            <span>Deducts amortized page rent from the shielded SOL amount so ephemeral wallets sweep cleanly to 0 lamports.</span>
                          </div>
                        </label>
                      )}

                      {tab === 'withdraw' && activeMintStr === WSOL_MINT && (
                        <label className="lv-checkbox-card">
                          <input
                            type="checkbox"
                            checked={unwrapWsol}
                            onChange={(e) => {
                              maxWithdrawSeqRef.current += 1
                              setQuotingMaxWithdraw(false)
                              lastQuotedMaxWithdrawRef.current = null
                              setUnwrapWsol(e.target.checked)
                            }}
                          />
                          <div>
                            <span className="lv-checkbox-title">Unwrap WSOL to native SOL atomically (WITHDRAW_FLAG_UNWRAP_WSOL)</span>
                            <span>Enabled by default via a 1-shot <code>audren_unwrap</code> PDA and works even when the pool is paused. Uncheck to withdraw raw SPL WSOL.</span>
                          </div>
                        </label>
                      )}

                      {tab === 'swap' && (
                        <>
                          <div className="lv-field-block">
                            <label className="lv-label">Slippage tolerance (bps)</label>
                            <input
                              type="number"
                              className="lv-input mono"
                              value={swapSlippageBps}
                              min={10}
                              max={1500}
                              onChange={(e) => setSwapSlippageBps(clampSlippageBps(Number(e.target.value)))}
                            />
                          </div>
                          <label className="lv-checkbox-card">
                            <input
                              type="checkbox"
                              checked={swapFeeOnOutput}
                              onChange={(e) => setSwapFeeOnOutput(e.target.checked)}
                            />
                            <div>
                              <span className="lv-checkbox-title">Pay relayer from swap output (EXEC_FLAG_FEE_ON_OUTPUT)</span>
                              <span>Atomic post-CPI deduction from received output tokens when relayed with a non-zero fee.</span>
                            </div>
                          </label>
                        </>
                      )}

                      {(tab === 'send' || tab === 'swap' || tab === 'withdraw') && (
                        <>
                          <div className="lv-field-block">
                            <label className="lv-label">UTXO note selection ({activeMintNotes.length} notes for {activeMintMeta.symbol})</label>
                            <select
                              className="lv-select mono"
                              value={manualNoteKey}
                              onChange={(e) => {
                                maxSendSeqRef.current += 1
                                maxWithdrawSeqRef.current += 1
                                setQuotingMaxSend(false)
                                setQuotingMaxWithdraw(false)
                                lastQuotedMaxWithdrawRef.current = null
                                setManualNoteKey(e.target.value)
                                setSwapEscrowShard(pickRandomEscrowShard(NUM_ESCROW_SHARDS))
                              }}
                              disabled={activeMintNotes.length === 0}
                            >
                              <option value="">Automatic (opportunistic 2-note pairing)</option>
                              {activeMintNotes.map((n) => {
                                const k = noteKey(n)
                                return (
                                  <option key={k} value={k}>
                                    Lane #{n.laneId} · Leaf #{n.leafIndex.toString()} · {formatUnits(n.amount, activeMintDecimals)} {activeMintMeta.symbol}
                                  </option>
                                )
                              })}
                            </select>
                            {activePlannedNotes && activePlannedNotes.length > 0 && (
                              <span className="lv-quote-loading mono">
                                Planned inputs:{' '}
                                {activePlannedNotes
                                  .map(
                                    (n) =>
                                      `Lane #${n.laneId} Leaf #${n.leafIndex.toString()} (${formatUnits(n.amount, activeMintDecimals)} ${activeMintMeta.symbol})`,
                                  )
                                  .join(' + ')}
                              </span>
                            )}
                          </div>

                          {activeMintNotes.length >= 2 && (
                            <div className="lv-receipt-actions">
                              <button
                                type="button"
                                className="lv-mini-btn"
                                disabled={busy || rootHistoryMigrationInProgress}
                                onClick={() => handleBatchMergeNotes(activeMintStr)}
                              >
                                <Layers size={13} /> Consolidate up to 4 pairs ({activeMintNotes.length} {activeMintMeta.symbol} notes)
                              </button>
                            </div>
                          )}

                          <label className="lv-checkbox-card">
                            <input
                              type="checkbox"
                              checked={economyMode}
                              onChange={(e) => {
                                maxSendSeqRef.current += 1
                                maxWithdrawSeqRef.current += 1
                                setQuotingMaxSend(false)
                                setQuotingMaxWithdraw(false)
                                lastQuotedMaxWithdrawRef.current = null
                                setEconomyMode(e.target.checked)
                              }}
                            />
                            <div>
                              <span className="lv-checkbox-title">Economy mode (1 nullifier &amp; unpadded full-note exits)</span>
                              <span>
                                Saves ~0.00065 SOL in NullifierPDA rent (live SysvarRent) on 1-note spends and skips zero-value change padding on full-note exits. Tradeoff: observers can distinguish 1-note spends and full sweeps from 2-note partial spends.
                              </span>
                            </div>
                          </label>
                        </>
                      )}

                      <p className="lv-quote-loading mono">
                        Birthday slot: #{vaultBirthdaySlot.toString()} · Unspent notes: {unspentNotes.length} · Prover: Web Worker
                      </p>
                    </div>
                  )}
                </div>
              )}

              {tab === 'compliance' && (
                <>
                  <div className="lv-receipt-drawer">
                    <div className="lv-receipt-head">
                      <span className="lv-box-title">Mode 1 · Single-note selective disclosure proof</span>
                      <button
                        type="button"
                        className="lv-mini-btn"
                        disabled={!complianceNote}
                        onClick={handleGenerateReceipt}
                      >
                        Export note proof
                      </button>
                    </div>
                    <p className="lv-receipt-copy">
                      Proves one note&apos;s mint, amount, and Poseidon commitment directly against its live on-chain <code>SubtreePage</code> leaf without revealing your viewing key, spend key, or any other note.
                    </p>
                    {unspentNotes.length > 0 && (
                      <select
                        className="lv-select mono"
                        value={complianceNote ? noteKey(complianceNote) : ''}
                        onChange={(e) => setComplianceNoteKey(e.target.value)}
                      >
                        {unspentNotes.map((n) => {
                          const mStr = base58Encode(n.mint)
                          const info = getTokenMeta(mStr)
                          const k = noteKey(n)
                          return (
                            <option key={k} value={k}>
                              Lane #{n.laneId} · Leaf #{n.leafIndex.toString()} · {formatUnits(n.amount, info.decimals)} {info.symbol}
                            </option>
                          )
                        })}
                      </select>
                    )}
                    <textarea
                      className="lv-input mono"
                      rows={5}
                      value={receiptJson}
                      onChange={(e) => {
                        verifyReceiptSeqRef.current += 1
                        setVerifyingReceipt(false)
                        setReceiptJson(e.target.value)
                        setReceiptVerdict(null)
                        setReceiptVerdictDetail(null)
                      }}
                      placeholder="Paste a SelectiveDisclosureProof JSON payload to verify on-chain…"
                    />
                    <div className="lv-receipt-actions">
                      <button
                        type="button"
                        className="lv-mini-btn"
                        disabled={verifyingReceipt || !receiptJson.trim()}
                        onClick={() => void handleVerifyReceipt()}
                      >
                        {verifyingReceipt ? <Loader2 size={13} className="spin" /> : <ShieldCheck size={13} />}
                        {verifyingReceipt ? 'Checking SubtreePage…' : `Verify on-chain (${cluster})`}
                      </button>
                      {receiptVerdict && (
                        <span className={`lv-receipt-verdict ${receiptVerdict === 'valid' ? 'is-valid' : 'is-forged'}`}>
                          {receiptVerdict === 'valid'
                            ? `Valid · ${receiptVerdictDetail ?? 'On-chain leaf verified'}`
                            : `Invalid · ${receiptVerdictDetail ?? 'Commitment mismatch'}`}
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="lv-backup-box">
                    <div className="lv-receipt-head">
                      <span className="lv-box-title">Mode 2 · Read-only FullViewingKey</span>
                      <button type="button" className="lv-mini-btn" onClick={() => setShowFvk((v) => !v)}>
                        {showFvk ? 'Hide FVK' : 'Reveal FVK'}
                      </button>
                    </div>
                    <p>
                      Grants read-only inbound &amp; outbound visibility (<code>spendPk, nk, viewSk, viewPk</code>) for treasury accounting without spend authority.
                    </p>
                    {showFvk && fvkExport && (
                      <pre className="mono" style={{ fontSize: '13px', overflowX: 'auto' }}>
                        {fvkExport}
                      </pre>
                    )}
                  </div>

                  {defiSession && (
                    <div className="lv-backup-box">
                      <div className="lv-receipt-head">
                        <span className="lv-box-title">Pseudonymous DeFi session wallet (#{sessionIndex})</span>
                        <div className="lv-priority-btns">
                          <button
                            type="button"
                            className="lv-mini-btn"
                            onClick={() => updateSessionIndex((i) => Math.max(0, i - 1))}
                          >
                            −
                          </button>
                          <button
                            type="button"
                            className="lv-mini-btn"
                            onClick={() => updateSessionIndex((i) => i + 1)}
                          >
                            +
                          </button>
                        </div>
                      </div>
                      <p>
                        Deterministic Ed25519 keypair for stateful lending, perps, or CLMM positions.{' '}
                        <span className="lv-strong">Boundary:</span> funding via relayed Withdraw removes the direct on-chain signer link to your main wallet, while timing/amount correlation and all external DeFi actions executed by this session wallet remain public on Solana.
                      </p>
                      <div className="lv-addr-row">
                        <code className="mono">{defiSession.pubkeyBase58}</code>
                        <button
                          type="button"
                          className="lv-copy-chip"
                          onClick={() => copyText('session', defiSession.pubkeyBase58)}
                        >
                          {copiedField === 'session' ? <Check size={12} /> : <Copy size={12} />}
                          {copiedField === 'session' ? 'Copied' : 'Copy'}
                        </button>
                      </div>
                    </div>
                  )}

                  <div className="lv-backup-box">
                    <span className="lv-box-title">Encrypted vault backup (PBKDF2-SHA256 + AES-256-GCM)</span>
                    <p>
                      Export or restore your Audren master seed with its recorded birthday slot (#{vaultBirthdaySlot.toString()}). Local IndexedDB cache can also be cleared anytime.
                    </p>
                    <div className="lv-backup-row">
                      <input
                        type="password"
                        className="lv-input"
                        value={backupPassphrase}
                        onChange={(e) => setBackupPassphrase(e.target.value)}
                        placeholder="Passphrase (min 8 chars)"
                      />
                      <input
                        type="text"
                        inputMode="numeric"
                        className="lv-input mono"
                        value={restoreBirthdayInput}
                        onChange={(e) => setRestoreBirthdayInput(e.target.value)}
                        placeholder="Restore birthday slot (optional)"
                      />
                      <button type="button" className="lv-mini-btn" onClick={handleExportBackup}>
                        <Download size={13} /> Export
                      </button>
                      <button
                        type="button"
                        className="lv-mini-btn"
                        disabled={busy || connecting}
                        onClick={() => fileInputRef.current?.click()}
                      >
                        <Upload size={13} /> Restore
                      </button>
                      <input
                        ref={fileInputRef}
                        type="file"
                        accept="application/json"
                        style={{ display: 'none' }}
                        onChange={(e) => {
                          const f = e.target.files?.[0]
                          e.target.value = ''
                          if (f) void handleImportBackup(f)
                        }}
                      />
                      <button
                        type="button"
                        className="lv-mini-btn"
                        disabled={syncing || busy || connecting}
                        onClick={async () => {
                          const targetCluster = cluster
                          const startVaultEpoch = vaultEpochRef.current
                          await clearEncryptedCompactStore(keys.spendPkBytes, targetCluster, 0, walletScope)
                          if (vaultEpochRef.current !== startVaultEpoch || clusterRef.current !== targetCluster) {
                            return
                          }
                          setStore(null)
                          setUnspentNotes([])
                          setSyncError(null)
                          setBackupStatus('Cleared local cache; rescanning from birthday slot...')
                          void syncVault(keys, targetCluster, null, walletScope, {
                            birthdaySlot: birthdayByCluster[targetCluster],
                            resetStore: true,
                            source: unlockSourceRef.current,
                          })
                        }}
                      >
                        Clear cache
                      </button>
                    </div>
                    {backupStatus && <p className="lv-backup-status mono">{backupStatus}</p>}
                  </div>
                </>
              )}

              {syncError && (
                <div className="lv-error-bar" style={{ alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                  <AlertCircle size={14} />
                  <span style={{ flex: 1 }}>RPC sync failed: {syncError}</span>
                  <button
                    type="button"
                    className="lv-mini-btn"
                    disabled={syncing || busy || connecting}
                    onClick={async () => {
                      const targetCluster = cluster
                      const startVaultEpoch = vaultEpochRef.current
                      await clearEncryptedCompactStore(keys.spendPkBytes, targetCluster, 0, walletScope)
                      if (vaultEpochRef.current !== startVaultEpoch || clusterRef.current !== targetCluster) {
                        return
                      }
                      setStore(null)
                      setUnspentNotes([])
                      setSyncError(null)
                      void syncVault(keys, targetCluster, null, walletScope, {
                        birthdaySlot: birthdayByCluster[targetCluster],
                        resetStore: true,
                        source: unlockSourceRef.current,
                      })
                    }}
                  >
                    <RefreshCw size={12} /> Reset &amp; rescan
                  </button>
                </div>
              )}

              {statusMsg && (
                <div className="lv-notice-bar">
                  <ShieldCheck size={14} />
                  <span style={{ flex: 1 }}>{statusMsg}</span>
                </div>
              )}

              {errorMsg && (
                <div className="lv-error-bar">
                  <AlertCircle size={14} />
                  <span>{errorMsg}</span>
                </div>
              )}

              {lastReceipt && (
                <div className="lv-audit-card">
                  <div className="lv-audit-head">
                    <h4>{lastReceipt.kind}</h4>
                    <a
                      href={solscanTx(lastReceipt.signature, lastReceipt.cluster)}
                      target="_blank"
                      rel="noreferrer"
                      className="lv-ledger-ext mono"
                    >
                      {shortHash(lastReceipt.signature, 8, 6)} <ArrowUpRight size={12} />
                    </a>
                  </div>
                  <p>{lastReceipt.summary}</p>
                  <div className="lv-proof-badge is-hidden mono">
                    {lastReceipt.pending ? 'Pending confirmation · ' : ''}
                    {lastReceipt.relayed ? 'Zero-signer relayed' : 'Direct self-pay'}
                    {lastReceipt.proverMs !== undefined ? ` · Web Worker prover ${lastReceipt.proverMs} ms` : ''}
                  </div>
                </div>
              )}
            </div>
          </section>
        </div>
      )}

      <div className="lv-backup-meta mono">
        <span>Program ID: </span>
        <a href={solscanAddress(AUDREN.programId, cluster)} target="_blank" rel="noreferrer">
          {AUDREN.programId}
        </a>
      </div>
    </div>
  )
}
