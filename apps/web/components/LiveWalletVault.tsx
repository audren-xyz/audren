'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ArrowDownUp,
  ArrowRight,
  ArrowUpRight,
  Check,
  ChevronDown,
  Code2,
  Copy,
  Download,
  EyeOff,
  ExternalLink,
  KeyRound,
  Layers,
  Lock,
  RefreshCw,
  Search,
  Send,
  Shield,
  ShieldCheck,
  Unlock,
  Upload,
  Wallet,
} from 'lucide-react'
import {
  NATIVE_SOL_MINT,
  base58Decode,
  base58Encode,
  buildSelectiveDisclosureReceipt,
  fromBase64,
  generateAudrenKeys,
  toBase64,
  verifySelectiveDisclosureOnPage,
  type AudrenKeypair,
  type SelectiveDisclosureReceipt,
  type SolanaInstruction,
} from '@/lib/audren-crypto'
import {
  CLASSIC_TOKEN_PROGRAM_ID_STR,
  MAX_MERGE_RING_SLOTS,
  PAGE_ROLLOVER_THRESHOLD,
  USDC_MAINNET_MINT_STR,
  WSOL_MINT,
  WSOL_MINT_STR,
  buildBufferedExecutionPlan,
  buildCloseProofBufferInstruction,
  buildCreateAtaIdempotentIx,
  buildDepositInstruction,
  buildExecViaEscrowInstruction,
  buildMergeInstruction,
  buildOpenLanePageInstruction,
  buildOpenPageInstruction,
  buildTransferInstruction,
  buildWalletUnlockMessage,
  buildWithdrawInstruction,
  buildCloseWsolAtaInstruction,
  buildWrapSolInstructions,
  calculateTransferFee,
  clearEncryptedVaultInventory,
  deriveAta,
  deriveDefiSessionKeypair,
  deriveSeedFromWalletSignature,
  exportEncryptedVaultBackup,
  extractRingFromPage,
  importEncryptedVaultBackup,
  loadEncryptedVaultInventory,
  loadPendingProofBuffers,
  netDepositAmount,
  pageIdForLane,
  parseAudrenAddress,
  recordPendingProofBuffer,
  removePendingProofBuffer,
  saveEncryptedVaultInventory,
  scanEpochPageSpendable,
  scanPageScanSlice,
  seqOfPageId,
  verifyDynamicAmountForNote,
  type AudrenEncryptedBackupFile,
  type RingSlotWitness,
  type SpendableAudrenNote,
  type VaultInventorySnapshot,
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

type VaultActionTab = 'shield' | 'transfer' | 'swap' | 'withdraw'
type FeeMode = 'relayer' | 'self'
type PriorityTier = 'standard' | 'fast' | 'turbo'

interface SearchTokenCard {
  mint: string
  symbol: string
  name: string
  decimals: number | null
  tokenProgram: string
  logoUrl: string | null
  priceUsd: number | null
  liquidityUsd: number | null
  verified: boolean
  flagged: boolean
}

interface WalletTokenBalance {
  mint: string
  symbol: string
  name: string
  decimals: number
  amountRaw: string
  uiAmount: number
  tokenProgram: string
  ata: string
  logoUrl: string | null
  priceUsd: number | null
  usdValue: number | null
  verified: boolean
  flagged: boolean
  hasActiveTransferFee?: boolean
  transferFeeBps?: number
  transferFeeMax?: string
  hasActiveTransferHook?: boolean
  isNonTransferable?: boolean
}

interface WalletBalancesResponse {
  cluster: SolanaCluster
  address: string
  solLamports: string
  solUi: number
  solPriceUsd: number | null
  solUsdValue: number | null
  solLogoUrl: string | null
  tokens: WalletTokenBalance[]
  blockhash: string
  lastValidBlockHeight: number
}

interface PoolPageSummary {
  pageId: string
  pagePda: string
  count: number
  closed: boolean
  pageBase64: string
}

interface PoolLaneSummary {
  laneId: number
  activePageId: string
  pageCount: number
  pageClosed: boolean
  createdSlot?: string
}

interface PoolResponse {
  cluster: SolanaCluster
  programId: string
  poolId: number
  poolPda: string
  solVaultPda: string
  vaultAuthPda: string
  swapEscrow0Pda: string
  solVaultLamports: number
  relayerAvailable: boolean
  relayerAddress: string | null
  relayerLamports: number | null
  pageRentFeeLamports: string
  activeLanes?: number
  lanes?: PoolLaneSummary[]
  currentPageId: string
  pagePda: string
  pageCount: number
  pageClosed: boolean
  totalNotes: string
  totalSpends: string
  paused: boolean
  ataExists: {
    vaultUsdc: boolean
    vaultWsol: boolean
    escrowUsdc: boolean
    escrowWsol: boolean
  }
  pages: PoolPageSummary[]
}

interface JupiterQuoteResponse {
  provider?: string
  inputMint?: string
  outputMint?: string
  slippageBps?: number
  rawQuote?: Record<string, unknown>
  feePlan?: {
    billingMode: 'self_paying' | 'sponsored'
    platformFeeBps: number
    feeAccount: string | null
    needsFeeAtaSetup?: boolean
    reason: string
  }
  quote: {
    inAmount: string
    outAmount: string
    otherAmountThreshold: string
    priceImpactPct?: string
    routePlan?: Array<{ swapInfo?: { label?: string } }>
  }
  usedDirectOnly: boolean
  shardId?: number
  swapEscrowPda: string
  vaultAuthPda: string
  escrowInAta: string
  escrowOutAta: string
  vaultInAta: string
  vaultOutAta: string
  tokenProgramIn: string
  tokenProgramOut: string
  missingAtas: Array<{
    label: string
    ata: string
    owner: string
    mint: string
    tokenProgram: string
  }>
}

const DEFAULT_RELAY_URL = (
  process.env.NEXT_PUBLIC_AUDREN_RELAY_URL || 'https://relay.audren.xyz'
).replace(/\/+$/, '')
const CUSTOM_RELAY_STORAGE_KEY = 'audren_custom_relayer_url_v1'

function normalizeRelayerUrl(raw: string): { ok: true; url: string } | { ok: false; error: string } {
  const trimmed = raw.trim().replace(/\/+$/, '')
  if (!trimmed) return { ok: true, url: DEFAULT_RELAY_URL }
  try {
    const parsed = new URL(trimmed)
    const isLocal = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1'
    if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLocal)) {
      return { ok: false, error: 'Relayer URL must start with https:// (or http://localhost for local dev).' }
    }
    return { ok: true, url: `${parsed.origin}${parsed.pathname}`.replace(/\/+$/, '') }
  } catch {
    return { ok: false, error: 'Enter a valid relayer URL, e.g. https://relay.audren.xyz' }
  }
}

function relayerHostLabel(url: string): string {
  try {
    return new URL(url).host
  } catch {
    return url
  }
}

interface OnChainTxProof {
  loading: boolean
  txVersion?: string
  signers?: string[]
  walletPresent?: boolean
  walletIsSigner?: boolean
  totalAccounts?: number
  computeUnits?: number | null
  feeLamports?: number
  error?: string
}

interface AuditRecord {
  action:
    | 'Make Private'
    | 'Pay Private Address'
    | 'Private Transfer'
    | 'Combine Notes'
    | 'DEX Swap'
    | 'Withdraw'
    | 'Withdraw (Unwrap WSOL)'
    | 'Reclaim Buffer Rent'
  cluster: SolanaCluster
  signature: string
  slot: number
  solscanUrl: string
  explorerUrl: string
  txFormat: string
  feePayerMode: FeeMode
  feePayerAddress: string
  priorityLabel: string
  proverMs: number
  summary: string
  publicSaw: string
  stayedPrivate: string
  sdkCode: string
  onChainProof?: OnChainTxProof
}

const VAULT_SEED_SESSION_PREFIX = 'audren_vault_seed_v1:'
const LAST_WALLET_SESSION_KEY = 'audren_last_wallet_v1'
const LAST_CLUSTER_STORAGE_KEY = 'audren_last_cluster_v1'

function loadSavedCluster(): SolanaCluster | null {
  if (typeof window === 'undefined') return null
  try {
    const val = window.localStorage.getItem(LAST_CLUSTER_STORAGE_KEY)
    return val === 'devnet' || val === 'mainnet' ? val : null
  } catch {
    return null
  }
}

function saveCluster(c: SolanaCluster) {
  if (typeof window === 'undefined') return
  try {
    window.localStorage.setItem(LAST_CLUSTER_STORAGE_KEY, c)
  } catch {
    // ignore
  }
}

function getPerfNowMs(): number {
  return typeof performance !== 'undefined' ? performance.now() : Date.now()
}

function getEpochNowMs(): number {
  return Date.now()
}

function loadSessionVaultSeed(address: string): Uint8Array | null {
  if (typeof window === 'undefined') return null
  try {
    const b64 = window.sessionStorage.getItem(`${VAULT_SEED_SESSION_PREFIX}${address}`)
    if (!b64) return null
    const bytes = fromBase64(b64)
    return bytes.length === 32 ? bytes : null
  } catch {
    return null
  }
}

function saveSessionVaultSeed(address: string, seed: Uint8Array) {
  if (typeof window === 'undefined') return
  try {
    window.sessionStorage.setItem(`${VAULT_SEED_SESSION_PREFIX}${address}`, toBase64(seed))
  } catch {
    // ignore storage quota errors
  }
}

function clearSessionVault(address?: string) {
  if (typeof window === 'undefined') return
  try {
    window.localStorage.removeItem(LAST_WALLET_SESSION_KEY)
    window.sessionStorage.removeItem(LAST_WALLET_SESSION_KEY)
    if (address) window.sessionStorage.removeItem(`${VAULT_SEED_SESSION_PREFIX}${address}`)
  } catch {
    // ignore
  }
}

function loadLastWalletName(): string | null {
  if (typeof window === 'undefined') return null
  try {
    return (
      window.localStorage.getItem(LAST_WALLET_SESSION_KEY) ??
      window.sessionStorage.getItem(LAST_WALLET_SESSION_KEY)
    )
  } catch {
    return null
  }
}

function saveLastWalletName(name: string) {
  if (typeof window === 'undefined') return
  try {
    window.localStorage.setItem(LAST_WALLET_SESSION_KEY, name)
    window.sessionStorage.setItem(LAST_WALLET_SESSION_KEY, name)
  } catch {
    // ignore
  }
}

function formatUsd(val: number | null | undefined): string | null {
  if (val === null || val === undefined || !Number.isFinite(val) || val <= 0) return null
  if (val < 0.01) return '<$0.01'
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    maximumFractionDigits: val >= 100 ? 0 : 2,
  }).format(val)
}

const PRIORITY_TIERS: Record<
  PriorityTier,
  { label: string; relayerLamports: bigint; microLamportsPerCu: bigint; desc: string }
> = {
  standard: {
    label: 'Standard',
    relayerLamports: 5_000n,
    microLamportsPerCu: 10_000n,
    desc: '~0.000005 SOL',
  },
  fast: {
    label: 'Fast',
    relayerLamports: 20_000n,
    microLamportsPerCu: 50_000n,
    desc: '~0.00002 SOL',
  },
  turbo: {
    label: 'Turbo',
    relayerLamports: 50_000n,
    microLamportsPerCu: 150_000n,
    desc: '~0.00005 SOL',
  },
}

const DYNAMIC_AMOUNTS_STORAGE_KEY = 'audren_dynamic_note_amounts_v1'

function loadKnownDynamicAmounts(): Record<string, bigint> {
  if (typeof window === 'undefined') return {}
  try {
    const raw = window.localStorage.getItem(DYNAMIC_AMOUNTS_STORAGE_KEY)
    if (!raw) return {}
    const parsed = JSON.parse(raw) as Record<string, string>
    const out: Record<string, bigint> = {}
    for (const [k, v] of Object.entries(parsed)) {
      if (/^\d+$/.test(v)) out[k] = BigInt(v)
    }
    return out
  } catch {
    return {}
  }
}

function saveKnownDynamicAmount(stealthPkB58: string, amount: bigint) {
  if (typeof window === 'undefined') return
  try {
    const raw = window.localStorage.getItem(DYNAMIC_AMOUNTS_STORAGE_KEY)
    const parsed = raw ? (JSON.parse(raw) as Record<string, string>) : {}
    parsed[stealthPkB58] = amount.toString()
    window.localStorage.setItem(DYNAMIC_AMOUNTS_STORAGE_KEY, JSON.stringify(parsed))
  } catch {
    // ignore storage errors
  }
}

function shortAddr(s: string, head = 5, tail = 4): string {
  if (s.length <= head + tail + 3) return s
  return `${s.slice(0, head)}…${s.slice(-tail)}`
}

function tokenMeta(
  mintB58: string,
  walletTokens?: WalletTokenBalance[],
  resolved?: Record<string, SearchTokenCard>,
  solLogoUrl?: string | null,
  solPriceUsd?: number | null,
): {
  symbol: string
  name: string
  decimals: number
  tokenProgram: string
  logoUrl: string | null
  priceUsd: number | null
} {
  if (mintB58 === 'SOL') {
    const wsol = resolved?.[WSOL_MINT_STR]
    return {
      symbol: 'SOL',
      name: 'Solana',
      decimals: 9,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID_STR,
      logoUrl: solLogoUrl ?? wsol?.logoUrl ?? null,
      priceUsd: solPriceUsd ?? wsol?.priceUsd ?? null,
    }
  }
  const fromWallet = walletTokens?.find((t) => t.mint === mintB58)
  const fromRegistry = resolved?.[mintB58]
  if (fromWallet) {
    return {
      symbol: mintB58 === WSOL_MINT_STR ? 'SOL' : fromWallet.symbol,
      name: fromWallet.name,
      decimals: fromWallet.decimals,
      tokenProgram: fromWallet.tokenProgram,
      logoUrl: fromWallet.logoUrl ?? fromRegistry?.logoUrl ?? null,
      priceUsd: fromWallet.priceUsd ?? fromRegistry?.priceUsd ?? null,
    }
  }
  if (fromRegistry) {
    return {
      symbol: mintB58 === WSOL_MINT_STR ? 'SOL' : fromRegistry.symbol,
      name: fromRegistry.name,
      decimals: fromRegistry.decimals ?? (mintB58 === WSOL_MINT_STR ? 9 : 6),
      tokenProgram: fromRegistry.tokenProgram,
      logoUrl: fromRegistry.logoUrl,
      priceUsd: fromRegistry.priceUsd,
    }
  }
  return {
    symbol: mintB58 === WSOL_MINT_STR ? 'SOL' : shortAddr(mintB58, 4, 4),
    name: mintB58 === WSOL_MINT_STR ? 'Solana' : 'Solana Token',
    decimals: mintB58 === WSOL_MINT_STR ? 9 : 6,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID_STR,
    logoUrl: null,
    priceUsd: null,
  }
}

function formatUnits(raw: bigint, decimals: number, maxFrac = 4): string {
  const neg = raw < 0n
  const v = neg ? -raw : raw
  const base = 10n ** BigInt(decimals)
  const whole = v / base
  const frac = v % base
  if (frac === 0n) return `${neg ? '-' : ''}${whole.toLocaleString()}`
  const padded = frac.toString().padStart(decimals, '0')
  let fracStr = padded.slice(0, maxFrac).replace(/0+$/, '')
  if (whole === 0n && !fracStr) {
    const firstNonZero = padded.search(/[1-9]/)
    if (firstNonZero >= 0) {
      fracStr = padded.slice(0, Math.min(decimals, firstNonZero + 2)).replace(/0+$/, '')
    }
  }
  return fracStr
    ? `${neg ? '-' : ''}${whole.toLocaleString()}.${fracStr}`
    : `${neg ? '-' : ''}${whole.toLocaleString()}`
}

function parseDecimalToRaw(input: string, decimals: number): bigint | null {
  const clean = input.trim().replace(/,/g, '')
  if (!clean || !/^\d+(\.\d+)?$/.test(clean)) return null
  const [wholePart, fracPart = ''] = clean.split('.')
  const fracPadded = fracPart.slice(0, decimals).padEnd(decimals, '0')
  const raw = BigInt(wholePart) * 10n ** BigInt(decimals) + BigInt(fracPadded || '0')
  return raw > 0n ? raw : null
}

function solscanAccountUrl(addr: string, cluster: SolanaCluster): string {
  return cluster === 'mainnet'
    ? `https://solscan.io/account/${addr}`
    : `https://solscan.io/account/${addr}?cluster=devnet`
}

export function LiveWalletVault({
  onSwitchToFreeSandbox,
}: {
  onSwitchToFreeSandbox?: () => void
} = {}) {
  const [cluster, setCluster] = useState<SolanaCluster>('mainnet')
  const [wallets, setWallets] = useState<DiscoveredSolanaWallet[]>([])
  const [connected, setConnected] = useState<ConnectedSolanaWallet | null>(null)
  const [connectingName, setConnectingName] = useState<string | null>(null)
  const [reconnectingWallet, setReconnectingWallet] = useState<string | null>(null)
  const [audrenKeys, setAudrenKeys] = useState<AudrenKeypair | null>(null)
  const [unlocking, setUnlocking] = useState(false)

  const [balances, setBalances] = useState<WalletBalancesResponse | null>(null)
  const [pool, setPool] = useState<PoolResponse | null>(null)
  const [notes, setNotes] = useState<SpendableAudrenNote[]>([])
  const [nullifierStatus, setNullifierStatus] = useState<'idle' | 'verifying' | 'verified' | 'error'>('idle')
  const [scanProgress, setScanProgress] = useState<string | null>(null)
  const [loadingState, setLoadingState] = useState(false)
  const [strangerEyes, setStrangerEyes] = useState(false)
  const historicalPageCacheRef = useRef<Map<string, string>>(new Map())

  const [actionTab, setActionTab] = useState<VaultActionTab>('shield')
  const [feeMode, setFeeMode] = useState<FeeMode>('relayer')
  const [relayerUrl, setRelayerUrl] = useState<string>(DEFAULT_RELAY_URL)
  const [relayerUrlError, setRelayerUrlError] = useState<string | null>(null)
  const [priorityTier, setPriorityTier] = useState<PriorityTier>('standard')
  const [ringSize, setRingSize] = useState<32 | 64 | 128>(32)

  // Selective Disclosure Viewing Receipt state (for any note in Private Balance)
  const [openReceiptKey, setOpenReceiptKey] = useState<string | null>(null)
  const [receiptVerifyState, setReceiptVerifyState] = useState<
    Record<string, { mode: 'real' | 'forged'; valid: boolean; reason: string } | null>
  >({})
  const [verifyingReceiptKey, setVerifyingReceiptKey] = useState<string | null>(null)

  // Interrupted ProofBuffer recovery + Encrypted Backup + Birth-Page Fast-Sync
  const [abandonedBuffers, setAbandonedBuffers] = useState<
    Array<{ pda: string; lamports: number; label: string }>
  >([])
  const [showVaultTools, setShowVaultTools] = useState<boolean>(false)
  const [backupPassphrase, setBackupPassphrase] = useState<string>('')
  const [backupStatus, setBackupStatus] = useState<string | null>(null)
  const [birthPageIdState, setBirthPageIdState] = useState<bigint | null>(null)
  const vaultSeedRef = useRef<Uint8Array | null>(null)
  const forceFullRescanRef = useRef<boolean>(false)

  // Tab 1: Deposit into Private Balance (to self OR any aud1… recipient)
  const [shieldAssetKey, setShieldAssetKey] = useState<string>('SOL')
  const [shieldWrapSol, setShieldWrapSol] = useState<boolean>(true)
  const [shieldAmountStr, setShieldAmountStr] = useState<string>('0.01')
  const [shieldToSelf, setShieldToSelf] = useState<boolean>(true)
  const [shieldRecipient, setShieldRecipient] = useState<string>('')
  const [shieldMemo, setShieldMemo] = useState<string>('VAULT')
  const [depositPickerOpen, setDepositPickerOpen] = useState<boolean>(false)
  const [depositSearchQuery, setDepositSearchQuery] = useState<string>('')
  const [showAdvanced, setShowAdvanced] = useState<boolean>(false)
  const [showPublicDrawer, setShowPublicDrawer] = useState<boolean>(false)
  const [publicDrawerQuery, setPublicDrawerQuery] = useState<string>('')

  // Tab 2: Private Transfer
  const [selectedNoteIdx, setSelectedNoteIdx] = useState<number>(0)
  const [transferToSelf, setTransferToSelf] = useState<boolean>(true)
  const [transferRecipient, setTransferRecipient] = useState<string>('')
  const [transferAmountDraft, setTransferAmountDraft] = useState<string | null>(null)
  const [transferMemo, setTransferMemo] = useState<string>('PAY')

  // Live token metadata registry hydrated dynamically from token search API (zero hardcoded token list)
  const [resolvedTokens, setResolvedTokens] = useState<Record<string, SearchTokenCard>>({})

  // Tab 3: Private Jupiter Swap (partial or full note, live searchable output picker via /api/tokens/search)
  const [swapNoteIdx, setSwapNoteIdx] = useState<number>(0)
  const [swapAmountDraft, setSwapAmountDraft] = useState<string | null>(null)
  const [swapOutMintChoice, setSwapOutMintChoice] = useState<string>(USDC_MAINNET_MINT_STR)
  const [swapSearchQuery, setSwapSearchQuery] = useState<string>('')
  const [swapSearchResults, setSwapSearchResults] = useState<SearchTokenCard[]>([])
  const [searchingTokens, setSearchingTokens] = useState<boolean>(false)
  const [swapPickerOpen, setSwapPickerOpen] = useState<boolean>(false)
  const [swapSlippageBps, setSwapSlippageBps] = useState<number>(50)
  const [jupiterQuote, setJupiterQuote] = useState<JupiterQuoteResponse | null>(null)
  const [quotingSwap, setQuotingSwap] = useState<boolean>(false)
  const [swapQuoteError, setSwapQuoteError] = useState<string | null>(null)
  const swapQuoteSeqRef = useRef(0)

  // Tab 4: Withdraw
  const [withdrawNoteIdx, setWithdrawNoteIdx] = useState<number>(0)
  const [withdrawToSelf, setWithdrawToSelf] = useState<boolean>(true)
  const [withdrawDest, setWithdrawDest] = useState<string>('')
  const [withdrawAmountDraft, setWithdrawAmountDraft] = useState<string | null>(null)
  const [withdrawUnwrapWsol, setWithdrawUnwrapWsol] = useState<boolean>(true)
  const [useDefiSessionDest, setUseDefiSessionDest] = useState<boolean>(false)
  const [defiSessionIndex, setDefiSessionIndex] = useState<number>(0)
  const [defiSessionAddr, setDefiSessionAddr] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    const seed = vaultSeedRef.current
    if (!audrenKeys || !seed) {
      setDefiSessionAddr(null)
      return
    }
    void deriveDefiSessionKeypair(seed, defiSessionIndex)
      .then((kp) => {
        if (!cancelled) setDefiSessionAddr(kp.address)
      })
      .catch(() => {
        if (!cancelled) setDefiSessionAddr(null)
      })
    return () => {
      cancelled = true
    }
  }, [audrenKeys, defiSessionIndex])

  // Execution state
  const [busyLabel, setBusyLabel] = useState<string | null>(null)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)
  const [audits, setAudits] = useState<AuditRecord[]>([])
  const [openSdkSig, setOpenSdkSig] = useState<string | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)

  const refreshSeqRef = useRef(0)

  const switchCluster = useCallback((next: SolanaCluster) => {
    setCluster(next)
    saveCluster(next)
    setNotes([])
    setNullifierStatus('idle')
    setScanProgress(null)
    setErrorMsg(null)
  }, [])

  const actionPanelRef = useRef<HTMLDivElement | null>(null)
  const historyRef = useRef<HTMLDivElement | null>(null)
  const unlockRef = useRef<HTMLDivElement | null>(null)
  const autoReconnectedRef = useRef(false)

  const activeRelayerHost = useMemo(() => relayerHostLabel(relayerUrl), [relayerUrl])

  const pushAudit = (entry: AuditRecord) => {
    const walletToCheck = connected?.address ?? null
    setAudits((prev) => [{ ...entry, onChainProof: { loading: true } }, ...prev])
    window.setTimeout(() => {
      historyRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }, 120)

    // Empirically inspect the confirmed Solana transaction live so the user sees on-chain proof directly on screen
    void (async () => {
      try {
        const res = await fetch(
          `/api/tx/inspect?cluster=${entry.cluster}&signature=${encodeURIComponent(entry.signature)}`,
        )
        const json = (await res.json()) as {
          ok?: boolean
          version?: number | 'legacy'
          signers?: string[]
          accountKeys?: string[]
          computeUnitsConsumed?: number | null
          feeLamports?: number
          error?: string
        }
        if (!res.ok || !json.ok) {
          throw new Error(json.error ?? 'Could not inspect transaction')
        }
        const signers = json.signers ?? []
        const keys = json.accountKeys ?? []
        const proof: OnChainTxProof = {
          loading: false,
          txVersion: json.version === 1 ? 'v1' : json.version === 0 ? 'v0' : String(json.version ?? 'v1'),
          signers,
          walletPresent: walletToCheck ? keys.includes(walletToCheck) : false,
          walletIsSigner: walletToCheck ? signers.includes(walletToCheck) : false,
          totalAccounts: keys.length,
          computeUnits: json.computeUnitsConsumed ?? null,
          feeLamports: json.feeLamports ?? 0,
        }
        setAudits((prev) =>
          prev.map((a) => (a.signature === entry.signature ? { ...a, onChainProof: proof } : a)),
        )
      } catch (err) {
        setAudits((prev) =>
          prev.map((a) =>
            a.signature === entry.signature
              ? {
                  ...a,
                  onChainProof: {
                    loading: false,
                    error: err instanceof Error ? err.message : 'Inspection pending',
                  },
                }
              : a,
          ),
        )
      }
    })()
  }

  const copyText = (id: string, val: string) => {
    navigator.clipboard?.writeText(val).catch(() => {})
    setCopiedId(id)
    window.setTimeout(() => setCopiedId((prev) => (prev === id ? null : prev)), 1800)
  }

  // Restore saved cluster, custom relayer URL & silent wallet reconnect immediately on mount
  useEffect(() => {
    const savedCluster = loadSavedCluster()
    if (savedCluster) {
      window.setTimeout(() => setCluster(savedCluster), 0)
    }
    try {
      const savedRelay = window.localStorage.getItem(CUSTOM_RELAY_STORAGE_KEY)
      if (savedRelay) {
        const norm = normalizeRelayerUrl(savedRelay)
        if (norm.ok) {
          window.setTimeout(() => setRelayerUrl(norm.url), 0)
        }
      }
    } catch {
      // ignore storage errors
    }
    const lastWallet = loadLastWalletName()
    if (lastWallet) {
      const startId = window.setTimeout(() => setReconnectingWallet(lastWallet), 0)
      const timeoutId = window.setTimeout(() => setReconnectingWallet(null), 1300)
      return () => {
        window.clearTimeout(startId)
        window.clearTimeout(timeoutId)
      }
    }
    return undefined
  }, [])

  // Subscribe to Wallet Standard wallets (Phantom, Solflare, Backpack, etc.)
  useEffect(() => {
    return subscribeSolanaWallets(setWallets)
  }, [])

  // Silently reconnect last used wallet (e.g. Phantom) + restore session-unlocked Private View on page reload
  useEffect(() => {
    if (connected || wallets.length === 0) return
    const lastName = loadLastWalletName()
    if (!lastName) return
    const match = wallets.find((w) => w.name.toLowerCase() === lastName.toLowerCase())
    if (!match) return

    let cancelled = false
    const attach = async (conn: ConnectedSolanaWallet) => {
      if (cancelled) return
      autoReconnectedRef.current = true
      setConnected(conn)
      setReconnectingWallet(null)
      const cachedSeed = loadSessionVaultSeed(conn.address)
      if (cachedSeed) {
        vaultSeedRef.current = cachedSeed
        const keys = await generateAudrenKeys(cachedSeed)
        if (!cancelled) setAudrenKeys(keys)
      }
    }

    // Listen in case Phantom finishes waking up asynchronously right after reload
    const offEvents = subscribeWalletStandardAccounts(match, (conn) => {
      void attach(conn)
    })

    if (!autoReconnectedRef.current) {
      void (async () => {
        const delays = [0, 250, 750]
        for (const ms of delays) {
          if (ms > 0) await new Promise((r) => setTimeout(r, ms))
          if (cancelled || autoReconnectedRef.current) return
          try {
            const conn = await connectSolanaWallet(match, { silent: true })
            await attach(conn)
            return
          } catch {
            // Try next retry slot in case Chrome extension worker is still waking up
          }
        }
        if (!cancelled) setReconnectingWallet(null)
      })()
    }

    return () => {
      cancelled = true
      offEvents()
    }
  }, [wallets, connected])

  const refreshPoolAndVault = useCallback(
    async (
      targetCluster: SolanaCluster,
      walletAddr: string | null,
      keys: AudrenKeypair | null,
      overrideRelayUrl?: string,
    ) => {
      const targetRelayUrl = overrideRelayUrl ?? relayerUrl
      setLoadingState(true)
      try {
        const [poolRes, relayInfoRes, balRes] = await Promise.all([
          fetch(`/api/pool?cluster=${targetCluster}`),
          fetch(`${targetRelayUrl}/v1/info?cluster=${targetCluster}`).catch(() => null),
          walletAddr
            ? fetch(`/api/wallet/balances?cluster=${targetCluster}&address=${walletAddr}`)
            : Promise.resolve(null),
        ])

        const poolJson = (await poolRes.json()) as PoolResponse & { error?: string }
        if (!poolRes.ok) throw new Error(poolJson.error ?? 'Failed to load pool')

        // Source Privacy Relayer availability exclusively from active relayer URL (/v1/info)
        let relayOnline = false
        let relayPubkey: string | null = null
        if (relayInfoRes && relayInfoRes.ok) {
          try {
            const relayJson = (await relayInfoRes.json()) as {
              ok?: boolean
              configured?: boolean
              relayerPubkey?: string | null
              balanceSol?: number | null
            }
            if (
              relayJson.ok &&
              relayJson.configured &&
              relayJson.relayerPubkey &&
              (relayJson.balanceSol ?? 0) >= 0.005
            ) {
              relayOnline = true
              relayPubkey = relayJson.relayerPubkey
            }
          } catch {
            // relayer returned unreadable payload -> mark unavailable
          }
        }
        poolJson.relayerAvailable = relayOnline
        poolJson.relayerAddress = relayPubkey
        if (overrideRelayUrl) {
          setRelayerUrlError(
            relayOnline
              ? null
              : `Could not reach a funded Audren relayer on ${targetCluster} at ${targetRelayUrl}/v1/info.`,
          )
        }

        setPool(poolJson)
        // Auto-select Privacy Relayer when funded and available on active cluster (both Mainnet & Devnet)
        setFeeMode((prev) => {
          if (!poolJson.relayerAvailable && prev === 'relayer') {
            return 'self'
          }
          if (overrideRelayUrl && poolJson.relayerAvailable) {
            return 'relayer'
          }
          return prev
        })

        if (balRes) {
          const balJson = (await balRes.json()) as WalletBalancesResponse & { error?: string }
          if (balRes.ok) setBalances(balJson)
        } else {
          setBalances(null)
        }

        // Check any journaled self-pay ProofBuffers so interrupted uploads can reclaim 100% rent in 1 click
        if (walletAddr) {
          const pendingBufs = loadPendingProofBuffers(targetCluster, walletAddr)
          if (pendingBufs.length > 0) {
            void (async () => {
              try {
                const bufRes = await fetch('/api/buffers/check', {
                  method: 'POST',
                  headers: { 'content-type': 'application/json' },
                  body: JSON.stringify({
                    cluster: targetCluster,
                    pdas: pendingBufs.map((b) => b.bufferPdaB58),
                  }),
                })
                if (!bufRes.ok) return
                const bufJson = (await bufRes.json()) as {
                  buffers?: Array<{ pda: string; exists: boolean; lamports: number }>
                }
                const live: Array<{ pda: string; lamports: number; label: string }> = []
                for (const item of bufJson.buffers ?? []) {
                  const meta = pendingBufs.find((b) => b.bufferPdaB58 === item.pda)
                  if (item.exists) {
                    live.push({
                      pda: item.pda,
                      lamports: item.lamports,
                      label: meta?.label ?? 'Interrupted proof upload',
                    })
                  } else {
                    removePendingProofBuffer(targetCluster, walletAddr, item.pda)
                  }
                }
                setAbandonedBuffers(live)
              } catch {
                // Non-fatal
              }
            })()
          } else {
            setAbandonedBuffers([])
          }
        } else {
          setAbandonedBuffers([])
        }

        if (keys && poolJson.pages.length > 0) {
          const seq = ++refreshSeqRef.current
          const knownDyn = loadKnownDynamicAmounts()
          const currentPageId = BigInt(poolJson.currentPageId)
          const isFullRescan = forceFullRescanRef.current
          forceFullRescanRef.current = false
          const rawInv = isFullRescan
            ? null
            : await loadEncryptedVaultInventory(keys, targetCluster, 0)
          if (seq !== refreshSeqRef.current) return
          const emptyInv: VaultInventorySnapshot = {
            version: 1,
            birthPageId: null,
            lastSealedPageId: null,
            lastOpenPageId: null,
            lastOpenPageCount: 0,
            laneSealedThrough: {},
            lastVerifiedAtMs: null,
            notes: [],
            verifiedDynamicAmounts: {},
          }
          // Guard against Devnet pool resets where cached checkpoint exceeds live pool head
          const inv: VaultInventorySnapshot =
            rawInv &&
            !(rawInv.lastSealedPageId !== null && rawInv.lastSealedPageId > currentPageId) &&
            !(rawInv.lastOpenPageId !== null && rawInv.lastOpenPageId > currentPageId)
              ? rawInv
              : emptyInv

          const effectiveBirthPageId =
            inv.birthPageId !== undefined && inv.birthPageId !== null && inv.birthPageId <= currentPageId
              ? inv.birthPageId
              : null
          setBirthPageIdState(effectiveBirthPageId)

          const verifiedDynMap: Record<string, bigint> = {
            ...knownDyn,
            ...inv.verifiedDynamicAmounts,
          }

          const noteMap = new Map<string, SpendableAudrenNote>()
          for (const n of inv.notes) {
            noteMap.set(`${n.pageId.toString()}:${n.slotIndex}`, n)
          }

          // Cache latest 16 full pages from `/api/pool` for instant ring building
          const recentById = new Map<bigint, PoolPageSummary>()
          let oldestRecentPageId = currentPageId
          for (const pg of poolJson.pages) {
            const pid = BigInt(pg.pageId)
            recentById.set(pid, pg)
            historicalPageCacheRef.current.set(`${targetCluster}:${pg.pageId}`, pg.pageBase64)
            if (pid < oldestRecentPageId) oldestRecentPageId = pid
          }

          // Stage 1 + Stage 2 full-history recovery across ALL pages on Lane 0 (`birth..=currentPageId`)
          // using immutable edge CDN caching (`&sealed=1`) for strictly sealed pages!
          const lane0Floor = effectiveBirthPageId ?? 0n
          const startHistorical =
            inv.lastSealedPageId === null
              ? lane0Floor
              : inv.lastSealedPageId + 1n > lane0Floor
                ? inv.lastSealedPageId + 1n
                : lane0Floor
          let allHistoricalOk = true

          if (startHistorical < oldestRecentPageId) {
            const hitPageIds: bigint[] = []
            const SLICE_BATCH = 100n
            for (let from = startHistorical; from < oldestRecentPageId; from += SLICE_BATCH) {
              const to =
                from + SLICE_BATCH - 1n < oldestRecentPageId - 1n
                  ? from + SLICE_BATCH - 1n
                  : oldestRecentPageId - 1n
              setScanProgress(
                `Scanning pages ${from.toString()}–${to.toString()} of ${currentPageId.toString()}…`,
              )
              const sealedFlag = to < currentPageId ? '&sealed=1' : ''
              const sliceRes = await fetch(
                `/api/pages/slices?cluster=${targetCluster}&lane=0&from=${from.toString()}&to=${to.toString()}${sealedFlag}`,
              )
              if (!sliceRes.ok) {
                allHistoricalOk = false
                break
              }
              const sliceJson = (await sliceRes.json()) as {
                slices?: Array<{ pageId: string; sliceBase64: string } | null>
              }
              if (seq !== refreshSeqRef.current) return
              for (const s of sliceJson.slices ?? []) {
                if (!s) continue
                const hits = await scanPageScanSlice(keys, fromBase64(s.sliceBase64))
                if (hits.length > 0) hitPageIds.push(BigInt(s.pageId))
              }
            }

            if (allHistoricalOk && hitPageIds.length > 0) {
              const FETCH_BATCH = 16
              for (let i = 0; i < hitPageIds.length; i += FETCH_BATCH) {
                const batchIds = hitPageIds.slice(i, i + FETCH_BATCH).map((id) => id.toString())
                setScanProgress(
                  `Decrypting ${Math.min(i + FETCH_BATCH, hitPageIds.length)} / ${hitPageIds.length} matching historical pages…`,
                )
                // Prefer CDN-cached sealed endpoint for pages strictly older than active tip
                const pgRes = await fetch(
                  `/api/pages/sealed?cluster=${targetCluster}&ids=${batchIds.join(',')}`,
                )
                if (!pgRes.ok) {
                  allHistoricalOk = false
                  break
                }
                const pgJson = (await pgRes.json()) as {
                  pages?: Array<{ pageId: string; pageBase64: string }>
                }
                if (seq !== refreshSeqRef.current) return
                for (const pg of pgJson.pages ?? []) {
                  historicalPageCacheRef.current.set(`${targetCluster}:${pg.pageId}`, pg.pageBase64)
                  const found = await scanEpochPageSpendable(
                    keys,
                    fromBase64(pg.pageBase64),
                    0,
                    verifiedDynMap,
                  )
                  for (const n of found) {
                    noteMap.set(`${n.pageId.toString()}:${n.slotIndex}`, n)
                  }
                }
              }
            }
          }

          // Scan recent Lane 0 pages from `/api/pool`
          const sortedRecent = [...poolJson.pages].sort((a, b) =>
            BigInt(a.pageId) < BigInt(b.pageId) ? -1 : 1,
          )
          for (const pg of sortedRecent) {
            const pid = BigInt(pg.pageId)
            const alreadyScannedClosed =
              inv.lastSealedPageId !== null && pid <= inv.lastSealedPageId
            const unchangedOpen =
              pid === currentPageId &&
              inv.lastOpenPageId === currentPageId &&
              inv.lastOpenPageCount === pg.count &&
              !pg.closed
            if (alreadyScannedClosed || unchangedOpen) continue
            const found = await scanEpochPageSpendable(
              keys,
              fromBase64(pg.pageBase64),
              0,
              verifiedDynMap,
            )
            for (const n of found) {
              noteMap.set(`${n.pageId.toString()}:${n.slotIndex}`, n)
            }
          }

          // Multi-lane discovery: scan any active parallel append lanes (1..15) incrementally!
          const nextLaneSealed: Record<number, bigint> = { ...(inv.laneSealedThrough ?? {}) }
          for (const laneInfo of poolJson.lanes ?? []) {
            if (laneInfo.laneId === 0) continue
            const tipPageId = BigInt(laneInfo.activePageId)
            const tipSeq = seqOfPageId(tipPageId)
            const prevSealedSeq = nextLaneSealed[laneInfo.laneId]
            const startSeq = prevSealedSeq !== undefined ? prevSealedSeq + 1n : 0n
            const laneHits: bigint[] = []
            let laneOk = true
            for (let fromSeq = startSeq; fromSeq <= tipSeq; fromSeq += 100n) {
              const toSeq = fromSeq + 99n < tipSeq ? fromSeq + 99n : tipSeq
              const sealedFlag = toSeq < tipSeq ? '&sealed=1' : ''
              setScanProgress(
                `Scanning Lane ${laneInfo.laneId} pages ${fromSeq.toString()}–${toSeq.toString()}…`,
              )
              const sRes = await fetch(
                `/api/pages/slices?cluster=${targetCluster}&lane=${laneInfo.laneId}&from=${fromSeq.toString()}&to=${toSeq.toString()}${sealedFlag}`,
              )
              if (!sRes.ok) {
                laneOk = false
                break
              }
              const sJson = (await sRes.json()) as {
                slices?: Array<{ pageId: string; sliceBase64: string } | null>
              }
              if (seq !== refreshSeqRef.current) return
              for (const s of sJson.slices ?? []) {
                if (!s) continue
                const hits = await scanPageScanSlice(keys, fromBase64(s.sliceBase64))
                if (hits.length > 0) laneHits.push(BigInt(s.pageId))
              }
            }
            if (laneOk && laneHits.length > 0) {
              for (let i = 0; i < laneHits.length; i += 32) {
                const batchIds = laneHits.slice(i, i + 32).map((id) => id.toString())
                const pgRes = await fetch('/api/pages/fetch', {
                  method: 'POST',
                  headers: { 'content-type': 'application/json' },
                  body: JSON.stringify({ cluster: targetCluster, poolId: 0, pageIds: batchIds }),
                })
                if (!pgRes.ok) {
                  laneOk = false
                  break
                }
                const pgJson = (await pgRes.json()) as {
                  pages?: Array<{ pageId: string; pageBase64: string }>
                }
                if (seq !== refreshSeqRef.current) return
                for (const pg of pgJson.pages ?? []) {
                  historicalPageCacheRef.current.set(`${targetCluster}:${pg.pageId}`, pg.pageBase64)
                  const found = await scanEpochPageSpendable(
                    keys,
                    fromBase64(pg.pageBase64),
                    0,
                    verifiedDynMap,
                  )
                  for (const n of found) {
                    noteMap.set(`${n.pageId.toString()}:${n.slotIndex}`, n)
                  }
                }
              }
            }
            if (laneOk) {
              if (laneInfo.pageClosed) {
                nextLaneSealed[laneInfo.laneId] = tipSeq
              } else if (tipSeq > 0n) {
                nextLaneSealed[laneInfo.laneId] = tipSeq - 1n
              }
            }
          }
          setScanProgress(null)

          // Verify any dynamic-amount swap notes cryptographically against on-chain Pedersen commitment V == amount * A
          const candidates = Array.from(noteMap.values())
          for (const n of candidates) {
            if (!n.isDynamicOutput) continue
            const stealthB58 = base58Encode(n.stealthPk)
            if (n.amountResolved && n.amount > 0n) {
              // Ensure cached/localStorage amount actually verifies cryptographically!
              if (!verifyDynamicAmountForNote(n, n.amount)) {
                n.amount = 0n
                n.amountResolved = false
              } else {
                verifiedDynMap[stealthB58] = n.amount
              }
            }
            if (!n.amountResolved) {
              const fromLocal = verifiedDynMap[stealthB58]
              if (fromLocal !== undefined && verifyDynamicAmountForNote(n, fromLocal)) {
                n.amount = fromLocal
                n.amountResolved = true
                continue
              }
              try {
                const dynRes = await fetch('/api/notes/resolve-dynamic', {
                  method: 'POST',
                  headers: { 'content-type': 'application/json' },
                  body: JSON.stringify({
                    cluster: targetCluster,
                    poolId: 0,
                    pageId: n.pageId.toString(),
                    slotIndex: n.slotIndex,
                    mint: n.mintB58,
                  }),
                })
                if (dynRes.ok) {
                  const dynJson = (await dynRes.json()) as { candidateAmounts?: string[] }
                  for (const candStr of dynJson.candidateAmounts ?? []) {
                    try {
                      const cand = BigInt(candStr)
                      if (verifyDynamicAmountForNote(n, cand)) {
                        n.amount = cand
                        n.amountResolved = true
                        verifiedDynMap[stealthB58] = cand
                        saveKnownDynamicAmount(stealthB58, cand)
                        break
                      }
                    } catch {
                      // ignore malformed candidate
                    }
                  }
                }
              } catch {
                // non-fatal; note remains flagged as verifying fill and excluded from spendable balance
              }
            }
          }
          if (seq !== refreshSeqRef.current) return

          // Fail-closed, padded & shuffled batched nullifier verification:
          // Pad to multiples of 16 with random 32-byte decoy PDAs and Fisher-Yates shuffle
          // so the Worker/RPC never observes exact wallet note counts or ordering!
          if (candidates.length > 0) {
            setNullifierStatus('verifying')
            const spentFlags: boolean[] = new Array<boolean>(candidates.length).fill(false)
            const NULLIFIER_BATCH = 480
            let nullifierFailed = false
            try {
              for (let i = 0; i < candidates.length; i += NULLIFIER_BATCH) {
                const batch = candidates.slice(i, i + NULLIFIER_BATCH)
                const paddedLen = Math.ceil(batch.length / 16) * 16
                const queryItems: Array<{ pda: string; realIdx: number | null }> = batch.map(
                  (n, bi) => ({ pda: n.nullifierPdaB58, realIdx: i + bi }),
                )
                while (queryItems.length < paddedLen) {
                  const decoy = crypto.getRandomValues(new Uint8Array(32))
                  queryItems.push({ pda: base58Encode(decoy), realIdx: null })
                }
                // Fisher-Yates shuffle
                const rand = crypto.getRandomValues(new Uint32Array(queryItems.length))
                for (let k = queryItems.length - 1; k > 0; k--) {
                  const j = rand[k] % (k + 1)
                  const tmp = queryItems[k]
                  queryItems[k] = queryItems[j]
                  queryItems[j] = tmp
                }

                const nullRes = await fetch('/api/nullifiers', {
                  method: 'POST',
                  headers: { 'content-type': 'application/json' },
                  body: JSON.stringify({
                    cluster: targetCluster,
                    pdas: queryItems.map((q) => q.pda),
                  }),
                })
                if (!nullRes.ok) {
                  nullifierFailed = true
                  break
                }
                const nullJson = (await nullRes.json()) as { spent?: boolean[] }
                if (!Array.isArray(nullJson.spent) || nullJson.spent.length !== queryItems.length) {
                  nullifierFailed = true
                  break
                }
                for (let k = 0; k < queryItems.length; k++) {
                  const ri = queryItems[k].realIdx
                  if (ri !== null) spentFlags[ri] = nullJson.spent[k]
                }
              }
            } catch {
              nullifierFailed = true
            }
            if (seq !== refreshSeqRef.current) return

            if (nullifierFailed) {
              // Fail closed: keep last verified UI balance, block spending until re-verified
              setNullifierStatus('error')
              setErrorMsg(
                'Could not verify spent status for all private notes right now. Click Refresh before spending.',
              )
            } else {
              const unspent = candidates
                .filter((_, idx) => !spentFlags[idx])
                .sort((a, b) =>
                  a.pageId !== b.pageId
                    ? a.pageId > b.pageId
                      ? -1
                      : 1
                    : b.slotIndex - a.slotIndex,
                )
              setNotes(unspent)
              setNullifierStatus('verified')

              const curPageSummary = recentById.get(currentPageId)
              const nextSealed = allHistoricalOk
                ? curPageSummary?.closed
                  ? currentPageId
                  : currentPageId > 0n
                    ? currentPageId - 1n
                    : null
                : inv.lastSealedPageId
              await saveEncryptedVaultInventory(keys, targetCluster, 0, {
                version: 1,
                birthPageId: effectiveBirthPageId,
                lastSealedPageId: nextSealed,
                lastOpenPageId: currentPageId,
                lastOpenPageCount: curPageSummary?.count ?? 0,
                laneSealedThrough: nextLaneSealed,
                lastVerifiedAtMs: Date.now(),
                notes: unspent,
                verifiedDynamicAmounts: verifiedDynMap,
              })
            }
          } else {
            setNotes([])
            setNullifierStatus('verified')
            const curPageSummary = recentById.get(currentPageId)
            const nextSealed = allHistoricalOk
              ? curPageSummary?.closed
                ? currentPageId
                : currentPageId > 0n
                  ? currentPageId - 1n
                  : null
              : inv.lastSealedPageId
            await saveEncryptedVaultInventory(keys, targetCluster, 0, {
              version: 1,
              birthPageId: effectiveBirthPageId,
              lastSealedPageId: nextSealed,
              lastOpenPageId: currentPageId,
              lastOpenPageCount: curPageSummary?.count ?? 0,
              laneSealedThrough: nextLaneSealed,
              lastVerifiedAtMs: Date.now(),
              notes: [],
              verifiedDynamicAmounts: verifiedDynMap,
            })
          }
        } else {
          setNotes([])
          setNullifierStatus('idle')
          setScanProgress(null)
        }
      } catch (err) {
        setErrorMsg(err instanceof Error ? err.message : 'Failed to refresh on-chain state')
      } finally {
        setLoadingState(false)
      }
    },
    [relayerUrl],
  )

  const handleApplyRelayerUrl = useCallback(
    async (rawInput: string) => {
      const norm = normalizeRelayerUrl(rawInput)
      if (!norm.ok) {
        setRelayerUrlError(norm.error)
        return
      }
      setRelayerUrlError(null)
      setRelayerUrl(norm.url)
      try {
        if (norm.url === DEFAULT_RELAY_URL) {
          window.localStorage.removeItem(CUSTOM_RELAY_STORAGE_KEY)
        } else {
          window.localStorage.setItem(CUSTOM_RELAY_STORAGE_KEY, norm.url)
        }
      } catch {
        // ignore storage errors
      }
      await refreshPoolAndVault(cluster, connected?.address ?? null, audrenKeys, norm.url)
    },
    [cluster, connected?.address, audrenKeys, refreshPoolAndVault],
  )

  const buildReceiptForNote = useCallback(
    (note: SpendableAudrenNote): SelectiveDisclosureReceipt => {
      const meta = tokenMeta(
        note.mintB58,
        balances?.tokens,
        resolvedTokens,
        balances?.solLogoUrl,
        balances?.solPriceUsd,
      )
      return buildSelectiveDisclosureReceipt(
        {
          pageId: note.pageId,
          slotIndex: note.slotIndex,
          mint: note.mint,
          amountLamports: note.amount,
          memoText: note.memoText,
          stealthPk: note.stealthPk,
          assetTag: note.assetTag,
          commitment: note.commitment,
          commitmentVerified: true,
          assetBlinding: note.assetBlinding,
          valueBlinding: note.valueBlinding,
        },
        `page-${note.pageId.toString()}-slot-${note.slotIndex}`,
        {
          cluster,
          assetSymbol: meta.symbol,
          decimals: meta.decimals,
        },
      )
    },
    [balances?.solLogoUrl, balances?.solPriceUsd, balances?.tokens, cluster, resolvedTokens],
  )

  const handleVerifyNoteReceipt = useCallback(
    async (note: SpendableAudrenNote, mode: 'real' | 'forged') => {
      const noteKey = `${note.pageId.toString()}:${note.slotIndex}`
      setVerifyingReceiptKey(noteKey)
      try {
        const receipt = buildReceiptForNote(note)
        const testReceipt: SelectiveDisclosureReceipt =
          mode === 'forged'
            ? {
                ...receipt,
                amountLamports: (BigInt(receipt.amountLamports) + 1n).toString(),
              }
            : receipt

        const cacheKey = `${cluster}:${note.pageId.toString()}`
        let pageB64 = historicalPageCacheRef.current.get(cacheKey)
        if (!pageB64) {
          const res = await fetch('/api/pages/fetch', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ cluster, pageIds: [note.pageId.toString()] }),
          })
          const json = (await res.json()) as {
            pages?: Array<{ pageId: string; pageBase64: string }>
          }
          pageB64 = json.pages?.[0]?.pageBase64
          if (pageB64) historicalPageCacheRef.current.set(cacheKey, pageB64)
        }
        if (!pageB64) {
          throw new Error(`Could not load EpochPage #${note.pageId.toString()} from Solana`)
        }
        const check = await verifySelectiveDisclosureOnPage(testReceipt, fromBase64(pageB64))
        setReceiptVerifyState((prev) => ({
          ...prev,
          [noteKey]: { mode, valid: check.valid, reason: check.reason },
        }))
      } catch (err) {
        setReceiptVerifyState((prev) => ({
          ...prev,
          [noteKey]: {
            mode,
            valid: false,
            reason: err instanceof Error ? err.message : 'Verification failed',
          },
        }))
      } finally {
        setVerifyingReceiptKey(null)
      }
    },
    [buildReceiptForNote, cluster],
  )

  useEffect(() => {
    const id = window.setTimeout(() => {
      void refreshPoolAndVault(cluster, connected?.address ?? null, audrenKeys)
    }, 0)
    return () => window.clearTimeout(id)
  }, [cluster, connected?.address, audrenKeys, refreshPoolAndVault])

  const handleConnect = async (w: DiscoveredSolanaWallet) => {
    setErrorMsg(null)
    setConnectingName(w.name)
    try {
      const conn = await connectSolanaWallet(w)
      autoReconnectedRef.current = true
      setReconnectingWallet(null)
      setConnected(conn)
      saveLastWalletName(w.name)
      const cachedSeed = loadSessionVaultSeed(conn.address)
      if (cachedSeed) {
        vaultSeedRef.current = cachedSeed
        const keys = await generateAudrenKeys(cachedSeed)
        setAudrenKeys(keys)
      } else {
        vaultSeedRef.current = null
        setAudrenKeys(null)
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : `Could not connect ${w.name}`)
    } finally {
      setConnectingName(null)
    }
  }

  const handleDisconnect = async () => {
    const prevAddr = connected?.address
    if (connected) await disconnectSolanaWallet(connected)
    clearSessionVault(prevAddr)
    vaultSeedRef.current = null
    autoReconnectedRef.current = false
    setReconnectingWallet(null)
    setConnected(null)
    setAudrenKeys(null)
    setBalances(null)
    setNotes([])
    setAbandonedBuffers([])
    setNullifierStatus('idle')
    setScanProgress(null)
    setErrorMsg(null)
  }

  const handleUnlockVault = async () => {
    if (!connected) return
    setErrorMsg(null)
    setUnlocking(true)
    try {
      const msg = buildWalletUnlockMessage(connected.address, 0)
      const sig = await signUtf8MessageWithWallet(connected, msg)
      const seed = await deriveSeedFromWalletSignature(connected.address, sig)
      vaultSeedRef.current = seed
      saveSessionVaultSeed(connected.address, seed)
      const keys = await generateAudrenKeys(seed)
      setAudrenKeys(keys)
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Unlock signature was cancelled')
    } finally {
      setUnlocking(false)
    }
  }

  const handleExportVaultBackup = async () => {
    if (!audrenKeys) return
    setBackupStatus(null)
    const seed = vaultSeedRef.current ?? (connected ? loadSessionVaultSeed(connected.address) : null)
    if (!seed) {
      setBackupStatus('Lock and re-unlock your Private Balance once to export an encrypted backup.')
      return
    }
    if (backupPassphrase.length < 8) {
      setBackupStatus('Enter a passphrase of at least 8 characters to encrypt your backup.')
      return
    }
    try {
      const inv = await loadEncryptedVaultInventory(audrenKeys, cluster, 0)
      const backup = await exportEncryptedVaultBackup({
        seed,
        audrenAddress: audrenKeys.address,
        cluster,
        passphrase: backupPassphrase,
        birthPageId: inv?.birthPageId ?? (pool ? BigInt(pool.currentPageId) : null),
        verifiedDynamicAmounts: {
          ...loadKnownDynamicAmounts(),
          ...(inv?.verifiedDynamicAmounts ?? {}),
        },
      })
      const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `audren-vault-backup-${cluster}-${new Date().toISOString().slice(0, 10)}.json`
      a.click()
      URL.revokeObjectURL(url)
      setBackupPassphrase('')
      setBackupStatus('Encrypted PBKDF2-SHA256 + AES-256-GCM backup downloaded.')
    } catch (err) {
      setBackupStatus(err instanceof Error ? err.message : 'Failed to export backup')
    }
  }

  const handleImportVaultBackup = async (file: File) => {
    setBackupStatus(null)
    setErrorMsg(null)
    if (backupPassphrase.length < 1) {
      setBackupStatus('Enter the backup passphrase first, then pick your .json backup file.')
      return
    }
    try {
      const text = await file.text()
      const parsed = JSON.parse(text) as AudrenEncryptedBackupFile
      const restored = await importEncryptedVaultBackup(parsed, backupPassphrase)
      vaultSeedRef.current = restored.seed
      if (connected) saveSessionVaultSeed(connected.address, restored.seed)
      const keys = await generateAudrenKeys(restored.seed)
      for (const [k, v] of Object.entries(restored.verifiedDynamicAmounts)) {
        saveKnownDynamicAmount(k, v)
      }
      // Seed encrypted local inventory with restored birthPageId & dynamic settlements
      await saveEncryptedVaultInventory(keys, restored.cluster, 0, {
        version: 1,
        birthPageId: restored.birthPageId,
        lastSealedPageId: null,
        lastOpenPageId: null,
        lastOpenPageCount: 0,
        laneSealedThrough: {},
        lastVerifiedAtMs: null,
        notes: [],
        verifiedDynamicAmounts: restored.verifiedDynamicAmounts,
      })
      setAudrenKeys(keys)
      setBackupPassphrase('')
      setBackupStatus(
        `Vault restored${restored.birthPageId !== null ? ` (fast-sync from page #${restored.birthPageId.toString()})` : ''}. Scanning balances…`,
      )
      if (restored.cluster !== cluster) {
        switchCluster(restored.cluster)
      } else {
        await refreshPoolAndVault(cluster, connected?.address ?? null, keys)
      }
    } catch (err) {
      setBackupStatus(err instanceof Error ? err.message : 'Failed to decrypt backup file')
    }
  }

  const handleFullRescanFromZero = async () => {
    if (!audrenKeys) return
    clearEncryptedVaultInventory(audrenKeys.spendPk, cluster, 0)
    forceFullRescanRef.current = true
    setBirthPageIdState(null)
    setBackupStatus('Cleared local checkpoint — rescanning all pages from Page 0…')
    await refreshPoolAndVault(cluster, connected?.address ?? null, audrenKeys)
    setBackupStatus('Full rescan from Page 0 complete.')
  }

  const handleReclaimAbandonedBuffers = async () => {
    if (!connected || abandonedBuffers.length === 0) return
    setErrorMsg(null)
    setBusyLabel(`Reclaiming rent from ${abandonedBuffers.length} ProofBuffer account(s)…`)
    try {
      const closeIxs = abandonedBuffers.map((b) =>
        buildCloseProofBufferInstruction({
          payer: connected.pubkeyBytes,
          proofBufferPda: base58Decode(b.pda),
        }),
      )
      const { blockhash, lastValidBlockHeight } = await fetchFreshBlockhash(cluster)
      const tier = PRIORITY_TIERS[priorityTier]
      const unsigned = compileKitV0Transaction({
        feePayer: connected.address,
        recentBlockhash: blockhash,
        lastValidBlockHeight,
        instructions: closeIxs,
        computeUnitLimit: 120_000,
        priorityMicroLamportsPerCu: tier.microLamportsPerCu,
      })
      setBusyLabel(`Approve rent reclaim in ${connected.name}…`)
      const [signed] = await signCompiledTransactionsWithWallet(connected, cluster, [unsigned])
      setBusyLabel(`Confirming rent refund on Solana…`)
      const [sent] = await sendAndConfirmSignedTransactions(cluster, [signed])
      const totalReclaimedLamports = abandonedBuffers.reduce((acc, b) => acc + b.lamports, 0)
      for (const b of abandonedBuffers) {
        removePendingProofBuffer(cluster, connected.address, b.pda)
      }
      setAbandonedBuffers([])
      pushAudit({
        action: 'Reclaim Buffer Rent',
        cluster,
        signature: sent.signature,
        slot: sent.slot,
        solscanUrl:
          cluster === 'mainnet'
            ? `https://solscan.io/tx/${sent.signature}`
            : `https://solscan.io/tx/${sent.signature}?cluster=devnet`,
        explorerUrl:
          cluster === 'mainnet'
            ? `https://explorer.solana.com/tx/${sent.signature}`
            : `https://explorer.solana.com/tx/${sent.signature}?cluster=devnet`,
        txFormat: `1 transaction · Direct wallet`,
        feePayerMode: 'self',
        feePayerAddress: connected.address,
        priorityLabel: `${tier.label} (${tier.desc})`,
        proverMs: 0,
        summary: `Reclaimed ${(totalReclaimedLamports / 1e9).toFixed(4)} SOL from ${closeIxs.length} interrupted buffer(s)`,
        publicSaw: `Closed temporary ProofBuffer PDA(s) and refunded 100% of rent back to ${shortAddr(connected.address)}.`,
        stayedPrivate: `Your private vault balances and notes remained untouched.`,
        sdkCode: `const closeIx = buildCloseProofBufferInstruction({ payer, proofBufferPda })`,
      })
      await refreshPoolAndVault(cluster, connected.address, audrenKeys)
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to reclaim ProofBuffer rent')
    } finally {
      setBusyLabel(null)
    }
  }

  // Build available assets for Deposit from the user's ACTUAL wallet balances (with live logos & USD values)
  const shieldOptions = useMemo(() => {
    const solUi = balances?.solUi ?? 0
    const wrapActive = cluster === 'mainnet' && shieldWrapSol
    const list: Array<{
      key: string
      label: string
      symbol: string
      name: string
      logoUrl: string | null
      usdValue: number | null
      mintB58: string
      decimals: number
      balanceUi: number
      rawBalance: bigint
      tokenProgram: string
      wrapFromSol: boolean
      isSol: boolean
      hint: string
      hasActiveTransferFee: boolean
      transferFeeBps: number
      transferFeeMax: string
      hasActiveTransferHook: boolean
      isNonTransferable: boolean
    }> = [
      {
        key: 'SOL',
        label: 'SOL (Solana)',
        symbol: 'SOL',
        name: 'Solana',
        logoUrl: balances?.solLogoUrl ?? null,
        usdValue: balances?.solUsdValue ?? null,
        mintB58: wrapActive ? WSOL_MINT_STR : 'SOL',
        decimals: 9,
        balanceUi: solUi,
        rawBalance: BigInt(balances?.solLamports ?? '0'),
        tokenProgram: CLASSIC_TOKEN_PROGRAM_ID_STR,
        wrapFromSol: wrapActive,
        isSol: true,
        hint: wrapActive
          ? 'Ready to send privately or swap via DEX aggregators immediately.'
          : 'Direct private SOL — instant private transfers & withdrawals.',
        hasActiveTransferFee: false,
        transferFeeBps: 0,
        transferFeeMax: '0',
        hasActiveTransferHook: false,
        isNonTransferable: false,
      },
    ]

    for (const tok of balances?.tokens ?? []) {
      const hasFee = Boolean(tok.hasActiveTransferFee && (tok.transferFeeBps ?? 0) > 0)
      const feePct = ((tok.transferFeeBps ?? 0) / 100).toFixed(2).replace(/\.?0+$/, '')
      list.push({
        key: tok.mint,
        label: `${tok.symbol}${tok.name && tok.name !== 'SPL Token' ? ` (${tok.name})` : ''}`,
        symbol: tok.symbol,
        name: tok.name,
        logoUrl: tok.logoUrl,
        usdValue: tok.usdValue,
        mintB58: tok.mint,
        decimals: tok.decimals,
        balanceUi: tok.uiAmount,
        rawBalance: BigInt(tok.amountRaw),
        tokenProgram: tok.tokenProgram,
        wrapFromSol: false,
        isSol: false,
        hint: tok.isNonTransferable
          ? 'Soulbound (non-transferable Token-2022) — cannot enter a shared vault.'
          : tok.hasActiveTransferHook
            ? 'Has an active Token-2022 Transfer Hook — unsupported for private deposits yet.'
            : hasFee
              ? `Token-2022 transfer fee (${feePct}%) — Audren automatically commits the exact net vault amount.`
              : 'Works for private transfers, DEX swaps, and withdrawals anytime.',
        hasActiveTransferFee: hasFee,
        transferFeeBps: tok.transferFeeBps ?? 0,
        transferFeeMax: tok.transferFeeMax ?? '0',
        hasActiveTransferHook: Boolean(tok.hasActiveTransferHook),
        isNonTransferable: Boolean(tok.isNonTransferable),
      })
    }
    return list
  }, [balances, cluster, shieldWrapSol])

  const filteredShieldOptions = useMemo(() => {
    const q = depositSearchQuery.trim().toLowerCase()
    if (!q) return shieldOptions
    return shieldOptions.filter(
      (o) =>
        o.symbol.toLowerCase().includes(q) ||
        o.name.toLowerCase().includes(q) ||
        o.mintB58.toLowerCase().includes(q),
    )
  }, [shieldOptions, depositSearchQuery])

  const filteredPublicDrawerOptions = useMemo(() => {
    const q = publicDrawerQuery.trim().toLowerCase()
    if (!q) return shieldOptions
    return shieldOptions.filter(
      (o) =>
        o.symbol.toLowerCase().includes(q) ||
        o.name.toLowerCase().includes(q) ||
        o.mintB58.toLowerCase().includes(q),
    )
  }, [shieldOptions, publicDrawerQuery])

  const selectedShieldOption =
    shieldOptions.find((o) => o.key === shieldAssetKey) ?? shieldOptions[0]

  const scrollToActionPanel = () => {
    window.setTimeout(() => {
      actionPanelRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
    }, 60)
  }

  const pickStarterAmount = (symbol: string, balanceUi: number, decimals: number): string => {
    if (balanceUi <= 0) return symbol === 'SOL' ? '0.01' : '1'
    if (symbol === 'SOL') {
      const safe = Math.max(0, balanceUi - 0.005)
      if (safe >= 0.01) return '0.01'
      if (safe >= 0.002) return '0.002'
      return Math.max(0.001, Number((safe * 0.5).toFixed(4))).toString()
    }
    if (['USDC', 'USDT', 'PYUSD', 'USDS', 'USDG', 'EURC', 'USDC (Dev)'].includes(symbol)) {
      if (balanceUi >= 1) return '1'
      return Number((balanceUi * 0.5).toFixed(Math.min(decimals, 4))).toString()
    }
    const quarter = balanceUi * 0.25
    const digits = quarter >= 100 ? 0 : quarter >= 1 ? 2 : Math.min(decimals, 4)
    return Number(quarter.toFixed(digits)).toString()
  }

  const startShieldToken = (
    key: string,
    symbol: string,
    balanceUi: number,
    decimals: number,
    forceJupiterReady?: boolean,
  ) => {
    setErrorMsg(null)
    if (!audrenKeys) {
      setErrorMsg('Click "Unlock Private View" above first (one free signature) so your private balance can receive it.')
      unlockRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' })
      return
    }
    setShieldAssetKey(key)
    if (key === 'SOL' && forceJupiterReady !== undefined) {
      setShieldWrapSol(forceJupiterReady)
    }
    setShieldAmountStr(pickStarterAmount(symbol, balanceUi, decimals))
    setActionTab('shield')
    scrollToActionPanel()
  }

  // Spendable notes strictly exclude unresolved dynamic swap notes so zero-amount placeholders can never be spent or inflate totals
  const spendableNotes = useMemo(
    () => notes.filter((n) => n.amountResolved && n.amount > 0n),
    [notes],
  )
  const unresolvedNotes = useMemo(
    () => notes.filter((n) => !n.amountResolved || n.amount <= 0n),
    [notes],
  )

  // Group same-mint verified notes so users holding >= 2 notes of the same token can combine them in 1 click (Tag 4: Merge)
  const mergeableGroups = useMemo(() => {
    const counts = new Map<string, { mintB58: string; count: number; totalRaw: bigint }>()
    for (const n of spendableNotes) {
      const prev = counts.get(n.mintB58)
      if (prev) {
        prev.count += 1
        prev.totalRaw += n.amount
      } else {
        counts.set(n.mintB58, { mintB58: n.mintB58, count: 1, totalRaw: n.amount })
      }
    }
    return Array.from(counts.values()).filter((g) => g.count >= 2)
  }, [spendableNotes])

  const startTransferNote = (note: SpendableAudrenNote) => {
    setErrorMsg(null)
    if (!note.amountResolved || note.amount <= 0n) {
      setErrorMsg('Still verifying this swap fill on-chain — click Refresh in a moment.')
      return
    }
    const idx = spendableNotes.findIndex(
      (n) => n.pageId === note.pageId && n.slotIndex === note.slotIndex,
    )
    if (idx >= 0) setSelectedNoteIdx(idx)
    setTransferAmountDraft(null)
    setActionTab('transfer')
    scrollToActionPanel()
  }

  const startWithdrawNote = (note: SpendableAudrenNote) => {
    setErrorMsg(null)
    if (!note.amountResolved || note.amount <= 0n) {
      setErrorMsg('Still verifying this swap fill on-chain — click Refresh in a moment.')
      return
    }
    const idx = spendableNotes.findIndex(
      (n) => n.pageId === note.pageId && n.slotIndex === note.slotIndex,
    )
    if (idx >= 0) setWithdrawNoteIdx(idx)
    setWithdrawAmountDraft(null)
    setActionTab('withdraw')
    scrollToActionPanel()
  }

  // Swappable notes = resolved SPL/WSOL notes (Jupiter trades SPL/WSOL mints)
  const swappableNotes = useMemo(
    () => spendableNotes.filter((n) => !n.isNativeSol),
    [spendableNotes],
  )
  const activeSwapNote = swappableNotes[swapNoteIdx] ?? swappableNotes[0] ?? null
  const activeTransferNote = spendableNotes[selectedNoteIdx] ?? spendableNotes[0] ?? null
  const activeWithdrawNote = spendableNotes[withdrawNoteIdx] ?? spendableNotes[0] ?? null

  const startSwapNote = (note: SpendableAudrenNote) => {
    setErrorMsg(null)
    if (cluster !== 'mainnet') {
      setActionTab('swap')
      scrollToActionPanel()
      return
    }
    if (note.isNativeSol) {
      setErrorMsg(
        'Direct SOL transfers privately right away, while DEX aggregator swaps require swap-ready SOL (WSOL) or any SPL token. Make a small amount of SOL private with "Ready for DEX swaps" checked (or pick USDC / any other token).',
      )
      setShieldAssetKey('SOL')
      setShieldWrapSol(true)
      setActionTab('shield')
      scrollToActionPanel()
      return
    }
    const idx = swappableNotes.findIndex(
      (n) => n.pageId === note.pageId && n.slotIndex === note.slotIndex,
    )
    if (idx >= 0) setSwapNoteIdx(idx)
    setSwapAmountDraft(null)
    setActionTab('swap')
    scrollToActionPanel()
  }

  // Resolve any mint held in Private Balance (or selected for swap) live from token metadata API
  useEffect(() => {
    if (cluster !== 'mainnet') return
    const wanted = new Set<string>([WSOL_MINT_STR, USDC_MAINNET_MINT_STR, swapOutMintChoice])
    for (const n of notes) {
      if (!n.isNativeSol) wanted.add(n.mintB58)
    }
    const missing = Array.from(wanted).filter((m) => !resolvedTokens[m])
    if (missing.length === 0) return

    let cancelled = false
    void (async () => {
      try {
        const res = await fetch('/api/tokens/resolve', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ mints: missing }),
        })
        if (!res.ok || cancelled) return
        const json = (await res.json()) as { items?: Record<string, SearchTokenCard> }
        if (json.items && !cancelled) {
          setResolvedTokens((prev) => ({ ...prev, ...json.items }))
        }
      } catch {
        // non-fatal
      }
    })()
    return () => {
      cancelled = true
    }
  }, [cluster, notes, swapOutMintChoice, resolvedTokens])

  // Live debounced search via token search API for Jupiter Swap output token picker
  useEffect(() => {
    if (cluster !== 'mainnet') return
    if (actionTab !== 'swap' && !swapPickerOpen) return
    let cancelled = false
    const timer = window.setTimeout(() => {
      setSearchingTokens(true)
      const params = new URLSearchParams({ limit: '15' })
      if (swapSearchQuery.trim()) params.set('q', swapSearchQuery.trim())
      void (async () => {
        try {
          const res = await fetch(`/api/tokens/search?${params}`)
          if (!res.ok || cancelled) return
          const json = (await res.json()) as { items?: SearchTokenCard[] }
          const items = (json.items ?? []).filter((t) => !t.flagged)
          if (!cancelled) {
            setSwapSearchResults(items)
            if (items.length > 0) {
              setResolvedTokens((prev) => {
                const next = { ...prev }
                for (const item of items) next[item.mint] = item
                return next
              })
            }
          }
        } catch {
          // non-fatal
        } finally {
          if (!cancelled) setSearchingTokens(false)
        }
      })()
    }, swapSearchQuery.trim() ? 220 : 0)
    return () => {
      cancelled = true
      window.clearTimeout(timer)
    }
  }, [cluster, actionTab, swapPickerOpen, swapSearchQuery])

  const getMeta = useCallback(
    (mintB58: string) =>
      tokenMeta(mintB58, balances?.tokens, resolvedTokens, balances?.solLogoUrl, balances?.solPriceUsd),
    [balances?.tokens, balances?.solLogoUrl, balances?.solPriceUsd, resolvedTokens],
  )

  // Keep output mint distinct from selected swap note's input mint (pure derivation)
  const swapOutMint =
    activeSwapNote && activeSwapNote.mintB58 === swapOutMintChoice
      ? (swapSearchResults.find((t) => t.mint !== activeSwapNote.mintB58)?.mint ??
        (activeSwapNote.mintB58 === USDC_MAINNET_MINT_STR ? WSOL_MINT_STR : USDC_MAINNET_MINT_STR))
      : swapOutMintChoice

  // Derived default amounts (user draft overrides until note switches)
  const transferInputMeta = activeTransferNote ? getMeta(activeTransferNote.mintB58) : null
  const transferAmountStr =
    transferAmountDraft ??
    (activeTransferNote && transferInputMeta
      ? formatUnits(
          activeTransferNote.amount,
          transferInputMeta.decimals,
          transferInputMeta.decimals,
        ).replace(/,/g, '')
      : '')
  const transferAmountRaw =
    activeTransferNote && transferInputMeta
      ? parseDecimalToRaw(transferAmountStr, transferInputMeta.decimals)
      : null
  const transferChangeRaw =
    activeTransferNote &&
    transferAmountRaw &&
    transferAmountRaw > 0n &&
    transferAmountRaw < activeTransferNote.amount
      ? activeTransferNote.amount - transferAmountRaw
      : 0n

  const withdrawInputMeta = activeWithdrawNote ? getMeta(activeWithdrawNote.mintB58) : null
  const withdrawAmountStr =
    withdrawAmountDraft ??
    (activeWithdrawNote && withdrawInputMeta
      ? formatUnits(
          activeWithdrawNote.amount,
          withdrawInputMeta.decimals,
          withdrawInputMeta.decimals,
        ).replace(/,/g, '')
      : '')
  const withdrawAmountRaw =
    activeWithdrawNote && withdrawInputMeta
      ? parseDecimalToRaw(withdrawAmountStr, withdrawInputMeta.decimals)
      : null
  const withdrawChangeRaw =
    activeWithdrawNote &&
    withdrawAmountRaw &&
    withdrawAmountRaw > 0n &&
    withdrawAmountRaw < activeWithdrawNote.amount
      ? activeWithdrawNote.amount - withdrawAmountRaw
      : 0n

  const swapInputMeta = activeSwapNote ? getMeta(activeSwapNote.mintB58) : null
  const swapInputMint = activeSwapNote?.mintB58 ?? null
  const swapNoteMaxRaw = activeSwapNote?.amount ?? null
  const swapInputDecimals = swapInputMeta?.decimals ?? 9
  const swapInputSymbol = swapInputMeta?.symbol ?? ''
  const swapAmountStr =
    swapAmountDraft ??
    (swapNoteMaxRaw !== null
      ? formatUnits(swapNoteMaxRaw, swapInputDecimals, swapInputDecimals).replace(/,/g, '')
      : '')
  const swapAmountRaw =
    swapNoteMaxRaw !== null ? parseDecimalToRaw(swapAmountStr, swapInputDecimals) : null
  const swapAmountExceedsNote = Boolean(
    swapNoteMaxRaw !== null && swapAmountRaw && swapAmountRaw > swapNoteMaxRaw,
  )
  const swapAmountValid = Boolean(
    swapNoteMaxRaw !== null && swapAmountRaw && swapAmountRaw > 0n && swapAmountRaw <= swapNoteMaxRaw,
  )
  const swapChangeRaw =
    swapNoteMaxRaw !== null && swapAmountValid && swapAmountRaw ? swapNoteMaxRaw - swapAmountRaw : 0n
  const swapQuoteMatchesAmount = Boolean(
    jupiterQuote &&
      swapInputMint &&
      swapAmountRaw &&
      jupiterQuote.quote.inAmount === swapAmountRaw.toString() &&
      jupiterQuote.inputMint === swapInputMint &&
      jupiterQuote.outputMint === swapOutMint &&
      jupiterQuote.slippageBps === swapSlippageBps,
  )

  // Fetch live Mainnet swap quote whenever swap inputs, amount, or fee mode change.
  // IMPORTANT: Dependencies are strictly primitives so re-renders never trigger an infinite re-quote loop!
  const relayerAvailable = Boolean(pool?.relayerAvailable)
  const fetchLiveJupiterQuote = useCallback(async () => {
    const reqSeq = ++swapQuoteSeqRef.current
    if (cluster !== 'mainnet' || !swapInputMint || swapNoteMaxRaw === null) {
      setJupiterQuote(null)
      setSwapQuoteError(null)
      return
    }
    if (!swapAmountValid || !swapAmountRaw) {
      setJupiterQuote(null)
      setQuotingSwap(false)
      setSwapQuoteError(
        swapAmountExceedsNote
          ? `Max available in this note is ${formatUnits(swapNoteMaxRaw, swapInputDecimals, swapInputDecimals)} ${swapInputSymbol}.`
          : null,
      )
      return
    }
    setQuotingSwap(true)
    setSwapQuoteError(null)
    try {
      const useRelaySwap = feeMode === 'relayer' && relayerAvailable
      if (useRelaySwap) {
        const res = await fetch(`${relayerUrl}/v1/swap/quote`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            provider: 'jupiter',
            inputMint: swapInputMint,
            outputMint: swapOutMint,
            amount: swapAmountRaw.toString(),
            slippageBps: swapSlippageBps,
            onlyDirectRoutes: true,
            includeFee: true,
          }),
        })
        const json = (await res.json()) as {
          ok?: boolean
          provider?: string
          shardId?: number
          escrowPda?: string
          quote?: {
            inAmount: string
            outAmount: string
            otherAmountThreshold: string
            priceImpactPct?: string | null
            routePlan?: Array<{ swapInfo?: { label?: string } }>
            rawQuote?: Record<string, unknown>
          }
          feePlan?: JupiterQuoteResponse['feePlan']
          mints?: {
            input?: { tokenProgram: string }
            output?: { tokenProgram: string }
          }
          error?: string
        }
        if (reqSeq !== swapQuoteSeqRef.current) return
        if (!res.ok || !json.quote) {
          throw new Error(json.error ?? 'Could not quote route via relay.audren.xyz')
        }
        setJupiterQuote({
          provider: json.provider ?? 'jupiter',
          inputMint: swapInputMint,
          outputMint: swapOutMint,
          slippageBps: swapSlippageBps,
          rawQuote: json.quote.rawQuote,
          feePlan: json.feePlan,
          quote: {
            inAmount: json.quote.inAmount,
            outAmount: json.quote.outAmount,
            otherAmountThreshold: json.quote.otherAmountThreshold,
            priceImpactPct: json.quote.priceImpactPct ?? undefined,
            routePlan: json.quote.routePlan,
          },
          usedDirectOnly: true,
          shardId: json.shardId ?? 0,
          swapEscrowPda: json.escrowPda ?? '',
          vaultAuthPda: '',
          escrowInAta: '',
          escrowOutAta: '',
          vaultInAta: '',
          vaultOutAta: '',
          tokenProgramIn: json.mints?.input?.tokenProgram ?? CLASSIC_TOKEN_PROGRAM_ID_STR,
          tokenProgramOut: json.mints?.output?.tokenProgram ?? CLASSIC_TOKEN_PROGRAM_ID_STR,
          missingAtas: [],
        })
      } else {
        const res = await fetch('/api/jupiter/quote', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            inputMint: swapInputMint,
            outputMint: swapOutMint,
            amount: swapAmountRaw.toString(),
            slippageBps: swapSlippageBps,
            onlyDirectRoutes: true,
          }),
        })
        const json = (await res.json()) as JupiterQuoteResponse & { error?: string }
        if (reqSeq !== swapQuoteSeqRef.current) return
        if (!res.ok) throw new Error(json.error ?? 'Could not quote Jupiter route')
        setJupiterQuote({
          ...json,
          inputMint: swapInputMint,
          outputMint: swapOutMint,
          slippageBps: swapSlippageBps,
        })
      }
    } catch (err) {
      if (reqSeq !== swapQuoteSeqRef.current) return
      setJupiterQuote(null)
      setSwapQuoteError(err instanceof Error ? err.message : 'Swap quote failed')
    } finally {
      if (reqSeq === swapQuoteSeqRef.current) setQuotingSwap(false)
    }
  }, [
    cluster,
    swapInputMint,
    swapNoteMaxRaw,
    swapInputDecimals,
    swapInputSymbol,
    swapAmountValid,
    swapAmountRaw,
    swapAmountExceedsNote,
    swapOutMint,
    swapSlippageBps,
    feeMode,
    relayerAvailable,
    relayerUrl,
  ])

  useEffect(() => {
    if (actionTab !== 'swap' || cluster !== 'mainnet' || !swapInputMint) return
    const id = window.setTimeout(() => {
      void fetchLiveJupiterQuote()
    }, 200)
    return () => window.clearTimeout(id)
  }, [actionTab, cluster, swapInputMint, fetchLiveJupiterQuote])

  // Helper: fetch fresh blockhash via Worker proxy
  const fetchFreshBlockhash = async (targetCluster: SolanaCluster) => {
    const res = await fetch(`/api/rpc/blockhash?cluster=${targetCluster}`)
    const json = (await res.json()) as {
      blockhash?: string
      lastValidBlockHeight?: number
      error?: string
    }
    if (!res.ok || !json.blockhash) {
      throw new Error(json.error ?? 'Failed to get latest blockhash')
    }
    return {
      blockhash: json.blockhash,
      lastValidBlockHeight: BigInt(json.lastValidBlockHeight ?? 0),
    }
  }

  // Helper: execute a proved Audren instruction either via Stateless Solana v1 Relayer OR @solana/kit Self-Pay
  const submitProvedInstruction = async (params: {
    innerIx: SolanaInstruction
    mode: FeeMode
    computeUnitLimit: number
    setupAtas?: Array<{ owner: string; mint: string; tokenProgram: string }>
    lookupTables?: Record<string, string[]>
    vaultOutAta?: string
    extraPreIxs?: SolanaInstruction[]
    extraPostIxs?: SolanaInstruction[]
    openPageIx?: SolanaInstruction
    rolloverFromPageId?: string
  }): Promise<{
    signature: string
    slot: number
    solscanUrl: string
    explorerUrl: string
    txFormat: string
    feePayerAddress: string
    actualOut?: string | null
  }> => {
    const tier = PRIORITY_TIERS[priorityTier]

    if (params.mode === 'relayer') {
      setBusyLabel(`Sending via ${activeRelayerHost}…`)
      const res = await fetch(`${relayerUrl}/v1/relay/submit`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          cluster,
          instructionDataB64: toBase64(params.innerIx.data),
          accounts: params.innerIx.accounts.map((a) => ({
            pubkey: base58Encode(a.pubkey),
            isSigner: a.isSigner,
            isWritable: a.isWritable,
          })),
          setupAtas: params.setupAtas,
          computeUnitLimit: params.computeUnitLimit,
          priorityFeeLamports: tier.relayerLamports.toString(),
          vaultOutAta: params.vaultOutAta,
          rolloverFromPageId: params.rolloverFromPageId,
        }),
      })
      const json = (await res.json()) as {
        signature?: string
        slot?: number
        txWireBytes?: number
        relayerPubkey?: string
        solscanUrl?: string
        explorerUrl?: string
        actualOut?: string | null
        billingMode?: string
        error?: string
      }
      if (!res.ok || !json.signature) {
        throw new Error(json.error ?? 'Privacy relay submission failed')
      }
      return {
        signature: json.signature,
        slot: json.slot ?? 0,
        solscanUrl: json.solscanUrl ?? '',
        explorerUrl: json.explorerUrl ?? '',
        txFormat: `1 transaction · ${activeRelayerHost}`,
        feePayerAddress: json.relayerPubkey ?? pool?.relayerAddress ?? 'Relayer',
        actualOut: json.actualOut ?? null,
      }
    }

    // Direct Self-Pay via @solana/kit + Wallet Standard (Phantom / Solflare / Backpack)
    if (!connected) throw new Error('Connect wallet first')
    const { blockhash, lastValidBlockHeight } = await fetchFreshBlockhash(cluster)

    // Prepend optional permissionless RolloverPage + any missing vault/escrow ATAs
    const preIxs: SolanaInstruction[] = [
      ...(params.openPageIx ? [params.openPageIx] : []),
      ...(params.extraPreIxs ?? []),
    ]
    for (const s of params.setupAtas ?? []) {
      const ownerBytes = base58Decode(s.owner)
      const mintBytes = base58Decode(s.mint)
      const tpBytes = base58Decode(s.tokenProgram)
      const ata = await deriveAta(ownerBytes, tpBytes, mintBytes)
      preIxs.push(
        buildCreateAtaIdempotentIx({
          payer: connected.pubkeyBytes,
          ata,
          owner: ownerBytes,
          mint: mintBytes,
          tokenProgram: tpBytes,
        }),
      )
    }

    // Try direct single v0 transaction first (works for full Withdraw when <= 1,232 B)
    let unsignedTxs: Uint8Array[] = []
    let txFormat = ''

    const singleTxCuLimit = Math.min(
      params.computeUnitLimit + (params.openPageIx ? 50_000 : 0),
      1_400_000,
    )
    const postIxs: SolanaInstruction[] = params.extraPostIxs ?? []
    const singleCandidate = compileKitV0Transaction({
      feePayer: connected.address,
      recentBlockhash: blockhash,
      lastValidBlockHeight,
      instructions: [...preIxs, params.innerIx, ...postIxs],
      computeUnitLimit: singleTxCuLimit,
      priorityMicroLamportsPerCu: tier.microLamportsPerCu,
      lookupTables: params.lookupTables,
    })

    if (singleCandidate.length <= 1232) {
      unsignedTxs = [singleCandidate]
      txFormat = `1 transaction · Direct wallet`
    } else {
      // Automatically split via ProofBuffer (100% temporary rent refunded atomically)
      // Record PDA in local journal BEFORE signing so interrupted uploads can reclaim rent in 1 click!
      const plan = await buildBufferedExecutionPlan(params.innerIx)
      const bufPdaB58 = base58Encode(plan.proofBufferPda)
      recordPendingProofBuffer(cluster, connected.address, {
        nonce: plan.nonce.toString(),
        bufferPdaB58: bufPdaB58,
        label: `Private action (${plan.uploadChunks.length} upload chunks)`,
        createdAtMs: getEpochNowMs(),
      })
      if (preIxs.length > 0) {
        unsignedTxs.push(
          compileKitV0Transaction({
            feePayer: connected.address,
            recentBlockhash: blockhash,
            lastValidBlockHeight,
            instructions: preIxs,
            computeUnitLimit: 200_000,
            priorityMicroLamportsPerCu: tier.microLamportsPerCu,
          }),
        )
      }
      for (const chunkIx of plan.uploadChunks) {
        unsignedTxs.push(
          compileKitV0Transaction({
            feePayer: connected.address,
            recentBlockhash: blockhash,
            lastValidBlockHeight,
            instructions: [chunkIx],
            computeUnitLimit: 100_000,
            priorityMicroLamportsPerCu: tier.microLamportsPerCu,
          }),
        )
      }
      const execWire = compileKitV0Transaction({
        feePayer: connected.address,
        recentBlockhash: blockhash,
        lastValidBlockHeight,
        instructions: [plan.executeIx, ...postIxs],
        computeUnitLimit: params.computeUnitLimit,
        priorityMicroLamportsPerCu: tier.microLamportsPerCu,
        lookupTables: params.lookupTables,
      })
      if (execWire.length > 1232) {
        removePendingProofBuffer(cluster, connected.address, bufPdaB58)
        throw new Error(
          `This swap route has too many accounts for direct browser signing. Try a simpler pair or Privacy Relayer mode.`,
        )
      }
      unsignedTxs.push(execWire)
      txFormat = `${unsignedTxs.length} transactions · Direct wallet (buffer rent refunded)`

      setBusyLabel(`Approve in ${connected.name} (${unsignedTxs.length} bundled steps)…`)
      let signed: Uint8Array[]
      try {
        signed = await signCompiledTransactionsWithWallet(connected, cluster, unsignedTxs)
      } catch (signErr) {
        // User cancelled before broadcasting — buffer was never created on-chain
        removePendingProofBuffer(cluster, connected.address, bufPdaB58)
        throw signErr
      }
      setBusyLabel(`Broadcasting to Solana ${cluster === 'mainnet' ? 'Mainnet' : 'Devnet'}…`)
      let confirmedCount = 0
      let results: Awaited<ReturnType<typeof sendAndConfirmSignedTransactions>>
      try {
        results = await sendAndConfirmSignedTransactions(cluster, signed, {
          vaultOutAta: params.vaultOutAta,
          onProgress: (idx, total) => {
            confirmedCount = idx + 1
            setBusyLabel(`Confirmed ${idx + 1} / ${total} on Solana…`)
          },
        })
      } catch (sendErr) {
        if (confirmedCount === 0) {
          removePendingProofBuffer(cluster, connected.address, bufPdaB58)
        }
        const msg = sendErr instanceof Error ? sendErr.message : String(sendErr)
        if (/blockhash not found/i.test(msg)) {
          throw new Error(
            'Transaction expired while waiting for wallet approval (~60s Solana blockhash window). Click again to submit with a fresh blockhash.',
          )
        }
        throw sendErr
      }
      // Atomic ExecBuffered closed the ProofBuffer and refunded rent — clear journal entry!
      removePendingProofBuffer(cluster, connected.address, bufPdaB58)
      const finalRes = results[results.length - 1]
      return {
        signature: finalRes.signature,
        slot: finalRes.slot,
        solscanUrl:
          cluster === 'mainnet'
            ? `https://solscan.io/tx/${finalRes.signature}`
            : `https://solscan.io/tx/${finalRes.signature}?cluster=devnet`,
        explorerUrl:
          cluster === 'mainnet'
            ? `https://explorer.solana.com/tx/${finalRes.signature}`
            : `https://explorer.solana.com/tx/${finalRes.signature}?cluster=devnet`,
        txFormat,
        feePayerAddress: connected.address,
        actualOut: finalRes.actualOut ?? null,
      }
    }

    setBusyLabel(`Approve in ${connected.name}…`)
    const signed = await signCompiledTransactionsWithWallet(connected, cluster, unsignedTxs)
    setBusyLabel(`Broadcasting to Solana ${cluster === 'mainnet' ? 'Mainnet' : 'Devnet'}…`)
    const results = await sendAndConfirmSignedTransactions(cluster, signed, {
      vaultOutAta: params.vaultOutAta,
      onProgress: (idx, total) => {
        setBusyLabel(`Confirmed ${idx + 1} / ${total} on Solana…`)
      },
    })
    const finalRes = results[results.length - 1]
    return {
      signature: finalRes.signature,
      slot: finalRes.slot,
      solscanUrl:
        cluster === 'mainnet'
          ? `https://solscan.io/tx/${finalRes.signature}`
          : `https://solscan.io/tx/${finalRes.signature}?cluster=devnet`,
      explorerUrl:
        cluster === 'mainnet'
          ? `https://explorer.solana.com/tx/${finalRes.signature}`
          : `https://explorer.solana.com/tx/${finalRes.signature}?cluster=devnet`,
      txFormat,
      feePayerAddress: connected.address,
      actualOut: finalRes.actualOut ?? null,
    }
  }

  // Fetch any historical input page on demand (even if older than the latest 16 pages in `/api/pool`)
  const resolveInputPageBase64 = async (pageId: bigint, preferSealedCdn = false): Promise<string> => {
    const idStr = pageId.toString()
    const inPool = pool?.pages.find((p) => p.pageId === idStr)?.pageBase64
    if (inPool) return inPool
    const cacheKey = `${cluster}:${idStr}`
    const cached = historicalPageCacheRef.current.get(cacheKey)
    if (cached) return cached
    setBusyLabel(`Loading pool page #${idStr}…`)
    const res = preferSealedCdn
      ? await fetch(`/api/pages/sealed?cluster=${cluster}&ids=${idStr}`)
      : await fetch('/api/pages/fetch', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ cluster, poolId: 0, pageIds: [idStr] }),
        })
    const json = (await res.json()) as {
      pages?: Array<{ pageId: string; pageBase64: string }>
      error?: string
    }
    const found = json.pages?.find((p) => p.pageId === idStr)?.pageBase64
    if (!res.ok || !found) {
      throw new Error(json.error ?? `Could not load historical pool page #${idStr}. Click Refresh and retry.`)
    }
    historicalPageCacheRef.current.set(cacheKey, found)
    return found
  }

  // Build a ring with 32, 64, or 128 slots from the real page and sampled decoy pages.
  // Public page IDs, populated prefixes and differing fetch paths can reveal metadata;
  // slot count does not establish equally plausible candidates or network anonymity.
  const buildMultiPageRingForNote = async (
    note: SpendableAudrenNote,
    desiredRingSize: 32 | 64 | 128,
  ): Promise<{
    inputPageIds: bigint[]
    ring: RingSlotWitness[]
    secretIndex: number
    nPages: 1 | 2 | 4
  }> => {
    const curLane0 = pool ? BigInt(pool.currentPageId) : note.pageId
    const decoyPool: bigint[] = []
    // Prefer sealed historical pages from Lane 0 (immutable, CDN-cached, full 32 notes)
    const maxSealed = curLane0 > 0n ? curLane0 - 1n : -1n
    for (let pid = maxSealed; pid >= 0n && decoyPool.length < 32; pid--) {
      if (pid !== note.pageId) decoyPool.push(pid)
    }
    // Also include any other non-empty loaded pages from `/api/pool` if pool has very few pages
    for (const pg of pool?.pages ?? []) {
      const pid = BigInt(pg.pageId)
      if (pid !== note.pageId && pg.count > 0 && !decoyPool.includes(pid)) decoyPool.push(pid)
    }

    const wantedPages: 1 | 2 | 4 = desiredRingSize === 128 ? 4 : desiredRingSize === 64 ? 2 : 1
    let nPages: 1 | 2 | 4 = 1
    if (wantedPages === 4 && decoyPool.length >= 3) nPages = 4
    else if (wantedPages >= 2 && decoyPool.length >= 1) nPages = 2

    if (nPages === 1) {
      const b64 = await resolveInputPageBase64(note.pageId)
      return {
        inputPageIds: [note.pageId],
        ring: extractRingFromPage(fromBase64(b64)),
        secretIndex: note.slotIndex,
        nPages: 1,
      }
    }

    // Uniformly sample (nPages - 1) distinct decoy pages via CSPRNG Fisher-Yates,
    // then sort strictly ascending (`prev.page_id < h.page_id`) as enforced on-chain by `load_input_pages`!
    const poolCopy = [...decoyPool]
    const rand = crypto.getRandomValues(new Uint32Array(poolCopy.length))
    for (let i = poolCopy.length - 1; i > 0; i--) {
      const j = rand[i] % (i + 1)
      const tmp = poolCopy[i]
      poolCopy[i] = poolCopy[j]
      poolCopy[j] = tmp
    }
    const decoys = poolCopy.slice(0, nPages - 1)
    const inputPageIds: bigint[] = [...decoys, note.pageId].sort((a, b) =>
      a < b ? -1 : a > b ? 1 : 0,
    )
    const realPageIdx = inputPageIds.indexOf(note.pageId)

    const pagesB64 = await Promise.all(
      inputPageIds.map((pid) =>
        resolveInputPageBase64(pid, pid !== note.pageId && pid < curLane0),
      ),
    )
    const ring: RingSlotWitness[] = []
    for (const b64 of pagesB64) {
      ring.push(...extractRingFromPage(fromBase64(b64)))
    }
    return {
      inputPageIds,
      ring,
      secretIndex: realPageIdx * 32 + note.slotIndex,
      nPages,
    }
  }

  // Decide output page ID + automatic permissionless RolloverPage (`Tag 1` on Lane 0 or
  // `Tag 12: OpenLanePage` with read-only PoolState on parallel Lanes 1..15!).
  const resolveOutputPagePlan = async (
    requiredOutputs: number,
    useRelayer: boolean,
  ): Promise<{
    outPageId: bigint
    openPageIx?: SolanaInstruction
    rolloverFromPageId?: string
  }> => {
    if (!pool) throw new Error('Pool state not loaded yet')
    const curId = BigInt(pool.currentPageId)
    if (requiredOutputs <= 0) {
      return { outPageId: curId }
    }

    // When parallel append lanes (1..15) are active, prefer an open parallel lane so
    // `PoolState` stays strictly READ-ONLY (zero global write-lock contention!).
    const liveLanes = pool.lanes ?? []
    if (liveLanes.length > 1) {
      const openParallel = liveLanes.filter(
        (l) => l.laneId > 0 && !l.pageClosed && l.pageCount < PAGE_ROLLOVER_THRESHOLD,
      )
      if (openParallel.length > 0) {
        const pick =
          openParallel[crypto.getRandomValues(new Uint8Array(1))[0] % openParallel.length]
        return { outPageId: BigInt(pick.activePageId) }
      }
      // If a parallel lane is ready to roll over, roll it over with Tag 12 (read-only PoolState!)
      const parallelReady = liveLanes.find((l) => l.laneId > 0)
      if (parallelReady) {
        const laneCurId = BigInt(parallelReady.activePageId)
        const nextId = pageIdForLane(parallelReady.laneId, seqOfPageId(laneCurId) + 1n)
        if (useRelayer) {
          return { outPageId: nextId, rolloverFromPageId: parallelReady.activePageId }
        }
        if (!connected) throw new Error('Connect wallet first')
        const openPageIx = await buildOpenLanePageInstruction({
          payer: connected.pubkeyBytes,
          poolId: 0,
          currentPageId: laneCurId,
        })
        return { outPageId: nextId, openPageIx }
      }
    }

    const curSummary = pool.pages.find((p) => p.pageId === pool.currentPageId)
    const needsRollover = Boolean(
      curSummary && (curSummary.closed || curSummary.count >= PAGE_ROLLOVER_THRESHOLD),
    )
    if (!needsRollover) {
      return { outPageId: curId }
    }
    const nextId = curId + 1n
    if (useRelayer) {
      return { outPageId: nextId, rolloverFromPageId: pool.currentPageId }
    }
    if (!connected) throw new Error('Connect wallet first')
    const openPageIx = await buildOpenPageInstruction({
      payer: connected.pubkeyBytes,
      poolId: 0,
      currentPageId: curId,
    })
    return { outPageId: nextId, openPageIx }
  }

  // ============================================================================
  // ACTION 1: SHIELD (Public Wallet -> My Private Balance OR Anyone's aud1… Address)
  // ============================================================================
  const handleShield = async () => {
    if (!connected || !pool) return
    if (shieldToSelf && !audrenKeys) return
    setErrorMsg(null)
    const opt = selectedShieldOption
    if (opt.isNonTransferable) {
      setErrorMsg(
        `${opt.symbol} is a non-transferable (soulbound) Token-2022 mint and cannot be deposited into a private vault.`,
      )
      return
    }
    if (opt.hasActiveTransferHook) {
      setErrorMsg(
        `${opt.symbol} has an active Token-2022 Transfer Hook program, which is not supported for private deposits yet.`,
      )
      return
    }
    let recipientAddr: { spendPk: Uint8Array; viewPk: Uint8Array }
    if (shieldToSelf) {
      recipientAddr = { spendPk: audrenKeys!.spendPk, viewPk: audrenKeys!.viewPk }
    } else {
      try {
        recipientAddr = parseAudrenAddress(shieldRecipient)
      } catch (err) {
        setErrorMsg(err instanceof Error ? err.message : 'Enter a valid recipient aud1… address')
        return
      }
    }
    const rawAmount = parseDecimalToRaw(shieldAmountStr, opt.decimals)
    if (!rawAmount) {
      setErrorMsg('Enter a valid positive amount to make private.')
      return
    }
    const maxRaw = BigInt(
      opt.wrapFromSol || opt.mintB58 === 'SOL'
        ? balances?.solLamports ?? '0'
        : balances?.tokens.find((t) => t.mint === opt.mintB58)?.amountRaw ?? '0',
    )
    if (rawAmount > maxRaw) {
      setErrorMsg(`Insufficient ${opt.symbol} balance in your public wallet.`)
      return
    }

    let netAmount: bigint | undefined
    if (opt.hasActiveTransferFee && opt.transferFeeBps > 0) {
      const net = netDepositAmount(rawAmount, opt.transferFeeBps, BigInt(opt.transferFeeMax))
      if (net <= 0n) {
        setErrorMsg(`Amount is too small after ${opt.symbol}'s Token-2022 transfer fee.`)
        return
      }
      netAmount = net
    }

    setBusyLabel(shieldToSelf ? 'Preparing private deposit…' : 'Preparing stealth payment…')
    try {
      const t0 = getPerfNowMs()
      const { outPageId, openPageIx } = await resolveOutputPagePlan(1, false)
      const preIxs: SolanaInstruction[] = openPageIx ? [openPageIx] : []
      const mintBytes = opt.wrapFromSol
        ? WSOL_MINT
        : opt.mintB58 === 'SOL'
          ? NATIVE_SOL_MINT
          : base58Decode(opt.mintB58)

      const postIxs: SolanaInstruction[] = []
      if (opt.wrapFromSol) {
        const wrapped = await buildWrapSolInstructions(connected.pubkeyBytes, rawAmount)
        preIxs.push(...wrapped.instructions)
        const hasExistingWsol = Boolean(
          balances?.tokens.some((t) => t.mint === WSOL_MINT_STR && BigInt(t.amountRaw) > 0n),
        )
        if (!hasExistingWsol) {
          postIxs.push(await buildCloseWsolAtaInstruction(connected.pubkeyBytes))
        }
      }

      const { instructions: depIxs } = await buildDepositInstruction({
        depositor: connected.pubkeyBytes,
        poolId: 0,
        activePageId: outPageId,
        recipient: recipientAddr,
        mint: mintBytes,
        amount: rawAmount,
        netAmount,
        tokenProgram: base58Decode(opt.tokenProgram),
        memoText: shieldMemo || 'VAULT',
        createVaultAtaIfMissing: opt.mintB58 !== 'SOL',
      })
      const proverMs = Math.round(getPerfNowMs() - t0)

      const { blockhash, lastValidBlockHeight } = await fetchFreshBlockhash(cluster)
      const tier = PRIORITY_TIERS[priorityTier]
      const unsigned = compileKitV0Transaction({
        feePayer: connected.address,
        recentBlockhash: blockhash,
        lastValidBlockHeight,
        instructions: [...preIxs, ...depIxs, ...postIxs],
        computeUnitLimit: openPageIx ? 360_000 : 300_000,
        priorityMicroLamportsPerCu: tier.microLamportsPerCu,
      })

      setBusyLabel(`Approve Deposit in ${connected.name}…`)
      const [signed] = await signCompiledTransactionsWithWallet(connected, cluster, [unsigned])
      setBusyLabel(`Confirming on Solana ${cluster === 'mainnet' ? 'Mainnet' : 'Devnet'}…`)
      const [sent] = await sendAndConfirmSignedTransactions(cluster, [signed])

      const uiDisplay = `${formatUnits(rawAmount, opt.decimals)} ${opt.symbol}`
      pushAudit({
        action: shieldToSelf ? 'Make Private' : 'Pay Private Address',
        cluster,
        signature: sent.signature,
        slot: sent.slot,
        solscanUrl:
          cluster === 'mainnet'
            ? `https://solscan.io/tx/${sent.signature}`
            : `https://solscan.io/tx/${sent.signature}?cluster=devnet`,
        explorerUrl:
          cluster === 'mainnet'
            ? `https://explorer.solana.com/tx/${sent.signature}`
            : `https://explorer.solana.com/tx/${sent.signature}?cluster=devnet`,
        txFormat: `1 transaction · Direct wallet`,
        feePayerMode: 'self',
        feePayerAddress: connected.address,
        priorityLabel: `${tier.label} (${tier.desc})`,
        proverMs,
        summary: shieldToSelf
          ? `Made ${uiDisplay} private`
          : `Sent ${uiDisplay} from public wallet to ${shortAddr(shieldRecipient.trim(), 7, 5)}`,
        publicSaw: `Your wallet (${shortAddr(connected.address)}) moved ${uiDisplay} into the shared Audren Pool.`,
        stayedPrivate: shieldToSelf
          ? `The recipient uses a fresh ownership key and the memo is encrypted. Deposit asset, amount and output location are public by design; later actions have their own visibility boundaries.`
          : `The reusable aud1… address is replaced by a fresh ownership key. Deposit asset, amount and output location remain public; outside information may identify the recipient.`,
        sdkCode: `import { AUDREN_PROGRAM_ID, encodeDepositData } from '@audren/sdk'

const depositIx = {
  programAddress: AUDREN_PROGRAM_ID,
  accounts: depositAccounts,
  data: encodeDepositData({
    isNativeSol: ${opt.mintB58 === 'SOL' && !opt.wrapFromSol ? 'true' : 'false'},
    amount: ${rawAmount.toString()}n, // ${uiDisplay}
    output: encryptedNote,
  }),
}`,
      })

      await refreshPoolAndVault(cluster, connected.address, audrenKeys)
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Shield transaction failed')
    } finally {
      setBusyLabel(null)
    }
  }

  // ============================================================================
  // ACTION 2: PRIVATE TRANSFER (Note -> Self or Any aud1… Recipient)
  // ============================================================================
  const handlePrivateTransfer = async () => {
    if (!connected || !audrenKeys || !pool || !activeTransferNote) return
    setErrorMsg(null)
    if (nullifierStatus !== 'verified') {
      setErrorMsg('Wait for spent-status verification to finish (or click Refresh) before sending.')
      return
    }
    const meta = getMeta(activeTransferNote.mintB58)
    const payAmount = parseDecimalToRaw(transferAmountStr, meta.decimals)
    if (!payAmount || payAmount > activeTransferNote.amount) {
      setErrorMsg(
        `Enter an amount up to ${formatUnits(activeTransferNote.amount, meta.decimals, meta.decimals)} ${meta.symbol}.`,
      )
      return
    }

    const useRelayer = feeMode === 'relayer' && pool.relayerAvailable && !!pool.relayerAddress
    const payerPubkey = useRelayer
      ? base58Decode(pool.relayerAddress!)
      : connected.pubkeyBytes

    let recipientAddr = { spendPk: audrenKeys.spendPk, viewPk: audrenKeys.viewPk }
    if (!transferToSelf) {
      try {
        recipientAddr = parseAudrenAddress(transferRecipient)
      } catch (err) {
        setErrorMsg(err instanceof Error ? err.message : 'Invalid recipient aud1… address')
        return
      }
    }

    setBusyLabel('Creating privacy proof in your browser…')
    await new Promise((r) => setTimeout(r, 30))
    try {
      const [ringPlan, outputPlan] = await Promise.all([
        buildMultiPageRingForNote(activeTransferNote, ringSize),
        resolveOutputPagePlan(2, useRelayer),
      ])
      const t0 = getPerfNowMs()
      const { instruction } = await buildTransferInstruction({
        payer: payerPubkey,
        poolId: 0,
        outPageId: outputPlan.outPageId,
        inputPageIds: ringPlan.inputPageIds,
        ring: ringPlan.ring,
        inputNote: activeTransferNote,
        secretIndex: ringPlan.secretIndex,
        recipient: recipientAddr,
        changeAddr: { spendPk: audrenKeys.spendPk, viewPk: audrenKeys.viewPk },
        payAmount,
        memoText: transferMemo || 'PAY',
      })
      const proverMs = Math.round(getPerfNowMs() - t0)
      const transferCu =
        ringPlan.nPages === 4 ? 1_380_000 : ringPlan.nPages === 2 ? 1_050_000 : 850_000

      const res = await submitProvedInstruction({
        innerIx: instruction,
        mode: useRelayer ? 'relayer' : 'self',
        computeUnitLimit: transferCu,
        openPageIx: outputPlan.openPageIx,
        rolloverFromPageId: outputPlan.rolloverFromPageId,
      })

      const uiDisplay = `${formatUnits(payAmount, meta.decimals)} ${meta.symbol}`
      const ringNote = `${ringPlan.nPages * 32}-slot proof ring`
      pushAudit({
        action: 'Private Transfer',
        cluster,
        signature: res.signature,
        slot: res.slot,
        solscanUrl: res.solscanUrl,
        explorerUrl: res.explorerUrl,
        txFormat: `${res.txFormat} · ${ringNote}`,
        feePayerMode: useRelayer ? 'relayer' : 'self',
        feePayerAddress: res.feePayerAddress,
        priorityLabel: `${PRIORITY_TIERS[priorityTier].label} (${PRIORITY_TIERS[priorityTier].desc})`,
        proverMs,
        summary: transferToSelf
          ? `Sent ${uiDisplay} privately to yourself (${ringNote})`
          : `Sent ${uiDisplay} privately to ${shortAddr(transferRecipient, 10, 6)} (${ringNote})`,
        publicSaw: useRelayer
          ? `Relayer ${shortAddr(res.feePayerAddress)} paid for this private transfer using a ${ringNote}. Candidate pages, timing and the relay fee payer are public; token and amount commitments are blinded.`
          : `Your wallet (${shortAddr(connected.address)}) is the public fee payer. The proof conceals input selection within the ${ringNote}; token and amount commitments are blinded and the recipient uses a fresh key.`,
        stayedPrivate: `The proof does not disclose the selected input note; payment token and amount are blinded. Candidate composition, timing and outside information can still create links.`,
        sdkCode: `${
          useRelayer
            ? `const RELAY_URL = '${relayerUrl}' // or swap for your own self-hosted relay\n`
            : ''
        }const { instruction } = await buildTransferInstruction({
  payer: ${useRelayer ? 'relayerPubkey' : 'walletPubkey'},
  poolId: 0,
  inputPageIds: [${ringPlan.inputPageIds.map((p) => `${p.toString()}n`).join(', ')}],
  inputNote,
  recipient,
  payAmount: ${payAmount.toString()}n, // ${uiDisplay}
})${
          useRelayer
            ? `\nawait fetch(\`\${RELAY_URL}/v1/relay/submit\`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ cluster: '${cluster}', instructionDataB64, accounts }) })`
            : ''
        }`,
      })

      await refreshPoolAndVault(cluster, connected.address, audrenKeys)
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Private transfer failed')
    } finally {
      setBusyLabel(null)
    }
  }

  // ============================================================================
  // ACTION 2B: COMBINE NOTES (Tag 4: Merge 2 same-asset notes -> 1 larger note)
  // ============================================================================
  const handleMergeNotes = async (mintB58: string) => {
    if (!connected || !audrenKeys || !pool) return
    setErrorMsg(null)
    if (nullifierStatus !== 'verified') {
      setErrorMsg('Wait for spent-status verification to finish (or click Refresh) before combining notes.')
      return
    }
    const matching = spendableNotes
      .filter((n) => n.mintB58 === mintB58)
      .sort((a, b) => (a.amount > b.amount ? -1 : a.amount < b.amount ? 1 : 0))
    if (matching.length < 2) {
      setErrorMsg('Need at least 2 verified private notes of the same token to combine.')
      return
    }
    const [note1, note2] = matching
    const meta = getMeta(mintB58)
    const useRelayer = feeMode === 'relayer' && pool.relayerAvailable && !!pool.relayerAddress
    const payerPubkey = useRelayer
      ? base58Decode(pool.relayerAddress!)
      : connected.pubkeyBytes

    // Tag 4 enforces MAX_MERGE_RING_SLOTS = 128 across both legs (max 64 + 64)
    const perLegRing: 32 | 64 = ringSize >= 64 && MAX_MERGE_RING_SLOTS >= 128 ? 64 : 32
    setBusyLabel(`Combining 2 ${meta.symbol} notes into 1…`)
    await new Promise((r) => setTimeout(r, 30))
    try {
      const [ring1Plan, ring2Plan, outputPlan] = await Promise.all([
        buildMultiPageRingForNote(note1, perLegRing),
        buildMultiPageRingForNote(note2, perLegRing),
        resolveOutputPagePlan(1, useRelayer),
      ])
      const t0 = getPerfNowMs()
      const { instruction } = await buildMergeInstruction({
        payer: payerPubkey,
        poolId: 0,
        outPageId: outputPlan.outPageId,
        input1PageIds: ring1Plan.inputPageIds,
        ring1: ring1Plan.ring,
        note1,
        secretIndex1: ring1Plan.secretIndex,
        input2PageIds: ring2Plan.inputPageIds,
        ring2: ring2Plan.ring,
        note2,
        secretIndex2: ring2Plan.secretIndex,
        ownerAddr: { spendPk: audrenKeys.spendPk, viewPk: audrenKeys.viewPk },
        memoText: 'MERGE',
      })
      const proverMs = Math.round(getPerfNowMs() - t0)
      const totalSlots = (ring1Plan.nPages + ring2Plan.nPages) * 32
      const mergeCu = totalSlots > 64 ? 1_380_000 : 1_150_000

      const res = await submitProvedInstruction({
        innerIx: instruction,
        mode: useRelayer ? 'relayer' : 'self',
        computeUnitLimit: mergeCu,
        openPageIx: outputPlan.openPageIx,
        rolloverFromPageId: outputPlan.rolloverFromPageId,
      })

      const totalDisplay = `${formatUnits(note1.amount + note2.amount, meta.decimals)} ${meta.symbol}`
      pushAudit({
        action: 'Combine Notes',
        cluster,
        signature: res.signature,
        slot: res.slot,
        solscanUrl: res.solscanUrl,
        explorerUrl: res.explorerUrl,
        txFormat: `${res.txFormat} · Tag 4 Merge`,
        feePayerMode: useRelayer ? 'relayer' : 'self',
        feePayerAddress: res.feePayerAddress,
        priorityLabel: `${PRIORITY_TIERS[priorityTier].label} (${PRIORITY_TIERS[priorityTier].desc})`,
        proverMs,
        summary: `Combined 2 ${meta.symbol} notes into 1 single ${totalDisplay} note`,
        publicSaw: useRelayer
          ? `Relayer ${shortAddr(res.feePayerAddress)} submitted a private 2-in → 1-out note consolidation on the shared Audren Pool. Token (${meta.symbol}), amounts, and selected inputs are blinded by the proof; candidate pages, timing, and the fee payer remain public.`
          : `Your wallet (${shortAddr(connected.address)}) paid the Solana network fee for a private 2-in → 1-out note consolidation. Token (${meta.symbol}), amounts, and selected inputs are blinded by the proof; candidate pages, timing, and your fee-payer wallet remain public.`,
        stayedPrivate: `Which two notes were merged, token (${meta.symbol}), combined amount (${totalDisplay}), and your private ownership.`,
        sdkCode: `const { instruction } = await buildMergeInstruction({
  payer: ${useRelayer ? 'relayerPubkey' : 'walletPubkey'},
  poolId: 0,
  note1,
  note2,
  ownerAddr,
})`,
      })

      await refreshPoolAndVault(cluster, connected.address, audrenKeys)
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Combine notes failed')
    } finally {
      setBusyLabel(null)
    }
  }

  // ============================================================================
  // ACTION 3: PRIVATE JUPITER SWAP (Real Mainnet SwapViaRouter — Partial or Full!)
  // ============================================================================
  const handlePrivateSwap = async () => {
    if (!connected || !audrenKeys || !pool || !activeSwapNote || !jupiterQuote) return
    setErrorMsg(null)
    if (nullifierStatus !== 'verified') {
      setErrorMsg('Wait for spent-status verification to finish (or click Refresh) before swapping.')
      return
    }
    const inMetaCheck = getMeta(activeSwapNote.mintB58)
    const amountIn = parseDecimalToRaw(swapAmountStr, inMetaCheck.decimals)
    if (!amountIn || amountIn <= 0n || amountIn > activeSwapNote.amount) {
      setErrorMsg(
        `Enter an amount up to ${formatUnits(activeSwapNote.amount, inMetaCheck.decimals, inMetaCheck.decimals)} ${inMetaCheck.symbol}.`,
      )
      return
    }
    if (!swapQuoteMatchesAmount || jupiterQuote.quote.inAmount !== amountIn.toString()) {
      setErrorMsg('Refreshing live Jupiter quote for your updated swap parameters…')
      void fetchLiveJupiterQuote()
      return
    }
    const hasChange = amountIn < activeSwapNote.amount
    const changeAmtRaw = activeSwapNote.amount - amountIn

    const useRelayer = feeMode === 'relayer' && pool.relayerAvailable && !!pool.relayerAddress
    const payerPubkey = useRelayer
      ? base58Decode(pool.relayerAddress!)
      : connected.pubkeyBytes
    const swapShardId = jupiterQuote.shardId ?? 0

    // Cap Jupiter swap ring to 64 (2 pages) max so Triptych + optional Bulletproof + Jupiter CPI fits inside Solana's 1.4M CU ceiling
    const swapRingSize: 32 | 64 = ringSize >= 64 ? 64 : 32
    setBusyLabel(useRelayer ? `Fetching live swap route via ${activeRelayerHost}…` : 'Fetching live Jupiter route…')
    try {
      const [ixRes, ringPlan, outputPlan] = await Promise.all([
        useRelayer
          ? fetch(`${relayerUrl}/v1/swap/instructions`, {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({
                cluster: 'mainnet',
                provider: jupiterQuote.provider ?? 'jupiter',
                quoteResponse: jupiterQuote.rawQuote ?? jupiterQuote.quote,
                inputMint: activeSwapNote.mintB58,
                outputMint: swapOutMint,
                shardId: swapShardId,
                includeFee: true,
              }),
            })
          : fetch('/api/jupiter/swap-instructions', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({
                quoteResponse: jupiterQuote.rawQuote ?? jupiterQuote.quote,
                inputMint: activeSwapNote.mintB58,
                outputMint: swapOutMint,
                shardId: swapShardId,
              }),
            }),
        buildMultiPageRingForNote(activeSwapNote, swapRingSize),
        resolveOutputPagePlan(hasChange ? 2 : 1, useRelayer),
      ])
      const ixJson = (await ixRes.json()) as {
        shardId?: number
        escrowPda?: string
        escrowInAta?: string
        escrowOutAta?: string
        vaultOutAta?: string
        tokenProgramIn?: string
        tokenProgramOut?: string
        missingAtas?: Array<{ owner: string; mint: string; tokenProgram: string }>
        swapInstruction?: {
          programId: string
          accounts: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }>
          data: string
        }
        escrowIdx?: number
        escrowInIdx?: number
        escrowOutIdx?: number
        lookupTables?: Record<string, string[]>
        computeUnitLimit?: number
        error?: string
      }
      if (!ixRes.ok || !ixJson.swapInstruction) {
        throw new Error(ixJson.error ?? 'Failed to fetch swap instructions')
      }

      const resolvedEscrowIdx =
        ixJson.escrowIdx ??
        ixJson.swapInstruction.accounts.findIndex((a) => a.pubkey === ixJson.escrowPda)
      const resolvedEscrowInIdx =
        ixJson.escrowInIdx ??
        ixJson.swapInstruction.accounts.findIndex((a) => a.pubkey === ixJson.escrowInAta)
      const resolvedEscrowOutIdx =
        ixJson.escrowOutIdx ??
        ixJson.swapInstruction.accounts.findIndex((a) => a.pubkey === ixJson.escrowOutAta)
      if (resolvedEscrowIdx < 0 || resolvedEscrowInIdx < 0 || resolvedEscrowOutIdx < 0) {
        throw new Error('Router swap instruction did not include Audren swap escrow accounts')
      }

      setBusyLabel('Creating privacy proof in your browser…')
      await new Promise((r) => setTimeout(r, 20))
      const t0 = getPerfNowMs()
      const minAmountOut = BigInt(jupiterQuote.quote.otherAmountThreshold)
      const { instruction, outDesc } = await buildExecViaEscrowInstruction({
        payer: payerPubkey,
        poolId: 0,
        outPageId: outputPlan.outPageId,
        shardId: ixJson.shardId ?? swapShardId,
        inputPageIds: ringPlan.inputPageIds,
        ring: ringPlan.ring,
        inputNote: activeSwapNote,
        secretIndex: ringPlan.secretIndex,
        mintOut: base58Decode(swapOutMint),
        tokenProgramIn: base58Decode(ixJson.tokenProgramIn ?? jupiterQuote.tokenProgramIn),
        tokenProgramOut: base58Decode(ixJson.tokenProgramOut ?? jupiterQuote.tokenProgramOut),
        amountIn,
        minAmountOut,
        recipient: { spendPk: audrenKeys.spendPk, viewPk: audrenKeys.viewPk },
        changeAddr: { spendPk: audrenKeys.spendPk, viewPk: audrenKeys.viewPk },
        targetProgramId: base58Decode(ixJson.swapInstruction.programId),
        targetIxData: fromBase64(ixJson.swapInstruction.data),
        actionAccounts: ixJson.swapInstruction.accounts.map((a) => ({
          pubkey: base58Decode(a.pubkey),
          isSigner: a.isSigner,
          isWritable: a.isWritable,
        })),
        escrowIdx: resolvedEscrowIdx,
        escrowInIdx: resolvedEscrowInIdx,
        escrowOutIdx: resolvedEscrowOutIdx,
        memoText: 'JUP',
      })
      const proverMs = Math.round(getPerfNowMs() - t0)
      const baseSwapCu = Math.max(ixJson.computeUnitLimit ?? 1_100_000, 1_100_000)
      const swapCu = Math.min(
        baseSwapCu + (hasChange ? 220_000 : 0) + (ringPlan.nPages > 1 ? 180_000 : 0),
        1_400_000,
      )
      const effectiveMissingAtas = ixJson.missingAtas ?? jupiterQuote.missingAtas
      const effectiveVaultOutAta = ixJson.vaultOutAta ?? jupiterQuote.vaultOutAta

      const res = await submitProvedInstruction({
        innerIx: instruction,
        mode: useRelayer ? 'relayer' : 'self',
        computeUnitLimit: swapCu,
        setupAtas: effectiveMissingAtas.map((m) => ({
          owner: m.owner,
          mint: m.mint,
          tokenProgram: m.tokenProgram,
        })),
        lookupTables: ixJson.lookupTables,
        vaultOutAta: effectiveVaultOutAta,
        openPageIx: outputPlan.openPageIx,
        rolloverFromPageId: outputPlan.rolloverFromPageId,
      })

      // Only persist VERIFIED on-chain settled output (never fall back to unverified quote!)
      // If RPC receipt is still indexing, refreshPoolAndVault will cryptographically verify via /api/notes/resolve-dynamic.
      const verifiedActualOut =
        res.actualOut && BigInt(res.actualOut) > 0n ? BigInt(res.actualOut) : null
      if (verifiedActualOut !== null) {
        saveKnownDynamicAmount(base58Encode(outDesc.stealthPk), verifiedActualOut)
      }

      const inMeta = getMeta(activeSwapNote.mintB58)
      const outMeta = getMeta(swapOutMint)
      const inDisplay = `${formatUnits(amountIn, inMeta.decimals)} ${inMeta.symbol}`
      const chgDisplay = hasChange ? `${formatUnits(changeAmtRaw, inMeta.decimals)} ${inMeta.symbol}` : null
      const outDisplay =
        verifiedActualOut !== null
          ? `${formatUnits(verifiedActualOut, outMeta.decimals)} ${outMeta.symbol}`
          : `~${formatUnits(BigInt(jupiterQuote.quote.outAmount), outMeta.decimals)} ${outMeta.symbol} (verifying fill)`
      const routeLabels =
        jupiterQuote.quote.routePlan
          ?.map((r) => r.swapInfo?.label)
          .filter(Boolean)
          .join(' → ') || 'Jupiter v6'

      pushAudit({
        action: 'DEX Swap',
        cluster,
        signature: res.signature,
        slot: res.slot,
        solscanUrl: res.solscanUrl,
        explorerUrl: res.explorerUrl,
        txFormat: res.txFormat,
        feePayerMode: useRelayer ? 'relayer' : 'self',
        feePayerAddress: res.feePayerAddress,
        priorityLabel: `${PRIORITY_TIERS[priorityTier].label} (${PRIORITY_TIERS[priorityTier].desc})`,
        proverMs,
        summary: chgDisplay
          ? `Swapped ${inDisplay} → ${outDisplay} privately via DEX aggregator (${routeLabels}); ${chgDisplay} stayed private`
          : `Swapped ${inDisplay} → ${outDisplay} privately via DEX aggregator (${routeLabels})`,
        publicSaw: useRelayer
          ? `Audren’s shared swap account (${shortAddr(jupiterQuote.swapEscrowPda)}) traded ${inDisplay} on ${routeLabels} and swept ${outDisplay} back into the shared pool. The relay pays the network fee. The DEX pair, amounts and output record remain public by design.`
          : `Audren’s shared swap account (${shortAddr(jupiterQuote.swapEscrowPda)}) traded on ${routeLabels} and returned ${outDisplay} straight back into your private balance (your wallet paid the Solana fee in Direct mode).`,
        stayedPrivate: chgDisplay
          ? `The proof conceals the selected input note and blinds the change amount. The change asset and swap output asset and amount are public; recipient ownership uses fresh keys.`
          : `The proof conceals the selected input note. Swap output asset and amount are public; its recipient uses a fresh key. Public details can still support correlation.`,
        sdkCode: `const { instruction } = await buildExecViaEscrowInstruction({
  payer: ${useRelayer ? 'relayerPubkey' : 'walletPubkey'},
  poolId: 0,
  inputNote,
  amountIn: ${amountIn.toString()}n, // ${inDisplay}${chgDisplay ? ` (${chgDisplay} shielded change)` : ''}
  mintOut: '${swapOutMint}',
  minAmountOut: ${minAmountOut.toString()}n,
  targetProgramId: '${ixJson.swapInstruction.programId}',
})`,
      })

      setSwapAmountDraft(null)
      await refreshPoolAndVault(cluster, connected.address, audrenKeys)
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Private DEX swap failed')
    } finally {
      setBusyLabel(null)
    }
  }

  // ============================================================================
  // ACTION 4: WITHDRAW ANYTIME (Private Vault -> Connected Wallet or Fresh Address)
  // ============================================================================
  const handleWithdraw = async () => {
    if (!connected || !audrenKeys || !pool || !activeWithdrawNote) return
    setErrorMsg(null)
    const meta = getMeta(activeWithdrawNote.mintB58)
    const withdrawAmount = parseDecimalToRaw(withdrawAmountStr, meta.decimals)
    if (!withdrawAmount || withdrawAmount > activeWithdrawNote.amount) {
      setErrorMsg(
        `Enter an amount up to ${formatUnits(activeWithdrawNote.amount, meta.decimals, meta.decimals)} ${meta.symbol}.`,
      )
      return
    }

    const destWalletStr = withdrawToSelf
      ? connected.address
      : useDefiSessionDest && defiSessionAddr
        ? defiSessionAddr
        : withdrawDest.trim()
    let destWalletBytes: Uint8Array
    try {
      destWalletBytes = base58Decode(destWalletStr)
      if (destWalletBytes.length !== 32) throw new Error('Invalid destination Solana address')
    } catch {
      setErrorMsg('Enter a valid destination Solana wallet address.')
      return
    }

    const useRelayer = feeMode === 'relayer' && pool.relayerAvailable && !!pool.relayerAddress
    const payerPubkey = useRelayer
      ? base58Decode(pool.relayerAddress!)
      : connected.pubkeyBytes

    if (nullifierStatus !== 'verified') {
      setErrorMsg('Wait for spent-status verification to finish (or click Refresh) before withdrawing.')
      return
    }

    const canUnwrapWsol = activeWithdrawNote.mintB58 === WSOL_MINT_STR
    const doUnwrapWsol = canUnwrapWsol && withdrawUnwrapWsol
    const isPartialInitial = withdrawAmount < activeWithdrawNote.amount
    setBusyLabel('Creating privacy proof in your browser…')
    await new Promise((r) => setTimeout(r, 20))
    try {
      // Optional v0.3.0 self-paying native relay fee quote (gracefully falls back to 0 when sponsored).
      let quotedRelayerFee = 0n
      let quotedFeeRecipient: Uint8Array | undefined
      let needsFeeAtaSetup = false
      if (useRelayer && pool.relayerAddress) {
        try {
          const feeUrl =
            `${relayerUrl}/v1/fee-quote?cluster=${cluster}&op=withdraw` +
            `&mint=${encodeURIComponent(activeWithdrawNote.isNativeSol ? 'native' : activeWithdrawNote.mintB58)}` +
            `&amount=${withdrawAmount.toString()}` +
            `&unwrapWsol=${doUnwrapWsol ? 'true' : 'false'}` +
            `&hasChange=${isPartialInitial ? 'true' : 'false'}`
          const fqRes = await fetch(feeUrl)
          if (fqRes.ok) {
            const fq = (await fqRes.json()) as {
              billingMode?: string
              relayerFee?: string
              feeRecipient?: string | null
              needsFeeAtaSetup?: boolean
            }
            if (
              fq.billingMode === 'self_paying' &&
              fq.relayerFee &&
              /^\d+$/.test(fq.relayerFee) &&
              fq.feeRecipient
            ) {
              const feeRaw = BigInt(fq.relayerFee)
              if (feeRaw > 0n && feeRaw < withdrawAmount) {
                quotedRelayerFee = feeRaw
                quotedFeeRecipient = base58Decode(fq.feeRecipient)
                needsFeeAtaSetup = Boolean(fq.needsFeeAtaSetup)
              }
            }
          }
        } catch {
          // Graceful fallback to sponsored mode if relay does not expose /v1/fee-quote
        }
      }

      // Guarantee `netWithdrawAmount + quotedRelayerFee <= activeWithdrawNote.amount`.
      const netWithdrawAmount =
        withdrawAmount + quotedRelayerFee <= activeWithdrawNote.amount
          ? withdrawAmount
          : withdrawAmount - quotedRelayerFee
      const isPartial = netWithdrawAmount + quotedRelayerFee < activeWithdrawNote.amount

      const [ringPlan, outputPlan] = await Promise.all([
        buildMultiPageRingForNote(activeWithdrawNote, ringSize),
        resolveOutputPagePlan(isPartial ? 1 : 0, useRelayer),
      ])
      const t0 = getPerfNowMs()
      const tokenProgBytes = base58Decode(meta.tokenProgram)
      const extraPreIxs: SolanaInstruction[] = []
      const extraPostIxs: SolanaInstruction[] = []
      const setupAtas: Array<{ owner: string; mint: string; tokenProgram: string }> = []

      let recipientAccount = destWalletBytes
      if (!activeWithdrawNote.isNativeSol && !doUnwrapWsol) {
        const recipientAta = await deriveAta(destWalletBytes, tokenProgBytes, activeWithdrawNote.mint)
        recipientAccount = recipientAta
        if (!useRelayer) {
          extraPreIxs.push(
            buildCreateAtaIdempotentIx({
              payer: connected.pubkeyBytes,
              ata: recipientAta,
              owner: destWalletBytes,
              mint: activeWithdrawNote.mint,
              tokenProgram: tokenProgBytes,
            }),
          )
        } else {
          setupAtas.push({
            owner: destWalletStr,
            mint: activeWithdrawNote.mintB58,
            tokenProgram: meta.tokenProgram,
          })
        }
      }
      if (useRelayer && needsFeeAtaSetup && !activeWithdrawNote.isNativeSol && !doUnwrapWsol && pool.relayerAddress) {
        setupAtas.push({
          owner: pool.relayerAddress,
          mint: activeWithdrawNote.mintB58,
          tokenProgram: meta.tokenProgram,
        })
      }

      const { instruction } = await buildWithdrawInstruction({
        payer: payerPubkey,
        poolId: 0,
        outPageId: outputPlan.outPageId,
        inputPageIds: ringPlan.inputPageIds,
        ring: ringPlan.ring,
        inputNote: activeWithdrawNote,
        secretIndex: ringPlan.secretIndex,
        recipientAccount,
        changeAddr: { spendPk: audrenKeys.spendPk, viewPk: audrenKeys.viewPk },
        amount: netWithdrawAmount,
        relayerFee: quotedRelayerFee,
        feeRecipient: quotedFeeRecipient,
        unwrapWsol: doUnwrapWsol,
        splTokenProgram: activeWithdrawNote.isNativeSol ? undefined : tokenProgBytes,
      })
      const proverMs = Math.round(getPerfNowMs() - t0)
      const withdrawCu = isPartial
        ? ringPlan.nPages === 4
          ? 1_350_000
          : ringPlan.nPages === 2
            ? 950_000
            : 750_000
        : ringPlan.nPages === 4
          ? 1_150_000
          : ringPlan.nPages === 2
            ? 750_000
            : 550_000

      const res = await submitProvedInstruction({
        innerIx: instruction,
        mode: useRelayer ? 'relayer' : 'self',
        computeUnitLimit: withdrawCu,
        extraPreIxs,
        extraPostIxs,
        openPageIx: outputPlan.openPageIx,
        rolloverFromPageId: outputPlan.rolloverFromPageId,
        setupAtas: setupAtas.length > 0 ? setupAtas : undefined,
      })

      const outSymbol = doUnwrapWsol ? 'SOL' : meta.symbol
      const uiDisplay = `${formatUnits(netWithdrawAmount, meta.decimals)} ${outSymbol}`
      pushAudit({
        action: doUnwrapWsol ? 'Withdraw (Unwrap WSOL)' : 'Withdraw',
        cluster,
        signature: res.signature,
        slot: res.slot,
        solscanUrl: res.solscanUrl,
        explorerUrl: res.explorerUrl,
        txFormat: res.txFormat,
        feePayerMode: useRelayer ? 'relayer' : 'self',
        feePayerAddress: res.feePayerAddress,
        priorityLabel: `${PRIORITY_TIERS[priorityTier].label} (${PRIORITY_TIERS[priorityTier].desc})`,
        proverMs,
        summary: doUnwrapWsol
          ? `Unwrapped & withdrew ${uiDisplay} (Native SOL) to ${shortAddr(destWalletStr)}`
          : `Withdrew ${uiDisplay} to ${shortAddr(destWalletStr)}`,
        publicSaw: useRelayer
          ? `Shared Audren Pool sent ${uiDisplay} to ${shortAddr(destWalletStr)}${quotedRelayerFee > 0n ? ` (self-paying relay fee ${formatUnits(quotedRelayerFee, meta.decimals)} ${outSymbol})` : ''}. The destination, token, amount and relay fee payer are public by design.`
          : `Shared Audren Pool sent ${uiDisplay} to ${shortAddr(destWalletStr)}. The destination, token, amount and your wallet as fee payer are public by design.`,
        stayedPrivate: `The proof conceals the selected input note${isPartial ? ` and blinds the change amount` : ''}. Public amounts, timing and candidate composition can still connect activity.`,
        sdkCode: `const { instruction } = await buildWithdrawInstruction({
  payer: ${useRelayer ? 'relayerPubkey' : 'walletPubkey'},
  poolId: 0,
  inputNote,
  recipientAccount: '${destWalletStr}',
  amount: ${netWithdrawAmount.toString()}n, // ${uiDisplay}${quotedRelayerFee > 0n ? `\n  relayerFee: ${quotedRelayerFee.toString()}n,` : ''}${doUnwrapWsol ? `\n  unwrapWsol: true, // atomic WSOL -> Native SOL` : ''}
})`,
      })

      await refreshPoolAndVault(cluster, connected.address, audrenKeys)
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Withdraw failed')
    } finally {
      setBusyLabel(null)
    }
  }

  const publicTotalUsd = useMemo(() => {
    if (!balances) return null
    let total = balances.solUsdValue ?? 0
    let hasAny = balances.solUsdValue !== null && balances.solUsdValue > 0
    for (const tok of balances.tokens) {
      if (tok.usdValue && tok.usdValue > 0) {
        total += tok.usdValue
        hasAny = true
      }
    }
    return hasAny ? total : null
  }, [balances])

  const privateTotalUsd = useMemo(() => {
    let total = 0
    let hasAnyPrice = false
    for (const n of spendableNotes) {
      const m = getMeta(n.mintB58)
      if (m.priceUsd) {
        total += (Number(n.amount) / 10 ** m.decimals) * m.priceUsd
        hasAnyPrice = true
      }
    }
    return hasAnyPrice ? total : null
  }, [spendableNotes, getMeta])

  const privateSolAndTokensLabel = useMemo(() => {
    if (spendableNotes.length === 0) {
      return unresolvedNotes.length > 0
        ? `Verifying ${unresolvedNotes.length} swap fill${unresolvedNotes.length > 1 ? 's' : ''}…`
        : '0 SOL'
    }
    const bySym = new Map<string, { raw: bigint; decimals: number }>()
    for (const n of spendableNotes) {
      const m = getMeta(n.mintB58)
      const prev = bySym.get(m.symbol)
      if (prev) {
        prev.raw += n.amount
      } else {
        bySym.set(m.symbol, { raw: n.amount, decimals: m.decimals })
      }
    }
    const base = Array.from(bySym.entries())
      .slice(0, 3)
      .map(([sym, v]) => `${formatUnits(v.raw, v.decimals)} ${sym}`)
      .join(' + ')
    return unresolvedNotes.length > 0
      ? `${base} (+${unresolvedNotes.length} verifying fill…)`
      : base
  }, [spendableNotes, unresolvedNotes.length, getMeta])

  return (
    <div className="lv-shell">
      {/* ================================================================
          TOP BAR: MAINNET / DEVNET + WALLET STATUS
         ================================================================ */}
      <div className="lv-topbar">
        <div className="lv-cluster-switch" role="group" aria-label="Solana network">
          <button
            type="button"
            className={`lv-cluster-btn ${cluster === 'mainnet' ? 'is-active' : ''}`}
            onClick={() => switchCluster('mainnet')}
          >
            <span className="lv-cluster-dot is-mainnet" />
            MAINNET
          </button>
          <button
            type="button"
            className={`lv-cluster-btn ${cluster === 'devnet' ? 'is-active' : ''}`}
            onClick={() => switchCluster('devnet')}
          >
            <span className="lv-cluster-dot is-devnet" />
            DEVNET
          </button>
        </div>

        <div className="lv-wallet-bar">
          {connected ? (
            <>
              <div className="lv-wallet-pill mono">
                <Wallet size={13} />
                <span>{connected.name}</span>
                <strong>{shortAddr(connected.address)}</strong>
                <a
                  href={solscanAccountUrl(connected.address, cluster)}
                  target="_blank"
                  rel="noreferrer"
                  className="lv-inline-link"
                  title="View your public wallet on Solscan"
                >
                  Solscan <ExternalLink size={11} />
                </a>
              </div>
              <button
                type="button"
                className="lv-mini-btn mono"
                onClick={() => void refreshPoolAndVault(cluster, connected.address, audrenKeys)}
                disabled={loadingState}
              >
                <RefreshCw size={12} className={loadingState ? 'spin' : ''} />
                REFRESH
              </button>
              <button type="button" className="lv-mini-btn mono" onClick={() => void handleDisconnect()}>
                DISCONNECT
              </button>
            </>
          ) : onSwitchToFreeSandbox ? (
            <button type="button" className="lv-mini-btn mono" onClick={onSwitchToFreeSandbox}>
              NO WALLET? TRY FREE DEVNET TEST <ArrowRight size={12} />
            </button>
          ) : null}
        </div>
      </div>

      {/* ================================================================
          STATE 1: NOT CONNECTED — OBVIOUS WALLET CONNECT OR INSTALL VS FREE TEST
         ================================================================ */}
      {!connected && (
        <div className="lv-welcome-shell">
          {reconnectingWallet ? (
            <div className="lv-reconnecting-card">
              <RefreshCw size={16} className="spin" />
              <div>
                <strong>Reconnecting {reconnectingWallet}…</strong>
                <span className="mono">
                  Restoring your wallet session on Solana {cluster === 'mainnet' ? 'Mainnet' : 'Devnet'}
                </span>
              </div>
              <button
                type="button"
                className="lv-mini-btn mono"
                onClick={() => setReconnectingWallet(null)}
              >
                CHOOSE ANOTHER WALLET
              </button>
            </div>
          ) : wallets.length > 0 ? (
            <div className="lv-connect-sheet">
              <div className="lv-connect-copy">
                <span className="kicker mono">
                  SOLANA {cluster === 'mainnet' ? 'MAINNET' : 'DEVNET'} · SELF-CUSTODIAL
                </span>
                <h2>Connect your wallet to open your Private Balance.</h2>
                <p>
                  No new seed phrase and no custody. Deposit a tiny amount of SOL or any token, try
                  a private send or live DEX aggregator swap, and withdraw right back anytime.
                </p>
                <ul className="lv-connect-steps">
                  <li>
                    <span className="lv-step-dot" aria-hidden="true" />
                    <div>
                      <strong>Deposit a supported token from your wallet</strong>
                      <p>Entry token and amount are public by design; spending keys stay in your browser.</p>
                    </div>
                  </li>
                  <li>
                    <span className="lv-step-dot" aria-hidden="true" />
                    <div>
                      <strong>Send privately or swap via compatible DEX aggregators</strong>
                      <p>Inspect every settled transaction on Solscan to see public vs. concealed fields.</p>
                    </div>
                  </li>
                  <li>
                    <span className="lv-step-dot" aria-hidden="true" />
                    <div>
                      <strong>Withdraw anytime</strong>
                      <p>Pull funds back to your own wallet or any fresh Solana address.</p>
                    </div>
                  </li>
                </ul>
              </div>

              <div className="lv-connect-actions">
                <div className="lv-wallet-grid">
                  <span className="lv-label mono">CHOOSE YOUR WALLET</span>
                  {wallets.map((w) => (
                    <button
                      key={w.id}
                      type="button"
                      className="lv-wallet-choice"
                      onClick={() => void handleConnect(w)}
                      disabled={connectingName !== null}
                    >
                      {w.icon ? (
                        <img src={w.icon} alt="" width={28} height={28} className="lv-wallet-icon" />
                      ) : (
                        <Wallet size={22} />
                      )}
                      <div className="lv-wallet-choice-text">
                        <strong>{w.name}</strong>
                        <span className="mono">
                          {connectingName === w.name ? 'WAITING FOR APPROVAL…' : 'CONNECT WALLET'}
                        </span>
                      </div>
                      <ArrowRight size={16} />
                    </button>
                  ))}
                  {onSwitchToFreeSandbox && (
                    <button
                      type="button"
                      className="lv-alt-link mono"
                      onClick={onSwitchToFreeSandbox}
                    >
                      Or try a free Devnet test without connecting <ArrowRight size={12} />
                    </button>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="lv-install-split">
              <div className="lv-install-card">
                <span className="mono" style={{ display: 'inline-block', fontSize: 11, letterSpacing: '0.08em', color: '#55574e', marginBottom: 8 }}>
                  SELF-CUSTODY WALLET
                </span>
                <h2>Connect a Solana wallet extension</h2>
                <p>
                  No Solana wallet was detected in this browser. Install Phantom, Solflare, or
                  Backpack and refresh to connect on Mainnet or Devnet.
                </p>
                <div className="lv-install-links">
                  <a
                    href="https://phantom.com/download"
                    target="_blank"
                    rel="noreferrer"
                    className="lv-install-btn"
                  >
                    <div>
                      <strong>Phantom</strong>
                      <span className="mono">Chrome · Brave · Firefox · Safari</span>
                    </div>
                    <Download size={15} />
                  </a>
                  <a
                    href="https://solflare.com/download"
                    target="_blank"
                    rel="noreferrer"
                    className="lv-install-btn"
                  >
                    <div>
                      <strong>Solflare</strong>
                      <span className="mono">Chrome · Brave · Mobile</span>
                    </div>
                    <Download size={15} />
                  </a>
                  <a
                    href="https://backpack.app/downloads"
                    target="_blank"
                    rel="noreferrer"
                    className="lv-install-btn"
                  >
                    <div>
                      <strong>Backpack</strong>
                      <span className="mono">Chrome · Brave · Mobile</span>
                    </div>
                    <Download size={15} />
                  </a>
                </div>
                <p className="lv-install-note mono">
                  ALREADY INSTALLED? UNLOCK YOUR EXTENSION AND REFRESH THIS PAGE.
                </p>
              </div>

              <div className="lv-install-card is-free">
                <span className="mono" style={{ display: 'inline-block', fontSize: 11, letterSpacing: '0.08em', color: '#184433', marginBottom: 8 }}>
                  INSTANT DEVNET SANDBOX
                </span>
                <h2>Try free on Devnet — no wallet needed</h2>
                <p>
                  Create a temporary key inside this browser tab and receive free Devnet test SOL to
                  inspect real deposits, relayed private transfers, and commitment receipts on
                  Solscan.
                </p>
                <ul className="lv-free-bullets">
                  <li>Zero wallet install &amp; $0 Devnet test SOL</li>
                  <li>Deposit into the shared pool with an AES-256-GCM encrypted memo</li>
                  <li>Run a relayed private transfer with blinded amount &amp; verify a receipt</li>
                </ul>
                {onSwitchToFreeSandbox && (
                  <button
                    type="button"
                    className="btn-pine lv-free-cta"
                    onClick={onSwitchToFreeSandbox}
                  >
                    Start Free Devnet Test <ArrowRight size={15} />
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ================================================================
          CONNECTED WORKSPACE — 2 CLEAN CARDS ABOVE THE FOLD
          LEFT: YOUR BALANCES (PUBLIC vs PRIVATE)  |  RIGHT: 4 SIMPLE ACTIONS
         ================================================================ */}
      {connected && (
        <div className="lv-workspace">
          {/* LEFT CARD: PUBLIC WALLET + PRIVATE BALANCE IN ONE PLACE */}
          <section
            className={`lv-card lv-private-card ${strangerEyes ? 'is-stranger' : ''}`}
            aria-label="Your Public and Private Balances"
          >
            {/* 1. PUBLIC WALLET STRIP (ALWAYS VISIBLE SO YOU KNOW WHAT'S PUBLIC VS PRIVATE) */}
            <div className="lv-pub-strip">
              <div className="lv-pub-strip-top">
                <div>
                  <span className="lv-ledger-kicker mono is-warn">
                    PUBLIC WALLET ({connected.name.toUpperCase()} · VISIBLE ON SOLSCAN)
                  </span>
                  <div className="lv-pub-val">
                    {balances ? (
                      <>
                        <strong>
                          {publicTotalUsd !== null
                            ? formatUsd(publicTotalUsd)
                            : `${balances.solUi.toFixed(4)} SOL`}
                        </strong>
                        <span className="mono">
                          {balances.solUi.toFixed(4)} SOL
                          {balances.tokens.length > 0
                            ? ` + ${balances.tokens.length} token${balances.tokens.length === 1 ? '' : 's'}`
                            : ''}
                        </span>
                      </>
                    ) : (
                      <span className="mono">Loading wallet balances…</span>
                    )}
                  </div>
                </div>

                <div className="lv-pub-strip-actions mono">
                  <button
                    type="button"
                    className="lv-mini-btn mono"
                    onClick={() => setShowPublicDrawer((v) => !v)}
                  >
                    {showPublicDrawer ? 'HIDE TOKENS' : 'TOKENS'}
                    <ChevronDown
                      size={12}
                      style={{
                        transform: showPublicDrawer ? 'rotate(180deg)' : 'none',
                        transition: 'transform 0.14s ease',
                      }}
                    />
                  </button>
                </div>
              </div>

              {showPublicDrawer && (
                <div className="lv-public-drawer-list">
                  {shieldOptions.length > 5 && (
                    <div className="lv-search-input-wrap" style={{ marginBottom: 8 }}>
                      <Search size={14} />
                      <input
                        type="text"
                        className="lv-search-input"
                        placeholder={`Search ${shieldOptions.length} wallet tokens by symbol, name, or mint…`}
                        value={publicDrawerQuery}
                        onChange={(e) => setPublicDrawerQuery(e.target.value)}
                      />
                    </div>
                  )}
                  {filteredPublicDrawerOptions.length === 0 && (
                    <p className="lv-search-empty mono">No matching tokens in wallet.</p>
                  )}
                  {filteredPublicDrawerOptions.slice(0, 60).map((opt) => (
                    <div key={opt.key} className="lv-balance-row is-clickable">
                      <div className="lv-token-id">
                        <TokenAvatar src={opt.logoUrl} symbol={opt.symbol} size={22} />
                        <div>
                          <strong>{opt.symbol}</strong>
                          <span className="mono">
                            {opt.name}
                            {opt.usdValue ? ` · ${formatUsd(opt.usdValue)}` : ''}
                          </span>
                        </div>
                      </div>
                      <div className="lv-row-right">
                        <div className="lv-balance-amt mono">
                          {formatUnits(opt.rawBalance, opt.decimals)} {opt.symbol}
                        </div>
                        <button
                          type="button"
                          className="lv-row-action mono"
                          onClick={() => {
                            startShieldToken(
                              opt.key,
                              opt.symbol,
                              opt.balanceUi,
                              opt.decimals,
                              opt.isSol ? cluster === 'mainnet' : undefined,
                            )
                            setShowPublicDrawer(false)
                          }}
                          disabled={opt.rawBalance <= 0n}
                        >
                          Go Private <ArrowRight size={11} />
                        </button>
                      </div>
                    </div>
                  ))}
                  {filteredPublicDrawerOptions.length > 60 && (
                    <p className="lv-search-empty mono">
                      Showing top 60 of {filteredPublicDrawerOptions.length} matching tokens —
                      refine your search above.
                    </p>
                  )}
                </div>
              )}
            </div>

            {/* 2. PRIVATE BALANCE SECTION (HIDDEN ON SOLSCAN) */}
            <div className="lv-card-head">
              <div>
                <span className="lv-ledger-kicker mono is-ok">
                  {strangerEyes ? (
                    <>
                      <EyeOff size={12} /> WHAT SOLSCAN SEES FOR YOUR PRIVATE BALANCE
                    </>
                  ) : (
                    <>
                      <ShieldCheck size={12} /> YOUR PRIVATE BALANCE (HIDDEN ON SOLSCAN)
                    </>
                  )}
                </span>
                <div className="lv-private-total">
                  {!audrenKeys ? (
                    <strong>Locked</strong>
                  ) : strangerEyes ? (
                    <span className="lv-redacted-bar is-lg" title="Hidden on Solscan" />
                  ) : (
                    <div className="lv-private-total-wrap">
                      <strong>
                        {spendableNotes.length === 0
                          ? unresolvedNotes.length > 0
                            ? 'Verifying fill…'
                            : '$0.00'
                          : privateTotalUsd !== null
                            ? formatUsd(privateTotalUsd) ?? privateSolAndTokensLabel
                            : privateSolAndTokensLabel}
                      </strong>
                      <span className="mono lv-private-sub-amt">
                        {scanProgress
                          ? scanProgress
                          : nullifierStatus === 'error'
                            ? 'Spent-status check failed — click Refresh'
                            : notes.length === 0
                              ? '0 SOL in Private'
                              : privateSolAndTokensLabel}
                      </span>
                    </div>
                  )}
                </div>
              </div>

              <div className="lv-card-head-right">
                {audrenKeys && (
                  <button
                    type="button"
                    className={`lv-eyes-toggle mono ${strangerEyes ? 'is-active' : ''}`}
                    onClick={() => setStrangerEyes((v) => !v)}
                  >
                    {strangerEyes ? <Unlock size={12} /> : <EyeOff size={12} />}
                    {strangerEyes ? 'MY VIEW' : 'STRANGER VIEW'}
                  </button>
                )}
              </div>
            </div>

            {pool?.paused && (
              <div className="lv-notice-bar is-warn mono">
                <strong>POOL PAUSED FOR NEW DEPOSITS / TRANSFERS:</strong> Full 100% withdrawals (
                <strong>Go Public → Max</strong>) bypass the current pool pause. Valid proofs, fees, available assets and token permissions are still required.
              </div>
            )}

            {abandonedBuffers.length > 0 && (
              <div className="lv-notice-bar is-reclaim mono">
                <div>
                  <strong>INTERRUPTED UPLOAD RENT AVAILABLE:</strong>{' '}
                  {(
                    abandonedBuffers.reduce((acc, b) => acc + b.lamports, 0) / 1e9
                  ).toFixed(4)}{' '}
                  SOL locked in {abandonedBuffers.length} temporary ProofBuffer
                  {abandonedBuffers.length === 1 ? '' : 's'}.
                </div>
                <button
                  type="button"
                  className="lv-copy-chip"
                  disabled={busyLabel !== null}
                  onClick={() => void handleReclaimAbandonedBuffers()}
                >
                  <Unlock size={11} /> RECLAIM RENT
                </button>
              </div>
            )}

            {!audrenKeys ? (
              <div ref={unlockRef} className="lv-inline-unlock">
                <p>
                  Sign <strong>one free message</strong> in <strong>{connected.name}</strong> (0 SOL
                  fee, nothing moves) so your browser can show your Private Balance.
                </p>
                <div className="lv-unlock-actions">
                  <button
                    type="button"
                    className="btn-pine"
                    onClick={() => void handleUnlockVault()}
                    disabled={unlocking}
                  >
                    <KeyRound size={15} />
                    {unlocking ? 'Waiting for signature…' : 'Unlock Private Balance'}
                  </button>
                  <button
                    type="button"
                    className="lv-mini-btn mono"
                    onClick={() => setShowVaultTools((v) => !v)}
                  >
                    <Upload size={11} /> RESTORE BACKUP
                  </button>
                </div>
                {showVaultTools && (
                  <div className="lv-backup-box">
                    <p className="mono">
                      Hardware wallet or fresh device? Enter your backup passphrase and pick your
                      encrypted <code>.json</code> backup file to restore without signing a message.
                    </p>
                    <div className="lv-backup-row">
                      <input
                        type="password"
                        className="lv-input mono"
                        placeholder="Backup passphrase…"
                        value={backupPassphrase}
                        onChange={(e) => setBackupPassphrase(e.target.value)}
                      />
                      <label className="lv-mini-btn mono lv-file-label">
                        <Upload size={11} /> IMPORT .JSON
                        <input
                          type="file"
                          accept="application/json,.json"
                          style={{ display: 'none' }}
                          onChange={(e) => {
                            const f = e.target.files?.[0]
                            if (f) void handleImportVaultBackup(f)
                            e.currentTarget.value = ''
                          }}
                        />
                      </label>
                    </div>
                    {backupStatus && <p className="lv-backup-status mono">{backupStatus}</p>}
                  </div>
                )}
              </div>
            ) : notes.length === 0 ? (
              <div className="lv-howto-box">
                <p className="lv-howto-lead">
                  <strong>Your Private Balance is empty right now.</strong> Use{' '}
                  <strong>Go Private</strong> on the right to move a tiny test amount (like{' '}
                  <strong>0.01 SOL</strong>) out of {connected.name} into here.
                </p>
                <ul className="lv-howto-steps">
                  <li>
                    <span className="lv-step-dot" aria-hidden="true" />
                    <div>
                      <strong>Go Private</strong> — move tokens from {connected.name} into your
                      Private Balance.
                    </div>
                  </li>
                  <li>
                    <span className="lv-step-dot" aria-hidden="true" />
                    <div>
                      <strong>Private Send or Private Swap</strong> — send privately or swap via DEX
                      aggregators without unshielding to your wallet.
                    </div>
                  </li>
                  <li>
                    <span className="lv-step-dot" aria-hidden="true" />
                    <div>
                      <strong>Go Public anytime</strong> — move tokens back to {connected.name} or
                      any fresh wallet.
                    </div>
                  </li>
                </ul>
              </div>
            ) : (
              <div className="lv-balance-list">
                {notes.map((note) => {
                  const meta = getMeta(note.mintB58)
                  const isVerifiedSpendable =
                    note.amountResolved && note.amount > 0n && nullifierStatus === 'verified'
                  const displayAmt = note.amountResolved
                    ? `${formatUnits(note.amount, meta.decimals)} ${meta.symbol}`
                    : `Verifying ${meta.symbol} fill…`
                  const uiNum = Number(note.amount) / 10 ** meta.decimals
                  const usdStr =
                    note.amountResolved && meta.priceUsd ? formatUsd(uiNum * meta.priceUsd) : null
                  const canSwap =
                    cluster === 'mainnet' && !note.isNativeSol && isVerifiedSpendable
                  return (
                    <div
                      key={`${note.pageId}-${note.slotIndex}`}
                      className={`lv-private-row ${strangerEyes ? 'is-redacted' : 'is-unlocked'}`}
                    >
                      <div className="lv-private-row-top">
                        <div className="lv-token-id">
                          {strangerEyes ? (
                            <span className="lv-avatar is-locked">
                              <Lock size={13} />
                            </span>
                          ) : (
                            <TokenAvatar src={meta.logoUrl} symbol={meta.symbol} />
                          )}
                          <div>
                            <strong>
                              {strangerEyes ? 'Hidden balance' : meta.symbol}
                              {!strangerEyes && note.memoText ? (
                                <span className="lv-memo-tag mono">{note.memoText}</span>
                              ) : null}
                            </strong>
                            <span className="mono">
                              {strangerEyes
                                ? note.valueBlinding !== 0n
                                  ? 'Blinded token & amount · one-time key · encrypted memo'
                                  : 'One-time key & encrypted memo · entry/swap amount was public on-chain'
                                : !note.amountResolved
                                  ? 'Confirming exact swap settlement on-chain…'
                                  : `${meta.name}${usdStr ? ` · ${usdStr}` : ''}`}
                            </span>
                          </div>
                        </div>

                        {strangerEyes ? (
                          <div
                            className="lv-redacted-bar"
                            title="Unreadable to strangers on Solscan"
                          />
                        ) : (
                          <div className="lv-balance-amt mono is-pine">
                            {displayAmt}
                          </div>
                        )}
                      </div>

                      {!strangerEyes && (
                        <div className="lv-private-row-actions mono">
                          {!note.amountResolved ? (
                            <button
                              type="button"
                              className="lv-row-chip"
                              onClick={() =>
                                void refreshPoolAndVault(cluster, connected.address, audrenKeys)
                              }
                              disabled={loadingState}
                            >
                              <RefreshCw size={11} className={loadingState ? 'spin' : ''} /> Verify
                              Fill Now
                            </button>
                          ) : (
                            <>
                              <button
                                type="button"
                                className="lv-row-chip"
                                disabled={!isVerifiedSpendable}
                                onClick={() => startTransferNote(note)}
                              >
                                <Send size={11} /> Private Send
                              </button>
                              {cluster === 'mainnet' && (
                                <button
                                  type="button"
                                  className={`lv-row-chip ${canSwap ? 'is-primary' : ''}`}
                                  disabled={!isVerifiedSpendable}
                                  onClick={() => startSwapNote(note)}
                                >
                                  <ArrowDownUp size={11} /> Private Swap
                                </button>
                              )}
                              <button
                                type="button"
                                className="lv-row-chip"
                                disabled={!isVerifiedSpendable}
                                onClick={() => startWithdrawNote(note)}
                              >
                                <Unlock size={11} /> Go Public
                              </button>
                              <button
                                type="button"
                                className={`lv-row-chip ${openReceiptKey === `${note.pageId.toString()}:${note.slotIndex}` ? 'is-primary' : ''}`}
                                onClick={() => {
                                  const rk = `${note.pageId.toString()}:${note.slotIndex}`
                                  setOpenReceiptKey((prev) => (prev === rk ? null : rk))
                                }}
                              >
                                <ShieldCheck size={11} /> Receipt
                              </button>
                            </>
                          )}
                        </div>
                      )}

                      {!strangerEyes &&
                        openReceiptKey === `${note.pageId.toString()}:${note.slotIndex}` && (() => {
                          const rk = `${note.pageId.toString()}:${note.slotIndex}`
                          const receipt = buildReceiptForNote(note)
                          const verifyRes = receiptVerifyState[rk]
                          const isChecking = verifyingReceiptKey === rk
                          return (
                            <div className="lv-receipt-drawer">
                              <div className="lv-receipt-head mono">
                                <span>
                                  SELECTIVE DISCLOSURE RECEIPT · PAGE #{note.pageId.toString()} SLOT #
                                  {note.slotIndex}
                                </span>
                                <button
                                  type="button"
                                  className="lv-copy-chip"
                                  onClick={() =>
                                    copyText(`rcpt-${rk}`, JSON.stringify(receipt, null, 2))
                                  }
                                >
                                  {copiedId === `rcpt-${rk}` ? <Check size={11} /> : <Copy size={11} />}
                                  {copiedId === `rcpt-${rk}` ? 'COPIED JSON' : 'COPY RECEIPT JSON'}
                                </button>
                              </div>
                              <p className="lv-receipt-copy">
                                Share this cryptographic proof with an accountant, auditor, or
                                counterparty to prove this single{' '}
                                <strong>
                                  {formatUnits(note.amount, meta.decimals)} {meta.symbol}
                                </strong>{' '}
                                note without exposing your wallet or any other balance.
                              </p>
                              <div className="lv-receipt-grid mono">
                                <span>
                                  COMMITMENT: <code>{shortAddr(receipt.commitment, 8, 6)}</code>
                                </span>
                                <span>
                                  STEALTH BOX: <code>{shortAddr(receipt.stealthPk, 8, 6)}</code>
                                </span>
                              </div>
                              <div className="lv-receipt-actions mono">
                                <button
                                  type="button"
                                  className="lv-row-chip is-primary"
                                  disabled={isChecking}
                                  onClick={() => void handleVerifyNoteReceipt(note, 'real')}
                                >
                                  <ShieldCheck size={11} />{' '}
                                  {isChecking ? 'Verifying…' : 'Verify Real Receipt Against Solana'}
                                </button>
                                <button
                                  type="button"
                                  className="lv-row-chip"
                                  disabled={isChecking}
                                  onClick={() => void handleVerifyNoteReceipt(note, 'forged')}
                                >
                                  Test Tampered Amount (+1)
                                </button>
                              </div>
                              {verifyRes && (
                                <div
                                  className={`lv-receipt-verdict mono ${verifyRes.valid ? 'is-valid' : 'is-forged'}`}
                                >
                                  <strong>
                                    {verifyRes.valid
                                      ? 'VERIFIED BY SOLANA ✓'
                                      : 'FORGERY CAUGHT ✕'}
                                  </strong>{' '}
                                  {verifyRes.reason}
                                </div>
                              )}
                            </div>
                          )
                        })()}
                    </div>
                  )
                })}
              </div>
            )}

            {audrenKeys && !strangerEyes && mergeableGroups.length > 0 && (
              <div className="lv-merge-bar mono">
                <span className="lv-merge-label">
                  <Layers size={12} /> COMBINE SPLIT NOTES INTO ONE:
                </span>
                <div className="lv-merge-chips">
                  {mergeableGroups.map((g) => {
                    const m = getMeta(g.mintB58)
                    return (
                      <button
                        key={g.mintB58}
                        type="button"
                        className="lv-row-chip is-primary"
                        disabled={busyLabel !== null || nullifierStatus !== 'verified'}
                        onClick={() => void handleMergeNotes(g.mintB58)}
                      >
                        <Layers size={11} /> Combine 2 of {g.count} {m.symbol}
                      </button>
                    )
                  })}
                </div>
              </div>
            )}

            {audrenKeys && (
              <>
                <div className="lv-private-foot mono">
                  <div className="lv-addr-row">
                    <span>PRIVATE ADDRESS:</span>
                    <code>{shortAddr(audrenKeys.address, 9, 5)}</code>
                    <button
                      type="button"
                      className="lv-copy-chip"
                      onClick={() => copyText('mailbox', audrenKeys.address)}
                    >
                      {copiedId === 'mailbox' ? <Check size={11} /> : <Copy size={11} />}
                      {copiedId === 'mailbox' ? 'COPIED' : 'COPY'}
                    </button>
                  </div>
                  <div className="lv-addr-row">
                    <button
                      type="button"
                      className="lv-copy-chip"
                      onClick={() => setShowVaultTools((v) => !v)}
                    >
                      <Download size={11} /> {showVaultTools ? 'HIDE BACKUP' : 'BACKUP & SYNC'}
                    </button>
                    {pool?.poolPda && (
                      <a
                        href={solscanAccountUrl(pool.poolPda, cluster)}
                        target="_blank"
                        rel="noreferrer"
                        className="lv-ledger-ext"
                      >
                        POOL ON SOLSCAN <ArrowUpRight size={11} />
                      </a>
                    )}
                  </div>
                </div>

                {showVaultTools && (
                  <div className="lv-backup-box">
                    <div className="lv-backup-meta mono">
                      <span>
                        LANES: <strong>{pool?.activeLanes ?? 1}</strong> · SYNC FLOOR:{' '}
                        <strong>
                          {birthPageIdState !== null ? `Page #${birthPageIdState.toString()}` : 'Page #0 (Full)'}
                        </strong>
                      </span>
                      <button
                        type="button"
                        className="lv-copy-chip"
                        disabled={loadingState}
                        onClick={() => void handleFullRescanFromZero()}
                      >
                        <RefreshCw size={11} className={loadingState ? 'spin' : ''} /> FULL RESCAN FROM PAGE 0
                      </button>
                    </div>
                    <p className="mono">
                      Export a passphrase-encrypted (PBKDF2-SHA256 + AES-256-GCM) backup for cross-device
                      or hardware-wallet recovery, or import an existing backup file.
                    </p>
                    <div className="lv-backup-row">
                      <input
                        type="password"
                        className="lv-input mono"
                        placeholder="Passphrase (min 8 chars)…"
                        value={backupPassphrase}
                        onChange={(e) => setBackupPassphrase(e.target.value)}
                      />
                      <button
                        type="button"
                        className="lv-copy-chip"
                        onClick={() => void handleExportVaultBackup()}
                      >
                        <Download size={11} /> EXPORT .JSON
                      </button>
                      <label className="lv-copy-chip lv-file-label">
                        <Upload size={11} /> IMPORT .JSON
                        <input
                          type="file"
                          accept="application/json,.json"
                          style={{ display: 'none' }}
                          onChange={(e) => {
                            const f = e.target.files?.[0]
                            if (f) void handleImportVaultBackup(f)
                            e.currentTarget.value = ''
                          }}
                        />
                      </label>
                    </div>
                    {backupStatus && <p className="lv-backup-status mono">{backupStatus}</p>}
                  </div>
                )}
              </>
            )}
          </section>

          {/* RIGHT CARD: 4 CLEAR ACTIONS (GO PRIVATE / PRIVATE SEND / PRIVATE SWAP / GO PUBLIC) */}
          <section ref={actionPanelRef} className="lv-card lv-simple-action" aria-label="Private actions">
            <div className="lv-verb-tabs" role="tablist">
              {(
                [
                  { id: 'shield', label: 'Go Private', sub: 'Public → Private' },
                  { id: 'transfer', label: 'Private Send', sub: 'Hidden transfer' },
                  { id: 'swap', label: 'Private Swap', sub: 'DEX Aggregator' },
                  { id: 'withdraw', label: 'Go Public', sub: 'Private → Public' },
                ] as const
              ).map((t) => (
                <button
                  key={t.id}
                  type="button"
                  role="tab"
                  aria-selected={actionTab === t.id}
                  className={`lv-verb-tab ${actionTab === t.id ? 'is-active' : ''}`}
                  onClick={() => {
                    setActionTab(t.id)
                    setDepositPickerOpen(false)
                    setSwapPickerOpen(false)
                    setErrorMsg(null)
                  }}
                >
                  <strong>{t.label}</strong>
                  <span className="mono">{t.sub}</span>
                </button>
              ))}
            </div>

            <div className="lv-simple-body">
              {/* ---- TAB 1: GO PRIVATE (PUBLIC WALLET -> PRIVATE BALANCE) ---- */}
              {actionTab === 'shield' && (
                <>
                    <div className="lv-dir-pill mono">
                      <span>{connected.name.toUpperCase()} (PUBLIC)</span>
                      <ArrowRight size={12} />
                      <strong>
                        {shieldToSelf ? 'YOUR PRIVATE BALANCE' : 'RECIPIENT PRIVATE (aud1…)'}
                      </strong>
                    </div>

                  <div className="lv-field-block">
                      <div className="lv-field-top mono">
                        <span>FROM {connected.name.toUpperCase()}</span>
                        <span>
                          Available:{' '}
                          {balances
                            ? `${formatUnits(selectedShieldOption.rawBalance, selectedShieldOption.decimals)} ${selectedShieldOption.symbol}`
                            : 'Loading…'}
                        </span>
                      </div>

                      {/* Clean searchable token picker — never dumps 38 coins on the page */}
                      <button
                        type="button"
                        className="lv-token-trigger"
                        onClick={() => setDepositPickerOpen((v) => !v)}
                      >
                        <div className="lv-token-id">
                          <TokenAvatar
                            src={selectedShieldOption.logoUrl}
                            symbol={selectedShieldOption.symbol}
                            size={26}
                          />
                          <div>
                            <strong>{selectedShieldOption.symbol}</strong>
                            <span className="mono">
                              {selectedShieldOption.name}
                              {selectedShieldOption.usdValue
                                ? ` · ${formatUsd(selectedShieldOption.usdValue)}`
                                : ''}
                            </span>
                          </div>
                        </div>
                        <span className="mono lv-change-tag">
                          {depositPickerOpen ? 'CLOSE' : `CHANGE (${shieldOptions.length})`}
                        </span>
                      </button>

                      {depositPickerOpen && (
                        <div className="lv-search-box">
                          <div className="lv-search-input-wrap">
                            <Search size={14} />
                            <input
                              type="text"
                              className="lv-search-input"
                              placeholder="Filter tokens in your wallet…"
                              value={depositSearchQuery}
                              onChange={(e) => setDepositSearchQuery(e.target.value)}
                              autoFocus
                            />
                          </div>
                          <div className="lv-search-results">
                            {filteredShieldOptions.length === 0 ? (
                              <p className="lv-search-empty mono">No matching tokens in wallet.</p>
                            ) : (
                              <>
                                {filteredShieldOptions.slice(0, 60).map((opt) => (
                                  <button
                                    key={opt.key}
                                    type="button"
                                    className={`lv-search-item ${shieldAssetKey === opt.key ? 'is-selected' : ''}`}
                                    onClick={() => {
                                      setShieldAssetKey(opt.key)
                                      setShieldAmountStr(
                                        pickStarterAmount(opt.symbol, opt.balanceUi, opt.decimals),
                                      )
                                      setDepositPickerOpen(false)
                                      setDepositSearchQuery('')
                                    }}
                                  >
                                    <div className="lv-token-id">
                                      <TokenAvatar src={opt.logoUrl} symbol={opt.symbol} size={22} />
                                      <div>
                                        <strong>{opt.symbol}</strong>
                                        <span className="mono">{opt.name}</span>
                                      </div>
                                    </div>
                                    <div className="lv-search-meta mono">
                                      {formatUnits(opt.rawBalance, opt.decimals)} {opt.symbol}
                                      {opt.usdValue ? ` · ${formatUsd(opt.usdValue)}` : ''}
                                    </div>
                                  </button>
                                ))}
                                {filteredShieldOptions.length > 60 && (
                                  <p className="lv-search-empty mono">
                                    Showing top 60 of {filteredShieldOptions.length} tokens — type
                                    above to filter any token.
                                  </p>
                                )}
                              </>
                            )}
                          </div>
                        </div>
                      )}
                    </div>

                    <div className="lv-field-block">
                      <label className="lv-label mono" htmlFor="lv-shield-amt">
                        AMOUNT ({selectedShieldOption.symbol})
                      </label>
                      <input
                        id="lv-shield-amt"
                        type="text"
                        inputMode="decimal"
                        className="lv-input lv-amount-big mono"
                        value={shieldAmountStr}
                        onChange={(e) => setShieldAmountStr(e.target.value)}
                      />
                      <div className="lv-quick-pills mono">
                        {selectedShieldOption.isSol
                          ? ['0.005', '0.01', '0.05', '0.1'].map((amt) => (
                              <button
                                key={amt}
                                type="button"
                                className={`lv-quick-pill ${shieldAmountStr === amt ? 'is-active' : ''}`}
                                onClick={() => setShieldAmountStr(amt)}
                              >
                                {amt} SOL
                              </button>
                            ))
                          : [
                              { label: '25%', frac: 0.25 },
                              { label: '50%', frac: 0.5 },
                              { label: '75%', frac: 0.75 },
                              { label: 'Max', frac: 1 },
                            ].map((pct) => {
                              const rawVal =
                                pct.frac === 1
                                  ? selectedShieldOption.rawBalance
                                  : (selectedShieldOption.rawBalance *
                                      BigInt(Math.round(pct.frac * 100))) /
                                    100n
                              const valStr = formatUnits(
                                rawVal,
                                selectedShieldOption.decimals,
                                selectedShieldOption.decimals,
                              ).replace(/,/g, '')
                              return (
                                <button
                                  key={pct.label}
                                  type="button"
                                  className={`lv-quick-pill ${shieldAmountStr === valStr ? 'is-active' : ''}`}
                                  onClick={() => setShieldAmountStr(valStr)}
                                  disabled={rawVal <= 0n}
                                >
                                  {pct.label}
                                </button>
                              )
                            })}
                      </div>
                    </div>

                    <div className="lv-toggle-row">
                      <button
                        type="button"
                        className={`lv-chip-btn ${shieldToSelf ? 'is-active' : ''}`}
                        onClick={() => setShieldToSelf(true)}
                      >
                        To My Private Balance
                      </button>
                      <button
                        type="button"
                        className={`lv-chip-btn ${!shieldToSelf ? 'is-active' : ''}`}
                        onClick={() => setShieldToSelf(false)}
                      >
                        Pay Someone’s aud1…
                      </button>
                    </div>

                    {!shieldToSelf && (
                      <div className="lv-field-block">
                        <label className="lv-label mono" htmlFor="lv-shield-rcpt">
                          RECIPIENT PRIVATE ADDRESS (ZERO ZK PROOFS NEEDED)
                        </label>
                        <input
                          id="lv-shield-rcpt"
                          type="text"
                          className="lv-input mono"
                          placeholder="aud1…"
                          value={shieldRecipient}
                          onChange={(e) => setShieldRecipient(e.target.value)}
                        />
                      </div>
                    )}

                    <p className="lv-plain-summary">
                      {selectedShieldOption.isNonTransferable ? (
                        <>
                          <strong>{selectedShieldOption.symbol} is non-transferable (soulbound)</strong>{' '}
                          and cannot be deposited into a private vault.
                        </>
                      ) : selectedShieldOption.hasActiveTransferHook ? (
                        <>
                          <strong>
                            {selectedShieldOption.symbol} uses a Token-2022 Transfer Hook
                          </strong>{' '}
                          which is not supported for private deposits yet.
                        </>
                      ) : (
                        <>
                          Moves{' '}
                          <strong>
                            {shieldAmountStr || '0'} {selectedShieldOption.symbol}
                          </strong>{' '}
                          from {connected.name}{' '}
                          {shieldToSelf
                            ? 'into your Private Balance on the left.'
                            : 'straight into the recipient’s private stealth balance (their aud1… never appears on Solscan).'}
                          {selectedShieldOption.hasActiveTransferFee &&
                          selectedShieldOption.transferFeeBps > 0
                            ? (() => {
                                const raw = parseDecimalToRaw(
                                  shieldAmountStr,
                                  selectedShieldOption.decimals,
                                )
                                if (!raw) return null
                                const maxFee = BigInt(selectedShieldOption.transferFeeMax)
                                const fee = calculateTransferFee(
                                  raw,
                                  selectedShieldOption.transferFeeBps,
                                  maxFee,
                                )
                                const net = netDepositAmount(
                                  raw,
                                  selectedShieldOption.transferFeeBps,
                                  maxFee,
                                )
                                return (
                                  <>
                                    {' '}
                                    Token-2022 transfer fee:{' '}
                                    <strong>
                                      {formatUnits(fee, selectedShieldOption.decimals)}{' '}
                                      {selectedShieldOption.symbol}
                                    </strong>{' '}
                                    → net private credit:{' '}
                                    <strong>
                                      {formatUnits(net, selectedShieldOption.decimals)}{' '}
                                      {selectedShieldOption.symbol}
                                    </strong>
                                    .
                                  </>
                                )
                              })()
                            : null}{' '}
                          {shieldToSelf
                            ? cluster === 'mainnet'
                              ? 'Once private, you can send privately, swap via DEX aggregators, share receipts, or Go Public anytime.'
                              : 'Once private, you can send privately, share verifiable receipts, or Go Public anytime (switch to Mainnet for live DEX swaps).'
                            : 'Zero ZK proofs needed — works for SOL, any SPL, or any transferable Token-2022 mint.'}
                          {' '}Solana network fee: ~0.00001 SOL.
                        </>
                      )}
                    </p>

                    {shieldToSelf && !audrenKeys ? (
                      <button
                        type="button"
                        className="btn-pine lv-submit-btn"
                        onClick={() => void handleUnlockVault()}
                        disabled={unlocking}
                      >
                        <KeyRound size={15} />
                        {unlocking
                          ? 'Waiting for signature…'
                          : 'Unlock Private Balance First (1 Free Signature)'}
                      </button>
                    ) : (
                      <button
                        type="button"
                        className="btn-pine lv-submit-btn"
                        onClick={() => void handleShield()}
                        disabled={
                          busyLabel !== null ||
                          !pool ||
                          selectedShieldOption.isNonTransferable ||
                          selectedShieldOption.hasActiveTransferHook ||
                          (!shieldToSelf && !shieldRecipient.trim())
                        }
                      >
                        <Shield size={15} />
                        {busyLabel ??
                          (selectedShieldOption.isNonTransferable ||
                          selectedShieldOption.hasActiveTransferHook
                            ? `${selectedShieldOption.symbol} Not Supported`
                            : shieldToSelf
                              ? `Go Private with ${shieldAmountStr || '0'} ${selectedShieldOption.symbol}`
                              : `Send ${shieldAmountStr || '0'} ${selectedShieldOption.symbol} to aud1…`)}
                      </button>
                    )}

                    {/* Optional Advanced Settings — Hidden by Default */}
                    <button
                      type="button"
                      className="lv-adv-toggle mono"
                      onClick={() => setShowAdvanced((v) => !v)}
                    >
                      <span>ADVANCED OPTIONS</span>
                      <ChevronDown
                        size={13}
                        style={{
                          transform: showAdvanced ? 'rotate(180deg)' : 'none',
                          transition: 'transform 0.14s ease',
                        }}
                      />
                    </button>

                    {showAdvanced && (
                      <div className="lv-adv-box">
                        {selectedShieldOption.isSol && cluster === 'mainnet' && (
                          <label className="lv-checkbox-card">
                            <input
                              type="checkbox"
                              checked={shieldWrapSol}
                              onChange={(e) => setShieldWrapSol(e.target.checked)}
                            />
                            <div>
                              <strong>Ready for DEX swaps</strong>
                              <span>
                                Keep checked so this SOL can be swapped via DEX aggregators into
                                USDC or any Solana token right away.
                              </span>
                            </div>
                          </label>
                        )}

                        <div>
                          <label className="lv-label mono" htmlFor="lv-shield-memo">
                            ENCRYPTED MEMO (OPTIONAL · MAX 7 BYTES · AES-256-GCM)
                          </label>
                          <input
                            id="lv-shield-memo"
                            type="text"
                            maxLength={7}
                            className="lv-input mono"
                            value={shieldMemo}
                            onChange={(e) => {
                              const enc = new TextEncoder()
                              let out = ''
                              let used = 0
                              for (const ch of e.target.value.toUpperCase()) {
                                const n = enc.encode(ch).length
                                if (used + n > 7) break
                                out += ch
                                used += n
                              }
                              setShieldMemo(out)
                            }}
                          />
                        </div>

                        <div className="lv-priority-bar">
                          <span className="mono">SOLANA PRIORITY FEE:</span>
                          <div className="lv-priority-btns">
                            {(Object.keys(PRIORITY_TIERS) as PriorityTier[]).map((t) => (
                              <button
                                key={t}
                                type="button"
                                className={`lv-prio-btn mono ${priorityTier === t ? 'is-active' : ''}`}
                                onClick={() => setPriorityTier(t)}
                              >
                                {PRIORITY_TIERS[t].label}
                              </button>
                            ))}
                          </div>
                        </div>
                      </div>
                    )}
                  </>
                )}

                {/* ---- TAB 2: SEND PRIVATELY ---- */}
                {actionTab === 'transfer' && (
                  <>
                    <div className="lv-dir-pill mono">
                      <span>PRIVATE BALANCE</span>
                      <ArrowRight size={12} />
                      <strong>HIDDEN ON SOLSCAN</strong>
                    </div>

                    {!audrenKeys ? (
                      <div className="lv-empty-action">
                        <p>Unlock your Private Balance first to send privately.</p>
                        <button
                          type="button"
                          className="btn-pine"
                          onClick={() => void handleUnlockVault()}
                          disabled={unlocking}
                        >
                          <KeyRound size={14} /> Unlock Private Balance
                        </button>
                      </div>
                    ) : spendableNotes.length === 0 ? (
                      <div className="lv-empty-action">
                        <p>
                          <strong>
                            {unresolvedNotes.length > 0
                              ? 'Your recent swap fill is still being verified on-chain.'
                              : 'You have 0 SOL in your Private Balance right now.'}
                          </strong>{' '}
                          {unresolvedNotes.length > 0
                            ? 'Click Refresh once confirmation settles so your private note unlocks.'
                            : 'Move a tiny amount (like 0.01 SOL) using Go Private first, then you can send it privately here.'}
                        </p>
                        <button
                          type="button"
                          className="btn-pine"
                          onClick={() => setActionTab('shield')}
                        >
                          Go Private First <ArrowRight size={14} />
                        </button>
                      </div>
                    ) : (
                      <>
                        <div className="lv-field-block">
                          <label className="lv-label mono" htmlFor="lv-xfer-note">
                            PRIVATE BALANCE TO SEND
                          </label>
                          <select
                            id="lv-xfer-note"
                            className="lv-select mono"
                            value={selectedNoteIdx}
                            onChange={(e) => {
                              setSelectedNoteIdx(Number(e.target.value))
                              setTransferAmountDraft(null)
                            }}
                          >
                            {spendableNotes.map((n, idx) => {
                              const m = getMeta(n.mintB58)
                              return (
                                <option key={`${n.pageId}-${n.slotIndex}`} value={idx}>
                                  {formatUnits(n.amount, m.decimals)} {m.symbol}
                                  {n.memoText ? ` · ${n.memoText}` : ''}
                                </option>
                              )
                            })}
                          </select>
                        </div>

                        <div className="lv-field-block">
                          <label className="lv-label mono" htmlFor="lv-xfer-amt">
                            AMOUNT
                          </label>
                          <input
                            id="lv-xfer-amt"
                            type="text"
                            inputMode="decimal"
                            className="lv-input lv-amount-big mono"
                            value={transferAmountStr}
                            onChange={(e) => setTransferAmountDraft(e.target.value)}
                          />
                          {activeTransferNote && transferInputMeta && (
                            <>
                              <div className="lv-quick-pills mono">
                                {[
                                  { label: '25%', num: 25n },
                                  { label: '50%', num: 50n },
                                  { label: '75%', num: 75n },
                                  { label: 'Max', num: 100n },
                                ].map((pct) => {
                                  const rawVal =
                                    pct.num === 100n
                                      ? activeTransferNote.amount
                                      : (activeTransferNote.amount * pct.num) / 100n
                                  const str = formatUnits(
                                    rawVal,
                                    transferInputMeta.decimals,
                                    transferInputMeta.decimals,
                                  ).replace(/,/g, '')
                                  return (
                                    <button
                                      key={pct.label}
                                      type="button"
                                      className={`lv-quick-pill ${transferAmountStr === str ? 'is-active' : ''}`}
                                      onClick={() => setTransferAmountDraft(str)}
                                      disabled={rawVal <= 0n}
                                    >
                                      {pct.label}
                                    </button>
                                  )
                                })}
                              </div>
                              {transferChangeRaw > 0n && (
                                <p className="lv-change-hint mono">
                                  Remaining{' '}
                                  {formatUnits(transferChangeRaw, transferInputMeta.decimals)}{' '}
                                  {transferInputMeta.symbol} stays private in your Private Balance.
                                </p>
                              )}
                            </>
                          )}
                        </div>

                        <div className="lv-toggle-row">
                          <button
                            type="button"
                            className={`lv-chip-btn ${transferToSelf ? 'is-active' : ''}`}
                            onClick={() => setTransferToSelf(true)}
                          >
                            Send to Myself (Test Privacy)
                          </button>
                          <button
                            type="button"
                            className={`lv-chip-btn ${!transferToSelf ? 'is-active' : ''}`}
                            onClick={() => setTransferToSelf(false)}
                          >
                            Send to Someone Else
                          </button>
                        </div>

                        {!transferToSelf && (
                          <div className="lv-field-block">
                            <label className="lv-label mono" htmlFor="lv-xfer-rcpt">
                              RECIPIENT PRIVATE ADDRESS
                            </label>
                            <input
                              id="lv-xfer-rcpt"
                              type="text"
                              className="lv-input mono"
                              placeholder="aud1…"
                              value={transferRecipient}
                              onChange={(e) => setTransferRecipient(e.target.value)}
                            />
                          </div>
                        )}

                        <p className="lv-plain-summary">
                          {feeMode === 'relayer' && pool?.relayerAvailable ? (
                            <>
                              Relayed via <strong>{activeRelayerHost}</strong> (
                              {shortAddr(pool.relayerAddress ?? '')}) — your wallet is not the fee
                              payer, the proof conceals the spent note, and the recipient, token,
                              and amount are blinded. Candidate pages, timing, and relay request
                              metadata remain observable.
                            </>
                          ) : (
                            <>
                              Direct Self-Pay mode: the proof conceals the spent note and blinds
                              token and amount, while{' '}
                              <strong>your wallet ({shortAddr(connected.address)}) signs as fee payer on Solscan</strong>
                              . Switch to Privacy Relayer in Advanced Options to use a separate fee payer.
                            </>
                          )}
                        </p>

                        <button
                          type="button"
                          className="btn-pine lv-submit-btn"
                          onClick={() => void handlePrivateTransfer()}
                          disabled={busyLabel !== null || !pool}
                        >
                          <Send size={15} />
                          {busyLabel ??
                            `Send ${transferAmountStr || '0'} ${activeTransferNote ? getMeta(activeTransferNote.mintB58).symbol : ''} Privately`}
                        </button>

                        <button
                          type="button"
                          className="lv-adv-toggle mono"
                          onClick={() => setShowAdvanced((v) => !v)}
                        >
                          <span>ADVANCED OPTIONS</span>
                          <ChevronDown
                            size={13}
                            style={{
                              transform: showAdvanced ? 'rotate(180deg)' : 'none',
                              transition: 'transform 0.14s ease',
                            }}
                          />
                        </button>

                        {showAdvanced && pool && (
                          <div className="lv-adv-box">
                            <div>
                              <label className="lv-label mono" htmlFor="lv-xfer-memo">
                                ENCRYPTED MEMO (MAX 7 BYTES)
                              </label>
                              <input
                                id="lv-xfer-memo"
                                type="text"
                                maxLength={7}
                                className="lv-input mono"
                                value={transferMemo}
                                onChange={(e) => {
                                  const enc = new TextEncoder()
                                  let out = ''
                                  let used = 0
                                  for (const ch of e.target.value.toUpperCase()) {
                                    const n = enc.encode(ch).length
                                    if (used + n > 7) break
                                    out += ch
                                    used += n
                                  }
                                  setTransferMemo(out)
                                }}
                              />
                            </div>
                            <FeeAndRelayerPanel
                              pool={pool}
                              connected={connected}
                              feeMode={feeMode}
                              setFeeMode={setFeeMode}
                              relayerUrl={relayerUrl}
                              relayerUrlError={relayerUrlError}
                              onApplyRelayerUrl={handleApplyRelayerUrl}
                              priorityTier={priorityTier}
                              setPriorityTier={setPriorityTier}
                              ringSize={ringSize}
                              setRingSize={setRingSize}
                              maxRingSize={128}
                            />
                          </div>
                        )}
                      </>
                    )}
                  </>
                )}

                {/* ---- TAB 3: PRIVATE DEX AGGREGATOR SWAP ---- */}
                {actionTab === 'swap' && (
                  <>
                    <div className="lv-dir-pill mono">
                      <span>PRIVATE BALANCE</span>
                      <ArrowRight size={12} />
                      <span>DEX AGGREGATOR</span>
                      <ArrowRight size={12} />
                      <strong>STAYS PRIVATE</strong>
                    </div>

                    {cluster !== 'mainnet' ? (
                      <div className="lv-empty-action">
                        <p>
                          <strong>Live DEX swaps run on Solana Mainnet.</strong> Switch to Mainnet
                          to search any Solana token and swap privately through a DEX aggregator.
                        </p>
                        <button
                          type="button"
                          className="btn-pine"
                          onClick={() => switchCluster('mainnet')}
                        >
                          Switch to Mainnet <ArrowRight size={14} />
                        </button>
                      </div>
                    ) : !audrenKeys ? (
                      <div className="lv-empty-action">
                        <p>Unlock your Private Balance first to swap privately via DEX aggregators.</p>
                        <button
                          type="button"
                          className="btn-pine"
                          onClick={() => void handleUnlockVault()}
                          disabled={unlocking}
                        >
                          <KeyRound size={14} /> Unlock Private Balance
                        </button>
                      </div>
                    ) : swappableNotes.length === 0 ? (
                      <div className="lv-empty-action">
                        <p>
                          <strong>Move a small amount into Private first</strong> (like 0.01 SOL or
                          $1 USDC) — then swap it privately via a DEX aggregator without your
                          wallet appearing on the trade.
                        </p>
                        <div className="lv-starter-picks">
                          <button
                            type="button"
                            className="btn-pine"
                            onClick={() =>
                              startShieldToken('SOL', 'SOL', balances?.solUi ?? 0, 9, true)
                            }
                          >
                            Go Private with SOL to Swap <ArrowRight size={14} />
                          </button>
                          {(balances?.tokens ?? []).slice(0, 2).map((tok) => (
                            <button
                              key={tok.mint}
                              type="button"
                              className="btn-rule"
                              onClick={() =>
                                startShieldToken(tok.mint, tok.symbol, tok.uiAmount, tok.decimals)
                              }
                            >
                              Go Private with {tok.symbol} <ArrowRight size={13} />
                            </button>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <>
                        <div className="lv-field-block">
                          <label className="lv-label mono" htmlFor="lv-swap-note">
                            YOU PAY (FROM PRIVATE BALANCE)
                          </label>
                          <select
                            id="lv-swap-note"
                            className="lv-select mono"
                            value={swapNoteIdx}
                            onChange={(e) => {
                              setSwapNoteIdx(Number(e.target.value))
                              setSwapAmountDraft(null)
                            }}
                          >
                            {swappableNotes.map((n, idx) => {
                              const m = getMeta(n.mintB58)
                              return (
                                <option key={`${n.pageId}-${n.slotIndex}`} value={idx}>
                                  {formatUnits(n.amount, m.decimals)} {m.symbol}
                                  {n.memoText ? ` · ${n.memoText}` : ''}
                                </option>
                              )
                            })}
                          </select>
                        </div>

                        <div className="lv-field-block">
                          <label className="lv-label mono" htmlFor="lv-swap-amt">
                            AMOUNT TO SWAP{swapInputMeta ? ` (${swapInputMeta.symbol})` : ''}
                          </label>
                          <input
                            id="lv-swap-amt"
                            type="text"
                            inputMode="decimal"
                            className="lv-input lv-amount-big mono"
                            value={swapAmountStr}
                            onChange={(e) => setSwapAmountDraft(e.target.value)}
                          />
                          {activeSwapNote && swapInputMeta && (
                            <>
                              <div className="lv-quick-pills mono">
                                {[
                                  { label: '25%', num: 25n },
                                  { label: '50%', num: 50n },
                                  { label: '75%', num: 75n },
                                  { label: 'Max', num: 100n },
                                ].map((pct) => {
                                  const rawVal =
                                    pct.num === 100n
                                      ? activeSwapNote.amount
                                      : (activeSwapNote.amount * pct.num) / 100n
                                  const str = formatUnits(
                                    rawVal,
                                    swapInputMeta.decimals,
                                    swapInputMeta.decimals,
                                  ).replace(/,/g, '')
                                  return (
                                    <button
                                      key={pct.label}
                                      type="button"
                                      className={`lv-quick-pill ${swapAmountStr === str ? 'is-active' : ''}`}
                                      onClick={() => setSwapAmountDraft(str)}
                                      disabled={rawVal <= 0n}
                                    >
                                      {pct.label}
                                    </button>
                                  )
                                })}
                              </div>
                              {swapChangeRaw > 0n && (
                                <p className="lv-change-hint mono">
                                  Remaining {formatUnits(swapChangeRaw, swapInputMeta.decimals)}{' '}
                                  {swapInputMeta.symbol} stays private in your Private Balance.
                                </p>
                              )}
                            </>
                          )}
                        </div>

                        <div className="lv-field-block">
                          <label className="lv-label mono" htmlFor="lv-swap-search">
                            YOU RECEIVE (STAYS PRIVATE)
                          </label>
                          <button
                            type="button"
                            className="lv-token-trigger"
                            onClick={() => setSwapPickerOpen((v) => !v)}
                          >
                            <div className="lv-token-id">
                              <TokenAvatar
                                src={getMeta(swapOutMint).logoUrl}
                                symbol={getMeta(swapOutMint).symbol}
                                size={24}
                              />
                              <div>
                                <strong>{getMeta(swapOutMint).symbol}</strong>
                                <span className="mono">{getMeta(swapOutMint).name}</span>
                              </div>
                            </div>
                            <span className="mono lv-change-tag">
                              {swapPickerOpen ? 'CLOSE' : 'SEARCH TOKENS'}
                            </span>
                          </button>

                          {swapPickerOpen && (
                            <div className="lv-search-box">
                              <div className="lv-search-input-wrap">
                                <Search size={14} />
                                <input
                                  id="lv-swap-search"
                                  type="text"
                                  className="lv-search-input"
                                  placeholder="Search any Solana token or paste mint…"
                                  value={swapSearchQuery}
                                  onChange={(e) => setSwapSearchQuery(e.target.value)}
                                  autoFocus
                                />
                              </div>
                              <div className="lv-search-results">
                                {searchingTokens ? (
                                  <p className="lv-search-empty mono">Searching tokens…</p>
                                ) : swapSearchResults.filter(
                                    (t) => t.mint !== activeSwapNote?.mintB58,
                                  ).length === 0 ? (
                                  <p className="lv-search-empty mono">No matching tokens found.</p>
                                ) : (
                                  swapSearchResults
                                    .filter((t) => t.mint !== activeSwapNote?.mintB58)
                                    .map((tok) => (
                                      <button
                                        key={tok.mint}
                                        type="button"
                                        className={`lv-search-item ${swapOutMint === tok.mint ? 'is-selected' : ''}`}
                                        onClick={() => {
                                          setSwapOutMintChoice(tok.mint)
                                          setSwapPickerOpen(false)
                                        }}
                                      >
                                        <div className="lv-token-id">
                                          <TokenAvatar
                                            src={tok.logoUrl}
                                            symbol={tok.symbol}
                                            size={22}
                                          />
                                          <div>
                                            <strong>
                                              {tok.mint === WSOL_MINT_STR ? 'SOL' : tok.symbol}
                                            </strong>
                                            <span className="mono">{tok.name}</span>
                                          </div>
                                        </div>
                                        <div className="lv-search-meta mono">
                                          {tok.priceUsd
                                            ? formatUsd(tok.priceUsd)
                                            : shortAddr(tok.mint, 4, 4)}
                                        </div>
                                      </button>
                                    ))
                                )}
                              </div>
                            </div>
                          )}
                        </div>

                        {/* Live Mainnet Aggregator Quote (Jupiter adapter in this demo) */}
                        <div className="lv-quote-card">
                          <div className="lv-quote-head mono">
                            <span>LIVE AGGREGATOR QUOTE · JUPITER</span>
                            <button
                              type="button"
                              className="lv-copy-chip"
                              onClick={() => void fetchLiveJupiterQuote()}
                              disabled={quotingSwap || !swapAmountValid}
                            >
                              <RefreshCw size={11} className={quotingSwap ? 'spin' : ''} />
                              REFRESH
                            </button>
                          </div>
                          {swapAmountExceedsNote && activeSwapNote && swapInputMeta ? (
                            <p className="lv-quote-err">
                              Max available in this note is{' '}
                              {formatUnits(
                                activeSwapNote.amount,
                                swapInputMeta.decimals,
                                swapInputMeta.decimals,
                              )}{' '}
                              {swapInputMeta.symbol}.
                            </p>
                          ) : !swapAmountRaw || swapAmountRaw <= 0n ? (
                            <p className="lv-quote-loading mono">
                              Enter an amount to swap to see a live aggregator quote.
                            </p>
                          ) : quotingSwap ? (
                            <p className="lv-quote-loading mono">Getting live aggregator quote…</p>
                          ) : swapQuoteError ? (
                            <p className="lv-quote-err">{swapQuoteError}</p>
                          ) : jupiterQuote && activeSwapNote && swapAmountRaw && swapQuoteMatchesAmount ? (
                            <div className="lv-quote-details">
                              <div className="lv-quote-pair">
                                <strong>
                                  {formatUnits(
                                    swapAmountRaw,
                                    getMeta(activeSwapNote.mintB58).decimals,
                                  )}{' '}
                                  {getMeta(activeSwapNote.mintB58).symbol}
                                </strong>
                                <ArrowRight size={14} />
                                <strong className="is-pine">
                                  {formatUnits(
                                    BigInt(jupiterQuote.quote.outAmount),
                                    getMeta(swapOutMint).decimals,
                                  )}{' '}
                                  {getMeta(swapOutMint).symbol}
                                </strong>
                              </div>
                              <div className="lv-quote-meta mono">
                                <span>
                                  ROUTE:{' '}
                                  {jupiterQuote.quote.routePlan
                                    ?.map((r) => r.swapInfo?.label)
                                    .filter(Boolean)
                                    .join(' → ') || 'Jupiter'}
                                </span>
                                {jupiterQuote.feePlan && feeMode === 'relayer' && (
                                  <span>
                                    RELAY:{' '}
                                    {jupiterQuote.feePlan.platformFeeBps > 0
                                      ? `${(jupiterQuote.feePlan.platformFeeBps / 100).toFixed(2)}% fee (${jupiterQuote.feePlan.billingMode === 'self_paying' ? 'self-paying' : 'subsidized'})`
                                      : 'sponsored (0% fee)'}
                                  </span>
                                )}
                                {jupiterQuote.missingAtas.length > 0 && (
                                  <span className="is-warn">
                                    Includes one-time token account rent (~
                                    {(jupiterQuote.missingAtas.length * 0.00149).toFixed(4)} SOL)
                                  </span>
                                )}
                              </div>
                            </div>
                          ) : (
                            <p className="lv-quote-loading mono">Updating live aggregator quote…</p>
                          )}
                        </div>

                        <p className="lv-plain-summary">
                          {feeMode === 'relayer' && pool?.relayerAvailable ? (
                            <>
                              Relayed via <strong>{activeRelayerHost}</strong> (
                              {shortAddr(pool.relayerAddress ?? '')}) — your wallet is not on the
                              swap transaction and proceeds settle back into a fresh pool note. The
                              DEX pair, routed amounts, and output record remain public on Solscan.
                            </>
                          ) : (
                            <>
                              Direct Self-Pay mode: the swap runs via Audren’s escrow (DEX pair and
                              amounts remain public), and{' '}
                              <strong>your wallet ({shortAddr(connected.address)}) appears as Signer / fee payer on Solscan</strong>
                              . Switch to Privacy Relayer in Advanced Options to use a separate fee payer.
                            </>
                          )}
                        </p>

                        <button
                          type="button"
                          className="btn-pine lv-submit-btn"
                          onClick={() => void handlePrivateSwap()}
                          disabled={
                            busyLabel !== null ||
                            !activeSwapNote ||
                            !swapAmountValid ||
                            !jupiterQuote ||
                            !swapQuoteMatchesAmount ||
                            quotingSwap ||
                            !pool
                          }
                        >
                          <ArrowDownUp size={15} />
                          {busyLabel ??
                            (jupiterQuote && activeSwapNote && swapAmountRaw && swapQuoteMatchesAmount
                              ? `Swap ${formatUnits(swapAmountRaw, getMeta(activeSwapNote.mintB58).decimals)} ${getMeta(activeSwapNote.mintB58).symbol} → ${formatUnits(BigInt(jupiterQuote.quote.outAmount), getMeta(swapOutMint).decimals)} ${getMeta(swapOutMint).symbol}`
                              : quotingSwap
                                ? 'Updating live quote…'
                                : 'Swap Privately via Aggregator')}
                        </button>

                        <button
                          type="button"
                          className="lv-adv-toggle mono"
                          onClick={() => setShowAdvanced((v) => !v)}
                        >
                          <span>ADVANCED OPTIONS (SLIPPAGE {(swapSlippageBps / 100).toFixed(1)}%)</span>
                          <ChevronDown
                            size={13}
                            style={{
                              transform: showAdvanced ? 'rotate(180deg)' : 'none',
                              transition: 'transform 0.14s ease',
                            }}
                          />
                        </button>

                        {showAdvanced && pool && (
                          <div className="lv-adv-box">
                            <div>
                              <label className="lv-label mono" htmlFor="lv-swap-slip">
                                MAX SLIPPAGE
                              </label>
                              <select
                                id="lv-swap-slip"
                                className="lv-select mono"
                                value={swapSlippageBps}
                                onChange={(e) => setSwapSlippageBps(Number(e.target.value))}
                              >
                                <option value={30}>0.3%</option>
                                <option value={50}>0.5%</option>
                                <option value={100}>1.0%</option>
                              </select>
                            </div>
                            <FeeAndRelayerPanel
                              pool={pool}
                              connected={connected}
                              feeMode={feeMode}
                              setFeeMode={setFeeMode}
                              relayerUrl={relayerUrl}
                              relayerUrlError={relayerUrlError}
                              onApplyRelayerUrl={handleApplyRelayerUrl}
                              priorityTier={priorityTier}
                              setPriorityTier={setPriorityTier}
                              ringSize={ringSize}
                              setRingSize={setRingSize}
                              maxRingSize={64}
                            />
                          </div>
                        )}
                      </>
                    )}
                  </>
                )}

                {/* ---- TAB 4: GO PUBLIC (PRIVATE -> PUBLIC WALLET) ---- */}
                {actionTab === 'withdraw' && (
                  <>
                    <div className="lv-dir-pill mono">
                      <span>PRIVATE BALANCE</span>
                      <ArrowRight size={12} />
                      <strong>{withdrawToSelf ? `${connected.name.toUpperCase()} (PUBLIC)` : 'ANY SOLANA WALLET'}</strong>
                    </div>

                    {!audrenKeys ? (
                      <div className="lv-empty-action">
                        <p>Unlock your Private Balance first to move funds back to public.</p>
                        <button
                          type="button"
                          className="btn-pine"
                          onClick={() => void handleUnlockVault()}
                          disabled={unlocking}
                        >
                          <KeyRound size={14} /> Unlock Private Balance
                        </button>
                      </div>
                    ) : spendableNotes.length === 0 ? (
                      <div className="lv-empty-action">
                        <p>
                          <strong>
                            {unresolvedNotes.length > 0
                              ? 'Your recent swap fill is still being verified on-chain.'
                              : 'You have 0 SOL in your Private Balance right now.'}
                          </strong>{' '}
                          {unresolvedNotes.length > 0
                            ? 'Click Refresh once confirmation settles so your private note unlocks.'
                            : `Use Go Private first, and you can move it right back to ${connected.name} (or any fresh wallet) anytime here.`}
                        </p>
                        <button
                          type="button"
                          className="btn-pine"
                          onClick={() => setActionTab('shield')}
                        >
                          Go Private First <ArrowRight size={14} />
                        </button>
                      </div>
                    ) : (
                      <>
                        <div className="lv-field-block">
                          <label className="lv-label mono" htmlFor="lv-wd-note">
                            PRIVATE BALANCE TO WITHDRAW
                          </label>
                          <select
                            id="lv-wd-note"
                            className="lv-select mono"
                            value={withdrawNoteIdx}
                            onChange={(e) => {
                              setWithdrawNoteIdx(Number(e.target.value))
                              setWithdrawAmountDraft(null)
                            }}
                          >
                            {spendableNotes.map((n, idx) => {
                              const m = getMeta(n.mintB58)
                              return (
                                <option key={`${n.pageId}-${n.slotIndex}`} value={idx}>
                                  {formatUnits(n.amount, m.decimals)} {m.symbol}
                                  {n.memoText ? ` · ${n.memoText}` : ''}
                                </option>
                              )
                            })}
                          </select>
                        </div>

                        <div className="lv-field-block">
                          <label className="lv-label mono" htmlFor="lv-wd-amt">
                            AMOUNT
                          </label>
                          <input
                            id="lv-wd-amt"
                            type="text"
                            inputMode="decimal"
                            className="lv-input lv-amount-big mono"
                            value={withdrawAmountStr}
                            onChange={(e) => setWithdrawAmountDraft(e.target.value)}
                          />
                          {activeWithdrawNote && withdrawInputMeta && (
                            <>
                              <div className="lv-quick-pills mono">
                                {[
                                  { label: '25%', num: 25n },
                                  { label: '50%', num: 50n },
                                  { label: '75%', num: 75n },
                                  { label: 'Max', num: 100n },
                                ].map((pct) => {
                                  const rawVal =
                                    pct.num === 100n
                                      ? activeWithdrawNote.amount
                                      : (activeWithdrawNote.amount * pct.num) / 100n
                                  const str = formatUnits(
                                    rawVal,
                                    withdrawInputMeta.decimals,
                                    withdrawInputMeta.decimals,
                                  ).replace(/,/g, '')
                                  return (
                                    <button
                                      key={pct.label}
                                      type="button"
                                      className={`lv-quick-pill ${withdrawAmountStr === str ? 'is-active' : ''}`}
                                      onClick={() => setWithdrawAmountDraft(str)}
                                      disabled={rawVal <= 0n}
                                    >
                                      {pct.label}
                                    </button>
                                  )
                                })}
                              </div>
                              {withdrawChangeRaw > 0n && (
                                <p className="lv-change-hint mono">
                                  Remaining{' '}
                                  {formatUnits(withdrawChangeRaw, withdrawInputMeta.decimals)}{' '}
                                  {withdrawInputMeta.symbol} stays private in your Private Balance.
                                </p>
                              )}
                            </>
                          )}
                        </div>

                        <div className="lv-toggle-row">
                          <button
                            type="button"
                            className={`lv-chip-btn ${withdrawToSelf ? 'is-active' : ''}`}
                            onClick={() => {
                              setWithdrawToSelf(true)
                              setUseDefiSessionDest(false)
                            }}
                          >
                            Back to My {connected.name}
                          </button>
                          <button
                            type="button"
                            className={`lv-chip-btn ${!withdrawToSelf && !useDefiSessionDest ? 'is-active' : ''}`}
                            onClick={() => {
                              setWithdrawToSelf(false)
                              setUseDefiSessionDest(false)
                            }}
                          >
                            Any Fresh Address
                          </button>
                          <button
                            type="button"
                            className={`lv-chip-btn ${!withdrawToSelf && useDefiSessionDest ? 'is-active' : ''}`}
                            onClick={() => {
                              setWithdrawToSelf(false)
                              setUseDefiSessionDest(true)
                            }}
                          >
                            DeFi Session B_{defiSessionIndex}
                          </button>
                        </div>

                        {activeWithdrawNote?.mintB58 === WSOL_MINT_STR && (
                          <div className="lv-toggle-row">
                            <button
                              type="button"
                              className={`lv-chip-btn ${withdrawUnwrapWsol ? 'is-active' : ''}`}
                              onClick={() => setWithdrawUnwrapWsol(true)}
                            >
                              Unwrap WSOL → Native SOL
                            </button>
                            <button
                              type="button"
                              className={`lv-chip-btn ${!withdrawUnwrapWsol ? 'is-active' : ''}`}
                              onClick={() => setWithdrawUnwrapWsol(false)}
                            >
                              Keep as WSOL (SPL)
                            </button>
                          </div>
                        )}

                        {!withdrawToSelf && useDefiSessionDest && (
                          <div className="lv-field-block">
                            <div className="lv-label-row">
                              <span className="lv-label mono">
                                DETERMINISTIC DEFI SESSION WALLET (B_{defiSessionIndex})
                              </span>
                              <div className="lv-toggle-row">
                                <button
                                  type="button"
                                  className="lv-chip-btn"
                                  onClick={() => setDefiSessionIndex((i) => Math.max(0, i - 1))}
                                >
                                  −
                                </button>
                                <button
                                  type="button"
                                  className="lv-chip-btn"
                                  onClick={() => setDefiSessionIndex((i) => i + 1)}
                                >
                                  + Next Session
                                </button>
                              </div>
                            </div>
                            <input
                              type="text"
                              readOnly
                              className="lv-input mono"
                              value={defiSessionAddr ?? 'Deriving session address…'}
                            />
                            <p className="lv-change-hint mono">
                              Derived deterministically from your Audren seed (HKDF-SHA256) with no on-chain link to your main wallet. Note: public DeFi positions opened by this address (collateral size, borrow, liquidation threshold) remain public on Solana.
                            </p>
                          </div>
                        )}

                        {!withdrawToSelf && !useDefiSessionDest && (
                          <div className="lv-field-block">
                            <label className="lv-label mono" htmlFor="lv-wd-dest">
                              DESTINATION SOLANA ADDRESS
                            </label>
                            <input
                              id="lv-wd-dest"
                              type="text"
                              className="lv-input mono"
                              placeholder="Paste any Solana wallet address…"
                              value={withdrawDest}
                              onChange={(e) => setWithdrawDest(e.target.value)}
                            />
                          </div>
                        )}

                        <p className="lv-plain-summary">
                          {feeMode === 'relayer' && pool?.relayerAvailable ? (
                            <>
                              Relayed via <strong>{activeRelayerHost}</strong> (
                              {shortAddr(pool.relayerAddress ?? '')}) — moves funds to a public
                              Solana wallet{' '}
                              <strong>without your wallet signing; the proof conceals the selected input note</strong>.
                            </>
                          ) : (
                            <>
                              Direct Self-Pay mode: the proof conceals the input note, but{' '}
                              <strong>your wallet ({shortAddr(connected.address)}) signs as fee payer on Solscan</strong>
                              . Switch to Privacy Relayer in Advanced Options to use the relay as fee payer instead of your wallet.
                            </>
                          )}
                        </p>

                        <button
                          type="button"
                          className="btn-pine lv-submit-btn"
                          onClick={() => void handleWithdraw()}
                          disabled={busyLabel !== null || !pool}
                        >
                          <Unlock size={15} />
                          {busyLabel ??
                            `Go Public with ${withdrawAmountStr || '0'} ${activeWithdrawNote ? getMeta(activeWithdrawNote.mintB58).symbol : ''}`}
                        </button>

                        <button
                          type="button"
                          className="lv-adv-toggle mono"
                          onClick={() => setShowAdvanced((v) => !v)}
                        >
                          <span>ADVANCED OPTIONS</span>
                          <ChevronDown
                            size={13}
                            style={{
                              transform: showAdvanced ? 'rotate(180deg)' : 'none',
                              transition: 'transform 0.14s ease',
                            }}
                          />
                        </button>

                        {showAdvanced && pool && (
                          <div className="lv-adv-box">
                            <FeeAndRelayerPanel
                              pool={pool}
                              connected={connected}
                              feeMode={feeMode}
                              setFeeMode={setFeeMode}
                              relayerUrl={relayerUrl}
                              relayerUrlError={relayerUrlError}
                              onApplyRelayerUrl={handleApplyRelayerUrl}
                              priorityTier={priorityTier}
                              setPriorityTier={setPriorityTier}
                              ringSize={ringSize}
                              setRingSize={setRingSize}
                              maxRingSize={128}
                            />
                          </div>
                        )}
                      </>
                    )}
                  </>
                )}
              </div>
            </section>
          </div>
      )}

      {/* ================================================================
          ERROR BANNER
         ================================================================ */}
      {errorMsg && (
        <div className="lv-error-bar" role="alert">
          <strong>Error:</strong> {errorMsg}
        </div>
      )}

      {/* ================================================================
          PERSISTENT LIVE TRANSACTIONS FEED — VERIFY EVERY TX ON SOLSCAN
         ================================================================ */}
      {audits.length > 0 && (
        <div ref={historyRef} className="lv-history-section">
          <div className="lv-history-head">
            <span className="kicker mono">YOUR LIVE TRANSACTIONS ({audits.length})</span>
            <h3>Open any transaction on Solscan to verify with your own eyes</h3>
          </div>

          {audits.map((item, idx) => {
            const codeOpen = openSdkSig === item.signature
            return (
              <div key={item.signature} className="lv-audit-card">
                <div className="lv-audit-head">
                  <div>
                    <span className="kicker mono">
                      {item.action.toUpperCase()} · SOLANA {item.cluster.toUpperCase()} · BLOCK #
                      {item.slot.toLocaleString()}
                    </span>
                    <h4>{item.summary}</h4>
                  </div>
                  <div className="lv-audit-links mono">
                    <a href={item.solscanUrl} target="_blank" rel="noreferrer" className="btn-pine">
                      Open on Solscan <ExternalLink size={13} />
                    </a>
                    <a href={item.explorerUrl} target="_blank" rel="noreferrer" className="btn-rule">
                      Solana Explorer <ExternalLink size={13} />
                    </a>
                  </div>
                </div>

                <dl className="lv-audit-facts mono">
                  <div>
                    <dt>FEE PAYER ON SOLSCAN</dt>
                    <dd>
                      {item.feePayerMode === 'relayer'
                        ? `Relayer (${shortAddr(item.feePayerAddress)})`
                        : `Your Wallet (${shortAddr(item.feePayerAddress)})`}
                    </dd>
                  </div>
                  <div>
                    <dt>PRIORITY FEE</dt>
                    <dd>{item.priorityLabel}</dd>
                  </div>
                  <div>
                    <dt>SETTLEMENT</dt>
                    <dd>{item.txFormat}</dd>
                  </div>
                  <div>
                    <dt>PROOF GENERATED IN</dt>
                    <dd>{item.proverMs} ms (in your browser)</dd>
                  </div>
                </dl>

                <div className="lv-audit-compare">
                  <div className="lv-audit-col">
                    <span className="mono">WHAT STRANGERS SEE ON SOLSCAN</span>
                    <p>{item.publicSaw}</p>
                  </div>
                  <div className="lv-audit-col is-private">
                    <span className="mono">WHAT STAYED PRIVATE</span>
                    <p>{item.stayedPrivate}</p>
                  </div>
                </div>

                {item.onChainProof && (
                  <div className="lv-onchain-proof mono">
                    {item.onChainProof.loading ? (
                      <span>Inspecting live transaction on Solana {item.cluster}…</span>
                    ) : item.onChainProof.error ? (
                      <span>Live Solana inspection pending — click Open on Solscan above to inspect.</span>
                    ) : (
                      <>
                        <span className="lv-proof-kicker">LIVE ON-CHAIN VERIFICATION:</span>
                        <span
                          className={`lv-proof-badge ${
                            !item.onChainProof.walletPresent
                              ? 'is-hidden'
                              : !item.onChainProof.walletIsSigner
                                ? 'is-recipient'
                                : 'is-public'
                          }`}
                        >
                          {!item.onChainProof.walletPresent
                            ? `YOUR WALLET ON TX: ABSENT (0 / ${item.onChainProof.totalAccounts ?? 0} accounts)`
                            : !item.onChainProof.walletIsSigner
                              ? `YOUR WALLET ON TX: RECIPIENT ONLY (NOT SIGNER)`
                              : `YOUR WALLET ON TX: SIGNER (FEE PAYER)`}
                        </span>
                        <span>
                          ON-CHAIN SIGNER:{' '}
                          <strong>
                            {shortAddr(item.onChainProof.signers?.[0] ?? item.feePayerAddress)}
                          </strong>
                        </span>
                        <span>
                          SOLANA {item.onChainProof.txVersion?.toUpperCase()}
                          {item.onChainProof.computeUnits
                            ? ` · ${item.onChainProof.computeUnits.toLocaleString()} CU`
                            : ''}
                          {typeof item.onChainProof.feeLamports === 'number'
                            ? ` · ${(item.onChainProof.feeLamports / 1e9).toFixed(6)} SOL fee`
                            : ''}
                        </span>
                      </>
                    )}
                  </div>
                )}

                {/* 1-click guided next steps on the most recent transaction */}
                {idx === 0 && (
                  <div className="lv-audit-next">
                    <span className="mono">WHAT TO TRY NEXT:</span>
                    <div className="lv-audit-next-btns">
                      {item.action === 'Make Private' && (
                        <>
                          <button
                            type="button"
                            className="lv-next-chip mono"
                            onClick={() => {
                              setActionTab('transfer')
                              scrollToActionPanel()
                            }}
                          >
                            <Send size={12} /> Try a Private Transfer <ArrowRight size={11} />
                          </button>
                          {cluster === 'mainnet' && (
                            <button
                              type="button"
                              className="lv-next-chip is-primary mono"
                              onClick={() => {
                                setActionTab('swap')
                                scrollToActionPanel()
                              }}
                            >
                              <ArrowDownUp size={12} /> Swap Privately via Aggregator{' '}
                              <ArrowRight size={11} />
                            </button>
                          )}
                          <button
                            type="button"
                            className="lv-next-chip mono"
                            onClick={() => {
                              setActionTab('withdraw')
                              scrollToActionPanel()
                            }}
                          >
                            <Unlock size={12} /> Withdraw Back to Wallet <ArrowRight size={11} />
                          </button>
                        </>
                      )}
                      {item.action === 'Private Transfer' && (
                        <>
                          {cluster === 'mainnet' && (
                            <button
                              type="button"
                              className="lv-next-chip is-primary mono"
                              onClick={() => {
                                setActionTab('swap')
                                scrollToActionPanel()
                              }}
                            >
                              <ArrowDownUp size={12} /> Now Try: Private DEX Swap{' '}
                              <ArrowRight size={11} />
                            </button>
                          )}
                          <button
                            type="button"
                            className="lv-next-chip mono"
                            onClick={() => {
                              setActionTab('withdraw')
                              scrollToActionPanel()
                            }}
                          >
                            <Unlock size={12} /> Withdraw Anytime <ArrowRight size={11} />
                          </button>
                        </>
                      )}
                      {item.action === 'DEX Swap' && (
                        <>
                          <button
                            type="button"
                            className="lv-next-chip is-primary mono"
                            onClick={() => {
                              setActionTab('withdraw')
                              scrollToActionPanel()
                            }}
                          >
                            <Unlock size={12} /> Withdraw Swapped Tokens <ArrowRight size={11} />
                          </button>
                          <button
                            type="button"
                            className="lv-next-chip mono"
                            onClick={() => {
                              setActionTab('transfer')
                              scrollToActionPanel()
                            }}
                          >
                            <Send size={12} /> Send Swapped Balance Privately{' '}
                            <ArrowRight size={11} />
                          </button>
                        </>
                      )}
                      {item.action === 'Withdraw' && (
                        <button
                          type="button"
                          className="lv-next-chip mono"
                          onClick={() => {
                            setActionTab('shield')
                            scrollToActionPanel()
                          }}
                        >
                          <Shield size={12} /> Make Another Token Private <ArrowRight size={11} />
                        </button>
                      )}
                    </div>
                  </div>
                )}

                <div className="lv-sdk-drawer">
                  <button
                    type="button"
                    className="lv-sdk-toggle mono"
                    onClick={() => setOpenSdkSig(codeOpen ? null : item.signature)}
                  >
                    <Code2 size={14} />
                    {codeOpen ? 'HIDE SDK CODE' : 'VIEW SDK CODE FOR THIS TRANSACTION'}
                  </button>
                  {codeOpen && (
                    <div className="lv-sdk-code-wrap">
                      <button
                        type="button"
                        className="lv-sdk-copy mono"
                        onClick={() => copyText(`sdk-${item.signature}`, item.sdkCode)}
                      >
                        {copiedId === `sdk-${item.signature}` ? <Check size={12} /> : <Copy size={12} />}
                        {copiedId === `sdk-${item.signature}` ? 'COPIED' : 'COPY'}
                      </button>
                      <pre className="mono">
                        <code>{item.sdkCode}</code>
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

function TokenAvatar({
  src,
  symbol,
  size = 28,
}: {
  src: string | null
  symbol: string
  size?: number
}) {
  const [failedSrc, setFailedSrc] = useState<string | null>(null)
  if (src && failedSrc !== src) {
    return (
      <img
        src={src}
        alt={symbol}
        width={size}
        height={size}
        className="lv-avatar"
        style={{ width: size, height: size }}
        onError={() => setFailedSrc(src)}
      />
    )
  }
  const initials = symbol.replace(/[^A-Za-z0-9]/g, '').slice(0, 3).toUpperCase() || '?'
  return (
    <span
      className="lv-avatar is-fallback mono"
      style={{ width: size, height: size, fontSize: Math.max(9, Math.round(size * 0.36)) }}
      aria-hidden="true"
    >
      {initials}
    </span>
  )
}

function FeeAndRelayerPanel({
  pool,
  connected,
  feeMode,
  setFeeMode,
  relayerUrl,
  relayerUrlError,
  onApplyRelayerUrl,
  priorityTier,
  setPriorityTier,
  ringSize,
  setRingSize,
  maxRingSize = 128,
}: {
  pool: PoolResponse
  connected: ConnectedSolanaWallet
  feeMode: FeeMode
  setFeeMode: (m: FeeMode) => void
  relayerUrl: string
  relayerUrlError: string | null
  onApplyRelayerUrl: (raw: string) => Promise<void>
  priorityTier: PriorityTier
  setPriorityTier: (t: PriorityTier) => void
  ringSize: 32 | 64 | 128
  setRingSize: (r: 32 | 64 | 128) => void
  maxRingSize?: 64 | 128
}) {
  const [editingRelay, setEditingRelay] = useState(false)
  const [relayDraft, setRelayDraft] = useState(relayerUrl)
  const host = relayerHostLabel(relayerUrl)
  const pageRentSol = (Number(pool.pageRentFeeLamports || '1400000') / 1e9).toFixed(4)
  const availablePages = Number(BigInt(pool.currentPageId) + 1n)
  return (
    <>
      <div className="lv-fee-title mono">PROOF RING CAPACITY</div>
      <div className="lv-priority-bar">
        <span className="mono">RING WIDTH:</span>
        <div className="lv-priority-btns">
          {([32, 64, 128] as const).map((sz) => {
            const neededPages = sz === 128 ? 4 : sz === 64 ? 2 : 1
            const disabled = sz > maxRingSize || availablePages < neededPages
            return (
              <button
                key={sz}
                type="button"
                disabled={disabled}
                className={`lv-prio-btn mono ${ringSize === sz ? 'is-active' : ''}`}
                onClick={() => setRingSize(sz)}
                title={
                  disabled
                    ? `Requires ${neededPages} pool pages (currently ${availablePages})`
                    : `${sz} proof slots across ${neededPages} page${neededPages > 1 ? 's' : ''}; plausible candidates may be fewer`
                }
              >
                {sz === 32 ? '32 (1 pg)' : sz === 64 ? '64 (2 pg)' : '128 (4 pg)'}
              </button>
            )
          })}
        </div>
      </div>

      <p className="lv-plain-summary">Slots are capacity, not a count of anonymous users. Populated notes, candidate selection and public information determine which inputs remain plausible.</p>
      <div className="lv-fee-title mono">SOLANA NETWORK FEE PAYER</div>

      <div className="lv-mode-cards">
        <button
          type="button"
          className={`lv-mode-card ${feeMode === 'relayer' ? 'is-selected' : ''} ${!pool.relayerAvailable ? 'is-disabled' : ''}`}
          onClick={() => {
            if (pool.relayerAvailable) setFeeMode('relayer')
          }}
        >
          <div className="lv-mode-top mono">
            <strong>Privacy Relayer</strong>
            <span>{pool.relayerAvailable ? `ACTIVE · ${host}` : `OFFLINE · ${host}`}</span>
          </div>
          <p>
            {pool.relayerAvailable
              ? `Relayer (${shortAddr(pool.relayerAddress ?? '')}) pays Solana rent & fees via ${host} so your wallet does not sign as fee payer (the relay still observes request metadata).`
              : `Privacy Relayer (${host}) is unavailable on this cluster — plug in another relayer below or use Direct next door.`}
          </p>
        </button>

        <button
          type="button"
          className={`lv-mode-card ${feeMode === 'self' ? 'is-selected' : ''}`}
          onClick={() => setFeeMode('self')}
        >
          <div className="lv-mode-top mono">
            <strong>Your Wallet (Direct)</strong>
            <span>NO RELAYER</span>
          </div>
          <p>
            Your wallet ({shortAddr(connected.address)}) signs and pays Solana account rent +
            network fee directly. Your token, amount, and private balance stay hidden; Solscan only
            shows your wallet paid the fee.
          </p>
        </button>
      </div>

      <div className="lv-custom-relay mono">
        <div className="lv-custom-relay-head">
          <span>
            RELAY ENDPOINT: <strong>{host}</strong>{' '}
            {relayerUrl !== DEFAULT_RELAY_URL && <em>(custom)</em>}
          </span>
          <button
            type="button"
            className="lv-copy-chip"
            onClick={() => {
              setRelayDraft(relayerUrl)
              setEditingRelay((v) => !v)
            }}
          >
            {editingRelay ? 'CLOSE' : 'USE YOUR OWN RELAY'}
          </button>
        </div>
        {editingRelay && (
          <div className="lv-custom-relay-form">
            <p>
              Audren is relayer-agnostic. Point this UI at your own self-hosted relay URL (implementing{' '}
              <code>/v1/info</code> &amp; <code>/v1/relay/submit</code>) or reset to default.
            </p>
            <div className="lv-backup-row">
              <input
                type="url"
                className="lv-input mono"
                placeholder="https://relay.yourdomain.com"
                value={relayDraft}
                onChange={(e) => setRelayDraft(e.target.value)}
              />
              <button
                type="button"
                className="lv-row-chip is-primary"
                onClick={() => void onApplyRelayerUrl(relayDraft)}
              >
                Apply
              </button>
              {relayerUrl !== DEFAULT_RELAY_URL && (
                <button
                  type="button"
                  className="lv-row-chip"
                  onClick={() => {
                    setRelayDraft(DEFAULT_RELAY_URL)
                    void onApplyRelayerUrl(DEFAULT_RELAY_URL)
                  }}
                >
                  Reset Default
                </button>
              )}
            </div>
            {relayerUrlError && <p className="lv-custom-relay-err">{relayerUrlError}</p>}
          </div>
        )}
      </div>

      <div className="lv-priority-bar">
        <span className="mono">SOLANA PRIORITY FEE:</span>
        <div className="lv-priority-btns">
          {(Object.keys(PRIORITY_TIERS) as PriorityTier[]).map((t) => (
            <button
              key={t}
              type="button"
              className={`lv-prio-btn mono ${priorityTier === t ? 'is-active' : ''}`}
              onClick={() => setPriorityTier(t)}
            >
              {PRIORITY_TIERS[t].label}
            </button>
          ))}
        </div>
      </div>

      <p className="lv-rent-breakdown mono">
        SOLANA COST BREAKDOWN: ~0.00065 SOL permanent 0-byte nullifier rent (anti-double-spend PDA) +{' '}
        {pageRentSol} SOL/output shared page rent + Solana network fee (~0.000005 SOL + priority).
        Temporary ProofBuffer rent (~0.02–0.07 SOL) is 100% refunded atomically upon execution.
      </p>
    </>
  )
}
