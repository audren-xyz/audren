'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertCircle,
  ArrowDownToLine,
  ArrowLeftRight,
  ArrowUpFromLine,
  ArrowUpRight,
  Check,
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
  Upload,
  Wallet,
} from 'lucide-react'
import {
  AUDREN_DEFAULT_RELAY_URL,
  AUDREN_PROGRAM_ID,
  ASSET_MODE_PRIVATE,
  ASSET_MODE_SOL,
  ASSET_MODE_SPL,
  CHECKPOINT_RING_SLOTS,
  CLASSIC_TOKEN_PROGRAM_ID,
  CompactWalletStore,
  MEMO_NOTES_PER_PAGE,
  NATIVE_SOL_MINT_BYTES,
  NUM_ESCROW_SHARDS,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_NULLIFIER,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  SUBROOTS_PER_PAGE,
  SUBTREE_LEAVES,
  SYSTEM_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  WSOL_MINT,
  AudrenRelayClient,
  audrenInstructionToSolana,
  base58Decode,
  base58Encode,
  buildCreateAtaIdempotentInstruction,
  buildDepositSolInstruction,
  buildDepositSplInstruction,
  buildExecViaEscrowInstruction,
  buildJoinsplitInstruction,
  buildOpenPageInstruction,
  buildPublishCheckpointInstruction,
  bytes32ToFrMasked,
  computeExecCtxHash,
  computeJoinsplitCtxHash,
  computePageRollovers,
  computeToken2022NetAmount,
  concatBytes,
  decodePoolState,
  decodeRootCheckpoint,
  deriveAssetId,
  deriveAssociatedTokenAddressSync,
  deriveCheckpointPdaSync,
  deriveDefiSessionKeypair,
  deriveEscrowPdaSync,
  deriveKeysFromSeed,
  deriveMemoPdaSync,
  deriveNfPagePdaSync,
  deriveStealthOwner,
  deriveSubrootPdaSync,
  deriveSubtreePdaSync,
  deriveVaultAuthPdaSync,
  encryptNoteMemo,
  exportFullViewingKey,
  exportSelectiveDisclosureProof,
  frFromBeBytesStrict,
  frToBeBytes,
  fromBase64,
  parseAudrenAddress,
  parseToken2022TransferFeeConfig,
  pickRandomEscrowShard,
  pickRandomLaneId,
  prepareDynamicSwapMemo,
  prepareEscrowAccountsForAudren,
  reconstructWitness,
  syncCompactStoreWithRpc,
  toBase64,
  toHex,
  u32le,
  u64le,
  verifySelectiveDisclosureProof,
  type AccountBatchFetcher,
  type AudrenInstruction,
  type AudrenKeys,
  type MerklePath4Ary,
  type OwnedNote,
  type RelayAggregatorId,
  type RelaySetupAta,
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
  proveJoinsplitInBrowser,
  saveEncryptedCompactStore,
  type AudrenEncryptedBackupFile,
  type JoinSplitInputWitness,
  type JoinSplitOutputWitness,
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
import { AUDREN, shortHash, solscanAddress, solscanTx } from '@/lib/protocol'

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
  tokenProgram?: string
}

interface PoolApiSnapshot {
  initialized?: boolean
  activeLanes?: number
  paused?: boolean
  ckptInterval?: string
  maxCkptAge?: string
  noteRentFee?: string
  deterministicNoteRentFee?: string
  currentSlot?: string
  currentEpoch?: string
  lastPublishedSlot?: string | null
  totalNotes?: string
  totalNullifiers?: string
  solVaultLamports?: number
  lanes?: Array<{ laneId: number; nextLeaf: string; nfCount: string } | null>
  latestCheckpoint?: {
    slotIndex: number
    epochId: string
    publishedSlot: string
    laneCounts: string[]
  } | null
}

interface PoolSummary {
  initialized: boolean
  activeLanes: number
  paused: boolean
  ckptInterval: bigint
  currentSlot: bigint
  currentEpoch: bigint
  lastPublishedSlot: bigint | null
  totalNotes: string
  totalNullifiers: string
  solVaultLamports: number
  latestCheckpointSlot: number | null
  latestCheckpointEpochId: bigint | null
  latestCheckpointLaneCounts: bigint[] | null
}

interface ActionReceipt {
  kind: string
  signature: string
  cluster: SolanaCluster
  proverMs?: number
  relayed: boolean
  summary: string
}

const USDC_MAINNET_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
const RELAY_STORAGE_KEY = 'audren_v2_custom_relay_url'
const NATIVE_SOL_MINT_STR = base58Encode(NATIVE_SOL_MINT_BYTES)

const BASE_TOKEN_META: Record<string, TokenMetaEntry> = {
  [NATIVE_SOL_MINT_STR]: { symbol: 'SOL', decimals: 9 },
  [WSOL_MINT]: { symbol: 'WSOL', decimals: 9, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
  [USDC_MAINNET_MINT]: { symbol: 'USDC', decimals: 6, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
}

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

function buildSystemTransferIx(from: string, to: string, lamports: bigint): AudrenInstruction {
  return {
    programId: SYSTEM_PROGRAM_ID,
    accounts: [
      { pubkey: from, isSigner: true, isWritable: true },
      { pubkey: to, isSigner: false, isWritable: true },
    ],
    data: concatBytes(u32le(2), u64le(lamports)),
  }
}

function buildSyncNativeIx(wsolAta: string): AudrenInstruction {
  return {
    programId: CLASSIC_TOKEN_PROGRAM_ID,
    accounts: [{ pubkey: wsolAta, isSigner: false, isWritable: true }],
    data: new Uint8Array([17]),
  }
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
}> {
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
  const data = json.accounts[0] ? fromBase64(json.accounts[0]) : null
  const decimals = data && data.byteLength >= 45 ? data[44]! : null
  const transferFee = isToken2022 ? parseToken2022TransferFeeConfig(data, currentEpoch) : null
  return {
    tokenProgram: isToken2022 ? TOKEN_2022_PROGRAM_ID : CLASSIC_TOKEN_PROGRAM_ID,
    isToken2022,
    decimals,
    transferFee,
  }
}

function createWorkerBatchFetcher(cluster: SolanaCluster): AccountBatchFetcher {
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

function selectInputNotesForMint(
  primaryNote: OwnedNote,
  allUnspent: readonly OwnedNote[],
  requiredAmount: bigint,
): OwnedNote[] | null {
  if (requiredAmount <= 0n || primaryNote.amount >= requiredAmount) return [primaryNote]
  const targetMint = base58Encode(primaryNote.mint)
  const sameMint = allUnspent.filter((n) => base58Encode(n.mint) === targetMint)
  const othersAsc = sameMint
    .filter((n) => !sameNote(n, primaryNote))
    .sort((a, b) => (a.amount < b.amount ? -1 : a.amount > b.amount ? 1 : 0))

  const deficit = requiredAmount - primaryNote.amount
  const bestPartner = othersAsc.find((n) => n.amount >= deficit)
  if (bestPartner) return [primaryNote, bestPartner]

  const sortedDesc = [...sameMint].sort((a, b) => (a.amount > b.amount ? -1 : a.amount < b.amount ? 1 : 0))
  if (sortedDesc.length >= 2 && sortedDesc[0]!.amount + sortedDesc[1]!.amount >= requiredAmount) {
    return [sortedDesc[0]!, sortedDesc[1]!]
  }
  return null
}

function createZeroDummyOutput(
  assetId: bigint,
  mintBytes: Uint8Array,
): { witness: JoinSplitOutputWitness; memo90: Uint8Array } {
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
    memo90: m.memo90,
  }
}

function checkpointCoversNotes(snap: PoolApiSnapshot, notesToSpend: readonly OwnedNote[]): boolean {
  if (!snap.initialized || !snap.latestCheckpoint) return false
  return notesToSpend.every((n) => {
    const covered = BigInt(snap.latestCheckpoint?.laneCounts[n.laneId] ?? '0')
    return n.leafIndex < covered
  })
}

async function ensureLanePagesPreIxs(params: {
  fetcher: AccountBatchFetcher
  payer: string
  laneId: number
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
    fetcher,
    payer,
    laneId,
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
  const needed: Array<{ kind: number; seq: bigint; addr: string }> = []
  if (includeOutputs) {
    needed.push(
      {
        kind: OPEN_PAGE_KIND_SUBTREE,
        seq: subSeq,
        addr: deriveSubtreePdaSync(0, laneId, subSeq, AUDREN_PROGRAM_ID).address,
      },
      {
        kind: OPEN_PAGE_KIND_SUBROOT,
        seq: rootSeq,
        addr: deriveSubrootPdaSync(0, laneId, rootSeq, AUDREN_PROGRAM_ID).address,
      },
      {
        kind: OPEN_PAGE_KIND_MEMO,
        seq: memoSeq,
        addr: deriveMemoPdaSync(0, laneId, memoSeq, AUDREN_PROGRAM_ID).address,
      },
    )
    if (nextSubSeq != null) {
      needed.push({
        kind: OPEN_PAGE_KIND_SUBTREE,
        seq: nextSubSeq,
        addr: deriveSubtreePdaSync(0, laneId, nextSubSeq, AUDREN_PROGRAM_ID).address,
      })
    }
    if (nextRootSeq != null) {
      needed.push({
        kind: OPEN_PAGE_KIND_SUBROOT,
        seq: nextRootSeq,
        addr: deriveSubrootPdaSync(0, laneId, nextRootSeq, AUDREN_PROGRAM_ID).address,
      })
    }
    if (nextMemoSeq != null) {
      needed.push({
        kind: OPEN_PAGE_KIND_MEMO,
        seq: nextMemoSeq,
        addr: deriveMemoPdaSync(0, laneId, nextMemoSeq, AUDREN_PROGRAM_ID).address,
      })
    }
  }
  needed.push({
    kind: OPEN_PAGE_KIND_NULLIFIER,
    seq: nfSeq,
    addr: deriveNfPagePdaSync(0, laneId, nfSeq, AUDREN_PROGRAM_ID).address,
  })
  if (nextNfSeq != null) {
    needed.push({
      kind: OPEN_PAGE_KIND_NULLIFIER,
      seq: nextNfSeq,
      addr: deriveNfPagePdaSync(0, laneId, nextNfSeq, AUDREN_PROGRAM_ID).address,
    })
  }
  const res = await fetcher(needed.map((p) => p.addr))
  const ixs: AudrenInstruction[] = []
  for (let i = 0; i < needed.length; i++) {
    if (!res[i]) {
      const p = needed[i]!
      ixs.push(buildOpenPageInstruction({ poolId: 0, laneId, pageKind: p.kind, pageSeq: p.seq, payer }))
    }
  }
  return ixs
}

export function LiveWalletVault() {
  const [cluster, setCluster] = useState<SolanaCluster>('devnet')
  const [discovered, setDiscovered] = useState<DiscoveredSolanaWallet[]>([])
  const [connected, setConnected] = useState<ConnectedSolanaWallet | null>(null)
  const [connecting, setConnecting] = useState(false)

  const [unlockSource, setUnlockSource] = useState<UnlockSource>(null)
  const [seedBytes, setSeedBytes] = useState<Uint8Array | null>(null)
  const [keys, setKeys] = useState<AudrenKeys | null>(null)
  const [store, setStore] = useState<CompactWalletStore | null>(null)
  const [unspentNotes, setUnspentNotes] = useState<OwnedNote[]>([])
  const [syncing, setSyncing] = useState(false)
  const [strangerView, setStrangerView] = useState(false)

  const [poolInfo, setPoolInfo] = useState<PoolSummary | null>(null)
  const [pubSolLamports, setPubSolLamports] = useState<bigint>(0n)
  const [pubTokens, setPubTokens] = useState<PublicTokenBalance[]>([])
  const [tokenMeta, setTokenMeta] = useState<Record<string, TokenMetaEntry>>(BASE_TOKEN_META)

  const [tab, setTab] = useState<VaultTab>('deposit')
  const [busy, setBusy] = useState(false)
  const [statusMsg, setStatusMsg] = useState<string | null>(null)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)
  const [lastReceipt, setLastReceipt] = useState<ActionReceipt | null>(null)
  const [copiedField, setCopiedField] = useState<string | null>(null)

  const defaultRelay = process.env.NEXT_PUBLIC_AUDREN_RELAY_URL?.trim() || AUDREN_DEFAULT_RELAY_URL
  const [relayUrl, setRelayUrl] = useState<string>(defaultRelay)
  const [relayDraft, setRelayDraft] = useState<string>(defaultRelay)
  const [showRelayConfig, setShowRelayConfig] = useState(false)
  const [useRelayer, setUseRelayer] = useState(true)
  const [economyMode, setEconomyMode] = useState(false)
  const [relayerCkptFallback, setRelayerCkptFallback] = useState(false)

  const [depositMint, setDepositMint] = useState<string>(NATIVE_SOL_MINT_STR)
  const [depositAmount, setDepositAmount] = useState<string>('0.05')
  const [feeFromAmount, setFeeFromAmount] = useState<boolean>(false)
  const [wrapSolToWsol, setWrapSolToWsol] = useState<boolean>(false)

  const [selectedNoteKey, setSelectedNoteKey] = useState<string>('')
  const [sendRecipient, setSendRecipient] = useState<string>('')
  const [sendAmount, setSendAmount] = useState<string>('')
  const [sendFeePreview, setSendFeePreview] = useState<{
    relayerFee: bigint
    billingMode: 'self_paying' | 'sponsored'
    reason: string
  } | null>(null)

  const [swapOutMint, setSwapOutMint] = useState<string>(USDC_MAINNET_MINT)
  const [swapAmount, setSwapAmount] = useState<string>('')
  const [swapSlippageBps, setSwapSlippageBps] = useState<number>(100)
  const [swapFeeOnOutput, setSwapFeeOnOutput] = useState<boolean>(true)
  const [swapEscrowShard, setSwapEscrowShard] = useState<number | null>(null)
  const [swapQuoteShard, setSwapQuoteShard] = useState<number | null>(null)
  const [swapQuoteNetIn, setSwapQuoteNetIn] = useState<string | null>(null)
  const [swapInputFeeBps, setSwapInputFeeBps] = useState<number>(0)
  const [swapQuoteOut, setSwapQuoteOut] = useState<string | null>(null)
  const [swapQuoteProvider, setSwapQuoteProvider] = useState<RelayAggregatorId | null>(null)
  const [swapQuoteLoading, setSwapQuoteLoading] = useState(false)
  const [swapQuoteRaw, setSwapQuoteRaw] = useState<unknown>(null)

  const [withdrawRecipient, setWithdrawRecipient] = useState<string>('')
  const [withdrawAmount, setWithdrawAmount] = useState<string>('')
  const [unwrapWsol, setUnwrapWsol] = useState<boolean>(true)
  const [withdrawFeePreview, setWithdrawFeePreview] = useState<{
    relayerFee: bigint
    billingMode: 'self_paying' | 'sponsored'
    reason: string
  } | null>(null)

  const [sessionIndex, setSessionIndex] = useState<number>(0)
  const [receiptJson, setReceiptJson] = useState<string>('')
  const [receiptVerdict, setReceiptVerdict] = useState<'valid' | 'invalid' | null>(null)
  const [showFvk, setShowFvk] = useState(false)
  const [backupPassphrase, setBackupPassphrase] = useState('')
  const [backupStatus, setBackupStatus] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement | null>(null)
  const lockedFileInputRef = useRef<HTMLInputElement | null>(null)

  const connectedAddress = connected?.address ?? null
  const walletScope = connectedAddress ?? 'local'

  const getTokenMeta = useCallback(
    (mintStr: string): TokenMetaEntry => {
      const cached = tokenMeta[mintStr]
      if (cached) return cached
      const pub = pubTokens.find((t) => t.mint === mintStr)
      if (pub) {
        return {
          symbol: shortHash(mintStr, 4, 4),
          decimals: pub.decimals,
          tokenProgram: pub.tokenProgram,
        }
      }
      return { symbol: shortHash(mintStr, 4, 4), decimals: 6 }
    },
    [tokenMeta, pubTokens],
  )

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

  // Reset vault session state cleanly if the user switches accounts inside their browser wallet extension
  useEffect(() => {
    if (!connected) return
    const match = discovered.find((d) => d.name === connected.name)
    if (!match) return
    return subscribeWalletStandardAccounts(match, (next) => {
      setConnected((prev) => {
        if (prev && prev.address !== next.address) {
          setKeys(null)
          setSeedBytes(null)
          setUnlockSource(null)
          setStore(null)
          setUnspentNotes([])
          setSelectedNoteKey('')
          setLastReceipt(null)
          setErrorMsg(null)
          setStatusMsg('Wallet account changed. Unlock vault for the active account.')
          setSwapQuoteOut(null)
          setSwapQuoteRaw(null)
          setSwapQuoteProvider(null)
          setWithdrawRecipient(next.address)
        } else if (!prev) {
          setWithdrawRecipient((r) => r || next.address)
        }
        return next
      })
    })
  }, [connected, discovered])

  const copyText = useCallback((label: string, text: string) => {
    if (typeof navigator === 'undefined' || !navigator.clipboard) return
    navigator.clipboard.writeText(text).catch(() => {})
    setCopiedField(label)
    setTimeout(() => setCopiedField((prev) => (prev === label ? null : prev)), 1800)
  }, [])

  const refreshPoolAndBalances = useCallback(
    async (targetCluster: SolanaCluster, ownerAddr: string | null) => {
      try {
        const poolRes = await fetch(`/api/pool?cluster=${targetCluster}&poolId=0`)
        if (poolRes.ok) {
          const pj = (await poolRes.json()) as PoolApiSnapshot
          setPoolInfo({
            initialized: Boolean(pj.initialized),
            activeLanes: pj.activeLanes ?? 4,
            paused: Boolean(pj.paused),
            ckptInterval: BigInt(pj.ckptInterval ?? '50'),
            currentSlot: BigInt(pj.currentSlot ?? '0'),
            currentEpoch: BigInt(pj.currentEpoch ?? '0'),
            lastPublishedSlot: pj.lastPublishedSlot ? BigInt(pj.lastPublishedSlot) : null,
            totalNotes: pj.totalNotes ?? '0',
            totalNullifiers: pj.totalNullifiers ?? '0',
            solVaultLamports: pj.solVaultLamports ?? 0,
            latestCheckpointSlot: pj.latestCheckpoint?.slotIndex ?? null,
            latestCheckpointEpochId: pj.latestCheckpoint ? BigInt(pj.latestCheckpoint.epochId) : null,
            latestCheckpointLaneCounts: pj.latestCheckpoint
              ? pj.latestCheckpoint.laneCounts.map((c) => BigInt(c))
              : null,
          })
        }
      } catch {
        setPoolInfo(null)
      }

      if (!ownerAddr) {
        setPubSolLamports(0n)
        setPubTokens([])
        return
      }
      try {
        const balRes = await fetch(
          `/api/wallet/balances?cluster=${targetCluster}&owner=${encodeURIComponent(ownerAddr)}`,
        )
        if (balRes.ok) {
          const bj = (await balRes.json()) as { solLamports?: string; tokens?: PublicTokenBalance[] }
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

  // Dynamically hydrate token symbols & exact on-chain decimals via /api/tokens/resolve
  const mintsToResolveKey = useMemo(() => {
    const needed = new Set<string>()
    for (const t of pubTokens) {
      if (!tokenMeta[t.mint]) needed.add(t.mint)
    }
    for (const n of unspentNotes) {
      const m = base58Encode(n.mint)
      if (!tokenMeta[m]) needed.add(m)
    }
    if (isValidSolanaPubkey(swapOutMint) && !tokenMeta[swapOutMint]) {
      needed.add(swapOutMint)
    }
    if (depositMint !== NATIVE_SOL_MINT_STR && isValidSolanaPubkey(depositMint) && !tokenMeta[depositMint]) {
      needed.add(depositMint)
    }
    return Array.from(needed).sort().join(',')
  }, [pubTokens, unspentNotes, swapOutMint, depositMint, tokenMeta])

  useEffect(() => {
    if (!mintsToResolveKey) return
    let active = true
    const mints = mintsToResolveKey.split(',').filter(Boolean)
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
                prev[m]!.symbol !== sym ||
                prev[m]!.decimals !== dec ||
                prev[m]!.tokenProgram !== info.tokenProgram
              ) {
                next[m] = { symbol: sym, decimals: dec, tokenProgram: info.tokenProgram }
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
  }, [mintsToResolveKey, cluster])

  const syncVault = useCallback(
    async (
      activeKeys: AudrenKeys,
      targetCluster: SolanaCluster,
      existingStore: CompactWalletStore | null,
      scope: string,
    ) => {
      setSyncing(true)
      setErrorMsg(null)
      try {
        let curStore = existingStore
        if (!curStore) {
          curStore =
            (await loadEncryptedCompactStore(activeKeys, targetCluster, 0, scope)) ??
            new CompactWalletStore(0)
        }
        const fvk = exportFullViewingKey(activeKeys)
        const fetcher = createWorkerBatchFetcher(targetCluster)
        let syncWarning: string | null = null
        try {
          await syncCompactStoreWithRpc({ store: curStore, fvk, fetchBatch: fetcher })
          await saveEncryptedCompactStore(activeKeys, targetCluster, 0, curStore, scope)
        } catch (syncErr) {
          syncWarning = syncErr instanceof Error ? syncErr.message : String(syncErr)
        }
        const unspent = curStore.unspentNotes()
        setStore(curStore)
        setUnspentNotes(unspent)
        if (unspent.length > 0) {
          setSelectedNoteKey((prev) => {
            if (prev && unspent.some((n) => `${n.laneId}:${n.leafIndex.toString()}` === prev)) {
              return prev
            }
            return `${unspent[0]!.laneId}:${unspent[0]!.leafIndex.toString()}`
          })
        } else {
          setSelectedNoteKey('')
        }
        if (syncWarning) {
          setStatusMsg(`Vault ready (RPC sync skipped: ${syncWarning})`)
        } else {
          setStatusMsg(
            `Synced ${unspent.length} unspent shielded ${unspent.length === 1 ? 'note' : 'notes'} on ${targetCluster} via ordinary RPC`,
          )
        }
      } finally {
        setSyncing(false)
      }
    },
    [],
  )

  const handleClusterSwitch = (nextCluster: SolanaCluster) => {
    if (nextCluster === cluster) return
    setCluster(nextCluster)
    setStore(null)
    setUnspentNotes([])
    setSelectedNoteKey('')
    setLastReceipt(null)
    setErrorMsg(null)
    setStatusMsg(null)
    setSwapQuoteOut(null)
    setSwapQuoteRaw(null)
    setSwapQuoteProvider(null)
    setSwapQuoteShard(null)
    setSwapQuoteNetIn(null)
    setSwapInputFeeBps(0)
    setSwapEscrowShard(pickRandomEscrowShard(NUM_ESCROW_SHARDS))
    setSendFeePreview(null)
    setWithdrawFeePreview(null)
    setRelayerCkptFallback(false)
    setReceiptJson('')
    setReceiptVerdict(null)
    setPubSolLamports(0n)
    setPubTokens([])
    setDepositMint(NATIVE_SOL_MINT_STR)
    if (unlockSource === 'wallet') {
      // Wallet-derived keys bind the cluster name in signMessage; require explicit unlock on the new cluster
      setKeys(null)
      setSeedBytes(null)
      setUnlockSource(null)
    } else if (keys) {
      void syncVault(keys, nextCluster, null, walletScope)
    }
  }

  const handleConnectWallet = async (wallet: DiscoveredSolanaWallet) => {
    setConnecting(true)
    setErrorMsg(null)
    try {
      const conn = await connectSolanaWallet(wallet)
      setConnected(conn)
      setWithdrawRecipient((prev) => prev || conn.address)
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setConnecting(false)
    }
  }

  const handleDisconnect = async () => {
    if (connected) await disconnectSolanaWallet(connected)
    setConnected(null)
    setSeedBytes(null)
    setKeys(null)
    setUnlockSource(null)
    setStore(null)
    setUnspentNotes([])
    setSelectedNoteKey('')
    setLastReceipt(null)
    setStatusMsg(null)
    setErrorMsg(null)
    setPubSolLamports(0n)
    setPubTokens([])
  }

  const unlockFromSeed = useCallback(
    async (
      seed: Uint8Array,
      targetCluster: SolanaCluster,
      source: UnlockSource,
      scope: string,
    ) => {
      const derived = deriveKeysFromSeed(seed)
      setSeedBytes(seed)
      setKeys(derived)
      setUnlockSource(source)
      await syncVault(derived, targetCluster, null, scope)
    },
    [syncVault],
  )

  const handleUnlockWithWalletSignature = async () => {
    if (!connected) return
    setBusy(true)
    setErrorMsg(null)
    try {
      const msg = `Audren Vault Key Derivation\nCluster: ${cluster}\nWallet: ${connected.address}`
      const sig = await signUtf8MessageWithWallet(connected, msg)
      const buf = new ArrayBuffer(sig.byteLength)
      new Uint8Array(buf).set(sig)
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', buf))
      await unlockFromSeed(digest, cluster, 'wallet', connected.address)
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const handleCreateLocalVault = async () => {
    setBusy(true)
    setErrorMsg(null)
    try {
      const freshSeed = crypto.getRandomValues(new Uint8Array(32))
      await unlockFromSeed(freshSeed, cluster, 'local', walletScope)
      setStatusMsg('Ephemeral local Audren vault created. Export an encrypted backup before closing.')
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const selectedNote = useMemo(() => {
    return (
      unspentNotes.find((n) => `${n.laneId}:${n.leafIndex.toString()}` === selectedNoteKey) ??
      unspentNotes[0] ??
      null
    )
  }, [selectedNoteKey, unspentNotes])

  const selectedNoteMintStr = useMemo(
    () => (selectedNote ? base58Encode(selectedNote.mint) : WSOL_MINT),
    [selectedNote],
  )

  const selectedNoteMeta = useMemo(
    () => getTokenMeta(selectedNoteMintStr),
    [getTokenMeta, selectedNoteMintStr],
  )

  const swapOutMeta = useMemo(
    () => getTokenMeta(swapOutMint),
    [getTokenMeta, swapOutMint],
  )

  const isSelectedNoteNativeSol = selectedNote !== null && selectedNoteMintStr === NATIVE_SOL_MINT_STR

  // Detect whether any unspent note is newer than the latest unexpired RootCheckpoint
  const noteNeedsCheckpoint = useMemo(() => {
    if (!poolInfo?.initialized) return false
    if (poolInfo.latestCheckpointSlot === null || !poolInfo.latestCheckpointLaneCounts) {
      return unspentNotes.length > 0
    }
    return unspentNotes.some((n) => {
      const laneCount = poolInfo.latestCheckpointLaneCounts?.[n.laneId] ?? 0n
      return n.leafIndex >= laneCount
    })
  }, [poolInfo, unspentNotes])

  const slotsUntilNextCheckpoint = useMemo(() => {
    if (!poolInfo?.initialized || poolInfo.ckptInterval <= 0n) return 0n
    const curEpoch = poolInfo.currentSlot / poolInfo.ckptInterval
    if (poolInfo.latestCheckpointEpochId !== null && curEpoch <= poolInfo.latestCheckpointEpochId) {
      const nextEpochSlot = (curEpoch + 1n) * poolInfo.ckptInterval
      return nextEpochSlot > poolInfo.currentSlot ? nextEpochSlot - poolInfo.currentSlot : 0n
    }
    return 0n
  }, [poolInfo])

  // Live swap quote effect: strictly primitive dependencies, cryptographically random escrowShard independent of leafIndex.
  const selectedNoteDecimals = selectedNoteMeta.decimals

  const sameMintNotesDesc = useMemo(() => {
    if (!selectedNote) return []
    return unspentNotes
      .filter((n) => base58Encode(n.mint) === selectedNoteMintStr)
      .sort((a, b) => (a.amount > b.amount ? -1 : a.amount < b.amount ? 1 : 0))
  }, [selectedNote, selectedNoteMintStr, unspentNotes])

  const maxSpendableNotePair = useMemo(() => {
    if (!selectedNote) return 0n
    if (sameMintNotesDesc.length >= 2) {
      return sameMintNotesDesc[0]!.amount + sameMintNotesDesc[1]!.amount
    }
    return selectedNote.amount
  }, [selectedNote, sameMintNotesDesc])

  const plannedSendNotes = useMemo(() => {
    if (!selectedNote) return null
    const amt = parseUnits(sendAmount, selectedNoteDecimals) ?? 0n
    const fee = useRelayer && sendFeePreview ? sendFeePreview.relayerFee : 0n
    return selectInputNotesForMint(selectedNote, unspentNotes, amt + fee)
  }, [selectedNote, sendAmount, selectedNoteDecimals, useRelayer, sendFeePreview, unspentNotes])

  const plannedWithdrawNotes = useMemo(() => {
    if (!selectedNote) return null
    const amt = parseUnits(withdrawAmount, selectedNoteDecimals) ?? 0n
    const fee = useRelayer && withdrawFeePreview ? withdrawFeePreview.relayerFee : 0n
    return selectInputNotesForMint(selectedNote, unspentNotes, amt + fee)
  }, [selectedNote, withdrawAmount, selectedNoteDecimals, useRelayer, withdrawFeePreview, unspentNotes])

  const plannedSwapNotes = useMemo(() => {
    if (!selectedNote) return null
    const amt = parseUnits(swapAmount, selectedNoteDecimals) ?? 0n
    return selectInputNotesForMint(selectedNote, unspentNotes, amt)
  }, [selectedNote, swapAmount, selectedNoteDecimals, unspentNotes])

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
    ) => {
      if (inMint === NATIVE_SOL_MINT_STR || !isValidSolanaPubkey(outMint)) {
        setSwapQuoteOut(null)
        setSwapQuoteRaw(null)
        setSwapQuoteProvider(null)
        setSwapQuoteShard(null)
        setSwapQuoteNetIn(null)
        setSwapInputFeeBps(0)
        return
      }
      const rawAmt = parseUnits(amountStr, inDecimals)
      if (!rawAmt || rawAmt <= 0n || inMint === outMint) {
        setSwapQuoteOut(null)
        setSwapQuoteRaw(null)
        setSwapQuoteProvider(null)
        setSwapQuoteShard(null)
        setSwapQuoteNetIn(null)
        setSwapInputFeeBps(0)
        return
      }
      setSwapQuoteLoading(true)
      try {
        if (relayed) {
          const client = new AudrenRelayClient(activeRelay)
          const resp = (await client.quoteSwap({
            cluster: targetCluster,
            inputMint: inMint,
            outputMint: outMint,
            amount: rawAmt.toString(),
            slippageBps: slippage,
            shardId,
            provider: 'auto',
            includeFee: false,
          })) as {
            provider?: string
            quote?: { provider?: string; outAmount?: string; rawQuote?: unknown }
            outAmount?: string
            netInputAmount?: string
            inputTransferFeeBps?: number
          }
          const outAmt =
            typeof resp.quote?.outAmount === 'string'
              ? resp.quote.outAmount
              : typeof resp.outAmount === 'string'
                ? resp.outAmount
                : null
          setSwapQuoteOut(outAmt)
          setSwapQuoteProvider(parseAggregatorId(resp.provider ?? resp.quote?.provider))
          setSwapQuoteRaw(resp.quote?.rawQuote ?? resp)
          setSwapQuoteShard(shardId)
          setSwapQuoteNetIn(typeof resp.netInputAmount === 'string' ? resp.netInputAmount : rawAmt.toString())
          setSwapInputFeeBps(typeof resp.inputTransferFeeBps === 'number' ? resp.inputTransferFeeBps : 0)
        } else {
          const res = await fetch('/api/jupiter/quote', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              cluster: targetCluster,
              inputMint: inMint,
              outputMint: outMint,
              amount: rawAmt.toString(),
              slippageBps: slippage,
            }),
          })
          const netInHeader = res.headers.get('x-audren-net-input-amount')
          const feeBpsHeader = res.headers.get('x-audren-input-transfer-fee-bps')
          const quote = (await res.json()) as Record<string, unknown>
          if (!res.ok) throw new Error(String(quote.error ?? `Quote HTTP ${res.status}`))
          const outAmt = typeof quote.outAmount === 'string' ? quote.outAmount : null
          setSwapQuoteOut(outAmt)
          setSwapQuoteProvider('jupiter')
          setSwapQuoteRaw(quote)
          setSwapQuoteShard(shardId)
          setSwapQuoteNetIn(netInHeader ?? (typeof quote.inAmount === 'string' ? quote.inAmount : rawAmt.toString()))
          setSwapInputFeeBps(feeBpsHeader ? Number(feeBpsHeader) || 0 : 0)
        }
      } catch {
        setSwapQuoteOut(null)
        setSwapQuoteRaw(null)
        setSwapQuoteProvider(null)
        setSwapQuoteShard(null)
        setSwapQuoteNetIn(null)
        setSwapInputFeeBps(0)
      } finally {
        setSwapQuoteLoading(false)
      }
    },
    [],
  )

  useEffect(() => {
    if (tab !== 'swap' || !swapAmount.trim() || isSelectedNoteNativeSol || swapEscrowShard === null) return
    const timer = setTimeout(() => {
      void fetchSwapQuote(
        selectedNoteMintStr,
        selectedNoteDecimals,
        swapOutMint,
        swapAmount,
        swapSlippageBps,
        cluster,
        relayUrl,
        useRelayer,
        swapEscrowShard,
      )
    }, 350)
    return () => clearTimeout(timer)
  }, [
    tab,
    selectedNoteMintStr,
    selectedNoteDecimals,
    swapOutMint,
    swapAmount,
    swapSlippageBps,
    cluster,
    relayUrl,
    useRelayer,
    swapEscrowShard,
    isSelectedNoteNativeSol,
    fetchSwapQuote,
  ])

  // Live relayer fee preview for Send (zero amount leaked!) & Withdraw (primitive dependencies only!)
  const selectedNoteAmountStr = selectedNote ? selectedNote.amount.toString() : ''
  const plannedSendInputCount = plannedSendNotes ? plannedSendNotes.length : 1
  const plannedWithdrawInputCount = plannedWithdrawNotes ? plannedWithdrawNotes.length : 1
  const plannedWithdrawTotalStr = plannedWithdrawNotes
    ? plannedWithdrawNotes.reduce((s, n) => s + n.amount, 0n).toString()
    : selectedNoteAmountStr

  useEffect(() => {
    if ((tab !== 'send' && tab !== 'withdraw') || !useRelayer || !selectedNoteAmountStr) {
      return
    }
    let active = true
    if (tab === 'send') {
      const timer = setTimeout(() => {
        const client = new AudrenRelayClient(relayUrl)
        const omitNf1 = economyMode && plannedSendInputCount <= 1
        client
          .getFeeQuote({
            cluster,
            op: 'transfer',
            mint: selectedNoteMintStr === NATIVE_SOL_MINT_STR ? 'native' : selectedNoteMintStr,
            outputCount: 3,
            omitNf1,
          })
          .then((fq) => {
            if (!active) return
            setSendFeePreview({
              relayerFee: BigInt(fq.relayerFee || '0'),
              billingMode: fq.billingMode,
              reason: fq.reason,
            })
          })
          .catch(() => {
            if (active) setSendFeePreview(null)
          })
      }, 250)
      return () => {
        active = false
        clearTimeout(timer)
      }
    }

    const totalAvail = BigInt(plannedWithdrawTotalStr || selectedNoteAmountStr)
    const rawAmt = parseUnits(withdrawAmount, selectedNoteDecimals) ?? totalAvail
    if (rawAmt <= 0n) return
    const timer = setTimeout(() => {
      const client = new AudrenRelayClient(relayUrl)
      const omitNf1 = economyMode && plannedWithdrawInputCount <= 1
      client
        .getFeeQuote({
          cluster,
          op: 'withdraw',
          mint: selectedNoteMintStr === NATIVE_SOL_MINT_STR ? 'native' : selectedNoteMintStr,
          amount: rawAmt.toString(),
          unwrapWsol: unwrapWsol && selectedNoteMintStr === WSOL_MINT,
          outputCount: rawAmt < totalAvail ? 1 : 0,
          omitNf1,
        })
        .then((fq) => {
          if (!active) return
          setWithdrawFeePreview({
            relayerFee: BigInt(fq.relayerFee || '0'),
            billingMode: fq.billingMode,
            reason: fq.reason,
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
    selectedNoteAmountStr,
    selectedNoteMintStr,
    selectedNoteDecimals,
    withdrawAmount,
    unwrapWsol,
    economyMode,
    plannedSendInputCount,
    plannedWithdrawInputCount,
    plannedWithdrawTotalStr,
    cluster,
    relayUrl,
  ])

  const signAndBroadcastDirect = async (
    ixs: AudrenInstruction[],
    computeUnitLimit: number,
    lookupTables?: Record<string, string[]>,
  ): Promise<{ signature: string; slot: number }> => {
    if (!connected) throw new Error('Connect a Solana wallet to sign direct transactions')
    const bhRes = await fetch(`/api/rpc/blockhash?cluster=${cluster}`)
    const bh = (await bhRes.json()) as { blockhash?: string; lastValidBlockHeight?: string; error?: string }
    if (!bhRes.ok || !bh.blockhash) throw new Error(bh.error ?? 'Failed to fetch recent blockhash')

    const unsigned = compileKitV0Transaction({
      feePayer: connected.address,
      recentBlockhash: bh.blockhash,
      lastValidBlockHeight: BigInt(bh.lastValidBlockHeight ?? '0'),
      instructions: ixs.map(audrenInstructionToSolana),
      computeUnitLimit,
      lookupTables,
    })
    if (unsigned.byteLength > 1232) {
      throw new Error(
        `Direct v0 transaction is ${unsigned.byteLength} B (> 1,232 B Solana packet limit). Enable Privacy Relayer (uses 4,096 B Solana Transaction v1 0x81) to execute this route in one transaction.`,
      )
    }
    const [signed] = await signCompiledTransactionsWithWallet(connected, cluster, [unsigned])
    if (!signed) throw new Error('Wallet returned no signed transaction')
    const [sent] = await sendAndConfirmSignedTransactions(cluster, [signed])
    if (!sent) throw new Error('Broadcast returned no signature')
    return { signature: sent.signature, slot: sent.slot }
  }

  const requestRelayerCheckpointWithRetry = async (targetCluster: SolanaCluster) => {
    const relayClient = new AudrenRelayClient(relayUrl)
    const resp = await relayClient.requestCheckpoint({ cluster: targetCluster, poolId: 0 })
    if (resp.status === 'cooldown') {
      const waitMs = Number(resp.waitMs ?? (resp.slotsRemaining ?? 4) * 400)
      if (Number.isFinite(waitMs) && waitMs > 0 && waitMs <= 12_000) {
        setStatusMsg(
          `Waiting ~${Math.ceil(waitMs / 1000)}s for checkpoint epoch cooldown, then requesting relayer checkpoint…`,
        )
        await new Promise((r) => setTimeout(r, waitMs))
        return relayClient.requestCheckpoint({ cluster: targetCluster, poolId: 0 })
      }
      throw new Error(
        `Checkpoint cooldown active (${resp.slotsRemaining ?? 'several'} slots remaining, ~${Math.ceil(waitMs / 1000)}s). Retry shortly.`,
      )
    }
    return resp
  }

  const ensureCheckpointCoversNotes = async (
    notesToSpend: readonly OwnedNote[],
    initialSnap: PoolApiSnapshot,
  ): Promise<PoolApiSnapshot> => {
    if (checkpointCoversNotes(initialSnap, notesToSpend)) {
      return initialSnap
    }
    if (!useRelayer) {
      throw new Error(
        'Selected note is newer than the latest RootCheckpoint. Click "Publish checkpoint" in the vault card to publish directly with your wallet, then retry.',
      )
    }
    setStatusMsg('Requesting permissionless RootCheckpoint from Privacy Relayer…')
    try {
      const ckResp = await requestRelayerCheckpointWithRetry(cluster)
      if (ckResp.status === 'cooldown') {
        throw new Error(
          `Checkpoint cooldown still active (${ckResp.slotsRemaining ?? 'several'} slots remaining). Retry shortly.`,
        )
      }
      setRelayerCkptFallback(false)
    } catch (ckErr) {
      const msg = ckErr instanceof Error ? ckErr.message : String(ckErr)
      if (!/cooldown/i.test(msg)) {
        setRelayerCkptFallback(true)
        throw new Error(
          `Relayer checkpoint endpoint failed (${msg}). Use the fallback "Publish checkpoint" button in your vault card or switch to a relayer supporting POST /v1/checkpoint.`,
        )
      }
      throw ckErr
    }

    let refreshed = (await fetch(`/api/pool?cluster=${cluster}&poolId=0`).then((r) =>
      r.json(),
    )) as PoolApiSnapshot
    if (!checkpointCoversNotes(refreshed, notesToSpend)) {
      await new Promise((r) => setTimeout(r, 1_200))
      refreshed = (await fetch(`/api/pool?cluster=${cluster}&poolId=0`).then((r) =>
        r.json(),
      )) as PoolApiSnapshot
    }
    if (!checkpointCoversNotes(refreshed, notesToSpend)) {
      throw new Error(
        'Relayer checkpoint confirmed but RPC snapshot has not caught up yet. Wait a moment and retry.',
      )
    }
    void refreshPoolAndBalances(cluster, connected?.address ?? null)
    return refreshed
  }

  const handlePublishCheckpoint = async () => {
    setBusy(true)
    setErrorMsg(null)
    setStatusMsg(
      useRelayer && !relayerCkptFallback
        ? 'Requesting permissionless RootCheckpoint from Privacy Relayer…'
        : 'Publishing permissionless RootCheckpoint (Tag 5)…',
    )
    try {
      if (useRelayer && !relayerCkptFallback) {
        try {
          const resp = await requestRelayerCheckpointWithRetry(cluster)
          if (resp.status === 'cooldown') {
            throw new Error(
              `Checkpoint cooldown active (${resp.slotsRemaining ?? 'several'} slots remaining). Retry shortly.`,
            )
          }
          if (resp.signature) {
            setLastReceipt({
              kind: 'PublishCheckpoint (Tag 5)',
              signature: resp.signature,
              cluster,
              relayed: true,
              summary: 'Published fresh RootCheckpoint via Privacy Relayer (zero wallet signature)',
            })
          }
          setRelayerCkptFallback(false)
          await refreshPoolAndBalances(cluster, connected?.address ?? null)
          setStatusMsg(
            resp.status === 'up_to_date'
              ? 'RootCheckpoint is already up to date. Shielded notes are ready to spend.'
              : 'RootCheckpoint published by Privacy Relayer. Shielded notes are ready to spend.',
          )
          return
        } catch (relayErr) {
          const msg = relayErr instanceof Error ? relayErr.message : String(relayErr)
          if (/cooldown/i.test(msg)) throw relayErr
          setRelayerCkptFallback(true)
          throw new Error(
            `Relayer checkpoint failed (${msg}). You can use the manual wallet fallback below (note: signing directly links your public wallet to this checkpoint timestamp).`,
          )
        }
      }

      if (cluster === 'devnet' && !connected) {
        const res = await fetch('/api/devnet/checkpoint', { method: 'POST' })
        const json = (await res.json()) as { signature?: string; slotIdx?: number; error?: string }
        if (!res.ok || !json.signature) {
          throw new Error(json.error ?? `Devnet checkpoint HTTP ${res.status}`)
        }
        setLastReceipt({
          kind: 'PublishCheckpoint (Tag 5)',
          signature: json.signature,
          cluster: 'devnet',
          relayed: true,
          summary: `Published fresh RootCheckpoint at ring slot #${json.slotIdx ?? 0}`,
        })
      } else {
        if (!connected) {
          throw new Error('Connect a Solana wallet to publish a RootCheckpoint directly in self-pay mode')
        }
        const snap = (await fetch(`/api/pool?cluster=${cluster}&poolId=0`).then((r) => r.json())) as PoolApiSnapshot
        if (!snap.initialized) throw new Error(`Pool #0 is not initialized on ${cluster}`)
        const curSlot = BigInt(snap.currentSlot ?? '0')
        const ckptInterval = BigInt(snap.ckptInterval ?? '50')
        const slotIdx = Number((curSlot / (ckptInterval > 0n ? ckptInterval : 1n)) % BigInt(CHECKPOINT_RING_SLOTS))
        const ix = buildPublishCheckpointInstruction({
          poolId: 0,
          slotIdx,
          activeLanes: snap.activeLanes ?? 4,
          payer: connected.address,
        })
        const res = await signAndBroadcastDirect([ix], 120_000)
        setLastReceipt({
          kind: 'PublishCheckpoint (Tag 5)',
          signature: res.signature,
          cluster,
          relayed: false,
          summary: `Published fresh RootCheckpoint at ring slot #${slotIdx}`,
        })
      }
      await refreshPoolAndBalances(cluster, connected?.address ?? null)
      setStatusMsg('RootCheckpoint published. Shielded notes are ready to spend.')
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const buildLocalOrRpcWitness = async (params: {
    activeStore: CompactWalletStore
    fetcher: AccountBatchFetcher
    ckptSlotIdx: number
    note: OwnedNote
  }): Promise<{ ckpt: ReturnType<typeof decodeRootCheckpoint>; superRoot: bigint; path: MerklePath4Ary }> => {
    const { activeStore, fetcher, ckptSlotIdx, note } = params
    const ckptAddr = deriveCheckpointPdaSync(0, ckptSlotIdx, AUDREN_PROGRAM_ID).address
    const [ckptRaw] = await fetcher([ckptAddr])
    if (!ckptRaw) {
      throw new Error(`RootCheckpoint #${ckptSlotIdx} not found. Request a checkpoint above.`)
    }
    const ckpt = decodeRootCheckpoint(ckptRaw)
    const laneCount = ckpt.laneCounts[note.laneId] ?? 0n
    if (note.leafIndex >= laneCount) {
      throw new Error(
        `Note (Lane #${note.laneId}, Leaf #${note.leafIndex.toString()}) is newer than the latest RootCheckpoint (covers ${laneCount.toString()} leaves). Request a fresh checkpoint, then retry.`,
      )
    }
    // Zero-leak local witness first using frozen intra-subtree siblings + subroots in CompactWalletStore
    try {
      const localWitness = activeStore.buildWitnessForNote(note, ckpt)
      if (localWitness) {
        return { ckpt, superRoot: localWitness.superRoot, path: localWitness.path }
      }
    } catch {
      // Fall back cleanly to ordinary batched RPC reconstruction if local store missed frontier/siblings
    }
    return reconstructWitness({
      fetchBatch: fetcher,
      poolId: 0,
      ckptSlotIdx,
      laneId: note.laneId,
      leafIdx: note.leafIndex,
    })
  }

  const handleDeposit = async () => {
    if (!connected || !keys) return
    setBusy(true)
    setErrorMsg(null)
    setStatusMsg(null)
    try {
      const isNativeSelected = depositMint === NATIVE_SOL_MINT_STR
      const wrapAsWsol = isNativeSelected && wrapSolToWsol
      const isSolDeposit = isNativeSelected && !wrapAsWsol
      const targetMint = wrapAsWsol ? WSOL_MINT : depositMint

      const fetcher = createWorkerBatchFetcher(cluster)
      const [poolRaw] = await fetcher([AUDREN.pool0Pda])
      if (!poolRaw) throw new Error(`Pool #0 is not initialized on ${cluster} yet`)
      const pool = decodePoolState(poolRaw)
      const poolSnap = (await fetch(`/api/pool?cluster=${cluster}&poolId=0`).then((r) => r.json())) as PoolApiSnapshot
      const currentEpoch = BigInt(poolSnap.currentEpoch ?? '0')

      const tok = pubTokens.find((t) => t.mint === targetMint)
      const mintInfo = isSolDeposit ? null : await resolveMintOnChain(cluster, targetMint, currentEpoch)
      const decimals = isSolDeposit ? 9 : mintInfo?.decimals ?? tok?.decimals ?? getTokenMeta(targetMint).decimals
      const amount = parseUnits(depositAmount, decimals)
      if (!amount || amount <= 0n) throw new Error('Enter a valid positive amount')

      const laneId = Number(BigInt(poolSnap.totalNotes ?? '0') % BigInt(pool.activeLanes))
      const nextLeaf = BigInt(poolSnap.lanes?.[laneId]?.nextLeaf ?? '0')
      const subPageSeq = nextLeaf / BigInt(SUBTREE_LEAVES)
      const rootPageSeq = subPageSeq / BigInt(SUBROOTS_PER_PAGE)
      const memoPageSeq = nextLeaf / BigInt(MEMO_NOTES_PER_PAGE)

      const pageChecks = await fetcher([
        deriveSubtreePdaSync(0, laneId, subPageSeq, AUDREN_PROGRAM_ID).address,
        deriveSubrootPdaSync(0, laneId, rootPageSeq, AUDREN_PROGRAM_ID).address,
        deriveMemoPdaSync(0, laneId, memoPageSeq, AUDREN_PROGRAM_ID).address,
      ])

      const ixs: AudrenInstruction[] = []
      if (!pageChecks[0]) {
        ixs.push(buildOpenPageInstruction({ poolId: 0, laneId, pageKind: OPEN_PAGE_KIND_SUBTREE, pageSeq: subPageSeq, payer: connected.address }))
      }
      if (!pageChecks[1]) {
        ixs.push(buildOpenPageInstruction({ poolId: 0, laneId, pageKind: OPEN_PAGE_KIND_SUBROOT, pageSeq: rootPageSeq, payer: connected.address }))
      }
      if (!pageChecks[2]) {
        ixs.push(buildOpenPageInstruction({ poolId: 0, laneId, pageKind: OPEN_PAGE_KIND_MEMO, pageSeq: memoPageSeq, payer: connected.address }))
      }

      const mintBytes = isSolDeposit ? NATIVE_SOL_MINT_BYTES : base58Decode(targetMint)
      const detNoteFee = BigInt(poolSnap.deterministicNoteRentFee ?? pool.noteRentFee.toString())
      const committedAmount = isSolDeposit
        ? feeFromAmount
          ? amount - detNoteFee
          : amount
        : computeToken2022NetAmount(amount, mintInfo?.transferFee ?? null)
      if (committedAmount <= 0n) {
        throw new Error(
          isSolDeposit
            ? `Deposit amount must exceed deterministic note rent fee (${formatUnits(detNoteFee, 9)} SOL)`
            : 'Net deposit amount after Token-2022 TransferFee must be > 0',
        )
      }
      const { tweak, blinding, memo90 } = encryptNoteMemo(
        keys.viewPk,
        crypto.getRandomValues(new Uint8Array(32)),
        committedAmount,
        mintBytes,
      )
      const stealthOwner = deriveStealthOwner(keys.spendPk, tweak)

      if (isSolDeposit) {
        ixs.push(
          buildDepositSolInstruction({
            poolId: 0,
            laneId,
            subPageSeq,
            rootPageSeq,
            memoPageSeq,
            depositor: connected.address,
            amount,
            stealthOwner,
            blinding,
            memo90,
            feeFromAmount,
          }),
        )
      } else {
        const tokenProgram = mintInfo?.tokenProgram ?? tok?.tokenProgram ?? CLASSIC_TOKEN_PROGRAM_ID
        const vaultAuth = deriveVaultAuthPdaSync(0, AUDREN_PROGRAM_ID).address
        const depositorAta =
          tok?.ata ?? deriveAssociatedTokenAddressSync(connected.address, targetMint, tokenProgram).address
        const vaultAta = deriveAssociatedTokenAddressSync(vaultAuth, targetMint, tokenProgram).address

        if (wrapAsWsol) {
          ixs.push(
            buildCreateAtaIdempotentInstruction({
              payer: connected.address,
              ata: depositorAta,
              owner: connected.address,
              mint: WSOL_MINT,
              tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
            }),
          )
          ixs.push(buildSystemTransferIx(connected.address, depositorAta, amount))
          ixs.push(buildSyncNativeIx(depositorAta))
        }

        const [vaultAtaInfo] = await fetcher([vaultAta])
        if (!vaultAtaInfo) {
          ixs.push(
            buildCreateAtaIdempotentInstruction({
              payer: connected.address,
              ata: vaultAta,
              owner: vaultAuth,
              mint: targetMint,
              tokenProgram,
            }),
          )
        }
        ixs.push(
          buildDepositSplInstruction({
            poolId: 0,
            laneId,
            subPageSeq,
            rootPageSeq,
            memoPageSeq,
            depositor: connected.address,
            depositorAta,
            vaultAta,
            mint: targetMint,
            tokenProgram,
            amount,
            stealthOwner,
            blinding,
            memo90,
          }),
        )
      }

      setStatusMsg('Waiting for wallet approval…')
      const res = await signAndBroadcastDirect(ixs, 280_000)

      // Best-effort permissionless checkpoint crank so newly deposited notes become spendable quickly
      if (useRelayer) {
        await new AudrenRelayClient(relayUrl).requestCheckpoint({ cluster, poolId: 0 }).catch(() => {})
      } else if (cluster === 'devnet') {
        await fetch('/api/devnet/checkpoint', { method: 'POST' }).catch(() => {})
      }

      const sym = getTokenMeta(targetMint).symbol
      setLastReceipt({
        kind: isSolDeposit
          ? 'DepositSol (Tag 3)'
          : wrapAsWsol
            ? 'Wrap & DepositSpl · WSOL (Tag 4)'
            : mintInfo?.isToken2022
              ? 'DepositSpl · Token-2022 (Tag 4)'
              : 'DepositSpl · SPL (Tag 4)',
        signature: res.signature,
        cluster,
        relayed: false,
        summary: `Shielded ${depositAmount} ${sym}${mintInfo?.isToken2022 ? ' (Token-2022)' : ''} into Lane #${laneId}`,
      })
      setStatusMsg('Deposit confirmed. Syncing CompactWalletStore…')
      await syncVault(keys, cluster, store, walletScope)
      await refreshPoolAndBalances(cluster, connected.address)
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const handleJoinSplitAction = async (mode: 'send' | 'withdraw') => {
    if (!keys || !store || !selectedNote) return
    setBusy(true)
    setErrorMsg(null)
    setStatusMsg('Loading RootCheckpoint and building local 4-ary Depth-20 Merkle witness…')
    try {
      const mintStr = base58Encode(selectedNote.mint)
      const isNativeSol = mintStr === NATIVE_SOL_MINT_STR
      const fetcher = createWorkerBatchFetcher(cluster)
      let snap = (await fetch(`/api/pool?cluster=${cluster}&poolId=0`).then((r) => r.json())) as PoolApiSnapshot
      if (!snap.initialized) {
        throw new Error(`Pool #0 is not initialized on ${cluster} yet`)
      }
      const currentEpoch = BigInt(snap.currentEpoch ?? '0')
      const mintInfo = isNativeSol ? null : await resolveMintOnChain(cluster, mintStr, currentEpoch)
      const decimals = isNativeSol ? 9 : mintInfo?.decimals ?? getTokenMeta(mintStr).decimals
      const symbol = getTokenMeta(mintStr).symbol
      const amount = parseUnits(mode === 'send' ? sendAmount : withdrawAmount, decimals)
      if (!amount || amount <= 0n) {
        throw new Error(`Enter a valid positive ${symbol} amount`)
      }

      let inputNotes = selectInputNotesForMint(selectedNote, unspentNotes, amount)
      if (!inputNotes) {
        const noteCount = unspentNotes.filter((n) => base58Encode(n.mint) === mintStr).length
        throw new Error(
          noteCount >= 3
            ? `Amount exceeds the largest 2-note combination (${formatUnits(maxSpendableNotePair, decimals)} ${symbol}). Click "Merge 2 notes" in your vault card to consolidate smaller notes first.`
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
      const relayClient = new AudrenRelayClient(relayUrl)

      const isWsolUnwrap = mode === 'withdraw' && mintStr === WSOL_MINT && unwrapWsol
      const assetMode =
        mode === 'send'
          ? ASSET_MODE_PRIVATE
          : isNativeSol
            ? ASSET_MODE_SOL
            : ASSET_MODE_SPL
      const tokenProgram =
        assetMode === ASSET_MODE_SPL
          ? mintInfo?.tokenProgram ?? CLASSIC_TOKEN_PROGRAM_ID
          : CLASSIC_TOKEN_PROGRAM_ID
      const rawRecipient = mode === 'withdraw' ? withdrawRecipient.trim() : null
      if (mode === 'withdraw' && (!rawRecipient || !isValidSolanaPubkey(rawRecipient))) {
        throw new Error('Enter a valid public Solana recipient address')
      }
      const recipientPubkey =
        rawRecipient && assetMode === ASSET_MODE_SPL && !isWsolUnwrap
          ? deriveAssociatedTokenAddressSync(rawRecipient, mintStr, tokenProgram).address
          : rawRecipient

      // Check whether recipient ATA needs creation (used for both accurate fee quoting and setupAtas)
      let missingRecipientAta = false
      if (rawRecipient && recipientPubkey && assetMode === ASSET_MODE_SPL && !isWsolUnwrap) {
        const [recAcc] = await fetcher([recipientPubkey])
        missingRecipientAta = !recAcc
      }

      const fetchRelayerFee = async (curOmitNf1: boolean, curTotalIn: bigint) => {
        const fq =
          mode === 'send'
            ? await relayClient.getFeeQuote({
                cluster,
                op: 'transfer',
                mint: isNativeSol ? 'native' : mintStr,
                outputCount: 3,
                omitNf1: curOmitNf1,
              })
            : await relayClient.getFeeQuote({
                cluster,
                op: 'withdraw',
                mint: isNativeSol ? 'native' : mintStr,
                amount: amount.toString(),
                unwrapWsol: isWsolUnwrap,
                outputCount: amount < curTotalIn ? 1 : 0,
                missingAtaCount: missingRecipientAta ? 1 : 0,
                omitNf1: curOmitNf1,
              })
        relayerFeeAmount = BigInt(fq.relayerFee || '0')
        relayerFeeRecipient = fq.feeRecipient
        feeShieldedAddr = fq.feeShieldedAddress
        needsFeeAtaSetup = Boolean(fq.needsFeeAtaSetup)
      }

      if (useRelayer) {
        setStatusMsg('Querying Privacy Relayer fee quote…')
        const info = await relayClient.getInfo(cluster)
        if (!info.relayerPubkey) throw new Error(`Relayer at ${relayUrl} has no fee payer for ${cluster}`)
        payerPubkey = info.relayerPubkey
        await fetchRelayerFee(omitNf1, totalIn)

        const requiredWithFee =
          amount + (mode === 'send' ? (feeShieldedAddr ? relayerFeeAmount : 0n) : relayerFeeAmount)
        if (totalIn < requiredWithFee) {
          const expanded = selectInputNotesForMint(selectedNote, unspentNotes, requiredWithFee)
          if (!expanded) {
            throw new Error(
              `Insufficient note balance to cover amount + relayer fee (${formatUnits(relayerFeeAmount, decimals)} ${symbol}). Use "Max" to auto-fit.`,
            )
          }
          const grewToTwo = expanded.length === 2 && inputNotes.length === 1
          inputNotes = expanded
          totalIn = inputNotes.reduce((s, n) => s + n.amount, 0n)
          if (grewToTwo && omitNf1) {
            omitNf1 = false
            await fetchRelayerFee(false, totalIn)
          }
        }
      } else if (!connected) {
        throw new Error('Enable Privacy Relayer or connect a Solana wallet for Direct Self-Pay')
      }

      // Guarantee 2-input spends never omit nf1
      if (inputNotes.length > 1) omitNf1 = false

      snap = await ensureCheckpointCoversNotes(inputNotes, snap)
      const ckptSlotIdx = snap.latestCheckpoint!.slotIndex
      const witnesses = await Promise.all(
        inputNotes.map((note) =>
          buildLocalOrRpcWitness({
            activeStore: store,
            fetcher,
            ckptSlotIdx,
            note,
          }),
        ),
      )
      const ckpt = witnesses[0]!.ckpt
      const superRoot = witnesses[0]!.superRoot

      const outLaneId = pickRandomLaneId(snap.activeLanes ?? 4)
      const outLane = snap.lanes?.[outLaneId]
      const outNextLeaf = BigInt(outLane?.nextLeaf ?? '0')
      const outNfCount = BigInt(outLane?.nfCount ?? '0')

      const assetId = deriveAssetId(selectedNote.mint)
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
        buildRealInput(inputNotes[0]!, witnesses[0]!.path),
        inputNotes[1]
          ? buildRealInput(inputNotes[1]!, witnesses[1]!.path)
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

        // Uniform outputMask = 0b111: always emit 3 indistinguishable encrypted 90 B memos
        const mRec = encryptNoteMemo(rec.viewPk, crypto.getRandomValues(new Uint8Array(32)), amount, selectedNote.mint)
        const recOwner = deriveStealthOwner(frFromBeBytesStrict(rec.spendPk), mRec.tweak)
        outputs[0] = { stealthOwner: recOwner, assetId, amount, blinding: mRec.blinding }
        memos.push(mRec.memo90)

        if (changeAmt > 0n) {
          const mCh = encryptNoteMemo(keys.viewPk, crypto.getRandomValues(new Uint8Array(32)), changeAmt, selectedNote.mint)
          const chOwner = deriveStealthOwner(keys.spendPk, mCh.tweak)
          outputs[1] = { stealthOwner: chOwner, assetId, amount: changeAmt, blinding: mCh.blinding }
          memos.push(mCh.memo90)
        } else {
          const pad1 = createZeroDummyOutput(assetId, selectedNote.mint)
          outputs[1] = pad1.witness
          memos.push(pad1.memo90)
        }

        if (effectiveShieldedFee > 0n && feeShieldedAddr) {
          const feeRec = parseAudrenAddress(feeShieldedAddr)
          const mFee = encryptNoteMemo(
            feeRec.viewPk,
            crypto.getRandomValues(new Uint8Array(32)),
            effectiveShieldedFee,
            selectedNote.mint,
          )
          const feeOwner = deriveStealthOwner(frFromBeBytesStrict(feeRec.spendPk), mFee.tweak)
          outputs[2] = { stealthOwner: feeOwner, assetId, amount: effectiveShieldedFee, blinding: mFee.blinding }
          memos.push(mFee.memo90)
        } else {
          const pad2 = createZeroDummyOutput(assetId, selectedNote.mint)
          outputs[2] = pad2.witness
          memos.push(pad2.memo90)
        }
        outputMask = 0b111
      } else {
        const changeAmt = totalIn - amount - relayerFeeAmount
        if (changeAmt < 0n) {
          throw new Error(
            `Insufficient note balance to cover withdrawal + relayer fee (${formatUnits(relayerFeeAmount, decimals)} ${symbol}). Click "Max (net of fee)" to auto-fit.`,
          )
        }
        if (changeAmt > 0n) {
          const mCh = encryptNoteMemo(keys.viewPk, crypto.getRandomValues(new Uint8Array(32)), changeAmt, selectedNote.mint)
          const chOwner = deriveStealthOwner(keys.spendPk, mCh.tweak)
          outputs[0] = { stealthOwner: chOwner, assetId, amount: changeAmt, blinding: mCh.blinding }
          outputMask |= 1
          memos.push(mCh.memo90)
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

      const memosConcat = new Uint8Array(memos.reduce((s, m) => s + m.byteLength, 0))
      let mOff = 0
      for (const m of memos) {
        memosConcat.set(m, mOff)
        mOff += m.byteLength
      }

      const pubOutAmt = mode === 'withdraw' ? amount : 0n
      const pubFeeAmt = mode === 'withdraw' ? relayerFeeAmount : 0n
      const pubAssetIdBytes = mode === 'withdraw' ? frToBeBytes(assetId) : new Uint8Array(32)

      const ctxHash = computeJoinsplitCtxHash({
        poolId: 0,
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

      setStatusMsg('Generating 192-byte BN254 Groth16 proof in browser WASM…')
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

      const vaultAuth = deriveVaultAuthPdaSync(0, AUDREN_PROGRAM_ID).address
      const ix = buildJoinsplitInstruction({
        poolId: 0,
        outLaneId,
        ckptSlotIdx,
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
        splWithdrawAccs:
          assetMode === ASSET_MODE_SPL
            ? {
                mint: mintStr,
                vaultAta: deriveAssociatedTokenAddressSync(vaultAuth, mintStr, tokenProgram).address,
                tokenProgram,
              }
            : null,
      })

      let signature: string
      if (useRelayer) {
        const setupAtas: RelaySetupAta[] = []
        if (assetMode === ASSET_MODE_SPL && !isWsolUnwrap) {
          if (missingRecipientAta && rawRecipient) {
            setupAtas.push({ owner: rawRecipient, mint: mintStr, tokenProgram })
          }
          if (pubFeeAmt > 0n && needsFeeAtaSetup) {
            setupAtas.push({ owner: payerPubkey, mint: mintStr, tokenProgram })
          }
        }
        setStatusMsg('Submitting zero-signer proof to Privacy Relayer…')
        const sub = await relayClient.submitRelayedInstruction({
          cluster,
          instructionDataB64: toBase64(ix.data),
          accounts: ix.accounts,
          ...(setupAtas.length > 0 ? { setupAtas } : {}),
          computeUnitLimit: 320_000,
        })
        signature = sub.signature
      } else {
        const preIxs = await ensureLanePagesPreIxs({
          fetcher,
          payer: payerPubkey,
          laneId: outLaneId,
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
        if (missingRecipientAta && rawRecipient && recipientPubkey) {
          preIxs.push(
            buildCreateAtaIdempotentInstruction({
              payer: payerPubkey,
              ata: recipientPubkey,
              owner: rawRecipient,
              mint: mintStr,
              tokenProgram,
            }),
          )
        }
        setStatusMsg('Waiting for wallet approval…')
        const sent = await signAndBroadcastDirect([...preIxs, ix], 350_000)
        signature = sent.signature
      }

      setLastReceipt({
        kind: mode === 'send' ? 'JoinSplit Private Transfer (Tag 6)' : 'JoinSplit Withdraw (Tag 6)',
        signature,
        cluster,
        proverMs: elapsedMs,
        relayed: useRelayer,
        summary:
          mode === 'send'
            ? `Sent ${sendAmount} ${symbol} privately (${inputNotes.length} ${inputNotes.length === 1 ? 'note' : 'notes'} · 192 B Groth16 · epoch #${ckpt.epochId.toString()})`
            : `Withdrew ${withdrawAmount} ${symbol}${isWsolUnwrap ? ' (atomic WSOL unwrap)' : ''}${inputNotes.length === 2 ? ' (2-note spend)' : ''}`,
      })
      setStatusMsg('Confirmed. Syncing CompactWalletStore…')
      await syncVault(keys, cluster, store, walletScope)
      await refreshPoolAndBalances(cluster, connected?.address ?? null)
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const handleMergeNotes = async (mintStr: string) => {
    if (!keys || !store) return
    const candidates = unspentNotes
      .filter((n) => base58Encode(n.mint) === mintStr)
      .sort((a, b) => (a.amount < b.amount ? -1 : a.amount > b.amount ? 1 : 0))
    if (candidates.length < 2) return

    const noteA = candidates[0]!
    const noteB = candidates[1]!
    const isNativeSol = mintStr === NATIVE_SOL_MINT_STR
    const info = getTokenMeta(mintStr)

    setBusy(true)
    setErrorMsg(null)
    setStatusMsg(`Consolidating 2 smallest ${info.symbol} notes into 1…`)
    try {
      const fetcher = createWorkerBatchFetcher(cluster)
      let snap = (await fetch(`/api/pool?cluster=${cluster}&poolId=0`).then((r) => r.json())) as PoolApiSnapshot
      if (!snap.initialized) {
        throw new Error(`Pool #0 is not initialized on ${cluster} yet`)
      }

      const relayClient = new AudrenRelayClient(relayUrl)
      let payerPubkey = connected?.address ?? ''
      let relayerFeeAmount = 0n
      let feeShieldedAddr: string | null = null

      if (useRelayer) {
        setStatusMsg('Querying Privacy Relayer fee quote…')
        const relayInfo = await relayClient.getInfo(cluster)
        if (!relayInfo.relayerPubkey) {
          throw new Error(`Relayer at ${relayUrl} has no fee payer for ${cluster}`)
        }
        payerPubkey = relayInfo.relayerPubkey
        const fq = await relayClient.getFeeQuote({
          cluster,
          op: 'transfer',
          mint: isNativeSol ? 'native' : mintStr,
          outputCount: 3,
          omitNf1: false,
        })
        relayerFeeAmount = BigInt(fq.relayerFee || '0')
        feeShieldedAddr = fq.feeShieldedAddress
      } else if (!connected) {
        throw new Error('Enable Privacy Relayer or connect a Solana wallet to merge notes')
      }

      const effectiveShieldedFee = feeShieldedAddr ? relayerFeeAmount : 0n
      const mergedAmount = noteA.amount + noteB.amount - effectiveShieldedFee
      if (mergedAmount <= 0n) {
        throw new Error(
          `Combined balance of the 2 smallest ${info.symbol} notes (${formatUnits(noteA.amount + noteB.amount, info.decimals)} ${info.symbol}) does not exceed the relayer fee (${formatUnits(effectiveShieldedFee, info.decimals)} ${info.symbol}).`,
        )
      }

      snap = await ensureCheckpointCoversNotes([noteA, noteB], snap)
      const ckptSlotIdx = snap.latestCheckpoint!.slotIndex
      const [wA, wB] = await Promise.all([
        buildLocalOrRpcWitness({ activeStore: store, fetcher, ckptSlotIdx, note: noteA }),
        buildLocalOrRpcWitness({ activeStore: store, fetcher, ckptSlotIdx, note: noteB }),
      ])

      const outLaneId = pickRandomLaneId(snap.activeLanes ?? 4)
      const outLane = snap.lanes?.[outLaneId]
      const outNextLeaf = BigInt(outLane?.nextLeaf ?? '0')
      const outNfCount = BigInt(outLane?.nfCount ?? '0')
      const roll = computePageRollovers({
        leafCount: outNextLeaf,
        outputCount: 3,
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

      const assetId = deriveAssetId(noteA.mint)
      const mSelf = encryptNoteMemo(keys.viewPk, crypto.getRandomValues(new Uint8Array(32)), mergedAmount, noteA.mint)
      const selfOwner = deriveStealthOwner(keys.spendPk, mSelf.tweak)
      const pad1 = createZeroDummyOutput(assetId, noteA.mint)

      let out2Witness: JoinSplitOutputWitness
      let out2Memo: Uint8Array
      if (effectiveShieldedFee > 0n && feeShieldedAddr) {
        const feeRec = parseAudrenAddress(feeShieldedAddr)
        const mFee = encryptNoteMemo(
          feeRec.viewPk,
          crypto.getRandomValues(new Uint8Array(32)),
          effectiveShieldedFee,
          noteA.mint,
        )
        out2Witness = {
          stealthOwner: deriveStealthOwner(frFromBeBytesStrict(feeRec.spendPk), mFee.tweak),
          assetId,
          amount: effectiveShieldedFee,
          blinding: mFee.blinding,
        }
        out2Memo = mFee.memo90
      } else {
        const pad2 = createZeroDummyOutput(assetId, noteA.mint)
        out2Witness = pad2.witness
        out2Memo = pad2.memo90
      }

      const memosConcat = concatBytes(mSelf.memo90, pad1.memo90, out2Memo)
      const ctxHash = computeJoinsplitCtxHash({
        poolId: 0,
        outLaneId,
        outputMask: 0b111,
        assetMode: ASSET_MODE_PRIVATE,
        unwrapWsol: false,
        recipient: null,
        relayerFeeRecipient: null,
        publicAssetId: new Uint8Array(32),
        publicAmountOut: 0n,
        relayerFeeAmount: 0n,
        memosBytes: memosConcat,
      })

      setStatusMsg('Generating 192-byte BN254 Groth16 proof in browser WASM…')
      const { result, elapsedMs } = await proveJoinsplitInBrowser({
        superRoot: wA.superRoot,
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
            merklePath: wA.path,
          },
          {
            isDummy: false,
            spendSk: keys.spendSk,
            tweak: frFromBeBytesStrict(noteB.tweak),
            assetId,
            amount: noteB.amount,
            blinding: frFromBeBytesStrict(noteB.blinding),
            merklePath: wB.path,
          },
        ],
        outputs: [
          { stealthOwner: selfOwner, assetId, amount: mergedAmount, blinding: mSelf.blinding },
          pad1.witness,
          out2Witness,
        ],
      })

      const ix = buildJoinsplitInstruction({
        poolId: 0,
        outLaneId,
        ckptSlotIdx,
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
        outputMask: 0b111,
        assetMode: ASSET_MODE_PRIVATE,
        unwrapWsol: false,
        publicAmountOut: 0n,
        relayerFeeAmount: 0n,
        memosBytes: memosConcat,
      })

      let signature: string
      if (useRelayer) {
        setStatusMsg('Submitting zero-signer 2-to-1 merge proof to Privacy Relayer…')
        const sub = await relayClient.submitRelayedInstruction({
          cluster,
          instructionDataB64: toBase64(ix.data),
          accounts: ix.accounts,
          computeUnitLimit: 320_000,
        })
        signature = sub.signature
      } else {
        const preIxs = await ensureLanePagesPreIxs({
          fetcher,
          payer: payerPubkey,
          laneId: outLaneId,
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
        setStatusMsg('Waiting for wallet approval…')
        const sent = await signAndBroadcastDirect([...preIxs, ix], 350_000)
        signature = sent.signature
      }

      setLastReceipt({
        kind: 'JoinSplit Note Merge 2 -> 1 (Tag 6)',
        signature,
        cluster,
        proverMs: elapsedMs,
        relayed: useRelayer,
        summary: `Consolidated 2 ${info.symbol} notes into 1 note (${formatUnits(mergedAmount, info.decimals)} ${info.symbol})`,
      })
      setStatusMsg('Merge confirmed. Syncing CompactWalletStore…')
      await syncVault(keys, cluster, store, walletScope)
      await refreshPoolAndBalances(cluster, connected?.address ?? null)
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const handleShieldedSwap = async () => {
    if (!keys || !store || !selectedNote || !swapQuoteRaw || !swapQuoteOut) return
    setBusy(true)
    setErrorMsg(null)
    setStatusMsg('Building isolated Escrow swap route…')
    try {
      const inMintStr = base58Encode(selectedNote.mint)
      if (inMintStr === NATIVE_SOL_MINT_STR) {
        throw new Error(
          'Jupiter CPI swaps spend shielded WSOL, Classic SPL, or Token-2022 notes. Shield WSOL from the Shield tab (check "Wrap SOL as WSOL") to swap SOL via ExecViaEscrow.',
        )
      }
      if (!isValidSolanaPubkey(swapOutMint)) {
        throw new Error('Enter a valid output Solana token mint')
      }

      const fetcher = createWorkerBatchFetcher(cluster)
      let snap = (await fetch(`/api/pool?cluster=${cluster}&poolId=0`).then((r) => r.json())) as PoolApiSnapshot
      if (!snap.initialized) {
        throw new Error(`Pool #0 is not initialized on ${cluster} yet`)
      }
      const currentEpoch = BigInt(snap.currentEpoch ?? '0')
      const [inMintInfo, outMintInfo] = await Promise.all([
        resolveMintOnChain(cluster, inMintStr, currentEpoch),
        resolveMintOnChain(cluster, swapOutMint, currentEpoch),
      ])
      const inTokenProgram = inMintInfo.tokenProgram
      const outTokenProgram = outMintInfo.tokenProgram
      const inDec = inMintInfo.decimals ?? getTokenMeta(inMintStr).decimals
      const inSym = getTokenMeta(inMintStr).symbol

      const amountIn = parseUnits(swapAmount, inDec)
      if (!amountIn || amountIn <= 0n) {
        throw new Error(`Invalid swap input amount (max ${formatUnits(maxSpendableNotePair, inDec)} ${inSym})`)
      }

      let inputNotes = selectInputNotesForMint(selectedNote, unspentNotes, amountIn)
      if (!inputNotes) {
        const noteCount = unspentNotes.filter((n) => base58Encode(n.mint) === inMintStr).length
        throw new Error(
          noteCount >= 3
            ? `Swap input exceeds the largest 2-note combination (${formatUnits(maxSpendableNotePair, inDec)} ${inSym}). Click "Merge 2 notes" in your vault card first.`
            : `Invalid swap input amount (max ${formatUnits(maxSpendableNotePair, inDec)} ${inSym})`,
        )
      }
      let totalIn = inputNotes.reduce((s, n) => s + n.amount, 0n)
      let omitNf1 = inputNotes.length === 1 && economyMode

      const escrowShard = swapQuoteShard ?? swapEscrowShard ?? pickRandomEscrowShard(NUM_ESCROW_SHARDS)
      const vaultAuth = deriveVaultAuthPdaSync(0, AUDREN_PROGRAM_ID).address
      const escrowPda = deriveEscrowPdaSync(0, escrowShard, AUDREN_PROGRAM_ID).address
      const inVaultAta = deriveAssociatedTokenAddressSync(vaultAuth, inMintStr, inTokenProgram).address
      const inEscrowAta = deriveAssociatedTokenAddressSync(escrowPda, inMintStr, inTokenProgram).address
      const outVaultAta = deriveAssociatedTokenAddressSync(vaultAuth, swapOutMint, outTokenProgram).address
      const outEscrowAta = deriveAssociatedTokenAddressSync(escrowPda, swapOutMint, outTokenProgram).address

      let activeQuoteRaw: unknown = swapQuoteRaw
      let activeQuoteOut: string = swapQuoteOut

      // Defense-in-depth for Direct Self-Pay Token-2022 TransferFeeConfig input mints:
      // ensure Jupiter's quoted input strictly matches net tokens arriving at escrow_in_ata.
      if (!useRelayer && inMintInfo.transferFee) {
        const expectedNetIn = computeToken2022NetAmount(amountIn, inMintInfo.transferFee)
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
              slippageBps: swapSlippageBps,
            }),
          })
          const requoted = (await requoteRes.json()) as Record<string, unknown>
          if (!requoteRes.ok || typeof requoted.outAmount !== 'string') {
            throw new Error(String(requoted.error ?? 'Failed to quote Token-2022 net swap input'))
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
      let swapCuLimit = 850_000
      let winningProvider: RelayAggregatorId = swapQuoteProvider ?? 'jupiter'

      if (useRelayer) {
        const info = await relayClient.getInfo(cluster)
        if (!info.relayerPubkey) throw new Error(`Relayer missing fee payer for ${cluster}`)
        payerPubkey = info.relayerPubkey

        const built = await relayClient.buildSwapInstructions({
          provider: winningProvider,
          quoteResponse: activeQuoteRaw,
          inputMint: inMintStr,
          outputMint: swapOutMint,
          cluster,
          shardId: escrowShard,
          includeFee: false,
        })
        winningProvider = built.provider
        routerProg = built.swapInstruction.programId
        rawRouterAccounts = built.swapInstruction.accounts
        routerIxData = fromBase64(built.swapInstruction.data)
        swapCuLimit = built.computeUnitLimit ?? 850_000
        relaySetupAtas = (built.missingAtas ?? []).map((m) => ({
          owner: m.owner,
          mint: m.mint,
          tokenProgram: m.tokenProgram,
        }))

        const fetchExecFee = async (curOmitNf1: boolean) => {
          const fq = await relayClient.getFeeQuote({
            cluster,
            op: 'exec_escrow',
            mint: swapFeeOnOutput ? swapOutMint : inMintStr,
            amount: swapFeeOnOutput ? activeQuoteOut : amountIn.toString(),
            feeOnOutput: swapFeeOnOutput,
            missingAtaCount: relaySetupAtas.length,
            omitNf1: curOmitNf1,
          })
          relayerFeeAmount = BigInt(fq.relayerFee || '0')
          relayerFeeRecipient = fq.feeRecipient
          if (relayerFeeAmount > 0n && fq.needsFeeAtaSetup) {
            const feeMint = swapFeeOnOutput ? swapOutMint : inMintStr
            const feeTp = swapFeeOnOutput ? outTokenProgram : inTokenProgram
            if (!relaySetupAtas.some((a) => a.owner === payerPubkey && a.mint === feeMint)) {
              relaySetupAtas.push({ owner: payerPubkey, mint: feeMint, tokenProgram: feeTp })
            }
          }
        }
        await fetchExecFee(omitNf1)

        if (!swapFeeOnOutput && relayerFeeAmount > 0n && totalIn < amountIn + relayerFeeAmount) {
          const expanded = selectInputNotesForMint(selectedNote, unspentNotes, amountIn + relayerFeeAmount)
          if (!expanded) {
            throw new Error(
              `Insufficient note balance for swap + input fee (${formatUnits(relayerFeeAmount, inDec)} ${inSym})`,
            )
          }
          const grewToTwo = expanded.length === 2 && inputNotes.length === 1
          inputNotes = expanded
          totalIn = inputNotes.reduce((s, n) => s + n.amount, 0n)
          if (grewToTwo && omitNf1) {
            omitNf1 = false
            await fetchExecFee(false)
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
          error?: string
        }
        if (!res.ok || !built.swapInstruction) throw new Error(built.error ?? 'Failed to build swap route')
        routerProg = built.swapInstruction.programId
        rawRouterAccounts = built.swapInstruction.accounts
        routerIxData = fromBase64(built.swapInstruction.data)
        directLookupTables = built.lookupTables
      }

      if (inputNotes.length > 1) omitNf1 = false

      // CRITICAL: on-chain ExecViaEscrow forbids EXEC_FLAG_FEE_ON_OUTPUT when relayer_fee_amount == 0!
      const effectiveFeeOnOutput = swapFeeOnOutput && relayerFeeAmount > 0n

      // CRITICAL: strip escrowPda signer flag AND promote Solana transaction-wide writability union
      // so ctx_hash matches runtime AccountView::is_writable() inside the on-chain program!
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

      // Compute net slippage floor AFTER output relayer fee & output Token-2022 TransferFeeConfig
      const grossMinOut = (BigInt(activeQuoteOut) * BigInt(10_000 - swapSlippageBps)) / 10_000n
      const afterRelayerFee = effectiveFeeOnOutput
        ? grossMinOut > relayerFeeAmount
          ? grossMinOut - relayerFeeAmount
          : 1n
        : grossMinOut
      const netMinOut = computeToken2022NetAmount(afterRelayerFee, outMintInfo.transferFee)
      const minOut = netMinOut > 0n ? netMinOut : 1n

      snap = await ensureCheckpointCoversNotes(inputNotes, snap)
      const ckptSlotIdx = snap.latestCheckpoint!.slotIndex
      const witnesses = await Promise.all(
        inputNotes.map((note) =>
          buildLocalOrRpcWitness({
            activeStore: store,
            fetcher,
            ckptSlotIdx,
            note,
          }),
        ),
      )
      const superRoot = witnesses[0]!.superRoot

      const outLaneId = pickRandomLaneId(snap.activeLanes ?? 4)
      const outLane = snap.lanes?.[outLaneId]
      const outNextLeaf = BigInt(outLane?.nextLeaf ?? '0')
      const outNfCount = BigInt(outLane?.nfCount ?? '0')

      const assetIn = deriveAssetId(selectedNote.mint)
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
        const mCh = encryptNoteMemo(keys.viewPk, crypto.getRandomValues(new Uint8Array(32)), changeAmt, selectedNote.mint)
        const chOwner = deriveStealthOwner(keys.spendPk, mCh.tweak)
        outputs[0] = { stealthOwner: chOwner, assetId: assetIn, amount: changeAmt, blinding: mCh.blinding }
        changeMask = 1
        changeMemos = mCh.memo90
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
        outLaneId,
        escrowShard,
        changeMask,
        inKind: 1,
        outKind: 1,
        feeOnOutput: effectiveFeeOnOutput,
        assetIn: frToBeBytes(assetIn),
        amountIn,
        relayerFeeAmount,
        relayerFeeRecipient: relayerFeeAmount > 0n ? relayerFeeRecipient : null,
        assetOut: frToBeBytes(assetOut),
        minAmountOut: minOut,
        routerProg,
        routerAccounts,
        outStealthOwner: frToBeBytes(outStealthOwner),
        outBlinding: frToBeBytes(dyn.blinding),
        dynMemoHead: dyn.dynHead34,
        dynMask56: dyn.dynMask56,
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
        buildSwapInput(inputNotes[0]!, witnesses[0]!.path),
        inputNotes[1]
          ? buildSwapInput(inputNotes[1]!, witnesses[1]!.path)
          : dummyInputWitness(keys.spendSk, assetIn, randomFr()),
      ]

      setStatusMsg('Generating 192-byte BN254 Groth16 proof in browser WASM…')
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

      const ix = buildExecViaEscrowInstruction({
        poolId: 0,
        outLaneId,
        ckptSlotIdx,
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
        inKind: 1,
        outKind: 1,
        feeOnOutput: effectiveFeeOnOutput,
        amountIn,
        relayerFeeAmount,
        minAmountOut: minOut,
        outStealthOwner: frToBeBytes(outStealthOwner),
        outBlinding: frToBeBytes(dyn.blinding),
        dynMemoHead: dyn.dynHead34,
        dynMask56: dyn.dynMask56,
        changeMemos,
        routerProg,
        routerAccounts,
        routerIxData,
        inSpl: {
          mint: inMintStr,
          vaultAta: inVaultAta,
          escrowAta: inEscrowAta,
          tokenProgram: inTokenProgram,
        },
        outSpl: {
          mint: swapOutMint,
          vaultAta: outVaultAta,
          escrowAta: outEscrowAta,
          tokenProgram: outTokenProgram,
        },
        relayerFeeRecipient: relayerFeeAmount > 0n ? relayerFeeRecipient : null,
      })

      let signature: string
      if (useRelayer) {
        setStatusMsg('Relaying ExecViaEscrow (Tag 7) via Transaction v1 (0x81)…')
        const sub = await relayClient.submitRelayedInstruction({
          cluster,
          instructionDataB64: toBase64(ix.data),
          accounts: ix.accounts,
          ...(relaySetupAtas.length > 0 ? { setupAtas: relaySetupAtas } : {}),
          computeUnitLimit: swapCuLimit,
          vaultOutAta: outVaultAta,
          provider: winningProvider,
        })
        signature = sub.signature
      } else {
        const preIxs = await ensureLanePagesPreIxs({
          fetcher,
          payer: payerPubkey,
          laneId: outLaneId,
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
        const ataPrep = await fetcher([outVaultAta, outEscrowAta, inEscrowAta])
        if (!ataPrep[0]) {
          preIxs.push(
            buildCreateAtaIdempotentInstruction({
              payer: payerPubkey,
              ata: outVaultAta,
              owner: vaultAuth,
              mint: swapOutMint,
              tokenProgram: outTokenProgram,
            }),
          )
        }
        if (!ataPrep[1]) {
          preIxs.push(
            buildCreateAtaIdempotentInstruction({
              payer: payerPubkey,
              ata: outEscrowAta,
              owner: escrowPda,
              mint: swapOutMint,
              tokenProgram: outTokenProgram,
            }),
          )
        }
        if (!ataPrep[2]) {
          preIxs.push(
            buildCreateAtaIdempotentInstruction({
              payer: payerPubkey,
              ata: inEscrowAta,
              owner: escrowPda,
              mint: inMintStr,
              tokenProgram: inTokenProgram,
            }),
          )
        }
        setStatusMsg('Waiting for wallet approval…')
        const sent = await signAndBroadcastDirect([...preIxs, ix], swapCuLimit, directLookupTables)
        signature = sent.signature
      }

      setLastReceipt({
        kind: 'ExecViaEscrow Shielded Swap (Tag 7)',
        signature,
        cluster,
        proverMs: elapsedMs,
        relayed: useRelayer,
        summary: `Swapped ${swapAmount} ${inSym} → ${getTokenMeta(swapOutMint).symbol} via isolated Escrow #${escrowShard} (${winningProvider})${inputNotes.length === 2 ? ' · 2-note spend' : ''}`,
      })
      setSwapEscrowShard(pickRandomEscrowShard(NUM_ESCROW_SHARDS))
      setSwapQuoteShard(null)
      setStatusMsg('Swap confirmed. Syncing CompactWalletStore…')
      await syncVault(keys, cluster, store, walletScope)
      await refreshPoolAndBalances(cluster, connected?.address ?? null)
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
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
        protocolVersion: 2,
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
    if (!selectedNote) return
    const proof = exportSelectiveDisclosureProof(selectedNote)
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
    setReceiptVerdict('valid')
  }

  const handleVerifyReceipt = () => {
    try {
      const p = JSON.parse(receiptJson) as {
        poolId: number
        laneId: number
        leafIndex: string
        stealthOwnerHex: string
        mint: string
        amount: string
        blindingHex: string
        commitmentHex: string
      }
      const hexToBytes = (h: string) => {
        const clean = h.trim().replace(/^0x/i, '')
        const out = new Uint8Array(clean.length / 2)
        for (let i = 0; i < out.byteLength; i++) out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16)
        return out
      }
      const sdp: SelectiveDisclosureProof = {
        poolId: Number(p.poolId),
        laneId: Number(p.laneId),
        leafIndex: BigInt(p.leafIndex),
        stealthOwner: hexToBytes(p.stealthOwnerHex),
        mint: base58Decode(p.mint),
        amount: BigInt(p.amount),
        blinding: hexToBytes(p.blindingHex),
        commitment: hexToBytes(p.commitmentHex),
      }
      setReceiptVerdict(verifySelectiveDisclosureProof(sdp, sdp.commitment) ? 'valid' : 'invalid')
    } catch {
      setReceiptVerdict('invalid')
    }
  }

  const handleExportBackup = async () => {
    if (!seedBytes || !keys) return
    setBackupStatus(null)
    try {
      const file = await exportEncryptedVaultBackup({
        seed: seedBytes,
        audrenAddress: keys.address,
        cluster,
        passphrase: backupPassphrase,
      })
      const blob = new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `audren-backup-${cluster}.json`
      a.click()
      URL.revokeObjectURL(url)
      setBackupStatus('Encrypted backup downloaded (PBKDF2-SHA256 600k + AES-256-GCM)')
    } catch (err) {
      setBackupStatus(err instanceof Error ? err.message : String(err))
    }
  }

  const handleImportBackup = async (file: File) => {
    setBackupStatus(null)
    setErrorMsg(null)
    try {
      const parsed = JSON.parse(await file.text()) as AudrenEncryptedBackupFile
      const restored = await importEncryptedVaultBackup(parsed, backupPassphrase)
      setCluster(restored.cluster)
      await unlockFromSeed(restored.seed, restored.cluster, 'backup', walletScope)
      setBackupStatus(`Restored Audren vault on ${restored.cluster}`)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      setBackupStatus(msg)
      setErrorMsg(msg)
    }
  }

  const totalShieldedByMint = useMemo(() => {
    const map = new Map<string, { total: bigint; count: number }>()
    for (const n of unspentNotes) {
      const m = base58Encode(n.mint)
      const prev = map.get(m)
      map.set(m, { total: (prev?.total ?? 0n) + n.amount, count: (prev?.count ?? 0) + 1 })
    }
    return Array.from(map.entries())
  }, [unspentNotes])

  const maxSendNet = useMemo(() => {
    if (!selectedNote) return 0n
    const fee = useRelayer && sendFeePreview ? sendFeePreview.relayerFee : 0n
    return maxSpendableNotePair > fee ? maxSpendableNotePair - fee : 0n
  }, [selectedNote, maxSpendableNotePair, useRelayer, sendFeePreview])

  const maxWithdrawNet = useMemo(() => {
    if (!selectedNote) return 0n
    const fee = useRelayer && withdrawFeePreview ? withdrawFeePreview.relayerFee : 0n
    return maxSpendableNotePair > fee ? maxSpendableNotePair - fee : 0n
  }, [selectedNote, maxSpendableNotePair, useRelayer, withdrawFeePreview])

  const activePlannedNotes =
    tab === 'send' ? plannedSendNotes : tab === 'withdraw' ? plannedWithdrawNotes : tab === 'swap' ? plannedSwapNotes : null

  return (
    <div className="lv-shell">
      <div className="lv-topbar">
        <div className="lv-cluster-switch" role="group" aria-label="Solana cluster">
          <button
            type="button"
            className={`lv-cluster-btn ${cluster === 'devnet' ? 'is-active' : ''}`}
            onClick={() => handleClusterSwitch('devnet')}
          >
            <span className="lv-cluster-dot is-devnet" />
            Devnet
          </button>
          <button
            type="button"
            className={`lv-cluster-btn ${cluster === 'mainnet' ? 'is-active' : ''}`}
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
              <button type="button" className="lv-mini-btn" onClick={handleDisconnect}>
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
          Perpetual Powers of Tau + BGM17 ceremony (<code>{shortHash(AUDREN.pkCompressedSha256, 8, 6)}</code>) ·
          Pre-audit release (open for independent security audit &amp; additional community Phase-2 contributions).
        </span>
      </div>

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
                  <p>Reads <code>SubtreePage</code>, <code>MemoPage</code>, and <code>NullifierPage</code> PDAs in batched <code>getMultipleAccounts</code> calls; persists compact encrypted state in IndexedDB.</p>
                </div>
              </li>
              <li>
                <span className="lv-step-dot">3</span>
                <div>
                  <span className="lv-step-title">Prove locally in browser WASM</span>
                  <p>Generates 192 B Groth16 proofs via <code>/wasm/audren_circuits.wasm</code> and submits via your chosen Privacy Relayer or direct self-pay.</p>
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
                    disabled={connecting}
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
                <button
                  type="button"
                  className="btn-primary lv-submit-btn"
                  disabled={busy}
                  onClick={handleUnlockWithWalletSignature}
                >
                  {busy ? <Loader2 size={15} className="spin" /> : <KeyRound size={15} />}
                  Unlock vault with {connected.name}
                </button>
              )}
              <button
                type="button"
                className="btn-secondary lv-submit-btn"
                disabled={busy}
                onClick={handleCreateLocalVault}
              >
                <Lock size={15} /> Create ephemeral local vault
              </button>
            </div>

            <div className="lv-backup-box" style={{ marginTop: '0.5rem' }}>
              <span className="lv-box-title">Restore encrypted backup</span>
              <p>Enter your backup passphrase and select an <code>audren-backup-*.json</code> file.</p>
              <div className="lv-backup-row">
                <input
                  type="password"
                  className="lv-input"
                  value={backupPassphrase}
                  onChange={(e) => setBackupPassphrase(e.target.value)}
                  placeholder="Backup passphrase"
                />
                <button
                  type="button"
                  className="lv-mini-btn"
                  disabled={busy || backupPassphrase.length < 8}
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
                  {strangerView ? 'What Solana observers see' : 'Shielded vault (local)'}
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
                  disabled={syncing}
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

            {noteNeedsCheckpoint && (
              <div className="lv-notice-bar is-warn">
                <AlertCircle size={14} />
                <span style={{ flex: 1 }}>
                  {useRelayer && !relayerCkptFallback
                    ? slotsUntilNextCheckpoint > 0n
                      ? `Recent deposit awaiting next checkpoint epoch (~${slotsUntilNextCheckpoint.toString()} slots). Your Privacy Relayer publishes it automatically when you spend, or request it now.`
                      : 'A fresh RootCheckpoint is needed before spending your latest note. Your Privacy Relayer can publish it permissionlessly without linking your wallet.'
                    : relayerCkptFallback
                      ? 'Custom relayer checkpoint endpoint unavailable. Privacy note: publishing directly with your wallet links your public address to this checkpoint timestamp.'
                      : slotsUntilNextCheckpoint > 0n
                        ? `Recent deposit awaiting next checkpoint epoch (~${slotsUntilNextCheckpoint.toString()} slots). Refresh shortly to publish.`
                        : 'A fresh RootCheckpoint is needed before spending your latest deposited note.'}
                </span>
                <button
                  type="button"
                  className="lv-mini-btn"
                  disabled={
                    busy ||
                    (!(useRelayer && !relayerCkptFallback) &&
                      (slotsUntilNextCheckpoint > 0n || (cluster === 'mainnet' && !connected)))
                  }
                  onClick={handlePublishCheckpoint}
                >
                  {useRelayer && !relayerCkptFallback ? 'Request relayer checkpoint' : 'Publish checkpoint'}
                </button>
              </div>
            )}

            <div className="lv-balance-list">
              {totalShieldedByMint.length === 0 ? (
                <div className="lv-balance-row">
                  <div>
                    <span className="lv-row-title">No shielded notes yet</span>
                    <span>Deposit SOL or SPL tokens below, or share your aud1… receive address</span>
                  </div>
                  <span className="lv-balance-amt mono">0.00</span>
                </div>
              ) : (
                totalShieldedByMint.map(([m, { total, count }]) => {
                  const info = getTokenMeta(m)
                  return (
                    <div key={m} className="lv-balance-row">
                      <div>
                        <span className="lv-row-title">{info.symbol}</span>
                        <span className="mono">
                          {shortHash(m, 6, 4)} · {count} {count === 1 ? 'note' : 'notes'}
                        </span>
                      </div>
                      {strangerView ? (
                        <span className="lv-redacted-bar mono">Encrypted 90 B memo</span>
                      ) : (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                          <span className="lv-balance-amt is-pine mono">
                            {formatUnits(total, info.decimals)} {info.symbol}
                          </span>
                          {count >= 2 && (
                            <button
                              type="button"
                              className="lv-mini-btn"
                              disabled={busy}
                              onClick={() => handleMergeNotes(m)}
                            >
                              <Layers size={12} /> Merge 2 notes
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
                  <span>Unspent notes</span>
                  <span className="lv-pub-num mono">{unspentNotes.length}</span>
                </div>
                <div className="lv-pub-val">
                  <span>Relayer</span>
                  <span className="lv-pub-num mono">{useRelayer ? new URL(relayUrl).host : 'Direct self-pay'}</span>
                </div>
              </div>
            </div>

            <div className="lv-private-foot">
              <div className="lv-addr-row">
                <span className="mono">aud1 receive address</span>
                <code className="mono">{shortHash(keys.address, 14, 10)}</code>
                <button
                  type="button"
                  className="lv-copy-chip"
                  onClick={() => copyText('addr', keys.address)}
                >
                  {copiedField === 'addr' ? <Check size={12} /> : <Copy size={12} />}
                  {copiedField === 'addr' ? 'Copied' : 'Copy'}
                </button>
              </div>
              <div className="lv-custom-relay">
                <div className="lv-custom-relay-head">
                  <label className="lv-toggle-row">
                    <input
                      type="checkbox"
                      checked={useRelayer}
                      onChange={(e) => {
                        setUseRelayer(e.target.checked)
                        setRelayerCkptFallback(false)
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
                        if (isAllowedRelayUrl(relayDraft)) {
                          setRelayUrl(relayDraft)
                          setRelayerCkptFallback(false)
                          window.localStorage.setItem(RELAY_STORAGE_KEY, relayDraft)
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
                  ['deposit', 'Shield', 'Tag 3/4', ArrowDownToLine],
                  ['send', 'Private send', 'Tag 6', Send],
                  ['swap', 'DeFi swap', 'Tag 7', ArrowLeftRight],
                  ['withdraw', 'Withdraw', 'Tag 6', ArrowUpFromLine],
                  ['compliance', 'Receipts & keys', 'Mode 1/2', FileKey2],
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
                  <div className="lv-field-block">
                    <label className="lv-label">Asset to shield</label>
                    <select
                      className="lv-select mono"
                      value={depositMint}
                      onChange={(e) => setDepositMint(e.target.value)}
                    >
                      <option value={NATIVE_SOL_MINT_STR}>Native SOL ({formatUnits(pubSolLamports, 9)} available)</option>
                      {pubTokens.map((t) => (
                        <option key={t.mint} value={t.mint}>
                          {getTokenMeta(t.mint).symbol}
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
                  {depositMint === NATIVE_SOL_MINT_STR && (
                    <>
                      <label className="lv-checkbox-card">
                        <input
                          type="checkbox"
                          checked={wrapSolToWsol}
                          onChange={(e) => {
                            setWrapSolToWsol(e.target.checked)
                            if (e.target.checked) setFeeFromAmount(false)
                          }}
                        />
                        <div>
                          <span className="lv-checkbox-title">Wrap SOL &amp; shield as WSOL (swap-ready)</span>
                          <span>Wraps native SOL into SPL WSOL in the same transaction so the shielded note can execute Jupiter DeFi swaps (Tag 7) or unwrap back to SOL atomically.</span>
                        </div>
                      </label>
                      {!wrapSolToWsol && (
                        <label className="lv-checkbox-card">
                          <input
                            type="checkbox"
                            checked={feeFromAmount}
                            onChange={(e) => setFeeFromAmount(e.target.checked)}
                          />
                          <div>
                            <span className="lv-checkbox-title">Zero-dust sweep (DEPOSIT_FLAG_FEE_FROM_AMOUNT)</span>
                            <span>Deducts amortized page rent from the shielded amount so ephemeral wallets sweep cleanly to 0 lamports.</span>
                          </div>
                        </label>
                      )}
                    </>
                  )}
                  <button
                    type="button"
                    className="btn-primary lv-submit-btn"
                    disabled={busy || !connected}
                    onClick={handleDeposit}
                  >
                    {busy ? <Loader2 size={15} className="spin" /> : <ArrowDownToLine size={15} />}
                    {connected
                      ? depositMint === NATIVE_SOL_MINT_STR && wrapSolToWsol
                        ? 'Wrap SOL & shield WSOL into global pool'
                        : 'Shield into global pool'
                      : 'Connect wallet to deposit'}
                  </button>
                </>
              )}

              {(tab === 'send' || tab === 'swap' || tab === 'withdraw') && (
                <>
                  <div className="lv-field-block">
                    <label className="lv-label">Input shielded note</label>
                    <select
                      className="lv-select mono"
                      value={selectedNote ? `${selectedNote.laneId}:${selectedNote.leafIndex.toString()}` : ''}
                      onChange={(e) => {
                        setSelectedNoteKey(e.target.value)
                        setSwapEscrowShard(pickRandomEscrowShard(NUM_ESCROW_SHARDS))
                      }}
                      disabled={unspentNotes.length === 0}
                    >
                      {unspentNotes.length === 0 ? (
                        <option value="">No unspent notes synced yet</option>
                      ) : (
                        unspentNotes.map((n) => {
                          const mStr = base58Encode(n.mint)
                          const info = getTokenMeta(mStr)
                          const k = `${n.laneId}:${n.leafIndex.toString()}`
                          return (
                            <option key={k} value={k}>
                              Lane #{n.laneId} · Leaf #{n.leafIndex.toString()} · {formatUnits(n.amount, info.decimals)} {info.symbol}
                            </option>
                          )
                        })
                      )}
                    </select>
                    {activePlannedNotes && activePlannedNotes.length === 2 && (
                      <span className="lv-quote-loading mono">
                        Auto-combining 2 {selectedNoteMeta.symbol} notes (Lane #{activePlannedNotes[0]!.laneId} Leaf #
                        {activePlannedNotes[0]!.leafIndex.toString()} + Lane #{activePlannedNotes[1]!.laneId} Leaf #
                        {activePlannedNotes[1]!.leafIndex.toString()} ·{' '}
                        {formatUnits(
                          activePlannedNotes[0]!.amount + activePlannedNotes[1]!.amount,
                          selectedNoteDecimals,
                        )}{' '}
                        {selectedNoteMeta.symbol}) with 2 nullifiers.
                      </span>
                    )}
                  </div>

                  {tab === 'send' && (
                    <>
                      <div className="lv-field-block">
                        <label className="lv-label">Recipient aud1… stealth address</label>
                        <input
                          type="text"
                          className="lv-input mono"
                          value={sendRecipient}
                          onChange={(e) => setSendRecipient(e.target.value)}
                          placeholder="aud1..."
                        />
                      </div>
                      <div className="lv-field-block">
                        <div className="lv-receipt-head">
                          <label className="lv-label">Amount ({selectedNoteMeta.symbol})</label>
                          {selectedNote && (
                            <button
                              type="button"
                              className="lv-inline-link mono"
                              onClick={() =>
                                setSendAmount(formatUnitsExact(maxSendNet, selectedNoteMeta.decimals))
                              }
                            >
                              Max ({formatUnits(maxSendNet, selectedNoteMeta.decimals)})
                            </button>
                          )}
                        </div>
                        <input
                          type="text"
                          inputMode="decimal"
                          className="lv-input lv-amount-big mono"
                          value={sendAmount}
                          onChange={(e) => setSendAmount(e.target.value)}
                          placeholder="0.01"
                        />
                      </div>
                      {useRelayer && sendFeePreview && (
                        <div className="lv-quote-card">
                          <div className="lv-quote-head">
                            <span>
                              Relayer fee preview ·{' '}
                              {sendFeePreview.billingMode === 'self_paying' ? 'Self-paying' : 'Sponsored'}
                            </span>
                          </div>
                          <p className="lv-quote-loading mono">
                            Flat fee: {formatUnits(sendFeePreview.relayerFee, selectedNoteMeta.decimals)}{' '}
                            {selectedNoteMeta.symbol} · private amount omitted from quote · uniform 3-output mask
                          </p>
                        </div>
                      )}
                      <label className="lv-checkbox-card">
                        <input
                          type="checkbox"
                          checked={economyMode}
                          onChange={(e) => setEconomyMode(e.target.checked)}
                        />
                        <div>
                          <span className="lv-checkbox-title">Economy mode (1 nullifier on single-note spends)</span>
                          <span>
                            Saves ~0.00089 SOL in permanent NullifierPDA rent on 1-note spends by omitting the dummy second nullifier.
                            Tradeoff: on-chain observers can distinguish 1-input spends from 2-input merges. Disabled automatically on 2-note spends.
                          </span>
                        </div>
                      </label>
                      <button
                        type="button"
                        className="btn-primary lv-submit-btn"
                        disabled={busy || !selectedNote || !sendRecipient.trim()}
                        onClick={() => handleJoinSplitAction('send')}
                      >
                        {busy ? <Loader2 size={15} className="spin" /> : <Send size={15} />}
                        Prove 192 B Groth16 &amp; send privately
                      </button>
                    </>
                  )}

                  {tab === 'swap' && (
                    <>
                      {isSelectedNoteNativeSol && (
                        <div className="lv-notice-bar is-warn">
                          <AlertCircle size={14} />
                          <span style={{ flex: 1 }}>
                            Jupiter <code>ExecViaEscrow</code> routes SPL / WSOL / Token-2022 notes from isolated escrow ATAs.
                            Select a shielded <span className="lv-strong">WSOL</span>, <span className="lv-strong">SPL</span>, or <span className="lv-strong">Token-2022</span> note, or shield SOL as WSOL using <span className="lv-strong">Wrap SOL &amp; shield as WSOL</span> on the Shield tab.
                          </span>
                        </div>
                      )}
                      <div className="lv-field-block">
                        <label className="lv-label">Output token mint ({swapOutMeta.symbol})</label>
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
                        />
                      </div>
                      <div className="lv-field-block">
                        <div className="lv-receipt-head">
                          <label className="lv-label">Swap input amount ({selectedNoteMeta.symbol})</label>
                          {selectedNote && !isSelectedNoteNativeSol && (
                            <button
                              type="button"
                              className="lv-inline-link mono"
                              onClick={() =>
                                setSwapAmount(formatUnitsExact(maxSpendableNotePair, selectedNoteMeta.decimals))
                              }
                            >
                              Max ({formatUnits(maxSpendableNotePair, selectedNoteMeta.decimals)})
                            </button>
                          )}
                        </div>
                        <input
                          type="text"
                          inputMode="decimal"
                          className="lv-input lv-amount-big mono"
                          value={swapAmount}
                          onChange={(e) => setSwapAmount(e.target.value)}
                          placeholder="0.05"
                          disabled={isSelectedNoteNativeSol}
                        />
                      </div>
                      <div className="lv-field-block">
                        <label className="lv-label">Slippage tolerance (bps)</label>
                        <input
                          type="number"
                          className="lv-input mono"
                          value={swapSlippageBps}
                          min={10}
                          max={1500}
                          onChange={(e) => setSwapSlippageBps(Number(e.target.value) || 100)}
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
                          <span>Atomic post-CPI deduction from received output tokens when relayed with a non-zero relayer fee, with no upfront SOL needed.</span>
                        </div>
                      </label>
                      <label className="lv-checkbox-card">
                        <input
                          type="checkbox"
                          checked={economyMode}
                          onChange={(e) => setEconomyMode(e.target.checked)}
                        />
                        <div>
                          <span className="lv-checkbox-title">Economy mode (1 nullifier on single-note spends)</span>
                          <span>
                            Saves ~0.00089 SOL in permanent NullifierPDA rent on 1-note spends by omitting the dummy second nullifier.
                            Disabled automatically when combining 2 notes.
                          </span>
                        </div>
                      </label>
                      <div className="lv-quote-card">
                        <div className="lv-quote-head">
                          <span>
                            Live escrow quote
                            {swapQuoteProvider ? ` · ${swapQuoteProvider}` : ''}
                          </span>
                          {swapQuoteLoading && <Loader2 size={13} className="spin" />}
                        </div>
                        {swapQuoteOut ? (
                          <div className="lv-quote-pair">
                            <div>
                              <span>Estimated output</span>
                              <span className="lv-quote-val is-pine mono">
                                {formatUnits(BigInt(swapQuoteOut), swapOutMeta.decimals)}{' '}
                                {swapOutMeta.symbol}
                              </span>
                            </div>
                          </div>
                        ) : (
                          <p className="lv-quote-loading">
                            {isSelectedNoteNativeSol
                              ? 'Select a shielded WSOL / SPL / Token-2022 note to quote a PDA-safe route.'
                              : 'Enter an amount to fetch a live PDA-safe route.'}
                          </p>
                        )}
                        {swapInputFeeBps > 0 && swapQuoteNetIn && (
                          <p className="lv-quote-loading mono">
                            Token-2022 input fee ({(swapInputFeeBps / 100).toFixed(2)}%) deducted before route · net input{' '}
                            {formatUnits(BigInt(swapQuoteNetIn), selectedNoteDecimals)} {selectedNoteMeta.symbol}
                          </p>
                        )}
                      </div>
                      <button
                        type="button"
                        className="btn-primary lv-submit-btn"
                        disabled={busy || !selectedNote || isSelectedNoteNativeSol || !swapQuoteOut}
                        onClick={handleShieldedSwap}
                      >
                        {busy ? <Loader2 size={15} className="spin" /> : <ArrowLeftRight size={15} />}
                        Prove 192 B Groth16 &amp; execute shielded swap
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
                          onChange={(e) => setWithdrawRecipient(e.target.value)}
                          placeholder="Solana public address"
                        />
                      </div>
                      <div className="lv-field-block">
                        <div className="lv-receipt-head">
                          <label className="lv-label">Withdraw amount ({selectedNoteMeta.symbol})</label>
                          {selectedNote && (
                            <button
                              type="button"
                              className="lv-inline-link mono"
                              onClick={() =>
                                setWithdrawAmount(formatUnitsExact(maxWithdrawNet, selectedNoteMeta.decimals))
                              }
                            >
                              Max (net of fee: {formatUnits(maxWithdrawNet, selectedNoteMeta.decimals)})
                            </button>
                          )}
                        </div>
                        <input
                          type="text"
                          inputMode="decimal"
                          className="lv-input lv-amount-big mono"
                          value={withdrawAmount}
                          onChange={(e) => setWithdrawAmount(e.target.value)}
                          placeholder="0.01"
                        />
                      </div>
                      {useRelayer && withdrawFeePreview && (
                        <div className="lv-quote-card">
                          <div className="lv-quote-head">
                            <span>
                              Relayer fee preview ·{' '}
                              {withdrawFeePreview.billingMode === 'self_paying' ? 'Self-paying' : 'Sponsored'}
                            </span>
                          </div>
                          <p className="lv-quote-loading mono">
                            Fee: {formatUnits(withdrawFeePreview.relayerFee, selectedNoteMeta.decimals)}{' '}
                            {selectedNoteMeta.symbol} · {withdrawFeePreview.reason}
                          </p>
                        </div>
                      )}
                      {selectedNoteMintStr === WSOL_MINT && (
                        <label className="lv-checkbox-card">
                          <input
                            type="checkbox"
                            checked={unwrapWsol}
                            onChange={(e) => setUnwrapWsol(e.target.checked)}
                          />
                          <div>
                            <span className="lv-checkbox-title">Atomic WSOL → Native SOL unwrap (WITHDRAW_FLAG_UNWRAP_WSOL)</span>
                            <span>Uses a 1-shot <code>audren_v2_unwrap</code> PDA and works even while the pool is paused.</span>
                          </div>
                        </label>
                      )}
                      <label className="lv-checkbox-card">
                        <input
                          type="checkbox"
                          checked={economyMode}
                          onChange={(e) => setEconomyMode(e.target.checked)}
                        />
                        <div>
                          <span className="lv-checkbox-title">Economy mode (1 nullifier on single-note spends)</span>
                          <span>
                            Saves ~0.00089 SOL in permanent NullifierPDA rent on 1-note spends by omitting the dummy second nullifier.
                            Tradeoff: on-chain observers can distinguish 1-input spends from 2-input merges. Disabled automatically on 2-note spends.
                          </span>
                        </div>
                      </label>
                      <button
                        type="button"
                        className="btn-primary lv-submit-btn"
                        disabled={busy || !selectedNote || !withdrawRecipient.trim()}
                        onClick={() => handleJoinSplitAction('withdraw')}
                      >
                        {busy ? <Loader2 size={15} className="spin" /> : <ArrowUpFromLine size={15} />}
                        Prove 192 B Groth16 &amp; withdraw
                      </button>
                    </>
                  )}
                </>
              )}

              {tab === 'compliance' && (
                <>
                  <div className="lv-receipt-drawer">
                    <div className="lv-receipt-head">
                      <span className="lv-box-title">Mode 1 · Single-note selective disclosure proof</span>
                      <button
                        type="button"
                        className="lv-mini-btn"
                        disabled={!selectedNote}
                        onClick={handleGenerateReceipt}
                      >
                        Export selected note proof
                      </button>
                    </div>
                    <p className="lv-receipt-copy">
                      Proves one note&apos;s mint, amount, and commitment without revealing your viewing key, spend key, or any other note.
                    </p>
                    <textarea
                      className="lv-input mono"
                      rows={5}
                      value={receiptJson}
                      onChange={(e) => {
                        setReceiptJson(e.target.value)
                        setReceiptVerdict(null)
                      }}
                      placeholder="Paste a SelectiveDisclosureProof JSON payload to verify…"
                    />
                    <div className="lv-receipt-actions">
                      <button type="button" className="lv-mini-btn" onClick={handleVerifyReceipt}>
                        <ShieldCheck size={13} /> Verify receipt
                      </button>
                      {receiptVerdict && (
                        <span className={`lv-receipt-verdict ${receiptVerdict === 'valid' ? 'is-valid' : 'is-forged'}`}>
                          {receiptVerdict === 'valid'
                            ? 'Valid · Poseidon commitment matches'
                            : 'Invalid · Commitment mismatch or malformed'}
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
                            onClick={() => setSessionIndex((i) => Math.max(0, i - 1))}
                          >
                            −
                          </button>
                          <button
                            type="button"
                            className="lv-mini-btn"
                            onClick={() => setSessionIndex((i) => i + 1)}
                          >
                            +
                          </button>
                        </div>
                      </div>
                      <p>
                        Deterministic Ed25519 keypair for stateful lending, perps, or CLMM positions.{' '}
                        <span className="lv-strong">Boundary:</span> funding via relayed Withdraw breaks the link to your main wallet, while external DeFi actions executed by this session wallet remain public on Solana.
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
                    <p>Export or restore your Audren master seed. Local IndexedDB cache can also be cleared anytime.</p>
                    <div className="lv-backup-row">
                      <input
                        type="password"
                        className="lv-input"
                        value={backupPassphrase}
                        onChange={(e) => setBackupPassphrase(e.target.value)}
                        placeholder="Passphrase (min 8 chars)"
                      />
                      <button type="button" className="lv-mini-btn" onClick={handleExportBackup}>
                        <Download size={13} /> Export
                      </button>
                      <button
                        type="button"
                        className="lv-mini-btn"
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
                        onClick={async () => {
                          await clearEncryptedCompactStore(keys.spendPkBytes, cluster, 0, walletScope)
                          setBackupStatus('Cleared local encrypted IndexedDB CompactWalletStore cache')
                        }}
                      >
                        Clear cache
                      </button>
                    </div>
                    {backupStatus && <p className="lv-backup-status mono">{backupStatus}</p>}
                  </div>
                </>
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
                    {lastReceipt.relayed ? 'Zero-signer relayed' : 'Direct self-pay'}
                    {lastReceipt.proverMs !== undefined ? ` · WASM prover ${lastReceipt.proverMs} ms` : ''}
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
