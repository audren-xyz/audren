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
  CLASSIC_TOKEN_PROGRAM_ID,
  CompactWalletStore,
  MEMO_NOTES_PER_PAGE,
  NATIVE_SOL_MINT_BYTES,
  NF_PER_PAGE,
  NUM_ESCROW_SHARDS,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_NULLIFIER,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  SUBROOTS_PER_PAGE,
  SUBTREE_LEAVES,
  WSOL_MINT,
  AudrenRelayClient,
  audrenInstructionToSolana,
  base58Decode,
  base58Encode,
  buildDepositSolInstruction,
  buildDepositSplInstruction,
  buildExecViaEscrowInstruction,
  buildJoinsplitInstruction,
  buildOpenPageInstruction,
  bytes32ToFrMasked,
  computeExecCtxHash,
  computeJoinsplitCtxHash,
  decodePoolState,
  deriveAssetId,
  deriveAssociatedTokenAddressSync,
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
  prepareDynamicSwapMemo,
  reconstructWitness,
  syncCompactStoreWithRpc,
  toBase64,
  toHex,
  verifySelectiveDisclosureProof,
  type AccountBatchFetcher,
  type AudrenInstruction,
  type AudrenKeys,
  type OwnedNote,
  type SelectiveDisclosureProof,
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

interface PublicTokenBalance {
  ata: string
  mint: string
  amount: string
  decimals: number
  uiAmountString: string
  tokenProgram: string
}

interface PoolSummary {
  initialized: boolean
  activeLanes: number
  paused: boolean
  totalNotes: string
  totalNullifiers: string
  solVaultLamports: number
  latestCheckpointSlot: number | null
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

const NATIVE_SOL_MINT_STR = base58Encode(NATIVE_SOL_MINT_BYTES)

function mintLabel(mintStr: string): { symbol: string; decimals: number } {
  if (mintStr === NATIVE_SOL_MINT_STR) return { symbol: 'SOL', decimals: 9 }
  if (mintStr === WSOL_MINT) return { symbol: 'WSOL', decimals: 9 }
  if (mintStr === USDC_MAINNET_MINT) return { symbol: 'USDC', decimals: 6 }
  return { symbol: shortHash(mintStr, 4, 4), decimals: 6 }
}

function createWorkerBatchFetcher(cluster: SolanaCluster): AccountBatchFetcher {
  return async (addresses: readonly string[]) => {
    const out: (Uint8Array | null)[] = new Array(addresses.length).fill(null)
    for (let off = 0; off < addresses.length; off += 100) {
      const chunk = addresses.slice(off, off + 100)
      const res = await fetch('/api/rpc/accounts', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ cluster, addresses: chunk }),
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

export function LiveWalletVault() {
  const [cluster, setCluster] = useState<SolanaCluster>('devnet')
  const [discovered, setDiscovered] = useState<DiscoveredSolanaWallet[]>([])
  const [connected, setConnected] = useState<ConnectedSolanaWallet | null>(null)
  const [connecting, setConnecting] = useState(false)

  const [seedBytes, setSeedBytes] = useState<Uint8Array | null>(null)
  const [keys, setKeys] = useState<AudrenKeys | null>(null)
  const [store, setStore] = useState<CompactWalletStore | null>(null)
  const [unspentNotes, setUnspentNotes] = useState<OwnedNote[]>([])
  const [syncing, setSyncing] = useState(false)
  const [strangerView, setStrangerView] = useState(false)

  const [poolInfo, setPoolInfo] = useState<PoolSummary | null>(null)
  const [pubSolLamports, setPubSolLamports] = useState<bigint>(0n)
  const [pubTokens, setPubTokens] = useState<PublicTokenBalance[]>([])

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

  const [depositMint, setDepositMint] = useState<string>(NATIVE_SOL_MINT_STR)
  const [depositAmount, setDepositAmount] = useState<string>('0.05')
  const [feeFromAmount, setFeeFromAmount] = useState<boolean>(false)

  const [selectedNoteKey, setSelectedNoteKey] = useState<string>('')
  const [sendRecipient, setSendRecipient] = useState<string>('')
  const [sendAmount, setSendAmount] = useState<string>('')

  const [swapOutMint, setSwapOutMint] = useState<string>(USDC_MAINNET_MINT)
  const [swapAmount, setSwapAmount] = useState<string>('')
  const [swapSlippageBps, setSwapSlippageBps] = useState<number>(100)
  const [swapFeeOnOutput, setSwapFeeOnOutput] = useState<boolean>(true)
  const [swapQuoteOut, setSwapQuoteOut] = useState<string | null>(null)
  const [swapQuoteLoading, setSwapQuoteLoading] = useState(false)
  const [swapQuoteRaw, setSwapQuoteRaw] = useState<unknown>(null)

  const [withdrawRecipient, setWithdrawRecipient] = useState<string>('')
  const [withdrawAmount, setWithdrawAmount] = useState<string>('')
  const [unwrapWsol, setUnwrapWsol] = useState<boolean>(true)

  const [sessionIndex, setSessionIndex] = useState<number>(0)
  const [receiptJson, setReceiptJson] = useState<string>('')
  const [receiptVerdict, setReceiptVerdict] = useState<'valid' | 'invalid' | null>(null)
  const [showFvk, setShowFvk] = useState(false)
  const [backupPassphrase, setBackupPassphrase] = useState('')
  const [backupStatus, setBackupStatus] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement | null>(null)

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

  useEffect(() => {
    if (!connected) return
    const match = discovered.find((d) => d.name === connected.name)
    if (!match) return
    return subscribeWalletStandardAccounts(match, (next) => {
      setConnected(next)
      setWithdrawRecipient((prev) => prev || next.address)
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
          const pj = (await poolRes.json()) as {
            initialized?: boolean
            activeLanes?: number
            paused?: boolean
            totalNotes?: string
            totalNullifiers?: string
            solVaultLamports?: number
            latestCheckpoint?: { slotIndex: number } | null
          }
          setPoolInfo({
            initialized: Boolean(pj.initialized),
            activeLanes: pj.activeLanes ?? 4,
            paused: Boolean(pj.paused),
            totalNotes: pj.totalNotes ?? '0',
            totalNullifiers: pj.totalNullifiers ?? '0',
            solVaultLamports: pj.solVaultLamports ?? 0,
            latestCheckpointSlot: pj.latestCheckpoint?.slotIndex ?? null,
          })
        }
      } catch {
        setPoolInfo(null)
      }

      if (!ownerAddr) return
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

  const connectedAddress = connected?.address ?? null

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

  const syncVault = useCallback(
    async (activeKeys: AudrenKeys, targetCluster: SolanaCluster, existingStore: CompactWalletStore | null) => {
      setSyncing(true)
      setErrorMsg(null)
      try {
        let curStore = existingStore
        if (!curStore) {
          curStore = (await loadEncryptedCompactStore(activeKeys, targetCluster, 0)) ?? new CompactWalletStore(0)
        }
        const fvk = exportFullViewingKey(activeKeys)
        const fetcher = createWorkerBatchFetcher(targetCluster)
        try {
          await syncCompactStoreWithRpc({ store: curStore, fvk, fetchBatch: fetcher })
          await saveEncryptedCompactStore(activeKeys, targetCluster, 0, curStore)
        } catch (syncErr) {
          const msg = syncErr instanceof Error ? syncErr.message : String(syncErr)
          setStatusMsg(`Vault ready (RPC sync skipped: ${msg})`)
        }
        const unspent = curStore.unspentNotes()
        setStore(curStore)
        setUnspentNotes(unspent)
        if (unspent.length > 0) {
          setSelectedNoteKey((prev) => prev || `${unspent[0]!.laneId}:${unspent[0]!.leafIndex.toString()}`)
        }
      } finally {
        setSyncing(false)
      }
    },
    [],
  )

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
    setStore(null)
    setUnspentNotes([])
    setPubSolLamports(0n)
    setPubTokens([])
  }

  const unlockFromSeed = useCallback(
    async (seed: Uint8Array, targetCluster: SolanaCluster) => {
      const derived = deriveKeysFromSeed(seed)
      setSeedBytes(seed)
      setKeys(derived)
      await syncVault(derived, targetCluster, null)
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
      await unlockFromSeed(digest, cluster)
      setStatusMsg('Audren vault unlocked from wallet signature')
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
      await unlockFromSeed(freshSeed, cluster)
      setStatusMsg('Ephemeral local Audren vault created — export an encrypted backup before closing')
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

  // Live swap quote effect — strictly primitive dependencies!
  const fetchSwapQuote = useCallback(
    async (
      inMint: string,
      outMint: string,
      amountStr: string,
      slippage: number,
      targetCluster: SolanaCluster,
      activeRelay: string,
      relayed: boolean,
    ) => {
      const { decimals } = mintLabel(inMint)
      const routerInMint = inMint === NATIVE_SOL_MINT_STR ? WSOL_MINT : inMint
      const rawAmt = parseUnits(amountStr, decimals)
      if (!rawAmt || rawAmt <= 0n || routerInMint === outMint) {
        setSwapQuoteOut(null)
        setSwapQuoteRaw(null)
        return
      }
      setSwapQuoteLoading(true)
      try {
        if (relayed) {
          const client = new AudrenRelayClient(activeRelay)
          const resp = (await client.quoteSwap({
            cluster: targetCluster,
            inputMint: routerInMint,
            outputMint: outMint,
            amount: rawAmt.toString(),
            slippageBps: slippage,
            provider: 'auto',
          })) as { quote?: { outAmount?: string; rawQuote?: unknown }; outAmount?: string }
          const outAmt =
            typeof resp.quote?.outAmount === 'string'
              ? resp.quote.outAmount
              : typeof resp.outAmount === 'string'
                ? resp.outAmount
                : null
          setSwapQuoteOut(outAmt)
          setSwapQuoteRaw(resp.quote?.rawQuote ?? resp)
        } else {
          const res = await fetch('/api/jupiter/quote', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              inputMint: routerInMint,
              outputMint: outMint,
              amount: rawAmt.toString(),
              slippageBps: slippage,
            }),
          })
          const quote = (await res.json()) as Record<string, unknown>
          if (!res.ok) throw new Error(String(quote.error ?? `Quote HTTP ${res.status}`))
          const outAmt = typeof quote.outAmount === 'string' ? quote.outAmount : null
          setSwapQuoteOut(outAmt)
          setSwapQuoteRaw(quote)
        }
      } catch {
        setSwapQuoteOut(null)
        setSwapQuoteRaw(null)
      } finally {
        setSwapQuoteLoading(false)
      }
    },
    [],
  )

  useEffect(() => {
    if (tab !== 'swap' || !swapAmount.trim()) return
    const timer = setTimeout(() => {
      fetchSwapQuote(
        selectedNoteMintStr,
        swapOutMint,
        swapAmount,
        swapSlippageBps,
        cluster,
        relayUrl,
        useRelayer,
      )
    }, 350)
    return () => clearTimeout(timer)
  }, [tab, selectedNoteMintStr, swapOutMint, swapAmount, swapSlippageBps, cluster, relayUrl, useRelayer, fetchSwapQuote])

  const signAndBroadcastDirect = async (
    ixs: AudrenInstruction[],
    computeUnitLimit: number,
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
    })
    const [signed] = await signCompiledTransactionsWithWallet(connected, cluster, [unsigned])
    if (!signed) throw new Error('Wallet returned no signed transaction')
    const [sent] = await sendAndConfirmSignedTransactions(cluster, [signed])
    if (!sent) throw new Error('Broadcast returned no signature')
    return { signature: sent.signature, slot: sent.slot }
  }

  const handleDeposit = async () => {
    if (!connected || !keys) return
    setBusy(true)
    setErrorMsg(null)
    setStatusMsg(null)
    try {
      const isSol = depositMint === NATIVE_SOL_MINT_STR
      const tok = pubTokens.find((t) => t.mint === depositMint)
      const decimals = isSol ? 9 : tok?.decimals ?? 6
      const amount = parseUnits(depositAmount, decimals)
      if (!amount || amount <= 0n) throw new Error('Enter a valid positive amount')

      const fetcher = createWorkerBatchFetcher(cluster)
      const [poolRaw] = await fetcher([AUDREN.pool0Pda])
      if (!poolRaw) throw new Error(`Pool #0 is not initialized on ${cluster} yet`)
      const pool = decodePoolState(poolRaw)
      const poolSnap = (await fetch(`/api/pool?cluster=${cluster}&poolId=0`).then((r) => r.json())) as {
        totalNotes?: string
        deterministicNoteRentFee?: string
        lanes?: Array<{ laneId: number; nextLeaf: string } | null>
      }
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

      const mintBytes = isSol ? NATIVE_SOL_MINT_BYTES : base58Decode(depositMint)
      const detNoteFee = BigInt(poolSnap.deterministicNoteRentFee ?? pool.noteRentFee.toString())
      const committedAmount = isSol && feeFromAmount ? amount - detNoteFee : amount
      if (committedAmount <= 0n) {
        throw new Error(`Deposit amount must exceed deterministic note rent fee (${formatUnits(detNoteFee, 9)} SOL)`)
      }
      const { tweak, blinding, memo90 } = encryptNoteMemo(
        keys.viewPk,
        crypto.getRandomValues(new Uint8Array(32)),
        committedAmount,
        mintBytes,
      )
      const stealthOwner = deriveStealthOwner(keys.spendPk, tweak)

      if (isSol) {
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
        const tokenProgram = tok?.tokenProgram ?? CLASSIC_TOKEN_PROGRAM_ID
        const vaultAuth = deriveVaultAuthPdaSync(0, AUDREN_PROGRAM_ID).address
        const depositorAta = tok?.ata ?? deriveAssociatedTokenAddressSync(connected.address, depositMint, tokenProgram).address
        const vaultAta = deriveAssociatedTokenAddressSync(vaultAuth, depositMint, tokenProgram).address
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
            mint: depositMint,
            tokenProgram,
            amount,
            stealthOwner,
            blinding,
            memo90,
          }),
        )
      }

      setStatusMsg('Waiting for wallet approval…')
      const res = await signAndBroadcastDirect(ixs, 250_000)
      setLastReceipt({
        kind: isSol ? 'DepositSol (Tag 3)' : 'DepositSpl (Tag 4)',
        signature: res.signature,
        cluster,
        relayed: false,
        summary: `Shielded ${depositAmount} ${mintLabel(depositMint).symbol} into Lane #${laneId}`,
      })
      setStatusMsg('Deposit confirmed — syncing CompactWalletStore…')
      await syncVault(keys, cluster, store)
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
    setStatusMsg('Reconstructing 4-ary Depth-20 Merkle witness from ordinary RPC…')
    try {
      const mintStr = base58Encode(selectedNote.mint)
      const { decimals, symbol } = mintLabel(mintStr)
      const amount = parseUnits(mode === 'send' ? sendAmount : withdrawAmount, decimals)
      if (!amount || amount <= 0n || amount > selectedNote.amount) {
        throw new Error(`Amount must be between 0 and ${formatUnits(selectedNote.amount, decimals)} ${symbol}`)
      }

      const fetcher = createWorkerBatchFetcher(cluster)
      const snap = (await fetch(`/api/pool?cluster=${cluster}&poolId=0`).then((r) => r.json())) as {
        initialized?: boolean
        activeLanes?: number
        latestCheckpoint?: { slotIndex: number } | null
        lanes?: Array<{ laneId: number; nextLeaf: string; nfCount: string } | null>
      }
      if (!snap.initialized || !snap.latestCheckpoint) {
        throw new Error(`No RootCheckpoint found on ${cluster} Pool #0`)
      }
      const ckptSlotIdx = snap.latestCheckpoint.slotIndex
      const { ckpt, superRoot, path } = await reconstructWitness({
        fetchBatch: fetcher,
        poolId: 0,
        ckptSlotIdx,
        laneId: selectedNote.laneId,
        leafIdx: selectedNote.leafIndex,
      })

      const outLaneId = (selectedNote.laneId + 1) % (snap.activeLanes ?? 4)
      const outLane = snap.lanes?.[outLaneId]
      const outNextLeaf = BigInt(outLane?.nextLeaf ?? '0')
      const outNfCount = BigInt(outLane?.nfCount ?? '0')
      const outSubSeq = outNextLeaf / BigInt(SUBTREE_LEAVES)
      const outRootSeq = outSubSeq / BigInt(SUBROOTS_PER_PAGE)
      const outMemoSeq = outNextLeaf / BigInt(MEMO_NOTES_PER_PAGE)
      const outNfSeq = outNfCount / BigInt(NF_PER_PAGE)

      let payerPubkey = connected?.address ?? ''
      let relayerFeeAmount = 0n
      let relayerFeeRecipient: string | null = null
      let feeShieldedAddr: string | null = null
      const relayClient = new AudrenRelayClient(relayUrl)

      if (useRelayer) {
        setStatusMsg('Querying Privacy Relayer fee quote…')
        const info = await relayClient.getInfo(cluster)
        if (!info.relayerPubkey) throw new Error(`Relayer at ${relayUrl} has no fee payer for ${cluster}`)
        payerPubkey = info.relayerPubkey
        const fq = await relayClient.getFeeQuote({
          cluster,
          op: mode === 'send' ? 'transfer' : 'withdraw',
          mint: mintStr,
          amount: amount.toString(),
          unwrapWsol: mode === 'withdraw' && unwrapWsol && mintStr === WSOL_MINT,
          outputCount: mode === 'send' ? 3 : 2,
        })
        relayerFeeAmount = BigInt(fq.relayerFee || '0')
        relayerFeeRecipient = fq.feeRecipient
        feeShieldedAddr = fq.feeShieldedAddress
      } else if (!connected) {
        throw new Error('Enable Privacy Relayer or connect a Solana wallet for Direct Self-Pay')
      }

      const assetId = deriveAssetId(selectedNote.mint)
      const noteTweak = frFromBeBytesStrict(selectedNote.tweak)
      const noteBlinding = frFromBeBytesStrict(selectedNote.blinding)
      const dummyIn = dummyInputWitness(keys.spendSk, assetId, randomFr())

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
        const mRec = encryptNoteMemo(rec.viewPk, crypto.getRandomValues(new Uint8Array(32)), amount, selectedNote.mint)
        const recOwner = deriveStealthOwner(frFromBeBytesStrict(rec.spendPk), mRec.tweak)
        outputs[0] = { stealthOwner: recOwner, assetId, amount, blinding: mRec.blinding }
        outputMask |= 1
        memos.push(mRec.memo90)

        const changeAmt = selectedNote.amount - amount - effectiveShieldedFee
        if (changeAmt < 0n) throw new Error('Insufficient note balance to cover amount + relayer fee')
        if (changeAmt > 0n) {
          const mCh = encryptNoteMemo(keys.viewPk, crypto.getRandomValues(new Uint8Array(32)), changeAmt, selectedNote.mint)
          const chOwner = deriveStealthOwner(keys.spendPk, mCh.tweak)
          outputs[1] = { stealthOwner: chOwner, assetId, amount: changeAmt, blinding: mCh.blinding }
          outputMask |= 2
          memos.push(mCh.memo90)
        }

        if (effectiveShieldedFee > 0n && feeShieldedAddr) {
          const feeRec = parseAudrenAddress(feeShieldedAddr)
          const mFee = encryptNoteMemo(feeRec.viewPk, crypto.getRandomValues(new Uint8Array(32)), effectiveShieldedFee, selectedNote.mint)
          const feeOwner = deriveStealthOwner(frFromBeBytesStrict(feeRec.spendPk), mFee.tweak)
          outputs[2] = { stealthOwner: feeOwner, assetId, amount: effectiveShieldedFee, blinding: mFee.blinding }
          outputMask |= 4
          memos.push(mFee.memo90)
        }
      } else {
        const changeAmt = selectedNote.amount - amount - relayerFeeAmount
        if (changeAmt < 0n) throw new Error('Insufficient note balance to cover withdrawal + relayer fee')
        if (changeAmt > 0n) {
          const mCh = encryptNoteMemo(keys.viewPk, crypto.getRandomValues(new Uint8Array(32)), changeAmt, selectedNote.mint)
          const chOwner = deriveStealthOwner(keys.spendPk, mCh.tweak)
          outputs[0] = { stealthOwner: chOwner, assetId, amount: changeAmt, blinding: mCh.blinding }
          outputMask |= 1
          memos.push(mCh.memo90)
        }
      }

      const memosConcat = new Uint8Array(memos.reduce((s, m) => s + m.byteLength, 0))
      let mOff = 0
      for (const m of memos) {
        memosConcat.set(m, mOff)
        mOff += m.byteLength
      }

      const isNativeSol = mintStr === NATIVE_SOL_MINT_STR
      const isWsolUnwrap = mode === 'withdraw' && mintStr === WSOL_MINT && unwrapWsol
      const assetMode =
        mode === 'send'
          ? ASSET_MODE_PRIVATE
          : isNativeSol
            ? ASSET_MODE_SOL
            : ASSET_MODE_SPL
      const pubOutAmt = mode === 'withdraw' ? amount : 0n
      const pubFeeAmt = mode === 'withdraw' ? relayerFeeAmount : 0n
      const pubAssetIdBytes = mode === 'withdraw' ? frToBeBytes(assetId) : new Uint8Array(32)
      const tokenProgram = CLASSIC_TOKEN_PROGRAM_ID
      const rawRecipient = mode === 'withdraw' ? withdrawRecipient.trim() : null
      const recipientPubkey =
        rawRecipient && assetMode === ASSET_MODE_SPL && !isWsolUnwrap
          ? deriveAssociatedTokenAddressSync(rawRecipient, mintStr, tokenProgram).address
          : rawRecipient

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
        omitNf1: true,
        inputs: [
          {
            isDummy: false,
            spendSk: keys.spendSk,
            tweak: noteTweak,
            assetId,
            amount: selectedNote.amount,
            blinding: noteBlinding,
            merklePath: path,
          },
          dummyIn,
        ],
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
        setStatusMsg('Submitting zero-signer proof to Privacy Relayer…')
        const sub = await relayClient.submitRelayedInstruction({
          cluster,
          instructionDataB64: toBase64(ix.data),
          accounts: ix.accounts,
          computeUnitLimit: 320_000,
        })
        signature = sub.signature
      } else {
        const prepPages = await fetcher([
          deriveNfPagePdaSync(0, outLaneId, outNfSeq, AUDREN_PROGRAM_ID).address,
        ])
        const preIxs: AudrenInstruction[] = []
        if (!prepPages[0]) {
          preIxs.push(buildOpenPageInstruction({ poolId: 0, laneId: outLaneId, pageKind: OPEN_PAGE_KIND_NULLIFIER, pageSeq: outNfSeq, payer: payerPubkey }))
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
            ? `Sent ${sendAmount} ${symbol} privately (192 B Groth16 · epoch #${ckpt.epochId.toString()})`
            : `Withdrew ${withdrawAmount} ${symbol}${isWsolUnwrap ? ' (atomic WSOL unwrap)' : ''}`,
      })
      setStatusMsg('Confirmed — syncing CompactWalletStore…')
      await syncVault(keys, cluster, store)
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
      const isNativeSolIn = inMintStr === NATIVE_SOL_MINT_STR
      const routerInMint = isNativeSolIn ? WSOL_MINT : inMintStr
      const { decimals: inDec, symbol: inSym } = mintLabel(inMintStr)
      const amountIn = parseUnits(swapAmount, inDec)
      if (!amountIn || amountIn <= 0n || amountIn > selectedNote.amount) {
        throw new Error('Invalid swap input amount')
      }
      const minOut = (BigInt(swapQuoteOut) * BigInt(10_000 - swapSlippageBps)) / 10_000n
      const escrowShard = Number(selectedNote.leafIndex % BigInt(NUM_ESCROW_SHARDS))

      const relayClient = new AudrenRelayClient(relayUrl)
      let routerProg: string
      let routerAccounts: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }>
      let routerIxData: Uint8Array
      let payerPubkey = connected?.address ?? ''
      let relayerFeeAmount = 0n
      let relayerFeeRecipient: string | null = null

      if (useRelayer) {
        const info = await relayClient.getInfo(cluster)
        if (!info.relayerPubkey) throw new Error(`Relayer missing fee payer for ${cluster}`)
        payerPubkey = info.relayerPubkey
        const fq = await relayClient.getFeeQuote({
          cluster,
          op: 'exec_escrow',
          mint: swapFeeOnOutput ? swapOutMint : routerInMint,
          amount: swapFeeOnOutput ? swapQuoteOut : amountIn.toString(),
          feeOnOutput: swapFeeOnOutput,
        })
        relayerFeeAmount = BigInt(fq.relayerFee || '0')
        relayerFeeRecipient = fq.feeRecipient
        const built = await relayClient.buildSwapInstructions({
          provider: 'jupiter',
          quoteResponse: swapQuoteRaw,
          inputMint: routerInMint,
          outputMint: swapOutMint,
          cluster,
          shardId: escrowShard,
        })
        routerProg = built.swapInstruction.programId
        routerAccounts = built.swapInstruction.accounts
        routerIxData = fromBase64(built.swapInstruction.data)
      } else {
        if (!connected) throw new Error('Connect a wallet or enable Privacy Relayer')
        const res = await fetch('/api/jupiter/swap-instructions', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            quoteResponse: swapQuoteRaw,
            poolId: 0,
            shardId: escrowShard,
            inputMint: routerInMint,
            outputMint: swapOutMint,
          }),
        })
        const built = (await res.json()) as {
          swapInstruction?: { programId: string; accounts: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }>; data: string }
          error?: string
        }
        if (!res.ok || !built.swapInstruction) throw new Error(built.error ?? 'Failed to build swap route')
        routerProg = built.swapInstruction.programId
        routerAccounts = built.swapInstruction.accounts
        routerIxData = fromBase64(built.swapInstruction.data)
      }

      const fetcher = createWorkerBatchFetcher(cluster)
      const snap = (await fetch(`/api/pool?cluster=${cluster}&poolId=0`).then((r) => r.json())) as {
        initialized?: boolean
        activeLanes?: number
        latestCheckpoint?: { slotIndex: number } | null
        lanes?: Array<{ laneId: number; nextLeaf: string; nfCount: string } | null>
      }
      if (!snap.initialized || !snap.latestCheckpoint) throw new Error('Pool checkpoint missing')
      const ckptSlotIdx = snap.latestCheckpoint.slotIndex
      const { superRoot, path } = await reconstructWitness({
        fetchBatch: fetcher,
        poolId: 0,
        ckptSlotIdx,
        laneId: selectedNote.laneId,
        leafIdx: selectedNote.leafIndex,
      })

      const outLaneId = (selectedNote.laneId + 1) % (snap.activeLanes ?? 4)
      const outLane = snap.lanes?.[outLaneId]
      const outNextLeaf = BigInt(outLane?.nextLeaf ?? '0')
      const outNfCount = BigInt(outLane?.nfCount ?? '0')
      const outSubSeq = outNextLeaf / BigInt(SUBTREE_LEAVES)
      const outRootSeq = outSubSeq / BigInt(SUBROOTS_PER_PAGE)
      const outMemoSeq = outNextLeaf / BigInt(MEMO_NOTES_PER_PAGE)
      const outNfSeq = outNfCount / BigInt(NF_PER_PAGE)

      const assetIn = deriveAssetId(selectedNote.mint)
      const outMintBytes = base58Decode(swapOutMint)
      const assetOut = deriveAssetId(outMintBytes)
      const noteTweak = frFromBeBytesStrict(selectedNote.tweak)
      const noteBlinding = frFromBeBytesStrict(selectedNote.blinding)

      const inFee = swapFeeOnOutput ? 0n : relayerFeeAmount
      const changeAmt = selectedNote.amount - amountIn - inFee
      if (changeAmt < 0n) throw new Error('Insufficient note balance for swap + fee')

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

      const dyn = prepareDynamicSwapMemo(keys.viewPk, crypto.getRandomValues(new Uint8Array(32)))
      const outStealthOwner = deriveStealthOwner(keys.spendPk, dyn.tweak)

      const inKind: 0 | 1 = isNativeSolIn ? 0 : 1
      const ctxHash = computeExecCtxHash({
        poolId: 0,
        outLaneId,
        escrowShard,
        changeMask,
        inKind,
        outKind: 1,
        feeOnOutput: swapFeeOnOutput,
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

      setStatusMsg('Generating 192-byte BN254 Groth16 proof in browser WASM…')
      const { result, elapsedMs } = await proveJoinsplitInBrowser({
        superRoot,
        txAssetId: assetIn,
        publicAssetId: assetIn,
        publicAmountOut: amountIn,
        relayerFeeAmount: inFee,
        ctxHash,
        omitNf1: true,
        inputs: [
          {
            isDummy: false,
            spendSk: keys.spendSk,
            tweak: noteTweak,
            assetId: assetIn,
            amount: selectedNote.amount,
            blinding: noteBlinding,
            merklePath: path,
          },
          dummyInputWitness(keys.spendSk, assetIn, randomFr()),
        ],
        outputs,
      })

      const vaultAuth = deriveVaultAuthPdaSync(0, AUDREN_PROGRAM_ID).address
      const escrowPda = deriveEscrowPdaSync(0, escrowShard, AUDREN_PROGRAM_ID).address
      const ix = buildExecViaEscrowInstruction({
        poolId: 0,
        outLaneId,
        ckptSlotIdx,
        escrowShard,
        outSubSeq,
        outRootSeq,
        outMemoSeq,
        outNfSeq,
        payer: payerPubkey,
        proof192: result.proof192,
        nf0: result.nf0,
        nf1: result.nf1,
        cm0: result.cm0,
        cm1: result.cm1,
        cm2: result.cm2,
        changeMask,
        inKind,
        outKind: 1,
        feeOnOutput: swapFeeOnOutput,
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
        inSpl: isNativeSolIn
          ? null
          : {
              mint: inMintStr,
              vaultAta: deriveAssociatedTokenAddressSync(vaultAuth, inMintStr, CLASSIC_TOKEN_PROGRAM_ID).address,
              escrowAta: deriveAssociatedTokenAddressSync(escrowPda, inMintStr, CLASSIC_TOKEN_PROGRAM_ID).address,
              tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
            },
        outSpl: {
          mint: swapOutMint,
          vaultAta: deriveAssociatedTokenAddressSync(vaultAuth, swapOutMint, CLASSIC_TOKEN_PROGRAM_ID).address,
          escrowAta: deriveAssociatedTokenAddressSync(escrowPda, swapOutMint, CLASSIC_TOKEN_PROGRAM_ID).address,
          tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
        },
        relayerFeeRecipient: relayerFeeAmount > 0n ? relayerFeeRecipient : null,
      })

      let signature: string
      if (useRelayer) {
        setStatusMsg('Relaying ExecViaEscrow (Tag 7)…')
        const sub = await relayClient.submitRelayedInstruction({
          cluster,
          instructionDataB64: toBase64(ix.data),
          accounts: ix.accounts,
          computeUnitLimit: 600_000,
        })
        signature = sub.signature
      } else {
        setStatusMsg('Waiting for wallet approval…')
        const sent = await signAndBroadcastDirect([ix], 600_000)
        signature = sent.signature
      }

      setLastReceipt({
        kind: 'ExecViaEscrow Shielded Swap (Tag 7)',
        signature,
        cluster,
        proverMs: elapsedMs,
        relayed: useRelayer,
        summary: `Swapped ${swapAmount} ${inSym} → ${mintLabel(swapOutMint).symbol} via isolated Escrow #${escrowShard}`,
      })
      await syncVault(keys, cluster, store)
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
    try {
      const parsed = JSON.parse(await file.text()) as AudrenEncryptedBackupFile
      const restored = await importEncryptedVaultBackup(parsed, backupPassphrase)
      setCluster(restored.cluster)
      await unlockFromSeed(restored.seed, restored.cluster)
      setBackupStatus(`Restored Audren vault on ${restored.cluster}`)
    } catch (err) {
      setBackupStatus(err instanceof Error ? err.message : String(err))
    }
  }

  const totalShieldedByMint = useMemo(() => {
    const map = new Map<string, bigint>()
    for (const n of unspentNotes) {
      const m = base58Encode(n.mint)
      map.set(m, (map.get(m) ?? 0n) + n.amount)
    }
    return Array.from(map.entries())
  }, [unspentNotes])

  return (
    <div className="lv-shell">
      <div className="lv-topbar">
        <div className="lv-cluster-switch" role="group" aria-label="Solana cluster">
          <button
            type="button"
            className={`lv-cluster-btn ${cluster === 'devnet' ? 'is-active' : ''}`}
            onClick={() => setCluster('devnet')}
          >
            <span className="lv-cluster-dot is-devnet" />
            Devnet
          </button>
          <button
            type="button"
            className={`lv-cluster-btn ${cluster === 'mainnet' ? 'is-active' : ''}`}
            onClick={() => setCluster('mainnet')}
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
        <span>
          <strong>Audren ({AUDREN.releaseTag}):</strong> 192 B BN254 Groth16 global 4-ary MASP (17,861 R1CS).
          Currently running <code>DEV_DETERMINISTIC_VK</code> prior to external audits and Phase-2 MPC ceremony.
        </span>
      </div>

      {!keys ? (
        <div className="lv-connect-sheet">
          <div className="lv-connect-copy">
            <h2>
              Non-custodial <em>Audren</em> Vault.
            </h2>
            <p>
              Derive your BN254 spend key, X25519 view key, and encrypted <code>CompactWalletStore</code>{' '}
              strictly inside your browser. Zero indexer, zero server-side key custody.
            </p>
            <ul className="lv-connect-steps">
              <li>
                <span className="lv-step-dot">1</span>
                <div>
                  <strong>Connect any Wallet Standard extension</strong>
                  <p>Sign one deterministic message to unlock your Audren vault keys, or spin up an ephemeral local vault.</p>
                </div>
              </li>
              <li>
                <span className="lv-step-dot">2</span>
                <div>
                  <strong>Sync via ordinary Solana RPC</strong>
                  <p>Reads <code>SubtreePage</code>, <code>MemoPage</code>, and <code>NullifierPage</code> PDAs in batched <code>getMultipleAccounts</code> calls; persists compact encrypted state in IndexedDB.</p>
                </div>
              </li>
              <li>
                <span className="lv-step-dot">3</span>
                <div>
                  <strong>Prove locally in browser WASM</strong>
                  <p>Generates 192 B Groth16 proofs via <code>/wasm/audren_circuits.wasm</code> and submits via your chosen Privacy Relayer or Direct Self-Pay.</p>
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
                      <strong>{w.name}</strong>
                      <span>{connected?.name === w.name ? 'Connected' : 'Wallet Standard'}</span>
                    </span>
                  </button>
                ))
              ) : (
                <div className="lv-empty-action">
                  <p>No Solana browser extension detected (Phantom, Solflare, Backpack). You can still launch a local vault or run the no-wallet Sandbox.</p>
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
                  Unlock Vault with {connected.name}
                </button>
              )}
              <button
                type="button"
                className="btn-secondary lv-submit-btn"
                disabled={busy}
                onClick={handleCreateLocalVault}
              >
                <Lock size={15} /> Create Ephemeral Local Vault
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="lv-workspace">
          <section className={`lv-card lv-private-card ${strangerView ? 'is-stranger' : ''}`}>
            <div className="lv-card-head">
              <div>
                <span className="lv-ledger-kicker is-ok">
                  {strangerView ? 'WHAT SOLANA OBSERVERS SEE' : 'SHIELDED VAULT (LOCAL)'}
                </span>
              </div>
              <div className="lv-card-head-right">
                <button
                  type="button"
                  className={`lv-eyes-toggle ${strangerView ? 'is-active' : ''}`}
                  onClick={() => setStrangerView((v) => !v)}
                >
                  {strangerView ? <EyeOff size={13} /> : <Eye size={13} />}
                  {strangerView ? 'Stranger View' : 'Owner View'}
                </button>
                <button
                  type="button"
                  className="lv-mini-btn"
                  disabled={syncing}
                  onClick={() => syncVault(keys, cluster, store)}
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
                    <strong>No shielded notes yet</strong>
                    <span>Deposit SOL or SPL tokens below, or share your aud1… receive address</span>
                  </div>
                  <span className="lv-balance-amt mono">0.00</span>
                </div>
              ) : (
                totalShieldedByMint.map(([m, total]) => {
                  const info = mintLabel(m)
                  return (
                    <div key={m} className="lv-balance-row">
                      <div>
                        <strong>{info.symbol}</strong>
                        <span className="mono">{shortHash(m, 6, 4)}</span>
                      </div>
                      {strangerView ? (
                        <span className="lv-redacted-bar mono">ENCRYPTED 90B MEMO</span>
                      ) : (
                        <span className="lv-balance-amt is-pine mono">
                          {formatUnits(total, info.decimals)} {info.symbol}
                        </span>
                      )}
                    </div>
                  )
                })
              )}
            </div>

            <div className="lv-pub-strip">
              <div className="lv-pub-strip-top">
                <div className="lv-pub-val">
                  <span>PUBLIC WALLET SOL</span>
                  <strong className="mono">{formatUnits(pubSolLamports, 9)} SOL</strong>
                </div>
                <div className="lv-pub-val">
                  <span>UNSPENT NOTES</span>
                  <strong className="mono">{unspentNotes.length}</strong>
                </div>
                <div className="lv-pub-val">
                  <span>RELAYER</span>
                  <strong className="mono">{useRelayer ? new URL(relayUrl).host : 'Direct Self-Pay'}</strong>
                </div>
              </div>
            </div>

            <div className="lv-private-foot">
              <div className="lv-addr-row">
                <span className="mono">aud1 Receive Address</span>
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
                      onChange={(e) => setUseRelayer(e.target.checked)}
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
                          window.localStorage.setItem(RELAY_STORAGE_KEY, relayDraft)
                          setShowRelayConfig(false)
                        } else {
                          setErrorMsg('Relay URL must be https:// or http://localhost')
                        }
                      }}
                    >
                      Save Relay
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
                  ['send', 'Private Send', 'Tag 6', Send],
                  ['swap', 'DeFi Swap', 'Tag 7', ArrowLeftRight],
                  ['withdraw', 'Withdraw', 'Tag 6', ArrowUpFromLine],
                  ['compliance', 'Receipts & Keys', 'Mode 1/2', FileKey2],
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
                  }}
                >
                  <strong>
                    <Icon size={13} /> {title}
                  </strong>
                  <span className="mono">{sub}</span>
                </button>
              ))}
            </div>

            <div className="lv-simple-body">
              {tab === 'deposit' && (
                <>
                  <div className="lv-field-block">
                    <label className="lv-label">Asset to Shield</label>
                    <select
                      className="lv-select mono"
                      value={depositMint}
                      onChange={(e) => setDepositMint(e.target.value)}
                    >
                      <option value={NATIVE_SOL_MINT_STR}>Native SOL ({formatUnits(pubSolLamports, 9)} available)</option>
                      {pubTokens.map((t) => (
                        <option key={t.mint} value={t.mint}>
                          {mintLabel(t.mint).symbol} ({t.uiAmountString} available)
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
                    <label className="lv-checkbox-card">
                      <input
                        type="checkbox"
                        checked={feeFromAmount}
                        onChange={(e) => setFeeFromAmount(e.target.checked)}
                      />
                      <div>
                        <strong>Zero-dust sweep (DEPOSIT_FLAG_FEE_FROM_AMOUNT)</strong>
                        <span>Deducts amortized page rent from the shielded amount so ephemeral wallets sweep cleanly to 0 lamports.</span>
                      </div>
                    </label>
                  )}
                  <button
                    type="button"
                    className="btn-primary lv-submit-btn"
                    disabled={busy || !connected}
                    onClick={handleDeposit}
                  >
                    {busy ? <Loader2 size={15} className="spin" /> : <ArrowDownToLine size={15} />}
                    {connected ? 'Shield into Global Pool' : 'Connect Wallet to Deposit'}
                  </button>
                </>
              )}

              {(tab === 'send' || tab === 'swap' || tab === 'withdraw') && (
                <>
                  <div className="lv-field-block">
                    <label className="lv-label">Input Shielded Note</label>
                    <select
                      className="lv-select mono"
                      value={selectedNote ? `${selectedNote.laneId}:${selectedNote.leafIndex.toString()}` : ''}
                      onChange={(e) => setSelectedNoteKey(e.target.value)}
                      disabled={unspentNotes.length === 0}
                    >
                      {unspentNotes.length === 0 ? (
                        <option value="">No unspent notes synced yet</option>
                      ) : (
                        unspentNotes.map((n) => {
                          const mStr = base58Encode(n.mint)
                          const info = mintLabel(mStr)
                          const k = `${n.laneId}:${n.leafIndex.toString()}`
                          return (
                            <option key={k} value={k}>
                              Lane #{n.laneId} · Leaf #{n.leafIndex.toString()} · {formatUnits(n.amount, info.decimals)} {info.symbol}
                            </option>
                          )
                        })
                      )}
                    </select>
                  </div>

                  {tab === 'send' && (
                    <>
                      <div className="lv-field-block">
                        <label className="lv-label">Recipient aud1… Stealth Address</label>
                        <input
                          type="text"
                          className="lv-input mono"
                          value={sendRecipient}
                          onChange={(e) => setSendRecipient(e.target.value)}
                          placeholder="aud1..."
                        />
                      </div>
                      <div className="lv-field-block">
                        <label className="lv-label">Amount</label>
                        <input
                          type="text"
                          inputMode="decimal"
                          className="lv-input lv-amount-big mono"
                          value={sendAmount}
                          onChange={(e) => setSendAmount(e.target.value)}
                          placeholder="0.01"
                        />
                      </div>
                      <button
                        type="button"
                        className="btn-primary lv-submit-btn"
                        disabled={busy || !selectedNote || !sendRecipient.trim()}
                        onClick={() => handleJoinSplitAction('send')}
                      >
                        {busy ? <Loader2 size={15} className="spin" /> : <Send size={15} />}
                        Prove 192 B Groth16 &amp; Send Privately
                      </button>
                    </>
                  )}

                  {tab === 'swap' && (
                    <>
                      <div className="lv-field-block">
                        <label className="lv-label">Output Token Mint</label>
                        <input
                          type="text"
                          className="lv-input mono"
                          value={swapOutMint}
                          onChange={(e) => setSwapOutMint(e.target.value)}
                        />
                      </div>
                      <div className="lv-field-block">
                        <label className="lv-label">Swap Input Amount</label>
                        <input
                          type="text"
                          inputMode="decimal"
                          className="lv-input lv-amount-big mono"
                          value={swapAmount}
                          onChange={(e) => setSwapAmount(e.target.value)}
                          placeholder="0.05"
                        />
                      </div>
                      <div className="lv-field-block">
                        <label className="lv-label">Slippage Tolerance (bps)</label>
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
                          <strong>Pay relayer from swap output (EXEC_FLAG_FEE_ON_OUTPUT)</strong>
                          <span>Atomic post-CPI deduction from received output tokens — zero upfront SOL needed.</span>
                        </div>
                      </label>
                      <div className="lv-quote-card">
                        <div className="lv-quote-head">
                          <span>LIVE ESCROW QUOTE</span>
                          {swapQuoteLoading && <Loader2 size={13} className="spin" />}
                        </div>
                        {swapQuoteOut ? (
                          <div className="lv-quote-pair">
                            <div>
                              <span>Estimated Output</span>
                              <strong className="is-pine mono">
                                {formatUnits(BigInt(swapQuoteOut), mintLabel(swapOutMint).decimals)}{' '}
                                {mintLabel(swapOutMint).symbol}
                              </strong>
                            </div>
                          </div>
                        ) : (
                          <p className="lv-quote-loading">Enter an amount to fetch a live PDA-safe route.</p>
                        )}
                      </div>
                      <button
                        type="button"
                        className="btn-primary lv-submit-btn"
                        disabled={busy || !selectedNote || !swapQuoteOut}
                        onClick={handleShieldedSwap}
                      >
                        {busy ? <Loader2 size={15} className="spin" /> : <ArrowLeftRight size={15} />}
                        Prove 192 B Groth16 &amp; Execute Shielded Swap
                      </button>
                    </>
                  )}

                  {tab === 'withdraw' && (
                    <>
                      <div className="lv-field-block">
                        <label className="lv-label">Public Solana Recipient</label>
                        <input
                          type="text"
                          className="lv-input mono"
                          value={withdrawRecipient}
                          onChange={(e) => setWithdrawRecipient(e.target.value)}
                          placeholder="Solana public address"
                        />
                      </div>
                      <div className="lv-field-block">
                        <label className="lv-label">Withdraw Amount</label>
                        <input
                          type="text"
                          inputMode="decimal"
                          className="lv-input lv-amount-big mono"
                          value={withdrawAmount}
                          onChange={(e) => setWithdrawAmount(e.target.value)}
                          placeholder="0.01"
                        />
                      </div>
                      {selectedNoteMintStr === WSOL_MINT && (
                        <label className="lv-checkbox-card">
                          <input
                            type="checkbox"
                            checked={unwrapWsol}
                            onChange={(e) => setUnwrapWsol(e.target.checked)}
                          />
                          <div>
                            <strong>Atomic WSOL → Native SOL unwrap (WITHDRAW_FLAG_UNWRAP_WSOL)</strong>
                            <span>Uses a 1-shot <code>audren_v2_unwrap</code> PDA and works even while the pool is paused.</span>
                          </div>
                        </label>
                      )}
                      <button
                        type="button"
                        className="btn-primary lv-submit-btn"
                        disabled={busy || !selectedNote || !withdrawRecipient.trim()}
                        onClick={() => handleJoinSplitAction('withdraw')}
                      >
                        {busy ? <Loader2 size={15} className="spin" /> : <ArrowUpFromLine size={15} />}
                        Prove 192 B Groth16 &amp; Withdraw
                      </button>
                    </>
                  )}
                </>
              )}

              {tab === 'compliance' && (
                <>
                  <div className="lv-receipt-drawer">
                    <div className="lv-receipt-head">
                      <strong>Mode 1 · Single-Note Selective Disclosure Proof</strong>
                      <button
                        type="button"
                        className="lv-mini-btn"
                        disabled={!selectedNote}
                        onClick={handleGenerateReceipt}
                      >
                        Export Selected Note Proof
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
                        <ShieldCheck size={13} /> Verify Receipt
                      </button>
                      {receiptVerdict && (
                        <span className={`lv-receipt-verdict ${receiptVerdict === 'valid' ? 'is-valid' : 'is-forged'}`}>
                          {receiptVerdict === 'valid'
                            ? 'VALID · Poseidon commitment matches'
                            : 'INVALID · Commitment mismatch or malformed'}
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="lv-backup-box">
                    <div className="lv-receipt-head">
                      <strong>Mode 2 · Read-Only FullViewingKey</strong>
                      <button type="button" className="lv-mini-btn" onClick={() => setShowFvk((v) => !v)}>
                        {showFvk ? 'Hide FVK' : 'Reveal FVK'}
                      </button>
                    </div>
                    <p>
                      Grants read-only inbound &amp; outbound visibility (<code>spendPk, nk, viewSk, viewPk</code>) for treasury accounting without spend authority.
                    </p>
                    {showFvk && fvkExport && (
                      <pre className="mono" style={{ fontSize: '0.74rem', overflowX: 'auto' }}>
                        {fvkExport}
                      </pre>
                    )}
                  </div>

                  {defiSession && (
                    <div className="lv-backup-box">
                      <div className="lv-receipt-head">
                        <strong>Pseudonymous DeFi Session Wallet (#{sessionIndex})</strong>
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
                        <strong>Boundary:</strong> funding via relayed Withdraw breaks the link to your main wallet, while external DeFi actions executed by this session wallet remain public on Solana.
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
                    <strong>Encrypted Vault Backup (PBKDF2-SHA256 + AES-256-GCM)</strong>
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
                          if (f) handleImportBackup(f)
                        }}
                      />
                      <button
                        type="button"
                        className="lv-mini-btn"
                        onClick={async () => {
                          await clearEncryptedCompactStore(keys.spendPkBytes, cluster, 0)
                          setBackupStatus('Cleared local encrypted IndexedDB CompactWalletStore cache')
                        }}
                      >
                        Clear Cache
                      </button>
                    </div>
                    {backupStatus && <p className="lv-backup-status mono">{backupStatus}</p>}
                  </div>
                </>
              )}

              {statusMsg && (
                <div className="lv-notice-bar">
                  <ShieldCheck size={14} />
                  <span>{statusMsg}</span>
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
                    {lastReceipt.relayed ? 'ZERO-SIGNER RELAYED' : 'DIRECT SELF-PAY'}
                    {lastReceipt.proverMs !== undefined ? ` · WASM PROVER ${lastReceipt.proverMs} ms` : ''}
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
