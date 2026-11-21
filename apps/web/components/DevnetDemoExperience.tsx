'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import {
  AlertCircle,
  ArrowLeft,
  ArrowRight,
  ArrowUpRight,
  Check,
  ChevronDown,
  Copy,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  Lock,
  LockOpen,
  RefreshCw,
  Send,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react'
import { SiteHeader } from '@/components/SiteHeader'
import { SiteFooter } from '@/components/SiteFooter'
import { LiveWalletVault } from '@/components/LiveWalletVault'
import {
  base58Decode,
  base58Encode,
  buildSelectiveDisclosureReceipt,
  fromBase64,
  fromHex,
  generateAudrenKeys,
  prepareSolDepositNote,
  scanEpochPageForOwner,
  toBase64,
  toHex,
  verifySelectiveDisclosureOnPage,
  verifySelectiveDisclosureReceipt,
  type AudrenKeypair,
  type DecryptedAudrenNote,
  type SelectiveDisclosureReceipt,
} from '@/lib/audren-crypto'
import {
  PAGE_ROLLOVER_THRESHOLD,
  buildTransferInstruction,
  extractRingFromPage,
  scanEpochPageSpendable,
  type SpendableAudrenNote,
} from '@/lib/audren-prover'
import { AUDREN, explorerTx, shortHash, solscanAddress, solscanTx } from '@/lib/protocol'

type DemoMode = 'wallet' | 'sandbox'

const SANDBOX_SEED_KEY = 'audren_demo_sandbox_seed_v1'
const SANDBOX_TX1_KEY = 'audren_demo_sandbox_tx1_v1'
const SANDBOX_TX2_KEY = 'audren_demo_sandbox_tx2_v1'

interface PublicPoolNote {
  slotIndex: number
  viewTag: number
  ephemeralPk: string
  stealthPk: string
  assetTag: string
  commitment: string
  ciphertextHex: string
}

interface PoolPagePayload {
  pageId: string
  pagePda: string
  count: number
  closed: boolean
  pageBase64: string
}

interface PoolResponse {
  cluster: 'devnet'
  programId: string
  poolId: number
  poolPda: string
  solVaultPda: string
  solVaultLamports: number
  faucetLamports: number | null
  relayerAvailable: boolean
  relayerAddress: string | null
  currentPageId: string
  viewingPageId: string
  pagePda: string
  pageCount: number
  pageClosed: boolean
  totalNotes: string
  totalSpends: string
  paused: boolean
  pageBase64: string
  notes: PublicPoolNote[]
  pages: PoolPagePayload[]
}

interface LiveDepositResult {
  txVersion: number
  txWireBytes: number
  signature: string
  slot: number
  amountLamports: string
  pageId: string
  pagePda: string
  slotIndex: number
  solscanUrl: string
  explorerUrl: string
  note: PublicPoolNote
  decrypted: DecryptedAudrenNote | null
  scannedCount: number
}

interface LiveTransferResult {
  signature: string
  slot: number
  amountLamports: string
  changeLamports: string
  memoText: string
  spentPageId: string
  spentSlotIndex: number
  relayerAddress: string
  proverMs: number
  solscanUrl: string
  explorerUrl: string
}

type ActiveStep = 0 | 1 | 2 | 3 | 4

const PRESET_AMOUNTS = [
  { label: '0.001 SOL', short: '0.001', lamports: 1_000_000n },
  { label: '0.002 SOL', short: '0.002', lamports: 2_000_000n },
  { label: '0.005 SOL', short: '0.005', lamports: 5_000_000n },
] as const

const PRESET_MEMOS = ['PAYROLL', 'RENT', 'INVOICE', 'BONUS'] as const

const REAL_LIFECYCLE_STEPS = [
  {
    id: 'program',
    tag: 'DEPLOYMENT',
    title: 'Mainnet Program',
    cluster: 'MAINNET',
    whatPublicSees:
      'Open-source Audren sBPFv3 program and Pool #0 on Solana Mainnet (pre-audit, upgradeable).',
    whatStaysPrivate: 'Private note ownership, spending keys, and encrypted note ciphertexts.',
    sig: AUDREN.programId,
    isMainnet: true,
    isProgram: true,
  },
  {
    id: 'transfer',
    tag: 'PRIVATE SEND',
    title: 'Mainnet Private Transfer',
    cluster: 'MAINNET',
    whatPublicSees:
      'Relayed Solana v1 transaction (0 user signers); fee payer, candidate page, and timing are public.',
    whatStaysPrivate: 'Spent note in the 32-slot ring, recipient key, token mint, and transfer amount.',
    sig: AUDREN.mainnet.transferTx,
    isMainnet: true,
    isProgram: false,
  },
  {
    id: 'withdraw',
    tag: 'EXIT',
    title: 'Mainnet Full Withdrawal',
    cluster: 'MAINNET',
    whatPublicSees:
      'Full SPL withdrawal (has_change = 0) from the shared vault to a public destination account.',
    whatStaysPrivate: 'Which candidate note in the 32-slot ring funded the payout.',
    sig: AUDREN.mainnet.withdrawTx,
    isMainnet: true,
    isProgram: false,
  },
  {
    id: 'sandbox',
    tag: 'SANDBOX',
    title: 'Devnet Sandbox Transfer',
    cluster: 'DEVNET',
    whatPublicSees:
      'Identical sBPFv3 program on Solana Devnet for running free relayed transfers with test SOL.',
    whatStaysPrivate: 'Same Triptych ring proof, blinded commitments, and AES-256-GCM ciphertexts.',
    sig: AUDREN.devnet.transferTx,
    isMainnet: false,
    isProgram: false,
  },
] as const

const UTF8_ENC = new TextEncoder()
function clampUtf8Bytes(input: string, maxBytes: number): string {
  let out = ''
  let used = 0
  for (const ch of input) {
    const n = UTF8_ENC.encode(ch).length
    if (used + n > maxBytes) break
    out += ch
    used += n
  }
  return out
}

function loadOrCreateSandboxSeed(): Uint8Array | undefined {
  if (typeof window === 'undefined') return undefined
  try {
    const saved = window.sessionStorage.getItem(SANDBOX_SEED_KEY)
    if (saved && /^[0-9a-f]{64}$/i.test(saved)) {
      return fromHex(saved)
    }
  } catch {
    // ignore storage errors
  }
  return undefined
}

function saveSandboxSeed(seedHex: string) {
  if (typeof window === 'undefined') return
  try {
    window.sessionStorage.setItem(SANDBOX_SEED_KEY, seedHex)
  } catch {
    // ignore storage errors
  }
}

type StoredDepositSummary = Omit<LiveDepositResult, 'decrypted'>

function loadStoredJson<T>(key: string): T | null {
  if (typeof window === 'undefined') return null
  try {
    const raw = window.sessionStorage.getItem(key)
    return raw ? (JSON.parse(raw) as T) : null
  } catch {
    return null
  }
}

function saveStoredJson(key: string, val: unknown) {
  if (typeof window === 'undefined') return
  try {
    window.sessionStorage.setItem(key, JSON.stringify(val))
  } catch {
    // ignore storage errors
  }
}

function clearSandboxSession() {
  if (typeof window === 'undefined') return
  try {
    window.sessionStorage.removeItem(SANDBOX_TX1_KEY)
    window.sessionStorage.removeItem(SANDBOX_TX2_KEY)
  } catch {
    // ignore storage errors
  }
}

export function DevnetDemoExperience() {
  const [mode, setMode] = useState<DemoMode>('wallet')
  const [keys, setKeys] = useState<AudrenKeypair | null>(null)
  const [pool, setPool] = useState<PoolResponse | null>(null)
  const [poolLoading, setPoolLoading] = useState(true)
  const [poolError, setPoolError] = useState<string | null>(null)

  const [ownedNotes, setOwnedNotes] = useState<SpendableAudrenNote[]>([])
  const [spentKeys, setSpentKeys] = useState<string[]>([])

  const [selectedLamports, setSelectedLamports] = useState<bigint>(1_000_000n)
  const [memo, setMemo] = useState('PAYROLL')

  const [activeStep, setActiveStep] = useState<ActiveStep>(0)
  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)
  const [result, setResult] = useState<LiveDepositResult | null>(null)

  // Step 2: Live Private Spend (Zero Wallet — paid by Devnet Relayer)
  const [spendPct, setSpendPct] = useState<50 | 100>(50)
  const [spendMemo, setSpendMemo] = useState('PRIVATE')
  const [spending, setSpending] = useState(false)
  const [spendStatus, setSpendStatus] = useState<string | null>(null)
  const [spendError, setSpendError] = useState<string | null>(null)
  const [transferResult, setTransferResult] = useState<LiveTransferResult | null>(null)

  // Step 3: Selective Disclosure Receipt + Simple Tabbed Sandbox UI
  const [sandboxTab, setSandboxTab] = useState<'fund' | 'spend' | 'receipt'>('fund')
  const [sandboxStrangerEyes, setSandboxStrangerEyes] = useState(false)
  const [receipt, setReceipt] = useState<SelectiveDisclosureReceipt | null>(null)
  const [receiptCheck, setReceiptCheck] = useState<{ valid: boolean; reason: string } | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [showSecrets, setShowSecrets] = useState(false)
  const [showHexTable, setShowHexTable] = useState(false)

  const headerRef = useRef<HTMLElement | null>(null)
  const depositProofRef = useRef<HTMLDivElement | null>(null)
  const transferProofRef = useRef<HTMLDivElement | null>(null)

  // Sync ?mode=sandbox or ?flow=payment on initial mount and browser navigation
  useEffect(() => {
    const syncFromUrl = () => {
      const qs = new URLSearchParams(window.location.search)
      const m = qs.get('mode')
      const f = qs.get('flow')
      if (m === 'sandbox' || f === 'payment') {
        setMode('sandbox')
      } else {
        setMode('wallet')
      }
    }
    const id = window.setTimeout(syncFromUrl, 0)
    window.addEventListener('popstate', syncFromUrl)
    return () => {
      window.clearTimeout(id)
      window.removeEventListener('popstate', syncFromUrl)
    }
  }, [])

  const copyText = (id: string, val: string) => {
    navigator.clipboard?.writeText(val).catch(() => {})
    setCopiedId(id)
    window.setTimeout(() => setCopiedId((prev) => (prev === id ? null : prev)), 1800)
  }

  const scanSandboxBalances = useCallback(
    async (activeKeys: AudrenKeypair, poolData: PoolResponse) => {
      try {
        const allFound: SpendableAudrenNote[] = []
        const pages =
          poolData.pages && poolData.pages.length > 0
            ? poolData.pages
            : [
                {
                  pageId: poolData.viewingPageId,
                  pagePda: poolData.pagePda,
                  count: poolData.pageCount,
                  closed: poolData.pageClosed,
                  pageBase64: poolData.pageBase64,
                },
              ]
        for (const pg of pages) {
          const found = await scanEpochPageSpendable(activeKeys, fromBase64(pg.pageBase64), 0)
          allFound.push(...found)
        }
        if (allFound.length === 0) {
          setOwnedNotes([])
          setSpentKeys([])
          return
        }
        const pdas = allFound.map((n) => n.nullifierPdaB58)
        const nfRes = await fetch('/api/nullifiers', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ cluster: 'devnet', pdas }),
        })
        if (!nfRes.ok) return
        const nfJson = (await nfRes.json()) as { spent?: boolean[] }
        if (!Array.isArray(nfJson.spent) || nfJson.spent.length !== pdas.length) return
        const spentFlags = nfJson.spent
        const unspent: SpendableAudrenNote[] = []
        const spentSlotIds: string[] = []
        allFound.forEach((n, idx) => {
          if (spentFlags[idx]) {
            spentSlotIds.push(`${n.pageId.toString()}-${n.slotIndex}`)
          } else if (n.amount > 0n) {
            unspent.push(n)
          }
        })
        setOwnedNotes(unspent)
        setSpentKeys(spentSlotIds)
      } catch {
        // Non-fatal: keep previous balance view
      }
    },
    [],
  )

  const refreshPool = useCallback(
    async (activeKeys?: AudrenKeypair | null) => {
      setPoolLoading(true)
      setPoolError(null)
      try {
        const res = await fetch('/api/devnet/pool', { cache: 'no-store' })
        const data = (await res.json()) as PoolResponse & { error?: string }
        if (!res.ok) throw new Error(data.error ?? `HTTP ${res.status}`)
        setPool(data)
        const k = activeKeys ?? keys
        if (k) await scanSandboxBalances(k, data)
        return data
      } catch (e) {
        setPoolError(e instanceof Error ? e.message : 'Unable to reach Solana right now')
        return null
      } finally {
        setPoolLoading(false)
      }
    },
    [keys, scanSandboxBalances],
  )

  const regenerateKeys = useCallback(async () => {
    const fresh = await generateAudrenKeys()
    saveSandboxSeed(fresh.seedHex)
    clearSandboxSession()
    setKeys(fresh)
    setOwnedNotes([])
    setSpentKeys([])
    setResult(null)
    setTransferResult(null)
    setActiveStep(0)
    setSandboxTab('fund')
    setReceipt(null)
    setReceiptCheck(null)
    setSubmitError(null)
    setSpendError(null)
  }, [])

  useEffect(() => {
    let cancelled = false
    void (async () => {
      const existingSeed = loadOrCreateSandboxSeed()
      const fresh = await generateAudrenKeys(existingSeed)
      saveSandboxSeed(fresh.seedHex)
      if (cancelled) return
      setKeys(fresh)
      try {
        const res = await fetch('/api/devnet/pool', { cache: 'no-store' })
        const data = (await res.json()) as PoolResponse & { error?: string }
        if (!res.ok) throw new Error(data.error ?? `HTTP ${res.status}`)
        if (!cancelled) {
          setPool(data)
          setPoolError(null)
          await scanSandboxBalances(fresh, data)

          // Rehydrate any Step 1 / Step 2 receipts from this browser tab session
          const savedTx1 = loadStoredJson<StoredDepositSummary>(SANDBOX_TX1_KEY)
          if (savedTx1) {
            const matchPage =
              data.pages?.find((p) => p.pageId === savedTx1.pageId) ??
              (data.viewingPageId === savedTx1.pageId
                ? { pageBase64: data.pageBase64 }
                : null)
            let decrypted: DecryptedAudrenNote | null = null
            if (matchPage) {
              const scanned = await scanEpochPageForOwner(fresh, fromBase64(matchPage.pageBase64))
              decrypted =
                scanned.ownedNotes.find((n) => n.slotIndex === savedTx1.slotIndex) ?? null
            }
            if (!cancelled && decrypted) {
              setResult({ ...savedTx1, decrypted })
              setActiveStep(4)
            }
          }
          const savedTx2 = loadStoredJson<LiveTransferResult>(SANDBOX_TX2_KEY)
          if (!cancelled && savedTx2) {
            setTransferResult(savedTx2)
          }
        }
      } catch (e) {
        if (!cancelled) {
          setPoolError(e instanceof Error ? e.message : 'Unable to reach Solana right now')
        }
      } finally {
        if (!cancelled) setPoolLoading(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [scanSandboxBalances])

  // STEP 1: Funded Devnet Deposit into User's Temporary Browser Private Account
  const handleLiveShield = async () => {
    if (!keys || submitting) return
    setSubmitting(true)
    setSubmitError(null)
    setReceipt(null)
    setReceiptCheck(null)

    try {
      setActiveStep(1)
      const prepared = await prepareSolDepositNote(
        keys.spendPk,
        keys.viewPk,
        selectedLamports,
        memo,
      )

      setActiveStep(2)
      const res = await fetch('/api/devnet/deposit', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          amountLamports: prepared.amountLamports.toString(),
          viewTag: prepared.viewTag,
          ephemeralPkHex: toHex(prepared.ephemeralPk),
          stealthPkHex: toHex(prepared.stealthPk),
          ciphertextHex: toHex(prepared.ciphertext),
        }),
      })
      const data = (await res.json()) as {
        ok?: boolean
        error?: string
        txVersion?: number
        txWireBytes?: number
        signature: string
        slot: number
        amountLamports: string
        pageId: string
        pagePda: string
        slotIndex: number
        solscanUrl: string
        explorerUrl: string
        note: PublicPoolNote
        pageBase64: string
      }

      if (!res.ok || !data.ok) {
        throw new Error(data.error ?? `Transaction failed (HTTP ${res.status})`)
      }

      setActiveStep(3)
      const pageBytes = fromBase64(data.pageBase64)
      const scanned = await scanEpochPageForOwner(keys, pageBytes)
      const matched =
        scanned.ownedNotes.find((n) => n.slotIndex === data.slotIndex) ??
        scanned.ownedNotes[scanned.ownedNotes.length - 1] ??
        null

      const depositSummary: StoredDepositSummary = {
        txVersion: data.txVersion ?? 1,
        txWireBytes: data.txWireBytes ?? 0,
        signature: data.signature,
        slot: data.slot,
        amountLamports: data.amountLamports,
        pageId: data.pageId,
        pagePda: data.pagePda,
        slotIndex: data.slotIndex,
        solscanUrl: data.solscanUrl,
        explorerUrl: data.explorerUrl,
        note: data.note,
        scannedCount: scanned.scannedCount,
      }
      saveStoredJson(SANDBOX_TX1_KEY, depositSummary)
      setResult({
        ...depositSummary,
        decrypted: matched,
      })
      setActiveStep(4)
      await refreshPool(keys)
      window.setTimeout(() => {
        depositProofRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
      }, 90)
    } catch (e) {
      setSubmitError(e instanceof Error ? e.message : 'Something went wrong')
      setActiveStep(result ? 4 : 0)
    } finally {
      setSubmitting(false)
    }
  }

  // STEP 2: Prove Access — Spend Temporary Private Balance Live via Devnet Privacy Relayer (Zero Wallet!)
  const handleLivePrivateSpend = async () => {
    if (!keys || !pool || spending) return
    const targetNote = ownedNotes[ownedNotes.length - 1]
    if (!targetNote) {
      setSpendError('Get free test SOL in Go Private first so your temporary private account has a balance to spend.')
      return
    }
    if (!pool.relayerAvailable || !pool.relayerAddress) {
      setSpendError('Free Devnet Relayer is temporarily refilling — please try again in a moment.')
      return
    }
    const inputPage = pool.pages.find((p) => p.pageId === targetNote.pageId.toString())
    if (!inputPage) {
      setSpendError('Refreshing shared pool state — click Refresh and try again.')
      return
    }

    setSpending(true)
    setSpendError(null)
    setSpendStatus('1/2 Creating privacy proof inside your browser…')
    try {
      await new Promise((r) => setTimeout(r, 25))
      const t0 = performance.now()
      const payAmount =
        spendPct === 100
          ? targetNote.amount
          : targetNote.amount / 2n > 0n
            ? targetNote.amount / 2n
            : targetNote.amount
      const changeAmount = targetNote.amount - payAmount
      const ring = extractRingFromPage(fromBase64(inputPage.pageBase64))
      const relayerPubkey = base58Decode(pool.relayerAddress)
      const cleanMemo = clampUtf8Bytes(spendMemo.trim().toUpperCase(), 7) || 'PRIVATE'

      const curPageId = BigInt(pool.currentPageId)
      const curPageSummary = pool.pages.find((p) => p.pageId === pool.currentPageId)
      const needsRollover = Boolean(
        curPageSummary && (curPageSummary.closed || curPageSummary.count >= PAGE_ROLLOVER_THRESHOLD),
      )
      const outPageId = needsRollover ? curPageId + 1n : curPageId

      const { instruction } = await buildTransferInstruction({
        payer: relayerPubkey,
        poolId: 0,
        outPageId,
        inputPageIds: [targetNote.pageId],
        ring,
        inputNote: targetNote,
        secretIndex: targetNote.slotIndex,
        recipient: { spendPk: keys.spendPk, viewPk: keys.viewPk },
        changeAddr: { spendPk: keys.spendPk, viewPk: keys.viewPk },
        payAmount,
        memoText: cleanMemo,
      })
      const proverMs = Math.round(performance.now() - t0)

      setSpendStatus('2/2 Privacy Relayer paying the Solana fee & settling on Devnet…')
      const res = await fetch('/api/relay/submit', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          cluster: 'devnet',
          instructionDataB64: toBase64(instruction.data),
          accounts: instruction.accounts.map((a) => ({
            pubkey: base58Encode(a.pubkey),
            isSigner: a.isSigner,
            isWritable: a.isWritable,
          })),
          computeUnitLimit: 850_000,
          priorityFeeLamports: '5000',
          rolloverFromPageId: needsRollover ? pool.currentPageId : undefined,
        }),
      })
      const data = (await res.json()) as {
        ok?: boolean
        error?: string
        signature: string
        slot: number
        relayerPubkey: string
        solscanUrl: string
        explorerUrl: string
      }
      if (!res.ok || !data.ok) {
        throw new Error(data.error ?? `Private transfer failed (HTTP ${res.status})`)
      }

      const nextTransfer: LiveTransferResult = {
        signature: data.signature,
        slot: data.slot,
        amountLamports: payAmount.toString(),
        changeLamports: changeAmount.toString(),
        memoText: cleanMemo,
        spentPageId: targetNote.pageId.toString(),
        spentSlotIndex: targetNote.slotIndex,
        relayerAddress: data.relayerPubkey || pool.relayerAddress,
        proverMs,
        solscanUrl: data.solscanUrl,
        explorerUrl: data.explorerUrl,
      }
      saveStoredJson(SANDBOX_TX2_KEY, nextTransfer)
      setTransferResult(nextTransfer)

      await refreshPool(keys)
      window.setTimeout(() => {
        transferProofRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
      }, 90)
    } catch (e) {
      setSpendError(e instanceof Error ? e.message : 'Private transfer failed')
    } finally {
      setSpending(false)
      setSpendStatus(null)
    }
  }

  const handleGenerateReceipt = async (tamper = false) => {
    if (!result?.decrypted) return
    const base = buildSelectiveDisclosureReceipt(result.decrypted, result.signature)
    const candidate: SelectiveDisclosureReceipt = tamper
      ? {
          ...base,
          amountLamports: (BigInt(base.amountLamports) + 1_000_000n).toString(),
          amountSol: ((Number(base.amountLamports) + 1_000_000) / 1_000_000_000).toFixed(4),
        }
      : base
    setReceipt(candidate)
    const matchPageB64 = pool?.pages.find((p) => p.pageId === candidate.pageId)?.pageBase64
    const check = matchPageB64
      ? await verifySelectiveDisclosureOnPage(candidate, fromBase64(matchPageB64))
      : await verifySelectiveDisclosureReceipt(candidate)
    setReceiptCheck(check)
  }

  const switchToSandbox = () => {
    setMode('sandbox')
    window.setTimeout(() => {
      headerRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }, 30)
  }

  const selectedSolLabel = (Number(selectedLamports) / 1e9).toFixed(3)
  const displayMemo = memo.trim() || 'PAYROLL'
  const recentLockers = pool ? pool.notes.slice(-12).reverse() : []

  const totalOwnedLamports = ownedNotes.reduce((acc, n) => acc + n.amount, 0n)
  const totalOwnedSol = (Number(totalOwnedLamports) / 1e9).toFixed(4)
  const latestSpendableNote = ownedNotes[ownedNotes.length - 1] ?? null
  const ownedSlotMap = new Map<string, SpendableAudrenNote>(
    ownedNotes.map((n) => [`${n.pageId.toString()}-${n.slotIndex}`, n]),
  )
  const spentSlotSet = new Set(spentKeys)

  const faucetShort = pool?.relayerAddress ? shortHash(pool.relayerAddress, 5, 4) : 'Bvf7…xDJ3'

  return (
    <div className="page-shell">
      <SiteHeader current="demo" />

      <main className="demo-page">
        <div className="container">
          {/* Compact Top Navigation */}
          <div className="demo-topbar mono">
            <Link href="/" className="back-link">
              <ArrowLeft size={13} /> AUDREN.XYZ
            </Link>
            <div className="demo-meta-tags">
              <a
                href={solscanAddress(AUDREN.programId, 'mainnet')}
                target="_blank"
                rel="noreferrer"
                className="back-link"
              >
                PROGRAM {shortHash(AUDREN.programId, 8, 6)} <ArrowUpRight size={11} />
              </a>
            </div>
          </div>

          {/* Crisp Plain-English Header — Adapts Immediately to Mode */}
          <header ref={headerRef} className="demo-header">
            <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'flex-end', justifyContent: 'space-between', gap: '20px 32px' }}>
              <div style={{ flex: '1 1 460px', maxWidth: 660 }}>
                {mode === 'wallet' ? (
                  <>
                    <h1>
                      Private balance for <em>your Solana wallet</em>.
                    </h1>
                    <p>
                      Move supported tokens between public and private balances, send privately or swap
                      through compatible DEX aggregators, and inspect every transaction on Solscan.
                    </p>
                  </>
                ) : (
                  <>
                    <h1>
                      Try Audren on Devnet — <em>no wallet needed</em>.
                    </h1>
                    <p>
                      Test real Solana Devnet transactions with free test SOL: deposit into the shared
                      pool, run a relayed private transfer with blinded amount, and verify a single-note
                      commitment receipt.
                    </p>
                  </>
                )}
              </div>
              <div
                role="tablist"
                aria-label="Demo mode"
                style={{
                  display: 'inline-flex',
                  border: '1px solid #121210',
                  background: '#fbf9f4',
                  flexShrink: 0,
                }}
              >
                <button
                  type="button"
                  role="tab"
                  aria-selected={mode === 'wallet'}
                  onClick={() => setMode('wallet')}
                  className="mono"
                  style={{
                    border: 0,
                    padding: '9px 14px',
                    fontSize: 11,
                    letterSpacing: '0.07em',
                    textTransform: 'uppercase',
                    cursor: 'pointer',
                    background: mode === 'wallet' ? '#121210' : 'transparent',
                    color: mode === 'wallet' ? '#f4f1ea' : '#121210',
                  }}
                >
                  Wallet app
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={mode === 'sandbox'}
                  onClick={switchToSandbox}
                  className="mono"
                  style={{
                    border: 0,
                    borderLeft: '1px solid rgba(18,18,16,0.16)',
                    padding: '9px 14px',
                    fontSize: 11,
                    letterSpacing: '0.07em',
                    textTransform: 'uppercase',
                    cursor: 'pointer',
                    background: mode === 'sandbox' ? '#184433' : 'transparent',
                    color: mode === 'sandbox' ? '#f4f1ea' : '#121210',
                  }}
                >
                  Free Devnet sandbox
                </button>
              </div>
            </div>
          </header>

          {/* ================================================================
              PRIMARY EXPERIENCE: LIVE CONNECTED WALLET (MAINNET / DEVNET)
             ================================================================ */}
          {mode === 'wallet' && <LiveWalletVault onSwitchToFreeSandbox={switchToSandbox} />}

          {/* ================================================================
              FREE DEVNET TEST — SAME ULTRA-CLEAN 2-CARD LAYOUT (NO WALLET!)
             ================================================================ */}
          {mode === 'sandbox' && (
            <div className="lv-shell">
              {/* Compact 1-line Top Bar matching Wallet Mode */}
              <div className="lv-topbar">
                <div className="sb-mode-pill mono">
                  <span>FREE TEST SANDBOX · SOLANA DEVNET (NO WALLET NEEDED)</span>
                </div>
                <div className="lv-wallet-bar">
                  <button
                    type="button"
                    className="lv-mini-btn mono"
                    onClick={() => void regenerateKeys()}
                    disabled={submitting || spending}
                    title="Create a brand-new temporary private key in this browser"
                  >
                    <RefreshCw size={12} /> RESET TEST ACCOUNT
                  </button>
                  <button
                    type="button"
                    className="lv-mini-btn mono"
                    onClick={() => setMode('wallet')}
                  >
                    <ArrowLeft size={12} /> USE MY OWN WALLET
                  </button>
                </div>
              </div>

              {poolError && (
                <div className="alert-banner is-error" style={{ marginBottom: 14 }}>
                  <AlertCircle size={16} />
                  <span>Could not load live shared vault: {poolError}</span>
                </div>
              )}

              {/* 2-COLUMN WORKSPACE — LEFT: YOUR TEST BALANCE | RIGHT: 3 SIMPLE STEP TABS */}
              <div className="lv-workspace">
                {/* LEFT CARD: YOUR TEST PRIVATE BALANCE */}
                <section
                  className={`lv-card lv-private-card ${sandboxStrangerEyes ? 'is-stranger' : ''}`}
                  aria-label="Your Test Private Balance"
                >
                  <div className="lv-card-head">
                    <div>
                      <span className="lv-ledger-kicker mono is-ok">
                        {sandboxStrangerEyes ? (
                          <>
                            <EyeOff size={12} /> WHAT SOLSCAN SEES
                          </>
                        ) : (
                          <>
                            <ShieldCheck size={12} /> YOUR TEST PRIVATE BALANCE
                          </>
                        )}
                      </span>
                      <div className="lv-private-total">
                        {sandboxStrangerEyes ? (
                          <span className="lv-redacted-bar is-lg" title="Hidden on Solscan" />
                        ) : (
                          <div className="lv-private-total-wrap">
                            <strong>{totalOwnedSol} SOL</strong>
                            <span className="mono lv-private-sub-amt">
                              {totalOwnedLamports > 0n
                                ? `${ownedNotes.length} unlocked box${ownedNotes.length === 1 ? '' : 'es'} · only this tab can spend`
                                : 'Free Devnet test SOL ($0 value)'}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>

                    <div className="lv-card-head-right">
                      <button
                        type="button"
                        className={`lv-eyes-toggle mono ${sandboxStrangerEyes ? 'is-active' : ''}`}
                        onClick={() => setSandboxStrangerEyes((v) => !v)}
                      >
                        {sandboxStrangerEyes ? <LockOpen size={12} /> : <EyeOff size={12} />}
                        {sandboxStrangerEyes ? 'MY VIEW' : 'STRANGER VIEW'}
                      </button>
                    </div>
                  </div>

                  {ownedNotes.length === 0 ? (
                    <div className="lv-howto-box">
                      <p className="lv-howto-lead">
                        <strong>Your temporary private account is empty.</strong> Click{' '}
                        <strong>Get Free Test SOL</strong> on the right — Audren’s faucet sends $0
                        test SOL and pays the Solana fee so you don’t need Phantom.
                      </p>
                      <ul className="lv-howto-steps">
                        <li>
                          <span className="lv-step-dot" aria-hidden="true" />
                          <div>
                            <strong>Go Private</strong> — get free test SOL and open the deposit on
                            Solscan.
                          </div>
                        </li>
                        <li>
                          <span className="lv-step-dot" aria-hidden="true" />
                          <div>
                            <strong>Send Private</strong> — spend it yourself and watch the SOL
                            amount disappear on Solscan.
                          </div>
                        </li>
                        <li>
                          <span className="lv-step-dot" aria-hidden="true" />
                          <div>
                            <strong>Prove Receipt</strong> — verify a single-note opening against
                            Solana’s commitment.
                          </div>
                        </li>
                      </ul>
                    </div>
                  ) : (
                    <div className="lv-balance-list">
                      {ownedNotes.map((n) => (
                        <div
                          key={`${n.pageId.toString()}-${n.slotIndex}`}
                          className={`lv-private-row ${sandboxStrangerEyes ? 'is-redacted' : 'is-unlocked'}`}
                        >
                          <div className="lv-private-row-top">
                            <div className="lv-token-id">
                              <span className="lv-avatar is-locked">
                                {sandboxStrangerEyes ? <Lock size={13} /> : <LockOpen size={13} />}
                              </span>
                              <div>
                                <strong>
                                  {sandboxStrangerEyes ? 'Hidden balance' : `SOL · Box #${n.slotIndex}`}
                                  {!sandboxStrangerEyes && n.memoText ? (
                                    <span className="lv-memo-tag mono">{n.memoText}</span>
                                  ) : null}
                                </strong>
                                <span className="mono">
                                  {sandboxStrangerEyes
                                    ? n.valueBlinding !== 0n
                                      ? 'Blinded token & amount · one-time key · encrypted memo'
                                      : 'One-time key & encrypted memo · deposit amount was public at entry'
                                    : 'Unlocked locally with your temporary browser key'}
                                </span>
                              </div>
                            </div>

                            {sandboxStrangerEyes ? (
                              <div className="lv-redacted-bar" title="Hidden on Solscan" />
                            ) : (
                              <div className="lv-balance-amt mono is-pine">
                                {(Number(n.amount) / 1e9).toFixed(4)} SOL
                              </div>
                            )}
                          </div>

                          {!sandboxStrangerEyes && (
                            <div className="lv-private-row-actions mono">
                              <button
                                type="button"
                                className="lv-row-chip is-primary"
                                onClick={() => setSandboxTab('spend')}
                              >
                                <Send size={11} /> Send Privately
                              </button>
                              {result?.decrypted && (
                                <button
                                  type="button"
                                  className="lv-row-chip"
                                  onClick={() => setSandboxTab('receipt')}
                                >
                                  <ShieldCheck size={11} /> Prove Receipt
                                </button>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="lv-private-foot mono">
                    <div className="lv-addr-row">
                      <span>TEMP KEY:</span>
                      <code>{keys ? shortHash(keys.address, 8, 5) : 'Creating…'}</code>
                      {keys && (
                        <button
                          type="button"
                          className="lv-copy-chip"
                          onClick={() => copyText('sb-addr', keys.address)}
                        >
                          {copiedId === 'sb-addr' ? <Check size={11} /> : <Copy size={11} />}
                          {copiedId === 'sb-addr' ? 'COPIED' : 'COPY'}
                        </button>
                      )}
                    </div>
                    <span>FAUCET PAYS FEE ({faucetShort})</span>
                  </div>
                </section>

                {/* RIGHT CARD: 3 SIMPLE STEP TABS — ONE ACTION AT A TIME */}
                <section className="lv-card lv-simple-action" aria-label="Sandbox test actions">
                  <div className="lv-verb-tabs sb-verb-tabs-3" role="tablist">
                    <button
                      type="button"
                      role="tab"
                      aria-selected={sandboxTab === 'fund'}
                      className={`lv-verb-tab ${sandboxTab === 'fund' ? 'is-active' : ''}`}
                      onClick={() => setSandboxTab('fund')}
                    >
                      <strong>Go Private</strong>
                      <span className="mono">
                        {result || totalOwnedLamports > 0n ? 'Done ✓ · Fund more' : 'Get free test SOL'}
                      </span>
                    </button>
                    <button
                      type="button"
                      role="tab"
                      aria-selected={sandboxTab === 'spend'}
                      className={`lv-verb-tab ${sandboxTab === 'spend' ? 'is-active' : ''}`}
                      onClick={() => setSandboxTab('spend')}
                    >
                      <strong>Send Private</strong>
                      <span className="mono">
                        {transferResult ? 'Done ✓ · Send again' : 'Hide amount on Solscan'}
                      </span>
                    </button>
                    <button
                      type="button"
                      role="tab"
                      aria-selected={sandboxTab === 'receipt'}
                      className={`lv-verb-tab ${sandboxTab === 'receipt' ? 'is-active' : ''}`}
                      onClick={() => setSandboxTab('receipt')}
                    >
                      <strong>Prove Receipt</strong>
                      <span className="mono">
                        {receipt ? 'Tested ✓' : 'Commitment check'}
                      </span>
                    </button>
                  </div>

                  <div className="lv-simple-body">
                    {/* ---- SANDBOX TAB 1: GET FREE TEST SOL PRIVATELY ---- */}
                    {sandboxTab === 'fund' && (
                      <>
                        <div className="lv-dir-pill mono">
                          <span>FREE FAUCET ({faucetShort})</span>
                          <ArrowRight size={12} />
                          <strong>YOUR TEST PRIVATE BALANCE</strong>
                        </div>

                        <div className="lv-field-block">
                          <span className="lv-label mono">PICK FREE TEST AMOUNT</span>
                          <div className="lv-quick-pills mono">
                            {PRESET_AMOUNTS.map((opt) => (
                              <button
                                key={opt.label}
                                type="button"
                                className={`lv-quick-pill ${selectedLamports === opt.lamports ? 'is-active' : ''}`}
                                onClick={() => setSelectedLamports(opt.lamports)}
                                disabled={submitting}
                              >
                                {opt.label}
                              </button>
                            ))}
                          </div>
                        </div>

                        <div className="lv-field-block">
                          <label className="lv-label mono" htmlFor="demo-memo-input">
                            ENCRYPTED MEMO (MAX 7 BYTES · AES-256-GCM)
                          </label>
                          <input
                            id="demo-memo-input"
                            type="text"
                            maxLength={7}
                            value={memo}
                            onChange={(e) => setMemo(clampUtf8Bytes(e.target.value, 7))}
                            placeholder="PAYROLL"
                            className="lv-input mono"
                            disabled={submitting}
                          />
                          <div className="lv-quick-pills mono">
                            {PRESET_MEMOS.map((m) => (
                              <button
                                key={m}
                                type="button"
                                className={`lv-quick-pill ${memo === m ? 'is-active' : ''}`}
                                onClick={() => setMemo(m)}
                                disabled={submitting}
                              >
                                {m}
                              </button>
                            ))}
                          </div>
                        </div>

                        <p className="lv-plain-summary">
                          Deposits <strong>{selectedSolLabel} free Devnet test SOL</strong> into the
                          shared pool under a fresh one-time key. On Solscan, the faucet payer, SOL
                          amount, and pool slot are public by design — while your reusable{' '}
                          <code>aud1…</code> address and encrypted{' '}
                          <strong>“{displayMemo}”</strong> memo never appear in plaintext.
                        </p>

                        <button
                          type="button"
                          className="btn-pine lv-submit-btn"
                          onClick={() => void handleLiveShield()}
                          disabled={!keys || submitting}
                        >
                          {submitting ? (
                            <>
                              <Loader2 size={15} className="spin" />
                              {activeStep === 1
                                ? '1/3 Sealing in your browser…'
                                : activeStep === 2
                                  ? '2/3 Confirming on Solana Devnet…'
                                  : '3/3 Unlocking with your key…'}
                            </>
                          ) : (
                            <>
                              Get {selectedSolLabel} Free Test SOL Privately <ArrowRight size={15} />
                            </>
                          )}
                        </button>

                        {submitError && (
                          <div className="alert-banner is-error">
                            <AlertCircle size={15} />
                            <span>{submitError}</span>
                          </div>
                        )}

                        {result && (
                          <div ref={depositProofRef} className="sb-mini-proof">
                            <div className="sb-mini-proof-top">
                              <span className="sb-confirmed-pill mono">
                                <Check size={11} /> CONFIRMED ON DEVNET · BLOCK #
                                {result.slot.toLocaleString()}
                              </span>
                              <a
                                href={result.solscanUrl}
                                target="_blank"
                                rel="noreferrer"
                                className="lv-ledger-ext mono"
                              >
                                OPEN TX #1 ON SOLSCAN <ArrowUpRight size={12} />
                              </a>
                            </div>
                            <p>
                              <strong>{(Number(result.amountLamports) / 1e9).toFixed(3)} SOL</strong>{' '}
                              is now in your Test Private Balance on the left. On Solscan, the
                              faucet deposit amount and pool slot are public by design, while your
                              reusable <code>aud1…</code> address is replaced by a one-time key and{' '}
                              <strong>“{result.decrypted?.memoText ?? displayMemo}”</strong> is
                              stored only as AES-256-GCM ciphertext.
                            </p>
                            <button
                              type="button"
                              className="btn-ink mono"
                              onClick={() => setSandboxTab('spend')}
                            >
                              Next: Send Privately (Hide Amount on Solscan){' '}
                              <ArrowRight size={13} />
                            </button>
                          </div>
                        )}
                      </>
                    )}

                    {/* ---- SANDBOX TAB 2: SPEND PRIVATELY (PROVES ACCESS + HIDES AMOUNT) ---- */}
                    {sandboxTab === 'spend' && (
                      <>
                        <div className="lv-dir-pill mono">
                          <span>YOUR TEST BALANCE</span>
                          <ArrowRight size={12} />
                          <strong>AMOUNT HIDDEN ON SOLSCAN</strong>
                        </div>

                        {!latestSpendableNote ? (
                          <div className="lv-empty-action">
                            <p>
                              <strong>Get free test SOL in Go Private first</strong> so your browser
                              has a private balance to spend.
                            </p>
                            <button
                              type="button"
                              className="btn-pine"
                              onClick={() => setSandboxTab('fund')}
                            >
                              <ArrowLeft size={14} /> Open Go Private
                            </button>
                          </div>
                        ) : (
                          <>
                            <div className="lv-field-block">
                              <span className="lv-label mono">HOW MUCH TO SEND PRIVATELY</span>
                              <div className="lv-toggle-row">
                                <button
                                  type="button"
                                  className={`lv-chip-btn ${spendPct === 50 ? 'is-active' : ''}`}
                                  onClick={() => setSpendPct(50)}
                                  disabled={spending}
                                >
                                  50% ({(Number(latestSpendableNote.amount / 2n) / 1e9).toFixed(4)}{' '}
                                  SOL + private change)
                                </button>
                                <button
                                  type="button"
                                  className={`lv-chip-btn ${spendPct === 100 ? 'is-active' : ''}`}
                                  onClick={() => setSpendPct(100)}
                                  disabled={spending}
                                >
                                  100% ({(Number(latestSpendableNote.amount) / 1e9).toFixed(4)} SOL)
                                </button>
                              </div>
                            </div>

                            <div className="lv-field-block">
                              <label className="lv-label mono" htmlFor="sb-spend-memo">
                                NEW ENCRYPTED MEMO (MAX 7 BYTES · AES-256-GCM)
                              </label>
                              <input
                                id="sb-spend-memo"
                                type="text"
                                maxLength={7}
                                className="lv-input mono"
                                value={spendMemo}
                                onChange={(e) =>
                                  setSpendMemo(clampUtf8Bytes(e.target.value.toUpperCase(), 7))
                                }
                                disabled={spending}
                              />
                            </div>

                            <p className="lv-plain-summary">
                              Your browser creates a real zero-knowledge proof locally and Audren’s
                              Devnet Relayer pays the Solana network fee.{' '}
                              <strong>
                                The private transfer blinds token and amount and uses a fresh recipient key.
                                The relay, candidate pages and transaction metadata remain public.
                              </strong>
                            </p>

                            <button
                              type="button"
                              className="btn-pine lv-submit-btn"
                              onClick={() => void handleLivePrivateSpend()}
                              disabled={spending}
                            >
                              {spending ? (
                                <>
                                  <Loader2 size={15} className="spin" />
                                  {spendStatus ?? 'Proving & sending privately…'}
                                </>
                              ) : (
                                <>
                                  <Send size={15} />
                                  Send Privately Live (Proves You Control It)
                                </>
                              )}
                            </button>
                          </>
                        )}

                        {spendError && (
                          <div className="alert-banner is-error">
                            <AlertCircle size={15} />
                            <span>{spendError}</span>
                          </div>
                        )}

                        {transferResult && (
                          <div ref={transferProofRef} className="sb-mini-proof is-dark-proof">
                            <div className="sb-mini-proof-top">
                              <span className="sb-confirmed-pill is-dark mono">
                                <ShieldCheck size={11} /> PRIVATE SPEND CONFIRMED ·{' '}
                                {transferResult.proverMs} ms PROOF
                              </span>
                            </div>
                            <p>
                              Moved{' '}
                              <strong>
                                {(Number(transferResult.amountLamports) / 1e9).toFixed(4)} SOL
                              </strong>{' '}
                              privately. Compare both transactions on Solscan:
                            </p>
                            <div className="sb-compare-mini mono">
                              {result && (
                                <a
                                  href={result.solscanUrl}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="btn-rule-sm"
                                >
                                  TX #1 (DEPOSIT) <ArrowUpRight size={11} />
                                </a>
                              )}
                              <a
                                href={transferResult.solscanUrl}
                                target="_blank"
                                rel="noreferrer"
                                className="btn-pine"
                                style={{ padding: '7px 12px', fontSize: '0.74rem' }}
                              >
                                TX #2 (PRIVATE · BLINDED AMOUNT) <ArrowUpRight size={12} />
                              </a>
                            </div>
                            <button
                              type="button"
                              className="btn-rule-sm mono"
                              onClick={() => setSandboxTab('receipt')}
                            >
                              Next: Verify Commitment Receipt <ArrowRight size={12} />
                            </button>
                          </div>
                        )}
                      </>
                    )}

                    {/* ---- SANDBOX TAB 3: SELECTIVE DISCLOSURE RECEIPT ---- */}
                    {sandboxTab === 'receipt' && (
                      <>
                        <div className="lv-dir-pill mono">
                          <span>ONE PAYMENT</span>
                          <ArrowRight size={12} />
                          <strong>MATH PROOF FOR TAXES OR INVOICES</strong>
                        </div>

                        {!result?.decrypted ? (
                          <div className="lv-empty-action">
                            <p>
                              <strong>Deposit test SOL in Go Private first</strong> so you have a
                              confirmed transaction to generate a receipt for.
                            </p>
                            <button
                              type="button"
                              className="btn-pine"
                              onClick={() => setSandboxTab('fund')}
                            >
                              <ArrowLeft size={14} /> Open Go Private
                            </button>
                          </div>
                        ) : (
                          <>
                            <p className="lv-plain-summary">
                              Prove just this one deposit to an accountant or counterparty without
                              revealing your wallet or other balances — or click{' '}
                              <strong>Try Faking the Amount</strong> to watch Solana’s math reject a
                              forged receipt instantly.
                            </p>

                            <div className="lv-toggle-row">
                              <button
                                type="button"
                                className="btn-pine"
                                onClick={() => void handleGenerateReceipt(false)}
                              >
                                <ShieldCheck size={14} /> Create Real Receipt
                              </button>
                              <button
                                type="button"
                                className="btn-tamper-sm mono"
                                onClick={() => void handleGenerateReceipt(true)}
                              >
                                <ShieldAlert size={14} /> Try Faking the Amount
                              </button>
                            </div>

                            {receipt && receiptCheck && (
                              <div className="receipt-output">
                                <div
                                  className={`verify-strip ${receiptCheck.valid ? 'is-valid' : 'is-invalid'}`}
                                >
                                  <span className="mono verify-stamp">
                                    {receiptCheck.valid
                                      ? 'VERIFIED BY SOLANA ✓'
                                      : 'FORGERY CAUGHT ✕'}
                                  </span>
                                  <span>
                                    {receiptCheck.valid
                                      ? `Confirmed ${receipt.amountSol} SOL matches Solana’s locked commitment — without exposing any other balance.`
                                      : `Someone edited the receipt to ${receipt.amountSol} SOL — it no longer matches Solana’s on-chain commitment.`}
                                  </span>
                                </div>

                                <details className="receipt-json-details">
                                  <summary className="mono">
                                    <span>INSPECT RECEIPT JSON</span>
                                    <ChevronDown size={13} />
                                  </summary>
                                  <div className="receipt-json-head">
                                    <span className="mono">audren_payment_receipt.json</span>
                                    <button
                                      type="button"
                                      className="mini-action-btn mono"
                                      onClick={() =>
                                        copyText('receipt', JSON.stringify(receipt, null, 2))
                                      }
                                    >
                                      {copiedId === 'receipt' ? (
                                        <>
                                          <Check size={11} /> COPIED
                                        </>
                                      ) : (
                                        <>
                                          <Copy size={11} /> COPY JSON
                                        </>
                                      )}
                                    </button>
                                  </div>
                                  <pre className="receipt-json mono">
                                    <code>{JSON.stringify(receipt, null, 2)}</code>
                                  </pre>
                                </details>
                              </div>
                            )}
                          </>
                        )}
                      </>
                    )}
                  </div>
                </section>
              </div>

              {/* OPTIONAL COLLAPSED INSPECTOR: SHARED VAULT LOCKER WALL + BROWSER KEYS */}
              <details className="keys-drawer" style={{ marginTop: 18 }}>
                <summary className="mono">
                  <span>
                    <KeyRound
                      size={13}
                      style={{ display: 'inline', verticalAlign: '-2px', marginRight: 6 }}
                    />
                    INSPECT LIVE SHARED VAULT NOTES &amp; TEMPORARY BROWSER KEYS
                    {pool ? ` · ${pool.totalNotes} TOTAL NOTES ON DEVNET` : ''}
                  </span>
                  <ChevronDown size={15} />
                </summary>

                <div className="sb-drawer-stack">
                  {pool && (
                    <div className="sb-drawer-vault">
                      <div className="locker-wall-head">
                        <div>
                          <p className="kicker mono">
                            SHARED VAULT · EPOCH PAGE #{pool.viewingPageId}
                          </p>
                          <p className="ledger-sub" style={{ marginTop: 4 }}>
                            Every box is an on-chain note in this Devnet EpochPage. Stranger notes
                            stay encrypted; your browser’s viewing key decrypts only yours.
                          </p>
                        </div>
                        <div className="locker-wall-actions">
                          <button
                            type="button"
                            className="btn-rule-sm mono"
                            onClick={() => void refreshPool(keys)}
                            disabled={poolLoading}
                          >
                            <RefreshCw size={12} className={poolLoading ? 'spin' : ''} /> REFRESH
                          </button>
                          <a
                            href={solscanAddress(pool.pagePda, 'devnet')}
                            target="_blank"
                            rel="noreferrer"
                            className="btn-rule-sm mono"
                          >
                            VAULT ON SOLSCAN <ArrowUpRight size={12} />
                          </a>
                        </div>
                      </div>

                      <div className="locker-grid">
                        {recentLockers.map((n) => {
                          const slotKey = `${pool.viewingPageId}-${n.slotIndex}`
                          const owned = ownedSlotMap.get(slotKey)
                          const wasSpent = spentSlotSet.has(slotKey)
                          const isFallbackYours =
                            !owned &&
                            !wasSpent &&
                            result?.decrypted &&
                            result.pageId === pool.viewingPageId &&
                            result.slotIndex === n.slotIndex

                          return (
                            <div
                              key={n.slotIndex}
                              className={`locker-box ${owned || isFallbackYours ? 'is-yours' : wasSpent ? 'is-spent' : ''}`}
                            >
                              <div className="locker-box-top mono">
                                <span className="locker-id">BOX #{n.slotIndex}</span>
                                {owned || isFallbackYours ? (
                                  <span className="locker-state is-open">
                                    <LockOpen size={11} /> YOURS
                                  </span>
                                ) : wasSpent ? (
                                  <span className="locker-state is-spent">
                                    <Check size={11} /> SPENT BY YOU
                                  </span>
                                ) : (
                                  <span className="locker-state">
                                    <Lock size={11} /> LOCKED
                                  </span>
                                )}
                              </div>

                              {owned ? (
                                <div className="locker-open-body">
                                  <div className="locker-open-amt mono">
                                    {(Number(owned.amount) / 1e9).toFixed(4)} SOL
                                  </div>
                                  <div className="locker-open-memo mono">
                                    {owned.memoText || '(no memo)'}
                                  </div>
                                </div>
                              ) : isFallbackYours && result?.decrypted ? (
                                <div className="locker-open-body">
                                  <div className="locker-open-amt mono">
                                    {(Number(result.decrypted.amountLamports) / 1e9).toFixed(4)} SOL
                                  </div>
                                  <div className="locker-open-memo mono">
                                    {result.decrypted.memoText || '(no memo)'}
                                  </div>
                                </div>
                              ) : wasSpent ? (
                                <div className="locker-locked-body">
                                  <span className="locker-spent-note mono">
                                    SPENT · NULLIFIER RECORDED (INPUT CONCEALED IN RING)
                                  </span>
                                </div>
                              ) : (
                                <div className="locker-locked-body">
                                  <span className="redaction-bar" style={{ width: '88%' }} />
                                  <span className="redaction-bar" style={{ width: '58%' }} />
                                  <span className="locker-stranger-note mono">
                                    STRANGER’S NOTE · ENCRYPTED
                                  </span>
                                </div>
                              )}
                            </div>
                          )
                        })}
                      </div>

                      <div className="locker-dev-toggle">
                        <button
                          type="button"
                          className="mini-action-btn mono"
                          onClick={() => setShowHexTable((v) => !v)}
                        >
                          {showHexTable
                            ? 'HIDE RAW ON-CHAIN HEX TABLE'
                            : 'SHOW RAW ON-CHAIN HEX TABLE'}
                          <ChevronDown
                            size={12}
                            style={{
                              transform: showHexTable ? 'rotate(180deg)' : 'none',
                              transition: 'transform 0.14s ease',
                            }}
                          />
                        </button>
                      </div>

                      {showHexTable && (
                        <div className="ledger-table-wrap" style={{ marginTop: 14 }}>
                          <table className="ledger-table">
                            <thead>
                              <tr>
                                <th>Box #</th>
                                <th>One-Time Address (Public)</th>
                                <th>Encrypted Data (64 B)</th>
                                <th>Your Reading Key</th>
                              </tr>
                            </thead>
                            <tbody>
                              {recentLockers.map((n) => {
                                const slotKey = `${pool.viewingPageId}-${n.slotIndex}`
                                const owned = ownedSlotMap.get(slotKey)
                                const wasSpent = spentSlotSet.has(slotKey)
                                return (
                                  <tr key={n.slotIndex} className={owned ? 'is-yours' : ''}>
                                    <td className="mono">#{n.slotIndex}</td>
                                    <td className="mono">{shortHash(n.stealthPk, 10, 8)}</td>
                                    <td className="mono muted-cell">
                                      {n.ciphertextHex.slice(0, 34)}…
                                    </td>
                                    <td>
                                      {owned ? (
                                        <span className="row-badge is-yours mono">
                                          YOURS · {(Number(owned.amount) / 1e9).toFixed(4)} SOL
                                        </span>
                                      ) : wasSpent ? (
                                        <span className="row-badge is-locked mono">SPENT BY YOU</span>
                                      ) : (
                                        <span className="row-badge is-locked mono">REDACTED</span>
                                      )}
                                    </td>
                                  </tr>
                                )
                              })}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  )}

                  <div className="keys-drawer-body">
                    <div className="keys-drawer-col">
                      <div className="drawer-subhead">
                        <span className="mono">LOCAL BROWSER KEYS (NEVER LEAVE YOUR DEVICE)</span>
                        <button
                          type="button"
                          className="mini-action-btn mono"
                          onClick={() => void regenerateKeys()}
                          disabled={submitting || spending}
                        >
                          <RefreshCw size={11} /> NEW ACCOUNT
                        </button>
                      </div>

                      <div className="key-box">
                        <div className="key-row">
                          <span className="key-label mono">
                            PRIVATE RECEIVE ADDRESS (SAFE TO SHARE)
                          </span>
                          <div className="key-val-wrap">
                            <code className="mono">
                              {keys ? shortHash(keys.address, 16, 10) : 'Creating…'}
                            </code>
                            {keys && (
                              <button
                                type="button"
                                className="icon-copy-btn"
                                aria-label="Copy Audren address"
                                onClick={() => copyText('addr', keys.address)}
                              >
                                {copiedId === 'addr' ? <Check size={13} /> : <Copy size={13} />}
                              </button>
                            )}
                          </div>
                        </div>
                        <div className="key-row">
                          <span className="key-label mono">
                            SECRET READING KEY (ONLY ON THIS DEVICE)
                          </span>
                          <div className="key-val-wrap">
                            <code className="mono">
                              {!keys
                                ? '…'
                                : showSecrets
                                  ? shortHash(keys.viewingKeyB58, 14, 10)
                                  : '••••••••••••••••••••••••••••'}
                            </code>
                            <button
                              type="button"
                              className="icon-copy-btn"
                              onClick={() => setShowSecrets((s) => !s)}
                              aria-label={showSecrets ? 'Hide reading key' : 'Reveal reading key'}
                            >
                              {showSecrets ? <EyeOff size={13} /> : <Eye size={13} />}
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="keys-drawer-col">
                      <div className="drawer-subhead">
                        <span className="mono">ON-CHAIN TRANSACTION DETAILS</span>
                      </div>
                      {result ? (
                        <dl className="tech-kv mono">
                          <div>
                            <dt>Pool Batch / Slot</dt>
                            <dd>
                              Batch #{result.pageId} · Box #{result.slotIndex} (
                              {shortHash(result.pagePda, 10, 8)})
                            </dd>
                          </div>
                          <div>
                            <dt>One-Time Receive Address</dt>
                            <dd>{result.note.stealthPk}</dd>
                          </div>
                          <div>
                            <dt>On-Chain Commitment</dt>
                            <dd>{result.note.commitment}</dd>
                          </div>
                          <div>
                            <dt>Encrypted Note (64 B)</dt>
                            <dd>{result.note.ciphertextHex}</dd>
                          </div>
                        </dl>
                      ) : (
                        <p className="demo-help" style={{ marginTop: 10 }}>
                          Complete a deposit in Go Private above to inspect live on-chain transaction details.
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              </details>
            </div>
          )}

          {/* ================================================================
              VERIFIED MAINNET PRODUCTION TRANSACTIONS
             ================================================================ */}
          <section className="verified-tx-section">
            <div className="section-head-split">
              <div>
                <h2>Inspect settled transactions on Solscan.</h2>
              </div>
              <p className="section-sub">
                Open real Mainnet and Devnet transactions on Solscan to compare public fields
                against what proofs conceal.
              </p>
            </div>

            <div className="lifecycle-grid">
              {REAL_LIFECYCLE_STEPS.map((item) => {
                const cluster = item.isMainnet ? 'mainnet' : 'devnet'
                const href = item.isProgram
                  ? solscanAddress(item.sig, cluster)
                  : solscanTx(item.sig, cluster)
                const explorer = item.isProgram
                  ? `https://explorer.solana.com/address/${item.sig}`
                  : explorerTx(item.sig, cluster)
                return (
                  <article key={item.id} className="lifecycle-cell">
                    <div className="lifecycle-top mono">
                      <span className="lc-step">{item.tag}</span>
                      <span className={`cluster-tag ${item.isMainnet ? 'is-mainnet' : ''}`}>
                        {item.cluster}
                      </span>
                    </div>
                    <h3>{item.title}</h3>
                    <p className="lc-line">
                      <strong>Public sees:</strong> {item.whatPublicSees}
                    </p>
                    <p className="lc-line is-hidden-line">
                      <strong>Stays private:</strong> {item.whatStaysPrivate}
                    </p>
                    <div className="lc-links mono">
                      <a href={href} target="_blank" rel="noreferrer" className="lc-solscan">
                        SOLSCAN <ArrowUpRight size={12} />
                      </a>
                      <a href={explorer} target="_blank" rel="noreferrer" className="lc-exp">
                        EXPLORER <ArrowUpRight size={11} />
                      </a>
                    </div>
                  </article>
                )
              })}
            </div>
          </section>
        </div>
      </main>

      <SiteFooter current="demo" />
    </div>
  )
}
