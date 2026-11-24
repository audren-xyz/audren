'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import {
  AlertCircle,
  ArrowLeft,
  ArrowUpRight,
  Check,
  Copy,
  Cpu,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  Lock,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Wallet,
} from 'lucide-react'
import { SiteHeader } from '@/components/SiteHeader'
import { SiteFooter } from '@/components/SiteFooter'
import { LiveWalletVault } from '@/components/LiveWalletVault'
import {
  ASSET_MODE_PRIVATE,
  AUDREN_PROGRAM_ID,
  NUM_LANES,
  SUBTREE_LEAVES,
  VK_ID_DEFAULT,
  WSOL_MINT,
  ZERO_HASHES_4ARY,
  base58Decode,
  buildTransactInstruction,
  buildWitnessFromFrozenSubsiblings,
  bytes32ToFrMasked,
  computeMerkleRoot4Ary,
  computeNoteCommitment,
  computePageRollovers,
  computeSubtree256Root,
  computeTransactCtxHash,
  decodeSubtreePage,
  deriveAssetId,
  deriveKeysFromSeed,
  deriveStealthOwner,
  deriveSubtreePdaSync,
  encryptNoteMemo,
  exportFullViewingKey,
  extractIntraSubtreeSiblings,
  fetchGlobalRootHistory,
  frFromBeBytesStrict,
  frToBeBytes,
  fromBase64,
  fromHex,
  pickRandomLaneId,
  recommendedTransactCuLimit,
  reconstructWitness,
  toBase64,
  toHex,
  tryDecryptAndVerifyMemo,
  verifySelectiveDisclosureProof,
  type AccountBatchFetcher,
  type AudrenKeys,
  type MerklePath4Ary,
  type SelectiveDisclosureProof,
} from '@/lib/audren-crypto'
import {
  dummyInputWitness,
  proveJoinsplitInBrowser,
  warmBrowserWasmProver,
} from '@/lib/audren-prover'
import { AUDREN, shortHash, solscanAddress, solscanTx } from '@/lib/protocol'

type DemoMode = 'wallet' | 'sandbox'

interface DevnetPoolSnapshot {
  error?: string
  initialized?: boolean
  paused?: boolean
  activeLanes?: number
  rootsPda?: string
  relayerAvailable?: boolean
  relayerAddress?: string | null
  lanes?: Array<{ laneId: number; nextLeaf: string; nfCount: string } | null>
  rootHistory?: {
    slotCursor: number
    epochCursor: number
    slotCount: number
    epochCount: number
    latestSlot: string
    stableSlot: string
    epochInterval: string
    latestSuperRoot: string
    stableSuperRoot: string
    latestLaneCounts: string[]
    stableLaneCounts: string[]
  } | null
}

interface SandboxNote {
  isLiveDevnet: boolean
  rootRingKind?: number
  rootRingIdx?: number
  rootCommitment?: 'finalized' | 'confirmed'
  laneId: number
  leafIndex: bigint
  amountLamports: bigint
  tweak: bigint
  blinding: bigint
  stealthOwner: bigint
  assetId: bigint
  commitment: bigint
  memo: Uint8Array
  path: MerklePath4Ary | null
  superRoot: bigint | null
  devnetSig?: string
}

interface SandboxProofArtifact {
  elapsedMs: number
  proofHex: string
  proofBytes: number
  nf0Hex: string
  cm0Hex: string
  cm1Hex: string
  ctxHashHex: string
  recipientAmountLamports: bigint
  changeAmountLamports: bigint
  transactDevnetSig?: string
  wireBytes?: number
}

const PRESET_AMOUNTS = [
  { label: '0.001 SOL', lamports: 1_000_000n },
  { label: '0.002 SOL', lamports: 2_000_000n },
  { label: '0.005 SOL', lamports: 5_000_000n },
] as const

const WSOL_MINT_BYTES = base58Decode(WSOL_MINT)

function randomFr(): bigint {
  return bytes32ToFrMasked(crypto.getRandomValues(new Uint8Array(32)))
}

function createDevnetBatchFetcher(
  commitment: 'confirmed' | 'finalized' = 'confirmed',
): AccountBatchFetcher {
  return async (addresses: readonly string[]) => {
    const out: (Uint8Array | null)[] = new Array(addresses.length).fill(null)
    for (let off = 0; off < addresses.length; off += 100) {
      const chunk = addresses.slice(off, off + 100)
      const res = await fetch('/api/rpc/accounts', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ cluster: 'devnet', addresses: chunk, commitment }),
      })
      const json = (await res.json()) as { accounts?: Array<string | null>; error?: string }
      if (!res.ok || !json.accounts) {
        throw new Error(json.error ?? `Devnet RPC batch fetch HTTP ${res.status}`)
      }
      for (let i = 0; i < chunk.length; i++) {
        const b64 = json.accounts[i]
        out[off + i] = b64 ? fromBase64(b64) : null
      }
    }
    return out
  }
}

export function DevnetDemoExperience() {
  const [mode, setMode] = useState<DemoMode>('wallet')
  const [keys, setKeys] = useState<AudrenKeys | null>(null)
  const [strangerView, setStrangerView] = useState(false)
  const [selectedAmount, setSelectedAmount] = useState<bigint>(PRESET_AMOUNTS[0].lamports)
  const [sandboxNote, setSandboxNote] = useState<SandboxNote | null>(null)
  const [proofArtifact, setProofArtifact] = useState<SandboxProofArtifact | null>(null)
  const [receiptTampered, setReceiptTampered] = useState(false)
  const [receiptValid, setReceiptValid] = useState<boolean | null>(null)
  const [receiptSourceNote, setReceiptSourceNote] = useState<string | null>(null)
  const [verifyingReceipt, setVerifyingReceipt] = useState(false)
  const [proving, setProving] = useState(false)
  const [fundingDevnet, setFundingDevnet] = useState(false)
  const [devnetRelayerAvailable, setDevnetRelayerAvailable] = useState(false)
  const [devnetRelayerAddress, setDevnetRelayerAddress] = useState<string | null>(null)
  const [devnetRootHistoryMigrating, setDevnetRootHistoryMigrating] = useState(false)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const sandboxEpochRef = useRef(0)

  const initSandboxKeys = useCallback(() => {
    sandboxEpochRef.current += 1
    const seed = crypto.getRandomValues(new Uint8Array(32))
    const derived = deriveKeysFromSeed(seed)
    setKeys(derived)
    setSandboxNote(null)
    setProofArtifact(null)
    setReceiptValid(null)
    setReceiptSourceNote(null)
    setReceiptTampered(false)
    setFundingDevnet(false)
    setProving(false)
    setVerifyingReceipt(false)
    setErrorMsg(null)
  }, [])

  const selectMode = useCallback(
    (next: DemoMode) => {
      setMode(next)
      if (next === 'sandbox' && !keys) {
        initSandboxKeys()
      }
    },
    [keys, initSandboxKeys],
  )

  useEffect(() => {
    if (typeof window === 'undefined') return
    let active = true
    const q = new URLSearchParams(window.location.search).get('mode')
    if (q === 'sandbox') {
      void Promise.resolve().then(() => {
        if (!active) return
        setMode('sandbox')
        setKeys((prev) => prev ?? deriveKeysFromSeed(crypto.getRandomValues(new Uint8Array(32))))
      })
    }
    return () => {
      active = false
    }
  }, [])

  useEffect(() => {
    if (mode !== 'sandbox') return
    let active = true
    void warmBrowserWasmProver().catch(() => {})
    fetch('/api/devnet/pool')
      .then((r) => (r.ok ? r.json() : null))
      .then((d: DevnetPoolSnapshot | null) => {
        if (!active) return
        setDevnetRelayerAvailable(Boolean(d?.relayerAvailable))
        setDevnetRelayerAddress(d?.relayerAddress ?? null)
        setDevnetRootHistoryMigrating(Boolean(d?.initialized && !d?.rootHistory))
      })
      .catch(() => {
        if (!active) return
        setDevnetRelayerAvailable(false)
        setDevnetRelayerAddress(null)
        setDevnetRootHistoryMigrating(false)
      })
    return () => {
      active = false
    }
  }, [mode])

  const syncLiveDevnetWitness = async (note: SandboxNote): Promise<SandboxNote> => {
    const poolRes = await fetch('/api/devnet/pool').catch(() => null)
    if (poolRes?.ok) {
      const pool = (await poolRes.json().catch(() => null)) as DevnetPoolSnapshot | null
      if (pool?.relayerAddress) setDevnetRelayerAddress(pool.relayerAddress)
      if (pool?.initialized && !pool.rootHistory) {
        setDevnetRootHistoryMigrating(true)
        throw new Error('Pool #0 GlobalRootHistory migration in progress; retry shortly')
      }
      if (pool?.rootHistory) {
        setDevnetRootHistoryMigrating(false)
      }
    }
    const fetchFinalized = createDevnetBatchFetcher('finalized')
    const fetchConfirmed = createDevnetBatchFetcher('confirmed')
    const { history, snapshot, commitment } = await fetchGlobalRootHistory({
      poolId: 0,
      programId: AUDREN_PROGRAM_ID,
      fetchFinalized,
      fetchConfirmed,
      requiredNotes: [{ laneId: note.laneId, leafIndex: note.leafIndex }],
    })
    const { superRoot, path, rootRingKind, rootRingIdx } = await reconstructWitness({
      fetchBatch: commitment === 'finalized' ? fetchFinalized : fetchConfirmed,
      poolId: 0,
      laneId: note.laneId,
      leafIdx: note.leafIndex,
      rootHistory: history,
      rootSnapshot: snapshot,
      viewSk: keys?.viewSk,
    })
    return {
      ...note,
      rootRingKind,
      rootRingIdx,
      rootCommitment: commitment,
      path,
      superRoot,
    }
  }

  const handleShieldSandboxNote = async (broadcastDevnet: boolean) => {
    if (!keys || fundingDevnet || proving || verifyingReceipt) return
    if (broadcastDevnet && devnetRootHistoryMigrating) {
      setErrorMsg('Pool #0 GlobalRootHistory migration in progress; retry shortly')
      return
    }
    const startEpoch = sandboxEpochRef.current
    setErrorMsg(null)
    setProofArtifact(null)
    setReceiptValid(null)
    setReceiptSourceNote(null)
    setReceiptTampered(false)

    try {
      const mintBytes = WSOL_MINT_BYTES
      const assetId = deriveAssetId(mintBytes)
      const fvk = exportFullViewingKey(keys)

      if (!broadcastDevnet) {
        const { tweak, blinding, memo } = encryptNoteMemo(
          keys.viewPk,
          crypto.getRandomValues(new Uint8Array(32)),
          selectedAmount,
          mintBytes,
        )
        const stealthOwner = deriveStealthOwner(keys.spendPk, tweak)
        const commitment = computeNoteCommitment(stealthOwner, assetId, selectedAmount, blinding)
        const dec = tryDecryptAndVerifyMemo(fvk, memo, frToBeBytes(commitment))
        if (!dec || dec.amount !== selectedAmount) {
          throw new Error('Local X25519 ChaCha20-Poly1305 memo verification failed')
        }

        const laneId = 0
        const leafIndex = 0n
        const leaves = [commitment]
        const { siblings: intraSiblings, positions: intraPositions } = extractIntraSubtreeSiblings(
          leaves,
          1,
          0,
        )
        const lane0Root = computeSubtree256Root(leaves, 1)
        const emptyLaneRoot = ZERO_HASHES_4ARY[18]!
        const laneRoots = Array.from({ length: NUM_LANES }, (_, i) =>
          i === laneId ? lane0Root : emptyLaneRoot,
        )
        const path = buildWitnessFromFrozenSubsiblings({
          laneId,
          targetLeafIdx: leafIndex,
          intraSiblings,
          intraPositions,
          laneRoots,
          laneLeafCount: 1n,
          finalizedSubtreeRoots: [],
          frontierPageLeaves: leaves,
        })
        const superRoot = computeMerkleRoot4Ary(path, commitment)

        setSandboxNote({
          isLiveDevnet: false,
          laneId,
          leafIndex,
          amountLamports: selectedAmount,
          tweak,
          blinding,
          stealthOwner,
          assetId,
          commitment,
          memo,
          path,
          superRoot,
        })
        return
      }

      // Live Devnet unified Deposit via faucet, then decrypt real on-chain memo & sync Merkle witness
      setFundingDevnet(true)
      const poolRes = await fetch('/api/devnet/pool').catch(() => null)
      if (sandboxEpochRef.current !== startEpoch) return
      if (poolRes?.ok) {
        const pool = (await poolRes.json().catch(() => null)) as DevnetPoolSnapshot | null
        if (sandboxEpochRef.current !== startEpoch) return
        if (pool?.relayerAddress) setDevnetRelayerAddress(pool.relayerAddress)
        if (pool?.initialized && !pool.rootHistory) {
          setDevnetRootHistoryMigrating(true)
          throw new Error('Pool #0 GlobalRootHistory migration in progress; retry shortly')
        }
        if (pool?.rootHistory) {
          setDevnetRootHistoryMigrating(false)
        }
      }
      const res = await fetch('/api/devnet/deposit', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          recipientAddress: keys.address,
          amountLamports: selectedAmount.toString(),
          poolId: 0,
        }),
      })
      const j = (await res.json()) as {
        signature?: string
        laneId?: number
        leafIndex?: string
        amountLamports?: string
        commitmentHex?: string
        memoB64?: string
        error?: string
      }
      if (sandboxEpochRef.current !== startEpoch) return
      if (!res.ok || !j.signature || !j.memoB64 || !j.commitmentHex) {
        if (j.error?.includes('GlobalRootHistory')) {
          setDevnetRootHistoryMigrating(true)
        }
        throw new Error(j.error ?? `Devnet deposit HTTP ${res.status}`)
      }

      const memo = fromBase64(j.memoB64)
      const cmBytes = fromHex(j.commitmentHex)
      const dec = tryDecryptAndVerifyMemo(fvk, memo, cmBytes)
      if (!dec) {
        throw new Error('Failed to decrypt & verify live Devnet 106 B memo against on-chain commitment')
      }
      const tweak = dec.tweak
      const blinding = dec.blinding
      const stealthOwner = deriveStealthOwner(keys.spendPk, tweak)
      const commitment = frFromBeBytesStrict(cmBytes)

      const baseNote: SandboxNote = {
        isLiveDevnet: true,
        laneId: j.laneId ?? 0,
        leafIndex: BigInt(j.leafIndex ?? '0'),
        amountLamports: dec.amount,
        tweak,
        blinding,
        stealthOwner,
        assetId,
        commitment,
        memo,
        path: null,
        superRoot: null,
        devnetSig: j.signature,
      }
      const hydrated = await syncLiveDevnetWitness(baseNote)
      if (sandboxEpochRef.current !== startEpoch) return
      setSandboxNote(hydrated)
    } catch (err) {
      if (sandboxEpochRef.current === startEpoch) {
        setErrorMsg(err instanceof Error ? err.message : String(err))
      }
    } finally {
      if (broadcastDevnet && sandboxEpochRef.current === startEpoch) {
        setFundingDevnet(false)
      }
    }
  }

  const handleRunBrowserWasmProof = async (broadcastLiveTransact: boolean) => {
    if (
      !keys ||
      !sandboxNote ||
      !sandboxNote.path ||
      sandboxNote.superRoot === null ||
      fundingDevnet ||
      proving ||
      verifyingReceipt
    ) {
      return
    }
    if (broadcastLiveTransact && devnetRootHistoryMigrating) {
      setErrorMsg('Pool #0 GlobalRootHistory migration in progress; retry shortly')
      return
    }
    const startEpoch = sandboxEpochRef.current
    setProving(true)
    setErrorMsg(null)
    try {
      const sendAmt = sandboxNote.amountLamports / 2n
      const changeAmt = sandboxNote.amountLamports - sendAmt
      const recKeys = deriveKeysFromSeed(crypto.getRandomValues(new Uint8Array(32)))

      let outLaneId = pickRandomLaneId(4)
      let outSubSeq = 0n
      let outRootSeq = 0n
      let outMemoSeq = 0n
      let outNfSeq = 0n
      let rollover: { nextSubSeq?: bigint | null; nextMemoSeq?: bigint | null; nextNfSeq?: bigint | null } | undefined
      let relayerPayer = devnetRelayerAddress

      if (broadcastLiveTransact) {
        const poolRes = await fetch('/api/devnet/pool')
        const pool = (await poolRes.json().catch(() => ({}))) as DevnetPoolSnapshot
        if (sandboxEpochRef.current !== startEpoch) return
        if (poolRes.ok && pool.initialized && !pool.rootHistory) {
          setDevnetRootHistoryMigrating(true)
          throw new Error('Pool #0 GlobalRootHistory migration in progress; retry shortly')
        }
        if (poolRes.ok && pool.rootHistory) {
          setDevnetRootHistoryMigrating(false)
        }
        if (!poolRes.ok || !pool.initialized || !pool.relayerAddress) {
          throw new Error(pool.error ?? 'Devnet sandbox relayer is unavailable on this Worker')
        }
        if (pool.paused) {
          throw new Error('Devnet Pool #0 is currently paused; private spends are temporarily disabled')
        }
        relayerPayer = pool.relayerAddress
        setDevnetRelayerAddress(pool.relayerAddress)
        const activeLanes = pool.activeLanes ?? 0
        if (!Number.isInteger(activeLanes) || activeLanes <= 0) {
          throw new Error('Devnet Pool #0 has no active lanes yet')
        }
        outLaneId = pickRandomLaneId(activeLanes)
        const outLane = pool.lanes?.[outLaneId]
        if (!outLane) {
          throw new Error(`Devnet Pool #0 lane #${outLaneId} state is unavailable; retry in a moment`)
        }
        const nextLeaf = BigInt(outLane.nextLeaf)
        const nfCount = BigInt(outLane.nfCount)
        const roll = computePageRollovers({
          leafCount: nextLeaf,
          outputCount: 3,
          nfCount,
          spentNullifiers: 2,
        })
        outSubSeq = BigInt(roll.outSubSeq)
        outRootSeq = BigInt(roll.outRootSeq)
        outMemoSeq = BigInt(roll.outMemoSeq)
        outNfSeq = BigInt(roll.nfPageSeq)
        rollover = {
          nextSubSeq: roll.nextSubSeq !== undefined ? BigInt(roll.nextSubSeq) : null,
          nextMemoSeq: roll.nextMemoSeq !== undefined ? BigInt(roll.nextMemoSeq) : null,
          nextNfSeq: roll.nextNfSeq !== undefined ? BigInt(roll.nextNfSeq) : null,
        }
      }

      let activeNote = sandboxNote
      if (activeNote.isLiveDevnet) {
        activeNote = await syncLiveDevnetWitness(activeNote)
        if (sandboxEpochRef.current !== startEpoch) return
        setSandboxNote(activeNote)
      }
      if (!activeNote.path || activeNote.superRoot === null) {
        throw new Error('Failed to synchronize fresh Devnet GlobalRootHistory witness before proving')
      }

      const mintBytes = WSOL_MINT_BYTES
      const m0 = encryptNoteMemo(recKeys.viewPk, crypto.getRandomValues(new Uint8Array(32)), sendAmt, mintBytes)
      const recOwner = deriveStealthOwner(recKeys.spendPk, m0.tweak)
      const m1 = encryptNoteMemo(keys.viewPk, crypto.getRandomValues(new Uint8Array(32)), changeAmt, mintBytes)
      const chOwner = deriveStealthOwner(keys.spendPk, m1.tweak)
      const dummyKeys = deriveKeysFromSeed(crypto.getRandomValues(new Uint8Array(32)))
      const m2 = encryptNoteMemo(dummyKeys.viewPk, crypto.getRandomValues(new Uint8Array(32)), 0n, mintBytes)
      const dummyOwner = deriveStealthOwner(dummyKeys.spendPk, m2.tweak)

      const memosConcat = new Uint8Array(
        m0.memo.byteLength + m1.memo.byteLength + m2.memo.byteLength,
      )
      memosConcat.set(m0.memo, 0)
      memosConcat.set(m1.memo, m0.memo.byteLength)
      memosConcat.set(m2.memo, m0.memo.byteLength + m1.memo.byteLength)

      const ctxHash = computeTransactCtxHash({
        poolId: 0,
        vkId: VK_ID_DEFAULT,
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

      const { result, elapsedMs } = await proveJoinsplitInBrowser({
        superRoot: activeNote.superRoot,
        txAssetId: activeNote.assetId,
        publicAssetId: 0n,
        publicAmountOut: 0n,
        relayerFeeAmount: 0n,
        ctxHash,
        omitNf1: false,
        inputs: [
          {
            isDummy: false,
            spendSk: keys.spendSk,
            tweak: activeNote.tweak,
            assetId: activeNote.assetId,
            amount: activeNote.amountLamports,
            blinding: activeNote.blinding,
            merklePath: activeNote.path,
          },
          dummyInputWitness(keys.spendSk, activeNote.assetId, randomFr()),
        ],
        outputs: [
          {
            stealthOwner: recOwner,
            assetId: activeNote.assetId,
            amount: sendAmt,
            blinding: m0.blinding,
          },
          {
            stealthOwner: chOwner,
            assetId: activeNote.assetId,
            amount: changeAmt,
            blinding: m1.blinding,
          },
          {
            stealthOwner: dummyOwner,
            assetId: activeNote.assetId,
            amount: 0n,
            blinding: m2.blinding,
          },
        ],
      })
      if (sandboxEpochRef.current !== startEpoch) return

      let transactDevnetSig: string | undefined
      let wireBytes: number | undefined
      if (broadcastLiveTransact) {
        if (
          !relayerPayer ||
          activeNote.rootRingKind === undefined ||
          activeNote.rootRingIdx === undefined
        ) {
          throw new Error('Live Devnet GlobalRootHistory snapshot or relayer address is missing')
        }
        const ix = buildTransactInstruction({
          poolId: 0,
          vkId: VK_ID_DEFAULT,
          rootRingKind: activeNote.rootRingKind,
          rootRingIdx: activeNote.rootRingIdx,
          outLaneId,
          outSubSeq,
          outRootSeq,
          outMemoSeq,
          outNfSeq,
          rollover,
          payer: relayerPayer,
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
        const subRes = await fetch('/api/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'devnet',
            instructionDataB64: toBase64(ix.data),
            accounts: ix.accounts,
            computeUnitLimit: recommendedTransactCuLimit({
              assetMode: ASSET_MODE_PRIVATE,
              outputMask: 0b111,
            }),
          }),
        })
        const subJson = (await subRes.json()) as {
          signature?: string
          wireBytes?: number
          error?: string
        }
        if (sandboxEpochRef.current !== startEpoch) return
        if (!subRes.ok || !subJson.signature) {
          throw new Error(subJson.error ?? `Devnet relay submit HTTP ${subRes.status}`)
        }
        transactDevnetSig = subJson.signature
        wireBytes = subJson.wireBytes
      }

      if (sandboxEpochRef.current !== startEpoch) return
      setProofArtifact({
        elapsedMs,
        proofHex: toHex(result.proof192),
        proofBytes: result.proof192.byteLength,
        nf0Hex: toHex(result.nf0),
        cm0Hex: toHex(result.cm0),
        cm1Hex: toHex(result.cm1),
        ctxHashHex: toHex(frToBeBytes(ctxHash)),
        recipientAmountLamports: sendAmt,
        changeAmountLamports: changeAmt,
        transactDevnetSig,
        wireBytes,
      })
    } catch (err) {
      if (sandboxEpochRef.current === startEpoch) {
        setErrorMsg(err instanceof Error ? err.message : String(err))
      }
    } finally {
      if (sandboxEpochRef.current === startEpoch) {
        setProving(false)
      }
    }
  }

  const handleCheckSelectiveDisclosure = async (tamper: boolean) => {
    if (!sandboxNote || fundingDevnet || proving || verifyingReceipt) return
    const startEpoch = sandboxEpochRef.current
    setReceiptTampered(tamper)
    setVerifyingReceipt(true)
    setReceiptValid(null)
    setReceiptSourceNote(null)
    try {
      const sdp: SelectiveDisclosureProof = {
        poolId: 0,
        laneId: sandboxNote.laneId,
        leafIndex: sandboxNote.leafIndex,
        stealthOwner: frToBeBytes(sandboxNote.stealthOwner),
        mint: WSOL_MINT_BYTES,
        amount: tamper ? sandboxNote.amountLamports + 1n : sandboxNote.amountLamports,
        blinding: frToBeBytes(sandboxNote.blinding),
        commitment: frToBeBytes(sandboxNote.commitment),
      }
      if (sandboxNote.isLiveDevnet) {
        const subSeq = sandboxNote.leafIndex / BigInt(SUBTREE_LEAVES)
        const offset = Number(sandboxNote.leafIndex % BigInt(SUBTREE_LEAVES))
        const pda = deriveSubtreePdaSync(0, sandboxNote.laneId, subSeq, AUDREN_PROGRAM_ID).address
        const rpcRes = await fetch('/api/rpc/accounts', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ cluster: 'devnet', addresses: [pda] }),
        })
        if (sandboxEpochRef.current !== startEpoch) return
        const rpcJson = (await rpcRes.json().catch(() => ({}))) as {
          accounts?: Array<string | null>
          owners?: Array<string | null>
          error?: string
        }
        if (sandboxEpochRef.current !== startEpoch) return
        if (!rpcRes.ok || !rpcJson.accounts) {
          throw new Error(rpcJson.error ?? `RPC SubtreePage fetch HTTP ${rpcRes.status}`)
        }
        const rawB64 = rpcJson.accounts[0]
        const owner = rpcJson.owners?.[0] ?? null
        if (!rawB64) {
          setReceiptValid(false)
          setReceiptSourceNote(`On-chain SubtreePage ${shortHash(pda, 6, 4)} not found on Devnet`)
          return
        }
        if (owner !== AUDREN_PROGRAM_ID) {
          setReceiptValid(false)
          setReceiptSourceNote(
            `Account owner mismatch on ${shortHash(pda, 6, 4)}: expected Audren program ${shortHash(AUDREN_PROGRAM_ID, 6, 4)}`,
          )
          return
        }
        const page = decodeSubtreePage(fromBase64(rawB64))
        if (page.poolId !== 0 || page.laneId !== sandboxNote.laneId || page.pageSeq !== subSeq) {
          setReceiptValid(false)
          setReceiptSourceNote(
            `SubtreePage header mismatch on ${shortHash(pda, 6, 4)} (got pool=${page.poolId}, lane=${page.laneId}, seq=${page.pageSeq.toString()})`,
          )
          return
        }
        const leaf = offset < page.count ? page.leaves[offset] : undefined
        if (!leaf) {
          setReceiptValid(false)
          setReceiptSourceNote(
            `Leaf #${sandboxNote.leafIndex.toString()} out of range on Devnet SubtreePage ${shortHash(pda, 6, 4)}`,
          )
          return
        }
        setReceiptValid(verifySelectiveDisclosureProof(sdp, leaf))
        setReceiptSourceNote(`Verified against live Devnet SubtreePage ${shortHash(pda, 6, 4)}`)
      } else {
        setReceiptValid(verifySelectiveDisclosureProof(sdp, frToBeBytes(sandboxNote.commitment)))
        setReceiptSourceNote('Verified against local offline SubtreePage leaf')
      }
    } catch (err) {
      if (sandboxEpochRef.current === startEpoch) {
        setReceiptValid(false)
        setReceiptSourceNote(err instanceof Error ? err.message : String(err))
      }
    } finally {
      if (sandboxEpochRef.current === startEpoch) {
        setVerifyingReceipt(false)
      }
    }
  }

  return (
    <div className="page-shell demo-page">
      <SiteHeader current="demo" />

      <main className="container">
        <div className="demo-topbar">
          <Link href="/" className="lv-inline-link">
            <ArrowLeft size={13} /> audren.xyz
          </Link>
          <div className="demo-meta-tags mono">
            <span>Audren {AUDREN.deployedReleaseTag}</span>
            <span>BN254 Groth16 · 192 B proof</span>
            <span>4-ary Depth-20 MASP</span>
          </div>
        </div>

        <header className="demo-header">
          <h1>Audren Wallet &amp; Sandbox</h1>
          <p>
            Connect a Solana wallet on Devnet or Mainnet, or run the zero-wallet Sandbox right in your
            browser to encrypt a 72-byte memo (a 106 B on-chain entry), generate a real 192-byte
            BN254 Groth16 proof in a dedicated Web Worker, broadcast live on Devnet, and verify a Mode 1
            selective disclosure receipt.
          </p>

          <div className="lv-cluster-switch" role="tablist" aria-label="App mode" style={{ marginTop: '1.25rem' }}>
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'wallet'}
              className={`lv-cluster-btn ${mode === 'wallet' ? 'is-active' : ''}`}
              onClick={() => selectMode('wallet')}
            >
              <Wallet size={14} /> Connect wallet (Mainnet / Devnet)
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'sandbox'}
              className={`lv-cluster-btn ${mode === 'sandbox' ? 'is-active' : ''}`}
              onClick={() => selectMode('sandbox')}
            >
              <Cpu size={14} /> No-wallet WASM sandbox
            </button>
          </div>
        </header>

        {mode === 'wallet' ? (
          <LiveWalletVault />
        ) : (
          <div className="lv-shell">
            <div className="lv-topbar">
              <div className="lv-wallet-bar">
                <span className="lv-wallet-pill mono">
                  <Lock size={12} /> Web Worker · <code>/wasm/audren_circuits.wasm</code>
                </span>
                <span className="lv-wallet-pill mono">
                  17,861 R1CS · 2^15 FFT · No indexer
                </span>
              </div>
              <div className="lv-wallet-bar">
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
                  disabled={fundingDevnet || proving || verifyingReceipt}
                  onClick={() => {
                    if (fundingDevnet || proving || verifyingReceipt) return
                    initSandboxKeys()
                  }}
                >
                  <RefreshCw size={12} /> New ephemeral keys
                </button>
              </div>
            </div>

            {devnetRootHistoryMigrating && (
              <div className="lv-notice-bar is-warn" role="status">
                <AlertCircle size={15} />
                <span style={{ flex: 1 }}>
                  Devnet Pool #0 GlobalRootHistory migration is in progress; live Devnet deposits and
                  relayed spends are temporarily paused while offline WASM sandbox proving remains
                  available.
                </span>
              </div>
            )}

            {errorMsg && (
              <div className="lv-error-bar">
                <AlertCircle size={14} />
                <span>{errorMsg}</span>
              </div>
            )}

            <div className="lv-workspace">
              <section className={`lv-card lv-private-card ${strangerView ? 'is-stranger' : ''}`}>
                <div className="lv-card-head">
                  <span className="lv-ledger-kicker is-ok">
                    {strangerView ? 'On-chain observer view' : 'Step 1 · Ephemeral identity'}
                  </span>
                </div>

                {keys && (
                  <div className="lv-simple-body">
                    <div className="lv-addr-row">
                      <span className="mono">aud1… Bech32m address</span>
                      <code className="mono">{shortHash(keys.address, 14, 10)}</code>
                      <button
                        type="button"
                        className="lv-copy-chip"
                        onClick={() => {
                          navigator.clipboard?.writeText(keys.address).catch(() => {})
                          setCopied(true)
                          setTimeout(() => setCopied(false), 1500)
                        }}
                      >
                        {copied ? <Check size={12} /> : <Copy size={12} />}
                        {copied ? 'Copied' : 'Copy'}
                      </button>
                    </div>

                    <div className="lv-balance-list">
                      <div className="lv-balance-row">
                        <div>
                          <span className="lv-row-title">Spend public key (BN254 Fr)</span>
                          <span className="mono">Poseidon2(DOMAIN_PK, spend_sk)</span>
                        </div>
                        <span className="mono">{shortHash(toHex(keys.spendPkBytes), 10, 8)}</span>
                      </div>
                      <div className="lv-balance-row">
                        <div>
                          <span className="lv-row-title">View public key (X25519)</span>
                          <span className="mono">72 B versioned AEAD memo · 106 B SoA entry</span>
                        </div>
                        <span className="mono">{shortHash(toHex(keys.viewPk), 10, 8)}</span>
                      </div>
                    </div>

                    {sandboxNote && (
                      <div className="sb-mini-proof is-dark-proof">
                        <div className="sb-mini-proof-top">
                          <span className="mono">
                            {sandboxNote.isLiveDevnet ? 'Live Devnet note' : 'Local note'} (lane #{sandboxNote.laneId} · leaf #{sandboxNote.leafIndex.toString()})
                          </span>
                          <span className="sb-confirmed-pill mono">Poseidon verified</span>
                        </div>
                        {strangerView ? (
                          <p className="mono">
                            View tag: 0x{toHex(sandboxNote.memo.subarray(0, 2))} · Memo (106 B):{' '}
                            {shortHash(toHex(sandboxNote.memo), 18, 12)} · Commitment:{' '}
                            {shortHash(toHex(frToBeBytes(sandboxNote.commitment)), 12, 8)}
                          </p>
                        ) : (
                          <p>
                            Decrypted locally with X25519 <code>view_sk</code>:{' '}
                            <span className="lv-strong">{(Number(sandboxNote.amountLamports) / 1e9).toFixed(4)} SOL</span>
                            {sandboxNote.superRoot !== null && (
                              <>
                                {' '}
                                · SuperRoot:{' '}
                                <code className="mono">
                                  {shortHash(toHex(frToBeBytes(sandboxNote.superRoot)), 12, 8)}
                                </code>
                              </>
                            )}
                          </p>
                        )}
                        {sandboxNote.devnetSig && (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'center' }}>
                            <a
                              href={solscanTx(sandboxNote.devnetSig, 'devnet')}
                              target="_blank"
                              rel="noreferrer"
                              className="lv-ledger-ext mono"
                            >
                              Devnet Deposit {shortHash(sandboxNote.devnetSig, 8, 6)} <ArrowUpRight size={12} />
                            </a>
                            {sandboxNote.rootCommitment && (
                              <span className="mono" style={{ fontSize: '0.75rem', opacity: 0.78 }}>
                                GlobalRootHistory ({sandboxNote.rootCommitment}) · instant spend
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </section>

              <section className="lv-card lv-simple-action">
                <div className="lv-simple-body">
                  <div className="lv-field-block">
                    <span className="lv-label">Step 2 · Shield note into global 4-ary tree</span>
                    <div className="lv-quick-pills">
                      {PRESET_AMOUNTS.map((p) => (
                        <button
                          key={p.label}
                          type="button"
                          className={`lv-quick-pill mono ${selectedAmount === p.lamports ? 'is-active' : ''}`}
                          onClick={() => setSelectedAmount(p.lamports)}
                        >
                          {p.label}
                        </button>
                      ))}
                    </div>
                    <div className="lv-unlock-actions" style={{ marginTop: '0.75rem' }}>
                      <button
                        type="button"
                        className="btn-primary lv-submit-btn"
                        disabled={!keys || fundingDevnet || proving || verifyingReceipt}
                        onClick={() => handleShieldSandboxNote(false)}
                      >
                        <KeyRound size={15} /> Shield note locally (offline WASM)
                      </button>
                      {devnetRelayerAvailable && (
                        <button
                          type="button"
                          className="btn-secondary lv-submit-btn"
                          disabled={
                            !keys ||
                            fundingDevnet ||
                            proving ||
                            verifyingReceipt ||
                            devnetRootHistoryMigrating
                          }
                          onClick={() => handleShieldSandboxNote(true)}
                        >
                          {fundingDevnet ? <Loader2 size={15} className="spin" /> : <ArrowUpRight size={15} />}
                          Broadcast live Devnet Deposit
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="lv-field-block">
                    <span className="lv-label">Step 3 · Prove 192 B BN254 Groth16 in Web Worker</span>
                    <div className="lv-unlock-actions">
                      <button
                        type="button"
                        className="btn-primary lv-submit-btn"
                        disabled={!sandboxNote || !sandboxNote.path || fundingDevnet || proving || verifyingReceipt}
                        onClick={() => handleRunBrowserWasmProof(false)}
                      >
                        {proving ? <Loader2 size={15} className="spin" /> : <Cpu size={15} />}
                        {proving
                          ? 'Proving 17,861 R1CS in Web Worker…'
                          : 'Prove 192 B Groth16 Transact locally'}
                      </button>
                      {sandboxNote?.isLiveDevnet && devnetRelayerAvailable && (
                        <button
                          type="button"
                          className="btn-secondary lv-submit-btn"
                          disabled={
                            !sandboxNote.path ||
                            fundingDevnet ||
                            proving ||
                            verifyingReceipt ||
                            devnetRootHistoryMigrating
                          }
                          onClick={() => handleRunBrowserWasmProof(true)}
                        >
                          {proving ? <Loader2 size={15} className="spin" /> : <ArrowUpRight size={15} />}
                          Prove &amp; broadcast live Devnet Transact
                        </button>
                      )}
                    </div>

                    {proofArtifact && (
                      <div className="lv-audit-card" style={{ marginTop: '0.85rem' }}>
                        <div className="lv-audit-head">
                          <h4>
                            {proofArtifact.transactDevnetSig
                              ? 'Live Devnet Transact (Tag 5) verified on-chain'
                              : '192-byte BN254 Groth16 proof generated in Web Worker'}
                          </h4>
                          <span className="sb-confirmed-pill mono">{proofArtifact.elapsedMs} ms</span>
                        </div>
                        {proofArtifact.transactDevnetSig && (
                          <p style={{ marginBottom: '0.6rem' }}>
                            <a
                              href={solscanTx(proofArtifact.transactDevnetSig, 'devnet')}
                              target="_blank"
                              rel="noreferrer"
                              className="lv-ledger-ext mono"
                            >
                              Solscan Devnet Transact {shortHash(proofArtifact.transactDevnetSig, 10, 8)}
                              {proofArtifact.wireBytes ? ` (${proofArtifact.wireBytes} B Tx v1)` : ''}{' '}
                              <ArrowUpRight size={12} />
                            </a>
                          </p>
                        )}
                        <div className="lv-balance-list">
                          <div className="lv-balance-row">
                            <div>
                              <span className="lv-row-title">Proof wire bytes (pi_a || pi_b || pi_c)</span>
                              <span className="mono">{proofArtifact.proofBytes} bytes · alt_bn128 pairing ready</span>
                            </div>
                            <code className="mono">{shortHash(proofArtifact.proofHex, 12, 10)}</code>
                          </div>
                          <div className="lv-balance-row">
                            <div>
                              <span className="lv-row-title">Nullifier nf0 (key-separated)</span>
                              <span className="mono">Poseidon4(DOMAIN_NULLIFIER, nk, cm, (lane &lt;&lt; 36) | leaf_idx)</span>
                            </div>
                            <code className="mono">{shortHash(proofArtifact.nf0Hex, 10, 8)}</code>
                          </div>
                          <div className="lv-balance-row">
                            <div>
                              <span className="lv-row-title">Output commitments (cm0 / cm1 shown, cm2 padded)</span>
                              <span className="mono">
                                {(Number(proofArtifact.recipientAmountLamports) / 1e9).toFixed(4)} +{' '}
                                {(Number(proofArtifact.changeAmountLamports) / 1e9).toFixed(4)} SOL (hidden on-chain)
                              </span>
                            </div>
                            <code className="mono">{shortHash(proofArtifact.cm0Hex, 10, 8)}</code>
                          </div>
                          <div className="lv-balance-row">
                            <div>
                              <span className="lv-row-title">Bound Fiat-Shamir ctx_hash</span>
                              <span className="mono">SHA-256 masked to 253-bit Fr (binds vk_id=0)</span>
                            </div>
                            <code className="mono">{shortHash(proofArtifact.ctxHashHex, 10, 8)}</code>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="lv-field-block">
                    <span className="lv-label">Step 4 · Mode 1 selective disclosure receipt check</span>
                    <div className="lv-receipt-actions">
                      <button
                        type="button"
                        className="lv-mini-btn"
                        disabled={!sandboxNote || fundingDevnet || proving || verifyingReceipt}
                        onClick={() => void handleCheckSelectiveDisclosure(false)}
                      >
                        {verifyingReceipt ? <Loader2 size={13} className="spin" /> : <ShieldCheck size={13} />}
                        Verify genuine note receipt
                      </button>
                      <button
                        type="button"
                        className="lv-mini-btn"
                        disabled={!sandboxNote || fundingDevnet || proving || verifyingReceipt}
                        onClick={() => void handleCheckSelectiveDisclosure(true)}
                      >
                        <ShieldAlert size={13} /> Tamper amount (+1 lamport)
                      </button>
                    </div>
                    {receiptValid !== null && (
                      <div
                        className={`lv-receipt-verdict ${receiptValid ? 'is-valid' : 'is-forged'}`}
                        style={{ marginTop: '0.6rem' }}
                      >
                        {receiptValid
                          ? `Valid · Poseidon5 commitment matches leaf (${receiptSourceNote ?? 'verified'})`
                          : receiptTampered
                            ? `Rejected · 1-lamport tamper broke Poseidon commitment binding (${receiptSourceNote ?? 'mismatch'})`
                            : `Invalid · ${receiptSourceNote ?? 'Commitment mismatch'}`}
                      </div>
                    )}
                  </div>
                </div>
              </section>
            </div>

            <div className="lv-backup-meta mono">
              <span>Canonical program ID: </span>
              <a href={solscanAddress(AUDREN.programId, 'devnet')} target="_blank" rel="noreferrer">
                {AUDREN.programId}
              </a>
            </div>
          </div>
        )}
      </main>

      <SiteFooter current="demo" />
    </div>
  )
}
