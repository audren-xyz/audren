'use client'

import { useCallback, useEffect, useState } from 'react'
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
  NATIVE_SOL_MINT_BYTES,
  NUM_LANES,
  ZERO_HASHES_4ARY,
  buildWitnessFromFrozenSubsiblings,
  bytes32ToFrMasked,
  computeJoinsplitCtxHash,
  computeMerkleRoot4Ary,
  computeNoteCommitment,
  computeSubtree256Root,
  deriveAssetId,
  deriveKeysFromSeed,
  deriveStealthOwner,
  encryptNoteMemo,
  exportFullViewingKey,
  extractIntraSubtreeSiblings,
  frToBeBytes,
  toHex,
  tryDecryptAndVerifyMemo90,
  verifySelectiveDisclosureProof,
  type AudrenKeys,
  type MerklePath4Ary,
  type SelectiveDisclosureProof,
} from '@/lib/audren-crypto'
import {
  dummyInputWitness,
  dummyOutputWitness,
  proveJoinsplitInBrowser,
} from '@/lib/audren-prover'
import { AUDREN, shortHash, solscanAddress, solscanTx } from '@/lib/protocol'

type DemoMode = 'wallet' | 'sandbox'

interface SandboxNote {
  laneId: number
  leafIndex: bigint
  amountLamports: bigint
  tweak: bigint
  blinding: bigint
  stealthOwner: bigint
  assetId: bigint
  commitment: bigint
  memo90: Uint8Array
  path: MerklePath4Ary
  superRoot: bigint
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
}

const PRESET_AMOUNTS = [
  { label: '0.001 SOL', lamports: 1_000_000n },
  { label: '0.002 SOL', lamports: 2_000_000n },
  { label: '0.005 SOL', lamports: 5_000_000n },
] as const

function randomFr(): bigint {
  return bytes32ToFrMasked(crypto.getRandomValues(new Uint8Array(32)))
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
  const [proving, setProving] = useState(false)
  const [fundingDevnet, setFundingDevnet] = useState(false)
  const [devnetRelayerAvailable, setDevnetRelayerAvailable] = useState(false)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const initSandboxKeys = useCallback(() => {
    const seed = crypto.getRandomValues(new Uint8Array(32))
    const derived = deriveKeysFromSeed(seed)
    setKeys(derived)
    setSandboxNote(null)
    setProofArtifact(null)
    setReceiptValid(null)
    setReceiptTampered(false)
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
    fetch('/api/devnet/pool')
      .then((r) => (r.ok ? r.json() : null))
      .then((d: { relayerAvailable?: boolean } | null) => {
        setDevnetRelayerAvailable(Boolean(d?.relayerAvailable))
      })
      .catch(() => setDevnetRelayerAvailable(false))
  }, [mode])

  const handleShieldSandboxNote = async (broadcastDevnet: boolean) => {
    if (!keys) return
    setErrorMsg(null)
    setProofArtifact(null)
    setReceiptValid(null)
    setReceiptTampered(false)

    try {
      const mintBytes = NATIVE_SOL_MINT_BYTES
      const assetId = deriveAssetId(mintBytes)
      const { tweak, blinding, memo90 } = encryptNoteMemo(
        keys.viewPk,
        crypto.getRandomValues(new Uint8Array(32)),
        selectedAmount,
        mintBytes,
      )
      const stealthOwner = deriveStealthOwner(keys.spendPk, tweak)
      const commitment = computeNoteCommitment(stealthOwner, assetId, selectedAmount, blinding)

      const fvk = exportFullViewingKey(keys)
      const dec = tryDecryptAndVerifyMemo90(fvk, memo90, frToBeBytes(commitment))
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
      const ckptLaneRoots = Array.from({ length: NUM_LANES }, (_, i) =>
        i === laneId ? lane0Root : emptyLaneRoot,
      )
      const path = buildWitnessFromFrozenSubsiblings({
        laneId,
        targetLeafIdx: leafIndex,
        intraSiblings,
        intraPositions,
        ckptLaneRoots,
        ckptLaneLeafCount: 1n,
        finalizedSubtreeRoots: [],
        frontierPageLeaves: leaves,
      })
      const superRoot = computeMerkleRoot4Ary(path, commitment)

      let devnetSig: string | undefined
      if (broadcastDevnet) {
        setFundingDevnet(true)
        const res = await fetch('/api/devnet/deposit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            recipientAddress: keys.address,
            amountLamports: selectedAmount.toString(),
            poolId: 0,
          }),
        })
        const j = (await res.json()) as { signature?: string; error?: string }
        if (!res.ok || !j.signature) {
          throw new Error(j.error ?? `Devnet deposit HTTP ${res.status}`)
        }
        devnetSig = j.signature
      }

      setSandboxNote({
        laneId,
        leafIndex,
        amountLamports: selectedAmount,
        tweak,
        blinding,
        stealthOwner,
        assetId,
        commitment,
        memo90,
        path,
        superRoot,
        devnetSig,
      })
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setFundingDevnet(false)
    }
  }

  const handleRunBrowserWasmProof = async () => {
    if (!keys || !sandboxNote) return
    setProving(true)
    setErrorMsg(null)
    try {
      const sendAmt = sandboxNote.amountLamports / 2n
      const changeAmt = sandboxNote.amountLamports - sendAmt
      const recKeys = deriveKeysFromSeed(crypto.getRandomValues(new Uint8Array(32)))

      const mintBytes = NATIVE_SOL_MINT_BYTES
      const m0 = encryptNoteMemo(recKeys.viewPk, crypto.getRandomValues(new Uint8Array(32)), sendAmt, mintBytes)
      const recOwner = deriveStealthOwner(recKeys.spendPk, m0.tweak)
      const m1 = encryptNoteMemo(keys.viewPk, crypto.getRandomValues(new Uint8Array(32)), changeAmt, mintBytes)
      const chOwner = deriveStealthOwner(keys.spendPk, m1.tweak)

      const memosConcat = new Uint8Array(m0.memo90.byteLength + m1.memo90.byteLength)
      memosConcat.set(m0.memo90, 0)
      memosConcat.set(m1.memo90, m0.memo90.byteLength)

      const ctxHash = computeJoinsplitCtxHash({
        poolId: 0,
        outLaneId: 1,
        outputMask: 0b011,
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
        superRoot: sandboxNote.superRoot,
        txAssetId: sandboxNote.assetId,
        publicAssetId: 0n,
        publicAmountOut: 0n,
        relayerFeeAmount: 0n,
        ctxHash,
        omitNf1: true,
        inputs: [
          {
            isDummy: false,
            spendSk: keys.spendSk,
            tweak: sandboxNote.tweak,
            assetId: sandboxNote.assetId,
            amount: sandboxNote.amountLamports,
            blinding: sandboxNote.blinding,
            merklePath: sandboxNote.path,
          },
          dummyInputWitness(keys.spendSk, sandboxNote.assetId, randomFr()),
        ],
        outputs: [
          {
            stealthOwner: recOwner,
            assetId: sandboxNote.assetId,
            amount: sendAmt,
            blinding: m0.blinding,
          },
          {
            stealthOwner: chOwner,
            assetId: sandboxNote.assetId,
            amount: changeAmt,
            blinding: m1.blinding,
          },
          dummyOutputWitness(sandboxNote.assetId, randomFr()),
        ],
      })

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
      })
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setProving(false)
    }
  }

  const handleCheckSelectiveDisclosure = (tamper: boolean) => {
    if (!sandboxNote) return
    setReceiptTampered(tamper)
    const sdp: SelectiveDisclosureProof = {
      poolId: 0,
      laneId: sandboxNote.laneId,
      leafIndex: sandboxNote.leafIndex,
      stealthOwner: frToBeBytes(sandboxNote.stealthOwner),
      mint: NATIVE_SOL_MINT_BYTES,
      amount: tamper ? sandboxNote.amountLamports + 1n : sandboxNote.amountLamports,
      blinding: frToBeBytes(sandboxNote.blinding),
      commitment: frToBeBytes(sandboxNote.commitment),
    }
    setReceiptValid(verifySelectiveDisclosureProof(sdp, frToBeBytes(sandboxNote.commitment)))
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
            <span>AUDREN {AUDREN.releaseTag}</span>
            <span>BN254 GROTH16 · 192 B PROOF</span>
            <span>4-ARY DEPTH-20 MASP</span>
          </div>
        </div>

        <header className="demo-header">
          <h1>
            Audren <em>Wallet &amp; Sandbox</em>
          </h1>
          <p>
            Connect a Solana wallet on Devnet or Mainnet, or run the zero-wallet Sandbox right in your
            browser to encrypt a 90-byte SoA note, generate a real 192-byte BN254 Groth16 proof in WASM,
            and verify a Mode 1 selective disclosure receipt.
          </p>

          <div className="lv-cluster-switch" role="tablist" aria-label="App mode" style={{ marginTop: '1.25rem' }}>
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'wallet'}
              className={`lv-cluster-btn ${mode === 'wallet' ? 'is-active' : ''}`}
              onClick={() => selectMode('wallet')}
            >
              <Wallet size={14} /> Connect Wallet (Mainnet / Devnet)
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'sandbox'}
              className={`lv-cluster-btn ${mode === 'sandbox' ? 'is-active' : ''}`}
              onClick={() => selectMode('sandbox')}
            >
              <Cpu size={14} /> No-Wallet WASM Sandbox
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
                  <Lock size={12} /> 100% Client-Side · <code>/wasm/audren_circuits.wasm</code>
                </span>
                <span className="lv-wallet-pill mono">
                  17,861 R1CS · 2^15 FFT · 0 Indexers
                </span>
              </div>
              <div className="lv-wallet-bar">
                <button
                  type="button"
                  className={`lv-eyes-toggle ${strangerView ? 'is-active' : ''}`}
                  onClick={() => setStrangerView((v) => !v)}
                >
                  {strangerView ? <EyeOff size={13} /> : <Eye size={13} />}
                  {strangerView ? 'Stranger View' : 'Owner View'}
                </button>
                <button type="button" className="lv-mini-btn" onClick={initSandboxKeys}>
                  <RefreshCw size={12} /> New Ephemeral Keys
                </button>
              </div>
            </div>

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
                    {strangerView ? 'ON-CHAIN OBSERVER VIEW' : 'STEP 1 · EPHEMERAL IDENTITY'}
                  </span>
                </div>

                {keys && (
                  <div className="lv-simple-body">
                    <div className="lv-addr-row">
                      <span className="mono">aud1… Address</span>
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
                          <strong>Spend Public Key (BN254 Fr)</strong>
                          <span className="mono">Poseidon2(DOMAIN_SPEND_PK, spend_sk)</span>
                        </div>
                        <span className="mono">{shortHash(toHex(keys.spendPkBytes), 10, 8)}</span>
                      </div>
                      <div className="lv-balance-row">
                        <div>
                          <strong>View Public Key (X25519)</strong>
                          <span className="mono">90 B SoA ChaCha20-Poly1305 ECDH</span>
                        </div>
                        <span className="mono">{shortHash(toHex(keys.viewPk), 10, 8)}</span>
                      </div>
                    </div>

                    {sandboxNote && (
                      <div className="sb-mini-proof is-dark-proof">
                        <div className="sb-mini-proof-top">
                          <span className="mono">SHIELDED NOTE (LANE #{sandboxNote.laneId} · LEAF #0)</span>
                          <span className="sb-confirmed-pill mono">POSEIDON VERIFIED</span>
                        </div>
                        {strangerView ? (
                          <p className="mono">
                            View Tag: 0x{toHex(sandboxNote.memo90.subarray(0, 2))} · Memo (90 B):{' '}
                            {shortHash(toHex(sandboxNote.memo90), 18, 12)} · Commitment:{' '}
                            {shortHash(toHex(frToBeBytes(sandboxNote.commitment)), 12, 8)}
                          </p>
                        ) : (
                          <p>
                            Decrypted locally with X25519 <code>view_sk</code>:{' '}
                            <strong>{(Number(sandboxNote.amountLamports) / 1e9).toFixed(4)} SOL</strong> · SuperRoot:{' '}
                            <code className="mono">{shortHash(toHex(frToBeBytes(sandboxNote.superRoot)), 12, 8)}</code>
                          </p>
                        )}
                        {sandboxNote.devnetSig && (
                          <a
                            href={solscanTx(sandboxNote.devnetSig, 'devnet')}
                            target="_blank"
                            rel="noreferrer"
                            className="lv-ledger-ext mono"
                          >
                            Devnet Tx {shortHash(sandboxNote.devnetSig, 8, 6)} <ArrowUpRight size={12} />
                          </a>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </section>

              <section className="lv-card lv-simple-action">
                <div className="lv-simple-body">
                  <div className="lv-field-block">
                    <span className="lv-label">STEP 2 · SHIELD NOTE INTO GLOBAL 4-ARY TREE</span>
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
                        disabled={!keys || fundingDevnet}
                        onClick={() => handleShieldSandboxNote(false)}
                      >
                        <KeyRound size={15} /> Shield Note Locally (90 B Memo + Depth-20 Path)
                      </button>
                      {devnetRelayerAvailable && (
                        <button
                          type="button"
                          className="btn-secondary lv-submit-btn"
                          disabled={!keys || fundingDevnet}
                          onClick={() => handleShieldSandboxNote(true)}
                        >
                          {fundingDevnet ? <Loader2 size={15} className="spin" /> : <ArrowUpRight size={15} />}
                          Also Broadcast Live Devnet DepositSol
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="lv-field-block">
                    <span className="lv-label">STEP 3 · PROVE 192 B BN254 GROTH16 IN BROWSER WASM</span>
                    <button
                      type="button"
                      className="btn-primary lv-submit-btn"
                      disabled={!sandboxNote || proving}
                      onClick={handleRunBrowserWasmProof}
                    >
                      {proving ? <Loader2 size={15} className="spin" /> : <Cpu size={15} />}
                      {proving
                        ? 'Proving 17,861 R1CS in WASM…'
                        : 'Prove 192 B Groth16 JoinSplit in Browser WASM'}
                    </button>

                    {proofArtifact && (
                      <div className="lv-audit-card" style={{ marginTop: '0.85rem' }}>
                        <div className="lv-audit-head">
                          <h4>192-Byte BN254 Groth16 Proof Generated Locally</h4>
                          <span className="sb-confirmed-pill mono">{proofArtifact.elapsedMs} ms</span>
                        </div>
                        <div className="lv-balance-list">
                          <div className="lv-balance-row">
                            <div>
                              <strong>Proof Wire Bytes (pi_a || pi_b || pi_c)</strong>
                              <span className="mono">{proofArtifact.proofBytes} bytes · alt_bn128 pairing ready</span>
                            </div>
                            <code className="mono">{shortHash(proofArtifact.proofHex, 12, 10)}</code>
                          </div>
                          <div className="lv-balance-row">
                            <div>
                              <strong>Nullifier nf0 (Key-Separated)</strong>
                              <span className="mono">Poseidon4(DOMAIN_NULLIFIER, nk, leaf_idx, tweak)</span>
                            </div>
                            <code className="mono">{shortHash(proofArtifact.nf0Hex, 10, 8)}</code>
                          </div>
                          <div className="lv-balance-row">
                            <div>
                              <strong>Output Commitments (cm0 / cm1)</strong>
                              <span className="mono">
                                {(Number(proofArtifact.recipientAmountLamports) / 1e9).toFixed(4)} +{' '}
                                {(Number(proofArtifact.changeAmountLamports) / 1e9).toFixed(4)} SOL (hidden on-chain)
                              </span>
                            </div>
                            <code className="mono">{shortHash(proofArtifact.cm0Hex, 10, 8)}</code>
                          </div>
                          <div className="lv-balance-row">
                            <div>
                              <strong>Bound Fiat-Shamir ctx_hash</strong>
                              <span className="mono">SHA-256 masked to 253-bit Fr</span>
                            </div>
                            <code className="mono">{shortHash(proofArtifact.ctxHashHex, 10, 8)}</code>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="lv-field-block">
                    <span className="lv-label">STEP 4 · MODE 1 SELECTIVE DISCLOSURE RECEIPT CHECK</span>
                    <div className="lv-receipt-actions">
                      <button
                        type="button"
                        className="lv-mini-btn"
                        disabled={!sandboxNote}
                        onClick={() => handleCheckSelectiveDisclosure(false)}
                      >
                        <ShieldCheck size={13} /> Verify Genuine Note Receipt
                      </button>
                      <button
                        type="button"
                        className="lv-mini-btn"
                        disabled={!sandboxNote}
                        onClick={() => handleCheckSelectiveDisclosure(true)}
                      >
                        <ShieldAlert size={13} /> Tamper Amount (+1 lamport)
                      </button>
                    </div>
                    {receiptValid !== null && (
                      <div
                        className={`lv-receipt-verdict ${receiptValid ? 'is-valid' : 'is-forged'}`}
                        style={{ marginTop: '0.6rem' }}
                      >
                        {receiptValid
                          ? 'VALID · Poseidon5(DOMAIN_COMMITMENT, stealth_owner, asset_id, amount, blinding) matches on-chain leaf'
                          : receiptTampered
                            ? 'REJECTED · 1-lamport tamper broke the Poseidon commitment binding immediately'
                            : 'INVALID'}
                      </div>
                    )}
                  </div>
                </div>
              </section>
            </div>

            <div className="lv-backup-meta mono">
              <span>Canonical Program ID: </span>
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
