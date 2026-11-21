'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import {
  ArrowRight,
  ArrowUpRight,
  Check,
  Eye,
  EyeOff,
  KeyRound,
  Layers,
  Lock,
  Pause,
  Play,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Wallet,
} from 'lucide-react'
import { AUDREN, solscanAddress, solscanTx } from '@/lib/protocol'

type FlowId = 'public-to-private' | 'private-to-private' | 'private-swap' | 'prove-or-exit'

interface FlowStep {
  actor: string
  title: string
  shortLabel: string
  packetLabel: string
  detail: string
  cryptoTag: string
}

interface SolscanField {
  label: string
  visibility: 'hidden' | 'visible' | 'verified'
  badge: string
  value: string
}

interface FlowDefinition {
  id: FlowId
  tabTitle: string
  tabSub: string
  exampleHeadline: string
  exampleNote: string
  txHref: string
  txLabel: string
  demoHref: string
  demoLabel: string
  steps: [FlowStep, FlowStep, FlowStep, FlowStep]
  solscan: SolscanField[]
}

const FLOWS: FlowDefinition[] = [
  {
    id: 'public-to-private',
    tabTitle: 'Public → Private',
    tabSub: 'Anyone pays your aud1… in any token',
    exampleHeadline: 'Alice pays your aud1… address 500 USDC from a regular Phantom wallet',
    exampleNote:
      'Alice doesn’t need an Audren account or a zero-knowledge proof. Works for Native SOL, any Classic SPL token, or any transferable Token-2022 mint.',
    txHref: solscanTx(AUDREN.mainnet.depositTx, 'mainnet'),
    txLabel: 'Inspect real Mainnet Deposit',
    demoHref: '/demo',
    demoLabel: 'Try Go Private live',
    steps: [
      {
        actor: 'ALICE’S PUBLIC WALLET',
        title: 'Any Solana wallet, any token',
        shortLabel: 'Alice picks 500 USDC + pastes your aud1…',
        packetLabel: '500 USDC + aud1…',
        detail:
          'Alice enters your reusable aud1… private address (from your invoice, bio, or payroll form) and chooses 500 USDC, SOL, BONK, or any Token-2022 mint. Zero ZK proof generation is required — she signs a normal Solana deposit transaction.',
        cryptoTag: 'Tag 2 Deposit · 0 ZK proofs · 1 standard wallet signature',
      },
      {
        actor: 'ONE-TIME STEALTH BOX',
        title: 'Fresh address derived for this payment',
        shortLabel: 'P = S + H(r·V)·G (never reuses aud1…)',
        packetLabel: 'Stealth P + Encrypted Note',
        detail:
          'Alice’s wallet picks a random secret r, derives a one-time stealth public key P = S + H(r·V)·G from your aud1… keys, computes a 1-byte view tag, and encrypts the token, amount, and memo with AES-256-GCM. Audren instructions use the derived one-time key instead of the reusable address.',
        cryptoTag: 'ECDH shared = r·V · AES-256-GCM ciphertext · 1-byte view_tag',
      },
      {
        actor: 'SHARED AUDREN POOL #0',
        title: 'Tokens enter the unified vault',
        shortLabel: '500 USDC → Pool vault · Note → EpochPage',
        packetLabel: 'Locked in EpochPage (32 slots)',
        detail:
          'Solana transfers 500 USDC into Audren’s unified permissionless vault ATA (created automatically on first use for any mint) and appends the encrypted stealth note into the active 32-note EpochPage alongside everyone else’s notes.',
        cryptoTag: 'Unified Pool #0 · Permissionless mint support · 32-note EpochPage',
      },
      {
        actor: 'YOUR PRIVATE BALANCE',
        title: 'Detected & unlocked only by you',
        shortLabel: 'Your view key spots it · Only your spend key moves it',
        packetLabel: '+500 USDC Private',
        detail:
          'You don’t need to be online or receive a link. Next time you open Audren, your local view key scans the 1-byte view tags (skipping 255/256 stranger notes instantly), decrypts your 500 USDC, and only your spend key can move it.',
        cryptoTag: 'Client-side scan · View key reads · Spend key controls funds',
      },
    ],
    solscan: [
      {
        label: 'Sender (Alice)',
        visibility: 'visible',
        badge: 'VISIBLE AT ENTRY',
        value: '7mQ2…9xRa deposited 500 USDC into shared Pool #0',
      },
      {
        label: 'Recipient (You)',
        visibility: 'hidden',
        badge: 'HIDDEN',
        value: 'One-time stealth key P in place of the reusable recipient address',
      },
      {
        label: 'Link to other payments',
        visibility: 'hidden',
        badge: 'FRESH KEY',
        value: 'The one-time key does not directly identify the reusable recipient address',
      },
      {
        label: 'Later private transfers',
        visibility: 'hidden',
        badge: 'HIDDEN INPUT',
        value: 'The proof conceals its source note; timing and amount correlations can remain',
      },
    ],
  },
  {
    id: 'private-to-private',
    tabTitle: 'Private → Private',
    tabSub: 'Pay an aud1… with a separate fee payer',
    exampleHeadline: 'You send 500 USDC from your Private Balance to Bob’s aud1… address',
    exampleNote:
      'This relayed private-transfer example conceals the spent record, uses a fresh recipient key and blinds the token and amount. The relay fee payer and transaction metadata are public.',
    txHref: solscanTx(AUDREN.mainnet.transferTx, 'mainnet'),
    txLabel: 'Inspect Mainnet Private Send (0 user signers)',
    demoHref: '/demo',
    demoLabel: 'Try Private Send live',
    steps: [
      {
        actor: '1-OF-32 ANONYMITY RING',
        title: 'Prove ownership without revealing which note',
        shortLabel: 'Triptych ring proof over 32 notes',
        packetLabel: 'Triptych Ring Proof + J',
        detail:
          'Your browser fetches the 32-note EpochPage holding your private USDC note and builds a Triptych zero-knowledge proof locally: “I own one of these 32 notes, and its unique nullifier J has never been spent.”',
        cryptoTag: 'Tag 3 Transfer · Triptych 1-of-32 · Unique Nullifier J = x⁻¹·U',
      },
      {
        actor: 'HIDDEN ASSET & AMOUNT',
        title: 'Blind both the coin and the dollar value',
        shortLabel: 'Pedersen commitments + 64-bit Bulletproof',
        packetLabel: 'Blinded (A, V) + Bulletproof',
        detail:
          'Your browser hides the token mint inside a blinded asset tag A and hides the amounts (500 USDC to Bob + your private change) inside Pedersen commitments V. A 64-bit Bulletproof proves conservation of value and no negative amounts.',
        cryptoTag: 'Cross-Base Pedersen ΣV_in = ΣV_out · 64-bit Bulletproofs',
      },
      {
        actor: 'OPEN PRIVACY RELAYER',
        title: 'Relayer pays gas — your wallet never signs',
        shortLabel: '1 Solana v1 tx · 0 user wallet signatures',
        packetLabel: 'Relayed Solana v1 Tx',
        detail:
          'Your browser sends the finished proof to relay.audren.xyz (or your own self-hosted relay). The relayer pays Solana fees and submits 1 Solana v1 transaction. Your Phantom wallet never signs and never appears in the tx accounts (0 / 8).',
        cryptoTag: 'relay.audren.xyz · Solana Tx v1 (0x81) · userWalletPresent = false',
      },
      {
        actor: 'BOB’S PRIVATE BALANCE',
        title: 'Two opaque stealth boxes land on Solana',
        shortLabel: 'Bob gets 500 USDC · You keep hidden change',
        packetLabel: 'Bob +500 · Your Change',
        detail:
          'Solana verifies the math on-chain, records nullifier J to reject repeat spends, and appends two encrypted notes: Bob’s 500 USDC (locked to Bob’s aud1…) and your remaining private change (locked back to your aud1…).',
        cryptoTag: 'On-chain sBPFv3 verified · Blinded transfer outputs · Fresh recipient keys',
      },
    ],
    solscan: [
      {
        label: 'Sender wallet',
        visibility: 'hidden',
        badge: 'ABSENT (0 / 8)',
        value: 'Signed only by Relayer H2Jc…p3vY — your wallet is not on the tx',
      },
      {
        label: 'Recipient (Bob)',
        visibility: 'hidden',
        badge: 'HIDDEN',
        value: 'One-time stealth key P_bob — Bob’s aud1… & wallet never appear',
      },
      {
        label: 'Token & amount',
        visibility: 'hidden',
        badge: 'BLINDED',
        value: 'Blinded curve commitments (A, V) conceal the mint and amount on-chain',
      },
      {
        label: 'Link to past deposits',
        visibility: 'hidden',
        badge: '1-OF-32 RING',
        value: 'Proof conceals the spent record; effective privacy depends on plausible candidates',
      },
    ],
  },
  {
    id: 'private-swap',
    tabTitle: 'Shielded DeFi',
    tabSub: 'ExecViaEscrow: swap, lend, stake in 1 tx',
    exampleHeadline: 'Swap, lend, stake, or mint yield tokens from your Private Balance in 1 tx',
    exampleNote:
      'Tag 5 ExecViaEscrow is protocol-agnostic: DEX swaps (Jupiter, Titan, DFlow, Raydium, Orca) are just one example alongside lending supply (kTokens), yield vaults, liquid staking (JitoSOL, INF), perp LP (JLP), and RWA vaults. External DeFi mints, amounts, and output record remain public.',
    txHref: solscanTx(AUDREN.mainnet.swapTx, 'mainnet'),
    txLabel: 'Inspect Mainnet ExecViaEscrow Tx',
    demoHref: '/demo',
    demoLabel: 'Try Shielded DeFi live',
    steps: [
      {
        actor: 'PRIVATE NOTE PROOF',
        title: 'Spend full or partial note + native relayer fee',
        shortLabel: 'Prove input note · Optional shielded change',
        packetLabel: 'ExecViaEscrow Proof',
        detail:
          'Your browser proves ownership of your private note inside its ring, binds the target Solana program and min_amount_out in the Fiat-Shamir transcript, and optionally pays the relayer directly from the input or output token. Your public wallet stays completely off-chain.',
        cryptoTag: 'Tag 5 ExecViaEscrow · Native relayer_fee · Transcript-bound target CPI',
      },
      {
        actor: 'SHARED ESCROW SHARD',
        title: 'Program unlocks into isolated sharded PDA',
        shortLabel: 'Pool vault → Sharded swap_escrow (0..15)',
        packetLabel: 'Token A → Escrow PDA',
        detail:
          'Audren’s on-chain program verifies your proof, locks the nullifier, and moves the exact input amount into one of 16 shared escrow PDAs. Only the escrow PDA signs the external CPI — vault_auth and custody vaults are never exposed.',
        cryptoTag: 'Sharded swap_escrow PDA (0..15) · Strict custody isolation',
      },
      {
        actor: 'PROTOCOL-AGNOSTIC DEFI CPI',
        title: 'Execute any Token A → Token B Solana program',
        shortLabel: 'DEX · Lending Supply · LST · Yield Vault · RWA',
        packetLabel: 'DeFi Fill ≥ min_out',
        detail:
          'Inside the same transaction, Audren invokes the target Solana program via PDA CPI — a DEX aggregator swap, lending reserve supply minting kTokens, liquid staking into JitoSOL/INF, or yield-vault deposit. If net output is below min_amount_out, the entire transaction reverts cleanly.',
        cryptoTag: 'Any stateless Token A → Token B CPI · min_amount_out enforced',
      },
      {
        actor: 'AUTO-RESHIELDED ON-CHAIN',
        title: 'Exact output or yield receipt lands in your vault',
        shortLabel: 'On-chain delta committed to your stealth key',
        packetLabel: 'Private Token B Note',
        detail:
          'Audren measures the exact vault balance delta received, deducts any configured output relayer fee, sweeps every remaining atom into the unified vault, and commits the exact net receipt on-chain to your fresh stealth key P_out.',
        cryptoTag: 'Measured net delta · Token-2022 safe · Instant private Token B note',
      },
    ],
    solscan: [
      { label: 'Target DeFi call & amounts', visibility: 'visible', badge: 'PUBLIC', value: 'External program, input/output mints, amount_in and actual_out are visible' },
      {
        label: 'Your public wallet',
        visibility: 'hidden',
        badge: 'ABSENT',
        value: 'Relayer paid gas (reimbursed natively); shared escrow PDA signed the DeFi CPI',
      },
      {
        label: 'Public unshield step',
        visibility: 'hidden',
        badge: 'NONE · 1 TX',
        value: 'Escrow executes the DeFi call and sweeps Token B directly into a fresh pool note',
      },
      {
        label: 'Output amount integrity',
        visibility: 'verified',
        badge: 'ON-CHAIN EXACT',
        value: 'Program measures exact net vault delta & enforces min_amount_out',
      },
      {
        label: 'New token or yield receipt',
        visibility: 'hidden',
        badge: 'OWNERSHIP PRIVATE',
        value: 'Reshielded immediately to your fresh stealth key inside Pool #0',
      },
    ],
  },
  {
    id: 'prove-or-exit',
    tabTitle: 'Receipt / Exit & Sessions',
    tabSub: 'Selective disclosure, unwrap WSOL, or DeFi sessions',
    exampleHeadline: 'Prove 1 invoice, self-pay an exit, or fund a 0-SOL DeFi session wallet',
    exampleNote:
      'Export a single-note opening for compliance, exit with self-paying native fees and atomic WSOL → SOL unwrap, or fund a deterministic session wallet (B_0, B_1…) for stateful borrow/perp protocols and later sweep every remaining lamport back with zero dust.',
    txHref: solscanTx(AUDREN.mainnet.withdrawTx, 'mainnet'),
    txLabel: 'Inspect Mainnet Go Public Withdraw',
    demoHref: '/demo?mode=sandbox',
    demoLabel: 'Test Receipts & Exit Flows',
    steps: [
      {
        actor: 'LOCKED NOTE ON SOLANA',
        title: 'Cryptographic commitment on-chain',
        shortLabel: 'EpochPage records the note commitments',
        packetLabel: 'On-Chain (A, V)',
        detail:
          'A private Transfer stores binding Pedersen commitments for token and amount in an EpochPage. The current program has no instruction to edit confirmed note contents; the deployment remains upgradeable.',
        cryptoTag: 'Binding Pedersen Commitments · A = G_mint + a·H · V = v·A + r_v·H',
      },
      {
        actor: 'SINGLE-PAYMENT RECEIPT',
        title: 'Export proof for just one note',
        shortLabel: 'JSON opening for 1 payment only',
        packetLabel: 'Viewing Receipt JSON',
        detail:
          'Click Receipt on any single note to export its cryptographic opening (mint, exact amount, blinding factors a and r_v, page & slot). Other notes and spending keys are not included. This does not prove a real-world identity.',
        cryptoTag: 'Zero spend key shared · Scoped strictly to 1 note slot',
      },
      {
        actor: 'SELF-PAYING EXIT & UNWRAP',
        title: 'Native relayer fee + atomic WSOL → Native SOL',
        shortLabel: 'Tag 6 Withdraw · unwrap_wsol · Pause-immune full exit',
        packetLabel: 'Direct Native SOL',
        detail:
          'Withdraw SOL or any SPL token to any wallet or deterministic DeFi Session keypair B_i with zero prior gas: pay the relayer natively from the withdrawn note and unwrap WSOL straight into Native SOL in one instruction via an ephemeral unwrap PDA.',
        cryptoTag: 'Tag 6 Withdraw · Native relayer_fee · Atomic audren_unwrap PDA',
      },
      {
        actor: 'ZERO-DUST SESSION SWEEP',
        title: 'Return every lamport back to the pool',
        shortLabel: 'Tag 2 Deposit(fee_from_amount) → 0 lamports left',
        packetLabel: '0-Dust Reshield',
        detail:
          'After closing a stateful borrow or perp position on a session wallet B_i, sweep 100% of remaining SOL back into the pool with Deposit(fee_from_amount=true): the protocol deducts the rent contribution from the deposit itself, leaving 0 lamports behind. Remember that stateful DeFi positions opened by B_i remain public on Solana.',
        cryptoTag: 'Tag 2 Deposit · DEPOSIT_FLAG_FEE_FROM_AMOUNT · Clean 0-lamport sweep',
      },
    ],
    solscan: [
      {
        label: 'Rest of your balance',
        visibility: 'hidden',
        badge: 'HIDDEN',
        value: 'Receipt reveals strictly 1 chosen payment — nothing else',
      },
      {
        label: 'Self-paying exit & unwrap',
        visibility: 'verified',
        badge: '1 TX · 0-SOL BOOTSTRAP',
        value: 'Relayer reimbursed natively; WSOL unwraps atomically to Native SOL',
      },
      {
        label: 'Stateful DeFi session positions',
        visibility: 'visible',
        badge: 'PUBLIC ON DEFI PROTOCOL',
        value: 'Collateral, borrow & perp positions opened by session wallet Bᵢ remain public on-chain',
      },
      {
        label: 'Exit to any fresh wallet',
        visibility: 'verified',
        badge: 'PERMISSIONLESS',
        value: 'Full-note Withdraw (including unwrap_wsol) bypasses pool pause, with or without relay',
      },
    ],
  },
]

interface SoundnessItem {
  tag: string
  question: string
  verdict: string
  answer: string
  primitive: string
}

const SOUNDNESS_PILLARS: SoundnessItem[] = [
  {
    tag: 'DOUBLE-SPEND',
    question: 'Can anyone spend the same private note twice?',
    verdict: 'REJECTED BY NULLIFIER CHECKS',
    answer:
      'Every note derives exactly one deterministic nullifier J = x⁻¹·U from your private spend key. The first spend initializes a Solana PDA seeded by J. Any replay fails immediately at Solana’s runtime — without ever revealing which deposit was spent.',
    primitive: 'Deterministic Nullifier J = x⁻¹·U · Solana PDA Uniqueness',
  },
  {
    tag: 'CONSERVATION',
    question: 'Can anyone counterfeit tokens or use negative amounts?',
    verdict: 'CHECKED BY RANGE & BALANCE PROOFS',
    answer:
      'Solana checks two things on every private spend without seeing the coin or number: every output commitment is proven to lie in [0, 2⁶⁴−1] via Bulletproofs, and input commitments equal output commitments for the exact same hidden asset.',
    primitive: '64-Bit Bulletproofs · Cross-Base Pedersen ΣV_in = ΣV_out',
  },
  {
    tag: 'TRANSPARENCY',
    question: 'Is there a trusted setup ceremony or “toxic waste”?',
    verdict: 'ZERO TRUSTED SETUP',
    answer:
      'Audren uses transparent Ristretto255 group proofs with hash-to-curve generators. No trusted-setup ceremony or proving-key download is required. This does not replace an independent security audit.',
    primitive: 'Ristretto255 (Prime Order ℓ) · SHA-256 Fiat-Shamir (Native Syscalls)',
  },
  {
    tag: 'STEALTH KEYS',
    question: 'Can anyone link two payments sent to my aud1… address?',
    verdict: 'FRESH STEALTH KEYS',
    answer:
      'Audren instructions use a one-time key instead of your reusable aud1… address. Each sender multiplies your public view key by fresh randomness to create a unique one-time stealth key P = S + H(r·V)·G. The keys do not directly identify the reusable address, but amounts, timing, viewing access and other observations can still connect payments.',
    primitive: 'Ristretto255 ECDH Stealth · 1-Byte View Tag · AES-256-GCM',
  },
  {
    tag: 'CUSTODY',
    question: 'Can Audren, a relayer, or an auditor steal or freeze funds?',
    verdict: 'FULL-NOTE EXIT BYPASSES PAUSE',
    answer:
      'The current pool authority cannot spend private notes. Full-note withdrawals bypass its pause; partial withdrawals do not. Relayers cannot alter proof-bound outputs. Auditor keys are read-only. Token issuer controls and the mutable program upgrade authority remain separate risks; see /architecture.',
    primitive: 'Transcript-Bound Outputs · Full-Note Direct RPC Exit',
  },
  {
    tag: 'ATOMIC ESCROW',
    question: 'Can a shielded DeFi CPI hide slippage or trap funds in escrow?',
    verdict: 'ATOMIC 1-TX ESCROW · EXACT DELTA',
    answer:
      'During ExecViaEscrow (Tag 5), the Solana program binds target_program and min_amount_out inside the proof transcript, measures the vault’s exact pre- and post-CPI balance delta, reverts atomically if actual_out < min_amount_out, sweeps every remaining atom back into Pool #0, and commits the exact net receipt on-chain.',
    primitive: 'ExecViaEscrow (Tag 5) · Native Relayer Fee · On-Chain Delta Commitment',
  },
]

const STEP_DURATION_MS = 3200

export function HowAudrenWorksVisual() {
  const [activeFlowId, setActiveFlowId] = useState<FlowId>('public-to-private')
  const [activeStep, setActiveStep] = useState<number>(0)
  const [autoPlay, setAutoPlay] = useState<boolean>(true)
  const [copiedSample, setCopiedSample] = useState<boolean>(false)

  const flow = FLOWS.find((f) => f.id === activeFlowId) ?? FLOWS[0]
  const currentStep = flow.steps[activeStep] ?? flow.steps[0]

  useEffect(() => {
    if (!autoPlay) return
    const timer = window.setInterval(() => {
      setActiveStep((prev) => (prev + 1) % 4)
    }, STEP_DURATION_MS)
    return () => window.clearInterval(timer)
  }, [autoPlay, activeFlowId])

  const selectFlow = (id: FlowId) => {
    setActiveFlowId(id)
    setActiveStep(0)
  }

  const selectStep = (idx: number) => {
    setActiveStep(idx)
    setAutoPlay(false)
  }

  const stepPrev = () => {
    setAutoPlay(false)
    setActiveStep((prev) => (prev + 3) % 4)
  }

  const stepNext = () => {
    setAutoPlay(false)
    setActiveStep((prev) => (prev + 1) % 4)
  }

  const copySampleAddress = () => {
    const sample =
      'aud136et2wsvTXKWMrmEQDrG7nRTofxBdSw6ZkwzmUT9vARfpCkY8YR9ENm9QV9WoUW3Nb1tp3BGejPA8BG8PWCWrwFL'
    navigator.clipboard?.writeText(sample).catch(() => {})
    setCopiedSample(true)
    window.setTimeout(() => setCopiedSample(false), 1600)
  }

  const activeCenterPct = 12.5 + activeStep * 25
  const fillWidthPct = (activeStep / 3) * 75

  return (
    <>
      {/* ================================================================
          SECTION 1 — YOUR aud1… ADDRESS + ANIMATED FLOWS
         ================================================================ */}
      <section className="section" id="how-it-works" style={{ paddingTop: 52 }}>
        <div className="container">
          {/* PART A: YOUR REUSABLE PRIVATE ADDRESS ANATOMY */}
          <div className="aud-addr-card">
            <div className="aud-addr-head">
              <div className="aud-addr-title-wrap">
                <span className="aud-addr-eyebrow mono">
                  <KeyRound size={12} /> REUSABLE PRIVATE ADDRESS
                </span>
                <h3>Share one <code>aud1…</code> address. Receive through fresh one-time keys.</h3>
              </div>
              <span className="mono" style={{ fontSize: 11, color: '#55574e' }}>
                Derived locally · 64-byte public keys
              </span>
            </div>

            <div className="aud-addr-specimen">
              <div className="aud-addr-string mono" aria-label="Anatomy of an Audren private address">
                <span className="aud-seg is-prefix" title="Audren protocol prefix">
                  aud1
                </span>
                <span className="aud-seg is-spend" title="32-byte Ristretto255 Spend Public Key S">
                  36et2wsvTXKWMrmEQDrG7nRTofxBdSw6ZkwzmUT9vAR
                </span>
                <span className="aud-seg is-view" title="32-byte Ristretto255 View Public Key V">
                  fpCkY8YR9ENm9QV9WoUW3Nb1tp3BGejPA8BG8PWCWrwFL
                </span>
              </div>
              <button
                type="button"
                className="aud-addr-copy mono"
                onClick={copySampleAddress}
                aria-label="Copy example aud1 address format"
              >
                {copiedSample ? (
                  <>
                    <Check size={12} /> COPIED FORMAT
                  </>
                ) : (
                  'EXAMPLE FORMAT'
                )}
              </button>
            </div>

            <div className="aud-addr-legend">
              <div className="aud-legend-item">
                <span className="aud-legend-dot is-prefix" />
                <div>
                  <strong className="mono">aud1 · PROTOCOL TAG</strong>
                  <p>
                    Identifies a reusable Audren stealth address. Unlike a normal Solana pubkey,
                    it is not an ordinary Solana account address that an explorer can look up.
                  </p>
                </div>
              </div>
              <div className="aud-legend-item">
                <span className="aud-legend-dot is-spend" />
                <div>
                  <strong className="mono">S · SPEND PUBLIC KEY (32 B)</strong>
                  <p>
                    Senders combine <code>S</code> with fresh randomness to lock funds into a
                    one-time stealth box that only your private spend key can ever unlock.
                  </p>
                </div>
              </div>
              <div className="aud-legend-item">
                <span className="aud-legend-dot is-view" />
                <div>
                  <strong className="mono">V · VIEW PUBLIC KEY (32 B)</strong>
                  <p>
                    Lets senders encrypt the coin, amount, and memo strictly for you. Your browser
                    auto-discovers incoming payments using your local view key.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* PART B: ANIMATED INTERACTIVE FLOW THEATER */}
          <div
            className="flow-theater"
            aria-label="Animated step-by-step walkthrough of Audren privacy flows"
          >
            {/* 4 Flow Tabs */}
            <div className="flow-tabs" role="tablist" aria-label="Choose a payment or swap flow">
              {FLOWS.map((item) => {
                const isActive = item.id === flow.id
                return (
                  <button
                    key={item.id}
                    type="button"
                    role="tab"
                    aria-selected={isActive}
                    className={`flow-tab-btn ${isActive ? 'is-active' : ''}`}
                    onClick={() => selectFlow(item.id)}
                  >
                    <span className="flow-tab-title">{item.tabTitle}</span>
                    <span className="flow-tab-sub">{item.tabSub}</span>
                  </button>
                )
              })}
            </div>

            {/* Scenario Header + Playback Controls */}
            <div className="flow-bar">
              <div className="flow-bar-copy">
                <p className="flow-bar-headline">{flow.exampleHeadline}</p>
                <p className="flow-bar-note">{flow.exampleNote}</p>
              </div>
              <div className="flow-controls mono">
                <button
                  type="button"
                  className="flow-ctrl-btn"
                  onClick={() => setAutoPlay((p) => !p)}
                  aria-label={autoPlay ? 'Pause animation' : 'Auto-play animation'}
                >
                  {autoPlay ? (
                    <>
                      <Pause size={12} /> PAUSE
                    </>
                  ) : (
                    <>
                      <Play size={12} /> PLAY
                    </>
                  )}
                </button>
                <button
                  type="button"
                  className="flow-ctrl-btn"
                  onClick={stepPrev}
                  aria-label="Previous step"
                >
                  ←
                </button>
                <span className="flow-step-counter">
                  {activeStep + 1} / 4
                </span>
                <button
                  type="button"
                  className="flow-ctrl-btn"
                  onClick={stepNext}
                  aria-label="Next step"
                >
                  →
                </button>
                <button
                  type="button"
                  className="flow-ctrl-btn"
                  onClick={() => {
                    setActiveStep(0)
                    setAutoPlay(true)
                  }}
                  aria-label="Replay flow"
                  title="Replay flow"
                >
                  <RefreshCw size={12} />
                </button>
              </div>
            </div>

            {/* Visual Stage: Animated Packet Rail + 4 Clickable Nodes */}
            <div className="flow-stage">
              <div className="flow-rail-wrap" aria-hidden="true">
                <div className="flow-rail-track">
                  <div className="flow-rail-base" />
                  <div
                    className="flow-rail-fill"
                    style={{ width: `${fillWidthPct}%` }}
                  />
                  {[0, 1, 2, 3].map((dotIdx) => (
                    <span
                      key={dotIdx}
                      className={`flow-rail-dot ${dotIdx === activeStep ? 'is-current' : ''} ${dotIdx < activeStep ? 'is-done' : ''}`}
                      style={{ left: `${12.5 + dotIdx * 25}%` }}
                    />
                  ))}
                  <div
                    className={`flow-packet mono ${autoPlay ? 'is-pulsing' : ''}`}
                    style={{ left: `${activeCenterPct}%` }}
                  >
                    <Lock size={11} />
                    <span>{currentStep.packetLabel}</span>
                  </div>
                </div>
              </div>

              <div className="flow-nodes">
                {flow.steps.map((step, idx) => {
                  const isCurrent = idx === activeStep
                  const isDone = idx < activeStep
                  return (
                    <button
                      key={step.actor}
                      type="button"
                      className={`flow-node ${isCurrent ? 'is-current' : ''} ${isDone ? 'is-done' : ''}`}
                      onClick={() => selectStep(idx)}
                      aria-current={isCurrent ? 'step' : undefined}
                    >
                      <div className="flow-node-top mono">
                        <span className="flow-node-num" aria-hidden="true">
                          {isDone ? <Check size={11} /> : <span className="flow-node-pip" />}
                        </span>
                        <span className="flow-node-actor">{step.actor}</span>
                      </div>
                      <h4 className="flow-node-title">{step.title}</h4>
                      <p className="flow-node-short">{step.shortLabel}</p>
                    </button>
                  )
                })}
              </div>
            </div>

            {/* Synchronized Spotlight: What Happens Now vs. What Solscan Sees */}
            <div className="flow-compare-split">
              <div className="flow-detail-pane">
                <div className="flow-pane-head mono">
                  <span>
                    <Sparkles size={12} /> WHAT ACTUALLY HAPPENS
                  </span>
                  <span className="flow-pane-actor">{currentStep.actor}</span>
                </div>
                <h4 className="flow-detail-title">{currentStep.title}</h4>
                <p className="flow-detail-body">{currentStep.detail}</p>
                <div className="flow-crypto-strip mono">
                  <Layers size={12} />
                  <span>{currentStep.cryptoTag}</span>
                </div>
              </div>

              <div className="flow-solscan-pane">
                <div className="flow-pane-head mono">
                  <span>
                    <EyeOff size={12} /> WHAT A STRANGER SEES ON SOLSCAN
                  </span>
                  <span>PUBLIC LEDGER VIEW</span>
                </div>

                <div className="flow-solscan-rows">
                  {flow.solscan.map((row) => (
                    <div key={row.label} className={`flow-solscan-row is-${row.visibility}`}>
                      <div className="flow-solscan-meta">
                        <span className="flow-solscan-label">{row.label}</span>
                        <span className={`flow-vis-badge mono is-${row.visibility}`}>
                          {row.visibility === 'hidden' && <EyeOff size={10} />}
                          {row.visibility === 'visible' && <Eye size={10} />}
                          {row.visibility === 'verified' && <ShieldCheck size={10} />}
                          {row.badge}
                        </span>
                      </div>
                      <p className="flow-solscan-val">{row.value}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Theater Footer */}
            <div className="flow-theater-footer mono">
              <a href={flow.txHref} target="_blank" rel="noreferrer" className="slip-link">
                {flow.txLabel} <ArrowUpRight size={13} />
              </a>
              <Link href={flow.demoHref} className="slip-link is-strong">
                <Wallet size={12} /> {flow.demoLabel} <ArrowRight size={12} />
              </Link>
            </div>
          </div>

          {/* Full-Width Carbon Ink Demo Band */}
          <div className="ink-callout">
            <div className="ink-callout-copy">
              <h3>Run these flows yourself on Mainnet or Devnet.</h3>
              <p>
                Connect Phantom, Solflare, or Backpack to deposit, send to any <code>aud1…</code>{' '}
                address, and swap through compatible DEX aggregators — or run the free Devnet
                sandbox without installing a wallet.
              </p>
            </div>
            <div className="ink-callout-actions">
              <Link href="/demo" className="btn-paper">
                Open the live app <ArrowRight size={15} />
              </Link>
              <a
                href={solscanAddress(AUDREN.programId, 'mainnet')}
                target="_blank"
                rel="noreferrer"
                className="btn-rule-light"
              >
                Inspect Mainnet Program <ArrowUpRight size={14} />
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* ================================================================
          SECTION 2 — CRYPTOGRAPHIC SOUNDNESS & ON-CHAIN CHECKS
         ================================================================ */}
      <section className="section section-ruled" id="security">
        <div className="container">
          <div className="section-head-split">
            <div>
              <h2>What the program checks before a spend.</h2>
            </div>
            <p className="section-sub">
              The program verifies ownership, value conservation, range proofs and nullifier
              uniqueness on-chain. These checks do not prove resistance to metadata analysis or
              establish an independent solvency audit. Audren is pre-audit and upgradeable.
            </p>
          </div>

          <div className="soundness-grid">
            {SOUNDNESS_PILLARS.map((item) => (
              <article key={item.tag} className="soundness-cell">
                <div className="soundness-top mono">
                  <span className="soundness-num">{item.tag}</span>
                  <span className="soundness-verdict">
                    <ShieldCheck size={11} /> {item.verdict}
                  </span>
                </div>
                <h3>{item.question}</h3>
                <p>{item.answer}</p>
                <div className="soundness-primitive mono">{item.primitive}</div>
              </article>
            ))}
          </div>

          <div className="soundness-footnote">
            <p className="mono">
              PRE-AUDIT · UPGRADEABLE DEPLOYMENT · PROGRAM <code>{AUDREN.programId}</code> ·
              APACHE-2.0
            </p>
            <Link href="/architecture" className="text-link">
              Read Full Cryptographic Proof &amp; Wire Spec <ArrowRight size={14} />
            </Link>
          </div>
        </div>
      </section>
    </>
  )
}
