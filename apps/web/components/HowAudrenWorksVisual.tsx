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
          'Alice enters your reusable aud1… private address and chooses 500 USDC, SOL, BONK, or any transferable Token-2022 mint. Zero ZK proof generation is required — she signs a standard DepositSol (Tag 3) or DepositSpl (Tag 4) transaction.',
        cryptoTag: 'Tag 3 / Tag 4 Deposit · 0 ZK proofs · 1 standard wallet signature',
      },
      {
        actor: 'ONE-TIME STEALTH BOX',
        title: 'Fresh Poseidon stealth owner + 90 B memo',
        shortLabel: 'stealth = Poseidon3(2, spend_pk, tweak)',
        packetLabel: 'Note cm + 90 B Memo',
        detail:
          'Alice’s wallet performs X25519 ECDH with your view public key, derives a deterministic tweak and blinding scalar, computes stealth_owner = Poseidon3(DOMAIN_STEALTH, spend_pk, tweak), and encrypts (amount, mint) into a 90-byte ChaCha20-Poly1305 memo with a 2-byte view tag.',
        cryptoTag: 'X25519 ECDH · 2-byte view_tag · ChaCha20-Poly1305 (90 B SoA)',
      },
      {
        actor: 'GLOBAL 4-ARY MASP POOL #0',
        title: 'Tokens enter the unified vault; leaf appends to lane',
        shortLabel: '500 USDC → Unified vault · cm → SubtreePage',
        packetLabel: '4^20 Global Tree (16 lanes)',
        detail:
          'Solana transfers 500 USDC into Audren’s unified vault ATA, computes cm = Poseidon5(DOMAIN_NOTE, stealth_owner, asset_id, net_received, blinding) on-chain, updates the active lane’s 4-ary Depth-18 frontier, and writes the 90 B memo to MemoPage.',
        cryptoTag: 'Unified Pool #0 · Net-delta Token-2022 solvency · 4→8→16 lanes',
      },
      {
        actor: 'YOUR PRIVATE BALANCE',
        title: 'Discovered via ordinary RPC — zero indexer',
        shortLabel: 'CompactWalletStore scans MemoPages & freezes siblings',
        packetLabel: '+500 USDC Private',
        detail:
          'Your device scans MemoPage PDAs using ordinary Solana RPC getMultipleAccounts, checks the 2-byte view tag (skipping 65,535/65,536 stranger memos instantly), verifies every decrypted note against SubtreePage to block forged memos, freezes 12 intra-subtree siblings on sealed pages, and discards raw pages permanently.',
        cryptoTag: 'Ordinary Solana RPC · Zero indexer · 1.28 MB store @ 10M notes',
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
        actor: 'GLOBAL 4^20 MERKLE PROOF',
        title: 'Prove ownership across the entire pool history',
        shortLabel: 'BN254 Groth16 over 20-level 4-ary super_root',
        packetLabel: '192 B Groth16 Proof',
        detail:
          'Your browser builds a 192-byte BN254 Groth16 proof (17,861 R1CS) locally in WASM against a recent RootCheckpoint: “I own 1 or 2 unspent notes anywhere in the global 4^20 Multi-Asset Shielded Pool, and their key-separated nullifiers have never been spent.”',
        cryptoTag: 'Tag 6 JoinSplit · 17,861 R1CS · Key-separated nk nullifiers',
      },
      {
        actor: 'HIDDEN ASSET & AMOUNT',
        title: 'Conservation & 64-bit range checks inside R1CS',
        shortLabel: 'Poseidon5 note commitments + 64-bit bit-decomposition',
        packetLabel: 'cm0, cm1, cm2 (Hidden)',
        detail:
          'The circuit enforces uniform hidden asset_id across all inputs and outputs, exact value conservation (Σin = Σout + public_out + relayer_fee), and 64-bit unsigned range checks on every output — hiding token mint and amounts completely on-chain.',
        cryptoTag: 'Poseidon5(3, stealth, asset_id, amt, r) · 1 public_input_hash',
      },
      {
        actor: 'OPEN PRIVACY RELAYER',
        title: 'Relayer pays gas — your wallet never signs',
        shortLabel: '1 Solana v1 tx · Optional shielded cm2 fee note',
        packetLabel: 'Relayed Solana v1 Tx',
        detail:
          'Your browser sends the finished proof to relay.audren.xyz (or your own self-hosted relay). For private transfers, the optional relayer fee can settle as shielded output cm2 verified via the relayer’s read-only FullViewingKey. Your public wallet never signs.',
        cryptoTag: 'Solana Tx v1 (0x81) · ~130k–160k CU · Zero user wallet signers',
      },
      {
        actor: 'BOB’S PRIVATE BALANCE',
        title: 'Opaque commitments & 90 B memos land on Solana',
        shortLabel: 'Bob gets 500 USDC · You keep hidden change',
        packetLabel: 'Bob +500 · Your Change',
        detail:
          'Solana verifies the 192 B Groth16 proof via native alt_bn128 pairing syscalls, locks NullifierPDA(s) and appends 16 B prefixes to NullifierPage, and writes the new commitments and 90 B SoA memos to your chosen append lane.',
        cryptoTag: 'alt_bn128 syscall verified · 16 B NullifierPage sync',
      },
    ],
    solscan: [
      {
        label: 'Sender wallet',
        visibility: 'hidden',
        badge: 'ABSENT (0 SIGNERS)',
        value: 'Signed only by Relayer — your wallet never appears on the transaction',
      },
      {
        label: 'Recipient (Bob)',
        visibility: 'hidden',
        badge: 'HIDDEN',
        value: 'One-time Poseidon stealth owner — Bob’s aud1… & wallet never appear',
      },
      {
        label: 'Token & amount',
        visibility: 'hidden',
        badge: 'HIDDEN IN POSEIDON5',
        value: 'All asset IDs and amounts remain hidden inside opaque 32 B commitments',
      },
      {
        label: 'Link to past deposits',
        visibility: 'hidden',
        badge: 'GLOBAL 4^20 MASP',
        value: 'Proof spans the entire historical pool; timing & outside metadata still matter',
      },
    ],
  },
  {
    id: 'private-swap',
    tabTitle: 'Shielded DeFi',
    tabSub: 'ExecViaEscrow: swap, lend, stake in 1 tx',
    exampleHeadline: 'Swap, lend, stake, or mint yield tokens from your Private Balance in 1 tx',
    exampleNote:
      'Tag 7 ExecViaEscrow is protocol-agnostic: DEX swaps (Jupiter, Titan, DFlow, Raydium, Orca) alongside lending supply (kTokens), yield vaults, liquid staking (JitoSOL, INF), perp LP (JLP), and RWA vaults. External DeFi mints, amounts, and output record remain public.',
    txHref: solscanTx(AUDREN.mainnet.swapTx, 'mainnet'),
    txLabel: 'Inspect ExecViaEscrow Tx',
    demoHref: '/demo',
    demoLabel: 'Try Shielded DeFi live',
    steps: [
      {
        actor: 'PRIVATE NOTE PROOF',
        title: 'Spend 1–2 global pool notes + native relayer fee',
        shortLabel: 'Prove input notes · Optional shielded change',
        packetLabel: '192 B Groth16 Proof',
        detail:
          'Your browser proves ownership of 1–2 global pool notes, binds router_program, every router account (pubkey + is_writable), min_amount_out, and relayer_fee inside ctx_hash, and optionally pays the relayer from the input or output leg (EXEC_FLAG_FEE_ON_OUTPUT).',
        cryptoTag: 'Tag 7 ExecViaEscrow · ctx_hash-bound router_accounts · ~158k CU',
      },
      {
        actor: 'SHARED ESCROW SHARD',
        title: 'Program unlocks into isolated sharded PDA',
        shortLabel: 'Unified vault → Sharded swap_escrow (0..15)',
        packetLabel: 'Token A → Escrow PDA',
        detail:
          'Audren verifies the 192 B Groth16 proof, locks nullifiers, snapshots pre-CPI owners/delegates/lamports in WatchedEscrowBuf, and moves exact amount_in into one of 16 sharded escrow PDAs. Only the escrow PDA signs the external CPI.',
        cryptoTag: 'Sharded swap_escrow PDA (0..15) · WatchedEscrowBuf firewall',
      },
      {
        actor: 'PROTOCOL-AGNOSTIC DEFI CPI',
        title: 'Execute any Token A → Token B Solana program',
        shortLabel: 'DEX · Lending Supply · LST · Yield Vault · RWA',
        packetLabel: 'DeFi Fill ≥ min_out',
        detail:
          'Inside the same Solana Transaction v1, Audren invokes the target Solana program via PDA CPI — leaving >1.2M CU for multi-hop DEXs, lending reserves, liquid staking, or vaults. If net output falls below min_amount_out, the entire transaction reverts cleanly.',
        cryptoTag: 'Any stateless Token A → Token B CPI · min_amount_out enforced',
      },
      {
        actor: 'AUTO-RESHIELDED ON-CHAIN',
        title: 'Exact output settles to your XOR-masked dynamic note',
        shortLabel: 'Measured net vault delta committed on-chain',
        packetLabel: 'Private Token B Note',
        detail:
          'Audren measures the exact vault balance delta received, settles any EXEC_FLAG_FEE_ON_OUTPUT relayer fee, sweeps every remaining atom into the unified vault, and writes an XOR-masked AUD2DYN2 dynamic memo (zero plaintext markers at rest) + Poseidon5 commitment to your stealth owner.',
        cryptoTag: 'Measured net delta · Token-2022 safe · Zero-plaintext dynamic memo',
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
        value: 'Reshielded immediately to your fresh Poseidon stealth owner inside Pool #0',
      },
    ],
  },
  {
    id: 'prove-or-exit',
    tabTitle: 'Receipt / Exit & Sessions',
    tabSub: 'Selective disclosure, unwrap WSOL, or DeFi sessions',
    exampleHeadline: 'Prove 1 invoice, self-pay an exit, or fund a 0-SOL DeFi session wallet',
    exampleNote:
      'Export a Mode 1 SelectiveDisclosureProof (1 Poseidon5 check) or Mode 2 FullViewingKey, exit with self-paying native fees and atomic WSOL → SOL unwrap, or fund a deterministic session wallet (B_0, B_1…) for stateful borrow/perp protocols and sweep every remaining lamport back with zero dust.',
    txHref: solscanTx(AUDREN.mainnet.withdrawTx, 'mainnet'),
    txLabel: 'Inspect Go Public Withdraw',
    demoHref: '/demo?mode=sandbox',
    demoLabel: 'Test Receipts & Exit Flows',
    steps: [
      {
        actor: 'LOCKED NOTE ON SOLANA',
        title: 'Poseidon5 commitment on SubtreePage',
        shortLabel: 'SubtreePage records cm = Poseidon5(3, stealth, asset, amt, r)',
        packetLabel: 'On-Chain Leaf cm',
        detail:
          'Every deposit, private JoinSplit, and shielded DeFi settlement writes a canonical 32-byte Poseidon5 commitment into a fixed 8,256 B SubtreePage PDA. Confirmed leaf commitments are append-only; note the deployment remains upgradeable during pre-audit.',
        cryptoTag: 'Poseidon5(DOMAIN_NOTE, stealth_owner, asset_id, amount, blinding)',
      },
      {
        actor: 'MODE 1 RECEIPT & MODE 2 FVK',
        title: 'Prove 1 note — or export read-only viewing access',
        shortLabel: 'Mode 1 = 1 Poseidon hash · Mode 2 = FullViewingKey',
        packetLabel: 'Receipt / FVK JSON',
        detail:
          'Mode 1 SelectiveDisclosureProof discloses (mint, amount, blinding, stealth_owner) for strictly 1 chosen note verified in 1 Poseidon5 check against SubtreePage (zero keys shared). Mode 2 FullViewingKey (spend_pk, nk, view_sk, view_pk) tracks both incoming notes AND spent nullifiers with zero spend authority.',
        cryptoTag: 'Zero spend_sk shared · Mode 1 single-note · Mode 2 key-separated nk',
      },
      {
        actor: 'SELF-PAYING EXIT & UNWRAP',
        title: 'Native relayer fee + atomic WSOL → Native SOL',
        shortLabel: 'Tag 6 JoinSplit · WITHDRAW_FLAG_UNWRAP_WSOL · Pause-immune',
        packetLabel: 'Direct Native SOL',
        detail:
          'Withdraw SOL or any SPL token to any wallet or deterministic DeFi Session keypair B_i with zero prior gas: pay relayer_fee natively from the withdrawn note and unwrap WSOL straight into Native SOL in one instruction via an ephemeral audren_v2_unwrap PDA (full exit bypasses SetPaused).',
        cryptoTag: 'Tag 6 JoinSplit · WITHDRAW_FLAG_UNWRAP_WSOL · ~103k–148k CU',
      },
      {
        actor: 'ZERO-DUST SESSION SWEEP',
        title: 'Return every lamport back to the pool',
        shortLabel: 'Tag 3 DepositSol(DEPOSIT_FLAG_FEE_FROM_AMOUNT) → 0 lamports',
        packetLabel: '0-Dust Reshield',
        detail:
          'After closing a stateful borrow or perp position on a session wallet B_i, sweep 100% of remaining SOL back into the pool with DepositSol(fee_from_amount=true): the protocol deducts deterministic LaneRentVault rent from the deposit itself, leaving 0 lamports behind. Remember that stateful DeFi positions opened by B_i remain public on Solana.',
        cryptoTag: 'Tag 3 DepositSol · DEPOSIT_FLAG_FEE_FROM_AMOUNT · 0-lamport sweep',
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
    verdict: 'REJECTED BY NULLIFIER PDAS',
    answer:
      'Every note derives one deterministic nullifier Poseidon4(4, nk, cm, global_leaf_index). The first spend initializes a permanent 0-byte Solana NullifierPDA and appends a 16-byte prefix to NullifierPage for zero-indexer wallet sync. Replays fail immediately at Solana’s runtime.',
    primitive: 'Key-Separated nk = Poseidon2(10, spend_sk) · NullifierPDA + NullifierPage',
  },
  {
    tag: 'CONSERVATION',
    question: 'Can anyone counterfeit tokens or use negative amounts?',
    verdict: 'ENFORCED IN FROZEN R1CS',
    answer:
      'The single minimal BN254 Groth16 circuit (17,861 constraints) enforces uniform asset_id across all inputs and outputs, exact value conservation, and 64-bit unsigned bit-decomposition range checks on every output commitment and public leg.',
    primitive: '17,861 R1CS · 64-Bit Range Gadgets · alt_bn128 Pairing Syscall',
  },
  {
    tag: 'SETUP & CEREMONY',
    question: 'What is the Groth16 trusted-setup provenance?',
    verdict: 'SINGLE FROZEN CIRCUIT · MPC BEFORE MAINNET',
    answer:
      'Audren freezes one minimal 17,861-constraint JoinSplit circuit capable of scaling 4→8→16 lanes without ever re-running a ceremony. Pre-audit deployments use DEV_DETERMINISTIC_VK; a public Phase-2 MPC ceremony and independent audit are planned prior to production custody.',
    primitive: 'BN254 Groth16 (vk_id = 0) · 192 B Proof · 3.75 MB Compressed PK',
  },
  {
    tag: 'STEALTH KEYS',
    question: 'Can anyone link two payments sent to my aud1… address?',
    verdict: 'FRESH POSEIDON STEALTH OWNERS',
    answer:
      'Audren instructions never write your reusable 65-byte aud1… address on-chain. Each sender derives a unique X25519 shared secret, computes stealth_owner = Poseidon3(2, spend_pk, tweak), and encrypts a 90 B ChaCha20-Poly1305 memo. Timing, public amounts, and external metadata can still correlate payments.',
    primitive: 'X25519 ECDH · Poseidon3 Stealth · 2-Byte View Tag · ChaCha20-Poly1305',
  },
  {
    tag: 'CUSTODY',
    question: 'Can Audren, a relayer, or a viewing-key holder steal or freeze funds?',
    verdict: 'FULL-NOTE EXIT BYPASSES PAUSE',
    answer:
      'Pool authority cannot spend shielded notes. Full withdrawals (output_mask == 0, including atomic WSOL unwrap) bypass SetPaused. Relayers cannot alter ctx_hash-bound outputs or router accounts. FullViewingKey (spend_pk, nk, view_sk, view_pk) is strictly read-only. Token issuer controls and mutable upgrade authority remain separate risks.',
    primitive: 'ctx_hash-Bound Outputs · Pause-Immune Full Exit · Key Separation',
  },
  {
    tag: 'ATOMIC ESCROW',
    question: 'Can a shielded DeFi CPI hijack escrow accounts or steal slippage?',
    verdict: 'HARDENED ESCROW FIREWALL · EXACT DELTA',
    answer:
      'During ExecViaEscrow (Tag 7), Audren binds router_program, every router account (pubkey + is_writable), min_amount_out, and relayer_fee inside ctx_hash, snapshots pre/post owner, delegate, close_authority, and lamports on escrow & token accounts, supports EXEC_FLAG_FEE_ON_OUTPUT, and commits the exact measured vault delta on-chain.',
    primitive: 'ExecViaEscrow (Tag 7) · WatchedEscrowBuf Firewall · ~158k CU',
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
                Derived locally · 65-byte payload (0x02 | spend_pk | view_pk)
              </span>
            </div>

            <div className="aud-addr-specimen">
              <div className="aud-addr-string mono" aria-label="Anatomy of an Audren private address">
                <span className="aud-seg is-prefix" title="Audren protocol prefix">
                  aud1
                </span>
                <span className="aud-seg is-spend" title="Version 0x02 + 32-byte BN254 Poseidon Spend Public Key">
                  Bzeekem3VfwxvTueYbWyZvRxvon9eD8duQLdj3FPEEZZ
                </span>
                <span className="aud-seg is-view" title="32-byte X25519 View Public Key">
                  e12BggMChombGhV3Ywujmet3YSXSoMd7jkd3WBaisnvF
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
                address, run shielded DeFi CPIs, and fund deterministic session wallets — or run
                the free Devnet sandbox without installing a wallet.
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
