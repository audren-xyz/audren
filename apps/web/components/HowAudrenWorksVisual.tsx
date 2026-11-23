'use client'

import { useState } from 'react'
import Link from 'next/link'
import {
  ArrowRight,
  ArrowUpRight,
  Check,
  Pause,
  Play,
  RefreshCw,
} from 'lucide-react'
import { AUDREN, solscanAddress, solscanTx } from '@/lib/protocol'
import { AttackSimulator } from '@/components/motion/AttackSimulator'
import { ProgressTrack } from '@/components/motion/SceneControls'
import { StealthDemo } from '@/components/motion/StealthDemo'
import { ViewTagScanner } from '@/components/motion/ViewTagScanner'
import { useAutoStepper, useInView } from '@/components/motion/hooks'

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
      'Alice does not need an Audren account or a zero-knowledge proof. Works for Native SOL, any Classic SPL token, or any transferable Token-2022 mint.',
    txHref: solscanTx(AUDREN.mainnet.depositTx, 'mainnet'),
    txLabel: 'Inspect real Mainnet deposit',
    demoHref: '/demo',
    demoLabel: 'Try Go Private live',
    steps: [
      {
        actor: 'Alice’s public wallet',
        title: 'Any Solana wallet, any token',
        shortLabel: 'Alice picks 500 USDC and pastes your aud1…',
        packetLabel: '500 USDC + aud1…',
        detail:
          'Alice enters your reusable Bech32m aud1… private address and chooses 500 USDC, SOL, BONK, or any transferable Token-2022 mint. Zero ZK proof generation is required: she signs a single unified Deposit (Tag 3) transaction (native SOL wraps atomically via SyncNative into WSOL alongside Classic SPL and Token-2022).',
        cryptoTag: 'Tag 3 Unified Deposit · 0 ZK proofs · 1 standard wallet signature',
      },
      {
        actor: 'One-time stealth box',
        title: 'Fresh Poseidon stealth owner and 106 B memo',
        shortLabel: 'stealth = Poseidon3(2, spend_pk, tweak)',
        packetLabel: 'Note cm + 106 B Memo',
        detail:
          'Alice’s wallet performs X25519 ECDH with your view public key (rejecting low-order points), derives a deterministic tweak and blinding scalar, computes stealth_owner = Poseidon3(DOMAIN_STEALTH, spend_pk, tweak), and encrypts (amount, mint, version, 14 B payment_id) into a 72-byte ChaCha20-Poly1305 AEAD ciphertext with (view_tag || epk) bound as AAD (106 B SoA entry).',
        cryptoTag: 'X25519 ECDH · 2-byte view_tag · ChaCha20-Poly1305 AEAD (72 B ct / 106 B SoA)',
      },
      {
        actor: 'Global 4-ary MASP Pool #0',
        title: 'Tokens enter the unified vault; leaf appends to lane',
        shortLabel: '500 USDC → Unified vault · cm → SubtreePage',
        packetLabel: '4^20 Global Tree (16 lanes)',
        detail:
          'Solana transfers 500 USDC into Audren’s canonical vault_auth ATA, computes cm = Poseidon5(DOMAIN_NOTE, stealth_owner, asset_id, net_received, blinding) on-chain, updates the active lane’s 4-ary Depth-18 frontier, and writes the 106 B SoA memo entry to MemoPage (10,240 B, 96 notes/page).',
        cryptoTag: 'Unified Pool #0 · Net-delta Token-2022 solvency · 4→8→16 lanes',
      },
      {
        actor: 'Your private balance',
        title: 'Discovered via ordinary RPC with zero indexer',
        shortLabel: 'CompactWalletStore scans MemoPages and freezes siblings',
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
        badge: 'Visible at entry',
        value: '7mQ2…9xRa deposited 500 USDC into shared Pool #0',
      },
      {
        label: 'Recipient (You)',
        visibility: 'hidden',
        badge: 'Hidden',
        value: 'One-time Poseidon stealth owner in place of the reusable recipient address',
      },
      {
        label: 'Link to other payments',
        visibility: 'hidden',
        badge: 'Fresh key',
        value: 'The one-time key does not directly identify the reusable recipient address',
      },
      {
        label: 'Later private transfers',
        visibility: 'hidden',
        badge: 'Hidden input',
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
      'This relayed private-transfer example conceals the spent record, uses a fresh recipient key, and blinds the token and amount. The relay fee payer and transaction metadata are public.',
    txHref: solscanTx(AUDREN.mainnet.transferTx, 'mainnet'),
    txLabel: 'Inspect Mainnet private send (0 user signers)',
    demoHref: '/demo',
    demoLabel: 'Try Private Send live',
    steps: [
      {
        actor: 'Global 4^20 Merkle proof',
        title: 'Prove ownership across the entire pool history',
        shortLabel: 'BN254 Groth16 over 20-level 4-ary super_root',
        packetLabel: '192 B Groth16 Proof',
        detail:
          'Your browser builds a 192-byte BN254 Groth16 proof (17,861 R1CS) locally in a dedicated WASM Web Worker against a recent RootCheckpoint: “I own 1 or 2 unspent notes anywhere in the global 4^20 Multi-Asset Shielded Pool, and their key-separated nullifiers have never been spent.”',
        cryptoTag: 'Tag 5 Transact · 17,861 R1CS · Key-separated nk nullifiers',
      },
      {
        actor: 'Hidden asset and amount',
        title: 'Conservation and 64-bit range checks inside R1CS',
        shortLabel: 'Poseidon5 note commitments and 64-bit bit-decomposition',
        packetLabel: 'cm0, cm1, cm2 (Hidden)',
        detail:
          'The circuit enforces uniform hidden asset_id across all inputs and outputs, exact value conservation (Σin = Σout + public_out + relayer_fee), and 64-bit unsigned range checks on every output, hiding token mint and amounts completely on-chain.',
        cryptoTag: 'Poseidon5(3, stealth, asset_id, amt, r) · 1 public_input_hash',
      },
      {
        actor: 'Open privacy relayer',
        title: 'Relayer pays gas while your wallet never signs',
        shortLabel: '1 Solana v1 tx · Optional shielded cm2 fee note',
        packetLabel: 'Relayed Solana v1 Tx',
        detail:
          'Your browser sends the finished proof to relay.audren.xyz (or your own self-hosted relay). For private transfers, the optional relayer fee settles as shielded output cm2 verified via the relayer’s read-only FullViewingKey (up to 4 parallel 2 → 1 merges fit in one Solana Transaction v1). Your public wallet never signs.',
        cryptoTag: 'Solana Tx v1 (0x81) · ~130k–160k CU · Zero user wallet signers',
      },
      {
        actor: 'Bob’s private balance',
        title: 'Opaque commitments and 106 B memos land on Solana',
        shortLabel: 'Bob gets 500 USDC · You keep hidden change',
        packetLabel: 'Bob +500 · Your Change',
        detail:
          'Solana verifies the 192 B Groth16 proof via native alt_bn128 pairing syscalls, locks NullifierPDA(s) and appends 16 B prefixes to NullifierPage, and writes the new commitments and 106 B SoA memos to your chosen append lane.',
        cryptoTag: 'alt_bn128 syscall verified · 16 B NullifierPage sync',
      },
    ],
    solscan: [
      {
        label: 'Sender wallet',
        visibility: 'hidden',
        badge: 'Absent (0 signers)',
        value: 'Signed only by the relayer; your wallet never appears on the transaction',
      },
      {
        label: 'Recipient (Bob)',
        visibility: 'hidden',
        badge: 'Hidden',
        value: 'One-time Poseidon stealth owner; Bob’s aud1… address and wallet never appear',
      },
      {
        label: 'Token and amount',
        visibility: 'hidden',
        badge: 'Hidden in Poseidon5',
        value: 'All asset IDs and amounts remain hidden inside opaque 32 B commitments',
      },
      {
        label: 'Link to past deposits',
        visibility: 'hidden',
        badge: 'Global 4^20 MASP',
        value: 'Proof spans the entire historical pool; timing and outside metadata still matter',
      },
    ],
  },
  {
    id: 'private-swap',
    tabTitle: 'Shielded DeFi',
    tabSub: 'ExecViaEscrow: swap, lend, stake in 1 tx',
    exampleHeadline: 'Swap, lend, stake, or mint yield tokens from your Private Balance in 1 tx',
    exampleNote:
      'Tag 6 ExecViaEscrow is protocol-agnostic across SPL and Token-2022: DEX swaps (Jupiter, Titan, DFlow, Raydium, Orca) alongside lending supply (kTokens), yield vaults, liquid staking (JitoSOL, INF), perp LP (JLP), and RWA vaults. External DeFi mints, amounts, and output record remain public.',
    txHref: solscanTx(AUDREN.mainnet.swapTx, 'mainnet'),
    txLabel: 'Inspect ExecViaEscrow transaction',
    demoHref: '/demo',
    demoLabel: 'Try Shielded DeFi live',
    steps: [
      {
        actor: 'Private note proof',
        title: 'Spend 1–2 global pool notes with native relayer fee',
        shortLabel: 'Prove input notes · Optional shielded change',
        packetLabel: '192 B Groth16 Proof',
        detail:
          'Your browser proves ownership of 1–2 global pool notes, binds router_program, every router account (pubkey + is_writable), min_amount_out, and relayer_fee inside ctx_hash, and optionally pays the relayer from the input or output leg (EXEC_FLAG_FEE_ON_OUTPUT).',
        cryptoTag: 'Tag 6 ExecViaEscrow · ctx_hash-bound router_accounts · ~158k CU',
      },
      {
        actor: 'Shared escrow shard',
        title: 'Program unlocks into isolated sharded PDA',
        shortLabel: 'Unified vault ATA → Sharded audren_escrow (0..15)',
        packetLabel: 'Token A → Escrow PDA',
        detail:
          'Audren verifies the 192 B Groth16 proof, locks nullifiers, snapshots pre-CPI owners, delegates, and lamports in WatchedEscrowBuf, and moves exact amount_in into a randomly chosen shard among 16 sharded escrow PDAs. Only the escrow PDA signs the external CPI.',
        cryptoTag: 'Sharded audren_escrow PDA (0..15) · WatchedEscrowBuf firewall',
      },
      {
        actor: 'Protocol-agnostic DeFi CPI',
        title: 'Execute any Token A → Token B Solana program',
        shortLabel: 'DEX · Lending Supply · LST · Yield Vault · RWA',
        packetLabel: 'DeFi Fill ≥ min_out',
        detail:
          'Inside the same Solana Transaction v1, Audren invokes the target Solana program via PDA CPI, leaving >1.2M CU for multi-hop DEXs, lending reserves, liquid staking, or vaults. If net output falls below min_amount_out, the entire transaction reverts cleanly.',
        cryptoTag: 'Any stateless Token A → Token B CPI · min_amount_out enforced',
      },
      {
        actor: 'Auto-reshielded on-chain',
        title: 'Exact output settles to your XOR-masked dynamic note',
        shortLabel: 'Measured net vault delta committed on-chain',
        packetLabel: 'Private Token B Note',
        detail:
          'Audren measures the exact vault balance delta received, settles any EXEC_FLAG_FEE_ON_OUTPUT relayer fee, sweeps every remaining atom into the canonical vault ATA, and writes a domain-separated 72 B XOR-masked AUD1DYN1 dynamic memo (zero plaintext markers at rest) plus a Poseidon5 commitment to your stealth owner.',
        cryptoTag: 'Measured net delta · Token-2022 safe · 72 B AUD1DYN1 dynamic memo',
      },
    ],
    solscan: [
      {
        label: 'Target DeFi call and amounts',
        visibility: 'visible',
        badge: 'Public',
        value: 'External program, input and output mints, amount_in, and actual_out are visible',
      },
      {
        label: 'Your public wallet',
        visibility: 'hidden',
        badge: 'Absent',
        value: 'Relayer paid gas (reimbursed natively); shared escrow PDA signed the DeFi CPI',
      },
      {
        label: 'Public unshield step',
        visibility: 'hidden',
        badge: 'None, 1 tx',
        value: 'Escrow executes the DeFi call and sweeps Token B directly into a fresh pool note',
      },
      {
        label: 'Output amount integrity',
        visibility: 'verified',
        badge: 'On-chain exact',
        value: 'Program measures exact net vault delta and enforces min_amount_out',
      },
      {
        label: 'New token or yield receipt',
        visibility: 'hidden',
        badge: 'Ownership private',
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
      'Export a Mode 1 SelectiveDisclosureProof (1 Poseidon5 check) or Mode 2 FullViewingKey, exit with self-paying native fees and atomic WSOL → SOL unwrap, or fund a deterministic session wallet (B_0, B_1…) for stateful borrow or perp protocols and sweep every remaining lamport back with zero dust.',
    txHref: solscanTx(AUDREN.mainnet.withdrawTx, 'mainnet'),
    txLabel: 'Inspect Go Public withdrawal',
    demoHref: '/demo?mode=sandbox',
    demoLabel: 'Test Receipts & Exit Flows',
    steps: [
      {
        actor: 'Locked note on Solana',
        title: 'Poseidon5 commitment on SubtreePage',
        shortLabel: 'SubtreePage records cm = Poseidon5(3, stealth, asset, amt, r)',
        packetLabel: 'On-Chain Leaf cm',
        detail:
          'Every Deposit, private Transact, and ExecViaEscrow settlement writes a canonical 32-byte Poseidon5 commitment into a fixed 8,256 B SubtreePage PDA. Confirmed leaf commitments are append-only; note the deployment remains upgradeable during pre-audit.',
        cryptoTag: 'Poseidon5(DOMAIN_NOTE, stealth_owner, asset_id, amount, blinding)',
      },
      {
        actor: 'Mode 1 receipt and Mode 2 FVK',
        title: 'Prove 1 note or export read-only viewing access',
        shortLabel: 'Mode 1 = 1 Poseidon hash · Mode 2 = FullViewingKey',
        packetLabel: 'Receipt / FVK JSON',
        detail:
          'Mode 1 SelectiveDisclosureProof discloses (mint, amount, blinding, stealth_owner) for strictly 1 chosen note verified in 1 Poseidon5 check against SubtreePage (zero keys shared). Mode 2 FullViewingKey (spend_pk, nk, view_sk, view_pk) tracks both incoming notes and spent nullifiers with zero spend authority.',
        cryptoTag: 'Zero spend_sk shared · Mode 1 single-note · Mode 2 key-separated nk',
      },
      {
        actor: 'Self-paying exit and unwrap',
        title: 'Native relayer fee plus atomic WSOL → Native SOL',
        shortLabel: 'Tag 5 Transact · WITHDRAW_FLAG_UNWRAP_WSOL · Pause-immune',
        packetLabel: 'Direct Native SOL',
        detail:
          'Withdraw SOL or any SPL token to any wallet or deterministic DeFi Session keypair B_i with zero prior gas: pay relayer_fee natively from the withdrawn note and unwrap WSOL straight into Native SOL in one instruction via an ephemeral audren_unwrap PDA (full exit bypasses SetPaused).',
        cryptoTag: 'Tag 5 Transact · WITHDRAW_FLAG_UNWRAP_WSOL · ~103k–148k CU',
      },
      {
        actor: 'Zero-dust session sweep',
        title: 'Return every lamport back to the pool',
        shortLabel: 'Tag 3 Deposit(NATIVE_SOL | FEE_FROM_AMOUNT) → 0 lamports',
        packetLabel: '0-Dust Reshield',
        detail:
          'After closing a stateful borrow or perp position on a session wallet B_i, sweep 100% of remaining SOL back into the pool with unified Deposit (DEPOSIT_FLAG_NATIVE_SOL | DEPOSIT_FLAG_FEE_FROM_AMOUNT): the protocol deducts deterministic LaneRentVault rent from the deposit itself, leaving 0 lamports behind. Remember that stateful DeFi positions opened by B_i remain public on Solana.',
        cryptoTag: 'Tag 3 Deposit · NATIVE_SOL + FEE_FROM_AMOUNT · 0-lamport sweep',
      },
    ],
    solscan: [
      {
        label: 'Rest of your balance',
        visibility: 'hidden',
        badge: 'Hidden',
        value: 'Receipt reveals strictly 1 chosen payment and nothing else',
      },
      {
        label: 'Self-paying exit and unwrap',
        visibility: 'verified',
        badge: '1 tx, 0-SOL bootstrap',
        value: 'Relayer reimbursed natively; WSOL unwraps atomically to Native SOL',
      },
      {
        label: 'Stateful DeFi session positions',
        visibility: 'visible',
        badge: 'Public on DeFi protocol',
        value: 'Collateral, borrow, and perp positions opened by session wallet Bᵢ remain public on-chain',
      },
      {
        label: 'Exit to any fresh wallet',
        visibility: 'verified',
        badge: 'Permissionless',
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
    tag: 'Double-spend',
    question: 'Can anyone spend the same private note twice?',
    verdict: 'Rejected by Nullifier PDAs',
    answer:
      'Every note derives one deterministic nullifier Poseidon4(4, nk, cm, global_leaf_index). The first spend initializes a permanent 0-byte Solana NullifierPDA and appends a 16-byte prefix to NullifierPage for zero-indexer wallet sync. Replays fail immediately at Solana’s runtime.',
    primitive: 'Key-separated nk = Poseidon2(10, spend_sk) · NullifierPDA + NullifierPage',
  },
  {
    tag: 'Conservation',
    question: 'Can anyone counterfeit tokens or use negative amounts?',
    verdict: 'Enforced in frozen R1CS',
    answer:
      'The single minimal BN254 Groth16 circuit (17,861 constraints) enforces uniform asset_id across all inputs and outputs, exact value conservation, and 64-bit unsigned bit-decomposition range checks on every output commitment and public leg.',
    primitive: '17,861 R1CS · 64-bit range gadgets · alt_bn128 pairing syscall',
  },
  {
    tag: 'Setup and ceremony',
    question: 'What is the Groth16 trusted-setup provenance?',
    verdict: 'Perpetual PTAU (71+) · BGM17 · Pre-audit',
    answer:
      'Audren freezes one minimal 17,861-constraint JoinSplit4AryCircuit capable of scaling 4→8→16 lanes without ever re-running a ceremony. Phase 1 uses Hermez/PSE Perpetual Powers of Tau (71+ independent public contributors) and Phase 2 uses verifiable BGM17 zeroized contributions plus a live drand Quicknet and Solana Mainnet beacon (ceremony/transcript.json). External security audit is pending prior to freezing upgrade authority.',
    primitive: 'BN254 Groth16 (vk_id = 0) · 192 B proof · 3.93 MB compressed PK',
  },
  {
    tag: 'Stealth keys',
    question: 'Can anyone link two payments sent to my aud1… address?',
    verdict: 'Fresh Poseidon stealth owners',
    answer:
      'Audren instructions never write your reusable 114-character Bech32m aud1… address on-chain. Each sender derives a unique X25519 shared secret (rejecting low-order points), computes stealth_owner = Poseidon3(2, spend_pk, tweak), and encrypts a versioned 72 B ChaCha20-Poly1305 AEAD memo (106 B SoA wire entry). Timing, public amounts, and external metadata can still correlate payments.',
    primitive: 'X25519 ECDH · Poseidon3 stealth · 2-byte view tag · 72 B AEAD (106 B SoA)',
  },
  {
    tag: 'Custody',
    question: 'Can Audren, a relayer, or a viewing-key holder steal or freeze funds?',
    verdict: 'Full-note exit bypasses pause',
    answer:
      'Pool authority cannot spend shielded notes. Full withdrawals (output_mask == 0, including atomic WSOL unwrap) bypass SetPaused. Relayers cannot alter ctx_hash-bound outputs or router accounts. FullViewingKey (spend_pk, nk, view_sk, view_pk) is strictly read-only. Token issuer controls and mutable upgrade authority remain separate risks.',
    primitive: 'ctx_hash-bound outputs · Pause-immune full exit · Key separation',
  },
  {
    tag: 'Atomic escrow',
    question: 'Can a shielded DeFi CPI hijack escrow accounts or steal slippage?',
    verdict: 'Escrow firewall · Exact delta',
    answer:
      'During ExecViaEscrow (Tag 6), Audren binds router_program, every router account (pubkey + is_writable), min_amount_out, and relayer_fee inside ctx_hash, snapshots pre/post owner, delegate, close_authority, and lamports on escrow and token accounts, supports EXEC_FLAG_FEE_ON_OUTPUT, and commits the exact measured vault delta on-chain.',
    primitive: 'ExecViaEscrow (Tag 6) · WatchedEscrowBuf firewall · ~158k CU',
  },
]

const STEP_DURATION_MS = 4800
const ADDRESS_PARTS = ['prefix', 'spend', 'view'] as const

export function HowAudrenWorksVisual() {
  const [activeFlowId, setActiveFlowId] = useState<FlowId>('public-to-private')
  const [copiedSample, setCopiedSample] = useState<boolean>(false)
  const [hoverPart, setHoverPart] = useState<number | null>(null)

  const [addrRef, addrInView] = useInView<HTMLDivElement>()
  // One guided pass (prefix → spend key → view key), then the whole address rests.
  const addrStepper = useAutoStepper({ count: 4, durations: 2600, active: addrInView, loop: false })
  const focusIdx = hoverPart ?? (addrStepper.reduced || addrStepper.step === 3 ? null : addrStepper.step)
  const addrFocus = focusIdx === null ? 'none' : ADDRESS_PARTS[focusIdx]

  const [theaterRef, theaterInView] = useInView<HTMLDivElement>()
  const flowStepper = useAutoStepper({
    count: 4,
    durations: STEP_DURATION_MS,
    active: theaterInView,
    resetKey: activeFlowId,
  })
  const activeStep = flowStepper.step
  const autoPlay = flowStepper.playing

  const flow = FLOWS.find((f) => f.id === activeFlowId) ?? FLOWS[0]
  const currentStep = flow.steps[activeStep] ?? flow.steps[0]

  const selectFlow = (id: FlowId) => {
    setActiveFlowId(id)
    flowStepper.goTo(0)
  }

  const selectStep = (idx: number) => flowStepper.select(idx)
  const stepPrev = () => flowStepper.select((activeStep + 3) % 4)
  const stepNext = () => flowStepper.select((activeStep + 1) % 4)

  const copySampleAddress = () => {
    const sample =
      'aud1qyy8j5pa6dnmqs9asr5u8cne6577wuy4a2yednkw5lre7xjfmlczddgk44pa6mf3ujjcgjgemvuwq2a44dcxgjjnp54jmk0dw5krjjcdppvea6'
    navigator.clipboard?.writeText(sample).catch(() => {})
    setCopiedSample(true)
    window.setTimeout(() => setCopiedSample(false), 1600)
  }

  const activeCenterPct = 12.5 + activeStep * 25
  const fillWidthPct = (activeStep / 3) * 75

  return (
    <>
      {/* ================================================================
          SECTION 1: YOUR aud1... ADDRESS AND ANIMATED FLOWS
         ================================================================ */}
      <section className="section" id="how-it-works" style={{ paddingTop: 52 }}>
        <div className="container">
          {/* PART A: YOUR REUSABLE PRIVATE ADDRESS ANATOMY */}
          <div
            ref={addrRef}
            className="aud-addr-card"
            data-focus={addrFocus}
            onMouseLeave={() => setHoverPart(null)}
          >
            <div className="aud-addr-head">
              <div className="aud-addr-title-wrap">
                <h3>
                  Share one reusable <code>aud1…</code> address to receive through fresh one-time
                  keys.
                </h3>
              </div>
              <span className="mono" style={{ fontSize: 12, color: '#55574e' }}>
                BIP-350 Bech32m (114 chars) · 65-byte payload (0x01 | spend_pk | view_pk) + checksum
              </span>
            </div>

            <div className="aud-addr-specimen">
              <div className="aud-addr-string mono" aria-label="Anatomy of an Audren BIP-350 Bech32m private address">
                <span className="aud-seg is-prefix" data-part="prefix" title="BIP-350 Bech32m human-readable prefix (hrp = aud) and separator">
                  aud1
                </span>
                <span className="aud-seg is-spend" data-part="spend" title="Version 0x01 + 32-byte BN254 Poseidon Spend Public Key (5-bit Bech32m)">
                  qyy8j5pa6dnmqs9asr5u8cne6577wuy4a2yednkw5lre7xjfmlczd
                </span>
                <span className="aud-seg is-view" data-part="view" title="32-byte X25519 View Public Key (5-bit Bech32m)">
                  dgk44pa6mf3ujjcgjgemvuwq2a44dcxgjjnp54jmk0dw5krjjcd
                </span>
                <span className="aud-seg is-prefix" data-part="prefix" title="6-character BIP-350 Bech32m typo-detecting checksum">
                  ppvea6
                </span>
              </div>
              <button
                type="button"
                className="aud-addr-copy"
                style={{ letterSpacing: 0 }}
                onClick={copySampleAddress}
                aria-label="Copy example aud1 address format"
              >
                {copiedSample ? (
                  <>
                    <Check size={12} /> Copied format
                  </>
                ) : (
                  'Copy example'
                )}
              </button>
            </div>

            <div className="aud-addr-legend">
              <div
                className="aud-legend-item"
                data-part="prefix"
                onPointerEnter={(e) => e.pointerType === 'mouse' && setHoverPart(0)}
              >
                <div>
                  <h4
                    className="mono"
                    style={{
                      margin: '0 0 6px',
                      fontSize: '0.82rem',
                      fontWeight: 500,
                      letterSpacing: 0,
                      color: 'var(--ink)',
                    }}
                  >
                    aud1 + checksum · BIP-350 Bech32m
                  </h4>
                  <p>
                    114-character lowercase Bech32m encoding (<code>hrp = &quot;aud&quot;</code>,
                    version <code>0x01</code>) with a built-in 6-character typo-detecting checksum.
                    Unlike a normal Solana pubkey, explorers cannot look up balances from it.
                  </p>
                </div>
              </div>
              <div
                className="aud-legend-item"
                data-part="spend"
                onPointerEnter={(e) => e.pointerType === 'mouse' && setHoverPart(1)}
              >
                <div>
                  <h4
                    className="mono"
                    style={{
                      margin: '0 0 6px',
                      fontSize: '0.82rem',
                      fontWeight: 500,
                      letterSpacing: 0,
                      color: 'var(--vault)',
                    }}
                  >
                    S · Spend public key (32 B)
                  </h4>
                  <p>
                    Senders combine <code>S</code> with fresh randomness to lock funds into a
                    one-time stealth box that only your private spend key can ever unlock.
                  </p>
                </div>
              </div>
              <div
                className="aud-legend-item"
                data-part="view"
                onPointerEnter={(e) => e.pointerType === 'mouse' && setHoverPart(2)}
              >
                <div>
                  <h4
                    className="mono"
                    style={{
                      margin: '0 0 6px',
                      fontSize: '0.82rem',
                      fontWeight: 500,
                      letterSpacing: 0,
                      color: '#7c5b1e',
                    }}
                  >
                    V · View public key (32 B)
                  </h4>
                  <p>
                    Lets senders encrypt the coin, amount, and memo strictly for you. Your browser
                    auto-discovers incoming payments using your local view key.
                  </p>
                </div>
              </div>
            </div>
          </div>

          <StealthDemo />

          {/* PART B: ANIMATED INTERACTIVE FLOW THEATER */}
          <div
            ref={theaterRef}
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
              <div className="flow-controls">
                <button
                  type="button"
                  className="flow-ctrl-btn"
                  style={{ letterSpacing: 0 }}
                  onClick={flowStepper.togglePlay}
                  aria-label={autoPlay ? 'Pause animation' : 'Auto-play animation'}
                >
                  {autoPlay ? (
                    <>
                      <Pause size={12} /> Pause
                    </>
                  ) : (
                    <>
                      <Play size={12} /> Play
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
                <span className="flow-step-counter mono">
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
                  onClick={flowStepper.restart}
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
                    className="flow-packet mono"
                    style={{ left: `${activeCenterPct}%`, letterSpacing: 0, border: 'none' }}
                  >
                    <span key={currentStep.packetLabel} className="flow-packet-label">
                      {currentStep.packetLabel}
                    </span>
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
                      <ProgressTrack
                        state={isCurrent ? 'current' : isDone ? 'done' : 'todo'}
                        animate={isCurrent && autoPlay}
                        running={flowStepper.running}
                        duration={flowStepper.duration}
                        resetKey={`${flowStepper.cycle}-${autoPlay}`}
                      />
                      <div className="flow-node-top">
                        <span
                          className="flow-node-num mono"
                          aria-hidden="true"
                          style={{ fontSize: 10, fontWeight: 500 }}
                        >
                          {isDone ? <Check size={11} /> : idx + 1}
                        </span>
                        <span className="flow-node-actor" style={{ letterSpacing: 0 }}>
                          {step.actor}
                        </span>
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
                <div className="flow-pane-head" style={{ letterSpacing: 0 }}>
                  <span style={{ fontWeight: 500 }}>What actually happens</span>
                  <span className="flow-pane-actor">{currentStep.actor}</span>
                </div>
                <div key={`${flow.id}-${activeStep}`} className="flow-detail-swap">
                  <h4 className="flow-detail-title">{currentStep.title}</h4>
                  <p className="flow-detail-body">{currentStep.detail}</p>
                </div>
                <div className="flow-crypto-strip mono">
                  <span>{currentStep.cryptoTag}</span>
                </div>
              </div>

              <div className="flow-solscan-pane">
                <div className="flow-pane-head" style={{ letterSpacing: 0 }}>
                  <span style={{ fontWeight: 500 }}>What an observer sees on Solscan</span>
                  <span>Public ledger view</span>
                </div>

                <div key={flow.id} className="flow-solscan-rows">
                  {flow.solscan.map((row, rowIdx) => (
                    <div
                      key={row.label}
                      className={`flow-solscan-row is-${row.visibility}`}
                      style={{ animationDelay: `${rowIdx * 70}ms` }}
                    >
                      <div className="flow-solscan-meta">
                        <span className="flow-solscan-label" style={{ fontWeight: 500 }}>
                          {row.label}
                        </span>
                        <span
                          className={`flow-vis-badge is-${row.visibility}`}
                          style={{ letterSpacing: 0, border: 'none', fontWeight: 500 }}
                        >
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
            <div className="flow-theater-footer">
              <a href={flow.txHref} target="_blank" rel="noreferrer" className="slip-link">
                {flow.txLabel} <ArrowUpRight size={13} />
              </a>
              <Link href={flow.demoHref} className="slip-link is-strong" style={{ fontWeight: 500 }}>
                {flow.demoLabel} <ArrowRight size={12} />
              </Link>
            </div>
          </div>

          {/* Full-Width Carbon Ink Demo Band */}
          <div className="ink-callout">
            <div className="ink-callout-copy">
              <h3>Run these flows yourself on Mainnet or Devnet.</h3>
              <p>
                Connect Phantom, Solflare, or Backpack to deposit, send to any <code>aud1…</code>{' '}
                address, run shielded DeFi CPIs, and fund deterministic session wallets, or run the
                free Devnet sandbox without installing a wallet.
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
                Inspect Mainnet program <ArrowUpRight size={14} />
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* ================================================================
          SECTION 2: ZERO-INDEXER WALLET DISCOVERY
         ================================================================ */}
      <section className="section section-ruled" id="discovery">
        <div className="container">
          <div className="section-head-split">
            <div>
              <h2>How your wallet finds its own payments.</h2>
            </div>
            <p className="section-sub">
              Nobody keeps a list of who received what. Your device reads the same public pages
              as everyone else and recognises its own notes locally, using ordinary Solana RPC and
              no indexer.
            </p>
          </div>
          <ViewTagScanner />
        </div>
      </section>

      {/* ================================================================
          SECTION 3: CRYPTOGRAPHIC SOUNDNESS AND ON-CHAIN CHECKS
         ================================================================ */}
      <section className="section section-ruled" id="security">
        <div className="container">
          <div className="section-head-split">
            <div>
              <h2>What the program checks before a spend.</h2>
            </div>
            <p className="section-sub">
              The program verifies ownership, value conservation, range proofs, and nullifier
              uniqueness on-chain. These checks do not prove resistance to metadata analysis or
              establish an independent solvency audit. Audren is pre-audit and upgradeable.
            </p>
          </div>

          <AttackSimulator />

          <div className="soundness-grid">
            {SOUNDNESS_PILLARS.map((item) => (
              <article key={item.tag} className="soundness-cell">
                <div className="soundness-top">
                  <span className="soundness-num" style={{ letterSpacing: 0 }}>
                    {item.tag}
                  </span>
                  <span
                    className="soundness-verdict"
                    style={{
                      letterSpacing: 0,
                      border: 'none',
                      background: 'transparent',
                      padding: 0,
                      fontWeight: 500,
                    }}
                  >
                    {item.verdict}
                  </span>
                </div>
                <h3>{item.question}</h3>
                <p>{item.answer}</p>
                <div className="soundness-primitive mono" style={{ letterSpacing: 0 }}>
                  {item.primitive}
                </div>
              </article>
            ))}
          </div>

          <div className="soundness-footnote">
            <p style={{ letterSpacing: 0 }}>
              Pre-audit · Upgradeable deployment · Program <code>{AUDREN.programId}</code> ·
              Apache-2.0
            </p>
            <Link href="/architecture" className="text-link" style={{ fontWeight: 500 }}>
              Read full cryptographic proof and wire spec <ArrowRight size={14} />
            </Link>
          </div>
        </div>
      </section>
    </>
  )
}
