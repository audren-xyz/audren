'use client'

import { useState } from 'react'
import Link from 'next/link'
import { ArrowLeft, ArrowRight, ArrowUpRight } from 'lucide-react'
import { SiteHeader } from '@/components/SiteHeader'
import { SiteFooter } from '@/components/SiteFooter'
import { AUDREN, MEASURED_CU_ROWS, explorerAddress, solscanAddress } from '@/lib/protocol'
import styles from '@/components/SubpageShell.module.css'

const INSTRUCTIONS = [
  {
    tag: '0x00',
    name: 'InitPool',
    summary:
      'Create PoolState (128 B, audren_v2_pool) and unified sol_vault PDA with ring-wrap deadlock guard (max_ckpt_age <= ckpt_interval * 256).',
  },
  {
    tag: '0x01',
    name: 'InitLane',
    summary:
      'Authority-signed monotonic lane initializer (active_lanes = 4 → 8 → 16) creating LaneTreeState (1,824 B), LaneRentVault, and seq-0 SubtreePage/SubtreeRootPage/MemoPage/NullifierPage PDAs.',
  },
  {
    tag: '0x02',
    name: 'OpenPage',
    summary:
      'Permissionless page opener for SubtreePage (8,256 B), SubtreeRootPage (9,664 B), MemoPage (10,144 B), or NullifierPage (9,664 B) reimbursed deterministically from LaneRentVault.',
  },
  {
    tag: '0x03',
    name: 'DepositSol',
    summary:
      'Shield Native SOL into the unified sol_vault (~42.5k CU, 0 ZK proof). Computes Poseidon5 commitment on-chain, updates the lane 4-ary frontier, appends 90 B SoA memo, and supports DEPOSIT_FLAG_FEE_FROM_AMOUNT for zero-dust session sweeps.',
  },
  {
    tag: '0x04',
    name: 'DepositSpl',
    summary:
      'Shield Classic SPL or Token-2022 tokens (~48k–53k CU, 0 ZK proof). Commits measured net vault balance delta (TransferFeeConfig safe) and validates sanitized trailing TransferHook accounts.',
  },
  {
    tag: '0x05',
    name: 'PublishCheckpoint',
    summary:
      'Permissionless 256-slot cyclic RootCheckpoint (704 B) publisher hashing all active lane roots (plus Z[18] for unactivated lanes) into one global 4-ary Depth-20 super_root (16.8k / 23.6k / 44.5k CU for 4 / 8 / 16 lanes).',
  },
  {
    tag: '0x06',
    name: 'JoinSplit',
    summary:
      '192 B BN254 Groth16 2-in/3-out spend (~103k–160k CU) across the global 4^20 MASP. Supports private transfers (ASSET_MODE_PRIVATE with optional shielded cm2 relayer fee), public SOL/SPL exits, and atomic WSOL→SOL unwrap (WITHDRAW_FLAG_UNWRAP_WSOL, pause-immune when output_mask == 0).',
  },
  {
    tag: '0x07',
    name: 'ExecViaEscrow',
    summary:
      'Protocol-agnostic 1-tx shielded DeFi CPI (~158k–189k CU, leaving >1.2M CU for DeFi) through 16 sharded swap_escrow PDAs with WatchedEscrowBuf firewall, ctx_hash-bound router_accounts, input or output relayer fees (EXEC_FLAG_FEE_ON_OUTPUT), and XOR-masked dynamic output notes.',
  },
  {
    tag: '0x08',
    name: 'SetPaused',
    summary:
      'Emergency authority circuit breaker halting deposits, private transfers, DeFi CPIs, and partial exits while preserving permissionless full withdrawals (output_mask == 0, including WSOL unwrap).',
  },
] as const

const CIRCUIT_CONSTRAINTS = [
  {
    id: 'Keying',
    label: 'Key separation (spend_pk & nk)',
    formula: 'spend_pk = Poseidon2(1, spend_sk)  ·  nk = Poseidon2(10, spend_sk)',
  },
  {
    id: 'Stealth',
    label: 'One-time stealth owner',
    formula: 'stealth_owner = Poseidon3(2, spend_pk, tweak)',
  },
  {
    id: 'Note',
    label: 'Canonical multi-asset note commitment',
    formula: 'cm = Poseidon5(3, stealth_owner, asset_id, amount, blinding)',
  },
  {
    id: 'Tree',
    label: '4-ary Depth-20 global Merkle membership',
    formula: '20 levels × Poseidon4(c0, c1, c2, c3) == RootCheckpoint.super_root  (4²⁰ = 1.099T notes)',
  },
  {
    id: 'Nullifier',
    label: 'Real & padded dummy nullifiers',
    formula: 'nf = Poseidon4(4, nk, cm, (lane_id << 36) | leaf_idx)  [or Poseidon3(5, nk, r) / 0 if omit_nf1]',
  },
  {
    id: 'Balance',
    label: 'Uniform asset & 64-bit value conservation',
    formula: 'in₀ + in₁ == out₀ + out₁ + out₂ + public_out + relayer_fee  (all amounts ∈ [0, 2⁶⁴))',
  },
  {
    id: 'Public',
    label: 'Single compressed Groth16 public input',
    formula: 'pub_hash = Poseidon4(9, Poseidon5(7, super_root, nf₀, nf₁, cm₀), Poseidon5(8, cm₁, cm₂, pub_asset, packed_amts), ctx_hash)',
  },
] as const

const MEMO_PAGE_MAP = [
  {
    offset: '0..64',
    bytes: '64 B',
    weight: 8,
    short: 'Hdr',
    field: 'MemoPageHeader',
    inScan: false,
    bg: '#e6e2d7',
    color: '#2b2d26',
    desc: 'AUD2MM03 magic, lane_id, bump, count (0..=112), pool_id, page_seq, created_slot, closed_slot.',
  },
  {
    offset: '64..288',
    bytes: '224 B',
    weight: 14,
    short: 'view_tags',
    field: 'view_tags[112] (2 B each)',
    inScan: true,
    bg: '#184433',
    color: '#f4f1ea',
    desc: '16-bit view tag rejects 65,535 / 65,536 non-owned notes before AEAD decryption.',
  },
  {
    offset: '288..3,872',
    bytes: '3,584 B',
    weight: 32,
    short: 'ephemeral_pks',
    field: 'ephemeral_pks[112] (32 B each)',
    inScan: true,
    bg: '#255a44',
    color: '#f4f1ea',
    desc: 'X25519 ephemeral public keys for deterministic ECDH shared secret derivation.',
  },
  {
    offset: '3,872..10,144',
    bytes: '6,272 B',
    weight: 46,
    short: 'ciphertexts',
    field: 'ciphertexts[112] (56 B each)',
    inScan: false,
    bg: '#eaede6',
    color: '#1b2b22',
    desc: 'ChaCha20-Poly1305 encrypted (amount_u64 || mint_32) + 16 B tag (or XOR-masked AUD2DYN2 swap note).',
  },
] as const

const MAX_TX_CU = 1_400_000

export function ArchitectureExperience() {
  const [activeSlice, setActiveSlice] = useState<number>(1)
  const slice = MEMO_PAGE_MAP[activeSlice] ?? MEMO_PAGE_MAP[0]

  return (
    <div className={`page-shell ${styles.page}`}>
      <SiteHeader current="architecture" />

      <main>
        {/* HERO */}
        <section className={`container ${styles.hero}`}>
          <Link href="/" className={styles.backLink}>
            <ArrowLeft size={12} /> audren.xyz
          </Link>
          <div className={styles.heroSingle}>
            <h1>Audren Cryptographic &amp; On-Chain Specification</h1>
            <p className={styles.heroLead}>
              Minimal frozen BN254 Groth16 circuit ({AUDREN.circuitConstraints.toLocaleString()}{' '}
              R1CS, 4-ary Depth-20 global MASP), 9 instructions, fixed &lt;10 KiB zero-realloc
              accounts, ordinary-RPC <code>CompactWalletStore</code>, and measured sBPFv3 Compute
              Units in{' '}
              <a
                href={AUDREN.githubCore}
                target="_blank"
                rel="noreferrer"
                className={styles.textLink}
              >
                github.com/audren-xyz/audren <ArrowUpRight size={13} />
              </a>
              .
            </p>
          </div>

          <div className={styles.heroMetaStrip}>
            <div className={styles.heroMetaCell}>
              <span>Program ID ({AUDREN.releaseTag})</span>
              <strong className="mono">
                <a href={solscanAddress(AUDREN.programId)} target="_blank" rel="noreferrer">
                  {AUDREN.programId.slice(0, 10)}…{AUDREN.programId.slice(-6)} <ArrowUpRight size={11} />
                </a>
              </strong>
            </div>
            <div className={styles.heroMetaCell}>
              <span>Frozen Circuit</span>
              <strong className="mono">
                {AUDREN.circuitConstraints.toLocaleString()} R1CS · {AUDREN.proofBytes} B Groth16
              </strong>
            </div>
            <div className={styles.heroMetaCell}>
              <span>Compiled ELF</span>
              <strong className="mono">{AUDREN.elfBytes.toLocaleString()} B · sBPFv3</strong>
            </div>
            <div className={styles.heroMetaCell}>
              <span>On-Chain IDL &amp; Pool Capacity</span>
              <strong className="mono">
                <a href={explorerAddress(AUDREN.programId, 'idl')} target="_blank" rel="noreferrer">
                  Codama 1.8.0 · 4²⁰ Notes <ArrowUpRight size={11} />
                </a>
              </strong>
            </div>
          </div>
        </section>

        {/* INTERACTIVE MEMOPAGE SOA MEMORY MAP */}
        <section className={`container ${styles.section}`}>
          <div className={styles.sectionIntro}>
            <div>
              <h2>Structure-of-Arrays MemoPage (10,144 B) &amp; CompactWalletStore</h2>
            </div>
            <p>
              Every on-chain account fits strictly below Solana’s 10,240 B CPI allocation cap with zero{' '}
              <code>realloc</code>. Wallets fetch sequential <code>SubtreePage</code> (8,256 B),{' '}
              <code>MemoPage</code> (10,144 B), and <code>NullifierPage</code> (9,664 B, 600 × 16 B
              prefixes) via ordinary <code>getMultipleAccounts</code>, verify every decrypted memo
              against <code>SubtreePage</code>, freeze 12 intra-subtree siblings on sealed pages,
              and discard raw pages permanently (<strong>1.28 MB</strong> local store at 10M pool
              notes).
            </p>
          </div>

          <div className={styles.diagramStagePaper}>
            <div className={styles.stageHead}>
              <strong>Interactive MemoPage byte layout — click any region to inspect</strong>
              <span>Green highlight = 2-byte view_tags + X25519 ephemeral_pks (112 notes/page)</span>
            </div>

            <div className={styles.soaBar} role="tablist" aria-label="MemoPage memory slices">
              {MEMO_PAGE_MAP.map((seg, idx) => (
                <button
                  key={seg.field}
                  type="button"
                  role="tab"
                  aria-selected={activeSlice === idx}
                  onClick={() => setActiveSlice(idx)}
                  className={styles.soaSeg}
                  style={{
                    flex: seg.weight,
                    background: seg.bg,
                    color: seg.color,
                    outline: activeSlice === idx ? '2px solid #c83e2b' : 'none',
                    outlineOffset: '-2px',
                  }}
                >
                  <span>{seg.short}</span>
                  <small>{seg.bytes}</small>
                </button>
              ))}
            </div>

            <div className={styles.soaDetail}>
              <code>
                [{slice.offset}] · {slice.bytes}
              </code>
              <div>
                <strong style={{ marginRight: 8 }}>{slice.field}</strong>
                <span style={{ color: '#464a40' }}>{slice.desc}</span>
              </div>
              <span
                className="mono"
                style={{
                  fontSize: 10.5,
                  color: slice.inScan ? '#184433' : '#6a6d62',
                  fontWeight: 600,
                }}
              >
                {slice.inScan ? 'FAST VIEW-TAG FILTER' : 'HEADER / AEAD PAYLOAD'}
              </span>
            </div>
          </div>
        </section>

        {/* MEASURED COMPUTE UNITS BAR CHART */}
        <section className={styles.sectionAlt}>
          <div className="container">
            <div className={styles.sectionIntro}>
              <div>
                <h2>Measured sBPFv3 Compute Units</h2>
              </div>
              <p>
                Measured directly against the compiled {AUDREN.elfBytes.toLocaleString()}-byte
                sBPFv3 ELF using native Solana <code>sol_poseidon</code> and{' '}
                <code>alt_bn128</code> pairing syscalls over Solana Transaction v1 (
                <code>0x81</code>).
              </p>
            </div>

            <div className={styles.diagramStagePaper}>
              <div className={styles.stageHead}>
                <strong>CU consumption vs. 1,400,000 CU Solana transaction cap</strong>
                <span>ExecViaEscrow leaves &gt;1.2M CU for external DeFi CPI</span>
              </div>
              <div className={styles.cuList}>
                {MEASURED_CU_ROWS.map((row) => {
                  const pct = Math.max(2, Math.min(100, (row.cu / MAX_TX_CU) * 100))
                  return (
                    <div key={row.ix} className={styles.cuRow}>
                      <span className={styles.cuName}>{row.ix}</span>
                      <div className={styles.cuTrack} aria-label={`${row.ix}: ${row.cu.toLocaleString()} CU`}>
                        <div
                          className={`${styles.cuFill} ${pct > 65 ? styles.cuFillHigh : ''}`}
                          style={{ width: `${pct.toFixed(1)}%` }}
                        />
                      </div>
                      <span className={styles.cuVal}>{row.cu.toLocaleString()} CU</span>
                      <span className={styles.cuNote}>{row.note}</span>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        </section>

        {/* 9 INSTRUCTIONS & FROZEN CIRCUIT SPEC */}
        <section className={`container ${styles.section}`}>
          <div className={styles.sectionIntro}>
            <div>
              <h2>9 Instructions &amp; Frozen JoinSplit4AryCircuit</h2>
            </div>
            <p>
              All 9 instructions settle in a single Solana Transaction v1 (<code>0x81</code>) with
              no multi-tx upload buffers. One frozen <code>vk_id = 0</code> circuit
              covers private transfers, public exits, atomic WSOL unwrap, and protocol-agnostic DeFi
              CPIs while scaling monotonically across 4 → 8 → 16 append lanes.
            </p>
          </div>

          <div className={styles.tableWrap} style={{ marginBottom: 32 }}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>Tag</th>
                  <th>Instruction</th>
                  <th>Behavior &amp; Invariants</th>
                </tr>
              </thead>
              <tbody>
                {INSTRUCTIONS.map((ix) => (
                  <tr key={ix.tag}>
                    <td><code>{ix.tag}</code></td>
                    <td><code>{ix.name}</code></td>
                    <td>{ix.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>Gadget</th>
                  <th>Property</th>
                  <th>Constraint Specification (BN254 Fr · Circom Poseidon)</th>
                </tr>
              </thead>
              <tbody>
                {CIRCUIT_CONSTRAINTS.map((eq) => (
                  <tr key={eq.id}>
                    <td><code>{eq.id}</code></td>
                    <td>{eq.label}</td>
                    <td><code>{eq.formula}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* PRIVACY SCOPE, TRUSTED SETUP & SECURITY BOUNDARIES */}
        <section className={styles.sectionAlt}>
          <div className="container">
            <div className={styles.sectionIntro}>
              <div>
                <h2>Privacy scope, ceremony provenance &amp; security boundaries.</h2>
              </div>
              <p>
                Cryptographic unlinkability, provider metadata visibility, custody controls, and
                independent review are distinct properties evaluated separately.
              </p>
            </div>

            <div className={styles.ledger2}>
              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>BOUNDARIES</span>
                <h3>Public entry/exit &amp; effective anonymity</h3>
                <ul className={styles.dashList}>
                  <li>
                    Public deposits, public withdrawals, external DeFi CPI legs (
                    <code>ExecViaEscrow</code>), and stateful positions opened by deterministic
                    session wallets (<code>Bᵢ</code> via{' '}
                    <code>HKDF-SHA256(&quot;audren/v2/defi_session&quot;)</code>) remain public on
                    Solana.
                  </li>
                  <li>
                    <code>JoinSplit</code> supports both padded 2-nullifier mode (hides 1-in vs
                    2-in arity) and economic 1-nullifier mode (<code>omit_nf1 = true</code>, saves
                    1 permanent NullifierPDA rent while exposing 1-input count).
                  </li>
                  <li>
                    More TVL alone does not guarantee more privacy; timing, public amounts, and
                    network correlation still narrow effective anonymity.
                  </li>
                </ul>
                <div className={styles.cellFoot}>
                  <Link href="/privacy" className={styles.textLink}>
                    Provider metadata notice <ArrowRight size={13} />
                  </Link>
                </div>
              </article>

              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>CUSTODY &amp; CEREMONY</span>
                <h3>Pause escape hatch, MPC setup &amp; pre-audit status</h3>
                <ul className={styles.dashList}>
                  <li>
                    <strong>Non-custodial pause bypass:</strong> <code>SetPaused</code> halts new
                    deposits, private transfers, DeFi CPIs, and partial exits, while full 100%
                    withdrawals (<code>output_mask == 0</code>, including WSOL unwrap) bypass the
                    pause check.
                  </li>
                  <li>
                    <strong>Trusted setup provenance:</strong> Current builds embed{' '}
                    <code>DEV_DETERMINISTIC_VK</code> for local testing and Devnet. Mainnet
                    deployment requires replacing <code>vk_generated.rs</code> with a public
                    Phase-2 MPC ceremony artifact and completing an independent audit.
                  </li>
                  <li>
                    <strong>Upgrade authority &amp; issuers:</strong> The BPF upgrade authority
                    remains mutable during pre-audit releases, and token issuers retain mint-level
                    controls (freeze authority, transfer-hook rules).
                  </li>
                </ul>
              </article>

              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>SCALING &amp; DISCLOSURE</span>
                <h3>4 → 8 → 16 append lanes &amp; two-mode compliance</h3>
                <ul className={styles.dashList}>
                  <li>
                    Pools launch with 4 active lanes (<code>~48M CU/slot</code> aggregate lane
                    ceiling) and expand monotonically to 8 or 16 lanes via <code>InitLane</code>{' '}
                    with zero circuit changes and zero migration of existing notes.
                  </li>
                  <li>
                    Mode 1 <code>SelectiveDisclosureProof</code> verifies one note against{' '}
                    <code>SubtreePage</code> in 1 Poseidon5 hash with zero keys disclosed.
                  </li>
                  <li>
                    Mode 2 <code>FullViewingKey</code> (<code>spend_pk, nk, view_sk, view_pk</code>)
                    tracks both incoming notes AND outgoing spent nullifiers with zero spend
                    authority.
                  </li>
                </ul>
              </article>

              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>RELAY CONTRACT</span>
                <h3>Three-mode pluggable privacy relay</h3>
                <ul className={styles.dashList}>
                  <li>
                    Clients submit directly through any Solana RPC or via{' '}
                    <code>{AUDREN.relayUrl}</code> / a self-hosted relay supporting rotating
                    fee-payer pools (<code>&gt;= active_lanes</code> signers).
                  </li>
                  <li>
                    Supports Mode 1 shielded <code>cm2</code> transfer fees verified via read-only
                    relayer FVK, Mode 2 public withdraw fees, and Mode 3 <code>ExecViaEscrow</code>{' '}
                    input/output fees (<code>EXEC_FLAG_FEE_ON_OUTPUT</code>).
                  </li>
                  <li>
                    Relayers hold zero user spend keys and cannot alter <code>ctx_hash</code>-bound
                    outputs or router accounts.
                  </li>
                </ul>
                <div className={styles.cellFoot}>
                  <a href={`${AUDREN.relayUrl}/v1/info`} target="_blank" rel="noreferrer" className={styles.textLink}>
                    Inspect relay /v1/info <ArrowUpRight size={13} />
                  </a>
                </div>
              </article>
            </div>
          </div>
        </section>

        {/* CLOSING */}
        <section className={styles.closing}>
          <div className={`container ${styles.closingInner}`}>
            <div>
              <h2>Ready to integrate?</h2>
              <p>
                Start with our Rust, TypeScript (+ WASM prover), Swift (iOS), or Kotlin (Android)
                SDK — all four verified byte-for-byte against <code>spec/test-vectors.json</code>.
              </p>
            </div>
            <div className={styles.closingActions}>
              <Link href="/developers" className="btn-paper">
                Developer guide
              </Link>
              <Link href="/demo" className={styles.closingLink}>
                Open the live app <ArrowRight size={15} />
              </Link>
            </div>
          </div>
        </section>
      </main>

      <SiteFooter current="architecture" />
    </div>
  )
}
