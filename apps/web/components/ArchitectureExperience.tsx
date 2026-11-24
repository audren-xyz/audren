'use client'

import { useState, type CSSProperties } from 'react'
import Link from 'next/link'
import { ArrowLeft, ArrowRight, ArrowUpRight } from 'lucide-react'
import { SiteHeader } from '@/components/SiteHeader'
import { SiteFooter } from '@/components/SiteFooter'
import { AUDREN, MEASURED_CU_ROWS, explorerAddress, solscanAddress } from '@/lib/protocol'
import styles from '@/components/SubpageShell.module.css'
import { MemoFetchModes } from '@/components/motion/MemoFetchModes'
import { useHydrated, useInView } from '@/components/motion/hooks'

const INSTRUCTIONS = [
  {
    tag: '0x00',
    name: 'InitPool',
    summary:
      'Create PoolState (128 B, audren_pool) and inline GlobalRootHistory (10,216 B, audren_roots, AUD1RT01) with immutable root_epoch_interval (default 32 slots, max 256) and canonical vault_auth PDA bump (10,433 CU measured, 45k budget).',
  },
  {
    tag: '0x01',
    name: 'InitLane',
    summary:
      'Authority-signed lane initializer that activates one lane at a time (4 at launch, expanding monotonically to 8 or 16), creating LaneTreeState (1,824 B), LaneRentVault, and seq-0 SubtreePage/SubtreeRootPage/MemoPage/NullifierPage PDAs (36,665 CU measured, 75k budget).',
  },
  {
    tag: '0x02',
    name: 'OpenPage',
    summary:
      'Idempotent, permissionless page opener for SubtreePage (8,256 B), SubtreeRootPage (9,664 B), MemoPage (10,240 B), or NullifierPage (9,664 B) reimbursed deterministically from LaneRentVault (13,514 CU measured, 40k budget). Auto-prepended inline by wallets and relayers for true zero-crank operation.',
  },
  {
    tag: '0x03',
    name: 'Deposit',
    summary:
      'Unified entry for Native SOL (atomic SyncNative wrap into canonical WSOL vault ATA with optional DEPOSIT_FLAG_FEE_FROM_AMOUNT zero-dust sweep), Classic SPL, and Token-2022 (53,971–55,590 CU measured, 75k budget; Token-2022 Fee+Hook 67,117 CU / 140k budget; 0 ZK proof). Commits measured net vault balance delta, updates the lane 4-ary frontier and write-locked inline GlobalRootHistory super_root (~160–222 deposits/slot, ~400–555 TPS at 400ms slots under Solana’s 12M CU/slot writable-account cap; ~400ms confirmation today, ~150ms under Alpenglow), and appends a 106 B SoA memo.',
  },
  {
    tag: '0x04',
    name: 'InitRootHistory',
    summary:
      'One-shot initializer creating canonical GlobalRootHistory (AUD1RT01, 10,216 B PDA, 249YJTuRtiKAnh346Tc18kF9bHrktdrTzyJMtvUKUgC7) across all active lanes (17,169 CU measured for 4 lanes, 41,755 CU for 16 lanes, 75k budget). Its dual ring (128-entry recent slot_ring holding 64–128 active slots / ~13.8s–27.5s under saturation + 89-entry stable epoch_ring holding >= 2,848 slots / >= 10.2m with zero idle wall-clock expiry) updates inline on every note-appending deposit and spend with zero external cranks.',
  },
  {
    tag: '0x05',
    name: 'Transact',
    summary:
      '192 B BN254 Groth16 2-in/3-out spend across the global 4^20 MASP proving against GlobalRootHistory. Pause-immune full exits (output_mask == 0, read-only roots, zero global write-lock contention) take 115,691–121,091 CU (165k budget); SPL / WSOL unwrap withdrawals take 144,813–217,442 CU (255k budget; Token-2022 + Hook 2in/3out 231,828 CU / 295k budget); private 2-in/3-out transfers with inline GlobalRootHistory write-lock updates take 204,906 CU (235k budget, sustaining ~51–58 private transfers/slot or ~127–145 TPS at 400ms slots under Solana’s 12M CU/slot per-writable-account ceiling).',
  },
  {
    tag: '0x06',
    name: 'ExecViaEscrow',
    summary:
      'Protocol-agnostic 1-tx SPL & Token-2022 shielded DeFi CPI (164,563–237,889 CU across 1in/0chg to 2in/2chg+fee 30-acc mocks, 285k base budget + router CPI, leaving >1.11M CU for DeFi) through 16 sharded audren_escrow PDAs with inline GlobalRootHistory update, canonical ATA enforcement, WatchedEscrowBuf firewall, ctx_hash-bound router_accounts, input or output relayer fees (EXEC_FLAG_FEE_ON_OUTPUT), and 72 B XOR-masked AUD1DYN1 dynamic output memos.',
  },
  {
    tag: '0x07',
    name: 'SetPaused',
    summary:
      'Emergency authority circuit breaker halting deposits, private transfers, DeFi CPIs, and partial exits while preserving permissionless full withdrawals (output_mask == 0, read-only GlobalRootHistory, including atomic WSOL unwrap).',
  },
  {
    tag: '0x08',
    name: 'UpdatePool',
    summary:
      'Authority-signed governance instruction supporting rent-fee cap updates (note_rent_fee, nf_rent_fee; root_epoch_interval stays immutable after initialization), 2-step authority transfer via pending_authority, and permanent authority renouncement (forbidden while paused).',
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
    formula: '20 levels × Poseidon4(c0, c1, c2, c3) == GlobalRootHistory.super_root  (4²⁰ = 1.099T notes)',
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
    inScan: true,
    bg: '#ebe7dc',
    color: '#2b2d26',
    desc: 'AUD1MM01 magic, lane_id, bump, count (0..=96), pool_id, page_seq, created_slot, closed_slot (enables optional birthdaySlot skipping during cold wallet recovery).',
  },
  {
    offset: '64..256',
    bytes: '192 B',
    weight: 14,
    short: 'view_tags',
    field: 'view_tags[96] (2 B each)',
    inScan: true,
    bg: '#184433',
    color: '#f4f1ea',
    desc: '16-bit view tag rejects 65,535 / 65,536 non-owned notes locally before AEAD decryption and is bound into the 34 B AEAD AAD.',
  },
  {
    offset: '256..3,328',
    bytes: '3,072 B',
    weight: 30,
    short: 'ephemeral_pks',
    field: 'ephemeral_pks[96] (32 B each)',
    inScan: true,
    bg: '#255a44',
    color: '#f4f1ea',
    desc: 'X25519 ephemeral public keys (low-order points rejected) bound with view_tag as 34 B AEAD AAD; included with header and view_tags in the opt-in 3,328 B fast-mode dataSlice.',
  },
  {
    offset: '3,328..10,240',
    bytes: '6,912 B',
    weight: 48,
    short: 'ciphertexts',
    field: 'ciphertexts[96] (72 B each)',
    inScan: false,
    bg: '#e8efe8',
    color: '#1b2b22',
    desc: 'ChaCha20-Poly1305 AEAD ciphertext over 56 B versioned plaintext (amount_u64 || mint_32 || ver || flags || payment_id_14) + 16 B tag with 34 B AAD (or 72 B XOR-masked AUD1DYN1 swap memo). Fetched in full in default strict mode; deferred until view-tag hit only in opt-in fast mode (> 25 pages) over self-hosted or trusted RPCs.',
  },
] as const

const MAX_TX_CU = 1_400_000

export function ArchitectureExperience() {
  const [activeSlice, setActiveSlice] = useState<number>(1)
  const [cuRef, cuInView] = useInView<HTMLDivElement>()
  const hydrated = useHydrated()
  const [cuSeen, setCuSeen] = useState(false)
  if (cuInView && !cuSeen) setCuSeen(true)
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
            <h1>Audren cryptographic and on-chain specification</h1>
            <p className={styles.heroLead}>
              Minimal frozen BN254 Groth16 circuit ({AUDREN.circuitConstraints.toLocaleString()}{' '}
              R1CS, 3.93 MB proving key, 4-ary Depth-20 global MASP), 9 instructions, fixed ≤10
              KiB zero-realloc accounts, 2-pass ordinary-RPC <code>CompactWalletStore</code>, and
              measured sBPFv3 Compute Units in{' '}
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
              <span>Program ID ({AUDREN.deployedReleaseTag})</span>
              <span className={`${styles.heroMetaValue} mono`}>
                <a href={solscanAddress(AUDREN.programId)} target="_blank" rel="noreferrer">
                  {AUDREN.programId.slice(0, 10)}…{AUDREN.programId.slice(-6)} <ArrowUpRight size={11} />
                </a>
              </span>
            </div>
            <div className={styles.heroMetaCell}>
              <span>Frozen circuit</span>
              <span className={`${styles.heroMetaValue} mono`}>
                {AUDREN.circuitConstraints.toLocaleString()} R1CS · {AUDREN.proofBytes} B Groth16
              </span>
            </div>
            <div className={styles.heroMetaCell}>
              <span>Compiled ELF ({AUDREN.releaseTag})</span>
              <span className={`${styles.heroMetaValue} mono`}>
                {AUDREN.sourceElfBytes.toLocaleString()} B · sBPFv3
              </span>
            </div>
            <div className={styles.heroMetaCell}>
              <span>On-chain IDL &amp; capacity</span>
              <span className={`${styles.heroMetaValue} mono`}>
                <a href={explorerAddress(AUDREN.programId, 'idl')} target="_blank" rel="noreferrer">
                  Codama 1.8.0 · 4²⁰ Notes <ArrowUpRight size={11} />
                </a>
              </span>
            </div>
          </div>
        </section>

        {/* INTERACTIVE MEMOPAGE SOA MEMORY MAP */}
        <section className={`container ${styles.section}`}>
          <div className={styles.sectionIntro}>
            <div>
              <h2>Structure-of-Arrays MemoPage and CompactWalletStore</h2>
            </div>
            <p>
              Every on-chain account fits within Solana’s 10,240 B CPI allocation cap with zero{' '}
              <code>realloc</code>. <code>CompactWalletStore</code> runs a 2-pass sync over ordinary{' '}
              <code>getMultipleAccounts</code>: in default <code>strict</code> privacy mode, Pass 1
              ingests <code>SubtreeRootPage</code> (9,664 B, 300 sealed roots), fetches full 10,240
              B <code>MemoPage</code>s (96 notes/page) in uniform batches (with uniform newly-synced{' '}
              <code>SubtreePage</code> fetches on incremental syncs of 25 pages or fewer, and
              deterministic wallet-keyed decoy-padded <code>SubtreePage</code> batches on larger
              catch-up and witness reconstruction) so the RPC cannot tell which memo is yours and the
              tree page you need hides among decoys; Pass
              2 always streams <code>NullifierPage</code>s (9,664 B, 600 × 16 B prefixes)
              unconditionally to lane head without early-exit, matching only owned unspent notes and
              discarding stranger prefixes permanently (
              <span style={{ fontWeight: 500, color: '#161614' }}>~1.28 MB</span> kept locally at 10M
              pool notes, though a cold sync still downloads every memo and nullifier page). Opt-in <code>fast</code> mode enables 3,328 B SoA <code>dataSlice</code>{' '}
              scanning (<code>[0..3,328]</code>) on large historical catch-up (&gt;25 pages) for
              self-hosted or trusted RPCs, trading RPC hit-visibility for lower bandwidth.
            </p>
          </div>

          <div className={styles.diagramStagePaper}>
            <div className={styles.stageHead}>
              <div className={styles.stageTitle}>
                Interactive MemoPage byte layout (10,240 B; click any region to inspect)
              </div>
              <span>
                Default strict mode fetches full 10,240 B uniformly; opt-in fast mode (&gt;25 pages)
                uses dataSlice [0..3,328] on trusted RPCs
              </span>
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
                <span style={{ marginRight: 8, fontWeight: 500, color: '#161614' }}>
                  {slice.field}
                </span>
                <span style={{ color: '#464a40' }}>{slice.desc}</span>
              </div>
              <span
                style={{
                  fontSize: 12.5,
                  color: slice.inScan ? '#184433' : '#5f6257',
                  fontWeight: 500,
                }}
              >
                {slice.inScan
                  ? 'Full in strict mode · in 3,328 B fast dataSlice'
                  : 'Full in strict mode · on hit in opt-in fast mode'}
              </span>
            </div>

            <MemoFetchModes />
          </div>
        </section>

        {/* MEASURED COMPUTE UNITS BAR CHART */}
        <section className={styles.sectionAlt}>
          <div className="container">
            <div className={styles.sectionIntro}>
              <div>
                <h2>Measured sBPFv3 compute units</h2>
              </div>
              <p>
                Measured in the LiteSVM end-to-end suite against the compiled{' '}
                {AUDREN.sourceElfBytes.toLocaleString()}-byte {AUDREN.releaseTag} sBPFv3 ELF, using native Solana <code>sol_poseidon</code> and{' '}
                <code>alt_bn128</code> pairing syscalls over Solana Transaction v1 (
                <code>0x81</code>).
              </p>
            </div>

            <div className={styles.diagramStagePaper}>
              <div className={styles.stageHead}>
                <div className={styles.stageTitle}>
                  Empirical CU consumption and tight CU limits vs. 1,400,000 CU Solana cap
                </div>
                <span>ExecViaEscrow leaves &gt;1.11M CU for external DeFi CPI</span>
              </div>
              <div ref={cuRef} className={styles.cuList} data-inview={!hydrated || cuSeen ? 'true' : 'false'}>
                {MEASURED_CU_ROWS.map((row, rowIdx) => {
                  const pct = Math.max(2, Math.min(100, (row.maxCu / MAX_TX_CU) * 100))
                  const measuredText =
                    row.cu === row.maxCu
                      ? `${(row.cu / 1000).toFixed(1)}k`
                      : `${(row.cu / 1000).toFixed(1)}k–${(row.maxCu / 1000).toFixed(1)}k`
                  return (
                    <div key={row.ix} className={styles.cuRow}>
                      <span className={styles.cuName}>{row.ix}</span>
                      <div
                        className={styles.cuTrack}
                        aria-label={`${row.ix}: ${row.cu.toLocaleString()} to ${row.maxCu.toLocaleString()} CU measured, ${row.budgetCu.toLocaleString()} CU budget`}
                      >
                        <div
                          className={`${styles.cuFill} ${pct > 65 ? styles.cuFillHigh : ''}`}
                          style={{ '--cu': (pct / 100).toFixed(3), '--i': rowIdx } as CSSProperties}
                        />
                      </div>
                      <span className={styles.cuVal}>
                        {measuredText} CU · {Math.round(row.budgetCu / 1000)}k req
                      </span>
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
              <h2>Nine instructions and the frozen JoinSplit4AryCircuit</h2>
            </div>
            <p>
              Every instruction settles in one transaction with no multi-tx upload buffers: relays
              submit Solana Transaction v1 (<code>0x81</code>, 4,096 B), and direct wallet
              submission uses v0 (1,232 B), where very large swap routes or merge batches need a
              relay. One frozen <code>vk_id = 0</code> circuit (3.93 MB
              compressed proving key, 2<sup>15</sup> FFT domain) covers private transfers, public
              exits, atomic WSOL unwrap, and protocol-agnostic DeFi CPIs while scaling monotonically
              across 4 → 8 → 16 append lanes.
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
                <h2>Privacy scope, ceremony provenance, and security boundaries.</h2>
              </div>
              <p>
                Cryptographic unlinkability, provider metadata visibility, custody controls, and
                independent review are distinct properties evaluated separately.
              </p>
            </div>

            <div className={styles.ledger2}>
              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>Boundaries</span>
                <h3>Public entry, exit, and effective anonymity</h3>
                <ul className={styles.dashList}>
                  <li>
                    Public deposits, public withdrawals, external DeFi CPI legs (
                    <code>ExecViaEscrow</code>), and stateful positions opened by deterministic
                    session wallets (<code>Bᵢ</code> via{' '}
                    <code>HKDF-SHA256(&quot;audren/v1/defi_session&quot;)</code>) remain public on
                    Solana.
                  </li>
                  <li>
                    Private transfers default to uniform padded shape (2 nullifiers,{' '}
                    <code>output_mask = 0b111</code>, randomized append lane, automatic 2-input
                    coin selection, and up to 4 parallel 2 → 1 private <code>Transact</code> merges
                    per Solana Transaction v1); opt-in <code>omit_nf1 = true</code> economy mode
                    saves 1 permanent <code>NullifierPDA</code> rent while exposing 1-input arity.
                  </li>
                  <li>
                    Each spend&rsquo;s fee payer (your wallet or a sponsoring relay) pays permanent{' '}
                    <code>NullifierPDA</code> plus amortized page rent
                    (~0.0007–0.0036 SOL/tx at current rent) instead of relying on a permissioned
                    Forester; on-chain{' '}
                    <code>rent_minimum_balance</code> reads <code>SysvarRent</code> dynamically so
                    cost scales down automatically if Solana lowers rent.
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
                <span className={styles.cellIndex}>Custody and ceremony</span>
                <h3>Pause escape hatch, ceremony setup, and pre-audit status</h3>
                <ul className={styles.dashList}>
                  <li>
                    <span style={{ fontWeight: 500, color: '#161614' }}>
                      Non-custodial pause bypass:
                    </span>{' '}
                    <code>SetPaused</code> halts new deposits, private transfers, DeFi CPIs, and
                    partial exits, while full 100% withdrawals (<code>output_mask == 0</code>,
                    including WSOL unwrap) bypass the pause check.
                  </li>
                  <li>
                    <span style={{ fontWeight: 500, color: '#161614' }}>
                      Trusted setup provenance:
                    </span>{' '}
                    Phase 1 uses the Hermez Perpetual Powers of Tau (
                    <code>powersOfTau28_hez_final_15.ptau</code>, 54 public contributions plus a
                    beacon). Phase 2 applies two BGM17 contributions, both generated by the Audren
                    release environment, plus a live drand Quicknet (<code>#34194203</code>) and
                    Solana Mainnet slot <code>472705896</code> blockhash beacon (
                    <code>ceremony/transcript.json</code>). The transcript is verifiable, but no
                    one outside can verify that the contribution secrets were destroyed, so until an
                    independent contributor joins, soundness relies on Audren. A new contribution
                    protects the live pool only after a program upgrade adopts its verifying key.
                  </li>
                  <li>
                    <span style={{ fontWeight: 500, color: '#161614' }}>
                      Upgrade authority and issuers:
                    </span>{' '}
                    The BPF upgrade authority remains mutable during pre-audit releases and, like
                    the Pool #0 authority, is held by one operator key (
                    <code>3WzAUV…67bV</code>), not a multisig. Token issuers retain mint-level
                    controls (freeze authority, permanent delegate, pausable mint, upgradable
                    transfer hook) over the shared vault account.
                  </li>
                </ul>
              </article>

              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>Scaling and disclosure</span>
                <h3>Append lane scaling and two-mode compliance</h3>
                <ul className={styles.dashList}>
                  <li>
                    Every note-appending write (<code>Deposit</code>, <code>Transact</code> with
                    outputs, and <code>ExecViaEscrow</code>) write-locks the single{' '}
                    <code>GlobalRootHistory</code> PDA (<code>accounts[2]</code>) for instant inline
                    root updates (bounded by Solana’s 12M CU/slot per-writable-account ceiling:
                    ~51–58 private transfers/slot or ~127–145 TPS, and ~160–222 deposits/slot or
                    ~400–555 TPS at 400ms slots). Pools launch with 4 active lanes and expand
                    monotonically to 8 or 16 lanes via <code>InitLane</code> with zero circuit
                    changes and zero migration of existing notes, scaling global tree capacity to
                    4<sup>20</sup> (1.099T notes), isolating per-lane page rollovers (enabling
                    4-merge Tx v1 batches across distinct lanes), and parallelizing read-only Full
                    Exits (<code>output_mask == 0</code>, which lock <code>GlobalRootHistory</code>{' '}
                    read-only).
                  </li>
                  <li>
                    Mode 1 <code>SelectiveDisclosureProof</code> verifies one note against{' '}
                    <code>SubtreePage</code> in 1 Poseidon5 hash with zero keys disclosed.
                  </li>
                  <li>
                    Mode 2 <code>FullViewingKey</code> (<code>spend_pk, nk, view_sk, view_pk</code>)
                    tracks both incoming notes and outgoing spent nullifiers with zero spend
                    authority.
                  </li>
                </ul>
              </article>

              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>Relay contract</span>
                <h3>Three-mode pluggable privacy relay</h3>
                <ul className={styles.dashList}>
                  <li>
                    Clients submit directly through any Solana RPC or via{' '}
                    <code>{AUDREN.relayUrl}</code> / a self-hosted relay, which can rotate a pool of
                    fee-payer keys (one key on the hosted relay today).
                  </li>
                  <li>
                    Can charge private-transfer fees as a shielded <code>cm2</code> note (flat per-mint quotes
                    defaulting to 2-nullifier spends with zero plaintext transfer amount sent to the
                    relayer, verified via read-only FVK, plus up to 4 parallel 2 → 1 private{' '}
                    <code>Transact</code> merges per Transaction v1), Mode 2 public withdraw fees,
                    and Mode 3 <code>ExecViaEscrow</code> input/output fees (
                    <code>EXEC_FLAG_FEE_ON_OUTPUT</code>) over random escrow shards. The hosted relay
                    currently sponsors private transfers with no fee note.
                  </li>
                  <li>
                    True zero-crank architecture: inline <code>GlobalRootHistory</code> (
                    <code>AUD1RT01</code>, 10,216 B PDA) updates on every deposit and spend with
                    zero checkpoint requests, zero checkpoint cranks, and zero checkpoint fees,
                    while relayers and direct wallets auto-prepend idempotent <code>OpenPage</code>{' '}
                    instructions subsidized by <code>LaneRentVault</code>. Rate limits use an
                    ephemeral daily secret IP-hash salt never stored alongside nullifiers, and
                    relayers hold zero spend keys and cannot alter <code>ctx_hash</code>-bound
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
              <h2>Start integrating with the Audren SDKs.</h2>
              <p>
                Start with our Rust, TypeScript (+ WASM prover), Swift (iOS), or Kotlin (Android)
                SDK, all four verified byte-for-byte against <code>spec/test-vectors.json</code>.
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
