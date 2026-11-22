'use client'

import { useState } from 'react'
import Link from 'next/link'
import { ArrowLeft, ArrowRight, ArrowUpRight } from 'lucide-react'
import { SiteHeader } from '@/components/SiteHeader'
import { SiteFooter } from '@/components/SiteFooter'
import { AUDREN, MEASURED_CU_ROWS, explorerAddress, solscanAddress } from '@/lib/protocol'
import styles from '@/components/SubpageShell.module.css'

const INSTRUCTIONS = [
  { tag: '0x00', name: 'InitPool', summary: 'Create PoolState (192 B), EpochPage #0 (6,240 B < 10 KiB CPI cap), sol_vault, and page_rent_vault.' },
  { tag: '0x01', name: 'OpenPage', summary: 'Permissionless rollover sealing current Lane 0 EpochPage and opening page_id + 1 funded by PageRentVault via live Rent::get().' },
  { tag: '0x02', name: 'Deposit', summary: 'Shield Native SOL, Classic SPL, or transferable Token-2022 directly to any Audren stealth address (commits exact net_received delta; DEPOSIT_FLAG_FEE_FROM_AMOUNT deducts rent contribution from deposit for 0-dust session sweeps; zero ZK proof required; PoolState stays read-only on parallel lanes 1..15).' },
  { tag: '0x03', name: 'Transfer', summary: 'Private multi-asset 1-in → 2-out transfer: Triptych (m=5/6/7 with strong Fiat-Shamir ring_root + prefix_counts), CrossBase2 (256 B, unlinkable asset tags), native Solana Bulletproof U128, optional AuditorAssetProof. Fits directly in a single Solana v1 transaction (4,096 B).' },
  { tag: '0x04', name: 'Merge', summary: 'Consolidate two same-asset shielded notes via 2 Triptych proofs (combined cap 128 ring slots) + CrossBase1 (128 B) + native Solana Bulletproof U64.' },
  { tag: '0x05', name: 'ExecViaEscrow', summary: 'Protocol-agnostic 1-tx shielded DeFi CPI (DEX swaps, lending supply, yield vaults, LSTs, perp LP, RWAs) through 16 sharded swap_escrow PDAs into any compatible Token A → Token B Solana program, with native relayer_fee (input or output mint, flags & 4), optional shielded change (flags & 1), and partial-fill refund (flags & 2) in one Solana v1 transaction (4,096 B).' },
  { tag: '0x06', name: 'Withdraw', summary: 'Unshield exact amount to any wallet/ATA or deterministic DeFi Session keypair with optional native relayer_fee, atomic WSOL → Native SOL unwrap via ephemeral audren_unwrap PDA (flags & 4), and optional shielded change (flags & 2). Full withdrawals (has_change = false, including unwrap_wsol) keep PoolState read-only and bypass pool pause.' },
  { tag: '0x07', name: 'SetPaused', summary: 'Emergency authority circuit breaker for deposits, transfers, merges, ExecViaEscrow, and partial withdrawals — never blocks full 100% withdrawals (including unwrap_wsol) and never grants vault custody.' },
  { tag: '0x08', name: 'WriteProofBuffer', summary: 'Optional chunked upload into an ephemeral ProofBuffer PDA tracked via u16 bitmask for standard wallet v0 (1,232 B) signing or oversized multi-hop DeFi CPIs.' },
  { tag: '0x09', name: 'ExecBuffered', summary: 'Zero-copy execute Transfer, Merge, ExecViaEscrow, or Withdraw from a completed ProofBuffer and atomically refund 100% of buffer rent to payer.' },
  { tag: '0x0A', name: 'CloseProofBuffer', summary: 'Reclaim 100% of rent lamports from an abandoned or interrupted ProofBuffer back to its authority.' },
  { tag: '0x0B', name: 'InitLane', summary: 'Authority-signed parallel lane initializer enabling parallel append lanes 1..15 inside an existing pool (page_id = (lane_id << 56) | seq) sharing one unified vault & nullifier namespace.' },
  { tag: '0x0C', name: 'OpenLanePage', summary: 'Permissionless rollover for parallel append lanes 1..15 funded by per-lane LaneRentVault while keeping PoolState strictly read-only.' },
] as const

const TRIPTYCH_EQS = [
  { id: 'Eq 1', label: 'Bit linearity', formula: 'A + ξ·B − Σ fⱼ·Hⱼ − z_A·H = 0' },
  { id: 'Eq 2', label: 'Bit booleanity (lⱼ ∈ {0,1})', formula: 'ξ·C + D − Σ fⱼ(ξ − fⱼ)·Hⱼ − z_C·H = 0' },
  { id: 'Eq 3', label: 'Stealth ownership (Pₗ = x·G)', formula: 'Σ pₖ(ξ)·Pₖ − Σ ξʲ·Xⱼ − z_x·G = 0' },
  { id: 'Eq 4', label: 'Unique nullifier (x·J = U)', formula: 'ξᵐ·U − Σ ξʲ·Yⱼ − z_x·J = 0' },
  { id: 'Eq 5', label: 'Multi-asset & value balance', formula: 'Σ pₖ(ξ)·(Aₖ + α·Vₖ) − ξᵐ·(A_spend + α·V_spend) − Σ ξʲ·Wⱼ − z_q·H = 0' },
  { id: 'Eq 6', label: 'Audited ElGamal S₁ = rₛ·G', formula: 'ξᵐ·S₁ − Σ ξʲ·Tⱼ − z_aud·G = 0  (InstitutionalAudited)' },
  { id: 'Eq 7', label: 'Audited ElGamal S₂ = Pₗ + rₛ·K_aud', formula: 'ξᵐ·S₂ − Σ pₖ(ξ)·Pₖ − Σ ξʲ·Eⱼ − z_aud·K_aud = 0  (InstitutionalAudited)' },
] as const

const PAGE_MAP = [
  { offset: '0..64', bytes: '64 B', weight: 6, short: 'Hdr', field: 'PageHeader', inSlice: false, bg: '#e6e2d7', color: '#2b2d26', desc: 'AUDRNPG1 magic, version, bump, closed flag, count (0..=32), pool_id, page_id, slots.' },
  { offset: '64..96', bytes: '32 B', weight: 6, short: 'Tags', field: 'view_tags[32]', inSlice: true, bg: '#184433', color: '#f4f1ea', desc: '1-byte fast scan filter (included in RPC & WS dataSlice — rejects 255/256 non-owned notes).' },
  { offset: '96..1,120', bytes: '1,024 B', weight: 18, short: 'eph_pks', field: 'ephemeral_pks[32]', inSlice: true, bg: '#255a44', color: '#f4f1ea', desc: 'Stealth ECDH R_k points (included in dataSlice → 1,056 B total per 32-note page).' },
  { offset: '1,120..2,144', bytes: '1,024 B', weight: 17, short: 'stealth_pks', field: 'stealth_pks[32]', inSlice: false, bg: '#dfe5dc', color: '#1b2b22', desc: 'One-time spend keys P_k read zero-copy under Direct Mapping (SIMD-0460).' },
  { offset: '2,144..3,168', bytes: '1,024 B', weight: 17, short: 'asset_tags', field: 'asset_tags[32]', inSlice: false, bg: '#eaede6', color: '#1b2b22', desc: 'Re-randomized hidden asset commitments A_k = G_mint + a·H.' },
  { offset: '3,168..4,192', bytes: '1,024 B', weight: 17, short: 'commitments', field: 'commitments[32]', inSlice: false, bg: '#f1f0e8', color: '#262922', desc: 'Pedersen value commitments V_k = v·A_k + r·H.' },
  { offset: '4,192..6,240', bytes: '2,048 B', weight: 28, short: 'ciphertexts[32]', field: 'ciphertexts[32]', inSlice: false, bg: '#faf8f3', color: '#262922', desc: 'AES-256-GCM encrypted note memos (48 B payload + 16 B auth tag per note).' },
] as const

const MAX_TX_CU = 1_400_000

export function ArchitectureExperience() {
  const [activeSlice, setActiveSlice] = useState<number>(1)
  const slice = PAGE_MAP[activeSlice]

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
            <h1>Cryptographic &amp; On-Chain Specification</h1>
            <p className={styles.heroLead}>
              Exact binary layouts, Multi-Base Binary Triptych verification equations,
              Structure-of-Arrays byte offsets, and measured sBPFv3 Compute Units implemented in{' '}
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
              <span>Verified Build Hash</span>
              <strong className="mono">
                <a href={explorerAddress(AUDREN.programId, 'verified-build')} target="_blank" rel="noreferrer">
                  {AUDREN.executableHash.slice(0, 16)}… <ArrowUpRight size={11} />
                </a>
              </strong>
            </div>
            <div className={styles.heroMetaCell}>
              <span>Deployed ELF</span>
              <strong className="mono">{AUDREN.elfBytes.toLocaleString()} B · sBPFv3</strong>
            </div>
            <div className={styles.heroMetaCell}>
              <span>On-Chain IDL &amp; Heap</span>
              <strong className="mono">
                <a href={explorerAddress(AUDREN.programId, 'idl')} target="_blank" rel="noreferrer">
                  Codama 1.8.0 · 32 KiB <ArrowUpRight size={11} />
                </a>
              </strong>
            </div>
          </div>
        </section>

        {/* INTERACTIVE EPOCHPAGE SOA MEMORY MAP */}
        <section className={`container ${styles.section}`}>
          <div className={styles.sectionIntro}>
            <div>
              <h2>Structure-of-Arrays EpochPage (6,240 B)</h2>
            </div>
            <p>
              Every <code>EpochPage</code> PDA holds up to 32 notes in column-major order under
              Solana’s 10 KiB CPI cap. Wallets fetch only <code>dataSlice: 64..1,120</code>{' '}
              (1,056 B) to scan 3,200 notes across 100 pages in ~106 KB.
            </p>
          </div>

          <div className={styles.diagramStagePaper}>
            <div className={styles.stageHead}>
              <strong>Interactive byte layout — click any region to inspect</strong>
              <span>Green highlight = RPC dataSlice (offset 64, length 1,056 B)</span>
            </div>

            <div className={styles.soaBar} role="tablist" aria-label="EpochPage memory slices">
              {PAGE_MAP.map((seg, idx) => (
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
                  color: slice.inSlice ? '#184433' : '#6a6d62',
                  fontWeight: 600,
                }}
              >
                {slice.inSlice ? 'IN RPC DATASLICE' : 'ON-DEMAND / PROOF'}
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
                Measured directly on the deployed {AUDREN.elfBytes.toLocaleString()}-byte sBPFv3
                ELF with radix-29 scalar arithmetic and native Solana Ristretto255 + ZK ElGamal
                Proof syscalls against Solana’s 1.4M CU transaction limit.
              </p>
            </div>

            <div className={styles.diagramStagePaper}>
              <div className={styles.stageHead}>
                <strong>CU consumption vs. 1,400,000 CU Solana transaction cap</strong>
                <span>ExecViaEscrow leaves ~1.0M CU for external DeFi CPI</span>
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

        {/* INSTRUCTION SET & TRIPTYCH EQUATIONS */}
        <section className={`container ${styles.section}`}>
          <div className={styles.sectionIntro}>
            <div>
              <h2>13 Instructions &amp; Multi-Base Binary Triptych</h2>
            </div>
            <p>
              For ring size <code>N = 2ᵐ</code> (32 / 64 / 128 slots), Fiat-Shamir weights batch
              all verification equations into chunked 8 KiB invocations of Solana’s native{' '}
              <code>sol_curve_multiscalar_mul</code> syscall.
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
                  <th>Eq</th>
                  <th>Property</th>
                  <th>Verification Equation</th>
                </tr>
              </thead>
              <tbody>
                {TRIPTYCH_EQS.map((eq) => (
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

        {/* PRIVACY SCOPE, ACCOUNTING EVIDENCE & SECURITY BOUNDARIES */}
        <section className={styles.sectionAlt}>
          <div className="container">
            <div className={styles.sectionIntro}>
              <div>
                <h2>Privacy scope, security boundaries &amp; accounting evidence.</h2>
              </div>
              <p>
                On-chain balance and range checks, independent implementation review, and practical
                anonymity measurements are separate forms of evidence.
              </p>
            </div>

            <div className={styles.ledger2}>
              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>BOUNDARIES</span>
                <h3>Public entry/exit &amp; effective anonymity</h3>
                <ul className={styles.dashList}>
                  <li>Public deposits, withdrawals, external DeFi CPI legs (<code>ExecViaEscrow</code>), and stateful positions opened by deterministic session wallets (<code>Bᵢ</code> via <code>HKDF-SHA256(&quot;audren/v1/defi_session&quot;)</code>) are intentional public boundaries; spending proofs conceal input selection within a candidate set.</li>
                  <li>Ring sizes (32 / 64 / 128) are slot capacities, not guaranteed counts of plausible notes or independent users.</li>
                  <li>More TVL alone does not guarantee more privacy; empty slots, known records, timing, and candidate selection reduce effective anonymity.</li>
                  <li>Public vault balances show held assets; they do not independently prove that every private liability is covered.</li>
                </ul>
                <div className={styles.cellFoot}>
                  <a
                    href="https://github.com/audren-xyz/audren/blob/main/ARCHITECTURE.md#privacy-boundaries-and-effective-anonymity"
                    target="_blank"
                    rel="noreferrer"
                    className={styles.textLink}
                  >
                    Full privacy specification <ArrowUpRight size={13} />
                  </a>
                  <Link href="/privacy" className={styles.textLink}>
                    Provider metadata notice <ArrowRight size={13} />
                  </Link>
                </div>
              </article>

              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>CUSTODY &amp; UPGRADES</span>
                <h3>Pause escape hatch &amp; pre-audit status</h3>
                <ul className={styles.dashList}>
                  <li><strong>Non-custodial pause bypass:</strong> <code>SetPaused</code> halts deposits, transfers, merges, DeFi CPIs, and partial withdrawals, while full 100% withdrawals (<code>has_change = false</code>, including <code>unwrap_wsol</code>) keep <code>PoolState</code> read-only and bypass the pause check.</li>
                  <li><strong>Mutable upgrade authority:</strong> Program <code>{AUDREN.programId.slice(0, 10)}…</code> is in active pre-audit release with a mutable BPF upgrade authority. Do not treat the deployment as frozen or immutable.</li>
                  <li><strong>Issuer controls:</strong> Token issuers retain mint-level controls such as freeze authority or transfer-hook policies.</li>
                </ul>
              </article>

              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>SCALING &amp; DISCLOSURE</span>
                <h3>Parallel lanes &amp; scoped sub-accounts</h3>
                <ul className={styles.dashList}>
                  <li>Pools scale up to 16 independent append lanes (<code>page_id = (lane_id &lt;&lt; 56) | seq</code>); Lanes 1..15 keep <code>PoolState</code> read-only while sharing one vault and nullifier set.</li>
                  <li>Sealed <code>EpochPage</code> PDAs are not modified by current instructions and support immutable edge caching.</li>
                  <li>Single-note receipts disclose one commitment opening with zero spend/view keys; child sub-accounts derive isolated <code>FullViewingKey</code> streams via <code>HKDF-SHA256(&quot;audren/v1/subaccount&quot;)</code>.</li>
                </ul>
              </article>

              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>RELAY CONTRACT</span>
                <h3>Optional pluggable privacy relay</h3>
                <ul className={styles.dashList}>
                  <li>Clients can submit directly through any Solana RPC without a relayer, or submit pre-proved instructions to <code>{AUDREN.relayUrl}</code> or a self-hosted relay with the same HTTP API (<code>/v1/info</code>, <code>/v1/fee-quote</code>, <code>/v1/swap/quote</code>, <code>/v1/swap/instructions</code>, <code>/v1/relay/submit</code>).</li>
                  <li>Relayers receive zero spend or view keys and cannot alter proof-bound outputs.</li>
                  <li>Relayers observe request metadata and wrap proven instructions into Solana v1 transactions.</li>
                </ul>
                <div className={styles.cellFoot}>
                  <a href={`${AUDREN.relayUrl}/v1/info`} target="_blank" rel="noreferrer" className={styles.textLink}>
                    Inspect live relay /v1/info <ArrowUpRight size={13} />
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
                Start with our Rust, TypeScript, Swift (iOS), or Kotlin (Android) SDK — all four
                verified byte-for-byte against <code>spec/test-vectors.json</code>.
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
