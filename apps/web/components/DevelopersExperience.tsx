'use client'

import { useState } from 'react'
import Link from 'next/link'
import { ArrowLeft, ArrowRight, ArrowUpRight, Check, Copy } from 'lucide-react'
import { SiteHeader } from '@/components/SiteHeader'
import { SiteFooter } from '@/components/SiteFooter'
import { AUDREN, explorerAddress } from '@/lib/protocol'
import styles from '@/components/SubpageShell.module.css'

type SnippetId = 'pda' | 'scan' | 'relay' | 'rust'

const SNIPPETS: Record<SnippetId, { tab: string; file: string; code: string }> = {
  pda: {
    tab: 'PDAs & aud1… (TS)',
    file: 'packages/sdk · zero runtime dependencies',
    code: `import {
  AUDREN_PROGRAM_ID,
  derivePoolPda,
  deriveEpochPagePda,
  deriveSwapEscrowPda,
  parseAudrenAddress,
} from '@audren/sdk';

// Validate RFC 9496 Ristretto255 points inside an aud1… address
const { spendPk, viewPk } = parseAudrenAddress('aud1...');

// Canonical Solana PDAs (Web Crypto SHA-256 + pure-BigInt Ed25519 check)
const [poolPda] = await derivePoolPda(0, AUDREN_PROGRAM_ID);
const [page0]   = await deriveEpochPagePda(0, 0n, AUDREN_PROGRAM_ID);
const [escrow]  = await deriveSwapEscrowPda(0, 0, AUDREN_PROGRAM_ID);`,
  },
  scan: {
    tab: 'Scan EpochPages (TS)',
    file: 'Standard Solana RPC · 1,056 B per 32-note page',
    code: `import { fetchPageScanSlices, PAGE_SCAN_DATA_SLICE } from '@audren/sdk';

// Fetch view_tags[32] + ephemeral_pks[32] across up to 100 pages per RPC batch
// PAGE_SCAN_DATA_SLICE = { offset: 64, length: 1056 } (~106 KB for 3,200 notes)
const slices = await fetchPageScanSlices(
  process.env.SOLANA_RPC_URL!,
  pageAddresses,
);

for (const slice of slices) {
  // Check 1-byte view tags locally with your viewing key (rejects 255/256 non-owned notes)
  console.log(slice.address, slice.viewTags.length);
}`,
  },
  relay: {
    tab: 'Relayer Client (TS)',
    file: 'Pluggable HTTP contract · relay.audren.xyz or self-hosted',
    code: `import { AudrenRelayClient, AUDREN_DEFAULT_RELAY_URL } from '@audren/sdk';

const relay = new AudrenRelayClient(AUDREN_DEFAULT_RELAY_URL);
const info  = await relay.info('mainnet');

// Submit a locally proved Audren instruction — zero spend/view keys sent
const settled = await relay.submit({
  cluster: 'mainnet',
  instructionDataB64,
  accounts,
  computeUnitLimit: 600_000,
  priorityFeeLamports: '10000',
});
console.log('Settled signature:', settled.signature);`,
  },
  rust: {
    tab: 'Rust Prover (Cargo)',
    file: 'crates/client · complete Ristretto255 proving & scanning',
    code: `use audren_client::keys::AudrenKeys;

// Derive master spend/view keypair + isolated stream-scoped sub-accounts
let master  = AudrenKeys::from_seed(&seed_32);
let payroll = AudrenKeys::from_seed_subaccount(&seed_32, 1);

// Export read-only viewing key strictly for sub-account #1
let payroll_fvk = payroll.full_viewing_key();
println!("Payable aud1 address: {}", payroll.address().to_string());`,
  },
}

export function DevelopersExperience() {
  const [tab, setTab] = useState<SnippetId>('pda')
  const [copied, setCopied] = useState(false)
  const snippet = SNIPPETS[tab]

  const copyCode = () => {
    navigator.clipboard?.writeText(snippet.code).catch(() => {})
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1600)
  }

  return (
    <div className={`page-shell ${styles.page}`}>
      <SiteHeader current="developers" />

      <main>
        {/* HERO */}
        <section className={`container ${styles.hero}`}>
          <Link href="/" className={styles.backLink}>
            <ArrowLeft size={12} /> audren.xyz
          </Link>
          <div className={styles.heroSingle}>
            <h1>Build your own way in.</h1>
            <p className={styles.heroLead}>
              No Audren account, API gate, or integration approval. Read the Apache-2.0 source,
              choose any Solana RPC provider, and plug in your own wallet or relayer. Hosted
              relayers and DEX providers carry separate availability, credentials, and policies.
            </p>
          </div>

          <div className={styles.heroMetaStrip}>
            <div className={styles.heroMetaCell}>
              <span>Program ID ({AUDREN.releaseTag})</span>
              <strong className="mono">
                <a href={explorerAddress(AUDREN.programId, 'verified-build')} target="_blank" rel="noreferrer">
                  {AUDREN.programId.slice(0, 12)}…{AUDREN.programId.slice(-6)} <ArrowUpRight size={11} />
                </a>
              </strong>
            </div>
            <div className={styles.heroMetaCell}>
              <span>Published IDLs</span>
              <strong>
                <a href={explorerAddress(AUDREN.programId, 'idl')} target="_blank" rel="noreferrer">
                  Codama 1.8.0 &amp; Anchor <ArrowUpRight size={11} />
                </a>
              </strong>
            </div>
            <div className={styles.heroMetaCell}>
              <span>TypeScript &amp; Rust SDKs</span>
              <strong><code>@audren/sdk</code> · <code>crates/client</code></strong>
            </div>
            <div className={styles.heroMetaCell}>
              <span>License &amp; Status</span>
              <strong>Apache-2.0 · Verified · Pre-audit</strong>
            </div>
          </div>
        </section>

        {/* ANIMATED INTEGRATION PIPELINE */}
        <section className={`container ${styles.section}`}>
          <div className={styles.sectionIntro}>
            <div>
              <h2>A small integration, with explicit responsibilities.</h2>
            </div>
            <p>
              Permissionless integration keeps the protocol surface minimal, but does not remove
              engineering work. Wallet recovery, provider failures, confirmation handling, and
              privacy disclosures belong in your application design.
            </p>
          </div>

          <div className={styles.diagramStage}>
            <div className={styles.stageHead}>
              <strong>End-to-end client integration pipeline</strong>
              <span>Standard Solana RPC · Local proving · Optional relay</span>
            </div>
            <svg
              className={styles.stageSvg}
              viewBox="0 0 920 176"
              role="img"
              aria-label="Audren client integration pipeline: Discover EpochPage dataSlices via RPC, Authorize and prove locally on device, Submit via Direct RPC or optional relayer, Confirm settlement and handle ProofBuffer recovery"
            >
              <defs>
                <filter id="dev-pulse-glow" x="-60%" y="-60%" width="220%" height="220%">
                  <feGaussianBlur stdDeviation="2.5" result="b" />
                  <feMerge>
                    <feMergeNode in="b" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>

              {/* Connecting tracks + sequential signal pulses */}
              {[
                { x1: 205, x2: 245, begin: '0s' },
                { x1: 440, x2: 480, begin: '0.85s' },
                { x1: 675, x2: 715, begin: '1.7s' },
              ].map((conn) => (
                <g key={conn.x1}>
                  <line x1={conn.x1} y1="84" x2={conn.x2} y2="84" stroke="#d5d0c3" strokeWidth="1.5" />
                  <line x1={conn.x1} y1="84" x2={conn.x2} y2="84" stroke="#184433" strokeWidth="1.6" className={styles.flowDash} />
                  <polygon points={`${conn.x2 + 3},84 ${conn.x2 - 5},79 ${conn.x2 - 5},89`} fill="#184433" />
                  <circle r="3.4" fill="#184433" opacity="0" filter="url(#dev-pulse-glow)">
                    <animateMotion
                      dur="2.6s"
                      begin={conn.begin}
                      repeatCount="indefinite"
                      path={`M ${conn.x1},84 L ${conn.x2},84`}
                      calcMode="spline"
                      keyTimes="0;1"
                      keySplines="0.4 0 0.2 1"
                    />
                    <animate
                      attributeName="opacity"
                      values="0;1;1;0"
                      keyTimes="0;0.15;0.82;1"
                      dur="2.6s"
                      begin={conn.begin}
                      repeatCount="indefinite"
                    />
                  </circle>
                </g>
              ))}

              {[
                {
                  x: 12,
                  tag: 'DISCOVER',
                  title: 'Scan records',
                  line1: 'getMultipleAccounts',
                  line2: 'dataSlice: 64..1120 (1,056 B)',
                  foot: 'Local view-key scan',
                },
                {
                  x: 247,
                  tag: 'PROVE',
                  title: 'Authorize locally',
                  line1: 'Triptych + Bulletproof',
                  line2: 'Bind recipient, mint & router',
                  foot: 'Spend keys stay on device',
                },
                {
                  x: 482,
                  tag: 'SUBMIT',
                  title: 'Submit Solana v1',
                  line1: 'Direct wallet fee payer',
                  line2: 'or pluggable privacy relay',
                  foot: '1 tx <= 4,096 B (or buffer)',
                },
                {
                  x: 717,
                  tag: 'SETTLE',
                  title: 'Confirm & recover',
                  line1: 'Scan new EpochPage slots',
                  line2: 'CloseProofBuffer on retry',
                  foot: 'Back up encrypted seed',
                },
              ].map((step) => (
                <g key={step.tag}>
                  <rect
                    x={step.x}
                    y="16"
                    width="193"
                    height="140"
                    rx="2"
                    fill="#faf8f3"
                    stroke="#184433"
                    strokeWidth="1.3"
                  />
                  <rect x={step.x} y="16" width="193" height="3" fill="#184433" />
                  <text x={step.x + 14} y="39" fill="#184433" fontSize="9.5" fontWeight="700" fontFamily="monospace" letterSpacing="0.8">
                    {step.tag}
                  </text>
                  <text x={step.x + 14} y="59" fill="#121210" fontSize="13.5" fontWeight="700">
                    {step.title}
                  </text>
                  <text x={step.x + 14} y="80" fill="#4f554b" fontSize="10.5">
                    {step.line1}
                  </text>
                  <text x={step.x + 14} y="97" fill="#4f554b" fontSize="10.5">
                    {step.line2}
                  </text>
                  <line x1={step.x + 14} y1="116" x2={step.x + 179} y2="116" stroke="#d5d0c3" strokeWidth="1" />
                  <text x={step.x + 14} y="136" fill="#184433" fontSize="10" fontWeight="600">
                    {step.foot}
                  </text>
                </g>
              ))}
            </svg>
          </div>
        </section>

        {/* CHOOSE YOUR STARTING POINT */}
        <section className={styles.sectionAlt}>
          <div className="container">
            <div className={styles.sectionIntro}>
              <div>
                <h2>Choose the right starting point.</h2>
              </div>
              <p>
                Full cryptographic proving and Ristretto255 key management live in Rust; wire
                codecs, PDA derivation, RPC scanning, and relayer submission live in zero-dependency
                TypeScript.
              </p>
            </div>

            <div className={styles.ledger2}>
              <article className={`${styles.ledgerCell} ${styles.ledgerCellHighlight}`}>
                <span className={styles.cellIndex}>RUST</span>
                <h3>Complete proving client</h3>
                <p className={styles.cellLead}>
                  Start in <code>crates/client</code> for an independent private wallet or backend
                  integration. Pin a git revision and verify the full deposit-to-withdrawal flow.
                </p>
                <ul className={styles.dashList}>
                  <li>Ristretto255 spend/view keypairs + HKDF sub-accounts (<code>from_seed_subaccount</code>)</li>
                  <li>Local Triptych (m=5/6/7), CrossBase, and native Bulletproof generation</li>
                  <li>RPC/WebSocket EpochPage scanner, note manager, and router swap builder</li>
                  <li>LiteSVM &amp; Devnet integration test harness included</li>
                </ul>
                <div className={styles.cellFoot}>
                  <a
                    href={`${AUDREN.githubCore}/tree/main/crates/client`}
                    target="_blank"
                    rel="noreferrer"
                    className={styles.textLink}
                  >
                    Read crates/client on GitHub <ArrowUpRight size={13} />
                  </a>
                </div>
              </article>

              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>TYPESCRIPT</span>
                <h3>Zero-dependency protocol &amp; relayer SDK</h3>
                <p className={styles.cellLead}>
                  <code>@audren/sdk</code> ships built ESM and declarations from the public repo
                  with zero runtime dependencies (not advertised as an npm registry release).
                </p>
                <ul className={styles.dashList}>
                  <li>Base58 &amp; RFC 9496 <code>aud1…</code> stealth address parsing and validation</li>
                  <li>All canonical Audren &amp; ATA PDA derivations (Web Crypto + Ed25519 check)</li>
                  <li>HKDF sub-account seed derivation (<code>deriveSubAccountSeed</code>), account decoders, instruction codecs &amp; Solana v1 serializer</li>
                  <li>Typed <code>AudrenRelayClient</code>, bundled <code>AUDREN_CODAMA_IDL</code> / <code>AUDREN_ANCHOR_IDL</code>, RPC/WS scan helpers &amp; DEX aggregator CPI account prep</li>
                </ul>
                <div className={styles.cellFoot}>
                  <a
                    href={`${AUDREN.githubCore}/tree/main/packages/sdk`}
                    target="_blank"
                    rel="noreferrer"
                    className={styles.textLink}
                  >
                    Build packages/sdk from source <ArrowUpRight size={13} />
                  </a>
                </div>
              </article>
            </div>
          </div>
        </section>

        {/* COPYABLE CODE WORKBENCH */}
        <section className={`container ${styles.section}`}>
          <div className={styles.sectionIntro}>
            <div>
              <h2>Wire it in minutes.</h2>
            </div>
            <p>
              Real exports straight from <code>@audren/sdk</code> and <code>crates/client</code>.
              No custom indexer or proprietary RPC extensions required.
            </p>
          </div>

          <div className={styles.tabBar} role="tablist" aria-label="SDK code snippets">
            {(Object.keys(SNIPPETS) as SnippetId[]).map((id) => {
              const s = SNIPPETS[id]
              return (
                <button
                  key={id}
                  type="button"
                  role="tab"
                  aria-selected={tab === id}
                  onClick={() => {
                    setTab(id)
                    setCopied(false)
                  }}
                  className={`${styles.tabBtn} ${tab === id ? styles.tabBtnActive : ''}`}
                >
                  {s.tab}
                </button>
              )
            })}
          </div>

          <div className={styles.codePanel}>
            <div className={styles.codeBar}>
              <span>{snippet.file}</span>
              <button type="button" className={styles.copyBtn} onClick={copyCode}>
                {copied ? <Check size={12} /> : <Copy size={12} />}
                {copied ? 'COPIED' : 'COPY'}
              </button>
            </div>
            <pre className={styles.codePre}>
              <code>{snippet.code}</code>
            </pre>
          </div>
        </section>

        {/* SECTION 04: SWAPS & BEFORE INTEGRATING */}
        <section className={styles.sectionAlt}>
          <div className="container">
            <div className={styles.ledger2}>
              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>ROUTER CPI</span>
                <h3>Swaps use existing liquidity.</h3>
                <p className={styles.cellLead}>
                  <code>SwapViaRouter</code> accepts compatible PDA-signing router instructions and
                  enforces escrow ownership, zero delegates, lamport invariants, and exact vault
                  deltas before settling to a fresh private note.
                </p>
                <ul className={styles.dashList}>
                  <li>The demo reads live routing capability from your selected relay; a router adapter in source does not guarantee a hosted service.</li>
                  <li>External DEX legs expose the token pair, trade amounts, and output record.</li>
                  <li>The TypeScript aggregator swap example demonstrates quote &amp; account planning (not an end-to-end settled swap); inspect the Rust tests or live app for full settlement.</li>
                </ul>
                <div className={styles.cellFoot}>
                  <a href={AUDREN.githubExamples} target="_blank" rel="noreferrer" className={styles.textLink}>
                    Explore audren-xyz/examples <ArrowUpRight size={13} />
                  </a>
                  <Link href="/demo" className={styles.textLink}>
                    Try the live app <ArrowRight size={13} />
                  </Link>
                </div>
              </article>

              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>CHECKLIST</span>
                <h3>Read before integrating.</h3>
                <p className={styles.cellLead}>
                  Audren is pre-audit and its Solana BPF program remains upgradeable. Validate the
                  deployed ProgramData hash you interact with and surface public-boundary
                  disclosures in your product UX.
                </p>
                <ul className={styles.dashList}>
                  <li>Handle interrupted <code>ProofBuffer</code> uploads cleanly via <code>CloseProofBuffer</code> (100% rent refund).</li>
                  <li>Design encrypted seed / viewing-key backups; lost spend keys cannot be recovered by any operator.</li>
                  <li>Communicate clearly that deposits, withdrawals, DEX legs, fee payers, and candidate pages remain public.</li>
                </ul>
                <div className={styles.cellFoot}>
                  <Link href="/architecture" className={styles.textLink}>
                    Protocol specification <ArrowRight size={13} />
                  </Link>
                  <Link href="/compare" className={styles.textLink}>
                    Privacy comparison <ArrowRight size={13} />
                  </Link>
                  <Link href="/faq" className={styles.textLink}>
                    FAQ <ArrowRight size={13} />
                  </Link>
                </div>
              </article>
            </div>
          </div>
        </section>

        {/* CLOSING */}
        <section className={styles.closing}>
          <div className={`container ${styles.closingInner}`}>
            <div>
              <h2>Inspect the on-chain specification.</h2>
              <p>
                Exact Structure-of-Arrays byte offsets, Multi-Base Binary Triptych equations, and
                measured sBPFv3 Compute Units.
              </p>
            </div>
            <div className={styles.closingActions}>
              <Link href="/architecture" className="btn-paper">
                Protocol specification
              </Link>
              <a href={AUDREN.githubCore} target="_blank" rel="noreferrer" className={styles.closingLink}>
                Apache-2.0 source <ArrowUpRight size={15} />
              </a>
            </div>
          </div>
        </section>
      </main>

      <SiteFooter current="developers" />
    </div>
  )
}
