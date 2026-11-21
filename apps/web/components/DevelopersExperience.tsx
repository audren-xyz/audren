'use client'

import { useState } from 'react'
import Link from 'next/link'
import { ArrowLeft, ArrowRight, ArrowUpRight, Check, Copy } from 'lucide-react'
import { SiteHeader } from '@/components/SiteHeader'
import { SiteFooter } from '@/components/SiteFooter'
import { AUDREN, explorerAddress } from '@/lib/protocol'
import styles from '@/components/SubpageShell.module.css'

type SnippetId = 'ts' | 'rust' | 'swift' | 'kotlin'

const SNIPPETS: Record<SnippetId, { tab: string; file: string; code: string }> = {
  ts: {
    tab: 'TypeScript (Web / Node)',
    file: 'packages/sdk · @audren/sdk (zero deps) + @audren/sdk/prover (pure TS)',
    code: `import {
  AUDREN_PROGRAM_ID,
  PAGE_SCAN_DATA_SLICE,
  derivePoolPda,
  deriveEpochPagePda,
  AudrenRelayClient,
  AUDREN_DEFAULT_RELAY_URL,
} from '@audren/sdk';
import {
  deriveKeysFromSeed,
  deriveSubaccountKeys,
  scanEpochPageSpendable,
  buildTransferInstruction,
  createSelectiveDisclosureProof,
} from '@audren/sdk/prover';

// 1. Keys & isolated sub-accounts (matching Rust, Swift & Kotlin byte-for-byte)
const alice   = await deriveKeysFromSeed(seed32);
const trading = await deriveSubaccountKeys(seed32, 1);

// 2. Canonical PDAs & standard RPC dataSlice scan (offset: 64, length: 1056)
const { address: poolPda } = await derivePoolPda(0, AUDREN_PROGRAM_ID);
const { address: page0 }   = await deriveEpochPagePda(0, 0n, AUDREN_PROGRAM_ID);

// 3. Decrypt notes, prove locally & submit via optional relayer (or direct v1 tx)
const notes = await scanEpochPageSpendable(alice, pageBytes, 0);
const proof = createSelectiveDisclosureProof(notes[0]);
const relay = new AudrenRelayClient(AUDREN_DEFAULT_RELAY_URL);`,
  },
  rust: {
    tab: 'Rust (Cargo)',
    file: 'crates/client · native ~50 ms local proving & RPC/WS scanner',
    code: `use audren_client::{
    keys::AudrenKeys,
    pda::{derive_epoch_page_pda, derive_pool_pda},
    scanner::{decrypt_owned_note, scan_page_dataslice},
};
use audren_core::AUDREN_PROGRAM_ID;
use solana_address::Address;

// 1. Master spend/view keys + stream-scoped sub-accounts
let alice   = AudrenKeys::from_seed(&seed_32);
let trading = AudrenKeys::from_seed_subaccount(&seed_32, 1);
let fvk     = trading.full_viewing_key();

// 2. Canonical PDAs & 1,056-byte EpochPage dataSlice scanning
let pid = Address::new_from_array(AUDREN_PROGRAM_ID);
let (pool_pda, _) = derive_pool_pda(&pid, 0);
let (page0, _)    = derive_epoch_page_pda(&pid, 0, 0);
let hits = scan_page_dataslice(&fvk, 0, &slice_1056)?;

// 3. Build Multi-Base Triptych + Batched Bulletproofs locally (~50 ms)
// build_transfer / build_merge / build_swap_via_router / build_withdraw`,
  },
  swift: {
    tab: 'Swift (iOS / macOS)',
    file: 'packages/swift · AudrenSDK via UniFFI over audren-client (~50 ms native)',
    code: `import AudrenSDK
import Foundation

// 1. Master keys, sub-accounts & read-only Full Viewing Key
let alice   = try deriveKeysFromSeed(seed32: seed32)
let trading = try deriveSubaccountKeys(masterSeed32: seed32, accountIndex: 1)
let fvk     = try exportFullViewingKey(seed32: seed32, accountIndex: 1)

// 2. Canonical PDAs & 1,056-byte EpochPage dataSlice scan
let pid   = programId()
let pool  = try derivePoolPda(poolId: 0, programId: pid)
let slice = pageScanDataSlice() // offset: 64, length: 1056
let hits  = try scanPageDataslice(
    pageId: 0, slice1056: sliceBytes, spendPk32: alice.spendPk, viewSk32: alice.viewSk
)

// 3. Decrypt notes, generate Mode 1 receipt, or prove Transfer locally
let notes = try scanEpochPage(
    poolId: 0, pageBytes: pageBytes,
    spendSk32: alice.spendSk, spendPk32: alice.spendPk, viewSk32: alice.viewSk, programId: pid
)
let receipt = createSelectiveDisclosureProof(note: notes[0])`,
  },
  kotlin: {
    tab: 'Kotlin (Android / JVM)',
    file: 'packages/kotlin · xyz.audren.sdk via UniFFI + JNA (~50 ms native)',
    code: `import xyz.audren.sdk.*

// 1. Master keys, sub-accounts & read-only Full Viewing Key
val alice   = deriveKeysFromSeed(seed32)
val trading = deriveSubaccountKeys(seed32, 1u)
val fvk     = exportFullViewingKey(seed32, 1u)

// 2. Canonical PDAs & 1,056-byte EpochPage dataSlice scan
val pid   = programId()
val pool  = derivePoolPda(0u, pid)
val slice = pageScanDataSlice() // offset: 64, length: 1056
val hits  = scanPageDataslice(0uL, sliceBytes, alice.spendPk, alice.viewSk)

// 3. Decrypt notes, generate Mode 1 receipt, or prove Transfer locally
val notes = scanEpochPage(0u, pageBytes, alice.spendSk, alice.spendPk, alice.viewSk, pid)
val receipt = createSelectiveDisclosureProof(notes[0])
val valid   = verifySelectiveDisclosureOnPage(receipt, pageBytes)`,
  },
}

export function DevelopersExperience() {
  const [tab, setTab] = useState<SnippetId>('ts')
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
              No Audren account, API gate, or integration approval. Four standardized SDKs —
              Rust, TypeScript, Swift (iOS), and Kotlin (Android) — sharing six identical
              building blocks and one cross-language conformance test suite.
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
              <span>4 Standardized SDKs</span>
              <strong>Rust · TypeScript · Swift · Kotlin</strong>
            </div>
            <div className={styles.heroMetaCell}>
              <span>Conformance &amp; License</span>
              <strong>
                <a
                  href={`${AUDREN.githubCore}/blob/main/spec/test-vectors.json`}
                  target="_blank"
                  rel="noreferrer"
                >
                  spec/test-vectors.json <ArrowUpRight size={11} />
                </a>{' '}
                · Apache-2.0
              </strong>
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

        {/* FOUR STANDARDIZED SDKS */}
        <section className={styles.sectionAlt}>
          <div className="container">
            <div className={styles.sectionIntro}>
              <div>
                <h2>Four languages. Six identical building blocks.</h2>
              </div>
              <p>
                Every Audren SDK exposes the same primitives — <strong>keys</strong>,{' '}
                <strong>PDAs &amp; layouts</strong>, <strong>dataSlice scanner</strong>,{' '}
                <strong>local ZK prover</strong>, <strong>disclosure &amp; audit</strong>, and{' '}
                <strong>relayer &amp; router helpers</strong> — consumed directly from Apache-2.0
                source and verified byte-for-byte in CI against{' '}
                <code>spec/test-vectors.json</code>.
              </p>
            </div>

            <div className={styles.ledger2}>
              <article className={`${styles.ledgerCell} ${styles.ledgerCellHighlight}`}>
                <span className={styles.cellIndex}>RUST · SERVICES &amp; CLIs</span>
                <h3><code>crates/client</code></h3>
                <p className={styles.cellLead}>
                  Canonical native proving client and cryptographic source of truth. Pin a git
                  revision directly in <code>Cargo.toml</code> (no crates.io lock-in).
                </p>
                <ul className={styles.dashList}>
                  <li>Ristretto255 spend/view hierarchy + HKDF sub-accounts (<code>from_seed_subaccount</code>)</li>
                  <li>~50 ms Multi-Base Triptych (m=5/6/7), CrossBase 1/2 &amp; Agave Bulletproofs</li>
                  <li>RPC/WebSocket <code>EpochPage</code> scanner, Mode 1/2 disclosure &amp; auditor decrypt</li>
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
                <span className={styles.cellIndex}>TYPESCRIPT · WEB &amp; NODE 22+</span>
                <h3><code>@audren/sdk</code> + <code>@audren/sdk/prover</code></h3>
                <p className={styles.cellLead}>
                  Built from source via <code>packages/sdk</code>: zero-dependency core entrypoint
                  for PDAs, layouts, scanner, relayer &amp; IDLs, plus a full pure-TS prover
                  powering <code>audren.xyz</code> directly.
                </p>
                <ul className={styles.dashList}>
                  <li><code>@audren/sdk</code>: zero runtime deps — PDAs, codecs, Solana v1 (<code>0x81</code>), Codama &amp; Anchor IDLs, <code>AudrenRelayClient</code></li>
                  <li><code>@audren/sdk/prover</code>: full pure-TS Ristretto255, Triptych (m=5/6/7) &amp; Bulletproofs (<code>@noble/curves</code>)</li>
                  <li>Matches Rust byte-for-byte on keys, sub-accounts, note decryption &amp; Mode 1 receipts</li>
                  <li>Runs natively in browsers, Node 22+, and Cloudflare Workers</li>
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

              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>SWIFT · iOS 15+ &amp; macOS 13+</span>
                <h3><code>packages/swift</code> (<code>AudrenSDK</code>)</h3>
                <p className={styles.cellLead}>
                  Native Swift Package generated via UniFFI directly over{' '}
                  <code>crates/audren-ffi</code> so iOS wallets inherit the exact audited Rust core
                  with zero re-implementation drift.
                </p>
                <ul className={styles.dashList}>
                  <li>~50 ms native local proving on Apple Silicon &amp; iPhone ARM64</li>
                  <li>Complete 6-building-block API with native Swift <code>Data</code> &amp; throwing errors</li>
                  <li>One-command iOS <code>XCFramework</code> script (<code>scripts/build-mobile-sdks.sh ios</code>)</li>
                  <li>Proven in CI on <code>macos-latest</code> via <code>swift test</code></li>
                </ul>
                <div className={styles.cellFoot}>
                  <a
                    href={`${AUDREN.githubCore}/tree/main/packages/swift`}
                    target="_blank"
                    rel="noreferrer"
                    className={styles.textLink}
                  >
                    Inspect packages/swift on GitHub <ArrowUpRight size={13} />
                  </a>
                </div>
              </article>

              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>KOTLIN · ANDROID API 24+ &amp; JVM</span>
                <h3><code>packages/kotlin</code> (<code>xyz.audren.sdk</code>)</h3>
                <p className={styles.cellLead}>
                  Native Kotlin SDK generated via UniFFI + JNA over{' '}
                  <code>crates/audren-ffi</code> for Android wallets and JVM services.
                </p>
                <ul className={styles.dashList}>
                  <li>~50 ms native local proving on Android ARM64 / x86_64 &amp; JVM 21+</li>
                  <li>Complete 6-building-block API identical to Rust, TypeScript &amp; Swift</li>
                  <li>One-command Android <code>jniLibs</code> build (<code>scripts/build-mobile-sdks.sh android</code>)</li>
                  <li>Proven in CI via <code>gradle test</code> against <code>spec/test-vectors.json</code></li>
                </ul>
                <div className={styles.cellFoot}>
                  <a
                    href={`${AUDREN.githubCore}/tree/main/packages/kotlin`}
                    target="_blank"
                    rel="noreferrer"
                    className={styles.textLink}
                  >
                    Inspect packages/kotlin on GitHub <ArrowUpRight size={13} />
                  </a>
                </div>
              </article>
            </div>
          </div>
        </section>

        {/* COPYABLE CODE WORKBENCH (ALL 4 LANGUAGES) */}
        <section className={`container ${styles.section}`}>
          <div className={styles.sectionIntro}>
            <div>
              <h2>Same primitives in every language.</h2>
            </div>
            <p>
              Compare the exact same keys → PDAs → <code>dataSlice</code> scan → local prover →
              selective disclosure flow across TypeScript, Rust, Swift, and Kotlin.
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
                <span className={styles.cellIndex}>EXAMPLES &amp; ROUTER CPI</span>
                <h3>Runnable examples across all 4 languages.</h3>
                <p className={styles.cellLead}>
                  <code>audren-xyz/examples</code> mirrors the same canonical flows — keys,
                  sub-accounts, <code>dataSlice</code> scanning, local proving, selective
                  disclosure, and <code>SwapViaRouter</code> account planning — in Rust,
                  TypeScript, Swift, and Kotlin.
                </p>
                <ul className={styles.dashList}>
                  <li><code>SwapViaRouter</code> accepts compatible PDA-signing router instructions and enforces escrow ownership, zero delegates, lamport invariants, and exact vault deltas.</li>
                  <li>External DEX legs expose the token pair, trade amounts, and output record.</li>
                  <li>All four example folders consume the official Audren SDKs directly — zero hand-rolled constants or byte offsets.</li>
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
