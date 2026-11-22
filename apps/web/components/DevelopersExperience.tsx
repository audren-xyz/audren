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
    file: 'packages/sdk · @audren/sdk (zero-WASM core) + @audren/sdk/prover (BN254 Groth16 WASM)',
    code: `import {
  AUDREN_PROGRAM_ID,
  CompactWalletStore,
  AudrenRelayClient,
  AUDREN_DEFAULT_RELAY_URL,
  createSolanaRpcBatchFetcher,
  deriveKeysFromSeed,
  deriveSubaccountKeys,
  deriveDefiSessionKeypair,
  exportFullViewingKey,
  derivePoolPdaSync,
  deriveEscrowPdaSync,
  deriveUnwrapPdaSync,
  exportSelectiveDisclosureProof,
  verifySelectiveDisclosureProof,
  syncCompactStoreWithRpc,
} from '@audren/sdk';
import { AudrenWasmProver } from '@audren/sdk/prover';

// 1. Keys, sub-accounts, read-only FVK & pseudonymous DeFi Session (B_0)
const alice   = deriveKeysFromSeed(seed32);
const trading = deriveSubaccountKeys(seed32, 1);
const fvk     = exportFullViewingKey(alice);
const session = deriveDefiSessionKeypair(seed32, 0); // Ed25519 B_0 (public on external DeFi)

// 2. Canonical PDAs (audren_v2_*)
const poolPda   = derivePoolPdaSync(0, AUDREN_PROGRAM_ID).address;
const escrowPda = deriveEscrowPdaSync(0, 0, AUDREN_PROGRAM_ID).address;
const unwrapPda = deriveUnwrapPdaSync(0, nf0Bytes, AUDREN_PROGRAM_ID).address;

// 3. Zero-indexer ordinary RPC sync -> offline witness -> local WASM Groth16 prover
const store = new CompactWalletStore(0);
const fetchBatch = createSolanaRpcBatchFetcher(rpcUrl);
await syncCompactStoreWithRpc({ store, fvk, fetchBatch });
const receipt = exportSelectiveDisclosureProof(store.notes[0]!);
const ok = verifySelectiveDisclosureProof(receipt, store.notes[0]!.commitment);
const prover = await AudrenWasmProver.init(); // loads audren_circuits.wasm
const relay  = new AudrenRelayClient(AUDREN_DEFAULT_RELAY_URL);`,
  },
  rust: {
    tab: 'Rust (Cargo)',
    file: 'crates/client · native BN254 Groth16 prover, CompactWalletStore & LiteSVM suite',
    code: `use audren_client::{
    keys::AudrenKeys,
    pda::{derive_escrow_pda, derive_pool_pda, derive_unwrap_pda},
    prover::AudrenProver,
    router::DEFAULT_RELAY_URL,
    store::CompactWalletStore,
};
use audren_core::AUDREN_PROGRAM_ID;
use solana_address::Address;

// 1. Master spend/view keys, sub-accounts, read-only FVK & DeFi Session B_0
let alice   = AudrenKeys::from_seed(&seed_32);
let trading = AudrenKeys::from_seed_subaccount(&seed_32, 1);
let fvk     = alice.full_viewing_key();
let session = AudrenKeys::derive_defi_session_keypair(&seed_32, 0);

// 2. Canonical PDAs (audren_v2_*)
let pid = Address::new_from_array(AUDREN_PROGRAM_ID);
let (pool_pda, _)   = derive_pool_pda(&pid, 0);
let (escrow_pda, _) = derive_escrow_pda(&pid, 0, 0);
let (unwrap_pda, _) = derive_unwrap_pda(&pid, 0, &nf0_32);

// 3. Zero-indexer CompactWalletStore, Mode 1 receipt & local BN254 Groth16 prover
let mut store = CompactWalletStore::new(0, 0);
store.ingest_lane_pages(&fvk, 0, &[(0, &sub_raw)], &[(0, &memo_raw)], &[])?;
let note = store.unspent_notes(None)[0];
assert!(note.selective_disclosure_proof().verify_against_leaf(&note.commitment));
let prover = AudrenProver::from_canonical_pk();
println!("Pool: {pool_pda} · Escrow: {escrow_pda} · Relay: {DEFAULT_RELAY_URL}");`,
  },
  swift: {
    tab: 'Swift (iOS / macOS)',
    file: 'packages/swift · AudrenSDK via UniFFI over crates/audren-ffi',
    code: `import AudrenSDK
import Foundation

// 1. Master keys, sub-accounts, read-only FVK & DeFi Session keypair B_0
let alice   = try deriveKeysFromSeed(seed: seed32)
let trading = try deriveSubaccountKeys(seed: seed32, accountIndex: 1)
let fvk     = try exportFullViewingKey(seed: seed32)
let session = try deriveDefiSessionKeypair(seed: seed32, sessionIndex: 0)

// 2. Canonical PDAs (audren_v2_*)
let pid    = canonicalProgramId()
let pool   = try derivePoolPda(programId: pid, poolId: 0)
let escrow = try deriveEscrowPda(programId: pid, poolId: 0, shardId: 0)
let unwrap = try deriveUnwrapPda(programId: pid, poolId: 0, nf0: nf0Data)

// 3. Decrypt & verify 90 B note memo + Mode 1 SelectiveDisclosureProof + Groth16 proof
let dec   = try decryptAndVerifyMemoEntry(fvk: fvk, memo90: memo90, onchainCommitment: leafCm)
let valid = try verifySelectiveDisclosureProof(proof: receipt, onchainSubtreeLeaf: leafCm)
let storeJson = try compactStoreNewJson(poolId: 0, birthdaySlot: 0)
let proof = try proveJoinsplitWitnessBytes(witness4611: witnessData, seed32: rngSeed32)`,
  },
  kotlin: {
    tab: 'Kotlin (Android / JVM)',
    file: 'packages/kotlin · xyz.audren.sdk via UniFFI + JNA over crates/audren-ffi',
    code: `import xyz.audren.sdk.*

// 1. Master keys, sub-accounts, read-only FVK & DeFi Session keypair B_0
val alice   = deriveKeysFromSeed(seed32)
val trading = deriveSubaccountKeys(seed32, 1u)
val fvk     = exportFullViewingKey(seed32)
val session = deriveDefiSessionKeypair(seed32, 0u)

// 2. Canonical PDAs (audren_v2_*)
val pid    = canonicalProgramId()
val pool   = derivePoolPda(pid, 0u)
val escrow = deriveEscrowPda(pid, 0u, 0u)
val unwrap = deriveUnwrapPda(pid, 0u, nf0Bytes)

// 3. Decrypt & verify 90 B note memo + Mode 1 SelectiveDisclosureProof + Groth16 proof
val dec       = decryptAndVerifyMemoEntry(fvk, memo90, leafCm)
val valid     = verifySelectiveDisclosureProof(receipt, leafCm)
val storeJson = compactStoreNewJson(0u, 0uL)
val proof     = proveJoinsplitWitnessBytes(witness4611, rngSeed32)`,
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
              No Audren account, API gate, or mandatory indexer. Four Apache-2.0 SDKs — Rust,
              TypeScript (+ WASM Groth16 prover), Swift (iOS), and Kotlin (Android) — verified
              byte-for-byte against <code>spec/test-vectors.json</code> on every CI run.
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
              <h2>Zero-indexer integration, with explicit responsibilities.</h2>
            </div>
            <p>
              Ordinary Solana RPC keeps infrastructure minimal, while wallet recovery, encrypted
              local persistence, confirmation handling, and privacy disclosures remain core
              application responsibilities.
            </p>
          </div>

          <div className={styles.diagramStage}>
            <div className={styles.stageHead}>
              <strong>End-to-end client integration pipeline</strong>
              <span>Ordinary Solana RPC · Local Groth16 proving · Optional relay</span>
            </div>
            <svg
              className={styles.stageSvg}
              viewBox="0 0 920 176"
              role="img"
              aria-label="Audren client integration pipeline: Sync CompactWalletStore via ordinary getMultipleAccounts, Generate 192 B BN254 Groth16 proof locally, Submit single Solana Transaction v1 directly or via pluggable relayer, Confirm settlement and freeze sealed siblings"
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
                  tag: 'SYNC',
                  title: 'CompactWalletStore',
                  line1: 'getMultipleAccounts RPC',
                  line2: 'Freeze sealed siblings, drop pages',
                  foot: '1.28 MB @ 10M notes',
                },
                {
                  x: 247,
                  tag: 'PROVE',
                  title: 'BN254 Groth16 locally',
                  line1: '17,861 R1CS · 192 B proof',
                  line2: 'Bind ctx_hash & router accounts',
                  foot: 'spend_sk stays on device',
                },
                {
                  x: 482,
                  tag: 'SUBMIT',
                  title: '1 Solana v1 tx (0x81)',
                  line1: 'Direct wallet fee payer',
                  line2: 'or pluggable privacy relay',
                  foot: '~103k–158k CU · 1 Tx v1',
                },
                {
                  x: 717,
                  tag: 'SETTLE',
                  title: 'Confirm & verify',
                  line1: 'NullifierPage marks spends',
                  line2: 'Mode 1 receipt / Mode 2 FVK',
                  foot: 'Encrypted seed backup',
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
                <h2>Four languages. Zero cryptographic drift.</h2>
              </div>
              <p>
                Rust, TypeScript (+ WASM), Swift, and Kotlin share the exact same Circom BN254
                Poseidon parameters, 17,861-R1CS Groth16 circuit, 90 B ChaCha20-Poly1305 memos, and{' '}
                <code>audren_v2_*</code> PDAs — verified byte-for-byte in CI against{' '}
                <code>spec/test-vectors.json</code>.
              </p>
            </div>

            <div className={styles.ledger2}>
              <article className={`${styles.ledgerCell} ${styles.ledgerCellHighlight}`}>
                <span className={styles.cellIndex}>RUST · SERVICES &amp; CLIs</span>
                <h3><code>crates/client</code> &amp; <code>crates/audren-circuits</code></h3>
                <p className={styles.cellLead}>
                  Canonical native proving client, frozen R1CS circuit, and zero-indexer{' '}
                  <code>CompactWalletStore</code>. Pin directly via git in <code>Cargo.toml</code>.
                </p>
                <ul className={styles.dashList}>
                  <li>BN254 Poseidon spend/view hierarchy + HKDF sub-accounts &amp; read-only FVK</li>
                  <li>Native BN254 Groth16 proving (~150 ms) over 4-ary Depth-20 global MASP</li>
                  <li>All 9 instruction builders + exact <code>ctx_hash</code> transcripts</li>
                  <li>Full LiteSVM &amp; adversarial DeFi regression test suite included</li>
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
                <span className={styles.cellIndex}>TYPESCRIPT · WEB, NODE 22+ &amp; WORKERS</span>
                <h3><code>@audren/sdk</code> + <code>@audren/sdk/prover</code></h3>
                <p className={styles.cellLead}>
                  Zero-WASM pure-TS root entrypoint (runs natively in Cloudflare Workers) paired
                  with the exact Rust-compiled <code>audren_circuits.wasm</code> Groth16 prover.
                </p>
                <ul className={styles.dashList}>
                  <li><code>@audren/sdk</code>: pure-TS BN254 Poseidon, ChaCha20-Poly1305, 13 PDAs, <code>CompactWalletStore</code>, Transaction v1, IDLs &amp; <code>AudrenRelayClient</code></li>
                  <li><code>@audren/sdk/prover</code>: exact Rust <code>audren_circuits.wasm</code> (2.1 MB) proving byte-for-byte identical 192 B Groth16 proofs</li>
                  <li>Cross-SDK LiteSVM tests verify TS WASM proofs directly on sBPFv3 <code>audren.so</code></li>
                </ul>
                <div className={styles.cellFoot}>
                  <a
                    href={`${AUDREN.githubCore}/tree/main/packages/sdk`}
                    target="_blank"
                    rel="noreferrer"
                    className={styles.textLink}
                  >
                    Inspect packages/sdk on GitHub <ArrowUpRight size={13} />
                  </a>
                </div>
              </article>

              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>SWIFT · iOS 15+ &amp; macOS 13+</span>
                <h3><code>packages/swift</code> (<code>AudrenSDK</code>)</h3>
                <p className={styles.cellLead}>
                  Native Swift Package generated via UniFFI directly over{' '}
                  <code>crates/audren-ffi</code> so iOS wallets inherit the exact Rust Groth16
                  prover with zero re-implementation drift.
                </p>
                <ul className={styles.dashList}>
                  <li>Native local BN254 Groth16 proving on Apple Silicon &amp; iPhone ARM64</li>
                  <li>Keys, FVK, 13 PDAs, 90 B memo verification, Mode 1 receipts &amp; 9 ix builders</li>
                  <li>One-command iOS <code>XCFramework</code> script (<code>scripts/build-mobile-sdks.sh ios</code>)</li>
                  <li>Verified in CI via <code>swift test</code> against <code>spec/test-vectors.json</code></li>
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
                <span className={styles.cellIndex}>KOTLIN · ANDROID API 24+ &amp; JVM 21+</span>
                <h3><code>packages/kotlin</code> (<code>xyz.audren.sdk</code>)</h3>
                <p className={styles.cellLead}>
                  Native Kotlin SDK generated via UniFFI + JNA over{' '}
                  <code>crates/audren-ffi</code> for Android wallets and JVM backend services.
                </p>
                <ul className={styles.dashList}>
                  <li>Native local BN254 Groth16 proving on Android ARM64 / x86_64 &amp; JVM 21+</li>
                  <li>Complete SDK API matching Rust, TypeScript &amp; Swift byte-for-byte</li>
                  <li>One-command Android <code>jniLibs</code> build (<code>scripts/build-mobile-sdks.sh android</code>)</li>
                  <li>Verified in CI via <code>gradle test</code> against <code>spec/test-vectors.json</code></li>
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
              Compare the exact keys → PDAs → ordinary-RPC <code>CompactWalletStore</code> →
              local BN254 Groth16 prover → selective disclosure flow across TypeScript, Rust,
              Swift, and Kotlin.
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

        {/* EXAMPLES & CHECKLIST */}
        <section className={styles.sectionAlt}>
          <div className="container">
            <div className={styles.ledger2}>
              <article className={styles.ledgerCell}>
                <span className={styles.cellIndex}>EXAMPLES &amp; ESCROW DEFI CPI</span>
                <h3>Runnable examples across all 4 languages.</h3>
                <p className={styles.cellLead}>
                  <code>audren-xyz/examples</code> mirrors the canonical Audren flows — keys,
                  sub-accounts, pseudonymous DeFi Sessions (<code>B₀, B₁…</code>), ordinary-RPC{' '}
                  <code>CompactWalletStore</code> sync, local WASM/native Groth16 proving,
                  selective disclosure, and <code>ExecViaEscrow</code> planning — in Rust,
                  TypeScript, Swift, and Kotlin.
                </p>
                <ul className={styles.dashList}>
                  <li><code>ExecViaEscrow</code> (Tag 7) supports any compatible PDA-signing Token A → Token B CPI with input or output relayer fees (<code>EXEC_FLAG_FEE_ON_OUTPUT</code>) and hardened pre/post escrow checks.</li>
                  <li>Self-paying <code>JoinSplit</code> (Tag 6) supports atomic <code>WITHDRAW_FLAG_UNWRAP_WSOL</code> to fund 0-SOL wallets or session keypairs, paired with zero-dust <code>DepositSol(DEPOSIT_FLAG_FEE_FROM_AMOUNT)</code> sweeps.</li>
                  <li>All four example suites import the official SDKs directly — zero duplicated cryptography.</li>
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
                  Audren verifies proofs under Perpetual Powers of Tau (71+ contributors) +
                  verifiable BGM17 Phase-2 ceremony keys (<code>ceremony/transcript.json</code>) and
                  remains pre-audit with mutable upgrade authority pending independent security
                  review.
                </p>
                <ul className={styles.dashList}>
                  <li>Persist <code>CompactWalletStore</code> locally (IndexedDB / mobile disk) with optional birthday slot so sealed pages are discarded immediately.</li>
                  <li>Back up the encrypted 32-byte master seed; lost spend keys cannot be recovered by any operator.</li>
                  <li>Surface clear UX notices that deposits, withdrawals, DeFi CPI legs, and session wallet positions remain public on Solana.</li>
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
                Exact fixed &lt;10 KiB account layouts, 17,861-R1CS BN254 Groth16 constraints, and
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
