'use client'

import { useState } from 'react'
import Link from 'next/link'
import { ArrowLeft, ArrowRight, ArrowUpRight, Check, Copy } from 'lucide-react'
import { SiteHeader } from '@/components/SiteHeader'
import { SiteFooter } from '@/components/SiteFooter'
import { AUDREN, explorerAddress } from '@/lib/protocol'
import styles from '@/components/SubpageShell.module.css'
import { IntegrationPipeline } from '@/components/motion/IntegrationPipeline'

type SnippetId = 'ts' | 'rust' | 'swift' | 'kotlin'

const SNIPPETS: Record<SnippetId, { tab: string; file: string; code: string }> = {
  ts: {
    tab: 'TypeScript (Web / Node)',
    file: 'packages/sdk · @audren/sdk (zero-WASM core) + @audren/sdk/prover (BN254 Groth16 WASM)',
    code: `import {
  AUDREN_DEFAULT_RELAY_URL,
  AudrenRelayClient,
  CompactWalletStore,
  createSolanaRpcBatchFetcher,
  decodeSubtreePage,
  deriveDefiSessionKeypair,
  deriveKeysFromSeed,
  derivePoolPdaSync,
  deriveRootsPdaSync,
  deriveSubaccountKeys,
  deriveSubtreePdaSync,
  exportFullViewingKey,
  exportSelectiveDisclosureProof,
  fetchGlobalRootHistory,
  syncCompactStoreWithRpc,
  verifySelectiveDisclosureProof,
} from '@audren/sdk';
import { AudrenWasmProver } from '@audren/sdk/prover';

// 1. Keys: reusable aud1… address, sub-account, read-only viewing key, session wallet B_0
const alice   = deriveKeysFromSeed(seed32);
const trading = deriveSubaccountKeys(seed32, 1);
const fvk     = exportFullViewingKey(alice);
const session = deriveDefiSessionKeypair(seed32, 0); // public when it touches external DeFi
console.log(alice.address, trading.address);

// 2. Canonical PDAs (12 audren_* seeds: PoolState + inline GlobalRootHistory)
const poolPda  = derivePoolPdaSync(0).address;
const rootsPda = deriveRootsPdaSync(0).address;

// 3. Sync over ordinary Solana RPC + finalized-first GlobalRootHistory (~150ms Alpenglow finality)
const fetchBatch = createSolanaRpcBatchFetcher(rpcUrl);
const store = new CompactWalletStore(0);
await syncCompactStoreWithRpc({ store, fvk, fetchBatch });
const { snapshot } = await fetchGlobalRootHistory({ poolId: 0, rpcUrl });

// 4. Mode 1 receipt for one note; the verifier checks it against the on-chain leaf
const note = store.unspentNotes()[0];
if (note) {
  const receipt = exportSelectiveDisclosureProof(note);
  const [page] = await fetchBatch([
    deriveSubtreePdaSync(receipt.poolId, receipt.laneId, receipt.leafIndex / 256n).address,
  ]);
  const leaf = decodeSubtreePage(page!).leaves[Number(receipt.leafIndex % 256n)]!;
  console.log(verifySelectiveDisclosureProof(receipt, leaf));
}

// 5. Local Groth16 prover (browser: serve the wasm and 3.93 MB proving key) and relay client
const prover = await AudrenWasmProver.init({
  wasmUrl: '/wasm/audren_circuits.wasm',
  pkUrl: '/wasm/audren_joinsplit.pk',
});
const relay = new AudrenRelayClient(AUDREN_DEFAULT_RELAY_URL);`,
  },
  rust: {
    tab: 'Rust (Cargo)',
    file: 'crates/client · audren-client (git dependency) + solana-address',
    code: `use audren_client::{
    audren_core::AUDREN_PROGRAM_ID,
    keys::AudrenKeys,
    pda::{derive_pool_pda, derive_roots_pda},
    prover::AudrenProver,
    router::DEFAULT_RELAY_URL,
    scanner::{sync_compact_store_with_batch, SyncOptions},
    store::CompactWalletStore,
};
use solana_address::Address;

// 1. Keys: reusable aud1… address, sub-account, read-only viewing key, session wallet B_0
let alice   = AudrenKeys::from_seed(&seed_32);
let trading = AudrenKeys::from_seed_subaccount(&seed_32, 1);
let fvk     = alice.full_viewing_key();
let session = AudrenKeys::derive_defi_session_keypair(&seed_32, 0); // public on external DeFi
println!("{}", alice.address().encode()?);

// 2. Canonical PDAs (12 audren_* seeds: PoolState + inline GlobalRootHistory)
let pid = Address::new_from_array(AUDREN_PROGRAM_ID);
let (pool_pda, _)  = derive_pool_pda(&pid, 0);
let (roots_pda, _) = derive_roots_pda(&pid, 0);

// 3. Sync over ordinary Solana RPC (strict privacy mode by default);
//    rpc_get_multiple_accounts is your getMultipleAccounts closure
let mut store = CompactWalletStore::new(0, 0);
sync_compact_store_with_batch(&mut store, &fvk, rpc_get_multiple_accounts, &pid, SyncOptions::default())?;

// 4. Mode 1 receipt for one note (a verifier checks it against the on-chain SubtreePage leaf)
if let Some(note) = store.unspent_notes(None).first() {
    let receipt = note.selective_disclosure_proof();
    println!("leaf {} in lane {}", receipt.leaf_index, receipt.lane_id);
}

// 5. Native BN254 Groth16 prover
let prover = AudrenProver::from_canonical_pk();
println!("Pool: {pool_pda} · Relay: {DEFAULT_RELAY_URL}");`,
  },
  swift: {
    tab: 'Swift (iOS / macOS)',
    file: 'packages/swift · AudrenSDK via UniFFI over crates/audren-ffi',
    code: `import AudrenSDK
import Foundation

// 1. Keys: reusable aud1… address, sub-account, viewing key (primary account), session B_0
let alice   = try deriveKeysFromSeed(seed: seed32)
let trading = try deriveSubaccountKeys(seed: seed32, accountIndex: 1)
let fvk     = try exportFullViewingKey(seed: seed32)
let session = try deriveDefiSessionKeypair(seed: seed32, sessionIndex: 0)
print(alice.address)

// 2. Canonical PDAs (12 audren_* seeds: PoolState + GlobalRootHistory)
let pool  = try derivePoolPda(programId: canonicalProgramId(), poolId: 0)
let roots = try deriveRootsPda(programId: canonicalProgramId(), poolId: 0)

// 3. Open one memo you fetched over RPC (106 B MemoPage entry + its SubtreePage leaf)
if let note = try decryptAndVerifyMemoEntry(fvk: fvk, memo106: memo106, onchainCommitment: leafCm) {
    print(note.amount)
}

// 4. Verify a Mode 1 receipt someone sent you against the on-chain leaf
let valid = try verifySelectiveDisclosureProof(proof: receivedReceipt, onchainSubtreeLeaf: leafCm)

// 5. Prove natively from a 4,611 B witness (wallet sync and witness building: Rust or TS SDK)
let proof = try proveJoinsplitWitnessBytes(witness4611: witnessData, seed32: rngSeed32)`,
  },
  kotlin: {
    tab: 'Kotlin (Android / JVM)',
    file: 'packages/kotlin · xyz.audren.sdk via UniFFI + JNA over crates/audren-ffi',
    code: `import xyz.audren.sdk.*

// 1. Keys: reusable aud1… address, sub-account, viewing key (primary account), session B_0
val alice   = deriveKeysFromSeed(seed32)
val trading = deriveSubaccountKeys(seed32, 1u)
val fvk     = exportFullViewingKey(seed32)
val session = deriveDefiSessionKeypair(seed32, 0u)
println(alice.address)

// 2. Canonical PDAs (12 audren_* seeds: PoolState + GlobalRootHistory)
val pool  = derivePoolPda(canonicalProgramId(), 0u)
val roots = deriveRootsPda(canonicalProgramId(), 0u)

// 3. Open one memo you fetched over RPC (106 B MemoPage entry + its SubtreePage leaf)
decryptAndVerifyMemoEntry(fvk, memo106, leafCm)?.let { println(it.amount) }

// 4. Verify a Mode 1 receipt someone sent you against the on-chain leaf
val valid = verifySelectiveDisclosureProof(receivedReceipt, leafCm)

// 5. Prove natively from a 4,611 B witness (wallet sync and witness building: Rust or TS SDK)
val proof = proveJoinsplitWitnessBytes(witness4611, rngSeed32)`,
  },
}

const PIPELINE_STEPS = [
  {
    tag: '1. Sync',
    title: 'CompactWalletStore',
    line1: 'getMultipleAccounts RPC',
    line2: 'Freeze sealed siblings, drop pages',
    foot: '~1.28 MB kept @ 10M notes',
  },
  {
    tag: '2. Prove',
    title: 'BN254 Groth16 locally',
    line1: '17,861 R1CS · 192 B proof',
    line2: 'Bind ctx_hash and router accounts',
    foot: 'spend_sk stays on device',
  },
  {
    tag: '3. Submit',
    title: 'One transaction',
    line1: 'Relay: Tx v1 (0x81, 4,096 B)',
    line2: 'Direct wallet: v0 + Auto-OpenPage',
    foot: '75k–285k CU tight budgets',
  },
  {
    tag: '4. Settle',
    title: 'Confirm and verify',
    line1: 'NullifierPage marks spends',
    line2: 'Mode 1 receipt / Mode 2 FVK',
    foot: 'Encrypted seed backup',
  },
] as const

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
              No Audren account, API gate, or mandatory indexer. Call the program directly via its
              published Codama and Anchor IDLs, or use four optional Apache-2.0 SDKs (Rust,
              TypeScript with WASM Groth16 prover, Swift for iOS, and Kotlin for Android), verified
              byte-for-byte against <code>spec/test-vectors.json</code> on every CI run.
            </p>
          </div>

          <div className={styles.heroMetaStrip}>
            <div className={styles.heroMetaCell}>
              <span>Program ID ({AUDREN.deployedReleaseTag})</span>
              <span className={`${styles.heroMetaValue} mono`}>
                <a href={explorerAddress(AUDREN.programId, 'verified-build')} target="_blank" rel="noreferrer">
                  {AUDREN.programId.slice(0, 12)}…{AUDREN.programId.slice(-6)} <ArrowUpRight size={11} />
                </a>
              </span>
            </div>
            <div className={styles.heroMetaCell}>
              <span>Published IDLs</span>
              <span className={styles.heroMetaValue}>
                <a href={explorerAddress(AUDREN.programId, 'idl')} target="_blank" rel="noreferrer">
                  Codama 1.8.0 &amp; Anchor <ArrowUpRight size={11} />
                </a>
              </span>
            </div>
            <div className={styles.heroMetaCell}>
              <span>4 standardized SDKs</span>
              <span className={styles.heroMetaValue}>Rust · TypeScript · Swift · Kotlin</span>
            </div>
            <div className={styles.heroMetaCell}>
              <span>Conformance and license</span>
              <span className={styles.heroMetaValue}>
                <a
                  href={`${AUDREN.githubCore}/blob/main/spec/test-vectors.json`}
                  target="_blank"
                  rel="noreferrer"
                >
                  spec/test-vectors.json <ArrowUpRight size={11} />
                </a>{' '}
                · Apache-2.0
              </span>
            </div>
          </div>
        </section>

        {/* INTEGRATION PIPELINE */}
        <section className={`container ${styles.section}`}>
          <div className={styles.sectionIntro}>
            <div>
              <h2>Zero-indexer integration with explicit responsibilities.</h2>
            </div>
            <p>
              Ordinary Solana RPC keeps infrastructure minimal, while wallet recovery, encrypted
              local persistence, confirmation handling, and privacy disclosures remain core
              application responsibilities.
            </p>
          </div>

          <div className={styles.diagramStage}>
            <div className={styles.stageHead}>
              <div className={styles.stageTitle}>End-to-end client integration pipeline</div>
              <span>Ordinary Solana RPC · Local Groth16 proving · Optional relay</span>
            </div>
            <IntegrationPipeline steps={PIPELINE_STEPS} />
          </div>
        </section>

        {/* FOUR STANDARDIZED SDKS */}
        <section className={styles.sectionAlt}>
          <div className="container">
            <div className={styles.sectionIntro}>
              <div>
                <h2>Four standardized SDKs with zero cryptographic drift.</h2>
              </div>
              <p>
                Rust, TypeScript (+ WASM), Swift, and Kotlin share the exact same Circom BN254
                Poseidon parameters, 17,861-R1CS Groth16 circuit, versioned 72 B ChaCha20-Poly1305
                AEAD memos (106 B SoA wire entries), BIP-350 Bech32m <code>aud1…</code> addresses,
                and 12 canonical <code>audren_*</code> PDAs, verified byte-for-byte in CI against{' '}
                <code>spec/test-vectors.json</code>.
              </p>
            </div>

            <div className={styles.ledger2}>
              <article className={`${styles.ledgerCell} ${styles.ledgerCellHighlight}`}>
                <span className={styles.cellIndex}>Rust · Services and CLIs</span>
                <h3><code>crates/client</code> &amp; <code>crates/audren-circuits</code></h3>
                <p className={styles.cellLead}>
                  Canonical native proving client, frozen R1CS circuit, and zero-indexer{' '}
                  <code>CompactWalletStore</code>. Pin directly via git in <code>Cargo.toml</code>.
                </p>
                <ul className={styles.dashList}>
                  <li>HKDF-SHA256 spend and view keys (Poseidon <code>spend_pk</code> and <code>nk</code>, X25519 view key), sub-accounts &amp; read-only FVK</li>
                  <li>Native BN254 Groth16 proving over the 4-ary depth-20 global pool</li>
                  <li>All 9 instruction builders + exact <code>ctx_hash</code> transcripts</li>
                  <li>Full LiteSVM &amp; adversarial DeFi regression test suite included</li>
                  <li>Not on crates.io yet: add <code>audren-client</code> as a git dependency pinned to a release tag, plus <code>solana-address</code></li>
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
                <span className={styles.cellIndex}>TypeScript · Web, Node 22+, and Workers</span>
                <h3><code>@audren/sdk</code> + <code>@audren/sdk/prover</code></h3>
                <p className={styles.cellLead}>
                  Zero-WASM pure-TS root entrypoint (runs natively in Cloudflare Workers) paired
                  with the exact Rust-compiled <code>audren_circuits.wasm</code> Groth16 prover.
                </p>
                <ul className={styles.dashList}>
                  <li><code>@audren/sdk</code>: pure-TS BN254 Poseidon, ChaCha20-Poly1305 AEAD, BIP-350 Bech32m <code>aud1…</code>, 12 PDAs, <code>CompactWalletStore</code>, Transaction v1, IDLs &amp; <code>AudrenRelayClient</code></li>
                  <li><code>@audren/sdk/prover</code>: the Rust prover compiled to <code>audren_circuits.wasm</code>, producing the same 192 B proof as native Rust for the same witness and seed</li>
                  <li>Not on npm yet: build <code>packages/sdk</code> from the repository and add it as a local dependency</li>
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
                <span className={styles.cellIndex}>Swift · iOS 15+ and macOS 13+</span>
                <h3><code>packages/swift</code> (<code>AudrenSDK</code>)</h3>
                <p className={styles.cellLead}>
                  Native Swift Package generated via UniFFI directly over{' '}
                  <code>crates/audren-ffi</code> so iOS wallets inherit the exact Rust Groth16
                  prover with zero re-implementation drift.
                </p>
                <ul className={styles.dashList}>
                  <li>Native local BN254 Groth16 proving on Apple Silicon &amp; iPhone ARM64</li>
                  <li>Keys, FVK, 12 PDAs, 106 B memo decryption, Mode 1 receipt verification &amp; 9 ix builders</li>
                  <li>Build the <code>XCFramework</code> locally with <code>scripts/build-mobile-sdks.sh ios</code>; no remote SwiftPM release yet</li>
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
                <span className={styles.cellIndex}>Kotlin · Android API 24+ and JVM 21+</span>
                <h3><code>packages/kotlin</code> (<code>xyz.audren.sdk</code>)</h3>
                <p className={styles.cellLead}>
                  Native Kotlin SDK generated via UniFFI + JNA over{' '}
                  <code>crates/audren-ffi</code> for Android wallets and JVM backend services.
                </p>
                <ul className={styles.dashList}>
                  <li>Native local BN254 Groth16 proving on Android ARM64 / x86_64 &amp; JVM 21+</li>
                  <li>Same FFI surface as Swift: keys, PDAs, memo decryption, receipt verification &amp; 9 ix builders</li>
                  <li>Build Android <code>jniLibs</code> locally with <code>scripts/build-mobile-sdks.sh android</code>; no Maven artifact yet</li>
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
              TypeScript and Rust run the full flow: keys → PDAs → ordinary-RPC{' '}
              <code>CompactWalletStore</code> sync → Mode 1 receipt → local Groth16 prover. Swift
              and Kotlin expose keys, PDAs, memo decryption, receipt verification, instruction
              builders, and native proving from a witness; wallet sync and witness building are not
              yet exported over FFI.
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
                {copied ? 'Copied' : 'Copy'}
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
                <span className={styles.cellIndex}>Examples and escrow DeFi CPI</span>
                <h3>Runnable examples across all four languages</h3>
                <p className={styles.cellLead}>
                  <code>audren-xyz/examples</code> mirrors the core Audren flows (keys,
                  sub-accounts, pseudonymous DeFi Sessions (<code>B₀, B₁…</code>), local
                  WASM/native Groth16 proving, memo decryption, selective disclosure, and{' '}
                  <code>ExecViaEscrow</code> instruction building) across Rust, TypeScript, Swift,
                  and Kotlin, with full ordinary-RPC <code>CompactWalletStore</code> sync and
                  Mainnet/Devnet submission examples in Rust and TypeScript.
                </p>
                <ul className={styles.dashList}>
                  <li><code>ExecViaEscrow</code> (Tag 6) supports any compatible PDA-signing SPL or Token-2022 Token A → Token B CPI with input or output relayer fees (<code>EXEC_FLAG_FEE_ON_OUTPUT</code>) and hardened pre/post escrow checks.</li>
                  <li>Self-paying <code>Transact</code> (Tag 5) supports atomic <code>WITHDRAW_FLAG_UNWRAP_WSOL</code> to fund 0-SOL wallets or session keypairs (plus up to 4 parallel 2 → 1 merges per Solana Transaction v1), paired with unified zero-dust <code>Deposit(DEPOSIT_FLAG_NATIVE_SOL | DEPOSIT_FLAG_FEE_FROM_AMOUNT)</code> sweeps.</li>
                  <li>All four example suites import the official SDKs directly with zero duplicated cryptography.</li>
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
                <span className={styles.cellIndex}>Checklist</span>
                <h3>Read before integrating</h3>
                <p className={styles.cellLead}>
                  Audren verifies proofs under the Hermez Perpetual Powers of Tau (54 contributions plus a beacon) plus
                  a BGM17 Phase-2 ceremony that so far has only Audren’s two contributions (
                  <code>ceremony/transcript.json</code>), and remains pre-audit with mutable upgrade authority pending independent security
                  review.
                </p>
                <ul className={styles.dashList}>
                  <li>Persist <code>CompactWalletStore</code> locally (IndexedDB / mobile disk) with an optional birthday slot so recovery skips pages closed before the wallet existed.</li>
                  <li>Back up the encrypted 32-byte master seed; lost spend keys cannot be recovered by any operator.</li>
                  <li>Surface clear UX notices that deposits, withdrawals, DeFi CPI legs, and session wallet positions remain public on Solana.</li>
                  <li>Fetch <code>GlobalRootHistory</code> via <code>fetchGlobalRootHistory</code> (finalized-first with confirmed fallback for instant spendability on ~150ms Alpenglow finality), pass all input notes to <code>selectRootSnapshotForNotes</code>, and prepend <code>buildAutoOpenPageInstructions</code> on direct transactions with calibrated tight CU limits.</li>
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
                Exact fixed ≤10 KiB account layouts, 17,861-R1CS BN254 Groth16 constraints, and
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
