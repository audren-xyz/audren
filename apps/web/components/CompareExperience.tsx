'use client'

import { useState, type CSSProperties } from 'react'
import Link from 'next/link'
import { ArrowLeft, ArrowRight, ArrowUpRight, Eye, EyeOff } from 'lucide-react'
import { SiteHeader } from '@/components/SiteHeader'
import { SiteFooter } from '@/components/SiteFooter'
import styles from '@/components/SubpageShell.module.css'
import m from '@/components/motion/motion.module.css'

type ModeId = 'transfer' | 'entry-exit' | 'swap'

interface ComparisonRow {
  method: string
  sub: string
  highlight?: boolean
  senderRecipient: { text: string; state: 'hidden' | 'public' | 'partial' }
  token: { text: string; state: 'hidden' | 'public' | 'partial' }
  amount: { text: string; state: 'hidden' | 'public' | 'partial' }
  assets: string
}

const MODE_META: Record<
  ModeId,
  { label: string; headline: string; note: string; col5Header: string; rows: ComparisonRow[] }
> = {
  transfer: {
    label: 'Private transfer',
    headline: 'What a public Solana observer sees on a peer-to-peer transfer',
    note: 'Transaction metadata and the fee payer remain public in every model. A separate relayer keeps your own wallet off the fee-payer field without removing network or timing metadata. Audren defaults to uniform padded private transfers (2 nullifiers, 3 encrypted outputs, random append lane) so observers cannot distinguish 1-in vs 2-in or relayed vs self-paid sends.',
    col5Header: 'Asset scope',
    rows: [
      {
        method: 'Ordinary Solana',
        sub: 'Standard SPL / SOL transfer',
        senderRecipient: { text: 'Public accounts', state: 'public' },
        token: { text: 'Public mint', state: 'public' },
        amount: { text: 'Public', state: 'public' },
        assets: 'SOL & all tokens',
      },
      {
        method: 'Confidential Balances',
        sub: 'Native Token-2022 extension',
        senderRecipient: { text: 'Public accounts', state: 'public' },
        token: { text: 'Public mint', state: 'public' },
        amount: { text: 'Encrypted', state: 'hidden' },
        assets: 'Configured Token-2022 mints only',
      },
      {
        method: 'Helius Privacy Rings',
        sub: 'Default confidential ring vs. custom policy ring',
        senderRecipient: { text: 'Public in default; hidden in custom ring', state: 'partial' },
        token: { text: 'Encrypted', state: 'hidden' },
        amount: { text: 'Encrypted', state: 'hidden' },
        assets: 'SOL, classic SPL, Token-2022',
      },
      {
        method: 'Audren',
        sub: 'Transact Private Transfer (Tag 5)',
        highlight: true,
        senderRecipient: { text: 'Hidden across global 4²⁰ pool · one-time stealth owner', state: 'hidden' },
        token: { text: 'Hidden inside Poseidon5 commitment', state: 'hidden' },
        amount: { text: 'Hidden inside Poseidon5 commitment', state: 'hidden' },
        assets: 'SOL, classic SPL, transferable Token-2022',
      },
    ],
  },
  'entry-exit': {
    label: 'Deposit & withdraw',
    headline: 'Public entry and exit boundaries, nullifier cost, and pause behavior',
    note: 'Deposits and withdrawals touch ordinary Solana accounts by design. Concealing the spent note on withdrawal does not prevent timing, public amounts, or outside information from creating links. Helius Privacy Rings reclaims nullifier rent down to 5,000 lamports via its permissioned Forester while pause_tree halts withdrawals; Audren pays permanent NullifierPDA rent on-chain (~0.002–0.0046 SOL/tx, scaling down automatically via SysvarRent if Solana lowers rent) and keeps full 100% withdrawals (including atomic WSOL unwrap) immune to SetPaused.',
    col5Header: 'Assets, rent & pause',
    rows: [
      {
        method: 'Ordinary Solana',
        sub: 'Direct wallet movement',
        senderRecipient: { text: 'Public accounts', state: 'public' },
        token: { text: 'Public mint', state: 'public' },
        amount: { text: 'Public', state: 'public' },
        assets: 'SOL & all tokens; standard tx fee',
      },
      {
        method: 'Confidential Balances',
        sub: 'Deposit / withdraw confidential balance',
        senderRecipient: { text: 'Public owner account', state: 'public' },
        token: { text: 'Public mint', state: 'public' },
        amount: { text: 'Public at boundary', state: 'public' },
        assets: 'Configured Token-2022 mints; issuer mint controls apply',
      },
      {
        method: 'Helius Privacy Rings',
        sub: 'Public SPL interface deposit / withdrawal',
        senderRecipient: { text: 'Public SPL boundary; default ring exposes participants', state: 'partial' },
        token: { text: 'Public at entry & exit', state: 'public' },
        amount: { text: 'Public at entry & exit', state: 'public' },
        assets: 'SOL, classic SPL, Token-2022 · 5,000-lamport Forester-reclaimed nullifiers · pause_tree halts exits',
      },
      {
        method: 'Privacy Cash',
        sub: 'Asset-specific Groth16 Merkle pools',
        senderRecipient: { text: 'Public depositor / destination; link broken by tree proof', state: 'partial' },
        token: { text: 'Public pool asset', state: 'public' },
        amount: { text: 'Public at entry & exit', state: 'public' },
        assets: 'Supported pool assets; separate Merkle tree per asset',
      },
      {
        method: 'Audren',
        sub: 'Unified Deposit (Tag 3) · Transact Exit (Tag 5)',
        highlight: true,
        senderRecipient: { text: 'One-time stealth output on deposit; global pool proof on exit', state: 'partial' },
        token: { text: 'Public at entry & exit', state: 'public' },
        amount: { text: 'Public at entry & exit (change hidden)', state: 'public' },
        assets: 'SOL (WSOL), classic SPL, Token-2022 · permanent NullifierPDA rent (~0.002–0.0046 SOL/tx, SysvarRent-scaled) · full exits incl. atomic WSOL unwrap bypass SetPaused',
      },
    ],
  },
  swap: {
    label: 'Shielded DeFi',
    headline: 'Composing with public Solana DeFi vs. custom ZK-CPI escrow apps',
    note: 'Two distinct architectural paths exist for shielded DeFi on Solana. Helius Privacy Rings uses programmable ZK-CPI escrows (utxo_data plus custom app Groth16 proofs) that can keep swap prices and amounts private, at the cost of building custom circuits and bootstrapping fresh liquidity per protocol under 2-proof CU and packet constraints. Audren takes the protocol-agnostic path: atomic ExecViaEscrow (Tag 6) hits live Solana DeFi liquidity today (Jupiter, Kamino, Jito, Sanctum, Raydium, Orca) in one transaction (~158k CU), keeping the external DeFi pair and amount public while concealing the funding notes and primary wallet inside the global 4²⁰ pool (plus deterministic Bᵢ session wallets for stateful borrowing or perps).',
    col5Header: 'Liquidity & execution',
    rows: [
      {
        method: 'Ordinary Solana',
        sub: 'Direct wallet swap via aggregator / AMM',
        senderRecipient: { text: 'Your public wallet signs', state: 'public' },
        token: { text: 'Public pair', state: 'public' },
        amount: { text: 'Public trade size', state: 'public' },
        assets: 'All live Solana DEX & DeFi liquidity',
      },
      {
        method: 'Confidential Balances',
        sub: 'Must withdraw to public balance first',
        senderRecipient: { text: 'Your public wallet signs', state: 'public' },
        token: { text: 'Public pair', state: 'public' },
        amount: { text: 'Public trade size', state: 'public' },
        assets: 'Public SPL liquidity after unwrapping',
      },
      {
        method: 'Helius Privacy Rings',
        sub: 'Programmable ZK-CPI escrows (utxo_data + custom app Groth16)',
        senderRecipient: { text: 'Public in default ring; hidden in custom policy rings', state: 'partial' },
        token: { text: 'Private in custom ZK-CPI escrows', state: 'hidden' },
        amount: { text: 'Private in custom ZK-CPI escrows', state: 'hidden' },
        assets: 'Requires custom app circuits & fresh liquidity per protocol (plus 2-proof CU & packet constraints)',
      },
      {
        method: 'Privacy Cash',
        sub: 'Withdraw to ephemeral wallet → Jupiter → reshield',
        senderRecipient: { text: 'Ephemeral wallet trades (primary wallet hidden)', state: 'partial' },
        token: { text: 'Public pair', state: 'public' },
        amount: { text: 'Public trade size', state: 'public' },
        assets: 'Multi-tx ephemeral Jupiter route on supported pool assets',
      },
      {
        method: 'Audren',
        sub: 'Atomic ExecViaEscrow (Tag 6) + Self-Paying DeFi Sessions (Tag 5 + Tag 3)',
        highlight: true,
        senderRecipient: { text: 'Global 4²⁰ pool proof · sharded escrow CPI (or Bᵢ session) · fresh stealth note', state: 'partial' },
        token: { text: 'Public external DeFi mints', state: 'public' },
        amount: { text: 'Public external DeFi amounts (optional hidden change)', state: 'public' },
        assets: 'Live Solana DeFi liquidity today (Jupiter, Kamino, Jito, Sanctum, Raydium, Orca) in 1 tx (~158k CU) + stateful Bᵢ sessions',
      },
    ],
  },
}

interface PeerComparison {
  tag: string
  name: string
  lead: string
  comparisons: ReadonlyArray<{ label: string; text: string }>
  sources: ReadonlyArray<{ label: string; href: string }>
}

const PEER_COMPARISONS: readonly PeerComparison[] = [
  {
    tag: 'Shielded rings on Solana',
    name: 'Audren vs. Helius Privacy Rings',
    lead: 'Both shield existing SOL, SPL, and Token-2022 assets on Solana, while making opposite bets on default anonymity, prover infrastructure, nullifier rent, and DeFi.',
    comparisons: [
      {
        label: 'Default visibility',
        text: 'Helius’s live default ring encrypts mint and amount while leaving sender and recipient wallets public; participant anonymity lives in separate Custom Policy Rings. Audren hides spent notes, stealth recipient, mint, and amount by default inside one global 4²⁰ pool.',
      },
      {
        label: 'Proving & state discovery',
        text: 'Helius relies on a Photon indexer, permissioned Forester, and remote GPU/TEE proving (or 350 MB to 1.27 GB multi-shape keys), with delegated viewing access for anonymous-ring sync. Audren proves locally from one frozen 3.93 MB key and syncs directly from ordinary Solana RPC with zero indexer or Forester.',
      },
      {
        label: 'DeFi composability',
        text: 'Helius’s programmable ZK-CPI escrows can keep swap prices and amounts private, requiring custom app circuits and fresh liquidity per protocol. Audren’s atomic ExecViaEscrow (~158k CU) routes directly into live Solana DeFi liquidity today while keeping external DeFi legs public.',
      },
      {
        label: 'Rent, fan-in & exits',
        text: 'Helius reclaims nullifier rent to 5,000 lamports, merges up to 49 to 52 inputs, and updates roots in 1 slot, while pause_tree halts withdrawals. Audren pays permanent NullifierPDA rent (~0.002 to 0.0046 SOL/tx, scaling via SysvarRent) with 2-in/3-out spends (and up to 4 parallel 2 → 1 private Transact merges per Solana Transaction v1) plus ~6.4s checkpoints, while full exits stay immune to pause.',
      },
    ],
    sources: [
      { label: 'Helius encryption modes', href: 'https://www.helius.dev/docs/privacy/concepts/encryption' },
      { label: 'Helius architecture', href: 'https://www.helius.dev/docs/privacy/concepts/architecture' },
      { label: 'Helius security evidence', href: 'https://www.helius.dev/docs/privacy/security' },
      { label: 'Helius deployments', href: 'https://www.helius.dev/docs/privacy/addresses' },
    ],
  },
  {
    tag: 'Per-asset Merkle pools',
    name: 'Audren vs. Privacy Cash',
    lead: 'Both use local BN254 Groth16 proofs over Merkle trees for existing Solana assets, while differing in pool structure, DeFi atomicity, and RPC discovery.',
    comparisons: [
      {
        label: 'Anonymity pool scope',
        text: 'Privacy Cash separates liquidity into one Merkle tree per supported asset. Audren merges SOL, classic SPL, and transferable Token-2022 into one shared 4²⁰ Multi-Asset Shielded Pool so activity across assets shares one global tree.',
      },
      {
        label: 'DeFi execution',
        text: 'Privacy Cash withdraws to an ephemeral wallet, trades on Jupiter, and reshields across multiple transactions. Audren settles compatible swaps, lending, and LST mints atomically in one transaction via sharded ExecViaEscrow (~158k CU), plus deterministic Bᵢ session wallets for stateful protocols.',
      },
      {
        label: 'Sync & local state',
        text: 'Audren syncs directly from ordinary Solana RPC getMultipleAccounts over fixed <10 KiB pages (CompactWalletStore, 1.28 MB at 10M notes) without requiring a dedicated indexer.',
      },
      {
        label: 'Review & maturity',
        text: 'Privacy Cash has published independent audits (including HashCloak). Audren is Apache-2.0 open source with an OtterSec-verified Mainnet build and live BGM17 ceremony, with independent audit pending.',
      },
    ],
    sources: [
      { label: 'Privacy Cash flows', href: 'https://privacycash.mintlify.app/' },
      { label: 'HashCloak audit study', href: 'https://hashcloak.com/case-studies/privacy-cash-audit-case-study' },
    ],
  },
  {
    tag: 'Dedicated privacy L1s',
    name: 'Audren vs. Monero & Zcash',
    lead: 'Monero and Zcash are battle-tested standalone privacy networks; Audren brings shielded pool proofs directly to native Solana assets and live DeFi without bridging.',
    comparisons: [
      {
        label: 'Assets & bridging',
        text: 'Monero and Zcash run on dedicated L1s and cannot shield native Solana SOL, USDC, or Token-2022 without wrapping or bridging. Audren shields original Solana assets in place inside unified WSOL and SPL custody vaults (wrapping and unwrapping native SOL atomically).',
      },
      {
        label: 'DeFi liquidity',
        text: 'Dedicated privacy chains have limited on-chain DeFi. Audren composes atomically with live Solana DEXs, lending markets, and LSTs via ExecViaEscrow and deterministic session wallets.',
      },
      {
        label: 'Proof system & setup',
        text: 'Monero uses ring signatures with no trusted setup and Zcash Orchard uses Halo 2 with no trusted setup. Audren uses one frozen 17,861-R1CS BN254 Groth16 circuit (Perpetual Powers of Tau + BGM17 Phase 2) so proofs stay 192 B and verify via Solana’s native alt_bn128 syscalls.',
      },
      {
        label: 'Production track record',
        text: 'Monero and Zcash carry years of adversarial review and production history. Audren is a newer Solana protocol and does not claim stronger privacy assurance than dedicated privacy L1s.',
      },
    ],
    sources: [
      { label: 'Monero specs', href: 'https://docs.getmonero.org/technical-specs/' },
      { label: 'Zcash pool design', href: 'https://zcash.github.io/ironwood/design.html' },
      { label: 'Halo 2 (ZIP-224)', href: 'https://zips.z.cash/zip-0224' },
    ],
  },
  {
    tag: 'Enclaves and MPC',
    name: 'Audren vs. Nimbus & Arcium',
    lead: 'Enclave and MPC systems target general confidential compute; Audren narrows scope to client-side ZK proofs so no hardware enclave or MPC committee sits in the custody path.',
    comparisons: [
      {
        label: 'Trust assumptions',
        text: 'Nimbus relies on enclave hardware and attester assumptions (distinct from historical Umbra SDK docs), and Arcium relies on honest-majority MPC clusters. Audren verifies every spend purely in on-chain BN254 Groth16 math with spending keys remaining strictly on your device.',
      },
      {
        label: 'Compute scope',
        text: 'Enclave and MPC networks can execute arbitrary private programs beyond payment pools. Audren intentionally freezes one minimal payment and escrow-handoff circuit (ExecViaEscrow) to keep local proving at 3.93 MB and on-chain behavior deterministic.',
      },
      {
        label: 'Liveness & emergency exits',
        text: 'Enclave and MPC execution depends on attester or committee availability and separate emergency-exit mechanisms. Audren syncs over ordinary Solana RPC and keeps full 100% withdrawals (including atomic WSOL unwrap) directly executable on Solana even during SetPaused.',
      },
    ],
    sources: [
      { label: 'Nimbus assumptions', href: 'https://docs.nimbusprivacy.xyz/security/assumptions' },
      { label: 'Nimbus exits', href: 'https://docs.nimbusprivacy.xyz/security/liveness' },
      { label: 'Arcium MPC model', href: 'https://docs.arcium.com/multi-party-execution-environments-mxes/mpc-protocols' },
    ],
  },
] as const

type Visibility = ComparisonRow['token']

const VIS_CLASS = {
  hidden: styles.visHidden,
  public: styles.visPublic,
  partial: styles.visPartial,
} as const

/**
 * A field cell. In observer view an ink bar covers what a chain explorer
 * cannot read (hatched where it depends on the mode or ring).
 */
function VisCell({ cell, observer, delayMs }: { cell: Visibility; observer: boolean; delayMs: number }) {
  return (
    <span className={VIS_CLASS[cell.state]}>
      <span
        className={m.redact}
        data-on={observer && cell.state !== 'public' ? 'true' : 'false'}
        data-partial={cell.state === 'partial' ? 'true' : 'false'}
        style={{ '--redact-delay': `${delayMs}ms` } as CSSProperties}
      >
        {cell.text}
      </span>
      {observer && cell.state !== 'public' ? (
        <span className={m.visuallyHidden}>
          {cell.state === 'hidden' ? ' (hidden from observers)' : ' (partly hidden)'}
        </span>
      ) : null}
    </span>
  )
}

export function CompareExperience() {
  const [mode, setMode] = useState<ModeId>('transfer')
  const [observer, setObserver] = useState(false)
  const active = MODE_META[mode]

  return (
    <div className={`page-shell ${styles.page}`}>
      <SiteHeader current="compare" />

      <main>
        {/* HERO */}
        <section className={`container ${styles.hero}`}>
          <Link href="/" className={styles.backLink}>
            <ArrowLeft size={12} /> audren.xyz
          </Link>
          <div className={styles.heroGrid}>
            <div>
              <h1>How Audren compares to every other privacy model.</h1>
              <p className={styles.heroLead}>
                Compare Audren side by side against Solana and dedicated-L1 privacy architectures
                across on-chain visibility, native asset support, DeFi composability, proving
                overhead, rent, and trust assumptions.
              </p>
            </div>
            <div className={styles.diagramStagePaper}>
              <div className={styles.stageHead}>
                <div className={styles.stageTitle}>Audren vs. Confidential Balances</div>
                <span>Token-2022 extension</span>
              </div>
              <p className={styles.cellLead} style={{ marginBottom: 12 }}>
                Solana’s native Confidential Balances encrypt transfer amounts on configured
                Token-2022 mints while leaving sender, recipient, and mint public. Audren hides all
                four fields across existing SOL, classic SPL, and Token-2022 inside one shared pool.
              </p>
              <a
                className={styles.textLink}
                style={{ fontSize: 14 }}
                href="https://solana.com/docs/tokens/extensions/confidential-transfer/integration-guide"
                target="_blank"
                rel="noreferrer"
              >
                Read Solana’s integration guide <ArrowUpRight size={13} />
              </a>
            </div>
          </div>
        </section>

        {/* INTERACTIVE VISIBILITY MATRIX */}
        <section className={`container ${styles.section}`}>
          <div className={styles.sectionIntro}>
            <div>
              <h2>Compare by transaction type.</h2>
            </div>
            <p>
              Privacy boundaries change between internal transfers, public deposits or withdrawals,
              and external DeFi CPIs or session wallets. Switch views below to compare every field directly.
            </p>
          </div>

          <div className={styles.tabBar} role="tablist" aria-label="Choose transaction flow to compare">
            {(Object.keys(MODE_META) as ModeId[]).map((id) => {
              const m = MODE_META[id]
              return (
                <button
                  key={id}
                  type="button"
                  role="tab"
                  aria-selected={mode === id}
                  onClick={() => setMode(id)}
                  className={`${styles.tabBtn} ${mode === id ? styles.tabBtnActive : ''}`}
                >
                  {m.label}
                </button>
              )
            })}
          </div>

          <div className={styles.observerBar}>
            <button
              type="button"
              className={styles.observerToggle}
              aria-pressed={observer}
              onClick={() => setObserver((o) => !o)}
            >
              {observer ? <EyeOff size={14} aria-hidden="true" /> : <Eye size={14} aria-hidden="true" />}
              {observer ? 'Back to field details' : 'See it as a chain observer'}
            </button>
            <span className={styles.observerLegend} aria-hidden="true">
              <i data-kind="solid" /> hidden
              <i data-kind="hatch" /> partly hidden
            </span>
          </div>

          <div className={styles.tableWrap}>
            <table className={styles.table} data-observer={observer ? 'true' : 'false'}>
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Sender / recipient</th>
                  <th>Token</th>
                  <th>Amount</th>
                  <th>{active.col5Header}</th>
                </tr>
              </thead>
              <tbody key={mode}>
                {active.rows.map((row, rowIdx) => (
                  <tr
                    key={row.method}
                    className={styles.matrixRow}
                    style={
                      {
                        ...(row.highlight ? { background: '#e8efe8' } : {}),
                        animationDelay: `${rowIdx * 60}ms`,
                      } as CSSProperties
                    }
                  >
                    <td>
                      <span className={styles.tableLead} style={{ display: 'block' }}>
                        {row.method}
                      </span>
                      <span style={{ fontSize: 13, color: '#5d6056' }}>{row.sub}</span>
                    </td>
                    <td>
                      <VisCell cell={row.senderRecipient} observer={observer} delayMs={rowIdx * 90} />
                    </td>
                    <td>
                      <VisCell cell={row.token} observer={observer} delayMs={rowIdx * 90 + 70} />
                    </td>
                    <td>
                      <VisCell cell={row.amount} observer={observer} delayMs={rowIdx * 90 + 140} />
                    </td>
                    <td>{row.assets}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <p className={styles.editorialNote}>
            <span className={styles.noteLead}>{active.headline}.</span> {active.note}
          </p>
        </section>

        {/* HEAD-TO-HEAD COMPARISONS */}
        <section className={styles.sectionAlt}>
          <div className="container">
            <div className={styles.sectionIntro}>
              <div>
                <h2>Audren compared head to head.</h2>
              </div>
              <p>
                Every privacy architecture makes concrete tradeoffs across anonymity, proving
                overhead, DeFi composability, cost, and trust assumptions. Compare Audren directly
                against each approach below.
              </p>
            </div>

            <div className={styles.ledger2}>
              {PEER_COMPARISONS.map((peer) => (
                <article key={peer.name} className={styles.ledgerCell}>
                  <span className={styles.cellIndex}>{peer.tag}</span>
                  <h3>{peer.name}</h3>
                  <p className={styles.cellLead}>{peer.lead}</p>
                  <ul className={styles.compareList}>
                    {peer.comparisons.map((item) => (
                      <li key={item.label}>
                        <span className={styles.compareLabel}>{item.label}</span>
                        {item.text}
                      </li>
                    ))}
                  </ul>
                  <div className={styles.cellFoot}>
                    {peer.sources.map((src) => (
                      <a
                        key={src.href}
                        href={src.href}
                        target="_blank"
                        rel="noreferrer"
                        className={styles.textLink}
                      >
                        {src.label} <ArrowUpRight size={12} />
                      </a>
                    ))}
                  </div>
                </article>
              ))}
            </div>
          </div>
        </section>

        {/* DESIGNED BOUNDARIES VS MEASURED PRIVACY */}
        <section className={`container ${styles.section}`}>
          <div className={styles.sectionIntro}>
            <div>
              <h2>Separate designed boundaries from measured privacy.</h2>
            </div>
            <p>
              Evaluate chain-observer privacy, provider visibility, custody and upgrade controls,
              recovery, and independent review separately. Successful transactions do not establish
              a tracing-resistance benchmark.
            </p>
          </div>

          <div className={styles.ledger4}>
            <div className={styles.ledgerCell}>
              <span className={styles.cellIndex}>Anonymity set</span>
              <h3>Global tree ≠ automatic privacy</h3>
              <p className={styles.cellLead}>
                A global 4²⁰ Merkle tree eliminates small ring leaks, but timing, public entry/exit
                amounts, and input-count modes (padded vs omit_nf1) still shape effective anonymity.
              </p>
            </div>
            <div className={styles.ledgerCell}>
              <span className={styles.cellIndex}>Liquidity</span>
              <h3>TVL ≠ privacy</h3>
              <p className={styles.cellLead}>
                More independently owned, plausible activity may help. Raw dollars or TVL alone do
                not establish stronger anonymity.
              </p>
            </div>
            <div className={styles.ledgerCell}>
              <span className={styles.cellIndex}>Accounting</span>
              <h3>Vault assets ≠ solvency</h3>
              <p className={styles.cellLead}>
                Inspectable WSOL and SPL vault accounts show held assets. They do not independently
                reveal or verify all private liabilities.
              </p>
            </div>
            <div className={styles.ledgerCell}>
              <span className={styles.cellIndex}>Assurance</span>
              <h3>Ceremony &amp; audit</h3>
              <p className={styles.cellLead}>
                Audren freezes one minimal 17,861-R1CS circuit anchored to Perpetual Powers of Tau
                (71+ contributors) and Audren’s verifiable BGM17 Phase-2 ceremony; additional
                community contributions remain open and an independent audit is pending.
              </p>
            </div>
          </div>
        </section>

        {/* WHAT AUDREN KEEPS SMALL */}
        <section className={styles.sectionAlt}>
          <div className="container">
            <div className={styles.sectionIntro}>
              <div>
                <h2>What Audren keeps small.</h2>
              </div>
              <p>
                One minimal frozen Groth16 circuit, ordinary Solana RPC discovery with zero
                mandatory indexer, and 9 single-transaction v1 instructions. These choices minimize
                infrastructure without claiming unconditional anonymity.
              </p>
            </div>

            <div className={styles.ledger3}>
              <div className={`${styles.ledgerCell} ${styles.ledgerCellHighlight}`}>
                <span className={styles.cellIndex}>Assets</span>
                <h3>Existing assets</h3>
                <p className={styles.cellLead}>
                  Original SOL (wrapped atomically to WSOL), classic SPL, and transferable
                  Token-2022 enter unified canonical <code>vault_auth</code> ATAs without an
                  Audren-issued wrapper token or bridge.
                </p>
              </div>
              <div className={styles.ledgerCell}>
                <span className={styles.cellIndex}>Proving</span>
                <h3>One 3.93 MB local circuit</h3>
                <p className={styles.cellLead}>
                  One frozen 17,861-R1CS circuit (3.93 MB proving key) generates 192 B BN254
                  Groth16 proofs locally in browser Web Workers and mobile SDKs, avoiding 350
                  MB–1.27 GB multi-shape keys or remote GPU/TEE provers.
                </p>
              </div>
              <div className={styles.ledgerCell}>
                <span className={styles.cellIndex}>Discovery</span>
                <h3>Ordinary Solana RPC only</h3>
                <p className={styles.cellLead}>
                  <code>CompactWalletStore</code> runs a 2-pass sync over{' '}
                  <code>SubtreeRootPage</code>, full 10,240 B <code>MemoPage</code>s, and
                  unconditional <code>NullifierPage</code> streaming via ordinary{' '}
                  <code>getMultipleAccounts</code>, using deterministic wallet-keyed decoys in
                  default <code>strict</code> mode and discarding stranger prefixes and raw pages
                  (1.28 MB @ 10M notes) with no Photon indexer or Forester.
                </p>
              </div>
              <div className={styles.ledgerCell}>
                <span className={styles.cellIndex}>DeFi and exits</span>
                <h3>Live DeFi &amp; pause-immune exits</h3>
                <p className={styles.cellLead}>
                  Send uniformly padded private transfers, batch up to 4 parallel 2 → 1 private{' '}
                  <code>Transact</code> merges per Solana Transaction v1, compose with live Solana
                  DeFi via atomic <code>ExecViaEscrow</code> (~158k CU), fund deterministic session
                  wallets, or exit 100% (including atomic WSOL unwrap) even during{' '}
                  <code>SetPaused</code>.
                </p>
              </div>
              <div className={styles.ledgerCell}>
                <span className={styles.cellIndex}>Openness</span>
                <h3>Open integration</h3>
                <p className={styles.cellLead}>
                  Integrate the Apache-2.0 source, run a compatible client, or host your own relay
                  (including ~6.4s on-demand <code>POST /v1/checkpoint</code>) without an Audren
                  account. Hosted services apply their own policies.
                </p>
              </div>
              <div className={styles.ledgerCell}>
                <span className={styles.cellIndex}>Tradeoffs</span>
                <h3>Pre-audit &amp; permanent rent</h3>
                <p className={styles.cellLead}>
                  Audren remains pre-audit with a mutable upgrade authority and pays permanent{' '}
                  <code>NullifierPDA</code> rent (~0.002–0.0046 SOL/tx, scaling automatically via{' '}
                  <code>SysvarRent</code>) rather than 5,000-lamport Forester-compressed nullifiers.
                </p>
                <div className={styles.cellFoot}>
                  <Link href="/faq" className={styles.textLink}>
                    Read the FAQ <ArrowRight size={13} />
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* CLOSING */}
        <section className={styles.closing}>
          <div className={`container ${styles.closingInner}`}>
            <div>
              <h2>Follow the cryptography step by step.</h2>
              <p>
                See how one reusable <code>aud1…</code> address derives fresh one-time stealth keys,
                blinds amounts, and composes with Solana DeFi protocols and deterministic sessions.
              </p>
            </div>
            <div className={styles.closingActions}>
              <Link href="/how-it-works" className="btn-paper">
                See how it works
              </Link>
              <Link href="/demo" className={styles.closingLink}>
                Open the live app <ArrowRight size={15} />
              </Link>
            </div>
          </div>
        </section>
      </main>

      <SiteFooter current="compare" />
    </div>
  )
}
