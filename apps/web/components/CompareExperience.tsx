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
    note: 'Transaction metadata and the fee payer remain public in every model. A separate relayer keeps your own wallet off the fee-payer field without removing network or timing metadata. Audren defaults to uniform padded private transfers (2 nullifiers, 3 encrypted outputs, random append lane) so the proof shape does not reveal 1-in vs 2-in spends or whether a relayer was paid. The fee-payer account still shows whether a relayer or your own wallet submitted it.',
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
        assets: 'Configured Token-2022 mints only; an optional issuer auditor key can decrypt amounts',
      },
      {
        method: 'Helius Privacy Rings',
        sub: 'Helius (third-party protocol, not native Solana) · default ring',
        senderRecipient: { text: 'Public in the live default ring; anonymous Custom Rings still in audit', state: 'partial' },
        token: { text: 'Encrypted', state: 'hidden' },
        amount: { text: 'Encrypted', state: 'hidden' },
        assets: 'SOL, classic SPL, Token-2022',
      },
      {
        method: 'Audren',
        sub: 'Transact Private Transfer (Tag 5)',
        highlight: true,
        senderRecipient: { text: 'Spent note hidden among all pool notes · one-time stealth owner (sender hidden when relayed)', state: 'hidden' },
        token: { text: 'Hidden inside Poseidon5 commitment', state: 'hidden' },
        amount: { text: 'Hidden inside Poseidon5 commitment', state: 'hidden' },
        assets: 'SOL, classic SPL, transferable Token-2022',
      },
    ],
  },
  'entry-exit': {
    label: 'Deposit & withdraw',
    headline: 'Public entry and exit boundaries, nullifier cost, and pause behavior',
    note: 'Deposits and withdrawals touch ordinary Solana accounts by design. Concealing the spent note on withdrawal does not prevent timing, public amounts, or outside information from creating links. Helius Privacy Rings charges a default 5,000-lamport fee per state tree an instruction updates, and its pause_tree halts withdrawals; Audren charges zero protocol fee, pays permanent nullifier and page rent on-chain (~0.0007–0.0036 SOL/tx at current rent, tracking SysvarRent), and keeps full 100% withdrawals (including atomic WSOL unwrap) available during SetPaused.',
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
        sub: 'Helius (third-party protocol) · public SPL boundary',
        senderRecipient: { text: 'Public SPL boundary; default ring exposes participants', state: 'partial' },
        token: { text: 'Public at entry & exit', state: 'public' },
        amount: { text: 'Public at entry & exit', state: 'public' },
        assets: 'SOL, classic SPL, Token-2022 · 5,000-lamport fee per state tree updated · pause_tree halts exits',
      },
      {
        method: 'Privacy Cash',
        sub: 'Asset-specific Groth16 Merkle pools',
        senderRecipient: { text: 'Public depositor / destination; Merkle proof hides which deposit is spent', state: 'partial' },
        token: { text: 'Public pool asset', state: 'public' },
        amount: { text: 'Public at entry & exit', state: 'public' },
        assets: 'Supported pool assets; separate Merkle tree per asset',
      },
      {
        method: 'Audren',
        sub: 'Unified Deposit (Tag 3) · Transact Exit (Tag 5)',
        highlight: true,
        senderRecipient: { text: 'Depositor wallet and exit recipient public; the exit proof hides which note was spent', state: 'partial' },
        token: { text: 'Public at entry & exit', state: 'public' },
        amount: { text: 'Public at entry & exit (change hidden)', state: 'public' },
        assets: 'SOL (WSOL), classic SPL, Token-2022 · zero protocol fee · issuer freeze / delegate controls apply to the shared vault · permanent rent ~0.0007–0.0036 SOL/tx · full exits incl. atomic WSOL unwrap bypass SetPaused',
      },
    ],
  },
  swap: {
    label: 'Shielded DeFi',
    headline: 'Composing with live Solana DeFi vs. custom per-app circuits',
    note: 'Two architectural paths exist for shielded DeFi on Solana. Helius Privacy Rings requires each app to build custom ZK proofs for private DeFi CPI (where amounts and prices stay hidden), while public withdraw → swap → deposit flows lack a built-in sharded-escrow measured-delta CPI (its public deposit takes a fixed amount and its live default ring exposes wallets). Audren takes the permissionless, protocol-agnostic path: atomic ExecViaEscrow (Tag 6) composes directly with unmodified Mainnet liquidity in one transaction (~165k–238k CU base / 285k budget plus the route), with verified Mainnet transactions across Jupiter, DFlow, JitoSOL, JLP, Kamino Lending (USDC ⇄ cUSDC), and Kamino Prime USDC Yield Vault (and OKX quoted on the hosted relay), keeping the external DeFi pair and amount public while hiding which pool note funded it (plus deterministic Bᵢ session wallets with zero-dust sweeps for stateful borrowing or perps).',
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
        sub: 'Helius (third-party protocol) · per-app custom ZK CPIs',
        senderRecipient: { text: 'Public in the live default ring; anonymous Custom Rings in audit', state: 'partial' },
        token: { text: 'Can stay private inside custom app-specific ZK programs', state: 'hidden' },
        amount: { text: 'Can stay private inside custom app-specific ZK programs', state: 'hidden' },
        assets: 'Custom ZK circuits required for private CPI; public swap composition lacks built-in sharded-escrow measured-delta reshielding',
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
        senderRecipient: { text: 'Pool proof hides the funding note · shared escrow signs (or Bᵢ session) · fresh stealth note', state: 'partial' },
        token: { text: 'Public external DeFi mints', state: 'public' },
        amount: { text: 'Public external DeFi amounts (optional hidden change)', state: 'public' },
        assets: 'Verified on Mainnet in 1 tx across Jupiter, DFlow, JitoSOL, JLP, Kamino Lending & Kamino Vaults (OKX quoted on relay; ~165k–238k CU base + route) + zero-dust Bᵢ sessions',
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
    tag: 'Third-party ring protocol',
    name: 'Audren vs. Helius Privacy Rings',
    lead: 'Helius Privacy Rings is a third-party Helius protocol (not native Solana). Both shield existing SOL, SPL, and Token-2022 assets, while diverging sharply on default privacy, infrastructure dependencies, DeFi composability, and pause-immune exits.',
    comparisons: [
      {
        label: 'Default visibility',
        text: 'Helius’s live default ring encrypts token and amount while leaving sender and recipient wallets public; anonymous Custom Rings remain in audit. Audren hides spent notes, stealth recipient, token, and amount by default today across one shared pool.',
      },
      {
        label: 'Proving & state discovery',
        text: 'Helius Privacy Rings depends on a Photon indexer (self-hostable), a permissioned Forester for tree maintenance, and local or remote GPU proving. Audren proves locally from one frozen 3.93 MB key and syncs directly from ordinary Solana RPC with zero indexer and zero Forester (at the cost of downloading full pages as the pool grows).',
      },
      {
        label: 'DeFi composability',
        text: 'Helius Privacy Rings requires each DeFi app to add custom ZK proofs for private DeFi CPI (where trade amounts stay hidden), while public withdraw → swap → deposit flows lack a built-in sharded-escrow measured-delta CPI and the live default ring exposes wallets. Audren’s atomic ExecViaEscrow composes permissionlessly in one transaction with unmodified Mainnet liquidity across Jupiter, DFlow, JitoSOL, JLP, Kamino Lending, and Kamino Prime USDC Vault (with OKX also quoted on the hosted relay, keeping the external DeFi leg public).',
      },
      {
        label: 'Fees, instant spendability & exits',
        text: 'Helius Privacy Rings charges a default 5,000-lamport fee per state tree updated and its pause_tree halts withdrawals. Audren charges zero protocol fee, pays live Solana SysvarRent for permanent nullifier and page storage (~0.0007–0.0036 SOL/tx at current rent), updates GlobalRootHistory inline for instant spendability on ~150ms Alpenglow finality with zero cranks (auto-prepended OpenPage), and keeps full 100% exits (including atomic WSOL unwrap) executable even during SetPaused.',
      },
      {
        label: 'Review & maturity',
        text: 'Helius’s program and circuits have published audits by Certora, zkSecurity, and OtterSec and a 15-contribution trusted setup per circuit. Audren is Apache-2.0 open source with a verified Mainnet Docker build (verify.osec.io), an independent audit pending, and a Phase-2 setup with only Audren’s contributions so far.',
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
        text: 'Privacy Cash withdraws to an ephemeral wallet, trades on Jupiter, and reshields across multiple transactions. Audren settles aggregator swaps, Kamino Lending supply/redeem, and Kamino Yield Vault deposit/withdraw atomically in one transaction via ExecViaEscrow (~165k–238k CU base / 285k budget plus the route), plus deterministic Bᵢ session wallets with zero-dust sweeps for stateful protocols.',
      },
      {
        label: 'Sync & local state',
        text: 'Audren syncs directly from ordinary Solana RPC getMultipleAccounts over fixed <10 KiB pages (CompactWalletStore keeps ~1.28 MB at 10M notes) without a dedicated indexer. A cold sync still downloads every memo and nullifier page, so bandwidth grows with the pool.',
      },
      {
        label: 'Review & maturity',
        text: 'Privacy Cash has published independent audits (including HashCloak). Audren is Apache-2.0 open source with a reproducible Mainnet build verified via OtterSec’s verify.osec.io (bytecode matches source; not an audit) and a Phase-2 ceremony with only Audren’s contributions so far; no independent audit yet.',
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
        text: 'Dedicated privacy chains have limited on-chain DeFi. Audren composes atomically in one transaction with live Solana DEX aggregators, Kamino Lending, and Kamino Yield Vaults via ExecViaEscrow, and with stateful protocols through zero-dust deterministic session wallets.',
      },
      {
        label: 'Proof system & setup',
        text: 'Monero uses ring signatures with no trusted setup and Zcash Orchard uses Halo 2 with no trusted setup. Audren uses one frozen 17,861-R1CS BN254 Groth16 circuit (Hermez Powers of Tau + Audren’s two-contribution BGM17 Phase 2) so proofs stay 192 B and verify via Solana’s native alt_bn128 syscalls.',
      },
      {
        label: 'Production track record',
        text: 'Monero and Zcash carry years of adversarial review and production history. Audren is a newer Solana protocol and does not claim stronger privacy assurance than dedicated privacy L1s.',
      },
    ],
    sources: [
      { label: 'Monero specs', href: 'https://docs.getmonero.org/technical-specs/' },
      { label: 'Zcash protocol spec', href: 'https://zips.z.cash/protocol/protocol.pdf' },
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
        text: 'Nimbus relies on enclave hardware and attester assumptions, with an operator-free escape hatch that pays out after a delay. Arcium’s Cerberus MPC is dishonest-majority (privacy holds if one cluster node is honest) but detect-and-abort, so liveness needs every node. Audren verifies every spend purely in on-chain BN254 Groth16 math with spending keys remaining strictly on your device.',
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
              <h1>How Audren compares to other privacy models.</h1>
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
                Token-2022 mints while leaving sender, recipient, and mint public. In relayed private
                transfers, Audren hides all four fields across SOL, classic SPL, and transferable
                Token-2022 inside one shared pool.
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
                One shared 4²⁰ Merkle tree avoids decoy-ring selection leaks, but timing, public entry/exit
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
                Audren freezes one minimal 17,861-R1CS circuit anchored to the Hermez Perpetual Powers of Tau
                (54 contributions plus a beacon) and Audren’s two-contribution BGM17 Phase-2 ceremony; additional
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
                <h3>One 3.93 MB proving key</h3>
                <p className={styles.cellLead}>
                  One frozen 17,861-R1CS circuit (3.93 MB proving key) generates 192 B BN254
                  Groth16 proofs locally in browser Web Workers and native SDKs, with no remote
                  prover in the path.
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
                  (~1.28 MB kept @ 10M notes) with no Photon indexer or Forester. Cold-sync
                  bandwidth still grows with the pool.
                </p>
              </div>
              <div className={styles.ledgerCell}>
                <span className={styles.cellIndex}>DeFi and exits</span>
                <h3>Live DeFi &amp; pause-immune exits</h3>
                <p className={styles.cellLead}>
                  Send uniformly padded private transfers, batch up to 4 parallel 2 → 1 private{' '}
                  <code>Transact</code> merges per Solana Transaction v1, execute DEX swaps, Kamino
                  Lending, and Kamino Yield Vault calls atomically via <code>ExecViaEscrow</code>{' '}
                  (~165k–238k CU base + route), fund zero-dust deterministic session wallets, or
                  exit 100% (including atomic WSOL unwrap) even during <code>SetPaused</code>.
                </p>
              </div>
              <div className={styles.ledgerCell}>
                <span className={styles.cellIndex}>Openness</span>
                <h3>Permissionless on-chain IDL</h3>
                <p className={styles.cellLead}>
                  Call the Apache-2.0 on-chain program directly from its published Codama and
                  Anchor IDLs with any client, drop in our optional Rust/TS/Swift/Kotlin SDKs for
                  convenience, or host your own zero-crank relay without an Audren account.
                </p>
              </div>
              <div className={styles.ledgerCell}>
                <span className={styles.cellIndex}>Tradeoffs</span>
                <h3>Pre-audit &amp; permanent rent</h3>
                <p className={styles.cellLead}>
                  Audren remains pre-audit with a mutable upgrade authority, pays permanent nullifier
                  and page rent (~0.0007–0.0036 SOL/tx at current rent, tracking{' '}
                  <code>SysvarRent</code>), and shares one vault per token, so issuer freeze or
                  delegate controls reach every holder of that token.
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
