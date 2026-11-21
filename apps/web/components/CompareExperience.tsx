'use client'

import { useState } from 'react'
import Link from 'next/link'
import { ArrowLeft, ArrowRight, ArrowUpRight, Eye, EyeOff } from 'lucide-react'
import { SiteHeader } from '@/components/SiteHeader'
import { SiteFooter } from '@/components/SiteFooter'
import styles from '@/components/SubpageShell.module.css'

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

const MODE_META: Record<ModeId, { label: string; headline: string; note: string; rows: ComparisonRow[] }> = {
  transfer: {
    label: 'Private transfer',
    headline: 'What a public Solana observer sees on a peer-to-peer transfer',
    note: 'Transaction metadata and the fee payer remain public in every model. A separate relayer keeps your own wallet off the fee-payer field without removing network or timing metadata.',
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
        sub: 'Default vs. custom anonymous ring',
        senderRecipient: { text: 'Public in default; hidden in custom mode', state: 'partial' },
        token: { text: 'Ring-dependent', state: 'partial' },
        amount: { text: 'Encrypted', state: 'hidden' },
        assets: 'SOL, classic SPL, Token-2022',
      },
      {
        method: 'Audren',
        sub: 'Private Transfer (Tag 3)',
        highlight: true,
        senderRecipient: { text: 'Hidden input · one-time recipient key', state: 'hidden' },
        token: { text: 'Blinded asset tag', state: 'hidden' },
        amount: { text: 'Blinded commitment', state: 'hidden' },
        assets: 'SOL, classic SPL, transferable Token-2022',
      },
    ],
  },
  'entry-exit': {
    label: 'Deposit & withdraw',
    headline: 'Public entry and exit boundaries when moving ordinary Solana assets',
    note: 'Deposits and withdrawals touch ordinary Solana accounts by design. Concealing the spent note on withdrawal does not prevent timing, public amounts, or outside information from creating links.',
    rows: [
      {
        method: 'Ordinary Solana',
        sub: 'Direct wallet movement',
        senderRecipient: { text: 'Public accounts', state: 'public' },
        token: { text: 'Public mint', state: 'public' },
        amount: { text: 'Public', state: 'public' },
        assets: 'SOL & all tokens',
      },
      {
        method: 'Confidential Balances',
        sub: 'Deposit / withdraw confidential balance',
        senderRecipient: { text: 'Public owner account', state: 'public' },
        token: { text: 'Public mint', state: 'public' },
        amount: { text: 'Public at boundary', state: 'public' },
        assets: 'Configured Token-2022 mints',
      },
      {
        method: 'Privacy Cash',
        sub: 'Asset-specific Groth16 Merkle pools',
        senderRecipient: { text: 'Public depositor / destination; link broken by tree proof', state: 'partial' },
        token: { text: 'Public pool asset', state: 'public' },
        amount: { text: 'Public at entry & exit', state: 'public' },
        assets: 'Supported pool assets',
      },
      {
        method: 'Audren',
        sub: 'Deposit (Tag 2) · Withdraw (Tag 6)',
        highlight: true,
        senderRecipient: { text: 'One-time output on deposit; hidden source on withdraw', state: 'partial' },
        token: { text: 'Public at entry & exit', state: 'public' },
        amount: { text: 'Public at entry & exit (change blinded)', state: 'public' },
        assets: 'SOL, classic SPL, transferable Token-2022',
      },
    ],
  },
  swap: {
    label: 'Shielded DeFi',
    headline: 'Composing with public Solana DeFi (DEXs, lending, LSTs, vaults)',
    note: 'Solana DEXs, lending markets, liquid staking pools, and perp protocols are public state machines: external calls always observe the target program, mints, and routed amounts. The difference is whether your primary wallet signs publicly or settles atomically via sharded escrow (ExecViaEscrow) or a self-funded deterministic session wallet.',
    rows: [
      {
        method: 'Ordinary Solana',
        sub: 'Direct wallet swap via aggregator / AMM',
        senderRecipient: { text: 'Your public wallet signs', state: 'public' },
        token: { text: 'Public pair', state: 'public' },
        amount: { text: 'Public trade size', state: 'public' },
        assets: 'All Solana DEX pairs',
      },
      {
        method: 'Confidential Balances',
        sub: 'Must withdraw to public balance first',
        senderRecipient: { text: 'Your public wallet signs', state: 'public' },
        token: { text: 'Public pair', state: 'public' },
        amount: { text: 'Public trade size', state: 'public' },
        assets: 'Public SPL after unwrapping',
      },
      {
        method: 'Privacy Cash',
        sub: 'Withdraw to ephemeral wallet → Jupiter → reshield',
        senderRecipient: { text: 'Ephemeral wallet trades (primary wallet hidden)', state: 'partial' },
        token: { text: 'Public pair', state: 'public' },
        amount: { text: 'Public trade size', state: 'public' },
        assets: 'Supported pool assets',
      },
      {
        method: 'Audren',
        sub: 'Atomic ExecViaEscrow (Tag 5) + Self-Paying DeFi Sessions (Tag 6 + Tag 2)',
        highlight: true,
        senderRecipient: { text: 'Hidden input · shared escrow CPI (or Bᵢ session) · fresh output note', state: 'partial' },
        token: { text: 'Public external DeFi mints', state: 'public' },
        amount: { text: 'Public external DeFi amounts (optional blinded change)', state: 'public' },
        assets: 'Any compatible Token A → B DeFi CPI (DEX, lend, LST, vault, RWA) + stateful Bᵢ sessions',
      },
    ],
  },
}

const PEER_PROTOCOLS = [
  {
    tag: 'SOLANA RINGS',
    name: 'Helius Privacy Rings',
    lead: 'Supports existing SOL, SPL and Token-2022 assets, self-custody, and programmable escrow, with published independent program and circuit reviews.',
    points: [
      'Default confidential ring exposes sender and recipient; anonymous custom rings are a separate mode with separate availability and audit scope.',
      'Documented anonymous-ring integration uses delegated viewing access for sync (no spend authority).',
      'Indexer and Forester maintain tree state; proofs can be generated locally and indexers can be self-hosted.',
      'Groth16 circuits rely on multi-party trusted-setup records and proving keys.',
    ],
    sources: [
      { label: 'Encryption modes', href: 'https://www.helius.dev/docs/privacy/concepts/encryption' },
      { label: 'Architecture', href: 'https://www.helius.dev/docs/privacy/concepts/architecture' },
      { label: 'Security evidence', href: 'https://www.helius.dev/docs/privacy/security' },
      { label: 'Deployments', href: 'https://www.helius.dev/docs/privacy/addresses' },
    ],
  },
  {
    tag: 'GROTH16 MERKLE',
    name: 'Privacy Cash',
    lead: 'Groth16 membership proofs over asset-specific Merkle trees with published independent audits and ephemeral-wallet Jupiter routing.',
    points: [
      'Tree-based membership proofs do not publish a small explicit ring of candidate inputs.',
      'Documented swap flow withdraws to an ephemeral wallet, trades on Jupiter, and reshields — concealing the primary wallet while keeping DEX trade details public.',
      'Existing assets, local proving, and deposit-to-withdrawal unlinking are not unique to Audren.',
      'Actual privacy still depends on public boundaries, timing, and external observations.',
    ],
    sources: [
      { label: 'User flows & limits', href: 'https://privacycash.mintlify.app/' },
      { label: 'HashCloak audit case study', href: 'https://hashcloak.com/case-studies/privacy-cash-audit-case-study' },
    ],
  },
  {
    tag: 'DEDICATED L1S',
    name: 'Monero & Zcash',
    lead: 'Dedicated privacy networks rather than direct integrations for existing Solana assets.',
    points: [
      'Monero makes ordinary payments private by default using ring signatures, stealth recipients, and confidential amounts.',
      'Zcash shielded proofs prove pool-tree membership without publishing a small ring; modern Halo 2 proofs need no trusted setup.',
      'Transparent legs and pool transitions remain important boundaries.',
      'Neither a larger Audren ring nor Solana compatibility establishes stronger privacy or assurance than these systems.',
    ],
    sources: [
      { label: 'Monero specs', href: 'https://docs.getmonero.org/technical-specs/' },
      { label: 'Zcash pool design', href: 'https://zcash.github.io/ironwood/design.html' },
      { label: 'Halo 2 (ZIP-224)', href: 'https://zips.z.cash/zip-0224' },
    ],
  },
  {
    tag: 'ENCLAVES & MPC',
    name: 'Nimbus, Umbra & Arcium',
    lead: 'Enclave and MPC privacy infrastructure targeting broader computation models beyond payment proofs.',
    points: [
      'Do not conflate historical Umbra SDK documentation with Nimbus’s current architecture.',
      'Nimbus documents attester/enclave dependencies and an emergency exit with distinct privacy and availability properties.',
      'Arcium targets general multi-party computation (MPC) on private inputs with cluster honesty and availability assumptions.',
      'Additional infrastructure can enable capabilities payment-only pools do not provide.',
    ],
    sources: [
      { label: 'Nimbus assumptions', href: 'https://docs.nimbusprivacy.xyz/security/assumptions' },
      { label: 'Nimbus exits', href: 'https://docs.nimbusprivacy.xyz/security/liveness' },
      { label: 'Arcium MPC model', href: 'https://docs.arcium.com/multi-party-execution-environments-mxes/mpc-protocols' },
    ],
  },
] as const

export function CompareExperience() {
  const [mode, setMode] = useState<ModeId>('transfer')
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
              <h1>Private numbers are one part of the story.</h1>
              <p className={styles.heroLead}>
                Compare Solana privacy approaches by what an observer can learn, which assets work
                without wrapping, what infrastructure is required, and what independent review
                exists. Self-custody and open source matter; they are not exclusive to Audren.
              </p>
            </div>
            <div className={styles.diagramStagePaper}>
              <div className={styles.stageHead}>
                <strong>Native Confidential Balances scope</strong>
                <span>Token-2022 extension</span>
              </div>
              <p style={{ margin: '0 0 12px', fontSize: 13, lineHeight: 1.6, color: '#464a40' }}>
                Solana’s native Confidential Balances encrypt transfer amounts on configured
                Token-2022 mints while account relationships and mint identity remain visible.
              </p>
              <a
                className={styles.textLink}
                style={{ fontSize: 12.5 }}
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
              and external DEX swaps. Switch views below to compare every field directly.
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

          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Sender / Recipient</th>
                  <th>Token</th>
                  <th>Amount</th>
                  <th>Asset Scope</th>
                </tr>
              </thead>
              <tbody>
                {active.rows.map((row) => (
                  <tr
                    key={row.method}
                    style={row.highlight ? { background: '#f1f5ee' } : undefined}
                  >
                    <td>
                      <strong style={{ display: 'block', color: '#121210' }}>{row.method}</strong>
                      <span style={{ fontSize: 11.5, color: '#5d6056' }}>{row.sub}</span>
                    </td>
                    <td>
                      <span
                        className={
                          row.senderRecipient.state === 'hidden'
                            ? styles.visHidden
                            : row.senderRecipient.state === 'public'
                              ? styles.visPublic
                              : styles.visPartial
                        }
                        style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}
                      >
                        {row.senderRecipient.state === 'hidden' ? (
                          <EyeOff size={12} />
                        ) : (
                          <Eye size={12} />
                        )}
                        {row.senderRecipient.text}
                      </span>
                    </td>
                    <td
                      className={
                        row.token.state === 'hidden'
                          ? styles.visHidden
                          : row.token.state === 'public'
                            ? styles.visPublic
                            : styles.visPartial
                      }
                    >
                      {row.token.text}
                    </td>
                    <td
                      className={
                        row.amount.state === 'hidden'
                          ? styles.visHidden
                          : row.amount.state === 'public'
                            ? styles.visPublic
                            : styles.visPartial
                      }
                    >
                      {row.amount.text}
                    </td>
                    <td>{row.assets}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <p className={styles.editorialNote}>
            <strong>{active.headline}.</strong> {active.note}
          </p>
        </section>

        {/* PEER PROTOCOLS LEDGER */}
        <section className={styles.sectionAlt}>
          <div className="container">
            <div className={styles.sectionIntro}>
              <div>
                <h2>Other protocols also offer privacy.</h2>
              </div>
              <p>
                The meaningful distinction is the cryptographic mechanism, operational dependencies,
                and review evidence — not a claim that other systems cannot provide privacy.
              </p>
            </div>

            <div className={styles.ledger2}>
              {PEER_PROTOCOLS.map((peer) => (
                <article key={peer.name} className={styles.ledgerCell}>
                  <span className={styles.cellIndex}>{peer.tag}</span>
                  <h3>{peer.name}</h3>
                  <p className={styles.cellLead}>{peer.lead}</p>
                  <ul className={styles.dashList}>
                    {peer.points.map((pt) => (
                      <li key={pt}>{pt}</li>
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
              <h2>Designed boundaries, measured privacy.</h2>
            </div>
            <p>
              Evaluate chain-observer privacy, provider visibility, custody and upgrade controls,
              recovery, and independent review separately. Successful transactions do not establish
              a tracing-resistance benchmark.
            </p>
          </div>

          <div className={styles.ledger4}>
            <div className={styles.ledgerCell}>
              <span className={styles.cellIndex}>CANDIDATES</span>
              <h3>Ring capacity ≠ users</h3>
              <p className={styles.cellLead}>
                32 / 64 / 128 slots describe ring capacity. Populated records, candidate selection,
                and known public data determine how many inputs remain plausible.
              </p>
            </div>
            <div className={styles.ledgerCell}>
              <span className={styles.cellIndex}>LIQUIDITY</span>
              <h3>TVL ≠ privacy</h3>
              <p className={styles.cellLead}>
                More independently owned, plausible activity may help. Raw dollars or TVL alone do
                not establish stronger anonymity.
              </p>
            </div>
            <div className={styles.ledgerCell}>
              <span className={styles.cellIndex}>ACCOUNTING</span>
              <h3>Vault assets ≠ solvency</h3>
              <p className={styles.cellLead}>
                Inspectable SOL and SPL vault accounts show held assets. They do not independently
                reveal or verify all private liabilities.
              </p>
            </div>
            <div className={styles.ledgerCell}>
              <span className={styles.cellIndex}>ASSURANCE</span>
              <h3>Audit evidence</h3>
              <p className={styles.cellLead}>
                Published audits cover specific review scopes. Audren is pre-audit and upgradeable
                and does not yet have equivalent independent review evidence.
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
                Transparent proofs with zero trusted setup and minimal moving parts. These choices
                simplify integration; they do not by themselves make Audren more private, more
                secure, or faster than another system.
              </p>
            </div>

            <div className={styles.ledger3}>
              <div className={`${styles.ledgerCell} ${styles.ledgerCellHighlight}`}>
                <span className={styles.cellIndex}>ASSETS</span>
                <h3>Existing assets</h3>
                <p className={styles.cellLead}>
                  Original SOL, classic SPL, and transferable Token-2022 enter program-controlled
                  vaults without an Audren-issued wrapper token or bridge. SOL DEX routes can use
                  wSOL.
                </p>
              </div>
              <div className={styles.ledgerCell}>
                <span className={styles.cellIndex}>PROVING</span>
                <h3>Local proving</h3>
                <p className={styles.cellLead}>
                  Clients derive keys and build proofs locally. Optional permissionless relayers
                  submit authorized transactions without spending keys.
                </p>
              </div>
              <div className={styles.ledgerCell}>
                <span className={styles.cellIndex}>DISCOVERY</span>
                <h3>Standard RPC only</h3>
                <p className={styles.cellLead}>
                  Discover private records via standard Solana account RPC and WebSocket dataSlices.
                  No protocol-specific indexer or proving service is required.
                </p>
              </div>
              <div className={styles.ledgerCell}>
                <span className={styles.cellIndex}>SURFACE</span>
                <h3>Unified workflow</h3>
                <p className={styles.cellLead}>
                  Deposit, transfer, merge notes, swap through a compatible router, withdraw to any
                  public address, or disclose a single receipt.
                </p>
              </div>
              <div className={styles.ledgerCell}>
                <span className={styles.cellIndex}>OPENNESS</span>
                <h3>Open integration</h3>
                <p className={styles.cellLead}>
                  Integrate the Apache-2.0 source, run a compatible client, or host your own relay
                  without an Audren account. Hosted services apply their own policies.
                </p>
              </div>
              <div className={styles.ledgerCell}>
                <span className={styles.cellIndex}>DISCLOSURE</span>
                <h3>Pre-audit transparency</h3>
                <p className={styles.cellLead}>
                  Audren remains pre-audit with a mutable upgrade authority. Read the exact
                  boundaries before committing capital.
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
                blinds amounts, and settles through Solana DEX liquidity.
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
