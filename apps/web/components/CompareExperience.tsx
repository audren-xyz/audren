'use client'

import { useState } from 'react'
import Link from 'next/link'
import { ArrowLeft, ArrowRight, ArrowUpRight } from 'lucide-react'
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
        sub: 'JoinSplit Private Transfer (Tag 6)',
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
        sub: 'DepositSol / DepositSpl (Tags 3–4) · JoinSplit Exit (Tag 6)',
        highlight: true,
        senderRecipient: { text: 'One-time stealth output on deposit; global pool proof on exit', state: 'partial' },
        token: { text: 'Public at entry & exit', state: 'public' },
        amount: { text: 'Public at entry & exit (change hidden)', state: 'public' },
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
        sub: 'Atomic ExecViaEscrow (Tag 7) + Self-Paying DeFi Sessions (Tag 6 + Tag 3)',
        highlight: true,
        senderRecipient: { text: 'Global pool proof · sharded escrow CPI (or Bᵢ session) · fresh stealth note', state: 'partial' },
        token: { text: 'Public external DeFi mints', state: 'public' },
        amount: { text: 'Public external DeFi amounts (optional hidden change)', state: 'public' },
        assets: 'Any compatible Token A → B DeFi CPI (DEX, lend, LST, vault, RWA) + stateful Bᵢ sessions',
      },
    ],
  },
}

const PEER_PROTOCOLS = [
  {
    tag: 'Solana rings',
    name: 'Helius Privacy Rings',
    lead: 'Supports existing SOL, SPL, and Token-2022 assets, self-custody, and programmable escrow, with published independent program and circuit reviews.',
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
    tag: 'Groth16 Merkle',
    name: 'Privacy Cash',
    lead: 'Groth16 membership proofs over asset-specific Merkle trees with published independent audits and ephemeral-wallet Jupiter routing.',
    points: [
      'Tree-based membership proofs do not publish a small explicit ring of candidate inputs.',
      'Documented swap flow withdraws to an ephemeral wallet, trades on Jupiter, and reshields, concealing the primary wallet while keeping DEX trade details public.',
      'Existing assets, local proving, and deposit-to-withdrawal unlinking are not unique to Audren.',
      'Actual privacy still depends on public boundaries, timing, and external observations.',
    ],
    sources: [
      { label: 'User flows & limits', href: 'https://privacycash.mintlify.app/' },
      { label: 'HashCloak audit case study', href: 'https://hashcloak.com/case-studies/privacy-cash-audit-case-study' },
    ],
  },
  {
    tag: 'Dedicated L1s',
    name: 'Monero & Zcash',
    lead: 'Dedicated privacy networks rather than direct integrations for existing Solana assets.',
    points: [
      'Monero makes ordinary payments private by default using ring signatures, stealth recipients, and confidential amounts.',
      'Zcash shielded proofs prove pool-tree membership without publishing a small ring; modern Halo 2 proofs need no trusted setup.',
      'Transparent legs and pool transitions remain important boundaries.',
      'Neither a larger Audren global pool nor Solana compatibility establishes stronger privacy or assurance than these systems.',
    ],
    sources: [
      { label: 'Monero specs', href: 'https://docs.getmonero.org/technical-specs/' },
      { label: 'Zcash pool design', href: 'https://zcash.github.io/ironwood/design.html' },
      { label: 'Halo 2 (ZIP-224)', href: 'https://zips.z.cash/zip-0224' },
    ],
  },
  {
    tag: 'Enclaves and MPC',
    name: 'Nimbus, Umbra & Arcium',
    lead: 'Enclave and MPC privacy infrastructure targeting broader computation models beyond payment proofs.',
    points: [
      'Do not conflate historical Umbra SDK documentation with Nimbus’s current architecture.',
      'Nimbus documents attester and enclave dependencies and an emergency exit with distinct privacy and availability properties.',
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
                <div className={styles.stageTitle}>Native Confidential Balances scope</div>
                <span>Token-2022 extension</span>
              </div>
              <p className={styles.cellLead} style={{ marginBottom: 12 }}>
                Solana’s native Confidential Balances encrypt transfer amounts on configured
                Token-2022 mints while account relationships and mint identity remain visible.
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
                    style={row.highlight ? { background: '#e8efe8' } : undefined}
                  >
                    <td>
                      <span className={styles.tableLead} style={{ display: 'block' }}>
                        {row.method}
                      </span>
                      <span style={{ fontSize: 13, color: '#5d6056' }}>{row.sub}</span>
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
                      >
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
            <span className={styles.noteLead}>{active.headline}.</span> {active.note}
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
                and review evidence, not a claim that other systems cannot provide privacy.
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
                Inspectable SOL and SPL vault accounts show held assets. They do not independently
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
                  Original SOL, classic SPL, and transferable Token-2022 enter unified custody
                  vaults without an Audren-issued wrapper token or bridge.
                </p>
              </div>
              <div className={styles.ledgerCell}>
                <span className={styles.cellIndex}>Proving</span>
                <h3>Local Groth16 proving</h3>
                <p className={styles.cellLead}>
                  Clients generate 192 B BN254 Groth16 proofs locally (native Rust/Swift/Kotlin or
                  browser WASM). Optional permissionless relayers submit without spending keys.
                </p>
              </div>
              <div className={styles.ledgerCell}>
                <span className={styles.cellIndex}>Discovery</span>
                <h3>Ordinary Solana RPC only</h3>
                <p className={styles.cellLead}>
                  <code>CompactWalletStore</code> scans sequential pages via{' '}
                  <code>getMultipleAccounts</code>, freezes sealed siblings, and discards raw pages
                  (1.28 MB @ 10M notes) with no mandatory indexer or CDN.
                </p>
              </div>
              <div className={styles.ledgerCell}>
                <span className={styles.cellIndex}>Surface</span>
                <h3>Unified workflow</h3>
                <p className={styles.cellLead}>
                  Deposit, transfer, merge notes, execute compatible DeFi CPIs, withdraw or fund
                  deterministic session wallets, or disclose a single receipt.
                </p>
              </div>
              <div className={styles.ledgerCell}>
                <span className={styles.cellIndex}>Openness</span>
                <h3>Open integration</h3>
                <p className={styles.cellLead}>
                  Integrate the Apache-2.0 source, run a compatible client, or host your own relay
                  without an Audren account. Hosted services apply their own policies.
                </p>
              </div>
              <div className={styles.ledgerCell}>
                <span className={styles.cellIndex}>Disclosure</span>
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
