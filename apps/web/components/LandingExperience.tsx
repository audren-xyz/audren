'use client'

import { useState, type KeyboardEvent } from 'react'
import Link from 'next/link'
import { ArrowRight, ArrowUpRight } from 'lucide-react'
import { SiteHeader } from '@/components/SiteHeader'
import { SiteFooter } from '@/components/SiteFooter'
import { AUDREN, explorerAddress, solscanAddress, solscanTx } from '@/lib/protocol'
import styles from './LandingExperience.module.css'

type CaseId = 'pay' | 'swap' | 'withdraw' | 'receipt'

interface ProtocolStep {
  phase: string
  headline: string
  detail: string
}

interface PoolCase {
  id: CaseId
  tab: string
  stageMeta: string
  title: string
  detail: string
  steps: readonly [ProtocolStep, ProtocolStep, ProtocolStep]
  resultText: string
  hiddenLabel: string
  publicLabel: string
  txHref: string | null
  txLabel: string
  tone: 'pool' | 'exit' | 'receipt'
}

const POOL_CASES: readonly PoolCase[] = [
  {
    id: 'pay',
    tab: 'Pay someone',
    stageMeta: 'Global MASP · Transact (Tag 5)',
    title: 'Pay privately with existing tokens.',
    detail:
      'Pay any reusable Bech32m aud1… address with SOL, Classic SPL, or Token-2022 inside a single global Multi-Asset Shielded Pool (4-ary Depth-20 Merkle tree, 1.099T note capacity). A 192-byte Groth16 proof conceals the spent notes across the entire pool history and creates fresh one-time stealth outputs with hidden asset and amount. Timing and external information can still create links.',
    steps: [
      {
        phase: 'Input',
        headline: 'Pool #0 note',
        detail: 'Any historical leaf in the 4^20 tree',
      },
      {
        phase: 'Verification',
        headline: '192 B Groth16 proof',
        detail: 'NullifierPDA and value conservation',
      },
      {
        phase: 'Settlement',
        headline: 'Fresh stealth note',
        detail: 'Poseidon stealth owner, all 4 fields hidden',
      },
    ],
    resultText:
      'Private Transact settles in ~130k CU with hidden inputs, stealth recipient, hidden asset, and hidden amount.',
    hiddenLabel: 'Spent notes across global pool, recipient, token, and amount',
    publicLabel: 'Checkpoint root, lane append slot, timing, and fee payer',
    txHref: solscanTx(AUDREN.mainnet.transferTx),
    txLabel: 'Inspect settled private send',
    tone: 'pool',
  },
  {
    id: 'swap',
    tab: 'Shielded DeFi',
    stageMeta: 'Isolated escrow CPI · ExecViaEscrow (Tag 6)',
    title: 'Swap, lend, stake, or deploy in DeFi and return to the pool.',
    detail:
      'ExecViaEscrow turns any SPL or Token-2022 Token A → Token B Solana program call into a single shielded Transaction v1: DEX swaps (Jupiter, Titan, DFlow, Raydium, Orca) alongside lending supply (kTokens), yield vaults, liquid staking (JitoSOL, INF), perp LP (JLP), and RWA mint or redeem. Native relayer fees settle from input or output tokens (EXEC_FLAG_FEE_ON_OUTPUT); external DeFi amounts, mints, and output record remain public.',
    steps: [
      {
        phase: 'Escrow out',
        headline: 'Sharded escrow PDA',
        detail: 'Pool spends input note via isolated shard',
      },
      {
        phase: 'External CPI',
        headline: 'Any Solana DeFi program',
        detail: 'DEX, lending reserve, stake pool, or vault',
      },
      {
        phase: 'Reshield',
        headline: 'Measured net delta',
        detail: 'Output token and change swept back to pool',
      },
    ],
    resultText:
      'Output token or yield receipt settles straight into a fresh dynamic pool note (~158k CU, leaving >1.2M CU for DeFi).',
    hiddenLabel: 'Spent pool notes and primary user wallet',
    publicLabel: 'External DeFi program, mints, routed amounts, output slot, and fee payer',
    txHref: solscanTx(AUDREN.mainnet.swapTx),
    txLabel: 'Inspect ExecViaEscrow tx',
    tone: 'pool',
  },
  {
    id: 'withdraw',
    tab: 'Pay or fund wallet',
    stageMeta: 'Self-paying exit · Transact with atomic WSOL unwrap (Tag 5)',
    title: 'Pay any address, or fund a fresh session wallet with zero SOL.',
    detail:
      'Exit SOL or SPL tokens from the global pool to any wallet, exchange, or deterministic Private DeFi Session keypair (B₀, B₁…) for stateful borrow or perp protocols. Pay the relayer directly from the withdrawn note, unwrap WSOL atomically to Native SOL in the same instruction (WITHDRAW_FLAG_UNWRAP_WSOL, pause-immune on full exit), and later sweep remaining gas back with zero-dust Deposit (DEPOSIT_FLAG_NATIVE_SOL | DEPOSIT_FLAG_FEE_FROM_AMOUNT). Positions opened by session wallets remain public on Solana.',
    steps: [
      {
        phase: 'Pool spend',
        headline: 'Shielded SOL or SPL',
        detail: 'Groth16 proof conceals historical funding note',
      },
      {
        phase: 'Unwrap & fee',
        headline: 'Atomic WSOL unwrap',
        detail: 'Relayer fee settled directly from payout',
      },
      {
        phase: 'Public exit',
        headline: 'Wallet or Session Bᵢ',
        detail: 'Zero prior SOL required for recipient',
      },
    ],
    resultText:
      'Public payout or 0-SOL DeFi session funded in one transaction (~103k CU); proof conceals its pool origin.',
    hiddenLabel: 'Which historical pool note funded the payout or session wallet',
    publicLabel: 'Destination wallet, token, payout amount, fee payer, and any DeFi positions opened',
    txHref: solscanTx(AUDREN.mainnet.withdrawTx),
    txLabel: 'Inspect full withdrawal',
    tone: 'exit',
  },
  {
    id: 'receipt',
    tab: 'Share 1 receipt',
    stageMeta: 'Selective disclosure · 1 Poseidon5 verification',
    title: 'Verify a single note while keeping spending keys private.',
    detail:
      'Export a Mode 1 SelectiveDisclosureProof for a single chosen note and let an accountant or counterparty verify it in one Poseidon5 hash directly against Solana’s SubtreePage commitment. Mode 2 FullViewingKey (spend_pk, nk, view_sk, view_pk) supports watch-only auditing of both incoming notes and spent nullifiers with zero spend authority.',
    steps: [
      {
        phase: 'Export',
        headline: 'Single-note opening',
        detail: 'Mode 1 receipt for one chosen commitment',
      },
      {
        phase: 'Check',
        headline: '1 Poseidon5 hash',
        detail: 'Verified directly against on-chain SubtreePage',
      },
      {
        phase: 'Scope',
        headline: 'Read-only proof',
        detail: 'Zero spend authority, other notes untouched',
      },
    ],
    resultText:
      'Selected note verified directly against Solana SubtreePage; zero spending keys or unrelated notes revealed.',
    hiddenLabel: 'spend_sk and every other note in the wallet',
    publicLabel: 'Disclosed note commitment, asset, and amount for the verifier',
    txHref: null,
    txLabel: 'Try receipt verification on Devnet',
    tone: 'receipt',
  },
]

function PrivacyComparisonCard() {
  return (
    <figure
      className={styles.comparison}
      aria-label="Public visibility comparison: ordinary Solana transfer, Token-2022 Confidential Balances and default confidential rings, and Audren shielded pool transfer"
    >
      <figcaption className={styles.figureHeader}>
        <h3>What Solscan shows on a transfer</h3>
        <span className={styles.figureSub}>Public chain observer view</span>
      </figcaption>

      <div className={styles.columnLabels} aria-hidden="true">
        <span>Method</span>
        <span>From → To</span>
        <span>Token / amount</span>
      </div>

      <div className={styles.comparisonRow}>
        <div className={styles.rowName}>
          <span className={styles.rowTitle}>Ordinary Solana</span>
          <span className={styles.rowMeta}>All 4 fields public</span>
        </div>
        <div className={styles.people}>
          <span>Wallet A</span>
          <ArrowRight size={13} className={styles.rowArrow} aria-hidden="true" />
          <span>Wallet B</span>
        </div>
        <div className={styles.value}>
          <span className={styles.valueUnit}>USDC</span>
          <span className={styles.valueAmount}>420.00</span>
        </div>
      </div>

      <div className={styles.comparisonRow}>
        <div className={styles.rowName}>
          <span className={styles.rowTitle}>Confidential / Rings</span>
          <span className={styles.rowMeta}>Token&#8209;2022 or default rings</span>
        </div>
        <div className={styles.people}>
          <span>Wallet A</span>
          <ArrowRight size={13} className={styles.rowArrow} aria-hidden="true" />
          <span>Wallet B</span>
        </div>
        <div className={styles.value}>
          <span className={styles.valueUnit}>Mint / ••••</span>
          <span className={`${styles.valueAmount} ${styles.masked}`}>
            <span aria-hidden="true">••••••</span>
            <span className={styles.visuallyHidden}>
              Amount hidden; mint public on Token-2022 or encrypted in default rings
            </span>
          </span>
        </div>
      </div>

      <div className={`${styles.comparisonRow} ${styles.audrenRow}`}>
        <div className={styles.rowName}>
          <span className={styles.rowTitle}>Audren Global MASP</span>
          <span className={styles.rowMeta}>SOL, Classic SPL, Token&#8209;2022</span>
        </div>
        <div className={styles.people}>
          <span>Hidden input</span>
          <ArrowRight size={13} className={styles.rowArrow} aria-hidden="true" />
          <span>Stealth note</span>
        </div>
        <div className={styles.value}>
          <span className={`${styles.valueUnit} ${styles.masked}`} aria-hidden="true">
            ••••
          </span>
          <span className={`${styles.valueAmount} ${styles.masked}`} aria-hidden="true">
            ••••••
          </span>
          <span className={styles.visuallyHidden}>Token and amount hidden</span>
        </div>
      </div>

      <p className={styles.hiddenSummary}>
        Concealed in private transfers: sender, recipient, token, and amount.
      </p>

      <p className={styles.figureNote}>
        Deposits, public withdrawals, and external DeFi CPI legs keep public token and amount
        boundaries. <Link href="/compare">Compare all models</Link>.
      </p>
    </figure>
  )
}

function ProtocolTracePanel({ activeCase }: { activeCase: PoolCase }) {
  const toneClass =
    activeCase.tone === 'exit'
      ? styles.traceExit
      : activeCase.tone === 'receipt'
        ? styles.traceReceipt
        : ''

  return (
    <div className={`${styles.tracePanel} ${toneClass}`}>
      <p className={styles.traceMeta}>{activeCase.stageMeta}</p>

      <ol className={styles.traceSteps}>
        {activeCase.steps.map((step, index) => (
          <li key={step.phase} className={styles.traceStep}>
            <span className={styles.tracePhase}>
              {index + 1}. {step.phase}
            </span>
            <span className={styles.traceHeadline}>{step.headline}</span>
            <span className={styles.traceDetail}>{step.detail}</span>
          </li>
        ))}
      </ol>

      <div className={styles.traceFooter}>
        <p className={styles.traceResult}>{activeCase.resultText}</p>
        <dl className={styles.boundaryLedger}>
          <div>
            <dt>Concealed</dt>
            <dd>{activeCase.hiddenLabel}</dd>
          </div>
          <div>
            <dt>Public on Solana</dt>
            <dd>{activeCase.publicLabel}</dd>
          </div>
        </dl>
      </div>
    </div>
  )
}

export function LandingExperience() {
  const [activeIdx, setActiveIdx] = useState(0)
  const current = POOL_CASES[activeIdx]

  const handleTabKeyDown = (e: KeyboardEvent<HTMLButtonElement>, idx: number) => {
    if (e.key === 'ArrowRight') {
      e.preventDefault()
      setActiveIdx((idx + 1) % POOL_CASES.length)
    } else if (e.key === 'ArrowLeft') {
      e.preventDefault()
      setActiveIdx((idx - 1 + POOL_CASES.length) % POOL_CASES.length)
    }
  }

  return (
    <div className={`page-shell ${styles.page}`}>
      <SiteHeader current="home" />
      <main>
        {/* HERO */}
        <section className={`container ${styles.hero}`}>
          <div className={styles.heroCopy}>
            <h1>Private payments on Solana with your existing tokens.</h1>
            <p>
              Deposit SOL, Classic SPL, or transferable Token-2022 assets into one shared pool
              without a wrapper token. Make private payments, compose with Solana DeFi via isolated
              escrow CPI (DEX swaps, lending supply, liquid staking, yield vaults, RWAs), or fund
              fresh wallets directly with self-paying fees and atomic WSOL unwrap. Your spending
              keys stay on your device.
            </p>
            <div className={styles.actions}>
              <Link href="/demo" className="btn-ink">
                Open wallet app
              </Link>
              <Link href="/demo?mode=sandbox" className={styles.textLink}>
                Try free with Devnet test SOL
              </Link>
            </div>
          </div>

          <PrivacyComparisonCard />

          <p className={styles.heroBoundary}>
            Private transfers conceal the spent record, recipient, token, and amount. Deposits,
            external DeFi CPI legs, public withdrawals, stateful session-wallet positions, and the
            fee payer remain public; a separate relayer keeps your wallet off the fee-payer field.
            Timing and outside information can still create links.{' '}
            <Link href="/faq">Read the privacy model</Link>.
          </p>
        </section>

        {/* ASSET SUPPORT STRIP */}
        <section className={styles.assetBand} aria-label="Supported Solana assets">
          <div className={`container ${styles.assetBandInner}`}>
            <div className={styles.assetLead}>
              <p className={styles.assetHeading}>No wrapper token or mint allowlist.</p>
              <p className={styles.assetNote}>
                Works with existing Solana assets without a bridge. Token issuer restrictions still
                apply.
              </p>
            </div>
            <div className={styles.assetTypes}>
              <span>Native SOL</span>
              <span>Classic SPL tokens</span>
              <span>Transferable Token-2022</span>
            </div>
          </div>
        </section>

        {/* SHARED VAULT & GLOBAL MASP */}
        <section className={`container ${styles.lifeSection}`} id="use-cases">
          <div className={styles.sectionIntro}>
            <h2>Deposit once to pay privately, use DeFi, or exit on demand.</h2>
            <p>
              Public vaults hold the pooled assets while private notes authorize spending. Proofs
              conceal the spent note across the entire historical global pool. Public amounts,
              timing, and outside information can still connect activity.
            </p>
          </div>

          <div
            className={styles.usecaseNav}
            role="tablist"
            aria-label="What you can do inside the global shielded pool"
          >
            {POOL_CASES.map((item, idx) => (
              <button
                key={item.id}
                id={`ring-tab-${item.id}`}
                type="button"
                role="tab"
                aria-selected={activeIdx === idx}
                aria-controls="ring-tabpanel"
                tabIndex={activeIdx === idx ? 0 : -1}
                onClick={() => setActiveIdx(idx)}
                onKeyDown={(e) => handleTabKeyDown(e, idx)}
                className={activeIdx === idx ? styles.selected : ''}
              >
                {item.tab}
              </button>
            ))}
          </div>

          <div
            id="ring-tabpanel"
            role="tabpanel"
            aria-labelledby={`ring-tab-${current.id}`}
            className={styles.scenario}
          >
            <div className={styles.scenarioCopy}>
              <h3>{current.title}</h3>
              <p>{current.detail}</p>
              <div className={styles.scenarioControls}>
                {current.txHref ? (
                  <a
                    className={styles.txActionLink}
                    href={current.txHref}
                    target="_blank"
                    rel="noreferrer"
                  >
                    {current.txLabel} <ArrowUpRight size={14} />
                  </a>
                ) : (
                  <Link className={styles.txActionLink} href="/demo?mode=sandbox">
                    {current.txLabel} <ArrowRight size={14} />
                  </Link>
                )}
              </div>
            </div>

            <ProtocolTracePanel activeCase={current} />
          </div>

          <p className={styles.editorialNote}>
            <span className={styles.noteLead}>
              More TVL does not automatically mean more privacy.
            </span>{' '}
            More independently owned, plausible activity may help. Dollars alone do not establish
            that. Timing, public amounts, and input-count selection still matter.
          </p>
        </section>

        {/* UNIVERSAL SOLANA DEFI RAIL */}
        <section className={styles.defiSection} id="defi-primitives">
          <div className="container">
            <div className={styles.sectionIntro}>
              <h2>One escrow primitive for open Solana DeFi.</h2>
              <p>
                <code>ExecViaEscrow</code> (Tag 6) executes any stateless SPL or Token-2022{' '}
                <code>Token A → Token B</code> Solana CPI through 16 sharded escrow PDAs and
                reshields the exact net vault delta on-chain (~158k CU, leaving &gt;1.2M CU for
                DeFi). Stateful protocols work cleanly through self-funded ephemeral session
                wallets.
              </p>
            </div>

            <div className={styles.defiGrid}>
              <article className={styles.defiCell}>
                <h3>DEX aggregators and AMMs</h3>
                <p>
                  Route across Jupiter, Titan, DFlow, OKX DEX, Raydium, Orca, Meteora, or custom
                  routers with <code>ctx_hash</code>-bound <code>router_accounts</code>,{' '}
                  <code>min_amount_out</code>, and native input or output relayer fees (
                  <code>EXEC_FLAG_FEE_ON_OUTPUT</code>).
                </p>
                <span className={styles.defiFlowTag}>
                  Tag 6 · WSOL or SPL → Any SPL → Shielded note
                </span>
              </article>

              <article className={styles.defiCell}>
                <h3>Lending supply</h3>
                <p>
                  Supply USDC or WSOL into Solana lending reserves (such as Kamino Lend) and
                  reshield the minted interest-bearing receipt token (<code>kUSDC</code>,{' '}
                  <code>kSOL</code>) directly into the unified global pool.
                </p>
                <span className={styles.defiFlowTag}>
                  Tag 6 · USDC → Reserve deposit → kUSDC note
                </span>
              </article>

              <article className={styles.defiCell}>
                <h3>Yield and compounding vaults</h3>
                <p>
                  Enter or exit ERC-4626-style Solana vaults (Kamino Vaults, Meteora Dynamic Vaults,
                  Jito Restaking) atomically, sweeping exact share tokens back into a fresh stealth
                  note.
                </p>
                <span className={styles.defiFlowTag}>
                  Tag 6 · Asset → Vault deposit → Share token note
                </span>
              </article>

              <article className={styles.defiCell}>
                <h3>Liquid staking tokens</h3>
                <p>
                  Convert shielded SOL (stored as canonical WSOL) into yield-bearing liquid staking
                  tokens (<code>JitoSOL</code>, <code>mSOL</code>, Sanctum <code>INF</code>) and
                  hold or unwind them back inside the unified pool.
                </p>
                <span className={styles.defiFlowTag}>
                  Tag 6 · WSOL → Stake pool CPI → LST note
                </span>
              </article>

              <article className={styles.defiCell}>
                <h3>Perp LP and tokenized RWAs</h3>
                <p>
                  Mint or redeem pooled liquidity tokens (such as Jupiter <code>JLP</code>) or
                  permissionless tokenized treasury vaults where the target program issues a
                  standard SPL or Token-2022 receipt token.
                </p>
                <span className={styles.defiFlowTag}>
                  Tag 6 · USDC → Mint or redeem → JLP or RWA note
                </span>
              </article>

              <article className={`${styles.defiCell} ${styles.defiCellSession}`}>
                <h3>Borrowing and perps via session wallets</h3>
                <p>
                  Fund deterministic session wallets (<code>B₀, B₁…</code>) from zero prior SOL via
                  self-paying <code>Transact(WITHDRAW_FLAG_UNWRAP_WSOL)</code>, trade or borrow on
                  stateful protocols, then sweep every remaining lamport back with zero-dust{' '}
                  <code>Deposit(DEPOSIT_FLAG_FEE_FROM_AMOUNT)</code>. Positions opened by{' '}
                  <code>Bᵢ</code> remain public on Solana.
                </p>
                <span className={styles.defiFlowTag}>
                  Tag 5 + Tag 3 · Unwrap exit → Session Bᵢ → 0-dust sweep
                </span>
              </article>
            </div>

            <p className={styles.editorialNote}>
              <span className={styles.noteLead}>Clear DeFi privacy boundary.</span> External CPI
              legs expose the target program, mints, routed amounts, and output slot; stateful
              positions opened by a session wallet <code>Bᵢ</code> (collateral, debt, margin,
              liquidations) remain public on that protocol. Audren conceals the funding notes inside
              the global 4<sup>20</sup> MASP and eliminates the on-chain link to your primary
              wallet.
            </p>
          </div>
        </section>

        {/* COMPARISON */}
        <section className={`container ${styles.cardsSection}`} id="why-audren">
          <div className={styles.sectionIntro}>
            <h2>How Audren compares on assets, fields, and infrastructure.</h2>
            <p>
              Different privacy designs make different engineering tradeoffs. Compare what stays
              hidden, which tokens work without wrapping, and what infrastructure you need to run.
            </p>
          </div>

          <div className={styles.compareGrid}>
            <article className={styles.compareCol}>
              <h3>Confidential Balances</h3>
              <p className={styles.colLead}>
                Native Token-2022 extension that encrypts transfer amounts at the token-program
                layer.
              </p>
              <ul className={styles.colList}>
                <li>Configured Token-2022 mints only; not native SOL or existing Classic SPL balances</li>
                <li>Sender wallet, recipient wallet, and token mint remain public</li>
                <li>Ordinary public DEX routes expose trade amounts and assets</li>
              </ul>
            </article>

            <article className={styles.compareCol}>
              <h3>Helius Privacy Rings</h3>
              <p className={styles.colLead}>
                Existing Solana assets, self-custody, and 1-slot spendability, with published
                independent program and circuit audits.
              </p>
              <ul className={styles.colList}>
                <li>
                  Default ring encrypts mint and amount while exposing sender and recipient wallets;
                  anonymity requires custom rings
                </li>
                <li>
                  Photon indexer, permissioned Forester, and remote GPU/TEE prover (or 350 MB to
                  1.27 GB local keys) in exchange for 5,000-lamport nullifiers and 49-input fan-in
                </li>
                <li>
                  Programmable ZK-CPI escrows enable private-amount DeFi, requiring custom circuits
                  and fresh liquidity per app
                </li>
              </ul>
            </article>

            <article className={`${styles.compareCol} ${styles.compareColAudren}`}>
              <h3>Audren</h3>
              <p className={styles.colLead}>
                One 4<sup>20</sup> global Multi-Asset Shielded Pool with a single 3.93 MB local
                Groth16 circuit, ordinary Solana RPC discovery, and no wrapper token.
              </p>
              <ul className={styles.colList}>
                <li>
                  Default 4-field anonymity (spent notes, stealth recipient, token, amount) across
                  SOL, Classic SPL, and transferable Token-2022
                </li>
                <li>
                  Zero mandatory indexer or Forester (CompactWalletStore is 1.28 MB at 10M notes);
                  full exits including atomic WSOL unwrap bypass pause
                </li>
                <li>
                  Atomic ExecViaEscrow CPI (~158k CU) hits live Solana DeFi liquidity today without
                  per-protocol circuits (external DeFi leg stays public)
                </li>
                <li>
                  Pre-audit release with permanent NullifierPDA rent (~0.002–0.0046 SOL/tx, scaling
                  via SysvarRent); PPoT and BGM17 ceremony live
                </li>
              </ul>
            </article>
          </div>

          <div className={styles.cardsFoot}>
            <Link className={styles.textLink} href="/compare">
              Read the full sourced comparison <ArrowRight size={15} />
            </Link>
            <Link className={styles.textLink} href="/how-it-works">
              Walk through the cryptography <ArrowRight size={15} />
            </Link>
          </div>
        </section>

        {/* PUBLIC VAULT ASSETS & LOCAL PROVING */}
        <section className={styles.mechanismSection} id="how-it-works">
          <div className="container">
            <div className={styles.sectionIntro}>
              <h2>Public vault balances on Solana, with spending keys on your device.</h2>
              <p>
                Anyone can inspect the unified WSOL and SPL token accounts held by the pool vault
                authority on Solscan. Public assets offer useful transparency, though they do not
                independently reveal or verify all private liabilities. The program checks spending
                proofs, range proofs, and value conservation; its implementation still needs
                independent review.
              </p>
            </div>

            <div className={styles.mechanism}>
              <article className={styles.device}>
                <h3>On your device</h3>
                <p>
                  Syncs state through ordinary Solana RPC (2-pass CompactWalletStore) and generates
                  192-byte BN254 Groth16 proofs locally in a dedicated Web Worker from one 3.93 MB
                  proving key. Spending keys never leave your device.
                </p>
                <span className={styles.deviceMeta}>Local key custody · CompactWalletStore</span>
              </article>

              <div className={styles.proofLink} aria-hidden="true">
                <span className={styles.proofLinkLabel}>192 B proof</span>
                <ArrowRight size={16} />
                <span className={styles.proofLinkSub}>No keys sent</span>
              </div>

              <article className={styles.chain}>
                <h3>Verified on Solana</h3>
                <ul>
                  <li>Global 4-ary Depth-20 Merkle membership against RootCheckpoint</li>
                  <li>BN254 Groth16 value conservation and 64-bit range checks (17,861 R1CS)</li>
                  <li>Nullifier PDAs reject repeated spends across all 16 append lanes</li>
                </ul>
                <div className={styles.vaultLinks}>
                  <a
                    href={`${solscanAddress(AUDREN.vaultAuthPda)}#portfolio`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Inspect Vault Authority · WSOL &amp; Token Custody <ArrowUpRight size={13} />
                  </a>
                  <a href={solscanAddress(AUDREN.pool0Pda)} target="_blank" rel="noreferrer">
                    Inspect Pool #0 state <ArrowUpRight size={13} />
                  </a>
                </div>
              </article>
            </div>
          </div>
        </section>

        {/* ON-CHAIN TRANSACTIONS & PRE-AUDIT NOTICE */}
        <section className={`container ${styles.proofSection}`} id="security">
          <div>
            <h2>Inspect settled Mainnet transactions directly.</h2>
            <p>
              Open real Mainnet deposits, relayed private transfers (0 user signers), private DEX
              aggregator swaps, and full withdrawals directly on Solscan, or inspect the program
              account{' '}
              <code>
                {AUDREN.programId.slice(0, 8)}…{AUDREN.programId.slice(-6)}
              </code>
              .
            </p>

            <div className={styles.linkGroups}>
              <div className={styles.linkGroup}>
                <span className={styles.linkGroupLabel}>Mainnet transactions</span>
                <div className={styles.proofLinks}>
                  {(['deposit', 'transfer', 'swap', 'withdraw'] as const).map((kind) => (
                    <a
                      key={kind}
                      href={solscanTx(AUDREN.mainnet[`${kind}Tx`])}
                      target="_blank"
                      rel="noreferrer"
                    >
                      {kind === 'transfer'
                        ? 'Private transfer'
                        : kind === 'swap'
                          ? 'Private DEX swap'
                          : kind === 'withdraw'
                            ? 'Full withdrawal'
                            : 'Deposit'}
                      <ArrowUpRight size={13} />
                    </a>
                  ))}
                </div>
              </div>

              <div className={styles.linkGroup}>
                <span className={styles.linkGroupLabel}>Program verification</span>
                <div className={styles.proofLinks}>
                  <a
                    href={explorerAddress(AUDREN.programId, 'verified-build')}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Verified build <ArrowUpRight size={13} />
                  </a>
                  <a
                    href={explorerAddress(AUDREN.programId, 'idl')}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Program IDL <ArrowUpRight size={13} />
                  </a>
                  <a
                    href={explorerAddress(AUDREN.programId, 'security')}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Security.txt <ArrowUpRight size={13} />
                  </a>
                  <a href={solscanAddress(AUDREN.programId)} target="_blank" rel="noreferrer">
                    Program account <ArrowUpRight size={13} />
                  </a>
                </div>
              </div>
            </div>
          </div>

          <aside className={styles.trustAside}>
            <h3>Pre-audit and trust boundaries</h3>
            <p>
              Audren is Apache-2.0 open source and currently in pre-audit release with a mutable BPF
              upgrade authority. An audit does not automatically remove that authority. Token
              issuers retain their own mint controls (such as freeze authority). Public vault
              balances show held assets; they do not independently prove all private liabilities.
            </p>
            <Link href="/architecture">
              Read the security model and specification <ArrowRight size={14} />
            </Link>
          </aside>
        </section>

        {/* CLOSING BAND */}
        <section className={styles.closing}>
          <div className={`container ${styles.closingInner}`}>
            <div>
              <h2>Use Audren directly, or integrate without permission.</h2>
              <p>
                Run private transfers, shielded DeFi via ExecViaEscrow, and self-paying WSOL
                withdrawals in your browser, or integrate the Rust, TypeScript, Swift (iOS), and
                Kotlin (Android) SDKs into your own wallet or app.
              </p>
            </div>
            <div className={styles.actions}>
              <Link href="/demo" className="btn-paper">
                Open wallet app
              </Link>
              <Link href="/developers" className={styles.buildLink}>
                Developer documentation <ArrowRight size={15} />
              </Link>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter current="home" />
    </div>
  )
}
