'use client'

import { useState, type CSSProperties, type KeyboardEvent } from 'react'
import Link from 'next/link'
import { ArrowRight, ArrowUpRight, Check, KeyRound, Lock, Pause, Play, RotateCcw } from 'lucide-react'
import { SiteHeader } from '@/components/SiteHeader'
import { SiteFooter } from '@/components/SiteFooter'
import { EscrowRail } from '@/components/motion/EscrowRail'
import { PoolScene, poolSceneCaption } from '@/components/motion/PoolScene'
import { SceneCaption, StepButton } from '@/components/motion/SceneControls'
import { useAutoStepper, useHydrated, useInView } from '@/components/motion/hooks'
import m from '@/components/motion/motion.module.css'
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
      'Pay any reusable Bech32m aud1… address with SOL, Classic SPL, or transferable Token-2022 inside a single global Multi-Asset Shielded Pool (4-ary Depth-20 Merkle tree, 1.099T-note capacity at 16 lanes; 4 active today). A 192-byte Groth16 proof hides which of the pool’s notes you spent (the pool is young, so that set is small today) and creates fresh one-time stealth outputs with hidden asset and amount. Timing and external information can still create links.',
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
        detail: 'Stealth owner, token, and amount hidden',
      },
    ],
    resultText:
      'Private Transact settles in ~205k CU (235k budget) with inline GlobalRootHistory update (~150ms Alpenglow finality), hidden inputs, stealth recipient, hidden asset, and hidden amount.',
    hiddenLabel: 'Which pool note was spent, recipient, token, and amount',
    publicLabel: 'GlobalRootHistory ring index, lane append slot, timing, and fee payer',
    txHref: solscanTx(AUDREN.mainnet.transferTx),
    txLabel: 'Inspect a self-paid Mainnet private send (economy 1-in/2-out shape)',
    tone: 'pool',
  },
  {
    id: 'swap',
    tab: 'Shielded DeFi',
    stageMeta: 'Isolated escrow CPI · ExecViaEscrow (Tag 6)',
    title: 'Swap privately through DeFi and return to the pool.',
    detail:
      'ExecViaEscrow spends a private note through a shared escrow into one Token A → Token B Solana program call and reshields the output in the same transaction. The app and hosted relay ship aggregator swaps today (Jupiter, DFlow, OKX), which also reach LSTs and JLP; lending supply and vault deposits can target the same instruction through the SDK’s generic builder but have not yet been exercised on Mainnet. Relayer fees settle from input or output tokens (EXEC_FLAG_FEE_ON_OUTPUT); the external DeFi call, its mints, amounts, and the output note remain public.',
    steps: [
      {
        phase: 'Escrow out',
        headline: 'Sharded escrow PDA',
        detail: 'Pool spends input note via isolated shard',
      },
      {
        phase: 'External CPI',
        headline: 'One external program call',
        detail: 'Aggregator route (other programs via SDK)',
      },
      {
        phase: 'Reshield',
        headline: 'Measured net delta',
        detail: 'Output reshielded; unspent input stays as change',
      },
    ],
    resultText:
      'Output token or yield receipt settles straight into a fresh pool note (~165k–238k CU base / 285k budget, leaving >1.11M CU for DeFi).',
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
      'Exit SOL or SPL tokens from the global pool to any wallet, exchange, or deterministic Private DeFi Session keypair (B₀, B₁…) for stateful borrow or perp protocols. Pay the relayer directly from the withdrawn note, unwrap WSOL atomically to Native SOL in the same instruction (WITHDRAW_FLAG_UNWRAP_WSOL; full exits still go through while the pool is paused), and later sweep remaining SOL back with a zero-dust Deposit (DEPOSIT_FLAG_NATIVE_SOL | DEPOSIT_FLAG_FEE_FROM_AMOUNT). The exit, the session wallet’s positions, and the sweep are public and linked through that wallet.',
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
        detail: 'No prior SOL needed for SOL exits',
      },
    ],
    resultText:
      'Public payout or 0-SOL DeFi session funded in one transaction (~116k–121k CU full exit with read-only roots / 165k budget; ~145k–217k CU withdraw / 255k budget); the proof conceals which pool note paid for it.',
    hiddenLabel: 'Which historical pool note funded the payout or session wallet',
    publicLabel: 'Destination wallet, token, payout amount, fee payer, and any DeFi positions opened',
    txHref: solscanTx(AUDREN.mainnet.withdrawTx),
    txLabel: 'Inspect a self-paid full withdrawal',
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
    publicLabel: 'Commitment on-chain; asset, amount, owner key, and position shown only to the verifier',
    txHref: null,
    txLabel: 'Try receipt verification on Devnet',
    tone: 'receipt',
  },
]

/** Delay (seconds) as a CSS variable for the hero ledger choreography. */
function at(seconds: number): CSSProperties {
  return { '--d': `${seconds}s` } as CSSProperties
}

/**
 * The same 420 USDC payment printed three times. Once the card is on screen,
 * ink bars wipe across exactly what each model hides from a chain observer.
 */
function PrivacyComparisonCard() {
  const [ref, inView] = useInView<HTMLElement>()
  const hydrated = useHydrated()
  const [started, setStarted] = useState(false)
  const [run, setRun] = useState(0)
  if (inView && !started) setStarted(true)

  return (
    <figure
      ref={ref}
      className={styles.comparison}
      data-play={!hydrated ? 'static' : started ? 'on' : 'off'}
      aria-label="Public visibility comparison: ordinary Solana transfer, Token-2022 Confidential Balances and default confidential rings, and Audren shielded pool transfer"
    >
      <figcaption className={styles.figureHeader}>
        <div>
          <h3>What Solscan shows on a transfer</h3>
          <span className={styles.figureSub}>The same 420 USDC payment, three ways</span>
        </div>
        <button
          type="button"
          className={styles.replayBtn}
          onClick={() => {
            setStarted(true)
            setRun((n) => n + 1)
          }}
        >
          <RotateCcw size={12} aria-hidden="true" /> Replay
        </button>
      </figcaption>

      <div className={styles.columnLabels} aria-hidden="true">
        <span>Method</span>
        <span>From → To</span>
        <span>Token / amount</span>
      </div>

      <div key={run} className={styles.ledgerRows}>
        <div className={styles.comparisonRow} style={at(0.2)}>
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

        <div className={styles.comparisonRow} style={at(0.7)}>
          <div className={styles.rowName}>
            <span className={styles.rowTitle}>Confidential / Rings</span>
            <span className={styles.rowMeta}>Default rings · CB on Token&#8209;2022 only</span>
          </div>
          <div className={styles.people}>
            <span>Wallet A</span>
            <ArrowRight size={13} className={styles.rowArrow} aria-hidden="true" />
            <span>Wallet B</span>
          </div>
          <div className={styles.value}>
            <span className={`${styles.valueUnit} ${styles.inkBar} ${styles.inkBarPartial}`} style={at(1.35)} aria-hidden="true">
              USDC
            </span>
            <span className={`${styles.valueAmount} ${styles.inkBar}`} style={at(1.15)} aria-hidden="true">
              420.00
            </span>
            <span className={styles.visuallyHidden}>
              Amount hidden; mint public on Token-2022 or encrypted in default rings
            </span>
          </div>
        </div>

        <div className={`${styles.comparisonRow} ${styles.audrenRow}`} style={at(1.3)}>
          <div className={styles.rowName}>
            <span className={styles.rowTitle}>Audren Global MASP</span>
            <span className={styles.rowMeta}>Relayed · SOL, SPL, Token&#8209;2022</span>
          </div>
          <div className={styles.people}>
            <span className={styles.swap} style={at(1.9)} aria-hidden="true">
              <span className={styles.swapFrom}>Wallet A</span>
              <span className={styles.swapTo}>Hidden input</span>
            </span>
            <ArrowRight size={13} className={styles.rowArrow} aria-hidden="true" />
            <span className={styles.swap} style={at(2.1)} aria-hidden="true">
              <span className={styles.swapFrom}>Wallet B</span>
              <span className={styles.swapTo}>Stealth note</span>
            </span>
            <span className={styles.visuallyHidden}>Hidden input to a one-time stealth note</span>
          </div>
          <div className={styles.value}>
            <span className={`${styles.valueUnit} ${styles.inkBar}`} style={at(2.35)} aria-hidden="true">
              USDC
            </span>
            <span className={`${styles.valueAmount} ${styles.inkBar}`} style={at(2.5)} aria-hidden="true">
              420.00
            </span>
            <span className={styles.visuallyHidden}>Token and amount hidden</span>
          </div>
        </div>
      </div>

      <div className={styles.ledgerLegend} aria-hidden="true">
        <span>
          <i className={styles.legendSolid} /> hidden from observers
        </span>
        <span>
          <i className={styles.legendHatch} /> depends on the mode
        </span>
      </div>

      <p className={styles.hiddenSummary}>
        Concealed in relayed private transfers: sender, recipient, token, and amount.
      </p>

      <p className={styles.figureNote}>
        Deposits, public withdrawals, and external DeFi CPI legs keep public token and amount
        boundaries. <Link href="/compare">Compare all models</Link>.
      </p>
    </figure>
  )
}

const TRACE_STEP_MS = [6200, 6600, 7000] as const

function ProtocolTracePanel({ activeCase }: { activeCase: PoolCase }) {
  const [ref, inView] = useInView<HTMLDivElement>()
  const stepper = useAutoStepper({
    count: 3,
    durations: TRACE_STEP_MS,
    active: inView,
    resetKey: activeCase.id,
  })
  const toneClass =
    activeCase.tone === 'exit'
      ? styles.traceExit
      : activeCase.tone === 'receipt'
        ? styles.traceReceipt
        : ''

  return (
    <div ref={ref} className={`${styles.tracePanel} ${toneClass}`}>
      <div className={styles.traceMetaRow}>
        <p className={styles.traceMeta}>{activeCase.stageMeta}</p>
        <button
          type="button"
          className={m.playBtn}
          onClick={stepper.togglePlay}
          aria-label={stepper.playing ? 'Pause walkthrough' : 'Play walkthrough'}
        >
          {stepper.playing ? <Pause size={13} aria-hidden="true" /> : <Play size={13} aria-hidden="true" />}
        </button>
      </div>

      <PoolScene
        caseId={activeCase.id}
        step={stepper.step}
        cycle={stepper.cycle}
        reduced={stepper.reduced}
      />

      <SceneCaption
        key={activeCase.id}
        className={styles.traceCaption}
        texts={[0, 1, 2].map((idx) => poolSceneCaption(activeCase.id, idx))}
        index={stepper.step}
        live={!stepper.playing}
      />

      <ol className={styles.traceSteps} aria-label="Steps in this flow">
        {activeCase.steps.map((step, index) => (
          <li key={step.phase} className={styles.traceStep}>
            <StepButton
              idx={index}
              step={stepper.step}
              text={step.headline}
              playing={stepper.playing}
              running={stepper.running}
              duration={stepper.duration}
              cycle={stepper.cycle}
              onSelect={stepper.select}
              className={styles.traceStepBtn}
            >
              <span className={styles.tracePhase}>
                {index + 1}. {step.phase}
              </span>
              <span className={styles.traceHeadline}>{step.headline}</span>
              <span className={styles.traceDetail}>{step.detail}</span>
            </StepButton>
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

const HANDOFF_STEPS = ['Prove', 'Send', 'Membership', 'Conservation', 'Nullifier', 'Accepted'] as const
const HANDOFF_MS = [1700, 1300, 950, 950, 950, 3200] as const
const CHAIN_CHECKS = [
  'Global 4-ary Depth-20 Merkle membership against inline GlobalRootHistory',
  'BN254 Groth16 value conservation and 64-bit range checks (17,861 R1CS)',
  'Pool-wide nullifier PDAs reject repeated spends',
] as const

/** Device → 192 B proof → Solana checks, with the spending key pinned to the device. */
function ProofHandoff() {
  const [ref, inView] = useInView<HTMLDivElement>()
  const stepper = useAutoStepper({ count: HANDOFF_STEPS.length, durations: HANDOFF_MS, active: inView })
  const step = stepper.reduced ? HANDOFF_STEPS.length - 1 : stepper.step

  return (
    <div ref={ref} className={styles.mechanism} data-step={step}>
      <article className={styles.device}>
        <h3>On your device</h3>
        <p>
          Syncs state through ordinary Solana RPC (2-pass CompactWalletStore) and generates
          192-byte BN254 Groth16 proofs locally in a dedicated Web Worker from one 3.93 MB
          proving key. Spending keys never leave your device.
        </p>
        <div className={styles.deviceWork} aria-hidden="true">
          <span className={`${m.chip} ${styles.deviceKey}`} data-tone="key">
            <KeyRound size={11} /> spend key <Lock size={10} />
          </span>
          <span className={styles.proveTrack}>
            <span
              key={step === 0 ? `prove-${stepper.cycle}` : 'proved'}
              className={styles.proveFill}
              data-state={step === 0 ? 'proving' : 'done'}
            />
          </span>
          <span className={styles.proveLabel}>{step === 0 ? 'Proving…' : 'Proof ready · key stays'}</span>
        </div>
        <span className={styles.deviceMeta}>Local key custody · CompactWalletStore</span>
      </article>

      <div className={styles.proofLink} aria-hidden="true">
        <span className={styles.proofLinkLabel}>192 B proof</span>
        <span className={styles.proofTrack}>
          <span
            key={step === 1 ? `send-${stepper.cycle}` : 'rest'}
            className={styles.proofPacket}
            data-state={step < 1 ? 'waiting' : step === 1 ? 'sending' : 'arrived'}
          />
          <ArrowRight size={16} className={styles.proofArrow} />
        </span>
        <span className={styles.proofLinkSub}>No keys sent</span>
      </div>

      <article className={styles.chain}>
        <h3>Verified on Solana</h3>
        <ul>
          {CHAIN_CHECKS.map((check, idx) => (
            <li key={check} data-state={step >= idx + 2 ? 'ok' : 'pending'}>
              <span className={styles.checkMark} aria-hidden="true">
                <Check size={11} />
              </span>
              {check}
            </li>
          ))}
        </ul>
        <div className={styles.chainVerdict}>
          {step >= 5 ? (
            <span className={`${m.stamp} ${m.stampOk}`} aria-hidden="true">
              Spend accepted
            </span>
          ) : (
            <span className={styles.chainWaiting} aria-hidden="true">
              {step < 2 ? 'Waiting for a proof' : 'Checking…'}
            </span>
          )}
          <button
            type="button"
            className={styles.handoffToggle}
            onClick={stepper.togglePlay}
            aria-label={stepper.playing ? 'Pause proof animation' : 'Play proof animation'}
          >
            {stepper.playing ? <Pause size={12} aria-hidden="true" /> : <Play size={12} aria-hidden="true" />}
          </button>
        </div>
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
              without a wrapper token. Make private payments, swap through Solana DEX aggregators via
              an isolated escrow, or fund fresh wallets directly with self-paying fees and atomic
              WSOL unwrap. Your spending keys stay on your device.
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
            Private transfers conceal which note was spent, the recipient, token, and amount, and
            the sender when a relay pays the fee. Deposits, external DeFi CPI legs, public
            withdrawals, stateful session-wallet positions, and the fee payer remain public.
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
              hide which of the pool’s notes was spent. Public amounts,
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
                <code>ExecViaEscrow</code> (Tag 6) runs one SPL or Token-2022{' '}
                <code>Token A → Token B</code> Solana program call through 16 shared escrow PDAs
                and reshields the exact net vault delta on-chain (~165k–238k CU base / 285k budget,
                leaving &gt;1.11M CU for DeFi). Aggregator swaps ship in the app today; any program that takes the
                input and returns the output in that one call fits the same instruction through
                the SDK. Stateful protocols use self-funded session wallets.
              </p>
            </div>

            <EscrowRail />

            <div className={styles.defiGrid}>
              <article className={styles.defiCell} data-flow="dex">
                <h3>DEX aggregators</h3>
                <p>
                  Live in the app: route through Jupiter, DFlow, or OKX DEX (reaching AMMs
                  such as Raydium, Orca, and Meteora); SDK integrations can target other routers.
                  Every call binds its <code>router_accounts</code>, <code>min_amount_out</code>,
                  and relayer fee into <code>ctx_hash</code>; the fee can come from the input or,
                  with <code>EXEC_FLAG_FEE_ON_OUTPUT</code>, from the output.
                </p>
                <span className={styles.defiFlowTag}>
                  Tag 6 · WSOL or SPL → Any SPL → Shielded note
                </span>
              </article>

              <article className={styles.defiCell} data-flow="lend">
                <h3>Lending supply</h3>
                <p>
                  Possible through the SDK&rsquo;s generic builder: supply USDC or WSOL to a lending
                  reserve in one escrow-signed call and reshield its interest-bearing collateral
                  token. Not in the app and not yet exercised on Mainnet.
                </p>
                <span className={styles.defiFlowTag}>
                  Tag 6 · USDC → Reserve deposit → Collateral token note
                </span>
              </article>

              <article className={styles.defiCell} data-flow="vault">
                <h3>Yield and compounding vaults</h3>
                <p>
                  Possible through the SDK&rsquo;s generic builder: enter or exit vaults that mint and
                  redeem share tokens in a single call, sweeping the exact shares into a fresh
                  stealth note. Not yet exercised on Mainnet; vaults with withdrawal queues or
                  cooldowns do not fit.
                </p>
                <span className={styles.defiFlowTag}>
                  Tag 6 · Asset → Vault deposit → Share token note
                </span>
              </article>

              <article className={styles.defiCell} data-flow="stake">
                <h3>Liquid staking tokens</h3>
                <p>
                  Swap shielded SOL (held as WSOL) into liquid staking tokens such as{' '}
                  <code>JitoSOL</code> or <code>mSOL</code> through an aggregator route, and hold or
                  unwind them inside the pool. Direct stake-pool deposits need native SOL from a
                  signer, so they go through aggregator routes instead.
                </p>
                <span className={styles.defiFlowTag}>
                  Tag 6 · WSOL → Aggregator LST route → LST note
                </span>
              </article>

              <article className={styles.defiCell} data-flow="lp">
                <h3>Perp LP tokens</h3>
                <p>
                  Buy or sell pooled liquidity tokens such as Jupiter <code>JLP</code> through an
                  aggregator route. Tokenized funds fit only when minting is permissionless and
                  settles in one call; most RWA tokens restrict who may hold them.
                </p>
                <span className={styles.defiFlowTag}>
                  Tag 6 · USDC → Aggregator route → JLP note
                </span>
              </article>

              <article className={`${styles.defiCell} ${styles.defiCellSession}`} data-flow="session">
                <h3>Borrowing and perps via session wallets</h3>
                <p>
                  Fund deterministic session wallets (<code>B₀, B₁…</code>) from zero prior SOL via
                  self-paying <code>Transact(WITHDRAW_FLAG_UNWRAP_WSOL)</code>, trade or borrow on
                  stateful protocols, then sweep every remaining lamport back with zero-dust{' '}
                  <code>Deposit(DEPOSIT_FLAG_NATIVE_SOL | DEPOSIT_FLAG_FEE_FROM_AMOUNT)</code>. The
                  exit, the positions opened by <code>Bᵢ</code>, and the sweep are public and
                  linked through <code>Bᵢ</code>.
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
              liquidations) remain public on that protocol. Audren hides which pool note funded the
              call and, when a relayer submits it, keeps your primary wallet out of the
              transaction; timing and public amounts can still link activity.
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
              <h3>Solana Privacy Rings</h3>
              <p className={styles.colLead}>
                Helius’s pool for existing Solana assets with self-custody, and program and circuit
                audits by Certora, zkSecurity, and OtterSec.
              </p>
              <ul className={styles.colList}>
                <li>
                  Default ring encrypts token and amount but shows sender and recipient wallets;
                  anonymous Custom Rings are still in audit
                </li>
                <li>
                  Photon indexer (self-hostable), permissioned Forester tree maintenance, and local
                  or GPU proving, with a 5,000-lamport fee per state tree updated
                </li>
                <li>
                  Apps can add their own proofs via CPI to keep DeFi amounts private; Jupiter, DFlow,
                  and Titan integrations are announced
                </li>
              </ul>
            </article>

            <article className={`${styles.compareCol} ${styles.compareColAudren}`}>
              <h3>Audren</h3>
              <p className={styles.colLead}>
                One 4<sup>20</sup> global Multi-Asset Shielded Pool with one 3.93 MB local Groth16
                proving key, ordinary Solana RPC discovery, and no wrapper token.
              </p>
              <ul className={styles.colList}>
                <li>
                  Default 4-field confidentiality (spent notes, stealth recipient, token, amount)
                  across SOL, Classic SPL, and transferable Token-2022
                </li>
                <li>
                  Zero mandatory indexer, Forester, or background cranks (~1.28 MB kept at 10M
                  notes): inline GlobalRootHistory (128-entry recent slot_ring + 89-entry stable
                  epoch_ring) gives instant spendability on confirmation (~150ms Alpenglow
                  finality) with auto-prepended idempotent OpenPage, and full exits including
                  atomic WSOL unwrap bypass pause
                </li>
                <li>
                  Atomic ExecViaEscrow CPI (~165k–238k CU base / 285k budget) reaches live
                  aggregator liquidity today without per-protocol circuits (external DeFi leg stays
                  public)
                </li>
                <li>
                  No protocol fee and no on-chain sign-up to receive. Each spend pays permanent
                  nullifier and page rent (~0.0007–0.0036 SOL at current rent), read live from
                  Solana, so rent cuts (6,960 → 5,080 lamports per byte so far) lower it with no
                  program upgrade
                </li>
                <li>
                  Pre-audit release; the Phase-2 ceremony has only Audren’s contributions so far
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

            <ProofHandoff />
          </div>
        </section>

        {/* ON-CHAIN TRANSACTIONS & PRE-AUDIT NOTICE */}
        <section className={`container ${styles.proofSection}`} id="security">
          <div>
            <h2>Inspect settled Mainnet transactions directly.</h2>
            <p>
              Open a relayed private DEX swap (0 user signers) and operator test deposit, private
              transfer, and full withdrawal transactions on Solscan. Those three are self-paid by
              the same operator wallet, so they are deliberately linkable. Or inspect the program
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
              upgrade authority, held together with the pool authority by one operator key (not a
              multisig). An audit does not automatically remove that authority. Token
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
