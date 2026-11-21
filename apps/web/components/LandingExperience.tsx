'use client'

import { useState, type KeyboardEvent } from 'react'
import Link from 'next/link'
import {
  ArrowRight,
  ArrowUpRight,
  EyeOff,
  KeyRound,
  LockKeyhole,
  RotateCcw,
} from 'lucide-react'
import { SiteHeader } from '@/components/SiteHeader'
import { SiteFooter } from '@/components/SiteFooter'
import { AUDREN, explorerAddress, solscanAddress, solscanTx } from '@/lib/protocol'
import styles from './LandingExperience.module.css'

type CaseId = 'pay' | 'swap' | 'withdraw' | 'receipt'

interface RingCase {
  id: CaseId
  tab: string
  stageTitle: string
  stageTag: string
  title: string
  detail: string
  hiddenLabel: string
  publicLabel: string
  packetLabel: string
  beamLabel: string
  outcomeTitle: string
  outcomeSub: string
  outcomeCaption: string
  resultText: string
  txHref: string | null
  txLabel: string
}

const RING_CASES: readonly RingCase[] = [
  {
    id: 'pay',
    tab: 'Pay someone',
    stageTitle: 'Shared pool · Triptych ring proof',
    stageTag: 'Tag 3 · Transfer',
    title: 'Pay privately with your existing tokens.',
    detail:
      'Pay a reusable aud1… address with a supported asset. The proof conceals the spent note among selected candidates and creates a fresh recipient key with blinded token and amount commitments. Timing and outside information can still create links.',
    hiddenLabel: 'Spent note within ring, recipient, token & amount',
    publicLabel: 'Candidate pages, timing & fee payer',
    packetLabel: '•••• USDC',
    beamLabel: 'Proof verified · input concealed',
    outcomeTitle: 'Fresh 1-time note',
    outcomeSub: 'One-time stealth key',
    outcomeCaption: '4 fields blinded',
    resultText: 'Private transfer: hidden input, fresh recipient, blinded token and amount.',
    txHref: solscanTx(AUDREN.mainnet.transferTx),
    txLabel: 'Inspect Mainnet private send',
  },
  {
    id: 'swap',
    tab: 'Shielded DeFi',
    stageTitle: 'Protocol-agnostic CPI · sharded escrow',
    stageTag: 'Tag 5 · ExecViaEscrow',
    title: 'Swap, lend, stake, or deploy into Solana DeFi — settle back into the pool.',
    detail:
      'ExecViaEscrow turns any Token A → Token B Solana program call into a single shielded transaction: DEX swaps (Jupiter, Titan, DFlow, Raydium, Orca) are just one example alongside lending supply (kTokens), yield vaults, liquid staking (JitoSOL, INF), perp LP (JLP), and RWA mint/redeem. Native relayer fees settle from input or output tokens; external DeFi amounts, mints and output record remain public.',
    hiddenLabel: 'Spent note within selected candidates & owner wallet',
    publicLabel: 'External DeFi program, mints, routed amounts, output slot & fee payer',
    packetLabel: 'Token A → B',
    beamLabel: 'Escrow PDA → DeFi CPI',
    outcomeTitle: 'Any Solana DeFi CPI',
    outcomeSub: 'DEX · Lend · LST · Vault',
    outcomeCaption: 'Swept back to pool',
    resultText: 'Output token or yield receipt settles straight into a fresh pool record.',
    txHref: solscanTx(AUDREN.mainnet.swapTx),
    txLabel: 'Inspect Mainnet ExecViaEscrow tx',
  },
  {
    id: 'withdraw',
    tab: 'Pay or fund wallet',
    stageTitle: 'Self-paying payout · atomic WSOL unwrap',
    stageTag: 'Tag 6 · Withdraw',
    title: 'Pay any address — or fund a fresh DeFi session wallet with zero prior SOL.',
    detail:
      'Send SOL or SPL tokens from the shared pool to any wallet, exchange, or deterministic Private DeFi Session keypair (B_0, B_1…) for stateful borrow or perp protocols. Pay the relayer directly from the withdrawn note, optionally unwrap WSOL atomically to Native SOL in the same instruction, and later sweep remaining gas back with zero-dust Deposit(fee_from_amount). Public payouts and any stateful DeFi position opened by a session wallet remain public on Solana.',
    hiddenLabel: 'Which candidate note funded the payout or session wallet',
    publicLabel: 'Destination wallet, token, payout amount, fee payer & any DeFi positions opened',
    packetLabel: 'SOL / WSOL',
    beamLabel: 'Self-paying · atomic unwrap',
    outcomeTitle: 'Wallet or Session Bᵢ',
    outcomeSub: '0-SOL bootstrap ready',
    outcomeCaption: 'Public payout',
    resultText: 'Public payout or 0-SOL DeFi session funded; proof conceals its input note.',
    txHref: solscanTx(AUDREN.mainnet.withdrawTx),
    txLabel: 'Inspect Mainnet full withdrawal',
  },
  {
    id: 'receipt',
    tab: 'Share 1 receipt',
    stageTitle: 'Selective disclosure · single-note opening',
    stageTag: 'Read-only proof',
    title: 'Verify one note. Keep spending keys private.',
    detail:
      'Export a cryptographic opening for a single chosen note and let an accountant or counterparty verify it directly against Solana’s on-chain record. SDK-derived sub-accounts also support stream-scoped read-only viewing keys.',
    hiddenLabel: 'Spending keys & all other notes',
    publicLabel: 'Disclosed note commitment, asset & amount',
    packetLabel: 'Opening ✓',
    beamLabel: 'Single-note opening',
    outcomeTitle: 'Your verifier',
    outcomeSub: '420.00 USDC checked',
    outcomeCaption: '1 note disclosed',
    resultText: 'Selected note verified against Solana; a receipt grants no spending authority.',
    txHref: null,
    txLabel: 'Try receipt verification on Devnet',
  },
]

const RING_CX = 142
const RING_CY = 136
const RING_R = 86

const RING_NODES = Array.from({ length: 12 }, (_, idx) => {
  const angle = (idx / 12) * Math.PI * 2 - Math.PI / 2
  const cos = Math.cos(angle)
  const sin = Math.sin(angle)
  return {
    idx,
    cx: Number((RING_CX + cos * RING_R).toFixed(1)),
    cy: Number((RING_CY + sin * RING_R).toFixed(1)),
    innerX: Number((RING_CX + cos * 47).toFixed(1)),
    innerY: Number((RING_CY + sin * 47).toFixed(1)),
    outerX: Number((RING_CX + cos * (RING_R - 10)).toFixed(1)),
    outerY: Number((RING_CY + sin * (RING_R - 10)).toFixed(1)),
  }
})

const COMPASS_TICKS = Array.from({ length: 36 }, (_, idx) => {
  const angle = (idx / 36) * Math.PI * 2
  const isMajor = idx % 3 === 0
  const r1 = isMajor ? 99 : 101
  const r2 = isMajor ? 106 : 104
  return {
    idx,
    isMajor,
    x1: Number((RING_CX + Math.cos(angle) * r1).toFixed(1)),
    y1: Number((RING_CY + Math.sin(angle) * r1).toFixed(1)),
    x2: Number((RING_CX + Math.cos(angle) * r2).toFixed(1)),
    y2: Number((RING_CY + Math.sin(angle) * r2).toFixed(1)),
  }
})

function PrivacyComparisonCard() {
  const [replay, setReplay] = useState(0)

  return (
    <figure
      className={styles.comparison}
      aria-label="Public visibility comparison: ordinary Solana transfer, Token-2022 Confidential Balances, and Audren private ring transfer"
    >
      <figcaption className={styles.figureHeader}>
        <div>
          <strong>What Solscan shows on a transfer</strong>
          <span className={styles.figureSub}>Public chain observer view</span>
        </div>
        <button
          type="button"
          onClick={() => setReplay((n) => n + 1)}
          aria-label="Replay privacy comparison"
          title="Replay comparison"
        >
          <RotateCcw size={14} />
        </button>
      </figcaption>

      <div className={styles.columnLabels} aria-hidden="true">
        <span>Method</span>
        <span>From → To</span>
        <span>Token / Amount</span>
      </div>

      <div className={styles.comparisonRow}>
        <div className={styles.rowName}>
          Ordinary Solana
          <span>All 4 fields public</span>
        </div>
        <div className={styles.people}>
          <span>Wallet A</span>
          <ArrowRight size={14} />
          <span>Wallet B</span>
        </div>
        <div className={styles.value}>
          USDC<strong>420.00</strong>
        </div>
      </div>

      <div className={styles.comparisonRow}>
        <div className={styles.rowName}>
          Confidential Balances
          <span>Configured Token&#8209;2022 only</span>
        </div>
        <div className={styles.people}>
          <span>Wallet A</span>
          <ArrowRight size={14} className={styles.rowArrow} />
          <span>Wallet B</span>
        </div>
        <div className={styles.value}>
          Token&#8209;2022
          <strong className={styles.masked}>
            <span aria-hidden="true">••••••</span>
            <span className={styles.visuallyHidden}>Amount hidden</span>
          </strong>
        </div>
      </div>

      <div key={replay} className={`${styles.comparisonRow} ${styles.audrenRow}`}>
        <div className={styles.rowName}>
          Audren Private Ring
          <span>SOL · Classic SPL · Token&#8209;2022</span>
        </div>
        <div className={styles.privatePeople}>
          <div className={styles.privateIdentity}>
            <div className={styles.privateIconBox}>
              <svg
                className={styles.miniRingSvg}
                viewBox="0 0 40 40"
                width="32"
                height="32"
                aria-hidden="true"
              >
                <circle
                  cx="20"
                  cy="20"
                  r="15"
                  fill="none"
                  stroke="rgba(212,223,205,0.28)"
                  strokeWidth="1"
                />
                <circle
                  cx="20"
                  cy="20"
                  r="15"
                  fill="none"
                  stroke="#e7efe4"
                  strokeWidth="1.5"
                  strokeDasharray="18 76"
                  strokeLinecap="round"
                  className={styles.miniOrbitSpin}
                />
                {[0, 45, 90, 135, 180, 225, 270, 315].map((deg, idx) => {
                  const rad = (deg * Math.PI) / 180
                  const x = (20 + Math.cos(rad) * 15).toFixed(1)
                  const y = (20 + Math.sin(rad) * 15).toFixed(1)
                  return (
                    <circle
                      key={deg}
                      cx={x}
                      cy={y}
                      r="2.1"
                      className={styles.miniRingDot}
                      style={{ animationDelay: `${idx * 110}ms` }}
                    />
                  )
                })}
                <circle cx="20" cy="20" r="4.2" fill="#d4dfcd" />
              </svg>
            </div>
            <small>Hidden input</small>
          </div>
          <ArrowRight size={14} className={styles.rowArrow} />
          <div className={styles.privateIdentity}>
            <div className={styles.privateIconBox}>
              <LockKeyhole size={18} />
            </div>
            <small>1-time address</small>
          </div>
        </div>
        <div className={styles.value}>
          <span className={`${styles.masked} ${styles.maskedShimmer}`} aria-hidden="true">
            ••••
          </span>
          <strong className={`${styles.masked} ${styles.maskedShimmer}`} aria-hidden="true">
            ••••••
          </strong>
          <span className={styles.visuallyHidden}>Token and amount hidden</span>
        </div>
      </div>

      <div className={styles.fourFields}>
        <strong className={styles.hiddenPrefix}>Concealed in private transfers:</strong>
        {['Sender', 'Recipient', 'Token', 'Amount'].map((field) => (
          <span key={field}>
            <EyeOff size={12} />
            {field}
            <span className={styles.visuallyHidden}> hidden in private transfers</span>
          </span>
        ))}
      </div>

      <p className={styles.figureNote}>
        Deposits, public withdrawals and external DEX legs keep public token and amount boundaries.{' '}
        <Link href="/compare">Compare all models</Link>.
      </p>
    </figure>
  )
}

function SharedVaultRingStage({
  activeCase,
  runId,
}: {
  activeCase: RingCase
  runId: number
}) {
  const isSwap = activeCase.id === 'swap'
  const isWithdraw = activeCase.id === 'withdraw'
  const isReceipt = activeCase.id === 'receipt'
  const accentStroke = isWithdraw ? '#8b5e34' : '#184433'
  const swapOutPathId = `audren-swap-out-${runId}`
  const swapBackPathId = `audren-swap-back-${runId}`
  const linearPathId = `audren-linear-${activeCase.id}-${runId}`

  return (
    <div
      className={`${styles.ringStage} ${isWithdraw ? styles.stageWithdraw : ''} ${isReceipt ? styles.stageReceipt : ''}`}
    >
      <div className={styles.ringStageTop}>
        <span className={styles.stageLabel}>{activeCase.stageTitle}</span>
        <span className={styles.stageTag}>{activeCase.stageTag}</span>
      </div>

      <svg
        key={`${activeCase.id}-${runId}`}
        className={styles.ringSvg}
        viewBox="0 0 580 272"
        role="img"
        aria-label={`${activeCase.tab} inside Audren shared vault ring: ${activeCase.resultText}`}
      >
        <defs>
          <radialGradient id={`vault-glow-${runId}`} cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor={isWithdraw ? '#8b5e34' : '#184433'} stopOpacity="0.16" />
            <stop offset="100%" stopColor={isWithdraw ? '#8b5e34' : '#184433'} stopOpacity="0" />
          </radialGradient>
          <filter id={`chip-shadow-${runId}`} x="-20%" y="-30%" width="140%" height="170%">
            <feDropShadow dx="0" dy="2" stdDeviation="2.4" floodColor="#121210" floodOpacity="0.16" />
          </filter>
          <path id={swapOutPathId} d="M 244 102 C 292 48, 358 48, 404 102" />
          <path id={swapBackPathId} d="M 404 170 C 358 224, 292 224, 244 170" />
          <path id={linearPathId} d="M 244 136 L 404 136" />
        </defs>

        {/* Ambient radial field behind the Shared Vault */}
        <circle cx={RING_CX} cy={RING_CY} r="106" fill={`url(#vault-glow-${runId})`} />

        {/* Architectural precision compass ticks around ring perimeter */}
        <g opacity={isReceipt ? 0.38 : 0.62}>
          {COMPASS_TICKS.map((t) => (
            <line
              key={t.idx}
              x1={t.x1}
              y1={t.y1}
              x2={t.x2}
              y2={t.y2}
              stroke={t.isMajor ? '#889782' : '#b7c1b2'}
              strokeWidth={t.isMajor ? '1.1' : '0.8'}
            />
          ))}
        </g>

        {/* Fine inner harmonic ring */}
        <circle
          cx={RING_CX}
          cy={RING_CY}
          r="64"
          fill="none"
          stroke={isReceipt ? '#c7cdc2' : '#b7c4b1'}
          strokeWidth="0.9"
          strokeDasharray="2 4"
        />

        {/* Main candidate orbit */}
        <circle
          cx={RING_CX}
          cy={RING_CY}
          r={RING_R}
          fill="none"
          stroke={isReceipt ? '#bcc4b6' : '#96aa8f'}
          strokeWidth="1.25"
        />

        {/* Rotating cryptographic sweep arc showing ring-wide Triptych verification */}
        {!isReceipt && (
          <circle
            cx={RING_CX}
            cy={RING_CY}
            r={RING_R}
            fill="none"
            stroke={accentStroke}
            strokeWidth="2.4"
            strokeDasharray="88 452"
            strokeLinecap="round"
            className={styles.orbitSweep}
          />
        )}

        {/* Radial filaments linking candidate notes to Shared Vault */}
        {RING_NODES.map((node) => {
          const isSingleReceiptNode = isReceipt && node.idx === 3
          return (
            <line
              key={`spoke-${node.idx}`}
              x1={node.innerX}
              y1={node.innerY}
              x2={node.outerX}
              y2={node.outerY}
              stroke={isSingleReceiptNode ? '#184433' : '#9fb098'}
              strokeWidth={isSingleReceiptNode ? '1.6' : '0.9'}
              strokeDasharray={isReceipt && !isSingleReceiptNode ? '2 3' : undefined}
              className={
                isReceipt
                  ? isSingleReceiptNode
                    ? styles.spokeActive
                    : styles.spokeDim
                  : styles.spokePulse
              }
              style={isReceipt ? undefined : { animationDelay: `${node.idx * 180}ms` }}
            />
          )
        })}

        {/* Subtle breathing halo emanating from Shared Vault core */}
        <circle
          cx={RING_CX}
          cy={RING_CY}
          r="46"
          fill="none"
          stroke={accentStroke}
          strokeWidth="1.4"
          className={styles.vaultHalo}
        />

        {/* Central Shared On-Chain Vault */}
        <circle cx={RING_CX} cy={RING_CY} r="45" fill="#184433" />
        <circle
          cx={RING_CX}
          cy={RING_CY}
          r="40.5"
          fill="none"
          stroke="rgba(244, 241, 234, 0.22)"
          strokeWidth="0.9"
        />
        <text
          x={RING_CX}
          y={RING_CY - 8}
          textAnchor="middle"
          fill="#f4f1ea"
          fontSize="10.8"
          fontWeight="600"
          letterSpacing="0.08em"
        >
          SHARED
        </text>
        <text
          x={RING_CX}
          y={RING_CY + 7}
          textAnchor="middle"
          fill="#f4f1ea"
          fontSize="10.8"
          fontWeight="600"
          letterSpacing="0.08em"
        >
          VAULT
        </text>
        <text x={RING_CX} y={RING_CY + 22} textAnchor="middle" fill="#c7dac8" fontSize="8.8">
          SOL · SPL · T22
        </text>

        {/* Candidate ring slots */}
        {RING_NODES.map((node) => {
          const isSingleReceiptNode = isReceipt && node.idx === 3
          return (
            <g key={node.idx}>
              {isSingleReceiptNode && (
                <>
                  <circle
                    cx={node.cx}
                    cy={node.cy}
                    r="11"
                    fill="none"
                    stroke="#184433"
                    strokeWidth="1.5"
                    className={styles.receiptRipple}
                  />
                  <circle
                    cx={node.cx}
                    cy={node.cy}
                    r="11"
                    fill="none"
                    stroke="#184433"
                    strokeWidth="1.2"
                    className={styles.receiptRippleDelayed}
                  />
                </>
              )}
              <circle
                cx={node.cx}
                cy={node.cy}
                r={isSingleReceiptNode ? '10.5' : '8'}
                className={
                  isReceipt
                    ? isSingleReceiptNode
                      ? styles.ringNodeSelected
                      : styles.ringNodeDim
                    : styles.ringNodePulse
                }
                style={isReceipt ? undefined : { animationDelay: `${node.idx * 180}ms` }}
              />
              {!isReceipt && (
                <circle
                  cx={node.cx}
                  cy={node.cy}
                  r="2.4"
                  className={styles.ringNodeCore}
                  style={{ animationDelay: `${node.idx * 180}ms` }}
                />
              )}
              {isSingleReceiptNode && (
                <path
                  d={`M ${node.cx - 3.6} ${node.cy + 0.2} l 2.5 2.6 l 4.8 -5.2`}
                  fill="none"
                  stroke="#f4f1ea"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              )}
            </g>
          )
        })}

        {/* Withdraw boundary demarcation (Pool -> Public chain) */}
        {isWithdraw && (
          <g>
            <line
              x1="324"
              y1="42"
              x2="324"
              y2="230"
              stroke="#c2ab8c"
              strokeWidth="1"
              strokeDasharray="3 4"
            />
            <text x="315" y="54" textAnchor="end" fill="#6f6d61" fontSize="8.8" fontFamily="monospace">
              POOL
            </text>
            <text x="333" y="54" textAnchor="start" fill="#8b5e34" fontSize="8.8" fontFamily="monospace">
              PUBLIC
            </text>
          </g>
        )}

        {/* Flow rails & smooth SVG animateMotion packets */}
        {isSwap ? (
          <>
            {/* Upper outgoing arc: Escrow PDA -> DEX */}
            <use href={`#${swapOutPathId}`} fill="none" stroke="#c3d0be" strokeWidth="2.5" />
            <use
              href={`#${swapOutPathId}`}
              fill="none"
              stroke="#184433"
              strokeWidth="1.8"
              strokeDasharray="6 6"
              className={styles.railFlowForward}
            />
            <polygon points="407,104 396,101 402,93" fill="#184433" />

            {/* Lower returning arc: Output + change -> Pool */}
            <use href={`#${swapBackPathId}`} fill="none" stroke="#c3d0be" strokeWidth="2.5" />
            <use
              href={`#${swapBackPathId}`}
              fill="none"
              stroke="#184433"
              strokeWidth="2"
              strokeDasharray="6 6"
              className={styles.railFlowForward}
            />
            <polygon points="241,168 252,169 246,178" fill="#184433" />

            {/* Clean non-overlapping arc captions */}
            <text x="324" y="34" textAnchor="middle" fill="#3a4738" fontSize="10.2" fontWeight="600">
              Escrow PDA → DEX
            </text>
            <text x="324" y="246" textAnchor="middle" fill="#184433" fontSize="10.2" fontWeight="600">
              Output + change reshielded in 1 tx
            </text>

            {/* Full-arc leading photons + clear-corridor pills (never clip ring or DEX box) */}
            <circle r="3" fill="#184433" opacity="0">
              <animateMotion
                dur="3.4s"
                repeatCount="indefinite"
                keyPoints="0;1;1;1"
                keyTimes="0;0.44;0.5;1"
                calcMode="spline"
                keySplines="0.42 0 0.2 1; 0 0 1 1; 0 0 1 1"
              >
                <mpath href={`#${swapOutPathId}`} />
              </animateMotion>
              <animate
                attributeName="opacity"
                values="0;0.9;0.9;0;0"
                keyTimes="0;0.06;0.39;0.45;1"
                dur="3.4s"
                repeatCount="indefinite"
              />
            </circle>

            {/* Outgoing packet smoothly following the clear arch of the upper Bezier curve */}
            <g filter={`url(#chip-shadow-${runId})`} opacity="0">
              <animateMotion
                dur="3.4s"
                repeatCount="indefinite"
                keyPoints="0.24;0.76;0.76;0.76"
                keyTimes="0;0.44;0.5;1"
                calcMode="spline"
                keySplines="0.42 0 0.2 1; 0 0 1 1; 0 0 1 1"
              >
                <mpath href={`#${swapOutPathId}`} />
              </animateMotion>
              <animate
                attributeName="opacity"
                values="0;1;1;0;0"
                keyTimes="0;0.09;0.37;0.44;1"
                dur="3.4s"
                repeatCount="indefinite"
              />
              <rect x="-30" y="-12" width="60" height="24" rx="3" fill="#2e3f35" stroke="#faf8f3" strokeWidth="1" />
              <text x="0" y="3.5" textAnchor="middle" fill="#faf8f3" fontSize="9.6" fontWeight="600">
                SOL →
              </text>
            </g>

            {/* Returning leading photon */}
            <circle r="3" fill="#184433" opacity="0">
              <animateMotion
                dur="3.4s"
                repeatCount="indefinite"
                keyPoints="0;0;1;1"
                keyTimes="0;0.5;0.94;1"
                calcMode="spline"
                keySplines="0 0 1 1; 0.42 0 0.2 1; 0 0 1 1"
              >
                <mpath href={`#${swapBackPathId}`} />
              </animateMotion>
              <animate
                attributeName="opacity"
                values="0;0;0.95;0.95;0"
                keyTimes="0;0.49;0.55;0.89;0.95"
                dur="3.4s"
                repeatCount="indefinite"
              />
            </circle>

            {/* Returning packet smoothly following the clear arch of the lower Bezier curve */}
            <g filter={`url(#chip-shadow-${runId})`} opacity="0">
              <animateMotion
                dur="3.4s"
                repeatCount="indefinite"
                keyPoints="0.26;0.26;0.74;0.74"
                keyTimes="0;0.5;0.94;1"
                calcMode="spline"
                keySplines="0 0 1 1; 0.42 0 0.2 1; 0 0 1 1"
              >
                <mpath href={`#${swapBackPathId}`} />
              </animateMotion>
              <animate
                attributeName="opacity"
                values="0;0;1;1;0"
                keyTimes="0;0.5;0.58;0.86;0.94"
                dur="3.4s"
                repeatCount="indefinite"
              />
              <rect x="-35" y="-12" width="70" height="24" rx="3" fill="#184433" stroke="#faf8f3" strokeWidth="1" />
              <text x="0" y="3.5" textAnchor="middle" fill="#faf8f3" fontSize="9.6" fontWeight="600">
                ← USDC
              </text>
            </g>
          </>
        ) : (
          <>
            {/* Dedicated airspace label above beam — zero overlap with packet */}
            <text
              x="324"
              y="98"
              textAnchor="middle"
              fill={isWithdraw ? '#6e4928' : '#3a4738'}
              fontSize="10.4"
              fontWeight="600"
            >
              {activeCase.beamLabel}
            </text>

            {/* Under-rail + animated flow dash */}
            <use
              href={`#${linearPathId}`}
              fill="none"
              stroke={isWithdraw ? '#dfd0ba' : '#c6d2c1'}
              strokeWidth="2.5"
            />
            <use
              href={`#${linearPathId}`}
              fill="none"
              stroke={accentStroke}
              strokeWidth="1.9"
              strokeDasharray={isReceipt ? '4 5' : '7 6'}
              className={styles.railFlowForward}
            />
            <polygon points="409,136 398,130 398,142" fill={accentStroke} />

            {/* Full-track leading photon */}
            <circle r="3" fill={accentStroke} opacity="0">
              <animateMotion
                dur="2.6s"
                repeatCount="indefinite"
                keyPoints="0;1"
                keyTimes="0;1"
                calcMode="spline"
                keySplines="0.35 0 0.2 1"
              >
                <mpath href={`#${linearPathId}`} />
              </animateMotion>
              <animate
                attributeName="opacity"
                values="0;0.9;0.9;0"
                keyTimes="0;0.1;0.88;1"
                dur="2.6s"
                repeatCount="indefinite"
              />
            </circle>

            {/* Clear-corridor high-contrast packet (strictly inside ring-to-card gap) */}
            <g filter={`url(#chip-shadow-${runId})`} opacity="0">
              <animateMotion
                dur="2.6s"
                repeatCount="indefinite"
                keyPoints="0.28;0.74"
                keyTimes="0;1"
                calcMode="spline"
                keySplines="0.35 0 0.2 1"
              >
                <mpath href={`#${linearPathId}`} />
              </animateMotion>
              <animate
                attributeName="opacity"
                values="0;1;1;0"
                keyTimes="0;0.16;0.8;1"
                dur="2.6s"
                repeatCount="indefinite"
              />
              <rect
                x="-37"
                y="-12.5"
                width="74"
                height="25"
                rx="3"
                fill={accentStroke}
                stroke="#faf8f3"
                strokeWidth="1"
              />
              <text x="0" y="3.6" textAnchor="middle" fill="#faf8f3" fontSize="9.8" fontWeight="600">
                {activeCase.packetLabel}
              </text>
            </g>
          </>
        )}

        {/* Right Outcome Ledger Card with subtle arrival accent */}
        <g>
          <rect
            x="414"
            y="82"
            width="152"
            height="108"
            rx="3"
            fill={isWithdraw ? '#f7efe3' : '#faf8f3'}
            stroke={isWithdraw ? '#9d7649' : '#184433'}
            strokeWidth="1.5"
          />
          <rect
            x="414"
            y="82"
            width="152"
            height="3.5"
            rx="1"
            fill={accentStroke}
            className={styles.cardTopAccent}
          />
          <text
            x="490"
            y="116"
            textAnchor="middle"
            fill={isWithdraw ? '#6e4928' : '#121210'}
            fontSize="12.2"
            fontWeight="700"
          >
            {activeCase.outcomeTitle}
          </text>
          <text x="490" y="136" textAnchor="middle" fill="#4f554b" fontSize="10">
            {activeCase.outcomeSub}
          </text>
          <line
            x1="430"
            y1="152"
            x2="550"
            y2="152"
            stroke={isWithdraw ? '#d4be9f' : '#d2d8cc'}
            strokeWidth="1"
          />
          <text
            x="490"
            y="171"
            textAnchor="middle"
            fill={isWithdraw ? '#6e4928' : '#184433'}
            fontSize="9.4"
            fontWeight="600"
          >
            {activeCase.outcomeCaption}
          </text>
        </g>
      </svg>

      <div className={styles.stageFooter}>
        <p className={styles.stageResult}>{activeCase.resultText}</p>
        <dl className={styles.boundaryLedger}>
          <div>
            <dt>Concealed</dt>
            <dd>{activeCase.hiddenLabel}</dd>
          </div>
          <div>
            <dt>Public</dt>
            <dd>{activeCase.publicLabel}</dd>
          </div>
        </dl>
      </div>
    </div>
  )
}

export function LandingExperience() {
  const [activeIdx, setActiveIdx] = useState(0)
  const [runId, setRunId] = useState(1)
  const current = RING_CASES[activeIdx]

  const selectCase = (idx: number) => {
    setActiveIdx(idx)
    setRunId((n) => n + 1)
  }

  const handleTabKeyDown = (e: KeyboardEvent<HTMLButtonElement>, idx: number) => {
    if (e.key === 'ArrowRight') {
      e.preventDefault()
      selectCase((idx + 1) % RING_CASES.length)
    } else if (e.key === 'ArrowLeft') {
      e.preventDefault()
      selectCase((idx - 1 + RING_CASES.length) % RING_CASES.length)
    }
  }

  return (
    <div className={`page-shell ${styles.page}`}>
      <SiteHeader current="home" />
      <main>
        {/* HERO */}
        <section className={`container ${styles.hero}`}>
          <div className={styles.heroCopy}>
            <h1>
              Private money on Solana.{' '}
              <br />
              Existing tokens.{' '}
              <br />
              One shared pool.
            </h1>
            <p>
              Deposit SOL, Classic SPL, or transferable Token-2022 assets without a wrapper token.
              Make private payments, compose with Solana DeFi via isolated escrow CPI (DEX swaps,
              lending supply, liquid staking, yield vaults, RWAs), or fund fresh wallets directly
              with self-paying fees and atomic WSOL unwrap. Your spending keys stay on your device.
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
            Private transfers conceal the spent record, recipient, token and amount. Deposits,
            external DeFi CPI legs, public withdrawals, stateful session-wallet positions and the
            fee payer remain public; a separate relayer keeps your wallet off the fee-payer field.
            Timing and outside information can still create links.{' '}
            <Link href="/faq">Read the privacy model</Link>.
          </p>
        </section>

        {/* Asset support strip */}
        <section className={styles.assetBand} aria-label="Supported Solana assets">
          <div className={`container ${styles.assetBandInner}`}>
            <span>Original assets. No Audren wrapper token.</span>
            <div>
              <strong>Native SOL</strong>
              <strong>Classic SPL tokens</strong>
              <strong>Transferable Token-2022</strong>
            </div>
            <p>No protocol mint allowlist or bridge. Token issuer restrictions still apply.</p>
          </div>
        </section>

        {/* INTERACTIVE SHARED VAULT & PRIVATE RING */}
        <section className={`container ${styles.lifeSection}`} id="use-cases">
          <div className={styles.sectionIntro}>
            <div>
              <h2>
                Enter the shared vault once.
                <br />
                Pay privately. Trade and return.
              </h2>
            </div>
            <p>
              Public vaults hold the pooled assets; private notes authorize spending. Proofs conceal
              the source note among selected candidates. Public amounts, timing and outside
              information can still connect activity.
            </p>
          </div>

          <div className={styles.usecaseNav} role="tablist" aria-label="What you can do inside the ring">
            {RING_CASES.map((item, idx) => (
              <button
                key={item.id}
                id={`ring-tab-${item.id}`}
                type="button"
                role="tab"
                aria-selected={activeIdx === idx}
                aria-controls="ring-tabpanel"
                tabIndex={activeIdx === idx ? 0 : -1}
                onClick={() => selectCase(idx)}
                onKeyDown={(e) => handleTabKeyDown(e, idx)}
                className={activeIdx === idx ? styles.selected : ''}
              >
                <span className={styles.tabDot} aria-hidden="true" />
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
                <button
                  type="button"
                  className={styles.playButton}
                  onClick={() => setRunId((n) => n + 1)}
                >
                  <RotateCcw size={14} /> Replay flow
                </button>
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

            <SharedVaultRingStage activeCase={current} runId={runId} />
          </div>

          <p className={styles.editorialNote}>
            <strong>More TVL does not automatically mean more privacy.</strong> More independently
            owned, plausible activity may help — dollars alone do not establish that. Timing,
            public amounts and candidate selection still matter.
          </p>
        </section>

        {/* UNIVERSAL SOLANA DEFI RAIL */}
        <section className={`container ${styles.defiSection}`} id="defi-primitives">
          <div className={styles.sectionIntro}>
            <div>
              <h2>
                One escrow primitive.
                <br />
                Endless Solana DeFi.
              </h2>
            </div>
            <p>
              <code>ExecViaEscrow</code> (Tag 5) executes any stateless{' '}
              <code>Token A → Token B</code> Solana CPI through a sharded escrow PDA and reshields
              the exact net vault delta on-chain. DEX swaps are only one example — and stateful
              protocols work cleanly through self-funded ephemeral session wallets.
            </p>
          </div>

          <div className={styles.defiLedger}>
            <article className={styles.defiCell}>
              <span className={styles.colKicker}>Tag 5 · 1 Tx · Stateless CPI</span>
              <h3>DEX Aggregators &amp; AMMs</h3>
              <p>
                Route across Jupiter, Titan, DFlow, OKX DEX, Raydium, Orca, Meteora, or custom
                routers with transcript-bound <code>min_amount_out</code> and native input/output
                relayer fees.
              </p>
              <span className={styles.defiFlowTag}>WSOL / SPL → Any SPL → Shielded Note</span>
            </article>

            <article className={styles.defiCell}>
              <span className={styles.colKicker}>Tag 5 · 1 Tx · Receipt Token</span>
              <h3>Lending Supply</h3>
              <p>
                Supply USDC or SOL into Solana lending reserves (such as Kamino Lend) and reshield
                the minted interest-bearing receipt token (<code>kUSDC</code>, <code>kSOL</code>)
                directly into the shared pool.
              </p>
              <span className={styles.defiFlowTag}>USDC → Reserve Deposit → kUSDC Note</span>
            </article>

            <article className={styles.defiCell}>
              <span className={styles.colKicker}>Tag 5 · 1 Tx · Yield Share</span>
              <h3>Yield &amp; Auto-Compounding Vaults</h3>
              <p>
                Enter or exit ERC-4626-style Solana vaults (Kamino Vaults, Meteora Dynamic Vaults,
                Jito Restaking) atomically, sweeping exact share tokens back into a fresh stealth
                note.
              </p>
              <span className={styles.defiFlowTag}>Asset → Vault Deposit → Share Token Note</span>
            </article>

            <article className={styles.defiCell}>
              <span className={styles.colKicker}>Tag 5 · 1 Tx · Stake Pool</span>
              <h3>Liquid Staking (LSTs)</h3>
              <p>
                Convert shielded WSOL into yield-bearing liquid staking tokens (<code>JitoSOL</code>
                , <code>mSOL</code>, Sanctum <code>INF</code>) and hold or unwind them back inside
                the unified pool.
              </p>
              <span className={styles.defiFlowTag}>WSOL → Stake Pool CPI → LST Note</span>
            </article>

            <article className={styles.defiCell}>
              <span className={styles.colKicker}>Tag 5 · 1 Tx · LP &amp; Treasury</span>
              <h3>Perp LP &amp; Tokenized RWAs</h3>
              <p>
                Mint or redeem pooled liquidity tokens (such as Jupiter <code>JLP</code>) or
                permissionless tokenized treasury vaults where the target program issues a standard
                SPL or Token-2022 receipt token.
              </p>
              <span className={styles.defiFlowTag}>USDC → Mint / Redeem → JLP / RWA Note</span>
            </article>

            <article className={`${styles.defiCell} ${styles.defiCellSession}`}>
              <span className={styles.colKicker}>Tag 6 + Tag 2 · Stateful Sessions</span>
              <h3>Borrowing &amp; Perps via Session Wallets</h3>
              <p>
                Fund deterministic session wallets (<code>B₀, B₁…</code>) from zero prior SOL via
                self-paying <code>Withdraw(unwrap_wsol)</code>, trade or borrow on stateful
                protocols, then sweep every remaining lamport back with zero-dust{' '}
                <code>Deposit(fee_from_amount)</code>. Positions opened by <code>Bᵢ</code> remain
                public on Solana.
              </p>
              <span className={styles.defiFlowTag}>
                Withdraw(unwrap_wsol) → Bᵢ DeFi → 0-Dust Sweep
              </span>
            </article>
          </div>

          <p className={styles.editorialNote}>
            <strong>Clear DeFi privacy boundary.</strong> External CPI legs expose the target
            program, mints, routed amounts and output slot; stateful positions opened by a session
            wallet <code>Bᵢ</code> (collateral, debt, margin, liquidations) remain public on that
            protocol. Audren conceals the funding note inside the pool ring and eliminates the
            on-chain link to your primary wallet.
          </p>
        </section>

        {/* COMPARISON LEDGER */}
        <section className={styles.cardsSection} id="why-audren">
          <div className="container">
            <div className={styles.sectionIntro}>
              <div>
                <h2>
                  How Audren compares on
                  <br />
                  assets, fields, and infrastructure.
                </h2>
              </div>
              <p>
                Different privacy designs make different engineering tradeoffs. Compare what stays
                hidden, which tokens work without wrapping, and what infrastructure you need to run.
              </p>
            </div>

            <div className={styles.compareLedger}>
              <article className={styles.compareCol}>
                <span className={styles.colKicker}>Token-2022 Extension</span>
                <h3>Confidential Balances</h3>
                <p className={styles.colLead}>
                  Native Token-2022 extension that encrypts transfer amounts at the token-program
                  layer.
                </p>
                <ul className={styles.colList}>
                  <li>Configured Token-2022 mints only; not native SOL or existing Classic SPL balances</li>
                  <li>Sender wallet, recipient wallet and token mint remain public</li>
                  <li>Ordinary public DEX routes expose trade amounts and assets</li>
                </ul>
              </article>

              <article className={styles.compareCol}>
                <span className={styles.colKicker}>Trusted-Setup Rings</span>
                <h3>Helius Privacy Rings</h3>
                <p className={styles.colLead}>
                  Existing Solana assets and self-custody, with published independent program and
                  circuit audits.
                </p>
                <ul className={styles.colList}>
                  <li>Indexer and Forester state services; proofs can be generated locally</li>
                  <li>Groth16 circuits rely on multi-party trusted setup and proving keys</li>
                  <li>Default ring exposes participants; anonymous custom rings are a separate mode</li>
                </ul>
              </article>

              <article className={`${styles.compareCol} ${styles.compareColAudren}`}>
                <span className={styles.colKicker}>Shared Shielded Pool</span>
                <h3>Audren</h3>
                <p className={styles.colLead}>
                  One permissionless pool with local proofs, standard account RPC discovery, and no
                  Audren-issued wrapper token.
                </p>
                <ul className={styles.colList}>
                  <li>Private transfers conceal input record, fresh recipient, token and amount</li>
                  <li>Supports SOL, Classic SPL and transferable Token-2022; issuer controls apply</li>
                  <li>Protocol-agnostic ExecViaEscrow CPI (DEXs, lending, LSTs, vaults) + self-paying WSOL unwrap</li>
                  <li>No protocol-specific indexer or trusted setup; pre-audit and upgradeable</li>
                </ul>
              </article>
            </div>

            <div className={styles.cardsFoot}>
              <Link className={styles.textLink} href="/compare">
                Read the full sourced comparison &amp; boundaries <ArrowRight size={15} />
              </Link>
              <Link className={styles.textLink} href="/how-it-works">
                Walk through the cryptography step by step <ArrowRight size={15} />
              </Link>
            </div>
          </div>
        </section>

        {/* PUBLIC VAULT ASSETS & LOCAL PROVING */}
        <section className={styles.mechanismSection} id="how-it-works">
          <div className="container">
            <div className={styles.sectionIntro}>
              <div>
                <h2>
                  Public assets on Solana.
                  <br />
                  Spending keys on your device.
                </h2>
              </div>
              <p>
                Anyone can inspect the pooled SOL and token accounts on Solscan. Public assets are
                useful transparency — they do not independently reveal or verify all private
                liabilities. The program checks spending proofs, range proofs and value
                conservation; its implementation still needs independent review.
              </p>
            </div>

            <div className={styles.mechanism}>
              <div className={styles.device}>
                <KeyRound size={24} />
                <strong>Your device</strong>
                <span>
                  Scans compact RPC slices.
                  <br />
                  Creates proofs locally.
                </span>
                <small>Spending keys stay local</small>
              </div>
              <div className={styles.proofLink} aria-hidden="true">
                <span>ZK Proof</span>
                <svg className={styles.proofBridgeSvg} viewBox="0 0 110 24" width="110" height="24">
                  <line x1="6" y1="12" x2="96" y2="12" stroke="#c3ccbe" strokeWidth="2" />
                  <line
                    x1="6"
                    y1="12"
                    x2="96"
                    y2="12"
                    stroke="#184433"
                    strokeWidth="1.8"
                    strokeDasharray="5 5"
                    className={styles.railFlowForward}
                  />
                  <polygon points="104,12 94,7 94,17" fill="#184433" />
                  <circle r="3.2" fill="#184433">
                    <animateMotion dur="1.8s" repeatCount="indefinite" path="M 10 12 L 92 12" />
                    <animate
                      attributeName="opacity"
                      values="0;1;1;0"
                      keyTimes="0;0.15;0.82;1"
                      dur="1.8s"
                      repeatCount="indefinite"
                    />
                  </circle>
                </svg>
                <small>No keys sent</small>
              </div>
              <div className={styles.chain}>
                <strong>Solana verifies on-chain</strong>
                <ul>
                  <li>Ring membership (32 / 64 / 128 slots, not guaranteed users)</li>
                  <li>Pedersen value conservation and 64-bit range proofs</li>
                  <li>Nullifier PDAs reject repeated spends</li>
                </ul>
                <div className={styles.vaultLinks}>
                  <a href={solscanAddress(AUDREN.solVaultPda)} target="_blank" rel="noreferrer">
                    Inspect SOL vault <ArrowUpRight size={13} />
                  </a>
                  <a
                    href={`${solscanAddress(AUDREN.vaultAuthPda)}#portfolio`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Inspect SPL vault <ArrowUpRight size={13} />
                  </a>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* On-chain transactions & pre-audit notice */}
        <section className={`container ${styles.proofSection}`} id="security">
          <div>
            <h2>Inspect settled Mainnet transactions directly.</h2>
            <p>
              Open real Mainnet deposits, relayed private transfers (0 user signers), private DEX
              aggregator swaps and full withdrawals directly on Solscan, or inspect the program
              account{' '}
              <code>{AUDREN.programId.slice(0, 8)}…{AUDREN.programId.slice(-6)}</code>.
            </p>
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
                  <ArrowUpRight size={14} />
                </a>
              ))}
              <a
                href={explorerAddress(AUDREN.programId, 'verified-build')}
                target="_blank"
                rel="noreferrer"
              >
                Verified build
                <ArrowUpRight size={14} />
              </a>
              <a
                href={explorerAddress(AUDREN.programId, 'idl')}
                target="_blank"
                rel="noreferrer"
              >
                Program IDL
                <ArrowUpRight size={14} />
              </a>
              <a
                href={explorerAddress(AUDREN.programId, 'security')}
                target="_blank"
                rel="noreferrer"
              >
                Security.txt
                <ArrowUpRight size={14} />
              </a>
              <a
                href={solscanAddress(AUDREN.programId)}
                target="_blank"
                rel="noreferrer"
              >
                Program account
                <ArrowUpRight size={14} />
              </a>
            </div>
          </div>
          <aside>
            <strong>Pre-audit &amp; trust boundaries.</strong>
            <p>
              Audren is Apache-2.0 open source and currently in pre-audit release with a mutable BPF
              upgrade authority. An audit does not automatically remove that authority. Token
              issuers retain their own mint controls (such as freeze authority). Public vault
              balances show held assets; they do not independently prove all private liabilities.
            </p>
            <Link href="/architecture">Read the security model &amp; specification</Link>
          </aside>
        </section>

        {/* Closing band */}
        <section className={styles.closing}>
          <div className={`container ${styles.closingInner}`}>
            <div>
              <h2>Use it directly. Integrate without permission.</h2>
              <p>
                Run private transfers, shielded DeFi via ExecViaEscrow, and self-paying WSOL
                withdrawals in your browser — or integrate the Rust, TypeScript, Swift (iOS), and
                Kotlin (Android) SDKs into your own wallet or app.
              </p>
            </div>
            <div className={styles.actions}>
              <Link href="/demo" className="btn-paper">
                Open the app
              </Link>
              <Link href="/developers" className={styles.buildLink}>
                Developer documentation <ArrowRight size={16} />
              </Link>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter current="home" />
    </div>
  )
}
