'use client'

import { Check, Minus, Pause, Play, X } from 'lucide-react'
import { useAutoStepper, useInView } from './hooks'
import m from './motion.module.css'
import h from './HowScenes.module.css'
import { usePhase } from './useDocks'

/** The key on-chain checks for a spend, in the order the program reaches them. */
const CHECKS = [
  { id: 'root', label: 'Proof uses a recent checkpoint root' },
  { id: 'proof', label: 'Groth16 proof verifies: ownership, balance, 64-bit ranges, bound outputs' },
  { id: 'nullifier', label: 'Record spent marks (fails if a mark already exists)' },
  { id: 'defi', label: 'DeFi leg: escrow accounts unaltered, output ≥ minimum' },
  { id: 'settle', label: 'Write the new sealed notes' },
] as const

interface Attempt {
  id: string
  tab: string
  /** Index of the check that rejects it; -1 = settles. */
  failAt: number
  /** Checks that do not apply (shown as skipped). */
  skip: readonly number[]
  error?: string
  verdict: string
}

const ATTEMPTS: readonly Attempt[] = [
  {
    id: 'honest',
    tab: 'Honest private payment',
    failAt: -1,
    skip: [3],
    verdict:
      'Every check passes. With the default padded shape, two spent marks are recorded and three fresh sealed notes are appended.',
  },
  {
    id: 'replay',
    tab: 'Spend the same note twice',
    failAt: 2,
    skip: [3],
    error: 'NullifierAlreadyUsed · 6012',
    verdict:
      'The proof is valid, but the note’s spent mark already exists on Solana. The transaction reverts and nothing changes.',
  },
  {
    id: 'inflate',
    tab: 'Pay out more than the note holds',
    failAt: 1,
    skip: [3],
    error: 'ProofVerificationFailed · 6010',
    verdict:
      'The circuit forces inputs to equal outputs plus fees, so no valid proof exists for extra money. A forged proof fails the pairing check.',
  },
  {
    id: 'tamper',
    tab: 'Relayer swaps in its own recipient',
    failAt: 1,
    skip: [3],
    error: 'ProofVerificationFailed · 6010',
    verdict:
      'The proof commits to every output, the fee and the fee recipient. Editing any of them in transit breaks verification.',
  },
  {
    id: 'router',
    tab: 'DeFi route returns less than promised',
    failAt: 3,
    skip: [],
    error: 'SlippageExceeded · 6014',
    verdict:
      'Audren measures the escrow after the external call. Below min_amount_out, the whole transaction reverts, including the spend, so your note stays spendable.',
  },
]

const CHECK_MS = 620
const PHASE_TIMES = CHECKS.map((_, idx) => 500 + idx * CHECK_MS)
const ATTEMPT_MS = 7600

/** Pick an attack, watch where the program stops it. */
export function AttackSimulator() {
  const [ref, inView] = useInView<HTMLDivElement>()
  const stepper = useAutoStepper({ count: ATTEMPTS.length, durations: ATTEMPT_MS, active: inView })
  const attempt = ATTEMPTS[stepper.step] ?? ATTEMPTS[0]
  const evaluated = usePhase(`${attempt.id}-${stepper.cycle}`, stepper.reduced, PHASE_TIMES)
  const lastCheck = attempt.failAt === -1 ? CHECKS.length - 1 : attempt.failAt
  const finished = evaluated > lastCheck

  return (
    <div ref={ref} className={h.attack}>
      <div className={h.attackPicker}>
        <div className={h.attackPickerHead}>
          <span>Try to break a spend</span>
          <button
            type="button"
            className={m.playBtn}
            onClick={stepper.togglePlay}
            aria-label={stepper.playing ? 'Pause attack walkthrough' : 'Play attack walkthrough'}
          >
            {stepper.playing ? <Pause size={13} aria-hidden="true" /> : <Play size={13} aria-hidden="true" />}
          </button>
        </div>
        <div className={h.attackTabs} role="group" aria-label="Attack scenarios">
          {ATTEMPTS.map((a, idx) => (
            <button
              key={a.id}
              type="button"
              aria-pressed={idx === stepper.step}
              className={h.attackTab}
              data-selected={idx === stepper.step ? 'true' : 'false'}
              onClick={() => stepper.select(idx)}
            >
              <span className={h.attackTabDot} data-kind={a.failAt === -1 ? 'ok' : 'bad'} />
              {a.tab}
            </button>
          ))}
        </div>
      </div>

      <div className={h.attackRun} role="group" aria-label={attempt.tab}>
        <ol className={h.checkList}>
          {CHECKS.map((c, idx) => {
            const skipped = attempt.skip.includes(idx)
            let state: 'pending' | 'pass' | 'fail' | 'skip' | 'unreached' = 'pending'
            if (attempt.failAt !== -1 && idx > attempt.failAt) state = finished ? 'unreached' : 'pending'
            else if (idx < evaluated) state = skipped ? 'skip' : idx === attempt.failAt ? 'fail' : 'pass'
            return (
              <li key={c.id} className={h.check} data-state={state}>
                <span className={h.checkIcon} aria-hidden="true">
                  {state === 'pass' ? (
                    <Check size={11} />
                  ) : state === 'fail' ? (
                    <X size={11} />
                  ) : state === 'skip' ? (
                    <Minus size={11} />
                  ) : null}
                </span>
                <span className={h.checkLabel}>
                  {c.label}
                  {state === 'skip' ? <em> · not used here</em> : null}
                </span>
              </li>
            )
          })}
        </ol>

        <p className={m.visuallyHidden} aria-live="polite">
          {!stepper.playing && finished
            ? `${attempt.failAt === -1 ? 'Settled' : 'Rejected'}${attempt.error ? `, ${attempt.error}` : ''}. ${attempt.verdict}`
            : ''}
        </p>
        <div className={h.verdict} data-show={finished ? 'true' : 'false'}>
          {finished ? (
            <>
              <span className={`${m.stamp} ${attempt.failAt === -1 ? m.stampOk : m.stampBad}`}>
                {attempt.failAt === -1 ? 'Settled' : 'Rejected'}
              </span>
              {attempt.error ? <code className={h.errCode}>{attempt.error}</code> : null}
              <p key={attempt.id} className={h.verdictText}>
                {attempt.verdict}
              </p>
            </>
          ) : (
            <span className={h.verdictWaiting}>Solana is checking…</span>
          )}
        </div>
      </div>
    </div>
  )
}
