'use client'

import type { CSSProperties } from 'react'
import { Check } from 'lucide-react'
import { SceneCaption, SceneControls } from './SceneControls'
import { useAutoStepper, useInView } from './hooks'
import m from './motion.module.css'
import h from './HowScenes.module.css'

const MEMOS = 96
const MATCHES: Record<number, { amount: string; source: string }> = {
  29: { amount: '+500 USDC', source: 'Deposit from Alice' },
  70: { amount: '+2 SOL', source: 'Private transfer' },
}

const STEPS = [
  {
    label: 'Download page',
    caption:
      'Your device downloads a whole MemoPage of 96 encrypted memos through an ordinary RPC call. The RPC cannot tell which memo, if any, is yours.',
  },
  {
    label: 'Check view tags',
    caption:
      'Each memo carries a 2-byte view tag. Your view key predicts the tag for memos meant for you, so 65,535 of every 65,536 strangers are skipped without decrypting.',
  },
  {
    label: 'Decrypt matches',
    caption:
      'Only the matching memos are decrypted with ChaCha20-Poly1305, revealing the token, amount and payment reference.',
  },
  {
    label: 'Verify on-chain',
    caption:
      'Each decrypted note is re-hashed and compared with the commitment Solana stored, so a forged memo can never add fake balance.',
  },
  {
    label: 'Done',
    caption:
      'No indexer and no account. Your device keeps your own notes plus the compact tree hashes it needs to spend them, and discards the raw pages.',
  },
] as const

const STEP_MS = [2200, 5200, 3200, 3200, 4200] as const

/** How a wallet finds its own payments in a page of strangers' memos. */
export function ViewTagScanner() {
  const [ref, inView] = useInView<HTMLDivElement>()
  const stepper = useAutoStepper({ count: STEPS.length, durations: STEP_MS, active: inView })
  const step = stepper.step
  const matchList = Object.entries(MATCHES)

  return (
    <div ref={ref} className={h.scanner}>
      <div className={h.scanGridWrap}>
        <div className={h.scanGridHead}>
          <span>MemoPage · 96 memos · 10,240 B</span>
          <span className={h.scanLegend}>
            <i data-kind="skip" /> skipped <i data-kind="hit" /> yours
          </span>
        </div>
        <div
          key={step <= 1 ? `grid-${stepper.cycle}` : 'grid-settled'}
          className={h.scanGrid}
          data-step={step}
          aria-hidden="true"
        >
          {Array.from({ length: MEMOS }, (_, idx) => {
            const hit = idx in MATCHES
            return (
              <span
                key={idx}
                className={h.memo}
                data-hit={hit ? 'true' : 'false'}
                style={{ '--i': idx, '--row': Math.floor(idx / 12) } as CSSProperties}
              >
                {hit && step >= 3 ? <Check size={10} /> : null}
              </span>
            )
          })}
        </div>
      </div>

      <div className={h.scanSide}>
        <ol className={h.scanSteps}>
          {STEPS.slice(0, 4).map((s, idx) => (
            <li key={s.label} data-state={idx < step ? 'done' : idx === step ? 'active' : 'todo'}>
              <span className={h.scanStepNum}>{idx < step ? <Check size={11} /> : idx + 1}</span>
              {s.label}
            </li>
          ))}
        </ol>

        <div className={h.found} data-show={step >= 2 ? 'true' : 'false'}>
          {matchList.map(([idx, note]) => (
            <div key={idx} className={h.foundRow}>
              <span className={h.foundAmt}>{note.amount}</span>
              <span className={h.foundSrc}>{note.source}</span>
              {step >= 3 ? (
                <span className={`${m.stamp} ${m.stampOk}`}>matches chain</span>
              ) : null}
            </div>
          ))}
        </div>

        <p className={h.scanTally}>
          {step >= 2 ? (
            <>
              <strong>96</strong> memos checked · <strong>94</strong> skipped by tag ·{' '}
              <strong>2</strong> opened
            </>
          ) : step === 1 ? (
            'Comparing tags…'
          ) : (
            'Fetching the full page…'
          )}
        </p>
      </div>

      <div className={h.scanFoot}>
        <SceneCaption texts={STEPS.map((s) => s.caption)} index={step} live={!stepper.playing} />
        <SceneControls
          steps={STEPS.map((s) => s.label)}
          step={step}
          playing={stepper.playing}
          running={stepper.running}
          duration={stepper.duration}
          cycle={stepper.cycle}
          onSelect={stepper.select}
          onTogglePlay={stepper.togglePlay}
          label="Wallet scanning walkthrough"
        />
      </div>
    </div>
  )
}
