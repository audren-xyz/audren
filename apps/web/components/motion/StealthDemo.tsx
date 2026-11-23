'use client'

import { ArrowRight } from 'lucide-react'
import { SceneCaption, SceneControls } from './SceneControls'
import { useAutoStepper, useInView } from './hooks'
import m from './motion.module.css'
import h from './HowScenes.module.css'
import { usePhase } from './useDocks'

const PAYMENTS = [
  { payer: 'Alice', amount: '500 USDC', owner: '0x5c1e…a903' },
  { payer: 'Carol', amount: '2 SOL', owner: '0x91af…07bd' },
  { payer: 'Dan', amount: '12,000 BONK', owner: '0x2e64…c118' },
] as const

const CAPTIONS = [
  'Alice pays your aud1… address. Her wallet mixes fresh randomness with your public keys and derives a one-time owner key.',
  'Carol pays the same address. Fresh randomness again, so the owner key on-chain is completely different.',
  'Dan pays too. Each deposit is public, but its owner is a new key that does not directly identify your address.',
  'Your device recognises all three with its view key. Timing, amounts and outside information can still hint at a link, so use the address with that in mind.',
] as const

const STEP_LABELS = ['Alice pays', 'Carol pays', 'Dan pays', 'You find all 3'] as const
const STEP_MS = [4200, 4200, 4400, 6000] as const
const PHASE_TIMES = [450, 1300] as const

/** One reusable aud1… address → a different one-time owner on every payment. */
export function StealthDemo() {
  const [ref, inView] = useInView<HTMLDivElement>()
  const stepper = useAutoStepper({ count: 4, durations: STEP_MS, active: inView })
  const phase = usePhase(`stealth-${stepper.cycle}`, stepper.reduced, PHASE_TIMES)
  const { step } = stepper

  return (
    <div ref={ref} className={h.stealth}>
      <div className={h.stealthHead}>
        <h3>One address, a new owner on every payment</h3>
        <span className={`${m.chip} ${h.addrChip}`} data-tone="key">
          aud1qyy8…ppvea6
        </span>
      </div>

      <div className={h.stealthRows} aria-hidden="true">
        {PAYMENTS.map((p, idx) => {
          const state = idx < step || step === 3 ? 'done' : idx === step ? 'active' : 'todo'
          const printed = state === 'done' || (state === 'active' && phase >= 2)
          return (
            <div key={p.payer} className={h.stealthRow} data-state={state}>
              <span className={h.stealthPayer}>
                <span className={h.payerName}>{p.payer}’s wallet</span>
                <span className={h.payerAmt}>pays {p.amount} · public</span>
              </span>
              <span
                className={h.mixer}
                data-on={state === 'active' && phase >= 1 && phase < 2 ? 'true' : 'false'}
              >
                <span className={h.mixerTop}>fresh randomness + your keys</span>
                <span className={h.mixerFn}>Poseidon3(2, S, tweak)</span>
              </span>
              <ArrowRight size={14} className={h.stealthArrow} />
              <span className={h.ownerCell}>
                <span className={h.ownerLabel}>On-chain owner</span>
                <span className={h.ownerHex} data-printed={printed ? 'true' : 'false'}>
                  {p.owner}
                </span>
              </span>
              {step === 3 ? (
                <span className={`${m.stamp} ${m.stampOk} ${h.foundStamp}`} style={{ animationDelay: `${idx * 160}ms` }}>
                  yours
                </span>
              ) : null}
            </div>
          )
        })}
      </div>

      <SceneCaption texts={CAPTIONS} index={step} live={!stepper.playing} />

      <SceneControls
        steps={STEP_LABELS}
        step={step}
        playing={stepper.playing}
        running={stepper.running}
        duration={stepper.duration}
        cycle={stepper.cycle}
        onSelect={stepper.select}
        onTogglePlay={stepper.togglePlay}
        label="Stealth address walkthrough"
      />
    </div>
  )
}
