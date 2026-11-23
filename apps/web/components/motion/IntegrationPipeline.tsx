'use client'

import { ArrowDown, ArrowUp, Check, Minus } from 'lucide-react'
import { SceneCaption, SceneControls } from './SceneControls'
import { useAutoStepper, useInView } from './hooks'
import x from './SubScenes.module.css'

interface PipelineStep {
  tag: string
  title: string
  line1: string
  line2: string
  foot: string
}

const WIRE = [
  { dir: 'down', text: 'Reads whole pages over ordinary RPC' },
  { dir: 'none', text: 'Nothing leaves the device' },
  { dir: 'up', text: 'Sends 1 transaction with a 192 B proof' },
  { dir: 'down', text: 'Reads the confirmation and new pages' },
] as const

const CAPTIONS = [
  'Sync: your app pulls public pages with getMultipleAccounts and keeps its own notes plus compact tree hashes, about 1.28 MB even at 10M pool notes, and drops the raw pages.',
  'Prove: the Groth16 proof is built locally. The spending key and the note details never go over the network.',
  'Submit: one transaction goes out, signed by your own wallet as fee payer (which shows your wallet) or handed to any relayer you choose.',
  'Settle: once confirmed, the spent marks land on-chain; your next sync marks the inputs spent and picks up the new change note.',
] as const

/** Sync → Prove → Submit → Settle, showing what crosses the network at each stage. */
export function IntegrationPipeline({ steps }: { steps: readonly PipelineStep[] }) {
  const [ref, inView] = useInView<HTMLDivElement>()
  const stepper = useAutoStepper({ count: steps.length, durations: 4600, active: inView })
  const active = stepper.step

  return (
    <div ref={ref} className={x.pipe}>
      <ol className={x.pipeCards}>
        {steps.map((step, idx) => {
          const state = idx < active ? 'done' : idx === active ? 'active' : 'todo'
          const wire = WIRE[idx]
          return (
            <li key={step.tag} className={x.pipeCard} data-state={state}>
              <div className={x.pipeBody}>
                <span className={x.pipeWire} data-dir={wire?.dir} data-live={state === 'active' ? 'true' : 'false'}>
                  {wire?.dir === 'down' ? (
                    <ArrowDown size={12} aria-hidden="true" />
                  ) : wire?.dir === 'up' ? (
                    <ArrowUp size={12} aria-hidden="true" />
                  ) : (
                    <Minus size={12} aria-hidden="true" />
                  )}
                  {wire?.text}
                </span>
                <span className={x.pipeTag}>
                  {state === 'done' ? <Check size={11} aria-hidden="true" /> : null}
                  {step.tag}
                </span>
                <span className={x.pipeTitle}>{step.title}</span>
                <span className={x.pipeLine}>{step.line1}</span>
                <span className={x.pipeLine}>{step.line2}</span>
                <span className={x.pipeFoot}>{step.foot}</span>
                {idx === 1 ? (
                  <span className={x.pipeProve} aria-hidden="true">
                    <span
                      key={state === 'active' ? `p-${stepper.cycle}` : state}
                      className={x.pipeProveFill}
                      data-state={state}
                    />
                  </span>
                ) : null}
              </div>
            </li>
          )
        })}
      </ol>

      <SceneCaption texts={CAPTIONS} index={active} live={!stepper.playing} />

      <SceneControls
        steps={steps.map((s) => s.tag.replace(/^\d+\.\s*/, ''))}
        step={active}
        playing={stepper.playing}
        running={stepper.running}
        duration={stepper.duration}
        cycle={stepper.cycle}
        onSelect={stepper.select}
        onTogglePlay={stepper.togglePlay}
        label="Integration pipeline steps"
      />
    </div>
  )
}
