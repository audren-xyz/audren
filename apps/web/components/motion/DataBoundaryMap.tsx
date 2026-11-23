'use client'

import { KeyRound, Lock } from 'lucide-react'
import { SceneCaption, SceneControls } from './SceneControls'
import { useAutoStepper, useInView } from './hooks'
import m from './motion.module.css'
import x from './SubScenes.module.css'
import { dockStyle, useDocks, usePhase } from './useDocks'

const ZONES = [
  {
    id: 'device',
    kicker: 'Stays on your device',
    title: 'Local keys & prover',
    items: [
      'Spend, nk & view key derivation',
      'ChaCha20-Poly1305 memo scan',
      'BN254 Groth16 Worker proving',
      'CompactWalletStore & receipts',
    ],
    foot: 'Never sent in ordinary RPC or relay calls',
  },
  {
    id: 'infra',
    kicker: 'Infrastructure operators',
    title: 'Web host, RPC & relay',
    items: [
      'Connection & IP request metadata',
      'Account lookups & swap quotes',
      'Relay: daily-salted IP rate limits',
      'Zero user spend or view keys',
    ],
    foot: 'Pluggable relay · RPC via the site host (self-host to change)',
  },
  {
    id: 'chain',
    kicker: 'Public Solana chain',
    title: 'On-chain visibility',
    items: [
      'Private transfer: hidden mint, amount & key',
      'Deposit / Exit: public amounts',
      'DeFi CPI & Bᵢ: public protocol legs',
      'Checkpoint, lane, fee payer & timing',
    ],
    foot: 'Permanent public blockchain record',
  },
] as const

const STEPS = [
  {
    label: 'Keys stay local',
    focus: 'device',
    caption:
      'Spending and view keys, memo decryption and proof generation all run in your browser. Keys are never part of a request.',
  },
  {
    label: 'Requests',
    focus: 'infra',
    caption:
      'To sync and fetch quotes, your browser talks to the web host (which forwards RPC reads) and optionally a relay. They can see your IP, which accounts you read and any public wallet you connect, never your keys.',
  },
  {
    label: 'Transactions',
    focus: 'infra',
    caption:
      'A finished transaction travels through an RPC or relay to Solana. A relay can pay the fee so your wallet is not the fee payer.',
  },
  {
    label: 'Public record',
    focus: 'chain',
    caption:
      'Solana keeps everything it receives forever: deposit and exit amounts, DeFi legs, fee payers and timing. A private transfer adds sealed notes, encrypted memos, spent marks and its proof, but no readable amounts or recipients.',
  },
] as const

const PHASE_TIMES = [350, 1350, 2400] as const

/** Three visibility zones with what actually crosses between them. */
export function DataBoundaryMap() {
  const [ref, inView] = useInView<HTMLDivElement>()
  const stepper = useAutoStepper({ count: STEPS.length, durations: 5200, active: inView })
  const step = stepper.step
  const current = STEPS[step] ?? STEPS[0]
  const phase = usePhase(`map-${stepper.cycle}`, stepper.reduced, PHASE_TIMES)
  const stageRef = useDocks<HTMLDivElement>(`${step}-${phase}`)

  let packet: { label: string; at: string; tone: 'proof' | 'public' } | null = null
  if (step === 1) packet = { label: 'page reads · IP', at: phase >= 1 ? 'infra' : 'device', tone: 'public' }
  if (step === 2) {
    packet = {
      label: 'signed tx · 192 B proof',
      at: phase >= 2 ? 'chain' : phase >= 1 ? 'infra' : 'device',
      tone: 'proof',
    }
  }

  return (
    <div ref={ref} className={x.boundary}>
      <div ref={stageRef} className={x.boundaryStage}>
        {ZONES.map((zone) => (
          <div
            key={zone.id}
            className={x.zone}
            data-zone={zone.id}
            data-focus={current.focus === zone.id ? 'true' : 'false'}
          >
            <span className={x.zoneKicker}>{zone.kicker}</span>
            <span className={x.zoneTitle}>{zone.title}</span>
            <ul className={x.zoneItems}>
              {zone.items.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
            {zone.id === 'device' ? (
              <span
                className={`${m.chip} ${x.zoneKey}`}
                data-tone="key"
                data-focus={step === 0 ? 'true' : 'false'}
                aria-hidden="true"
              >
                <KeyRound size={11} /> keys stay here <Lock size={10} />
              </span>
            ) : null}
            <span className={x.zoneFoot}>{zone.foot}</span>
            <span className={x.zoneDock} data-dock={zone.id} />
          </div>
        ))}
        {packet ? (
          <span
            key={`pkt-${step}-${stepper.cycle}`}
            className={`${m.chip} ${x.zonePacket}`}
            data-tone={packet.tone}
            style={dockStyle(packet.at)}
            aria-hidden="true"
          >
            {packet.label}
          </span>
        ) : null}
      </div>

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
        label="Data boundary walkthrough"
      />
    </div>
  )
}
