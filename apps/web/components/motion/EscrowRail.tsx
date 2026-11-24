'use client'

import { Pause, Play } from 'lucide-react'
import { SceneCaption } from './SceneControls'
import { useAutoStepper, useInView } from './hooks'
import m from './motion.module.css'
import r from './EscrowRail.module.css'
import { dockStyle, useDocks, usePhase } from './useDocks'

export interface RailFlow {
  id: string
  tab: string
  /** The two public middle stops. */
  stops: readonly [string, string]
  stopNotes: readonly [string, string]
  /** Chip label at each of the four stops. */
  chips: readonly [string, string, string, string]
  caption: string
}

export const RAIL_FLOWS: readonly RailFlow[] = [
  {
    id: 'dex',
    tab: 'DEX swap',
    stops: ['Escrow shard', 'DEX route'],
    stopNotes: ['1 of 16, signs the CPI', 'Jupiter, DFlow, OKX'],
    chips: ['sealed note', '100 USDC', 'SOL ≥ min out', 'sealed note'],
    caption:
      'Your note pays a shared escrow, the escrow trades through a public aggregator route, and the output is sealed back into the pool in the same transaction. This is the flow the app ships today.',
  },
  {
    id: 'lend',
    tab: 'Lending',
    stops: ['Escrow shard', 'Lending reserve'],
    stopNotes: ['1 of 16, signs the CPI', 'Kamino Lending USDC'],
    chips: ['sealed note', '100 USDC', 'cUSDC', 'sealed note'],
    caption:
      'Live on Mainnet via Tag 6 ExecViaEscrow: supply USDC to Kamino Lending in one escrow-signed call, keep interest-bearing cUSDC as a private note, and redeem back the same way.',
  },
  {
    id: 'vault',
    tab: 'Yield vault',
    stops: ['Escrow shard', 'Yield vault'],
    stopNotes: ['1 of 16, signs the CPI', 'Kamino Prime USDC'],
    chips: ['sealed note', '100 USDC', 'vault shares', 'sealed note'],
    caption:
      'Live on Mainnet via Tag 6 ExecViaEscrow: enter a single-call yield vault such as Kamino Prime USDC, hold the minted shares privately, and withdraw back to shielded USDC the same way.',
  },
  {
    id: 'stake',
    tab: 'Liquid staking',
    stops: ['Escrow shard', 'LST route'],
    stopNotes: ['1 of 16, signs the CPI', 'Swaps WSOL for JitoSOL'],
    chips: ['sealed note', '2 WSOL', 'JitoSOL', 'sealed note'],
    caption: 'Swap shielded SOL into a liquid staking token through an aggregator route, without a wallet linked to you ever holding it.',
  },
  {
    id: 'lp',
    tab: 'Perp LP',
    stops: ['Escrow shard', 'JLP route'],
    stopNotes: ['1 of 16, signs the CPI', 'Buys or sells JLP'],
    chips: ['sealed note', '100 USDC', 'JLP', 'sealed note'],
    caption: 'Buy or sell perp liquidity tokens such as JLP through an aggregator route and hold them as a private note.',
  },
  {
    id: 'session',
    tab: 'Sessions',
    stops: ['Exit + unwrap', 'Session wallet B₀'],
    stopNotes: ['Pays its own fee', 'Borrow or trade perps'],
    chips: ['sealed note', '2 SOL', 'positions public', 'swept back'],
    caption:
      'Stateful protocols use a fresh session wallet: fund it from the pool with zero prior SOL, trade in public, then sweep the rest back with a public deposit. The exit, the positions and the sweep are linked through that wallet.',
  },
]

const FLOW_MS = 6200
const PHASE_TIMES = [700, 1900, 3100] as const

/**
 * One escrow primitive, many DeFi programs. The wrapper exposes
 * `data-active-flow` so sibling cards can highlight with `:has()`.
 */
export function EscrowRail() {
  const [viewRef, inView] = useInView<HTMLDivElement>()
  const stepper = useAutoStepper({ count: RAIL_FLOWS.length, durations: FLOW_MS, active: inView })
  const flow = RAIL_FLOWS[stepper.step] ?? RAIL_FLOWS[0]
  const phase = usePhase(`${flow.id}-${stepper.cycle}`, stepper.reduced, PHASE_TIMES)
  const stageRef = useDocks<HTMLDivElement>(`${flow.id}-${phase}`)

  return (
    <div ref={viewRef} className={r.wrap} data-active-flow={flow.id}>
      <div className={r.head}>
        <button
          type="button"
          className={m.playBtn}
          onClick={stepper.togglePlay}
          aria-label={stepper.playing ? 'Pause DeFi walkthrough' : 'Play DeFi walkthrough'}
        >
          {stepper.playing ? <Pause size={13} aria-hidden="true" /> : <Play size={13} aria-hidden="true" />}
        </button>
        <div className={r.tabs} role="group" aria-label="DeFi flows through the escrow">
          {RAIL_FLOWS.map((f, idx) => (
            <button
              key={f.id}
              type="button"
              aria-pressed={idx === stepper.step}
              className={r.tab}
              data-selected={idx === stepper.step ? 'true' : 'false'}
              onClick={() => stepper.select(idx)}
            >
              {f.tab}
            </button>
          ))}
        </div>
      </div>

      <div className={r.scene}>
        <div ref={stageRef} className={r.stage} data-flow={flow.id} aria-hidden="true">
          <div className={r.privateBand} data-side="start">
            <span className={r.bandLabel}>Private</span>
          </div>
          <div className={r.publicBand}>
            <span className={r.bandLabel}>Public on Solana</span>
          </div>
          <div className={r.privateBand} data-side="end">
            <span className={r.bandLabel}>Private</span>
          </div>

          {[
            { title: 'Shared pool', note: 'Your sealed note' },
            { title: flow.stops[0], note: flow.stopNotes[0] },
            { title: flow.stops[1], note: flow.stopNotes[1] },
            {
              title: 'Shared pool',
              note: flow.id === 'session' ? 'Public deposit → new note' : 'Fresh sealed note',
            },
          ].map((node, idx) => (
            <div
              key={idx}
              className={r.node}
              data-idx={idx}
              data-reached={phase >= idx ? 'true' : 'false'}
            >
              <span className={r.nodeIdx}>{idx + 1}</span>
              <span className={r.nodeTitle}>{node.title}</span>
              <span className={r.nodeNote}>{node.note}</span>
              <span className={r.dock} data-dock={`n${idx}`} />
            </div>
          ))}

          <span
            className={`${m.chip} ${r.chip}`}
            data-tone={phase === 0 || phase === 3 ? 'sealed' : 'public'}
            style={dockStyle(`n${phase}`)}
          >
            <span key={flow.chips[phase]} className={r.chipLabel}>
              {flow.chips[phase]}
            </span>
          </span>
        </div>
      </div>

      <SceneCaption
        className={r.caption}
        texts={RAIL_FLOWS.map((f) => f.caption)}
        index={stepper.step}
        live={!stepper.playing}
      />
    </div>
  )
}
