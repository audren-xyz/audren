'use client'

import { Check, KeyRound, Lock } from 'lucide-react'
import m from './motion.module.css'
import s from './PoolScene.module.css'
import { dockStyle, useDocks, usePhase } from './useDocks'

export type PoolCaseId = 'pay' | 'swap' | 'withdraw' | 'receipt'

type Dock = 'device' | 'pool' | 'poolL' | 'poolR' | 'outA' | 'outB'
type Tone = 'sealed' | 'proof' | 'public' | 'fee' | 'key'

interface PacketDef {
  id: string
  from: Dock
  to: Dock
  label: string
  tone: Tone
  /** Label/tone after the chip lands (phase 2). */
  settle?: { label: string; tone: Tone }
}

interface BoxCopy {
  title: string
  body: string
  /** Body once the step settles. */
  settled?: string
  tone?: 'public' | 'private'
}

interface StepDef {
  caption: string
  packets: PacketDef[]
  /** Every note in the pool pulses together: "one of these", never "this one". */
  pulse?: boolean
  /** Spent marks (nullifiers) recorded when this step settles. */
  spend?: number
  /** Fresh sealed notes appended when this step settles. */
  append?: number
  /** A single on-chain commitment is matched (receipt check). */
  match?: boolean
  device: { note: string; detail?: string; keyNote?: string }
  outA?: BoxCopy
  outB: BoxCopy
}

const POOL_NOTES = 15
const POOL_SLOTS = 18
const BASE_SPENT = 5
const MATCH_CELL = 6

const SCENES: Record<PoolCaseId, readonly [StepDef, StepDef, StepDef]> = {
  pay: [
    {
      caption:
        'Your 800 USDC sits in the shared pool as one sealed note among everyone else’s. Only your device holds the key that can spend it.',
      packets: [],
      device: { note: '800 USDC note' },
      outB: { title: 'Bob’s device', body: 'Shares a reusable aud1… address. Nothing received yet.', tone: 'private' },
    },
    {
      caption:
        'Your device builds a 192-byte proof that it owns unspent notes in this pool, without saying which. By default every transfer records two spent marks, padded if needed, so transfers look alike.',
      packets: [{ id: 'proof', from: 'device', to: 'pool', label: '192 B proof', tone: 'proof' }],
      pulse: true,
      spend: 2,
      device: { note: '800 USDC note', detail: 'Proving locally…' },
      outB: { title: 'Bob’s device', body: 'Shares a reusable aud1… address. Nothing received yet.', tone: 'private' },
    },
    {
      caption:
        'Solana accepts the proof, records the spend, and adds three sealed notes: Bob’s 420 USDC, your change (380 USDC, less any relay fee), and a zero-value pad or the relay’s fee note. Only Bob can spend his.',
      packets: [
        {
          id: 'memo',
          from: 'pool',
          to: 'outB',
          label: 'sealed note',
          tone: 'sealed',
          settle: { label: '+420 USDC', tone: 'key' },
        },
      ],
      append: 3,
      device: { note: '380 USDC change', detail: 'Hidden on-chain' },
      outB: {
        title: 'Bob’s device',
        body: 'Scanning new notes…',
        settled: 'Found and decrypted his note.',
        tone: 'private',
      },
    },
  ],
  swap: [
    {
      caption:
        'A proof spends your note into one of 16 shared escrow accounts. Sent through a relayer, your own wallet never signs.',
      packets: [
        {
          id: 'tok',
          from: 'pool',
          to: 'outA',
          label: 'sealed note',
          tone: 'sealed',
          settle: { label: '1 SOL', tone: 'public' },
        },
      ],
      pulse: true,
      spend: 2,
      device: { note: '1 SOL note', detail: 'Proof sent via relayer' },
      outA: { title: 'Escrow shard 7 of 16', body: 'Shared by every user', tone: 'public' },
      outB: { title: 'DeFi program', body: 'Aggregator swap', tone: 'public' },
    },
    {
      caption:
        'The escrow calls the DeFi program in the open. This leg shows its tokens and amounts like any other Solana trade.',
      packets: [
        {
          id: 'tok',
          from: 'outA',
          to: 'outB',
          label: '1 SOL',
          tone: 'public',
          settle: { label: '~0.8 JitoSOL', tone: 'public' },
        },
      ],
      device: { note: '1 SOL note', detail: 'Spent' },
      outA: { title: 'Escrow shard 7 of 16', body: 'Shared by every user', tone: 'public' },
      outB: { title: 'DeFi program', body: 'Running the trade…', settled: 'Output ≥ your minimum', tone: 'public' },
    },
    {
      caption:
        'Audren measures exactly what came back and seals it into a fresh note that only you can spend, next to a change note (a zero-value pad if nothing is left). No wallet linked to you ever held it.',
      packets: [
        {
          id: 'tok',
          from: 'outB',
          to: 'pool',
          label: '~0.8 JitoSOL',
          tone: 'public',
          settle: { label: 'sealed note', tone: 'sealed' },
        },
      ],
      append: 2,
      device: { note: 'JitoSOL note', detail: 'Hidden on-chain' },
      outA: { title: 'Escrow shard 7 of 16', body: 'Emptied again', tone: 'public' },
      outB: { title: 'DeFi program', body: 'Trade settled', tone: 'public' },
    },
  ],
  withdraw: [
    {
      caption:
        'Your device proves it owns a note somewhere in the pool, without pointing at which one.',
      packets: [{ id: 'proof', from: 'device', to: 'pool', label: '192 B proof', tone: 'proof' }],
      pulse: true,
      spend: 2,
      device: { note: '1.254 SOL note', detail: 'Proving locally…' },
      outA: { title: 'Relayer', body: 'Pays the network fee', tone: 'public' },
      outB: { title: 'Fresh wallet', body: '0 SOL, never used', tone: 'public' },
    },
    {
      caption:
        'In the same instruction, wrapped SOL becomes native SOL and the relayer’s fee comes out of the withdrawal itself.',
      packets: [
        {
          id: 'sol',
          from: 'poolL',
          to: 'poolL',
          label: '1.254 WSOL',
          tone: 'public',
          settle: { label: '1.25 SOL', tone: 'public' },
        },
        { id: 'fee', from: 'poolR', to: 'outA', label: '0.004 SOL fee', tone: 'fee' },
      ],
      device: { note: '1.254 SOL note', detail: 'Spent' },
      outA: { title: 'Relayer', body: 'Pays the network fee', settled: 'Reimbursed from payout', tone: 'public' },
      outB: { title: 'Fresh wallet', body: '0 SOL, never used', tone: 'public' },
    },
    {
      caption:
        '1.25 SOL lands publicly in a fresh wallet that needed no SOL beforehand. A zero-value pad note makes a full exit look like a partial one (the app drops the pad while the pool is paused so the exit can still settle); amount and timing can still hint at a link.',
      packets: [
        { id: 'fee', from: 'outA', to: 'outA', label: '0.004 SOL fee', tone: 'fee' },
        { id: 'sol', from: 'pool', to: 'outB', label: '1.25 SOL', tone: 'public' },
      ],
      append: 1,
      device: { note: 'Nothing left', detail: 'Full exit, padded' },
      outA: { title: 'Relayer', body: 'Reimbursed from payout', tone: 'public' },
      outB: { title: 'Fresh wallet', body: 'Receiving…', settled: '+1.25 SOL, publicly', tone: 'public' },
    },
  ],
  receipt: [
    {
      caption:
        'You pick one note and export its opening: the token, the amount, its one-time owner key and the random blinding that sealed it.',
      packets: [{ id: 'rcpt', from: 'device', to: 'outB', label: '1-note receipt', tone: 'key' }],
      device: { note: '500 USDC · invoice 114', detail: 'Opening one note' },
      outB: { title: 'Accountant', body: 'Waiting for a receipt', settled: 'Receipt received', tone: 'private' },
    },
    {
      caption:
        'The accountant hashes it once and finds the identical commitment already on Solana. A match proves this exact note was created on-chain; it does not show whether it is still unspent or who holds it now.',
      packets: [{ id: 'hash', from: 'outB', to: 'pool', label: 'Poseidon5 hash', tone: 'proof' }],
      match: true,
      device: { note: '500 USDC · invoice 114', detail: 'Shared one note' },
      outB: { title: 'Accountant', body: 'Hashing the receipt…', settled: 'Matches on-chain', tone: 'private' },
    },
    {
      caption:
        'They also learn where the note sits in the pool, which points to the transaction that created it. Never your spending key, other notes or balance. A receipt cannot move funds.',
      packets: [],
      device: { note: '500 USDC · invoice 114', detail: 'Other notes untouched', keyNote: 'never shared' },
      outB: { title: 'Accountant', body: 'Sees 1 note · cannot spend', tone: 'private' },
    },
  ],
}

export function poolSceneCaption(caseId: PoolCaseId, step: number) {
  return SCENES[caseId][step]?.caption ?? ''
}

export function PoolScene({
  caseId,
  step,
  cycle,
  reduced,
}: {
  caseId: PoolCaseId
  step: number
  /** `cycle` from useAutoStepper: restarts the choreography of the current step. */
  cycle: string
  reduced: boolean
}) {
  const steps = SCENES[caseId]
  const def = steps[step] ?? steps[0]
  const phase = usePhase(`${caseId}-${step}-${cycle}`, reduced)
  const settled = phase >= 2
  const stageRef = useDocks<HTMLDivElement>(`${caseId}-${step}-${phase}`)

  // Effects accumulate across the steps already played.
  let spent = BASE_SPENT
  let appended = 0
  steps.forEach((st, idx) => {
    if (idx < step || (idx === step && settled)) {
      spent += st.spend ?? 0
      appended += st.append ?? 0
    }
  })
  const newSpentFrom = BASE_SPENT + steps.slice(0, step).reduce((n, st) => n + (st.spend ?? 0), 0)
  const matched = def.match && settled
  const twoBoxes = Boolean(def.outA)

  return (
    <div className={s.scene}>
      <div ref={stageRef} className={s.stage} data-case={caseId} aria-hidden="true">
        {/* YOUR DEVICE */}
        <div className={`${s.zone} ${s.zoneDevice}`}>
          <span className={s.zoneLabel}>Your device</span>
          <span className={`${m.chip} ${s.keyChip}`} data-tone="key">
            <KeyRound size={11} /> spend key
            <Lock size={10} className={s.keyLock} />
          </span>
          {def.device.keyNote && settled ? (
            <span className={`${m.stamp} ${m.stampOk} ${s.keyStamp}`}>{def.device.keyNote}</span>
          ) : null}
          <div className={s.noteCard}>
            <span className={s.noteLabel}>Only you can read</span>
            <span key={def.device.note} className={s.noteValue}>
              {def.device.note}
            </span>
            {def.device.detail ? (
              <span key={def.device.detail} className={s.noteDetail}>
                {def.device.detail}
              </span>
            ) : null}
          </div>
          <div className={s.dockRow}>
            <span data-dock="device" className={s.dock} />
          </div>
        </div>

        {/* SHARED POOL */}
        <div className={`${s.zone} ${s.zonePool}`}>
          <span className={s.zoneLabel}>Shared pool on Solana</span>
          <div className={s.noteGrid} data-pulse={def.pulse && phase >= 1 ? 'on' : 'off'}>
            {Array.from({ length: POOL_SLOTS }, (_, idx) => {
              const filled = idx < POOL_NOTES + appended
              const fresh = idx >= POOL_NOTES && filled
              const isMatch = matched && idx === MATCH_CELL
              return (
                <span
                  key={idx}
                  className={s.cell}
                  data-filled={filled ? 'true' : 'false'}
                  data-fresh={fresh ? 'true' : 'false'}
                  data-match={isMatch ? 'true' : 'false'}
                  style={{ '--i': idx } as React.CSSProperties}
                >
                  {isMatch ? <Check size={11} /> : null}
                </span>
              )
            })}
          </div>
          <div className={s.spentRow}>
            <span className={s.spentLabel}>Spent marks</span>
            <span className={s.ticks}>
              {Array.from({ length: spent }, (_, idx) => (
                <span key={idx} className={s.tick} data-new={idx >= newSpentFrom ? 'true' : 'false'} />
              ))}
            </span>
          </div>
          <div className={s.dockRow}>
            <span data-dock="pool" className={s.dock} />
            <span data-dock="poolL" className={`${s.dock} ${s.dockL}`} />
            <span data-dock="poolR" className={`${s.dock} ${s.dockR}`} />
          </div>
        </div>

        {/* OUTSIDE / COUNTERPARTY */}
        <div className={`${s.zone} ${s.zoneOut}`} data-split={twoBoxes ? 'true' : 'false'}>
          {def.outA ? <OutBox box={def.outA} dock="outA" settled={settled} /> : null}
          <OutBox box={def.outB} dock="outB" settled={settled} />
        </div>

        {/* MOVING CHIPS */}
        <div className={s.packets}>
          {def.packets.map((p) => {
            const at = phase >= 1 ? p.to : p.from
            const label = settled && p.settle ? p.settle.label : p.label
            const tone = settled && p.settle ? p.settle.tone : p.tone
            return (
              <span key={p.id} className={`${m.chip} ${s.packet}`} data-tone={tone} style={dockStyle(at)}>
                <span key={label} className={s.packetLabel}>
                  {label}
                </span>
              </span>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function OutBox({ box, dock, settled }: { box: BoxCopy; dock: Dock; settled: boolean }) {
  const body = settled && box.settled ? box.settled : box.body
  return (
    <div className={s.outBox} data-tone={box.tone ?? 'private'}>
      <span className={s.zoneLabel}>
        {box.title}
        {box.tone === 'public' ? <span className={s.publicTag}>public</span> : null}
      </span>
      <span key={body} className={s.outBody}>
        {body}
      </span>
      <div className={s.dockRow}>
        <span data-dock={dock} className={s.dock} />
      </div>
    </div>
  )
}
