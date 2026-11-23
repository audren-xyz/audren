'use client'

import type { CSSProperties } from 'react'
import { SceneCaption, SceneControls } from './SceneControls'
import { useAutoStepper, useInView } from './hooks'
import x from './SubScenes.module.css'
import { usePhase } from './useDocks'

const PAGES = 6
const HIT_PAGE = 3
/** Share of a 10,240 B MemoPage covered by header + view tags + ephemeral keys. */
const SLICE_PCT = (3328 / 10240) * 100

const MODES = [
  {
    id: 'strict',
    label: 'Strict · default',
    caption:
      'Strict mode downloads every MemoPage in full. Every request looks the same, so the RPC provider cannot tell which page held your payment.',
    log: ['getMultipleAccounts · 30 full pages · 307,200 B'],
    verdict: 'RPC learns: nothing about which page matched',
  },
  {
    id: 'fast',
    label: 'Fast · opt-in',
    caption:
      'Fast mode, for long catch-ups of more than 25 pages, first fetches only the first 3,328 B of each page, then asks again for the page with a view-tag hit. Less bandwidth, but that second request points at your page, so use it only with an RPC you trust.',
    log: ['dataSlice [0..3,328] · 30 pages · 99,840 B', 'full page #4 · 10,240 B'],
    verdict: 'RPC learns: page #4 had a hit',
  },
] as const

const ROW_TIMES = [250, 650, 1050, 1450, 1850, 2250, 3100, 3900] as const

/** Strict vs fast wallet sync: what each mode reveals to the RPC provider. */
export function MemoFetchModes() {
  const [ref, inView] = useInView<HTMLDivElement>()
  const stepper = useAutoStepper({ count: 2, durations: 8200, active: inView })
  const mode = MODES[stepper.step] ?? MODES[0]
  const phase = usePhase(`${mode.id}-${stepper.cycle}`, stepper.reduced, ROW_TIMES)
  const fast = mode.id === 'fast'
  const rowsDone = Math.min(phase, PAGES)
  const secondFetch = fast && phase >= PAGES + 1
  const summary = phase >= PAGES + 2

  return (
    <div ref={ref} className={x.fetch}>
      <div className={x.fetchHead}>
        <span className={x.fetchTitle}>Syncing a wallet: strict vs fast page downloads</span>
        <span className={x.fetchMeta}>First 6 of a 30-page catch-up · your payment is on page #4</span>
      </div>
      <div className={x.fetchPages} aria-hidden="true">
        <div className={x.fetchScale}>
          <span>0</span>
          <span style={{ left: `${SLICE_PCT}%` }}>3,328 B</span>
          <span style={{ right: 0 }}>10,240 B</span>
        </div>
        {Array.from({ length: PAGES }, (_, idx) => {
          const fetched = idx < rowsDone
          const full = fetched && !fast
          const hit = idx === HIT_PAGE
          return (
            <div key={idx} className={x.fetchRow}>
              <span className={x.fetchLabel}>MemoPage #{idx + 1}</span>
              <span className={x.fetchBar}>
                <span className={x.fetchSlice} style={{ width: `${SLICE_PCT}%` }} />
                <span
                  className={x.fetchFill}
                  data-on={fetched ? 'true' : 'false'}
                  style={{ '--to': full ? 1 : SLICE_PCT / 100 } as CSSProperties}
                />
                {fast && hit ? (
                  <span
                    className={x.fetchSecond}
                    data-on={secondFetch ? 'true' : 'false'}
                    style={{ left: `${SLICE_PCT}%` }}
                  />
                ) : null}
              </span>
              <span className={x.fetchTag} data-hit={hit && phase >= PAGES ? 'true' : 'false'}>
                {hit && phase >= PAGES ? 'tag hit' : ''}
              </span>
            </div>
          )
        })}
      </div>

      <div className={x.fetchSide}>
        <span className={x.fetchSideHead}>What the RPC provider sees</span>
        <ol className={x.fetchLog}>
          {mode.log.map((line, idx) => {
            const shown = idx === 0 ? phase >= 1 : secondFetch
            return (
              <li key={line} data-shown={shown ? 'true' : 'false'} data-alert={idx === 1 ? 'true' : 'false'}>
                {line}
              </li>
            )
          })}
        </ol>
        <span
          className={`${x.fetchVerdict} ${summary ? '' : x.fetchVerdictHidden}`}
          data-alert={fast ? 'true' : 'false'}
        >
          {mode.verdict}
        </span>
      </div>

      <div className={x.fetchFoot}>
        <SceneCaption texts={MODES.map((md) => md.caption)} index={stepper.step} live={!stepper.playing} />
        <SceneControls
          steps={MODES.map((md) => md.label)}
          step={stepper.step}
          playing={stepper.playing}
          running={stepper.running}
          duration={stepper.duration}
          cycle={stepper.cycle}
          onSelect={stepper.select}
          onTogglePlay={stepper.togglePlay}
          label="Wallet sync modes"
        />
      </div>
    </div>
  )
}
