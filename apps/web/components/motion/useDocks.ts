'use client'

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'

/**
 * Measures every `[data-dock="name"]` anchor inside a stage and publishes its
 * centre as CSS custom properties on the stage (`--dock-name-x/-y`). Moving
 * chips position themselves with those variables, so they always land on the
 * real layout (desktop row, stacked mobile column, or anything in between)
 * without duplicating coordinates in CSS.
 */
export function useDocks<T extends HTMLElement>(changeKey: string) {
  const ref = useRef<T | null>(null)

  const measure = useCallback(() => {
    const stage = ref.current
    if (!stage) return
    const base = stage.getBoundingClientRect()
    stage.querySelectorAll<HTMLElement>('[data-dock]').forEach((el) => {
      const r = el.getBoundingClientRect()
      const name = el.dataset.dock
      if (!name) return
      stage.style.setProperty(`--dock-${name}-x`, `${(r.left + r.width / 2 - base.left).toFixed(1)}px`)
      stage.style.setProperty(`--dock-${name}-y`, `${(r.top + r.height / 2 - base.top).toFixed(1)}px`)
    })
    stage.dataset.measured = 'true'
  }, [])

  useLayoutEffect(() => {
    measure()
  }, [measure, changeKey])

  useEffect(() => {
    const stage = ref.current
    if (!stage) return
    const ro = new ResizeObserver(() => measure())
    ro.observe(stage)
    document.fonts?.ready.then(measure).catch(() => {})
    return () => ro.disconnect()
  }, [measure])

  return ref
}

const DEFAULT_PHASES = [380, 1450] as const

/**
 * Sub-step choreography inside one step. With the default timings:
 * 0 = chips appear at their origin, 1 = chips travel, 2 = effects settle
 * (labels flip, stamps land). The phase restarts whenever `key` changes.
 * Reduced motion jumps straight to the final phase.
 */
export function usePhase(key: string, reduced: boolean, times: readonly number[] = DEFAULT_PHASES) {
  const [state, setState] = useState({ key: '', phase: 0 })
  const timesKey = times.join(',')

  useEffect(() => {
    if (reduced) return
    const timers = timesKey
      .split(',')
      .map(Number)
      .map((at, idx) => window.setTimeout(() => setState({ key, phase: idx + 1 }), at))
    return () => timers.forEach((t) => window.clearTimeout(t))
  }, [key, reduced, timesKey])

  if (reduced) return times.length
  return state.key === key ? state.phase : 0
}

/** Inline style that places a chip on a measured dock. */
export function dockStyle(dock: string): React.CSSProperties {
  return { left: `var(--dock-${dock}-x)`, top: `var(--dock-${dock}-y)` }
}
