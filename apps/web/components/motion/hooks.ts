'use client'

import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react'

/* ----------------------------------------------------------------------------
   Shared motion primitives for the explanatory scenes.

   Every scene follows the same contract:
   - it only advances while it is on screen and the tab is visible,
   - it never auto-advances when the visitor prefers reduced motion,
   - every step is reachable by hand (buttons, not hover or scroll position).
   ---------------------------------------------------------------------------- */

const REDUCED_QUERY = '(prefers-reduced-motion: reduce)'

function subscribeReducedMotion(onChange: () => void) {
  const mq = window.matchMedia(REDUCED_QUERY)
  mq.addEventListener('change', onChange)
  return () => mq.removeEventListener('change', onChange)
}

export function useReducedMotion(): boolean {
  return useSyncExternalStore(
    subscribeReducedMotion,
    () => window.matchMedia(REDUCED_QUERY).matches,
    () => false,
  )
}

function subscribeVisibility(onChange: () => void) {
  document.addEventListener('visibilitychange', onChange)
  return () => document.removeEventListener('visibilitychange', onChange)
}

export function usePageVisible(): boolean {
  return useSyncExternalStore(
    subscribeVisibility,
    () => document.visibilityState === 'visible',
    () => true,
  )
}

const noopSubscribe = () => () => {}

/**
 * False in the static HTML and during hydration, true afterwards. Scenes use
 * it to ship their finished state to crawlers, link previews and no-JS
 * visitors, and only "arm" the opening animation once scripts are running.
 */
export function useHydrated(): boolean {
  return useSyncExternalStore(
    noopSubscribe,
    () => true,
    () => false,
  )
}

interface InViewOptions {
  /**
   * Viewport band the element has to reach, as an IntersectionObserver
   * rootMargin. Measured against the viewport rather than the element's own
   * size, so tall scenes on short screens still start.
   */
  rootMargin?: string
}

/** Tracks whether an element has reached the middle band of the viewport. */
export function useInView<T extends Element>({ rootMargin = '-18% 0px -18% 0px' }: InViewOptions = {}) {
  const ref = useRef<T | null>(null)
  const [inView, setInView] = useState(false)

  useEffect(() => {
    const el = ref.current
    if (!el) return
    const io = new IntersectionObserver(
      ([entry]) => {
        if (entry) setInView(entry.isIntersecting)
      },
      { threshold: 0, rootMargin },
    )
    io.observe(el)
    return () => io.disconnect()
  }, [rootMargin])

  return [ref, inView] as const
}

interface StepperOptions {
  count: number
  /** Milliseconds to hold each step (one value for all, or one per step). */
  durations: number | readonly number[]
  /** External gate, normally "the scene is on screen". */
  active: boolean
  /** Restart at step 0 after the last step (default) or stop there. */
  loop?: boolean
  /** Changing this goes back to step 0 and restarts the timer (e.g. a new tab was chosen). */
  resetKey?: string
}

/**
 * Auto-advancing step machine. Whenever the scene (re)starts running — it
 * scrolls into view, the tab becomes visible, or the visitor presses play —
 * the current step replays from its beginning, and `cycle` changes so
 * progress tracks and sub-step choreography restart in sync.
 */
export function useAutoStepper({
  count,
  durations,
  active,
  loop = true,
  resetKey = '',
}: StepperOptions) {
  const reduced = useReducedMotion()
  const visible = usePageVisible()
  const [step, setStep] = useState(0)
  const [playing, setPlaying] = useState(true)
  /** Reduced-motion visitors start paused; pressing play is an explicit opt-in. */
  const [optedIn, setOptedIn] = useState(false)
  const motionOK = !reduced || optedIn

  // A new resetKey (another tab) starts again from the first step, keeping play/pause.
  const [lastResetKey, setLastResetKey] = useState(resetKey)
  if (lastResetKey !== resetKey) {
    setLastResetKey(resetKey)
    setStep(0)
  }

  const durationsKey = typeof durations === 'number' ? String(durations) : durations.join(',')
  const durationFor = useCallback(
    (idx: number) => {
      const list = durationsKey.split(',').map(Number)
      return list.length === 1 ? list[0] : (list[idx] ?? list[list.length - 1])
    },
    [durationsKey],
  )

  const atEnd = !loop && step === count - 1
  const running = active && visible && playing && motionOK && !atEnd

  // Count every start of a run (derived-state pattern, no effect needed).
  const [runState, setRunState] = useState({ running, runId: 0 })
  if (runState.running !== running) {
    setRunState({ running, runId: running ? runState.runId + 1 : runState.runId })
  }
  const runId = runState.runId

  useEffect(() => {
    if (!running) return
    const timer = window.setTimeout(() => {
      setStep((s) => (s + 1 >= count ? (loop ? 0 : s) : s + 1))
    }, durationFor(step))
    return () => window.clearTimeout(timer)
  }, [running, step, count, loop, durationFor, runId, resetKey])

  const goTo = useCallback((idx: number) => setStep(((idx % count) + count) % count), [count])

  /** Manual navigation pauses auto-play so the visitor can read. */
  const select = useCallback(
    (idx: number) => {
      setPlaying(false)
      goTo(idx)
    },
    [goTo],
  )

  const togglePlay = useCallback(() => {
    if (!motionOK) {
      setOptedIn(true)
      setPlaying(true)
      if (!loop && step === count - 1) setStep(0)
      return
    }
    if (!playing && !loop && step === count - 1) setStep(0)
    setPlaying(!playing)
  }, [motionOK, playing, loop, step, count])

  const restart = useCallback(() => {
    setStep(0)
    setPlaying(true)
  }, [])

  return {
    step,
    playing: playing && motionOK,
    running,
    /** True while motion should be skipped (reduced motion and no opt-in). */
    reduced: !motionOK,
    duration: durationFor(step),
    /** Changes on every step change and every (re)start of a run. */
    cycle: `${resetKey}:${step}:${runId}`,
    goTo,
    select,
    togglePlay,
    restart,
  }
}
