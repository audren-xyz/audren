import type { JoinSplitProofResult } from '@audren/sdk/prover'

export interface ProverWorkerReply {
  id: number
  ok: boolean
  result?: JoinSplitProofResult
  elapsedMs?: number
  error?: string
}

interface PendingJob {
  kind: 'warm' | 'prove'
  resolve: (reply: ProverWorkerReply) => void
  reject: (error: Error) => void
  timer: ReturnType<typeof setTimeout>
  cleanupAbort?: () => void
}

export const PROVER_WORKER_URL = '/wasm/prover-worker.js?v=c57b404f'
export const PROVER_WARM_TIMEOUT_MS = 30_000
export const PROVER_PROVE_TIMEOUT_MS = 45_000

let worker: Worker | null = null
let nextRequestId = 1
const pending = new Map<number, PendingJob>()

function detachAndTerminate(active: Worker | null): void {
  if (!active) return
  active.onmessage = null
  active.onerror = null
  active.onmessageerror = null
  active.terminate()
}

function terminateAndRejectAll(err: Error): void {
  const active = worker
  worker = null
  detachAndTerminate(active)
  pending.forEach((job) => {
    clearTimeout(job.timer)
    job.cleanupAbort?.()
    job.reject(err)
  })
  pending.clear()
}

export function callProverWorker(
  msg: Record<string, unknown>,
  transfer: Transferable[],
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<ProverWorkerReply> {
  if (signal?.aborted) {
    return Promise.reject(new Error('Prover request aborted'))
  }
  const kind: 'warm' | 'prove' = msg.type === 'warm' ? 'warm' : 'prove'
  if (!worker) {
    const w = new Worker(PROVER_WORKER_URL)
    worker = w
    w.onmessage = ({ data }: MessageEvent<ProverWorkerReply>) => {
      if (worker !== w) return
      const job = pending.get(data.id)
      if (!job) return
      clearTimeout(job.timer)
      job.cleanupAbort?.()
      pending.delete(data.id)
      if (data.ok) job.resolve(data)
      else job.reject(new Error(data.error ?? 'Prover worker failed'))
    }
    w.onerror = (ev: ErrorEvent) => {
      if (worker !== w) return
      terminateAndRejectAll(new Error(ev.message || 'Prover worker error'))
    }
    w.onmessageerror = () => {
      if (worker !== w) return
      terminateAndRejectAll(new Error('Prover worker message decode error'))
    }
  }
  const id = nextRequestId++
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      const job = pending.get(id)
      if (!job) return
      const hasActiveProve = Array.from(pending.values()).some((j) => j.kind === 'prove')
      if (job.kind === 'warm' && hasActiveProve) {
        // Never kill an active proof generation when an earlier background warm-up times out.
        pending.delete(id)
        job.cleanupAbort?.()
        job.reject(new Error('Prover warm-up timed out while proving is active'))
        return
      }
      terminateAndRejectAll(new Error('Prover worker timed out'))
    }, timeoutMs)

    let cleanupAbort: (() => void) | undefined
    if (signal) {
      const onAbort = () => {
        const job = pending.get(id)
        if (!job) return
        clearTimeout(job.timer)
        pending.delete(id)
        job.cleanupAbort?.()
        if (job.kind === 'prove' && !Array.from(pending.values()).some((j) => j.kind === 'prove')) {
          terminateAndRejectAll(new Error('Prover request aborted'))
        }
        job.reject(new Error('Prover request aborted'))
      }
      signal.addEventListener('abort', onAbort, { once: true })
      cleanupAbort = () => signal.removeEventListener('abort', onAbort)
    }

    pending.set(id, { kind, resolve, reject, timer, cleanupAbort })
    try {
      worker!.postMessage({ id, ...msg }, transfer)
    } catch (err) {
      terminateAndRejectAll(err instanceof Error ? err : new Error(String(err)))
    }
  })
}
