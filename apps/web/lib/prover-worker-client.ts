import type { JoinSplitProofResult } from '@audren/sdk/prover'

export interface ProverWorkerReply {
  id: number
  ok: boolean
  result?: JoinSplitProofResult
  elapsedMs?: number
  error?: string
}

interface PendingJob {
  resolve: (reply: ProverWorkerReply) => void
  reject: (error: Error) => void
  timer: ReturnType<typeof setTimeout>
}

export const PROVER_WORKER_URL = '/wasm/prover-worker.js?v=1.3.0'
export const PROVER_WARM_TIMEOUT_MS = 30_000
export const PROVER_PROVE_TIMEOUT_MS = 45_000

let worker: Worker | null = null
let nextRequestId = 1
const pending = new Map<number, PendingJob>()

function terminateAndRejectAll(err: Error): void {
  const active = worker
  worker = null
  active?.terminate()
  pending.forEach((job) => {
    clearTimeout(job.timer)
    job.reject(err)
  })
  pending.clear()
}

export function callProverWorker(
  msg: Record<string, unknown>,
  transfer: Transferable[],
  timeoutMs: number,
): Promise<ProverWorkerReply> {
  if (!worker) {
    worker = new Worker(PROVER_WORKER_URL)
    worker.onmessage = ({ data }: MessageEvent<ProverWorkerReply>) => {
      const job = pending.get(data.id)
      if (!job) return
      clearTimeout(job.timer)
      pending.delete(data.id)
      if (data.ok) job.resolve(data)
      else job.reject(new Error(data.error ?? 'Prover worker failed'))
    }
    worker.onerror = (ev: ErrorEvent) => {
      terminateAndRejectAll(new Error(ev.message || 'Prover worker error'))
    }
    worker.onmessageerror = () => {
      terminateAndRejectAll(new Error('Prover worker message decode error'))
    }
  }
  const id = nextRequestId++
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      terminateAndRejectAll(new Error('Prover worker timed out'))
    }, timeoutMs)
    pending.set(id, { resolve, reject, timer })
    try {
      worker!.postMessage({ id, ...msg }, transfer)
    } catch (err) {
      terminateAndRejectAll(err instanceof Error ? err : new Error(String(err)))
    }
  })
}
