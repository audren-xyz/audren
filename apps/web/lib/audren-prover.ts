import { AudrenWasmProver, encodeJoinsplitWitness, type JoinSplitProofResult, type JoinSplitWitness } from '@audren/sdk/prover'

export * from '@audren/sdk/prover'
export * from './vault-storage'

const WASM_URL = '/wasm/audren_circuits.wasm?v=1.2.0'
const PK_URL = '/wasm/audren_joinsplit.pk?v=2b22603e'

type Reply = { id: number; ok: boolean; result?: JoinSplitProofResult; elapsedMs?: number; error?: string }

let cached: Promise<AudrenWasmProver> | null = null
let worker: Worker | null = null
let reqId = 1
const pending = new Map<number, [(r: Reply) => void, (e: Error) => void]>()

function rpc(msg: Record<string, unknown>, transfer: Transferable[] = []): Promise<Reply> {
  if (!worker) {
    worker = new Worker('/wasm/prover-worker.js?v=1.2.0')
    worker.onmessage = ({ data }: MessageEvent<Reply>) => {
      const p = pending.get(data.id)
      if (!p) return
      pending.delete(data.id)
      if (data.ok) p[0](data)
      else p[1](new Error(data.error ?? 'Prover failed'))
    }
    worker.onerror = (ev: ErrorEvent) => {
      const e = new Error(ev.message || 'Prover worker error')
      pending.forEach(([, rej]) => rej(e))
      pending.clear()
      worker = null
    }
  }
  const id = reqId++
  return new Promise((res, rej) => {
    pending.set(id, [res, rej])
    worker!.postMessage({ id, ...msg }, transfer)
  })
}

export function getBrowserWasmProver(wasmUrl = WASM_URL, pkUrl = PK_URL): Promise<AudrenWasmProver> {
  return (cached ??= AudrenWasmProver.init({ wasmUrl, pkUrl }).catch((e) => {
    cached = null
    throw e
  }))
}

export async function warmBrowserWasmProver(wasmUrl = WASM_URL, pkUrl = PK_URL): Promise<void> {
  if (typeof Worker !== 'undefined') await rpc({ type: 'warm', wasmUrl, pkUrl })
  else await getBrowserWasmProver(wasmUrl, pkUrl)
}

export async function proveJoinsplitInBrowser(
  witness: JoinSplitWitness,
  seed32?: Uint8Array,
): Promise<{ result: JoinSplitProofResult; elapsedMs: number }> {
  if (typeof Worker !== 'undefined') {
    const wb = encodeJoinsplitWitness(witness)
    const s = seed32 ? new Uint8Array(seed32) : crypto.getRandomValues(new Uint8Array(32))
    const r = await rpc({ type: 'prove', witnessBytes: wb, seed32: s }, [wb.buffer, s.buffer])
    return { result: r.result!, elapsedMs: r.elapsedMs ?? 0 }
  }
  const t0 = performance.now()
  return { result: (await getBrowserWasmProver()).proveJoinsplit(witness, seed32), elapsedMs: Math.round(performance.now() - t0) }
}
