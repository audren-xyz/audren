import { AudrenWasmProver, encodeJoinsplitWitness, type JoinSplitProofResult, type JoinSplitWitness } from '@audren/sdk/prover'
import { callProverWorker, PROVER_PROVE_TIMEOUT_MS, PROVER_WARM_TIMEOUT_MS } from './prover-worker-client'

export * from '@audren/sdk/prover'
export * from './vault-storage'

const WASM_URL = '/wasm/audren_circuits.wasm?v=1.3.0'
const PK_URL = '/wasm/audren_joinsplit.pk?v=2b22603e'

let cached: Promise<AudrenWasmProver> | null = null

export function getBrowserWasmProver(wasmUrl = WASM_URL, pkUrl = PK_URL): Promise<AudrenWasmProver> {
  return (cached ??= AudrenWasmProver.init({ wasmUrl, pkUrl }).catch((e) => {
    cached = null
    throw e
  }))
}

export async function warmBrowserWasmProver(wasmUrl = WASM_URL, pkUrl = PK_URL): Promise<void> {
  if (typeof Worker !== 'undefined') {
    try {
      await callProverWorker({ type: 'warm', wasmUrl, pkUrl }, [], PROVER_WARM_TIMEOUT_MS)
      return
    } catch {
      // Fall back cleanly to main-thread AudrenWasmProver if worker fails or times out
    }
  }
  await getBrowserWasmProver(wasmUrl, pkUrl)
}

export async function proveJoinsplitInBrowser(
  witness: JoinSplitWitness,
  seed32?: Uint8Array,
): Promise<{ result: JoinSplitProofResult; elapsedMs: number }> {
  if (typeof Worker !== 'undefined') {
    let wb: Uint8Array | null = null
    let s: Uint8Array | null = null
    try {
      wb = encodeJoinsplitWitness(witness)
      s = seed32 ? new Uint8Array(seed32) : crypto.getRandomValues(new Uint8Array(32))
      const r = await callProverWorker({ type: 'prove', witnessBytes: wb, seed32: s }, [wb.buffer, s.buffer], PROVER_PROVE_TIMEOUT_MS)
      return { result: r.result!, elapsedMs: r.elapsedMs ?? 0 }
    } catch (err) {
      if (err instanceof RangeError || /rc=-6|code -6/i.test(String(err))) throw err
      // Fall back cleanly to main-thread AudrenWasmProver if worker fails or times out
    } finally {
      if (wb && wb.byteLength > 0) wb.fill(0)
      if (s && s.byteLength > 0) s.fill(0)
    }
  }
  const t0 = performance.now()
  const prover = await getBrowserWasmProver()
  try {
    return { result: prover.proveJoinsplit(witness, seed32), elapsedMs: Math.round(performance.now() - t0) }
  } catch (err) {
    if (err instanceof WebAssembly.RuntimeError) cached = null
    throw err
  }
}
