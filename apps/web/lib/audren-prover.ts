// Canonical Audren Browser WASM BN254 Groth16 Prover + AES-GCM IndexedDB CompactWalletStore persistence.
import {
  AudrenWasmProver,
  dummyInputWitness,
  dummyOutputWitness,
  encodeJoinsplitWitness,
  type JoinSplitInputWitness,
  type JoinSplitOutputWitness,
  type JoinSplitProofResult,
  type JoinSplitWitness,
} from '@audren/sdk/prover'

export {
  AudrenWasmProver,
  dummyInputWitness,
  dummyOutputWitness,
  encodeJoinsplitWitness,
  type JoinSplitInputWitness,
  type JoinSplitOutputWitness,
  type JoinSplitProofResult,
  type JoinSplitWitness,
}
export * from './vault-storage'

let cachedProverPromise: Promise<AudrenWasmProver> | null = null

/**
 * Lazily load and cache the warm `/wasm/audren_circuits.wasm` BN254 Groth16 prover in the browser.
 * Keeping one warm instance avoids re-initializing the 3.75 MB proving key across subsequent spends.
 */
export function getBrowserWasmProver(wasmUrl = '/wasm/audren_circuits.wasm'): Promise<AudrenWasmProver> {
  if (!cachedProverPromise) {
    cachedProverPromise = AudrenWasmProver.init({ wasmUrl, useDevPk: true }).catch((err) => {
      cachedProverPromise = null
      throw err
    })
  }
  return cachedProverPromise
}

/**
 * Prove a `JoinSplit` witness asynchronously in the browser without blocking the initial paint.
 */
export async function proveJoinsplitInBrowser(
  witness: JoinSplitWitness,
  seed32?: Uint8Array,
): Promise<{ result: JoinSplitProofResult; elapsedMs: number }> {
  const prover = await getBrowserWasmProver()
  await new Promise((resolve) => setTimeout(resolve, 16))
  const t0 = performance.now()
  const result = prover.proveJoinsplit(witness, seed32)
  const elapsedMs = Math.round(performance.now() - t0)
  return { result, elapsedMs }
}
