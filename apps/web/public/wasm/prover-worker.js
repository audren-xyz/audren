/**
 * Dedicated zero-dependency Web Worker for Audren BN254 Groth16 proving
 * (`audren_circuits.wasm` + verified ceremony proving key `audren_joinsplit.pk`).
 *
 * Keeps the deserialized proving key warm in WASM RAM across proofs so the
 * browser UI thread stays completely responsive during 17,861-R1CS proving.
 */

const CANONICAL_PK_SHA256 =
  '2b22603e466c79b6710e01898dc8b458b09a3ee905b25db996f0c59e76187ee4'
const CANONICAL_WASM_SHA256 =
  '7e3aa59205009e07cfe48981d428c4650087ed7421b894e43de8f396b91f2dc3'
const WITNESS_TOTAL_BYTES = 4611
const PROVE_OUTPUT_BYTES = 384
const DEFAULT_WASM_URL = '/wasm/audren_circuits.wasm?v=1.3.0'
const DEFAULT_PK_URL = '/wasm/audren_joinsplit.pk?v=2b22603e'

let readyPromise = null

function bytesToHex(bytes) {
  let out = ''
  for (let i = 0; i < bytes.byteLength; i++) {
    out += bytes[i].toString(16).padStart(2, '0')
  }
  return out
}

async function sha256Hex(bytes) {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  const digest = await globalThis.crypto.subtle.digest('SHA-256', copy.buffer)
  return bytesToHex(new Uint8Array(digest))
}

async function initWasmProver(wasmUrl, pkUrl) {
  const [wasmRes, pkRes] = await Promise.all([fetch(wasmUrl), fetch(pkUrl)])
  if (!wasmRes.ok) {
    throw new Error(`Failed to fetch Audren WASM prover: HTTP ${wasmRes.status}`)
  }
  if (!pkRes.ok) {
    throw new Error(`Failed to fetch Audren ceremony PK: HTTP ${pkRes.status}`)
  }
  const [wasmBuf, pkBuf] = await Promise.all([wasmRes.arrayBuffer(), pkRes.arrayBuffer()])
  const wasmBytes = new Uint8Array(wasmBuf)
  const pkBytes = new Uint8Array(pkBuf)
  const [wasmDigest, pkDigest] = await Promise.all([sha256Hex(wasmBytes), sha256Hex(pkBytes)])
  if (wasmDigest !== CANONICAL_WASM_SHA256) {
    throw new Error(
      `Audren WASM prover SHA-256 mismatch: got ${wasmDigest}, expected ${CANONICAL_WASM_SHA256}`,
    )
  }
  if (pkDigest !== CANONICAL_PK_SHA256) {
    throw new Error(
      `Audren proving key SHA-256 mismatch: got ${pkDigest}, expected ${CANONICAL_PK_SHA256}`,
    )
  }

  const { instance } = await WebAssembly.instantiate(wasmBuf, {})
  const exports = instance.exports
  let pkPtr = 0
  let deallocFailed = false
  try {
    pkPtr = exports.wasm_alloc(pkBytes.byteLength)
    new Uint8Array(exports.memory.buffer, pkPtr, pkBytes.byteLength).set(pkBytes)
    const rc = exports.wasm_load_pk_compressed(pkPtr, pkBytes.byteLength)
    if (rc !== 0) {
      throw new Error(`wasm_load_pk_compressed failed with code ${rc}`)
    }
  } finally {
    if (pkPtr) {
      try {
        exports.wasm_dealloc(pkPtr, pkBytes.byteLength)
      } catch {
        deallocFailed = true
      }
    }
  }
  if (deallocFailed) {
    throw new Error('WASM proving key buffer cleanup trapped; discarding instance')
  }
  return { exports, poisoned: false }
}

function invalidateReady(targetPromise, handle) {
  if (handle) handle.poisoned = true
  if (targetPromise && readyPromise === targetPromise) {
    readyPromise = null
  }
}

function ensureReady(wasmUrl, pkUrl) {
  if (!readyPromise) {
    const current = initWasmProver(
      wasmUrl || DEFAULT_WASM_URL,
      pkUrl || DEFAULT_PK_URL,
    ).catch((err) => {
      if (readyPromise === current) readyPromise = null
      throw err
    })
    readyPromise = current
  }
  return readyPromise
}

function scrubBytes(val) {
  if (!val) return
  try {
    if (val instanceof Uint8Array) {
      if (val.byteLength > 0) val.fill(0)
    } else if (val instanceof ArrayBuffer) {
      if (val.byteLength > 0) new Uint8Array(val).fill(0)
    } else if (ArrayBuffer.isView(val) && val.byteLength > 0) {
      new Uint8Array(val.buffer, val.byteOffset, val.byteLength).fill(0)
    }
  } catch {
    // Ignore detached or non-writable buffer views
  }
}

globalThis.addEventListener('message', async (event) => {
  const data = event.data || {}
  const id = data.id
  try {
    if (data.type === 'warm') {
      const p = ensureReady(data.wasmUrl, data.pkUrl)
      const h = await p
      if (h.poisoned) {
        invalidateReady(p, h)
        await ensureReady(data.wasmUrl, data.pkUrl)
      }
      globalThis.postMessage({ id, ok: true })
      return
    }

    if (data.type === 'prove') {
      let handlePromise = null
      let handle = null
      let exports = null
      let witnessBytes = null
      let seed = null
      let wPtr = 0
      let sPtr = 0
      let oPtr = 0
      let raw
      let elapsedMs = 0
      try {
        handlePromise = ensureReady(data.wasmUrl, data.pkUrl)
        handle = await handlePromise
        if (handle.poisoned) {
          invalidateReady(handlePromise, handle)
          handlePromise = ensureReady(data.wasmUrl, data.pkUrl)
          handle = await handlePromise
          if (handle.poisoned) {
            throw new Error('WASM prover instance is poisoned')
          }
        }
        exports = handle.exports
        witnessBytes =
          data.witnessBytes instanceof Uint8Array
            ? data.witnessBytes
            : new Uint8Array(data.witnessBytes)
        if (witnessBytes.byteLength !== WITNESS_TOTAL_BYTES) {
          throw new RangeError(
            `Expected ${WITNESS_TOTAL_BYTES}-byte witness, got ${witnessBytes.byteLength}`,
          )
        }
        if (data.seed32 instanceof Uint8Array && data.seed32.byteLength === 32) {
          seed = data.seed32
        } else if (data.seed32 && data.seed32.byteLength === 32) {
          seed = new Uint8Array(data.seed32)
        } else {
          seed = globalThis.crypto.getRandomValues(new Uint8Array(32))
        }

        const t0 = globalThis.performance.now()
        wPtr = exports.wasm_alloc(WITNESS_TOTAL_BYTES)
        sPtr = exports.wasm_alloc(32)
        oPtr = exports.wasm_alloc(PROVE_OUTPUT_BYTES)
        if (!wPtr || !sPtr || !oPtr) {
          invalidateReady(handlePromise, handle)
          throw new Error('wasm_alloc returned null pointer for proveJoinsplit')
        }
        new Uint8Array(exports.memory.buffer, wPtr, WITNESS_TOTAL_BYTES).set(witnessBytes)
        new Uint8Array(exports.memory.buffer, sPtr, 32).set(seed)
        const rc = exports.wasm_prove_joinsplit(wPtr, WITNESS_TOTAL_BYTES, sPtr, oPtr)
        if (rc === -6) {
          throw new Error('Groth16 witness failed off-chain R1CS verification (rc=-6)')
        }
        if (rc !== 0) {
          throw new Error(`wasm_prove_joinsplit failed with code ${rc}`)
        }
        raw = new Uint8Array(exports.memory.buffer, oPtr, PROVE_OUTPUT_BYTES).slice()
        elapsedMs = Math.round(globalThis.performance.now() - t0)
      } catch (proveErr) {
        if (proveErr instanceof WebAssembly.RuntimeError) {
          invalidateReady(handlePromise, handle)
        }
        throw proveErr
      } finally {
        if (exports && oPtr) {
          try {
            new Uint8Array(exports.memory.buffer, oPtr, PROVE_OUTPUT_BYTES).fill(0)
            exports.wasm_dealloc(oPtr, PROVE_OUTPUT_BYTES)
          } catch {
            invalidateReady(handlePromise, handle)
          }
        }
        if (exports && sPtr) {
          try {
            new Uint8Array(exports.memory.buffer, sPtr, 32).fill(0)
            exports.wasm_dealloc(sPtr, 32)
          } catch {
            invalidateReady(handlePromise, handle)
          }
        }
        if (exports && wPtr) {
          try {
            new Uint8Array(exports.memory.buffer, wPtr, WITNESS_TOTAL_BYTES).fill(0)
            exports.wasm_dealloc(wPtr, WITNESS_TOTAL_BYTES)
          } catch {
            invalidateReady(handlePromise, handle)
          }
        }
        scrubBytes(seed)
        scrubBytes(data.seed32)
        scrubBytes(witnessBytes)
        scrubBytes(data.witnessBytes)
      }
      const result = {
        proof192: raw.slice(0, 192),
        nf0: raw.slice(192, 224),
        nf1: raw.slice(224, 256),
        cm0: raw.slice(256, 288),
        cm1: raw.slice(288, 320),
        cm2: raw.slice(320, 352),
        publicInputHash: raw.slice(352, 384),
      }
      globalThis.postMessage({ id, ok: true, result, elapsedMs }, [
        result.proof192.buffer,
        result.nf0.buffer,
        result.nf1.buffer,
        result.cm0.buffer,
        result.cm1.buffer,
        result.cm2.buffer,
        result.publicInputHash.buffer,
      ])
      return
    }

    throw new Error(`Unsupported prover worker message type: ${String(data.type)}`)
  } catch (err) {
    globalThis.postMessage({
      id,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    })
  }
})
