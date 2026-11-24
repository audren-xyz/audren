/**
 * `@audren/sdk/prover` — Exact BN254 Groth16 WASM prover backed by `crates/audren-circuits`
 * (`JoinSplit4AryCircuit`, `DEPTH = 20`, `17,861` R1CS, `2^15` FFT domain, `192 B` proof).
 *
 * Works identically in Node.js and Browser Web Workers with zero `wasm-bindgen` glue
 * using the fixed `4,611 B` binary witness -> `384 B` proof+public-outputs ABI.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import {
  BN254_FR_MODULUS,
  CANONICAL_PK_SHA256,
  CANONICAL_WASM_SHA256,
  PROVE_OUTPUT_BYTES,
  TOTAL_DEPTH_4ARY,
  WITNESS_TOTAL_BYTES,
} from './constants.ts';
import { frToBeBytes } from './poseidon.ts';
import { emptyMerklePath4Ary, type MerklePath4Ary } from './store.ts';

export interface JoinSplitInputWitness {
  spendSk: bigint;
  tweak: bigint;
  assetId: bigint;
  amount: bigint;
  blinding: bigint;
  isDummy: boolean;
  merklePath: MerklePath4Ary;
}

export interface JoinSplitOutputWitness {
  stealthOwner: bigint;
  assetId: bigint;
  amount: bigint;
  blinding: bigint;
}

export interface JoinSplitWitness {
  superRoot: bigint;
  txAssetId: bigint;
  publicAssetId: bigint;
  publicAmountOut: bigint;
  relayerFeeAmount: bigint;
  ctxHash: bigint;
  omitNf1: boolean;
  inputs: [JoinSplitInputWitness, JoinSplitInputWitness];
  outputs: [JoinSplitOutputWitness, JoinSplitOutputWitness, JoinSplitOutputWitness];
}

export interface JoinSplitProofResult {
  proof192: Uint8Array;
  nf0: Uint8Array;
  nf1: Uint8Array;
  cm0: Uint8Array;
  cm1: Uint8Array;
  cm2: Uint8Array;
  publicInputHash: Uint8Array;
}

export function dummyInputWitness(
  spendSk: bigint,
  assetId: bigint,
  blinding: bigint,
): JoinSplitInputWitness {
  return {
    spendSk,
    tweak: 0n,
    assetId,
    amount: 0n,
    blinding,
    isDummy: true,
    merklePath: emptyMerklePath4Ary(),
  };
}

export function dummyOutputWitness(assetId: bigint, blinding: bigint): JoinSplitOutputWitness {
  return {
    stealthOwner: 0n,
    assetId,
    amount: 0n,
    blinding,
  };
}

const U64_MAX = 0xffff_ffff_ffff_ffffn;

/**
 * Encode `JoinSplitWitness` into the exact `4,611 B` binary witness ABI consumed by
 * `audren_circuits.wasm` (`encode_joinsplit_witness_bytes` in `crates/audren-circuits`).
 */
export function encodeJoinsplitWitness(w: JoinSplitWitness): Uint8Array {
  if (!w || typeof w !== 'object') {
    throw new RangeError('JoinSplitWitness must be an object');
  }
  if (!Array.isArray(w.inputs) || w.inputs.length !== 2) {
    throw new RangeError(`Expected 2 inputs, got ${Array.isArray(w.inputs) ? w.inputs.length : String(w.inputs)}`);
  }
  if (!Array.isArray(w.outputs) || w.outputs.length !== 3) {
    throw new RangeError(`Expected 3 outputs, got ${Array.isArray(w.outputs) ? w.outputs.length : String(w.outputs)}`);
  }
  const buf = new Uint8Array(WITNESS_TOTAL_BYTES);
  const dv = new DataView(buf.buffer);
  let off = 0;

  try {
    const pushBytes = (b: Uint8Array) => {
      if (!(b instanceof Uint8Array)) {
        throw new RangeError(`Expected Uint8Array, got ${String(b)}`);
      }
      buf.set(b, off);
      off += b.byteLength;
    };
    const pushFr = (v: bigint, label: string) => {
      if (typeof v !== 'bigint' || v < 0n || v >= BN254_FR_MODULUS) {
        throw new RangeError(
          `${label} must be a canonical BN254 Fr bigint in 0..r-1, got ${String(v)}`,
        );
      }
      pushBytes(frToBeBytes(v));
    };
    const pushU64 = (v: bigint, label: string) => {
      if (typeof v !== 'bigint' || v < 0n || v > U64_MAX) {
        throw new RangeError(`${label} must be a u64 bigint in 0..=2^64-1, got ${String(v)}`);
      }
      dv.setBigUint64(off, v, true);
      off += 8;
    };
    const pushU8 = (v: number, label: string) => {
      if (!Number.isInteger(v) || v < 0 || v > 0xff) {
        throw new RangeError(`${label} must be a u8 integer in 0..=255, got ${v}`);
      }
      buf[off++] = v;
    };

    pushFr(w.superRoot, 'superRoot');
    pushFr(w.txAssetId, 'txAssetId');
    pushFr(w.publicAssetId, 'publicAssetId');
    pushU64(w.publicAmountOut, 'publicAmountOut');
    pushU64(w.relayerFeeAmount, 'relayerFeeAmount');
    pushFr(w.ctxHash, 'ctxHash');
    pushU8(w.omitNf1 ? 1 : 0, 'omitNf1');

    for (let i = 0; i < w.inputs.length; i++) {
      const inp = w.inputs[i];
      if (!inp || typeof inp !== 'object') {
        throw new RangeError(`inputs[${i}] must be an object`);
      }
      pushFr(inp.spendSk, `inputs[${i}].spendSk`);
      pushFr(inp.tweak, `inputs[${i}].tweak`);
      pushFr(inp.assetId, `inputs[${i}].assetId`);
      pushU64(inp.amount, `inputs[${i}].amount`);
      pushFr(inp.blinding, `inputs[${i}].blinding`);
      pushU8(inp.isDummy ? 1 : 0, `inputs[${i}].isDummy`);
      if (
        !inp.merklePath ||
        typeof inp.merklePath !== 'object' ||
        !Array.isArray(inp.merklePath.positions) ||
        !Array.isArray(inp.merklePath.siblings)
      ) {
        throw new RangeError(`inputs[${i}].merklePath must provide positions and siblings arrays`);
      }
      if (inp.merklePath.positions.length !== TOTAL_DEPTH_4ARY) {
        throw new RangeError(`Expected ${TOTAL_DEPTH_4ARY} Merkle positions`);
      }
      if (inp.merklePath.siblings.length !== TOTAL_DEPTH_4ARY) {
        throw new RangeError(`Expected ${TOTAL_DEPTH_4ARY} Merkle sibling levels`);
      }
      for (let h = 0; h < TOTAL_DEPTH_4ARY; h++) {
        const pos = inp.merklePath.positions[h]!;
        if (!Number.isInteger(pos) || pos < 0 || pos > 3) {
          throw new RangeError(`Invalid 4-ary Merkle position at depth ${h}: ${pos}`);
        }
        pushU8(pos, `inputs[${i}].merklePath.positions[${h}]`);
      }
      for (let h = 0; h < TOTAL_DEPTH_4ARY; h++) {
        const sib = inp.merklePath.siblings[h];
        if (!Array.isArray(sib) || sib.length !== 3) {
          throw new RangeError(`Expected 3 siblings at depth ${h}, got ${Array.isArray(sib) ? sib.length : String(sib)}`);
        }
        for (let k = 0; k < 3; k++) {
          pushFr(sib[k]!, `inputs[${i}].merklePath.siblings[${h}][${k}]`);
        }
      }
    }

    for (let i = 0; i < w.outputs.length; i++) {
      const out = w.outputs[i];
      if (!out || typeof out !== 'object') {
        throw new RangeError(`outputs[${i}] must be an object`);
      }
      pushFr(out.stealthOwner, `outputs[${i}].stealthOwner`);
      pushFr(out.assetId, `outputs[${i}].assetId`);
      pushU64(out.amount, `outputs[${i}].amount`);
      pushFr(out.blinding, `outputs[${i}].blinding`);
    }

    if (off !== WITNESS_TOTAL_BYTES) {
      throw new Error(`Witness encoding length mismatch: ${off} !== ${WITNESS_TOTAL_BYTES}`);
    }
    return buf;
  } catch (err) {
    buf.fill(0);
    throw err;
  }
}

interface AudrenWasmExports {
  memory: WebAssembly.Memory;
  wasm_alloc(len: number): number;
  wasm_dealloc(ptr: number, len: number): void;
  wasm_load_pk_compressed(ptr: number, len: number): number;
  wasm_prove_joinsplit(
    witnessPtr: number,
    witnessLen: number,
    seedPtr: number,
    outPtr: number,
  ): number;
  wasm_poseidon_hash(arity: number, inputsPtr: number, outPtr: number): number;
}

export interface AudrenWasmProverInitOptions {
  /** Pre-fetched `audren_circuits.wasm` binary (Browser/Worker or custom loader). */
  wasmBytes?: Uint8Array | ArrayBuffer;
  /** URL to fetch `audren_circuits.wasm` (Browser/Worker, e.g. `/wasm/audren_circuits.wasm`). */
  wasmUrl?: string;
  /** Pre-fetched compressed ceremony proving key (`audren_joinsplit.pk`, 3,927,280 B). */
  pkCompressed?: Uint8Array | ArrayBuffer;
  /** URL to fetch `audren_joinsplit.pk` (Browser/Worker, defaults to sibling `/wasm/audren_joinsplit.pk`). */
  pkUrl?: string;
  /** Skip loading the proving key during `init()` (caller will call `loadProvingKeyCompressed()`). */
  deferPk?: boolean;
  /** Verify loaded proving key SHA-256 against `CANONICAL_PK_SHA256` (default: true). */
  verifyPkHash?: boolean;
  /** Verify loaded WASM binary SHA-256 against `CANONICAL_WASM_SHA256` (default: true). */
  verifyWasmHash?: boolean;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    out += bytes[i]!.toString(16).padStart(2, '0');
  }
  return out;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  if (!(bytes instanceof Uint8Array)) {
    throw new RangeError(`Expected Uint8Array for SHA-256, got ${String(bytes)}`);
  }
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', copy.buffer);
  return bytesToHex(new Uint8Array(digest));
}

function toStrictUint8ArrayOrArrayBuffer(
  val: Uint8Array | ArrayBuffer,
  label: string,
): Uint8Array {
  if (val instanceof Uint8Array) return val;
  if (val instanceof ArrayBuffer) return new Uint8Array(val);
  throw new RangeError(`${label} must be a Uint8Array or ArrayBuffer, got ${String(val)}`);
}

async function resolveDefaultAssetBytes(relPath: string, hint: string): Promise<Uint8Array> {
  const proc = (globalThis as { process?: { versions?: { node?: string } } }).process;
  const isNode = typeof proc?.versions?.node === 'string';
  if (isNode) {
    const fsSpec = 'node:' + 'fs/promises';
    const urlSpec = 'node:' + 'url';
    const fsMod = (await import(/* webpackIgnore: true */ fsSpec)) as {
      readFile(p: string): Promise<Uint8Array>;
    };
    const urlMod = (await import(/* webpackIgnore: true */ urlSpec)) as {
      fileURLToPath(u: URL): string;
    };
    const assetFile = urlMod.fileURLToPath(new URL(relPath, import.meta.url));
    const buf = await fsMod.readFile(assetFile);
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  throw new Error(hint);
}

function defaultSiblingPkUrl(wasmUrl: string): string {
  const [base] = wasmUrl.split('?');
  const slash = base!.lastIndexOf('/');
  const dir = slash >= 0 ? base!.slice(0, slash + 1) : '';
  return `${dir}audren_joinsplit.pk?v=${CANONICAL_PK_SHA256.slice(0, 8)}`;
}

/**
 * Stateful handle to the loaded `audren_circuits.wasm` BN254 Groth16 prover instance.
 * Reuse one instance per Worker/process to keep the deserialized ceremony proving key warm in WASM RAM.
 */
export class AudrenWasmProver {
  private exports: AudrenWasmExports | null;
  private pkReady = false;
  private disposed = false;
  private poisoned = false;

  private constructor(exports: AudrenWasmExports) {
    this.exports = exports;
  }

  private assertUsable(): AudrenWasmExports {
    if (this.disposed || this.exports === null) {
      throw new Error('AudrenWasmProver has been disposed; call AudrenWasmProver.init() to create a new instance');
    }
    if (this.poisoned) {
      throw new Error('AudrenWasmProver WASM instance trapped (e.g. OOM) and is poisoned; create a fresh instance');
    }
    return this.exports;
  }

  /**
   * Release this prover handle, zeroize WASM linear memory, and drop the `WebAssembly.Instance`
   * reference so residual witness secrets and proving-key buffers can be garbage-collected.
   * Subsequent calls throw immediately instead of reusing freed or stale WASM state.
   */
  dispose(): void {
    const exp = this.exports;
    this.pkReady = false;
    this.disposed = true;
    this.exports = null;
    if (exp) {
      try {
        new Uint8Array(exp.memory.buffer).fill(0);
      } catch {
        // Ignore detached or non-writable WASM linear memory during teardown
      }
    }
  }

  static async init(options: AudrenWasmProverInitOptions = {}): Promise<AudrenWasmProver> {
    if (!options || typeof options !== 'object') {
      throw new RangeError('AudrenWasmProver.init options must be an object');
    }
    // Validate caller-supplied byte buffers synchronously BEFORE initiating any async fetch/file
    // I/O so invalid `pkCompressed` never abandons an in-flight `wasmPromise` (unhandled rejection).
    const prevalidatedWasm =
      options.wasmBytes !== undefined
        ? toStrictUint8ArrayOrArrayBuffer(options.wasmBytes, 'wasmBytes')
        : undefined;
    const prevalidatedPk =
      !options.deferPk && options.pkCompressed !== undefined
        ? toStrictUint8ArrayOrArrayBuffer(options.pkCompressed, 'pkCompressed')
        : undefined;

    const wasmPromise: Promise<Uint8Array> =
      prevalidatedWasm !== undefined
        ? Promise.resolve(prevalidatedWasm)
        : options.wasmUrl
          ? fetch(options.wasmUrl).then(async (res) => {
              if (!res.ok) throw new Error(`Failed to fetch Audren WASM prover: HTTP ${res.status}`);
              return new Uint8Array(await res.arrayBuffer());
            })
          : resolveDefaultAssetBytes(
              '../wasm/audren_circuits.wasm',
              'In browser environments pass { wasmUrl: "/wasm/audren_circuits.wasm", pkUrl: "/wasm/audren_joinsplit.pk" } to AudrenWasmProver.init()',
            );

    let pkPromise: Promise<Uint8Array | null>;
    if (options.deferPk) {
      pkPromise = Promise.resolve(null);
    } else if (prevalidatedPk !== undefined) {
      pkPromise = Promise.resolve(prevalidatedPk);
    } else if (options.pkUrl) {
      pkPromise = fetch(options.pkUrl).then(async (res) => {
        if (!res.ok) throw new Error(`Failed to fetch Audren ceremony PK: HTTP ${res.status}`);
        return new Uint8Array(await res.arrayBuffer());
      });
    } else if (options.wasmUrl) {
      const siblingPkUrl = defaultSiblingPkUrl(options.wasmUrl);
      pkPromise = fetch(siblingPkUrl).then(async (res) => {
        if (!res.ok) throw new Error(`Failed to fetch Audren ceremony PK (${siblingPkUrl}): HTTP ${res.status}`);
        return new Uint8Array(await res.arrayBuffer());
      });
    } else {
      pkPromise = resolveDefaultAssetBytes(
        '../wasm/audren_joinsplit.pk',
        'In browser environments pass { pkUrl: "/wasm/audren_joinsplit.pk" } or { pkCompressed } to AudrenWasmProver.init()',
      );
    }

    const [bytes, pkBytes] = await Promise.all([wasmPromise, pkPromise]);

    if (options.verifyWasmHash !== false) {
      const wasmDigest = await sha256Hex(bytes);
      if (wasmDigest !== CANONICAL_WASM_SHA256) {
        throw new Error(
          `Audren WASM prover SHA-256 mismatch: got ${wasmDigest}, expected ${CANONICAL_WASM_SHA256}`,
        );
      }
    }

    const wasmBuf = new Uint8Array(bytes.byteLength);
    wasmBuf.set(bytes);
    const { instance } = await WebAssembly.instantiate(wasmBuf, {});
    const prover = new AudrenWasmProver(instance.exports as unknown as AudrenWasmExports);

    if (pkBytes) {
      prover.loadProvingKeyCompressed(pkBytes, {
        allowCustomPk: options.verifyPkHash === false,
      });
    }
    return prover;
  }

  /**
   * Load a compressed `ProvingKey<Bn254>` (`audren_joinsplit.pk`, curve-validated inside WASM).
   * Enforces `CANONICAL_PK_SHA256` by default (even when `init({ deferPk: true })` was used);
   * pass `{ allowCustomPk: true }` to opt out explicitly for custom circuits/testing.
   */
  loadProvingKeyCompressed(
    pkCompressed: Uint8Array,
    options?: { allowCustomPk?: boolean },
  ): void {
    const exp = this.assertUsable();
    if (!(pkCompressed instanceof Uint8Array) || pkCompressed.byteLength === 0) {
      throw new RangeError(
        `pkCompressed must be a non-empty Uint8Array, got ${pkCompressed instanceof Uint8Array ? pkCompressed.byteLength : String(pkCompressed)}`,
      );
    }
    if (!options?.allowCustomPk) {
      const digest = bytesToHex(sha256(pkCompressed));
      if (digest !== CANONICAL_PK_SHA256) {
        throw new Error(
          `Audren proving key SHA-256 mismatch: got ${digest}, expected ${CANONICAL_PK_SHA256}`,
        );
      }
    }
    let ptr = 0;
    try {
      ptr = exp.wasm_alloc(pkCompressed.byteLength);
      if (!ptr) {
        this.poisoned = true;
        throw new Error('wasm_alloc returned null pointer for proving key');
      }
      new Uint8Array(exp.memory.buffer, ptr, pkCompressed.byteLength).set(pkCompressed);
      const rc = exp.wasm_load_pk_compressed(ptr, pkCompressed.byteLength);
      if (rc !== 0) {
        throw new Error(`wasm_load_pk_compressed failed with code ${rc}`);
      }
      this.pkReady = true;
    } catch (err) {
      if (err instanceof WebAssembly.RuntimeError) {
        this.poisoned = true;
        this.pkReady = false;
      }
      throw err;
    } finally {
      if (ptr) {
        try {
          new Uint8Array(exp.memory.buffer, ptr, pkCompressed.byteLength).fill(0);
          exp.wasm_dealloc(ptr, pkCompressed.byteLength);
        } catch {
          this.poisoned = true;
          this.pkReady = false;
        }
      }
    }
  }

  /** Compute canonical Circom / `sol_poseidon` BN254 hash directly inside WASM (1..=12 inputs). */
  poseidonHashWasm(inputsBe32: readonly Uint8Array[]): Uint8Array {
    const exp = this.assertUsable();
    if (!Array.isArray(inputsBe32)) {
      throw new RangeError('inputsBe32 must be an array of 32-byte Uint8Arrays');
    }
    const arity = inputsBe32.length;
    if (arity < 1 || arity > 12) {
      throw new RangeError(`Expected 1..=12 inputs, got ${arity}`);
    }
    for (let i = 0; i < arity; i++) {
      const inp = inputsBe32[i];
      if (!(inp instanceof Uint8Array) || inp.byteLength !== 32) {
        throw new RangeError(
          `inputsBe32[${i}] must be a 32-byte Uint8Array, got ${inp instanceof Uint8Array ? inp.byteLength : String(inp)}`,
        );
      }
    }
    const inLen = arity * 32;
    let inPtr = 0;
    let outPtr = 0;
    try {
      inPtr = exp.wasm_alloc(inLen);
      outPtr = exp.wasm_alloc(32);
      if (!inPtr || !outPtr) {
        this.poisoned = true;
        throw new Error('wasm_alloc returned null pointer for poseidonHashWasm');
      }
      const memIn = new Uint8Array(exp.memory.buffer, inPtr, inLen);
      for (let i = 0; i < arity; i++) memIn.set(inputsBe32[i]!, i * 32);
      const rc = exp.wasm_poseidon_hash(arity, inPtr, outPtr);
      if (rc !== 0) throw new Error(`wasm_poseidon_hash failed with code ${rc}`);
      return new Uint8Array(exp.memory.buffer, outPtr, 32).slice();
    } catch (err) {
      if (err instanceof WebAssembly.RuntimeError) {
        this.poisoned = true;
        this.pkReady = false;
      }
      throw err;
    } finally {
      if (outPtr) {
        try {
          new Uint8Array(exp.memory.buffer, outPtr, 32).fill(0);
          exp.wasm_dealloc(outPtr, 32);
        } catch {
          this.poisoned = true;
          this.pkReady = false;
        }
      }
      if (inPtr) {
        try {
          new Uint8Array(exp.memory.buffer, inPtr, inLen).fill(0);
          exp.wasm_dealloc(inPtr, inLen);
        } catch {
          this.poisoned = true;
          this.pkReady = false;
        }
      }
    }
  }

  /**
   * Generate a canonical `192 B` Solana-compressed BN254 Groth16 proof + public outputs.
   * Uses cryptographic randomness from `crypto.getRandomValues` unless an explicit `seed32` is passed.
   */
  proveJoinsplit(witness: JoinSplitWitness, seed32?: Uint8Array): JoinSplitProofResult {
    const exp = this.assertUsable();
    if (!this.pkReady) {
      throw new Error('Proving key not initialized — pass pkUrl/pkCompressed or call loadProvingKeyCompressed()');
    }
    if (seed32 !== undefined && (!(seed32 instanceof Uint8Array) || seed32.byteLength !== 32)) {
      throw new RangeError(
        `seed32 must be a 32-byte Uint8Array, got ${seed32 instanceof Uint8Array ? seed32.byteLength : String(seed32)}`,
      );
    }
    const witnessBytes = encodeJoinsplitWitness(witness);
    const generatedSeed = seed32 === undefined;
    let seed: Uint8Array | null = seed32 ?? null;

    let wPtr = 0;
    let sPtr = 0;
    let oPtr = 0;
    try {
      if (seed === null) {
        const s = new Uint8Array(32);
        globalThis.crypto.getRandomValues(s);
        seed = s;
      }
      wPtr = exp.wasm_alloc(WITNESS_TOTAL_BYTES);
      sPtr = exp.wasm_alloc(32);
      oPtr = exp.wasm_alloc(PROVE_OUTPUT_BYTES);
      if (!wPtr || !sPtr || !oPtr) {
        this.poisoned = true;
        throw new Error('wasm_alloc returned null pointer for proveJoinsplit');
      }
      new Uint8Array(exp.memory.buffer, wPtr, WITNESS_TOTAL_BYTES).set(witnessBytes);
      new Uint8Array(exp.memory.buffer, sPtr, 32).set(seed);
      const rc = exp.wasm_prove_joinsplit(wPtr, WITNESS_TOTAL_BYTES, sPtr, oPtr);
      if (rc === -6) {
        throw new Error('Groth16 witness failed off-chain R1CS verification (rc=-6)');
      }
      if (rc !== 0) {
        throw new Error(`wasm_prove_joinsplit failed with code ${rc}`);
      }
      const raw = new Uint8Array(exp.memory.buffer, oPtr, PROVE_OUTPUT_BYTES).slice();
      return {
        proof192: raw.slice(0, 192),
        nf0: raw.slice(192, 224),
        nf1: raw.slice(224, 256),
        cm0: raw.slice(256, 288),
        cm1: raw.slice(288, 320),
        cm2: raw.slice(320, 352),
        publicInputHash: raw.slice(352, 384),
      };
    } catch (err) {
      if (err instanceof WebAssembly.RuntimeError) {
        this.poisoned = true;
        this.pkReady = false;
      }
      throw err;
    } finally {
      witnessBytes.fill(0);
      if (generatedSeed && seed) seed.fill(0);
      if (oPtr) {
        try {
          new Uint8Array(exp.memory.buffer, oPtr, PROVE_OUTPUT_BYTES).fill(0);
          exp.wasm_dealloc(oPtr, PROVE_OUTPUT_BYTES);
        } catch {
          this.poisoned = true;
          this.pkReady = false;
        }
      }
      if (sPtr) {
        try {
          new Uint8Array(exp.memory.buffer, sPtr, 32).fill(0);
          exp.wasm_dealloc(sPtr, 32);
        } catch {
          this.poisoned = true;
          this.pkReady = false;
        }
      }
      if (wPtr) {
        try {
          new Uint8Array(exp.memory.buffer, wPtr, WITNESS_TOTAL_BYTES).fill(0);
          exp.wasm_dealloc(wPtr, WITNESS_TOTAL_BYTES);
        } catch {
          this.poisoned = true;
          this.pkReady = false;
        }
      }
    }
  }
}
