/**
 * `@audren/sdk/prover` — Exact BN254 Groth16 WASM prover backed by `crates/audren-circuits`
 * (`JoinSplit4AryCircuit`, `DEPTH = 20`, `17,861` R1CS, `2^15` FFT domain, `192 B` proof).
 *
 * Works identically in Node.js and Browser Web Workers with zero `wasm-bindgen` glue
 * using the fixed `4,611 B` binary witness -> `384 B` proof+public-outputs ABI.
 */

import {
  CANONICAL_PK_SHA256,
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

/**
 * Encode `JoinSplitWitness` into the exact `4,611 B` binary witness ABI consumed by
 * `audren_circuits.wasm` (`encode_joinsplit_witness_bytes` in `crates/audren-circuits`).
 */
export function encodeJoinsplitWitness(w: JoinSplitWitness): Uint8Array {
  const buf = new Uint8Array(WITNESS_TOTAL_BYTES);
  const dv = new DataView(buf.buffer);
  let off = 0;

  const pushBytes = (b: Uint8Array) => {
    buf.set(b, off);
    off += b.byteLength;
  };
  const pushFr = (v: bigint) => pushBytes(frToBeBytes(v));
  const pushU64 = (v: bigint) => {
    dv.setBigUint64(off, v, true);
    off += 8;
  };
  const pushU8 = (v: number) => {
    buf[off++] = v & 0xff;
  };

  pushFr(w.superRoot);
  pushFr(w.txAssetId);
  pushFr(w.publicAssetId);
  pushU64(w.publicAmountOut);
  pushU64(w.relayerFeeAmount);
  pushFr(w.ctxHash);
  pushU8(w.omitNf1 ? 1 : 0);

  for (const inp of w.inputs) {
    pushFr(inp.spendSk);
    pushFr(inp.tweak);
    pushFr(inp.assetId);
    pushU64(inp.amount);
    pushFr(inp.blinding);
    pushU8(inp.isDummy ? 1 : 0);
    if (inp.merklePath.positions.length !== TOTAL_DEPTH_4ARY) {
      throw new RangeError(`Expected ${TOTAL_DEPTH_4ARY} Merkle positions`);
    }
    for (let h = 0; h < TOTAL_DEPTH_4ARY; h++) {
      pushU8(inp.merklePath.positions[h]!);
    }
    for (let h = 0; h < TOTAL_DEPTH_4ARY; h++) {
      const sib = inp.merklePath.siblings[h]!;
      for (let k = 0; k < 3; k++) {
        pushFr(sib[k]!);
      }
    }
  }

  for (const out of w.outputs) {
    pushFr(out.stealthOwner);
    pushFr(out.assetId);
    pushU64(out.amount);
    pushFr(out.blinding);
  }

  if (off !== WITNESS_TOTAL_BYTES) {
    throw new Error(`Witness encoding length mismatch: ${off} !== ${WITNESS_TOTAL_BYTES}`);
  }
  return buf;
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
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    out += bytes[i]!.toString(16).padStart(2, '0');
  }
  return out;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', copy.buffer);
  return bytesToHex(new Uint8Array(digest));
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
  private readonly exports: AudrenWasmExports;
  private pkReady = false;

  private constructor(exports: AudrenWasmExports) {
    this.exports = exports;
  }

  static async init(options: AudrenWasmProverInitOptions = {}): Promise<AudrenWasmProver> {
    const wasmPromise: Promise<Uint8Array> = options.wasmBytes
      ? Promise.resolve(
          options.wasmBytes instanceof Uint8Array
            ? options.wasmBytes
            : new Uint8Array(options.wasmBytes),
        )
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
    } else if (options.pkCompressed) {
      pkPromise = Promise.resolve(
        options.pkCompressed instanceof Uint8Array
          ? options.pkCompressed
          : new Uint8Array(options.pkCompressed),
      );
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

    const wasmBuf = new Uint8Array(bytes.byteLength);
    wasmBuf.set(bytes);
    const { instance } = await WebAssembly.instantiate(wasmBuf, {});
    const prover = new AudrenWasmProver(instance.exports as unknown as AudrenWasmExports);

    if (pkBytes) {
      if (options.verifyPkHash !== false) {
        const digest = await sha256Hex(pkBytes);
        if (digest !== CANONICAL_PK_SHA256) {
          throw new Error(
            `Audren proving key SHA-256 mismatch: got ${digest}, expected ${CANONICAL_PK_SHA256}`,
          );
        }
      }
      prover.loadProvingKeyCompressed(pkBytes);
    }
    return prover;
  }

  /** Load a compressed `ProvingKey<Bn254>` (`audren_joinsplit.pk`, curve-validated inside WASM). */
  loadProvingKeyCompressed(pkCompressed: Uint8Array): void {
    const ptr = this.exports.wasm_alloc(pkCompressed.byteLength);
    try {
      new Uint8Array(this.exports.memory.buffer, ptr, pkCompressed.byteLength).set(pkCompressed);
      const rc = this.exports.wasm_load_pk_compressed(ptr, pkCompressed.byteLength);
      if (rc !== 0) {
        throw new Error(`wasm_load_pk_compressed failed with code ${rc}`);
      }
      this.pkReady = true;
    } finally {
      this.exports.wasm_dealloc(ptr, pkCompressed.byteLength);
    }
  }

  /** Compute canonical Circom / `sol_poseidon` BN254 hash directly inside WASM (1..=12 inputs). */
  poseidonHashWasm(inputsBe32: readonly Uint8Array[]): Uint8Array {
    const arity = inputsBe32.length;
    if (arity < 1 || arity > 12) {
      throw new RangeError(`Expected 1..=12 inputs, got ${arity}`);
    }
    const inLen = arity * 32;
    const inPtr = this.exports.wasm_alloc(inLen);
    const outPtr = this.exports.wasm_alloc(32);
    try {
      const memIn = new Uint8Array(this.exports.memory.buffer, inPtr, inLen);
      for (let i = 0; i < arity; i++) memIn.set(inputsBe32[i]!, i * 32);
      const rc = this.exports.wasm_poseidon_hash(arity, inPtr, outPtr);
      if (rc !== 0) throw new Error(`wasm_poseidon_hash failed with code ${rc}`);
      return new Uint8Array(this.exports.memory.buffer, outPtr, 32).slice();
    } finally {
      this.exports.wasm_dealloc(inPtr, inLen);
      this.exports.wasm_dealloc(outPtr, 32);
    }
  }

  /**
   * Generate a canonical `192 B` Solana-compressed BN254 Groth16 proof + public outputs.
   * Uses cryptographic randomness from `crypto.getRandomValues` unless an explicit `seed32` is passed.
   */
  proveJoinsplit(witness: JoinSplitWitness, seed32?: Uint8Array): JoinSplitProofResult {
    if (!this.pkReady) {
      throw new Error('Proving key not initialized — pass pkUrl/pkCompressed or call loadProvingKeyCompressed()');
    }
    const witnessBytes = encodeJoinsplitWitness(witness);
    const seed =
      seed32 ??
      (() => {
        const s = new Uint8Array(32);
        globalThis.crypto.getRandomValues(s);
        return s;
      })();
    if (seed.byteLength !== 32) {
      throw new RangeError(`seed32 must be 32 bytes, got ${seed.byteLength}`);
    }

    const wPtr = this.exports.wasm_alloc(WITNESS_TOTAL_BYTES);
    const sPtr = this.exports.wasm_alloc(32);
    const oPtr = this.exports.wasm_alloc(PROVE_OUTPUT_BYTES);
    try {
      new Uint8Array(this.exports.memory.buffer, wPtr, WITNESS_TOTAL_BYTES).set(witnessBytes);
      new Uint8Array(this.exports.memory.buffer, sPtr, 32).set(seed);
      const rc = this.exports.wasm_prove_joinsplit(wPtr, WITNESS_TOTAL_BYTES, sPtr, oPtr);
      if (rc !== 0) {
        throw new Error(`wasm_prove_joinsplit failed with code ${rc}`);
      }
      const raw = new Uint8Array(this.exports.memory.buffer, oPtr, PROVE_OUTPUT_BYTES).slice();
      return {
        proof192: raw.slice(0, 192),
        nf0: raw.slice(192, 224),
        nf1: raw.slice(224, 256),
        cm0: raw.slice(256, 288),
        cm1: raw.slice(288, 320),
        cm2: raw.slice(320, 352),
        publicInputHash: raw.slice(352, 384),
      };
    } finally {
      this.exports.wasm_dealloc(wPtr, WITNESS_TOTAL_BYTES);
      this.exports.wasm_dealloc(sPtr, 32);
      this.exports.wasm_dealloc(oPtr, PROVE_OUTPUT_BYTES);
    }
  }
}
