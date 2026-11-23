/**
 * Pure TypeScript Circom / Solana `sol_poseidon` BN254 x^5 Poseidon hash and
 * canonical Audren field/note primitives (zero WASM required — runs natively
 * in Node.js, Browsers, and Cloudflare Workers).
 */

import { sha256 } from '@noble/hashes/sha2.js';
import {
  ASSET_ID_DOMAIN,
  BN254_FR_MODULUS,
  DOMAIN_DUMMY_NF,
  DOMAIN_NK,
  DOMAIN_NOTE,
  DOMAIN_NULLIFIER,
  DOMAIN_PK,
  DOMAIN_PUB_HASH_A,
  DOMAIN_PUB_HASH_B,
  DOMAIN_PUB_HASH_FINAL,
  DOMAIN_STEALTH,
  NUM_LANES,
  ZERO_HASHES_4ARY,
} from './constants.ts';
import { POSEIDON_PARAMS } from './poseidon-constants.ts';

const utf8Encoder = new TextEncoder();
const ASSET_ID_DOMAIN_BYTES = utf8Encoder.encode(ASSET_ID_DOMAIN);

export function modFr(x: bigint): bigint {
  const r = x % BN254_FR_MODULUS;
  return r >= 0n ? r : r + BN254_FR_MODULUS;
}

export function isCanonicalFr(bytes: Uint8Array): boolean {
  if (bytes.byteLength !== 32) return false;
  return bytesToBigIntBe(bytes) < BN254_FR_MODULUS;
}

export function bytesToBigIntBe(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (let i = 0; i < bytes.byteLength; i++) {
    acc = (acc << 8n) | BigInt(bytes[i]!);
  }
  return acc;
}

export function frToBeBytes(v: bigint): Uint8Array {
  let x = modFr(v);
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

export function frFromBeBytesStrict(bytes: Uint8Array): bigint {
  if (bytes.byteLength !== 32) {
    throw new RangeError(`Expected 32-byte BN254 Fr, got ${bytes.byteLength}`);
  }
  const v = bytesToBigIntBe(bytes);
  if (v >= BN254_FR_MODULUS) {
    throw new RangeError('Non-canonical BN254 scalar field element (>= r)');
  }
  return v;
}

export function maskToFrBe(bytes: Uint8Array): Uint8Array {
  if (bytes.byteLength !== 32) {
    throw new RangeError(`Expected 32 bytes, got ${bytes.byteLength}`);
  }
  const out = new Uint8Array(32);
  out.set(bytes);
  out[0] = out[0]! & 0x1f;
  return out;
}

export function bytes32ToFrMasked(bytes: Uint8Array): bigint {
  return bytesToBigIntBe(maskToFrBe(bytes));
}

function sbox5(x: bigint): bigint {
  const x2 = (x * x) % BN254_FR_MODULUS;
  const x4 = (x2 * x2) % BN254_FR_MODULUS;
  return (x4 * x) % BN254_FR_MODULUS;
}

/**
 * Exact Circom / Solana `sol_poseidon` BN254 x^5 Poseidon hash for 1..=5 inputs.
 */
export function poseidonHash(inputs: readonly bigint[]): bigint {
  const width = inputs.length + 1;
  const params = POSEIDON_PARAMS[width];
  if (!params) {
    throw new RangeError(`Unsupported Poseidon arity ${inputs.length} (expected 1..=5)`);
  }
  const state = new Array<bigint>(width);
  state[0] = 0n;
  for (let i = 0; i < inputs.length; i++) {
    state[i + 1] = modFr(inputs[i]!);
  }

  const half = params.fullRounds >>> 1;
  const totalRounds = params.fullRounds + params.partialRounds;
  const { ark, mds } = params;
  const next = new Array<bigint>(width);

  for (let r = 0; r < totalRounds; r++) {
    const base = r * width;
    for (let i = 0; i < width; i++) {
      let s = state[i]! + ark[base + i]!;
      if (s >= BN254_FR_MODULUS) s -= BN254_FR_MODULUS;
      state[i] = s;
    }

    if (r < half || r >= half + params.partialRounds) {
      for (let i = 0; i < width; i++) {
        state[i] = sbox5(state[i]!);
      }
    } else {
      state[0] = sbox5(state[0]!);
    }

    for (let row = 0; row < width; row++) {
      const mdsRow = mds[row]!;
      let acc = 0n;
      for (let col = 0; col < width; col++) {
        acc += state[col]! * mdsRow[col]!;
      }
      next[row] = acc % BN254_FR_MODULUS;
    }
    for (let i = 0; i < width; i++) {
      state[i] = next[i]!;
    }
  }
  return state[0]!;
}

export function poseidon2(a: bigint, b: bigint): bigint {
  return poseidonHash([a, b]);
}

export function poseidon3(a: bigint, b: bigint, c: bigint): bigint {
  return poseidonHash([a, b, c]);
}

export function poseidon4(a: bigint, b: bigint, c: bigint, d: bigint): bigint {
  return poseidonHash([a, b, c, d]);
}

export function poseidon5(a: bigint, b: bigint, c: bigint, d: bigint, e: bigint): bigint {
  return poseidonHash([a, b, c, d, e]);
}

/** `asset_id = mask_to_fr_be(SHA-256("audren/v1/asset" || mint_32))`. */
export function deriveAssetId(mintBytes: Uint8Array): bigint {
  if (mintBytes.byteLength !== 32) {
    throw new RangeError(`mintBytes must be 32 bytes, got ${mintBytes.byteLength}`);
  }
  const preimage = new Uint8Array(ASSET_ID_DOMAIN_BYTES.byteLength + 32);
  preimage.set(ASSET_ID_DOMAIN_BYTES, 0);
  preimage.set(mintBytes, ASSET_ID_DOMAIN_BYTES.byteLength);
  return bytes32ToFrMasked(sha256(preimage));
}

export function deriveAssetIdBytes(mintBytes: Uint8Array): Uint8Array {
  return frToBeBytes(deriveAssetId(mintBytes));
}

export function deriveSpendPk(spendSk: bigint): bigint {
  return poseidon2(DOMAIN_PK, spendSk);
}

export function deriveNullifierKey(spendSk: bigint): bigint {
  return poseidon2(DOMAIN_NK, spendSk);
}

export function deriveStealthOwner(spendPk: bigint, tweak: bigint): bigint {
  return poseidon3(DOMAIN_STEALTH, spendPk, tweak);
}

export function computeNoteCommitment(
  stealthOwner: bigint,
  assetId: bigint,
  amount: bigint,
  blinding: bigint,
): bigint {
  return poseidon5(DOMAIN_NOTE, stealthOwner, assetId, amount, blinding);
}

export function computeRealNullifier(nk: bigint, noteCm: bigint, globalLeafIndex: bigint): bigint {
  return poseidon4(DOMAIN_NULLIFIER, nk, noteCm, globalLeafIndex);
}

export function computeDummyNullifier(nk: bigint, blinding: bigint): bigint {
  return poseidon3(DOMAIN_DUMMY_NF, nk, blinding);
}

export function packPublicAmounts(publicAmountOut: bigint, relayerFeeAmount: bigint): bigint {
  return modFr(publicAmountOut + (relayerFeeAmount << 64n));
}

export function computePublicInputHash(params: {
  superRoot: bigint;
  nf0: bigint;
  nf1: bigint;
  cm0: bigint;
  cm1: bigint;
  cm2: bigint;
  publicAssetId: bigint;
  publicAmountOut: bigint;
  relayerFeeAmount: bigint;
  ctxHash: bigint;
}): bigint {
  const hA = poseidon5(DOMAIN_PUB_HASH_A, params.superRoot, params.nf0, params.nf1, params.cm0);
  const hB = poseidon5(
    DOMAIN_PUB_HASH_B,
    params.cm1,
    params.cm2,
    params.publicAssetId,
    packPublicAmounts(params.publicAmountOut, params.relayerFeeAmount),
  );
  return poseidon4(DOMAIN_PUB_HASH_FINAL, hA, hB, params.ctxHash);
}

/** Compute the global 16-lane super-root (2-level 4-ary Poseidon4 tree). */
export function computeSuperRoot4Ary(laneRoots: readonly bigint[]): bigint {
  if (laneRoots.length !== NUM_LANES) {
    throw new RangeError(`Expected ${NUM_LANES} lane roots, got ${laneRoots.length}`);
  }
  const mid = [
    poseidon4(laneRoots[0]!, laneRoots[1]!, laneRoots[2]!, laneRoots[3]!),
    poseidon4(laneRoots[4]!, laneRoots[5]!, laneRoots[6]!, laneRoots[7]!),
    poseidon4(laneRoots[8]!, laneRoots[9]!, laneRoots[10]!, laneRoots[11]!),
    poseidon4(laneRoots[12]!, laneRoots[13]!, laneRoots[14]!, laneRoots[15]!),
  ];
  return poseidon4(mid[0]!, mid[1]!, mid[2]!, mid[3]!);
}

/** Compute level-4 root of a 256-leaf subtree truncated at `activeLen` leaves (rest = Z[0]). */
export function computeSubtree256Root(leaves: readonly bigint[], activeLen: number): bigint {
  let layer = new Array<bigint>(256);
  for (let i = 0; i < 256; i++) {
    layer[i] = i < activeLen && i < leaves.length ? leaves[i]! : ZERO_HASHES_4ARY[0]!;
  }
  for (let level = 0; level < 4; level++) {
    const nextLen = layer.length >>> 2;
    const next = new Array<bigint>(nextLen);
    for (let i = 0; i < nextLen; i++) {
      next[i] = poseidon4(
        layer[i * 4]!,
        layer[i * 4 + 1]!,
        layer[i * 4 + 2]!,
        layer[i * 4 + 3]!,
      );
    }
    layer = next;
  }
  return layer[0]!;
}
