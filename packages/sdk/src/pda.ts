/**
 * Zero-dependency Solana Base58 codec, `aud1…` stealth address parser (with canonical
 * Ristretto255 point validation per RFC 9496 §4.3.1), and canonical PDA derivation helpers
 * matching `crates/client/src/pda.rs` byte-for-byte.
 *
 * Uses native Web Crypto (`SHA-256`) and pure `BigInt` curve arithmetic
 * (`curve25519-dalek` `CompressedEdwardsY::decompress` semantics matching Solana's
 * `Pubkey::find_program_address`) with zero npm dependencies.
 */

import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  AUDREN_PROGRAM_ID,
  CLASSIC_TOKEN_PROGRAM_ID,
  ESCROW_SEED,
  LANE_RENT_SEED,
  LANE_SEED,
  MAX_APPEND_LANES,
  MAX_ESCROW_SHARDS,
  NULLIFIER_SEED,
  PAGE_RENT_SEED,
  PAGE_SEED,
  POOL_SEED,
  PROOF_BUFFER_SEED,
  SOL_VAULT_SEED,
  VAULT_AUTH_SEED,
} from './constants.ts';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_MAP = new Int16Array(128).fill(-1);
for (let i = 0; i < BASE58_ALPHABET.length; i++) {
  BASE58_MAP[BASE58_ALPHABET.charCodeAt(i)] = i;
}

const utf8Encoder = new TextEncoder();
const PDA_MARKER = utf8Encoder.encode('ProgramDerivedAddress');

// Ed25519 prime field constants: p = 2^255 - 19, d = -121665/121666 mod p, sqrt(-1) = 2^((p-1)/4) mod p
const ED25519_P = (1n << 255n) - 19n;
const ED25519_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
const ED25519_SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
const ED25519_EXP = (ED25519_P - 5n) >> 3n;

export interface DerivedPda {
  address: string;
  addressBytes: Uint8Array;
  bump: number;
}

export interface ParsedAudrenAddress {
  encoded: string;
  spendPk: Uint8Array; // 32 bytes (valid non-identity Ristretto255 point)
  viewPk: Uint8Array; // 32 bytes (valid non-identity Ristretto255 point)
}

export function base58Encode(bytes: Uint8Array): string {
  if (bytes.byteLength === 0) return '';
  let zeros = 0;
  while (zeros < bytes.byteLength && bytes[zeros] === 0) zeros++;
  if (zeros === bytes.byteLength) {
    return '1'.repeat(zeros);
  }
  const digits: number[] = [0];
  for (let i = zeros; i < bytes.byteLength; i++) {
    let carry = bytes[i]!;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = '1'.repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) {
    out += BASE58_ALPHABET[digits[i]!]!;
  }
  return out;
}

export function base58Decode(input: string): Uint8Array {
  if (input.length === 0) return new Uint8Array(0);
  let zeros = 0;
  while (zeros < input.length && input[zeros] === '1') zeros++;
  const bytes: number[] = [0];
  for (let i = zeros; i < input.length; i++) {
    const code = input.charCodeAt(i);
    const val = code < 128 ? BASE58_MAP[code]! : -1;
    if (val < 0) {
      throw new Error(`Invalid base58 character at index ${i}`);
    }
    let carry = val;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j]! * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  const trimmedLen = bytes.length === 1 && bytes[0] === 0 ? 0 : bytes.length;
  const out = new Uint8Array(zeros + trimmedLen);
  for (let i = 0; i < trimmedLen; i++) {
    out[zeros + i] = bytes[trimmedLen - 1 - i]!;
  }
  return out;
}

/** Decode a base58 Solana public key or validate a 32-byte `Uint8Array`. */
export function toPubkeyBytes(pubkey: string | Uint8Array): Uint8Array {
  const bytes = typeof pubkey === 'string' ? base58Decode(pubkey) : pubkey;
  if (bytes.byteLength !== 32) {
    throw new RangeError(`Solana public key must be 32 bytes, got ${bytes.byteLength}`);
  }
  return bytes;
}

function modP(n: bigint): bigint {
  const r = n % ED25519_P;
  return r >= 0n ? r : r + ED25519_P;
}

function modPowP(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let b = modP(base);
  let e = exp;
  while (e > 0n) {
    if ((e & 1n) === 1n) result = (result * b) % ED25519_P;
    b = (b * b) % ED25519_P;
    e >>= 1n;
  }
  return result;
}

/**
 * Validate whether 32 bytes are a canonical Ristretto255 encoding per RFC 9496 §4.3.1.
 * Note: the all-zero encoding is the valid Ristretto255 identity point; callers requiring
 * a non-identity public key should also reject all-zero bytes.
 */
export function isValidRistretto255Point(bytes: Uint8Array): boolean {
  if (bytes.byteLength !== 32) return false;
  let s = 0n;
  for (let i = 31; i >= 0; i--) {
    s = (s << 8n) | BigInt(bytes[i]!);
  }
  if (s >= ED25519_P || (s & 1n) === 1n) return false;

  const ss = (s * s) % ED25519_P;
  const u1 = modP(1n - ss);
  const u2 = modP(1n + ss);
  const u2Sqr = (u2 * u2) % ED25519_P;
  const v = modP(-((ED25519_D * ((u1 * u1) % ED25519_P)) % ED25519_P) - u2Sqr);

  // invsqrt(v * u2^2) via SQRT_RATIO_M1(1, w)
  const w = (v * u2Sqr) % ED25519_P;
  const w2 = (w * w) % ED25519_P;
  const w3 = (w2 * w) % ED25519_P;
  const w7 = (((w3 * w3) % ED25519_P) * w) % ED25519_P;
  let invsqrt = (w3 * modPowP(w7, ED25519_EXP)) % ED25519_P;
  const check = (w * ((invsqrt * invsqrt) % ED25519_P)) % ED25519_P;

  if (check === modP(-1n)) {
    invsqrt = (invsqrt * ED25519_SQRT_M1) % ED25519_P;
  } else if (check !== 1n) {
    return false;
  }

  const denX = (invsqrt * u2) % ED25519_P;
  const denY = (((invsqrt * denX) % ED25519_P) * v) % ED25519_P;
  let x = (2n * s * denX) % ED25519_P;
  if ((x & 1n) === 1n) x = modP(-x);
  const y = (u1 * denY) % ED25519_P;
  const t = (x * y) % ED25519_P;

  return (t & 1n) === 0n && y !== 0n;
}

/**
 * Format 32-byte non-identity Ristretto255 `(spendPk, viewPk)` into a shareable `aud1…` address.
 */
export function formatAudrenAddress(spendPk: Uint8Array, viewPk: Uint8Array): string {
  if (spendPk.byteLength !== 32 || viewPk.byteLength !== 32) {
    throw new RangeError('spendPk and viewPk must each be 32 bytes');
  }
  if (spendPk.every((b) => b === 0) || viewPk.every((b) => b === 0)) {
    throw new Error('Audren stealth address keys cannot be zero');
  }
  if (!isValidRistretto255Point(spendPk) || !isValidRistretto255Point(viewPk)) {
    throw new Error('Audren stealth address keys must be canonical Ristretto255 points');
  }
  const raw = new Uint8Array(64);
  raw.set(spendPk, 0);
  raw.set(viewPk, 32);
  return `aud1${base58Encode(raw)}`;
}

/**
 * Parse and cryptographically validate an `aud1…` stealth meta-address (or raw 64-byte base58
 * body) into its canonical non-identity Ristretto255 `(spendPk, viewPk)` pair.
 */
export function parseAudrenAddress(encoded: string): ParsedAudrenAddress {
  const trimmed = encoded.trim();
  const body = trimmed.startsWith('aud1') ? trimmed.slice(4) : trimmed;
  const raw = base58Decode(body);
  if (raw.byteLength !== 64) {
    throw new Error(`Audren stealth address payload must be 64 bytes, got ${raw.byteLength}`);
  }
  const spendPk = raw.slice(0, 32);
  const viewPk = raw.slice(32, 64);
  if (spendPk.every((b) => b === 0) || viewPk.every((b) => b === 0)) {
    throw new Error('Audren stealth address keys cannot be zero');
  }
  if (!isValidRistretto255Point(spendPk) || !isValidRistretto255Point(viewPk)) {
    throw new Error('Audren stealth address contains an invalid Ristretto255 point');
  }
  return { encoded: `aud1${base58Encode(raw)}`, spendPk, viewPk };
}

/**
 * Check whether 32 bytes decode to a point on the Ed25519 twisted Edwards curve using
 * `curve25519-dalek` `CompressedEdwardsY::decompress` semantics, matching Solana's
 * `Pubkey::find_program_address` byte-for-byte.
 */
export function isOnEd25519Curve(bytes: Uint8Array): boolean {
  if (bytes.byteLength !== 32) return false;
  let y = 0n;
  for (let i = 31; i >= 0; i--) {
    const b = i === 31 ? bytes[i]! & 0x7f : bytes[i]!;
    y = (y << 8n) | BigInt(b);
  }
  const yMod = modP(y);
  const y2 = (yMod * yMod) % ED25519_P;
  const u = modP(y2 - 1n);
  const v = modP(ED25519_D * y2 + 1n);
  if (v === 0n) return u === 0n;

  const v2 = (v * v) % ED25519_P;
  const v3 = (v2 * v) % ED25519_P;
  const v7 = (v3 * v3 % ED25519_P * v) % ED25519_P;
  const uv7 = (u * v7) % ED25519_P;
  let x = (u * v3 % ED25519_P * modPowP(uv7, ED25519_EXP)) % ED25519_P;

  const vx2 = (v * ((x * x) % ED25519_P)) % ED25519_P;
  if (vx2 === u) return true;
  if (vx2 === modP(-u)) {
    x = (x * ED25519_SQRT_M1) % ED25519_P;
    return (v * ((x * x) % ED25519_P)) % ED25519_P === u;
  }
  return false;
}

function u32le(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) {
    throw new RangeError(`Expected u32 integer, got ${n}`);
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, true);
  return out;
}

function u64le(n: bigint): Uint8Array {
  if (n < 0n || n > 0xffff_ffff_ffff_ffffn) {
    throw new RangeError(`Expected u64 bigint, got ${n.toString()}`);
  }
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, n, true);
  return out;
}

async function sha256Concat(parts: readonly Uint8Array[]): Promise<Uint8Array> {
  let total = 0;
  for (const p of parts) total += p.byteLength;
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.byteLength;
  }
  const digest = await globalThis.crypto.subtle.digest('SHA-256', buf);
  return new Uint8Array(digest);
}

/**
 * Derive a deterministic Solana Program Derived Address (`find_program_address`).
 * Solana enforces at most 16 total seeds including the 1-byte bump (`<= 15` caller seeds).
 */
export async function findProgramAddress(
  seeds: readonly Uint8Array[],
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  if (seeds.length >= 16) {
    throw new RangeError(`Solana findProgramAddress supports at most 15 caller seeds (16 with bump), got ${seeds.length}`);
  }
  for (const seed of seeds) {
    if (seed.byteLength > 32) {
      throw new RangeError(`Solana PDA seed exceeds 32 bytes (got ${seed.byteLength})`);
    }
  }
  const programBytes = toPubkeyBytes(programId);
  const bumpBuf = new Uint8Array(1);
  for (let bump = 255; bump >= 0; bump--) {
    bumpBuf[0] = bump;
    const candidate = await sha256Concat([...seeds, bumpBuf, programBytes, PDA_MARKER]);
    if (!isOnEd25519Curve(candidate)) {
      return {
        address: base58Encode(candidate),
        addressBytes: candidate,
        bump,
      };
    }
  }
  throw new Error('Unable to find viable Program Derived Address bump');
}

export async function derivePoolPda(
  poolId = 0,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return findProgramAddress([utf8Encoder.encode(POOL_SEED), u32le(poolId)], programId);
}

export async function deriveVaultAuthPda(
  poolId = 0,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return findProgramAddress([utf8Encoder.encode(VAULT_AUTH_SEED), u32le(poolId)], programId);
}

export async function deriveSolVaultPda(
  poolId = 0,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return findProgramAddress([utf8Encoder.encode(SOL_VAULT_SEED), u32le(poolId)], programId);
}

export async function derivePageRentVaultPda(
  poolId = 0,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return findProgramAddress([utf8Encoder.encode(PAGE_RENT_SEED), u32le(poolId)], programId);
}

export async function deriveEpochPagePda(
  poolId: number,
  pageId: bigint,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return findProgramAddress(
    [utf8Encoder.encode(PAGE_SEED), u32le(poolId), u64le(pageId)],
    programId,
  );
}

export async function deriveNullifierPda(
  poolId: number,
  nullifier: Uint8Array,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  if (nullifier.byteLength !== 32) {
    throw new RangeError(`Nullifier must be 32 bytes, got ${nullifier.byteLength}`);
  }
  return findProgramAddress(
    [utf8Encoder.encode(NULLIFIER_SEED), u32le(poolId), nullifier],
    programId,
  );
}

export async function deriveSwapEscrowPda(
  poolId = 0,
  shardId = 0,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  if (!Number.isInteger(shardId) || shardId < 0 || shardId >= MAX_ESCROW_SHARDS) {
    throw new RangeError(`shardId must be an integer in 0..${MAX_ESCROW_SHARDS - 1}, got ${shardId}`);
  }
  return findProgramAddress(
    [utf8Encoder.encode(ESCROW_SEED), u32le(poolId), new Uint8Array([shardId])],
    programId,
  );
}

export async function deriveProofBufferPda(
  authority: string | Uint8Array,
  nonce: bigint,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return findProgramAddress(
    [utf8Encoder.encode(PROOF_BUFFER_SEED), toPubkeyBytes(authority), u64le(nonce)],
    programId,
  );
}

export async function deriveLanePda(
  poolId: number,
  laneId: number,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  if (!Number.isInteger(laneId) || laneId < 1 || laneId >= MAX_APPEND_LANES) {
    throw new RangeError(`Parallel laneId must be an integer in 1..${MAX_APPEND_LANES - 1}, got ${laneId}`);
  }
  return findProgramAddress(
    [utf8Encoder.encode(LANE_SEED), u32le(poolId), new Uint8Array([laneId])],
    programId,
  );
}

export async function deriveLaneRentVaultPda(
  poolId: number,
  laneId: number,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  if (!Number.isInteger(laneId) || laneId < 1 || laneId >= MAX_APPEND_LANES) {
    throw new RangeError(`Parallel laneId must be an integer in 1..${MAX_APPEND_LANES - 1}, got ${laneId}`);
  }
  return findProgramAddress(
    [utf8Encoder.encode(LANE_RENT_SEED), u32le(poolId), new Uint8Array([laneId])],
    programId,
  );
}

/** Derive the canonical Associated Token Account address for `(owner, mint, tokenProgramId)`. */
export async function deriveAssociatedTokenAddress(
  owner: string | Uint8Array,
  mint: string | Uint8Array,
  tokenProgramId: string | Uint8Array = CLASSIC_TOKEN_PROGRAM_ID,
): Promise<DerivedPda> {
  return findProgramAddress(
    [toPubkeyBytes(owner), toPubkeyBytes(tokenProgramId), toPubkeyBytes(mint)],
    ASSOCIATED_TOKEN_PROGRAM_ID,
  );
}
