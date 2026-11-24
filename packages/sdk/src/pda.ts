/**
 * Solana Base58 codec, BIP-350 Bech32m `aud1...` stealth address codec (HRP `"aud"`,
 * version `0x01`, 65-byte payload, 114 chars), and canonical 12 Audren v1 PDA derivations
 * (`audren_*`) matching `crates/client/src/pda.rs` byte-for-byte.
 */

import { x25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  AUDREN_PROGRAM_ID,
  CLASSIC_TOKEN_PROGRAM_ID,
  ESCROW_SEED,
  LANE_RENT_SEED,
  LANE_SEED,
  MEMO_SEED,
  NF_PAGE_SEED,
  NULLIFIER_SEED,
  NUM_ESCROW_SHARDS,
  NUM_LANES,
  POOL_SEED,
  ROOTS_SEED,
  SUBROOT_SEED,
  SUBTREE_SEED,
  UNWRAP_SEED,
  VAULT_AUTH_SEED,
} from './constants.ts';
import { isCanonicalFr } from './poseidon.ts';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_MAP = new Int16Array(128).fill(-1);
for (let i = 0; i < BASE58_ALPHABET.length; i++) {
  BASE58_MAP[BASE58_ALPHABET.charCodeAt(i)] = i;
}

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32_CHARSET_MAP = new Int8Array(128).fill(-1);
for (let i = 0; i < BECH32_CHARSET.length; i++) {
  BECH32_CHARSET_MAP[BECH32_CHARSET.charCodeAt(i)] = i;
}
const BECH32M_CONST = 0x2bc830a3;
const BECH32_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3] as const;
const BECH32_MAX_LEN = 128;
const AUDREN_ADDR_HRP = 'aud';
const ADDR_VERSION_V1 = 0x01;
const X25519_PROBE_SCALAR = new Uint8Array(32).fill(0x09);

function isAllZero32(bytes: Uint8Array): boolean {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 32) return true;
  let acc = 0;
  for (let i = 0; i < 32; i++) acc |= bytes[i]!;
  return acc === 0;
}

/**
 * Verify an X25519 public key is contributory (rejects all-zero and Curve25519 order-8 low-order
 * points using the fixed RFC 7748 probe scalar `[0x09; 32]`).
 */
export function isContributoryX25519Point(viewPk: Uint8Array): boolean {
  if (!(viewPk instanceof Uint8Array) || viewPk.byteLength !== 32) return false;
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(X25519_PROBE_SCALAR, viewPk);
  } catch {
    return false;
  }
  return !isAllZero32(shared);
}

const utf8Encoder = new TextEncoder();
const PDA_MARKER = utf8Encoder.encode('ProgramDerivedAddress');

const ED25519_P = (1n << 255n) - 19n;
const ED25519_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
const ED25519_SQRT_M1 =
  19681161376707505956807079304988542015446066515923890162744021073123829784752n;
const ED25519_EXP = (ED25519_P - 5n) >> 3n;

export interface DerivedPda {
  address: string;
  addressBytes: Uint8Array;
  bump: number;
}

export interface ParsedAudrenAddress {
  encoded: string;
  spendPk: Uint8Array; // 32 bytes canonical BN254 Fr BE
  viewPk: Uint8Array; // 32 bytes X25519 public key
}

export function base58Encode(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array)) {
    throw new RangeError(`base58Encode input must be a Uint8Array, got ${String(bytes)}`);
  }
  if (bytes.byteLength === 0) return '';
  let zeros = 0;
  while (zeros < bytes.byteLength && bytes[zeros] === 0) zeros++;
  if (zeros === bytes.byteLength) return '1'.repeat(zeros);
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

const BASE58_DEFAULT_MAX_LEN = 256;

export function base58Decode(input: string, maxLen = BASE58_DEFAULT_MAX_LEN): Uint8Array {
  if (typeof input !== 'string') {
    throw new Error(`Base58 input must be a string, got ${typeof input}`);
  }
  if (!Number.isInteger(maxLen) || maxLen < 0) {
    throw new RangeError(`Base58 maxLen must be a non-negative integer, got ${String(maxLen)}`);
  }
  if (input.length === 0) return new Uint8Array(0);
  if (input.length > maxLen) {
    throw new RangeError(`Base58 input length ${input.length} exceeds limit ${maxLen}`);
  }
  let zeros = 0;
  while (zeros < input.length && input[zeros] === '1') zeros++;
  const bytes: number[] = [0];
  for (let i = zeros; i < input.length; i++) {
    const code = input.charCodeAt(i);
    const val = code < 128 ? BASE58_MAP[code]! : -1;
    if (val < 0) throw new Error(`Invalid base58 character at index ${i}`);
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

export function toPubkeyBytes(pubkey: string | Uint8Array): Uint8Array {
  if (typeof pubkey === 'string') {
    if (pubkey.length > 44) {
      throw new RangeError(`Solana public key base58 length ${pubkey.length} exceeds 44`);
    }
    const bytes = base58Decode(pubkey, 44);
    if (bytes.byteLength !== 32) {
      throw new RangeError(`Solana public key must be 32 bytes, got ${bytes.byteLength}`);
    }
    return bytes;
  }
  if (!(pubkey instanceof Uint8Array) || pubkey.byteLength !== 32) {
    throw new RangeError(
      `Solana public key must be a base58 string or 32-byte Uint8Array, got ${pubkey instanceof Uint8Array ? pubkey.byteLength : String(pubkey)}`,
    );
  }
  return pubkey;
}

// =============================================================================
// Canonical BIP-350 Bech32m Codec (`hrp = "aud"`, up to 128 chars)
// =============================================================================

function bech32Polymod(values: readonly number[]): number {
  let chk = 1;
  for (let i = 0; i < values.length; i++) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ values[i]!;
    for (let b = 0; b < 5; b++) {
      if ((top >>> b) & 1) chk ^= BECH32_GEN[b]!;
    }
  }
  return chk >>> 0;
}

function bech32HrpExpand(hrp: string): number[] {
  const ret: number[] = [];
  for (let i = 0; i < hrp.length; i++) {
    ret.push(hrp.charCodeAt(i) >>> 5);
  }
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) {
    ret.push(hrp.charCodeAt(i) & 31);
  }
  return ret;
}

function bech32mCreateChecksum(hrp: string, data5: readonly number[]): number[] {
  const values = [...bech32HrpExpand(hrp), ...data5, 0, 0, 0, 0, 0, 0];
  const pmod = (bech32Polymod(values) ^ BECH32M_CONST) >>> 0;
  const out: number[] = [];
  for (let i = 0; i < 6; i++) {
    out.push((pmod >>> (5 * (5 - i))) & 31);
  }
  return out;
}

function convertBits(
  data: readonly number[] | Uint8Array,
  fromBits: number,
  toBits: number,
  pad: boolean,
): number[] {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  const maxv = (1 << toBits) - 1;
  const maxAcc = (1 << (fromBits + toBits - 1)) - 1;
  for (let i = 0; i < data.length; i++) {
    const value = data[i]!;
    if (value < 0 || value >>> fromBits !== 0) {
      throw new Error(`Invalid Bech32m bit group value: ${value}`);
    }
    acc = ((acc << fromBits) | value) & maxAcc;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      out.push((acc >>> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) {
      out.push((acc << (toBits - bits)) & maxv);
    }
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) {
    throw new Error('Invalid Bech32m padding bits');
  }
  return out;
}

/**
 * Encode `(spendPk[32], viewPk[32])` into a canonical BIP-350 Bech32m `aud1...` stealth address
 * (`hrp = "aud"`, payload `0x01 || spend_pk[32] || view_pk[32]`, 114 lowercase characters).
 */
export function formatAudrenAddress(spendPk: Uint8Array, viewPk: Uint8Array): string {
  if (
    !(spendPk instanceof Uint8Array) ||
    spendPk.byteLength !== 32 ||
    !(viewPk instanceof Uint8Array) ||
    viewPk.byteLength !== 32
  ) {
    throw new RangeError('spendPk and viewPk must each be a 32-byte Uint8Array');
  }
  if (!isCanonicalFr(spendPk)) {
    throw new Error('spendPk must be a canonical BN254 Fr scalar (< r)');
  }
  if (!isContributoryX25519Point(viewPk)) {
    throw new Error('viewPk must be a contributory X25519 public key (non-low-order)');
  }
  const raw = new Uint8Array(65);
  raw[0] = ADDR_VERSION_V1;
  raw.set(spendPk, 1);
  raw.set(viewPk, 33);
  const data5 = convertBits(raw, 8, 5, true);
  const checksum = bech32mCreateChecksum(AUDREN_ADDR_HRP, data5);
  let out = `${AUDREN_ADDR_HRP}1`;
  for (const v of data5) out += BECH32_CHARSET[v]!;
  for (const v of checksum) out += BECH32_CHARSET[v]!;
  return out;
}

/**
 * Strictly decode and validate a BIP-350 Bech32m `aud1...` stealth address.
 * Rejects leading/trailing whitespace, mixed case, wrong HRP, invalid Bech32m checksum,
 * non-zero pad bits, wrong payload length, wrong version byte (`!== 0x01`),
 * non-canonical `spendPk >= r`, and non-contributory / low-order X25519 `viewPk`.
 */
export function parseAudrenAddress(encoded: string): ParsedAudrenAddress {
  if (typeof encoded !== 'string' || encoded.length < 8 || encoded.length > BECH32_MAX_LEN) {
    throw new Error(
      `Invalid Audren Bech32m address length (${typeof encoded === 'string' ? encoded.length : String(encoded)})`,
    );
  }
  let hasLower = false;
  let hasUpper = false;
  for (let i = 0; i < encoded.length; i++) {
    const code = encoded.charCodeAt(i);
    if (code < 33 || code > 126) {
      throw new Error(`Invalid character in Audren Bech32m address at index ${i}`);
    }
    if (code >= 97 && code <= 122) hasLower = true;
    if (code >= 65 && code <= 90) hasUpper = true;
  }
  if (hasLower && hasUpper) {
    throw new Error('Mixed case is forbidden in Bech32m Audren address');
  }
  const lower = encoded.toLowerCase();
  const sep = lower.lastIndexOf('1');
  if (sep < 1 || sep + 7 > lower.length) {
    throw new Error('Invalid Bech32m separator position in Audren address');
  }
  const hrp = lower.slice(0, sep);
  if (hrp !== AUDREN_ADDR_HRP) {
    throw new Error(`Invalid Audren address HRP: expected "${AUDREN_ADDR_HRP}", got "${hrp}"`);
  }
  const dataPart = lower.slice(sep + 1);
  const dataValues: number[] = [];
  for (let i = 0; i < dataPart.length; i++) {
    const code = dataPart.charCodeAt(i);
    const val = code < 128 ? BECH32_CHARSET_MAP[code]! : -1;
    if (val < 0) {
      throw new Error(`Invalid Bech32m character '${dataPart[i]}' in Audren address`);
    }
    dataValues.push(val);
  }
  if (bech32Polymod([...bech32HrpExpand(hrp), ...dataValues]) !== BECH32M_CONST) {
    throw new Error('Invalid Bech32m checksum in Audren address');
  }
  const payload5 = dataValues.slice(0, dataValues.length - 6);
  const raw = new Uint8Array(convertBits(payload5, 5, 8, false));
  if (raw.byteLength !== 65 || raw[0] !== ADDR_VERSION_V1) {
    throw new Error(`Invalid Audren address payload length or version (len=${raw.byteLength}, v=${raw[0]})`);
  }
  const spendPk = raw.slice(1, 33);
  const viewPk = raw.slice(33, 65);
  if (!isCanonicalFr(spendPk)) {
    throw new Error('Audren address spendPk is not a canonical BN254 Fr scalar');
  }
  if (!isContributoryX25519Point(viewPk)) {
    throw new Error('Audren address viewPk is a low-order X25519 public key');
  }
  return { encoded: lower, spendPk, viewPk };
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

export function isOnEd25519Curve(bytes: Uint8Array): boolean {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 32) return false;
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
  const v7 = (((v3 * v3) % ED25519_P) * v) % ED25519_P;
  const uv7 = (u * v7) % ED25519_P;
  let x = (((u * v3) % ED25519_P) * modPowP(uv7, ED25519_EXP)) % ED25519_P;

  const vx2 = (v * ((x * x) % ED25519_P)) % ED25519_P;
  if (vx2 === u) return true;
  if (vx2 === modP(-u)) {
    x = (x * ED25519_SQRT_M1) % ED25519_P;
    return (v * ((x * x) % ED25519_P)) % ED25519_P === u;
  }
  return false;
}

const U32_MAX = 0xffff_ffff;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

function assertLaneId(laneId: number): void {
  if (!Number.isInteger(laneId) || laneId < 0 || laneId >= NUM_LANES) {
    throw new RangeError(`laneId must be 0..${NUM_LANES - 1}, got ${laneId}`);
  }
}

function u32le(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > U32_MAX) {
    throw new RangeError(`u32 value out of range (0..=${U32_MAX}), got ${n}`);
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, true);
  return out;
}

function u64le(n: bigint): Uint8Array {
  if (typeof n !== 'bigint' || n < 0n || n > U64_MAX) {
    throw new RangeError(`u64 value out of range (0..=2^64-1), got ${String(n)}`);
  }
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, n, true);
  return out;
}

const MAX_SEED_LEN = 32;

function sha256ConcatSync(parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) {
    if (!(p instanceof Uint8Array)) {
      throw new RangeError(`Expected Uint8Array seed part, got ${String(p)}`);
    }
    total += p.byteLength;
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.byteLength;
  }
  return sha256(buf);
}

/** Synchronous Solana `Pubkey::find_program_address`. */
export function findProgramAddressSync(
  seeds: readonly Uint8Array[],
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): DerivedPda {
  if (!Array.isArray(seeds)) {
    throw new RangeError('seeds must be an array of Uint8Arrays');
  }
  if (seeds.length >= 16) {
    throw new RangeError(`Solana PDA supports at most 15 caller seeds, got ${seeds.length}`);
  }
  for (let i = 0; i < seeds.length; i++) {
    const s = seeds[i];
    if (!(s instanceof Uint8Array)) {
      throw new RangeError(`PDA seed[${i}] must be a Uint8Array, got ${String(s)}`);
    }
    if (s.byteLength > MAX_SEED_LEN) {
      throw new RangeError(
        `PDA seed[${i}] length ${s.byteLength} exceeds Solana MAX_SEED_LEN (${MAX_SEED_LEN})`,
      );
    }
  }
  const programBytes = toPubkeyBytes(programId);
  const bumpBuf = new Uint8Array(1);
  for (let bump = 255; bump >= 0; bump--) {
    bumpBuf[0] = bump;
    const candidate = sha256ConcatSync([...seeds, bumpBuf, programBytes, PDA_MARKER]);
    if (!isOnEd25519Curve(candidate)) {
      return {
        address: base58Encode(candidate),
        addressBytes: candidate,
        bump,
      };
    }
  }
  throw new Error('Unable to find viable PDA bump');
}

export async function findProgramAddress(
  seeds: readonly Uint8Array[],
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return findProgramAddressSync(seeds, programId);
}

export function derivePoolPdaSync(
  poolId = 0,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): DerivedPda {
  return findProgramAddressSync([utf8Encoder.encode(POOL_SEED), u32le(poolId)], programId);
}

export async function derivePoolPda(
  poolId = 0,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return derivePoolPdaSync(poolId, programId);
}

export function deriveVaultAuthPdaSync(
  poolId = 0,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): DerivedPda {
  return findProgramAddressSync([utf8Encoder.encode(VAULT_AUTH_SEED), u32le(poolId)], programId);
}

export async function deriveVaultAuthPda(
  poolId = 0,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return deriveVaultAuthPdaSync(poolId, programId);
}

export function deriveLanePdaSync(
  poolId: number,
  laneId: number,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): DerivedPda {
  assertLaneId(laneId);
  return findProgramAddressSync(
    [utf8Encoder.encode(LANE_SEED), u32le(poolId), new Uint8Array([laneId])],
    programId,
  );
}

export async function deriveLanePda(
  poolId: number,
  laneId: number,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return deriveLanePdaSync(poolId, laneId, programId);
}

export function deriveLaneRentVaultPdaSync(
  poolId: number,
  laneId: number,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): DerivedPda {
  assertLaneId(laneId);
  return findProgramAddressSync(
    [utf8Encoder.encode(LANE_RENT_SEED), u32le(poolId), new Uint8Array([laneId])],
    programId,
  );
}

export async function deriveLaneRentVaultPda(
  poolId: number,
  laneId: number,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return deriveLaneRentVaultPdaSync(poolId, laneId, programId);
}

export function deriveSubtreePdaSync(
  poolId: number,
  laneId: number,
  pageSeq: bigint,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): DerivedPda {
  assertLaneId(laneId);
  return findProgramAddressSync(
    [utf8Encoder.encode(SUBTREE_SEED), u32le(poolId), new Uint8Array([laneId]), u64le(pageSeq)],
    programId,
  );
}

export async function deriveSubtreePda(
  poolId: number,
  laneId: number,
  pageSeq: bigint,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return deriveSubtreePdaSync(poolId, laneId, pageSeq, programId);
}

export function deriveSubrootPdaSync(
  poolId: number,
  laneId: number,
  rootPageSeq: bigint,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): DerivedPda {
  assertLaneId(laneId);
  return findProgramAddressSync(
    [utf8Encoder.encode(SUBROOT_SEED), u32le(poolId), new Uint8Array([laneId]), u64le(rootPageSeq)],
    programId,
  );
}

export async function deriveSubrootPda(
  poolId: number,
  laneId: number,
  rootPageSeq: bigint,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return deriveSubrootPdaSync(poolId, laneId, rootPageSeq, programId);
}

export function deriveMemoPdaSync(
  poolId: number,
  laneId: number,
  pageSeq: bigint,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): DerivedPda {
  assertLaneId(laneId);
  return findProgramAddressSync(
    [utf8Encoder.encode(MEMO_SEED), u32le(poolId), new Uint8Array([laneId]), u64le(pageSeq)],
    programId,
  );
}

export async function deriveMemoPda(
  poolId: number,
  laneId: number,
  pageSeq: bigint,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return deriveMemoPdaSync(poolId, laneId, pageSeq, programId);
}

export function deriveNfPagePdaSync(
  poolId: number,
  laneId: number,
  pageSeq: bigint,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): DerivedPda {
  assertLaneId(laneId);
  return findProgramAddressSync(
    [utf8Encoder.encode(NF_PAGE_SEED), u32le(poolId), new Uint8Array([laneId]), u64le(pageSeq)],
    programId,
  );
}

export async function deriveNfPagePda(
  poolId: number,
  laneId: number,
  pageSeq: bigint,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return deriveNfPagePdaSync(poolId, laneId, pageSeq, programId);
}

export function deriveRootsPdaSync(
  poolId = 0,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): DerivedPda {
  return findProgramAddressSync([utf8Encoder.encode(ROOTS_SEED), u32le(poolId)], programId);
}

export async function deriveRootsPda(
  poolId = 0,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return deriveRootsPdaSync(poolId, programId);
}

export function deriveNullifierPdaSync(
  poolId: number,
  nullifier: Uint8Array,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): DerivedPda {
  if (!(nullifier instanceof Uint8Array) || nullifier.byteLength !== 32) {
    throw new RangeError(
      `nullifier must be a 32-byte Uint8Array, got ${nullifier instanceof Uint8Array ? nullifier.byteLength : String(nullifier)}`,
    );
  }
  return findProgramAddressSync(
    [utf8Encoder.encode(NULLIFIER_SEED), u32le(poolId), nullifier],
    programId,
  );
}

export async function deriveNullifierPda(
  poolId: number,
  nullifier: Uint8Array,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return deriveNullifierPdaSync(poolId, nullifier, programId);
}

export function deriveEscrowPdaSync(
  poolId = 0,
  shardId = 0,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): DerivedPda {
  if (!Number.isInteger(shardId) || shardId < 0 || shardId >= NUM_ESCROW_SHARDS) {
    throw new RangeError(`shardId must be 0..${NUM_ESCROW_SHARDS - 1}, got ${shardId}`);
  }
  return findProgramAddressSync(
    [utf8Encoder.encode(ESCROW_SEED), u32le(poolId), new Uint8Array([shardId])],
    programId,
  );
}

export async function deriveEscrowPda(
  poolId = 0,
  shardId = 0,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return deriveEscrowPdaSync(poolId, shardId, programId);
}

export function deriveUnwrapPdaSync(
  poolId: number,
  nf0: Uint8Array,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): DerivedPda {
  if (!(nf0 instanceof Uint8Array) || nf0.byteLength !== 32) {
    throw new RangeError(
      `nf0 must be a 32-byte Uint8Array, got ${nf0 instanceof Uint8Array ? nf0.byteLength : String(nf0)}`,
    );
  }
  return findProgramAddressSync(
    [utf8Encoder.encode(UNWRAP_SEED), u32le(poolId), nf0],
    programId,
  );
}

export async function deriveUnwrapPda(
  poolId: number,
  nf0: Uint8Array,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return deriveUnwrapPdaSync(poolId, nf0, programId);
}

export function deriveAssociatedTokenAddressSync(
  owner: string | Uint8Array,
  mint: string | Uint8Array,
  tokenProgramId: string | Uint8Array = CLASSIC_TOKEN_PROGRAM_ID,
): DerivedPda {
  return findProgramAddressSync(
    [toPubkeyBytes(owner), toPubkeyBytes(tokenProgramId), toPubkeyBytes(mint)],
    ASSOCIATED_TOKEN_PROGRAM_ID,
  );
}

export async function deriveAssociatedTokenAddress(
  owner: string | Uint8Array,
  mint: string | Uint8Array,
  tokenProgramId: string | Uint8Array = CLASSIC_TOKEN_PROGRAM_ID,
): Promise<DerivedPda> {
  return deriveAssociatedTokenAddressSync(owner, mint, tokenProgramId);
}
