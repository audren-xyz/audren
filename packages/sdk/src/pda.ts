/**
 * Solana Base58 codec, `aud1...` stealth address codec (version `0x02`, 65 bytes),
 * and canonical Audren PDA derivations (`audren_v2_*`) matching `crates/client/src/pda.rs`
 * byte-for-byte.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  AUDREN_PROGRAM_ID,
  CHECKPOINT_RING_SLOTS,
  CKPT_SEED,
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
  SOL_VAULT_SEED,
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

const utf8Encoder = new TextEncoder();
const PDA_MARKER = utf8Encoder.encode('ProgramDerivedAddress');
const ADDR_VERSION_V2 = 0x02;

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

export function base58Decode(input: string): Uint8Array {
  if (input.length === 0) return new Uint8Array(0);
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
  const bytes = typeof pubkey === 'string' ? base58Decode(pubkey) : pubkey;
  if (bytes.byteLength !== 32) {
    throw new RangeError(`Solana public key must be 32 bytes, got ${bytes.byteLength}`);
  }
  return bytes;
}

export function formatAudrenAddress(spendPk: Uint8Array, viewPk: Uint8Array): string {
  if (spendPk.byteLength !== 32 || viewPk.byteLength !== 32) {
    throw new RangeError('spendPk and viewPk must each be 32 bytes');
  }
  if (!isCanonicalFr(spendPk)) {
    throw new Error('spendPk must be a canonical BN254 Fr scalar (< r)');
  }
  const raw = new Uint8Array(65);
  raw[0] = ADDR_VERSION_V2;
  raw.set(spendPk, 1);
  raw.set(viewPk, 33);
  return `aud1${base58Encode(raw)}`;
}

export const encodeAudrenAddress = formatAudrenAddress;

export function parseAudrenAddress(encoded: string): ParsedAudrenAddress {
  const trimmed = encoded.trim();
  if (!trimmed.startsWith('aud1')) {
    throw new Error('Audren stealth address must start with aud1');
  }
  const raw = base58Decode(trimmed.slice(4));
  if (raw.byteLength !== 65 || raw[0] !== ADDR_VERSION_V2) {
    throw new Error(`Invalid Audren address length or version (got ${raw.byteLength} bytes, v=${raw[0]})`);
  }
  const spendPk = raw.slice(1, 33);
  const viewPk = raw.slice(33, 65);
  if (!isCanonicalFr(spendPk)) {
    throw new Error('Audren address spendPk is not a canonical BN254 Fr scalar');
  }
  return { encoded: `aud1${base58Encode(raw)}`, spendPk, viewPk };
}

export const decodeAudrenAddress = parseAudrenAddress;

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

function u16le(n: number): Uint8Array {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, n, true);
  return out;
}

function u32le(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, true);
  return out;
}

function u64le(n: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, n, true);
  return out;
}

function sha256ConcatSync(parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.byteLength;
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
  if (seeds.length >= 16) {
    throw new RangeError(`Solana PDA supports at most 15 caller seeds, got ${seeds.length}`);
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

export function deriveSolVaultPdaSync(
  poolId = 0,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): DerivedPda {
  return findProgramAddressSync([utf8Encoder.encode(SOL_VAULT_SEED), u32le(poolId)], programId);
}

export async function deriveSolVaultPda(
  poolId = 0,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return deriveSolVaultPdaSync(poolId, programId);
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
  if (!Number.isInteger(laneId) || laneId < 0 || laneId >= NUM_LANES) {
    throw new RangeError(`laneId must be 0..${NUM_LANES - 1}, got ${laneId}`);
  }
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
  if (!Number.isInteger(laneId) || laneId < 0 || laneId >= NUM_LANES) {
    throw new RangeError(`laneId must be 0..${NUM_LANES - 1}, got ${laneId}`);
  }
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

export function deriveCheckpointPdaSync(
  poolId: number,
  slotIdx: number,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): DerivedPda {
  if (!Number.isInteger(slotIdx) || slotIdx < 0 || slotIdx >= CHECKPOINT_RING_SLOTS) {
    throw new RangeError(`slotIdx must be 0..${CHECKPOINT_RING_SLOTS - 1}, got ${slotIdx}`);
  }
  return findProgramAddressSync(
    [utf8Encoder.encode(CKPT_SEED), u32le(poolId), u16le(slotIdx)],
    programId,
  );
}

export async function deriveCheckpointPda(
  poolId: number,
  slotIdx: number,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): Promise<DerivedPda> {
  return deriveCheckpointPdaSync(poolId, slotIdx, programId);
}

export function deriveNullifierPdaSync(
  poolId: number,
  nullifier: Uint8Array,
  programId: string | Uint8Array = AUDREN_PROGRAM_ID,
): DerivedPda {
  if (nullifier.byteLength !== 32) {
    throw new RangeError(`nullifier must be 32 bytes, got ${nullifier.byteLength}`);
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
  if (nf0.byteLength !== 32) {
    throw new RangeError(`nf0 must be 32 bytes, got ${nf0.byteLength}`);
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
