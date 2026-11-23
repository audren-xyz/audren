/**
 * Pure TypeScript RFC 8439 ChaCha20-Poly1305 AEAD, X25519 memo encryption/decryption,
 * and dynamic XOR-masked swap memo helpers matching `crates/client/src/keys.rs` byte-for-byte.
 */

import { x25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  DYN_MEMO_HEAD_LEN,
  DYN_MEMO_MAGIC,
  MEMO_CT_LEN,
  MEMO_ENTRY_WIRE_LEN,
  NUM_ESCROW_SHARDS,
  NUM_LANES,
} from './constants.ts';
import {
  bytes32ToFrMasked,
  computeNoteCommitment,
  deriveAssetId,
  deriveStealthOwner,
  frFromBeBytesStrict,
  frToBeBytes,
} from './poseidon.ts';

const utf8Encoder = new TextEncoder();
const DYN_MAGIC_BYTES = utf8Encoder.encode(DYN_MEMO_MAGIC);

// =============================================================================
// RFC 8439 ChaCha20-Poly1305 AEAD (zero extra dependencies)
// =============================================================================

function rotl32(v: number, n: number): number {
  return ((v << n) | (v >>> (32 - n))) >>> 0;
}

function quarterRound(s: Uint32Array, a: number, b: number, c: number, d: number): void {
  s[a] = (s[a]! + s[b]!) >>> 0;
  s[d] = rotl32(s[d]! ^ s[a]!, 16);
  s[c] = (s[c]! + s[d]!) >>> 0;
  s[b] = rotl32(s[b]! ^ s[c]!, 12);
  s[a] = (s[a]! + s[b]!) >>> 0;
  s[d] = rotl32(s[d]! ^ s[a]!, 8);
  s[c] = (s[c]! + s[d]!) >>> 0;
  s[b] = rotl32(s[b]! ^ s[c]!, 7);
}

function chacha20Block(key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array {
  const kv = new DataView(key.buffer, key.byteOffset, key.byteLength);
  const nv = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  const state = new Uint32Array(16);
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) state[4 + i] = kv.getUint32(i * 4, true);
  state[12] = counter >>> 0;
  state[13] = nv.getUint32(0, true);
  state[14] = nv.getUint32(4, true);
  state[15] = nv.getUint32(8, true);

  const w = new Uint32Array(state);
  for (let i = 0; i < 10; i++) {
    quarterRound(w, 0, 4, 8, 12);
    quarterRound(w, 1, 5, 9, 13);
    quarterRound(w, 2, 6, 10, 14);
    quarterRound(w, 3, 7, 11, 15);
    quarterRound(w, 0, 5, 10, 15);
    quarterRound(w, 1, 6, 11, 12);
    quarterRound(w, 2, 7, 8, 13);
    quarterRound(w, 3, 4, 9, 14);
  }
  const out = new Uint8Array(64);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 16; i++) {
    ov.setUint32(i * 4, (w[i]! + state[i]!) >>> 0, true);
  }
  return out;
}

function chacha20Xor(
  key: Uint8Array,
  counter: number,
  nonce: Uint8Array,
  input: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(input.byteLength);
  let blockCounter = counter;
  for (let off = 0; off < input.byteLength; off += 64) {
    const ks = chacha20Block(key, blockCounter++, nonce);
    const n = Math.min(64, input.byteLength - off);
    for (let i = 0; i < n; i++) {
      out[off + i] = input[off + i]! ^ ks[i]!;
    }
  }
  return out;
}

const POLY1305_P = (1n << 130n) - 5n;

function bytesToLeBigInt(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (let i = bytes.byteLength - 1; i >= 0; i--) {
    acc = (acc << 8n) | BigInt(bytes[i]!);
  }
  return acc;
}

function poly1305Mac(msg: Uint8Array, otk32: Uint8Array): Uint8Array {
  const rBytes = new Uint8Array(otk32.subarray(0, 16));
  rBytes[3] = rBytes[3]! & 15;
  rBytes[7] = rBytes[7]! & 15;
  rBytes[11] = rBytes[11]! & 15;
  rBytes[15] = rBytes[15]! & 15;
  rBytes[4] = rBytes[4]! & 252;
  rBytes[8] = rBytes[8]! & 252;
  rBytes[12] = rBytes[12]! & 252;
  const r = bytesToLeBigInt(rBytes);
  const s = bytesToLeBigInt(otk32.subarray(16, 32));

  let acc = 0n;
  for (let off = 0; off < msg.byteLength; off += 16) {
    const chunk = msg.subarray(off, Math.min(off + 16, msg.byteLength));
    const n = bytesToLeBigInt(chunk) | (1n << BigInt(chunk.byteLength * 8));
    acc = ((acc + n) * r) % POLY1305_P;
  }
  const tagVal = (acc + s) & ((1n << 128n) - 1n);
  const tag = new Uint8Array(16);
  let t = tagVal;
  for (let i = 0; i < 16; i++) {
    tag[i] = Number(t & 0xffn);
    t >>= 8n;
  }
  return tag;
}

function buildPoly1305Input(aad: Uint8Array, ct: Uint8Array): Uint8Array {
  const padAad = (16 - (aad.byteLength % 16)) % 16;
  const padCt = (16 - (ct.byteLength % 16)) % 16;
  const buf = new Uint8Array(aad.byteLength + padAad + ct.byteLength + padCt + 16);
  let off = 0;
  buf.set(aad, off);
  off += aad.byteLength + padAad;
  buf.set(ct, off);
  off += ct.byteLength + padCt;
  const dv = new DataView(buf.buffer);
  dv.setBigUint64(off, BigInt(aad.byteLength), true);
  dv.setBigUint64(off + 8, BigInt(ct.byteLength), true);
  return buf;
}

export function chacha20Poly1305Encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  const otk = chacha20Block(key, 0, nonce).subarray(0, 32);
  const ct = chacha20Xor(key, 1, nonce, plaintext);
  const tag = poly1305Mac(buildPoly1305Input(aad, ct), otk);
  const out = new Uint8Array(ct.byteLength + 16);
  out.set(ct, 0);
  out.set(tag, ct.byteLength);
  return out;
}

export function chacha20Poly1305Decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertextWithTag: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
): Uint8Array | null {
  if (ciphertextWithTag.byteLength < 16) return null;
  const ctLen = ciphertextWithTag.byteLength - 16;
  const ct = ciphertextWithTag.subarray(0, ctLen);
  const tag = ciphertextWithTag.subarray(ctLen);
  const otk = chacha20Block(key, 0, nonce).subarray(0, 32);
  const expected = poly1305Mac(buildPoly1305Input(aad, ct), otk);
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= tag[i]! ^ expected[i]!;
  if (diff !== 0) return null;
  return chacha20Xor(key, 1, nonce, ct);
}

// =============================================================================
// Audren 90-Byte Compact SoA Note Memos
// =============================================================================

export interface DecryptedMemo {
  tweak: bigint;
  blinding: bigint;
  amount: bigint;
  mint: Uint8Array;
  isDynamic: boolean;
}

export interface MemoVerificationFvk {
  spendPk: Uint8Array;
  viewSk: Uint8Array;
}

function sha256Labeled(label: string, data: Uint8Array): Uint8Array {
  const lb = utf8Encoder.encode(label);
  const buf = new Uint8Array(lb.byteLength + data.byteLength);
  buf.set(lb, 0);
  buf.set(data, lb.byteLength);
  return sha256(buf);
}

function deriveMemoSecrets(shared: Uint8Array): {
  viewTag: Uint8Array;
  aeadKey: Uint8Array;
  nonce: Uint8Array;
  tweak: bigint;
  blinding: bigint;
  dynMask: Uint8Array;
} {
  const vtRaw = sha256Labeled('audren/v2/vt', shared);
  const viewTag = vtRaw.slice(0, 2);
  const aeadKey = sha256Labeled('audren/v2/aead_key', shared);
  const nonce = sha256Labeled('audren/v2/aead_nonce', shared).slice(0, 12);
  const tweak = bytes32ToFrMasked(sha256Labeled('audren/v2/tweak', shared));
  const blinding = bytes32ToFrMasked(sha256Labeled('audren/v2/blinding', shared));
  const m0 = sha256Labeled('audren/v2/dyn_mask0', shared);
  const m1 = sha256Labeled('audren/v2/dyn_mask1', shared);
  const dynMask = new Uint8Array(MEMO_CT_LEN);
  dynMask.set(m0, 0);
  dynMask.set(m1.subarray(0, 24), 32);
  return { viewTag, aeadKey, nonce, tweak, blinding, dynMask };
}

/**
 * Encrypt a compact `90 B` SoA note memo (`view_tag[2] || epk[32] || ct[56]`).
 * Returns `{ tweak, blinding, memo90 }`.
 */
export function encryptNoteMemo(
  recipientViewPk: Uint8Array,
  ephSecret32: Uint8Array,
  amount: bigint,
  mint32: Uint8Array,
): { tweak: bigint; blinding: bigint; memo90: Uint8Array } {
  if (recipientViewPk.byteLength !== 32 || ephSecret32.byteLength !== 32 || mint32.byteLength !== 32) {
    throw new RangeError('recipientViewPk, ephSecret32, and mint32 must be 32 bytes');
  }
  const ephPub = x25519.getPublicKey(ephSecret32);
  const shared = x25519.getSharedSecret(ephSecret32, recipientViewPk);
  const { viewTag, aeadKey, nonce, tweak, blinding } = deriveMemoSecrets(shared);

  const plain = new Uint8Array(40);
  new DataView(plain.buffer).setBigUint64(0, amount, true);
  plain.set(mint32, 8);
  const ct = chacha20Poly1305Encrypt(aeadKey, nonce, plain);

  const memo90 = new Uint8Array(MEMO_ENTRY_WIRE_LEN);
  memo90.set(viewTag, 0);
  memo90.set(ephPub, 2);
  memo90.set(ct, 34);
  return { tweak, blinding, memo90 };
}

/**
 * Prepare XOR-masked `AUD2DYN2` dynamic swap memo parameters for `ExecViaEscrow`.
 */
export function prepareDynamicSwapMemo(
  recipientViewPk: Uint8Array,
  ephSecret32: Uint8Array,
): { tweak: bigint; blinding: bigint; dynHead34: Uint8Array; dynMask56: Uint8Array } {
  if (recipientViewPk.byteLength !== 32 || ephSecret32.byteLength !== 32) {
    throw new RangeError('recipientViewPk and ephSecret32 must be 32 bytes');
  }
  const ephPub = x25519.getPublicKey(ephSecret32);
  const shared = x25519.getSharedSecret(ephSecret32, recipientViewPk);
  const { viewTag, tweak, blinding, dynMask } = deriveMemoSecrets(shared);

  const dynHead34 = new Uint8Array(DYN_MEMO_HEAD_LEN);
  dynHead34.set(viewTag, 0);
  dynHead34.set(ephPub, 2);
  return { tweak, blinding, dynHead34, dynMask56: dynMask };
}

/**
 * Decrypt or unmask a `90 B` `MemoPage` entry AND mandatorily verify
 * `computeNoteCommitment(stealthOwner, deriveAssetId(mint), amount, blinding) == onchainCmBe`.
 */
export function tryDecryptAndVerifyMemoEntry(
  fvk: MemoVerificationFvk,
  viewTag: Uint8Array,
  epk: Uint8Array,
  ct56: Uint8Array,
  onchainCmBe: Uint8Array,
): DecryptedMemo | null {
  if (
    viewTag.byteLength !== 2 ||
    epk.byteLength !== 32 ||
    ct56.byteLength !== MEMO_CT_LEN ||
    onchainCmBe.byteLength !== 32
  ) {
    return null;
  }
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(fvk.viewSk, epk);
  } catch {
    // Low-order / all-zero ephemeral pubkey in an unrelated or adversarial memo slot
    return null;
  }
  const { viewTag: expVt, aeadKey, nonce, tweak, blinding, dynMask } = deriveMemoSecrets(shared);
  if (expVt[0] !== viewTag[0] || expVt[1] !== viewTag[1]) {
    return null;
  }

  let candidate: DecryptedMemo | null = null;
  const plain = chacha20Poly1305Decrypt(aeadKey, nonce, ct56);
  if (plain && plain.byteLength === 40) {
    const dv = new DataView(plain.buffer, plain.byteOffset, plain.byteLength);
    candidate = {
      tweak,
      blinding,
      amount: dv.getBigUint64(0, true),
      mint: plain.slice(8, 40),
      isDynamic: false,
    };
  } else {
    const unmasked = new Uint8Array(MEMO_CT_LEN);
    for (let i = 0; i < MEMO_CT_LEN; i++) {
      unmasked[i] = ct56[i]! ^ dynMask[i]!;
    }
    let magicOk = true;
    for (let i = 0; i < 8; i++) {
      if (unmasked[i] !== DYN_MAGIC_BYTES[i]) {
        magicOk = false;
        break;
      }
    }
    if (magicOk) {
      const dv = new DataView(unmasked.buffer);
      candidate = {
        tweak,
        blinding,
        amount: dv.getBigUint64(8, true),
        mint: unmasked.slice(16, 48),
        isDynamic: true,
      };
    }
  }
  if (!candidate) return null;

  let spendPkFr: bigint;
  try {
    spendPkFr = frFromBeBytesStrict(fvk.spendPk);
  } catch {
    return null;
  }
  const stealth = deriveStealthOwner(spendPkFr, candidate.tweak);
  const assetId = deriveAssetId(candidate.mint);
  const expectedCm = frToBeBytes(
    computeNoteCommitment(stealth, assetId, candidate.amount, candidate.blinding),
  );
  for (let i = 0; i < 32; i++) {
    if (expectedCm[i] !== onchainCmBe[i]) return null;
  }
  return candidate;
}

/**
 * Fast X25519 + 2-byte view-tag prefilter for SoA `MemoPage` `dataSlice` scanning
 * (`1 / 65,536` false-positive rate; zero ciphertext bytes required).
 */
export function checkMemoViewTag(
  viewSk: Uint8Array,
  viewTag: Uint8Array,
  epk: Uint8Array,
): boolean {
  if (viewSk.byteLength !== 32 || viewTag.byteLength !== 2 || epk.byteLength !== 32) {
    return false;
  }
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(viewSk, epk);
  } catch {
    return false;
  }
  const expVt = sha256Labeled('audren/v2/vt', shared);
  return expVt[0] === viewTag[0] && expVt[1] === viewTag[1];
}

function randomUniformInt(bound: number): number {
  if (!Number.isInteger(bound) || bound <= 0) {
    throw new RangeError(`bound must be a positive integer, got ${bound}`);
  }
  if (bound === 1) return 0;
  // Unbiased rejection sampling over uint32 using CSPRNG (`crypto.getRandomValues`).
  const maxUnbiased = Math.floor(0x1_0000_0000 / bound) * bound;
  const buf = new Uint32Array(1);
  for (;;) {
    globalThis.crypto.getRandomValues(buf);
    const v = buf[0]!;
    if (v < maxUnbiased) return v % bound;
  }
}

/**
 * Sample an unbiased uniform output lane ID in `0..activeLanes`, strictly independent of input notes.
 */
export function pickRandomLaneId(activeLanes: number): number {
  if (!Number.isInteger(activeLanes) || activeLanes < 1 || activeLanes > NUM_LANES) {
    throw new RangeError(`activeLanes must be an integer in 1..=${NUM_LANES}, got ${activeLanes}`);
  }
  return randomUniformInt(activeLanes);
}

/**
 * Sample an unbiased uniform `ExecViaEscrow` shard ID in `0..numShards`, strictly independent of input notes.
 */
export function pickRandomEscrowShard(numShards: number = NUM_ESCROW_SHARDS): number {
  if (!Number.isInteger(numShards) || numShards < 1 || numShards > NUM_ESCROW_SHARDS) {
    throw new RangeError(
      `numShards must be an integer in 1..=${NUM_ESCROW_SHARDS}, got ${numShards}`,
    );
  }
  return randomUniformInt(numShards);
}

/** Convenience wrapper accepting a single 90-byte wire memo slice. */
export function tryDecryptAndVerifyMemo90(
  fvk: MemoVerificationFvk,
  memo90: Uint8Array,
  onchainCmBe: Uint8Array,
): DecryptedMemo | null {
  if (memo90.byteLength !== MEMO_ENTRY_WIRE_LEN) return null;
  return tryDecryptAndVerifyMemoEntry(
    fvk,
    memo90.subarray(0, 2),
    memo90.subarray(2, 34),
    memo90.subarray(34, 90),
    onchainCmBe,
  );
}
