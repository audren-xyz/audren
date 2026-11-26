/**
 * Pure TypeScript RFC 8439 ChaCha20-Poly1305 AEAD, X25519 low-order-safe versioned
 * `106 B` SoA note memo encryption/decryption (with `34 B` AEAD AAD + `14 B` `paymentId`),
 * and domain-separated `72 B` `AUD1DYN1` XOR-masked dynamic swap memo helpers matching
 * `crates/client/src/keys.rs` byte-for-byte.
 */

import { x25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  DYN_MEMO_HEAD_LEN,
  DYN_MEMO_MAGIC,
  KDF_DOMAIN_BLIND,
  KDF_DOMAIN_DYN_BLIND,
  KDF_DOMAIN_DYN_MASK,
  KDF_DOMAIN_DYN_TWEAK,
  KDF_DOMAIN_MEMO_KEY,
  KDF_DOMAIN_MEMO_NONCE,
  KDF_DOMAIN_TWEAK,
  KDF_DOMAIN_VIEW_TAG,
  MEMO_CT_LEN,
  MEMO_ENTRY_WIRE_LEN,
  MEMO_PAYMENT_ID_LEN,
  MEMO_PLAINTEXT_LEN,
  MEMO_VERSION_V1,
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
const DYN_MASK_LABEL_BYTES = utf8Encoder.encode(KDF_DOMAIN_DYN_MASK);
const U64_MAX = 0xffff_ffff_ffff_ffffn;

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
  if (!(key instanceof Uint8Array) || key.byteLength !== 32) {
    throw new RangeError(
      `ChaCha20-Poly1305 key must be 32-byte Uint8Array, got ${key instanceof Uint8Array ? key.byteLength : String(key)}`,
    );
  }
  if (!(nonce instanceof Uint8Array) || nonce.byteLength !== 12) {
    throw new RangeError(
      `ChaCha20-Poly1305 nonce must be 12-byte Uint8Array, got ${nonce instanceof Uint8Array ? nonce.byteLength : String(nonce)}`,
    );
  }
  if (!(plaintext instanceof Uint8Array)) {
    throw new RangeError('ChaCha20-Poly1305 plaintext must be a Uint8Array');
  }
  if (!(aad instanceof Uint8Array)) {
    throw new RangeError('ChaCha20-Poly1305 aad must be a Uint8Array');
  }
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
  if (!(key instanceof Uint8Array) || key.byteLength !== 32) {
    throw new RangeError(
      `ChaCha20-Poly1305 key must be 32-byte Uint8Array, got ${key instanceof Uint8Array ? key.byteLength : String(key)}`,
    );
  }
  if (!(nonce instanceof Uint8Array) || nonce.byteLength !== 12) {
    throw new RangeError(
      `ChaCha20-Poly1305 nonce must be 12-byte Uint8Array, got ${nonce instanceof Uint8Array ? nonce.byteLength : String(nonce)}`,
    );
  }
  if (
    !(ciphertextWithTag instanceof Uint8Array) ||
    ciphertextWithTag.byteLength < 16 ||
    !(aad instanceof Uint8Array)
  ) {
    return null;
  }
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
// Audren v1 Versioned 106-Byte SoA Note Memos (72 B Ciphertext + 34 B AAD)
// =============================================================================

export interface DecryptedMemo {
  tweak: bigint;
  blinding: bigint;
  amount: bigint;
  mint: Uint8Array;
  memoVersion: number;
  memoFlags: number;
  paymentId: Uint8Array;
  isDynamic: boolean;
}

export interface MemoVerificationFvk {
  spendPk: Uint8Array;
  viewSk: Uint8Array;
}

function isAllZero32(bytes: Uint8Array): boolean {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 32) return true;
  let acc = 0;
  for (let i = 0; i < 32; i++) acc |= bytes[i]!;
  return acc === 0;
}

function computeContributorySharedSecret(secret32: Uint8Array, public32: Uint8Array): Uint8Array | null {
  if (
    !(secret32 instanceof Uint8Array) ||
    secret32.byteLength !== 32 ||
    !(public32 instanceof Uint8Array) ||
    public32.byteLength !== 32
  ) {
    return null;
  }
  if (isAllZero32(public32)) {
    return null;
  }
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(secret32, public32);
  } catch {
    return null;
  }
  if (isAllZero32(shared)) {
    return null;
  }
  return shared;
}

function sha256Labeled(label: string, data: Uint8Array): Uint8Array {
  if (!(data instanceof Uint8Array)) {
    throw new RangeError(`sha256Labeled data must be a Uint8Array, got ${String(data)}`);
  }
  const lb = utf8Encoder.encode(label);
  const buf = new Uint8Array(lb.byteLength + data.byteLength);
  buf.set(lb, 0);
  buf.set(data, lb.byteLength);
  return sha256(buf);
}

function deriveDynMask72(shared: Uint8Array): Uint8Array {
  if (!(shared instanceof Uint8Array) || shared.byteLength !== 32) {
    throw new RangeError('shared secret must be a 32-byte Uint8Array');
  }
  const buf = new Uint8Array(DYN_MASK_LABEL_BYTES.byteLength + 32 + 1);
  buf.set(DYN_MASK_LABEL_BYTES, 0);
  buf.set(shared, DYN_MASK_LABEL_BYTES.byteLength);
  const out = new Uint8Array(MEMO_CT_LEN);
  buf[DYN_MASK_LABEL_BYTES.byteLength + 32] = 0;
  out.set(sha256(buf), 0);
  buf[DYN_MASK_LABEL_BYTES.byteLength + 32] = 1;
  out.set(sha256(buf), 32);
  buf[DYN_MASK_LABEL_BYTES.byteLength + 32] = 2;
  out.set(sha256(buf).subarray(0, 8), 64);
  return out;
}

function deriveMemoSecrets(shared: Uint8Array): {
  viewTag: Uint8Array;
  aeadKey: Uint8Array;
  nonce: Uint8Array;
  tweak: bigint;
  blinding: bigint;
  dynTweak: bigint;
  dynBlinding: bigint;
  dynMask72: Uint8Array;
} {
  const viewTag = sha256Labeled(KDF_DOMAIN_VIEW_TAG, shared).slice(0, 2);
  const aeadKey = sha256Labeled(KDF_DOMAIN_MEMO_KEY, shared);
  const nonce = sha256Labeled(KDF_DOMAIN_MEMO_NONCE, shared).slice(0, 12);
  const tweak = bytes32ToFrMasked(sha256Labeled(KDF_DOMAIN_TWEAK, shared));
  const blinding = bytes32ToFrMasked(sha256Labeled(KDF_DOMAIN_BLIND, shared));
  const dynTweak = bytes32ToFrMasked(sha256Labeled(KDF_DOMAIN_DYN_TWEAK, shared));
  const dynBlinding = bytes32ToFrMasked(sha256Labeled(KDF_DOMAIN_DYN_BLIND, shared));
  const dynMask72 = deriveDynMask72(shared);
  return { viewTag, aeadKey, nonce, tweak, blinding, dynTweak, dynBlinding, dynMask72 };
}

/**
 * Encrypt a versioned `106 B` SoA note memo (`view_tag[2] || epk[32] || ct[72]`) with
 * `34 B` AEAD AAD (`view_tag[2] || epk[32]`) and `56 B` plaintext
 * (`amount_le[8] || mint[32] || memo_ver[1](1) || memo_flags[1](0) || payment_id[14]`).
 *
 * Rejects low-order X25519 recipient public keys (non-contributory all-zero shared secret).
 */
export function encryptNoteMemo(
  recipientViewPk: Uint8Array,
  ephSecret32: Uint8Array,
  amount: bigint,
  mint32: Uint8Array,
  paymentId?: Uint8Array,
): { tweak: bigint; blinding: bigint; memo: Uint8Array } {
  if (
    !(recipientViewPk instanceof Uint8Array) ||
    recipientViewPk.byteLength !== 32 ||
    !(ephSecret32 instanceof Uint8Array) ||
    ephSecret32.byteLength !== 32 ||
    !(mint32 instanceof Uint8Array) ||
    mint32.byteLength !== 32
  ) {
    throw new RangeError('recipientViewPk, ephSecret32, and mint32 must be 32-byte Uint8Arrays');
  }
  if (typeof amount !== 'bigint' || amount < 0n || amount > U64_MAX) {
    throw new RangeError(`amount must be a u64 bigint in 0..=2^64-1, got ${String(amount)}`);
  }
  if (
    paymentId !== undefined &&
    (!(paymentId instanceof Uint8Array) || paymentId.byteLength !== MEMO_PAYMENT_ID_LEN)
  ) {
    throw new RangeError(
      `paymentId must be a ${MEMO_PAYMENT_ID_LEN}-byte Uint8Array, got ${paymentId instanceof Uint8Array ? paymentId.byteLength : String(paymentId)}`,
    );
  }
  const ephPub = x25519.getPublicKey(ephSecret32);
  const shared = computeContributorySharedSecret(ephSecret32, recipientViewPk);
  if (!shared) {
    throw new Error('Low-order X25519 recipientViewPk (non-contributory shared secret)');
  }
  const { viewTag, aeadKey, nonce, tweak, blinding } = deriveMemoSecrets(shared);

  const aad = new Uint8Array(DYN_MEMO_HEAD_LEN);
  aad.set(viewTag, 0);
  aad.set(ephPub, 2);

  const plain = new Uint8Array(MEMO_PLAINTEXT_LEN);
  new DataView(plain.buffer).setBigUint64(0, amount, true);
  plain.set(mint32, 8);
  plain[40] = MEMO_VERSION_V1;
  plain[41] = 0;
  if (paymentId) {
    plain.set(paymentId, 42);
  }
  const ct72 = chacha20Poly1305Encrypt(aeadKey, nonce, plain, aad);

  const memo = new Uint8Array(MEMO_ENTRY_WIRE_LEN);
  memo.set(aad, 0);
  memo.set(ct72, DYN_MEMO_HEAD_LEN);
  return { tweak, blinding, memo };
}

/**
 * Prepare domain-separated XOR-masked `72 B` `AUD1DYN1` dynamic swap memo parameters for
 * `ExecViaEscrow`. Rejects low-order X25519 recipient public keys.
 */
export function prepareDynamicSwapMemo(
  recipientViewPk: Uint8Array,
  ephSecret32: Uint8Array,
): { tweak: bigint; blinding: bigint; dynHead34: Uint8Array; dynMask72: Uint8Array } {
  if (
    !(recipientViewPk instanceof Uint8Array) ||
    recipientViewPk.byteLength !== 32 ||
    !(ephSecret32 instanceof Uint8Array) ||
    ephSecret32.byteLength !== 32
  ) {
    throw new RangeError('recipientViewPk and ephSecret32 must be 32-byte Uint8Arrays');
  }
  const ephPub = x25519.getPublicKey(ephSecret32);
  const shared = computeContributorySharedSecret(ephSecret32, recipientViewPk);
  if (!shared) {
    throw new Error('Low-order X25519 recipientViewPk (non-contributory shared secret)');
  }
  const { viewTag, dynTweak, dynBlinding, dynMask72 } = deriveMemoSecrets(shared);

  const dynHead34 = new Uint8Array(DYN_MEMO_HEAD_LEN);
  dynHead34.set(viewTag, 0);
  dynHead34.set(ephPub, 2);
  return { tweak: dynTweak, blinding: dynBlinding, dynHead34, dynMask72 };
}

const KDF_DOMAIN_HIT_DEDUP = 'audren/v1/hit_dedup';

function decryptMemoPayloadInternal(
  viewSk: Uint8Array,
  viewTag: Uint8Array,
  epk: Uint8Array,
  ct72: Uint8Array,
): { memo: DecryptedMemo; dedupTag: Uint8Array } | null {
  if (
    !(viewSk instanceof Uint8Array) ||
    viewSk.byteLength !== 32 ||
    !(viewTag instanceof Uint8Array) ||
    viewTag.byteLength !== 2 ||
    !(epk instanceof Uint8Array) ||
    epk.byteLength !== 32 ||
    !(ct72 instanceof Uint8Array) ||
    ct72.byteLength !== MEMO_CT_LEN
  ) {
    return null;
  }
  const shared = computeContributorySharedSecret(viewSk, epk);
  if (!shared) {
    return null;
  }
  const {
    viewTag: expVt,
    aeadKey,
    nonce,
    tweak,
    blinding,
    dynTweak,
    dynBlinding,
    dynMask72,
  } = deriveMemoSecrets(shared);
  if (expVt[0] !== viewTag[0] || expVt[1] !== viewTag[1]) {
    shared.fill(0);
    return null;
  }

  const aad = new Uint8Array(DYN_MEMO_HEAD_LEN);
  aad.set(viewTag, 0);
  aad.set(epk, 2);

  let memo: DecryptedMemo | null = null;
  const plain = chacha20Poly1305Decrypt(aeadKey, nonce, ct72, aad);
  if (plain && plain.byteLength === MEMO_PLAINTEXT_LEN && plain[40] === MEMO_VERSION_V1) {
    const dv = new DataView(plain.buffer, plain.byteOffset, plain.byteLength);
    memo = {
      tweak,
      blinding,
      amount: dv.getBigUint64(0, true),
      mint: plain.slice(8, 40),
      memoVersion: plain[40]!,
      memoFlags: plain[41]!,
      paymentId: plain.slice(42, 42 + MEMO_PAYMENT_ID_LEN),
      isDynamic: false,
    };
  } else {
    const unmasked = new Uint8Array(MEMO_CT_LEN);
    for (let i = 0; i < MEMO_CT_LEN; i++) {
      unmasked[i] = ct72[i]! ^ dynMask72[i]!;
    }
    let magicOk = true;
    for (let i = 0; i < 8; i++) {
      if (unmasked[i] !== DYN_MAGIC_BYTES[i]) {
        magicOk = false;
        break;
      }
    }
    let paddingOk = magicOk;
    if (paddingOk) {
      let padOr = 0;
      for (let i = 48; i < MEMO_CT_LEN; i++) {
        padOr |= unmasked[i]!;
      }
      paddingOk = padOr === 0;
    }
    if (paddingOk) {
      const dv = new DataView(unmasked.buffer);
      memo = {
        tweak: dynTweak,
        blinding: dynBlinding,
        amount: dv.getBigUint64(8, true),
        mint: unmasked.slice(16, 48),
        memoVersion: MEMO_VERSION_V1,
        memoFlags: 0,
        paymentId: new Uint8Array(MEMO_PAYMENT_ID_LEN),
        isDynamic: true,
      };
    }
    unmasked.fill(0);
  }
  if (!memo) {
    shared.fill(0);
    return null;
  }
  // Key cross-subtree Pass 1D hit deduplication on the X25519 shared secret (domain-separated)
  // so all 16 Curve25519 torsion + bit-255 + non-canonical `epk` equivalents for `AUD1DYN1`
  // dynamic swap memos collapse into a single deduplication entry.
  const dedupTag = sha256Labeled(KDF_DOMAIN_HIT_DEDUP, shared);
  shared.fill(0);
  return { memo, dedupTag };
}

const PUBLIC_CANON_EPK_SCALAR = new Uint8Array(32);
PUBLIC_CANON_EPK_SCALAR[0] = 0x08;
PUBLIC_CANON_EPK_SCALAR[31] = 0x40;

/**
 * Public, key-independent canonicalization of a Curve25519 ephemeral public key modulo cofactor 8
 * and bit-255 / `u + p` non-canonicality (matches Rust `canonicalize_public_epk` bit-for-bit).
 * Returns `null` for all-zero and all 12 low-order points (curve + twist).
 */
export function canonicalizePublicEpk(epk: Uint8Array): Uint8Array | null {
  return computeContributorySharedSecret(PUBLIC_CANON_EPK_SCALAR, epk);
}

/**
 * AEAD / `AUD1DYN1` pre-filter for full `MemoPage` scans (`'strict'` mode): returns a domain-
 * separated `32 B` deduplication tag `SHA256("audren/v1/hit_dedup" || shared)` (collapsing all 16
 * Curve25519 torsion + bit-255 `epk` equivalents) iff the payload decrypts/unmasks cleanly, or
 * `null` otherwise, without exposing any unverified note plaintext or raw shared secret.
 */
export function computeMemoScanDedupTag(
  viewSk: Uint8Array,
  viewTag: Uint8Array,
  epk: Uint8Array,
  ct72: Uint8Array,
): Uint8Array | null {
  return decryptMemoPayloadInternal(viewSk, viewTag, epk, ct72)?.dedupTag ?? null;
}

/**
 * Boolean-only AEAD / `AUD1DYN1` pre-filter for full `MemoPage` scans (`Strict` mode):
 * rejects random `1/65536` `viewTag` false positives and `(viewTag, epk, junkCt)` probes before
 * Pass 1D scheduling without exposing any unverified note plaintext.
 */
export function checkMemoPayloadForScan(
  viewSk: Uint8Array,
  viewTag: Uint8Array,
  epk: Uint8Array,
  ct72: Uint8Array,
): boolean {
  return computeMemoScanDedupTag(viewSk, viewTag, epk, ct72) !== null;
}

/**
 * Decrypt or unmask a `106 B` `MemoPage` entry (`viewTag[2]`, `epk[32]`, `ct72[72]`) AND
 * mandatorily verify `computeNoteCommitment(stealthOwner, deriveAssetId(mint), amount, blinding) == onchainCmBe`.
 * Rejects low-order X25519 ephemeral keys, tampered AEAD AAD, non-v1 static memo versions,
 * and non-zero trailing padding bytes on `AUD1DYN1` dynamic swap memos.
 */
export function tryDecryptAndVerifyMemoEntry(
  fvk: MemoVerificationFvk,
  viewTag: Uint8Array,
  epk: Uint8Array,
  ct72: Uint8Array,
  onchainCmBe: Uint8Array,
): DecryptedMemo | null {
  if (
    !fvk ||
    typeof fvk !== 'object' ||
    !(fvk.viewSk instanceof Uint8Array) ||
    fvk.viewSk.byteLength !== 32 ||
    !(fvk.spendPk instanceof Uint8Array) ||
    fvk.spendPk.byteLength !== 32 ||
    !(onchainCmBe instanceof Uint8Array) ||
    onchainCmBe.byteLength !== 32
  ) {
    return null;
  }
  const decoded = decryptMemoPayloadInternal(fvk.viewSk, viewTag, epk, ct72);
  if (!decoded) return null;
  const candidate = decoded.memo;

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
  let cmDiff = 0;
  for (let i = 0; i < 32; i++) {
    cmDiff |= expectedCm[i]! ^ onchainCmBe[i]!;
  }
  if (cmDiff !== 0) return null;
  return candidate;
}

/**
 * Fast X25519 + 2-byte view-tag prefilter for SoA `MemoPage` scanning
 * (`1 / 65,536` false-positive rate; rejects low-order X25519 ephemeral keys).
 */
export function checkMemoViewTag(
  viewSk: Uint8Array,
  viewTag: Uint8Array,
  epk: Uint8Array,
): boolean {
  if (
    !(viewSk instanceof Uint8Array) ||
    viewSk.byteLength !== 32 ||
    !(viewTag instanceof Uint8Array) ||
    viewTag.byteLength !== 2 ||
    !(epk instanceof Uint8Array) ||
    epk.byteLength !== 32
  ) {
    return false;
  }
  const shared = computeContributorySharedSecret(viewSk, epk);
  if (!shared) {
    return false;
  }
  const expVt = sha256Labeled(KDF_DOMAIN_VIEW_TAG, shared);
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

/** Convenience wrapper accepting a single 106-byte wire memo slice. */
export function tryDecryptAndVerifyMemo(
  fvk: MemoVerificationFvk,
  memo: Uint8Array,
  onchainCmBe: Uint8Array,
): DecryptedMemo | null {
  if (!(memo instanceof Uint8Array) || memo.byteLength !== MEMO_ENTRY_WIRE_LEN) return null;
  return tryDecryptAndVerifyMemoEntry(
    fvk,
    memo.subarray(0, 2),
    memo.subarray(2, 34),
    memo.subarray(34, MEMO_ENTRY_WIRE_LEN),
    onchainCmBe,
  );
}
