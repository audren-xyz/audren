/**
 * Canonical Audren key derivation, Mode 1 `SelectiveDisclosureProof`,
 * Mode 2 read-only `FullViewingKey` (`spendPk`, `nk`, `viewSk`, `viewPk`),
 * and deterministic `DefiSessionKeypair` matching `crates/client/src/keys.rs` byte-for-byte.
 */

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { NUM_LANES } from './constants.ts';
import { base58Encode, formatAudrenAddress } from './pda.ts';
import {
  bytes32ToFrMasked,
  computeNoteCommitment,
  computeRealNullifier,
  deriveAssetId,
  deriveNullifierKey,
  deriveSpendPk,
  deriveStealthOwner,
  frFromBeBytesStrict,
  frToBeBytes,
} from './poseidon.ts';

const utf8Encoder = new TextEncoder();
const U32_MAX = 0xffff_ffff;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

export interface AudrenKeys {
  spendSk: bigint;
  spendSkBytes: Uint8Array;
  spendPk: bigint;
  spendPkBytes: Uint8Array;
  nk: bigint;
  nkBytes: Uint8Array;
  viewSk: Uint8Array;
  viewPk: Uint8Array;
  address: string;
}

export interface FullViewingKey {
  spendPk: Uint8Array;
  nk: Uint8Array;
  viewSk: Uint8Array;
  viewPk: Uint8Array;
}

/**
 * Deterministic Solana Ed25519 keypair for stateful account-bound DeFi protocols
 * (borrowing, perp margin, CLMM positions).
 *
 * **Privacy boundary:** Each `sessionIndex` is a pseudonymous Solana wallet unlinkable to the
 * user's primary public wallet or other sessions when funded via relayed `Transact` Withdraw
 * and swept back via zero-dust `Deposit` (`DEPOSIT_FLAG_NATIVE_SOL | DEPOSIT_FLAG_FEE_FROM_AMOUNT`).
 * All positions and transactions executed BY that session wallet on external DeFi protocols remain
 * public on Solana.
 */
export interface DefiSessionKeypair {
  sessionIndex: number;
  secretSeed: Uint8Array;
  pubkey: Uint8Array;
  pubkeyBase58: string;
}

export interface SelectiveDisclosureProof {
  poolId: number;
  laneId: number;
  leafIndex: bigint;
  stealthOwner: Uint8Array;
  mint: Uint8Array;
  amount: bigint;
  blinding: Uint8Array;
  commitment: Uint8Array;
}

function u32le(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > U32_MAX) {
    throw new RangeError(`u32 value out of range (expected 0..=${U32_MAX}), got ${n}`);
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, true);
  return out;
}

export function deriveKeysFromSeed(seed32: Uint8Array): AudrenKeys {
  if (!(seed32 instanceof Uint8Array) || seed32.byteLength !== 32) {
    throw new RangeError(
      `Master seed must be 32 bytes (Uint8Array), got ${seed32 instanceof Uint8Array ? seed32.byteLength : String(seed32)}`,
    );
  }
  const salt = utf8Encoder.encode('audren/v1/root');
  const spendRaw = hkdf(sha256, seed32, salt, utf8Encoder.encode('audren/v1/spend_sk'), 32);
  const spendSk = bytes32ToFrMasked(spendRaw);
  const spendPk = deriveSpendPk(spendSk);
  const nk = deriveNullifierKey(spendSk);

  const viewSk = hkdf(sha256, seed32, salt, utf8Encoder.encode('audren/v1/view_sk'), 32);
  const viewPk = x25519.getPublicKey(viewSk);

  const spendSkBytes = frToBeBytes(spendSk);
  const spendPkBytes = frToBeBytes(spendPk);
  const nkBytes = frToBeBytes(nk);
  const address = formatAudrenAddress(spendPkBytes, viewPk);

  return {
    spendSk,
    spendSkBytes,
    spendPk,
    spendPkBytes,
    nk,
    nkBytes,
    viewSk,
    viewPk,
    address,
  };
}

export function deriveSubaccountKeys(masterSeed32: Uint8Array, accountIndex: number): AudrenKeys {
  if (!(masterSeed32 instanceof Uint8Array) || masterSeed32.byteLength !== 32) {
    throw new RangeError(
      `Master seed must be 32 bytes (Uint8Array), got ${masterSeed32 instanceof Uint8Array ? masterSeed32.byteLength : String(masterSeed32)}`,
    );
  }
  if (!Number.isInteger(accountIndex) || accountIndex < 0 || accountIndex > U32_MAX) {
    throw new RangeError(`accountIndex must be a u32 integer in 0..=${U32_MAX}, got ${accountIndex}`);
  }
  if (accountIndex === 0) return deriveKeysFromSeed(masterSeed32);
  const child = hkdf(
    sha256,
    masterSeed32,
    utf8Encoder.encode('audren/v1/subaccount'),
    u32le(accountIndex),
    32,
  );
  return deriveKeysFromSeed(child);
}

export function exportFullViewingKey(keys: AudrenKeys): FullViewingKey {
  if (
    !keys ||
    typeof keys !== 'object' ||
    !(keys.spendPkBytes instanceof Uint8Array) ||
    keys.spendPkBytes.byteLength !== 32 ||
    !(keys.nkBytes instanceof Uint8Array) ||
    keys.nkBytes.byteLength !== 32 ||
    !(keys.viewSk instanceof Uint8Array) ||
    keys.viewSk.byteLength !== 32 ||
    !(keys.viewPk instanceof Uint8Array) ||
    keys.viewPk.byteLength !== 32
  ) {
    throw new RangeError('keys must provide 32-byte Uint8Array spendPkBytes, nkBytes, viewSk, and viewPk');
  }
  return {
    spendPk: new Uint8Array(keys.spendPkBytes),
    nk: new Uint8Array(keys.nkBytes),
    viewSk: new Uint8Array(keys.viewSk),
    viewPk: new Uint8Array(keys.viewPk),
  };
}

export function deriveDefiSessionKeypair(
  masterSeed32: Uint8Array,
  sessionIndex: number,
): DefiSessionKeypair {
  if (!(masterSeed32 instanceof Uint8Array) || masterSeed32.byteLength !== 32) {
    throw new RangeError(
      `Master seed must be 32 bytes (Uint8Array), got ${masterSeed32 instanceof Uint8Array ? masterSeed32.byteLength : String(masterSeed32)}`,
    );
  }
  if (!Number.isInteger(sessionIndex) || sessionIndex < 0 || sessionIndex > U32_MAX) {
    throw new RangeError(`sessionIndex must be a u32 integer in 0..=${U32_MAX}, got ${sessionIndex}`);
  }
  const secretSeed = hkdf(
    sha256,
    masterSeed32,
    utf8Encoder.encode('audren/v1/defi_session'),
    u32le(sessionIndex),
    32,
  );
  const pubkey = ed25519.getPublicKey(secretSeed);
  return {
    sessionIndex,
    secretSeed,
    pubkey,
    pubkeyBase58: base58Encode(pubkey),
  };
}

export function fvkStealthOwner(fvk: FullViewingKey, tweak: bigint): bigint {
  if (!fvk || typeof fvk !== 'object') {
    throw new RangeError('fvk must be an object');
  }
  return deriveStealthOwner(frFromBeBytesStrict(fvk.spendPk), tweak);
}

export function fvkRealNullifier(
  fvk: FullViewingKey,
  noteCm: bigint,
  globalLeafIndex: bigint,
): Uint8Array {
  if (!fvk || typeof fvk !== 'object') {
    throw new RangeError('fvk must be an object');
  }
  return frToBeBytes(computeRealNullifier(frFromBeBytesStrict(fvk.nk), noteCm, globalLeafIndex));
}

/**
 * Verify a Mode 1 per-transaction `SelectiveDisclosureProof` against an on-chain
 * `SubtreePage` leaf commitment in 1 Poseidon hash (reveals zero keys).
 * Enforces strict field bounds (`0 <= amount <= u64::MAX`, `0 <= leafIndex <= u64::MAX`,
 * valid `u32` `poolId`, `0 <= laneId < NUM_LANES`, exact 32-byte arrays) so modular
 * field aliasing (`amount + k * r`) is unconditionally rejected.
 */
export function verifySelectiveDisclosureProof(
  proof: SelectiveDisclosureProof,
  onchainSubtreeLeaf: Uint8Array,
): boolean {
  if (
    !proof ||
    typeof proof !== 'object' ||
    !(onchainSubtreeLeaf instanceof Uint8Array) ||
    !(proof.stealthOwner instanceof Uint8Array) ||
    !(proof.mint instanceof Uint8Array) ||
    !(proof.blinding instanceof Uint8Array) ||
    !(proof.commitment instanceof Uint8Array) ||
    onchainSubtreeLeaf.byteLength !== 32 ||
    proof.stealthOwner.byteLength !== 32 ||
    proof.mint.byteLength !== 32 ||
    proof.blinding.byteLength !== 32 ||
    proof.commitment.byteLength !== 32
  ) {
    return false;
  }
  if (!Number.isInteger(proof.poolId) || proof.poolId < 0 || proof.poolId > U32_MAX) {
    return false;
  }
  if (!Number.isInteger(proof.laneId) || proof.laneId < 0 || proof.laneId >= NUM_LANES) {
    return false;
  }
  if (typeof proof.leafIndex !== 'bigint' || proof.leafIndex < 0n || proof.leafIndex > U64_MAX) {
    return false;
  }
  if (typeof proof.amount !== 'bigint' || proof.amount < 0n || proof.amount > U64_MAX) {
    return false;
  }
  try {
    const stealth = frFromBeBytesStrict(proof.stealthOwner);
    const blinding = frFromBeBytesStrict(proof.blinding);
    const assetId = deriveAssetId(proof.mint);
    const computed = frToBeBytes(computeNoteCommitment(stealth, assetId, proof.amount, blinding));
    for (let i = 0; i < 32; i++) {
      if (computed[i] !== proof.commitment[i] || computed[i] !== onchainSubtreeLeaf[i]) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}
