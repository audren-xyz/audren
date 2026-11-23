/**
 * Canonical Audren key derivation, Mode 1 `SelectiveDisclosureProof`,
 * Mode 2 read-only `FullViewingKey` (`spendPk`, `nk`, `viewSk`, `viewPk`),
 * and deterministic `DefiSessionKeypair` matching `crates/client/src/keys.rs` byte-for-byte.
 */

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
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
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, true);
  return out;
}

export function deriveKeysFromSeed(seed32: Uint8Array): AudrenKeys {
  if (seed32.byteLength !== 32) {
    throw new RangeError(`Master seed must be 32 bytes, got ${seed32.byteLength}`);
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
  if (!Number.isInteger(accountIndex) || accountIndex < 0) {
    throw new RangeError(`accountIndex must be a non-negative integer, got ${accountIndex}`);
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
  if (masterSeed32.byteLength !== 32) {
    throw new RangeError(`Master seed must be 32 bytes, got ${masterSeed32.byteLength}`);
  }
  if (!Number.isInteger(sessionIndex) || sessionIndex < 0) {
    throw new RangeError(`sessionIndex must be a non-negative integer, got ${sessionIndex}`);
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
  return deriveStealthOwner(frFromBeBytesStrict(fvk.spendPk), tweak);
}

export function fvkRealNullifier(
  fvk: FullViewingKey,
  noteCm: bigint,
  globalLeafIndex: bigint,
): Uint8Array {
  return frToBeBytes(computeRealNullifier(frFromBeBytesStrict(fvk.nk), noteCm, globalLeafIndex));
}

/**
 * Verify a Mode 1 per-transaction `SelectiveDisclosureProof` against an on-chain
 * `SubtreePage` leaf commitment in 1 Poseidon hash (reveals zero keys).
 */
export function verifySelectiveDisclosureProof(
  proof: SelectiveDisclosureProof,
  onchainSubtreeLeaf: Uint8Array,
): boolean {
  if (onchainSubtreeLeaf.byteLength !== 32) return false;
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
