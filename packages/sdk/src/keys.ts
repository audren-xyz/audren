/**
 * Deterministic HKDF-SHA256 sub-account seed derivation matching
 * `crates/client/src/keys.rs::AudrenKeys::from_seed_subaccount` byte-for-byte.
 *
 * Uses native Web Crypto (`crypto.subtle`) in Node.js 22+ and browsers with zero npm dependencies.
 */

const SUBACCOUNT_SALT = new TextEncoder().encode('audren/v1/subaccount');
const DEFI_SESSION_SALT = new TextEncoder().encode('audren/v1/defi_session');

/**
 * Derive a 32-byte child seed for scoped sub-account `accountIndex` (`u32`):
 * - `accountIndex === 0` returns a copy of `masterSeed` (the primary wallet account).
 * - `accountIndex >= 1` derives an independent child seed via
 *   `HKDF-SHA256(salt = "audren/v1/subaccount", ikm = masterSeed, info = u32_le(accountIndex))`,
 *   producing an unlinkable `aud1…` address whose `FullViewingKey` exposes only that stream.
 */
export async function deriveSubAccountSeed(
  masterSeed: Uint8Array,
  accountIndex: number,
): Promise<Uint8Array> {
  if (masterSeed.byteLength !== 32) {
    throw new RangeError(`masterSeed must be 32 bytes, got ${masterSeed.byteLength}`);
  }
  if (!Number.isInteger(accountIndex) || accountIndex < 0 || accountIndex > 0xffff_ffff) {
    throw new RangeError(`accountIndex must be a u32 integer, got ${accountIndex}`);
  }
  if (accountIndex === 0) {
    return new Uint8Array(masterSeed);
  }
  const info = new Uint8Array(4);
  new DataView(info.buffer).setUint32(0, accountIndex, true);
  const baseKey = await globalThis.crypto.subtle.importKey(
    'raw',
    new Uint8Array(masterSeed),
    'HKDF',
    false,
    ['deriveBits'],
  );
  const bits = await globalThis.crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: SUBACCOUNT_SALT, info },
    baseKey,
    256,
  );
  return new Uint8Array(bits);
}

/**
 * Derive a deterministic 32-byte Ed25519 secret seed for an ephemeral DeFi session wallet
 * (`sessionIndex: u32`) via `HKDF-SHA256(salt = "audren/v1/defi_session", ikm = masterSeed, info = u32_le(sessionIndex))`,
 * matching `crates/client/src/keys.rs::AudrenKeys::derive_defi_session_keypair` byte-for-byte.
 */
export async function deriveDefiSessionSeed(
  masterSeed: Uint8Array,
  sessionIndex: number,
): Promise<Uint8Array> {
  if (masterSeed.byteLength !== 32) {
    throw new RangeError(`masterSeed must be 32 bytes, got ${masterSeed.byteLength}`);
  }
  if (!Number.isInteger(sessionIndex) || sessionIndex < 0 || sessionIndex > 0xffff_ffff) {
    throw new RangeError(`sessionIndex must be a u32 integer, got ${sessionIndex}`);
  }
  const info = new Uint8Array(4);
  new DataView(info.buffer).setUint32(0, sessionIndex, true);
  const baseKey = await globalThis.crypto.subtle.importKey(
    'raw',
    new Uint8Array(masterSeed),
    'HKDF',
    false,
    ['deriveBits'],
  );
  const bits = await globalThis.crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: DEFI_SESSION_SALT, info },
    baseKey,
    256,
  );
  return new Uint8Array(bits);
}
