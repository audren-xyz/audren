//! Canonical Audren v1 key hierarchy, BIP-350 Bech32m `aud1...` stealth addresses,
//! versioned `106 B` SoA note memos (`72 B` AEAD ciphertext with `34 B` header AAD),
//! Mode 1 `SelectiveDisclosureProof`, Mode 2 `FullViewingKey` (`spend_pk`, `nk`, `view_sk`, `view_pk`),
//! and deterministic `DefiSessionKeypair` for stateful account-bound Solana DeFi.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use audren_circuits::{
    note::{
        compute_note_commitment, compute_real_nullifier, derive_asset_id, derive_nullifier_key,
        derive_spend_pk, derive_stealth_owner,
    },
    poseidon::{fr_from_be_bytes_strict, fr_to_be_bytes},
};
use audren_core::{
    instruction::{
        KDF_DOMAIN_BLIND, KDF_DOMAIN_DYN_BLIND, KDF_DOMAIN_DYN_MASK, KDF_DOMAIN_DYN_TWEAK,
        KDF_DOMAIN_MEMO_KEY, KDF_DOMAIN_MEMO_NONCE, KDF_DOMAIN_TWEAK, KDF_DOMAIN_VIEW_TAG,
    },
    layout::{
        DYN_MEMO_HEAD_LEN, DYN_MEMO_MAGIC, MEMO_CT_LEN, MEMO_ENTRY_WIRE_LEN, MEMO_PAYMENT_ID_LEN,
        MEMO_PLAINTEXT_LEN, MEMO_VERSION_V1,
    },
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Sec};
use zeroize::{Zeroize, Zeroizing};

use crate::ClientError;

const ADDR_VERSION_V1: u8 = 0x01;
const ADDR_HRP: &str = "aud";
const BECH32M_CONST: u32 = 0x2bc8_30a3;
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const MAX_BECH32M_LEN: usize = 128;
const X25519_PROBE_SCALAR: [u8; 32] = [0x09; 32];

/// Verify an X25519 public key is contributory (rejects all-zero and Curve25519 order-8 low-order
/// points using the fixed RFC 7748 probe scalar `[0x09; 32]`).
pub fn is_contributory_x25519_point(view_pk: &[u8; 32]) -> bool {
    X25519Sec::from(X25519_PROBE_SCALAR)
        .diffie_hellman(&X25519Pub::from(*view_pk))
        .was_contributory()
}

const HKDF_SALT_ROOT: &[u8] = b"audren/v1/root";
const HKDF_INFO_SPEND_SK: &[u8] = b"audren/v1/spend_sk";
const HKDF_INFO_VIEW_SK: &[u8] = b"audren/v1/view_sk";
const HKDF_SALT_SUBACCOUNT: &[u8] = b"audren/v1/subaccount";
const HKDF_SALT_DEFI_SESSION: &[u8] = b"audren/v1/defi_session";

// =============================================================================
// Canonical BIP-350 Bech32m (zero dependencies, up to 128 chars for 65 B payload)
// =============================================================================

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, &g) in GEN.iter().enumerate() {
            if ((top >> i) & 1) != 0 {
                chk ^= g;
            }
        }
    }
    chk
}

fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let bytes = hrp.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 2 + 1);
    for &b in bytes {
        out.push(b >> 5);
    }
    out.push(0);
    for &b in bytes {
        out.push(b & 31);
    }
    out
}

fn bech32m_create_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut values = bech32_hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);
    let polymod = bech32_polymod(&values) ^ BECH32M_CONST;
    let mut out = [0u8; 6];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = ((polymod >> (5 * (5 - i))) & 31) as u8;
    }
    out
}

fn bech32m_verify_checksum(hrp: &str, data_with_checksum: &[u8]) -> bool {
    let mut values = bech32_hrp_expand(hrp);
    values.extend_from_slice(data_with_checksum);
    bech32_polymod(&values) == BECH32M_CONST
}

fn convert_bits(
    data: &[u8],
    from_bits: u32,
    to_bits: u32,
    pad: bool,
) -> Result<Vec<u8>, ClientError> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv: u32 = (1 << to_bits) - 1;
    let max_acc: u32 = (1 << (from_bits + to_bits - 1)) - 1;
    let mut out = Vec::with_capacity((data.len() * from_bits as usize).div_ceil(to_bits as usize));

    for &value in data {
        let v = u32::from(value);
        if (v >> from_bits) != 0 {
            return Err(ClientError::InvalidEncoding("invalid bech32m bit group"));
        }
        acc = ((acc << from_bits) | v) & max_acc;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }

    if pad {
        if bits > 0 {
            out.push(((acc << (to_bits - bits)) & maxv) as u8);
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0 {
        return Err(ClientError::InvalidEncoding(
            "non-zero trailing pad bits in bech32m",
        ));
    }
    Ok(out)
}

fn bech32_char_value(b: u8) -> Option<u8> {
    BECH32_CHARSET
        .iter()
        .position(|&c| c == b)
        .map(|pos| pos as u8)
}

/// Full Audren shielded keypair derived deterministically from a 32-byte master seed.
#[derive(Clone)]
pub struct AudrenKeys {
    pub spend_sk: Fr,
    pub spend_pk: Fr,
    pub nk: Fr,
    pub view_sk: [u8; 32],
    pub view_pk: [u8; 32],
}

impl std::fmt::Debug for AudrenKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AudrenKeys")
            .field("spend_sk", &"<redacted>")
            .field("spend_pk", &bs58::encode(fr_to_be_bytes(&self.spend_pk)).into_string())
            .field("nk", &"<redacted>")
            .field("view_sk", &"<redacted>")
            .field("view_pk", &bs58::encode(self.view_pk).into_string())
            .finish()
    }
}

impl Drop for AudrenKeys {
    fn drop(&mut self) {
        self.spend_sk.zeroize();
        self.nk.zeroize();
        self.view_sk.zeroize();
    }
}

impl AudrenKeys {
    /// Derive `(spend_sk, spend_pk, nk, view_sk, view_pk)` from a 32-byte master seed via HKDF-SHA256.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT_ROOT), seed);

        let mut spend_raw = Zeroizing::new([0u8; 32]);
        hk.expand(HKDF_INFO_SPEND_SK, &mut *spend_raw)
            .expect("32-byte HKDF expand");
        let spend_masked = Zeroizing::new(audren_core::mask_to_fr_be(*spend_raw));
        let spend_sk = Fr::from_be_bytes_mod_order(&*spend_masked);

        let mut view_sk = Zeroizing::new([0u8; 32]);
        hk.expand(HKDF_INFO_VIEW_SK, &mut *view_sk)
            .expect("32-byte HKDF expand");
        let vsec = X25519Sec::from(*view_sk);
        let vpub = X25519Pub::from(&vsec);

        Self {
            spend_sk,
            spend_pk: derive_spend_pk(spend_sk),
            nk: derive_nullifier_key(spend_sk),
            view_sk: vsec.to_bytes(),
            view_pk: vpub.to_bytes(),
        }
    }

    /// Derive a cryptographically isolated sub-account (`account_index == 0` is primary).
    pub fn from_seed_subaccount(seed: &[u8; 32], account_index: u32) -> Self {
        if account_index == 0 {
            return Self::from_seed(seed);
        }
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT_SUBACCOUNT), seed);
        let mut child = Zeroizing::new([0u8; 32]);
        hk.expand(&account_index.to_le_bytes(), &mut *child)
            .expect("32-byte HKDF expand");
        Self::from_seed(&child)
    }

    /// Generate a fresh random Audren keypair.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *seed);
        Self::from_seed(&seed)
    }

    /// Public BIP-350 Bech32m `aud1...` stealth meta-address (accepts SOL/WSOL, Classic SPL, and Token-2022).
    pub fn address(&self) -> AudrenAddress {
        AudrenAddress {
            spend_pk: fr_to_be_bytes(&self.spend_pk),
            view_pk: self.view_pk,
        }
    }

    /// Export Mode 2 read-only `FullViewingKey` (detects both incoming notes AND outgoing
    /// spends via `nk`, with zero spend authority).
    pub fn full_viewing_key(&self) -> FullViewingKey {
        FullViewingKey {
            spend_pk: fr_to_be_bytes(&self.spend_pk),
            nk: fr_to_be_bytes(&self.nk),
            view_sk: self.view_sk,
            view_pk: self.view_pk,
        }
    }

    /// Derive a deterministic Solana Ed25519 keypair for stateful account-bound DeFi protocols
    /// (lending borrows, perpetual margin accounts, CLMM LP NFTs).
    ///
    /// **Privacy Boundary (Honest Threat Model):** Each `session_index` produces an independent
    /// pseudonymous Solana wallet unlinkable to the user's primary public wallet or other sessions
    /// (when funded via relayed `Transact` WSOL unwrap and swept back via zero-dust
    /// `Deposit(DEPOSIT_FLAG_NATIVE_SOL | DEPOSIT_FLAG_FEE_FROM_AMOUNT)`). However, all positions
    /// and transactions executed BY that session wallet on external DeFi protocols remain public on Solana.
    pub fn derive_defi_session_keypair(seed: &[u8; 32], session_index: u32) -> DefiSessionKeypair {
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT_DEFI_SESSION), seed);
        let mut secret_seed = Zeroizing::new([0u8; 32]);
        hk.expand(&session_index.to_le_bytes(), &mut *secret_seed)
            .expect("32-byte HKDF expand");
        let signing = SigningKey::from_bytes(&secret_seed);
        let pubkey = signing.verifying_key().to_bytes();
        DefiSessionKeypair {
            session_index,
            secret_seed: *secret_seed,
            pubkey,
        }
    }
}

/// Deterministic Ed25519 keypair for stateful DeFi interactions (`session_index = 0, 1, 2, ...`).
/// Recoverable from the single 32-byte Audren master seed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiSessionKeypair {
    pub session_index: u32,
    pub secret_seed: [u8; 32],
    pub pubkey: [u8; 32],
}

impl Drop for DefiSessionKeypair {
    fn drop(&mut self) {
        self.secret_seed.zeroize();
    }
}

impl std::fmt::Debug for DefiSessionKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefiSessionKeypair")
            .field("session_index", &self.session_index)
            .field("pubkey", &bs58::encode(self.pubkey).into_string())
            .field("secret_seed", &"<redacted>")
            .finish()
    }
}

/// Public Audren v1 stealth address encoded as canonical BIP-350 Bech32m
/// (`hrp = "aud"`, 65-byte payload `[0x01 | spend_pk_be[32] | view_pk[32]]`, `114` chars total).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudrenAddress {
    pub spend_pk: [u8; 32],
    pub view_pk: [u8; 32],
}

impl AudrenAddress {
    pub fn encode(&self) -> Result<String, ClientError> {
        if !audren_core::is_canonical_fr(&self.spend_pk) {
            return Err(ClientError::InvalidFieldElement);
        }
        if !is_contributory_x25519_point(&self.view_pk) {
            return Err(ClientError::Crypto("low-order X25519 public key"));
        }
        let mut raw = [0u8; 65];
        raw[0] = ADDR_VERSION_V1;
        raw[1..33].copy_from_slice(&self.spend_pk);
        raw[33..65].copy_from_slice(&self.view_pk);
        let data5 = convert_bits(&raw, 8, 5, true)?;
        let checksum = bech32m_create_checksum(ADDR_HRP, &data5);
        let mut out = String::with_capacity(ADDR_HRP.len() + 1 + data5.len() + checksum.len());
        out.push_str(ADDR_HRP);
        out.push('1');
        for &v in &data5 {
            out.push(BECH32_CHARSET[v as usize] as char);
        }
        for &v in &checksum {
            out.push(BECH32_CHARSET[v as usize] as char);
        }
        Ok(out)
    }

    pub fn decode(s: &str) -> Result<Self, ClientError> {
        if s.is_empty() || s.len() > MAX_BECH32M_LEN {
            return Err(ClientError::InvalidEncoding(
                "invalid aud1 bech32m address length",
            ));
        }
        let mut has_lower = false;
        let mut has_upper = false;
        for b in s.bytes() {
            if !(33..=126).contains(&b) {
                return Err(ClientError::InvalidEncoding(
                    "invalid ASCII character in aud1 address",
                ));
            }
            if b.is_ascii_lowercase() {
                has_lower = true;
            } else if b.is_ascii_uppercase() {
                has_upper = true;
            }
        }
        if has_lower && has_upper {
            return Err(ClientError::InvalidEncoding(
                "mixed case not allowed in bech32m address",
            ));
        }
        let lower = s.to_ascii_lowercase();
        let sep = lower
            .rfind('1')
            .ok_or(ClientError::InvalidEncoding("missing bech32m separator"))?;
        if sep == 0 || lower.len() - sep - 1 < 6 {
            return Err(ClientError::InvalidEncoding(
                "malformed bech32m hrp or checksum",
            ));
        }
        let hrp = &lower[..sep];
        if hrp != ADDR_HRP {
            return Err(ClientError::InvalidEncoding(
                "address HRP must be \"aud\"",
            ));
        }
        let data_part = &lower[sep + 1..];
        let mut data_5bit = Vec::with_capacity(data_part.len());
        for b in data_part.bytes() {
            let v = bech32_char_value(b)
                .ok_or(ClientError::InvalidEncoding("invalid bech32m character"))?;
            data_5bit.push(v);
        }
        if !bech32m_verify_checksum(hrp, &data_5bit) {
            return Err(ClientError::InvalidEncoding(
                "invalid bech32m checksum in aud1 address",
            ));
        }
        let payload_5bit = &data_5bit[..data_5bit.len() - 6];
        let raw = convert_bits(payload_5bit, 5, 8, false)?;
        if raw.len() != 65 || raw[0] != ADDR_VERSION_V1 {
            return Err(ClientError::InvalidEncoding(
                "invalid aud1 address payload length or version",
            ));
        }
        let spend_pk: [u8; 32] = raw[1..33].try_into().unwrap();
        let view_pk: [u8; 32] = raw[33..65].try_into().unwrap();
        if !audren_core::is_canonical_fr(&spend_pk) {
            return Err(ClientError::InvalidFieldElement);
        }
        if !is_contributory_x25519_point(&view_pk) {
            return Err(ClientError::Crypto("low-order X25519 public key"));
        }
        Ok(Self { spend_pk, view_pk })
    }

    pub fn spend_pk_fr(&self) -> Result<Fr, ClientError> {
        fr_from_be_bytes_strict(&self.spend_pk).ok_or(ClientError::InvalidFieldElement)
    }
}

/// Mode 2 read-only `FullViewingKey` (`spend_pk`, `nk`, `view_sk`, `view_pk`).
///
/// Enables watch-only wallets, offline balance tracking, relayer hot-worker fee verification,
/// and compliance auditors to decrypt incoming notes AND compute exact spent nullifiers with
/// zero spend capability (`spend_sk` is never exposed).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullViewingKey {
    pub spend_pk: [u8; 32],
    pub nk: [u8; 32],
    pub view_sk: [u8; 32],
    pub view_pk: [u8; 32],
}

impl std::fmt::Debug for FullViewingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FullViewingKey")
            .field("spend_pk", &bs58::encode(self.spend_pk).into_string())
            .field("view_pk", &bs58::encode(self.view_pk).into_string())
            .field("nk", &"<redacted>")
            .field("view_sk", &"<redacted>")
            .finish()
    }
}

impl FullViewingKey {
    pub fn spend_pk_fr(&self) -> Result<Fr, ClientError> {
        fr_from_be_bytes_strict(&self.spend_pk).ok_or(ClientError::InvalidFieldElement)
    }

    pub fn nk_fr(&self) -> Result<Fr, ClientError> {
        fr_from_be_bytes_strict(&self.nk).ok_or(ClientError::InvalidFieldElement)
    }

    pub fn stealth_owner(&self, tweak: Fr) -> Result<Fr, ClientError> {
        Ok(derive_stealth_owner(self.spend_pk_fr()?, tweak))
    }

    pub fn real_nullifier(
        &self,
        note_cm: Fr,
        global_leaf_index: u64,
    ) -> Result<[u8; 32], ClientError> {
        let nf = compute_real_nullifier(self.nk_fr()?, note_cm, global_leaf_index);
        Ok(fr_to_be_bytes(&nf))
    }
}

/// Mode 1 per-transaction `SelectiveDisclosureProof`: proves the commitment preimage opening
/// `(stealth_owner, mint, amount, blinding)` at a specific on-chain `(pool_id, lane_id, leaf_index)`
/// in 1 Poseidon hash against `SubtreePage` without revealing `spend_sk`, `nk`, or `view_sk`.
///
/// Note: Mode 1 proves commitment opening (that the leaf commits to `mint` and `amount`), not
/// exclusive recipient ownership (any party who knows the opening preimage, such as the sender or
/// a public observer of `Deposit`/`ExecViaEscrow`, can construct the same opening).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectiveDisclosureProof {
    pub pool_id: u32,
    pub lane_id: u8,
    pub leaf_index: u64,
    pub stealth_owner: [u8; 32],
    pub mint: [u8; 32],
    pub amount: u64,
    pub blinding: [u8; 32],
    pub commitment: [u8; 32],
}

impl SelectiveDisclosureProof {
    pub fn verify_against_leaf(&self, onchain_subtree_leaf: &[u8; 32]) -> bool {
        if (self.lane_id as usize) >= audren_core::NUM_LANES
            || self.leaf_index >= audren_core::layout::MAX_LEAVES_PER_LANE
        {
            return false;
        }
        let Some(stealth) = fr_from_be_bytes_strict(&self.stealth_owner) else {
            return false;
        };
        let Some(blinding) = fr_from_be_bytes_strict(&self.blinding) else {
            return false;
        };
        let asset_id = derive_asset_id(&self.mint);
        let computed = compute_note_commitment(stealth, asset_id, self.amount, blinding);
        let computed_be = fr_to_be_bytes(&computed);
        computed_be == self.commitment && computed_be == *onchain_subtree_leaf
    }
}

/// Decrypted note fields recovered from a versioned `106 B` `MemoPage` entry and verified
/// against `SubtreePage`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptedMemo {
    pub tweak: Fr,
    pub blinding: Fr,
    pub amount: u64,
    pub mint: [u8; 32],
    pub memo_version: u8,
    pub memo_flags: u8,
    pub payment_id: [u8; MEMO_PAYMENT_ID_LEN],
    pub is_dynamic: bool,
}

fn sha256_labeled(label: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label);
    h.update(data);
    h.finalize().into()
}

fn derive_view_tag(shared: &[u8; 32]) -> [u8; 2] {
    let vt_raw = sha256_labeled(KDF_DOMAIN_VIEW_TAG, shared);
    [vt_raw[0], vt_raw[1]]
}

fn derive_static_memo_secrets(
    shared: &[u8; 32],
) -> ([u8; 2], Zeroizing<[u8; 32]>, [u8; 12], Fr, Fr) {
    let view_tag = derive_view_tag(shared);
    let aead_key = Zeroizing::new(sha256_labeled(KDF_DOMAIN_MEMO_KEY, shared));
    let mut nonce_raw = Zeroizing::new(sha256_labeled(KDF_DOMAIN_MEMO_NONCE, shared));
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_raw[0..12]);
    nonce_raw.zeroize();

    let tw_raw = Zeroizing::new(audren_core::mask_to_fr_be(sha256_labeled(
        KDF_DOMAIN_TWEAK,
        shared,
    )));
    let bl_raw = Zeroizing::new(audren_core::mask_to_fr_be(sha256_labeled(
        KDF_DOMAIN_BLIND,
        shared,
    )));
    let tweak = Fr::from_be_bytes_mod_order(&*tw_raw);
    let blinding = Fr::from_be_bytes_mod_order(&*bl_raw);

    (view_tag, aead_key, nonce, tweak, blinding)
}

fn derive_dynamic_memo_secrets(shared: &[u8; 32]) -> ([u8; 2], Fr, Fr, [u8; MEMO_CT_LEN]) {
    let view_tag = derive_view_tag(shared);
    let tw_raw = Zeroizing::new(audren_core::mask_to_fr_be(sha256_labeled(
        KDF_DOMAIN_DYN_TWEAK,
        shared,
    )));
    let bl_raw = Zeroizing::new(audren_core::mask_to_fr_be(sha256_labeled(
        KDF_DOMAIN_DYN_BLIND,
        shared,
    )));
    let dyn_tweak = Fr::from_be_bytes_mod_order(&*tw_raw);
    let dyn_blinding = Fr::from_be_bytes_mod_order(&*bl_raw);

    let mut dyn_mask = [0u8; MEMO_CT_LEN];
    for block_idx in 0u8..3u8 {
        let mut h = Sha256::new();
        h.update(KDF_DOMAIN_DYN_MASK);
        h.update(shared);
        h.update([block_idx]);
        let digest = Zeroizing::new(<[u8; 32]>::from(h.finalize()));
        let start = (block_idx as usize) * 32;
        let take = (MEMO_CT_LEN - start).min(32);
        dyn_mask[start..start + take].copy_from_slice(&digest[..take]);
    }

    (view_tag, dyn_tweak, dyn_blinding, dyn_mask)
}

/// Encrypt a versioned `106 B` SoA note memo (`view_tag[2] || epk[32] || ct[72]`) with zero
/// `payment_id` and `34 B` AEAD AAD (`view_tag || epk`).
/// Returns `(tweak, blinding, memo_106)` or `Err` if `recipient_view_pk` is a low-order X25519 point.
pub fn encrypt_note_memo(
    recipient_view_pk: &[u8; 32],
    eph_secret_32: [u8; 32],
    amount: u64,
    mint_32: &[u8; 32],
) -> Result<(Fr, Fr, [u8; MEMO_ENTRY_WIRE_LEN]), ClientError> {
    encrypt_note_memo_with_payment_id(
        recipient_view_pk,
        eph_secret_32,
        amount,
        mint_32,
        [0u8; MEMO_PAYMENT_ID_LEN],
    )
}

/// Encrypt a versioned `106 B` SoA note memo (`view_tag[2] || epk[32] || ct[72]`) with an explicit
/// 14-byte `payment_id` and `34 B` AEAD AAD (`view_tag || epk`).
/// Returns `(tweak, blinding, memo_106)` or `Err` if `recipient_view_pk` is a low-order X25519 point.
pub fn encrypt_note_memo_with_payment_id(
    recipient_view_pk: &[u8; 32],
    mut eph_secret_32: [u8; 32],
    amount: u64,
    mint_32: &[u8; 32],
    payment_id: [u8; MEMO_PAYMENT_ID_LEN],
) -> Result<(Fr, Fr, [u8; MEMO_ENTRY_WIRE_LEN]), ClientError> {
    let eph_sec = X25519Sec::from(eph_secret_32);
    eph_secret_32.zeroize();
    let eph_pub = X25519Pub::from(&eph_sec);
    let shared = eph_sec.diffie_hellman(&X25519Pub::from(*recipient_view_pk));
    if !shared.was_contributory() {
        return Err(ClientError::Crypto("low-order X25519 public key"));
    }
    let (vt, key, nonce, tweak, blinding) = derive_static_memo_secrets(shared.as_bytes());

    let mut plain = Zeroizing::new([0u8; MEMO_PLAINTEXT_LEN]);
    plain[0..8].copy_from_slice(&amount.to_le_bytes());
    plain[8..40].copy_from_slice(mint_32);
    plain[40] = MEMO_VERSION_V1;
    plain[41] = 0; // memo_flags
    plain[42..56].copy_from_slice(&payment_id);

    let mut aad = [0u8; DYN_MEMO_HEAD_LEN];
    aad[0..2].copy_from_slice(&vt);
    aad[2..34].copy_from_slice(eph_pub.as_bytes());

    let cipher = ChaCha20Poly1305::new((&*key).into());
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plain.as_slice(),
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| ClientError::Crypto("chacha20poly1305 encrypt failed"))?;
    debug_assert_eq!(ct.len(), MEMO_CT_LEN);

    let mut out = [0u8; MEMO_ENTRY_WIRE_LEN];
    out[0..34].copy_from_slice(&aad);
    out[34..MEMO_ENTRY_WIRE_LEN].copy_from_slice(&ct);
    Ok((tweak, blinding, out))
}

/// Prepare domain-separated XOR-masked `AUD1DYN1` (`72 B`) dynamic memo inputs for `ExecViaEscrow`
/// (`0` plaintext markers at rest; uses `audren/v1/dyn_tweak`, `audren/v1/dyn_blind`, `audren/v1/dyn_mask`).
pub fn prepare_dynamic_swap_memo(
    recipient_view_pk: &[u8; 32],
    mut eph_secret_32: [u8; 32],
) -> Result<(Fr, Fr, [u8; DYN_MEMO_HEAD_LEN], [u8; MEMO_CT_LEN]), ClientError> {
    let eph_sec = X25519Sec::from(eph_secret_32);
    eph_secret_32.zeroize();
    let eph_pub = X25519Pub::from(&eph_sec);
    let shared = eph_sec.diffie_hellman(&X25519Pub::from(*recipient_view_pk));
    if !shared.was_contributory() {
        return Err(ClientError::Crypto("low-order X25519 public key"));
    }
    let (vt, dyn_tweak, dyn_blinding, dyn_mask) = derive_dynamic_memo_secrets(shared.as_bytes());

    let mut head = [0u8; DYN_MEMO_HEAD_LEN];
    head[0..2].copy_from_slice(&vt);
    head[2..34].copy_from_slice(eph_pub.as_bytes());
    Ok((dyn_tweak, dyn_blinding, head, dyn_mask))
}

/// Public fixed RFC 7748 clamped Curve25519 scalar `8 * (2^251 + 1)` (`gcd(2^251 + 1, L) = 1`
/// and `gcd(2^251 + 1, L_twist) = 1`): multiplying any 32-byte Montgomery u-coordinate by this
/// scalar maps all 12 low-order points (curve + twist) to `None` and maps any two non-zero
/// `epk`s to the exact same 32-byte point iff they induce the same `x25519(view_sk, epk)` for
/// every clamped `view_sk` (collapsing all 16 Curve25519 torsion + bit-255 + `u + p` variants
/// completely publicly without touching `view_sk`).
const PUBLIC_CANON_EPK_SCALAR: [u8; 32] = [
    0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0x40,
];

/// Public, key-independent canonicalization of a Curve25519 ephemeral public key modulo cofactor 8
/// and bit-255 / `u + p` non-canonicality. Returns `None` for `[0; 32]` and all 12 low-order points.
pub fn canonicalize_public_epk(epk: &[u8; 32]) -> Option<[u8; 32]> {
    if *epk == [0u8; 32] {
        return None;
    }
    let canon_sec = X25519Sec::from(PUBLIC_CANON_EPK_SCALAR);
    let shared = canon_sec.diffie_hellman(&X25519Pub::from(*epk));
    if !shared.was_contributory() {
        return None;
    }
    Some(*shared.as_bytes())
}

/// Fast X25519 + 2-byte view-tag prefilter for SoA `MemoPage` scanning (`1/65,536` false positives).
/// Rejects low-order Curve25519 ephemeral public keys (`!shared.was_contributory()`).
pub fn check_memo_view_tag(fvk: &FullViewingKey, view_tag: [u8; 2], epk: &[u8; 32]) -> bool {
    if *epk == [0u8; 32] {
        return false;
    }
    let vsec = X25519Sec::from(fvk.view_sk);
    let shared = vsec.diffie_hellman(&X25519Pub::from(*epk));
    if !shared.was_contributory() {
        return false;
    }
    derive_view_tag(shared.as_bytes()) == view_tag
}

const KDF_DOMAIN_HIT_DEDUP: &[u8] = b"audren/v1/hit_dedup";

fn try_decrypt_memo_payload_with_dedup_tag(
    fvk: &FullViewingKey,
    view_tag: [u8; 2],
    epk: &[u8; 32],
    ct72: &[u8; MEMO_CT_LEN],
) -> Option<(DecryptedMemo, Zeroizing<[u8; 32]>)> {
    if *epk == [0u8; 32] {
        return None;
    }
    let vsec = X25519Sec::from(fvk.view_sk);
    let shared = vsec.diffie_hellman(&X25519Pub::from(*epk));
    if !shared.was_contributory() {
        return None;
    }
    let (exp_vt, key, nonce, tweak, blinding) = derive_static_memo_secrets(shared.as_bytes());
    if exp_vt != view_tag {
        return None;
    }

    let mut aad = [0u8; DYN_MEMO_HEAD_LEN];
    aad[0..2].copy_from_slice(&view_tag);
    aad[2..34].copy_from_slice(epk);

    let cipher = ChaCha20Poly1305::new((&*key).into());
    let candidate = if let Ok(plain_vec) = cipher.decrypt(
        Nonce::from_slice(&nonce),
        Payload {
            msg: ct72.as_slice(),
            aad: aad.as_slice(),
        },
    ) {
        let plain = Zeroizing::new(plain_vec);
        if plain.len() != MEMO_PLAINTEXT_LEN || plain[40] != MEMO_VERSION_V1 {
            return None;
        }
        let amount = u64::from_le_bytes(plain[0..8].try_into().unwrap());
        let mint: [u8; 32] = plain[8..40].try_into().unwrap();
        let memo_version = plain[40];
        let memo_flags = plain[41];
        let payment_id: [u8; MEMO_PAYMENT_ID_LEN] = plain[42..56].try_into().unwrap();
        DecryptedMemo {
            tweak,
            blinding,
            amount,
            mint,
            memo_version,
            memo_flags,
            payment_id,
            is_dynamic: false,
        }
    } else {
        let (_, dyn_tweak, dyn_blinding, mut dyn_mask) =
            derive_dynamic_memo_secrets(shared.as_bytes());
        let mut unmasked = Zeroizing::new([0u8; MEMO_CT_LEN]);
        for i in 0..MEMO_CT_LEN {
            unmasked[i] = ct72[i] ^ dyn_mask[i];
        }
        dyn_mask.zeroize();
        if unmasked[0..8] != DYN_MEMO_MAGIC || unmasked[48..72] != [0u8; 24] {
            return None;
        }
        let amount = u64::from_le_bytes(unmasked[8..16].try_into().unwrap());
        let mint: [u8; 32] = unmasked[16..48].try_into().unwrap();
        DecryptedMemo {
            tweak: dyn_tweak,
            blinding: dyn_blinding,
            amount,
            mint,
            memo_version: MEMO_VERSION_V1,
            memo_flags: 0,
            payment_id: [0u8; MEMO_PAYMENT_ID_LEN],
            is_dynamic: true,
        }
    };
    // Key cross-subtree Pass 1D hit deduplication on the X25519 shared secret (domain-separated)
    // so all 16 Curve25519 torsion + bit-255 + non-canonical `epk` equivalents for `AUD1DYN1`
    // dynamic swap memos collapse into a single deduplication entry.
    let dedup_tag = Zeroizing::new(sha256_labeled(KDF_DOMAIN_HIT_DEDUP, shared.as_bytes()));
    Some((candidate, dedup_tag))
}

/// Internal Pass 1C pre-filter for full `MemoPage` scans (`Strict` mode / incremental `Fast`):
/// verifies AEAD / `AUD1DYN1` payload and returns `SHA256("audren/v1/hit_dedup" || shared)`
/// (collapsing Curve25519 torsion + bit-255 `epk` malleability) without exposing any unverified
/// note plaintext.
pub(crate) fn compute_memo_scan_dedup_tag(
    fvk: &FullViewingKey,
    view_tag: [u8; 2],
    epk: &[u8; 32],
    ct72: &[u8; MEMO_CT_LEN],
) -> Option<Zeroizing<[u8; 32]>> {
    try_decrypt_memo_payload_with_dedup_tag(fvk, view_tag, epk, ct72).map(|(_, tag)| tag)
}

/// Decrypt or unmask a `106 B` `MemoPage` entry (`view_tag[2]`, `epk[32]`, `ct72[72]`) AND
/// mandatorily verify
/// `compute_note_commitment(stealth_owner, derive_asset_id(mint), amount, blinding) == onchain_cm_be`
/// (from the local `SubtreePage` leaf) to block forged-memo balance poisoning.
/// Rejects low-order Curve25519 points (`!shared.was_contributory()`), tampered AAD headers,
/// unsupported memo versions, and non-zero dynamic swap padding bytes.
pub fn try_decrypt_and_verify_memo_entry(
    fvk: &FullViewingKey,
    view_tag: [u8; 2],
    epk: &[u8; 32],
    ct72: &[u8; MEMO_CT_LEN],
    onchain_cm_be: &[u8; 32],
) -> Option<DecryptedMemo> {
    let (candidate, _) = try_decrypt_memo_payload_with_dedup_tag(fvk, view_tag, epk, ct72)?;
    let stealth = fvk.stealth_owner(candidate.tweak).ok()?;
    let asset_id = derive_asset_id(&candidate.mint);
    let expected_cm =
        compute_note_commitment(stealth, asset_id, candidate.amount, candidate.blinding);
    if fr_to_be_bytes(&expected_cm) != *onchain_cm_be {
        return None;
    }
    Some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use audren_core::WSOL_MINT;

    /// RFC 7748 Curve25519 low-order point of order 8.
    const ORDER_8_POINT: [u8; 32] = [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ];

    #[test]
    fn bech32m_aud1_address_roundtrip_and_strict_validation() {
        let keys = AudrenKeys::from_seed(&[0x11u8; 32]);
        let addr = keys.address();
        let encoded = addr.encode().unwrap();
        assert!(encoded.starts_with("aud1"));
        assert_eq!(encoded.len(), 114, "aud1 + 104 data chars + 6 checksum chars");

        // Lowercase and uppercase both decode identically
        assert_eq!(AudrenAddress::decode(&encoded).unwrap(), addr);
        assert_eq!(
            AudrenAddress::decode(&encoded.to_ascii_uppercase()).unwrap(),
            addr
        );

        // Leading / trailing whitespace rejected strictly
        assert!(AudrenAddress::decode(&format!(" {encoded}")).is_err());
        assert!(AudrenAddress::decode(&format!("{encoded} ")).is_err());
        assert!(AudrenAddress::decode(&format!("\n{encoded}\t")).is_err());

        // Single-character typo rejected
        let mut typo = encoded.as_bytes().to_vec();
        typo[10] = if typo[10] == b'q' { b'p' } else { b'q' };
        assert!(AudrenAddress::decode(&String::from_utf8(typo).unwrap()).is_err());

        // Mixed-case rejected
        let mut mixed = encoded.clone();
        let first = mixed.remove(0).to_ascii_uppercase();
        mixed.insert(0, first);
        assert!(AudrenAddress::decode(&mixed).is_err());

        // Wrong HRP rejected
        let mut raw = [0u8; 65];
        raw[0] = ADDR_VERSION_V1;
        raw[1..33].copy_from_slice(&addr.spend_pk);
        raw[33..65].copy_from_slice(&addr.view_pk);
        let data5 = convert_bits(&raw, 8, 5, true).unwrap();
        let bad_hrp_ck = bech32m_create_checksum("sol", &data5);
        let mut bad_hrp = String::from("sol1");
        for &v in data5.iter().chain(bad_hrp_ck.iter()) {
            bad_hrp.push(BECH32_CHARSET[v as usize] as char);
        }
        assert!(AudrenAddress::decode(&bad_hrp).is_err());

        // Bad version byte (0x02) with valid Bech32m checksum rejected
        raw[0] = 0x02;
        let bad_ver5 = convert_bits(&raw, 8, 5, true).unwrap();
        let bad_ver_ck = bech32m_create_checksum(ADDR_HRP, &bad_ver5);
        let mut bad_ver = String::from("aud1");
        for &v in bad_ver5.iter().chain(bad_ver_ck.iter()) {
            bad_ver.push(BECH32_CHARSET[v as usize] as char);
        }
        assert!(AudrenAddress::decode(&bad_ver).is_err());

        // Non-canonical spend_pk >= BN254_FR_MODULUS_BE rejected by both encode and decode
        assert!(matches!(
            AudrenAddress {
                spend_pk: audren_core::BN254_FR_MODULUS_BE,
                view_pk: addr.view_pk,
            }
            .encode(),
            Err(ClientError::InvalidFieldElement)
        ));
        raw[0] = ADDR_VERSION_V1;
        raw[1..33].copy_from_slice(&audren_core::BN254_FR_MODULUS_BE);
        let bad_fr5 = convert_bits(&raw, 8, 5, true).unwrap();
        let bad_fr_ck = bech32m_create_checksum(ADDR_HRP, &bad_fr5);
        let mut bad_fr = String::from("aud1");
        for &v in bad_fr5.iter().chain(bad_fr_ck.iter()) {
            bad_fr.push(BECH32_CHARSET[v as usize] as char);
        }
        assert!(matches!(
            AudrenAddress::decode(&bad_fr),
            Err(ClientError::InvalidFieldElement)
        ));

        // Low-order X25519 view_pk ([0; 32] and RFC 7748 order-8 point) rejected by both encode and decode
        for bad_vpk in [[0u8; 32], ORDER_8_POINT] {
            assert!(matches!(
                AudrenAddress {
                    spend_pk: addr.spend_pk,
                    view_pk: bad_vpk,
                }
                .encode(),
                Err(ClientError::Crypto(_))
            ));
            raw[0] = ADDR_VERSION_V1;
            raw[1..33].copy_from_slice(&addr.spend_pk);
            raw[33..65].copy_from_slice(&bad_vpk);
            let bad_vp5 = convert_bits(&raw, 8, 5, true).unwrap();
            let bad_vp_ck = bech32m_create_checksum(ADDR_HRP, &bad_vp5);
            let mut bad_vp = String::from("aud1");
            for &v in bad_vp5.iter().chain(bad_vp_ck.iter()) {
                bad_vp.push(BECH32_CHARSET[v as usize] as char);
            }
            assert!(matches!(
                AudrenAddress::decode(&bad_vp),
                Err(ClientError::Crypto(_))
            ));
        }

        // SelectiveDisclosureProof rejects lane_id >= 16
        let stealth_fr = derive_stealth_owner(keys.spend_pk, Fr::from(7u64));
        let blind_fr = Fr::from(9u64);
        let cm_fr = compute_note_commitment(stealth_fr, derive_asset_id(&WSOL_MINT), 1_000, blind_fr);
        let cm_be = fr_to_be_bytes(&cm_fr);
        let mut sd = SelectiveDisclosureProof {
            pool_id: 0,
            lane_id: 15,
            leaf_index: 0,
            stealth_owner: fr_to_be_bytes(&stealth_fr),
            mint: WSOL_MINT,
            amount: 1_000,
            blinding: fr_to_be_bytes(&blind_fr),
            commitment: cm_be,
        };
        assert!(sd.verify_against_leaf(&cm_be));
        sd.lane_id = 16;
        assert!(!sd.verify_against_leaf(&cm_be));
    }

    #[test]
    fn x25519_low_order_points_and_aad_and_dyn_padding_rejected() {
        let alice = AudrenKeys::from_seed(&[0x22u8; 32]);
        let fvk = alice.full_viewing_key();
        let zero_epk = [0u8; 32];

        for bad_pk in [&zero_epk, &ORDER_8_POINT] {
            assert!(encrypt_note_memo(bad_pk, [0x33u8; 32], 1_000, &WSOL_MINT).is_err());
            assert!(prepare_dynamic_swap_memo(bad_pk, [0x33u8; 32]).is_err());
            let forged_vt = derive_view_tag(&[0u8; 32]);
            assert!(!check_memo_view_tag(&fvk, forged_vt, bad_pk));
            assert!(try_decrypt_and_verify_memo_entry(
                &fvk,
                forged_vt,
                bad_pk,
                &[0u8; MEMO_CT_LEN],
                &[0u8; 32],
            )
            .is_none());
        }

        // Static memo with payment_id round-trips and rejects tampered AAD
        let pid = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let (tw, bl, memo106) =
            encrypt_note_memo_with_payment_id(&alice.view_pk, [0x44u8; 32], 500_000, &WSOL_MINT, pid)
                .unwrap();
        let cm = compute_note_commitment(
            derive_stealth_owner(alice.spend_pk, tw),
            derive_asset_id(&WSOL_MINT),
            500_000,
            bl,
        );
        let cm_be = fr_to_be_bytes(&cm);
        let vt = [memo106[0], memo106[1]];
        let epk: [u8; 32] = memo106[2..34].try_into().unwrap();
        let ct72: [u8; MEMO_CT_LEN] = memo106[34..106].try_into().unwrap();
        let dec = try_decrypt_and_verify_memo_entry(&fvk, vt, &epk, &ct72, &cm_be).unwrap();
        assert_eq!(dec.amount, 500_000);
        assert_eq!(dec.mint, WSOL_MINT);
        assert_eq!(dec.memo_version, MEMO_VERSION_V1);
        assert_eq!(dec.memo_flags, 0);
        assert_eq!(dec.payment_id, pid);
        assert!(!dec.is_dynamic);

        // Dynamic swap memo uses domain-separated tweak/blind and enforces zero 24 B tail
        let (dtw, dbl, dhead, dmask) = prepare_dynamic_swap_memo(&alice.view_pk, [0x44u8; 32]).unwrap();
        assert_ne!(dtw, tw, "dyn_tweak must be domain-separated from static tweak");
        assert_ne!(dbl, bl, "dyn_blind must be domain-separated from static blinding");
        let dcm = compute_note_commitment(
            derive_stealth_owner(alice.spend_pk, dtw),
            derive_asset_id(&WSOL_MINT),
            999_999,
            dbl,
        );
        let dcm_be = fr_to_be_bytes(&dcm);
        let mut dplain = [0u8; MEMO_CT_LEN];
        dplain[0..8].copy_from_slice(&DYN_MEMO_MAGIC);
        dplain[8..16].copy_from_slice(&999_999u64.to_le_bytes());
        dplain[16..48].copy_from_slice(&WSOL_MINT);
        let mut dct = [0u8; MEMO_CT_LEN];
        for i in 0..MEMO_CT_LEN {
            dct[i] = dplain[i] ^ dmask[i];
        }
        let dvt = [dhead[0], dhead[1]];
        let depk: [u8; 32] = dhead[2..34].try_into().unwrap();
        let ddec = try_decrypt_and_verify_memo_entry(&fvk, dvt, &depk, &dct, &dcm_be).unwrap();
        assert!(ddec.is_dynamic);
        assert_eq!(ddec.amount, 999_999);

        // Flip any of the 24 zero-padding tail bytes -> MUST reject!
        let mut bad_dct = dct;
        bad_dct[48] ^= 0x01;
        assert!(try_decrypt_and_verify_memo_entry(&fvk, dvt, &depk, &bad_dct, &dcm_be).is_none());
    }
}
