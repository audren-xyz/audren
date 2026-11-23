//! Canonical Audren key hierarchy, `aud1...` stealth addresses, compact `90 B` SoA note memos,
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
use audren_core::layout::{DYN_MEMO_HEAD_LEN, DYN_MEMO_MAGIC, MEMO_CT_LEN, MEMO_ENTRY_WIRE_LEN};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Sec};

use crate::ClientError;

const ADDR_VERSION_V2: u8 = 0x02;
const ADDR_PREFIX: &str = "aud1";

/// Full Audren shielded keypair derived deterministically from a 32-byte master seed.
#[derive(Clone)]
pub struct AudrenKeys {
    pub spend_sk: Fr,
    pub spend_pk: Fr,
    pub nk: Fr,
    pub view_sk: [u8; 32],
    pub view_pk: [u8; 32],
}

impl AudrenKeys {
    /// Derive `(spend_sk, spend_pk, nk, view_sk, view_pk)` from a 32-byte master seed via HKDF-SHA256.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"audren/v2/root"), seed);

        let mut spend_raw = [0u8; 32];
        hk.expand(b"audren/v2/spend_sk", &mut spend_raw)
            .expect("32-byte HKDF expand");
        let spend_masked = audren_core::mask_to_fr_be(spend_raw);
        let spend_sk = Fr::from_be_bytes_mod_order(&spend_masked);

        let mut view_sk = [0u8; 32];
        hk.expand(b"audren/v2/view_sk", &mut view_sk)
            .expect("32-byte HKDF expand");
        let vsec = X25519Sec::from(view_sk);
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
        let hk = Hkdf::<Sha256>::new(Some(b"audren/v2/subaccount"), seed);
        let mut child = [0u8; 32];
        hk.expand(&account_index.to_le_bytes(), &mut child)
            .expect("32-byte HKDF expand");
        Self::from_seed(&child)
    }

    /// Generate a fresh random Audren keypair.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Public `aud1...` stealth meta-address (accepts SOL, Classic SPL, and Token-2022).
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
    /// (when funded via relayed `JoinSplit` Withdraw and swept back via zero-dust `DepositSol`).
    /// However, all positions and transactions executed BY that session wallet on external DeFi
    /// protocols remain public on Solana.
    pub fn derive_defi_session_keypair(seed: &[u8; 32], session_index: u32) -> DefiSessionKeypair {
        let hk = Hkdf::<Sha256>::new(Some(b"audren/v2/defi_session"), seed);
        let mut secret_seed = [0u8; 32];
        hk.expand(&session_index.to_le_bytes(), &mut secret_seed)
            .expect("32-byte HKDF expand");
        let signing = SigningKey::from_bytes(&secret_seed);
        let pubkey = signing.verifying_key().to_bytes();
        DefiSessionKeypair {
            session_index,
            secret_seed,
            pubkey,
        }
    }
}

/// Deterministic Ed25519 keypair for stateful DeFi interactions (`session_index = 0, 1, 2, ...`).
/// Recoverable from the single 32-byte Audren master seed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiSessionKeypair {
    pub session_index: u32,
    pub secret_seed: [u8; 32],
    pub pubkey: [u8; 32],
}

/// Public Audren stealth address (`aud1` + Base58(`[0x02 | spend_pk_be[32] | view_pk[32]]`)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudrenAddress {
    pub spend_pk: [u8; 32],
    pub view_pk: [u8; 32],
}

impl AudrenAddress {
    pub fn encode(&self) -> String {
        let mut raw = [0u8; 65];
        raw[0] = ADDR_VERSION_V2;
        raw[1..33].copy_from_slice(&self.spend_pk);
        raw[33..65].copy_from_slice(&self.view_pk);
        format!("{ADDR_PREFIX}{}", bs58::encode(raw).into_string())
    }

    pub fn decode(s: &str) -> Result<Self, ClientError> {
        let body = s
            .strip_prefix(ADDR_PREFIX)
            .ok_or(ClientError::InvalidEncoding("address must start with aud1"))?;
        let raw = bs58::decode(body)
            .into_vec()
            .map_err(|_| ClientError::InvalidEncoding("invalid base58 in aud1 address"))?;
        if raw.len() != 65 || raw[0] != ADDR_VERSION_V2 {
            return Err(ClientError::InvalidEncoding("invalid aud1 address length or version"));
        }
        let spend_pk: [u8; 32] = raw[1..33].try_into().unwrap();
        let view_pk: [u8; 32] = raw[33..65].try_into().unwrap();
        if !audren_core::is_canonical_fr(&spend_pk) {
            return Err(ClientError::InvalidFieldElement);
        }
        Ok(Self { spend_pk, view_pk })
    }

    pub fn spend_pk_fr(&self) -> Result<Fr, ClientError> {
        fr_from_be_bytes_strict(&self.spend_pk).ok_or(ClientError::InvalidFieldElement)
    }
}

/// Mode 2 read-only `FullViewingKey` (`spend_pk`, `nk`, `view_sk`, `view_pk`).
///
/// Enables watch-only wallets, hardware-signer separation, relayer hot-worker fee verification,
/// and compliance auditors to decrypt incoming notes AND compute exact spent nullifiers with
/// zero spend capability (`spend_sk` is never exposed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullViewingKey {
    pub spend_pk: [u8; 32],
    pub nk: [u8; 32],
    pub view_sk: [u8; 32],
    pub view_pk: [u8; 32],
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

    pub fn real_nullifier(&self, note_cm: Fr, global_leaf_index: u64) -> Result<[u8; 32], ClientError> {
        let nf = compute_real_nullifier(self.nk_fr()?, note_cm, global_leaf_index);
        Ok(fr_to_be_bytes(&nf))
    }
}

/// Mode 1 per-transaction `SelectiveDisclosureProof`: proves receipt of `(mint, amount)` at a
/// specific on-chain `(pool_id, lane_id, leaf_index)` in 1 Poseidon hash against `SubtreePage`
/// without revealing `spend_sk`, `nk`, or `view_sk`.
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

/// Decrypted note fields recovered from a `90 B` `MemoPage` entry and verified against `SubtreePage`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptedMemo {
    pub tweak: Fr,
    pub blinding: Fr,
    pub amount: u64,
    pub mint: [u8; 32],
    pub is_dynamic: bool,
}

fn sha256_labeled(label: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label);
    h.update(data);
    h.finalize().into()
}

fn derive_memo_secrets(shared: &[u8; 32]) -> ([u8; 2], [u8; 32], [u8; 12], Fr, Fr, [u8; 56]) {
    let vt_raw = sha256_labeled(b"audren/v2/vt", shared);
    let view_tag = [vt_raw[0], vt_raw[1]];
    let aead_key = sha256_labeled(b"audren/v2/aead_key", shared);
    let nonce_raw = sha256_labeled(b"audren/v2/aead_nonce", shared);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_raw[0..12]);

    let tw_raw = audren_core::mask_to_fr_be(sha256_labeled(b"audren/v2/tweak", shared));
    let bl_raw = audren_core::mask_to_fr_be(sha256_labeled(b"audren/v2/blinding", shared));
    let tweak = Fr::from_be_bytes_mod_order(&tw_raw);
    let blinding = Fr::from_be_bytes_mod_order(&bl_raw);

    let m0 = sha256_labeled(b"audren/v2/dyn_mask0", shared);
    let m1 = sha256_labeled(b"audren/v2/dyn_mask1", shared);
    let mut dyn_mask = [0u8; 56];
    dyn_mask[0..32].copy_from_slice(&m0);
    dyn_mask[32..56].copy_from_slice(&m1[0..24]);

    (view_tag, aead_key, nonce, tweak, blinding, dyn_mask)
}

/// Encrypt a compact `90 B` SoA note memo (`view_tag[2] || epk[32] || ct[56]`).
/// Returns `(tweak, blinding, memo_90)` with zero wire overhead for `tweak`/`blinding`.
pub fn encrypt_note_memo(
    recipient_view_pk: &[u8; 32],
    eph_secret_32: [u8; 32],
    amount: u64,
    mint_32: &[u8; 32],
) -> (Fr, Fr, [u8; MEMO_ENTRY_WIRE_LEN]) {
    let eph_sec = X25519Sec::from(eph_secret_32);
    let eph_pub = X25519Pub::from(&eph_sec);
    let shared = eph_sec.diffie_hellman(&X25519Pub::from(*recipient_view_pk));
    let (vt, key, nonce, tweak, blinding, _) = derive_memo_secrets(shared.as_bytes());

    let mut plain = [0u8; 40];
    plain[0..8].copy_from_slice(&amount.to_le_bytes());
    plain[8..40].copy_from_slice(mint_32);

    let cipher = ChaCha20Poly1305::new((&key).into());
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plain.as_slice())
        .expect("chacha20poly1305 encrypt");
    debug_assert_eq!(ct.len(), MEMO_CT_LEN);

    let mut out = [0u8; MEMO_ENTRY_WIRE_LEN];
    out[0..2].copy_from_slice(&vt);
    out[2..34].copy_from_slice(eph_pub.as_bytes());
    out[34..90].copy_from_slice(&ct);
    (tweak, blinding, out)
}

/// Prepare XOR-masked `AUD2DYN2` dynamic memo inputs for `ExecViaEscrow` (`0` plaintext markers at rest).
pub fn prepare_dynamic_swap_memo(
    recipient_view_pk: &[u8; 32],
    eph_secret_32: [u8; 32],
) -> (Fr, Fr, [u8; DYN_MEMO_HEAD_LEN], [u8; MEMO_CT_LEN]) {
    let eph_sec = X25519Sec::from(eph_secret_32);
    let eph_pub = X25519Pub::from(&eph_sec);
    let shared = eph_sec.diffie_hellman(&X25519Pub::from(*recipient_view_pk));
    let (vt, _, _, tweak, blinding, dyn_mask) = derive_memo_secrets(shared.as_bytes());

    let mut head = [0u8; DYN_MEMO_HEAD_LEN];
    head[0..2].copy_from_slice(&vt);
    head[2..34].copy_from_slice(eph_pub.as_bytes());
    (tweak, blinding, head, dyn_mask)
}

/// Fast X25519 + 2-byte view-tag prefilter for SoA `MemoPage` scanning (`1/65,536` false positives).
pub fn check_memo_view_tag(fvk: &FullViewingKey, view_tag: [u8; 2], epk: &[u8; 32]) -> bool {
    let vsec = X25519Sec::from(fvk.view_sk);
    let shared = vsec.diffie_hellman(&X25519Pub::from(*epk));
    let vt_raw = sha256_labeled(b"audren/v2/vt", shared.as_bytes());
    vt_raw[0] == view_tag[0] && vt_raw[1] == view_tag[1]
}

/// Decrypt or unmask a `90 B` `MemoPage` entry AND **mandatorily verify** that
/// `compute_note_commitment(stealth_owner, derive_asset_id(mint), amount, blinding) == onchain_cm_be`
/// (from the local `SubtreePage` leaf) to block forged-memo balance poisoning.
pub fn try_decrypt_and_verify_memo_entry(
    fvk: &FullViewingKey,
    view_tag: [u8; 2],
    epk: &[u8; 32],
    ct56: &[u8; MEMO_CT_LEN],
    onchain_cm_be: &[u8; 32],
) -> Option<DecryptedMemo> {
    let vsec = X25519Sec::from(fvk.view_sk);
    let shared = vsec.diffie_hellman(&X25519Pub::from(*epk));
    let (exp_vt, key, nonce, tweak, blinding, dyn_mask) = derive_memo_secrets(shared.as_bytes());
    if exp_vt != view_tag {
        return None;
    }

    let cipher = ChaCha20Poly1305::new((&key).into());
    let candidate = if let Ok(plain) = cipher.decrypt(Nonce::from_slice(&nonce), ct56.as_slice()) {
        if plain.len() != 40 {
            return None;
        }
        let amount = u64::from_le_bytes(plain[0..8].try_into().unwrap());
        let mint: [u8; 32] = plain[8..40].try_into().unwrap();
        DecryptedMemo {
            tweak,
            blinding,
            amount,
            mint,
            is_dynamic: false,
        }
    } else {
        let mut unmasked = [0u8; MEMO_CT_LEN];
        for i in 0..MEMO_CT_LEN {
            unmasked[i] = ct56[i] ^ dyn_mask[i];
        }
        if unmasked[0..8] != DYN_MEMO_MAGIC {
            return None;
        }
        let amount = u64::from_le_bytes(unmasked[8..16].try_into().unwrap());
        let mint: [u8; 32] = unmasked[16..48].try_into().unwrap();
        DecryptedMemo {
            tweak,
            blinding,
            amount,
            mint,
            is_dynamic: true,
        }
    };

    let stealth = fvk.stealth_owner(candidate.tweak).ok()?;
    let asset_id = derive_asset_id(&candidate.mint);
    let expected_cm = compute_note_commitment(stealth, asset_id, candidate.amount, candidate.blinding);
    if fr_to_be_bytes(&expected_cm) != *onchain_cm_be {
        return None;
    }
    Some(candidate)
}
