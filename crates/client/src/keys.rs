//! Key hierarchy, stealth note encryption (AES-256-GCM + PQ-ready envelope),
//! read-only `FullViewingKey` (Mode 2), per-transaction `SelectiveDisclosureProof` (Mode 1),
//! and `AuditorKeypair` (`PoolMode::InstitutionalAudited`).

use crate::prover::{
    asset_generator, compress, decompress, g_point, h_point, hash_to_scalar, nullifier_generator,
    Point,
};
use crate::ClientError;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use audren_core::layout::{NoteEntry, NOTE_CT_LEN};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use solana_sha256_hasher::hashv;

/// Plaintext flags encoded in the 48-byte AES-256-GCM note payload.
pub const NOTE_FLAG_BLINDED_ASSET: u8 = 1 << 0;
pub const NOTE_FLAG_BLINDED_VALUE: u8 = 1 << 1;
pub const NOTE_FLAG_DYNAMIC_ONCHAIN_VALUE: u8 = 1 << 2;

/// Post-quantum hybrid KEM envelope scheme identifiers (bound to `Transfer` transcript).
pub const PQ_ENVELOPE_NONE: u8 = 0;
pub const PQ_ENVELOPE_MLKEM768_READY: u8 = 1;

/// Full Audren shielded keypair derived deterministically from a 32-byte master seed.
#[derive(Clone)]
pub struct AudrenKeys {
    pub spend_sk: Scalar,
    pub spend_pk: Point,
    pub view_sk: Scalar,
    pub view_pk: Point,
}

impl AudrenKeys {
    /// Derive `(spend_sk, view_sk)` deterministically from a 32-byte wallet seed using HKDF-SHA256.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"audren/v1/root"), seed);

        let mut spend_wide = [0u8; 64];
        hk.expand(b"audren/v1/spend_sk", &mut spend_wide)
            .expect("64-byte HKDF expand");
        let spend_sk = Scalar::from_bytes_mod_order_wide(&spend_wide);

        let mut view_wide = [0u8; 64];
        hk.expand(b"audren/v1/view_sk", &mut view_wide)
            .expect("64-byte HKDF expand");
        let view_sk = Scalar::from_bytes_mod_order_wide(&view_wide);

        let spend_pk = compress(&(spend_sk * g_point()));
        let view_pk = compress(&(view_sk * g_point()));
        Self {
            spend_sk,
            spend_pk,
            view_sk,
            view_pk,
        }
    }

    /// Generate a fresh random Audren keypair.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Public stealth meta-address (accepts SOL, USDC, SPL, and safe Token-2022 in one address).
    pub fn address(&self) -> AudrenAddress {
        AudrenAddress {
            spend_pk: self.spend_pk,
            view_pk: self.view_pk,
        }
    }

    /// Export read-only `FullViewingKey` (zero spend capability; safe for accountants & tax tools).
    pub fn full_viewing_key(&self) -> FullViewingKey {
        FullViewingKey {
            spend_pk: self.spend_pk,
            view_sk: self.view_sk,
            view_pk: self.view_pk,
        }
    }
}

/// Shareable Audren stealth meta-address (`64 B` raw / base58 string).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudrenAddress {
    pub spend_pk: Point,
    pub view_pk: Point,
}

impl AudrenAddress {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.spend_pk);
        out[32..].copy_from_slice(&self.view_pk);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ClientError> {
        if bytes.len() != 64 {
            return Err(ClientError::InvalidEncoding("address must be 64 bytes"));
        }
        let mut spend_pk = [0u8; 32];
        let mut view_pk = [0u8; 32];
        spend_pk.copy_from_slice(&bytes[..32]);
        view_pk.copy_from_slice(&bytes[32..]);
        let _ = decompress(&spend_pk)?;
        let _ = decompress(&view_pk)?;
        Ok(Self { spend_pk, view_pk })
    }

    pub fn to_base58(&self) -> String {
        format!("aud1{}", bs58::encode(self.to_bytes()).into_string())
    }

    pub fn from_base58(encoded: &str) -> Result<Self, ClientError> {
        let body = encoded.strip_prefix("aud1").unwrap_or(encoded);
        let raw = bs58::decode(body)
            .into_vec()
            .map_err(|_| ClientError::InvalidEncoding("invalid base58 audren address"))?;
        Self::from_bytes(&raw)
    }
}

/// Mode 2: Exportable Read-Only Full Viewing Key (zero spend authority).
#[derive(Clone)]
pub struct FullViewingKey {
    pub spend_pk: Point,
    pub view_sk: Scalar,
    pub view_pk: Point,
}

impl FullViewingKey {
    pub fn to_export(&self) -> FullViewingKeyExport {
        FullViewingKeyExport {
            version: 1,
            spend_pk_b58: bs58::encode(self.spend_pk).into_string(),
            view_sk_b58: bs58::encode(self.view_sk.to_bytes()).into_string(),
            view_pk_b58: bs58::encode(self.view_pk).into_string(),
        }
    }

    pub fn from_export(exp: &FullViewingKeyExport) -> Result<Self, ClientError> {
        let spend_pk = decode_b58_32(&exp.spend_pk_b58)?;
        let view_sk_bytes = decode_b58_32(&exp.view_sk_b58)?;
        let view_pk = decode_b58_32(&exp.view_pk_b58)?;
        let view_sk = Option::from(Scalar::from_canonical_bytes(view_sk_bytes))
            .ok_or(ClientError::InvalidEncoding("non-canonical view_sk"))?;
        if compress(&(view_sk * g_point())) != view_pk {
            return Err(ClientError::InvalidEncoding("view_sk does not match view_pk"));
        }
        Ok(Self {
            spend_pk,
            view_sk,
            view_pk,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullViewingKeyExport {
    pub version: u8,
    pub spend_pk_b58: String,
    pub view_sk_b58: String,
    pub view_pk_b58: String,
}

/// Institutional Auditor Keypair (`PoolMode::InstitutionalAudited`).
#[derive(Clone)]
pub struct AuditorKeypair {
    pub auditor_sk: Scalar,
    pub auditor_pk: Point,
}

impl AuditorKeypair {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"audren/v1/auditor"), seed);
        let mut wide = [0u8; 64];
        hk.expand(b"audren/v1/auditor_sk", &mut wide)
            .expect("64-byte HKDF expand");
        let auditor_sk = Scalar::from_bytes_mod_order_wide(&wide);
        let auditor_pk = compress(&(auditor_sk * g_point()));
        Self {
            auditor_sk,
            auditor_pk,
        }
    }

    /// Decrypt `(S_1, S_2) = (r_s * G, P_l + r_s * K_aud)` to recover exact spent stealth pubkey `P_l`.
    pub fn decrypt_spent_pubkey(&self, s1: &Point, s2: &Point) -> Result<Point, ClientError> {
        let p1 = decompress(s1)?;
        let p2 = decompress(s2)?;
        Ok(compress(&(p2 - self.auditor_sk * p1)))
    }

    /// Decrypt `(M_1, M_2) = (r_m * G, G_mint + r_m * K_aud)` to recover exact hidden mint generator `G_mint`.
    pub fn decrypt_asset_generator(&self, m1: &Point, m2: &Point) -> Result<Point, ClientError> {
        let p1 = decompress(m1)?;
        let p2 = decompress(m2)?;
        Ok(compress(&(p2 - self.auditor_sk * p1)))
    }
}

/// Derived shared secret materials for a single stealth note.
pub struct StealthMaterial {
    pub ephemeral_pk: Point,
    pub stealth_pk: Point,
    pub stealth_scalar: Scalar,
    pub view_tag: u8,
    pub aes_key: [u8; 32],
    pub aes_nonce: [u8; 12],
    pub derived_asset_blinding: Scalar,
    pub derived_value_blinding: Scalar,
}

/// Compute all deterministic stealth note derivations from shared ECDH point `shared`.
pub fn derive_stealth_from_shared(
    recipient_spend_pk: &Point,
    ephemeral_pk: Point,
    shared: &RistrettoPoint,
) -> Result<StealthMaterial, ClientError> {
    let shared_bytes = compress(shared);
    let view_tag = hashv(&[b"audren/v1/view_tag", &shared_bytes]).to_bytes()[0];
    let stealth_scalar = hash_to_scalar(&[b"audren/v1/stealth_x", &shared_bytes]);
    let spend_pt = decompress(recipient_spend_pk)?;
    let stealth_pk = compress(&(spend_pt + stealth_scalar * g_point()));

    let hk = Hkdf::<Sha256>::new(Some(b"audren/v1/note_kdf"), &shared_bytes);
    let mut aes_key = [0u8; 32];
    hk.expand(b"aes256gcm_key", &mut aes_key)
        .expect("32-byte HKDF expand");
    let mut aes_nonce = [0u8; 12];
    hk.expand(b"aes256gcm_nonce", &mut aes_nonce)
        .expect("12-byte HKDF expand");

    let derived_asset_blinding = hash_to_scalar(&[b"audren/v1/note_a_blind", &shared_bytes]);
    let derived_value_blinding = hash_to_scalar(&[b"audren/v1/note_r_blind", &shared_bytes]);

    Ok(StealthMaterial {
        ephemeral_pk,
        stealth_pk,
        stealth_scalar,
        view_tag,
        aes_key,
        aes_nonce,
        derived_asset_blinding,
        derived_value_blinding,
    })
}

/// Sender-side stealth derivation using fresh ephemeral scalar `r_eph`.
pub fn derive_stealth_for_recipient<R: RngCore + CryptoRng>(
    recipient: &AudrenAddress,
    rng: &mut R,
) -> Result<StealthMaterial, ClientError> {
    let r_eph = Scalar::random(rng);
    let ephemeral_pk = compress(&(r_eph * g_point()));
    let view_pt = decompress(&recipient.view_pk)?;
    let shared = r_eph * view_pt;
    derive_stealth_from_shared(&recipient.spend_pk, ephemeral_pk, &shared)
}

/// Fast 1-byte `view_tag` check for zero-indexer `dataSlice` scanning (`255/256` rejection rate).
#[inline]
pub fn quick_view_tag_match(fvk: &FullViewingKey, ephemeral_pk: &Point, view_tag: u8) -> Option<RistrettoPoint> {
    let r_pt = decompress(ephemeral_pk).ok()?;
    let shared = fvk.view_sk * r_pt;
    let shared_bytes = compress(&shared);
    let expected = hashv(&[b"audren/v1/view_tag", &shared_bytes]).to_bytes()[0];
    if expected == view_tag {
        Some(shared)
    } else {
        None
    }
}

/// Decrypted stealth note payload (`48 B` plaintext -> `64 B` AES-256-GCM ciphertext).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecryptedPayload {
    pub mint: [u8; 32],
    pub amount: u64,
    pub flags: u8,
    pub memo_tag: [u8; 7],
}

/// Encrypt `(mint, amount, flags, memo_tag)` into `64 B` AES-256-GCM bound to `stealth_pk` as AAD.
pub fn encrypt_note_memo(
    mat: &StealthMaterial,
    payload: &DecryptedPayload,
) -> Result<[u8; NOTE_CT_LEN], ClientError> {
    let mut pt = [0u8; 48];
    pt[..32].copy_from_slice(&payload.mint);
    pt[32..40].copy_from_slice(&payload.amount.to_le_bytes());
    pt[40] = payload.flags;
    pt[41..48].copy_from_slice(&payload.memo_tag);

    let cipher = Aes256Gcm::new_from_slice(&mat.aes_key)
        .map_err(|_| ClientError::Crypto("aes key init failed"))?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&mat.aes_nonce),
            Payload {
                msg: &pt,
                aad: &mat.stealth_pk,
            },
        )
        .map_err(|_| ClientError::Crypto("aes encryption failed"))?;
    let mut out = [0u8; NOTE_CT_LEN];
    out.copy_from_slice(&ct);
    Ok(out)
}

/// Decrypt a `64 B` AES-256-GCM note memo using `StealthMaterial`.
pub fn decrypt_note_memo(
    mat: &StealthMaterial,
    ct: &[u8; NOTE_CT_LEN],
) -> Result<DecryptedPayload, ClientError> {
    let cipher = Aes256Gcm::new_from_slice(&mat.aes_key)
        .map_err(|_| ClientError::Crypto("aes key init failed"))?;
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&mat.aes_nonce),
            Payload {
                msg: ct.as_slice(),
                aad: &mat.stealth_pk,
            },
        )
        .map_err(|_| ClientError::Crypto("note decryption failed"))?;
    if pt.len() != 48 {
        return Err(ClientError::Crypto("unexpected plaintext len"));
    }
    let mut mint = [0u8; 32];
    mint.copy_from_slice(&pt[..32]);
    let amount = u64::from_le_bytes(pt[32..40].try_into().unwrap());
    let flags = pt[40];
    let mut memo_tag = [0u8; 7];
    memo_tag.copy_from_slice(&pt[41..48]);
    Ok(DecryptedPayload {
        mint,
        amount,
        flags,
        memo_tag,
    })
}

/// Fully constructed note ready to send on-chain plus its secret openings.
#[derive(Clone)]
pub struct PreparedNote {
    pub entry: NoteEntry,
    pub mint: [u8; 32],
    pub amount: u64,
    pub asset_blinding: Scalar,
    pub value_blinding: Scalar,
    pub stealth_scalar: Scalar,
}

/// Prepare a shielded stealth note (`Deposit` / `Transfer` / `Merge` / `Change`).
pub fn prepare_shielded_note<R: RngCore + CryptoRng>(
    recipient: &AudrenAddress,
    mint: [u8; 32],
    amount: u64,
    blind_asset: bool,
    forced_asset_blinding: Option<Scalar>,
    blind_value: bool,
    memo_tag: [u8; 7],
    rng: &mut R,
) -> Result<PreparedNote, ClientError> {
    let mat = derive_stealth_for_recipient(recipient, rng)?;
    let g_mint = decompress(&asset_generator(&mint))?;

    let asset_blinding = if !blind_asset {
        Scalar::ZERO
    } else {
        forced_asset_blinding.unwrap_or(mat.derived_asset_blinding)
    };
    let a_pt = g_mint + asset_blinding * h_point();
    let asset_tag = compress(&a_pt);

    let value_blinding = if blind_value {
        mat.derived_value_blinding
    } else {
        Scalar::ZERO
    };
    let v_pt = Scalar::from(amount) * a_pt + value_blinding * h_point();
    let commitment = compress(&v_pt);

    let mut flags = 0u8;
    if blind_asset {
        flags |= NOTE_FLAG_BLINDED_ASSET;
    }
    if blind_value {
        flags |= NOTE_FLAG_BLINDED_VALUE;
    }

    let encrypted_memo = encrypt_note_memo(
        &mat,
        &DecryptedPayload {
            mint,
            amount,
            flags,
            memo_tag,
        },
    )?;

    Ok(PreparedNote {
        entry: NoteEntry {
            view_tag: mat.view_tag,
            ephemeral_pk: mat.ephemeral_pk,
            stealth_pk: mat.stealth_pk,
            asset_tag,
            commitment,
            ciphertext: encrypted_memo,
        },
        mint,
        amount,
        asset_blinding,
        value_blinding,
        stealth_scalar: mat.stealth_scalar,
    })
}

/// Prepare a dynamic output descriptor for `SwapViaRouter` (where `actual_out` is committed on-chain).
pub struct PreparedDynamicOutput {
    pub view_tag: u8,
    pub ephemeral_pk: Point,
    pub stealth_pk: Point,
    pub encrypted_memo: [u8; NOTE_CT_LEN],
    pub stealth_scalar: Scalar,
}

pub fn prepare_dynamic_swap_output<R: RngCore + CryptoRng>(
    recipient: &AudrenAddress,
    mint_out: [u8; 32],
    min_amount_out: u64,
    memo_tag: [u8; 7],
    rng: &mut R,
) -> Result<PreparedDynamicOutput, ClientError> {
    let mat = derive_stealth_for_recipient(recipient, rng)?;
    let encrypted_memo = encrypt_note_memo(
        &mat,
        &DecryptedPayload {
            mint: mint_out,
            amount: min_amount_out,
            flags: NOTE_FLAG_DYNAMIC_ONCHAIN_VALUE,
            memo_tag,
        },
    )?;
    Ok(PreparedDynamicOutput {
        view_tag: mat.view_tag,
        ephemeral_pk: mat.ephemeral_pk,
        stealth_pk: mat.stealth_pk,
        encrypted_memo,
        stealth_scalar: mat.stealth_scalar,
    })
}

/// Compute a note's unique deterministic spend nullifier `J = x^{-1} * U`.
pub fn compute_note_nullifier(spend_sk: &Scalar, stealth_scalar: &Scalar) -> Result<(Scalar, Point), ClientError> {
    let x = spend_sk + stealth_scalar;
    if x == Scalar::ZERO {
        return Err(ClientError::Crypto("degenerate zero stealth spend key"));
    }
    let u = decompress(&nullifier_generator())?;
    let j = compress(&(x.invert() * u));
    Ok((x, j))
}

/// Mode 1: Selective Per-Transaction Disclosure Proof (zero keys revealed).
/// Proves to any third party that on-chain note `(stealth_pk, asset_tag, commitment)`
/// holds exact `(mint, amount)` without disclosing any other notes or keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SelectiveDisclosureProof {
    pub version: u8,
    pub page_id: u64,
    pub slot_index: u8,
    pub stealth_pk_b58: String,
    pub asset_tag_b58: String,
    pub commitment_b58: String,
    pub mint_b58: String,
    pub amount: u64,
    pub asset_blinding_b58: String,
    pub value_blinding_b58: String,
}

impl SelectiveDisclosureProof {
    /// Independently verify a selective disclosure proof against on-chain note points.
    pub fn verify(&self) -> Result<bool, ClientError> {
        let a_pt = decompress(&decode_b58_32(&self.asset_tag_b58)?)?;
        let v_pt = decompress(&decode_b58_32(&self.commitment_b58)?)?;
        let mint = decode_b58_32(&self.mint_b58)?;
        let a_blind: Scalar = Option::from(Scalar::from_canonical_bytes(decode_b58_32(
            &self.asset_blinding_b58,
        )?))
        .ok_or(ClientError::InvalidEncoding("non-canonical asset_blinding"))?;
        let v_blind: Scalar = Option::from(Scalar::from_canonical_bytes(decode_b58_32(
            &self.value_blinding_b58,
        )?))
        .ok_or(ClientError::InvalidEncoding("non-canonical value_blinding"))?;

        let g_mint = decompress(&asset_generator(&mint))?;
        let expected_a = g_mint + a_blind * h_point();
        let expected_v = Scalar::from(self.amount) * expected_a + v_blind * h_point();
        Ok(expected_a == a_pt && expected_v == v_pt)
    }
}

pub(crate) fn decode_b58_32(s: &str) -> Result<[u8; 32], ClientError> {
    let raw = bs58::decode(s)
        .into_vec()
        .map_err(|_| ClientError::InvalidEncoding("invalid base58"))?;
    if raw.len() != 32 {
        return Err(ClientError::InvalidEncoding("expected 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}
