//! Frozen Canonical Note, Stealth Owner, Key-Separated Nullifier (`nk`), and Public Input Hash.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use audren_core::instruction::ASSET_ID_DOMAIN;
use sha2::{Digest, Sha256};

pub use audren_core::{
    DOMAIN_DUMMY_NF, DOMAIN_NK, DOMAIN_NOTE, DOMAIN_NULLIFIER, DOMAIN_PK, DOMAIN_PUB_HASH_A,
    DOMAIN_PUB_HASH_B, DOMAIN_PUB_HASH_FINAL, DOMAIN_STEALTH, WSOL_MINT,
};

use crate::poseidon::{poseidon2, poseidon3, poseidon4, poseidon5, poseidon_hash_var};

/// Deterministic canonical `asset_id` derived directly from a 32-byte Solana mint pubkey
/// (`WSOL_MINT` for SOL/WSOL, or any Classic SPL / Token-2022 mint address):
/// `asset_id = mask_to_fr_be(SHA-256("audren/v1/asset" || mint_32))`.
#[inline]
pub fn derive_asset_id(mint: &[u8; 32]) -> Fr {
    let mut h = Sha256::new();
    h.update(ASSET_ID_DOMAIN);
    h.update(mint);
    let digest: [u8; 32] = h.finalize().into();
    let masked = audren_core::mask_to_fr_be(digest);
    Fr::from_be_bytes_mod_order(&masked)
}

/// Derive canonical long-term spend public key: `spend_pk = Poseidon2(DOMAIN_PK, spend_sk)`.
#[inline]
pub fn derive_spend_pk(spend_sk: Fr) -> Fr {
    poseidon2(Fr::from(DOMAIN_PK), spend_sk)
}

/// Derive read-only nullifier key: `nk = Poseidon2(DOMAIN_NK, spend_sk)`.
#[inline]
pub fn derive_nullifier_key(spend_sk: Fr) -> Fr {
    poseidon2(Fr::from(DOMAIN_NK), spend_sk)
}

/// Derive one-time stealth owner pubkey: `stealth_owner = Poseidon3(DOMAIN_STEALTH, spend_pk, tweak)`.
#[inline]
pub fn derive_stealth_owner(spend_pk: Fr, tweak: Fr) -> Fr {
    poseidon3(Fr::from(DOMAIN_STEALTH), spend_pk, tweak)
}

/// Canonical multi-asset shielded note commitment:
/// `cm = Poseidon5(DOMAIN_NOTE, stealth_owner, asset_id, amount, blinding)`.
#[inline]
pub fn compute_note_commitment(
    stealth_owner: Fr,
    asset_id: Fr,
    amount: u64,
    blinding: Fr,
) -> Fr {
    poseidon5(
        Fr::from(DOMAIN_NOTE),
        stealth_owner,
        asset_id,
        Fr::from(amount),
        blinding,
    )
}

/// Canonical nullifier for a real spent note at global `leaf_index`:
/// `nullifier = Poseidon4(DOMAIN_NULLIFIER, nk, note_commitment, leaf_index)`.
#[inline]
pub fn compute_real_nullifier(nk: Fr, note_commitment: Fr, leaf_index: u64) -> Fr {
    poseidon4(
        Fr::from(DOMAIN_NULLIFIER),
        nk,
        note_commitment,
        Fr::from(leaf_index),
    )
}

/// Domain-separated dummy nullifier for an unused (`is_dummy == 1`) input slot in padded mode:
/// `dummy_nf = Poseidon3(DOMAIN_DUMMY_NF, nk, blinding)`.
#[inline]
pub fn compute_dummy_nullifier(nk: Fr, blinding: Fr) -> Fr {
    poseidon3(Fr::from(DOMAIN_DUMMY_NF), nk, blinding)
}

/// Pack `(public_amount_out: u64, relayer_fee_amount: u64)` injectively into one BN254 Fr element:
/// `packed = public_amount_out + relayer_fee_amount * 2^64`.
#[inline]
pub fn pack_public_amounts(public_amount_out: u64, relayer_fee_amount: u64) -> Fr {
    Fr::from(public_amount_out) + Fr::from(relayer_fee_amount) * Fr::from(1u128 << 64)
}

/// All public statement fields folded into the single Groth16 public input (`public_input_hash`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinSplitPublicInputs {
    pub super_root: Fr,
    pub nullifiers: [Fr; 2],
    pub out_commitments: [Fr; 3],
    pub public_asset_id: Fr,
    pub public_amount_out: u64,
    pub relayer_fee_amount: u64,
    pub ctx_hash: Fr,
}

impl JoinSplitPublicInputs {
    pub fn compute_hash(&self) -> Fr {
        let h_a = poseidon5(
            Fr::from(DOMAIN_PUB_HASH_A),
            self.super_root,
            self.nullifiers[0],
            self.nullifiers[1],
            self.out_commitments[0],
        );
        let h_b = poseidon5(
            Fr::from(DOMAIN_PUB_HASH_B),
            self.out_commitments[1],
            self.out_commitments[2],
            self.public_asset_id,
            pack_public_amounts(self.public_amount_out, self.relayer_fee_amount),
        );
        poseidon4(Fr::from(DOMAIN_PUB_HASH_FINAL), h_a, h_b, self.ctx_hash)
    }
}

/// R1CS gadget enforcing `value` fits strictly inside an unsigned 64-bit integer `[0, 2^64)`.
pub fn enforce_u64_range(
    cs: ConstraintSystemRef<Fr>,
    value: &FpVar<Fr>,
) -> Result<Vec<Boolean<Fr>>, SynthesisError> {
    let val_u64 = value
        .value()
        .map(|f| {
            let bytes = crate::poseidon::fr_to_be_bytes(&f);
            u64::from_be_bytes(bytes[24..32].try_into().unwrap())
        })
        .unwrap_or(0);

    let mut bits = Vec::with_capacity(64);
    let mut reconstructed = FpVar::Constant(Fr::from(0u64));
    let mut coeff = Fr::from(1u64);
    for i in 0..64 {
        let bit_val = ((val_u64 >> i) & 1) == 1;
        let bit = Boolean::new_witness(cs.clone(), || Ok(bit_val))?;
        reconstructed += FpVar::from(bit.clone()) * coeff;
        coeff.double_in_place();
        bits.push(bit);
    }
    value.enforce_equal(&reconstructed)?;
    Ok(bits)
}

/// R1CS gadget for canonical output note commitment with strict u64 range check.
pub fn constrain_canonical_note_output(
    cs: ConstraintSystemRef<Fr>,
    stealth_owner: &FpVar<Fr>,
    asset_id: &FpVar<Fr>,
    amount: &FpVar<Fr>,
    blinding: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let _ = enforce_u64_range(cs.clone(), amount)?;
    let dom_note = FpVar::Constant(Fr::from(DOMAIN_NOTE));
    poseidon_hash_var(
        cs,
        &[
            dom_note,
            stealth_owner.clone(),
            asset_id.clone(),
            amount.clone(),
            blinding.clone(),
        ],
    )
}

/// R1CS gadget folding public inputs into the single `public_input_hash`.
pub fn constrain_public_input_hash(
    cs: ConstraintSystemRef<Fr>,
    super_root: &FpVar<Fr>,
    nullifiers: &[FpVar<Fr>; 2],
    out_commitments: &[FpVar<Fr>; 3],
    public_asset_id: &FpVar<Fr>,
    packed_amounts: &FpVar<Fr>,
    ctx_hash: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let h_a = poseidon_hash_var(
        cs.clone(),
        &[
            FpVar::Constant(Fr::from(DOMAIN_PUB_HASH_A)),
            super_root.clone(),
            nullifiers[0].clone(),
            nullifiers[1].clone(),
            out_commitments[0].clone(),
        ],
    )?;
    let h_b = poseidon_hash_var(
        cs.clone(),
        &[
            FpVar::Constant(Fr::from(DOMAIN_PUB_HASH_B)),
            out_commitments[1].clone(),
            out_commitments[2].clone(),
            public_asset_id.clone(),
            packed_amounts.clone(),
        ],
    )?;
    poseidon_hash_var(
        cs,
        &[
            FpVar::Constant(Fr::from(DOMAIN_PUB_HASH_FINAL)),
            h_a,
            h_b,
            ctx_hash.clone(),
        ],
    )
}
