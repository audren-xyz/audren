//! Exact Circom / Solana `sol_poseidon` BN254 x^5 Poseidon hash — both native and R1CS gadgets.
//!
//! Uses `light_poseidon::parameters::bn254_x5::get_poseidon_parameters::<Fr>(width)` so every
//! hash computed natively and constrained in R1CS matches Solana's on-chain `sol_poseidon`
//! syscall (`Parameters::Bn254X5`, `Endianness::BigEndian`) 100% bit-for-bit.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::{fp::FpVar, FieldVar},
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use light_poseidon::{
    parameters::bn254_x5::get_poseidon_parameters, Poseidon, PoseidonHasher, PoseidonParameters,
};

/// Convert an `Fr` element to its 32-byte canonical big-endian representation
/// (exact wire format expected by `sol_poseidon` and `groth16-solana`).
#[inline]
pub fn fr_to_be_bytes(f: &Fr) -> [u8; 32] {
    let bytes = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Parse a 32-byte canonical big-endian BN254 scalar field element, rejecting values >= modulus.
#[inline]
pub fn fr_from_be_bytes_strict(bytes: &[u8; 32]) -> Option<Fr> {
    if !audren_core::is_canonical_fr(bytes) {
        return None;
    }
    Some(Fr::from_be_bytes_mod_order(bytes))
}

/// Map arbitrary 32 bytes (e.g. a SHA-256 `ctx_hash` or Solana mint digest) into `Fr`
/// by masking the top 3 bits to guarantee `< r`, matching on-chain `mask_to_fr_be` bit-for-bit.
#[inline]
pub fn bytes32_to_fr_masked(bytes: &[u8; 32]) -> Fr {
    let masked = audren_core::mask_to_fr_be(*bytes);
    Fr::from_be_bytes_mod_order(&masked)
}

/// Native Poseidon hash over `inputs` (1..=12 inputs), matching `sol_poseidon` bit-for-bit.
pub fn poseidon_hash(inputs: &[Fr]) -> Fr {
    assert!(
        !inputs.is_empty() && inputs.len() <= 12,
        "sol_poseidon supports 1..=12 inputs, got {}",
        inputs.len()
    );
    let mut hasher = Poseidon::<Fr>::new_circom(inputs.len()).expect("valid circom width");
    hasher.hash(inputs).expect("poseidon hash")
}

#[inline]
pub fn poseidon2(a: Fr, b: Fr) -> Fr {
    poseidon_hash(&[a, b])
}

#[inline]
pub fn poseidon3(a: Fr, b: Fr, c: Fr) -> Fr {
    poseidon_hash(&[a, b, c])
}

#[inline]
pub fn poseidon4(a: Fr, b: Fr, c: Fr, d: Fr) -> Fr {
    poseidon_hash(&[a, b, c, d])
}

#[inline]
pub fn poseidon5(a: Fr, b: Fr, c: Fr, d: Fr, e: Fr) -> Fr {
    poseidon_hash(&[a, b, c, d, e])
}

/// R1CS S-box `x^5` in exactly 3 constraints: `x2 = x*x`, `x4 = x2*x2`, `x5 = x4*x`.
#[inline]
fn sbox_var(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let x2 = x.square()?;
    let x4 = x2.square()?;
    Ok(x4 * x)
}

/// In-circuit R1CS Poseidon hash matching `light_poseidon::Poseidon::new_circom(inputs.len())`
/// and Solana's `sol_poseidon` syscall bit-for-bit.
pub fn poseidon_hash_var(
    cs: ConstraintSystemRef<Fr>,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let width = inputs.len() + 1;
    let params: PoseidonParameters<Fr> =
        get_poseidon_parameters::<Fr>(width as u8).expect("supported poseidon width");

    let mut state: Vec<FpVar<Fr>> = Vec::with_capacity(width);
    state.push(FpVar::new_constant(cs, Fr::from(0u64))?);
    for inp in inputs {
        state.push(inp.clone());
    }

    let half_rounds = params.full_rounds / 2;
    let all_rounds = params.full_rounds + params.partial_rounds;

    let apply_mds = |st: &[FpVar<Fr>]| -> Vec<FpVar<Fr>> {
        let mut next = Vec::with_capacity(width);
        for row in 0..width {
            let mut acc = FpVar::Constant(Fr::from(0u64));
            for col in 0..width {
                let coeff = params.mds[row][col];
                acc += &st[col] * coeff;
            }
            next.push(acc);
        }
        next
    };

    for round in 0..all_rounds {
        for i in 0..width {
            let c = params.ark[round * width + i];
            state[i] += FpVar::Constant(c);
        }

        if round < half_rounds || round >= half_rounds + params.partial_rounds {
            for s in state.iter_mut() {
                *s = sbox_var(s)?;
            }
        } else {
            state[0] = sbox_var(&state[0])?;
        }

        state = apply_mds(&state);
    }

    Ok(state[0].clone())
}
