//! Exact Circom / Solana `sol_poseidon` BN254 x^5 Poseidon hash — both native and R1CS gadgets.
//!
//! Uses `light_poseidon::parameters::bn254_x5::get_poseidon_parameters::<Fr>(width)` so every
//! hash computed natively and constrained in R1CS matches Solana's on-chain `sol_poseidon`
//! syscall (`Parameters::Bn254X5`, `Endianness::BigEndian`) 100% bit-for-bit.

use std::sync::OnceLock;

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::{fp::FpVar, FieldVar},
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use light_poseidon::{
    parameters::bn254_x5::get_poseidon_parameters, PoseidonParameters,
};

static POSEIDON_PARAMS_CACHE: [OnceLock<PoseidonParameters<Fr>>; 12] =
    [const { OnceLock::new() }; 12];

/// Return cached Circom BN254 `x^5` Poseidon parameters for `width` (`2..=13`, i.e., `1..=12` inputs).
#[inline]
fn cached_poseidon_parameters(width: usize) -> &'static PoseidonParameters<Fr> {
    assert!(
        (2..=13).contains(&width),
        "sol_poseidon supports width 2..=13 (1..=12 inputs), got {width}"
    );
    POSEIDON_PARAMS_CACHE[width - 2].get_or_init(|| {
        get_poseidon_parameters::<Fr>(width as u8).expect("supported poseidon width")
    })
}

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

/// Native Poseidon hash over `inputs` (1..=12 inputs), matching `sol_poseidon` bit-for-bit.
/// Uses cached `OnceLock` parameters with zero per-call heap allocations or parameter rebuilds.
pub fn poseidon_hash(inputs: &[Fr]) -> Fr {
    assert!(
        !inputs.is_empty() && inputs.len() <= 12,
        "sol_poseidon supports 1..=12 inputs, got {}",
        inputs.len()
    );
    let width = inputs.len() + 1;
    let params = cached_poseidon_parameters(width);

    let mut state = [Fr::from(0u64); 13];
    let mut next = [Fr::from(0u64); 13];
    state[1..width].copy_from_slice(inputs);

    let half_rounds = params.full_rounds / 2;
    let all_rounds = params.full_rounds + params.partial_rounds;

    #[inline(always)]
    fn sbox_x5(a: Fr) -> Fr {
        let x2 = a.square();
        let x4 = x2.square();
        x4 * a
    }

    for round in 0..all_rounds {
        let ark_base = round * width;
        for (i, slot) in state[..width].iter_mut().enumerate() {
            *slot += params.ark[ark_base + i];
        }
        if round < half_rounds || round >= half_rounds + params.partial_rounds {
            for slot in &mut state[..width] {
                *slot = sbox_x5(*slot);
            }
        } else {
            state[0] = sbox_x5(state[0]);
        }
        for (r, mds_row) in params.mds.iter().enumerate().take(width) {
            let mut acc = Fr::from(0u64);
            for (c, &coeff) in mds_row.iter().enumerate().take(width) {
                acc += state[c] * coeff;
            }
            next[r] = acc;
        }
        state[..width].copy_from_slice(&next[..width]);
    }

    state[0]
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
    let params: &PoseidonParameters<Fr> = cached_poseidon_parameters(width);

    let mut state: Vec<FpVar<Fr>> = Vec::with_capacity(width);
    state.push(FpVar::new_constant(cs, Fr::from(0u64))?);
    for inp in inputs {
        state.push(inp.clone());
    }

    let half_rounds = params.full_rounds / 2;
    let all_rounds = params.full_rounds + params.partial_rounds;

    let apply_mds = |st: &[FpVar<Fr>]| -> Vec<FpVar<Fr>> {
        let mut next = Vec::with_capacity(width);
        for mds_row in params.mds.iter().take(width) {
            let mut acc = FpVar::Constant(Fr::from(0u64));
            for (st_col, &coeff) in st.iter().zip(mds_row.iter()).take(width) {
                acc += st_col * coeff;
            }
            next.push(acc);
        }
        next
    };

    for round in 0..all_rounds {
        for (i, slot) in state.iter_mut().enumerate().take(width) {
            let c = params.ark[round * width + i];
            *slot += FpVar::Constant(c);
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
