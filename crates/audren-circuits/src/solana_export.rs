//! Arkworks BN254 Groth16 -> Solana `groth16-solana` 0.3.1 wire & VerifyingKey conversion.

use ark_bn254::{Bn254, Fq, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use core::ops::Neg;

fn fq_to_be(f: &Fq) -> [u8; 32] {
    let bytes = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

pub fn g1_to_be_uncompressed(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&fq_to_be(&p.x));
    out[32..64].copy_from_slice(&fq_to_be(&p.y));
    out
}

pub fn g1_to_be_compressed(p: &G1Affine) -> [u8; 32] {
    let mut le = [0u8; 32];
    p.serialize_compressed(&mut le[..]).expect("g1 compress");
    le.reverse();
    le
}

pub fn g2_to_be_uncompressed(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    out[0..32].copy_from_slice(&fq_to_be(&p.x.c1));
    out[32..64].copy_from_slice(&fq_to_be(&p.x.c0));
    out[64..96].copy_from_slice(&fq_to_be(&p.y.c1));
    out[96..128].copy_from_slice(&fq_to_be(&p.y.c0));
    out
}

/// Encode an Arkworks Groth16 proof into the **192-byte** compressed wire format:
/// `(-A)_compressed_be[32] || B_be[128] || C_compressed_be[32]`.
pub fn proof_to_solana_compressed_192(proof: &Proof<Bn254>) -> [u8; 192] {
    let mut out = [0u8; 192];
    let neg_a = proof.a.neg();
    out[0..32].copy_from_slice(&g1_to_be_compressed(&neg_a));
    out[32..160].copy_from_slice(&g2_to_be_uncompressed(&proof.b));
    out[160..192].copy_from_slice(&g1_to_be_compressed(&proof.c));
    out
}

/// Render an Arkworks `VerifyingKey<Bn254>` into a Rust constant for `groth16-solana`.
pub fn render_solana_vk_const(const_name: &str, vk: &VerifyingKey<Bn254>) -> String {
    let nr_pubinputs = vk.gamma_abc_g1.len() - 1;
    let alpha = g1_to_be_uncompressed(&vk.alpha_g1);
    let beta = g2_to_be_uncompressed(&vk.beta_g2);
    let gamma = g2_to_be_uncompressed(&vk.gamma_g2);
    let delta = g2_to_be_uncompressed(&vk.delta_g2);
    let ic: Vec<[u8; 64]> = vk.gamma_abc_g1.iter().map(g1_to_be_uncompressed).collect();

    let fmt_arr = |bytes: &[u8]| -> String {
        let inner: Vec<String> = bytes.iter().map(|b| format!("{b}u8")).collect();
        format!("[{}]", inner.join(", "))
    };

    let mut out = String::new();
    out.push_str(&format!("pub const {const_name}_IC: &[[u8; 64]] = &[\n"));
    for pt in &ic {
        out.push_str(&format!("    {},\n", fmt_arr(pt)));
    }
    out.push_str("];\n\n");
    out.push_str(&format!(
        "pub const {const_name}: groth16_solana::groth16::Groth16Verifyingkey<'static> = groth16_solana::groth16::Groth16Verifyingkey {{\n"
    ));
    out.push_str(&format!("    nr_pubinputs: {nr_pubinputs},\n"));
    out.push_str(&format!("    vk_alpha_g1: {},\n", fmt_arr(&alpha)));
    out.push_str(&format!("    vk_beta_g2: {},\n", fmt_arr(&beta)));
    out.push_str(&format!("    vk_gamma_g2: {},\n", fmt_arr(&gamma)));
    out.push_str(&format!("    vk_delta_g2: {},\n", fmt_arr(&delta)));
    out.push_str(&format!("    vk_ic: {const_name}_IC,\n"));
    out.push_str("    vk_commitment: None,\n");
    out.push_str("};\n");
    out
}
