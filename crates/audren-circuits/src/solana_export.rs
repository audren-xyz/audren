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

/// Canonical ceremony provenance string embedded in `program/src/vk_generated.rs`.
pub const CANONICAL_VK_PROVENANCE: &str = "Perpetual Powers of Tau (powersOfTau28_hez_final_15.ptau, 54 contributions + beacon) + Audren BGM17 Phase-2 Ceremony (drand Quicknet #34194203 & Solana Mainnet slot 472705896)";

/// Render the full `program/src/vk_generated.rs` file (shared identically by `gen_vk` and `ceremony`).
pub fn render_vk_generated_rs(
    vk: &VerifyingKey<Bn254>,
    pk_sha256: &str,
    provenance: &str,
) -> String {
    let mut src = String::new();
    src.push_str("//! Auto-generated VerifyingKey for Audren `JoinSplit4AryCircuit` (`vk_id = 0`).\n");
    src.push_str("//!\n");
    src.push_str(&format!("//! Provenance: {provenance}\n"));
    src.push_str(&format!("//! ProvingKey compressed SHA-256: `{pk_sha256}`\n"));
    src.push_str(
        "//! Phase 1: Official Hermez Perpetual Powers of Tau (`powersOfTau28_hez_final_15.ptau`,\n",
    );
    src.push_str(
        "//!          54 public contributions + beacon, BLAKE2b-512 `982372c8...69ae6e`, SHA-256 `3ef2ecc5...9e7f`).\n",
    );
    src.push_str("//! Phase 2: BGM17 Groth16 MPC ceremony (`ceremony/transcript.json`, verifiable via\n");
    src.push_str("//!          `cargo run -p audren-circuits --release --bin ceremony -- verify`).\n\n");
    src.push_str("#[allow(dead_code)]\n");
    src.push_str(&format!("pub const VK_PROVENANCE: &str = \"{provenance}\";\n"));
    src.push_str("#[allow(dead_code)]\n");
    src.push_str(&format!(
        "pub const PK_COMPRESSED_SHA256: &str = \"{pk_sha256}\";\n\n"
    ));
    src.push_str(&render_solana_vk_const("VK_JOINSPLIT_DEFAULT", vk));
    src
}

/// Render an Arkworks `VerifyingKey<Bn254>` into a Rust constant for `groth16-solana`.
pub fn render_solana_vk_const(const_name: &str, vk: &VerifyingKey<Bn254>) -> String {
    assert!(
        !vk.gamma_abc_g1.is_empty(),
        "VerifyingKey.gamma_abc_g1 must contain at least the constant term"
    );
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
