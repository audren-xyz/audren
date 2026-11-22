//! Audren Groth16 Phase-2 MPC Ceremony Tool (BGM17 over Perpetual Powers of Tau).
//!
//! Independently verifiable Phase-2 Groth16 trusted setup for the frozen
//! `JoinSplit4AryCircuit` (`17,861` R1CS, `2^15 = 32,768` FFT domain, BN254):
//!
//!   1. `init`       — Parses & pairing-verifies official Hermez/PSE Perpetual Powers of Tau
//!                     (`powersOfTau28_hez_final_15.ptau`, 71+ public contributors), transforms
//!                     monomial powers into `ark-bn254` `LibsnarkReduction` Lagrange QAP form,
//!                     and writes `phase2_0000.pk`.
//!   2. `contribute` — Applies a BGM17 Phase-2 contribution (`delta_k` from OS CSPRNG), emits
//!                     Schnorr PoK + pairing-verifiable transition receipt JSON, and zeroizes
//!                     all secret scalars from RAM immediately.
//!   3. `beacon`     — Applies a deterministic, publicly verifiable final beacon contribution
//!                     derived via `2^20` sequential SHA-256 iterations over a live drand
//!                     League of Entropy round + Solana Mainnet finalized blockhash.
//!   4. `verify`     — Independently verifies `.ptau` -> `init` -> every contribution -> beacon
//!                     via BN254 pairing checks (including Fiat-Shamir random linear combination
//!                     checks over ALL `l_query` and `h_query` elements) + live Groth16 proof test.
//!   5. `export`     — Exports the verified `ProvingKey<Bn254>` verifying key into
//!                     `program/src/vk_generated.rs` (`groth16-solana` `alt_bn128` wire format).

use std::{
    env, fs,
    path::Path,
    sync::atomic::{compiler_fence, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use audren_circuits::{
    deserialize_pk_compressed,
    joinsplit::JoinSplit4AryCircuit,
    prove_joinsplit,
    solana_export::{proof_to_solana_compressed_192, render_solana_vk_const},
    verify_joinsplit_offchain,
};
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};

/// Expected SHA-256 of official Hermez / Perpetual Powers of Tau `powersOfTau28_hez_final_15.ptau`
/// (BLAKE2b-512 `982372c867d229c236091f767e703253249a9b432c1710b4f326306bfa2428a17b06240359606cfe4d580b10a5a1f63fbed499527069c18ae17060472969ae6e`).
const EXPECTED_PTAU_SHA256: &str =
    "3ef2ecc5b75d687048cf2d59195119b42fb07c5af639c5f283d84bfa69829e7f";
const EXPECTED_DOMAIN_SIZE: usize = 32_768; // 2^15
const EXPECTED_CONSTRAINTS: usize = 17_861;
const BEACON_SHA256_ITERATIONS: usize = 1 << 20; // 1,048,576 sequential SHA-256 delay steps

fn sha256_hex(bytes: &[u8]) -> String {
    let h = Sha256::digest(bytes);
    hex_encode(&h)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(s.len() % 2 == 0, "odd hex length");
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char).to_digit(16).expect("hex") as u8;
        let lo = (b[i + 1] as char).to_digit(16).expect("hex") as u8;
        out.push((hi << 4) | lo);
    }
    out
}

fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

fn zeroize_fr(val: &mut Fr) {
    unsafe { std::ptr::write_volatile(val as *mut Fr, Fr::zero()) };
    compiler_fence(Ordering::SeqCst);
}

/// Computes `R^{-1} mod p` where `R = 2^256 mod p` so Montgomery-encoded `.ptau` coordinates
/// convert cleanly and portably into standard `ark_bn254::Fq` elements.
fn bn254_fq_r_inv() -> Fq {
    // 2^256 mod p = (2^128 mod p)^2
    let two_64 = Fq::from(1u128 << 64);
    let two_128 = two_64 * two_64;
    let two_256 = two_128 * two_128;
    two_256.inverse().expect("2^256 invertible mod p")
}

fn read_ptau_fq(slice: &[u8], r_inv: Fq) -> Fq {
    assert_eq!(slice.len(), 32);
    Fq::from_le_bytes_mod_order(slice) * r_inv
}

fn read_ptau_g1(slice: &[u8], r_inv: Fq) -> G1Affine {
    assert_eq!(slice.len(), 64);
    let x = read_ptau_fq(&slice[0..32], r_inv);
    let y = read_ptau_fq(&slice[32..64], r_inv);
    if x.is_zero() && y.is_zero() {
        return G1Affine::identity();
    }
    let pt = G1Affine::new_unchecked(x, y);
    assert!(
        pt.is_on_curve() && pt.is_in_correct_subgroup_assuming_on_curve(),
        "invalid BN254 G1 point in .ptau"
    );
    pt
}

fn read_ptau_g2(slice: &[u8], r_inv: Fq) -> G2Affine {
    assert_eq!(slice.len(), 128);
    let x = Fq2::new(
        read_ptau_fq(&slice[0..32], r_inv),
        read_ptau_fq(&slice[32..64], r_inv),
    );
    let y = Fq2::new(
        read_ptau_fq(&slice[64..96], r_inv),
        read_ptau_fq(&slice[96..128], r_inv),
    );
    if x.is_zero() && y.is_zero() {
        return G2Affine::identity();
    }
    let pt = G2Affine::new_unchecked(x, y);
    assert!(
        pt.is_on_curve() && pt.is_in_correct_subgroup_assuming_on_curve(),
        "invalid BN254 G2 point in .ptau"
    );
    pt
}

struct ParsedPtau {
    sha256: String,
    tau_g1: Vec<G1Affine>,       // 2*N - 1 points
    tau_g2: Vec<G2Affine>,       // N points
    alpha_tau_g1: Vec<G1Affine>, // N points
    beta_tau_g1: Vec<G1Affine>,  // N points
    beta_g2: G2Affine,
}

fn parse_and_verify_ptau(path: &Path) -> ParsedPtau {
    let data = fs::read(path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let sha256 = sha256_hex(&data);
    assert_eq!(
        sha256, EXPECTED_PTAU_SHA256,
        ".ptau SHA-256 mismatch!\n  got: {sha256}\n  exp: {EXPECTED_PTAU_SHA256}"
    );
    assert_eq!(&data[0..4], b"ptau", "invalid .ptau magic");
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let nsec = u32::from_le_bytes(data[8..12].try_into().unwrap());
    assert_eq!(version, 1, "expected .ptau version 1");

    let mut off = 12usize;
    let mut sections = std::collections::HashMap::<u32, (usize, usize)>::new();
    for _ in 0..nsec {
        let sid = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let slen = u64::from_le_bytes(data[off + 4..off + 12].try_into().unwrap()) as usize;
        off += 12;
        sections.insert(sid, (off, slen));
        off += slen;
    }

    let (s1_off, _) = sections[&1];
    let n8 = u32::from_le_bytes(data[s1_off..s1_off + 4].try_into().unwrap()) as usize;
    assert_eq!(n8, 32, "expected 32-byte BN254 field elements");
    let power = u32::from_le_bytes(data[s1_off + 4 + n8..s1_off + 8 + n8].try_into().unwrap());
    assert_eq!(power, 15, "expected power=15 (2^15 = 32,768)");

    let n = 1usize << power;
    assert_eq!(n, EXPECTED_DOMAIN_SIZE);
    let r_inv = bn254_fq_r_inv();

    let (s2_off, s2_len) = sections[&2];
    assert_eq!(s2_len, (2 * n - 1) * 64);
    let tau_g1: Vec<G1Affine> = (0..(2 * n - 1))
        .map(|i| read_ptau_g1(&data[s2_off + i * 64..s2_off + (i + 1) * 64], r_inv))
        .collect();

    let (s3_off, s3_len) = sections[&3];
    assert_eq!(s3_len, n * 128);
    let tau_g2: Vec<G2Affine> = (0..n)
        .map(|i| read_ptau_g2(&data[s3_off + i * 128..s3_off + (i + 1) * 128], r_inv))
        .collect();

    let (s4_off, s4_len) = sections[&4];
    assert_eq!(s4_len, n * 64);
    let alpha_tau_g1: Vec<G1Affine> = (0..n)
        .map(|i| read_ptau_g1(&data[s4_off + i * 64..s4_off + (i + 1) * 64], r_inv))
        .collect();

    let (s5_off, s5_len) = sections[&5];
    assert_eq!(s5_len, n * 64);
    let beta_tau_g1: Vec<G1Affine> = (0..n)
        .map(|i| read_ptau_g1(&data[s5_off + i * 64..s5_off + (i + 1) * 64], r_inv))
        .collect();

    let (s6_off, s6_len) = sections[&6];
    assert_eq!(s6_len, 128);
    let beta_g2 = read_ptau_g2(&data[s6_off..s6_off + 128], r_inv);

    // Pairing self-verification of parsed Powers of Tau points
    assert_eq!(tau_g1[0], G1Affine::generator(), "tauG1[0] != G1 generator");
    assert_eq!(tau_g2[0], G2Affine::generator(), "tauG2[0] != G2 generator");
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    assert_eq!(
        Bn254::pairing(tau_g1[1], g2),
        Bn254::pairing(g1, tau_g2[1]),
        "tauG1[1] / tauG2[1] pairing mismatch"
    );
    for &k in &[2usize, 17, 1024, n - 1, 2 * n - 2] {
        assert_eq!(
            Bn254::pairing(tau_g1[k], g2),
            Bn254::pairing(tau_g1[k - 1], tau_g2[1]),
            "tauG1[{k}] power pairing mismatch"
        );
    }
    assert_eq!(
        Bn254::pairing(alpha_tau_g1[0], tau_g2[1]),
        Bn254::pairing(alpha_tau_g1[1], g2),
        "alphaTauG1 pairing mismatch"
    );
    assert_eq!(
        Bn254::pairing(beta_tau_g1[0], g2),
        Bn254::pairing(g1, beta_g2),
        "betaG1 / betaG2 pairing mismatch"
    );
    assert_eq!(
        Bn254::pairing(beta_tau_g1[0], tau_g2[1]),
        Bn254::pairing(beta_tau_g1[1], g2),
        "betaTauG1 pairing mismatch"
    );

    ParsedPtau {
        sha256,
        tau_g1,
        tau_g2,
        alpha_tau_g1,
        beta_tau_g1,
        beta_g2,
    }
}

/// Deterministic Phase-2 initialization from verified Perpetual Powers of Tau + frozen
/// `JoinSplit4AryCircuit` using exact `ark_groth16::r1cs_to_qap::LibsnarkReduction` equations.
fn build_initial_phase2_pk(ptau: &ParsedPtau) -> ProvingKey<Bn254> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    JoinSplit4AryCircuit::empty_for_setup()
        .generate_constraints(cs.clone())
        .expect("circuit setup synthesis failed");
    cs.finalize();

    let num_constraints = cs.num_constraints();
    let num_instance = cs.num_instance_variables();
    let num_witness = cs.num_witness_variables();
    assert_eq!(num_constraints, EXPECTED_CONSTRAINTS);
    assert_eq!(num_instance, 2); // [1, public_input_hash]

    let domain = GeneralEvaluationDomain::<Fr>::new(num_constraints + num_instance)
        .expect("domain creation failed");
    let n = domain.size();
    assert_eq!(n, EXPECTED_DOMAIN_SIZE);

    let matrices = cs.to_matrices().expect("R1CS matrices");
    let qap_num_vars = (num_instance - 1) + num_witness;
    let total_vars = qap_num_vars + 1;

    // Transform monomial Powers of Tau into exact ark-bn254 Lagrange basis via IFFT on curve points.
    let mut lag_g1: Vec<G1Projective> = ptau.tau_g1[..n].iter().map(|p| p.into_group()).collect();
    domain.ifft_in_place(&mut lag_g1);

    let mut lag_g2: Vec<G2Projective> = ptau.tau_g2[..n].iter().map(|p| p.into_group()).collect();
    domain.ifft_in_place(&mut lag_g2);

    let mut alpha_lag_g1: Vec<G1Projective> =
        ptau.alpha_tau_g1[..n].iter().map(|p| p.into_group()).collect();
    domain.ifft_in_place(&mut alpha_lag_g1);

    let mut beta_lag_g1: Vec<G1Projective> =
        ptau.beta_tau_g1[..n].iter().map(|p| p.into_group()).collect();
    domain.ifft_in_place(&mut beta_lag_g1);

    // Accumulate exact LibsnarkReduction polynomials in the exponent:
    //   a[index]    = sum_i A[i][index] * L_i(tau)  (+ L_{num_constraints + k}(tau) for k in 0..num_instance)
    //   b[index]    = sum_i B[i][index] * L_i(tau)
    //   c[index]    = sum_i C[i][index] * L_i(tau)
    //   ic_l[index] = beta * a[index] + alpha * b[index] + c[index]
    let mut a_g1 = vec![G1Projective::zero(); total_vars];
    let mut b_g1 = vec![G1Projective::zero(); total_vars];
    let mut b_g2 = vec![G2Projective::zero(); total_vars];
    let mut abc_g1 = vec![G1Projective::zero(); total_vars];

    for k in 0..num_instance {
        a_g1[k] += lag_g1[num_constraints + k];
        abc_g1[k] += beta_lag_g1[num_constraints + k];
    }

    for i in 0..num_constraints {
        let li_g1 = lag_g1[i];
        let li_g2 = lag_g2[i];
        let a_li = alpha_lag_g1[i];
        let b_li = beta_lag_g1[i];

        for &(coeff, idx) in &matrices.a[i] {
            if coeff.is_one() {
                a_g1[idx] += li_g1;
                abc_g1[idx] += b_li;
            } else {
                a_g1[idx] += li_g1 * coeff;
                abc_g1[idx] += b_li * coeff;
            }
        }
        for &(coeff, idx) in &matrices.b[i] {
            if coeff.is_one() {
                b_g1[idx] += li_g1;
                b_g2[idx] += li_g2;
                abc_g1[idx] += a_li;
            } else {
                b_g1[idx] += li_g1 * coeff;
                b_g2[idx] += li_g2 * coeff;
                abc_g1[idx] += a_li * coeff;
            }
        }
        for &(coeff, idx) in &matrices.c[i] {
            if coeff.is_one() {
                abc_g1[idx] += li_g1;
            } else {
                abc_g1[idx] += li_g1 * coeff;
            }
        }
    }

    // H-query: h_j = [(tau^N - 1) * tau^j]_1 = [tau^{N+j}]_1 - [tau^j]_1 for j in 0..N-1
    let h_proj: Vec<G1Projective> = (0..(n - 1))
        .map(|j| ptau.tau_g1[n + j].into_group() - ptau.tau_g1[j].into_group())
        .collect();

    let a_query = G1Projective::normalize_batch(&a_g1);
    let b_g1_query = G1Projective::normalize_batch(&b_g1);
    let b_g2_query = G2Projective::normalize_batch(&b_g2);
    let abc_aff = G1Projective::normalize_batch(&abc_g1);
    let gamma_abc_g1 = abc_aff[..num_instance].to_vec();
    let l_query = abc_aff[num_instance..].to_vec();
    let h_query = G1Projective::normalize_batch(&h_proj);

    let vk = VerifyingKey::<Bn254> {
        alpha_g1: ptau.alpha_tau_g1[0],
        beta_g2: ptau.beta_g2,
        gamma_g2: G2Affine::generator(),
        delta_g2: G2Affine::generator(),
        gamma_abc_g1,
    };

    ProvingKey::<Bn254> {
        vk,
        beta_g1: ptau.beta_tau_g1[0],
        delta_g1: G1Affine::generator(),
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query,
    }
}

fn serialize_pk(pk: &ProvingKey<Bn254>) -> Vec<u8> {
    let mut out = Vec::new();
    pk.serialize_compressed(&mut out).expect("serialize pk");
    out
}

fn deserialize_pk(bytes: &[u8]) -> ProvingKey<Bn254> {
    ProvingKey::<Bn254>::deserialize_compressed(bytes).expect("deserialize pk")
}

fn affine_g1_hex(p: &G1Affine) -> String {
    let mut b = Vec::new();
    p.serialize_compressed(&mut b).unwrap();
    hex_encode(&b)
}

fn affine_g2_hex(p: &G2Affine) -> String {
    let mut b = Vec::new();
    p.serialize_compressed(&mut b).unwrap();
    hex_encode(&b)
}

fn g1_from_hex(s: &str) -> G1Affine {
    let b = hex_decode(s);
    let p = G1Affine::deserialize_compressed(&b[..]).expect("g1");
    assert!(p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve());
    p
}

fn g2_from_hex(s: &str) -> G2Affine {
    let b = hex_decode(s);
    let p = G2Affine::deserialize_compressed(&b[..]).expect("g2");
    assert!(p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve());
    p
}

fn fr_hex(f: &Fr) -> String {
    let mut b = f.into_bigint().to_bytes_be();
    if b.len() < 32 {
        let mut p = vec![0u8; 32 - b.len()];
        p.extend_from_slice(&b);
        b = p;
    }
    hex_encode(&b)
}

fn fr_from_hex(s: &str) -> Fr {
    Fr::from_be_bytes_mod_order(&hex_decode(s))
}

fn schnorr_challenge(
    prev_sha256: &str,
    prev_delta_g1: &G1Affine,
    new_delta_g1: &G1Affine,
    pub_delta_g1: &G1Affine,
    r_g1: &G1Affine,
) -> Fr {
    let mut h = Sha256::new();
    h.update(b"audren/ceremony/phase2/schnorr_v1");
    h.update(prev_sha256.as_bytes());
    h.update(affine_g1_hex(prev_delta_g1).as_bytes());
    h.update(affine_g1_hex(new_delta_g1).as_bytes());
    h.update(affine_g1_hex(pub_delta_g1).as_bytes());
    h.update(affine_g1_hex(r_g1).as_bytes());
    Fr::from_be_bytes_mod_order(&h.finalize())
}

fn derive_rlc_scalars(domain_tag: &[u8], prev_sha256: &str, next_sha256: &str, len: usize) -> Vec<Fr> {
    let mut seed_h = Sha256::new();
    seed_h.update(domain_tag);
    seed_h.update(prev_sha256.as_bytes());
    seed_h.update(next_sha256.as_bytes());
    let base = Fr::from_be_bytes_mod_order(&seed_h.finalize());
    let mut out = Vec::with_capacity(len);
    let mut cur = Fr::one();
    for _ in 0..len {
        out.push(cur);
        cur *= base;
    }
    out
}

fn apply_delta(pk: &mut ProvingKey<Bn254>, delta: Fr) {
    assert!(!delta.is_zero(), "delta must be non-zero");
    let mut delta_inv = delta.inverse().expect("delta invertible");

    pk.delta_g1 = (pk.delta_g1.into_group() * delta).into_affine();
    pk.vk.delta_g2 = (pk.vk.delta_g2.into_group() * delta).into_affine();

    let l_proj: Vec<G1Projective> = pk.l_query.iter().map(|p| p.into_group() * delta_inv).collect();
    pk.l_query = G1Projective::normalize_batch(&l_proj);

    let h_proj: Vec<G1Projective> = pk.h_query.iter().map(|p| p.into_group() * delta_inv).collect();
    pk.h_query = G1Projective::normalize_batch(&h_proj);

    zeroize_fr(&mut delta_inv);
}

fn derive_beacon_delta(
    prev_sha256: &str,
    drand_round: u64,
    drand_randomness: &str,
    solana_slot: u64,
    solana_blockhash: &str,
) -> Fr {
    let mut h = Sha256::new();
    h.update(b"audren/ceremony/phase2/beacon_v1");
    h.update(prev_sha256.as_bytes());
    h.update(drand_round.to_le_bytes());
    h.update(drand_randomness.trim().as_bytes());
    h.update(solana_slot.to_le_bytes());
    h.update(solana_blockhash.trim().as_bytes());
    let mut state: [u8; 32] = h.finalize().into();
    for _ in 0..BEACON_SHA256_ITERATIONS {
        state = Sha256::digest(state).into();
    }
    let mut d = Fr::from_be_bytes_mod_order(&state);
    if d.is_zero() {
        d = Fr::one();
    }
    d
}

fn verify_transition(
    prev: &ProvingKey<Bn254>,
    prev_sha: &str,
    next: &ProvingKey<Bn254>,
    next_sha: &str,
    pub_delta_g1: G1Affine,
    pub_delta_g2: G2Affine,
    pok_r_g1: G1Affine,
    pok_s: Fr,
) {
    // 1. All Phase-1 elements MUST be strictly invariant across every Phase-2 transition.
    assert_eq!(prev.vk.alpha_g1, next.vk.alpha_g1, "alpha_g1 mutated!");
    assert_eq!(prev.vk.beta_g2, next.vk.beta_g2, "beta_g2 mutated!");
    assert_eq!(prev.vk.gamma_g2, next.vk.gamma_g2, "gamma_g2 mutated!");
    assert_eq!(prev.vk.gamma_abc_g1, next.vk.gamma_abc_g1, "gamma_abc_g1 mutated!");
    assert_eq!(prev.beta_g1, next.beta_g1, "beta_g1 mutated!");
    assert_eq!(prev.a_query, next.a_query, "a_query mutated!");
    assert_eq!(prev.b_g1_query, next.b_g1_query, "b_g1_query mutated!");
    assert_eq!(prev.b_g2_query, next.b_g2_query, "b_g2_query mutated!");
    assert_eq!(prev.l_query.len(), next.l_query.len(), "l_query length mutated!");
    assert_eq!(prev.h_query.len(), next.h_query.len(), "h_query length mutated!");

    // 2. Non-degenerate contribution
    assert!(!pub_delta_g1.is_zero() && !pub_delta_g2.is_zero(), "zero delta contribution!");
    assert!(!next.delta_g1.is_zero() && !next.vk.delta_g2.is_zero(), "zero resulting delta!");
    assert_ne!(prev.delta_g1, next.delta_g1, "identity contribution (delta=1) rejected!");

    // 3. Schnorr PoK of delta_k bound to prev_sha256 & delta points
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let e = schnorr_challenge(prev_sha, &prev.delta_g1, &next.delta_g1, &pub_delta_g1, &pok_r_g1);
    let lhs = (g1.into_group() * pok_s).into_affine();
    let rhs = (pok_r_g1.into_group() + pub_delta_g1.into_group() * e).into_affine();
    assert_eq!(lhs, rhs, "Schnorr PoK verification FAILED!");

    // 4. Pairing checks linking pub_delta_g1, pub_delta_g2, prev.delta, next.delta
    assert_eq!(
        Bn254::pairing(pub_delta_g1, g2),
        Bn254::pairing(g1, pub_delta_g2),
        "pub_delta G1/G2 pairing mismatch!"
    );
    assert_eq!(
        Bn254::pairing(next.delta_g1, g2),
        Bn254::pairing(prev.delta_g1, pub_delta_g2),
        "delta_g1 transition pairing mismatch!"
    );
    assert_eq!(
        Bn254::pairing(g1, next.vk.delta_g2),
        Bn254::pairing(pub_delta_g1, prev.vk.delta_g2),
        "delta_g2 transition pairing mismatch!"
    );

    // 5. Fiat-Shamir random linear combination pairing check over EVERY l_query & h_query element
    let l_coeffs = derive_rlc_scalars(b"audren/ceremony/rlc_l", prev_sha, next_sha, prev.l_query.len());
    let mut l_prev_acc = G1Projective::zero();
    let mut l_next_acc = G1Projective::zero();
    for i in 0..prev.l_query.len() {
        l_prev_acc += prev.l_query[i].into_group() * l_coeffs[i];
        l_next_acc += next.l_query[i].into_group() * l_coeffs[i];
    }
    assert_eq!(
        Bn254::pairing(l_next_acc.into_affine(), next.vk.delta_g2),
        Bn254::pairing(l_prev_acc.into_affine(), prev.vk.delta_g2),
        "l_query inverse-delta scaling pairing check FAILED!"
    );

    let h_coeffs = derive_rlc_scalars(b"audren/ceremony/rlc_h", prev_sha, next_sha, prev.h_query.len());
    let mut h_prev_acc = G1Projective::zero();
    let mut h_next_acc = G1Projective::zero();
    for j in 0..prev.h_query.len() {
        h_prev_acc += prev.h_query[j].into_group() * h_coeffs[j];
        h_next_acc += next.h_query[j].into_group() * h_coeffs[j];
    }
    assert_eq!(
        Bn254::pairing(h_next_acc.into_affine(), next.vk.delta_g2),
        Bn254::pairing(h_prev_acc.into_affine(), prev.vk.delta_g2),
        "h_query inverse-delta scaling pairing check FAILED!"
    );
}

fn sanity_prove_and_verify(pk: &ProvingKey<Bn254>) {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let circuit = JoinSplit4AryCircuit::realistic_benchmark_instance();
    let pub_hash = circuit.public_input_hash;

    // Prove & verify directly against the ceremony ProvingKey
    let proof = prove_joinsplit(pk, circuit.clone(), seed);
    assert!(
        verify_joinsplit_offchain(&pk.vk, &proof, pub_hash),
        "Groth16 sanity verification FAILED!"
    );

    // Also verify compressed serialization round-trip and 192-byte Solana proof export
    let pk_bytes = serialize_pk(pk);
    let pk_rt = deserialize_pk_compressed(&pk_bytes).expect("deserialize_pk_compressed");
    let proof_rt = prove_joinsplit(&pk_rt, circuit, seed);
    assert!(verify_joinsplit_offchain(&pk_rt.vk, &proof_rt, pub_hash));
    let wire192 = proof_to_solana_compressed_192(&proof_rt);
    assert_eq!(wire192.len(), 192);
}

fn render_vk_generated_rs(pk: &ProvingKey<Bn254>, pk_sha256: &str, provenance: &str) -> String {
    let mut src = String::new();
    src.push_str("//! Auto-generated VerifyingKey for Audren `JoinSplit4AryCircuit` (`vk_id = 0`).\n");
    src.push_str("//!\n");
    src.push_str(&format!("//! Provenance: {provenance}\n"));
    src.push_str(&format!("//! ProvingKey compressed SHA-256: `{pk_sha256}`\n"));
    src.push_str("//! Phase 1: Official Hermez/PSE Perpetual Powers of Tau (`powersOfTau28_hez_final_15.ptau`,\n");
    src.push_str("//!          71+ public contributors, BLAKE2b-512 `982372c8...69ae6e`, SHA-256 `3ef2ecc5...9e7f`).\n");
    src.push_str("//! Phase 2: BGM17 Groth16 MPC ceremony (`ceremony/transcript.json`, verifiable via\n");
    src.push_str("//!          `cargo run -p audren-circuits --release --bin ceremony -- verify`).\n\n");
    src.push_str("#[allow(dead_code)]\n");
    src.push_str(&format!("pub const VK_PROVENANCE: &str = \"{provenance}\";\n"));
    src.push_str("#[allow(dead_code)]\n");
    src.push_str(&format!(
        "pub const PK_COMPRESSED_SHA256: &str = \"{pk_sha256}\";\n\n"
    ));
    src.push_str(&render_solana_vk_const("VK_JOINSPLIT_DEFAULT", &pk.vk));
    src
}

fn get_arg(args: &[String], flag: &str) -> String {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| panic!("missing required argument {flag}"))
}

fn get_opt_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn parse_json_str(json: &str, key: &str) -> String {
    let pat = format!("\"{key}\"");
    let pos = json.find(&pat).unwrap_or_else(|| panic!("missing JSON key {key}"));
    let rest = &json[pos + pat.len()..];
    let colon = rest.find(':').unwrap();
    let after = rest[colon + 1..].trim_start();
    assert!(after.starts_with('"'), "expected string value for {key}");
    let end = after[1..].find('"').unwrap();
    after[1..1 + end].to_string()
}

fn parse_json_u64(json: &str, key: &str) -> u64 {
    let pat = format!("\"{key}\"");
    let pos = json.find(&pat).unwrap_or_else(|| panic!("missing JSON key {key}"));
    let rest = &json[pos + pat.len()..];
    let colon = rest.find(':').unwrap();
    let after = rest[colon + 1..].trim_start();
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().expect("u64")
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");
    match cmd {
        "init" => {
            let ptau_path = get_arg(&args, "--ptau");
            let out_path = get_arg(&args, "--out");
            println!("Parsing & pairing-verifying Perpetual Powers of Tau ({ptau_path})...");
            let ptau = parse_and_verify_ptau(Path::new(&ptau_path));
            println!("  .ptau SHA-256 verified: {}", ptau.sha256);
            println!("  Building initial Phase-2 ProvingKey for frozen JoinSplit4AryCircuit (17,861 R1CS, N=32,768)...");
            let pk = build_initial_phase2_pk(&ptau);
            println!("  Running Groth16 prove+verify sanity check on initial Phase-2 parameters...");
            sanity_prove_and_verify(&pk);
            let bytes = serialize_pk(&pk);
            let sha = sha256_hex(&bytes);
            if let Some(parent) = Path::new(&out_path).parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&out_path, &bytes).unwrap();
            println!("Wrote initial Phase-2 PK: {out_path} ({} bytes, SHA-256: {sha})", bytes.len());
        }
        "contribute" => {
            let in_path = get_arg(&args, "--in");
            let out_path = get_arg(&args, "--out");
            let att_path = get_arg(&args, "--attestation");
            let name = get_opt_arg(&args, "--name").unwrap_or_else(|| "contributor".into());
            let extra = get_opt_arg(&args, "--entropy").unwrap_or_default();

            let prev_bytes = fs::read(&in_path).expect("read prev pk");
            let prev_sha = sha256_hex(&prev_bytes);
            let prev_pk = deserialize_pk(&prev_bytes);

            // Mix 64 bytes OS CSPRNG + optional caller entropy + nanosecond timestamp via SHA-512
            let mut os_rand = [0u8; 64];
            rand::rngs::OsRng.fill_bytes(&mut os_rand);
            let now_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let mut h = Sha512::new();
            h.update(b"audren/ceremony/phase2/contribute_v1");
            h.update(&os_rand);
            h.update(prev_sha.as_bytes());
            h.update(now_ns.to_le_bytes());
            h.update(extra.as_bytes());
            let mut digest = h.finalize();
            let mut delta = Fr::from_be_bytes_mod_order(&digest[..64]);
            assert!(!delta.is_zero());

            let mut nonce_rand = [0u8; 64];
            rand::rngs::OsRng.fill_bytes(&mut nonce_rand);
            let mut r = Fr::from_be_bytes_mod_order(&nonce_rand);
            assert!(!r.is_zero());

            let pub_delta_g1 = (G1Affine::generator().into_group() * delta).into_affine();
            let pub_delta_g2 = (G2Affine::generator().into_group() * delta).into_affine();
            let pok_r_g1 = (G1Affine::generator().into_group() * r).into_affine();

            let mut next_pk = prev_pk.clone();
            apply_delta(&mut next_pk, delta);

            let e = schnorr_challenge(
                &prev_sha,
                &prev_pk.delta_g1,
                &next_pk.delta_g1,
                &pub_delta_g1,
                &pok_r_g1,
            );
            let pok_s = r + e * delta;

            // Immediately zeroize ALL toxic waste & entropy from memory!
            zeroize_fr(&mut delta);
            zeroize_fr(&mut r);
            zeroize_bytes(&mut os_rand);
            zeroize_bytes(&mut nonce_rand);
            zeroize_bytes(&mut digest);

            let next_bytes = serialize_pk(&next_pk);
            let next_sha = sha256_hex(&next_bytes);

            // Self-verify the transition mathematically before saving
            verify_transition(
                &prev_pk,
                &prev_sha,
                &next_pk,
                &next_sha,
                pub_delta_g1,
                pub_delta_g2,
                pok_r_g1,
                pok_s,
            );
            sanity_prove_and_verify(&next_pk);

            fs::write(&out_path, &next_bytes).unwrap();
            let att = format!(
                "{{\n  \"kind\": \"contribution\",\n  \"name\": \"{name}\",\n  \"prev_pk_sha256\": \"{prev_sha}\",\n  \"next_pk_sha256\": \"{next_sha}\",\n  \"pub_delta_g1\": \"{}\",\n  \"pub_delta_g2\": \"{}\",\n  \"pok_r_g1\": \"{}\",\n  \"pok_s\": \"{}\",\n  \"new_delta_g1\": \"{}\",\n  \"new_delta_g2\": \"{}\"\n}}\n",
                affine_g1_hex(&pub_delta_g1),
                affine_g2_hex(&pub_delta_g2),
                affine_g1_hex(&pok_r_g1),
                fr_hex(&pok_s),
                affine_g1_hex(&next_pk.delta_g1),
                affine_g2_hex(&next_pk.vk.delta_g2),
            );
            fs::write(&att_path, &att).unwrap();
            println!(
                "Contribution '{name}' applied, pairing-verified & toxic waste zeroized: {out_path} (SHA-256: {next_sha})"
            );
        }
        "beacon" => {
            let in_path = get_arg(&args, "--in");
            let out_path = get_arg(&args, "--out");
            let att_path = get_arg(&args, "--attestation");
            let drand_round: u64 = get_arg(&args, "--drand-round").parse().expect("drand round u64");
            let drand_randomness = get_arg(&args, "--drand-randomness");
            let solana_slot: u64 = get_arg(&args, "--solana-slot").parse().expect("solana slot u64");
            let solana_blockhash = get_arg(&args, "--solana-blockhash");

            let prev_bytes = fs::read(&in_path).expect("read prev pk");
            let prev_sha = sha256_hex(&prev_bytes);
            let prev_pk = deserialize_pk(&prev_bytes);

            let delta = derive_beacon_delta(
                &prev_sha,
                drand_round,
                &drand_randomness,
                solana_slot,
                &solana_blockhash,
            );
            // Deterministic public Schnorr PoK for the public beacon
            let r_bytes = Sha256::digest(format!("audren/beacon/r/{prev_sha}/{drand_round}").as_bytes());
            let r = Fr::from_be_bytes_mod_order(&r_bytes);
            let pub_delta_g1 = (G1Affine::generator().into_group() * delta).into_affine();
            let pub_delta_g2 = (G2Affine::generator().into_group() * delta).into_affine();
            let pok_r_g1 = (G1Affine::generator().into_group() * r).into_affine();

            let mut next_pk = prev_pk.clone();
            apply_delta(&mut next_pk, delta);

            let e = schnorr_challenge(
                &prev_sha,
                &prev_pk.delta_g1,
                &next_pk.delta_g1,
                &pub_delta_g1,
                &pok_r_g1,
            );
            let pok_s = r + e * delta;

            let next_bytes = serialize_pk(&next_pk);
            let next_sha = sha256_hex(&next_bytes);
            verify_transition(
                &prev_pk,
                &prev_sha,
                &next_pk,
                &next_sha,
                pub_delta_g1,
                pub_delta_g2,
                pok_r_g1,
                pok_s,
            );
            sanity_prove_and_verify(&next_pk);

            fs::write(&out_path, &next_bytes).unwrap();
            let att = format!(
                "{{\n  \"kind\": \"beacon\",\n  \"name\": \"drand_quicknet_and_solana_mainnet_finalized_beacon\",\n  \"drand_chain_hash\": \"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971\",\n  \"drand_round\": {drand_round},\n  \"drand_randomness\": \"{drand_randomness}\",\n  \"solana_mainnet_slot\": {solana_slot},\n  \"solana_mainnet_blockhash\": \"{solana_blockhash}\",\n  \"sha256_delay_iterations\": {BEACON_SHA256_ITERATIONS},\n  \"prev_pk_sha256\": \"{prev_sha}\",\n  \"next_pk_sha256\": \"{next_sha}\",\n  \"pub_delta_g1\": \"{}\",\n  \"pub_delta_g2\": \"{}\",\n  \"pok_r_g1\": \"{}\",\n  \"pok_s\": \"{}\",\n  \"new_delta_g1\": \"{}\",\n  \"new_delta_g2\": \"{}\"\n}}\n",
                affine_g1_hex(&pub_delta_g1),
                affine_g2_hex(&pub_delta_g2),
                affine_g1_hex(&pok_r_g1),
                fr_hex(&pok_s),
                affine_g1_hex(&next_pk.delta_g1),
                affine_g2_hex(&next_pk.vk.delta_g2),
            );
            fs::write(&att_path, &att).unwrap();
            println!(
                "Public beacon finalized & pairing-verified: {out_path} ({} bytes, SHA-256: {next_sha})",
                next_bytes.len()
            );
        }
        "verify" => {
            let ptau_path = get_arg(&args, "--ptau");
            let init_path = get_arg(&args, "--initial");
            let steps_arg = get_arg(&args, "--steps"); // comma-separated pk:att.json pairs
            let vk_rs_opt = get_opt_arg(&args, "--vk-rs");

            println!("1. Verifying Perpetual Powers of Tau ({ptau_path})...");
            let ptau = parse_and_verify_ptau(Path::new(&ptau_path));
            let expected_init = build_initial_phase2_pk(&ptau);
            let expected_init_bytes = serialize_pk(&expected_init);
            let actual_init_bytes = fs::read(&init_path).expect("read initial pk");
            assert_eq!(
                sha256_hex(&expected_init_bytes),
                sha256_hex(&actual_init_bytes),
                "initial phase2_0000.pk does NOT match deterministic .ptau + R1CS derivation!"
            );
            println!("   OK: initial phase2_0000.pk matches .ptau + frozen JoinSplit4AryCircuit byte-for-byte.");

            let mut cur_pk = expected_init;
            let mut cur_sha = sha256_hex(&actual_init_bytes);

            for (idx, pair) in steps_arg.split(',').enumerate() {
                let (pk_p, att_p) = pair.split_once(':').expect("step format pk:att.json");
                let att = fs::read_to_string(att_p).expect("read attestation");
                let next_bytes = fs::read(pk_p).expect("read step pk");
                let next_sha = sha256_hex(&next_bytes);
                let next_pk = deserialize_pk(&next_bytes);

                let kind = parse_json_str(&att, "kind");
                let name = parse_json_str(&att, "name");
                assert_eq!(parse_json_str(&att, "prev_pk_sha256"), cur_sha);
                assert_eq!(parse_json_str(&att, "next_pk_sha256"), next_sha);

                let pub_g1 = g1_from_hex(&parse_json_str(&att, "pub_delta_g1"));
                let pub_g2 = g2_from_hex(&parse_json_str(&att, "pub_delta_g2"));
                let pok_r = g1_from_hex(&parse_json_str(&att, "pok_r_g1"));
                let pok_s = fr_from_hex(&parse_json_str(&att, "pok_s"));

                verify_transition(&cur_pk, &cur_sha, &next_pk, &next_sha, pub_g1, pub_g2, pok_r, pok_s);

                if kind == "beacon" {
                    let dr = parse_json_u64(&att, "drand_round");
                    let drand_rand = parse_json_str(&att, "drand_randomness");
                    let slot = parse_json_u64(&att, "solana_mainnet_slot");
                    let bh = parse_json_str(&att, "solana_mainnet_blockhash");
                    let exp_delta = derive_beacon_delta(&cur_sha, dr, &drand_rand, slot, &bh);
                    let mut exp_next = cur_pk.clone();
                    apply_delta(&mut exp_next, exp_delta);
                    assert_eq!(
                        sha256_hex(&serialize_pk(&exp_next)),
                        next_sha,
                        "beacon deterministic transition mismatch!"
                    );
                }
                println!("   Step #{} ({kind}: {name}) pairing-verified OK ({next_sha})", idx + 1);
                cur_pk = next_pk;
                cur_sha = next_sha;
            }

            println!("3. Running live Groth16 prove+verify against final ceremony PK...");
            sanity_prove_and_verify(&cur_pk);

            if let Some(vk_rs_path) = vk_rs_opt {
                let vk_rs = fs::read_to_string(&vk_rs_path).expect("read vk_generated.rs");
                assert!(
                    vk_rs.contains(&cur_sha),
                    "vk_generated.rs does not match final ceremony PK SHA-256 ({cur_sha})"
                );
                let expected_const = render_solana_vk_const("VK_JOINSPLIT_DEFAULT", &cur_pk.vk);
                assert!(
                    vk_rs.contains(&expected_const),
                    "VK_JOINSPLIT_DEFAULT bytes in {vk_rs_path} do NOT match final ceremony VerifyingKey!"
                );
                println!("   OK: {vk_rs_path} matches final ceremony VerifyingKey byte-for-byte.");
            }
            println!("\nCEREMONY VERIFICATION PASSED 100% (final PK SHA-256: {cur_sha})");
        }
        "export" => {
            let pk_path = get_arg(&args, "--pk");
            let out_vk = get_arg(&args, "--out-vk");
            let provenance = get_opt_arg(&args, "--provenance")
                .unwrap_or_else(|| "Perpetual Powers of Tau (2^15) + Audren BGM17 Phase-2 Ceremony".into());
            let pk_bytes = fs::read(&pk_path).expect("read final pk");
            let pk_sha = sha256_hex(&pk_bytes);
            let pk = deserialize_pk(&pk_bytes);
            sanity_prove_and_verify(&pk);
            let rs = render_vk_generated_rs(&pk, &pk_sha, &provenance);
            fs::write(&out_vk, rs).unwrap();
            println!("Exported verified VerifyingKey -> {out_vk} (PK SHA-256: {pk_sha}, {} bytes)", pk_bytes.len());
        }
        _ => {
            eprintln!("Usage: ceremony <init|contribute|beacon|verify|export> [args]");
            std::process::exit(1);
        }
    }
}
