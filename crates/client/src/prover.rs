//! Pure Ristretto255 Provers matching `programs/audren/program/src/crypto.rs` byte-for-byte:
//! - Multi-Base Binary Triptych (`m = 5` -> 32 notes / 1 page, `m = 6` -> 64 notes / 2 pages,
//!   `m = 7` -> 128 notes / 4 pages), optional audited mode
//! - Verifiable Auditor Asset Encryption (`192 B`)
//! - Cross-Base Bridge 1 (`128 B`) & 2 (`224 B`)
//! - Native Agave Batched Bulletproofs (`672 B` / `736 B`) via `solana-zk-sdk`

use crate::ClientError;
use audren_core::{
    instruction::{
        input_pages_for_m, triptych_proof_len, AUDITOR_ASSET_PROOF_LEN, CROSS_BASE_1_LEN,
        CROSS_BASE_2_LEN, RANGE_U128_PROOF_LEN, RANGE_U64_PROOF_LEN,
    },
    layout::PAGE_CAPACITY,
};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use rand::{CryptoRng, RngCore};
use solana_sha256_hasher::hashv;
use solana_zk_sdk::{
    encryption::pedersen::{Pedersen, PedersenOpening, G as SDK_G, H as SDK_H},
    zk_elgamal_proof_program::{
        build_batched_range_proof_u128_data, build_batched_range_proof_u64_data,
    },
};

pub type Point = [u8; 32];

pub const IDENTITY: Point = [0u8; 32];

#[inline]
pub fn g_point() -> RistrettoPoint {
    SDK_G
}

#[inline]
pub fn h_point() -> RistrettoPoint {
    *SDK_H
}

#[inline]
pub fn compress(p: &RistrettoPoint) -> Point {
    p.compress().to_bytes()
}

#[inline]
pub fn decompress(p: &Point) -> Result<RistrettoPoint, ClientError> {
    if *p == IDENTITY {
        return Ok(RistrettoPoint::identity());
    }
    CompressedRistretto(*p)
        .decompress()
        .ok_or(ClientError::InvalidPoint)
}

/// Deterministic Try-and-Increment Hash-to-Ristretto255 matching `program/src/crypto.rs::hash_to_point`.
pub fn hash_to_point(domain: &[u8], data: &[u8]) -> Point {
    let mut ctr: u32 = 0;
    loop {
        let mut cand = hashv(&[domain, data, &ctr.to_le_bytes()]).to_bytes();
        cand[0] &= 0xfe;
        cand[31] &= 0x7f;
        if cand != IDENTITY && CompressedRistretto(cand).decompress().is_some() {
            return cand;
        }
        ctr = ctr.wrapping_add(1);
    }
}

/// Deterministic Fiat-Shamir Hash-to-Scalar matching `program/src/crypto.rs::hash_to_scalar`.
pub fn hash_to_scalar(slices: &[&[u8]]) -> Scalar {
    let mut s0: Vec<&[u8]> = Vec::with_capacity(slices.len() + 1);
    s0.push(b"audren/v1/fs/0");
    s0.extend_from_slice(slices);
    let h0 = hashv(&s0).to_bytes();

    let mut s1: Vec<&[u8]> = Vec::with_capacity(slices.len() + 1);
    s1.push(b"audren/v1/fs/1");
    s1.extend_from_slice(slices);
    let h1 = hashv(&s1).to_bytes();

    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&h0);
    wide[32..].copy_from_slice(&h1);
    Scalar::from_bytes_mod_order_wide(&wide)
}

#[inline]
pub fn asset_generator(mint: &[u8; 32]) -> Point {
    hash_to_point(b"audren/v1/mint", mint)
}

#[inline]
pub fn nullifier_generator() -> Point {
    hash_to_point(b"audren/v1/U", b"nullifier")
}

#[inline]
pub fn bit_generator(j: usize) -> Point {
    hash_to_point(b"audren/v1/triptych/H", &(j as u32).to_le_bytes())
}

#[inline]
pub fn transcript_root(parts: &[&[u8]]) -> [u8; 32] {
    hashv(parts).to_bytes()
}

/// Public ring entry extracted from an on-chain `EpochPage` slot.
#[derive(Clone, Copy, Debug)]
pub struct RingSlotWitness {
    pub stealth_pk: Point,
    pub asset_tag: Point,
    pub commitment: Point,
}

impl RingSlotWitness {
    pub const EMPTY: Self = Self {
        stealth_pk: IDENTITY,
        asset_tag: IDENTITY,
        commitment: IDENTITY,
    };
}

/// Witness secrets for the real spent note at index `secret_index` in the ring.
pub struct TriptychWitness<'a> {
    /// Ring size exponent (`6` -> 64 slots / 1 page, `7` -> 128 slots / 2 pages).
    pub m: u8,
    /// Index `l ∈ 0..2^m` of the real spent note in `ring`.
    pub secret_index: usize,
    /// Full ring slice (`len == 2^m`; unpopulated tail slots are `RingSlotWitness::EMPTY`).
    pub ring: &'a [RingSlotWitness],
    /// Spend secret `x` such that `P_l = x * G`.
    pub spend_x: Scalar,
    /// Secret asset blinding `a_l` of note `l` (`A_l = G_mint + a_l * H`).
    pub a_note_blinding: Scalar,
    /// Secret value `v_l` of note `l`.
    pub value: u64,
    /// Secret value blinding `r_l` of note `l` (`V_l = v_l * A_l + r_l * H`).
    pub v_note_blinding: Scalar,
    /// Target `A_spend = G_mint + a_spend_blinding * H`.
    pub a_spend: Point,
    pub a_spend_blinding: Scalar,
    /// Target `V_spend = v_l * G_mint + v_spend_eff_blinding * H`.
    /// Note: if `V_spend = ∑ (v_i * A_spend + r_i * H)`, then
    /// `v_spend_eff_blinding = v_l * a_spend_blinding + ∑ r_i`.
    pub v_spend: Point,
    pub v_spend_eff_blinding: Scalar,
    /// Required if pool is in `PoolMode::InstitutionalAudited`.
    pub auditor_pk: Option<Point>,
    /// Instruction transcript hash bound to all outputs & metadata.
    pub ctx_hash: [u8; 32],
}

/// Proof bytes and derived public nullifier `J = x^{-1} * U`.
pub struct TriptychProofOutput {
    pub proof: Vec<u8>,
    pub nullifier: Point,
    pub auditor_s1: Option<Point>,
    pub auditor_s2: Option<Point>,
}

/// Compute polynomial coefficients `p_{k, j}` for `k = 0..N, j = 0..m` where
/// `p_k(X) = ∏_{j=0}^{m-1} ((l_j * X + a_j) if k_j==1 else ((1 - l_j) * X - a_j))`.
fn compute_poly_coeffs(m: usize, l: usize, a: &[Scalar]) -> Vec<Vec<Scalar>> {
    let n = 1usize << m;
    let mut coeffs = vec![vec![Scalar::ZERO; m + 1]; n];
    for (k, poly) in coeffs.iter_mut().enumerate() {
        poly[0] = Scalar::ONE;
        let mut deg = 0usize;
        for j in 0..m {
            let l_bit = (l >> j) & 1;
            let k_bit = (k >> j) & 1;
            let c1 = if k_bit == 1 {
                Scalar::from(l_bit as u64)
            } else {
                Scalar::from((1 - l_bit) as u64)
            };
            let c0 = if k_bit == 1 { a[j] } else { -a[j] };

            // Multiply current polynomial `poly[0..=deg]` by `(c1 * X + c0)`.
            for d in (0..=deg).rev() {
                let prev = poly[d];
                poly[d + 1] += prev * c1;
                poly[d] = prev * c0;
            }
            deg += 1;
        }
    }
    coeffs
}

/// Generate a Multi-Base Binary Triptych proof verified by `program/src/crypto.rs::verify_triptych`.
pub fn prove_triptych<R: RngCore + CryptoRng>(
    w: &TriptychWitness<'_>,
    rng: &mut R,
) -> Result<TriptychProofOutput, ClientError> {
    input_pages_for_m(w.m).map_err(|_| ClientError::InvalidProofInput("m must be 5, 6, or 7"))?;
    let mu = w.m as usize;
    let n = 1usize << mu;
    if w.ring.len() != n || w.secret_index >= n {
        return Err(ClientError::InvalidProofInput(
            "ring length must equal 2^m and secret_index < 2^m",
        ));
    }
    if w.spend_x == Scalar::ZERO {
        return Err(ClientError::InvalidProofInput("spend_x cannot be zero"));
    }

    let audited = w.auditor_pk.is_some();
    let expected_len = triptych_proof_len(w.m, audited)
        .map_err(|_| ClientError::InvalidProofInput("invalid triptych dimensions"))?;

    let g = g_point();
    let h = h_point();
    let u = decompress(&nullifier_generator())?;
    let j_pt = w.spend_x.invert() * u;
    let j_bytes = compress(&j_pt);

    let mut h_bits = Vec::with_capacity(mu);
    for j in 0..mu {
        h_bits.push(decompress(&bit_generator(j))?);
    }

    // Decompress ring points once.
    let mut ring_p = Vec::with_capacity(n);
    let mut ring_a = Vec::with_capacity(n);
    let mut ring_v = Vec::with_capacity(n);
    for slot in w.ring {
        ring_p.push(decompress(&slot.stealth_pk)?);
        ring_a.push(decompress(&slot.asset_tag)?);
        ring_v.push(decompress(&slot.commitment)?);
    }

    // Challenge 1: `alpha` binds `A_spend` and `V_spend` before `W[..]`.
    let alpha = hash_to_scalar(&[b"triptych/alpha", &w.ctx_hash, &w.a_spend, &w.v_spend]);
    let alpha_bytes = alpha.to_bytes();

    // Effective difference scalar `delta` such that:
    // `(A_l - A_spend) + alpha * (V_l - V_spend) = delta * H`.
    let v_sc = Scalar::from(w.value);
    let v_note_eff_blind = v_sc * w.a_note_blinding + w.v_note_blinding;
    let delta = (w.a_note_blinding - w.a_spend_blinding)
        + alpha * (v_note_eff_blind - w.v_spend_eff_blinding);

    // Bit commitments `A, B, C, D`.
    let r_a = Scalar::random(rng);
    let r_b = Scalar::random(rng);
    let r_c = Scalar::random(rng);
    let r_d = Scalar::random(rng);
    let mut a_bits = Vec::with_capacity(mu);
    for _ in 0..mu {
        a_bits.push(Scalar::random(rng));
    }

    let mut pt_a = r_a * h;
    let mut pt_b = r_b * h;
    let mut pt_c = r_c * h;
    let mut pt_d = r_d * h;
    for j in 0..mu {
        let lj = Scalar::from(((w.secret_index >> j) & 1) as u64);
        let aj = a_bits[j];
        pt_a += aj * h_bits[j];
        pt_b += lj * h_bits[j];
        pt_c += (aj * (Scalar::ONE - Scalar::from(2u64) * lj)) * h_bits[j];
        pt_d += (-(aj * aj)) * h_bits[j];
    }

    // Polynomial coefficients `p_{k, j}` for `j = 0..m`.
    let poly = compute_poly_coeffs(mu, w.secret_index, &a_bits);

    // Masking terms `X_j, Y_j, W_j`.
    let mut rhos = Vec::with_capacity(mu);
    let mut taus = Vec::with_capacity(mu);
    let mut xs = Vec::with_capacity(mu);
    let mut ys = Vec::with_capacity(mu);
    let mut ws = Vec::with_capacity(mu);

    for j in 0..mu {
        let rho = Scalar::random(rng);
        let tau = Scalar::random(rng);
        rhos.push(rho);
        taus.push(tau);

        let mut x_acc = rho * g;
        let mut w_acc = tau * h;
        for k in 0..n {
            let pkj = poly[k][j];
            if pkj != Scalar::ZERO {
                if ring_p[k] != RistrettoPoint::identity() {
                    x_acc += pkj * ring_p[k];
                }
                if ring_a[k] != RistrettoPoint::identity() {
                    w_acc += pkj * ring_a[k];
                }
                if ring_v[k] != RistrettoPoint::identity() {
                    w_acc += (pkj * alpha) * ring_v[k];
                }
            }
        }
        xs.push(compress(&x_acc));
        ys.push(compress(&(rho * j_pt)));
        ws.push(compress(&w_acc));
    }

    // Optional audited ElGamal `(S_1, S_2) = (r_s * G, P_l + r_s * K_aud)` + `T_j, E_j`.
    let mut r_s = Scalar::ZERO;
    let mut gammas = Vec::with_capacity(mu);
    let mut s1_bytes: Option<Point> = None;
    let mut s2_bytes: Option<Point> = None;
    let mut ts = Vec::with_capacity(mu);
    let mut es = Vec::with_capacity(mu);

    if let Some(k_aud_bytes) = w.auditor_pk {
        let k_aud = decompress(&k_aud_bytes)?;
        r_s = Scalar::random(rng);
        let s1 = r_s * g;
        let s2 = ring_p[w.secret_index] + r_s * k_aud;
        s1_bytes = Some(compress(&s1));
        s2_bytes = Some(compress(&s2));

        for j in 0..mu {
            let gamma = Scalar::random(rng);
            gammas.push(gamma);
            let t_pt = gamma * g;
            let mut e_pt = gamma * k_aud;
            for k in 0..n {
                let pkj = poly[k][j];
                if pkj != Scalar::ZERO && ring_p[k] != RistrettoPoint::identity() {
                    e_pt -= pkj * ring_p[k];
                }
            }
            ts.push(compress(&t_pt));
            es.push(compress(&e_pt));
        }
    }

    let a_bytes = compress(&pt_a);
    let b_bytes = compress(&pt_b);
    let c_bytes = compress(&pt_c);
    let d_bytes = compress(&pt_d);

    // Challenge 2: `xi` binds all prover commitments identically to `program/src/crypto.rs`.
    let mut xi_slices: Vec<&[u8]> = Vec::with_capacity(8 + 5 * mu);
    xi_slices.push(b"triptych/xi");
    xi_slices.push(&alpha_bytes);
    xi_slices.push(&j_bytes);
    xi_slices.push(&a_bytes);
    xi_slices.push(&b_bytes);
    xi_slices.push(&c_bytes);
    xi_slices.push(&d_bytes);
    for item in &xs {
        xi_slices.push(item);
    }
    for item in &ys {
        xi_slices.push(item);
    }
    for item in &ws {
        xi_slices.push(item);
    }
    if let (Some(ref s1), Some(ref s2)) = (&s1_bytes, &s2_bytes) {
        xi_slices.push(s1);
        xi_slices.push(s2);
        for item in &ts {
            xi_slices.push(item);
        }
        for item in &es {
            xi_slices.push(item);
        }
    }
    let xi = hash_to_scalar(&xi_slices);

    // Responses.
    let mut fs = Vec::with_capacity(mu);
    for j in 0..mu {
        let lj = Scalar::from(((w.secret_index >> j) & 1) as u64);
        fs.push(lj * xi + a_bits[j]);
    }
    let z_a = r_b * xi + r_a;
    let z_c = r_c * xi + r_d;

    let mut xi_pow = Scalar::ONE;
    let mut rho_sum = Scalar::ZERO;
    let mut tau_sum = Scalar::ZERO;
    let mut gamma_sum = Scalar::ZERO;
    for j in 0..mu {
        rho_sum += rhos[j] * xi_pow;
        tau_sum += taus[j] * xi_pow;
        if audited {
            gamma_sum += gammas[j] * xi_pow;
        }
        xi_pow *= xi;
    }
    let xi_m = xi_pow;
    let z_x = w.spend_x * xi_m - rho_sum;
    let z_q = delta * xi_m - tau_sum;
    let z_aud = r_s * xi_m - gamma_sum;

    // Serialize in exact wire order matching `verify_triptych`.
    let mut out = Vec::with_capacity(expected_len);
    out.extend_from_slice(&j_bytes);
    out.extend_from_slice(&a_bytes);
    out.extend_from_slice(&b_bytes);
    out.extend_from_slice(&c_bytes);
    out.extend_from_slice(&d_bytes);
    for item in &xs {
        out.extend_from_slice(item);
    }
    for item in &ys {
        out.extend_from_slice(item);
    }
    for item in &ws {
        out.extend_from_slice(item);
    }
    for f in &fs {
        out.extend_from_slice(&f.to_bytes());
    }
    out.extend_from_slice(&z_a.to_bytes());
    out.extend_from_slice(&z_c.to_bytes());
    out.extend_from_slice(&z_x.to_bytes());
    out.extend_from_slice(&z_q.to_bytes());
    if let (Some(s1), Some(s2)) = (s1_bytes, s2_bytes) {
        out.extend_from_slice(&s1);
        out.extend_from_slice(&s2);
        for item in &ts {
            out.extend_from_slice(item);
        }
        for item in &es {
            out.extend_from_slice(item);
        }
        out.extend_from_slice(&z_aud.to_bytes());
    }
    debug_assert_eq!(out.len(), expected_len);

    Ok(TriptychProofOutput {
        proof: out,
        nullifier: j_bytes,
        auditor_s1: s1_bytes,
        auditor_s2: s2_bytes,
    })
}

/// Generate the `192 B` verifiable ElGamal proof of hidden mint `G_mint` under `K_aud`
/// matching `program/src/crypto.rs::verify_auditor_asset_proof`.
pub fn prove_auditor_asset<R: RngCore + CryptoRng>(
    k_aud: &Point,
    mint: &[u8; 32],
    a_spend: &Point,
    a_spend_blinding: Scalar,
    ctx_hash: &[u8; 32],
    rng: &mut R,
) -> Result<[u8; AUDITOR_ASSET_PROOF_LEN], ClientError> {
    let g = g_point();
    let h = h_point();
    let k_pt = decompress(k_aud)?;
    let g_mint = decompress(&asset_generator(mint))?;

    let r_m = Scalar::random(rng);
    let m1 = compress(&(r_m * g));
    let m2 = compress(&(g_mint + r_m * k_pt));

    let k_m = Scalar::random(rng);
    let k_a = Scalar::random(rng);
    let r1 = compress(&(k_m * g));
    let r2 = compress(&(k_m * k_pt - k_a * h));

    let c = hash_to_scalar(&[
        b"auditor_asset",
        ctx_hash,
        k_aud,
        a_spend,
        &m1,
        &m2,
        &r1,
        &r2,
    ]);
    let s_m = k_m + c * r_m;
    let s_a = k_a + c * a_spend_blinding;

    let mut out = [0u8; AUDITOR_ASSET_PROOF_LEN];
    out[0..32].copy_from_slice(&m1);
    out[32..64].copy_from_slice(&m2);
    out[64..96].copy_from_slice(&r1);
    out[96..128].copy_from_slice(&r2);
    out[128..160].copy_from_slice(&s_m.to_bytes());
    out[160..192].copy_from_slice(&s_a.to_bytes());
    Ok(out)
}

/// Prove equality of value `v` across `(A, V = v*A + t*H)` and `(G, C = v*G + s*H)` (`128 B`).
pub fn prove_cross_base_1<R: RngCore + CryptoRng>(
    a_pt: &Point,
    v_pt: &Point,
    c_pt: &Point,
    v: u64,
    t: Scalar,
    s: Scalar,
    ctx_hash: &[u8; 32],
    rng: &mut R,
) -> Result<[u8; CROSS_BASE_1_LEN], ClientError> {
    let a = decompress(a_pt)?;
    let g = g_point();
    let h = h_point();

    let kv = Scalar::random(rng);
    let kt = Scalar::random(rng);
    let ks = Scalar::random(rng);
    let rv = compress(&(kv * a + kt * h));
    let rc = compress(&(kv * g + ks * h));

    let c = hash_to_scalar(&[b"xbase1", ctx_hash, a_pt, v_pt, c_pt, &rv, &rc]);
    let z_v = kv + c * Scalar::from(v);
    let z_t = kt + c * t;
    let z_s = ks + c * s;

    let mut out = [0u8; CROSS_BASE_1_LEN];
    out[0..32].copy_from_slice(&c.to_bytes());
    out[32..64].copy_from_slice(&z_v.to_bytes());
    out[64..96].copy_from_slice(&z_t.to_bytes());
    out[96..128].copy_from_slice(&z_s.to_bytes());
    Ok(out)
}

/// Prove equality of two values `(v1, v2)` across `(A1, V1)/(G, C1)` and `(A2, V2)/(G, C2)`
/// AND prove `A2 - A1 = (a2_blinding - a1_blinding) * H` (`256 B`).
#[allow(clippy::too_many_arguments)]
pub fn prove_cross_base_2<R: RngCore + CryptoRng>(
    a1: &Point,
    v1_pt: &Point,
    c1_pt: &Point,
    v1: u64,
    t1: Scalar,
    s1: Scalar,
    a2: &Point,
    v2_pt: &Point,
    c2_pt: &Point,
    v2: u64,
    t2: Scalar,
    s2: Scalar,
    a_diff: Scalar,
    ctx_hash: &[u8; 32],
    rng: &mut R,
) -> Result<[u8; CROSS_BASE_2_LEN], ClientError> {
    let a1_p = decompress(a1)?;
    let a2_p = decompress(a2)?;
    let g = g_point();
    let h = h_point();

    let kv1 = Scalar::random(rng);
    let kt1 = Scalar::random(rng);
    let ks1 = Scalar::random(rng);
    let kv2 = Scalar::random(rng);
    let kt2 = Scalar::random(rng);
    let ks2 = Scalar::random(rng);
    let kd = Scalar::random(rng);

    let rv1 = compress(&(kv1 * a1_p + kt1 * h));
    let rc1 = compress(&(kv1 * g + ks1 * h));
    let rv2 = compress(&(kv2 * a2_p + kt2 * h));
    let rc2 = compress(&(kv2 * g + ks2 * h));
    let rd = compress(&(kd * h));

    let c = hash_to_scalar(&[
        b"xbase2", ctx_hash, a1, v1_pt, c1_pt, a2, v2_pt, c2_pt, &rv1, &rc1, &rv2, &rc2, &rd,
    ]);
    let z_v1 = kv1 + c * Scalar::from(v1);
    let z_t1 = kt1 + c * t1;
    let z_s1 = ks1 + c * s1;
    let z_v2 = kv2 + c * Scalar::from(v2);
    let z_t2 = kt2 + c * t2;
    let z_s2 = ks2 + c * s2;
    let z_d = kd + c * a_diff;

    let mut out = [0u8; CROSS_BASE_2_LEN];
    out[0..32].copy_from_slice(&c.to_bytes());
    out[32..64].copy_from_slice(&z_v1.to_bytes());
    out[64..96].copy_from_slice(&z_t1.to_bytes());
    out[96..128].copy_from_slice(&z_s1.to_bytes());
    out[128..160].copy_from_slice(&z_v2.to_bytes());
    out[160..192].copy_from_slice(&z_t2.to_bytes());
    out[192..224].copy_from_slice(&z_s2.to_bytes());
    out[224..256].copy_from_slice(&z_d.to_bytes());
    Ok(out)
}

/// Generate a native Agave 64-bit Bulletproof (`672 B`) and Pedersen commitment `C = v*G + s*H`.
pub fn prove_range_u64(
    amount: u64,
    opening: Scalar,
) -> Result<([u8; RANGE_U64_PROOF_LEN], Point), ClientError> {
    let op = PedersenOpening::from_bytes(&opening.to_bytes())
        .ok_or(ClientError::Crypto("invalid pedersen opening"))?;
    let c = Pedersen::with(amount, &op);
    let data = build_batched_range_proof_u64_data(vec![&c], vec![amount], vec![64], vec![&op])
        .map_err(|_| ClientError::Crypto("batched range u64 proof failed"))?;
    Ok((data.proof.0, c.get_point().compress().to_bytes()))
}

/// Generate a native Agave batched two-value 64-bit Bulletproof (`736 B`) and `(C1, C2)`.
pub fn prove_range_u128(
    amount_1: u64,
    opening_1: Scalar,
    amount_2: u64,
    opening_2: Scalar,
) -> Result<([u8; RANGE_U128_PROOF_LEN], Point, Point), ClientError> {
    let op1 = PedersenOpening::from_bytes(&opening_1.to_bytes())
        .ok_or(ClientError::Crypto("invalid pedersen opening 1"))?;
    let op2 = PedersenOpening::from_bytes(&opening_2.to_bytes())
        .ok_or(ClientError::Crypto("invalid pedersen opening 2"))?;
    let c1 = Pedersen::with(amount_1, &op1);
    let c2 = Pedersen::with(amount_2, &op2);
    let data = build_batched_range_proof_u128_data(
        vec![&c1, &c2],
        vec![amount_1, amount_2],
        vec![64, 64],
        vec![&op1, &op2],
    )
    .map_err(|_| ClientError::Crypto("batched range u128 proof failed"))?;
    Ok((
        data.proof.0,
        c1.get_point().compress().to_bytes(),
        c2.get_point().compress().to_bytes(),
    ))
}

/// Extract a full `PAGE_CAPACITY` (`32`) ring slice from raw `EpochPage` account bytes.
pub fn extract_ring_from_page(page_bytes: &[u8]) -> Result<Vec<RingSlotWitness>, ClientError> {
    let hdr = audren_core::layout::PageHeader::decode(page_bytes)
        .map_err(|_| ClientError::InvalidEncoding("invalid epoch page header"))?;
    let count = hdr.count as usize;
    let mut ring = vec![RingSlotWitness::EMPTY; PAGE_CAPACITY];
    for (slot, dst) in ring.iter_mut().enumerate().take(count) {
        let entry = audren_core::layout::read_page_note(page_bytes, slot)
            .map_err(|_| ClientError::InvalidEncoding("invalid note slot"))?;
        *dst = RingSlotWitness {
            stealth_pk: entry.stealth_pk,
            asset_tag: entry.asset_tag,
            commitment: entry.commitment,
        };
    }
    Ok(ring)
}
