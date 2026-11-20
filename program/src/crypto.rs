//! Audren On-Chain Ristretto255 Cryptographic Verifiers (~520 LOC audit surface).
//!
//! Zero Groth16 circuits, zero trusted setup, zero custom indexer:
//! 1. [`verify_triptych`] — Multi-Base Binary Triptych (`N = 32`, `64`, or `128` across
//!    `1`, `2`, or `4` `EpochPage`s) verified in ONE single batched Agave
//!    `sol_curve_multiscalar_mul` syscall (`<= 439` points, well under Agave's `512`-point cap),
//!    proving simultaneously:
//!    - Secret note ownership `P_l = x * G`
//!    - Unique deterministic nullifier `x * J = U` (which also makes spending empty `IDENTITY`
//!      slots mathematically impossible since `0 * J = IDENTITY != U`)
//!    - Unified multi-asset & value balance `(A_l - A_spend) + alpha * (V_l - V_spend) = delta * H`
//!    - Optional cryptographically enforced Auditor ElGamal `(S_1, S_2) = (r_s * G, P_l + r_s * K_aud)`
//! 2. [`verify_auditor_asset_proof`] — Verifiable ElGamal encryption of hidden `G_mint` to `K_aud` (192 B).
//! 3. [`verify_cross_base_1`] / [`verify_cross_base_2`] — Bridges hidden-asset commitments `(A, V)`
//!    to Agave native Pedersen `(G, C)` (128 B / 224 B).
//! 4. [`verify_native_range_u64`] / [`verify_native_range_u128`] — Delegates Bulletproofs via CPI
//!    to Agave's native `zk_elgamal_proof_program`.

use crate::scalar::Scalar;
use crate::state::{ensure, err, page_slot_witness, Point};
use audren_core::{
    instruction::{
        input_pages_for_m, triptych_proof_len, AUDITOR_ASSET_PROOF_LEN, CROSS_BASE_1_LEN,
        CROSS_BASE_2_LEN, RANGE_U128_PROOF_LEN, RANGE_U64_PROOF_LEN,
    },
    layout::{read_32, PageHeader, PAGE_CAPACITY},
    AudrenError,
};
use bytemuck::Zeroable;
use solana_account_info::AccountInfo;
use solana_address::Address;
use solana_cpi::invoke;
use solana_curve25519::{
    ristretto::{
        add_ristretto, multiscalar_multiply_ristretto, multiply_ristretto, subtract_ristretto,
        validate_ristretto, PodRistrettoPoint,
    },
    scalar::PodScalar,
};
use solana_program_error::{ProgramError, ProgramResult};
use solana_sha256_hasher::hashv;
use solana_zk_elgamal_proof_interface::{
    instruction::ProofInstruction,
    proof_data::{BatchedRangeProofU128Data, BatchedRangeProofU64Data},
};

/// Agave's Pedersen value base G (`RISTRETTO_BASEPOINT_POINT`).
pub const G: Point = [
    226, 242, 174, 10, 106, 188, 78, 113, 168, 132, 169, 97, 197, 0, 81, 95, 88, 227, 11, 106, 165,
    130, 221, 141, 182, 166, 89, 69, 224, 141, 45, 118,
];

/// Agave's exact Pedersen blinding base `H = HashToRistretto(Sha3_512(G))`.
pub const H: Point = [
    140, 146, 64, 180, 86, 169, 230, 220, 101, 195, 119, 161, 4, 141, 116, 95, 148, 160, 140, 219,
    127, 68, 203, 205, 123, 70, 243, 64, 72, 135, 17, 52,
];

pub const IDENTITY: Point = [0u8; 32];

#[inline]
pub fn validate_point(p: &Point) -> ProgramResult {
    ensure(
        validate_ristretto(&PodRistrettoPoint(*p)),
        AudrenError::InvalidPoint,
    )
}

#[inline]
pub fn validate_nonzero_point(p: &Point) -> ProgramResult {
    ensure(
        *p != IDENTITY && validate_ristretto(&PodRistrettoPoint(*p)),
        AudrenError::InvalidPoint,
    )
}

#[inline]
pub fn canonical_scalar(bytes: [u8; 32]) -> Result<Scalar, ProgramError> {
    Option::from(Scalar::from_canonical_bytes(bytes)).ok_or_else(|| err(AudrenError::InvalidScalar))
}

#[inline]
fn pod_s(s: Scalar) -> PodScalar {
    PodScalar(s.to_bytes())
}

#[inline]
fn pod_p(p: Point) -> PodRistrettoPoint {
    PodRistrettoPoint(p)
}

#[inline]
pub fn pt_add(a: Point, b: Point) -> Result<Point, ProgramError> {
    add_ristretto(&pod_p(a), &pod_p(b))
        .map(|p| p.0)
        .ok_or_else(|| err(AudrenError::InvalidPoint))
}

#[inline]
pub fn pt_sub(a: Point, b: Point) -> Result<Point, ProgramError> {
    subtract_ristretto(&pod_p(a), &pod_p(b))
        .map(|p| p.0)
        .ok_or_else(|| err(AudrenError::InvalidPoint))
}

#[inline]
pub fn pt_mul_u64(amount: u64, base: Point) -> Result<Point, ProgramError> {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&amount.to_le_bytes());
    multiply_ristretto(&PodScalar(s), &pod_p(base))
        .map(|p| p.0)
        .ok_or_else(|| err(AudrenError::InvalidPoint))
}

fn msm_is_identity(scalars: &[PodScalar], points: &[PodRistrettoPoint]) -> Result<bool, ProgramError> {
    let res = multiscalar_multiply_ristretto(scalars, points)
        .ok_or_else(|| err(AudrenError::InvalidPoint))?;
    Ok(res.0 == IDENTITY)
}

/// Deterministic Try-and-Increment Hash-to-Ristretto255 backed by Agave's native
/// `sol_curve_validate_point` syscall (~540 CU average vs ~280,000 CU for software Elligator2).
///
/// Clearing bit 0 (canonical Ristretto `s` is always even) and bit 255 (`s < 2^255 - 19`)
/// maps uniform SHA-256 outputs uniformly onto all non-identity canonical Ristretto255 points.
pub fn hash_to_point(domain: &[u8], data: &[u8]) -> Point {
    let mut ctr: u32 = 0;
    loop {
        let mut cand = hashv(&[domain, data, &ctr.to_le_bytes()]).to_bytes();
        cand[0] &= 0xfe;
        cand[31] &= 0x7f;
        if cand != IDENTITY && validate_ristretto(&PodRistrettoPoint(cand)) {
            return cand;
        }
        ctr = ctr.wrapping_add(1);
    }
}

/// Deterministic Fiat-Shamir Hash-to-Scalar (64 uniform bytes reduced mod `l`).
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

/// Independent NUMS per-mint asset generator `G_mint = HashToRistretto("audren/v1/mint", mint)`.
#[inline]
pub fn asset_generator(mint: &[u8; 32]) -> Point {
    hash_to_point(b"audren/v1/mint", mint)
}

/// Independent NUMS Triptych nullifier base `U = HashToRistretto("audren/v1/U", "")`.
#[inline]
pub fn nullifier_generator() -> Point {
    hash_to_point(b"audren/v1/U", b"nullifier")
}

/// Independent NUMS Triptych bit-commitment generator `H_j`.
#[inline]
pub fn bit_generator(j: usize) -> Point {
    hash_to_point(b"audren/v1/triptych/H", &(j as u32).to_le_bytes())
}

/// Parsed public outputs returned by [`verify_triptych`].
pub struct VerifiedTriptych {
    pub nullifier: Point,
    pub auditor_s1: Option<Point>,
    pub auditor_s2: Option<Point>,
}

impl VerifiedTriptych {
    /// Defense-in-depth check that audited proofs always produced non-empty ElGamal ciphertexts.
    #[inline(always)]
    pub fn check_mode(&self, audited: bool) -> ProgramResult {
        ensure(
            self.auditor_s1.is_some() == audited && self.auditor_s2.is_some() == audited,
            AudrenError::InvalidTriptychProof,
        )
    }
}

/// Verify a Multi-Base Binary Triptych proof (`m = 6` -> 64 notes, or `m = 7` -> 128 notes)
/// in ONE batched Agave `sol_curve_multiscalar_mul` syscall.
#[allow(clippy::too_many_arguments)]
pub fn verify_triptych(
    m: u8,
    pages: &[&[u8]],
    page_headers: &[PageHeader],
    a_spend: &Point,
    v_spend: &Point,
    auditor_pk: Option<&Point>,
    ctx_hash: &[u8; 32],
    proof: &[u8],
) -> Result<VerifiedTriptych, ProgramError> {
    let expected_pages =
        input_pages_for_m(m).map_err(|_| err(AudrenError::InvalidTriptychProof))?;
    let mu = m as usize;
    let n = 1usize << mu;
    ensure(
        pages.len() == expected_pages && page_headers.len() == expected_pages,
        AudrenError::InvalidTriptychProof,
    )?;
    let audited = auditor_pk.is_some();
    let expected_len = triptych_proof_len(m, audited).map_err(err)?;
    ensure(proof.len() == expected_len, AudrenError::InvalidTriptychProof)?;

    validate_nonzero_point(a_spend)?;
    validate_point(v_spend)?;
    if let Some(k_aud) = auditor_pk {
        validate_nonzero_point(k_aud)?;
    }

    // Parse proof elements sequentially.
    let mut off = 0usize;
    let read_pt = |off: &mut usize, nonzero: bool| -> Result<Point, ProgramError> {
        let p = read_32(proof, *off).map_err(err)?;
        *off += 32;
        if nonzero {
            validate_nonzero_point(&p)?;
        } else {
            validate_point(&p)?;
        }
        Ok(p)
    };
    let read_sc = |off: &mut usize| -> Result<Scalar, ProgramError> {
        let s = read_32(proof, *off).map_err(err)?;
        *off += 32;
        canonical_scalar(s)
    };

    let j_nullifier = read_pt(&mut off, true)?;
    let pt_a = read_pt(&mut off, false)?;
    let pt_b = read_pt(&mut off, false)?;
    let pt_c = read_pt(&mut off, false)?;
    let pt_d = read_pt(&mut off, false)?;

    let mut xs = [IDENTITY; 7];
    let mut ys = [IDENTITY; 7];
    let mut ws = [IDENTITY; 7];
    for item in xs.iter_mut().take(mu) {
        *item = read_pt(&mut off, false)?;
    }
    for item in ys.iter_mut().take(mu) {
        *item = read_pt(&mut off, false)?;
    }
    for item in ws.iter_mut().take(mu) {
        *item = read_pt(&mut off, false)?;
    }

    let mut fs = [Scalar::ZERO; 7];
    for item in fs.iter_mut().take(mu) {
        *item = read_sc(&mut off)?;
    }
    let z_a = read_sc(&mut off)?;
    let z_c = read_sc(&mut off)?;
    let z_x = read_sc(&mut off)?;
    let z_q = read_sc(&mut off)?;

    let mut s1_opt: Option<Point> = None;
    let mut s2_opt: Option<Point> = None;
    let mut ts = [IDENTITY; 7];
    let mut es = [IDENTITY; 7];
    let mut z_aud = Scalar::ZERO;

    if audited {
        s1_opt = Some(read_pt(&mut off, false)?);
        s2_opt = Some(read_pt(&mut off, false)?);
        for item in ts.iter_mut().take(mu) {
            *item = read_pt(&mut off, false)?;
        }
        for item in es.iter_mut().take(mu) {
            *item = read_pt(&mut off, false)?;
        }
        z_aud = read_sc(&mut off)?;
    }
    ensure(off == proof.len(), AudrenError::InvalidTriptychProof)?;

    // Challenge 1: `alpha` binds `A_spend` and `V_spend` before `W[..]`.
    let alpha = hash_to_scalar(&[b"triptych/alpha", ctx_hash, a_spend, v_spend]);
    let alpha_bytes = alpha.to_bytes();

    // Challenge 2: `xi` binds all prover commitments.
    let mut xi_slices: Vec<&[u8]> = Vec::with_capacity(8 + 5 * mu);
    xi_slices.push(b"triptych/xi");
    xi_slices.push(&alpha_bytes);
    xi_slices.push(&j_nullifier);
    xi_slices.push(&pt_a);
    xi_slices.push(&pt_b);
    xi_slices.push(&pt_c);
    xi_slices.push(&pt_d);
    for item in xs.iter().take(mu) {
        xi_slices.push(item);
    }
    for item in ys.iter().take(mu) {
        xi_slices.push(item);
    }
    for item in ws.iter().take(mu) {
        xi_slices.push(item);
    }
    if let (Some(ref s1), Some(ref s2)) = (&s1_opt, &s2_opt) {
        xi_slices.push(s1);
        xi_slices.push(s2);
        for item in ts.iter().take(mu) {
            xi_slices.push(item);
        }
        for item in es.iter().take(mu) {
            xi_slices.push(item);
        }
    }
    let xi = hash_to_scalar(&xi_slices);
    let xi_bytes = xi.to_bytes();

    // Random batching weights derived after full proof (including responses).
    let mu_seed = hashv(&[b"audren/v1/triptych/batch", &xi_bytes, proof]).to_bytes();
    let mu2 = hash_to_scalar(&[b"mu", &mu_seed, &[2]]);
    let mu3 = hash_to_scalar(&[b"mu", &mu_seed, &[3]]);
    let mu4 = hash_to_scalar(&[b"mu", &mu_seed, &[4]]);
    let mu5 = hash_to_scalar(&[b"mu", &mu_seed, &[5]]);
    let mu6 = hash_to_scalar(&[b"mu", &mu_seed, &[6]]);
    let mu7 = hash_to_scalar(&[b"mu", &mu_seed, &[7]]);

    // Powers of `xi`: xi_pows[j] = xi^j for j = 0..=mu.
    let mut xi_pows = [Scalar::ONE; 8];
    for j in 1..=mu {
        xi_pows[j] = xi_pows[j - 1] * xi;
    }
    let xi_m = xi_pows[mu];

    // Precompute `p_k(xi)` for all `k = 0..N` in O(N) on heap (keeps SBF stack frame tiny!).
    let mut p_k = vec![Scalar::ZERO; n];
    p_k[0] = Scalar::ONE;
    for bit in 0..mu {
        let half = 1usize << bit;
        let f1 = fs[bit];
        let f0 = xi - f1;
        for idx in (0..half).rev() {
            let base = p_k[idx];
            p_k[idx | half] = base * f1;
            p_k[idx] = base * f0;
        }
    }

    // Verify the batched Ristretto255 relation in bounded-heap page chunks (`<= 96` points per
    // page chunk, reusing ONE 8 KiB `(scalars, points)` buffer so even `m = 7` / 128 notes
    // never approaches Solana's 32 KiB default bump heap).
    //
    // Using `mul_normal_to_bytes` (`mont_mul(pk_mont, weight_normal) = pk * weight`) avoids
    // a second Montgomery reduction per ring point (~250k CU saved on `m = 7`).
    const CHUNK_CAP: usize = 3 * PAGE_CAPACITY + 16;
    let mut scalars: Vec<PodScalar> = Vec::with_capacity(CHUNK_CAP);
    let mut points: Vec<PodRistrettoPoint> = Vec::with_capacity(CHUNK_CAP);
    let mut acc = IDENTITY;

    let flush_chunk = |acc: &mut Point,
                       scalars: &mut Vec<PodScalar>,
                       points: &mut Vec<PodRistrettoPoint>|
     -> ProgramResult {
        if !scalars.is_empty() {
            let chunk = multiscalar_multiply_ristretto(scalars, points)
                .ok_or_else(|| err(AudrenError::InvalidPoint))?;
            if chunk.0 != IDENTITY {
                *acc = if *acc == IDENTITY {
                    chunk.0
                } else {
                    pt_add(*acc, chunk.0)?
                };
            }
            scalars.clear();
            points.clear();
        }
        Ok(())
    };

    // Ring witnesses across 1, 2, or 4 `EpochPage`s (skipping unpopulated IDENTITY slots).
    let p_weight_n = (if audited { mu3 - mu7 } else { mu3 }).to_normal();
    let mu5_n = mu5.to_normal();
    let v_weight = mu5 * alpha;
    let v_weight_n = v_weight.to_normal();
    for (p_idx, page_bytes) in pages.iter().enumerate() {
        let count = page_headers[p_idx].count as usize;
        let base_k = p_idx * PAGE_CAPACITY;
        for slot in 0..count {
            let pk_coeff = p_k[base_k + slot];
            if pk_coeff == Scalar::ZERO {
                continue;
            }
            let (p_pt, a_pt, v_pt) = page_slot_witness(page_bytes, slot)?;
            if p_pt != IDENTITY {
                let b = pk_coeff.mul_normal_to_bytes(&p_weight_n);
                if b != IDENTITY {
                    scalars.push(PodScalar(b));
                    points.push(pod_p(p_pt));
                }
            }
            if a_pt != IDENTITY {
                let b = pk_coeff.mul_normal_to_bytes(&mu5_n);
                if b != IDENTITY {
                    scalars.push(PodScalar(b));
                    points.push(pod_p(a_pt));
                }
            }
            if v_pt != IDENTITY {
                let b = pk_coeff.mul_normal_to_bytes(&v_weight_n);
                if b != IDENTITY {
                    scalars.push(PodScalar(b));
                    points.push(pod_p(v_pt));
                }
            }
        }
        flush_chunk(&mut acc, &mut scalars, &mut points)?;
    }

    let mut push = |s: Scalar, p: Point| {
        if s != Scalar::ZERO && p != IDENTITY {
            scalars.push(pod_s(s));
            points.push(pod_p(p));
        }
    };

    // Eq 1 & Eq 2: binary bit commitments (`A, B, C, D`, `H_0..H_{m-1}`).
    push(Scalar::ONE, pt_a);
    push(xi, pt_b);
    push(mu2 * xi, pt_c);
    push(mu2, pt_d);
    for j in 0..mu {
        let hj = bit_generator(j);
        let coeff = -(fs[j] + mu2 * fs[j] * (xi - fs[j]));
        push(coeff, hj);
    }

    // Eq 3, 4, 5: masked polynomial terms `X_j, Y_j, W_j`.
    for j in 0..mu {
        let xj = xi_pows[j];
        push(-(mu3 * xj), xs[j]);
        push(-(mu4 * xj), ys[j]);
        push(-(mu5 * xj), ws[j]);
    }

    // Fixed generators `G`, `H`, `U`, `J`, `A_spend`, `V_spend`.
    let g_coeff = if audited {
        -(mu3 * z_x + mu6 * z_aud)
    } else {
        -(mu3 * z_x)
    };
    push(g_coeff, G);
    push(-(z_a + mu2 * z_c + mu5 * z_q), H);
    push(mu4 * xi_m, nullifier_generator());
    push(-(mu4 * z_x), j_nullifier);
    push(-(mu5 * xi_m), *a_spend);
    push(-(v_weight * xi_m), *v_spend);

    // Eq 6 & Eq 7 (Institutional Audited mode): verifiable ElGamal of spent note `P_l` under `K_aud`.
    if let (Some(k_aud), Some(s1), Some(s2)) = (auditor_pk, s1_opt, s2_opt) {
        push(mu6 * xi_m, s1);
        push(mu7 * xi_m, s2);
        push(-(mu7 * z_aud), *k_aud);
        for j in 0..mu {
            let xj = xi_pows[j];
            push(-(mu6 * xj), ts[j]);
            push(-(mu7 * xj), es[j]);
        }
    }

    flush_chunk(&mut acc, &mut scalars, &mut points)?;
    ensure(acc == IDENTITY, AudrenError::InvalidTriptychProof)?;

    Ok(VerifiedTriptych {
        nullifier: j_nullifier,
        auditor_s1: s1_opt,
        auditor_s2: s2_opt,
    })
}

/// Verify that `(M_1, M_2)` is a valid ElGamal encryption of the hidden mint generator `G_mint`
/// inside `A_spend = G_mint + a_spend * H` under `K_aud` (192 B).
///
/// Equations:
/// 1. `s_m * G - c * M_1 == R_1`
/// 2. `s_m * K_aud - s_a * H - c * (M_2 - A_spend) == R_2`
pub fn verify_auditor_asset_proof(
    k_aud: &Point,
    a_spend: &Point,
    ctx_hash: &[u8; 32],
    proof: &[u8],
) -> Result<(Point, Point), ProgramError> {
    ensure(
        proof.len() == AUDITOR_ASSET_PROOF_LEN,
        AudrenError::InvalidAuditorProof,
    )?;
    validate_nonzero_point(k_aud)?;
    validate_nonzero_point(a_spend)?;

    let m1 = read_32(proof, 0).map_err(err)?;
    let m2 = read_32(proof, 32).map_err(err)?;
    let r1 = read_32(proof, 64).map_err(err)?;
    let r2 = read_32(proof, 96).map_err(err)?;
    validate_point(&m1)?;
    validate_point(&m2)?;
    validate_point(&r1)?;
    validate_point(&r2)?;
    let s_m = canonical_scalar(read_32(proof, 128).map_err(err)?)?;
    let s_a = canonical_scalar(read_32(proof, 160).map_err(err)?)?;

    let c = hash_to_scalar(&[b"auditor_asset", ctx_hash, k_aud, a_spend, &m1, &m2, &r1, &r2]);
    let w = hash_to_scalar(&[b"auditor_asset/w", &c.to_bytes(), proof]);

    let m2_minus_a = pt_sub(m2, *a_spend)?;
    let scalars = [
        pod_s(s_m),
        pod_s(-c),
        pod_s(-Scalar::ONE),
        pod_s(w * s_m),
        pod_s(-(w * s_a)),
        pod_s(-(w * c)),
        pod_s(-w),
    ];
    let points = [
        pod_p(G),
        pod_p(m1),
        pod_p(r1),
        pod_p(*k_aud),
        pod_p(H),
        pod_p(m2_minus_a),
        pod_p(r2),
    ];
    ensure(
        msm_is_identity(&scalars, &points)?,
        AudrenError::InvalidAuditorProof,
    )?;
    Ok((m1, m2))
}

/// Bridge a single hidden-asset commitment `(A, V)` to an Agave Pedersen commitment `(G, C)` (128 B).
///
/// Proves knowledge of `(v, t, s)` such that `V = v * A + t * H` and `C = v * G + s * H`.
pub fn verify_cross_base_1(
    a_pt: &Point,
    v_pt: &Point,
    c_pt: &Point,
    ctx_hash: &[u8; 32],
    proof: &[u8],
) -> ProgramResult {
    ensure(
        proof.len() == CROSS_BASE_1_LEN,
        AudrenError::InvalidCrossBaseProof,
    )?;
    validate_nonzero_point(a_pt)?;
    validate_point(v_pt)?;
    validate_point(c_pt)?;

    let c = canonical_scalar(read_32(proof, 0).map_err(err)?)?;
    let z_v = canonical_scalar(read_32(proof, 32).map_err(err)?)?;
    let z_t = canonical_scalar(read_32(proof, 64).map_err(err)?)?;
    let z_s = canonical_scalar(read_32(proof, 96).map_err(err)?)?;

    let rv = multiscalar_multiply_ristretto(
        &[pod_s(z_v), pod_s(z_t), pod_s(-c)],
        &[pod_p(*a_pt), pod_p(H), pod_p(*v_pt)],
    )
    .ok_or_else(|| err(AudrenError::InvalidCrossBaseProof))?;
    let rc = multiscalar_multiply_ristretto(
        &[pod_s(z_v), pod_s(z_s), pod_s(-c)],
        &[pod_p(G), pod_p(H), pod_p(*c_pt)],
    )
    .ok_or_else(|| err(AudrenError::InvalidCrossBaseProof))?;

    let c_exp = hash_to_scalar(&[b"xbase1", ctx_hash, a_pt, v_pt, c_pt, &rv.0, &rc.0]);
    ensure(c == c_exp, AudrenError::InvalidCrossBaseProof)
}

/// Bridge two hidden-asset commitments `(A1, V1)` and `(A2, V2)` to `(G, C1)` and `(G, C2)`
/// AND prove `A2 - A1 = d * H` (same hidden mint generator `G_mint` with independent, unlinkable
/// per-note asset blindings `a1 != a2`) in `256 B`.
#[allow(clippy::too_many_arguments)]
pub fn verify_cross_base_2(
    a1: &Point,
    v1: &Point,
    c1: &Point,
    a2: &Point,
    v2: &Point,
    c2: &Point,
    ctx_hash: &[u8; 32],
    proof: &[u8],
) -> ProgramResult {
    ensure(
        proof.len() == CROSS_BASE_2_LEN,
        AudrenError::InvalidCrossBaseProof,
    )?;
    validate_nonzero_point(a1)?;
    validate_point(v1)?;
    validate_point(c1)?;
    validate_nonzero_point(a2)?;
    validate_point(v2)?;
    validate_point(c2)?;

    let c = canonical_scalar(read_32(proof, 0).map_err(err)?)?;
    let z_v1 = canonical_scalar(read_32(proof, 32).map_err(err)?)?;
    let z_t1 = canonical_scalar(read_32(proof, 64).map_err(err)?)?;
    let z_s1 = canonical_scalar(read_32(proof, 96).map_err(err)?)?;
    let z_v2 = canonical_scalar(read_32(proof, 128).map_err(err)?)?;
    let z_t2 = canonical_scalar(read_32(proof, 160).map_err(err)?)?;
    let z_s2 = canonical_scalar(read_32(proof, 192).map_err(err)?)?;
    let z_d = canonical_scalar(read_32(proof, 224).map_err(err)?)?;

    let rv1 = multiscalar_multiply_ristretto(
        &[pod_s(z_v1), pod_s(z_t1), pod_s(-c)],
        &[pod_p(*a1), pod_p(H), pod_p(*v1)],
    )
    .ok_or_else(|| err(AudrenError::InvalidCrossBaseProof))?;
    let rc1 = multiscalar_multiply_ristretto(
        &[pod_s(z_v1), pod_s(z_s1), pod_s(-c)],
        &[pod_p(G), pod_p(H), pod_p(*c1)],
    )
    .ok_or_else(|| err(AudrenError::InvalidCrossBaseProof))?;
    let rv2 = multiscalar_multiply_ristretto(
        &[pod_s(z_v2), pod_s(z_t2), pod_s(-c)],
        &[pod_p(*a2), pod_p(H), pod_p(*v2)],
    )
    .ok_or_else(|| err(AudrenError::InvalidCrossBaseProof))?;
    let rc2 = multiscalar_multiply_ristretto(
        &[pod_s(z_v2), pod_s(z_s2), pod_s(-c)],
        &[pod_p(G), pod_p(H), pod_p(*c2)],
    )
    .ok_or_else(|| err(AudrenError::InvalidCrossBaseProof))?;
    let a2_minus_a1 = pt_sub(*a2, *a1)?;
    let rd = multiscalar_multiply_ristretto(
        &[pod_s(z_d), pod_s(-c)],
        &[pod_p(H), pod_p(a2_minus_a1)],
    )
    .ok_or_else(|| err(AudrenError::InvalidCrossBaseProof))?;

    let c_exp = hash_to_scalar(&[
        b"xbase2", ctx_hash, a1, v1, c1, a2, v2, c2, &rv1.0, &rc1.0, &rv2.0, &rc2.0, &rd.0,
    ]);
    ensure(c == c_exp, AudrenError::InvalidCrossBaseProof)
}

/// CPI into Agave's native `zk_elgamal_proof_program` to verify a 64-bit Bulletproof (`672 B`).
#[inline(never)]
pub fn verify_native_range_u64(
    zk_program: &AccountInfo,
    c: &Point,
    proof_bytes: &[u8],
) -> ProgramResult {
    ensure(
        *zk_program.key == solana_zk_elgamal_proof_interface::id(),
        AudrenError::InvalidAccount,
    )?;
    ensure(
        proof_bytes.len() == RANGE_U64_PROOF_LEN,
        AudrenError::InvalidRangeProof,
    )?;
    let mut data = Box::new(BatchedRangeProofU64Data::zeroed());
    data.context.commitments[0].0 = *c;
    data.context.bit_lengths[0] = 64;
    data.proof.0.copy_from_slice(proof_bytes);
    let ix = ProofInstruction::VerifyBatchedRangeProofU64
        .encode_verify_proof(None, &*data);
    invoke(&ix, &[zk_program.clone()])
}

/// CPI into Agave's native `zk_elgamal_proof_program` to verify two batched 64-bit Bulletproofs (`736 B`).
#[inline(never)]
pub fn verify_native_range_u128(
    zk_program: &AccountInfo,
    c1: &Point,
    c2: &Point,
    proof_bytes: &[u8],
) -> ProgramResult {
    ensure(
        *zk_program.key == solana_zk_elgamal_proof_interface::id(),
        AudrenError::InvalidAccount,
    )?;
    ensure(
        proof_bytes.len() == RANGE_U128_PROOF_LEN,
        AudrenError::InvalidRangeProof,
    )?;
    let mut data = Box::new(BatchedRangeProofU128Data::zeroed());
    data.context.commitments[0].0 = *c1;
    data.context.commitments[1].0 = *c2;
    data.context.bit_lengths[0] = 64;
    data.context.bit_lengths[1] = 64;
    data.proof.0.copy_from_slice(proof_bytes);
    let ix = ProofInstruction::VerifyBatchedRangeProofU128
        .encode_verify_proof(None, &*data);
    invoke(&ix, &[zk_program.clone()])
}

/// Compute a 32-byte domain-separated Fiat-Shamir context root.
pub fn transcript_root(parts: &[&[u8]]) -> [u8; 32] {
    hashv(parts).to_bytes()
}

/// Helper: derive the canonical zero-value commitment check (`V == IDENTITY`) when change is omitted.
#[inline]
pub fn is_zero_point(p: &Point) -> bool {
    *p == IDENTITY
}

#[inline]
pub fn address_bytes(a: &Address) -> [u8; 32] {
    a.to_bytes()
}
