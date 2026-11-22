//! Audren On-Chain Ristretto255 Cryptographic Verifiers (Pinocchio + Agave Syscalls).
//!
//! Pure Ristretto255 + native Agave syscalls (no trusted setup):
//! 1. [`verify_triptych`] — Multi-Base Binary Triptych (`N = 32`, `64`, or `128` across
//!    `1`, `2`, or `4` `EpochPage`s) verified via chunked Agave `sol_curve_multiscalar_mul`
//!    syscalls with a single reusable `TriptychScratch` heap buffer (reused across both legs
//!    of `Merge`), precomputed NUMS generators (`U`, `H_0..H_6`), and zero-allocation stack
//!    Fiat-Shamir hashing:
//!    - Secret note ownership `P_l = x * G`
//!    - Unique deterministic nullifier `x * J = U` (empty `IDENTITY` slots are mathematically
//!      unspendable since `0 * J = IDENTITY != U`)
//!    - Unified multi-asset & value balance `(A_l - A_spend) + alpha * (V_l - V_spend) = delta * H`
//!    - Optional protocol-enforced Auditor ElGamal `(S_1, S_2) = (r_s * G, P_l + r_s * K_aud)`
//! 2. [`verify_auditor_asset_proof`] — Verifiable ElGamal encryption of hidden `G_mint` to `K_aud` (`192 B`).
//! 3. [`verify_cross_base_1`] / [`verify_cross_base_2`] — Bridges hidden-asset commitments `(A, V)`
//!    to Agave native Pedersen `(G, C)` (`128 B` / `256 B`).
//! 4. [`verify_native_range_u64`] / [`verify_native_range_u128`] — Zero-allocation stack CPI
//!    to Agave's native `zk_elgamal_proof_program` (`VerifyBatchedRangeProofU64`/`U128`).

use crate::scalar::Scalar;
use crate::state::{ensure, err, page_slot_witness, Point};
use audren_core::{
    instruction::{
        input_pages_for_m, triptych_proof_len, AUDITOR_ASSET_PROOF_LEN, CROSS_BASE_1_LEN,
        CROSS_BASE_2_LEN, RANGE_U128_PROOF_LEN, RANGE_U64_PROOF_LEN,
    },
    layout::{
        read_32, PageHeader, PAGE_CAPACITY, PAGE_OFF_ASSET_TAGS, PAGE_OFF_COMMITMENTS,
        PAGE_OFF_STEALTH_PKS,
    },
    AudrenError, ZK_ELGAMAL_PROOF_PROGRAM_ID,
};
use pinocchio::{
    cpi::invoke,
    error::ProgramError,
    instruction::InstructionView,
    AccountView, Address, ProgramResult,
};
use solana_curve25519::{
    ristretto::{
        add_ristretto, multiscalar_multiply_ristretto, multiply_ristretto, subtract_ristretto,
        validate_ristretto, PodRistrettoPoint,
    },
    scalar::PodScalar,
};
use solana_sha256_hasher::hashv;

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

/// Precomputed NUMS Triptych nullifier base `U = hash_to_point(b"audren/v1/U", b"nullifier")` (`ctr = 1`).
pub const NULLIFIER_U: Point = [
    246, 243, 30, 57, 201, 149, 117, 118, 130, 141, 111, 96, 165, 209, 204, 89, 135, 120, 94, 122,
    171, 140, 20, 70, 251, 91, 57, 57, 34, 207, 100, 73,
];

/// Precomputed NUMS Triptych bit-commitment generators
/// `BIT_GENS[j] = hash_to_point(b"audren/v1/triptych/H", &(j as u32).to_le_bytes())` for `j = 0..7`.
/// Precomputing avoids 46 runtime syscalls (`23` SHA-256 + `23` `validate_ristretto`) per `m = 7` spend.
pub const BIT_GENS: [Point; 7] = [
    // j = 0 (ctr = 0)
    [
        74, 91, 161, 216, 179, 116, 178, 138, 243, 176, 15, 170, 54, 196, 133, 223, 183, 119, 196,
        228, 82, 99, 22, 250, 223, 59, 2, 82, 218, 70, 113, 29,
    ],
    // j = 1 (ctr = 2)
    [
        30, 102, 238, 46, 4, 181, 221, 228, 71, 154, 212, 189, 15, 194, 202, 104, 242, 38, 72, 137,
        216, 216, 128, 139, 127, 166, 20, 120, 168, 137, 129, 16,
    ],
    // j = 2 (ctr = 0)
    [
        106, 6, 143, 41, 175, 241, 199, 247, 89, 217, 63, 178, 135, 255, 100, 65, 38, 188, 199, 99,
        85, 15, 187, 117, 26, 202, 160, 241, 197, 8, 200, 89,
    ],
    // j = 3 (ctr = 0)
    [
        156, 184, 92, 250, 19, 226, 145, 225, 165, 233, 174, 65, 191, 142, 215, 141, 124, 25, 225,
        195, 218, 117, 36, 223, 212, 67, 136, 41, 132, 55, 133, 30,
    ],
    // j = 4 (ctr = 1)
    [
        142, 115, 40, 229, 3, 42, 194, 65, 66, 99, 157, 195, 116, 129, 107, 175, 242, 89, 224, 110,
        45, 245, 56, 221, 65, 26, 247, 125, 33, 230, 80, 107,
    ],
    // j = 5 (ctr = 0)
    [
        94, 5, 184, 159, 83, 216, 237, 181, 235, 173, 35, 114, 219, 44, 192, 83, 210, 136, 88, 217,
        78, 209, 87, 249, 70, 174, 145, 57, 172, 35, 94, 104,
    ],
    // j = 6 (ctr = 11)
    [
        198, 200, 162, 180, 81, 225, 211, 152, 222, 198, 113, 82, 2, 9, 77, 72, 26, 211, 103, 58,
        67, 130, 192, 225, 6, 145, 132, 223, 204, 239, 4, 88,
    ],
];

pub const IDENTITY: Point = [0u8; 32];

/// Agave native ZK ElGamal Proof program discriminants (`ProofInstruction`).
const ZK_IX_VERIFY_BATCHED_RANGE_U64: u8 = 6;
const ZK_IX_VERIFY_BATCHED_RANGE_U128: u8 = 7;

/// Fixed wire size of `BatchedRangeProofContext`: `8 * 32` commitments + `8` bit lengths = `264 B`.
const BATCHED_RANGE_CONTEXT_LEN: usize = 8 * 32 + 8;

#[inline(always)]
pub fn validate_point(p: &Point) -> ProgramResult {
    ensure(
        validate_ristretto(&PodRistrettoPoint(*p)),
        AudrenError::InvalidPoint,
    )
}

#[inline(always)]
pub fn validate_nonzero_point(p: &Point) -> ProgramResult {
    ensure(
        *p != IDENTITY && validate_ristretto(&PodRistrettoPoint(*p)),
        AudrenError::InvalidPoint,
    )
}

#[inline(always)]
pub fn canonical_scalar(bytes: [u8; 32]) -> Result<Scalar, ProgramError> {
    Option::from(Scalar::from_canonical_bytes(bytes)).ok_or_else(|| err(AudrenError::InvalidScalar))
}

#[inline(always)]
fn pod_s(s: Scalar) -> PodScalar {
    PodScalar(s.to_bytes())
}

#[inline(always)]
fn pod_p(p: Point) -> PodRistrettoPoint {
    PodRistrettoPoint(p)
}

#[inline(always)]
pub fn pt_add(a: Point, b: Point) -> Result<Point, ProgramError> {
    add_ristretto(&pod_p(a), &pod_p(b))
        .map(|p| p.0)
        .ok_or_else(|| err(AudrenError::InvalidPoint))
}

#[inline(always)]
pub fn pt_sub(a: Point, b: Point) -> Result<Point, ProgramError> {
    subtract_ristretto(&pod_p(a), &pod_p(b))
        .map(|p| p.0)
        .ok_or_else(|| err(AudrenError::InvalidPoint))
}

#[inline(always)]
pub fn pt_mul_u64(amount: u64, base: Point) -> Result<Point, ProgramError> {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&amount.to_le_bytes());
    multiply_ristretto(&PodScalar(s), &pod_p(base))
        .map(|p| p.0)
        .ok_or_else(|| err(AudrenError::InvalidPoint))
}

fn msm_is_identity(
    scalars: &[PodScalar],
    points: &[PodRistrettoPoint],
) -> Result<bool, ProgramError> {
    let res = multiscalar_multiply_ristretto(scalars, points)
        .ok_or_else(|| err(AudrenError::InvalidPoint))?;
    Ok(res.0 == IDENTITY)
}

/// Deterministic Try-and-Increment Hash-to-Ristretto255 backed by Agave's native
/// `sol_curve_validate_point` syscall (~540 CU average vs ~280,000 CU for software Elligator2).
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

/// Zero-allocation deterministic Fiat-Shamir Hash-to-Scalar (64 uniform bytes reduced mod `l`).
///
/// Maximum caller slice count across the entire protocol is `45` (`xi_slices` for audited `m = 7`),
/// so a fixed `[&[u8]; 64]` stack array completely eliminates heap allocations.
#[inline(never)]
pub fn hash_to_scalar(slices: &[&[u8]]) -> Scalar {
    debug_assert!(slices.len() < 64);
    let mut buf: [&[u8]; 64] = [&[]; 64];
    let n = slices.len();
    buf[1..1 + n].copy_from_slice(slices);

    buf[0] = b"audren/v1/fs/0";
    let h0 = hashv(&buf[..1 + n]).to_bytes();

    buf[0] = b"audren/v1/fs/1";
    let h1 = hashv(&buf[..1 + n]).to_bytes();

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

#[inline(never)]
fn compute_triptych_ring_root(
    m: u8,
    expected_pages: usize,
    page_headers: &[PageHeader],
    pages: &[&[u8]],
    auditor_pk: Option<&Point>,
    proof_prefix: &[u8],
) -> Result<([usize; 4], [u8; 32]), ProgramError> {
    let audited = auditor_pk.is_some();
    let mut prefix_counts = [0usize; 4];
    let mut page_hashes = [[0u8; 32]; 4];
    for p_idx in 0..expected_pages {
        let prefix = proof_prefix[p_idx] as usize;
        ensure(
            prefix >= 1
                && prefix <= page_headers[p_idx].count as usize
                && prefix <= PAGE_CAPACITY,
            AudrenError::InvalidTriptychProof,
        )?;
        prefix_counts[p_idx] = prefix;
        let len32 = prefix * 32;
        let page_bytes = pages[p_idx];
        page_hashes[p_idx] = hashv(&[
            b"audren/v1/ring/page",
            &page_headers[p_idx].page_id.to_le_bytes(),
            &[prefix as u8],
            &page_bytes[PAGE_OFF_STEALTH_PKS..PAGE_OFF_STEALTH_PKS + len32],
            &page_bytes[PAGE_OFF_ASSET_TAGS..PAGE_OFF_ASSET_TAGS + len32],
            &page_bytes[PAGE_OFF_COMMITMENTS..PAGE_OFF_COMMITMENTS + len32],
        ])
        .to_bytes();
    }
    let aud_bytes = auditor_pk.copied().unwrap_or(IDENTITY);
    let mut ring_parts: [&[u8]; 7] = [
        b"audren/v1/triptych/ring",
        &[m, u8::from(audited)],
        &aud_bytes,
        &[],
        &[],
        &[],
        &[],
    ];
    for p_idx in 0..expected_pages {
        ring_parts[3 + p_idx] = &page_hashes[p_idx];
    }
    let ring_root = hashv(&ring_parts[..3 + expected_pages]).to_bytes();
    Ok((prefix_counts, ring_root))
}

/// Chunk buffer capacity for `sol_curve_multiscalar_mul` (`<= 96` ring points per page + tail).
const CHUNK_CAP: usize = 3 * PAGE_CAPACITY + 16;

/// Single reusable static heap scratchpad (~12.9 KiB) for Triptych verification.
///
/// Placed in the dedicated `[0 .. 16 KiB)` region of Solana's 32 KiB SBF heap with zero
/// dynamic allocator, keeping every SBF function stack frame far below the 4,096 B limit.
pub struct TriptychScratch {
    xs: [Point; 7],
    ys: [Point; 7],
    ws: [Point; 7],
    ts: [Point; 7],
    es: [Point; 7],
    p_k: [Scalar; 128],
    scalars: [PodScalar; CHUNK_CAP],
    points: [PodRistrettoPoint; CHUNK_CAP],
}

impl TriptychScratch {
    /// Run `f` with a zeroed [`TriptychScratch`] backed by Solana's dedicated `[0 .. 16 KiB)`
    /// static heap arena (or a host heap box under `no-entrypoint` tests).
    #[inline(never)]
    pub fn with_scratch<R>(f: impl FnOnce(&mut Self) -> R) -> R {
        #[cfg(any(target_os = "solana", target_arch = "bpf"))]
        {
            const _: () = assert!(core::mem::size_of::<TriptychScratch>() <= 16 * 1024);
            const _: () = assert!(core::mem::align_of::<TriptychScratch>() <= 8);
            // SAFETY: `[0 .. 16 KiB)` of Solana's 32 KiB heap is disjoint from all other
            // arenas (`WatchedEscrowBuf` at `[16..24 KiB)`, `CpiAccount` at `[24..32 KiB)`),
            // and `TriptychScratch` contains only all-zero-valid POD types.
            let ptr = pinocchio::entrypoint::HEAP_START_ADDRESS as *mut Self;
            unsafe {
                core::ptr::write_bytes(ptr, 0, 1);
                f(&mut *ptr)
            }
        }
        #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
        {
            let mut raw = std::boxed::Box::<Self>::new_uninit();
            // SAFETY: All fields of `TriptychScratch` have valid all-zero bit representations.
            let scratch = unsafe {
                core::ptr::write_bytes(raw.as_mut_ptr(), 0, 1);
                raw.assume_init()
            };
            let mut scratch = scratch;
            f(&mut scratch)
        }
    }
}

/// Verify a Multi-Base Binary Triptych proof (`m = 5` -> 32 notes, `m = 6` -> 64 notes,
/// or `m = 7` -> 128 notes) via batched Agave `sol_curve_multiscalar_mul` syscalls.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn verify_triptych_with_scratch(
    scratch: &mut TriptychScratch,
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

    let (prefix_counts, ring_root) = compute_triptych_ring_root(
        m,
        expected_pages,
        page_headers,
        pages,
        auditor_pk,
        &proof[..expected_pages],
    )?;

    // Parse proof elements sequentially after `prefix_counts`.
    let mut off = expected_pages;
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

    for item in scratch.xs.iter_mut().take(mu) {
        *item = read_pt(&mut off, false)?;
    }
    for item in scratch.ys.iter_mut().take(mu) {
        *item = read_pt(&mut off, false)?;
    }
    for item in scratch.ws.iter_mut().take(mu) {
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
    let mut z_aud = Scalar::ZERO;

    if audited {
        s1_opt = Some(read_pt(&mut off, false)?);
        s2_opt = Some(read_pt(&mut off, false)?);
        for item in scratch.ts.iter_mut().take(mu) {
            *item = read_pt(&mut off, false)?;
        }
        for item in scratch.es.iter_mut().take(mu) {
            *item = read_pt(&mut off, false)?;
        }
        z_aud = read_sc(&mut off)?;
    }
    ensure(off == proof.len(), AudrenError::InvalidTriptychProof)?;

    // Challenge 1: `alpha` binds `ctx_hash`, full `ring_root`, `A_spend`, and `V_spend` before `W[..]`.
    let alpha = hash_to_scalar(&[b"triptych/alpha", ctx_hash, &ring_root, a_spend, v_spend]);
    let alpha_bytes = alpha.to_bytes();

    // Challenge 2: `xi` binds `ring_root` and all prover commitments (zero-alloc stack slice table).
    let mut xi_slices: [&[u8]; 48] = [&[]; 48];
    let mut xi_len = 0usize;
    macro_rules! push_xi {
        ($slice:expr) => {{
            xi_slices[xi_len] = $slice;
            xi_len += 1;
        }};
    }
    push_xi!(b"triptych/xi");
    push_xi!(&ring_root);
    push_xi!(&alpha_bytes);
    push_xi!(&j_nullifier);
    push_xi!(&pt_a);
    push_xi!(&pt_b);
    push_xi!(&pt_c);
    push_xi!(&pt_d);
    for item in scratch.xs.iter().take(mu) {
        push_xi!(item);
    }
    for item in scratch.ys.iter().take(mu) {
        push_xi!(item);
    }
    for item in scratch.ws.iter().take(mu) {
        push_xi!(item);
    }
    if let (Some(ref s1), Some(ref s2)) = (&s1_opt, &s2_opt) {
        push_xi!(s1);
        push_xi!(s2);
        for item in scratch.ts.iter().take(mu) {
            push_xi!(item);
        }
        for item in scratch.es.iter().take(mu) {
            push_xi!(item);
        }
    }
    let xi = hash_to_scalar(&xi_slices[..xi_len]);
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

    // Precompute `p_k(xi)` for all `k = 0..N` in O(N) inside the reusable scratchpad.
    scratch.p_k[0] = Scalar::ONE;
    for bit in 0..mu {
        let half = 1usize << bit;
        let f1 = fs[bit];
        let f0 = xi - f1;
        for idx in (0..half).rev() {
            let base = scratch.p_k[idx];
            scratch.p_k[idx | half] = base * f1;
            scratch.p_k[idx] = base * f0;
        }
    }

    let mut chunk_len = 0usize;
    let mut acc = IDENTITY;

    let flush_chunk = |acc: &mut Point,
                       scalars: &[PodScalar; CHUNK_CAP],
                       points: &[PodRistrettoPoint; CHUNK_CAP],
                       len: &mut usize|
     -> ProgramResult {
        if *len > 0 {
            let chunk = multiscalar_multiply_ristretto(&scalars[..*len], &points[..*len])
                .ok_or_else(|| err(AudrenError::InvalidPoint))?;
            if chunk.0 != IDENTITY {
                *acc = if *acc == IDENTITY {
                    chunk.0
                } else {
                    pt_add(*acc, chunk.0)?
                };
            }
            *len = 0;
        }
        Ok(())
    };

    // Ring witnesses across 1, 2, or 4 `EpochPage`s over each page's immutable `prefix_counts[p_idx]`.
    let p_weight_n = (if audited { mu3 - mu7 } else { mu3 }).to_normal();
    let mu5_n = mu5.to_normal();
    let v_weight = mu5 * alpha;
    let v_weight_n = v_weight.to_normal();
    for (p_idx, page_bytes) in pages.iter().enumerate() {
        let count = prefix_counts[p_idx];
        let base_k = p_idx * PAGE_CAPACITY;
        for slot in 0..count {
            let pk_coeff = scratch.p_k[base_k + slot];
            if pk_coeff == Scalar::ZERO {
                continue;
            }
            let (p_pt, a_pt, v_pt) = page_slot_witness(page_bytes, slot)?;
            if p_pt != IDENTITY {
                let b = pk_coeff.mul_normal_to_bytes(&p_weight_n);
                if b != IDENTITY {
                    scratch.scalars[chunk_len] = PodScalar(b);
                    scratch.points[chunk_len] = pod_p(p_pt);
                    chunk_len += 1;
                }
            }
            if a_pt != IDENTITY {
                let b = pk_coeff.mul_normal_to_bytes(&mu5_n);
                if b != IDENTITY {
                    scratch.scalars[chunk_len] = PodScalar(b);
                    scratch.points[chunk_len] = pod_p(a_pt);
                    chunk_len += 1;
                }
            }
            if v_pt != IDENTITY {
                let b = pk_coeff.mul_normal_to_bytes(&v_weight_n);
                if b != IDENTITY {
                    scratch.scalars[chunk_len] = PodScalar(b);
                    scratch.points[chunk_len] = pod_p(v_pt);
                    chunk_len += 1;
                }
            }
        }
        flush_chunk(&mut acc, &scratch.scalars, &scratch.points, &mut chunk_len)?;
    }

    macro_rules! push_term {
        ($s:expr, $p:expr) => {{
            let s_val: Scalar = $s;
            let p_val: Point = $p;
            if s_val != Scalar::ZERO && p_val != IDENTITY {
                scratch.scalars[chunk_len] = pod_s(s_val);
                scratch.points[chunk_len] = pod_p(p_val);
                chunk_len += 1;
            }
        }};
    }

    // Eq 1 & Eq 2: binary bit commitments (`A, B, C, D`, precomputed `BIT_GENS[0..m]`).
    push_term!(Scalar::ONE, pt_a);
    push_term!(xi, pt_b);
    push_term!(mu2 * xi, pt_c);
    push_term!(mu2, pt_d);
    for j in 0..mu {
        let coeff = -(fs[j] + mu2 * fs[j] * (xi - fs[j]));
        push_term!(coeff, BIT_GENS[j]);
    }

    // Eq 3, 4, 5: masked polynomial terms `X_j, Y_j, W_j`.
    for j in 0..mu {
        let xj = xi_pows[j];
        push_term!(-(mu3 * xj), scratch.xs[j]);
        push_term!(-(mu4 * xj), scratch.ys[j]);
        push_term!(-(mu5 * xj), scratch.ws[j]);
    }

    // Fixed generators `G`, `H`, precomputed `NULLIFIER_U`, `J`, `A_spend`, `V_spend`.
    let g_coeff = if audited {
        -(mu3 * z_x + mu6 * z_aud)
    } else {
        -(mu3 * z_x)
    };
    push_term!(g_coeff, G);
    push_term!(-(z_a + mu2 * z_c + mu5 * z_q), H);
    push_term!(mu4 * xi_m, NULLIFIER_U);
    push_term!(-(mu4 * z_x), j_nullifier);
    push_term!(-(mu5 * xi_m), *a_spend);
    push_term!(-(v_weight * xi_m), *v_spend);

    // Eq 6 & Eq 7 (Institutional Audited mode): verifiable ElGamal of spent note `P_l` under `K_aud`.
    if let (Some(k_aud), Some(s1), Some(s2)) = (auditor_pk, s1_opt, s2_opt) {
        push_term!(mu6 * xi_m, s1);
        push_term!(mu7 * xi_m, s2);
        push_term!(-(mu7 * z_aud), *k_aud);
        for j in 0..mu {
            let xj = xi_pows[j];
            push_term!(-(mu6 * xj), scratch.ts[j]);
            push_term!(-(mu7 * xj), scratch.es[j]);
        }
    }

    flush_chunk(&mut acc, &scratch.scalars, &scratch.points, &mut chunk_len)?;
    ensure(acc == IDENTITY, AudrenError::InvalidTriptychProof)?;

    Ok(VerifiedTriptych {
        nullifier: j_nullifier,
        auditor_s1: s1_opt,
        auditor_s2: s2_opt,
    })
}

/// Convenience single-leg wrapper allocating one [`TriptychScratch`].
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
    TriptychScratch::with_scratch(|scratch| {
        verify_triptych_with_scratch(
            scratch,
            m,
            pages,
            page_headers,
            a_spend,
            v_spend,
            auditor_pk,
            ctx_hash,
            proof,
        )
    })
}

/// Verify that `(M_1, M_2)` is a valid ElGamal encryption of the hidden mint generator `G_mint`
/// inside `A_spend = G_mint + a_spend * H` under `K_aud` (192 B).
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
/// AND prove `A2 - A1 = d * H` in `256 B`.
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

/// Zero-allocation stack CPI into Agave's native `zk_elgamal_proof_program` (`VerifyBatchedRangeProofU64`).
///
/// Exact wire layout (`937 B`):
/// `[0]`: `6` (`ProofInstruction::VerifyBatchedRangeProofU64`)
/// `[1..257]`: `commitments[8]` (`commitments[0] = c`, rest zeroed)
/// `[257..265]`: `bit_lengths[8]` (`bit_lengths[0] = 64`, rest zeroed)
/// `[265..937]`: `PodRangeProofU64` (`672 B`)
#[inline(never)]
pub fn verify_native_range_u64(
    zk_program: &AccountView,
    c: &Point,
    proof_bytes: &[u8],
) -> ProgramResult {
    let zk_id = Address::new_from_array(ZK_ELGAMAL_PROOF_PROGRAM_ID);
    ensure(zk_program.address() == &zk_id, AudrenError::InvalidAccount)?;
    ensure(
        proof_bytes.len() == RANGE_U64_PROOF_LEN,
        AudrenError::InvalidRangeProof,
    )?;
    let mut buf = [0u8; 1 + BATCHED_RANGE_CONTEXT_LEN + RANGE_U64_PROOF_LEN];
    buf[0] = ZK_IX_VERIFY_BATCHED_RANGE_U64;
    buf[1..33].copy_from_slice(c);
    buf[1 + 256] = 64;
    buf[1 + BATCHED_RANGE_CONTEXT_LEN..].copy_from_slice(proof_bytes);

    let ix = InstructionView {
        program_id: &zk_id,
        accounts: &[],
        data: &buf,
    };
    invoke::<0, &AccountView>(&ix, &[])
}

/// Zero-allocation stack CPI into Agave's native `zk_elgamal_proof_program` (`VerifyBatchedRangeProofU128`).
///
/// Exact wire layout (`1,001 B`):
/// `[0]`: `7` (`ProofInstruction::VerifyBatchedRangeProofU128`)
/// `[1..257]`: `commitments[8]` (`commitments[0] = c1`, `commitments[1] = c2`, rest zeroed)
/// `[257..265]`: `bit_lengths[8]` (`bit_lengths[0] = 64`, `bit_lengths[1] = 64`, rest zeroed)
/// `[265..1001]`: `PodRangeProofU128` (`736 B`)
#[inline(never)]
pub fn verify_native_range_u128(
    zk_program: &AccountView,
    c1: &Point,
    c2: &Point,
    proof_bytes: &[u8],
) -> ProgramResult {
    let zk_id = Address::new_from_array(ZK_ELGAMAL_PROOF_PROGRAM_ID);
    ensure(zk_program.address() == &zk_id, AudrenError::InvalidAccount)?;
    ensure(
        proof_bytes.len() == RANGE_U128_PROOF_LEN,
        AudrenError::InvalidRangeProof,
    )?;
    let mut buf = [0u8; 1 + BATCHED_RANGE_CONTEXT_LEN + RANGE_U128_PROOF_LEN];
    buf[0] = ZK_IX_VERIFY_BATCHED_RANGE_U128;
    buf[1..33].copy_from_slice(c1);
    buf[33..65].copy_from_slice(c2);
    buf[1 + 256] = 64;
    buf[1 + 257] = 64;
    buf[1 + BATCHED_RANGE_CONTEXT_LEN..].copy_from_slice(proof_bytes);

    let ix = InstructionView {
        program_id: &zk_id,
        accounts: &[],
        data: &buf,
    };
    invoke::<0, &AccountView>(&ix, &[])
}

/// Compute a 32-byte domain-separated Fiat-Shamir context root.
#[inline]
pub fn transcript_root(parts: &[&[u8]]) -> [u8; 32] {
    hashv(parts).to_bytes()
}

/// Helper: derive the canonical zero-value commitment check (`V == IDENTITY`) when change is omitted.
#[inline(always)]
pub fn is_zero_point(p: &Point) -> bool {
    *p == IDENTITY
}

#[inline(always)]
pub fn address_bytes(a: &Address) -> [u8; 32] {
    *a.as_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_precomputed_nums_generators() {
        assert_eq!(NULLIFIER_U, hash_to_point(b"audren/v1/U", b"nullifier"));
        for (j, expected) in BIT_GENS.iter().enumerate() {
            assert_eq!(
                *expected,
                hash_to_point(b"audren/v1/triptych/H", &(j as u32).to_le_bytes()),
                "BIT_GENS[{j}] mismatch"
            );
        }
    }
}
