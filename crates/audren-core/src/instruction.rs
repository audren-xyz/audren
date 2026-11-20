//! Instruction discriminants, proof wire lengths, and deterministic framing helpers.

use crate::AudrenError;

/// Instruction tags (1-byte leading discriminant).
pub const TAG_INIT_POOL: u8 = 0;
pub const TAG_OPEN_PAGE: u8 = 1;
pub const TAG_DEPOSIT: u8 = 2;
pub const TAG_TRANSFER: u8 = 3;
pub const TAG_MERGE: u8 = 4;
pub const TAG_SWAP_VIA_ROUTER: u8 = 5;
pub const TAG_WITHDRAW: u8 = 6;
pub const TAG_SET_PAUSED: u8 = 7;
/// Upload one `<= 768 B` chunk of an oversized proof/swap payload (exceeding Solana Transaction v1's
/// `4,096 B` budget) into an ephemeral `ProofBuffer` PDA.
pub const TAG_WRITE_PROOF_BUFFER: u8 = 8;
/// Execute `TAG_TRANSFER`, `TAG_MERGE`, `TAG_SWAP_VIA_ROUTER`, or `TAG_WITHDRAW` using a
/// completed `ProofBuffer` PDA, atomically closing the buffer and refunding 100% of rent to `payer`.
pub const TAG_EXEC_BUFFERED: u8 = 9;
/// Reclaim 100% of rent from an abandoned/unexecuted `ProofBuffer` PDA back to its `authority`.
pub const TAG_CLOSE_PROOF_BUFFER: u8 = 10;

/// Supported binary Triptych exponents (`PAGE_CAPACITY = 32`):
/// - `m = 5`: 1 `EpochPage` (`2^5 = 32` anonymity set)
/// - `m = 6`: 2 `EpochPage`s (`2^6 = 64` anonymity set)
/// - `m = 7`: 4 `EpochPage`s (`2^7 = 128` anonymity set)
pub const TRIPTYCH_M_ONE_PAGE: u8 = 5;
pub const TRIPTYCH_M_TWO_PAGES: u8 = 6;
pub const TRIPTYCH_M_FOUR_PAGES: u8 = 7;

/// Native Agave Bulletproof wire sizes (via `solana_zk_elgamal_proof_program` CPI).
pub const RANGE_U64_PROOF_LEN: usize = 672;
pub const RANGE_U128_PROOF_LEN: usize = 736;

/// Cross-base proofs bridging hidden-asset commitments `(A, V)` to Agave Pedersen `(G, C)`.
/// `CROSS_BASE_2_LEN = 256` also proves `A_2 - A_1 = (a_2 - a_1) * H` so both transfer outputs
/// carry completely independent, unlinkable hidden asset tags derived from ECDH while proving
/// they commit to the exact same hidden mint `G_mint`.
pub const CROSS_BASE_1_LEN: usize = 128;
pub const CROSS_BASE_2_LEN: usize = 256;

/// Verifiable auditor asset-tag encryption proof (`M_1, M_2` ElGamal of `G_mint` + DLEQ).
/// Wire: `M_1 (32) || M_2 (32) || R_1 (32) || R_2 (32) || s_m (32) || s_a (32) = 192 B`.
pub const AUDITOR_ASSET_PROOF_LEN: usize = 192;

/// Exact wire size of a Multi-Base Binary Triptych proof for exponent `m` and auditor flag.
///
/// Unaudited layout:
/// - `J` (32 B): nullifier / key image (`x^{-1} * U`)
/// - `A, B, C, D` (4 * 32 = 128 B): bit-decomposition Pedersen commitments
/// - `X[m], Y[m], W[m]` (3m * 32 B): masked degree-`<m` ring terms
/// - `f[m]` (m * 32 B): bit responses (`f_{j,1}`; `f_{j,0} = xi - f_j`)
/// - `z_a, z_c, z_x, z_q` (4 * 32 = 128 B): scalar opening responses
/// Total unaudited = `(9 + 4 * m) * 32` (`m=5`: 928 B; `m=6`: 1,056 B; `m=7`: 1,184 B).
///
/// Audited extension (appended when `pool.has_auditor()`):
/// - `S_1, S_2` (2 * 32 = 64 B): verifiable ElGamal of spent note pubkey `P_l` under `K_aud`
/// - `T[m], E[m]` (2m * 32 B): masked degree-`<m` auditor terms
/// - `z_aud` (32 B): auditor randomness response
/// Total audited extension = `(3 + 2 * m) * 32` (`m=5`: +416 B = 1,344 B; `m=6`: +480 B = 1,536 B; `m=7`: +544 B = 1,728 B).
#[inline]
pub const fn triptych_proof_len(m: u8, audited: bool) -> Result<usize, AudrenError> {
    if m != TRIPTYCH_M_ONE_PAGE && m != TRIPTYCH_M_TWO_PAGES && m != TRIPTYCH_M_FOUR_PAGES {
        return Err(AudrenError::InvalidInstruction);
    }
    let mu = m as usize;
    let base = (9 + 4 * mu) * 32;
    if audited {
        Ok(base + (3 + 2 * mu) * 32)
    } else {
        Ok(base)
    }
}

/// Number of `EpochPage` input accounts required for exponent `m`.
#[inline]
pub const fn input_pages_for_m(m: u8) -> Result<usize, AudrenError> {
    match m {
        TRIPTYCH_M_ONE_PAGE => Ok(1),
        TRIPTYCH_M_TWO_PAGES => Ok(2),
        TRIPTYCH_M_FOUR_PAGES => Ok(4),
        _ => Err(AudrenError::InvalidInstruction),
    }
}

/// Binary Triptych exponent `m` corresponding to `1`, `2`, or `4` input `EpochPage`s.
#[inline]
pub const fn m_for_input_pages(pages: usize) -> Result<u8, AudrenError> {
    match pages {
        1 => Ok(TRIPTYCH_M_ONE_PAGE),
        2 => Ok(TRIPTYCH_M_TWO_PAGES),
        4 => Ok(TRIPTYCH_M_FOUR_PAGES),
        _ => Err(AudrenError::InvalidInstruction),
    }
}

/// Output note wire block passed in `Deposit`, `Transfer`, `Merge`, `SwapViaRouter`, `Withdraw`:
/// `view_tag (1) || ephemeral_pk (32) || stealth_pk (32) || asset_tag (32) || commitment (32) || ciphertext (64) = 193 B`.
pub const NOTE_WIRE_LEN: usize = 1 + 32 + 32 + 32 + 32 + 64;

/// Stealth output descriptor for dynamic-amount swap outputs (`SwapViaRouter`) where `asset_tag`
/// and `commitment = actual_out * G_{mint_out}` are computed on-chain after the external router CPI:
/// `view_tag (1) || ephemeral_pk (32) || stealth_pk (32) || ciphertext (64) = 129 B`.
pub const DYNAMIC_OUTPUT_WIRE_LEN: usize = 1 + 32 + 32 + 64;
