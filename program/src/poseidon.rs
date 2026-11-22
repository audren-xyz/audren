//! On-chain `sol_poseidon` BN254 x^5 hashing, 4-ary Depth-18 incremental frontier append,
//! Depth-2 super-root aggregation, and canonical note / public-input hashing.

use audren_core::{
    is_canonical_fr, mask_to_fr_be as core_mask_to_fr_be, pack_u64_pair_be32, u64_to_be32,
    DOMAIN_NOTE, DOMAIN_PUB_HASH_A, DOMAIN_PUB_HASH_B, DOMAIN_PUB_HASH_FINAL, ZERO_HASHES_4ARY,
};
use pinocchio::error::ProgramError;
use solana_poseidon::{hashv, Endianness, Parameters};

use crate::state::{
    err, read_u64, AudrenError, LANE_DEPTH_4ARY, LN_OFF_CURRENT_ROOT, LN_OFF_FRONTIER,
    LN_OFF_NEXT_LEAF, NUM_LANES,
};

#[inline(always)]
pub fn ensure_canonical_fr(bytes: &[u8; 32]) -> Result<(), ProgramError> {
    if is_canonical_fr(bytes) {
        Ok(())
    } else {
        Err(err(AudrenError::InvalidFieldElement))
    }
}

#[inline(always)]
pub fn mask_to_fr_be(bytes: &[u8; 32]) -> [u8; 32] {
    core_mask_to_fr_be(*bytes)
}

#[inline]
pub fn poseidon4(
    a: &[u8; 32],
    b: &[u8; 32],
    c: &[u8; 32],
    d: &[u8; 32],
) -> Result<[u8; 32], ProgramError> {
    hashv(Parameters::Bn254X5, Endianness::BigEndian, &[a, b, c, d])
        .map(|h| h.to_bytes())
        .map_err(|_| err(AudrenError::PoseidonFailed))
}

#[inline]
pub fn poseidon5(
    a: &[u8; 32],
    b: &[u8; 32],
    c: &[u8; 32],
    d: &[u8; 32],
    e: &[u8; 32],
) -> Result<[u8; 32], ProgramError> {
    hashv(
        Parameters::Bn254X5,
        Endianness::BigEndian,
        &[a, b, c, d, e],
    )
    .map(|h| h.to_bytes())
    .map_err(|_| err(AudrenError::PoseidonFailed))
}

/// Canonical multi-asset note commitment:
/// `Poseidon5(DOMAIN_NOTE, stealth_owner, asset_id, amount, blinding)`.
pub fn compute_note_commitment(
    stealth_owner: &[u8; 32],
    asset_id: &[u8; 32],
    amount: u64,
    blinding: &[u8; 32],
) -> Result<[u8; 32], ProgramError> {
    let dom = u64_to_be32(DOMAIN_NOTE);
    let amt = u64_to_be32(amount);
    poseidon5(&dom, stealth_owner, asset_id, &amt, blinding)
}

/// Fold all public statement fields into the single Groth16 `public_input_hash`.
#[allow(clippy::too_many_arguments)]
pub fn compute_public_input_hash(
    super_root: &[u8; 32],
    nf0: &[u8; 32],
    nf1: &[u8; 32],
    cm0: &[u8; 32],
    cm1: &[u8; 32],
    cm2: &[u8; 32],
    public_asset_id: &[u8; 32],
    public_amount_out: u64,
    relayer_fee_amount: u64,
    ctx_hash: &[u8; 32],
) -> Result<[u8; 32], ProgramError> {
    let dom_a = u64_to_be32(DOMAIN_PUB_HASH_A);
    let dom_b = u64_to_be32(DOMAIN_PUB_HASH_B);
    let dom_f = u64_to_be32(DOMAIN_PUB_HASH_FINAL);
    let packed = pack_u64_pair_be32(public_amount_out, relayer_fee_amount);

    let h_a = poseidon5(&dom_a, super_root, nf0, nf1, cm0)?;
    let h_b = poseidon5(&dom_b, cm1, cm2, public_asset_id, &packed)?;
    poseidon4(&dom_f, &h_a, &h_b, ctx_hash)
}

/// Compute 4-ary depth-2 `super_root` across 16 lane slots (2x `sol_poseidon(4)` at 4 active lanes,
/// 3x at 8 active lanes, 5x at 16 active lanes). Inactive 4-lane groups fold directly to
/// `ZERO_HASHES_4ARY[19]`, guaranteeing bit-for-bit identical `super_root` before & after expansion.
pub fn compute_super_root_4ary(
    lane_roots: &[[u8; 32]; NUM_LANES],
    active_lanes: usize,
) -> Result<[u8; 32], ProgramError> {
    let g0 = poseidon4(
        &lane_roots[0],
        &lane_roots[1],
        &lane_roots[2],
        &lane_roots[3],
    )?;
    let g1 = if active_lanes > 4 {
        poseidon4(
            &lane_roots[4],
            &lane_roots[5],
            &lane_roots[6],
            &lane_roots[7],
        )?
    } else {
        ZERO_HASHES_4ARY[19]
    };
    let g2 = if active_lanes > 8 {
        poseidon4(
            &lane_roots[8],
            &lane_roots[9],
            &lane_roots[10],
            &lane_roots[11],
        )?
    } else {
        ZERO_HASHES_4ARY[19]
    };
    let g3 = if active_lanes > 12 {
        poseidon4(
            &lane_roots[12],
            &lane_roots[13],
            &lane_roots[14],
            &lane_roots[15],
        )?
    } else {
        ZERO_HASHES_4ARY[19]
    };
    poseidon4(&g0, &g1, &g2, &g3)
}

#[inline(always)]
fn frontier_offset(level: usize, slot: usize) -> usize {
    LN_OFF_FRONTIER + (level * 3 + slot) * 32
}

/// Append one leaf directly into `LaneTreeState` in-place (zero-copy, 18x `sol_poseidon(4)`).
pub fn append_leaf_4ary_in_place(
    lane_data: &mut [u8],
    leaf: &[u8; 32],
) -> Result<(u64, Option<[u8; 32]>), ProgramError> {
    let idx = read_u64(lane_data, LN_OFF_NEXT_LEAF);
    if idx >= (1u64 << 36) {
        return Err(err(AudrenError::Overflow));
    }
    let mut cur = *leaf;
    let mut k = idx;
    let mut finalized_sub_root: Option<[u8; 32]> = None;

    for h in 0..LANE_DEPTH_4ARY {
        let pos = (k & 3) as usize;
        if pos < 3 {
            let off = frontier_offset(h, pos);
            lane_data[off..off + 32].copy_from_slice(&cur);
        }

        let z = ZERO_HASHES_4ARY[h];
        let mut f0 = [0u8; 32];
        let mut f1 = [0u8; 32];
        let mut f2 = [0u8; 32];
        if pos >= 1 {
            let off0 = frontier_offset(h, 0);
            f0.copy_from_slice(&lane_data[off0..off0 + 32]);
        }
        if pos >= 2 {
            let off1 = frontier_offset(h, 1);
            f1.copy_from_slice(&lane_data[off1..off1 + 32]);
        }
        if pos == 3 {
            let off2 = frontier_offset(h, 2);
            f2.copy_from_slice(&lane_data[off2..off2 + 32]);
        }

        let c0 = if pos == 0 { &cur } else { &f0 };
        let c1 = match pos {
            0 => &z,
            1 => &cur,
            _ => &f1,
        };
        let c2 = match pos {
            0 | 1 => &z,
            2 => &cur,
            _ => &f2,
        };
        let c3 = if pos == 3 { &cur } else { &z };

        cur = poseidon4(c0, c1, c2, c3)?;

        if h == 3 && ((idx + 1) & 0xFF) == 0 {
            finalized_sub_root = Some(cur);
        }

        k >>= 2;
    }

    lane_data[LN_OFF_CURRENT_ROOT..LN_OFF_CURRENT_ROOT + 32].copy_from_slice(&cur);
    lane_data[LN_OFF_NEXT_LEAF..LN_OFF_NEXT_LEAF + 8].copy_from_slice(&(idx + 1).to_le_bytes());

    Ok((idx, finalized_sub_root))
}
