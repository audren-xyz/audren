//! 4-ary Depth-20 (`4^20 = 2^40 = 1.099 Trillion` notes) Merkle tree, R1CS membership gadget,
//! and deterministic historical prefix witness reconstruction.

use ark_bn254::Fr;
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    fields::fp::FpVar,
    select::CondSelectGadget,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use audren_core::layout::SUBTREE_LEAVES;

pub use audren_core::{LANE_DEPTH_4ARY, NUM_LANES, TOTAL_DEPTH_4ARY};

use crate::poseidon::{poseidon4, poseidon_hash_var};

/// Top super-root levels combining 16 lanes (`4^2 = 16`).
pub const SUPER_DEPTH_4ARY: usize = 2;

/// Subtree height (`4^4 = 256` leaves per `SubtreePage`).
pub const SUBTREE_LEVELS_4ARY: usize = 4;

/// Precomputed zero hashes for 4-ary tree: `ZERO_4[0] = 0`, `ZERO_4[h+1] = Poseidon4(Z[h], Z[h], Z[h], Z[h])`.
pub fn zero_hashes_4ary() -> [Fr; TOTAL_DEPTH_4ARY + 1] {
    let mut z = [Fr::from(0u64); TOTAL_DEPTH_4ARY + 1];
    for h in 0..TOTAL_DEPTH_4ARY {
        z[h + 1] = poseidon4(z[h], z[h], z[h], z[h]);
    }
    z
}

/// Compute 4-ary depth-2 `super_root` over 16 lane roots.
pub fn compute_super_root_4ary(lane_roots: &[Fr; NUM_LANES]) -> Fr {
    let g0 = poseidon4(lane_roots[0], lane_roots[1], lane_roots[2], lane_roots[3]);
    let g1 = poseidon4(lane_roots[4], lane_roots[5], lane_roots[6], lane_roots[7]);
    let g2 = poseidon4(lane_roots[8], lane_roots[9], lane_roots[10], lane_roots[11]);
    let g3 = poseidon4(
        lane_roots[12],
        lane_roots[13],
        lane_roots[14],
        lane_roots[15],
    );
    poseidon4(g0, g1, g2, g3)
}

/// Native 4-ary Merkle witness (3 siblings + 2-bit child position `0..=3` at each of 20 levels).
#[derive(Clone, Debug)]
pub struct MerklePath4Ary {
    /// Siblings at each level `h = 0..20` in canonical order (excluding the active child).
    pub siblings: [[Fr; 3]; TOTAL_DEPTH_4ARY],
    /// Child position `0..=3` at each level `h = 0..20` (`global_leaf_index` in base-4, LSB first).
    pub positions: [u8; TOTAL_DEPTH_4ARY],
}

impl Default for MerklePath4Ary {
    fn default() -> Self {
        Self {
            siblings: [[Fr::from(0u64); 3]; TOTAL_DEPTH_4ARY],
            positions: [0u8; TOTAL_DEPTH_4ARY],
        }
    }
}

impl MerklePath4Ary {
    /// Recover the exact 40-bit global leaf index from base-4 `positions`.
    pub fn global_leaf_index(&self) -> u64 {
        let mut idx = 0u64;
        for h in (0..TOTAL_DEPTH_4ARY).rev() {
            idx = (idx << 2) | (self.positions[h] as u64 & 3);
        }
        idx
    }

    /// Compute the root natively from `leaf`.
    pub fn compute_root(&self, leaf: Fr) -> Fr {
        let mut cur = leaf;
        for h in 0..TOTAL_DEPTH_4ARY {
            let s = self.siblings[h];
            let children = match self.positions[h] {
                0 => [cur, s[0], s[1], s[2]],
                1 => [s[0], cur, s[1], s[2]],
                2 => [s[0], s[1], cur, s[2]],
                3 => [s[0], s[1], s[2], cur],
                p => panic!("invalid 4-ary position {p}"),
            };
            cur = poseidon4(children[0], children[1], children[2], children[3]);
        }
        cur
    }
}

/// R1CS gadget for 4-ary Depth-20 Merkle root computation + 40-bit `global_leaf_index` reconstruction.
pub fn constrain_merkle_root_4ary(
    cs: ConstraintSystemRef<Fr>,
    leaf: &FpVar<Fr>,
    path: &MerklePath4Ary,
) -> Result<(FpVar<Fr>, FpVar<Fr>), SynthesisError> {
    let mut cur = leaf.clone();
    let mut leaf_index = FpVar::Constant(Fr::from(0u64));
    let mut pow4 = Fr::from(1u64);

    for h in 0..TOTAL_DEPTH_4ARY {
        let pos = path.positions[h];
        let b0 = Boolean::new_witness(cs.clone(), || Ok((pos & 1) != 0))?;
        let b1 = Boolean::new_witness(cs.clone(), || Ok(((pos >> 1) & 1) != 0))?;

        let s0 = FpVar::new_witness(cs.clone(), || Ok(path.siblings[h][0]))?;
        let s1 = FpVar::new_witness(cs.clone(), || Ok(path.siblings[h][1]))?;
        let s2 = FpVar::new_witness(cs.clone(), || Ok(path.siblings[h][2]))?;

        let c0_lo = FpVar::conditionally_select(&b0, &s0, &cur)?;
        let c0 = FpVar::conditionally_select(&b1, &s0, &c0_lo)?;

        let c1_lo = FpVar::conditionally_select(&b0, &cur, &s0)?;
        let c1 = FpVar::conditionally_select(&b1, &s1, &c1_lo)?;

        let c2_hi = FpVar::conditionally_select(&b0, &s2, &cur)?;
        let c2 = FpVar::conditionally_select(&b1, &c2_hi, &s1)?;

        let c3_hi = FpVar::conditionally_select(&b0, &cur, &s2)?;
        let c3 = FpVar::conditionally_select(&b1, &c3_hi, &s2)?;

        cur = poseidon_hash_var(cs.clone(), &[c0, c1, c2, c3])?;

        let digit = FpVar::from(b0) + FpVar::from(b1) * Fr::from(2u64);
        leaf_index += digit * pow4;
        pow4 *= Fr::from(4u64);
    }

    Ok((cur, leaf_index))
}

/// Compute the 4-level (256-leaf) subtree root of a `SubtreePage`, truncating at `valid_len <= 256`
/// and zero-padding any tail slots with `ZERO_4[0] = 0`.
pub fn compute_subtree_256_root(leaves: &[Fr], valid_len: usize) -> Fr {
    assert!(valid_len <= SUBTREE_LEAVES);
    let mut level = vec![Fr::from(0u64); SUBTREE_LEAVES];
    for (i, slot) in level.iter_mut().enumerate().take(valid_len) {
        *slot = leaves[i];
    }
    let mut len = SUBTREE_LEAVES;
    while len > 1 {
        let next_len = len / 4;
        for j in 0..next_len {
            level[j] = poseidon4(
                level[4 * j],
                level[4 * j + 1],
                level[4 * j + 2],
                level[4 * j + 3],
            );
        }
        len = next_len;
    }
    level[0]
}

/// Extract the 4 levels (`12` siblings + `4` base-4 positions) inside a sealed 256-leaf `SubtreePage`
/// for `target_offset in 0..256` so `CompactWalletStore` can freeze them and discard the 8 KB page.
pub fn extract_intra_subtree_siblings(
    page_leaves: &[Fr],
    valid_len: usize,
    target_offset: usize,
) -> ([[Fr; 3]; SUBTREE_LEVELS_4ARY], [u8; SUBTREE_LEVELS_4ARY]) {
    assert!(target_offset < valid_len && valid_len <= SUBTREE_LEAVES);
    let mut page_nodes = vec![Fr::from(0u64); SUBTREE_LEAVES];
    page_nodes[..valid_len].copy_from_slice(&page_leaves[..valid_len]);
    let mut siblings = [[Fr::from(0u64); 3]; SUBTREE_LEVELS_4ARY];
    let mut positions = [0u8; SUBTREE_LEVELS_4ARY];
    let mut cur_idx = target_offset;
    let mut cur_len = SUBTREE_LEAVES;
    for h in 0..SUBTREE_LEVELS_4ARY {
        let group_start = (cur_idx / 4) * 4;
        let pos = cur_idx % 4;
        positions[h] = pos as u8;
        let mut s_i = 0;
        for k in 0..4 {
            if k != pos {
                siblings[h][s_i] = page_nodes[group_start + k];
                s_i += 1;
            }
        }
        let next_len = cur_len / 4;
        for j in 0..next_len {
            page_nodes[j] = poseidon4(
                page_nodes[4 * j],
                page_nodes[4 * j + 1],
                page_nodes[4 * j + 2],
                page_nodes[4 * j + 3],
            );
        }
        cur_idx /= 4;
        cur_len = next_len;
    }
    (siblings, positions)
}

/// Assemble a full 20-level `MerklePath4Ary` from pre-frozen intra-subtree siblings (`levels 0..4`)
/// plus upper level-4 finalized subroots (`levels 4..18`) and `GlobalRootHistory` snapshot `lane_roots` (`levels 18..20`).
#[allow(clippy::too_many_arguments)]
pub fn build_witness_from_frozen_subsiblings(
    lane_id: usize,
    target_leaf_idx: u64,
    intra_siblings: &[[Fr; 3]; SUBTREE_LEVELS_4ARY],
    intra_positions: &[u8; SUBTREE_LEVELS_4ARY],
    ckpt_lane_roots: &[Fr; NUM_LANES],
    ckpt_lane_leaf_count: u64,
    finalized_subtree_roots: &[Fr],
    frontier_page_leaves: Option<&[Fr]>,
) -> MerklePath4Ary {
    assert!(lane_id < NUM_LANES);
    assert!(target_leaf_idx < ckpt_lane_leaf_count);

    let zeros = zero_hashes_4ary();
    let mut path = MerklePath4Ary::default();
    path.siblings[..SUBTREE_LEVELS_4ARY].copy_from_slice(intra_siblings);
    path.positions[..SUBTREE_LEVELS_4ARY].copy_from_slice(intra_positions);

    let target_page_idx = (target_leaf_idx / SUBTREE_LEAVES as u64) as usize;
    let frontier_page_idx = (ckpt_lane_leaf_count / SUBTREE_LEAVES as u64) as usize;
    let frontier_rem = (ckpt_lane_leaf_count % SUBTREE_LEAVES as u64) as usize;

    let mut level_nodes: Vec<Fr> = Vec::with_capacity(frontier_page_idx + 1);
    level_nodes.extend_from_slice(&finalized_subtree_roots[..frontier_page_idx]);
    if frontier_rem > 0 {
        let f_leaves = frontier_page_leaves
            .expect("frontier_page_leaves required when ckpt_lane_leaf_count % 256 != 0");
        level_nodes.push(compute_subtree_256_root(f_leaves, frontier_rem));
    }

    let mut node_idx = target_page_idx;
    for (h, &zero_at_h) in zeros
        .iter()
        .enumerate()
        .take(LANE_DEPTH_4ARY)
        .skip(SUBTREE_LEVELS_4ARY)
    {
        let group_start = (node_idx / 4) * 4;
        let pos = node_idx % 4;
        path.positions[h] = pos as u8;

        let mut s_i = 0;
        for k in 0..4 {
            if k != pos {
                let child_i = group_start + k;
                path.siblings[h][s_i] = if child_i < level_nodes.len() {
                    level_nodes[child_i]
                } else {
                    zero_at_h
                };
                s_i += 1;
            }
        }

        let next_len = level_nodes.len().div_ceil(4);
        let mut next_level = Vec::with_capacity(next_len);
        for g in 0..next_len {
            let base = g * 4;
            let c0 = *level_nodes.get(base).unwrap_or(&zero_at_h);
            let c1 = *level_nodes.get(base + 1).unwrap_or(&zero_at_h);
            let c2 = *level_nodes.get(base + 2).unwrap_or(&zero_at_h);
            let c3 = *level_nodes.get(base + 3).unwrap_or(&zero_at_h);
            next_level.push(poseidon4(c0, c1, c2, c3));
        }
        level_nodes = next_level;
        node_idx /= 4;
    }

    let group4 = lane_id / 4;
    let pos18 = lane_id % 4;
    path.positions[LANE_DEPTH_4ARY] = pos18 as u8;
    let mut s_i = 0;
    for k in 0..4 {
        if k != pos18 {
            path.siblings[LANE_DEPTH_4ARY][s_i] = ckpt_lane_roots[group4 * 4 + k];
            s_i += 1;
        }
    }

    let group_hashes = [
        poseidon4(
            ckpt_lane_roots[0],
            ckpt_lane_roots[1],
            ckpt_lane_roots[2],
            ckpt_lane_roots[3],
        ),
        poseidon4(
            ckpt_lane_roots[4],
            ckpt_lane_roots[5],
            ckpt_lane_roots[6],
            ckpt_lane_roots[7],
        ),
        poseidon4(
            ckpt_lane_roots[8],
            ckpt_lane_roots[9],
            ckpt_lane_roots[10],
            ckpt_lane_roots[11],
        ),
        poseidon4(
            ckpt_lane_roots[12],
            ckpt_lane_roots[13],
            ckpt_lane_roots[14],
            ckpt_lane_roots[15],
        ),
    ];

    path.positions[LANE_DEPTH_4ARY + 1] = group4 as u8;
    let mut s_i = 0;
    for (k, &gh) in group_hashes.iter().enumerate() {
        if k != group4 {
            path.siblings[LANE_DEPTH_4ARY + 1][s_i] = gh;
            s_i += 1;
        }
    }

    path
}

/// Reconstruct the exact historical 4-ary Depth-20 Merkle path for `(lane_id, target_leaf_idx)`
/// at a `GlobalRootHistory` snapshot.
pub fn build_historical_witness_4ary(
    lane_id: usize,
    target_leaf_idx: u64,
    ckpt_lane_roots: &[Fr; NUM_LANES],
    ckpt_lane_leaf_count: u64,
    finalized_subtree_roots: &[Fr],
    target_page_leaves: &[Fr],
    frontier_page_leaves: Option<&[Fr]>,
) -> MerklePath4Ary {
    let target_page_idx = (target_leaf_idx / SUBTREE_LEAVES as u64) as usize;
    let target_offset = (target_leaf_idx % SUBTREE_LEAVES as u64) as usize;
    let frontier_page_idx = (ckpt_lane_leaf_count / SUBTREE_LEAVES as u64) as usize;
    let frontier_rem = (ckpt_lane_leaf_count % SUBTREE_LEAVES as u64) as usize;
    let target_valid_len = if target_page_idx == frontier_page_idx {
        frontier_rem
    } else {
        SUBTREE_LEAVES
    };
    let (intra_sibs, intra_pos) =
        extract_intra_subtree_siblings(target_page_leaves, target_valid_len, target_offset);
    build_witness_from_frozen_subsiblings(
        lane_id,
        target_leaf_idx,
        &intra_sibs,
        &intra_pos,
        ckpt_lane_roots,
        ckpt_lane_leaf_count,
        finalized_subtree_roots,
        frontier_page_leaves,
    )
}
