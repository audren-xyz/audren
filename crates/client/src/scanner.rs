//! Stateless account/witness reconstruction helpers over any ordinary Solana account fetcher.

use ark_bn254::Fr;
use audren_circuits::{
    merkle::{build_historical_witness_4ary, MerklePath4Ary},
    poseidon::fr_from_be_bytes_strict,
};
use audren_core::{
    layout::{
        read_32, read_u16, LaneTreeHeader, PoolState, RootCheckpoint, SB_OFF_COUNT, SB_OFF_LEAVES,
        SR_OFF_COUNT, SR_OFF_ROOTS, SUBROOTS_PER_PAGE, SUBROOT_MAGIC, SUBROOT_PAGE_LEN,
        SUBTREE_LEAVES, SUBTREE_MAGIC, SUBTREE_PAGE_LEN,
    },
    NUM_LANES,
};
use solana_address::Address;

use crate::{
    pda::{derive_checkpoint_pda, derive_lane_pda, derive_pool_pda, derive_subroot_pda, derive_subtree_pda},
    ClientError,
};

pub fn decode_pool_state(data: &[u8]) -> Result<PoolState, ClientError> {
    PoolState::decode(data).ok_or(ClientError::InvalidEncoding("invalid PoolState account"))
}

pub fn decode_lane_header(data: &[u8]) -> Result<LaneTreeHeader, ClientError> {
    LaneTreeHeader::decode(data).ok_or(ClientError::InvalidEncoding("invalid LaneTreeState account"))
}

pub fn decode_root_checkpoint(data: &[u8]) -> Result<RootCheckpoint, ClientError> {
    RootCheckpoint::decode(data).ok_or(ClientError::InvalidEncoding("invalid RootCheckpoint account"))
}

/// Reconstruct an exact historical 4-ary Depth-20 `MerklePath4Ary` witness for `(lane_id, leaf_idx)`
/// at `RootCheckpoint(ckpt_slot_idx)` from any account-fetch closure (LiteSVM or Solana RPC).
pub fn reconstruct_witness_with<F>(
    mut get_account_data: F,
    program_id: &Address,
    pool_id: u32,
    ckpt_slot_idx: u16,
    lane_id: u8,
    leaf_idx: u64,
) -> Result<(RootCheckpoint, Fr, MerklePath4Ary), ClientError>
where
    F: FnMut(&Address) -> Option<Vec<u8>>,
{
    let (ckpt_pda, _) = derive_checkpoint_pda(program_id, pool_id, ckpt_slot_idx);
    let ckpt_data = get_account_data(&ckpt_pda)
        .ok_or(ClientError::WitnessNotFound("RootCheckpoint account missing"))?;
    let ckpt = decode_root_checkpoint(&ckpt_data)?;

    let l = lane_id as usize;
    let ckpt_count = ckpt.lane_counts[l];
    if leaf_idx >= ckpt_count {
        return Err(ClientError::WitnessNotFound("leaf_idx >= checkpoint lane count"));
    }

    let target_page_idx = leaf_idx / SUBTREE_LEAVES as u64;
    let frontier_page_idx = ckpt_count / SUBTREE_LEAVES as u64;
    let frontier_rem = (ckpt_count % SUBTREE_LEAVES as u64) as usize;

    let mut finalized_roots = Vec::with_capacity(frontier_page_idx as usize);
    let needed_sr_pages = (frontier_page_idx as usize).div_ceil(SUBROOTS_PER_PAGE);
    for rp in 0..needed_sr_pages {
        let (sr_pda, _) = derive_subroot_pda(program_id, pool_id, lane_id, rp as u64);
        let sr_data = get_account_data(&sr_pda)
            .ok_or(ClientError::WitnessNotFound("SubtreeRootPage missing"))?;
        if sr_data.len() != SUBROOT_PAGE_LEN || sr_data[0..8] != SUBROOT_MAGIC {
            return Err(ClientError::InvalidEncoding("invalid SubtreeRootPage"));
        }
        let cnt = read_u16(&sr_data, SR_OFF_COUNT) as usize;
        for j in 0..cnt {
            if finalized_roots.len() == frontier_page_idx as usize {
                break;
            }
            let b = read_32(&sr_data, SR_OFF_ROOTS + j * 32);
            finalized_roots.push(
                fr_from_be_bytes_strict(&b).ok_or(ClientError::InvalidFieldElement)?,
            );
        }
    }

    let read_sub_leaves = |get_fn: &mut F, seq: u64| -> Result<Vec<Fr>, ClientError> {
        let (sub_pda, _) = derive_subtree_pda(program_id, pool_id, lane_id, seq);
        let data = get_fn(&sub_pda).ok_or(ClientError::WitnessNotFound("SubtreePage missing"))?;
        if data.len() != SUBTREE_PAGE_LEN || data[0..8] != SUBTREE_MAGIC {
            return Err(ClientError::InvalidEncoding("invalid SubtreePage"));
        }
        let cnt = read_u16(&data, SB_OFF_COUNT) as usize;
        let mut leaves = Vec::with_capacity(cnt);
        for i in 0..cnt {
            let b = read_32(&data, SB_OFF_LEAVES + i * 32);
            leaves.push(fr_from_be_bytes_strict(&b).ok_or(ClientError::InvalidFieldElement)?);
        }
        Ok(leaves)
    };

    let target_leaves = read_sub_leaves(&mut get_account_data, target_page_idx)?;
    let frontier_leaves = if frontier_rem > 0 {
        if frontier_page_idx == target_page_idx {
            Some(target_leaves.clone())
        } else {
            Some(read_sub_leaves(&mut get_account_data, frontier_page_idx)?)
        }
    } else {
        None
    };

    let mut lane_roots_fr = [Fr::from(0u64); NUM_LANES];
    for i in 0..NUM_LANES {
        lane_roots_fr[i] =
            fr_from_be_bytes_strict(&ckpt.lane_roots[i]).ok_or(ClientError::InvalidFieldElement)?;
    }
    let path = build_historical_witness_4ary(
        l,
        leaf_idx,
        &lane_roots_fr,
        ckpt_count,
        &finalized_roots,
        &target_leaves,
        frontier_leaves.as_deref(),
    );
    let super_root =
        fr_from_be_bytes_strict(&ckpt.super_root).ok_or(ClientError::InvalidFieldElement)?;
    Ok((ckpt, super_root, path))
}

/// Convenience reader for `PoolState` + active lane headers via any fetcher.
pub fn fetch_pool_and_lanes<F>(
    mut get_account_data: F,
    program_id: &Address,
    pool_id: u32,
) -> Result<(PoolState, Vec<LaneTreeHeader>), ClientError>
where
    F: FnMut(&Address) -> Option<Vec<u8>>,
{
    let (pool_pda, _) = derive_pool_pda(program_id, pool_id);
    let pool_data = get_account_data(&pool_pda)
        .ok_or(ClientError::WitnessNotFound("PoolState missing"))?;
    let pool = decode_pool_state(&pool_data)?;
    let mut lanes = Vec::with_capacity(pool.active_lanes as usize);
    for l in 0..pool.active_lanes {
        let (lpda, _) = derive_lane_pda(program_id, pool_id, l);
        let ldata = get_account_data(&lpda)
            .ok_or(ClientError::WitnessNotFound("LaneTreeState missing"))?;
        lanes.push(decode_lane_header(&ldata)?);
    }
    Ok((pool, lanes))
}
