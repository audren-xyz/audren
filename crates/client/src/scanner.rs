//! Stateless account/witness reconstruction and 2-pass `CompactWalletStore` sync helpers
//! over any ordinary Solana account fetcher (LiteSVM or Solana RPC).

use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

use ark_bn254::Fr;
use audren_circuits::{
    merkle::{build_historical_witness_4ary, compute_subtree_256_root, MerklePath4Ary},
    poseidon::{fr_from_be_bytes_strict, fr_to_be_bytes},
};
use audren_core::{
    layout::{
        read_32, read_u16, read_u64, LaneTreeHeader, PoolState, RootCheckpoint, MEMO_CT_LEN,
        MEMO_MAGIC, MEMO_NOTES_PER_PAGE, MEMO_PAGE_LEN, MM_OFF_CIPHERTEXTS, MM_OFF_CLOSED_SLOT,
        MM_OFF_COUNT, MM_OFF_EPHEMERAL_PKS, MM_OFF_VIEW_TAGS, NF_OFF_CLOSED_SLOT, NF_OFF_COUNT,
        NF_PAGE_LEN, NF_PAGE_MAGIC, NF_PER_PAGE, SB_OFF_COUNT, SB_OFF_LEAVES, SR_OFF_COUNT,
        SR_OFF_ROOTS, SUBROOTS_PER_PAGE, SUBROOT_MAGIC, SUBROOT_PAGE_LEN, SUBTREE_LEAVES,
        SUBTREE_MAGIC, SUBTREE_PAGE_LEN,
    },
    NUM_LANES,
};
use solana_address::Address;

use crate::{
    keys::{check_memo_view_tag, try_decrypt_and_verify_memo_entry, FullViewingKey},
    pda::{
        derive_checkpoint_pda, derive_lane_pda, derive_memo_pda, derive_nf_page_pda,
        derive_pool_pda, derive_subroot_pda, derive_subtree_pda,
    },
    store::CompactWalletStore,
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
    for (dst, src) in lane_roots_fr.iter_mut().zip(ckpt.lane_roots.iter()) {
        *dst = fr_from_be_bytes_strict(src).ok_or(ClientError::InvalidFieldElement)?;
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

fn read_subtree_leaves_be<F>(
    get_account_data: &mut F,
    program_id: &Address,
    pool_id: u32,
    lane_id: u8,
    sub_seq: u64,
) -> Result<Option<Vec<[u8; 32]>>, ClientError>
where
    F: FnMut(&Address) -> Option<Vec<u8>>,
{
    let (sub_pda, _) = derive_subtree_pda(program_id, pool_id, lane_id, sub_seq);
    let Some(data) = get_account_data(&sub_pda) else {
        return Ok(None);
    };
    if data.len() != SUBTREE_PAGE_LEN || data[0..8] != SUBTREE_MAGIC {
        return Err(ClientError::InvalidEncoding("invalid SubtreePage"));
    }
    let cnt = read_u16(&data, SB_OFF_COUNT) as usize;
    let mut leaves = Vec::with_capacity(cnt);
    for i in 0..cnt {
        leaves.push(read_32(&data, SB_OFF_LEAVES + i * 32));
    }
    Ok(Some(leaves))
}

/// Incrementally sync `CompactWalletStore` across ALL active lanes using a strict **2-pass sync**:
///
/// - **Pass 1:** Sync finalized subroots via `SubtreeRootPage` (`9,664 B` / 300 subroots), skip
///   sealed pre-`birthday_slot` `MemoPage`s via binary search, view-tag filter `MemoPage`s, fetch
///   historical `SubtreePage`s ONLY on view-tag hits / unfrozen notes / just-sealed frontier, and
///   update live frontiers across ALL active lanes so every owned note is present in `store.notes`.
/// - **Pass 2:** Stream `NullifierPage`s across ALL active lanes against an `O(owned_unspent_notes)`
///   prefix map and immediately discard every stranger prefix (zero unbounded growth).
pub fn sync_compact_store_with<F>(
    store: &mut CompactWalletStore,
    fvk: &FullViewingKey,
    mut get_account_data: F,
    program_id: &Address,
) -> Result<(PoolState, Vec<LaneTreeHeader>, usize), ClientError>
where
    F: FnMut(&Address) -> Option<Vec<u8>>,
{
    let pool_id = store.pool_id;
    let birthday_slot = store.birthday_slot;
    let (pool, lanes) = fetch_pool_and_lanes(&mut get_account_data, program_id, pool_id)?;

    let mut discovered_notes = 0usize;

    // =========================================================================
    // PASS 1: SubtreeRootPage + MemoPage + frontier across ALL active lanes
    // =========================================================================
    for lane_hdr in &lanes {
        let lane_id = lane_hdr.lane_id;
        let l = lane_id as usize;
        let finalized_count = lane_hdr.next_leaf / SUBTREE_LEAVES as u64;
        let frontier_rem = (lane_hdr.next_leaf % SUBTREE_LEAVES as u64) as usize;
        let old_frontier_sub_seq = store.lanes[l].frontier_sub_seq;
        let old_frontier_leaves = store.lanes[l].frontier_leaves.clone();

        // 1A. Fast-sync finalized subroots via SubtreeRootPage (fallback to SubtreePage only if missing)
        let mut fallback_subtrees: BTreeSet<u64> = BTreeSet::new();
        if finalized_count > store.lanes[l].finalized_subroots.len() as u64 {
            let start_sr = (store.lanes[l].finalized_subroots.len() as u64) / SUBROOTS_PER_PAGE as u64;
            let end_sr = (finalized_count - 1) / SUBROOTS_PER_PAGE as u64;
            for rp in start_sr..=end_sr {
                let (sr_pda, _) = derive_subroot_pda(program_id, pool_id, lane_id, rp);
                if let Some(sr_raw) = get_account_data(&sr_pda) {
                    store.ingest_subroot_pages(lane_id, &[(rp, &sr_raw)], Some(finalized_count))?;
                } else {
                    let base = rp * SUBROOTS_PER_PAGE as u64;
                    let end = (base + SUBROOTS_PER_PAGE as u64).min(finalized_count);
                    for s in base..end {
                        fallback_subtrees.insert(s);
                    }
                }
            }
        }

        // 1B. Optional birthday_slot binary search over sealed MemoPages
        if birthday_slot > 0 && lane_hdr.next_leaf > 0 && store.lanes[l].next_memo_leaf == 0 {
            let target_memo_max = (lane_hdr.next_leaf - 1) / MEMO_NOTES_PER_PAGE as u64;
            if target_memo_max > 2 {
                let mut lo = 0u64;
                let mut hi = target_memo_max + 1;
                while lo < hi {
                    let mid = (lo + hi) / 2;
                    let (mpda, _) = derive_memo_pda(program_id, pool_id, lane_id, mid);
                    if let Some(mraw) = get_account_data(&mpda) {
                        if mraw.len() >= 64 && mraw[0..8] == MEMO_MAGIC {
                            let cnt = read_u16(&mraw, MM_OFF_COUNT) as usize;
                            let closed = read_u64(&mraw, MM_OFF_CLOSED_SLOT);
                            if cnt == MEMO_NOTES_PER_PAGE && closed > 0 && closed < birthday_slot {
                                lo = mid + 1;
                                continue;
                            }
                        }
                    }
                    hi = mid;
                }
                if lo > 0 {
                    store.lanes[l].next_memo_leaf = (lo * MEMO_NOTES_PER_PAGE as u64).min(lane_hdr.next_leaf);
                }
            }
        }

        // 1C. Scan MemoPages with view-tag prefilter; fetch SubtreePage only on match/need
        let mut fetched_subtrees: BTreeMap<u64, Vec<[u8; 32]>> = BTreeMap::new();
        if lane_hdr.next_leaf > 0 && store.lanes[l].next_memo_leaf < lane_hdr.next_leaf {
            let start_memo = store.lanes[l].next_memo_leaf / MEMO_NOTES_PER_PAGE as u64;
            let target_memo_max = (lane_hdr.next_leaf - 1) / MEMO_NOTES_PER_PAGE as u64;
            let mut cursor = store.lanes[l].next_memo_leaf;

            'memo_loop: for m in start_memo..=target_memo_max {
                let (mpda, _) = derive_memo_pda(program_id, pool_id, lane_id, m);
                let Some(mraw) = get_account_data(&mpda) else {
                    break;
                };
                if mraw.len() != MEMO_PAGE_LEN || mraw[0..8] != MEMO_MAGIC {
                    return Err(ClientError::InvalidEncoding("invalid MemoPage"));
                }
                let count = read_u16(&mraw, MM_OFF_COUNT) as usize;
                let closed_slot = read_u64(&mraw, MM_OFF_CLOSED_SLOT);
                let page_base = m * MEMO_NOTES_PER_PAGE as u64;
                let start_slot = cursor.saturating_sub(page_base) as usize;
                let max_for_snapshot =
                    (lane_hdr.next_leaf.saturating_sub(page_base) as usize).min(MEMO_NOTES_PER_PAGE);
                let limit_slot = count.min(max_for_snapshot);

                if start_slot == 0
                    && birthday_slot > 0
                    && count == MEMO_NOTES_PER_PAGE
                    && closed_slot > 0
                    && closed_slot < birthday_slot
                {
                    cursor = page_base + limit_slot as u64;
                    if count < max_for_snapshot {
                        break;
                    }
                    continue;
                }

                for slot in start_slot..limit_slot {
                    let vt = [
                        mraw[MM_OFF_VIEW_TAGS + slot * 2],
                        mraw[MM_OFF_VIEW_TAGS + slot * 2 + 1],
                    ];
                    let epk = read_32(&mraw, MM_OFF_EPHEMERAL_PKS + slot * 32);
                    if check_memo_view_tag(fvk, vt, &epk) {
                        let leaf_idx = page_base + slot as u64;
                        let sub_seq = leaf_idx / SUBTREE_LEAVES as u64;
                        let sub_slot = (leaf_idx % SUBTREE_LEAVES as u64) as usize;

                        if let Entry::Vacant(e) = fetched_subtrees.entry(sub_seq) {
                            if let Some(leaves) = read_subtree_leaves_be(
                                &mut get_account_data,
                                program_id,
                                pool_id,
                                lane_id,
                                sub_seq,
                            )? {
                                e.insert(leaves);
                            }
                        }

                        let cm_be = if let Some(leaves) = fetched_subtrees.get(&sub_seq) {
                            if sub_slot >= leaves.len() {
                                break 'memo_loop;
                            }
                            leaves[sub_slot]
                        } else if sub_seq == old_frontier_sub_seq && sub_slot < old_frontier_leaves.len() {
                            old_frontier_leaves[sub_slot]
                        } else {
                            break 'memo_loop;
                        };

                        let ct_off = MM_OFF_CIPHERTEXTS + slot * MEMO_CT_LEN;
                        let ct56: [u8; MEMO_CT_LEN] =
                            mraw[ct_off..ct_off + MEMO_CT_LEN].try_into().unwrap();
                        if let Some(dec) =
                            try_decrypt_and_verify_memo_entry(fvk, vt, &epk, &ct56, &cm_be)
                        {
                            if store.record_verified_memo(fvk, lane_id, leaf_idx, &dec, cm_be)? {
                                discovered_notes += 1;
                            }
                        }
                    }
                    cursor = page_base + slot as u64 + 1;
                }
                if count < max_for_snapshot {
                    break;
                }
            }
            if cursor > store.lanes[l].next_memo_leaf {
                store.lanes[l].next_memo_leaf = cursor;
            }
        }

        // 1D. Fetch any still-needed SubtreePages: live frontier, unfrozen sealed notes,
        //     just-sealed previous frontier, or SubtreeRootPage fallback pages.
        let mut extra_subtrees: BTreeSet<u64> = fallback_subtrees.clone();
        if frontier_rem > 0 {
            extra_subtrees.insert(finalized_count);
        }
        for note in &store.notes {
            if note.lane_id == lane_id && note.frozen_intra_siblings.is_none() {
                let s = note.leaf_index / SUBTREE_LEAVES as u64;
                if s < finalized_count {
                    extra_subtrees.insert(s);
                }
            }
        }
        if finalized_count > 0
            && !old_frontier_leaves.is_empty()
            && old_frontier_sub_seq == finalized_count - 1
        {
            extra_subtrees.insert(finalized_count - 1);
        }
        for s in extra_subtrees {
            if let Entry::Vacant(e) = fetched_subtrees.entry(s) {
                if let Some(leaves) = read_subtree_leaves_be(
                    &mut get_account_data,
                    program_id,
                    pool_id,
                    lane_id,
                    s,
                )? {
                    e.insert(leaves);
                }
            }
        }

        for s in fallback_subtrees {
            if let Some(leaves) = fetched_subtrees.get(&s) {
                if leaves.len() == SUBTREE_LEAVES {
                    let fr_leaves: Vec<Fr> = leaves
                        .iter()
                        .map(|b| fr_from_be_bytes_strict(b).ok_or(ClientError::InvalidFieldElement))
                        .collect::<Result<_, _>>()?;
                    let subroot =
                        fr_to_be_bytes(&compute_subtree_256_root(&fr_leaves, SUBTREE_LEAVES));
                    while store.lanes[l].finalized_subroots.len() < s as usize {
                        store.lanes[l].finalized_subroots.push([0u8; 32]);
                    }
                    if store.lanes[l].finalized_subroots.len() == s as usize {
                        store.lanes[l].finalized_subroots.push(subroot);
                    } else {
                        store.lanes[l].finalized_subroots[s as usize] = subroot;
                    }
                }
            }
        }

        for (&s, leaves) in &fetched_subtrees {
            if leaves.len() == SUBTREE_LEAVES {
                store.freeze_owned_notes_in_subtree_page(lane_id, s, leaves)?;
            }
        }

        if finalized_count > 0 {
            let latest_sealed = finalized_count - 1;
            if let Some(leaves) = fetched_subtrees.get(&latest_sealed) {
                if leaves.len() == SUBTREE_LEAVES {
                    store.lanes[l].prev_sealed_sub_seq = Some(latest_sealed);
                    store.lanes[l].prev_sealed_leaves = leaves.clone();
                }
            } else if old_frontier_sub_seq == latest_sealed
                && !old_frontier_leaves.is_empty()
                && store.lanes[l].prev_sealed_sub_seq != Some(latest_sealed)
            {
                store.lanes[l].prev_sealed_sub_seq = Some(old_frontier_sub_seq);
                store.lanes[l].prev_sealed_leaves = old_frontier_leaves;
            }
        }

        if frontier_rem > 0 {
            if let Some(leaves) = fetched_subtrees.get(&finalized_count) {
                if leaves.len() >= frontier_rem {
                    store.lanes[l].frontier_sub_seq = finalized_count;
                    store.lanes[l].frontier_leaves = leaves[..frontier_rem].to_vec();
                }
            }
        } else if finalized_count >= store.lanes[l].frontier_sub_seq {
            store.lanes[l].frontier_sub_seq = finalized_count;
            store.lanes[l].frontier_leaves.clear();
        }
    }

    // =========================================================================
    // PASS 2: Stream NullifierPages across ALL active lanes (zero stranger prefixes stored)
    // =========================================================================
    let all_caught_up = lanes
        .iter()
        .all(|h| store.lanes[h.lane_id as usize].next_memo_leaf >= h.next_leaf);
    if all_caught_up {
        if !store.notes.iter().any(|n| !n.spent) {
            for lane_hdr in &lanes {
                let l = lane_hdr.lane_id as usize;
                store.lanes[l].next_nf_index = store.lanes[l].next_nf_index.max(lane_hdr.nf_count);
            }
        } else {
            for lane_hdr in &lanes {
                let lane_id = lane_hdr.lane_id;
                let l = lane_id as usize;
                if lane_hdr.nf_count == 0 || store.lanes[l].next_nf_index >= lane_hdr.nf_count {
                    continue;
                }
                if !store.notes.iter().any(|n| !n.spent) {
                    store.lanes[l].next_nf_index =
                        store.lanes[l].next_nf_index.max(lane_hdr.nf_count);
                    continue;
                }

                // Optional birthday_slot binary search on sealed NullifierPages
                if birthday_slot > 0 && store.lanes[l].next_nf_index == 0 {
                    let target_nf_max = (lane_hdr.nf_count - 1) / NF_PER_PAGE as u64;
                    if target_nf_max > 2 {
                        let mut lo = 0u64;
                        let mut hi = target_nf_max + 1;
                        while lo < hi {
                            let mid = (lo + hi) / 2;
                            let (npda, _) = derive_nf_page_pda(program_id, pool_id, lane_id, mid);
                            if let Some(nraw) = get_account_data(&npda) {
                                if nraw.len() >= 64 && nraw[0..8] == NF_PAGE_MAGIC {
                                    let cnt = read_u16(&nraw, NF_OFF_COUNT) as usize;
                                    let closed = read_u64(&nraw, NF_OFF_CLOSED_SLOT);
                                    if cnt == NF_PER_PAGE && closed > 0 && closed < birthday_slot {
                                        lo = mid + 1;
                                        continue;
                                    }
                                }
                            }
                            hi = mid;
                        }
                        if lo > 0 {
                            store.lanes[l].next_nf_index =
                                (lo * NF_PER_PAGE as u64).min(lane_hdr.nf_count);
                        }
                    }
                }

                if store.lanes[l].next_nf_index >= lane_hdr.nf_count {
                    continue;
                }
                let start_nf = store.lanes[l].next_nf_index / NF_PER_PAGE as u64;
                let target_nf_max = (lane_hdr.nf_count - 1) / NF_PER_PAGE as u64;
                for n in start_nf..=target_nf_max {
                    let (npda, _) = derive_nf_page_pda(program_id, pool_id, lane_id, n);
                    let Some(nraw) = get_account_data(&npda) else {
                        break;
                    };
                    if nraw.len() != NF_PAGE_LEN || nraw[0..8] != NF_PAGE_MAGIC {
                        return Err(ClientError::InvalidEncoding("invalid NullifierPage"));
                    }
                    store.ingest_nullifier_page(lane_id, n, &nraw, Some(lane_hdr.nf_count))?;
                    if !store.notes.iter().any(|note| !note.spent) {
                        store.lanes[l].next_nf_index =
                            store.lanes[l].next_nf_index.max(lane_hdr.nf_count);
                        break;
                    }
                }
            }
        }
    }

    Ok((pool, lanes, discovered_notes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    use audren_circuits::{
        note::{compute_note_commitment, derive_asset_id, derive_stealth_owner},
        poseidon::fr_to_be_bytes,
    };
    use audren_core::{
        layout::{
            LANE_MAGIC, LANE_STATE_LEN, LN_OFF_LANE_ID, LN_OFF_NEXT_LEAF, LN_OFF_NF_COUNT,
            LN_OFF_VERSION, NF_OFF_PREFIXES, NF_PREFIX_LEN, PL_OFF_ACTIVE_LANES, PL_OFF_VERSION,
            POOL_MAGIC, POOL_STATE_LEN, SB_OFF_LANE_ID, SB_OFF_PAGE_SEQ, SR_OFF_LANE_ID,
            SR_OFF_ROOT_PAGE_SEQ,
        },
        AUDREN_PROGRAM_ID, NATIVE_SOL_MINT, PROTOCOL_VERSION,
    };

    use crate::keys::{encrypt_note_memo, AudrenKeys};

    fn make_pool(active_lanes: u8) -> Vec<u8> {
        let mut buf = vec![0u8; POOL_STATE_LEN];
        buf[0..8].copy_from_slice(&POOL_MAGIC);
        buf[PL_OFF_VERSION] = PROTOCOL_VERSION;
        buf[PL_OFF_ACTIVE_LANES] = active_lanes;
        buf
    }

    fn make_lane(lane_id: u8, next_leaf: u64, nf_count: u64) -> Vec<u8> {
        let mut buf = vec![0u8; LANE_STATE_LEN];
        buf[0..8].copy_from_slice(&LANE_MAGIC);
        buf[LN_OFF_VERSION] = PROTOCOL_VERSION;
        buf[LN_OFF_LANE_ID] = lane_id;
        buf[LN_OFF_NEXT_LEAF..LN_OFF_NEXT_LEAF + 8].copy_from_slice(&next_leaf.to_le_bytes());
        buf[LN_OFF_NF_COUNT..LN_OFF_NF_COUNT + 8].copy_from_slice(&nf_count.to_le_bytes());
        buf
    }

    fn make_subtree(lane_id: u8, seq: u64, leaves: &[Fr]) -> Vec<u8> {
        let mut buf = vec![0u8; SUBTREE_PAGE_LEN];
        buf[0..8].copy_from_slice(&SUBTREE_MAGIC);
        buf[SB_OFF_LANE_ID] = lane_id;
        buf[SB_OFF_COUNT..SB_OFF_COUNT + 2].copy_from_slice(&(leaves.len() as u16).to_le_bytes());
        buf[SB_OFF_PAGE_SEQ..SB_OFF_PAGE_SEQ + 8].copy_from_slice(&seq.to_le_bytes());
        for (i, leaf) in leaves.iter().enumerate() {
            buf[SB_OFF_LEAVES + i * 32..SB_OFF_LEAVES + (i + 1) * 32]
                .copy_from_slice(&fr_to_be_bytes(leaf));
        }
        buf
    }

    fn make_subroot(lane_id: u8, seq: u64, roots: &[Fr]) -> Vec<u8> {
        let mut buf = vec![0u8; SUBROOT_PAGE_LEN];
        buf[0..8].copy_from_slice(&SUBROOT_MAGIC);
        buf[SR_OFF_LANE_ID] = lane_id;
        buf[SR_OFF_COUNT..SR_OFF_COUNT + 2].copy_from_slice(&(roots.len() as u16).to_le_bytes());
        buf[SR_OFF_ROOT_PAGE_SEQ..SR_OFF_ROOT_PAGE_SEQ + 8].copy_from_slice(&seq.to_le_bytes());
        for (i, root) in roots.iter().enumerate() {
            buf[SR_OFF_ROOTS + i * 32..SR_OFF_ROOTS + (i + 1) * 32]
                .copy_from_slice(&fr_to_be_bytes(root));
        }
        buf
    }

    fn make_memo(count: u16, closed_slot: u64) -> Vec<u8> {
        let mut buf = vec![0u8; MEMO_PAGE_LEN];
        buf[0..8].copy_from_slice(&MEMO_MAGIC);
        buf[MM_OFF_COUNT..MM_OFF_COUNT + 2].copy_from_slice(&count.to_le_bytes());
        buf[MM_OFF_CLOSED_SLOT..MM_OFF_CLOSED_SLOT + 8].copy_from_slice(&closed_slot.to_le_bytes());
        buf
    }

    fn write_memo(buf: &mut [u8], slot: usize, memo_90: &[u8; 90]) {
        buf[MM_OFF_VIEW_TAGS + slot * 2..MM_OFF_VIEW_TAGS + (slot + 1) * 2]
            .copy_from_slice(&memo_90[0..2]);
        buf[MM_OFF_EPHEMERAL_PKS + slot * 32..MM_OFF_EPHEMERAL_PKS + (slot + 1) * 32]
            .copy_from_slice(&memo_90[2..34]);
        buf[MM_OFF_CIPHERTEXTS + slot * MEMO_CT_LEN..MM_OFF_CIPHERTEXTS + (slot + 1) * MEMO_CT_LEN]
            .copy_from_slice(&memo_90[34..90]);
    }

    #[test]
    fn two_pass_cross_lane_sync_with_subroot_fast_sync_and_birthday_skip() {
        let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
        let alice = AudrenKeys::from_seed(&[0x7au8; 32]);
        let fvk = alice.full_viewing_key();
        let sol_asset = derive_asset_id(&NATIVE_SOL_MINT);

        // Lane 2 has 520 leaves (2 sealed subtrees 0 & 1 + 8 frontier leaves in subtree 2).
        // Alice owns 1 note at leaf 515 (SubtreePage 2, MemoPage 4), spent on Lane 0 alongside 40 strangers.
        let total_leaves = 520usize;
        let mut leaves = Vec::with_capacity(total_leaves);
        let mut memos: Vec<Vec<u8>> = (0..5)
            .map(|m| {
                let cnt = MEMO_NOTES_PER_PAGE.min(total_leaves - m * MEMO_NOTES_PER_PAGE) as u16;
                let closed = if cnt as usize == MEMO_NOTES_PER_PAGE {
                    if m < 3 {
                        ((m + 1) * 100) as u64
                    } else {
                        1200
                    }
                } else {
                    0
                };
                make_memo(cnt, closed)
            })
            .collect();

        for i in 0..total_leaves {
            if i == 515 {
                let (tw, bl, memo_90) =
                    encrypt_note_memo(&alice.view_pk, [0x7bu8; 32], 4_200_000, &NATIVE_SOL_MINT);
                let cm = compute_note_commitment(
                    derive_stealth_owner(alice.spend_pk, tw),
                    sol_asset,
                    4_200_000,
                    bl,
                );
                leaves.push(cm);
                write_memo(&mut memos[i / MEMO_NOTES_PER_PAGE], i % MEMO_NOTES_PER_PAGE, &memo_90);
            } else {
                leaves.push(Fr::from((i + 1) as u64));
            }
        }

        let global_leaf = (2u64 << 36) | 515u64;
        let own_nf = fvk.real_nullifier(leaves[515], global_leaf).unwrap();

        let mut nf0 = vec![0u8; NF_PAGE_LEN];
        nf0[0..8].copy_from_slice(&NF_PAGE_MAGIC);
        nf0[NF_OFF_COUNT..NF_OFF_COUNT + 2].copy_from_slice(&41u16.to_le_bytes());
        for i in 0..40 {
            let mut s = [0u8; NF_PREFIX_LEN];
            s[0] = 0xbb;
            s[1] = i as u8;
            nf0[NF_OFF_PREFIXES + i * NF_PREFIX_LEN..NF_OFF_PREFIXES + (i + 1) * NF_PREFIX_LEN]
                .copy_from_slice(&s);
        }
        nf0[NF_OFF_PREFIXES + 40 * NF_PREFIX_LEN..NF_OFF_PREFIXES + 41 * NF_PREFIX_LEN]
            .copy_from_slice(&own_nf[0..NF_PREFIX_LEN]);

        let mut accounts: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
        accounts.insert(derive_pool_pda(&program_id, 0).0, make_pool(4));
        accounts.insert(derive_lane_pda(&program_id, 0, 0).0, make_lane(0, 0, 41));
        accounts.insert(derive_lane_pda(&program_id, 0, 1).0, make_lane(1, 0, 0));
        accounts.insert(derive_lane_pda(&program_id, 0, 2).0, make_lane(2, total_leaves as u64, 0));
        accounts.insert(derive_lane_pda(&program_id, 0, 3).0, make_lane(3, 0, 0));
        accounts.insert(
            derive_subroot_pda(&program_id, 0, 2, 0).0,
            make_subroot(
                2,
                0,
                &[
                    compute_subtree_256_root(&leaves[0..256], 256),
                    compute_subtree_256_root(&leaves[256..512], 256),
                ],
            ),
        );
        accounts.insert(derive_subtree_pda(&program_id, 0, 2, 0).0, make_subtree(2, 0, &leaves[0..256]));
        accounts.insert(derive_subtree_pda(&program_id, 0, 2, 1).0, make_subtree(2, 1, &leaves[256..512]));
        accounts.insert(derive_subtree_pda(&program_id, 0, 2, 2).0, make_subtree(2, 2, &leaves[512..520]));
        for (m, raw) in memos.into_iter().enumerate() {
            accounts.insert(derive_memo_pda(&program_id, 0, 2, m as u64).0, raw);
        }
        accounts.insert(derive_nf_page_pda(&program_id, 0, 0, 0).0, nf0);

        let requested: RefCell<Vec<Address>> = RefCell::new(Vec::new());
        let mut store = CompactWalletStore::new(0, 1000);
        let (_, _, discovered) = sync_compact_store_with(
            &mut store,
            &fvk,
            |addr| {
                requested.borrow_mut().push(*addr);
                accounts.get(addr).cloned()
            },
            &program_id,
        )
        .unwrap();

        assert_eq!(discovered, 1);
        assert_eq!(store.notes.len(), 1);
        assert!(store.notes[0].spent, "Pass 2 must mark Lane 2 note spent via Lane 0 NullifierPage");
        assert_eq!(store.lanes[2].finalized_subroots.len(), 2);
        assert_eq!(store.lanes[2].frontier_sub_seq, 2);
        assert_eq!(store.lanes[2].frontier_leaves.len(), 8);

        // Sealed SubtreePages 0 & 1 had zero owned notes and must NEVER be downloaded!
        let reqs = requested.borrow();
        assert!(!reqs.contains(&derive_subtree_pda(&program_id, 0, 2, 0).0));
        assert!(!reqs.contains(&derive_subtree_pda(&program_id, 0, 2, 1).0));
        // Pre-birthday MemoPage 0 was skipped by binary search!
        assert!(!reqs.contains(&derive_memo_pda(&program_id, 0, 2, 0).0));

        // Zero stranger prefixes serialized
        let json = String::from_utf8(store.to_json_bytes().unwrap()).unwrap();
        assert!(!json.contains("seen_nf_prefixes"));
    }
}
