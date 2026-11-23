//! Stateless account/witness reconstruction and 2-pass `CompactWalletStore` sync helpers
//! over any ordinary Solana account fetcher (LiteSVM or Solana RPC).
//!
//! Default `SyncPrivacyMode::Strict` eliminates RPC hit/spend-correlation leaks:
//! - Fetches full `10,240 B` `MemoPage`s in uniform 100-account batches (zero `dataSlice`
//!   hit-correlated second round-trip).
//! - Fetches newly synced `SubtreePage`s uniformly on incremental syncs (`<= 25` pages /
//!   `<= 25` subtrees) and uses deterministic wallet-keyed decoy padding (`SHA256(view_sk ||
//!   "audren/v1/decoy" || epoch_bucket)`) with fixed uniform batch count on large catch-ups
//!   (`> 25` pages) so repeated syncs cannot be intersected and hit count is hidden.
//! - Streams all new `NullifierPage`s to `lane_hdr.nf_count` in Pass 2 unconditionally
//!   (even if Pass 1D hits a transient `SubtreePage` miss) with zero early-exit.

use std::collections::{BTreeMap, BTreeSet};

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
use sha2::{Digest, Sha256};
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

/// Standard Solana `getMultipleAccounts` batch size.
pub const RPC_BATCH_CHUNK: usize = 100;
/// Maximum new `MemoPage`s fetched as an incremental sync (`<= ~256 KB`).
pub const INCREMENTAL_FULL_MEMO_PAGE_THRESHOLD: u64 = 25;
/// Maximum newly synced `SubtreePage`s fetched uniformly on incremental sync in `Strict` mode.
pub const INCREMENTAL_UNIFORM_SUBTREE_THRESHOLD: u64 = 25;
/// Minimum sealed `SubtreePage` anonymity set size when decoy-padding in `Strict` mode.
pub const STRICT_DECOY_SEALED_SUBTREE_TARGET: usize = 16;
/// Domain tag for deterministic wallet-keyed decoy selection in `Strict` large catch-up.
const DECOY_DOMAIN: &[u8] = b"audren/v1/decoy";
/// Byte length of the `MemoPage` header prefix (`closed_slot` binary search).
pub const MEMO_PAGE_HEADER_LEN: usize = 64;
/// Byte length of the `MemoPage` SoA scan slice (`header + view_tags + ephemeral_pks = 3,328 B`).
pub const MEMO_PAGE_SCAN_SLICE_LEN: usize = MM_OFF_CIPHERTEXTS;
/// Byte length of the `NullifierPage` header prefix (`closed_slot` binary search).
pub const NF_PAGE_HEADER_LEN: usize = 64;

/// RPC privacy mode for `CompactWalletStore` synchronization.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SyncPrivacyMode {
    /// Default privacy-preserving sync: fetches full `10,240 B` `MemoPage`s in uniform batches,
    /// fetches newly synced `SubtreePage`s uniformly on incremental syncs (`<= 25` pages / `<= 25`
    /// subtrees), uses deterministic wallet-keyed decoy padding (`min(16, total_sealed_subtrees)`)
    /// on large catch-ups, and runs Pass 2 unconditionally without early-exit.
    #[default]
    Strict,
    /// Opt-in bandwidth-saving mode for large historical catch-up (`> 25` `MemoPage`s) over a
    /// self-hosted or trusted RPC: uses `3,328 B` `MemoPage` SoA `dataSlice` scanning followed by
    /// targeted full `MemoPage` re-fetches on view-tag hits (trading RPC hit-visibility for lower
    /// bandwidth). Small incremental syncs (`<= 25` `MemoPage`s) still fetch full `MemoPage`s
    /// directly, and Pass 2 still streams all new `NullifierPage`s unconditionally without early-exit.
    Fast,
}

/// Optional Solana `getMultipleAccounts` `dataSlice` byte window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountDataSlice {
    pub offset: usize,
    pub length: usize,
}

/// Options controlling `CompactWalletStore` synchronization.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncOptions {
    pub privacy_mode: SyncPrivacyMode,
}

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

fn decode_subtree_leaves_be(data: &[u8]) -> Result<Vec<[u8; 32]>, ClientError> {
    if data.len() != SUBTREE_PAGE_LEN || data[0..8] != SUBTREE_MAGIC {
        return Err(ClientError::InvalidEncoding("invalid SubtreePage"));
    }
    let cnt = read_u16(data, SB_OFF_COUNT) as usize;
    let mut leaves = Vec::with_capacity(cnt);
    for i in 0..cnt {
        leaves.push(read_32(data, SB_OFF_LEAVES + i * 32));
    }
    Ok(leaves)
}

#[derive(Clone, Copy, Debug)]
struct MemoHitCandidate {
    memo_seq: u64,
    slot: usize,
    leaf_idx: u64,
}

/// Incrementally sync `CompactWalletStore` across ALL active lanes using default
/// `SyncPrivacyMode::Strict` (**2-pass sync** with zero Pass 2 early-exit and zero hit-revealing
/// `MemoPage` re-fetches).
///
/// For explicit privacy mode configuration (`Strict` vs opt-in `Fast`) or slice-aware batched
/// `getMultipleAccounts` fetchers, see [`sync_compact_store_with_options`] and
/// [`sync_compact_store_with_batch`].
pub fn sync_compact_store_with<F>(
    store: &mut CompactWalletStore,
    fvk: &FullViewingKey,
    get_account_data: F,
    program_id: &Address,
) -> Result<(PoolState, Vec<LaneTreeHeader>, usize), ClientError>
where
    F: FnMut(&Address) -> Option<Vec<u8>>,
{
    sync_compact_store_with_options(
        store,
        fvk,
        get_account_data,
        program_id,
        SyncOptions::default(),
    )
}

/// Incrementally sync `CompactWalletStore` across ALL active lanes over a single-account fetcher
/// closure with explicit [`SyncOptions`].
pub fn sync_compact_store_with_options<F>(
    store: &mut CompactWalletStore,
    fvk: &FullViewingKey,
    mut get_account_data: F,
    program_id: &Address,
    options: SyncOptions,
) -> Result<(PoolState, Vec<LaneTreeHeader>, usize), ClientError>
where
    F: FnMut(&Address) -> Option<Vec<u8>>,
{
    sync_compact_store_with_batch(
        store,
        fvk,
        |addrs, slice| {
            addrs
                .iter()
                .map(|a| {
                    let full = get_account_data(a)?;
                    match slice {
                        Some(s) => {
                            let end = s.offset.saturating_add(s.length).min(full.len());
                            if s.offset <= end {
                                Some(full[s.offset..end].to_vec())
                            } else {
                                Some(Vec::new())
                            }
                        }
                        None => Some(full),
                    }
                })
                .collect()
        },
        program_id,
        options,
    )
}

/// Incrementally sync `CompactWalletStore` across ALL active lanes via batched
/// `getMultipleAccounts` + optional [`AccountDataSlice`] calls and [`SyncOptions`]:
///
/// - **Pass 1A:** Fast-sync finalized level-4 subroots via `SubtreeRootPage`.
/// - **Pass 1B:** Optional `birthday_slot` binary search on `64 B` `MemoPage` headers.
/// - **Pass 1C:** Fetch `MemoPage`s across all active lanes in uniform 100-account batches:
///   - `Strict` (default): ALWAYS fetches full `10,240 B` `MemoPage`s in one pass (zero
///     `dataSlice` hit-correlated re-fetches).
///   - `Fast` (opt-in): fetches full `10,240 B` `MemoPage`s on small incremental syncs
///     (`<= 25` pages), and uses `3,328 B` SoA `dataSlice` on large catch-ups (`> 25` pages)
///     followed by Pass 1D full fetches on view-tag hits.
/// - **Pass 1D:** Fetch required `SubtreePage`s in uniform shuffled batches:
///   - `Strict` incremental sync (`<= 25` MemoPages & `<= 25` newly synced SubtreePages): fetches
///     all `SubtreePage`s covering newly synced leaves uniformly without revealing hits.
///   - `Strict` large catch-up (`> 25` MemoPages): pads sealed `SubtreePage` fetch batches with
///     deterministic wallet-keyed decoy sealed `SubtreePage`s across active lanes up to a fixed
///     uniform batch size (`min(16, total_sealed_subtrees)`, even when 0 hits occur) and shuffles
///     deterministically before fetching.
/// - **Pass 2:** Unconditionally streams ALL new `NullifierPage`s across ALL active lanes up to
///   `lane_hdr.nf_count` in uniform 100-account batches with ZERO early-exit (even when 0 unspent
///   notes exist or after the last unspent note is marked spent), discarding all stranger prefixes.
pub fn sync_compact_store_with_batch<F>(
    store: &mut CompactWalletStore,
    fvk: &FullViewingKey,
    mut fetch_batch: F,
    program_id: &Address,
    options: SyncOptions,
) -> Result<(PoolState, Vec<LaneTreeHeader>, usize), ClientError>
where
    F: FnMut(&[Address], Option<AccountDataSlice>) -> Vec<Option<Vec<u8>>>,
{
    let pool_id = store.pool_id;
    let birthday_slot = store.birthday_slot;
    let privacy_mode = options.privacy_mode;

    // Phase 0: PoolState + active LaneTreeState headers (2 batched RPC calls)
    let (pool_pda, _) = derive_pool_pda(program_id, pool_id);
    let pool_res = fetch_batch(&[pool_pda], None);
    let pool_data = pool_res
        .into_iter()
        .next()
        .flatten()
        .ok_or(ClientError::WitnessNotFound("PoolState missing"))?;
    let pool = decode_pool_state(&pool_data)?;

    let lane_pdas: Vec<Address> = (0..pool.active_lanes)
        .map(|l| derive_lane_pda(program_id, pool_id, l).0)
        .collect();
    let lane_raws = fetch_batch(&lane_pdas, None);
    let mut lanes = Vec::with_capacity(pool.active_lanes as usize);
    for l in 0..pool.active_lanes as usize {
        let ldata = lane_raws
            .get(l)
            .and_then(|o| o.as_ref())
            .ok_or(ClientError::WitnessNotFound("LaneTreeState missing"))?;
        lanes.push(decode_lane_header(ldata)?);
    }

    let sub_size = SUBTREE_LEAVES as u64;
    let sr_size = SUBROOTS_PER_PAGE as u64;
    let memo_size = MEMO_NOTES_PER_PAGE as u64;
    let nf_size = NF_PER_PAGE as u64;

    // =========================================================================
    // PASS 1A: Fast-sync finalized level-4 subroots via `SubtreeRootPage`
    // =========================================================================
    struct SrReq {
        lane_id: u8,
        root_page_seq: u64,
        finalized_count: u64,
        addr: Address,
    }
    let mut sr_requests: Vec<SrReq> = Vec::new();
    for lane_hdr in &lanes {
        let l = lane_hdr.lane_id as usize;
        let finalized_count = lane_hdr.next_leaf / sub_size;
        if finalized_count > store.lanes[l].finalized_subroots.len() as u64 {
            let start_sr = (store.lanes[l].finalized_subroots.len() as u64) / sr_size;
            let end_sr = (finalized_count - 1) / sr_size;
            for rp in start_sr..=end_sr {
                sr_requests.push(SrReq {
                    lane_id: lane_hdr.lane_id,
                    root_page_seq: rp,
                    finalized_count,
                    addr: derive_subroot_pda(program_id, pool_id, lane_hdr.lane_id, rp).0,
                });
            }
        }
    }

    let mut fallback_subtrees: BTreeMap<u8, BTreeSet<u64>> = BTreeMap::new();
    for chunk in sr_requests.chunks(RPC_BATCH_CHUNK) {
        let addrs: Vec<Address> = chunk.iter().map(|r| r.addr).collect();
        let raws = fetch_batch(&addrs, None);
        for (i, req) in chunk.iter().enumerate() {
            if let Some(sr_raw) = raws.get(i).and_then(|o| o.as_ref()) {
                store.ingest_subroot_pages(
                    req.lane_id,
                    &[(req.root_page_seq, sr_raw.as_slice())],
                    Some(req.finalized_count),
                )?;
            } else {
                let set = fallback_subtrees.entry(req.lane_id).or_default();
                let base = req.root_page_seq * sr_size;
                let end = (base + sr_size).min(req.finalized_count);
                for s in base..end {
                    set.insert(s);
                }
            }
        }
    }

    // =========================================================================
    // PASS 1B: Optional `birthday_slot` binary search on `64 B` `MemoPage` headers
    // =========================================================================
    if birthday_slot > 0 {
        struct BsState {
            lane_id: u8,
            next_leaf: u64,
            lo: u64,
            hi: u64,
        }
        let mut bs_states: Vec<BsState> = Vec::new();
        for lane_hdr in &lanes {
            let l = lane_hdr.lane_id as usize;
            if lane_hdr.next_leaf > 0 && store.lanes[l].next_memo_leaf == 0 {
                let target_memo_max = (lane_hdr.next_leaf - 1) / memo_size;
                if target_memo_max > 2 {
                    bs_states.push(BsState {
                        lane_id: lane_hdr.lane_id,
                        next_leaf: lane_hdr.next_leaf,
                        lo: 0,
                        hi: target_memo_max + 1,
                    });
                }
            }
        }
        while bs_states.iter().any(|s| s.lo < s.hi) {
            let active_indices: Vec<usize> = bs_states
                .iter()
                .enumerate()
                .filter_map(|(idx, s)| (s.lo < s.hi).then_some(idx))
                .collect();
            let mids: Vec<u64> = active_indices
                .iter()
                .map(|&idx| (bs_states[idx].lo + bs_states[idx].hi) / 2)
                .collect();
            let addrs: Vec<Address> = active_indices
                .iter()
                .zip(mids.iter())
                .map(|(&idx, &mid)| derive_memo_pda(program_id, pool_id, bs_states[idx].lane_id, mid).0)
                .collect();
            let raws = fetch_batch(
                &addrs,
                Some(AccountDataSlice {
                    offset: 0,
                    length: MEMO_PAGE_HEADER_LEN,
                }),
            );
            for (i, &idx) in active_indices.iter().enumerate() {
                let mid = mids[i];
                let skip = raws
                    .get(i)
                    .and_then(|o| o.as_ref())
                    .map(|mraw| {
                        if mraw.len() >= MEMO_PAGE_HEADER_LEN && mraw[0..8] == MEMO_MAGIC {
                            let cnt = read_u16(mraw, MM_OFF_COUNT) as usize;
                            let closed = read_u64(mraw, MM_OFF_CLOSED_SLOT);
                            cnt == MEMO_NOTES_PER_PAGE && closed > 0 && closed < birthday_slot
                        } else {
                            false
                        }
                    })
                    .unwrap_or(false);
                if skip {
                    bs_states[idx].lo = mid + 1;
                } else {
                    bs_states[idx].hi = mid;
                }
            }
        }
        for st in &bs_states {
            if st.lo > 0 {
                let skip_to = (st.lo * memo_size).min(st.next_leaf);
                store.lanes[st.lane_id as usize].next_memo_leaf = skip_to;
            }
        }
    }

    // Compute total new MemoPages and newly synced SubtreePages across all active lanes (post-Pass 1B)
    let mut scan_start_leaf_by_lane: BTreeMap<u8, u64> = BTreeMap::new();
    let mut total_new_memo_pages = 0u64;
    let mut total_new_subtrees = 0u64;
    for lane_hdr in &lanes {
        let l = lane_hdr.lane_id as usize;
        let start_leaf = store.lanes[l].next_memo_leaf;
        scan_start_leaf_by_lane.insert(lane_hdr.lane_id, start_leaf);
        if lane_hdr.next_leaf > 0 && start_leaf < lane_hdr.next_leaf {
            let start_memo = start_leaf / memo_size;
            let target_memo_max = (lane_hdr.next_leaf - 1) / memo_size;
            total_new_memo_pages = total_new_memo_pages
                .saturating_add(target_memo_max - start_memo + 1);
            let start_sub = start_leaf / sub_size;
            let end_sub = (lane_hdr.next_leaf - 1) / sub_size;
            total_new_subtrees = total_new_subtrees.saturating_add(end_sub - start_sub + 1);
        }
    }

    let is_incremental_memo_sync = total_new_memo_pages <= INCREMENTAL_FULL_MEMO_PAGE_THRESHOLD;
    // In `Strict` mode we NEVER use `dataSlice` + targeted hit re-fetch for MemoPages.
    // Even in opt-in `Fast` mode, small incremental syncs (`<= 25` pages) fetch full MemoPages directly.
    let use_memo_data_slice = privacy_mode == SyncPrivacyMode::Fast && !is_incremental_memo_sync;
    let fetch_new_subtrees_uniformly = privacy_mode == SyncPrivacyMode::Strict
        && is_incremental_memo_sync
        && total_new_subtrees <= INCREMENTAL_UNIFORM_SUBTREE_THRESHOLD;

    // =========================================================================
    // PASS 1C: Fetch `MemoPage`s across ALL active lanes in uniform 100-account batches
    // =========================================================================
    struct MemoReq {
        lane_id: u8,
        memo_seq: u64,
        next_leaf: u64,
        addr: Address,
    }
    let mut memo_queue: Vec<MemoReq> = Vec::new();
    let mut hits_by_lane: BTreeMap<u8, Vec<MemoHitCandidate>> = BTreeMap::new();
    let mut scanned_watermark_by_lane: BTreeMap<u8, u64> = BTreeMap::new();
    let mut inline_full_memos: BTreeMap<(u8, u64), Vec<u8>> = BTreeMap::new();
    let mut needed_full_memos: BTreeMap<(u8, u64), Address> = BTreeMap::new();

    for lane_hdr in &lanes {
        let start_leaf = *scan_start_leaf_by_lane
            .get(&lane_hdr.lane_id)
            .unwrap_or(&store.lanes[lane_hdr.lane_id as usize].next_memo_leaf);
        scanned_watermark_by_lane.insert(lane_hdr.lane_id, start_leaf);
        hits_by_lane.insert(lane_hdr.lane_id, Vec::new());
        if lane_hdr.next_leaf == 0 || start_leaf >= lane_hdr.next_leaf {
            continue;
        }
        let start_memo = start_leaf / memo_size;
        let target_memo_max = (lane_hdr.next_leaf - 1) / memo_size;
        for m in start_memo..=target_memo_max {
            memo_queue.push(MemoReq {
                lane_id: lane_hdr.lane_id,
                memo_seq: m,
                next_leaf: lane_hdr.next_leaf,
                addr: derive_memo_pda(program_id, pool_id, lane_hdr.lane_id, m).0,
            });
        }
    }

    let memo_slice_opt = if use_memo_data_slice {
        Some(AccountDataSlice {
            offset: 0,
            length: MEMO_PAGE_SCAN_SLICE_LEN,
        })
    } else {
        None
    };

    let mut stopped_memo_lanes: BTreeSet<u8> = BTreeSet::new();
    for chunk in memo_queue.chunks(RPC_BATCH_CHUNK) {
        if chunk.iter().all(|item| stopped_memo_lanes.contains(&item.lane_id)) {
            continue;
        }
        let addrs: Vec<Address> = chunk.iter().map(|item| item.addr).collect();
        let raws = fetch_batch(&addrs, memo_slice_opt);
        for (i, item) in chunk.iter().enumerate() {
            if stopped_memo_lanes.contains(&item.lane_id) {
                continue;
            }
            let Some(mraw) = raws.get(i).and_then(|o| o.as_ref()) else {
                stopped_memo_lanes.insert(item.lane_id);
                continue;
            };
            if !use_memo_data_slice {
                if mraw.len() != MEMO_PAGE_LEN || mraw[0..8] != MEMO_MAGIC {
                    return Err(ClientError::InvalidEncoding("invalid MemoPage"));
                }
            } else if mraw.len() < MEMO_PAGE_SCAN_SLICE_LEN || mraw[0..8] != MEMO_MAGIC {
                return Err(ClientError::InvalidEncoding("invalid MemoPage scan slice"));
            }

            let count = read_u16(mraw, MM_OFF_COUNT) as usize;
            let closed_slot = read_u64(mraw, MM_OFF_CLOSED_SLOT);
            let page_base = item.memo_seq * memo_size;
            let cursor = *scanned_watermark_by_lane.get(&item.lane_id).unwrap_or(&0);
            let start_slot = cursor.saturating_sub(page_base) as usize;
            let max_for_snapshot =
                (item.next_leaf.saturating_sub(page_base) as usize).min(MEMO_NOTES_PER_PAGE);
            let limit_slot = count.min(max_for_snapshot);

            if start_slot == 0
                && birthday_slot > 0
                && count == MEMO_NOTES_PER_PAGE
                && closed_slot > 0
                && closed_slot < birthday_slot
            {
                scanned_watermark_by_lane.insert(item.lane_id, page_base + limit_slot as u64);
                if count < max_for_snapshot {
                    stopped_memo_lanes.insert(item.lane_id);
                }
                continue;
            }

            let lane_hits = hits_by_lane.entry(item.lane_id).or_default();
            let mut page_matched = false;
            for slot in start_slot..limit_slot {
                let vt = [
                    mraw[MM_OFF_VIEW_TAGS + slot * 2],
                    mraw[MM_OFF_VIEW_TAGS + slot * 2 + 1],
                ];
                let epk = read_32(mraw, MM_OFF_EPHEMERAL_PKS + slot * 32);
                if check_memo_view_tag(fvk, vt, &epk) {
                    page_matched = true;
                    lane_hits.push(MemoHitCandidate {
                        memo_seq: item.memo_seq,
                        slot,
                        leaf_idx: page_base + slot as u64,
                    });
                }
            }
            if page_matched {
                let key = (item.lane_id, item.memo_seq);
                if mraw.len() == MEMO_PAGE_LEN {
                    inline_full_memos.insert(key, mraw.clone());
                } else {
                    needed_full_memos.entry(key).or_insert(item.addr);
                }
            }
            scanned_watermark_by_lane.insert(item.lane_id, page_base + limit_slot as u64);
            if count < max_for_snapshot {
                stopped_memo_lanes.insert(item.lane_id);
            }
        }
    }

    // =========================================================================
    // PASS 1D: Fetch full `MemoPage`s (`Fast` >25 pages only) & `SubtreePage`s
    // =========================================================================
    let mut fetched_full_memos = inline_full_memos;
    if !needed_full_memos.is_empty() {
        let full_memo_list: Vec<((u8, u64), Address)> = needed_full_memos.into_iter().collect();
        for chunk in full_memo_list.chunks(RPC_BATCH_CHUNK) {
            let addrs: Vec<Address> = chunk.iter().map(|(_, a)| *a).collect();
            let raws = fetch_batch(&addrs, None);
            for (i, &(key, _)) in chunk.iter().enumerate() {
                if let Some(mraw) = raws.get(i).and_then(|o| o.as_ref()) {
                    if mraw.len() != MEMO_PAGE_LEN || mraw[0..8] != MEMO_MAGIC {
                        return Err(ClientError::InvalidEncoding("invalid MemoPage"));
                    }
                    fetched_full_memos.insert(key, mraw.clone());
                }
            }
        }
    }

    let mut needed_subtrees: BTreeMap<(u8, u64), Address> = BTreeMap::new();
    let mut uniform_new_subtrees: BTreeSet<(u8, u64)> = BTreeSet::new();
    let add_needed_subtree =
        |map: &mut BTreeMap<(u8, u64), Address>, lane_id: u8, sub_seq: u64| -> bool {
            let key = (lane_id, sub_seq);
            if map.contains_key(&key) {
                return false;
            }
            map.insert(
                key,
                derive_subtree_pda(program_id, pool_id, lane_id, sub_seq).0,
            );
            true
        };

    if fetch_new_subtrees_uniformly {
        for lane_hdr in &lanes {
            let start_leaf = *scan_start_leaf_by_lane
                .get(&lane_hdr.lane_id)
                .unwrap_or(&store.lanes[lane_hdr.lane_id as usize].next_memo_leaf);
            if lane_hdr.next_leaf > 0 && start_leaf < lane_hdr.next_leaf {
                let start_sub = start_leaf / sub_size;
                let end_sub = (lane_hdr.next_leaf - 1) / sub_size;
                for s in start_sub..=end_sub {
                    add_needed_subtree(&mut needed_subtrees, lane_hdr.lane_id, s);
                    uniform_new_subtrees.insert((lane_hdr.lane_id, s));
                }
            }
        }
    }

    let mut has_hit_correlated_sealed_subtree = false;
    for lane_hdr in &lanes {
        let lane_id = lane_hdr.lane_id;
        let l = lane_id as usize;
        let finalized_count = lane_hdr.next_leaf / sub_size;
        let frontier_rem = (lane_hdr.next_leaf % sub_size) as usize;

        if frontier_rem > 0 {
            add_needed_subtree(&mut needed_subtrees, lane_id, finalized_count);
        }
        if let Some(hits) = hits_by_lane.get(&lane_id) {
            for hit in hits {
                let hit_sub_seq = hit.leaf_idx / sub_size;
                add_needed_subtree(&mut needed_subtrees, lane_id, hit_sub_seq);
                if hit_sub_seq < finalized_count
                    && !uniform_new_subtrees.contains(&(lane_id, hit_sub_seq))
                {
                    has_hit_correlated_sealed_subtree = true;
                }
            }
        }
        for note in &store.notes {
            if note.lane_id == lane_id && note.frozen_intra_siblings.is_none() {
                let note_sub_seq = note.leaf_index / sub_size;
                if note_sub_seq < finalized_count {
                    add_needed_subtree(&mut needed_subtrees, lane_id, note_sub_seq);
                    if !uniform_new_subtrees.contains(&(lane_id, note_sub_seq)) {
                        has_hit_correlated_sealed_subtree = true;
                    }
                }
            }
        }
        if finalized_count > 0
            && !store.lanes[l].frontier_leaves.is_empty()
            && store.lanes[l].frontier_sub_seq == finalized_count - 1
        {
            add_needed_subtree(&mut needed_subtrees, lane_id, finalized_count - 1);
        }
        if let Some(fb) = fallback_subtrees.get(&lane_id) {
            for &s in fb {
                add_needed_subtree(&mut needed_subtrees, lane_id, s);
            }
        }
    }

    // Deterministic wallet-keyed decoy padding for historical sealed `SubtreePage` fetches in
    // `Strict` mode (`SHA256(view_sk || "audren/v1/decoy" || epoch_bucket || counter)`):
    // - Always fetches a fixed uniform count independent of hit count (even 0 hits) during large
    //   catch-up so RPC cannot tell whether a wallet had hits.
    // - Deterministic per `(view_sk, epoch_bucket)` so repeated syncs / retries emit identical
    //   decoy sets and cannot be intersected.
    let mut finalized_by_lane: BTreeMap<u8, u64> = BTreeMap::new();
    let mut total_sealed_subtrees = 0u64;
    for lane_hdr in &lanes {
        let fc = lane_hdr.next_leaf / sub_size;
        finalized_by_lane.insert(lane_hdr.lane_id, fc);
        total_sealed_subtrees = total_sealed_subtrees.saturating_add(fc);
    }
    let epoch_bucket: u64 = total_sealed_subtrees / 64;

    let should_decoy_pad = privacy_mode == SyncPrivacyMode::Strict
        && total_sealed_subtrees > 0
        && (has_hit_correlated_sealed_subtree
            || (!fetch_new_subtrees_uniformly && total_new_memo_pages > 0));
    if should_decoy_pad {
        let mut current_sealed_count = needed_subtrees
            .keys()
            .filter(|&&(lid, s)| s < *finalized_by_lane.get(&lid).unwrap_or(&0))
            .count();
        let buckets = current_sealed_count
            .max(1)
            .div_ceil(STRICT_DECOY_SEALED_SUBTREE_TARGET);
        let target_sealed = (buckets * STRICT_DECOY_SEALED_SUBTREE_TARGET)
            .min(total_sealed_subtrees as usize);

        if current_sealed_count < target_sealed {
            if total_sealed_subtrees <= target_sealed as u64 {
                for lane_hdr in &lanes {
                    let fc = *finalized_by_lane.get(&lane_hdr.lane_id).unwrap_or(&0);
                    for s in 0..fc {
                        add_needed_subtree(&mut needed_subtrees, lane_hdr.lane_id, s);
                    }
                }
            } else {
                let mut counter: u32 = 0;
                while current_sealed_count < target_sealed {
                    let mut h = Sha256::new();
                    h.update(fvk.view_sk);
                    h.update(DECOY_DOMAIN);
                    h.update(epoch_bucket.to_le_bytes());
                    h.update(counter.to_le_bytes());
                    counter = counter.wrapping_add(1);
                    let digest: [u8; 32] = h.finalize().into();
                    let mut g =
                        u64::from_le_bytes(digest[0..8].try_into().unwrap()) % total_sealed_subtrees;
                    for lane_hdr in &lanes {
                        let fc = *finalized_by_lane.get(&lane_hdr.lane_id).unwrap_or(&0);
                        if g < fc {
                            if add_needed_subtree(&mut needed_subtrees, lane_hdr.lane_id, g) {
                                current_sealed_count += 1;
                            }
                            break;
                        }
                        g -= fc;
                    }
                }
            }
        }
    }

    let mut sub_list: Vec<((u8, u64), Address)> =
        needed_subtrees.iter().map(|(&k, &v)| (k, v)).collect();
    if sub_list.len() > 1 {
        sub_list.sort_by_cached_key(|(_, addr)| {
            let mut h = Sha256::new();
            h.update(fvk.view_sk);
            h.update(DECOY_DOMAIN);
            h.update(epoch_bucket.to_le_bytes());
            h.update(b"order");
            h.update(addr.as_ref());
            let d: [u8; 32] = h.finalize().into();
            d
        });
    }

    let mut fetched_subtrees: BTreeMap<(u8, u64), Vec<[u8; 32]>> = BTreeMap::new();
    for chunk in sub_list.chunks(RPC_BATCH_CHUNK) {
        let addrs: Vec<Address> = chunk.iter().map(|(_, a)| *a).collect();
        let raws = fetch_batch(&addrs, None);
        for (i, &(key, _)) in chunk.iter().enumerate() {
            if let Some(raw) = raws.get(i).and_then(|o| o.as_ref()) {
                fetched_subtrees.insert(key, decode_subtree_leaves_be(raw)?);
            }
        }
    }

    let mut discovered_notes = 0usize;
    for lane_hdr in &lanes {
        let lane_id = lane_hdr.lane_id;
        let l = lane_id as usize;
        let old_frontier_sub_seq = store.lanes[l].frontier_sub_seq;
        let old_frontier_leaves = store.lanes[l].frontier_leaves.clone();
        let finalized_count = lane_hdr.next_leaf / sub_size;
        let frontier_rem = (lane_hdr.next_leaf % sub_size) as usize;

        if let Some(fb) = fallback_subtrees.get(&lane_id) {
            for &s in fb {
                if let Some(leaves) = fetched_subtrees.get(&(lane_id, s)) {
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
        }

        // Verify all view-tag candidates for this lane in ascending leaf order
        let mut verified_watermark = *scanned_watermark_by_lane
            .get(&lane_id)
            .unwrap_or(&store.lanes[l].next_memo_leaf);
        if let Some(hits) = hits_by_lane.get(&lane_id) {
            for hit in hits {
                let memo_raw = fetched_full_memos.get(&(lane_id, hit.memo_seq));
                let sub_seq = hit.leaf_idx / sub_size;
                let sub_slot = (hit.leaf_idx % sub_size) as usize;
                let sub_leaves = fetched_subtrees.get(&(lane_id, sub_seq)).or_else(|| {
                    (sub_seq == old_frontier_sub_seq).then_some(&old_frontier_leaves)
                });

                let (Some(mraw), Some(leaves)) = (memo_raw, sub_leaves) else {
                    if hit.leaf_idx < verified_watermark {
                        verified_watermark = hit.leaf_idx;
                    }
                    break;
                };
                let memo_count = read_u16(mraw, MM_OFF_COUNT) as usize;
                if hit.slot >= memo_count || sub_slot >= leaves.len() {
                    if hit.leaf_idx < verified_watermark {
                        verified_watermark = hit.leaf_idx;
                    }
                    break;
                }

                let vt = [
                    mraw[MM_OFF_VIEW_TAGS + hit.slot * 2],
                    mraw[MM_OFF_VIEW_TAGS + hit.slot * 2 + 1],
                ];
                let epk = read_32(mraw, MM_OFF_EPHEMERAL_PKS + hit.slot * 32);
                let ct_off = MM_OFF_CIPHERTEXTS + hit.slot * MEMO_CT_LEN;
                let ct72: [u8; MEMO_CT_LEN] =
                    mraw[ct_off..ct_off + MEMO_CT_LEN].try_into().unwrap();
                let cm_be = leaves[sub_slot];
                if let Some(dec) =
                    try_decrypt_and_verify_memo_entry(fvk, vt, &epk, &ct72, &cm_be)
                {
                    if store.record_verified_memo(fvk, lane_id, hit.leaf_idx, &dec, cm_be)? {
                        discovered_notes += 1;
                    }
                }
            }
        }
        if verified_watermark > store.lanes[l].next_memo_leaf {
            store.lanes[l].next_memo_leaf = verified_watermark;
        }

        // Freeze owned notes for every fetched sealed SubtreePage on this lane
        for &(lid, s) in needed_subtrees.keys() {
            if lid != lane_id {
                continue;
            }
            if let Some(leaves) = fetched_subtrees.get(&(lid, s)) {
                if leaves.len() == SUBTREE_LEAVES {
                    store.freeze_owned_notes_in_subtree_page(lane_id, s, leaves)?;
                }
            }
        }

        if finalized_count > 0 {
            let latest_sealed = finalized_count - 1;
            if let Some(leaves) = fetched_subtrees.get(&(lane_id, latest_sealed)) {
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
            if let Some(leaves) = fetched_subtrees.get(&(lane_id, finalized_count)) {
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
    // PASS 2: Unconditionally stream ALL new `NullifierPage`s across ALL active
    //         lanes (ZERO early-exit, ZERO Pass 1D -> Pass 2 miss oracle!).
    //         If Pass 1D missed a `SubtreePage` / `MemoPage` (`!all_caught_up`),
    //         we still issue every Pass 2 RPC identically and apply nullifiers to
    //         known notes, while keeping `next_nf_index` pinned so the retried
    //         note's nullifier is guaranteed to be checked on the next sync.
    // =========================================================================
    let all_caught_up = lanes
        .iter()
        .all(|h| store.lanes[h.lane_id as usize].next_memo_leaf >= h.next_leaf);
    let saved_nf_indices: Vec<u64> = lanes
        .iter()
        .map(|h| store.lanes[h.lane_id as usize].next_nf_index)
        .collect();

    // Optional birthday_slot binary search on `64 B` NullifierPage headers for fresh wallets
    // (runs unconditionally regardless of owned-note balance so RPC cannot infer first receipt).
    if birthday_slot > 0 {
        struct NfBsState {
            lane_id: u8,
            nf_count: u64,
            lo: u64,
            hi: u64,
        }
        let mut nf_bs_states: Vec<NfBsState> = Vec::new();
        for lane_hdr in &lanes {
            let l = lane_hdr.lane_id as usize;
            if lane_hdr.nf_count > 0 && store.lanes[l].next_nf_index == 0 {
                let target_nf_max = (lane_hdr.nf_count - 1) / nf_size;
                if target_nf_max > 2 {
                    nf_bs_states.push(NfBsState {
                        lane_id: lane_hdr.lane_id,
                        nf_count: lane_hdr.nf_count,
                        lo: 0,
                        hi: target_nf_max + 1,
                    });
                }
            }
        }
        while nf_bs_states.iter().any(|s| s.lo < s.hi) {
            let active_indices: Vec<usize> = nf_bs_states
                .iter()
                .enumerate()
                .filter_map(|(idx, s)| (s.lo < s.hi).then_some(idx))
                .collect();
            let mids: Vec<u64> = active_indices
                .iter()
                .map(|&idx| (nf_bs_states[idx].lo + nf_bs_states[idx].hi) / 2)
                .collect();
            let addrs: Vec<Address> = active_indices
                .iter()
                .zip(mids.iter())
                .map(|(&idx, &mid)| {
                    derive_nf_page_pda(program_id, pool_id, nf_bs_states[idx].lane_id, mid).0
                })
                .collect();
            let raws = fetch_batch(
                &addrs,
                Some(AccountDataSlice {
                    offset: 0,
                    length: NF_PAGE_HEADER_LEN,
                }),
            );
            for (i, &idx) in active_indices.iter().enumerate() {
                let mid = mids[i];
                let skip = raws
                    .get(i)
                    .and_then(|o| o.as_ref())
                    .map(|nraw| {
                        if nraw.len() >= NF_PAGE_HEADER_LEN && nraw[0..8] == NF_PAGE_MAGIC {
                            let cnt = read_u16(nraw, NF_OFF_COUNT) as usize;
                            let closed = read_u64(nraw, NF_OFF_CLOSED_SLOT);
                            cnt == NF_PER_PAGE && closed > 0 && closed < birthday_slot
                        } else {
                            false
                        }
                    })
                    .unwrap_or(false);
                if skip {
                    nf_bs_states[idx].lo = mid + 1;
                } else {
                    nf_bs_states[idx].hi = mid;
                }
            }
        }
        for st in &nf_bs_states {
            if st.lo > 0 {
                store.lanes[st.lane_id as usize].next_nf_index =
                    (st.lo * nf_size).min(st.nf_count);
            }
        }
    }

    // Stream ALL new NullifierPages up to `lane_hdr.nf_count` in uniform 100-account batches.
    // NEVER skip when 0 unspent notes exist or when Pass 1D had a transient miss, and NEVER break
    // early when the last unspent note is marked spent — stranger prefixes are discarded immediately.
    struct NfReq {
        lane_id: u8,
        page_seq: u64,
        max_nf_index: u64,
        addr: Address,
    }
    let mut nf_queue: Vec<NfReq> = Vec::new();
    for lane_hdr in &lanes {
        let l = lane_hdr.lane_id as usize;
        if lane_hdr.nf_count == 0 || store.lanes[l].next_nf_index >= lane_hdr.nf_count {
            continue;
        }
        let start_nf = store.lanes[l].next_nf_index / nf_size;
        let target_nf_max = (lane_hdr.nf_count - 1) / nf_size;
        for n in start_nf..=target_nf_max {
            nf_queue.push(NfReq {
                lane_id: lane_hdr.lane_id,
                page_seq: n,
                max_nf_index: lane_hdr.nf_count,
                addr: derive_nf_page_pda(program_id, pool_id, lane_hdr.lane_id, n).0,
            });
        }
    }

    let mut stopped_nf_lanes: BTreeSet<u8> = BTreeSet::new();
    for chunk in nf_queue.chunks(RPC_BATCH_CHUNK) {
        if chunk.iter().all(|item| stopped_nf_lanes.contains(&item.lane_id)) {
            continue;
        }
        let addrs: Vec<Address> = chunk.iter().map(|item| item.addr).collect();
        let raws = fetch_batch(&addrs, None);
        for (i, item) in chunk.iter().enumerate() {
            if stopped_nf_lanes.contains(&item.lane_id) {
                continue;
            }
            let Some(nraw) = raws.get(i).and_then(|o| o.as_ref()) else {
                stopped_nf_lanes.insert(item.lane_id);
                continue;
            };
            if nraw.len() != NF_PAGE_LEN || nraw[0..8] != NF_PAGE_MAGIC {
                return Err(ClientError::InvalidEncoding("invalid NullifierPage"));
            }
            let hdr_count = read_u16(nraw, NF_OFF_COUNT) as usize;
            let page_base = item.page_seq * nf_size;
            let expected_cap =
                (item.max_nf_index.saturating_sub(page_base) as usize).min(NF_PER_PAGE);
            store.ingest_nullifier_page(
                item.lane_id,
                item.page_seq,
                nraw,
                Some(item.max_nf_index),
            )?;
            if hdr_count < expected_cap {
                stopped_nf_lanes.insert(item.lane_id);
            }
        }
    }

    if !all_caught_up {
        for (i, lane_hdr) in lanes.iter().enumerate() {
            store.lanes[lane_hdr.lane_id as usize].next_nf_index = saved_nf_indices[i];
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
            LN_OFF_VERSION, MEMO_ENTRY_WIRE_LEN, NF_OFF_PREFIXES, NF_PREFIX_LEN,
            PL_OFF_ACTIVE_LANES, PL_OFF_VERSION, POOL_MAGIC, POOL_STATE_LEN, SB_OFF_LANE_ID,
            SB_OFF_PAGE_SEQ, SR_OFF_LANE_ID, SR_OFF_ROOT_PAGE_SEQ,
        },
        AUDREN_PROGRAM_ID, PROTOCOL_VERSION, WSOL_MINT,
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

    fn write_memo(buf: &mut [u8], slot: usize, memo_106: &[u8; MEMO_ENTRY_WIRE_LEN]) {
        buf[MM_OFF_VIEW_TAGS + slot * 2..MM_OFF_VIEW_TAGS + (slot + 1) * 2]
            .copy_from_slice(&memo_106[0..2]);
        buf[MM_OFF_EPHEMERAL_PKS + slot * 32..MM_OFF_EPHEMERAL_PKS + (slot + 1) * 32]
            .copy_from_slice(&memo_106[2..34]);
        buf[MM_OFF_CIPHERTEXTS + slot * MEMO_CT_LEN..MM_OFF_CIPHERTEXTS + (slot + 1) * MEMO_CT_LEN]
            .copy_from_slice(&memo_106[34..MEMO_ENTRY_WIRE_LEN]);
    }

    fn make_nf_page(lane_id: u8, seq: u64, prefixes: &[[u8; NF_PREFIX_LEN]]) -> Vec<u8> {
        use audren_core::layout::{NF_OFF_LANE_ID, NF_OFF_PAGE_SEQ};
        let mut buf = vec![0u8; NF_PAGE_LEN];
        buf[0..8].copy_from_slice(&NF_PAGE_MAGIC);
        buf[NF_OFF_LANE_ID] = lane_id;
        buf[NF_OFF_COUNT..NF_OFF_COUNT + 2].copy_from_slice(&(prefixes.len() as u16).to_le_bytes());
        buf[NF_OFF_PAGE_SEQ..NF_OFF_PAGE_SEQ + 8].copy_from_slice(&seq.to_le_bytes());
        for (i, pref) in prefixes.iter().enumerate() {
            buf[NF_OFF_PREFIXES + i * NF_PREFIX_LEN..NF_OFF_PREFIXES + (i + 1) * NF_PREFIX_LEN]
                .copy_from_slice(pref);
        }
        buf
    }

    #[test]
    fn two_pass_cross_lane_sync_with_subroot_fast_sync_and_birthday_skip() {
        let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
        let alice = AudrenKeys::from_seed(&[0x7au8; 32]);
        let fvk = alice.full_viewing_key();
        let sol_asset = derive_asset_id(&WSOL_MINT);

        // Lane 2 has 520 leaves (2 sealed subtrees 0 & 1 + 8 frontier leaves in subtree 2;
        // 6 MemoPages @ 96 notes/page).
        // Alice owns 1 note at leaf 515 (SubtreePage 2, MemoPage 5), spent on Lane 0 alongside 40 strangers.
        let total_leaves = 520usize;
        let mut leaves = Vec::with_capacity(total_leaves);
        let memo_page_count = total_leaves.div_ceil(MEMO_NOTES_PER_PAGE);
        let mut memos: Vec<Vec<u8>> = (0..memo_page_count)
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
                let (tw, bl, memo_106) =
                    encrypt_note_memo(&alice.view_pk, [0x7bu8; 32], 4_200_000, &WSOL_MINT).unwrap();
                let cm = compute_note_commitment(
                    derive_stealth_owner(alice.spend_pk, tw),
                    sol_asset,
                    4_200_000,
                    bl,
                );
                leaves.push(cm);
                write_memo(&mut memos[i / MEMO_NOTES_PER_PAGE], i % MEMO_NOTES_PER_PAGE, &memo_106);
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

        // Default Strict mode: skips pre-birthday MemoPage 0 & SubtreePage 0; fetches post-birthday
        // newly synced SubtreePages 1 & 2 uniformly so RPC cannot tell which subtree held a hit!
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

        let reqs = requested.borrow();
        // Pre-birthday SubtreePage 0 and MemoPage 0 were skipped by birthday_slot binary search!
        assert!(!reqs.contains(&derive_subtree_pda(&program_id, 0, 2, 0).0));
        assert!(!reqs.contains(&derive_memo_pda(&program_id, 0, 2, 0).0));
        // Newly synced post-birthday SubtreePages 1 & 2 were both fetched uniformly in Strict mode!
        assert!(reqs.contains(&derive_subtree_pda(&program_id, 0, 2, 1).0));
        assert!(reqs.contains(&derive_subtree_pda(&program_id, 0, 2, 2).0));

        // Zero stranger prefixes serialized
        let json = String::from_utf8(store.to_json_bytes().unwrap()).unwrap();
        assert!(!json.contains("seen_nf_prefixes"));

        // Explicit Fast mode on the same fixture skips unhit sealed SubtreePages 0 & 1 via SubtreeRootPage!
        let fast_reqs: RefCell<Vec<Address>> = RefCell::new(Vec::new());
        let mut fast_store = CompactWalletStore::new(0, 1000);
        let (_, _, fast_disc) = sync_compact_store_with_options(
            &mut fast_store,
            &fvk,
            |addr| {
                fast_reqs.borrow_mut().push(*addr);
                accounts.get(addr).cloned()
            },
            &program_id,
            SyncOptions {
                privacy_mode: SyncPrivacyMode::Fast,
            },
        )
        .unwrap();
        assert_eq!(fast_disc, 1);
        assert!(fast_store.notes[0].spent);
        let freq = fast_reqs.borrow();
        assert!(!freq.contains(&derive_subtree_pda(&program_id, 0, 2, 0).0));
        assert!(!freq.contains(&derive_subtree_pda(&program_id, 0, 2, 1).0));
    }

    #[test]
    fn pass2_streams_all_nullifier_pages_without_early_exit_for_zero_notes_and_midstream_spend() {
        let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
        let alice = AudrenKeys::from_seed(&[0xa1u8; 32]);
        let alice_fvk = alice.full_viewing_key();
        let bob = AudrenKeys::from_seed(&[0xb2u8; 32]);
        let bob_fvk = bob.full_viewing_key();
        let sol_asset = derive_asset_id(&WSOL_MINT);

        let (tw, bl, memo_106) =
            encrypt_note_memo(&alice.view_pk, [0xa2u8; 32], 3_000_000, &WSOL_MINT).unwrap();
        let cm = compute_note_commitment(
            derive_stealth_owner(alice.spend_pk, tw),
            sol_asset,
            3_000_000,
            bl,
        );
        let lane0_sub0 = make_subtree(0, 0, &[cm]);
        let mut lane0_memo0 = make_memo(1, 0);
        write_memo(&mut lane0_memo0, 0, &memo_106);

        let alice_nf = alice_fvk.real_nullifier(cm, 0).unwrap();
        let alice_nf_prefix: [u8; NF_PREFIX_LEN] = alice_nf[0..NF_PREFIX_LEN].try_into().unwrap();

        let lane0_nf_pages = 121usize; // 2 uniform RPC batches (100 + 21)
        let lane0_nf_total = ((lane0_nf_pages - 1) * NF_PER_PAGE + 5) as u64;
        let lane1_nf_pages = 3usize;
        let lane1_nf_total = ((lane1_nf_pages - 1) * NF_PER_PAGE + 3) as u64;

        let full_strangers: Vec<[u8; NF_PREFIX_LEN]> = (0..NF_PER_PAGE)
            .map(|i| {
                let mut p = [0u8; NF_PREFIX_LEN];
                p[0] = 0xcc;
                p[1] = (i & 0xff) as u8;
                p[2] = ((i >> 8) & 0xff) as u8;
                p
            })
            .collect();
        let mut page0_prefixes = full_strangers.clone();
        page0_prefixes[0] = alice_nf_prefix;

        let reusable_lane0_full = make_nf_page(0, 1, &full_strangers);
        let lane0_tail = make_nf_page(0, (lane0_nf_pages - 1) as u64, &full_strangers[..5]);
        let reusable_lane1_full = make_nf_page(1, 0, &full_strangers);
        let lane1_tail = make_nf_page(1, (lane1_nf_pages - 1) as u64, &full_strangers[..3]);

        let mut accounts: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
        accounts.insert(derive_pool_pda(&program_id, 0).0, make_pool(2));
        accounts.insert(derive_lane_pda(&program_id, 0, 0).0, make_lane(0, 1, lane0_nf_total));
        accounts.insert(derive_lane_pda(&program_id, 0, 1).0, make_lane(1, 0, lane1_nf_total));
        accounts.insert(derive_subtree_pda(&program_id, 0, 0, 0).0, lane0_sub0);
        accounts.insert(derive_memo_pda(&program_id, 0, 0, 0).0, lane0_memo0);

        let mut expected_nf_addrs: BTreeSet<Address> = BTreeSet::new();
        for p in 0..lane0_nf_pages {
            let addr = derive_nf_page_pda(&program_id, 0, 0, p as u64).0;
            expected_nf_addrs.insert(addr);
            if p == 0 {
                accounts.insert(addr, make_nf_page(0, 0, &page0_prefixes));
            } else if p == lane0_nf_pages - 1 {
                accounts.insert(addr, lane0_tail.clone());
            } else {
                accounts.insert(addr, reusable_lane0_full.clone());
            }
        }
        for p in 0..lane1_nf_pages {
            let addr = derive_nf_page_pda(&program_id, 0, 1, p as u64).0;
            expected_nf_addrs.insert(addr);
            accounts.insert(
                addr,
                if p == lane1_nf_pages - 1 {
                    lane1_tail.clone()
                } else {
                    reusable_lane1_full.clone()
                },
            );
        }

        // Case 1: Bob has 0 unspent notes -> Pass 2 MUST STILL fetch all 124 NullifierPages!
        let mut bob_log: Vec<(Vec<Address>, Option<AccountDataSlice>)> = Vec::new();
        let mut bob_store = CompactWalletStore::new(0, 0);
        let (_, _, bob_disc) = sync_compact_store_with_batch(
            &mut bob_store,
            &bob_fvk,
            |addrs, slice| {
                bob_log.push((addrs.to_vec(), slice));
                addrs.iter().map(|a| accounts.get(a).cloned()).collect()
            },
            &program_id,
            SyncOptions::default(),
        )
        .unwrap();
        assert_eq!(bob_disc, 0);
        assert!(bob_store.notes.is_empty());
        assert_eq!(bob_store.lanes[0].next_nf_index, lane0_nf_total);
        assert_eq!(bob_store.lanes[1].next_nf_index, lane1_nf_total);
        let bob_nf_fetched: BTreeSet<Address> = bob_log
            .iter()
            .flat_map(|(a, _)| a.iter().copied())
            .filter(|a| expected_nf_addrs.contains(a))
            .collect();
        assert_eq!(
            bob_nf_fetched.len(),
            expected_nf_addrs.len(),
            "wallet with 0 unspent notes must fetch ALL 124 NullifierPages without skipping Pass 2"
        );
        assert!(!String::from_utf8(bob_store.to_json_bytes().unwrap())
            .unwrap()
            .contains("seen_nf_prefixes"));

        // Case 2: Alice's only note is spent on NullifierPage 0 (batch 0) -> Pass 2 MUST NOT break early!
        let mut alice_log: Vec<(Vec<Address>, Option<AccountDataSlice>)> = Vec::new();
        let mut alice_store = CompactWalletStore::new(0, 0);
        let (_, _, alice_disc) = sync_compact_store_with_batch(
            &mut alice_store,
            &alice_fvk,
            |addrs, slice| {
                alice_log.push((addrs.to_vec(), slice));
                addrs.iter().map(|a| accounts.get(a).cloned()).collect()
            },
            &program_id,
            SyncOptions::default(),
        )
        .unwrap();
        assert_eq!(alice_disc, 1);
        assert!(alice_store.notes[0].spent);
        assert!(alice_store.unspent_notes(None).is_empty());
        assert_eq!(alice_store.lanes[0].next_nf_index, lane0_nf_total);
        assert_eq!(alice_store.lanes[1].next_nf_index, lane1_nf_total);
        let alice_nf_fetched: BTreeSet<Address> = alice_log
            .iter()
            .flat_map(|(a, _)| a.iter().copied())
            .filter(|a| expected_nf_addrs.contains(a))
            .collect();
        assert_eq!(
            alice_nf_fetched.len(),
            expected_nf_addrs.len(),
            "Pass 2 must fetch ALL 124 NullifierPages even after last unspent note is marked spent on page 0"
        );
        let alice_json = String::from_utf8(alice_store.to_json_bytes().unwrap()).unwrap();
        assert!(!alice_json.contains("seen_nf_prefixes"));
    }

    #[test]
    fn strict_mode_incremental_zero_dataslice_and_large_catchup_decoy_padding_vs_fast_mode() {
        let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
        let alice = AudrenKeys::from_seed(&[0xd1u8; 32]);
        let fvk = alice.full_viewing_key();
        let bob = AudrenKeys::from_seed(&[0xd9u8; 32]);
        let bob_fvk = bob.full_viewing_key();
        let sol_asset = derive_asset_id(&WSOL_MINT);

        let dummy_leaves: Vec<Fr> = (0..SUBTREE_LEAVES).map(|i| Fr::from((i + 1) as u64)).collect();
        let dummy_subroot = compute_subtree_256_root(&dummy_leaves, SUBTREE_LEAVES);
        let dummy_frontier = &dummy_leaves[..4];

        let (tw, bl, memo_106) =
            encrypt_note_memo(&alice.view_pk, [0xd2u8; 32], 8_888_888, &WSOL_MINT).unwrap();
        let alice_cm = compute_note_commitment(
            derive_stealth_owner(alice.spend_pk, tw),
            sol_asset,
            8_888_888,
            bl,
        );
        // Alice's note is on Lane 2, leaf 300 -> sealed SubtreePage (lane=2, seq=1, slot=44),
        // MemoPage (lane=2, seq=3, slot=12 @ 96/page), spent on Lane 0 NullifierPage 0 (of 3 pages).
        let alice_leaf_idx = 300u64;
        let alice_sub_seq = 1u64;
        let alice_sub_slot = (alice_leaf_idx % SUBTREE_LEAVES as u64) as usize;
        let alice_memo_seq = alice_leaf_idx / MEMO_NOTES_PER_PAGE as u64;
        let alice_memo_slot = (alice_leaf_idx % MEMO_NOTES_PER_PAGE as u64) as usize;

        let mut hit_sub_leaves = dummy_leaves.clone();
        hit_sub_leaves[alice_sub_slot] = alice_cm;
        let hit_subroot = compute_subtree_256_root(&hit_sub_leaves, SUBTREE_LEAVES);
        let hit_sub_raw = make_subtree(2, alice_sub_seq, &hit_sub_leaves);
        let mut hit_memo_raw = make_memo(MEMO_NOTES_PER_PAGE as u16, 0);
        write_memo(&mut hit_memo_raw, alice_memo_slot, &memo_106);

        let alice_nf = fvk
            .real_nullifier(alice_cm, (2u64 << 36) | alice_leaf_idx)
            .unwrap();
        let alice_nf_prefix: [u8; NF_PREFIX_LEN] = alice_nf[0..NF_PREFIX_LEN].try_into().unwrap();

        let build_fixture = |sealed_per_lane: usize| {
            let active_lanes = 4u8;
            let leaves_per_lane = sealed_per_lane * SUBTREE_LEAVES + 4;
            let memos_per_lane = leaves_per_lane.div_ceil(MEMO_NOTES_PER_PAGE);
            let nf_pages_lane0 = 3usize;
            let nf_total_lane0 = ((nf_pages_lane0 - 1) * NF_PER_PAGE + 5) as u64;

            let mut accounts: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
            accounts.insert(derive_pool_pda(&program_id, 0).0, make_pool(active_lanes));

            let mut sealed_sub_addrs: BTreeSet<Address> = BTreeSet::new();
            let mut all_memo_addrs: BTreeSet<Address> = BTreeSet::new();
            let mut all_nf_addrs: BTreeSet<Address> = BTreeSet::new();

            let stranger_prefixes: Vec<[u8; NF_PREFIX_LEN]> = (0..NF_PER_PAGE)
                .map(|i| {
                    let mut p = [0u8; NF_PREFIX_LEN];
                    p[0] = 0xdd;
                    p[1] = (i & 0xff) as u8;
                    p
                })
                .collect();
            let mut nf0_prefixes = stranger_prefixes.clone();
            nf0_prefixes[0] = alice_nf_prefix;
            for p in 0..nf_pages_lane0 {
                let addr = derive_nf_page_pda(&program_id, 0, 0, p as u64).0;
                all_nf_addrs.insert(addr);
                let raw = if p == 0 {
                    make_nf_page(0, 0, &nf0_prefixes)
                } else if p == nf_pages_lane0 - 1 {
                    make_nf_page(0, p as u64, &stranger_prefixes[..5])
                } else {
                    make_nf_page(0, p as u64, &stranger_prefixes)
                };
                accounts.insert(addr, raw);
            }

            let empty_full_memo = make_memo(MEMO_NOTES_PER_PAGE as u16, 0);
            for l in 0..active_lanes {
                accounts.insert(
                    derive_lane_pda(&program_id, 0, l).0,
                    make_lane(l, leaves_per_lane as u64, if l == 0 { nf_total_lane0 } else { 0 }),
                );
                let roots: Vec<Fr> = (0..sealed_per_lane)
                    .map(|s| {
                        if l == 2 && s as u64 == alice_sub_seq {
                            hit_subroot
                        } else {
                            dummy_subroot
                        }
                    })
                    .collect();
                accounts.insert(
                    derive_subroot_pda(&program_id, 0, l, 0).0,
                    make_subroot(l, 0, &roots),
                );
                let generic_sealed = make_subtree(l, 0, &dummy_leaves);
                for s in 0..sealed_per_lane {
                    let addr = derive_subtree_pda(&program_id, 0, l, s as u64).0;
                    sealed_sub_addrs.insert(addr);
                    accounts.insert(
                        addr,
                        if l == 2 && s as u64 == alice_sub_seq {
                            hit_sub_raw.clone()
                        } else {
                            generic_sealed.clone()
                        },
                    );
                }
                accounts.insert(
                    derive_subtree_pda(&program_id, 0, l, sealed_per_lane as u64).0,
                    make_subtree(l, sealed_per_lane as u64, dummy_frontier),
                );
                for m in 0..memos_per_lane {
                    let addr = derive_memo_pda(&program_id, 0, l, m as u64).0;
                    all_memo_addrs.insert(addr);
                    let cnt = MEMO_NOTES_PER_PAGE.min(leaves_per_lane - m * MEMO_NOTES_PER_PAGE);
                    if l == 2 && m as u64 == alice_memo_seq {
                        accounts.insert(addr, hit_memo_raw.clone());
                    } else if cnt == MEMO_NOTES_PER_PAGE {
                        accounts.insert(addr, empty_full_memo.clone());
                    } else {
                        accounts.insert(addr, make_memo(cnt as u16, 0));
                    }
                }
            }

            (
                accounts,
                sealed_sub_addrs,
                all_memo_addrs,
                all_nf_addrs,
                nf_total_lane0,
                derive_subtree_pda(&program_id, 0, 2, alice_sub_seq).0,
                derive_memo_pda(&program_id, 0, 2, alice_memo_seq).0,
            )
        };

        let slice_fetch = |accounts: &BTreeMap<Address, Vec<u8>>,
                           log: &mut Vec<(Vec<Address>, Option<AccountDataSlice>)>,
                           addrs: &[Address],
                           slice: Option<AccountDataSlice>| {
            log.push((addrs.to_vec(), slice));
            addrs
                .iter()
                .map(|a| {
                    let full = accounts.get(a)?;
                    match slice {
                        Some(s) => {
                            let end = s.offset.saturating_add(s.length).min(full.len());
                            Some(full[s.offset..end].to_vec())
                        }
                        None => Some(full.clone()),
                    }
                })
                .collect()
        };

        // 1. Small incremental fixture: 2 sealed subtrees/lane = 8 sealed subtrees, 24 MemoPages (<= 25)
        let (acc_small, sealed_small, memos_small, nf_small, _, _, _) = build_fixture(2);
        assert_eq!(memos_small.len(), 24);
        let mut small_log = Vec::new();
        let mut small_store = CompactWalletStore::new(0, 0);
        let (_, _, d_small) = sync_compact_store_with_batch(
            &mut small_store,
            &fvk,
            |addrs, slice| slice_fetch(&acc_small, &mut small_log, addrs, slice),
            &program_id,
            SyncOptions::default(),
        )
        .unwrap();
        assert_eq!(d_small, 1);
        assert!(small_log.iter().all(|(_, s)| s.is_none()), "strict incremental sync must issue ZERO dataSlice calls");
        let small_fetched: Vec<Address> = small_log.iter().flat_map(|(a, _)| a.iter().copied()).collect();
        for m in &memos_small {
            assert_eq!(small_fetched.iter().filter(|&x| x == m).count(), 1, "zero hit-correlated MemoPage re-fetch");
        }
        let small_sealed_fetched: BTreeSet<Address> = small_fetched
            .iter()
            .copied()
            .filter(|a| sealed_small.contains(a))
            .collect();
        assert_eq!(small_sealed_fetched.len(), sealed_small.len(), "all <= 25 newly synced SubtreePages fetched uniformly");
        let small_nf_fetched: BTreeSet<Address> = small_fetched
            .iter()
            .copied()
            .filter(|a| nf_small.contains(a))
            .collect();
        assert_eq!(small_nf_fetched.len(), 3);

        // Even Fast mode on <= 25 MemoPages fetches full MemoPages directly (zero 3,328 B dataSlice)!
        let mut fast_small_log = Vec::new();
        let mut fast_small_store = CompactWalletStore::new(0, 0);
        sync_compact_store_with_batch(
            &mut fast_small_store,
            &fvk,
            |addrs, slice| slice_fetch(&acc_small, &mut fast_small_log, addrs, slice),
            &program_id,
            SyncOptions {
                privacy_mode: SyncPrivacyMode::Fast,
            },
        )
        .unwrap();
        assert!(
            fast_small_log
                .iter()
                .all(|(_, s)| s.map(|x| x.length != MEMO_PAGE_SCAN_SLICE_LEN).unwrap_or(true)),
            "fast mode must fetch full MemoPages directly on <= 25 pages"
        );

        // 2. Large catch-up fixture: 5 sealed subtrees/lane = 20 sealed subtrees (> 16), 56 MemoPages (> 25)
        let (acc_20, sealed_20, memos_20, nf_20, nf_total_20, hit_sub_20, hit_memo_20) = build_fixture(5);
        assert_eq!(sealed_20.len(), 20);
        assert_eq!(memos_20.len(), 56);

        // 2A. Default Strict mode: ZERO dataSlice, ZERO MemoPage re-fetch, 16 deterministic decoy-padded
        //     sealed SubtreePages, full Pass 2!
        let mut strict20_log = Vec::new();
        let mut strict20_store = CompactWalletStore::new(0, 0);
        let (_, _, d20) = sync_compact_store_with_batch(
            &mut strict20_store,
            &fvk,
            |addrs, slice| slice_fetch(&acc_20, &mut strict20_log, addrs, slice),
            &program_id,
            SyncOptions::default(),
        )
        .unwrap();
        assert_eq!(d20, 1);
        assert!(strict20_store.notes[0].spent);
        assert!(strict20_store.notes[0].frozen_intra_siblings.is_some());
        assert_eq!(strict20_store.lanes[0].next_nf_index, nf_total_20);
        assert!(strict20_log.iter().all(|(_, s)| s.is_none()), "strict mode large catch-up must issue ZERO dataSlice calls");
        let strict20_fetched: Vec<Address> = strict20_log.iter().flat_map(|(a, _)| a.iter().copied()).collect();
        for m in &memos_20 {
            assert_eq!(strict20_fetched.iter().filter(|&x| x == m).count(), 1, "each MemoPage fetched exactly once in full");
        }
        let strict20_sealed_ordered: Vec<Address> = strict20_fetched
            .iter()
            .copied()
            .filter(|a| sealed_20.contains(a))
            .collect();
        let strict20_sealed: BTreeSet<Address> = strict20_sealed_ordered.iter().copied().collect();
        assert!(strict20_sealed.contains(&hit_sub_20));
        assert_eq!(
            strict20_sealed.len(),
            16,
            "strict mode must decoy-pad historical sealed SubtreePage batch to min(16, 20) = 16"
        );
        let strict20_nf: BTreeSet<Address> = strict20_fetched
            .iter()
            .copied()
            .filter(|a| nf_20.contains(a))
            .collect();
        assert_eq!(strict20_nf.len(), 3, "Pass 2 must fetch all 3 NullifierPages without early-exit");

        // 2A-repeat: Repeated Strict sync for same wallet produces IDENTICAL decoy set & order (zero intersection leak),
        //            and Bob (0 hits) ALSO fetches 16 sealed SubtreePages (fixed uniform batch size)!
        let mut strict20_repeat_log = Vec::new();
        let mut strict20_repeat_store = CompactWalletStore::new(0, 0);
        sync_compact_store_with_batch(
            &mut strict20_repeat_store,
            &fvk,
            |addrs, slice| slice_fetch(&acc_20, &mut strict20_repeat_log, addrs, slice),
            &program_id,
            SyncOptions::default(),
        )
        .unwrap();
        let repeat_sealed_ordered: Vec<Address> = strict20_repeat_log
            .iter()
            .flat_map(|(a, _)| a.iter().copied())
            .filter(|a| sealed_20.contains(a))
            .collect();
        assert_eq!(
            strict20_sealed_ordered, repeat_sealed_ordered,
            "deterministic wallet-keyed decoys must be identical across repeated syncs"
        );

        let mut bob20_log = Vec::new();
        let mut bob20_store = CompactWalletStore::new(0, 0);
        let (_, _, bob_d20) = sync_compact_store_with_batch(
            &mut bob20_store,
            &bob_fvk,
            |addrs, slice| slice_fetch(&acc_20, &mut bob20_log, addrs, slice),
            &program_id,
            SyncOptions::default(),
        )
        .unwrap();
        assert_eq!(bob_d20, 0);
        let bob20_sealed: BTreeSet<Address> = bob20_log
            .iter()
            .flat_map(|(a, _)| a.iter().copied())
            .filter(|a| sealed_20.contains(a))
            .collect();
        assert_eq!(
            bob20_sealed.len(),
            16,
            "zero-hit wallet in strict large catch-up must still fetch 16 sealed SubtreePages"
        );

        // 2A-miss: Transient Pass 1D SubtreePage miss on hit MUST STILL run Pass 2 unconditionally
        //          (zero Pass 1D -> Pass 2 oracle!), cap next_memo_leaf, and recover on retry!
        let mut miss_log = Vec::new();
        let mut miss_store = CompactWalletStore::new(0, 0);
        let (_, _, d_miss) = sync_compact_store_with_batch(
            &mut miss_store,
            &fvk,
            |addrs, slice| {
                miss_log.push((addrs.to_vec(), slice));
                addrs
                    .iter()
                    .map(|a| {
                        if *a == hit_sub_20 {
                            return None;
                        }
                        let full = acc_20.get(a)?;
                        match slice {
                            Some(s) => {
                                let end = s.offset.saturating_add(s.length).min(full.len());
                                Some(full[s.offset..end].to_vec())
                            }
                            None => Some(full.clone()),
                        }
                    })
                    .collect()
            },
            &program_id,
            SyncOptions::default(),
        )
        .unwrap();
        assert_eq!(d_miss, 0, "missed SubtreePage cannot verify hit note yet");
        assert_eq!(
            miss_store.lanes[2].next_memo_leaf, alice_leaf_idx,
            "next_memo_leaf must be capped at the missed hit leaf"
        );
        let miss_nf: BTreeSet<Address> = miss_log
            .iter()
            .flat_map(|(a, _)| a.iter().copied())
            .filter(|a| nf_20.contains(a))
            .collect();
        assert_eq!(
            miss_nf.len(),
            3,
            "Pass 2 MUST run unconditionally and fetch all 3 NullifierPages even when Pass 1D misses a hit SubtreePage"
        );
        // Retry once RPC returns hit_sub_20 -> discovers note AND marks it spent!
        let mut retry_log = Vec::new();
        let (_, _, d_retry) = sync_compact_store_with_batch(
            &mut miss_store,
            &fvk,
            |addrs, slice| slice_fetch(&acc_20, &mut retry_log, addrs, slice),
            &program_id,
            SyncOptions::default(),
        )
        .unwrap();
        assert_eq!(d_retry, 1, "retry must recover missed hit note");
        assert!(
            miss_store.notes[0].spent,
            "retry Pass 2 must mark recovered note spent"
        );
        assert_eq!(miss_store.lanes[0].next_nf_index, nf_total_20);

        // 2B. Smaller large catch-up: 3 sealed subtrees/lane = 12 (< 16), 36 MemoPages (> 25) -> pads to all 12!
        let (acc_12, sealed_12, memos_12, _, _, _, _) = build_fixture(3);
        assert_eq!(sealed_12.len(), 12);
        assert_eq!(memos_12.len(), 36);
        let mut strict12_log = Vec::new();
        let mut strict12_store = CompactWalletStore::new(0, 0);
        let (_, _, d12) = sync_compact_store_with_batch(
            &mut strict12_store,
            &fvk,
            |addrs, slice| slice_fetch(&acc_12, &mut strict12_log, addrs, slice),
            &program_id,
            SyncOptions::default(),
        )
        .unwrap();
        assert_eq!(d12, 1);
        let strict12_sealed: BTreeSet<Address> = strict12_log
            .iter()
            .flat_map(|(a, _)| a.iter().copied())
            .filter(|a| sealed_12.contains(a))
            .collect();
        assert_eq!(strict12_sealed.len(), 12, "when < 16 sealed subtrees exist, strict mode must pad to all 12");

        // 2C. Explicit Fast mode on > 25 MemoPages: uses dataSlice(0, 3328), full re-fetch only on hit,
        //     skips decoy SubtreePages, and STILL runs full Pass 2 without early-exit!
        let mut fast20_log = Vec::new();
        let mut fast20_store = CompactWalletStore::new(0, 0);
        let (_, _, df20) = sync_compact_store_with_batch(
            &mut fast20_store,
            &fvk,
            |addrs, slice| slice_fetch(&acc_20, &mut fast20_log, addrs, slice),
            &program_id,
            SyncOptions {
                privacy_mode: SyncPrivacyMode::Fast,
            },
        )
        .unwrap();
        assert_eq!(df20, 1);
        assert!(fast20_store.notes[0].spent);
        assert_eq!(fast20_store.lanes[0].next_nf_index, nf_total_20);

        let fast_sliced_memos: BTreeSet<Address> = fast20_log
            .iter()
            .filter(|(_, s)| *s == Some(AccountDataSlice { offset: 0, length: MEMO_PAGE_SCAN_SLICE_LEN }))
            .flat_map(|(a, _)| a.iter().copied())
            .collect();
        assert_eq!(fast_sliced_memos.len(), 56, "fast mode > 25 pages must scan all 56 MemoPages via dataSlice(0, 3328)");

        let fast_full_memos: Vec<Address> = fast20_log
            .iter()
            .filter(|(_, s)| s.is_none())
            .flat_map(|(a, _)| a.iter().copied())
            .filter(|a| memos_20.contains(a))
            .collect();
        assert_eq!(fast_full_memos, vec![hit_memo_20], "fast mode Pass 1D fetches ONLY hit MemoPage in full");

        let fast_sealed: BTreeSet<Address> = fast20_log
            .iter()
            .flat_map(|(a, _)| a.iter().copied())
            .filter(|a| sealed_20.contains(a))
            .collect();
        assert_eq!(fast_sealed.into_iter().collect::<Vec<_>>(), vec![hit_sub_20]);

        let fast_nf: BTreeSet<Address> = fast20_log
            .iter()
            .flat_map(|(a, _)| a.iter().copied())
            .filter(|a| nf_20.contains(a))
            .collect();
        assert_eq!(fast_nf.len(), 3, "fast mode must STILL run full Pass 2 without early-exit");
    }
}
