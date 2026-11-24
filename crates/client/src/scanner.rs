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
    merkle::{
        build_historical_witness_4ary, compute_subtree_256_root, compute_super_root_4ary,
        extract_intra_subtree_siblings, zero_hashes_4ary, MerklePath4Ary, SUBTREE_LEVELS_4ARY,
    },
    poseidon::{fr_from_be_bytes_strict, fr_to_be_bytes, poseidon4},
};
use audren_core::{
    layout::{
        read_32, read_u16, read_u32, read_u64, GlobalRootHistory, LaneTreeHeader, PoolState,
        RootSnapshotChoice, MAX_LEAVES_PER_LANE, MEMO_CT_LEN, MEMO_MAGIC, MEMO_NOTES_PER_PAGE,
        MEMO_PAGE_LEN, MM_OFF_CIPHERTEXTS, MM_OFF_CLOSED_SLOT, MM_OFF_COUNT, MM_OFF_EPHEMERAL_PKS,
        MM_OFF_LANE_ID, MM_OFF_PAGE_SEQ, MM_OFF_POOL_ID, MM_OFF_VIEW_TAGS, NF_OFF_CLOSED_SLOT,
        NF_OFF_COUNT, NF_OFF_LANE_ID, NF_OFF_PAGE_SEQ, NF_OFF_POOL_ID, NF_PAGE_LEN, NF_PAGE_MAGIC,
        NF_PER_PAGE, SB_OFF_COUNT, SB_OFF_LANE_ID, SB_OFF_LEAVES, SB_OFF_PAGE_SEQ, SB_OFF_POOL_ID,
        SR_OFF_COUNT, SR_OFF_LANE_ID, SR_OFF_POOL_ID, SR_OFF_ROOTS, SR_OFF_ROOT_PAGE_SEQ,
        SUBROOTS_PER_PAGE, SUBROOT_MAGIC, SUBROOT_PAGE_LEN, SUBTREE_LEAVES, SUBTREE_MAGIC,
        SUBTREE_PAGE_LEN,
    },
    EPOCH_RING_LEN, LANE_DEPTH_4ARY, MAX_ROOT_EPOCH_INTERVAL, NUM_LANES, ROOT_RING_EPOCH,
    ROOT_RING_SLOT, SLOT_RING_LEN, ZERO_HASHES_4ARY,
};
use rand::{rngs::OsRng, Rng};
use sha2::{Digest, Sha256};
use solana_address::Address;

use crate::{
    instructions::validate_root_ring,
    keys::{
        check_memo_view_tag, try_decrypt_and_verify_memo_entry, DecryptedMemo, FullViewingKey,
    },
    pda::{
        derive_lane_pda, derive_memo_pda, derive_nf_page_pda, derive_pool_pda, derive_roots_pda,
        derive_subroot_pda, derive_subtree_pda,
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
/// Sealed-subtree count divisor for deterministic decoy epoch buckets (synced with TypeScript SDK).
pub const DECOY_EPOCH_BUCKET_SIZE: u64 = 64;
/// Maximum pages fetched per pass in a single `sync_compact_store_with_batch` call (prevents untrusted-RPC OOM/hang).
pub const MAX_SYNC_PAGES_PER_CALL: usize = 4_096;
/// Maximum total `SubtreeRootPage`s fetched in a single `reconstruct_witness_with_batch` call (`4,096 * 300 = 1.22M` subtrees).
pub const MAX_WITNESS_SR_PAGES: usize = 4_096;
/// Maximum total sealed subtrees scanned by `select_hrw_sealed_decoys` (`262,144 * 256 = 67M` notes).
pub const MAX_HRW_SEALED_SUBTREES: u64 = 262_144;

fn compute_lane_root_from_subroots_and_frontier(
    finalized_subroots: &[Fr],
    frontier_leaves: Option<&[Fr]>,
    frontier_rem: usize,
) -> Result<Fr, ClientError> {
    let zeros = zero_hashes_4ary();
    let mut level_nodes = Vec::with_capacity(finalized_subroots.len() + usize::from(frontier_rem > 0));
    level_nodes.extend_from_slice(finalized_subroots);
    if frontier_rem > 0 {
        let f_leaves = frontier_leaves
            .ok_or(ClientError::WitnessNotFound("Frontier SubtreePage missing"))?;
        if f_leaves.len() < frontier_rem || frontier_rem > SUBTREE_LEAVES {
            return Err(ClientError::WitnessNotFound("Frontier SubtreePage truncated"));
        }
        level_nodes.push(compute_subtree_256_root(f_leaves, frontier_rem));
    }
    if level_nodes.is_empty() {
        return Ok(zeros[LANE_DEPTH_4ARY]);
    }
    for &zero_at_h in &zeros[SUBTREE_LEVELS_4ARY..LANE_DEPTH_4ARY] {
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
    }
    Ok(level_nodes[0])
}
/// Domain tag for Rendezvous (HRW) wallet-keyed decoy selection in `Strict` mode.
const DECOY_DOMAIN: &[u8] = b"audren/v1/decoy";
const DECOY_SCOPE_SYNC: &[u8] = b"sync";
const DECOY_SCOPE_WITNESS_PREFIX: &[u8] = b"witness";
const DECOY_ORDER_LABEL: &[u8] = b"order";
/// Byte length of the `MemoPage` header prefix (`closed_slot` binary search).
pub const MEMO_PAGE_HEADER_LEN: usize = 64;
/// Byte length of the `MemoPage` SoA scan slice (`header + view_tags + ephemeral_pks = 3,328 B`).
pub const MEMO_PAGE_SCAN_SLICE_LEN: usize = MM_OFF_CIPHERTEXTS;
/// Byte length of the `NullifierPage` header prefix (`closed_slot` binary search).
pub const NF_PAGE_HEADER_LEN: usize = 64;

/// RPC privacy mode for `CompactWalletStore` synchronization and witness reconstruction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SyncPrivacyMode {
    /// Default privacy-preserving mode: fetches full `10,240 B` `MemoPage`s in uniform batches,
    /// fetches newly synced `SubtreePage`s uniformly on incremental syncs (`<= 25` pages / `<= 25`
    /// subtrees), uses Rendezvous (HRW) wallet-keyed decoy padding (`min(16, total_sealed)`)
    /// on large catch-ups & unfrozen sealed notes, fetches all active lanes' frontiers + subroots
    /// during witness reconstruction, and runs Pass 2 unconditionally without early-exit.
    #[default]
    Strict,
    /// Opt-in bandwidth-saving mode for large historical catch-up (`> 25` `MemoPage`s) or minimal
    /// witness fetching over a self-hosted / trusted RPC.
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
    /// Optional explicit epoch bucket override (defaults to `0`, letting Rendezvous HRW naturally
    /// preserve overlapping decoys across monotonic pool growth with zero cliff rotation).
    pub decoy_epoch_bucket: Option<u64>,
}

/// Options controlling stateless witness reconstruction (`reconstruct_witness_with_batch`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WitnessOptions {
    pub privacy_mode: SyncPrivacyMode,
    /// Required 32-byte `view_sk` in `SyncPrivacyMode::Strict` for deterministic Rendezvous (HRW)
    /// decoy selection scoped to `(lane_id, target_page_seq, epoch_bucket)`. Ignored in
    /// `SyncPrivacyMode::Fast`.
    pub view_sk: Option<[u8; 32]>,
    /// Optional explicit epoch bucket override (defaults to `0`, letting Rendezvous HRW naturally
    /// preserve overlapping decoys across monotonic pool growth with zero cliff rotation).
    pub decoy_epoch_bucket: Option<u64>,
}

fn make_witness_decoy_scope(target_lane_id: u8, target_page_seq: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..7].copy_from_slice(DECOY_SCOPE_WITNESS_PREFIX);
    out[7] = target_lane_id;
    out[8..16].copy_from_slice(&target_page_seq.to_le_bytes());
    out
}

fn compute_subtree_order_key(
    view_sk: &[u8; 32],
    scope: &[u8],
    epoch_bucket: u64,
    addr: &Address,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(view_sk);
    h.update(DECOY_DOMAIN);
    h.update(scope);
    h.update(epoch_bucket.to_le_bytes());
    h.update(DECOY_ORDER_LABEL);
    h.update(addr.as_ref());
    h.finalize().into()
}

/// Fallible deterministic Rendezvous (Highest Random Weight) sealed `SubtreePage` decoy selection
/// enforcing [`MAX_HRW_SEALED_SUBTREES`] before iterating so untrusted RPC headers cannot spin CPU.
pub fn try_select_hrw_sealed_decoys(
    view_sk: &[u8; 32],
    scope: &[u8],
    epoch_bucket: u64,
    sealed_by_lane: &[(u8, u64)],
    already_selected: &BTreeSet<(u8, u64)>,
    target_sealed: usize,
) -> Result<Vec<(u8, u64)>, ClientError> {
    let mut total_sealed = 0u64;
    let mut already_sealed_count = 0usize;
    for &(lane_id, sealed_count) in sealed_by_lane {
        total_sealed = total_sealed.saturating_add(sealed_count);
        if total_sealed > MAX_HRW_SEALED_SUBTREES {
            return Err(ClientError::InvalidEncoding(
                "sealed subtree count exceeds HRW operational bound",
            ));
        }
        for &(sel_lane, sel_seq) in already_selected {
            if sel_lane == lane_id && sel_seq < sealed_count {
                already_sealed_count += 1;
            }
        }
    }
    let capped_target = (target_sealed as u64).min(total_sealed) as usize;
    let need = capped_target.saturating_sub(already_sealed_count);
    if need == 0 {
        return Ok(Vec::new());
    }

    if total_sealed <= capped_target as u64 {
        let mut out = Vec::with_capacity(need);
        for &(lane_id, sealed_count) in sealed_by_lane {
            for s in 0..sealed_count {
                if !already_selected.contains(&(lane_id, s)) {
                    out.push((lane_id, s));
                }
            }
        }
        return Ok(out);
    }

    let mut preimage = Vec::with_capacity(32 + DECOY_DOMAIN.len() + scope.len() + 8 + 1 + 8);
    preimage.extend_from_slice(view_sk);
    preimage.extend_from_slice(DECOY_DOMAIN);
    preimage.extend_from_slice(scope);
    preimage.extend_from_slice(&epoch_bucket.to_le_bytes());
    let lane_off = preimage.len();
    preimage.push(0);
    let seq_off = preimage.len();
    preimage.extend_from_slice(&0u64.to_le_bytes());

    let beats = |score_a: &[u8; 32],
                 lane_a: u8,
                 seq_a: u64,
                 b: &([u8; 32], u8, u64)|
     -> bool {
        match score_a.cmp(&b.0) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => (lane_a, seq_a) < (b.1, b.2),
        }
    };

    let mut top: Vec<([u8; 32], u8, u64)> = Vec::with_capacity(need + 1);
    for &(lane_id, sealed_count) in sealed_by_lane {
        preimage[lane_off] = lane_id;
        for s in 0..sealed_count {
            if already_selected.contains(&(lane_id, s)) {
                continue;
            }
            preimage[seq_off..seq_off + 8].copy_from_slice(&s.to_le_bytes());
            let score: [u8; 32] = Sha256::digest(&preimage).into();
            if top.len() == need && !beats(&score, lane_id, s, &top[need - 1]) {
                continue;
            }
            let mut insert_at = top.len();
            while insert_at > 0 && beats(&score, lane_id, s, &top[insert_at - 1]) {
                insert_at -= 1;
            }
            top.insert(insert_at, (score, lane_id, s));
            if top.len() > need {
                top.pop();
            }
        }
    }

    Ok(top.into_iter().map(|(_, l, s)| (l, s)).collect())
}

/// Deterministic Rendezvous (Highest Random Weight) sealed `SubtreePage` decoy selection matching
/// `packages/sdk/src/scanner.ts::selectHrwSealedDecoys` bit-for-bit:
///
/// `score = SHA256(view_sk[32] || "audren/v1/decoy" || scope || epoch_bucket_le8 || lane_id || page_seq_le8)`
///
/// Selects the top-`K` highest-scoring candidates not in `already_selected` so `+1` sealed subtree
/// growth within an epoch bucket preserves `~(K - 1) / K` (typically `K / K`) of decoys instead
/// of scrambling modulo indices.
pub fn select_hrw_sealed_decoys(
    view_sk: &[u8; 32],
    scope: &[u8],
    epoch_bucket: u64,
    sealed_by_lane: &[(u8, u64)],
    already_selected: &BTreeSet<(u8, u64)>,
    target_sealed: usize,
) -> Vec<(u8, u64)> {
    try_select_hrw_sealed_decoys(
        view_sk,
        scope,
        epoch_bucket,
        sealed_by_lane,
        already_selected,
        target_sealed,
    )
    .unwrap_or_default()
}

fn shuffle_in_place<T>(items: &mut [T]) {
    let len = items.len();
    for i in (1..len).rev() {
        let j = OsRng.gen_range(0..=i);
        items.swap(i, j);
    }
}

pub fn decode_pool_state(data: &[u8]) -> Result<PoolState, ClientError> {
    PoolState::decode(data).ok_or(ClientError::InvalidEncoding("invalid PoolState account"))
}

pub fn decode_lane_header(data: &[u8]) -> Result<LaneTreeHeader, ClientError> {
    LaneTreeHeader::decode(data).ok_or(ClientError::InvalidEncoding("invalid LaneTreeState account"))
}

pub fn decode_global_root_history(data: &[u8]) -> Result<GlobalRootHistory, ClientError> {
    GlobalRootHistory::decode(data)
        .ok_or(ClientError::InvalidEncoding("invalid GlobalRootHistory account"))
}

/// Strictly validate `GlobalRootHistory` pool binding, ring cursor/count bounds, epoch/slot
/// header consistency, lane count monotonicity and zero-root/equal-root invariants, non-zero
/// roots, ring cursor parity (super_root + slot), and full canonical BN254 `Fr` + 4-ary super-root
/// integrity for BOTH `latest` and `stable` snapshots before trusting any root or lane count from
/// an untrusted RPC.
pub fn validate_global_root_history(
    roots: &GlobalRootHistory,
    pool_id: u32,
) -> Result<(), ClientError> {
    if roots.pool_id != pool_id {
        return Err(ClientError::InvalidEncoding(
            "GlobalRootHistory header mismatch",
        ));
    }
    let slot_count = roots.slot_count as usize;
    let slot_cursor = roots.slot_cursor as usize;
    let epoch_count = roots.epoch_count as usize;
    let epoch_cursor = roots.epoch_cursor as usize;
    if slot_count < 1
        || slot_count > SLOT_RING_LEN
        || slot_cursor >= slot_count
        || epoch_count < 1
        || epoch_count > EPOCH_RING_LEN
        || epoch_cursor >= epoch_count
    {
        return Err(ClientError::InvalidEncoding(
            "GlobalRootHistory ring cursor or count out of bounds",
        ));
    }
    if !(1..=MAX_ROOT_EPOCH_INTERVAL).contains(&roots.epoch_interval) {
        return Err(ClientError::InvalidEncoding(
            "GlobalRootHistory epoch_interval out of bounds",
        ));
    }
    if roots.stable_slot > roots.latest_slot {
        return Err(ClientError::InvalidEncoding(
            "GlobalRootHistory stable_slot exceeds latest_slot",
        ));
    }
    if roots.stable_epoch_id != roots.stable_slot / roots.epoch_interval {
        return Err(ClientError::InvalidEncoding(
            "GlobalRootHistory stable_epoch_id mismatch",
        ));
    }
    for l in 0..NUM_LANES {
        let lc = roots.latest_lane_counts[l];
        let sc = roots.stable_lane_counts[l];
        if lc > MAX_LEAVES_PER_LANE || sc > MAX_LEAVES_PER_LANE {
            return Err(ClientError::InvalidEncoding(
                "GlobalRootHistory lane count exceeds MAX_LEAVES_PER_LANE",
            ));
        }
        if sc > lc {
            return Err(ClientError::InvalidEncoding(
                "GlobalRootHistory stable_lane_count exceeds latest_lane_count",
            ));
        }
    }
    if roots.latest_super_root == [0u8; 32] || roots.stable_super_root == [0u8; 32] {
        return Err(ClientError::InvalidEncoding(
            "GlobalRootHistory super_root must not be all-zero",
        ));
    }
    let latest_entry = roots.latest_entry();
    if latest_entry.super_root != roots.latest_super_root {
        return Err(ClientError::InvalidEncoding(
            "GlobalRootHistory slot_ring cursor super_root mismatch",
        ));
    }
    if latest_entry.slot != roots.latest_slot {
        return Err(ClientError::InvalidEncoding(
            "GlobalRootHistory slot_ring cursor slot mismatch",
        ));
    }
    let stable_entry = roots.stable_entry();
    if stable_entry.super_root != roots.stable_super_root {
        return Err(ClientError::InvalidEncoding(
            "GlobalRootHistory epoch_ring cursor super_root mismatch",
        ));
    }
    if stable_entry.slot != roots.stable_slot {
        return Err(ClientError::InvalidEncoding(
            "GlobalRootHistory epoch_ring cursor slot mismatch",
        ));
    }
    verify_root_snapshot_integrity(&roots.latest_super_root, &roots.latest_lane_roots)?;
    verify_root_snapshot_integrity(&roots.stable_super_root, &roots.stable_lane_roots)?;
    for l in 0..NUM_LANES {
        let lc = roots.latest_lane_counts[l];
        let sc = roots.stable_lane_counts[l];
        let latest_is_zero = roots.latest_lane_roots[l] == ZERO_HASHES_4ARY[LANE_DEPTH_4ARY];
        let stable_is_zero = roots.stable_lane_roots[l] == ZERO_HASHES_4ARY[LANE_DEPTH_4ARY];
        if (lc == 0) != latest_is_zero {
            return Err(ClientError::InvalidEncoding(
                "GlobalRootHistory latest_lane_root equals ZERO_HASHES_4ARY[18] iff count is 0",
            ));
        }
        if (sc == 0) != stable_is_zero {
            return Err(ClientError::InvalidEncoding(
                "GlobalRootHistory stable_lane_root equals ZERO_HASHES_4ARY[18] iff count is 0",
            ));
        }
        if (sc == lc) != (roots.stable_lane_roots[l] == roots.latest_lane_roots[l]) {
            return Err(ClientError::InvalidEncoding(
                "GlobalRootHistory stable_lane_root equals latest_lane_root iff counts match",
            ));
        }
    }
    Ok(())
}

/// Strictly validate a [`RootSnapshotChoice`]: ring kind/index bounds, non-zero canonical BN254
/// `Fr` super-root & lane roots, `compute_super_root_4ary(lane_roots) == super_root`, lane counts
/// `<= MAX_LEAVES_PER_LANE`, and `lane_counts[l] == 0 <=> lane_roots[l] == ZERO_HASHES_4ARY[18]`.
pub fn validate_root_snapshot_choice(snapshot: &RootSnapshotChoice) -> Result<(), ClientError> {
    validate_root_ring(snapshot.ring_kind, snapshot.ring_idx)?;
    if snapshot.super_root == [0u8; 32] {
        return Err(ClientError::InvalidEncoding(
            "RootSnapshotChoice super_root must not be all-zero",
        ));
    }
    if snapshot
        .lane_counts
        .iter()
        .any(|&c| c > MAX_LEAVES_PER_LANE)
    {
        return Err(ClientError::InvalidEncoding(
            "RootSnapshotChoice lane count exceeds MAX_LEAVES_PER_LANE",
        ));
    }
    verify_root_snapshot_integrity(&snapshot.super_root, &snapshot.lane_roots)?;
    for l in 0..NUM_LANES {
        let is_zero = snapshot.lane_roots[l] == ZERO_HASHES_4ARY[LANE_DEPTH_4ARY];
        if (snapshot.lane_counts[l] == 0) != is_zero {
            return Err(ClientError::InvalidEncoding(
                "RootSnapshotChoice lane_root equals ZERO_HASHES_4ARY[18] iff count is 0",
            ));
        }
    }
    Ok(())
}

/// Verify that `super_root` is non-zero and canonical BN254 `Fr`, all 16 `lane_roots` are canonical
/// BN254 `Fr`, and `compute_super_root_4ary(&lane_roots_fr) == super_root`.
pub fn verify_root_snapshot_integrity(
    super_root: &[u8; 32],
    lane_roots: &[[u8; 32]; NUM_LANES],
) -> Result<(), ClientError> {
    if *super_root == [0u8; 32] {
        return Err(ClientError::InvalidEncoding(
            "GlobalRootHistory super_root must not be all-zero",
        ));
    }
    let sr_fr = fr_from_be_bytes_strict(super_root).ok_or(ClientError::InvalidFieldElement)?;
    let mut lr_fr = [Fr::from(0u64); NUM_LANES];
    for (dst, src) in lr_fr.iter_mut().zip(lane_roots.iter()) {
        *dst = fr_from_be_bytes_strict(src).ok_or(ClientError::InvalidFieldElement)?;
    }
    if compute_super_root_4ary(&lr_fr) != sr_fr {
        return Err(ClientError::WitnessNotFound(
            "reconstructed Merkle super_root mismatch",
        ));
    }
    Ok(())
}

/// Fetch and validate `GlobalRootHistory` (`10,216 B`) with a `finalized`-first + `confirmed`-upgrade
/// strategy:
/// - Returns `finalized` immediately ONLY when `choice.ring_kind == ROOT_RING_EPOCH` (maximizing
///   reorg safety and 10-minute epoch proving stability).
/// - When `finalized` yields `ROOT_RING_SLOT` (not yet covered by `finalized`'s `stable` epoch
///   ring), fetches and strictly validates `confirmed` to upgrade to `ROOT_RING_EPOCH` or a newer /
///   un-evicted `ROOT_RING_SLOT` entry, returning `finalized` only if the same live slot entry is
///   still intact in `confirmed` (or `confirmed` is missing/older).
/// - Falls back to `fetch_confirmed` when a freshly deposited/created note is not yet included in
///   the `finalized` snapshot, enabling instant 0-slot spendability.
/// - Never falls back to `confirmed` if `finalized` bytes exist and fail decode/validation.
pub fn fetch_root_history<FF, FC>(
    mut fetch_finalized: FF,
    mut fetch_confirmed: FC,
    program_id: &Address,
    pool_id: u32,
    required_notes: &[(u8, u64)],
) -> Result<(GlobalRootHistory, RootSnapshotChoice), ClientError>
where
    FF: FnMut(&Address) -> Option<Vec<u8>>,
    FC: FnMut(&Address) -> Option<Vec<u8>>,
{
    for &(lane_id, _) in required_notes {
        if (lane_id as usize) >= NUM_LANES {
            return Err(ClientError::InvalidEncoding("lane_id out of range"));
        }
    }
    let (roots_pda, _) = derive_roots_pda(program_id, pool_id);
    let mut finalized_roots: Option<GlobalRootHistory> = None;
    let mut finalized_slot_choice: Option<RootSnapshotChoice> = None;
    if let Some(raw_finalized) = fetch_finalized(&roots_pda) {
        let roots = decode_global_root_history(&raw_finalized)?;
        validate_global_root_history(&roots, pool_id)?;
        if let Some(choice) = roots.select_snapshot_for_notes(required_notes) {
            if choice.ring_kind == ROOT_RING_EPOCH {
                return Ok((roots, choice));
            }
            finalized_slot_choice = Some(choice);
        }
        finalized_roots = Some(roots);
    }
    if let Some(raw_confirmed) = fetch_confirmed(&roots_pda) {
        let confirmed_roots = decode_global_root_history(&raw_confirmed)?;
        validate_global_root_history(&confirmed_roots, pool_id)?;
        if let Some(confirmed_choice) = confirmed_roots.select_snapshot_for_notes(required_notes) {
            if let Some(fin_roots) = finalized_roots {
                let confirmed_not_behind = confirmed_roots.epoch_interval
                    == fin_roots.epoch_interval
                    && confirmed_roots.latest_slot >= fin_roots.latest_slot
                    && confirmed_roots.stable_slot >= fin_roots.stable_slot
                    && (0..NUM_LANES).all(|l| {
                        let clc = confirmed_roots.latest_lane_counts[l];
                        let flc = fin_roots.latest_lane_counts[l];
                        let csc = confirmed_roots.stable_lane_counts[l];
                        let fsc = fin_roots.stable_lane_counts[l];
                        let clr = confirmed_roots.latest_lane_roots[l];
                        let flr = fin_roots.latest_lane_roots[l];
                        let csr = confirmed_roots.stable_lane_roots[l];
                        let fsr = fin_roots.stable_lane_roots[l];
                        clc >= flc
                            && csc >= fsc
                            && (clc != flc || clr == flr)
                            && (csc != fsc || csr == fsr)
                            && (csc != flc || csr == flr)
                            && (clc != fsc || clr == fsr)
                    });
                if let Some(fin_choice) = finalized_slot_choice {
                    let confirmed_strictly_ahead = confirmed_roots.latest_slot
                        > fin_roots.latest_slot
                        || (0..NUM_LANES).any(|l| {
                            confirmed_roots.latest_lane_counts[l] > fin_roots.latest_lane_counts[l]
                        });
                    let upgrade_to_confirmed = confirmed_not_behind
                        && confirmed_strictly_ahead
                        && (confirmed_choice.ring_kind == ROOT_RING_EPOCH
                            || (confirmed_choice.ring_kind == ROOT_RING_SLOT
                                && (confirmed_choice.slot > fin_choice.slot
                                    || confirmed_choice.ring_idx != fin_choice.ring_idx
                                    || confirmed_roots.slot_ring[fin_choice.ring_idx as usize]
                                        .super_root
                                        != fin_choice.super_root)));
                    return if upgrade_to_confirmed {
                        Ok((confirmed_roots, confirmed_choice))
                    } else {
                        Ok((fin_roots, fin_choice))
                    };
                }
                if !confirmed_not_behind {
                    return Err(ClientError::InvalidEncoding(
                        "confirmed GlobalRootHistory lags behind finalized snapshot",
                    ));
                }
            }
            return Ok((confirmed_roots, confirmed_choice));
        }
        if let (Some(fin_roots), Some(fin_choice)) = (finalized_roots, finalized_slot_choice) {
            return Ok((fin_roots, fin_choice));
        }
        return Err(ClientError::WitnessNotFound(
            "note not yet included in GlobalRootHistory",
        ));
    }
    if let (Some(fin_roots), Some(fin_choice)) = (finalized_roots, finalized_slot_choice) {
        return Ok((fin_roots, fin_choice));
    }
    Err(ClientError::WitnessNotFound(
        "GlobalRootHistory account missing",
    ))
}

/// Reconstruct an exact historical 4-ary Depth-20 `MerklePath4Ary` witness for `(lane_id, leaf_idx)`
/// against `GlobalRootHistory` using default `SyncPrivacyMode::Strict` padding over a single-account
/// fetcher closure with a mandatory wallet `view_sk` (preventing retry intersection).
///
/// Returns `(witness, root_ring_kind, root_ring_idx, super_root)`.
pub fn reconstruct_witness_with<F>(
    get_account_data: F,
    program_id: &Address,
    pool_id: u32,
    lane_id: u8,
    leaf_idx: u64,
    view_sk: [u8; 32],
) -> Result<(MerklePath4Ary, u8, u8, Fr), ClientError>
where
    F: FnMut(&Address) -> Option<Vec<u8>>,
{
    reconstruct_witness_with_options(
        get_account_data,
        program_id,
        pool_id,
        lane_id,
        leaf_idx,
        WitnessOptions {
            privacy_mode: SyncPrivacyMode::Strict,
            view_sk: Some(view_sk),
            decoy_epoch_bucket: None,
        },
    )
}

/// Reconstruct an exact historical 4-ary Depth-20 `MerklePath4Ary` witness over a single-account
/// fetcher closure with explicit [`WitnessOptions`].
pub fn reconstruct_witness_with_options<F>(
    mut get_account_data: F,
    program_id: &Address,
    pool_id: u32,
    lane_id: u8,
    leaf_idx: u64,
    options: WitnessOptions,
) -> Result<(MerklePath4Ary, u8, u8, Fr), ClientError>
where
    F: FnMut(&Address) -> Option<Vec<u8>>,
{
    reconstruct_witness_with_batch(
        |addrs, _slice| addrs.iter().map(&mut get_account_data).collect(),
        program_id,
        pool_id,
        lane_id,
        leaf_idx,
        options,
    )
}

/// Reconstruct an exact historical 4-ary Depth-20 `MerklePath4Ary` witness in `SyncPrivacyMode::Strict`
/// over a batched `getMultipleAccounts` fetcher against `GlobalRootHistory`.
pub fn reconstruct_witness_strict<F>(
    fetch_batch: F,
    program_id: &Address,
    pool_id: u32,
    lane_id: u8,
    leaf_idx: u64,
    view_sk: [u8; 32],
) -> Result<(MerklePath4Ary, u8, u8, Fr), ClientError>
where
    F: FnMut(&[Address], Option<AccountDataSlice>) -> Vec<Option<Vec<u8>>>,
{
    reconstruct_witness_with_batch(
        fetch_batch,
        program_id,
        pool_id,
        lane_id,
        leaf_idx,
        WitnessOptions {
            privacy_mode: SyncPrivacyMode::Strict,
            view_sk: Some(view_sk),
            decoy_epoch_bucket: None,
        },
    )
}

/// Reconstruct an exact historical 4-ary Depth-20 `MerklePath4Ary` witness for `(lane_id, leaf_idx)`
/// against `GlobalRootHistory` via a batched `getMultipleAccounts` fetcher.
///
/// Returns `(witness, root_ring_kind, root_ring_idx, super_root)`.
pub fn reconstruct_witness_with_batch<F>(
    fetch_batch: F,
    program_id: &Address,
    pool_id: u32,
    lane_id: u8,
    leaf_idx: u64,
    options: WitnessOptions,
) -> Result<(MerklePath4Ary, u8, u8, Fr), ClientError>
where
    F: FnMut(&[Address], Option<AccountDataSlice>) -> Vec<Option<Vec<u8>>>,
{
    let (mut paths, ring_kind, ring_idx, super_root) = reconstruct_witness_for_notes_with_batch(
        fetch_batch,
        program_id,
        pool_id,
        &[(lane_id, leaf_idx)],
        options,
    )?;
    let path = paths
        .pop()
        .ok_or(ClientError::WitnessNotFound("witness missing"))?;
    Ok((path, ring_kind, ring_idx, super_root))
}

/// Reconstruct shared historical 4-ary Depth-20 witnesses for 1, 2, or multi-note batches against
/// ONE `GlobalRootHistory` snapshot over a single-account fetcher closure.
pub fn reconstruct_witness_for_notes<F>(
    mut get_account_data: F,
    program_id: &Address,
    pool_id: u32,
    notes: &[(u8, u64)],
    options: WitnessOptions,
) -> Result<(Vec<MerklePath4Ary>, u8, u8, Fr), ClientError>
where
    F: FnMut(&Address) -> Option<Vec<u8>>,
{
    reconstruct_witness_for_notes_with_batch(
        |addrs, _slice| addrs.iter().map(&mut get_account_data).collect(),
        program_id,
        pool_id,
        notes,
        options,
    )
}

/// Reconstruct shared historical 4-ary Depth-20 witnesses for 1, 2, or multi-note batches against
/// `GlobalRootHistory` via a batched `getMultipleAccounts` fetcher.
///
/// Selects ONE shared `RootSnapshotChoice` covering ALL `notes` (preferring `stable` `epoch_ring`
/// when all notes are covered, falling back to `latest` `slot_ring` when any note is newer than
/// `stable_epoch`) so every note in a 2-input JoinSplit or batched merge proves against the exact
/// same root!
pub fn reconstruct_witness_for_notes_with_batch<F>(
    mut fetch_batch: F,
    program_id: &Address,
    pool_id: u32,
    notes: &[(u8, u64)],
    options: WitnessOptions,
) -> Result<(Vec<MerklePath4Ary>, u8, u8, Fr), ClientError>
where
    F: FnMut(&[Address], Option<AccountDataSlice>) -> Vec<Option<Vec<u8>>>,
{
    if notes.is_empty() {
        return Err(ClientError::InvalidEncoding("notes slice must not be empty"));
    }
    for &(lane_id, _) in notes {
        if (lane_id as usize) >= NUM_LANES {
            return Err(ClientError::InvalidEncoding("lane_id out of range"));
        }
    }
    if options.privacy_mode == SyncPrivacyMode::Strict && options.view_sk.is_none() {
        return Err(ClientError::InvalidEncoding(
            "view_sk is required in SyncPrivacyMode::Strict",
        ));
    }

    let (roots_pda, _) = derive_roots_pda(program_id, pool_id);
    let roots_data = fetch_batch(&[roots_pda], None)
        .into_iter()
        .next()
        .flatten()
        .ok_or(ClientError::WitnessNotFound("GlobalRootHistory account missing"))?;
    let roots = decode_global_root_history(&roots_data)?;
    validate_global_root_history(&roots, pool_id)?;
    let snapshot = roots
        .select_snapshot_for_notes(notes)
        .ok_or(ClientError::WitnessNotFound(
            "note not yet included in GlobalRootHistory",
        ))?;

    reconstruct_witness_for_notes_with_snapshot_batch(
        fetch_batch,
        program_id,
        pool_id,
        &snapshot,
        notes,
        options,
    )
}

/// Core stateless witness reconstruction against an already-fetched & validated [`RootSnapshotChoice`].
///
/// In default `SyncPrivacyMode::Strict` mode:
/// - Requires a 32-byte `view_sk` (preventing fresh-key retry intersection).
/// - Fetches ALL active lanes' `SubtreeRootPage`s uniformly (never capped by `needed_sr_pages`).
/// - Fetches ALL active lanes' unsealed frontier `SubtreePage`s uniformly (zero `lane_id` leak).
/// - Fetches `min(16 * buckets, total_sealed)` sealed `SubtreePage`s via Rendezvous (HRW) hashing
///   scoped to `("witness" || lane_id || target_page_seq_le8, epoch_bucket=0)` matching TypeScript
///   `reconstructWitness` bit-for-bit.
/// - Shuffles the combined batch, fetches in `RPC_BATCH_CHUNK` (100) chunks, and uniformly
///   validates EVERY fetched page (both target and decoy/non-target lanes) for presence, header,
///   count, strict canonical BN254 `Fr` on ALL `0..cnt` entries, sealed subtree root parity, and
///   all-16-lane Merkle root rollup parity against `snapshot.lane_roots` and `snapshot.super_root`.
/// - Verifies `path.compute_root(target_leaf) == super_root` for every note before returning.
pub fn reconstruct_witness_for_notes_with_snapshot_batch<F>(
    mut fetch_batch: F,
    program_id: &Address,
    pool_id: u32,
    snapshot: &RootSnapshotChoice,
    notes: &[(u8, u64)],
    options: WitnessOptions,
) -> Result<(Vec<MerklePath4Ary>, u8, u8, Fr), ClientError>
where
    F: FnMut(&[Address], Option<AccountDataSlice>) -> Vec<Option<Vec<u8>>>,
{
    if notes.is_empty() {
        return Err(ClientError::InvalidEncoding("notes slice must not be empty"));
    }
    validate_root_snapshot_choice(snapshot)?;
    for &(lane_id, _) in notes {
        if (lane_id as usize) >= NUM_LANES {
            return Err(ClientError::InvalidEncoding("lane_id out of range"));
        }
    }
    let strict_view_sk = if options.privacy_mode == SyncPrivacyMode::Strict {
        Some(options.view_sk.ok_or(ClientError::InvalidEncoding(
            "view_sk is required in SyncPrivacyMode::Strict",
        ))?)
    } else {
        None
    };

    for &(lane_id, leaf_idx) in notes {
        if leaf_idx >= snapshot.lane_counts[lane_id as usize] {
            return Err(ClientError::WitnessNotFound(
                "leaf_idx >= snapshot lane count",
            ));
        }
    }

    let mut lane_roots_fr = [Fr::from(0u64); NUM_LANES];
    for (dst, src) in lane_roots_fr.iter_mut().zip(snapshot.lane_roots.iter()) {
        *dst = fr_from_be_bytes_strict(src).ok_or(ClientError::InvalidFieldElement)?;
    }
    let super_root =
        fr_from_be_bytes_strict(&snapshot.super_root).ok_or(ClientError::InvalidFieldElement)?;
    if compute_super_root_4ary(&lane_roots_fr) != super_root {
        return Err(ClientError::WitnessNotFound(
            "reconstructed Merkle root mismatch",
        ));
    }

    let sub_size = SUBTREE_LEAVES as u64;
    let sr_size = SUBROOTS_PER_PAGE as u64;

    if strict_view_sk.is_some() {
        let mut total_sr_pages = 0u64;
        let mut total_sealed_bound = 0u64;
        for &cnt in &snapshot.lane_counts {
            let lane_sealed = cnt / sub_size;
            total_sealed_bound = total_sealed_bound.saturating_add(lane_sealed);
            total_sr_pages = total_sr_pages.saturating_add(lane_sealed.div_ceil(sr_size));
        }
        if total_sr_pages > MAX_WITNESS_SR_PAGES as u64
            || total_sealed_bound > MAX_HRW_SEALED_SUBTREES
        {
            return Err(ClientError::InvalidEncoding(
                "root snapshot lane counts exceed strict witness operational bound",
            ));
        }
    }

    let mut sr_expected: BTreeMap<Address, (u8, u64, usize)> = BTreeMap::new();
    let mut sub_expected: BTreeMap<Address, (u8, u64, usize)> = BTreeMap::new();
    let mut target_sr_pages_bound = 0u64;
    let mut seen_target_lanes: BTreeSet<u8> = BTreeSet::new();

    for &(lane_id, leaf_idx) in notes {
        let cnt = snapshot.lane_counts[lane_id as usize];
        let target_page_idx = leaf_idx / sub_size;
        let frontier_page_idx = cnt / sub_size;
        let frontier_rem = (cnt % sub_size) as usize;

        if seen_target_lanes.insert(lane_id) {
            let needed_sr_pages_u64 = frontier_page_idx.div_ceil(sr_size);
            target_sr_pages_bound = target_sr_pages_bound.saturating_add(needed_sr_pages_u64);
            if target_sr_pages_bound > MAX_WITNESS_SR_PAGES as u64 {
                return Err(ClientError::InvalidEncoding(
                    "root snapshot lane count exceeds witness operational bound",
                ));
            }
            for rp in 0..(needed_sr_pages_u64 as usize) {
                let rp_u64 = rp as u64;
                let exp_min = (frontier_page_idx - rp_u64 * sr_size).min(sr_size) as usize;
                let (sr_pda, _) = derive_subroot_pda(program_id, pool_id, lane_id, rp_u64);
                sr_expected.entry(sr_pda).or_insert((lane_id, rp_u64, exp_min));
            }
        }

        let (target_sub_addr, _) =
            derive_subtree_pda(program_id, pool_id, lane_id, target_page_idx);
        let target_expected_min = if target_page_idx < frontier_page_idx {
            SUBTREE_LEAVES
        } else {
            frontier_rem
        };
        sub_expected
            .entry(target_sub_addr)
            .and_modify(|e| e.2 = e.2.max(target_expected_min))
            .or_insert((lane_id, target_page_idx, target_expected_min));

        if frontier_rem > 0 && frontier_page_idx != target_page_idx {
            let (f_addr, _) = derive_subtree_pda(program_id, pool_id, lane_id, frontier_page_idx);
            sub_expected
                .entry(f_addr)
                .and_modify(|e| e.2 = e.2.max(frontier_rem))
                .or_insert((lane_id, frontier_page_idx, frontier_rem));
        }
    }

    if let Some(key) = strict_view_sk {
        let mut sealed_by_lane = Vec::with_capacity(NUM_LANES);
        let mut already_sealed: BTreeSet<(u8, u64)> = BTreeSet::new();
        for &(lane_id, leaf_idx) in notes {
            let frontier_page_idx = snapshot.lane_counts[lane_id as usize] / sub_size;
            let target_page_idx = leaf_idx / sub_size;
            if target_page_idx < frontier_page_idx {
                already_sealed.insert((lane_id, target_page_idx));
            }
        }
        let mut total_sealed = 0u64;

        for lane_idx in 0..NUM_LANES {
            let lid = lane_idx as u8;
            let cnt = snapshot.lane_counts[lane_idx];
            let lane_sealed = cnt / sub_size;
            let lane_frontier_rem = (cnt % sub_size) as usize;
            sealed_by_lane.push((lid, lane_sealed));
            total_sealed = total_sealed.saturating_add(lane_sealed);

            if lane_sealed > 0 {
                let lane_sr_pages = lane_sealed.div_ceil(sr_size) as usize;
                for rp in 0..lane_sr_pages {
                    let rp_u64 = rp as u64;
                    let exp_min = (lane_sealed - rp_u64 * sr_size).min(sr_size) as usize;
                    sr_expected
                        .entry(derive_subroot_pda(program_id, pool_id, lid, rp_u64).0)
                        .or_insert((lid, rp_u64, exp_min));
                }
            }
            if lane_frontier_rem > 0 {
                sub_expected
                    .entry(derive_subtree_pda(program_id, pool_id, lid, lane_sealed).0)
                    .or_insert((lid, lane_sealed, lane_frontier_rem));
            }
        }

        if total_sealed > 0 {
            let buckets = already_sealed
                .len()
                .max(1)
                .div_ceil(STRICT_DECOY_SEALED_SUBTREE_TARGET);
            let target_sealed = ((buckets as u64)
                .saturating_mul(STRICT_DECOY_SEALED_SUBTREE_TARGET as u64))
            .min(total_sealed) as usize;
            let epoch_bucket = options.decoy_epoch_bucket.unwrap_or(0);
            let scope = make_witness_decoy_scope(notes[0].0, notes[0].1 / sub_size);
            let decoys = try_select_hrw_sealed_decoys(
                &key,
                &scope,
                epoch_bucket,
                &sealed_by_lane,
                &already_sealed,
                target_sealed,
            )?;
            for (d_lane, d_seq) in decoys {
                sub_expected
                    .entry(derive_subtree_pda(program_id, pool_id, d_lane, d_seq).0)
                    .or_insert((d_lane, d_seq, SUBTREE_LEAVES));
            }
        }
    }

    let mut addrs: Vec<Address> = sr_expected
        .keys()
        .copied()
        .chain(sub_expected.keys().copied())
        .collect();
    if addrs.len() > 1 {
        shuffle_in_place(&mut addrs);
    }

    let mut raw_by_addr: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
    for chunk in addrs.chunks(RPC_BATCH_CHUNK) {
        let raws = fetch_batch(chunk, None);
        for (i, &addr) in chunk.iter().enumerate() {
            if let Some(raw) = raws.get(i).and_then(|o| o.as_ref()) {
                raw_by_addr.insert(addr, raw.clone());
            }
        }
    }

    // Privacy & integrity invariant (R1-C1 + R2-C2): uniformly validate EVERY requested page
    // (both target AND decoy/non-target lanes in Strict mode) for presence, header, count,
    // strict canonical BN254 Fr on ALL `0..cnt` entries, sealed subtree root parity, and
    // per-lane Merkle root parity against `snapshot.lane_roots` before extracting target witnesses.
    let mut decoded_sr_fr_by_key: BTreeMap<(u8, u64), Vec<Fr>> = BTreeMap::new();
    let mut decoded_sub_fr_by_key: BTreeMap<(u8, u64), Vec<Fr>> = BTreeMap::new();
    for addr in &addrs {
        if let Some(&(exp_lane, exp_seq, exp_min)) = sr_expected.get(addr) {
            let sr_data = raw_by_addr
                .get(addr)
                .ok_or(ClientError::WitnessNotFound("SubtreeRootPage missing"))?;
            if sr_data.len() != SUBROOT_PAGE_LEN || sr_data[0..8] != SUBROOT_MAGIC {
                return Err(ClientError::InvalidEncoding("invalid SubtreeRootPage"));
            }
            if read_u32(sr_data, SR_OFF_POOL_ID) != pool_id
                || sr_data[SR_OFF_LANE_ID] != exp_lane
                || read_u64(sr_data, SR_OFF_ROOT_PAGE_SEQ) != exp_seq
            {
                return Err(ClientError::InvalidEncoding("SubtreeRootPage header mismatch"));
            }
            let cnt = read_u16(sr_data, SR_OFF_COUNT) as usize;
            if cnt > SUBROOTS_PER_PAGE {
                return Err(ClientError::InvalidEncoding(
                    "SubtreeRootPage count exceeds capacity",
                ));
            }
            if cnt < exp_min {
                return Err(ClientError::WitnessNotFound("SubtreeRootPage truncated"));
            }
            let mut roots_fr = Vec::with_capacity(cnt);
            for j in 0..cnt {
                let b = read_32(sr_data, SR_OFF_ROOTS + j * 32);
                roots_fr.push(
                    fr_from_be_bytes_strict(&b).ok_or(ClientError::InvalidFieldElement)?,
                );
            }
            decoded_sr_fr_by_key.insert((exp_lane, exp_seq), roots_fr);
        } else if let Some(&(exp_lane, exp_seq, exp_min)) = sub_expected.get(addr) {
            let sub_data = raw_by_addr
                .get(addr)
                .ok_or(ClientError::WitnessNotFound("SubtreePage missing"))?;
            if sub_data.len() != SUBTREE_PAGE_LEN || sub_data[0..8] != SUBTREE_MAGIC {
                return Err(ClientError::InvalidEncoding("invalid SubtreePage"));
            }
            if read_u32(sub_data, SB_OFF_POOL_ID) != pool_id
                || sub_data[SB_OFF_LANE_ID] != exp_lane
                || read_u64(sub_data, SB_OFF_PAGE_SEQ) != exp_seq
            {
                return Err(ClientError::InvalidEncoding("SubtreePage header mismatch"));
            }
            let cnt = read_u16(sub_data, SB_OFF_COUNT) as usize;
            if cnt > SUBTREE_LEAVES {
                return Err(ClientError::InvalidEncoding(
                    "SubtreePage count exceeds capacity",
                ));
            }
            if cnt < exp_min {
                return Err(ClientError::WitnessNotFound("SubtreePage truncated"));
            }
            let mut leaves_fr = Vec::with_capacity(cnt);
            for i in 0..cnt {
                let b = read_32(sub_data, SB_OFF_LEAVES + i * 32);
                leaves_fr
                    .push(fr_from_be_bytes_strict(&b).ok_or(ClientError::InvalidFieldElement)?);
            }
            decoded_sub_fr_by_key.insert((exp_lane, exp_seq), leaves_fr);
        }
    }

    if strict_view_sk.is_some() {
        // (b) Verify EVERY fetched sealed SubtreePage (target AND decoy) against its SubtreeRootPage entry.
        for &(exp_lane, exp_seq, _) in sub_expected.values() {
            let lane_sealed = snapshot.lane_counts[exp_lane as usize] / sub_size;
            if exp_seq < lane_sealed {
                let leaves_fr = decoded_sub_fr_by_key
                    .get(&(exp_lane, exp_seq))
                    .ok_or(ClientError::WitnessNotFound(
                        "reconstructed Merkle root mismatch",
                    ))?;
                let sr_seq = exp_seq / sr_size;
                let sr_slot = (exp_seq % sr_size) as usize;
                let sr_roots_fr = decoded_sr_fr_by_key
                    .get(&(exp_lane, sr_seq))
                    .ok_or(ClientError::WitnessNotFound(
                        "reconstructed Merkle root mismatch",
                    ))?;
                if leaves_fr.len() < SUBTREE_LEAVES || sr_slot >= sr_roots_fr.len() {
                    return Err(ClientError::WitnessNotFound(
                        "reconstructed Merkle root mismatch",
                    ));
                }
                if compute_subtree_256_root(leaves_fr, SUBTREE_LEAVES) != sr_roots_fr[sr_slot] {
                    return Err(ClientError::WitnessNotFound(
                        "reconstructed Merkle root mismatch",
                    ));
                }
            }
        }

        // (c) Verify EVERY lane's rolled-up root (all 16 lanes) matches `snapshot.lane_roots[lane_idx]`.
        let zeros = zero_hashes_4ary();
        for (lane_idx, &expected_lane_root) in lane_roots_fr.iter().enumerate() {
            let lid = lane_idx as u8;
            let cnt = snapshot.lane_counts[lane_idx];
            if cnt == 0 {
                if expected_lane_root != zeros[LANE_DEPTH_4ARY] {
                    return Err(ClientError::WitnessNotFound(
                        "reconstructed Merkle root mismatch",
                    ));
                }
                continue;
            }
            let lane_sealed = cnt / sub_size;
            let lane_frontier_rem = (cnt % sub_size) as usize;
            let lane_sr_pages = lane_sealed.div_ceil(sr_size) as usize;
            let mut lane_finalized = Vec::with_capacity(lane_sealed as usize);
            for rp in 0..lane_sr_pages {
                let sr_roots_fr = decoded_sr_fr_by_key
                    .get(&(lid, rp as u64))
                    .ok_or(ClientError::WitnessNotFound("SubtreeRootPage missing"))?;
                for &r in sr_roots_fr {
                    if lane_finalized.len() == lane_sealed as usize {
                        break;
                    }
                    lane_finalized.push(r);
                }
            }
            if lane_finalized.len() != lane_sealed as usize {
                return Err(ClientError::WitnessNotFound(
                    "SubtreeRootPage missing finalized roots",
                ));
            }
            let lane_frontier = if lane_frontier_rem > 0 {
                Some(
                    decoded_sub_fr_by_key
                        .get(&(lid, lane_sealed))
                        .ok_or(ClientError::WitnessNotFound("Frontier SubtreePage missing"))?
                        .as_slice(),
                )
            } else {
                None
            };
            let computed_lane_root = compute_lane_root_from_subroots_and_frontier(
                &lane_finalized,
                lane_frontier,
                lane_frontier_rem,
            )?;
            if computed_lane_root != expected_lane_root {
                return Err(ClientError::WitnessNotFound(
                    "reconstructed Merkle root mismatch",
                ));
            }
        }
    }

    let mut paths = Vec::with_capacity(notes.len());
    for &(lane_id, leaf_idx) in notes {
        let l = lane_id as usize;
        let cnt = snapshot.lane_counts[l];
        let target_page_idx = leaf_idx / sub_size;
        let target_offset = (leaf_idx % sub_size) as usize;
        let frontier_page_idx = cnt / sub_size;
        let frontier_rem = (cnt % sub_size) as usize;
        let needed_sr_pages = frontier_page_idx.div_ceil(sr_size) as usize;

        let mut finalized_roots = Vec::with_capacity(frontier_page_idx as usize);
        for rp in 0..needed_sr_pages {
            let sr_roots_fr = decoded_sr_fr_by_key
                .get(&(lane_id, rp as u64))
                .ok_or(ClientError::WitnessNotFound("SubtreeRootPage missing"))?;
            for &r in sr_roots_fr {
                if finalized_roots.len() == frontier_page_idx as usize {
                    break;
                }
                finalized_roots.push(r);
            }
        }
        if finalized_roots.len() != frontier_page_idx as usize {
            return Err(ClientError::WitnessNotFound(
                "SubtreeRootPage missing finalized roots",
            ));
        }

        let target_leaves = decoded_sub_fr_by_key
            .get(&(lane_id, target_page_idx))
            .ok_or(ClientError::WitnessNotFound("SubtreePage missing"))?;
        let target_expected_min = if target_page_idx < frontier_page_idx {
            SUBTREE_LEAVES
        } else {
            frontier_rem
        };
        if target_expected_min > SUBTREE_LEAVES
            || target_offset >= target_expected_min
            || target_leaves.len() < target_expected_min
        {
            return Err(ClientError::WitnessNotFound("SubtreePage truncated"));
        }
        let frontier_leaves = if frontier_rem > 0 {
            let fl = decoded_sub_fr_by_key
                .get(&(lane_id, frontier_page_idx))
                .ok_or(ClientError::WitnessNotFound("SubtreePage missing"))?;
            if fl.len() < frontier_rem {
                return Err(ClientError::WitnessNotFound("Frontier SubtreePage truncated"));
            }
            Some(fl.as_slice())
        } else {
            None
        };

        let path = build_historical_witness_4ary(
            l,
            leaf_idx,
            &lane_roots_fr,
            cnt,
            &finalized_roots,
            target_leaves,
            frontier_leaves,
        );
        if path.compute_root(target_leaves[target_offset]) != super_root {
            return Err(ClientError::WitnessNotFound(
                "reconstructed Merkle root mismatch",
            ));
        }
        paths.push(path);
    }

    Ok((paths, snapshot.ring_kind, snapshot.ring_idx, super_root))
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
    if pool.pool_id != pool_id {
        return Err(ClientError::InvalidEncoding("PoolState pool_id mismatch"));
    }
    let mut lanes = Vec::with_capacity(pool.active_lanes as usize);
    for l in 0..pool.active_lanes {
        let (lpda, _) = derive_lane_pda(program_id, pool_id, l);
        let ldata = get_account_data(&lpda)
            .ok_or(ClientError::WitnessNotFound("LaneTreeState missing"))?;
        let hdr = decode_lane_header(&ldata)?;
        if hdr.lane_id != l || hdr.pool_id != pool_id {
            return Err(ClientError::InvalidEncoding("LaneTreeState header mismatch"));
        }
        lanes.push(hdr);
    }
    Ok((pool, lanes))
}

fn decode_subtree_page_strict(
    data: &[u8],
    expected_pool_id: u32,
    expected_lane_id: u8,
    expected_seq: u64,
) -> Result<(Vec<[u8; 32]>, Vec<Fr>), ClientError> {
    if data.len() != SUBTREE_PAGE_LEN || data[0..8] != SUBTREE_MAGIC {
        return Err(ClientError::InvalidEncoding("invalid SubtreePage"));
    }
    if data[SB_OFF_LANE_ID] as usize >= NUM_LANES {
        return Err(ClientError::InvalidEncoding("SubtreePage lane_id out of range"));
    }
    if read_u32(data, SB_OFF_POOL_ID) != expected_pool_id
        || data[SB_OFF_LANE_ID] != expected_lane_id
        || read_u64(data, SB_OFF_PAGE_SEQ) != expected_seq
    {
        return Err(ClientError::InvalidEncoding("SubtreePage header mismatch"));
    }
    let cnt = read_u16(data, SB_OFF_COUNT) as usize;
    if cnt > SUBTREE_LEAVES {
        return Err(ClientError::InvalidEncoding(
            "SubtreePage count exceeds capacity",
        ));
    }
    let mut leaves_be = Vec::with_capacity(cnt);
    let mut leaves_fr = Vec::with_capacity(cnt);
    for i in 0..cnt {
        let b = read_32(data, SB_OFF_LEAVES + i * 32);
        let fr = fr_from_be_bytes_strict(&b).ok_or(ClientError::InvalidFieldElement)?;
        leaves_be.push(b);
        leaves_fr.push(fr);
    }
    Ok((leaves_be, leaves_fr))
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
    if store.lanes.len() != NUM_LANES {
        return Err(ClientError::InvalidEncoding(
            "store lanes length must equal NUM_LANES",
        ));
    }

    // Phase 0: PoolState + all NUM_LANES (16) LaneTreeState headers in ONE atomic 17-account
    // `getMultipleAccounts` batch (eliminates `InitLane` expansion snapshot skew and saves 1 RPC
    // round-trip on every sync).
    let (pool_pda, _) = derive_pool_pda(program_id, pool_id);
    let mut phase0_addrs = Vec::with_capacity(1 + NUM_LANES);
    phase0_addrs.push(pool_pda);
    for l in 0..NUM_LANES as u8 {
        phase0_addrs.push(derive_lane_pda(program_id, pool_id, l).0);
    }
    let phase0_raws = fetch_batch(&phase0_addrs, None);
    let pool_data = phase0_raws
        .first()
        .and_then(|o| o.as_ref())
        .ok_or(ClientError::WitnessNotFound("PoolState missing"))?;
    let pool = decode_pool_state(pool_data)?;
    if pool.pool_id != pool_id {
        return Err(ClientError::InvalidEncoding("PoolState pool_id mismatch"));
    }

    let mut lanes = Vec::with_capacity(pool.active_lanes as usize);
    for l in 0..pool.active_lanes as usize {
        let ldata = phase0_raws
            .get(1 + l)
            .and_then(|o| o.as_ref())
            .ok_or(ClientError::WitnessNotFound("LaneTreeState missing"))?;
        let hdr = decode_lane_header(ldata)?;
        if hdr.lane_id != l as u8 || hdr.pool_id != pool_id {
            return Err(ClientError::InvalidEncoding("LaneTreeState header mismatch"));
        }
        lanes.push(hdr);
    }

    let sub_size = SUBTREE_LEAVES as u64;
    let sr_size = SUBROOTS_PER_PAGE as u64;
    let memo_size = MEMO_NOTES_PER_PAGE as u64;
    let nf_size = NF_PER_PAGE as u64;

    // =========================================================================
    // PASS 1A: Fast-sync finalized level-4 subroots via `SubtreeRootPage`
    //          (lazy RPC_BATCH_CHUNK windowing, contiguous buffering, zero
    //          early store mutation, strict header & canonical-Fr validation).
    // =========================================================================
    struct SrCursor {
        lane_id: u8,
        next_sr: u64,
        end_sr: u64,
        finalized_count: u64,
        stopped: bool,
    }
    let mut sr_cursors: Vec<SrCursor> = Vec::new();
    let mut pass1a_new_subroots: BTreeMap<u8, Vec<[u8; 32]>> = BTreeMap::new();
    for lane_hdr in &lanes {
        let l = lane_hdr.lane_id as usize;
        pass1a_new_subroots.insert(lane_hdr.lane_id, Vec::new());
        let finalized_count = lane_hdr.next_leaf / sub_size;
        let existing_len = store.lanes[l].finalized_subroots.len() as u64;
        if finalized_count > existing_len {
            sr_cursors.push(SrCursor {
                lane_id: lane_hdr.lane_id,
                next_sr: existing_len / sr_size,
                end_sr: (finalized_count - 1) / sr_size,
                finalized_count,
                stopped: false,
            });
        }
    }

    let mut sr_pages_fetched = 0usize;
    while sr_pages_fetched < MAX_SYNC_PAGES_PER_CALL {
        let mut chunk: Vec<(usize, u8, u64, u64, Address)> = Vec::new();
        for (c_idx, cursor) in sr_cursors.iter_mut().enumerate() {
            while !cursor.stopped
                && cursor.next_sr <= cursor.end_sr
                && chunk.len() < RPC_BATCH_CHUNK
                && sr_pages_fetched + chunk.len() < MAX_SYNC_PAGES_PER_CALL
            {
                let rp = cursor.next_sr;
                cursor.next_sr = rp.saturating_add(1);
                chunk.push((
                    c_idx,
                    cursor.lane_id,
                    rp,
                    cursor.finalized_count,
                    derive_subroot_pda(program_id, pool_id, cursor.lane_id, rp).0,
                ));
            }
            if chunk.len() >= RPC_BATCH_CHUNK
                || sr_pages_fetched + chunk.len() >= MAX_SYNC_PAGES_PER_CALL
            {
                break;
            }
        }
        if chunk.is_empty() {
            break;
        }
        sr_pages_fetched += chunk.len();
        let addrs: Vec<Address> = chunk.iter().map(|&(_, _, _, _, a)| a).collect();
        let raws = fetch_batch(&addrs, None);
        for (i, &(c_idx, lane_id, root_page_seq, finalized_count, _)) in chunk.iter().enumerate() {
            if sr_cursors[c_idx].stopped {
                continue;
            }
            let l = lane_id as usize;
            let pass1a_buf = pass1a_new_subroots.entry(lane_id).or_default();
            let cur_len = (store.lanes[l].finalized_subroots.len() + pass1a_buf.len()) as u64;
            let base = root_page_seq
                .checked_mul(sr_size)
                .ok_or(ClientError::InvalidEncoding(
                    "SubtreeRootPage root_page_seq overflow",
                ))?;
            let expected_on_page = finalized_count.saturating_sub(base).min(sr_size) as usize;

            let Some(sr_raw) = raws.get(i).and_then(|o| o.as_ref()) else {
                sr_cursors[c_idx].stopped = true;
                continue;
            };
            if sr_raw.len() != SUBROOT_PAGE_LEN || sr_raw[0..8] != SUBROOT_MAGIC {
                return Err(ClientError::InvalidEncoding("invalid SubtreeRootPage"));
            }
            if read_u32(sr_raw, SR_OFF_POOL_ID) != pool_id
                || sr_raw[SR_OFF_LANE_ID] != lane_id
                || read_u64(sr_raw, SR_OFF_ROOT_PAGE_SEQ) != root_page_seq
            {
                return Err(ClientError::InvalidEncoding(
                    "SubtreeRootPage header mismatch",
                ));
            }
            let cnt = read_u16(sr_raw, SR_OFF_COUNT) as usize;
            if cnt > SUBROOTS_PER_PAGE {
                return Err(ClientError::InvalidEncoding(
                    "SubtreeRootPage count exceeds capacity",
                ));
            }
            for k in 0..cnt {
                let r = read_32(sr_raw, SR_OFF_ROOTS + k * 32);
                fr_from_be_bytes_strict(&r).ok_or(ClientError::InvalidFieldElement)?;
            }
            let start_in_page = cur_len.saturating_sub(base).min(sr_size) as usize;
            let avail = cnt.min(expected_on_page);
            if avail < start_in_page {
                sr_cursors[c_idx].stopped = true;
                continue;
            }
            for k in start_in_page..avail {
                pass1a_buf.push(read_32(sr_raw, SR_OFF_ROOTS + k * 32));
            }
            if cnt < expected_on_page {
                sr_cursors[c_idx].stopped = true;
            }
        }
    }

    let lookup_verified_subroot = |lane_id: u8, sub_seq: u64| -> Option<[u8; 32]> {
        let existing = &store.lanes[lane_id as usize].finalized_subroots;
        let existing_len = existing.len() as u64;
        if sub_seq < existing_len {
            return Some(existing[sub_seq as usize]);
        }
        let buf = pass1a_new_subroots.get(&lane_id)?;
        let off = usize::try_from(sub_seq - existing_len).ok()?;
        buf.get(off).copied()
    };

    // =========================================================================
    // PASS 1B: Optional `birthday_slot` binary search on `64 B` `MemoPage` headers
    //          (deferred commit so Pass 1D misses preserve zero store mutation).
    // =========================================================================
    let mut scan_start_leaf_by_lane: BTreeMap<u8, u64> = BTreeMap::new();
    for lane_hdr in &lanes {
        scan_start_leaf_by_lane.insert(
            lane_hdr.lane_id,
            store.lanes[lane_hdr.lane_id as usize].next_memo_leaf,
        );
    }
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
                .map(|&idx| bs_states[idx].lo + (bs_states[idx].hi - bs_states[idx].lo) / 2)
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
                let lane_id = bs_states[idx].lane_id;
                let skip = match raws.get(i).and_then(|o| o.as_ref()) {
                    Some(mraw) => {
                        if mraw.len() < MEMO_PAGE_HEADER_LEN || mraw[0..8] != MEMO_MAGIC {
                            return Err(ClientError::InvalidEncoding("invalid MemoPage header"));
                        }
                        if read_u32(mraw, MM_OFF_POOL_ID) != pool_id
                            || mraw[MM_OFF_LANE_ID] != lane_id
                            || read_u64(mraw, MM_OFF_PAGE_SEQ) != mid
                        {
                            return Err(ClientError::InvalidEncoding("MemoPage header mismatch"));
                        }
                        let cnt = read_u16(mraw, MM_OFF_COUNT) as usize;
                        if cnt > MEMO_NOTES_PER_PAGE {
                            return Err(ClientError::InvalidEncoding(
                                "MemoPage count exceeds capacity",
                            ));
                        }
                        let closed = read_u64(mraw, MM_OFF_CLOSED_SLOT);
                        cnt == MEMO_NOTES_PER_PAGE && closed > 0 && closed < birthday_slot
                    }
                    None => false,
                };
                if skip {
                    bs_states[idx].lo = mid + 1;
                } else {
                    bs_states[idx].hi = mid;
                }
            }
        }
        for st in &bs_states {
            if st.lo > 0 {
                let skip_to = st.lo.saturating_mul(memo_size).min(st.next_leaf);
                scan_start_leaf_by_lane.insert(st.lane_id, skip_to);
            }
        }
    }

    // Compute total new MemoPages and newly synced SubtreePages across all active lanes (post-Pass 1B)
    let mut total_new_memo_pages = 0u64;
    let mut total_new_subtrees = 0u64;
    for lane_hdr in &lanes {
        let l = lane_hdr.lane_id as usize;
        let start_leaf = *scan_start_leaf_by_lane
            .get(&lane_hdr.lane_id)
            .unwrap_or(&store.lanes[l].next_memo_leaf);
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
    // PASS 1C: Lazily stream `MemoPage`s across ALL active lanes in 100-account windows
    // =========================================================================
    struct MemoCursor {
        lane_id: u8,
        next_memo: u64,
        end_memo: u64,
        next_leaf: u64,
        stopped: bool,
    }
    let mut memo_cursors: Vec<MemoCursor> = Vec::new();
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
        memo_cursors.push(MemoCursor {
            lane_id: lane_hdr.lane_id,
            next_memo: start_leaf / memo_size,
            end_memo: (lane_hdr.next_leaf - 1) / memo_size,
            next_leaf: lane_hdr.next_leaf,
            stopped: false,
        });
    }

    let memo_slice_opt = if use_memo_data_slice {
        Some(AccountDataSlice {
            offset: 0,
            length: MEMO_PAGE_SCAN_SLICE_LEN,
        })
    } else {
        None
    };

    let mut memo_pages_fetched = 0usize;
    while memo_pages_fetched < MAX_SYNC_PAGES_PER_CALL {
        let mut chunk: Vec<(usize, u8, u64, u64, Address)> = Vec::new();
        for (c_idx, cursor) in memo_cursors.iter_mut().enumerate() {
            while !cursor.stopped
                && cursor.next_memo <= cursor.end_memo
                && chunk.len() < RPC_BATCH_CHUNK
                && memo_pages_fetched + chunk.len() < MAX_SYNC_PAGES_PER_CALL
            {
                let m = cursor.next_memo;
                cursor.next_memo = m.saturating_add(1);
                chunk.push((
                    c_idx,
                    cursor.lane_id,
                    m,
                    cursor.next_leaf,
                    derive_memo_pda(program_id, pool_id, cursor.lane_id, m).0,
                ));
            }
            if chunk.len() >= RPC_BATCH_CHUNK
                || memo_pages_fetched + chunk.len() >= MAX_SYNC_PAGES_PER_CALL
            {
                break;
            }
        }
        if chunk.is_empty() {
            break;
        }
        memo_pages_fetched += chunk.len();
        let addrs: Vec<Address> = chunk.iter().map(|&(_, _, _, _, a)| a).collect();
        let raws = fetch_batch(&addrs, memo_slice_opt);
        for (i, &(c_idx, lane_id, memo_seq, next_leaf, addr)) in chunk.iter().enumerate() {
            if memo_cursors[c_idx].stopped {
                continue;
            }
            let Some(mraw) = raws.get(i).and_then(|o| o.as_ref()) else {
                memo_cursors[c_idx].stopped = true;
                continue;
            };
            if !use_memo_data_slice {
                if mraw.len() != MEMO_PAGE_LEN || mraw[0..8] != MEMO_MAGIC {
                    return Err(ClientError::InvalidEncoding("invalid MemoPage"));
                }
            } else if mraw.len() < MEMO_PAGE_SCAN_SLICE_LEN || mraw[0..8] != MEMO_MAGIC {
                return Err(ClientError::InvalidEncoding("invalid MemoPage scan slice"));
            }
            if read_u32(mraw, MM_OFF_POOL_ID) != pool_id
                || mraw[MM_OFF_LANE_ID] != lane_id
                || read_u64(mraw, MM_OFF_PAGE_SEQ) != memo_seq
            {
                return Err(ClientError::InvalidEncoding("MemoPage header mismatch"));
            }

            let count = read_u16(mraw, MM_OFF_COUNT) as usize;
            if count > MEMO_NOTES_PER_PAGE {
                return Err(ClientError::InvalidEncoding(
                    "MemoPage count exceeds capacity",
                ));
            }
            let closed_slot = read_u64(mraw, MM_OFF_CLOSED_SLOT);
            let page_base = memo_seq * memo_size;
            let cursor_wm = *scanned_watermark_by_lane.get(&lane_id).unwrap_or(&0);
            let start_slot = cursor_wm.saturating_sub(page_base).min(memo_size) as usize;
            let max_for_snapshot = next_leaf.saturating_sub(page_base).min(memo_size) as usize;
            let limit_slot = count.min(max_for_snapshot);

            if start_slot == 0
                && birthday_slot > 0
                && count == MEMO_NOTES_PER_PAGE
                && closed_slot > 0
                && closed_slot < birthday_slot
            {
                scanned_watermark_by_lane.insert(lane_id, page_base + limit_slot as u64);
                if count < max_for_snapshot {
                    memo_cursors[c_idx].stopped = true;
                }
                continue;
            }

            let lane_hits = hits_by_lane.entry(lane_id).or_default();
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
                        memo_seq,
                        slot,
                        leaf_idx: page_base + slot as u64,
                    });
                }
            }
            if page_matched {
                let key = (lane_id, memo_seq);
                if mraw.len() == MEMO_PAGE_LEN {
                    inline_full_memos.insert(key, mraw.clone());
                } else {
                    needed_full_memos.entry(key).or_insert(addr);
                }
            }
            scanned_watermark_by_lane.insert(lane_id, page_base + limit_slot as u64);
            if count < max_for_snapshot {
                memo_cursors[c_idx].stopped = true;
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
                    if read_u32(mraw, MM_OFF_POOL_ID) != pool_id
                        || mraw[MM_OFF_LANE_ID] != key.0
                        || read_u64(mraw, MM_OFF_PAGE_SEQ) != key.1
                    {
                        return Err(ClientError::InvalidEncoding("MemoPage header mismatch"));
                    }
                    if (read_u16(mraw, MM_OFF_COUNT) as usize) > MEMO_NOTES_PER_PAGE {
                        return Err(ClientError::InvalidEncoding("MemoPage header out of range"));
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
    }

    // Rendezvous (HRW) wallet-keyed decoy padding for historical sealed `SubtreePage` fetches in
    // `Strict` mode (`SHA256(view_sk || "audren/v1/decoy" || "sync" || epoch_bucket_le8 || lane_id || page_seq_le8)`):
    // - Always fetches a fixed uniform count independent of hit count (even 0 hits) during large
    //   catch-up so RPC cannot tell whether a wallet had hits.
    // - Preserves `~(K - 1) / K` of decoys across `+1` sealed subtree growth within an epoch bucket
    //   and matches TypeScript `packages/sdk/src/scanner.ts` bit-for-bit.
    let mut finalized_by_lane: BTreeMap<u8, u64> = BTreeMap::new();
    let mut frontier_rem_by_lane: BTreeMap<u8, usize> = BTreeMap::new();
    let mut sealed_by_lane_list: Vec<(u8, u64)> = Vec::with_capacity(lanes.len());
    let mut total_sealed_subtrees = 0u64;
    for lane_hdr in &lanes {
        let fc = lane_hdr.next_leaf / sub_size;
        let frem = (lane_hdr.next_leaf % sub_size) as usize;
        finalized_by_lane.insert(lane_hdr.lane_id, fc);
        frontier_rem_by_lane.insert(lane_hdr.lane_id, frem);
        sealed_by_lane_list.push((lane_hdr.lane_id, fc));
        total_sealed_subtrees = total_sealed_subtrees.saturating_add(fc);
    }
    let epoch_bucket: u64 = options.decoy_epoch_bucket.unwrap_or(0);

    let should_decoy_pad = privacy_mode == SyncPrivacyMode::Strict
        && total_sealed_subtrees > 0
        && (has_hit_correlated_sealed_subtree
            || (!fetch_new_subtrees_uniformly && total_new_memo_pages > 0));
    if should_decoy_pad {
        if total_sealed_subtrees > MAX_HRW_SEALED_SUBTREES {
            return Err(ClientError::InvalidEncoding(
                "sealed subtree count exceeds HRW operational bound",
            ));
        }
        let current_sealed_count = needed_subtrees
            .keys()
            .filter(|&&(lid, s)| s < *finalized_by_lane.get(&lid).unwrap_or(&0))
            .count();
        let buckets = current_sealed_count
            .max(1)
            .div_ceil(STRICT_DECOY_SEALED_SUBTREE_TARGET);
        let target_sealed = ((buckets as u64)
            .saturating_mul(STRICT_DECOY_SEALED_SUBTREE_TARGET as u64))
            .min(total_sealed_subtrees) as usize;

        if current_sealed_count < target_sealed {
            let already_selected: BTreeSet<(u8, u64)> = needed_subtrees.keys().copied().collect();
            let decoys = try_select_hrw_sealed_decoys(
                &fvk.view_sk,
                DECOY_SCOPE_SYNC,
                epoch_bucket,
                &sealed_by_lane_list,
                &already_selected,
                target_sealed,
            )?;
            for (d_lane, d_seq) in decoys {
                add_needed_subtree(&mut needed_subtrees, d_lane, d_seq);
            }
        }
    }

    let mut sub_list: Vec<((u8, u64), Address)> =
        needed_subtrees.iter().map(|(&k, &v)| (k, v)).collect();
    if sub_list.len() > 1 {
        sub_list.sort_by_cached_key(|(_, addr)| {
            compute_subtree_order_key(&fvk.view_sk, DECOY_SCOPE_SYNC, epoch_bucket, addr)
        });
    }

    // Privacy & integrity invariant (R2-C1): uniformly validate EVERY fetched SubtreePage (both
    // hits AND decoys) for exact header `(pool_id, lane_id, page_seq)`, strict canonical Fr on ALL
    // `0..count` leaves, and exact Poseidon root parity against Pass 1A's verified SubtreeRootPage
    // BEFORE any store mutation and BEFORE Pass 2 executes.
    type DecodedSubtreeLeaves = (Vec<[u8; 32]>, Vec<Fr>);
    let mut fetched_subtrees: BTreeMap<(u8, u64), DecodedSubtreeLeaves> = BTreeMap::new();
    let mut any_pass1d_subtree_missing = false;
    for chunk in sub_list.chunks(RPC_BATCH_CHUNK) {
        let addrs: Vec<Address> = chunk.iter().map(|(_, a)| *a).collect();
        let raws = fetch_batch(&addrs, None);
        for (i, &(key, _)) in chunk.iter().enumerate() {
            let Some(raw) = raws.get(i).and_then(|o| o.as_ref()) else {
                any_pass1d_subtree_missing = true;
                continue;
            };
            let (leaves_be, leaves_fr) = decode_subtree_page_strict(raw, pool_id, key.0, key.1)?;
            let fc = *finalized_by_lane.get(&key.0).unwrap_or(&0);
            let expected_min_leaves = if key.1 < fc {
                SUBTREE_LEAVES
            } else {
                *frontier_rem_by_lane.get(&key.0).unwrap_or(&0)
            };
            if leaves_be.len() < expected_min_leaves {
                any_pass1d_subtree_missing = true;
                continue;
            } else if key.1 < fc {
                let Some(expected_subroot_be) = lookup_verified_subroot(key.0, key.1) else {
                    any_pass1d_subtree_missing = true;
                    continue;
                };
                let expected_subroot_fr = fr_from_be_bytes_strict(&expected_subroot_be)
                    .ok_or(ClientError::InvalidFieldElement)?;
                if compute_subtree_256_root(&leaves_fr, SUBTREE_LEAVES) != expected_subroot_fr {
                    return Err(ClientError::InvalidEncoding(
                        "SubtreePage root mismatch against SubtreeRootPage",
                    ));
                }
            }
            if key.1 >= fc {
                // Cap live-advancing frontier SubtreePage to Phase 0 `frontier_rem` so unverified
                // trailing leaves beyond `lane_hdr.next_leaf` are never exposed or committed.
                fetched_subtrees.insert(
                    key,
                    (
                        leaves_be[..expected_min_leaves].to_vec(),
                        leaves_fr[..expected_min_leaves].to_vec(),
                    ),
                );
            } else {
                fetched_subtrees.insert(key, (leaves_be, leaves_fr));
            }
        }
    }

    // Cryptographic lane-root verification: before verifying memos or committing Pass 1A/1D state
    // to `store`, verify EVERY active lane with `next_leaf > 0` by rolling up
    // `all_finalized_subroots[..finalized_count]` + `frontier_fr_leaves[..frontier_rem]` against
    // Phase 0 `LaneTreeState.current_root`. If Pass 1A stopped short of `finalized_count`
    // (transient RPC lag), withhold committing Pass 1A/1D for this sync cycle rather than
    // committing unverified leaves.
    let mut any_pass1a_incomplete = false;
    for lane_hdr in &lanes {
        let l = lane_hdr.lane_id as usize;
        let finalized_count = lane_hdr.next_leaf / sub_size;
        let frontier_rem = (lane_hdr.next_leaf % sub_size) as usize;
        if finalized_count == 0 && frontier_rem == 0 {
            continue;
        }

        let expected_lane_root_fr =
            fr_from_be_bytes_strict(&lane_hdr.current_root).ok_or(ClientError::InvalidFieldElement)?;
        let existing_subroots = &store.lanes[l].finalized_subroots;
        let pass1a_buf = pass1a_new_subroots
            .get(&lane_hdr.lane_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let total_available =
            (existing_subroots.len() as u64).saturating_add(pass1a_buf.len() as u64);
        if total_available < finalized_count {
            any_pass1a_incomplete = true;
            continue;
        }

        let frontier_fr_slice = if frontier_rem > 0 {
            match fetched_subtrees.get(&(lane_hdr.lane_id, finalized_count)) {
                Some((_, f_fr)) if f_fr.len() >= frontier_rem => Some(&f_fr[..frontier_rem]),
                _ => {
                    any_pass1d_subtree_missing = true;
                    continue;
                }
            }
        } else {
            None
        };

        let fc_usize = usize::try_from(finalized_count)
            .map_err(|_| ClientError::InvalidEncoding("finalized_count exceeds platform usize"))?;
        let mut all_finalized_fr = Vec::with_capacity(fc_usize);
        let take_existing = existing_subroots.len().min(fc_usize);
        for r in &existing_subroots[..take_existing] {
            all_finalized_fr.push(
                fr_from_be_bytes_strict(r).ok_or(ClientError::InvalidFieldElement)?,
            );
        }
        for r in &pass1a_buf[..(fc_usize - take_existing)] {
            all_finalized_fr.push(
                fr_from_be_bytes_strict(r).ok_or(ClientError::InvalidFieldElement)?,
            );
        }
        let computed_lane_root_fr = compute_lane_root_from_subroots_and_frontier(
            &all_finalized_fr,
            frontier_fr_slice,
            frontier_rem,
        )?;
        if computed_lane_root_fr != expected_lane_root_fr {
            return Err(ClientError::InvalidEncoding(
                "lane root mismatch against LaneTreeState.current_root",
            ));
        }
    }

    let mut discovered_notes = 0usize;
    let mut pending_verified_memos: Vec<(u8, u64, DecryptedMemo, [u8; 32])> = Vec::new();
    let mut pending_watermarks: Vec<(usize, u64)> = Vec::new();

    for lane_hdr in &lanes {
        let lane_id = lane_hdr.lane_id;
        let l = lane_id as usize;
        let old_frontier_sub_seq = store.lanes[l].frontier_sub_seq;
        let old_frontier_leaves = &store.lanes[l].frontier_leaves;

        // Verify all view-tag candidates for this lane in ascending leaf order into a temporary
        // buffer; `store` is ONLY mutated below when `!any_pass1d_subtree_missing` so any dropped
        // Pass 1D page (hit OR decoy) leaves `store` and `discovered_notes` 100% untouched.
        let mut verified_watermark = *scanned_watermark_by_lane
            .get(&lane_id)
            .unwrap_or(&store.lanes[l].next_memo_leaf);
        if let Some(hits) = hits_by_lane.get(&lane_id) {
            for hit in hits {
                let memo_raw = fetched_full_memos.get(&(lane_id, hit.memo_seq));
                let sub_seq = hit.leaf_idx / sub_size;
                let sub_slot = (hit.leaf_idx % sub_size) as usize;
                let sub_leaves = fetched_subtrees
                    .get(&(lane_id, sub_seq))
                    .map(|(be, _)| be.as_slice())
                    .or_else(|| {
                        (sub_seq == old_frontier_sub_seq).then_some(old_frontier_leaves.as_slice())
                    });

                let (Some(mraw), Some(leaves)) = (memo_raw, sub_leaves) else {
                    if hit.leaf_idx < verified_watermark {
                        verified_watermark = hit.leaf_idx;
                    }
                    break;
                };
                let memo_count = read_u16(mraw, MM_OFF_COUNT) as usize;
                if memo_count > MEMO_NOTES_PER_PAGE {
                    return Err(ClientError::InvalidEncoding(
                        "MemoPage count exceeds capacity",
                    ));
                }
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
                    pending_verified_memos.push((lane_id, hit.leaf_idx, dec, cm_be));
                }
            }
        }
        pending_watermarks.push((l, verified_watermark));
    }

    // Privacy & atomicity invariant: if ANY Pass 1A `SubtreeRootPage` stopped short of
    // `finalized_count` OR ANY Pass 1D `SubtreePage` fetch returned `None` (or truncated) —
    // whether for a hit page OR a decoy/batch page — uniformly withhold ALL Pass 1A/1B/1D store
    // mutations (`finalized_subroots`, `notes`, `discovered_notes`, `next_memo_leaf`, note
    // freezing, and frontier updates) across ALL lanes. Precompute ALL frozen intra-subtree
    // witnesses BEFORE mutating `store` so a validation error can NEVER leave partially mutated state!
    let pass1_incomplete = any_pass1d_subtree_missing || any_pass1a_incomplete;
    if !pass1_incomplete {
        if !pending_verified_memos.is_empty() {
            fr_from_be_bytes_strict(&fvk.spend_pk).ok_or(ClientError::InvalidFieldElement)?;
            fr_from_be_bytes_strict(&fvk.nk).ok_or(ClientError::InvalidFieldElement)?;
        }

        let compute_frozen_be = |leaves_fr: &[Fr], offset: usize| {
            let (sibs, pos) = extract_intra_subtree_siblings(leaves_fr, SUBTREE_LEAVES, offset);
            let mut sibs_be = [[[0u8; 32]; 3]; SUBTREE_LEVELS_4ARY];
            for h in 0..SUBTREE_LEVELS_4ARY {
                for k in 0..3 {
                    sibs_be[h][k] = fr_to_be_bytes(&sibs[h][k]);
                }
            }
            (sibs_be, pos)
        };

        type FrozenIntraWitness = ([[[u8; 32]; 3]; SUBTREE_LEVELS_4ARY], [u8; SUBTREE_LEVELS_4ARY]);
        let mut precomputed_existing_freezes: Vec<(usize, FrozenIntraWitness)> = Vec::new();
        for (ni, note) in store.notes.iter().enumerate() {
            if note.frozen_intra_siblings.is_some() {
                continue;
            }
            let sub_seq = note.leaf_index / sub_size;
            let fc = *finalized_by_lane.get(&note.lane_id).unwrap_or(&0);
            if sub_seq < fc {
                if let Some((leaves_be, leaves_fr)) = fetched_subtrees.get(&(note.lane_id, sub_seq))
                {
                    let offset = (note.leaf_index % sub_size) as usize;
                    if leaves_fr.len() == SUBTREE_LEAVES
                        && offset < leaves_be.len()
                        && leaves_be[offset] == note.commitment
                    {
                        precomputed_existing_freezes
                            .push((ni, compute_frozen_be(leaves_fr, offset)));
                    }
                }
            }
        }

        let mut precomputed_new_freezes: BTreeMap<(u8, u64), FrozenIntraWitness> = BTreeMap::new();
        for &(lane_id, leaf_idx, _, cm_be) in &pending_verified_memos {
            let sub_seq = leaf_idx / sub_size;
            let fc = *finalized_by_lane.get(&lane_id).unwrap_or(&0);
            if sub_seq < fc {
                if let Some((leaves_be, leaves_fr)) = fetched_subtrees.get(&(lane_id, sub_seq)) {
                    let offset = (leaf_idx % sub_size) as usize;
                    if leaves_fr.len() == SUBTREE_LEAVES
                        && offset < leaves_be.len()
                        && leaves_be[offset] == cm_be
                    {
                        precomputed_new_freezes
                            .insert((lane_id, leaf_idx), compute_frozen_be(leaves_fr, offset));
                    }
                }
            }
        }

        // All validations & precomputations succeeded: commit atomically to `store`.
        for lane_hdr in &lanes {
            if let Some(new_roots) = pass1a_new_subroots.get(&lane_hdr.lane_id) {
                if !new_roots.is_empty() {
                    store.lanes[lane_hdr.lane_id as usize]
                        .finalized_subroots
                        .extend_from_slice(new_roots);
                }
            }
        }

        for (ni, (sibs_be, pos)) in precomputed_existing_freezes {
            store.notes[ni].frozen_intra_siblings = Some(sibs_be);
            store.notes[ni].frozen_intra_positions = Some(pos);
        }

        for (lane_id, leaf_idx, dec, cm_be) in pending_verified_memos {
            if store.record_verified_memo(fvk, lane_id, leaf_idx, &dec, cm_be)? {
                discovered_notes += 1;
                if let Some(&(sibs_be, pos)) = precomputed_new_freezes.get(&(lane_id, leaf_idx)) {
                    if let Some(added) = store.notes.last_mut() {
                        added.frozen_intra_siblings = Some(sibs_be);
                        added.frozen_intra_positions = Some(pos);
                    }
                }
            }
        }

        for (l, verified_watermark) in pending_watermarks {
            if verified_watermark > store.lanes[l].next_memo_leaf {
                store.lanes[l].next_memo_leaf = verified_watermark;
            }
        }

        for lane_hdr in &lanes {
            let lane_id = lane_hdr.lane_id;
            let l = lane_id as usize;
            let old_frontier_sub_seq = store.lanes[l].frontier_sub_seq;
            let old_frontier_leaves = store.lanes[l].frontier_leaves.clone();
            let finalized_count = lane_hdr.next_leaf / sub_size;
            let frontier_rem = (lane_hdr.next_leaf % sub_size) as usize;
            let finalized_subroots_len = store.lanes[l].finalized_subroots.len() as u64;

            if finalized_count > 0 {
                let latest_sealed = finalized_count - 1;
                let prev_sealed_advances = store.lanes[l]
                    .prev_sealed_sub_seq
                    .is_none_or(|p| latest_sealed >= p)
                    && finalized_count >= old_frontier_sub_seq
                    && finalized_count >= finalized_subroots_len;
                if prev_sealed_advances {
                    if let Some((leaves, _)) = fetched_subtrees.get(&(lane_id, latest_sealed)) {
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
            }

            if frontier_rem > 0 {
                let frontier_advances = finalized_count >= finalized_subroots_len
                    && (finalized_count > store.lanes[l].frontier_sub_seq
                        || (finalized_count == store.lanes[l].frontier_sub_seq
                            && frontier_rem > store.lanes[l].frontier_leaves.len()));
                if frontier_advances {
                    if let Some((leaves, _)) = fetched_subtrees.get(&(lane_id, finalized_count)) {
                        if leaves.len() >= frontier_rem {
                            store.lanes[l].frontier_sub_seq = finalized_count;
                            store.lanes[l].frontier_leaves = leaves[..frontier_rem].to_vec();
                        }
                    }
                }
            } else if finalized_count > store.lanes[l].frontier_sub_seq
                && finalized_count >= finalized_subroots_len
            {
                store.lanes[l].frontier_sub_seq = finalized_count;
                store.lanes[l].frontier_leaves.clear();
            }
        }
    }

    // =========================================================================
    // PASS 2: Unconditionally stream ALL new `NullifierPage`s across ALL active
    //         lanes (ZERO early-exit, ZERO Pass 1D -> Pass 2 miss oracle!).
    //         If ANY Pass 1D `SubtreePage` was missing/truncated OR any lane had
    //         an unverified miss (`!all_caught_up`), we still issue every Pass 2
    //         RPC identically while guaranteeing unconditional rollback of
    //         `next_nf_index` on BOTH `Ok` AND `Err` exits.
    // =========================================================================
    let all_caught_up = !pass1_incomplete
        && lanes
            .iter()
            .all(|h| store.lanes[h.lane_id as usize].next_memo_leaf >= h.next_leaf);
    let saved_nf_indices: Vec<(u8, u64)> = lanes
        .iter()
        .map(|h| (h.lane_id, store.lanes[h.lane_id as usize].next_nf_index))
        .collect();

    let pass2_res: Result<(), ClientError> = (|| {
        let mut nf_start_idx_by_lane: BTreeMap<u8, u64> = BTreeMap::new();
        for lane_hdr in &lanes {
            nf_start_idx_by_lane.insert(
                lane_hdr.lane_id,
                store.lanes[lane_hdr.lane_id as usize].next_nf_index,
            );
        }

        // Optional birthday_slot binary search on `64 B` NullifierPage headers for fresh wallets
        // (runs unconditionally regardless of owned-note balance so RPC cannot infer first receipt;
        // keeps working start index local so Pass 2 errors never leak mutated `next_nf_index`).
        if birthday_slot > 0 {
            struct NfBsState {
                lane_id: u8,
                nf_count: u64,
                lo: u64,
                hi: u64,
            }
            let mut nf_bs_states: Vec<NfBsState> = Vec::new();
            for lane_hdr in &lanes {
                let start_idx = *nf_start_idx_by_lane
                    .get(&lane_hdr.lane_id)
                    .unwrap_or(&store.lanes[lane_hdr.lane_id as usize].next_nf_index);
                if lane_hdr.nf_count > 0 && start_idx == 0 {
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
                    .map(|&idx| {
                        nf_bs_states[idx].lo + (nf_bs_states[idx].hi - nf_bs_states[idx].lo) / 2
                    })
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
                    let lane_id = nf_bs_states[idx].lane_id;
                    let skip = match raws.get(i).and_then(|o| o.as_ref()) {
                        Some(nraw) => {
                            if nraw.len() < NF_PAGE_HEADER_LEN || nraw[0..8] != NF_PAGE_MAGIC {
                                return Err(ClientError::InvalidEncoding(
                                    "invalid NullifierPage header",
                                ));
                            }
                            if read_u32(nraw, NF_OFF_POOL_ID) != pool_id
                                || nraw[NF_OFF_LANE_ID] != lane_id
                                || read_u64(nraw, NF_OFF_PAGE_SEQ) != mid
                            {
                                return Err(ClientError::InvalidEncoding(
                                    "NullifierPage header mismatch",
                                ));
                            }
                            let cnt = read_u16(nraw, NF_OFF_COUNT) as usize;
                            if cnt > NF_PER_PAGE {
                                return Err(ClientError::InvalidEncoding(
                                    "NullifierPage count exceeds capacity",
                                ));
                            }
                            let closed = read_u64(nraw, NF_OFF_CLOSED_SLOT);
                            cnt == NF_PER_PAGE && closed > 0 && closed < birthday_slot
                        }
                        None => false,
                    };
                    if skip {
                        nf_bs_states[idx].lo = mid + 1;
                    } else {
                        nf_bs_states[idx].hi = mid;
                    }
                }
            }
            for st in &nf_bs_states {
                if st.lo > 0 {
                    let skip_to = st.lo.saturating_mul(nf_size).min(st.nf_count);
                    nf_start_idx_by_lane.insert(st.lane_id, skip_to);
                }
            }
        }

        // Lazily stream ALL new NullifierPages up to `lane_hdr.nf_count` in uniform 100-account windows.
        // NEVER skip when 0 unspent notes exist or when Pass 1D had a transient miss, and NEVER break
        // early when the last unspent note is marked spent — stranger prefixes are discarded immediately.
        struct NfCursor {
            lane_id: u8,
            next_nf: u64,
            end_nf: u64,
            max_nf_index: u64,
            stopped: bool,
        }
        let mut nf_cursors: Vec<NfCursor> = Vec::new();
        for lane_hdr in &lanes {
            let start_idx = *nf_start_idx_by_lane
                .get(&lane_hdr.lane_id)
                .unwrap_or(&store.lanes[lane_hdr.lane_id as usize].next_nf_index);
            if lane_hdr.nf_count == 0 || start_idx >= lane_hdr.nf_count {
                continue;
            }
            nf_cursors.push(NfCursor {
                lane_id: lane_hdr.lane_id,
                next_nf: start_idx / nf_size,
                end_nf: (lane_hdr.nf_count - 1) / nf_size,
                max_nf_index: lane_hdr.nf_count,
                stopped: false,
            });
        }

        let mut nf_pages_fetched = 0usize;
        while nf_pages_fetched < MAX_SYNC_PAGES_PER_CALL {
            let mut chunk: Vec<(usize, u8, u64, u64, Address)> = Vec::new();
            for (c_idx, cursor) in nf_cursors.iter_mut().enumerate() {
                while !cursor.stopped
                    && cursor.next_nf <= cursor.end_nf
                    && chunk.len() < RPC_BATCH_CHUNK
                    && nf_pages_fetched + chunk.len() < MAX_SYNC_PAGES_PER_CALL
                {
                    let n = cursor.next_nf;
                    cursor.next_nf = n.saturating_add(1);
                    chunk.push((
                        c_idx,
                        cursor.lane_id,
                        n,
                        cursor.max_nf_index,
                        derive_nf_page_pda(program_id, pool_id, cursor.lane_id, n).0,
                    ));
                }
                if chunk.len() >= RPC_BATCH_CHUNK
                    || nf_pages_fetched + chunk.len() >= MAX_SYNC_PAGES_PER_CALL
                {
                    break;
                }
            }
            if chunk.is_empty() {
                break;
            }
            nf_pages_fetched += chunk.len();
            let addrs: Vec<Address> = chunk.iter().map(|&(_, _, _, _, a)| a).collect();
            let raws = fetch_batch(&addrs, None);
            for (i, &(c_idx, lane_id, page_seq, max_nf_index, _)) in chunk.iter().enumerate() {
                if nf_cursors[c_idx].stopped {
                    continue;
                }
                let Some(nraw) = raws.get(i).and_then(|o| o.as_ref()) else {
                    nf_cursors[c_idx].stopped = true;
                    continue;
                };
                if nraw.len() != NF_PAGE_LEN || nraw[0..8] != NF_PAGE_MAGIC {
                    return Err(ClientError::InvalidEncoding("invalid NullifierPage"));
                }
                if read_u32(nraw, NF_OFF_POOL_ID) != pool_id
                    || nraw[NF_OFF_LANE_ID] != lane_id
                    || read_u64(nraw, NF_OFF_PAGE_SEQ) != page_seq
                {
                    return Err(ClientError::InvalidEncoding(
                        "NullifierPage header mismatch",
                    ));
                }
                let hdr_count = read_u16(nraw, NF_OFF_COUNT) as usize;
                if hdr_count > NF_PER_PAGE {
                    return Err(ClientError::InvalidEncoding(
                        "NullifierPage count exceeds capacity",
                    ));
                }
                let page_base = page_seq
                    .checked_mul(nf_size)
                    .ok_or(ClientError::InvalidEncoding("NullifierPage page_seq overflow"))?;
                let expected_cap = max_nf_index.saturating_sub(page_base).min(nf_size) as usize;
                store.ingest_nullifier_page(lane_id, page_seq, nraw, Some(max_nf_index))?;
                if hdr_count < expected_cap {
                    nf_cursors[c_idx].stopped = true;
                }
            }
        }

        if all_caught_up {
            for (&lane_id, &start_idx) in &nf_start_idx_by_lane {
                let l = lane_id as usize;
                if start_idx > store.lanes[l].next_nf_index {
                    store.lanes[l].next_nf_index = start_idx;
                }
            }
        }
        Ok(())
    })();

    if !all_caught_up {
        for &(lane_id, prev_idx) in &saved_nf_indices {
            store.lanes[lane_id as usize].next_nf_index = prev_idx;
        }
    }
    pass2_res?;

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
            LANE_MAGIC, LANE_STATE_LEN, LN_OFF_CURRENT_ROOT, LN_OFF_LANE_ID, LN_OFF_NEXT_LEAF,
            LN_OFF_NF_COUNT, LN_OFF_VERSION, MAX_LEAVES_PER_LANE, MEMO_ENTRY_WIRE_LEN,
            NF_OFF_PREFIXES, NF_PREFIX_LEN, PL_OFF_ACTIVE_LANES, PL_OFF_VERSION, POOL_MAGIC,
            POOL_STATE_LEN, SB_OFF_LANE_ID, SB_OFF_PAGE_SEQ, SR_OFF_LANE_ID,
            SR_OFF_ROOT_PAGE_SEQ,
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

    fn make_lane_with_root(
        lane_id: u8,
        next_leaf: u64,
        nf_count: u64,
        current_root: Fr,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; LANE_STATE_LEN];
        buf[0..8].copy_from_slice(&LANE_MAGIC);
        buf[LN_OFF_VERSION] = PROTOCOL_VERSION;
        buf[LN_OFF_LANE_ID] = lane_id;
        buf[LN_OFF_NEXT_LEAF..LN_OFF_NEXT_LEAF + 8].copy_from_slice(&next_leaf.to_le_bytes());
        buf[LN_OFF_NF_COUNT..LN_OFF_NF_COUNT + 8].copy_from_slice(&nf_count.to_le_bytes());
        buf[LN_OFF_CURRENT_ROOT..LN_OFF_CURRENT_ROOT + 32]
            .copy_from_slice(&fr_to_be_bytes(&current_root));
        buf
    }

    fn make_lane(lane_id: u8, next_leaf: u64, nf_count: u64) -> Vec<u8> {
        let mut buf = vec![0u8; LANE_STATE_LEN];
        buf[0..8].copy_from_slice(&LANE_MAGIC);
        buf[LN_OFF_VERSION] = PROTOCOL_VERSION;
        buf[LN_OFF_LANE_ID] = lane_id;
        buf[LN_OFF_NEXT_LEAF..LN_OFF_NEXT_LEAF + 8].copy_from_slice(&next_leaf.to_le_bytes());
        buf[LN_OFF_NF_COUNT..LN_OFF_NF_COUNT + 8].copy_from_slice(&nf_count.to_le_bytes());
        buf[LN_OFF_CURRENT_ROOT..LN_OFF_CURRENT_ROOT + 32]
            .copy_from_slice(&ZERO_HASHES_4ARY[LANE_DEPTH_4ARY]);
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

    fn make_memo(lane_id: u8, seq: u64, count: u16, closed_slot: u64) -> Vec<u8> {
        let mut buf = vec![0u8; MEMO_PAGE_LEN];
        buf[0..8].copy_from_slice(&MEMO_MAGIC);
        buf[MM_OFF_LANE_ID] = lane_id;
        buf[MM_OFF_COUNT..MM_OFF_COUNT + 2].copy_from_slice(&count.to_le_bytes());
        buf[MM_OFF_PAGE_SEQ..MM_OFF_PAGE_SEQ + 8].copy_from_slice(&seq.to_le_bytes());
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

    fn make_root_history(
        pool_id: u32,
        latest_roots: &[Fr; NUM_LANES],
        latest_counts: &[u64; NUM_LANES],
        stable_roots: &[Fr; NUM_LANES],
        stable_counts: &[u64; NUM_LANES],
    ) -> Vec<u8> {
        use audren_core::{
            layout::{
                ROOTS_MAGIC, ROOT_HISTORY_LEN, RT_OFF_EPOCH_COUNT, RT_OFF_EPOCH_CURSOR,
                RT_OFF_EPOCH_INTERVAL, RT_OFF_EPOCH_RING, RT_OFF_GROUP_ROOTS,
                RT_OFF_LATEST_LANE_COUNTS, RT_OFF_LATEST_LANE_ROOTS, RT_OFF_LATEST_SLOT,
                RT_OFF_LATEST_SUPER_ROOT, RT_OFF_MAGIC, RT_OFF_POOL_ID, RT_OFF_SLOT_COUNT,
                RT_OFF_SLOT_CURSOR, RT_OFF_SLOT_RING, RT_OFF_STABLE_EPOCH_ID,
                RT_OFF_STABLE_LANE_COUNTS, RT_OFF_STABLE_LANE_ROOTS, RT_OFF_STABLE_SLOT,
                RT_OFF_STABLE_SUPER_ROOT, RT_OFF_VERSION,
            },
            DEFAULT_ROOT_EPOCH_INTERVAL,
        };
        let latest_sr = fr_to_be_bytes(&compute_super_root_4ary(latest_roots));
        let stable_sr = fr_to_be_bytes(&compute_super_root_4ary(stable_roots));
        let mut buf = vec![0u8; ROOT_HISTORY_LEN];
        buf[RT_OFF_MAGIC..RT_OFF_MAGIC + 8].copy_from_slice(&ROOTS_MAGIC);
        buf[RT_OFF_VERSION] = PROTOCOL_VERSION;
        buf[RT_OFF_SLOT_CURSOR..RT_OFF_SLOT_CURSOR + 2].copy_from_slice(&0u16.to_le_bytes());
        buf[RT_OFF_POOL_ID..RT_OFF_POOL_ID + 4].copy_from_slice(&pool_id.to_le_bytes());
        buf[RT_OFF_EPOCH_CURSOR..RT_OFF_EPOCH_CURSOR + 2].copy_from_slice(&0u16.to_le_bytes());
        buf[RT_OFF_SLOT_COUNT..RT_OFF_SLOT_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
        buf[RT_OFF_EPOCH_COUNT..RT_OFF_EPOCH_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
        buf[RT_OFF_LATEST_SLOT..RT_OFF_LATEST_SLOT + 8].copy_from_slice(&104u64.to_le_bytes());
        buf[RT_OFF_STABLE_EPOCH_ID..RT_OFF_STABLE_EPOCH_ID + 8].copy_from_slice(&3u64.to_le_bytes());
        buf[RT_OFF_STABLE_SLOT..RT_OFF_STABLE_SLOT + 8].copy_from_slice(&96u64.to_le_bytes());
        buf[RT_OFF_EPOCH_INTERVAL..RT_OFF_EPOCH_INTERVAL + 8]
            .copy_from_slice(&DEFAULT_ROOT_EPOCH_INTERVAL.to_le_bytes());
        for g in 0..4 {
            let gr = poseidon4(
                latest_roots[g * 4],
                latest_roots[g * 4 + 1],
                latest_roots[g * 4 + 2],
                latest_roots[g * 4 + 3],
            );
            buf[RT_OFF_GROUP_ROOTS + g * 32..RT_OFF_GROUP_ROOTS + (g + 1) * 32]
                .copy_from_slice(&fr_to_be_bytes(&gr));
        }
        buf[RT_OFF_LATEST_SUPER_ROOT..RT_OFF_LATEST_SUPER_ROOT + 32].copy_from_slice(&latest_sr);
        buf[RT_OFF_STABLE_SUPER_ROOT..RT_OFF_STABLE_SUPER_ROOT + 32].copy_from_slice(&stable_sr);
        for i in 0..NUM_LANES {
            buf[RT_OFF_LATEST_LANE_ROOTS + i * 32..RT_OFF_LATEST_LANE_ROOTS + (i + 1) * 32]
                .copy_from_slice(&fr_to_be_bytes(&latest_roots[i]));
            buf[RT_OFF_LATEST_LANE_COUNTS + i * 8..RT_OFF_LATEST_LANE_COUNTS + (i + 1) * 8]
                .copy_from_slice(&latest_counts[i].to_le_bytes());
            buf[RT_OFF_STABLE_LANE_ROOTS + i * 32..RT_OFF_STABLE_LANE_ROOTS + (i + 1) * 32]
                .copy_from_slice(&fr_to_be_bytes(&stable_roots[i]));
            buf[RT_OFF_STABLE_LANE_COUNTS + i * 8..RT_OFF_STABLE_LANE_COUNTS + (i + 1) * 8]
                .copy_from_slice(&stable_counts[i].to_le_bytes());
        }
        buf[RT_OFF_SLOT_RING..RT_OFF_SLOT_RING + 32].copy_from_slice(&latest_sr);
        buf[RT_OFF_SLOT_RING + 32..RT_OFF_SLOT_RING + 40].copy_from_slice(&104u64.to_le_bytes());
        buf[RT_OFF_EPOCH_RING..RT_OFF_EPOCH_RING + 32].copy_from_slice(&stable_sr);
        buf[RT_OFF_EPOCH_RING + 32..RT_OFF_EPOCH_RING + 40].copy_from_slice(&96u64.to_le_bytes());
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
                make_memo(2, m as u64, cnt, closed)
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

        let lane2_subroots = [
            compute_subtree_256_root(&leaves[0..256], 256),
            compute_subtree_256_root(&leaves[256..512], 256),
        ];
        let lane2_root = compute_lane_root_from_subroots_and_frontier(
            &lane2_subroots,
            Some(&leaves[512..520]),
            8,
        )
        .unwrap();
        let mut accounts: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
        accounts.insert(derive_pool_pda(&program_id, 0).0, make_pool(4));
        accounts.insert(derive_lane_pda(&program_id, 0, 0).0, make_lane(0, 0, 41));
        accounts.insert(derive_lane_pda(&program_id, 0, 1).0, make_lane(1, 0, 0));
        accounts.insert(
            derive_lane_pda(&program_id, 0, 2).0,
            make_lane_with_root(2, total_leaves as u64, 0, lane2_root),
        );
        accounts.insert(derive_lane_pda(&program_id, 0, 3).0, make_lane(3, 0, 0));
        accounts.insert(
            derive_subroot_pda(&program_id, 0, 2, 0).0,
            make_subroot(2, 0, &lane2_subroots),
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
                ..Default::default()
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
        let mut lane0_memo0 = make_memo(0, 0, 1, 0);
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

        let lane0_root =
            compute_lane_root_from_subroots_and_frontier(&[], Some(&[cm]), 1).unwrap();
        let mut accounts: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
        accounts.insert(derive_pool_pda(&program_id, 0).0, make_pool(2));
        accounts.insert(
            derive_lane_pda(&program_id, 0, 0).0,
            make_lane_with_root(0, 1, lane0_nf_total, lane0_root),
        );
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
                accounts.insert(addr, make_nf_page(0, p as u64, &full_strangers[..5]));
            } else {
                accounts.insert(addr, make_nf_page(0, p as u64, &full_strangers));
            }
        }
        for p in 0..lane1_nf_pages {
            let addr = derive_nf_page_pda(&program_id, 0, 1, p as u64).0;
            expected_nf_addrs.insert(addr);
            accounts.insert(
                addr,
                if p == lane1_nf_pages - 1 {
                    make_nf_page(1, p as u64, &full_strangers[..3])
                } else {
                    make_nf_page(1, p as u64, &full_strangers)
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
        let mut hit_memo_raw = make_memo(2, alice_memo_seq, MEMO_NOTES_PER_PAGE as u16, 0);
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

            for l in 0..active_lanes {
                let roots: Vec<Fr> = (0..sealed_per_lane)
                    .map(|s| {
                        if l == 2 && s as u64 == alice_sub_seq {
                            hit_subroot
                        } else {
                            dummy_subroot
                        }
                    })
                    .collect();
                let lane_root = compute_lane_root_from_subroots_and_frontier(
                    &roots,
                    Some(dummy_frontier),
                    dummy_frontier.len(),
                )
                .unwrap();
                accounts.insert(
                    derive_lane_pda(&program_id, 0, l).0,
                    make_lane_with_root(
                        l,
                        leaves_per_lane as u64,
                        if l == 0 { nf_total_lane0 } else { 0 },
                        lane_root,
                    ),
                );
                accounts.insert(
                    derive_subroot_pda(&program_id, 0, l, 0).0,
                    make_subroot(l, 0, &roots),
                );
                for s in 0..sealed_per_lane {
                    let addr = derive_subtree_pda(&program_id, 0, l, s as u64).0;
                    sealed_sub_addrs.insert(addr);
                    accounts.insert(
                        addr,
                        if l == 2 && s as u64 == alice_sub_seq {
                            hit_sub_raw.clone()
                        } else {
                            make_subtree(l, s as u64, &dummy_leaves)
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
                    } else {
                        accounts.insert(addr, make_memo(l, m as u64, cnt as u16, 0));
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
                ..Default::default()
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
        for l in 0..4 {
            assert_eq!(
                miss_store.lanes[l].next_memo_leaf, 0,
                "Pass 1D SubtreePage drop must uniformly withhold next_memo_leaf across ALL lanes"
            );
            assert_eq!(
                miss_store.lanes[l].next_nf_index, 0,
                "Pass 1D SubtreePage drop must uniformly withhold next_nf_index across ALL lanes"
            );
        }
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
        // Dropping a DECOY SubtreePage instead of the hit page MUST produce identical withheld watermarks
        // and IDENTICAL Sync #2 RPC batches (closing the Pass 1D watermark rollback oracle!).
        let decoy_to_drop = *strict20_sealed
            .iter()
            .find(|&&a| a != hit_sub_20)
            .expect("at least one decoy sealed SubtreePage");
        let mut decoy_drop_store = CompactWalletStore::new(0, 0);
        let (_, _, d_decoy_drop) = sync_compact_store_with_batch(
            &mut decoy_drop_store,
            &fvk,
            |addrs, slice| {
                addrs
                    .iter()
                    .map(|a| {
                        if *a == decoy_to_drop {
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
        assert_eq!(
            d_decoy_drop, 0,
            "R1-C3: dropping a Pass 1D decoy SubtreePage must return discovered_notes == 0"
        );
        assert!(
            decoy_drop_store.notes.is_empty(),
            "R1-C3: dropping a Pass 1D decoy SubtreePage must leave store.notes completely untouched"
        );
        assert!(
            miss_store.notes.is_empty(),
            "R1-C3: dropping a Pass 1D hit SubtreePage must leave store.notes completely untouched"
        );
        for l in 0..4 {
            assert_eq!(
                decoy_drop_store.lanes[l].next_memo_leaf, 0,
                "dropping a decoy SubtreePage must uniformly withhold next_memo_leaf on lane {l}"
            );
            assert_eq!(
                decoy_drop_store.lanes[l].next_nf_index, 0,
                "dropping a decoy SubtreePage must uniformly withhold next_nf_index on lane {l}"
            );
        }

        // Retry once RPC returns all pages -> BOTH hit-drop and decoy-drop emit IDENTICAL Sync #2 traffic!
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

        let mut decoy_retry_log = Vec::new();
        sync_compact_store_with_batch(
            &mut decoy_drop_store,
            &fvk,
            |addrs, slice| slice_fetch(&acc_20, &mut decoy_retry_log, addrs, slice),
            &program_id,
            SyncOptions::default(),
        )
        .unwrap();
        assert_eq!(
            retry_log, decoy_retry_log,
            "Sync #2 RPC traffic MUST be 100% identical after hit-page drop vs decoy-page drop"
        );
        assert!(decoy_drop_store.notes[0].spent);
        assert!(decoy_drop_store.notes[0].frozen_intra_siblings.is_some());

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
                ..Default::default()
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

    #[test]
    fn hrw_decoy_stability_and_uniform_batched_witness_reconstruction() {
        use audren_circuits::merkle::{compute_super_root_4ary, zero_hashes_4ary};
        use audren_core::{
            layout::{
                RT_OFF_EPOCH_RING, RT_OFF_LATEST_LANE_COUNTS, RT_OFF_LATEST_SUPER_ROOT,
                RT_OFF_SLOT_RING, RT_OFF_STABLE_LANE_COUNTS, RT_OFF_STABLE_SUPER_ROOT,
            },
            ROOT_RING_EPOCH,
        };

        let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
        let view_sk = [0x42u8; 32];

        // 1. Rendezvous (HRW) stability across +1 sealed subtree growth within epoch_bucket = 0:
        //    growing from 32 -> 33 sealed subtrees preserves >= 15/16 of decoys!
        let sealed_32 = vec![(0u8, 8u64), (1, 8), (2, 8), (3, 8)];
        let sealed_33 = vec![(0u8, 9u64), (1, 8), (2, 8), (3, 8)];
        let empty = BTreeSet::new();
        let d32: BTreeSet<(u8, u64)> =
            select_hrw_sealed_decoys(&view_sk, DECOY_SCOPE_SYNC, 0, &sealed_32, &empty, 16)
                .into_iter()
                .collect();
        let d33: BTreeSet<(u8, u64)> =
            select_hrw_sealed_decoys(&view_sk, DECOY_SCOPE_SYNC, 0, &sealed_33, &empty, 16)
                .into_iter()
                .collect();
        assert_eq!(d32.len(), 16);
        assert_eq!(d33.len(), 16);
        let overlap = d32.intersection(&d33).count();
        assert!(
            overlap >= 15,
            "HRW +1 sealed subtree growth must preserve >= 15/16 decoys, got {overlap}/16"
        );

        // 2. Asymmetric root history fixture:
        //    Lane 0: 20 sealed + 4 frontier (5,124 leaves)
        //    Lane 1: 5 sealed + 7 frontier (1,287 leaves)
        //    Lane 2: 0 sealed + 10 frontier (10 leaves)
        //    Lane 3: 0 leaves
        let dummy_leaves: Vec<Fr> = (0..SUBTREE_LEAVES)
            .map(|i| Fr::from((i + 10) as u64))
            .collect();
        let dummy_subroot = compute_subtree_256_root(&dummy_leaves, SUBTREE_LEAVES);
        let zeros = zero_hashes_4ary();
        let compute_lane_root = |sealed_cnt: usize, frontier: &[Fr]| -> Fr {
            let mut l4: Vec<Fr> = vec![dummy_subroot; sealed_cnt];
            if !frontier.is_empty() {
                l4.push(compute_subtree_256_root(frontier, frontier.len()));
            }
            if l4.is_empty() {
                return zeros[18];
            }
            let mut cur = l4;
            for zero_h in &zeros[4..18] {
                let mut next = Vec::with_capacity(cur.len().div_ceil(4));
                for chunk in cur.chunks(4) {
                    let c0 = chunk[0];
                    let c1 = *chunk.get(1).unwrap_or(zero_h);
                    let c2 = *chunk.get(2).unwrap_or(zero_h);
                    let c3 = *chunk.get(3).unwrap_or(zero_h);
                    next.push(audren_circuits::poseidon::poseidon4(c0, c1, c2, c3));
                }
                cur = next;
            }
            cur[0]
        };

        let lane_specs: [(u8, usize, usize); 3] = [(0, 20, 4), (1, 5, 7), (2, 0, 10)];
        let mut accounts: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
        let mut lane_roots = [zeros[18]; NUM_LANES];
        let mut lane_counts = [0u64; NUM_LANES];
        let mut all_sr_addrs: BTreeSet<Address> = BTreeSet::new();
        let mut all_frontier_addrs: BTreeSet<Address> = BTreeSet::new();
        let mut all_sealed_addrs: BTreeSet<Address> = BTreeSet::new();

        for (lid, sealed_cnt, frem) in lane_specs {
            let frontier = &dummy_leaves[..frem];
            lane_counts[lid as usize] = (sealed_cnt * SUBTREE_LEAVES + frem) as u64;
            lane_roots[lid as usize] = compute_lane_root(sealed_cnt, frontier);
            if sealed_cnt > 0 {
                let sr_addr = derive_subroot_pda(&program_id, 0, lid, 0).0;
                all_sr_addrs.insert(sr_addr);
                accounts.insert(sr_addr, make_subroot(lid, 0, &vec![dummy_subroot; sealed_cnt]));
            }
            for s in 0..sealed_cnt {
                let addr = derive_subtree_pda(&program_id, 0, lid, s as u64).0;
                all_sealed_addrs.insert(addr);
                accounts.insert(addr, make_subtree(lid, s as u64, &dummy_leaves));
            }
            let f_addr = derive_subtree_pda(&program_id, 0, lid, sealed_cnt as u64).0;
            all_frontier_addrs.insert(f_addr);
            accounts.insert(f_addr, make_subtree(lid, sealed_cnt as u64, frontier));
        }

        let super_root = compute_super_root_4ary(&lane_roots);
        let roots_addr = derive_roots_pda(&program_id, 0).0;
        accounts.insert(
            roots_addr,
            make_root_history(0, &lane_roots, &lane_counts, &lane_roots, &lane_counts),
        );

        let run_witness = |lid: u8, leaf: u64, mode: SyncPrivacyMode| {
            let mut log: Vec<Address> = Vec::new();
            let (path, ring_kind, ring_idx, sr) = reconstruct_witness_with_batch(
                |addrs, _| {
                    log.extend_from_slice(addrs);
                    addrs.iter().map(|a| accounts.get(a).cloned()).collect()
                },
                &program_id,
                0,
                lid,
                leaf,
                WitnessOptions {
                    privacy_mode: mode,
                    view_sk: Some(view_sk),
                    decoy_epoch_bucket: None,
                },
            )
            .unwrap();
            assert_eq!(ring_kind, ROOT_RING_EPOCH);
            assert_eq!(ring_idx, 0);
            assert_eq!(sr, super_root);
            let leaf_val = dummy_leaves[(leaf % SUBTREE_LEAVES as u64) as usize];
            assert_eq!(path.compute_root(leaf_val), super_root);
            log.into_iter().collect::<BTreeSet<Address>>()
        };

        // Spending frontier-only note on Lane 2 (0 sealed) vs sealed note on Lane 0 (page 1):
        // BOTH fetch ALL active lanes' SubtreeRootPages AND ALL active lanes' frontier SubtreePages
        // AND exactly 16 sealed SubtreePages!
        let f_lane2 = run_witness(2, 3, SyncPrivacyMode::Strict);
        let f_lane0_p1 = run_witness(0, 300, SyncPrivacyMode::Strict);
        let f_lane0_p1_repeat = run_witness(0, 300, SyncPrivacyMode::Strict);
        let f_lane0_p7 = run_witness(0, 7 * 256 + 5, SyncPrivacyMode::Strict);

        for set in [&f_lane2, &f_lane0_p1, &f_lane0_p7] {
            for sr_addr in &all_sr_addrs {
                assert!(set.contains(sr_addr), "Strict witness must fetch ALL active lanes' SubtreeRootPages");
            }
            for f_addr in &all_frontier_addrs {
                assert!(set.contains(f_addr), "Strict witness must fetch ALL active lanes' unsealed frontier pages");
            }
            let sealed_cnt = set.intersection(&all_sealed_addrs).count();
            assert_eq!(sealed_cnt, 16, "Strict witness must always fetch exactly 16 sealed SubtreePages");
        }
        assert_eq!(f_lane0_p1, f_lane0_p1_repeat, "same note retry must yield identical page set");

        // Spending two DIFFERENT notes in the same epoch uses independent witness-scoped decoys
        // (symmetric difference must NOT isolate just the 2 target pages!)
        let sealed_p1: BTreeSet<Address> = f_lane0_p1.intersection(&all_sealed_addrs).copied().collect();
        let sealed_p7: BTreeSet<Address> = f_lane0_p7.intersection(&all_sealed_addrs).copied().collect();
        let sym_diff = sealed_p1.symmetric_difference(&sealed_p7).count();
        assert!(
            sym_diff > 4,
            "two different spends in same epoch must use independent witness-scoped decoys (sym_diff={sym_diff})"
        );

        // Fast mode fetches only minimal target pages
        let fast_l2 = run_witness(2, 3, SyncPrivacyMode::Fast);
        assert_eq!(fast_l2.intersection(&all_sealed_addrs).count(), 0);
        assert_eq!(fast_l2.intersection(&all_frontier_addrs).count(), 1);

        // --- R1-C1: Strict mode rejects missing view_sk, dropped decoy SubtreePage, dropped
        //            non-target lane SubtreeRootPage, truncated decoy, header mismatch, & bad root! ---
        assert!(
            reconstruct_witness_with_batch(
                |addrs, _| addrs.iter().map(|a| accounts.get(a).cloned()).collect(),
                &program_id,
                0,
                0,
                300,
                WitnessOptions {
                    privacy_mode: SyncPrivacyMode::Strict,
                    view_sk: None,
                    decoy_epoch_bucket: None,
                },
            )
            .is_err(),
            "R1-C1: Strict reconstruct_witness must reject missing view_sk"
        );

        let target_sub_l0_p1 = derive_subtree_pda(&program_id, 0, 0, 1).0;
        let decoy_sub_to_drop = *f_lane0_p1
            .intersection(&all_sealed_addrs)
            .find(|&&a| a != target_sub_l0_p1)
            .expect("at least one sealed decoy page");
        assert!(
            reconstruct_witness_strict(
                |addrs, _| {
                    addrs
                        .iter()
                        .map(|a| if *a == decoy_sub_to_drop { None } else { accounts.get(a).cloned() })
                        .collect()
                },
                &program_id,
                0,
                0,
                300,
                view_sk,
            )
            .is_err(),
            "R1-C1: Strict reconstruct_witness must fail uniformly when a DECOY SubtreePage is dropped"
        );

        // Dropping a non-target lane's SubtreeRootPage (lane 1 while spending lane 0) must fail!
        let lane1_sr_addr = derive_subroot_pda(&program_id, 0, 1, 0).0;
        assert!(
            reconstruct_witness_strict(
                |addrs, _| {
                    addrs
                        .iter()
                        .map(|a| if *a == lane1_sr_addr { None } else { accounts.get(a).cloned() })
                        .collect()
                },
                &program_id,
                0,
                0,
                300,
                view_sk,
            )
            .is_err(),
            "R1-C1: Strict reconstruct_witness must fail uniformly when a non-target lane SubtreeRootPage is dropped"
        );

        // Truncating a decoy SubtreePage count (< 256) or forging count > 256 must fail!
        let mut truncated_decoy = accounts.get(&decoy_sub_to_drop).unwrap().clone();
        truncated_decoy[SB_OFF_COUNT..SB_OFF_COUNT + 2].copy_from_slice(&255u16.to_le_bytes());
        assert!(
            reconstruct_witness_strict(
                |addrs, _| {
                    addrs
                        .iter()
                        .map(|a| {
                            if *a == decoy_sub_to_drop {
                                Some(truncated_decoy.clone())
                            } else {
                                accounts.get(a).cloned()
                            }
                        })
                        .collect()
                },
                &program_id,
                0,
                0,
                300,
                view_sk,
            )
            .is_err(),
            "R1-C1: Strict reconstruct_witness must fail when a decoy SubtreePage is truncated"
        );

        // Forged GlobalRootHistory super_root mismatch must fail!
        let mut bad_root_rh = accounts.get(&roots_addr).unwrap().clone();
        let bad_sr = fr_to_be_bytes(&Fr::from(123_456_789u64));
        bad_root_rh[RT_OFF_STABLE_SUPER_ROOT..RT_OFF_STABLE_SUPER_ROOT + 32].copy_from_slice(&bad_sr);
        bad_root_rh[RT_OFF_EPOCH_RING..RT_OFF_EPOCH_RING + 32].copy_from_slice(&bad_sr);
        bad_root_rh[RT_OFF_LATEST_SUPER_ROOT..RT_OFF_LATEST_SUPER_ROOT + 32].copy_from_slice(&bad_sr);
        bad_root_rh[RT_OFF_SLOT_RING..RT_OFF_SLOT_RING + 32].copy_from_slice(&bad_sr);
        assert!(
            reconstruct_witness_strict(
                |addrs, _| {
                    addrs
                        .iter()
                        .map(|a| {
                            if *a == roots_addr {
                                Some(bad_root_rh.clone())
                            } else {
                                accounts.get(a).cloned()
                            }
                        })
                        .collect()
                },
                &program_id,
                0,
                0,
                300,
                view_sk,
            )
            .is_err(),
            "R1-C1: reconstruct_witness must reject mismatched GlobalRootHistory super_root"
        );

        // --- R1-C2: Forged count > capacity, lane_hdr.lane_id != expected_l, huge lane_counts ---
        let mut forged_count_sub = accounts.get(&target_sub_l0_p1).unwrap().clone();
        forged_count_sub[SB_OFF_COUNT..SB_OFF_COUNT + 2].copy_from_slice(&257u16.to_le_bytes());
        assert!(
            reconstruct_witness_with_batch(
                |addrs, _| {
                    addrs
                        .iter()
                        .map(|a| {
                            if *a == target_sub_l0_p1 {
                                Some(forged_count_sub.clone())
                            } else {
                                accounts.get(a).cloned()
                            }
                        })
                        .collect()
                },
                &program_id,
                0,
                0,
                300,
                WitnessOptions {
                    privacy_mode: SyncPrivacyMode::Fast,
                    view_sk: None,
                    decoy_epoch_bucket: None,
                },
            )
            .is_err(),
            "R1-C2: forged SubtreePage count=257 must return Err without panicking"
        );

        let mut huge_rh = accounts.get(&roots_addr).unwrap().clone();
        huge_rh[RT_OFF_LATEST_LANE_COUNTS..RT_OFF_LATEST_LANE_COUNTS + 8]
            .copy_from_slice(&u64::MAX.to_le_bytes());
        huge_rh[RT_OFF_STABLE_LANE_COUNTS..RT_OFF_STABLE_LANE_COUNTS + 8]
            .copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(
            reconstruct_witness_with_batch(
                |addrs, _| {
                    addrs
                        .iter()
                        .map(|a| if *a == roots_addr { Some(huge_rh.clone()) } else { None })
                        .collect()
                },
                &program_id,
                0,
                0,
                0,
                WitnessOptions {
                    privacy_mode: SyncPrivacyMode::Fast,
                    view_sk: None,
                    decoy_epoch_bucket: None,
                },
            )
            .is_err(),
            "R1-C2: forged GlobalRootHistory lane_counts=u64::MAX must return Err without OOM/panic"
        );

        // fetch_pool_and_lanes / sync must reject lane_hdr.lane_id != expected_l and active_lanes > 16
        let bad_pool_pda = derive_pool_pda(&program_id, 0).0;
        let bad_lane0_pda = derive_lane_pda(&program_id, 0, 0).0;
        let bad_lane1_pda = derive_lane_pda(&program_id, 0, 1).0;
        assert!(
            fetch_pool_and_lanes(
                |a| {
                    if *a == bad_pool_pda {
                        Some(make_pool(17))
                    } else {
                        None
                    }
                },
                &program_id,
                0,
            )
            .is_err(),
            "R1-C2: active_lanes > 16 must be rejected"
        );
        assert!(
            fetch_pool_and_lanes(
                |a| {
                    if *a == bad_pool_pda {
                        Some(make_pool(2))
                    } else if *a == bad_lane0_pda {
                        Some(make_lane(0, 0, 0))
                    } else if *a == bad_lane1_pda {
                        Some(make_lane(3, 0, 0)) // mismatched lane_id!
                    } else {
                        None
                    }
                },
                &program_id,
                0,
            )
            .is_err(),
            "R1-C2: lane_hdr.lane_id != expected_l must be rejected"
        );
    }

    #[test]
    fn r1_c4_hrw_default_epoch_bucket_zero_eliminates_64_subtree_cliff_rotation() {
        let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
        let alice = AudrenKeys::from_seed(&[0x4cu8; 32]);
        let fvk = alice.full_viewing_key();

        let dummy_leaves: Vec<Fr> = (0..SUBTREE_LEAVES)
            .map(|i| Fr::from((i + 100) as u64))
            .collect();
        let dummy_subroot = compute_subtree_256_root(&dummy_leaves, SUBTREE_LEAVES);

        // Sync across 63 -> 64 -> 65 sealed subtrees using default SyncOptions (epoch_bucket = 0)
        // and verify >= 14/16 decoy overlap across the 64-subtree boundary (no 100% cliff rotation!).
        let run_sync_sealed_set = |sealed_counts: [usize; 4]| -> BTreeSet<Address> {
            let mut accounts: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
            accounts.insert(derive_pool_pda(&program_id, 0).0, make_pool(4));
            let mut all_sealed: BTreeSet<Address> = BTreeSet::new();

            for (l_idx, &sc) in sealed_counts.iter().enumerate() {
                let l = l_idx as u8;
                let total_leaves = sc * SUBTREE_LEAVES;
                let roots = vec![dummy_subroot; sc];
                let lane_root =
                    compute_lane_root_from_subroots_and_frontier(&roots, None, 0).unwrap();
                accounts.insert(
                    derive_lane_pda(&program_id, 0, l).0,
                    make_lane_with_root(l, total_leaves as u64, 0, lane_root),
                );
                accounts.insert(
                    derive_subroot_pda(&program_id, 0, l, 0).0,
                    make_subroot(l, 0, &roots),
                );
                for s in 0..sc {
                    let addr = derive_subtree_pda(&program_id, 0, l, s as u64).0;
                    all_sealed.insert(addr);
                    accounts.insert(addr, make_subtree(l, s as u64, &dummy_leaves));
                }
                let memos = total_leaves.div_ceil(MEMO_NOTES_PER_PAGE);
                for m in 0..memos {
                    let cnt = MEMO_NOTES_PER_PAGE.min(total_leaves - m * MEMO_NOTES_PER_PAGE);
                    let addr = derive_memo_pda(&program_id, 0, l, m as u64).0;
                    accounts.insert(addr, make_memo(l, m as u64, cnt as u16, 0));
                }
            }

            let mut store = CompactWalletStore::new(0, 0);
            let mut fetched_sealed: BTreeSet<Address> = BTreeSet::new();
            sync_compact_store_with_batch(
                &mut store,
                &fvk,
                |addrs, _| {
                    for &a in addrs {
                        if all_sealed.contains(&a) {
                            fetched_sealed.insert(a);
                        }
                    }
                    addrs.iter().map(|a| accounts.get(a).cloned()).collect()
                },
                &program_id,
                SyncOptions::default(),
            )
            .unwrap();
            assert_eq!(fetched_sealed.len(), 16);
            fetched_sealed
        };

        let s63 = run_sync_sealed_set([16, 16, 16, 15]); // total_sealed = 63
        let s64 = run_sync_sealed_set([16, 16, 16, 16]); // total_sealed = 64
        let s65 = run_sync_sealed_set([17, 16, 16, 16]); // total_sealed = 65

        let ov_63_64 = s63.intersection(&s64).count();
        let ov_64_65 = s64.intersection(&s65).count();
        let ov_63_65 = s63.intersection(&s65).count();
        assert!(
            ov_63_64 >= 15,
            "R1-C4: HRW decoy overlap across 63->64 must be >= 15/16, got {ov_63_64}/16"
        );
        assert!(
            ov_64_65 >= 15,
            "R1-C4: HRW decoy overlap across 64->65 must be >= 15/16, got {ov_64_65}/16"
        );
        assert!(
            ov_63_65 >= 14,
            "R1-C4: HRW decoy overlap across 63->65 must be >= 14/16, got {ov_63_65}/16"
        );
    }

    #[test]
    fn r2_c1_c2_c3_c4_scanner_integrity_bounds_and_headers() {
        use audren_circuits::poseidon::poseidon4;
        use audren_core::layout::{
            MM_OFF_POOL_ID, NF_OFF_CLOSED_SLOT, NF_OFF_LANE_ID, NF_OFF_PAGE_SEQ, NF_OFF_POOL_ID,
            SB_OFF_POOL_ID, SR_OFF_POOL_ID,
        };
        use audren_core::ZERO_HASHES_4ARY;

        let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
        let alice = AudrenKeys::from_seed(&[0x61u8; 32]);
        let fvk = alice.full_viewing_key();
        let sol_asset = derive_asset_id(&WSOL_MINT);

        let dummy_leaves: Vec<Fr> = (0..SUBTREE_LEAVES)
            .map(|i| Fr::from((i + 10) as u64))
            .collect();
        let dummy_subroot = compute_subtree_256_root(&dummy_leaves, SUBTREE_LEAVES);
        let dummy_frontier: Vec<Fr> = (0..4).map(|i| Fr::from((i + 900) as u64)).collect();

        // Alice owns a note at lane 2, leaf 1 * 256 + 7 = 263 (SubtreePage (2, 1), MemoPage (2, 2))
        let alice_leaf_idx: u64 = SUBTREE_LEAVES as u64 + 7;
        let (tw, bl, memo_106) =
            encrypt_note_memo(&alice.view_pk, [0x62u8; 32], 3_333_333, &WSOL_MINT).unwrap();
        let alice_cm = compute_note_commitment(
            derive_stealth_owner(alice.spend_pk, tw),
            sol_asset,
            3_333_333,
            bl,
        );
        let mut hit_leaves = dummy_leaves.clone();
        hit_leaves[7] = alice_cm;
        let hit_subroot = compute_subtree_256_root(&hit_leaves, SUBTREE_LEAVES);

        let sealed_per_lane = 5usize;
        let leaves_per_lane = sealed_per_lane * SUBTREE_LEAVES + 4;
        let memos_per_lane = leaves_per_lane.div_ceil(MEMO_NOTES_PER_PAGE);

        let mut accounts: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
        accounts.insert(derive_pool_pda(&program_id, 0).0, make_pool(4));

        let mut sealed_addrs: BTreeSet<Address> = BTreeSet::new();
        let mut nf_addrs: BTreeSet<Address> = BTreeSet::new();
        let mut lane_roots_fr = [fr_from_be_bytes_strict(&ZERO_HASHES_4ARY[18]).unwrap(); NUM_LANES];
        let mut lane_counts = [0u64; NUM_LANES];

        for l in 0..4u8 {
            lane_counts[l as usize] = leaves_per_lane as u64;
            let roots: Vec<Fr> = (0..sealed_per_lane)
                .map(|s| if l == 2 && s == 1 { hit_subroot } else { dummy_subroot })
                .collect();
            lane_roots_fr[l as usize] = compute_lane_root_from_subroots_and_frontier(
                &roots,
                Some(&dummy_frontier),
                dummy_frontier.len(),
            )
            .unwrap();
            accounts.insert(
                derive_lane_pda(&program_id, 0, l).0,
                make_lane_with_root(
                    l,
                    leaves_per_lane as u64,
                    if l == 0 { 2 } else { 0 },
                    lane_roots_fr[l as usize],
                ),
            );
            accounts.insert(
                derive_subroot_pda(&program_id, 0, l, 0).0,
                make_subroot(l, 0, &roots),
            );
            for s in 0..sealed_per_lane {
                let addr = derive_subtree_pda(&program_id, 0, l, s as u64).0;
                sealed_addrs.insert(addr);
                accounts.insert(
                    addr,
                    make_subtree(l, s as u64, if l == 2 && s == 1 { &hit_leaves } else { &dummy_leaves }),
                );
            }
            accounts.insert(
                derive_subtree_pda(&program_id, 0, l, sealed_per_lane as u64).0,
                make_subtree(l, sealed_per_lane as u64, &dummy_frontier),
            );
            for m in 0..memos_per_lane {
                let cnt = MEMO_NOTES_PER_PAGE.min(leaves_per_lane - m * MEMO_NOTES_PER_PAGE) as u16;
                let mut mraw = make_memo(l, m as u64, cnt, ((m + 1) * 50) as u64);
                if l == 2 && m == (alice_leaf_idx as usize) / MEMO_NOTES_PER_PAGE {
                    write_memo(&mut mraw, (alice_leaf_idx as usize) % MEMO_NOTES_PER_PAGE, &memo_106);
                }
                accounts.insert(derive_memo_pda(&program_id, 0, l, m as u64).0, mraw);
            }
        }

        let nf0_addr = derive_nf_page_pda(&program_id, 0, 0, 0).0;
        nf_addrs.insert(nf0_addr);
        accounts.insert(nf0_addr, make_nf_page(0, 0, &[[0x11u8; NF_PREFIX_LEN], [0x22u8; NF_PREFIX_LEN]]));

        let build_rh_raw = |lroots: &[Fr; NUM_LANES], lcounts: &[u64; NUM_LANES]| {
            make_root_history(0, lroots, lcounts, lroots, lcounts)
        };
        let roots_addr = derive_roots_pda(&program_id, 0).0;
        accounts.insert(roots_addr, build_rh_raw(&lane_roots_fr, &lane_counts));

        // Discover deterministic Pass 1D sealed batch (16 pages including hit + decoys)
        let mut baseline_store = CompactWalletStore::new(0, 0);
        let mut fetched_sealed: Vec<Address> = Vec::new();
        let (_, _, disc) = sync_compact_store_with_batch(
            &mut baseline_store,
            &fvk,
            |addrs, _| {
                for &a in addrs {
                    if sealed_addrs.contains(&a) {
                        fetched_sealed.push(a);
                    }
                }
                addrs.iter().map(|a| accounts.get(a).cloned()).collect()
            },
            &program_id,
            SyncOptions::default(),
        )
        .unwrap();
        assert_eq!(disc, 1);
        assert_eq!(fetched_sealed.len(), 16);
        let hit_sub_addr = derive_subtree_pda(&program_id, 0, 2, 1).0;
        let decoy_sub_addr = *fetched_sealed.iter().find(|&&a| a != hit_sub_addr).unwrap();

        // === R2-C1: Pass 1D non-canonical Fr & 1-bit canonical tamper on BOTH decoy AND hit ===
        // Must fail uniformly BEFORE Pass 2 executes and leave `store` 100% untouched!
        for (label, target_addr, non_canonical) in [
            ("decoy non-canonical Fr", decoy_sub_addr, true),
            ("hit non-canonical Fr", hit_sub_addr, true),
            ("decoy 1-bit canonical tamper", decoy_sub_addr, false),
            ("hit 1-bit canonical tamper", hit_sub_addr, false),
        ] {
            let mut tampered = accounts.get(&target_addr).unwrap().clone();
            // Modify leaf 0 (not Alice's leaf 7) so even on hit page decryption alone wouldn't fail
            if non_canonical {
                tampered[SB_OFF_LEAVES..SB_OFF_LEAVES + 32].fill(0xff);
            } else {
                tampered[SB_OFF_LEAVES + 31] ^= 0x01;
            }
            let mut st = CompactWalletStore::new(0, 0);
            let mut pass2_called = false;
            let res = sync_compact_store_with_batch(
                &mut st,
                &fvk,
                |addrs, _| {
                    if addrs.iter().any(|a| nf_addrs.contains(a)) {
                        pass2_called = true;
                    }
                    addrs
                        .iter()
                        .map(|a| {
                            if *a == target_addr {
                                Some(tampered.clone())
                            } else {
                                accounts.get(a).cloned()
                            }
                        })
                        .collect()
                },
                &program_id,
                SyncOptions::default(),
            );
            assert!(res.is_err(), "R2-C1 ({label}): must return Err");
            assert!(
                !pass2_called,
                "R2-C1 ({label}): must fail uniformly in Pass 1D before Pass 2"
            );
            assert!(st.notes.is_empty(), "R2-C1 ({label}): store.notes must stay untouched");
            for l in 0..4 {
                assert_eq!(st.lanes[l].next_memo_leaf, 0);
                assert!(st.lanes[l].finalized_subroots.is_empty());
            }
        }

        // === R2-C2: Strict `reconstruct_witness_with_batch` content-tampering & non-canonical Fr ===
        // First capture the witness decoy set
        let mut wit_fetched_sealed: Vec<Address> = Vec::new();
        reconstruct_witness_strict(
            |addrs, _| {
                for &a in addrs {
                    if sealed_addrs.contains(&a) {
                        wit_fetched_sealed.push(a);
                    }
                }
                addrs.iter().map(|a| accounts.get(a).cloned()).collect()
            },
            &program_id,
            0,
            2,
            alice_leaf_idx,
            alice.view_sk,
        )
        .unwrap();
        let wit_decoy = *wit_fetched_sealed.iter().find(|&&a| a != hit_sub_addr).unwrap();
        let non_target_sr = derive_subroot_pda(&program_id, 0, 0, 0).0;
        let non_target_frontier = derive_subtree_pda(&program_id, 0, 0, sealed_per_lane as u64).0;

        let mut decoy_noncanon = accounts.get(&wit_decoy).unwrap().clone();
        decoy_noncanon[SB_OFF_LEAVES..SB_OFF_LEAVES + 32].fill(0xff);
        let mut decoy_bitflip = accounts.get(&wit_decoy).unwrap().clone();
        decoy_bitflip[SB_OFF_LEAVES + 31] ^= 0x01;
        let mut sr_noncanon = accounts.get(&non_target_sr).unwrap().clone();
        sr_noncanon[SR_OFF_ROOTS..SR_OFF_ROOTS + 32].fill(0xff);
        let mut sr_bitflip = accounts.get(&non_target_sr).unwrap().clone();
        sr_bitflip[SR_OFF_ROOTS + 31] ^= 0x01;
        let mut frontier_bitflip = accounts.get(&non_target_frontier).unwrap().clone();
        frontier_bitflip[SB_OFF_LEAVES + 31] ^= 0x01;
        let mut bad_empty_lane_roots = lane_roots_fr;
        bad_empty_lane_roots[5] = poseidon4(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64));
        let rh_bad_empty_lane = build_rh_raw(&bad_empty_lane_roots, &lane_counts);

        for (label, override_addr, override_bytes) in [
            ("decoy SubtreePage non-canonical Fr", wit_decoy, decoy_noncanon),
            ("decoy SubtreePage 1-bit canonical tamper", wit_decoy, decoy_bitflip),
            ("non-target SubtreeRootPage non-canonical Fr", non_target_sr, sr_noncanon),
            ("non-target SubtreeRootPage 1-bit canonical tamper", non_target_sr, sr_bitflip),
            ("non-target frontier SubtreePage 1-bit tamper", non_target_frontier, frontier_bitflip),
            ("empty lane roots.lane_roots[5] tamper", roots_addr, rh_bad_empty_lane),
        ] {
            let res = reconstruct_witness_strict(
                |addrs, _| {
                    addrs
                        .iter()
                        .map(|a| {
                            if *a == override_addr {
                                Some(override_bytes.clone())
                            } else {
                                accounts.get(a).cloned()
                            }
                        })
                        .collect()
                },
                &program_id,
                0,
                2,
                alice_leaf_idx,
                alice.view_sk,
            );
            assert!(res.is_err(), "R2-C2 ({label}): strict reconstruct_witness must reject");
        }

        // === R2-C3: Untrusted RPC `nf_count = u64::MAX`, `next_leaf = 1 << 36`, HRW cap ===
        // 3a. `nf_count = u64::MAX` with `birthday_slot = 0` & `birthday_slot = 1000` (closed headers):
        //     must NEVER overflow `u64` or OOM/hang!
        let pool_pda = derive_pool_pda(&program_id, 0).0;
        let lane0_pda = derive_lane_pda(&program_id, 0, 0).0;
        let mut st_nf_zero = CompactWalletStore::new(0, 0);
        let mut rpc_calls = 0usize;
        sync_compact_store_with_batch(
            &mut st_nf_zero,
            &fvk,
            |addrs, _| {
                rpc_calls += 1;
                addrs
                    .iter()
                    .map(|a| {
                        if *a == pool_pda {
                            Some(make_pool(1))
                        } else if *a == lane0_pda {
                            Some(make_lane(0, 0, u64::MAX))
                        } else {
                            None
                        }
                    })
                    .collect()
            },
            &program_id,
            SyncOptions::default(),
        )
        .unwrap();
        assert!(rpc_calls <= 4, "R2-C3: lazy NF streaming must halt after first missing chunk (got {rpc_calls})");

        let mut st_nf_bday = CompactWalletStore::new(0, 1000);
        let mut bday_calls = 0usize;
        // Precompute map of probe seqs on demand by returning valid closed NullifierPage headers
        let mut last_probe_lo: u64 = 0;
        let last_probe_hi: u64 = (u64::MAX - 1) / (NF_PER_PAGE as u64) + 1;
        sync_compact_store_with_batch(
            &mut st_nf_bday,
            &fvk,
            |addrs, slice| {
                bday_calls += 1;
                addrs
                    .iter()
                    .map(|a| {
                        if *a == pool_pda {
                            Some(make_pool(1))
                        } else if *a == lane0_pda {
                            Some(make_lane(0, 0, u64::MAX))
                        } else if slice.is_some() && last_probe_lo < last_probe_hi {
                            let mid = last_probe_lo + (last_probe_hi - last_probe_lo) / 2;
                            last_probe_lo = mid + 1;
                            let mut hdr = vec![0u8; NF_PAGE_HEADER_LEN];
                            hdr[0..8].copy_from_slice(&NF_PAGE_MAGIC);
                            hdr[NF_OFF_LANE_ID] = 0;
                            hdr[NF_OFF_COUNT..NF_OFF_COUNT + 2]
                                .copy_from_slice(&(NF_PER_PAGE as u16).to_le_bytes());
                            hdr[NF_OFF_PAGE_SEQ..NF_OFF_PAGE_SEQ + 8]
                                .copy_from_slice(&mid.to_le_bytes());
                            hdr[NF_OFF_CLOSED_SLOT..NF_OFF_CLOSED_SLOT + 8]
                                .copy_from_slice(&500u64.to_le_bytes());
                            Some(hdr)
                        } else {
                            None
                        }
                    })
                    .collect()
            },
            &program_id,
            SyncOptions::default(),
        )
        .unwrap();
        assert_eq!(
            st_nf_bday.lanes[0].next_nf_index,
            u64::MAX,
            "R2-C3: Pass 2 birthday_slot saturating_mul must clamp to u64::MAX without overflow panic"
        );
        assert!(bday_calls <= 70, "R2-C3: binary search + lazy stream must stay bounded (got {bday_calls})");

        // 3b. `next_leaf = MAX_LEAVES_PER_LANE` (`1 << 36`) in sync must reject cleanly without OOM/hang
        let mut st_huge_leaf = CompactWalletStore::new(0, 0);
        let mut huge_calls = 0usize;
        let huge_res = sync_compact_store_with_batch(
            &mut st_huge_leaf,
            &fvk,
            |addrs, _| {
                huge_calls += 1;
                addrs
                    .iter()
                    .map(|a| {
                        if *a == pool_pda {
                            Some(make_pool(1))
                        } else if *a == lane0_pda {
                            Some(make_lane(0, MAX_LEAVES_PER_LANE, 0))
                        } else {
                            None
                        }
                    })
                    .collect()
            },
            &program_id,
            SyncOptions::default(),
        );
        assert!(
            huge_res.is_err(),
            "R2-C3: next_leaf = MAX_LEAVES_PER_LANE must cleanly error on HRW operational bound without OOM/spin"
        );
        assert!(huge_calls <= 10, "R2-C3: lazy Pass 1A/1C must halt immediately on missing pages (got {huge_calls})");

        // 3b-ii. Large but bounded `next_leaf = 10_000_000` (> 104k MemoPages) with missing pages
        //        must lazily halt in <= 6 RPC calls and return Ok without pre-materializing queues
        let mut st_large_leaf = CompactWalletStore::new(0, 0);
        let mut large_calls = 0usize;
        sync_compact_store_with_batch(
            &mut st_large_leaf,
            &fvk,
            |addrs, _| {
                large_calls += 1;
                addrs
                    .iter()
                    .map(|a| {
                        if *a == pool_pda {
                            Some(make_pool(1))
                        } else if *a == lane0_pda {
                            Some(make_lane(0, 10_000_000, 0))
                        } else {
                            None
                        }
                    })
                    .collect()
            },
            &program_id,
            SyncOptions::default(),
        )
        .unwrap();
        assert!(
            large_calls <= 10,
            "R2-C3: lazy Pass 1A/1C on 10M leaves must halt on first missing batch (got {large_calls})"
        );

        // 3c. `lane_counts[0] = MAX_LEAVES_PER_LANE` in `reconstruct_witness_with_batch` (Strict & Fast)
        let mut max_counts = [0u64; NUM_LANES];
        max_counts[0] = MAX_LEAVES_PER_LANE;
        let max_rh_raw = build_rh_raw(&lane_roots_fr, &max_counts);
        for mode in [SyncPrivacyMode::Strict, SyncPrivacyMode::Fast] {
            let res = reconstruct_witness_with_batch(
                |addrs, _| {
                    addrs
                        .iter()
                        .map(|a| if *a == roots_addr { Some(max_rh_raw.clone()) } else { None })
                        .collect()
                },
                &program_id,
                0,
                0,
                0,
                WitnessOptions {
                    privacy_mode: mode,
                    view_sk: Some(alice.view_sk),
                    decoy_epoch_bucket: None,
                },
            );
            assert!(
                res.is_err(),
                "R2-C3: lane_counts = MAX_LEAVES_PER_LANE must return Err before OOM/4B-HRW spin"
            );
        }
        assert!(try_select_hrw_sealed_decoys(
            &alice.view_sk,
            b"sync",
            0,
            &[(0, MAX_HRW_SEALED_SUBTREES + 1)],
            &BTreeSet::new(),
            16,
        )
        .is_err());

        // === R2-C4: Pass 1A missing/lagged `rp=0` never zero-fills; Pass 1A/1B zero-mutation on 1D miss ===
        let sr0_pda = derive_subroot_pda(&program_id, 0, 0, 0).0;
        let sr1_pda = derive_subroot_pda(&program_id, 0, 0, 1).0;
        let sr1_10 = make_subroot(0, 1, &vec![dummy_subroot; 10]);

        // 4a-i: `rp=0 -> None`, `rp=1 -> 10 roots` -> MUST NOT zero-fill 300 entries!
        let mut st_gap0 = CompactWalletStore::new(0, 0);
        sync_compact_store_with_batch(
            &mut st_gap0,
            &fvk,
            |addrs, _| {
                addrs
                    .iter()
                    .map(|a| {
                        if *a == pool_pda {
                            Some(make_pool(1))
                        } else if *a == lane0_pda {
                            Some(make_lane(0, 310 * (SUBTREE_LEAVES as u64), 0))
                        } else if *a == sr1_pda {
                            Some(sr1_10.clone())
                        } else {
                            None
                        }
                    })
                    .collect()
            },
            &program_id,
            SyncOptions::default(),
        )
        .unwrap();
        assert!(
            st_gap0.lanes[0].finalized_subroots.is_empty(),
            "R2-C4: missing rp=0 must never be zero-filled when rp=1 is present"
        );

        // 4a-ii: `rp=0 -> 299 roots` (lagged), `rp=1 -> 10 roots` -> stops short of `finalized_count = 310`
        //        without zero-filling slot 299 AND withholds committing unverified partial subroots!
        let sr0_299 = make_subroot(0, 0, &vec![dummy_subroot; SUBROOTS_PER_PAGE - 1]);
        let mut st_lag299 = CompactWalletStore::new(0, 0);
        // Set next_memo_leaf = 310*256 so Pass 1C/1D fetch 0 pages and only Pass 1A runs
        st_lag299.lanes[0].next_memo_leaf = 310 * (SUBTREE_LEAVES as u64);
        sync_compact_store_with_batch(
            &mut st_lag299,
            &fvk,
            |addrs, _| {
                addrs
                    .iter()
                    .map(|a| {
                        if *a == pool_pda {
                            Some(make_pool(1))
                        } else if *a == lane0_pda {
                            Some(make_lane(0, 310 * (SUBTREE_LEAVES as u64), 0))
                        } else if *a == sr0_pda {
                            Some(sr0_299.clone())
                        } else if *a == sr1_pda {
                            Some(sr1_10.clone())
                        } else {
                            None
                        }
                    })
                    .collect()
            },
            &program_id,
            SyncOptions::default(),
        )
        .unwrap();
        assert!(
            st_lag299.lanes[0].finalized_subroots.is_empty(),
            "R2-C4 + F1: lagged rp=0 (299/300) must neither zero-fill slot 299 nor commit unverified partial subroots"
        );

        // 4b: Pass 1A + Pass 1B zero-mutation when a Pass 1D decoy SubtreePage is missing
        let mut st_1d_drop = CompactWalletStore::new(0, 200);
        let mut dropped_one_sealed = false;
        sync_compact_store_with_batch(
            &mut st_1d_drop,
            &fvk,
            |addrs, slice| {
                addrs
                    .iter()
                    .map(|a| {
                        if !dropped_one_sealed && sealed_addrs.contains(a) {
                            dropped_one_sealed = true;
                            return None;
                        }
                        let full = accounts.get(a)?;
                        if let Some(sl) = slice {
                            Some(full[sl.offset..sl.offset + sl.length].to_vec())
                        } else {
                            Some(full.clone())
                        }
                    })
                    .collect()
            },
            &program_id,
            SyncOptions::default(),
        )
        .unwrap();
        assert!(dropped_one_sealed, "R2-C4: expected Pass 1D to request at least one sealed SubtreePage");
        for l in 0..4 {
            assert!(
                st_1d_drop.lanes[l].finalized_subroots.is_empty(),
                "R2-C4: Pass 1A finalized_subroots must NOT mutate on Pass 1D miss"
            );
            assert_eq!(
                st_1d_drop.lanes[l].next_memo_leaf, 0,
                "R2-C4: Pass 1B next_memo_leaf must NOT mutate on Pass 1D miss"
            );
        }

        // 4c: Header `(pool_id, lane_id, page_seq)` mismatch rejected across Pass 1A, 1B, 1C, 1D, 2
        let bad_sr_addr = derive_subroot_pda(&program_id, 0, 0, 0).0;
        let mut bad_sr_hdr = accounts.get(&bad_sr_addr).unwrap().clone();
        bad_sr_hdr[SR_OFF_POOL_ID..SR_OFF_POOL_ID + 4].copy_from_slice(&99u32.to_le_bytes());

        let bad_memo_addr = derive_memo_pda(&program_id, 0, 0, 0).0;
        let mut bad_memo_hdr = accounts.get(&bad_memo_addr).unwrap().clone();
        bad_memo_hdr[MM_OFF_POOL_ID..MM_OFF_POOL_ID + 4].copy_from_slice(&99u32.to_le_bytes());

        let mut bad_sub_hdr = accounts.get(&decoy_sub_addr).unwrap().clone();
        bad_sub_hdr[SB_OFF_POOL_ID..SB_OFF_POOL_ID + 4].copy_from_slice(&99u32.to_le_bytes());

        let mut bad_nf_hdr = accounts.get(&nf0_addr).unwrap().clone();
        bad_nf_hdr[NF_OFF_POOL_ID..NF_OFF_POOL_ID + 4].copy_from_slice(&99u32.to_le_bytes());

        for (label, bday, bad_addr, bad_bytes) in [
            ("Pass 1A SubtreeRootPage pool_id", 0u64, bad_sr_addr, bad_sr_hdr),
            ("Pass 1C MemoPage pool_id", 0u64, bad_memo_addr, bad_memo_hdr.clone()),
            ("Pass 1B MemoPage birthday header pool_id", 200u64, derive_memo_pda(&program_id, 0, 0, 7).0, {
                let mut m = accounts.get(&derive_memo_pda(&program_id, 0, 0, 7).0).unwrap().clone();
                m[MM_OFF_POOL_ID..MM_OFF_POOL_ID + 4].copy_from_slice(&99u32.to_le_bytes());
                m
            }),
            ("Pass 1D SubtreePage pool_id", 0u64, decoy_sub_addr, bad_sub_hdr),
            ("Pass 2 NullifierPage pool_id", 0u64, nf0_addr, bad_nf_hdr),
        ] {
            let mut st = CompactWalletStore::new(0, bday);
            let res = sync_compact_store_with_batch(
                &mut st,
                &fvk,
                |addrs, slice| {
                    addrs
                        .iter()
                        .map(|a| {
                            let full = if *a == bad_addr {
                                &bad_bytes
                            } else {
                                accounts.get(a)?
                            };
                            if let Some(sl) = slice {
                                Some(full[sl.offset..sl.offset + sl.length].to_vec())
                            } else {
                                Some(full.clone())
                            }
                        })
                        .collect()
                },
                &program_id,
                SyncOptions::default(),
            );
            assert!(res.is_err(), "R2-C4 ({label}): header mismatch must return Err");
        }
    }

    #[test]
    fn r3_c1_c2_c3_pass2_rollback_subroot_verification_and_monotonic_frontier() {
        use audren_circuits::merkle::compute_super_root_4ary;
        use audren_core::layout::{NF_OFF_CLOSED_SLOT, NF_OFF_POOL_ID};
        use audren_core::{ROOT_RING_EPOCH, ZERO_HASHES_4ARY};

        let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
        let alice = AudrenKeys::from_seed(&[0x73u8; 32]);
        let fvk = alice.full_viewing_key();
        let sol_asset = derive_asset_id(&WSOL_MINT);

        let slice_lookup = |accounts: &BTreeMap<Address, Vec<u8>>,
                            addrs: &[Address],
                            slice: Option<AccountDataSlice>|
         -> Vec<Option<Vec<u8>>> {
            addrs
                .iter()
                .map(|a| {
                    let full = accounts.get(a)?;
                    match slice {
                        Some(sl) => {
                            let end = sl.offset.saturating_add(sl.length).min(full.len());
                            Some(full[sl.offset..end].to_vec())
                        }
                        None => Some(full.clone()),
                    }
                })
                .collect()
        };

        // =====================================================================
        // R3-C1: Pass 1 incomplete (`!all_caught_up`) + Pass 2 fails mid-stream
        //        -> `next_nf_index` is strictly restored to pre-sync value for
        //           BOTH `birthday_slot == 0` AND `birthday_slot > 0`!
        // =====================================================================
        {
            let (tw, bl, memo_106) =
                encrypt_note_memo(&alice.view_pk, [0x74u8; 32], 5_555_555, &WSOL_MINT).unwrap();
            let cm = compute_note_commitment(
                derive_stealth_owner(alice.spend_pk, tw),
                sol_asset,
                5_555_555,
                bl,
            );
            let alice_nf = fvk.real_nullifier(cm, 0).unwrap();
            let alice_nf_prefix: [u8; NF_PREFIX_LEN] =
                alice_nf[0..NF_PREFIX_LEN].try_into().unwrap();

            let mut stranger_page: Vec<[u8; NF_PREFIX_LEN]> = (0..NF_PER_PAGE)
                .map(|i| {
                    let mut p = [0u8; NF_PREFIX_LEN];
                    p[0] = 0xee;
                    p[1] = (i & 0xff) as u8;
                    p[2] = ((i >> 8) & 0xff) as u8;
                    p
                })
                .collect();
            let mut nf3_prefixes = stranger_page.clone();
            nf3_prefixes[10] = alice_nf_prefix;

            let nf_pages_total = 5usize; // pages 0..=4; 0..=2 closed < 1000, page 3 closed 1200, page 4 open
            let nf_total = ((nf_pages_total - 1) * NF_PER_PAGE + 5) as u64;

            let lane0_root =
                compute_lane_root_from_subroots_and_frontier(&[], Some(&[cm]), 1).unwrap();
            let mut accounts: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
            accounts.insert(derive_pool_pda(&program_id, 0).0, make_pool(1));
            accounts.insert(
                derive_lane_pda(&program_id, 0, 0).0,
                make_lane_with_root(0, 1, nf_total, lane0_root),
            );
            let sub0_addr = derive_subtree_pda(&program_id, 0, 0, 0).0;
            accounts.insert(sub0_addr, make_subtree(0, 0, &[cm]));
            let mut m0 = make_memo(0, 0, 1, 0);
            write_memo(&mut m0, 0, &memo_106);
            accounts.insert(derive_memo_pda(&program_id, 0, 0, 0).0, m0);

            for p in 0..nf_pages_total {
                let addr = derive_nf_page_pda(&program_id, 0, 0, p as u64).0;
                let mut raw = if p == 3 {
                    make_nf_page(0, p as u64, &nf3_prefixes)
                } else if p == nf_pages_total - 1 {
                    stranger_page[0][0] = 0xef;
                    make_nf_page(0, p as u64, &stranger_page[..5])
                } else {
                    make_nf_page(0, p as u64, &stranger_page)
                };
                let closed_slot = match p {
                    0 => 100u64,
                    1 => 200u64,
                    2 => 300u64,
                    3 => 1200u64,
                    _ => 0u64,
                };
                raw[NF_OFF_CLOSED_SLOT..NF_OFF_CLOSED_SLOT + 8]
                    .copy_from_slice(&closed_slot.to_le_bytes());
                accounts.insert(addr, raw);
            }

            let nf1_addr = derive_nf_page_pda(&program_id, 0, 0, 1).0;
            let mut bad_nf1 = accounts.get(&nf1_addr).unwrap().clone();
            bad_nf1[NF_OFF_POOL_ID..NF_OFF_POOL_ID + 4].copy_from_slice(&77u32.to_le_bytes());

            // 1a. `birthday_slot = 0`, pre-sync `next_nf_index = 5`: Pass 1D drops `sub0` ->
            //     Pass 2 ingests page 0 (advancing `next_nf_index` to 600), then page 1 errors ->
            //     `next_nf_index` MUST roll back strictly to `5`!
            let mut st0 = CompactWalletStore::new(0, 0);
            st0.lanes[0].next_nf_index = 5;
            let res0 = sync_compact_store_with_batch(
                &mut st0,
                &fvk,
                |addrs, slice| {
                    addrs
                        .iter()
                        .map(|a| {
                            if *a == sub0_addr {
                                return None;
                            }
                            let full = if *a == nf1_addr {
                                &bad_nf1
                            } else {
                                accounts.get(a)?
                            };
                            match slice {
                                Some(sl) => {
                                    let end = sl.offset.saturating_add(sl.length).min(full.len());
                                    Some(full[sl.offset..end].to_vec())
                                }
                                None => Some(full.clone()),
                            }
                        })
                        .collect()
                },
                &program_id,
                SyncOptions::default(),
            );
            assert!(res0.is_err(), "R3-C1 (bday=0): bad NF page 1 must return Err");
            assert_eq!(
                st0.lanes[0].next_nf_index, 5,
                "R3-C1 (bday=0): next_nf_index must strictly roll back to pre-sync value 5 on Pass 2 Err"
            );

            // 1b. `birthday_slot = 1000`, pre-sync `next_nf_index = 0`: Pass 1D drops `sub0` ->
            //     Pass 2 binary search skips pages 0..=2 (`skip_to = 1800`), ingests page 3 (2400),
            //     then page 4 errors -> `next_nf_index` MUST roll back strictly to `0`!
            let nf4_addr = derive_nf_page_pda(&program_id, 0, 0, 4).0;
            let mut bad_nf4 = accounts.get(&nf4_addr).unwrap().clone();
            bad_nf4[NF_OFF_POOL_ID..NF_OFF_POOL_ID + 4].copy_from_slice(&88u32.to_le_bytes());

            let mut st_bday = CompactWalletStore::new(0, 1000);
            let res_bday = sync_compact_store_with_batch(
                &mut st_bday,
                &fvk,
                |addrs, slice| {
                    addrs
                        .iter()
                        .map(|a| {
                            if *a == sub0_addr {
                                return None;
                            }
                            let full = if *a == nf4_addr && slice.is_none() {
                                &bad_nf4
                            } else {
                                accounts.get(a)?
                            };
                            match slice {
                                Some(sl) => {
                                    let end = sl.offset.saturating_add(sl.length).min(full.len());
                                    Some(full[sl.offset..end].to_vec())
                                }
                                None => Some(full.clone()),
                            }
                        })
                        .collect()
                },
                &program_id,
                SyncOptions::default(),
            );
            assert!(res_bday.is_err(), "R3-C1 (bday>0): bad NF page 4 must return Err");
            assert_eq!(
                st_bday.lanes[0].next_nf_index, 0,
                "R3-C1 (bday>0): next_nf_index must strictly roll back to 0 on Pass 2 Err"
            );

            // Subsequent healthy sync discovers Alice's note AND marks it spent via NF page 3!
            let (_, _, disc) = sync_compact_store_with_batch(
                &mut st_bday,
                &fvk,
                |addrs, slice| slice_lookup(&accounts, addrs, slice),
                &program_id,
                SyncOptions::default(),
            )
            .unwrap();
            assert_eq!(disc, 1);
            assert!(
                st_bday.notes[0].spent,
                "R3-C1: healthy retry after rolled-back Pass 2 Err must detect note spend"
            );
            assert_eq!(st_bday.lanes[0].next_nf_index, nf_total);
        }

        // =====================================================================
        // R3-C2: Sealed `SubtreePage` when `SubtreeRootPage` is missing/lagged
        //        (`count = 0`) -> uniform `any_pass1d_subtree_missing = true`,
        //        zero store mutation, `frozen_intra_siblings` NOT poisoned
        //        (uniformly on BOTH hit and decoy lanes), plus commitment match
        //        defense-in-depth & no frontier-256 unverified freeze!
        // =====================================================================
        {
            let dummy_leaves: Vec<Fr> =
                (0..SUBTREE_LEAVES).map(|i| Fr::from((i + 30) as u64)).collect();
            let dummy_subroot = compute_subtree_256_root(&dummy_leaves, SUBTREE_LEAVES);
            let dummy_frontier: Vec<Fr> = (0..4).map(|i| Fr::from((i + 500) as u64)).collect();

            let alice_leaf_idx = SUBTREE_LEAVES as u64 + 7; // lane 2, subtree 1, slot 7
            let (tw, bl, memo_106) =
                encrypt_note_memo(&alice.view_pk, [0x75u8; 32], 4_444_444, &WSOL_MINT).unwrap();
            let alice_cm = compute_note_commitment(
                derive_stealth_owner(alice.spend_pk, tw),
                sol_asset,
                4_444_444,
                bl,
            );
            let mut hit_leaves = dummy_leaves.clone();
            hit_leaves[7] = alice_cm;
            let hit_subroot = compute_subtree_256_root(&hit_leaves, SUBTREE_LEAVES);

            let sealed_per_lane = 5usize;
            let leaves_per_lane = sealed_per_lane * SUBTREE_LEAVES + 4;
            let memos_per_lane = leaves_per_lane.div_ceil(MEMO_NOTES_PER_PAGE);

            let mut accounts: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
            accounts.insert(derive_pool_pda(&program_id, 0).0, make_pool(4));
            let mut sealed_addrs: BTreeSet<Address> = BTreeSet::new();
            for l in 0..4u8 {
                let roots: Vec<Fr> = (0..sealed_per_lane)
                    .map(|s| if l == 2 && s == 1 { hit_subroot } else { dummy_subroot })
                    .collect();
                let lane_root = compute_lane_root_from_subroots_and_frontier(
                    &roots,
                    Some(&dummy_frontier),
                    dummy_frontier.len(),
                )
                .unwrap();
                accounts.insert(
                    derive_lane_pda(&program_id, 0, l).0,
                    make_lane_with_root(
                        l,
                        leaves_per_lane as u64,
                        if l == 0 { 2 } else { 0 },
                        lane_root,
                    ),
                );
                accounts.insert(
                    derive_subroot_pda(&program_id, 0, l, 0).0,
                    make_subroot(l, 0, &roots),
                );
                for s in 0..sealed_per_lane {
                    let addr = derive_subtree_pda(&program_id, 0, l, s as u64).0;
                    sealed_addrs.insert(addr);
                    accounts.insert(
                        addr,
                        make_subtree(
                            l,
                            s as u64,
                            if l == 2 && s == 1 { &hit_leaves } else { &dummy_leaves },
                        ),
                    );
                }
                accounts.insert(
                    derive_subtree_pda(&program_id, 0, l, sealed_per_lane as u64).0,
                    make_subtree(l, sealed_per_lane as u64, &dummy_frontier),
                );
                for m in 0..memos_per_lane {
                    let cnt = MEMO_NOTES_PER_PAGE
                        .min(leaves_per_lane - m * MEMO_NOTES_PER_PAGE) as u16;
                    let mut mraw = make_memo(l, m as u64, cnt, 0);
                    if l == 2 && m == (alice_leaf_idx as usize) / MEMO_NOTES_PER_PAGE {
                        write_memo(
                            &mut mraw,
                            (alice_leaf_idx as usize) % MEMO_NOTES_PER_PAGE,
                            &memo_106,
                        );
                    }
                    accounts.insert(derive_memo_pda(&program_id, 0, l, m as u64).0, mraw);
                }
            }
            let nf0_addr = derive_nf_page_pda(&program_id, 0, 0, 0).0;
            accounts.insert(
                nf0_addr,
                make_nf_page(0, 0, &[[0x11u8; NF_PREFIX_LEN], [0x22u8; NF_PREFIX_LEN]]),
            );

            // Identify a decoy lane ( != 2 ) that appears in Pass 1D's 16-page sealed batch
            let mut probe_store = CompactWalletStore::new(0, 0);
            let mut probe_sealed: Vec<Address> = Vec::new();
            sync_compact_store_with_batch(
                &mut probe_store,
                &fvk,
                |addrs, slice| {
                    for &a in addrs {
                        if sealed_addrs.contains(&a) {
                            probe_sealed.push(a);
                        }
                    }
                    slice_lookup(&accounts, addrs, slice)
                },
                &program_id,
                SyncOptions::default(),
            )
            .unwrap();
            let decoy_lane: u8 = (0..4u8)
                .find(|&l| {
                    l != 2
                        && (0..sealed_per_lane).any(|s| {
                            probe_sealed.contains(&derive_subtree_pda(&program_id, 0, l, s as u64).0)
                        })
                })
                .expect("at least one non-hit lane in sealed batch");

            // 2a. Lagged `SubtreeRootPage` (`count = 0`) OR missing (`None`) on hit lane 2 vs decoy lane:
            //     BOTH must withhold ALL store mutations, run Pass 2 & roll back `next_nf_index`,
            //     and produce 100% identical Sync #2 RPC traffic!
            let hit_sr_addr = derive_subroot_pda(&program_id, 0, 2, 0).0;
            let decoy_sr_addr = derive_subroot_pda(&program_id, 0, decoy_lane, 0).0;
            let lagged_hit_sr = make_subroot(2, 0, &[]);
            let lagged_decoy_sr = make_subroot(decoy_lane, 0, &[]);

            let mut retry_logs: Vec<Vec<Vec<Address>>> = Vec::new();
            for (label, target_sr, replacement) in [
                ("hit lane lagged count=0", hit_sr_addr, Some(lagged_hit_sr.clone())),
                ("decoy lane lagged count=0", decoy_sr_addr, Some(lagged_decoy_sr.clone())),
                ("hit lane missing None", hit_sr_addr, None),
                ("decoy lane missing None", decoy_sr_addr, None),
            ] {
                let mut st = CompactWalletStore::new(0, 0);
                let mut pass2_seen = false;
                let (_, _, disc) = sync_compact_store_with_batch(
                    &mut st,
                    &fvk,
                    |addrs, slice| {
                        if addrs.contains(&nf0_addr) {
                            pass2_seen = true;
                        }
                        addrs
                            .iter()
                            .map(|a| {
                                if *a == target_sr {
                                    return replacement.clone();
                                }
                                let full = accounts.get(a)?;
                                match slice {
                                    Some(sl) => {
                                        let end =
                                            sl.offset.saturating_add(sl.length).min(full.len());
                                        Some(full[sl.offset..end].to_vec())
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
                assert_eq!(disc, 0, "R3-C2 ({label}): discovered must be 0");
                assert!(pass2_seen, "R3-C2 ({label}): Pass 2 must still execute unconditionally");
                assert!(st.notes.is_empty(), "R3-C2 ({label}): store.notes must stay untouched");
                for l in 0..4 {
                    assert!(
                        st.lanes[l].finalized_subroots.is_empty(),
                        "R3-C2 ({label}): finalized_subroots must stay untouched on lane {l}"
                    );
                    assert_eq!(
                        st.lanes[l].next_memo_leaf, 0,
                        "R3-C2 ({label}): next_memo_leaf must stay 0 on lane {l}"
                    );
                    assert_eq!(
                        st.lanes[l].next_nf_index, 0,
                        "R3-C2 ({label}): next_nf_index must roll back to 0 on lane {l}"
                    );
                }

                let mut retry_log: Vec<Vec<Address>> = Vec::new();
                let (_, _, d_retry) = sync_compact_store_with_batch(
                    &mut st,
                    &fvk,
                    |addrs, slice| {
                        retry_log.push(addrs.to_vec());
                        slice_lookup(&accounts, addrs, slice)
                    },
                    &program_id,
                    SyncOptions::default(),
                )
                .unwrap();
                assert_eq!(d_retry, 1, "R3-C2 ({label}): healthy retry must discover note");
                assert!(st.notes[0].frozen_intra_siblings.is_some());
                retry_logs.push(retry_log);
            }
            assert_eq!(
                retry_logs[0], retry_logs[1],
                "R3-C2: Sync #2 traffic must be identical after hit-lane vs decoy-lane lagged SubtreeRootPage"
            );
            assert_eq!(
                retry_logs[2], retry_logs[3],
                "R3-C2: Sync #2 traffic must be identical after hit-lane vs decoy-lane missing SubtreeRootPage"
            );

            // 2b. Existing unfrozen owned note inside a sealed subtree when SubtreeRootPage is lagged
            //     AND RPC serves a POISONED SubtreePage -> MUST NOT poison `frozen_intra_siblings`!
            let mut poisoned_hit_leaves = hit_leaves.clone();
            poisoned_hit_leaves[0] = Fr::from(9_999_999u64);
            let poisoned_hit_sub = make_subtree(2, 1, &poisoned_hit_leaves);
            let hit_sub_addr = derive_subtree_pda(&program_id, 0, 2, 1).0;

            let mut st_poison = CompactWalletStore::new(0, 0);
            for l in 0..4 {
                st_poison.lanes[l].next_memo_leaf = leaves_per_lane as u64;
            }
            let dec_memo = DecryptedMemo {
                amount: 4_444_444,
                mint: WSOL_MINT,
                tweak: tw,
                blinding: bl,
                memo_version: audren_core::layout::MEMO_VERSION_V1,
                memo_flags: 0,
                payment_id: [0u8; audren_core::layout::MEMO_PAYMENT_ID_LEN],
                is_dynamic: false,
            };
            st_poison
                .record_verified_memo(&fvk, 2, alice_leaf_idx, &dec_memo, fr_to_be_bytes(&alice_cm))
                .unwrap();
            assert!(st_poison.notes[0].frozen_intra_siblings.is_none());

            sync_compact_store_with_batch(
                &mut st_poison,
                &fvk,
                |addrs, slice| {
                    addrs
                        .iter()
                        .map(|a| {
                            if *a == hit_sr_addr {
                                return Some(lagged_hit_sr.clone());
                            }
                            if *a == hit_sub_addr {
                                return Some(poisoned_hit_sub.clone());
                            }
                            let full = accounts.get(a)?;
                            match slice {
                                Some(sl) => {
                                    let end = sl.offset.saturating_add(sl.length).min(full.len());
                                    Some(full[sl.offset..end].to_vec())
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
            assert!(
                st_poison.notes[0].frozen_intra_siblings.is_none(),
                "R3-C2: poisoned SubtreePage with lagged SubtreeRootPage must NEVER freeze note"
            );

            // 2c. Defense-in-depth: forged matching (SubtreeRootPage, SubtreePage) pair is rejected
            //     immediately when LaneTreeState.current_root is honest; even when LaneTreeState is
            //     ALSO forged to match `wrong_cm_sr`, `leaves_be[offset] != note.commitment` still
            //     keeps `frozen_intra_siblings` as `None`!
            let mut wrong_cm_leaves = dummy_leaves.clone();
            wrong_cm_leaves[7] = Fr::from(123_456u64); // != alice_cm
            let wrong_cm_subroot = compute_subtree_256_root(&wrong_cm_leaves, SUBTREE_LEAVES);
            let wrong_cm_sub = make_subtree(2, 1, &wrong_cm_leaves);
            let wrong_cm_roots = [
                dummy_subroot,
                wrong_cm_subroot,
                dummy_subroot,
                dummy_subroot,
                dummy_subroot,
            ];
            let wrong_cm_sr = make_subroot(2, 0, &wrong_cm_roots);
            let forged_lane2_root = compute_lane_root_from_subroots_and_frontier(
                &wrong_cm_roots,
                Some(&dummy_frontier),
                dummy_frontier.len(),
            )
            .unwrap();
            let lane2_pda = derive_lane_pda(&program_id, 0, 2).0;
            let forged_lane2 = make_lane_with_root(2, leaves_per_lane as u64, 0, forged_lane2_root);

            assert!(
                sync_compact_store_with_batch(
                    &mut st_poison,
                    &fvk,
                    |addrs, slice| {
                        addrs
                            .iter()
                            .map(|a| {
                                if *a == hit_sr_addr {
                                    return Some(wrong_cm_sr.clone());
                                }
                                if *a == hit_sub_addr {
                                    return Some(wrong_cm_sub.clone());
                                }
                                let full = accounts.get(a)?;
                                match slice {
                                    Some(sl) => {
                                        let end =
                                            sl.offset.saturating_add(sl.length).min(full.len());
                                        Some(full[sl.offset..end].to_vec())
                                    }
                                    None => Some(full.clone()),
                                }
                            })
                            .collect()
                    },
                    &program_id,
                    SyncOptions::default(),
                )
                .is_err(),
                "F1: forged (SubtreeRootPage, SubtreePage) against honest LaneTreeState must be rejected"
            );

            sync_compact_store_with_batch(
                &mut st_poison,
                &fvk,
                |addrs, slice| {
                    addrs
                        .iter()
                        .map(|a| {
                            if *a == lane2_pda {
                                return Some(forged_lane2.clone());
                            }
                            if *a == hit_sr_addr {
                                return Some(wrong_cm_sr.clone());
                            }
                            if *a == hit_sub_addr {
                                return Some(wrong_cm_sub.clone());
                            }
                            let full = accounts.get(a)?;
                            match slice {
                                Some(sl) => {
                                    let end = sl.offset.saturating_add(sl.length).min(full.len());
                                    Some(full[sl.offset..end].to_vec())
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
            assert!(
                st_poison.notes[0].frozen_intra_siblings.is_none(),
                "R3-C2 defense-in-depth: leaf commitment mismatch must prevent freezing existing note"
            );

            // 2d. Defense-in-depth: lagging LaneTreeState (`next_leaf = 250`, `fc = 0`) paired with
            //     a 256-leaf live-advancing frontier SubtreePage (matching `current_root` on `0..250`)
            //     must NEVER freeze an unfrozen owned note AND must cap committed frontier_leaves to 250!
            let mut st_unverified_256 = CompactWalletStore::new(0, 0);
            st_unverified_256.lanes[0].next_memo_leaf = 250;
            let mut unverified_leaves = dummy_leaves.clone();
            unverified_leaves[7] = alice_cm;
            let unverified_sub0 = make_subtree(0, 0, &unverified_leaves);
            let lane0_250_root = compute_lane_root_from_subroots_and_frontier(
                &[],
                Some(&unverified_leaves[..250]),
                250,
            )
            .unwrap();
            st_unverified_256
                .record_verified_memo(&fvk, 0, 7, &dec_memo, fr_to_be_bytes(&alice_cm))
                .unwrap();
            let pool_pda = derive_pool_pda(&program_id, 0).0;
            let lane0_pda = derive_lane_pda(&program_id, 0, 0).0;
            let sub0_pda = derive_subtree_pda(&program_id, 0, 0, 0).0;
            sync_compact_store_with_batch(
                &mut st_unverified_256,
                &fvk,
                |addrs, _| {
                    addrs
                        .iter()
                        .map(|a| {
                            if *a == pool_pda {
                                Some(make_pool(1))
                            } else if *a == lane0_pda {
                                Some(make_lane_with_root(0, 250, 0, lane0_250_root))
                            } else if *a == sub0_pda {
                                Some(unverified_sub0.clone())
                            } else {
                                None
                            }
                        })
                        .collect()
                },
                &program_id,
                SyncOptions::default(),
            )
            .unwrap();
            assert!(
                st_unverified_256.notes[0].frozen_intra_siblings.is_none(),
                "R3-C2 defense-in-depth: unverified frontier SubtreePage with 256 leaves must NEVER freeze note"
            );
            assert_eq!(
                st_unverified_256.lanes[0].frontier_leaves.len(),
                250,
                "F1: live-advancing frontier commit must be capped to verified frontier_rem (250)"
            );
        }

        // =====================================================================
        // R3-C3: Monotonicity guards for `frontier_sub_seq`, `frontier_leaves`,
        //        and `prev_sealed_sub_seq` against lagging RPC replicas!
        // =====================================================================
        {
            let total_leaves_520 = 520usize; // 2 sealed (0, 1) + 8 frontier in subtree 2
            let mut all_leaves: Vec<Fr> = Vec::with_capacity(total_leaves_520);

            let (tw200, bl200, memo200) =
                encrypt_note_memo(&alice.view_pk, [0x76u8; 32], 2_000_000, &WSOL_MINT).unwrap();
            let cm200 = compute_note_commitment(
                derive_stealth_owner(alice.spend_pk, tw200),
                sol_asset,
                2_000_000,
                bl200,
            );
            let (tw257, bl257, memo257) =
                encrypt_note_memo(&alice.view_pk, [0x77u8; 32], 3_000_000, &WSOL_MINT).unwrap();
            let cm257 = compute_note_commitment(
                derive_stealth_owner(alice.spend_pk, tw257),
                sol_asset,
                3_000_000,
                bl257,
            );
            let (tw515, bl515, memo515) =
                encrypt_note_memo(&alice.view_pk, [0x78u8; 32], 4_000_000, &WSOL_MINT).unwrap();
            let cm515 = compute_note_commitment(
                derive_stealth_owner(alice.spend_pk, tw515),
                sol_asset,
                4_000_000,
                bl515,
            );

            for i in 0..total_leaves_520 {
                if i == 200 {
                    all_leaves.push(cm200);
                } else if i == 257 {
                    all_leaves.push(cm257);
                } else if i == 515 {
                    all_leaves.push(cm515);
                } else {
                    all_leaves.push(Fr::from((i + 1) as u64));
                }
            }

            let sr_root0 = compute_subtree_256_root(&all_leaves[0..256], 256);
            let sr_root1 = compute_subtree_256_root(&all_leaves[256..512], 256);

            let build_snapshot = |next_leaf: usize| -> BTreeMap<Address, Vec<u8>> {
                let mut acc: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
                acc.insert(derive_pool_pda(&program_id, 0).0, make_pool(1));
                let fc = next_leaf / SUBTREE_LEAVES;
                let frem = next_leaf % SUBTREE_LEAVES;
                let mut roots = Vec::new();
                if fc >= 1 {
                    roots.push(sr_root0);
                }
                if fc >= 2 {
                    roots.push(sr_root1);
                }
                let frontier_opt = (frem > 0).then(|| &all_leaves[fc * SUBTREE_LEAVES..next_leaf]);
                let lane0_root =
                    compute_lane_root_from_subroots_and_frontier(&roots, frontier_opt, frem)
                        .unwrap();
                acc.insert(
                    derive_lane_pda(&program_id, 0, 0).0,
                    make_lane_with_root(0, next_leaf as u64, 0, lane0_root),
                );
                acc.insert(
                    derive_subroot_pda(&program_id, 0, 0, 0).0,
                    make_subroot(0, 0, &roots),
                );
                for s in 0..fc {
                    acc.insert(
                        derive_subtree_pda(&program_id, 0, 0, s as u64).0,
                        make_subtree(
                            0,
                            s as u64,
                            &all_leaves[s * SUBTREE_LEAVES..(s + 1) * SUBTREE_LEAVES],
                        ),
                    );
                }
                if frem > 0 {
                    acc.insert(
                        derive_subtree_pda(&program_id, 0, 0, fc as u64).0,
                        make_subtree(
                            0,
                            fc as u64,
                            &all_leaves[fc * SUBTREE_LEAVES..fc * SUBTREE_LEAVES + frem],
                        ),
                    );
                }
                let memos = next_leaf.div_ceil(MEMO_NOTES_PER_PAGE);
                for m in 0..memos {
                    let cnt = MEMO_NOTES_PER_PAGE.min(next_leaf - m * MEMO_NOTES_PER_PAGE);
                    let mut mraw = make_memo(0, m as u64, cnt as u16, 0);
                    for (idx, memo_bytes) in [(200usize, &memo200), (257, &memo257), (515, &memo515)]
                    {
                        if idx < next_leaf && idx / MEMO_NOTES_PER_PAGE == m {
                            write_memo(&mut mraw, idx % MEMO_NOTES_PER_PAGE, memo_bytes);
                        }
                    }
                    acc.insert(derive_memo_pda(&program_id, 0, 0, m as u64).0, mraw);
                }
                acc
            };

            let build_snap_at = |next_leaf: usize| -> (RootSnapshotChoice, Fr) {
                let fc = next_leaf / SUBTREE_LEAVES;
                let frem = next_leaf % SUBTREE_LEAVES;
                let mut roots = Vec::new();
                if fc >= 1 {
                    roots.push(sr_root0);
                }
                if fc >= 2 {
                    roots.push(sr_root1);
                }
                let frontier_opt = (frem > 0).then(|| &all_leaves[fc * SUBTREE_LEAVES..next_leaf]);
                let lane0_root =
                    compute_lane_root_from_subroots_and_frontier(&roots, frontier_opt, frem)
                        .unwrap();
                let mut lane_roots_fr =
                    [fr_from_be_bytes_strict(&ZERO_HASHES_4ARY[18]).unwrap(); NUM_LANES];
                lane_roots_fr[0] = lane0_root;
                let sr = compute_super_root_4ary(&lane_roots_fr);
                let mut lane_roots = [[0u8; 32]; NUM_LANES];
                let mut lane_counts = [0u64; NUM_LANES];
                for i in 0..NUM_LANES {
                    lane_roots[i] = fr_to_be_bytes(&lane_roots_fr[i]);
                }
                lane_counts[0] = next_leaf as u64;
                (
                    RootSnapshotChoice {
                        ring_kind: ROOT_RING_EPOCH,
                        ring_idx: 0,
                        slot: 100,
                        super_root: fr_to_be_bytes(&sr),
                        lane_roots,
                        lane_counts,
                    },
                    sr,
                )
            };

            // Sync 1 at `next_leaf = 260` (1 sealed subtree + 4 frontier leaves)
            let snap260 = build_snapshot(260);
            let mut store = CompactWalletStore::new(0, 0);
            let (_, _, d1) = sync_compact_store_with_batch(
                &mut store,
                &fvk,
                |addrs, slice| slice_lookup(&snap260, addrs, slice),
                &program_id,
                SyncOptions::default(),
            )
            .unwrap();
            assert_eq!(d1, 2);
            assert_eq!(store.lanes[0].finalized_subroots.len(), 1);
            assert_eq!(store.lanes[0].frontier_sub_seq, 1);
            assert_eq!(store.lanes[0].frontier_leaves.len(), 4);
            assert_eq!(store.lanes[0].prev_sealed_sub_seq, Some(0));
            assert_eq!(store.lanes[0].prev_sealed_leaves.len(), SUBTREE_LEAVES);

            let (snap_choice260, sr260) = build_snap_at(260);
            let (snap_choice250, sr250) = build_snap_at(250);
            let note257 = store
                .notes
                .iter()
                .find(|n| n.leaf_index == 257)
                .unwrap()
                .clone();
            let note200 = store
                .notes
                .iter()
                .find(|n| n.leaf_index == 200)
                .unwrap()
                .clone();

            // Sync 2 against lagging RPC replicas at `next_leaf = 254`, `256`, and `258`:
            // `frontier_sub_seq`, `frontier_leaves`, and `prev_sealed_sub_seq` MUST NEVER regress!
            for lagged_leaf in [254usize, 256, 258] {
                let lagged_snap = build_snapshot(lagged_leaf);
                sync_compact_store_with_batch(
                    &mut store,
                    &fvk,
                    |addrs, slice| slice_lookup(&lagged_snap, addrs, slice),
                    &program_id,
                    SyncOptions::default(),
                )
                .unwrap();
                assert_eq!(
                    store.lanes[0].frontier_sub_seq, 1,
                    "R3-C3 (lag={lagged_leaf}): frontier_sub_seq must not regress"
                );
                assert_eq!(
                    store.lanes[0].frontier_leaves.len(),
                    4,
                    "R3-C3 (lag={lagged_leaf}): frontier_leaves must not clear or truncate"
                );
                assert_eq!(
                    store.lanes[0].prev_sealed_sub_seq,
                    Some(0),
                    "R3-C3 (lag={lagged_leaf}): prev_sealed_sub_seq must not regress"
                );
                assert_eq!(
                    store.lanes[0].prev_sealed_leaves.len(),
                    SUBTREE_LEAVES,
                    "R3-C3 (lag={lagged_leaf}): prev_sealed_leaves must stay intact"
                );
                let (sr_f, path_f) = store.build_witness_for_note(&note257, &snap_choice260).unwrap();
                assert_eq!(sr_f, sr260);
                assert_eq!(path_f.compute_root(cm257), sr260);
                let (sr_p, path_p) = store.build_witness_for_note(&note200, &snap_choice250).unwrap();
                assert_eq!(sr_p, sr250);
                assert_eq!(path_p.compute_root(cm200), sr250);
            }

            // Sync 3 advances to `next_leaf = 520` (`prev_sealed_sub_seq = Some(1)`, `frontier_sub_seq = 2`, 8 frontier leaves),
            // then Sync 4 against lagging RPC at `next_leaf = 260` must NOT regress `prev_sealed_sub_seq` to `Some(0)`!
            let snap520 = build_snapshot(520);
            sync_compact_store_with_batch(
                &mut store,
                &fvk,
                |addrs, slice| slice_lookup(&snap520, addrs, slice),
                &program_id,
                SyncOptions::default(),
            )
            .unwrap();
            assert_eq!(store.lanes[0].finalized_subroots.len(), 2);
            assert_eq!(store.lanes[0].frontier_sub_seq, 2);
            assert_eq!(store.lanes[0].frontier_leaves.len(), 8);
            assert_eq!(store.lanes[0].prev_sealed_sub_seq, Some(1));

            sync_compact_store_with_batch(
                &mut store,
                &fvk,
                |addrs, slice| slice_lookup(&snap260, addrs, slice),
                &program_id,
                SyncOptions::default(),
            )
            .unwrap();
            assert_eq!(store.lanes[0].frontier_sub_seq, 2);
            assert_eq!(store.lanes[0].frontier_leaves.len(), 8);
            assert_eq!(
                store.lanes[0].prev_sealed_sub_seq,
                Some(1),
                "R3-C3: lagging RPC at 260 must not regress prev_sealed_sub_seq from 1 back to 0"
            );
            let (snap_choice520, sr520) = build_snap_at(520);
            let note515 = store
                .notes
                .iter()
                .find(|n| n.leaf_index == 515)
                .unwrap()
                .clone();
            let (sr_520, path_520) = store.build_witness_for_note(&note515, &snap_choice520).unwrap();
            assert_eq!(sr_520, sr520);
            assert_eq!(path_520.compute_root(cm515), sr520);
        }
    }

    #[test]
    fn r4_c1_and_c4_phase0_atomic_17_batch_and_high_u64_clamping() {
        let alice = AudrenKeys::from_seed(&[0xc4u8; 32]);
        let fvk = alice.full_viewing_key();
        let sol_asset = derive_asset_id(&WSOL_MINT);
        let program_id = Address::from(AUDREN_PROGRAM_ID);

        let (tw, bl, memo_106) =
            encrypt_note_memo(&alice.view_pk, [0xc5u8; 32], 1_234_567, &WSOL_MINT).unwrap();
        let cm = compute_note_commitment(
            derive_stealth_owner(alice.spend_pk, tw),
            sol_asset,
            1_234_567,
            bl,
        );

        let slice_lookup = |accounts: &BTreeMap<Address, Vec<u8>>,
                            addrs: &[Address],
                            slice: Option<AccountDataSlice>|
         -> Vec<Option<Vec<u8>>> {
            addrs
                .iter()
                .map(|a| {
                    let full = accounts.get(a)?;
                    match slice {
                        Some(s) => {
                            let end = s.offset.saturating_add(s.length).min(full.len());
                            Some(if s.offset <= end {
                                full[s.offset..end].to_vec()
                            } else {
                                Vec::new()
                            })
                        }
                        None => Some(full.clone()),
                    }
                })
                .collect()
        };

        // =====================================================================
        // R4-C4: Phase 0 fetches [pool_pda, lane_0..lane_15] (17 accounts) in ONE
        //        atomic batch, ignoring uninitialized lanes >= active_lanes.
        // =====================================================================
        let pool_pda = derive_pool_pda(&program_id, 0).0;
        let all_lane_pdas: Vec<Address> = (0..NUM_LANES as u8)
            .map(|l| derive_lane_pda(&program_id, 0, l).0)
            .collect();

        let cm_lane0_root =
            compute_lane_root_from_subroots_and_frontier(&[], Some(&[cm]), 1).unwrap();
        for active_lanes in [4u8, 8u8] {
            let mut accounts: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
            accounts.insert(pool_pda, make_pool(active_lanes));
            for l in 0..active_lanes {
                if l == 0 {
                    accounts.insert(all_lane_pdas[0], make_lane_with_root(0, 1, 0, cm_lane0_root));
                } else {
                    accounts.insert(all_lane_pdas[l as usize], make_lane(l, 0, 0));
                }
            }
            accounts.insert(
                derive_subtree_pda(&program_id, 0, 0, 0).0,
                make_subtree(0, 0, &[cm]),
            );
            let mut m0 = make_memo(0, 0, 1, 0);
            write_memo(&mut m0, 0, &memo_106);
            accounts.insert(derive_memo_pda(&program_id, 0, 0, 0).0, m0);

            let recorded_calls: RefCell<Vec<Vec<Address>>> = RefCell::new(Vec::new());
            let mut store = CompactWalletStore::new(0, 0);
            let (pool, lanes, discovered) = sync_compact_store_with_batch(
                &mut store,
                &fvk,
                |addrs, slice| {
                    recorded_calls.borrow_mut().push(addrs.to_vec());
                    slice_lookup(&accounts, addrs, slice)
                },
                &program_id,
                SyncOptions::default(),
            )
            .unwrap();

            assert_eq!(pool.active_lanes, active_lanes);
            assert_eq!(lanes.len(), active_lanes as usize);
            assert_eq!(discovered, 1);

            let calls = recorded_calls.borrow();
            assert!(
                !calls.is_empty(),
                "R4-C4: expected at least one Phase 0 batch call"
            );
            assert_eq!(
                calls[0].len(),
                1 + NUM_LANES,
                "R4-C4: Phase 0 must fetch all 17 [pool_pda, lane_0..lane_15] accounts in ONE batch"
            );
            assert_eq!(calls[0][0], pool_pda);
            for (l, expected_lane_pda) in all_lane_pdas.iter().enumerate() {
                assert_eq!(calls[0][1 + l], *expected_lane_pda);
            }
            for later_call in calls.iter().skip(1) {
                for addr in later_call {
                    assert!(
                        !all_lane_pdas.contains(addr),
                        "R4-C4: no second Phase 0 LaneTreeState batch should occur"
                    );
                }
            }
        }

        // Missing an active lane (< active_lanes) in the 17-account batch must fail cleanly
        {
            let mut missing_accounts: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
            missing_accounts.insert(pool_pda, make_pool(4));
            for l in 0..3u8 {
                missing_accounts.insert(all_lane_pdas[l as usize], make_lane(l, 0, 0));
            }
            let mut store = CompactWalletStore::new(0, 0);
            let err = sync_compact_store_with_batch(
                &mut store,
                &fvk,
                |addrs, slice| slice_lookup(&missing_accounts, addrs, slice),
                &program_id,
                SyncOptions::default(),
            );
            assert!(
                err.is_err(),
                "R4-C4: missing active lane #3 must return WitnessNotFound"
            );
        }

        // =====================================================================
        // R4-C1: u64 clamp BEFORE `as usize` at 2^32 boundary in Pass 1C & Pass 2
        // =====================================================================
        {
            let boundary_u32_wrap: u64 = 1u64 << 32;
            assert_eq!(
                boundary_u32_wrap.min(MEMO_NOTES_PER_PAGE as u64) as u32,
                MEMO_NOTES_PER_PAGE as u32
            );
            assert_eq!(
                boundary_u32_wrap.min(NF_PER_PAGE as u64) as u32,
                NF_PER_PAGE as u32
            );

            let mut leaves0: Vec<Fr> = (0..SUBTREE_LEAVES).map(|i| Fr::from((i + 2) as u64)).collect();
            leaves0[0] = cm;
            let sr0 = compute_subtree_256_root(&leaves0, SUBTREE_LEAVES);
            let nf0 = fvk.real_nullifier(cm, 0).unwrap();
            let nf0_pref: [u8; NF_PREFIX_LEN] = nf0[0..NF_PREFIX_LEN].try_into().unwrap();

            // Part A: `nf_count == 2^32` with valid lane root -> Pass 2 scans NullifierPage #0
            // without 32-bit wrap and marks the discovered note spent!
            let mut nf_accounts: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
            nf_accounts.insert(pool_pda, make_pool(1));
            nf_accounts.insert(
                all_lane_pdas[0],
                make_lane_with_root(0, 1, boundary_u32_wrap, cm_lane0_root),
            );
            nf_accounts.insert(
                derive_subtree_pda(&program_id, 0, 0, 0).0,
                make_subtree(0, 0, &[cm]),
            );
            let mut m0_single = make_memo(0, 0, 1, 0);
            write_memo(&mut m0_single, 0, &memo_106);
            nf_accounts.insert(derive_memo_pda(&program_id, 0, 0, 0).0, m0_single);
            nf_accounts.insert(
                derive_nf_page_pda(&program_id, 0, 0, 0).0,
                make_nf_page(0, 0, &[nf0_pref]),
            );

            let mut store_nf = CompactWalletStore::new(0, 0);
            let (_, _, disc_nf) = sync_compact_store_with_batch(
                &mut store_nf,
                &fvk,
                |addrs, slice| slice_lookup(&nf_accounts, addrs, slice),
                &program_id,
                SyncOptions {
                    privacy_mode: SyncPrivacyMode::Fast,
                    decoy_epoch_bucket: None,
                },
            )
            .unwrap();
            assert_eq!(disc_nf, 1);
            assert_eq!(store_nf.notes.len(), 1);
            assert!(
                store_nf.notes[0].spent,
                "R4-C1: Pass 2 must scan NullifierPage #0 when nf_count == 2^32"
            );

            // Part B: `next_leaf == 2^32` -> Pass 1C must clamp `max_for_snapshot` to 96 BEFORE
            // `as usize` (evidenced by Pass 1D fetching `SubtreePage #0` for leaf 0's view-tag
            // hit), while Pass 1A stopping short of `finalized_count = 2^24` withholds committing
            // unverified leaves & rolls back `next_nf_index`!
            let sub0_pda = derive_subtree_pda(&program_id, 0, 0, 0).0;
            let mut accounts: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
            accounts.insert(pool_pda, make_pool(1));
            accounts.insert(
                all_lane_pdas[0],
                make_lane(0, boundary_u32_wrap, boundary_u32_wrap),
            );
            accounts.insert(
                derive_subroot_pda(&program_id, 0, 0, 0).0,
                make_subroot(0, 0, &[sr0]),
            );
            accounts.insert(sub0_pda, make_subtree(0, 0, &leaves0));
            let mut m0 = make_memo(0, 0, MEMO_NOTES_PER_PAGE as u16, 100);
            write_memo(&mut m0, 0, &memo_106);
            accounts.insert(derive_memo_pda(&program_id, 0, 0, 0).0, m0);
            accounts.insert(
                derive_nf_page_pda(&program_id, 0, 0, 0).0,
                make_nf_page(0, 0, &[nf0_pref]),
            );

            let mut fetched_sub0 = false;
            let mut store = CompactWalletStore::new(0, 0);
            let (_, _, discovered) = sync_compact_store_with_batch(
                &mut store,
                &fvk,
                |addrs, slice| {
                    if addrs.contains(&sub0_pda) {
                        fetched_sub0 = true;
                    }
                    slice_lookup(&accounts, addrs, slice)
                },
                &program_id,
                SyncOptions {
                    privacy_mode: SyncPrivacyMode::Fast,
                    decoy_epoch_bucket: None,
                },
            )
            .unwrap();
            assert!(
                fetched_sub0,
                "R4-C1: Pass 1C must scan MemoPage #0 when next_leaf == 2^32 (triggering Pass 1D fetch of SubtreePage #0)"
            );
            assert_eq!(
                discovered, 0,
                "F1: incomplete Pass 1A (1 < 2^24 finalized subroots) must withhold committing unverified leaves"
            );
            assert_eq!(store.lanes[0].next_memo_leaf, 0);
            assert!(store.lanes[0].finalized_subroots.is_empty());
            assert!(store.notes.is_empty());
            assert_eq!(store.lanes[0].next_nf_index, 0);
        }
    }

    #[test]
    fn r5_c1_root_history_validation_multi_note_selection_and_finalized_fallback() {
        use audren_core::{
            layout::{RT_OFF_EPOCH_RING, RT_OFF_SLOT_RING},
            ROOT_RING_EPOCH, ROOT_RING_SLOT,
        };

        let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
        let view_sk = [0x42u8; 32];
        let leaf0 = Fr::from(777u64);
        let leaf1 = Fr::from(888u64);
        let lane0_sub0_stable = make_subtree(0, 0, &[leaf0]);
        let lane0_sub0_latest = make_subtree(0, 0, &[leaf0, leaf1]);

        let zeros = zero_hashes_4ary();
        let mut stable_roots = [zeros[LANE_DEPTH_4ARY]; NUM_LANES];
        stable_roots[0] =
            compute_lane_root_from_subroots_and_frontier(&[], Some(&[leaf0]), 1).unwrap();
        let mut stable_counts = [0u64; NUM_LANES];
        stable_counts[0] = 1;
        let stable_sr = compute_super_root_4ary(&stable_roots);

        let mut latest_roots = [zeros[LANE_DEPTH_4ARY]; NUM_LANES];
        latest_roots[0] =
            compute_lane_root_from_subroots_and_frontier(&[], Some(&[leaf0, leaf1]), 2).unwrap();
        let mut latest_counts = [0u64; NUM_LANES];
        latest_counts[0] = 2;
        let latest_sr = compute_super_root_4ary(&latest_roots);

        let roots_pda = derive_roots_pda(&program_id, 0).0;
        let sub0_pda = derive_subtree_pda(&program_id, 0, 0, 0).0;

        let valid_rh = make_root_history(0, &latest_roots, &latest_counts, &stable_roots, &stable_counts);
        let wrong_pool_rh =
            make_root_history(1, &latest_roots, &latest_counts, &stable_roots, &stable_counts);
        let mut bad_slot_ring_rh = valid_rh.clone();
        bad_slot_ring_rh[RT_OFF_SLOT_RING + 31] ^= 0x01;
        let mut bad_epoch_ring_rh = valid_rh.clone();
        bad_epoch_ring_rh[RT_OFF_EPOCH_RING + 31] ^= 0x01;

        // 1. Header / pool_id / ring cursor super_root mismatches must fail in both Strict & Fast modes.
        for (label, rh_bytes) in [
            ("wrong pool_id", &wrong_pool_rh),
            ("slot_ring cursor mismatch", &bad_slot_ring_rh),
            ("epoch_ring cursor mismatch", &bad_epoch_ring_rh),
        ] {
            for mode in [SyncPrivacyMode::Strict, SyncPrivacyMode::Fast] {
                let err = reconstruct_witness_with_batch(
                    |addrs, _| {
                        addrs
                            .iter()
                            .map(|a| {
                                if *a == roots_pda {
                                    Some(rh_bytes.clone())
                                } else if *a == sub0_pda {
                                    Some(lane0_sub0_latest.clone())
                                } else {
                                    None
                                }
                            })
                            .collect()
                    },
                    &program_id,
                    0,
                    0,
                    0,
                    WitnessOptions {
                        privacy_mode: mode,
                        view_sk: (mode == SyncPrivacyMode::Strict).then_some(view_sk),
                        decoy_epoch_bucket: None,
                    },
                )
                .expect_err(&format!("R5-C1 ({label}, {mode:?}): must reject"));
                assert!(
                    matches!(err, ClientError::InvalidEncoding(_)),
                    "unexpected error for {label}: {err:?}"
                );
            }
        }

        // 2. Single note covered by `stable` chooses `ROOT_RING_EPOCH`.
        let (path0, rk0, ri0, sr0) = reconstruct_witness_strict(
            |addrs, _| {
                addrs
                    .iter()
                    .map(|a| {
                        if *a == roots_pda {
                            Some(valid_rh.clone())
                        } else if *a == sub0_pda {
                            Some(lane0_sub0_latest.clone())
                        } else {
                            None
                        }
                    })
                    .collect()
            },
            &program_id,
            0,
            0,
            0,
            view_sk,
        )
        .expect("note 0 should prove against stable epoch_ring");
        assert_eq!(rk0, ROOT_RING_EPOCH);
        assert_eq!(ri0, 0);
        assert_eq!(sr0, stable_sr);
        assert_eq!(path0.compute_root(leaf0), stable_sr);

        // 3. Challenge #2 multi-note batch `(0, 0)` + `(0, 1)`: note 1 is newer than `stable` ->
        //    BOTH notes prove together against the SAME `latest` `ROOT_RING_SLOT` snapshot!
        let (paths, rk_batch, ri_batch, sr_batch) = reconstruct_witness_for_notes_with_batch(
            |addrs, _| {
                addrs
                    .iter()
                    .map(|a| {
                        if *a == roots_pda {
                            Some(valid_rh.clone())
                        } else if *a == sub0_pda {
                            Some(lane0_sub0_latest.clone())
                        } else {
                            None
                        }
                    })
                    .collect()
            },
            &program_id,
            0,
            &[(0, 0), (0, 1)],
            WitnessOptions {
                privacy_mode: SyncPrivacyMode::Strict,
                view_sk: Some(view_sk),
                decoy_epoch_bucket: None,
            },
        )
        .expect("multi-note batch should share latest slot_ring snapshot");
        assert_eq!(rk_batch, ROOT_RING_SLOT);
        assert_eq!(ri_batch, 0);
        assert_eq!(sr_batch, latest_sr);
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].compute_root(leaf0), latest_sr);
        assert_eq!(paths[1].compute_root(leaf1), latest_sr);

        // 4. Challenge #1 `fetch_root_history`: finalized-first, confirmed-fallback for fresh note!
        let finalized_only_note0 =
            make_root_history(0, &stable_roots, &stable_counts, &stable_roots, &stable_counts);
        let mut confirmed_called = false;
        let (_, snap_fin) = fetch_root_history(
            |a| (*a == roots_pda).then(|| finalized_only_note0.clone()),
            |_| {
                confirmed_called = true;
                Some(valid_rh.clone())
            },
            &program_id,
            0,
            &[(0, 0)],
        )
        .unwrap();
        assert!(!confirmed_called, "must not call confirmed when finalized covers note");
        assert_eq!(snap_fin.ring_kind, ROOT_RING_EPOCH);
        assert_eq!(snap_fin.super_root, fr_to_be_bytes(&stable_sr));

        let (_, snap_conf) = fetch_root_history(
            |a| (*a == roots_pda).then(|| finalized_only_note0.clone()),
            |a| {
                confirmed_called = true;
                (*a == roots_pda).then(|| valid_rh.clone())
            },
            &program_id,
            0,
            &[(0, 1)],
        )
        .unwrap();
        assert!(confirmed_called, "must fall back to confirmed when fresh note not in finalized");
        assert_eq!(snap_conf.ring_kind, ROOT_RING_SLOT);
        assert_eq!(snap_conf.super_root, fr_to_be_bytes(&latest_sr));

        // Verify lane0_sub0_stable still satisfies stable_sr
        let (paths_fin, _, _, _) = reconstruct_witness_for_notes_with_snapshot_batch(
            |addrs, _| {
                addrs
                    .iter()
                    .map(|a| (*a == sub0_pda).then(|| lane0_sub0_stable.clone()))
                    .collect()
            },
            &program_id,
            0,
            &snap_fin,
            &[(0, 0)],
            WitnessOptions {
                privacy_mode: SyncPrivacyMode::Strict,
                view_sk: Some(view_sk),
                decoy_epoch_bucket: None,
            },
        )
        .unwrap();
        assert_eq!(paths_fin[0].compute_root(leaf0), stable_sr);

        // 5. `fetch_root_history` rejects forged super_root echoed into ring, non-canonical Fr, and all-zero super_root
        let mut forged_sr = finalized_only_note0.clone();
        let fake_sr = fr_to_be_bytes(&Fr::from(123_456u64));
        forged_sr[audren_core::layout::RT_OFF_STABLE_SUPER_ROOT
            ..audren_core::layout::RT_OFF_STABLE_SUPER_ROOT + 32]
            .copy_from_slice(&fake_sr);
        forged_sr[audren_core::layout::RT_OFF_EPOCH_RING
            ..audren_core::layout::RT_OFF_EPOCH_RING + 32]
            .copy_from_slice(&fake_sr);
        assert!(matches!(
            fetch_root_history(
                |a| (*a == roots_pda).then(|| forged_sr.clone()),
                |_| None,
                &program_id,
                0,
                &[(0, 0)],
            ),
            Err(ClientError::WitnessNotFound(_))
        ));

        let mut non_canon_sr = finalized_only_note0.clone();
        non_canon_sr[audren_core::layout::RT_OFF_STABLE_SUPER_ROOT
            ..audren_core::layout::RT_OFF_STABLE_SUPER_ROOT + 32]
            .fill(0xff);
        non_canon_sr[audren_core::layout::RT_OFF_EPOCH_RING
            ..audren_core::layout::RT_OFF_EPOCH_RING + 32]
            .fill(0xff);
        assert!(matches!(
            fetch_root_history(
                |a| (*a == roots_pda).then(|| non_canon_sr.clone()),
                |_| None,
                &program_id,
                0,
                &[(0, 0)],
            ),
            Err(ClientError::InvalidFieldElement)
        ));

        let mut non_canon_lane = finalized_only_note0.clone();
        non_canon_lane[audren_core::layout::RT_OFF_STABLE_LANE_ROOTS
            ..audren_core::layout::RT_OFF_STABLE_LANE_ROOTS + 32]
            .fill(0xff);
        assert!(matches!(
            fetch_root_history(
                |a| (*a == roots_pda).then(|| non_canon_lane.clone()),
                |_| None,
                &program_id,
                0,
                &[(0, 0)],
            ),
            Err(ClientError::InvalidFieldElement)
        ));

        let mut zero_sr = finalized_only_note0.clone();
        zero_sr[audren_core::layout::RT_OFF_STABLE_SUPER_ROOT
            ..audren_core::layout::RT_OFF_STABLE_SUPER_ROOT + 32]
            .fill(0);
        zero_sr[audren_core::layout::RT_OFF_EPOCH_RING
            ..audren_core::layout::RT_OFF_EPOCH_RING + 32]
            .fill(0);
        assert!(matches!(
            fetch_root_history(
                |a| (*a == roots_pda).then(|| zero_sr.clone()),
                |_| None,
                &program_id,
                0,
                &[(0, 0)],
            ),
            Err(ClientError::InvalidEncoding(_))
        ));

        // 6. Round-2 security regression: tampered/non-canonical/forged unchosen snapshot MUST be
        //    rejected immediately (NO silent `stable -> latest` downgrade AND NO silent `finalized -> confirmed` fallback!)
        let zero_counts = [0u64; NUM_LANES];
        let zero_counts_valid_latest =
            make_root_history(0, &latest_roots, &latest_counts, &stable_roots, &zero_counts);

        // 6a. Non-canonical stable_super_root = [0xff; 32] echoed into epoch_ring + stable_lane_counts = [0; 16], genuine latest
        let mut downgrade_non_canon_stable = zero_counts_valid_latest.clone();
        downgrade_non_canon_stable[audren_core::layout::RT_OFF_STABLE_SUPER_ROOT
            ..audren_core::layout::RT_OFF_STABLE_SUPER_ROOT + 32]
            .fill(0xff);
        downgrade_non_canon_stable[RT_OFF_EPOCH_RING..RT_OFF_EPOCH_RING + 32].fill(0xff);

        // 6b. Forged canonical Fr != H(stable_lane_roots) echoed into epoch_ring + stable_lane_counts = [0; 16], genuine latest
        let mut downgrade_forged_stable = zero_counts_valid_latest.clone();
        downgrade_forged_stable[audren_core::layout::RT_OFF_STABLE_SUPER_ROOT
            ..audren_core::layout::RT_OFF_STABLE_SUPER_ROOT + 32]
            .copy_from_slice(&fake_sr);
        downgrade_forged_stable[RT_OFF_EPOCH_RING..RT_OFF_EPOCH_RING + 32]
            .copy_from_slice(&fake_sr);

        // 6c. All-zero stable_super_root echoed into epoch_ring + genuine latest
        let mut downgrade_zero_stable = valid_rh.clone();
        downgrade_zero_stable[audren_core::layout::RT_OFF_STABLE_SUPER_ROOT
            ..audren_core::layout::RT_OFF_STABLE_SUPER_ROOT + 32]
            .fill(0);
        downgrade_zero_stable[RT_OFF_EPOCH_RING..RT_OFF_EPOCH_RING + 32].fill(0);

        // 6d. Tampered finalized payload with BOTH snapshots forged and lane_counts = [0; 16] (must NOT fall back to confirmed!)
        let mut tampered_finalized_zero_counts =
            make_root_history(0, &latest_roots, &zero_counts, &stable_roots, &zero_counts);
        tampered_finalized_zero_counts[audren_core::layout::RT_OFF_LATEST_SUPER_ROOT
            ..audren_core::layout::RT_OFF_LATEST_SUPER_ROOT + 32]
            .fill(0xff);
        tampered_finalized_zero_counts[RT_OFF_SLOT_RING..RT_OFF_SLOT_RING + 32].fill(0xff);
        tampered_finalized_zero_counts[audren_core::layout::RT_OFF_STABLE_SUPER_ROOT
            ..audren_core::layout::RT_OFF_STABLE_SUPER_ROOT + 32]
            .fill(0xff);
        tampered_finalized_zero_counts[RT_OFF_EPOCH_RING..RT_OFF_EPOCH_RING + 32].fill(0xff);

        // 6e. Valid stable covering note 0, but tampered non-canonical latest_super_root -> must reject!
        let mut tampered_latest_valid_stable = valid_rh.clone();
        tampered_latest_valid_stable[audren_core::layout::RT_OFF_LATEST_SUPER_ROOT
            ..audren_core::layout::RT_OFF_LATEST_SUPER_ROOT + 32]
            .fill(0xff);
        tampered_latest_valid_stable[RT_OFF_SLOT_RING..RT_OFF_SLOT_RING + 32].fill(0xff);

        for (label, bad_raw) in [
            ("non-canonical stable + genuine latest", &downgrade_non_canon_stable),
            ("forged stable + genuine latest", &downgrade_forged_stable),
            ("all-zero stable + genuine latest", &downgrade_zero_stable),
            ("tampered finalized with zero counts", &tampered_finalized_zero_counts),
            ("valid stable + tampered latest", &tampered_latest_valid_stable),
        ] {
            let mut confirmed_hit = false;
            let res = fetch_root_history(
                |a| (*a == roots_pda).then(|| bad_raw.clone()),
                |a| {
                    confirmed_hit = true;
                    (*a == roots_pda).then(|| valid_rh.clone())
                },
                &program_id,
                0,
                &[(0, 0)],
            );
            assert!(
                res.is_err(),
                "R2: fetch_root_history ({label}) must reject tampered finalized payload"
            );
            assert!(
                !confirmed_hit,
                "R2: fetch_root_history ({label}) must NOT silently fall back to confirmed"
            );

            let res_rec = reconstruct_witness_for_notes_with_batch(
                |addrs, _| {
                    addrs
                        .iter()
                        .map(|a| {
                            if *a == roots_pda {
                                Some(bad_raw.clone())
                            } else if *a == sub0_pda {
                                Some(lane0_sub0_latest.clone())
                            } else {
                                None
                            }
                        })
                        .collect()
                },
                &program_id,
                0,
                &[(0, 0)],
                WitnessOptions {
                    privacy_mode: SyncPrivacyMode::Fast,
                    view_sk: None,
                    decoy_epoch_bucket: None,
                },
            );
            assert!(
                res_rec.is_err(),
                "R2: reconstruct_witness_for_notes_with_batch ({label}) must reject"
            );
        }

        // 7. Out-of-bounds ring cursors/counts & lane_counts > MAX_LEAVES_PER_LANE on constructed
        //    GlobalRootHistory MUST return None / Err without panicking!
        let decoded_valid = decode_global_root_history(&valid_rh).unwrap();
        for mutator in [
            (|h: &mut GlobalRootHistory| h.slot_count = 0) as fn(&mut GlobalRootHistory),
            |h| h.slot_count = (SLOT_RING_LEN + 1) as u16,
            |h| h.slot_cursor = h.slot_count,
            |h| h.slot_cursor = (SLOT_RING_LEN + 10) as u16,
            |h| h.epoch_count = 0,
            |h| h.epoch_count = (EPOCH_RING_LEN + 1) as u16,
            |h| h.epoch_cursor = h.epoch_count,
            |h| h.epoch_cursor = (EPOCH_RING_LEN + 10) as u16,
        ] {
            let mut mutated = decoded_valid.clone();
            mutator(&mut mutated);
            assert!(
                mutated.select_snapshot_for_notes(&[(0, 0)]).is_none(),
                "select_snapshot_for_notes must return None without panicking on OOB cursor/count"
            );
            assert!(
                matches!(
                    validate_global_root_history(&mutated, 0),
                    Err(ClientError::InvalidEncoding(_))
                ),
                "validate_global_root_history must return InvalidEncoding without panicking on OOB cursor/count"
            );
        }

        let mut bad_latest_cnt = decoded_valid.clone();
        bad_latest_cnt.latest_lane_counts[0] = MAX_LEAVES_PER_LANE + 1;
        assert!(matches!(
            validate_global_root_history(&bad_latest_cnt, 0),
            Err(ClientError::InvalidEncoding(_))
        ));

        let mut bad_stable_cnt = decoded_valid.clone();
        bad_stable_cnt.stable_lane_counts[0] = MAX_LEAVES_PER_LANE + 1;
        assert!(matches!(
            validate_global_root_history(&bad_stable_cnt, 0),
            Err(ClientError::InvalidEncoding(_))
        ));

        // 8. Round-3 security regressions:
        //    8a. 8-byte `stable_lane_counts[0] = 0` mutation (with non-zero stable_lane_roots[0]):
        //        MUST be rejected (NO silent `stable -> latest` downgrade in fetch_root_history,
        //        reconstruct_witness (strict & fast), validate_global_root_history, or select_snapshot_for_notes!).
        let mut eight_byte_downgrade = valid_rh.clone();
        eight_byte_downgrade[audren_core::layout::RT_OFF_STABLE_LANE_COUNTS
            ..audren_core::layout::RT_OFF_STABLE_LANE_COUNTS + 8]
            .copy_from_slice(&0u64.to_le_bytes());

        //    8b. 16-byte finalized mutation (`stable_lane_counts[0] = 0` AND `latest_lane_counts[0] = 0`):
        //        MUST reject finalized immediately (NO silent `finalized -> confirmed` fallback!).
        let mut sixteen_byte_fallback = eight_byte_downgrade.clone();
        sixteen_byte_fallback[audren_core::layout::RT_OFF_LATEST_LANE_COUNTS
            ..audren_core::layout::RT_OFF_LATEST_LANE_COUNTS + 8]
            .copy_from_slice(&0u64.to_le_bytes());

        //    8c. Header & monotonicity mutations:
        let mut stable_gt_latest_cnt = valid_rh.clone();
        stable_gt_latest_cnt[audren_core::layout::RT_OFF_STABLE_LANE_COUNTS
            ..audren_core::layout::RT_OFF_STABLE_LANE_COUNTS + 8]
            .copy_from_slice(&999u64.to_le_bytes());

        let mut equal_cnt_diff_root = valid_rh.clone();
        equal_cnt_diff_root[audren_core::layout::RT_OFF_STABLE_LANE_COUNTS
            ..audren_core::layout::RT_OFF_STABLE_LANE_COUNTS + 8]
            .copy_from_slice(&2u64.to_le_bytes());

        let mut stable_gt_latest_slot = valid_rh.clone();
        stable_gt_latest_slot[audren_core::layout::RT_OFF_STABLE_SLOT
            ..audren_core::layout::RT_OFF_STABLE_SLOT + 8]
            .copy_from_slice(&200u64.to_le_bytes());
        stable_gt_latest_slot[RT_OFF_EPOCH_RING + 32..RT_OFF_EPOCH_RING + 40]
            .copy_from_slice(&200u64.to_le_bytes());
        stable_gt_latest_slot[audren_core::layout::RT_OFF_STABLE_EPOCH_ID
            ..audren_core::layout::RT_OFF_STABLE_EPOCH_ID + 8]
            .copy_from_slice(&(200u64 / audren_core::DEFAULT_ROOT_EPOCH_INTERVAL).to_le_bytes());

        let mut bad_slot_ring_slot = valid_rh.clone();
        bad_slot_ring_slot[RT_OFF_SLOT_RING + 32..RT_OFF_SLOT_RING + 40]
            .copy_from_slice(&103u64.to_le_bytes());

        let mut bad_epoch_ring_slot = valid_rh.clone();
        bad_epoch_ring_slot[RT_OFF_EPOCH_RING + 32..RT_OFF_EPOCH_RING + 40]
            .copy_from_slice(&95u64.to_le_bytes());

        let mut bad_stable_epoch_id = valid_rh.clone();
        bad_stable_epoch_id[audren_core::layout::RT_OFF_STABLE_EPOCH_ID
            ..audren_core::layout::RT_OFF_STABLE_EPOCH_ID + 8]
            .copy_from_slice(&99u64.to_le_bytes());

        for (label, bad_raw) in [
            ("8-byte stable_lane_counts=0 downgrade", &eight_byte_downgrade),
            ("16-byte finalized counts=0 fallback", &sixteen_byte_fallback),
            ("stable_lane_counts > latest_lane_counts", &stable_gt_latest_cnt),
            ("equal counts with differing lane roots", &equal_cnt_diff_root),
            ("stable_slot > latest_slot", &stable_gt_latest_slot),
            ("slot_ring cursor slot mismatch", &bad_slot_ring_slot),
            ("epoch_ring cursor slot mismatch", &bad_epoch_ring_slot),
            ("wrong stable_epoch_id", &bad_stable_epoch_id),
        ] {
            let mut confirmed_hit = false;
            let res = fetch_root_history(
                |a| (*a == roots_pda).then(|| bad_raw.clone()),
                |a| {
                    confirmed_hit = true;
                    (*a == roots_pda).then(|| valid_rh.clone())
                },
                &program_id,
                0,
                &[(0, 0)],
            );
            assert!(
                res.is_err(),
                "R3: fetch_root_history ({label}) must reject"
            );
            assert!(
                !confirmed_hit,
                "R3: fetch_root_history ({label}) must NOT silently fall back to confirmed"
            );

            for privacy_mode in [SyncPrivacyMode::Strict, SyncPrivacyMode::Fast] {
                let res_rec = reconstruct_witness_for_notes_with_batch(
                    |addrs, _| {
                        addrs
                            .iter()
                            .map(|a| {
                                if *a == roots_pda {
                                    Some(bad_raw.clone())
                                } else if *a == sub0_pda {
                                    Some(lane0_sub0_latest.clone())
                                } else {
                                    None
                                }
                            })
                            .collect()
                    },
                    &program_id,
                    0,
                    &[(0, 0)],
                    WitnessOptions {
                        privacy_mode,
                        view_sk: (privacy_mode == SyncPrivacyMode::Strict).then_some(view_sk),
                        decoy_epoch_bucket: None,
                    },
                );
                assert!(
                    res_rec.is_err(),
                    "R3: reconstruct_witness ({label}, {privacy_mode:?}) must reject"
                );
            }
        }

        // Caller-supplied epoch_interval == 0 or > MAX_ROOT_EPOCH_INTERVAL rejected
        for bad_interval in [0u64, MAX_ROOT_EPOCH_INTERVAL + 1] {
            let mut bad_iv = decoded_valid.clone();
            bad_iv.epoch_interval = bad_interval;
            assert!(matches!(
                validate_global_root_history(&bad_iv, 0),
                Err(ClientError::InvalidEncoding(_))
            ));
        }

        // RootSnapshotChoice with count == 0 and non-zero lane_root rejected
        let mut bad_snap = snap_fin;
        bad_snap.lane_counts[0] = 0;
        assert!(validate_root_snapshot_choice(&bad_snap).is_err());

        // R4 Finding #1: biconditional checks block 1-byte sc < lc (with sr == lr)
        // AND 2-byte count > 0 on ZERO_HASHES_4ARY[18] lane root.
        let mut r4_same_root_diff_cnt = decoded_valid.clone();
        r4_same_root_diff_cnt.latest_lane_counts[0] = 2;
        r4_same_root_diff_cnt.stable_lane_counts[0] = 1;
        r4_same_root_diff_cnt.stable_lane_roots[0] = r4_same_root_diff_cnt.latest_lane_roots[0];
        r4_same_root_diff_cnt.stable_super_root = r4_same_root_diff_cnt.latest_super_root;
        r4_same_root_diff_cnt.epoch_ring[r4_same_root_diff_cnt.epoch_cursor as usize].super_root =
            r4_same_root_diff_cnt.stable_super_root;
        assert!(validate_global_root_history(&r4_same_root_diff_cnt, 0).is_err());
        assert!(r4_same_root_diff_cnt.select_snapshot_for_notes(&[(0, 0)]).is_none());

        let mut r4_zero_root_nonzero_cnt = decoded_valid.clone();
        r4_zero_root_nonzero_cnt.stable_lane_counts[1] = 256;
        r4_zero_root_nonzero_cnt.latest_lane_counts[1] = 256;
        assert!(validate_global_root_history(&r4_zero_root_nonzero_cnt, 0).is_err());
        assert!(r4_zero_root_nonzero_cnt.select_snapshot_for_notes(&[(0, 0)]).is_none());

        let mut r4_snap_zero_root_nonzero_cnt = snap_fin;
        r4_snap_zero_root_nonzero_cnt.lane_counts[1] = 1;
        assert!(validate_root_snapshot_choice(&r4_snap_zero_root_nonzero_cnt).is_err());
    }

    #[test]
    fn fetch_root_history_upgrades_lagged_finalized_slot_ring_to_confirmed() {
        use audren_core::{
            layout::{
                RT_OFF_EPOCH_COUNT, RT_OFF_EPOCH_CURSOR, RT_OFF_EPOCH_RING, RT_OFF_LATEST_SLOT,
                RT_OFF_SLOT_COUNT, RT_OFF_SLOT_CURSOR, RT_OFF_SLOT_RING, RT_OFF_STABLE_EPOCH_ID,
                RT_OFF_STABLE_SLOT,
            },
            DEFAULT_ROOT_EPOCH_INTERVAL, ROOT_ENTRY_LEN,
        };

        let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
        let roots_pda = derive_roots_pda(&program_id, 0).0;
        let zeros = zero_hashes_4ary();

        let leaf0 = Fr::from(101u64);
        let leaf1 = Fr::from(202u64);
        let leaf2 = Fr::from(303u64);

        let make_lane_roots = |leaves: &[Fr]| -> [Fr; NUM_LANES] {
            let mut r = [zeros[LANE_DEPTH_4ARY]; NUM_LANES];
            r[0] = compute_lane_root_from_subroots_and_frontier(&[], Some(leaves), leaves.len())
                .unwrap();
            r
        };
        let make_counts = |n: u64| -> [u64; NUM_LANES] {
            let mut c = [0u64; NUM_LANES];
            c[0] = n;
            c
        };

        let r1 = make_lane_roots(&[leaf0]);
        let r2 = make_lane_roots(&[leaf0, leaf1]);
        let r3 = make_lane_roots(&[leaf0, leaf1, leaf2]);
        let c1 = make_counts(1);
        let c2 = make_counts(2);
        let c3 = make_counts(3);

        let set_ring_meta = |mut raw: Vec<u8>,
                             slot_cursor: u16,
                             slot_count: u16,
                             latest_slot: u64,
                             epoch_cursor: u16,
                             epoch_count: u16,
                             stable_slot: u64|
         -> Vec<u8> {
            let latest_sr: [u8; 32] = raw[audren_core::layout::RT_OFF_LATEST_SUPER_ROOT
                ..audren_core::layout::RT_OFF_LATEST_SUPER_ROOT + 32]
                .try_into()
                .unwrap();
            let stable_sr: [u8; 32] = raw[audren_core::layout::RT_OFF_STABLE_SUPER_ROOT
                ..audren_core::layout::RT_OFF_STABLE_SUPER_ROOT + 32]
                .try_into()
                .unwrap();
            raw[RT_OFF_SLOT_CURSOR..RT_OFF_SLOT_CURSOR + 2]
                .copy_from_slice(&slot_cursor.to_le_bytes());
            raw[RT_OFF_SLOT_COUNT..RT_OFF_SLOT_COUNT + 2]
                .copy_from_slice(&slot_count.to_le_bytes());
            raw[RT_OFF_LATEST_SLOT..RT_OFF_LATEST_SLOT + 8]
                .copy_from_slice(&latest_slot.to_le_bytes());
            raw[RT_OFF_EPOCH_CURSOR..RT_OFF_EPOCH_CURSOR + 2]
                .copy_from_slice(&epoch_cursor.to_le_bytes());
            raw[RT_OFF_EPOCH_COUNT..RT_OFF_EPOCH_COUNT + 2]
                .copy_from_slice(&epoch_count.to_le_bytes());
            raw[RT_OFF_STABLE_SLOT..RT_OFF_STABLE_SLOT + 8]
                .copy_from_slice(&stable_slot.to_le_bytes());
            raw[RT_OFF_STABLE_EPOCH_ID..RT_OFF_STABLE_EPOCH_ID + 8]
                .copy_from_slice(&(stable_slot / DEFAULT_ROOT_EPOCH_INTERVAL).to_le_bytes());
            let s_off = RT_OFF_SLOT_RING + (slot_cursor as usize) * ROOT_ENTRY_LEN;
            raw[s_off..s_off + 32].copy_from_slice(&latest_sr);
            raw[s_off + 32..s_off + 40].copy_from_slice(&latest_slot.to_le_bytes());
            let e_off = RT_OFF_EPOCH_RING + (epoch_cursor as usize) * ROOT_ENTRY_LEN;
            raw[e_off..e_off + 32].copy_from_slice(&stable_sr);
            raw[e_off + 32..e_off + 40].copy_from_slice(&stable_slot.to_le_bytes());
            raw
        };

        // Finalized: stable covers 1 leaf (slot 96), latest covers 2 leaves (slot 104, slot_cursor = 5)
        let fin_raw = set_ring_meta(
            make_root_history(0, &r2, &c2, &r1, &c1),
            5,
            6,
            104,
            2,
            3,
            96,
        );

        // (a) Note 0 is covered by finalized ROOT_RING_EPOCH -> returns immediately without calling confirmed!
        let mut confirmed_calls = 0usize;
        let (_, snap_epoch) = fetch_root_history(
            |a| (*a == roots_pda).then(|| fin_raw.clone()),
            |_| {
                confirmed_calls += 1;
                Some(fin_raw.clone())
            },
            &program_id,
            0,
            &[(0, 0)],
        )
        .unwrap();
        assert_eq!(confirmed_calls, 0);
        assert_eq!(snap_epoch.ring_kind, ROOT_RING_EPOCH);
        assert_eq!(snap_epoch.ring_idx, 2);

        // (b) Note 1 is only in finalized ROOT_RING_SLOT; confirmed has advanced epoch so Note 1 is now in ROOT_RING_EPOCH!
        let conf_epoch_raw = set_ring_meta(
            make_root_history(0, &r3, &c3, &r2, &c2),
            8,
            9,
            135,
            3,
            4,
            128,
        );
        confirmed_calls = 0;
        let (_, snap_upgraded_epoch) = fetch_root_history(
            |a| (*a == roots_pda).then(|| fin_raw.clone()),
            |a| {
                confirmed_calls += 1;
                (*a == roots_pda).then(|| conf_epoch_raw.clone())
            },
            &program_id,
            0,
            &[(0, 1)],
        )
        .unwrap();
        assert_eq!(confirmed_calls, 1);
        assert_eq!(snap_upgraded_epoch.ring_kind, ROOT_RING_EPOCH);
        assert_eq!(snap_upgraded_epoch.ring_idx, 3);
        assert_eq!(snap_upgraded_epoch.slot, 128);
        assert_eq!(
            snap_upgraded_epoch.super_root,
            fr_to_be_bytes(&compute_super_root_4ary(&r2))
        );

        // (c1) Confirmed still in ROOT_RING_SLOT with higher slot -> upgrades to confirmed ROOT_RING_SLOT
        let conf_newer_slot_raw = set_ring_meta(
            make_root_history(0, &r3, &c3, &r1, &c1),
            6,
            7,
            110,
            2,
            3,
            96,
        );
        confirmed_calls = 0;
        let (_, snap_newer_slot) = fetch_root_history(
            |a| (*a == roots_pda).then(|| fin_raw.clone()),
            |a| {
                confirmed_calls += 1;
                (*a == roots_pda).then(|| conf_newer_slot_raw.clone())
            },
            &program_id,
            0,
            &[(0, 1)],
        )
        .unwrap();
        assert_eq!(confirmed_calls, 1);
        assert_eq!(snap_newer_slot.ring_kind, ROOT_RING_SLOT);
        assert_eq!(snap_newer_slot.ring_idx, 6);
        assert_eq!(snap_newer_slot.slot, 110);

        // (c2) Same slot (104), but same-slot bump advanced ring_idx (5 -> 6) -> upgrades to confirmed!
        let conf_bumped_idx_raw = set_ring_meta(
            make_root_history(0, &r3, &c3, &r1, &c1),
            6,
            7,
            104,
            2,
            3,
            96,
        );
        let (_, snap_bumped_idx) = fetch_root_history(
            |a| (*a == roots_pda).then(|| fin_raw.clone()),
            |a| (*a == roots_pda).then(|| conf_bumped_idx_raw.clone()),
            &program_id,
            0,
            &[(0, 1)],
        )
        .unwrap();
        assert_eq!(snap_bumped_idx.ring_kind, ROOT_RING_SLOT);
        assert_eq!(snap_bumped_idx.ring_idx, 6);
        assert_eq!(snap_bumped_idx.slot, 104);

        // (d) Evicted finalized slot_ring[5] (same ring_idx=5, same slot=104, overwritten super_root!) -> upgrades to confirmed!
        let conf_evicted_raw = set_ring_meta(
            make_root_history(0, &r3, &c3, &r1, &c1),
            5,
            6,
            104,
            2,
            3,
            96,
        );
        let (_, snap_evicted) = fetch_root_history(
            |a| (*a == roots_pda).then(|| fin_raw.clone()),
            |a| (*a == roots_pda).then(|| conf_evicted_raw.clone()),
            &program_id,
            0,
            &[(0, 1)],
        )
        .unwrap();
        assert_eq!(snap_evicted.ring_kind, ROOT_RING_SLOT);
        assert_eq!(snap_evicted.ring_idx, 5);
        assert_eq!(
            snap_evicted.super_root,
            fr_to_be_bytes(&compute_super_root_4ary(&r3))
        );

        // (e) Same live slot entry intact in confirmed OR confirmed missing -> returns finalized choice
        let (_, snap_same) = fetch_root_history(
            |a| (*a == roots_pda).then(|| fin_raw.clone()),
            |a| (*a == roots_pda).then(|| fin_raw.clone()),
            &program_id,
            0,
            &[(0, 1)],
        )
        .unwrap();
        assert_eq!(snap_same.ring_kind, ROOT_RING_SLOT);
        assert_eq!(snap_same.ring_idx, 5);
        assert_eq!(
            snap_same.super_root,
            fr_to_be_bytes(&compute_super_root_4ary(&r2))
        );

        let (_, snap_conf_none) = fetch_root_history(
            |a| (*a == roots_pda).then(|| fin_raw.clone()),
            |_| None,
            &program_id,
            0,
            &[(0, 1)],
        )
        .unwrap();
        assert_eq!(snap_conf_none.ring_kind, ROOT_RING_SLOT);
        assert_eq!(snap_conf_none.ring_idx, 5);

        // (f) Tampered confirmed payload when upgrading from finalized ROOT_RING_SLOT MUST still error
        let mut tampered_conf = conf_epoch_raw;
        tampered_conf[RT_OFF_EPOCH_RING + 3 * ROOT_ENTRY_LEN] ^= 0xff;
        assert!(fetch_root_history(
            |a| (*a == roots_pda).then(|| fin_raw.clone()),
            |a| (*a == roots_pda).then(|| tampered_conf.clone()),
            &program_id,
            0,
            &[(0, 1)],
        )
        .is_err());

        // (g) Cross-slot lagging confirmed replica (`confirmed.latest_slot < fin.latest_slot`)
        //     MUST NOT downgrade newer finalized ROOT_RING_SLOT!
        let fin_slot200_raw = set_ring_meta(
            make_root_history(0, &r3, &c3, &r1, &c1),
            5,
            6,
            200,
            2,
            3,
            96,
        );
        let conf_lagging_slot198_raw = set_ring_meta(
            make_root_history(0, &r2, &c2, &r1, &c1),
            3,
            4,
            198,
            2,
            3,
            96,
        );
        let (_, snap_cross_slot_lag) = fetch_root_history(
            |a| (*a == roots_pda).then(|| fin_slot200_raw.clone()),
            |a| (*a == roots_pda).then(|| conf_lagging_slot198_raw.clone()),
            &program_id,
            0,
            &[(0, 1)],
        )
        .unwrap();
        assert_eq!(snap_cross_slot_lag.ring_kind, ROOT_RING_SLOT);
        assert_eq!(snap_cross_slot_lag.ring_idx, 5);
        assert_eq!(snap_cross_slot_lag.slot, 200);
        assert_eq!(
            snap_cross_slot_lag.super_root,
            fr_to_be_bytes(&compute_super_root_4ary(&r3))
        );

        // (h1) Same-slot mid-slot lagging confirmed replica (in-place overwrite: finalized post-Tx-2
        //      c3/r3 at slot 104 ring_idx=5 vs lagging confirmed pre-Tx-2 c2/r2 at slot 104 ring_idx=5)
        //      MUST NOT downgrade to already-overwritten super_root!
        let (_, snap_same_slot_overwrite_lag) = fetch_root_history(
            |a| (*a == roots_pda).then(|| conf_evicted_raw.clone()),
            |a| (*a == roots_pda).then(|| fin_raw.clone()),
            &program_id,
            0,
            &[(0, 1)],
        )
        .unwrap();
        assert_eq!(snap_same_slot_overwrite_lag.ring_kind, ROOT_RING_SLOT);
        assert_eq!(snap_same_slot_overwrite_lag.ring_idx, 5);
        assert_eq!(snap_same_slot_overwrite_lag.slot, 104);
        assert_eq!(
            snap_same_slot_overwrite_lag.super_root,
            fr_to_be_bytes(&compute_super_root_4ary(&r3))
        );

        // (h2) Same-slot mid-slot lagging confirmed replica (same_slot_bumped: finalized post-Tx-2
        //      c3/r3 at slot 104 ring_idx=6 vs lagging confirmed pre-Tx-2 c2/r2 at slot 104 ring_idx=5)
        //      MUST NOT downgrade to earlier slot_ring index!
        let (_, snap_same_slot_bump_lag) = fetch_root_history(
            |a| (*a == roots_pda).then(|| conf_bumped_idx_raw.clone()),
            |a| (*a == roots_pda).then(|| fin_raw.clone()),
            &program_id,
            0,
            &[(0, 1)],
        )
        .unwrap();
        assert_eq!(snap_same_slot_bump_lag.ring_kind, ROOT_RING_SLOT);
        assert_eq!(snap_same_slot_bump_lag.ring_idx, 6);
        assert_eq!(snap_same_slot_bump_lag.slot, 104);
        assert_eq!(
            snap_same_slot_bump_lag.super_root,
            fr_to_be_bytes(&compute_super_root_4ary(&r3))
        );

        // (i) Non-monotonic multi-lane confirmed view (lane 0 & slot ahead, lane 1 behind finalized)
        //     MUST NOT downgrade finalized!
        let mut r_fin_ml = r2;
        r_fin_ml[1] =
            compute_lane_root_from_subroots_and_frontier(&[], Some(&[leaf0]), 1).unwrap();
        let mut c_fin_ml = c2;
        c_fin_ml[1] = 1;
        let fin_ml_raw = set_ring_meta(
            make_root_history(0, &r_fin_ml, &c_fin_ml, &r1, &c1),
            5,
            6,
            104,
            2,
            3,
            96,
        );
        let (_, snap_non_monotonic_lane) = fetch_root_history(
            |a| (*a == roots_pda).then(|| fin_ml_raw.clone()),
            |a| (*a == roots_pda).then(|| conf_newer_slot_raw.clone()),
            &program_id,
            0,
            &[(0, 1)],
        )
        .unwrap();
        assert_eq!(snap_non_monotonic_lane.ring_kind, ROOT_RING_SLOT);
        assert_eq!(snap_non_monotonic_lane.ring_idx, 5);
        assert_eq!(snap_non_monotonic_lane.slot, 104);
        assert_eq!(
            snap_non_monotonic_lane.super_root,
            fr_to_be_bytes(&compute_super_root_4ary(&r_fin_ml))
        );
    }

    #[test]
    fn fetch_root_history_rejects_lagging_confirmed_when_note_missing_from_finalized() {
        use audren_core::{
            layout::{
                RT_OFF_EPOCH_COUNT, RT_OFF_EPOCH_CURSOR, RT_OFF_EPOCH_RING, RT_OFF_LATEST_SLOT,
                RT_OFF_SLOT_COUNT, RT_OFF_SLOT_CURSOR, RT_OFF_SLOT_RING, RT_OFF_STABLE_EPOCH_ID,
                RT_OFF_STABLE_SLOT,
            },
            DEFAULT_ROOT_EPOCH_INTERVAL, ROOT_ENTRY_LEN,
        };

        let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
        let roots_pda = derive_roots_pda(&program_id, 0).0;
        let zeros = zero_hashes_4ary();

        let leaf0 = Fr::from(101u64);
        let leaf1 = Fr::from(202u64);
        let leaf_lane1 = Fr::from(303u64);

        let lane0_r1 =
            compute_lane_root_from_subroots_and_frontier(&[], Some(&[leaf0]), 1).unwrap();
        let lane0_r2 =
            compute_lane_root_from_subroots_and_frontier(&[], Some(&[leaf0, leaf1]), 2).unwrap();
        let lane1_r1 =
            compute_lane_root_from_subroots_and_frontier(&[], Some(&[leaf_lane1]), 1).unwrap();

        let make_roots = |l0_count: u64, l1_count: u64| -> ([Fr; NUM_LANES], [u64; NUM_LANES]) {
            let mut r = [zeros[LANE_DEPTH_4ARY]; NUM_LANES];
            let mut c = [0u64; NUM_LANES];
            if l0_count == 1 {
                r[0] = lane0_r1;
            } else if l0_count == 2 {
                r[0] = lane0_r2;
            }
            if l1_count == 1 {
                r[1] = lane1_r1;
            }
            c[0] = l0_count;
            c[1] = l1_count;
            (r, c)
        };

        let build_rh = |latest_l0: u64,
                        latest_l1: u64,
                        stable_l0: u64,
                        stable_l1: u64,
                        latest_slot: u64,
                        stable_slot: u64|
         -> Vec<u8> {
            let (lr, lc) = make_roots(latest_l0, latest_l1);
            let (sr, sc) = make_roots(stable_l0, stable_l1);
            let mut raw = make_root_history(0, &lr, &lc, &sr, &sc);
            let latest_sr: [u8; 32] = raw[audren_core::layout::RT_OFF_LATEST_SUPER_ROOT
                ..audren_core::layout::RT_OFF_LATEST_SUPER_ROOT + 32]
                .try_into()
                .unwrap();
            let stable_sr: [u8; 32] = raw[audren_core::layout::RT_OFF_STABLE_SUPER_ROOT
                ..audren_core::layout::RT_OFF_STABLE_SUPER_ROOT + 32]
                .try_into()
                .unwrap();
            raw[RT_OFF_SLOT_CURSOR..RT_OFF_SLOT_CURSOR + 2].copy_from_slice(&5u16.to_le_bytes());
            raw[RT_OFF_SLOT_COUNT..RT_OFF_SLOT_COUNT + 2].copy_from_slice(&6u16.to_le_bytes());
            raw[RT_OFF_LATEST_SLOT..RT_OFF_LATEST_SLOT + 8]
                .copy_from_slice(&latest_slot.to_le_bytes());
            raw[RT_OFF_EPOCH_CURSOR..RT_OFF_EPOCH_CURSOR + 2].copy_from_slice(&2u16.to_le_bytes());
            raw[RT_OFF_EPOCH_COUNT..RT_OFF_EPOCH_COUNT + 2].copy_from_slice(&3u16.to_le_bytes());
            raw[RT_OFF_STABLE_SLOT..RT_OFF_STABLE_SLOT + 8]
                .copy_from_slice(&stable_slot.to_le_bytes());
            raw[RT_OFF_STABLE_EPOCH_ID..RT_OFF_STABLE_EPOCH_ID + 8]
                .copy_from_slice(&(stable_slot / DEFAULT_ROOT_EPOCH_INTERVAL).to_le_bytes());
            let s_off = RT_OFF_SLOT_RING + 5 * ROOT_ENTRY_LEN;
            raw[s_off..s_off + 32].copy_from_slice(&latest_sr);
            raw[s_off + 32..s_off + 40].copy_from_slice(&latest_slot.to_le_bytes());
            let e_off = RT_OFF_EPOCH_RING + 2 * ROOT_ENTRY_LEN;
            raw[e_off..e_off + 32].copy_from_slice(&stable_sr);
            raw[e_off + 32..e_off + 40].copy_from_slice(&stable_slot.to_le_bytes());
            raw
        };

        // Note `(0, 1)` is missing from `finalized` (lane 0 count = 1, so `select_snapshot_for_notes`
        // returns `None`) and present in `confirmed` (lane 0 count = 2). Every lagging/inconsistent
        // `confirmed` vector MUST fail closed with `InvalidEncoding` rather than being accepted.
        let lagging_cases: &[(&str, Vec<u8>, Vec<u8>)] = &[
            (
                "confirmed.latest_slot < fin.latest_slot",
                build_rh(1, 0, 1, 0, 200, 96),
                build_rh(2, 0, 1, 0, 198, 96),
            ),
            (
                "confirmed.stable_slot < fin.stable_slot",
                build_rh(1, 0, 1, 0, 150, 128),
                build_rh(2, 0, 1, 0, 160, 96),
            ),
            (
                "confirmed.latest_lane_counts[1] < fin.latest_lane_counts[1]",
                build_rh(1, 1, 1, 0, 150, 96),
                build_rh(2, 0, 1, 0, 160, 96),
            ),
            (
                "confirmed.stable_lane_counts[1] < fin.stable_lane_counts[1]",
                build_rh(1, 1, 1, 1, 150, 128),
                build_rh(2, 1, 1, 0, 160, 128),
            ),
        ];

        for (label, fin_raw, conf_raw) in lagging_cases {
            let err = fetch_root_history(
                |a| (*a == roots_pda).then(|| fin_raw.clone()),
                |a| (*a == roots_pda).then(|| conf_raw.clone()),
                &program_id,
                0,
                &[(0, 1)],
            )
            .expect_err(&format!(
                "fetch_root_history must reject lagging confirmed snapshot ({label})"
            ));
            assert!(
                matches!(
                    err,
                    ClientError::InvalidEncoding(
                        "confirmed GlobalRootHistory lags behind finalized snapshot"
                    )
                ),
                "unexpected error for {label}: {err:?}"
            );
        }

        // Positive control: monotonic confirmed snapshot carrying the fresh note `(0, 1)` succeeds.
        let fin_ok = build_rh(1, 1, 1, 1, 150, 128);
        let conf_ok = build_rh(2, 1, 1, 1, 160, 128);
        let (_, snap_ok) = fetch_root_history(
            |a| (*a == roots_pda).then(|| fin_ok.clone()),
            |a| (*a == roots_pda).then(|| conf_ok.clone()),
            &program_id,
            0,
            &[(0, 1)],
        )
        .expect("monotonic confirmed snapshot with new note must succeed");
        let (expected_roots, _) = make_roots(2, 1);
        assert_eq!(snap_ok.ring_kind, ROOT_RING_SLOT);
        assert_eq!(snap_ok.ring_idx, 5);
        assert_eq!(snap_ok.slot, 160);
        assert_eq!(
            snap_ok.super_root,
            fr_to_be_bytes(&compute_super_root_4ary(&expected_roots))
        );
    }

    #[test]
    fn sync_verifies_pass1a_subroots_and_frontier_against_lane_current_root() {
        let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
        let alice = AudrenKeys::from_seed(&[0x9du8; 32]);
        let fvk = alice.full_viewing_key();
        let sol_asset = derive_asset_id(&WSOL_MINT);

        let sealed_leaves: Vec<Fr> = (0..SUBTREE_LEAVES)
            .map(|i| Fr::from((i + 100) as u64))
            .collect();
        let sealed_subroot = compute_subtree_256_root(&sealed_leaves, SUBTREE_LEAVES);

        let (tw, bl, memo_106) =
            encrypt_note_memo(&alice.view_pk, [0x9eu8; 32], 5_555_555, &WSOL_MINT).unwrap();
        let alice_cm = compute_note_commitment(
            derive_stealth_owner(alice.spend_pk, tw),
            sol_asset,
            5_555_555,
            bl,
        );
        // 1 sealed subtree (256 leaves) + 3 frontier leaves (alice_cm at leaf 257 -> frontier slot 1)
        let frontier_3 = vec![Fr::from(701u64), alice_cm, Fr::from(703u64)];
        let frontier_4_live = vec![Fr::from(701u64), alice_cm, Fr::from(703u64), Fr::from(704u64)];
        let next_leaf = (SUBTREE_LEAVES + 3) as u64;
        let real_lane_root = compute_lane_root_from_subroots_and_frontier(
            &[sealed_subroot],
            Some(&frontier_3),
            3,
        )
        .unwrap();

        let pool_pda = derive_pool_pda(&program_id, 0).0;
        let lane0_pda = derive_lane_pda(&program_id, 0, 0).0;
        let sr0_pda = derive_subroot_pda(&program_id, 0, 0, 0).0;
        let sub0_pda = derive_subtree_pda(&program_id, 0, 0, 0).0;
        let sub1_pda = derive_subtree_pda(&program_id, 0, 0, 1).0;

        let mut base_accounts: BTreeMap<Address, Vec<u8>> = BTreeMap::new();
        base_accounts.insert(pool_pda, make_pool(1));
        base_accounts.insert(lane0_pda, make_lane_with_root(0, next_leaf, 0, real_lane_root));
        base_accounts.insert(sr0_pda, make_subroot(0, 0, &[sealed_subroot]));
        base_accounts.insert(sub0_pda, make_subtree(0, 0, &sealed_leaves));
        base_accounts.insert(sub1_pda, make_subtree(0, 1, &frontier_3));
        let memo_pages = (next_leaf as usize).div_ceil(MEMO_NOTES_PER_PAGE);
        for m in 0..memo_pages {
            let cnt = MEMO_NOTES_PER_PAGE.min(next_leaf as usize - m * MEMO_NOTES_PER_PAGE) as u16;
            let mut mraw = make_memo(0, m as u64, cnt, 0);
            let target = SUBTREE_LEAVES + 1;
            if target / MEMO_NOTES_PER_PAGE == m {
                write_memo(&mut mraw, target % MEMO_NOTES_PER_PAGE, &memo_106);
            }
            base_accounts.insert(derive_memo_pda(&program_id, 0, 0, m as u64).0, mraw);
        }

        // (a) Tampered/fork-skewed frontier SubtreePage (both exact length `frontier_rem` and
        //     `frontier_rem + 1` with valid canonical Fr leaves) MUST be rejected and MUST NOT
        //     advance `next_memo_leaf` or poison `frontier_leaves` / `finalized_subroots`!
        let tampered_frontier_3 = vec![Fr::from(701u64), Fr::from(999_999u64), Fr::from(703u64)];
        let tampered_frontier_4 = vec![
            Fr::from(701u64),
            Fr::from(999_999u64),
            Fr::from(703u64),
            Fr::from(704u64),
        ];
        for (label, bad_frontier) in [
            ("tampered frontier (len == frontier_rem)", &tampered_frontier_3),
            ("tampered frontier (len == frontier_rem + 1)", &tampered_frontier_4),
        ] {
            let mut bad_accounts = base_accounts.clone();
            bad_accounts.insert(sub1_pda, make_subtree(0, 1, bad_frontier));
            let mut st = CompactWalletStore::new(0, 0);
            let err = sync_compact_store_with_batch(
                &mut st,
                &fvk,
                |addrs, _| addrs.iter().map(|a| bad_accounts.get(a).cloned()).collect(),
                &program_id,
                SyncOptions::default(),
            )
            .expect_err(&format!("{label} must be rejected"));
            assert!(
                matches!(
                    err,
                    ClientError::InvalidEncoding(
                        "lane root mismatch against LaneTreeState.current_root"
                    )
                ),
                "unexpected error for {label}: {err:?}"
            );
            assert_eq!(st.lanes[0].next_memo_leaf, 0);
            assert!(st.lanes[0].frontier_leaves.is_empty());
            assert!(st.lanes[0].finalized_subroots.is_empty());
            assert!(st.notes.is_empty());
        }

        // (b) Tampered Pass 1A SubtreeRootPage in Fast mode (0 hits, frontier_rem == 0, so zero
        //     SubtreePages are fetched) MUST still be rejected against `LaneTreeState.current_root`!
        {
            let sealed_only_root =
                compute_lane_root_from_subroots_and_frontier(&[sealed_subroot], None, 0).unwrap();
            let bogus_subroot = Fr::from(42_424_242u64);
            let mut bad_sr_accounts = BTreeMap::new();
            bad_sr_accounts.insert(pool_pda, make_pool(1));
            bad_sr_accounts.insert(
                lane0_pda,
                make_lane_with_root(0, SUBTREE_LEAVES as u64, 0, sealed_only_root),
            );
            bad_sr_accounts.insert(sr0_pda, make_subroot(0, 0, &[bogus_subroot]));
            for m in 0..SUBTREE_LEAVES.div_ceil(MEMO_NOTES_PER_PAGE) {
                let cnt = MEMO_NOTES_PER_PAGE
                    .min(SUBTREE_LEAVES - m * MEMO_NOTES_PER_PAGE) as u16;
                bad_sr_accounts.insert(
                    derive_memo_pda(&program_id, 0, 0, m as u64).0,
                    make_memo(0, m as u64, cnt, 0),
                );
            }
            let mut st = CompactWalletStore::new(0, 0);
            let err = sync_compact_store_with_batch(
                &mut st,
                &fvk,
                |addrs, _| addrs.iter().map(|a| bad_sr_accounts.get(a).cloned()).collect(),
                &program_id,
                SyncOptions {
                    privacy_mode: SyncPrivacyMode::Fast,
                    decoy_epoch_bucket: None,
                },
            )
            .expect_err("tampered Pass 1A SubtreeRootPage must be rejected");
            assert!(matches!(
                err,
                ClientError::InvalidEncoding(
                    "lane root mismatch against LaneTreeState.current_root"
                )
            ));
            assert!(st.lanes[0].finalized_subroots.is_empty());
            assert_eq!(st.lanes[0].next_memo_leaf, 0);
        }

        // (c) Live-advancing frontier SubtreePage (`frontier_rem + 1` leaves matching the first
        //     `frontier_rem` leaves of `LaneTreeState.current_root`) MUST succeed cleanly and
        //     commit ONLY the verified `frontier_rem` (3) leaves!
        {
            let mut live_accounts = base_accounts.clone();
            live_accounts.insert(sub1_pda, make_subtree(0, 1, &frontier_4_live));
            let mut st = CompactWalletStore::new(0, 0);
            let (_, _, discovered) = sync_compact_store_with_batch(
                &mut st,
                &fvk,
                |addrs, _| addrs.iter().map(|a| live_accounts.get(a).cloned()).collect(),
                &program_id,
                SyncOptions::default(),
            )
            .expect("live-advancing frontier SubtreePage must verify against Phase 0 current_root");
            assert_eq!(discovered, 1);
            assert_eq!(st.notes.len(), 1);
            assert_eq!(st.notes[0].leaf_index, (SUBTREE_LEAVES + 1) as u64);
            assert_eq!(st.lanes[0].next_memo_leaf, next_leaf);
            assert_eq!(st.lanes[0].finalized_subroots.len(), 1);
            assert_eq!(st.lanes[0].frontier_sub_seq, 1);
            assert_eq!(
                st.lanes[0].frontier_leaves.len(),
                3,
                "unverified trailing live leaf beyond frontier_rem must NOT be committed"
            );
            for (idx, expected) in frontier_3.iter().enumerate() {
                assert_eq!(st.lanes[0].frontier_leaves[idx], fr_to_be_bytes(expected));
            }
        }
    }

    #[test]
    fn fetch_root_history_enforces_epoch_interval_and_equal_count_lane_root_parity() {
        use audren_core::{
            layout::{
                RT_OFF_EPOCH_COUNT, RT_OFF_EPOCH_CURSOR, RT_OFF_EPOCH_INTERVAL, RT_OFF_EPOCH_RING,
                RT_OFF_LATEST_SLOT, RT_OFF_SLOT_COUNT, RT_OFF_SLOT_CURSOR, RT_OFF_SLOT_RING,
                RT_OFF_STABLE_EPOCH_ID, RT_OFF_STABLE_SLOT,
            },
            ROOT_ENTRY_LEN,
        };

        let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
        let roots_pda = derive_roots_pda(&program_id, 0).0;
        let zeros = zero_hashes_4ary();

        let l0_1 = compute_lane_root_from_subroots_and_frontier(&[], Some(&[Fr::from(11u64)]), 1)
            .unwrap();
        let l0_2 = compute_lane_root_from_subroots_and_frontier(
            &[],
            Some(&[Fr::from(11u64), Fr::from(22u64)]),
            2,
        )
        .unwrap();
        let l0_3 = compute_lane_root_from_subroots_and_frontier(
            &[],
            Some(&[Fr::from(11u64), Fr::from(22u64), Fr::from(33u64)]),
            3,
        )
        .unwrap();

        let l1_a1 = compute_lane_root_from_subroots_and_frontier(&[], Some(&[Fr::from(101u64)]), 1)
            .unwrap();
        let l1_a2 = compute_lane_root_from_subroots_and_frontier(
            &[],
            Some(&[Fr::from(101u64), Fr::from(102u64)]),
            2,
        )
        .unwrap();
        let l1_b1 = compute_lane_root_from_subroots_and_frontier(&[], Some(&[Fr::from(201u64)]), 1)
            .unwrap();
        let l1_b2 = compute_lane_root_from_subroots_and_frontier(
            &[],
            Some(&[Fr::from(201u64), Fr::from(202u64)]),
            2,
        )
        .unwrap();
        let l1_b3 = compute_lane_root_from_subroots_and_frontier(
            &[],
            Some(&[Fr::from(201u64), Fr::from(202u64), Fr::from(203u64)]),
            3,
        )
        .unwrap();

        let make_state = |l0: (u64, Fr), l1: (u64, Fr)| -> ([Fr; NUM_LANES], [u64; NUM_LANES]) {
            let mut r = [zeros[LANE_DEPTH_4ARY]; NUM_LANES];
            let mut c = [0u64; NUM_LANES];
            if l0.0 > 0 {
                r[0] = l0.1;
                c[0] = l0.0;
            }
            if l1.0 > 0 {
                r[1] = l1.1;
                c[1] = l1.0;
            }
            (r, c)
        };

        let build_rh = |latest_l0: (u64, Fr),
                        latest_l1: (u64, Fr),
                        stable_l0: (u64, Fr),
                        stable_l1: (u64, Fr),
                        latest_slot: u64,
                        stable_slot: u64,
                        epoch_interval: u64|
         -> Vec<u8> {
            let (lr, lc) = make_state(latest_l0, latest_l1);
            let (sr, sc) = make_state(stable_l0, stable_l1);
            let mut raw = make_root_history(0, &lr, &lc, &sr, &sc);
            let latest_sr: [u8; 32] = raw[audren_core::layout::RT_OFF_LATEST_SUPER_ROOT
                ..audren_core::layout::RT_OFF_LATEST_SUPER_ROOT + 32]
                .try_into()
                .unwrap();
            let stable_sr: [u8; 32] = raw[audren_core::layout::RT_OFF_STABLE_SUPER_ROOT
                ..audren_core::layout::RT_OFF_STABLE_SUPER_ROOT + 32]
                .try_into()
                .unwrap();
            raw[RT_OFF_SLOT_CURSOR..RT_OFF_SLOT_CURSOR + 2].copy_from_slice(&5u16.to_le_bytes());
            raw[RT_OFF_SLOT_COUNT..RT_OFF_SLOT_COUNT + 2].copy_from_slice(&6u16.to_le_bytes());
            raw[RT_OFF_LATEST_SLOT..RT_OFF_LATEST_SLOT + 8]
                .copy_from_slice(&latest_slot.to_le_bytes());
            raw[RT_OFF_EPOCH_CURSOR..RT_OFF_EPOCH_CURSOR + 2].copy_from_slice(&2u16.to_le_bytes());
            raw[RT_OFF_EPOCH_COUNT..RT_OFF_EPOCH_COUNT + 2].copy_from_slice(&3u16.to_le_bytes());
            raw[RT_OFF_STABLE_SLOT..RT_OFF_STABLE_SLOT + 8]
                .copy_from_slice(&stable_slot.to_le_bytes());
            raw[RT_OFF_EPOCH_INTERVAL..RT_OFF_EPOCH_INTERVAL + 8]
                .copy_from_slice(&epoch_interval.to_le_bytes());
            raw[RT_OFF_STABLE_EPOCH_ID..RT_OFF_STABLE_EPOCH_ID + 8]
                .copy_from_slice(&(stable_slot / epoch_interval).to_le_bytes());
            let s_off = RT_OFF_SLOT_RING + 5 * ROOT_ENTRY_LEN;
            raw[s_off..s_off + 32].copy_from_slice(&latest_sr);
            raw[s_off + 32..s_off + 40].copy_from_slice(&latest_slot.to_le_bytes());
            let e_off = RT_OFF_EPOCH_RING + 2 * ROOT_ENTRY_LEN;
            raw[e_off..e_off + 32].copy_from_slice(&stable_sr);
            raw[e_off + 32..e_off + 40].copy_from_slice(&stable_slot.to_le_bytes());
            raw
        };

        let z0 = (0u64, zeros[LANE_DEPTH_4ARY]);
        // Each pair has finalized latest_l0 = 2 (stable_l0 = 1) and confirmed latest_l0 = 3 (stable_l0 = 2):
        // - Querying note `(0, 1)` has `finalizedSlotFallback` -> must fall back to `finalized`!
        // - Querying note `(0, 2)` is absent from `finalized` -> must fail closed!
        let mismatch_cases: &[(&str, Vec<u8>, Vec<u8>)] = &[
            (
                "epoch_interval mismatch",
                build_rh((2, l0_2), z0, (1, l0_1), z0, 150, 128, 32),
                build_rh((3, l0_3), z0, (2, l0_2), z0, 160, 128, 64),
            ),
            (
                "latest == latest lane_root mismatch",
                build_rh((2, l0_2), (1, l1_a1), (1, l0_1), z0, 150, 128, 32),
                build_rh((3, l0_3), (1, l1_b1), (2, l0_2), z0, 160, 128, 32),
            ),
            (
                "stable == stable lane_root mismatch",
                build_rh((2, l0_2), (2, l1_a2), (1, l0_1), (1, l1_a1), 150, 128, 32),
                build_rh((3, l0_3), (3, l1_b3), (2, l0_2), (1, l1_b1), 160, 128, 32),
            ),
            (
                "conf.stable == fin.latest lane_root mismatch",
                build_rh((2, l0_2), (1, l1_a1), (1, l0_1), z0, 150, 128, 32),
                build_rh((3, l0_3), (2, l1_b2), (2, l0_2), (1, l1_b1), 160, 128, 32),
            ),
            (
                "conf.latest == fin.stable lane_root mismatch",
                build_rh((2, l0_2), (1, l1_a1), (1, l0_1), (1, l1_a1), 150, 128, 32),
                build_rh((3, l0_3), (1, l1_b1), (2, l0_2), (1, l1_b1), 160, 128, 32),
            ),
        ];

        for (label, fin_raw, conf_raw) in mismatch_cases {
            let fin_decoded = decode_global_root_history(fin_raw).unwrap();
            // Branch 1: `finalizedSlotFallback` present for note `(0, 1)` -> fall back to `finalized`
            let (chosen_rh, chosen_snap) = fetch_root_history(
                |a| (*a == roots_pda).then(|| fin_raw.clone()),
                |a| (*a == roots_pda).then(|| conf_raw.clone()),
                &program_id,
                0,
                &[(0, 1)],
            )
            .expect(&format!("{label}: must fall back to finalizedSlotFallback"));
            assert_eq!(chosen_snap.ring_kind, ROOT_RING_SLOT, "{label}");
            assert_eq!(chosen_snap.slot, 150, "{label}");
            assert_eq!(
                chosen_rh.latest_super_root, fin_decoded.latest_super_root,
                "{label}: must NOT upgrade to contradicting confirmed snapshot"
            );

            // Branch 2: note `(0, 2)` missing from `finalized` -> fail closed!
            let err = fetch_root_history(
                |a| (*a == roots_pda).then(|| fin_raw.clone()),
                |a| (*a == roots_pda).then(|| conf_raw.clone()),
                &program_id,
                0,
                &[(0, 2)],
            )
            .expect_err(&format!("{label}: must fail closed without finalized fallback"));
            assert!(
                matches!(
                    err,
                    ClientError::InvalidEncoding(
                        "confirmed GlobalRootHistory lags behind finalized snapshot"
                    )
                ),
                "unexpected error for {label}: {err:?}"
            );
        }
    }
}
