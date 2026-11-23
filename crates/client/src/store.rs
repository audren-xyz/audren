//! Zero-indexer `CompactWalletStore` for ordinary Solana RPC (`getMultipleAccounts`) sync.
//!
//! Discards every sealed `SubtreePage` (`8,256 B`), `MemoPage` (`10,144 B`), and stranger
//! `NullifierPage` prefix immediately after scanning, retaining ONLY:
//! - Frozen 4-level (`12` siblings = `384 B`) intra-subtree siblings for each owned unspent note
//! - `32 B` finalized level-4 subroots per 256-leaf page (`1.28 MB` total at 10M pool notes = `980x` smaller!)
//! - Unsealed frontier `SubtreePage` tail leaves per active lane (plus at most 1 just-sealed page
//!   until a newer `RootCheckpoint` crosses it)

use std::collections::{BTreeMap, HashMap, HashSet};

use ark_bn254::Fr;
use audren_circuits::{
    merkle::{
        build_witness_from_frozen_subsiblings, compute_subtree_256_root,
        extract_intra_subtree_siblings, MerklePath4Ary, SUBTREE_LEVELS_4ARY,
    },
    note::{compute_note_commitment, derive_asset_id},
    poseidon::{fr_from_be_bytes_strict, fr_to_be_bytes},
};
use audren_core::{
    layout::{
        read_32, read_u16, RootCheckpoint, MEMO_CT_LEN, MEMO_MAGIC, MEMO_NOTES_PER_PAGE,
        MEMO_PAGE_LEN, MM_OFF_CIPHERTEXTS, MM_OFF_COUNT, MM_OFF_EPHEMERAL_PKS, MM_OFF_VIEW_TAGS,
        NF_OFF_COUNT, NF_OFF_PREFIXES, NF_PAGE_LEN, NF_PAGE_MAGIC, NF_PER_PAGE, NF_PREFIX_LEN,
        SB_OFF_COUNT, SB_OFF_LEAVES, SR_OFF_COUNT, SR_OFF_ROOTS, SUBROOTS_PER_PAGE, SUBROOT_MAGIC,
        SUBROOT_PAGE_LEN, SUBTREE_LEAVES, SUBTREE_MAGIC, SUBTREE_PAGE_LEN,
    },
    NUM_LANES,
};
use serde::{Deserialize, Serialize};

use crate::{
    keys::{
        try_decrypt_and_verify_memo_entry, DecryptedMemo, FullViewingKey,
        SelectiveDisclosureProof,
    },
    ClientError,
};

/// An owned shielded note tracked by `CompactWalletStore`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedNote {
    pub pool_id: u32,
    pub lane_id: u8,
    pub leaf_index: u64,
    pub global_leaf_index: u64,
    pub mint: [u8; 32],
    pub amount: u64,
    pub tweak: [u8; 32],
    pub blinding: [u8; 32],
    pub stealth_owner: [u8; 32],
    pub commitment: [u8; 32],
    pub nullifier: [u8; 32],
    pub is_dynamic: bool,
    pub spent: bool,
    /// Frozen 4-level intra-subtree siblings (`12 x 32 B = 384 B`) populated once the note's
    /// 256-leaf `SubtreePage` seals (allowing the `8,256 B` page to be permanently discarded).
    pub frozen_intra_siblings: Option<[[[u8; 32]; 3]; SUBTREE_LEVELS_4ARY]>,
    pub frozen_intra_positions: Option<[u8; SUBTREE_LEVELS_4ARY]>,
}

impl OwnedNote {
    /// Export a Mode 1 per-transaction `SelectiveDisclosureProof` (discloses zero keys).
    pub fn selective_disclosure_proof(&self) -> SelectiveDisclosureProof {
        SelectiveDisclosureProof {
            pool_id: self.pool_id,
            lane_id: self.lane_id,
            leaf_index: self.leaf_index,
            stealth_owner: self.stealth_owner,
            mint: self.mint,
            amount: self.amount,
            blinding: self.blinding,
            commitment: self.commitment,
        }
    }

    pub fn tweak_fr(&self) -> Result<Fr, ClientError> {
        fr_from_be_bytes_strict(&self.tweak).ok_or(ClientError::InvalidFieldElement)
    }

    pub fn blinding_fr(&self) -> Result<Fr, ClientError> {
        fr_from_be_bytes_strict(&self.blinding).ok_or(ClientError::InvalidFieldElement)
    }

    pub fn asset_id_fr(&self) -> Fr {
        derive_asset_id(&self.mint)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CompactLaneState {
    /// Finalized 256-leaf level-4 subtree roots (`32 B` per 256 pool notes).
    pub finalized_subroots: Vec<[u8; 32]>,
    /// Unsealed frontier `SubtreePage` sequence (`== finalized_subroots.len()`).
    pub frontier_sub_seq: u64,
    /// Current leaves in the unsealed frontier `SubtreePage` (`< 256` entries).
    pub frontier_leaves: Vec<[u8; 32]>,
    /// Most recently sealed `SubtreePage` sequence retained until a newer `RootCheckpoint` crosses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_sealed_sub_seq: Option<u64>,
    /// Leaves of `prev_sealed_sub_seq` (at most 1 page = 8 KB per lane), pruned once crossed by a checkpoint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prev_sealed_leaves: Vec<[u8; 32]>,
    /// Next memo index (`lane_leaf_index`) to scan in this lane.
    pub next_memo_leaf: u64,
    /// Next nullifier prefix index to scan in this lane.
    pub next_nf_index: u64,
}

/// Persistent, indexer-free mobile & desktop wallet store (`1.28 MB` @ 10M notes, `0` targeted RPCs).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactWalletStore {
    pub pool_id: u32,
    pub birthday_slot: u64,
    pub lanes: Vec<CompactLaneState>,
    pub notes: Vec<OwnedNote>,
}

#[derive(Deserialize)]
struct CompactWalletStoreWire {
    pool_id: u32,
    birthday_slot: u64,
    lanes: Vec<CompactLaneState>,
    notes: Vec<OwnedNote>,
    #[serde(default)]
    seen_nf_prefixes: Vec<[u8; NF_PREFIX_LEN]>,
}

impl CompactWalletStore {
    pub fn new(pool_id: u32, birthday_slot: u64) -> Self {
        Self {
            pool_id,
            birthday_slot,
            lanes: (0..NUM_LANES).map(|_| CompactLaneState::default()).collect(),
            notes: Vec::new(),
        }
    }

    /// Serialize compact store to JSON bytes (mobile disk / browser IndexedDB).
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, ClientError> {
        serde_json::to_vec(self).map_err(|_| ClientError::InvalidEncoding("serialize store"))
    }

    /// Restore compact store from persisted JSON bytes (backwards-compatible with legacy
    /// snapshots containing `seen_nf_prefixes`, which are applied and immediately discarded).
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ClientError> {
        let mut wire: CompactWalletStoreWire = serde_json::from_slice(bytes)
            .map_err(|_| ClientError::InvalidEncoding("deserialize store"))?;
        if !wire.seen_nf_prefixes.is_empty() {
            let legacy: HashSet<[u8; NF_PREFIX_LEN]> = wire.seen_nf_prefixes.into_iter().collect();
            for note in &mut wire.notes {
                if !note.spent {
                    let pref: [u8; NF_PREFIX_LEN] = note.nullifier[0..NF_PREFIX_LEN].try_into().unwrap();
                    if legacy.contains(&pref) {
                        note.spent = true;
                    }
                }
            }
        }
        Ok(Self {
            pool_id: wire.pool_id,
            birthday_slot: wire.birthday_slot,
            lanes: wire.lanes,
            notes: wire.notes,
        })
    }

    /// Return all currently unspent notes matching `mint` (or all mints if `None`).
    pub fn unspent_notes(&self, mint: Option<&[u8; 32]>) -> Vec<&OwnedNote> {
        self.notes
            .iter()
            .filter(|n| !n.spent && mint.map(|m| &n.mint == m).unwrap_or(true))
            .collect()
    }

    /// Compute total unspent shielded balance per mint.
    pub fn balances(&self) -> BTreeMap<[u8; 32], u64> {
        let mut out = BTreeMap::new();
        for n in &self.notes {
            if !n.spent {
                *out.entry(n.mint).or_insert(0) += n.amount;
            }
        }
        out
    }

    /// Record a decrypted and commitment-verified owned note if not already present.
    pub fn record_verified_memo(
        &mut self,
        fvk: &FullViewingKey,
        lane_id: u8,
        leaf_idx: u64,
        dec: &DecryptedMemo,
        cm_be: [u8; 32],
    ) -> Result<bool, ClientError> {
        if (lane_id as usize) >= NUM_LANES {
            return Err(ClientError::InvalidEncoding("invalid lane_id"));
        }
        if self
            .notes
            .iter()
            .any(|n| n.lane_id == lane_id && n.leaf_index == leaf_idx)
        {
            return Ok(false);
        }
        let global_leaf = ((lane_id as u64) << 36) | leaf_idx;
        let stealth = fvk.stealth_owner(dec.tweak)?;
        let cm_fr = compute_note_commitment(
            stealth,
            derive_asset_id(&dec.mint),
            dec.amount,
            dec.blinding,
        );
        let nf = fvk.real_nullifier(cm_fr, global_leaf)?;
        self.notes.push(OwnedNote {
            pool_id: self.pool_id,
            lane_id,
            leaf_index: leaf_idx,
            global_leaf_index: global_leaf,
            mint: dec.mint,
            amount: dec.amount,
            tweak: fr_to_be_bytes(&dec.tweak),
            blinding: fr_to_be_bytes(&dec.blinding),
            stealth_owner: fr_to_be_bytes(&stealth),
            commitment: cm_be,
            nullifier: nf,
            is_dynamic: dec.is_dynamic,
            spent: false,
            frozen_intra_siblings: None,
            frozen_intra_positions: None,
        });
        Ok(true)
    }

    /// Freeze 12-sibling intra-subtree paths for every owned note in sealed `(lane_id, sub_seq)`.
    pub fn freeze_owned_notes_in_subtree_page(
        &mut self,
        lane_id: u8,
        sub_seq: u64,
        leaves: &[[u8; 32]],
    ) -> Result<(), ClientError> {
        if (lane_id as usize) >= NUM_LANES {
            return Err(ClientError::InvalidEncoding("invalid lane_id"));
        }
        if leaves.len() != SUBTREE_LEAVES {
            return Ok(());
        }
        let mut fr_leaves_opt: Option<Vec<Fr>> = None;
        for note in &mut self.notes {
            if note.lane_id == lane_id
                && note.leaf_index / SUBTREE_LEAVES as u64 == sub_seq
                && note.frozen_intra_siblings.is_none()
            {
                let fr_leaves = match fr_leaves_opt {
                    Some(ref v) => v,
                    None => {
                        let parsed: Vec<Fr> = leaves
                            .iter()
                            .map(|b| fr_from_be_bytes_strict(b).ok_or(ClientError::InvalidFieldElement))
                            .collect::<Result<_, _>>()?;
                        fr_leaves_opt = Some(parsed);
                        fr_leaves_opt.as_ref().unwrap()
                    }
                };
                let offset = (note.leaf_index % SUBTREE_LEAVES as u64) as usize;
                let (sibs, pos) =
                    extract_intra_subtree_siblings(fr_leaves, SUBTREE_LEAVES, offset);
                let mut sibs_be = [[[0u8; 32]; 3]; SUBTREE_LEVELS_4ARY];
                for h in 0..SUBTREE_LEVELS_4ARY {
                    for k in 0..3 {
                        sibs_be[h][k] = fr_to_be_bytes(&sibs[h][k]);
                    }
                }
                note.frozen_intra_siblings = Some(sibs_be);
                note.frozen_intra_positions = Some(pos);
            }
        }
        Ok(())
    }

    /// Ingest `SubtreeRootPage` accounts (`9,664 B`, 300 finalized subroots each) without
    /// downloading sealed `SubtreePage`s for subtrees with no owned notes.
    pub fn ingest_subroot_pages(
        &mut self,
        lane_id: u8,
        subroot_pages: &[(u64, &[u8])],
        finalized_count: Option<u64>,
    ) -> Result<(), ClientError> {
        let l = lane_id as usize;
        if l >= NUM_LANES {
            return Err(ClientError::InvalidEncoding("invalid lane_id"));
        }
        let max_roots = finalized_count.map(|v| v as usize).unwrap_or(usize::MAX);
        for &(root_page_seq, raw) in subroot_pages {
            if raw.len() != SUBROOT_PAGE_LEN || raw[0..8] != SUBROOT_MAGIC {
                return Err(ClientError::InvalidEncoding("invalid SubtreeRootPage"));
            }
            let cnt = read_u16(raw, SR_OFF_COUNT) as usize;
            let base_idx = (root_page_seq as usize) * SUBROOTS_PER_PAGE;
            for i in 0..cnt {
                let sub_idx = base_idx + i;
                if sub_idx >= max_roots {
                    break;
                }
                let root = read_32(raw, SR_OFF_ROOTS + i * 32);
                while self.lanes[l].finalized_subroots.len() < sub_idx {
                    self.lanes[l].finalized_subroots.push([0u8; 32]);
                }
                if self.lanes[l].finalized_subroots.len() == sub_idx {
                    self.lanes[l].finalized_subroots.push(root);
                } else {
                    self.lanes[l].finalized_subroots[sub_idx] = root;
                }
            }
        }
        Ok(())
    }

    /// Stream a single `NullifierPage` against our `O(owned_unspent_notes)` prefix index,
    /// marking matches `spent = true`, advancing `next_nf_index`, and discarding stranger prefixes.
    pub fn ingest_nullifier_page(
        &mut self,
        lane_id: u8,
        page_seq: u64,
        raw: &[u8],
        max_nf_index: Option<u64>,
    ) -> Result<usize, ClientError> {
        self.ingest_nullifier_pages(lane_id, &[(page_seq, raw)], max_nf_index)
    }

    /// Stream `NullifierPage`s in ascending sequence order against an `O(owned_unspent_notes)`
    /// prefix map across all lanes, discarding every stranger prefix immediately.
    pub fn ingest_nullifier_pages(
        &mut self,
        lane_id: u8,
        nf_pages: &[(u64, &[u8])],
        max_nf_index: Option<u64>,
    ) -> Result<usize, ClientError> {
        let l = lane_id as usize;
        if l >= NUM_LANES {
            return Err(ClientError::InvalidEncoding("invalid lane_id"));
        }
        if nf_pages.is_empty() {
            return Ok(0);
        }

        let mut unspent_by_prefix: HashMap<[u8; NF_PREFIX_LEN], Vec<usize>> = HashMap::new();
        for (idx, note) in self.notes.iter().enumerate() {
            if !note.spent {
                let pref: [u8; NF_PREFIX_LEN] = note.nullifier[0..NF_PREFIX_LEN].try_into().unwrap();
                unspent_by_prefix.entry(pref).or_default().push(idx);
            }
        }

        let mut sorted_nf_pages: Vec<(u64, &[u8])> = nf_pages.to_vec();
        sorted_nf_pages.sort_by_key(|&(seq, _)| seq);
        let mut newly_spent = 0usize;

        for (seq, raw) in sorted_nf_pages {
            if raw.len() != NF_PAGE_LEN || raw[0..8] != NF_PAGE_MAGIC {
                return Err(ClientError::InvalidEncoding("invalid NullifierPage"));
            }
            let count = read_u16(raw, NF_OFF_COUNT) as usize;
            let page_base = seq * NF_PER_PAGE as u64;
            let start_slot = self.lanes[l].next_nf_index.saturating_sub(page_base) as usize;
            let limit_slot = match max_nf_index {
                Some(cap) => count.min(cap.saturating_sub(page_base) as usize),
                None => count,
            };
            for slot in start_slot..limit_slot {
                if !unspent_by_prefix.is_empty() {
                    let off = NF_OFF_PREFIXES + slot * NF_PREFIX_LEN;
                    let pref: [u8; NF_PREFIX_LEN] = raw[off..off + NF_PREFIX_LEN].try_into().unwrap();
                    if let Some(indices) = unspent_by_prefix.remove(&pref) {
                        for ni in indices {
                            if !self.notes[ni].spent {
                                self.notes[ni].spent = true;
                                newly_spent += 1;
                            }
                        }
                    }
                }
                self.lanes[l].next_nf_index =
                    self.lanes[l].next_nf_index.max(page_base + slot as u64 + 1);
            }
        }
        Ok(newly_spent)
    }

    /// Prune retained `prev_sealed_leaves` on any lane whose checkpoint has crossed past it.
    pub fn prune_sealed_before_checkpoint(&mut self, ckpt: &RootCheckpoint) {
        for (l, lane) in self.lanes.iter_mut().enumerate().take(NUM_LANES) {
            let ckpt_frontier_page = ckpt.lane_counts[l] / SUBTREE_LEAVES as u64;
            if let Some(prev_seq) = lane.prev_sealed_sub_seq {
                if ckpt_frontier_page > prev_seq {
                    lane.prev_sealed_sub_seq = None;
                    lane.prev_sealed_leaves.clear();
                }
            }
        }
    }

    /// Ingest sequential `SubtreePage`, `MemoPage`, and `NullifierPage` bytes for one lane.
    ///
    /// - Verifies every decrypted memo strictly against its `SubtreePage` leaf commitment.
    /// - Freezes intra-subtree siblings for owned notes whenever a `SubtreePage` reaches 256 leaves,
    ///   retaining at most 1 just-sealed page (`prev_sealed_leaves`) until a newer checkpoint crosses it.
    /// - Streams `NullifierPage`s against owned unspent notes and discards stranger prefixes immediately.
    pub fn ingest_lane_pages(
        &mut self,
        fvk: &FullViewingKey,
        lane_id: u8,
        subtree_pages: &[(u64, &[u8])],
        memo_pages: &[(u64, &[u8])],
        nf_pages: &[(u64, &[u8])],
    ) -> Result<usize, ClientError> {
        let l = lane_id as usize;
        if l >= NUM_LANES {
            return Err(ClientError::InvalidEncoding("invalid lane_id"));
        }

        // 1. Collect newly provided SubtreePage leaves into a temporary page map for memo verification & freezing
        let mut page_leaves_map: BTreeMap<u64, Vec<[u8; 32]>> = BTreeMap::new();
        for &(seq, raw) in subtree_pages {
            if raw.len() != SUBTREE_PAGE_LEN || raw[0..8] != SUBTREE_MAGIC {
                return Err(ClientError::InvalidEncoding("invalid SubtreePage"));
            }
            let count = read_u16(raw, SB_OFF_COUNT) as usize;
            let mut leaves = Vec::with_capacity(count);
            for i in 0..count {
                leaves.push(read_32(raw, SB_OFF_LEAVES + i * 32));
            }
            page_leaves_map.insert(seq, leaves);
        }

        // 2. Scan MemoPages sequentially from `next_memo_leaf`, verifying every hit vs SubtreePage leaf
        let mut discovered = 0usize;
        let mut memo_map: BTreeMap<u64, &[u8]> = BTreeMap::new();
        for &(seq, raw) in memo_pages {
            if raw.len() != MEMO_PAGE_LEN || raw[0..8] != MEMO_MAGIC {
                return Err(ClientError::InvalidEncoding("invalid MemoPage"));
            }
            memo_map.insert(seq, raw);
        }

        loop {
            let leaf_idx = self.lanes[l].next_memo_leaf;
            let m_seq = leaf_idx / MEMO_NOTES_PER_PAGE as u64;
            let m_slot = (leaf_idx % MEMO_NOTES_PER_PAGE as u64) as usize;
            let Some(&m_raw) = memo_map.get(&m_seq) else {
                break;
            };
            let m_count = read_u16(m_raw, MM_OFF_COUNT) as usize;
            if m_slot >= m_count {
                break;
            }

            let s_seq = leaf_idx / SUBTREE_LEAVES as u64;
            let s_slot = (leaf_idx % SUBTREE_LEAVES as u64) as usize;
            let cm_be = if let Some(leaves) = page_leaves_map.get(&s_seq) {
                if s_slot >= leaves.len() {
                    break;
                }
                leaves[s_slot]
            } else if s_seq == self.lanes[l].frontier_sub_seq
                && s_slot < self.lanes[l].frontier_leaves.len()
            {
                self.lanes[l].frontier_leaves[s_slot]
            } else {
                break;
            };

            let vt = [
                m_raw[MM_OFF_VIEW_TAGS + m_slot * 2],
                m_raw[MM_OFF_VIEW_TAGS + m_slot * 2 + 1],
            ];
            let epk = read_32(m_raw, MM_OFF_EPHEMERAL_PKS + m_slot * 32);
            let ct_off = MM_OFF_CIPHERTEXTS + m_slot * MEMO_CT_LEN;
            let ct56: [u8; MEMO_CT_LEN] = m_raw[ct_off..ct_off + MEMO_CT_LEN].try_into().unwrap();

            if let Some(dec) = try_decrypt_and_verify_memo_entry(fvk, vt, &epk, &ct56, &cm_be) {
                if self.record_verified_memo(fvk, lane_id, leaf_idx, &dec, cm_be)? {
                    discovered += 1;
                }
            }
            self.lanes[l].next_memo_leaf += 1;
        }

        // 3. Advance finalized subroots & freeze intra-subtree siblings for owned notes in sealed pages.
        //    Hold a full 256-leaf page in `frontier_leaves` until `next_memo_leaf` finishes scanning all
        //    256 leaves (spanning 3 MemoPages) so lagged MemoPage batches never stall sync.
        if self.lanes[l].frontier_leaves.len() == SUBTREE_LEAVES
            && !page_leaves_map.contains_key(&self.lanes[l].frontier_sub_seq)
        {
            let held_seq = self.lanes[l].frontier_sub_seq;
            let held_leaves = self.lanes[l].frontier_leaves.clone();
            self.freeze_owned_notes_in_subtree_page(lane_id, held_seq, &held_leaves)?;
            let page_end_leaf = (held_seq + 1) * SUBTREE_LEAVES as u64;
            if self.lanes[l].next_memo_leaf >= page_end_leaf {
                self.lanes[l].prev_sealed_sub_seq = Some(held_seq);
                self.lanes[l].prev_sealed_leaves = held_leaves;
                self.lanes[l].frontier_sub_seq = held_seq + 1;
                self.lanes[l].frontier_leaves.clear();
            }
        }

        for (&seq, leaves) in &page_leaves_map {
            let memo_sub_seq = self.lanes[l].next_memo_leaf / SUBTREE_LEAVES as u64;
            if leaves.len() == SUBTREE_LEAVES {
                let fr_leaves: Vec<Fr> = leaves
                    .iter()
                    .map(|b| fr_from_be_bytes_strict(b).ok_or(ClientError::InvalidFieldElement))
                    .collect::<Result<_, _>>()?;
                let subroot = fr_to_be_bytes(&compute_subtree_256_root(&fr_leaves, SUBTREE_LEAVES));
                while self.lanes[l].finalized_subroots.len() < seq as usize {
                    self.lanes[l].finalized_subroots.push([0u8; 32]);
                }
                if self.lanes[l].finalized_subroots.len() == seq as usize {
                    self.lanes[l].finalized_subroots.push(subroot);
                } else {
                    self.lanes[l].finalized_subroots[seq as usize] = subroot;
                }

                self.freeze_owned_notes_in_subtree_page(lane_id, seq, leaves)?;

                let page_end_leaf = (seq + 1) * SUBTREE_LEAVES as u64;
                if self.lanes[l].next_memo_leaf >= page_end_leaf {
                    if seq >= self.lanes[l].frontier_sub_seq {
                        self.lanes[l].prev_sealed_sub_seq = Some(seq);
                        self.lanes[l].prev_sealed_leaves = leaves.clone();
                        self.lanes[l].frontier_sub_seq = seq + 1;
                        self.lanes[l].frontier_leaves.clear();
                    }
                } else if seq == memo_sub_seq {
                    self.lanes[l].frontier_sub_seq = seq;
                    self.lanes[l].frontier_leaves = leaves.clone();
                }
            } else if seq >= self.lanes[l].frontier_sub_seq && seq <= memo_sub_seq {
                self.lanes[l].frontier_sub_seq = seq;
                self.lanes[l].frontier_leaves = leaves.clone();
            }
        }

        // 4. Stream NullifierPages in ascending sequence order against owned unspent notes
        //    (discarding all stranger prefixes immediately).
        self.ingest_nullifier_pages(lane_id, nf_pages, None)?;

        Ok(discovered)
    }

    /// Build an exact 4-ary Depth-20 `MerklePath4Ary` witness for an owned note against `ckpt`
    /// 100% offline from `CompactWalletStore` with **ZERO targeted RPC calls**.
    pub fn build_witness_for_note(
        &self,
        note: &OwnedNote,
        ckpt: &RootCheckpoint,
    ) -> Result<(Fr, MerklePath4Ary), ClientError> {
        let l = note.lane_id as usize;
        if l >= NUM_LANES {
            return Err(ClientError::WitnessNotFound("invalid lane_id"));
        }
        let ckpt_count = ckpt.lane_counts[l];
        if note.leaf_index >= ckpt_count {
            return Err(ClientError::WitnessNotFound("note not yet included in checkpoint"));
        }

        let target_page = note.leaf_index / SUBTREE_LEAVES as u64;
        let target_offset = (note.leaf_index % SUBTREE_LEAVES as u64) as usize;
        let frontier_page = ckpt_count / SUBTREE_LEAVES as u64;
        let frontier_rem = (ckpt_count % SUBTREE_LEAVES as u64) as usize;

        let resolve_frontier_leaves = || -> Option<&[[u8; 32]]> {
            let lane = &self.lanes[l];
            if lane.frontier_sub_seq == frontier_page && lane.frontier_leaves.len() >= frontier_rem {
                return Some(&lane.frontier_leaves);
            }
            if lane.prev_sealed_sub_seq == Some(frontier_page)
                && lane.prev_sealed_leaves.len() >= frontier_rem
            {
                return Some(&lane.prev_sealed_leaves);
            }
            None
        };

        let (intra_sibs, intra_pos) = if target_page < frontier_page {
            let sibs_be = note
                .frozen_intra_siblings
                .ok_or(ClientError::WitnessNotFound("missing frozen intra-subtree siblings"))?;
            let pos = note
                .frozen_intra_positions
                .ok_or(ClientError::WitnessNotFound("missing frozen intra-subtree positions"))?;
            let mut sibs = [[Fr::from(0u64); 3]; SUBTREE_LEVELS_4ARY];
            for h in 0..SUBTREE_LEVELS_4ARY {
                for k in 0..3 {
                    sibs[h][k] = fr_from_be_bytes_strict(&sibs_be[h][k])
                        .ok_or(ClientError::InvalidFieldElement)?;
                }
            }
            (sibs, pos)
        } else {
            let f_leaves = resolve_frontier_leaves()
                .ok_or(ClientError::WitnessNotFound("missing frontier SubtreePage leaves"))?;
            let f_fr: Vec<Fr> = f_leaves[..frontier_rem]
                .iter()
                .map(|b| fr_from_be_bytes_strict(b).ok_or(ClientError::InvalidFieldElement))
                .collect::<Result<_, _>>()?;
            extract_intra_subtree_siblings(&f_fr, frontier_rem, target_offset)
        };

        let mut ckpt_roots_fr = [Fr::from(0u64); NUM_LANES];
        for (dst, src) in ckpt_roots_fr.iter_mut().zip(ckpt.lane_roots.iter()) {
            *dst = fr_from_be_bytes_strict(src).ok_or(ClientError::InvalidFieldElement)?;
        }

        if self.lanes[l].finalized_subroots.len() < frontier_page as usize {
            return Err(ClientError::WitnessNotFound("missing finalized subroots"));
        }
        let finalized_fr: Vec<Fr> = self.lanes[l].finalized_subroots[..frontier_page as usize]
            .iter()
            .map(|b| fr_from_be_bytes_strict(b).ok_or(ClientError::InvalidFieldElement))
            .collect::<Result<_, _>>()?;

        let frontier_fr: Option<Vec<Fr>> = if frontier_rem > 0 {
            let f_leaves = resolve_frontier_leaves()
                .ok_or(ClientError::WitnessNotFound("missing frontier SubtreePage leaves"))?;
            Some(
                f_leaves[..frontier_rem]
                    .iter()
                    .map(|b| fr_from_be_bytes_strict(b).ok_or(ClientError::InvalidFieldElement))
                    .collect::<Result<_, _>>()?,
            )
        } else {
            None
        };

        let path = build_witness_from_frozen_subsiblings(
            l,
            note.leaf_index,
            &intra_sibs,
            &intra_pos,
            &ckpt_roots_fr,
            ckpt_count,
            &finalized_fr,
            frontier_fr.as_deref(),
        );
        let super_root = fr_from_be_bytes_strict(&ckpt.super_root)
            .ok_or(ClientError::InvalidFieldElement)?;
        let cm = fr_from_be_bytes_strict(&note.commitment).ok_or(ClientError::InvalidFieldElement)?;
        if path.compute_root(cm) != super_root {
            return Err(ClientError::WitnessNotFound("reconstructed Merkle root mismatch"));
        }
        Ok((super_root, path))
    }

    /// Estimate active SubtreeRootPage count required for `lane_id` (`ceil(finalized / 300)`).
    pub fn subroot_pages_for_lane(&self, lane_id: u8) -> u64 {
        let n = self.lanes[lane_id as usize].finalized_subroots.len();
        (n.div_ceil(SUBROOTS_PER_PAGE).max(1)) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{encrypt_note_memo, AudrenKeys};
    use audren_circuits::note::derive_stealth_owner;
    use audren_core::NATIVE_SOL_MINT;

    fn make_memo_page(count: u16) -> Vec<u8> {
        let mut buf = vec![0u8; MEMO_PAGE_LEN];
        buf[0..8].copy_from_slice(&MEMO_MAGIC);
        buf[MM_OFF_COUNT..MM_OFF_COUNT + 2].copy_from_slice(&count.to_le_bytes());
        buf
    }

    fn write_memo_slot(buf: &mut [u8], slot: usize, memo_90: &[u8; 90]) {
        buf[MM_OFF_VIEW_TAGS + slot * 2..MM_OFF_VIEW_TAGS + (slot + 1) * 2]
            .copy_from_slice(&memo_90[0..2]);
        buf[MM_OFF_EPHEMERAL_PKS + slot * 32..MM_OFF_EPHEMERAL_PKS + (slot + 1) * 32]
            .copy_from_slice(&memo_90[2..34]);
        buf[MM_OFF_CIPHERTEXTS + slot * MEMO_CT_LEN..MM_OFF_CIPHERTEXTS + (slot + 1) * MEMO_CT_LEN]
            .copy_from_slice(&memo_90[34..90]);
    }

    #[test]
    fn sealed_subtree_holds_frontier_until_lagged_memos_arrive_and_sorts_nf_pages() {
        let alice = AudrenKeys::from_seed(&[0x55u8; 32]);
        let fvk = alice.full_viewing_key();
        let sol_asset = derive_asset_id(&NATIVE_SOL_MINT);

        let mut sub_raw = vec![0u8; SUBTREE_PAGE_LEN];
        sub_raw[0..8].copy_from_slice(&SUBTREE_MAGIC);
        sub_raw[SB_OFF_COUNT..SB_OFF_COUNT + 2]
            .copy_from_slice(&(SUBTREE_LEAVES as u16).to_le_bytes());

        let memo0 = make_memo_page(MEMO_NOTES_PER_PAGE as u16);
        let mut memo1 = make_memo_page(MEMO_NOTES_PER_PAGE as u16);
        let memo2 = make_memo_page((SUBTREE_LEAVES - 2 * MEMO_NOTES_PER_PAGE) as u16);

        for i in 0..SUBTREE_LEAVES {
            if i == 150 {
                let (tw, bl, memo_90) =
                    encrypt_note_memo(&alice.view_pk, [0x66u8; 32], 5_000_000, &NATIVE_SOL_MINT);
                let cm = compute_note_commitment(
                    derive_stealth_owner(alice.spend_pk, tw),
                    sol_asset,
                    5_000_000,
                    bl,
                );
                sub_raw[SB_OFF_LEAVES + i * 32..SB_OFF_LEAVES + (i + 1) * 32]
                    .copy_from_slice(&fr_to_be_bytes(&cm));
                write_memo_slot(&mut memo1, i - MEMO_NOTES_PER_PAGE, &memo_90);
            } else {
                let leaf = Fr::from((i + 1) as u64);
                sub_raw[SB_OFF_LEAVES + i * 32..SB_OFF_LEAVES + (i + 1) * 32]
                    .copy_from_slice(&fr_to_be_bytes(&leaf));
            }
        }

        let mut store = CompactWalletStore::new(0, 0);
        // Batch 1: sealed SubtreePage #0 + MemoPage #0 only (MemoPage #1 lags)
        let d1 = store
            .ingest_lane_pages(&fvk, 0, &[(0, &sub_raw)], &[(0, &memo0)], &[])
            .unwrap();
        assert_eq!(d1, 0);
        assert_eq!(store.lanes[0].next_memo_leaf, 112);
        assert_eq!(store.lanes[0].frontier_sub_seq, 0);
        assert_eq!(store.lanes[0].frontier_leaves.len(), SUBTREE_LEAVES);

        // Batch 2: MemoPage #1 arrives without re-passing SubtreePage #0
        let d2 = store
            .ingest_lane_pages(&fvk, 0, &[], &[(1, &memo1)], &[])
            .unwrap();
        assert_eq!(d2, 1);
        assert_eq!(store.lanes[0].next_memo_leaf, 224);
        assert_eq!(store.notes[0].amount, 5_000_000);
        assert!(store.notes[0].frozen_intra_siblings.is_some());

        // Batch 3: MemoPage #2 completes all 256 leaves -> frontier advances & clears
        let d3 = store
            .ingest_lane_pages(&fvk, 0, &[], &[(2, &memo2)], &[])
            .unwrap();
        assert_eq!(d3, 0);
        assert_eq!(store.lanes[0].next_memo_leaf, 256);
        assert_eq!(store.lanes[0].frontier_sub_seq, 1);
        assert!(store.lanes[0].frontier_leaves.is_empty());

        // Out-of-order NullifierPages (page 1 before page 0) must not skip page 0
        let mut nf0 = vec![0u8; NF_PAGE_LEN];
        nf0[0..8].copy_from_slice(&NF_PAGE_MAGIC);
        nf0[NF_OFF_COUNT..NF_OFF_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
        nf0[NF_OFF_PREFIXES..NF_OFF_PREFIXES + NF_PREFIX_LEN]
            .copy_from_slice(&store.notes[0].nullifier[0..NF_PREFIX_LEN]);

        let mut nf1 = vec![0u8; NF_PAGE_LEN];
        nf1[0..8].copy_from_slice(&NF_PAGE_MAGIC);
        nf1[NF_OFF_COUNT..NF_OFF_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
        nf1[NF_OFF_PREFIXES..NF_OFF_PREFIXES + NF_PREFIX_LEN].fill(0xee);

        store
            .ingest_lane_pages(&fvk, 0, &[], &[], &[(1, &nf1), (0, &nf0)])
            .unwrap();
        assert_eq!(store.unspent_notes(None).len(), 0);
        let json = String::from_utf8(store.to_json_bytes().unwrap()).unwrap();
        assert!(
            !json.contains("seen_nf_prefixes"),
            "to_json_bytes must never serialize stranger seen_nf_prefixes"
        );
    }

    #[test]
    fn post_seal_checkpoint_witness_uses_prev_sealed_leaves_and_prunes_on_newer_ckpt() {
        use audren_circuits::merkle::compute_super_root_4ary;
        use audren_circuits::poseidon::poseidon4;
        use audren_core::ZERO_HASHES_4ARY;

        let alice = AudrenKeys::from_seed(&[0x44u8; 32]);
        let fvk = alice.full_viewing_key();
        let sol_asset = derive_asset_id(&NATIVE_SOL_MINT);

        let mut sub_raw = vec![0u8; SUBTREE_PAGE_LEN];
        sub_raw[0..8].copy_from_slice(&SUBTREE_MAGIC);
        sub_raw[SB_OFF_COUNT..SB_OFF_COUNT + 2]
            .copy_from_slice(&(SUBTREE_LEAVES as u16).to_le_bytes());

        let memo0 = make_memo_page(MEMO_NOTES_PER_PAGE as u16);
        let mut memo1 = make_memo_page(MEMO_NOTES_PER_PAGE as u16);
        let memo2 = make_memo_page((SUBTREE_LEAVES - 2 * MEMO_NOTES_PER_PAGE) as u16);

        let mut leaves_fr = Vec::with_capacity(SUBTREE_LEAVES);
        for i in 0..SUBTREE_LEAVES {
            if i == 200 {
                let (tw, bl, memo_90) =
                    encrypt_note_memo(&alice.view_pk, [0x45u8; 32], 7_500_000, &NATIVE_SOL_MINT);
                let cm = compute_note_commitment(
                    derive_stealth_owner(alice.spend_pk, tw),
                    sol_asset,
                    7_500_000,
                    bl,
                );
                leaves_fr.push(cm);
                sub_raw[SB_OFF_LEAVES + i * 32..SB_OFF_LEAVES + (i + 1) * 32]
                    .copy_from_slice(&fr_to_be_bytes(&cm));
                write_memo_slot(&mut memo1, i - MEMO_NOTES_PER_PAGE, &memo_90);
            } else {
                let leaf = Fr::from((i + 10) as u64);
                leaves_fr.push(leaf);
                sub_raw[SB_OFF_LEAVES + i * 32..SB_OFF_LEAVES + (i + 1) * 32]
                    .copy_from_slice(&fr_to_be_bytes(&leaf));
            }
        }

        let mut store = CompactWalletStore::new(0, 0);
        store
            .ingest_lane_pages(
                &fvk,
                0,
                &[(0, &sub_raw)],
                &[(0, &memo0), (1, &memo1), (2, &memo2)],
                &[],
            )
            .unwrap();
        assert_eq!(store.lanes[0].frontier_sub_seq, 1);
        assert!(store.lanes[0].frontier_leaves.is_empty());
        assert_eq!(store.lanes[0].prev_sealed_sub_seq, Some(0));
        assert_eq!(store.lanes[0].prev_sealed_leaves.len(), SUBTREE_LEAVES);

        // Reload from JSON and verify witness against pre-seal checkpoint (count = 250)
        let mut reloaded = CompactWalletStore::from_json_bytes(&store.to_json_bytes().unwrap()).unwrap();
        let make_ckpt = |count: usize| {
            let mut lroot = compute_subtree_256_root(&leaves_fr[..count], count);
            for zero_be in ZERO_HASHES_4ARY.iter().take(18).skip(4) {
                let z = fr_from_be_bytes_strict(zero_be).unwrap();
                lroot = poseidon4(lroot, z, z, z);
            }
            let z18 = fr_from_be_bytes_strict(&ZERO_HASHES_4ARY[18]).unwrap();
            let mut lane_roots_fr = [z18; NUM_LANES];
            lane_roots_fr[0] = lroot;
            let super_root = compute_super_root_4ary(&lane_roots_fr);
            let mut lane_roots = [[0u8; 32]; NUM_LANES];
            for i in 0..NUM_LANES {
                lane_roots[i] = fr_to_be_bytes(&lane_roots_fr[i]);
            }
            let mut lane_counts = [0u64; NUM_LANES];
            lane_counts[0] = count as u64;
            (
                RootCheckpoint {
                    version: 2,
                    bump: 0,
                    slot_idx: 0,
                    pool_id: 0,
                    epoch_id: 1,
                    published_slot: 100,
                    super_root: fr_to_be_bytes(&super_root),
                    lane_roots,
                    lane_counts,
                },
                super_root,
            )
        };

        let (pre_ckpt, pre_super) = make_ckpt(250);
        let note = reloaded.notes[0].clone();
        let (sr250, path250) = reloaded.build_witness_for_note(&note, &pre_ckpt).unwrap();
        assert_eq!(sr250, pre_super);
        assert_eq!(path250.compute_root(leaves_fr[200]), pre_super);

        // Newer checkpoint crosses page 0 (count = 256) -> prunes prev_sealed_leaves
        let (post_ckpt, post_super) = make_ckpt(256);
        reloaded.prune_sealed_before_checkpoint(&post_ckpt);
        assert_eq!(reloaded.lanes[0].prev_sealed_sub_seq, None);
        assert!(reloaded.lanes[0].prev_sealed_leaves.is_empty());
        let (sr256, path256) = reloaded.build_witness_for_note(&note, &post_ckpt).unwrap();
        assert_eq!(sr256, post_super);
        assert_eq!(path256.compute_root(leaves_fr[200]), post_super);
    }

    #[test]
    fn from_json_bytes_migrates_legacy_seen_nf_prefixes_and_discards_strangers() {
        let alice = AudrenKeys::from_seed(&[0x33u8; 32]);
        let fvk = alice.full_viewing_key();
        let sol_asset = derive_asset_id(&NATIVE_SOL_MINT);

        let (tw, bl, memo_90) =
            encrypt_note_memo(&alice.view_pk, [0x34u8; 32], 1_000_000, &NATIVE_SOL_MINT);
        let cm = compute_note_commitment(derive_stealth_owner(alice.spend_pk, tw), sol_asset, 1_000_000, bl);
        let mut sub_raw = vec![0u8; SUBTREE_PAGE_LEN];
        sub_raw[0..8].copy_from_slice(&SUBTREE_MAGIC);
        sub_raw[SB_OFF_COUNT..SB_OFF_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
        sub_raw[SB_OFF_LEAVES..SB_OFF_LEAVES + 32].copy_from_slice(&fr_to_be_bytes(&cm));
        let mut memo0 = make_memo_page(1);
        write_memo_slot(&mut memo0, 0, &memo_90);

        let mut store = CompactWalletStore::new(0, 0);
        store
            .ingest_lane_pages(&fvk, 0, &[(0, &sub_raw)], &[(0, &memo0)], &[])
            .unwrap();
        assert_eq!(store.unspent_notes(None).len(), 1);
        let own_pref: [u8; NF_PREFIX_LEN] = store.notes[0].nullifier[0..NF_PREFIX_LEN].try_into().unwrap();

        let mut val: serde_json::Value =
            serde_json::from_slice(&store.to_json_bytes().unwrap()).unwrap();
        let stranger = [0xdeu8; NF_PREFIX_LEN];
        val["seen_nf_prefixes"] = serde_json::json!([stranger, own_pref]);
        let legacy_bytes = serde_json::to_vec(&val).unwrap();

        let migrated = CompactWalletStore::from_json_bytes(&legacy_bytes).unwrap();
        assert_eq!(migrated.unspent_notes(None).len(), 0);
        let re_json = String::from_utf8(migrated.to_json_bytes().unwrap()).unwrap();
        assert!(!re_json.contains("seen_nf_prefixes"));
    }
}
