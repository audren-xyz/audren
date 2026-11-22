//! Zero-indexer `CompactWalletStore` for ordinary Solana RPC (`getMultipleAccounts`) sync.
//!
//! Discards every sealed `SubtreePage` (`8,256 B`) and `MemoPage` (`10,144 B`) immediately after
//! scanning, retaining ONLY:
//! - Frozen 4-level (`12` siblings = `384 B`) intra-subtree siblings for each owned unspent note
//! - `32 B` finalized level-4 subroots per 256-leaf page (`1.28 MB` total at 10M pool notes = `980x` smaller!)
//! - Unsealed frontier `SubtreePage` tail leaves per active lane
//! - `16 B` spent nullifier prefixes for local spent-status resolution (`0` individual `NullifierPDA` lookups!)

use std::collections::{BTreeMap, HashSet};

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
        SB_OFF_COUNT, SB_OFF_LEAVES, SUBROOTS_PER_PAGE, SUBTREE_LEAVES, SUBTREE_MAGIC,
        SUBTREE_PAGE_LEN,
    },
    NUM_LANES,
};
use serde::{Deserialize, Serialize};

use crate::{
    keys::{try_decrypt_and_verify_memo_entry, FullViewingKey, SelectiveDisclosureProof},
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
    /// Set of observed 16-byte nullifier prefixes across all scanned `NullifierPage`s.
    pub seen_nf_prefixes: HashSet<[u8; NF_PREFIX_LEN]>,
}

impl CompactWalletStore {
    pub fn new(pool_id: u32, birthday_slot: u64) -> Self {
        Self {
            pool_id,
            birthday_slot,
            lanes: (0..NUM_LANES).map(|_| CompactLaneState::default()).collect(),
            notes: Vec::new(),
            seen_nf_prefixes: HashSet::new(),
        }
    }

    /// Serialize compact store to JSON bytes (mobile disk / browser IndexedDB).
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, ClientError> {
        serde_json::to_vec(self).map_err(|_| ClientError::InvalidEncoding("serialize store"))
    }

    /// Restore compact store from persisted JSON bytes.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ClientError> {
        serde_json::from_slice(bytes).map_err(|_| ClientError::InvalidEncoding("deserialize store"))
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

    /// Ingest sequential `SubtreePage`, `MemoPage`, and `NullifierPage` bytes for one lane.
    ///
    /// - Verifies every decrypted memo strictly against its `SubtreePage` leaf commitment.
    /// - Freezes intra-subtree siblings for owned notes whenever a `SubtreePage` reaches 256 leaves,
    ///   then discards the sealed page from RAM/disk permanently.
    /// - Marks owned notes spent whenever their 16-byte nullifier prefix appears in `NullifierPage`s.
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
                let global_leaf = ((lane_id as u64) << 36) | leaf_idx;
                let stealth = fvk.stealth_owner(dec.tweak)?;
                let cm_fr = compute_note_commitment(
                    stealth,
                    derive_asset_id(&dec.mint),
                    dec.amount,
                    dec.blinding,
                );
                let nf = fvk.real_nullifier(cm_fr, global_leaf)?;
                let nf_prefix: [u8; NF_PREFIX_LEN] = nf[0..NF_PREFIX_LEN].try_into().unwrap();
                let already_spent = self.seen_nf_prefixes.contains(&nf_prefix);

                if !self
                    .notes
                    .iter()
                    .any(|n| n.lane_id == lane_id && n.leaf_index == leaf_idx)
                {
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
                        spent: already_spent,
                        frozen_intra_siblings: None,
                        frozen_intra_positions: None,
                    });
                    discovered += 1;
                }
            }
            self.lanes[l].next_memo_leaf += 1;
        }

        // 3. Advance finalized subroots & freeze intra-subtree siblings for owned notes in sealed pages!
        for (&seq, leaves) in &page_leaves_map {
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

                // Freeze 12 siblings for every owned note residing in this newly-sealed 256-leaf page
                for note in &mut self.notes {
                    if note.lane_id == lane_id
                        && note.leaf_index / SUBTREE_LEAVES as u64 == seq
                        && note.frozen_intra_siblings.is_none()
                    {
                        let offset = (note.leaf_index % SUBTREE_LEAVES as u64) as usize;
                        let (sibs, pos) =
                            extract_intra_subtree_siblings(&fr_leaves, SUBTREE_LEAVES, offset);
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

                if seq >= self.lanes[l].frontier_sub_seq {
                    self.lanes[l].frontier_sub_seq = seq + 1;
                    self.lanes[l].frontier_leaves.clear();
                }
            } else if seq >= self.lanes[l].frontier_sub_seq {
                self.lanes[l].frontier_sub_seq = seq;
                self.lanes[l].frontier_leaves = leaves.clone();
            }
        }

        // 4. Scan NullifierPages sequentially and mark spent notes locally (0 individual NullifierPDA RPCs!)
        for &(seq, raw) in nf_pages {
            if raw.len() != NF_PAGE_LEN || raw[0..8] != NF_PAGE_MAGIC {
                return Err(ClientError::InvalidEncoding("invalid NullifierPage"));
            }
            let count = read_u16(raw, NF_OFF_COUNT) as usize;
            let page_base = seq * NF_PER_PAGE as u64;
            let start_slot = self.lanes[l].next_nf_index.saturating_sub(page_base) as usize;
            for slot in start_slot..count {
                let off = NF_OFF_PREFIXES + slot * NF_PREFIX_LEN;
                let pref: [u8; NF_PREFIX_LEN] = raw[off..off + NF_PREFIX_LEN].try_into().unwrap();
                self.seen_nf_prefixes.insert(pref);
                self.lanes[l].next_nf_index = self.lanes[l].next_nf_index.max(page_base + slot as u64 + 1);
            }
        }
        for note in &mut self.notes {
            if !note.spent {
                let pref: [u8; NF_PREFIX_LEN] = note.nullifier[0..NF_PREFIX_LEN].try_into().unwrap();
                if self.seen_nf_prefixes.contains(&pref) {
                    note.spent = true;
                }
            }
        }

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
            if self.lanes[l].frontier_sub_seq != frontier_page
                || self.lanes[l].frontier_leaves.len() < frontier_rem
            {
                return Err(ClientError::WitnessNotFound("missing frontier SubtreePage leaves"));
            }
            let f_fr: Vec<Fr> = self.lanes[l].frontier_leaves[..frontier_rem]
                .iter()
                .map(|b| fr_from_be_bytes_strict(b).ok_or(ClientError::InvalidFieldElement))
                .collect::<Result<_, _>>()?;
            extract_intra_subtree_siblings(&f_fr, frontier_rem, target_offset)
        };

        let mut ckpt_roots_fr = [Fr::from(0u64); NUM_LANES];
        for i in 0..NUM_LANES {
            ckpt_roots_fr[i] = fr_from_be_bytes_strict(&ckpt.lane_roots[i])
                .ok_or(ClientError::InvalidFieldElement)?;
        }

        if self.lanes[l].finalized_subroots.len() < frontier_page as usize {
            return Err(ClientError::WitnessNotFound("missing finalized subroots"));
        }
        let finalized_fr: Vec<Fr> = self.lanes[l].finalized_subroots[..frontier_page as usize]
            .iter()
            .map(|b| fr_from_be_bytes_strict(b).ok_or(ClientError::InvalidFieldElement))
            .collect::<Result<_, _>>()?;

        let frontier_fr: Option<Vec<Fr>> = if frontier_rem > 0 {
            if self.lanes[l].frontier_sub_seq != frontier_page
                || self.lanes[l].frontier_leaves.len() < frontier_rem
            {
                return Err(ClientError::WitnessNotFound("missing frontier SubtreePage leaves"));
            }
            Some(
                self.lanes[l].frontier_leaves[..frontier_rem]
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
