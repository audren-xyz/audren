//! Zero-indexer `CompactWalletStore` for ordinary Solana RPC (`getMultipleAccounts`) sync.
//!
//! Discards every sealed `SubtreePage` (`8,256 B`), `MemoPage` (`10,240 B`), and stranger
//! `NullifierPage` prefix immediately after scanning, retaining ONLY:
//! - Frozen 4-level (`12` siblings = `384 B`) intra-subtree siblings for each owned unspent note
//! - `32 B` finalized level-4 subroots per 256-leaf page (`1.28 MB` total at 10M pool notes = `980x` smaller!)
//! - Unsealed frontier `SubtreePage` tail leaves per active lane (plus at most 1 just-sealed page
//!   until a newer `GlobalRootHistory` stable snapshot crosses it)

use std::collections::{BTreeMap, HashMap, HashSet};

use ark_bn254::Fr;
use audren_circuits::{
    merkle::{
        build_witness_from_frozen_subsiblings, compute_subtree_256_root, compute_super_root_4ary,
        extract_intra_subtree_siblings, MerklePath4Ary, SUBTREE_LEVELS_4ARY,
    },
    note::{compute_note_commitment, derive_asset_id},
    poseidon::{fr_from_be_bytes_strict, fr_to_be_bytes},
};
use audren_core::{
    layout::{
        read_32, read_u16, read_u32, read_u64, GlobalRootHistory, RootSnapshotChoice,
        MAX_LEAVES_PER_LANE, MEMO_CT_LEN, MEMO_MAGIC, MEMO_NOTES_PER_PAGE, MEMO_PAGE_LEN,
        MEMO_PAYMENT_ID_LEN, MM_OFF_CIPHERTEXTS, MM_OFF_COUNT, MM_OFF_EPHEMERAL_PKS,
        MM_OFF_LANE_ID, MM_OFF_PAGE_SEQ, MM_OFF_POOL_ID, MM_OFF_VIEW_TAGS, NF_OFF_COUNT,
        NF_OFF_LANE_ID, NF_OFF_PAGE_SEQ, NF_OFF_POOL_ID, NF_OFF_PREFIXES, NF_PAGE_LEN,
        NF_PAGE_MAGIC, NF_PER_PAGE, NF_PREFIX_LEN, SB_OFF_COUNT, SB_OFF_LANE_ID, SB_OFF_LEAVES,
        SB_OFF_PAGE_SEQ, SB_OFF_POOL_ID, SR_OFF_COUNT, SR_OFF_LANE_ID, SR_OFF_POOL_ID,
        SR_OFF_ROOTS, SR_OFF_ROOT_PAGE_SEQ, SUBROOTS_PER_PAGE, SUBROOT_MAGIC, SUBROOT_PAGE_LEN,
        SUBTREE_LEAVES, SUBTREE_MAGIC, SUBTREE_PAGE_LEN,
    },
    NUM_LANES, ROOT_RING_EPOCH, ROOT_RING_SLOT,
};

const MAX_SUBROOTS_PER_LANE: u64 = MAX_LEAVES_PER_LANE / SUBTREE_LEAVES as u64;
use serde::{Deserialize, Deserializer, Serialize};

fn deserialize_u64_flex<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum FlexU64 {
        Num(u64),
        Str(String),
    }
    match FlexU64::deserialize(d)? {
        FlexU64::Num(n) => Ok(n),
        FlexU64::Str(s) => s.parse::<u64>().map_err(serde::de::Error::custom),
    }
}

fn deserialize_opt_u64_flex<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum FlexOptU64 {
        Num(u64),
        Str(String),
    }
    match Option::<FlexOptU64>::deserialize(d)? {
        None => Ok(None),
        Some(FlexOptU64::Num(n)) => Ok(Some(n)),
        Some(FlexOptU64::Str(s)) => s.parse::<u64>().map(Some).map_err(serde::de::Error::custom),
    }
}

fn parse_hex_exact<const N: usize>(s: &str) -> Result<[u8; N], String> {
    if s.len() != N * 2 || !s.is_ascii() {
        return Err(format!("expected {} hex chars", N * 2));
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; N];
    for i in 0..N {
        let hi = (bytes[i * 2] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hex digit".to_string())?;
        let lo = (bytes[i * 2 + 1] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hex digit".to_string())?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

fn deserialize_bytes_flex<'de, D: Deserializer<'de>, const N: usize>(
    d: D,
) -> Result<[u8; N], D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum FlexBytes {
        Arr(Vec<u8>),
        Hex(String),
    }
    match FlexBytes::deserialize(d)? {
        FlexBytes::Arr(v) => v
            .try_into()
            .map_err(|_| serde::de::Error::custom(format!("expected {N} bytes"))),
        FlexBytes::Hex(s) => parse_hex_exact::<N>(&s).map_err(serde::de::Error::custom),
    }
}

fn deserialize_vec_bytes_flex<'de, D: Deserializer<'de>, const N: usize>(
    d: D,
) -> Result<Vec<[u8; N]>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum FlexBytes {
        Arr(Vec<u8>),
        Hex(String),
    }
    let items = Vec::<FlexBytes>::deserialize(d)?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let arr = match item {
            FlexBytes::Arr(v) => v
                .try_into()
                .map_err(|_| serde::de::Error::custom(format!("expected {N} bytes")))?,
            FlexBytes::Hex(s) => parse_hex_exact::<N>(&s).map_err(serde::de::Error::custom)?,
        };
        out.push(arr);
    }
    Ok(out)
}

type FrozenIntraSiblings = [[[u8; 32]; 3]; SUBTREE_LEVELS_4ARY];

fn deserialize_opt_frozen_sibs_flex<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<FrozenIntraSiblings>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum FlexBytes {
        Arr(Vec<u8>),
        Hex(String),
    }
    let Some(levels) = Option::<Vec<Vec<FlexBytes>>>::deserialize(d)? else {
        return Ok(None);
    };
    if levels.len() != SUBTREE_LEVELS_4ARY {
        return Err(serde::de::Error::custom("invalid frozen_intra_siblings level count"));
    }
    let mut out = [[[0u8; 32]; 3]; SUBTREE_LEVELS_4ARY];
    for (h, lvl) in levels.into_iter().enumerate() {
        if lvl.len() != 3 {
            return Err(serde::de::Error::custom("invalid frozen_intra_siblings width"));
        }
        for (k, item) in lvl.into_iter().enumerate() {
            out[h][k] = match item {
                FlexBytes::Arr(v) => v
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 32 bytes"))?,
                FlexBytes::Hex(s) => parse_hex_exact::<32>(&s).map_err(serde::de::Error::custom)?,
            };
        }
    }
    Ok(Some(out))
}

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
    #[serde(alias = "poolId")]
    pub pool_id: u32,
    #[serde(alias = "laneId")]
    pub lane_id: u8,
    #[serde(alias = "leafIndex", deserialize_with = "deserialize_u64_flex")]
    pub leaf_index: u64,
    #[serde(alias = "globalLeafIndex", deserialize_with = "deserialize_u64_flex")]
    pub global_leaf_index: u64,
    #[serde(deserialize_with = "deserialize_bytes_flex")]
    pub mint: [u8; 32],
    #[serde(deserialize_with = "deserialize_u64_flex")]
    pub amount: u64,
    #[serde(deserialize_with = "deserialize_bytes_flex")]
    pub tweak: [u8; 32],
    #[serde(deserialize_with = "deserialize_bytes_flex")]
    pub blinding: [u8; 32],
    #[serde(alias = "stealthOwner", deserialize_with = "deserialize_bytes_flex")]
    pub stealth_owner: [u8; 32],
    #[serde(deserialize_with = "deserialize_bytes_flex")]
    pub commitment: [u8; 32],
    #[serde(deserialize_with = "deserialize_bytes_flex")]
    pub nullifier: [u8; 32],
    #[serde(
        default,
        alias = "paymentId",
        deserialize_with = "deserialize_bytes_flex"
    )]
    pub payment_id: [u8; MEMO_PAYMENT_ID_LEN],
    #[serde(alias = "isDynamic")]
    pub is_dynamic: bool,
    pub spent: bool,
    /// Frozen 4-level intra-subtree siblings (`12 x 32 B = 384 B`) populated once the note's
    /// 256-leaf `SubtreePage` seals (allowing the `8,256 B` page to be permanently discarded).
    #[serde(
        default,
        alias = "frozenIntraSiblings",
        deserialize_with = "deserialize_opt_frozen_sibs_flex"
    )]
    pub frozen_intra_siblings: Option<[[[u8; 32]; 3]; SUBTREE_LEVELS_4ARY]>,
    #[serde(default, alias = "frozenIntraPositions")]
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
    #[serde(
        alias = "finalizedSubroots",
        deserialize_with = "deserialize_vec_bytes_flex"
    )]
    pub finalized_subroots: Vec<[u8; 32]>,
    /// Unsealed frontier `SubtreePage` sequence (`== finalized_subroots.len()`).
    #[serde(alias = "frontierSubSeq", deserialize_with = "deserialize_u64_flex")]
    pub frontier_sub_seq: u64,
    /// Current leaves in the unsealed frontier `SubtreePage` (`< 256` entries).
    #[serde(
        alias = "frontierLeaves",
        deserialize_with = "deserialize_vec_bytes_flex"
    )]
    pub frontier_leaves: Vec<[u8; 32]>,
    /// Most recently sealed `SubtreePage` sequence retained until a newer `GlobalRootHistory` stable snapshot crosses it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "prevSealedSubSeq",
        deserialize_with = "deserialize_opt_u64_flex"
    )]
    pub prev_sealed_sub_seq: Option<u64>,
    /// Leaves of `prev_sealed_sub_seq` (at most 1 page = 8 KB per lane), pruned once crossed by the stable snapshot.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        alias = "prevSealedLeaves",
        deserialize_with = "deserialize_vec_bytes_flex"
    )]
    pub prev_sealed_leaves: Vec<[u8; 32]>,
    /// Next memo index (`lane_leaf_index`) to scan in this lane.
    #[serde(alias = "nextMemoLeaf", deserialize_with = "deserialize_u64_flex")]
    pub next_memo_leaf: u64,
    /// Next nullifier prefix index to scan in this lane.
    #[serde(alias = "nextNfIndex", deserialize_with = "deserialize_u64_flex")]
    pub next_nf_index: u64,
}

/// Persistent, indexer-free mobile & desktop wallet store (`1.28 MB` @ 10M notes, `0` targeted RPCs).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactWalletStore {
    #[serde(alias = "poolId")]
    pub pool_id: u32,
    #[serde(alias = "birthdaySlot", deserialize_with = "deserialize_u64_flex")]
    pub birthday_slot: u64,
    pub lanes: Vec<CompactLaneState>,
    pub notes: Vec<OwnedNote>,
}

#[derive(Deserialize)]
struct CompactWalletStoreWire {
    #[serde(alias = "poolId")]
    pool_id: u32,
    #[serde(alias = "birthdaySlot", deserialize_with = "deserialize_u64_flex")]
    birthday_slot: u64,
    lanes: Vec<CompactLaneState>,
    notes: Vec<OwnedNote>,
    #[serde(
        default,
        alias = "seenNfPrefixes",
        deserialize_with = "deserialize_vec_bytes_flex"
    )]
    seen_nf_prefixes: Vec<[u8; NF_PREFIX_LEN]>,
}

struct ValidatedNullifierPage<'a> {
    page_base: u64,
    start_slot: usize,
    limit_slot: usize,
    raw: &'a [u8],
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
        if wire.lanes.len() != NUM_LANES {
            return Err(ClientError::InvalidEncoding(
                "store lanes length must equal NUM_LANES",
            ));
        }
        for lane in &wire.lanes {
            if lane.frontier_leaves.len() > SUBTREE_LEAVES
                || lane.prev_sealed_leaves.len() > SUBTREE_LEAVES
            {
                return Err(ClientError::InvalidEncoding(
                    "store lane leaves exceed SUBTREE_LEAVES",
                ));
            }
            if (lane.finalized_subroots.len() as u64) > MAX_SUBROOTS_PER_LANE {
                return Err(ClientError::InvalidEncoding(
                    "store lane finalized_subroots exceeds MAX_SUBROOTS_PER_LANE",
                ));
            }
            if lane.frontier_sub_seq > MAX_SUBROOTS_PER_LANE {
                return Err(ClientError::InvalidEncoding(
                    "store lane frontier_sub_seq exceeds MAX_SUBROOTS_PER_LANE",
                ));
            }
            if let Some(prev) = lane.prev_sealed_sub_seq {
                if prev >= MAX_SUBROOTS_PER_LANE {
                    return Err(ClientError::InvalidEncoding(
                        "store lane prev_sealed_sub_seq out of range",
                    ));
                }
            }
            if lane.next_memo_leaf > MAX_LEAVES_PER_LANE {
                return Err(ClientError::InvalidEncoding(
                    "store lane next_memo_leaf exceeds MAX_LEAVES_PER_LANE",
                ));
            }
            for sr in &lane.finalized_subroots {
                if !audren_core::is_canonical_fr(sr) {
                    return Err(ClientError::InvalidFieldElement);
                }
            }
            for leaf in &lane.frontier_leaves {
                if !audren_core::is_canonical_fr(leaf) {
                    return Err(ClientError::InvalidFieldElement);
                }
            }
            for leaf in &lane.prev_sealed_leaves {
                if !audren_core::is_canonical_fr(leaf) {
                    return Err(ClientError::InvalidFieldElement);
                }
            }
        }
        let mut seen_notes: HashSet<(u8, u64)> = HashSet::with_capacity(wire.notes.len());
        for note in &wire.notes {
            if note.pool_id != wire.pool_id {
                return Err(ClientError::InvalidEncoding("store note pool_id mismatch"));
            }
            if (note.lane_id as usize) >= NUM_LANES {
                return Err(ClientError::InvalidEncoding("store note lane_id out of range"));
            }
            if note.leaf_index >= MAX_LEAVES_PER_LANE {
                return Err(ClientError::InvalidEncoding(
                    "store note leaf_index exceeds MAX_LEAVES_PER_LANE",
                ));
            }
            if !seen_notes.insert((note.lane_id, note.leaf_index)) {
                return Err(ClientError::InvalidEncoding(
                    "store contains duplicate (lane_id, leaf_index) note",
                ));
            }
            let expected_global = ((note.lane_id as u64) << 36) | note.leaf_index;
            if note.global_leaf_index != expected_global {
                return Err(ClientError::InvalidEncoding(
                    "store note global_leaf_index mismatch",
                ));
            }
            if !audren_core::is_canonical_fr(&note.tweak)
                || !audren_core::is_canonical_fr(&note.blinding)
                || !audren_core::is_canonical_fr(&note.stealth_owner)
                || !audren_core::is_canonical_fr(&note.commitment)
                || !audren_core::is_canonical_fr(&note.nullifier)
            {
                return Err(ClientError::InvalidFieldElement);
            }
            if note.frozen_intra_siblings.is_some() != note.frozen_intra_positions.is_some() {
                return Err(ClientError::InvalidEncoding(
                    "store note frozen_intra_siblings/positions mismatch",
                ));
            }
            if let Some(ref sibs) = note.frozen_intra_siblings {
                for lvl in sibs {
                    for entry in lvl {
                        if !audren_core::is_canonical_fr(entry) {
                            return Err(ClientError::InvalidFieldElement);
                        }
                    }
                }
            }
            if let Some(positions) = note.frozen_intra_positions {
                if positions.iter().any(|&p| p > 3) {
                    return Err(ClientError::InvalidEncoding(
                        "store note frozen_intra_positions out of range",
                    ));
                }
            }
        }
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
                let entry = out.entry(n.mint).or_insert(0u64);
                *entry = entry.saturating_add(n.amount);
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
        if leaf_idx >= MAX_LEAVES_PER_LANE {
            return Err(ClientError::InvalidEncoding(
                "leaf_idx exceeds MAX_LEAVES_PER_LANE",
            ));
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
        if fr_to_be_bytes(&cm_fr) != cm_be {
            return Err(ClientError::InvalidEncoding(
                "note commitment mismatch in record_verified_memo",
            ));
        }
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
            payment_id: dec.payment_id,
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
                let offset = (note.leaf_index % SUBTREE_LEAVES as u64) as usize;
                if leaves[offset] != note.commitment {
                    continue;
                }
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
    ///
    /// Validates every page in sorted sequence order and enforces strict contiguity (zero
    /// zero-filled gaps, zero sparse amplification DoS, zero partial mutation on error) BEFORE
    /// writing any subroots into `finalized_subroots`.
    pub fn ingest_subroot_pages(
        &mut self,
        lane_id: u8,
        subroot_pages: &[(u64, &[u8])],
        finalized_count: Option<u64>,
    ) -> Result<(), ClientError> {
        let l = lane_id as usize;
        if l >= NUM_LANES || l >= self.lanes.len() {
            return Err(ClientError::InvalidEncoding("invalid lane_id"));
        }
        let max_roots_u64 = finalized_count
            .unwrap_or(MAX_SUBROOTS_PER_LANE)
            .min(MAX_SUBROOTS_PER_LANE);

        let mut dedup_pages: BTreeMap<u64, (&[u8], usize)> = BTreeMap::new();
        for &(root_page_seq, raw) in subroot_pages {
            if raw.len() != SUBROOT_PAGE_LEN || raw[0..8] != SUBROOT_MAGIC {
                return Err(ClientError::InvalidEncoding("invalid SubtreeRootPage"));
            }
            if raw[SR_OFF_LANE_ID] as usize >= NUM_LANES {
                return Err(ClientError::InvalidEncoding(
                    "SubtreeRootPage lane_id out of range",
                ));
            }
            if read_u32(raw, SR_OFF_POOL_ID) != self.pool_id
                || raw[SR_OFF_LANE_ID] != lane_id
                || read_u64(raw, SR_OFF_ROOT_PAGE_SEQ) != root_page_seq
            {
                return Err(ClientError::InvalidEncoding(
                    "SubtreeRootPage header mismatch",
                ));
            }
            let cnt = read_u16(raw, SR_OFF_COUNT) as usize;
            if cnt > SUBROOTS_PER_PAGE {
                return Err(ClientError::InvalidEncoding(
                    "SubtreeRootPage count exceeds capacity",
                ));
            }
            let base_idx_u64 = root_page_seq
                .checked_mul(SUBROOTS_PER_PAGE as u64)
                .ok_or(ClientError::InvalidEncoding(
                    "SubtreeRootPage root_page_seq overflow",
                ))?;
            if base_idx_u64 > MAX_SUBROOTS_PER_LANE {
                return Err(ClientError::InvalidEncoding(
                    "SubtreeRootPage root_page_seq out of range",
                ));
            }
            let base_idx = usize::try_from(base_idx_u64).map_err(|_| {
                ClientError::InvalidEncoding("SubtreeRootPage root_page_seq overflow")
            })?;
            let existing_subroots = &self.lanes[l].finalized_subroots;
            for i in 0..cnt {
                let root = read_32(raw, SR_OFF_ROOTS + i * 32);
                fr_from_be_bytes_strict(&root).ok_or(ClientError::InvalidFieldElement)?;
                let sub_idx = base_idx.checked_add(i).ok_or(ClientError::InvalidEncoding(
                    "SubtreeRootPage index overflow",
                ))?;
                if sub_idx < existing_subroots.len() && existing_subroots[sub_idx] != root {
                    return Err(ClientError::InvalidEncoding(
                        "SubtreeRootPage subroot mismatch against persisted finalized_subroots",
                    ));
                }
            }
            match dedup_pages.get(&root_page_seq) {
                Some(&(existing_raw, existing_cnt)) => {
                    let overlap = existing_cnt.min(cnt);
                    for i in 0..overlap {
                        if read_32(existing_raw, SR_OFF_ROOTS + i * 32)
                            != read_32(raw, SR_OFF_ROOTS + i * 32)
                        {
                            return Err(ClientError::InvalidEncoding(
                                "conflicting duplicate SubtreeRootPage entries",
                            ));
                        }
                    }
                    if cnt > existing_cnt {
                        dedup_pages.insert(root_page_seq, (raw, cnt));
                    }
                }
                None => {
                    dedup_pages.insert(root_page_seq, (raw, cnt));
                }
            }
        }

        let mut running_len = self.lanes[l].finalized_subroots.len();
        let mut validated: Vec<(usize, Vec<[u8; 32]>)> = Vec::with_capacity(dedup_pages.len());

        for (root_page_seq, (raw, cnt)) in dedup_pages {
            let base_idx_u64 = root_page_seq
                .checked_mul(SUBROOTS_PER_PAGE as u64)
                .ok_or(ClientError::InvalidEncoding(
                    "SubtreeRootPage root_page_seq overflow",
                ))?;
            if base_idx_u64 > MAX_SUBROOTS_PER_LANE {
                return Err(ClientError::InvalidEncoding(
                    "SubtreeRootPage root_page_seq out of range",
                ));
            }
            let base_idx = usize::try_from(base_idx_u64).map_err(|_| {
                ClientError::InvalidEncoding("SubtreeRootPage root_page_seq overflow")
            })?;
            if base_idx > running_len {
                return Err(ClientError::InvalidEncoding(
                    "SubtreeRootPage sequence gap exceeds contiguous frontier",
                ));
            }
            let end_idx_u64 = base_idx_u64
                .checked_add(cnt as u64)
                .ok_or(ClientError::InvalidEncoding("SubtreeRootPage index overflow"))?
                .min(max_roots_u64);
            if end_idx_u64 <= base_idx_u64 {
                continue;
            }
            let end_idx = usize::try_from(end_idx_u64).map_err(|_| {
                ClientError::InvalidEncoding("SubtreeRootPage index overflow")
            })?;
            let write_cnt = (end_idx_u64 - base_idx_u64) as usize;
            let mut roots = Vec::with_capacity(write_cnt);
            for i in 0..write_cnt {
                let root = read_32(raw, SR_OFF_ROOTS + i * 32);
                fr_from_be_bytes_strict(&root).ok_or(ClientError::InvalidFieldElement)?;
                roots.push(root);
            }
            running_len = running_len.max(end_idx);
            validated.push((base_idx, roots));
        }

        for (base_idx, roots) in validated {
            for (i, root) in roots.into_iter().enumerate() {
                let sub_idx = base_idx + i;
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

    fn validate_nullifier_pages<'a>(
        &self,
        lane_id: u8,
        nf_pages: &[(u64, &'a [u8])],
        max_nf_index: Option<u64>,
    ) -> Result<Vec<ValidatedNullifierPage<'a>>, ClientError> {
        let l = lane_id as usize;
        if l >= NUM_LANES {
            return Err(ClientError::InvalidEncoding("invalid lane_id"));
        }
        if nf_pages.is_empty() {
            return Ok(Vec::new());
        }

        let mut sorted_nf_pages: Vec<(u64, &'a [u8])> = nf_pages.to_vec();
        sorted_nf_pages.sort_by_key(|&(seq, _)| seq);

        let mut running_nf_index = self.lanes[l].next_nf_index;
        let mut validated: Vec<ValidatedNullifierPage<'a>> =
            Vec::with_capacity(sorted_nf_pages.len());

        for (seq, raw) in sorted_nf_pages {
            if raw.len() != NF_PAGE_LEN || raw[0..8] != NF_PAGE_MAGIC {
                return Err(ClientError::InvalidEncoding("invalid NullifierPage"));
            }
            if raw[NF_OFF_LANE_ID] as usize >= NUM_LANES {
                return Err(ClientError::InvalidEncoding(
                    "NullifierPage lane_id out of range",
                ));
            }
            if read_u32(raw, NF_OFF_POOL_ID) != self.pool_id
                || raw[NF_OFF_LANE_ID] != lane_id
                || read_u64(raw, NF_OFF_PAGE_SEQ) != seq
            {
                return Err(ClientError::InvalidEncoding(
                    "NullifierPage header mismatch",
                ));
            }
            let count = read_u16(raw, NF_OFF_COUNT) as usize;
            if count > NF_PER_PAGE {
                return Err(ClientError::InvalidEncoding(
                    "NullifierPage count exceeds capacity",
                ));
            }
            let page_base = seq
                .checked_mul(NF_PER_PAGE as u64)
                .ok_or(ClientError::InvalidEncoding("NullifierPage page_seq overflow"))?;
            page_base
                .checked_add(count as u64)
                .ok_or(ClientError::InvalidEncoding("NullifierPage index overflow"))?;
            if page_base > running_nf_index {
                return Err(ClientError::InvalidEncoding("NullifierPage sequence gap"));
            }
            let start_slot = running_nf_index
                .saturating_sub(page_base)
                .min(NF_PER_PAGE as u64) as usize;
            let limit_slot = match max_nf_index {
                Some(cap) => {
                    count.min(cap.saturating_sub(page_base).min(NF_PER_PAGE as u64) as usize)
                }
                None => count,
            };
            if limit_slot > start_slot {
                let end_idx = page_base
                    .checked_add(limit_slot as u64)
                    .ok_or(ClientError::InvalidEncoding("NullifierPage index overflow"))?;
                running_nf_index = running_nf_index.max(end_idx);
            }
            validated.push(ValidatedNullifierPage {
                page_base,
                start_slot,
                limit_slot,
                raw,
            });
        }
        Ok(validated)
    }

    fn apply_validated_nullifier_pages(
        &mut self,
        lane_id: u8,
        validated: Vec<ValidatedNullifierPage<'_>>,
    ) -> usize {
        if validated.is_empty() {
            return 0;
        }
        let l = lane_id as usize;
        let mut unspent_by_prefix: HashMap<[u8; NF_PREFIX_LEN], Vec<usize>> = HashMap::new();
        for (idx, note) in self.notes.iter().enumerate() {
            if !note.spent {
                let pref: [u8; NF_PREFIX_LEN] = note.nullifier[0..NF_PREFIX_LEN].try_into().unwrap();
                unspent_by_prefix.entry(pref).or_default().push(idx);
            }
        }

        let mut newly_spent = 0usize;
        for ValidatedNullifierPage {
            page_base,
            start_slot,
            limit_slot,
            raw,
        } in validated
        {
            for slot in start_slot..limit_slot {
                if !unspent_by_prefix.is_empty() {
                    let off = NF_OFF_PREFIXES + slot * NF_PREFIX_LEN;
                    let pref: [u8; NF_PREFIX_LEN] =
                        raw[off..off + NF_PREFIX_LEN].try_into().unwrap();
                    if let Some(indices) = unspent_by_prefix.remove(&pref) {
                        for ni in indices {
                            if !self.notes[ni].spent {
                                self.notes[ni].spent = true;
                                newly_spent += 1;
                            }
                        }
                    }
                }
                let next_idx = page_base + slot as u64 + 1;
                self.lanes[l].next_nf_index = self.lanes[l].next_nf_index.max(next_idx);
            }
        }
        newly_spent
    }

    /// Stream `NullifierPage`s in ascending sequence order against an `O(owned_unspent_notes)`
    /// prefix map across all lanes, discarding every stranger prefix immediately.
    ///
    /// Pre-validates every page header, bounds, and strict contiguity (`page_base <= running_nf_index`)
    /// BEFORE mutating any note or advancing `next_nf_index` so a gapped or lagging batch can never
    /// silently skip uninspected nullifier slots or leave partially mutated state on error.
    pub fn ingest_nullifier_pages(
        &mut self,
        lane_id: u8,
        nf_pages: &[(u64, &[u8])],
        max_nf_index: Option<u64>,
    ) -> Result<usize, ClientError> {
        let validated = self.validate_nullifier_pages(lane_id, nf_pages, max_nf_index)?;
        Ok(self.apply_validated_nullifier_pages(lane_id, validated))
    }

    /// Prune retained `prev_sealed_leaves` on any lane whose `ROOT_RING_EPOCH` (`stable`)
    /// `RootSnapshotChoice` has crossed past it.
    /// No-op if `snapshot` is not `ROOT_RING_EPOCH` (so a `ROOT_RING_SLOT` snapshot can never wipe
    /// `prev_sealed_leaves` needed for offline `stable` witness builds) or fails validation.
    pub fn prune_sealed_before_snapshot(&mut self, snapshot: &RootSnapshotChoice) {
        if snapshot.ring_kind != ROOT_RING_EPOCH
            || crate::scanner::validate_root_snapshot_choice(snapshot).is_err()
        {
            return;
        }
        for (l, lane) in self.lanes.iter_mut().enumerate().take(NUM_LANES) {
            let snap_frontier_page = snapshot.lane_counts[l] / SUBTREE_LEAVES as u64;
            if let Some(prev_seq) = lane.prev_sealed_sub_seq {
                if snap_frontier_page > prev_seq {
                    lane.prev_sealed_sub_seq = None;
                    lane.prev_sealed_leaves.clear();
                }
            }
        }
    }

    /// Prune retained `prev_sealed_leaves` on any lane whose `GlobalRootHistory` `stable` snapshot
    /// (and therefore also `latest`) has crossed past it.
    /// No-op if `history` fails `pool_id`, ring, or cryptographic validation.
    pub fn prune_sealed_before_root_history(&mut self, history: &GlobalRootHistory) {
        if crate::scanner::validate_global_root_history(history, self.pool_id).is_err() {
            return;
        }
        for (l, lane) in self.lanes.iter_mut().enumerate().take(NUM_LANES) {
            let stable_frontier_page = history.stable_lane_counts[l] / SUBTREE_LEAVES as u64;
            if let Some(prev_seq) = lane.prev_sealed_sub_seq {
                if stable_frontier_page > prev_seq {
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
    ///   retaining at most 1 just-sealed page (`prev_sealed_leaves`) until a newer root snapshot crosses it.
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

        // 1. Pre-validate ALL SubtreePages (headers, counts, canonical BN254 Fr on BOTH sealed
        //    AND unsealed leaves, and contiguous sealed page_seq), ALL MemoPages, and ALL
        //    NullifierPages BEFORE mutating ANY store state (100% atomic on validation error).
        let mut page_leaves_map: BTreeMap<u64, (Vec<[u8; 32]>, Vec<Fr>)> = BTreeMap::new();
        for &(seq, raw) in subtree_pages {
            if raw.len() != SUBTREE_PAGE_LEN || raw[0..8] != SUBTREE_MAGIC {
                return Err(ClientError::InvalidEncoding("invalid SubtreePage"));
            }
            if read_u32(raw, SB_OFF_POOL_ID) != self.pool_id
                || raw[SB_OFF_LANE_ID] != lane_id
                || read_u64(raw, SB_OFF_PAGE_SEQ) != seq
            {
                return Err(ClientError::InvalidEncoding("SubtreePage header mismatch"));
            }
            let count = read_u16(raw, SB_OFF_COUNT) as usize;
            if count > SUBTREE_LEAVES {
                return Err(ClientError::InvalidEncoding(
                    "SubtreePage count exceeds capacity",
                ));
            }
            let mut leaves = Vec::with_capacity(count);
            let mut fr_leaves = Vec::with_capacity(count);
            for i in 0..count {
                let leaf_be = read_32(raw, SB_OFF_LEAVES + i * 32);
                let leaf_fr =
                    fr_from_be_bytes_strict(&leaf_be).ok_or(ClientError::InvalidFieldElement)?;
                leaves.push(leaf_be);
                fr_leaves.push(leaf_fr);
            }
            // Enforce append-only prefix immutability against persisted frontier & prev_sealed leaves
            let old_frontier = &self.lanes[l].frontier_leaves;
            if !old_frontier.is_empty() && seq == self.lanes[l].frontier_sub_seq {
                let prefix_len = leaves.len().min(old_frontier.len());
                if leaves[..prefix_len] != old_frontier[..prefix_len] {
                    return Err(ClientError::InvalidEncoding(
                        "SubtreePage frontier prefix mismatch against persisted frontier_leaves",
                    ));
                }
            }
            let old_prev = &self.lanes[l].prev_sealed_leaves;
            if !old_prev.is_empty() && self.lanes[l].prev_sealed_sub_seq == Some(seq) {
                let prefix_len = leaves.len().min(old_prev.len());
                if leaves[..prefix_len] != old_prev[..prefix_len] {
                    return Err(ClientError::InvalidEncoding(
                        "SubtreePage prefix mismatch against persisted prev_sealed_leaves",
                    ));
                }
            }
            // Enforce immutability against already-persisted `finalized_subroots[seq]`
            if leaves.len() == SUBTREE_LEAVES {
                if let Ok(seq_idx) = usize::try_from(seq) {
                    if seq_idx < self.lanes[l].finalized_subroots.len() {
                        let subroot =
                            fr_to_be_bytes(&compute_subtree_256_root(&fr_leaves, SUBTREE_LEAVES));
                        if subroot != self.lanes[l].finalized_subroots[seq_idx] {
                            return Err(ClientError::InvalidEncoding(
                                "SubtreePage subroot mismatch against persisted finalized_subroots",
                            ));
                        }
                    }
                }
            }
            match page_leaves_map.get(&seq) {
                Some((existing, _)) => {
                    let overlap = existing.len().min(leaves.len());
                    if existing[..overlap] != leaves[..overlap] {
                        return Err(ClientError::InvalidEncoding(
                            "conflicting duplicate SubtreePage entries",
                        ));
                    }
                    if leaves.len() > existing.len() {
                        page_leaves_map.insert(seq, (leaves, fr_leaves));
                    }
                }
                None => {
                    page_leaves_map.insert(seq, (leaves, fr_leaves));
                }
            }
        }

        let mut memo_map: BTreeMap<u64, &[u8]> = BTreeMap::new();
        for &(seq, raw) in memo_pages {
            if raw.len() != MEMO_PAGE_LEN || raw[0..8] != MEMO_MAGIC {
                return Err(ClientError::InvalidEncoding("invalid MemoPage"));
            }
            if read_u32(raw, MM_OFF_POOL_ID) != self.pool_id
                || raw[MM_OFF_LANE_ID] != lane_id
                || read_u64(raw, MM_OFF_PAGE_SEQ) != seq
            {
                return Err(ClientError::InvalidEncoding("MemoPage header mismatch"));
            }
            let m_count = read_u16(raw, MM_OFF_COUNT) as usize;
            if m_count > MEMO_NOTES_PER_PAGE {
                return Err(ClientError::InvalidEncoding(
                    "MemoPage count exceeds capacity",
                ));
            }
            match memo_map.get(&seq) {
                Some(&existing) if read_u16(existing, MM_OFF_COUNT) as usize >= m_count => {}
                _ => {
                    memo_map.insert(seq, raw);
                }
            }
        }

        // Pre-validate all sealed SubtreePages for contiguity & compute subroots up front, AND
        // reject any truncated (`< 256`-leaf) SubtreePage covering an already-finalized
        // `seq < finalized_subroots.len()` unless the store already holds a full verified 256-leaf
        // copy of `seq` (which was prefix-checked above).
        let mut running_subroot_len = self.lanes[l].finalized_subroots.len();
        let mut validated_sealed_subroots: BTreeMap<u64, [u8; 32]> = BTreeMap::new();
        for (&seq, (leaves, fr_leaves)) in &page_leaves_map {
            if leaves.len() < SUBTREE_LEAVES {
                if let Ok(seq_idx) = usize::try_from(seq) {
                    if seq_idx < self.lanes[l].finalized_subroots.len() {
                        let has_full_held_copy = (seq == self.lanes[l].frontier_sub_seq
                            && self.lanes[l].frontier_leaves.len() == SUBTREE_LEAVES)
                            || (self.lanes[l].prev_sealed_sub_seq == Some(seq)
                                && self.lanes[l].prev_sealed_leaves.len() == SUBTREE_LEAVES);
                        if !has_full_held_copy {
                            return Err(ClientError::InvalidEncoding(
                                "truncated SubtreePage cannot be verified against persisted finalized_subroots",
                            ));
                        }
                    }
                }
            }
            if leaves.len() == SUBTREE_LEAVES {
                if seq >= MAX_SUBROOTS_PER_LANE {
                    return Err(ClientError::InvalidEncoding(
                        "SubtreePage page_seq out of range",
                    ));
                }
                let seq_idx = usize::try_from(seq)
                    .map_err(|_| ClientError::InvalidEncoding("SubtreePage page_seq overflow"))?;
                if seq_idx > running_subroot_len {
                    return Err(ClientError::InvalidEncoding(
                        "SubtreePage sequence gap exceeds contiguous frontier",
                    ));
                }
                let next_seq = seq
                    .checked_add(1)
                    .ok_or(ClientError::InvalidEncoding("SubtreePage page_seq overflow"))?;
                next_seq
                    .checked_mul(SUBTREE_LEAVES as u64)
                    .ok_or(ClientError::InvalidEncoding("SubtreePage page_seq overflow"))?;
                let subroot = fr_to_be_bytes(&compute_subtree_256_root(fr_leaves, SUBTREE_LEAVES));
                running_subroot_len = running_subroot_len.max(seq_idx + 1);
                validated_sealed_subroots.insert(seq, subroot);
            }
        }

        // Pre-validate held sealed frontier leaves & bounds before mutating anything
        let held_sealed = self.lanes[l].frontier_leaves.len() == SUBTREE_LEAVES
            && page_leaves_map
                .get(&self.lanes[l].frontier_sub_seq)
                .is_none_or(|(leaves, _)| leaves.len() < SUBTREE_LEAVES);
        if held_sealed {
            let held_seq = self.lanes[l].frontier_sub_seq;
            let next_frontier_seq = held_seq
                .checked_add(1)
                .ok_or(ClientError::InvalidEncoding("frontier_sub_seq overflow"))?;
            next_frontier_seq
                .checked_mul(SUBTREE_LEAVES as u64)
                .ok_or(ClientError::InvalidEncoding("frontier_sub_seq overflow"))?;
            for b in &self.lanes[l].frontier_leaves {
                fr_from_be_bytes_strict(b).ok_or(ClientError::InvalidFieldElement)?;
            }
        }

        // Pre-validate ALL NullifierPages (headers, counts, contiguity) BEFORE any mutation
        let validated_nf_pages = self.validate_nullifier_pages(lane_id, nf_pages, None)?;

        // Pre-validate FVK field elements when memos will be scanned
        if !memo_map.is_empty() {
            fvk.spend_pk_fr()?;
            fvk.nk_fr()?;
        }

        // 2. Scan MemoPages sequentially from `next_memo_leaf`, verifying every hit vs SubtreePage leaf
        let mut discovered = 0usize;
        loop {
            let leaf_idx = self.lanes[l].next_memo_leaf;
            if leaf_idx >= MAX_LEAVES_PER_LANE {
                break;
            }
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
            let supplied = page_leaves_map.get(&s_seq).map(|(v, _)| v.as_slice());
            let best_leaves = if s_seq == self.lanes[l].frontier_sub_seq {
                let held = self.lanes[l].frontier_leaves.as_slice();
                match supplied {
                    Some(leaves) if leaves.len() > held.len() => Some(leaves),
                    _ => Some(held),
                }
            } else {
                supplied
            };
            let cm_be = match best_leaves {
                Some(leaves) if s_slot < leaves.len() => leaves[s_slot],
                _ => break,
            };

            let vt = [
                m_raw[MM_OFF_VIEW_TAGS + m_slot * 2],
                m_raw[MM_OFF_VIEW_TAGS + m_slot * 2 + 1],
            ];
            let epk = read_32(m_raw, MM_OFF_EPHEMERAL_PKS + m_slot * 32);
            let ct_off = MM_OFF_CIPHERTEXTS + m_slot * MEMO_CT_LEN;
            let ct72: [u8; MEMO_CT_LEN] = m_raw[ct_off..ct_off + MEMO_CT_LEN].try_into().unwrap();

            if let Some(dec) = try_decrypt_and_verify_memo_entry(fvk, vt, &epk, &ct72, &cm_be) {
                if self.record_verified_memo(fvk, lane_id, leaf_idx, &dec, cm_be)? {
                    discovered += 1;
                }
            }
            self.lanes[l].next_memo_leaf = leaf_idx
                .checked_add(1)
                .ok_or(ClientError::InvalidEncoding("next_memo_leaf overflow"))?;
        }

        // 3. Advance finalized subroots & freeze intra-subtree siblings for owned notes in sealed pages.
        //    Hold a full 256-leaf page in `frontier_leaves` until `next_memo_leaf` finishes scanning all
        //    256 leaves (spanning 3 MemoPages) so lagged MemoPage batches never stall sync.
        if held_sealed {
            let held_seq = self.lanes[l].frontier_sub_seq;
            let held_leaves = self.lanes[l].frontier_leaves.clone();
            self.freeze_owned_notes_in_subtree_page(lane_id, held_seq, &held_leaves)?;
            let next_frontier_seq = held_seq + 1;
            let page_end_leaf = next_frontier_seq * SUBTREE_LEAVES as u64;
            if self.lanes[l].next_memo_leaf >= page_end_leaf {
                self.lanes[l].prev_sealed_sub_seq = Some(held_seq);
                self.lanes[l].prev_sealed_leaves = held_leaves;
                self.lanes[l].frontier_sub_seq = next_frontier_seq;
                self.lanes[l].frontier_leaves.clear();
            }
        }

        for (&seq, (leaves, _)) in &page_leaves_map {
            let memo_sub_seq = self.lanes[l].next_memo_leaf / SUBTREE_LEAVES as u64;
            if leaves.len() == SUBTREE_LEAVES {
                let seq_idx = usize::try_from(seq)
                    .map_err(|_| ClientError::InvalidEncoding("SubtreePage page_seq overflow"))?;
                let subroot = validated_sealed_subroots[&seq];
                if self.lanes[l].finalized_subroots.len() == seq_idx {
                    self.lanes[l].finalized_subroots.push(subroot);
                } else {
                    self.lanes[l].finalized_subroots[seq_idx] = subroot;
                }

                self.freeze_owned_notes_in_subtree_page(lane_id, seq, leaves)?;

                let next_seq = seq + 1;
                let page_end_leaf = next_seq * SUBTREE_LEAVES as u64;
                if self.lanes[l].next_memo_leaf >= page_end_leaf {
                    if seq >= self.lanes[l].frontier_sub_seq {
                        self.lanes[l].prev_sealed_sub_seq = Some(seq);
                        self.lanes[l].prev_sealed_leaves = leaves.clone();
                        self.lanes[l].frontier_sub_seq = next_seq;
                        self.lanes[l].frontier_leaves.clear();
                    }
                } else if seq == memo_sub_seq
                    && seq >= self.lanes[l].frontier_sub_seq
                    && (seq > self.lanes[l].frontier_sub_seq
                        || leaves.len() > self.lanes[l].frontier_leaves.len())
                {
                    self.lanes[l].frontier_sub_seq = seq;
                    self.lanes[l].frontier_leaves = leaves.clone();
                }
            } else if seq >= self.lanes[l].finalized_subroots.len() as u64
                && seq >= self.lanes[l].frontier_sub_seq
                && seq <= memo_sub_seq
                && (seq > self.lanes[l].frontier_sub_seq
                    || leaves.len() > self.lanes[l].frontier_leaves.len())
            {
                self.lanes[l].frontier_sub_seq = seq;
                self.lanes[l].frontier_leaves = leaves.clone();
            }
        }

        // 4. Commit already-validated NullifierPages against owned unspent notes
        //    (discarding all stranger prefixes immediately).
        self.apply_validated_nullifier_pages(lane_id, validated_nf_pages);

        Ok(discovered)
    }

    /// Build an exact 4-ary Depth-20 `MerklePath4Ary` witness for an owned note against `snapshot`
    /// 100% offline from `CompactWalletStore` with **ZERO targeted RPC calls**.
    pub fn build_witness_for_note(
        &self,
        note: &OwnedNote,
        snapshot: &RootSnapshotChoice,
    ) -> Result<(Fr, MerklePath4Ary), ClientError> {
        if note.pool_id != self.pool_id {
            return Err(ClientError::InvalidEncoding("note pool_id mismatch"));
        }
        crate::scanner::validate_root_snapshot_choice(snapshot)?;
        let l = note.lane_id as usize;
        if l >= NUM_LANES {
            return Err(ClientError::WitnessNotFound("invalid lane_id"));
        }
        let snap_count = snapshot.lane_counts[l];
        if note.leaf_index >= snap_count {
            return Err(ClientError::WitnessNotFound(
                "note not yet included in root snapshot",
            ));
        }

        let target_page = note.leaf_index / SUBTREE_LEAVES as u64;
        let target_offset = (note.leaf_index % SUBTREE_LEAVES as u64) as usize;
        let frontier_page = snap_count / SUBTREE_LEAVES as u64;
        let frontier_rem = (snap_count % SUBTREE_LEAVES as u64) as usize;

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
            if pos.iter().any(|&p| p > 3) {
                return Err(ClientError::InvalidEncoding(
                    "frozen_intra_positions out of range",
                ));
            }
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

        let mut snap_roots_fr = [Fr::from(0u64); NUM_LANES];
        for (dst, src) in snap_roots_fr.iter_mut().zip(snapshot.lane_roots.iter()) {
            *dst = fr_from_be_bytes_strict(src).ok_or(ClientError::InvalidFieldElement)?;
        }
        let super_root = fr_from_be_bytes_strict(&snapshot.super_root)
            .ok_or(ClientError::InvalidFieldElement)?;
        if compute_super_root_4ary(&snap_roots_fr) != super_root {
            return Err(ClientError::WitnessNotFound("reconstructed Merkle root mismatch"));
        }

        let frontier_page_usize = usize::try_from(frontier_page)
            .map_err(|_| ClientError::WitnessNotFound("missing finalized subroots"))?;
        if self.lanes[l].finalized_subroots.len() < frontier_page_usize {
            return Err(ClientError::WitnessNotFound("missing finalized subroots"));
        }
        let finalized_fr: Vec<Fr> = self.lanes[l].finalized_subroots[..frontier_page_usize]
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
            &snap_roots_fr,
            snap_count,
            &finalized_fr,
            frontier_fr.as_deref(),
        );
        let cm = fr_from_be_bytes_strict(&note.commitment).ok_or(ClientError::InvalidFieldElement)?;
        if path.compute_root(cm) != super_root {
            return Err(ClientError::WitnessNotFound("reconstructed Merkle root mismatch"));
        }
        Ok((super_root, path))
    }

    fn latest_snapshot_choice(history: &GlobalRootHistory) -> RootSnapshotChoice {
        RootSnapshotChoice {
            ring_kind: ROOT_RING_SLOT,
            ring_idx: history.slot_cursor as u8,
            slot: history.latest_slot,
            super_root: history.latest_super_root,
            lane_roots: history.latest_lane_roots,
            lane_counts: history.latest_lane_counts,
        }
    }

    /// Select the optimal `GlobalRootHistory` snapshot (preferring `stable` `epoch_ring`, falling
    /// back to `latest` `slot_ring` for freshly deposited notes OR when the local store lacks
    /// pre-seal frontier leaves for an older `stable` page) and build an offline witness for `note`.
    pub fn build_witness_from_root_history(
        &self,
        note: &OwnedNote,
        history: &GlobalRootHistory,
    ) -> Result<(RootSnapshotChoice, Fr, MerklePath4Ary), ClientError> {
        let (snapshot, super_root, mut paths) =
            self.build_witnesses_from_root_history(&[note], history)?;
        let path = paths
            .pop()
            .ok_or(ClientError::WitnessNotFound("witness missing"))?;
        Ok((snapshot, super_root, path))
    }

    /// Select ONE shared `GlobalRootHistory` snapshot covering ALL `notes` (for 2-input JoinSplits
    /// or multi-tx merge batches) and build offline witnesses for every note against that snapshot.
    ///
    /// When `select_snapshot_for_notes` picks `ROOT_RING_EPOCH` (`stable`) and local witness
    /// construction fails because the local store lacks pre-seal frontier leaves for that older
    /// `stable` page (e.g., fresh/exact-256/multi-page sync), falls back atomically to `history.latest`
    /// (`ROOT_RING_SLOT`) so every note in the batch still shares one valid snapshot.
    pub fn build_witnesses_from_root_history(
        &self,
        notes: &[&OwnedNote],
        history: &GlobalRootHistory,
    ) -> Result<(RootSnapshotChoice, Fr, Vec<MerklePath4Ary>), ClientError> {
        if notes.is_empty() {
            return Err(ClientError::InvalidEncoding("notes slice must not be empty"));
        }
        for note in notes {
            if note.pool_id != self.pool_id {
                return Err(ClientError::InvalidEncoding("note pool_id mismatch"));
            }
        }
        crate::scanner::validate_global_root_history(history, self.pool_id)?;
        let coords: Vec<(u8, u64)> = notes.iter().map(|n| (n.lane_id, n.leaf_index)).collect();
        let snapshot = history
            .select_snapshot_for_notes(&coords)
            .ok_or(ClientError::WitnessNotFound(
                "notes not yet included in GlobalRootHistory",
            ))?;

        let build_all =
            |snap: &RootSnapshotChoice| -> Result<(Fr, Vec<MerklePath4Ary>), ClientError> {
                let mut paths = Vec::with_capacity(notes.len());
                let mut sr_out = Fr::from(0u64);
                for note in notes {
                    let (sr, path) = self.build_witness_for_note(note, snap)?;
                    sr_out = sr;
                    paths.push(path);
                }
                Ok((sr_out, paths))
            };

        match build_all(&snapshot) {
            Ok((sr_out, paths)) => Ok((snapshot, sr_out, paths)),
            Err(ClientError::WitnessNotFound("missing frontier SubtreePage leaves"))
                if snapshot.ring_kind == ROOT_RING_EPOCH
                    && history.latest_lane_counts != history.stable_lane_counts
                    && coords
                        .iter()
                        .all(|&(lane, leaf)| leaf < history.latest_lane_counts[lane as usize]) =>
            {
                let latest_snapshot = Self::latest_snapshot_choice(history);
                let (sr_out, paths) = build_all(&latest_snapshot)?;
                Ok((latest_snapshot, sr_out, paths))
            }
            Err(err) => Err(err),
        }
    }

    /// Estimate active SubtreeRootPage count required for `lane_id` (`ceil(finalized / 300)`).
    /// Returns `0` if `lane_id` is out of range (`>= NUM_LANES`).
    pub fn subroot_pages_for_lane(&self, lane_id: u8) -> u64 {
        let Some(lane) = self.lanes.get(lane_id as usize) else {
            return 0;
        };
        let n = lane.finalized_subroots.len();
        (n.div_ceil(SUBROOTS_PER_PAGE).max(1)) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{encrypt_note_memo, AudrenKeys};
    use audren_circuits::note::derive_stealth_owner;
    use audren_core::{layout::MEMO_ENTRY_WIRE_LEN, ROOT_RING_EPOCH, WSOL_MINT};

    fn make_memo_page(lane_id: u8, seq: u64, count: u16) -> Vec<u8> {
        let mut buf = vec![0u8; MEMO_PAGE_LEN];
        buf[0..8].copy_from_slice(&MEMO_MAGIC);
        buf[MM_OFF_LANE_ID] = lane_id;
        buf[MM_OFF_COUNT..MM_OFF_COUNT + 2].copy_from_slice(&count.to_le_bytes());
        buf[MM_OFF_PAGE_SEQ..MM_OFF_PAGE_SEQ + 8].copy_from_slice(&seq.to_le_bytes());
        buf
    }

    fn write_memo_slot(buf: &mut [u8], slot: usize, memo_106: &[u8; MEMO_ENTRY_WIRE_LEN]) {
        buf[MM_OFF_VIEW_TAGS + slot * 2..MM_OFF_VIEW_TAGS + (slot + 1) * 2]
            .copy_from_slice(&memo_106[0..2]);
        buf[MM_OFF_EPHEMERAL_PKS + slot * 32..MM_OFF_EPHEMERAL_PKS + (slot + 1) * 32]
            .copy_from_slice(&memo_106[2..34]);
        buf[MM_OFF_CIPHERTEXTS + slot * MEMO_CT_LEN..MM_OFF_CIPHERTEXTS + (slot + 1) * MEMO_CT_LEN]
            .copy_from_slice(&memo_106[34..MEMO_ENTRY_WIRE_LEN]);
    }

    #[test]
    fn sealed_subtree_holds_frontier_until_lagged_memos_arrive_and_sorts_nf_pages() {
        let alice = AudrenKeys::from_seed(&[0x55u8; 32]);
        let fvk = alice.full_viewing_key();
        let sol_asset = derive_asset_id(&WSOL_MINT);

        let mut sub_raw = vec![0u8; SUBTREE_PAGE_LEN];
        sub_raw[0..8].copy_from_slice(&SUBTREE_MAGIC);
        sub_raw[SB_OFF_COUNT..SB_OFF_COUNT + 2]
            .copy_from_slice(&(SUBTREE_LEAVES as u16).to_le_bytes());

        let memo0 = make_memo_page(0, 0, MEMO_NOTES_PER_PAGE as u16);
        let mut memo1 = make_memo_page(0, 1, MEMO_NOTES_PER_PAGE as u16);
        let memo2 = make_memo_page(0, 2, (SUBTREE_LEAVES - 2 * MEMO_NOTES_PER_PAGE) as u16);

        for i in 0..SUBTREE_LEAVES {
            if i == 150 {
                let (tw, bl, memo_106) =
                    encrypt_note_memo(&alice.view_pk, [0x66u8; 32], 5_000_000, &WSOL_MINT).unwrap();
                let cm = compute_note_commitment(
                    derive_stealth_owner(alice.spend_pk, tw),
                    sol_asset,
                    5_000_000,
                    bl,
                );
                sub_raw[SB_OFF_LEAVES + i * 32..SB_OFF_LEAVES + (i + 1) * 32]
                    .copy_from_slice(&fr_to_be_bytes(&cm));
                write_memo_slot(&mut memo1, i - MEMO_NOTES_PER_PAGE, &memo_106);
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
        assert_eq!(store.lanes[0].next_memo_leaf, 96);
        assert_eq!(store.lanes[0].frontier_sub_seq, 0);
        assert_eq!(store.lanes[0].frontier_leaves.len(), SUBTREE_LEAVES);

        // Batch 2: MemoPage #1 arrives without re-passing SubtreePage #0
        let d2 = store
            .ingest_lane_pages(&fvk, 0, &[], &[(1, &memo1)], &[])
            .unwrap();
        assert_eq!(d2, 1);
        assert_eq!(store.lanes[0].next_memo_leaf, 192);
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

        // Out-of-order contiguous NullifierPages (page 1 before full page 0) must not skip page 0
        let mut nf0 = vec![0u8; NF_PAGE_LEN];
        nf0[0..8].copy_from_slice(&NF_PAGE_MAGIC);
        nf0[NF_OFF_COUNT..NF_OFF_COUNT + 2].copy_from_slice(&(NF_PER_PAGE as u16).to_le_bytes());
        nf0[NF_OFF_PREFIXES..NF_OFF_PREFIXES + NF_PREFIX_LEN]
            .copy_from_slice(&store.notes[0].nullifier[0..NF_PREFIX_LEN]);

        let mut nf1 = vec![0u8; NF_PAGE_LEN];
        nf1[0..8].copy_from_slice(&NF_PAGE_MAGIC);
        nf1[NF_OFF_COUNT..NF_OFF_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
        nf1[NF_OFF_PAGE_SEQ..NF_OFF_PAGE_SEQ + 8].copy_from_slice(&1u64.to_le_bytes());
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
    fn post_seal_snapshot_witness_uses_prev_sealed_leaves_and_prunes_on_newer_snapshot() {
        use audren_circuits::merkle::compute_super_root_4ary;
        use audren_circuits::poseidon::poseidon4;
        use audren_core::ZERO_HASHES_4ARY;

        let alice = AudrenKeys::from_seed(&[0x44u8; 32]);
        let fvk = alice.full_viewing_key();
        let sol_asset = derive_asset_id(&WSOL_MINT);

        let mut sub_raw = vec![0u8; SUBTREE_PAGE_LEN];
        sub_raw[0..8].copy_from_slice(&SUBTREE_MAGIC);
        sub_raw[SB_OFF_COUNT..SB_OFF_COUNT + 2]
            .copy_from_slice(&(SUBTREE_LEAVES as u16).to_le_bytes());

        let memo0 = make_memo_page(0, 0, MEMO_NOTES_PER_PAGE as u16);
        let memo1 = make_memo_page(0, 1, MEMO_NOTES_PER_PAGE as u16);
        let mut memo2 = make_memo_page(0, 2, (SUBTREE_LEAVES - 2 * MEMO_NOTES_PER_PAGE) as u16);

        let mut leaves_fr = Vec::with_capacity(SUBTREE_LEAVES);
        for i in 0..SUBTREE_LEAVES {
            if i == 200 {
                let (tw, bl, memo_106) =
                    encrypt_note_memo(&alice.view_pk, [0x45u8; 32], 7_500_000, &WSOL_MINT).unwrap();
                let cm = compute_note_commitment(
                    derive_stealth_owner(alice.spend_pk, tw),
                    sol_asset,
                    7_500_000,
                    bl,
                );
                leaves_fr.push(cm);
                sub_raw[SB_OFF_LEAVES + i * 32..SB_OFF_LEAVES + (i + 1) * 32]
                    .copy_from_slice(&fr_to_be_bytes(&cm));
                write_memo_slot(&mut memo2, i - 2 * MEMO_NOTES_PER_PAGE, &memo_106);
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

        // Reload from JSON and verify witness against pre-seal snapshot (count = 250)
        let mut reloaded = CompactWalletStore::from_json_bytes(&store.to_json_bytes().unwrap()).unwrap();
        let make_snap = |count: usize| {
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
                RootSnapshotChoice {
                    ring_kind: ROOT_RING_EPOCH,
                    ring_idx: 0,
                    slot: 100,
                    super_root: fr_to_be_bytes(&super_root),
                    lane_roots,
                    lane_counts,
                },
                super_root,
            )
        };

        let (pre_snap, pre_super) = make_snap(250);
        let note = reloaded.notes[0].clone();
        let (sr250, path250) = reloaded.build_witness_for_note(&note, &pre_snap).unwrap();
        assert_eq!(sr250, pre_super);
        assert_eq!(path250.compute_root(leaves_fr[200]), pre_super);

        // Newer snapshot crosses page 0 (count = 256) -> prunes prev_sealed_leaves
        let (post_snap, post_super) = make_snap(256);
        reloaded.prune_sealed_before_snapshot(&post_snap);
        assert_eq!(reloaded.lanes[0].prev_sealed_sub_seq, None);
        assert!(reloaded.lanes[0].prev_sealed_leaves.is_empty());
        let (sr256, path256) = reloaded.build_witness_for_note(&note, &post_snap).unwrap();
        assert_eq!(sr256, post_super);
        assert_eq!(path256.compute_root(leaves_fr[200]), post_super);
    }

    #[test]
    fn from_json_bytes_migrates_legacy_seen_nf_prefixes_and_discards_strangers() {
        let alice = AudrenKeys::from_seed(&[0x33u8; 32]);
        let fvk = alice.full_viewing_key();
        let sol_asset = derive_asset_id(&WSOL_MINT);

        let (tw, bl, memo_106) =
            encrypt_note_memo(&alice.view_pk, [0x34u8; 32], 1_000_000, &WSOL_MINT).unwrap();
        let cm = compute_note_commitment(
            derive_stealth_owner(alice.spend_pk, tw),
            sol_asset,
            1_000_000,
            bl,
        );
        let mut sub_raw = vec![0u8; SUBTREE_PAGE_LEN];
        sub_raw[0..8].copy_from_slice(&SUBTREE_MAGIC);
        sub_raw[SB_OFF_COUNT..SB_OFF_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
        sub_raw[SB_OFF_LEAVES..SB_OFF_LEAVES + 32].copy_from_slice(&fr_to_be_bytes(&cm));
        let mut memo0 = make_memo_page(0, 0, 1);
        write_memo_slot(&mut memo0, 0, &memo_106);

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

    #[test]
    fn r1_c2_store_deserialization_and_untrusted_bounds_never_panic() {
        // 1. JSON deserialization strictly requires lanes.len() == NUM_LANES (16)
        let empty_lanes_json = br#"{"pool_id":0,"birthday_slot":0,"lanes":[],"notes":[]}"#;
        assert!(CompactWalletStore::from_json_bytes(empty_lanes_json).is_err());

        let short_lanes_json = serde_json::json!({
            "pool_id": 0,
            "birthday_slot": 0,
            "lanes": (0..15).map(|_| CompactLaneState::default()).collect::<Vec<_>>(),
            "notes": []
        });
        assert!(CompactWalletStore::from_json_bytes(
            &serde_json::to_vec(&short_lanes_json).unwrap()
        )
        .is_err());

        // 2. subroot_pages_for_lane safely handles out-of-range lane_id >= NUM_LANES without panic
        let mut store = CompactWalletStore::new(0, 0);
        assert_eq!(store.subroot_pages_for_lane(0), 1);
        assert_eq!(store.subroot_pages_for_lane(NUM_LANES as u8), 0);
        assert_eq!(store.subroot_pages_for_lane(255), 0);

        // 3. balances() uses saturating_add (no u64 overflow panic!)
        let alice = AudrenKeys::from_seed(&[0x99u8; 32]);
        let fvk = alice.full_viewing_key();
        let dec1 = DecryptedMemo {
            tweak: Fr::from(1u64),
            blinding: Fr::from(2u64),
            amount: u64::MAX - 10,
            mint: WSOL_MINT,
            memo_version: 1,
            memo_flags: 0,
            payment_id: [0u8; MEMO_PAYMENT_ID_LEN],
            is_dynamic: false,
        };
        let dec2 = DecryptedMemo {
            tweak: Fr::from(3u64),
            blinding: Fr::from(4u64),
            amount: 100,
            mint: WSOL_MINT,
            memo_version: 1,
            memo_flags: 0,
            payment_id: [0u8; MEMO_PAYMENT_ID_LEN],
            is_dynamic: false,
        };
        let cm1 = fr_to_be_bytes(&compute_note_commitment(
            fvk.stealth_owner(dec1.tweak).unwrap(),
            derive_asset_id(&dec1.mint),
            dec1.amount,
            dec1.blinding,
        ));
        let cm2 = fr_to_be_bytes(&compute_note_commitment(
            fvk.stealth_owner(dec2.tweak).unwrap(),
            derive_asset_id(&dec2.mint),
            dec2.amount,
            dec2.blinding,
        ));
        store.record_verified_memo(&fvk, 0, 0, &dec1, cm1).unwrap();
        store.record_verified_memo(&fvk, 0, 1, &dec2, cm2).unwrap();
        assert_eq!(store.balances().get(&WSOL_MINT), Some(&u64::MAX));

        // 4. Forged page count > capacity & absurd page_seq jumps rejected without OOM/panic
        let mut bad_sr = vec![0u8; SUBROOT_PAGE_LEN];
        bad_sr[0..8].copy_from_slice(&SUBROOT_MAGIC);
        bad_sr[SR_OFF_COUNT..SR_OFF_COUNT + 2]
            .copy_from_slice(&((SUBROOTS_PER_PAGE + 1) as u16).to_le_bytes());
        assert!(store.ingest_subroot_pages(0, &[(0, &bad_sr)], None).is_err());

        let mut ok_sr = vec![0u8; SUBROOT_PAGE_LEN];
        ok_sr[0..8].copy_from_slice(&SUBROOT_MAGIC);
        ok_sr[SR_OFF_COUNT..SR_OFF_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
        ok_sr[SR_OFF_ROOT_PAGE_SEQ..SR_OFF_ROOT_PAGE_SEQ + 8]
            .copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(store
            .ingest_subroot_pages(0, &[(u64::MAX, &ok_sr)], None)
            .is_err());
        ok_sr[SR_OFF_ROOT_PAGE_SEQ..SR_OFF_ROOT_PAGE_SEQ + 8]
            .copy_from_slice(&10_000u64.to_le_bytes());
        assert!(store
            .ingest_subroot_pages(0, &[(10_000, &ok_sr)], None)
            .is_err());

        let mut bad_nf = vec![0u8; NF_PAGE_LEN];
        bad_nf[0..8].copy_from_slice(&NF_PAGE_MAGIC);
        bad_nf[NF_OFF_COUNT..NF_OFF_COUNT + 2]
            .copy_from_slice(&((NF_PER_PAGE + 1) as u16).to_le_bytes());
        assert!(store.ingest_nullifier_page(0, 0, &bad_nf, None).is_err());

        let mut ok_nf = vec![0u8; NF_PAGE_LEN];
        ok_nf[0..8].copy_from_slice(&NF_PAGE_MAGIC);
        ok_nf[NF_OFF_COUNT..NF_OFF_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
        ok_nf[NF_OFF_PAGE_SEQ..NF_OFF_PAGE_SEQ + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(store
            .ingest_nullifier_page(0, u64::MAX, &ok_nf, None)
            .is_err());

        let mut bad_sub = vec![0u8; SUBTREE_PAGE_LEN];
        bad_sub[0..8].copy_from_slice(&SUBTREE_MAGIC);
        bad_sub[SB_OFF_COUNT..SB_OFF_COUNT + 2]
            .copy_from_slice(&((SUBTREE_LEAVES + 1) as u16).to_le_bytes());
        assert!(store
            .ingest_lane_pages(&fvk, 0, &[(0, &bad_sub)], &[], &[])
            .is_err());

        let bad_memo = make_memo_page(0, 0, (MEMO_NOTES_PER_PAGE + 1) as u16);
        assert!(store
            .ingest_lane_pages(&fvk, 0, &[], &[(0, &bad_memo)], &[])
            .is_err());
    }

    #[test]
    fn r2_c4_and_c5_store_headers_json_invariants_and_checked_arithmetic() {
        let alice = AudrenKeys::from_seed(&[0xaau8; 32]);
        let fvk = alice.full_viewing_key();
        let mut store = CompactWalletStore::new(7, 0);

        // --- R2-C4: Strict (pool_id, lane_id, page_seq) header checks & canonical subroot Fr ---
        let make_sr = |pool_id: u32, lane_id: u8, seq: u64, root_be: [u8; 32]| {
            let mut b = vec![0u8; SUBROOT_PAGE_LEN];
            b[0..8].copy_from_slice(&SUBROOT_MAGIC);
            b[SR_OFF_POOL_ID..SR_OFF_POOL_ID + 4].copy_from_slice(&pool_id.to_le_bytes());
            b[SR_OFF_LANE_ID] = lane_id;
            b[SR_OFF_COUNT..SR_OFF_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
            b[SR_OFF_ROOT_PAGE_SEQ..SR_OFF_ROOT_PAGE_SEQ + 8].copy_from_slice(&seq.to_le_bytes());
            b[SR_OFF_ROOTS..SR_OFF_ROOTS + 32].copy_from_slice(&root_be);
            b
        };
        let valid_root = fr_to_be_bytes(&Fr::from(42u64));
        assert!(store
            .ingest_subroot_pages(1, &[(0, &make_sr(8, 1, 0, valid_root))], None)
            .is_err()); // pool_id mismatch
        assert!(store
            .ingest_subroot_pages(1, &[(0, &make_sr(7, 2, 0, valid_root))], None)
            .is_err()); // lane_id mismatch
        assert!(store
            .ingest_subroot_pages(1, &[(0, &make_sr(7, 1, 1, valid_root))], None)
            .is_err()); // page_seq mismatch
        assert!(store
            .ingest_subroot_pages(1, &[(0, &make_sr(7, 1, 0, [0xffu8; 32]))], None)
            .is_err()); // non-canonical Fr >= r
        assert!(store
            .ingest_subroot_pages(1, &[(0, &make_sr(7, 1, 0, valid_root))], None)
            .is_ok());

        let make_nf = |pool_id: u32, lane_id: u8, seq: u64| {
            let mut b = vec![0u8; NF_PAGE_LEN];
            b[0..8].copy_from_slice(&NF_PAGE_MAGIC);
            b[NF_OFF_POOL_ID..NF_OFF_POOL_ID + 4].copy_from_slice(&pool_id.to_le_bytes());
            b[NF_OFF_LANE_ID] = lane_id;
            b[NF_OFF_COUNT..NF_OFF_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
            b[NF_OFF_PAGE_SEQ..NF_OFF_PAGE_SEQ + 8].copy_from_slice(&seq.to_le_bytes());
            b
        };
        assert!(store
            .ingest_nullifier_page(1, 0, &make_nf(8, 1, 0), None)
            .is_err());
        assert!(store
            .ingest_nullifier_page(1, 0, &make_nf(7, 2, 0), None)
            .is_err());
        assert!(store
            .ingest_nullifier_page(1, 0, &make_nf(7, 1, 1), None)
            .is_err());
        assert!(store
            .ingest_nullifier_page(1, 0, &make_nf(7, 1, 0), None)
            .is_ok());

        let make_sub = |pool_id: u32, lane_id: u8, seq: u64| {
            let mut b = vec![0u8; SUBTREE_PAGE_LEN];
            b[0..8].copy_from_slice(&SUBTREE_MAGIC);
            b[SB_OFF_POOL_ID..SB_OFF_POOL_ID + 4].copy_from_slice(&pool_id.to_le_bytes());
            b[SB_OFF_LANE_ID] = lane_id;
            b[SB_OFF_COUNT..SB_OFF_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
            b[SB_OFF_PAGE_SEQ..SB_OFF_PAGE_SEQ + 8].copy_from_slice(&seq.to_le_bytes());
            b[SB_OFF_LEAVES..SB_OFF_LEAVES + 32].copy_from_slice(&valid_root);
            b
        };
        assert!(store
            .ingest_lane_pages(&fvk, 1, &[(0, &make_sub(8, 1, 0))], &[], &[])
            .is_err());
        assert!(store
            .ingest_lane_pages(&fvk, 1, &[(0, &make_sub(7, 2, 0))], &[], &[])
            .is_err());
        assert!(store
            .ingest_lane_pages(&fvk, 1, &[(0, &make_sub(7, 1, 1))], &[], &[])
            .is_err());

        // --- R2-C5: Malformed CompactWalletStore JSON rejected without panics ---
        let mut base = CompactWalletStore::new(0, 0);
        let dec = DecryptedMemo {
            tweak: Fr::from(1u64),
            blinding: Fr::from(2u64),
            amount: 1_000,
            mint: WSOL_MINT,
            memo_version: 1,
            memo_flags: 0,
            payment_id: [0u8; MEMO_PAYMENT_ID_LEN],
            is_dynamic: false,
        };
        let dec_cm = fr_to_be_bytes(&compute_note_commitment(
            fvk.stealth_owner(dec.tweak).unwrap(),
            derive_asset_id(&dec.mint),
            dec.amount,
            dec.blinding,
        ));
        base.record_verified_memo(&fvk, 0, 5, &dec, dec_cm).unwrap();
        let base_val: serde_json::Value =
            serde_json::from_slice(&base.to_json_bytes().unwrap()).unwrap();

        // 1. Out-of-range frozen_intra_positions (`p = 4`) must be rejected by from_json_bytes
        let mut bad_pos = base_val.clone();
        bad_pos["notes"][0]["frozen_intra_siblings"] =
            serde_json::json!([[[[0u8; 32]; 3]; SUBTREE_LEVELS_4ARY]][0]);
        bad_pos["notes"][0]["frozen_intra_positions"] = serde_json::json!([4, 0, 0, 0]);
        assert!(
            CompactWalletStore::from_json_bytes(&serde_json::to_vec(&bad_pos).unwrap()).is_err(),
            "R2-C5: frozen_intra_positions >= 4 must be rejected"
        );

        // 2. Unpaired frozen_intra_siblings / frozen_intra_positions
        let mut unpaired = base_val.clone();
        unpaired["notes"][0]["frozen_intra_positions"] = serde_json::json!([0, 1, 2, 3]);
        assert!(
            CompactWalletStore::from_json_bytes(&serde_json::to_vec(&unpaired).unwrap()).is_err(),
            "R2-C5: unpaired frozen_intra_positions must be rejected"
        );

        // 3. Invalid lane_id (>= 16), leaf_index (>= MAX_LEAVES_PER_LANE), global_leaf_index mismatch
        let mut bad_lane_id = base_val.clone();
        bad_lane_id["notes"][0]["lane_id"] = serde_json::json!(16);
        assert!(
            CompactWalletStore::from_json_bytes(&serde_json::to_vec(&bad_lane_id).unwrap())
                .is_err()
        );
        let mut bad_leaf_idx = base_val.clone();
        bad_leaf_idx["notes"][0]["leaf_index"] = serde_json::json!(MAX_LEAVES_PER_LANE);
        bad_leaf_idx["notes"][0]["global_leaf_index"] = serde_json::json!(MAX_LEAVES_PER_LANE);
        assert!(
            CompactWalletStore::from_json_bytes(&serde_json::to_vec(&bad_leaf_idx).unwrap())
                .is_err()
        );
        let mut bad_global = base_val.clone();
        bad_global["notes"][0]["global_leaf_index"] = serde_json::json!(999);
        assert!(
            CompactWalletStore::from_json_bytes(&serde_json::to_vec(&bad_global).unwrap()).is_err()
        );

        // 4. Out-of-bounds lane metadata (`next_memo_leaf`, `frontier_sub_seq`, `prev_sealed_sub_seq`)
        let mut bad_next_memo = base_val.clone();
        bad_next_memo["lanes"][0]["next_memo_leaf"] = serde_json::json!(MAX_LEAVES_PER_LANE + 1);
        assert!(
            CompactWalletStore::from_json_bytes(&serde_json::to_vec(&bad_next_memo).unwrap())
                .is_err()
        );
        let mut bad_frontier_seq = base_val.clone();
        bad_frontier_seq["lanes"][0]["frontier_sub_seq"] =
            serde_json::json!(MAX_SUBROOTS_PER_LANE + 1);
        assert!(
            CompactWalletStore::from_json_bytes(&serde_json::to_vec(&bad_frontier_seq).unwrap())
                .is_err()
        );
        let mut bad_prev_seq = base_val.clone();
        bad_prev_seq["lanes"][0]["prev_sealed_sub_seq"] = serde_json::json!(MAX_SUBROOTS_PER_LANE);
        assert!(
            CompactWalletStore::from_json_bytes(&serde_json::to_vec(&bad_prev_seq).unwrap())
                .is_err()
        );

        // 5. Defense-in-depth: in-memory corrupted `frozen_intra_positions = [4,0,0,0]` returns Err
        //    (never panics inside `MerklePath4Ary` / `merkle.rs:85`)
        let mut mem_corrupt = base.clone();
        mem_corrupt.lanes[0].finalized_subroots.push(valid_root);
        mem_corrupt.notes[0].frozen_intra_siblings = Some([[[0u8; 32]; 3]; SUBTREE_LEVELS_4ARY]);
        mem_corrupt.notes[0].frozen_intra_positions = Some([4, 0, 0, 0]);
        let mut lane_counts = [0u64; NUM_LANES];
        lane_counts[0] = SUBTREE_LEAVES as u64;
        let z18 = fr_from_be_bytes_strict(&audren_core::ZERO_HASHES_4ARY[18]).unwrap();
        let mut lane_roots_fr = [z18; NUM_LANES];
        lane_roots_fr[0] = Fr::from(42u64);
        let mut lane_roots = [audren_core::ZERO_HASHES_4ARY[18]; NUM_LANES];
        lane_roots[0] = fr_to_be_bytes(&lane_roots_fr[0]);
        let dummy_snap = RootSnapshotChoice {
            ring_kind: ROOT_RING_EPOCH,
            ring_idx: 0,
            slot: 1,
            super_root: fr_to_be_bytes(&compute_super_root_4ary(&lane_roots_fr)),
            lane_roots,
            lane_counts,
        };
        assert!(
            matches!(
                mem_corrupt.build_witness_for_note(&mem_corrupt.notes[0], &dummy_snap),
                Err(ClientError::InvalidEncoding("frozen_intra_positions out of range"))
            ),
            "R2-C5: build_witness_for_note must return Err instead of panicking on pos >= 4"
        );

        // 6. Defense-in-depth: in-memory `frontier_sub_seq = u64::MAX` returns Err on checked_add/mul
        let mut overflow_store = CompactWalletStore::new(0, 0);
        overflow_store.lanes[0].frontier_sub_seq = u64::MAX;
        overflow_store.lanes[0].frontier_leaves = vec![valid_root; SUBTREE_LEAVES];
        assert!(
            overflow_store
                .ingest_lane_pages(&fvk, 0, &[], &[], &[])
                .is_err(),
            "R2-C5: frontier_sub_seq = u64::MAX must return Err instead of panicking on arithmetic overflow"
        );
    }

    #[test]
    fn r4_c3_freeze_owned_notes_skips_mismatched_commitment_and_caps_max_leaves() {
        let alice = AudrenKeys::from_seed(&[0xb4u8; 32]);
        let fvk = alice.full_viewing_key();
        let sol_asset = derive_asset_id(&WSOL_MINT);

        let (tw, bl, memo_106) =
            encrypt_note_memo(&alice.view_pk, [0xb5u8; 32], 2_500_000, &WSOL_MINT).unwrap();
        let cm = compute_note_commitment(
            derive_stealth_owner(alice.spend_pk, tw),
            sol_asset,
            2_500_000,
            bl,
        );
        let cm_be = fr_to_be_bytes(&cm);

        // Ingest an unsealed frontier page containing Alice's note at leaf index 7
        let mut sub_partial = vec![0u8; SUBTREE_PAGE_LEN];
        sub_partial[0..8].copy_from_slice(&SUBTREE_MAGIC);
        sub_partial[SB_OFF_COUNT..SB_OFF_COUNT + 2].copy_from_slice(&10u16.to_le_bytes());
        for i in 0..10 {
            let leaf_be = if i == 7 {
                cm_be
            } else {
                fr_to_be_bytes(&Fr::from((i + 1) as u64))
            };
            sub_partial[SB_OFF_LEAVES + i * 32..SB_OFF_LEAVES + (i + 1) * 32]
                .copy_from_slice(&leaf_be);
        }
        let mut memo_partial = make_memo_page(0, 0, 10);
        write_memo_slot(&mut memo_partial, 7, &memo_106);

        let mut store = CompactWalletStore::new(0, 0);
        let discovered = store
            .ingest_lane_pages(&fvk, 0, &[(0, &sub_partial)], &[(0, &memo_partial)], &[])
            .unwrap();
        assert_eq!(discovered, 1);
        assert_eq!(store.notes.len(), 1);
        assert!(store.notes[0].frozen_intra_siblings.is_none());

        // 1. Direct freeze_owned_notes_in_subtree_page with mismatched leaf at offset 7 MUST skip!
        let forged_leaves: Vec<[u8; 32]> = (0..SUBTREE_LEAVES)
            .map(|i| fr_to_be_bytes(&Fr::from((i + 100) as u64)))
            .collect();
        assert_ne!(forged_leaves[7], cm_be);
        store
            .freeze_owned_notes_in_subtree_page(0, 0, &forged_leaves)
            .unwrap();
        assert!(
            store.notes[0].frozen_intra_siblings.is_none(),
            "R4-C3: forged direct freeze must NOT populate frozen_intra_siblings"
        );
        assert!(
            store.notes[0].frozen_intra_positions.is_none(),
            "R4-C3: forged direct freeze must NOT populate frozen_intra_positions"
        );

        // 2. ingest_lane_pages with a forged sealed SubtreePage #0 MUST reject the mutated
        //    frontier prefix outright (zero subroot poisoning, zero freezing)!
        let mut forged_sub_raw = vec![0u8; SUBTREE_PAGE_LEN];
        forged_sub_raw[0..8].copy_from_slice(&SUBTREE_MAGIC);
        forged_sub_raw[SB_OFF_COUNT..SB_OFF_COUNT + 2]
            .copy_from_slice(&(SUBTREE_LEAVES as u16).to_le_bytes());
        for (i, leaf) in forged_leaves.iter().enumerate() {
            forged_sub_raw[SB_OFF_LEAVES + i * 32..SB_OFF_LEAVES + (i + 1) * 32]
                .copy_from_slice(leaf);
        }
        assert!(
            store
                .ingest_lane_pages(&fvk, 0, &[(0, &forged_sub_raw)], &[], &[])
                .is_err(),
            "R4-C3 + R6-1: forged sealed SubtreePage via ingest_lane_pages must reject mutated frontier prefix"
        );
        assert!(
            store.lanes[0].finalized_subroots.is_empty(),
            "R6-1: rejected forged SubtreePage must NOT poison finalized_subroots"
        );
        assert!(
            store.notes[0].frozen_intra_siblings.is_none(),
            "R4-C3: forged sealed SubtreePage via ingest_lane_pages must NOT freeze mismatched note"
        );

        // 3. Matching commitment at offset 7 freezes cleanly!
        let mut valid_leaves = forged_leaves;
        valid_leaves[7] = cm_be;
        store
            .freeze_owned_notes_in_subtree_page(0, 0, &valid_leaves)
            .unwrap();
        assert!(store.notes[0].frozen_intra_siblings.is_some());
        assert!(store.notes[0].frozen_intra_positions.is_some());

        // 4. ingest_lane_pages stops at MAX_LEAVES_PER_LANE without advancing next_memo_leaf past cap
        let mut cap_store = CompactWalletStore::new(0, 0);
        cap_store.lanes[0].next_memo_leaf = MAX_LEAVES_PER_LANE;
        let max_memo_seq = MAX_LEAVES_PER_LANE / MEMO_NOTES_PER_PAGE as u64;
        let memo_at_max = make_memo_page(0, max_memo_seq, MEMO_NOTES_PER_PAGE as u16);
        let d_cap = cap_store
            .ingest_lane_pages(&fvk, 0, &[], &[(max_memo_seq, &memo_at_max)], &[])
            .unwrap();
        assert_eq!(d_cap, 0);
        assert_eq!(cap_store.lanes[0].next_memo_leaf, MAX_LEAVES_PER_LANE);
    }

    #[test]
    fn r2_store_dual_snapshot_direct_validation_and_pool_id_deserialization_parity() {
        use audren_circuits::merkle::zero_hashes_4ary;
        use audren_core::{
            layout::{RootEntry, ROOT_HISTORY_LEN},
            DEFAULT_ROOT_EPOCH_INTERVAL, EPOCH_RING_LEN, LANE_DEPTH_4ARY, ROOT_RING_SLOT,
            SLOT_RING_LEN,
        };

        let alice = AudrenKeys::from_seed(&[0xc1u8; 32]);
        let fvk = alice.full_viewing_key();
        let sol_asset = derive_asset_id(&WSOL_MINT);

        let (tw0, bl0, memo0) =
            encrypt_note_memo(&alice.view_pk, [0xc2u8; 32], 1_000_000, &WSOL_MINT).unwrap();
        let cm0 = compute_note_commitment(
            derive_stealth_owner(alice.spend_pk, tw0),
            sol_asset,
            1_000_000,
            bl0,
        );
        let cm0_be = fr_to_be_bytes(&cm0);

        let (tw1, bl1, memo1) =
            encrypt_note_memo(&alice.view_pk, [0xc3u8; 32], 2_000_000, &WSOL_MINT).unwrap();
        let cm1 = compute_note_commitment(
            derive_stealth_owner(alice.spend_pk, tw1),
            sol_asset,
            2_000_000,
            bl1,
        );
        let cm1_be = fr_to_be_bytes(&cm1);

        let mut sub_raw = vec![0u8; SUBTREE_PAGE_LEN];
        sub_raw[0..8].copy_from_slice(&SUBTREE_MAGIC);
        sub_raw[SB_OFF_COUNT..SB_OFF_COUNT + 2].copy_from_slice(&2u16.to_le_bytes());
        sub_raw[SB_OFF_LEAVES..SB_OFF_LEAVES + 32].copy_from_slice(&cm0_be);
        sub_raw[SB_OFF_LEAVES + 32..SB_OFF_LEAVES + 64].copy_from_slice(&cm1_be);

        let mut memo_raw = make_memo_page(0, 0, 2);
        write_memo_slot(&mut memo_raw, 0, &memo0);
        write_memo_slot(&mut memo_raw, 1, &memo1);

        let mut store = CompactWalletStore::new(0, 0);
        assert_eq!(
            store
                .ingest_lane_pages(&fvk, 0, &[(0, &sub_raw)], &[(0, &memo_raw)], &[])
                .unwrap(),
            2
        );
        let note0 = store.notes[0].clone();
        let note1 = store.notes[1].clone();

        // 1. from_json_bytes rejects any deserialized note where note.pool_id != store.pool_id
        let mut bad_pool_json: serde_json::Value =
            serde_json::from_slice(&store.to_json_bytes().unwrap()).unwrap();
        bad_pool_json["notes"][0]["pool_id"] = serde_json::json!(1);
        assert!(
            matches!(
                CompactWalletStore::from_json_bytes(&serde_json::to_vec(&bad_pool_json).unwrap()),
                Err(ClientError::InvalidEncoding("store note pool_id mismatch"))
            ),
            "from_json_bytes must reject note.pool_id != store.pool_id"
        );

        // Build a cryptographically valid dual-snapshot GlobalRootHistory (stable=1 leaf, latest=2 leaves)
        let zeros = zero_hashes_4ary();
        let compute_lane0_root = |leaves: &[Fr]| -> Fr {
            let mut cur = compute_subtree_256_root(leaves, leaves.len());
            for &z in &zeros[SUBTREE_LEVELS_4ARY..LANE_DEPTH_4ARY] {
                cur = audren_circuits::poseidon::poseidon4(cur, z, z, z);
            }
            cur
        };

        let mut stable_lane_roots_fr = [zeros[LANE_DEPTH_4ARY]; NUM_LANES];
        stable_lane_roots_fr[0] = compute_lane0_root(&[cm0]);
        let stable_sr_fr = compute_super_root_4ary(&stable_lane_roots_fr);
        let stable_sr = fr_to_be_bytes(&stable_sr_fr);
        let mut stable_lane_roots = [[0u8; 32]; NUM_LANES];
        for i in 0..NUM_LANES {
            stable_lane_roots[i] = fr_to_be_bytes(&stable_lane_roots_fr[i]);
        }
        let mut stable_lane_counts = [0u64; NUM_LANES];
        stable_lane_counts[0] = 1;

        let mut latest_lane_roots_fr = [zeros[LANE_DEPTH_4ARY]; NUM_LANES];
        latest_lane_roots_fr[0] = compute_lane0_root(&[cm0, cm1]);
        let latest_sr_fr = compute_super_root_4ary(&latest_lane_roots_fr);
        let latest_sr = fr_to_be_bytes(&latest_sr_fr);
        let mut latest_lane_roots = [[0u8; 32]; NUM_LANES];
        for i in 0..NUM_LANES {
            latest_lane_roots[i] = fr_to_be_bytes(&latest_lane_roots_fr[i]);
        }
        let mut latest_lane_counts = [0u64; NUM_LANES];
        latest_lane_counts[0] = 2;

        let mut slot_ring = [RootEntry {
            super_root: [0u8; 32],
            slot: 0,
        }; SLOT_RING_LEN];
        slot_ring[0] = RootEntry {
            super_root: latest_sr,
            slot: 100,
        };
        let mut epoch_ring = [RootEntry {
            super_root: [0u8; 32],
            slot: 0,
        }; EPOCH_RING_LEN];
        epoch_ring[0] = RootEntry {
            super_root: stable_sr,
            slot: 96,
        };

        let valid_history = GlobalRootHistory {
            version: audren_core::PROTOCOL_VERSION,
            bump: 254,
            slot_cursor: 0,
            pool_id: 0,
            epoch_cursor: 0,
            slot_count: 1,
            epoch_count: 1,
            same_slot_bumped: false,
            latest_slot: 100,
            stable_epoch_id: 3,
            stable_slot: 96,
            epoch_interval: DEFAULT_ROOT_EPOCH_INTERVAL,
            group_roots: [fr_to_be_bytes(&zeros[19]); 4],
            latest_super_root: latest_sr,
            latest_lane_roots,
            latest_lane_counts,
            stable_super_root: stable_sr,
            stable_lane_roots,
            stable_lane_counts,
            slot_ring,
            epoch_ring,
        };
        let _ = ROOT_HISTORY_LEN;

        // Baseline succeeds (note0 selects stable, [note0, note1] selects latest)
        let (snap0, sr0, path0) = store
            .build_witness_from_root_history(&note0, &valid_history)
            .unwrap();
        assert_eq!(snap0.ring_kind, ROOT_RING_EPOCH);
        assert_eq!(sr0, stable_sr_fr);
        assert_eq!(path0.compute_root(cm0), stable_sr_fr);

        let (snap_both, sr_both, paths_both) = store
            .build_witnesses_from_root_history(&[&note0, &note1], &valid_history)
            .unwrap();
        assert_eq!(snap_both.ring_kind, ROOT_RING_SLOT);
        assert_eq!(sr_both, latest_sr_fr);
        assert_eq!(paths_both[0].compute_root(cm0), latest_sr_fr);
        assert_eq!(paths_both[1].compute_root(cm1), latest_sr_fr);

        // 2. Direct build_witness_for_note rejects pool_id mismatch, invalid ring_kind/ring_idx, zero super_root, and snap_count > MAX_LEAVES_PER_LANE
        let mut wrong_pool_note = note0.clone();
        wrong_pool_note.pool_id = 1;
        assert!(matches!(
            store.build_witness_for_note(&wrong_pool_note, &snap0),
            Err(ClientError::InvalidEncoding("note pool_id mismatch"))
        ));

        let mut bad_ring_kind = snap0;
        bad_ring_kind.ring_kind = 99;
        assert!(store.build_witness_for_note(&note0, &bad_ring_kind).is_err());

        let mut bad_slot_idx = snap_both;
        bad_slot_idx.ring_kind = ROOT_RING_SLOT;
        bad_slot_idx.ring_idx = SLOT_RING_LEN as u8;
        assert!(store.build_witness_for_note(&note0, &bad_slot_idx).is_err());

        let mut bad_epoch_idx = snap0;
        bad_epoch_idx.ring_kind = ROOT_RING_EPOCH;
        bad_epoch_idx.ring_idx = EPOCH_RING_LEN as u8;
        assert!(store.build_witness_for_note(&note0, &bad_epoch_idx).is_err());

        let mut zero_sr_snap = snap0;
        zero_sr_snap.super_root = [0u8; 32];
        assert!(store.build_witness_for_note(&note0, &zero_sr_snap).is_err());

        let mut huge_count_snap = snap0;
        huge_count_snap.lane_counts[0] = MAX_LEAVES_PER_LANE + 1;
        assert!(store.build_witness_for_note(&note0, &huge_count_snap).is_err());

        // 3. build_witness{,es}_from_root_history reject note.pool_id != store.pool_id even if history.pool_id == note.pool_id!
        let mut pool1_history = valid_history.clone();
        pool1_history.pool_id = 1;
        assert!(matches!(
            store.build_witness_from_root_history(&wrong_pool_note, &pool1_history),
            Err(ClientError::InvalidEncoding("note pool_id mismatch"))
        ));
        assert!(matches!(
            store.build_witnesses_from_root_history(&[&wrong_pool_note], &pool1_history),
            Err(ClientError::InvalidEncoding("note pool_id mismatch"))
        ));

        // 4. Tampered/all-zero/non-canonical/forged stable snapshot MUST NOT silently downgrade to latest!
        let mut zero_stable = valid_history.clone();
        zero_stable.stable_super_root = [0u8; 32];
        zero_stable.epoch_ring[0].super_root = [0u8; 32];
        assert!(store.build_witness_from_root_history(&note0, &zero_stable).is_err());
        assert!(store.build_witnesses_from_root_history(&[&note0], &zero_stable).is_err());

        let mut non_canon_stable = valid_history.clone();
        non_canon_stable.stable_super_root = [0xffu8; 32];
        non_canon_stable.epoch_ring[0].super_root = [0xffu8; 32];
        non_canon_stable.stable_lane_counts = [0u64; NUM_LANES];
        assert!(matches!(
            store.build_witness_from_root_history(&note0, &non_canon_stable),
            Err(ClientError::InvalidFieldElement)
        ));
        assert!(matches!(
            store.build_witnesses_from_root_history(&[&note0], &non_canon_stable),
            Err(ClientError::InvalidFieldElement)
        ));

        let mut forged_stable = valid_history.clone();
        let fake_sr = fr_to_be_bytes(&Fr::from(999_999u64));
        forged_stable.stable_super_root = fake_sr;
        forged_stable.epoch_ring[0].super_root = fake_sr;
        forged_stable.stable_lane_counts = [0u64; NUM_LANES];
        assert!(store.build_witness_from_root_history(&note0, &forged_stable).is_err());
        assert!(store.build_witnesses_from_root_history(&[&note0], &forged_stable).is_err());

        // 5. Tampered latest snapshot even when stable covers note MUST be rejected!
        let mut tampered_latest = valid_history.clone();
        tampered_latest.latest_super_root = fake_sr;
        tampered_latest.slot_ring[0].super_root = fake_sr;
        assert!(store.build_witness_from_root_history(&note0, &tampered_latest).is_err());

        // 6. Out-of-bounds cursors/counts MUST return Err without panicking!
        for mutator in [
            (|h: &mut GlobalRootHistory| h.slot_cursor = 200) as fn(&mut GlobalRootHistory),
            |h| h.slot_count = 0,
            |h| h.epoch_cursor = 200,
            |h| h.epoch_count = 90,
            |h| h.latest_lane_counts[0] = MAX_LEAVES_PER_LANE + 1,
            |h| h.stable_lane_counts[0] = MAX_LEAVES_PER_LANE + 1,
            |h| h.stable_lane_counts[0] = 0, // 8-byte stable downgrade (lane_root != Z18)
            |h| h.stable_lane_counts[0] = 3, // stable_lane_counts > latest_lane_counts
            |h| h.stable_lane_counts[0] = 2, // equal counts with differing roots
            |h| {
                h.stable_slot = 101;
                h.epoch_ring[0].slot = 101;
                h.stable_epoch_id = 101 / DEFAULT_ROOT_EPOCH_INTERVAL;
            },
            |h| h.slot_ring[0].slot = 99,
            |h| h.epoch_ring[0].slot = 95,
            |h| h.stable_epoch_id = 999,
            |h| h.epoch_interval = 0,
            |h| h.epoch_interval = audren_core::MAX_ROOT_EPOCH_INTERVAL + 1,
        ] {
            let mut bad_h = valid_history.clone();
            mutator(&mut bad_h);
            assert!(store.build_witness_from_root_history(&note0, &bad_h).is_err());
            assert!(store.build_witnesses_from_root_history(&[&note0], &bad_h).is_err());
        }

        // 7. Round-3: record_verified_memo rejects leaf_idx >= MAX_LEAVES_PER_LANE (no bit collision!)
        let dummy_dec = DecryptedMemo {
            tweak: Fr::from(1u64),
            blinding: Fr::from(2u64),
            amount: 100,
            mint: [0u8; 32],
            memo_version: 1,
            memo_flags: 0,
            payment_id: [0u8; MEMO_PAYMENT_ID_LEN],
            is_dynamic: false,
        };
        let alice_keys = AudrenKeys::from_seed(&[0x55u8; 32]);
        let alice_fvk = alice_keys.full_viewing_key();
        let mut rec_store = CompactWalletStore::new(0, 0);
        assert!(matches!(
            rec_store.record_verified_memo(&alice_fvk, 0, MAX_LEAVES_PER_LANE, &dummy_dec, [0u8; 32]),
            Err(ClientError::InvalidEncoding("leaf_idx exceeds MAX_LEAVES_PER_LANE"))
        ));
        assert!(matches!(
            rec_store.record_verified_memo(&alice_fvk, 0, u64::MAX, &dummy_dec, [0u8; 32]),
            Err(ClientError::InvalidEncoding("leaf_idx exceeds MAX_LEAVES_PER_LANE"))
        ));
        assert!(rec_store.notes.is_empty());

        // 8. Round-3: prune_sealed_before_root_history ignores wrong-pool / tampered history
        let mut prune_store = CompactWalletStore::new(0, 0);
        prune_store.lanes[0].prev_sealed_sub_seq = Some(0);
        prune_store.lanes[0].prev_sealed_leaves = vec![[1u8; 32]; SUBTREE_LEAVES];
        let mut wrong_pool_prune = valid_history.clone();
        wrong_pool_prune.pool_id = 1;
        wrong_pool_prune.stable_lane_counts[0] = 512;
        wrong_pool_prune.latest_lane_counts[0] = 512;
        prune_store.prune_sealed_before_root_history(&wrong_pool_prune);
        assert_eq!(prune_store.lanes[0].prev_sealed_sub_seq, Some(0));
        assert_eq!(prune_store.lanes[0].prev_sealed_leaves.len(), SUBTREE_LEAVES);

        let mut bad_snap_prune = snap0;
        bad_snap_prune.lane_counts[0] = 0; // non-zero lane_root[0] -> invalid snapshot
        prune_store.prune_sealed_before_snapshot(&bad_snap_prune);
        assert_eq!(prune_store.lanes[0].prev_sealed_sub_seq, Some(0));
    }

    #[test]
    fn prune_refuses_slot_ring_and_witness_builders_fallback_stable_to_latest() {
        use audren_circuits::merkle::zero_hashes_4ary;
        use audren_circuits::poseidon::poseidon4;
        use audren_core::{
            layout::RootEntry, DEFAULT_ROOT_EPOCH_INTERVAL, EPOCH_RING_LEN, LANE_DEPTH_4ARY,
            SLOT_RING_LEN,
        };

        let alice = AudrenKeys::from_seed(&[0xd1u8; 32]);
        let fvk = alice.full_viewing_key();
        let sol_asset = derive_asset_id(&WSOL_MINT);

        // Build two full 256-leaf pages on lane 0 (512 leaves total) with owned notes at leaf 10 and leaf 200
        let mut sub0 = vec![0u8; SUBTREE_PAGE_LEN];
        sub0[0..8].copy_from_slice(&SUBTREE_MAGIC);
        sub0[SB_OFF_COUNT..SB_OFF_COUNT + 2]
            .copy_from_slice(&(SUBTREE_LEAVES as u16).to_le_bytes());

        let mut memo0 = make_memo_page(0, 0, MEMO_NOTES_PER_PAGE as u16);
        let memo1 = make_memo_page(0, 1, MEMO_NOTES_PER_PAGE as u16);
        let mut memo2 = make_memo_page(0, 2, (SUBTREE_LEAVES - 2 * MEMO_NOTES_PER_PAGE) as u16);

        let mut page0_fr = Vec::with_capacity(SUBTREE_LEAVES);
        for i in 0..SUBTREE_LEAVES {
            if i == 10 {
                let (tw, bl, m106) =
                    encrypt_note_memo(&alice.view_pk, [0xd2u8; 32], 3_000_000, &WSOL_MINT).unwrap();
                let cm = compute_note_commitment(
                    derive_stealth_owner(alice.spend_pk, tw),
                    sol_asset,
                    3_000_000,
                    bl,
                );
                page0_fr.push(cm);
                sub0[SB_OFF_LEAVES + i * 32..SB_OFF_LEAVES + (i + 1) * 32]
                    .copy_from_slice(&fr_to_be_bytes(&cm));
                write_memo_slot(&mut memo0, i, &m106);
            } else if i == 200 {
                let (tw, bl, m106) =
                    encrypt_note_memo(&alice.view_pk, [0xd3u8; 32], 4_000_000, &WSOL_MINT).unwrap();
                let cm = compute_note_commitment(
                    derive_stealth_owner(alice.spend_pk, tw),
                    sol_asset,
                    4_000_000,
                    bl,
                );
                page0_fr.push(cm);
                sub0[SB_OFF_LEAVES + i * 32..SB_OFF_LEAVES + (i + 1) * 32]
                    .copy_from_slice(&fr_to_be_bytes(&cm));
                write_memo_slot(&mut memo2, i - 2 * MEMO_NOTES_PER_PAGE, &m106);
            } else {
                let leaf = Fr::from((i + 50) as u64);
                page0_fr.push(leaf);
                sub0[SB_OFF_LEAVES + i * 32..SB_OFF_LEAVES + (i + 1) * 32]
                    .copy_from_slice(&fr_to_be_bytes(&leaf));
            }
        }

        let mut store = CompactWalletStore::new(0, 0);
        assert_eq!(
            store
                .ingest_lane_pages(
                    &fvk,
                    0,
                    &[(0, &sub0)],
                    &[(0, &memo0), (1, &memo1), (2, &memo2)],
                    &[],
                )
                .unwrap(),
            2
        );
        assert_eq!(store.lanes[0].prev_sealed_sub_seq, Some(0));
        assert_eq!(store.lanes[0].prev_sealed_leaves.len(), SUBTREE_LEAVES);

        let zeros = zero_hashes_4ary();
        let lane_root_partial = |leaves: &[Fr]| -> Fr {
            let mut cur = compute_subtree_256_root(leaves, leaves.len());
            for &z in &zeros[SUBTREE_LEVELS_4ARY..LANE_DEPTH_4ARY] {
                cur = poseidon4(cur, z, z, z);
            }
            cur
        };

        let make_lane_roots = |r0: Fr| -> ([Fr; NUM_LANES], [[u8; 32]; NUM_LANES]) {
            let mut frs = [zeros[LANE_DEPTH_4ARY]; NUM_LANES];
            frs[0] = r0;
            let mut bytes = [[0u8; 32]; NUM_LANES];
            for i in 0..NUM_LANES {
                bytes[i] = fr_to_be_bytes(&frs[i]);
            }
            (frs, bytes)
        };

        let (stable_frs, stable_lr) = make_lane_roots(lane_root_partial(&page0_fr[..250]));
        let stable_sr_fr = compute_super_root_4ary(&stable_frs);
        let stable_sr = fr_to_be_bytes(&stable_sr_fr);
        let mut stable_counts = [0u64; NUM_LANES];
        stable_counts[0] = 250;

        let (latest_frs, latest_lr) = make_lane_roots(lane_root_partial(&page0_fr[..256]));
        let latest_sr_fr = compute_super_root_4ary(&latest_frs);
        let latest_sr = fr_to_be_bytes(&latest_sr_fr);
        let mut latest_counts = [0u64; NUM_LANES];
        latest_counts[0] = 256;

        // 1. `prune_sealed_before_snapshot` MUST be a no-op for `ROOT_RING_SLOT` even though count 256 crosses page 0!
        let slot_snap_256 = RootSnapshotChoice {
            ring_kind: ROOT_RING_SLOT,
            ring_idx: 2,
            slot: 105,
            super_root: latest_sr,
            lane_roots: latest_lr,
            lane_counts: latest_counts,
        };
        store.prune_sealed_before_snapshot(&slot_snap_256);
        assert_eq!(
            store.lanes[0].prev_sealed_sub_seq,
            Some(0),
            "ROOT_RING_SLOT snapshot MUST NOT prune prev_sealed_leaves"
        );
        assert_eq!(store.lanes[0].prev_sealed_leaves.len(), SUBTREE_LEAVES);

        // 2. When `prev_sealed_leaves` is absent (e.g., fresh/exact-256 or multi-page sync where `stable`
        //    at 250 is pre-seal while `latest` is at 256), `build_witness_from_root_history` and
        //    `build_witnesses_from_root_history` fall back atomically from `stable` to `latest`!
        let mut slot_ring = [RootEntry {
            super_root: [0u8; 32],
            slot: 0,
        }; SLOT_RING_LEN];
        slot_ring[2] = RootEntry {
            super_root: latest_sr,
            slot: 105,
        };
        let mut epoch_ring = [RootEntry {
            super_root: [0u8; 32],
            slot: 0,
        }; EPOCH_RING_LEN];
        epoch_ring[1] = RootEntry {
            super_root: stable_sr,
            slot: 96,
        };
        let history = GlobalRootHistory {
            version: audren_core::PROTOCOL_VERSION,
            bump: 254,
            slot_cursor: 2,
            pool_id: 0,
            epoch_cursor: 1,
            slot_count: 3,
            epoch_count: 2,
            same_slot_bumped: false,
            latest_slot: 105,
            stable_epoch_id: 3,
            stable_slot: 96,
            epoch_interval: DEFAULT_ROOT_EPOCH_INTERVAL,
            group_roots: [fr_to_be_bytes(&zeros[19]); 4],
            latest_super_root: latest_sr,
            latest_lane_roots: latest_lr,
            latest_lane_counts: latest_counts,
            stable_super_root: stable_sr,
            stable_lane_roots: stable_lr,
            stable_lane_counts: stable_counts,
            slot_ring,
            epoch_ring,
        };

        // While prev_sealed_leaves is still intact, stable (ROOT_RING_EPOCH) succeeds directly!
        let note_a = store.notes[0].clone();
        let note_b = store.notes[1].clone();
        let (snap_direct, sr_direct, _) = store
            .build_witness_from_root_history(&note_a, &history)
            .unwrap();
        assert_eq!(snap_direct.ring_kind, ROOT_RING_EPOCH);
        assert_eq!(sr_direct, stable_sr_fr);

        // Now clear prev_sealed_leaves (simulating exact-256 / multi-page sync past page 0)
        store.lanes[0].prev_sealed_sub_seq = None;
        store.lanes[0].prev_sealed_leaves.clear();

        // Single-note fallback: stable lacks page 0 frontier -> seamlessly falls back to latest (ROOT_RING_SLOT)!
        let (snap_fb, sr_fb, path_fb) = store
            .build_witness_from_root_history(&note_a, &history)
            .unwrap();
        assert_eq!(snap_fb.ring_kind, ROOT_RING_SLOT);
        assert_eq!(snap_fb.ring_idx, 2);
        assert_eq!(sr_fb, latest_sr_fr);
        assert_eq!(path_fb.compute_root(page0_fr[10]), latest_sr_fr);

        // Multi-note fallback: BOTH notes share the exact same latest ROOT_RING_SLOT snapshot!
        let (snap_multi, sr_multi, paths_multi) = store
            .build_witnesses_from_root_history(&[&note_a, &note_b], &history)
            .unwrap();
        assert_eq!(snap_multi.ring_kind, ROOT_RING_SLOT);
        assert_eq!(snap_multi.ring_idx, 2);
        assert_eq!(sr_multi, latest_sr_fr);
        assert_eq!(paths_multi.len(), 2);
        assert_eq!(paths_multi[0].compute_root(page0_fr[10]), latest_sr_fr);
        assert_eq!(paths_multi[1].compute_root(page0_fr[200]), latest_sr_fr);

        // 3. When NEITHER stable nor latest can be built locally, return Err cleanly!
        let mut stale_store = store.clone();
        stale_store.lanes[0].finalized_subroots.clear();
        assert!(stale_store
            .build_witness_from_root_history(&note_a, &history)
            .is_err());
        assert!(stale_store
            .build_witnesses_from_root_history(&[&note_a, &note_b], &history)
            .is_err());
    }

    #[test]
    fn ingest_lane_pages_rejects_lagging_subtree_truncation_and_preserves_held_sealed_page() {
        use audren_circuits::merkle::zero_hashes_4ary;
        use audren_circuits::poseidon::poseidon4;
        use audren_core::LANE_DEPTH_4ARY;

        let alice = AudrenKeys::from_seed(&[0xe1u8; 32]);
        let fvk = alice.full_viewing_key();
        let sol_asset = derive_asset_id(&WSOL_MINT);

        let make_sub_page = |seq: u64, leaves: &[Fr]| -> Vec<u8> {
            let mut raw = vec![0u8; SUBTREE_PAGE_LEN];
            raw[0..8].copy_from_slice(&SUBTREE_MAGIC);
            raw[SB_OFF_COUNT..SB_OFF_COUNT + 2]
                .copy_from_slice(&(leaves.len() as u16).to_le_bytes());
            raw[SB_OFF_PAGE_SEQ..SB_OFF_PAGE_SEQ + 8].copy_from_slice(&seq.to_le_bytes());
            for (i, leaf) in leaves.iter().enumerate() {
                raw[SB_OFF_LEAVES + i * 32..SB_OFF_LEAVES + (i + 1) * 32]
                    .copy_from_slice(&fr_to_be_bytes(leaf));
            }
            raw
        };

        let zeros = zero_hashes_4ary();
        let make_lane0_snap = |leaves: &[Fr]| -> (RootSnapshotChoice, Fr) {
            let mut cur = compute_subtree_256_root(leaves, leaves.len());
            for &z in &zeros[SUBTREE_LEVELS_4ARY..LANE_DEPTH_4ARY] {
                cur = poseidon4(cur, z, z, z);
            }
            let mut lane_roots_fr = [zeros[LANE_DEPTH_4ARY]; NUM_LANES];
            lane_roots_fr[0] = cur;
            let super_root = compute_super_root_4ary(&lane_roots_fr);
            let mut lane_roots = [[0u8; 32]; NUM_LANES];
            for i in 0..NUM_LANES {
                lane_roots[i] = fr_to_be_bytes(&lane_roots_fr[i]);
            }
            let mut lane_counts = [0u64; NUM_LANES];
            lane_counts[0] = leaves.len() as u64;
            (
                RootSnapshotChoice {
                    ring_kind: ROOT_RING_EPOCH,
                    ring_idx: 0,
                    slot: 120,
                    super_root: fr_to_be_bytes(&super_root),
                    lane_roots,
                    lane_counts,
                },
                super_root,
            )
        };

        // --- Case 1: Lagging RPC SubtreePage #0 (count = 150) MUST NOT truncate live frontier_leaves (count = 200) ---
        let mut leaves_200 = Vec::with_capacity(200);
        let mut memo0_200 = make_memo_page(0, 0, MEMO_NOTES_PER_PAGE as u16);
        let mut memo1_200 = make_memo_page(0, 1, MEMO_NOTES_PER_PAGE as u16);
        let memo2_200 = make_memo_page(0, 2, (200 - 2 * MEMO_NOTES_PER_PAGE) as u16);
        for i in 0..200 {
            if i == 10 {
                let (tw, bl, m106) =
                    encrypt_note_memo(&alice.view_pk, [0xe2u8; 32], 1_500_000, &WSOL_MINT).unwrap();
                let cm = compute_note_commitment(
                    derive_stealth_owner(alice.spend_pk, tw),
                    sol_asset,
                    1_500_000,
                    bl,
                );
                leaves_200.push(cm);
                write_memo_slot(&mut memo0_200, i, &m106);
            } else if i == 180 {
                let (tw, bl, m106) =
                    encrypt_note_memo(&alice.view_pk, [0xe3u8; 32], 2_500_000, &WSOL_MINT).unwrap();
                let cm = compute_note_commitment(
                    derive_stealth_owner(alice.spend_pk, tw),
                    sol_asset,
                    2_500_000,
                    bl,
                );
                leaves_200.push(cm);
                write_memo_slot(&mut memo1_200, i - MEMO_NOTES_PER_PAGE, &m106);
            } else {
                leaves_200.push(Fr::from((i + 100) as u64));
            }
        }
        let sub0_200 = make_sub_page(0, &leaves_200);
        let sub0_150 = make_sub_page(0, &leaves_200[..150]);

        let mut live_store = CompactWalletStore::new(0, 0);
        assert_eq!(
            live_store
                .ingest_lane_pages(
                    &fvk,
                    0,
                    &[(0, &sub0_200)],
                    &[(0, &memo0_200), (1, &memo1_200), (2, &memo2_200)],
                    &[],
                )
                .unwrap(),
            2
        );
        assert_eq!(live_store.lanes[0].frontier_sub_seq, 0);
        assert_eq!(live_store.lanes[0].frontier_leaves.len(), 200);
        assert_eq!(live_store.lanes[0].next_memo_leaf, 200);

        // Lagging replica returns SubtreePage #0 with count = 150 -> MUST NOT truncate frontier_leaves
        assert_eq!(
            live_store
                .ingest_lane_pages(
                    &fvk,
                    0,
                    &[(0, &sub0_150)],
                    &[(0, &memo0_200), (1, &memo1_200)],
                    &[],
                )
                .unwrap(),
            0
        );
        assert_eq!(live_store.lanes[0].frontier_sub_seq, 0);
        assert_eq!(
            live_store.lanes[0].frontier_leaves.len(),
            200,
            "lagging SubtreePage #0 (count=150) must not truncate live frontier_leaves (count=200)"
        );

        let (snap_200, sr_200) = make_lane0_snap(&leaves_200);
        for (note, expected_cm) in [
            (&live_store.notes[0], leaves_200[10]),
            (&live_store.notes[1], leaves_200[180]),
        ] {
            let (sr, path) = live_store.build_witness_for_note(note, &snap_200).unwrap();
            assert_eq!(sr, sr_200);
            assert_eq!(path.compute_root(expected_cm), sr_200);
        }

        // --- Case 2: Lagging RPC SubtreePage #0 (count = 150) + MemoPage #1 MUST NOT destroy held 256-leaf sealed page
        //             and MUST verify memos beyond index 150 using the 256 held leaves ---
        let mut leaves_256 = Vec::with_capacity(SUBTREE_LEAVES);
        let memo0_256 = make_memo_page(0, 0, MEMO_NOTES_PER_PAGE as u16);
        let mut memo1_256 = make_memo_page(0, 1, MEMO_NOTES_PER_PAGE as u16);
        let mut memo2_256 = make_memo_page(0, 2, (SUBTREE_LEAVES - 2 * MEMO_NOTES_PER_PAGE) as u16);
        for i in 0..SUBTREE_LEAVES {
            if i == 160 {
                let (tw, bl, m106) =
                    encrypt_note_memo(&alice.view_pk, [0xe4u8; 32], 3_500_000, &WSOL_MINT).unwrap();
                let cm = compute_note_commitment(
                    derive_stealth_owner(alice.spend_pk, tw),
                    sol_asset,
                    3_500_000,
                    bl,
                );
                leaves_256.push(cm);
                write_memo_slot(&mut memo1_256, i - MEMO_NOTES_PER_PAGE, &m106);
            } else if i == 220 {
                let (tw, bl, m106) =
                    encrypt_note_memo(&alice.view_pk, [0xe5u8; 32], 4_500_000, &WSOL_MINT).unwrap();
                let cm = compute_note_commitment(
                    derive_stealth_owner(alice.spend_pk, tw),
                    sol_asset,
                    4_500_000,
                    bl,
                );
                leaves_256.push(cm);
                write_memo_slot(&mut memo2_256, i - 2 * MEMO_NOTES_PER_PAGE, &m106);
            } else {
                leaves_256.push(Fr::from((i + 300) as u64));
            }
        }
        let sub0_sealed = make_sub_page(0, &leaves_256);
        let sub0_lag150 = make_sub_page(0, &leaves_256[..150]);

        let mut held_store = CompactWalletStore::new(0, 0);
        // Batch 1: sealed SubtreePage #0 (256 leaves) + MemoPage #0 only (MemoPage #1,#2 lag)
        assert_eq!(
            held_store
                .ingest_lane_pages(&fvk, 0, &[(0, &sub0_sealed)], &[(0, &memo0_256)], &[])
                .unwrap(),
            0
        );
        assert_eq!(held_store.lanes[0].next_memo_leaf, 96);
        assert_eq!(held_store.lanes[0].frontier_sub_seq, 0);
        assert_eq!(held_store.lanes[0].frontier_leaves.len(), SUBTREE_LEAVES);

        // Batch 2: lagging SubtreePage #0 (count = 150) + MemoPage #1 (leaves 96..192, owned note at 160 > 150)
        assert_eq!(
            held_store
                .ingest_lane_pages(&fvk, 0, &[(0, &sub0_lag150)], &[(1, &memo1_256)], &[])
                .unwrap(),
            1
        );
        assert_eq!(held_store.lanes[0].next_memo_leaf, 192);
        assert_eq!(held_store.lanes[0].frontier_sub_seq, 0);
        assert_eq!(
            held_store.lanes[0].frontier_leaves.len(),
            SUBTREE_LEAVES,
            "lagging SubtreePage #0 (count=150) must not destroy held 256-leaf sealed page"
        );
        assert_eq!(held_store.notes.len(), 1);
        assert_eq!(held_store.notes[0].leaf_index, 160);
        assert_eq!(held_store.notes[0].amount, 3_500_000);
        assert!(held_store.notes[0].frozen_intra_siblings.is_some());

        // Batch 3: lagging SubtreePage #0 (count = 150) + MemoPage #2 (leaves 192..256, owned note at 220)
        // finishes page 0 cleanly, freezes note 220, promotes page 0 to prev_sealed, and advances frontier_sub_seq -> 1!
        assert_eq!(
            held_store
                .ingest_lane_pages(&fvk, 0, &[(0, &sub0_lag150)], &[(2, &memo2_256)], &[])
                .unwrap(),
            1
        );
        assert_eq!(held_store.lanes[0].next_memo_leaf, 256);
        assert_eq!(held_store.lanes[0].frontier_sub_seq, 1);
        assert!(held_store.lanes[0].frontier_leaves.is_empty());
        assert_eq!(held_store.lanes[0].prev_sealed_sub_seq, Some(0));
        assert_eq!(held_store.lanes[0].prev_sealed_leaves.len(), SUBTREE_LEAVES);
        assert_eq!(held_store.notes.len(), 2);
        assert_eq!(held_store.notes[1].leaf_index, 220);
        assert!(held_store.notes[1].frozen_intra_siblings.is_some());

        // Witnesses for both notes against count = 256 snapshot verify cleanly!
        let (snap_256, sr_256) = make_lane0_snap(&leaves_256);
        for (note, expected_cm) in [
            (&held_store.notes[0], leaves_256[160]),
            (&held_store.notes[1], leaves_256[220]),
        ] {
            let (sr, path) = held_store.build_witness_for_note(note, &snap_256).unwrap();
            assert_eq!(sr, sr_256);
            assert_eq!(path.compute_root(expected_cm), sr_256);
        }

        // Extra guard: stale sealed SubtreePage #0 must not regress frontier_sub_seq = 1 when memo_sub_seq = 0
        let mut ahead_store = CompactWalletStore::new(0, 0);
        ahead_store.lanes[0].next_memo_leaf = 96;
        ahead_store.lanes[0].frontier_sub_seq = 1;
        ahead_store.lanes[0].frontier_leaves = vec![[1u8; 32]; 5];
        ahead_store
            .ingest_lane_pages(&fvk, 0, &[(0, &sub0_sealed)], &[], &[])
            .unwrap();
        assert_eq!(ahead_store.lanes[0].frontier_sub_seq, 1);
        assert_eq!(ahead_store.lanes[0].frontier_leaves.len(), 5);

        // Extra guard: duplicate same-seq MemoPage in one batch keeps the fuller count (monotonic)
        let memo1_lag10 = make_memo_page(0, 1, 10);
        let mut dup_memo_store = CompactWalletStore::new(0, 0);
        let found_dup_memo = dup_memo_store
            .ingest_lane_pages(
                &fvk,
                0,
                &[(0, &sub0_200)],
                &[
                    (0, &memo0_200),
                    (1, &memo1_200),   // fuller (96 entries, owns leaf 180)
                    (1, &memo1_lag10), // lagging duplicate (10 entries) MUST NOT overwrite fuller copy
                    (2, &memo2_200),
                ],
                &[],
            )
            .unwrap();
        assert_eq!(found_dup_memo, 2);
        assert_eq!(dup_memo_store.lanes[0].next_memo_leaf, 200);
        assert_eq!(dup_memo_store.notes.len(), 2);
        assert_eq!(dup_memo_store.notes[1].leaf_index, 180);
    }

    #[test]
    fn store_rejects_sparse_subroot_gaps_nullifier_gaps_duplicate_notes_and_noncanonical_json() {
        let keys = AudrenKeys::from_seed(&[0x55u8; 32]);
        let fvk = keys.full_viewing_key();

        let make_sr_page = |lane_id: u8, seq: u64, roots: &[[u8; 32]]| -> Vec<u8> {
            let mut raw = vec![0u8; SUBROOT_PAGE_LEN];
            raw[0..8].copy_from_slice(&SUBROOT_MAGIC);
            raw[SR_OFF_LANE_ID] = lane_id;
            raw[SR_OFF_COUNT..SR_OFF_COUNT + 2].copy_from_slice(&(roots.len() as u16).to_le_bytes());
            raw[SR_OFF_ROOT_PAGE_SEQ..SR_OFF_ROOT_PAGE_SEQ + 8].copy_from_slice(&seq.to_le_bytes());
            for (i, r) in roots.iter().enumerate() {
                raw[SR_OFF_ROOTS + i * 32..SR_OFF_ROOTS + (i + 1) * 32].copy_from_slice(r);
            }
            raw
        };
        let make_nf = |lane_id: u8, seq: u64, count: u16, first_pref: Option<[u8; NF_PREFIX_LEN]>| {
            let mut raw = vec![0u8; NF_PAGE_LEN];
            raw[0..8].copy_from_slice(&NF_PAGE_MAGIC);
            raw[NF_OFF_LANE_ID] = lane_id;
            raw[NF_OFF_COUNT..NF_OFF_COUNT + 2].copy_from_slice(&count.to_le_bytes());
            raw[NF_OFF_PAGE_SEQ..NF_OFF_PAGE_SEQ + 8].copy_from_slice(&seq.to_le_bytes());
            if let Some(p) = first_pref {
                raw[NF_OFF_PREFIXES..NF_OFF_PREFIXES + NF_PREFIX_LEN].copy_from_slice(&p);
            }
            raw
        };

        // 1. SubtreeRootPage sparse gap / amplification attack MUST fail atomically with zero mutation
        let mut sr_store = CompactWalletStore::new(0, 0);
        let sr0 = make_sr_page(0, 0, &[fr_to_be_bytes(&Fr::from(1u64)); 10]);
        let sr2 = make_sr_page(0, 2, &[fr_to_be_bytes(&Fr::from(2u64)); 1]);
        assert!(sr_store
            .ingest_subroot_pages(0, &[(0, &sr0), (2, &sr2)], None)
            .is_err());
        assert!(
            sr_store.lanes[0].finalized_subroots.is_empty(),
            "failed ingest_subroot_pages batch must not partially mutate finalized_subroots"
        );
        // Contiguous full page 0 (300) + page 1 (2) in reverse order succeeds cleanly
        let sr0_full = make_sr_page(0, 0, &[fr_to_be_bytes(&Fr::from(1u64)); SUBROOTS_PER_PAGE]);
        let sr1 = make_sr_page(0, 1, &[fr_to_be_bytes(&Fr::from(2u64)); 2]);
        sr_store
            .ingest_subroot_pages(0, &[(1, &sr1), (0, &sr0_full)], None)
            .unwrap();
        assert_eq!(sr_store.lanes[0].finalized_subroots.len(), SUBROOTS_PER_PAGE + 2);

        // 2. NullifierPage gapped batch (partial page 0 + page 1) MUST fail atomically without
        //    marking notes spent or advancing next_nf_index
        let mut nf_store = CompactWalletStore::new(0, 0);
        let (tw, bl, _memo) =
            encrypt_note_memo(&keys.view_pk, [0x44u8; 32], 10_000, &audren_core::WSOL_MINT)
                .unwrap();
        let stealth = fvk.stealth_owner(tw).unwrap();
        let cm = compute_note_commitment(stealth, derive_asset_id(&audren_core::WSOL_MINT), 10_000, bl);
        let cm_be = fr_to_be_bytes(&cm);
        let dec = DecryptedMemo {
            tweak: tw,
            blinding: bl,
            amount: 10_000,
            mint: audren_core::WSOL_MINT,
            memo_version: 1,
            memo_flags: 0,
            payment_id: [0u8; MEMO_PAYMENT_ID_LEN],
            is_dynamic: false,
        };
        nf_store.record_verified_memo(&fvk, 0, 0, &dec, cm_be).unwrap();
        let own_pref: [u8; NF_PREFIX_LEN] = nf_store.notes[0].nullifier[0..NF_PREFIX_LEN]
            .try_into()
            .unwrap();
        let nf0_partial = make_nf(0, 0, 1, Some(own_pref));
        let nf1 = make_nf(0, 1, 1, None);
        assert!(nf_store
            .ingest_nullifier_pages(0, &[(0, &nf0_partial), (1, &nf1)], None)
            .is_err());
        assert_eq!(nf_store.lanes[0].next_nf_index, 0);
        assert!(!nf_store.notes[0].spent);

        // 3. from_json_bytes rejects duplicate (lane_id, leaf_index) notes and non-canonical Fr
        let mut dup_store = nf_store.clone();
        dup_store.notes.push(dup_store.notes[0].clone());
        let dup_json = dup_store.to_json_bytes().unwrap();
        assert!(CompactWalletStore::from_json_bytes(&dup_json).is_err());

        let mut bad_fr_store = nf_store.clone();
        bad_fr_store.notes[0].commitment = audren_core::BN254_FR_MODULUS_BE;
        let bad_fr_json = bad_fr_store.to_json_bytes().unwrap();
        assert!(matches!(
            CompactWalletStore::from_json_bytes(&bad_fr_json),
            Err(ClientError::InvalidFieldElement)
        ));

        let mut bad_sr_store = nf_store.clone();
        bad_sr_store.lanes[0]
            .finalized_subroots
            .push(audren_core::BN254_FR_MODULUS_BE);
        let bad_sr_json = bad_sr_store.to_json_bytes().unwrap();
        assert!(matches!(
            CompactWalletStore::from_json_bytes(&bad_sr_json),
            Err(ClientError::InvalidFieldElement)
        ));

        // 4. ingest_lane_pages rejects unsealed non-canonical Fr leaf & is 100% atomic on
        //    gapped sealed SubtreePage or gapped NullifierPage (zero partial state mutation)
        let mut unsealed_bad = vec![0u8; SUBTREE_PAGE_LEN];
        unsealed_bad[0..8].copy_from_slice(&SUBTREE_MAGIC);
        unsealed_bad[SB_OFF_COUNT..SB_OFF_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
        unsealed_bad[SB_OFF_LEAVES..SB_OFF_LEAVES + 32]
            .copy_from_slice(&audren_core::BN254_FR_MODULUS_BE);
        let mut atomic_store = CompactWalletStore::new(0, 0);
        assert!(matches!(
            atomic_store.ingest_lane_pages(&fvk, 0, &[(0, &unsealed_bad)], &[], &[]),
            Err(ClientError::InvalidFieldElement)
        ));
        assert!(atomic_store.lanes[0].frontier_leaves.is_empty());

        let mut sealed0 = vec![0u8; SUBTREE_PAGE_LEN];
        sealed0[0..8].copy_from_slice(&SUBTREE_MAGIC);
        sealed0[SB_OFF_COUNT..SB_OFF_COUNT + 2]
            .copy_from_slice(&(SUBTREE_LEAVES as u16).to_le_bytes());
        sealed0[SB_OFF_LEAVES..SB_OFF_LEAVES + 32].copy_from_slice(&cm_be);
        let mut sealed2 = sealed0.clone();
        sealed2[SB_OFF_PAGE_SEQ..SB_OFF_PAGE_SEQ + 8].copy_from_slice(&2u64.to_le_bytes());
        let mut memo0 = vec![0u8; MEMO_PAGE_LEN];
        memo0[0..8].copy_from_slice(&MEMO_MAGIC);
        memo0[MM_OFF_COUNT..MM_OFF_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
        memo0[MM_OFF_VIEW_TAGS..MM_OFF_VIEW_TAGS + 2].copy_from_slice(&_memo[0..2]);
        memo0[MM_OFF_EPHEMERAL_PKS..MM_OFF_EPHEMERAL_PKS + 32].copy_from_slice(&_memo[2..34]);
        memo0[MM_OFF_CIPHERTEXTS..MM_OFF_CIPHERTEXTS + MEMO_CT_LEN]
            .copy_from_slice(&_memo[34..MEMO_ENTRY_WIRE_LEN]);
        assert!(atomic_store
            .ingest_lane_pages(&fvk, 0, &[(0, &sealed0), (2, &sealed2)], &[(0, &memo0)], &[])
            .is_err());
        assert_eq!(atomic_store.lanes[0].next_memo_leaf, 0);
        assert!(atomic_store.notes.is_empty());
        assert!(atomic_store.lanes[0].finalized_subroots.is_empty());

        assert!(atomic_store
            .ingest_lane_pages(&fvk, 0, &[(0, &sealed0)], &[(0, &memo0)], &[(1, &nf1)])
            .is_err());
        assert_eq!(atomic_store.lanes[0].next_memo_leaf, 0);
        assert!(atomic_store.notes.is_empty());
        assert!(atomic_store.lanes[0].finalized_subroots.is_empty());
        assert_eq!(atomic_store.lanes[0].next_nf_index, 0);

        // 5. Duplicate root_page_seq in ingest_subroot_pages: consistent shorter prefix keeps
        //    fuller copy, while conflicting duplicate entry MUST be rejected atomically!
        let mut dup_sr_store = CompactWalletStore::new(0, 0);
        let sr0_short_consistent = make_sr_page(0, 0, &[fr_to_be_bytes(&Fr::from(1u64)); 1]);
        let sr0_short_conflict = make_sr_page(0, 0, &[fr_to_be_bytes(&Fr::from(99u64)); 1]);
        assert!(
            dup_sr_store
                .ingest_subroot_pages(0, &[(0, &sr0_full), (0, &sr0_short_conflict)], None)
                .is_err(),
            "conflicting duplicate SubtreeRootPage entries must be rejected"
        );
        assert!(dup_sr_store.lanes[0].finalized_subroots.is_empty());
        dup_sr_store
            .ingest_subroot_pages(0, &[(0, &sr0_full), (0, &sr0_short_consistent)], None)
            .unwrap();
        assert_eq!(dup_sr_store.lanes[0].finalized_subroots.len(), SUBROOTS_PER_PAGE);
        assert_eq!(
            dup_sr_store.lanes[0].finalized_subroots[0],
            fr_to_be_bytes(&Fr::from(1u64))
        );

        // 6. Round-2 Audit Finding #4: ingest_subroot_pages validates canonical Fr on ALL 0..cnt
        //    entries of EVERY input page (including discarded shorter duplicates and trailing
        //    entries past `finalized_count`) with zero store mutation on error.
        let sr0_bad_short = make_sr_page(0, 0, &[audren_core::BN254_FR_MODULUS_BE]);
        let sr0_trailing_bad = make_sr_page(
            0,
            0,
            &[
                fr_to_be_bytes(&Fr::from(7u64)),
                audren_core::BN254_FR_MODULUS_BE,
            ],
        );
        let mut strict_sr_store = CompactWalletStore::new(0, 0);
        assert!(matches!(
            strict_sr_store.ingest_subroot_pages(0, &[(0, &sr0_bad_short), (0, &sr0_full)], None),
            Err(ClientError::InvalidFieldElement)
        ));
        assert!(strict_sr_store.lanes[0].finalized_subroots.is_empty());
        assert!(matches!(
            strict_sr_store.ingest_subroot_pages(0, &[(0, &sr0_full), (0, &sr0_bad_short)], None),
            Err(ClientError::InvalidFieldElement)
        ));
        assert!(strict_sr_store.lanes[0].finalized_subroots.is_empty());
        assert!(matches!(
            strict_sr_store.ingest_subroot_pages(0, &[(0, &sr0_trailing_bad)], Some(1)),
            Err(ClientError::InvalidFieldElement)
        ));
        assert!(strict_sr_store.lanes[0].finalized_subroots.is_empty());
    }

    #[test]
    fn compact_store_bidirectional_ts_camel_case_json_roundtrip() {
        let mut ts_json = String::new();
        let big_u64 = 18_446_744_073_709_551_615u64 - 7; // > 2^53
        let global_leaf = (2u64 << 36) | 41u64;
        let ts_lanes: Vec<String> = (0..NUM_LANES)
            .map(|lane_id| {
                if lane_id == 2 {
                    format!(
                        r#"{{"finalizedSubroots":["{}"],"frontierSubSeq":"1","frontierLeaves":["{}"],"prevSealedSubSeq":null,"prevSealedLeaves":[],"nextMemoLeaf":"42","nextNfIndex":"17"}}"#,
                        "1a".repeat(32),
                        "1b".repeat(32)
                    )
                } else {
                    r#"{"finalizedSubroots":[],"frontierSubSeq":"0","frontierLeaves":[],"prevSealedSubSeq":null,"prevSealedLeaves":[],"nextMemoLeaf":"0","nextNfIndex":"0"}"#
                        .to_string()
                }
            })
            .collect();
        ts_json.push_str(&format!(
            r#"{{"poolId":0,"birthdaySlot":"{big_u64}","lanes":[{}],"notes":[{{"poolId":0,"laneId":2,"leafIndex":"41","globalLeafIndex":"{global_leaf}","mint":"{}","amount":"{big_u64}","tweak":"{}","blinding":"{}","stealthOwner":"{}","commitment":"{}","nullifier":"{}","paymentId":"{}","isDynamic":false,"spent":false,"frozenIntraSiblings":[["{}","{}","{}"],["{}","{}","{}"],["{}","{}","{}"],["{}","{}","{}"]],"frozenIntraPositions":[1,2,0,3]}}]}}"#,
            ts_lanes.join(","),
            "11".repeat(32),
            "12".repeat(32),
            "13".repeat(32),
            "14".repeat(32),
            "15".repeat(32),
            "16".repeat(32),
            "44".repeat(14),
            "01".repeat(32),
            "02".repeat(32),
            "03".repeat(32),
            "04".repeat(32),
            "05".repeat(32),
            "06".repeat(32),
            "07".repeat(32),
            "08".repeat(32),
            "09".repeat(32),
            "0a".repeat(32),
            "0b".repeat(32),
            "0c".repeat(32),
        ));

        let parsed: CompactWalletStore =
            serde_json::from_str(&ts_json).expect("Rust must deserialize TS camelCase/hex/string JSON");
        assert_eq!(parsed.pool_id, 0);
        assert_eq!(parsed.birthday_slot, big_u64);
        assert_eq!(parsed.lanes[2].next_memo_leaf, 42);
        assert_eq!(parsed.lanes[2].next_nf_index, 17);
        assert_eq!(parsed.lanes[2].finalized_subroots, vec![[0x1au8; 32]]);
        assert_eq!(parsed.lanes[2].frontier_leaves, vec![[0x1bu8; 32]]);
        assert_eq!(parsed.notes.len(), 1);
        assert_eq!(parsed.notes[0].pool_id, 0);
        assert_eq!(parsed.notes[0].global_leaf_index, global_leaf);
        assert_eq!(parsed.notes[0].amount, big_u64);
        assert_eq!(parsed.notes[0].mint, [0x11u8; 32]);
        assert_eq!(parsed.notes[0].stealth_owner, [0x14u8; 32]);
        assert_eq!(parsed.notes[0].payment_id, [0x44u8; 14]);
        assert_eq!(parsed.notes[0].frozen_intra_positions, Some([1, 2, 0, 3]));
        assert_eq!(
            parsed.notes[0].frozen_intra_siblings.unwrap()[3][2],
            [0x0cu8; 32]
        );

        // Round-trip Rust serde_json output back into Rust cleanly as well.
        let rust_json = serde_json::to_string(&parsed).unwrap();
        let reparsed: CompactWalletStore = serde_json::from_str(&rust_json).unwrap();
        assert_eq!(reparsed.birthday_slot, big_u64);
        assert_eq!(reparsed.notes[0].amount, big_u64);
        assert_eq!(reparsed.notes[0].frozen_intra_siblings, parsed.notes[0].frozen_intra_siblings);
    }
}
