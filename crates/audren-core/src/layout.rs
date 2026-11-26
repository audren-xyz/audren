//! Fixed-size, zero-copy account layouts for Audren (all `<= 10,240 B` CPI allocation cap,
//! zero `realloc`, SIMD-0460 compliant).

use crate::{
    Bytes32, EPOCH_RING_LEN, LANE_DEPTH_4ARY, MAX_ROOT_EPOCH_INTERVAL, NUM_LANES,
    PROTOCOL_VERSION, ROOT_ENTRY_LEN, SLOT_RING_LEN,
};
#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
use crate::{ROOT_RING_EPOCH, ROOT_RING_SLOT, ZERO_HASHES_4ARY};
#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
use alloc::boxed::Box;

/// Solana maximum CPI account creation size (`10 KiB`).
pub const MAX_CPI_ACCOUNT_ALLOC: usize = 10_240;

/// Maximum note commitments per lane (`4^18 = 2^36 = 68,719,476,736`).
pub const MAX_LEAVES_PER_LANE: u64 = 1u64 << (LANE_DEPTH_4ARY * 2);

const _: () = assert!(MAX_LEAVES_PER_LANE == (1u64 << 36));

/// 4^4 = 256 note commitments per `SubtreePage`.
pub const SUBTREE_LEAVES: usize = 256;

/// 300 finalized 256-leaf subtree roots per `SubtreeRootPage`.
pub const SUBROOTS_PER_PAGE: usize = 300;

/// 96 versioned `106 B` SoA note memos per `MemoPage` (`64 + 96 * 106 = 10,240 B == MAX_CPI_ACCOUNT_ALLOC`).
pub const MEMO_NOTES_PER_PAGE: usize = 96;
pub const MEMO_PLAINTEXT_LEN: usize = 56;
pub const MEMO_VERSION_V1: u8 = 1;
pub const MEMO_PAYMENT_ID_LEN: usize = 14;
pub const MEMO_CT_LEN: usize = 72; // 56 B plaintext + 16 B Poly1305 tag
pub const MEMO_ENTRY_WIRE_LEN: usize = 2 + 32 + MEMO_CT_LEN; // 106 B
pub const DYN_MEMO_HEAD_LEN: usize = 2 + 32; // 34 B

/// 600 x 16-byte (128-bit) nullifier prefixes per `NullifierPage` (`64 + 600 * 16 = 9,664 B`).
pub const NF_PREFIX_LEN: usize = 16;
pub const NF_PER_PAGE: usize = 600;

/// 8-byte ASCII account magic headers (`AUD1*`).
pub const POOL_MAGIC: [u8; 8] = *b"AUD1PL01";
pub const LANE_RENT_MAGIC: [u8; 8] = *b"AUD1RV01";
pub const LANE_MAGIC: [u8; 8] = *b"AUD1LN01";
pub const SUBTREE_MAGIC: [u8; 8] = *b"AUD1SB01";
pub const SUBROOT_MAGIC: [u8; 8] = *b"AUD1SR01";
pub const MEMO_MAGIC: [u8; 8] = *b"AUD1MM01";
pub const NF_PAGE_MAGIC: [u8; 8] = *b"AUD1NF01";
pub const ROOTS_MAGIC: [u8; 8] = *b"AUD1RT01";
pub const DYN_MEMO_MAGIC: [u8; 8] = *b"AUD1DYN1";

/// Fixed account byte lengths (all `<= 10,240 B`, zero `realloc`).
pub const POOL_STATE_LEN: usize = 128;
pub const SENTINEL_LEN: usize = 16;
pub const LANE_STATE_LEN: usize = 64 + 32 + (LANE_DEPTH_4ARY * 3 * 32); // 1,824 B
pub const SUBTREE_PAGE_LEN: usize = 64 + (SUBTREE_LEAVES * 32); // 8,256 B
pub const SUBROOT_PAGE_LEN: usize = 64 + (SUBROOTS_PER_PAGE * 32); // 9,664 B
pub const MEMO_PAGE_LEN: usize = 64 + (MEMO_NOTES_PER_PAGE * MEMO_ENTRY_WIRE_LEN); // 10,240 B
pub const NF_PAGE_LEN: usize = 64 + (NF_PER_PAGE * NF_PREFIX_LEN); // 9,664 B
pub const ROOT_SNAPSHOT_LEN: usize = 32 + (NUM_LANES * 32) + (NUM_LANES * 8); // 672 B
pub const ROOT_HISTORY_LEN: usize = 192
    + (2 * ROOT_SNAPSHOT_LEN)
    + (SLOT_RING_LEN * ROOT_ENTRY_LEN)
    + (EPOCH_RING_LEN * ROOT_ENTRY_LEN); // 10,216 B

const _: () = assert!(POOL_STATE_LEN == 128);
const _: () = assert!(LANE_STATE_LEN == 1_824);
const _: () = assert!(SUBTREE_PAGE_LEN == 8_256 && SUBTREE_PAGE_LEN <= MAX_CPI_ACCOUNT_ALLOC);
const _: () = assert!(SUBROOT_PAGE_LEN == 9_664 && SUBROOT_PAGE_LEN <= MAX_CPI_ACCOUNT_ALLOC);
const _: () = assert!(MEMO_PAGE_LEN == 10_240 && MEMO_PAGE_LEN <= MAX_CPI_ACCOUNT_ALLOC);
const _: () = assert!(NF_PAGE_LEN == 9_664 && NF_PAGE_LEN <= MAX_CPI_ACCOUNT_ALLOC);
const _: () = assert!(ROOT_SNAPSHOT_LEN == 672);
const _: () = assert!(ROOT_HISTORY_LEN == 10_216 && ROOT_HISTORY_LEN <= MAX_CPI_ACCOUNT_ALLOC);

// --- PoolState offsets (128 B) ---
pub const PL_OFF_MAGIC: usize = 0; // 8
pub const PL_OFF_VERSION: usize = 8; // 1
pub const PL_OFF_BUMP: usize = 9; // 1
pub const PL_OFF_PAUSED: usize = 10; // 1
pub const PL_OFF_ACTIVE_LANES: usize = 11; // 1
pub const PL_OFF_POOL_ID: usize = 12; // 4 (u32)
pub const PL_OFF_ROOT_EPOCH_INTERVAL: usize = 16; // 8 (u64)
pub const PL_OFF_RESERVED_24: usize = 24; // 8 ([0; 8] reserved)
pub const PL_OFF_AUTHORITY: usize = 32; // 32
pub const PL_OFF_VAULT_AUTH_BUMP: usize = 64; // 1 (65..72 reserved [0; 7])
pub const PL_OFF_NOTE_RENT_FEE: usize = 72; // 8 (u64)
pub const PL_OFF_NF_RENT_FEE: usize = 80; // 8 (u64)
pub const PL_OFF_PENDING_AUTHORITY: usize = 88; // 32 (120..128 reserved [0; 8])

// --- LaneRentVault sentinel offsets (16 B) ---
pub const SN_OFF_MAGIC: usize = 0; // 8
pub const SN_OFF_POOL_ID: usize = 8; // 4
pub const SN_OFF_LANE_ID: usize = 12; // 1
pub const SN_OFF_BUMP: usize = 13; // 1

// --- LaneTreeState offsets (1,824 B) ---
pub const LN_OFF_MAGIC: usize = 0; // 8
pub const LN_OFF_VERSION: usize = 8; // 1
pub const LN_OFF_LANE_ID: usize = 9; // 1
pub const LN_OFF_BUMP: usize = 10; // 1
pub const LN_OFF_RENT_BUMP: usize = 11; // 1
pub const LN_OFF_POOL_ID: usize = 12; // 4 (u32)
pub const LN_OFF_NEXT_LEAF: usize = 16; // 8 (u64)
pub const LN_OFF_NF_COUNT: usize = 24; // 8 (u64)
pub const LN_OFF_CURRENT_ROOT: usize = 64; // 32
pub const LN_OFF_FRONTIER: usize = 96; // 18 * 3 * 32 = 1,728 B

// --- SubtreePage offsets (8,256 B) ---
pub const SB_OFF_MAGIC: usize = 0; // 8
pub const SB_OFF_LANE_ID: usize = 8; // 1
pub const SB_OFF_BUMP: usize = 9; // 1
pub const SB_OFF_COUNT: usize = 10; // 2 (u16: 0..=256)
pub const SB_OFF_POOL_ID: usize = 12; // 4 (u32)
pub const SB_OFF_PAGE_SEQ: usize = 16; // 8 (u64)
pub const SB_OFF_LEAVES: usize = 64; // 256 * 32 = 8,192 B

// --- SubtreeRootPage offsets (9,664 B) ---
pub const SR_OFF_MAGIC: usize = 0; // 8
pub const SR_OFF_LANE_ID: usize = 8; // 1
pub const SR_OFF_BUMP: usize = 9; // 1
pub const SR_OFF_COUNT: usize = 10; // 2 (u16: 0..=300)
pub const SR_OFF_POOL_ID: usize = 12; // 4 (u32)
pub const SR_OFF_ROOT_PAGE_SEQ: usize = 16; // 8 (u64)
pub const SR_OFF_ROOTS: usize = 64; // 300 * 32 = 9,600 B

// --- MemoPage offsets (10,240 B; Structure-of-Arrays) ---
pub const MM_OFF_MAGIC: usize = 0; // 8
pub const MM_OFF_LANE_ID: usize = 8; // 1
pub const MM_OFF_BUMP: usize = 9; // 1
pub const MM_OFF_COUNT: usize = 10; // 2 (u16: 0..=96)
pub const MM_OFF_POOL_ID: usize = 12; // 4 (u32)
pub const MM_OFF_PAGE_SEQ: usize = 16; // 8 (u64)
pub const MM_OFF_CREATED_SLOT: usize = 24; // 8 (u64)
pub const MM_OFF_CLOSED_SLOT: usize = 32; // 8 (u64)
pub const MM_OFF_VIEW_TAGS: usize = 64; // 96 * 2 = 192 B (64..256)
pub const MM_OFF_EPHEMERAL_PKS: usize = 64 + MEMO_NOTES_PER_PAGE * 2; // 256; 96 * 32 = 3,072 B (256..3,328)
pub const MM_OFF_CIPHERTEXTS: usize = MM_OFF_EPHEMERAL_PKS + MEMO_NOTES_PER_PAGE * 32; // 3,328; 96 * 72 = 6,912 B (3,328..10,240)

const _: () = assert!(MM_OFF_EPHEMERAL_PKS == 256);
const _: () = assert!(MM_OFF_CIPHERTEXTS == 3_328);
const _: () = assert!(MM_OFF_CIPHERTEXTS + MEMO_NOTES_PER_PAGE * MEMO_CT_LEN == MEMO_PAGE_LEN);

// --- NullifierPage offsets (9,664 B) ---
pub const NF_OFF_MAGIC: usize = 0; // 8
pub const NF_OFF_LANE_ID: usize = 8; // 1
pub const NF_OFF_BUMP: usize = 9; // 1
pub const NF_OFF_COUNT: usize = 10; // 2 (u16: 0..=600)
pub const NF_OFF_POOL_ID: usize = 12; // 4 (u32)
pub const NF_OFF_PAGE_SEQ: usize = 16; // 8 (u64)
pub const NF_OFF_CREATED_SLOT: usize = 24; // 8 (u64)
pub const NF_OFF_CLOSED_SLOT: usize = 32; // 8 (u64)
pub const NF_OFF_PREFIXES: usize = 64; // 600 * 16 = 9,600 B

// --- GlobalRootHistory offsets (10,216 B <= 10,240 B CPI cap) ---
pub const RT_OFF_MAGIC: usize = 0; // 8
pub const RT_OFF_VERSION: usize = 8; // 1
pub const RT_OFF_BUMP: usize = 9; // 1
pub const RT_OFF_SLOT_CURSOR: usize = 10; // 2 (u16: 0..128)
pub const RT_OFF_POOL_ID: usize = 12; // 4 (u32)
pub const RT_OFF_EPOCH_CURSOR: usize = 16; // 2 (u16: 0..89)
pub const RT_OFF_SLOT_COUNT: usize = 18; // 2 (u16: 1..=128)
pub const RT_OFF_EPOCH_COUNT: usize = 20; // 2 (u16: 1..=89)
pub const RT_OFF_SAME_SLOT_BUMPED: usize = 22; // 1 (u8: 0 or 1; byte 23 _pad = 0)
pub const RT_OFF_LATEST_SLOT: usize = 24; // 8 (u64)
pub const RT_OFF_STABLE_EPOCH_ID: usize = 32; // 8 (u64)
pub const RT_OFF_STABLE_SLOT: usize = 40; // 8 (u64)
pub const RT_OFF_EPOCH_INTERVAL: usize = 48; // 8 (u64: 1..=256)
// bytes 56..64: _reserved ([0; 8])
pub const RT_OFF_GROUP_ROOTS: usize = 64; // 4 * 32 = 128 B (64..192)
pub const RT_OFF_LATEST_SUPER_ROOT: usize = 192; // 32 B
pub const RT_OFF_LATEST_LANE_ROOTS: usize = 224; // 16 * 32 = 512 B
pub const RT_OFF_LATEST_LANE_COUNTS: usize = 736; // 16 * 8 = 128 B (ends 864)
pub const RT_OFF_STABLE_SUPER_ROOT: usize = 864; // 32 B
pub const RT_OFF_STABLE_LANE_ROOTS: usize = 896; // 16 * 32 = 512 B
pub const RT_OFF_STABLE_LANE_COUNTS: usize = 1_408; // 16 * 8 = 128 B (ends 1,536)
pub const RT_OFF_SLOT_RING: usize = 1_536; // 128 * 40 = 5,120 B (1,536..6,656)
pub const RT_OFF_EPOCH_RING: usize = 6_656; // 89 * 40 = 3,560 B (6,656..10,216)

const _: () = assert!(RT_OFF_GROUP_ROOTS + 4 * 32 == RT_OFF_LATEST_SUPER_ROOT);
const _: () = assert!(RT_OFF_LATEST_SUPER_ROOT + 32 == RT_OFF_LATEST_LANE_ROOTS);
const _: () = assert!(RT_OFF_LATEST_LANE_ROOTS + NUM_LANES * 32 == RT_OFF_LATEST_LANE_COUNTS);
const _: () = assert!(RT_OFF_LATEST_LANE_COUNTS + NUM_LANES * 8 == RT_OFF_STABLE_SUPER_ROOT);
const _: () = assert!(RT_OFF_STABLE_SUPER_ROOT - RT_OFF_LATEST_SUPER_ROOT == ROOT_SNAPSHOT_LEN);
const _: () = assert!(RT_OFF_STABLE_SUPER_ROOT + 32 == RT_OFF_STABLE_LANE_ROOTS);
const _: () = assert!(RT_OFF_STABLE_LANE_ROOTS + NUM_LANES * 32 == RT_OFF_STABLE_LANE_COUNTS);
const _: () = assert!(RT_OFF_STABLE_LANE_COUNTS + NUM_LANES * 8 == RT_OFF_SLOT_RING);
const _: () = assert!(RT_OFF_SLOT_RING - RT_OFF_STABLE_SUPER_ROOT == ROOT_SNAPSHOT_LEN);
const _: () = assert!(RT_OFF_SLOT_RING + SLOT_RING_LEN * ROOT_ENTRY_LEN == RT_OFF_EPOCH_RING);
const _: () = assert!(RT_OFF_EPOCH_RING + EPOCH_RING_LEN * ROOT_ENTRY_LEN == ROOT_HISTORY_LEN);

/// Little-endian integer readers (zero-copy, `no_std`).
#[inline(always)]
pub fn read_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

#[inline(always)]
pub fn read_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

#[inline(always)]
pub fn read_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}

#[inline(always)]
pub fn read_32(b: &[u8], off: usize) -> Bytes32 {
    let mut out = [0u8; 32];
    out.copy_from_slice(&b[off..off + 32]);
    out
}

/// Decoded `PoolState` (`128 B`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolState {
    pub version: u8,
    pub bump: u8,
    pub paused: bool,
    pub active_lanes: u8,
    pub pool_id: u32,
    pub root_epoch_interval: u64,
    pub authority: Bytes32,
    pub vault_auth_bump: u8,
    pub note_rent_fee: u64,
    pub nf_rent_fee: u64,
    pub pending_authority: Bytes32,
}

impl PoolState {
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() != POOL_STATE_LEN || data[PL_OFF_MAGIC..PL_OFF_MAGIC + 8] != POOL_MAGIC {
            return None;
        }
        let version = data[PL_OFF_VERSION];
        let paused_raw = data[PL_OFF_PAUSED];
        let active_lanes = data[PL_OFF_ACTIVE_LANES];
        let root_epoch_interval = read_u64(data, PL_OFF_ROOT_EPOCH_INTERVAL);
        if version != PROTOCOL_VERSION
            || paused_raw > 1
            || (active_lanes as usize) > NUM_LANES
            || !(1..=MAX_ROOT_EPOCH_INTERVAL).contains(&root_epoch_interval)
        {
            return None;
        }
        Some(Self {
            version,
            bump: data[PL_OFF_BUMP],
            paused: paused_raw != 0,
            active_lanes,
            pool_id: read_u32(data, PL_OFF_POOL_ID),
            root_epoch_interval,
            authority: read_32(data, PL_OFF_AUTHORITY),
            vault_auth_bump: data[PL_OFF_VAULT_AUTH_BUMP],
            note_rent_fee: read_u64(data, PL_OFF_NOTE_RENT_FEE),
            nf_rent_fee: read_u64(data, PL_OFF_NF_RENT_FEE),
            pending_authority: read_32(data, PL_OFF_PENDING_AUTHORITY),
        })
    }
}

/// Decoded `LaneTreeState` header (`64 B` + `32 B` current_root; frontier stays zero-copy on-chain).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneTreeHeader {
    pub version: u8,
    pub lane_id: u8,
    pub bump: u8,
    pub rent_bump: u8,
    pub pool_id: u32,
    pub next_leaf: u64,
    pub nf_count: u64,
    pub current_root: Bytes32,
}

impl LaneTreeHeader {
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() != LANE_STATE_LEN || data[LN_OFF_MAGIC..LN_OFF_MAGIC + 8] != LANE_MAGIC {
            return None;
        }
        let version = data[LN_OFF_VERSION];
        let lane_id = data[LN_OFF_LANE_ID];
        let next_leaf = read_u64(data, LN_OFF_NEXT_LEAF);
        if version != PROTOCOL_VERSION
            || (lane_id as usize) >= NUM_LANES
            || next_leaf > MAX_LEAVES_PER_LANE
        {
            return None;
        }
        Some(Self {
            version,
            lane_id,
            bump: data[LN_OFF_BUMP],
            rent_bump: data[LN_OFF_RENT_BUMP],
            pool_id: read_u32(data, LN_OFF_POOL_ID),
            next_leaf,
            nf_count: read_u64(data, LN_OFF_NF_COUNT),
            current_root: read_32(data, LN_OFF_CURRENT_ROOT),
        })
    }
}

/// Single ring entry inside `GlobalRootHistory` (`40 B`: `super_root[32] || slot[8]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootEntry {
    pub super_root: Bytes32,
    pub slot: u64,
}

/// Selected witness snapshot from `GlobalRootHistory` (either `stable` in `epoch_ring` or
/// `latest` in `slot_ring`), directly consumable by witness reconstruction and transaction builders.
#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootSnapshotChoice {
    pub ring_kind: u8,
    pub ring_idx: u8,
    pub slot: u64,
    pub super_root: Bytes32,
    pub lane_roots: [Bytes32; NUM_LANES],
    pub lane_counts: [u64; NUM_LANES],
}

/// Zero-copy reader for one entry in `GlobalRootHistory.slot_ring` (`idx < 128`).
#[inline]
pub fn decode_slot_ring_entry(data: &[u8], idx: usize) -> Option<RootEntry> {
    if data.len() != ROOT_HISTORY_LEN
        || data[RT_OFF_MAGIC..RT_OFF_MAGIC + 8] != ROOTS_MAGIC
        || idx >= SLOT_RING_LEN
    {
        return None;
    }
    let off = RT_OFF_SLOT_RING + idx * ROOT_ENTRY_LEN;
    Some(RootEntry {
        super_root: read_32(data, off),
        slot: read_u64(data, off + 32),
    })
}

/// Zero-copy reader for one entry in `GlobalRootHistory.epoch_ring` (`idx < 89`).
#[inline]
pub fn decode_epoch_ring_entry(data: &[u8], idx: usize) -> Option<RootEntry> {
    if data.len() != ROOT_HISTORY_LEN
        || data[RT_OFF_MAGIC..RT_OFF_MAGIC + 8] != ROOTS_MAGIC
        || idx >= EPOCH_RING_LEN
    {
        return None;
    }
    let off = RT_OFF_EPOCH_RING + idx * ROOT_ENTRY_LEN;
    Some(RootEntry {
        super_root: read_32(data, off),
        slot: read_u64(data, off + 32),
    })
}

/// Decoded `GlobalRootHistory` (`10,216 B`, host/SDK only).
///
/// Gated out on `target_os = "solana"` so sBPFv3 programs can never accidentally place a 10 KiB
/// account struct on Solana's 4 KiB stack frame; on-chain code operates strictly zero-copy over
/// raw account slices using `RT_OFF_*`.
#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalRootHistory {
    pub version: u8,
    pub bump: u8,
    pub slot_cursor: u16,
    pub pool_id: u32,
    pub epoch_cursor: u16,
    pub slot_count: u16,
    pub epoch_count: u16,
    pub same_slot_bumped: bool,
    pub latest_slot: u64,
    pub stable_epoch_id: u64,
    pub stable_slot: u64,
    pub epoch_interval: u64,
    pub group_roots: [Bytes32; 4],
    pub latest_super_root: Bytes32,
    pub latest_lane_roots: [Bytes32; NUM_LANES],
    pub latest_lane_counts: [u64; NUM_LANES],
    pub stable_super_root: Bytes32,
    pub stable_lane_roots: [Bytes32; NUM_LANES],
    pub stable_lane_counts: [u64; NUM_LANES],
    pub slot_ring: [RootEntry; SLOT_RING_LEN],
    pub epoch_ring: [RootEntry; EPOCH_RING_LEN],
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
impl GlobalRootHistory {
    /// Decode `GlobalRootHistory` directly into a heap-allocated `Box<Self>` so callers on
    /// stack-constrained mobile worker threads never hold multiple 10 KiB copies on the stack.
    #[inline(never)]
    pub fn decode_boxed(data: &[u8]) -> Option<Box<Self>> {
        Self::decode(data).map(Box::new)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() != ROOT_HISTORY_LEN || data[RT_OFF_MAGIC..RT_OFF_MAGIC + 8] != ROOTS_MAGIC {
            return None;
        }
        let version = data[RT_OFF_VERSION];
        let slot_cursor = read_u16(data, RT_OFF_SLOT_CURSOR);
        let epoch_cursor = read_u16(data, RT_OFF_EPOCH_CURSOR);
        let slot_count = read_u16(data, RT_OFF_SLOT_COUNT);
        let epoch_count = read_u16(data, RT_OFF_EPOCH_COUNT);
        let same_slot_bumped_raw = data[RT_OFF_SAME_SLOT_BUMPED];
        let epoch_interval = read_u64(data, RT_OFF_EPOCH_INTERVAL);

        if version != PROTOCOL_VERSION
            || slot_count < 1
            || (slot_count as usize) > SLOT_RING_LEN
            || slot_cursor >= slot_count
            || epoch_count < 1
            || (epoch_count as usize) > EPOCH_RING_LEN
            || epoch_cursor >= epoch_count
            || same_slot_bumped_raw > 1
            || !(1..=MAX_ROOT_EPOCH_INTERVAL).contains(&epoch_interval)
        {
            return None;
        }

        let mut group_roots = [ZERO_HASHES_4ARY[19]; 4];
        let mut g = 0;
        while g < 4 {
            group_roots[g] = read_32(data, RT_OFF_GROUP_ROOTS + g * 32);
            g += 1;
        }

        let mut latest_lane_roots = [ZERO_HASHES_4ARY[18]; NUM_LANES];
        let mut latest_lane_counts = [0u64; NUM_LANES];
        let mut stable_lane_roots = [ZERO_HASHES_4ARY[18]; NUM_LANES];
        let mut stable_lane_counts = [0u64; NUM_LANES];
        let mut i = 0;
        while i < NUM_LANES {
            latest_lane_roots[i] = read_32(data, RT_OFF_LATEST_LANE_ROOTS + i * 32);
            let lc = read_u64(data, RT_OFF_LATEST_LANE_COUNTS + i * 8);
            if lc > MAX_LEAVES_PER_LANE {
                return None;
            }
            latest_lane_counts[i] = lc;

            stable_lane_roots[i] = read_32(data, RT_OFF_STABLE_LANE_ROOTS + i * 32);
            let sc = read_u64(data, RT_OFF_STABLE_LANE_COUNTS + i * 8);
            if sc > MAX_LEAVES_PER_LANE {
                return None;
            }
            stable_lane_counts[i] = sc;
            i += 1;
        }

        let mut slot_ring = [RootEntry {
            super_root: [0u8; 32],
            slot: 0,
        }; SLOT_RING_LEN];
        let mut s = 0;
        while s < SLOT_RING_LEN {
            let off = RT_OFF_SLOT_RING + s * ROOT_ENTRY_LEN;
            slot_ring[s] = RootEntry {
                super_root: read_32(data, off),
                slot: read_u64(data, off + 32),
            };
            s += 1;
        }

        let mut epoch_ring = [RootEntry {
            super_root: [0u8; 32],
            slot: 0,
        }; EPOCH_RING_LEN];
        let mut e = 0;
        while e < EPOCH_RING_LEN {
            let off = RT_OFF_EPOCH_RING + e * ROOT_ENTRY_LEN;
            epoch_ring[e] = RootEntry {
                super_root: read_32(data, off),
                slot: read_u64(data, off + 32),
            };
            e += 1;
        }

        Some(Self {
            version: data[RT_OFF_VERSION],
            bump: data[RT_OFF_BUMP],
            slot_cursor,
            pool_id: read_u32(data, RT_OFF_POOL_ID),
            epoch_cursor,
            slot_count,
            epoch_count,
            same_slot_bumped: same_slot_bumped_raw != 0,
            latest_slot: read_u64(data, RT_OFF_LATEST_SLOT),
            stable_epoch_id: read_u64(data, RT_OFF_STABLE_EPOCH_ID),
            stable_slot: read_u64(data, RT_OFF_STABLE_SLOT),
            epoch_interval,
            group_roots,
            latest_super_root: read_32(data, RT_OFF_LATEST_SUPER_ROOT),
            latest_lane_roots,
            latest_lane_counts,
            stable_super_root: read_32(data, RT_OFF_STABLE_SUPER_ROOT),
            stable_lane_roots,
            stable_lane_counts,
            slot_ring,
            epoch_ring,
        })
    }

    /// Return the current entry at `slot_ring[slot_cursor]`.
    #[inline]
    pub fn latest_entry(&self) -> RootEntry {
        self.slot_ring[self.slot_cursor as usize]
    }

    /// Return the current entry at `epoch_ring[epoch_cursor]`.
    #[inline]
    pub fn stable_entry(&self) -> RootEntry {
        self.epoch_ring[self.epoch_cursor as usize]
    }

    /// Select the best witness snapshot covering every `(lane_id, leaf_index)` note to spend.
    ///
    /// Prefers the long-lived `stable` epoch snapshot (`ROOT_RING_EPOCH`) whenever all notes are
    /// included in `stable_lane_counts` (maximizing shared anonymity set & proving stability), and
    /// falls back to `latest` (`ROOT_RING_SLOT`) for instant 0-slot spendability of newly created notes.
    pub fn select_snapshot_for_notes(
        &self,
        lane_and_leaf_indices: &[(u8, u64)],
    ) -> Option<RootSnapshotChoice> {
        let slot_count = self.slot_count as usize;
        let slot_cursor = self.slot_cursor as usize;
        let epoch_count = self.epoch_count as usize;
        let epoch_cursor = self.epoch_cursor as usize;
        if slot_count == 0
            || slot_count > SLOT_RING_LEN
            || slot_cursor >= slot_count
            || epoch_count == 0
            || epoch_count > EPOCH_RING_LEN
            || epoch_cursor >= epoch_count
        {
            return None;
        }
        if self.stable_super_root == [0u8; 32]
            || self.latest_super_root == [0u8; 32]
            || self.stable_entry().super_root != self.stable_super_root
            || self.latest_entry().super_root != self.latest_super_root
            || self.stable_slot > self.latest_slot
            || self.stable_entry().slot != self.stable_slot
            || self.latest_entry().slot != self.latest_slot
        {
            return None;
        }
        let mut l = 0;
        while l < NUM_LANES {
            let sc = self.stable_lane_counts[l];
            let lc = self.latest_lane_counts[l];
            if lc > MAX_LEAVES_PER_LANE || sc > lc {
                return None;
            }
            if (lc == 0) != (self.latest_lane_roots[l] == ZERO_HASHES_4ARY[18]) {
                return None;
            }
            if (sc == 0) != (self.stable_lane_roots[l] == ZERO_HASHES_4ARY[18]) {
                return None;
            }
            if (sc == lc) != (self.stable_lane_roots[l] == self.latest_lane_roots[l]) {
                return None;
            }
            l += 1;
        }
        for &(lane_id, _) in lane_and_leaf_indices {
            if (lane_id as usize) >= NUM_LANES {
                return None;
            }
        }

        if lane_and_leaf_indices
            .iter()
            .all(|&(lane, leaf)| leaf < self.stable_lane_counts[lane as usize])
        {
            return Some(RootSnapshotChoice {
                ring_kind: ROOT_RING_EPOCH,
                ring_idx: self.epoch_cursor as u8,
                slot: self.stable_slot,
                super_root: self.stable_super_root,
                lane_roots: self.stable_lane_roots,
                lane_counts: self.stable_lane_counts,
            });
        }

        if lane_and_leaf_indices
            .iter()
            .all(|&(lane, leaf)| leaf < self.latest_lane_counts[lane as usize])
        {
            return Some(RootSnapshotChoice {
                ring_kind: ROOT_RING_SLOT,
                ring_idx: self.slot_cursor as u8,
                slot: self.latest_slot,
                super_root: self.latest_super_root,
                lane_roots: self.latest_lane_roots,
                lane_counts: self.latest_lane_counts,
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        is_canonical_fr, mask_to_fr_be, pack_u64_pair_be32, u64_to_be32, BN254_FR_MODULUS_BE,
        DEFAULT_ROOT_EPOCH_INTERVAL,
    };

    fn make_valid_root_history() -> [u8; ROOT_HISTORY_LEN] {
        let mut buf = [0u8; ROOT_HISTORY_LEN];
        buf[RT_OFF_MAGIC..RT_OFF_MAGIC + 8].copy_from_slice(&ROOTS_MAGIC);
        buf[RT_OFF_VERSION] = crate::PROTOCOL_VERSION;
        buf[RT_OFF_BUMP] = 254;
        buf[RT_OFF_SLOT_CURSOR..RT_OFF_SLOT_CURSOR + 2].copy_from_slice(&0u16.to_le_bytes());
        buf[RT_OFF_POOL_ID..RT_OFF_POOL_ID + 4].copy_from_slice(&0u32.to_le_bytes());
        buf[RT_OFF_EPOCH_CURSOR..RT_OFF_EPOCH_CURSOR + 2].copy_from_slice(&0u16.to_le_bytes());
        buf[RT_OFF_SLOT_COUNT..RT_OFF_SLOT_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
        buf[RT_OFF_EPOCH_COUNT..RT_OFF_EPOCH_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
        buf[RT_OFF_SAME_SLOT_BUMPED] = 0;
        buf[RT_OFF_LATEST_SLOT..RT_OFF_LATEST_SLOT + 8].copy_from_slice(&100u64.to_le_bytes());
        buf[RT_OFF_STABLE_EPOCH_ID..RT_OFF_STABLE_EPOCH_ID + 8]
            .copy_from_slice(&(96u64 / DEFAULT_ROOT_EPOCH_INTERVAL).to_le_bytes());
        buf[RT_OFF_STABLE_SLOT..RT_OFF_STABLE_SLOT + 8].copy_from_slice(&96u64.to_le_bytes());
        buf[RT_OFF_EPOCH_INTERVAL..RT_OFF_EPOCH_INTERVAL + 8]
            .copy_from_slice(&DEFAULT_ROOT_EPOCH_INTERVAL.to_le_bytes());

        let mut latest_sr = [0u8; 32];
        latest_sr[31] = 0xAA;
        let mut stable_sr = [0u8; 32];
        stable_sr[31] = 0xBB;
        let mut latest_lane0 = [0u8; 32];
        latest_lane0[31] = 0x11;
        let mut stable_lane0 = [0u8; 32];
        stable_lane0[31] = 0x22;

        buf[RT_OFF_LATEST_SUPER_ROOT..RT_OFF_LATEST_SUPER_ROOT + 32].copy_from_slice(&latest_sr);
        buf[RT_OFF_STABLE_SUPER_ROOT..RT_OFF_STABLE_SUPER_ROOT + 32].copy_from_slice(&stable_sr);
        for i in 0..NUM_LANES {
            let lr = if i == 0 { latest_lane0 } else { ZERO_HASHES_4ARY[18] };
            let sr = if i == 0 { stable_lane0 } else { ZERO_HASHES_4ARY[18] };
            buf[RT_OFF_LATEST_LANE_ROOTS + i * 32..RT_OFF_LATEST_LANE_ROOTS + (i + 1) * 32]
                .copy_from_slice(&lr);
            buf[RT_OFF_STABLE_LANE_ROOTS + i * 32..RT_OFF_STABLE_LANE_ROOTS + (i + 1) * 32]
                .copy_from_slice(&sr);
        }
        buf[RT_OFF_LATEST_LANE_COUNTS..RT_OFF_LATEST_LANE_COUNTS + 8]
            .copy_from_slice(&5u64.to_le_bytes());
        buf[RT_OFF_STABLE_LANE_COUNTS..RT_OFF_STABLE_LANE_COUNTS + 8]
            .copy_from_slice(&3u64.to_le_bytes());

        buf[RT_OFF_SLOT_RING..RT_OFF_SLOT_RING + 32].copy_from_slice(&latest_sr);
        buf[RT_OFF_SLOT_RING + 32..RT_OFF_SLOT_RING + 40].copy_from_slice(&100u64.to_le_bytes());
        buf[RT_OFF_EPOCH_RING..RT_OFF_EPOCH_RING + 32].copy_from_slice(&stable_sr);
        buf[RT_OFF_EPOCH_RING + 32..RT_OFF_EPOCH_RING + 40].copy_from_slice(&96u64.to_le_bytes());
        buf
    }

    #[test]
    fn layout_invariants_hold() {
        assert_eq!(MM_OFF_VIEW_TAGS, 64);
        assert_eq!(MM_OFF_EPHEMERAL_PKS, 256);
        assert_eq!(MM_OFF_CIPHERTEXTS, 3_328);
        assert_eq!(MEMO_PAGE_LEN, 10_240);
        assert_eq!(MEMO_PAGE_LEN, MAX_CPI_ACCOUNT_ALLOC);
        assert_eq!(MM_OFF_CIPHERTEXTS + MEMO_NOTES_PER_PAGE * MEMO_CT_LEN, MEMO_PAGE_LEN);
        assert_eq!(ROOT_SNAPSHOT_LEN, 672);
        assert_eq!(ROOT_HISTORY_LEN, 10_216);
        assert_eq!(RT_OFF_LATEST_LANE_COUNTS + NUM_LANES * 8, RT_OFF_STABLE_SUPER_ROOT);
        assert_eq!(RT_OFF_STABLE_LANE_COUNTS + NUM_LANES * 8, RT_OFF_SLOT_RING);
        assert_eq!(RT_OFF_SLOT_RING + SLOT_RING_LEN * ROOT_ENTRY_LEN, RT_OFF_EPOCH_RING);
        assert_eq!(RT_OFF_EPOCH_RING + EPOCH_RING_LEN * ROOT_ENTRY_LEN, ROOT_HISTORY_LEN);
        assert!(is_canonical_fr(&[0u8; 32]));
        assert!(!is_canonical_fr(&BN254_FR_MODULUS_BE));
        assert!(is_canonical_fr(&mask_to_fr_be([0xFFu8; 32])));
        assert_eq!(u64_to_be32(42)[31], 42);
        let packed = pack_u64_pair_be32(100, 7);
        assert_eq!(&packed[16..24], &7u64.to_be_bytes());
        assert_eq!(&packed[24..32], &100u64.to_be_bytes());
    }

    #[test]
    fn decoders_enforce_strict_protocol_bounds() {
        // PoolState: strict version, paused (0|1), active_lanes <= 16, and root_epoch_interval (1..=256)
        let mut pool = [0u8; POOL_STATE_LEN];
        pool[0..8].copy_from_slice(&POOL_MAGIC);
        pool[PL_OFF_VERSION] = PROTOCOL_VERSION;
        pool[PL_OFF_ACTIVE_LANES] = NUM_LANES as u8;
        pool[PL_OFF_ROOT_EPOCH_INTERVAL..PL_OFF_ROOT_EPOCH_INTERVAL + 8]
            .copy_from_slice(&DEFAULT_ROOT_EPOCH_INTERVAL.to_le_bytes());
        let decoded_pool = PoolState::decode(&pool).expect("valid pool must decode");
        assert_eq!(decoded_pool.root_epoch_interval, DEFAULT_ROOT_EPOCH_INTERVAL);

        let mut bad_pool = pool;
        bad_pool[PL_OFF_ACTIVE_LANES] = (NUM_LANES + 1) as u8;
        assert!(PoolState::decode(&bad_pool).is_none());

        let mut bad_pool = pool;
        bad_pool[PL_OFF_PAUSED] = 2;
        assert!(PoolState::decode(&bad_pool).is_none());

        let mut bad_pool = pool;
        bad_pool[PL_OFF_VERSION] = 0;
        assert!(PoolState::decode(&bad_pool).is_none());

        let mut bad_pool = pool;
        bad_pool[PL_OFF_ROOT_EPOCH_INTERVAL..PL_OFF_ROOT_EPOCH_INTERVAL + 8]
            .copy_from_slice(&0u64.to_le_bytes());
        assert!(PoolState::decode(&bad_pool).is_none());

        let mut bad_pool = pool;
        bad_pool[PL_OFF_ROOT_EPOCH_INTERVAL..PL_OFF_ROOT_EPOCH_INTERVAL + 8]
            .copy_from_slice(&(MAX_ROOT_EPOCH_INTERVAL + 1).to_le_bytes());
        assert!(PoolState::decode(&bad_pool).is_none());

        // LaneTreeHeader: strict version, lane_id < NUM_LANES and next_leaf <= MAX_LEAVES_PER_LANE (1 << 36)
        let mut lane = [0u8; LANE_STATE_LEN];
        lane[0..8].copy_from_slice(&LANE_MAGIC);
        lane[LN_OFF_VERSION] = PROTOCOL_VERSION;
        lane[LN_OFF_LANE_ID] = (NUM_LANES - 1) as u8;
        lane[LN_OFF_NEXT_LEAF..LN_OFF_NEXT_LEAF + 8]
            .copy_from_slice(&MAX_LEAVES_PER_LANE.to_le_bytes());
        assert!(LaneTreeHeader::decode(&lane).is_some());

        let mut bad_lane = lane;
        bad_lane[LN_OFF_VERSION] = 0;
        assert!(LaneTreeHeader::decode(&bad_lane).is_none());

        lane[LN_OFF_LANE_ID] = NUM_LANES as u8;
        assert!(LaneTreeHeader::decode(&lane).is_none());
        lane[LN_OFF_LANE_ID] = 0;
        lane[LN_OFF_NEXT_LEAF..LN_OFF_NEXT_LEAF + 8]
            .copy_from_slice(&(MAX_LEAVES_PER_LANE + 1).to_le_bytes());
        assert!(LaneTreeHeader::decode(&lane).is_none());

        // GlobalRootHistory: strict version, cursor, count, same_slot_bumped, epoch_interval, and lane_counts bounds
        let base = make_valid_root_history();
        let decoded = GlobalRootHistory::decode_boxed(&base).expect("valid root history must decode");
        assert_eq!(decoded.slot_count, 1);
        assert_eq!(decoded.epoch_count, 1);
        assert_eq!(decoded.epoch_interval, DEFAULT_ROOT_EPOCH_INTERVAL);
        assert_eq!(decode_slot_ring_entry(&base, 0), Some(decoded.latest_entry()));
        assert_eq!(decode_epoch_ring_entry(&base, 0), Some(decoded.stable_entry()));
        let mut bad_ver = base;
        bad_ver[RT_OFF_VERSION] = 0;
        assert!(GlobalRootHistory::decode(&bad_ver).is_none());
        assert!(decode_slot_ring_entry(&base, SLOT_RING_LEN).is_none());
        assert!(decode_epoch_ring_entry(&base, EPOCH_RING_LEN).is_none());

        // Snapshot selection: prefers stable epoch snapshot when covered, falls back to latest slot snapshot
        let choice_stable = decoded
            .select_snapshot_for_notes(&[(0, 2)])
            .expect("note 2 covered by stable");
        assert_eq!(choice_stable.ring_kind, ROOT_RING_EPOCH);
        assert_eq!(choice_stable.ring_idx, 0);
        assert_eq!(choice_stable.super_root, decoded.stable_super_root);

        let choice_latest = decoded
            .select_snapshot_for_notes(&[(0, 4)])
            .expect("note 4 covered by latest");
        assert_eq!(choice_latest.ring_kind, ROOT_RING_SLOT);
        assert_eq!(choice_latest.ring_idx, 0);
        assert_eq!(choice_latest.super_root, decoded.latest_super_root);

        assert!(decoded.select_snapshot_for_notes(&[(0, 5)]).is_none());
        assert!(decoded.select_snapshot_for_notes(&[(NUM_LANES as u8, 0)]).is_none());

        // Reject slot_count == 0, slot_count > 128, slot_cursor >= slot_count
        let mut bad = base;
        bad[RT_OFF_SLOT_COUNT..RT_OFF_SLOT_COUNT + 2].copy_from_slice(&0u16.to_le_bytes());
        assert!(GlobalRootHistory::decode(&bad).is_none());

        let mut bad = base;
        bad[RT_OFF_SLOT_COUNT..RT_OFF_SLOT_COUNT + 2]
            .copy_from_slice(&((SLOT_RING_LEN + 1) as u16).to_le_bytes());
        assert!(GlobalRootHistory::decode(&bad).is_none());

        let mut bad = base;
        bad[RT_OFF_SLOT_CURSOR..RT_OFF_SLOT_CURSOR + 2].copy_from_slice(&1u16.to_le_bytes());
        assert!(GlobalRootHistory::decode(&bad).is_none());

        // Reject epoch_count == 0, epoch_count > 89, epoch_cursor >= epoch_count
        let mut bad = base;
        bad[RT_OFF_EPOCH_COUNT..RT_OFF_EPOCH_COUNT + 2].copy_from_slice(&0u16.to_le_bytes());
        assert!(GlobalRootHistory::decode(&bad).is_none());

        let mut bad = base;
        bad[RT_OFF_EPOCH_COUNT..RT_OFF_EPOCH_COUNT + 2]
            .copy_from_slice(&((EPOCH_RING_LEN + 1) as u16).to_le_bytes());
        assert!(GlobalRootHistory::decode(&bad).is_none());

        let mut bad = base;
        bad[RT_OFF_EPOCH_CURSOR..RT_OFF_EPOCH_CURSOR + 2].copy_from_slice(&1u16.to_le_bytes());
        assert!(GlobalRootHistory::decode(&bad).is_none());

        // Reject same_slot_bumped > 1
        let mut bad = base;
        bad[RT_OFF_SAME_SLOT_BUMPED] = 2;
        assert!(GlobalRootHistory::decode(&bad).is_none());

        // Reject epoch_interval == 0 or > MAX_ROOT_EPOCH_INTERVAL
        let mut bad = base;
        bad[RT_OFF_EPOCH_INTERVAL..RT_OFF_EPOCH_INTERVAL + 8].copy_from_slice(&0u64.to_le_bytes());
        assert!(GlobalRootHistory::decode(&bad).is_none());

        let mut bad = base;
        bad[RT_OFF_EPOCH_INTERVAL..RT_OFF_EPOCH_INTERVAL + 8]
            .copy_from_slice(&(MAX_ROOT_EPOCH_INTERVAL + 1).to_le_bytes());
        assert!(GlobalRootHistory::decode(&bad).is_none());

        // Reject latest_lane_counts or stable_lane_counts > MAX_LEAVES_PER_LANE
        let mut bad = base;
        bad[RT_OFF_LATEST_LANE_COUNTS + 5 * 8..RT_OFF_LATEST_LANE_COUNTS + 6 * 8]
            .copy_from_slice(&(MAX_LEAVES_PER_LANE + 1).to_le_bytes());
        assert!(GlobalRootHistory::decode(&bad).is_none());

        let mut bad = base;
        bad[RT_OFF_STABLE_LANE_COUNTS + 3 * 8..RT_OFF_STABLE_LANE_COUNTS + 4 * 8]
            .copy_from_slice(&(MAX_LEAVES_PER_LANE + 1).to_le_bytes());
        assert!(GlobalRootHistory::decode(&bad).is_none());

        // Round-3 regression: select_snapshot_for_notes enforces hard preconditions BEFORE
        // checking note coverage (zero silent `stable -> latest` downgrade on tampered structs!)
        let mut bad_epoch_ring = decoded.clone();
        bad_epoch_ring.epoch_ring[0].super_root[0] ^= 1;
        assert!(bad_epoch_ring.select_snapshot_for_notes(&[(0, 2)]).is_none());

        let mut zero_stable_sr = decoded.clone();
        zero_stable_sr.stable_super_root = [0u8; 32];
        zero_stable_sr.epoch_ring[0].super_root = [0u8; 32];
        assert!(zero_stable_sr.select_snapshot_for_notes(&[(0, 2)]).is_none());

        let mut bad_slot_ring = decoded.clone();
        bad_slot_ring.slot_ring[0].super_root[0] ^= 1;
        assert!(bad_slot_ring.select_snapshot_for_notes(&[(0, 2)]).is_none());

        let mut zero_latest_sr = decoded.clone();
        zero_latest_sr.latest_super_root = [0u8; 32];
        zero_latest_sr.slot_ring[0].super_root = [0u8; 32];
        assert!(zero_latest_sr.select_snapshot_for_notes(&[(0, 2)]).is_none());

        let mut eight_byte_downgrade = decoded.clone();
        eight_byte_downgrade.stable_lane_counts[0] = 0; // stable_lane_roots[0] != ZERO_HASHES_4ARY[18]
        assert!(eight_byte_downgrade.select_snapshot_for_notes(&[(0, 2)]).is_none());

        let mut stable_gt_latest_cnt = decoded.clone();
        stable_gt_latest_cnt.stable_lane_counts[0] = 6;
        assert!(stable_gt_latest_cnt.select_snapshot_for_notes(&[(0, 2)]).is_none());

        let mut equal_cnt_diff_root = decoded.clone();
        equal_cnt_diff_root.stable_lane_counts[0] = 5;
        assert!(equal_cnt_diff_root.select_snapshot_for_notes(&[(0, 2)]).is_none());

        let mut stable_gt_latest_slot = decoded.clone();
        stable_gt_latest_slot.stable_slot = 101;
        stable_gt_latest_slot.epoch_ring[0].slot = 101;
        assert!(stable_gt_latest_slot.select_snapshot_for_notes(&[(0, 2)]).is_none());

        let mut bad_ring_slot = decoded.clone();
        bad_ring_slot.epoch_ring[0].slot = 95;
        assert!(bad_ring_slot.select_snapshot_for_notes(&[(0, 2)]).is_none());

        let mut bad_slot_ring_slot = decoded.clone();
        bad_slot_ring_slot.slot_ring[0].slot = 99;
        assert!(bad_slot_ring_slot.select_snapshot_for_notes(&[(0, 2)]).is_none());

        // Round-5 regression: decode_{slot,epoch}_ring_entry enforce ROOTS_MAGIC
        let zero_buf = [0u8; ROOT_HISTORY_LEN];
        assert!(decode_slot_ring_entry(&zero_buf, 0).is_none());
        assert!(decode_epoch_ring_entry(&zero_buf, 0).is_none());
        assert!(decode_slot_ring_entry(&base, 0).is_some());
        assert!(decode_epoch_ring_entry(&base, 0).is_some());
    }
}
