//! Fixed-size, zero-copy account layouts for Audren (all `<= 10,240 B` CPI allocation cap,
//! zero `realloc`, SIMD-0460 compliant).

use crate::{Bytes32, LANE_DEPTH_4ARY, NUM_LANES, ZERO_HASHES_4ARY};

/// Solana maximum CPI account creation size (`10 KiB`).
pub const MAX_CPI_ACCOUNT_ALLOC: usize = 10_240;

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
pub const CKPT_MAGIC: [u8; 8] = *b"AUD1CK01";
pub const DYN_MEMO_MAGIC: [u8; 8] = *b"AUD1DYN1";

/// Fixed account byte lengths (all `<= 10,240 B`, zero `realloc`).
pub const POOL_STATE_LEN: usize = 128;
pub const SENTINEL_LEN: usize = 16;
pub const LANE_STATE_LEN: usize = 64 + 32 + (LANE_DEPTH_4ARY * 3 * 32); // 1,824 B
pub const SUBTREE_PAGE_LEN: usize = 64 + (SUBTREE_LEAVES * 32); // 8,256 B
pub const SUBROOT_PAGE_LEN: usize = 64 + (SUBROOTS_PER_PAGE * 32); // 9,664 B
pub const MEMO_PAGE_LEN: usize = 64 + (MEMO_NOTES_PER_PAGE * MEMO_ENTRY_WIRE_LEN); // 10,240 B
pub const NF_PAGE_LEN: usize = 64 + (NF_PER_PAGE * NF_PREFIX_LEN); // 9,664 B
pub const CKPT_LEN: usize = 64 + (NUM_LANES * 32) + (NUM_LANES * 8); // 704 B

const _: () = assert!(POOL_STATE_LEN == 128);
const _: () = assert!(LANE_STATE_LEN == 1_824);
const _: () = assert!(SUBTREE_PAGE_LEN == 8_256 && SUBTREE_PAGE_LEN <= MAX_CPI_ACCOUNT_ALLOC);
const _: () = assert!(SUBROOT_PAGE_LEN == 9_664 && SUBROOT_PAGE_LEN <= MAX_CPI_ACCOUNT_ALLOC);
const _: () = assert!(MEMO_PAGE_LEN == 10_240 && MEMO_PAGE_LEN <= MAX_CPI_ACCOUNT_ALLOC);
const _: () = assert!(NF_PAGE_LEN == 9_664 && NF_PAGE_LEN <= MAX_CPI_ACCOUNT_ALLOC);
const _: () = assert!(CKPT_LEN == 704);

// --- PoolState offsets (128 B) ---
pub const PL_OFF_MAGIC: usize = 0; // 8
pub const PL_OFF_VERSION: usize = 8; // 1
pub const PL_OFF_BUMP: usize = 9; // 1
pub const PL_OFF_PAUSED: usize = 10; // 1
pub const PL_OFF_ACTIVE_LANES: usize = 11; // 1
pub const PL_OFF_POOL_ID: usize = 12; // 4 (u32)
pub const PL_OFF_CKPT_INTERVAL: usize = 16; // 8 (u64)
pub const PL_OFF_MAX_CKPT_AGE: usize = 24; // 8 (u64)
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

// --- RootCheckpoint offsets (704 B) ---
pub const CK_OFF_MAGIC: usize = 0; // 8
pub const CK_OFF_VERSION: usize = 8; // 1
pub const CK_OFF_BUMP: usize = 9; // 1
pub const CK_OFF_SLOT_IDX: usize = 10; // 2 (u16: 0..256)
pub const CK_OFF_POOL_ID: usize = 12; // 4 (u32)
pub const CK_OFF_EPOCH_ID: usize = 16; // 8 (u64)
pub const CK_OFF_PUBLISHED_SLOT: usize = 24; // 8 (u64)
pub const CK_OFF_SUPER_ROOT: usize = 32; // 32
pub const CK_OFF_LANE_ROOTS: usize = 64; // 16 * 32 = 512 B
pub const CK_OFF_LANE_COUNTS: usize = 576; // 16 * 8 = 128 B

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
    pub ckpt_interval: u64,
    pub max_ckpt_age: u64,
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
        Some(Self {
            version: data[PL_OFF_VERSION],
            bump: data[PL_OFF_BUMP],
            paused: data[PL_OFF_PAUSED] != 0,
            active_lanes: data[PL_OFF_ACTIVE_LANES],
            pool_id: read_u32(data, PL_OFF_POOL_ID),
            ckpt_interval: read_u64(data, PL_OFF_CKPT_INTERVAL),
            max_ckpt_age: read_u64(data, PL_OFF_MAX_CKPT_AGE),
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
        Some(Self {
            version: data[LN_OFF_VERSION],
            lane_id: data[LN_OFF_LANE_ID],
            bump: data[LN_OFF_BUMP],
            rent_bump: data[LN_OFF_RENT_BUMP],
            pool_id: read_u32(data, LN_OFF_POOL_ID),
            next_leaf: read_u64(data, LN_OFF_NEXT_LEAF),
            nf_count: read_u64(data, LN_OFF_NF_COUNT),
            current_root: read_32(data, LN_OFF_CURRENT_ROOT),
        })
    }
}

/// Decoded `RootCheckpoint` (`704 B`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootCheckpoint {
    pub version: u8,
    pub bump: u8,
    pub slot_idx: u16,
    pub pool_id: u32,
    pub epoch_id: u64,
    pub published_slot: u64,
    pub super_root: Bytes32,
    pub lane_roots: [Bytes32; NUM_LANES],
    pub lane_counts: [u64; NUM_LANES],
}

impl RootCheckpoint {
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() != CKPT_LEN || data[CK_OFF_MAGIC..CK_OFF_MAGIC + 8] != CKPT_MAGIC {
            return None;
        }
        let mut lane_roots = [ZERO_HASHES_4ARY[18]; NUM_LANES];
        let mut lane_counts = [0u64; NUM_LANES];
        let mut i = 0;
        while i < NUM_LANES {
            lane_roots[i] = read_32(data, CK_OFF_LANE_ROOTS + i * 32);
            lane_counts[i] = read_u64(data, CK_OFF_LANE_COUNTS + i * 8);
            i += 1;
        }
        Some(Self {
            version: data[CK_OFF_VERSION],
            bump: data[CK_OFF_BUMP],
            slot_idx: read_u16(data, CK_OFF_SLOT_IDX),
            pool_id: read_u32(data, CK_OFF_POOL_ID),
            epoch_id: read_u64(data, CK_OFF_EPOCH_ID),
            published_slot: read_u64(data, CK_OFF_PUBLISHED_SLOT),
            super_root: read_32(data, CK_OFF_SUPER_ROOT),
            lane_roots,
            lane_counts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{is_canonical_fr, mask_to_fr_be, pack_u64_pair_be32, u64_to_be32, BN254_FR_MODULUS_BE};

    #[test]
    fn layout_invariants_hold() {
        assert_eq!(MM_OFF_VIEW_TAGS, 64);
        assert_eq!(MM_OFF_EPHEMERAL_PKS, 256);
        assert_eq!(MM_OFF_CIPHERTEXTS, 3_328);
        assert_eq!(MEMO_PAGE_LEN, 10_240);
        assert_eq!(MEMO_PAGE_LEN, MAX_CPI_ACCOUNT_ALLOC);
        assert_eq!(MM_OFF_CIPHERTEXTS + MEMO_NOTES_PER_PAGE * MEMO_CT_LEN, MEMO_PAGE_LEN);
        assert_eq!(CK_OFF_LANE_COUNTS + NUM_LANES * 8, CKPT_LEN);
        assert!(is_canonical_fr(&[0u8; 32]));
        assert!(!is_canonical_fr(&BN254_FR_MODULUS_BE));
        assert!(is_canonical_fr(&mask_to_fr_be([0xFFu8; 32])));
        assert_eq!(u64_to_be32(42)[31], 42);
        let packed = pack_u64_pair_be32(100, 7);
        assert_eq!(&packed[16..24], &7u64.to_be_bytes());
        assert_eq!(&packed[24..32], &100u64.to_be_bytes());
    }
}
