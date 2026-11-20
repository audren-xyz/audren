//! Fixed-offset, zero-copy account layouts for Audren.
//!
//! `EpochPage` intentionally uses a **Structure-of-Arrays (SoA)** layout sized at
//! `6,240 bytes` (`32` notes/page) — comfortably below Solana's `10,240 B` (`10 KiB`)
//! per-instruction CPI allocation limit (`MAX_PERMITTED_DATA_INCREASE`) and 100%
//! compatible with Agave 4.5 Account Data Direct Mapping (`SIMD-0460`).
//!
//! Pure-RPC wallets scan up to 100 pages (`3,200` notes) in a single Solana
//! `getMultipleAccounts` call (or real-time Agave 4.4 `programSubscribe` WebSocket)
//! using `dataSlice: { offset: PAGE_SCAN_OFFSET, length: PAGE_SCAN_LEN }` (`1,056 B`/page)
//! with zero custom indexer.

use crate::{AudrenError, Bytes32, PoolMode};

/// Account magics (8 ASCII bytes).
pub const POOL_MAGIC: [u8; 8] = *b"AUDRNPL1";
pub const PAGE_MAGIC: [u8; 8] = *b"AUDRNPG1";
pub const SOL_VAULT_MAGIC: [u8; 8] = *b"AUDRNSL1";
pub const PAGE_RENT_MAGIC: [u8; 8] = *b"AUDRNRN1";
pub const PROOF_BUFFER_MAGIC: [u8; 8] = *b"AUDRNBF1";

// ---------------------------------------------------------------------------
// Ephemeral ProofBuffer PDA (48 B header + up to 9,984 B payload <= 10 KiB CPI cap)
// ---------------------------------------------------------------------------

pub const PROOF_BUFFER_HEADER_LEN: usize = 48;
/// Fixed per-chunk payload slice (`768 B` + `14 B` ix header + 3 accounts = `~950 B` wire tx,
/// comfortably under Solana's `1,232 B` packet limit).
pub const PROOF_BUFFER_CHUNK_SIZE: usize = 768;
/// Maximum chunks tracked by the `u16` `written_mask` (`13 * 768 + 48 = 10,032 B <= 10,240 B`).
pub const PROOF_BUFFER_MAX_CHUNKS: usize = 13;
pub const PROOF_BUFFER_MAX_PAYLOAD: usize = PROOF_BUFFER_CHUNK_SIZE * PROOF_BUFFER_MAX_CHUNKS;

pub const BUF_OFF_MAGIC: usize = 0; // [u8; 8]
pub const BUF_OFF_AUTHORITY: usize = 8; // [u8; 32]
pub const BUF_OFF_EXPECTED_LEN: usize = 40; // u32 LE
pub const BUF_OFF_WRITTEN_MASK: usize = 44; // u16 LE
// [46..48]: reserved zero bytes

// ---------------------------------------------------------------------------
// PoolState (192 bytes)
// ---------------------------------------------------------------------------

pub const POOL_STATE_LEN: usize = 192;

pub const POOL_OFF_MAGIC: usize = 0; // [u8; 8]
pub const POOL_OFF_VERSION: usize = 8; // u8
pub const POOL_OFF_BUMP: usize = 9; // u8
pub const POOL_OFF_MODE: usize = 10; // u8 (PoolMode)
pub const POOL_OFF_PAUSED: usize = 11; // u8
pub const POOL_OFF_POOL_ID: usize = 12; // u32 LE
pub const POOL_OFF_CURRENT_PAGE: usize = 16; // u64 LE
pub const POOL_OFF_TOTAL_NOTES: usize = 24; // u64 LE
pub const POOL_OFF_TOTAL_SPENDS: usize = 32; // u64 LE
pub const POOL_OFF_PAGE_RENT_FEE: usize = 40; // u64 LE (lamports collected per note into PageRentVault)
pub const POOL_OFF_AUTHORITY: usize = 48; // [u8; 32] (governance / pause / future v2 upgrade)
pub const POOL_OFF_AUDITOR_PK: usize = 80; // [u8; 32] (Ristretto255 point K_aud when InstitutionalAudited, else 0)
pub const POOL_OFF_AUDITOR_LOCKED: usize = 112; // u8 (1 = auditor_pk permanently locked)
pub const POOL_OFF_VAULT_AUTH_BUMP: usize = 113; // u8
pub const POOL_OFF_SOL_VAULT_BUMP: usize = 114; // u8
pub const POOL_OFF_PAGE_RENT_BUMP: usize = 115; // u8
// [116..192]: 76 bytes reserved zero padding for forward-compatible PQ metadata

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolState {
    pub version: u8,
    pub bump: u8,
    pub mode: PoolMode,
    pub paused: bool,
    pub pool_id: u32,
    pub current_page_id: u64,
    pub total_notes: u64,
    pub total_spends: u64,
    pub page_rent_fee_lamports: u64,
    pub authority: Bytes32,
    pub auditor_pk: Bytes32,
    pub auditor_locked: bool,
    pub vault_auth_bump: u8,
    pub sol_vault_bump: u8,
    pub page_rent_bump: u8,
}

impl PoolState {
    pub fn decode(data: &[u8]) -> Result<Self, AudrenError> {
        if data.len() != POOL_STATE_LEN {
            return Err(AudrenError::InvalidAccount);
        }
        if data[POOL_OFF_MAGIC..POOL_OFF_MAGIC + 8] != POOL_MAGIC {
            return Err(AudrenError::InvalidMagic);
        }
        let mode = PoolMode::from_u8(data[POOL_OFF_MODE]).ok_or(AudrenError::InvalidAccount)?;
        Ok(Self {
            version: data[POOL_OFF_VERSION],
            bump: data[POOL_OFF_BUMP],
            mode,
            paused: data[POOL_OFF_PAUSED] != 0,
            pool_id: read_u32(data, POOL_OFF_POOL_ID)?,
            current_page_id: read_u64(data, POOL_OFF_CURRENT_PAGE)?,
            total_notes: read_u64(data, POOL_OFF_TOTAL_NOTES)?,
            total_spends: read_u64(data, POOL_OFF_TOTAL_SPENDS)?,
            page_rent_fee_lamports: read_u64(data, POOL_OFF_PAGE_RENT_FEE)?,
            authority: read_32(data, POOL_OFF_AUTHORITY)?,
            auditor_pk: read_32(data, POOL_OFF_AUDITOR_PK)?,
            auditor_locked: data[POOL_OFF_AUDITOR_LOCKED] != 0,
            vault_auth_bump: data[POOL_OFF_VAULT_AUTH_BUMP],
            sol_vault_bump: data[POOL_OFF_SOL_VAULT_BUMP],
            page_rent_bump: data[POOL_OFF_PAGE_RENT_BUMP],
        })
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<(), AudrenError> {
        if out.len() != POOL_STATE_LEN {
            return Err(AudrenError::InvalidAccount);
        }
        out.fill(0);
        out[POOL_OFF_MAGIC..POOL_OFF_MAGIC + 8].copy_from_slice(&POOL_MAGIC);
        out[POOL_OFF_VERSION] = self.version;
        out[POOL_OFF_BUMP] = self.bump;
        out[POOL_OFF_MODE] = self.mode as u8;
        out[POOL_OFF_PAUSED] = u8::from(self.paused);
        out[POOL_OFF_POOL_ID..POOL_OFF_POOL_ID + 4].copy_from_slice(&self.pool_id.to_le_bytes());
        out[POOL_OFF_CURRENT_PAGE..POOL_OFF_CURRENT_PAGE + 8]
            .copy_from_slice(&self.current_page_id.to_le_bytes());
        out[POOL_OFF_TOTAL_NOTES..POOL_OFF_TOTAL_NOTES + 8]
            .copy_from_slice(&self.total_notes.to_le_bytes());
        out[POOL_OFF_TOTAL_SPENDS..POOL_OFF_TOTAL_SPENDS + 8]
            .copy_from_slice(&self.total_spends.to_le_bytes());
        out[POOL_OFF_PAGE_RENT_FEE..POOL_OFF_PAGE_RENT_FEE + 8]
            .copy_from_slice(&self.page_rent_fee_lamports.to_le_bytes());
        out[POOL_OFF_AUTHORITY..POOL_OFF_AUTHORITY + 32].copy_from_slice(&self.authority);
        out[POOL_OFF_AUDITOR_PK..POOL_OFF_AUDITOR_PK + 32].copy_from_slice(&self.auditor_pk);
        out[POOL_OFF_AUDITOR_LOCKED] = u8::from(self.auditor_locked);
        out[POOL_OFF_VAULT_AUTH_BUMP] = self.vault_auth_bump;
        out[POOL_OFF_SOL_VAULT_BUMP] = self.sol_vault_bump;
        out[POOL_OFF_PAGE_RENT_BUMP] = self.page_rent_bump;
        Ok(())
    }

    #[inline]
    pub fn has_auditor(&self) -> bool {
        self.mode == PoolMode::InstitutionalAudited && self.auditor_pk != [0u8; 32]
    }
}

// ---------------------------------------------------------------------------
// EpochPage (6,240 bytes, Structure-of-Arrays for pure-RPC dataSlice scanning)
// ---------------------------------------------------------------------------

/// Solana runtime per-CPI / per-instruction account allocation cap (`10 KiB`).
/// Enforced both pre- and post-Account Data Direct Mapping (`SIMD-0460`).
pub const MAX_CPI_ACCOUNT_ALLOC: usize = 10_240;

/// Notes per fixed-size `EpochPage` PDA (`2^5 = 32`).
/// - `m = 5` (1 page): `32`-note anonymity set (`<= 135` MSM points)
/// - `m = 6` (2 pages): `64`-note anonymity set (`<= 243` MSM points)
/// - `m = 7` (4 pages): `128`-note anonymity set (`<= 439` MSM points < Agave's `512` cap)
pub const PAGE_CAPACITY: usize = 32;

/// Encrypted note payload stored inline per note (48 B AES-256-GCM ciphertext + 16 B tag
/// or compact P2P envelope; full 1,088 B NIST ML-KEM-768 P2P encapsulations live in tx data).
pub const NOTE_CT_LEN: usize = 64;

pub const PAGE_HEADER_LEN: usize = 64;
pub const PAGE_OFF_MAGIC: usize = 0; // [u8; 8]
pub const PAGE_OFF_VERSION: usize = 8; // u8
pub const PAGE_OFF_BUMP: usize = 9; // u8
pub const PAGE_OFF_CLOSED: usize = 10; // u8
pub const PAGE_OFF_COUNT: usize = 11; // u8 (0..=32)
pub const PAGE_OFF_POOL_ID: usize = 12; // u32 LE
pub const PAGE_OFF_PAGE_ID: usize = 16; // u64 LE
pub const PAGE_OFF_CREATED_SLOT: usize = 24; // u64 LE
pub const PAGE_OFF_CLOSED_SLOT: usize = 32; // u64 LE
// [40..64]: 24 bytes reserved

/// Contiguous pure-RPC scan slice: `view_tags[32]` + `ephemeral_pks[32]`.
pub const PAGE_OFF_VIEW_TAGS: usize = PAGE_HEADER_LEN; // 64..96 (32 B)
pub const PAGE_OFF_EPHEMERAL_PKS: usize = PAGE_OFF_VIEW_TAGS + PAGE_CAPACITY; // 96..1,120 (1,024 B)
pub const PAGE_SCAN_OFFSET: usize = PAGE_OFF_VIEW_TAGS;
pub const PAGE_SCAN_LEN: usize = PAGE_CAPACITY + PAGE_CAPACITY * 32; // 1,056 B

/// Contiguous witness arrays read during Triptych verification.
pub const PAGE_OFF_STEALTH_PKS: usize = PAGE_OFF_EPHEMERAL_PKS + PAGE_CAPACITY * 32; // 1,120..2,144 (1,024 B)
pub const PAGE_OFF_ASSET_TAGS: usize = PAGE_OFF_STEALTH_PKS + PAGE_CAPACITY * 32; // 2,144..3,168 (1,024 B)
pub const PAGE_OFF_COMMITMENTS: usize = PAGE_OFF_ASSET_TAGS + PAGE_CAPACITY * 32; // 3,168..4,192 (1,024 B)

/// Contiguous encrypted note metadata.
pub const PAGE_OFF_CIPHERTEXTS: usize = PAGE_OFF_COMMITMENTS + PAGE_CAPACITY * 32; // 4,192..6,240 (2,048 B)

/// Exact total byte length of an `EpochPage` PDA (`6,240 B < 10,240 B` CPI cap).
pub const PAGE_LEN: usize = PAGE_OFF_CIPHERTEXTS + PAGE_CAPACITY * NOTE_CT_LEN; // 6,240 B

const _: () = assert!(PAGE_LEN <= MAX_CPI_ACCOUNT_ALLOC);

/// Minimum remaining slots below which `OpenPage` is allowed to pre-open `page_id + 1`.
pub const PAGE_ROLLOVER_HEADROOM: usize = 4;

/// Tiny sentinel accounts (`SOL_VAULT`, `PAGE_RENT_VAULT`) storing an 8-byte magic + bump.
pub const SENTINEL_ACCOUNT_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageHeader {
    pub version: u8,
    pub bump: u8,
    pub closed: bool,
    pub count: u8,
    pub pool_id: u32,
    pub page_id: u64,
    pub created_slot: u64,
    pub closed_slot: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteEntry {
    pub view_tag: u8,
    pub ephemeral_pk: Bytes32,
    pub stealth_pk: Bytes32,
    pub asset_tag: Bytes32,
    pub commitment: Bytes32,
    pub ciphertext: [u8; NOTE_CT_LEN],
}

impl PageHeader {
    pub fn decode(data: &[u8]) -> Result<Self, AudrenError> {
        if data.len() != PAGE_LEN {
            return Err(AudrenError::InvalidAccount);
        }
        if data[PAGE_OFF_MAGIC..PAGE_OFF_MAGIC + 8] != PAGE_MAGIC {
            return Err(AudrenError::InvalidMagic);
        }
        let count = data[PAGE_OFF_COUNT];
        if (count as usize) > PAGE_CAPACITY {
            return Err(AudrenError::InvalidAccount);
        }
        Ok(Self {
            version: data[PAGE_OFF_VERSION],
            bump: data[PAGE_OFF_BUMP],
            closed: data[PAGE_OFF_CLOSED] != 0,
            count,
            pool_id: read_u32(data, PAGE_OFF_POOL_ID)?,
            page_id: read_u64(data, PAGE_OFF_PAGE_ID)?,
            created_slot: read_u64(data, PAGE_OFF_CREATED_SLOT)?,
            closed_slot: read_u64(data, PAGE_OFF_CLOSED_SLOT)?,
        })
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<(), AudrenError> {
        if out.len() < PAGE_HEADER_LEN {
            return Err(AudrenError::InvalidAccount);
        }
        out[PAGE_OFF_MAGIC..PAGE_OFF_MAGIC + 8].copy_from_slice(&PAGE_MAGIC);
        out[PAGE_OFF_VERSION] = self.version;
        out[PAGE_OFF_BUMP] = self.bump;
        out[PAGE_OFF_CLOSED] = u8::from(self.closed);
        out[PAGE_OFF_COUNT] = self.count;
        out[PAGE_OFF_POOL_ID..PAGE_OFF_POOL_ID + 4].copy_from_slice(&self.pool_id.to_le_bytes());
        out[PAGE_OFF_PAGE_ID..PAGE_OFF_PAGE_ID + 8].copy_from_slice(&self.page_id.to_le_bytes());
        out[PAGE_OFF_CREATED_SLOT..PAGE_OFF_CREATED_SLOT + 8]
            .copy_from_slice(&self.created_slot.to_le_bytes());
        out[PAGE_OFF_CLOSED_SLOT..PAGE_OFF_CLOSED_SLOT + 8]
            .copy_from_slice(&self.closed_slot.to_le_bytes());
        Ok(())
    }
}

/// Zero-copy read of `(stealth_pk, asset_tag, commitment)` at slot `idx` in a validated `EpochPage`.
#[inline]
pub fn read_page_witness(data: &[u8], idx: usize) -> Result<(Bytes32, Bytes32, Bytes32), AudrenError> {
    if data.len() != PAGE_LEN || idx >= PAGE_CAPACITY {
        return Err(AudrenError::InvalidAccount);
    }
    let off = idx * 32;
    Ok((
        read_32(data, PAGE_OFF_STEALTH_PKS + off)?,
        read_32(data, PAGE_OFF_ASSET_TAGS + off)?,
        read_32(data, PAGE_OFF_COMMITMENTS + off)?,
    ))
}

/// Write a single `NoteEntry` into slot `idx` of a validated `EpochPage` buffer.
#[inline]
pub fn write_page_note(data: &mut [u8], idx: usize, note: &NoteEntry) -> Result<(), AudrenError> {
    if data.len() != PAGE_LEN || idx >= PAGE_CAPACITY {
        return Err(AudrenError::InvalidAccount);
    }
    let off32 = idx * 32;
    let off_ct = idx * NOTE_CT_LEN;
    data[PAGE_OFF_VIEW_TAGS + idx] = note.view_tag;
    data[PAGE_OFF_EPHEMERAL_PKS + off32..PAGE_OFF_EPHEMERAL_PKS + off32 + 32]
        .copy_from_slice(&note.ephemeral_pk);
    data[PAGE_OFF_STEALTH_PKS + off32..PAGE_OFF_STEALTH_PKS + off32 + 32]
        .copy_from_slice(&note.stealth_pk);
    data[PAGE_OFF_ASSET_TAGS + off32..PAGE_OFF_ASSET_TAGS + off32 + 32]
        .copy_from_slice(&note.asset_tag);
    data[PAGE_OFF_COMMITMENTS + off32..PAGE_OFF_COMMITMENTS + off32 + 32]
        .copy_from_slice(&note.commitment);
    data[PAGE_OFF_CIPHERTEXTS + off_ct..PAGE_OFF_CIPHERTEXTS + off_ct + NOTE_CT_LEN]
        .copy_from_slice(&note.ciphertext);
    Ok(())
}

/// Read a full `NoteEntry` at slot `idx`.
pub fn read_page_note(data: &[u8], idx: usize) -> Result<NoteEntry, AudrenError> {
    if data.len() != PAGE_LEN || idx >= PAGE_CAPACITY {
        return Err(AudrenError::InvalidAccount);
    }
    let off32 = idx * 32;
    let off_ct = idx * NOTE_CT_LEN;
    let mut ciphertext = [0u8; NOTE_CT_LEN];
    ciphertext.copy_from_slice(&data[PAGE_OFF_CIPHERTEXTS + off_ct..PAGE_OFF_CIPHERTEXTS + off_ct + NOTE_CT_LEN]);
    Ok(NoteEntry {
        view_tag: data[PAGE_OFF_VIEW_TAGS + idx],
        ephemeral_pk: read_32(data, PAGE_OFF_EPHEMERAL_PKS + off32)?,
        stealth_pk: read_32(data, PAGE_OFF_STEALTH_PKS + off32)?,
        asset_tag: read_32(data, PAGE_OFF_ASSET_TAGS + off32)?,
        commitment: read_32(data, PAGE_OFF_COMMITMENTS + off32)?,
        ciphertext,
    })
}

#[inline]
pub fn read_u16(data: &[u8], off: usize) -> Result<u16, AudrenError> {
    let slice = data.get(off..off + 2).ok_or(AudrenError::InvalidInstruction)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

#[inline]
pub fn read_u32(data: &[u8], off: usize) -> Result<u32, AudrenError> {
    let slice = data.get(off..off + 4).ok_or(AudrenError::InvalidInstruction)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[inline]
pub fn read_u64(data: &[u8], off: usize) -> Result<u64, AudrenError> {
    let slice = data.get(off..off + 8).ok_or(AudrenError::InvalidInstruction)?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

#[inline]
pub fn read_32(data: &[u8], off: usize) -> Result<Bytes32, AudrenError> {
    let slice = data.get(off..off + 32).ok_or(AudrenError::InvalidInstruction)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Ok(out)
}
