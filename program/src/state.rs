//! Zero-copy PDA helpers and account guards for Audren, backed by `audren-core`.

pub use audren_core::{
    instruction::*,
    layout::*,
    AudrenError, PoolMode, ASSOCIATED_TOKEN_PROGRAM_ID, CLASSIC_TOKEN_PROGRAM_ID, CKPT_SEED,
    ESCROW_SEED, LANE_DEPTH_4ARY, LANE_RENT_SEED, LANE_SEED, MEMO_SEED, NATIVE_SOL_MINT,
    NF_PAGE_SEED, NULLIFIER_SEED, NUM_ESCROW_SHARDS, NUM_LANES, POOL_SEED, PROTOCOL_VERSION,
    SOL_VAULT_SEED, SUBROOT_SEED, SUBTREE_SEED, SYSTEM_PROGRAM_ID as SYSTEM_PROGRAM_BYTES,
    TOKEN_2022_PROGRAM_ID, UNWRAP_SEED, VAULT_AUTH_SEED, WSOL_MINT as WSOL_MINT_BYTES,
    ZERO_HASHES_4ARY, CHECKPOINT_RING_SLOTS,
};
use pinocchio::{error::ProgramError, AccountView, Address};

/// System Program (`11111111111111111111111111111111`)
pub const SYSTEM_PROGRAM_ID: Address = Address::new_from_array(SYSTEM_PROGRAM_BYTES);

/// Classic SPL Token (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`)
pub const SPL_TOKEN_ID: Address = Address::new_from_array(CLASSIC_TOKEN_PROGRAM_ID);

/// SPL Token-2022 (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`)
pub const TOKEN_2022_ID: Address = Address::new_from_array(TOKEN_2022_PROGRAM_ID);

/// Associated Token Account Program (`ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`)
pub const ATA_PROGRAM_ID: Address = Address::new_from_array(ASSOCIATED_TOKEN_PROGRAM_ID);

/// Classic SPL Wrapped SOL Mint (`So11111111111111111111111111111111111111112`)
pub const WSOL_MINT: Address = Address::new_from_array(WSOL_MINT_BYTES);

#[inline(always)]
pub fn err(e: AudrenError) -> ProgramError {
    ProgramError::Custom(e as u32)
}

#[inline(always)]
pub fn ensure(cond: bool, e: AudrenError) -> Result<(), ProgramError> {
    if cond {
        Ok(())
    } else {
        Err(err(e))
    }
}

#[inline(always)]
pub fn is_supported_token_program(addr: &Address) -> bool {
    addr == &SPL_TOKEN_ID || addr == &TOKEN_2022_ID
}

pub fn check_owned_and_magic(
    acc: &AccountView,
    program_id: &Address,
    expected_len: usize,
    magic: &[u8; 8],
) -> Result<(), ProgramError> {
    ensure(acc.owned_by(program_id), AudrenError::InvalidAccount)?;
    let data = acc.try_borrow()?;
    ensure(
        data.len() == expected_len && &data[0..8] == magic,
        AudrenError::InvalidAccount,
    )
}

pub fn pool_pda(program_id: &Address, pool_id: u32) -> (Address, u8) {
    Address::find_program_address(&[POOL_SEED, &pool_id.to_le_bytes()], program_id)
}

pub fn sol_vault_pda(program_id: &Address, pool_id: u32) -> (Address, u8) {
    Address::find_program_address(&[SOL_VAULT_SEED, &pool_id.to_le_bytes()], program_id)
}

pub fn vault_auth_pda(program_id: &Address, pool_id: u32) -> (Address, u8) {
    Address::find_program_address(&[VAULT_AUTH_SEED, &pool_id.to_le_bytes()], program_id)
}

pub fn lane_pda(program_id: &Address, pool_id: u32, lane_id: u8) -> (Address, u8) {
    Address::find_program_address(&[LANE_SEED, &pool_id.to_le_bytes(), &[lane_id]], program_id)
}

pub fn lane_rent_pda(program_id: &Address, pool_id: u32, lane_id: u8) -> (Address, u8) {
    Address::find_program_address(
        &[LANE_RENT_SEED, &pool_id.to_le_bytes(), &[lane_id]],
        program_id,
    )
}

pub fn nf_page_pda(program_id: &Address, pool_id: u32, lane_id: u8, page_seq: u64) -> (Address, u8) {
    Address::find_program_address(
        &[
            NF_PAGE_SEED,
            &pool_id.to_le_bytes(),
            &[lane_id],
            &page_seq.to_le_bytes(),
        ],
        program_id,
    )
}

pub fn subtree_pda(
    program_id: &Address,
    pool_id: u32,
    lane_id: u8,
    page_seq: u64,
) -> (Address, u8) {
    Address::find_program_address(
        &[
            SUBTREE_SEED,
            &pool_id.to_le_bytes(),
            &[lane_id],
            &page_seq.to_le_bytes(),
        ],
        program_id,
    )
}

pub fn subroot_pda(
    program_id: &Address,
    pool_id: u32,
    lane_id: u8,
    root_page_seq: u64,
) -> (Address, u8) {
    Address::find_program_address(
        &[
            SUBROOT_SEED,
            &pool_id.to_le_bytes(),
            &[lane_id],
            &root_page_seq.to_le_bytes(),
        ],
        program_id,
    )
}

pub fn memo_pda(program_id: &Address, pool_id: u32, lane_id: u8, page_seq: u64) -> (Address, u8) {
    Address::find_program_address(
        &[
            MEMO_SEED,
            &pool_id.to_le_bytes(),
            &[lane_id],
            &page_seq.to_le_bytes(),
        ],
        program_id,
    )
}

pub fn checkpoint_pda(program_id: &Address, pool_id: u32, slot_idx: u16) -> (Address, u8) {
    Address::find_program_address(
        &[CKPT_SEED, &pool_id.to_le_bytes(), &slot_idx.to_le_bytes()],
        program_id,
    )
}

pub fn nullifier_pda(program_id: &Address, pool_id: u32, nf: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(
        &[NULLIFIER_SEED, &pool_id.to_le_bytes(), nf],
        program_id,
    )
}

pub fn escrow_pda(program_id: &Address, pool_id: u32, shard: u8) -> (Address, u8) {
    Address::find_program_address(&[ESCROW_SEED, &pool_id.to_le_bytes(), &[shard]], program_id)
}

pub fn unwrap_pda(program_id: &Address, pool_id: u32, nf0: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[UNWRAP_SEED, &pool_id.to_le_bytes(), nf0], program_id)
}

pub fn expected_ata(owner: &Address, token_program: &Address, mint: &Address) -> Address {
    Address::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ATA_PROGRAM_ID,
    )
    .0
}
