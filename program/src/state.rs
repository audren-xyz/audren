//! On-chain account PDA derivation, validation, and zero-copy state accessors (Pinocchio).
//!
//! Hot read paths verify PDA authenticity using single-shot `Address::create_program_address`
//! with the canonical bump persisted inside program-owned state (`PoolState`, `PageHeader`,
//! `AppendLaneState`, sentinel accounts), avoiding repeated `find_program_address` SHA-256 loops.

use audren_core::{
    lane_of_page_id,
    layout::{
        read_page_witness, write_page_note, AppendLaneState, NoteEntry, PageHeader, PoolState,
        LANE_STATE_LEN, PAGE_LEN, PAGE_RENT_MAGIC, POOL_STATE_LEN, SENTINEL_ACCOUNT_LEN,
        SOL_VAULT_MAGIC,
    },
    AudrenError, Bytes32, ASSOCIATED_TOKEN_PROGRAM_ID, CLASSIC_TOKEN_PROGRAM_ID, ESCROW_SEED,
    LANE_RENT_SEED, LANE_SEED, MAX_APPEND_LANES, MAX_ESCROW_SHARDS, NULLIFIER_SEED,
    PAGE_RENT_SEED, PAGE_SEED, POOL_SEED, PROOF_BUFFER_SEED, PROTOCOL_VERSION, SOL_VAULT_SEED,
    TOKEN_2022_PROGRAM_ID, UNWRAP_SEED, VAULT_AUTH_SEED,
};
use pinocchio::{error::ProgramError, AccountView, Address};

pub type Point = Bytes32;

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

/// Single-shot PDA derivation from a trusted canonical bump (`1` SHA-256 call vs up to `255`).
#[inline(always)]
pub fn create_pda_checked(seeds: &[&[u8]], program_id: &Address) -> Result<Address, ProgramError> {
    Address::create_program_address(seeds, program_id).map_err(|_| err(AudrenError::InvalidPda))
}

pub fn pool_pda(program_id: &Address, pool_id: u32) -> (Address, u8) {
    Address::find_program_address(&[POOL_SEED, &pool_id.to_le_bytes()], program_id)
}

pub fn page_pda(program_id: &Address, pool_id: u32, page_id: u64) -> (Address, u8) {
    Address::find_program_address(
        &[PAGE_SEED, &pool_id.to_le_bytes(), &page_id.to_le_bytes()],
        program_id,
    )
}

pub fn nullifier_pda(program_id: &Address, pool_id: u32, nullifier: &Bytes32) -> (Address, u8) {
    Address::find_program_address(
        &[NULLIFIER_SEED, &pool_id.to_le_bytes(), nullifier],
        program_id,
    )
}

pub fn vault_auth_pda(program_id: &Address, pool_id: u32) -> (Address, u8) {
    Address::find_program_address(&[VAULT_AUTH_SEED, &pool_id.to_le_bytes()], program_id)
}

/// Single-shot `vault_auth` address derivation from `PoolState::vault_auth_bump`.
#[inline]
pub fn vault_auth_from_pool(program_id: &Address, pool: &PoolState) -> Result<Address, ProgramError> {
    let pool_le = pool.pool_id.to_le_bytes();
    let bump = [pool.vault_auth_bump];
    create_pda_checked(&[VAULT_AUTH_SEED, &pool_le, &bump], program_id)
}

/// Single-shot `sol_vault` address derivation from `PoolState::sol_vault_bump`.
#[inline]
pub fn sol_vault_from_pool(program_id: &Address, pool: &PoolState) -> Result<Address, ProgramError> {
    let pool_le = pool.pool_id.to_le_bytes();
    let bump = [pool.sol_vault_bump];
    create_pda_checked(&[SOL_VAULT_SEED, &pool_le, &bump], program_id)
}

pub fn sol_vault_pda(program_id: &Address, pool_id: u32) -> (Address, u8) {
    Address::find_program_address(&[SOL_VAULT_SEED, &pool_id.to_le_bytes()], program_id)
}

pub fn page_rent_pda(program_id: &Address, pool_id: u32) -> (Address, u8) {
    Address::find_program_address(&[PAGE_RENT_SEED, &pool_id.to_le_bytes()], program_id)
}

pub fn lane_pda(
    program_id: &Address,
    pool_id: u32,
    lane_id: u8,
) -> Result<(Address, u8), ProgramError> {
    ensure(
        lane_id >= 1 && lane_id < MAX_APPEND_LANES,
        AudrenError::InvalidLane,
    )?;
    Ok(Address::find_program_address(
        &[LANE_SEED, &pool_id.to_le_bytes(), &[lane_id]],
        program_id,
    ))
}

pub fn lane_rent_pda(
    program_id: &Address,
    pool_id: u32,
    lane_id: u8,
) -> Result<(Address, u8), ProgramError> {
    ensure(
        lane_id >= 1 && lane_id < MAX_APPEND_LANES,
        AudrenError::InvalidLane,
    )?;
    Ok(Address::find_program_address(
        &[LANE_RENT_SEED, &pool_id.to_le_bytes(), &[lane_id]],
        program_id,
    ))
}

pub fn escrow_pda(
    program_id: &Address,
    pool_id: u32,
    shard_id: u8,
) -> Result<(Address, u8), ProgramError> {
    ensure(shard_id < MAX_ESCROW_SHARDS, AudrenError::InvalidEscrowShard)?;
    Ok(Address::find_program_address(
        &[ESCROW_SEED, &pool_id.to_le_bytes(), &[shard_id]],
        program_id,
    ))
}

pub fn unwrap_pda(program_id: &Address, pool_id: u32, nullifier: &Bytes32) -> (Address, u8) {
    Address::find_program_address(&[UNWRAP_SEED, &pool_id.to_le_bytes(), nullifier], program_id)
}

pub fn proof_buffer_pda(program_id: &Address, authority: &Address, nonce: u64) -> (Address, u8) {
    Address::find_program_address(
        &[PROOF_BUFFER_SEED, authority.as_ref(), &nonce.to_le_bytes()],
        program_id,
    )
}

pub fn expected_ata(owner: &Address, token_program: &Address, mint: &Address) -> Address {
    let ata_prog = Address::new_from_array(ASSOCIATED_TOKEN_PROGRAM_ID);
    Address::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ata_prog,
    )
    .0
}

#[inline(always)]
pub fn check_supported_token_program(token_program: &Address) -> Result<(), ProgramError> {
    let key = token_program.as_ref();
    ensure(
        key == &CLASSIC_TOKEN_PROGRAM_ID || key == &TOKEN_2022_PROGRAM_ID,
        AudrenError::UnsupportedTokenProgram,
    )
}

pub fn load_pool(account: &AccountView, program_id: &Address) -> Result<PoolState, ProgramError> {
    ensure(account.owned_by(program_id), AudrenError::InvalidAccount)?;
    let data = account.try_borrow()?;
    ensure(data.len() == POOL_STATE_LEN, AudrenError::InvalidAccount)?;
    let state = PoolState::decode(&data).map_err(err)?;
    ensure(
        state.version == PROTOCOL_VERSION,
        AudrenError::UnsupportedVersion,
    )?;
    // Account is program-owned with valid POOL_MAGIC; `state.bump` was recorded from canonical
    // `pool_pda` on init, so single-shot `create_program_address` is 100% sound and O(1).
    let pool_le = state.pool_id.to_le_bytes();
    let bump = [state.bump];
    let expected = create_pda_checked(&[POOL_SEED, &pool_le, &bump], program_id)?;
    ensure(account.address() == &expected, AudrenError::InvalidPda)?;
    Ok(state)
}

pub fn save_pool(
    mut account: AccountView,
    program_id: &Address,
    state: &PoolState,
) -> Result<(), ProgramError> {
    ensure(
        account.is_writable() && account.owned_by(program_id),
        AudrenError::InvalidAccount,
    )?;
    let mut data = account.try_borrow_mut()?;
    state.encode(&mut data).map_err(err)
}

pub fn load_page_header(
    account: &AccountView,
    program_id: &Address,
    pool_id: u32,
) -> Result<PageHeader, ProgramError> {
    ensure(account.owned_by(program_id), AudrenError::InvalidAccount)?;
    let data = account.try_borrow()?;
    ensure(data.len() == PAGE_LEN, AudrenError::InvalidAccount)?;
    let header = PageHeader::decode(&data).map_err(err)?;
    ensure(header.pool_id == pool_id, AudrenError::WrongPool)?;
    ensure(
        header.version == PROTOCOL_VERSION,
        AudrenError::UnsupportedVersion,
    )?;
    let pool_le = pool_id.to_le_bytes();
    let page_le = header.page_id.to_le_bytes();
    let bump = [header.bump];
    let expected = create_pda_checked(&[PAGE_SEED, &pool_le, &page_le, &bump], program_id)?;
    ensure(account.address() == &expected, AudrenError::InvalidPda)?;
    Ok(header)
}

pub fn append_note_to_page(
    mut account: AccountView,
    program_id: &Address,
    pool_id: u32,
    expected_page_id: Option<u64>,
    note: &NoteEntry,
    slot: u64,
) -> Result<(u64, u8), ProgramError> {
    ensure(
        account.is_writable() && account.owned_by(program_id),
        AudrenError::InvalidAccount,
    )?;
    let account_addr = *account.address();
    let mut data = account.try_borrow_mut()?;
    ensure(data.len() == PAGE_LEN, AudrenError::InvalidAccount)?;
    let mut header = PageHeader::decode(&data).map_err(err)?;
    ensure(header.pool_id == pool_id, AudrenError::WrongPool)?;
    if let Some(expected_id) = expected_page_id {
        ensure(header.page_id == expected_id, AudrenError::WrongPool)?;
    } else {
        ensure(
            lane_of_page_id(header.page_id) >= 1,
            AudrenError::InvalidLane,
        )?;
    }
    let pool_le = pool_id.to_le_bytes();
    let page_le = header.page_id.to_le_bytes();
    let bump = [header.bump];
    let expected = create_pda_checked(&[PAGE_SEED, &pool_le, &page_le, &bump], program_id)?;
    ensure(account_addr == expected, AudrenError::InvalidPda)?;
    let idx = header.count as usize;
    ensure(
        !header.closed && idx < audren_core::layout::PAGE_CAPACITY,
        AudrenError::PageFull,
    )?;
    write_page_note(&mut data, idx, note).map_err(err)?;
    header.count = header
        .count
        .checked_add(1)
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    if (header.count as usize) == audren_core::layout::PAGE_CAPACITY {
        header.closed = true;
        header.closed_slot = slot;
    }
    header.encode(&mut data).map_err(err)?;
    Ok((header.page_id, idx as u8))
}

pub fn load_lane(
    account: &AccountView,
    program_id: &Address,
    pool_id: u32,
    lane_id: u8,
) -> Result<AppendLaneState, ProgramError> {
    ensure(
        lane_id >= 1 && lane_id < MAX_APPEND_LANES,
        AudrenError::InvalidLane,
    )?;
    ensure(account.owned_by(program_id), AudrenError::InvalidAccount)?;
    let data = account.try_borrow()?;
    ensure(data.len() == LANE_STATE_LEN, AudrenError::InvalidAccount)?;
    let state = AppendLaneState::decode(&data).map_err(err)?;
    ensure(
        state.version == PROTOCOL_VERSION
            && state.pool_id == pool_id
            && state.lane_id == lane_id,
        AudrenError::InvalidLane,
    )?;
    let pool_le = pool_id.to_le_bytes();
    let lane_b = [lane_id];
    let bump = [state.bump];
    let expected = create_pda_checked(&[LANE_SEED, &pool_le, &lane_b, &bump], program_id)?;
    ensure(account.address() == &expected, AudrenError::InvalidPda)?;
    Ok(state)
}

pub fn save_lane(
    mut account: AccountView,
    program_id: &Address,
    state: &AppendLaneState,
) -> Result<(), ProgramError> {
    ensure(
        account.is_writable() && account.owned_by(program_id),
        AudrenError::InvalidAccount,
    )?;
    let mut data = account.try_borrow_mut()?;
    state.encode(&mut data).map_err(err)
}

pub fn check_lane_rent_vault(
    account: &AccountView,
    program_id: &Address,
    pool_id: u32,
    lane_id: u8,
) -> Result<(), ProgramError> {
    ensure(
        lane_id >= 1 && lane_id < MAX_APPEND_LANES,
        AudrenError::InvalidLane,
    )?;
    ensure(account.owned_by(program_id), AudrenError::InvalidPda)?;
    let data = account.try_borrow()?;
    ensure(
        data.len() == SENTINEL_ACCOUNT_LEN && data[..8] == PAGE_RENT_MAGIC,
        AudrenError::InvalidMagic,
    )?;
    let pool_le = pool_id.to_le_bytes();
    let lane_b = [lane_id];
    let bump = [data[8]];
    let expected = create_pda_checked(&[LANE_RENT_SEED, &pool_le, &lane_b, &bump], program_id)?;
    ensure(account.address() == &expected, AudrenError::InvalidPda)
}

pub fn init_sentinel_bytes(
    mut account: AccountView,
    program_id: &Address,
    magic: [u8; 8],
    bump: u8,
) -> Result<(), ProgramError> {
    ensure(
        account.is_writable() && account.owned_by(program_id),
        AudrenError::InvalidAccount,
    )?;
    let mut data = account.try_borrow_mut()?;
    ensure(data.len() == SENTINEL_ACCOUNT_LEN, AudrenError::InvalidAccount)?;
    data.fill(0);
    data[..8].copy_from_slice(&magic);
    data[8] = bump;
    Ok(())
}

pub fn check_sol_vault(
    account: &AccountView,
    program_id: &Address,
    pool: &PoolState,
) -> Result<(), ProgramError> {
    let expected = sol_vault_from_pool(program_id, pool)?;
    ensure(
        account.owned_by(program_id) && account.address() == &expected,
        AudrenError::InvalidPda,
    )?;
    let data = account.try_borrow()?;
    ensure(
        data.len() == SENTINEL_ACCOUNT_LEN && data[..8] == SOL_VAULT_MAGIC,
        AudrenError::InvalidMagic,
    )
}

pub fn check_page_rent_vault(
    account: &AccountView,
    program_id: &Address,
    pool: &PoolState,
) -> Result<(), ProgramError> {
    let pool_le = pool.pool_id.to_le_bytes();
    let bump = [pool.page_rent_bump];
    let expected = create_pda_checked(&[PAGE_RENT_SEED, &pool_le, &bump], program_id)?;
    ensure(
        account.owned_by(program_id) && account.address() == &expected,
        AudrenError::InvalidPda,
    )?;
    let data = account.try_borrow()?;
    ensure(
        data.len() == SENTINEL_ACCOUNT_LEN && data[..8] == PAGE_RENT_MAGIC,
        AudrenError::InvalidMagic,
    )
}

#[inline(always)]
pub fn page_slot_witness(data: &[u8], idx: usize) -> Result<(Point, Point, Point), ProgramError> {
    read_page_witness(data, idx).map_err(err)
}
