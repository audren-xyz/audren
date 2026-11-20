//! On-chain account PDA derivation, validation, and zero-copy state accessors.

use audren_core::{
    layout::{
        read_page_witness, write_page_note, NoteEntry, PageHeader, PoolState, PAGE_LEN,
        PAGE_RENT_MAGIC, POOL_STATE_LEN, SENTINEL_ACCOUNT_LEN, SOL_VAULT_MAGIC,
    },
    AudrenError, Bytes32, ASSOCIATED_TOKEN_PROGRAM_ID, CLASSIC_TOKEN_PROGRAM_ID, ESCROW_SEED,
    MAX_ESCROW_SHARDS, NULLIFIER_SEED, PAGE_RENT_SEED, PAGE_SEED, POOL_SEED, PROOF_BUFFER_SEED,
    PROTOCOL_VERSION, SOL_VAULT_SEED, TOKEN_2022_PROGRAM_ID, VAULT_AUTH_SEED,
};
use solana_account_info::AccountInfo;
use solana_address::Address;
use solana_program_error::ProgramError;

pub type Point = Bytes32;

#[inline]
pub fn err(e: AudrenError) -> ProgramError {
    ProgramError::Custom(e as u32)
}

#[inline]
pub fn ensure(cond: bool, e: AudrenError) -> Result<(), ProgramError> {
    if cond {
        Ok(())
    } else {
        Err(err(e))
    }
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

pub fn sol_vault_pda(program_id: &Address, pool_id: u32) -> (Address, u8) {
    Address::find_program_address(&[SOL_VAULT_SEED, &pool_id.to_le_bytes()], program_id)
}

pub fn page_rent_pda(program_id: &Address, pool_id: u32) -> (Address, u8) {
    Address::find_program_address(&[PAGE_RENT_SEED, &pool_id.to_le_bytes()], program_id)
}

pub fn escrow_pda(program_id: &Address, pool_id: u32, shard_id: u8) -> Result<(Address, u8), ProgramError> {
    ensure(shard_id < MAX_ESCROW_SHARDS, AudrenError::InvalidEscrowShard)?;
    Ok(Address::find_program_address(
        &[ESCROW_SEED, &pool_id.to_le_bytes(), &[shard_id]],
        program_id,
    ))
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

#[inline]
pub fn check_supported_token_program(token_program: &Address) -> Result<(), ProgramError> {
    let key = token_program.to_bytes();
    ensure(
        key == CLASSIC_TOKEN_PROGRAM_ID || key == TOKEN_2022_PROGRAM_ID,
        AudrenError::UnsupportedTokenProgram,
    )
}

pub fn load_pool(account: &AccountInfo, program_id: &Address) -> Result<PoolState, ProgramError> {
    ensure(account.owner == program_id, AudrenError::InvalidAccount)?;
    let data = account.try_borrow_data()?;
    ensure(data.len() == POOL_STATE_LEN, AudrenError::InvalidAccount)?;
    let state = PoolState::decode(&data).map_err(err)?;
    ensure(
        state.version == PROTOCOL_VERSION,
        AudrenError::UnsupportedVersion,
    )?;
    let (expected, _) = pool_pda(program_id, state.pool_id);
    ensure(*account.key == expected, AudrenError::InvalidPda)?;
    Ok(state)
}

pub fn save_pool(
    account: &AccountInfo,
    program_id: &Address,
    state: &PoolState,
) -> Result<(), ProgramError> {
    ensure(
        account.is_writable && account.owner == program_id,
        AudrenError::InvalidAccount,
    )?;
    let mut data = account.try_borrow_mut_data()?;
    state.encode(&mut data).map_err(err)
}

pub fn load_page_header(
    account: &AccountInfo,
    program_id: &Address,
    pool_id: u32,
) -> Result<PageHeader, ProgramError> {
    ensure(account.owner == program_id, AudrenError::InvalidAccount)?;
    let data = account.try_borrow_data()?;
    ensure(data.len() == PAGE_LEN, AudrenError::InvalidAccount)?;
    let header = PageHeader::decode(&data).map_err(err)?;
    ensure(header.pool_id == pool_id, AudrenError::WrongPool)?;
    ensure(
        header.version == PROTOCOL_VERSION,
        AudrenError::UnsupportedVersion,
    )?;
    let (expected, _) = page_pda(program_id, pool_id, header.page_id);
    ensure(*account.key == expected, AudrenError::InvalidPda)?;
    Ok(header)
}

pub fn append_note_to_page(
    account: &AccountInfo,
    program_id: &Address,
    pool_id: u32,
    expected_page_id: u64,
    note: &NoteEntry,
) -> Result<u8, ProgramError> {
    ensure(
        account.is_writable && account.owner == program_id,
        AudrenError::InvalidAccount,
    )?;
    let mut data = account.try_borrow_mut_data()?;
    ensure(data.len() == PAGE_LEN, AudrenError::InvalidAccount)?;
    let mut header = PageHeader::decode(&data).map_err(err)?;
    ensure(
        header.pool_id == pool_id && header.page_id == expected_page_id,
        AudrenError::WrongPool,
    )?;
    let (expected, _) = page_pda(program_id, pool_id, expected_page_id);
    ensure(*account.key == expected, AudrenError::InvalidPda)?;
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
    }
    header.encode(&mut data).map_err(err)?;
    Ok(idx as u8)
}

pub fn check_sentinel(
    account: &AccountInfo,
    program_id: &Address,
    expected_pda: &Address,
    magic: [u8; 8],
) -> Result<(), ProgramError> {
    ensure(
        account.owner == program_id && account.key == expected_pda,
        AudrenError::InvalidPda,
    )?;
    let data = account.try_borrow_data()?;
    ensure(
        data.len() == SENTINEL_ACCOUNT_LEN && data[..8] == magic,
        AudrenError::InvalidMagic,
    )
}

pub fn init_sentinel_bytes(
    account: &AccountInfo,
    program_id: &Address,
    magic: [u8; 8],
    bump: u8,
) -> Result<(), ProgramError> {
    ensure(
        account.is_writable && account.owner == program_id,
        AudrenError::InvalidAccount,
    )?;
    let mut data = account.try_borrow_mut_data()?;
    ensure(data.len() == SENTINEL_ACCOUNT_LEN, AudrenError::InvalidAccount)?;
    data.fill(0);
    data[..8].copy_from_slice(&magic);
    data[8] = bump;
    Ok(())
}

pub fn check_sol_vault(
    account: &AccountInfo,
    program_id: &Address,
    pool_id: u32,
) -> Result<(), ProgramError> {
    let (expected, _) = sol_vault_pda(program_id, pool_id);
    check_sentinel(account, program_id, &expected, SOL_VAULT_MAGIC)
}

pub fn check_page_rent_vault(
    account: &AccountInfo,
    program_id: &Address,
    pool_id: u32,
) -> Result<(), ProgramError> {
    let (expected, _) = page_rent_pda(program_id, pool_id);
    check_sentinel(account, program_id, &expected, PAGE_RENT_MAGIC)
}

#[inline]
pub fn page_slot_witness(data: &[u8], idx: usize) -> Result<(Point, Point, Point), ProgramError> {
    read_page_witness(data, idx).map_err(err)
}
