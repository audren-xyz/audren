//! Deterministic PDA derivation helpers matching `programs/audren/program/src/state.rs` byte-for-byte.

use audren_core::{
    ASSOCIATED_TOKEN_PROGRAM_ID, ESCROW_SEED, NULLIFIER_SEED, PAGE_RENT_SEED, PAGE_SEED, POOL_SEED,
    PROOF_BUFFER_SEED, SOL_VAULT_SEED, VAULT_AUTH_SEED,
};
use solana_address::Address;

#[inline]
pub fn derive_pool_pda(program_id: &Address, pool_id: u32) -> (Address, u8) {
    let id_le = pool_id.to_le_bytes();
    Address::find_program_address(&[POOL_SEED, &id_le], program_id)
}

#[inline]
pub fn derive_vault_auth_pda(program_id: &Address, pool_id: u32) -> (Address, u8) {
    let id_le = pool_id.to_le_bytes();
    Address::find_program_address(&[VAULT_AUTH_SEED, &id_le], program_id)
}

#[inline]
pub fn derive_sol_vault_pda(program_id: &Address, pool_id: u32) -> (Address, u8) {
    let id_le = pool_id.to_le_bytes();
    Address::find_program_address(&[SOL_VAULT_SEED, &id_le], program_id)
}

#[inline]
pub fn derive_page_rent_vault_pda(program_id: &Address, pool_id: u32) -> (Address, u8) {
    let id_le = pool_id.to_le_bytes();
    Address::find_program_address(&[PAGE_RENT_SEED, &id_le], program_id)
}

#[inline]
pub fn derive_epoch_page_pda(program_id: &Address, pool_id: u32, page_id: u64) -> (Address, u8) {
    let id_le = pool_id.to_le_bytes();
    let page_le = page_id.to_le_bytes();
    Address::find_program_address(&[PAGE_SEED, &id_le, &page_le], program_id)
}

#[inline]
pub fn derive_nullifier_pda(
    program_id: &Address,
    pool_id: u32,
    nullifier: &[u8; 32],
) -> (Address, u8) {
    let id_le = pool_id.to_le_bytes();
    Address::find_program_address(&[NULLIFIER_SEED, &id_le, nullifier], program_id)
}

#[inline]
pub fn derive_swap_escrow_pda(program_id: &Address, pool_id: u32, shard_id: u8) -> (Address, u8) {
    let id_le = pool_id.to_le_bytes();
    Address::find_program_address(&[ESCROW_SEED, &id_le, &[shard_id]], program_id)
}

#[inline]
pub fn derive_proof_buffer_pda(
    program_id: &Address,
    authority: &Address,
    nonce: u64,
) -> (Address, u8) {
    let nonce_le = nonce.to_le_bytes();
    Address::find_program_address(
        &[PROOF_BUFFER_SEED, authority.as_ref(), &nonce_le],
        program_id,
    )
}

/// Derive the canonical Associated Token Account for `(owner, token_program, mint)`.
#[inline]
pub fn derive_ata(owner: &Address, token_program: &Address, mint: &Address) -> Address {
    let ata_prog = Address::new_from_array(ASSOCIATED_TOKEN_PROGRAM_ID);
    Address::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ata_prog,
    )
    .0
}
