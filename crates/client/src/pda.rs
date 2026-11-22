//! Deterministic Audren PDA derivation helpers matching `program/src/state.rs` bit-for-bit.

use audren_core::{
    ASSOCIATED_TOKEN_PROGRAM_ID, CKPT_SEED, ESCROW_SEED, LANE_RENT_SEED, LANE_SEED, MEMO_SEED,
    NF_PAGE_SEED, NULLIFIER_SEED, POOL_SEED, SOL_VAULT_SEED, SUBROOT_SEED, SUBTREE_SEED,
    UNWRAP_SEED, VAULT_AUTH_SEED,
};
use solana_address::Address;

pub fn derive_pool_pda(program_id: &Address, pool_id: u32) -> (Address, u8) {
    Address::find_program_address(&[POOL_SEED, &pool_id.to_le_bytes()], program_id)
}

pub fn derive_sol_vault_pda(program_id: &Address, pool_id: u32) -> (Address, u8) {
    Address::find_program_address(&[SOL_VAULT_SEED, &pool_id.to_le_bytes()], program_id)
}

pub fn derive_vault_auth_pda(program_id: &Address, pool_id: u32) -> (Address, u8) {
    Address::find_program_address(&[VAULT_AUTH_SEED, &pool_id.to_le_bytes()], program_id)
}

pub fn derive_lane_pda(program_id: &Address, pool_id: u32, lane_id: u8) -> (Address, u8) {
    Address::find_program_address(&[LANE_SEED, &pool_id.to_le_bytes(), &[lane_id]], program_id)
}

pub fn derive_lane_rent_pda(program_id: &Address, pool_id: u32, lane_id: u8) -> (Address, u8) {
    Address::find_program_address(
        &[LANE_RENT_SEED, &pool_id.to_le_bytes(), &[lane_id]],
        program_id,
    )
}

pub fn derive_subtree_pda(
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

pub fn derive_subroot_pda(
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

pub fn derive_memo_pda(
    program_id: &Address,
    pool_id: u32,
    lane_id: u8,
    page_seq: u64,
) -> (Address, u8) {
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

pub fn derive_nf_page_pda(
    program_id: &Address,
    pool_id: u32,
    lane_id: u8,
    page_seq: u64,
) -> (Address, u8) {
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

pub fn derive_checkpoint_pda(program_id: &Address, pool_id: u32, slot_idx: u16) -> (Address, u8) {
    Address::find_program_address(
        &[CKPT_SEED, &pool_id.to_le_bytes(), &slot_idx.to_le_bytes()],
        program_id,
    )
}

pub fn derive_nullifier_pda(program_id: &Address, pool_id: u32, nf: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[NULLIFIER_SEED, &pool_id.to_le_bytes(), nf], program_id)
}

pub fn derive_escrow_pda(program_id: &Address, pool_id: u32, shard_id: u8) -> (Address, u8) {
    Address::find_program_address(
        &[ESCROW_SEED, &pool_id.to_le_bytes(), &[shard_id]],
        program_id,
    )
}

pub fn derive_unwrap_pda(program_id: &Address, pool_id: u32, nf0: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[UNWRAP_SEED, &pool_id.to_le_bytes(), nf0], program_id)
}

pub fn derive_ata(owner: &Address, token_program: &Address, mint: &Address) -> Address {
    let ata_prog = Address::new_from_array(ASSOCIATED_TOKEN_PROGRAM_ID);
    Address::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ata_prog,
    )
    .0
}
