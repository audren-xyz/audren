//! Minimal `#![no_std]` sBPFv3 SPL Token-2022 TransferHook Program for LiteSVM Security Testing.
//!
//! Implements the real SPL TransferHook Interface (`spl-transfer-hook-interface:execute`) with:
//!   - `TAG_INIT_META` (0): initializes `["extra-account-metas", mint]` TLV (`51 B`) pointing to
//!     writable `["hook_state", mint]` (`16 B`) and optionally a second writable extra account
//!     (for adversarial signer-escalation testing when `extra_count == 2`).
//!   - `TAG_SET_MODE` (1): toggles `attack_mode` (`0 = honest increment`, `1 = attempt SystemProgram::Transfer
//!     signer escalation from accounts[6] -> accounts[5]`).
//!   - Execute discriminator `[105, 37, 101, 197, 75, 251, 102, 26]`: invoked automatically by
//!     real `token2022.so` during `TransferChecked`!

#![no_std]
#![allow(unexpected_cfgs)]

use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::{CreateAccount, Transfer};

pinocchio::program_entrypoint!(process, 16);
pinocchio::no_allocator!();
pinocchio::nostd_panic_handler!();

const EXECUTE_DISC: [u8; 8] = [105, 37, 101, 197, 75, 251, 102, 26];
const EXTRA_META_SEED: &[u8] = b"extra-account-metas";
const HOOK_STATE_SEED: &[u8] = b"hook_state";

const TAG_INIT_META: u8 = 0;
const TAG_SET_MODE: u8 = 1;

pub fn process(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if data.len() >= 8 && data[0..8] == EXECUTE_DISC {
        return handle_execute(program_id, accounts);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    match data[0] {
        TAG_INIT_META => handle_init_meta(program_id, accounts, &data[1..]),
        TAG_SET_MODE => handle_set_mode(program_id, accounts, &data[1..]),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn handle_init_meta(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    // accounts: [0] payer (signer, wr), [1] mint, [2] extra_meta_pda (wr), [3] hook_state_pda (wr),
    //           [4] sys_prog, optional [5] extra_victim_pubkey (for mode=1 escalation test)
    if accounts.len() < 5 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let include_second = !data.is_empty() && data[0] == 1 && accounts.len() >= 6;

    let (exp_meta, meta_bump) =
        Address::find_program_address(&[EXTRA_META_SEED, accounts[1].address().as_ref()], program_id);
    let (exp_state, state_bump) =
        Address::find_program_address(&[HOOK_STATE_SEED, accounts[1].address().as_ref()], program_id);
    if accounts[2].address() != &exp_meta || accounts[3].address() != &exp_state {
        return Err(ProgramError::InvalidSeeds);
    }

    let rent = Rent::get()?;
    let meta_count: usize = if include_second { 2 } else { 1 };
    let payload_len: u32 = (4 + 35 * meta_count) as u32;
    let total_meta_len: usize = 8 + 4 + (payload_len as usize);

    let mb = [meta_bump];
    let meta_seeds = [
        Seed::from(EXTRA_META_SEED),
        Seed::from(accounts[1].address().as_ref()),
        Seed::from(&mb),
    ];
    CreateAccount {
        from: &accounts[0],
        to: &accounts[2],
        lamports: rent.try_minimum_balance(total_meta_len)?,
        space: total_meta_len as u64,
        owner: program_id,
    }
    .invoke_signed(&[Signer::from(&meta_seeds)])?;

    let state_addr = *accounts[3].address();
    let victim_addr = if include_second {
        *accounts[5].address()
    } else {
        Address::new_from_array([0u8; 32])
    };
    {
        let mut md = accounts[2].try_borrow_mut()?;
        md[0..8].copy_from_slice(&EXECUTE_DISC);
        md[8..12].copy_from_slice(&payload_len.to_le_bytes());
        md[12..16].copy_from_slice(&(meta_count as u32).to_le_bytes());
        // Entry 0: literal pubkey = hook_state_pda (is_signer = 0, is_writable = 1)
        md[16] = 0; // discriminator 0 = literal Pubkey
        md[17..49].copy_from_slice(state_addr.as_ref());
        md[49] = 0; // is_signer = false
        md[50] = 1; // is_writable = true
        if include_second {
            md[51] = 0;
            md[52..84].copy_from_slice(victim_addr.as_ref());
            md[84] = 0;
            md[85] = 1;
        }
    }

    let sb = [state_bump];
    let state_seeds = [
        Seed::from(HOOK_STATE_SEED),
        Seed::from(accounts[1].address().as_ref()),
        Seed::from(&sb),
    ];
    CreateAccount {
        from: &accounts[0],
        to: &accounts[3],
        lamports: rent.try_minimum_balance(16)?,
        space: 16,
        owner: program_id,
    }
    .invoke_signed(&[Signer::from(&state_seeds)])?;

    Ok(())
}

fn handle_set_mode(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if data.is_empty() || accounts.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    if !accounts[0].owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }
    let mut sd = accounts[0].try_borrow_mut()?;
    sd[8] = data[0];
    Ok(())
}

fn handle_execute(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    // Token-2022 TransferHook Execute layout:
    //   [0] source, [1] mint, [2] dest, [3] authority, [4] extra_meta_pda, [5] hook_state_pda,
    //   optional [6] victim_acc
    if accounts.len() < 6 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if !accounts[5].owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }
    let attack_mode = {
        let mut sd = accounts[5].try_borrow_mut()?;
        let cnt = u64::from_le_bytes(sd[0..8].try_into().unwrap());
        sd[0..8].copy_from_slice(&(cnt + 1).to_le_bytes());
        sd[8]
    };

    if attack_mode == 1 {
        // Adversarial hook tries to steal lamports from extra account [6] (e.g., payer or authority)
        // via SystemProgram::Transfer — MUST fail because Audren strips `is_signer` on ALL trailing accounts!
        if accounts.len() < 7 {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        Transfer {
            from: &accounts[6],
            to: &accounts[5],
            lamports: 1_000_000,
        }
        .invoke()?;
    }
    Ok(())
}
