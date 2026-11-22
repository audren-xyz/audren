//! Multi-Asset & Adversarial sBPFv3 Mock AMM Router for Audren LiteSVM verification.
//!
//! Supports both honest swaps (SPL->SOL, SOL->SPL, SPL->SPL across multiple indexed pools + up to
//! 64 trailing router accounts) and adversarial router attacks to prove both baseline exploitability
//! adversarial attacks strictly blocked by the Audren escrow firewall:
//!   - `TAG_INIT_DEX` (0): init `dex_pool` PDA `["dex_pool", pool_idx]` with `(rate_bps, liq)`
//!   - `TAG_SET_RATE` (1): update `rate_bps` on a `dex_pool`
//!   - `TAG_SWAP_SPL_TO_SOL` (3): SPL/T22 -> Native SOL (reads `rate_bps` from passed `dex_pool`)
//!   - `TAG_SWAP_SOL_TO_SPL` (4): Native SOL -> SPL/T22 (with optional `leave_dust_lamports`)
//!   - `TAG_SWAP_SPL_TO_SPL` (5): SPL/T22 -> SPL/T22 with `attack_mode`:
//!       0 = honest swap
//!       1 = `SystemProgram::Assign(escrow, attacker_prog)` (permanent escrow shard ownership hijack)
//!       2 = `spl_token::SetAuthority(AccountOwner -> attacker)` on unrelated `other_escrow_ata`
//!       3 = `SystemProgram::Transfer(escrow -> attacker)` (SPL->SPL escrow lamport drain)
//!       4 = Token-2022 `Reallocate([MemoTransfer]) + EnableRequiredMemoTransfers` on `escrow_in`
//!       5 = `spl_token::Approve(delegate = attacker)` on `escrow_in`
//!       6 = Create uninitialized canonical escrow ATA + hijack owner to `attacker`

#![no_std]
#![allow(unexpected_cfgs)]

use pinocchio::{
    cpi::{invoke, invoke_signed, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    sysvars::{rent::Rent, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};

pinocchio::program_entrypoint!(process, 64);
pinocchio::no_allocator!();
pinocchio::nostd_panic_handler!();

#[cfg_attr(any(target_os = "solana", target_arch = "bpf"), link_section = ".security.txt")]
#[allow(dead_code)]
#[used]
#[no_mangle]
pub static SECURITY_TXT: &str = concat!(
    "=======BEGIN SECURITY.TXT V1=======\0",
    "name\0Audren Mock Router\0",
    "project_url\0https://audren.xyz\0",
    "contacts\0email:security@audren.xyz\0",
    "policy\0https://github.com/audren-xyz/audren/blob/main/SECURITY.md\0",
    "preferred_languages\0en\0",
    "source_code\0https://github.com/audren-xyz/audren\0",
    "source_release\0v", env!("CARGO_PKG_VERSION"), "\0",
    "=======END SECURITY.TXT V1=======\0"
);

pub const DEX_POOL_SEED: &[u8] = b"dex_pool";
pub const DEX_POOL_LEN: usize = 16; // rate_bps (u64) | bump (u8) | pool_idx (u8) | pad (6)

pub const TAG_INIT_DEX: u8 = 0;
pub const TAG_SET_RATE: u8 = 1;
pub const TAG_SWAP_SPL_TO_SOL: u8 = 3;
pub const TAG_SWAP_SOL_TO_SPL: u8 = 4;
pub const TAG_SWAP_SPL_TO_SPL: u8 = 5;
pub const TAG_MULTI_HOP_SWAP: u8 = 6;
pub const TAG_YIELD_VAULT: u8 = 7;

const TOKEN_IX_APPROVE: u8 = 4;
const TOKEN_IX_SET_AUTHORITY: u8 = 6;
const TOKEN_IX_MINT_TO: u8 = 7;
const TOKEN_IX_BURN: u8 = 8;
const TOKEN_IX_CLOSE_ACCOUNT: u8 = 9;
const TOKEN_IX_TRANSFER_CHECKED: u8 = 12;
const AUTHORITY_TYPE_ACCOUNT_OWNER: u8 = 2;
const AUTHORITY_TYPE_CLOSE_ACCOUNT: u8 = 3;

pub fn process(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    match data[0] {
        TAG_INIT_DEX => {
            // data: [tag(1), rate_bps(8), liquidity(8), optional pool_idx(1)]
            if data.len() != 17 && data.len() != 18 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let [payer, pool, ..] = accounts else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };
            let rate_bps = u64::from_le_bytes(data[1..9].try_into().unwrap());
            let liq = u64::from_le_bytes(data[9..17].try_into().unwrap());
            let pool_idx = if data.len() == 18 { data[17] } else { 0 };
            let idx_b = [pool_idx];
            let (exp, bump) = if pool_idx == 0 {
                Address::find_program_address(&[DEX_POOL_SEED], program_id)
            } else {
                Address::find_program_address(&[DEX_POOL_SEED, &idx_b], program_id)
            };
            if pool.address() != &exp {
                return Err(ProgramError::InvalidSeeds);
            }
            let rent = Rent::get()?.try_minimum_balance(DEX_POOL_LEN)?;
            let b = [bump];
            if pool_idx == 0 {
                let seeds = [Seed::from(DEX_POOL_SEED), Seed::from(&b)];
                CreateAccount {
                    from: payer,
                    to: pool,
                    lamports: rent + liq,
                    space: DEX_POOL_LEN as u64,
                    owner: program_id,
                }
                .invoke_signed(&[Signer::from(&seeds)])?;
            } else {
                let seeds = [Seed::from(DEX_POOL_SEED), Seed::from(&idx_b), Seed::from(&b)];
                CreateAccount {
                    from: payer,
                    to: pool,
                    lamports: rent + liq,
                    space: DEX_POOL_LEN as u64,
                    owner: program_id,
                }
                .invoke_signed(&[Signer::from(&seeds)])?;
            }
            let mut d = pool.try_borrow_mut()?;
            d[0..8].copy_from_slice(&rate_bps.to_le_bytes());
            d[8] = bump;
            d[9] = pool_idx;
            Ok(())
        }
        TAG_SET_RATE => {
            if data.len() != 9 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let [pool, ..] = accounts else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };
            let rate_bps = u64::from_le_bytes(data[1..9].try_into().unwrap());
            let mut d = pool.try_borrow_mut()?;
            d[0..8].copy_from_slice(&rate_bps.to_le_bytes());
            Ok(())
        }
        TAG_SWAP_SPL_TO_SOL => {
            // data: [tag(1), amount_in(8), decimals(1)] (+ optional trailing routing payload)
            if data.len() < 10 {
                return Err(ProgramError::InvalidInstructionData);
            }
            // accounts: [0] escrow (signer), [1] escrow_in_ata, [2] dex_in_vault,
            //           [3] dex_sol_pool, [4] mint_in, [5] token_prog, [6..] optional route accounts
            let [escrow, escrow_in_ata, dex_in_vault, dex_sol_pool, mint_in, token_prog, ..] =
                accounts
            else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };
            if !escrow.is_signer() || !dex_sol_pool.owned_by(program_id) {
                return Err(ProgramError::MissingRequiredSignature);
            }
            let amount_in = u64::from_le_bytes(data[1..9].try_into().unwrap());
            let decimals = data[9];
            let rate = {
                let d = dex_sol_pool.try_borrow()?;
                u64::from_le_bytes(d[0..8].try_into().unwrap())
            };
            let actual_sol_out = ((amount_in as u128) * (rate as u128) / 10_000u128) as u64;

            let mut ix_data = [0u8; 10];
            ix_data[0] = TOKEN_IX_TRANSFER_CHECKED;
            ix_data[1..9].copy_from_slice(&amount_in.to_le_bytes());
            ix_data[9] = decimals;
            let views: [&AccountView; 4] = [escrow_in_ata, mint_in, dex_in_vault, escrow];
            let metas = [
                InstructionAccount::writable(views[0].address()),
                InstructionAccount::readonly(views[1].address()),
                InstructionAccount::writable(views[2].address()),
                InstructionAccount::readonly_signer(views[3].address()),
            ];
            let ix = InstructionView {
                program_id: token_prog.address(),
                accounts: &metas,
                data: &ix_data,
            };
            invoke_signed(&ix, &views, &[])?;

            let pool_bal = dex_sol_pool.lamports();
            if pool_bal < actual_sol_out {
                return Err(ProgramError::InsufficientFunds);
            }
            dex_sol_pool.set_lamports(pool_bal - actual_sol_out);
            escrow.set_lamports(
                escrow
                    .lamports()
                    .checked_add(actual_sol_out)
                    .ok_or(ProgramError::ArithmeticOverflow)?,
            );
            Ok(())
        }
        TAG_SWAP_SOL_TO_SPL => {
            // data: [tag(1), amount_in(8), out_amount(8), decimals(1), leave_dust_lamports(8)] = 26 B
            if data.len() != 26 {
                return Err(ProgramError::InvalidInstructionData);
            }
            // accounts: [0] escrow (signer), [1] dex_sol_pool, [2] dex_spl_vault (owner = dex_sol_pool),
            //           [3] escrow_out_ata, [4] mint_out, [5] token_prog, [6] sys
            let [escrow, dex_sol_pool, dex_spl_vault, escrow_out_ata, mint_out, token_prog, _sys, ..] =
                accounts
            else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };
            if !escrow.is_signer() || !dex_sol_pool.owned_by(program_id) {
                return Err(ProgramError::MissingRequiredSignature);
            }
            let amount_in = u64::from_le_bytes(data[1..9].try_into().unwrap());
            let out_amount = u64::from_le_bytes(data[9..17].try_into().unwrap());
            let decimals = data[17];
            let leave_dust = u64::from_le_bytes(data[18..26].try_into().unwrap());
            let spend_sol = amount_in
                .checked_sub(leave_dust)
                .ok_or(ProgramError::InvalidInstructionData)?;

            Transfer {
                from: escrow,
                to: dex_sol_pool,
                lamports: spend_sol,
            }
            .invoke()?;

            let (bump, pool_idx) = {
                let d = dex_sol_pool.try_borrow()?;
                (d[8], d[9])
            };
            let b = [bump];
            let idx_b = [pool_idx];
            let mut ix_data = [0u8; 10];
            ix_data[0] = TOKEN_IX_TRANSFER_CHECKED;
            ix_data[1..9].copy_from_slice(&out_amount.to_le_bytes());
            ix_data[9] = decimals;
            let views: [&AccountView; 4] = [dex_spl_vault, mint_out, escrow_out_ata, dex_sol_pool];
            let metas = [
                InstructionAccount::writable(views[0].address()),
                InstructionAccount::readonly(views[1].address()),
                InstructionAccount::writable(views[2].address()),
                InstructionAccount::readonly_signer(views[3].address()),
            ];
            let ix = InstructionView {
                program_id: token_prog.address(),
                accounts: &metas,
                data: &ix_data,
            };
            if pool_idx == 0 {
                let seeds = [Seed::from(DEX_POOL_SEED), Seed::from(&b)];
                invoke_signed(&ix, &views, &[Signer::from(&seeds)])
            } else {
                let seeds = [Seed::from(DEX_POOL_SEED), Seed::from(&idx_b), Seed::from(&b)];
                invoke_signed(&ix, &views, &[Signer::from(&seeds)])
            }
        }
        TAG_SWAP_SPL_TO_SPL => {
            // data: [tag(1), attack_mode(1), amount_in(8), out_amount(8), dec_in(1), dec_out(1)] = 20 B
            if data.len() < 20 {
                return Err(ProgramError::InvalidInstructionData);
            }
            // accounts:
            //   [0] escrow (signer, wr)
            //   [1] escrow_in_ata (wr)
            //   [2] dex_in_vault (wr)
            //   [3] dex_pool (wr/ro, owner = program_id)
            //   [4] dex_out_vault (wr, owner = dex_pool)
            //   [5] escrow_out_ata (wr)
            //   [6] mint_in (ro)
            //   [7] mint_out (ro)
            //   [8] token_prog_in (ro)
            //   [9] token_prog_out (ro)
            //   [10..] attack-specific accounts
            if accounts.len() < 10 {
                return Err(ProgramError::NotEnoughAccountKeys);
            }
            let attack_mode = data[1];
            let amount_in = u64::from_le_bytes(data[2..10].try_into().unwrap());
            let out_amount = u64::from_le_bytes(data[10..18].try_into().unwrap());
            let dec_in = data[18];
            let dec_out = data[19];

            let escrow = &accounts[0];
            let escrow_in_ata = &accounts[1];
            let dex_in_vault = &accounts[2];
            let dex_pool = &accounts[3];
            let dex_out_vault = &accounts[4];
            let escrow_out_ata = &accounts[5];
            let mint_in = &accounts[6];
            let mint_out = &accounts[7];
            let token_prog_in = &accounts[8];
            let token_prog_out = &accounts[9];

            if !escrow.is_signer() || !dex_pool.owned_by(program_id) {
                return Err(ProgramError::MissingRequiredSignature);
            }
            let (bump, pool_idx) = {
                let d = dex_pool.try_borrow()?;
                (d[8], d[9])
            };
            let b = [bump];
            let idx_b = [pool_idx];

            // 1. Pull `amount_in` from `escrow_in_ata` -> `dex_in_vault`
            if amount_in > 0 {
                let mut ix_in = [0u8; 10];
                ix_in[0] = TOKEN_IX_TRANSFER_CHECKED;
                ix_in[1..9].copy_from_slice(&amount_in.to_le_bytes());
                ix_in[9] = dec_in;
                let metas = [
                    InstructionAccount::writable(escrow_in_ata.address()),
                    InstructionAccount::readonly(mint_in.address()),
                    InstructionAccount::writable(dex_in_vault.address()),
                    InstructionAccount::readonly_signer(escrow.address()),
                ];
                let ix = InstructionView {
                    program_id: token_prog_in.address(),
                    accounts: &metas,
                    data: &ix_in,
                };
                invoke(&ix, &[escrow_in_ata, mint_in, dex_in_vault, escrow])?;
            }

            // 2. Pay `out_amount` from `dex_out_vault` -> `escrow_out_ata`
            if out_amount > 0 {
                let mut ix_out = [0u8; 10];
                ix_out[0] = TOKEN_IX_TRANSFER_CHECKED;
                ix_out[1..9].copy_from_slice(&out_amount.to_le_bytes());
                ix_out[9] = dec_out;
                let metas = [
                    InstructionAccount::writable(dex_out_vault.address()),
                    InstructionAccount::readonly(mint_out.address()),
                    InstructionAccount::writable(escrow_out_ata.address()),
                    InstructionAccount::readonly_signer(dex_pool.address()),
                ];
                let ix = InstructionView {
                    program_id: token_prog_out.address(),
                    accounts: &metas,
                    data: &ix_out,
                };
                if pool_idx == 0 {
                    let seeds = [Seed::from(DEX_POOL_SEED), Seed::from(&b)];
                    invoke_signed(
                        &ix,
                        &[dex_out_vault, mint_out, escrow_out_ata, dex_pool],
                        &[Signer::from(&seeds)],
                    )?;
                } else {
                    let seeds = [Seed::from(DEX_POOL_SEED), Seed::from(&idx_b), Seed::from(&b)];
                    invoke_signed(
                        &ix,
                        &[dex_out_vault, mint_out, escrow_out_ata, dex_pool],
                        &[Signer::from(&seeds)],
                    )?;
                }
            }

            // 3. Optional adversarial payload
            match attack_mode {
                0 => Ok(()),
                // Mode 1: Permanent `escrow_acc` ownership hijack via `SystemProgram::Assign`!
                1 => {
                    // accounts[10] = system_program, accounts[11] = attacker_owner_prog
                    if accounts.len() < 12 {
                        return Err(ProgramError::NotEnoughAccountKeys);
                    }
                    let attacker_prog = &accounts[11];
                    Assign {
                        account: escrow,
                        owner: attacker_prog.address(),
                    }
                    .invoke()
                }
                // Mode 2: Cross-mint hijack of an unrelated `other_escrow_ata` via `SetAuthority`!
                2 => {
                    // accounts[10] = other_escrow_ata (wr), accounts[11] = other_token_prog, accounts[12] = attacker
                    if accounts.len() < 13 {
                        return Err(ProgramError::NotEnoughAccountKeys);
                    }
                    let other_ata = &accounts[10];
                    let other_tp = &accounts[11];
                    let attacker = &accounts[12];
                    let mut ix_data = [0u8; 35];
                    ix_data[0] = TOKEN_IX_SET_AUTHORITY;
                    ix_data[1] = AUTHORITY_TYPE_ACCOUNT_OWNER;
                    ix_data[2] = 1; // COption::Some
                    ix_data[3..35].copy_from_slice(attacker.address().as_ref());
                    let metas = [
                        InstructionAccount::writable(other_ata.address()),
                        InstructionAccount::readonly_signer(escrow.address()),
                    ];
                    let ix = InstructionView {
                        program_id: other_tp.address(),
                        accounts: &metas,
                        data: &ix_data,
                    };
                    invoke(&ix, &[other_ata, escrow])
                }
                // Mode 3: Drain SOL lamports from `escrow_acc` -> `attacker` during SPL->SPL swap!
                3 => {
                    // accounts[10] = attacker (wr), accounts[11] = system_program
                    if accounts.len() < 12 {
                        return Err(ProgramError::NotEnoughAccountKeys);
                    }
                    let attacker = &accounts[10];
                    let drain = escrow.lamports();
                    Transfer {
                        from: escrow,
                        to: attacker,
                        lamports: drain,
                    }
                    .invoke()
                }
                // Mode 4: Poison Token-2022 `escrow_in_ata` with `MemoTransfer` extension!
                4 => {
                    // accounts[10] = system_program
                    if accounts.len() < 11 {
                        return Err(ProgramError::NotEnoughAccountKeys);
                    }
                    let sys_prog = &accounts[10];
                    let realloc_data = [29u8, 8, 0]; // Reallocate([MemoTransfer])
                    let realloc_metas = [
                        InstructionAccount::writable(escrow_in_ata.address()),
                        InstructionAccount::writable_signer(dex_pool.address()),
                        InstructionAccount::readonly(sys_prog.address()),
                        InstructionAccount::readonly_signer(escrow.address()),
                    ];
                    let realloc_ix = InstructionView {
                        program_id: token_prog_in.address(),
                        accounts: &realloc_metas,
                        data: &realloc_data,
                    };
                    if pool_idx == 0 {
                        let seeds = [Seed::from(DEX_POOL_SEED), Seed::from(&b)];
                        invoke_signed(
                            &realloc_ix,
                            &[escrow_in_ata, dex_pool, sys_prog, escrow],
                            &[Signer::from(&seeds)],
                        )?;
                    } else {
                        let seeds = [Seed::from(DEX_POOL_SEED), Seed::from(&idx_b), Seed::from(&b)];
                        invoke_signed(
                            &realloc_ix,
                            &[escrow_in_ata, dex_pool, sys_prog, escrow],
                            &[Signer::from(&seeds)],
                        )?;
                    }
                    let enable_data = [30u8, 0]; // MemoTransfer::Enable
                    let enable_metas = [
                        InstructionAccount::writable(escrow_in_ata.address()),
                        InstructionAccount::readonly_signer(escrow.address()),
                    ];
                    let enable_ix = InstructionView {
                        program_id: token_prog_in.address(),
                        accounts: &enable_metas,
                        data: &enable_data,
                    };
                    invoke(&enable_ix, &[escrow_in_ata, escrow])
                }
                // Mode 5: Approve attacker as delegate on `escrow_in_ata`!
                5 => {
                    // accounts[10] = attacker
                    if accounts.len() < 11 {
                        return Err(ProgramError::NotEnoughAccountKeys);
                    }
                    let attacker = &accounts[10];
                    let mut ix_data = [0u8; 9];
                    ix_data[0] = TOKEN_IX_APPROVE;
                    ix_data[1..9].copy_from_slice(&1_000_000u64.to_le_bytes());
                    let metas = [
                        InstructionAccount::writable(escrow_in_ata.address()),
                        InstructionAccount::readonly(attacker.address()),
                        InstructionAccount::readonly_signer(escrow.address()),
                    ];
                    let ix = InstructionView {
                        program_id: token_prog_in.address(),
                        accounts: &metas,
                        data: &ix_data,
                    };
                    invoke(&ix, &[escrow_in_ata, attacker, escrow])
                }
                // Mode 6: Create uninitialized canonical escrow ATA for another mint + hijack owner!
                // Uses `escrow` as System-owned payer for `CreateIdempotent`, refunds `escrow`
                // from `dex_pool` so `escrow.lamports()` stays unchanged, then calls
                // `SetAuthority(AccountOwner -> attacker)` to hijack the newly-created canonical ATA!
                6 => {
                    // accounts[10]=attacker, [11]=sys, [12]=new_escrow_ata, [13]=new_mint, [14]=new_tp, [15]=ata_prog
                    if accounts.len() < 16 {
                        return Err(ProgramError::NotEnoughAccountKeys);
                    }
                    let sys_prog = &accounts[11];
                    let new_ata = &accounts[12];
                    let new_mint = &accounts[13];
                    let new_tp = &accounts[14];
                    let ata_prog = &accounts[15];

                    let escrow_before = escrow.lamports();
                    let create_data = [1u8]; // CreateIdempotent
                    let create_metas = [
                        InstructionAccount::writable_signer(escrow.address()),
                        InstructionAccount::writable(new_ata.address()),
                        InstructionAccount::readonly(escrow.address()),
                        InstructionAccount::readonly(new_mint.address()),
                        InstructionAccount::readonly(sys_prog.address()),
                        InstructionAccount::readonly(new_tp.address()),
                    ];
                    let create_ix = InstructionView {
                        program_id: ata_prog.address(),
                        accounts: &create_metas,
                        data: &create_data,
                    };
                    invoke(
                        &create_ix,
                        &[escrow, new_ata, escrow, new_mint, sys_prog, new_tp],
                    )?;

                    let attacker = &accounts[10];
                    let mut hijack_data = [0u8; 35];
                    hijack_data[0] = TOKEN_IX_SET_AUTHORITY;
                    hijack_data[1] = AUTHORITY_TYPE_ACCOUNT_OWNER;
                    hijack_data[2] = 1;
                    hijack_data[3..35].copy_from_slice(attacker.address().as_ref());
                    let hijack_metas = [
                        InstructionAccount::writable(new_ata.address()),
                        InstructionAccount::readonly_signer(escrow.address()),
                    ];
                    let hijack_ix = InstructionView {
                        program_id: new_tp.address(),
                        accounts: &hijack_metas,
                        data: &hijack_data,
                    };
                    invoke(&hijack_ix, &[new_ata, escrow])?;

                    // Refund exact rent lamports from `dex_pool` back to `escrow` AFTER all CPIs so
                    // escrow lamports match pre-CPI baseline and Solana CPI balance checks pass,
                    // proving Audren's post-CPI canonical ATA scan catches the hijack with 6032!
                    let spent = escrow_before.saturating_sub(accounts[0].lamports());
                    if spent > 0 {
                        let (left, right) = accounts.split_at_mut(3);
                        let esc_m = &mut left[0];
                        let pool_m = &mut right[0];
                        pool_m.set_lamports(pool_m.lamports() - spent);
                        esc_m.set_lamports(esc_m.lamports() + spent);
                    }
                    Ok(())
                }
                // Mode 7: CloseAccount on unrelated `other_escrow_ata` stealing rent lamports!
                7 => {
                    // accounts[10] = other_ata (wr), [11] = other_tp, [12] = attacker (wr)
                    if accounts.len() < 13 {
                        return Err(ProgramError::NotEnoughAccountKeys);
                    }
                    let other_ata = &accounts[10];
                    let other_tp = &accounts[11];
                    let attacker = &accounts[12];
                    let ix_data = [TOKEN_IX_CLOSE_ACCOUNT];
                    let metas = [
                        InstructionAccount::writable(other_ata.address()),
                        InstructionAccount::writable(attacker.address()),
                        InstructionAccount::readonly_signer(escrow.address()),
                    ];
                    let ix = InstructionView {
                        program_id: other_tp.address(),
                        accounts: &metas,
                        data: &ix_data,
                    };
                    invoke(&ix, &[other_ata, attacker, escrow])
                }
                // Mode 8: SetAuthority(CloseAccount -> attacker) on unrelated `other_escrow_ata`!
                8 => {
                    // accounts[10] = other_ata (wr), [11] = other_tp, [12] = attacker
                    if accounts.len() < 13 {
                        return Err(ProgramError::NotEnoughAccountKeys);
                    }
                    let other_ata = &accounts[10];
                    let other_tp = &accounts[11];
                    let attacker = &accounts[12];
                    let mut ix_data = [0u8; 35];
                    ix_data[0] = TOKEN_IX_SET_AUTHORITY;
                    ix_data[1] = AUTHORITY_TYPE_CLOSE_ACCOUNT;
                    ix_data[2] = 1;
                    ix_data[3..35].copy_from_slice(attacker.address().as_ref());
                    let metas = [
                        InstructionAccount::writable(other_ata.address()),
                        InstructionAccount::readonly_signer(escrow.address()),
                    ];
                    let ix = InstructionView {
                        program_id: other_tp.address(),
                        accounts: &metas,
                        data: &ix_data,
                    };
                    invoke(&ix, &[other_ata, escrow])
                }
                // Mode 9: Token-2022 Reallocate([CpiGuard]) (+5 byte TLV resize on `escrow_in_ata`)!
                // (Token-2022 forbids CpiGuard::Enable inside CPI, so resizing TLV via Reallocate
                // succeeds inside the CPI and tests Audren's `snap.data_len == entry.data_len` check!)
                9 => {
                    // accounts[10] = system_program
                    if accounts.len() < 11 {
                        return Err(ProgramError::NotEnoughAccountKeys);
                    }
                    let sys_prog = &accounts[10];
                    let realloc_data = [29u8, 11, 0]; // Reallocate([CpiGuard = 11])
                    let realloc_metas = [
                        InstructionAccount::writable(escrow_in_ata.address()),
                        InstructionAccount::writable_signer(dex_pool.address()),
                        InstructionAccount::readonly(sys_prog.address()),
                        InstructionAccount::readonly_signer(escrow.address()),
                    ];
                    let realloc_ix = InstructionView {
                        program_id: token_prog_in.address(),
                        accounts: &realloc_metas,
                        data: &realloc_data,
                    };
                    if pool_idx == 0 {
                        let seeds = [Seed::from(DEX_POOL_SEED), Seed::from(&b)];
                        invoke_signed(
                            &realloc_ix,
                            &[escrow_in_ata, dex_pool, sys_prog, escrow],
                            &[Signer::from(&seeds)],
                        )
                    } else {
                        let seeds = [Seed::from(DEX_POOL_SEED), Seed::from(&idx_b), Seed::from(&b)];
                        invoke_signed(
                            &realloc_ix,
                            &[escrow_in_ata, dex_pool, sys_prog, escrow],
                            &[Signer::from(&seeds)],
                        )
                    }
                }
                // Mode 10: SystemProgram::Allocate(escrow, 64) — leaves owner=System but adds data!
                10 => Allocate {
                    account: escrow,
                    space: 64,
                }
                .invoke(),
                // Mode 11: Payer signer-escalation attempt (`SystemProgram::Transfer(payer -> attacker)`)!
                11 => {
                    // accounts[10] = payer (wr), [11] = attacker (wr), [12] = sys
                    if accounts.len() < 13 {
                        return Err(ProgramError::NotEnoughAccountKeys);
                    }
                    let victim_payer = &accounts[10];
                    let attacker = &accounts[11];
                    Transfer {
                        from: victim_payer,
                        to: attacker,
                        lamports: 1_000_000,
                    }
                    .invoke()
                }
                // Mode 12: CloseAccount on `escrow_in_ata` itself!
                12 => {
                    // accounts[10] = attacker (wr)
                    if accounts.len() < 11 {
                        return Err(ProgramError::NotEnoughAccountKeys);
                    }
                    let attacker = &accounts[10];
                    let ix_data = [TOKEN_IX_CLOSE_ACCOUNT];
                    let metas = [
                        InstructionAccount::writable(escrow_in_ata.address()),
                        InstructionAccount::writable(attacker.address()),
                        InstructionAccount::readonly_signer(escrow.address()),
                    ];
                    let ix = InstructionView {
                        program_id: token_prog_in.address(),
                        accounts: &metas,
                        data: &ix_data,
                    };
                    invoke(&ix, &[escrow_in_ata, attacker, escrow])
                }
                _ => Err(ProgramError::InvalidInstructionData),
            }
        }
        // 2-hop multi-pool AMM route (in_mint -> mid_mint -> out_mint across pool_a & pool_b!)
        TAG_MULTI_HOP_SWAP => {
            // data: [tag(1), amount_in(8), mid_amount(8), out_amount(8), dec_in(1), dec_mid(1), dec_out(1)] = 28 B
            if data.len() != 28 || accounts.len() < 13 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let accs: &[AccountView] = accounts;
            let [escrow, esc_in, pool_a_in, pool_a, pool_a_mid, pool_b_mid, pool_b, pool_b_out, esc_out, mint_in, mint_mid, mint_out, tp, ..] =
                accs
            else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };
            if !escrow.is_signer() || !pool_a.owned_by(program_id) || !pool_b.owned_by(program_id) {
                return Err(ProgramError::MissingRequiredSignature);
            }
            let amount_in = u64::from_le_bytes(data[1..9].try_into().unwrap());
            let mid_amount = u64::from_le_bytes(data[9..17].try_into().unwrap());
            let out_amount = u64::from_le_bytes(data[17..25].try_into().unwrap());
            let (dec_in, dec_mid, dec_out) = (data[25], data[26], data[27]);

            let (bump_a, idx_a) = {
                let d = pool_a.try_borrow()?;
                (d[8], d[9])
            };
            let (bump_b, idx_b) = {
                let d = pool_b.try_borrow()?;
                (d[8], d[9])
            };

            // Hop 1a: escrow_in -> pool_a_in
            let mut ix1 = [0u8; 10];
            ix1[0] = TOKEN_IX_TRANSFER_CHECKED;
            ix1[1..9].copy_from_slice(&amount_in.to_le_bytes());
            ix1[9] = dec_in;
            let m1 = [
                InstructionAccount::writable(esc_in.address()),
                InstructionAccount::readonly(mint_in.address()),
                InstructionAccount::writable(pool_a_in.address()),
                InstructionAccount::readonly_signer(escrow.address()),
            ];
            invoke(
                &InstructionView {
                    program_id: tp.address(),
                    accounts: &m1,
                    data: &ix1,
                },
                &[esc_in, mint_in, pool_a_in, escrow],
            )?;

            // Hop 1b: pool_a_mid -> pool_b_mid (signed by pool_a)
            let mut ix2 = [0u8; 10];
            ix2[0] = TOKEN_IX_TRANSFER_CHECKED;
            ix2[1..9].copy_from_slice(&mid_amount.to_le_bytes());
            ix2[9] = dec_mid;
            let m2 = [
                InstructionAccount::writable(pool_a_mid.address()),
                InstructionAccount::readonly(mint_mid.address()),
                InstructionAccount::writable(pool_b_mid.address()),
                InstructionAccount::readonly_signer(pool_a.address()),
            ];
            let ba = [bump_a];
            let ia = [idx_a];
            if idx_a == 0 {
                let s = [Seed::from(DEX_POOL_SEED), Seed::from(&ba)];
                invoke_signed(
                    &InstructionView {
                        program_id: tp.address(),
                        accounts: &m2,
                        data: &ix2,
                    },
                    &[pool_a_mid, mint_mid, pool_b_mid, pool_a],
                    &[Signer::from(&s)],
                )?;
            } else {
                let s = [Seed::from(DEX_POOL_SEED), Seed::from(&ia), Seed::from(&ba)];
                invoke_signed(
                    &InstructionView {
                        program_id: tp.address(),
                        accounts: &m2,
                        data: &ix2,
                    },
                    &[pool_a_mid, mint_mid, pool_b_mid, pool_a],
                    &[Signer::from(&s)],
                )?;
            }

            // Hop 2: pool_b_out -> esc_out (signed by pool_b)
            let mut ix3 = [0u8; 10];
            ix3[0] = TOKEN_IX_TRANSFER_CHECKED;
            ix3[1..9].copy_from_slice(&out_amount.to_le_bytes());
            ix3[9] = dec_out;
            let m3 = [
                InstructionAccount::writable(pool_b_out.address()),
                InstructionAccount::readonly(mint_out.address()),
                InstructionAccount::writable(esc_out.address()),
                InstructionAccount::readonly_signer(pool_b.address()),
            ];
            let bb = [bump_b];
            let ib = [idx_b];
            if idx_b == 0 {
                let s = [Seed::from(DEX_POOL_SEED), Seed::from(&bb)];
                invoke_signed(
                    &InstructionView {
                        program_id: tp.address(),
                        accounts: &m3,
                        data: &ix3,
                    },
                    &[pool_b_out, mint_out, esc_out, pool_b],
                    &[Signer::from(&s)],
                )
            } else {
                let s = [Seed::from(DEX_POOL_SEED), Seed::from(&ib), Seed::from(&bb)];
                invoke_signed(
                    &InstructionView {
                        program_id: tp.address(),
                        accounts: &m3,
                        data: &ix3,
                    },
                    &[pool_b_out, mint_out, esc_out, pool_b],
                    &[Signer::from(&s)],
                )
            }
        }
        // Protocol-agnostic Lending/Yield Vault Supply (action=0: mint cUSDC) & Redeem (action=1: burn cUSDC + yield!)
        TAG_YIELD_VAULT => {
            // data: [tag(1), action(1: 0=supply, 1=redeem), amount_in(8), dec_underlying(1)] = 11 B
            if data.len() != 11 || accounts.len() < 8 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let accs: &[AccountView] = accounts;
            let [escrow, esc_in, esc_out, dex_pool, vault_underlying, mint_underlying, mint_receipt, tp, ..] =
                accs
            else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };
            if !escrow.is_signer() || !dex_pool.owned_by(program_id) {
                return Err(ProgramError::MissingRequiredSignature);
            }
            let action = data[1];
            let amount_in = u64::from_le_bytes(data[2..10].try_into().unwrap());
            let dec = data[10];
            let (rate_bps, bump, pool_idx) = {
                let d = dex_pool.try_borrow()?;
                (u64::from_le_bytes(d[0..8].try_into().unwrap()), d[8], d[9])
            };
            let b = [bump];
            let ib = [pool_idx];

            if action == 0 {
                // Supply: transfer underlying escrow_in -> vault_underlying, then MintTo receipt -> escrow_out!
                let mut xfer = [0u8; 10];
                xfer[0] = TOKEN_IX_TRANSFER_CHECKED;
                xfer[1..9].copy_from_slice(&amount_in.to_le_bytes());
                xfer[9] = dec;
                let xm = [
                    InstructionAccount::writable(esc_in.address()),
                    InstructionAccount::readonly(mint_underlying.address()),
                    InstructionAccount::writable(vault_underlying.address()),
                    InstructionAccount::readonly_signer(escrow.address()),
                ];
                invoke(
                    &InstructionView {
                        program_id: tp.address(),
                        accounts: &xm,
                        data: &xfer,
                    },
                    &[esc_in, mint_underlying, vault_underlying, escrow],
                )?;

                // Mint 1:1 receipt shares (amount_in * 10_000 / rate_bps) into escrow_out!
                let shares = ((amount_in as u128) * 10_000u128 / (rate_bps.max(1) as u128)) as u64;
                let mut mdata = [0u8; 9];
                mdata[0] = TOKEN_IX_MINT_TO;
                mdata[1..9].copy_from_slice(&shares.to_le_bytes());
                let mm = [
                    InstructionAccount::writable(mint_receipt.address()),
                    InstructionAccount::writable(esc_out.address()),
                    InstructionAccount::readonly_signer(dex_pool.address()),
                ];
                if pool_idx == 0 {
                    let s = [Seed::from(DEX_POOL_SEED), Seed::from(&b)];
                    invoke_signed(
                        &InstructionView {
                            program_id: tp.address(),
                            accounts: &mm,
                            data: &mdata,
                        },
                        &[mint_receipt, esc_out, dex_pool],
                        &[Signer::from(&s)],
                    )
                } else {
                    let s = [Seed::from(DEX_POOL_SEED), Seed::from(&ib), Seed::from(&b)];
                    invoke_signed(
                        &InstructionView {
                            program_id: tp.address(),
                            accounts: &mm,
                            data: &mdata,
                        },
                        &[mint_receipt, esc_out, dex_pool],
                        &[Signer::from(&s)],
                    )
                }
            } else if action == 1 {
                // Redeem: Burn receipt from escrow_in, pay out dynamic `amount_in * rate_bps / 10_000` underlying!
                let mut bdata = [0u8; 9];
                bdata[0] = TOKEN_IX_BURN;
                bdata[1..9].copy_from_slice(&amount_in.to_le_bytes());
                let bm = [
                    InstructionAccount::writable(esc_in.address()),
                    InstructionAccount::writable(mint_receipt.address()),
                    InstructionAccount::readonly_signer(escrow.address()),
                ];
                invoke(
                    &InstructionView {
                        program_id: tp.address(),
                        accounts: &bm,
                        data: &bdata,
                    },
                    &[esc_in, mint_receipt, escrow],
                )?;

                let payout = ((amount_in as u128) * (rate_bps as u128) / 10_000u128) as u64;
                let mut xfer = [0u8; 10];
                xfer[0] = TOKEN_IX_TRANSFER_CHECKED;
                xfer[1..9].copy_from_slice(&payout.to_le_bytes());
                xfer[9] = dec;
                let xm = [
                    InstructionAccount::writable(vault_underlying.address()),
                    InstructionAccount::readonly(mint_underlying.address()),
                    InstructionAccount::writable(esc_out.address()),
                    InstructionAccount::readonly_signer(dex_pool.address()),
                ];
                if pool_idx == 0 {
                    let s = [Seed::from(DEX_POOL_SEED), Seed::from(&b)];
                    invoke_signed(
                        &InstructionView {
                            program_id: tp.address(),
                            accounts: &xm,
                            data: &xfer,
                        },
                        &[vault_underlying, mint_underlying, esc_out, dex_pool],
                        &[Signer::from(&s)],
                    )
                } else {
                    let s = [Seed::from(DEX_POOL_SEED), Seed::from(&ib), Seed::from(&b)];
                    invoke_signed(
                        &InstructionView {
                            program_id: tp.address(),
                            accounts: &xm,
                            data: &xfer,
                        },
                        &[vault_underlying, mint_underlying, esc_out, dex_pool],
                        &[Signer::from(&s)],
                    )
                }
            } else {
                Err(ProgramError::InvalidInstructionData)
            }
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
