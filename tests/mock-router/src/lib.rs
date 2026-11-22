//! Minimal zero-alloc Pinocchio sBPFv3 mock DEX router for Audren `ExecViaEscrow` integration tests.
//!
//! Intentionally places `escrow`, `escrow_in`, and `escrow_out` at non-zero arbitrary
//! account indices to verify Audren's protocol-agnostic `(escrow_idx, escrow_in_idx, escrow_out_idx)`
//! CPI plumbing and adversarial custody guardrails.
//!
//! Account layout:
//!   [0] pool_authority (PDA `[b"mock_pool"]`, ro; wr in modes 4 & 5 to fund rent)
//!   [1] escrow_in (wr, owned by escrow)
//!   [2] pool_in (wr)
//!   [3] escrow (signer, wr/ro)
//!   [4] escrow_out (wr, owned by escrow)
//!   [5] pool_out (wr)
//!   [6] token_program_in (ro)
//!   [7] token_program_out (ro)
//!   [8] mint_in (ro)
//!   [9] mint_out (ro)
//!   [10] attacker_or_system (wr/ro, used only in adversarial modes)
//!   [11] system_program (used in modes 3, 4)
//!   [12..16] new_escrow_ata, new_mint, new_token_prog, ata_program (mode 4 only)
//!
//! Data (19 B):
//!   mode (1 B):
//!     0 = honest swap (spend_in from escrow_in -> pool_in, pay_out from pool_out -> escrow_out)
//!     1 = malicious delegate approval on escrow_in before completing swap
//!     2 = malicious authority hijack on escrow_out
//!     3 = malicious lamport drain from escrow to attacker
//!     4 = malicious uninitialized canonical escrow ATA create + owner hijack
//!     5 = malicious Token-2022 Reallocate([MemoTransfer]) + EnableRequiredMemoTransfers on escrow_in
//!   spend_in (8 B u64 LE)
//!   pay_out (8 B u64 LE)
//!   dec_in (1 B)
//!   dec_out (1 B)

#![no_std]
#![allow(unexpected_cfgs)]

use pinocchio::{
    cpi::{invoke, invoke_signed, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::Transfer;

pinocchio::program_entrypoint!(process, 16);
pinocchio::no_allocator!();
pinocchio::nostd_panic_handler!();

/// Embedded Neodyme `security.txt` V1 section (test-only program; never deployed to Mainnet).
#[cfg_attr(any(target_os = "solana", target_arch = "bpf"), link_section = ".security.txt")]
#[allow(dead_code)]
#[used]
#[no_mangle]
pub static SECURITY_TXT: &str = concat!(
    "=======BEGIN SECURITY.TXT V1=======\0",
    "name\0Audren Mock Router (Test Program)\0",
    "project_url\0https://audren.xyz\0",
    "contacts\0email:security@audren.xyz\0",
    "policy\0https://github.com/audren-xyz/audren/blob/main/SECURITY.md\0",
    "preferred_languages\0en\0",
    "source_code\0https://github.com/audren-xyz/audren\0",
    "source_release\0v", env!("CARGO_PKG_VERSION"), "\0",
    "=======END SECURITY.TXT V1=======\0"
);

const TOKEN_IX_APPROVE: u8 = 4;
const TOKEN_IX_SET_AUTHORITY: u8 = 6;
const TOKEN_IX_TRANSFER_CHECKED: u8 = 12;
const AUTHORITY_TYPE_ACCOUNT_OWNER: u8 = 2;

pub fn process(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if data.len() < 19 || accounts.len() < 10 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mode = data[0];
    let spend_in = u64::from_le_bytes([
        data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
    ]);
    let pay_out = u64::from_le_bytes([
        data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16],
    ]);
    let dec_in = data[17];
    let dec_out = data[18];

    let pool_auth = &accounts[0];
    let escrow_in = &accounts[1];
    let pool_in = &accounts[2];
    let swap_escrow = &accounts[3];
    let escrow_out = &accounts[4];
    let pool_out = &accounts[5];
    let token_prog_in = &accounts[6];
    let token_prog_out = &accounts[7];
    let mint_in = &accounts[8];
    let mint_out = &accounts[9];

    let (expected_pool_auth, bump) = Address::find_program_address(&[b"mock_pool"], program_id);
    if pool_auth.address() != &expected_pool_auth {
        return Err(ProgramError::InvalidSeeds);
    }

    // Pull `spend_in` from escrow_in -> pool_in using swap_escrow signer.
    if spend_in > 0 {
        let mut ix_data = [0u8; 10];
        ix_data[0] = TOKEN_IX_TRANSFER_CHECKED;
        ix_data[1..9].copy_from_slice(&spend_in.to_le_bytes());
        ix_data[9] = dec_in;
        let metas = [
            InstructionAccount::writable(escrow_in.address()),
            InstructionAccount::readonly(mint_in.address()),
            InstructionAccount::writable(pool_in.address()),
            InstructionAccount::readonly_signer(swap_escrow.address()),
        ];
        let ix = InstructionView {
            program_id: token_prog_in.address(),
            accounts: &metas,
            data: &ix_data,
        };
        invoke(&ix, &[escrow_in, mint_in, pool_in, swap_escrow])?;
    }

    // Pay `pay_out` from pool_out -> escrow_out using pool_auth PDA signer.
    if pay_out > 0 {
        let mut ix_data = [0u8; 10];
        ix_data[0] = TOKEN_IX_TRANSFER_CHECKED;
        ix_data[1..9].copy_from_slice(&pay_out.to_le_bytes());
        ix_data[9] = dec_out;
        let metas = [
            InstructionAccount::writable(pool_out.address()),
            InstructionAccount::readonly(mint_out.address()),
            InstructionAccount::writable(escrow_out.address()),
            InstructionAccount::readonly_signer(pool_auth.address()),
        ];
        let ix = InstructionView {
            program_id: token_prog_out.address(),
            accounts: &metas,
            data: &ix_data,
        };
        let bump_b = [bump];
        let seeds = [Seed::from(b"mock_pool"), Seed::from(&bump_b)];
        let signer = [Signer::from(&seeds)];
        invoke_signed(&ix, &[pool_out, mint_out, escrow_out, pool_auth], &signer)?;
    }

    match mode {
        0 => Ok(()),
        1 => {
            if accounts.len() < 11 {
                return Err(ProgramError::NotEnoughAccountKeys);
            }
            let attacker = &accounts[10];
            let mut ix_data = [0u8; 9];
            ix_data[0] = TOKEN_IX_APPROVE;
            ix_data[1..9].copy_from_slice(&1_000_000u64.to_le_bytes());
            let metas = [
                InstructionAccount::writable(escrow_in.address()),
                InstructionAccount::readonly(attacker.address()),
                InstructionAccount::readonly_signer(swap_escrow.address()),
            ];
            let ix = InstructionView {
                program_id: token_prog_in.address(),
                accounts: &metas,
                data: &ix_data,
            };
            invoke(&ix, &[escrow_in, attacker, swap_escrow])
        }
        2 => {
            if accounts.len() < 11 {
                return Err(ProgramError::NotEnoughAccountKeys);
            }
            let attacker = &accounts[10];
            let mut ix_data = [0u8; 35];
            ix_data[0] = TOKEN_IX_SET_AUTHORITY;
            ix_data[1] = AUTHORITY_TYPE_ACCOUNT_OWNER;
            ix_data[2] = 1; // COption::Some
            ix_data[3..35].copy_from_slice(attacker.address().as_ref());
            let metas = [
                InstructionAccount::writable(escrow_out.address()),
                InstructionAccount::readonly_signer(swap_escrow.address()),
            ];
            let ix = InstructionView {
                program_id: token_prog_out.address(),
                accounts: &metas,
                data: &ix_data,
            };
            invoke(&ix, &[escrow_out, swap_escrow])
        }
        3 => {
            if accounts.len() < 11 {
                return Err(ProgramError::NotEnoughAccountKeys);
            }
            let attacker = &accounts[10];
            Transfer {
                from: swap_escrow,
                to: attacker,
                lamports: 1_000,
            }
            .invoke()
        }
        4 => {
            // Create an uninitialized canonical ATA for `escrow` funded by `pool_auth` PDA,
            // then immediately hijack its AccountOwner to `attacker` using `escrow`'s signer privilege.
            if accounts.len() < 16 {
                return Err(ProgramError::NotEnoughAccountKeys);
            }
            let attacker = &accounts[10];
            let sys_prog = &accounts[11];
            let new_escrow_ata = &accounts[12];
            let new_mint = &accounts[13];
            let new_token_prog = &accounts[14];
            let ata_prog = &accounts[15];
            let bump_b = [bump];
            let seeds = [Seed::from(b"mock_pool"), Seed::from(&bump_b)];
            let signer = [Signer::from(&seeds)];

            let create_ix_data = [1u8]; // CreateIdempotent
            let create_metas = [
                InstructionAccount::writable_signer(pool_auth.address()),
                InstructionAccount::writable(new_escrow_ata.address()),
                InstructionAccount::readonly(swap_escrow.address()),
                InstructionAccount::readonly(new_mint.address()),
                InstructionAccount::readonly(sys_prog.address()),
                InstructionAccount::readonly(new_token_prog.address()),
            ];
            let create_ix = InstructionView {
                program_id: ata_prog.address(),
                accounts: &create_metas,
                data: &create_ix_data,
            };
            invoke_signed(
                &create_ix,
                &[pool_auth, new_escrow_ata, swap_escrow, new_mint, sys_prog, new_token_prog],
                &signer,
            )?;

            let mut hijack_data = [0u8; 35];
            hijack_data[0] = TOKEN_IX_SET_AUTHORITY;
            hijack_data[1] = AUTHORITY_TYPE_ACCOUNT_OWNER;
            hijack_data[2] = 1; // COption::Some
            hijack_data[3..35].copy_from_slice(attacker.address().as_ref());
            let hijack_metas = [
                InstructionAccount::writable(new_escrow_ata.address()),
                InstructionAccount::readonly_signer(swap_escrow.address()),
            ];
            let hijack_ix = InstructionView {
                program_id: new_token_prog.address(),
                accounts: &hijack_metas,
                data: &hijack_data,
            };
            invoke(&hijack_ix, &[new_escrow_ata, swap_escrow])
        }
        5 => {
            // Reallocate Token-2022 `escrow_in` with MemoTransfer extension and enable required
            // incoming transfer memos (permanently bricking future transfers into `escrow_in`).
            if accounts.len() < 11 {
                return Err(ProgramError::NotEnoughAccountKeys);
            }
            let sys_prog = &accounts[10];
            let bump_b = [bump];
            let seeds = [Seed::from(b"mock_pool"), Seed::from(&bump_b)];
            let signer = [Signer::from(&seeds)];

            let realloc_data = [29u8, 8, 0]; // TokenInstruction::Reallocate([ExtensionType::MemoTransfer])
            let realloc_metas = [
                InstructionAccount::writable(escrow_in.address()),
                InstructionAccount::writable_signer(pool_auth.address()),
                InstructionAccount::readonly(sys_prog.address()),
                InstructionAccount::readonly_signer(swap_escrow.address()),
            ];
            let realloc_ix = InstructionView {
                program_id: token_prog_in.address(),
                accounts: &realloc_metas,
                data: &realloc_data,
            };
            invoke_signed(
                &realloc_ix,
                &[escrow_in, pool_auth, sys_prog, swap_escrow],
                &signer,
            )?;

            let enable_data = [30u8, 0]; // MemoTransferExtension :: Enable
            let enable_metas = [
                InstructionAccount::writable(escrow_in.address()),
                InstructionAccount::readonly_signer(swap_escrow.address()),
            ];
            let enable_ix = InstructionView {
                program_id: token_prog_in.address(),
                accounts: &enable_metas,
                data: &enable_data,
            };
            invoke(&enable_ix, &[escrow_in, swap_escrow])
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
