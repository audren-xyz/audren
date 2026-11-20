//! Minimal sBPFv3 mock DEX router for Audren `SwapViaRouter` LiteSVM integration tests.
//!
//! Intentionally places `swap_escrow`, `escrow_in`, and `escrow_out` at non-zero arbitrary
//! account indices to verify Audren's router-agnostic `(escrow_idx, escrow_in_idx, escrow_out_idx)`
//! CPI plumbing and adversarial custody guardrails.
//!
//! Account layout:
//!   [0] pool_authority (PDA `[b"mock_pool"]`, ro)
//!   [1] escrow_in (wr, owned by swap_escrow)
//!   [2] pool_in (wr)
//!   [3] swap_escrow (signer, wr/ro)
//!   [4] escrow_out (wr, owned by swap_escrow)
//!   [5] pool_out (wr)
//!   [6] token_program_in (ro)
//!   [7] token_program_out (ro)
//!   [8] mint_in (ro)
//!   [9] mint_out (ro)
//!   [10] attacker_or_system (wr/ro, used only in adversarial modes)
//!
//! Data:
//!   mode (1 B):
//!     0 = honest swap (spend_in from escrow_in -> pool_in, pay_out from pool_out -> escrow_out)
//!     1 = malicious delegate approval on escrow_in before completing swap
//!     2 = malicious authority hijack on escrow_out
//!     3 = malicious lamport drain from swap_escrow to attacker
//!   spend_in (8 B u64 LE)
//!   pay_out (8 B u64 LE)
//!   dec_in (1 B)
//!   dec_out (1 B)

use solana_account_info::AccountInfo;
use solana_address::Address;
use solana_cpi::{invoke, invoke_signed};
use solana_program_error::{ProgramError, ProgramResult};
use solana_system_interface::instruction as sys;
use spl_token_2022_interface::instruction as token_ix;

solana_program_entrypoint::entrypoint!(process);

pub fn process(program_id: &Address, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() < 19 || accounts.len() < 10 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mode = data[0];
    let spend_in = u64::from_le_bytes(data[1..9].try_into().unwrap());
    let pay_out = u64::from_le_bytes(data[9..17].try_into().unwrap());
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
    if *pool_auth.key != expected_pool_auth {
        return Err(ProgramError::InvalidSeeds);
    }

    // Pull `spend_in` from escrow_in -> pool_in using swap_escrow signer.
    if spend_in > 0 {
        let ix = token_ix::transfer_checked(
            token_prog_in.key,
            escrow_in.key,
            mint_in.key,
            pool_in.key,
            swap_escrow.key,
            &[],
            spend_in,
            dec_in,
        )?;
        invoke(
            &ix,
            &[
                escrow_in.clone(),
                mint_in.clone(),
                pool_in.clone(),
                swap_escrow.clone(),
                token_prog_in.clone(),
            ],
        )?;
    }

    // Pay `pay_out` from pool_out -> escrow_out using pool_auth PDA signer.
    if pay_out > 0 {
        let ix = token_ix::transfer_checked(
            token_prog_out.key,
            pool_out.key,
            mint_out.key,
            escrow_out.key,
            pool_auth.key,
            &[],
            pay_out,
            dec_out,
        )?;
        invoke_signed(
            &ix,
            &[
                pool_out.clone(),
                mint_out.clone(),
                escrow_out.clone(),
                pool_auth.clone(),
                token_prog_out.clone(),
            ],
            &[&[b"mock_pool", &[bump]]],
        )?;
    }

    match mode {
        0 => Ok(()),
        1 => {
            // Adversarial: approve attacker as delegate on escrow_in!
            let attacker = &accounts[10];
            let ix = token_ix::approve(
                token_prog_in.key,
                escrow_in.key,
                attacker.key,
                swap_escrow.key,
                &[],
                1_000_000,
            )?;
            invoke(
                &ix,
                &[
                    escrow_in.clone(),
                    attacker.clone(),
                    swap_escrow.clone(),
                    token_prog_in.clone(),
                ],
            )
        }
        2 => {
            // Adversarial: reassign owner of escrow_out to attacker!
            let attacker = &accounts[10];
            let ix = token_ix::set_authority(
                token_prog_out.key,
                escrow_out.key,
                Some(attacker.key),
                token_ix::AuthorityType::AccountOwner,
                swap_escrow.key,
                &[],
            )?;
            invoke(
                &ix,
                &[escrow_out.clone(), swap_escrow.clone(), token_prog_out.clone()],
            )
        }
        3 => {
            // Adversarial: drain lamports from swap_escrow -> attacker!
            let attacker = &accounts[10];
            let sys_prog = &accounts[11];
            let ix = sys::transfer(swap_escrow.key, attacker.key, 1_000);
            invoke(
                &ix,
                &[swap_escrow.clone(), attacker.clone(), sys_prog.clone()],
            )
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
