//! Audren — Private Multi-Asset Settlement & Swap Program on Solana (sBPFv3).
//!
//! Native SOL, Classic SPL tokens, and transferable Token-2022 mints (including
//! `PermanentDelegate`, net-delta `TransferFee`, and `TransferHook`) share one unified shielded
//! `EpochPage` pool (`32` notes / `6,240 B` per page):
//! - Private multi-asset transfers hiding sender, recipient, token mint, and amount
//! - Single-transaction private DEX swaps (`SwapViaRouter`) through 16 isolated `swap_escrow`
//!   shards into any Solana DEX aggregator or AMM router (Jupiter, Orca, Raydium, Meteora,
//!   Phoenix, Titan, DFlow, or custom routers), settling output into a fresh stealth note
//! - Opt-in institutional auditability (`PoolMode::InstitutionalAudited`), enforcing verifiable
//!   ElGamal encryption of spent stealth pubkeys and hidden mints under `K_aud` on-chain
//! - Pure Ristretto255 Multi-Base Binary Triptych (`32 / 64 / 128`-note rings) verified via
//!   Agave's native `sol_curve_multiscalar_mul` syscall and native Agave Bulletproofs
//! - Structure-of-Arrays `EpochPage` accounts (`6,240 B < 10 KiB` CPI cap, `SIMD-0460` zero
//!   realloc) readable directly via standard Solana RPC `getMultipleAccounts` and
//!   `programSubscribe` `dataSlice[64..1120]`
//! - Live `Rent::get()` self-balancing page-rent vault (`SIMD-0437` / `SIMD-0438` compatible)
//! - Crypto-agile `protocol_version` field for future verifier upgrades

#![allow(unexpected_cfgs)]

mod crypto;
mod scalar;
mod state;

use audren_core::{
    instruction::{
        input_pages_for_m, triptych_proof_len, AUDITOR_ASSET_PROOF_LEN, CROSS_BASE_1_LEN,
        CROSS_BASE_2_LEN, DYNAMIC_OUTPUT_WIRE_LEN, NOTE_WIRE_LEN, RANGE_U128_PROOF_LEN,
        RANGE_U64_PROOF_LEN, TAG_CLOSE_PROOF_BUFFER, TAG_DEPOSIT, TAG_EXEC_BUFFERED, TAG_INIT_POOL,
        TAG_MERGE, TAG_OPEN_PAGE, TAG_SET_PAUSED, TAG_SWAP_VIA_ROUTER, TAG_TRANSFER, TAG_WITHDRAW,
        TAG_WRITE_PROOF_BUFFER,
    },
    layout::{
        read_32, read_u16, read_u32, read_u64, NoteEntry, PageHeader, PoolState, BUF_OFF_AUTHORITY,
        BUF_OFF_EXPECTED_LEN, BUF_OFF_MAGIC, BUF_OFF_WRITTEN_MASK, MAX_CPI_ACCOUNT_ALLOC,
        NOTE_CT_LEN, PAGE_CAPACITY, PAGE_LEN, PAGE_RENT_MAGIC, PAGE_ROLLOVER_HEADROOM,
        POOL_STATE_LEN, PROOF_BUFFER_CHUNK_SIZE, PROOF_BUFFER_HEADER_LEN, PROOF_BUFFER_MAGIC,
        PROOF_BUFFER_MAX_PAYLOAD, SENTINEL_ACCOUNT_LEN, SOL_VAULT_MAGIC,
    },
    AudrenError, PoolMode, CLASSIC_TOKEN_PROGRAM_ID, ESCROW_SEED, NATIVE_SOL_MINT,
    NULLIFIER_SEED, PAGE_RENT_SEED, PAGE_SEED, POOL_SEED, PROOF_BUFFER_SEED, PROTOCOL_VERSION,
    SOL_VAULT_SEED, TOKEN_2022_PROGRAM_ID, VAULT_AUTH_SEED, WSOL_MINT,
};
use crypto::{
    address_bytes, asset_generator, is_zero_point, pt_add, pt_mul_u64, transcript_root,
    validate_nonzero_point, validate_point, verify_auditor_asset_proof, verify_cross_base_1,
    verify_cross_base_2, verify_native_range_u128, verify_native_range_u64, verify_triptych,
    IDENTITY,
};
use solana_account_info::AccountInfo;
use solana_address::Address;
use solana_cpi::{invoke, invoke_signed};
use solana_msg::msg;
use solana_program_error::{ProgramError, ProgramResult};
use solana_rent::{sysvar::GetSysvar, Rent};
use solana_system_interface::{instruction as sys, program as system};
use spl_token_2022_interface::{
    extension::{transfer_hook::TransferHook, BaseStateWithExtensions, StateWithExtensions},
    instruction as token_ix,
    state::{Account as TokenAccount, Mint},
};
use state::{
    append_note_to_page, check_page_rent_vault, check_sol_vault, check_supported_token_program,
    ensure, err, escrow_pda, expected_ata, init_sentinel_bytes, load_page_header, load_pool,
    nullifier_pda, page_pda, page_rent_pda, pool_pda, proof_buffer_pda, save_pool, sol_vault_pda,
    vault_auth_pda,
};

solana_program_entrypoint::entrypoint!(process);

/// Maximum accounts forwarded to an external DEX router inside a single transaction
/// (`80` provides full headroom for Agave 4.5 `SIMD-0596` TxV1 96-account lock limit: `96 - 16 = 80`).
const MAX_ROUTER_CPI_ACCOUNTS: usize = 80;

fn create_pda<'a>(
    payer: &AccountInfo<'a>,
    target: &AccountInfo<'a>,
    system_program: &AccountInfo<'a>,
    seeds: &[&[u8]],
    space: usize,
    owner: &Address,
) -> ProgramResult {
    ensure(
        space <= MAX_CPI_ACCOUNT_ALLOC
            && payer.is_writable
            && target.is_writable
            && *system_program.key == system::id()
            && target.owner == system_program.key
            && target.data_is_empty(),
        AudrenError::InvalidAccount,
    )?;
    let required = Rent::get()?.minimum_balance(space);
    let deficit = required.saturating_sub(target.lamports());
    if deficit > 0 {
        invoke(
            &sys::transfer(payer.key, target.key, deficit),
            &[payer.clone(), target.clone(), system_program.clone()],
        )?;
    }
    invoke_signed(
        &sys::allocate(target.key, space as u64),
        &[target.clone(), system_program.clone()],
        &[seeds],
    )?;
    invoke_signed(
        &sys::assign(target.key, owner),
        &[target.clone(), system_program.clone()],
        &[seeds],
    )
}

/// Create a 0-byte `NullifierPDA` owned by `program_id`, preventing double-spends forever
/// while remaining immune to lamport pre-funding DoS attacks.
fn claim_nullifier<'a>(
    payer: &AccountInfo<'a>,
    nullifier_acc: &AccountInfo<'a>,
    system_program: &AccountInfo<'a>,
    program_id: &Address,
    pool_id: u32,
    nullifier: &[u8; 32],
) -> ProgramResult {
    let (expected, bump) = nullifier_pda(program_id, pool_id, nullifier);
    ensure(*nullifier_acc.key == expected, AudrenError::InvalidPda)?;
    if nullifier_acc.owner == program_id {
        return Err(err(AudrenError::NullifierAlreadySpent));
    }
    let pool_le = pool_id.to_le_bytes();
    let bump_slice = [bump];
    let seeds: &[&[u8]] = &[NULLIFIER_SEED, &pool_le, nullifier, &bump_slice];
    create_pda(payer, nullifier_acc, system_program, seeds, 0, program_id)
}

#[derive(Clone, Copy)]
struct MintInfo {
    decimals: u8,
    has_active_hook: bool,
}

/// Unpack a Classic SPL or Token-2022 mint and read decimals + active `TransferHook` state.
///
/// Supports all transferable Token-2022 mints (including `PermanentDelegate`, `TransferFeeConfig`,
/// and `TransferHook`). Soulbound `NonTransferable` mints are rejected natively by Token-2022
/// during `transfer_checked`.
fn load_mint_info(mint: &AccountInfo, token_program: &Address) -> Result<MintInfo, ProgramError> {
    ensure(mint.owner == token_program, AudrenError::InvalidAccount)?;
    let md = mint.try_borrow_data()?;
    let mint_state = StateWithExtensions::<Mint>::unpack(&md)?;
    let has_active_hook = mint_state
        .get_extension::<TransferHook>()
        .ok()
        .and_then(|hook| Option::<Address>::from(hook.program_id))
        .is_some();
    Ok(MintInfo {
        decimals: mint_state.base.decimals,
        has_active_hook,
    })
}

/// Invoke Classic SPL or Token-2022 `transfer_checked`.
///
/// Uses a zero-allocation fast path when the mint has no active `TransferHook` (`program_id == None`).
/// When a mint has an active `TransferHook`, appends sanitized extra accounts from `hook_candidates`
/// with `is_signer = false` and never forwards Audren program, Audren-owned state, or blocked custody accounts.
#[allow(clippy::too_many_arguments)]
fn invoke_token_transfer_checked<'a>(
    program_id: &Address,
    vault_auth_key: &Address,
    token_prog: &AccountInfo<'a>,
    source: &AccountInfo<'a>,
    mint: &AccountInfo<'a>,
    dest: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    amount: u64,
    mint_info: MintInfo,
    hook_candidates: &[AccountInfo<'a>],
    blocked_keys: &[&Address],
    signer_seeds: &[&[&[u8]]],
) -> ProgramResult {
    let mut ix = token_ix::transfer_checked(
        token_prog.key,
        source.key,
        mint.key,
        dest.key,
        authority.key,
        &[],
        amount,
        mint_info.decimals,
    )?;

    if !mint_info.has_active_hook || hook_candidates.is_empty() {
        let base_infos = [
            source.clone(),
            mint.clone(),
            dest.clone(),
            authority.clone(),
            token_prog.clone(),
        ];
        return if signer_seeds.is_empty() {
            invoke(&ix, &base_infos)
        } else {
            invoke_signed(&ix, &base_infos, signer_seeds)
        };
    }

    let mut infos = Vec::with_capacity(5 + hook_candidates.len());
    infos.push(source.clone());
    infos.push(mint.clone());
    infos.push(dest.clone());
    infos.push(authority.clone());
    infos.push(token_prog.clone());

    for acc in hook_candidates {
        if acc.key == program_id || acc.owner == program_id {
            continue;
        }
        if acc.key == source.key
            || acc.key == mint.key
            || acc.key == dest.key
            || acc.key == authority.key
            || acc.key == token_prog.key
        {
            continue;
        }
        if blocked_keys.iter().any(|k| *k == acc.key) {
            continue;
        }
        if let Some(snap) = token_account_security(acc) {
            if snap.owner == *vault_auth_key {
                continue;
            }
        }
        if ix.accounts.iter().any(|m| m.pubkey == *acc.key) {
            continue;
        }
        ix.accounts.push(if acc.is_writable {
            solana_instruction::AccountMeta::new(*acc.key, false)
        } else {
            solana_instruction::AccountMeta::new_readonly(*acc.key, false)
        });
        infos.push(acc.clone());
    }

    if signer_seeds.is_empty() {
        invoke(&ix, &infos)
    } else {
        invoke_signed(&ix, &infos, signer_seeds)
    }
}

fn token_balance(account: &AccountInfo, token_program: &Address) -> Result<u64, ProgramError> {
    ensure(account.owner == token_program, AudrenError::InvalidAccount)?;
    let data = account.try_borrow_data()?;
    Ok(StateWithExtensions::<TokenAccount>::unpack(&data)?.base.amount)
}

struct TokenSecuritySnapshot {
    token_program: Address,
    owner: Address,
    has_delegate: bool,
    close_authority: Option<Address>,
}

fn token_account_security(account: &AccountInfo) -> Option<TokenSecuritySnapshot> {
    let owner_prog = account.owner.to_bytes();
    if owner_prog != CLASSIC_TOKEN_PROGRAM_ID && owner_prog != TOKEN_2022_PROGRAM_ID {
        return None;
    }
    let data = account.try_borrow_data().ok()?;
    let unpacked = StateWithExtensions::<TokenAccount>::unpack(&data).ok()?;
    Some(TokenSecuritySnapshot {
        token_program: *account.owner,
        owner: unpacked.base.owner,
        has_delegate: unpacked.base.delegate.is_some(),
        close_authority: unpacked.base.close_authority.into(),
    })
}

fn decode_note_wire(data: &[u8]) -> Result<NoteEntry, ProgramError> {
    ensure(data.len() == NOTE_WIRE_LEN, AudrenError::InvalidInstruction)?;
    let view_tag = data[0];
    let ephemeral_pk = read_32(data, 1).map_err(err)?;
    let stealth_pk = read_32(data, 33).map_err(err)?;
    let asset_tag = read_32(data, 65).map_err(err)?;
    let commitment = read_32(data, 97).map_err(err)?;
    let mut ciphertext = [0u8; NOTE_CT_LEN];
    ciphertext.copy_from_slice(&data[129..129 + NOTE_CT_LEN]);
    validate_nonzero_point(&stealth_pk)?;
    validate_nonzero_point(&asset_tag)?;
    validate_point(&commitment)?;
    Ok(NoteEntry {
        view_tag,
        ephemeral_pk,
        stealth_pk,
        asset_tag,
        commitment,
        ciphertext,
    })
}

/// Collect a self-balancing per-note page-rent contribution into `PageRentVault`.
///
/// Immune to `SIMD-0437` incremental rent reductions (steps 1–5 down to `696` lamports/byte)
/// and any `SIMD-0438` rollback:
/// 1. Reads the live cluster `Rent` sysvar (`Rent::get()`) instead of static constants.
/// 2. Caps each note's fee at `min(pool.page_rent_fee_lamports, ceil(page_rent / PAGE_CAPACITY))`.
/// 3. Automatically skips collection once `PageRentVault` already holds a 2-page rollover buffer
///    (`min_vault + 2 * page_rent`) so excess SOL is never overcharged or trapped.
fn collect_page_rent_fee<'a>(
    payer: &AccountInfo<'a>,
    page_rent_vault: &AccountInfo<'a>,
    system_program: &AccountInfo<'a>,
    pool: &PoolState,
    num_notes: u64,
) -> ProgramResult {
    if pool.page_rent_fee_lamports == 0 || num_notes == 0 {
        return Ok(());
    }
    let rent = Rent::get()?;
    let page_rent = rent.minimum_balance(PAGE_LEN);
    let min_vault = rent.minimum_balance(SENTINEL_ACCOUNT_LEN);
    let target_vault_balance = min_vault
        .checked_add(page_rent.saturating_mul(2))
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    let deficit_to_target = target_vault_balance.saturating_sub(page_rent_vault.lamports());
    if deficit_to_target == 0 {
        return Ok(());
    }
    let live_per_note = page_rent.div_ceil(PAGE_CAPACITY as u64);
    let effective_per_note = pool.page_rent_fee_lamports.min(live_per_note);
    let total = effective_per_note
        .checked_mul(num_notes)
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?
        .min(deficit_to_target);
    if total > 0 {
        invoke(
            &sys::transfer(payer.key, page_rent_vault.key, total),
            &[
                payer.clone(),
                page_rent_vault.clone(),
                system_program.clone(),
            ],
        )?;
    }
    Ok(())
}

/// Load 1, 2, or 4 strictly ordered input `EpochPage` accounts for Triptych verification.
fn load_input_pages<'a, 'b>(
    accounts: &'a [AccountInfo<'b>],
    program_id: &Address,
    pool_id: u32,
    m: u8,
) -> Result<(Vec<PageHeader>, Vec<std::cell::Ref<'a, &'a mut [u8]>>), ProgramError> {
    let needed = input_pages_for_m(m).map_err(err)?;
    ensure(accounts.len() >= needed, AudrenError::InvalidAccount)?;
    let mut headers: Vec<PageHeader> = Vec::with_capacity(needed);
    let mut borrows: Vec<std::cell::Ref<'a, &'a mut [u8]>> = Vec::with_capacity(needed);
    for acc in accounts.iter().take(needed) {
        let h = load_page_header(acc, program_id, pool_id)?;
        ensure(h.count > 0, AudrenError::PageEmpty)?;
        if let Some(prev) = headers.last() {
            ensure(
                prev.page_id < h.page_id,
                AudrenError::DuplicateOrUnorderedPages,
            )?;
        }
        headers.push(h);
        borrows.push(acc.try_borrow_data()?);
    }
    Ok((headers, borrows))
}

/// Append a note to `out_page` and bump `pool.total_notes`.
fn write_output_note(
    out_page: &AccountInfo,
    program_id: &Address,
    pool: &mut PoolState,
    note: &NoteEntry,
) -> Result<u8, ProgramError> {
    let idx = append_note_to_page(out_page, program_id, pool.pool_id, pool.current_page_id, note)?;
    pool.total_notes = pool
        .total_notes
        .checked_add(1)
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    Ok(idx)
}

fn process(program_id: &Address, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (&tag, rest) = data
        .split_first()
        .ok_or_else(|| err(AudrenError::InvalidInstruction))?;
    match tag {
        TAG_INIT_POOL => ix_init_pool(program_id, accounts, rest),
        TAG_OPEN_PAGE => ix_open_page(program_id, accounts, rest),
        TAG_DEPOSIT => ix_deposit(program_id, accounts, rest),
        TAG_TRANSFER => ix_transfer(program_id, accounts, rest),
        TAG_MERGE => ix_merge(program_id, accounts, rest),
        TAG_SWAP_VIA_ROUTER => ix_swap_via_router(program_id, accounts, rest),
        TAG_WITHDRAW => ix_withdraw(program_id, accounts, rest),
        TAG_SET_PAUSED => ix_set_paused(program_id, accounts, rest),
        TAG_WRITE_PROOF_BUFFER => ix_write_proof_buffer(program_id, accounts, rest),
        TAG_EXEC_BUFFERED => ix_exec_buffered(program_id, accounts, rest),
        TAG_CLOSE_PROOF_BUFFER => ix_close_proof_buffer(program_id, accounts, rest),
        _ => Err(err(AudrenError::InvalidInstruction)),
    }
}

// ============================================================================
// Tag 0: InitPool
// Data: pool_id (4) | mode (1) | auditor_locked (1) | page_rent_fee (8) | auditor_pk (32) = 46 B
// Accounts: [0] payer/authority (signer, wr), [1] pool (wr), [2] page_0 (wr),
//           [3] sol_vault (wr), [4] page_rent_vault (wr), [5] system_program
// ============================================================================
fn ix_init_pool(program_id: &Address, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    ensure(data.len() == 46, AudrenError::InvalidInstruction)?;
    ensure(accounts.len() >= 6, AudrenError::InvalidAccount)?;
    let payer = &accounts[0];
    let pool_acc = &accounts[1];
    let page0_acc = &accounts[2];
    let sol_vault_acc = &accounts[3];
    let rent_vault_acc = &accounts[4];
    let sys_prog = &accounts[5];
    ensure(payer.is_signer, AudrenError::Unauthorized)?;
    ensure(
        payer.is_writable
            && pool_acc.is_writable
            && page0_acc.is_writable
            && sol_vault_acc.is_writable
            && rent_vault_acc.is_writable,
        AudrenError::InvalidAccount,
    )?;

    let pool_id = read_u32(data, 0).map_err(err)?;
    let mode = PoolMode::from_u8(data[4]).ok_or_else(|| err(AudrenError::InvalidInstruction))?;
    let auditor_locked = data[5] != 0;
    let page_rent_fee = read_u64(data, 6).map_err(err)?;
    let auditor_pk = read_32(data, 14).map_err(err)?;

    if mode == PoolMode::InstitutionalAudited {
        validate_nonzero_point(&auditor_pk)?;
    } else {
        ensure(auditor_pk == IDENTITY, AudrenError::InvalidInstruction)?;
    }

    let pool_le = pool_id.to_le_bytes();
    let (p_addr, p_bump) = pool_pda(program_id, pool_id);
    ensure(*pool_acc.key == p_addr, AudrenError::InvalidPda)?;
    let (pg_addr, pg_bump) = page_pda(program_id, pool_id, 0);
    ensure(*page0_acc.key == pg_addr, AudrenError::InvalidPda)?;
    let (_, vault_auth_bump) = vault_auth_pda(program_id, pool_id);
    let (sv_addr, sv_bump) = sol_vault_pda(program_id, pool_id);
    ensure(*sol_vault_acc.key == sv_addr, AudrenError::InvalidPda)?;
    let (rv_addr, rv_bump) = page_rent_pda(program_id, pool_id);
    ensure(*rent_vault_acc.key == rv_addr, AudrenError::InvalidPda)?;

    create_pda(
        payer,
        pool_acc,
        sys_prog,
        &[POOL_SEED, &pool_le, &[p_bump]],
        POOL_STATE_LEN,
        program_id,
    )?;
    create_pda(
        payer,
        page0_acc,
        sys_prog,
        &[PAGE_SEED, &pool_le, &0u64.to_le_bytes(), &[pg_bump]],
        PAGE_LEN,
        program_id,
    )?;
    create_pda(
        payer,
        sol_vault_acc,
        sys_prog,
        &[SOL_VAULT_SEED, &pool_le, &[sv_bump]],
        SENTINEL_ACCOUNT_LEN,
        program_id,
    )?;
    create_pda(
        payer,
        rent_vault_acc,
        sys_prog,
        &[PAGE_RENT_SEED, &pool_le, &[rv_bump]],
        SENTINEL_ACCOUNT_LEN,
        program_id,
    )?;

    init_sentinel_bytes(sol_vault_acc, program_id, SOL_VAULT_MAGIC, sv_bump)?;
    init_sentinel_bytes(rent_vault_acc, program_id, PAGE_RENT_MAGIC, rv_bump)?;

    let pool_state = PoolState {
        version: PROTOCOL_VERSION,
        bump: p_bump,
        mode,
        paused: false,
        pool_id,
        current_page_id: 0,
        total_notes: 0,
        total_spends: 0,
        page_rent_fee_lamports: page_rent_fee,
        authority: payer.key.to_bytes(),
        auditor_pk,
        auditor_locked,
        vault_auth_bump,
        sol_vault_bump: sv_bump,
        page_rent_bump: rv_bump,
    };
    save_pool(pool_acc, program_id, &pool_state)?;

    let mut page_data = page0_acc.try_borrow_mut_data()?;
    PageHeader {
        version: PROTOCOL_VERSION,
        bump: pg_bump,
        closed: false,
        count: 0,
        pool_id,
        page_id: 0,
        created_slot: 0,
        closed_slot: 0,
    }
    .encode(&mut page_data)
    .map_err(err)?;

    msg!("audren:init_pool id={} mode={}", pool_id, mode as u8);
    Ok(())
}

// ============================================================================
// Tag 1: OpenPage (permissionless self-funding page rollover)
// Data: empty (0 B)
// Accounts: [0] payer (signer, wr), [1] pool (wr), [2] current_page (wr),
//           [3] next_page (wr), [4] page_rent_vault (wr), [5] system_program
// ============================================================================
fn ix_open_page(program_id: &Address, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    ensure(data.is_empty(), AudrenError::InvalidInstruction)?;
    ensure(accounts.len() >= 6, AudrenError::InvalidAccount)?;
    let payer = &accounts[0];
    let pool_acc = &accounts[1];
    let cur_page_acc = &accounts[2];
    let next_page_acc = &accounts[3];
    let rent_vault_acc = &accounts[4];
    let sys_prog = &accounts[5];
    ensure(payer.is_signer, AudrenError::Unauthorized)?;
    ensure(
        payer.is_writable
            && pool_acc.is_writable
            && cur_page_acc.is_writable
            && next_page_acc.is_writable
            && rent_vault_acc.is_writable
            && *sys_prog.key == system::id()
            && next_page_acc.owner == sys_prog.key
            && next_page_acc.data_is_empty(),
        AudrenError::InvalidAccount,
    )?;

    let mut pool = load_pool(pool_acc, program_id)?;
    ensure(!pool.paused, AudrenError::PoolPaused)?;
    check_page_rent_vault(rent_vault_acc, program_id, pool.pool_id)?;

    let mut cur_hdr = load_page_header(cur_page_acc, program_id, pool.pool_id)?;
    ensure(
        cur_hdr.page_id == pool.current_page_id,
        AudrenError::WrongPool,
    )?;
    let remaining = PAGE_CAPACITY.saturating_sub(cur_hdr.count as usize);
    ensure(
        cur_hdr.closed || remaining <= PAGE_ROLLOVER_HEADROOM,
        AudrenError::PageNotReady,
    )?;

    let next_id = pool
        .current_page_id
        .checked_add(1)
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    let (next_addr, next_bump) = page_pda(program_id, pool.pool_id, next_id);
    ensure(*next_page_acc.key == next_addr, AudrenError::InvalidPda)?;

    // Permanently seal the outgoing page so its witness set becomes immutable.
    {
        cur_hdr.closed = true;
        let mut cd = cur_page_acc.try_borrow_mut_data()?;
        cur_hdr.encode(&mut cd).map_err(err)?;
    }

    // Allocate & assign `next_page_acc` BEFORE any direct lamport transfer from `rent_vault_acc`
    // (Agave enforces balanced lamports across CPI boundaries, so direct lamport debits must
    // occur only after all CPIs complete). Even a zero-balance cranker can open pages once
    // `PageRentVault` is funded because `allocate`/`assign` do not require upfront lamports.
    let rent = Rent::get()?;
    let min_vault = rent.minimum_balance(SENTINEL_ACCOUNT_LEN);
    let page_rent = rent.minimum_balance(PAGE_LEN);
    let available = rent_vault_acc.lamports().saturating_sub(min_vault);
    let needed = page_rent.saturating_sub(next_page_acc.lamports());
    let subsidy = available.min(needed);
    let payer_deficit = needed.saturating_sub(subsidy);

    let pool_le = pool.pool_id.to_le_bytes();
    let next_le = next_id.to_le_bytes();
    let page_seeds: &[&[u8]] = &[PAGE_SEED, &pool_le, &next_le, &[next_bump]];

    if payer_deficit > 0 {
        invoke(
            &sys::transfer(payer.key, next_page_acc.key, payer_deficit),
            &[payer.clone(), next_page_acc.clone(), sys_prog.clone()],
        )?;
    }
    invoke_signed(
        &sys::allocate(next_page_acc.key, PAGE_LEN as u64),
        &[next_page_acc.clone(), sys_prog.clone()],
        &[page_seeds],
    )?;
    invoke_signed(
        &sys::assign(next_page_acc.key, program_id),
        &[next_page_acc.clone(), sys_prog.clone()],
        &[page_seeds],
    )?;

    if subsidy > 0 {
        **rent_vault_acc.try_borrow_mut_lamports()? = rent_vault_acc
            .lamports()
            .checked_sub(subsidy)
            .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
        **next_page_acc.try_borrow_mut_lamports()? = next_page_acc
            .lamports()
            .checked_add(subsidy)
            .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    }

    {
        let mut nd = next_page_acc.try_borrow_mut_data()?;
        PageHeader {
            version: PROTOCOL_VERSION,
            bump: next_bump,
            closed: false,
            count: 0,
            pool_id: pool.pool_id,
            page_id: next_id,
            created_slot: 0,
            closed_slot: 0,
        }
        .encode(&mut nd)
        .map_err(err)?;
    }

    pool.current_page_id = next_id;
    save_pool(pool_acc, program_id, &pool)?;
    msg!("audren:open_page pool={} page={}", pool.pool_id, next_id);
    Ok(())
}

// ============================================================================
// Tag 2: Deposit (supports both self-shielding and third-party confidential onramps)
// Data: is_native_sol (1) | amount (8) | dynamic_out_wire (129) = 138 B
//   (Asset generator G_mint and commitment = amount * G_mint are computed on-chain,
//    so third-party depositors such as regulated fiat onramps never need the user's
//    spend key or a ZK proof to credit a private note!)
// Accounts (Native SOL):
//   [0] depositor (signer, wr), [1] pool (wr), [2] out_page (wr),
//   [3] sol_vault (wr), [4] page_rent_vault (wr), [5] system_program
// Accounts (SPL / Token-2022):
//   [0] depositor (signer, wr), [1] pool (wr), [2] out_page (wr),
//   [3] mint, [4] depositor_ata (wr), [5] vault_ata (wr),
//   [6] token_program, [7] page_rent_vault (wr), [8] system_program
// ============================================================================
fn ix_deposit(program_id: &Address, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    ensure(
        data.len() == 9 + DYNAMIC_OUTPUT_WIRE_LEN,
        AudrenError::InvalidInstruction,
    )?;
    let is_native = data[0] != 0;
    ensure(
        accounts.len() >= if is_native { 6 } else { 9 },
        AudrenError::InvalidAccount,
    )?;
    let amount = read_u64(data, 1).map_err(err)?;
    ensure(amount > 0, AudrenError::ZeroAmount)?;

    let view_tag = data[9];
    let ephemeral_pk = read_32(data, 10).map_err(err)?;
    let stealth_pk = read_32(data, 42).map_err(err)?;
    validate_nonzero_point(&stealth_pk)?;
    let mut ciphertext = [0u8; NOTE_CT_LEN];
    ciphertext.copy_from_slice(&data[74..74 + NOTE_CT_LEN]);

    let depositor = &accounts[0];
    let pool_acc = &accounts[1];
    let out_page_acc = &accounts[2];
    ensure(depositor.is_signer, AudrenError::Unauthorized)?;
    ensure(
        depositor.is_writable && pool_acc.is_writable && out_page_acc.is_writable,
        AudrenError::InvalidAccount,
    )?;

    let mut pool = load_pool(pool_acc, program_id)?;
    ensure(!pool.paused, AudrenError::PoolPaused)?;

    let mint_bytes: [u8; 32];
    let committed_amount: u64;
    let rent_vault_acc: &AccountInfo;
    let sys_prog: &AccountInfo;

    if is_native {
        ensure(accounts.len() >= 6, AudrenError::InvalidAccount)?;
        let sol_vault = &accounts[3];
        rent_vault_acc = &accounts[4];
        sys_prog = &accounts[5];
        check_sol_vault(sol_vault, program_id, pool.pool_id)?;
        check_page_rent_vault(rent_vault_acc, program_id, pool.pool_id)?;
        ensure(
            sol_vault.is_writable && rent_vault_acc.is_writable,
            AudrenError::InvalidAccount,
        )?;
        invoke(
            &sys::transfer(depositor.key, sol_vault.key, amount),
            &[depositor.clone(), sol_vault.clone(), sys_prog.clone()],
        )?;
        mint_bytes = NATIVE_SOL_MINT;
        committed_amount = amount;
    } else {
        ensure(accounts.len() >= 9, AudrenError::InvalidAccount)?;
        let mint = &accounts[3];
        let depositor_ata = &accounts[4];
        let vault_ata = &accounts[5];
        let token_prog = &accounts[6];
        rent_vault_acc = &accounts[7];
        sys_prog = &accounts[8];
        let hook_accounts = &accounts[9..];
        check_supported_token_program(token_prog.key)?;
        check_page_rent_vault(rent_vault_acc, program_id, pool.pool_id)?;
        ensure(
            depositor_ata.is_writable && vault_ata.is_writable && rent_vault_acc.is_writable,
            AudrenError::InvalidAccount,
        )?;
        let mint_info = load_mint_info(mint, token_prog.key)?;
        let (v_auth, _) = vault_auth_pda(program_id, pool.pool_id);
        let (expected_sol_vault, _) = sol_vault_pda(program_id, pool.pool_id);
        let expected_vault = expected_ata(&v_auth, token_prog.key, mint.key);
        ensure(*vault_ata.key == expected_vault, AudrenError::InvalidPda)?;
        ensure(depositor_ata.key != vault_ata.key, AudrenError::InvalidAccount)?;
        let before = token_balance(vault_ata, token_prog.key)?;
        let blocked = [
            pool_acc.key,
            out_page_acc.key,
            rent_vault_acc.key,
            &v_auth,
            &expected_sol_vault,
        ];
        invoke_token_transfer_checked(
            program_id,
            &v_auth,
            token_prog,
            depositor_ata,
            mint,
            vault_ata,
            depositor,
            amount,
            mint_info,
            hook_accounts,
            &blocked,
            &[],
        )?;
        let after = token_balance(vault_ata, token_prog.key)?;
        let net_received = after
            .checked_sub(before)
            .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
        ensure(net_received > 0, AudrenError::ZeroAmount)?;
        mint_bytes = mint.key.to_bytes();
        committed_amount = net_received;
    }

    collect_page_rent_fee(depositor, rent_vault_acc, sys_prog, &pool, 1)?;

    let g_mint = asset_generator(&mint_bytes);
    let commitment = pt_mul_u64(committed_amount, g_mint)?;
    let note = NoteEntry {
        view_tag,
        ephemeral_pk,
        stealth_pk,
        asset_tag: g_mint,
        commitment,
        ciphertext,
    };
    let idx = write_output_note(out_page_acc, program_id, &mut pool, &note)?;
    save_pool(pool_acc, program_id, &pool)?;
    msg!(
        "audren:deposit page={} idx={} amount={}",
        pool.current_page_id,
        idx,
        committed_amount
    );
    Ok(())
}

// ============================================================================
// Tag 3: Transfer (1-in -> 2-out full-private P2P transfer: sender, receiver, token, amount hidden)
// Data: m (1) | note_pay (193) | note_chg (193) | c_pay (32) | c_chg (32)
//       | triptych_proof (1056/1184/1536/1728) | xbase2 (224) | range_u128 (736)
//       | [auditor_asset_proof (192) when InstitutionalAudited]
//       | [optional PQ ML-KEM-768 payload trailing bytes committed in transcript]
// Accounts:
//   [0] payer/relayer (signer, wr), [1] pool (wr), [2] out_page (wr),
//   [3] nullifier_pda (wr), [4] page_rent_vault (wr), [5] zk_program, [6] system_program,
//   [7..7+pages] input EpochPage(s) (ro)
// ============================================================================
fn ix_transfer(program_id: &Address, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    ensure(data.len() >= 1 + 2 * NOTE_WIRE_LEN + 64, AudrenError::InvalidInstruction)?;
    ensure(accounts.len() >= 8, AudrenError::InvalidAccount)?;

    let payer = &accounts[0];
    let pool_acc = &accounts[1];
    let out_page_acc = &accounts[2];
    let nullifier_acc = &accounts[3];
    let rent_vault_acc = &accounts[4];
    let zk_prog = &accounts[5];
    let sys_prog = &accounts[6];
    ensure(payer.is_signer, AudrenError::Unauthorized)?;
    ensure(
        payer.is_writable
            && pool_acc.is_writable
            && out_page_acc.is_writable
            && nullifier_acc.is_writable
            && rent_vault_acc.is_writable,
        AudrenError::InvalidAccount,
    )?;

    let mut pool = load_pool(pool_acc, program_id)?;
    ensure(!pool.paused, AudrenError::PoolPaused)?;
    check_page_rent_vault(rent_vault_acc, program_id, pool.pool_id)?;

    let m = data[0];
    let note_pay = decode_note_wire(&data[1..1 + NOTE_WIRE_LEN])?;
    let note_chg = decode_note_wire(&data[1 + NOTE_WIRE_LEN..1 + 2 * NOTE_WIRE_LEN])?;
    // `note_pay` and `note_chg` carry independent, unlinkable hidden asset tags `A_pay` and `A_chg`.
    // Triptych proves `A_in - A_pay ∈ <H>`, and `verify_cross_base_2` proves `A_chg - A_pay ∈ <H>`,
    // so `V_pay + V_chg = (v_pay + v_chg) * G_mint + (eff_blinding) * H` binds both outputs to the
    // exact same hidden mint generator as the spent note.
    let a_spend = note_pay.asset_tag;
    let v_spend = pt_add(note_pay.commitment, note_chg.commitment)?;

    let mut off = 1 + 2 * NOTE_WIRE_LEN;
    let c_pay = read_32(data, off).map_err(err)?;
    let c_chg = read_32(data, off + 32).map_err(err)?;
    off += 64;

    let audited = pool.has_auditor();
    let trip_len = triptych_proof_len(m, audited).map_err(err)?;
    let aud_asset_len = if audited { AUDITOR_ASSET_PROOF_LEN } else { 0 };
    let min_total = off + trip_len + CROSS_BASE_2_LEN + RANGE_U128_PROOF_LEN + aud_asset_len;
    ensure(data.len() >= min_total, AudrenError::InvalidInstruction)?;

    let trip_bytes = &data[off..off + trip_len];
    off += trip_len;
    let xbase2_bytes = &data[off..off + CROSS_BASE_2_LEN];
    off += CROSS_BASE_2_LEN;
    let range_bytes = &data[off..off + RANGE_U128_PROOF_LEN];
    off += RANGE_U128_PROOF_LEN;
    let aud_asset_bytes = &data[off..off + aud_asset_len];
    off += aud_asset_len;
    // Trailing bytes (e.g. post-quantum NIST ML-KEM-768 P2P ciphertext) are bound to the transcript.
    let pq_envelope = &data[off..];

    let (page_headers, page_borrows) =
        load_input_pages(&accounts[7..], program_id, pool.pool_id, m)?;
    let page_slices: Vec<&[u8]> = page_borrows.iter().map(|r| &***r).collect();

    let ctx_hash = transcript_root(&[
        b"audren/v1/transfer",
        &address_bytes(program_id),
        &pool.pool_id.to_le_bytes(),
        &[m],
        &data[1..1 + 2 * NOTE_WIRE_LEN],
        &c_pay,
        &c_chg,
        pq_envelope,
    ]);

    let auditor_opt = if audited { Some(&pool.auditor_pk) } else { None };
    let verified = verify_triptych(
        m,
        &page_slices,
        &page_headers,
        &a_spend,
        &v_spend,
        auditor_opt,
        &ctx_hash,
        trip_bytes,
    )?;
    verified.check_mode(audited)?;
    drop(page_borrows);

    if let Some(k_aud) = auditor_opt {
        verify_auditor_asset_proof(k_aud, &a_spend, &ctx_hash, aud_asset_bytes)?;
    }

    verify_cross_base_2(
        &note_pay.asset_tag,
        &note_pay.commitment,
        &c_pay,
        &note_chg.asset_tag,
        &note_chg.commitment,
        &c_chg,
        &ctx_hash,
        xbase2_bytes,
    )?;
    verify_native_range_u128(zk_prog, &c_pay, &c_chg, range_bytes)?;

    claim_nullifier(
        payer,
        nullifier_acc,
        sys_prog,
        program_id,
        pool.pool_id,
        &verified.nullifier,
    )?;
    collect_page_rent_fee(payer, rent_vault_acc, sys_prog, &pool, 2)?;

    let idx1 = write_output_note(out_page_acc, program_id, &mut pool, &note_pay)?;
    let idx2 = write_output_note(out_page_acc, program_id, &mut pool, &note_chg)?;
    pool.total_spends = pool
        .total_spends
        .checked_add(1)
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    save_pool(pool_acc, program_id, &pool)?;
    msg!(
        "audren:transfer page={} idx1={} idx2={}",
        pool.current_page_id,
        idx1,
        idx2
    );
    Ok(())
}

// ============================================================================
// Tag 4: Merge (2-in -> 1-out full-private consolidation of two same-asset notes)
// Data: m1 (1) | m2 (1) | note_out (193) | v_in1 (32) | v_in2 (32)
//       | triptych1 | triptych2 | [auditor_asset_proof (192)]
//   Note: Both inputs share `A_out = note_out.asset_tag`, and on-chain we check
//         `v_in1 + v_in2 == note_out.commitment` (so no range proof is even needed:
//         sum of two valid non-negative note values in `[0, 2^64)` cannot overflow
//         when the merged balance stays below `2^64`, checked on subsequent spend!).
//         Wait — to prevent 64-bit wraparound across repeated merges, we STILL require
//         a single 64-bit Bulletproof on `note_out.commitment` (`c_out + xbase1 + range_u64`)!
// Accounts:
//   [0] payer (signer, wr), [1] pool (wr), [2] out_page (wr),
//   [3] nullifier_1 (wr), [4] nullifier_2 (wr), [5] page_rent_vault (wr),
//   [6] zk_program, [7] system_program,
//   [8..8+pages1] input pages for note 1, [8+pages1..8+pages1+pages2] input pages for note 2
// ============================================================================
fn ix_merge(program_id: &Address, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    ensure(data.len() >= 2 + NOTE_WIRE_LEN + 96, AudrenError::InvalidInstruction)?;
    ensure(accounts.len() >= 10, AudrenError::InvalidAccount)?;

    let payer = &accounts[0];
    let pool_acc = &accounts[1];
    let out_page_acc = &accounts[2];
    let null1_acc = &accounts[3];
    let null2_acc = &accounts[4];
    let rent_vault_acc = &accounts[5];
    let zk_prog = &accounts[6];
    let sys_prog = &accounts[7];
    ensure(payer.is_signer, AudrenError::Unauthorized)?;
    ensure(
        payer.is_writable
            && pool_acc.is_writable
            && out_page_acc.is_writable
            && null1_acc.is_writable
            && null2_acc.is_writable
            && rent_vault_acc.is_writable,
        AudrenError::InvalidAccount,
    )?;

    let mut pool = load_pool(pool_acc, program_id)?;
    ensure(!pool.paused, AudrenError::PoolPaused)?;
    check_page_rent_vault(rent_vault_acc, program_id, pool.pool_id)?;

    let m1 = data[0];
    let m2 = data[1];
    let note_out = decode_note_wire(&data[2..2 + NOTE_WIRE_LEN])?;
    let mut off = 2 + NOTE_WIRE_LEN;
    let v_in1 = read_32(data, off).map_err(err)?;
    let v_in2 = read_32(data, off + 32).map_err(err)?;
    let c_out = read_32(data, off + 64).map_err(err)?;
    off += 96;

    validate_point(&v_in1)?;
    validate_point(&v_in2)?;
    ensure(
        pt_add(v_in1, v_in2)? == note_out.commitment,
        AudrenError::InvalidInstruction,
    )?;

    let audited = pool.has_auditor();
    let len1 = triptych_proof_len(m1, audited).map_err(err)?;
    let len2 = triptych_proof_len(m2, audited).map_err(err)?;
    let aud_asset_len = if audited { AUDITOR_ASSET_PROOF_LEN } else { 0 };
    let total = off + len1 + len2 + CROSS_BASE_1_LEN + RANGE_U64_PROOF_LEN + aud_asset_len;
    ensure(data.len() == total, AudrenError::InvalidInstruction)?;

    let trip1 = &data[off..off + len1];
    off += len1;
    let trip2 = &data[off..off + len2];
    off += len2;
    let xbase1 = &data[off..off + CROSS_BASE_1_LEN];
    off += CROSS_BASE_1_LEN;
    let range64 = &data[off..off + RANGE_U64_PROOF_LEN];
    off += RANGE_U64_PROOF_LEN;
    let aud_asset = &data[off..off + aud_asset_len];

    let n_pages1 = input_pages_for_m(m1).map_err(err)?;
    let n_pages2 = input_pages_for_m(m2).map_err(err)?;
    ensure(
        accounts.len() >= 8 + n_pages1 + n_pages2,
        AudrenError::InvalidAccount,
    )?;

    let (hdr1, bor1) = load_input_pages(&accounts[8..8 + n_pages1], program_id, pool.pool_id, m1)?;
    let (hdr2, bor2) = load_input_pages(
        &accounts[8 + n_pages1..8 + n_pages1 + n_pages2],
        program_id,
        pool.pool_id,
        m2,
    )?;
    let sl1: Vec<&[u8]> = bor1.iter().map(|r| &***r).collect();
    let sl2: Vec<&[u8]> = bor2.iter().map(|r| &***r).collect();

    let ctx_base = transcript_root(&[
        b"audren/v1/merge",
        &address_bytes(program_id),
        &pool.pool_id.to_le_bytes(),
        &[m1, m2],
        &data[2..2 + NOTE_WIRE_LEN],
        &v_in1,
        &v_in2,
        &c_out,
    ]);
    let ctx1 = transcript_root(&[b"leg1", &ctx_base]);
    let ctx2 = transcript_root(&[b"leg2", &ctx_base]);

    let auditor_opt = if audited { Some(&pool.auditor_pk) } else { None };
    let ver1 = verify_triptych(
        m1,
        &sl1,
        &hdr1,
        &note_out.asset_tag,
        &v_in1,
        auditor_opt,
        &ctx1,
        trip1,
    )?;
    ver1.check_mode(audited)?;
    let ver2 = verify_triptych(
        m2,
        &sl2,
        &hdr2,
        &note_out.asset_tag,
        &v_in2,
        auditor_opt,
        &ctx2,
        trip2,
    )?;
    ver2.check_mode(audited)?;
    drop(bor1);
    drop(bor2);
    ensure(
        ver1.nullifier != ver2.nullifier,
        AudrenError::NullifierAlreadySpent,
    )?;
    if let Some(k_aud) = auditor_opt {
        verify_auditor_asset_proof(k_aud, &note_out.asset_tag, &ctx_base, aud_asset)?;
    }

    verify_cross_base_1(
        &note_out.asset_tag,
        &note_out.commitment,
        &c_out,
        &ctx_base,
        xbase1,
    )?;
    verify_native_range_u64(zk_prog, &c_out, range64)?;

    claim_nullifier(
        payer,
        null1_acc,
        sys_prog,
        program_id,
        pool.pool_id,
        &ver1.nullifier,
    )?;
    claim_nullifier(
        payer,
        null2_acc,
        sys_prog,
        program_id,
        pool.pool_id,
        &ver2.nullifier,
    )?;
    collect_page_rent_fee(payer, rent_vault_acc, sys_prog, &pool, 1)?;

    let idx = write_output_note(out_page_acc, program_id, &mut pool, &note_out)?;
    pool.total_spends = pool
        .total_spends
        .checked_add(2)
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    save_pool(pool_acc, program_id, &pool)?;
    msg!("audren:merge page={} idx={}", pool.current_page_id, idx);
    Ok(())
}

// ============================================================================
// Tag 5: SwapViaRouter (1-tx router-agnostic private swap via isolated `swap_escrow` PDA)
//
// Works with ANY Solana DEX aggregator or AMM router (Jupiter, Raydium, Orca, Meteora,
// Phoenix, Titan, DFlow, or custom routers). Shared protocol `swap_escrow` executes the
// external CPI with isolated custody; dynamic `actual_out` returns directly into an
// unlinkable stealth note for the unknown originator inside the shared `EpochPage`.
//
// Data:
//   m (1) | shard_id (1) | flags (1: bit0=has_change, bit1=allow_partial_refund)
//   | amount_in (8) | min_amount_out (8)
//   | escrow_idx (1) | escrow_in_idx (1) | escrow_out_idx (1) | router_data_len (2)
//   | swap_out_desc (129: DynamicOutputWire for P_out)
//   | [change_note (193) + c_chg (32) + xbase1 (128) + range64 (672) if has_change]
//   | [refund_desc (129: DynamicOutputWire for unspent CLOB input) if allow_partial_refund]
//   | triptych_proof (928/1056/1184/1344/1536/1728)
//   | router_instruction_data (router_data_len)
//
// Accounts:
//   [0] payer/relayer (signer, wr)
//   [1] pool (wr)
//   [2] out_page (wr)
//   [3] nullifier_pda (wr)
//   [4] page_rent_vault (wr)
//   [5] zk_program
//   [6] system_program
//   [7] vault_auth (ro PDA)
//   [8] mint_in (ro)
//   [9] vault_in (wr ATA of vault_auth for mint_in)
//   [10] token_program_in (ro)
//   [11] mint_out (ro)
//   [12] vault_out (wr ATA of vault_auth for mint_out)
//   [13] token_program_out (ro)
//   [14] router_program (ro, executable external DEX / aggregator program)
//   [15..15+pages] input EpochPage(s) (ro)
//   [15+pages..] Router instruction accounts in exact router order:
//       router[escrow_idx]     = swap_escrow PDA (signed via invoke_signed)
//       router[escrow_in_idx]  = escrow_in (wr ATA owned by swap_escrow for mint_in)
//       router[escrow_out_idx] = escrow_out (wr ATA owned by swap_escrow for mint_out)
// ============================================================================
fn ix_swap_via_router(
    program_id: &Address,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    ensure(
        data.len() >= 24 + DYNAMIC_OUTPUT_WIRE_LEN,
        AudrenError::InvalidInstruction,
    )?;
    ensure(accounts.len() >= 19, AudrenError::InvalidAccount)?;

    let payer = &accounts[0];
    let pool_acc = &accounts[1];
    let out_page_acc = &accounts[2];
    let nullifier_acc = &accounts[3];
    let rent_vault_acc = &accounts[4];
    let zk_prog = &accounts[5];
    let sys_prog = &accounts[6];
    let vault_auth_acc = &accounts[7];
    let mint_in = &accounts[8];
    let vault_in = &accounts[9];
    let token_prog_in = &accounts[10];
    let mint_out = &accounts[11];
    let vault_out = &accounts[12];
    let token_prog_out = &accounts[13];
    let router_prog = &accounts[14];

    ensure(payer.is_signer, AudrenError::Unauthorized)?;
    ensure(
        payer.is_writable
            && pool_acc.is_writable
            && out_page_acc.is_writable
            && nullifier_acc.is_writable
            && rent_vault_acc.is_writable
            && vault_in.is_writable
            && vault_out.is_writable,
        AudrenError::InvalidAccount,
    )?;
    // Allow any executable external DEX/aggregator router, blocking self-reentrancy and native/token programs.
    ensure(
        router_prog.executable
            && router_prog.key != program_id
            && router_prog.key != sys_prog.key
            && router_prog.key != zk_prog.key
            && router_prog.key != token_prog_in.key
            && router_prog.key != token_prog_out.key,
        AudrenError::InvalidRouterProgram,
    )?;

    let mut pool = load_pool(pool_acc, program_id)?;
    ensure(!pool.paused, AudrenError::PoolPaused)?;
    check_page_rent_vault(rent_vault_acc, program_id, pool.pool_id)?;
    check_supported_token_program(token_prog_in.key)?;
    check_supported_token_program(token_prog_out.key)?;
    let mint_info_in = load_mint_info(mint_in, token_prog_in.key)?;
    let mint_info_out = load_mint_info(mint_out, token_prog_out.key)?;

    let (expected_va, va_bump) = vault_auth_pda(program_id, pool.pool_id);
    ensure(*vault_auth_acc.key == expected_va, AudrenError::InvalidPda)?;
    ensure(
        *vault_in.key == expected_ata(&expected_va, token_prog_in.key, mint_in.key),
        AudrenError::InvalidPda,
    )?;
    ensure(
        *vault_out.key == expected_ata(&expected_va, token_prog_out.key, mint_out.key),
        AudrenError::InvalidPda,
    )?;

    // Parse header.
    let m = data[0];
    let shard_id = data[1];
    let flags = data[2];
    let has_change = (flags & 1) != 0;
    let allow_partial = (flags & 2) != 0;
    let amount_in = read_u64(data, 3).map_err(err)?;
    let min_amount_out = read_u64(data, 11).map_err(err)?;
    let escrow_idx = data[19] as usize;
    let escrow_in_idx = data[20] as usize;
    let escrow_out_idx = data[21] as usize;
    let router_data_len = u16::from_le_bytes([data[22], data[23]]) as usize;
    ensure(amount_in > 0 && min_amount_out > 0, AudrenError::ZeroAmount)?;

    let mut off = 24usize;
    let out_desc = &data[off..off + DYNAMIC_OUTPUT_WIRE_LEN];
    off += DYNAMIC_OUTPUT_WIRE_LEN;
    let out_view_tag = out_desc[0];
    let out_eph_pk = read_32(out_desc, 1).map_err(err)?;
    let out_stealth_pk = read_32(out_desc, 33).map_err(err)?;
    validate_nonzero_point(&out_stealth_pk)?;
    let mut out_ct = [0u8; NOTE_CT_LEN];
    out_ct.copy_from_slice(&out_desc[65..65 + NOTE_CT_LEN]);

    let mut change_bundle: Option<(NoteEntry, [u8; 32], &[u8], &[u8])> = None;
    if has_change {
        let chg_need = NOTE_WIRE_LEN + 32 + CROSS_BASE_1_LEN + RANGE_U64_PROOF_LEN;
        ensure(data.len() >= off + chg_need, AudrenError::InvalidInstruction)?;
        let note_chg = decode_note_wire(&data[off..off + NOTE_WIRE_LEN])?;
        off += NOTE_WIRE_LEN;
        let c_chg = read_32(data, off).map_err(err)?;
        off += 32;
        let xbase1 = &data[off..off + CROSS_BASE_1_LEN];
        off += CROSS_BASE_1_LEN;
        let range64 = &data[off..off + RANGE_U64_PROOF_LEN];
        off += RANGE_U64_PROOF_LEN;
        change_bundle = Some((note_chg, c_chg, xbase1, range64));
    }

    let mut refund_desc: Option<(u8, [u8; 32], [u8; 32], [u8; NOTE_CT_LEN])> = None;
    let mut refund_raw: &[u8] = &[];
    if allow_partial {
        ensure(
            data.len() >= off + DYNAMIC_OUTPUT_WIRE_LEN,
            AudrenError::InvalidInstruction,
        )?;
        let rd = &data[off..off + DYNAMIC_OUTPUT_WIRE_LEN];
        refund_raw = rd;
        off += DYNAMIC_OUTPUT_WIRE_LEN;
        let r_stealth = read_32(rd, 33).map_err(err)?;
        validate_nonzero_point(&r_stealth)?;
        let mut r_ct = [0u8; NOTE_CT_LEN];
        r_ct.copy_from_slice(&rd[65..65 + NOTE_CT_LEN]);
        refund_desc = Some((rd[0], read_32(rd, 1).map_err(err)?, r_stealth, r_ct));
    }

    let audited = pool.has_auditor();
    let trip_len = triptych_proof_len(m, audited).map_err(err)?;
    ensure(
        data.len() == off + trip_len + router_data_len,
        AudrenError::InvalidInstruction,
    )?;
    let trip_bytes = &data[off..off + trip_len];
    off += trip_len;
    let router_data = &data[off..off + router_data_len];

    let g_in = asset_generator(&mint_in.key.to_bytes());
    let v_in_exact = pt_mul_u64(amount_in, g_in)?;
    let v_spend = if let Some((ref note_chg, _, _, _)) = change_bundle {
        ensure(note_chg.asset_tag == g_in, AudrenError::InvalidInstruction)?;
        pt_add(v_in_exact, note_chg.commitment)?
    } else {
        v_in_exact
    };

    let n_pages = input_pages_for_m(m).map_err(err)?;
    let router_start = 15 + n_pages;
    ensure(accounts.len() >= router_start + 3, AudrenError::InvalidAccount)?;
    let router_accounts = &accounts[router_start..];
    ensure(
        router_accounts.len() <= MAX_ROUTER_CPI_ACCOUNTS
            && escrow_idx < router_accounts.len()
            && escrow_in_idx < router_accounts.len()
            && escrow_out_idx < router_accounts.len()
            && escrow_idx != escrow_in_idx
            && escrow_idx != escrow_out_idx
            && escrow_in_idx != escrow_out_idx,
        AudrenError::InvalidAccount,
    )?;

    let (expected_escrow, escrow_bump) = escrow_pda(program_id, pool.pool_id, shard_id)?;
    let escrow_acc = &router_accounts[escrow_idx];
    let escrow_in = &router_accounts[escrow_in_idx];
    let escrow_out = &router_accounts[escrow_out_idx];
    ensure(*escrow_acc.key == expected_escrow, AudrenError::InvalidPda)?;
    ensure(
        escrow_in.is_writable && escrow_out.is_writable,
        AudrenError::InvalidAccount,
    )?;
    ensure(
        escrow_acc.owner == &system::id() && escrow_acc.data_is_empty(),
        AudrenError::EscrowAuthorityAltered,
    )?;
    ensure(
        *escrow_in.key == expected_ata(&expected_escrow, token_prog_in.key, mint_in.key),
        AudrenError::InvalidPda,
    )?;
    ensure(
        *escrow_out.key == expected_ata(&expected_escrow, token_prog_out.key, mint_out.key),
        AudrenError::InvalidPda,
    )?;
    // Ensure input and output mints differ so escrow_in != escrow_out.
    ensure(mint_in.key != mint_out.key, AudrenError::InvalidInstruction)?;

    // Build Fiat-Shamir context binding EVERY swap term (including `router_prog.key`) so neither
    // a relayer nor searcher can substitute the router, mints, `min_amount_out`, or stealth outputs.
    let chg_commit = change_bundle
        .as_ref()
        .map(|(n, _, _, _)| n.commitment)
        .unwrap_or(IDENTITY);
    let ctx_hash = transcript_root(&[
        b"audren/v1/swap_router",
        &address_bytes(program_id),
        &pool.pool_id.to_le_bytes(),
        &[m, shard_id, flags],
        &router_prog.key.to_bytes(),
        &mint_in.key.to_bytes(),
        &mint_out.key.to_bytes(),
        &amount_in.to_le_bytes(),
        &min_amount_out.to_le_bytes(),
        out_desc,
        &chg_commit,
        refund_raw,
    ]);

    // 1. Verify Triptych proof + optional change range proof.
    let (page_headers, page_borrows) =
        load_input_pages(&accounts[15..router_start], program_id, pool.pool_id, m)?;
    let page_slices: Vec<&[u8]> = page_borrows.iter().map(|r| &***r).collect();
    let auditor_opt = if audited { Some(&pool.auditor_pk) } else { None };
    let verified = verify_triptych(
        m,
        &page_slices,
        &page_headers,
        &g_in,
        &v_spend,
        auditor_opt,
        &ctx_hash,
        trip_bytes,
    )?;
    verified.check_mode(audited)?;
    drop(page_borrows);

    if let Some((ref note_chg, ref c_chg, xbase1, range64)) = change_bundle {
        verify_cross_base_1(&note_chg.asset_tag, &note_chg.commitment, c_chg, &ctx_hash, xbase1)?;
        verify_native_range_u64(zk_prog, c_chg, range64)?;
    }

    // 2. Claim nullifier before external CPI (prevents any re-entrancy / replay).
    claim_nullifier(
        payer,
        nullifier_acc,
        sys_prog,
        program_id,
        pool.pool_id,
        &verified.nullifier,
    )?;

    // 3. Validate router account firewall & snapshot every writable token account owned by
    //    `swap_escrow` BEFORE any external CPI (including optional TransferHook accounts).
    let (expected_sol_vault, _) = sol_vault_pda(program_id, pool.pool_id);
    let mut watched_escrow_accs: Vec<(usize, Address, Option<Address>)> = Vec::new();
    for (idx, acc) in router_accounts.iter().enumerate() {
        ensure(
            acc.key != program_id
                && acc.owner != program_id
                && acc.key != vault_auth_acc.key
                && acc.key != vault_in.key
                && acc.key != vault_out.key
                && acc.key != pool_acc.key
                && acc.key != out_page_acc.key
                && acc.key != nullifier_acc.key
                && acc.key != rent_vault_acc.key
                && *acc.key != expected_sol_vault,
            AudrenError::InvalidAccount,
        )?;
        if !acc.is_writable {
            continue;
        }
        if let Some(snap) = token_account_security(acc) {
            if snap.owner == expected_escrow {
                ensure(!snap.has_delegate, AudrenError::EscrowAccountAltered)?;
                watched_escrow_accs.push((idx, snap.token_program, snap.close_authority));
            }
        }
    }

    // 4. Custody isolation: transfer exact `amount_in` from global `vault_in` -> isolated `escrow_in`.
    let escrow_lamports_before = escrow_acc.lamports();
    let escrow_in_before = token_balance(escrow_in, token_prog_in.key)?;
    let escrow_out_before = token_balance(escrow_out, token_prog_out.key)?;
    let vault_in_before_fund = token_balance(vault_in, token_prog_in.key)?;

    let pool_le = pool.pool_id.to_le_bytes();
    let va_seeds: &[&[u8]] = &[VAULT_AUTH_SEED, &pool_le, &[va_bump]];
    let swap_blocked = [
        payer.key,
        pool_acc.key,
        out_page_acc.key,
        nullifier_acc.key,
        rent_vault_acc.key,
        vault_auth_acc.key,
        vault_in.key,
        vault_out.key,
        &expected_sol_vault,
    ];
    invoke_token_transfer_checked(
        program_id,
        vault_auth_acc.key,
        token_prog_in,
        vault_in,
        mint_in,
        escrow_in,
        vault_auth_acc,
        amount_in,
        mint_info_in,
        router_accounts,
        &swap_blocked,
        &[va_seeds],
    )?;
    let vault_in_after_fund = token_balance(vault_in, token_prog_in.key)?;
    ensure(
        vault_in_before_fund.checked_sub(vault_in_after_fund) == Some(amount_in),
        AudrenError::ArithmeticOverflow,
    )?;
    let escrow_in_funded = token_balance(escrow_in, token_prog_in.key)?
        .checked_sub(escrow_in_before)
        .ok_or_else(|| err(AudrenError::EscrowAccountAltered))?;

    // 5. Invoke the external router with ONLY `swap_escrow` signing (never `vault_auth` or `payer`).
    let cpi_metas: Vec<solana_instruction::AccountMeta> = router_accounts
        .iter()
        .map(|acc| {
            let is_signer = acc.key == &expected_escrow;
            if acc.is_writable {
                solana_instruction::AccountMeta::new(*acc.key, is_signer)
            } else {
                solana_instruction::AccountMeta::new_readonly(*acc.key, is_signer)
            }
        })
        .collect();
    let router_ix = solana_instruction::Instruction {
        program_id: *router_prog.key,
        accounts: cpi_metas,
        data: router_data.to_vec(),
    };
    let escrow_seeds: &[&[u8]] = &[ESCROW_SEED, &pool_le, &[shard_id], &[escrow_bump]];
    invoke_signed(&router_ix, router_accounts, &[escrow_seeds])?;

    // 6. Post-CPI custody & authority integrity checks (owner, lamports, zero delegate, close_authority).
    ensure(
        escrow_acc.owner == &system::id()
            && escrow_acc.data_is_empty()
            && escrow_acc.lamports() >= escrow_lamports_before,
        AudrenError::EscrowAuthorityAltered,
    )?;
    for &(idx, expected_prog, expected_close_auth) in &watched_escrow_accs {
        let acc = &router_accounts[idx];
        let Some(snap) = token_account_security(acc) else {
            return Err(err(AudrenError::EscrowAccountAltered));
        };
        ensure(
            snap.token_program == expected_prog
                && snap.owner == expected_escrow
                && !snap.has_delegate
                && snap.close_authority == expected_close_auth,
            AudrenError::EscrowAccountAltered,
        )?;
    }

    let escrow_out_after = token_balance(escrow_out, token_prog_out.key)?;
    let escrow_in_after = token_balance(escrow_in, token_prog_in.key)?;
    let actual_out = escrow_out_after
        .checked_sub(escrow_out_before)
        .ok_or_else(|| err(AudrenError::SlippageExceeded))?;
    ensure(actual_out > 0, AudrenError::SlippageExceeded)?;

    let unspent_in = escrow_in_after
        .checked_sub(escrow_in_before)
        .ok_or_else(|| err(AudrenError::EscrowAccountAltered))?;
    ensure(unspent_in <= escrow_in_funded, AudrenError::EscrowAccountAltered)?;
    if unspent_in > 0 {
        ensure(allow_partial, AudrenError::UnexpectedPartialFill)?;
    }

    // 7. Sweep `actual_out` from `escrow_out` -> global `vault_out` and commit the exact net
    //    vault delta `net_out >= min_amount_out` (1:1 solvent even on TransferFee mints).
    let vault_out_before = token_balance(vault_out, token_prog_out.key)?;
    invoke_token_transfer_checked(
        program_id,
        vault_auth_acc.key,
        token_prog_out,
        escrow_out,
        mint_out,
        vault_out,
        escrow_acc,
        actual_out,
        mint_info_out,
        router_accounts,
        &swap_blocked,
        &[escrow_seeds],
    )?;
    let vault_out_after = token_balance(vault_out, token_prog_out.key)?;
    let net_out = vault_out_after
        .checked_sub(vault_out_before)
        .ok_or_else(|| err(AudrenError::SlippageExceeded))?;
    ensure(net_out >= min_amount_out, AudrenError::SlippageExceeded)?;

    let mut net_refund = 0u64;
    if unspent_in > 0 {
        let vault_in_before = token_balance(vault_in, token_prog_in.key)?;
        invoke_token_transfer_checked(
            program_id,
            vault_auth_acc.key,
            token_prog_in,
            escrow_in,
            mint_in,
            vault_in,
            escrow_acc,
            unspent_in,
            mint_info_in,
            router_accounts,
            &swap_blocked,
            &[escrow_seeds],
        )?;
        let vault_in_after = token_balance(vault_in, token_prog_in.key)?;
        net_refund = vault_in_after
            .checked_sub(vault_in_before)
            .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    }

    // 8. Compute dynamic `V_out = net_out * G_{mint_out}` on-chain
    //    and append fresh stealth note(s) into the shared `EpochPage`.
    let out_notes_count = 1u64 + u64::from(has_change) + u64::from(net_refund > 0);
    collect_page_rent_fee(payer, rent_vault_acc, sys_prog, &pool, out_notes_count)?;

    let g_out = asset_generator(&mint_out.key.to_bytes());
    let v_out = pt_mul_u64(net_out, g_out)?;
    let swap_note = NoteEntry {
        view_tag: out_view_tag,
        ephemeral_pk: out_eph_pk,
        stealth_pk: out_stealth_pk,
        asset_tag: g_out,
        commitment: v_out,
        ciphertext: out_ct,
    };
    let idx_out = write_output_note(out_page_acc, program_id, &mut pool, &swap_note)?;

    if let Some((note_chg, _, _, _)) = change_bundle {
        write_output_note(out_page_acc, program_id, &mut pool, &note_chg)?;
    }
    if net_refund > 0 {
        if let Some((r_tag, r_eph, r_stealth, r_ct)) = refund_desc {
            let v_ref = pt_mul_u64(net_refund, g_in)?;
            let refund_note = NoteEntry {
                view_tag: r_tag,
                ephemeral_pk: r_eph,
                stealth_pk: r_stealth,
                asset_tag: g_in,
                commitment: v_ref,
                ciphertext: r_ct,
            };
            write_output_note(out_page_acc, program_id, &mut pool, &refund_note)?;
        }
    }

    pool.total_spends = pool
        .total_spends
        .checked_add(1)
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    save_pool(pool_acc, program_id, &pool)?;
    msg!(
        "audren:swap_router page={} idx={} net_out={} net_refund={}",
        pool.current_page_id,
        idx_out,
        net_out,
        net_refund
    );
    Ok(())
}

// ============================================================================
// Tag 6: Withdraw (full-private 1-in spend -> public recipient SPL/SOL + optional hidden change)
// Data: m (1) | is_native_sol (1) | has_change (1) | amount_out (8)
//       | [change_note (193) + c_chg (32) + xbase1 (128) + range64 (672) if has_change]
//       | triptych_proof (1056/1184/1536/1728)
// Accounts (Native SOL):
//   [0] payer (signer, wr), [1] pool (wr), [2] out_page (wr), [3] nullifier_pda (wr),
//   [4] page_rent_vault (wr), [5] zk_program, [6] system_program,
//   [7] sol_vault (wr), [8] recipient (wr),
//   [9..9+pages] input EpochPage(s) (ro)
// Accounts (SPL / Token-2022):
//   [0] payer (signer, wr), [1] pool (wr), [2] out_page (wr), [3] nullifier_pda (wr),
//   [4] page_rent_vault (wr), [5] zk_program, [6] system_program,
//   [7] vault_auth (ro), [8] mint (ro), [9] vault_ata (wr), [10] recipient_ata (wr),
//   [11] token_program (ro),
//   [12..12+pages] input EpochPage(s) (ro)
// ============================================================================
fn ix_withdraw(program_id: &Address, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    ensure(data.len() >= 11, AudrenError::InvalidInstruction)?;
    let m = data[0];
    let is_native = data[1] != 0;
    let has_change = data[2] != 0;
    let amount_out = read_u64(data, 3).map_err(err)?;
    ensure(amount_out > 0, AudrenError::ZeroAmount)?;
    ensure(accounts.len() >= 10, AudrenError::InvalidAccount)?;

    let payer = &accounts[0];
    let pool_acc = &accounts[1];
    let out_page_acc = &accounts[2];
    let nullifier_acc = &accounts[3];
    let rent_vault_acc = &accounts[4];
    let zk_prog = &accounts[5];
    let sys_prog = &accounts[6];
    ensure(payer.is_signer, AudrenError::Unauthorized)?;
    ensure(
        payer.is_writable && pool_acc.is_writable && nullifier_acc.is_writable,
        AudrenError::InvalidAccount,
    )?;
    if has_change {
        ensure(
            out_page_acc.is_writable && rent_vault_acc.is_writable,
            AudrenError::InvalidAccount,
        )?;
    }

    let mut pool = load_pool(pool_acc, program_id)?;
    ensure(!pool.paused, AudrenError::PoolPaused)?;
    check_page_rent_vault(rent_vault_acc, program_id, pool.pool_id)?;

    let mut off = 11usize;
    let mut change_bundle: Option<(NoteEntry, [u8; 32], &[u8], &[u8])> = None;
    if has_change {
        let chg_need = NOTE_WIRE_LEN + 32 + CROSS_BASE_1_LEN + RANGE_U64_PROOF_LEN;
        ensure(data.len() >= off + chg_need, AudrenError::InvalidInstruction)?;
        let note_chg = decode_note_wire(&data[off..off + NOTE_WIRE_LEN])?;
        off += NOTE_WIRE_LEN;
        let c_chg = read_32(data, off).map_err(err)?;
        off += 32;
        let xbase1 = &data[off..off + CROSS_BASE_1_LEN];
        off += CROSS_BASE_1_LEN;
        let range64 = &data[off..off + RANGE_U64_PROOF_LEN];
        off += RANGE_U64_PROOF_LEN;
        change_bundle = Some((note_chg, c_chg, xbase1, range64));
    }

    let audited = pool.has_auditor();
    let trip_len = triptych_proof_len(m, audited).map_err(err)?;
    ensure(data.len() == off + trip_len, AudrenError::InvalidInstruction)?;
    let trip_bytes = &data[off..off + trip_len];

    let (mint_bytes, recipient_key, pages_start) = if is_native {
        ensure(accounts.len() >= 10, AudrenError::InvalidAccount)?;
        ensure(
            accounts[7].is_writable && accounts[8].is_writable,
            AudrenError::InvalidAccount,
        )?;
        (NATIVE_SOL_MINT, accounts[8].key.to_bytes(), 9usize)
    } else {
        ensure(accounts.len() >= 13, AudrenError::InvalidAccount)?;
        ensure(
            accounts[9].is_writable && accounts[10].is_writable,
            AudrenError::InvalidAccount,
        )?;
        (accounts[8].key.to_bytes(), accounts[10].key.to_bytes(), 12usize)
    };

    let g_mint = asset_generator(&mint_bytes);
    let v_out = pt_mul_u64(amount_out, g_mint)?;
    let v_spend = if let Some((ref note_chg, _, _, _)) = change_bundle {
        ensure(note_chg.asset_tag == g_mint, AudrenError::InvalidInstruction)?;
        pt_add(v_out, note_chg.commitment)?
    } else {
        v_out
    };

    let chg_commit = change_bundle
        .as_ref()
        .map(|(n, _, _, _)| n.commitment)
        .unwrap_or(IDENTITY);
    let ctx_hash = transcript_root(&[
        b"audren/v1/withdraw",
        &address_bytes(program_id),
        &pool.pool_id.to_le_bytes(),
        &[m, u8::from(is_native), u8::from(has_change)],
        &mint_bytes,
        &recipient_key,
        &amount_out.to_le_bytes(),
        &chg_commit,
    ]);

    let (page_headers, page_borrows) =
        load_input_pages(&accounts[pages_start..], program_id, pool.pool_id, m)?;
    let page_slices: Vec<&[u8]> = page_borrows.iter().map(|r| &***r).collect();
    let auditor_opt = if audited { Some(&pool.auditor_pk) } else { None };
    let verified = verify_triptych(
        m,
        &page_slices,
        &page_headers,
        &g_mint,
        &v_spend,
        auditor_opt,
        &ctx_hash,
        trip_bytes,
    )?;
    verified.check_mode(audited)?;
    drop(page_borrows);

    if let Some((ref note_chg, ref c_chg, xbase1, range64)) = change_bundle {
        ensure(
            !is_zero_point(&note_chg.stealth_pk),
            AudrenError::InvalidPoint,
        )?;
        verify_cross_base_1(&note_chg.asset_tag, &note_chg.commitment, c_chg, &ctx_hash, xbase1)?;
        verify_native_range_u64(zk_prog, c_chg, range64)?;
    }

    claim_nullifier(
        payer,
        nullifier_acc,
        sys_prog,
        program_id,
        pool.pool_id,
        &verified.nullifier,
    )?;

    if let Some((note_chg, _, _, _)) = change_bundle {
        collect_page_rent_fee(payer, rent_vault_acc, sys_prog, &pool, 1)?;
        write_output_note(out_page_acc, program_id, &mut pool, &note_chg)?;
    }

    if is_native {
        let sol_vault = &accounts[7];
        let recipient = &accounts[8];
        check_sol_vault(sol_vault, program_id, pool.pool_id)?;
        ensure(recipient.key != sol_vault.key, AudrenError::InvalidAccount)?;
        let min_bal = Rent::get()?.minimum_balance(SENTINEL_ACCOUNT_LEN);
        let new_bal = sol_vault
            .lamports()
            .checked_sub(amount_out)
            .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
        ensure(new_bal >= min_bal, AudrenError::ArithmeticOverflow)?;
        **sol_vault.try_borrow_mut_lamports()? = new_bal;
        **recipient.try_borrow_mut_lamports()? = recipient
            .lamports()
            .checked_add(amount_out)
            .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    } else {
        let vault_auth = &accounts[7];
        let mint = &accounts[8];
        let vault_ata = &accounts[9];
        let recipient_ata = &accounts[10];
        let token_prog = &accounts[11];
        let n_pages = input_pages_for_m(m).map_err(err)?;
        let hook_accounts = &accounts[pages_start + n_pages..];
        check_supported_token_program(token_prog.key)?;
        let mint_info = load_mint_info(mint, token_prog.key)?;
        let (expected_va, va_bump) = vault_auth_pda(program_id, pool.pool_id);
        let (expected_sol_vault, _) = sol_vault_pda(program_id, pool.pool_id);
        ensure(*vault_auth.key == expected_va, AudrenError::InvalidPda)?;
        ensure(
            *vault_ata.key == expected_ata(&expected_va, token_prog.key, mint.key),
            AudrenError::InvalidPda,
        )?;
        ensure(recipient_ata.key != vault_ata.key, AudrenError::InvalidAccount)?;
        let pool_le = pool.pool_id.to_le_bytes();
        let va_seeds: &[&[u8]] = &[VAULT_AUTH_SEED, &pool_le, &[va_bump]];
        let vault_before = token_balance(vault_ata, token_prog.key)?;
        let blocked = [
            payer.key,
            pool_acc.key,
            out_page_acc.key,
            nullifier_acc.key,
            rent_vault_acc.key,
            &expected_sol_vault,
        ];
        invoke_token_transfer_checked(
            program_id,
            &expected_va,
            token_prog,
            vault_ata,
            mint,
            recipient_ata,
            vault_auth,
            amount_out,
            mint_info,
            hook_accounts,
            &blocked,
            &[va_seeds],
        )?;
        let vault_after = token_balance(vault_ata, token_prog.key)?;
        ensure(
            vault_before.checked_sub(vault_after) == Some(amount_out),
            AudrenError::ArithmeticOverflow,
        )?;
    }

    // Touch `WSOL_MINT` so the constant stays linked and audited for WSOL swap routes.
    let _ = WSOL_MINT;

    pool.total_spends = pool
        .total_spends
        .checked_add(1)
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    save_pool(pool_acc, program_id, &pool)?;
    msg!("audren:withdraw amount={}", amount_out);
    Ok(())
}

// ============================================================================
// Tag 7: SetPaused (authority emergency pause — never grants fund withdrawal)
// Data: paused (1)
// Accounts: [0] authority (signer), [1] pool (wr)
// ============================================================================
fn ix_set_paused(program_id: &Address, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    ensure(data.len() == 1, AudrenError::InvalidInstruction)?;
    ensure(accounts.len() >= 2, AudrenError::InvalidAccount)?;
    let authority = &accounts[0];
    let pool_acc = &accounts[1];
    ensure(authority.is_signer, AudrenError::Unauthorized)?;
    ensure(pool_acc.is_writable, AudrenError::InvalidAccount)?;
    let mut pool = load_pool(pool_acc, program_id)?;
    ensure(
        authority.key.to_bytes() == pool.authority,
        AudrenError::Unauthorized,
    )?;
    pool.paused = data[0] != 0;
    save_pool(pool_acc, program_id, &pool)?;
    msg!("audren:set_paused paused={}", pool.paused);
    Ok(())
}

/// Zero magic, shrink to 0 bytes, assign back to System Program, and refund 100% of rent to `payer`.
fn close_proof_buffer_account(
    proof_buffer: &AccountInfo,
    payer: &AccountInfo,
) -> ProgramResult {
    {
        let mut buf = proof_buffer.try_borrow_mut_data()?;
        if buf.len() >= 8 {
            buf[..8].fill(0);
        }
    }
    proof_buffer.resize(0)?;
    proof_buffer.assign(&system::id());
    let refund = proof_buffer.lamports();
    **proof_buffer.try_borrow_mut_lamports()? = 0;
    **payer.try_borrow_mut_lamports()? = payer
        .lamports()
        .checked_add(refund)
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    Ok(())
}

// ============================================================================
// Tag 8: WriteProofBuffer (out-of-order / parallel <=768 B chunk uploader)
// Data: nonce (8) | total_len (4) | chunk_index (1) | chunk (1..=768 B)
// Accounts: [0] payer/authority (signer, wr), [1] proof_buffer PDA (wr), [2] system_program
// ============================================================================
fn ix_write_proof_buffer(
    program_id: &Address,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    ensure(data.len() >= 14, AudrenError::InvalidInstruction)?;
    ensure(accounts.len() >= 3, AudrenError::InvalidAccount)?;
    let payer = &accounts[0];
    let buf_acc = &accounts[1];
    let sys_prog = &accounts[2];
    ensure(payer.is_signer && payer.is_writable, AudrenError::Unauthorized)?;
    ensure(
        buf_acc.is_writable && *sys_prog.key == system::id() && buf_acc.key != payer.key,
        AudrenError::InvalidAccount,
    )?;

    let nonce = read_u64(data, 0).map_err(err)?;
    let total_len = read_u32(data, 8).map_err(err)? as usize;
    let chunk_index = data[12] as usize;
    let chunk = &data[13..];

    ensure(
        total_len > 0 && total_len <= PROOF_BUFFER_MAX_PAYLOAD,
        AudrenError::InvalidProofBuffer,
    )?;
    let num_chunks = total_len.div_ceil(PROOF_BUFFER_CHUNK_SIZE);
    ensure(chunk_index < num_chunks, AudrenError::InvalidProofBuffer)?;
    let start = chunk_index * PROOF_BUFFER_CHUNK_SIZE;
    let expected_chunk_len = (total_len - start).min(PROOF_BUFFER_CHUNK_SIZE);
    ensure(
        chunk.len() == expected_chunk_len,
        AudrenError::InvalidProofBuffer,
    )?;

    let (expected_buf, bump) = proof_buffer_pda(program_id, payer.key, nonce);
    ensure(*buf_acc.key == expected_buf, AudrenError::InvalidPda)?;

    let expected_space = PROOF_BUFFER_HEADER_LEN + total_len;
    if buf_acc.data_is_empty() {
        let nonce_le = nonce.to_le_bytes();
        let seeds: &[&[u8]] = &[PROOF_BUFFER_SEED, payer.key.as_ref(), &nonce_le, &[bump]];
        create_pda(payer, buf_acc, sys_prog, seeds, expected_space, program_id)?;
        let mut buf = buf_acc.try_borrow_mut_data()?;
        buf[BUF_OFF_MAGIC..BUF_OFF_MAGIC + 8].copy_from_slice(&PROOF_BUFFER_MAGIC);
        buf[BUF_OFF_AUTHORITY..BUF_OFF_AUTHORITY + 32].copy_from_slice(payer.key.as_ref());
        buf[BUF_OFF_EXPECTED_LEN..BUF_OFF_EXPECTED_LEN + 4]
            .copy_from_slice(&(total_len as u32).to_le_bytes());
        buf[BUF_OFF_WRITTEN_MASK..BUF_OFF_WRITTEN_MASK + 2].copy_from_slice(&0u16.to_le_bytes());
        buf[46..48].fill(0);
    } else {
        ensure(buf_acc.owner == program_id, AudrenError::InvalidProofBuffer)?;
        let buf = buf_acc.try_borrow_data()?;
        ensure(
            buf.len() == expected_space
                && buf[BUF_OFF_MAGIC..BUF_OFF_MAGIC + 8] == PROOF_BUFFER_MAGIC
                && buf[BUF_OFF_AUTHORITY..BUF_OFF_AUTHORITY + 32] == *payer.key.as_ref()
                && read_u32(&buf, BUF_OFF_EXPECTED_LEN).map_err(err)? as usize == total_len,
            AudrenError::InvalidProofBuffer,
        )?;
    }

    let mut buf = buf_acc.try_borrow_mut_data()?;
    let payload_off = PROOF_BUFFER_HEADER_LEN + start;
    buf[payload_off..payload_off + expected_chunk_len].copy_from_slice(chunk);
    let mask = read_u16(&buf, BUF_OFF_WRITTEN_MASK).map_err(err)? | (1u16 << chunk_index);
    buf[BUF_OFF_WRITTEN_MASK..BUF_OFF_WRITTEN_MASK + 2].copy_from_slice(&mask.to_le_bytes());
    Ok(())
}

// ============================================================================
// Tag 9: ExecBuffered (zero-copy execute from ProofBuffer + atomic 100% rent refund)
// Data: inner_tag (1 B: TAG_TRANSFER | TAG_MERGE | TAG_SWAP_VIA_ROUTER | TAG_WITHDRAW)
// Accounts: [0] proof_buffer (wr), [1..] exact inner instruction accounts ([1] = payer/authority)
// ============================================================================
fn ix_exec_buffered(
    program_id: &Address,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    ensure(data.len() == 1, AudrenError::InvalidInstruction)?;
    ensure(accounts.len() >= 2, AudrenError::InvalidAccount)?;
    let inner_tag = data[0];
    ensure(
        matches!(
            inner_tag,
            TAG_TRANSFER | TAG_MERGE | TAG_SWAP_VIA_ROUTER | TAG_WITHDRAW
        ),
        AudrenError::InvalidInstruction,
    )?;

    let buf_acc = &accounts[0];
    let inner_accounts = &accounts[1..];
    let payer = &inner_accounts[0];
    ensure(payer.is_signer && payer.is_writable, AudrenError::Unauthorized)?;
    ensure(
        buf_acc.owner == program_id && buf_acc.is_writable,
        AudrenError::InvalidProofBuffer,
    )?;
    // Guarantee `proof_buffer` never aliases any account inside `inner_accounts`
    // (prevents RefCell double-borrow across CPIs and router account smuggling).
    for acc in inner_accounts {
        ensure(acc.key != buf_acc.key, AudrenError::InvalidProofBuffer)?;
    }

    {
        let buf = buf_acc.try_borrow_data()?;
        ensure(
            buf.len() > PROOF_BUFFER_HEADER_LEN
                && buf[BUF_OFF_MAGIC..BUF_OFF_MAGIC + 8] == PROOF_BUFFER_MAGIC
                && buf[BUF_OFF_AUTHORITY..BUF_OFF_AUTHORITY + 32] == *payer.key.as_ref(),
            AudrenError::InvalidProofBuffer,
        )?;
        let expected_len = read_u32(&buf, BUF_OFF_EXPECTED_LEN).map_err(err)? as usize;
        ensure(
            expected_len > 0
                && expected_len <= PROOF_BUFFER_MAX_PAYLOAD
                && buf.len() == PROOF_BUFFER_HEADER_LEN + expected_len,
            AudrenError::InvalidProofBuffer,
        )?;
        let num_chunks = expected_len.div_ceil(PROOF_BUFFER_CHUNK_SIZE);
        let full_mask = (1u16 << num_chunks) - 1;
        let written_mask = read_u16(&buf, BUF_OFF_WRITTEN_MASK).map_err(err)?;
        ensure(written_mask == full_mask, AudrenError::InvalidProofBuffer)?;

        let payload = &buf[PROOF_BUFFER_HEADER_LEN..PROOF_BUFFER_HEADER_LEN + expected_len];
        match inner_tag {
            TAG_TRANSFER => ix_transfer(program_id, inner_accounts, payload)?,
            TAG_MERGE => ix_merge(program_id, inner_accounts, payload)?,
            TAG_SWAP_VIA_ROUTER => ix_swap_via_router(program_id, inner_accounts, payload)?,
            TAG_WITHDRAW => ix_withdraw(program_id, inner_accounts, payload)?,
            _ => return Err(err(AudrenError::InvalidInstruction)),
        }
    }

    close_proof_buffer_account(buf_acc, payer)?;
    Ok(())
}

// ============================================================================
// Tag 10: CloseProofBuffer (reclaim 100% rent from an abandoned ProofBuffer)
// Data: empty
// Accounts: [0] payer/authority (signer, wr), [1] proof_buffer (wr)
// ============================================================================
fn ix_close_proof_buffer(
    program_id: &Address,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    ensure(data.is_empty(), AudrenError::InvalidInstruction)?;
    ensure(accounts.len() >= 2, AudrenError::InvalidAccount)?;
    let payer = &accounts[0];
    let buf_acc = &accounts[1];
    ensure(payer.is_signer && payer.is_writable, AudrenError::Unauthorized)?;
    ensure(
        buf_acc.owner == program_id && buf_acc.is_writable && buf_acc.key != payer.key,
        AudrenError::InvalidProofBuffer,
    )?;
    {
        let buf = buf_acc.try_borrow_data()?;
        ensure(
            buf.len() >= PROOF_BUFFER_HEADER_LEN
                && buf[BUF_OFF_MAGIC..BUF_OFF_MAGIC + 8] == PROOF_BUFFER_MAGIC
                && buf[BUF_OFF_AUTHORITY..BUF_OFF_AUTHORITY + 32] == *payer.key.as_ref(),
            AudrenError::InvalidProofBuffer,
        )?;
    }
    close_proof_buffer_account(buf_acc, payer)?;
    Ok(())
}
