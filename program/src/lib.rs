//! Audren — Private Multi-Asset Settlement & Shielded DeFi Execution Program on Solana (Pinocchio + sBPFv3).
//!
//! Native SOL, Classic SPL tokens, and transferable Token-2022 mints (including
//! `PermanentDelegate`, net-delta `TransferFee`, and `TransferHook`) share one unified shielded
//! `EpochPage` pool (`32` notes / `6,240 B` per page):
//! - Private multi-asset transfers hiding sender, recipient, token mint, and amount
//! - Single-transaction protocol-agnostic shielded DeFi execution (`ExecViaEscrow`, Tag 5) through
//!   16 isolated `escrow` shards into any compatible PDA-signing Solana program (DEX swaps, supply
//!   lending, yield vaults, liquid staking, perp LP, RWA mint/redeem) with native `ctx_hash`-bound
//!   relayer fees on either the input or output mint
//! - Self-paying withdrawals (`Withdraw`, Tag 6) with optional atomic WSOL unwrap into Native SOL
//!   via 1-shot nullifier-seeded PDA (`audren_unwrap`), plus zero-dust Native SOL sweep deposits
//! - Opt-in institutional auditability (`PoolMode::InstitutionalAudited`), enforcing verifiable
//!   ElGamal encryption of spent stealth pubkeys and hidden mints under `K_aud` on-chain
//! - Pure Ristretto255 Multi-Base Binary Triptych (`32 / 64 / 128`-note rings) verified via
//!   Agave's native `sol_curve_multiscalar_mul` syscall and native Agave Bulletproofs
//! - Structure-of-Arrays `EpochPage` accounts (`6,240 B < 10 KiB` CPI cap, `SIMD-0460` zero
//!   realloc) readable directly via standard Solana RPC `getMultipleAccounts` and
//!   `programSubscribe` `dataSlice[64..1120]`
//! - Live `SysvarRent` self-balancing page-rent vault (`SIMD-0194`, `SIMD-0437` / `SIMD-0438` compatible)
//! - Zero-`std`, Pinocchio `0.11.1` zero-copy entrypoint and CPIs with `lto = "fat"`

#![no_std]
#![allow(unexpected_cfgs)]

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
extern crate std;

mod crypto;
mod scalar;
mod state;

use audren_core::{
    instruction::{
        input_pages_for_m, triptych_proof_len, AUDITOR_ASSET_PROOF_LEN, CROSS_BASE_1_LEN,
        CROSS_BASE_2_LEN, DEPOSIT_FLAG_FEE_FROM_AMOUNT, DEPOSIT_FLAG_NATIVE_SOL,
        DYNAMIC_OUTPUT_WIRE_LEN, EXEC_FLAG_ALLOW_PARTIAL_REFUND, EXEC_FLAG_FEE_ON_OUTPUT,
        EXEC_FLAG_HAS_CHANGE, MAX_MERGE_RING_SLOTS, NOTE_WIRE_LEN, RANGE_U128_PROOF_LEN,
        RANGE_U64_PROOF_LEN, TAG_CLOSE_PROOF_BUFFER, TAG_DEPOSIT, TAG_EXEC_BUFFERED,
        TAG_EXEC_VIA_ESCROW, TAG_INIT_LANE, TAG_INIT_POOL, TAG_MERGE, TAG_OPEN_LANE_PAGE,
        TAG_OPEN_PAGE, TAG_SET_PAUSED, TAG_TRANSFER, TAG_WITHDRAW, TAG_WRITE_PROOF_BUFFER,
        WITHDRAW_FLAG_HAS_CHANGE, WITHDRAW_FLAG_NATIVE_SOL, WITHDRAW_FLAG_UNWRAP_WSOL,
    },
    lane_of_page_id,
    layout::{
        read_32, read_u16, read_u32, read_u64, AppendLaneState, NoteEntry, PageHeader, PoolState,
        BUF_OFF_AUTHORITY, BUF_OFF_EXPECTED_LEN, BUF_OFF_MAGIC, BUF_OFF_WRITTEN_MASK,
        LANE_STATE_LEN, MAX_CPI_ACCOUNT_ALLOC, NOTE_CT_LEN, PAGE_CAPACITY, PAGE_LEN,
        PAGE_RENT_MAGIC, PAGE_ROLLOVER_HEADROOM, POOL_STATE_LEN, PROOF_BUFFER_CHUNK_SIZE,
        PROOF_BUFFER_HEADER_LEN, PROOF_BUFFER_MAGIC, PROOF_BUFFER_MAX_PAYLOAD,
        SENTINEL_ACCOUNT_LEN, SOL_VAULT_MAGIC,
    },
    page_id_for_lane, seq_of_page_id, AudrenError, PoolMode, CLASSIC_TOKEN_PROGRAM_ID,
    ESCROW_SEED, LANE_RENT_SEED, LANE_SEED, MAX_APPEND_LANES, NATIVE_SOL_MINT, NULLIFIER_SEED,
    PAGE_RENT_SEED, PAGE_SEED, POOL_SEED, PROOF_BUFFER_SEED, PROTOCOL_VERSION, SOL_VAULT_SEED,
    SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, UNWRAP_SEED, VAULT_AUTH_SEED, WSOL_MINT,
};
use core::mem::MaybeUninit;
use crypto::{
    address_bytes, asset_generator, is_zero_point, pt_add, pt_mul_u64, transcript_root,
    validate_nonzero_point, validate_point, verify_auditor_asset_proof, verify_cross_base_1,
    verify_cross_base_2, verify_native_range_u128, verify_native_range_u64, verify_triptych,
    verify_triptych_with_scratch, TriptychScratch, IDENTITY,
};
use pinocchio::{
    account::Ref,
    cpi::{invoke_signed, invoke_signed_unchecked, CpiAccount, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    sysvars::{clock::Clock, get_sysvar, rent::RENT_ID, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};
use state::{
    append_note_to_page, check_lane_rent_vault, check_page_rent_vault, check_sol_vault,
    check_supported_token_program, ensure, err, escrow_pda, expected_ata, init_sentinel_bytes,
    lane_pda, lane_rent_pda, load_lane, load_page_header, load_pool, nullifier_pda, page_pda,
    page_rent_pda, pool_pda, proof_buffer_pda, save_lane, save_pool, sol_vault_from_pool,
    sol_vault_pda, unwrap_pda, vault_auth_from_pool, vault_auth_pda,
};

// Pinocchio zero-copy entrypoint bounded at 128 accounts (covers `SIMD-0596` TxV1 + headroom
// while keeping the entrypoint stack frame compact).
#[cfg(not(feature = "no-entrypoint"))]
pinocchio::program_entrypoint!(process, 128);
#[cfg(not(feature = "no-entrypoint"))]
pinocchio::no_allocator!();
#[cfg(not(feature = "no-entrypoint"))]
pinocchio::nostd_panic_handler!();

/// Embedded Neodyme `security.txt` V1 section (zero runtime CU, complements canonical
/// Solana Program Metadata `security` account).
#[cfg(not(feature = "no-entrypoint"))]
#[cfg_attr(any(target_os = "solana", target_arch = "bpf"), link_section = ".security.txt")]
#[allow(dead_code)]
#[used]
#[no_mangle]
pub static SECURITY_TXT: &str = concat!(
    "=======BEGIN SECURITY.TXT V1=======\0",
    "name\0Audren\0",
    "project_url\0https://audren.xyz\0",
    "contacts\0email:security@audren.xyz\0",
    "policy\0https://github.com/audren-xyz/audren/blob/main/SECURITY.md\0",
    "preferred_languages\0en\0",
    "source_code\0https://github.com/audren-xyz/audren\0",
    "source_release\0v", env!("CARGO_PKG_VERSION"), "\0",
    "=======END SECURITY.TXT V1=======\0"
);

/// Maximum accounts forwarded to an external DEX router inside a single transaction
/// (`80` provides full headroom for Agave 4.5 `SIMD-0596` TxV1 96-account lock limit: `96 - 16 = 80`).
const MAX_ROUTER_CPI_ACCOUNTS: usize = 80;

/// Maximum accounts in a `TransferChecked` CPI when a Token-2022 `TransferHook` is active.
const MAX_HOOK_CPI_ACCOUNTS: usize = 64;

/// System Program ID (`11111111111111111111111111111111`).
const SYSTEM_ID: Address = Address::new_from_array(SYSTEM_PROGRAM_ID);

/// Zero-formatting static log emitter (~100 CU, zero `core::fmt` ELF bloat).
#[inline(always)]
fn log_tag(tag: &str) {
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    unsafe {
        pinocchio::syscalls::sol_log_(tag.as_ptr(), tag.len() as u64);
    }
    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    let _ = tag;
}

/// Exact live `SysvarRent` minimum balance calculation supporting both `exemption_threshold == 1.0`
/// (SIMD-0194) and `exemption_threshold == 2.0` clusters with zero floating-point instructions.
#[inline]
fn rent_minimum_balance(data_len: usize) -> Result<u64, ProgramError> {
    const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;
    const THRESHOLD_1_0: [u8; 8] = [0, 0, 0, 0, 0, 0, 240, 63]; // 1.0f64 LE
    const THRESHOLD_2_0: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 64]; // 2.0f64 LE

    let mut raw = [0u8; 17];
    get_sysvar(&mut raw, &RENT_ID, 0)?;
    let lamports_per_byte = u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]);
    let threshold: [u8; 8] = [
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
    ];
    let total_bytes = ACCOUNT_STORAGE_OVERHEAD
        .checked_add(data_len as u64)
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    let base = total_bytes
        .checked_mul(lamports_per_byte)
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;

    if threshold == THRESHOLD_1_0 {
        Ok(base)
    } else if threshold == THRESHOLD_2_0 {
        base.checked_mul(2)
            .ok_or_else(|| err(AudrenError::ArithmeticOverflow))
    } else {
        Err(ProgramError::UnsupportedSysvar)
    }
}

/// Create a PDA with a single-CPI `CreateAccount` fast-path when `target.lamports() == 0`
/// (saving 2 CPI invocations on 99.99% of calls), falling back to `Transfer` + `Allocate` + `Assign`
/// whenever lamports were pre-funded (preserving 100% DoS immunity against lamport griefing).
fn create_pda(
    payer: &AccountView,
    target: &AccountView,
    system_program: &AccountView,
    signer_seeds: &[Seed],
    space: usize,
    owner: &Address,
) -> ProgramResult {
    ensure(
        space <= MAX_CPI_ACCOUNT_ALLOC
            && payer.is_writable()
            && target.is_writable()
            && system_program.address() == &SYSTEM_ID
            && target.owned_by(&SYSTEM_ID)
            && target.is_data_empty(),
        AudrenError::InvalidAccount,
    )?;
    let required = rent_minimum_balance(space)?;
    let signer = [Signer::from(signer_seeds)];
    if target.lamports() == 0 {
        CreateAccount {
            from: payer,
            to: target,
            lamports: required,
            space: space as u64,
            owner,
        }
        .invoke_signed(&signer)
    } else {
        let deficit = required.saturating_sub(target.lamports());
        if deficit > 0 {
            Transfer {
                from: payer,
                to: target,
                lamports: deficit,
            }
            .invoke()?;
        }
        Allocate {
            account: target,
            space: space as u64,
        }
        .invoke_signed(&signer)?;
        Assign {
            account: target,
            owner,
        }
        .invoke_signed(&signer)
    }
}

/// Create a 0-byte `NullifierPDA` owned by `program_id`, preventing double-spends forever
/// while remaining immune to lamport pre-funding DoS attacks.
fn claim_nullifier(
    payer: &AccountView,
    nullifier_acc: &AccountView,
    system_program: &AccountView,
    program_id: &Address,
    pool_id: u32,
    nullifier: &[u8; 32],
) -> ProgramResult {
    let (expected, bump) = nullifier_pda(program_id, pool_id, nullifier);
    ensure(nullifier_acc.address() == &expected, AudrenError::InvalidPda)?;
    if nullifier_acc.owned_by(program_id) {
        return Err(err(AudrenError::NullifierAlreadySpent));
    }
    let pool_le = pool_id.to_le_bytes();
    let bump_slice = [bump];
    let seeds = [
        Seed::from(NULLIFIER_SEED),
        Seed::from(&pool_le),
        Seed::from(nullifier),
        Seed::from(&bump_slice),
    ];
    create_pda(payer, nullifier_acc, system_program, &seeds, 0, program_id)
}

// ============================================================================
// Zero-Copy Classic SPL Token & Token-2022 Helpers (replaces spl-token-2022-interface)
// ============================================================================

const SPL_MINT_LEN: usize = 82;
const SPL_ACCOUNT_LEN: usize = 165;
const SPL_MULTISIG_LEN: usize = 355;
const TOKEN_2022_ACCOUNT_TYPE_MINT: u8 = 1;
const TOKEN_2022_ACCOUNT_TYPE_ACCOUNT: u8 = 2;
const TOKEN_2022_EXT_TRANSFER_HOOK: u16 = 14;
const TOKEN_IX_CLOSE_ACCOUNT: u8 = 9;
const TOKEN_IX_TRANSFER_CHECKED: u8 = 12;
const TOKEN_IX_INITIALIZE_ACCOUNT3: u8 = 18;
const CLASSIC_TOKEN_ID: Address = Address::new_from_array(CLASSIC_TOKEN_PROGRAM_ID);
const WSOL_ID: Address = Address::new_from_array(WSOL_MINT);

#[derive(Clone, Copy)]
struct MintInfo {
    decimals: u8,
    has_active_hook: bool,
}

/// Zero-copy validation of a Classic SPL or Token-2022 mint (decimals + active `TransferHook` TLV).
fn load_mint_info(mint: &AccountView, token_program: &Address) -> Result<MintInfo, ProgramError> {
    ensure(mint.owned_by(token_program), AudrenError::InvalidAccount)?;
    let md = mint.try_borrow()?;
    let len = md.len();
    let valid_len = len == SPL_MINT_LEN
        || (len > SPL_ACCOUNT_LEN
            && len != SPL_MULTISIG_LEN
            && md[SPL_ACCOUNT_LEN] == TOKEN_2022_ACCOUNT_TYPE_MINT);
    if !valid_len || md[45] != 1 {
        return Err(ProgramError::InvalidAccountData);
    }
    let decimals = md[44];
    let mut has_active_hook = false;

    if len > SPL_ACCOUNT_LEN + 1 {
        let tlv = &md[SPL_ACCOUNT_LEN + 1..];
        let mut pos = 0usize;
        while pos + 4 <= tlv.len() {
            let ext_type = u16::from_le_bytes([tlv[pos], tlv[pos + 1]]);
            if ext_type == 0 {
                break;
            }
            let ext_len = u16::from_le_bytes([tlv[pos + 2], tlv[pos + 3]]) as usize;
            let val_start = pos + 4;
            let val_end = val_start.saturating_add(ext_len);
            if val_end > tlv.len() {
                return Err(ProgramError::InvalidAccountData);
            }
            if ext_type == TOKEN_2022_EXT_TRANSFER_HOOK && ext_len >= 64 {
                // TransferHook { authority: [u8; 32], program_id: [u8; 32] }
                has_active_hook = tlv[val_start + 32..val_start + 64] != [0u8; 32];
                break;
            }
            pos = val_end;
        }
    }
    Ok(MintInfo {
        decimals,
        has_active_hook,
    })
}

/// Zero-copy read of Classic SPL / Token-2022 token account balance at fixed offset `64..72`.
#[inline]
fn token_balance(account: &AccountView, token_program: &Address) -> Result<u64, ProgramError> {
    ensure(account.owned_by(token_program), AudrenError::InvalidAccount)?;
    let data = account.try_borrow()?;
    let len = data.len();
    let valid = (len == SPL_ACCOUNT_LEN
        || (len > SPL_ACCOUNT_LEN
            && len != SPL_MULTISIG_LEN
            && data[SPL_ACCOUNT_LEN] == TOKEN_2022_ACCOUNT_TYPE_ACCOUNT))
        && data[108] != 0;
    if !valid {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(u64::from_le_bytes([
        data[64], data[65], data[66], data[67], data[68], data[69], data[70], data[71],
    ]))
}

struct TokenSecuritySnapshot {
    token_program: Address,
    owner: Address,
    has_delegate: bool,
    close_authority: Option<Address>,
}

/// Zero-copy security snapshot of a Classic SPL or Token-2022 token account (`owner`, `delegate`,
/// `close_authority`) without unpacking full TLV extensions.
fn token_account_security(account: &AccountView) -> Option<TokenSecuritySnapshot> {
    let owner_prog = account.owner().as_ref();
    if owner_prog != &CLASSIC_TOKEN_PROGRAM_ID && owner_prog != &TOKEN_2022_PROGRAM_ID {
        return None;
    }
    let data = account.try_borrow().ok()?;
    let len = data.len();
    let valid = (len == SPL_ACCOUNT_LEN
        || (len > SPL_ACCOUNT_LEN
            && len != SPL_MULTISIG_LEN
            && data[SPL_ACCOUNT_LEN] == TOKEN_2022_ACCOUNT_TYPE_ACCOUNT))
        && data[108] != 0;
    if !valid {
        return None;
    }
    let owner_bytes: [u8; 32] = data[32..64].try_into().ok()?;
    let has_delegate = match &data[72..76] {
        [0, 0, 0, 0] => false,
        [1, 0, 0, 0] => true,
        _ => return None,
    };
    let close_authority = match &data[129..133] {
        [0, 0, 0, 0] => None,
        [1, 0, 0, 0] => {
            let ca_bytes: [u8; 32] = data[133..165].try_into().ok()?;
            Some(Address::new_from_array(ca_bytes))
        }
        _ => return None,
    };
    Some(TokenSecuritySnapshot {
        token_program: *account.owner(),
        owner: Address::new_from_array(owner_bytes),
        has_delegate,
        close_authority,
    })
}

/// Out-of-line helper for Token-2022 `TransferHook` CPIs so the stack array never bloats callers.
/// Zero-alloc CPI launcher backed by the disjoint `[24 KiB .. 32 KiB)` SBF heap arena
/// (`<= 3,200 B` for `MAX_ROUTER_CPI_ACCOUNTS = 80`), avoiding dynamic allocation while
/// keeping SBF stack frames strictly below `4,096 B`.
#[inline(never)]
fn invoke_signed_arena<'account, A: AsRef<AccountView>>(
    instruction: &InstructionView,
    account_views: &'account [A],
    signers: &[Signer],
) -> ProgramResult {
    let n = instruction.accounts.len();
    ensure(n <= MAX_ROUTER_CPI_ACCOUNTS, AudrenError::InvalidAccount)?;
    if account_views.len() < n {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let run =
        |cpi_buf: &mut [MaybeUninit<CpiAccount<'account>>; MAX_ROUTER_CPI_ACCOUNTS]| -> ProgramResult {
        for i in 0..n {
            let av = account_views[i].as_ref();
            let ia = &instruction.accounts[i];
            if av.address() != ia.address {
                return Err(ProgramError::InvalidArgument);
            }
            if ia.is_writable {
                av.check_borrow_mut()?;
            }
            CpiAccount::init_from_account_view(av, &mut cpi_buf[i]);
        }
        // SAFETY: First `n` `CpiAccount` entries are initialized and borrow-checked above.
        unsafe {
            let slice = core::slice::from_raw_parts(cpi_buf.as_ptr() as *const CpiAccount<'account>, n);
            invoke_signed_unchecked(instruction, slice, signers);
        }
        Ok(())
    };
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        const HEAP_CPI_OFFSET: usize = 24 * 1024;
        const _: () = assert!(
            core::mem::size_of::<[MaybeUninit<CpiAccount<'static>>; MAX_ROUTER_CPI_ACCOUNTS]>()
                <= 8 * 1024
        );
        const _: () = assert!(HEAP_CPI_OFFSET % core::mem::align_of::<CpiAccount<'static>>() == 0);
        // SAFETY: `[24 KiB .. 32 KiB)` of Solana's 32 KiB heap is disjoint from
        // `TriptychScratch` `[0 .. 16 KiB)` and `WatchedEscrowBuf` `[16 .. 24 KiB)`,
        // and Audren rejects self-CPI (`key == program_id`).
        let buf = unsafe {
            &mut *((pinocchio::entrypoint::HEAP_START_ADDRESS as usize + HEAP_CPI_OFFSET)
                as *mut [MaybeUninit<CpiAccount<'account>>; MAX_ROUTER_CPI_ACCOUNTS])
        };
        run(buf)
    }
    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        let mut buf =
            [const { MaybeUninit::<CpiAccount<'account>>::uninit() }; MAX_ROUTER_CPI_ACCOUNTS];
        run(&mut buf)
    }
}

#[derive(Clone, Copy)]
struct WatchedEscrowSnap {
    idx: u8,
    has_close_auth: bool,
    token_program: Address,
    close_authority: Address,
}

/// Static `[16 KiB .. 24 KiB)` SBF heap arena storing pre-CPI `swap_escrow` token account
/// snapshots (`80 * 66 B = 5,280 B`) with zero dynamic allocation and zero stack bloat.
struct WatchedEscrowBuf {
    len: usize,
    entries: [WatchedEscrowSnap; MAX_ROUTER_CPI_ACCOUNTS],
}

impl WatchedEscrowBuf {
    #[inline(never)]
    fn with_buf<R>(f: impl FnOnce(&mut Self) -> R) -> R {
        #[cfg(any(target_os = "solana", target_arch = "bpf"))]
        {
            const HEAP_WATCH_OFFSET: usize = 16 * 1024;
            const _: () = assert!(core::mem::size_of::<WatchedEscrowBuf>() <= 8 * 1024);
            const _: () = assert!(HEAP_WATCH_OFFSET % core::mem::align_of::<WatchedEscrowBuf>() == 0);
            // SAFETY: `[16 KiB .. 24 KiB)` of Solana's 32 KiB heap is disjoint from
            // `TriptychScratch` `[0 .. 16 KiB)` and `CpiAccount` `[24 .. 32 KiB)`, and
            // `WatchedEscrowBuf` contains only all-zero-valid POD types.
            let ptr = (pinocchio::entrypoint::HEAP_START_ADDRESS as usize + HEAP_WATCH_OFFSET)
                as *mut Self;
            unsafe {
                (*ptr).len = 0;
                f(&mut *ptr)
            }
        }
        #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
        {
            let mut raw = std::boxed::Box::<Self>::new_uninit();
            // SAFETY: All fields of `WatchedEscrowBuf` have valid all-zero bit representations.
            let mut buf = unsafe {
                core::ptr::write_bytes(raw.as_mut_ptr(), 0, 1);
                raw.assume_init()
            };
            f(&mut buf)
        }
    }

    #[inline(always)]
    fn push(&mut self, idx: usize, token_program: Address, close_authority: Option<Address>) {
        if self.len < MAX_ROUTER_CPI_ACCOUNTS {
            self.entries[self.len] = WatchedEscrowSnap {
                idx: idx as u8,
                has_close_auth: close_authority.is_some(),
                token_program,
                close_authority: close_authority.unwrap_or_else(|| Address::new_from_array([0u8; 32])),
            };
            self.len += 1;
        }
    }

    #[inline(always)]
    fn as_slice(&self) -> &[WatchedEscrowSnap] {
        &self.entries[..self.len]
    }
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn invoke_token_transfer_checked_with_hook(
    program_id: &Address,
    vault_auth_key: &Address,
    token_prog: &AccountView,
    source: &AccountView,
    mint: &AccountView,
    dest: &AccountView,
    authority: &AccountView,
    ix_data: &[u8; 10],
    hook_candidates: &[AccountView],
    blocked_keys: &[&Address],
    signers: &[Signer],
) -> ProgramResult {
    let mut metas = [const { MaybeUninit::<InstructionAccount>::uninit() }; MAX_HOOK_CPI_ACCOUNTS];
    let mut views = [const { MaybeUninit::<&AccountView>::uninit() }; MAX_HOOK_CPI_ACCOUNTS];

    metas[0].write(InstructionAccount::writable(source.address()));
    metas[1].write(InstructionAccount::readonly(mint.address()));
    metas[2].write(InstructionAccount::writable(dest.address()));
    metas[3].write(InstructionAccount::readonly_signer(authority.address()));
    views[0].write(source);
    views[1].write(mint);
    views[2].write(dest);
    views[3].write(authority);
    let mut n = 4usize;

    for acc in hook_candidates {
        let key = acc.address();
        if key == program_id || acc.owned_by(program_id) {
            continue;
        }
        if key == source.address()
            || key == mint.address()
            || key == dest.address()
            || key == authority.address()
            || key == token_prog.address()
        {
            continue;
        }
        if blocked_keys.iter().any(|k| *k == key) {
            continue;
        }
        if let Some(snap) = token_account_security(acc) {
            if snap.owner == *vault_auth_key {
                continue;
            }
        }
        // SAFETY: `metas[..n]` are initialized.
        let dup = (0..n).any(|i| unsafe { metas[i].assume_init_ref().address } == key);
        if dup {
            continue;
        }
        ensure(n < MAX_HOOK_CPI_ACCOUNTS, AudrenError::InvalidAccount)?;
        metas[n].write(if acc.is_writable() {
            InstructionAccount::writable(key)
        } else {
            InstructionAccount::readonly(key)
        });
        views[n].write(acc);
        n += 1;
    }

    // SAFETY: First `n` entries of `metas` and `views` are initialized.
    let meta_slice = unsafe { core::slice::from_raw_parts(metas.as_ptr() as *const InstructionAccount, n) };
    let view_slice = unsafe { core::slice::from_raw_parts(views.as_ptr() as *const &AccountView, n) };

    let ix = InstructionView {
        program_id: token_prog.address(),
        accounts: meta_slice,
        data: ix_data,
    };
    invoke_signed_arena(&ix, view_slice, signers)
}

/// Invoke Classic SPL or Token-2022 `transfer_checked` via zero-copy Pinocchio CPI.
#[allow(clippy::too_many_arguments)]
fn invoke_token_transfer_checked(
    program_id: &Address,
    vault_auth_key: &Address,
    token_prog: &AccountView,
    source: &AccountView,
    mint: &AccountView,
    dest: &AccountView,
    authority: &AccountView,
    amount: u64,
    mint_info: MintInfo,
    hook_candidates: &[AccountView],
    blocked_keys: &[&Address],
    signers: &[Signer],
) -> ProgramResult {
    let mut ix_data = [0u8; 10];
    ix_data[0] = TOKEN_IX_TRANSFER_CHECKED;
    ix_data[1..9].copy_from_slice(&amount.to_le_bytes());
    ix_data[9] = mint_info.decimals;

    if !mint_info.has_active_hook || hook_candidates.is_empty() {
        let metas = [
            InstructionAccount::writable(source.address()),
            InstructionAccount::readonly(mint.address()),
            InstructionAccount::writable(dest.address()),
            InstructionAccount::readonly_signer(authority.address()),
        ];
        let ix = InstructionView {
            program_id: token_prog.address(),
            accounts: &metas,
            data: &ix_data,
        };
        return invoke_signed(&ix, &[source, mint, dest, authority], signers);
    }

    invoke_token_transfer_checked_with_hook(
        program_id,
        vault_auth_key,
        token_prog,
        source,
        mint,
        dest,
        authority,
        &ix_data,
        hook_candidates,
        blocked_keys,
        signers,
    )
}

/// Out-of-line zero-copy external DeFi target CPI (`data` forwarded by slice reference, zero `.to_vec()`).
#[inline(never)]
fn invoke_target_cpi(
    target_prog: &Address,
    action_accounts: &[AccountView],
    target_data: &[u8],
    expected_escrow: &Address,
    escrow_signer: &[Signer],
) -> ProgramResult {
    let n = action_accounts.len();
    ensure(n <= MAX_ROUTER_CPI_ACCOUNTS, AudrenError::InvalidAccount)?;
    let mut metas = [const { MaybeUninit::<InstructionAccount>::uninit() }; MAX_ROUTER_CPI_ACCOUNTS];
    for (i, acc) in action_accounts.iter().enumerate() {
        let is_signer = acc.address() == expected_escrow;
        metas[i].write(InstructionAccount::new(
            acc.address(),
            acc.is_writable(),
            is_signer,
        ));
    }
    // SAFETY: First `n` entries of `metas` are initialized.
    let meta_slice =
        unsafe { core::slice::from_raw_parts(metas.as_ptr() as *const InstructionAccount, n) };
    let ix = InstructionView {
        program_id: target_prog,
        accounts: meta_slice,
        data: target_data,
    };
    invoke_signed_arena(&ix, action_accounts, escrow_signer)
}

/// Out-of-line atomic WSOL unwrap helper (`Withdraw` with `WITHDRAW_FLAG_UNWRAP_WSOL`):
/// creates a 1-shot nullifier-seeded token account (`["audren_unwrap", pool_id, J]`) owned by
/// `vault_auth`, transfers `total_out` WSOL into it, closes it to `payer` (refunding 100% of
/// temporary token account rent), and distributes exact `amount_out` Native SOL to `recipient`
/// and optional `relayer_fee` Native SOL to `fee_recipient`.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn unwrap_wsol_and_payout(
    program_id: &Address,
    pool_id: u32,
    nullifier: &[u8; 32],
    payer: &AccountView,
    sys_prog: &AccountView,
    vault_auth: &AccountView,
    mint: &AccountView,
    vault_ata: &AccountView,
    recipient: &AccountView,
    fee_recipient: &AccountView,
    token_prog: &AccountView,
    unwrap_acc: &AccountView,
    amount_out: u64,
    relayer_fee: u64,
    va_signer: &[Signer],
) -> ProgramResult {
    let total_out = amount_out
        .checked_add(relayer_fee)
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    let (expected_unwrap, unwrap_bump) = unwrap_pda(program_id, pool_id, nullifier);
    ensure(unwrap_acc.address() == &expected_unwrap, AudrenError::InvalidPda)?;
    ensure(
        unwrap_acc.is_writable() && unwrap_acc.owned_by(&SYSTEM_ID) && unwrap_acc.is_data_empty(),
        AudrenError::InvalidAccount,
    )?;
    ensure(
        recipient.address() != unwrap_acc.address()
            && recipient.address() != vault_auth.address()
            && recipient.address() != vault_ata.address()
            && recipient.address() != program_id
            && !recipient.owned_by(program_id),
        AudrenError::InvalidAccount,
    )?;
    if relayer_fee > 0 {
        ensure(
            fee_recipient.is_writable()
                && fee_recipient.address() != unwrap_acc.address()
                && fee_recipient.address() != vault_auth.address()
                && fee_recipient.address() != vault_ata.address()
                && fee_recipient.address() != program_id
                && !fee_recipient.owned_by(program_id),
            AudrenError::InvalidAccount,
        )?;
    }

    let pool_le = pool_id.to_le_bytes();
    let unwrap_bump_b = [unwrap_bump];
    let unwrap_seeds = [
        Seed::from(UNWRAP_SEED),
        Seed::from(&pool_le),
        Seed::from(nullifier),
        Seed::from(&unwrap_bump_b),
    ];
    create_pda(
        payer,
        unwrap_acc,
        sys_prog,
        &unwrap_seeds,
        SPL_ACCOUNT_LEN,
        token_prog.address(),
    )?;

    // InitializeAccount3 (tag 18 || owner[32]) with owner = vault_auth.
    let mut init_data = [0u8; 33];
    init_data[0] = TOKEN_IX_INITIALIZE_ACCOUNT3;
    init_data[1..33].copy_from_slice(vault_auth.address().as_ref());
    let init_metas = [
        InstructionAccount::writable(unwrap_acc.address()),
        InstructionAccount::readonly(mint.address()),
    ];
    let init_ix = InstructionView {
        program_id: token_prog.address(),
        accounts: &init_metas,
        data: &init_data,
    };
    invoke_signed(&init_ix, &[unwrap_acc, mint], &[])?;

    // TransferChecked `total_out` WSOL from `vault_ata` -> `unwrap_acc`.
    let vault_before = token_balance(vault_ata, token_prog.address())?;
    let mut xfer_data = [0u8; 10];
    xfer_data[0] = TOKEN_IX_TRANSFER_CHECKED;
    xfer_data[1..9].copy_from_slice(&total_out.to_le_bytes());
    xfer_data[9] = 9; // WSOL always has 9 decimals
    let xfer_metas = [
        InstructionAccount::writable(vault_ata.address()),
        InstructionAccount::readonly(mint.address()),
        InstructionAccount::writable(unwrap_acc.address()),
        InstructionAccount::readonly_signer(vault_auth.address()),
    ];
    let xfer_ix = InstructionView {
        program_id: token_prog.address(),
        accounts: &xfer_metas,
        data: &xfer_data,
    };
    invoke_signed(&xfer_ix, &[vault_ata, mint, unwrap_acc, vault_auth], va_signer)?;
    let vault_after = token_balance(vault_ata, token_prog.address())?;
    ensure(
        vault_before.checked_sub(vault_after) == Some(total_out),
        AudrenError::ArithmeticOverflow,
    )?;

    // CloseAccount `unwrap_acc` -> `payer` (destroys ephemeral PDA, refunds 100% rent + total_out SOL).
    let payer_before_close = payer.lamports();
    let close_data = [TOKEN_IX_CLOSE_ACCOUNT];
    let close_metas = [
        InstructionAccount::writable(unwrap_acc.address()),
        InstructionAccount::writable(payer.address()),
        InstructionAccount::readonly_signer(vault_auth.address()),
    ];
    let close_ix = InstructionView {
        program_id: token_prog.address(),
        accounts: &close_metas,
        data: &close_data,
    };
    invoke_signed(&close_ix, &[unwrap_acc, payer, vault_auth], va_signer)?;
    let unwrapped_received = payer
        .lamports()
        .checked_sub(payer_before_close)
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    ensure(
        unwrap_acc.lamports() == 0 && unwrapped_received >= total_out,
        AudrenError::ArithmeticOverflow,
    )?;

    // Distribute exact `amount_out` to `recipient` and optional `relayer_fee` to `fee_recipient`.
    if recipient.address() != payer.address() {
        Transfer {
            from: payer,
            to: recipient,
            lamports: amount_out,
        }
        .invoke()?;
    }
    if relayer_fee > 0 && fee_recipient.address() != payer.address() {
        Transfer {
            from: payer,
            to: fee_recipient,
            lamports: relayer_fee,
        }
        .invoke()?;
    }
    Ok(())
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
    validate_nonzero_point(&ephemeral_pk)?;
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
/// Immune to `SIMD-0437` incremental rent reductions and any `SIMD-0438` rollback:
/// 1. Reads the live cluster `SysvarRent` instead of static constants.
/// 2. Caps each note's fee at `min(pool.page_rent_fee_lamports, ceil(page_rent / PAGE_CAPACITY))`.
/// 3. Automatically skips collection once `PageRentVault` holds a 2-page rollover buffer.
fn collect_page_rent_fee(
    payer: &AccountView,
    page_rent_vault: &AccountView,
    _system_program: &AccountView,
    pool: &PoolState,
    num_notes: u64,
) -> Result<u64, ProgramError> {
    if pool.page_rent_fee_lamports == 0 || num_notes == 0 {
        return Ok(0);
    }
    let page_rent = rent_minimum_balance(PAGE_LEN)?;
    let min_vault = rent_minimum_balance(SENTINEL_ACCOUNT_LEN)?;
    let target_vault_balance = min_vault
        .checked_add(page_rent.saturating_mul(2))
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    let deficit_to_target = target_vault_balance.saturating_sub(page_rent_vault.lamports());
    if deficit_to_target == 0 {
        return Ok(0);
    }
    let live_per_note = page_rent.div_ceil(PAGE_CAPACITY as u64);
    let effective_per_note = pool.page_rent_fee_lamports.min(live_per_note);
    let total = effective_per_note
        .checked_mul(num_notes)
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?
        .min(deficit_to_target);
    if total > 0 {
        Transfer {
            from: payer,
            to: page_rent_vault,
            lamports: total,
        }
        .invoke()?;
    }
    Ok(total)
}

/// Zero-allocation stack container for `1`, `2`, or `4` strictly ordered input `EpochPage` borrows.
struct InputPages<'a> {
    len: usize,
    headers: [PageHeader; 4],
    borrows: [Option<Ref<'a, [u8]>>; 4],
}

impl<'a> InputPages<'a> {
    fn load(
        accounts: &'a [AccountView],
        program_id: &Address,
        pool_id: u32,
        m: u8,
    ) -> Result<Self, ProgramError> {
        let needed = input_pages_for_m(m).map_err(err)?;
        ensure(accounts.len() >= needed, AudrenError::InvalidAccount)?;
        let empty_hdr = PageHeader {
            version: 0,
            bump: 0,
            closed: false,
            count: 0,
            pool_id: 0,
            page_id: 0,
            created_slot: 0,
            closed_slot: 0,
        };
        let mut headers = [empty_hdr; 4];
        let mut borrows: [Option<Ref<'a, [u8]>>; 4] = [None, None, None, None];
        for i in 0..needed {
            let acc = &accounts[i];
            let h = load_page_header(acc, program_id, pool_id)?;
            ensure(h.count > 0, AudrenError::PageEmpty)?;
            if i > 0 {
                ensure(
                    headers[i - 1].page_id < h.page_id,
                    AudrenError::DuplicateOrUnorderedPages,
                )?;
            }
            headers[i] = h;
            borrows[i] = Some(acc.try_borrow()?);
        }
        Ok(Self {
            len: needed,
            headers,
            borrows,
        })
    }

    #[inline]
    fn as_slices(&self) -> [&[u8]; 4] {
        let mut out: [&[u8]; 4] = [&[]; 4];
        for i in 0..self.len {
            out[i] = self.borrows[i].as_deref().unwrap_or(&[]);
        }
        out
    }
}

/// Validate the output `EpochPage` and matching rent vault for Lane 0 or parallel
/// append lanes `1..15` (where `pool_acc` remains read-only for zero write contention).
fn resolve_output_target(
    pool_acc: &AccountView,
    out_page_acc: &AccountView,
    rent_vault_acc: &AccountView,
    program_id: &Address,
    pool: &PoolState,
) -> Result<(u8, u64), ProgramError> {
    let hdr = load_page_header(out_page_acc, program_id, pool.pool_id)?;
    let out_lane = lane_of_page_id(hdr.page_id);
    ensure(
        out_lane < pool.effective_lane_count(),
        AudrenError::InvalidLane,
    )?;
    if out_lane == 0 {
        ensure(pool_acc.is_writable(), AudrenError::InvalidAccount)?;
        ensure(hdr.page_id == pool.current_page_id, AudrenError::WrongPool)?;
        check_page_rent_vault(rent_vault_acc, program_id, pool)?;
    } else {
        ensure(!hdr.closed, AudrenError::PageFull)?;
        check_lane_rent_vault(rent_vault_acc, program_id, pool.pool_id, out_lane)?;
    }
    Ok((out_lane, hdr.page_id))
}

/// Append a note to `out_page` (Lane 0 or parallel Lane `1..15`) and bump `pool.total_notes` on Lane 0.
fn write_output_note(
    out_page: AccountView,
    program_id: &Address,
    pool: &mut PoolState,
    out_lane: u8,
    note: &NoteEntry,
    slot: u64,
) -> Result<(u64, u8), ProgramError> {
    let expected = if out_lane == 0 {
        Some(pool.current_page_id)
    } else {
        None
    };
    let (page_id, idx) =
        append_note_to_page(out_page, program_id, pool.pool_id, expected, note, slot)?;
    if out_lane == 0 {
        pool.total_notes = pool
            .total_notes
            .checked_add(1)
            .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    }
    Ok((page_id, idx))
}

/// Persist `PoolState` counters only when writing to Lane 0 (or when caller explicitly passed
/// `pool_acc` writable on a full withdrawal). Parallel Lanes `1..15` keep `PoolState` read-only!
fn finalize_pool_spend(
    pool_acc: AccountView,
    program_id: &Address,
    pool: &mut PoolState,
    out_lane: u8,
    spend_delta: u64,
) -> ProgramResult {
    if out_lane == 0 && pool_acc.is_writable() {
        if spend_delta > 0 {
            pool.total_spends = pool
                .total_spends
                .checked_add(spend_delta)
                .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
        }
        save_pool(pool_acc, program_id, pool)?;
    }
    Ok(())
}

pub fn process(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let (&tag, rest) = data
        .split_first()
        .ok_or_else(|| err(AudrenError::InvalidInstruction))?;
    match tag {
        TAG_INIT_POOL => ix_init_pool(program_id, accounts, rest),
        TAG_OPEN_PAGE => ix_open_page(program_id, accounts, rest),
        TAG_DEPOSIT => ix_deposit(program_id, accounts, rest),
        TAG_TRANSFER => ix_transfer(program_id, accounts, rest),
        TAG_MERGE => ix_merge(program_id, accounts, rest),
        TAG_EXEC_VIA_ESCROW => ix_exec_via_escrow(program_id, accounts, rest),
        TAG_WITHDRAW => ix_withdraw(program_id, accounts, rest),
        TAG_SET_PAUSED => ix_set_paused(program_id, accounts, rest),
        TAG_WRITE_PROOF_BUFFER => ix_write_proof_buffer(program_id, accounts, rest),
        TAG_EXEC_BUFFERED => ix_exec_buffered(program_id, accounts, rest),
        TAG_CLOSE_PROOF_BUFFER => ix_close_proof_buffer(program_id, accounts, rest),
        TAG_INIT_LANE => ix_init_lane(program_id, accounts, rest),
        TAG_OPEN_LANE_PAGE => ix_open_lane_page(program_id, accounts, rest),
        _ => Err(err(AudrenError::InvalidInstruction)),
    }
}

// ============================================================================
// Tag 0: InitPool
// Data: pool_id (4) | mode (1) | auditor_locked (1) | page_rent_fee (8) | auditor_pk (32) = 46 B
// Accounts: [0] payer/authority (signer, wr), [1] pool (wr), [2] page_0 (wr),
//           [3] sol_vault (wr), [4] page_rent_vault (wr), [5] system_program
// ============================================================================
fn ix_init_pool(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    ensure(data.len() == 46, AudrenError::InvalidInstruction)?;
    ensure(accounts.len() >= 6, AudrenError::InvalidAccount)?;
    let payer = &accounts[0];
    let pool_acc = &accounts[1];
    let mut page0_acc = accounts[2];
    let sol_vault_acc = &accounts[3];
    let rent_vault_acc = &accounts[4];
    let sys_prog = &accounts[5];
    ensure(payer.is_signer(), AudrenError::Unauthorized)?;
    ensure(
        payer.is_writable()
            && pool_acc.is_writable()
            && page0_acc.is_writable()
            && sol_vault_acc.is_writable()
            && rent_vault_acc.is_writable(),
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
    ensure(pool_acc.address() == &p_addr, AudrenError::InvalidPda)?;
    let (pg_addr, pg_bump) = page_pda(program_id, pool_id, 0);
    ensure(page0_acc.address() == &pg_addr, AudrenError::InvalidPda)?;
    let (_, vault_auth_bump) = vault_auth_pda(program_id, pool_id);
    let (sv_addr, sv_bump) = sol_vault_pda(program_id, pool_id);
    ensure(sol_vault_acc.address() == &sv_addr, AudrenError::InvalidPda)?;
    let (rv_addr, rv_bump) = page_rent_pda(program_id, pool_id);
    ensure(rent_vault_acc.address() == &rv_addr, AudrenError::InvalidPda)?;

    let p_bump_b = [p_bump];
    let pg_bump_b = [pg_bump];
    let sv_bump_b = [sv_bump];
    let rv_bump_b = [rv_bump];
    let zero_le = 0u64.to_le_bytes();

    create_pda(
        payer,
        pool_acc,
        sys_prog,
        &[Seed::from(POOL_SEED), Seed::from(&pool_le), Seed::from(&p_bump_b)],
        POOL_STATE_LEN,
        program_id,
    )?;
    create_pda(
        payer,
        &page0_acc,
        sys_prog,
        &[
            Seed::from(PAGE_SEED),
            Seed::from(&pool_le),
            Seed::from(&zero_le),
            Seed::from(&pg_bump_b),
        ],
        PAGE_LEN,
        program_id,
    )?;
    create_pda(
        payer,
        sol_vault_acc,
        sys_prog,
        &[
            Seed::from(SOL_VAULT_SEED),
            Seed::from(&pool_le),
            Seed::from(&sv_bump_b),
        ],
        SENTINEL_ACCOUNT_LEN,
        program_id,
    )?;
    create_pda(
        payer,
        rent_vault_acc,
        sys_prog,
        &[
            Seed::from(PAGE_RENT_SEED),
            Seed::from(&pool_le),
            Seed::from(&rv_bump_b),
        ],
        SENTINEL_ACCOUNT_LEN,
        program_id,
    )?;

    init_sentinel_bytes(*sol_vault_acc, program_id, SOL_VAULT_MAGIC, sv_bump)?;
    init_sentinel_bytes(*rent_vault_acc, program_id, PAGE_RENT_MAGIC, rv_bump)?;

    let slot = Clock::get()?.slot;
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
        authority: address_bytes(payer.address()),
        auditor_pk,
        auditor_locked,
        vault_auth_bump,
        sol_vault_bump: sv_bump,
        page_rent_bump: rv_bump,
        active_lanes: 1,
    };
    save_pool(*pool_acc, program_id, &pool_state)?;

    let mut page_data = page0_acc.try_borrow_mut()?;
    PageHeader {
        version: PROTOCOL_VERSION,
        bump: pg_bump,
        closed: false,
        count: 0,
        pool_id,
        page_id: 0,
        created_slot: slot,
        closed_slot: 0,
    }
    .encode(&mut page_data)
    .map_err(err)?;

    log_tag("audren:init_pool");
    Ok(())
}

// ============================================================================
// Tag 1: OpenPage (permissionless self-funding page rollover)
// Data: empty (0 B)
// Accounts: [0] payer (signer, wr), [1] pool (wr), [2] current_page (wr),
//           [3] next_page (wr), [4] page_rent_vault (wr), [5] system_program
// ============================================================================
fn ix_open_page(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    ensure(data.is_empty(), AudrenError::InvalidInstruction)?;
    ensure(accounts.len() >= 6, AudrenError::InvalidAccount)?;
    let payer = &accounts[0];
    let pool_acc = &accounts[1];
    let mut cur_page_acc = accounts[2];
    let mut next_page_acc = accounts[3];
    let mut rent_vault_acc = accounts[4];
    let sys_prog = &accounts[5];
    ensure(payer.is_signer(), AudrenError::Unauthorized)?;
    ensure(
        payer.is_writable()
            && pool_acc.is_writable()
            && cur_page_acc.is_writable()
            && next_page_acc.is_writable()
            && rent_vault_acc.is_writable()
            && sys_prog.address() == &SYSTEM_ID
            && next_page_acc.owned_by(&SYSTEM_ID)
            && next_page_acc.is_data_empty(),
        AudrenError::InvalidAccount,
    )?;

    let mut pool = load_pool(pool_acc, program_id)?;
    ensure(!pool.paused, AudrenError::PoolPaused)?;
    check_page_rent_vault(&rent_vault_acc, program_id, &pool)?;

    let mut cur_hdr = load_page_header(&cur_page_acc, program_id, pool.pool_id)?;
    ensure(
        cur_hdr.page_id == pool.current_page_id,
        AudrenError::WrongPool,
    )?;
    let remaining = PAGE_CAPACITY.saturating_sub(cur_hdr.count as usize);
    ensure(
        cur_hdr.closed || remaining <= PAGE_ROLLOVER_HEADROOM,
        AudrenError::PageNotReady,
    )?;

    let next_id = page_id_for_lane(
        0,
        seq_of_page_id(pool.current_page_id)
            .checked_add(1)
            .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?,
    )
    .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    let (next_addr, next_bump) = page_pda(program_id, pool.pool_id, next_id);
    ensure(next_page_acc.address() == &next_addr, AudrenError::InvalidPda)?;

    let slot = Clock::get()?.slot;
    // Permanently seal the outgoing page so its witness set becomes immutable.
    {
        cur_hdr.closed = true;
        if cur_hdr.closed_slot == 0 {
            cur_hdr.closed_slot = slot;
        }
        let mut cd = cur_page_acc.try_borrow_mut()?;
        cur_hdr.encode(&mut cd).map_err(err)?;
    }

    // Allocate & assign `next_page_acc` BEFORE any direct lamport transfer from `rent_vault_acc`
    // (Agave enforces balanced lamports across CPI boundaries, so direct lamport debits must
    // occur only after all CPIs complete). Even a zero-balance cranker can open pages once
    // `PageRentVault` is funded because `allocate`/`assign` do not require upfront lamports.
    let min_vault = rent_minimum_balance(SENTINEL_ACCOUNT_LEN)?;
    let page_rent = rent_minimum_balance(PAGE_LEN)?;
    let available = rent_vault_acc.lamports().saturating_sub(min_vault);
    let needed = page_rent.saturating_sub(next_page_acc.lamports());
    let subsidy = available.min(needed);
    let payer_deficit = needed.saturating_sub(subsidy);

    let pool_le = pool.pool_id.to_le_bytes();
    let next_le = next_id.to_le_bytes();
    let bump_b = [next_bump];
    let page_seeds = [
        Seed::from(PAGE_SEED),
        Seed::from(&pool_le),
        Seed::from(&next_le),
        Seed::from(&bump_b),
    ];
    let page_signer = [Signer::from(&page_seeds)];

    if subsidy == 0 && next_page_acc.lamports() == 0 {
        CreateAccount {
            from: payer,
            to: &next_page_acc,
            lamports: payer_deficit,
            space: PAGE_LEN as u64,
            owner: program_id,
        }
        .invoke_signed(&page_signer)?;
    } else {
        if payer_deficit > 0 {
            Transfer {
                from: payer,
                to: &next_page_acc,
                lamports: payer_deficit,
            }
            .invoke()?;
        }
        Allocate {
            account: &next_page_acc,
            space: PAGE_LEN as u64,
        }
        .invoke_signed(&page_signer)?;
        Assign {
            account: &next_page_acc,
            owner: program_id,
        }
        .invoke_signed(&page_signer)?;
    }

    if subsidy > 0 {
        let new_vault = rent_vault_acc
            .lamports()
            .checked_sub(subsidy)
            .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
        let new_page = next_page_acc
            .lamports()
            .checked_add(subsidy)
            .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
        rent_vault_acc.set_lamports(new_vault);
        next_page_acc.set_lamports(new_page);
    }

    {
        let mut nd = next_page_acc.try_borrow_mut()?;
        PageHeader {
            version: PROTOCOL_VERSION,
            bump: next_bump,
            closed: false,
            count: 0,
            pool_id: pool.pool_id,
            page_id: next_id,
            created_slot: slot,
            closed_slot: 0,
        }
        .encode(&mut nd)
        .map_err(err)?;
    }

    pool.current_page_id = next_id;
    save_pool(*pool_acc, program_id, &pool)?;
    log_tag("audren:open_page");
    Ok(())
}

// ============================================================================
// Tag 2: Deposit (supports both self-shielding and third-party confidential onramps)
// Data: is_native_sol (1) | amount (8) | dynamic_out_wire (129) = 138 B
// ============================================================================
fn ix_deposit(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    ensure(
        data.len() == 9 + DYNAMIC_OUTPUT_WIRE_LEN,
        AudrenError::InvalidInstruction,
    )?;
    let flags = data[0];
    ensure(
        (flags & !(DEPOSIT_FLAG_NATIVE_SOL | DEPOSIT_FLAG_FEE_FROM_AMOUNT)) == 0,
        AudrenError::InvalidInstruction,
    )?;
    let is_native = (flags & DEPOSIT_FLAG_NATIVE_SOL) != 0;
    let fee_from_amount = (flags & DEPOSIT_FLAG_FEE_FROM_AMOUNT) != 0;
    if fee_from_amount {
        ensure(is_native, AudrenError::InvalidInstruction)?;
    }
    ensure(
        accounts.len() >= if is_native { 6 } else { 9 },
        AudrenError::InvalidAccount,
    )?;
    let amount = read_u64(data, 1).map_err(err)?;
    ensure(amount > 0, AudrenError::ZeroAmount)?;

    let view_tag = data[9];
    let ephemeral_pk = read_32(data, 10).map_err(err)?;
    validate_nonzero_point(&ephemeral_pk)?;
    let stealth_pk = read_32(data, 42).map_err(err)?;
    validate_nonzero_point(&stealth_pk)?;
    let mut ciphertext = [0u8; NOTE_CT_LEN];
    ciphertext.copy_from_slice(&data[74..74 + NOTE_CT_LEN]);

    let depositor = &accounts[0];
    let pool_acc = &accounts[1];
    let out_page_acc = &accounts[2];
    ensure(depositor.is_signer(), AudrenError::Unauthorized)?;
    ensure(
        depositor.is_writable() && out_page_acc.is_writable(),
        AudrenError::InvalidAccount,
    )?;

    let mut pool = load_pool(pool_acc, program_id)?;
    ensure(!pool.paused, AudrenError::PoolPaused)?;

    let mint_bytes: [u8; 32];
    let committed_amount: u64;
    let out_lane: u8;

    if is_native {
        ensure(accounts.len() >= 6, AudrenError::InvalidAccount)?;
        let sol_vault = &accounts[3];
        let rent_vault_acc = &accounts[4];
        let sys_prog = &accounts[5];
        check_sol_vault(sol_vault, program_id, &pool)?;
        out_lane =
            resolve_output_target(pool_acc, out_page_acc, rent_vault_acc, program_id, &pool)?.0;
        ensure(
            sol_vault.is_writable() && rent_vault_acc.is_writable(),
            AudrenError::InvalidAccount,
        )?;
        if fee_from_amount {
            let fee_paid = collect_page_rent_fee(depositor, rent_vault_acc, sys_prog, &pool, 1)?;
            let net_sol = amount
                .checked_sub(fee_paid)
                .ok_or_else(|| err(AudrenError::ZeroAmount))?;
            ensure(net_sol > 0, AudrenError::ZeroAmount)?;
            Transfer {
                from: depositor,
                to: sol_vault,
                lamports: net_sol,
            }
            .invoke()?;
            committed_amount = net_sol;
        } else {
            Transfer {
                from: depositor,
                to: sol_vault,
                lamports: amount,
            }
            .invoke()?;
            collect_page_rent_fee(depositor, rent_vault_acc, sys_prog, &pool, 1)?;
            committed_amount = amount;
        }
        mint_bytes = NATIVE_SOL_MINT;
    } else {
        ensure(accounts.len() >= 9, AudrenError::InvalidAccount)?;
        let mint = &accounts[3];
        let depositor_ata = &accounts[4];
        let vault_ata = &accounts[5];
        let token_prog = &accounts[6];
        let rent_vault_acc = &accounts[7];
        let sys_prog = &accounts[8];
        let hook_accounts = &accounts[9..];
        check_supported_token_program(token_prog.address())?;
        out_lane =
            resolve_output_target(pool_acc, out_page_acc, rent_vault_acc, program_id, &pool)?.0;
        ensure(
            depositor_ata.is_writable() && vault_ata.is_writable() && rent_vault_acc.is_writable(),
            AudrenError::InvalidAccount,
        )?;
        let mint_info = load_mint_info(mint, token_prog.address())?;
        let v_auth = vault_auth_from_pool(program_id, &pool)?;
        let expected_sol_vault = sol_vault_from_pool(program_id, &pool)?;
        let expected_vault = expected_ata(&v_auth, token_prog.address(), mint.address());
        ensure(vault_ata.address() == &expected_vault, AudrenError::InvalidPda)?;
        ensure(
            depositor_ata.address() != vault_ata.address(),
            AudrenError::InvalidAccount,
        )?;
        let before = token_balance(vault_ata, token_prog.address())?;
        let blocked = [
            pool_acc.address(),
            out_page_acc.address(),
            rent_vault_acc.address(),
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
        let after = token_balance(vault_ata, token_prog.address())?;
        let net_received = after
            .checked_sub(before)
            .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
        ensure(net_received > 0, AudrenError::ZeroAmount)?;
        collect_page_rent_fee(depositor, rent_vault_acc, sys_prog, &pool, 1)?;
        mint_bytes = address_bytes(mint.address());
        committed_amount = net_received;
    }

    let slot = Clock::get()?.slot;
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
    write_output_note(*out_page_acc, program_id, &mut pool, out_lane, &note, slot)?;
    finalize_pool_spend(*pool_acc, program_id, &mut pool, out_lane, 0)?;
    log_tag("audren:deposit");
    Ok(())
}

// ============================================================================
// Tag 3: Transfer (1-in -> 2-out full-private P2P transfer)
// ============================================================================
fn ix_transfer(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    ensure(
        data.len() >= 1 + 2 * NOTE_WIRE_LEN + 64,
        AudrenError::InvalidInstruction,
    )?;
    ensure(accounts.len() >= 8, AudrenError::InvalidAccount)?;

    let payer = &accounts[0];
    let pool_acc = &accounts[1];
    let out_page_acc = &accounts[2];
    let nullifier_acc = &accounts[3];
    let rent_vault_acc = &accounts[4];
    let zk_prog = &accounts[5];
    let sys_prog = &accounts[6];
    ensure(payer.is_signer(), AudrenError::Unauthorized)?;
    ensure(
        payer.is_writable()
            && out_page_acc.is_writable()
            && nullifier_acc.is_writable()
            && rent_vault_acc.is_writable(),
        AudrenError::InvalidAccount,
    )?;

    let mut pool = load_pool(pool_acc, program_id)?;
    ensure(!pool.paused, AudrenError::PoolPaused)?;
    let (out_lane, _) =
        resolve_output_target(pool_acc, out_page_acc, rent_vault_acc, program_id, &pool)?;

    let m = data[0];
    let note_pay = decode_note_wire(&data[1..1 + NOTE_WIRE_LEN])?;
    let note_chg = decode_note_wire(&data[1 + NOTE_WIRE_LEN..1 + 2 * NOTE_WIRE_LEN])?;
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
    let pq_envelope = &data[off..];

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
    let verified = {
        let input_pages = InputPages::load(&accounts[7..], program_id, pool.pool_id, m)?;
        let slices = input_pages.as_slices();
        let v = verify_triptych(
            m,
            &slices[..input_pages.len],
            &input_pages.headers[..input_pages.len],
            &a_spend,
            &v_spend,
            auditor_opt,
            &ctx_hash,
            trip_bytes,
        )?;
        v.check_mode(audited)?;
        v
    };

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

    let slot = Clock::get()?.slot;
    write_output_note(*out_page_acc, program_id, &mut pool, out_lane, &note_pay, slot)?;
    write_output_note(*out_page_acc, program_id, &mut pool, out_lane, &note_chg, slot)?;
    finalize_pool_spend(*pool_acc, program_id, &mut pool, out_lane, 1)?;
    log_tag("audren:transfer");
    Ok(())
}

// ============================================================================
// Tag 4: Merge (2-in -> 1-out full-private consolidation of two same-asset notes)
// ============================================================================
fn ix_merge(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    ensure(
        data.len() >= 2 + NOTE_WIRE_LEN + 96,
        AudrenError::InvalidInstruction,
    )?;
    ensure(accounts.len() >= 10, AudrenError::InvalidAccount)?;

    let payer = &accounts[0];
    let pool_acc = &accounts[1];
    let out_page_acc = &accounts[2];
    let null1_acc = &accounts[3];
    let null2_acc = &accounts[4];
    let rent_vault_acc = &accounts[5];
    let zk_prog = &accounts[6];
    let sys_prog = &accounts[7];
    ensure(payer.is_signer(), AudrenError::Unauthorized)?;
    ensure(
        payer.is_writable()
            && out_page_acc.is_writable()
            && null1_acc.is_writable()
            && null2_acc.is_writable()
            && rent_vault_acc.is_writable(),
        AudrenError::InvalidAccount,
    )?;

    let mut pool = load_pool(pool_acc, program_id)?;
    ensure(!pool.paused, AudrenError::PoolPaused)?;
    let (out_lane, _) =
        resolve_output_target(pool_acc, out_page_acc, rent_vault_acc, program_id, &pool)?;

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
        (n_pages1 + n_pages2) * PAGE_CAPACITY <= MAX_MERGE_RING_SLOTS,
        AudrenError::InvalidInstruction,
    )?;
    ensure(
        accounts.len() >= 8 + n_pages1 + n_pages2,
        AudrenError::InvalidAccount,
    )?;

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
    // Reuse ONE static heap TriptychScratch (~12.9 KiB) for BOTH legs.
    let (ver1, ver2) = TriptychScratch::with_scratch(|scratch| -> Result<_, ProgramError> {
        let v1 = {
            let p1 = InputPages::load(&accounts[8..8 + n_pages1], program_id, pool.pool_id, m1)?;
            let sl1 = p1.as_slices();
            let v = verify_triptych_with_scratch(
                scratch,
                m1,
                &sl1[..p1.len],
                &p1.headers[..p1.len],
                &note_out.asset_tag,
                &v_in1,
                auditor_opt,
                &ctx1,
                trip1,
            )?;
            v.check_mode(audited)?;
            v
        };
        let v2 = {
            let p2 = InputPages::load(
                &accounts[8 + n_pages1..8 + n_pages1 + n_pages2],
                program_id,
                pool.pool_id,
                m2,
            )?;
            let sl2 = p2.as_slices();
            let v = verify_triptych_with_scratch(
                scratch,
                m2,
                &sl2[..p2.len],
                &p2.headers[..p2.len],
                &note_out.asset_tag,
                &v_in2,
                auditor_opt,
                &ctx2,
                trip2,
            )?;
            v.check_mode(audited)?;
            v
        };
        Ok((v1, v2))
    })?;

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

    let slot = Clock::get()?.slot;
    write_output_note(*out_page_acc, program_id, &mut pool, out_lane, &note_out, slot)?;
    finalize_pool_spend(*pool_acc, program_id, &mut pool, out_lane, 2)?;
    log_tag("audren:merge");
    Ok(())
}

// ============================================================================
// Tag 5: ExecViaEscrow (1-tx protocol-agnostic private DeFi execution via sharded `escrow` PDA)
// ============================================================================
fn ix_exec_via_escrow(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    ensure(
        data.len() >= 32 + DYNAMIC_OUTPUT_WIRE_LEN,
        AudrenError::InvalidInstruction,
    )?;
    ensure(accounts.len() >= 20, AudrenError::InvalidAccount)?;

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
    let target_prog = &accounts[14];
    let fee_recipient_ata = &accounts[15];

    ensure(payer.is_signer(), AudrenError::Unauthorized)?;
    ensure(
        payer.is_writable()
            && out_page_acc.is_writable()
            && nullifier_acc.is_writable()
            && rent_vault_acc.is_writable()
            && vault_in.is_writable()
            && vault_out.is_writable(),
        AudrenError::InvalidAccount,
    )?;
    ensure(
        target_prog.executable()
            && target_prog.address() != program_id
            && target_prog.address() != sys_prog.address()
            && target_prog.address() != zk_prog.address()
            && target_prog.address() != token_prog_in.address()
            && target_prog.address() != token_prog_out.address(),
        AudrenError::InvalidTargetProgram,
    )?;

    let mut pool = load_pool(pool_acc, program_id)?;
    ensure(!pool.paused, AudrenError::PoolPaused)?;
    let (out_lane, _) =
        resolve_output_target(pool_acc, out_page_acc, rent_vault_acc, program_id, &pool)?;
    check_supported_token_program(token_prog_in.address())?;
    check_supported_token_program(token_prog_out.address())?;
    let mint_info_in = load_mint_info(mint_in, token_prog_in.address())?;
    let mint_info_out = load_mint_info(mint_out, token_prog_out.address())?;

    let expected_va = vault_auth_from_pool(program_id, &pool)?;
    let va_bump = pool.vault_auth_bump;
    ensure(vault_auth_acc.address() == &expected_va, AudrenError::InvalidPda)?;
    ensure(
        vault_in.address() == &expected_ata(&expected_va, token_prog_in.address(), mint_in.address()),
        AudrenError::InvalidPda,
    )?;
    ensure(
        vault_out.address()
            == &expected_ata(&expected_va, token_prog_out.address(), mint_out.address()),
        AudrenError::InvalidPda,
    )?;

    let m = data[0];
    let shard_id = data[1];
    let flags = data[2];
    ensure(
        (flags & !(EXEC_FLAG_HAS_CHANGE | EXEC_FLAG_ALLOW_PARTIAL_REFUND | EXEC_FLAG_FEE_ON_OUTPUT))
            == 0,
        AudrenError::InvalidInstruction,
    )?;
    let has_change = (flags & EXEC_FLAG_HAS_CHANGE) != 0;
    let allow_partial = (flags & EXEC_FLAG_ALLOW_PARTIAL_REFUND) != 0;
    let fee_on_output = (flags & EXEC_FLAG_FEE_ON_OUTPUT) != 0;
    let amount_in = read_u64(data, 3).map_err(err)?;
    let min_amount_out = read_u64(data, 11).map_err(err)?;
    let relayer_fee = read_u64(data, 19).map_err(err)?;
    let escrow_idx = data[27] as usize;
    let escrow_in_idx = data[28] as usize;
    let escrow_out_idx = data[29] as usize;
    let target_data_len = u16::from_le_bytes([data[30], data[31]]) as usize;
    ensure(amount_in > 0 && min_amount_out > 0, AudrenError::ZeroAmount)?;
    if relayer_fee == 0 {
        ensure(!fee_on_output, AudrenError::InvalidInstruction)?;
    } else if !fee_on_output {
        ensure(relayer_fee < amount_in, AudrenError::InvalidInstruction)?;
    }

    let mut off = 32usize;
    let out_desc = &data[off..off + DYNAMIC_OUTPUT_WIRE_LEN];
    off += DYNAMIC_OUTPUT_WIRE_LEN;
    let out_view_tag = out_desc[0];
    let out_eph_pk = read_32(out_desc, 1).map_err(err)?;
    validate_nonzero_point(&out_eph_pk)?;
    let out_stealth_pk = read_32(out_desc, 33).map_err(err)?;
    validate_nonzero_point(&out_stealth_pk)?;
    let mut out_ct = [0u8; NOTE_CT_LEN];
    out_ct.copy_from_slice(&out_desc[65..65 + NOTE_CT_LEN]);

    let mut change_bundle: Option<(NoteEntry, [u8; 32], &[u8], &[u8])> = None;
    let mut chg_wire_slice: &[u8] = &[];
    let mut c_chg_slice: &[u8] = &[];
    if has_change {
        let chg_need = NOTE_WIRE_LEN + 32 + CROSS_BASE_1_LEN + RANGE_U64_PROOF_LEN;
        ensure(data.len() >= off + chg_need, AudrenError::InvalidInstruction)?;
        chg_wire_slice = &data[off..off + NOTE_WIRE_LEN];
        let note_chg = decode_note_wire(chg_wire_slice)?;
        off += NOTE_WIRE_LEN;
        c_chg_slice = &data[off..off + 32];
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
        let r_eph = read_32(rd, 1).map_err(err)?;
        validate_nonzero_point(&r_eph)?;
        let r_stealth = read_32(rd, 33).map_err(err)?;
        validate_nonzero_point(&r_stealth)?;
        let mut r_ct = [0u8; NOTE_CT_LEN];
        r_ct.copy_from_slice(&rd[65..65 + NOTE_CT_LEN]);
        refund_desc = Some((rd[0], r_eph, r_stealth, r_ct));
    }

    let audited = pool.has_auditor();
    let trip_len = triptych_proof_len(m, audited).map_err(err)?;
    ensure(
        data.len() == off + trip_len + target_data_len,
        AudrenError::InvalidInstruction,
    )?;
    let trip_bytes = &data[off..off + trip_len];
    off += trip_len;
    let target_data = &data[off..off + target_data_len];

    let g_in = asset_generator(&address_bytes(mint_in.address()));
    let v_in_exact = pt_mul_u64(amount_in, g_in)?;
    let v_spend = if let Some((ref note_chg, _, _, _)) = change_bundle {
        ensure(note_chg.asset_tag == g_in, AudrenError::InvalidInstruction)?;
        pt_add(v_in_exact, note_chg.commitment)?
    } else {
        v_in_exact
    };

    let n_pages = input_pages_for_m(m).map_err(err)?;
    let action_start = 16 + n_pages;
    ensure(accounts.len() >= action_start + 3, AudrenError::InvalidAccount)?;
    let action_accounts = &accounts[action_start..];
    ensure(
        action_accounts.len() <= MAX_ROUTER_CPI_ACCOUNTS
            && escrow_idx < action_accounts.len()
            && escrow_in_idx < action_accounts.len()
            && escrow_out_idx < action_accounts.len()
            && escrow_idx != escrow_in_idx
            && escrow_idx != escrow_out_idx
            && escrow_in_idx != escrow_out_idx,
        AudrenError::InvalidAccount,
    )?;

    let (expected_escrow, escrow_bump) = escrow_pda(program_id, pool.pool_id, shard_id)?;
    let escrow_acc = &action_accounts[escrow_idx];
    let escrow_in = &action_accounts[escrow_in_idx];
    let escrow_out = &action_accounts[escrow_out_idx];
    ensure(escrow_acc.address() == &expected_escrow, AudrenError::InvalidPda)?;
    ensure(
        escrow_in.is_writable() && escrow_out.is_writable(),
        AudrenError::InvalidAccount,
    )?;
    ensure(
        escrow_acc.owned_by(&SYSTEM_ID) && escrow_acc.is_data_empty(),
        AudrenError::EscrowAuthorityAltered,
    )?;
    ensure(
        escrow_in.address()
            == &expected_ata(&expected_escrow, token_prog_in.address(), mint_in.address()),
        AudrenError::InvalidPda,
    )?;
    ensure(
        escrow_out.address()
            == &expected_ata(&expected_escrow, token_prog_out.address(), mint_out.address()),
        AudrenError::InvalidPda,
    )?;
    ensure(
        mint_in.address() != mint_out.address(),
        AudrenError::InvalidInstruction,
    )?;

    let expected_sol_vault = sol_vault_from_pool(program_id, &pool)?;
    let fee_recip_bytes = if relayer_fee > 0 {
        let fee_prog = if fee_on_output {
            token_prog_out.address()
        } else {
            token_prog_in.address()
        };
        let fee_k = fee_recipient_ata.address();
        ensure(
            fee_recipient_ata.is_writable()
                && !fee_recipient_ata.owned_by(program_id)
                && fee_k != program_id
                && fee_k != vault_auth_acc.address()
                && fee_k != vault_in.address()
                && fee_k != vault_out.address()
                && fee_k != escrow_acc.address()
                && fee_k != escrow_in.address()
                && fee_k != escrow_out.address()
                && fee_k != pool_acc.address()
                && fee_k != out_page_acc.address()
                && fee_k != nullifier_acc.address()
                && fee_k != rent_vault_acc.address()
                && fee_k != &expected_sol_vault,
            AudrenError::InvalidAccount,
        )?;
        let Some(fee_snap) = token_account_security(fee_recipient_ata) else {
            return Err(err(AudrenError::InvalidAccount));
        };
        ensure(
            fee_snap.token_program == *fee_prog
                && fee_snap.owner != expected_va
                && fee_snap.owner != expected_escrow,
            AudrenError::InvalidAccount,
        )?;
        address_bytes(fee_k)
    } else {
        [0u8; 32]
    };

    let ctx_hash = transcript_root(&[
        b"audren/v1/exec_escrow",
        &address_bytes(program_id),
        &pool.pool_id.to_le_bytes(),
        &[m, shard_id, flags],
        &address_bytes(target_prog.address()),
        &address_bytes(mint_in.address()),
        &address_bytes(mint_out.address()),
        &amount_in.to_le_bytes(),
        &min_amount_out.to_le_bytes(),
        &relayer_fee.to_le_bytes(),
        &fee_recip_bytes,
        out_desc,
        chg_wire_slice,
        c_chg_slice,
        refund_raw,
    ]);

    // 1. Verify Triptych proof + optional change range proof.
    let auditor_opt = if audited { Some(&pool.auditor_pk) } else { None };
    let verified = {
        let input_pages =
            InputPages::load(&accounts[16..action_start], program_id, pool.pool_id, m)?;
        let slices = input_pages.as_slices();
        let v = verify_triptych(
            m,
            &slices[..input_pages.len],
            &input_pages.headers[..input_pages.len],
            &g_in,
            &v_spend,
            auditor_opt,
            &ctx_hash,
            trip_bytes,
        )?;
        v.check_mode(audited)?;
        v
    };

    if let Some((ref note_chg, ref c_chg, xbase1, range64)) = change_bundle {
        verify_cross_base_1(
            &note_chg.asset_tag,
            &note_chg.commitment,
            c_chg,
            &ctx_hash,
            xbase1,
        )?;
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

    // 3–6. Validate action account firewall, snapshot every writable `escrow` token account
    //      in the disjoint `[16 KiB .. 24 KiB)` SBF heap arena, optionally pay input-side
    //      `relayer_fee`, fund `escrow_in`, invoke `target_prog`, and verify post-CPI integrity.
    let pool_le = pool.pool_id.to_le_bytes();
    let va_bump_b = [va_bump];
    let va_seeds = [
        Seed::from(VAULT_AUTH_SEED),
        Seed::from(&pool_le),
        Seed::from(&va_bump_b),
    ];
    let va_signer = [Signer::from(&va_seeds)];
    let shard_b = [shard_id];
    let escrow_bump_b = [escrow_bump];
    let escrow_seeds = [
        Seed::from(ESCROW_SEED),
        Seed::from(&pool_le),
        Seed::from(&shard_b),
        Seed::from(&escrow_bump_b),
    ];
    let escrow_signer = [Signer::from(&escrow_seeds)];
    let exec_blocked = [
        payer.address(),
        pool_acc.address(),
        out_page_acc.address(),
        nullifier_acc.address(),
        rent_vault_acc.address(),
        vault_auth_acc.address(),
        vault_in.address(),
        vault_out.address(),
        &expected_sol_vault,
    ];
    let escrow_in_before = token_balance(escrow_in, token_prog_in.address())?;
    let escrow_out_before = token_balance(escrow_out, token_prog_out.address())?;

    let escrow_in_funded = WatchedEscrowBuf::with_buf(|watched_escrow_accs| -> Result<u64, ProgramError> {
        for (idx, acc) in action_accounts.iter().enumerate() {
            let k = acc.address();
            ensure(
                k != program_id
                    && !acc.owned_by(program_id)
                    && k != vault_auth_acc.address()
                    && k != vault_in.address()
                    && k != vault_out.address()
                    && k != pool_acc.address()
                    && k != out_page_acc.address()
                    && k != nullifier_acc.address()
                    && k != rent_vault_acc.address()
                    && k != &expected_sol_vault
                    && (relayer_fee == 0 || k != fee_recipient_ata.address()),
                AudrenError::InvalidAccount,
            )?;
            if !acc.is_writable() {
                continue;
            }
            if let Some(snap) = token_account_security(acc) {
                if snap.owner == expected_escrow {
                    ensure(!snap.has_delegate, AudrenError::EscrowAccountAltered)?;
                    watched_escrow_accs.push(idx, snap.token_program, snap.close_authority);
                }
            }
        }

        let escrow_lamports_before = escrow_acc.lamports();
        let vault_in_before_fund = token_balance(vault_in, token_prog_in.address())?;
        let exec_amount_in = if relayer_fee > 0 && !fee_on_output {
            invoke_token_transfer_checked(
                program_id,
                vault_auth_acc.address(),
                token_prog_in,
                vault_in,
                mint_in,
                fee_recipient_ata,
                vault_auth_acc,
                relayer_fee,
                mint_info_in,
                action_accounts,
                &exec_blocked,
                &va_signer,
            )?;
            amount_in
                .checked_sub(relayer_fee)
                .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?
        } else {
            amount_in
        };

        invoke_token_transfer_checked(
            program_id,
            vault_auth_acc.address(),
            token_prog_in,
            vault_in,
            mint_in,
            escrow_in,
            vault_auth_acc,
            exec_amount_in,
            mint_info_in,
            action_accounts,
            &exec_blocked,
            &va_signer,
        )?;
        let vault_in_after_fund = token_balance(vault_in, token_prog_in.address())?;
        ensure(
            vault_in_before_fund.checked_sub(vault_in_after_fund) == Some(amount_in),
            AudrenError::ArithmeticOverflow,
        )?;
        let funded = token_balance(escrow_in, token_prog_in.address())?
            .checked_sub(escrow_in_before)
            .ok_or_else(|| err(AudrenError::EscrowAccountAltered))?;

        invoke_target_cpi(
            target_prog.address(),
            action_accounts,
            target_data,
            &expected_escrow,
            &escrow_signer,
        )?;

        ensure(
            escrow_acc.owned_by(&SYSTEM_ID)
                && escrow_acc.is_data_empty()
                && escrow_acc.lamports() >= escrow_lamports_before,
            AudrenError::EscrowAuthorityAltered,
        )?;
        for entry in watched_escrow_accs.as_slice() {
            let acc = &action_accounts[entry.idx as usize];
            let Some(snap) = token_account_security(acc) else {
                return Err(err(AudrenError::EscrowAccountAltered));
            };
            let expected_close_auth = entry.has_close_auth.then_some(entry.close_authority);
            ensure(
                snap.token_program == entry.token_program
                    && snap.owner == expected_escrow
                    && !snap.has_delegate
                    && snap.close_authority == expected_close_auth,
                AudrenError::EscrowAccountAltered,
            )?;
        }
        Ok(funded)
    })?;

    let escrow_out_after = token_balance(escrow_out, token_prog_out.address())?;
    let escrow_in_after = token_balance(escrow_in, token_prog_in.address())?;
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

    // 7. Optionally pay output-side `relayer_fee` and sweep net output from `escrow_out` -> `vault_out`.
    let user_gross_out = if relayer_fee > 0 && fee_on_output {
        let rem = actual_out
            .checked_sub(relayer_fee)
            .ok_or_else(|| err(AudrenError::SlippageExceeded))?;
        ensure(rem > 0, AudrenError::SlippageExceeded)?;
        invoke_token_transfer_checked(
            program_id,
            vault_auth_acc.address(),
            token_prog_out,
            escrow_out,
            mint_out,
            fee_recipient_ata,
            escrow_acc,
            relayer_fee,
            mint_info_out,
            action_accounts,
            &exec_blocked,
            &escrow_signer,
        )?;
        rem
    } else {
        actual_out
    };

    let vault_out_before = token_balance(vault_out, token_prog_out.address())?;
    invoke_token_transfer_checked(
        program_id,
        vault_auth_acc.address(),
        token_prog_out,
        escrow_out,
        mint_out,
        vault_out,
        escrow_acc,
        user_gross_out,
        mint_info_out,
        action_accounts,
        &exec_blocked,
        &escrow_signer,
    )?;
    let vault_out_after = token_balance(vault_out, token_prog_out.address())?;
    let net_out = vault_out_after
        .checked_sub(vault_out_before)
        .ok_or_else(|| err(AudrenError::SlippageExceeded))?;
    ensure(net_out >= min_amount_out, AudrenError::SlippageExceeded)?;

    let mut net_refund = 0u64;
    if unspent_in > 0 {
        let vault_in_before = token_balance(vault_in, token_prog_in.address())?;
        invoke_token_transfer_checked(
            program_id,
            vault_auth_acc.address(),
            token_prog_in,
            escrow_in,
            mint_in,
            vault_in,
            escrow_acc,
            unspent_in,
            mint_info_in,
            action_accounts,
            &exec_blocked,
            &escrow_signer,
        )?;
        let vault_in_after = token_balance(vault_in, token_prog_in.address())?;
        net_refund = vault_in_after
            .checked_sub(vault_in_before)
            .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    }

    // 8. Compute dynamic `V_out = net_out * G_{mint_out}` on-chain and append stealth notes.
    let out_notes_count = 1u64 + u64::from(has_change) + u64::from(net_refund > 0);
    collect_page_rent_fee(payer, rent_vault_acc, sys_prog, &pool, out_notes_count)?;

    let slot = Clock::get()?.slot;
    let g_out = asset_generator(&address_bytes(mint_out.address()));
    let v_out = pt_mul_u64(net_out, g_out)?;
    let exec_note = NoteEntry {
        view_tag: out_view_tag,
        ephemeral_pk: out_eph_pk,
        stealth_pk: out_stealth_pk,
        asset_tag: g_out,
        commitment: v_out,
        ciphertext: out_ct,
    };
    write_output_note(*out_page_acc, program_id, &mut pool, out_lane, &exec_note, slot)?;

    if let Some((note_chg, _, _, _)) = change_bundle {
        write_output_note(*out_page_acc, program_id, &mut pool, out_lane, &note_chg, slot)?;
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
            write_output_note(
                *out_page_acc,
                program_id,
                &mut pool,
                out_lane,
                &refund_note,
                slot,
            )?;
        }
    }

    finalize_pool_spend(*pool_acc, program_id, &mut pool, out_lane, 1)?;
    log_tag("audren:exec_escrow");
    Ok(())
}

// ============================================================================
// Tag 6: Withdraw (self-paying 1-in spend -> public SOL / SPL / unwrapped WSOL + optional change)
// ============================================================================
fn ix_withdraw(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    ensure(data.len() >= 18, AudrenError::InvalidInstruction)?;
    let m = data[0];
    let flags = data[1];
    ensure(
        (flags & !(WITHDRAW_FLAG_NATIVE_SOL | WITHDRAW_FLAG_HAS_CHANGE | WITHDRAW_FLAG_UNWRAP_WSOL))
            == 0,
        AudrenError::InvalidInstruction,
    )?;
    let is_native = (flags & WITHDRAW_FLAG_NATIVE_SOL) != 0;
    let has_change = (flags & WITHDRAW_FLAG_HAS_CHANGE) != 0;
    let unwrap_wsol = (flags & WITHDRAW_FLAG_UNWRAP_WSOL) != 0;
    ensure(!(is_native && unwrap_wsol), AudrenError::InvalidInstruction)?;
    let amount_out = read_u64(data, 2).map_err(err)?;
    let relayer_fee = read_u64(data, 10).map_err(err)?;
    ensure(amount_out > 0, AudrenError::ZeroAmount)?;
    let total_out = amount_out
        .checked_add(relayer_fee)
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    ensure(accounts.len() >= 11, AudrenError::InvalidAccount)?;

    let payer = &accounts[0];
    let pool_acc = &accounts[1];
    let out_page_acc = &accounts[2];
    let nullifier_acc = &accounts[3];
    let rent_vault_acc = &accounts[4];
    let zk_prog = &accounts[5];
    let sys_prog = &accounts[6];
    let fee_recipient = &accounts[7];
    ensure(payer.is_signer(), AudrenError::Unauthorized)?;
    ensure(
        payer.is_writable() && nullifier_acc.is_writable(),
        AudrenError::InvalidAccount,
    )?;

    let mut pool = load_pool(pool_acc, program_id)?;
    // Non-custodial escape hatch: full withdrawals (`!has_change`) ALWAYS succeed even if paused.
    let out_lane = if has_change {
        ensure(!pool.paused, AudrenError::PoolPaused)?;
        ensure(
            out_page_acc.is_writable() && rent_vault_acc.is_writable(),
            AudrenError::InvalidAccount,
        )?;
        resolve_output_target(pool_acc, out_page_acc, rent_vault_acc, program_id, &pool)?.0
    } else {
        check_page_rent_vault(rent_vault_acc, program_id, &pool)?;
        0
    };

    let mut off = 18usize;
    let mut change_bundle: Option<(NoteEntry, [u8; 32], &[u8], &[u8])> = None;
    let mut chg_wire_slice: &[u8] = &[];
    let mut c_chg_slice: &[u8] = &[];
    if has_change {
        let chg_need = NOTE_WIRE_LEN + 32 + CROSS_BASE_1_LEN + RANGE_U64_PROOF_LEN;
        ensure(data.len() >= off + chg_need, AudrenError::InvalidInstruction)?;
        chg_wire_slice = &data[off..off + NOTE_WIRE_LEN];
        let note_chg = decode_note_wire(chg_wire_slice)?;
        off += NOTE_WIRE_LEN;
        c_chg_slice = &data[off..off + 32];
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
        ensure(accounts.len() >= 11, AudrenError::InvalidAccount)?;
        ensure(
            accounts[8].is_writable() && accounts[9].is_writable(),
            AudrenError::InvalidAccount,
        )?;
        (NATIVE_SOL_MINT, address_bytes(accounts[9].address()), 10usize)
    } else if unwrap_wsol {
        ensure(accounts.len() >= 15, AudrenError::InvalidAccount)?;
        ensure(
            accounts[10].is_writable() && accounts[11].is_writable() && accounts[13].is_writable(),
            AudrenError::InvalidAccount,
        )?;
        ensure(
            accounts[9].address() == &WSOL_ID && accounts[12].address() == &CLASSIC_TOKEN_ID,
            AudrenError::InvalidAccount,
        )?;
        (
            WSOL_MINT,
            address_bytes(accounts[11].address()),
            14usize,
        )
    } else {
        ensure(accounts.len() >= 14, AudrenError::InvalidAccount)?;
        ensure(
            accounts[10].is_writable() && accounts[11].is_writable(),
            AudrenError::InvalidAccount,
        )?;
        (
            address_bytes(accounts[9].address()),
            address_bytes(accounts[11].address()),
            13usize,
        )
    };

    let fee_recip_bytes = if relayer_fee > 0 {
        ensure(
            fee_recipient.is_writable()
                && !fee_recipient.owned_by(program_id)
                && fee_recipient.address() != program_id
                && fee_recipient.address() != nullifier_acc.address()
                && fee_recipient.address() != pool_acc.address()
                && fee_recipient.address() != out_page_acc.address()
                && fee_recipient.address() != rent_vault_acc.address(),
            AudrenError::InvalidAccount,
        )?;
        address_bytes(fee_recipient.address())
    } else {
        [0u8; 32]
    };

    let g_mint = asset_generator(&mint_bytes);
    let v_out = pt_mul_u64(total_out, g_mint)?;
    let v_spend = if let Some((ref note_chg, _, _, _)) = change_bundle {
        ensure(note_chg.asset_tag == g_mint, AudrenError::InvalidInstruction)?;
        pt_add(v_out, note_chg.commitment)?
    } else {
        v_out
    };

    let ctx_hash = transcript_root(&[
        b"audren/v1/withdraw",
        &address_bytes(program_id),
        &pool.pool_id.to_le_bytes(),
        &[m, flags],
        &mint_bytes,
        &recipient_key,
        &amount_out.to_le_bytes(),
        &relayer_fee.to_le_bytes(),
        &fee_recip_bytes,
        chg_wire_slice,
        c_chg_slice,
    ]);

    let auditor_opt = if audited { Some(&pool.auditor_pk) } else { None };
    let verified = {
        let input_pages =
            InputPages::load(&accounts[pages_start..], program_id, pool.pool_id, m)?;
        let slices = input_pages.as_slices();
        let v = verify_triptych(
            m,
            &slices[..input_pages.len],
            &input_pages.headers[..input_pages.len],
            &g_mint,
            &v_spend,
            auditor_opt,
            &ctx_hash,
            trip_bytes,
        )?;
        v.check_mode(audited)?;
        v
    };

    if let Some((ref note_chg, ref c_chg, xbase1, range64)) = change_bundle {
        ensure(
            !is_zero_point(&note_chg.stealth_pk),
            AudrenError::InvalidPoint,
        )?;
        verify_cross_base_1(
            &note_chg.asset_tag,
            &note_chg.commitment,
            c_chg,
            &ctx_hash,
            xbase1,
        )?;
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
        let slot = Clock::get()?.slot;
        collect_page_rent_fee(payer, rent_vault_acc, sys_prog, &pool, 1)?;
        write_output_note(*out_page_acc, program_id, &mut pool, out_lane, &note_chg, slot)?;
    }

    if is_native {
        let mut sol_vault = accounts[8];
        let mut recipient = accounts[9];
        let mut fee_acc = accounts[7];
        check_sol_vault(&sol_vault, program_id, &pool)?;
        ensure(
            recipient.address() != sol_vault.address()
                && recipient.address() != program_id
                && !recipient.owned_by(program_id),
            AudrenError::InvalidAccount,
        )?;
        let min_bal = rent_minimum_balance(SENTINEL_ACCOUNT_LEN)?;
        let new_bal = sol_vault
            .lamports()
            .checked_sub(total_out)
            .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
        ensure(new_bal >= min_bal, AudrenError::ArithmeticOverflow)?;
        sol_vault.set_lamports(new_bal);
        if relayer_fee > 0 && fee_acc.address() == recipient.address() {
            let new_recip = recipient
                .lamports()
                .checked_add(total_out)
                .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
            recipient.set_lamports(new_recip);
        } else {
            let new_recip = recipient
                .lamports()
                .checked_add(amount_out)
                .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
            recipient.set_lamports(new_recip);
            if relayer_fee > 0 {
                ensure(
                    fee_acc.address() != sol_vault.address(),
                    AudrenError::InvalidAccount,
                )?;
                let new_fee = fee_acc
                    .lamports()
                    .checked_add(relayer_fee)
                    .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
                fee_acc.set_lamports(new_fee);
            }
        }
    } else if unwrap_wsol {
        let vault_auth = &accounts[8];
        let mint = &accounts[9];
        let vault_ata = &accounts[10];
        let recipient = &accounts[11];
        let token_prog = &accounts[12];
        let unwrap_acc = &accounts[13];
        let expected_va = vault_auth_from_pool(program_id, &pool)?;
        let va_bump = pool.vault_auth_bump;
        ensure(vault_auth.address() == &expected_va, AudrenError::InvalidPda)?;
        ensure(
            vault_ata.address()
                == &expected_ata(&expected_va, token_prog.address(), mint.address()),
            AudrenError::InvalidPda,
        )?;
        let pool_le = pool.pool_id.to_le_bytes();
        let va_bump_b = [va_bump];
        let va_seeds = [
            Seed::from(VAULT_AUTH_SEED),
            Seed::from(&pool_le),
            Seed::from(&va_bump_b),
        ];
        let va_signer = [Signer::from(&va_seeds)];
        unwrap_wsol_and_payout(
            program_id,
            pool.pool_id,
            &verified.nullifier,
            payer,
            sys_prog,
            vault_auth,
            mint,
            vault_ata,
            recipient,
            fee_recipient,
            token_prog,
            unwrap_acc,
            amount_out,
            relayer_fee,
            &va_signer,
        )?;
    } else {
        let vault_auth = &accounts[8];
        let mint = &accounts[9];
        let vault_ata = &accounts[10];
        let recipient_ata = &accounts[11];
        let token_prog = &accounts[12];
        let n_pages = input_pages_for_m(m).map_err(err)?;
        let hook_accounts = &accounts[pages_start + n_pages..];
        check_supported_token_program(token_prog.address())?;
        let mint_info = load_mint_info(mint, token_prog.address())?;
        let expected_va = vault_auth_from_pool(program_id, &pool)?;
        let va_bump = pool.vault_auth_bump;
        let expected_sol_vault = sol_vault_from_pool(program_id, &pool)?;
        ensure(vault_auth.address() == &expected_va, AudrenError::InvalidPda)?;
        ensure(
            vault_ata.address()
                == &expected_ata(&expected_va, token_prog.address(), mint.address()),
            AudrenError::InvalidPda,
        )?;
        ensure(
            recipient_ata.address() != vault_ata.address(),
            AudrenError::InvalidAccount,
        )?;
        if relayer_fee > 0 {
            ensure(
                fee_recipient.address() != vault_ata.address(),
                AudrenError::InvalidAccount,
            )?;
            let Some(fee_snap) = token_account_security(fee_recipient) else {
                return Err(err(AudrenError::InvalidAccount));
            };
            ensure(
                fee_snap.token_program == *token_prog.address() && fee_snap.owner != expected_va,
                AudrenError::InvalidAccount,
            )?;
        }
        let pool_le = pool.pool_id.to_le_bytes();
        let va_bump_b = [va_bump];
        let va_seeds = [
            Seed::from(VAULT_AUTH_SEED),
            Seed::from(&pool_le),
            Seed::from(&va_bump_b),
        ];
        let va_signer = [Signer::from(&va_seeds)];
        let vault_before = token_balance(vault_ata, token_prog.address())?;
        let blocked = [
            payer.address(),
            pool_acc.address(),
            out_page_acc.address(),
            nullifier_acc.address(),
            rent_vault_acc.address(),
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
            &va_signer,
        )?;
        if relayer_fee > 0 {
            invoke_token_transfer_checked(
                program_id,
                &expected_va,
                token_prog,
                vault_ata,
                mint,
                fee_recipient,
                vault_auth,
                relayer_fee,
                mint_info,
                hook_accounts,
                &blocked,
                &va_signer,
            )?;
        }
        let vault_after = token_balance(vault_ata, token_prog.address())?;
        ensure(
            vault_before.checked_sub(vault_after) == Some(total_out),
            AudrenError::ArithmeticOverflow,
        )?;
    }

    finalize_pool_spend(*pool_acc, program_id, &mut pool, out_lane, 1)?;
    log_tag("audren:withdraw");
    Ok(())
}

// ============================================================================
// Tag 7: SetPaused (authority emergency pause — never grants fund withdrawal)
// ============================================================================
fn ix_set_paused(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    ensure(data.len() == 1, AudrenError::InvalidInstruction)?;
    ensure(accounts.len() >= 2, AudrenError::InvalidAccount)?;
    let authority = &accounts[0];
    let pool_acc = &accounts[1];
    ensure(authority.is_signer(), AudrenError::Unauthorized)?;
    ensure(pool_acc.is_writable(), AudrenError::InvalidAccount)?;
    let mut pool = load_pool(pool_acc, program_id)?;
    ensure(
        address_bytes(authority.address()) == pool.authority,
        AudrenError::Unauthorized,
    )?;
    pool.paused = data[0] != 0;
    save_pool(*pool_acc, program_id, &pool)?;
    log_tag("audren:set_paused");
    Ok(())
}

/// Zero magic, refund 100% of rent to `payer`, and atomically close `proof_buffer` (owner -> System,
/// lamports -> 0, data_len -> 0 in one Pinocchio `AccountView::close()` call).
fn close_proof_buffer_account(
    mut proof_buffer: AccountView,
    mut payer: AccountView,
) -> ProgramResult {
    {
        let mut buf = proof_buffer.try_borrow_mut()?;
        if buf.len() >= 8 {
            buf[..8].fill(0);
        }
    }
    let refund = proof_buffer.lamports();
    let new_payer = payer
        .lamports()
        .checked_add(refund)
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    payer.set_lamports(new_payer);
    proof_buffer.close()?;
    Ok(())
}

// ============================================================================
// Tag 8: WriteProofBuffer (out-of-order / parallel <=768 B chunk uploader)
// ============================================================================
fn ix_write_proof_buffer(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    ensure(data.len() >= 14, AudrenError::InvalidInstruction)?;
    ensure(accounts.len() >= 3, AudrenError::InvalidAccount)?;
    let payer = &accounts[0];
    let mut buf_acc = accounts[1];
    let sys_prog = &accounts[2];
    ensure(payer.is_signer() && payer.is_writable(), AudrenError::Unauthorized)?;
    ensure(
        buf_acc.is_writable()
            && sys_prog.address() == &SYSTEM_ID
            && buf_acc.address() != payer.address(),
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

    let (expected_buf, bump) = proof_buffer_pda(program_id, payer.address(), nonce);
    ensure(buf_acc.address() == &expected_buf, AudrenError::InvalidPda)?;

    let expected_space = PROOF_BUFFER_HEADER_LEN + total_len;
    if buf_acc.is_data_empty() {
        let nonce_le = nonce.to_le_bytes();
        let bump_b = [bump];
        let seeds = [
            Seed::from(PROOF_BUFFER_SEED),
            Seed::from(payer.address().as_ref()),
            Seed::from(&nonce_le),
            Seed::from(&bump_b),
        ];
        create_pda(payer, &buf_acc, sys_prog, &seeds, expected_space, program_id)?;
        let mut buf = buf_acc.try_borrow_mut()?;
        buf[BUF_OFF_MAGIC..BUF_OFF_MAGIC + 8].copy_from_slice(&PROOF_BUFFER_MAGIC);
        buf[BUF_OFF_AUTHORITY..BUF_OFF_AUTHORITY + 32].copy_from_slice(payer.address().as_ref());
        buf[BUF_OFF_EXPECTED_LEN..BUF_OFF_EXPECTED_LEN + 4]
            .copy_from_slice(&(total_len as u32).to_le_bytes());
        buf[BUF_OFF_WRITTEN_MASK..BUF_OFF_WRITTEN_MASK + 2].copy_from_slice(&0u16.to_le_bytes());
        buf[46..48].fill(0);
    } else {
        ensure(buf_acc.owned_by(program_id), AudrenError::InvalidProofBuffer)?;
        let buf = buf_acc.try_borrow()?;
        ensure(
            buf.len() == expected_space
                && buf[BUF_OFF_MAGIC..BUF_OFF_MAGIC + 8] == PROOF_BUFFER_MAGIC
                && buf[BUF_OFF_AUTHORITY..BUF_OFF_AUTHORITY + 32] == *payer.address().as_ref()
                && read_u32(&buf, BUF_OFF_EXPECTED_LEN).map_err(err)? as usize == total_len,
            AudrenError::InvalidProofBuffer,
        )?;
    }

    let mut buf = buf_acc.try_borrow_mut()?;
    let payload_off = PROOF_BUFFER_HEADER_LEN + start;
    buf[payload_off..payload_off + expected_chunk_len].copy_from_slice(chunk);
    let mask = read_u16(&buf, BUF_OFF_WRITTEN_MASK).map_err(err)? | (1u16 << chunk_index);
    buf[BUF_OFF_WRITTEN_MASK..BUF_OFF_WRITTEN_MASK + 2].copy_from_slice(&mask.to_le_bytes());
    Ok(())
}

// ============================================================================
// Tag 9: ExecBuffered (zero-copy execute from ProofBuffer + atomic 100% rent refund)
// ============================================================================
fn ix_exec_buffered(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    ensure(data.len() == 1, AudrenError::InvalidInstruction)?;
    ensure(accounts.len() >= 2, AudrenError::InvalidAccount)?;
    let inner_tag = data[0];
    ensure(
        matches!(
            inner_tag,
            TAG_TRANSFER | TAG_MERGE | TAG_EXEC_VIA_ESCROW | TAG_WITHDRAW
        ),
        AudrenError::InvalidInstruction,
    )?;

    let buf_acc = &accounts[0];
    let inner_accounts = &accounts[1..];
    let payer = &inner_accounts[0];
    ensure(payer.is_signer() && payer.is_writable(), AudrenError::Unauthorized)?;
    ensure(
        buf_acc.owned_by(program_id) && buf_acc.is_writable(),
        AudrenError::InvalidProofBuffer,
    )?;
    for acc in inner_accounts {
        ensure(
            acc.address() != buf_acc.address(),
            AudrenError::InvalidProofBuffer,
        )?;
    }

    {
        let buf = buf_acc.try_borrow()?;
        ensure(
            buf.len() > PROOF_BUFFER_HEADER_LEN
                && buf[BUF_OFF_MAGIC..BUF_OFF_MAGIC + 8] == PROOF_BUFFER_MAGIC
                && buf[BUF_OFF_AUTHORITY..BUF_OFF_AUTHORITY + 32] == *payer.address().as_ref(),
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
            TAG_EXEC_VIA_ESCROW => ix_exec_via_escrow(program_id, inner_accounts, payload)?,
            TAG_WITHDRAW => ix_withdraw(program_id, inner_accounts, payload)?,
            _ => return Err(err(AudrenError::InvalidInstruction)),
        }
    }

    close_proof_buffer_account(*buf_acc, *payer)?;
    Ok(())
}

// ============================================================================
// Tag 10: CloseProofBuffer (reclaim 100% rent from an abandoned ProofBuffer)
// ============================================================================
fn ix_close_proof_buffer(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    ensure(data.is_empty(), AudrenError::InvalidInstruction)?;
    ensure(accounts.len() >= 2, AudrenError::InvalidAccount)?;
    let payer = &accounts[0];
    let buf_acc = &accounts[1];
    ensure(payer.is_signer() && payer.is_writable(), AudrenError::Unauthorized)?;
    ensure(
        buf_acc.owned_by(program_id)
            && buf_acc.is_writable()
            && buf_acc.address() != payer.address(),
        AudrenError::InvalidProofBuffer,
    )?;
    {
        let buf = buf_acc.try_borrow()?;
        ensure(
            buf.len() >= PROOF_BUFFER_HEADER_LEN
                && buf[BUF_OFF_MAGIC..BUF_OFF_MAGIC + 8] == PROOF_BUFFER_MAGIC
                && buf[BUF_OFF_AUTHORITY..BUF_OFF_AUTHORITY + 32] == *payer.address().as_ref(),
            AudrenError::InvalidProofBuffer,
        )?;
    }
    close_proof_buffer_account(*buf_acc, *payer)?;
    Ok(())
}

// ============================================================================
// Tag 11: InitLane (enable parallel append lane 1..15 inside an existing pool)
// ============================================================================
fn ix_init_lane(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    ensure(data.len() == 1, AudrenError::InvalidInstruction)?;
    ensure(accounts.len() >= 6, AudrenError::InvalidAccount)?;

    let authority = &accounts[0];
    let pool_acc = &accounts[1];
    let lane_acc = &accounts[2];
    let mut page0_acc = accounts[3];
    let rent_vault_acc = &accounts[4];
    let sys_prog = &accounts[5];
    ensure(authority.is_signer(), AudrenError::Unauthorized)?;
    ensure(
        authority.is_writable()
            && pool_acc.is_writable()
            && lane_acc.is_writable()
            && page0_acc.is_writable()
            && rent_vault_acc.is_writable()
            && sys_prog.address() == &SYSTEM_ID,
        AudrenError::InvalidAccount,
    )?;

    let lane_id = data[0];
    ensure(
        lane_id >= 1 && lane_id < MAX_APPEND_LANES,
        AudrenError::InvalidLane,
    )?;

    let mut pool = load_pool(pool_acc, program_id)?;
    ensure(
        address_bytes(authority.address()) == pool.authority,
        AudrenError::Unauthorized,
    )?;
    let current_lanes = pool.effective_lane_count();
    ensure(lane_id == current_lanes, AudrenError::InvalidLane)?;

    let pool_le = pool.pool_id.to_le_bytes();
    let (l_addr, l_bump) = lane_pda(program_id, pool.pool_id, lane_id)?;
    ensure(lane_acc.address() == &l_addr, AudrenError::InvalidPda)?;
    let (lr_addr, lr_bump) = lane_rent_pda(program_id, pool.pool_id, lane_id)?;
    ensure(rent_vault_acc.address() == &lr_addr, AudrenError::InvalidPda)?;
    let first_page_id =
        page_id_for_lane(lane_id, 0).ok_or_else(|| err(AudrenError::InvalidLane))?;
    let (pg_addr, pg_bump) = page_pda(program_id, pool.pool_id, first_page_id);
    ensure(page0_acc.address() == &pg_addr, AudrenError::InvalidPda)?;

    let lane_b = [lane_id];
    let l_bump_b = [l_bump];
    let lr_bump_b = [lr_bump];
    let pg_bump_b = [pg_bump];
    let first_page_le = first_page_id.to_le_bytes();

    create_pda(
        authority,
        lane_acc,
        sys_prog,
        &[
            Seed::from(LANE_SEED),
            Seed::from(&pool_le),
            Seed::from(&lane_b),
            Seed::from(&l_bump_b),
        ],
        LANE_STATE_LEN,
        program_id,
    )?;
    create_pda(
        authority,
        rent_vault_acc,
        sys_prog,
        &[
            Seed::from(LANE_RENT_SEED),
            Seed::from(&pool_le),
            Seed::from(&lane_b),
            Seed::from(&lr_bump_b),
        ],
        SENTINEL_ACCOUNT_LEN,
        program_id,
    )?;
    create_pda(
        authority,
        &page0_acc,
        sys_prog,
        &[
            Seed::from(PAGE_SEED),
            Seed::from(&pool_le),
            Seed::from(&first_page_le),
            Seed::from(&pg_bump_b),
        ],
        PAGE_LEN,
        program_id,
    )?;

    let slot = Clock::get()?.slot;
    init_sentinel_bytes(*rent_vault_acc, program_id, PAGE_RENT_MAGIC, lr_bump)?;
    save_lane(
        *lane_acc,
        program_id,
        &AppendLaneState {
            version: PROTOCOL_VERSION,
            lane_id,
            bump: l_bump,
            rent_vault_bump: lr_bump,
            pool_id: pool.pool_id,
            current_page_id: first_page_id,
            created_slot: slot,
        },
    )?;

    {
        let mut pd = page0_acc.try_borrow_mut()?;
        PageHeader {
            version: PROTOCOL_VERSION,
            bump: pg_bump,
            closed: false,
            count: 0,
            pool_id: pool.pool_id,
            page_id: first_page_id,
            created_slot: slot,
            closed_slot: 0,
        }
        .encode(&mut pd)
        .map_err(err)?;
    }

    pool.active_lanes = current_lanes
        .checked_add(1)
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    save_pool(*pool_acc, program_id, &pool)?;
    log_tag("audren:init_lane");
    Ok(())
}

// ============================================================================
// Tag 12: OpenLanePage (permissionless self-funding rollover for parallel lanes 1..15)
// ============================================================================
fn ix_open_lane_page(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    ensure(data.len() == 1, AudrenError::InvalidInstruction)?;
    ensure(accounts.len() >= 7, AudrenError::InvalidAccount)?;

    let payer = &accounts[0];
    let pool_acc = &accounts[1];
    let lane_acc = &accounts[2];
    let mut cur_page_acc = accounts[3];
    let mut next_page_acc = accounts[4];
    let mut rent_vault_acc = accounts[5];
    let sys_prog = &accounts[6];
    ensure(payer.is_signer(), AudrenError::Unauthorized)?;
    ensure(
        payer.is_writable()
            && lane_acc.is_writable()
            && cur_page_acc.is_writable()
            && next_page_acc.is_writable()
            && rent_vault_acc.is_writable()
            && sys_prog.address() == &SYSTEM_ID
            && next_page_acc.owned_by(&SYSTEM_ID)
            && next_page_acc.is_data_empty(),
        AudrenError::InvalidAccount,
    )?;

    let lane_id = data[0];
    ensure(
        lane_id >= 1 && lane_id < MAX_APPEND_LANES,
        AudrenError::InvalidLane,
    )?;

    let pool = load_pool(pool_acc, program_id)?;
    ensure(!pool.paused, AudrenError::PoolPaused)?;
    ensure(
        lane_id < pool.effective_lane_count(),
        AudrenError::InvalidLane,
    )?;
    check_lane_rent_vault(&rent_vault_acc, program_id, pool.pool_id, lane_id)?;

    let mut lane = load_lane(lane_acc, program_id, pool.pool_id, lane_id)?;
    let mut cur_hdr = load_page_header(&cur_page_acc, program_id, pool.pool_id)?;
    ensure(
        cur_hdr.page_id == lane.current_page_id,
        AudrenError::WrongPool,
    )?;
    let remaining = PAGE_CAPACITY.saturating_sub(cur_hdr.count as usize);
    ensure(
        cur_hdr.closed || remaining <= PAGE_ROLLOVER_HEADROOM,
        AudrenError::PageNotReady,
    )?;

    let next_seq = seq_of_page_id(lane.current_page_id)
        .checked_add(1)
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    let next_id = page_id_for_lane(lane_id, next_seq)
        .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
    let (next_addr, next_bump) = page_pda(program_id, pool.pool_id, next_id);
    ensure(next_page_acc.address() == &next_addr, AudrenError::InvalidPda)?;

    let slot = Clock::get()?.slot;
    {
        cur_hdr.closed = true;
        if cur_hdr.closed_slot == 0 {
            cur_hdr.closed_slot = slot;
        }
        let mut cd = cur_page_acc.try_borrow_mut()?;
        cur_hdr.encode(&mut cd).map_err(err)?;
    }

    let min_vault = rent_minimum_balance(SENTINEL_ACCOUNT_LEN)?;
    let page_rent = rent_minimum_balance(PAGE_LEN)?;
    let available = rent_vault_acc.lamports().saturating_sub(min_vault);
    let needed = page_rent.saturating_sub(next_page_acc.lamports());
    let subsidy = available.min(needed);
    let payer_deficit = needed.saturating_sub(subsidy);

    let pool_le = pool.pool_id.to_le_bytes();
    let next_le = next_id.to_le_bytes();
    let bump_b = [next_bump];
    let page_seeds = [
        Seed::from(PAGE_SEED),
        Seed::from(&pool_le),
        Seed::from(&next_le),
        Seed::from(&bump_b),
    ];
    let page_signer = [Signer::from(&page_seeds)];

    if subsidy == 0 && next_page_acc.lamports() == 0 {
        CreateAccount {
            from: payer,
            to: &next_page_acc,
            lamports: payer_deficit,
            space: PAGE_LEN as u64,
            owner: program_id,
        }
        .invoke_signed(&page_signer)?;
    } else {
        if payer_deficit > 0 {
            Transfer {
                from: payer,
                to: &next_page_acc,
                lamports: payer_deficit,
            }
            .invoke()?;
        }
        Allocate {
            account: &next_page_acc,
            space: PAGE_LEN as u64,
        }
        .invoke_signed(&page_signer)?;
        Assign {
            account: &next_page_acc,
            owner: program_id,
        }
        .invoke_signed(&page_signer)?;
    }

    if subsidy > 0 {
        let new_vault = rent_vault_acc
            .lamports()
            .checked_sub(subsidy)
            .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
        let new_page = next_page_acc
            .lamports()
            .checked_add(subsidy)
            .ok_or_else(|| err(AudrenError::ArithmeticOverflow))?;
        rent_vault_acc.set_lamports(new_vault);
        next_page_acc.set_lamports(new_page);
    }

    {
        let mut nd = next_page_acc.try_borrow_mut()?;
        PageHeader {
            version: PROTOCOL_VERSION,
            bump: next_bump,
            closed: false,
            count: 0,
            pool_id: pool.pool_id,
            page_id: next_id,
            created_slot: slot,
            closed_slot: 0,
        }
        .encode(&mut nd)
        .map_err(err)?;
    }

    lane.current_page_id = next_id;
    save_lane(*lane_acc, program_id, &lane)?;
    log_tag("audren:open_lane_page");
    Ok(())
}
