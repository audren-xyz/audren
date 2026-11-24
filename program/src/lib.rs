//! Audren On-Chain Solana Program (Pinocchio `#![no_std]`, sBPFv3).
//!
//! 9 clean instructions (`PROTOCOL_VERSION = 1`):
//!   0: InitPool        — PoolState (128 B) + empty GlobalRootHistory (10,216 B)
//!   1: InitLane        — LaneTreeState + `LaneRentVault` sentinel (16 B) + page 0s (sub0/sr0/memo0/nf0)
//!   2: OpenPage        — Unified, idempotent, sequence-bounded, `LaneRentVault`-subsidized page opener
//!   3: Deposit         — Unified Native SOL (`SyncNative` -> WSOL ATA) & SPL / Token-2022 deposit into canonical `vault_auth` ATA + inline `GlobalRootHistory` update
//!   4: InitRootHistory — Authority-gated one-shot initializer creating `GlobalRootHistory` (10,216 B) from existing active lanes
//!   5: Transact        — Private transfer (shielded `cm2` fees, economy 1-in `nf1==0` or padded) / Public withdraw (incl. atomic WSOL unwrap & pause-exempt full exit) with `GlobalRootHistory` verification & inline update
//!   6: ExecViaEscrow   — SPL / Token-2022 DeFi CPI behind `WatchedEscrowBuf` firewall,
//!                        `router_accounts` bound in `ctx_hash`, Token-2022 TLV checks, XOR-masked 72 B `MemoPage`, and inline `GlobalRootHistory` update
//!   7: SetPaused       — Authority-only pause/unpause (never locks full withdrawals or `OpenPage`)
//!   8: UpdatePool      — Governance parameter updates (`note_rent_fee`, `nf_rent_fee`; `root_epoch_interval` immutable after `InitPool` / `InitRootHistory`) and two-step authority transfer / renounce (`!paused`)

#![no_std]
#![allow(unexpected_cfgs)]

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
extern crate std;

mod poseidon;
mod state;
mod verifier;
mod vk_generated;

use core::mem::MaybeUninit;
use pinocchio::{
    cpi::{invoke_signed, invoke_signed_unchecked, CpiAccount, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    sysvars::{clock::Clock, get_sysvar, rent::RENT_ID, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};

use crate::{
    poseidon::{
        append_leaf_4ary_in_place, compute_note_commitment, compute_public_input_hash,
        ensure_canonical_fr, mask_to_fr_be, poseidon4,
    },
    state::{
        check_owned_and_magic, ensure, err, escrow_pda, expected_ata, is_supported_token_program,
        lane_pda, lane_rent_pda, memo_pda, nf_page_pda, nullifier_pda, pool_pda, read_32, read_u16,
        read_u32, read_u64, roots_pda, subroot_pda, subtree_pda, unwrap_pda, vault_auth_pda,
        AudrenError, ASSET_ID_DOMAIN, ASSET_MODE_PRIVATE, ASSET_MODE_PUBLIC, ATA_PROGRAM_ID,
        CTX_DOMAIN_EXEC_VIA_ESCROW, CTX_DOMAIN_ROUTER_ACCOUNTS, CTX_DOMAIN_TRANSACT,
        DEPOSIT_FLAG_FEE_FROM_AMOUNT, DEPOSIT_FLAG_NATIVE_SOL, DYN_MEMO_HEAD_LEN, DYN_MEMO_MAGIC,
        ELGAMAL_REGISTRY_ID, EPOCH_RING_LEN, ESCROW_SEED, EXEC_FLAG_FEE_ON_OUTPUT,
        GROTH16_PROOF_LEN, LANE_MAGIC, LANE_RENT_MAGIC, LANE_RENT_SEED, LANE_SEED, LANE_STATE_LEN,
        LN_OFF_BUMP, LN_OFF_CURRENT_ROOT, LN_OFF_LANE_ID, LN_OFF_MAGIC, LN_OFF_NEXT_LEAF,
        LN_OFF_NF_COUNT, LN_OFF_POOL_ID, LN_OFF_RENT_BUMP, LN_OFF_VERSION, MAX_CPI_ACCOUNT_ALLOC,
        MAX_ROOT_EPOCH_INTERVAL, MEMO_CT_LEN, MEMO_ENTRY_WIRE_LEN, MEMO_MAGIC, MEMO_NOTES_PER_PAGE,
        MEMO_PAGE_LEN, MEMO_SEED, MM_OFF_BUMP, MM_OFF_CIPHERTEXTS, MM_OFF_CLOSED_SLOT,
        MM_OFF_COUNT, MM_OFF_CREATED_SLOT, MM_OFF_EPHEMERAL_PKS, MM_OFF_LANE_ID, MM_OFF_MAGIC,
        MM_OFF_PAGE_SEQ, MM_OFF_POOL_ID, MM_OFF_VIEW_TAGS, NF_OFF_BUMP, NF_OFF_CLOSED_SLOT,
        NF_OFF_COUNT, NF_OFF_CREATED_SLOT, NF_OFF_LANE_ID, NF_OFF_MAGIC, NF_OFF_PAGE_SEQ,
        NF_OFF_POOL_ID, NF_OFF_PREFIXES, NF_PAGE_LEN, NF_PAGE_MAGIC, NF_PAGE_SEED, NF_PER_PAGE,
        NF_PREFIX_LEN, NULLIFIER_SEED, NUM_ESCROW_SHARDS, NUM_LANES,
        OPEN_PAGE_KIND_MEMO as PAGE_KIND_MEMO, OPEN_PAGE_KIND_NULLIFIER as PAGE_KIND_NF,
        OPEN_PAGE_KIND_SUBROOT as PAGE_KIND_SUBROOT, OPEN_PAGE_KIND_SUBTREE as PAGE_KIND_SUBTREE,
        PL_OFF_ACTIVE_LANES, PL_OFF_AUTHORITY, PL_OFF_BUMP, PL_OFF_MAGIC, PL_OFF_NF_RENT_FEE,
        PL_OFF_NOTE_RENT_FEE, PL_OFF_PAUSED, PL_OFF_PENDING_AUTHORITY, PL_OFF_POOL_ID,
        PL_OFF_RESERVED_24, PL_OFF_ROOT_EPOCH_INTERVAL, PL_OFF_VAULT_AUTH_BUMP, PL_OFF_VERSION,
        POOL_MAGIC, POOL_SEED, POOL_STATE_LEN, PROTOCOL_VERSION, ROOTS_MAGIC, ROOTS_SEED,
        ROOT_ENTRY_LEN, ROOT_HISTORY_LEN, ROOT_RING_EPOCH, ROOT_RING_SLOT, ROOT_SNAPSHOT_LEN,
        RT_OFF_BUMP, RT_OFF_EPOCH_COUNT, RT_OFF_EPOCH_CURSOR, RT_OFF_EPOCH_INTERVAL,
        RT_OFF_EPOCH_RING, RT_OFF_GROUP_ROOTS, RT_OFF_LATEST_LANE_COUNTS, RT_OFF_LATEST_LANE_ROOTS,
        RT_OFF_LATEST_SLOT, RT_OFF_LATEST_SUPER_ROOT, RT_OFF_MAGIC, RT_OFF_POOL_ID,
        RT_OFF_SAME_SLOT_BUMPED, RT_OFF_SLOT_COUNT, RT_OFF_SLOT_CURSOR, RT_OFF_SLOT_RING,
        RT_OFF_STABLE_EPOCH_ID, RT_OFF_STABLE_SLOT, RT_OFF_STABLE_SUPER_ROOT, RT_OFF_VERSION,
        SB_OFF_BUMP, SB_OFF_COUNT, SB_OFF_LANE_ID, SB_OFF_LEAVES, SB_OFF_MAGIC, SB_OFF_PAGE_SEQ,
        SB_OFF_POOL_ID, SENTINEL_LEN, SLOT_RING_LEN, SN_OFF_BUMP, SN_OFF_LANE_ID, SN_OFF_MAGIC,
        SN_OFF_POOL_ID, SPL_TOKEN_ID, SR_OFF_BUMP, SR_OFF_COUNT, SR_OFF_LANE_ID, SR_OFF_MAGIC,
        SR_OFF_POOL_ID, SR_OFF_ROOTS, SR_OFF_ROOT_PAGE_SEQ, SUBROOTS_PER_PAGE, SUBROOT_MAGIC,
        SUBROOT_PAGE_LEN, SUBROOT_SEED, SUBTREE_LEAVES, SUBTREE_MAGIC, SUBTREE_PAGE_LEN,
        SUBTREE_SEED, SYSTEM_PROGRAM_ID, TAG_DEPOSIT, TAG_EXEC_VIA_ESCROW, TAG_INIT_LANE,
        TAG_INIT_POOL, TAG_INIT_ROOT_HISTORY, TAG_OPEN_PAGE, TAG_SET_PAUSED, TAG_TRANSACT,
        TAG_UPDATE_POOL, TOKEN_2022_ID, UNWRAP_SEED, UPDATE_POOL_ACCEPT_AUTHORITY,
        UPDATE_POOL_PARAMS, UPDATE_POOL_PROPOSE_AUTHORITY, UPDATE_POOL_RENOUNCE_AUTHORITY,
        VAULT_AUTH_SEED, WITHDRAW_FLAG_UNWRAP_WSOL, WSOL_MINT, ZERO_HASHES_4ARY,
    },
    verifier::verify_joinsplit_proof_192,
};

#[cfg(not(feature = "no-entrypoint"))]
pinocchio::program_entrypoint!(process, 96);
#[cfg(not(feature = "no-entrypoint"))]
pinocchio::no_allocator!();
#[cfg(not(feature = "no-entrypoint"))]
pinocchio::nostd_panic_handler!();

/// Embedded Neodyme `security.txt` V1 section (zero runtime CU; complements canonical
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

const MAX_ROUTER_CPI_ACCOUNTS: usize = 64;
const MAX_HOOK_CPI_ACCOUNTS: usize = MAX_ROUTER_CPI_ACCOUNTS + 4;
const ZERO_ADDRESS: Address = Address::new_from_array([0u8; 32]);

const SPL_MINT_LEN: usize = 82;
const SPL_ACCOUNT_LEN: usize = 165;
const SPL_MULTISIG_LEN: usize = 355;
const TOKEN_2022_ACCOUNT_TYPE_MINT: u8 = 1;
const TOKEN_2022_ACCOUNT_TYPE_ACCOUNT: u8 = 2;
const TOKEN_2022_EXT_CONFIDENTIAL_TRANSFER_ACCOUNT: u16 = 5;
const TOKEN_2022_EXT_MEMO_TRANSFER: u16 = 8;
const TOKEN_2022_EXT_CPI_GUARD: u16 = 11;
const TOKEN_2022_EXT_TRANSFER_HOOK: u16 = 14;
const TOKEN_IX_CLOSE_ACCOUNT: u8 = 9;
const TOKEN_IX_TRANSFER_CHECKED: u8 = 12;
const TOKEN_IX_SYNC_NATIVE: u8 = 17;
const TOKEN_IX_INITIALIZE_ACCOUNT3: u8 = 18;

fn sha256_v(slices: &[&[u8]]) -> [u8; 32] {
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        let mut out = [0u8; 32];
        unsafe {
            pinocchio::syscalls::sol_sha256(
                slices.as_ptr() as *const u8,
                slices.len() as u64,
                out.as_mut_ptr(),
            );
        }
        out
    }
    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        solana_sha256_hasher::hashv(slices).to_bytes()
    }
}

/// Deterministic canonical `asset_id` derived strictly ON-CHAIN from the 32-byte mint pubkey
/// (`WSOL_MINT` for SOL/WSOL, or any Classic SPL / Token-2022 mint address).
#[inline]
fn derive_asset_id(mint_32: &[u8; 32]) -> [u8; 32] {
    let raw = sha256_v(&[ASSET_ID_DOMAIN, mint_32]);
    mask_to_fr_be(&raw)
}

/// Cached raw `SysvarRent` fields (`lamports_per_byte_year` + raw IEEE-754 `f64` threshold bits).
#[derive(Clone, Copy)]
struct RentParams {
    lamports_per_byte_year: u64,
    threshold_bits: u64,
}

impl RentParams {
    #[inline]
    fn get() -> Result<Self, ProgramError> {
        let mut raw = [0u8; 17];
        get_sysvar(&mut raw, &RENT_ID, 0)?;
        let lamports_per_byte_year = u64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]);
        let threshold_bits = u64::from_le_bytes([
            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
        ]);
        Ok(Self {
            lamports_per_byte_year,
            threshold_bits,
        })
    }

    #[inline]
    fn minimum_balance(self, data_len: usize) -> Result<u64, ProgramError> {
        compute_rent_minimum_balance(self.lamports_per_byte_year, self.threshold_bits, data_len)
    }
}

/// Pure-integer (`u128`) exact IEEE-754 binary64 emulation of Agave's `Rent::minimum_balance`:
/// `((lamports_per_byte_year * (data_len + 128)) as f64 * exemption_threshold) as u64`,
/// supporting arbitrary positive normal/subnormal `exemption_threshold` values (including
/// SIMD-0194 / SIMD-0437 fractional thresholds) with zero floating-point instructions on sBPFv3.
fn compute_rent_minimum_balance(
    lamports_per_byte_year: u64,
    threshold_bits: u64,
    data_len: usize,
) -> Result<u64, ProgramError> {
    const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;

    let sign = threshold_bits >> 63;
    let exp = ((threshold_bits >> 52) & 0x7ff) as i32;
    let frac = threshold_bits & ((1u64 << 52) - 1);

    // Negative non-zero, NaN, or +/-Inf
    let is_zero = exp == 0 && frac == 0;
    if (!is_zero && sign != 0) || exp == 0x7ff {
        return Err(ProgramError::UnsupportedSysvar);
    }

    let data_len_u64 = u64::try_from(data_len).map_err(|_| err(AudrenError::Overflow))?;
    let total_bytes = ACCOUNT_STORAGE_OVERHEAD
        .checked_add(data_len_u64)
        .ok_or_else(|| err(AudrenError::Overflow))?;
    let base = total_bytes
        .checked_mul(lamports_per_byte_year)
        .ok_or_else(|| err(AudrenError::Overflow))?;
    if is_zero || base == 0 {
        return Ok(0);
    }

    // 1. Convert `base: u64` (`1 <= base <= u64::MAX`) to exact IEEE-754 binary64 `(base_m, base_e)`
    //    with `2^52 <= base_m < 2^53` and `(base as f64) == base_m * 2^base_e`.
    let base_bits = 64 - base.leading_zeros();
    let (base_m, base_e): (u128, i32) = if base_bits <= 53 {
        let s = 53 - base_bits;
        ((base as u128) << s, -(s as i32))
    } else {
        let s = base_bits - 53;
        let base_u128 = base as u128;
        let mut q = base_u128 >> s;
        let rem = base_u128 & ((1u128 << s) - 1);
        let half = 1u128 << (s - 1);
        if rem > half || (rem == half && (q & 1) != 0) {
            q += 1;
        }
        if q == (1u128 << 53) {
            (q >> 1, (s as i32) + 1)
        } else {
            (q, s as i32)
        }
    };

    // 2. Normalize `threshold` (normal or subnormal) to `(thresh_m, thresh_e)`
    //    with `2^52 <= thresh_m < 2^53` and `threshold == thresh_m * 2^thresh_e`.
    let (thresh_m, thresh_e): (u128, i32) = if exp == 0 {
        // Subnormal: `frac * 2^-1074` (`1 <= frac < 2^52`)
        let frac_bits = 64 - frac.leading_zeros();
        let s = 53 - frac_bits;
        ((frac as u128) << s, -1074 - (s as i32))
    } else {
        // Normal: `(2^52 + frac) * 2^(exp - 1075)`
        (((1u64 << 52) | frac) as u128, exp - 1075)
    };

    // 3. Exact 53x53 -> 105..106 bit product, rounded to 53-bit binary64 significand
    //    using IEEE-754 round-to-nearest-even.
    let prod = base_m * thresh_m;
    let (mut sig, mut exp_lsb) = if prod >= (1u128 << 105) {
        let q = prod >> 53;
        let rem = prod & ((1u128 << 53) - 1);
        let half = 1u128 << 52;
        let rounded = if rem > half || (rem == half && (q & 1) != 0) {
            q + 1
        } else {
            q
        };
        (rounded, base_e + thresh_e + 53)
    } else {
        let q = prod >> 52;
        let rem = prod & ((1u128 << 52) - 1);
        let half = 1u128 << 51;
        let rounded = if rem > half || (rem == half && (q & 1) != 0) {
            q + 1
        } else {
            q
        };
        (rounded, base_e + thresh_e + 52)
    };

    if sig == (1u128 << 53) {
        sig >>= 1;
        exp_lsb += 1;
    }

    // 4. Truncate toward zero (`as u64`): `sig * 2^exp_lsb in [2^(exp_lsb + 52), 2^(exp_lsb + 53))`.
    if exp_lsb < -52 {
        Ok(0)
    } else if exp_lsb >= 12 {
        Err(err(AudrenError::Overflow))
    } else if exp_lsb >= 0 {
        Ok((sig as u64) << (exp_lsb as u32))
    } else {
        Ok((sig as u64) >> ((-exp_lsb) as u32))
    }
}

/// Create a PDA safely using pre-fetched `RentParams` (even if an attacker pre-funded lamports
/// to it — immune to 1-lamport DoS) and clamp to at least `1` lamport so no Audren PDA can ever
/// be reaped on a zero-rent cluster.
#[inline(never)]
fn create_pda_safe_with_rent<'a>(
    payer: &'a AccountView,
    pda: &'a AccountView,
    sys_prog: &'a AccountView,
    space: usize,
    program_id: &Address,
    seeds: &[Seed<'_>],
    rent: RentParams,
) -> ProgramResult {
    ensure(
        space <= MAX_CPI_ACCOUNT_ALLOC
            && sys_prog.address() == &SYSTEM_PROGRAM_ID
            && pda.owned_by(&SYSTEM_PROGRAM_ID)
            && pda.is_data_empty(),
        AudrenError::InvalidAccount,
    )?;
    let required = rent.minimum_balance(space)?.max(1);
    if pda.lamports() == 0 {
        let signer = Signer::from(seeds);
        CreateAccount {
            from: payer,
            to: pda,
            lamports: required,
            space: space as u64,
            owner: program_id,
        }
        .invoke_signed(&[signer])
    } else {
        let deficit = required.saturating_sub(pda.lamports());
        if deficit > 0 {
            Transfer {
                from: payer,
                to: pda,
                lamports: deficit,
            }
            .invoke()?;
        }
        if space > 0 {
            let s1 = Signer::from(seeds);
            Allocate {
                account: pda,
                space: space as u64,
            }
            .invoke_signed(&[s1])?;
        }
        let s2 = Signer::from(seeds);
        Assign {
            account: pda,
            owner: program_id,
        }
        .invoke_signed(&[s2])
    }
}

/// Create a PDA safely, fetching live `SysvarRent` once via `RentParams::get()`.
#[inline]
fn create_pda_safe<'a>(
    payer: &'a AccountView,
    pda: &'a AccountView,
    sys_prog: &'a AccountView,
    space: usize,
    program_id: &Address,
    seeds: &[Seed<'_>],
) -> ProgramResult {
    create_pda_safe_with_rent(payer, pda, sys_prog, space, program_id, seeds, RentParams::get()?)
}

// =============================================================================
// Disjoint 32 KiB SBF Heap Arenas (`no_allocator!()`, zero stack bloat)
//   [ 0 ..  8 KiB): WatchedEscrowBuf (`2,312 B`)
//   [ 8 .. 12 KiB): RouterAccsHashBuf (`2,112 B`)
//   [16 .. 20 KiB): InstructionAccount metas (`<= 4 KiB`)
//   [20 .. 32 KiB): CpiAccount views (`<= 12 KiB`)
// =============================================================================

#[derive(Clone, Copy)]
struct WatchedEscrowSnap {
    idx: u8,
    data_len: u16,
    token_program: Address,
}

struct WatchedEscrowBuf {
    len: usize,
    entries: [WatchedEscrowSnap; MAX_ROUTER_CPI_ACCOUNTS],
}

impl WatchedEscrowBuf {
    #[inline(never)]
    fn with_buf<R>(f: impl FnOnce(&mut Self) -> R) -> R {
        #[cfg(any(target_os = "solana", target_arch = "bpf"))]
        {
            const HEAP_WATCH_OFFSET: usize = 0;
            const _: () = assert!(core::mem::size_of::<WatchedEscrowBuf>() <= 8 * 1024);
            const _: () = assert!(HEAP_WATCH_OFFSET % core::mem::align_of::<WatchedEscrowBuf>() == 0);
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
            let mut buf = unsafe {
                core::ptr::write_bytes(raw.as_mut_ptr(), 0, 1);
                raw.assume_init()
            };
            f(&mut buf)
        }
    }

    #[inline(always)]
    fn push(&mut self, idx: usize, token_program: Address, data_len: u16) {
        if self.len < MAX_ROUTER_CPI_ACCOUNTS {
            self.entries[self.len] = WatchedEscrowSnap {
                idx: idx as u8,
                data_len,
                token_program,
            };
            self.len += 1;
        }
    }

    #[inline(always)]
    fn as_slice(&self) -> &[WatchedEscrowSnap] {
        &self.entries[..self.len]
    }
}

/// Hash EVERY router account `(pubkey[32] || is_writable[1])` + count in a single `sol_sha256` call
/// backed by disjoint SBF heap `[8 KiB .. 12 KiB)`. Prevents relayer pool/account substitution!
#[inline(never)]
fn hash_router_accounts_arena(router_accounts: &[AccountView]) -> Result<[u8; 32], ProgramError> {
    let n = router_accounts.len();
    ensure(n > 0 && n <= MAX_ROUTER_CPI_ACCOUNTS, AudrenError::InvalidAccount)?;
    let total_len = n * 33;
    let n_le = (n as u16).to_le_bytes();

    let run = |buf: &mut [u8; MAX_ROUTER_CPI_ACCOUNTS * 33]| -> [u8; 32] {
        for (i, acc) in router_accounts.iter().enumerate() {
            let off = i * 33;
            buf[off..off + 32].copy_from_slice(acc.address().as_ref());
            buf[off + 32] = u8::from(acc.is_writable());
        }
        sha256_v(&[CTX_DOMAIN_ROUTER_ACCOUNTS, &n_le, &buf[..total_len]])
    };

    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        const HEAP_HASH_OFFSET: usize = 8 * 1024;
        const _: () = assert!(MAX_ROUTER_CPI_ACCOUNTS * 33 <= 4 * 1024);
        let buf = unsafe {
            &mut *((pinocchio::entrypoint::HEAP_START_ADDRESS as usize + HEAP_HASH_OFFSET)
                as *mut [u8; MAX_ROUTER_CPI_ACCOUNTS * 33])
        };
        Ok(run(buf))
    }
    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        let mut buf = [0u8; MAX_ROUTER_CPI_ACCOUNTS * 33];
        Ok(run(&mut buf))
    }
}

/// Zero-alloc CPI launcher in Solana's 32 KiB SBF heap (`[16 KiB .. 32 KiB)`) supporting up to
/// `MAX_ROUTER_CPI_ACCOUNTS = 64` router accounts with zero dynamic allocation and tiny stack usage.
/// ONLY `expected_escrow` is granted signer privilege; `payer` is NEVER forwarded as a signer.
#[inline(never)]
fn invoke_router_cpi_arena<'account>(
    target_prog: &Address,
    router_data: &[u8],
    router_accounts: &'account [AccountView],
    expected_escrow: &Address,
    signers: &[Signer],
) -> ProgramResult {
    let n = router_accounts.len();
    ensure(n > 0 && n <= MAX_ROUTER_CPI_ACCOUNTS, AudrenError::InvalidAccount)?;

    let run = |metas: &mut [MaybeUninit<InstructionAccount<'account>>; MAX_ROUTER_CPI_ACCOUNTS],
               cpi_buf: &mut [MaybeUninit<CpiAccount<'account>>; MAX_ROUTER_CPI_ACCOUNTS]|
     -> ProgramResult {
        for (i, acc) in router_accounts.iter().enumerate() {
            let is_signer = acc.address() == expected_escrow;
            metas[i].write(InstructionAccount::new(acc.address(), acc.is_writable(), is_signer));
            if acc.is_writable() {
                acc.check_borrow_mut()?;
            } else {
                acc.check_borrow()?;
            }
            CpiAccount::init_from_account_view(acc, &mut cpi_buf[i]);
        }
        unsafe {
            let meta_slice =
                core::slice::from_raw_parts(metas.as_ptr() as *const InstructionAccount<'account>, n);
            let cpi_slice =
                core::slice::from_raw_parts(cpi_buf.as_ptr() as *const CpiAccount<'account>, n);
            let ix = InstructionView {
                program_id: target_prog,
                accounts: meta_slice,
                data: router_data,
            };
            invoke_signed_unchecked(&ix, cpi_slice, signers);
        }
        Ok(())
    };

    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        const HEAP_METAS_OFFSET: usize = 16 * 1024;
        const HEAP_CPI_OFFSET: usize = 20 * 1024;
        const _: () = assert!(
            core::mem::size_of::<[MaybeUninit<InstructionAccount<'static>>; MAX_ROUTER_CPI_ACCOUNTS]>()
                <= 4 * 1024
        );
        const _: () = assert!(
            core::mem::size_of::<[MaybeUninit<CpiAccount<'static>>; MAX_ROUTER_CPI_ACCOUNTS]>()
                <= 12 * 1024
        );
        const _: () = assert!(HEAP_METAS_OFFSET % core::mem::align_of::<InstructionAccount<'static>>() == 0);
        const _: () = assert!(HEAP_CPI_OFFSET % core::mem::align_of::<CpiAccount<'static>>() == 0);
        let metas = unsafe {
            &mut *((pinocchio::entrypoint::HEAP_START_ADDRESS as usize + HEAP_METAS_OFFSET)
                as *mut [MaybeUninit<InstructionAccount<'account>>; MAX_ROUTER_CPI_ACCOUNTS])
        };
        let cpi_buf = unsafe {
            &mut *((pinocchio::entrypoint::HEAP_START_ADDRESS as usize + HEAP_CPI_OFFSET)
                as *mut [MaybeUninit<CpiAccount<'account>>; MAX_ROUTER_CPI_ACCOUNTS])
        };
        run(metas, cpi_buf)
    }
    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        let mut metas = [const { MaybeUninit::<InstructionAccount<'account>>::uninit() }; MAX_ROUTER_CPI_ACCOUNTS];
        let mut cpi_buf = [const { MaybeUninit::<CpiAccount<'account>>::uninit() }; MAX_ROUTER_CPI_ACCOUNTS];
        run(&mut metas, &mut cpi_buf)
    }
}

// =============================================================================
// Classic SPL Token & Token-2022 TLV Verification + TransferHook-Safe CPI
// =============================================================================

#[derive(Clone, Copy)]
struct MintInfo {
    decimals: u8,
    has_active_hook: bool,
}

fn load_mint_info(mint: &AccountView, token_program: &Address) -> Result<MintInfo, ProgramError> {
    ensure(
        is_supported_token_program(token_program) && mint.owned_by(token_program),
        AudrenError::InvalidTokenAccount,
    )?;
    let md = mint.try_borrow()?;
    let len = md.len();
    let valid_len = len == SPL_MINT_LEN
        || (token_program == &TOKEN_2022_ID
            && len > SPL_ACCOUNT_LEN
            && len != SPL_MULTISIG_LEN
            && md[SPL_ACCOUNT_LEN] == TOKEN_2022_ACCOUNT_TYPE_MINT);
    ensure(valid_len && md[45] == 1, AudrenError::InvalidTokenAccount)?;
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
                return Err(err(AudrenError::InvalidTokenAccount));
            }
            if ext_type == TOKEN_2022_EXT_TRANSFER_HOOK {
                ensure(ext_len >= 64, AudrenError::InvalidTokenAccount)?;
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

struct TokenSecuritySnapshot {
    token_program: Address,
    mint: Address,
    owner: Address,
    amount: u64,
    is_frozen: bool,
    has_delegate: bool,
    close_authority: Option<Address>,
    data_len: u16,
    has_restrictive_ext: bool,
}

#[inline]
fn parse_token_account_security(
    owner_prog: &Address,
    data: &[u8],
) -> Option<TokenSecuritySnapshot> {
    if !is_supported_token_program(owner_prog) {
        return None;
    }
    let len = data.len();
    let valid = (len == SPL_ACCOUNT_LEN
        || (owner_prog == &TOKEN_2022_ID
            && len > SPL_ACCOUNT_LEN
            && len != SPL_MULTISIG_LEN
            && data[SPL_ACCOUNT_LEN] == TOKEN_2022_ACCOUNT_TYPE_ACCOUNT))
        && (data[108] == 1 || data[108] == 2);
    if !valid {
        return None;
    }
    let is_frozen = data[108] == 2;
    let data_len = u16::try_from(len).ok()?;
    let mint_bytes: [u8; 32] = data[0..32].try_into().ok()?;
    let owner_bytes: [u8; 32] = data[32..64].try_into().ok()?;
    let amount = read_u64(data, 64);
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
    let mut has_restrictive_ext = false;
    if owner_prog == &TOKEN_2022_ID && len > SPL_ACCOUNT_LEN + 1 {
        let tlv = &data[SPL_ACCOUNT_LEN + 1..];
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
                has_restrictive_ext = true;
                break;
            }
            if ext_type == TOKEN_2022_EXT_CONFIDENTIAL_TRANSFER_ACCOUNT
                || ((ext_type == TOKEN_2022_EXT_MEMO_TRANSFER
                    || ext_type == TOKEN_2022_EXT_CPI_GUARD)
                    && (ext_len < 1 || tlv[val_start] != 0))
            {
                has_restrictive_ext = true;
                break;
            }
            pos = val_end;
        }
    }
    Some(TokenSecuritySnapshot {
        token_program: *owner_prog,
        mint: Address::new_from_array(mint_bytes),
        owner: Address::new_from_array(owner_bytes),
        amount,
        is_frozen,
        has_delegate,
        close_authority,
        data_len,
        has_restrictive_ext,
    })
}

fn token_account_security(account: &AccountView) -> Option<TokenSecuritySnapshot> {
    let owner_prog = account.owner();
    if !is_supported_token_program(owner_prog) {
        return None;
    }
    let data = account.try_borrow().ok()?;
    parse_token_account_security(owner_prog, &data)
}

/// Validate SPL Token / Token-2022 custody account invariants (`mint`, `owner`, `Initialized`
/// state — not `Uninitialized` or `Frozen` — and when `strict_custody == true`, forbids
/// delegates, close authorities, `ConfidentialTransferAccount`, and active
/// `MemoTransfer` / `CpiGuard` extensions).
fn validate_token_account(
    acc: &AccountView,
    token_prog: &Address,
    expected_mint: &Address,
    expected_owner: &Address,
    strict_custody: bool,
) -> Result<u64, ProgramError> {
    let snap = token_account_security(acc).ok_or_else(|| err(AudrenError::InvalidTokenAccount))?;
    ensure(
        &snap.token_program == token_prog
            && &snap.mint == expected_mint
            && &snap.owner == expected_owner
            && !snap.is_frozen,
        AudrenError::InvalidTokenAccount,
    )?;
    if strict_custody {
        ensure(
            !snap.has_delegate && snap.close_authority.is_none() && !snap.has_restrictive_ext,
            AudrenError::InvalidTokenAccount,
        )?;
    }
    Ok(snap.amount)
}

/// Enforce canonical ATA derivation (`expected_ata(expected_owner, token_prog, expected_mint)`)
/// in addition to all strict custody invariants (owner, mint, initialized, no delegate, no
/// `close_authority`, no restrictive Token-2022 TLV extensions).
fn validate_canonical_ata(
    acc: &AccountView,
    token_prog: &Address,
    expected_mint: &Address,
    expected_owner: &Address,
) -> Result<u64, ProgramError> {
    ensure(
        acc.address() == &expected_ata(expected_owner, token_prog, expected_mint),
        AudrenError::InvalidTokenAccount,
    )?;
    validate_token_account(acc, token_prog, expected_mint, expected_owner, true)
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn invoke_token_transfer_checked_with_hook<'a>(
    program_id: &Address,
    vault_auth_key: &Address,
    token_prog: &'a AccountView,
    source: &'a AccountView,
    mint: &'a AccountView,
    dest: &'a AccountView,
    authority: &'a AccountView,
    ix_data: &[u8; 10],
    hook_candidates: &'a [AccountView],
    blocked_keys: &[&Address],
    signers: &[Signer],
) -> ProgramResult {
    let run = |metas: &mut [MaybeUninit<InstructionAccount<'a>>; MAX_HOOK_CPI_ACCOUNTS],
               cpi_buf: &mut [MaybeUninit<CpiAccount<'a>>; MAX_HOOK_CPI_ACCOUNTS]|
     -> ProgramResult {
        let base_views = [source, mint, dest, authority];
        metas[0].write(InstructionAccount::writable(source.address()));
        metas[1].write(InstructionAccount::readonly(mint.address()));
        metas[2].write(InstructionAccount::writable(dest.address()));
        metas[3].write(InstructionAccount::readonly_signer(authority.address()));
        for (i, av) in base_views.iter().enumerate() {
            if i == 0 || i == 2 {
                av.check_borrow_mut()?;
            } else {
                av.check_borrow()?;
            }
            CpiAccount::init_from_account_view(av, &mut cpi_buf[i]);
        }
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
            if blocked_keys.contains(&key) {
                continue;
            }
            if let Some(snap) = token_account_security(acc) {
                if &snap.owner == vault_auth_key {
                    continue;
                }
            }
            let dup = (0..n).any(|i| unsafe { metas[i].assume_init_ref().address } == key);
            if dup {
                continue;
            }
            ensure(n < MAX_HOOK_CPI_ACCOUNTS, AudrenError::InvalidAccount)?;
            // Never forward `is_signer` to untrusted TransferHook trailing accounts!
            metas[n].write(InstructionAccount::new(key, acc.is_writable(), false));
            if acc.is_writable() {
                acc.check_borrow_mut()?;
            } else {
                acc.check_borrow()?;
            }
            CpiAccount::init_from_account_view(acc, &mut cpi_buf[n]);
            n += 1;
        }

        unsafe {
            let meta_slice =
                core::slice::from_raw_parts(metas.as_ptr() as *const InstructionAccount<'a>, n);
            let cpi_slice =
                core::slice::from_raw_parts(cpi_buf.as_ptr() as *const CpiAccount<'a>, n);
            let ix = InstructionView {
                program_id: token_prog.address(),
                accounts: meta_slice,
                data: ix_data,
            };
            invoke_signed_unchecked(&ix, cpi_slice, signers);
        }
        Ok(())
    };

    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    {
        const HEAP_METAS_OFFSET: usize = 16 * 1024;
        const HEAP_CPI_OFFSET: usize = 20 * 1024;
        const _: () = assert!(
            core::mem::size_of::<[MaybeUninit<InstructionAccount<'static>>; MAX_HOOK_CPI_ACCOUNTS]>()
                <= 4 * 1024
        );
        const _: () = assert!(
            core::mem::size_of::<[MaybeUninit<CpiAccount<'static>>; MAX_HOOK_CPI_ACCOUNTS]>()
                <= 12 * 1024
        );
        let metas = unsafe {
            &mut *((pinocchio::entrypoint::HEAP_START_ADDRESS as usize + HEAP_METAS_OFFSET)
                as *mut [MaybeUninit<InstructionAccount<'a>>; MAX_HOOK_CPI_ACCOUNTS])
        };
        let cpi_buf = unsafe {
            &mut *((pinocchio::entrypoint::HEAP_START_ADDRESS as usize + HEAP_CPI_OFFSET)
                as *mut [MaybeUninit<CpiAccount<'a>>; MAX_HOOK_CPI_ACCOUNTS])
        };
        run(metas, cpi_buf)
    }
    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    {
        let mut metas = [const { MaybeUninit::<InstructionAccount<'a>>::uninit() }; MAX_HOOK_CPI_ACCOUNTS];
        let mut cpi_buf = [const { MaybeUninit::<CpiAccount<'a>>::uninit() }; MAX_HOOK_CPI_ACCOUNTS];
        run(&mut metas, &mut cpi_buf)
    }
}

#[allow(clippy::too_many_arguments)]
fn invoke_token_transfer_checked<'a>(
    program_id: &Address,
    vault_auth_key: &Address,
    token_prog: &'a AccountView,
    source: &'a AccountView,
    mint: &'a AccountView,
    dest: &'a AccountView,
    authority: &'a AccountView,
    amount: u64,
    mint_info: MintInfo,
    hook_candidates: &'a [AccountView],
    blocked_keys: &[&Address],
    signers: &[Signer],
) -> ProgramResult {
    let mut ix_data = [0u8; 10];
    ix_data[0] = TOKEN_IX_TRANSFER_CHECKED;
    ix_data[1..9].copy_from_slice(&amount.to_le_bytes());
    ix_data[9] = mint_info.decimals;

    if !mint_info.has_active_hook {
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
        invoke_signed(&ix, &[source, mint, dest, authority], signers)
    } else {
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
}

// =============================================================================
// Account PDA Verifiers & Self-Balancing `LaneRentVault` Amortization
// =============================================================================

struct PoolConfig {
    paused: bool,
    active_lanes: u8,
    authority: Address,
    pending_authority: Address,
    vault_auth_bump: u8,
    note_rent_fee: u64,
    nf_rent_fee: u64,
}

fn load_and_verify_pool(
    program_id: &Address,
    pool_id: u32,
    pool_acc: &AccountView,
) -> Result<PoolConfig, ProgramError> {
    check_owned_and_magic(pool_acc, program_id, POOL_STATE_LEN, &POOL_MAGIC)?;
    let pd = pool_acc.try_borrow()?;
    ensure(read_u32(&pd, PL_OFF_POOL_ID) == pool_id, AudrenError::InvalidAccount)?;
    let pool_le = pool_id.to_le_bytes();
    let pb = pd[PL_OFF_BUMP];
    let exp = Address::create_program_address(&[POOL_SEED, &pool_le, &[pb]], program_id)
        .map_err(|_| err(AudrenError::InvalidPda))?;
    ensure(pool_acc.address() == &exp, AudrenError::InvalidPda)?;
    Ok(PoolConfig {
        paused: pd[PL_OFF_PAUSED] != 0,
        active_lanes: pd[PL_OFF_ACTIVE_LANES],
        authority: Address::new_from_array(read_32(&pd, PL_OFF_AUTHORITY)),
        pending_authority: Address::new_from_array(read_32(&pd, PL_OFF_PENDING_AUTHORITY)),
        vault_auth_bump: pd[PL_OFF_VAULT_AUTH_BUMP],
        note_rent_fee: read_u64(&pd, PL_OFF_NOTE_RENT_FEE),
        nf_rent_fee: read_u64(&pd, PL_OFF_NF_RENT_FEE),
    })
}

fn verify_lane_pda(
    program_id: &Address,
    pool_id: u32,
    lane_id: u8,
    lane_acc: &AccountView,
) -> Result<u8, ProgramError> {
    check_owned_and_magic(lane_acc, program_id, LANE_STATE_LEN, &LANE_MAGIC)?;
    let ld = lane_acc.try_borrow()?;
    ensure(
        ld[LN_OFF_LANE_ID] == lane_id && read_u32(&ld, LN_OFF_POOL_ID) == pool_id,
        AudrenError::InvalidLane,
    )?;
    let pool_le = pool_id.to_le_bytes();
    let lb = ld[LN_OFF_BUMP];
    let rent_bump = ld[LN_OFF_RENT_BUMP];
    let exp = Address::create_program_address(&[LANE_SEED, &pool_le, &[lane_id], &[lb]], program_id)
        .map_err(|_| err(AudrenError::InvalidPda))?;
    ensure(lane_acc.address() == &exp, AudrenError::InvalidPda)?;
    Ok(rent_bump)
}

fn verify_lane_rent_vault(
    program_id: &Address,
    pool_id: u32,
    lane_id: u8,
    rent_bump: u8,
    lane_rent_vault: &AccountView,
) -> ProgramResult {
    check_owned_and_magic(lane_rent_vault, program_id, SENTINEL_LEN, &LANE_RENT_MAGIC)?;
    let rd = lane_rent_vault.try_borrow()?;
    ensure(
        read_u32(&rd, SN_OFF_POOL_ID) == pool_id
            && rd[SN_OFF_LANE_ID] == lane_id
            && rd[SN_OFF_BUMP] == rent_bump,
        AudrenError::InvalidPda,
    )?;
    let pool_le = pool_id.to_le_bytes();
    let exp = Address::create_program_address(
        &[LANE_RENT_SEED, &pool_le, &[lane_id], &[rent_bump]],
        program_id,
    )
    .map_err(|_| err(AudrenError::InvalidPda))?;
    ensure(lane_rent_vault.address() == &exp, AudrenError::InvalidPda)
}

#[inline(always)]
fn slice_32(b: &[u8], off: usize) -> &[u8; 32] {
    b[off..off + 32].try_into().unwrap()
}

fn verify_roots_pda(
    program_id: &Address,
    pool_id: u32,
    roots_acc: &AccountView,
) -> ProgramResult {
    ensure(roots_acc.owned_by(program_id), AudrenError::RootHistoryMismatch)?;
    let rd = roots_acc.try_borrow()?;
    ensure(
        rd.len() == ROOT_HISTORY_LEN
            && rd[RT_OFF_MAGIC..RT_OFF_MAGIC + 8] == ROOTS_MAGIC
            && read_u32(&rd, RT_OFF_POOL_ID) == pool_id,
        AudrenError::RootHistoryMismatch,
    )?;
    let pool_le = pool_id.to_le_bytes();
    let rb = rd[RT_OFF_BUMP];
    let exp = Address::create_program_address(&[ROOTS_SEED, &pool_le, &[rb]], program_id)
        .map_err(|_| err(AudrenError::InvalidPda))?;
    ensure(roots_acc.address() == &exp, AudrenError::InvalidPda)
}

/// Zero-copy in-place initializer for `GlobalRootHistory` (`10,216 B`).
/// Used by both `InitPool` (`lanes = &[]`, 0 Poseidon calls) and one-shot `InitRootHistory`
/// (`lanes = lane_0..lane_{active-1}`, reading live lane roots directly into `roots_acc`).
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn init_root_history_account(
    program_id: &Address,
    pool_id: u32,
    root_epoch_interval: u64,
    now: u64,
    payer: &AccountView,
    roots_acc: &mut AccountView,
    sys_prog: &AccountView,
    lanes: &[AccountView],
    rent: RentParams,
) -> ProgramResult {
    ensure(
        (1..=MAX_ROOT_EPOCH_INTERVAL).contains(&root_epoch_interval),
        AudrenError::InvalidInstruction,
    )?;
    let active = lanes.len();
    ensure(active <= NUM_LANES, AudrenError::InvalidLane)?;
    for (i, lane_acc) in lanes.iter().enumerate() {
        let _ = verify_lane_pda(program_id, pool_id, i as u8, lane_acc)?;
    }

    let (exp_roots, roots_bump) = roots_pda(program_id, pool_id);
    ensure(roots_acc.address() == &exp_roots, AudrenError::InvalidPda)?;
    ensure(roots_acc.is_writable(), AudrenError::InvalidAccount)?;

    let pool_le = pool_id.to_le_bytes();
    let rb = [roots_bump];
    create_pda_safe_with_rent(
        payer,
        roots_acc,
        sys_prog,
        ROOT_HISTORY_LEN,
        program_id,
        &[Seed::from(ROOTS_SEED), Seed::from(&pool_le), Seed::from(&rb)],
        rent,
    )?;

    let mut rd = roots_acc.try_borrow_mut()?;
    let stable_epoch_id = now / root_epoch_interval;
    rd[RT_OFF_MAGIC..RT_OFF_MAGIC + 8].copy_from_slice(&ROOTS_MAGIC);
    rd[RT_OFF_VERSION] = PROTOCOL_VERSION;
    rd[RT_OFF_BUMP] = roots_bump;
    rd[RT_OFF_SLOT_CURSOR..RT_OFF_SLOT_CURSOR + 2].copy_from_slice(&0u16.to_le_bytes());
    rd[RT_OFF_POOL_ID..RT_OFF_POOL_ID + 4].copy_from_slice(&pool_le);
    rd[RT_OFF_EPOCH_CURSOR..RT_OFF_EPOCH_CURSOR + 2].copy_from_slice(&0u16.to_le_bytes());
    rd[RT_OFF_SLOT_COUNT..RT_OFF_SLOT_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
    rd[RT_OFF_EPOCH_COUNT..RT_OFF_EPOCH_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
    rd[RT_OFF_SAME_SLOT_BUMPED] = 0;
    rd[RT_OFF_LATEST_SLOT..RT_OFF_LATEST_SLOT + 8].copy_from_slice(&now.to_le_bytes());
    rd[RT_OFF_STABLE_EPOCH_ID..RT_OFF_STABLE_EPOCH_ID + 8]
        .copy_from_slice(&stable_epoch_id.to_le_bytes());
    rd[RT_OFF_STABLE_SLOT..RT_OFF_STABLE_SLOT + 8].copy_from_slice(&now.to_le_bytes());
    rd[RT_OFF_EPOCH_INTERVAL..RT_OFF_EPOCH_INTERVAL + 8]
        .copy_from_slice(&root_epoch_interval.to_le_bytes());

    for (i, lane_acc) in lanes.iter().enumerate() {
        let r_off = RT_OFF_LATEST_LANE_ROOTS + i * 32;
        let c_off = RT_OFF_LATEST_LANE_COUNTS + i * 8;
        let ld = lane_acc.try_borrow()?;
        rd[r_off..r_off + 32].copy_from_slice(&ld[LN_OFF_CURRENT_ROOT..LN_OFF_CURRENT_ROOT + 32]);
        rd[c_off..c_off + 8].copy_from_slice(&ld[LN_OFF_NEXT_LEAF..LN_OFF_NEXT_LEAF + 8]);
    }
    for i in active..NUM_LANES {
        let r_off = RT_OFF_LATEST_LANE_ROOTS + i * 32;
        let c_off = RT_OFF_LATEST_LANE_COUNTS + i * 8;
        rd[r_off..r_off + 32].copy_from_slice(&ZERO_HASHES_4ARY[18]);
        rd[c_off..c_off + 8].fill(0);
    }

    if active == 0 {
        for g in 0..4 {
            let g_off = RT_OFF_GROUP_ROOTS + g * 32;
            rd[g_off..g_off + 32].copy_from_slice(&ZERO_HASHES_4ARY[19]);
        }
        rd[RT_OFF_LATEST_SUPER_ROOT..RT_OFF_LATEST_SUPER_ROOT + 32]
            .copy_from_slice(&ZERO_HASHES_4ARY[20]);
    } else {
        for g in 0..4 {
            let g_off = RT_OFF_GROUP_ROOTS + g * 32;
            if g * 4 < active {
                let base = RT_OFF_LATEST_LANE_ROOTS + g * 4 * 32;
                let gr = poseidon4(
                    slice_32(&rd, base),
                    slice_32(&rd, base + 32),
                    slice_32(&rd, base + 64),
                    slice_32(&rd, base + 96),
                )?;
                rd[g_off..g_off + 32].copy_from_slice(&gr);
            } else {
                rd[g_off..g_off + 32].copy_from_slice(&ZERO_HASHES_4ARY[19]);
            }
        }
        let sr = poseidon4(
            slice_32(&rd, RT_OFF_GROUP_ROOTS),
            slice_32(&rd, RT_OFF_GROUP_ROOTS + 32),
            slice_32(&rd, RT_OFF_GROUP_ROOTS + 64),
            slice_32(&rd, RT_OFF_GROUP_ROOTS + 96),
        )?;
        rd[RT_OFF_LATEST_SUPER_ROOT..RT_OFF_LATEST_SUPER_ROOT + 32].copy_from_slice(&sr);
    }

    rd.copy_within(
        RT_OFF_LATEST_SUPER_ROOT..RT_OFF_LATEST_SUPER_ROOT + ROOT_SNAPSHOT_LEN,
        RT_OFF_STABLE_SUPER_ROOT,
    );
    rd.copy_within(
        RT_OFF_LATEST_SUPER_ROOT..RT_OFF_LATEST_SUPER_ROOT + 32,
        RT_OFF_SLOT_RING,
    );
    rd[RT_OFF_SLOT_RING + 32..RT_OFF_SLOT_RING + ROOT_ENTRY_LEN]
        .copy_from_slice(&now.to_le_bytes());
    rd.copy_within(
        RT_OFF_LATEST_SUPER_ROOT..RT_OFF_LATEST_SUPER_ROOT + 32,
        RT_OFF_EPOCH_RING,
    );
    rd[RT_OFF_EPOCH_RING + 32..RT_OFF_EPOCH_RING + ROOT_ENTRY_LEN]
        .copy_from_slice(&now.to_le_bytes());
    Ok(())
}

/// Zero-copy `GlobalRootHistory` verifier and root loader (no wall-clock expiry).
#[inline(never)]
fn verify_and_load_global_root(
    program_id: &Address,
    pool_id: u32,
    roots_acc: &AccountView,
    root_ring_kind: u8,
    root_ring_idx: u8,
) -> Result<[u8; 32], ProgramError> {
    verify_roots_pda(program_id, pool_id, roots_acc)?;
    let rd = roots_acc.try_borrow()?;
    let idx = root_ring_idx as usize;
    let entry_off = match root_ring_kind {
        ROOT_RING_SLOT => {
            let slot_count = read_u16(&rd, RT_OFF_SLOT_COUNT) as usize;
            ensure(
                (1..=SLOT_RING_LEN).contains(&slot_count),
                AudrenError::RootHistoryMismatch,
            )?;
            ensure(idx < slot_count, AudrenError::RootIndexOutOfBounds)?;
            RT_OFF_SLOT_RING + idx * ROOT_ENTRY_LEN
        }
        ROOT_RING_EPOCH => {
            let epoch_count = read_u16(&rd, RT_OFF_EPOCH_COUNT) as usize;
            ensure(
                (1..=EPOCH_RING_LEN).contains(&epoch_count),
                AudrenError::RootHistoryMismatch,
            )?;
            ensure(idx < epoch_count, AudrenError::RootIndexOutOfBounds)?;
            RT_OFF_EPOCH_RING + idx * ROOT_ENTRY_LEN
        }
        _ => return Err(err(AudrenError::InvalidRootRing)),
    };
    let super_root = read_32(&rd, entry_off);
    ensure(super_root != [0u8; 32], AudrenError::RootIndexOutOfBounds)?;
    Ok(super_root)
}

/// Zero-copy incremental `GlobalRootHistory` updater (2x `sol_poseidon(4)` regardless of lane count).
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn update_global_root_history(
    program_id: &Address,
    pool_id: u32,
    roots_acc: &mut AccountView,
    lane_id: u8,
    new_lane_root: &[u8; 32],
    new_next_leaf: u64,
    now: u64,
    verified_slot_ring_idx: Option<u8>,
) -> ProgramResult {
    ensure((lane_id as usize) < NUM_LANES, AudrenError::InvalidLane)?;
    ensure(roots_acc.is_writable(), AudrenError::InvalidAccount)?;
    verify_roots_pda(program_id, pool_id, roots_acc)?;

    let mut rd = roots_acc.try_borrow_mut()?;
    let l_idx = lane_id as usize;
    let r_off = RT_OFF_LATEST_LANE_ROOTS + l_idx * 32;
    rd[r_off..r_off + 32].copy_from_slice(new_lane_root);
    let c_off = RT_OFF_LATEST_LANE_COUNTS + l_idx * 8;
    rd[c_off..c_off + 8].copy_from_slice(&new_next_leaf.to_le_bytes());

    let g = l_idx / 4;
    let grp_base = RT_OFF_LATEST_LANE_ROOTS + g * 4 * 32;
    let group_root = poseidon4(
        slice_32(&rd, grp_base),
        slice_32(&rd, grp_base + 32),
        slice_32(&rd, grp_base + 64),
        slice_32(&rd, grp_base + 96),
    )?;
    let g_off = RT_OFF_GROUP_ROOTS + g * 32;
    rd[g_off..g_off + 32].copy_from_slice(&group_root);

    let new_super_root = poseidon4(
        slice_32(&rd, RT_OFF_GROUP_ROOTS),
        slice_32(&rd, RT_OFF_GROUP_ROOTS + 32),
        slice_32(&rd, RT_OFF_GROUP_ROOTS + 64),
        slice_32(&rd, RT_OFF_GROUP_ROOTS + 96),
    )?;
    rd[RT_OFF_LATEST_SUPER_ROOT..RT_OFF_LATEST_SUPER_ROOT + 32].copy_from_slice(&new_super_root);

    let prev_latest_slot = read_u64(&rd, RT_OFF_LATEST_SLOT);
    let mut slot_cursor = read_u16(&rd, RT_OFF_SLOT_CURSOR) as usize;
    let mut slot_count = read_u16(&rd, RT_OFF_SLOT_COUNT) as usize;
    let mut same_slot_bumped = rd[RT_OFF_SAME_SLOT_BUMPED];
    ensure(
        (1..=SLOT_RING_LEN).contains(&slot_count)
            && slot_cursor < slot_count
            && same_slot_bumped <= 1,
        AudrenError::RootHistoryMismatch,
    )?;
    ensure(now >= prev_latest_slot, AudrenError::RootHistoryMismatch)?;

    if now > prev_latest_slot {
        slot_cursor = (slot_cursor + 1) % SLOT_RING_LEN;
        if slot_count < SLOT_RING_LEN {
            slot_count += 1;
        }
        same_slot_bumped = 0;
        rd[RT_OFF_LATEST_SLOT..RT_OFF_LATEST_SLOT + 8].copy_from_slice(&now.to_le_bytes());
    } else if now == prev_latest_slot
        && verified_slot_ring_idx == Some(slot_cursor as u8)
        && same_slot_bumped == 0
    {
        slot_cursor = (slot_cursor + 1) % SLOT_RING_LEN;
        if slot_count < SLOT_RING_LEN {
            slot_count += 1;
        }
        same_slot_bumped = 1;
    }

    rd[RT_OFF_SLOT_CURSOR..RT_OFF_SLOT_CURSOR + 2]
        .copy_from_slice(&(slot_cursor as u16).to_le_bytes());
    rd[RT_OFF_SLOT_COUNT..RT_OFF_SLOT_COUNT + 2]
        .copy_from_slice(&(slot_count as u16).to_le_bytes());
    rd[RT_OFF_SAME_SLOT_BUMPED] = same_slot_bumped;

    let slot_entry_off = RT_OFF_SLOT_RING + slot_cursor * ROOT_ENTRY_LEN;
    rd[slot_entry_off..slot_entry_off + 32].copy_from_slice(&new_super_root);
    rd[slot_entry_off + 32..slot_entry_off + ROOT_ENTRY_LEN].copy_from_slice(&now.to_le_bytes());

    let epoch_interval = read_u64(&rd, RT_OFF_EPOCH_INTERVAL);
    ensure(
        (1..=MAX_ROOT_EPOCH_INTERVAL).contains(&epoch_interval),
        AudrenError::RootHistoryMismatch,
    )?;
    let stable_epoch_id = read_u64(&rd, RT_OFF_STABLE_EPOCH_ID);
    let cur_epoch_id = now / epoch_interval;
    if cur_epoch_id > stable_epoch_id {
        let mut epoch_cursor = read_u16(&rd, RT_OFF_EPOCH_CURSOR) as usize;
        let mut epoch_count = read_u16(&rd, RT_OFF_EPOCH_COUNT) as usize;
        ensure(
            (1..=EPOCH_RING_LEN).contains(&epoch_count) && epoch_cursor < epoch_count,
            AudrenError::RootHistoryMismatch,
        )?;
        epoch_cursor = (epoch_cursor + 1) % EPOCH_RING_LEN;
        if epoch_count < EPOCH_RING_LEN {
            epoch_count += 1;
        }
        rd[RT_OFF_EPOCH_CURSOR..RT_OFF_EPOCH_CURSOR + 2]
            .copy_from_slice(&(epoch_cursor as u16).to_le_bytes());
        rd[RT_OFF_EPOCH_COUNT..RT_OFF_EPOCH_COUNT + 2]
            .copy_from_slice(&(epoch_count as u16).to_le_bytes());
        rd[RT_OFF_STABLE_EPOCH_ID..RT_OFF_STABLE_EPOCH_ID + 8]
            .copy_from_slice(&cur_epoch_id.to_le_bytes());
        rd[RT_OFF_STABLE_SLOT..RT_OFF_STABLE_SLOT + 8].copy_from_slice(&now.to_le_bytes());

        let epoch_entry_off = RT_OFF_EPOCH_RING + epoch_cursor * ROOT_ENTRY_LEN;
        rd[epoch_entry_off..epoch_entry_off + 32].copy_from_slice(&new_super_root);
        rd[epoch_entry_off + 32..epoch_entry_off + ROOT_ENTRY_LEN]
            .copy_from_slice(&now.to_le_bytes());

        rd.copy_within(
            RT_OFF_LATEST_SUPER_ROOT..RT_OFF_LATEST_SUPER_ROOT + ROOT_SNAPSHOT_LEN,
            RT_OFF_STABLE_SUPER_ROOT,
        );
    }

    Ok(())
}

/// Collect a self-balancing per-note & per-nullifier amortized rent contribution into `LaneRentVault`.
///
/// Immune to SIMD-0437 rent reductions:
/// 1. Reads live `SysvarRent` once via `RentParams::get()`.
/// 2. Caps each note at `min(pool.note_rent_fee, live_per_note)` and each nullifier at `min(pool.nf_rent_fee, live_per_nf)`.
/// 3. Automatically skips collection once `LaneRentVault` holds a full 1-rollover buffer of all 4 page types.
fn collect_lane_rent_fee(
    payer: &AccountView,
    lane_rent_vault: &AccountView,
    cfg: &PoolConfig,
    num_notes: u64,
    num_nfs: u64,
) -> Result<u64, ProgramError> {
    if (cfg.note_rent_fee == 0 || num_notes == 0) && (cfg.nf_rent_fee == 0 || num_nfs == 0) {
        return Ok(0);
    }
    let rent = RentParams::get()?;
    let min_vault = rent.minimum_balance(SENTINEL_LEN)?.max(1);
    let sub_rent = rent.minimum_balance(SUBTREE_PAGE_LEN)?.max(1);
    let sr_rent = rent.minimum_balance(SUBROOT_PAGE_LEN)?.max(1);
    let memo_rent = rent.minimum_balance(MEMO_PAGE_LEN)?.max(1);
    let nf_rent = rent.minimum_balance(NF_PAGE_LEN)?.max(1);

    let target_balance = min_vault
        .saturating_add(sub_rent)
        .saturating_add(sr_rent)
        .saturating_add(memo_rent)
        .saturating_add(nf_rent);
    let deficit = target_balance.saturating_sub(lane_rent_vault.lamports());
    if deficit == 0 {
        return Ok(0);
    }

    let live_per_note = sub_rent
        .div_ceil(SUBTREE_LEAVES as u64)
        .saturating_add(sr_rent.div_ceil((SUBTREE_LEAVES * SUBROOTS_PER_PAGE) as u64))
        .saturating_add(memo_rent.div_ceil(MEMO_NOTES_PER_PAGE as u64));
    let live_per_nf = nf_rent.div_ceil(NF_PER_PAGE as u64);

    let note_part = cfg
        .note_rent_fee
        .min(live_per_note)
        .saturating_mul(num_notes);
    let nf_part = cfg.nf_rent_fee.min(live_per_nf).saturating_mul(num_nfs);
    let total = note_part.saturating_add(nf_part).min(deficit);
    if total > 0 {
        Transfer {
            from: payer,
            to: lane_rent_vault,
            lamports: total,
        }
        .invoke()?;
    }
    Ok(total)
}

/// Deterministic per-note rent fee (`min(pool.note_rent_fee, live_per_note)`) independent of
/// concurrent `LaneRentVault` balance changes — guarantees race-free exact memo parity for
/// `DEPOSIT_FLAG_FEE_FROM_AMOUNT` zero-dust sweeps!
fn deterministic_note_rent_fee(cfg: &PoolConfig) -> Result<u64, ProgramError> {
    if cfg.note_rent_fee == 0 {
        return Ok(0);
    }
    let rent = RentParams::get()?;
    let sub_rent = rent.minimum_balance(SUBTREE_PAGE_LEN)?.max(1);
    let sr_rent = rent.minimum_balance(SUBROOT_PAGE_LEN)?.max(1);
    let memo_rent = rent.minimum_balance(MEMO_PAGE_LEN)?.max(1);
    let live_per_note = sub_rent
        .div_ceil(SUBTREE_LEAVES as u64)
        .saturating_add(sr_rent.div_ceil((SUBTREE_LEAVES * SUBROOTS_PER_PAGE) as u64))
        .saturating_add(memo_rent.div_ceil(MEMO_NOTES_PER_PAGE as u64));
    Ok(cfg.note_rent_fee.min(live_per_note))
}

/// Out-of-line atomic WSOL unwrap helper (`Transact` with `WITHDRAW_FLAG_UNWRAP_WSOL`):
/// creates a 1-shot nullifier-seeded Classic SPL token account (`["audren_unwrap", pool_id, nf0]`)
/// owned by `vault_auth`, transfers `total_out` WSOL into it, closes it to `payer` (refunding
/// 100% of temporary token account rent + `total_out` SOL), and transfers exact `amount_out` SOL
/// to `recipient` and optional `relayer_fee` SOL to `fee_recipient`.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn unwrap_wsol_and_payout(
    pool_id: u32,
    nf0: &[u8; 32],
    unwrap_bump: u8,
    payer: &AccountView,
    sys_prog: &AccountView,
    vault_auth: &AccountView,
    mint_acc: &AccountView,
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
        .ok_or_else(|| err(AudrenError::Overflow))?;
    ensure(
        unwrap_acc.is_writable()
            && unwrap_acc.owned_by(&SYSTEM_PROGRAM_ID)
            && unwrap_acc.is_data_empty(),
        AudrenError::InvalidAccount,
    )?;

    let pool_le = pool_id.to_le_bytes();
    let ub = [unwrap_bump];
    let unwrap_seeds = [
        Seed::from(UNWRAP_SEED),
        Seed::from(&pool_le),
        Seed::from(nf0.as_slice()),
        Seed::from(&ub),
    ];
    create_pda_safe(
        payer,
        unwrap_acc,
        sys_prog,
        SPL_ACCOUNT_LEN,
        token_prog.address(),
        &unwrap_seeds,
    )?;

    // InitializeAccount3 (tag 18 || owner[32]) with owner = vault_auth
    let mut init_data = [0u8; 33];
    init_data[0] = TOKEN_IX_INITIALIZE_ACCOUNT3;
    init_data[1..33].copy_from_slice(vault_auth.address().as_ref());
    let init_metas = [
        InstructionAccount::writable(unwrap_acc.address()),
        InstructionAccount::readonly(mint_acc.address()),
    ];
    let init_ix = InstructionView {
        program_id: token_prog.address(),
        accounts: &init_metas,
        data: &init_data,
    };
    invoke_signed(&init_ix, &[unwrap_acc, mint_acc], &[])?;

    // TransferChecked `total_out` WSOL (decimals = 9) from `vault_ata` -> `unwrap_acc`
    let vault_before = validate_token_account(
        vault_ata,
        token_prog.address(),
        mint_acc.address(),
        vault_auth.address(),
        true,
    )?;
    let mut xfer_data = [0u8; 10];
    xfer_data[0] = TOKEN_IX_TRANSFER_CHECKED;
    xfer_data[1..9].copy_from_slice(&total_out.to_le_bytes());
    xfer_data[9] = 9;
    let xfer_metas = [
        InstructionAccount::writable(vault_ata.address()),
        InstructionAccount::readonly(mint_acc.address()),
        InstructionAccount::writable(unwrap_acc.address()),
        InstructionAccount::readonly_signer(vault_auth.address()),
    ];
    let xfer_ix = InstructionView {
        program_id: token_prog.address(),
        accounts: &xfer_metas,
        data: &xfer_data,
    };
    invoke_signed(&xfer_ix, &[vault_ata, mint_acc, unwrap_acc, vault_auth], va_signer)?;
    let vault_after = validate_token_account(
        vault_ata,
        token_prog.address(),
        mint_acc.address(),
        vault_auth.address(),
        true,
    )?;
    ensure(
        vault_before.checked_sub(vault_after) == Some(total_out),
        AudrenError::CustodyInvariantViolated,
    )?;

    // CloseAccount `unwrap_acc` -> `payer` (destroys 1-shot PDA, refunds 100% rent + total_out SOL)
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
        .ok_or_else(|| err(AudrenError::CustodyInvariantViolated))?;
    ensure(
        unwrap_acc.lamports() == 0 && unwrapped_received >= total_out,
        AudrenError::CustodyInvariantViolated,
    )?;

    // Distribute exact Native SOL to `recipient` and optional `fee_recipient`
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

// =============================================================================
// Tree + On-Chain Versioned 106 B MemoPage & NullifierPage Helpers
// =============================================================================

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn append_leaf_and_memo(
    program_id: &Address,
    pool_id: u32,
    lane_id: u8,
    lane_acc: &mut AccountView,
    subtree_acc: &mut AccountView,
    next_subtree_opt: Option<&mut AccountView>,
    subroot_acc: &mut AccountView,
    memo_acc: &mut AccountView,
    next_memo_opt: Option<&mut AccountView>,
    leaf: &[u8; 32],
    memo_entry: &[u8],
    slot: u64,
) -> Result<u64, ProgramError> {
    ensure(memo_entry.len() == MEMO_ENTRY_WIRE_LEN, AudrenError::InvalidInstruction)?;

    let (leaf_idx, finalized_sub_root) = {
        let mut lane_data = lane_acc.try_borrow_mut()?;
        append_leaf_4ary_in_place(&mut lane_data, leaf)?
    };

    // 1. Write commitment leaf to SubtreePage (+ optional rollover to next_subtree_opt)
    let page_seq = leaf_idx / (SUBTREE_LEAVES as u64);
    let offset_in_page = (leaf_idx % (SUBTREE_LEAVES as u64)) as usize;

    let primary_sub_matches = {
        let d = subtree_acc.try_borrow()?;
        ensure(
            subtree_acc.owned_by(program_id)
                && d.len() == SUBTREE_PAGE_LEN
                && d[0..8] == SUBTREE_MAGIC
                && d[SB_OFF_LANE_ID] == lane_id
                && read_u32(&d, SB_OFF_POOL_ID) == pool_id,
            AudrenError::SubtreePageMismatch,
        )?;
        read_u64(&d, SB_OFF_PAGE_SEQ) == page_seq
    };

    let target_sub: &mut AccountView = if primary_sub_matches {
        subtree_acc
    } else if let Some(next_sub) = next_subtree_opt {
        {
            let d = next_sub.try_borrow()?;
            ensure(
                next_sub.owned_by(program_id)
                    && d.len() == SUBTREE_PAGE_LEN
                    && d[0..8] == SUBTREE_MAGIC
                    && d[SB_OFF_LANE_ID] == lane_id
                    && read_u32(&d, SB_OFF_POOL_ID) == pool_id
                    && read_u64(&d, SB_OFF_PAGE_SEQ) == page_seq,
                AudrenError::SubtreePageMismatch,
            )?;
        }
        next_sub
    } else {
        return Err(err(AudrenError::SubtreePageFull));
    };

    {
        let mut sd = target_sub.try_borrow_mut()?;
        let count = read_u16(&sd, SB_OFF_COUNT) as usize;
        ensure(count == offset_in_page, AudrenError::SubtreePageMismatch)?;
        let pos = SB_OFF_LEAVES + offset_in_page * 32;
        sd[pos..pos + 32].copy_from_slice(leaf);
        sd[SB_OFF_COUNT..SB_OFF_COUNT + 2].copy_from_slice(&((count + 1) as u16).to_le_bytes());
    }

    if let Some(sub_root) = finalized_sub_root {
        let root_page_seq = page_seq / (SUBROOTS_PER_PAGE as u64);
        let root_slot = (page_seq % (SUBROOTS_PER_PAGE as u64)) as usize;
        ensure(subroot_acc.owned_by(program_id), AudrenError::SubrootPageMismatch)?;
        let mut srd = subroot_acc.try_borrow_mut()?;
        ensure(
            srd.len() == SUBROOT_PAGE_LEN
                && srd[0..8] == SUBROOT_MAGIC
                && srd[SR_OFF_LANE_ID] == lane_id
                && read_u32(&srd, SR_OFF_POOL_ID) == pool_id
                && read_u64(&srd, SR_OFF_ROOT_PAGE_SEQ) == root_page_seq,
            AudrenError::SubrootPageMismatch,
        )?;
        let pos = SR_OFF_ROOTS + root_slot * 32;
        srd[pos..pos + 32].copy_from_slice(&sub_root);
        let cur_cnt = read_u16(&srd, SR_OFF_COUNT) as usize;
        if root_slot + 1 > cur_cnt {
            srd[SR_OFF_COUNT..SR_OFF_COUNT + 2]
                .copy_from_slice(&((root_slot + 1) as u16).to_le_bytes());
        }
    }

    // 2. Write (view_tag[2], ephemeral_pk[32], ciphertext[72]) into deterministic MemoPage PDA
    let memo_seq = leaf_idx / (MEMO_NOTES_PER_PAGE as u64);
    let memo_slot = (leaf_idx % (MEMO_NOTES_PER_PAGE as u64)) as usize;

    let primary_memo_matches = {
        let d = memo_acc.try_borrow()?;
        ensure(
            memo_acc.owned_by(program_id)
                && d.len() == MEMO_PAGE_LEN
                && d[0..8] == MEMO_MAGIC
                && d[MM_OFF_LANE_ID] == lane_id
                && read_u32(&d, MM_OFF_POOL_ID) == pool_id,
            AudrenError::MemoPageMismatch,
        )?;
        read_u64(&d, MM_OFF_PAGE_SEQ) == memo_seq
    };

    let target_memo: &mut AccountView = if primary_memo_matches {
        memo_acc
    } else if let Some(next_memo) = next_memo_opt {
        {
            let d = next_memo.try_borrow()?;
            ensure(
                next_memo.owned_by(program_id)
                    && d.len() == MEMO_PAGE_LEN
                    && d[0..8] == MEMO_MAGIC
                    && d[MM_OFF_LANE_ID] == lane_id
                    && read_u32(&d, MM_OFF_POOL_ID) == pool_id
                    && read_u64(&d, MM_OFF_PAGE_SEQ) == memo_seq,
                AudrenError::MemoPageMismatch,
            )?;
        }
        next_memo
    } else {
        return Err(err(AudrenError::MemoPageFull));
    };

    {
        let mut md = target_memo.try_borrow_mut()?;
        let count = read_u16(&md, MM_OFF_COUNT) as usize;
        ensure(count == memo_slot, AudrenError::MemoPageMismatch)?;
        if count == 0 {
            md[MM_OFF_CREATED_SLOT..MM_OFF_CREATED_SLOT + 8].copy_from_slice(&slot.to_le_bytes());
        }
        let vt_pos = MM_OFF_VIEW_TAGS + memo_slot * 2;
        md[vt_pos..vt_pos + 2].copy_from_slice(&memo_entry[0..2]);
        let epk_pos = MM_OFF_EPHEMERAL_PKS + memo_slot * 32;
        md[epk_pos..epk_pos + 32].copy_from_slice(&memo_entry[2..34]);
        let ct_pos = MM_OFF_CIPHERTEXTS + memo_slot * MEMO_CT_LEN;
        md[ct_pos..ct_pos + MEMO_CT_LEN].copy_from_slice(&memo_entry[34..MEMO_ENTRY_WIRE_LEN]);
        let new_cnt = count + 1;
        md[MM_OFF_COUNT..MM_OFF_COUNT + 2].copy_from_slice(&(new_cnt as u16).to_le_bytes());
        if new_cnt == MEMO_NOTES_PER_PAGE {
            md[MM_OFF_CLOSED_SLOT..MM_OFF_CLOSED_SLOT + 8].copy_from_slice(&slot.to_le_bytes());
        }
    }

    Ok(leaf_idx)
}

fn create_nullifier_pda<'a>(
    program_id: &Address,
    payer: &'a AccountView,
    nf_acc: &'a AccountView,
    sys_prog: &'a AccountView,
    pool_id: u32,
    nf: &[u8; 32],
) -> ProgramResult {
    ensure(nf != &[0u8; 32], AudrenError::InvalidInstruction)?;
    ensure(
        nf_acc.owned_by(&SYSTEM_PROGRAM_ID) && nf_acc.is_data_empty(),
        AudrenError::NullifierAlreadyUsed,
    )?;
    let (expected, bump) = nullifier_pda(program_id, pool_id, nf);
    ensure(nf_acc.address() == &expected, AudrenError::InvalidPda)?;
    let pool_le = pool_id.to_le_bytes();
    let bump_b = [bump];
    let seeds = [
        Seed::from(NULLIFIER_SEED),
        Seed::from(&pool_le),
        Seed::from(nf.as_slice()),
        Seed::from(&bump_b),
    ];
    create_pda_safe(payer, nf_acc, sys_prog, 0, program_id, &seeds)
}

#[allow(clippy::too_many_arguments)]
fn append_nullifier_prefix(
    program_id: &Address,
    pool_id: u32,
    lane_id: u8,
    lane_acc: &mut AccountView,
    nf_page_acc: &mut AccountView,
    next_nf_page_opt: Option<&mut AccountView>,
    nf: &[u8; 32],
    slot: u64,
) -> ProgramResult {
    let nf_idx = {
        let mut ld = lane_acc.try_borrow_mut()?;
        let cur = read_u64(&ld, LN_OFF_NF_COUNT);
        let next = cur.checked_add(1).ok_or_else(|| err(AudrenError::Overflow))?;
        ld[LN_OFF_NF_COUNT..LN_OFF_NF_COUNT + 8].copy_from_slice(&next.to_le_bytes());
        cur
    };
    let page_seq = nf_idx / (NF_PER_PAGE as u64);
    let slot_in_page = (nf_idx % (NF_PER_PAGE as u64)) as usize;

    let primary_matches = {
        let d = nf_page_acc.try_borrow()?;
        ensure(
            nf_page_acc.owned_by(program_id)
                && d.len() == NF_PAGE_LEN
                && d[0..8] == NF_PAGE_MAGIC
                && d[NF_OFF_LANE_ID] == lane_id
                && read_u32(&d, NF_OFF_POOL_ID) == pool_id,
            AudrenError::NullifierPageMismatch,
        )?;
        read_u64(&d, NF_OFF_PAGE_SEQ) == page_seq
    };

    let target: &mut AccountView = if primary_matches {
        nf_page_acc
    } else if let Some(next_nf) = next_nf_page_opt {
        {
            let d = next_nf.try_borrow()?;
            ensure(
                next_nf.owned_by(program_id)
                    && d.len() == NF_PAGE_LEN
                    && d[0..8] == NF_PAGE_MAGIC
                    && d[NF_OFF_LANE_ID] == lane_id
                    && read_u32(&d, NF_OFF_POOL_ID) == pool_id
                    && read_u64(&d, NF_OFF_PAGE_SEQ) == page_seq,
                AudrenError::NullifierPageMismatch,
            )?;
        }
        next_nf
    } else {
        return Err(err(AudrenError::NullifierPageFull));
    };

    let mut nd = target.try_borrow_mut()?;
    let count = read_u16(&nd, NF_OFF_COUNT) as usize;
    ensure(count == slot_in_page, AudrenError::NullifierPageMismatch)?;
    if count == 0 {
        nd[NF_OFF_CREATED_SLOT..NF_OFF_CREATED_SLOT + 8].copy_from_slice(&slot.to_le_bytes());
    }
    let pos = NF_OFF_PREFIXES + slot_in_page * NF_PREFIX_LEN;
    nd[pos..pos + NF_PREFIX_LEN].copy_from_slice(&nf[0..NF_PREFIX_LEN]);
    let new_cnt = count + 1;
    nd[NF_OFF_COUNT..NF_OFF_COUNT + 2].copy_from_slice(&(new_cnt as u16).to_le_bytes());
    if new_cnt == NF_PER_PAGE {
        nd[NF_OFF_CLOSED_SLOT..NF_OFF_CLOSED_SLOT + 8].copy_from_slice(&slot.to_le_bytes());
    }
    Ok(())
}

pub fn process(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    ensure(!data.is_empty(), AudrenError::InvalidInstruction)?;
    match data[0] {
        TAG_INIT_POOL => ix_init_pool(program_id, accounts, &data[1..]),
        TAG_INIT_LANE => ix_init_lane(program_id, accounts, &data[1..]),
        TAG_OPEN_PAGE => ix_open_page(program_id, accounts, &data[1..]),
        TAG_DEPOSIT => ix_deposit(program_id, accounts, &data[1..]),
        TAG_INIT_ROOT_HISTORY => ix_init_root_history(program_id, accounts, &data[1..]),
        TAG_TRANSACT => ix_transact(program_id, accounts, &data[1..]),
        TAG_EXEC_VIA_ESCROW => ix_exec_via_escrow(program_id, accounts, &data[1..]),
        TAG_SET_PAUSED => ix_set_paused(program_id, accounts, &data[1..]),
        TAG_UPDATE_POOL => ix_update_pool(program_id, accounts, &data[1..]),
        _ => Err(err(AudrenError::InvalidInstruction)),
    }
}

// =============================================================================
// 0. InitPool (PoolState 128 B + empty GlobalRootHistory 10,216 B)
// =============================================================================

#[inline(never)]
fn ix_init_pool(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    // pool_id(4) + root_epoch_interval(8) + note_rent_fee(8) + nf_rent_fee(8) = 28 B
    ensure(data.len() == 28, AudrenError::InvalidInstruction)?;
    let [payer, pool_acc, roots_acc, sys_prog, ..] = accounts else {
        return Err(err(AudrenError::InvalidInstruction));
    };
    ensure(payer.is_signer(), AudrenError::Unauthorized)?;
    ensure(
        pool_acc.is_writable()
            && roots_acc.is_writable()
            && sys_prog.address() == &SYSTEM_PROGRAM_ID,
        AudrenError::InvalidAccount,
    )?;

    let pool_id = read_u32(data, 0);
    let root_epoch_interval = read_u64(data, 4);
    let note_rent_fee = read_u64(data, 12);
    let nf_rent_fee = read_u64(data, 20);

    ensure(
        (1..=MAX_ROOT_EPOCH_INTERVAL).contains(&root_epoch_interval),
        AudrenError::InvalidInstruction,
    )?;

    let (expected_pool, pool_bump) = pool_pda(program_id, pool_id);
    ensure(pool_acc.address() == &expected_pool, AudrenError::InvalidPda)?;
    let (_, va_bump) = vault_auth_pda(program_id, pool_id);

    let pool_le = pool_id.to_le_bytes();
    let pb = [pool_bump];
    let rent = RentParams::get()?;
    create_pda_safe_with_rent(
        payer,
        pool_acc,
        sys_prog,
        POOL_STATE_LEN,
        program_id,
        &[Seed::from(POOL_SEED), Seed::from(&pool_le), Seed::from(&pb)],
        rent,
    )?;

    {
        let mut pd = pool_acc.try_borrow_mut()?;
        pd[PL_OFF_MAGIC..PL_OFF_MAGIC + 8].copy_from_slice(&POOL_MAGIC);
        pd[PL_OFF_VERSION] = PROTOCOL_VERSION;
        pd[PL_OFF_BUMP] = pool_bump;
        pd[PL_OFF_PAUSED] = 0;
        pd[PL_OFF_ACTIVE_LANES] = 0;
        pd[PL_OFF_POOL_ID..PL_OFF_POOL_ID + 4].copy_from_slice(&pool_le);
        pd[PL_OFF_ROOT_EPOCH_INTERVAL..PL_OFF_ROOT_EPOCH_INTERVAL + 8]
            .copy_from_slice(&root_epoch_interval.to_le_bytes());
        pd[PL_OFF_RESERVED_24..PL_OFF_RESERVED_24 + 8].fill(0);
        pd[PL_OFF_AUTHORITY..PL_OFF_AUTHORITY + 32].copy_from_slice(payer.address().as_ref());
        pd[PL_OFF_VAULT_AUTH_BUMP] = va_bump;
        pd[PL_OFF_NOTE_RENT_FEE..PL_OFF_NOTE_RENT_FEE + 8]
            .copy_from_slice(&note_rent_fee.to_le_bytes());
        pd[PL_OFF_NF_RENT_FEE..PL_OFF_NF_RENT_FEE + 8].copy_from_slice(&nf_rent_fee.to_le_bytes());
        pd[PL_OFF_PENDING_AUTHORITY..PL_OFF_PENDING_AUTHORITY + 32].fill(0);
    }

    let now = Clock::get()?.slot;
    init_root_history_account(
        program_id,
        pool_id,
        root_epoch_interval,
        now,
        payer,
        roots_acc,
        sys_prog,
        &[],
        rent,
    )
}

// =============================================================================
// 1. InitLane (LaneTreeState + per-lane LaneRentVault sentinel + page 0s)
// =============================================================================

#[inline(never)]
fn ix_init_lane(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    ensure(data.len() == 5, AudrenError::InvalidInstruction)?;
    let [payer, pool_acc, lane_acc, lane_rent_vault, sub0, sr0, memo0, nf0, sys_prog, ..] =
        accounts
    else {
        return Err(err(AudrenError::InvalidInstruction));
    };
    ensure(payer.is_signer(), AudrenError::Unauthorized)?;

    let pool_id = read_u32(data, 0);
    let lane_id = data[4];
    ensure((lane_id as usize) < NUM_LANES, AudrenError::InvalidLane)?;
    let cfg = load_and_verify_pool(program_id, pool_id, pool_acc)?;
    // Authority-gated sequential activation (`0 -> 1 -> ... -> 15`) so `active_lanes`
    // expands cleanly (`4 -> 8 -> 16`) with zero gaps and zero circuit changes.
    ensure(
        cfg.authority != ZERO_ADDRESS && payer.address() == &cfg.authority,
        AudrenError::Unauthorized,
    )?;
    ensure(lane_id == cfg.active_lanes, AudrenError::InvalidLane)?;
    ensure(pool_acc.is_writable(), AudrenError::InvalidAccount)?;

    let pool_le = pool_id.to_le_bytes();
    let lane_b = [lane_id];
    let seq0 = 0u64.to_le_bytes();
    let slot = Clock::get()?.slot;
    let rent = RentParams::get()?;

    let (exp_rv, rvb) = lane_rent_pda(program_id, pool_id, lane_id);
    ensure(lane_rent_vault.address() == &exp_rv, AudrenError::InvalidPda)?;
    let rvb_arr = [rvb];
    create_pda_safe_with_rent(
        payer,
        lane_rent_vault,
        sys_prog,
        SENTINEL_LEN,
        program_id,
        &[
            Seed::from(LANE_RENT_SEED),
            Seed::from(&pool_le),
            Seed::from(&lane_b),
            Seed::from(&rvb_arr),
        ],
        rent,
    )?;
    {
        let mut rd = lane_rent_vault.try_borrow_mut()?;
        rd[SN_OFF_MAGIC..SN_OFF_MAGIC + 8].copy_from_slice(&LANE_RENT_MAGIC);
        rd[SN_OFF_POOL_ID..SN_OFF_POOL_ID + 4].copy_from_slice(&pool_le);
        rd[SN_OFF_LANE_ID] = lane_id;
        rd[SN_OFF_BUMP] = rvb;
    }

    let (exp_lane, lb) = lane_pda(program_id, pool_id, lane_id);
    ensure(lane_acc.address() == &exp_lane, AudrenError::InvalidPda)?;
    let lb_arr = [lb];
    create_pda_safe_with_rent(
        payer,
        lane_acc,
        sys_prog,
        LANE_STATE_LEN,
        program_id,
        &[
            Seed::from(LANE_SEED),
            Seed::from(&pool_le),
            Seed::from(&lane_b),
            Seed::from(&lb_arr),
        ],
        rent,
    )?;
    {
        let mut ld = lane_acc.try_borrow_mut()?;
        ld[LN_OFF_MAGIC..LN_OFF_MAGIC + 8].copy_from_slice(&LANE_MAGIC);
        ld[LN_OFF_VERSION] = PROTOCOL_VERSION;
        ld[LN_OFF_LANE_ID] = lane_id;
        ld[LN_OFF_BUMP] = lb;
        ld[LN_OFF_RENT_BUMP] = rvb;
        ld[LN_OFF_POOL_ID..LN_OFF_POOL_ID + 4].copy_from_slice(&pool_le);
        ld[LN_OFF_CURRENT_ROOT..LN_OFF_CURRENT_ROOT + 32].copy_from_slice(&ZERO_HASHES_4ARY[18]);
    }

    let (exp_sub0, sb) = subtree_pda(program_id, pool_id, lane_id, 0);
    ensure(sub0.address() == &exp_sub0, AudrenError::InvalidPda)?;
    let sb_arr = [sb];
    create_pda_safe_with_rent(
        payer,
        sub0,
        sys_prog,
        SUBTREE_PAGE_LEN,
        program_id,
        &[
            Seed::from(SUBTREE_SEED),
            Seed::from(&pool_le),
            Seed::from(&lane_b),
            Seed::from(&seq0),
            Seed::from(&sb_arr),
        ],
        rent,
    )?;
    {
        let mut sd = sub0.try_borrow_mut()?;
        sd[SB_OFF_MAGIC..SB_OFF_MAGIC + 8].copy_from_slice(&SUBTREE_MAGIC);
        sd[SB_OFF_LANE_ID] = lane_id;
        sd[SB_OFF_BUMP] = sb;
        sd[SB_OFF_POOL_ID..SB_OFF_POOL_ID + 4].copy_from_slice(&pool_le);
    }

    let (exp_sr0, srb) = subroot_pda(program_id, pool_id, lane_id, 0);
    ensure(sr0.address() == &exp_sr0, AudrenError::InvalidPda)?;
    let srb_arr = [srb];
    create_pda_safe_with_rent(
        payer,
        sr0,
        sys_prog,
        SUBROOT_PAGE_LEN,
        program_id,
        &[
            Seed::from(SUBROOT_SEED),
            Seed::from(&pool_le),
            Seed::from(&lane_b),
            Seed::from(&seq0),
            Seed::from(&srb_arr),
        ],
        rent,
    )?;
    {
        let mut srd = sr0.try_borrow_mut()?;
        srd[SR_OFF_MAGIC..SR_OFF_MAGIC + 8].copy_from_slice(&SUBROOT_MAGIC);
        srd[SR_OFF_LANE_ID] = lane_id;
        srd[SR_OFF_BUMP] = srb;
        srd[SR_OFF_POOL_ID..SR_OFF_POOL_ID + 4].copy_from_slice(&pool_le);
    }

    let (exp_mm0, mmb) = memo_pda(program_id, pool_id, lane_id, 0);
    ensure(memo0.address() == &exp_mm0, AudrenError::InvalidPda)?;
    let mmb_arr = [mmb];
    create_pda_safe_with_rent(
        payer,
        memo0,
        sys_prog,
        MEMO_PAGE_LEN,
        program_id,
        &[
            Seed::from(MEMO_SEED),
            Seed::from(&pool_le),
            Seed::from(&lane_b),
            Seed::from(&seq0),
            Seed::from(&mmb_arr),
        ],
        rent,
    )?;
    {
        let mut md = memo0.try_borrow_mut()?;
        md[MM_OFF_MAGIC..MM_OFF_MAGIC + 8].copy_from_slice(&MEMO_MAGIC);
        md[MM_OFF_LANE_ID] = lane_id;
        md[MM_OFF_BUMP] = mmb;
        md[MM_OFF_POOL_ID..MM_OFF_POOL_ID + 4].copy_from_slice(&pool_le);
        md[MM_OFF_CREATED_SLOT..MM_OFF_CREATED_SLOT + 8].copy_from_slice(&slot.to_le_bytes());
    }

    let (exp_nf0, nfb) = nf_page_pda(program_id, pool_id, lane_id, 0);
    ensure(nf0.address() == &exp_nf0, AudrenError::InvalidPda)?;
    let nfb_arr = [nfb];
    create_pda_safe_with_rent(
        payer,
        nf0,
        sys_prog,
        NF_PAGE_LEN,
        program_id,
        &[
            Seed::from(NF_PAGE_SEED),
            Seed::from(&pool_le),
            Seed::from(&lane_b),
            Seed::from(&seq0),
            Seed::from(&nfb_arr),
        ],
        rent,
    )?;
    {
        let mut nd = nf0.try_borrow_mut()?;
        nd[NF_OFF_MAGIC..NF_OFF_MAGIC + 8].copy_from_slice(&NF_PAGE_MAGIC);
        nd[NF_OFF_LANE_ID] = lane_id;
        nd[NF_OFF_BUMP] = nfb;
        nd[NF_OFF_POOL_ID..NF_OFF_POOL_ID + 4].copy_from_slice(&pool_le);
        nd[NF_OFF_CREATED_SLOT..NF_OFF_CREATED_SLOT + 8].copy_from_slice(&slot.to_le_bytes());
    }
    {
        let mut pd = pool_acc.try_borrow_mut()?;
        pd[PL_OFF_ACTIVE_LANES] = lane_id + 1;
    }
    Ok(())
}

// =============================================================================
// 2. OpenPage (idempotent, sequence-bounded, self-funded via LaneRentVault, pause-exempt)
// =============================================================================

#[inline(never)]
fn ix_open_page(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    // page_kind(1) + pool_id(4) + lane_id(1) + page_seq(8) = 14 B
    ensure(data.len() == 14, AudrenError::InvalidInstruction)?;
    let [payer, pool_acc, lane_acc, lane_rent_vault, page_acc, sys_prog, ..] = accounts else {
        return Err(err(AudrenError::InvalidInstruction));
    };
    ensure(
        payer.is_signer() && sys_prog.address() == &SYSTEM_PROGRAM_ID,
        AudrenError::InvalidAccount,
    )?;

    let page_kind = data[0];
    let pool_id = read_u32(data, 1);
    let lane_id = data[5];
    let page_seq = read_u64(data, 6);
    ensure((lane_id as usize) < NUM_LANES, AudrenError::InvalidLane)?;

    let cfg = load_and_verify_pool(program_id, pool_id, pool_acc)?;
    ensure(lane_id < cfg.active_lanes, AudrenError::InvalidLane)?;
    let rent_bump = verify_lane_pda(program_id, pool_id, lane_id, lane_acc)?;
    verify_lane_rent_vault(program_id, pool_id, lane_id, rent_bump, lane_rent_vault)?;

    let (next_leaf, nf_count) = {
        let ld = lane_acc.try_borrow()?;
        (read_u64(&ld, LN_OFF_NEXT_LEAF), read_u64(&ld, LN_OFF_NF_COUNT))
    };
    let (seed, magic, space, cur_seq, stamp_created, (exp, bump)) = match page_kind {
        PAGE_KIND_SUBTREE => (
            SUBTREE_SEED,
            SUBTREE_MAGIC,
            SUBTREE_PAGE_LEN,
            next_leaf / (SUBTREE_LEAVES as u64),
            false,
            subtree_pda(program_id, pool_id, lane_id, page_seq),
        ),
        PAGE_KIND_SUBROOT => (
            SUBROOT_SEED,
            SUBROOT_MAGIC,
            SUBROOT_PAGE_LEN,
            (next_leaf / (SUBTREE_LEAVES as u64)) / (SUBROOTS_PER_PAGE as u64),
            false,
            subroot_pda(program_id, pool_id, lane_id, page_seq),
        ),
        PAGE_KIND_MEMO => (
            MEMO_SEED,
            MEMO_MAGIC,
            MEMO_PAGE_LEN,
            next_leaf / (MEMO_NOTES_PER_PAGE as u64),
            true,
            memo_pda(program_id, pool_id, lane_id, page_seq),
        ),
        PAGE_KIND_NF => (
            NF_PAGE_SEED,
            NF_PAGE_MAGIC,
            NF_PAGE_LEN,
            nf_count / (NF_PER_PAGE as u64),
            true,
            nf_page_pda(program_id, pool_id, lane_id, page_seq),
        ),
        _ => return Err(err(AudrenError::InvalidInstruction)),
    };

    if page_kind == PAGE_KIND_SUBROOT {
        let subroot_slot = (next_leaf / (SUBTREE_LEAVES as u64)) % (SUBROOTS_PER_PAGE as u64);
        let allowed = page_seq <= cur_seq
            || (cur_seq.checked_add(1) == Some(page_seq) && subroot_slot >= 280);
        ensure(allowed, AudrenError::PageSeqOutOfRange)?;
    } else {
        ensure(page_seq <= cur_seq.saturating_add(2), AudrenError::PageSeqOutOfRange)?;
    }
    ensure(page_acc.address() == &exp, AudrenError::InvalidPda)?;

    // Idempotent: concurrent pre-openers both succeed cleanly!
    if page_acc.owned_by(program_id) {
        let d = page_acc.try_borrow()?;
        ensure(
            d.len() == space
                && d[0..8] == magic
                && d[8] == lane_id
                && read_u32(&d, 12) == pool_id
                && read_u64(&d, 16) == page_seq,
            AudrenError::InvalidAccount,
        )?;
        return Ok(());
    }

    ensure(
        page_acc.owned_by(&SYSTEM_PROGRAM_ID) && page_acc.is_data_empty(),
        AudrenError::InvalidAccount,
    )?;

    // Self-funding via `LaneRentVault`: Allocate & Assign BEFORE direct lamport debit
    // so a 0-SOL cranker can open pages once `LaneRentVault` is funded.
    // Clamp both the sentinel floor and required page rent to `>= 1` lamport so zero-rent
    // clusters can never drain `LaneRentVault` or create a 0-lamport page subject to reaping.
    let rent = RentParams::get()?;
    let min_vault = rent.minimum_balance(SENTINEL_LEN)?.max(1);
    let page_rent = rent.minimum_balance(space)?.max(1);
    let available = lane_rent_vault.lamports().saturating_sub(min_vault);
    let needed = page_rent.saturating_sub(page_acc.lamports());
    let subsidy = available.min(needed);
    let payer_deficit = needed.saturating_sub(subsidy);

    let pool_le = pool_id.to_le_bytes();
    let lane_b = [lane_id];
    let seq_le = page_seq.to_le_bytes();
    let bump_b = [bump];
    let page_seeds = [
        Seed::from(seed),
        Seed::from(&pool_le),
        Seed::from(&lane_b),
        Seed::from(&seq_le),
        Seed::from(&bump_b),
    ];

    if subsidy == 0 && page_acc.lamports() == 0 {
        CreateAccount {
            from: payer,
            to: page_acc,
            lamports: payer_deficit,
            space: space as u64,
            owner: program_id,
        }
        .invoke_signed(&[Signer::from(&page_seeds)])?;
    } else {
        if payer_deficit > 0 {
            Transfer {
                from: payer,
                to: page_acc,
                lamports: payer_deficit,
            }
            .invoke()?;
        }
        Allocate {
            account: page_acc,
            space: space as u64,
        }
        .invoke_signed(&[Signer::from(&page_seeds)])?;
        Assign {
            account: page_acc,
            owner: program_id,
        }
        .invoke_signed(&[Signer::from(&page_seeds)])?;
    }

    if subsidy > 0 {
        let new_vault = lane_rent_vault
            .lamports()
            .checked_sub(subsidy)
            .ok_or_else(|| err(AudrenError::Overflow))?;
        let new_page = page_acc
            .lamports()
            .checked_add(subsidy)
            .ok_or_else(|| err(AudrenError::Overflow))?;
        lane_rent_vault.set_lamports(new_vault);
        page_acc.set_lamports(new_page);
    }

    let mut d = page_acc.try_borrow_mut()?;
    d[0..8].copy_from_slice(&magic);
    d[8] = lane_id;
    d[9] = bump;
    d[12..16].copy_from_slice(&pool_le);
    d[16..24].copy_from_slice(&seq_le);
    if stamp_created {
        let slot = Clock::get()?.slot;
        d[24..32].copy_from_slice(&slot.to_le_bytes());
    }
    Ok(())
}

// =============================================================================
// 3. Deposit (Unified Native SOL via SyncNative & SPL / Token-2022 -> canonical vault_auth ATA + inline GlobalRootHistory update)
// =============================================================================

#[inline(never)]
fn ix_deposit(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    // pool_id(4) + lane_id(1) + flags(1) + amount(8) + stealth_owner(32) + blinding(32) + memo(106) = 184 B (185 B w/ tag)
    const DATA_LEN: usize = 4 + 1 + 1 + 8 + 32 + 32 + MEMO_ENTRY_WIRE_LEN;
    ensure(data.len() == DATA_LEN && accounts.len() >= 14, AudrenError::InvalidInstruction)?;
    let (head, tail) = accounts.split_at_mut(14);
    let [depositor, pool_acc, roots_acc, vault_auth, mint_acc, source_account, vault_ata, token_prog, lane_acc, lane_rent_vault, subtree_acc, subroot_acc, memo_acc, sys_prog] =
        head
    else {
        return Err(err(AudrenError::InvalidInstruction));
    };

    ensure(
        depositor.is_signer() && sys_prog.address() == &SYSTEM_PROGRAM_ID,
        AudrenError::InvalidAccount,
    )?;

    let pool_id = read_u32(data, 0);
    let lane_id = data[4];
    let flags = data[5];
    let amount = read_u64(data, 6);
    let stealth_owner = read_32(data, 14);
    let blinding = read_32(data, 46);
    let memo_entry = &data[78..DATA_LEN];

    let valid_flags = 0b11 | DEPOSIT_FLAG_FEE_FROM_AMOUNT | DEPOSIT_FLAG_NATIVE_SOL;
    ensure(
        (lane_id as usize) < NUM_LANES
            && (flags & !valid_flags) == 0
            && amount > 0
            && blinding != [0u8; 32],
        AudrenError::InvalidInstruction,
    )?;
    ensure_canonical_fr(&stealth_owner)?;
    ensure_canonical_fr(&blinding)?;

    let cfg = load_and_verify_pool(program_id, pool_id, pool_acc)?;
    ensure(!cfg.paused, AudrenError::PoolPaused)?;
    ensure(lane_id < cfg.active_lanes, AudrenError::InvalidLane)?;
    ensure(roots_acc.is_writable(), AudrenError::InvalidAccount)?;
    verify_roots_pda(program_id, pool_id, roots_acc)?;

    let pool_le = pool_id.to_le_bytes();
    let exp_va = Address::create_program_address(
        &[VAULT_AUTH_SEED, &pool_le, &[cfg.vault_auth_bump]],
        program_id,
    )
    .map_err(|_| err(AudrenError::InvalidPda))?;
    ensure(vault_auth.address() == &exp_va, AudrenError::InvalidPda)?;
    let rent_bump = verify_lane_pda(program_id, pool_id, lane_id, lane_acc)?;
    verify_lane_rent_vault(program_id, pool_id, lane_id, rent_bump, lane_rent_vault)?;

    let has_next_sub = (flags & 1) != 0;
    let has_next_memo = (flags & 2) != 0;
    let fee_from_amount = (flags & DEPOSIT_FLAG_FEE_FROM_AMOUNT) != 0;
    let native_sol = (flags & DEPOSIT_FLAG_NATIVE_SOL) != 0;
    let roll_cnt = usize::from(has_next_sub) + usize::from(has_next_memo);
    ensure(tail.len() >= roll_cnt, AudrenError::InvalidInstruction)?;
    let (roll_slice, hook_candidates) = tail.split_at_mut(roll_cnt);
    let (sub_slot, memo_slot) = roll_slice.split_at_mut(usize::from(has_next_sub));

    let mint_info = load_mint_info(mint_acc, token_prog.address())?;
    let vault_before = validate_canonical_ata(
        vault_ata,
        token_prog.address(),
        mint_acc.address(),
        vault_auth.address(),
    )?;

    let committed_amount = if native_sol {
        ensure(
            mint_acc.address() == &WSOL_MINT && token_prog.address() == &SPL_TOKEN_ID,
            AudrenError::InvalidTokenAccount,
        )?;
        ensure(
            source_account.address() == depositor.address(),
            AudrenError::InvalidAccount,
        )?;

        let net_sol = if fee_from_amount {
            let fee = deterministic_note_rent_fee(&cfg)?;
            let net = amount
                .checked_sub(fee)
                .ok_or_else(|| err(AudrenError::InvalidInstruction))?;
            ensure(net > 0, AudrenError::InvalidInstruction)?;
            if fee > 0 {
                Transfer {
                    from: depositor,
                    to: lane_rent_vault,
                    lamports: fee,
                }
                .invoke()?;
            }
            net
        } else {
            amount
        };

        let pre_lamports = vault_ata.lamports();
        Transfer {
            from: depositor,
            to: vault_ata,
            lamports: net_sol,
        }
        .invoke()?;

        let sync_data = [TOKEN_IX_SYNC_NATIVE];
        let sync_metas = [InstructionAccount::writable(vault_ata.address())];
        let sync_ix = InstructionView {
            program_id: token_prog.address(),
            accounts: &sync_metas,
            data: &sync_data,
        };
        invoke_signed(&sync_ix, &[&*vault_ata], &[])?;

        let vault_after = validate_token_account(
            vault_ata,
            token_prog.address(),
            mint_acc.address(),
            vault_auth.address(),
            true,
        )?;
        let expected_lamports = pre_lamports
            .checked_add(net_sol)
            .ok_or_else(|| err(AudrenError::Overflow))?;
        let min_vault_after = vault_before
            .checked_add(net_sol)
            .ok_or_else(|| err(AudrenError::Overflow))?;
        ensure(
            vault_ata.lamports() == expected_lamports && vault_after >= min_vault_after,
            AudrenError::CustodyInvariantViolated,
        )?;

        if !fee_from_amount {
            collect_lane_rent_fee(depositor, lane_rent_vault, &cfg, 1, 0)?;
        }
        net_sol
    } else {
        ensure(!fee_from_amount, AudrenError::InvalidInstruction)?;
        let blocked = [
            pool_acc.address(),
            roots_acc.address(),
            vault_auth.address(),
            lane_acc.address(),
            lane_rent_vault.address(),
            subtree_acc.address(),
            subroot_acc.address(),
            memo_acc.address(),
        ];
        invoke_token_transfer_checked(
            program_id,
            vault_auth.address(),
            token_prog,
            source_account,
            mint_acc,
            vault_ata,
            depositor,
            amount,
            mint_info,
            hook_candidates,
            &blocked,
            &[],
        )?;

        let vault_after = validate_token_account(
            vault_ata,
            token_prog.address(),
            mint_acc.address(),
            vault_auth.address(),
            true,
        )?;
        ensure(vault_after > vault_before, AudrenError::CustodyInvariantViolated)?;
        let net_received = vault_after - vault_before;

        collect_lane_rent_fee(depositor, lane_rent_vault, &cfg, 1, 0)?;
        net_received
    };

    let slot = Clock::get()?.slot;
    let mut mint_32 = [0u8; 32];
    mint_32.copy_from_slice(mint_acc.address().as_ref());
    let asset_id = derive_asset_id(&mint_32);
    let cm = compute_note_commitment(&stealth_owner, &asset_id, committed_amount, &blinding)?;
    append_leaf_and_memo(
        program_id,
        pool_id,
        lane_id,
        lane_acc,
        subtree_acc,
        sub_slot.first_mut(),
        subroot_acc,
        memo_acc,
        if has_next_memo { memo_slot.first_mut() } else { None },
        &cm,
        memo_entry,
        slot,
    )?;

    let (new_lane_root, new_next_leaf) = {
        let ld = lane_acc.try_borrow()?;
        (read_32(&ld, LN_OFF_CURRENT_ROOT), read_u64(&ld, LN_OFF_NEXT_LEAF))
    };
    update_global_root_history(
        program_id,
        pool_id,
        roots_acc,
        lane_id,
        &new_lane_root,
        new_next_leaf,
        slot,
        None,
    )
}

// =============================================================================
// 4. InitRootHistory (Authority-gated one-shot GlobalRootHistory initializer from live lanes)
// =============================================================================

#[inline(never)]
fn ix_init_root_history(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    // pool_id(4) + root_epoch_interval(8) = 12 B
    ensure(accounts.len() >= 4 && data.len() == 12, AudrenError::InvalidInstruction)?;
    let (head, lanes) = accounts.split_at_mut(4);
    let [authority, pool_acc, roots_acc, sys_prog] = head else {
        return Err(err(AudrenError::InvalidInstruction));
    };
    ensure(authority.is_signer(), AudrenError::Unauthorized)?;
    ensure(
        pool_acc.is_writable()
            && roots_acc.is_writable()
            && sys_prog.address() == &SYSTEM_PROGRAM_ID,
        AudrenError::InvalidAccount,
    )?;

    let pool_id = read_u32(data, 0);
    let root_epoch_interval = read_u64(data, 4);
    ensure(
        (1..=MAX_ROOT_EPOCH_INTERVAL).contains(&root_epoch_interval),
        AudrenError::InvalidInstruction,
    )?;

    let cfg = load_and_verify_pool(program_id, pool_id, pool_acc)?;
    ensure(
        cfg.authority != ZERO_ADDRESS && authority.address() == &cfg.authority,
        AudrenError::Unauthorized,
    )?;
    let active = cfg.active_lanes as usize;
    ensure(active <= NUM_LANES && lanes.len() == active, AudrenError::InvalidInstruction)?;

    let now = Clock::get()?.slot;
    let rent = RentParams::get()?;
    init_root_history_account(
        program_id,
        pool_id,
        root_epoch_interval,
        now,
        authority,
        roots_acc,
        sys_prog,
        lanes,
        rent,
    )?;

    let mut pd = pool_acc.try_borrow_mut()?;
    pd[PL_OFF_ROOT_EPOCH_INTERVAL..PL_OFF_ROOT_EPOCH_INTERVAL + 8]
        .copy_from_slice(&root_epoch_interval.to_le_bytes());
    pd[PL_OFF_RESERVED_24..PL_OFF_RESERVED_24 + 8].fill(0);
    Ok(())
}

// =============================================================================
// 5. Transact (Private Transfer w/ shielded fees / Merge / Public Withdraw w/ pause bypass)
// =============================================================================

#[inline(never)]
fn ix_transact(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    // pool_id(4) + vk_id(1) + out_lane(1) + output_mask(1) + asset_mode(1) + flags(1)
    // + root_ring_kind(1) + root_ring_idx(1)
    // + proof(192) + nf0(32) + nf1(32) + cm0(32) + cm1(32) + cm2(32) + pub_out(8) + rel_fee(8) = 379 B
    const FIXED_LEN: usize =
        4 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + GROTH16_PROOF_LEN + 32 * 5 + 8 + 8;
    const _: () = assert!(FIXED_LEN == 379);
    ensure(accounts.len() >= 12 && data.len() >= FIXED_LEN, AudrenError::InvalidInstruction)?;

    let (head, tail) = accounts.split_at_mut(12);
    let [payer, pool_acc, roots_acc, nf0_acc, nf1_acc, lane_acc, lane_rent_vault, subtree_acc, subroot_acc, memo_acc, nf_page_acc, sys_prog] =
        head
    else {
        return Err(err(AudrenError::InvalidInstruction));
    };

    ensure(
        payer.is_signer() && sys_prog.address() == &SYSTEM_PROGRAM_ID,
        AudrenError::InvalidAccount,
    )?;

    let pool_id = read_u32(data, 0);
    let vk_id = data[4];
    let out_lane_id = data[5];
    let output_mask = data[6];
    let asset_mode = data[7];
    let rollover_flags = data[8];
    let root_ring_kind = data[9];
    let root_ring_idx = data[10];
    let proof_192: &[u8; GROTH16_PROOF_LEN] =
        data[11..11 + GROTH16_PROOF_LEN].try_into().unwrap();
    let nf0 = read_32(data, 203);
    let nf1 = read_32(data, 235);
    let cm0 = read_32(data, 267);
    let cm1 = read_32(data, 299);
    let cm2 = read_32(data, 331);
    let public_amount_out = read_u64(data, 363);
    let relayer_fee_amount = read_u64(data, 371);
    let memos_bytes = &data[FIXED_LEN..];

    let num_outputs = (output_mask & 1).count_ones() as usize
        + ((output_mask >> 1) & 1).count_ones() as usize
        + ((output_mask >> 2) & 1).count_ones() as usize;
    let unwrap_wsol = (rollover_flags & WITHDRAW_FLAG_UNWRAP_WSOL) != 0;
    ensure(
        (out_lane_id as usize) < NUM_LANES
            && (output_mask & !0b111) == 0
            && (rollover_flags & !(0b111 | WITHDRAW_FLAG_UNWRAP_WSOL)) == 0
            && (!unwrap_wsol || (asset_mode == ASSET_MODE_PUBLIC && public_amount_out > 0))
            && nf0 != [0u8; 32]
            && memos_bytes.len() == num_outputs * MEMO_ENTRY_WIRE_LEN,
        AudrenError::InvalidInstruction,
    )?;
    ensure_canonical_fr(&nf0)?;
    ensure_canonical_fr(&nf1)?;
    ensure_canonical_fr(&cm0)?;
    ensure_canonical_fr(&cm1)?;
    ensure_canonical_fr(&cm2)?;

    let cfg = load_and_verify_pool(program_id, pool_id, pool_acc)?;
    ensure(out_lane_id < cfg.active_lanes, AudrenError::InvalidLane)?;

    // Non-custodial escape hatch: full withdrawals (`output_mask == 0 && public_amount_out > 0`)
    // ALWAYS succeed even when `pool.paused == true` (including `WITHDRAW_FLAG_UNWRAP_WSOL`)!
    let is_full_exit =
        output_mask == 0 && public_amount_out > 0 && asset_mode == ASSET_MODE_PUBLIC;
    if cfg.paused {
        ensure(is_full_exit, AudrenError::PoolPaused)?;
    }

    if num_outputs > 0 {
        ensure(roots_acc.is_writable(), AudrenError::InvalidAccount)?;
    }

    let now = Clock::get()?.slot;
    let super_root = verify_and_load_global_root(
        program_id,
        pool_id,
        roots_acc,
        root_ring_kind,
        root_ring_idx,
    )?;
    let rent_bump = verify_lane_pda(program_id, pool_id, out_lane_id, lane_acc)?;
    verify_lane_rent_vault(program_id, pool_id, out_lane_id, rent_bump, lane_rent_vault)?;
    let pool_le = pool_id.to_le_bytes();

    let outflow_cnt = match asset_mode {
        ASSET_MODE_PRIVATE => 0usize,
        ASSET_MODE_PUBLIC => {
            if unwrap_wsol {
                7usize
            } else {
                6usize
            }
        }
        _ => return Err(err(AudrenError::InvalidInstruction)),
    };
    ensure(tail.len() >= outflow_cnt, AudrenError::InvalidInstruction)?;
    let (outflow_tail, rest_after_outflow) = tail.split_at_mut(outflow_cnt);

    let has_next_sub = (rollover_flags & 1) != 0;
    let has_next_memo = (rollover_flags & 2) != 0;
    let has_next_nf = (rollover_flags & 4) != 0;
    let need_roll =
        usize::from(has_next_sub) + usize::from(has_next_memo) + usize::from(has_next_nf);
    ensure(rest_after_outflow.len() >= need_roll, AudrenError::InvalidInstruction)?;
    let (rollover_tail, hook_candidates) = rest_after_outflow.split_at_mut(need_roll);

    let total_outflow = public_amount_out
        .checked_add(relayer_fee_amount)
        .ok_or_else(|| err(AudrenError::Overflow))?;
    // Economy mode: `nf1 == [0;32]` is ONLY provable when `is_dummy[1] == true && amount[1] == 0`.
    let has_nf1 = nf1 != [0u8; 32];

    let (public_asset_id, recipient_key, relayer_fee_key, spl_mint_info, vault_before, unwrap_bump): (
        [u8; 32],
        [u8; 32],
        [u8; 32],
        Option<MintInfo>,
        u64,
        Option<u8>,
    ) = match asset_mode {
        ASSET_MODE_PRIVATE => {
            // Pure private transfers MUST NOT pay a public asset-disclosing relayer fee!
            // Relayers are compensated privately via shielded output `cm2`.
            ensure(total_outflow == 0, AudrenError::InvalidInstruction)?;
            ([0u8; 32], [0u8; 32], [0u8; 32], None, 0, None)
        }
        ASSET_MODE_PUBLIC => {
            // Public outflow mode requires `public_amount_out > 0`.
            ensure(public_amount_out > 0, AudrenError::InvalidInstruction)?;
            let vault_auth = &outflow_tail[0];
            let mint_acc = &outflow_tail[1];
            let vault_ata = &outflow_tail[2];
            let token_prog = &outflow_tail[3];
            let recipient_acc = &outflow_tail[4];
            let relayer_fee_acc = &outflow_tail[5];
            let exp_va = Address::create_program_address(
                &[VAULT_AUTH_SEED, &pool_le, &[cfg.vault_auth_bump]],
                program_id,
            )
            .map_err(|_| err(AudrenError::InvalidPda))?;
            ensure(vault_auth.address() == &exp_va, AudrenError::InvalidPda)?;
            let mi = load_mint_info(mint_acc, token_prog.address())?;
            let bal = validate_canonical_ata(
                vault_ata,
                token_prog.address(),
                mint_acc.address(),
                vault_auth.address(),
            )?;
            ensure(bal >= total_outflow, AudrenError::InsufficientVaultBalance)?;
            ensure(
                recipient_acc.address() != vault_ata.address()
                    && recipient_acc.address() != vault_auth.address()
                    && recipient_acc.address() != nf0_acc.address()
                    && (!has_nf1 || recipient_acc.address() != nf1_acc.address())
                    && recipient_acc.address() != program_id
                    && !recipient_acc.owned_by(program_id),
                AudrenError::InvalidAccount,
            )?;
            let unwrap_bump = if unwrap_wsol {
                ensure(
                    mint_acc.address() == &WSOL_MINT && token_prog.address() == &SPL_TOKEN_ID,
                    AudrenError::InvalidTokenAccount,
                )?;
                let unwrap_acc = &outflow_tail[6];
                let (exp_unwrap, bump) = unwrap_pda(program_id, pool_id, &nf0);
                ensure(unwrap_acc.address() == &exp_unwrap, AudrenError::InvalidPda)?;
                ensure(
                    unwrap_acc.is_writable()
                        && unwrap_acc.owned_by(&SYSTEM_PROGRAM_ID)
                        && unwrap_acc.is_data_empty(),
                    AudrenError::InvalidAccount,
                )?;
                ensure(
                    recipient_acc.is_writable() && recipient_acc.address() != unwrap_acc.address(),
                    AudrenError::InvalidAccount,
                )?;
                if let Some(rec_snap) = token_account_security(recipient_acc) {
                    ensure(
                        rec_snap.owner != *vault_auth.address(),
                        AudrenError::InvalidAccount,
                    )?;
                }
                if relayer_fee_amount > 0 {
                    ensure(
                        relayer_fee_acc.is_writable()
                            && relayer_fee_acc.address() != unwrap_acc.address()
                            && relayer_fee_acc.address() != vault_auth.address()
                            && relayer_fee_acc.address() != vault_ata.address()
                            && relayer_fee_acc.address() != nf0_acc.address()
                            && (!has_nf1 || relayer_fee_acc.address() != nf1_acc.address())
                            && relayer_fee_acc.address() != program_id
                            && !relayer_fee_acc.owned_by(program_id),
                        AudrenError::InvalidAccount,
                    )?;
                    if let Some(fee_snap) = token_account_security(relayer_fee_acc) {
                        ensure(
                            fee_snap.owner != *vault_auth.address(),
                            AudrenError::InvalidAccount,
                        )?;
                    }
                }
                Some(bump)
            } else {
                let rec_snap = token_account_security(recipient_acc)
                    .ok_or_else(|| err(AudrenError::InvalidTokenAccount))?;
                ensure(
                    recipient_acc.is_writable()
                        && rec_snap.token_program == *token_prog.address()
                        && rec_snap.mint == *mint_acc.address()
                        && rec_snap.owner != *vault_auth.address(),
                    AudrenError::InvalidAccount,
                )?;
                ensure(!rec_snap.is_frozen, AudrenError::InvalidTokenAccount)?;
                if relayer_fee_amount > 0 {
                    ensure(
                        relayer_fee_acc.address() != vault_ata.address()
                            && relayer_fee_acc.address() != vault_auth.address()
                            && relayer_fee_acc.address() != nf0_acc.address()
                            && (!has_nf1 || relayer_fee_acc.address() != nf1_acc.address())
                            && relayer_fee_acc.address() != program_id
                            && !relayer_fee_acc.owned_by(program_id),
                        AudrenError::InvalidAccount,
                    )?;
                    let fee_snap = token_account_security(relayer_fee_acc)
                        .ok_or_else(|| err(AudrenError::InvalidTokenAccount))?;
                    ensure(
                        relayer_fee_acc.is_writable()
                            && fee_snap.token_program == *token_prog.address()
                            && fee_snap.mint == *mint_acc.address()
                            && fee_snap.owner != *vault_auth.address(),
                        AudrenError::InvalidAccount,
                    )?;
                    ensure(!fee_snap.is_frozen, AudrenError::InvalidTokenAccount)?;
                }
                None
            };
            let mut m32 = [0u8; 32];
            m32.copy_from_slice(mint_acc.address().as_ref());
            let mut rk = [0u8; 32];
            rk.copy_from_slice(recipient_acc.address().as_ref());
            let mut fk = [0u8; 32];
            if relayer_fee_amount > 0 {
                fk.copy_from_slice(relayer_fee_acc.address().as_ref());
            }
            (derive_asset_id(&m32), rk, fk, Some(mi), bal, unwrap_bump)
        }
        _ => return Err(err(AudrenError::InvalidInstruction)),
    };

    let raw_ctx = sha256_v(&[
        CTX_DOMAIN_TRANSACT,
        program_id.as_ref(),
        &pool_le,
        &[vk_id, out_lane_id, output_mask, asset_mode, u8::from(unwrap_wsol)],
        &recipient_key,
        &relayer_fee_key,
        &public_asset_id,
        &public_amount_out.to_le_bytes(),
        &relayer_fee_amount.to_le_bytes(),
        memos_bytes,
    ]);
    let ctx_hash = mask_to_fr_be(&raw_ctx);

    let pub_hash = compute_public_input_hash(
        &super_root,
        &nf0,
        &nf1,
        &cm0,
        &cm1,
        &cm2,
        &public_asset_id,
        public_amount_out,
        relayer_fee_amount,
        &ctx_hash,
    )?;

    verify_joinsplit_proof_192(vk_id, proof_192, pub_hash)?;

    create_nullifier_pda(program_id, payer, nf0_acc, sys_prog, pool_id, &nf0)?;
    if has_nf1 {
        create_nullifier_pda(program_id, payer, nf1_acc, sys_prog, pool_id, &nf1)?;
    }

    let (sub_slot, rest1) = rollover_tail.split_at_mut(usize::from(has_next_sub));
    let (memo_slot, nf_slot) = rest1.split_at_mut(usize::from(has_next_memo));

    append_nullifier_prefix(
        program_id,
        pool_id,
        out_lane_id,
        lane_acc,
        nf_page_acc,
        if has_next_nf { nf_slot.first_mut() } else { None },
        &nf0,
        now,
    )?;
    if has_nf1 {
        append_nullifier_prefix(
            program_id,
            pool_id,
            out_lane_id,
            lane_acc,
            nf_page_acc,
            if has_next_nf { nf_slot.first_mut() } else { None },
            &nf1,
            now,
        )?;
    }

    let cms = [cm0, cm1, cm2];
    let mut memo_cursor = 0usize;
    for (idx, cm) in cms.iter().enumerate() {
        if (output_mask & (1 << idx)) != 0 {
            let memo_entry = &memos_bytes[memo_cursor..memo_cursor + MEMO_ENTRY_WIRE_LEN];
            memo_cursor += MEMO_ENTRY_WIRE_LEN;
            append_leaf_and_memo(
                program_id,
                pool_id,
                out_lane_id,
                lane_acc,
                subtree_acc,
                sub_slot.first_mut(),
                subroot_acc,
                memo_acc,
                memo_slot.first_mut(),
                cm,
                memo_entry,
                now,
            )?;
        }
    }

    if num_outputs > 0 {
        let (new_lane_root, new_next_leaf) = {
            let ld = lane_acc.try_borrow()?;
            (read_32(&ld, LN_OFF_CURRENT_ROOT), read_u64(&ld, LN_OFF_NEXT_LEAF))
        };
        update_global_root_history(
            program_id,
            pool_id,
            roots_acc,
            out_lane_id,
            &new_lane_root,
            new_next_leaf,
            now,
            if root_ring_kind == ROOT_RING_SLOT {
                Some(root_ring_idx)
            } else {
                None
            },
        )?;
    }

    if !cfg.paused {
        let num_nfs = if has_nf1 { 2u64 } else { 1u64 };
        collect_lane_rent_fee(payer, lane_rent_vault, &cfg, num_outputs as u64, num_nfs)?;
    }

    if asset_mode == ASSET_MODE_PUBLIC {
        let vault_auth = &outflow_tail[0];
        let mint_acc = &outflow_tail[1];
        let vault_ata = &outflow_tail[2];
        let token_prog = &outflow_tail[3];
        let recipient_acc = &outflow_tail[4];
        let relayer_fee_acc = &outflow_tail[5];
        let vab = [cfg.vault_auth_bump];
        let va_seeds = [Seed::from(VAULT_AUTH_SEED), Seed::from(&pool_le), Seed::from(&vab)];
        if unwrap_wsol {
            let unwrap_acc = &outflow_tail[6];
            let unwrap_bump = unwrap_bump.ok_or_else(|| err(AudrenError::InvalidPda))?;
            unwrap_wsol_and_payout(
                pool_id,
                &nf0,
                unwrap_bump,
                payer,
                sys_prog,
                vault_auth,
                mint_acc,
                vault_ata,
                recipient_acc,
                relayer_fee_acc,
                token_prog,
                unwrap_acc,
                public_amount_out,
                relayer_fee_amount,
                &[Signer::from(&va_seeds)],
            )?;
        } else {
            let mi = spl_mint_info.unwrap();
            let blocked = [
                payer.address(),
                pool_acc.address(),
                roots_acc.address(),
                nf0_acc.address(),
                if has_nf1 { nf1_acc.address() } else { nf0_acc.address() },
                lane_acc.address(),
                lane_rent_vault.address(),
                if num_outputs > 0 { subtree_acc.address() } else { pool_acc.address() },
                if num_outputs > 0 { subroot_acc.address() } else { pool_acc.address() },
                if num_outputs > 0 { memo_acc.address() } else { pool_acc.address() },
                nf_page_acc.address(),
                vault_auth.address(),
            ];
            invoke_token_transfer_checked(
                program_id,
                vault_auth.address(),
                token_prog,
                vault_ata,
                mint_acc,
                recipient_acc,
                vault_auth,
                public_amount_out,
                mi,
                hook_candidates,
                &blocked,
                &[Signer::from(&va_seeds)],
            )?;
            if relayer_fee_amount > 0 {
                invoke_token_transfer_checked(
                    program_id,
                    vault_auth.address(),
                    token_prog,
                    vault_ata,
                    mint_acc,
                    relayer_fee_acc,
                    vault_auth,
                    relayer_fee_amount,
                    mi,
                    hook_candidates,
                    &blocked,
                    &[Signer::from(&va_seeds)],
                )?;
            }
            let vault_after = validate_token_account(
                vault_ata,
                token_prog.address(),
                mint_acc.address(),
                vault_auth.address(),
                true,
            )?;
            ensure(
                vault_before.checked_sub(vault_after) == Some(total_outflow),
                AudrenError::CustodyInvariantViolated,
            )?;
        }
    }

    Ok(())
}

// =============================================================================
// 6. ExecViaEscrow (SPL / Token-2022 Escrow Firewall + `router_accounts` ctx_hash + XOR 72 B Memo)
// =============================================================================

#[inline(never)]
fn ix_exec_via_escrow(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    // pool_id(4) + vk_id(1) + out_lane(1) + escrow_shard(1) + change_mask(1) + flags(1)
    // + root_ring_kind(1) + root_ring_idx(1)
    // + proof(192) + nf0(32) + nf1(32) + cm0(32) + cm1(32) + cm2(32)
    // + amount_in(8) + min_amount_out(8) + relayer_fee_amount(8)
    // + out_stealth_owner(32) + out_blinding(32) + dyn_memo_head(34) + dyn_mask_72(72)
    // + router_ix_len(2) = 559 B (560 B w/ tag)
    const HEADER_LEN: usize =
        11 + GROTH16_PROOF_LEN + 32 * 5 + 8 * 3 + 32 + 32 + DYN_MEMO_HEAD_LEN + MEMO_CT_LEN + 2;
    const _: () = assert!(HEADER_LEN == 559);
    ensure(accounts.len() >= 14 && data.len() >= HEADER_LEN, AudrenError::InvalidInstruction)?;

    let (head, rest) = accounts.split_at_mut(14);
    let [payer, pool_acc, roots_acc, nf0_acc, nf1_acc, lane_acc, lane_rent_vault, subtree_acc, subroot_acc, memo_acc, nf_page_acc, escrow_acc, router_prog, sys_prog] =
        head
    else {
        return Err(err(AudrenError::InvalidInstruction));
    };

    ensure(
        payer.is_signer() && sys_prog.address() == &SYSTEM_PROGRAM_ID,
        AudrenError::InvalidAccount,
    )?;

    let pool_id = read_u32(data, 0);
    let vk_id = data[4];
    let out_lane_id = data[5];
    let escrow_shard = data[6];
    let change_mask = data[7];
    let rollover_flags = data[8];
    let root_ring_kind = data[9];
    let root_ring_idx = data[10];
    let proof_192: &[u8; GROTH16_PROOF_LEN] =
        data[11..11 + GROTH16_PROOF_LEN].try_into().unwrap();
    let nf0 = read_32(data, 203);
    let nf1 = read_32(data, 235);
    let cm0 = read_32(data, 267);
    let cm1 = read_32(data, 299);
    let cm2 = read_32(data, 331);
    let amount_in = read_u64(data, 363);
    let min_amount_out = read_u64(data, 371);
    let relayer_fee_amount = read_u64(data, 379);
    let out_stealth_owner = read_32(data, 387);
    let out_blinding = read_32(data, 419);
    let dyn_memo_head = &data[451..451 + DYN_MEMO_HEAD_LEN];
    let dyn_mask_72 = &data[485..485 + MEMO_CT_LEN];
    let router_ix_len = read_u16(data, 557) as usize;

    let num_changes = (change_mask & 1).count_ones() as usize
        + ((change_mask >> 1) & 1).count_ones() as usize;
    let fee_on_output = (rollover_flags & EXEC_FLAG_FEE_ON_OUTPUT) != 0;
    ensure((escrow_shard as usize) < NUM_ESCROW_SHARDS, AudrenError::InvalidEscrowShard)?;
    ensure(
        (out_lane_id as usize) < NUM_LANES
            && (change_mask & !0b11) == 0
            && (rollover_flags & !(0b111 | EXEC_FLAG_FEE_ON_OUTPUT)) == 0
            && (!fee_on_output || relayer_fee_amount > 0)
            && amount_in > 0
            && nf0 != [0u8; 32]
            && out_blinding != [0u8; 32]
            && data.len() == HEADER_LEN + router_ix_len + num_changes * MEMO_ENTRY_WIRE_LEN,
        AudrenError::InvalidInstruction,
    )?;
    ensure_canonical_fr(&nf0)?;
    ensure_canonical_fr(&nf1)?;
    ensure_canonical_fr(&cm0)?;
    ensure_canonical_fr(&cm1)?;
    ensure_canonical_fr(&cm2)?;
    ensure_canonical_fr(&out_stealth_owner)?;
    ensure_canonical_fr(&out_blinding)?;

    let router_ix_data = &data[HEADER_LEN..HEADER_LEN + router_ix_len];
    let change_memos = &data[HEADER_LEN + router_ix_len..];

    let cfg = load_and_verify_pool(program_id, pool_id, pool_acc)?;
    ensure(!cfg.paused, AudrenError::PoolPaused)?;
    ensure(out_lane_id < cfg.active_lanes, AudrenError::InvalidLane)?;
    ensure(roots_acc.is_writable(), AudrenError::InvalidAccount)?;

    let now = Clock::get()?.slot;
    let super_root = verify_and_load_global_root(
        program_id,
        pool_id,
        roots_acc,
        root_ring_kind,
        root_ring_idx,
    )?;
    let rent_bump = verify_lane_pda(program_id, pool_id, out_lane_id, lane_acc)?;
    verify_lane_rent_vault(program_id, pool_id, out_lane_id, rent_bump, lane_rent_vault)?;
    let pool_le = pool_id.to_le_bytes();

    // Strict escrow PDA & target program denylist
    let (exp_escrow, escrow_bump) = escrow_pda(program_id, pool_id, escrow_shard);
    ensure(escrow_acc.address() == &exp_escrow, AudrenError::InvalidPda)?;
    ensure(
        escrow_acc.owned_by(&SYSTEM_PROGRAM_ID) && escrow_acc.is_data_empty(),
        AudrenError::EscrowAuthorityAltered,
    )?;
    ensure(
        router_prog.executable()
            && router_prog.address() != program_id
            && router_prog.address() != &SYSTEM_PROGRAM_ID
            && router_prog.address() != &SPL_TOKEN_ID
            && router_prog.address() != &TOKEN_2022_ID
            && router_prog.address() != &ATA_PROGRAM_ID
            && router_prog.address() != &ELGAMAL_REGISTRY_ID,
        AudrenError::InvalidTargetProgram,
    )?;

    let exp_va = Address::create_program_address(
        &[VAULT_AUTH_SEED, &pool_le, &[cfg.vault_auth_bump]],
        program_id,
    )
    .map_err(|_| err(AudrenError::InvalidPda))?;

    // Split SPL/Token-2022 leg accounts + optional rollover accounts + router accounts
    let has_fee = relayer_fee_amount > 0;
    let has_in_fee = has_fee && !fee_on_output;
    let has_out_fee = has_fee && fee_on_output;
    let in_cnt = 5 + usize::from(has_in_fee);
    let out_cnt = 5 + usize::from(has_out_fee);
    let has_next_sub = (rollover_flags & 1) != 0;
    let has_next_memo = (rollover_flags & 2) != 0;
    let has_next_nf = (rollover_flags & 4) != 0;
    let roll_cnt = usize::from(has_next_sub) + usize::from(has_next_memo) + usize::from(has_next_nf);
    ensure(rest.len() > in_cnt + out_cnt + roll_cnt, AudrenError::InvalidInstruction)?;

    let (in_leg, rest2) = rest.split_at_mut(in_cnt);
    let (out_leg, rest3) = rest2.split_at_mut(out_cnt);
    let (roll_leg, router_accounts) = rest3.split_at_mut(roll_cnt);

    let circuit_relayer_fee = if fee_on_output { 0 } else { relayer_fee_amount };
    let total_in_outflow = amount_in
        .checked_add(circuit_relayer_fee)
        .ok_or_else(|| err(AudrenError::Overflow))?;
    // Economy mode: `nf1 == [0;32]` is ONLY provable when `is_dummy[1] == true && amount[1] == 0`.
    let has_nf1 = nf1 != [0u8; 32];

    let mut forbidden_keys: [Address; 6] = [ZERO_ADDRESS; 6];
    let mut forbidden_len = 0usize;
    forbidden_keys[forbidden_len] = exp_va;
    forbidden_len += 1;

    // Validate SPL/Token-2022 input leg (enforcing canonical vault & escrow ATAs) and derive `asset_in`
    let mut relayer_fee_key = [0u8; 32];
    let (asset_in, in_mint_info, pre_vault_in_spl, pre_escrow_in_spl) = {
        let va_in = &in_leg[0];
        let mint_in = &in_leg[1];
        let vault_in_ata = &in_leg[2];
        let escrow_in_ata = &in_leg[3];
        let token_prog_in = &in_leg[4];
        ensure(va_in.address() == &exp_va, AudrenError::InvalidPda)?;
        let mi = load_mint_info(mint_in, token_prog_in.address())?;
        let v_bal = validate_canonical_ata(
            vault_in_ata,
            token_prog_in.address(),
            mint_in.address(),
            va_in.address(),
        )?;
        ensure(v_bal >= total_in_outflow, AudrenError::InsufficientVaultBalance)?;
        let e_bal = validate_canonical_ata(
            escrow_in_ata,
            token_prog_in.address(),
            mint_in.address(),
            escrow_acc.address(),
        )?;
        forbidden_keys[forbidden_len] = *vault_in_ata.address();
        forbidden_len += 1;
        if has_in_fee {
            let fee_ata = &in_leg[5];
            ensure(
                fee_ata.address() != vault_in_ata.address()
                    && fee_ata.address() != escrow_in_ata.address()
                    && fee_ata.address() != &exp_va
                    && fee_ata.address() != &exp_escrow
                    && fee_ata.address() != nf0_acc.address()
                    && (!has_nf1 || fee_ata.address() != nf1_acc.address())
                    && fee_ata.address() != program_id
                    && !fee_ata.owned_by(program_id),
                AudrenError::InvalidAccount,
            )?;
            let fee_snap = token_account_security(fee_ata)
                .ok_or_else(|| err(AudrenError::InvalidTokenAccount))?;
            ensure(
                fee_ata.is_writable()
                    && fee_snap.token_program == *token_prog_in.address()
                    && fee_snap.mint == *mint_in.address()
                    && fee_snap.owner != exp_va
                    && fee_snap.owner != exp_escrow,
                AudrenError::InvalidAccount,
            )?;
            ensure(!fee_snap.is_frozen, AudrenError::InvalidTokenAccount)?;
            forbidden_keys[forbidden_len] = *fee_ata.address();
            forbidden_len += 1;
            relayer_fee_key.copy_from_slice(fee_ata.address().as_ref());
        }
        let mut m32 = [0u8; 32];
        m32.copy_from_slice(mint_in.address().as_ref());
        (derive_asset_id(&m32), mi, v_bal, e_bal)
    };

    // Validate SPL/Token-2022 output leg (enforcing canonical vault & escrow ATAs) and derive `asset_out`
    let (asset_out, mint_out_32, out_mint_info, pre_escrow_out_spl) = {
        let va_out = &out_leg[0];
        let mint_out = &out_leg[1];
        let vault_out_ata = &out_leg[2];
        let escrow_out_ata = &out_leg[3];
        let token_prog_out = &out_leg[4];
        ensure(va_out.address() == &exp_va, AudrenError::InvalidPda)?;
        let mi = load_mint_info(mint_out, token_prog_out.address())?;
        let _ = validate_canonical_ata(
            vault_out_ata,
            token_prog_out.address(),
            mint_out.address(),
            va_out.address(),
        )?;
        let e_bal = validate_canonical_ata(
            escrow_out_ata,
            token_prog_out.address(),
            mint_out.address(),
            escrow_acc.address(),
        )?;
        forbidden_keys[forbidden_len] = *vault_out_ata.address();
        forbidden_len += 1;
        if has_out_fee {
            let fee_ata = &out_leg[5];
            ensure(
                fee_ata.address() != vault_out_ata.address()
                    && fee_ata.address() != escrow_out_ata.address()
                    && fee_ata.address() != &exp_va
                    && fee_ata.address() != &exp_escrow
                    && fee_ata.address() != nf0_acc.address()
                    && (!has_nf1 || fee_ata.address() != nf1_acc.address())
                    && fee_ata.address() != program_id
                    && !fee_ata.owned_by(program_id),
                AudrenError::InvalidAccount,
            )?;
            let fee_snap = token_account_security(fee_ata)
                .ok_or_else(|| err(AudrenError::InvalidTokenAccount))?;
            ensure(
                fee_ata.is_writable()
                    && fee_snap.token_program == *token_prog_out.address()
                    && fee_snap.mint == *mint_out.address()
                    && fee_snap.owner != exp_va
                    && fee_snap.owner != exp_escrow,
                AudrenError::InvalidAccount,
            )?;
            ensure(!fee_snap.is_frozen, AudrenError::InvalidTokenAccount)?;
            forbidden_keys[forbidden_len] = *fee_ata.address();
            forbidden_len += 1;
            relayer_fee_key.copy_from_slice(fee_ata.address().as_ref());
        }
        let mut m32 = [0u8; 32];
        m32.copy_from_slice(mint_out.address().as_ref());
        (derive_asset_id(&m32), m32, mi, e_bal)
    };

    // Forbid self-swaps (Mint X -> Mint X)
    ensure(asset_in != asset_out, AudrenError::InvalidInstruction)?;

    // Cryptographically bind every router account pubkey, order, & writable flag inside ctx_hash.
    let router_accs_hash = hash_router_accounts_arena(router_accounts)?;

    let raw_ctx = sha256_v(&[
        CTX_DOMAIN_EXEC_VIA_ESCROW,
        program_id.as_ref(),
        &pool_le,
        &[
            vk_id,
            out_lane_id,
            escrow_shard,
            change_mask,
            u8::from(fee_on_output),
        ],
        &asset_in,
        &amount_in.to_le_bytes(),
        &relayer_fee_amount.to_le_bytes(),
        &relayer_fee_key,
        &asset_out,
        &min_amount_out.to_le_bytes(),
        router_prog.address().as_ref(),
        &router_accs_hash,
        &out_stealth_owner,
        &out_blinding,
        dyn_memo_head,
        dyn_mask_72,
        &(router_ix_len as u16).to_le_bytes(),
        router_ix_data,
        change_memos,
    ]);
    let ctx_hash = mask_to_fr_be(&raw_ctx);

    let pub_hash = compute_public_input_hash(
        &super_root,
        &nf0,
        &nf1,
        &cm0,
        &cm1,
        &cm2,
        &asset_in,
        amount_in,
        circuit_relayer_fee,
        &ctx_hash,
    )?;

    verify_joinsplit_proof_192(vk_id, proof_192, pub_hash)?;

    // Nullifier-first ordering (prevents re-entrancy / replay) + economy `nf1 == 0` support
    create_nullifier_pda(program_id, payer, nf0_acc, sys_prog, pool_id, &nf0)?;
    if has_nf1 {
        create_nullifier_pda(program_id, payer, nf1_acc, sys_prog, pool_id, &nf1)?;
    }

    let (sub_slot, rest_roll1) = roll_leg.split_at_mut(usize::from(has_next_sub));
    let (memo_slot, nf_slot) = rest_roll1.split_at_mut(usize::from(has_next_memo));

    append_nullifier_prefix(
        program_id,
        pool_id,
        out_lane_id,
        lane_acc,
        nf_page_acc,
        if has_next_nf { nf_slot.first_mut() } else { None },
        &nf0,
        now,
    )?;
    if has_nf1 {
        append_nullifier_prefix(
            program_id,
            pool_id,
            out_lane_id,
            lane_acc,
            nf_page_acc,
            if has_next_nf { nf_slot.first_mut() } else { None },
            &nf1,
            now,
        )?;
    }

    // Persist shielded change note(s) in `asset_in`
    let mut cm_cursor = 0usize;
    if (change_mask & 1) != 0 {
        let memo_entry = &change_memos[cm_cursor..cm_cursor + MEMO_ENTRY_WIRE_LEN];
        cm_cursor += MEMO_ENTRY_WIRE_LEN;
        append_leaf_and_memo(
            program_id,
            pool_id,
            out_lane_id,
            lane_acc,
            subtree_acc,
            sub_slot.first_mut(),
            subroot_acc,
            memo_acc,
            memo_slot.first_mut(),
            &cm0,
            memo_entry,
            now,
        )?;
    }
    if (change_mask & 2) != 0 {
        let memo_entry = &change_memos[cm_cursor..cm_cursor + MEMO_ENTRY_WIRE_LEN];
        append_leaf_and_memo(
            program_id,
            pool_id,
            out_lane_id,
            lane_acc,
            subtree_acc,
            sub_slot.first_mut(),
            subroot_acc,
            memo_acc,
            memo_slot.first_mut(),
            &cm1,
            memo_entry,
            now,
        )?;
    }

    // Collect self-balancing `LaneRentVault` fees for (1 dynamic output + change notes, 1 or 2 nfs)
    let total_notes = 1u64 + num_changes as u64;
    let total_nfs = if has_nf1 { 2u64 } else { 1u64 };
    collect_lane_rent_fee(payer, lane_rent_vault, &cfg, total_notes, total_nfs)?;

    // WatchedEscrowBuf firewall + escrow funding + router CPI + post-CPI audit
    let shard_b = [escrow_shard];
    let eb_b = [escrow_bump];
    let escrow_seeds = [
        Seed::from(ESCROW_SEED),
        Seed::from(&pool_le),
        Seed::from(&shard_b),
        Seed::from(&eb_b),
    ];
    let vab = [cfg.vault_auth_bump];
    let va_seeds = [Seed::from(VAULT_AUTH_SEED), Seed::from(&pool_le), Seed::from(&vab)];
    let blocked_hook = [
        payer.address(),
        pool_acc.address(),
        roots_acc.address(),
        nf0_acc.address(),
        if has_nf1 { nf1_acc.address() } else { nf0_acc.address() },
        lane_acc.address(),
        lane_rent_vault.address(),
        subtree_acc.address(),
        subroot_acc.address(),
        memo_acc.address(),
        nf_page_acc.address(),
        &exp_va,
    ];

    let escrow_sol_baseline = escrow_acc.lamports();
    WatchedEscrowBuf::with_buf(|watched_escrow_accs| -> ProgramResult {
        let mut pre_token_mask: u128 = 0;
        for (idx, acc) in router_accounts.iter().enumerate() {
            let a = acc.address();
            ensure(
                a != program_id
                    && !acc.owned_by(program_id)
                    && a != &ELGAMAL_REGISTRY_ID
                    && !acc.owned_by(&ELGAMAL_REGISTRY_ID),
                AudrenError::ForbiddenRouterAccount,
            )?;
            for fk in &forbidden_keys[..forbidden_len] {
                ensure(a != fk, AudrenError::ForbiddenRouterAccount)?;
            }
            let pre_snap = token_account_security(acc);
            if let Some(ref snap) = pre_snap {
                ensure(snap.owner != exp_va, AudrenError::ForbiddenRouterAccount)?;
            }
            if !acc.is_writable() {
                continue;
            }
            if let Some(snap) = pre_snap {
                pre_token_mask |= 1u128 << idx;
                if snap.owner == exp_escrow {
                    ensure(
                        !snap.is_frozen
                            && !snap.has_delegate
                            && snap.close_authority.is_none()
                            && !snap.has_restrictive_ext,
                        AudrenError::EscrowAccountAltered,
                    )?;
                    watched_escrow_accs.push(idx, snap.token_program, snap.data_len);
                }
            }
        }

        // Fund isolated escrow (+ optional input-side relayer fee) from unified `vault_in_ata`
        let va_in = &in_leg[0];
        let mint_in = &in_leg[1];
        let vault_in_ata = &in_leg[2];
        let escrow_in_ata = &in_leg[3];
        let token_prog_in = &in_leg[4];
        invoke_token_transfer_checked(
            program_id,
            va_in.address(),
            token_prog_in,
            vault_in_ata,
            mint_in,
            escrow_in_ata,
            va_in,
            amount_in,
            in_mint_info,
            router_accounts,
            &blocked_hook,
            &[Signer::from(&va_seeds)],
        )?;
        if has_in_fee {
            invoke_token_transfer_checked(
                program_id,
                va_in.address(),
                token_prog_in,
                vault_in_ata,
                mint_in,
                &in_leg[5],
                va_in,
                relayer_fee_amount,
                in_mint_info,
                router_accounts,
                &blocked_hook,
                &[Signer::from(&va_seeds)],
            )?;
        }
        let vault_in_after = validate_token_account(
            vault_in_ata,
            token_prog_in.address(),
            mint_in.address(),
            va_in.address(),
            true,
        )?;
        ensure(
            pre_vault_in_spl.checked_sub(vault_in_after) == Some(total_in_outflow),
            AudrenError::CustodyInvariantViolated,
        )?;

        // Invoke external DeFi router CPI via zero-alloc 64-account arena, signed ONLY by `escrow_acc`
        invoke_router_cpi_arena(
            router_prog.address(),
            router_ix_data,
            router_accounts,
            escrow_acc.address(),
            &[Signer::from(&escrow_seeds)],
        )?;

        // Unconditional post-CPI `escrow_acc` ownership, data, and lamport check.
        ensure(
            escrow_acc.owned_by(&SYSTEM_PROGRAM_ID)
                && escrow_acc.is_data_empty()
                && escrow_acc.lamports() >= escrow_sol_baseline,
            AudrenError::EscrowAuthorityAltered,
        )?;

        // Verify every pre-existing writable escrow-owned token account against tampering & TLV edits.
        for entry in watched_escrow_accs.as_slice() {
            let acc = &router_accounts[entry.idx as usize];
            let Some(snap) = token_account_security(acc) else {
                return Err(err(AudrenError::EscrowAccountAltered));
            };
            ensure(
                snap.token_program == entry.token_program
                    && snap.owner == exp_escrow
                    && !snap.is_frozen
                    && !snap.has_delegate
                    && snap.close_authority.is_none()
                    && !snap.has_restrictive_ext
                    && snap.data_len == entry.data_len,
                AudrenError::EscrowAccountAltered,
            )?;
        }

        // Post-CPI rescan for newly created token accounts (blocks creating & hijacking a canonical escrow ATA!)
        for (idx, acc) in router_accounts.iter().enumerate() {
            if !acc.is_writable() || (pre_token_mask & (1u128 << idx)) != 0 {
                continue;
            }
            if let Some(post_snap) = token_account_security(acc) {
                let is_escrow_owned = post_snap.owner == exp_escrow;
                let is_canonical_escrow_ata = acc.address()
                    == &expected_ata(&exp_escrow, &post_snap.token_program, &post_snap.mint);
                if is_escrow_owned || is_canonical_escrow_ata {
                    ensure(
                        is_escrow_owned
                            && !post_snap.is_frozen
                            && !post_snap.has_delegate
                            && post_snap.close_authority.is_none()
                            && !post_snap.has_restrictive_ext,
                        AudrenError::EscrowAccountAltered,
                    )?;
                }
            }
        }
        Ok(())
    })?;

    // Exact input drain check (ZERO trapped input dust!)
    let post_escrow_in = validate_token_account(
        &in_leg[3],
        in_leg[4].address(),
        in_leg[1].address(),
        escrow_acc.address(),
        true,
    )?;
    ensure(post_escrow_in == pre_escrow_in_spl, AudrenError::EscrowNotDrained)?;

    // Sweep actual output from isolated escrow -> unified output vault (& optional output-side
    // relayer fee directly from escrow) & measure exact net user vault delta!
    let actual_out = {
        let va_out = &out_leg[0];
        let mint_out = &out_leg[1];
        let vault_out_ata = &out_leg[2];
        let escrow_out_ata = &out_leg[3];
        let token_prog_out = &out_leg[4];
        let post_escrow_out = validate_token_account(
            escrow_out_ata,
            token_prog_out.address(),
            mint_out.address(),
            escrow_acc.address(),
            true,
        )?;
        ensure(post_escrow_out > pre_escrow_out_spl, AudrenError::SlippageExceeded)?;
        let gross_out = post_escrow_out - pre_escrow_out_spl;
        let user_gross_out = if has_out_fee {
            let rem = gross_out
                .checked_sub(relayer_fee_amount)
                .ok_or_else(|| err(AudrenError::SlippageExceeded))?;
            ensure(rem > 0, AudrenError::SlippageExceeded)?;
            invoke_token_transfer_checked(
                program_id,
                va_out.address(),
                token_prog_out,
                escrow_out_ata,
                mint_out,
                &out_leg[5],
                escrow_acc,
                relayer_fee_amount,
                out_mint_info,
                router_accounts,
                &blocked_hook,
                &[Signer::from(&escrow_seeds)],
            )?;
            rem
        } else {
            gross_out
        };
        let vault_before_sweep = validate_token_account(
            vault_out_ata,
            token_prog_out.address(),
            mint_out.address(),
            va_out.address(),
            true,
        )?;
        invoke_token_transfer_checked(
            program_id,
            va_out.address(),
            token_prog_out,
            escrow_out_ata,
            mint_out,
            vault_out_ata,
            escrow_acc,
            user_gross_out,
            out_mint_info,
            router_accounts,
            &blocked_hook,
            &[Signer::from(&escrow_seeds)],
        )?;
        let post_sweep_escrow_out = validate_token_account(
            escrow_out_ata,
            token_prog_out.address(),
            mint_out.address(),
            escrow_acc.address(),
            true,
        )?;
        ensure(
            post_sweep_escrow_out == pre_escrow_out_spl,
            AudrenError::CustodyInvariantViolated,
        )?;
        let vault_after_sweep = validate_token_account(
            vault_out_ata,
            token_prog_out.address(),
            mint_out.address(),
            va_out.address(),
            true,
        )?;
        ensure(vault_after_sweep > vault_before_sweep, AudrenError::CustodyInvariantViolated)?;
        let net_out = vault_after_sweep - vault_before_sweep;
        ensure(net_out >= min_amount_out && net_out > 0, AudrenError::SlippageExceeded)?;
        net_out
    };

    // Commit dynamic output using user's ECDH `out_blinding` and XOR-mask the 72 B dynamic
    // payload (`AUD1DYN1[8] || actual_out[8] || mint_out[32] || [0u8; 24]`) with `dyn_mask_72`
    // so zero plaintext magic/amount/mint sits at rest in `MemoPage`.
    let dynamic_cm =
        compute_note_commitment(&out_stealth_owner, &asset_out, actual_out, &out_blinding)?;

    let mut plain_72 = [0u8; MEMO_CT_LEN];
    plain_72[0..8].copy_from_slice(&DYN_MEMO_MAGIC);
    plain_72[8..16].copy_from_slice(&actual_out.to_le_bytes());
    plain_72[16..48].copy_from_slice(&mint_out_32);

    let mut stamped_dyn_memo = [0u8; MEMO_ENTRY_WIRE_LEN];
    stamped_dyn_memo[0..DYN_MEMO_HEAD_LEN].copy_from_slice(dyn_memo_head);
    for i in 0..MEMO_CT_LEN {
        stamped_dyn_memo[DYN_MEMO_HEAD_LEN + i] = plain_72[i] ^ dyn_mask_72[i];
    }

    append_leaf_and_memo(
        program_id,
        pool_id,
        out_lane_id,
        lane_acc,
        subtree_acc,
        sub_slot.first_mut(),
        subroot_acc,
        memo_acc,
        memo_slot.first_mut(),
        &dynamic_cm,
        &stamped_dyn_memo,
        now,
    )?;

    let (new_lane_root, new_next_leaf) = {
        let ld = lane_acc.try_borrow()?;
        (read_32(&ld, LN_OFF_CURRENT_ROOT), read_u64(&ld, LN_OFF_NEXT_LEAF))
    };
    update_global_root_history(
        program_id,
        pool_id,
        roots_acc,
        out_lane_id,
        &new_lane_root,
        new_next_leaf,
        now,
        if root_ring_kind == ROOT_RING_SLOT {
            Some(root_ring_idx)
        } else {
            None
        },
    )
}

// =============================================================================
// 7. SetPaused (authority-only emergency pause; full exits & OpenPage always remain open)
// =============================================================================

#[inline(never)]
fn ix_set_paused(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    // pool_id(4) + paused(1: 0 or 1) = 5 B
    ensure(data.len() == 5, AudrenError::InvalidInstruction)?;
    let [authority, pool_acc, ..] = accounts else {
        return Err(err(AudrenError::InvalidInstruction));
    };
    ensure(authority.is_signer(), AudrenError::Unauthorized)?;
    ensure(pool_acc.is_writable(), AudrenError::InvalidAccount)?;
    let pool_id = read_u32(data, 0);
    let paused = data[4];
    ensure(paused <= 1, AudrenError::InvalidInstruction)?;

    let cfg = load_and_verify_pool(program_id, pool_id, pool_acc)?;
    ensure(
        cfg.authority != ZERO_ADDRESS && authority.address() == &cfg.authority,
        AudrenError::Unauthorized,
    )?;
    let mut pd = pool_acc.try_borrow_mut()?;
    pd[PL_OFF_PAUSED] = paused;
    Ok(())
}

// =============================================================================
// 8. UpdatePool (params, two-step authority transfer, and renounce when !paused)
// =============================================================================

#[inline(never)]
fn ix_update_pool(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    // pool_id(4) + action(1) + action-specific payload
    ensure(data.len() >= 5, AudrenError::InvalidInstruction)?;
    let [signer, pool_acc, ..] = accounts else {
        return Err(err(AudrenError::InvalidInstruction));
    };
    ensure(signer.is_signer(), AudrenError::Unauthorized)?;
    ensure(pool_acc.is_writable(), AudrenError::InvalidAccount)?;

    let pool_id = read_u32(data, 0);
    let action = data[4];
    let cfg = load_and_verify_pool(program_id, pool_id, pool_acc)?;

    match action {
        UPDATE_POOL_PARAMS => {
            // pool_id(4) + action(1) + note_rent_fee(8) + nf_rent_fee(8) = 21 B
            ensure(data.len() == 21, AudrenError::InvalidInstruction)?;
            ensure(
                cfg.authority != ZERO_ADDRESS && signer.address() == &cfg.authority,
                AudrenError::Unauthorized,
            )?;
            let note_rent_fee = read_u64(data, 5);
            let nf_rent_fee = read_u64(data, 13);
            let mut pd = pool_acc.try_borrow_mut()?;
            pd[PL_OFF_NOTE_RENT_FEE..PL_OFF_NOTE_RENT_FEE + 8]
                .copy_from_slice(&note_rent_fee.to_le_bytes());
            pd[PL_OFF_NF_RENT_FEE..PL_OFF_NF_RENT_FEE + 8]
                .copy_from_slice(&nf_rent_fee.to_le_bytes());
            Ok(())
        }
        UPDATE_POOL_PROPOSE_AUTHORITY => {
            // pool_id(4) + action(1) + pending_authority(32) = 37 B
            ensure(data.len() == 37, AudrenError::InvalidInstruction)?;
            ensure(
                cfg.authority != ZERO_ADDRESS && signer.address() == &cfg.authority,
                AudrenError::Unauthorized,
            )?;
            let mut pd = pool_acc.try_borrow_mut()?;
            pd[PL_OFF_PENDING_AUTHORITY..PL_OFF_PENDING_AUTHORITY + 32]
                .copy_from_slice(&data[5..37]);
            Ok(())
        }
        UPDATE_POOL_ACCEPT_AUTHORITY => {
            // pool_id(4) + action(1) = 5 B
            ensure(data.len() == 5, AudrenError::InvalidInstruction)?;
            ensure(
                cfg.authority != ZERO_ADDRESS
                    && cfg.pending_authority != ZERO_ADDRESS
                    && signer.address() == &cfg.pending_authority,
                AudrenError::Unauthorized,
            )?;
            let mut pd = pool_acc.try_borrow_mut()?;
            pd[PL_OFF_AUTHORITY..PL_OFF_AUTHORITY + 32]
                .copy_from_slice(cfg.pending_authority.as_ref());
            pd[PL_OFF_PENDING_AUTHORITY..PL_OFF_PENDING_AUTHORITY + 32].fill(0);
            Ok(())
        }
        UPDATE_POOL_RENOUNCE_AUTHORITY => {
            // pool_id(4) + action(1) = 5 B
            ensure(data.len() == 5, AudrenError::InvalidInstruction)?;
            ensure(
                cfg.authority != ZERO_ADDRESS && signer.address() == &cfg.authority,
                AudrenError::Unauthorized,
            )?;
            ensure(!cfg.paused, AudrenError::PoolPaused)?;
            let mut pd = pool_acc.try_borrow_mut()?;
            pd[PL_OFF_AUTHORITY..PL_OFF_AUTHORITY + 32].fill(0);
            pd[PL_OFF_PENDING_AUTHORITY..PL_OFF_PENDING_AUTHORITY + 32].fill(0);
            Ok(())
        }
        _ => Err(err(AudrenError::InvalidInstruction)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_security_txt_matches_package_version() {
        let ver = concat!("source_release\0v", env!("CARGO_PKG_VERSION"), "\0");
        assert!(SECURITY_TXT.contains(ver));
        assert!(SECURITY_TXT.contains("email:security@audren.xyz"));
    }

    #[test]
    fn asset_id_is_canonical_and_distinct() {
        let wsol = derive_asset_id(&audren_core::WSOL_MINT);
        let usdc_mock = derive_asset_id(&[0x11u8; 32]);
        assert!(audren_core::is_canonical_fr(&wsol));
        assert!(audren_core::is_canonical_fr(&usdc_mock));
        assert_ne!(wsol, usdc_mock);
    }

    #[test]
    fn canonical_pda_derivation_is_deterministic() {
        let prog = Address::new_from_array(audren_core::AUDREN_PROGRAM_ID);
        let (p0, pb) = pool_pda(&prog, 0);
        let (va0, vab) = vault_auth_pda(&prog, 0);
        let (rt0, rtb) = roots_pda(&prog, 0);
        assert_eq!(
            p0,
            Address::new_from_array(audren_core::decode_base58(
                "5Bvt5f5QMfsVb9TyX8bzkRMvAX6JSWwRtnymGveF9U3G"
            ))
        );
        assert_eq!(pb, 255);
        assert_eq!(
            va0,
            Address::new_from_array(audren_core::decode_base58(
                "3aMtBvVMatfBvoBWQaTxCPwQ2SWyW5ejceVgLFTtk2WF"
            ))
        );
        assert_eq!(vab, 255);
        assert_eq!(
            rt0,
            Address::new_from_array(audren_core::decode_base58(
                "249YJTuRtiKAnh346Tc18kF9bHrktdrTzyJMtvUKUgC7"
            ))
        );
        assert_eq!(rtb, 254);
        assert_ne!(p0, va0);
        assert_ne!(p0, rt0);
        assert_ne!(va0, rt0);
    }

    #[test]
    fn rent_minimum_balance_pure_integer_ieee754() {
        const LPBY: u64 = 3_480;
        const TWO_POW_64: f64 = 18_446_744_073_709_551_616.0; // exact 2^64 in binary64

        // Reference Agave `Rent::minimum_balance` formula on host (`f64` -> `u64` truncation).
        let check_matches_agave = |lpby: u64, threshold: f64, data_len: usize| {
            let total_bytes = 128u64.checked_add(u64::try_from(data_len).unwrap());
            let base = total_bytes.and_then(|b| b.checked_mul(lpby));
            let actual = compute_rent_minimum_balance(lpby, threshold.to_bits(), data_len);
            match base {
                None => assert_eq!(actual, Err(err(AudrenError::Overflow))),
                Some(base_u64) => {
                    let prod = (base_u64 as f64) * threshold;
                    if prod >= TWO_POW_64 {
                        assert_eq!(
                            actual,
                            Err(err(AudrenError::Overflow)),
                            "expected Overflow for lpby={lpby} data_len={data_len} thresh={threshold:e}"
                        );
                    } else {
                        let expected = prod as u64;
                        assert_eq!(
                            actual,
                            Ok(expected),
                            "mismatch for lpby={lpby} data_len={data_len} thresh={threshold} (bits={:#018x})",
                            threshold.to_bits()
                        );
                    }
                }
            }
        };

        // 1. Canonical cluster spot checks (classic 2.0, SIMD-0194 1.0, fractional thresholds)
        assert_eq!(
            compute_rent_minimum_balance(LPBY, 2.0f64.to_bits(), 0).unwrap(),
            890_880
        );
        assert_eq!(
            compute_rent_minimum_balance(LPBY, 2.0f64.to_bits(), POOL_STATE_LEN).unwrap(),
            1_781_760
        );
        assert_eq!(
            compute_rent_minimum_balance(LPBY, 1.0f64.to_bits(), 0).unwrap(),
            445_440
        );
        assert_eq!(
            compute_rent_minimum_balance(LPBY, 1.0f64.to_bits(), MEMO_PAGE_LEN).unwrap(),
            36_080_640
        );
        // Fractional truncation matches Agave bit-for-bit (never off-by-1 ceiling)
        assert_eq!(
            compute_rent_minimum_balance(3, 0.5f64.to_bits(), 1).unwrap(),
            193 // (129 * 3) as f64 * 0.5 = 193.5 -> 193
        );
        assert_eq!(
            compute_rent_minimum_balance(1, 0.25f64.to_bits(), 1).unwrap(),
            32 // 129.0 * 0.25 = 32.25 -> 32
        );
        assert_eq!(
            compute_rent_minimum_balance(LPBY, 0.1f64.to_bits(), 0).unwrap(),
            44_544
        );
        assert_eq!(
            compute_rent_minimum_balance(LPBY, 0.1f64.to_bits(), MEMO_PAGE_LEN).unwrap(),
            3_608_064
        );

        // 2. Exhaustive Cartesian matrix over all Audren account sizes, lpby values, and thresholds
        let data_lens: &[usize] = &[
            0,
            1,
            SENTINEL_LEN,
            128,
            SPL_ACCOUNT_LEN,
            LANE_STATE_LEN,
            SUBTREE_PAGE_LEN,
            SUBROOT_PAGE_LEN,
            NF_PAGE_LEN,
            ROOT_HISTORY_LEN,
            MEMO_PAGE_LEN,
        ];
        let lpbys: &[u64] = &[
            0,
            1,
            3,
            1_000,
            1_740,
            3_480,
            10_000,
            100_000,
            // Large >53-bit `base` cases (128 * lpby in 2^53 .. 2^64 - 1, testing ties & carry!)
            (1u64 << 46) + 1,                 // base for data_len=0 is 2^53 + 128
            (1u64 << 47) - 1,                 // base ~ 2^54
            (1u64 << 55) + 1,                 // base ~ 2^62
            (1u64 << 56) - 8,                 // base for data_len=0 is 2^63 - 1024 (exact max < 2^63)
            (1u64 << 56) - 4,                 // base for data_len=0 is 2^63 - 512 (tie rounds UP to 2^63!)
            (1u64 << 56),                     // base for data_len=0 is 2^63
            u64::MAX / 128,                   // base for data_len=0 is 2^64 - 128 (rounds UP to 2^64!)
            u64::MAX / (128 + MEMO_PAGE_LEN as u64), // near u64::MAX for 10 KiB page
        ];
        let thresholds: &[f64] = &[
            2.0,
            1.5,
            1.0,
            0.7,
            0.5,
            0.3,
            0.25,
            0.1,
            0.01,
            1.9999999999999998,
            f64::from_bits(1.0f64.to_bits() - 1),
            f64::from_bits(1.0f64.to_bits() + 1),
            1.0 / 128.0,
            f64::from_bits((1.0f64 / 128.0f64).to_bits() - 1),
            f64::from_bits((1.0f64 / 128.0f64).to_bits() + 1),
            1.0 / 384.0,
            f64::from_bits((1.0f64 / 384.0f64).to_bits() - 1),
            f64::from_bits((1.0f64 / 384.0f64).to_bits() + 1),
            0.0,
            -0.0,
            // Subnormals
            f64::from_bits(1),
            f64::from_bits(1u64 << 25),
            f64::from_bits(1u64 << 51),
            f64::from_bits(0x000f_ffff_ffff_ffff),
            // Smallest normal
            f64::MIN_POSITIVE,
            // Large normal (overflow boundary)
            1e30,
            f64::MAX,
        ];

        for &data_len in data_lens {
            for &lpby in lpbys {
                for &thresh in thresholds {
                    check_matches_agave(lpby, thresh, data_len);
                }
            }
        }

        // 3. Explicit round-to-nearest-even >53-bit `base` tie-breaking & `2^64` boundary checks
        //    `data_len = 0` => `total_bytes = 128 = 2^7`.
        //    - `(1 << 46) * 128 = 2^53`. Add `data_len` offsets with `lpby = 1` to hit EVERY bit of `2^53 + k`!
        let base_2_53 = 1usize << 53; // valid on 64-bit host
        for delta in 0usize..16 {
            let dl = base_2_53 - 128 + delta;
            for &thresh in &[1.0, 0.5, 1.5, 0.7, 0.3, 1.9999999999999998] {
                check_matches_agave(1, thresh, dl);
            }
        }
        // `2^63 - 1024` * 2.0 == `2^64 - 2048` (exact max representable binary64 < 2^64)
        assert_eq!(
            compute_rent_minimum_balance((1u64 << 56) - 8, 2.0f64.to_bits(), 0),
            Ok(0xffff_ffff_ffff_f800)
        );
        // `2^63 - 512` rounds UP to `2^63` in binary64 -> `* 2.0 == 2^64` -> Overflow!
        assert_eq!(
            compute_rent_minimum_balance((1u64 << 56) - 4, 2.0f64.to_bits(), 0),
            Err(err(AudrenError::Overflow))
        );
        // `2^64 - 128` rounds UP to `2^64` in binary64 -> `* 1.0 == 2^64` -> Overflow, `* 0.5 == 2^63` -> Ok!
        assert_eq!(
            compute_rent_minimum_balance(u64::MAX / 128, 1.0f64.to_bits(), 0),
            Err(err(AudrenError::Overflow))
        );
        assert_eq!(
            compute_rent_minimum_balance(u64::MAX / 128, 0.5f64.to_bits(), 0),
            Ok(1u64 << 63)
        );

        // 4. Deterministic fuzz sweep over >53-bit bases & arbitrary positive binary64 exponents
        let mut rng: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next_u64 = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        for _ in 0..4_000 {
            let dl = (next_u64() & 0x3fff) as usize;
            let shift = (next_u64() % 56) as u32;
            let lpby = next_u64() >> shift;
            // Construct valid positive finite binary64 (exp in 0..=2046)
            let exp = next_u64() % 2047;
            let frac = next_u64() & ((1u64 << 52) - 1);
            let thresh = f64::from_bits((exp << 52) | frac);
            check_matches_agave(lpby, thresh, dl);
        }

        // 5. Negative (normal & subnormal), NaN, +Inf, -Inf -> UnsupportedSysvar
        for bad_bits in [
            (-1.0f64).to_bits(),
            (-0.0001f64).to_bits(),
            0x8000_0000_0000_0001u64, // negative subnormal
            f64::NAN.to_bits(),
            0x7ff8_0000_0000_0001u64, // quiet NaN payload
            0xfff0_0000_0000_0001u64, // negative signaling NaN
            f64::INFINITY.to_bits(),
            f64::NEG_INFINITY.to_bits(),
        ] {
            assert_eq!(
                compute_rent_minimum_balance(LPBY, bad_bits, 0),
                Err(ProgramError::UnsupportedSysvar)
            );
        }
    }

    #[test]
    fn token_account_security_detects_frozen_and_confidential_transfer_ext() {
        let mint = [0x11u8; 32];
        let owner = [0x22u8; 32];
        let make_base = |state: u8| -> [u8; SPL_ACCOUNT_LEN] {
            let mut buf = [0u8; SPL_ACCOUNT_LEN];
            buf[0..32].copy_from_slice(&mint);
            buf[32..64].copy_from_slice(&owner);
            buf[64..72].copy_from_slice(&42u64.to_le_bytes());
            buf[108] = state;
            buf
        };

        // Short accounts & uninitialized / invalid states return None without panicking
        assert!(parse_token_account_security(&SPL_TOKEN_ID, &[]).is_none());
        assert!(parse_token_account_security(&SPL_TOKEN_ID, &[0u8; SPL_MINT_LEN]).is_none());
        assert!(parse_token_account_security(&SPL_TOKEN_ID, &make_base(0)).is_none());
        assert!(parse_token_account_security(&SPL_TOKEN_ID, &make_base(3)).is_none());

        // Classic SPL: Initialized (1) and Frozen (2) both parse with accurate `is_frozen`
        let init_snap = parse_token_account_security(&SPL_TOKEN_ID, &make_base(1))
            .expect("initialized classic SPL token account must parse");
        assert!(!init_snap.is_frozen);
        assert_eq!(init_snap.owner, Address::new_from_array(owner));
        assert_eq!(init_snap.mint, Address::new_from_array(mint));
        assert_eq!(init_snap.amount, 42);
        assert!(!init_snap.has_restrictive_ext);

        let frozen_snap = parse_token_account_security(&SPL_TOKEN_ID, &make_base(2))
            .expect("frozen classic SPL token account must parse");
        assert!(frozen_snap.is_frozen);
        assert_eq!(frozen_snap.owner, Address::new_from_array(owner));

        // Token-2022: Frozen account with benign ImmutableOwner (ext_type = 7, len = 0) parses as frozen
        let mut t22_frozen = make_base(2).to_vec();
        t22_frozen.push(TOKEN_2022_ACCOUNT_TYPE_ACCOUNT);
        t22_frozen.extend_from_slice(&7u16.to_le_bytes());
        t22_frozen.extend_from_slice(&0u16.to_le_bytes());
        let t22_frozen_snap = parse_token_account_security(&TOKEN_2022_ID, &t22_frozen)
            .expect("frozen Token-2022 account must parse");
        assert!(t22_frozen_snap.is_frozen);
        assert!(!t22_frozen_snap.has_restrictive_ext);

        // Token-2022: ConfidentialTransferAccount (ext_type = 5) is unconditionally restrictive
        let mut t22_ct = make_base(1).to_vec();
        t22_ct.push(TOKEN_2022_ACCOUNT_TYPE_ACCOUNT);
        // Preceded by ImmutableOwner (7, len 0) to verify TLV traversal
        t22_ct.extend_from_slice(&7u16.to_le_bytes());
        t22_ct.extend_from_slice(&0u16.to_le_bytes());
        t22_ct.extend_from_slice(&TOKEN_2022_EXT_CONFIDENTIAL_TRANSFER_ACCOUNT.to_le_bytes());
        t22_ct.extend_from_slice(&4u16.to_le_bytes());
        t22_ct.extend_from_slice(&[0u8; 4]);
        let t22_ct_snap = parse_token_account_security(&TOKEN_2022_ID, &t22_ct)
            .expect("Token-2022 account with ConfidentialTransferAccount must parse");
        assert!(!t22_ct_snap.is_frozen);
        assert!(t22_ct_snap.has_restrictive_ext);

        // Token-2022: Disabled MemoTransfer (8, val=[0]) & CpiGuard (11, val=[0]) remain non-restrictive
        let mut t22_ok = make_base(1).to_vec();
        t22_ok.push(TOKEN_2022_ACCOUNT_TYPE_ACCOUNT);
        t22_ok.extend_from_slice(&TOKEN_2022_EXT_MEMO_TRANSFER.to_le_bytes());
        t22_ok.extend_from_slice(&1u16.to_le_bytes());
        t22_ok.push(0);
        t22_ok.extend_from_slice(&TOKEN_2022_EXT_CPI_GUARD.to_le_bytes());
        t22_ok.extend_from_slice(&1u16.to_le_bytes());
        t22_ok.push(0);
        let t22_ok_snap = parse_token_account_security(&TOKEN_2022_ID, &t22_ok)
            .expect("Token-2022 account with disabled MemoTransfer/CpiGuard must parse");
        assert!(!t22_ok_snap.has_restrictive_ext);

        // Multisig length (355) is rejected even under Token-2022
        let mut t22_ms = [0u8; SPL_MULTISIG_LEN];
        t22_ms[108] = 1;
        t22_ms[SPL_ACCOUNT_LEN] = TOKEN_2022_ACCOUNT_TYPE_ACCOUNT;
        assert!(parse_token_account_security(&TOKEN_2022_ID, &t22_ms).is_none());
    }
}
