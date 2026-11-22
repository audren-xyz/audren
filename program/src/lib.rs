//! Audren On-Chain Solana Program (Pinocchio `#![no_std]`, sBPFv3).
//!
//! 9 clean instructions:
//!   0: InitPool            — PoolState (128 B) + unified program-owned `sol_vault` sentinel (16 B)
//!   1: InitLane            — LaneTreeState + `LaneRentVault` sentinel (16 B) + page 0s (sub0/sr0/memo0/nf0)
//!   2: OpenPage            — Unified, idempotent, sequence-bounded, `LaneRentVault`-subsidized page opener
//!   3: DepositSol          — Native SOL deposit into unified `sol_vault` (+ `LaneRentVault` fee + rollover)
//!   4: DepositSpl          — SPL / Token-2022 (net TransferFee + TransferHook) into unified `vault_auth` ATA
//!   5: PublishCheckpoint   — 256-slot cyclic checkpoint ring (16 read-only lanes -> super_root; pause-exempt)
//!   6: JoinSplit           — Private transfer (shielded `cm2` fees, economy 1-in `nf1==0` or padded) / Withdraw (pause-exempt full exit)
//!   7: ExecViaEscrow       — Multi-asset DeFi CPI with full `WatchedEscrowBuf` firewall,
//!                            `router_accounts` bound in `ctx_hash`, Token-2022 TLV checks, and XOR-masked `MemoPage`
//!   8: SetPaused           — Authority-only pause/unpause (never locks full withdrawals, checkpoints, or `OpenPage`)

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
        compute_super_root_4ary, ensure_canonical_fr, mask_to_fr_be,
    },
    state::{
        check_owned_and_magic, checkpoint_pda, ensure, err, escrow_pda, expected_ata,
        is_supported_token_program, lane_pda, lane_rent_pda, memo_pda, nf_page_pda, nullifier_pda,
        pool_pda, read_32, read_u16, read_u32, read_u64, sol_vault_pda, subroot_pda, subtree_pda,
        unwrap_pda, vault_auth_pda, AudrenError, PoolMode, ASSET_ID_DOMAIN, ASSET_MODE_PRIVATE,
        ASSET_MODE_SOL, ASSET_MODE_SPL, ATA_PROGRAM_ID, CHECKPOINT_RING_SLOTS, CKPT_LEN,
        CKPT_MAGIC, CKPT_SEED, CK_OFF_BUMP, CK_OFF_EPOCH_ID, CK_OFF_LANE_COUNTS,
        CK_OFF_LANE_ROOTS, CK_OFF_MAGIC, CK_OFF_POOL_ID, CK_OFF_PUBLISHED_SLOT, CK_OFF_SLOT_IDX,
        CK_OFF_SUPER_ROOT, CK_OFF_VERSION, CTX_DOMAIN_EXEC_VIA_ESCROW, CTX_DOMAIN_JOINSPLIT,
        CTX_DOMAIN_ROUTER_ACCOUNTS, DEPOSIT_FLAG_FEE_FROM_AMOUNT, DYN_MEMO_HEAD_LEN,
        DYN_MEMO_MAGIC, ESCROW_SEED, EXEC_FLAG_FEE_ON_OUTPUT, EXEC_KIND_SOL, EXEC_KIND_SPL,
        GROTH16_PROOF_LEN, LANE_MAGIC,
        LANE_RENT_MAGIC, LANE_RENT_SEED, LANE_SEED, LANE_STATE_LEN, LN_OFF_BUMP,
        LN_OFF_CURRENT_ROOT, LN_OFF_LANE_ID, LN_OFF_MAGIC, LN_OFF_NEXT_LEAF, LN_OFF_NF_COUNT,
        LN_OFF_POOL_ID, LN_OFF_RENT_BUMP, LN_OFF_VERSION, MAX_CPI_ACCOUNT_ALLOC, MEMO_CT_LEN,
        MEMO_ENTRY_WIRE_LEN, MEMO_MAGIC, MEMO_NOTES_PER_PAGE, MEMO_PAGE_LEN, MEMO_SEED,
        MM_OFF_BUMP, MM_OFF_CIPHERTEXTS, MM_OFF_CLOSED_SLOT, MM_OFF_COUNT, MM_OFF_CREATED_SLOT,
        MM_OFF_EPHEMERAL_PKS, MM_OFF_LANE_ID, MM_OFF_MAGIC, MM_OFF_PAGE_SEQ, MM_OFF_POOL_ID,
        MM_OFF_VIEW_TAGS, NATIVE_SOL_MINT, NF_OFF_BUMP, NF_OFF_CLOSED_SLOT, NF_OFF_COUNT,
        NF_OFF_CREATED_SLOT, NF_OFF_LANE_ID, NF_OFF_MAGIC, NF_OFF_PAGE_SEQ, NF_OFF_POOL_ID,
        NF_OFF_PREFIXES, NF_PAGE_LEN, NF_PAGE_MAGIC, NF_PAGE_SEED, NF_PER_PAGE, NF_PREFIX_LEN,
        NULLIFIER_SEED, NUM_ESCROW_SHARDS, NUM_LANES, OPEN_PAGE_KIND_MEMO as PAGE_KIND_MEMO,
        OPEN_PAGE_KIND_NULLIFIER as PAGE_KIND_NF, OPEN_PAGE_KIND_SUBROOT as PAGE_KIND_SUBROOT,
        OPEN_PAGE_KIND_SUBTREE as PAGE_KIND_SUBTREE, PL_OFF_ACTIVE_LANES, PL_OFF_AUTHORITY,
        PL_OFF_BUMP, PL_OFF_CKPT_INTERVAL, PL_OFF_MAGIC, PL_OFF_MAX_CKPT_AGE, PL_OFF_MODE,
        PL_OFF_NF_RENT_FEE, PL_OFF_NOTE_RENT_FEE, PL_OFF_PAUSED, PL_OFF_POOL_ID,
        PL_OFF_SOL_VAULT_BUMP, PL_OFF_VAULT_AUTH_BUMP, PL_OFF_VERSION, POOL_MAGIC, POOL_SEED,
        POOL_STATE_LEN, PROTOCOL_VERSION, SB_OFF_BUMP, SB_OFF_COUNT, SB_OFF_LANE_ID,
        SB_OFF_LEAVES, SB_OFF_MAGIC, SB_OFF_PAGE_SEQ, SB_OFF_POOL_ID, SENTINEL_LEN, SN_OFF_BUMP,
        SN_OFF_LANE_ID, SN_OFF_MAGIC, SN_OFF_POOL_ID, SOL_VAULT_SEED, SPL_TOKEN_ID, SR_OFF_BUMP,
        SR_OFF_COUNT, SR_OFF_LANE_ID, SR_OFF_MAGIC, SR_OFF_POOL_ID, SR_OFF_ROOTS,
        SR_OFF_ROOT_PAGE_SEQ, SUBROOTS_PER_PAGE, SUBROOT_MAGIC, SUBROOT_PAGE_LEN, SUBROOT_SEED,
        SUBTREE_LEAVES, SUBTREE_MAGIC, SUBTREE_PAGE_LEN, SUBTREE_SEED, SYSTEM_PROGRAM_ID,
        TAG_DEPOSIT_SOL, TAG_DEPOSIT_SPL, TAG_EXEC_VIA_ESCROW, TAG_INIT_LANE, TAG_INIT_POOL,
        TAG_JOINSPLIT, TAG_OPEN_PAGE, TAG_PUBLISH_CHECKPOINT, TAG_SET_PAUSED, TOKEN_2022_ID,
        UNWRAP_SEED, VAULT_AUTH_SEED, WITHDRAW_FLAG_UNWRAP_WSOL, WSOL_MINT, ZERO_HASHES_4ARY,
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
const MAX_HOOK_CPI_ACCOUNTS: usize = 64;

const SPL_MINT_LEN: usize = 82;
const SPL_ACCOUNT_LEN: usize = 165;
const SPL_MULTISIG_LEN: usize = 355;
const TOKEN_2022_ACCOUNT_TYPE_MINT: u8 = 1;
const TOKEN_2022_ACCOUNT_TYPE_ACCOUNT: u8 = 2;
const TOKEN_2022_EXT_MEMO_TRANSFER: u16 = 8;
const TOKEN_2022_EXT_CPI_GUARD: u16 = 11;
const TOKEN_2022_EXT_TRANSFER_HOOK: u16 = 14;
const TOKEN_IX_CLOSE_ACCOUNT: u8 = 9;
const TOKEN_IX_TRANSFER_CHECKED: u8 = 12;
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
/// (`[0u8; 32]` for Native SOL, or the SPL / Token-2022 mint address).
#[inline]
fn derive_asset_id(mint_32: &[u8; 32]) -> [u8; 32] {
    let raw = sha256_v(&[ASSET_ID_DOMAIN, mint_32]);
    mask_to_fr_be(&raw)
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
        .ok_or_else(|| err(AudrenError::Overflow))?;
    let base = total_bytes
        .checked_mul(lamports_per_byte)
        .ok_or_else(|| err(AudrenError::Overflow))?;

    if threshold == THRESHOLD_1_0 {
        Ok(base)
    } else if threshold == THRESHOLD_2_0 {
        base.checked_mul(2)
            .ok_or_else(|| err(AudrenError::Overflow))
    } else {
        Err(ProgramError::UnsupportedSysvar)
    }
}

/// Create a PDA safely even if an attacker pre-funded lamports to it (immune to 1-lamport DoS).
fn create_pda_safe<'a>(
    payer: &'a AccountView,
    pda: &'a AccountView,
    sys_prog: &'a AccountView,
    space: usize,
    program_id: &Address,
    seeds: &[Seed<'_>],
) -> ProgramResult {
    ensure(
        space <= MAX_CPI_ACCOUNT_ALLOC
            && sys_prog.address() == &SYSTEM_PROGRAM_ID
            && pda.owned_by(&SYSTEM_PROGRAM_ID)
            && pda.is_data_empty(),
        AudrenError::InvalidAccount,
    )?;
    let required = rent_minimum_balance(space)?;
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
        || (len > SPL_ACCOUNT_LEN
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
            if ext_type == TOKEN_2022_EXT_TRANSFER_HOOK && ext_len >= 64 {
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
    has_delegate: bool,
    close_authority: Option<Address>,
    data_len: u16,
    has_restrictive_ext: bool,
}

fn token_account_security(account: &AccountView) -> Option<TokenSecuritySnapshot> {
    let owner_prog = account.owner();
    if !is_supported_token_program(owner_prog) {
        return None;
    }
    let data = account.try_borrow().ok()?;
    let len = data.len();
    let valid = (len == SPL_ACCOUNT_LEN
        || (len > SPL_ACCOUNT_LEN
            && len != SPL_MULTISIG_LEN
            && data[SPL_ACCOUNT_LEN] == TOKEN_2022_ACCOUNT_TYPE_ACCOUNT))
        && data[108] == 1;
    if !valid {
        return None;
    }
    let data_len = u16::try_from(len).ok()?;
    let mint_bytes: [u8; 32] = data[0..32].try_into().ok()?;
    let owner_bytes: [u8; 32] = data[32..64].try_into().ok()?;
    let amount = read_u64(&data, 64);
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
    if len > SPL_ACCOUNT_LEN + 1 {
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
            if (ext_type == TOKEN_2022_EXT_MEMO_TRANSFER || ext_type == TOKEN_2022_EXT_CPI_GUARD)
                && (ext_len < 1 || tlv[val_start] != 0)
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
        has_delegate,
        close_authority,
        data_len,
        has_restrictive_ext,
    })
}

/// Validate SPL Token / Token-2022 custody account invariants (`mint`, `owner`, state != 0,
/// and when `strict_custody == true`, forbids delegates, close authorities, and active
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
            && &snap.owner == expected_owner,
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
    ckpt_interval: u64,
    max_ckpt_age: u64,
    sol_vault_bump: u8,
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
        ckpt_interval: read_u64(&pd, PL_OFF_CKPT_INTERVAL),
        max_ckpt_age: read_u64(&pd, PL_OFF_MAX_CKPT_AGE),
        sol_vault_bump: pd[PL_OFF_SOL_VAULT_BUMP],
        vault_auth_bump: pd[PL_OFF_VAULT_AUTH_BUMP],
        note_rent_fee: read_u64(&pd, PL_OFF_NOTE_RENT_FEE),
        nf_rent_fee: read_u64(&pd, PL_OFF_NF_RENT_FEE),
    })
}

fn verify_sol_vault(
    program_id: &Address,
    pool_id: u32,
    sol_vault_bump: u8,
    sol_vault: &AccountView,
) -> ProgramResult {
    ensure(
        sol_vault.owned_by(&SYSTEM_PROGRAM_ID) && sol_vault.is_data_empty(),
        AudrenError::InvalidAccount,
    )?;
    let pool_le = pool_id.to_le_bytes();
    let exp = Address::create_program_address(
        &[SOL_VAULT_SEED, &pool_le, &[sol_vault_bump]],
        program_id,
    )
    .map_err(|_| err(AudrenError::InvalidPda))?;
    ensure(sol_vault.address() == &exp, AudrenError::InvalidPda)
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

fn verify_and_load_checkpoint_root(
    program_id: &Address,
    pool_id: u32,
    max_ckpt_age: u64,
    now: u64,
    ckpt_acc: &AccountView,
) -> Result<[u8; 32], ProgramError> {
    check_owned_and_magic(ckpt_acc, program_id, CKPT_LEN, &CKPT_MAGIC)?;
    let cd = ckpt_acc.try_borrow()?;
    ensure(read_u32(&cd, CK_OFF_POOL_ID) == pool_id, AudrenError::CheckpointMismatch)?;
    let slot_idx = read_u16(&cd, CK_OFF_SLOT_IDX);
    let cb = cd[CK_OFF_BUMP];
    let pool_le = pool_id.to_le_bytes();
    let slot_le = slot_idx.to_le_bytes();
    let exp = Address::create_program_address(&[CKPT_SEED, &pool_le, &slot_le, &[cb]], program_id)
        .map_err(|_| err(AudrenError::InvalidPda))?;
    ensure(ckpt_acc.address() == &exp, AudrenError::InvalidPda)?;
    let pub_slot = read_u64(&cd, CK_OFF_PUBLISHED_SLOT);
    ensure(
        now >= pub_slot && now.saturating_sub(pub_slot) <= max_ckpt_age,
        AudrenError::CheckpointExpired,
    )?;
    Ok(read_32(&cd, CK_OFF_SUPER_ROOT))
}

/// Collect a self-balancing per-note & per-nullifier amortized rent contribution into `LaneRentVault`.
///
/// Immune to SIMD-0437 rent reductions:
/// 1. Reads live `SysvarRent` (`rent_minimum_balance`).
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
    let min_vault = rent_minimum_balance(SENTINEL_LEN)?;
    let sub_rent = rent_minimum_balance(SUBTREE_PAGE_LEN)?;
    let sr_rent = rent_minimum_balance(SUBROOT_PAGE_LEN)?;
    let memo_rent = rent_minimum_balance(MEMO_PAGE_LEN)?;
    let nf_rent = rent_minimum_balance(NF_PAGE_LEN)?;

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
    let sub_rent = rent_minimum_balance(SUBTREE_PAGE_LEN)?;
    let sr_rent = rent_minimum_balance(SUBROOT_PAGE_LEN)?;
    let memo_rent = rent_minimum_balance(MEMO_PAGE_LEN)?;
    let live_per_note = sub_rent
        .div_ceil(SUBTREE_LEAVES as u64)
        .saturating_add(sr_rent.div_ceil((SUBTREE_LEAVES * SUBROOTS_PER_PAGE) as u64))
        .saturating_add(memo_rent.div_ceil(MEMO_NOTES_PER_PAGE as u64));
    Ok(cfg.note_rent_fee.min(live_per_note))
}

/// Out-of-line atomic WSOL unwrap helper (`JoinSplit` with `WITHDRAW_FLAG_UNWRAP_WSOL`):
/// creates a 1-shot nullifier-seeded Classic SPL token account (`["audren_v2_unwrap", pool_id, nf0]`)
/// owned by `vault_auth`, transfers `total_out` WSOL into it, closes it to `payer` (refunding
/// 100% of temporary token account rent + `total_out` SOL), and transfers exact `amount_out` SOL
/// to `recipient` and optional `relayer_fee` SOL to `fee_recipient`.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn unwrap_wsol_and_payout(
    program_id: &Address,
    pool_id: u32,
    nf0: &[u8; 32],
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
    let (exp_unwrap, unwrap_bump) = unwrap_pda(program_id, pool_id, nf0);
    ensure(unwrap_acc.address() == &exp_unwrap, AudrenError::InvalidPda)?;
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
// Tree + On-Chain Compact 90 B MemoPage & NullifierPage Helpers
// =============================================================================

#[allow(clippy::too_many_arguments)]
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
    memo_90: &[u8],
    slot: u64,
) -> Result<u64, ProgramError> {
    ensure(memo_90.len() == MEMO_ENTRY_WIRE_LEN, AudrenError::InvalidInstruction)?;

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

    // 2. Write (view_tag[2], ephemeral_pk[32], ciphertext[56]) into deterministic MemoPage PDA
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
        md[vt_pos..vt_pos + 2].copy_from_slice(&memo_90[0..2]);
        let epk_pos = MM_OFF_EPHEMERAL_PKS + memo_slot * 32;
        md[epk_pos..epk_pos + 32].copy_from_slice(&memo_90[2..34]);
        let ct_pos = MM_OFF_CIPHERTEXTS + memo_slot * MEMO_CT_LEN;
        md[ct_pos..ct_pos + MEMO_CT_LEN].copy_from_slice(&memo_90[34..MEMO_ENTRY_WIRE_LEN]);
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
        ld[LN_OFF_NF_COUNT..LN_OFF_NF_COUNT + 8].copy_from_slice(&(cur + 1).to_le_bytes());
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
        TAG_DEPOSIT_SOL => ix_deposit_sol(program_id, accounts, &data[1..]),
        TAG_DEPOSIT_SPL => ix_deposit_spl(program_id, accounts, &data[1..]),
        TAG_PUBLISH_CHECKPOINT => ix_publish_checkpoint(program_id, accounts, &data[1..]),
        TAG_JOINSPLIT => ix_joinsplit(program_id, accounts, &data[1..]),
        TAG_EXEC_VIA_ESCROW => ix_exec_via_escrow(program_id, accounts, &data[1..]),
        TAG_SET_PAUSED => ix_set_paused(program_id, accounts, &data[1..]),
        _ => Err(err(AudrenError::InvalidInstruction)),
    }
}

// =============================================================================
// 0. InitPool (unified `sol_vault` sentinel + ring-wrap deadlock guard)
// =============================================================================

fn ix_init_pool(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    // pool_id(4) + ckpt_interval(8) + max_ckpt_age(8) + note_rent_fee(8) + nf_rent_fee(8) = 36 B
    ensure(data.len() == 36, AudrenError::InvalidInstruction)?;
    let [payer, pool_acc, sol_vault, sys_prog, ..] = accounts else {
        return Err(err(AudrenError::InvalidInstruction));
    };
    ensure(payer.is_signer(), AudrenError::Unauthorized)?;

    let pool_id = read_u32(data, 0);
    let ckpt_interval = read_u64(data, 4);
    let max_ckpt_age = read_u64(data, 12);
    let note_rent_fee = read_u64(data, 20);
    let nf_rent_fee = read_u64(data, 28);

    // Prevent checkpoint ring deadlock: max_ckpt_age MUST stay strictly below (RING - 1) * interval!
    let max_safe_age = (CHECKPOINT_RING_SLOTS - 1).saturating_mul(ckpt_interval);
    ensure(
        ckpt_interval > 0 && max_ckpt_age >= ckpt_interval && max_ckpt_age < max_safe_age,
        AudrenError::InvalidInstruction,
    )?;

    let (expected_pool, pool_bump) = pool_pda(program_id, pool_id);
    ensure(pool_acc.address() == &expected_pool, AudrenError::InvalidPda)?;
    let (expected_sol, sol_bump) = sol_vault_pda(program_id, pool_id);
    ensure(sol_vault.address() == &expected_sol, AudrenError::InvalidPda)?;
    let (_, va_bump) = vault_auth_pda(program_id, pool_id);

    let pool_le = pool_id.to_le_bytes();
    let pb = [pool_bump];
    create_pda_safe(
        payer,
        pool_acc,
        sys_prog,
        POOL_STATE_LEN,
        program_id,
        &[Seed::from(POOL_SEED), Seed::from(&pool_le), Seed::from(&pb)],
    )?;

    // Prefund 0-byte System-owned `sol_vault` PDA to rent-exempt minimum so SystemProgram::Transfer
    // works cleanly both on Withdraw AND before router CPI in direct Native SOL -> SPL ExecViaEscrow!
    ensure(
        sol_vault.owned_by(&SYSTEM_PROGRAM_ID) && sol_vault.is_data_empty(),
        AudrenError::InvalidAccount,
    )?;
    let rent_min_0 = rent_minimum_balance(0)?;
    let sol_deficit = rent_min_0.saturating_sub(sol_vault.lamports());
    if sol_deficit > 0 {
        Transfer {
            from: payer,
            to: sol_vault,
            lamports: sol_deficit,
        }
        .invoke()?;
    }

    let mut pd = pool_acc.try_borrow_mut()?;
    pd[PL_OFF_MAGIC..PL_OFF_MAGIC + 8].copy_from_slice(&POOL_MAGIC);
    pd[PL_OFF_VERSION] = PROTOCOL_VERSION;
    pd[PL_OFF_MODE] = PoolMode::Permissionless as u8;
    pd[PL_OFF_BUMP] = pool_bump;
    pd[PL_OFF_PAUSED] = 0;
    pd[PL_OFF_ACTIVE_LANES] = 0;
    pd[PL_OFF_POOL_ID..PL_OFF_POOL_ID + 4].copy_from_slice(&pool_le);
    pd[PL_OFF_CKPT_INTERVAL..PL_OFF_CKPT_INTERVAL + 8]
        .copy_from_slice(&ckpt_interval.to_le_bytes());
    pd[PL_OFF_MAX_CKPT_AGE..PL_OFF_MAX_CKPT_AGE + 8].copy_from_slice(&max_ckpt_age.to_le_bytes());
    pd[PL_OFF_AUTHORITY..PL_OFF_AUTHORITY + 32].copy_from_slice(payer.address().as_ref());
    pd[PL_OFF_SOL_VAULT_BUMP] = sol_bump;
    pd[PL_OFF_VAULT_AUTH_BUMP] = va_bump;
    pd[PL_OFF_NOTE_RENT_FEE..PL_OFF_NOTE_RENT_FEE + 8]
        .copy_from_slice(&note_rent_fee.to_le_bytes());
    pd[PL_OFF_NF_RENT_FEE..PL_OFF_NF_RENT_FEE + 8].copy_from_slice(&nf_rent_fee.to_le_bytes());
    Ok(())
}

// =============================================================================
// 1. InitLane (LaneTreeState + per-lane LaneRentVault sentinel + page 0s)
// =============================================================================

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
    ensure(payer.address() == &cfg.authority, AudrenError::Unauthorized)?;
    ensure(lane_id == cfg.active_lanes, AudrenError::InvalidLane)?;
    ensure(pool_acc.is_writable(), AudrenError::InvalidAccount)?;

    let pool_le = pool_id.to_le_bytes();
    let lane_b = [lane_id];
    let seq0 = 0u64.to_le_bytes();
    let slot = Clock::get()?.slot;

    let (exp_rv, rvb) = lane_rent_pda(program_id, pool_id, lane_id);
    ensure(lane_rent_vault.address() == &exp_rv, AudrenError::InvalidPda)?;
    let rvb_arr = [rvb];
    create_pda_safe(
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
    create_pda_safe(
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
    )?;
    {
        let mut ld = lane_acc.try_borrow_mut()?;
        ld[LN_OFF_MAGIC..LN_OFF_MAGIC + 8].copy_from_slice(&LANE_MAGIC);
        ld[LN_OFF_VERSION] = 3;
        ld[LN_OFF_LANE_ID] = lane_id;
        ld[LN_OFF_BUMP] = lb;
        ld[LN_OFF_RENT_BUMP] = rvb;
        ld[LN_OFF_POOL_ID..LN_OFF_POOL_ID + 4].copy_from_slice(&pool_le);
        ld[LN_OFF_CURRENT_ROOT..LN_OFF_CURRENT_ROOT + 32].copy_from_slice(&ZERO_HASHES_4ARY[18]);
    }

    let (exp_sub0, sb) = subtree_pda(program_id, pool_id, lane_id, 0);
    ensure(sub0.address() == &exp_sub0, AudrenError::InvalidPda)?;
    let sb_arr = [sb];
    create_pda_safe(
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
    create_pda_safe(
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
    create_pda_safe(
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
    create_pda_safe(
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

    ensure(page_seq <= cur_seq.saturating_add(2), AudrenError::PageSeqOutOfRange)?;
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
    let min_vault = rent_minimum_balance(SENTINEL_LEN)?;
    let page_rent = rent_minimum_balance(space)?;
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
// 3. DepositSol (unified `sol_vault` + `LaneRentVault` fee + rollover)
// =============================================================================

fn ix_deposit_sol(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    // pool_id(4) + lane_id(1) + rollover_flags(1) + amount(8) + stealth_owner(32) + blinding(32) + memo(90) = 168 B
    const DATA_LEN: usize = 4 + 1 + 1 + 8 + 32 + 32 + MEMO_ENTRY_WIRE_LEN;
    ensure(data.len() == DATA_LEN && accounts.len() >= 9, AudrenError::InvalidInstruction)?;
    let (head, roll_tail) = accounts.split_at_mut(9);
    let [depositor, pool_acc, sol_vault, lane_acc, lane_rent_vault, subtree_acc, subroot_acc, memo_acc, sys_prog] =
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
    let rollover_flags = data[5];
    let amount = read_u64(data, 6);
    let stealth_owner = read_32(data, 14);
    let blinding = read_32(data, 46);
    let memo_90 = &data[78..DATA_LEN];

    ensure(
        (lane_id as usize) < NUM_LANES
            && (rollover_flags & !(0b11 | DEPOSIT_FLAG_FEE_FROM_AMOUNT)) == 0
            && amount > 0
            && blinding != [0u8; 32],
        AudrenError::InvalidInstruction,
    )?;
    ensure_canonical_fr(&stealth_owner)?;
    ensure_canonical_fr(&blinding)?;

    let cfg = load_and_verify_pool(program_id, pool_id, pool_acc)?;
    ensure(!cfg.paused, AudrenError::PoolPaused)?;
    ensure(lane_id < cfg.active_lanes, AudrenError::InvalidLane)?;
    verify_sol_vault(program_id, pool_id, cfg.sol_vault_bump, sol_vault)?;
    let rent_bump = verify_lane_pda(program_id, pool_id, lane_id, lane_acc)?;
    verify_lane_rent_vault(program_id, pool_id, lane_id, rent_bump, lane_rent_vault)?;

    let has_next_sub = (rollover_flags & 1) != 0;
    let has_next_memo = (rollover_flags & 2) != 0;
    let fee_from_amount = (rollover_flags & DEPOSIT_FLAG_FEE_FROM_AMOUNT) != 0;
    ensure(
        roll_tail.len() >= usize::from(has_next_sub) + usize::from(has_next_memo),
        AudrenError::InvalidInstruction,
    )?;
    let (sub_slot, memo_slot) = roll_tail.split_at_mut(usize::from(has_next_sub));

    let vault_before = sol_vault.lamports();
    let committed_amount = if fee_from_amount {
        // Zero-dust sweep: deduct deterministic per-note rent fee from `amount` so total
        // debited from `depositor` equals `amount` exactly and `memo_90` parity is race-free!
        let fee = deterministic_note_rent_fee(&cfg)?;
        let net_sol = amount
            .checked_sub(fee)
            .ok_or_else(|| err(AudrenError::InvalidInstruction))?;
        ensure(net_sol > 0, AudrenError::InvalidInstruction)?;
        if fee > 0 {
            Transfer {
                from: depositor,
                to: lane_rent_vault,
                lamports: fee,
            }
            .invoke()?;
        }
        Transfer {
            from: depositor,
            to: sol_vault,
            lamports: net_sol,
        }
        .invoke()?;
        ensure(
            sol_vault.lamports()
                == vault_before
                    .checked_add(net_sol)
                    .ok_or_else(|| err(AudrenError::Overflow))?,
            AudrenError::CustodyInvariantViolated,
        )?;
        net_sol
    } else {
        Transfer {
            from: depositor,
            to: sol_vault,
            lamports: amount,
        }
        .invoke()?;
        ensure(
            sol_vault.lamports()
                == vault_before
                    .checked_add(amount)
                    .ok_or_else(|| err(AudrenError::Overflow))?,
            AudrenError::CustodyInvariantViolated,
        )?;
        collect_lane_rent_fee(depositor, lane_rent_vault, &cfg, 1, 0)?;
        amount
    };

    let slot = Clock::get()?.slot;
    let asset_id = derive_asset_id(&NATIVE_SOL_MINT);
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
        memo_90,
        slot,
    )?;
    Ok(())
}

// =============================================================================
// 4. DepositSpl (unified `vault_auth` + net TransferFee + TransferHook + rollover)
// =============================================================================

fn ix_deposit_spl(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    const DATA_LEN: usize = 4 + 1 + 1 + 8 + 32 + 32 + MEMO_ENTRY_WIRE_LEN;
    ensure(data.len() == DATA_LEN && accounts.len() >= 13, AudrenError::InvalidInstruction)?;
    let (head, tail) = accounts.split_at_mut(13);
    let [depositor, pool_acc, vault_auth, mint_acc, depositor_ata, vault_ata, token_prog, lane_acc, lane_rent_vault, subtree_acc, subroot_acc, memo_acc, sys_prog] =
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
    let rollover_flags = data[5];
    let amount = read_u64(data, 6);
    let stealth_owner = read_32(data, 14);
    let blinding = read_32(data, 46);
    let memo_90 = &data[78..DATA_LEN];

    ensure(
        (lane_id as usize) < NUM_LANES
            && (rollover_flags & !0b11) == 0
            && amount > 0
            && blinding != [0u8; 32],
        AudrenError::InvalidInstruction,
    )?;
    ensure_canonical_fr(&stealth_owner)?;
    ensure_canonical_fr(&blinding)?;

    let cfg = load_and_verify_pool(program_id, pool_id, pool_acc)?;
    ensure(!cfg.paused, AudrenError::PoolPaused)?;
    ensure(lane_id < cfg.active_lanes, AudrenError::InvalidLane)?;

    let pool_le = pool_id.to_le_bytes();
    let exp_va = Address::create_program_address(
        &[VAULT_AUTH_SEED, &pool_le, &[cfg.vault_auth_bump]],
        program_id,
    )
    .map_err(|_| err(AudrenError::InvalidPda))?;
    ensure(vault_auth.address() == &exp_va, AudrenError::InvalidPda)?;
    let rent_bump = verify_lane_pda(program_id, pool_id, lane_id, lane_acc)?;
    verify_lane_rent_vault(program_id, pool_id, lane_id, rent_bump, lane_rent_vault)?;

    let has_next_sub = (rollover_flags & 1) != 0;
    let has_next_memo = (rollover_flags & 2) != 0;
    let roll_cnt = usize::from(has_next_sub) + usize::from(has_next_memo);
    ensure(tail.len() >= roll_cnt, AudrenError::InvalidInstruction)?;
    let (roll_slice, hook_candidates) = tail.split_at_mut(roll_cnt);
    let (sub_slot, memo_slot) = roll_slice.split_at_mut(usize::from(has_next_sub));

    let mint_info = load_mint_info(mint_acc, token_prog.address())?;
    let vault_before = validate_token_account(
        vault_ata,
        token_prog.address(),
        mint_acc.address(),
        vault_auth.address(),
        true,
    )?;

    let blocked = [
        pool_acc.address(),
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
        depositor_ata,
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

    let slot = Clock::get()?.slot;
    let mut mint_32 = [0u8; 32];
    mint_32.copy_from_slice(mint_acc.address().as_ref());
    let asset_id = derive_asset_id(&mint_32);
    let cm = compute_note_commitment(&stealth_owner, &asset_id, net_received, &blinding)?;
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
        memo_90,
        slot,
    )?;
    Ok(())
}

// =============================================================================
// 5. PublishCheckpoint (256-slot bounded cyclic ring, pause-exempt, DoS-safe)
// =============================================================================

fn ix_publish_checkpoint(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    ensure(accounts.len() >= 5 && data.len() == 4, AudrenError::InvalidInstruction)?;
    let (head, lanes) = accounts.split_at_mut(4);
    let [payer, pool_acc, ckpt_acc, sys_prog] = head else {
        return Err(err(AudrenError::InvalidInstruction));
    };
    ensure(
        payer.is_signer() && sys_prog.address() == &SYSTEM_PROGRAM_ID,
        AudrenError::InvalidAccount,
    )?;

    let pool_id = read_u32(data, 0);
    let cfg = load_and_verify_pool(program_id, pool_id, pool_acc)?;
    let active = cfg.active_lanes as usize;
    ensure(active > 0 && active <= NUM_LANES, AudrenError::InvalidLane)?;
    ensure(lanes.len() == active, AudrenError::InvalidInstruction)?;

    let slot = Clock::get()?.slot;
    let epoch_id = slot / cfg.ckpt_interval;
    let slot_idx = (epoch_id % CHECKPOINT_RING_SLOTS) as u16;

    let (exp_ckpt, bump) = checkpoint_pda(program_id, pool_id, slot_idx);
    ensure(ckpt_acc.address() == &exp_ckpt, AudrenError::InvalidPda)?;

    let pool_le = pool_id.to_le_bytes();
    let mut lane_roots = [ZERO_HASHES_4ARY[18]; NUM_LANES];
    let mut lane_counts = [0u64; NUM_LANES];
    for i in 0..active {
        let lane_acc = &lanes[i];
        let _ = verify_lane_pda(program_id, pool_id, i as u8, lane_acc)?;
        let ld = lane_acc.try_borrow()?;
        lane_roots[i] = read_32(&ld, LN_OFF_CURRENT_ROOT);
        lane_counts[i] = read_u64(&ld, LN_OFF_NEXT_LEAF);
    }

    let super_root = compute_super_root_4ary(&lane_roots, active)?;

    if ckpt_acc.owned_by(&SYSTEM_PROGRAM_ID) {
        let slot_le = slot_idx.to_le_bytes();
        let bump_b = [bump];
        create_pda_safe(
            payer,
            ckpt_acc,
            sys_prog,
            CKPT_LEN,
            program_id,
            &[
                Seed::from(CKPT_SEED),
                Seed::from(&pool_le),
                Seed::from(&slot_le),
                Seed::from(&bump_b),
            ],
        )?;
    } else {
        check_owned_and_magic(ckpt_acc, program_id, CKPT_LEN, &CKPT_MAGIC)?;
        let cd = ckpt_acc.try_borrow()?;
        let prev_epoch = read_u64(&cd, CK_OFF_EPOCH_ID);
        let prev_slot = read_u64(&cd, CK_OFF_PUBLISHED_SLOT);
        ensure(epoch_id > prev_epoch, AudrenError::CheckpointTooSoon)?;
        ensure(
            slot.saturating_sub(prev_slot) > cfg.max_ckpt_age,
            AudrenError::CheckpointTooSoon,
        )?;
    }

    let mut cd = ckpt_acc.try_borrow_mut()?;
    cd[CK_OFF_MAGIC..CK_OFF_MAGIC + 8].copy_from_slice(&CKPT_MAGIC);
    cd[CK_OFF_VERSION] = 3;
    cd[CK_OFF_BUMP] = bump;
    cd[CK_OFF_SLOT_IDX..CK_OFF_SLOT_IDX + 2].copy_from_slice(&slot_idx.to_le_bytes());
    cd[CK_OFF_POOL_ID..CK_OFF_POOL_ID + 4].copy_from_slice(&pool_le);
    cd[CK_OFF_EPOCH_ID..CK_OFF_EPOCH_ID + 8].copy_from_slice(&epoch_id.to_le_bytes());
    cd[CK_OFF_PUBLISHED_SLOT..CK_OFF_PUBLISHED_SLOT + 8].copy_from_slice(&slot.to_le_bytes());
    cd[CK_OFF_SUPER_ROOT..CK_OFF_SUPER_ROOT + 32].copy_from_slice(&super_root);
    for i in 0..NUM_LANES {
        let r_off = CK_OFF_LANE_ROOTS + i * 32;
        cd[r_off..r_off + 32].copy_from_slice(&lane_roots[i]);
        let c_off = CK_OFF_LANE_COUNTS + i * 8;
        cd[c_off..c_off + 8].copy_from_slice(&lane_counts[i].to_le_bytes());
    }
    Ok(())
}

// =============================================================================
// 6. JoinSplit (Private Transfer w/ shielded fees / Merge / Withdraw w/ pause bypass)
// =============================================================================

fn ix_joinsplit(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    // pool_id(4) + vk_id(1) + out_lane(1) + output_mask(1) + asset_mode(1) + rollover_flags(1)
    // + proof(192) + nf0(32) + nf1(32) + cm0(32) + cm1(32) + cm2(32) + pub_out(8) + rel_fee(8) = 377 B
    const FIXED_LEN: usize = 4 + 1 + 1 + 1 + 1 + 1 + GROTH16_PROOF_LEN + 32 * 5 + 8 + 8;
    ensure(accounts.len() >= 12 && data.len() >= FIXED_LEN, AudrenError::InvalidInstruction)?;

    let (head, tail) = accounts.split_at_mut(12);
    let [payer, pool_acc, ckpt_acc, nf0_acc, nf1_acc, lane_acc, lane_rent_vault, subtree_acc, subroot_acc, memo_acc, nf_page_acc, sys_prog] =
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
    let proof_192: &[u8; GROTH16_PROOF_LEN] =
        data[9..9 + GROTH16_PROOF_LEN].try_into().unwrap();
    let nf0 = read_32(data, 201);
    let nf1 = read_32(data, 233);
    let cm0 = read_32(data, 265);
    let cm1 = read_32(data, 297);
    let cm2 = read_32(data, 329);
    let public_amount_out = read_u64(data, 361);
    let relayer_fee_amount = read_u64(data, 369);
    let memos_bytes = &data[FIXED_LEN..];

    let num_outputs = (output_mask & 1).count_ones() as usize
        + ((output_mask >> 1) & 1).count_ones() as usize
        + ((output_mask >> 2) & 1).count_ones() as usize;
    let unwrap_wsol = (rollover_flags & WITHDRAW_FLAG_UNWRAP_WSOL) != 0;
    ensure(
        (out_lane_id as usize) < NUM_LANES
            && (output_mask & !0b111) == 0
            && (rollover_flags & !(0b111 | WITHDRAW_FLAG_UNWRAP_WSOL)) == 0
            && (!unwrap_wsol || (asset_mode == ASSET_MODE_SPL && public_amount_out > 0))
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
    let is_full_exit = output_mask == 0
        && public_amount_out > 0
        && (asset_mode == ASSET_MODE_SOL || asset_mode == ASSET_MODE_SPL);
    if cfg.paused {
        ensure(is_full_exit, AudrenError::PoolPaused)?;
    }

    let now = Clock::get()?.slot;
    let super_root =
        verify_and_load_checkpoint_root(program_id, pool_id, cfg.max_ckpt_age, now, ckpt_acc)?;
    let rent_bump = verify_lane_pda(program_id, pool_id, out_lane_id, lane_acc)?;
    verify_lane_rent_vault(program_id, pool_id, out_lane_id, rent_bump, lane_rent_vault)?;
    let pool_le = pool_id.to_le_bytes();

    let outflow_cnt = match asset_mode {
        ASSET_MODE_PRIVATE => 0usize,
        ASSET_MODE_SOL => 3usize,
        ASSET_MODE_SPL => {
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

    let (public_asset_id, recipient_key, relayer_fee_key, spl_mint_info): (
        [u8; 32],
        [u8; 32],
        [u8; 32],
        Option<MintInfo>,
    ) = match asset_mode {
        ASSET_MODE_PRIVATE => {
            // Pure private transfers MUST NOT pay a public asset-disclosing relayer fee!
            // Relayers are compensated privately via shielded output `cm2`.
            ensure(total_outflow == 0, AudrenError::InvalidInstruction)?;
            ([0u8; 32], [0u8; 32], [0u8; 32], None)
        }
        ASSET_MODE_SOL => {
            // Public outflow mode requires `public_amount_out > 0`.
            ensure(public_amount_out > 0, AudrenError::InvalidInstruction)?;
            let [sol_vault, recipient, relayer_fee_recip] = outflow_tail else {
                return Err(err(AudrenError::InvalidInstruction));
            };
            verify_sol_vault(program_id, pool_id, cfg.sol_vault_bump, sol_vault)?;
            let min_vault = rent_minimum_balance(0)?;
            ensure(
                sol_vault.lamports() >= total_outflow.saturating_add(min_vault),
                AudrenError::InsufficientVaultBalance,
            )?;
            ensure(
                recipient.address() != sol_vault.address() && !recipient.owned_by(program_id),
                AudrenError::InvalidAccount,
            )?;
            let mut rk = [0u8; 32];
            rk.copy_from_slice(recipient.address().as_ref());
            let mut fk = [0u8; 32];
            if relayer_fee_amount > 0 {
                ensure(
                    relayer_fee_recip.address() != sol_vault.address()
                        && !relayer_fee_recip.owned_by(program_id),
                    AudrenError::InvalidAccount,
                )?;
                fk.copy_from_slice(relayer_fee_recip.address().as_ref());
            }
            (derive_asset_id(&NATIVE_SOL_MINT), rk, fk, None)
        }
        ASSET_MODE_SPL => {
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
            let bal = validate_token_account(
                vault_ata,
                token_prog.address(),
                mint_acc.address(),
                vault_auth.address(),
                true,
            )?;
            ensure(bal >= total_outflow, AudrenError::InsufficientVaultBalance)?;
            ensure(
                recipient_acc.address() != vault_ata.address()
                    && recipient_acc.address() != vault_auth.address()
                    && recipient_acc.address() != program_id
                    && !recipient_acc.owned_by(program_id),
                AudrenError::InvalidAccount,
            )?;
            if unwrap_wsol {
                ensure(
                    mint_acc.address() == &WSOL_MINT && token_prog.address() == &SPL_TOKEN_ID,
                    AudrenError::InvalidTokenAccount,
                )?;
                let unwrap_acc = &outflow_tail[6];
                let exp_sol_vault = Address::create_program_address(
                    &[SOL_VAULT_SEED, &pool_le, &[cfg.sol_vault_bump]],
                    program_id,
                )
                .map_err(|_| err(AudrenError::InvalidPda))?;
                let (exp_unwrap, _) = unwrap_pda(program_id, pool_id, &nf0);
                ensure(unwrap_acc.address() == &exp_unwrap, AudrenError::InvalidPda)?;
                ensure(
                    unwrap_acc.is_writable()
                        && unwrap_acc.owned_by(&SYSTEM_PROGRAM_ID)
                        && unwrap_acc.is_data_empty(),
                    AudrenError::InvalidAccount,
                )?;
                ensure(
                    recipient_acc.address() != unwrap_acc.address()
                        && recipient_acc.address() != &exp_sol_vault,
                    AudrenError::InvalidAccount,
                )?;
                if relayer_fee_amount > 0 {
                    ensure(
                        relayer_fee_acc.is_writable()
                            && relayer_fee_acc.address() != unwrap_acc.address()
                            && relayer_fee_acc.address() != &exp_sol_vault
                            && relayer_fee_acc.address() != vault_auth.address()
                            && relayer_fee_acc.address() != vault_ata.address()
                            && relayer_fee_acc.address() != program_id
                            && !relayer_fee_acc.owned_by(program_id),
                        AudrenError::InvalidAccount,
                    )?;
                }
            } else if relayer_fee_amount > 0 {
                ensure(
                    relayer_fee_acc.address() != vault_ata.address(),
                    AudrenError::InvalidAccount,
                )?;
            }
            let mut m32 = [0u8; 32];
            m32.copy_from_slice(mint_acc.address().as_ref());
            let mut rk = [0u8; 32];
            rk.copy_from_slice(recipient_acc.address().as_ref());
            let mut fk = [0u8; 32];
            if relayer_fee_amount > 0 {
                fk.copy_from_slice(relayer_fee_acc.address().as_ref());
            }
            (derive_asset_id(&m32), rk, fk, Some(mi))
        }
        _ => return Err(err(AudrenError::InvalidInstruction)),
    };

    let raw_ctx = sha256_v(&[
        CTX_DOMAIN_JOINSPLIT,
        program_id.as_ref(),
        &pool_le,
        &[out_lane_id, output_mask, asset_mode, u8::from(unwrap_wsol)],
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

    // Economy mode: `nf1 == [0;32]` is ONLY provable when `is_dummy[1] == true && amount[1] == 0`.
    let has_nf1 = nf1 != [0u8; 32];
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
            let memo_90 = &memos_bytes[memo_cursor..memo_cursor + MEMO_ENTRY_WIRE_LEN];
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
                memo_90,
                now,
            )?;
        }
    }

    if !cfg.paused {
        let num_nfs = if has_nf1 { 2u64 } else { 1u64 };
        collect_lane_rent_fee(payer, lane_rent_vault, &cfg, num_outputs as u64, num_nfs)?;
    }

    if asset_mode == ASSET_MODE_SOL {
        let [sol_vault, recipient, relayer_fee_recip] = outflow_tail else {
            return Err(err(AudrenError::InvalidInstruction));
        };
        let svb = [cfg.sol_vault_bump];
        let sv_seeds = [Seed::from(SOL_VAULT_SEED), Seed::from(&pool_le), Seed::from(&svb)];
        Transfer {
            from: sol_vault,
            to: recipient,
            lamports: public_amount_out,
        }
        .invoke_signed(&[Signer::from(&sv_seeds)])?;
        if relayer_fee_amount > 0 {
            Transfer {
                from: sol_vault,
                to: relayer_fee_recip,
                lamports: relayer_fee_amount,
            }
            .invoke_signed(&[Signer::from(&sv_seeds)])?;
        }
    } else if asset_mode == ASSET_MODE_SPL {
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
            unwrap_wsol_and_payout(
                program_id,
                pool_id,
                &nf0,
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
                ckpt_acc.address(),
                nf0_acc.address(),
                nf1_acc.address(),
                lane_acc.address(),
                lane_rent_vault.address(),
                subtree_acc.address(),
                subroot_acc.address(),
                memo_acc.address(),
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
        }
    }

    Ok(())
}

// =============================================================================
// 7. ExecViaEscrow (Escrow Firewall + `router_accounts` ctx_hash + XOR Memo)
// =============================================================================

fn ix_exec_via_escrow(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    // pool_id(4) + vk_id(1) + out_lane(1) + escrow_shard(1) + change_mask(1)
    // + in_kind(1) + out_kind(1) + rollover_flags(1)
    // + proof(192) + nf0(32) + nf1(32) + cm0(32) + cm1(32) + cm2(32)
    // + amount_in(8) + min_amount_out(8) + relayer_fee_amount(8)
    // + out_stealth_owner(32) + out_blinding(32) + dyn_memo_head(34) + dyn_mask_56(56)
    // + router_ix_len(2) = 543 B
    const HEADER_LEN: usize =
        11 + GROTH16_PROOF_LEN + 32 * 5 + 8 * 3 + 32 + 32 + DYN_MEMO_HEAD_LEN + MEMO_CT_LEN + 2;
    ensure(accounts.len() >= 14 && data.len() >= HEADER_LEN, AudrenError::InvalidInstruction)?;

    let (head, rest) = accounts.split_at_mut(14);
    let [payer, pool_acc, ckpt_acc, nf0_acc, nf1_acc, lane_acc, lane_rent_vault, subtree_acc, subroot_acc, memo_acc, nf_page_acc, escrow_acc, router_prog, sys_prog] =
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
    let in_kind = data[8]; // EXEC_KIND_SOL (0) or EXEC_KIND_SPL (1)
    let out_kind = data[9]; // EXEC_KIND_SOL (0) or EXEC_KIND_SPL (1)
    let rollover_flags = data[10];
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
    let dyn_mask_56 = &data[485..485 + MEMO_CT_LEN];
    let router_ix_len = read_u16(data, 541) as usize;

    let num_changes = (change_mask & 1).count_ones() as usize
        + ((change_mask >> 1) & 1).count_ones() as usize;
    let fee_on_output = (rollover_flags & EXEC_FLAG_FEE_ON_OUTPUT) != 0;
    ensure((escrow_shard as usize) < NUM_ESCROW_SHARDS, AudrenError::InvalidEscrowShard)?;
    ensure(
        (out_lane_id as usize) < NUM_LANES
            && (change_mask & !0b11) == 0
            && (rollover_flags & !(0b111 | EXEC_FLAG_FEE_ON_OUTPUT)) == 0
            && (!fee_on_output || relayer_fee_amount > 0)
            && (in_kind == EXEC_KIND_SOL || in_kind == EXEC_KIND_SPL)
            && (out_kind == EXEC_KIND_SOL || out_kind == EXEC_KIND_SPL)
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

    let now = Clock::get()?.slot;
    let super_root =
        verify_and_load_checkpoint_root(program_id, pool_id, cfg.max_ckpt_age, now, ckpt_acc)?;
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
            && router_prog.address() != &ATA_PROGRAM_ID,
        AudrenError::InvalidTargetProgram,
    )?;

    let exp_va = Address::create_program_address(
        &[VAULT_AUTH_SEED, &pool_le, &[cfg.vault_auth_bump]],
        program_id,
    )
    .map_err(|_| err(AudrenError::InvalidPda))?;
    let exp_sol_vault = Address::create_program_address(
        &[SOL_VAULT_SEED, &pool_le, &[cfg.sol_vault_bump]],
        program_id,
    )
    .map_err(|_| err(AudrenError::InvalidPda))?;

    // Split dynamic leg accounts + optional rollover accounts + router accounts
    let has_fee = relayer_fee_amount > 0;
    let has_in_fee = has_fee && !fee_on_output;
    let has_out_fee = has_fee && fee_on_output;
    let in_cnt = (if in_kind == EXEC_KIND_SOL { 1 } else { 5 }) + usize::from(has_in_fee);
    let out_cnt = (if out_kind == EXEC_KIND_SOL { 1 } else { 5 }) + usize::from(has_out_fee);
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
    let min_vault = rent_minimum_balance(0)?;

    let mut forbidden_keys: [Address; 8] = [Address::new_from_array([0u8; 32]); 8];
    let mut forbidden_len = 0usize;
    forbidden_keys[forbidden_len] = exp_sol_vault;
    forbidden_len += 1;
    forbidden_keys[forbidden_len] = exp_va;
    forbidden_len += 1;

    // Validate input leg and derive `asset_in` strictly ON-CHAIN
    let mut relayer_fee_key = [0u8; 32];
    let (asset_in, in_mint_info, pre_escrow_in_spl) = if in_kind == EXEC_KIND_SOL {
        let sol_vault = &in_leg[0];
        verify_sol_vault(program_id, pool_id, cfg.sol_vault_bump, sol_vault)?;
        ensure(
            sol_vault.lamports() >= total_in_outflow.saturating_add(min_vault),
            AudrenError::InsufficientVaultBalance,
        )?;
        if has_in_fee {
            let fee_recip = &in_leg[1];
            ensure(
                fee_recip.address() != sol_vault.address()
                    && fee_recip.address() != escrow_acc.address()
                    && !fee_recip.owned_by(program_id),
                AudrenError::InvalidAccount,
            )?;
            forbidden_keys[forbidden_len] = *fee_recip.address();
            forbidden_len += 1;
            relayer_fee_key.copy_from_slice(fee_recip.address().as_ref());
        }
        (derive_asset_id(&NATIVE_SOL_MINT), None, 0u64)
    } else {
        let va_in = &in_leg[0];
        let mint_in = &in_leg[1];
        let vault_in_ata = &in_leg[2];
        let escrow_in_ata = &in_leg[3];
        let token_prog_in = &in_leg[4];
        ensure(va_in.address() == &exp_va, AudrenError::InvalidPda)?;
        let mi = load_mint_info(mint_in, token_prog_in.address())?;
        let v_bal = validate_token_account(
            vault_in_ata,
            token_prog_in.address(),
            mint_in.address(),
            va_in.address(),
            true,
        )?;
        ensure(v_bal >= total_in_outflow, AudrenError::InsufficientVaultBalance)?;
        let e_bal = validate_token_account(
            escrow_in_ata,
            token_prog_in.address(),
            mint_in.address(),
            escrow_acc.address(),
            true,
        )?;
        forbidden_keys[forbidden_len] = *vault_in_ata.address();
        forbidden_len += 1;
        if has_in_fee {
            let fee_ata = &in_leg[5];
            let fee_snap = token_account_security(fee_ata)
                .ok_or_else(|| err(AudrenError::InvalidTokenAccount))?;
            ensure(
                fee_ata.is_writable()
                    && fee_snap.token_program == *token_prog_in.address()
                    && fee_snap.mint == *mint_in.address()
                    && fee_snap.owner != exp_va
                    && fee_snap.owner != exp_escrow
                    && fee_ata.address() != vault_in_ata.address()
                    && fee_ata.address() != escrow_in_ata.address(),
                AudrenError::InvalidAccount,
            )?;
            forbidden_keys[forbidden_len] = *fee_ata.address();
            forbidden_len += 1;
            relayer_fee_key.copy_from_slice(fee_ata.address().as_ref());
        }
        let mut m32 = [0u8; 32];
        m32.copy_from_slice(mint_in.address().as_ref());
        (derive_asset_id(&m32), Some(mi), e_bal)
    };

    // Validate output leg and derive `asset_out` strictly ON-CHAIN
    let (asset_out, mint_out_32, out_mint_info, pre_escrow_out_spl) = if out_kind == EXEC_KIND_SOL {
        let sol_vault = &out_leg[0];
        verify_sol_vault(program_id, pool_id, cfg.sol_vault_bump, sol_vault)?;
        if has_out_fee {
            let fee_recip = &out_leg[1];
            ensure(
                fee_recip.is_writable()
                    && fee_recip.address() != sol_vault.address()
                    && fee_recip.address() != escrow_acc.address()
                    && fee_recip.address() != program_id
                    && !fee_recip.owned_by(program_id),
                AudrenError::InvalidAccount,
            )?;
            forbidden_keys[forbidden_len] = *fee_recip.address();
            forbidden_len += 1;
            relayer_fee_key.copy_from_slice(fee_recip.address().as_ref());
        }
        (derive_asset_id(&NATIVE_SOL_MINT), NATIVE_SOL_MINT, None, 0u64)
    } else {
        let va_out = &out_leg[0];
        let mint_out = &out_leg[1];
        let vault_out_ata = &out_leg[2];
        let escrow_out_ata = &out_leg[3];
        let token_prog_out = &out_leg[4];
        ensure(va_out.address() == &exp_va, AudrenError::InvalidPda)?;
        let mi = load_mint_info(mint_out, token_prog_out.address())?;
        let _ = validate_token_account(
            vault_out_ata,
            token_prog_out.address(),
            mint_out.address(),
            va_out.address(),
            true,
        )?;
        let e_bal = validate_token_account(
            escrow_out_ata,
            token_prog_out.address(),
            mint_out.address(),
            escrow_acc.address(),
            true,
        )?;
        forbidden_keys[forbidden_len] = *vault_out_ata.address();
        forbidden_len += 1;
        if has_out_fee {
            let fee_ata = &out_leg[5];
            let fee_snap = token_account_security(fee_ata)
                .ok_or_else(|| err(AudrenError::InvalidTokenAccount))?;
            ensure(
                fee_ata.is_writable()
                    && fee_snap.token_program == *token_prog_out.address()
                    && fee_snap.mint == *mint_out.address()
                    && fee_snap.owner != exp_va
                    && fee_snap.owner != exp_escrow
                    && fee_ata.address() != vault_out_ata.address()
                    && fee_ata.address() != escrow_out_ata.address(),
                AudrenError::InvalidAccount,
            )?;
            forbidden_keys[forbidden_len] = *fee_ata.address();
            forbidden_len += 1;
            relayer_fee_key.copy_from_slice(fee_ata.address().as_ref());
        }
        let mut m32 = [0u8; 32];
        m32.copy_from_slice(mint_out.address().as_ref());
        (derive_asset_id(&m32), m32, Some(mi), e_bal)
    };

    // Forbid self-swaps (SOL -> SOL or Mint X -> Mint X)
    ensure(asset_in != asset_out, AudrenError::InvalidInstruction)?;

    // Cryptographically bind every router account pubkey, order, & writable flag inside ctx_hash.
    let router_accs_hash = hash_router_accounts_arena(router_accounts)?;

    let raw_ctx = sha256_v(&[
        CTX_DOMAIN_EXEC_VIA_ESCROW,
        program_id.as_ref(),
        &pool_le,
        &[
            out_lane_id,
            escrow_shard,
            change_mask,
            in_kind,
            out_kind,
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
        dyn_mask_56,
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
    let has_nf1 = nf1 != [0u8; 32];
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
        let m90 = &change_memos[cm_cursor..cm_cursor + MEMO_ENTRY_WIRE_LEN];
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
            m90,
            now,
        )?;
    }
    if (change_mask & 2) != 0 {
        let m90 = &change_memos[cm_cursor..cm_cursor + MEMO_ENTRY_WIRE_LEN];
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
            m90,
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
        ckpt_acc.address(),
        nf0_acc.address(),
        nf1_acc.address(),
        lane_acc.address(),
        lane_rent_vault.address(),
        subtree_acc.address(),
        subroot_acc.address(),
        memo_acc.address(),
        nf_page_acc.address(),
        &exp_va,
        &exp_sol_vault,
    ];

    let escrow_sol_baseline = escrow_acc.lamports();
    WatchedEscrowBuf::with_buf(|watched_escrow_accs| -> ProgramResult {
        let mut pre_token_mask: u128 = 0;
        for (idx, acc) in router_accounts.iter().enumerate() {
            let a = acc.address();
            ensure(
                a != program_id && !acc.owned_by(program_id),
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
                        !snap.has_delegate
                            && snap.close_authority.is_none()
                            && !snap.has_restrictive_ext,
                        AudrenError::EscrowAccountAltered,
                    )?;
                    watched_escrow_accs.push(idx, snap.token_program, snap.data_len);
                }
            }
        }

        // Fund isolated escrow (+ optional relayer fee) via CPI so Agave CPI lamport invariants hold!
        if in_kind == EXEC_KIND_SOL {
            let svb = [cfg.sol_vault_bump];
            let sv_seeds = [
                Seed::from(SOL_VAULT_SEED),
                Seed::from(&pool_le),
                Seed::from(&svb),
            ];
            Transfer {
                from: &in_leg[0],
                to: escrow_acc,
                lamports: amount_in,
            }
            .invoke_signed(&[Signer::from(&sv_seeds)])?;
            if has_in_fee {
                Transfer {
                    from: &in_leg[0],
                    to: &in_leg[1],
                    lamports: relayer_fee_amount,
                }
                .invoke_signed(&[Signer::from(&sv_seeds)])?;
            }
        } else {
            let va_in = &in_leg[0];
            let mint_in = &in_leg[1];
            let vault_in_ata = &in_leg[2];
            let escrow_in_ata = &in_leg[3];
            let token_prog_in = &in_leg[4];
            let mi = in_mint_info.unwrap();
            invoke_token_transfer_checked(
                program_id,
                va_in.address(),
                token_prog_in,
                vault_in_ata,
                mint_in,
                escrow_in_ata,
                va_in,
                amount_in,
                mi,
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
                    mi,
                    router_accounts,
                    &blocked_hook,
                    &[Signer::from(&va_seeds)],
                )?;
            }
        }

        // Invoke external DeFi router CPI via zero-alloc 64-account arena, signed ONLY by `escrow_acc`
        invoke_router_cpi_arena(
            router_prog.address(),
            router_ix_data,
            router_accounts,
            escrow_acc.address(),
            &[Signer::from(&escrow_seeds)],
        )?;

        // Unconditional post-CPI `escrow_acc` ownership, data, and lamport check across all modes.
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

    // Exact input drain check on BOTH SOL and SPL/T22 (ZERO trapped input dust!)
    if in_kind == EXEC_KIND_SOL {
        ensure(escrow_acc.lamports() == escrow_sol_baseline, AudrenError::EscrowNotDrained)?;
    } else {
        let post_escrow_in = validate_token_account(
            &in_leg[3],
            in_leg[4].address(),
            in_leg[1].address(),
            escrow_acc.address(),
            true,
        )?;
        ensure(post_escrow_in == pre_escrow_in_spl, AudrenError::EscrowNotDrained)?;
    }

    // Sweep actual output from isolated escrow -> unified output vault (& optional output-side
    // relayer fee directly from escrow) & measure exact net user vault delta!
    let actual_out = if out_kind == EXEC_KIND_SOL {
        let sol_vault = &out_leg[0];
        let escrow_after = escrow_acc.lamports();
        ensure(escrow_after >= escrow_sol_baseline, AudrenError::CustodyInvariantViolated)?;
        let gained = escrow_after - escrow_sol_baseline;
        let user_sol_out = if has_out_fee {
            let rem = gained
                .checked_sub(relayer_fee_amount)
                .ok_or_else(|| err(AudrenError::SlippageExceeded))?;
            ensure(rem >= min_amount_out && rem > 0, AudrenError::SlippageExceeded)?;
            Transfer {
                from: escrow_acc,
                to: &out_leg[1],
                lamports: relayer_fee_amount,
            }
            .invoke_signed(&[Signer::from(&escrow_seeds)])?;
            rem
        } else {
            ensure(gained >= min_amount_out && gained > 0, AudrenError::SlippageExceeded)?;
            gained
        };
        let vault_before_sweep = sol_vault.lamports();
        Transfer {
            from: escrow_acc,
            to: sol_vault,
            lamports: user_sol_out,
        }
        .invoke_signed(&[Signer::from(&escrow_seeds)])?;
        ensure(
            sol_vault.lamports()
                == vault_before_sweep
                    .checked_add(user_sol_out)
                    .ok_or_else(|| err(AudrenError::Overflow))?
                && escrow_acc.lamports() == escrow_sol_baseline,
            AudrenError::CustodyInvariantViolated,
        )?;
        user_sol_out
    } else {
        let va_out = &out_leg[0];
        let mint_out = &out_leg[1];
        let vault_out_ata = &out_leg[2];
        let escrow_out_ata = &out_leg[3];
        let token_prog_out = &out_leg[4];
        let mi_out = out_mint_info.unwrap();
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
                mi_out,
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
            mi_out,
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

    // Commit dynamic output using user's ECDH `out_blinding` and XOR-mask the 56 B dynamic
    // payload with `dyn_mask_56` so zero plaintext magic/amount/mint sits at rest in `MemoPage`.
    let dynamic_cm =
        compute_note_commitment(&out_stealth_owner, &asset_out, actual_out, &out_blinding)?;

    let mut plain_56 = [0u8; MEMO_CT_LEN];
    plain_56[0..8].copy_from_slice(&DYN_MEMO_MAGIC);
    plain_56[8..16].copy_from_slice(&actual_out.to_le_bytes());
    plain_56[16..48].copy_from_slice(&mint_out_32);

    let mut stamped_dyn_memo = [0u8; MEMO_ENTRY_WIRE_LEN];
    stamped_dyn_memo[0..DYN_MEMO_HEAD_LEN].copy_from_slice(dyn_memo_head);
    for i in 0..MEMO_CT_LEN {
        stamped_dyn_memo[DYN_MEMO_HEAD_LEN + i] = plain_56[i] ^ dyn_mask_56[i];
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

    Ok(())
}

// =============================================================================
// 8. SetPaused (authority-only emergency pause; full exits & checkpoints always remain open)
// =============================================================================

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
    let pool_id = read_u32(data, 0);
    let paused = data[4];
    ensure(paused <= 1, AudrenError::InvalidInstruction)?;

    let _cfg = load_and_verify_pool(program_id, pool_id, pool_acc)?;
    let mut pd = pool_acc.try_borrow_mut()?;
    ensure(
        &pd[PL_OFF_AUTHORITY..PL_OFF_AUTHORITY + 32] == authority.address().as_ref(),
        AudrenError::Unauthorized,
    )?;
    pd[PL_OFF_PAUSED] = paused;
    Ok(())
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
        let sol = derive_asset_id(&NATIVE_SOL_MINT);
        let wsol = derive_asset_id(&audren_core::WSOL_MINT);
        assert!(audren_core::is_canonical_fr(&sol));
        assert!(audren_core::is_canonical_fr(&wsol));
        assert_ne!(sol, wsol);
    }

    #[test]
    fn canonical_pda_derivation_is_deterministic() {
        let prog = Address::new_from_array(audren_core::AUDREN_PROGRAM_ID);
        let (p0, _) = pool_pda(&prog, 0);
        let (sv0, _) = sol_vault_pda(&prog, 0);
        let (va0, _) = vault_auth_pda(&prog, 0);
        assert_ne!(p0, sv0);
        assert_ne!(sv0, va0);
    }
}
