//! Builders for all 9 Audren v1 instructions (`0x00..=0x08`) and exact `ctx_hash` transcripts.

use std::collections::BTreeSet;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use audren_circuits::poseidon::fr_to_be_bytes;
use audren_core::{
    instruction::{
        ASSET_MODE_PRIVATE, ASSET_MODE_PUBLIC, CTX_DOMAIN_EXEC_VIA_ESCROW,
        CTX_DOMAIN_ROUTER_ACCOUNTS, CTX_DOMAIN_TRANSACT, DEPOSIT_FLAG_FEE_FROM_AMOUNT,
        DEPOSIT_FLAG_NATIVE_SOL, EXEC_FLAG_FEE_ON_OUTPUT, GROTH16_PROOF_LEN, OPEN_PAGE_KIND_MEMO,
        OPEN_PAGE_KIND_NULLIFIER, OPEN_PAGE_KIND_SUBROOT, OPEN_PAGE_KIND_SUBTREE,
        OPEN_PAGE_WIRE_LEN, TAG_DEPOSIT, TAG_EXEC_VIA_ESCROW, TAG_INIT_LANE, TAG_INIT_POOL,
        TAG_INIT_ROOT_HISTORY, TAG_OPEN_PAGE, TAG_SET_PAUSED, TAG_TRANSACT, TAG_UPDATE_POOL,
        UPDATE_POOL_ACCEPT_AUTHORITY, UPDATE_POOL_PARAMS, UPDATE_POOL_PROPOSE_AUTHORITY,
        UPDATE_POOL_RENOUNCE_AUTHORITY, WITHDRAW_FLAG_UNWRAP_WSOL,
    },
    layout::{
        DYN_MEMO_HEAD_LEN, MAX_LEAVES_PER_LANE, MEMO_CT_LEN, MEMO_ENTRY_WIRE_LEN,
        MEMO_NOTES_PER_PAGE, NF_PER_PAGE, SUBROOTS_PER_PAGE, SUBTREE_LEAVES,
    },
    CLASSIC_TOKEN_PROGRAM_ID, CU_LIMIT_DEPOSIT, CU_LIMIT_DEPOSIT_HOOK,
    CU_LIMIT_EXEC_VIA_ESCROW_BASE, CU_LIMIT_INIT_LANE, CU_LIMIT_INIT_POOL,
    CU_LIMIT_INIT_ROOT_HISTORY, CU_LIMIT_OPEN_PAGE, CU_LIMIT_TRANSACT_FULL_EXIT,
    CU_LIMIT_TRANSACT_PRIVATE, CU_LIMIT_TRANSACT_WITHDRAW, CU_LIMIT_TRANSACT_WITHDRAW_HOOK,
    EPOCH_RING_LEN, MAX_ROOT_EPOCH_INTERVAL, NUM_ESCROW_SHARDS, NUM_LANES, ROOT_RING_EPOCH,
    ROOT_RING_SLOT, SLOT_RING_LEN, SYSTEM_PROGRAM_ID, WSOL_MINT,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_address::Address;

use crate::{
    pda::{
        derive_escrow_pda, derive_lane_pda, derive_lane_rent_pda, derive_memo_pda,
        derive_nf_page_pda, derive_nullifier_pda, derive_pool_pda, derive_roots_pda,
        derive_subroot_pda, derive_subtree_pda, derive_unwrap_pda, derive_vault_auth_pda,
    },
    router::prepare_escrow_accounts_for_audren,
    ClientError,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudrenAccountMeta {
    pub pubkey: [u8; 32],
    pub is_signer: bool,
    pub is_writable: bool,
}

impl AudrenAccountMeta {
    pub fn writable(addr: Address, is_signer: bool) -> Self {
        Self {
            pubkey: addr.to_bytes(),
            is_signer,
            is_writable: true,
        }
    }

    pub fn readonly(addr: Address, is_signer: bool) -> Self {
        Self {
            pubkey: addr.to_bytes(),
            is_signer,
            is_writable: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudrenInstruction {
    pub program_id: [u8; 32],
    pub accounts: Vec<AudrenAccountMeta>,
    pub data: Vec<u8>,
}

/// Governance actions accepted by `UpdatePool` (`TAG_UPDATE_POOL = 0x08`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdatePoolAction {
    UpdateParams {
        note_rent_fee: u64,
        nf_rent_fee: u64,
    },
    ProposeAuthority {
        pending_authority: Address,
    },
    AcceptAuthority,
    RenounceAuthority,
}

/// Lookahead thresholds (`>= 90%` full) for zero-crank proactive `OpenPage` prepending.
pub const AUTO_OPEN_SUBTREE_LOOKAHEAD_REM: u64 = 26;
pub const AUTO_OPEN_MEMO_LOOKAHEAD_REM: u64 = 10;
pub const AUTO_OPEN_NF_LOOKAHEAD_REM: u64 = 60;
pub const AUTO_OPEN_SUBROOT_LOOKAHEAD_SLOT: u64 = 280;

/// Single `OpenPage` (`TAG_OPEN_PAGE = 0x02`) candidate planned for zero-crank auto-opening.
///
/// - `mandatory == true`: required by the current transaction's own rollover boundary.
/// - `mandatory == false`: proactive `>= 90%` lookahead (pass `max_payer_deficit = 0` so only
///   `LaneRentVault` pays and TOCTOU races revert cleanly instead of debiting `payer`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AutoOpenPageSpec {
    pub page_kind: u8,
    pub page_seq: u64,
    pub pda: Address,
    pub mandatory: bool,
}

/// Optional writable account context for `ExecViaEscrow` `ctx_hash` writability promotion,
/// ensuring 100% parity with Solana's instruction-wide writability merge in `build_exec_via_escrow`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExecCtxWritableAccounts {
    pub payer: Option<Address>,
    pub escrow_in_ata: Option<Address>,
    pub escrow_out_ata: Option<Address>,
    pub vault_in_ata: Option<Address>,
    pub vault_out_ata: Option<Address>,
}

/// Validate `(root_ring_kind, root_ring_idx)` against `GlobalRootHistory` ring capacities.
pub fn validate_root_ring(root_ring_kind: u8, root_ring_idx: u8) -> Result<(), ClientError> {
    match root_ring_kind {
        ROOT_RING_SLOT => {
            if (root_ring_idx as usize) >= SLOT_RING_LEN {
                return Err(ClientError::InvalidEncoding(
                    "root_ring_idx out of range for slot ring",
                ));
            }
        }
        ROOT_RING_EPOCH => {
            if (root_ring_idx as usize) >= EPOCH_RING_LEN {
                return Err(ClientError::InvalidEncoding(
                    "root_ring_idx out of range for epoch ring",
                ));
            }
        }
        _ => {
            return Err(ClientError::InvalidEncoding(
                "invalid root_ring_kind (expected 0 for slot ring or 1 for epoch ring)",
            ));
        }
    }
    Ok(())
}

/// Solana per-transaction maximum Compute Unit limit (`1,400,000` CU).
pub const MAX_TX_CU_LIMIT: u32 = 1_400_000;
/// Compute Unit cost per failed `find_program_address` bump iteration on Solana (`1,500` CU).
pub const CU_PER_PDA_BUMP_ITERATION: u32 = 1_500;
/// Recommended Compute Unit headroom per Classic SPL `CreateIdempotent` ATA instruction.
pub const CU_LIMIT_CREATE_ATA_CLASSIC: u32 = 30_000;
/// Recommended Compute Unit headroom per SPL Token-2022 `CreateIdempotent` ATA instruction.
pub const CU_LIMIT_CREATE_ATA_TOKEN_2022: u32 = 45_000;
/// Additional Compute Unit headroom for `ExecViaEscrow` when either input or output mint is Token-2022.
pub const CU_LIMIT_EXEC_VIA_ESCROW_T22_LEG: u32 = 25_000;

const fn saturating_usize_to_u32(n: usize) -> u32 {
    if n > u32::MAX as usize {
        u32::MAX
    } else {
        n as u32
    }
}

const fn clamp_tx_cu(cu: u32) -> u32 {
    if cu > MAX_TX_CU_LIMIT {
        MAX_TX_CU_LIMIT
    } else {
        cu
    }
}

/// Compute extra Compute Unit headroom for non-255 PDA bumps (`sum((255 - bump) * 1_500)`),
/// saturating and capped safely at `MAX_TX_CU_LIMIT` (`1,400,000` CU).
pub const fn compute_bump_cu_margin(bumps: &[u8]) -> u32 {
    let mut total: u32 = 0;
    let mut i = 0;
    while i < bumps.len() {
        let delta = ((255u8 - bumps[i]) as u32).saturating_mul(CU_PER_PDA_BUMP_ITERATION);
        total = total.saturating_add(delta);
        if total >= MAX_TX_CU_LIMIT {
            return MAX_TX_CU_LIMIT;
        }
        i += 1;
    }
    total
}

/// Tight recommended Compute Unit budgets matching `audren_core::CU_LIMIT_*`.
pub const fn recommended_cu_limit_init_pool() -> u32 {
    CU_LIMIT_INIT_POOL
}

pub const fn recommended_cu_limit_init_lane() -> u32 {
    CU_LIMIT_INIT_LANE
}

pub const fn recommended_cu_limit_init_root_history() -> u32 {
    CU_LIMIT_INIT_ROOT_HISTORY
}

pub const fn recommended_cu_limit_open_page(open_page_count: usize) -> u32 {
    clamp_tx_cu(CU_LIMIT_OPEN_PAGE.saturating_mul(saturating_usize_to_u32(open_page_count)))
}

pub const fn recommended_cu_limit_create_ata(
    classic_ata_count: usize,
    token_2022_ata_count: usize,
) -> u32 {
    let classic =
        CU_LIMIT_CREATE_ATA_CLASSIC.saturating_mul(saturating_usize_to_u32(classic_ata_count));
    let t22 = CU_LIMIT_CREATE_ATA_TOKEN_2022
        .saturating_mul(saturating_usize_to_u32(token_2022_ata_count));
    clamp_tx_cu(classic.saturating_add(t22))
}

pub const fn recommended_cu_limit_deposit(has_transfer_hook: bool, open_page_count: usize) -> u32 {
    recommended_cu_limit_deposit_with_atas(has_transfer_hook, open_page_count, 0, 0)
}

pub const fn recommended_cu_limit_deposit_with_atas(
    has_transfer_hook: bool,
    open_page_count: usize,
    create_ata_count: usize,
    create_token_2022_ata_count: usize,
) -> u32 {
    let base = if has_transfer_hook {
        CU_LIMIT_DEPOSIT_HOOK
    } else {
        CU_LIMIT_DEPOSIT
    };
    clamp_tx_cu(
        base.saturating_add(recommended_cu_limit_open_page(open_page_count))
            .saturating_add(recommended_cu_limit_create_ata(
                create_ata_count,
                create_token_2022_ata_count,
            )),
    )
}

pub const fn recommended_cu_limit_transact(
    is_public_withdraw: bool,
    output_mask: u8,
    has_transfer_hook: bool,
    open_page_count: usize,
    create_ata_count: usize,
) -> u32 {
    recommended_cu_limit_transact_with_atas(
        is_public_withdraw,
        output_mask,
        has_transfer_hook,
        open_page_count,
        create_ata_count,
        0,
    )
}

pub const fn recommended_cu_limit_transact_with_atas(
    is_public_withdraw: bool,
    output_mask: u8,
    has_transfer_hook: bool,
    open_page_count: usize,
    create_ata_count: usize,
    create_token_2022_ata_count: usize,
) -> u32 {
    let base = if !is_public_withdraw {
        CU_LIMIT_TRANSACT_PRIVATE
    } else if has_transfer_hook {
        CU_LIMIT_TRANSACT_WITHDRAW_HOOK
    } else if output_mask == 0 {
        CU_LIMIT_TRANSACT_FULL_EXIT
    } else {
        CU_LIMIT_TRANSACT_WITHDRAW
    };
    clamp_tx_cu(
        base.saturating_add(recommended_cu_limit_open_page(open_page_count))
            .saturating_add(recommended_cu_limit_create_ata(
                create_ata_count,
                create_token_2022_ata_count,
            )),
    )
}

pub const fn recommended_cu_limit_exec_via_escrow(
    router_cu_estimate: u32,
    open_page_count: usize,
    create_ata_count: usize,
) -> u32 {
    recommended_cu_limit_exec_via_escrow_with_atas(
        router_cu_estimate,
        false,
        open_page_count,
        create_ata_count,
        0,
    )
}

pub const fn recommended_cu_limit_exec_via_escrow_with_atas(
    router_cu_estimate: u32,
    has_token_2022_leg: bool,
    open_page_count: usize,
    create_ata_count: usize,
    create_token_2022_ata_count: usize,
) -> u32 {
    let leg_cu = if has_token_2022_leg {
        CU_LIMIT_EXEC_VIA_ESCROW_T22_LEG
    } else {
        0
    };
    clamp_tx_cu(
        CU_LIMIT_EXEC_VIA_ESCROW_BASE
            .saturating_add(leg_cu)
            .saturating_add(router_cu_estimate)
            .saturating_add(recommended_cu_limit_open_page(open_page_count))
            .saturating_add(recommended_cu_limit_create_ata(
                create_ata_count,
                create_token_2022_ata_count,
            )),
    )
}

pub const fn recommended_cu_limit_open_page_with_bumps(
    open_page_count: usize,
    bumps: &[u8],
) -> u32 {
    clamp_tx_cu(
        recommended_cu_limit_open_page(open_page_count)
            .saturating_add(compute_bump_cu_margin(bumps)),
    )
}

pub const fn recommended_cu_limit_deposit_with_bumps(
    has_transfer_hook: bool,
    open_page_count: usize,
    create_ata_count: usize,
    create_token_2022_ata_count: usize,
    bumps: &[u8],
) -> u32 {
    clamp_tx_cu(
        recommended_cu_limit_deposit_with_atas(
            has_transfer_hook,
            open_page_count,
            create_ata_count,
            create_token_2022_ata_count,
        )
        .saturating_add(compute_bump_cu_margin(bumps)),
    )
}

pub const fn recommended_cu_limit_transact_with_bumps(
    is_public_withdraw: bool,
    output_mask: u8,
    has_transfer_hook: bool,
    open_page_count: usize,
    create_ata_count: usize,
    create_token_2022_ata_count: usize,
    bumps: &[u8],
) -> u32 {
    clamp_tx_cu(
        recommended_cu_limit_transact_with_atas(
            is_public_withdraw,
            output_mask,
            has_transfer_hook,
            open_page_count,
            create_ata_count,
            create_token_2022_ata_count,
        )
        .saturating_add(compute_bump_cu_margin(bumps)),
    )
}

pub const fn recommended_cu_limit_exec_via_escrow_with_bumps(
    router_cu_estimate: u32,
    has_token_2022_leg: bool,
    open_page_count: usize,
    create_ata_count: usize,
    create_token_2022_ata_count: usize,
    bumps: &[u8],
) -> u32 {
    clamp_tx_cu(
        recommended_cu_limit_exec_via_escrow_with_atas(
            router_cu_estimate,
            has_token_2022_leg,
            open_page_count,
            create_ata_count,
            create_token_2022_ata_count,
        )
        .saturating_add(compute_bump_cu_margin(bumps)),
    )
}

fn sys_id() -> Address {
    Address::new_from_array(SYSTEM_PROGRAM_ID)
}

fn mask_to_fr(digest: &[u8; 32]) -> Fr {
    let m = audren_core::mask_to_fr_be(*digest);
    Fr::from_be_bytes_mod_order(&m)
}

/// Deterministic per-note `LaneRentVault` fee matching `deterministic_note_rent_fee` on-chain.
pub fn deterministic_note_rent_fee(
    pool_note_rent_fee_cap: u64,
    sub_rent: u64,
    sr_rent: u64,
    memo_rent: u64,
) -> u64 {
    let live = sub_rent
        .max(1)
        .div_ceil(SUBTREE_LEAVES as u64)
        .saturating_add(
            sr_rent
                .max(1)
                .div_ceil((SUBTREE_LEAVES * SUBROOTS_PER_PAGE) as u64),
        )
        .saturating_add(memo_rent.max(1).div_ceil(MEMO_NOTES_PER_PAGE as u64));
    pool_note_rent_fee_cap.min(live)
}

/// Primary page sequences and atomic rollover page sequences for a lane write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageRolloverPlan {
    pub out_sub_seq: u64,
    pub out_root_seq: u64,
    pub out_memo_seq: u64,
    pub nf_page_seq: u64,
    pub next_sub_seq: Option<u64>,
    pub next_root_seq: Option<u64>,
    pub next_memo_seq: Option<u64>,
    pub next_nf_seq: Option<u64>,
}

/// Compute primary page sequences and atomic rollover page sequences matching
/// `append_leaf_and_memo` and `append_nullifier_prefix` in `program/src/lib.rs` byte-for-byte.
pub fn compute_page_rollovers(
    leaf_count: u64,
    output_count: usize,
    nf_count: u64,
    spent_nullifiers: usize,
) -> PageRolloverPlan {
    let sub_size = SUBTREE_LEAVES as u64;
    let sr_size = SUBROOTS_PER_PAGE as u64;
    let memo_size = MEMO_NOTES_PER_PAGE as u64;
    let nf_size = NF_PER_PAGE as u64;

    let out_sub_seq = leaf_count / sub_size;
    let out_root_seq = out_sub_seq / sr_size;
    let out_memo_seq = leaf_count / memo_size;
    let nf_page_seq = nf_count / nf_size;

    let (next_sub_seq, next_root_seq, next_memo_seq) = if output_count > 0 {
        let last_leaf = leaf_count.saturating_add((output_count - 1) as u64);
        let last_sub = last_leaf / sub_size;
        let last_root = last_sub / sr_size;
        let last_memo = last_leaf / memo_size;
        (
            (last_sub > out_sub_seq).then_some(last_sub),
            (last_root > out_root_seq).then_some(last_root),
            (last_memo > out_memo_seq).then_some(last_memo),
        )
    } else {
        (None, None, None)
    };

    let next_nf_seq = if spent_nullifiers > 0 {
        let last_nf = nf_count.saturating_add((spent_nullifiers - 1) as u64);
        let last_nf_seq = last_nf / nf_size;
        (last_nf_seq > nf_page_seq).then_some(last_nf_seq)
    } else {
        None
    };

    PageRolloverPlan {
        out_sub_seq,
        out_root_seq,
        out_memo_seq,
        nf_page_seq,
        next_sub_seq,
        next_root_seq,
        next_memo_seq,
        next_nf_seq,
    }
}

/// Return all candidate `OpenPage` PDAs that may be needed at exact rollover or `>= 90%` lookahead
/// (`sub_rem <= 26`, `memo_rem <= 10`, `nf_rem <= 60`, `subroot_slot >= 280`) for `(lane_id, next_leaf, nf_count)`.
///
/// Callers can check these PDAs in a single `getMultipleAccounts` batch, build `existing_pages`
/// from already-initialized accounts, and pass that set to [`plan_auto_open_pages`] or
/// [`build_auto_open_page_ixs`].
#[allow(clippy::too_many_arguments)]
pub fn plan_auto_open_pages(
    program_id: &Address,
    pool_id: u32,
    lane_id: u8,
    next_leaf: u64,
    nf_count: u64,
    num_outputs: usize,
    num_nfs: usize,
    existing_pages: &BTreeSet<Address>,
) -> Result<Vec<AutoOpenPageSpec>, ClientError> {
    if (lane_id as usize) >= NUM_LANES {
        return Err(ClientError::InvalidEncoding("lane_id out of range"));
    }

    let sub_size = SUBTREE_LEAVES as u64;
    let sr_size = SUBROOTS_PER_PAGE as u64;
    let memo_size = MEMO_NOTES_PER_PAGE as u64;
    let nf_size = NF_PER_PAGE as u64;
    let num_outputs_u64 = u64::try_from(num_outputs).unwrap_or(u64::MAX);
    let num_nfs_u64 = u64::try_from(num_nfs).unwrap_or(u64::MAX);

    let mut specs: Vec<AutoOpenPageSpec> = Vec::new();
    let mut seen: std::collections::BTreeMap<(u8, u64), usize> = std::collections::BTreeMap::new();

    let mut maybe_push = |page_kind: u8, page_seq: u64, pda: Address, mandatory: bool| {
        if existing_pages.contains(&pda) {
            return;
        }
        if let Some(&idx) = seen.get(&(page_kind, page_seq)) {
            if mandatory {
                specs[idx].mandatory = true;
            }
            return;
        }
        seen.insert((page_kind, page_seq), specs.len());
        specs.push(AutoOpenPageSpec {
            page_kind,
            page_seq,
            pda,
            mandatory,
        });
    };

    let max_sub_pages = MAX_LEAVES_PER_LANE / sub_size;
    let max_sr_pages = max_sub_pages.div_ceil(sr_size);
    let max_memo_pages = MAX_LEAVES_PER_LANE.div_ceil(memo_size);

    if num_outputs > 0 && next_leaf < MAX_LEAVES_PER_LANE {
        let cur_sub = next_leaf / sub_size;
        let sub_used = next_leaf % sub_size;
        let sub_rem = sub_size - sub_used;
        if cur_sub > 0 && sub_used == 0 {
            maybe_push(
                OPEN_PAGE_KIND_SUBTREE,
                cur_sub,
                derive_subtree_pda(program_id, pool_id, lane_id, cur_sub).0,
                true,
            );
        }
        let sub_mandatory_next = sub_rem < num_outputs_u64;
        if sub_mandatory_next || sub_rem <= AUTO_OPEN_SUBTREE_LOOKAHEAD_REM {
            if let Some(next_sub) = cur_sub.checked_add(1) {
                if next_sub < max_sub_pages {
                    maybe_push(
                        OPEN_PAGE_KIND_SUBTREE,
                        next_sub,
                        derive_subtree_pda(program_id, pool_id, lane_id, next_sub).0,
                        sub_mandatory_next,
                    );
                }
            }
        }

        let cur_sr = cur_sub / sr_size;
        let subroot_slot = cur_sub % sr_size;
        if cur_sr > 0 && subroot_slot == 0 {
            maybe_push(
                OPEN_PAGE_KIND_SUBROOT,
                cur_sr,
                derive_subroot_pda(program_id, pool_id, lane_id, cur_sr).0,
                true,
            );
        }
        let sr_mandatory_next = sub_mandatory_next
            && cur_sub
                .checked_add(1)
                .map(|ns| ns / sr_size > cur_sr)
                .unwrap_or(false);
        if sr_mandatory_next || subroot_slot >= AUTO_OPEN_SUBROOT_LOOKAHEAD_SLOT {
            if let Some(next_sr) = cur_sr.checked_add(1) {
                if next_sr < max_sr_pages {
                    maybe_push(
                        OPEN_PAGE_KIND_SUBROOT,
                        next_sr,
                        derive_subroot_pda(program_id, pool_id, lane_id, next_sr).0,
                        sr_mandatory_next,
                    );
                }
            }
        }

        let cur_memo = next_leaf / memo_size;
        let memo_used = next_leaf % memo_size;
        let memo_rem = memo_size - memo_used;
        if cur_memo > 0 && memo_used == 0 {
            maybe_push(
                OPEN_PAGE_KIND_MEMO,
                cur_memo,
                derive_memo_pda(program_id, pool_id, lane_id, cur_memo).0,
                true,
            );
        }
        let memo_mandatory_next = memo_rem < num_outputs_u64;
        if memo_mandatory_next || memo_rem <= AUTO_OPEN_MEMO_LOOKAHEAD_REM {
            if let Some(next_memo) = cur_memo.checked_add(1) {
                if next_memo < max_memo_pages {
                    maybe_push(
                        OPEN_PAGE_KIND_MEMO,
                        next_memo,
                        derive_memo_pda(program_id, pool_id, lane_id, next_memo).0,
                        memo_mandatory_next,
                    );
                }
            }
        }
    }

    if num_nfs > 0 {
        let cur_nf = nf_count / nf_size;
        let nf_used = nf_count % nf_size;
        let nf_rem = nf_size - nf_used;
        if cur_nf > 0 && nf_used == 0 {
            maybe_push(
                OPEN_PAGE_KIND_NULLIFIER,
                cur_nf,
                derive_nf_page_pda(program_id, pool_id, lane_id, cur_nf).0,
                true,
            );
        }
        let nf_mandatory_next = nf_rem < num_nfs_u64;
        if nf_mandatory_next || nf_rem <= AUTO_OPEN_NF_LOOKAHEAD_REM {
            if let Some(next_nf) = cur_nf.checked_add(1) {
                maybe_push(
                    OPEN_PAGE_KIND_NULLIFIER,
                    next_nf,
                    derive_nf_page_pda(program_id, pool_id, lane_id, next_nf).0,
                    nf_mandatory_next,
                );
            }
        }
    }

    Ok(specs)
}

/// Build idempotent `OpenPage` (`TAG_OPEN_PAGE = 0x02`) instructions with explicit control over
/// proactive `>= 90%` lookaheads and mandatory rollover `max_payer_deficit`.
///
/// Proactive (`!mandatory`) lookahead instructions ALWAYS set `max_payer_deficit = 0` so
/// `LaneRentVault` bears 100% of rent and TOCTOU drains revert cleanly instead of debiting `payer`.
#[allow(clippy::too_many_arguments)]
pub fn build_auto_open_page_ixs_with_options(
    program_id: Address,
    payer: Address,
    pool_id: u32,
    lane_id: u8,
    next_leaf: u64,
    nf_count: u64,
    num_outputs: usize,
    num_nfs: usize,
    existing_pages: &BTreeSet<Address>,
    include_proactive: bool,
    mandatory_max_payer_deficit: u64,
) -> Result<Vec<AudrenInstruction>, ClientError> {
    let specs = plan_auto_open_pages(
        &program_id,
        pool_id,
        lane_id,
        next_leaf,
        nf_count,
        num_outputs,
        num_nfs,
        existing_pages,
    )?;
    specs
        .into_iter()
        .filter(|s| s.mandatory || include_proactive)
        .map(|s| {
            let max_deficit = if s.mandatory {
                mandatory_max_payer_deficit
            } else {
                0
            };
            try_build_open_page(
                program_id,
                payer,
                s.page_kind,
                pool_id,
                lane_id,
                s.page_seq,
                max_deficit,
            )
        })
        .collect()
}

/// Build idempotent `OpenPage` (`TAG_OPEN_PAGE = 0x02`) instructions to prepend in the same
/// Transaction v1 whenever a lane is at exact rollover or `>= 90%` full and the target page PDA
/// is not yet initialized. Proactive lookahead pages pass `max_payer_deficit = 0`.
#[allow(clippy::too_many_arguments)]
pub fn build_auto_open_page_ixs(
    program_id: Address,
    payer: Address,
    pool_id: u32,
    lane_id: u8,
    next_leaf: u64,
    nf_count: u64,
    num_outputs: usize,
    num_nfs: usize,
    existing_pages: &BTreeSet<Address>,
) -> Result<Vec<AudrenInstruction>, ClientError> {
    build_auto_open_page_ixs_with_options(
        program_id,
        payer,
        pool_id,
        lane_id,
        next_leaf,
        nf_count,
        num_outputs,
        num_nfs,
        existing_pages,
        true,
        u64::MAX,
    )
}

/// Fallible exact `Transact` (`0x05`) `ctx_hash` matching `program/src/lib.rs` bit-for-bit.
#[allow(clippy::too_many_arguments)]
pub fn try_compute_transact_ctx_hash(
    program_id: &Address,
    pool_id: u32,
    vk_id: u8,
    out_lane_id: u8,
    output_mask: u8,
    asset_mode: u8,
    unwrap_wsol: bool,
    recipient: Option<&Address>,
    relayer_fee_recipient: Option<&Address>,
    public_asset_id: &[u8; 32],
    public_amount_out: u64,
    relayer_fee_amount: u64,
    memos_bytes: &[u8],
) -> Result<Fr, ClientError> {
    if (out_lane_id as usize) >= NUM_LANES {
        return Err(ClientError::InvalidEncoding("out_lane_id out of range"));
    }
    if output_mask > 0b111 {
        return Err(ClientError::InvalidEncoding("output_mask must be 0..=7"));
    }
    if asset_mode != ASSET_MODE_PRIVATE && asset_mode != ASSET_MODE_PUBLIC {
        return Err(ClientError::InvalidEncoding(
            "asset_mode must be 0 (PRIVATE) or 1 (PUBLIC)",
        ));
    }
    if unwrap_wsol && asset_mode != ASSET_MODE_PUBLIC {
        return Err(ClientError::InvalidEncoding(
            "unwrap_wsol requires ASSET_MODE_PUBLIC",
        ));
    }
    let rec_bytes: [u8; 32] = if public_amount_out > 0 {
        recipient
            .ok_or(ClientError::InvalidEncoding(
                "recipient required when public_amount_out > 0",
            ))?
            .to_bytes()
    } else {
        [0u8; 32]
    };
    let fee_rec_bytes: [u8; 32] = if relayer_fee_amount > 0 {
        relayer_fee_recipient
            .ok_or(ClientError::InvalidEncoding(
                "relayer_fee_recipient required when relayer_fee_amount > 0",
            ))?
            .to_bytes()
    } else {
        [0u8; 32]
    };

    let mut h = Sha256::new();
    h.update(CTX_DOMAIN_TRANSACT);
    h.update(program_id.as_ref());
    h.update(pool_id.to_le_bytes());
    h.update([
        vk_id,
        out_lane_id,
        output_mask,
        asset_mode,
        u8::from(unwrap_wsol),
    ]);
    h.update(rec_bytes);
    h.update(fee_rec_bytes);
    h.update(public_asset_id);
    h.update(public_amount_out.to_le_bytes());
    h.update(relayer_fee_amount.to_le_bytes());
    h.update(memos_bytes);
    let digest: [u8; 32] = h.finalize().into();
    Ok(mask_to_fr(&digest))
}

/// Exact `Transact` (`0x05`) `ctx_hash` matching `program/src/lib.rs` bit-for-bit (with `vk_id` bound).
#[allow(clippy::too_many_arguments)]
pub fn compute_transact_ctx_hash(
    program_id: &Address,
    pool_id: u32,
    vk_id: u8,
    out_lane_id: u8,
    output_mask: u8,
    asset_mode: u8,
    unwrap_wsol: bool,
    recipient: Option<&Address>,
    relayer_fee_recipient: Option<&Address>,
    public_asset_id: &[u8; 32],
    public_amount_out: u64,
    relayer_fee_amount: u64,
    memos_bytes: &[u8],
) -> Fr {
    try_compute_transact_ctx_hash(
        program_id,
        pool_id,
        vk_id,
        out_lane_id,
        output_mask,
        asset_mode,
        unwrap_wsol,
        recipient,
        relayer_fee_recipient,
        public_asset_id,
        public_amount_out,
        relayer_fee_amount,
        memos_bytes,
    )
    .expect("valid Transact ctx_hash parameters")
}

/// Exact `router_accounts` hash matching `hash_router_accounts_arena` in `program/src/lib.rs`.
pub fn compute_router_accounts_hash(router_accounts: &[AudrenAccountMeta]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CTX_DOMAIN_ROUTER_ACCOUNTS);
    h.update((router_accounts.len() as u16).to_le_bytes());
    for acc in router_accounts {
        h.update(acc.pubkey);
        h.update([u8::from(acc.is_writable)]);
    }
    h.finalize().into()
}

/// Collect every writable account preceding `router_accounts` in `ExecViaEscrow` that can
/// trigger Solana's instruction-wide writability merge (`payer`, `escrow_in_ata`,
/// `escrow_out_ata`, `vault_in_ata`, `vault_out_ata`, `relayer_fee_recipient`, plus
/// `extra_writable_pubkeys`), matching `build_exec_via_escrow` and on-chain `ix_exec_via_escrow`.
pub fn collect_exec_writable_pubkeys(
    writable_accounts: Option<&ExecCtxWritableAccounts>,
    relayer_fee_amount: u64,
    relayer_fee_recipient: Option<&Address>,
    extra_writable_pubkeys: &[Address],
) -> Vec<Address> {
    let mut out = Vec::with_capacity(6 + extra_writable_pubkeys.len());
    if let Some(w) = writable_accounts {
        if let Some(a) = w.payer {
            out.push(a);
        }
        if let Some(a) = w.escrow_in_ata {
            out.push(a);
        }
        if let Some(a) = w.escrow_out_ata {
            out.push(a);
        }
        if let Some(a) = w.vault_in_ata {
            out.push(a);
        }
        if let Some(a) = w.vault_out_ata {
            out.push(a);
        }
    }
    if relayer_fee_amount > 0 {
        if let Some(fee_r) = relayer_fee_recipient {
            out.push(*fee_r);
        }
    }
    out.extend_from_slice(extra_writable_pubkeys);
    out
}

/// Fallible exact `ExecViaEscrow` (`0x06`) `ctx_hash` matching `program/src/lib.rs` bit-for-bit,
/// with full writability-promotion parity against `build_exec_via_escrow` (covering `payer`,
/// `escrow_pda`, `escrow_in_ata`, `escrow_out_ata`, `vault_in_ata`, `vault_out_ata`,
/// `relayer_fee_recipient`, and `extra_writable_pubkeys`).
#[allow(clippy::too_many_arguments)]
pub fn try_compute_exec_ctx_hash_with_writable(
    program_id: &Address,
    pool_id: u32,
    vk_id: u8,
    out_lane_id: u8,
    escrow_shard: u8,
    change_mask: u8,
    fee_on_output: bool,
    asset_in: &[u8; 32],
    amount_in: u64,
    relayer_fee_amount: u64,
    relayer_fee_recipient: Option<&Address>,
    asset_out: &[u8; 32],
    min_amount_out: u64,
    router_prog: &Address,
    router_accounts: &[AudrenAccountMeta],
    writable_accounts: Option<&ExecCtxWritableAccounts>,
    extra_writable_pubkeys: &[Address],
    out_stealth_owner: &[u8; 32],
    out_blinding: &[u8; 32],
    dyn_memo_head: &[u8; DYN_MEMO_HEAD_LEN],
    dyn_mask_72: &[u8; MEMO_CT_LEN],
    router_ix_data: &[u8],
    change_memos: &[u8],
) -> Result<Fr, ClientError> {
    if (out_lane_id as usize) >= NUM_LANES {
        return Err(ClientError::InvalidEncoding("out_lane_id out of range"));
    }
    if (escrow_shard as usize) >= NUM_ESCROW_SHARDS {
        return Err(ClientError::InvalidEncoding("escrow_shard out of range"));
    }
    if change_mask > 0b11 {
        return Err(ClientError::InvalidEncoding("change_mask must be 0..=3"));
    }
    if u16::try_from(router_accounts.len()).is_err() {
        return Err(ClientError::InvalidEncoding(
            "router_accounts length exceeds u16::MAX",
        ));
    }
    let router_ix_len = u16::try_from(router_ix_data.len()).map_err(|_| {
        ClientError::InvalidEncoding("router_ix_data length exceeds u16::MAX")
    })?;
    let fee_rec_bytes: [u8; 32] = if relayer_fee_amount > 0 {
        relayer_fee_recipient
            .ok_or(ClientError::InvalidEncoding(
                "relayer_fee_recipient required when relayer_fee_amount > 0",
            ))?
            .to_bytes()
    } else {
        [0u8; 32]
    };

    let (escrow_pda, _) = derive_escrow_pda(program_id, pool_id, escrow_shard);
    let extra_writable = collect_exec_writable_pubkeys(
        writable_accounts,
        relayer_fee_amount,
        relayer_fee_recipient,
        extra_writable_pubkeys,
    );
    let normalized_router_accs =
        prepare_escrow_accounts_for_audren(router_accounts, &escrow_pda, &extra_writable);
    let router_accs_hash = compute_router_accounts_hash(&normalized_router_accs);

    let mut h = Sha256::new();
    h.update(CTX_DOMAIN_EXEC_VIA_ESCROW);
    h.update(program_id.as_ref());
    h.update(pool_id.to_le_bytes());
    h.update([
        vk_id,
        out_lane_id,
        escrow_shard,
        change_mask,
        u8::from(fee_on_output),
    ]);
    h.update(asset_in);
    h.update(amount_in.to_le_bytes());
    h.update(relayer_fee_amount.to_le_bytes());
    h.update(fee_rec_bytes);
    h.update(asset_out);
    h.update(min_amount_out.to_le_bytes());
    h.update(router_prog.as_ref());
    h.update(router_accs_hash);
    h.update(out_stealth_owner);
    h.update(out_blinding);
    h.update(dyn_memo_head);
    h.update(dyn_mask_72);
    h.update(router_ix_len.to_le_bytes());
    h.update(router_ix_data);
    h.update(change_memos);
    let digest: [u8; 32] = h.finalize().into();
    Ok(mask_to_fr(&digest))
}

/// Fallible exact `ExecViaEscrow` (`0x06`) `ctx_hash` matching `program/src/lib.rs` bit-for-bit.
///
/// Applies Solana's transaction-wide writability promotion across `escrow_pda`,
/// `relayer_fee_recipient`, `extra_writable_pubkeys`, and duplicate writable `router_accounts`
/// before hashing `router_accounts` so on-chain `hash_router_accounts_arena` matches identically.
/// For automatic promotion of `payer`, `escrow_in_ata`, `escrow_out_ata`, `vault_in_ata`, and
/// `vault_out_ata` without manually listing them in `extra_writable_pubkeys`, use
/// [`try_compute_exec_ctx_hash_with_writable`].
#[allow(clippy::too_many_arguments)]
pub fn try_compute_exec_ctx_hash(
    program_id: &Address,
    pool_id: u32,
    vk_id: u8,
    out_lane_id: u8,
    escrow_shard: u8,
    change_mask: u8,
    fee_on_output: bool,
    asset_in: &[u8; 32],
    amount_in: u64,
    relayer_fee_amount: u64,
    relayer_fee_recipient: Option<&Address>,
    asset_out: &[u8; 32],
    min_amount_out: u64,
    router_prog: &Address,
    router_accounts: &[AudrenAccountMeta],
    extra_writable_pubkeys: &[Address],
    out_stealth_owner: &[u8; 32],
    out_blinding: &[u8; 32],
    dyn_memo_head: &[u8; DYN_MEMO_HEAD_LEN],
    dyn_mask_72: &[u8; MEMO_CT_LEN],
    router_ix_data: &[u8],
    change_memos: &[u8],
) -> Result<Fr, ClientError> {
    try_compute_exec_ctx_hash_with_writable(
        program_id,
        pool_id,
        vk_id,
        out_lane_id,
        escrow_shard,
        change_mask,
        fee_on_output,
        asset_in,
        amount_in,
        relayer_fee_amount,
        relayer_fee_recipient,
        asset_out,
        min_amount_out,
        router_prog,
        router_accounts,
        None,
        extra_writable_pubkeys,
        out_stealth_owner,
        out_blinding,
        dyn_memo_head,
        dyn_mask_72,
        router_ix_data,
        change_memos,
    )
}

/// Exact `ExecViaEscrow` (`0x06`) `ctx_hash` matching `program/src/lib.rs` bit-for-bit (with `vk_id` bound).
///
/// Applies Solana's transaction-wide writability promotion across `escrow_pda`,
/// `relayer_fee_recipient`, `extra_writable_pubkeys`, and duplicate writable `router_accounts`
/// before hashing `router_accounts` so on-chain `hash_router_accounts_arena` matches identically.
#[allow(clippy::too_many_arguments)]
pub fn compute_exec_ctx_hash(
    program_id: &Address,
    pool_id: u32,
    vk_id: u8,
    out_lane_id: u8,
    escrow_shard: u8,
    change_mask: u8,
    fee_on_output: bool,
    asset_in: &[u8; 32],
    amount_in: u64,
    relayer_fee_amount: u64,
    relayer_fee_recipient: Option<&Address>,
    asset_out: &[u8; 32],
    min_amount_out: u64,
    router_prog: &Address,
    router_accounts: &[AudrenAccountMeta],
    extra_writable_pubkeys: &[Address],
    out_stealth_owner: &[u8; 32],
    out_blinding: &[u8; 32],
    dyn_memo_head: &[u8; DYN_MEMO_HEAD_LEN],
    dyn_mask_72: &[u8; MEMO_CT_LEN],
    router_ix_data: &[u8],
    change_memos: &[u8],
) -> Fr {
    try_compute_exec_ctx_hash(
        program_id,
        pool_id,
        vk_id,
        out_lane_id,
        escrow_shard,
        change_mask,
        fee_on_output,
        asset_in,
        amount_in,
        relayer_fee_amount,
        relayer_fee_recipient,
        asset_out,
        min_amount_out,
        router_prog,
        router_accounts,
        extra_writable_pubkeys,
        out_stealth_owner,
        out_blinding,
        dyn_memo_head,
        dyn_mask_72,
        router_ix_data,
        change_memos,
    )
    .expect("valid ExecViaEscrow ctx_hash parameters")
}

// =============================================================================
// 9 Canonical Audren v1 Instruction Builders (0x00..=0x08)
// =============================================================================

pub fn try_build_init_pool(
    program_id: Address,
    payer: Address,
    pool_id: u32,
    root_epoch_interval: u64,
    note_rent_fee: u64,
    nf_rent_fee: u64,
) -> Result<AudrenInstruction, ClientError> {
    if !(1..=MAX_ROOT_EPOCH_INTERVAL).contains(&root_epoch_interval) {
        return Err(ClientError::InvalidEncoding(
            "root_epoch_interval must be in 1..=MAX_ROOT_EPOCH_INTERVAL",
        ));
    }
    let mut data = Vec::with_capacity(29);
    data.push(TAG_INIT_POOL);
    data.extend_from_slice(&pool_id.to_le_bytes());
    data.extend_from_slice(&root_epoch_interval.to_le_bytes());
    data.extend_from_slice(&note_rent_fee.to_le_bytes());
    data.extend_from_slice(&nf_rent_fee.to_le_bytes());
    Ok(AudrenInstruction {
        program_id: program_id.to_bytes(),
        accounts: vec![
            AudrenAccountMeta::writable(payer, true),
            AudrenAccountMeta::writable(derive_pool_pda(&program_id, pool_id).0, false),
            AudrenAccountMeta::writable(derive_roots_pda(&program_id, pool_id).0, false),
            AudrenAccountMeta::readonly(sys_id(), false),
        ],
        data,
    })
}

pub fn build_init_pool(
    program_id: Address,
    payer: Address,
    pool_id: u32,
    root_epoch_interval: u64,
    note_rent_fee: u64,
    nf_rent_fee: u64,
) -> AudrenInstruction {
    try_build_init_pool(
        program_id,
        payer,
        pool_id,
        root_epoch_interval,
        note_rent_fee,
        nf_rent_fee,
    )
    .expect("valid InitPool parameters")
}

pub fn try_build_init_lane(
    program_id: Address,
    authority: Address,
    pool_id: u32,
    lane_id: u8,
) -> Result<AudrenInstruction, ClientError> {
    if (lane_id as usize) >= NUM_LANES {
        return Err(ClientError::InvalidEncoding("lane_id out of range"));
    }
    let mut data = Vec::with_capacity(6);
    data.push(TAG_INIT_LANE);
    data.extend_from_slice(&pool_id.to_le_bytes());
    data.push(lane_id);
    Ok(AudrenInstruction {
        program_id: program_id.to_bytes(),
        accounts: vec![
            AudrenAccountMeta::writable(authority, true),
            AudrenAccountMeta::writable(derive_pool_pda(&program_id, pool_id).0, false),
            AudrenAccountMeta::writable(derive_lane_pda(&program_id, pool_id, lane_id).0, false),
            AudrenAccountMeta::writable(
                derive_lane_rent_pda(&program_id, pool_id, lane_id).0,
                false,
            ),
            AudrenAccountMeta::writable(
                derive_subtree_pda(&program_id, pool_id, lane_id, 0).0,
                false,
            ),
            AudrenAccountMeta::writable(
                derive_subroot_pda(&program_id, pool_id, lane_id, 0).0,
                false,
            ),
            AudrenAccountMeta::writable(derive_memo_pda(&program_id, pool_id, lane_id, 0).0, false),
            AudrenAccountMeta::writable(
                derive_nf_page_pda(&program_id, pool_id, lane_id, 0).0,
                false,
            ),
            AudrenAccountMeta::readonly(sys_id(), false),
        ],
        data,
    })
}

pub fn build_init_lane(
    program_id: Address,
    authority: Address,
    pool_id: u32,
    lane_id: u8,
) -> AudrenInstruction {
    try_build_init_lane(program_id, authority, pool_id, lane_id)
        .expect("valid InitLane parameters")
}

pub fn try_build_open_page(
    program_id: Address,
    payer: Address,
    page_kind: u8,
    pool_id: u32,
    lane_id: u8,
    page_seq: u64,
    max_payer_deficit: u64,
) -> Result<AudrenInstruction, ClientError> {
    if (lane_id as usize) >= NUM_LANES {
        return Err(ClientError::InvalidEncoding("lane_id out of range"));
    }
    let page_pda = match page_kind {
        OPEN_PAGE_KIND_SUBTREE => derive_subtree_pda(&program_id, pool_id, lane_id, page_seq).0,
        OPEN_PAGE_KIND_SUBROOT => derive_subroot_pda(&program_id, pool_id, lane_id, page_seq).0,
        OPEN_PAGE_KIND_MEMO => derive_memo_pda(&program_id, pool_id, lane_id, page_seq).0,
        OPEN_PAGE_KIND_NULLIFIER => derive_nf_page_pda(&program_id, pool_id, lane_id, page_seq).0,
        _ => {
            return Err(ClientError::InvalidEncoding(
                "invalid page_kind (expected 0..=3)",
            ));
        }
    };
    let mut data = Vec::with_capacity(OPEN_PAGE_WIRE_LEN);
    data.push(TAG_OPEN_PAGE);
    data.push(page_kind);
    data.extend_from_slice(&pool_id.to_le_bytes());
    data.push(lane_id);
    data.extend_from_slice(&page_seq.to_le_bytes());
    data.extend_from_slice(&max_payer_deficit.to_le_bytes());
    Ok(AudrenInstruction {
        program_id: program_id.to_bytes(),
        accounts: vec![
            AudrenAccountMeta::writable(payer, true),
            AudrenAccountMeta::readonly(derive_pool_pda(&program_id, pool_id).0, false),
            AudrenAccountMeta::readonly(derive_lane_pda(&program_id, pool_id, lane_id).0, false),
            AudrenAccountMeta::writable(
                derive_lane_rent_pda(&program_id, pool_id, lane_id).0,
                false,
            ),
            AudrenAccountMeta::writable(page_pda, false),
            AudrenAccountMeta::readonly(sys_id(), false),
        ],
        data,
    })
}

pub fn build_open_page(
    program_id: Address,
    payer: Address,
    page_kind: u8,
    pool_id: u32,
    lane_id: u8,
    page_seq: u64,
    max_payer_deficit: u64,
) -> AudrenInstruction {
    try_build_open_page(
        program_id,
        payer,
        page_kind,
        pool_id,
        lane_id,
        page_seq,
        max_payer_deficit,
    )
    .expect("valid OpenPage parameters")
}

/// Fallible unified `Deposit` (`TAG_DEPOSIT = 0x03`, `185 B`, 14 fixed accounts + optional rollovers/hooks).
#[allow(clippy::too_many_arguments)]
pub fn try_build_deposit(
    program_id: Address,
    depositor: Address,
    pool_id: u32,
    mint: Address,
    source_account: Address,
    vault_ata: Address,
    token_prog: Address,
    lane_id: u8,
    sub_page_seq: u64,
    root_page_seq: u64,
    memo_page_seq: u64,
    next_sub_seq: Option<u64>,
    next_memo_seq: Option<u64>,
    native_sol: bool,
    fee_from_amount: bool,
    amount: u64,
    stealth_owner: Fr,
    blinding: Fr,
    memo_106: &[u8; MEMO_ENTRY_WIRE_LEN],
    transfer_hook_accounts: &[AudrenAccountMeta],
) -> Result<AudrenInstruction, ClientError> {
    if (lane_id as usize) >= NUM_LANES {
        return Err(ClientError::InvalidEncoding("lane_id out of range"));
    }
    if fee_from_amount && !native_sol {
        return Err(ClientError::InvalidEncoding(
            "fee_from_amount is only valid when native_sol is true",
        ));
    }
    if native_sol {
        if mint != Address::new_from_array(WSOL_MINT) {
            return Err(ClientError::InvalidEncoding(
                "native_sol deposit requires WSOL_MINT",
            ));
        }
        if token_prog != Address::new_from_array(CLASSIC_TOKEN_PROGRAM_ID) {
            return Err(ClientError::InvalidEncoding(
                "native_sol deposit requires CLASSIC_TOKEN_PROGRAM_ID",
            ));
        }
        if source_account != depositor {
            return Err(ClientError::InvalidEncoding(
                "native_sol deposit requires source_account == depositor",
            ));
        }
    }
    let flags = u8::from(next_sub_seq.is_some())
        | (u8::from(next_memo_seq.is_some()) << 1)
        | if fee_from_amount {
            DEPOSIT_FLAG_FEE_FROM_AMOUNT
        } else {
            0
        }
        | if native_sol {
            DEPOSIT_FLAG_NATIVE_SOL
        } else {
            0
        };
    let mut data = Vec::with_capacity(185);
    data.push(TAG_DEPOSIT);
    data.extend_from_slice(&pool_id.to_le_bytes());
    data.push(lane_id);
    data.push(flags);
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&fr_to_be_bytes(&stealth_owner));
    data.extend_from_slice(&fr_to_be_bytes(&blinding));
    data.extend_from_slice(memo_106);

    let mut accounts = vec![
        AudrenAccountMeta::writable(depositor, true),
        AudrenAccountMeta::readonly(derive_pool_pda(&program_id, pool_id).0, false),
        AudrenAccountMeta::writable(derive_roots_pda(&program_id, pool_id).0, false),
        AudrenAccountMeta::readonly(derive_vault_auth_pda(&program_id, pool_id).0, false),
        AudrenAccountMeta::readonly(mint, false),
        AudrenAccountMeta::writable(source_account, source_account == depositor),
        AudrenAccountMeta::writable(vault_ata, false),
        AudrenAccountMeta::readonly(token_prog, false),
        AudrenAccountMeta::writable(derive_lane_pda(&program_id, pool_id, lane_id).0, false),
        AudrenAccountMeta::writable(
            derive_lane_rent_pda(&program_id, pool_id, lane_id).0,
            false,
        ),
        AudrenAccountMeta::writable(
            derive_subtree_pda(&program_id, pool_id, lane_id, sub_page_seq).0,
            false,
        ),
        AudrenAccountMeta::writable(
            derive_subroot_pda(&program_id, pool_id, lane_id, root_page_seq).0,
            false,
        ),
        AudrenAccountMeta::writable(
            derive_memo_pda(&program_id, pool_id, lane_id, memo_page_seq).0,
            false,
        ),
        AudrenAccountMeta::readonly(sys_id(), false),
    ];
    if let Some(ns) = next_sub_seq {
        accounts.push(AudrenAccountMeta::writable(
            derive_subtree_pda(&program_id, pool_id, lane_id, ns).0,
            false,
        ));
    }
    if let Some(nm) = next_memo_seq {
        accounts.push(AudrenAccountMeta::writable(
            derive_memo_pda(&program_id, pool_id, lane_id, nm).0,
            false,
        ));
    }
    accounts.extend_from_slice(transfer_hook_accounts);
    Ok(AudrenInstruction {
        program_id: program_id.to_bytes(),
        accounts,
        data,
    })
}

/// Unified `Deposit` (`TAG_DEPOSIT = 0x03`, `185 B`, 14 fixed accounts + optional rollovers/hooks).
///
/// - When `native_sol == true`: sets `DEPOSIT_FLAG_NATIVE_SOL`; `mint` must be `WSOL_MINT`,
///   `token_prog` must be `CLASSIC_TOKEN_PROGRAM_ID`, `source_account` must equal `depositor`,
///   and `vault_ata` must be the canonical WSOL ATA owned by `vault_auth(pool_id)`.
/// - When `native_sol == false`: transfers SPL / Token-2022 tokens from `source_account`
///   (`depositor_ata`) into the canonical `vault_ata` owned by `vault_auth(pool_id)` (and
///   `fee_from_amount` must be `false`).
#[allow(clippy::too_many_arguments)]
pub fn build_deposit(
    program_id: Address,
    depositor: Address,
    pool_id: u32,
    mint: Address,
    source_account: Address,
    vault_ata: Address,
    token_prog: Address,
    lane_id: u8,
    sub_page_seq: u64,
    root_page_seq: u64,
    memo_page_seq: u64,
    next_sub_seq: Option<u64>,
    next_memo_seq: Option<u64>,
    native_sol: bool,
    fee_from_amount: bool,
    amount: u64,
    stealth_owner: Fr,
    blinding: Fr,
    memo_106: &[u8; MEMO_ENTRY_WIRE_LEN],
    transfer_hook_accounts: &[AudrenAccountMeta],
) -> AudrenInstruction {
    try_build_deposit(
        program_id,
        depositor,
        pool_id,
        mint,
        source_account,
        vault_ata,
        token_prog,
        lane_id,
        sub_page_seq,
        root_page_seq,
        memo_page_seq,
        next_sub_seq,
        next_memo_seq,
        native_sol,
        fee_from_amount,
        amount,
        stealth_owner,
        blinding,
        memo_106,
        transfer_hook_accounts,
    )
    .expect("valid Deposit parameters")
}

/// Fallible authority-gated one-shot `InitRootHistory` (`TAG_INIT_ROOT_HISTORY = 0x04`, `13 B`,
/// `4 + active_lanes` accounts).
pub fn try_build_init_root_history(
    program_id: Address,
    authority: Address,
    pool_id: u32,
    root_epoch_interval: u64,
    active_lanes: u8,
) -> Result<AudrenInstruction, ClientError> {
    if !(1..=MAX_ROOT_EPOCH_INTERVAL).contains(&root_epoch_interval) {
        return Err(ClientError::InvalidEncoding(
            "root_epoch_interval must be in 1..=MAX_ROOT_EPOCH_INTERVAL",
        ));
    }
    if (active_lanes as usize) > NUM_LANES {
        return Err(ClientError::InvalidEncoding("active_lanes out of range"));
    }
    let mut data = Vec::with_capacity(13);
    data.push(TAG_INIT_ROOT_HISTORY);
    data.extend_from_slice(&pool_id.to_le_bytes());
    data.extend_from_slice(&root_epoch_interval.to_le_bytes());
    let mut accounts = Vec::with_capacity(4 + active_lanes as usize);
    accounts.push(AudrenAccountMeta::writable(authority, true));
    accounts.push(AudrenAccountMeta::writable(
        derive_pool_pda(&program_id, pool_id).0,
        false,
    ));
    accounts.push(AudrenAccountMeta::writable(
        derive_roots_pda(&program_id, pool_id).0,
        false,
    ));
    accounts.push(AudrenAccountMeta::readonly(sys_id(), false));
    for l in 0..active_lanes {
        accounts.push(AudrenAccountMeta::readonly(
            derive_lane_pda(&program_id, pool_id, l).0,
            false,
        ));
    }
    Ok(AudrenInstruction {
        program_id: program_id.to_bytes(),
        accounts,
        data,
    })
}

pub fn build_init_root_history(
    program_id: Address,
    authority: Address,
    pool_id: u32,
    root_epoch_interval: u64,
    active_lanes: u8,
) -> AudrenInstruction {
    try_build_init_root_history(
        program_id,
        authority,
        pool_id,
        root_epoch_interval,
        active_lanes,
    )
    .expect("valid InitRootHistory parameters")
}

#[allow(clippy::too_many_arguments)]
pub fn try_build_transact(
    program_id: Address,
    payer: Address,
    pool_id: u32,
    vk_id: u8,
    root_ring_kind: u8,
    root_ring_idx: u8,
    out_lane_id: u8,
    out_sub_seq: u64,
    out_root_seq: u64,
    out_memo_seq: u64,
    out_nf_seq: u64,
    output_mask: u8,
    asset_mode: u8,
    unwrap_wsol: bool,
    public_withdraw_accs: Option<(Address, Address, Address)>, // (mint, vault_ata, token_prog)
    rollover: (Option<u64>, Option<u64>, Option<u64>),
    proof_192: &[u8; GROTH16_PROOF_LEN],
    nf0: &[u8; 32],
    nf1: &[u8; 32],
    cm0: &[u8; 32],
    cm1: &[u8; 32],
    cm2: &[u8; 32],
    public_amount_out: u64,
    relayer_fee_amount: u64,
    recipient: Address,
    relayer_fee_recipient: Address,
    memos_bytes: &[u8],
    transfer_hook_accounts: &[AudrenAccountMeta],
) -> Result<AudrenInstruction, ClientError> {
    validate_root_ring(root_ring_kind, root_ring_idx)?;
    if (out_lane_id as usize) >= NUM_LANES {
        return Err(ClientError::InvalidEncoding("out_lane_id out of range"));
    }
    if output_mask > 0b111 {
        return Err(ClientError::InvalidEncoding("output_mask must be 0..=7"));
    }
    if asset_mode != ASSET_MODE_PRIVATE && asset_mode != ASSET_MODE_PUBLIC {
        return Err(ClientError::InvalidEncoding(
            "asset_mode must be 0 (PRIVATE) or 1 (PUBLIC)",
        ));
    }
    if unwrap_wsol && asset_mode != ASSET_MODE_PUBLIC {
        return Err(ClientError::InvalidEncoding(
            "unwrap_wsol requires ASSET_MODE_PUBLIC",
        ));
    }
    let flags = u8::from(rollover.0.is_some())
        | (u8::from(rollover.1.is_some()) << 1)
        | (u8::from(rollover.2.is_some()) << 2)
        | if unwrap_wsol {
            WITHDRAW_FLAG_UNWRAP_WSOL
        } else {
            0
        };
    let mut data = Vec::with_capacity(380 + memos_bytes.len());
    data.push(TAG_TRANSACT);
    data.extend_from_slice(&pool_id.to_le_bytes());
    data.push(vk_id);
    data.push(out_lane_id);
    data.push(output_mask);
    data.push(asset_mode);
    data.push(flags);
    data.push(root_ring_kind);
    data.push(root_ring_idx);
    data.extend_from_slice(proof_192);
    data.extend_from_slice(nf0);
    data.extend_from_slice(nf1);
    data.extend_from_slice(cm0);
    data.extend_from_slice(cm1);
    data.extend_from_slice(cm2);
    data.extend_from_slice(&public_amount_out.to_le_bytes());
    data.extend_from_slice(&relayer_fee_amount.to_le_bytes());
    data.extend_from_slice(memos_bytes);

    let nf1_meta = if *nf1 == [0u8; 32] {
        AudrenAccountMeta::readonly(sys_id(), false)
    } else {
        AudrenAccountMeta::writable(derive_nullifier_pda(&program_id, pool_id, nf1).0, false)
    };
    let roots_addr = derive_roots_pda(&program_id, pool_id).0;
    let roots_meta = if output_mask == 0 {
        AudrenAccountMeta::readonly(roots_addr, false)
    } else {
        AudrenAccountMeta::writable(roots_addr, false)
    };

    let mut accounts = vec![
        AudrenAccountMeta::writable(payer, true),
        AudrenAccountMeta::readonly(derive_pool_pda(&program_id, pool_id).0, false),
        roots_meta,
        AudrenAccountMeta::writable(derive_nullifier_pda(&program_id, pool_id, nf0).0, false),
        nf1_meta,
        AudrenAccountMeta::writable(derive_lane_pda(&program_id, pool_id, out_lane_id).0, false),
        AudrenAccountMeta::writable(
            derive_lane_rent_pda(&program_id, pool_id, out_lane_id).0,
            false,
        ),
        AudrenAccountMeta::writable(
            derive_subtree_pda(&program_id, pool_id, out_lane_id, out_sub_seq).0,
            false,
        ),
        AudrenAccountMeta::writable(
            derive_subroot_pda(&program_id, pool_id, out_lane_id, out_root_seq).0,
            false,
        ),
        AudrenAccountMeta::writable(
            derive_memo_pda(&program_id, pool_id, out_lane_id, out_memo_seq).0,
            false,
        ),
        AudrenAccountMeta::writable(
            derive_nf_page_pda(&program_id, pool_id, out_lane_id, out_nf_seq).0,
            false,
        ),
        AudrenAccountMeta::readonly(sys_id(), false),
    ];

    if asset_mode == ASSET_MODE_PUBLIC {
        let (mint, vault_ata, token_prog) = public_withdraw_accs.ok_or(
            ClientError::InvalidEncoding("public_withdraw_accs required for ASSET_MODE_PUBLIC"),
        )?;
        accounts.push(AudrenAccountMeta::readonly(
            derive_vault_auth_pda(&program_id, pool_id).0,
            false,
        ));
        accounts.push(AudrenAccountMeta::readonly(mint, false));
        accounts.push(AudrenAccountMeta::writable(vault_ata, false));
        accounts.push(AudrenAccountMeta::readonly(token_prog, false));
        accounts.push(AudrenAccountMeta::writable(recipient, false));
        accounts.push(if relayer_fee_amount > 0 {
            AudrenAccountMeta::writable(relayer_fee_recipient, false)
        } else {
            AudrenAccountMeta::readonly(relayer_fee_recipient, false)
        });
        if unwrap_wsol {
            accounts.push(AudrenAccountMeta::writable(
                derive_unwrap_pda(&program_id, pool_id, nf0).0,
                false,
            ));
        }
    }

    if let Some(ns) = rollover.0 {
        accounts.push(AudrenAccountMeta::writable(
            derive_subtree_pda(&program_id, pool_id, out_lane_id, ns).0,
            false,
        ));
    }
    if let Some(nm) = rollover.1 {
        accounts.push(AudrenAccountMeta::writable(
            derive_memo_pda(&program_id, pool_id, out_lane_id, nm).0,
            false,
        ));
    }
    if let Some(nn) = rollover.2 {
        accounts.push(AudrenAccountMeta::writable(
            derive_nf_page_pda(&program_id, pool_id, out_lane_id, nn).0,
            false,
        ));
    }
    accounts.extend_from_slice(transfer_hook_accounts);

    Ok(AudrenInstruction {
        program_id: program_id.to_bytes(),
        accounts,
        data,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_transact(
    program_id: Address,
    payer: Address,
    pool_id: u32,
    vk_id: u8,
    root_ring_kind: u8,
    root_ring_idx: u8,
    out_lane_id: u8,
    out_sub_seq: u64,
    out_root_seq: u64,
    out_memo_seq: u64,
    out_nf_seq: u64,
    output_mask: u8,
    asset_mode: u8,
    unwrap_wsol: bool,
    public_withdraw_accs: Option<(Address, Address, Address)>, // (mint, vault_ata, token_prog)
    rollover: (Option<u64>, Option<u64>, Option<u64>),
    proof_192: &[u8; GROTH16_PROOF_LEN],
    nf0: &[u8; 32],
    nf1: &[u8; 32],
    cm0: &[u8; 32],
    cm1: &[u8; 32],
    cm2: &[u8; 32],
    public_amount_out: u64,
    relayer_fee_amount: u64,
    recipient: Address,
    relayer_fee_recipient: Address,
    memos_bytes: &[u8],
    transfer_hook_accounts: &[AudrenAccountMeta],
) -> AudrenInstruction {
    try_build_transact(
        program_id,
        payer,
        pool_id,
        vk_id,
        root_ring_kind,
        root_ring_idx,
        out_lane_id,
        out_sub_seq,
        out_root_seq,
        out_memo_seq,
        out_nf_seq,
        output_mask,
        asset_mode,
        unwrap_wsol,
        public_withdraw_accs,
        rollover,
        proof_192,
        nf0,
        nf1,
        cm0,
        cm1,
        cm2,
        public_amount_out,
        relayer_fee_amount,
        recipient,
        relayer_fee_recipient,
        memos_bytes,
        transfer_hook_accounts,
    )
    .expect("valid Transact parameters")
}

#[allow(clippy::too_many_arguments)]
pub fn try_build_exec_via_escrow(
    program_id: Address,
    payer: Address,
    pool_id: u32,
    vk_id: u8,
    root_ring_kind: u8,
    root_ring_idx: u8,
    out_lane_id: u8,
    out_sub_seq: u64,
    out_root_seq: u64,
    out_memo_seq: u64,
    out_nf_seq: u64,
    escrow_shard: u8,
    change_mask: u8,
    fee_on_output: bool,
    in_leg: (Address, Address, Address, Address), // (mint, vault_ata, escrow_ata, token_prog)
    out_leg: (Address, Address, Address, Address), // (mint, vault_ata, escrow_ata, token_prog)
    relayer_fee_amount: u64,
    relayer_fee_recipient: Option<Address>,
    rollover: (Option<u64>, Option<u64>, Option<u64>),
    proof_192: &[u8; GROTH16_PROOF_LEN],
    nf0: &[u8; 32],
    nf1: &[u8; 32],
    cm0: &[u8; 32],
    cm1: &[u8; 32],
    cm2: &[u8; 32],
    amount_in: u64,
    min_amount_out: u64,
    out_stealth_owner: &[u8; 32],
    out_blinding: &[u8; 32],
    dyn_memo_head: &[u8; DYN_MEMO_HEAD_LEN],
    dyn_mask_72: &[u8; MEMO_CT_LEN],
    router_prog: Address,
    router_ix_data: &[u8],
    router_accounts: Vec<AudrenAccountMeta>,
    extra_writable_pubkeys: &[Address],
    change_memos: &[u8],
) -> Result<AudrenInstruction, ClientError> {
    validate_root_ring(root_ring_kind, root_ring_idx)?;
    if (out_lane_id as usize) >= NUM_LANES {
        return Err(ClientError::InvalidEncoding("out_lane_id out of range"));
    }
    if (escrow_shard as usize) >= NUM_ESCROW_SHARDS {
        return Err(ClientError::InvalidEncoding("escrow_shard out of range"));
    }
    if change_mask > 0b11 {
        return Err(ClientError::InvalidEncoding("change_mask must be 0..=3"));
    }
    if u16::try_from(router_accounts.len()).is_err() {
        return Err(ClientError::InvalidEncoding(
            "router_accounts length exceeds u16::MAX",
        ));
    }
    let router_ix_len = u16::try_from(router_ix_data.len()).map_err(|_| {
        ClientError::InvalidEncoding("router_ix_data length exceeds u16::MAX")
    })?;
    let fee_recipient = if relayer_fee_amount > 0 {
        Some(relayer_fee_recipient.ok_or(ClientError::InvalidEncoding(
            "relayer_fee_recipient required when relayer_fee_amount > 0",
        ))?)
    } else {
        None
    };

    let flags = u8::from(rollover.0.is_some())
        | (u8::from(rollover.1.is_some()) << 1)
        | (u8::from(rollover.2.is_some()) << 2)
        | if fee_on_output {
            EXEC_FLAG_FEE_ON_OUTPUT
        } else {
            0
        };
    let mut data = Vec::with_capacity(560 + router_ix_data.len() + change_memos.len());
    data.push(TAG_EXEC_VIA_ESCROW);
    data.extend_from_slice(&pool_id.to_le_bytes());
    data.push(vk_id);
    data.push(out_lane_id);
    data.push(escrow_shard);
    data.push(change_mask);
    data.push(flags);
    data.push(root_ring_kind);
    data.push(root_ring_idx);
    data.extend_from_slice(proof_192);
    data.extend_from_slice(nf0);
    data.extend_from_slice(nf1);
    data.extend_from_slice(cm0);
    data.extend_from_slice(cm1);
    data.extend_from_slice(cm2);
    data.extend_from_slice(&amount_in.to_le_bytes());
    data.extend_from_slice(&min_amount_out.to_le_bytes());
    data.extend_from_slice(&relayer_fee_amount.to_le_bytes());
    data.extend_from_slice(out_stealth_owner);
    data.extend_from_slice(out_blinding);
    data.extend_from_slice(dyn_memo_head);
    data.extend_from_slice(dyn_mask_72);
    data.extend_from_slice(&router_ix_len.to_le_bytes());
    data.extend_from_slice(router_ix_data);
    data.extend_from_slice(change_memos);

    let nf1_meta = if *nf1 == [0u8; 32] {
        AudrenAccountMeta::readonly(sys_id(), false)
    } else {
        AudrenAccountMeta::writable(derive_nullifier_pda(&program_id, pool_id, nf1).0, false)
    };

    let (escrow_pda, _) = derive_escrow_pda(&program_id, pool_id, escrow_shard);
    let (vault_auth, _) = derive_vault_auth_pda(&program_id, pool_id);
    let mut accounts = vec![
        AudrenAccountMeta::writable(payer, true),
        AudrenAccountMeta::readonly(derive_pool_pda(&program_id, pool_id).0, false),
        AudrenAccountMeta::writable(derive_roots_pda(&program_id, pool_id).0, false),
        AudrenAccountMeta::writable(derive_nullifier_pda(&program_id, pool_id, nf0).0, false),
        nf1_meta,
        AudrenAccountMeta::writable(derive_lane_pda(&program_id, pool_id, out_lane_id).0, false),
        AudrenAccountMeta::writable(
            derive_lane_rent_pda(&program_id, pool_id, out_lane_id).0,
            false,
        ),
        AudrenAccountMeta::writable(
            derive_subtree_pda(&program_id, pool_id, out_lane_id, out_sub_seq).0,
            false,
        ),
        AudrenAccountMeta::writable(
            derive_subroot_pda(&program_id, pool_id, out_lane_id, out_root_seq).0,
            false,
        ),
        AudrenAccountMeta::writable(
            derive_memo_pda(&program_id, pool_id, out_lane_id, out_memo_seq).0,
            false,
        ),
        AudrenAccountMeta::writable(
            derive_nf_page_pda(&program_id, pool_id, out_lane_id, out_nf_seq).0,
            false,
        ),
        AudrenAccountMeta::writable(escrow_pda, false),
        AudrenAccountMeta::readonly(router_prog, false),
        AudrenAccountMeta::readonly(sys_id(), false),
    ];

    let (m_in, v_in, e_in, tp_in) = in_leg;
    accounts.push(AudrenAccountMeta::readonly(vault_auth, false));
    accounts.push(AudrenAccountMeta::readonly(m_in, false));
    accounts.push(AudrenAccountMeta::writable(v_in, false));
    accounts.push(AudrenAccountMeta::writable(e_in, false));
    accounts.push(AudrenAccountMeta::readonly(tp_in, false));
    if !fee_on_output {
        if let Some(fee_r) = fee_recipient {
            accounts.push(AudrenAccountMeta::writable(fee_r, false));
        }
    }

    let (m_out, v_out, e_out, tp_out) = out_leg;
    accounts.push(AudrenAccountMeta::readonly(vault_auth, false));
    accounts.push(AudrenAccountMeta::readonly(m_out, false));
    accounts.push(AudrenAccountMeta::writable(v_out, false));
    accounts.push(AudrenAccountMeta::writable(e_out, false));
    accounts.push(AudrenAccountMeta::readonly(tp_out, false));
    if fee_on_output {
        if let Some(fee_r) = fee_recipient {
            accounts.push(AudrenAccountMeta::writable(fee_r, false));
        }
    }

    if let Some(ns) = rollover.0 {
        accounts.push(AudrenAccountMeta::writable(
            derive_subtree_pda(&program_id, pool_id, out_lane_id, ns).0,
            false,
        ));
    }
    if let Some(nm) = rollover.1 {
        accounts.push(AudrenAccountMeta::writable(
            derive_memo_pda(&program_id, pool_id, out_lane_id, nm).0,
            false,
        ));
    }
    if let Some(nn) = rollover.2 {
        accounts.push(AudrenAccountMeta::writable(
            derive_nf_page_pda(&program_id, pool_id, out_lane_id, nn).0,
            false,
        ));
    }

    let mut all_extra_writable: Vec<Address> = accounts
        .iter()
        .filter(|a| a.is_writable)
        .map(|a| Address::new_from_array(a.pubkey))
        .collect();
    all_extra_writable.extend_from_slice(extra_writable_pubkeys);
    let normalized_router_accs =
        prepare_escrow_accounts_for_audren(&router_accounts, &escrow_pda, &all_extra_writable);
    accounts.extend(normalized_router_accs);
    Ok(AudrenInstruction {
        program_id: program_id.to_bytes(),
        accounts,
        data,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_exec_via_escrow(
    program_id: Address,
    payer: Address,
    pool_id: u32,
    vk_id: u8,
    root_ring_kind: u8,
    root_ring_idx: u8,
    out_lane_id: u8,
    out_sub_seq: u64,
    out_root_seq: u64,
    out_memo_seq: u64,
    out_nf_seq: u64,
    escrow_shard: u8,
    change_mask: u8,
    fee_on_output: bool,
    in_leg: (Address, Address, Address, Address), // (mint, vault_ata, escrow_ata, token_prog)
    out_leg: (Address, Address, Address, Address), // (mint, vault_ata, escrow_ata, token_prog)
    relayer_fee_amount: u64,
    relayer_fee_recipient: Option<Address>,
    rollover: (Option<u64>, Option<u64>, Option<u64>),
    proof_192: &[u8; GROTH16_PROOF_LEN],
    nf0: &[u8; 32],
    nf1: &[u8; 32],
    cm0: &[u8; 32],
    cm1: &[u8; 32],
    cm2: &[u8; 32],
    amount_in: u64,
    min_amount_out: u64,
    out_stealth_owner: &[u8; 32],
    out_blinding: &[u8; 32],
    dyn_memo_head: &[u8; DYN_MEMO_HEAD_LEN],
    dyn_mask_72: &[u8; MEMO_CT_LEN],
    router_prog: Address,
    router_ix_data: &[u8],
    router_accounts: Vec<AudrenAccountMeta>,
    extra_writable_pubkeys: &[Address],
    change_memos: &[u8],
) -> AudrenInstruction {
    try_build_exec_via_escrow(
        program_id,
        payer,
        pool_id,
        vk_id,
        root_ring_kind,
        root_ring_idx,
        out_lane_id,
        out_sub_seq,
        out_root_seq,
        out_memo_seq,
        out_nf_seq,
        escrow_shard,
        change_mask,
        fee_on_output,
        in_leg,
        out_leg,
        relayer_fee_amount,
        relayer_fee_recipient,
        rollover,
        proof_192,
        nf0,
        nf1,
        cm0,
        cm1,
        cm2,
        amount_in,
        min_amount_out,
        out_stealth_owner,
        out_blinding,
        dyn_memo_head,
        dyn_mask_72,
        router_prog,
        router_ix_data,
        router_accounts,
        extra_writable_pubkeys,
        change_memos,
    )
    .expect("valid ExecViaEscrow parameters")
}

pub fn build_set_paused(
    program_id: Address,
    authority: Address,
    pool_id: u32,
    paused: bool,
) -> AudrenInstruction {
    let mut data = Vec::with_capacity(6);
    data.push(TAG_SET_PAUSED);
    data.extend_from_slice(&pool_id.to_le_bytes());
    data.push(u8::from(paused));
    AudrenInstruction {
        program_id: program_id.to_bytes(),
        accounts: vec![
            AudrenAccountMeta::readonly(authority, true),
            AudrenAccountMeta::writable(derive_pool_pda(&program_id, pool_id).0, false),
        ],
        data,
    }
}

pub fn build_update_pool_params(
    program_id: Address,
    authority: Address,
    pool_id: u32,
    note_rent_fee: u64,
    nf_rent_fee: u64,
) -> AudrenInstruction {
    build_update_pool(
        program_id,
        authority,
        pool_id,
        UpdatePoolAction::UpdateParams {
            note_rent_fee,
            nf_rent_fee,
        },
    )
}

pub fn build_update_pool(
    program_id: Address,
    signer: Address,
    pool_id: u32,
    action: UpdatePoolAction,
) -> AudrenInstruction {
    let mut data = Vec::with_capacity(38);
    data.push(TAG_UPDATE_POOL);
    data.extend_from_slice(&pool_id.to_le_bytes());
    match action {
        UpdatePoolAction::UpdateParams {
            note_rent_fee,
            nf_rent_fee,
        } => {
            data.push(UPDATE_POOL_PARAMS);
            data.extend_from_slice(&note_rent_fee.to_le_bytes());
            data.extend_from_slice(&nf_rent_fee.to_le_bytes());
        }
        UpdatePoolAction::ProposeAuthority { pending_authority } => {
            data.push(UPDATE_POOL_PROPOSE_AUTHORITY);
            data.extend_from_slice(pending_authority.as_ref());
        }
        UpdatePoolAction::AcceptAuthority => {
            data.push(UPDATE_POOL_ACCEPT_AUTHORITY);
        }
        UpdatePoolAction::RenounceAuthority => {
            data.push(UPDATE_POOL_RENOUNCE_AUTHORITY);
        }
    }
    AudrenInstruction {
        program_id: program_id.to_bytes(),
        accounts: vec![
            AudrenAccountMeta::readonly(signer, true),
            AudrenAccountMeta::writable(derive_pool_pda(&program_id, pool_id).0, false),
        ],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_page_rollovers_exact_boundaries() {
        assert_eq!(
            compute_page_rollovers(93, 3, 0, 2),
            PageRolloverPlan {
                out_sub_seq: 0,
                out_root_seq: 0,
                out_memo_seq: 0,
                nf_page_seq: 0,
                next_sub_seq: None,
                next_root_seq: None,
                next_memo_seq: None,
                next_nf_seq: None,
            }
        );
        assert_eq!(compute_page_rollovers(94, 3, 0, 2).next_memo_seq, Some(1));
        assert_eq!(compute_page_rollovers(95, 2, 0, 1).next_memo_seq, Some(1));
        assert_eq!(compute_page_rollovers(96, 3, 0, 2).out_memo_seq, 1);
        assert_eq!(compute_page_rollovers(96, 3, 0, 2).next_memo_seq, None);

        assert_eq!(compute_page_rollovers(254, 2, 0, 1).next_sub_seq, None);
        assert_eq!(compute_page_rollovers(254, 3, 0, 2).next_sub_seq, Some(1));
        assert_eq!(compute_page_rollovers(255, 2, 0, 2).next_sub_seq, Some(1));
        assert_eq!(compute_page_rollovers(256, 3, 0, 2).out_sub_seq, 1);
        assert_eq!(compute_page_rollovers(256, 3, 0, 2).next_sub_seq, None);

        assert_eq!(compute_page_rollovers(0, 0, 598, 2).next_nf_seq, None);
        assert_eq!(compute_page_rollovers(0, 0, 599, 2).next_nf_seq, Some(1));
        assert_eq!(compute_page_rollovers(0, 0, 599, 1).next_nf_seq, None);
        assert_eq!(compute_page_rollovers(0, 0, 600, 2).nf_page_seq, 1);
        assert_eq!(compute_page_rollovers(0, 0, 600, 2).next_nf_seq, None);

        let sr_cross = compute_page_rollovers(76_799, 2, 0, 1);
        assert_eq!(sr_cross.out_root_seq, 0);
        assert_eq!(sr_cross.next_sub_seq, Some(300));
        assert_eq!(sr_cross.next_root_seq, Some(1));
    }

    #[test]
    fn fallible_builders_reject_invalid_inputs_and_exec_extra_writable_promotes_router_accounts() {
        let pid = Address::new_from_array(audren_core::AUDREN_PROGRAM_ID);
        let payer = Address::new_from_array([0x11u8; 32]);
        let rprog = Address::new_from_array([0x22u8; 32]);
        let sibling_writable = Address::new_from_array([0x33u8; 32]);
        let leg_acc = Address::new_from_array([0x44u8; 32]);

        // try_build_open_page rejects page_kind > 3 and lane_id >= 16, and encodes 23 B with max_payer_deficit
        assert!(try_build_open_page(pid, payer, 4, 0, 0, 0, u64::MAX).is_err());
        assert!(try_build_open_page(pid, payer, 0, 0, 16, 0, u64::MAX).is_err());
        let op_zero = try_build_open_page(pid, payer, OPEN_PAGE_KIND_MEMO, 0, 0, 1, 0).unwrap();
        assert_eq!(op_zero.data.len(), OPEN_PAGE_WIRE_LEN);
        assert_eq!(&op_zero.data[15..23], &0u64.to_le_bytes());

        // try_build_init_pool / try_build_init_lane / try_build_init_root_history / try_build_deposit bounds
        assert!(try_build_init_pool(pid, payer, 0, 0, 0, 0).is_err());
        assert!(try_build_init_pool(pid, payer, 0, MAX_ROOT_EPOCH_INTERVAL + 1, 0, 0).is_err());
        let init_pool_ix = try_build_init_pool(pid, payer, 0, 32, 1_500_000, 500_000).unwrap();
        assert_eq!(init_pool_ix.accounts.len(), 4);
        assert_eq!(init_pool_ix.data.len(), 29);

        assert!(try_build_init_lane(pid, payer, 0, 16).is_err());
        assert!(try_build_init_root_history(pid, payer, 0, 0, 4).is_err());
        assert!(try_build_init_root_history(pid, payer, 0, MAX_ROOT_EPOCH_INTERVAL + 1, 4).is_err());
        assert!(try_build_init_root_history(pid, payer, 0, 32, 17).is_err());
        let init_rh_ix = try_build_init_root_history(pid, payer, 0, 32, 4).unwrap();
        assert_eq!(init_rh_ix.accounts.len(), 8);
        assert_eq!(init_rh_ix.data.len(), 13);
        assert_eq!(init_rh_ix.data[0], TAG_INIT_ROOT_HISTORY);

        let up_ix = build_update_pool_params(pid, payer, 0, 1_500_000, 500_000);
        assert_eq!(up_ix.data.len(), 22);

        assert!(try_build_deposit(
            pid,
            payer,
            0,
            leg_acc,
            leg_acc,
            leg_acc,
            leg_acc,
            0,
            0,
            0,
            0,
            None,
            None,
            false,
            true, // fee_from_amount invalid when !native_sol
            1,
            Fr::from(1u64),
            Fr::from(2u64),
            &[0u8; MEMO_ENTRY_WIRE_LEN],
            &[],
        )
        .is_err());

        // validate_root_ring bounds
        assert!(validate_root_ring(ROOT_RING_SLOT, (SLOT_RING_LEN - 1) as u8).is_ok());
        assert!(validate_root_ring(ROOT_RING_SLOT, SLOT_RING_LEN as u8).is_err());
        assert!(validate_root_ring(ROOT_RING_EPOCH, (EPOCH_RING_LEN - 1) as u8).is_ok());
        assert!(validate_root_ring(ROOT_RING_EPOCH, EPOCH_RING_LEN as u8).is_err());
        assert!(validate_root_ring(2, 0).is_err());

        // try_compute_transact_ctx_hash rejects missing recipient/fee_recipient & invalid modes
        assert!(try_compute_transact_ctx_hash(
            &pid, 0, 0, 0, 0, 1, false, None, None, &[0u8; 32], 1, 0, &[]
        )
        .is_err());
        assert!(try_compute_transact_ctx_hash(
            &pid, 0, 0, 0, 0, 1, false, Some(&payer), None, &[0u8; 32], 1, 1, &[]
        )
        .is_err());
        assert!(try_compute_transact_ctx_hash(
            &pid, 0, 0, 0, 0, 2, false, None, None, &[0u8; 32], 0, 0, &[]
        )
        .is_err());
        assert!(try_compute_transact_ctx_hash(
            &pid, 0, 0, 0, 8, 0, false, None, None, &[0u8; 32], 0, 0, &[]
        )
        .is_err());
        assert!(try_compute_transact_ctx_hash(
            &pid, 0, 0, 0, 0, 0, true, None, None, &[0u8; 32], 0, 0, &[]
        )
        .is_err());

        // try_build_transact rejects ASSET_MODE_PUBLIC with None public_withdraw_accs and verifies roots writability
        assert!(try_build_transact(
            pid,
            payer,
            0,
            0,
            ROOT_RING_EPOCH,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            ASSET_MODE_PUBLIC,
            false,
            None,
            (None, None, None),
            &[0u8; GROTH16_PROOF_LEN],
            &[1u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            1,
            0,
            payer,
            payer,
            &[],
            &[],
        )
        .is_err());

        let tx_full_exit = try_build_transact(
            pid,
            payer,
            0,
            0,
            ROOT_RING_EPOCH,
            0,
            0,
            0,
            0,
            0,
            0,
            0, // output_mask == 0 => roots MUST be read-only
            ASSET_MODE_PUBLIC,
            false,
            Some((leg_acc, leg_acc, leg_acc)),
            (None, None, None),
            &[0u8; GROTH16_PROOF_LEN],
            &[1u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            1,
            0,
            payer,
            payer,
            &[],
            &[],
        )
        .unwrap();
        assert!(!tx_full_exit.accounts[2].is_writable, "full exit must mark roots read-only");
        assert_eq!(tx_full_exit.data.len(), 380);
        assert_eq!(tx_full_exit.data[10], ROOT_RING_EPOCH);
        assert_eq!(tx_full_exit.data[11], 0);

        let tx_with_out = try_build_transact(
            pid,
            payer,
            0,
            0,
            ROOT_RING_SLOT,
            7,
            0,
            0,
            0,
            0,
            0,
            1, // output_mask != 0 => roots MUST be writable
            ASSET_MODE_PRIVATE,
            false,
            None,
            (None, None, None),
            &[0u8; GROTH16_PROOF_LEN],
            &[1u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            0,
            0,
            payer,
            payer,
            &[0u8; MEMO_ENTRY_WIRE_LEN],
            &[],
        )
        .unwrap();
        assert!(tx_with_out.accounts[2].is_writable, "output_mask != 0 must mark roots writable");
        assert_eq!(tx_with_out.data[10], ROOT_RING_SLOT);
        assert_eq!(tx_with_out.data[11], 7);

        // try_compute_exec_ctx_hash & try_build_exec_via_escrow promote `extra_writable_pubkeys`
        let router_accs = vec![AudrenAccountMeta::readonly(sibling_writable, false)];
        let h_no_extra = try_compute_exec_ctx_hash(
            &pid, 0, 0, 0, 0, 0, false, &[1u8; 32], 100, 0, None, &[2u8; 32], 50, &rprog,
            &router_accs, &[], &[3u8; 32], &[4u8; 32], &[5u8; DYN_MEMO_HEAD_LEN],
            &[6u8; MEMO_CT_LEN], &[1, 2], &[],
        )
        .unwrap();
        let h_with_extra = try_compute_exec_ctx_hash(
            &pid, 0, 0, 0, 0, 0, false, &[1u8; 32], 100, 0, None, &[2u8; 32], 50, &rprog,
            &router_accs, &[sibling_writable], &[3u8; 32], &[4u8; 32], &[5u8; DYN_MEMO_HEAD_LEN],
            &[6u8; MEMO_CT_LEN], &[1, 2], &[],
        )
        .unwrap();
        let router_accs_already_wr = vec![AudrenAccountMeta::writable(sibling_writable, false)];
        let h_explicit_wr = try_compute_exec_ctx_hash(
            &pid, 0, 0, 0, 0, 0, false, &[1u8; 32], 100, 0, None, &[2u8; 32], 50, &rprog,
            &router_accs_already_wr, &[], &[3u8; 32], &[4u8; 32], &[5u8; DYN_MEMO_HEAD_LEN],
            &[6u8; MEMO_CT_LEN], &[1, 2], &[],
        )
        .unwrap();
        assert_ne!(h_no_extra, h_with_extra);
        assert_eq!(h_with_extra, h_explicit_wr);

        let ix = try_build_exec_via_escrow(
            pid,
            payer,
            0,
            0,
            ROOT_RING_EPOCH,
            3,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            false,
            (leg_acc, leg_acc, leg_acc, leg_acc),
            (leg_acc, leg_acc, leg_acc, leg_acc),
            0,
            None,
            (None, None, None),
            &[0u8; GROTH16_PROOF_LEN],
            &[1u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            100,
            50,
            &[3u8; 32],
            &[4u8; 32],
            &[5u8; DYN_MEMO_HEAD_LEN],
            &[6u8; MEMO_CT_LEN],
            rprog,
            &[1, 2],
            router_accs,
            &[sibling_writable],
            &[],
        )
        .unwrap();
        assert!(ix.accounts[2].is_writable);
        assert_eq!(ix.data.len(), 560 + 2);
        assert_eq!(ix.data[10], ROOT_RING_EPOCH);
        assert_eq!(ix.data[11], 3);
        assert!(
            ix.accounts.last().unwrap().is_writable,
            "extra_writable_pubkeys must promote aliased readonly router account to writable"
        );
    }

    #[test]
    fn auto_open_page_planner_triggers_at_lookahead_and_exact_rollover() {
        let pid = Address::new_from_array(audren_core::AUDREN_PROGRAM_ID);
        let payer = Address::new_from_array([0x11u8; 32]);
        let empty = BTreeSet::new();

        // Fresh lane and mid-page with EMPTY existing_pages MUST return `[]` (TS parity, no page-0 or mid-page spam)
        assert!(plan_auto_open_pages(&pid, 0, 0, 0, 0, 1, 1, &empty)
            .unwrap()
            .is_empty());
        assert!(plan_auto_open_pages(&pid, 0, 0, 10, 10, 1, 1, &empty)
            .unwrap()
            .is_empty());

        // Exact boundary rollovers (`cur_* > 0 && rem == page_size`) emit the new current page even with empty existing_pages
        let memo_boundary = plan_auto_open_pages(&pid, 0, 0, 96, 0, 1, 0, &empty).unwrap();
        assert_eq!(memo_boundary.len(), 1);
        assert_eq!(memo_boundary[0].page_kind, OPEN_PAGE_KIND_MEMO);
        assert_eq!(memo_boundary[0].page_seq, 1);

        let sub_boundary = plan_auto_open_pages(&pid, 0, 0, 256, 0, 1, 0, &empty).unwrap();
        assert_eq!(sub_boundary.len(), 1);
        assert_eq!(sub_boundary[0].page_kind, OPEN_PAGE_KIND_SUBTREE);
        assert_eq!(sub_boundary[0].page_seq, 1);

        let nf_boundary = plan_auto_open_pages(&pid, 0, 0, 0, 600, 0, 1, &empty).unwrap();
        assert_eq!(nf_boundary.len(), 1);
        assert_eq!(nf_boundary[0].page_kind, OPEN_PAGE_KIND_NULLIFIER);
        assert_eq!(nf_boundary[0].page_seq, 1);

        // Exact subroot page boundary (`300 * 256 = 76_800`, also divisible by 96 -> memo page 800)
        let sr_boundary = plan_auto_open_pages(&pid, 0, 0, 76_800, 0, 1, 0, &empty).unwrap();
        assert!(sr_boundary
            .iter()
            .any(|s| s.page_kind == OPEN_PAGE_KIND_SUBTREE && s.page_seq == 300));
        assert!(sr_boundary
            .iter()
            .any(|s| s.page_kind == OPEN_PAGE_KIND_SUBROOT && s.page_seq == 1));
        assert!(sr_boundary
            .iter()
            .any(|s| s.page_kind == OPEN_PAGE_KIND_MEMO && s.page_seq == 800));

        // Memo >= 90% full (`next_leaf = 86` -> `memo_rem = 10 <= 10`) -> plans ONLY Memo page 1
        let memo_specs = plan_auto_open_pages(&pid, 0, 0, 86, 0, 1, 0, &empty).unwrap();
        assert_eq!(memo_specs.len(), 1);
        assert_eq!(memo_specs[0].page_kind, OPEN_PAGE_KIND_MEMO);
        assert_eq!(memo_specs[0].page_seq, 1);

        // Subtree >= 90% full (`next_leaf = 230` -> `sub_rem = 26 <= 26`) -> plans ONLY Subtree page 1
        let sub_specs = plan_auto_open_pages(&pid, 0, 0, 230, 0, 1, 0, &empty).unwrap();
        assert_eq!(sub_specs.len(), 1);
        assert_eq!(sub_specs[0].page_kind, OPEN_PAGE_KIND_SUBTREE);
        assert_eq!(sub_specs[0].page_seq, 1);

        // Nullifier >= 90% full (`nf_count = 540` -> `nf_rem = 60 <= 60`) -> plans ONLY NF page 1
        let nf_specs = plan_auto_open_pages(&pid, 0, 0, 0, 540, 0, 1, &empty).unwrap();
        assert_eq!(nf_specs.len(), 1);
        assert_eq!(nf_specs[0].page_kind, OPEN_PAGE_KIND_NULLIFIER);
        assert_eq!(nf_specs[0].page_seq, 1);

        // Subroot lookahead (`subroot_slot == 280` => `next_leaf = 280 * 256 = 71_680`)
        let sr_specs = plan_auto_open_pages(&pid, 0, 0, 71_680, 0, 1, 0, &empty).unwrap();
        assert!(sr_specs
            .iter()
            .any(|s| s.page_kind == OPEN_PAGE_KIND_SUBROOT && s.page_seq == 1));
        assert!(sr_specs
            .iter()
            .any(|s| s.page_kind == OPEN_PAGE_KIND_SUBTREE && s.page_seq == 280));

        // Large `num_outputs` cap: NEVER emits `page_seq > cur + 1` or OOR subroot when `subroot_slot < 280`
        let large_specs = plan_auto_open_pages(&pid, 0, 0, 0, 0, 10_000, 10_000, &empty).unwrap();
        assert_eq!(
            large_specs
                .iter()
                .map(|s| (s.page_kind, s.page_seq))
                .collect::<Vec<_>>(),
            vec![
                (OPEN_PAGE_KIND_SUBTREE, 1),
                (OPEN_PAGE_KIND_MEMO, 1),
                (OPEN_PAGE_KIND_NULLIFIER, 1),
            ]
        );

        // `existing_pages` filters out already-initialized candidates
        let mut existing = BTreeSet::new();
        existing.insert(derive_memo_pda(&pid, 0, 0, 1).0);
        let filtered = plan_auto_open_pages(&pid, 0, 0, 86, 540, 1, 1, &existing).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].page_kind, OPEN_PAGE_KIND_NULLIFIER);
        assert_eq!(filtered[0].page_seq, 1);

        // build_auto_open_page_ixs builds matching Tag 2 instructions and tight CU helpers match finalized budgets
        let ixs = build_auto_open_page_ixs(pid, payer, 0, 0, 86, 540, 1, 1, &empty).unwrap();
        assert_eq!(ixs.len(), 2);
        assert!(ixs.iter().all(|ix| ix.data[0] == TAG_OPEN_PAGE));
        assert_eq!(CU_LIMIT_OPEN_PAGE, 40_000);
        assert_eq!(CU_LIMIT_INIT_LANE, 75_000);
        assert_eq!(CU_LIMIT_INIT_ROOT_HISTORY, 75_000);
        assert_eq!(CU_LIMIT_EXEC_VIA_ESCROW_BASE, 285_000);
        assert_eq!(CU_LIMIT_TRANSACT_FULL_EXIT, 165_000);
        assert_eq!(recommended_cu_limit_open_page(1), 40_000);
        assert_eq!(recommended_cu_limit_init_lane(), 75_000);
        assert_eq!(recommended_cu_limit_init_root_history(), 75_000);
        assert_eq!(compute_bump_cu_margin(&[]), 0);
        assert_eq!(compute_bump_cu_margin(&[255]), 0);
        assert_eq!(compute_bump_cu_margin(&[254, 250]), 9_000);
        assert_eq!(compute_bump_cu_margin(&[0; 10]), MAX_TX_CU_LIMIT);
        assert_eq!(
            recommended_cu_limit_open_page_with_bumps(1, &[250]),
            CU_LIMIT_OPEN_PAGE + 7_500
        );
        assert_eq!(
            recommended_cu_limit_deposit_with_bumps(false, 1, 1, 0, &[253, 252]),
            CU_LIMIT_DEPOSIT + CU_LIMIT_OPEN_PAGE + CU_LIMIT_CREATE_ATA_CLASSIC + 7_500
        );
        assert_eq!(
            recommended_cu_limit_transact_with_bumps(true, 0, false, 0, 0, 0, &[245]),
            CU_LIMIT_TRANSACT_FULL_EXIT + 15_000
        );
        assert_eq!(
            recommended_cu_limit_exec_via_escrow_with_bumps(300_000, true, 1, 1, 0, &[240, 255]),
            CU_LIMIT_EXEC_VIA_ESCROW_BASE
                + CU_LIMIT_EXEC_VIA_ESCROW_T22_LEG
                + 300_000
                + CU_LIMIT_OPEN_PAGE
                + CU_LIMIT_CREATE_ATA_CLASSIC
                + 22_500
        );
        assert_eq!(
            recommended_cu_limit_exec_via_escrow_with_bumps(1_300_000, true, 1, 0, 0, &[0, 0]),
            MAX_TX_CU_LIMIT
        );
        assert_eq!(
            recommended_cu_limit_deposit(false, ixs.len()),
            CU_LIMIT_DEPOSIT + 2 * CU_LIMIT_OPEN_PAGE
        );
        assert_eq!(
            recommended_cu_limit_deposit_with_atas(false, 1, 1, 1),
            CU_LIMIT_DEPOSIT + CU_LIMIT_OPEN_PAGE + CU_LIMIT_CREATE_ATA_CLASSIC + CU_LIMIT_CREATE_ATA_TOKEN_2022
        );
        assert_eq!(
            recommended_cu_limit_transact(true, 0, false, 0, 0),
            CU_LIMIT_TRANSACT_FULL_EXIT
        );
        assert_eq!(
            recommended_cu_limit_transact(true, 0, false, 0, 0),
            165_000
        );
        assert_eq!(
            recommended_cu_limit_transact(true, 0b001, false, 1, 1),
            CU_LIMIT_TRANSACT_WITHDRAW + CU_LIMIT_OPEN_PAGE + CU_LIMIT_CREATE_ATA_CLASSIC
        );
        assert_eq!(
            recommended_cu_limit_transact(true, 0, true, 0, 0),
            CU_LIMIT_TRANSACT_WITHDRAW_HOOK
        );
        assert_eq!(
            recommended_cu_limit_transact(false, 0, false, 0, 0),
            CU_LIMIT_TRANSACT_PRIVATE
        );
        assert_eq!(
            recommended_cu_limit_transact_with_atas(true, 0b011, false, 0, 0, 1),
            CU_LIMIT_TRANSACT_WITHDRAW + CU_LIMIT_CREATE_ATA_TOKEN_2022
        );
        assert_eq!(
            recommended_cu_limit_exec_via_escrow(300_000, 2, 1),
            CU_LIMIT_EXEC_VIA_ESCROW_BASE + 300_000 + 2 * CU_LIMIT_OPEN_PAGE + CU_LIMIT_CREATE_ATA_CLASSIC
        );
        assert_eq!(
            recommended_cu_limit_exec_via_escrow_with_atas(300_000, true, 1, 0, 2),
            CU_LIMIT_EXEC_VIA_ESCROW_BASE
                + CU_LIMIT_EXEC_VIA_ESCROW_T22_LEG
                + 300_000
                + CU_LIMIT_OPEN_PAGE
                + 2 * CU_LIMIT_CREATE_ATA_TOKEN_2022
        );
        // Saturation before u32 cast (no 64-bit truncation wrap) + 1.4M MAX_TX_CU_LIMIT clamp
        assert_eq!(recommended_cu_limit_open_page(usize::MAX), MAX_TX_CU_LIMIT);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(recommended_cu_limit_open_page(1usize << 32), MAX_TX_CU_LIMIT);
        assert_eq!(
            recommended_cu_limit_exec_via_escrow_with_atas(1_300_000, true, 4, 2, 2),
            MAX_TX_CU_LIMIT
        );

        // True MAX_LEAVES_PER_LANE (4^18 = 68,719,476,736) ceiling:
        // - SubtreePage #4096 (at leaf 1,048,575 / 1,048,576) is WELL below 4^18 and MUST still be emitted!
        let at_4096_lookahead =
            plan_auto_open_pages(&pid, 0, 0, 4096 * 256 - 1, 0, 1, 0, &empty).unwrap();
        assert!(
            at_4096_lookahead
                .iter()
                .any(|s| s.page_kind == OPEN_PAGE_KIND_SUBTREE && s.page_seq == 4096),
            "SubtreePage #4096 MUST still be emitted (true MAX_LEAVES_PER_LANE = 4^18, not 2^20)"
        );
        let at_4096_exact =
            plan_auto_open_pages(&pid, 0, 0, 4096 * 256, 0, 1, 0, &empty).unwrap();
        assert!(
            at_4096_exact
                .iter()
                .any(|s| s.page_kind == OPEN_PAGE_KIND_SUBTREE && s.page_seq == 4096)
        );

        // - Last valid pages (SubtreePage #268_435_455, SubtreeRootPage #894_784, MemoPage #715_827_882) ARE emitted
        let max_sub = MAX_LEAVES_PER_LANE / SUBTREE_LEAVES as u64; // 268_435_456
        let max_sr = max_sub.div_ceil(SUBROOTS_PER_PAGE as u64); // 894_785
        let max_memo = MAX_LEAVES_PER_LANE.div_ceil(MEMO_NOTES_PER_PAGE as u64); // 715_827_883
        assert_eq!(max_sub, 268_435_456);
        assert_eq!(max_sr, 894_785);
        assert_eq!(max_memo, 715_827_883);

        let last_valid_sub = plan_auto_open_pages(
            &pid,
            0,
            0,
            (max_sub - 1) * SUBTREE_LEAVES as u64,
            0,
            1,
            0,
            &empty,
        )
        .unwrap();
        assert!(last_valid_sub
            .iter()
            .any(|s| s.page_kind == OPEN_PAGE_KIND_SUBTREE && s.page_seq == max_sub - 1));

        let last_valid_sr = plan_auto_open_pages(
            &pid,
            0,
            0,
            ((max_sr - 2) * SUBROOTS_PER_PAGE as u64 + AUTO_OPEN_SUBROOT_LOOKAHEAD_SLOT)
                * SUBTREE_LEAVES as u64,
            0,
            1,
            0,
            &empty,
        )
        .unwrap();
        assert!(last_valid_sr
            .iter()
            .any(|s| s.page_kind == OPEN_PAGE_KIND_SUBROOT && s.page_seq == max_sr - 1));

        let last_valid_memo = plan_auto_open_pages(
            &pid,
            0,
            0,
            (max_memo - 1) * MEMO_NOTES_PER_PAGE as u64,
            0,
            1,
            0,
            &empty,
        )
        .unwrap();
        assert!(last_valid_memo
            .iter()
            .any(|s| s.page_kind == OPEN_PAGE_KIND_MEMO && s.page_seq == max_memo - 1));

        // - At MAX_LEAVES_PER_LANE - 1: unreachable SubtreePage #268_435_456 / SubrootPage #894_785 / MemoPage #715_827_883 MUST NOT be emitted!
        for num_outputs in [1usize, 100usize] {
            let at_max_minus_1 = plan_auto_open_pages(
                &pid,
                0,
                0,
                MAX_LEAVES_PER_LANE - 1,
                0,
                num_outputs,
                0,
                &empty,
            )
            .unwrap();
            assert!(
                at_max_minus_1.is_empty(),
                "MAX_LEAVES_PER_LANE - 1 (num_outputs={num_outputs}) must not emit unreachable pages, got {at_max_minus_1:?}"
            );
        }

        // - At MAX_LEAVES_PER_LANE (and above): ALL output-page planning is skipped, while NullifierPage planning still works!
        let at_max =
            plan_auto_open_pages(&pid, 0, 0, MAX_LEAVES_PER_LANE, 540, 1, 1, &empty).unwrap();
        assert_eq!(at_max.len(), 1);
        assert_eq!(at_max[0].page_kind, OPEN_PAGE_KIND_NULLIFIER);
        assert_eq!(at_max[0].page_seq, 1);
        assert!(plan_auto_open_pages(&pid, 0, 0, MAX_LEAVES_PER_LANE, 0, 3, 0, &empty)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn deterministic_note_rent_fee_clamps_zero_rent_parity() {
        assert_eq!(
            deterministic_note_rent_fee(10_000_000, 256 * 100, 76_800 * 10, 96 * 200),
            310
        );
        assert_eq!(
            deterministic_note_rent_fee(150, 256 * 100, 76_800 * 10, 96 * 200),
            150
        );
        // Zero-rent cluster `.max(1)` clamp parity (`1 + 1 + 1 = 3`, capped by `pool_note_rent_fee_cap`)
        assert_eq!(deterministic_note_rent_fee(10_000_000, 0, 0, 0), 3);
        assert_eq!(deterministic_note_rent_fee(3, 0, 0, 0), 3);
        assert_eq!(deterministic_note_rent_fee(2, 0, 0, 0), 2);
        assert_eq!(deterministic_note_rent_fee(0, 0, 0, 0), 0);
        assert_eq!(deterministic_note_rent_fee(10_000_000, 0, 76_800 * 5, 0), 7);
    }
}
