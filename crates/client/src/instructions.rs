//! Builders for all 9 Audren instructions (`0x00..=0x08`) and exact `ctx_hash` transcripts.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use audren_circuits::poseidon::fr_to_be_bytes;
use audren_core::{
    instruction::{
        ASSET_MODE_SOL, ASSET_MODE_SPL, CTX_DOMAIN_EXEC_VIA_ESCROW, CTX_DOMAIN_JOINSPLIT,
        CTX_DOMAIN_ROUTER_ACCOUNTS, DEPOSIT_FLAG_FEE_FROM_AMOUNT, EXEC_FLAG_FEE_ON_OUTPUT,
        GROTH16_PROOF_LEN, OPEN_PAGE_KIND_MEMO, OPEN_PAGE_KIND_NULLIFIER, OPEN_PAGE_KIND_SUBROOT,
        OPEN_PAGE_KIND_SUBTREE, TAG_DEPOSIT_SOL, TAG_DEPOSIT_SPL, TAG_EXEC_VIA_ESCROW,
        TAG_INIT_LANE, TAG_INIT_POOL, TAG_JOINSPLIT, TAG_OPEN_PAGE, TAG_PUBLISH_CHECKPOINT,
        TAG_SET_PAUSED, WITHDRAW_FLAG_UNWRAP_WSOL,
    },
    layout::{
        DYN_MEMO_HEAD_LEN, MEMO_CT_LEN, MEMO_ENTRY_WIRE_LEN, MEMO_NOTES_PER_PAGE, NF_PER_PAGE,
        SUBROOTS_PER_PAGE, SUBTREE_LEAVES,
    },
    SYSTEM_PROGRAM_ID,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_address::Address;

use crate::{
    pda::{
        derive_checkpoint_pda, derive_escrow_pda, derive_lane_pda, derive_lane_rent_pda,
        derive_memo_pda, derive_nf_page_pda, derive_nullifier_pda, derive_pool_pda,
        derive_sol_vault_pda, derive_subroot_pda, derive_subtree_pda, derive_unwrap_pda,
        derive_vault_auth_pda,
    },
    router::prepare_escrow_accounts_for_audren,
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
    let live = sub_rent.div_ceil(256) + sr_rent.div_ceil(256 * 300) + memo_rent.div_ceil(112);
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

/// Exact `JoinSplit` `ctx_hash` matching `program/src/lib.rs` bit-for-bit.
#[allow(clippy::too_many_arguments)]
pub fn compute_joinsplit_ctx_hash(
    program_id: &Address,
    pool_id: u32,
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
    let mut h = Sha256::new();
    h.update(CTX_DOMAIN_JOINSPLIT);
    h.update(program_id.as_ref());
    h.update(pool_id.to_le_bytes());
    h.update([out_lane_id, output_mask, asset_mode, u8::from(unwrap_wsol)]);
    if public_amount_out > 0 {
        h.update(recipient.expect("recipient required").as_ref());
    } else {
        h.update([0u8; 32]);
    }
    if relayer_fee_amount > 0 {
        h.update(relayer_fee_recipient.expect("relayer_fee_recipient required").as_ref());
    } else {
        h.update([0u8; 32]);
    }
    h.update(public_asset_id);
    h.update(public_amount_out.to_le_bytes());
    h.update(relayer_fee_amount.to_le_bytes());
    h.update(memos_bytes);
    let digest: [u8; 32] = h.finalize().into();
    mask_to_fr(&digest)
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

/// Exact `ExecViaEscrow` `ctx_hash` matching `program/src/lib.rs` bit-for-bit.
///
/// Applies Solana's transaction-wide writability promotion across `escrow_pda`, `sol_vault`,
/// `relayer_fee_recipient`, and duplicate writable `router_accounts` before hashing
/// `router_accounts` so on-chain `hash_router_accounts_arena` matches identically.
#[allow(clippy::too_many_arguments)]
pub fn compute_exec_ctx_hash(
    program_id: &Address,
    pool_id: u32,
    out_lane_id: u8,
    escrow_shard: u8,
    change_mask: u8,
    in_kind: u8,
    out_kind: u8,
    fee_on_output: bool,
    asset_in: &[u8; 32],
    amount_in: u64,
    relayer_fee_amount: u64,
    relayer_fee_recipient: Option<&Address>,
    asset_out: &[u8; 32],
    min_amount_out: u64,
    router_prog: &Address,
    router_accounts: &[AudrenAccountMeta],
    out_stealth_owner: &[u8; 32],
    out_blinding: &[u8; 32],
    dyn_memo_head: &[u8; DYN_MEMO_HEAD_LEN],
    dyn_mask_56: &[u8; MEMO_CT_LEN],
    router_ix_data: &[u8],
    change_memos: &[u8],
) -> Fr {
    let (escrow_pda, _) = derive_escrow_pda(program_id, pool_id, escrow_shard);
    let mut extra_writable = Vec::with_capacity(2);
    if in_kind == 0 || out_kind == 0 {
        extra_writable.push(derive_sol_vault_pda(program_id, pool_id).0);
    }
    if relayer_fee_amount > 0 {
        if let Some(fee_r) = relayer_fee_recipient {
            extra_writable.push(*fee_r);
        }
    }
    let normalized_router_accs =
        prepare_escrow_accounts_for_audren(router_accounts, &escrow_pda, &extra_writable);
    let router_accs_hash = compute_router_accounts_hash(&normalized_router_accs);
    let mut h = Sha256::new();
    h.update(CTX_DOMAIN_EXEC_VIA_ESCROW);
    h.update(program_id.as_ref());
    h.update(pool_id.to_le_bytes());
    h.update([
        out_lane_id,
        escrow_shard,
        change_mask,
        in_kind,
        out_kind,
        u8::from(fee_on_output),
    ]);
    h.update(asset_in);
    h.update(amount_in.to_le_bytes());
    h.update(relayer_fee_amount.to_le_bytes());
    if relayer_fee_amount > 0 {
        h.update(relayer_fee_recipient.expect("relayer_fee_recipient required").as_ref());
    } else {
        h.update([0u8; 32]);
    }
    h.update(asset_out);
    h.update(min_amount_out.to_le_bytes());
    h.update(router_prog.as_ref());
    h.update(router_accs_hash);
    h.update(out_stealth_owner);
    h.update(out_blinding);
    h.update(dyn_memo_head);
    h.update(dyn_mask_56);
    h.update((router_ix_data.len() as u16).to_le_bytes());
    h.update(router_ix_data);
    h.update(change_memos);
    let digest: [u8; 32] = h.finalize().into();
    mask_to_fr(&digest)
}

// =============================================================================
// 9 Canonical Audren Instruction Builders (0x00..=0x08)
// =============================================================================

pub fn build_init_pool(
    program_id: Address,
    payer: Address,
    pool_id: u32,
    ckpt_interval: u64,
    max_ckpt_age: u64,
    note_rent_fee: u64,
    nf_rent_fee: u64,
) -> AudrenInstruction {
    let mut data = Vec::with_capacity(37);
    data.push(TAG_INIT_POOL);
    data.extend_from_slice(&pool_id.to_le_bytes());
    data.extend_from_slice(&ckpt_interval.to_le_bytes());
    data.extend_from_slice(&max_ckpt_age.to_le_bytes());
    data.extend_from_slice(&note_rent_fee.to_le_bytes());
    data.extend_from_slice(&nf_rent_fee.to_le_bytes());
    AudrenInstruction {
        program_id: program_id.to_bytes(),
        accounts: vec![
            AudrenAccountMeta::writable(payer, true),
            AudrenAccountMeta::writable(derive_pool_pda(&program_id, pool_id).0, false),
            AudrenAccountMeta::writable(derive_sol_vault_pda(&program_id, pool_id).0, false),
            AudrenAccountMeta::readonly(sys_id(), false),
        ],
        data,
    }
}

pub fn build_init_lane(
    program_id: Address,
    authority: Address,
    pool_id: u32,
    lane_id: u8,
) -> AudrenInstruction {
    let mut data = Vec::with_capacity(6);
    data.push(TAG_INIT_LANE);
    data.extend_from_slice(&pool_id.to_le_bytes());
    data.push(lane_id);
    AudrenInstruction {
        program_id: program_id.to_bytes(),
        accounts: vec![
            AudrenAccountMeta::writable(authority, true),
            AudrenAccountMeta::writable(derive_pool_pda(&program_id, pool_id).0, false),
            AudrenAccountMeta::writable(derive_lane_pda(&program_id, pool_id, lane_id).0, false),
            AudrenAccountMeta::writable(derive_lane_rent_pda(&program_id, pool_id, lane_id).0, false),
            AudrenAccountMeta::writable(derive_subtree_pda(&program_id, pool_id, lane_id, 0).0, false),
            AudrenAccountMeta::writable(derive_subroot_pda(&program_id, pool_id, lane_id, 0).0, false),
            AudrenAccountMeta::writable(derive_memo_pda(&program_id, pool_id, lane_id, 0).0, false),
            AudrenAccountMeta::writable(derive_nf_page_pda(&program_id, pool_id, lane_id, 0).0, false),
            AudrenAccountMeta::readonly(sys_id(), false),
        ],
        data,
    }
}

pub fn build_open_page(
    program_id: Address,
    payer: Address,
    page_kind: u8,
    pool_id: u32,
    lane_id: u8,
    page_seq: u64,
) -> AudrenInstruction {
    let page_pda = match page_kind {
        OPEN_PAGE_KIND_SUBTREE => derive_subtree_pda(&program_id, pool_id, lane_id, page_seq).0,
        OPEN_PAGE_KIND_SUBROOT => derive_subroot_pda(&program_id, pool_id, lane_id, page_seq).0,
        OPEN_PAGE_KIND_MEMO => derive_memo_pda(&program_id, pool_id, lane_id, page_seq).0,
        OPEN_PAGE_KIND_NULLIFIER => derive_nf_page_pda(&program_id, pool_id, lane_id, page_seq).0,
        _ => panic!("invalid page_kind {page_kind}"),
    };
    let mut data = Vec::with_capacity(15);
    data.push(TAG_OPEN_PAGE);
    data.push(page_kind);
    data.extend_from_slice(&pool_id.to_le_bytes());
    data.push(lane_id);
    data.extend_from_slice(&page_seq.to_le_bytes());
    AudrenInstruction {
        program_id: program_id.to_bytes(),
        accounts: vec![
            AudrenAccountMeta::writable(payer, true),
            AudrenAccountMeta::readonly(derive_pool_pda(&program_id, pool_id).0, false),
            AudrenAccountMeta::readonly(derive_lane_pda(&program_id, pool_id, lane_id).0, false),
            AudrenAccountMeta::writable(derive_lane_rent_pda(&program_id, pool_id, lane_id).0, false),
            AudrenAccountMeta::writable(page_pda, false),
            AudrenAccountMeta::readonly(sys_id(), false),
        ],
        data,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_deposit_sol(
    program_id: Address,
    depositor: Address,
    pool_id: u32,
    lane_id: u8,
    sub_page_seq: u64,
    root_page_seq: u64,
    memo_page_seq: u64,
    next_sub_seq: Option<u64>,
    next_memo_seq: Option<u64>,
    fee_from_amount: bool,
    amount: u64,
    stealth_owner: Fr,
    blinding: Fr,
    memo_90: &[u8; MEMO_ENTRY_WIRE_LEN],
) -> AudrenInstruction {
    let flags = u8::from(next_sub_seq.is_some())
        | (u8::from(next_memo_seq.is_some()) << 1)
        | if fee_from_amount {
            DEPOSIT_FLAG_FEE_FROM_AMOUNT
        } else {
            0
        };
    let mut data = Vec::with_capacity(169);
    data.push(TAG_DEPOSIT_SOL);
    data.extend_from_slice(&pool_id.to_le_bytes());
    data.push(lane_id);
    data.push(flags);
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&fr_to_be_bytes(&stealth_owner));
    data.extend_from_slice(&fr_to_be_bytes(&blinding));
    data.extend_from_slice(memo_90);

    let mut accounts = vec![
        AudrenAccountMeta::writable(depositor, true),
        AudrenAccountMeta::readonly(derive_pool_pda(&program_id, pool_id).0, false),
        AudrenAccountMeta::writable(derive_sol_vault_pda(&program_id, pool_id).0, false),
        AudrenAccountMeta::writable(derive_lane_pda(&program_id, pool_id, lane_id).0, false),
        AudrenAccountMeta::writable(derive_lane_rent_pda(&program_id, pool_id, lane_id).0, false),
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
    AudrenInstruction {
        program_id: program_id.to_bytes(),
        accounts,
        data,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_deposit_spl(
    program_id: Address,
    depositor: Address,
    pool_id: u32,
    mint: Address,
    depositor_ata: Address,
    vault_ata: Address,
    token_prog: Address,
    lane_id: u8,
    sub_page_seq: u64,
    root_page_seq: u64,
    memo_page_seq: u64,
    next_sub_seq: Option<u64>,
    next_memo_seq: Option<u64>,
    amount: u64,
    stealth_owner: Fr,
    blinding: Fr,
    memo_90: &[u8; MEMO_ENTRY_WIRE_LEN],
    transfer_hook_accounts: &[AudrenAccountMeta],
) -> AudrenInstruction {
    let flags = u8::from(next_sub_seq.is_some()) | (u8::from(next_memo_seq.is_some()) << 1);
    let mut data = Vec::with_capacity(169);
    data.push(TAG_DEPOSIT_SPL);
    data.extend_from_slice(&pool_id.to_le_bytes());
    data.push(lane_id);
    data.push(flags);
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&fr_to_be_bytes(&stealth_owner));
    data.extend_from_slice(&fr_to_be_bytes(&blinding));
    data.extend_from_slice(memo_90);

    let mut accounts = vec![
        AudrenAccountMeta::writable(depositor, true),
        AudrenAccountMeta::readonly(derive_pool_pda(&program_id, pool_id).0, false),
        AudrenAccountMeta::readonly(derive_vault_auth_pda(&program_id, pool_id).0, false),
        AudrenAccountMeta::readonly(mint, false),
        AudrenAccountMeta::writable(depositor_ata, false),
        AudrenAccountMeta::writable(vault_ata, false),
        AudrenAccountMeta::readonly(token_prog, false),
        AudrenAccountMeta::writable(derive_lane_pda(&program_id, pool_id, lane_id).0, false),
        AudrenAccountMeta::writable(derive_lane_rent_pda(&program_id, pool_id, lane_id).0, false),
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
    AudrenInstruction {
        program_id: program_id.to_bytes(),
        accounts,
        data,
    }
}

pub fn build_publish_checkpoint(
    program_id: Address,
    payer: Address,
    pool_id: u32,
    slot_idx: u16,
    active_lanes: u8,
) -> AudrenInstruction {
    let mut data = Vec::with_capacity(5);
    data.push(TAG_PUBLISH_CHECKPOINT);
    data.extend_from_slice(&pool_id.to_le_bytes());
    let mut accounts = Vec::with_capacity(4 + active_lanes as usize);
    accounts.push(AudrenAccountMeta::writable(payer, true));
    accounts.push(AudrenAccountMeta::readonly(
        derive_pool_pda(&program_id, pool_id).0,
        false,
    ));
    accounts.push(AudrenAccountMeta::writable(
        derive_checkpoint_pda(&program_id, pool_id, slot_idx).0,
        false,
    ));
    accounts.push(AudrenAccountMeta::readonly(sys_id(), false));
    for l in 0..active_lanes {
        accounts.push(AudrenAccountMeta::readonly(
            derive_lane_pda(&program_id, pool_id, l).0,
            false,
        ));
    }
    AudrenInstruction {
        program_id: program_id.to_bytes(),
        accounts,
        data,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_joinsplit(
    program_id: Address,
    payer: Address,
    pool_id: u32,
    vk_id: u8,
    ckpt_slot_idx: u16,
    out_lane_id: u8,
    out_sub_seq: u64,
    out_root_seq: u64,
    out_memo_seq: u64,
    out_nf_seq: u64,
    output_mask: u8,
    asset_mode: u8,
    unwrap_wsol: bool,
    spl_withdraw_accs: Option<(Address, Address, Address)>, // (mint, vault_ata, token_prog)
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
    let flags = u8::from(rollover.0.is_some())
        | (u8::from(rollover.1.is_some()) << 1)
        | (u8::from(rollover.2.is_some()) << 2)
        | if unwrap_wsol {
            WITHDRAW_FLAG_UNWRAP_WSOL
        } else {
            0
        };
    let mut data = Vec::with_capacity(378 + memos_bytes.len());
    data.push(TAG_JOINSPLIT);
    data.extend_from_slice(&pool_id.to_le_bytes());
    data.push(vk_id);
    data.push(out_lane_id);
    data.push(output_mask);
    data.push(asset_mode);
    data.push(flags);
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

    let mut accounts = vec![
        AudrenAccountMeta::writable(payer, true),
        AudrenAccountMeta::readonly(derive_pool_pda(&program_id, pool_id).0, false),
        AudrenAccountMeta::readonly(
            derive_checkpoint_pda(&program_id, pool_id, ckpt_slot_idx).0,
            false,
        ),
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

    if asset_mode == ASSET_MODE_SOL {
        accounts.push(AudrenAccountMeta::writable(
            derive_sol_vault_pda(&program_id, pool_id).0,
            false,
        ));
        accounts.push(AudrenAccountMeta::writable(recipient, false));
        accounts.push(if relayer_fee_amount > 0 {
            AudrenAccountMeta::writable(relayer_fee_recipient, false)
        } else {
            AudrenAccountMeta::readonly(relayer_fee_recipient, false)
        });
    } else if asset_mode == ASSET_MODE_SPL {
        let (mint, vault_ata, token_prog) = spl_withdraw_accs.expect("SPL withdraw accs required");
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

    AudrenInstruction {
        program_id: program_id.to_bytes(),
        accounts,
        data,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_exec_via_escrow(
    program_id: Address,
    payer: Address,
    pool_id: u32,
    vk_id: u8,
    ckpt_slot_idx: u16,
    out_lane_id: u8,
    out_sub_seq: u64,
    out_root_seq: u64,
    out_memo_seq: u64,
    out_nf_seq: u64,
    escrow_shard: u8,
    change_mask: u8,
    in_kind: u8,
    out_kind: u8,
    fee_on_output: bool,
    in_spl: Option<(Address, Address, Address, Address)>,
    out_spl: Option<(Address, Address, Address, Address)>,
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
    dyn_mask_56: &[u8; MEMO_CT_LEN],
    router_prog: Address,
    router_ix_data: &[u8],
    router_accounts: Vec<AudrenAccountMeta>,
    change_memos: &[u8],
) -> AudrenInstruction {
    let flags = u8::from(rollover.0.is_some())
        | (u8::from(rollover.1.is_some()) << 1)
        | (u8::from(rollover.2.is_some()) << 2)
        | if fee_on_output {
            EXEC_FLAG_FEE_ON_OUTPUT
        } else {
            0
        };
    let mut data = Vec::with_capacity(544 + router_ix_data.len() + change_memos.len());
    data.push(TAG_EXEC_VIA_ESCROW);
    data.extend_from_slice(&pool_id.to_le_bytes());
    data.push(vk_id);
    data.push(out_lane_id);
    data.push(escrow_shard);
    data.push(change_mask);
    data.push(in_kind);
    data.push(out_kind);
    data.push(flags);
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
    data.extend_from_slice(dyn_mask_56);
    data.extend_from_slice(&(router_ix_data.len() as u16).to_le_bytes());
    data.extend_from_slice(router_ix_data);
    data.extend_from_slice(change_memos);

    let nf1_meta = if *nf1 == [0u8; 32] {
        AudrenAccountMeta::readonly(sys_id(), false)
    } else {
        AudrenAccountMeta::writable(derive_nullifier_pda(&program_id, pool_id, nf1).0, false)
    };

    let (escrow_pda, _) = derive_escrow_pda(&program_id, pool_id, escrow_shard);
    let mut accounts = vec![
        AudrenAccountMeta::writable(payer, true),
        AudrenAccountMeta::readonly(derive_pool_pda(&program_id, pool_id).0, false),
        AudrenAccountMeta::readonly(
            derive_checkpoint_pda(&program_id, pool_id, ckpt_slot_idx).0,
            false,
        ),
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

    if in_kind == 0 {
        accounts.push(AudrenAccountMeta::writable(
            derive_sol_vault_pda(&program_id, pool_id).0,
            false,
        ));
    } else {
        let (m_in, v_in, e_in, tp_in) = in_spl.expect("in_spl required");
        accounts.push(AudrenAccountMeta::readonly(
            derive_vault_auth_pda(&program_id, pool_id).0,
            false,
        ));
        accounts.push(AudrenAccountMeta::readonly(m_in, false));
        accounts.push(AudrenAccountMeta::writable(v_in, false));
        accounts.push(AudrenAccountMeta::writable(e_in, false));
        accounts.push(AudrenAccountMeta::readonly(tp_in, false));
    }
    if relayer_fee_amount > 0 && !fee_on_output {
        accounts.push(AudrenAccountMeta::writable(
            relayer_fee_recipient.expect("relayer_fee_recipient required"),
            false,
        ));
    }

    if out_kind == 0 {
        accounts.push(AudrenAccountMeta::writable(
            derive_sol_vault_pda(&program_id, pool_id).0,
            false,
        ));
    } else {
        let (m_out, v_out, e_out, tp_out) = out_spl.expect("out_spl required");
        accounts.push(AudrenAccountMeta::readonly(
            derive_vault_auth_pda(&program_id, pool_id).0,
            false,
        ));
        accounts.push(AudrenAccountMeta::readonly(m_out, false));
        accounts.push(AudrenAccountMeta::writable(v_out, false));
        accounts.push(AudrenAccountMeta::writable(e_out, false));
        accounts.push(AudrenAccountMeta::readonly(tp_out, false));
    }
    if relayer_fee_amount > 0 && fee_on_output {
        accounts.push(AudrenAccountMeta::writable(
            relayer_fee_recipient.expect("relayer_fee_recipient required"),
            false,
        ));
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

    let preceding_writable: Vec<Address> = accounts
        .iter()
        .filter(|a| a.is_writable)
        .map(|a| Address::new_from_array(a.pubkey))
        .collect();
    let normalized_router_accs =
        prepare_escrow_accounts_for_audren(&router_accounts, &escrow_pda, &preceding_writable);
    accounts.extend(normalized_router_accs);
    AudrenInstruction {
        program_id: program_id.to_bytes(),
        accounts,
        data,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_page_rollovers_exact_boundaries() {
        assert_eq!(
            compute_page_rollovers(109, 3, 0, 2),
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
        assert_eq!(compute_page_rollovers(110, 3, 0, 2).next_memo_seq, Some(1));
        assert_eq!(compute_page_rollovers(111, 2, 0, 1).next_memo_seq, Some(1));
        assert_eq!(compute_page_rollovers(112, 3, 0, 2).out_memo_seq, 1);
        assert_eq!(compute_page_rollovers(112, 3, 0, 2).next_memo_seq, None);

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
}
