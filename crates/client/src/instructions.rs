//! Instruction builders for all 13 Audren instructions (`InitPool`, `OpenPage`, `Deposit`,
//! `Transfer`, `Merge`, `SwapViaRouter`, `Withdraw`, `SetPaused`, `WriteProofBuffer`,
//! `ExecBuffered`, `CloseProofBuffer`, `InitLane`, `OpenLanePage`).
//!
//! Verified byte-for-byte against `program/src/lib.rs`.

use crate::keys::{
    prepare_dynamic_swap_output, prepare_shielded_note, AudrenAddress, PreparedDynamicOutput,
    PreparedNote,
};
use crate::pda::{
    derive_ata, derive_epoch_page_pda, derive_lane_pda, derive_lane_rent_vault_pda,
    derive_nullifier_pda, derive_page_rent_vault_pda, derive_pool_pda, derive_proof_buffer_pda,
    derive_sol_vault_pda, derive_swap_escrow_pda, derive_vault_auth_pda,
};
use crate::prover::{
    asset_generator, compress, decompress, h_point, prove_auditor_asset, prove_cross_base_1,
    prove_cross_base_2, prove_range_u128, prove_range_u64, prove_triptych, transcript_root, Point,
    RingSlotWitness, TriptychWitness,
};
use crate::scanner::OwnedNote;
use crate::ClientError;
use audren_core::{
    instruction::{
        m_for_input_pages, DYNAMIC_OUTPUT_WIRE_LEN, MAX_MERGE_RING_SLOTS, NOTE_WIRE_LEN,
        TAG_CLOSE_PROOF_BUFFER, TAG_DEPOSIT, TAG_EXEC_BUFFERED, TAG_INIT_LANE, TAG_INIT_POOL,
        TAG_MERGE, TAG_OPEN_LANE_PAGE, TAG_OPEN_PAGE, TAG_SET_PAUSED, TAG_SWAP_VIA_ROUTER,
        TAG_TRANSFER, TAG_WITHDRAW, TAG_WRITE_PROOF_BUFFER,
    },
    lane_of_page_id,
    layout::{NoteEntry, PROOF_BUFFER_CHUNK_SIZE, PROOF_BUFFER_MAX_PAYLOAD},
    page_id_for_lane, seq_of_page_id, PoolMode, NATIVE_SOL_MINT, SYSTEM_PROGRAM_ID,
    ZK_ELGAMAL_PROOF_PROGRAM_ID,
};
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use solana_address::Address;

/// Runtime-agnostic Solana account meta.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AudrenAccountMeta {
    pub pubkey: Address,
    pub is_signer: bool,
    pub is_writable: bool,
}

impl AudrenAccountMeta {
    #[inline]
    pub fn writable_signer(pubkey: Address) -> Self {
        Self {
            pubkey,
            is_signer: true,
            is_writable: true,
        }
    }
    #[inline]
    pub fn readonly_signer(pubkey: Address) -> Self {
        Self {
            pubkey,
            is_signer: true,
            is_writable: false,
        }
    }
    #[inline]
    pub fn writable(pubkey: Address) -> Self {
        Self {
            pubkey,
            is_signer: false,
            is_writable: true,
        }
    }
    #[inline]
    pub fn readonly(pubkey: Address) -> Self {
        Self {
            pubkey,
            is_signer: false,
            is_writable: false,
        }
    }
}

/// Runtime-agnostic Solana instruction ready for `solana-sdk` or RPC submission.
#[derive(Clone, Debug)]
pub struct AudrenInstruction {
    pub program_id: Address,
    pub accounts: Vec<AudrenAccountMeta>,
    pub data: Vec<u8>,
}

impl AudrenInstruction {
    /// Append optional trailing accounts (for example Token-2022 `TransferHook` program,
    /// `ExtraAccountMetaList`, and hook accounts on `Deposit` or `Withdraw`).
    pub fn with_extra_accounts(mut self, extra: &[AudrenAccountMeta]) -> Self {
        self.accounts.extend_from_slice(extra);
        self
    }
}

/// Compute the SPL Token-2022 transfer fee withheld on a gross transfer of `amount`
/// using Token-2022's exact ceiling division (`fee_bps / 10_000`, capped at `max_fee`).
pub fn calculate_transfer_fee(amount: u64, fee_bps: u16, max_fee: u64) -> u64 {
    const ONE_IN_BASIS_POINTS: u128 = 10_000;
    if fee_bps == 0 || amount == 0 {
        return 0;
    }
    let bps = (fee_bps as u128).min(ONE_IN_BASIS_POINTS);
    let raw = if bps == ONE_IN_BASIS_POINTS {
        amount as u128
    } else {
        (amount as u128)
            .saturating_mul(bps)
            .saturating_add(ONE_IN_BASIS_POINTS - 1)
            / ONE_IN_BASIS_POINTS
    };
    raw.min(max_fee as u128).min(amount as u128) as u64
}

/// Net amount credited to the Audren vault on a gross `Deposit` of `amount` for a Token-2022
/// mint with `TransferFeeConfig`.
pub fn net_deposit_amount(amount: u64, fee_bps: u16, max_fee: u64) -> u64 {
    amount.saturating_sub(calculate_transfer_fee(amount, fee_bps, max_fee))
}

fn encode_note_wire(note: &NoteEntry) -> [u8; NOTE_WIRE_LEN] {
    let mut out = [0u8; NOTE_WIRE_LEN];
    out[0] = note.view_tag;
    out[1..33].copy_from_slice(&note.ephemeral_pk);
    out[33..65].copy_from_slice(&note.stealth_pk);
    out[65..97].copy_from_slice(&note.asset_tag);
    out[97..129].copy_from_slice(&note.commitment);
    out[129..193].copy_from_slice(&note.ciphertext);
    out
}

fn encode_dynamic_output_wire(out_desc: &PreparedDynamicOutput) -> [u8; DYNAMIC_OUTPUT_WIRE_LEN] {
    let mut out = [0u8; DYNAMIC_OUTPUT_WIRE_LEN];
    out[0] = out_desc.view_tag;
    out[1..33].copy_from_slice(&out_desc.ephemeral_pk);
    out[33..65].copy_from_slice(&out_desc.stealth_pk);
    out[65..129].copy_from_slice(&out_desc.encrypted_memo);
    out
}

/// Tag 0: `InitPool` — create `PoolState`, Page 0, `sol_vault`, and `page_rent_vault`.
pub fn build_init_pool(
    program_id: Address,
    authority: Address,
    pool_id: u32,
    mode: PoolMode,
    auditor_locked: bool,
    auditor_pk: Point,
    page_rent_fee_lamports: u64,
) -> AudrenInstruction {
    let (pool_pda, _) = derive_pool_pda(&program_id, pool_id);
    let (page0, _) = derive_epoch_page_pda(&program_id, pool_id, 0);
    let (sol_vault, _) = derive_sol_vault_pda(&program_id, pool_id);
    let (rent_vault, _) = derive_page_rent_vault_pda(&program_id, pool_id);
    let sys_prog = Address::new_from_array(SYSTEM_PROGRAM_ID);

    let mut data = Vec::with_capacity(47);
    data.push(TAG_INIT_POOL);
    data.extend_from_slice(&pool_id.to_le_bytes());
    data.push(mode as u8);
    data.push(u8::from(auditor_locked));
    data.extend_from_slice(&page_rent_fee_lamports.to_le_bytes());
    data.extend_from_slice(&auditor_pk);

    AudrenInstruction {
        program_id,
        accounts: vec![
            AudrenAccountMeta::writable_signer(authority),
            AudrenAccountMeta::writable(pool_pda),
            AudrenAccountMeta::writable(page0),
            AudrenAccountMeta::writable(sol_vault),
            AudrenAccountMeta::writable(rent_vault),
            AudrenAccountMeta::readonly(sys_prog),
        ],
        data,
    }
}

/// Tag 1: `OpenPage` — permissionless crank to seal `current_page_id` and open `current_page_id + 1`.
pub fn build_open_page(
    program_id: Address,
    payer: Address,
    pool_id: u32,
    current_page_id: u64,
) -> AudrenInstruction {
    let (pool_pda, _) = derive_pool_pda(&program_id, pool_id);
    let (cur_page, _) = derive_epoch_page_pda(&program_id, pool_id, current_page_id);
    let (next_page, _) = derive_epoch_page_pda(&program_id, pool_id, current_page_id + 1);
    let (rent_vault, _) = derive_page_rent_vault_pda(&program_id, pool_id);
    let sys_prog = Address::new_from_array(SYSTEM_PROGRAM_ID);

    AudrenInstruction {
        program_id,
        accounts: vec![
            AudrenAccountMeta::writable_signer(payer),
            AudrenAccountMeta::writable(pool_pda),
            AudrenAccountMeta::writable(cur_page),
            AudrenAccountMeta::writable(next_page),
            AudrenAccountMeta::writable(rent_vault),
            AudrenAccountMeta::readonly(sys_prog),
        ],
        data: vec![TAG_OPEN_PAGE],
    }
}

/// Tag 2: `Deposit` — shield native SOL, Classic SPL, or Token-2022 directly to any Audren stealth address.
/// Works identically for self-deposits and third-party payment gateways: the on-chain program computes
/// `G_mint` and `V = net_received * G_mint` directly so the depositor never needs the user's spend key
/// or a ZK proof.
#[allow(clippy::too_many_arguments)]
pub fn build_deposit<R: RngCore + CryptoRng>(
    program_id: Address,
    depositor: Address,
    pool_id: u32,
    active_page_id: u64,
    recipient: &AudrenAddress,
    mint: [u8; 32],
    amount: u64,
    spl_accounts: Option<(Address, Address, Address)>, // (token_program, depositor_ata, vault_ata)
    rng: &mut R,
) -> Result<(AudrenInstruction, PreparedNote), ClientError> {
    build_deposit_with_options(
        program_id,
        depositor,
        pool_id,
        active_page_id,
        recipient,
        mint,
        amount,
        amount,
        spl_accounts,
        &[],
        rng,
    )
}

/// Tag 2: `Deposit` with explicit net vault amount (for active `TransferFee` Token-2022 mints,
/// see [`net_deposit_amount`]) and optional trailing `TransferHook` accounts.
#[allow(clippy::too_many_arguments)]
pub fn build_deposit_with_options<R: RngCore + CryptoRng>(
    program_id: Address,
    depositor: Address,
    pool_id: u32,
    active_page_id: u64,
    recipient: &AudrenAddress,
    mint: [u8; 32],
    gross_amount: u64,
    net_amount: u64,
    spl_accounts: Option<(Address, Address, Address)>, // (token_program, depositor_ata, vault_ata)
    extra_hook_accounts: &[AudrenAccountMeta],
    rng: &mut R,
) -> Result<(AudrenInstruction, PreparedNote), ClientError> {
    let is_native = mint == NATIVE_SOL_MINT;
    let prepared = prepare_shielded_note(
        recipient, mint, net_amount, false, None, false, [0u8; 7], rng,
    )?;

    let (pool_pda, _) = derive_pool_pda(&program_id, pool_id);
    let (out_page, _) = derive_epoch_page_pda(&program_id, pool_id, active_page_id);
    let out_lane = lane_of_page_id(active_page_id);
    let pool_meta = if out_lane == 0 {
        AudrenAccountMeta::writable(pool_pda)
    } else {
        AudrenAccountMeta::readonly(pool_pda)
    };
    let rent_vault = if out_lane == 0 {
        derive_page_rent_vault_pda(&program_id, pool_id).0
    } else {
        derive_lane_rent_vault_pda(&program_id, pool_id, out_lane).0
    };
    let sys_prog = Address::new_from_array(SYSTEM_PROGRAM_ID);

    let mut data = Vec::with_capacity(1 + 9 + DYNAMIC_OUTPUT_WIRE_LEN);
    data.push(TAG_DEPOSIT);
    data.push(u8::from(is_native));
    data.extend_from_slice(&gross_amount.to_le_bytes());
    data.push(prepared.entry.view_tag);
    data.extend_from_slice(&prepared.entry.ephemeral_pk);
    data.extend_from_slice(&prepared.entry.stealth_pk);
    data.extend_from_slice(&prepared.entry.ciphertext);

    let mut accounts = if is_native {
        let (sol_vault, _) = derive_sol_vault_pda(&program_id, pool_id);
        vec![
            AudrenAccountMeta::writable_signer(depositor),
            pool_meta,
            AudrenAccountMeta::writable(out_page),
            AudrenAccountMeta::writable(sol_vault),
            AudrenAccountMeta::writable(rent_vault),
            AudrenAccountMeta::readonly(sys_prog),
        ]
    } else {
        let (token_program, depositor_ata, vault_ata) =
            spl_accounts.ok_or(ClientError::InvalidProofInput(
                "SPL deposit requires (token_program, depositor_ata, vault_ata)",
            ))?;
        vec![
            AudrenAccountMeta::writable_signer(depositor),
            pool_meta,
            AudrenAccountMeta::writable(out_page),
            AudrenAccountMeta::readonly(Address::new_from_array(mint)),
            AudrenAccountMeta::writable(depositor_ata),
            AudrenAccountMeta::writable(vault_ata),
            AudrenAccountMeta::readonly(token_program),
            AudrenAccountMeta::writable(rent_vault),
            AudrenAccountMeta::readonly(sys_prog),
        ]
    };
    if !is_native && !extra_hook_accounts.is_empty() {
        accounts.extend_from_slice(extra_hook_accounts);
    }

    Ok((
        AudrenInstruction {
            program_id,
            accounts,
            data,
        },
        prepared,
    ))
}

/// Tag 3: `Transfer` — private multi-asset shielded transfer (1 input -> 2 outputs: `pay` + `change`).
#[allow(clippy::too_many_arguments)]
pub fn build_transfer<R: RngCore + CryptoRng>(
    program_id: Address,
    payer: Address,
    pool_id: u32,
    out_page_id: u64,
    input_page_ids: &[u64],
    ring: &[RingSlotWitness],
    input_note: &OwnedNote,
    secret_index: usize,
    recipient: &AudrenAddress,
    change_addr: &AudrenAddress,
    pay_amount: u64,
    auditor_pk: Option<Point>,
    pq_envelope: &[u8],
    rng: &mut R,
) -> Result<(AudrenInstruction, PreparedNote, PreparedNote), ClientError> {
    if pay_amount > input_note.amount {
        return Err(ClientError::InvalidProofInput("insufficient note balance"));
    }
    let chg_amount = input_note.amount - pay_amount;
    let m = m_for_input_pages(input_page_ids.len())
        .map_err(|_| ClientError::InvalidProofInput("input_page_ids must have 1, 2, or 4 pages"))?;
    let spend_x = input_note.spend_x.ok_or(ClientError::InvalidProofInput(
        "spend_x required to spend note",
    ))?;

    // Both outputs derive their own independent, unlinkable ECDH `asset_blinding` so recipient
    // and sender recover both notes purely from `EpochPage` without any local state.
    let note_pay = prepare_shielded_note(
        recipient,
        input_note.mint,
        pay_amount,
        true,
        None,
        true,
        [0u8; 7],
        rng,
    )?;
    let note_chg = prepare_shielded_note(
        change_addr,
        input_note.mint,
        chg_amount,
        true,
        None,
        true,
        [0u8; 7],
        rng,
    )?;

    let a_spend = note_pay.entry.asset_tag;
    let a_spend_blinding = note_pay.asset_blinding;
    let v_spend = compress(
        &(decompress(&note_pay.entry.commitment)? + decompress(&note_chg.entry.commitment)?),
    );
    // V_pay + V_chg = (pay + chg) * G_mint + (pay * a_pay + r_pay + chg * a_chg + r_chg) * H
    let v_spend_eff_blinding = Scalar::from(pay_amount) * note_pay.asset_blinding
        + note_pay.value_blinding
        + Scalar::from(chg_amount) * note_chg.asset_blinding
        + note_chg.value_blinding;

    let s_pay = Scalar::random(rng);
    let s_chg = Scalar::random(rng);
    let (range_bytes, c_pay, c_chg) = prove_range_u128(pay_amount, s_pay, chg_amount, s_chg)?;

    let pay_wire = encode_note_wire(&note_pay.entry);
    let chg_wire = encode_note_wire(&note_chg.entry);
    let mut notes_wire = Vec::with_capacity(2 * NOTE_WIRE_LEN);
    notes_wire.extend_from_slice(&pay_wire);
    notes_wire.extend_from_slice(&chg_wire);

    let ctx_hash = transcript_root(&[
        b"audren/v1/transfer",
        program_id.as_ref(),
        &pool_id.to_le_bytes(),
        &[m],
        &notes_wire,
        &c_pay,
        &c_chg,
        pq_envelope,
    ]);

    let triptych = prove_triptych(
        &TriptychWitness {
            m,
            input_page_ids,
            secret_index,
            ring,
            spend_x,
            a_note_blinding: input_note.asset_blinding,
            value: input_note.amount,
            v_note_blinding: input_note.value_blinding,
            a_spend,
            a_spend_blinding,
            v_spend,
            v_spend_eff_blinding,
            auditor_pk,
            ctx_hash,
        },
        rng,
    )?;

    let xbase2 = prove_cross_base_2(
        &note_pay.entry.asset_tag,
        &note_pay.entry.commitment,
        &c_pay,
        pay_amount,
        note_pay.value_blinding,
        s_pay,
        &note_chg.entry.asset_tag,
        &note_chg.entry.commitment,
        &c_chg,
        chg_amount,
        note_chg.value_blinding,
        s_chg,
        note_chg.asset_blinding - note_pay.asset_blinding,
        &ctx_hash,
        rng,
    )?;

    let aud_asset_opt = if let Some(k_aud) = auditor_pk {
        Some(prove_auditor_asset(
            &k_aud,
            &input_note.mint,
            &a_spend,
            a_spend_blinding,
            &ctx_hash,
            rng,
        )?)
    } else {
        None
    };

    let mut data = Vec::with_capacity(
        2 + notes_wire.len()
            + 64
            + triptych.proof.len()
            + xbase2.len()
            + range_bytes.len()
            + 192
            + pq_envelope.len(),
    );
    data.push(TAG_TRANSFER);
    data.push(m);
    data.extend_from_slice(&notes_wire);
    data.extend_from_slice(&c_pay);
    data.extend_from_slice(&c_chg);
    data.extend_from_slice(&triptych.proof);
    data.extend_from_slice(&xbase2);
    data.extend_from_slice(&range_bytes);
    if let Some(aud_bytes) = aud_asset_opt {
        data.extend_from_slice(&aud_bytes);
    }
    data.extend_from_slice(pq_envelope);

    let (pool_pda, _) = derive_pool_pda(&program_id, pool_id);
    let (out_page, _) = derive_epoch_page_pda(&program_id, pool_id, out_page_id);
    let (nullifier_pda, _) = derive_nullifier_pda(&program_id, pool_id, &triptych.nullifier);
    let out_lane = lane_of_page_id(out_page_id);
    let pool_meta = if out_lane == 0 {
        AudrenAccountMeta::writable(pool_pda)
    } else {
        AudrenAccountMeta::readonly(pool_pda)
    };
    let rent_vault = if out_lane == 0 {
        derive_page_rent_vault_pda(&program_id, pool_id).0
    } else {
        derive_lane_rent_vault_pda(&program_id, pool_id, out_lane).0
    };
    let zk_prog = Address::new_from_array(ZK_ELGAMAL_PROOF_PROGRAM_ID);
    let sys_prog = Address::new_from_array(SYSTEM_PROGRAM_ID);

    let mut accounts = vec![
        AudrenAccountMeta::writable_signer(payer),
        pool_meta,
        AudrenAccountMeta::writable(out_page),
        AudrenAccountMeta::writable(nullifier_pda),
        AudrenAccountMeta::writable(rent_vault),
        AudrenAccountMeta::readonly(zk_prog),
        AudrenAccountMeta::readonly(sys_prog),
    ];
    for &pid in input_page_ids {
        accounts.push(AudrenAccountMeta::readonly(
            derive_epoch_page_pda(&program_id, pool_id, pid).0,
        ));
    }

    Ok((
        AudrenInstruction {
            program_id,
            accounts,
            data,
        },
        note_pay,
        note_chg,
    ))
}

/// Tag 4: `Merge` — consolidate 2 same-asset shielded notes into 1 larger shielded note.
#[allow(clippy::too_many_arguments)]
pub fn build_merge<R: RngCore + CryptoRng>(
    program_id: Address,
    payer: Address,
    pool_id: u32,
    out_page_id: u64,
    input1_page_ids: &[u64],
    ring1: &[RingSlotWitness],
    note1: &OwnedNote,
    secret_index1: usize,
    input2_page_ids: &[u64],
    ring2: &[RingSlotWitness],
    note2: &OwnedNote,
    secret_index2: usize,
    owner_addr: &AudrenAddress,
    auditor_pk: Option<Point>,
    rng: &mut R,
) -> Result<(AudrenInstruction, PreparedNote), ClientError> {
    if note1.mint != note2.mint {
        return Err(ClientError::InvalidProofInput(
            "merge inputs must share same mint",
        ));
    }
    if (note1.nullifier.is_some() && note1.nullifier == note2.nullifier)
        || note1.stealth_pk == note2.stealth_pk
    {
        return Err(ClientError::InvalidProofInput(
            "cannot merge a note with itself",
        ));
    }
    let total_amount = note1
        .amount
        .checked_add(note2.amount)
        .ok_or(ClientError::InvalidProofInput("merge overflow"))?;
    let m1 = m_for_input_pages(input1_page_ids.len()).map_err(|_| {
        ClientError::InvalidProofInput("input1_page_ids must have 1, 2, or 4 pages")
    })?;
    let m2 = m_for_input_pages(input2_page_ids.len()).map_err(|_| {
        ClientError::InvalidProofInput("input2_page_ids must have 1, 2, or 4 pages")
    })?;
    if ((1usize << m1) + (1usize << m2)) > MAX_MERGE_RING_SLOTS {
        return Err(ClientError::InvalidProofInput(
            "combined merge ring width exceeds 128 slots (max 64+64)",
        ));
    }
    let spend_x1 = note1
        .spend_x
        .ok_or(ClientError::InvalidProofInput("spend_x1 required"))?;
    let spend_x2 = note2
        .spend_x
        .ok_or(ClientError::InvalidProofInput("spend_x2 required"))?;

    let note_out = prepare_shielded_note(
        owner_addr,
        note1.mint,
        total_amount,
        true,
        None,
        true,
        [0u8; 7],
        rng,
    )?;
    let a_out_blinding = note_out.asset_blinding;

    let a_out_pt = decompress(&note_out.entry.asset_tag)?;
    let r_in1 = Scalar::random(rng);
    let r_in2 = note_out.value_blinding - r_in1;
    let v_in1 = compress(&(Scalar::from(note1.amount) * a_out_pt + r_in1 * h_point()));
    let v_in2 = compress(&(Scalar::from(note2.amount) * a_out_pt + r_in2 * h_point()));
    let v_in1_eff = Scalar::from(note1.amount) * a_out_blinding + r_in1;
    let v_in2_eff = Scalar::from(note2.amount) * a_out_blinding + r_in2;

    let s_out = Scalar::random(rng);
    let (range64, c_out) = prove_range_u64(total_amount, s_out)?;
    let out_wire = encode_note_wire(&note_out.entry);

    let ctx_base = transcript_root(&[
        b"audren/v1/merge",
        program_id.as_ref(),
        &pool_id.to_le_bytes(),
        &[m1, m2],
        &out_wire,
        &v_in1,
        &v_in2,
        &c_out,
    ]);
    let ctx1 = transcript_root(&[b"leg1", &ctx_base]);
    let ctx2 = transcript_root(&[b"leg2", &ctx_base]);

    let t1 = prove_triptych(
        &TriptychWitness {
            m: m1,
            input_page_ids: input1_page_ids,
            secret_index: secret_index1,
            ring: ring1,
            spend_x: spend_x1,
            a_note_blinding: note1.asset_blinding,
            value: note1.amount,
            v_note_blinding: note1.value_blinding,
            a_spend: note_out.entry.asset_tag,
            a_spend_blinding: a_out_blinding,
            v_spend: v_in1,
            v_spend_eff_blinding: v_in1_eff,
            auditor_pk,
            ctx_hash: ctx1,
        },
        rng,
    )?;
    let t2 = prove_triptych(
        &TriptychWitness {
            m: m2,
            input_page_ids: input2_page_ids,
            secret_index: secret_index2,
            ring: ring2,
            spend_x: spend_x2,
            a_note_blinding: note2.asset_blinding,
            value: note2.amount,
            v_note_blinding: note2.value_blinding,
            a_spend: note_out.entry.asset_tag,
            a_spend_blinding: a_out_blinding,
            v_spend: v_in2,
            v_spend_eff_blinding: v_in2_eff,
            auditor_pk,
            ctx_hash: ctx2,
        },
        rng,
    )?;

    let xbase1 = prove_cross_base_1(
        &note_out.entry.asset_tag,
        &note_out.entry.commitment,
        &c_out,
        total_amount,
        note_out.value_blinding,
        s_out,
        &ctx_base,
        rng,
    )?;

    let aud_asset_opt = if let Some(k_aud) = auditor_pk {
        Some(prove_auditor_asset(
            &k_aud,
            &note1.mint,
            &note_out.entry.asset_tag,
            a_out_blinding,
            &ctx_base,
            rng,
        )?)
    } else {
        None
    };

    let mut data = Vec::with_capacity(
        3 + out_wire.len()
            + 96
            + t1.proof.len()
            + t2.proof.len()
            + xbase1.len()
            + range64.len()
            + 192,
    );
    data.push(TAG_MERGE);
    data.push(m1);
    data.push(m2);
    data.extend_from_slice(&out_wire);
    data.extend_from_slice(&v_in1);
    data.extend_from_slice(&v_in2);
    data.extend_from_slice(&c_out);
    data.extend_from_slice(&t1.proof);
    data.extend_from_slice(&t2.proof);
    data.extend_from_slice(&xbase1);
    data.extend_from_slice(&range64);
    if let Some(aud_bytes) = aud_asset_opt {
        data.extend_from_slice(&aud_bytes);
    }

    let (pool_pda, _) = derive_pool_pda(&program_id, pool_id);
    let (out_page, _) = derive_epoch_page_pda(&program_id, pool_id, out_page_id);
    let (n1_pda, _) = derive_nullifier_pda(&program_id, pool_id, &t1.nullifier);
    let (n2_pda, _) = derive_nullifier_pda(&program_id, pool_id, &t2.nullifier);
    let out_lane = lane_of_page_id(out_page_id);
    let pool_meta = if out_lane == 0 {
        AudrenAccountMeta::writable(pool_pda)
    } else {
        AudrenAccountMeta::readonly(pool_pda)
    };
    let rent_vault = if out_lane == 0 {
        derive_page_rent_vault_pda(&program_id, pool_id).0
    } else {
        derive_lane_rent_vault_pda(&program_id, pool_id, out_lane).0
    };
    let zk_prog = Address::new_from_array(ZK_ELGAMAL_PROOF_PROGRAM_ID);
    let sys_prog = Address::new_from_array(SYSTEM_PROGRAM_ID);

    let mut accounts = vec![
        AudrenAccountMeta::writable_signer(payer),
        pool_meta,
        AudrenAccountMeta::writable(out_page),
        AudrenAccountMeta::writable(n1_pda),
        AudrenAccountMeta::writable(n2_pda),
        AudrenAccountMeta::writable(rent_vault),
        AudrenAccountMeta::readonly(zk_prog),
        AudrenAccountMeta::readonly(sys_prog),
    ];
    for &pid in input1_page_ids {
        accounts.push(AudrenAccountMeta::readonly(
            derive_epoch_page_pda(&program_id, pool_id, pid).0,
        ));
    }
    for &pid in input2_page_ids {
        accounts.push(AudrenAccountMeta::readonly(
            derive_epoch_page_pda(&program_id, pool_id, pid).0,
        ));
    }

    Ok((
        AudrenInstruction {
            program_id,
            accounts,
            data,
        },
        note_out,
    ))
}

/// Parameters for a non-custodial 1-tx router-agnostic private swap (Jupiter, Orca, Raydium, etc.).
pub struct SwapViaRouterParams<'a> {
    pub program_id: Address,
    pub payer: Address,
    pub pool_id: u32,
    pub out_page_id: u64,
    pub shard_id: u8,
    pub input_page_ids: &'a [u64],
    pub ring: &'a [RingSlotWitness],
    pub input_note: &'a OwnedNote,
    pub secret_index: usize,
    pub mint_out: [u8; 32],
    pub token_program_in: Address,
    pub token_program_out: Address,
    pub amount_in: u64,
    pub min_amount_out: u64,
    pub allow_partial_refund: bool,
    pub recipient: &'a AudrenAddress,
    pub change_addr: &'a AudrenAddress,
    pub auditor_pk: Option<Point>,
    /// External DEX / aggregator program ID (e.g., Jupiter v6, Orca, Raydium, Meteora, Phoenix).
    pub router_program_id: Address,
    /// Index of `swap_escrow` PDA inside `router_accounts`.
    pub escrow_idx: u8,
    /// Index of `escrow_in` ATA (owned by `swap_escrow`) inside `router_accounts`.
    pub escrow_in_idx: u8,
    /// Index of `escrow_out` ATA (owned by `swap_escrow`) inside `router_accounts`.
    pub escrow_out_idx: u8,
    /// Raw external router instruction data (e.g., from Jupiter `/swap-instructions` or AMM builder).
    pub router_ix_data: &'a [u8],
    /// Remaining accounts required by the external router instruction.
    pub router_accounts: &'a [AudrenAccountMeta],
}

/// Tag 5: `SwapViaRouter` — 1-tx router-agnostic private swap matching `program/src/lib.rs` byte-for-byte.
pub fn build_swap_via_router<R: RngCore + CryptoRng>(
    params: &SwapViaRouterParams<'_>,
    rng: &mut R,
) -> Result<
    (
        AudrenInstruction,
        PreparedDynamicOutput,
        Option<PreparedNote>,
        Option<PreparedDynamicOutput>,
    ),
    ClientError,
> {
    if params.amount_in == 0 || params.amount_in > params.input_note.amount {
        return Err(ClientError::InvalidProofInput("invalid swap amount_in"));
    }
    if params.min_amount_out == 0 {
        return Err(ClientError::InvalidProofInput("min_amount_out must be > 0"));
    }
    let m = m_for_input_pages(params.input_page_ids.len())
        .map_err(|_| ClientError::InvalidProofInput("input_page_ids must have 1, 2, or 4 pages"))?;
    let spend_x = params
        .input_note
        .spend_x
        .ok_or(ClientError::InvalidProofInput("spend_x required"))?;

    let chg_amount = params.input_note.amount - params.amount_in;
    let has_change = chg_amount > 0;
    let flags = (u8::from(has_change)) | (u8::from(params.allow_partial_refund) << 1);

    let out_desc = prepare_dynamic_swap_output(
        params.recipient,
        params.mint_out,
        params.min_amount_out,
        [0u8; 7],
        rng,
    )?;
    let out_desc_wire = encode_dynamic_output_wire(&out_desc);

    let refund_desc_opt = if params.allow_partial_refund {
        Some(prepare_dynamic_swap_output(
            params.change_addr,
            params.input_note.mint,
            0,
            [0u8; 7],
            rng,
        )?)
    } else {
        None
    };
    let refund_wire_opt = refund_desc_opt.as_ref().map(encode_dynamic_output_wire);

    let g_in = asset_generator(&params.input_note.mint);
    let g_in_pt = decompress(&g_in)?;

    let (change_note_opt, c_chg_opt, range64_opt, v_spend, v_spend_eff_blinding) = if has_change {
        let note_chg = prepare_shielded_note(
            params.change_addr,
            params.input_note.mint,
            chg_amount,
            false,
            None,
            true,
            [0u8; 7],
            rng,
        )?;
        let s_chg = Scalar::random(rng);
        let (range64, c_chg) = prove_range_u64(chg_amount, s_chg)?;
        let v_spend_pt =
            Scalar::from(params.amount_in) * g_in_pt + decompress(&note_chg.entry.commitment)?;
        let chg_v_blind = note_chg.value_blinding;
        (
            Some((note_chg, s_chg)),
            Some(c_chg),
            Some(range64),
            compress(&v_spend_pt),
            chg_v_blind,
        )
    } else {
        (
            None,
            None,
            None,
            compress(&(Scalar::from(params.amount_in) * g_in_pt)),
            Scalar::ZERO,
        )
    };

    let chg_wire_opt = change_note_opt
        .as_ref()
        .map(|(n, _)| encode_note_wire(&n.entry));
    let chg_wire_slice: &[u8] = chg_wire_opt.as_ref().map(|b| b.as_slice()).unwrap_or(&[]);
    let c_chg_slice: &[u8] = c_chg_opt.as_ref().map(|b| b.as_slice()).unwrap_or(&[]);
    let refund_slice: &[u8] = refund_wire_opt
        .as_ref()
        .map(|b| b.as_slice())
        .unwrap_or(&[]);

    let ctx_hash = transcript_root(&[
        b"audren/v1/swap_router",
        params.program_id.as_ref(),
        &params.pool_id.to_le_bytes(),
        &[m, params.shard_id, flags],
        params.router_program_id.as_ref(),
        &params.input_note.mint,
        &params.mint_out,
        &params.amount_in.to_le_bytes(),
        &params.min_amount_out.to_le_bytes(),
        &out_desc_wire,
        chg_wire_slice,
        c_chg_slice,
        refund_slice,
    ]);

    let triptych = prove_triptych(
        &TriptychWitness {
            m,
            input_page_ids: params.input_page_ids,
            secret_index: params.secret_index,
            ring: params.ring,
            spend_x,
            a_note_blinding: params.input_note.asset_blinding,
            value: params.input_note.amount,
            v_note_blinding: params.input_note.value_blinding,
            a_spend: g_in,
            a_spend_blinding: Scalar::ZERO,
            v_spend,
            v_spend_eff_blinding,
            auditor_pk: params.auditor_pk,
            ctx_hash,
        },
        rng,
    )?;

    let mut data = Vec::with_capacity(
        25 + DYNAMIC_OUTPUT_WIRE_LEN + 1200 + triptych.proof.len() + params.router_ix_data.len(),
    );
    data.push(TAG_SWAP_VIA_ROUTER);
    data.push(m);
    data.push(params.shard_id);
    data.push(flags);
    data.extend_from_slice(&params.amount_in.to_le_bytes());
    data.extend_from_slice(&params.min_amount_out.to_le_bytes());
    data.push(params.escrow_idx);
    data.push(params.escrow_in_idx);
    data.push(params.escrow_out_idx);
    data.extend_from_slice(&(params.router_ix_data.len() as u16).to_le_bytes());
    data.extend_from_slice(&out_desc_wire);

    let ret_change = if let Some((note_chg, s_chg)) = change_note_opt {
        let c_chg = c_chg_opt.unwrap();
        let range64 = range64_opt.unwrap();
        let xbase1 = prove_cross_base_1(
            &note_chg.entry.asset_tag,
            &note_chg.entry.commitment,
            &c_chg,
            chg_amount,
            note_chg.value_blinding,
            s_chg,
            &ctx_hash,
            rng,
        )?;
        data.extend_from_slice(&encode_note_wire(&note_chg.entry));
        data.extend_from_slice(&c_chg);
        data.extend_from_slice(&xbase1);
        data.extend_from_slice(&range64);
        Some(note_chg)
    } else {
        None
    };

    if let Some(ref rw) = refund_wire_opt {
        data.extend_from_slice(rw);
    }
    data.extend_from_slice(&triptych.proof);
    data.extend_from_slice(params.router_ix_data);

    let (pool_pda, _) = derive_pool_pda(&params.program_id, params.pool_id);
    let (vault_auth, _) = derive_vault_auth_pda(&params.program_id, params.pool_id);
    let (swap_escrow, _) =
        derive_swap_escrow_pda(&params.program_id, params.pool_id, params.shard_id);
    let (out_page, _) =
        derive_epoch_page_pda(&params.program_id, params.pool_id, params.out_page_id);
    let (nullifier_pda, _) =
        derive_nullifier_pda(&params.program_id, params.pool_id, &triptych.nullifier);
    let out_lane = lane_of_page_id(params.out_page_id);
    let pool_meta = if out_lane == 0 {
        AudrenAccountMeta::writable(pool_pda)
    } else {
        AudrenAccountMeta::readonly(pool_pda)
    };
    let rent_vault = if out_lane == 0 {
        derive_page_rent_vault_pda(&params.program_id, params.pool_id).0
    } else {
        derive_lane_rent_vault_pda(&params.program_id, params.pool_id, out_lane).0
    };

    let mint_in_addr = Address::new_from_array(params.input_note.mint);
    let mint_out_addr = Address::new_from_array(params.mint_out);
    let vault_in = derive_ata(&vault_auth, &params.token_program_in, &mint_in_addr);
    let vault_out = derive_ata(&vault_auth, &params.token_program_out, &mint_out_addr);

    let zk_prog = Address::new_from_array(ZK_ELGAMAL_PROOF_PROGRAM_ID);
    let sys_prog = Address::new_from_array(SYSTEM_PROGRAM_ID);

    let mut accounts = vec![
        AudrenAccountMeta::writable_signer(params.payer),
        pool_meta,
        AudrenAccountMeta::writable(out_page),
        AudrenAccountMeta::writable(nullifier_pda),
        AudrenAccountMeta::writable(rent_vault),
        AudrenAccountMeta::readonly(zk_prog),
        AudrenAccountMeta::readonly(sys_prog),
        AudrenAccountMeta::readonly(vault_auth),
        AudrenAccountMeta::readonly(mint_in_addr),
        AudrenAccountMeta::writable(vault_in),
        AudrenAccountMeta::readonly(params.token_program_in),
        AudrenAccountMeta::readonly(mint_out_addr),
        AudrenAccountMeta::writable(vault_out),
        AudrenAccountMeta::readonly(params.token_program_out),
        AudrenAccountMeta::readonly(params.router_program_id),
    ];
    for &pid in params.input_page_ids {
        accounts.push(AudrenAccountMeta::readonly(
            derive_epoch_page_pda(&params.program_id, params.pool_id, pid).0,
        ));
    }
    for meta in params.router_accounts {
        let is_signer = if meta.pubkey == swap_escrow {
            false
        } else {
            meta.is_signer
        };
        accounts.push(AudrenAccountMeta {
            pubkey: meta.pubkey,
            is_signer,
            is_writable: meta.is_writable,
        });
    }

    Ok((
        AudrenInstruction {
            program_id: params.program_id,
            accounts,
            data,
        },
        out_desc,
        ret_change,
        refund_desc_opt,
    ))
}

/// Tag 6: `Withdraw` — unshield exact `amount` to any recipient address, with optional hidden change note.
#[allow(clippy::too_many_arguments)]
pub fn build_withdraw<R: RngCore + CryptoRng>(
    program_id: Address,
    payer: Address,
    pool_id: u32,
    out_page_id: u64,
    input_page_ids: &[u64],
    ring: &[RingSlotWitness],
    input_note: &OwnedNote,
    secret_index: usize,
    recipient_account: Address, // wallet for native SOL, recipient_ata for SPL/Token-2022
    change_addr: &AudrenAddress,
    amount: u64,
    spl_token_program: Option<Address>, // `None` for native SOL, `Some(token_program)` for SPL
    auditor_pk: Option<Point>,
    rng: &mut R,
) -> Result<(AudrenInstruction, Option<PreparedNote>), ClientError> {
    if amount == 0 || amount > input_note.amount {
        return Err(ClientError::InvalidProofInput("invalid withdraw amount"));
    }
    let m = m_for_input_pages(input_page_ids.len())
        .map_err(|_| ClientError::InvalidProofInput("input_page_ids must have 1, 2, or 4 pages"))?;
    let spend_x = input_note
        .spend_x
        .ok_or(ClientError::InvalidProofInput("spend_x required"))?;
    let is_native = input_note.mint == NATIVE_SOL_MINT;
    let chg_amount = input_note.amount - amount;
    let has_change = chg_amount > 0;

    let g_mint = asset_generator(&input_note.mint);
    let g_mint_pt = decompress(&g_mint)?;

    let (change_opt, c_chg_opt, range64_opt, v_spend, v_spend_eff_blinding) = if has_change {
        let note_chg = prepare_shielded_note(
            change_addr,
            input_note.mint,
            chg_amount,
            false,
            None,
            true,
            [0u8; 7],
            rng,
        )?;
        let s_chg = Scalar::random(rng);
        let (range64, c_chg) = prove_range_u64(chg_amount, s_chg)?;
        let v_spend_pt = Scalar::from(amount) * g_mint_pt + decompress(&note_chg.entry.commitment)?;
        let chg_v_blind = note_chg.value_blinding;
        (
            Some((note_chg, s_chg)),
            Some(c_chg),
            Some(range64),
            compress(&v_spend_pt),
            chg_v_blind,
        )
    } else {
        (
            None,
            None,
            None,
            compress(&(Scalar::from(amount) * g_mint_pt)),
            Scalar::ZERO,
        )
    };

    let chg_wire_opt = change_opt.as_ref().map(|(n, _)| encode_note_wire(&n.entry));
    let chg_wire_slice: &[u8] = chg_wire_opt.as_ref().map(|b| b.as_slice()).unwrap_or(&[]);
    let c_chg_slice: &[u8] = c_chg_opt.as_ref().map(|b| b.as_slice()).unwrap_or(&[]);

    let ctx_hash = transcript_root(&[
        b"audren/v1/withdraw",
        program_id.as_ref(),
        &pool_id.to_le_bytes(),
        &[m, u8::from(is_native), u8::from(has_change)],
        &input_note.mint,
        recipient_account.as_ref(),
        &amount.to_le_bytes(),
        chg_wire_slice,
        c_chg_slice,
    ]);

    let triptych = prove_triptych(
        &TriptychWitness {
            m,
            input_page_ids,
            secret_index,
            ring,
            spend_x,
            a_note_blinding: input_note.asset_blinding,
            value: input_note.amount,
            v_note_blinding: input_note.value_blinding,
            a_spend: g_mint,
            a_spend_blinding: Scalar::ZERO,
            v_spend,
            v_spend_eff_blinding,
            auditor_pk,
            ctx_hash,
        },
        rng,
    )?;

    let mut data = Vec::with_capacity(12 + 1025 + triptych.proof.len());
    data.push(TAG_WITHDRAW);
    data.push(m);
    data.push(u8::from(is_native));
    data.push(u8::from(has_change));
    data.extend_from_slice(&amount.to_le_bytes());

    let ret_change = if let Some((note_chg, s_chg)) = change_opt {
        let c_chg = c_chg_opt.unwrap();
        let range64 = range64_opt.unwrap();
        let xbase1 = prove_cross_base_1(
            &note_chg.entry.asset_tag,
            &note_chg.entry.commitment,
            &c_chg,
            chg_amount,
            note_chg.value_blinding,
            s_chg,
            &ctx_hash,
            rng,
        )?;
        data.extend_from_slice(&encode_note_wire(&note_chg.entry));
        data.extend_from_slice(&c_chg);
        data.extend_from_slice(&xbase1);
        data.extend_from_slice(&range64);
        Some(note_chg)
    } else {
        None
    };

    data.extend_from_slice(&triptych.proof);

    let (pool_pda, _) = derive_pool_pda(&program_id, pool_id);
    let (out_page, _) = derive_epoch_page_pda(&program_id, pool_id, out_page_id);
    let (nullifier_pda, _) = derive_nullifier_pda(&program_id, pool_id, &triptych.nullifier);
    let out_lane = lane_of_page_id(out_page_id);
    let pool_meta = if has_change && out_lane == 0 {
        AudrenAccountMeta::writable(pool_pda)
    } else {
        AudrenAccountMeta::readonly(pool_pda)
    };
    let rent_vault = if has_change && out_lane >= 1 {
        derive_lane_rent_vault_pda(&program_id, pool_id, out_lane).0
    } else {
        derive_page_rent_vault_pda(&program_id, pool_id).0
    };
    let zk_prog = Address::new_from_array(ZK_ELGAMAL_PROOF_PROGRAM_ID);
    let sys_prog = Address::new_from_array(SYSTEM_PROGRAM_ID);

    let mut accounts = vec![
        AudrenAccountMeta::writable_signer(payer),
        pool_meta,
        if has_change {
            AudrenAccountMeta::writable(out_page)
        } else {
            AudrenAccountMeta::readonly(out_page)
        },
        AudrenAccountMeta::writable(nullifier_pda),
        if has_change {
            AudrenAccountMeta::writable(rent_vault)
        } else {
            AudrenAccountMeta::readonly(rent_vault)
        },
        AudrenAccountMeta::readonly(zk_prog),
        AudrenAccountMeta::readonly(sys_prog),
    ];

    if is_native {
        let (sol_vault, _) = derive_sol_vault_pda(&program_id, pool_id);
        accounts.push(AudrenAccountMeta::writable(sol_vault));
        accounts.push(AudrenAccountMeta::writable(recipient_account));
    } else {
        let token_program = spl_token_program.ok_or(ClientError::InvalidProofInput(
            "SPL withdraw requires token_program",
        ))?;
        let (vault_auth, _) = derive_vault_auth_pda(&program_id, pool_id);
        let mint_addr = Address::new_from_array(input_note.mint);
        let vault_ata = derive_ata(&vault_auth, &token_program, &mint_addr);
        accounts.push(AudrenAccountMeta::readonly(vault_auth));
        accounts.push(AudrenAccountMeta::readonly(mint_addr));
        accounts.push(AudrenAccountMeta::writable(vault_ata));
        accounts.push(AudrenAccountMeta::writable(recipient_account));
        accounts.push(AudrenAccountMeta::readonly(token_program));
    }

    for &pid in input_page_ids {
        accounts.push(AudrenAccountMeta::readonly(
            derive_epoch_page_pda(&program_id, pool_id, pid).0,
        ));
    }

    Ok((
        AudrenInstruction {
            program_id,
            accounts,
            data,
        },
        ret_change,
    ))
}

/// Tag 7: `SetPaused` — emergency deposit/transfer/swap circuit breaker.
pub fn build_set_paused(
    program_id: Address,
    authority: Address,
    pool_id: u32,
    paused: bool,
) -> AudrenInstruction {
    let (pool_pda, _) = derive_pool_pda(&program_id, pool_id);
    AudrenInstruction {
        program_id,
        accounts: vec![
            AudrenAccountMeta::readonly_signer(authority),
            AudrenAccountMeta::writable(pool_pda),
        ],
        data: vec![TAG_SET_PAUSED, u8::from(paused)],
    }
}

/// Split an oversized Audren instruction (`Transfer`, `Merge`, `SwapViaRouter`, `Withdraw`) that
/// exceeds Solana Transaction v1's `4,096 B` single-tx limit into `<= 768 B` `WriteProofBuffer`
/// chunks plus a `2 B` `ExecBuffered` instruction that atomically executes the payload and
/// refunds 100% of the ephemeral `ProofBuffer` rent back to `payer`.
pub struct BufferedExecutionPlan {
    pub proof_buffer: Address,
    pub upload_chunks: Vec<AudrenInstruction>,
    pub execute: AudrenInstruction,
}

pub fn build_buffered_execution(
    inner: &AudrenInstruction,
    nonce: u64,
) -> Result<BufferedExecutionPlan, ClientError> {
    let (&inner_tag, payload) = inner
        .data
        .split_first()
        .ok_or(ClientError::InvalidProofInput("empty inner instruction"))?;
    if !matches!(
        inner_tag,
        TAG_TRANSFER | TAG_MERGE | TAG_SWAP_VIA_ROUTER | TAG_WITHDRAW
    ) {
        return Err(ClientError::InvalidProofInput(
            "only Transfer, Merge, SwapViaRouter, and Withdraw support ProofBuffer execution",
        ));
    }
    if payload.is_empty() || payload.len() > PROOF_BUFFER_MAX_PAYLOAD {
        return Err(ClientError::InvalidProofInput(
            "payload exceeds ProofBuffer 9,984 B cap",
        ));
    }
    let payer = inner
        .accounts
        .first()
        .ok_or(ClientError::InvalidProofInput("missing payer account"))?
        .pubkey;
    let (proof_buffer, _) = derive_proof_buffer_pda(&inner.program_id, &payer, nonce);
    let sys_prog = Address::new_from_array(SYSTEM_PROGRAM_ID);
    let total_len = payload.len() as u32;

    let mut upload_chunks = Vec::with_capacity(payload.len().div_ceil(PROOF_BUFFER_CHUNK_SIZE));
    for (chunk_idx, chunk) in payload.chunks(PROOF_BUFFER_CHUNK_SIZE).enumerate() {
        let mut data = Vec::with_capacity(14 + chunk.len());
        data.push(TAG_WRITE_PROOF_BUFFER);
        data.extend_from_slice(&nonce.to_le_bytes());
        data.extend_from_slice(&total_len.to_le_bytes());
        data.push(chunk_idx as u8);
        data.extend_from_slice(chunk);
        upload_chunks.push(AudrenInstruction {
            program_id: inner.program_id,
            accounts: vec![
                AudrenAccountMeta::writable_signer(payer),
                AudrenAccountMeta::writable(proof_buffer),
                AudrenAccountMeta::readonly(sys_prog),
            ],
            data,
        });
    }

    let mut exec_accounts = Vec::with_capacity(inner.accounts.len() + 1);
    exec_accounts.push(AudrenAccountMeta::writable(proof_buffer));
    exec_accounts.extend(inner.accounts.iter().cloned());
    let execute = AudrenInstruction {
        program_id: inner.program_id,
        accounts: exec_accounts,
        data: vec![TAG_EXEC_BUFFERED, inner_tag],
    };

    Ok(BufferedExecutionPlan {
        proof_buffer,
        upload_chunks,
        execute,
    })
}

/// Tag 10: `CloseProofBuffer` — reclaim 100% rent from an abandoned `ProofBuffer`.
pub fn build_close_proof_buffer(
    program_id: Address,
    payer: Address,
    nonce: u64,
) -> AudrenInstruction {
    let (proof_buffer, _) = derive_proof_buffer_pda(&program_id, &payer, nonce);
    AudrenInstruction {
        program_id,
        accounts: vec![
            AudrenAccountMeta::writable_signer(payer),
            AudrenAccountMeta::writable(proof_buffer),
        ],
        data: vec![TAG_CLOSE_PROOF_BUFFER],
    }
}

/// Tag 11: `InitLane` — enable parallel append lane `lane_id` (`1..15`) inside an existing pool.
pub fn build_init_lane(
    program_id: Address,
    authority: Address,
    pool_id: u32,
    lane_id: u8,
) -> Result<AudrenInstruction, ClientError> {
    let first_page_id =
        page_id_for_lane(lane_id, 0).ok_or(ClientError::InvalidProofInput("invalid lane_id"))?;
    if lane_id == 0 {
        return Err(ClientError::InvalidProofInput("lane_id must be 1..15"));
    }
    let (pool_pda, _) = derive_pool_pda(&program_id, pool_id);
    let (lane_pda, _) = derive_lane_pda(&program_id, pool_id, lane_id);
    let (page0_pda, _) = derive_epoch_page_pda(&program_id, pool_id, first_page_id);
    let (rent_vault, _) = derive_lane_rent_vault_pda(&program_id, pool_id, lane_id);
    let sys_prog = Address::new_from_array(SYSTEM_PROGRAM_ID);
    Ok(AudrenInstruction {
        program_id,
        accounts: vec![
            AudrenAccountMeta::writable_signer(authority),
            AudrenAccountMeta::writable(pool_pda),
            AudrenAccountMeta::writable(lane_pda),
            AudrenAccountMeta::writable(page0_pda),
            AudrenAccountMeta::writable(rent_vault),
            AudrenAccountMeta::readonly(sys_prog),
        ],
        data: vec![TAG_INIT_LANE, lane_id],
    })
}

/// Tag 12: `OpenLanePage` — permissionless rollover for parallel lane `1..15` with read-only `PoolState`.
pub fn build_open_lane_page(
    program_id: Address,
    payer: Address,
    pool_id: u32,
    current_page_id: u64,
) -> Result<AudrenInstruction, ClientError> {
    let lane_id = lane_of_page_id(current_page_id);
    if lane_id == 0 {
        return Err(ClientError::InvalidProofInput(
            "use build_open_page for lane 0",
        ));
    }
    let next_seq = seq_of_page_id(current_page_id)
        .checked_add(1)
        .ok_or(ClientError::InvalidProofInput("lane sequence overflow"))?;
    let next_page_id = page_id_for_lane(lane_id, next_seq)
        .ok_or(ClientError::InvalidProofInput("invalid lane page_id"))?;
    let (pool_pda, _) = derive_pool_pda(&program_id, pool_id);
    let (lane_pda, _) = derive_lane_pda(&program_id, pool_id, lane_id);
    let (cur_page, _) = derive_epoch_page_pda(&program_id, pool_id, current_page_id);
    let (next_page, _) = derive_epoch_page_pda(&program_id, pool_id, next_page_id);
    let (rent_vault, _) = derive_lane_rent_vault_pda(&program_id, pool_id, lane_id);
    let sys_prog = Address::new_from_array(SYSTEM_PROGRAM_ID);
    Ok(AudrenInstruction {
        program_id,
        accounts: vec![
            AudrenAccountMeta::writable_signer(payer),
            AudrenAccountMeta::readonly(pool_pda),
            AudrenAccountMeta::writable(lane_pda),
            AudrenAccountMeta::writable(cur_page),
            AudrenAccountMeta::writable(next_page),
            AudrenAccountMeta::writable(rent_vault),
            AudrenAccountMeta::readonly(sys_prog),
        ],
        data: vec![TAG_OPEN_LANE_PAGE, lane_id],
    })
}

/// Extract the `(S_1, S_2, M_1, M_2)` ElGamal auditor ciphertexts from an audited `Transfer`
/// (`Tag 3`) instruction payload, following the exact `audren-core` wire layout:
/// `tag(1) | m(1) | out1(226) | out2(226) | c_pay(32) | c_chg(32) | triptych_audited | cross_base_2(256) | range_u128(736) | auditor_asset(192) | [pq_envelope]`.
///
/// Returns `Ok((s1, s2, m1, m2))` ready to pass directly to [`crate::keys::AuditorKeypair::decrypt_spent_pubkey`]
/// and [`crate::keys::AuditorKeypair::decrypt_asset_generator`].
pub fn extract_transfer_auditor_ciphertexts(
    ix_data: &[u8],
) -> Result<([u8; 32], [u8; 32], [u8; 32], [u8; 32]), ClientError> {
    let trip_off = 2 + 2 * NOTE_WIRE_LEN + 64;
    if ix_data.len() < trip_off {
        return Err(ClientError::InvalidEncoding("Transfer payload too short"));
    }
    if ix_data[0] != TAG_TRANSFER {
        return Err(ClientError::InvalidEncoding("expected Transfer tag (3)"));
    }
    let m = ix_data[1];
    let trip_base_len = audren_core::instruction::triptych_proof_len(m, false)
        .map_err(|_| ClientError::InvalidEncoding("invalid Triptych m"))?;
    let trip_audited_len = audren_core::instruction::triptych_proof_len(m, true)
        .map_err(|_| ClientError::InvalidEncoding("invalid audited Triptych m"))?;
    let auditor_asset_off = trip_off
        + trip_audited_len
        + audren_core::instruction::CROSS_BASE_2_LEN
        + audren_core::instruction::RANGE_U128_PROOF_LEN;
    if ix_data.len() < auditor_asset_off + audren_core::instruction::AUDITOR_ASSET_PROOF_LEN {
        return Err(ClientError::InvalidEncoding(
            "Transfer payload does not contain audited Triptych + AuditorAssetProof",
        ));
    }
    let s1: [u8; 32] = ix_data[trip_off + trip_base_len..trip_off + trip_base_len + 32]
        .try_into()
        .map_err(|_| ClientError::InvalidEncoding("invalid S_1 slice"))?;
    let s2: [u8; 32] = ix_data[trip_off + trip_base_len + 32..trip_off + trip_base_len + 64]
        .try_into()
        .map_err(|_| ClientError::InvalidEncoding("invalid S_2 slice"))?;
    let m1: [u8; 32] = ix_data[auditor_asset_off..auditor_asset_off + 32]
        .try_into()
        .map_err(|_| ClientError::InvalidEncoding("invalid M_1 slice"))?;
    let m2: [u8; 32] = ix_data[auditor_asset_off + 32..auditor_asset_off + 64]
        .try_into()
        .map_err(|_| ClientError::InvalidEncoding("invalid M_2 slice"))?;
    Ok((s1, s2, m1, m2))
}
