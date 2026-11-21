//! Conformance test for the UniFFI `audren-ffi` layer (backing Swift & Kotlin SDKs)
//! against the canonical `spec/test-vectors.json` shared by all 4 languages.

use std::path::PathBuf;

use audren_ffi::*;
use serde_json::Value;

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn ffi_layer_matches_canonical_vectors_and_builds_proofs() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("spec/test-vectors.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();

    // 1. Keys & sub-accounts & FVK & Asset generators
    assert_eq!(program_id(), v["program_id"].as_str().unwrap());

    let alice_seed = from_hex(v["alice"]["seed_hex"].as_str().unwrap());
    let alice = derive_keys_from_seed(alice_seed.clone()).unwrap();
    assert_eq!(to_hex(&alice.spend_sk), v["alice"]["spend_sk_hex"].as_str().unwrap());
    assert_eq!(to_hex(&alice.spend_pk), v["alice"]["spend_pk_hex"].as_str().unwrap());
    assert_eq!(to_hex(&alice.view_sk), v["alice"]["view_sk_hex"].as_str().unwrap());
    assert_eq!(to_hex(&alice.view_pk), v["alice"]["view_pk_hex"].as_str().unwrap());
    assert_eq!(alice.address, v["alice"]["address"].as_str().unwrap());

    let parsed = parse_audren_address(alice.address.clone()).unwrap();
    assert_eq!(parsed.spend_pk, alice.spend_pk);
    assert_eq!(parsed.view_pk, alice.view_pk);
    assert_eq!(
        format_audren_address(parsed.spend_pk, parsed.view_pk).unwrap(),
        alice.address
    );

    let fvk = export_full_viewing_key(alice_seed.clone(), 0).unwrap();
    let expected_fvk: Value =
        serde_json::from_str(v["alice"]["full_viewing_key_json"].as_str().unwrap()).unwrap();
    assert_eq!(fvk.spend_pk_b58, expected_fvk["spend_pk_b58"].as_str().unwrap());
    assert_eq!(fvk.view_sk_b58, expected_fvk["view_sk_b58"].as_str().unwrap());
    assert_eq!(fvk.view_pk_b58, expected_fvk["view_pk_b58"].as_str().unwrap());

    for sub in v["alice_subaccounts"].as_array().unwrap() {
        let idx = sub["account_index"].as_u64().unwrap() as u32;
        let sk = derive_subaccount_keys(alice_seed.clone(), idx).unwrap();
        assert_eq!(to_hex(&sk.spend_sk), sub["spend_sk_hex"].as_str().unwrap());
        assert_eq!(sk.address, sub["address"].as_str().unwrap());
    }

    let native_sol_gen = asset_generator(vec![0u8; 32]).unwrap();
    assert_eq!(
        to_hex(&native_sol_gen),
        v["asset_generators"]["native_sol_gen_hex"].as_str().unwrap()
    );

    // 2. PDAs & Layout decoders
    let pid = program_id();
    let pdas = &v["pdas"];
    assert_eq!(derive_pool_pda(0, pid.clone()).unwrap().address, pdas["pool"]["address"].as_str().unwrap());
    assert_eq!(derive_epoch_page_pda(0, 0, pid.clone()).unwrap().address, pdas["epoch_page_0"]["address"].as_str().unwrap());
    assert_eq!(derive_epoch_page_pda(0, 1u64 << 56, pid.clone()).unwrap().address, pdas["epoch_page_lane1_seq0"]["address"].as_str().unwrap());
    assert_eq!(derive_sol_vault_pda(0, pid.clone()).unwrap().address, pdas["sol_vault"]["address"].as_str().unwrap());
    assert_eq!(derive_vault_auth_pda(0, pid.clone()).unwrap().address, pdas["vault_auth"]["address"].as_str().unwrap());
    assert_eq!(derive_page_rent_vault_pda(0, pid.clone()).unwrap().address, pdas["page_rent_vault"]["address"].as_str().unwrap());
    assert_eq!(derive_swap_escrow_pda(0, 0, pid.clone()).unwrap().address, pdas["swap_escrow_0"]["address"].as_str().unwrap());
    assert_eq!(derive_lane_pda(0, 1, pid.clone()).unwrap().address, pdas["lane_1"]["address"].as_str().unwrap());
    assert_eq!(derive_lane_rent_vault_pda(0, 1, pid.clone()).unwrap().address, pdas["lane_rent_vault_1"]["address"].as_str().unwrap());
    assert_eq!(
        derive_proof_buffer_pda(
            pdas["proof_buffer_authority"].as_str().unwrap().to_string(),
            pdas["proof_buffer_nonce"].as_u64().unwrap(),
            pid.clone(),
        )
        .unwrap()
        .address,
        pdas["proof_buffer"]["address"].as_str().unwrap()
    );

    let ps = decode_pool_state(from_hex(v["pool_state"]["raw_hex"].as_str().unwrap())).unwrap();
    assert_eq!(ps.total_notes, v["pool_state"]["total_notes"].as_u64().unwrap());
    assert_eq!(ps.active_lanes, v["pool_state"]["active_lanes"].as_u64().unwrap() as u8);

    // 3. Scanner & Note Decryption
    let slice_cfg = page_scan_data_slice();
    assert_eq!(slice_cfg.offset, v["epoch_page"]["scan_offset"].as_u64().unwrap() as u32);
    assert_eq!(slice_cfg.length, v["epoch_page"]["scan_length"].as_u64().unwrap() as u32);

    let page_bytes = from_hex(v["epoch_page"]["page_hex"].as_str().unwrap());
    let hdr = decode_epoch_page_header(page_bytes.clone()).unwrap();
    assert_eq!(hdr.count, v["epoch_page"]["count"].as_u64().unwrap() as u8);
    assert_eq!(hdr.created_slot, v["epoch_page"]["created_slot"].as_u64().unwrap());

    let matched = scan_page_dataslice(
        0,
        from_hex(v["epoch_page"]["scan_slice_hex"].as_str().unwrap()),
        alice.spend_pk.clone(),
        alice.view_sk.clone(),
    )
    .unwrap();
    assert_eq!(matched, vec![5u8]);

    let notes = scan_epoch_page(
        0,
        page_bytes.clone(),
        Some(alice.spend_sk.clone()),
        alice.spend_pk.clone(),
        alice.view_sk.clone(),
        pid.clone(),
    )
    .unwrap();
    assert_eq!(notes.len(), 1);
    let note = &notes[0];
    assert_eq!(note.slot_index, 5);
    assert_eq!(note.amount, v["epoch_page"]["alice_note"]["amount"].as_u64().unwrap());
    assert_eq!(
        to_hex(note.nullifier.as_ref().unwrap()),
        v["epoch_page"]["alice_note"]["nullifier_hex"].as_str().unwrap()
    );
    assert_eq!(
        note.nullifier_pda.as_deref().unwrap(),
        v["epoch_page"]["alice_note"]["nullifier_pda"].as_str().unwrap()
    );

    // Read-only FVK scan (spend_sk = None) + fault-isolation against corrupted decoy slot 0
    let mut poisoned_page = page_bytes.clone();
    poisoned_page[96..128].fill(0xff); // invalid Ristretto255 bytes in slot 0 ephemeral_pk
    let fvk_notes = scan_epoch_page(
        0,
        poisoned_page,
        None,
        alice.spend_pk.clone(),
        alice.view_sk.clone(),
        pid.clone(),
    )
    .unwrap();
    assert_eq!(fvk_notes.len(), 1);
    assert_eq!(fvk_notes[0].slot_index, 5);
    assert_eq!(fvk_notes[0].amount, note.amount);
    assert!(fvk_notes[0].nullifier.is_none());

    // Lane helpers & Token-2022 transfer fee ceiling math
    let lane1_seq7 = page_id_for_lane(1, 7).unwrap();
    assert_eq!(lane1_seq7, (1u64 << 56) | 7);
    assert_eq!(lane_of_page_id(lane1_seq7), 1);
    assert_eq!(seq_of_page_id(lane1_seq7), 7);
    assert_eq!(net_deposit_amount(1_000_000, 250, 10_000), 990_000);
    assert_eq!(net_deposit_amount(1_000_000, 250, 0), 1_000_000);

    // 4. Provers (exact wire lengths + account counts for Deposit, Transfer, Merge, Withdraw, ProofBuffer, Close, OpenPage, OpenLanePage)
    let payer = pdas["proof_buffer_authority"].as_str().unwrap().to_string();
    let bob_addr = v["bob"]["address"].as_str().unwrap().to_string();

    let dep = build_deposit_instruction(FfiDepositParams {
        program_id: pid.clone(),
        depositor: payer.clone(),
        pool_id: 0,
        active_page_id: 1,
        recipient_address: bob_addr.clone(),
        mint_32: vec![0u8; 32],
        gross_amount: 500_000,
        net_amount: 500_000,
        token_program: None,
        depositor_ata: None,
        vault_ata: None,
    })
    .unwrap();
    assert_eq!(dep.data[0], 2);
    assert_eq!(dep.data.len(), 139);
    assert_eq!(dep.accounts.len(), 6);

    let xfer = build_transfer_instruction(FfiTransferParams {
        program_id: pid.clone(),
        payer: payer.clone(),
        pool_id: 0,
        out_page_id: 1,
        input_page_ids: vec![0],
        input_pages_bytes: vec![page_bytes.clone()],
        input_note: note.clone(),
        secret_index: 5,
        recipient_address: bob_addr.clone(),
        change_address: alice.address.clone(),
        pay_amount: 900_000,
        auditor_pk_32: None,
    })
    .unwrap();
    assert_eq!(xfer.data[0], 3);
    assert_eq!(xfer.data.len(), 2_373);
    assert_eq!(xfer.accounts.len(), 8);

    // Merge two distinct Bob SOL notes (slots 0 & 2) + assert self-merge rejection!
    let bob = derive_keys_from_seed(from_hex(v["bob"]["seed_hex"].as_str().unwrap())).unwrap();
    let bob_sol: Vec<FfiOwnedNote> = scan_epoch_page(
        0,
        page_bytes.clone(),
        Some(bob.spend_sk.clone()),
        bob.spend_pk.clone(),
        bob.view_sk.clone(),
        pid.clone(),
    )
    .unwrap()
    .into_iter()
    .filter(|n| n.mint == vec![0u8; 32])
    .collect();
    assert!(bob_sol.len() >= 2);
    assert!(
        build_merge_instruction(FfiMergeParams {
            program_id: pid.clone(),
            payer: payer.clone(),
            pool_id: 0,
            out_page_id: 1,
            input1_page_ids: vec![0],
            input1_pages_bytes: vec![page_bytes.clone()],
            note1: note.clone(),
            secret_index1: 5,
            input2_page_ids: vec![0],
            input2_pages_bytes: vec![page_bytes.clone()],
            note2: note.clone(),
            secret_index2: 5,
            owner_address: alice.address.clone(),
            auditor_pk_32: None,
        })
        .is_err(),
        "self-merge must be rejected"
    );
    let mrg = build_merge_instruction(FfiMergeParams {
        program_id: pid.clone(),
        payer: payer.clone(),
        pool_id: 0,
        out_page_id: 1,
        input1_page_ids: vec![0],
        input1_pages_bytes: vec![page_bytes.clone()],
        note1: bob_sol[0].clone(),
        secret_index1: bob_sol[0].slot_index as u32,
        input2_page_ids: vec![0],
        input2_pages_bytes: vec![page_bytes.clone()],
        note2: bob_sol[1].clone(),
        secret_index2: bob_sol[1].slot_index as u32,
        owner_address: bob.address.clone(),
        auditor_pk_32: None,
    })
    .unwrap();
    assert_eq!(mrg.data[0], 4);
    assert_eq!(mrg.data.len(), 2_950);
    assert_eq!(mrg.accounts.len(), 10);

    let plan = build_buffered_execution_plan(42, xfer).unwrap();
    assert_eq!(plan.upload_chunks.len(), 4);
    assert_eq!(plan.execute_ix.data, vec![9, 3]);
    assert_eq!(plan.proof_buffer_pda, pdas["proof_buffer"]["address"].as_str().unwrap());

    let close_ix = build_close_proof_buffer_instruction(pid.clone(), payer.clone(), 42).unwrap();
    assert_eq!(close_ix.data, vec![10]);
    assert_eq!(close_ix.accounts.len(), 2);
    assert_eq!(close_ix.accounts[1].pubkey, plan.proof_buffer_pda);

    let open_ix = build_open_page_instruction(pid.clone(), payer.clone(), 0, 0).unwrap();
    assert_eq!(open_ix.data, vec![1]);
    assert_eq!(open_ix.accounts.len(), 6);

    let open_lane_ix =
        build_open_lane_page_instruction(pid.clone(), payer.clone(), 0, 1u64 << 56).unwrap();
    assert_eq!(open_lane_ix.data, vec![12, 1]);
    assert_eq!(open_lane_ix.accounts.len(), 7);
    assert!(!open_lane_ix.accounts[1].is_writable, "PoolState must stay read-only on Lane 1 rollover");

    let wd = build_withdraw_instruction(FfiWithdrawParams {
        program_id: pid.clone(),
        payer: payer.clone(),
        pool_id: 0,
        out_page_id: 1,
        input_page_ids: vec![0],
        input_pages_bytes: vec![page_bytes.clone()],
        input_note: note.clone(),
        secret_index: 5,
        recipient_account: payer.clone(),
        change_address: alice.address.clone(),
        amount: 1_000_000,
        spl_token_program: None,
        auditor_pk_32: None,
    })
    .unwrap();
    assert_eq!(wd.data[0], 6);
    assert_eq!(wd.data.len(), 1_966);
    assert_eq!(wd.accounts.len(), 10);

    let wd_full = build_withdraw_instruction(FfiWithdrawParams {
        program_id: pid.clone(),
        payer: payer.clone(),
        pool_id: 0,
        out_page_id: 1,
        input_page_ids: vec![0],
        input_pages_bytes: vec![page_bytes.clone()],
        input_note: note.clone(),
        secret_index: 5,
        recipient_account: payer,
        change_address: alice.address.clone(),
        amount: note.amount,
        spl_token_program: None,
        auditor_pk_32: None,
    })
    .unwrap();
    assert_eq!(wd_full.data[0], 6);
    assert_eq!(wd_full.data.len(), 941);
    assert!(!wd_full.accounts[1].is_writable, "Full withdraw must keep PoolState read-only");

    // 5. Selective Disclosure & Auditor Decrypt
    let mut sd = create_selective_disclosure_proof(note.clone());
    assert!(verify_selective_disclosure_proof(sd.clone()).unwrap());
    assert!(verify_selective_disclosure_on_page(sd.clone(), page_bytes.clone()).unwrap());
    sd.amount += 1;
    assert!(!verify_selective_disclosure_proof(sd.clone()).unwrap());
    assert!(!verify_selective_disclosure_on_page(sd, page_bytes).unwrap());

    let aud = derive_auditor_keypair(from_hex(v["auditor"]["auditor_seed_hex"].as_str().unwrap())).unwrap();
    assert_eq!(to_hex(&aud.auditor_pk), v["auditor"]["auditor_pk_hex"].as_str().unwrap());
    let dec = auditor_decrypt_note(
        aud.auditor_sk,
        from_hex(v["auditor"]["elgamal_s1_hex"].as_str().unwrap()),
        from_hex(v["auditor"]["elgamal_s2_hex"].as_str().unwrap()),
        from_hex(v["auditor"]["elgamal_m1_hex"].as_str().unwrap()),
        from_hex(v["auditor"]["elgamal_m2_hex"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(
        to_hex(&dec.spent_stealth_pk),
        v["auditor"]["expected_spent_pk_hex"].as_str().unwrap()
    );
    assert_eq!(
        to_hex(&dec.asset_generator),
        v["auditor"]["expected_asset_gen_hex"].as_str().unwrap()
    );

    // 6. Router & Relayer (including prepare_router_accounts + ATA derivation + signer stripping)
    assert_eq!(
        jupiter_cpi_excluded_dexes().join(","),
        v["jupiter_cpi_excluded_dexes"].as_str().unwrap()
    );
    assert_eq!(default_relay_url(), "https://relay.audren.xyz");

    let classic_tp = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string();
    let wsol_mint = v["asset_generators"]["wsol_mint_b58"].as_str().unwrap().to_string();
    let usdc_mint = v["asset_generators"]["usdc_mint_b58"].as_str().unwrap().to_string();
    let escrow0 = pdas["swap_escrow_0"]["address"].as_str().unwrap().to_string();
    let escrow_in_ata =
        derive_associated_token_address(escrow0.clone(), wsol_mint.clone(), classic_tp.clone()).unwrap();
    let escrow_out_ata =
        derive_associated_token_address(escrow0.clone(), usdc_mint.clone(), classic_tp.clone()).unwrap();
    let prep = prepare_router_accounts(
        0,
        0,
        wsol_mint,
        usdc_mint,
        classic_tp.clone(),
        classic_tp,
        vec![
            FfiAccountMeta { pubkey: escrow_in_ata.clone(), is_signer: false, is_writable: true },
            FfiAccountMeta { pubkey: escrow0.clone(), is_signer: true, is_writable: true },
            FfiAccountMeta { pubkey: escrow_out_ata.clone(), is_signer: false, is_writable: true },
        ],
        pid,
    )
    .unwrap();
    assert_eq!(prep.escrow_pda, escrow0);
    assert_eq!(prep.escrow_in_ata, escrow_in_ata);
    assert_eq!(prep.escrow_out_ata, escrow_out_ata);
    assert_eq!((prep.escrow_idx, prep.escrow_in_idx, prep.escrow_out_idx), (1, 0, 2));
    assert!(!prep.accounts[1].is_signer, "swap_escrow signer bit must be stripped");
}
