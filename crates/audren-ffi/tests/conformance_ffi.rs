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

    // 4. Provers (Deposit, Transfer m=5, Withdraw, ProofBuffer)
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
    assert!(xfer.data.len() > 2_000);

    let plan = build_buffered_execution_plan(42, xfer).unwrap();
    assert!(!plan.upload_chunks.is_empty());

    let wd = build_withdraw_instruction(FfiWithdrawParams {
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
        amount: 1_000_000,
        spl_token_program: None,
        auditor_pk_32: None,
    })
    .unwrap();
    assert_eq!(wd.data[0], 6);

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

    // 6. Router & Relayer
    assert_eq!(
        jupiter_cpi_excluded_dexes().join(","),
        v["jupiter_cpi_excluded_dexes"].as_str().unwrap()
    );
    assert_eq!(default_relay_url(), "https://relay.audren.xyz");
}
