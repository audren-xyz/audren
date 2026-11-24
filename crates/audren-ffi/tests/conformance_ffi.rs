//! Verifies `audren-ffi` UniFFI surface matches `spec/test-vectors.json` byte-for-byte.

use std::path::PathBuf;

use audren_ffi::{
    build_exec_via_escrow_ix, build_init_pool_ix, build_init_root_history_ix, build_open_page_ix,
    build_transact_ix, build_update_pool_ix, canonical_program_id, check_memo_view_tag,
    compute_exec_ctx_hash_ffi, compute_page_rollovers_ffi, compute_transact_ctx_hash_ffi,
    decode_audren_address, decode_global_root_history_account, decode_pool_state_account,
    decrypt_and_verify_memo_entry, derive_asset_id_bytes, derive_defi_session_keypair,
    derive_escrow_pda, derive_keys_from_seed, derive_lane_pda, derive_lane_rent_pda,
    derive_memo_pda, derive_nf_page_pda, derive_nullifier_pda, derive_pool_pda, derive_roots_pda,
    derive_subaccount_keys, derive_subroot_pda, derive_subtree_pda, derive_unwrap_pda,
    derive_vault_auth_pda, deterministic_note_rent_fee_ffi, encrypt_note_memo,
    export_full_viewing_key, plan_auto_open_pages,
    prepare_dynamic_swap_memo, protocol_version, prove_joinsplit_witness_bytes,
    recommended_cu_limit_deposit, recommended_cu_limit_exec_via_escrow,
    recommended_cu_limit_open_page, recommended_cu_limit_transact, select_root_snapshot_for_notes,
    verify_selective_disclosure_proof, FfiAccountMeta, FfiExecCtxHashParams,
    FfiExecViaEscrowParams, FfiNoteCoord, FfiOpenPageSpec, FfiSelectiveDisclosureProof,
    FfiTransactCtxHashParams, FfiTransactParams, FfiUpdatePoolAction,
};
use serde_json::Value;

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn ffi_conformance_matches_spec_vectors() {
    let spec_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/test-vectors.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(spec_path).unwrap()).unwrap();

    assert_eq!(protocol_version(), v["protocol_version"].as_u64().unwrap() as u8);
    let pid = v["program_id"].as_str().unwrap().to_string();
    assert_eq!(canonical_program_id(), pid);

    // 1. Keys, subaccount, FVK, BIP-350 Bech32m aud1 address, and DeFi sessions
    let alice_seed = from_hex(v["alice"]["seed_hex"].as_str().unwrap());
    let alice = derive_keys_from_seed(alice_seed.clone()).unwrap();
    assert_eq!(to_hex(&alice.spend_sk), v["alice"]["spend_sk_hex"]);
    assert_eq!(to_hex(&alice.spend_pk), v["alice"]["spend_pk_hex"]);
    assert_eq!(to_hex(&alice.nk), v["alice"]["nk_hex"]);
    assert_eq!(to_hex(&alice.view_sk), v["alice"]["view_sk_hex"]);
    assert_eq!(to_hex(&alice.view_pk), v["alice"]["view_pk_hex"]);
    assert_eq!(alice.address, v["alice"]["address"].as_str().unwrap());
    assert_eq!(alice.address.len(), 114);

    let decoded_addr = decode_audren_address(alice.address.clone()).unwrap();
    assert_eq!(to_hex(&decoded_addr[0]), v["alice"]["spend_pk_hex"]);
    assert_eq!(to_hex(&decoded_addr[1]), v["alice"]["view_pk_hex"]);
    // Uppercase Bech32m succeeds, mixed-case & typo fail
    assert!(decode_audren_address(alice.address.to_ascii_uppercase()).is_ok());
    let mut mixed = alice.address.clone();
    let ch0 = mixed.remove(0).to_ascii_uppercase();
    mixed.insert(0, ch0);
    assert!(decode_audren_address(mixed).is_err());

    let sub1 = derive_subaccount_keys(alice_seed.clone(), 1).unwrap();
    assert_eq!(sub1.address, v["alice_sub1"]["address"].as_str().unwrap());

    let fvk = export_full_viewing_key(alice_seed.clone()).unwrap();
    assert_eq!(to_hex(&fvk.nk), v["alice"]["nk_hex"]);

    let s0 = derive_defi_session_keypair(alice_seed.clone(), 0).unwrap();
    assert_eq!(s0.pubkey_b58, v["defi_session_0"]["pubkey_b58"].as_str().unwrap());
    let s3 = derive_defi_session_keypair(alice_seed, 3).unwrap();
    assert_eq!(s3.pubkey_b58, v["defi_session_3"]["pubkey_b58"].as_str().unwrap());

    // 2. Asset IDs (WSOL + USDC)
    let wsol_bytes = from_hex(v["memo"]["mint_hex"].as_str().unwrap());
    assert_eq!(
        to_hex(&derive_asset_id_bytes(wsol_bytes.clone()).unwrap()),
        v["asset_ids"]["wsol_asset_id_hex"]
    );
    let usdc_bytes = bs58::decode(v["asset_ids"]["usdc_mint_b58"].as_str().unwrap())
        .into_vec()
        .unwrap();
    assert_eq!(
        to_hex(&derive_asset_id_bytes(usdc_bytes).unwrap()),
        v["asset_ids"]["usdc_asset_id_hex"]
    );

    // 3. All 12 canonical v1 PDAs
    let p = &v["pdas"];
    let pool_id = p["pool_id"].as_u64().unwrap() as u32;
    let lane_id = p["lane_id"].as_u64().unwrap() as u8;
    let page_seq = p["page_seq"].as_u64().unwrap();
    let shard_id = p["shard_id"].as_u64().unwrap() as u8;
    let nf = from_hex(p["nullifier_hex"].as_str().unwrap());

    assert_eq!(derive_pool_pda(pid.clone(), pool_id).unwrap().address, p["pool"]["address"].as_str().unwrap());
    assert_eq!(derive_vault_auth_pda(pid.clone(), pool_id).unwrap().address, p["vault_auth"]["address"].as_str().unwrap());
    assert_eq!(derive_lane_pda(pid.clone(), pool_id, lane_id).unwrap().address, p["lane"]["address"].as_str().unwrap());
    assert_eq!(derive_lane_rent_pda(pid.clone(), pool_id, lane_id).unwrap().address, p["lane_rent"]["address"].as_str().unwrap());
    assert_eq!(derive_subtree_pda(pid.clone(), pool_id, lane_id, page_seq).unwrap().address, p["subtree"]["address"].as_str().unwrap());
    assert_eq!(derive_subroot_pda(pid.clone(), pool_id, lane_id, page_seq).unwrap().address, p["subroot"]["address"].as_str().unwrap());
    assert_eq!(derive_memo_pda(pid.clone(), pool_id, lane_id, page_seq).unwrap().address, p["memo"]["address"].as_str().unwrap());
    assert_eq!(derive_nf_page_pda(pid.clone(), pool_id, lane_id, page_seq).unwrap().address, p["nf_page"]["address"].as_str().unwrap());
    let roots_pda = derive_roots_pda(pid.clone(), pool_id).unwrap();
    assert_eq!(roots_pda.address, p["roots"]["address"].as_str().unwrap());
    assert_eq!(roots_pda.bump, p["roots"]["bump"].as_u64().unwrap() as u8);
    assert_eq!(derive_nullifier_pda(pid.clone(), pool_id, nf.clone()).unwrap().address, p["nullifier"]["address"].as_str().unwrap());
    assert_eq!(derive_escrow_pda(pid.clone(), pool_id, shard_id).unwrap().address, p["escrow"]["address"].as_str().unwrap());
    assert_eq!(derive_unwrap_pda(pid.clone(), pool_id, nf).unwrap().address, p["unwrap"]["address"].as_str().unwrap());

    // 4. Versioned 106 B Memo encrypt + decrypt + payment_id + AAD + dynamic swap memo + low-order X25519
    let payment_id = from_hex(v["memo"]["payment_id_hex"].as_str().unwrap());
    let enc = encrypt_note_memo(
        alice.spend_pk.clone(),
        alice.view_pk.clone(),
        from_hex(v["memo"]["eph_secret_hex"].as_str().unwrap()),
        v["memo"]["amount"].as_u64().unwrap(),
        wsol_bytes.clone(),
        Some(payment_id.clone()),
    )
    .unwrap();
    assert_eq!(to_hex(&enc.memo_106), v["memo"]["memo_106_hex"]);
    assert_eq!(to_hex(&enc.commitment), v["memo"]["commitment_hex"]);

    assert!(check_memo_view_tag(fvk.clone(), enc.memo_106[0..2].to_vec(), enc.memo_106[2..34].to_vec()).unwrap());
    let dec = decrypt_and_verify_memo_entry(fvk.clone(), enc.memo_106.clone(), enc.commitment.clone())
        .unwrap()
        .expect("decrypt memo");
    assert_eq!(dec.amount, v["memo"]["amount"].as_u64().unwrap());
    assert_eq!(dec.memo_version, 1);
    assert_eq!(dec.memo_flags, 0);
    assert_eq!(dec.payment_id, payment_id);
    assert!(!dec.is_dynamic);

    // Low-order X25519 points rejected
    for key_field in ["all_zero_epk_hex", "order_8_epk_hex"] {
        let low_pk = from_hex(v["low_order_x25519"][key_field].as_str().unwrap());
        assert!(encrypt_note_memo(alice.spend_pk.clone(), low_pk.clone(), vec![0x33u8; 32], 1_000, wsol_bytes.clone(), None).is_err());
        assert!(prepare_dynamic_swap_memo(low_pk.clone(), vec![0x33u8; 32]).is_err());
        assert!(!check_memo_view_tag(fvk.clone(), vec![0, 0], low_pk).unwrap());
    }

    let bob_seed = from_hex(v["bob"]["seed_hex"].as_str().unwrap());
    let bob_fvk = export_full_viewing_key(bob_seed).unwrap();
    let bob_vpk = from_hex(v["bob"]["view_pk_hex"].as_str().unwrap());
    let dyn_m = prepare_dynamic_swap_memo(bob_vpk, from_hex(v["memo"]["dyn_eph_secret_hex"].as_str().unwrap())).unwrap();
    assert_eq!(to_hex(&dyn_m.tweak), v["memo"]["dyn_tweak_hex"]);
    assert_eq!(to_hex(&dyn_m.blinding), v["memo"]["dyn_blinding_hex"]);
    assert_eq!(to_hex(&dyn_m.dyn_head_34), v["memo"]["dyn_head_34_hex"]);
    assert_eq!(to_hex(&dyn_m.dyn_mask_72), v["memo"]["dyn_mask_72_hex"]);
    let dyn_dec = decrypt_and_verify_memo_entry(
        bob_fvk,
        from_hex(v["memo"]["dyn_stamped_memo_106_hex"].as_str().unwrap()),
        from_hex(v["memo"]["dyn_commitment_hex"].as_str().unwrap()),
    )
    .unwrap()
    .expect("decrypt dynamic swap memo");
    assert!(dyn_dec.is_dynamic);
    assert_eq!(dyn_dec.amount, v["memo"]["dyn_amount"].as_u64().unwrap());

    // 5. Mode 1 SelectiveDisclosureProof
    let sd = &v["selective_disclosure"];
    let to_bytes = |arr: &Value| -> Vec<u8> {
        arr.as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap() as u8)
            .collect()
    };
    let sd_proof = FfiSelectiveDisclosureProof {
        pool_id: sd["pool_id"].as_u64().unwrap() as u32,
        lane_id: sd["lane_id"].as_u64().unwrap() as u8,
        leaf_index: sd["leaf_index"].as_u64().unwrap(),
        stealth_owner: to_bytes(&sd["stealth_owner"]),
        mint: to_bytes(&sd["mint"]),
        amount: sd["amount"].as_u64().unwrap(),
        blinding: to_bytes(&sd["blinding"]),
        commitment: to_bytes(&sd["commitment"]),
    };
    assert!(verify_selective_disclosure_proof(sd_proof, enc.commitment).unwrap());

    // 6. Context hashes (with vk_id = 0 bound)
    let ctx_priv = compute_transact_ctx_hash_ffi(FfiTransactCtxHashParams {
        program_id: pid.clone(),
        pool_id: 0,
        vk_id: 0,
        out_lane_id: 2,
        output_mask: 0b111,
        asset_mode: 0,
        unwrap_wsol: false,
        recipient: None,
        relayer_fee_recipient: None,
        public_asset_id: vec![0u8; 32],
        public_amount_out: 0,
        relayer_fee_amount: 0,
        memos_bytes: enc.memo_106.clone(),
    })
    .unwrap();
    assert_eq!(to_hex(&ctx_priv), v["ctx_hashes"]["transact_private_ctx_hash_hex"]);

    let ctx_exec = compute_exec_ctx_hash_ffi(FfiExecCtxHashParams {
        program_id: pid.clone(),
        pool_id: 0,
        vk_id: 0,
        out_lane_id: 1,
        escrow_shard: 3,
        change_mask: 0b01,
        fee_on_output: true,
        asset_in: from_hex(v["asset_ids"]["usdc_asset_id_hex"].as_str().unwrap()),
        amount_in: 50_000_000,
        relayer_fee_amount: 2_000_000,
        relayer_fee_recipient: Some(s3.pubkey_b58.clone()),
        asset_out: from_hex(v["asset_ids"]["wsol_asset_id_hex"].as_str().unwrap()),
        min_amount_out: 400_000_000,
        router_prog: bs58::encode([0x77u8; 32]).into_string(),
        router_accounts: vec![
            FfiAccountMeta {
                pubkey_b58: bs58::encode([0x88u8; 32]).into_string(),
                is_signer: false,
                is_writable: true,
            },
            FfiAccountMeta {
                pubkey_b58: bs58::encode([0x99u8; 32]).into_string(),
                is_signer: false,
                is_writable: false,
            },
        ],
        extra_writable_pubkeys: vec![],
        out_stealth_owner: enc.stealth_owner,
        out_blinding: enc.blinding.clone(),
        dyn_memo_head: dyn_m.dyn_head_34,
        dyn_mask_72: dyn_m.dyn_mask_72,
        router_ix_data: vec![1, 2, 3, 4],
        change_memos: enc.memo_106,
    })
    .unwrap();
    assert_eq!(to_hex(&ctx_exec), v["ctx_hashes"]["exec_fee_on_output_ctx_hash_hex"]);

    // 7. Account decoders + rollover planner + InitPool/InitRootHistory/UpdatePool builders
    let ps = decode_pool_state_account(from_hex(v["pool_state"]["raw_hex"].as_str().unwrap())).unwrap();
    assert_eq!(ps.active_lanes, 4);
    assert_eq!(ps.root_epoch_interval, v["pool_state"]["root_epoch_interval"].as_u64().unwrap());
    assert_eq!(ps.pending_authority_b58, v["pool_state"]["pending_authority_b58"].as_str().unwrap());

    let rh = decode_global_root_history_account(
        from_hex(v["root_history"]["raw_hex"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(rh.pool_id, 0);
    assert_eq!(rh.bump, 254);
    assert_eq!(rh.slot_count, 1);
    assert_eq!(rh.epoch_count, 1);
    assert_eq!(rh.epoch_interval, 32);
    assert_eq!(to_hex(&rh.latest_super_root), v["root_history"]["latest_super_root_hex"]);
    assert_eq!(to_hex(&rh.stable_super_root), v["root_history"]["stable_super_root_hex"]);
    assert_eq!(rh.latest_lane_counts[2], 6);
    assert_eq!(rh.stable_lane_counts[2], 6);

    assert_eq!(compute_page_rollovers_ffi(95, 2, 0, 1).next_memo_seq, Some(1));
    let init_pool_ix = build_init_pool_ix(pid.clone(), s0.pubkey_b58.clone(), 0, 32, 1_500_000, 500_000).unwrap();
    assert_eq!(init_pool_ix.accounts.len(), 4);
    assert_eq!(init_pool_ix.data.len(), 29);
    let init_rh_ix = build_init_root_history_ix(pid.clone(), s0.pubkey_b58.clone(), 0, 32, 4).unwrap();
    assert_eq!(init_rh_ix.accounts.len(), 8);
    assert_eq!(init_rh_ix.data.len(), 13);
    assert_eq!(init_rh_ix.data[0], 4);
    let up_params_ix = build_update_pool_ix(
        pid.clone(),
        s0.pubkey_b58.clone(),
        0,
        FfiUpdatePoolAction::UpdateParams {
            note_rent_fee: 1_500_000,
            nf_rent_fee: 500_000,
        },
    )
    .unwrap();
    assert_eq!(up_params_ix.data.len(), 22);
    let up_ix = build_update_pool_ix(pid.clone(), s0.pubkey_b58.clone(), 0, FfiUpdatePoolAction::RenounceAuthority).unwrap();
    assert_eq!(up_ix.data, vec![8, 0, 0, 0, 0, 3]);

    // 8. Live BN254 Groth16 proving via `prove_joinsplit_witness_bytes`
    let zero_hashes = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0532fd436e19c70e51209694d9c215250937921b8b79060488c1206db73e9946",
        "1ea8dbbca1ca3a574b1b871aad1e8bc47571c7e11a99a6fb25f3f19d4bfad32c",
        "1b98ec5a992cd3688e655aef8674386f4e84f0a442eaab4840427e359c214dd2",
        "0fd83a3939005974d559c13c652a31942ffd61cab9a038e04239af96cafaee14",
        "11eb54967ae25ce42205223461cda9dbb1a1811db38b71e404d1fd94c9627777",
        "1c682a99981cf10a215d2788721e0ca060ddc0932cbb04c903eee3bd899dcfc0",
        "2b3de1ae8e72d64a5cb03934061e3fd03789273f370e32d576ae54b4cbeca719",
        "1b64ed0dc55f80f1f3da256b451baf16110fc268311a13fe903f87945b734861",
        "06efb4c4a55b0225fd1088d357b2432f422b0593015c57980e373ecef9029c72",
        "262138dff44f5352d2d7ec48461c771444a6c00c761a3263735d0a99143a51f1",
        "07ea118d86ace14a8eaa26fc18b36fefe7d5f5b00e0eb9ebfd1c88f37131c178",
        "0c2a4af81a2cd78159ce2f3d7ee05367fc5b3c3e1becea2a86d1e66dd27ffb7f",
        "1a953a710c22f79c369c976fc9981ffdbfe236695297fec65886e645e6fa2884",
        "16b0c5e286286eb6c4774ad6292b4f0bdc5b36cb7890b27544268892ae255e0d",
        "2dd7186449cc82702fb8f2d7fa86e0095263f8afb521e1976f499e67a0d7cbb8",
        "151399c724e17408a7a43cdadba2fc000da9339c56e4d49c6cdee6c4356fbc68",
        "1905d56dc6be6157b64b80d21a207b96e862aea4b68f4674ce4c1b7db4a8bc2e",
        "16d33ae1e54afb1453fc544206899ddf3e1a5bdc7f6d8993550aa6876a380319",
        "16e195c570f224cc86219527096fa55516cc9ee1b96764dd263db0884983fdaf",
    ];
    let wsol_asset = from_hex(v["asset_ids"]["wsol_asset_id_hex"].as_str().unwrap());
    let u64_be32 = |x: u64| -> Vec<u8> {
        let mut b = vec![0u8; 32];
        b[24..32].copy_from_slice(&x.to_be_bytes());
        b
    };
    let mut w = Vec::with_capacity(4_611);
    w.extend_from_slice(&from_hex(v["groth16"]["super_root_hex"].as_str().unwrap()));
    w.extend_from_slice(&wsol_asset);
    w.extend_from_slice(&[0u8; 32]);
    w.extend_from_slice(&0u64.to_le_bytes());
    w.extend_from_slice(&0u64.to_le_bytes());
    w.extend_from_slice(&ctx_priv);
    w.push(1); // omit_nf1 = true

    // Input 0: real note at lane 2, leaf 5
    w.extend_from_slice(&alice.spend_sk);
    w.extend_from_slice(&enc.tweak);
    w.extend_from_slice(&wsol_asset);
    w.extend_from_slice(&v["memo"]["amount"].as_u64().unwrap().to_le_bytes());
    w.extend_from_slice(&enc.blinding);
    w.push(0); // is_dummy = false
    let mut pos = [0u8; 20];
    pos[0] = 1;
    pos[1] = 1;
    pos[18] = 2;
    w.extend_from_slice(&pos);
    for zh in zero_hashes {
        let z = from_hex(zh);
        for _ in 0..3 {
            w.extend_from_slice(&z);
        }
    }

    // Input 1: dummy
    w.extend_from_slice(&alice.spend_sk);
    w.extend_from_slice(&[0u8; 32]);
    w.extend_from_slice(&wsol_asset);
    w.extend_from_slice(&0u64.to_le_bytes());
    w.extend_from_slice(&u64_be32(0x5555));
    w.push(1); // is_dummy = true
    w.extend_from_slice(&[0u8; 20 + 20 * 3 * 32]);

    // Outputs 0, 1, 2
    w.extend_from_slice(&from_hex(v["groth16"]["out0_stealth_owner_hex"].as_str().unwrap()));
    w.extend_from_slice(&wsol_asset);
    w.extend_from_slice(&1_000_000u64.to_le_bytes());
    w.extend_from_slice(&u64_be32(0x201));

    w.extend_from_slice(&from_hex(v["groth16"]["out1_stealth_owner_hex"].as_str().unwrap()));
    w.extend_from_slice(&wsol_asset);
    w.extend_from_slice(&500_000u64.to_le_bytes());
    w.extend_from_slice(&u64_be32(0x202));

    w.extend_from_slice(&[0u8; 32]);
    w.extend_from_slice(&wsol_asset);
    w.extend_from_slice(&0u64.to_le_bytes());
    w.extend_from_slice(&u64_be32(0x203));
    assert_eq!(w.len(), 4_611);

    let proved = prove_joinsplit_witness_bytes(w, vec![0x99u8; 32]).unwrap();
    assert_eq!(to_hex(&proved.nf0), v["groth16"]["nf0_hex"]);
    assert_eq!(to_hex(&proved.nf1), v["groth16"]["nf1_hex"]);
    assert_eq!(to_hex(&proved.cm0), v["groth16"]["cm0_hex"]);
    assert_eq!(to_hex(&proved.cm1), v["groth16"]["cm1_hex"]);
    assert_eq!(to_hex(&proved.cm2), v["groth16"]["cm2_hex"]);
    assert_eq!(to_hex(&proved.public_input_hash), v["groth16"]["public_input_hash_hex"]);
    assert_eq!(to_hex(&proved.proof_192), v["groth16"]["proof_192_hex"]);

    // 9. Zero-panic UniFFI hardening (Finding #17) + extra_writable_pubkeys parity + Finding #14/#18
    let partial_err = build_transact_ix(FfiTransactParams {
        program_id: pid.clone(),
        payer: s0.pubkey_b58.clone(),
        pool_id: 0,
        vk_id: 0,
        root_ring_kind: 1,
        root_ring_idx: 0,
        out_lane_id: 2,
        out_sub_seq: 0,
        out_root_seq: 0,
        out_memo_seq: 0,
        out_nf_seq: 0,
        next_sub_seq: None,
        next_memo_seq: None,
        next_nf_seq: None,
        output_mask: 0,
        asset_mode: 1,
        unwrap_wsol: false,
        public_mint: Some(v["asset_ids"]["usdc_mint_b58"].as_str().unwrap().to_string()),
        public_vault_ata: None,
        public_token_prog: None,
        proof_192: proved.proof_192.clone(),
        nf0: proved.nf0.clone(),
        nf1: proved.nf1.clone(),
        cm0: proved.cm0.clone(),
        cm1: proved.cm1.clone(),
        cm2: proved.cm2.clone(),
        public_amount_out: 1,
        relayer_fee_amount: 0,
        recipient: s0.pubkey_b58.clone(),
        relayer_fee_recipient: s0.pubkey_b58.clone(),
        memos_bytes: vec![],
        transfer_hook_accounts: vec![],
    });
    assert!(partial_err.is_err(), "partial public withdraw accounts must return InvalidInput");

    // asset_mode == 1 with ALL None public accounts MUST return Err (zero panic!)
    let all_none_public_err = build_transact_ix(FfiTransactParams {
        program_id: pid.clone(),
        payer: s0.pubkey_b58.clone(),
        pool_id: 0,
        vk_id: 0,
        root_ring_kind: 1,
        root_ring_idx: 0,
        out_lane_id: 2,
        out_sub_seq: 0,
        out_root_seq: 0,
        out_memo_seq: 0,
        out_nf_seq: 0,
        next_sub_seq: None,
        next_memo_seq: None,
        next_nf_seq: None,
        output_mask: 0,
        asset_mode: 1,
        unwrap_wsol: false,
        public_mint: None,
        public_vault_ata: None,
        public_token_prog: None,
        proof_192: proved.proof_192.clone(),
        nf0: proved.nf0.clone(),
        nf1: proved.nf1.clone(),
        cm0: proved.cm0.clone(),
        cm1: proved.cm1.clone(),
        cm2: proved.cm2.clone(),
        public_amount_out: 1,
        relayer_fee_amount: 0,
        recipient: s0.pubkey_b58.clone(),
        relayer_fee_recipient: s0.pubkey_b58.clone(),
        memos_bytes: vec![],
        transfer_hook_accounts: vec![],
    });
    assert!(all_none_public_err.is_err(), "ASSET_MODE_PUBLIC with None accs must not panic");

    // page_kind > 3 & out-of-range PDA / interval indices MUST return Err (zero panic!)
    assert!(build_open_page_ix(pid.clone(), s0.pubkey_b58.clone(), 4, 0, 0, 0).is_err());
    assert!(build_open_page_ix(pid.clone(), s0.pubkey_b58.clone(), 0, 0, 16, 0).is_err());
    assert!(build_init_pool_ix(pid.clone(), s0.pubkey_b58.clone(), 0, 0, 0, 0).is_err());
    assert!(build_init_root_history_ix(pid.clone(), s0.pubkey_b58.clone(), 0, 257, 4).is_err());
    assert!(derive_lane_pda(pid.clone(), 0, 16).is_err());
    assert!(derive_escrow_pda(pid.clone(), 0, 16).is_err());

    // Missing recipient / relayer_fee_recipient in ctx_hash MUST return Err (zero panic!)
    assert!(compute_transact_ctx_hash_ffi(FfiTransactCtxHashParams {
        program_id: pid.clone(),
        pool_id: 0,
        vk_id: 0,
        out_lane_id: 0,
        output_mask: 0,
        asset_mode: 1,
        unwrap_wsol: false,
        recipient: None,
        relayer_fee_recipient: None,
        public_asset_id: vec![0u8; 32],
        public_amount_out: 1,
        relayer_fee_amount: 0,
        memos_bytes: vec![],
    })
    .is_err());
    assert!(compute_exec_ctx_hash_ffi(FfiExecCtxHashParams {
        program_id: pid.clone(),
        pool_id: 0,
        vk_id: 0,
        out_lane_id: 0,
        escrow_shard: 0,
        change_mask: 0,
        fee_on_output: false,
        asset_in: vec![0u8; 32],
        amount_in: 100,
        relayer_fee_amount: 10,
        relayer_fee_recipient: None,
        asset_out: vec![0u8; 32],
        min_amount_out: 1,
        router_prog: s0.pubkey_b58.clone(),
        router_accounts: vec![],
        extra_writable_pubkeys: vec![],
        out_stealth_owner: vec![0u8; 32],
        out_blinding: vec![0u8; 32],
        dyn_memo_head: vec![0u8; 34],
        dyn_mask_72: vec![0u8; 72],
        router_ix_data: vec![],
        change_memos: vec![],
    })
    .is_err());

    // extra_writable_pubkeys promotes aliased readonly router account in both ctx_hash & ix builder
    let sibling_b58 = bs58::encode([0x99u8; 32]).into_string();
    let h_promoted = compute_exec_ctx_hash_ffi(FfiExecCtxHashParams {
        program_id: pid.clone(),
        pool_id: 0,
        vk_id: 0,
        out_lane_id: 1,
        escrow_shard: 3,
        change_mask: 0,
        fee_on_output: false,
        asset_in: vec![1u8; 32],
        amount_in: 100,
        relayer_fee_amount: 0,
        relayer_fee_recipient: None,
        asset_out: vec![2u8; 32],
        min_amount_out: 50,
        router_prog: bs58::encode([0x77u8; 32]).into_string(),
        router_accounts: vec![FfiAccountMeta {
            pubkey_b58: sibling_b58.clone(),
            is_signer: false,
            is_writable: false,
        }],
        extra_writable_pubkeys: vec![sibling_b58.clone()],
        out_stealth_owner: vec![3u8; 32],
        out_blinding: vec![4u8; 32],
        dyn_memo_head: vec![5u8; 34],
        dyn_mask_72: vec![6u8; 72],
        router_ix_data: vec![1, 2],
        change_memos: vec![],
    })
    .unwrap();
    let h_explicit = compute_exec_ctx_hash_ffi(FfiExecCtxHashParams {
        program_id: pid.clone(),
        pool_id: 0,
        vk_id: 0,
        out_lane_id: 1,
        escrow_shard: 3,
        change_mask: 0,
        fee_on_output: false,
        asset_in: vec![1u8; 32],
        amount_in: 100,
        relayer_fee_amount: 0,
        relayer_fee_recipient: None,
        asset_out: vec![2u8; 32],
        min_amount_out: 50,
        router_prog: bs58::encode([0x77u8; 32]).into_string(),
        router_accounts: vec![FfiAccountMeta {
            pubkey_b58: sibling_b58.clone(),
            is_signer: false,
            is_writable: true,
        }],
        extra_writable_pubkeys: vec![],
        out_stealth_owner: vec![3u8; 32],
        out_blinding: vec![4u8; 32],
        dyn_memo_head: vec![5u8; 34],
        dyn_mask_72: vec![6u8; 72],
        router_ix_data: vec![1, 2],
        change_memos: vec![],
    })
    .unwrap();
    assert_eq!(h_promoted, h_explicit);
    let exec_ix = build_exec_via_escrow_ix(FfiExecViaEscrowParams {
        program_id: pid.clone(),
        payer: s0.pubkey_b58.clone(),
        pool_id: 0,
        vk_id: 0,
        root_ring_kind: 1,
        root_ring_idx: 0,
        out_lane_id: 1,
        out_sub_seq: 0,
        out_root_seq: 0,
        out_memo_seq: 0,
        out_nf_seq: 0,
        next_sub_seq: None,
        next_memo_seq: None,
        next_nf_seq: None,
        escrow_shard: 3,
        change_mask: 0,
        fee_on_output: false,
        in_leg: vec![s0.pubkey_b58.clone(); 4],
        out_leg: vec![s0.pubkey_b58.clone(); 4],
        relayer_fee_amount: 0,
        relayer_fee_recipient: None,
        proof_192: proved.proof_192,
        nf0: proved.nf0,
        nf1: proved.nf1,
        cm0: proved.cm0,
        cm1: proved.cm1,
        cm2: proved.cm2,
        amount_in: 100,
        min_amount_out: 50,
        out_stealth_owner: vec![3u8; 32],
        out_blinding: vec![4u8; 32],
        dyn_memo_head: vec![5u8; 34],
        dyn_mask_72: vec![6u8; 72],
        router_prog: bs58::encode([0x77u8; 32]).into_string(),
        router_ix_data: vec![1, 2],
        router_accounts: vec![FfiAccountMeta {
            pubkey_b58: sibling_b58.clone(),
            is_signer: false,
            is_writable: false,
        }],
        extra_writable_pubkeys: vec![sibling_b58],
        change_memos: vec![],
    })
    .unwrap();
    assert!(exec_ix.accounts.last().unwrap().is_writable);

    // Leading/trailing whitespace rejected in decode_audren_address
    assert!(decode_audren_address(format!(" {}", alice.address)).is_err());
    assert!(decode_audren_address(format!("{} ", alice.address)).is_err());

    // Unsatisfied Groth16 witness returns Err cleanly instead of panicking!
    let bad_witness = vec![0u8; 4_611];
    assert!(prove_joinsplit_witness_bytes(bad_witness, vec![0x99u8; 32]).is_err());
}

#[test]
fn decode_global_root_history_rejects_tampered_rings_and_forged_super_roots() {
    use audren_core::layout::{
        RT_OFF_EPOCH_RING, RT_OFF_LATEST_LANE_COUNTS, RT_OFF_LATEST_LANE_ROOTS,
        RT_OFF_LATEST_SUPER_ROOT, RT_OFF_SLOT_RING, RT_OFF_STABLE_EPOCH_ID,
        RT_OFF_STABLE_LANE_COUNTS, RT_OFF_STABLE_LANE_ROOTS, RT_OFF_STABLE_SLOT,
        RT_OFF_STABLE_SUPER_ROOT,
    };

    let raw_json = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/test-vectors.json"),
    )
    .expect("read spec/test-vectors.json");
    let v: serde_json::Value = serde_json::from_str(&raw_json).expect("parse JSON");
    let valid_rh = from_hex(v["root_history"]["raw_hex"].as_str().unwrap());

    // Baseline passes
    assert!(decode_global_root_history_account(valid_rh.clone()).is_ok());

    // 1. Tampered slot_ring cursor entry (desynced from latest_super_root)
    let mut bad_slot_ring = valid_rh.clone();
    bad_slot_ring[RT_OFF_SLOT_RING] ^= 0x01;
    assert!(decode_global_root_history_account(bad_slot_ring).is_err());

    // 2. Tampered epoch_ring cursor entry (desynced from stable_super_root)
    let mut bad_epoch_ring = valid_rh.clone();
    bad_epoch_ring[RT_OFF_EPOCH_RING] ^= 0x01;
    assert!(decode_global_root_history_account(bad_epoch_ring).is_err());

    // 3. All-zero latest_super_root echoed into slot_ring
    let mut zero_latest = valid_rh.clone();
    zero_latest[RT_OFF_LATEST_SUPER_ROOT..RT_OFF_LATEST_SUPER_ROOT + 32].fill(0);
    zero_latest[RT_OFF_SLOT_RING..RT_OFF_SLOT_RING + 32].fill(0);
    assert!(decode_global_root_history_account(zero_latest).is_err());

    // 4. All-zero stable_super_root echoed into epoch_ring
    let mut zero_stable = valid_rh.clone();
    zero_stable[RT_OFF_STABLE_SUPER_ROOT..RT_OFF_STABLE_SUPER_ROOT + 32].fill(0);
    zero_stable[RT_OFF_EPOCH_RING..RT_OFF_EPOCH_RING + 32].fill(0);
    assert!(decode_global_root_history_account(zero_stable).is_err());

    // 5. Forged canonical Fr latest_super_root ( != compute_super_root_4ary(latest_lane_roots) ) echoed into slot_ring
    let mut forged_latest = valid_rh.clone();
    let mut fake_fr = [0u8; 32];
    fake_fr[31] = 0x42;
    forged_latest[RT_OFF_LATEST_SUPER_ROOT..RT_OFF_LATEST_SUPER_ROOT + 32]
        .copy_from_slice(&fake_fr);
    forged_latest[RT_OFF_SLOT_RING..RT_OFF_SLOT_RING + 32].copy_from_slice(&fake_fr);
    assert!(decode_global_root_history_account(forged_latest).is_err());

    // 6. Forged canonical Fr stable_super_root echoed into epoch_ring
    let mut forged_stable = valid_rh.clone();
    forged_stable[RT_OFF_STABLE_SUPER_ROOT..RT_OFF_STABLE_SUPER_ROOT + 32]
        .copy_from_slice(&fake_fr);
    forged_stable[RT_OFF_EPOCH_RING..RT_OFF_EPOCH_RING + 32].copy_from_slice(&fake_fr);
    assert!(decode_global_root_history_account(forged_stable).is_err());

    // 7. Non-canonical BN254 Fr in latest_super_root / latest_lane_roots / stable_lane_roots
    let mut non_canon_latest = valid_rh.clone();
    non_canon_latest[RT_OFF_LATEST_SUPER_ROOT..RT_OFF_LATEST_SUPER_ROOT + 32].fill(0xff);
    non_canon_latest[RT_OFF_SLOT_RING..RT_OFF_SLOT_RING + 32].fill(0xff);
    assert!(decode_global_root_history_account(non_canon_latest).is_err());

    let mut bad_latest_lane = valid_rh.clone();
    bad_latest_lane[RT_OFF_LATEST_LANE_ROOTS] ^= 0x01;
    assert!(decode_global_root_history_account(bad_latest_lane).is_err());

    let mut bad_stable_lane = valid_rh.clone();
    bad_stable_lane[RT_OFF_STABLE_LANE_ROOTS..RT_OFF_STABLE_LANE_ROOTS + 32].fill(0xff);
    assert!(decode_global_root_history_account(bad_stable_lane).is_err());

    // 8. Round-3: 8-byte stable_lane_counts[2]=0 downgrade, 16-byte both counts=0, monotonicity,
    //    slot/epoch ring slot mismatches, stable_slot > latest_slot, and wrong stable_epoch_id!
    let mut eight_byte_downgrade = valid_rh.clone();
    eight_byte_downgrade[RT_OFF_STABLE_LANE_COUNTS + 2 * 8..RT_OFF_STABLE_LANE_COUNTS + 3 * 8]
        .copy_from_slice(&0u64.to_le_bytes());
    assert!(decode_global_root_history_account(eight_byte_downgrade.clone()).is_err());

    let mut sixteen_byte_zero = eight_byte_downgrade;
    sixteen_byte_zero[RT_OFF_LATEST_LANE_COUNTS + 2 * 8..RT_OFF_LATEST_LANE_COUNTS + 3 * 8]
        .copy_from_slice(&0u64.to_le_bytes());
    assert!(decode_global_root_history_account(sixteen_byte_zero).is_err());

    let mut stable_gt_latest_cnt = valid_rh.clone();
    stable_gt_latest_cnt[RT_OFF_STABLE_LANE_COUNTS + 2 * 8..RT_OFF_STABLE_LANE_COUNTS + 3 * 8]
        .copy_from_slice(&999u64.to_le_bytes());
    assert!(decode_global_root_history_account(stable_gt_latest_cnt).is_err());

    let mut stable_gt_latest_slot = valid_rh.clone();
    stable_gt_latest_slot[RT_OFF_STABLE_SLOT..RT_OFF_STABLE_SLOT + 8]
        .copy_from_slice(&200u64.to_le_bytes());
    stable_gt_latest_slot[RT_OFF_EPOCH_RING + 32..RT_OFF_EPOCH_RING + 40]
        .copy_from_slice(&200u64.to_le_bytes());
    stable_gt_latest_slot[RT_OFF_STABLE_EPOCH_ID..RT_OFF_STABLE_EPOCH_ID + 8]
        .copy_from_slice(&(200u64 / 32).to_le_bytes());
    assert!(decode_global_root_history_account(stable_gt_latest_slot).is_err());

    let mut bad_slot_ring_slot = valid_rh.clone();
    bad_slot_ring_slot[RT_OFF_SLOT_RING + 32..RT_OFF_SLOT_RING + 40]
        .copy_from_slice(&103u64.to_le_bytes());
    assert!(decode_global_root_history_account(bad_slot_ring_slot).is_err());

    let mut bad_epoch_ring_slot = valid_rh.clone();
    bad_epoch_ring_slot[RT_OFF_EPOCH_RING + 32..RT_OFF_EPOCH_RING + 40]
        .copy_from_slice(&103u64.to_le_bytes());
    assert!(decode_global_root_history_account(bad_epoch_ring_slot).is_err());

    let mut bad_epoch_id = valid_rh;
    bad_epoch_id[RT_OFF_STABLE_EPOCH_ID..RT_OFF_STABLE_EPOCH_ID + 8]
        .copy_from_slice(&99u64.to_le_bytes());
    assert!(decode_global_root_history_account(bad_epoch_id).is_err());
}

#[test]
fn ffi_wave2_root_snapshot_auto_open_pages_and_bump_aware_cu_exports() {
    let raw_json = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/test-vectors.json"),
    )
    .expect("read spec/test-vectors.json");
    let v: serde_json::Value = serde_json::from_str(&raw_json).expect("parse JSON");
    let valid_rh = from_hex(v["root_history"]["raw_hex"].as_str().unwrap());
    let pid = canonical_program_id();

    // 1. select_root_snapshot_for_notes: covered note selects ROOT_RING_EPOCH, uncovered / wrong pool / OOB lane returns Err
    let choice = select_root_snapshot_for_notes(
        valid_rh.clone(),
        0,
        vec![FfiNoteCoord {
            lane_id: 2,
            leaf_index: 5,
        }],
    )
    .unwrap();
    assert_eq!(choice.ring_kind, audren_core::ROOT_RING_EPOCH);
    assert_eq!(choice.ring_idx, 0);
    assert_eq!(
        to_hex(&choice.super_root),
        v["root_history"]["stable_super_root_hex"]
    );
    assert_eq!(choice.lane_roots.len(), audren_core::NUM_LANES);
    assert_eq!(choice.lane_counts[2], 6);

    // Wrong expected_pool_id, uncovered leaf_index, invalid lane_id, and tampered bytes all return Err (zero panic)
    assert!(select_root_snapshot_for_notes(
        valid_rh.clone(),
        1,
        vec![FfiNoteCoord {
            lane_id: 2,
            leaf_index: 5
        }]
    )
    .is_err());
    assert!(select_root_snapshot_for_notes(
        valid_rh.clone(),
        0,
        vec![FfiNoteCoord {
            lane_id: 2,
            leaf_index: 6
        }]
    )
    .is_err());
    assert!(select_root_snapshot_for_notes(
        valid_rh.clone(),
        0,
        vec![FfiNoteCoord {
            lane_id: 16,
            leaf_index: 0
        }]
    )
    .is_err());
    let mut bad_rh = valid_rh;
    bad_rh[0] ^= 0xff;
    assert!(select_root_snapshot_for_notes(bad_rh, 0, vec![]).is_err());

    // 2. plan_auto_open_pages: lookahead & exact rollover + custom program_id + existing_pages filtering + invalid input errors
    assert!(
        plan_auto_open_pages(pid.clone(), 0, 0, 10, 10, 1, 1, vec![])
            .unwrap()
            .is_empty()
    );

    let planned = plan_auto_open_pages(pid.clone(), 0, 0, 86, 540, 1, 1, vec![]).unwrap();
    assert_eq!(planned.len(), 2);
    assert_eq!(planned[0].page_kind, 2); // OPEN_PAGE_KIND_MEMO
    assert_eq!(planned[0].page_seq, 1);
    assert_eq!(
        planned[0].pda_b58,
        derive_memo_pda(pid.clone(), 0, 0, 1).unwrap().address
    );
    assert_eq!(planned[1].page_kind, 3); // OPEN_PAGE_KIND_NULLIFIER
    assert_eq!(planned[1].page_seq, 1);
    assert_eq!(
        planned[1].pda_b58,
        derive_nf_page_pda(pid.clone(), 0, 0, 1).unwrap().address
    );

    // Passing planned[0] in existing_pages filters out Memo page 1 (both by pda_b58 and by empty pda_b58 fallback)
    let filtered =
        plan_auto_open_pages(pid.clone(), 0, 0, 86, 540, 1, 1, vec![planned[0].clone()]).unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].page_kind, 3);

    let filtered_by_coord = plan_auto_open_pages(
        pid.clone(),
        0,
        0,
        86,
        540,
        1,
        1,
        vec![FfiOpenPageSpec {
            page_kind: 2,
            page_seq: 1,
            pda_b58: String::new(),
        }],
    )
    .unwrap();
    assert_eq!(filtered_by_coord.len(), 1);
    assert_eq!(filtered_by_coord[0].page_kind, 3);

    // Custom staging/localnet program_id derives custom-program PDAs and filters against them
    let custom_pid = solana_address::Address::new_from_array([0x42u8; 32]).to_string();
    let custom_planned =
        plan_auto_open_pages(custom_pid.clone(), 0, 0, 86, 540, 1, 1, vec![]).unwrap();
    assert_eq!(custom_planned.len(), 2);
    assert_eq!(
        custom_planned[0].pda_b58,
        derive_memo_pda(custom_pid.clone(), 0, 0, 1)
            .unwrap()
            .address
    );
    assert_ne!(custom_planned[0].pda_b58, planned[0].pda_b58);
    assert_eq!(
        custom_planned[1].pda_b58,
        derive_nf_page_pda(custom_pid.clone(), 0, 0, 1)
            .unwrap()
            .address
    );
    let custom_filtered = plan_auto_open_pages(
        custom_pid.clone(),
        0,
        0,
        86,
        540,
        1,
        1,
        vec![custom_planned[0].clone()],
    )
    .unwrap();
    assert_eq!(custom_filtered.len(), 1);
    assert_eq!(custom_filtered[0].pda_b58, custom_planned[1].pda_b58);
    let custom_filtered_coord = plan_auto_open_pages(
        custom_pid,
        0,
        0,
        86,
        540,
        1,
        1,
        vec![FfiOpenPageSpec {
            page_kind: 2,
            page_seq: 1,
            pda_b58: String::new(),
        }],
    )
    .unwrap();
    assert_eq!(custom_filtered_coord.len(), 1);
    assert_eq!(custom_filtered_coord[0].pda_b58, custom_planned[1].pda_b58);

    // Invalid program_id, lane_id, page_kind, or base58 PDA return Err cleanly
    assert!(
        plan_auto_open_pages("not-valid-pid!!!".to_string(), 0, 0, 86, 0, 1, 0, vec![]).is_err()
    );
    assert!(plan_auto_open_pages(pid.clone(), 0, 16, 86, 0, 1, 0, vec![]).is_err());
    assert!(plan_auto_open_pages(
        pid.clone(),
        0,
        0,
        86,
        0,
        1,
        0,
        vec![FfiOpenPageSpec {
            page_kind: 4,
            page_seq: 1,
            pda_b58: String::new(),
        }]
    )
    .is_err());
    assert!(plan_auto_open_pages(
        pid,
        0,
        0,
        86,
        0,
        1,
        0,
        vec![FfiOpenPageSpec {
            page_kind: 2,
            page_seq: 1,
            pda_b58: "not-valid-base58!!!".to_string(),
        }]
    )
    .is_err());

    // Zero-rent `.max(1)` clamp parity through FFI
    assert_eq!(deterministic_note_rent_fee_ffi(10_000_000, 0, 0, 0), 3);
    assert_eq!(deterministic_note_rent_fee_ffi(2, 0, 0, 0), 2);
    assert_eq!(deterministic_note_rent_fee_ffi(0, 0, 0, 0), 0);

    // 3-6. Bump-aware CU limit exports match calibrated v1.3.0 constants (incl. 45k Token-2022 ATA vs 30k classic ATA) & clamp safely at 1.4M
    assert_eq!(recommended_cu_limit_open_page(1, vec![]), 40_000);
    assert_eq!(recommended_cu_limit_open_page(2, vec![250]), 87_500);
    assert_eq!(recommended_cu_limit_open_page(u32::MAX, vec![0]), 1_400_000);

    assert_eq!(recommended_cu_limit_deposit(false, 0, 0, 0, vec![]), 75_000);
    assert_eq!(
        recommended_cu_limit_deposit(true, 1, 1, 0, vec![253, 252]),
        140_000 + 40_000 + 30_000 + 7_500
    );
    assert_eq!(
        recommended_cu_limit_deposit(true, 1, 1, 2, vec![253, 252]),
        140_000 + 40_000 + 30_000 + 2 * 45_000 + 7_500
    );

    assert_eq!(
        recommended_cu_limit_transact(false, false, 0b111, 0, 0, 0, vec![]),
        235_000
    );
    assert_eq!(
        recommended_cu_limit_transact(true, false, 0, 0, 0, 0, vec![245]),
        165_000 + 15_000
    );
    assert_eq!(
        recommended_cu_limit_transact(true, false, 0b001, 1, 1, 0, vec![254]),
        255_000 + 40_000 + 30_000 + 1_500
    );
    assert_eq!(
        recommended_cu_limit_transact(true, true, 0b001, 1, 0, 2, vec![254]),
        295_000 + 40_000 + 2 * 45_000 + 1_500
    );
    assert_eq!(
        recommended_cu_limit_transact(true, true, 0, 0, 0, 0, vec![]),
        295_000
    );

    assert_eq!(
        recommended_cu_limit_exec_via_escrow(300_000, false, 2, 0, 0, vec![]),
        285_000 + 300_000 + 80_000
    );
    assert_eq!(
        recommended_cu_limit_exec_via_escrow(300_000, true, 1, 1, 0, vec![240, 255]),
        285_000 + 25_000 + 300_000 + 40_000 + 30_000 + 22_500
    );
    assert_eq!(
        recommended_cu_limit_exec_via_escrow(300_000, true, 1, 1, 2, vec![240, 255]),
        285_000 + 25_000 + 300_000 + 40_000 + 30_000 + 2 * 45_000 + 22_500
    );
    assert_eq!(
        recommended_cu_limit_exec_via_escrow(1_300_000, true, 2, 1, 2, vec![0, 0]),
        1_400_000
    );
}
