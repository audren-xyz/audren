//! Verifies `audren-ffi` UniFFI surface matches `spec/test-vectors.json` byte-for-byte.

use std::path::PathBuf;

use audren_ffi::{
    build_exec_via_escrow_ix, build_open_page_ix, build_transact_ix, build_update_pool_ix,
    canonical_program_id, check_memo_view_tag, compute_exec_ctx_hash_ffi,
    compute_page_rollovers_ffi, compute_transact_ctx_hash_ffi, decode_audren_address,
    decode_pool_state_account, decode_root_checkpoint_account, decrypt_and_verify_memo_entry,
    derive_asset_id_bytes, derive_checkpoint_pda, derive_defi_session_keypair, derive_escrow_pda,
    derive_keys_from_seed, derive_lane_pda, derive_lane_rent_pda, derive_memo_pda,
    derive_nf_page_pda, derive_nullifier_pda, derive_pool_pda, derive_subaccount_keys,
    derive_subroot_pda, derive_subtree_pda, derive_unwrap_pda, derive_vault_auth_pda,
    encrypt_note_memo, export_full_viewing_key, prepare_dynamic_swap_memo, protocol_version,
    prove_joinsplit_witness_bytes, verify_selective_disclosure_proof, FfiAccountMeta,
    FfiExecCtxHashParams, FfiExecViaEscrowParams, FfiSelectiveDisclosureProof,
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
    let slot_idx = p["slot_idx"].as_u64().unwrap() as u16;
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
    assert_eq!(derive_checkpoint_pda(pid.clone(), pool_id, slot_idx).unwrap().address, p["checkpoint"]["address"].as_str().unwrap());
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

    // 7. Account decoders + rollover planner + UpdatePool builder
    let ps = decode_pool_state_account(from_hex(v["pool_state"]["raw_hex"].as_str().unwrap())).unwrap();
    assert_eq!(ps.active_lanes, 4);
    assert_eq!(ps.ckpt_interval, 8);
    assert_eq!(ps.pending_authority_b58, v["pool_state"]["pending_authority_b58"].as_str().unwrap());
    let ck = decode_root_checkpoint_account(from_hex(v["checkpoint_raw_hex"].as_str().unwrap())).unwrap();
    assert_eq!(ck.slot_idx, 13);
    assert_eq!(ck.lane_counts[2], 6);
    assert_eq!(compute_page_rollovers_ffi(95, 2, 0, 1).next_memo_seq, Some(1));
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
        ckpt_slot_idx: 13,
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
        ckpt_slot_idx: 13,
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

    // page_kind > 3 & out-of-range PDA indices MUST return Err (zero panic!)
    assert!(build_open_page_ix(pid.clone(), s0.pubkey_b58.clone(), 4, 0, 0, 0).is_err());
    assert!(build_open_page_ix(pid.clone(), s0.pubkey_b58.clone(), 0, 0, 16, 0).is_err());
    assert!(derive_lane_pda(pid.clone(), 0, 16).is_err());
    assert!(derive_checkpoint_pda(pid.clone(), 0, 256).is_err());
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
        ckpt_slot_idx: 13,
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
