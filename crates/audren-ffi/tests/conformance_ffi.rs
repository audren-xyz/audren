//! Verifies `audren-ffi` UniFFI surface matches `spec/test-vectors.json` byte-for-byte.

use std::path::PathBuf;

use audren_ffi::{
    canonical_program_id, compute_exec_ctx_hash_ffi, compute_joinsplit_ctx_hash_ffi,
    decode_audren_address, decode_pool_state_account, decode_root_checkpoint_account,
    decrypt_and_verify_memo_entry, derive_asset_id_bytes, derive_checkpoint_pda,
    derive_defi_session_keypair, derive_escrow_pda, derive_keys_from_seed, derive_lane_pda,
    derive_lane_rent_pda, derive_memo_pda, derive_nf_page_pda, derive_nullifier_pda,
    derive_pool_pda, derive_sol_vault_pda, derive_subaccount_keys, derive_subroot_pda,
    derive_subtree_pda, derive_unwrap_pda, derive_vault_auth_pda, encrypt_note_memo,
    export_full_viewing_key, prepare_dynamic_swap_memo, protocol_version,
    verify_selective_disclosure_proof, FfiAccountMeta, FfiExecCtxHashParams,
    FfiJoinSplitCtxHashParams, FfiSelectiveDisclosureProof,
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

    // 1. Keys, subaccount, FVK, aud1 address, and DeFi sessions
    let alice_seed = from_hex(v["alice"]["seed_hex"].as_str().unwrap());
    let alice = derive_keys_from_seed(alice_seed.clone()).unwrap();
    assert_eq!(to_hex(&alice.spend_sk), v["alice"]["spend_sk_hex"]);
    assert_eq!(to_hex(&alice.spend_pk), v["alice"]["spend_pk_hex"]);
    assert_eq!(to_hex(&alice.nk), v["alice"]["nk_hex"]);
    assert_eq!(to_hex(&alice.view_sk), v["alice"]["view_sk_hex"]);
    assert_eq!(to_hex(&alice.view_pk), v["alice"]["view_pk_hex"]);
    assert_eq!(alice.address, v["alice"]["address"].as_str().unwrap());

    let decoded_addr = decode_audren_address(alice.address.clone()).unwrap();
    assert_eq!(to_hex(&decoded_addr[0]), v["alice"]["spend_pk_hex"]);
    assert_eq!(to_hex(&decoded_addr[1]), v["alice"]["view_pk_hex"]);

    let sub1 = derive_subaccount_keys(alice_seed.clone(), 1).unwrap();
    assert_eq!(sub1.address, v["alice_sub1"]["address"].as_str().unwrap());

    let fvk = export_full_viewing_key(alice_seed.clone()).unwrap();
    assert_eq!(to_hex(&fvk.nk), v["alice"]["nk_hex"]);

    let s0 = derive_defi_session_keypair(alice_seed.clone(), 0).unwrap();
    assert_eq!(s0.pubkey_b58, v["defi_session_0"]["pubkey_b58"].as_str().unwrap());
    let s3 = derive_defi_session_keypair(alice_seed, 3).unwrap();
    assert_eq!(s3.pubkey_b58, v["defi_session_3"]["pubkey_b58"].as_str().unwrap());

    // 2. Asset IDs
    assert_eq!(
        to_hex(&derive_asset_id_bytes(vec![0u8; 32]).unwrap()),
        v["asset_ids"]["native_sol_asset_id_hex"]
    );
    let usdc_bytes = bs58::decode(v["asset_ids"]["usdc_mint_b58"].as_str().unwrap())
        .into_vec()
        .unwrap();
    assert_eq!(
        to_hex(&derive_asset_id_bytes(usdc_bytes).unwrap()),
        v["asset_ids"]["usdc_asset_id_hex"]
    );

    // 3. All 13 V2 PDAs
    let p = &v["pdas"];
    let pool_id = p["pool_id"].as_u64().unwrap() as u32;
    let lane_id = p["lane_id"].as_u64().unwrap() as u8;
    let page_seq = p["page_seq"].as_u64().unwrap();
    let slot_idx = p["slot_idx"].as_u64().unwrap() as u16;
    let shard_id = p["shard_id"].as_u64().unwrap() as u8;
    let nf = from_hex(p["nullifier_hex"].as_str().unwrap());

    assert_eq!(derive_pool_pda(pid.clone(), pool_id).unwrap().address, p["pool"]["address"].as_str().unwrap());
    assert_eq!(derive_sol_vault_pda(pid.clone(), pool_id).unwrap().address, p["sol_vault"]["address"].as_str().unwrap());
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

    // 4. Memo encrypt + decrypt + commitment verify + dynamic swap memo
    let enc = encrypt_note_memo(
        alice.spend_pk.clone(),
        alice.view_pk.clone(),
        from_hex(v["memo"]["eph_secret_hex"].as_str().unwrap()),
        v["memo"]["amount"].as_u64().unwrap(),
        from_hex(v["memo"]["mint_hex"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(to_hex(&enc.memo_90), v["memo"]["memo_90_hex"]);
    assert_eq!(to_hex(&enc.commitment), v["memo"]["commitment_hex"]);

    let dec = decrypt_and_verify_memo_entry(fvk, enc.memo_90.clone(), enc.commitment.clone())
        .unwrap()
        .expect("decrypt memo");
    assert_eq!(dec.amount, v["memo"]["amount"].as_u64().unwrap());

    let bob_vpk = from_hex(v["bob"]["view_pk_hex"].as_str().unwrap());
    let dyn_m = prepare_dynamic_swap_memo(bob_vpk, vec![0x44u8; 32]).unwrap();
    assert_eq!(to_hex(&dyn_m.dyn_head_34), v["memo"]["dyn_head_34_hex"]);
    assert_eq!(to_hex(&dyn_m.dyn_mask_56), v["memo"]["dyn_mask_56_hex"]);

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

    // 6. Context hashes
    let ctx_priv = compute_joinsplit_ctx_hash_ffi(FfiJoinSplitCtxHashParams {
        program_id: pid.clone(),
        pool_id: 0,
        out_lane_id: 2,
        output_mask: 0b111,
        asset_mode: 0,
        unwrap_wsol: false,
        recipient: None,
        relayer_fee_recipient: None,
        public_asset_id: vec![0u8; 32],
        public_amount_out: 0,
        relayer_fee_amount: 0,
        memos_bytes: enc.memo_90.clone(),
    })
    .unwrap();
    assert_eq!(to_hex(&ctx_priv), v["ctx_hashes"]["joinsplit_private_ctx_hash_hex"]);

    let ctx_exec = compute_exec_ctx_hash_ffi(FfiExecCtxHashParams {
        program_id: pid,
        pool_id: 0,
        out_lane_id: 1,
        escrow_shard: 3,
        change_mask: 0b01,
        in_kind: 1,
        out_kind: 0,
        fee_on_output: true,
        asset_in: from_hex(v["asset_ids"]["usdc_asset_id_hex"].as_str().unwrap()),
        amount_in: 50_000_000,
        relayer_fee_amount: 2_000_000,
        relayer_fee_recipient: Some(s3.pubkey_b58),
        asset_out: from_hex(v["asset_ids"]["native_sol_asset_id_hex"].as_str().unwrap()),
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
        out_stealth_owner: enc.stealth_owner,
        out_blinding: enc.blinding,
        dyn_memo_head: dyn_m.dyn_head_34,
        dyn_mask_56: dyn_m.dyn_mask_56,
        router_ix_data: vec![1, 2, 3, 4],
        change_memos: enc.memo_90,
    })
    .unwrap();
    assert_eq!(to_hex(&ctx_exec), v["ctx_hashes"]["exec_fee_on_output_ctx_hash_hex"]);

    // 7. Account decoders
    let ps = decode_pool_state_account(from_hex(v["pool_state"]["raw_hex"].as_str().unwrap())).unwrap();
    assert_eq!(ps.active_lanes, 4);
    assert_eq!(ps.ckpt_interval, 8);
    let ck = decode_root_checkpoint_account(from_hex(v["checkpoint_raw_hex"].as_str().unwrap())).unwrap();
    assert_eq!(ck.slot_idx, 13);
    assert_eq!(ck.lane_counts[2], 6);
}
