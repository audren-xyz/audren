//! Empirical Cross-SDK On-Chain Verification Suite (LiteSVM + Real sBPFv3 `audren.so`).
//!
//! Proves with ZERO mocks over real Solana Transaction v1 (`0x81`) that:
//!   1. TypeScript `@audren/sdk` + `@audren/sdk/prover` WASM (`audren_circuits.wasm`) builds a
//!      `DepositSol` instruction, ingests on-chain `SubtreePage`/`MemoPage` via TS
//!      `CompactWalletStore`, proves a real BN254 Groth16 `JoinSplit` private transfer inside WASM,
//!      and executes it on-chain against `target/deploy/audren.so`!
//!   2. Rust UniFFI (`audren-ffi`, exact library powering Swift & Kotlin) ingests the resulting
//!      on-chain pages produced by TypeScript, proves a Groth16 `JoinSplit` SOL withdrawal with
//!      relayer fee via `prove_joinsplit_witness_bytes` + `build_joinsplit_ix`, and executes on-chain!
//!   3. TypeScript `@audren/sdk/prover` WASM then spends Alice's change note in a public SOL
//!      withdrawal with relayer fee, verifying full bidirectional cross-SDK interoperability!

use agave_feature_set::FeatureSet;
use ark_bn254::Fr;
use audren_circuits::{
    encode_joinsplit_witness_bytes,
    joinsplit::{JoinSplit4AryCircuit, JoinSplitInputWitness, JoinSplitOutputWitness},
    merkle::MerklePath4Ary,
    note::derive_asset_id,
    poseidon::fr_from_be_bytes_strict,
};
use audren_client::{keys::AudrenKeys, store::CompactWalletStore};
use audren_core::{
    instruction::ASSET_MODE_SOL,
    layout::{LaneTreeHeader, RootCheckpoint},
    AUDREN_PROGRAM_ID, NATIVE_SOL_MINT,
};
use audren_ffi::*;
use litesvm::{types::TransactionResult, LiteSVM};
use serde_json::{json, Value};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{
    v1::{self, TransactionConfig},
    VersionedMessage,
};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

const DEFAULT_LOADED_ACCOUNTS_DATA_SIZE: u32 = 64 * 1024 * 1024;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("resolve repo root")
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn ffi_ix_to_solana(ix: FfiInstruction) -> Instruction {
    Instruction {
        program_id: ix.program_id_b58.parse::<Address>().unwrap(),
        accounts: ix
            .accounts
            .into_iter()
            .map(|a| AccountMeta {
                pubkey: a.pubkey_b58.parse::<Address>().unwrap(),
                is_signer: a.is_signer,
                is_writable: a.is_writable,
            })
            .collect(),
        data: ix.data,
    }
}

fn json_ix_to_solana(v: &Value) -> Instruction {
    Instruction {
        program_id: v["program_id"].as_str().unwrap().parse::<Address>().unwrap(),
        accounts: v["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| AccountMeta {
                pubkey: a["pubkey"].as_str().unwrap().parse::<Address>().unwrap(),
                is_signer: a["is_signer"].as_bool().unwrap(),
                is_writable: a["is_writable"].as_bool().unwrap(),
            })
            .collect(),
        data: from_hex(v["data_hex"].as_str().unwrap()),
    }
}

fn run_ts_driver(payload: &Value) -> Value {
    let driver = repo_root().join("packages/sdk/test/litesvm-driver.mjs");
    let mut child = Command::new("node")
        .arg(&driver)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn node litesvm-driver.mjs");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("wait driver");
    if !out.status.success() {
        panic!(
            "TS litesvm-driver.mjs failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    serde_json::from_slice(&out.stdout).expect("parse driver stdout JSON")
}

fn send_v1(
    svm: &mut LiteSVM,
    payer: &Keypair,
    signers: &[&Keypair],
    ixs: &[Instruction],
    cu_limit: u32,
) -> TransactionResult {
    svm.expire_blockhash();
    let bh = svm.latest_blockhash();
    let msg = v1::Message::try_compile_with_config(
        &payer.pubkey(),
        ixs,
        bh,
        TransactionConfig {
            compute_unit_limit: Some(cu_limit),
            loaded_accounts_data_size_limit: Some(DEFAULT_LOADED_ACCOUNTS_DATA_SIZE),
            priority_fee: None,
            heap_size: None,
        },
    )
    .expect("compile v1 msg");
    let tx = VersionedTransaction::try_new(VersionedMessage::V1(msg), signers).expect("sign v1 tx");
    svm.send_transaction(tx)
}

#[test]
fn cross_sdk_typescript_wasm_and_uniffi_execute_onchain_v2() {
    let root = repo_root();
    let so_path = root.join("target/deploy/audren.so");
    assert!(
        so_path.exists(),
        "Build audren.so first via python3 scripts/build-sbf.py"
    );

    let mut svm = LiteSVM::new()
        .with_feature_set(FeatureSet::all_enabled())
        .with_builtins()
        .with_sysvars()
        .with_default_programs()
        .with_sigverify(true)
        .with_blockhash_check(false);
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let program_id_str = canonical_program_id();
    svm.add_program_from_file(program_id, &so_path)
        .expect("load audren.so");

    let authority = Keypair::new();
    let depositor = Keypair::new();
    let relayer = Keypair::new();
    let recipient_bob = Keypair::new();
    let recipient_alice = Keypair::new();
    for kp in [&authority, &depositor, &relayer] {
        svm.airdrop(&kp.pubkey(), 20_000_000_000).unwrap();
    }

    // 1. InitPool + InitLane(0..4) using audren-ffi (exact Swift/Kotlin path)
    let init_pool = ffi_ix_to_solana(
        build_init_pool_ix(
            program_id_str.clone(),
            authority.pubkey().to_string(),
            0,
            8,
            1_536,
            1_500_000,
            500_000,
        )
        .unwrap(),
    );
    send_v1(&mut svm, &authority, &[&authority], &[init_pool], 200_000).expect("init_pool");

    for lane in 0u8..4u8 {
        let ix = ffi_ix_to_solana(
            build_init_lane_ix(
                program_id_str.clone(),
                authority.pubkey().to_string(),
                0,
                lane,
            )
            .unwrap(),
        );
        send_v1(&mut svm, &authority, &[&authority], &[ix], 300_000).expect("init_lane");
    }

    // 2. TypeScript @audren/sdk builds DepositSol (2.0 SOL to Alice on lane 0)
    let alice_seed = [0x11u8; 32];
    let bob_seed = [0x22u8; 32];
    let dep_res = run_ts_driver(&json!({
        "action": "deposit_sol",
        "program_id": program_id_str,
        "depositor": depositor.pubkey().to_string(),
        "pool_id": 0,
        "lane_id": 0,
        "sub_page_seq": 0,
        "root_page_seq": 0,
        "memo_page_seq": 0,
        "fee_from_amount": false,
        "amount": 2_000_000_000u64,
        "recipient_seed_hex": to_hex(&alice_seed),
        "eph_secret_hex": to_hex(&[0x33u8; 32]),
    }));
    let dep_ix = json_ix_to_solana(&dep_res);
    let dep_meta = send_v1(&mut svm, &depositor, &[&depositor], &[dep_ix], 200_000)
        .expect("TS DepositSol on-chain");
    println!(
        "[cross-sdk] TS DepositSol executed on-chain ({} CU)",
        dep_meta.compute_units_consumed
    );

    // 3. PublishCheckpoint slot 1 (warp slot to 8 = epoch 1)
    svm.warp_to_slot(8);
    let ck1_ix = ffi_ix_to_solana(
        build_publish_checkpoint_ix(
            program_id_str.clone(),
            relayer.pubkey().to_string(),
            0,
            1,
            4,
        )
        .unwrap(),
    );
    send_v1(&mut svm, &relayer, &[&relayer], &[ck1_ix], 150_000).expect("ckpt 1");

    // 4. TypeScript @audren/sdk + @audren/sdk/prover WASM scans lane 0 and proves private transfer:
    //    Alice sends 1.2 SOL to Bob + 0.8 SOL change to Alice on lane 1!
    let sub0_addr: Address = derive_subtree_pda(program_id_str.clone(), 0, 0, 0)
        .unwrap()
        .address
        .parse()
        .unwrap();
    let memo0_addr: Address = derive_memo_pda(program_id_str.clone(), 0, 0, 0)
        .unwrap()
        .address
        .parse()
        .unwrap();
    let ck1_addr: Address = derive_checkpoint_pda(program_id_str.clone(), 0, 1)
        .unwrap()
        .address
        .parse()
        .unwrap();

    let ts_xfer = run_ts_driver(&json!({
        "action": "joinsplit_transfer",
        "program_id": program_id_str,
        "payer": relayer.pubkey().to_string(),
        "pool_id": 0,
        "ckpt_slot_idx": 1,
        "in_lane_id": 0,
        "in_sub_seq": 0,
        "in_memo_seq": 0,
        "out_lane_id": 1,
        "out_sub_seq": 0,
        "out_root_seq": 0,
        "out_memo_seq": 0,
        "out_nf_seq": 0,
        "sender_seed_hex": to_hex(&alice_seed),
        "recipient_seed_hex": to_hex(&bob_seed),
        "send_amount": 1_200_000_000u64,
        "eph0_hex": to_hex(&[0x44u8; 32]),
        "eph1_hex": to_hex(&[0x55u8; 32]),
        "subtree_raw_hex": to_hex(&svm.get_account(&sub0_addr).unwrap().data),
        "memo_raw_hex": to_hex(&svm.get_account(&memo0_addr).unwrap().data),
        "checkpoint_raw_hex": to_hex(&svm.get_account(&ck1_addr).unwrap().data),
    }));
    let xfer_ix = json_ix_to_solana(&ts_xfer);
    let xfer_meta = send_v1(&mut svm, &relayer, &[&relayer], &[xfer_ix], 350_000)
        .expect("TS WASM JoinSplit private transfer on-chain");
    println!(
        "[cross-sdk] TS WASM JoinSplit Private Transfer executed on-chain ({} CU)",
        xfer_meta.compute_units_consumed
    );

    // 5. PublishCheckpoint slot 2 (warp slot to 16 = epoch 2)
    svm.warp_to_slot(16);
    let ck2_ix = ffi_ix_to_solana(
        build_publish_checkpoint_ix(
            program_id_str.clone(),
            relayer.pubkey().to_string(),
            0,
            2,
            4,
        )
        .unwrap(),
    );
    send_v1(&mut svm, &relayer, &[&relayer], &[ck2_ix], 150_000).expect("ckpt 2");

    // 6. Rust UniFFI (Swift/Kotlin backend) ingests lane 1 pages created by TypeScript,
    //    decrypts Bob's 1.2 SOL note, proves JoinSplit SOL withdrawal (1.15 SOL + 0.05 SOL relayer fee),
    //    and executes on-chain!
    let sub1_addr: Address = derive_subtree_pda(program_id_str.clone(), 0, 1, 0)
        .unwrap()
        .address
        .parse()
        .unwrap();
    let memo1_addr: Address = derive_memo_pda(program_id_str.clone(), 0, 1, 0)
        .unwrap()
        .address
        .parse()
        .unwrap();
    let ck2_addr: Address = derive_checkpoint_pda(program_id_str.clone(), 0, 2)
        .unwrap()
        .address
        .parse()
        .unwrap();

    let sub1_raw = svm.get_account(&sub1_addr).unwrap().data.clone();
    let memo1_raw = svm.get_account(&memo1_addr).unwrap().data.clone();
    let ck2_raw = svm.get_account(&ck2_addr).unwrap().data.clone();

    let bob_keys = AudrenKeys::from_seed(&bob_seed);
    let bob_fvk = bob_keys.full_viewing_key();
    let mut bob_store = CompactWalletStore::from_json_bytes(
        compact_store_new_json(0, 0).unwrap().as_bytes(),
    )
    .unwrap();
    let found = bob_store
        .ingest_lane_pages(&bob_fvk, 1, &[(0, &sub1_raw)], &[(0, &memo1_raw)], &[])
        .unwrap();
    assert_eq!(found, 1, "Store must decrypt Bob's note sent by TS WASM");
    let bob_note = bob_store.unspent_notes(None)[0].clone();
    assert_eq!(bob_note.amount, 1_200_000_000);

    let ck2 = RootCheckpoint::decode(&ck2_raw).unwrap();
    let (super_root, path) = bob_store.build_witness_for_note(&bob_note, &ck2).unwrap();
    let sol_asset_bytes = derive_asset_id_bytes(NATIVE_SOL_MINT.to_vec()).unwrap();
    let sol_asset = derive_asset_id(&NATIVE_SOL_MINT);
    let bob_fee = 50_000_000u64;
    let bob_out = bob_note.amount - bob_fee;
    let ctx_bob_bytes = compute_joinsplit_ctx_hash_ffi(audren_ffi::FfiJoinSplitCtxHashParams {
        program_id: program_id_str.clone(),
        pool_id: 0,
        out_lane_id: 2,
        output_mask: 0,
        asset_mode: ASSET_MODE_SOL,
        unwrap_wsol: false,
        recipient: Some(recipient_bob.pubkey().to_string()),
        relayer_fee_recipient: Some(relayer.pubkey().to_string()),
        public_asset_id: sol_asset_bytes,
        public_amount_out: bob_out,
        relayer_fee_amount: bob_fee,
        memos_bytes: vec![],
    })
    .unwrap();
    let ctx_bob = fr_from_be_bytes_strict(&ctx_bob_bytes.try_into().unwrap()).unwrap();

    let circuit = JoinSplit4AryCircuit::new_with_options(
        super_root,
        sol_asset,
        sol_asset,
        bob_out,
        bob_fee,
        ctx_bob,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: bob_keys.spend_sk,
                tweak: bob_note.tweak_fr().unwrap(),
                asset_id: sol_asset,
                amount: bob_note.amount,
                blinding: bob_note.blinding_fr().unwrap(),
                is_dummy: false,
                merkle_path: path,
            },
            JoinSplitInputWitness {
                spend_sk: bob_keys.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: sol_asset,
                amount: 0,
                blinding: Fr::from(0x5555u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness::dummy(sol_asset, Fr::from(1u64)),
            JoinSplitOutputWitness::dummy(sol_asset, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(sol_asset, Fr::from(3u64)),
        ],
    );
    let witness_bytes = encode_joinsplit_witness_bytes(&circuit);
    let bob_proof = prove_joinsplit_witness_bytes(witness_bytes.to_vec(), vec![0x77u8; 32]).unwrap();

    let bob_wd_ix = ffi_ix_to_solana(
        build_joinsplit_ix(audren_ffi::FfiJoinSplitParams {
            program_id: program_id_str.clone(),
            payer: relayer.pubkey().to_string(),
            pool_id: 0,
            vk_id: 0,
            ckpt_slot_idx: 2,
            out_lane_id: 2,
            out_sub_seq: 0,
            out_root_seq: 0,
            out_memo_seq: 0,
            out_nf_seq: 0,
            output_mask: 0,
            asset_mode: ASSET_MODE_SOL,
            unwrap_wsol: false,
            spl_mint: None,
            spl_vault_ata: None,
            spl_token_prog: None,
            proof_192: bob_proof.proof_192,
            nf0: bob_proof.nf0,
            nf1: bob_proof.nf1,
            cm0: bob_proof.cm0,
            cm1: bob_proof.cm1,
            cm2: bob_proof.cm2,
            public_amount_out: bob_out,
            relayer_fee_amount: bob_fee,
            recipient: recipient_bob.pubkey().to_string(),
            relayer_fee_recipient: relayer.pubkey().to_string(),
            memos_bytes: vec![],
        })
        .unwrap(),
    );
    let bob_meta = send_v1(&mut svm, &relayer, &[&relayer], &[bob_wd_ix], 350_000)
        .expect("FFI JoinSplit Withdraw SOL on-chain");
    assert_eq!(svm.get_balance(&recipient_bob.pubkey()).unwrap(), bob_out);
    println!(
        "[cross-sdk] UniFFI (Swift/Kotlin) JoinSplit SOL Withdraw executed on-chain ({} CU)",
        bob_meta.compute_units_consumed
    );

    // 7. TypeScript @audren/sdk/prover WASM spends Alice's 0.8 SOL change note from lane 1!
    let ts_wd = run_ts_driver(&json!({
        "action": "joinsplit_withdraw_sol",
        "program_id": program_id_str,
        "payer": relayer.pubkey().to_string(),
        "pool_id": 0,
        "ckpt_slot_idx": 2,
        "in_lane_id": 1,
        "in_sub_seq": 0,
        "in_memo_seq": 0,
        "out_lane_id": 3,
        "out_sub_seq": 0,
        "out_root_seq": 0,
        "out_memo_seq": 0,
        "out_nf_seq": 0,
        "sender_seed_hex": to_hex(&alice_seed),
        "recipient": recipient_alice.pubkey().to_string(),
        "relayer_fee_recipient": relayer.pubkey().to_string(),
        "relayer_fee_amount": 25_000_000u64,
        "subtree_raw_hex": to_hex(&sub1_raw),
        "memo_raw_hex": to_hex(&memo1_raw),
        "checkpoint_raw_hex": to_hex(&ck2_raw),
    }));
    let alice_wd_ix = json_ix_to_solana(&ts_wd);
    let alice_meta = send_v1(&mut svm, &relayer, &[&relayer], &[alice_wd_ix], 350_000)
        .expect("TS WASM JoinSplit Withdraw SOL on-chain");
    assert_eq!(
        svm.get_balance(&recipient_alice.pubkey()).unwrap(),
        775_000_000
    );
    println!(
        "[cross-sdk] TS WASM JoinSplit SOL Withdraw executed on-chain ({} CU)",
        alice_meta.compute_units_consumed
    );

    // Confirm on-chain lane state & checkpoint integrity
    let lane1_addr: Address = derive_lane_pda(program_id_str.clone(), 0, 1)
        .unwrap()
        .address
        .parse()
        .unwrap();
    let l1 = LaneTreeHeader::decode(&svm.get_account(&lane1_addr).unwrap().data).unwrap();
    assert_eq!(l1.next_leaf, 2);
    assert_eq!(ck2.lane_counts[1], 2);
}
