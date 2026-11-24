//! Empirical Cross-SDK On-Chain Verification Suite (LiteSVM + Real sBPFv3 `audren.so`).
//!
//! Proves with ZERO mocks over real Solana Transaction v1 (`0x81`) that:
//!   1. TypeScript `@audren/sdk` + `@audren/sdk/prover` WASM (`audren_circuits.wasm`) builds a
//!      unified `Deposit(DEPOSIT_FLAG_NATIVE_SOL)` instruction, ingests on-chain `SubtreePage`/
//!      `MemoPage` via TS `CompactWalletStore`, proves a real BN254 Groth16 `Transact` private
//!      transfer inside WASM, and executes it on-chain against `target/deploy/audren.so`!
//!   2. Rust UniFFI (`audren-ffi`, exact library powering Swift & Kotlin) ingests the resulting
//!      on-chain pages produced by TypeScript, proves a Groth16 `Transact(WITHDRAW_FLAG_UNWRAP_WSOL)`
//!      SOL withdrawal with relayer fee via `prove_joinsplit_witness_bytes` + `build_transact_ix`,
//!      and executes on-chain!
//!   3. TypeScript `@audren/sdk/prover` WASM then spends Alice's change note in a public
//!      `Transact(WITHDRAW_FLAG_UNWRAP_WSOL)` withdrawal with relayer fee, verifying full
//!      bidirectional cross-SDK interoperability!

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
    instruction::{ASSET_MODE_PUBLIC, VK_ID_DEFAULT},
    layout::{GlobalRootHistory, LaneTreeHeader},
    ASSOCIATED_TOKEN_PROGRAM_ID, AUDREN_PROGRAM_ID, CLASSIC_TOKEN_PROGRAM_ID,
    DEFAULT_ROOT_EPOCH_INTERVAL, SYSTEM_PROGRAM_ID, WSOL_MINT,
};
use audren_ffi::*;
use litesvm::{types::TransactionResult, LiteSVM};
use serde_json::{json, Value};
use solana_account::Account;
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

#[allow(clippy::result_large_err)]
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
fn cross_sdk_typescript_wasm_and_uniffi_execute_onchain() {
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
    let spl_token_id = Address::new_from_array(CLASSIC_TOKEN_PROGRAM_ID);
    let ata_prog_id = Address::new_from_array(ASSOCIATED_TOKEN_PROGRAM_ID);
    let sys_prog_id = Address::new_from_array(SYSTEM_PROGRAM_ID);
    let wsol_mint = Address::new_from_array(WSOL_MINT);

    svm.add_program_from_file(program_id, &so_path)
        .expect("load audren.so");

    // Seed canonical Solana genesis WSOL Mint (82 B, decimals = 9, is_initialized = 1)
    let mut wsol_data = vec![0u8; 82];
    wsol_data[44] = 9;
    wsol_data[45] = 1;
    svm.set_account(
        wsol_mint,
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(82),
            data: wsol_data,
            owner: spl_token_id,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    let authority = Keypair::new();
    let depositor = Keypair::new();
    let relayer = Keypair::new();
    let recipient_bob = Keypair::new();
    let recipient_alice = Keypair::new();
    for kp in [&authority, &depositor, &relayer] {
        svm.airdrop(&kp.pubkey(), 20_000_000_000).unwrap();
    }

    // 1. InitPool (with GlobalRootHistory) + InitLane(0..4) + canonical WSOL vault ATA using audren-ffi
    let init_pool = ffi_ix_to_solana(
        build_init_pool_ix(
            program_id_str.clone(),
            authority.pubkey().to_string(),
            0,
            DEFAULT_ROOT_EPOCH_INTERVAL,
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

    let vault_auth_str = derive_vault_auth_pda(program_id_str.clone(), 0).unwrap().address;
    let vault_auth_addr: Address = vault_auth_str.parse().unwrap();
    let vault_wsol_str = derive_ata(
        vault_auth_str.clone(),
        spl_token_id.to_string(),
        wsol_mint.to_string(),
    )
    .unwrap();
    let vault_wsol_addr: Address = vault_wsol_str.parse().unwrap();
    let create_vault_wsol_ix = Instruction {
        program_id: ata_prog_id,
        accounts: vec![
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new(vault_wsol_addr, false),
            AccountMeta::new_readonly(vault_auth_addr, false),
            AccountMeta::new_readonly(wsol_mint, false),
            AccountMeta::new_readonly(sys_prog_id, false),
            AccountMeta::new_readonly(spl_token_id, false),
        ],
        data: vec![1u8], // CreateIdempotent
    };
    send_v1(&mut svm, &authority, &[&authority], &[create_vault_wsol_ix], 200_000)
        .expect("create canonical vault WSOL ATA");

    // 2. TypeScript @audren/sdk builds unified Deposit(DEPOSIT_FLAG_NATIVE_SOL) (2.0 SOL to Alice on lane 0)
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
        .expect("TS Deposit(NATIVE_SOL) on-chain");
    println!(
        "[cross-sdk] TS Deposit(NATIVE_SOL) executed on-chain ({} CU)",
        dep_meta.compute_units_consumed
    );

    // 3. Instant spendability via GlobalRootHistory (zero external checkpoint crank!):
    //    TypeScript @audren/sdk + @audren/sdk/prover WASM scans lane 0 and proves private Transact:
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
    let roots_addr: Address = derive_roots_pda(program_id_str.clone(), 0)
        .unwrap()
        .address
        .parse()
        .unwrap();

    let ts_xfer = run_ts_driver(&json!({
        "action": "transact_transfer",
        "program_id": program_id_str,
        "payer": relayer.pubkey().to_string(),
        "pool_id": 0,
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
        "roots_raw_hex": to_hex(&svm.get_account(&roots_addr).unwrap().data),
    }));
    let xfer_ix = json_ix_to_solana(&ts_xfer);
    assert!(
        xfer_ix.accounts[2].is_writable,
        "Transact with outputs must mark GlobalRootHistory writable"
    );
    let xfer_meta = send_v1(&mut svm, &relayer, &[&relayer], &[xfer_ix], 350_000)
        .expect("TS WASM Transact private transfer on-chain");
    println!(
        "[cross-sdk] TS WASM Transact Private Transfer executed on-chain ({} CU)",
        xfer_meta.compute_units_consumed
    );

    // 4. Rust UniFFI (Swift/Kotlin backend) ingests lane 1 pages created by TypeScript immediately
    //    (zero checkpoint crank!), decrypts Bob's 1.2 SOL note, proves Transact WSOL unwrap
    //    withdrawal (1.15 SOL + 0.05 SOL relayer fee) with READ-ONLY GlobalRootHistory, and executes on-chain!
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

    let sub1_raw = svm.get_account(&sub1_addr).unwrap().data.clone();
    let memo1_raw = svm.get_account(&memo1_addr).unwrap().data.clone();
    let roots_raw = svm.get_account(&roots_addr).unwrap().data.clone();

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

    let roots = GlobalRootHistory::decode(&roots_raw).unwrap();
    let (bob_choice, super_root, path) = bob_store
        .build_witness_from_root_history(&bob_note, &roots)
        .unwrap();
    let (bob_ring_kind, bob_ring_idx) = (bob_choice.ring_kind, bob_choice.ring_idx);
    let wsol_asset_bytes = derive_asset_id_bytes(WSOL_MINT.to_vec()).unwrap();
    let wsol_asset = derive_asset_id(&WSOL_MINT);
    let bob_fee = 50_000_000u64;
    let bob_out = bob_note.amount - bob_fee;
    let ctx_bob_bytes = compute_transact_ctx_hash_ffi(FfiTransactCtxHashParams {
        program_id: program_id_str.clone(),
        pool_id: 0,
        vk_id: VK_ID_DEFAULT,
        out_lane_id: 2,
        output_mask: 0,
        asset_mode: ASSET_MODE_PUBLIC,
        unwrap_wsol: true,
        recipient: Some(recipient_bob.pubkey().to_string()),
        relayer_fee_recipient: Some(relayer.pubkey().to_string()),
        public_asset_id: wsol_asset_bytes,
        public_amount_out: bob_out,
        relayer_fee_amount: bob_fee,
        memos_bytes: vec![],
    })
    .unwrap();
    let ctx_bob = fr_from_be_bytes_strict(&ctx_bob_bytes.try_into().unwrap()).unwrap();

    let circuit = JoinSplit4AryCircuit::new_with_options(
        super_root,
        wsol_asset,
        wsol_asset,
        bob_out,
        bob_fee,
        ctx_bob,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: bob_keys.spend_sk,
                tweak: bob_note.tweak_fr().unwrap(),
                asset_id: wsol_asset,
                amount: bob_note.amount,
                blinding: bob_note.blinding_fr().unwrap(),
                is_dummy: false,
                merkle_path: path,
            },
            JoinSplitInputWitness {
                spend_sk: bob_keys.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: wsol_asset,
                amount: 0,
                blinding: Fr::from(0x5555u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness::dummy(wsol_asset, Fr::from(1u64)),
            JoinSplitOutputWitness::dummy(wsol_asset, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(wsol_asset, Fr::from(3u64)),
        ],
    );
    let witness_bytes = encode_joinsplit_witness_bytes(&circuit);
    let bob_proof = prove_joinsplit_witness_bytes(witness_bytes.to_vec(), vec![0x77u8; 32]).unwrap();

    let bob_wd_ix = ffi_ix_to_solana(
        build_transact_ix(FfiTransactParams {
            program_id: program_id_str.clone(),
            payer: relayer.pubkey().to_string(),
            pool_id: 0,
            vk_id: VK_ID_DEFAULT,
            root_ring_kind: bob_ring_kind,
            root_ring_idx: bob_ring_idx,
            out_lane_id: 2,
            out_sub_seq: 0,
            out_root_seq: 0,
            out_memo_seq: 0,
            out_nf_seq: 0,
            next_sub_seq: None,
            next_memo_seq: None,
            next_nf_seq: None,
            output_mask: 0,
            asset_mode: ASSET_MODE_PUBLIC,
            unwrap_wsol: true,
            public_mint: Some(wsol_mint.to_string()),
            public_vault_ata: Some(vault_wsol_str),
            public_token_prog: Some(spl_token_id.to_string()),
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
            transfer_hook_accounts: vec![],
        })
        .unwrap(),
    );
    assert!(
        !bob_wd_ix.accounts[2].is_writable,
        "Full exit (output_mask == 0) must pass GlobalRootHistory as READ-ONLY"
    );
    let bob_meta = send_v1(&mut svm, &relayer, &[&relayer], &[bob_wd_ix], 350_000)
        .expect("FFI Transact WSOL Unwrap Withdraw on-chain");
    assert_eq!(svm.get_balance(&recipient_bob.pubkey()).unwrap(), bob_out);
    println!(
        "[cross-sdk] UniFFI (Swift/Kotlin) Transact WSOL Unwrap executed on-chain ({} CU)",
        bob_meta.compute_units_consumed
    );

    // 5. TypeScript @audren/sdk/prover WASM spends Alice's 0.8 SOL change note from lane 1
    //    with READ-ONLY GlobalRootHistory!
    let ts_wd = run_ts_driver(&json!({
        "action": "transact_withdraw_sol",
        "program_id": program_id_str,
        "payer": relayer.pubkey().to_string(),
        "pool_id": 0,
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
        "roots_raw_hex": to_hex(&svm.get_account(&roots_addr).unwrap().data),
    }));
    let alice_wd_ix = json_ix_to_solana(&ts_wd);
    assert!(
        !alice_wd_ix.accounts[2].is_writable,
        "TS full exit (output_mask == 0) must pass GlobalRootHistory as READ-ONLY"
    );
    let alice_meta = send_v1(&mut svm, &relayer, &[&relayer], &[alice_wd_ix], 350_000)
        .expect("TS WASM Transact WSOL Unwrap Withdraw on-chain");
    assert_eq!(
        svm.get_balance(&recipient_alice.pubkey()).unwrap(),
        775_000_000
    );
    println!(
        "[cross-sdk] TS WASM Transact WSOL Unwrap executed on-chain ({} CU)",
        alice_meta.compute_units_consumed
    );

    // Confirm on-chain lane state & GlobalRootHistory integrity
    let lane1_addr: Address = derive_lane_pda(program_id_str.clone(), 0, 1)
        .unwrap()
        .address
        .parse()
        .unwrap();
    let l1 = LaneTreeHeader::decode(&svm.get_account(&lane1_addr).unwrap().data).unwrap();
    assert_eq!(l1.next_leaf, 2);
    let roots_final = GlobalRootHistory::decode(&svm.get_account(&roots_addr).unwrap().data).unwrap();
    assert_eq!(roots_final.latest_lane_counts[1], 2);
}
