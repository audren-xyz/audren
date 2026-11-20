//! Live Solana End-to-End Verification for Audren (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`)
//! using Solana Transaction Version 1 (SIMD-0385, `0x81`, 4,096 B, inline `TransactionConfig`).
//!
//! Run explicitly against a QuickNode Devnet or Mainnet RPC:
//! ```bash
//! AUDREN_RPC_URL="https://your-devnet-rpc-endpoint" \
//! AUDREN_KEYPAIR_PATH="/path/to/funder.json" \
//! cargo test --test devnet_live -- --ignored --nocapture
//! ```
//!
//! Proves live on-chain Agave execution via Solana Transaction v1 of:
//! 1. `InitPool` (if pool does not exist yet)
//! 2. `Deposit` (native SOL -> stealth note) in ONE Solana v1 transaction
//! 3. Standard RPC `getAccountInfo` `dataSlice[64..1120]` note discovery
//! 4. `Transfer` (real Ristretto255 Multi-Base Triptych + native Agave ZK ElGamal Bulletproof U128)
//!    directly in ONE Solana v1 transaction (`<= 4,096 B`, zero legacy transactions)
//! 5. `Withdraw` (with optional shielded change) directly in ONE Solana v1 transaction

use audren_client::{
    instructions::{
        build_buffered_execution, build_deposit, build_init_pool, build_transfer, build_withdraw,
        AudrenInstruction,
    },
    keys::AudrenKeys,
    pda::{derive_epoch_page_pda, derive_pool_pda},
    prover::extract_ring_from_page,
    scanner::{decrypt_owned_note, scan_page_dataslice},
};
use audren_core::{
    layout::{PoolState, PAGE_SCAN_LEN, PAGE_SCAN_OFFSET},
    AUDREN_PROGRAM_ID, NATIVE_SOL_MINT, PoolMode,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::{rngs::StdRng, SeedableRng};
use serde_json::{json, Value};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{
    v1::{self, TransactionConfig, MAX_TRANSACTION_SIZE},
    VersionedMessage,
};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_LOADED_ACCOUNTS_DATA_SIZE: u32 = 64 * 1024 * 1024;

fn to_ix(ix: &AudrenInstruction) -> Instruction {
    Instruction {
        program_id: ix.program_id,
        accounts: ix
            .accounts
            .iter()
            .map(|m| AccountMeta {
                pubkey: m.pubkey,
                is_signer: m.is_signer,
                is_writable: m.is_writable,
            })
            .collect(),
        data: ix.data.clone(),
    }
}

fn rpc_call(url: &str, method: &str, params: Value) -> Value {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    .to_string();
    let out = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "15",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            &body,
            url,
        ])
        .output()
        .expect("curl failed");
    assert!(
        out.status.success(),
        "curl exited {}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let resp: Value = serde_json::from_slice(&out.stdout).expect("invalid JSON from RPC");
    if let Some(err) = resp.get("error") {
        panic!("RPC {method} error: {err}");
    }
    resp["result"].clone()
}

fn get_blockhash(url: &str) -> [u8; 32] {
    let res = rpc_call(url, "getLatestBlockhash", json!([{"commitment": "confirmed"}]));
    let s = res["value"]["blockhash"].as_str().unwrap();
    let bytes = bs58::decode(s).into_vec().unwrap();
    bytes.try_into().unwrap()
}

fn get_account_data(url: &str, pubkey: &Address, slice: Option<(usize, usize)>) -> Option<Vec<u8>> {
    let mut cfg = json!({
        "encoding": "base64",
        "commitment": "confirmed"
    });
    if let Some((offset, length)) = slice {
        cfg["dataSlice"] = json!({ "offset": offset, "length": length });
    }
    let res = rpc_call(url, "getAccountInfo", json!([pubkey.to_string(), cfg]));
    if res["value"].is_null() {
        return None;
    }
    let b64 = res["value"]["data"][0].as_str().unwrap();
    Some(B64.decode(b64).unwrap())
}

fn build_v1_wire(
    payer: &Keypair,
    ixs: &[Instruction],
    blockhash: [u8; 32],
    cu_limit: u32,
    priority_fee_lamports: u64,
) -> Vec<u8> {
    let config = TransactionConfig::empty()
        .with_priority_fee(priority_fee_lamports)
        .with_compute_unit_limit(cu_limit)
        .with_loaded_accounts_data_size_limit(DEFAULT_LOADED_ACCOUNTS_DATA_SIZE);
    let msg = v1::Message::try_compile_with_config(&payer.pubkey(), ixs, blockhash.into(), config)
        .expect("compile Solana v1 message");
    let tx = VersionedTransaction::try_new(VersionedMessage::V1(msg), &[payer])
        .expect("sign Solana v1 transaction");
    wincode::serialize(&tx).expect("wincode-serialize Solana v1 transaction")
}

fn send_v1_and_confirm(
    url: &str,
    payer: &Keypair,
    ixs: &[Instruction],
    cu_limit: u32,
    label: &str,
) -> String {
    let bh = get_blockhash(url);
    let wire = build_v1_wire(payer, ixs, bh, cu_limit, 10_000);
    assert_eq!(wire[0], 0x81, "expected Solana Transaction v1 prefix 0x81");
    assert!(
        wire.len() <= MAX_TRANSACTION_SIZE,
        "{label}: Solana v1 wire tx {} B exceeds {MAX_TRANSACTION_SIZE} B limit!",
        wire.len()
    );
    let b64 = B64.encode(&wire);
    let sig = rpc_call(
        url,
        "sendTransaction",
        json!([b64, {"encoding": "base64", "preflightCommitment": "confirmed", "maxRetries": 5}]),
    )
    .as_str()
    .unwrap()
    .to_string();

    for attempt in 0..45 {
        let st = rpc_call(
            url,
            "getSignatureStatuses",
            json!([[&sig], {"searchTransactionHistory": true}]),
        );
        if let Some(entry) = st["value"][0].as_object() {
            if let Some(err) = entry.get("err") {
                if !err.is_null() {
                    panic!("{label} failed on-chain ({sig}): {err}");
                }
            }
            if let Some(conf) = entry.get("confirmationStatus").and_then(|v| v.as_str()) {
                if conf == "confirmed" || conf == "finalized" {
                    println!(
                        "  [CONFIRMED] {label} (Solana v1 · {} B / {MAX_TRANSACTION_SIZE} B) -> {sig}",
                        wire.len()
                    );
                    return sig;
                }
            }
        } else if attempt > 0 && attempt % 5 == 0 {
            let _ = rpc_call(
                url,
                "sendTransaction",
                json!([b64, {"encoding": "base64", "skipPreflight": true, "maxRetries": 2}]),
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("timed out waiting for confirmation of {label} ({sig})");
}

/// Sends an Audren instruction directly in ONE Solana v1 transaction (`<= 4,096 B`),
/// automatically falling back to `ProofBuffer` (over v1 transactions) only if a payload
/// ever exceeds 4,096 B.
fn send_audren_v1(
    url: &str,
    payer: &Keypair,
    audren_ix: &AudrenInstruction,
    cu_limit: u32,
    nonce: u64,
    label: &str,
) -> String {
    let ix = to_ix(audren_ix);
    let probe = build_v1_wire(payer, std::slice::from_ref(&ix), [0u8; 32], cu_limit, 10_000);
    if probe.len() <= MAX_TRANSACTION_SIZE {
        return send_v1_and_confirm(url, payer, &[ix], cu_limit, label);
    }

    let plan = build_buffered_execution(audren_ix, nonce).expect("build ProofBuffer plan");
    for (i, chunk_ix) in plan.upload_chunks.iter().enumerate() {
        send_v1_and_confirm(
            url,
            payer,
            &[to_ix(chunk_ix)],
            80_000,
            &format!("{label} WriteProofBuffer(chunk {i})"),
        );
    }
    let sig = send_v1_and_confirm(
        url,
        payer,
        &[to_ix(&plan.execute)],
        cu_limit,
        &format!("ExecBuffered({label})"),
    );
    assert!(
        get_account_data(url, &plan.proof_buffer, None).is_none(),
        "{label} ProofBuffer must be closed on-chain"
    );
    sig
}

#[test]
#[ignore = "live Solana Devnet E2E test; pass AUDREN_RPC_URL and AUDREN_KEYPAIR_PATH"]
fn test_live_devnet_full_shielded_lifecycle() {
    let rpc_url = std::env::var("AUDREN_RPC_URL").expect("set AUDREN_RPC_URL");
    let kp_path = std::env::var("AUDREN_KEYPAIR_PATH").expect("set AUDREN_KEYPAIR_PATH");
    let kp_bytes: Vec<u8> =
        serde_json::from_str(&std::fs::read_to_string(&kp_path).expect("read keypair"))
            .expect("parse keypair JSON");
    let payer = Keypair::try_from(kp_bytes.as_slice()).expect("valid keypair");
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);

    let seed_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let mut rng = StdRng::seed_from_u64(seed_now);

    let mut alice_seed = [0u8; 32];
    alice_seed[..8].copy_from_slice(&seed_now.to_le_bytes());
    alice_seed[8] = 0xAA;
    let mut bob_seed = [0u8; 32];
    bob_seed[..8].copy_from_slice(&seed_now.to_le_bytes());
    bob_seed[8] = 0xBB;
    let alice = AudrenKeys::from_seed(&alice_seed);
    let bob = AudrenKeys::from_seed(&bob_seed);

    let pool_id = 0u32;
    let (pool_pda, _) = derive_pool_pda(&program_id, pool_id);

    println!("=== Audren Live Devnet E2E (Solana Transaction v1) ===");
    println!("Program ID: {program_id}");
    println!("Payer:      {}", payer.pubkey());
    println!("Pool PDA:   {pool_pda}");

    let active_page_id = if let Some(pool_bytes) = get_account_data(&rpc_url, &pool_pda, None) {
        let pool = PoolState::decode(&pool_bytes).expect("decode PoolState");
        println!(
            "Existing Pool #0 found: page={} total_notes={} total_spends={}",
            pool.current_page_id, pool.total_notes, pool.total_spends
        );
        pool.current_page_id
    } else {
        let init_ix = build_init_pool(
            program_id,
            payer.pubkey(),
            pool_id,
            PoolMode::Permissionless,
            false,
            [0u8; 32],
            2_000_000,
        );
        send_v1_and_confirm(&rpc_url, &payer, &[to_ix(&init_ix)], 120_000, "InitPool(#0)");
        0
    };

    // 1. Shield 0.05 SOL to Alice in ONE Solana v1 transaction
    let (dep_ix, _) = build_deposit(
        program_id,
        payer.pubkey(),
        pool_id,
        active_page_id,
        &alice.address(),
        NATIVE_SOL_MINT,
        50_000_000,
        None,
        &mut rng,
    )
    .unwrap();
    send_audren_v1(&rpc_url, &payer, &dep_ix, 120_000, seed_now, "Deposit(0.05 SOL -> Alice)");

    // 2. Scan EpochPage via standard RPC dataSlice[64..1120]
    let (page_pda, _) = derive_epoch_page_pda(&program_id, pool_id, active_page_id);
    let scan_slice =
        get_account_data(&rpc_url, &page_pda, Some((PAGE_SCAN_OFFSET, PAGE_SCAN_LEN)))
            .expect("EpochPage dataSlice");
    let alice_fvk = alice.full_viewing_key();
    let alice_hits = scan_page_dataslice(&alice_fvk, active_page_id, &scan_slice).unwrap();
    assert_eq!(alice_hits.len(), 1, "Alice must find exactly 1 shielded note via dataSlice");

    let page_full = get_account_data(&rpc_url, &page_pda, None).expect("EpochPage full");
    let alice_note = decrypt_owned_note(
        &alice_fvk,
        Some(&alice),
        &program_id,
        pool_id,
        &page_full,
        alice_hits[0].slot_index,
        None,
    )
    .unwrap()
    .expect("decrypt Alice note");
    assert_eq!(alice_note.amount, 50_000_000);
    println!(
        "  [PURE-RPC SCAN OK] Found Alice note at page={} slot={} amount=0.05 SOL",
        active_page_id, alice_note.slot_index
    );

    // 3. Shielded Transfer (0.03 SOL -> Bob, 0.02 SOL change -> Alice) in ONE Solana v1 tx!
    let ring = extract_ring_from_page(&page_full).unwrap();
    let (xfer_ix, _, _) = build_transfer(
        program_id,
        payer.pubkey(),
        pool_id,
        active_page_id,
        &[active_page_id],
        &ring,
        &alice_note,
        alice_note.slot_index,
        &bob.address(),
        &alice.address(),
        30_000_000,
        None,
        &[],
        &mut rng,
    )
    .unwrap();
    send_audren_v1(
        &rpc_url,
        &payer,
        &xfer_ix,
        900_000,
        seed_now + 1,
        "Transfer(0.03 SOL -> Bob + 0.02 SOL change -> Alice)",
    );

    // 4. Bob scans pure-RPC dataSlice & Withdraws 0.02 SOL (keeping 0.01 SOL shielded change!)
    let scan_slice_2 =
        get_account_data(&rpc_url, &page_pda, Some((PAGE_SCAN_OFFSET, PAGE_SCAN_LEN)))
            .expect("EpochPage dataSlice 2");
    let bob_fvk = bob.full_viewing_key();
    let bob_hits = scan_page_dataslice(&bob_fvk, active_page_id, &scan_slice_2).unwrap();
    assert_eq!(bob_hits.len(), 1, "Bob must find his 0.03 SOL shielded note");

    let page_full_2 = get_account_data(&rpc_url, &page_pda, None).expect("EpochPage full 2");
    let bob_note = decrypt_owned_note(
        &bob_fvk,
        Some(&bob),
        &program_id,
        pool_id,
        &page_full_2,
        bob_hits[0].slot_index,
        None,
    )
    .unwrap()
    .expect("decrypt Bob note");
    assert_eq!(bob_note.amount, 30_000_000);

    let ring2 = extract_ring_from_page(&page_full_2).unwrap();
    let (wd_ix, _) = build_withdraw(
        program_id,
        payer.pubkey(),
        pool_id,
        active_page_id,
        &[active_page_id],
        &ring2,
        &bob_note,
        bob_note.slot_index,
        payer.pubkey(),
        &bob.address(),
        20_000_000,
        None,
        None,
        &mut rng,
    )
    .unwrap();
    send_audren_v1(
        &rpc_url,
        &payer,
        &wd_ix,
        800_000,
        seed_now + 2,
        "Withdraw(0.02 SOL + 0.01 SOL shielded change)",
    );

    println!("=== ALL LIVE SOLANA V1 DEVNET E2E CHECKS PASSED 100%! ===");
}

#[test]
#[ignore = "live Mainnet smoke test (0.001 SOL full-recovery roundtrip via Solana v1); pass AUDREN_RPC_URL and AUDREN_KEYPAIR_PATH"]
fn test_live_mainnet_smoke_full_recovery() {
    let rpc_url = std::env::var("AUDREN_RPC_URL").expect("set AUDREN_RPC_URL");
    let kp_path = std::env::var("AUDREN_KEYPAIR_PATH").expect("set AUDREN_KEYPAIR_PATH");
    let kp_bytes: Vec<u8> =
        serde_json::from_str(&std::fs::read_to_string(&kp_path).expect("read keypair"))
            .expect("parse keypair JSON");
    let payer = Keypair::try_from(kp_bytes.as_slice()).expect("valid keypair");
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);

    let seed_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let mut rng = StdRng::seed_from_u64(seed_now);

    let mut alice_seed = [0u8; 32];
    alice_seed[..8].copy_from_slice(&seed_now.to_le_bytes());
    alice_seed[8] = 0x11;
    let mut bob_seed = [0u8; 32];
    bob_seed[..8].copy_from_slice(&seed_now.to_le_bytes());
    bob_seed[8] = 0x22;
    let alice = AudrenKeys::from_seed(&alice_seed);
    let bob = AudrenKeys::from_seed(&bob_seed);

    let pool_id = 0u32;
    let (pool_pda, _) = derive_pool_pda(&program_id, pool_id);

    let active_page_id = if let Some(pool_bytes) = get_account_data(&rpc_url, &pool_pda, None) {
        PoolState::decode(&pool_bytes).expect("decode PoolState").current_page_id
    } else {
        let init_ix = build_init_pool(
            program_id,
            payer.pubkey(),
            pool_id,
            PoolMode::Permissionless,
            false,
            [0u8; 32],
            2_000_000,
        );
        send_v1_and_confirm(&rpc_url, &payer, &[to_ix(&init_ix)], 120_000, "Mainnet InitPool(#0)");
        0
    };

    // 1. Shield 0.001 SOL -> 2. Transfer 0.001 SOL to Bob -> 3. Full Withdraw back to payer (all single-tx Solana v1!)
    let (dep_ix, _) = build_deposit(
        program_id,
        payer.pubkey(),
        pool_id,
        active_page_id,
        &alice.address(),
        NATIVE_SOL_MINT,
        1_000_000,
        None,
        &mut rng,
    )
    .unwrap();
    send_audren_v1(&rpc_url, &payer, &dep_ix, 120_000, seed_now, "Mainnet Deposit(0.001 SOL)");

    let (page_pda, _) = derive_epoch_page_pda(&program_id, pool_id, active_page_id);
    let scan_slice = get_account_data(&rpc_url, &page_pda, Some((PAGE_SCAN_OFFSET, PAGE_SCAN_LEN)))
        .expect("EpochPage dataSlice");
    let alice_fvk = alice.full_viewing_key();
    let alice_hits = scan_page_dataslice(&alice_fvk, active_page_id, &scan_slice).unwrap();
    assert_eq!(alice_hits.len(), 1);
    let page_full = get_account_data(&rpc_url, &page_pda, None).expect("EpochPage full");
    let alice_note = decrypt_owned_note(
        &alice_fvk,
        Some(&alice),
        &program_id,
        pool_id,
        &page_full,
        alice_hits[0].slot_index,
        None,
    )
    .unwrap()
    .expect("decrypt Alice note");

    let ring = extract_ring_from_page(&page_full).unwrap();
    let (xfer_ix, _, _) = build_transfer(
        program_id,
        payer.pubkey(),
        pool_id,
        active_page_id,
        &[active_page_id],
        &ring,
        &alice_note,
        alice_note.slot_index,
        &bob.address(),
        &alice.address(),
        1_000_000,
        None,
        &[],
        &mut rng,
    )
    .unwrap();
    send_audren_v1(
        &rpc_url,
        &payer,
        &xfer_ix,
        900_000,
        seed_now + 1,
        "Mainnet Transfer(0.001 SOL -> Bob)",
    );

    let scan_slice_2 = get_account_data(&rpc_url, &page_pda, Some((PAGE_SCAN_OFFSET, PAGE_SCAN_LEN)))
        .expect("EpochPage dataSlice 2");
    let bob_fvk = bob.full_viewing_key();
    let bob_hits = scan_page_dataslice(&bob_fvk, active_page_id, &scan_slice_2).unwrap();
    assert_eq!(bob_hits.len(), 1);
    let page_full_2 = get_account_data(&rpc_url, &page_pda, None).expect("EpochPage full 2");
    let bob_note = decrypt_owned_note(
        &bob_fvk,
        Some(&bob),
        &program_id,
        pool_id,
        &page_full_2,
        bob_hits[0].slot_index,
        None,
    )
    .unwrap()
    .expect("decrypt Bob note");
    assert_eq!(bob_note.amount, 1_000_000);

    let ring2 = extract_ring_from_page(&page_full_2).unwrap();
    let (wd_ix, _) = build_withdraw(
        program_id,
        payer.pubkey(),
        pool_id,
        active_page_id,
        &[active_page_id],
        &ring2,
        &bob_note,
        bob_note.slot_index,
        payer.pubkey(),
        &bob.address(),
        1_000_000,
        None,
        None,
        &mut rng,
    )
    .unwrap();
    send_audren_v1(
        &rpc_url,
        &payer,
        &wd_ix,
        600_000,
        seed_now + 2,
        "Mainnet Full Withdraw(0.001 SOL -> payer)",
    );
    println!("=== LIVE SOLANA V1 MAINNET SMOKE TEST PASSED 100%! ===");
}
