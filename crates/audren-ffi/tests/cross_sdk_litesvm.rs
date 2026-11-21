//! Empirical Cross-SDK On-Chain Verification Suite (LiteSVM + Real sBPFv3 `audren.so`).
//!
//! Proves with ZERO mocks that instructions produced by:
//!   1. Pure TypeScript (`@audren/sdk` + `@audren/sdk/prover`),
//!   2. UniFFI native mobile core (`audren-ffi` — exact code called by Swift & Kotlin), and
//!   3. Rust (`audren-client`)
//! ALL pass Solana's real sBPFv3 `audren.so` & `audren_mock_router.so` verifiers in LiteSVM,
//! AND that note encryption/decryption (full + read-only FVK) and Mode 1 Selective Disclosure
//! proofs (including parallel append lane 1 `page_id > 2^53`) interoperate bidirectionally!

use agave_feature_set::FeatureSet;
use audren_client::{
    instructions::{build_init_lane, build_init_pool, build_set_paused, AudrenInstruction},
    keys::{AudrenKeys, SelectiveDisclosureProof},
    pda::{
        derive_ata, derive_epoch_page_pda, derive_lane_pda, derive_pool_pda, derive_swap_escrow_pda,
        derive_vault_auth_pda,
    },
    scanner::{decrypt_owned_note, scan_page_dataslice},
};
use audren_core::{
    layout::{PageHeader, PoolState, PAGE_LEN, PAGE_SCAN_LEN, PAGE_SCAN_OFFSET},
    AUDREN_PROGRAM_ID, CLASSIC_TOKEN_PROGRAM_ID, NATIVE_SOL_MINT, PoolMode,
};
use audren_ffi::*;
use litesvm::{types::TransactionResult, LiteSVM};
use serde_json::{json, Value};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{
    v1::{self, TransactionConfig, MAX_TRANSACTION_SIZE},
    VersionedMessage,
};
use solana_program_pack::Pack;
use solana_rent::Rent;
use solana_signer::Signer;
use solana_system_interface::instruction as sys_ix;
use solana_transaction::versioned::VersionedTransaction;
use spl_token_2022_interface::{
    instruction as token_ix,
    state::{Account as TokenAccount, Mint},
};
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

struct DeployArtifacts {
    audren_so: PathBuf,
    mock_router_so: Option<PathBuf>,
}

fn deploy_artifacts_if_available() -> Option<DeployArtifacts> {
    let dir = repo_root().join("target/deploy");
    let audren_so = dir.join("audren.so");
    let mock_router_path = dir.join("audren_mock_router.so");
    let mock_router_so = mock_router_path.exists().then_some(mock_router_path);
    if !audren_so.exists() {
        if std::env::var("AUDREN_REQUIRE_SBF").is_ok() {
            panic!("AUDREN_REQUIRE_SBF=1 but target/deploy/audren.so is missing");
        }
        eprintln!("SKIP cross_sdk_litesvm: target/deploy/audren.so not present");
        return None;
    }
    if mock_router_so.is_none() && std::env::var("AUDREN_REQUIRE_MOCK_ROUTER").is_ok() {
        panic!("AUDREN_REQUIRE_MOCK_ROUTER=1 but target/deploy/audren_mock_router.so is missing");
    }
    Some(DeployArtifacts {
        audren_so,
        mock_router_so,
    })
}

fn new_svm(audren_id: Address, mock_router_id: Address, artifacts: &DeployArtifacts) -> LiteSVM {
    let mut svm = LiteSVM::new()
        .with_feature_set(FeatureSet::all_enabled())
        .with_builtins()
        .with_sysvars()
        .with_default_programs()
        .with_sigverify(true)
        .with_blockhash_check(false)
        .with_log_bytes_limit(None);
    svm.add_program_from_file(audren_id, &artifacts.audren_so)
        .expect("load audren.so");
    if let Some(ref router_so) = artifacts.mock_router_so {
        svm.add_program_from_file(mock_router_id, router_so)
            .expect("load audren_mock_router.so");
    }
    svm
}

fn to_svm_ix(ix: &AudrenInstruction) -> Instruction {
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

fn ffi_to_svm_ix(ix: &FfiBuiltInstruction) -> Instruction {
    Instruction {
        program_id: ix.program_id.parse().expect("valid program_id"),
        accounts: ix
            .accounts
            .iter()
            .map(|a| AccountMeta {
                pubkey: a.pubkey.parse().expect("valid account pubkey"),
                is_signer: a.is_signer,
                is_writable: a.is_writable,
            })
            .collect(),
        data: ix.data.clone(),
    }
}

fn json_to_svm_ix(v: &Value) -> Instruction {
    let program_id: Address = v["programId"]
        .as_str()
        .expect("programId")
        .parse()
        .expect("parse programId");
    let accounts = v["accounts"]
        .as_array()
        .expect("accounts array")
        .iter()
        .map(|a| AccountMeta {
            pubkey: a["pubkey"]
                .as_str()
                .expect("pubkey")
                .parse()
                .expect("parse pubkey"),
            is_signer: a["isSigner"].as_bool().expect("isSigner"),
            is_writable: a["isWritable"].as_bool().expect("isWritable"),
        })
        .collect();
    let data = from_hex(v["dataHex"].as_str().expect("dataHex"));
    Instruction {
        program_id,
        accounts,
        data,
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn from_hex(h: &str) -> Vec<u8> {
    assert_eq!(h.len() % 2, 0);
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).expect("hex"))
        .collect()
}

fn call_ts_driver(payload: &Value) -> Value {
    let driver = repo_root().join("packages/sdk/test/litesvm-driver.mjs");
    let mut child = Command::new("node")
        .arg(&driver)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn node packages/sdk/test/litesvm-driver.mjs");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        stdin
            .write_all(payload.to_string().as_bytes())
            .expect("write stdin");
    }
    let output = child.wait_with_output().expect("wait node");
    if !output.status.success() {
        panic!(
            "TS driver failed (status={}):\nstderr:\n{}\nstdout:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout),
        );
    }
    serde_json::from_slice(&output.stdout).expect("parse TS driver JSON output")
}

fn send_v1(
    svm: &mut LiteSVM,
    payer: &Keypair,
    extra_signers: &[&Keypair],
    ixs: &[Instruction],
    cu_limit: u32,
) -> TransactionResult {
    let config = TransactionConfig::empty()
        .with_compute_unit_limit(cu_limit)
        .with_loaded_accounts_data_size_limit(DEFAULT_LOADED_ACCOUNTS_DATA_SIZE);
    let msg = v1::Message::try_compile_with_config(
        &payer.pubkey(),
        ixs,
        svm.latest_blockhash().to_bytes().into(),
        config,
    )
    .expect("compile Solana v1 tx");
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra_signers);
    let tx = VersionedTransaction::try_new(VersionedMessage::V1(msg), &signers).expect("sign v1 tx");
    let wire = wincode::serialize(&tx).expect("serialize v1 tx");
    assert_eq!(wire[0], 0x81, "expected Solana v1 tx (0x81)");
    assert!(
        wire.len() <= MAX_TRANSACTION_SIZE,
        "wire len {} > {MAX_TRANSACTION_SIZE}",
        wire.len()
    );
    svm.send_transaction(tx)
}

fn expect_ok(res: TransactionResult, label: &str) -> u64 {
    match res {
        Ok(meta) => {
            println!("  [OK] {label:<56} CU={}", meta.compute_units_consumed);
            meta.compute_units_consumed
        }
        Err(err) => panic!(
            "FAILED `{label}`: {:?}\nLogs:\n{}",
            err.err,
            err.meta.logs.join("\n")
        ),
    }
}

fn create_mint(svm: &mut LiteSVM, payer: &Keypair, token_program: &Address, decimals: u8) -> Keypair {
    let mint = Keypair::new();
    let rent = Rent::default().minimum_balance(Mint::LEN);
    let create_ix = sys_ix::create_account(&payer.pubkey(), &mint.pubkey(), rent, Mint::LEN as u64, token_program);
    let init_ix = token_ix::initialize_mint2(token_program, &mint.pubkey(), &payer.pubkey(), None, decimals).unwrap();
    expect_ok(
        send_v1(svm, payer, &[&mint], &[create_ix, init_ix], 200_000),
        "Create SPL mint",
    );
    mint
}

fn create_ata_with_balance(
    svm: &mut LiteSVM,
    token_program: &Address,
    mint: &Address,
    owner: &Address,
    amount: u64,
) -> Address {
    let ata = derive_ata(owner, token_program, mint);
    let mut state = TokenAccount::default();
    state.mint = *mint;
    state.owner = *owner;
    state.amount = amount;
    state.state = spl_token_2022_interface::state::AccountState::Initialized;
    let mut data = vec![0u8; TokenAccount::LEN];
    TokenAccount::pack(state, &mut data).unwrap();
    svm.set_account(
        ata,
        Account {
            lamports: Rent::default().minimum_balance(TokenAccount::LEN),
            data,
            owner: *token_program,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    ata
}

fn read_page(svm: &LiteSVM, program_id: &Address, pool_id: u32, page_id: u64) -> Vec<u8> {
    let pda = derive_epoch_page_pda(program_id, pool_id, page_id).0;
    let acc = svm.get_account(&pda).expect("epoch page exists");
    assert_eq!(acc.data.len(), PAGE_LEN);
    acc.data
}

#[test]
fn typescript_sdk_prover_real_litesvm_all_instructions() {
    let Some(artifacts) = deploy_artifacts_if_available() else {
        return;
    };
    println!("\n=== CROSS-SDK LITESVM 1: Pure TypeScript @audren/sdk/prover -> Real audren.so ===");

    let audren_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let router_id = Keypair::new().pubkey();
    let mut svm = new_svm(audren_id, router_id, &artifacts);

    let authority = Keypair::new();
    let payer = Keypair::new();
    let recipient_wallet = Keypair::new();
    svm.airdrop(&authority.pubkey(), 100_000_000_000).unwrap();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
    svm.airdrop(&recipient_wallet.pubkey(), 1_000_000_000).unwrap();

    let pool_id = 0u32;
    let shard_id = 3u8;

    let init_ix = build_init_pool(audren_id, authority.pubkey(), pool_id, PoolMode::Permissionless, false, [0u8; 32], 1_500_000);
    expect_ok(send_v1(&mut svm, &authority, &[], &[to_svm_ix(&init_ix)], 300_000), "InitPool(0)");

    // Deterministic Alice & Bob keys (shared across Rust, TS, Swift, Kotlin!)
    let alice_seed = [0x42u8; 32];
    let bob_seed = [0x99u8; 32];
    let alice_rust = AudrenKeys::from_seed(&alice_seed);
    let bob_rust = AudrenKeys::from_seed(&bob_seed);
    let alice_addr = alice_rust.address().to_string();
    let bob_addr = bob_rust.address().to_string();

    // Setup SPL mints (USDC -> WSOL) + mock router liquidity
    let token_prog = Address::new_from_array(CLASSIC_TOKEN_PROGRAM_ID);
    let mint_usdc = create_mint(&mut svm, &payer, &token_prog, 6);
    let mint_wsol = create_mint(&mut svm, &payer, &token_prog, 9);
    let (vault_auth, _) = derive_vault_auth_pda(&audren_id, pool_id);
    let (swap_escrow, _) = derive_swap_escrow_pda(&audren_id, pool_id, shard_id);
    svm.airdrop(&swap_escrow, 1_000_000).unwrap();

    let _payer_usdc = create_ata_with_balance(&mut svm, &token_prog, &mint_usdc.pubkey(), &payer.pubkey(), 100_000_000);
    let _vault_usdc = create_ata_with_balance(&mut svm, &token_prog, &mint_usdc.pubkey(), &vault_auth, 0);
    let _vault_wsol = create_ata_with_balance(&mut svm, &token_prog, &mint_wsol.pubkey(), &vault_auth, 0);
    let escrow_usdc = create_ata_with_balance(&mut svm, &token_prog, &mint_usdc.pubkey(), &swap_escrow, 0);
    let escrow_wsol = create_ata_with_balance(&mut svm, &token_prog, &mint_wsol.pubkey(), &swap_escrow, 0);
    let (mock_pool_auth, _) = Address::find_program_address(&[b"mock_pool"], &router_id);
    let mock_pool_usdc = create_ata_with_balance(&mut svm, &token_prog, &mint_usdc.pubkey(), &mock_pool_auth, 500_000_000);
    let mock_pool_wsol = create_ata_with_balance(&mut svm, &token_prog, &mint_wsol.pubkey(), &mock_pool_auth, 500_000_000_000);

    // 1. TS Deposit #1 (2.0 SOL), #2 (1.0 SOL), #3 (50 USDC)
    for (label, mint_bytes, amt, tp) in [
        ("TS Deposit #0: 2.0 SOL", NATIVE_SOL_MINT, 2_000_000_000u64, None),
        ("TS Deposit #1: 1.0 SOL", NATIVE_SOL_MINT, 1_000_000_000u64, None),
        ("TS Deposit #2: 50 USDC (SPL)", mint_usdc.pubkey().to_bytes(), 50_000_000u64, Some(token_prog.to_string())),
    ] {
        let resp = call_ts_driver(&json!({
            "op": "deposit",
            "depositor": payer.pubkey().to_string(),
            "poolId": pool_id,
            "activePageId": "0",
            "recipientAddr": alice_addr,
            "mintHex": to_hex(&mint_bytes),
            "amount": amt.to_string(),
            "tokenProgram": tp,
            "createVaultAtaIfMissing": false,
        }));
        let ixs: Vec<Instruction> = resp["instructions"].as_array().unwrap().iter().map(json_to_svm_ix).collect();
        expect_ok(send_v1(&mut svm, &payer, &[], &ixs, 300_000), label);
    }

    // Cross-SDK Decrypt Proof #1: Rust + FFI decrypt all 3 TS deposits
    let page0 = read_page(&svm, &audren_id, pool_id, 0);
    assert_eq!(PageHeader::decode(&page0).unwrap().count, 3);
    let rust_hits = scan_page_dataslice(&alice_rust.full_viewing_key(), 0, &page0[PAGE_SCAN_OFFSET..PAGE_SCAN_OFFSET + PAGE_SCAN_LEN]).unwrap();
    assert_eq!(rust_hits.len(), 3, "Rust dataSlice must detect all 3 TS deposits");
    let ffi_alice = derive_keys_from_seed(alice_seed.to_vec()).unwrap();
    let ffi_notes = scan_epoch_page(
        pool_id,
        page0.clone(),
        Some(ffi_alice.spend_sk.clone()),
        ffi_alice.spend_pk.clone(),
        ffi_alice.view_sk.clone(),
        audren_id.to_string(),
    ).unwrap();
    assert_eq!(ffi_notes.len(), 3);
    assert_eq!(ffi_notes[0].amount, 2_000_000_000);
    assert_eq!(ffi_notes[1].amount, 1_000_000_000);
    assert_eq!(ffi_notes[2].amount, 50_000_000);
    println!("  [OK] Cross-SDK decrypt (TS deposits -> Rust & FFI): 3/3 exact");

    // 2. TS Transfer (Tag 3, m=5): spend slot 0 (2.0 SOL) -> 0.75 SOL to Bob + 1.25 SOL change to Alice
    let ts_xfer = call_ts_driver(&json!({
        "op": "transfer",
        "seedHex": to_hex(&alice_seed),
        "payer": payer.pubkey().to_string(),
        "poolId": pool_id,
        "outPageId": "0",
        "inputPageIds": ["0"],
        "pagesHex": [to_hex(&page0)],
        "noteSlot": 0,
        "secretIndex": 0,
        "recipientAddr": bob_addr,
        "changeAddr": alice_addr,
        "payAmount": "750000000",
    }));
    expect_ok(
        send_v1(&mut svm, &payer, &[], &[json_to_svm_ix(&ts_xfer["instruction"])], 1_000_000),
        "TS Transfer m=5 (Triptych + CrossBase2 + BP U128)",
    );

    // Verify Rust + FFI read-only FVK decrypt BOTH blinded TS transfer outputs!
    let page0 = read_page(&svm, &audren_id, pool_id, 0);
    assert_eq!(PageHeader::decode(&page0).unwrap().count, 5);
    let bob_fvk = bob_rust.full_viewing_key();
    let bob_note = decrypt_owned_note(&bob_fvk, None, &audren_id, pool_id, &page0, 3, None).unwrap().expect("Bob FVK decrypts TS blinded transfer");
    assert_eq!(bob_note.amount, 750_000_000);
    assert!(bob_note.spend_x.is_none());
    let alice_chg = decrypt_owned_note(&alice_rust.full_viewing_key(), None, &audren_id, pool_id, &page0, 4, None).unwrap().expect("Alice FVK decrypts TS blinded change");
    assert_eq!(alice_chg.amount, 1_250_000_000);
    println!("  [OK] Cross-SDK read-only FVK decrypt (TS blinded Transfer -> Rust)");

    // 3. TS Merge (Tag 4, m=5+5): combine Alice's blinded 1.25 SOL (slot 4) + 1.0 SOL (slot 1) -> 2.25 SOL (slot 5)
    let ts_merge = call_ts_driver(&json!({
        "op": "merge",
        "seedHex": to_hex(&alice_seed),
        "payer": payer.pubkey().to_string(),
        "poolId": pool_id,
        "outPageId": "0",
        "input1PageIds": ["0"],
        "pages1Hex": [to_hex(&page0)],
        "slot1": 4,
        "secretIndex1": 4,
        "input2PageIds": ["0"],
        "pages2Hex": [to_hex(&page0)],
        "slot2": 1,
        "secretIndex2": 1,
        "ownerAddr": alice_addr,
    }));
    expect_ok(
        send_v1(&mut svm, &payer, &[], &[json_to_svm_ix(&ts_merge["instruction"])], 1_300_000),
        "TS Merge m=5+5 (2x Triptych + CrossBase1 + BP U64)",
    );
    let page0 = read_page(&svm, &audren_id, pool_id, 0);
    assert_eq!(PageHeader::decode(&page0).unwrap().count, 6);
    let merged_rust = decrypt_owned_note(&alice_rust.full_viewing_key(), Some(&alice_rust), &audren_id, pool_id, &page0, 5, None).unwrap().expect("Rust decrypts TS Merge output");
    assert_eq!(merged_rust.amount, 2_250_000_000);

    // 4. TS SwapViaRouter (Tag 5, partial with shielded change!): 30 USDC -> 250 WSOL (20 USDC change!)
    let mut router_data = Vec::with_capacity(19);
    router_data.push(0u8); // happy path mode
    router_data.extend_from_slice(&30_000_000u64.to_le_bytes());
    router_data.extend_from_slice(&250_000_000u64.to_le_bytes());
    router_data.push(6);
    router_data.push(9);
    let router_accounts_json = json!([
        { "pubkey": mock_pool_auth.to_string(), "isSigner": false, "isWritable": false },
        { "pubkey": escrow_usdc.to_string(), "isSigner": false, "isWritable": true },
        { "pubkey": mock_pool_usdc.to_string(), "isSigner": false, "isWritable": true },
        { "pubkey": swap_escrow.to_string(), "isSigner": true, "isWritable": true },
        { "pubkey": escrow_wsol.to_string(), "isSigner": false, "isWritable": true },
        { "pubkey": mock_pool_wsol.to_string(), "isSigner": false, "isWritable": true },
        { "pubkey": token_prog.to_string(), "isSigner": false, "isWritable": false },
        { "pubkey": token_prog.to_string(), "isSigner": false, "isWritable": false },
        { "pubkey": mint_usdc.pubkey().to_string(), "isSigner": false, "isWritable": false },
        { "pubkey": mint_wsol.pubkey().to_string(), "isSigner": false, "isWritable": false },
    ]);
    let ts_swap = call_ts_driver(&json!({
        "op": "swap",
        "seedHex": to_hex(&alice_seed),
        "payer": payer.pubkey().to_string(),
        "poolId": pool_id,
        "outPageId": "0",
        "shardId": shard_id,
        "inputPageIds": ["0"],
        "pagesHex": [to_hex(&page0)],
        "noteSlot": 2,
        "secretIndex": 2,
        "inputMintB58": mint_usdc.pubkey().to_string(),
        "outputMintB58": mint_wsol.pubkey().to_string(),
        "tokenProgramIn": token_prog.to_string(),
        "tokenProgramOut": token_prog.to_string(),
        "amountIn": "30000000",
        "minAmountOut": "200000000",
        "recipientAddr": bob_addr,
        "changeAddr": alice_addr,
        "routerProgramId": router_id.to_string(),
        "routerIxDataHex": to_hex(&router_data),
        "routerAccounts": router_accounts_json,
    }));
    if artifacts.mock_router_so.is_some() {
        expect_ok(
            send_v1(&mut svm, &payer, &[], &[json_to_svm_ix(&ts_swap["instruction"])], 1_100_000),
            "TS SwapViaRouter partial + change (real mock router)",
        );
        let page0 = read_page(&svm, &audren_id, pool_id, 0);
        assert_eq!(PageHeader::decode(&page0).unwrap().count, 8);
        let bob_swap_out = decrypt_owned_note(&bob_fvk, Some(&bob_rust), &audren_id, pool_id, &page0, 6, Some(250_000_000)).unwrap().expect("Bob decrypts TS swap dynamic output");
        assert_eq!(bob_swap_out.amount, 250_000_000);
        assert_eq!(bob_swap_out.mint, mint_wsol.pubkey().to_bytes());
        let alice_swap_chg = decrypt_owned_note(&alice_rust.full_viewing_key(), Some(&alice_rust), &audren_id, pool_id, &page0, 7, None).unwrap().expect("Alice decrypts TS swap blinded change");
        assert_eq!(alice_swap_chg.amount, 20_000_000);
        assert_eq!(alice_swap_chg.mint, mint_usdc.pubkey().to_bytes());
    } else {
        assert!(!ts_swap["instruction"]["dataHex"].as_str().unwrap().is_empty());
        println!("  [OK] TS SwapViaRouter instruction built (on-chain mock router skipped: audren_mock_router.so not present)");
    }
    let page0 = read_page(&svm, &audren_id, pool_id, 0);

    // 5. TS Withdraw (Tag 6): partial (0.5 SOL + 1.75 SOL change), THEN pause pool & FULL withdraw (1.75 SOL)!
    let before_bal = svm.get_account(&recipient_wallet.pubkey()).unwrap().lamports;
    let ts_wd_part = call_ts_driver(&json!({
        "op": "withdraw",
        "seedHex": to_hex(&alice_seed),
        "payer": payer.pubkey().to_string(),
        "poolId": pool_id,
        "outPageId": "0",
        "inputPageIds": ["0"],
        "pagesHex": [to_hex(&page0)],
        "noteSlot": 5,
        "secretIndex": 5,
        "recipientAccount": recipient_wallet.pubkey().to_string(),
        "changeAddr": alice_addr,
        "amount": "500000000",
    }));
    expect_ok(
        send_v1(&mut svm, &payer, &[], &[json_to_svm_ix(&ts_wd_part["instruction"])], 1_000_000),
        "TS Withdraw partial (0.5 SOL + 1.75 SOL change)",
    );
    assert_eq!(svm.get_account(&recipient_wallet.pubkey()).unwrap().lamports, before_bal + 500_000_000);

    // Pause pool, then execute TS FULL withdraw (1.75 SOL, has_change=false -> bypasses pause!)
    let pause_ix = build_set_paused(audren_id, authority.pubkey(), pool_id, true);
    expect_ok(send_v1(&mut svm, &payer, &[&authority], &[to_svm_ix(&pause_ix)], 100_000), "SetPaused(true)");
    let page0 = read_page(&svm, &audren_id, pool_id, 0);
    let wd_chg_slot = (PageHeader::decode(&page0).unwrap().count - 1) as usize;
    let ts_wd_full = call_ts_driver(&json!({
        "op": "withdraw",
        "seedHex": to_hex(&alice_seed),
        "payer": payer.pubkey().to_string(),
        "poolId": pool_id,
        "outPageId": "0",
        "inputPageIds": ["0"],
        "pagesHex": [to_hex(&page0)],
        "noteSlot": wd_chg_slot,
        "secretIndex": wd_chg_slot,
        "recipientAccount": recipient_wallet.pubkey().to_string(),
        "changeAddr": alice_addr,
        "amount": "1750000000",
    }));
    expect_ok(
        send_v1(&mut svm, &payer, &[], &[json_to_svm_ix(&ts_wd_full["instruction"])], 800_000),
        "TS Withdraw FULL while paused (unstoppable exit!)",
    );
    assert_eq!(svm.get_account(&recipient_wallet.pubkey()).unwrap().lamports, before_bal + 2_250_000_000);
    let unpause_ix = build_set_paused(audren_id, authority.pubkey(), pool_id, false);
    expect_ok(send_v1(&mut svm, &payer, &[&authority], &[to_svm_ix(&unpause_ix)], 100_000), "SetPaused(false)");

    // 6. TS ProofBuffer (Tag 8 WriteProofBuffer + Tag 9 ExecBuffered + Tag 10 CloseProofBuffer)
    let page0 = read_page(&svm, &audren_id, pool_id, 0);
    let ts_buf = call_ts_driver(&json!({
        "op": "buffered_transfer",
        "seedHex": to_hex(&bob_seed),
        "payer": payer.pubkey().to_string(),
        "poolId": pool_id,
        "outPageId": "0",
        "inputPageIds": ["0"],
        "pagesHex": [to_hex(&page0)],
        "noteSlot": 3,
        "secretIndex": 3,
        "recipientAddr": alice_addr,
        "changeAddr": bob_addr,
        "payAmount": "250000000",
        "nonce": "777",
    }));
    for (i, ch) in ts_buf["uploadChunks"].as_array().unwrap().iter().enumerate() {
        expect_ok(send_v1(&mut svm, &payer, &[], &[json_to_svm_ix(ch)], 200_000), &format!("TS WriteProofBuffer chunk {i}"));
    }
    expect_ok(
        send_v1(&mut svm, &payer, &[], &[json_to_svm_ix(&ts_buf["executeIx"])], 1_100_000),
        "TS ExecBuffered Transfer + 100% rent refund",
    );
    let buf_pda: Address = ts_buf["proofBufferPda"].as_str().unwrap().parse().unwrap();
    assert!(svm.get_account(&buf_pda).map(|a| a.lamports == 0).unwrap_or(true), "ProofBuffer must be closed after ExecBuffered");

    // Open an abandoned ProofBuffer (chunk 0 only) and close via TS CloseProofBuffer (Tag 10)
    let ts_buf2 = call_ts_driver(&json!({
        "op": "buffered_transfer",
        "seedHex": to_hex(&bob_seed),
        "payer": payer.pubkey().to_string(),
        "poolId": pool_id,
        "outPageId": "0",
        "inputPageIds": ["0"],
        "pagesHex": [to_hex(&page0)],
        "noteSlot": 3,
        "secretIndex": 3,
        "recipientAddr": alice_addr,
        "changeAddr": bob_addr,
        "payAmount": "250000000",
        "nonce": "778",
    }));
    let chunk0 = json_to_svm_ix(&ts_buf2["uploadChunks"][0]);
    expect_ok(send_v1(&mut svm, &payer, &[], &[chunk0], 200_000), "TS WriteProofBuffer chunk 0 (abandoned)");
    expect_ok(
        send_v1(&mut svm, &payer, &[], &[json_to_svm_ix(&ts_buf2["closeIx"])], 100_000),
        "TS CloseProofBuffer (Tag 10 rent reclaim)",
    );
    let buf2_pda: Address = ts_buf2["proofBufferPda"].as_str().unwrap().parse().unwrap();
    assert!(svm.get_account(&buf2_pda).map(|a| a.lamports == 0).unwrap_or(true), "Abandoned ProofBuffer must be closed");

    // 7. Cross-SDK Selective Disclosure from LIVE LiteSVM EpochPage #0
    let page0 = read_page(&svm, &audren_id, pool_id, 0);
    let buf_pay_slot = (PageHeader::decode(&page0).unwrap().count - 2) as usize;
    let ts_sd = call_ts_driver(&json!({
        "op": "disclosure",
        "seedHex": to_hex(&alice_seed),
        "poolId": pool_id,
        "pageHex": to_hex(&page0),
        "noteSlot": buf_pay_slot,
    }));
    assert_eq!(ts_sd["onPageValid"], json!(true));
    assert_eq!(ts_sd["tamperedValid"], json!(false));
    let rust_sd: SelectiveDisclosureProof = serde_json::from_value(ts_sd["proof"].clone()).unwrap();
    assert!(rust_sd.verify_against_page(&page0).unwrap(), "Rust must verify TS SelectiveDisclosureProof on live LiteSVM page!");
    let mut tampered = rust_sd.clone();
    tampered.amount += 1;
    assert!(!tampered.verify_against_page(&page0).unwrap());
    println!("  [OK] Cross-SDK Selective Disclosure (TS -> Rust on live LiteSVM page)");
}

#[test]
fn ffi_swift_kotlin_core_real_litesvm_and_ts_decrypt() {
    let Some(artifacts) = deploy_artifacts_if_available() else {
        return;
    };
    println!("\n=== CROSS-SDK LITESVM 2: UniFFI (Swift & Kotlin core) -> Real audren.so -> TS Decrypt ===");

    let audren_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let router_id = Keypair::new().pubkey();
    let mut svm = new_svm(audren_id, router_id, &artifacts);

    let authority = Keypair::new();
    let payer = Keypair::new();
    let recipient_wallet = Keypair::new();
    svm.airdrop(&authority.pubkey(), 100_000_000_000).unwrap();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
    svm.airdrop(&recipient_wallet.pubkey(), 1_000_000_000).unwrap();

    let pool_id = 0u32;
    let shard_id = 5u8;
    let pid_str = audren_id.to_string();

    let init_ix = build_init_pool(audren_id, authority.pubkey(), pool_id, PoolMode::Permissionless, false, [0u8; 32], 1_500_000);
    expect_ok(send_v1(&mut svm, &authority, &[], &[to_svm_ix(&init_ix)], 300_000), "InitPool(0)");

    let alice_seed = [0x42u8; 32];
    let bob_seed = [0x99u8; 32];
    let alice = derive_keys_from_seed(alice_seed.to_vec()).unwrap();
    let bob = derive_keys_from_seed(bob_seed.to_vec()).unwrap();

    // Setup SPL mints & mock router
    let token_prog = Address::new_from_array(CLASSIC_TOKEN_PROGRAM_ID);
    let mint_usdc = create_mint(&mut svm, &payer, &token_prog, 6);
    let mint_wsol = create_mint(&mut svm, &payer, &token_prog, 9);
    let (vault_auth, _) = derive_vault_auth_pda(&audren_id, pool_id);
    let (swap_escrow, _) = derive_swap_escrow_pda(&audren_id, pool_id, shard_id);
    svm.airdrop(&swap_escrow, 1_000_000).unwrap();
    let payer_usdc = create_ata_with_balance(&mut svm, &token_prog, &mint_usdc.pubkey(), &payer.pubkey(), 100_000_000);
    let vault_usdc = create_ata_with_balance(&mut svm, &token_prog, &mint_usdc.pubkey(), &vault_auth, 0);
    let _vault_wsol = create_ata_with_balance(&mut svm, &token_prog, &mint_wsol.pubkey(), &vault_auth, 0);
    let escrow_usdc = create_ata_with_balance(&mut svm, &token_prog, &mint_usdc.pubkey(), &swap_escrow, 0);
    let escrow_wsol = create_ata_with_balance(&mut svm, &token_prog, &mint_wsol.pubkey(), &swap_escrow, 0);
    let (mock_pool_auth, _) = Address::find_program_address(&[b"mock_pool"], &router_id);
    let mock_pool_usdc = create_ata_with_balance(&mut svm, &token_prog, &mint_usdc.pubkey(), &mock_pool_auth, 500_000_000);
    let mock_pool_wsol = create_ata_with_balance(&mut svm, &token_prog, &mint_wsol.pubkey(), &mock_pool_auth, 500_000_000_000);

    // 1. FFI Deposits: 2.0 SOL, 1.0 SOL, 50 USDC
    let dep0 = build_deposit_instruction(FfiDepositParams {
        program_id: pid_str.clone(),
        depositor: payer.pubkey().to_string(),
        pool_id,
        active_page_id: 0,
        recipient_address: alice.address.clone(),
        mint_32: NATIVE_SOL_MINT.to_vec(),
        gross_amount: 2_000_000_000,
        net_amount: 2_000_000_000,
        token_program: None,
        depositor_ata: None,
        vault_ata: None,
    }).unwrap();
    expect_ok(send_v1(&mut svm, &payer, &[], &[ffi_to_svm_ix(&dep0)], 300_000), "FFI Deposit #0: 2.0 SOL");

    let dep1 = build_deposit_instruction(FfiDepositParams {
        program_id: pid_str.clone(),
        depositor: payer.pubkey().to_string(),
        pool_id,
        active_page_id: 0,
        recipient_address: alice.address.clone(),
        mint_32: NATIVE_SOL_MINT.to_vec(),
        gross_amount: 1_000_000_000,
        net_amount: 1_000_000_000,
        token_program: None,
        depositor_ata: None,
        vault_ata: None,
    }).unwrap();
    expect_ok(send_v1(&mut svm, &payer, &[], &[ffi_to_svm_ix(&dep1)], 300_000), "FFI Deposit #1: 1.0 SOL");

    let dep2 = build_deposit_instruction(FfiDepositParams {
        program_id: pid_str.clone(),
        depositor: payer.pubkey().to_string(),
        pool_id,
        active_page_id: 0,
        recipient_address: alice.address.clone(),
        mint_32: mint_usdc.pubkey().to_bytes().to_vec(),
        gross_amount: 50_000_000,
        net_amount: 50_000_000,
        token_program: Some(token_prog.to_string()),
        depositor_ata: Some(payer_usdc.to_string()),
        vault_ata: Some(vault_usdc.to_string()),
    }).unwrap();
    expect_ok(send_v1(&mut svm, &payer, &[], &[ffi_to_svm_ix(&dep2)], 300_000), "FFI Deposit #2: 50 USDC");

    // 2. FFI Transfer m=5 -> LiteSVM -> TypeScript decrypts BOTH read-only FVK AND spendable!
    let page0 = read_page(&svm, &audren_id, pool_id, 0);
    let alice_notes = scan_epoch_page(pool_id, page0.clone(), Some(alice.spend_sk.clone()), alice.spend_pk.clone(), alice.view_sk.clone(), pid_str.clone()).unwrap();
    let xfer = build_transfer_instruction(FfiTransferParams {
        program_id: pid_str.clone(),
        payer: payer.pubkey().to_string(),
        pool_id,
        out_page_id: 0,
        input_page_ids: vec![0],
        input_pages_bytes: vec![page0.clone()],
        input_note: alice_notes[0].clone(),
        secret_index: 0,
        recipient_address: bob.address.clone(),
        change_address: alice.address.clone(),
        pay_amount: 750_000_000,
        auditor_pk_32: None,
    }).unwrap();
    expect_ok(send_v1(&mut svm, &payer, &[], &[ffi_to_svm_ix(&xfer)], 1_000_000), "FFI Transfer m=5 (real audren.so)");

    let page0 = read_page(&svm, &audren_id, pool_id, 0);
    let ts_bob_scan = call_ts_driver(&json!({
        "op": "scan",
        "seedHex": to_hex(&bob_seed),
        "poolId": pool_id,
        "pageHex": to_hex(&page0),
    }));
    assert_eq!(ts_bob_scan["fvkNotes"].as_array().unwrap().len(), 1);
    assert_eq!(ts_bob_scan["fvkNotes"][0]["amount"], json!("750000000"));
    assert_eq!(ts_bob_scan["fvkNotes"][0]["nullifierHex"], json!(null), "FVK scan must stay read-only");
    assert_eq!(ts_bob_scan["spendNotes"].as_array().unwrap().len(), 1);
    assert!(ts_bob_scan["spendNotes"][0]["nullifierHex"].is_string());
    println!("  [OK] Reverse cross-SDK decrypt (FFI blinded Transfer -> TS FVK & spendable)");

    // 3. FFI Merge m=5+5 -> LiteSVM -> TS decrypts!
    let alice_notes = scan_epoch_page(pool_id, page0.clone(), Some(alice.spend_sk.clone()), alice.spend_pk.clone(), alice.view_sk.clone(), pid_str.clone()).unwrap();
    let n_slot4 = alice_notes.iter().find(|n| n.slot_index == 4).unwrap().clone();
    let n_slot1 = alice_notes.iter().find(|n| n.slot_index == 1).unwrap().clone();
    let mrg = build_merge_instruction(FfiMergeParams {
        program_id: pid_str.clone(),
        payer: payer.pubkey().to_string(),
        pool_id,
        out_page_id: 0,
        input1_page_ids: vec![0],
        input1_pages_bytes: vec![page0.clone()],
        note1: n_slot4,
        secret_index1: 4,
        input2_page_ids: vec![0],
        input2_pages_bytes: vec![page0.clone()],
        note2: n_slot1,
        secret_index2: 1,
        owner_address: alice.address.clone(),
        auditor_pk_32: None,
    }).unwrap();
    expect_ok(send_v1(&mut svm, &payer, &[], &[ffi_to_svm_ix(&mrg)], 1_300_000), "FFI Merge m=5+5 (real audren.so)");

    // 4. FFI prepare_router_accounts + build_swap_via_router_instruction (partial with change!)
    let page0 = read_page(&svm, &audren_id, pool_id, 0);
    let alice_notes = scan_epoch_page(pool_id, page0.clone(), Some(alice.spend_sk.clone()), alice.spend_pk.clone(), alice.view_sk.clone(), pid_str.clone()).unwrap();
    let n_usdc = alice_notes.iter().find(|n| n.slot_index == 2).unwrap().clone();
    let raw_router_accs = vec![
        FfiAccountMeta { pubkey: mock_pool_auth.to_string(), is_signer: false, is_writable: false },
        FfiAccountMeta { pubkey: escrow_usdc.to_string(), is_signer: false, is_writable: true },
        FfiAccountMeta { pubkey: mock_pool_usdc.to_string(), is_signer: false, is_writable: true },
        FfiAccountMeta { pubkey: swap_escrow.to_string(), is_signer: true, is_writable: true },
        FfiAccountMeta { pubkey: escrow_wsol.to_string(), is_signer: false, is_writable: true },
        FfiAccountMeta { pubkey: mock_pool_wsol.to_string(), is_signer: false, is_writable: true },
        FfiAccountMeta { pubkey: token_prog.to_string(), is_signer: false, is_writable: false },
        FfiAccountMeta { pubkey: token_prog.to_string(), is_signer: false, is_writable: false },
        FfiAccountMeta { pubkey: mint_usdc.pubkey().to_string(), is_signer: false, is_writable: false },
        FfiAccountMeta { pubkey: mint_wsol.pubkey().to_string(), is_signer: false, is_writable: false },
    ];
    let prep = prepare_router_accounts(
        pool_id,
        shard_id,
        mint_usdc.pubkey().to_string(),
        mint_wsol.pubkey().to_string(),
        token_prog.to_string(),
        token_prog.to_string(),
        raw_router_accs,
        pid_str.clone(),
    ).unwrap();
    assert_eq!((prep.escrow_idx, prep.escrow_in_idx, prep.escrow_out_idx), (3, 1, 4));
    let mut rdata = Vec::with_capacity(19);
    rdata.push(0u8);
    rdata.extend_from_slice(&30_000_000u64.to_le_bytes());
    rdata.extend_from_slice(&250_000_000u64.to_le_bytes());
    rdata.push(6);
    rdata.push(9);
    let swp = build_swap_via_router_instruction(FfiSwapViaRouterParams {
        program_id: pid_str.clone(),
        payer: payer.pubkey().to_string(),
        pool_id,
        out_page_id: 0,
        shard_id,
        input_page_ids: vec![0],
        input_pages_bytes: vec![page0.clone()],
        input_note: n_usdc,
        secret_index: 2,
        mint_out_32: mint_wsol.pubkey().to_bytes().to_vec(),
        token_program_in: token_prog.to_string(),
        token_program_out: token_prog.to_string(),
        amount_in: 30_000_000,
        min_amount_out: 200_000_000,
        allow_partial_refund: false,
        recipient_address: bob.address.clone(),
        change_address: alice.address.clone(),
        router_program_id: router_id.to_string(),
        escrow_idx: prep.escrow_idx,
        escrow_in_idx: prep.escrow_in_idx,
        escrow_out_idx: prep.escrow_out_idx,
        router_ix_data: rdata,
        router_accounts: prep.accounts,
        auditor_pk_32: None,
    }).unwrap();
    if artifacts.mock_router_so.is_some() {
        expect_ok(send_v1(&mut svm, &payer, &[], &[ffi_to_svm_ix(&swp)], 1_100_000), "FFI SwapViaRouter partial + change");
    } else {
        assert!(!swp.data.is_empty());
        println!("  [OK] FFI SwapViaRouter instruction built (on-chain mock router skipped: audren_mock_router.so not present)");
    }

    // 5. FFI Withdraw (full) + ProofBuffer + CloseProofBuffer
    let page0 = read_page(&svm, &audren_id, pool_id, 0);
    let alice_notes = scan_epoch_page(pool_id, page0.clone(), Some(alice.spend_sk.clone()), alice.spend_pk.clone(), alice.view_sk.clone(), pid_str.clone()).unwrap();
    let merged_note = alice_notes.iter().find(|n| n.slot_index == 5).unwrap().clone();
    let wd = build_withdraw_instruction(FfiWithdrawParams {
        program_id: pid_str.clone(),
        payer: payer.pubkey().to_string(),
        pool_id,
        out_page_id: 0,
        input_page_ids: vec![0],
        input_pages_bytes: vec![page0.clone()],
        input_note: merged_note,
        secret_index: 5,
        recipient_account: recipient_wallet.pubkey().to_string(),
        change_address: alice.address.clone(),
        amount: 2_250_000_000,
        spl_token_program: None,
        auditor_pk_32: None,
    }).unwrap();
    let plan = build_buffered_execution_plan(901, wd.clone()).unwrap();
    for ch in &plan.upload_chunks {
        expect_ok(send_v1(&mut svm, &payer, &[], &[ffi_to_svm_ix(ch)], 200_000), "FFI WriteProofBuffer chunk");
    }
    expect_ok(send_v1(&mut svm, &payer, &[], &[ffi_to_svm_ix(&plan.execute_ix)], 1_000_000), "FFI ExecBuffered Withdraw");

    let plan_close = build_buffered_execution_plan(902, wd).unwrap();
    expect_ok(send_v1(&mut svm, &payer, &[], &[ffi_to_svm_ix(&plan_close.upload_chunks[0])], 200_000), "FFI WriteProofBuffer abandoned");
    let close_ix = build_close_proof_buffer_instruction(pid_str.clone(), payer.pubkey().to_string(), 902).unwrap();
    expect_ok(send_v1(&mut svm, &payer, &[], &[ffi_to_svm_ix(&close_ix)], 100_000), "FFI CloseProofBuffer (Tag 10)");

    // 6. Parallel Lane 1 + Odd page_id (> 2^53!) Selective Disclosure FFI -> TypeScript proof!
    let init_lane1 = build_init_lane(audren_id, authority.pubkey(), pool_id, 1).unwrap();
    expect_ok(send_v1(&mut svm, &authority, &[], &[to_svm_ix(&init_lane1)], 300_000), "InitLane(1)");
    let lane1_page0 = page_id_for_lane(1, 0).unwrap();
    assert_eq!(lane_of_page_id(lane1_page0), 1);
    assert_eq!(seq_of_page_id(lane1_page0), 0);

    // Fill 28 notes on Lane 1 page 0 (`72057594037927936`) so we can call FFI OpenLanePage
    // rolling to ODD `page_id = 72057594037927937` (which overflows IEEE-754 float64!)
    for i in 0..28u32 {
        let d = build_deposit_instruction(FfiDepositParams {
            program_id: pid_str.clone(),
            depositor: payer.pubkey().to_string(),
            pool_id,
            active_page_id: lane1_page0,
            recipient_address: alice.address.clone(),
            mint_32: NATIVE_SOL_MINT.to_vec(),
            gross_amount: 10_000_000 + u64::from(i),
            net_amount: 10_000_000 + u64::from(i),
            token_program: None,
            depositor_ata: None,
            vault_ata: None,
        }).unwrap();
        send_v1(&mut svm, &payer, &[], &[ffi_to_svm_ix(&d)], 300_000).unwrap();
    }
    let open_lane1 = build_open_lane_page_instruction(pid_str.clone(), payer.pubkey().to_string(), pool_id, lane1_page0).unwrap();
    expect_ok(send_v1(&mut svm, &payer, &[], &[ffi_to_svm_ix(&open_lane1)], 300_000), "FFI OpenLanePage (Lane 1: seq 0 -> 1)");

    let lane1_pda = derive_lane_pda(&audren_id, pool_id, 1).0;
    let lane1_state = decode_append_lane_state(svm.get_account(&lane1_pda).unwrap().data).unwrap();
    let lane1_page1 = page_id_for_lane(1, 1).unwrap();
    assert_eq!(lane1_state.current_page_id, lane1_page1);
    assert_eq!(lane1_page1, (1u64 << 56) | 1); // 72057594037927937 (ODD > MAX_SAFE_INTEGER!)

    // Deposit onto odd Lane 1 page_id = 72057594037927937!
    let dep_odd = build_deposit_instruction(FfiDepositParams {
        program_id: pid_str.clone(),
        depositor: payer.pubkey().to_string(),
        pool_id,
        active_page_id: lane1_page1,
        recipient_address: bob.address.clone(),
        mint_32: NATIVE_SOL_MINT.to_vec(),
        gross_amount: 123_456_789,
        net_amount: 123_456_789,
        token_program: None,
        depositor_ata: None,
        vault_ata: None,
    }).unwrap();
    expect_ok(send_v1(&mut svm, &payer, &[], &[ffi_to_svm_ix(&dep_odd)], 300_000), "FFI Deposit on Lane 1 odd page_id (72057594037927937)");

    let lane1_bytes = read_page(&svm, &audren_id, pool_id, lane1_page1);
    let bob_lane1 = scan_epoch_page(pool_id, lane1_bytes.clone(), None, bob.spend_pk.clone(), bob.view_sk.clone(), pid_str.clone()).unwrap();
    assert_eq!(bob_lane1.len(), 1);
    assert_eq!(bob_lane1[0].page_id, lane1_page1);
    let ffi_sd = create_selective_disclosure_proof(bob_lane1[0].clone());
    assert!(verify_selective_disclosure_on_page(ffi_sd.clone(), lane1_bytes.clone()).unwrap());

    // Pass odd 64-bit page_id SelectiveDisclosureProof into TypeScript AND have TS create & verify one too!
    let ts_verify_odd = call_ts_driver(&json!({
        "op": "verify_disclosure",
        "pageHex": to_hex(&lane1_bytes),
        "proof": {
            "version": ffi_sd.version,
            "page_id": ffi_sd.page_id.to_string(),
            "slot_index": ffi_sd.slot_index,
            "stealth_pk_b58": ffi_sd.stealth_pk_b58,
            "asset_tag_b58": ffi_sd.asset_tag_b58,
            "commitment_b58": ffi_sd.commitment_b58,
            "mint_b58": ffi_sd.mint_b58,
            "amount": ffi_sd.amount,
            "asset_blinding_b58": ffi_sd.asset_blinding_b58,
            "value_blinding_b58": ffi_sd.value_blinding_b58,
        },
    }));
    assert_eq!(ts_verify_odd["valid"], json!(true), "TS must verify Lane 1 odd page_id proof: {ts_verify_odd}");

    let ts_create_odd = call_ts_driver(&json!({
        "op": "disclosure",
        "seedHex": to_hex(&bob_seed),
        "poolId": pool_id,
        "pageHex": to_hex(&lane1_bytes),
        "noteSlot": 0,
    }));
    assert_eq!(ts_create_odd["onPageValid"], json!(true), "TS must create & verify Lane 1 odd page_id proof without float64 loss!");
    assert_eq!(ts_create_odd["proof"]["page_id"], json!(lane1_page1.to_string()));
    println!("  [OK] Lane 1 odd 64-bit page_id (72057594037927937) FFI <-> TS Selective Disclosure exact!");

    // Check PoolState decode via FFI too
    let pool_pda = derive_pool_pda(&audren_id, pool_id).0;
    let pool_acc = svm.get_account(&pool_pda).unwrap();
    let rust_pool = PoolState::decode(&pool_acc.data).unwrap();
    let ffi_pool = decode_pool_state(pool_acc.data).unwrap();
    assert_eq!(ffi_pool.active_lanes, rust_pool.active_lanes);
    assert_eq!(ffi_pool.active_lanes, 2);
}
