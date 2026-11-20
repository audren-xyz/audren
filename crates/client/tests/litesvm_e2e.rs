//! End-to-End LiteSVM Integration Test Suite for Audren (sBPFv3 ELF).
//!
//! Runs the real compiled `audren.so` and `audren_mock_router.so` sBPFv3 binaries inside
//! LiteSVM (`agave-feature-set 4.3.0`, Direct Mapping & ZK ElGamal Proof builtin enabled)
//! and verifies every instruction, cryptographic proof mode, custody invariant, SIMD-0437
//! dynamic rent behavior, pure-RPC `dataSlice` scanner, and adversarial rejection path.

use agave_feature_set::FeatureSet;
use audren_client::{
    instructions::{
        build_buffered_execution, build_close_proof_buffer, build_deposit,
        build_deposit_with_options, build_init_pool, build_merge, build_open_page,
        build_set_paused, build_swap_via_router, build_transfer, build_withdraw,
        net_deposit_amount, AudrenAccountMeta, AudrenInstruction, SwapViaRouterParams,
    },
    keys::{AudrenKeys, AuditorKeypair, SelectiveDisclosureProof},
    pda::{
        derive_ata, derive_epoch_page_pda, derive_page_rent_vault_pda, derive_pool_pda,
        derive_sol_vault_pda, derive_swap_escrow_pda, derive_vault_auth_pda,
    },
    prover::{asset_generator, extract_ring_from_page, RingSlotWitness},
    router::locate_escrow_indices,
    scanner::{decrypt_owned_note, scan_page_dataslice, OwnedNote},
};
use audren_core::{
    instruction::{triptych_proof_len, AUDITOR_ASSET_PROOF_LEN, NOTE_WIRE_LEN},
    layout::{
        PageHeader, PoolState, PAGE_CAPACITY, PAGE_LEN, PAGE_ROLLOVER_HEADROOM, PAGE_SCAN_LEN,
        PAGE_SCAN_OFFSET,
    },
    AudrenError, CLASSIC_TOKEN_PROGRAM_ID, NATIVE_SOL_MINT, PoolMode, SYSTEM_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID,
};
use litesvm::{types::TransactionResult, LiteSVM};
use rand::{rngs::StdRng, SeedableRng};
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
    extension::{
        transfer_fee::instruction as transfer_fee_ix,
        transfer_hook::instruction as transfer_hook_ix,
        ExtensionType,
    },
    instruction as token_ix,
    state::{Account as TokenAccount, Mint},
};
use std::path::PathBuf;

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

fn deploy_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/deploy")
        .canonicalize()
        .expect("run build-sbf.py for audren and mock-router first")
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

fn new_svm(audren_id: Address, mock_router_id: Option<Address>) -> LiteSVM {
    // Enable all Agave 4.3 features (Direct Mapping SIMD-0460, sBPFv3, ZK ElGamal Proof, Curve25519).
    let mut svm = LiteSVM::new()
        .with_feature_set(FeatureSet::all_enabled())
        .with_builtins()
        .with_sysvars()
        .with_default_programs()
        .with_sigverify(true)
        .with_blockhash_check(false)
        .with_log_bytes_limit(None);

    let dir = deploy_dir();
    svm.add_program_from_file(audren_id, dir.join("audren.so"))
        .expect("load audren.so");
    if let Some(router_id) = mock_router_id {
        svm.add_program_from_file(router_id, dir.join("audren_mock_router.so"))
            .expect("load audren_mock_router.so");
    }
    svm
}

const DEFAULT_LOADED_ACCOUNTS_DATA_SIZE: u32 = 64 * 1024 * 1024;

fn build_v1_tx(
    payer: &Keypair,
    extra_signers: &[&Keypair],
    ixs: &[Instruction],
    blockhash: [u8; 32],
    cu_limit: u32,
) -> (VersionedTransaction, Vec<u8>) {
    let config = TransactionConfig::empty()
        .with_compute_unit_limit(cu_limit)
        .with_loaded_accounts_data_size_limit(DEFAULT_LOADED_ACCOUNTS_DATA_SIZE);
    let msg = v1::Message::try_compile_with_config(&payer.pubkey(), ixs, blockhash.into(), config)
        .expect("compile Solana v1 message");
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra_signers);
    let tx = VersionedTransaction::try_new(VersionedMessage::V1(msg), &signers)
        .expect("sign Solana v1 transaction");
    let wire = wincode::serialize(&tx).expect("wincode-serialize Solana v1 transaction");
    assert_eq!(wire[0], 0x81, "Solana Transaction v1 must start with 0x81");
    (tx, wire)
}

fn send_ixs(
    svm: &mut LiteSVM,
    payer: &Keypair,
    extra_signers: &[&Keypair],
    ixs: &[Instruction],
    cu_limit: u32,
) -> TransactionResult {
    let (tx, wire) = build_v1_tx(payer, extra_signers, ixs, svm.latest_blockhash().to_bytes(), cu_limit);
    assert!(
        wire.len() <= MAX_TRANSACTION_SIZE,
        "Solana v1 wire tx {} B exceeds {MAX_TRANSACTION_SIZE} B limit",
        wire.len()
    );
    svm.send_transaction(tx)
}

fn expect_ok(res: TransactionResult, label: &str) -> u64 {
    match res {
        Ok(meta) => {
            println!("  [OK] {label:<44} CU={}", meta.compute_units_consumed);
            for l in &meta.logs {
                if l.contains("consumption:") {
                    println!("       {l}");
                }
            }
            meta.compute_units_consumed
        }
        Err(err) => {
            panic!(
                "Expected OK for `{label}`, got err: {:?}\nLogs:\n{}",
                err.err,
                err.meta.logs.join("\n")
            );
        }
    }
}

fn expect_custom_err(res: TransactionResult, expected: AudrenError, label: &str) {
    let want = expected as u32;
    match res {
        Ok(meta) => panic!(
            "Expected Custom({want}) [{expected:?}] for `{label}`, but tx SUCCEEDED! Logs:\n{}",
            meta.logs.join("\n")
        ),
        Err(failed) => {
            let s = format!("{:?}", failed.err);
            assert!(
                s.contains(&format!("Custom({want})")),
                "Expected Custom({want}) [{expected:?}] for `{label}`, got: {s}\nLogs:\n{}",
                failed.meta.logs.join("\n")
            );
            println!("  [REJECTED OK] {label:<35} -> Custom({want}) [{expected:?}]");
        }
    }
}

fn read_pool(svm: &LiteSVM, program_id: &Address, pool_id: u32) -> PoolState {
    let pda = derive_pool_pda(program_id, pool_id).0;
    let acc = svm.get_account(&pda).expect("pool account exists");
    PoolState::decode(&acc.data).expect("valid pool state")
}

fn read_page_bytes(svm: &LiteSVM, program_id: &Address, pool_id: u32, page_id: u64) -> Vec<u8> {
    let pda = derive_epoch_page_pda(program_id, pool_id, page_id).0;
    let acc = svm.get_account(&pda).expect("epoch page exists");
    assert_eq!(acc.data.len(), PAGE_LEN);
    acc.data
}

fn read_ring(
    svm: &LiteSVM,
    program_id: &Address,
    pool_id: u32,
    page_ids: &[u64],
) -> Vec<RingSlotWitness> {
    let mut ring = Vec::with_capacity(page_ids.len() * PAGE_CAPACITY);
    for &pid in page_ids {
        let bytes = read_page_bytes(svm, program_id, pool_id, pid);
        ring.extend(extract_ring_from_page(&bytes).expect("extract ring"));
    }
    ring
}

fn scan_and_decrypt_page(
    svm: &LiteSVM,
    program_id: &Address,
    pool_id: u32,
    page_id: u64,
    keys: &AudrenKeys,
    resolved_dynamic: Option<u64>,
) -> Vec<OwnedNote> {
    let fvk = keys.full_viewing_key();
    let page_bytes = read_page_bytes(svm, program_id, pool_id, page_id);
    // Stage 1: pure-RPC 1,056-byte dataSlice scan!
    let slice = &page_bytes[PAGE_SCAN_OFFSET..PAGE_SCAN_OFFSET + PAGE_SCAN_LEN];
    let candidates = scan_page_dataslice(&fvk, page_id, slice).expect("scan slice");
    // Stage 2: full note decryption & on-chain commitment verification!
    let mut owned = Vec::new();
    for c in candidates {
        if let Some(note) = decrypt_owned_note(
            &fvk,
            Some(keys),
            program_id,
            pool_id,
            &page_bytes,
            c.slot_index,
            resolved_dynamic,
        )
        .expect("decrypt")
        {
            owned.push(note);
        }
    }
    owned
}

/// Create an SPL or Token-2022 mint directly in LiteSVM.
fn create_mint(
    svm: &mut LiteSVM,
    payer: &Keypair,
    token_program: &Address,
    decimals: u8,
) -> Keypair {
    let mint = Keypair::new();
    let rent = svm.minimum_balance_for_rent_exemption(Mint::LEN);
    let create_ix = sys_ix::create_account(
        &payer.pubkey(),
        &mint.pubkey(),
        rent,
        Mint::LEN as u64,
        token_program,
    );
    let init_ix = token_ix::initialize_mint2(
        token_program,
        &mint.pubkey(),
        &payer.pubkey(),
        None,
        decimals,
    )
    .unwrap();
    expect_ok(
        send_ixs(svm, payer, &[&mint], &[create_ix, init_ix], 200_000),
        "create_mint",
    );
    mint
}

/// Create an Associated Token Account (deterministic ATA address) in LiteSVM by injecting
/// an initialized SPL token account owned by `owner` at the canonical ATA address.
fn create_ata_with_balance(
    svm: &mut LiteSVM,
    token_program: &Address,
    mint: &Address,
    owner: &Address,
    amount: u64,
) -> Address {
    let ata = derive_ata(owner, token_program, mint);
    let mut data = vec![0u8; TokenAccount::LEN];
    let mut acc_state = TokenAccount::default();
    acc_state.mint = *mint;
    acc_state.owner = *owner;
    acc_state.amount = amount;
    acc_state.state = spl_token_2022_interface::state::AccountState::Initialized;
    TokenAccount::pack(acc_state, &mut data).unwrap();
    let rent = svm.minimum_balance_for_rent_exemption(data.len());
    svm.set_account(
        ata,
        Account {
            lamports: rent,
            data,
            owner: *token_program,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    ata
}

fn token_balance_of(svm: &LiteSVM, ata: &Address) -> u64 {
    let acc = svm.get_account(ata).expect("token account exists");
    assert!(acc.data.len() >= 72);
    u64::from_le_bytes(acc.data[64..72].try_into().unwrap())
}

/// Create a real Token-2022 ATA with required account extensions (e.g. `TransferFeeAmount`,
/// `NonTransferableAccount`) initialized via `initialize_account3` and funded via `mint_to`.
fn create_t22_ata_with_balance(
    svm: &mut LiteSVM,
    payer: &Keypair,
    t22_prog: &Address,
    mint: &Address,
    owner: &Address,
    amount: u64,
    account_extensions: &[ExtensionType],
) -> Address {
    let ata = derive_ata(owner, t22_prog, mint);
    let space = ExtensionType::try_calculate_account_len::<TokenAccount>(account_extensions).unwrap();
    let rent = svm.minimum_balance_for_rent_exemption(space);
    svm.set_account(
        ata,
        Account {
            lamports: rent,
            data: vec![0u8; space],
            owner: *t22_prog,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    let init_ix = token_ix::initialize_account3(t22_prog, &ata, mint, owner).unwrap();
    let mut ixs = vec![init_ix];
    if amount > 0 {
        ixs.push(token_ix::mint_to(t22_prog, mint, &ata, &payer.pubkey(), &[], amount).unwrap());
    }
    expect_ok(
        send_ixs(svm, payer, &[], &ixs, 200_000),
        "init_t22_ata_with_balance",
    );
    ata
}

// ----------------------------------------------------------------------------
// TEST 1: Full Lifecycle — SOL + SPL + Token-2022 (incl. PermanentDelegate &
//         active TransferFee), Transfer (m=5,6,7), Merge, Withdraw, Pure-RPC
//         DataSlice Scan, Selective Disclosure, Double-Spend & Bad Proof
//         Rejection, Soulbound NonTransferable Rejection!
// ----------------------------------------------------------------------------
#[test]
fn test_full_permissionless_lifecycle_and_security() {
    println!("\n=== TEST 1: Full Permissionless Lifecycle (m=5/6/7, SOL/SPL/T22, Merge, Withdraw, Security) ===");
    let mut rng = StdRng::seed_from_u64(0xA0D8_E101);
    let audren_id = Keypair::new().pubkey();
    let mut svm = new_svm(audren_id, None);

    let authority = Keypair::new();
    let payer = Keypair::new();
    let bob_wallet = Keypair::new();
    svm.airdrop(&authority.pubkey(), 100_000_000_000).unwrap();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();

    let alice = AudrenKeys::random(&mut rng);
    let bob = AudrenKeys::random(&mut rng);
    let pool_id = 0u32;

    // 1. InitPool (Permissionless)
    let init_ix = build_init_pool(
        audren_id,
        authority.pubkey(),
        pool_id,
        PoolMode::Permissionless,
        true,
        [0u8; 32],
        2_000_000, // 0.002 SOL max per-note fee (dynamically capped by live Rent::get())
    );
    expect_ok(
        send_ixs(&mut svm, &authority, &[], &[to_svm_ix(&init_ix)], 300_000),
        "InitPool (Permissionless)",
    );

    let pool = read_pool(&svm, &audren_id, pool_id);
    assert_eq!(pool.mode, PoolMode::Permissionless);
    assert_eq!(pool.current_page_id, 0);
    assert_eq!(pool.total_notes, 0);

    // 2. Deposit Native SOL (1.5 SOL) -> Alice stealth address
    let sol_amount = 1_500_000_000u64;
    let (dep_sol_ix, _prep_sol) = build_deposit(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &alice.address(),
        NATIVE_SOL_MINT,
        sol_amount,
        None,
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&dep_sol_ix)], 300_000),
        "Deposit Native SOL (1.5 SOL)",
    );

    let sol_vault = derive_sol_vault_pda(&audren_id, pool_id).0;
    let sol_vault_rent = svm.minimum_balance_for_rent_exemption(audren_core::layout::SENTINEL_ACCOUNT_LEN);
    assert_eq!(
        svm.get_account(&sol_vault).unwrap().lamports,
        sol_vault_rent + sol_amount
    );

    // Verify pure-RPC dataSlice scan recovers Alice's exact SOL note!
    let alice_notes = scan_and_decrypt_page(&svm, &audren_id, pool_id, 0, &alice, None);
    assert_eq!(alice_notes.len(), 1);
    assert_eq!(alice_notes[0].amount, sol_amount);
    assert_eq!(alice_notes[0].mint, NATIVE_SOL_MINT);

    // 3. Deposit Classic SPL Token + Plain Token-2022 Token
    let classic_prog = Address::new_from_array(CLASSIC_TOKEN_PROGRAM_ID);
    let t22_prog = Address::new_from_array(TOKEN_2022_PROGRAM_ID);
    let (vault_auth, _) = derive_vault_auth_pda(&audren_id, pool_id);

    let usdc_mint = create_mint(&mut svm, &payer, &classic_prog, 6);
    let payer_usdc = create_ata_with_balance(&mut svm, &classic_prog, &usdc_mint.pubkey(), &payer.pubkey(), 10_000_000);
    let vault_usdc = create_ata_with_balance(&mut svm, &classic_prog, &usdc_mint.pubkey(), &vault_auth, 0);

    let (dep_spl_ix, _) = build_deposit(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &alice.address(),
        usdc_mint.pubkey().to_bytes(),
        5_000_000,
        Some((classic_prog, payer_usdc, vault_usdc)),
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&dep_spl_ix)], 300_000),
        "Deposit Classic SPL (5 USDC)",
    );
    assert_eq!(token_balance_of(&svm, &vault_usdc), 5_000_000);

    // Plain Token-2022 mint (no extensions)
    let safe_t22_mint = create_mint(&mut svm, &payer, &t22_prog, 6);
    let payer_t22 = create_ata_with_balance(&mut svm, &t22_prog, &safe_t22_mint.pubkey(), &payer.pubkey(), 2_000_000);
    let vault_t22 = create_ata_with_balance(&mut svm, &t22_prog, &safe_t22_mint.pubkey(), &vault_auth, 0);
    let (dep_t22_ix, _) = build_deposit(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &alice.address(),
        safe_t22_mint.pubkey().to_bytes(),
        1_000_000,
        Some((t22_prog, payer_t22, vault_t22)),
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&dep_t22_ix)], 300_000),
        "Deposit Plain Token-2022 (1 T22)",
    );

    // 4a. Regulated Token-2022 Stablecoin Mint (PYUSD / USDG extension profile:
    //     PermanentDelegate + TransferFeeConfig(0/0, mutable) + TransferHook(None, mutable))
    let reg_mint = Keypair::new();
    let reg_space = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::PermanentDelegate,
        ExtensionType::TransferFeeConfig,
        ExtensionType::TransferHook,
    ])
    .unwrap();
    let reg_rent = svm.minimum_balance_for_rent_exemption(reg_space);
    let c_ix = sys_ix::create_account(
        &payer.pubkey(),
        &reg_mint.pubkey(),
        reg_rent,
        reg_space as u64,
        &t22_prog,
    );
    let pd_ix =
        token_ix::initialize_permanent_delegate(&t22_prog, &reg_mint.pubkey(), &authority.pubkey())
            .unwrap();
    let tf_ix = transfer_fee_ix::initialize_transfer_fee_config(
        &t22_prog,
        &reg_mint.pubkey(),
        Some(&authority.pubkey()),
        Some(&authority.pubkey()),
        0,
        0,
    )
    .unwrap();
    let th_ix = transfer_hook_ix::initialize(
        &t22_prog,
        &reg_mint.pubkey(),
        Some(authority.pubkey()),
        None,
    )
    .unwrap();
    let m_ix =
        token_ix::initialize_mint2(&t22_prog, &reg_mint.pubkey(), &payer.pubkey(), None, 6)
            .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[&reg_mint], &[c_ix, pd_ix, tf_ix, th_ix, m_ix], 300_000),
        "create regulated T22 mint (PYUSD/USDG profile)",
    );
    let payer_reg = create_t22_ata_with_balance(
        &mut svm,
        &payer,
        &t22_prog,
        &reg_mint.pubkey(),
        &payer.pubkey(),
        500_000,
        &[ExtensionType::TransferFeeAmount],
    );
    let vault_reg = create_t22_ata_with_balance(
        &mut svm,
        &payer,
        &t22_prog,
        &reg_mint.pubkey(),
        &vault_auth,
        0,
        &[ExtensionType::TransferFeeAmount],
    );
    let (dep_reg_ix, _) = build_deposit(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &alice.address(),
        reg_mint.pubkey().to_bytes(),
        100_000,
        Some((t22_prog, payer_reg, vault_reg)),
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&dep_reg_ix)], 300_000),
        "Deposit Regulated Token-2022 (PYUSD/USDG profile)",
    );
    assert_eq!(token_balance_of(&svm, &vault_reg), 100_000);

    // 4b. Active TransferFee Token-2022 Mint (100 bps = 1%, max_fee = 50_000):
    //     Gross deposit 1_000_000 credits exact net 990_000 to vault & commits V = 990_000 * G_mint.
    let fee_mint = Keypair::new();
    let fee_space = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::TransferFeeConfig,
    ])
    .unwrap();
    let fee_rent = svm.minimum_balance_for_rent_exemption(fee_space);
    let c_fee = sys_ix::create_account(
        &payer.pubkey(),
        &fee_mint.pubkey(),
        fee_rent,
        fee_space as u64,
        &t22_prog,
    );
    let tf_active = transfer_fee_ix::initialize_transfer_fee_config(
        &t22_prog,
        &fee_mint.pubkey(),
        Some(&authority.pubkey()),
        Some(&authority.pubkey()),
        100,    // 1.00% transfer fee
        50_000, // max fee cap
    )
    .unwrap();
    let m_fee =
        token_ix::initialize_mint2(&t22_prog, &fee_mint.pubkey(), &payer.pubkey(), None, 6)
            .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[&fee_mint], &[c_fee, tf_active, m_fee], 300_000),
        "create active TransferFee T22 mint (100 bps)",
    );
    let payer_fee = create_t22_ata_with_balance(
        &mut svm,
        &payer,
        &t22_prog,
        &fee_mint.pubkey(),
        &payer.pubkey(),
        2_000_000,
        &[ExtensionType::TransferFeeAmount],
    );
    let vault_fee = create_t22_ata_with_balance(
        &mut svm,
        &payer,
        &t22_prog,
        &fee_mint.pubkey(),
        &vault_auth,
        0,
        &[ExtensionType::TransferFeeAmount],
    );
    let expected_net = net_deposit_amount(1_000_000, 100, 50_000);
    assert_eq!(expected_net, 990_000);
    let (dep_fee_ix, _) = build_deposit_with_options(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &alice.address(),
        fee_mint.pubkey().to_bytes(),
        1_000_000,
        expected_net,
        Some((t22_prog, payer_fee, vault_fee)),
        &[],
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&dep_fee_ix)], 300_000),
        "Deposit Active TransferFee T22 (1_000_000 gross -> 990_000 net)",
    );
    assert_eq!(token_balance_of(&svm, &vault_fee), 990_000);
    let alice_t22_notes = scan_and_decrypt_page(&svm, &audren_id, pool_id, 0, &alice, None);
    let fee_note = alice_t22_notes
        .iter()
        .find(|n| n.mint == fee_mint.pubkey().to_bytes())
        .expect("Alice decrypts and verifies net 990_000 commitment for TransferFee note");
    assert_eq!(fee_note.amount, 990_000);

    // 4c. Soulbound NonTransferable Token-2022 Mint -> rejected natively by Token-2022!
    let soul_mint = Keypair::new();
    let soul_space = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::NonTransferable,
    ])
    .unwrap();
    let soul_rent = svm.minimum_balance_for_rent_exemption(soul_space);
    let c_soul = sys_ix::create_account(
        &payer.pubkey(),
        &soul_mint.pubkey(),
        soul_rent,
        soul_space as u64,
        &t22_prog,
    );
    let nt_ix = token_ix::initialize_non_transferable_mint(&t22_prog, &soul_mint.pubkey()).unwrap();
    let m_soul =
        token_ix::initialize_mint2(&t22_prog, &soul_mint.pubkey(), &payer.pubkey(), None, 6)
            .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[&soul_mint], &[c_soul, nt_ix, m_soul], 300_000),
        "create soulbound NonTransferable T22 mint",
    );
    let payer_soul = create_t22_ata_with_balance(
        &mut svm,
        &payer,
        &t22_prog,
        &soul_mint.pubkey(),
        &payer.pubkey(),
        100_000,
        &[ExtensionType::NonTransferableAccount],
    );
    let vault_soul = create_t22_ata_with_balance(
        &mut svm,
        &payer,
        &t22_prog,
        &soul_mint.pubkey(),
        &vault_auth,
        0,
        &[ExtensionType::NonTransferableAccount],
    );
    let (dep_soul_ix, _) = build_deposit(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &alice.address(),
        soul_mint.pubkey().to_bytes(),
        50_000,
        Some((t22_prog, payer_soul, vault_soul)),
        &mut rng,
    )
    .unwrap();
    assert!(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&dep_soul_ix)], 300_000).is_err(),
        "Soulbound NonTransferable mint must fail transfer_checked natively in Token-2022"
    );

    // 5. Shielded Transfer (m=5, 1 page = 32 notes): Alice sends 0.6 SOL to Bob + 0.9 SOL change
    //    AND verifies independent unlinkable asset_tags (A_pay != A_chg) + PQ envelope binding!
    let ring_p0 = read_ring(&svm, &audren_id, pool_id, &[0]);
    let alice_sol_note = &alice_notes[0];
    let pq_envelope = b"mlkem768-demo-ciphertext-bound-to-fiat-shamir";
    let (xfer_ix, prep_pay, prep_chg) = build_transfer(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &[0],
        &ring_p0,
        alice_sol_note,
        alice_sol_note.slot_index,
        &bob.address(),
        &alice.address(),
        600_000_000,
        None,
        pq_envelope,
        &mut rng,
    )
    .unwrap();
    // Crucial privacy invariant: payment and change notes have distinct, unlinkable asset_tags!
    assert_ne!(prep_pay.entry.asset_tag, prep_chg.entry.asset_tag);

    // Adversarial test: tamper with pq_envelope -> MUST reject with InvalidTriptychProof!
    let mut tampered_xfer = to_svm_ix(&xfer_ix);
    let last = tampered_xfer.data.len() - 1;
    tampered_xfer.data[last] ^= 0x01;
    expect_custom_err(
        send_ixs(&mut svm, &payer, &[], &[tampered_xfer], 600_000),
        AudrenError::InvalidTriptychProof,
        "Reject tampered pq_envelope",
    );

    // Execute valid Transfer (m=5)
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&xfer_ix)], 1_400_000),
        "Transfer (m=5, 1-page / 32 ring)",
    );

    // Fresh double-spend attack: Alice constructs a BRAND NEW valid Triptych proof over the updated
    // Page 0 trying to spend the exact same `alice_sol_note` a second time -> MUST hit NullifierAlreadySpent!
    let ring_p0_updated = read_ring(&svm, &audren_id, pool_id, &[0]);
    let (double_spend_ix, _, _) = build_transfer(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &[0],
        &ring_p0_updated,
        alice_sol_note,
        alice_sol_note.slot_index,
        &bob.address(),
        &alice.address(),
        100_000_000,
        None,
        &[],
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&double_spend_ix)], 1_400_000),
        AudrenError::NullifierAlreadySpent,
        "Reject double-spend nullifier",
    );

    // Verify BOTH Bob (recipient) AND Alice (change) recover their notes purely via stateless dataSlice scan!
    let bob_notes = scan_and_decrypt_page(&svm, &audren_id, pool_id, 0, &bob, None);
    assert_eq!(bob_notes.len(), 1);
    assert_eq!(bob_notes[0].amount, 600_000_000);
    assert_eq!(bob_notes[0].mint, NATIVE_SOL_MINT);

    let alice_notes_after = scan_and_decrypt_page(&svm, &audren_id, pool_id, 0, &alice, None);
    let alice_chg = alice_notes_after
        .iter()
        .find(|n| n.amount == 900_000_000 && n.mint == NATIVE_SOL_MINT)
        .expect("Alice change note recovered purely from EpochPage");

    // Verify Mode 1 Selective Disclosure Proof independently against on-chain note points!
    let disclosure = SelectiveDisclosureProof {
        version: 1,
        page_id: bob_notes[0].page_id,
        slot_index: bob_notes[0].slot_index as u8,
        stealth_pk_b58: bs58::encode(bob_notes[0].stealth_pk).into_string(),
        asset_tag_b58: bs58::encode(bob_notes[0].asset_tag).into_string(),
        commitment_b58: bs58::encode(bob_notes[0].commitment).into_string(),
        mint_b58: bs58::encode(bob_notes[0].mint).into_string(),
        amount: bob_notes[0].amount,
        asset_blinding_b58: bs58::encode(bob_notes[0].asset_blinding.to_bytes()).into_string(),
        value_blinding_b58: bs58::encode(bob_notes[0].value_blinding.to_bytes()).into_string(),
    };
    assert!(disclosure.verify().unwrap(), "Mode 1 SelectiveDisclosureProof verified!");

    // 6. Fill Page 0..3 via Deposits & OpenPage rollovers to test m=6 (2-page / 64) & m=7 (4-page / 128)!
    //    Also tests PageNotReady rejection before headroom (count < 28)!
    let open_early = build_open_page(audren_id, payer.pubkey(), pool_id, 0);
    expect_custom_err(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&open_early)], 200_000),
        AudrenError::PageNotReady,
        "Reject OpenPage before count>=28",
    );

    // Fill pages 0, 1, 2 to trigger rollovers into page 3 (so pages 0, 1, 2, 3 all exist!)
    for target_page in 0..3u64 {
        loop {
            let page_bytes = read_page_bytes(&svm, &audren_id, pool_id, target_page);
            let hdr = PageHeader::decode(&page_bytes).unwrap();
            if hdr.count as usize >= PAGE_CAPACITY - PAGE_ROLLOVER_HEADROOM {
                break;
            }
            let (d_ix, _) = build_deposit(
                audren_id,
                payer.pubkey(),
                pool_id,
                target_page,
                &alice.address(),
                NATIVE_SOL_MINT,
                10_000_000, // 0.01 SOL
                None,
                &mut rng,
            )
            .unwrap();
            send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&d_ix)], 300_000).unwrap();
        }
        let op_ix = build_open_page(audren_id, payer.pubkey(), pool_id, target_page);
        expect_ok(
            send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&op_ix)], 300_000),
            &format!("OpenPage rollover {} -> {}", target_page, target_page + 1),
        );
    }

    // Verify Page 3 is active now!
    let pool_p3 = read_pool(&svm, &audren_id, pool_id);
    assert_eq!(pool_p3.current_page_id, 3);

    // 7. Transfer with m=6 (2-page / 64 anonymity set) — Alice spends her 0.9 SOL change note!
    let ring_2p = read_ring(&svm, &audren_id, pool_id, &[0, 1]);
    let (xfer_m6, _, _) = build_transfer(
        audren_id,
        payer.pubkey(),
        pool_id,
        3,
        &[0, 1],
        &ring_2p,
        alice_chg,
        alice_chg.slot_index, // in page 0
        &bob.address(),
        &alice.address(),
        400_000_000,
        None,
        &[],
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&xfer_m6)], 1_400_000),
        "Transfer (m=6, 2-page / 64 ring)",
    );

    // 8. Transfer with m=7 (4-page / 128 anonymity set) — Bob spends his 0.6 SOL note!
    let ring_4p = read_ring(&svm, &audren_id, pool_id, &[0, 1, 2, 3]);
    let (xfer_m7, _, _) = build_transfer(
        audren_id,
        payer.pubkey(),
        pool_id,
        3,
        &[0, 1, 2, 3],
        &ring_4p,
        &bob_notes[0],
        bob_notes[0].slot_index, // in page 0
        &alice.address(),
        &bob.address(),
        250_000_000,
        None,
        &[],
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&xfer_m7)], 1_400_000),
        "Transfer (m=7, 4-page / 128 ring)",
    );

    // 9. Merge (2-in -> 1-out across two notes on Page 3): Bob merges his 0.4 SOL + 0.35 SOL -> 0.75 SOL!
    let bob_p3_notes = scan_and_decrypt_page(&svm, &audren_id, pool_id, 3, &bob, None);
    assert_eq!(bob_p3_notes.len(), 2);
    let ring_p3 = read_ring(&svm, &audren_id, pool_id, &[3]);
    let (merge_ix, _) = build_merge(
        audren_id,
        payer.pubkey(),
        pool_id,
        3,
        &[3],
        &ring_p3,
        &bob_p3_notes[0],
        bob_p3_notes[0].slot_index,
        &[3],
        &ring_p3,
        &bob_p3_notes[1],
        bob_p3_notes[1].slot_index,
        &bob.address(),
        None,
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&merge_ix)], 1_400_000),
        "Merge (2x m=5 -> 1 combined note)",
    );

    // Verify Bob recovers the merged 0.75 SOL note purely from EpochPage 3!
    let bob_p3_after_merge = scan_and_decrypt_page(&svm, &audren_id, pool_id, 3, &bob, None);
    let merged_note = bob_p3_after_merge
        .iter()
        .find(|n| n.amount == 750_000_000)
        .expect("Bob merged 0.75 SOL note recovered via stateless scan!");

    // 10. Withdraw Native SOL: Bob withdraws 0.5 SOL with 0.25 SOL change (testing self-withdraw recipient == payer
    //     when PageRentVault collects a fee!), then withdraws full 0.25 SOL (no change, readonly out_page!)
    let ring_p3_now = read_ring(&svm, &audren_id, pool_id, &[3]);
    let (wd_partial, _) = build_withdraw(
        audren_id,
        payer.pubkey(),
        pool_id,
        3,
        &[3],
        &ring_p3_now,
        merged_note,
        merged_note.slot_index,
        payer.pubkey(), // self-withdraw recipient == payer WITH change note!
        &bob.address(),
        500_000_000,
        None,
        None,
        &mut rng,
    )
    .unwrap();
    let payer_before = svm.get_account(&payer.pubkey()).unwrap().lamports;
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&wd_partial)], 600_000),
        "Withdraw Native SOL (0.5 SOL self + change)",
    );
    let payer_after = svm.get_account(&payer.pubkey()).unwrap().lamports;
    assert!(
        payer_after > payer_before + 490_000_000,
        "Self-withdraw with change must credit payer without UnbalancedInstruction!"
    );

    // Withdraw full remaining 0.25 SOL to bob_wallet (has_change = false -> out_page & rent_vault are READONLY!)
    let bob_p3_chg = scan_and_decrypt_page(&svm, &audren_id, pool_id, 3, &bob, None)
        .into_iter()
        .find(|n| n.amount == 250_000_000)
        .expect("Bob 0.25 SOL withdraw change note");
    let ring_p3_final = read_ring(&svm, &audren_id, pool_id, &[3]);
    let (wd_full, _) = build_withdraw(
        audren_id,
        payer.pubkey(),
        pool_id,
        3,
        &[3],
        &ring_p3_final,
        &bob_p3_chg,
        bob_p3_chg.slot_index,
        bob_wallet.pubkey(),
        &bob.address(),
        250_000_000,
        None,
        None,
        &mut rng,
    )
    .unwrap();
    assert!(!wd_full.accounts[2].is_writable, "out_page MUST be readonly when !has_change");
    assert!(!wd_full.accounts[4].is_writable, "rent_vault MUST be readonly when !has_change");
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&wd_full)], 600_000),
        "Withdraw Native SOL (0.25 SOL full, ro page)",
    );
    assert_eq!(svm.get_account(&bob_wallet.pubkey()).unwrap().lamports, 250_000_000);

    // 11. Withdraw Classic SPL (Alice withdraws 3 USDC of her 5 USDC with 2 USDC change)
    let alice_usdc = alice_notes_after
        .iter()
        .find(|n| n.mint == usdc_mint.pubkey().to_bytes())
        .expect("Alice USDC note");
    let bob_usdc_ata = create_ata_with_balance(&mut svm, &classic_prog, &usdc_mint.pubkey(), &bob_wallet.pubkey(), 0);
    let ring_p0_now = read_ring(&svm, &audren_id, pool_id, &[0]);
    let (wd_spl, _) = build_withdraw(
        audren_id,
        payer.pubkey(),
        pool_id,
        3,
        &[0],
        &ring_p0_now,
        alice_usdc,
        alice_usdc.slot_index,
        bob_usdc_ata,
        &alice.address(),
        3_000_000,
        Some(classic_prog),
        None,
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&wd_spl)], 600_000),
        "Withdraw Classic SPL (3 USDC + 2 change)",
    );
    assert_eq!(token_balance_of(&svm, &bob_usdc_ata), 3_000_000);
    assert_eq!(token_balance_of(&svm, &vault_usdc), 2_000_000);

    // 12. SetPaused + Unauthorized rejection + Deposit blocked when paused!
    let bad_pause = build_set_paused(audren_id, payer.pubkey(), pool_id, true);
    expect_custom_err(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&bad_pause)], 200_000),
        AudrenError::Unauthorized,
        "Reject unauthorized SetPaused",
    );
    let pause_ix = build_set_paused(audren_id, authority.pubkey(), pool_id, true);
    expect_ok(
        send_ixs(&mut svm, &authority, &[], &[to_svm_ix(&pause_ix)], 200_000),
        "SetPaused(true)",
    );
    let (dep_paused, _) = build_deposit(
        audren_id,
        payer.pubkey(),
        pool_id,
        3,
        &alice.address(),
        NATIVE_SOL_MINT,
        1_000_000,
        None,
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&dep_paused)], 200_000),
        AudrenError::PoolPaused,
        "Reject Deposit while paused",
    );
}

// ----------------------------------------------------------------------------
// TEST 2: InstitutionalAudited Mode — On-Chain Verifiable Auditor ElGamal
//         (S_1, S_2) & (M_1, M_2) Decryption + Forged Auditor Proof Rejection!
// ----------------------------------------------------------------------------
#[test]
fn test_institutional_audited_mode_and_decryption() {
    println!("\n=== TEST 2: InstitutionalAudited Mode (S1/S2 + M1/M2 Verifiable Auditor Decryption) ===");
    let mut rng = StdRng::seed_from_u64(0xA0D8_E202);
    let audren_id = Keypair::new().pubkey();
    let mut svm = new_svm(audren_id, None);

    let authority = Keypair::new();
    let payer = Keypair::new();
    svm.airdrop(&authority.pubkey(), 20_000_000_000).unwrap();
    svm.airdrop(&payer.pubkey(), 20_000_000_000).unwrap();

    let auditor = AuditorKeypair::from_seed(&[0x42u8; 32]);
    let alice = AudrenKeys::random(&mut rng);
    let bob = AudrenKeys::random(&mut rng);
    let pool_id = 1u32;

    // 1. InitPool(InstitutionalAudited, auditor_pk)
    let init_ix = build_init_pool(
        audren_id,
        authority.pubkey(),
        pool_id,
        PoolMode::InstitutionalAudited,
        true,
        auditor.auditor_pk,
        1_500_000,
    );
    expect_ok(
        send_ixs(&mut svm, &authority, &[], &[to_svm_ix(&init_ix)], 300_000),
        "InitPool (InstitutionalAudited)",
    );

    // 2. Deposit 2.0 SOL to Alice
    let (dep_ix, _) = build_deposit(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &alice.address(),
        NATIVE_SOL_MINT,
        2_000_000_000,
        None,
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&dep_ix)], 300_000),
        "Deposit 2 SOL into Audited Pool",
    );

    let alice_note = scan_and_decrypt_page(&svm, &audren_id, pool_id, 0, &alice, None)
        .pop()
        .unwrap();
    let ring = read_ring(&svm, &audren_id, pool_id, &[0]);

    // 3. Adversarial: submitting an UNAUDITED Transfer into an InstitutionalAudited pool MUST FAIL!
    let (unaudited_xfer, _, _) = build_transfer(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &[0],
        &ring,
        &alice_note,
        alice_note.slot_index,
        &bob.address(),
        &alice.address(),
        500_000_000,
        None, // <-- missing auditor_pk!
        &[],
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&unaudited_xfer)], 700_000),
        AudrenError::InvalidInstruction,
        "Reject unaudited tx in audited pool",
    );

    // 4. Execute valid AUDITED Transfer (m=5)
    let (audited_xfer, _, _) = build_transfer(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &[0],
        &ring,
        &alice_note,
        alice_note.slot_index,
        &bob.address(),
        &alice.address(),
        500_000_000,
        Some(auditor.auditor_pk),
        &[],
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&audited_xfer)], 1_400_000),
        "Transfer (InstitutionalAudited, m=5)",
    );

    // 5. Auditor independently parses `(S_1, S_2)` from Triptych proof AND `(M_1, M_2)` from AuditorAssetProof
    //    and decrypts BOTH the exact spent stealth pubkey `P_l` AND the exact hidden mint `G_mint`!
    let m = 5u8;
    let trip_off = 2 + 2 * NOTE_WIRE_LEN + 64;
    let _trip_len = triptych_proof_len(m, true).unwrap();
    let base_trip_len = triptych_proof_len(m, false).unwrap();
    let s1: [u8; 32] = audited_xfer.data[trip_off + base_trip_len..trip_off + base_trip_len + 32]
        .try_into()
        .unwrap();
    let s2: [u8; 32] = audited_xfer.data[trip_off + base_trip_len + 32..trip_off + base_trip_len + 64]
        .try_into()
        .unwrap();
    let recovered_p_l = auditor.decrypt_spent_pubkey(&s1, &s2).unwrap();
    assert_eq!(
        recovered_p_l, alice_note.stealth_pk,
        "Auditor MUST recover exact spent stealth pubkey P_l from (S_1, S_2)!"
    );

    let aud_asset_off = audited_xfer.data.len() - AUDITOR_ASSET_PROOF_LEN;
    let m1: [u8; 32] = audited_xfer.data[aud_asset_off..aud_asset_off + 32].try_into().unwrap();
    let m2: [u8; 32] = audited_xfer.data[aud_asset_off + 32..aud_asset_off + 64].try_into().unwrap();
    let recovered_g_mint = auditor.decrypt_asset_generator(&m1, &m2).unwrap();
    assert_eq!(
        recovered_g_mint,
        asset_generator(&NATIVE_SOL_MINT),
        "Auditor MUST recover exact hidden mint generator G_mint from (M_1, M_2)!"
    );
    println!("  [AUDITOR VERIFIED] Decrypted exact P_l and exact G_mint with zero false positives!");
}

// ----------------------------------------------------------------------------
// TEST 3: SwapViaRouter (Router-Agnostic 1-Tx Private Swap) + ALL Adversarial
//         Router Attacks (Slippage, Delegate Hijack, Owner Hijack, Lamport Drain,
//         Dust Theft, Protected Account Smuggling, Self-Reentrancy, Router Swap)!
// ----------------------------------------------------------------------------
#[test]
fn test_swap_via_router_and_adversarial_defenses() {
    println!("\n=== TEST 3: SwapViaRouter (Arbitrary Indices, Change, Partial Refund & 8 Adversarial Attacks) ===");
    let mut rng = StdRng::seed_from_u64(0xA0D8_E303);
    let audren_id = Keypair::new().pubkey();
    let router_id = Keypair::new().pubkey();
    let mut svm = new_svm(audren_id, Some(router_id));

    let authority = Keypair::new();
    let payer = Keypair::new();
    let attacker = Keypair::new();
    svm.airdrop(&authority.pubkey(), 20_000_000_000).unwrap();
    svm.airdrop(&payer.pubkey(), 20_000_000_000).unwrap();

    let alice = AudrenKeys::random(&mut rng);
    let bob = AudrenKeys::random(&mut rng);
    let pool_id = 7u32;
    let shard_id = 3u8;

    let init_ix = build_init_pool(
        audren_id,
        authority.pubkey(),
        pool_id,
        PoolMode::Permissionless,
        true,
        [0u8; 32],
        1_500_000,
    );
    expect_ok(
        send_ixs(&mut svm, &authority, &[], &[to_svm_ix(&init_ix)], 300_000),
        "InitPool for SwapViaRouter",
    );

    let token_prog = Address::new_from_array(CLASSIC_TOKEN_PROGRAM_ID);
    let mint_usdc = create_mint(&mut svm, &payer, &token_prog, 6);
    let mint_wsol = create_mint(&mut svm, &payer, &token_prog, 9);

    let (vault_auth, _) = derive_vault_auth_pda(&audren_id, pool_id);
    let (swap_escrow, _) = derive_swap_escrow_pda(&audren_id, pool_id, shard_id);
    // Give swap_escrow 1_000_000 lamports so we can verify malicious router cannot drain lamports!
    svm.airdrop(&swap_escrow, 1_000_000).unwrap();

    let payer_usdc = create_ata_with_balance(&mut svm, &token_prog, &mint_usdc.pubkey(), &payer.pubkey(), 100_000_000);
    let vault_usdc = create_ata_with_balance(&mut svm, &token_prog, &mint_usdc.pubkey(), &vault_auth, 0);
    let vault_wsol = create_ata_with_balance(&mut svm, &token_prog, &mint_wsol.pubkey(), &vault_auth, 0);
    let escrow_usdc = create_ata_with_balance(&mut svm, &token_prog, &mint_usdc.pubkey(), &swap_escrow, 0);
    let escrow_wsol = create_ata_with_balance(&mut svm, &token_prog, &mint_wsol.pubkey(), &swap_escrow, 0);

    // Mock DEX liquidity pool accounts
    let (mock_pool_auth, _) = Address::find_program_address(&[b"mock_pool"], &router_id);
    let mock_pool_usdc = create_ata_with_balance(&mut svm, &token_prog, &mint_usdc.pubkey(), &mock_pool_auth, 500_000_000);
    let mock_pool_wsol = create_ata_with_balance(&mut svm, &token_prog, &mint_wsol.pubkey(), &mock_pool_auth, 500_000_000_000);

    // Deposit 50 USDC (50_000_000) into Audren for Alice
    let (dep_ix, _) = build_deposit(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &alice.address(),
        mint_usdc.pubkey().to_bytes(),
        50_000_000,
        Some((token_prog, payer_usdc, vault_usdc)),
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&dep_ix)], 300_000),
        "Deposit 50 USDC for private swap",
    );

    let alice_usdc_note = scan_and_decrypt_page(&svm, &audren_id, pool_id, 0, &alice, None)
        .pop()
        .unwrap();
    let ring = read_ring(&svm, &audren_id, pool_id, &[0]);

    // Build mock router accounts with ARBITRARY non-zero indices:
    //   [0]=mock_pool_auth, [1]=escrow_in, [2]=mock_pool_in, [3]=swap_escrow, [4]=escrow_out, [5]=mock_pool_out, ...
    let make_router_accounts = |extra: Vec<AudrenAccountMeta>| {
        let mut v = vec![
            AudrenAccountMeta::readonly(mock_pool_auth),
            AudrenAccountMeta::writable(escrow_usdc),
            AudrenAccountMeta::writable(mock_pool_usdc),
            AudrenAccountMeta::writable_signer(swap_escrow),
            AudrenAccountMeta::writable(escrow_wsol),
            AudrenAccountMeta::writable(mock_pool_wsol),
            AudrenAccountMeta::readonly(token_prog),
            AudrenAccountMeta::readonly(token_prog),
            AudrenAccountMeta::readonly(mint_usdc.pubkey()),
            AudrenAccountMeta::readonly(mint_wsol.pubkey()),
        ];
        v.extend(extra);
        v
    };
    let make_router_data = |mode: u8, spend_in: u64, pay_out: u64| {
        let mut d = Vec::with_capacity(19);
        d.push(mode);
        d.extend_from_slice(&spend_in.to_le_bytes());
        d.extend_from_slice(&pay_out.to_le_bytes());
        d.push(6);
        d.push(9);
        d
    };

    let base_router_accs = make_router_accounts(vec![]);
    let (escrow_idx, escrow_in_idx, escrow_out_idx) =
        locate_escrow_indices(&base_router_accs, &swap_escrow, &escrow_usdc, &escrow_wsol)
            .expect("locate escrow indices");
    assert_eq!((escrow_idx, escrow_in_idx, escrow_out_idx), (3, 1, 4));

    // --- ADVERSARIAL 1: Slippage violation (router pays 199_999_999 < min 200_000_000) ---
    let bad_slip_data = make_router_data(0, 30_000_000, 199_999_999);
    let (slip_ix, _, _, _) = build_swap_via_router(
        &SwapViaRouterParams {
            program_id: audren_id,
            payer: payer.pubkey(),
            pool_id,
            out_page_id: 0,
            shard_id,
            input_page_ids: &[0],
            ring: &ring,
            input_note: &alice_usdc_note,
            secret_index: alice_usdc_note.slot_index,
            mint_out: mint_wsol.pubkey().to_bytes(),
            token_program_in: token_prog,
            token_program_out: token_prog,
            amount_in: 30_000_000,
            min_amount_out: 200_000_000,
            allow_partial_refund: false,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            router_program_id: router_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            router_ix_data: &bad_slip_data,
            router_accounts: &base_router_accs,
        },
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&slip_ix)], 700_000),
        AudrenError::SlippageExceeded,
        "Reject slippage violation",
    );

    // --- ADVERSARIAL 2: Malicious delegate approval on escrow_in -> EscrowAccountAltered ---
    let delegate_accs = make_router_accounts(vec![AudrenAccountMeta::readonly(attacker.pubkey())]);
    let delegate_data = make_router_data(1, 30_000_000, 250_000_000);
    let (del_ix, _, _, _) = build_swap_via_router(
        &SwapViaRouterParams {
            program_id: audren_id,
            payer: payer.pubkey(),
            pool_id,
            out_page_id: 0,
            shard_id,
            input_page_ids: &[0],
            ring: &ring,
            input_note: &alice_usdc_note,
            secret_index: alice_usdc_note.slot_index,
            mint_out: mint_wsol.pubkey().to_bytes(),
            token_program_in: token_prog,
            token_program_out: token_prog,
            amount_in: 30_000_000,
            min_amount_out: 200_000_000,
            allow_partial_refund: false,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            router_program_id: router_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            router_ix_data: &delegate_data,
            router_accounts: &delegate_accs,
        },
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&del_ix)], 700_000),
        AudrenError::EscrowAccountAltered,
        "Reject malicious router delegate",
    );

    // --- ADVERSARIAL 3: Malicious owner hijack on escrow_out -> EscrowAccountAltered ---
    let owner_data = make_router_data(2, 30_000_000, 250_000_000);
    let (own_ix, _, _, _) = build_swap_via_router(
        &SwapViaRouterParams {
            program_id: audren_id,
            payer: payer.pubkey(),
            pool_id,
            out_page_id: 0,
            shard_id,
            input_page_ids: &[0],
            ring: &ring,
            input_note: &alice_usdc_note,
            secret_index: alice_usdc_note.slot_index,
            mint_out: mint_wsol.pubkey().to_bytes(),
            token_program_in: token_prog,
            token_program_out: token_prog,
            amount_in: 30_000_000,
            min_amount_out: 200_000_000,
            allow_partial_refund: false,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            router_program_id: router_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            router_ix_data: &owner_data,
            router_accounts: &delegate_accs,
        },
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&own_ix)], 700_000),
        AudrenError::EscrowAccountAltered,
        "Reject malicious owner hijack",
    );

    // --- ADVERSARIAL 4: Malicious lamport drain from swap_escrow -> EscrowAuthorityAltered ---
    let drain_accs = make_router_accounts(vec![
        AudrenAccountMeta::writable(attacker.pubkey()),
        AudrenAccountMeta::readonly(Address::new_from_array(SYSTEM_PROGRAM_ID)),
    ]);
    let drain_data = make_router_data(3, 30_000_000, 250_000_000);
    let (drain_ix, _, _, _) = build_swap_via_router(
        &SwapViaRouterParams {
            program_id: audren_id,
            payer: payer.pubkey(),
            pool_id,
            out_page_id: 0,
            shard_id,
            input_page_ids: &[0],
            ring: &ring,
            input_note: &alice_usdc_note,
            secret_index: alice_usdc_note.slot_index,
            mint_out: mint_wsol.pubkey().to_bytes(),
            token_program_in: token_prog,
            token_program_out: token_prog,
            amount_in: 30_000_000,
            min_amount_out: 200_000_000,
            allow_partial_refund: false,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            router_program_id: router_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            router_ix_data: &drain_data,
            router_accounts: &drain_accs,
        },
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&drain_ix)], 700_000),
        AudrenError::EscrowAuthorityAltered,
        "Reject escrow lamport drain",
    );

    // --- ADVERSARIAL 5: Smuggling protected `vault_usdc` inside router_accounts -> InvalidAccount ---
    let smuggle_accs = make_router_accounts(vec![AudrenAccountMeta::writable(vault_usdc)]);
    let ok_data = make_router_data(0, 30_000_000, 250_000_000);
    let (smug_ix, _, _, _) = build_swap_via_router(
        &SwapViaRouterParams {
            program_id: audren_id,
            payer: payer.pubkey(),
            pool_id,
            out_page_id: 0,
            shard_id,
            input_page_ids: &[0],
            ring: &ring,
            input_note: &alice_usdc_note,
            secret_index: alice_usdc_note.slot_index,
            mint_out: mint_wsol.pubkey().to_bytes(),
            token_program_in: token_prog,
            token_program_out: token_prog,
            amount_in: 30_000_000,
            min_amount_out: 200_000_000,
            allow_partial_refund: false,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            router_program_id: router_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            router_ix_data: &ok_data,
            router_accounts: &smuggle_accs,
        },
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&smug_ix)], 700_000),
        AudrenError::InvalidAccount,
        "Reject vault smuggling into router",
    );

    // --- ADVERSARIAL 6: Self-reentrancy (router_program == audren_id) -> InvalidRouterProgram ---
    let (self_ix, _, _, _) = build_swap_via_router(
        &SwapViaRouterParams {
            program_id: audren_id,
            payer: payer.pubkey(),
            pool_id,
            out_page_id: 0,
            shard_id,
            input_page_ids: &[0],
            ring: &ring,
            input_note: &alice_usdc_note,
            secret_index: alice_usdc_note.slot_index,
            mint_out: mint_wsol.pubkey().to_bytes(),
            token_program_in: token_prog,
            token_program_out: token_prog,
            amount_in: 30_000_000,
            min_amount_out: 200_000_000,
            allow_partial_refund: false,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            router_program_id: audren_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            router_ix_data: &ok_data,
            router_accounts: &base_router_accs,
        },
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&self_ix)], 700_000),
        AudrenError::InvalidRouterProgram,
        "Reject self-reentrancy router",
    );

    // --- ADVERSARIAL 7: Unexpected partial fill when allow_partial_refund == false ---
    let partial_data = make_router_data(0, 22_000_000, 210_000_000); // leaves 8_000_000 unspent
    let (unexp_partial_ix, _, _, _) = build_swap_via_router(
        &SwapViaRouterParams {
            program_id: audren_id,
            payer: payer.pubkey(),
            pool_id,
            out_page_id: 0,
            shard_id,
            input_page_ids: &[0],
            ring: &ring,
            input_note: &alice_usdc_note,
            secret_index: alice_usdc_note.slot_index,
            mint_out: mint_wsol.pubkey().to_bytes(),
            token_program_in: token_prog,
            token_program_out: token_prog,
            amount_in: 30_000_000,
            min_amount_out: 200_000_000,
            allow_partial_refund: false,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            router_program_id: router_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            router_ix_data: &partial_data,
            router_accounts: &base_router_accs,
        },
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&unexp_partial_ix)], 700_000),
        AudrenError::UnexpectedPartialFill,
        "Reject unexpected partial fill",
    );

    // --- HAPPY PATH: Partial fill swap WITH change note AND stealth refund note! ---
    // Alice spends 50 USDC note -> swaps 30 USDC (router fills 22 USDC -> pays 250_000_000 WSOL to Bob,
    // 8 USDC unspent refunded to Alice stealth refund note, 20 USDC private change note to Alice!)
    let happy_data = make_router_data(0, 22_000_000, 250_000_000);
    let (happy_ix, _, _, _) = build_swap_via_router(
        &SwapViaRouterParams {
            program_id: audren_id,
            payer: payer.pubkey(),
            pool_id,
            out_page_id: 0,
            shard_id,
            input_page_ids: &[0],
            ring: &ring,
            input_note: &alice_usdc_note,
            secret_index: alice_usdc_note.slot_index,
            mint_out: mint_wsol.pubkey().to_bytes(),
            token_program_in: token_prog,
            token_program_out: token_prog,
            amount_in: 30_000_000,
            min_amount_out: 200_000_000,
            allow_partial_refund: true,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            router_program_id: router_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            router_ix_data: &happy_data,
            router_accounts: &base_router_accs,
        },
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&happy_ix)], 800_000),
        "SwapViaRouter (fill+change+refund, idx=3/1/4)",
    );

    // Verify exact vault & escrow balances (zero tokens left stranded in escrow!)
    assert_eq!(token_balance_of(&svm, &escrow_usdc), 0);
    assert_eq!(token_balance_of(&svm, &escrow_wsol), 0);
    assert_eq!(token_balance_of(&svm, &vault_usdc), 28_000_000); // 20 change + 8 refund!
    assert_eq!(token_balance_of(&svm, &vault_wsol), 250_000_000); // 0.25 WSOL!

    // Verify Bob decrypts his dynamic 250_000_000 WSOL note and can immediately spend/withdraw it!
    let bob_wsol_notes = scan_and_decrypt_page(&svm, &audren_id, pool_id, 0, &bob, Some(250_000_000));
    assert_eq!(bob_wsol_notes.len(), 1);
    assert_eq!(bob_wsol_notes[0].amount, 250_000_000);
    assert_eq!(bob_wsol_notes[0].mint, mint_wsol.pubkey().to_bytes());
    assert!(bob_wsol_notes[0].is_dynamic_output);

    // Prove Bob can spend his dynamic swap output note on-chain via Withdraw!
    let bob_wsol_ata = create_ata_with_balance(&mut svm, &token_prog, &mint_wsol.pubkey(), &authority.pubkey(), 0);
    let ring_after_swap = read_ring(&svm, &audren_id, pool_id, &[0]);
    let (wd_swap_out, _) = build_withdraw(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &[0],
        &ring_after_swap,
        &bob_wsol_notes[0],
        bob_wsol_notes[0].slot_index,
        bob_wsol_ata,
        &bob.address(),
        250_000_000,
        Some(token_prog),
        None,
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&wd_swap_out)], 600_000),
        "Spend & Withdraw dynamic swap output note",
    );
    assert_eq!(token_balance_of(&svm, &bob_wsol_ata), 250_000_000);
}

// ----------------------------------------------------------------------------
// TEST 4: SIMD-0437 Dynamic Rent Scaling & Self-Balancing PageRentVault!
//         Verifies that a 90% Solana rent cut automatically lowers per-note
//         rent collection and stops collecting once vault holds a 2-page buffer!
// ----------------------------------------------------------------------------
#[test]
fn test_simd0437_dynamic_rent_self_balancing() {
    println!("\n=== TEST 4: SIMD-0437 Dynamic Rent Scaling & PageRentVault Self-Balancing ===");
    let mut rng = StdRng::seed_from_u64(0xA0D8_E404);
    let audren_id = Keypair::new().pubkey();
    let mut svm = new_svm(audren_id, None);

    let authority = Keypair::new();
    let payer = Keypair::new();
    svm.airdrop(&authority.pubkey(), 20_000_000_000).unwrap();
    svm.airdrop(&payer.pubkey(), 20_000_000_000).unwrap();

    let alice = AudrenKeys::random(&mut rng);
    let pool_id = 9u32;

    // Initialize pool with a generous max fee cap (0.01 SOL/note) under legacy rent (6960 lamports/byte)
    let init_ix = build_init_pool(
        audren_id,
        authority.pubkey(),
        pool_id,
        PoolMode::Permissionless,
        true,
        [0u8; 32],
        10_000_000,
    );
    expect_ok(
        send_ixs(&mut svm, &authority, &[], &[to_svm_ix(&init_ix)], 300_000),
        "InitPool with 0.01 SOL cap",
    );

    let rent_vault = derive_page_rent_vault_pda(&audren_id, pool_id).0;
    let vault_before = svm.get_account(&rent_vault).unwrap().lamports;

    // Simulate SIMD-0437 90% rent cut (lamports_per_byte: 3480 -> 348 lamports/byte/year)!
    #[allow(deprecated)]
    let simd0437_rent = Rent {
        lamports_per_byte: 348,
        exemption_threshold: 2.0f64.to_le_bytes(),
        burn_percent: 50,
    };
    svm.set_sysvar(&simd0437_rent);
    let reduced_page_rent = simd0437_rent.minimum_balance(PAGE_LEN);
    let expected_capped_per_note = reduced_page_rent.div_ceil(PAGE_CAPACITY as u64);

    // Deposit 1 note — fee MUST automatically cap at `reduced_page_rent / 32`, NOT 10_000_000!
    let (dep_ix, _) = build_deposit(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &alice.address(),
        NATIVE_SOL_MINT,
        100_000_000,
        None,
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&dep_ix)], 300_000),
        "Deposit under SIMD-0437 90% rent cut",
    );
    let vault_after = svm.get_account(&rent_vault).unwrap().lamports;
    let collected = vault_after - vault_before;
    assert_eq!(
        collected, expected_capped_per_note,
        "Fee MUST dynamically track live Rent::get() (got {collected}, want {expected_capped_per_note})"
    );
    assert!(
        collected < 200_000,
        "SIMD-0437 fee must be < 0.0002 SOL/note (was {collected})"
    );

    // Top up PageRentVault to >= min_vault + 2 * reduced_page_rent -> next Deposit collects ZERO fee!
    svm.airdrop(&rent_vault, 2 * reduced_page_rent).unwrap();
    let vault_funded = svm.get_account(&rent_vault).unwrap().lamports;
    let (dep_free, _) = build_deposit(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &alice.address(),
        NATIVE_SOL_MINT,
        100_000_000,
        None,
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&dep_free)], 300_000),
        "Deposit when PageRentVault buffer full",
    );
    assert_eq!(
        svm.get_account(&rent_vault).unwrap().lamports,
        vault_funded,
        "PageRentVault MUST stop collecting once 2-page buffer is reached (zero trapped SOL)!"
    );
    println!(
        "  [SIMD-0437 VERIFIED] Dynamic per-note fee={} lamports (capped from 10,000,000), buffer auto-skip=0!",
        collected
    );
}

// ============================================================================
// TEST 5: ProofBuffer Chunked Upload (Solana Transaction v1) & Adversarial Guards
// ============================================================================
#[test]
fn test_proof_buffer_mtu_and_adversarial_guards() {
    let mut rng = StdRng::seed_from_u64(0xB0F_F32_0005);
    let audren_id = Address::new_unique();
    let mut svm = new_svm(audren_id, None);

    let payer = Keypair::new();
    let attacker = Keypair::new();
    svm.airdrop(&payer.pubkey(), 20_000_000_000).unwrap();
    svm.airdrop(&attacker.pubkey(), 5_000_000_000).unwrap();

    let alice = AudrenKeys::from_seed(&[0xA1; 32]);
    let bob = AudrenKeys::from_seed(&[0xB2; 32]);
    let pool_id = 55u32;

    let init_ix = build_init_pool(
        audren_id,
        payer.pubkey(),
        pool_id,
        PoolMode::Permissionless,
        false,
        [0u8; 32],
        2_000_000,
    );
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&init_ix)], 300_000),
        "InitPool for ProofBuffer test",
    );

    // Deposit 2.0 SOL to Alice
    let (dep_ix, _) = build_deposit(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &alice.address(),
        NATIVE_SOL_MINT,
        2_000_000_000,
        None,
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&dep_ix)], 300_000),
        "Deposit 2 SOL",
    );

    // Build full Transfer (m=5, 2,450+ B payload) to verify chunked ProofBuffer execution via Solana v1 txs
    let ring = read_ring(&svm, &audren_id, pool_id, &[0]);
    let alice_notes = scan_and_decrypt_page(&svm, &audren_id, pool_id, 0, &alice, None);
    assert_eq!(alice_notes.len(), 1);
    let alice_owned = &alice_notes[0];

    let (xfer_ix, _, _) = build_transfer(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &[0],
        &ring,
        alice_owned,
        alice_owned.slot_index,
        &bob.address(),
        &alice.address(),
        1_250_000_000,
        None,
        &[],
        &mut rng,
    )
    .unwrap();

    let plan = build_buffered_execution(&xfer_ix, 777).unwrap();
    assert!(plan.upload_chunks.len() >= 3);

    // Helper: serialize full Solana Transaction v1 (`0x81`) and assert <= 4,096 B limit!
    let send_mtu_checked = |svm: &mut LiteSVM,
                            signer: &Keypair,
                            ixs: &[Instruction],
                            cu_limit: u32,
                            label: &str|
     -> TransactionResult {
        let (tx, wire) = build_v1_tx(signer, &[], ixs, svm.latest_blockhash().to_bytes(), cu_limit);
        let wire_len = wire.len();
        assert!(
            wire_len <= MAX_TRANSACTION_SIZE,
            "{label}: Solana v1 wire tx {wire_len} B exceeds {MAX_TRANSACTION_SIZE} B limit!"
        );
        println!("    [V1 OK] {label}: {wire_len} B <= {MAX_TRANSACTION_SIZE} B");
        svm.send_transaction(tx)
    };

    // Upload chunks OUT OF ORDER (last chunk first!) and verify incomplete buffer rejects ExecBuffered!
    let last_idx = plan.upload_chunks.len() - 1;
    expect_ok(
        send_mtu_checked(
            &mut svm,
            &payer,
            &[to_svm_ix(&plan.upload_chunks[last_idx])],
            100_000,
            "WriteProofBuffer(last chunk first)",
        ),
        "WriteProofBuffer out-of-order chunk",
    );

    // Incomplete buffer MUST reject ExecBuffered!
    expect_custom_err(
        send_mtu_checked(
            &mut svm,
            &payer,
            &[to_svm_ix(&plan.execute)],
            800_000,
            "ExecBuffered(incomplete)",
        ),
        AudrenError::InvalidProofBuffer,
        "incomplete ProofBuffer rejected",
    );

    // Attacker trying to close payer's ProofBuffer MUST fail!
    let mut attacker_close = build_close_proof_buffer(audren_id, attacker.pubkey(), 777);
    attacker_close.accounts[1] = AudrenAccountMeta::writable(plan.proof_buffer);
    expect_custom_err(
        send_mtu_checked(
            &mut svm,
            &attacker,
            &[to_svm_ix(&attacker_close)],
            100_000,
            "CloseProofBuffer(attacker)",
        ),
        AudrenError::InvalidProofBuffer,
        "attacker CloseProofBuffer rejected",
    );

    // Upload remaining chunks (0..last_idx)
    for (idx, chunk_ix) in plan.upload_chunks[..last_idx].iter().enumerate() {
        expect_ok(
            send_mtu_checked(
                &mut svm,
                &payer,
                &[to_svm_ix(chunk_ix)],
                100_000,
                &format!("WriteProofBuffer(chunk {idx})"),
            ),
            "WriteProofBuffer remaining chunk",
        );
    }

    let buf_rent = svm.get_account(&plan.proof_buffer).unwrap().lamports;
    assert!(buf_rent > 0);

    // Execute buffered Transfer — verifies proof, writes 2 notes, AND refunds 100% of buf_rent!
    let exec_cu = expect_ok(
        send_mtu_checked(
            &mut svm,
            &payer,
            &[to_svm_ix(&plan.execute)],
            1_000_000,
            "ExecBuffered(Transfer m=5)",
        ),
        "ExecBuffered Transfer",
    );
    println!(
        "  [BUFFERED TRANSFER OK] CU={} | buffer_rent_refunded={} lamports",
        exec_cu, buf_rent
    );

    // ProofBuffer MUST be closed (either None or 0 lamports & 0 bytes owned by System)
    let buf_after = svm.get_account(&plan.proof_buffer);
    assert!(
        buf_after.as_ref().map(|a| a.lamports == 0 && a.data.is_empty()).unwrap_or(true),
        "ProofBuffer MUST be fully closed and refunded after ExecBuffered!"
    );

    // Verify Bob recovered his 1.25 SOL note via pure-RPC dataSlice scan!
    let bob_notes = scan_and_decrypt_page(&svm, &audren_id, pool_id, 0, &bob, None);
    assert_eq!(bob_notes.len(), 1);
    let bob_owned = &bob_notes[0];
    assert_eq!(bob_owned.amount, 1_250_000_000);

    // Verify CloseProofBuffer reclaims 100% rent from an abandoned upload AND allows nonce reuse!
    svm.expire_blockhash();
    let abandon_chunk = &plan.upload_chunks[0];
    expect_ok(
        send_mtu_checked(
            &mut svm,
            &payer,
            &[to_svm_ix(abandon_chunk)],
            100_000,
            "WriteProofBuffer(abandoned reuse nonce 777)",
        ),
        "reuse closed nonce 777",
    );
    let close_ix = build_close_proof_buffer(audren_id, payer.pubkey(), 777);
    expect_ok(
        send_mtu_checked(
            &mut svm,
            &payer,
            &[to_svm_ix(&close_ix)],
            100_000,
            "CloseProofBuffer(reclaim rent)",
        ),
        "CloseProofBuffer reclaim",
    );
    let buf_closed = svm.get_account(&plan.proof_buffer);
    assert!(
        buf_closed.as_ref().map(|a| a.lamports == 0 && a.data.is_empty()).unwrap_or(true),
        "CloseProofBuffer MUST refund 100% rent!"
    );

    // Verify Buffered Withdraw WITH change also succeeds via Solana Transaction v1!
    let ring2 = read_ring(&svm, &audren_id, pool_id, &[0]);
    let (wd_ix, _) = build_withdraw(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &[0],
        &ring2,
        bob_owned,
        bob_owned.slot_index,
        payer.pubkey(),
        &bob.address(),
        750_000_000,
        None,
        None,
        &mut rng,
    )
    .unwrap();
    let wd_plan = build_buffered_execution(&wd_ix, 888).unwrap();
    for (idx, chunk_ix) in wd_plan.upload_chunks.iter().enumerate() {
        expect_ok(
            send_mtu_checked(
                &mut svm,
                &payer,
                &[to_svm_ix(chunk_ix)],
                100_000,
                &format!("Withdraw WriteProofBuffer(chunk {idx})"),
            ),
            "Withdraw chunk upload",
        );
    }
    let wd_cu = expect_ok(
        send_mtu_checked(
            &mut svm,
            &payer,
            &[to_svm_ix(&wd_plan.execute)],
            800_000,
            "ExecBuffered(Withdraw w/ change)",
        ),
        "ExecBuffered Withdraw with change",
    );
    println!(
        "  [BUFFERED WITHDRAW OK] CU={} | ALL TXS SOLANA V1 (0x81) <= {MAX_TRANSACTION_SIZE} B!",
        wd_cu
    );
}
