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
        build_deposit_with_options, build_exec_via_escrow, build_init_lane, build_init_pool,
        build_merge, build_open_lane_page, build_open_page, build_set_paused, build_transfer,
        build_withdraw, build_withdraw_with_params, net_deposit_amount, AudrenAccountMeta,
        AudrenInstruction, ExecViaEscrowParams, WithdrawParams,
    },
    keys::{AuditorKeypair, AudrenKeys, SelectiveDisclosureProof},
    pda::{
        derive_ata, derive_epoch_page_pda, derive_escrow_pda, derive_lane_pda,
        derive_page_rent_vault_pda, derive_pool_pda, derive_sol_vault_pda, derive_unwrap_pda,
        derive_vault_auth_pda,
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
    AudrenError, PoolMode, CLASSIC_TOKEN_PROGRAM_ID, NATIVE_SOL_MINT, SYSTEM_PROGRAM_ID,
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
        transfer_hook::instruction as transfer_hook_ix, ExtensionType,
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
    let (tx, wire) = build_v1_tx(
        payer,
        extra_signers,
        ixs,
        svm.latest_blockhash().to_bytes(),
        cu_limit,
    );
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
    let space =
        ExtensionType::try_calculate_account_len::<TokenAccount>(account_extensions).unwrap();
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
    let sol_vault_rent =
        svm.minimum_balance_for_rent_exemption(audren_core::layout::SENTINEL_ACCOUNT_LEN);
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
    let payer_usdc = create_ata_with_balance(
        &mut svm,
        &classic_prog,
        &usdc_mint.pubkey(),
        &payer.pubkey(),
        10_000_000,
    );
    let vault_usdc =
        create_ata_with_balance(&mut svm, &classic_prog, &usdc_mint.pubkey(), &vault_auth, 0);

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
    let payer_t22 = create_ata_with_balance(
        &mut svm,
        &t22_prog,
        &safe_t22_mint.pubkey(),
        &payer.pubkey(),
        2_000_000,
    );
    let vault_t22 =
        create_ata_with_balance(&mut svm, &t22_prog, &safe_t22_mint.pubkey(), &vault_auth, 0);
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
    let m_ix = token_ix::initialize_mint2(&t22_prog, &reg_mint.pubkey(), &payer.pubkey(), None, 6)
        .unwrap();
    expect_ok(
        send_ixs(
            &mut svm,
            &payer,
            &[&reg_mint],
            &[c_ix, pd_ix, tf_ix, th_ix, m_ix],
            300_000,
        ),
        "create regulated T22 mint (PYUSD/USDG profile)",
    );
    let payer_reg = create_t22_ata_with_balance(
        &mut svm,
        &payer,
        &t22_prog,
        &reg_mint.pubkey(),
        &payer.pubkey(),
        500_000,
        &[
            ExtensionType::TransferFeeAmount,
            ExtensionType::TransferHookAccount,
        ],
    );
    let vault_reg = create_t22_ata_with_balance(
        &mut svm,
        &payer,
        &t22_prog,
        &reg_mint.pubkey(),
        &vault_auth,
        0,
        &[
            ExtensionType::TransferFeeAmount,
            ExtensionType::TransferHookAccount,
        ],
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
    let fee_space =
        ExtensionType::try_calculate_account_len::<Mint>(&[ExtensionType::TransferFeeConfig])
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
    let m_fee = token_ix::initialize_mint2(&t22_prog, &fee_mint.pubkey(), &payer.pubkey(), None, 6)
        .unwrap();
    expect_ok(
        send_ixs(
            &mut svm,
            &payer,
            &[&fee_mint],
            &[c_fee, tf_active, m_fee],
            300_000,
        ),
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
        false,
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
    let soul_space =
        ExtensionType::try_calculate_account_len::<Mint>(&[ExtensionType::NonTransferable])
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
        send_ixs(
            &mut svm,
            &payer,
            &[&soul_mint],
            &[c_soul, nt_ix, m_soul],
            300_000,
        ),
        "create soulbound NonTransferable T22 mint",
    );
    let payer_soul = create_t22_ata_with_balance(
        &mut svm,
        &payer,
        &t22_prog,
        &soul_mint.pubkey(),
        &payer.pubkey(),
        100_000,
        &[
            ExtensionType::ImmutableOwner,
            ExtensionType::NonTransferableAccount,
        ],
    );
    let vault_soul = create_t22_ata_with_balance(
        &mut svm,
        &payer,
        &t22_prog,
        &soul_mint.pubkey(),
        &vault_auth,
        0,
        &[
            ExtensionType::ImmutableOwner,
            ExtensionType::NonTransferableAccount,
        ],
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
        send_ixs(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&double_spend_ix)],
            1_400_000,
        ),
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
    assert!(
        disclosure.verify().unwrap(),
        "Mode 1 SelectiveDisclosureProof verified!"
    );

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
    assert!(
        !wd_full.accounts[2].is_writable,
        "out_page MUST be readonly when !has_change"
    );
    assert!(
        !wd_full.accounts[4].is_writable,
        "rent_vault MUST be readonly when !has_change"
    );
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&wd_full)], 600_000),
        "Withdraw Native SOL (0.25 SOL full, ro page)",
    );
    assert_eq!(
        svm.get_account(&bob_wallet.pubkey()).unwrap().lamports,
        250_000_000
    );

    // 11. Withdraw Classic SPL (Alice withdraws 3 USDC of her 5 USDC with 2 USDC change)
    let alice_usdc = alice_notes_after
        .iter()
        .find(|n| n.mint == usdc_mint.pubkey().to_bytes())
        .expect("Alice USDC note");
    let bob_usdc_ata = create_ata_with_balance(
        &mut svm,
        &classic_prog,
        &usdc_mint.pubkey(),
        &bob_wallet.pubkey(),
        0,
    );
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
    println!(
        "\n=== TEST 2: InstitutionalAudited Mode (S1/S2 + M1/M2 Verifiable Auditor Decryption) ==="
    );
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
        send_ixs(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&unaudited_xfer)],
            700_000,
        ),
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
        send_ixs(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&audited_xfer)],
            1_400_000,
        ),
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
    let s2: [u8; 32] = audited_xfer.data
        [trip_off + base_trip_len + 32..trip_off + base_trip_len + 64]
        .try_into()
        .unwrap();
    let recovered_p_l = auditor.decrypt_spent_pubkey(&s1, &s2).unwrap();
    assert_eq!(
        recovered_p_l, alice_note.stealth_pk,
        "Auditor MUST recover exact spent stealth pubkey P_l from (S_1, S_2)!"
    );

    let aud_asset_off = audited_xfer.data.len() - AUDITOR_ASSET_PROOF_LEN;
    let m1: [u8; 32] = audited_xfer.data[aud_asset_off..aud_asset_off + 32]
        .try_into()
        .unwrap();
    let m2: [u8; 32] = audited_xfer.data[aud_asset_off + 32..aud_asset_off + 64]
        .try_into()
        .unwrap();
    let recovered_g_mint = auditor.decrypt_asset_generator(&m1, &m2).unwrap();
    assert_eq!(
        recovered_g_mint,
        asset_generator(&NATIVE_SOL_MINT),
        "Auditor MUST recover exact hidden mint generator G_mint from (M_1, M_2)!"
    );
    println!(
        "  [AUDITOR VERIFIED] Decrypted exact P_l and exact G_mint with zero false positives!"
    );
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
    let (swap_escrow, _) = derive_escrow_pda(&audren_id, pool_id, shard_id);
    // Give swap_escrow 1_000_000 lamports so we can verify malicious router cannot drain lamports!
    svm.airdrop(&swap_escrow, 1_000_000).unwrap();

    let payer_usdc = create_ata_with_balance(
        &mut svm,
        &token_prog,
        &mint_usdc.pubkey(),
        &payer.pubkey(),
        100_000_000,
    );
    let vault_usdc =
        create_ata_with_balance(&mut svm, &token_prog, &mint_usdc.pubkey(), &vault_auth, 0);
    let vault_wsol =
        create_ata_with_balance(&mut svm, &token_prog, &mint_wsol.pubkey(), &vault_auth, 0);
    let escrow_usdc =
        create_ata_with_balance(&mut svm, &token_prog, &mint_usdc.pubkey(), &swap_escrow, 0);
    let escrow_wsol =
        create_ata_with_balance(&mut svm, &token_prog, &mint_wsol.pubkey(), &swap_escrow, 0);

    // Mock DEX liquidity pool accounts
    let (mock_pool_auth, _) = Address::find_program_address(&[b"mock_pool"], &router_id);
    let mock_pool_usdc = create_ata_with_balance(
        &mut svm,
        &token_prog,
        &mint_usdc.pubkey(),
        &mock_pool_auth,
        500_000_000,
    );
    let mock_pool_wsol = create_ata_with_balance(
        &mut svm,
        &token_prog,
        &mint_wsol.pubkey(),
        &mock_pool_auth,
        500_000_000_000,
    );

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
    let (slip_ix, _, _, _) = build_exec_via_escrow(
        &ExecViaEscrowParams {
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
            relayer_fee: 0,
            fee_on_output: false,
            fee_recipient_ata: None,
            allow_partial_refund: false,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            target_program_id: router_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            target_ix_data: &bad_slip_data,
            action_accounts: &base_router_accs,
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
    let (del_ix, _, _, _) = build_exec_via_escrow(
        &ExecViaEscrowParams {
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
            relayer_fee: 0,
            fee_on_output: false,
            fee_recipient_ata: None,
            allow_partial_refund: false,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            target_program_id: router_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            target_ix_data: &delegate_data,
            action_accounts: &delegate_accs,
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
    let (own_ix, _, _, _) = build_exec_via_escrow(
        &ExecViaEscrowParams {
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
            relayer_fee: 0,
            fee_on_output: false,
            fee_recipient_ata: None,
            allow_partial_refund: false,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            target_program_id: router_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            target_ix_data: &owner_data,
            action_accounts: &delegate_accs,
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
    let (drain_ix, _, _, _) = build_exec_via_escrow(
        &ExecViaEscrowParams {
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
            relayer_fee: 0,
            fee_on_output: false,
            fee_recipient_ata: None,
            allow_partial_refund: false,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            target_program_id: router_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            target_ix_data: &drain_data,
            action_accounts: &drain_accs,
        },
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&drain_ix)], 700_000),
        AudrenError::EscrowAuthorityAltered,
        "Reject escrow lamport drain",
    );

    // --- ADVERSARIAL 5: Smuggling protected `vault_usdc` inside action_accounts -> InvalidAccount ---
    let smuggle_accs = make_router_accounts(vec![AudrenAccountMeta::writable(vault_usdc)]);
    let ok_data = make_router_data(0, 30_000_000, 250_000_000);
    let (smug_ix, _, _, _) = build_exec_via_escrow(
        &ExecViaEscrowParams {
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
            relayer_fee: 0,
            fee_on_output: false,
            fee_recipient_ata: None,
            allow_partial_refund: false,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            target_program_id: router_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            target_ix_data: &ok_data,
            action_accounts: &smuggle_accs,
        },
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&smug_ix)], 700_000),
        AudrenError::InvalidAccount,
        "Reject vault smuggling into router",
    );

    // --- ADVERSARIAL 6: Self-reentrancy (target_program == audren_id) -> InvalidTargetProgram ---
    let (self_ix, _, _, _) = build_exec_via_escrow(
        &ExecViaEscrowParams {
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
            relayer_fee: 0,
            fee_on_output: false,
            fee_recipient_ata: None,
            allow_partial_refund: false,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            target_program_id: audren_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            target_ix_data: &ok_data,
            action_accounts: &base_router_accs,
        },
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&self_ix)], 700_000),
        AudrenError::InvalidTargetProgram,
        "Reject self-reentrancy target program",
    );

    // --- ADVERSARIAL 7: Unexpected partial fill when allow_partial_refund == false ---
    let partial_data = make_router_data(0, 22_000_000, 210_000_000); // leaves 8_000_000 unspent
    let (unexp_partial_ix, _, _, _) = build_exec_via_escrow(
        &ExecViaEscrowParams {
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
            relayer_fee: 0,
            fee_on_output: false,
            fee_recipient_ata: None,
            allow_partial_refund: false,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            target_program_id: router_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            target_ix_data: &partial_data,
            action_accounts: &base_router_accs,
        },
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&unexp_partial_ix)],
            700_000,
        ),
        AudrenError::UnexpectedPartialFill,
        "Reject unexpected partial fill",
    );

    // --- HAPPY PATH: Partial fill swap WITH change note AND stealth refund note! ---
    // Alice spends 50 USDC note -> swaps 30 USDC (router fills 22 USDC -> pays 250_000_000 WSOL to Bob,
    // 8 USDC unspent refunded to Alice stealth refund note, 20 USDC private change note to Alice!)
    let happy_data = make_router_data(0, 22_000_000, 250_000_000);
    let (happy_ix, _, _, _) = build_exec_via_escrow(
        &ExecViaEscrowParams {
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
            relayer_fee: 0,
            fee_on_output: false,
            fee_recipient_ata: None,
            allow_partial_refund: true,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            target_program_id: router_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            target_ix_data: &happy_data,
            action_accounts: &base_router_accs,
        },
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&happy_ix)], 800_000),
        "ExecViaEscrow (fill+change+refund, idx=3/1/4)",
    );

    // Verify exact vault & escrow balances (zero tokens left stranded in escrow!)
    assert_eq!(token_balance_of(&svm, &escrow_usdc), 0);
    assert_eq!(token_balance_of(&svm, &escrow_wsol), 0);
    assert_eq!(token_balance_of(&svm, &vault_usdc), 28_000_000); // 20 change + 8 refund!
    assert_eq!(token_balance_of(&svm, &vault_wsol), 250_000_000); // 0.25 WSOL!

    // Verify Bob decrypts his dynamic 250_000_000 WSOL note and can immediately spend/withdraw it!
    let bob_wsol_notes =
        scan_and_decrypt_page(&svm, &audren_id, pool_id, 0, &bob, Some(250_000_000));
    assert_eq!(bob_wsol_notes.len(), 1);
    assert_eq!(bob_wsol_notes[0].amount, 250_000_000);
    assert_eq!(bob_wsol_notes[0].mint, mint_wsol.pubkey().to_bytes());
    assert!(bob_wsol_notes[0].is_dynamic_output);

    // Prove Bob can spend his dynamic swap output note on-chain via Withdraw!
    let bob_wsol_ata = create_ata_with_balance(
        &mut svm,
        &token_prog,
        &mint_wsol.pubkey(),
        &authority.pubkey(),
        0,
    );
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
        let (tx, wire) = build_v1_tx(
            signer,
            &[],
            ixs,
            svm.latest_blockhash().to_bytes(),
            cu_limit,
        );
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
        buf_after
            .as_ref()
            .map(|a| a.lamports == 0 && a.data.is_empty())
            .unwrap_or(true),
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
        buf_closed
            .as_ref()
            .map(|a| a.lamports == 0 && a.data.is_empty())
            .unwrap_or(true),
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

// ----------------------------------------------------------------------------
// TEST 6: Cryptographic & Protocol Security Regressions
//   6a. Frozen Heart single-tx `[Deposit(solved P_s), Withdraw(forged)]` MUST fail
//   6b. Open-page concurrent append immunity (immutable per-page prefix_count)
//   6c. Relayer change-note stealth_pk hijacking on Withdraw & SwapViaRouter MUST fail
//   6d. Zero ephemeral_pk deposit rejected + scanner continues past zero slot + 128+128 merge cap
// ----------------------------------------------------------------------------
#[test]
fn test_security_frozen_heart_prefix_immunity_and_change_binding() {
    use audren_client::pda::derive_nullifier_pda;
    use audren_client::prover::{
        bit_generator, compress, decompress, g_point, h_point, hash_to_scalar, nullifier_generator,
        transcript_root,
    };
    use audren_core::{
        instruction::{TAG_DEPOSIT, TAG_WITHDRAW},
        ZK_ELGAMAL_PROOF_PROGRAM_ID,
    };
    use curve25519_dalek::{scalar::Scalar, traits::Identity};

    println!("\n=== TEST 6: Frozen Heart, Open-Page Prefix Immunity, Change Theft & Scanner Hardening ===");
    let mut rng = StdRng::seed_from_u64(0xF802_E477);
    let audren_id = Keypair::new().pubkey();
    let mock_router_id = Keypair::new().pubkey();
    let mut svm = new_svm(audren_id, Some(mock_router_id));

    let authority = Keypair::new();
    let payer = Keypair::new();
    let attacker = Keypair::new();
    svm.airdrop(&authority.pubkey(), 100_000_000_000).unwrap();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
    svm.airdrop(&attacker.pubkey(), 100_000_000_000).unwrap();

    let alice = AudrenKeys::random(&mut rng);
    let bob = AudrenKeys::random(&mut rng);
    let pool_id = 0u32;

    let init_ix = build_init_pool(
        audren_id,
        authority.pubkey(),
        pool_id,
        PoolMode::Permissionless,
        true,
        [0u8; 32],
        2_000_000,
    );
    expect_ok(
        send_ixs(&mut svm, &authority, &[], &[to_svm_ix(&init_ix)], 300_000),
        "InitPool (Security Regression)",
    );

    // 6a. Alice deposits 2 SOL at slot 0; attacker tries the Frozen Heart forge using slot 1 (1 lamport).
    let victim_amount = 2_000_000_000u64;
    let (dep_alice, _) = build_deposit(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &alice.address(),
        NATIVE_SOL_MINT,
        victim_amount,
        None,
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&dep_alice)], 300_000),
        "Alice deposits 2 SOL (slot 0)",
    );

    let ring_before = read_ring(&svm, &audren_id, pool_id, &[0]);
    let p0 = decompress(&ring_before[0].stealth_pk).unwrap();
    let g_sol_bytes = asset_generator(&NATIVE_SOL_MINT);
    let g_sol = decompress(&g_sol_bytes).unwrap();
    let v0_pt = Scalar::from(victim_amount) * g_sol;
    let v1_pt = Scalar::from(1u64) * g_sol;
    let v_spend_bytes = compress(&v0_pt);

    // Build an algebraically consistent Frozen Heart forgery (weak Fiat-Shamir omitting ring_root from xi).
    let m = 5usize;
    let ctx_hash = transcript_root(&[
        b"audren/v1/withdraw",
        audren_id.as_ref(),
        &pool_id.to_le_bytes(),
        &[m as u8, 1u8],
        &NATIVE_SOL_MINT,
        attacker.pubkey().as_ref(),
        &victim_amount.to_le_bytes(),
        &0u64.to_le_bytes(),
        attacker.pubkey().as_ref(),
        &[],
        &[],
    ]);
    let fake_ring_root = [0xAAu8; 32]; // cannot know true ring_root before solving for P_1!
    let alpha = hash_to_scalar(&[
        b"triptych/alpha",
        &ctx_hash,
        &fake_ring_root,
        &g_sol_bytes,
        &v_spend_bytes,
    ]);
    let alpha_bytes = alpha.to_bytes();

    let g = g_point();
    let h = h_point();
    let u = decompress(&nullifier_generator()).unwrap();
    let x_fake = Scalar::random(&mut rng);
    let j_pt = x_fake.invert() * u;
    let j_bytes = compress(&j_pt);

    let r_a = Scalar::random(&mut rng);
    let r_b = Scalar::random(&mut rng);
    let r_c = Scalar::random(&mut rng);
    let r_d = Scalar::random(&mut rng);
    let a_bits: Vec<Scalar> = (0..m).map(|_| Scalar::random(&mut rng)).collect();
    let mut pt_a = r_a * h;
    let pt_b = r_b * h;
    let mut pt_c = r_c * h;
    let mut pt_d = r_d * h;
    for j in 0..m {
        let hj = decompress(&bit_generator(j)).unwrap();
        let aj = a_bits[j];
        pt_a += aj * hj;
        pt_c += aj * hj;
        pt_d += -(aj * aj) * hj;
    }

    // Polynomial coefficients for l = 0: slot 0 has leading xi^m, slot 1 has degree <= m-1.
    let mut poly = vec![vec![Scalar::ZERO; m + 1]; 1 << m];
    for (k, p) in poly.iter_mut().enumerate() {
        p[0] = Scalar::ONE;
        let mut deg = 0usize;
        for j in 0..m {
            let k_bit = (k >> j) & 1;
            let c1 = if k_bit == 0 {
                Scalar::ONE
            } else {
                Scalar::ZERO
            };
            let c0 = if k_bit == 1 { a_bits[j] } else { -a_bits[j] };
            for d in (0..=deg).rev() {
                let prev = p[d];
                p[d + 1] += prev * c1;
                p[d] = prev * c0;
            }
            deg += 1;
        }
    }

    let mut rhos = Vec::with_capacity(m);
    let mut taus = Vec::with_capacity(m);
    let mut xs = Vec::with_capacity(m);
    let mut ys = Vec::with_capacity(m);
    let mut ws = Vec::with_capacity(m);
    for j in 0..m {
        let rho = Scalar::random(&mut rng);
        let tau = Scalar::random(&mut rng);
        rhos.push(rho);
        taus.push(tau);
        xs.push(compress(&(rho * g)));
        ys.push(compress(&(rho * j_pt)));
        let w_acc =
            tau * h + poly[0][j] * (g_sol + alpha * v0_pt) + poly[1][j] * (g_sol + alpha * v1_pt);
        ws.push(compress(&w_acc));
    }
    let a_bytes = compress(&pt_a);
    let b_bytes = compress(&pt_b);
    let c_bytes = compress(&pt_c);
    let d_bytes = compress(&pt_d);
    let mut xi_slices: Vec<&[u8]> = vec![
        b"triptych/xi",
        &fake_ring_root,
        &alpha_bytes,
        &j_bytes,
        &a_bytes,
        &b_bytes,
        &c_bytes,
        &d_bytes,
    ];
    for x in &xs {
        xi_slices.push(x);
    }
    for y in &ys {
        xi_slices.push(y);
    }
    for w in &ws {
        xi_slices.push(w);
    }
    let xi = hash_to_scalar(&xi_slices);

    let mut xi_pow = Scalar::ONE;
    let mut rho_sum = Scalar::ZERO;
    let mut tau_sum = Scalar::ZERO;
    let mut x_eval = curve25519_dalek::ristretto::RistrettoPoint::identity();
    for j in 0..m {
        rho_sum += rhos[j] * xi_pow;
        tau_sum += taus[j] * xi_pow;
        x_eval += xi_pow * decompress(&xs[j]).unwrap();
        xi_pow *= xi;
    }
    let z_a = r_b * xi + r_a;
    let z_c = r_c * xi + r_d;
    let z_x = x_fake * xi_pow - rho_sum;
    let z_q = -tau_sum;

    // Evaluate p_0(xi) and p_1(xi) and solve Eq 3 for P_1!
    let mut p0_xi = Scalar::ONE;
    let mut p1_xi = Scalar::ONE;
    for j in 0..m {
        p0_xi *= xi - a_bits[j];
        p1_xi *= if j == 0 { a_bits[j] } else { xi - a_bits[j] };
    }
    let solved_p1 = compress(&(p1_xi.invert() * (z_x * g + x_eval - p0_xi * p0)));

    // Build atomic [Deposit(1 lamport, solved_p1), Withdraw(2 SOL -> attacker, forged_proof)].
    let (pool_pda, _) = derive_pool_pda(&audren_id, pool_id);
    let (page0_pda, _) = derive_epoch_page_pda(&audren_id, pool_id, 0);
    let (sol_vault, _) = derive_sol_vault_pda(&audren_id, pool_id);
    let (rent_vault, _) = derive_page_rent_vault_pda(&audren_id, pool_id);
    let (null_pda, _) = derive_nullifier_pda(&audren_id, pool_id, &j_bytes);
    let sys_prog = Address::new_from_array(SYSTEM_PROGRAM_ID);
    let zk_prog = Address::new_from_array(ZK_ELGAMAL_PROOF_PROGRAM_ID);

    let mut dep_forge_data = Vec::with_capacity(139);
    dep_forge_data.push(TAG_DEPOSIT);
    dep_forge_data.push(1);
    dep_forge_data.extend_from_slice(&1u64.to_le_bytes());
    dep_forge_data.push(0x42);
    dep_forge_data.extend_from_slice(&compress(&(Scalar::from(7u64) * g)));
    dep_forge_data.extend_from_slice(&solved_p1);
    dep_forge_data.extend_from_slice(&[0u8; 64]);
    let dep_forge_ix = Instruction {
        program_id: audren_id,
        accounts: vec![
            AccountMeta::new(attacker.pubkey(), true),
            AccountMeta::new(pool_pda, false),
            AccountMeta::new(page0_pda, false),
            AccountMeta::new(sol_vault, false),
            AccountMeta::new(rent_vault, false),
            AccountMeta::new_readonly(sys_prog, false),
        ],
        data: dep_forge_data,
    };

    let mut wd_forge_data = Vec::new();
    wd_forge_data.push(TAG_WITHDRAW);
    wd_forge_data.push(m as u8);
    wd_forge_data.push(1); // flags = WITHDRAW_FLAG_NATIVE_SOL
    wd_forge_data.extend_from_slice(&victim_amount.to_le_bytes());
    wd_forge_data.extend_from_slice(&0u64.to_le_bytes()); // relayer_fee = 0
    wd_forge_data.push(2); // prefix_count = 2 (includes slot 0 + freshly deposited slot 1!)
    wd_forge_data.extend_from_slice(&j_bytes);
    wd_forge_data.extend_from_slice(&a_bytes);
    wd_forge_data.extend_from_slice(&b_bytes);
    wd_forge_data.extend_from_slice(&c_bytes);
    wd_forge_data.extend_from_slice(&d_bytes);
    for x in &xs {
        wd_forge_data.extend_from_slice(x);
    }
    for y in &ys {
        wd_forge_data.extend_from_slice(y);
    }
    for w in &ws {
        wd_forge_data.extend_from_slice(w);
    }
    for aj in &a_bits {
        wd_forge_data.extend_from_slice(&aj.to_bytes());
    }
    wd_forge_data.extend_from_slice(&z_a.to_bytes());
    wd_forge_data.extend_from_slice(&z_c.to_bytes());
    wd_forge_data.extend_from_slice(&z_x.to_bytes());
    wd_forge_data.extend_from_slice(&z_q.to_bytes());
    let wd_forge_ix = Instruction {
        program_id: audren_id,
        accounts: vec![
            AccountMeta::new(attacker.pubkey(), true),
            AccountMeta::new(pool_pda, false),
            AccountMeta::new_readonly(page0_pda, false),
            AccountMeta::new(null_pda, false),
            AccountMeta::new_readonly(rent_vault, false),
            AccountMeta::new_readonly(zk_prog, false),
            AccountMeta::new_readonly(sys_prog, false),
            AccountMeta::new_readonly(attacker.pubkey(), false),
            AccountMeta::new(sol_vault, false),
            AccountMeta::new(attacker.pubkey(), false),
            AccountMeta::new_readonly(page0_pda, false),
        ],
        data: wd_forge_data,
    };
    expect_custom_err(
        send_ixs(
            &mut svm,
            &attacker,
            &[],
            &[dep_forge_ix, wd_forge_ix],
            1_000_000,
        ),
        AudrenError::InvalidTriptychProof,
        "Frozen Heart atomic deposit+withdraw forge",
    );

    // 6b. Open-page concurrent append immunity: Bob deposits at slot 1, then Alice and Bob BOTH
    //     build transfers from the exact same open-page snapshot (count=2). Alice lands first
    //     (appending slots 2 and 3). Bob's UNCHANGED pre-built tx MUST still succeed!
    let (dep_bob, _) = build_deposit(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &bob.address(),
        NATIVE_SOL_MINT,
        1_000_000_000,
        None,
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&dep_bob)], 300_000),
        "Bob deposits 1 SOL (slot 1)",
    );
    let shared_open_ring = read_ring(&svm, &audren_id, pool_id, &[0]);
    let alice_note = scan_and_decrypt_page(&svm, &audren_id, pool_id, 0, &alice, None)
        .pop()
        .unwrap();
    let bob_note = scan_and_decrypt_page(&svm, &audren_id, pool_id, 0, &bob, None)
        .pop()
        .unwrap();

    let (alice_tx, _, _) = build_transfer(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &[0],
        &shared_open_ring,
        &alice_note,
        alice_note.slot_index,
        &bob.address(),
        &alice.address(),
        500_000_000,
        None,
        &[],
        &mut rng,
    )
    .unwrap();
    let (bob_tx, _, _) = build_transfer(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &[0],
        &shared_open_ring,
        &bob_note,
        bob_note.slot_index,
        &alice.address(),
        &bob.address(),
        400_000_000,
        None,
        &[],
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&alice_tx)], 900_000),
        "Open-page concurrent transfer #1 (Alice)",
    );
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&bob_tx)], 900_000),
        "Open-page concurrent transfer #2 (Bob, same snapshot!)",
    );

    // 6c. Relayer change-note theft defense: tamper ONLY with change note stealth_pk on partial Withdraw!
    let ring_after = read_ring(&svm, &audren_id, pool_id, &[0]);
    let bob_new_notes = scan_and_decrypt_page(&svm, &audren_id, pool_id, 0, &bob, None);
    let bob_spendable = bob_new_notes
        .iter()
        .find(|n| n.slot_index >= 2 && n.amount >= 500_000_000)
        .expect("Bob received transfer note");
    let (mut partial_wd, _) = build_withdraw(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &[0],
        &ring_after,
        bob_spendable,
        bob_spendable.slot_index,
        payer.pubkey(),
        &bob.address(),
        100_000_000,
        None,
        None,
        &mut rng,
    )
    .unwrap();
    // Change note wire starts at data[19..]; stealth_pk is at offset +33..+65 inside NOTE_WIRE_LEN.
    let attacker_stealth = compress(&(Scalar::from(999u64) * g));
    partial_wd.data[19 + 33..19 + 65].copy_from_slice(&attacker_stealth);
    expect_custom_err(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&partial_wd)], 900_000),
        AudrenError::InvalidTriptychProof,
        "Relayer change stealth_pk hijack on Withdraw",
    );

    // 6d. Zero ephemeral_pk deposit rejected + scanner survives synthetic zero slot + 128+128 merge rejected.
    let (mut bad_eph_dep, _) = build_deposit(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &alice.address(),
        NATIVE_SOL_MINT,
        10_000,
        None,
        &mut rng,
    )
    .unwrap();
    bad_eph_dep.data[11..43].fill(0); // ephemeral_pk = [0u8; 32]
    expect_custom_err(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&bad_eph_dep)], 300_000),
        AudrenError::InvalidPoint,
        "Deposit with zero ephemeral_pk",
    );

    // Rust dataSlice scanner must NOT abort at a zero ephemeral_pk in slot 0 when slot 1 is owned!
    let mut crafted_slice = [0u8; PAGE_SCAN_LEN];
    let page0_bytes = read_page_bytes(&svm, &audren_id, pool_id, 0);
    // Copy slot 0 (Alice's deposit) into slot 1, leaving slot 0 all zeros.
    crafted_slice[1] = page0_bytes[PAGE_SCAN_OFFSET];
    crafted_slice[PAGE_CAPACITY + 32..PAGE_CAPACITY + 64].copy_from_slice(
        &page0_bytes[PAGE_SCAN_OFFSET + PAGE_CAPACITY..PAGE_SCAN_OFFSET + PAGE_CAPACITY + 32],
    );
    let hits = scan_page_dataslice(&alice.full_viewing_key(), 0, &crafted_slice).unwrap();
    assert!(
        hits.iter().any(|h| h.slot_index == 1),
        "scan_page_dataslice MUST continue past a zero slot and find slot 1"
    );

    // Client build_merge MUST reject combined ring > 128 (e.g. 4 pages + 4 pages = 128+128).
    let fake_4pages = vec![RingSlotWitness::EMPTY; 4 * PAGE_CAPACITY];
    assert!(
        build_merge(
            audren_id,
            payer.pubkey(),
            pool_id,
            0,
            &[0, 1, 2, 3],
            &fake_4pages,
            bob_spendable,
            0,
            &[0, 1, 2, 3],
            &fake_4pages,
            bob_spendable,
            0,
            &bob.address(),
            None,
            &mut rng,
        )
        .is_err(),
        "build_merge MUST reject 128+128 rings (> 128 combined cap)"
    );
    println!("  [ALL SECURITY REGRESSIONS PASSED]");
}

// ----------------------------------------------------------------------------
// TEST 7: Multi-Lane Lock-Free Appends (Read-Only PoolState), Non-Custodial
//         Pause Escape Hatch (Full Withdraw While Paused), Real Page Slots,
//         and On-Chain Selective Disclosure Inclusion Verification!
// ----------------------------------------------------------------------------
#[test]
fn test_multilane_parallel_appends_pause_escape_and_slots() {
    println!("\n=== TEST 7: Multi-Lane Appends + Pause Escape Hatch + Real Slots ===");
    let audren_id = Keypair::new().pubkey();
    let mut svm = new_svm(audren_id, None);
    svm.warp_to_slot(42_000);
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_7777);

    let authority = Keypair::new();
    let payer = Keypair::new();
    svm.airdrop(&authority.pubkey(), 100_000_000_000).unwrap();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();

    let alice = AudrenKeys::random(&mut rng);
    let bob = AudrenKeys::random(&mut rng);
    let pool_id = 0u32;

    let init_ix = build_init_pool(
        audren_id,
        authority.pubkey(),
        pool_id,
        PoolMode::Permissionless,
        true,
        [0u8; 32],
        2_000_000,
    );
    expect_ok(
        send_ixs(&mut svm, &authority, &[], &[to_svm_ix(&init_ix)], 300_000),
        "InitPool (Multi-Lane)",
    );

    // 7a. Page 0 records real non-zero `created_slot`!
    let p0_hdr = PageHeader::decode(&read_page_bytes(&svm, &audren_id, pool_id, 0)).unwrap();
    assert_eq!(
        p0_hdr.created_slot, 42_000,
        "Page 0 MUST record real created_slot"
    );

    // 7b. Authority activates parallel Lane 1 (`Tag 11`), initializing `(1 << 56) | 0`.
    svm.warp_to_slot(42_100);
    let init_lane1 = build_init_lane(audren_id, authority.pubkey(), pool_id, 1).unwrap();
    expect_ok(
        send_ixs(
            &mut svm,
            &authority,
            &[],
            &[to_svm_ix(&init_lane1)],
            300_000,
        ),
        "InitLane (Lane 1)",
    );
    let (pool_pda, _) = derive_pool_pda(&audren_id, pool_id);
    let pool_state = PoolState::decode(&svm.get_account(&pool_pda).unwrap().data).unwrap();
    assert_eq!(
        pool_state.effective_lane_count(),
        2,
        "Pool MUST report 2 active lanes"
    );

    let lane1_page0 = audren_core::page_id_for_lane(1, 0).unwrap();
    let (lane1_pda, _) = derive_lane_pda(&audren_id, pool_id, 1);
    let lane1_state =
        audren_core::layout::AppendLaneState::decode(&svm.get_account(&lane1_pda).unwrap().data)
            .unwrap();
    assert_eq!(lane1_state.current_page_id, lane1_page0);
    assert_eq!(lane1_state.created_slot, 42_100);

    // 7c. Deposit into Lane 1 with `PoolState` READ-ONLY!
    let (dep_lane1, _) = build_deposit(
        audren_id,
        payer.pubkey(),
        pool_id,
        lane1_page0,
        &alice.address(),
        NATIVE_SOL_MINT,
        2_000_000_000,
        None,
        &mut rng,
    )
    .unwrap();
    assert!(
        !dep_lane1.accounts[1].is_writable,
        "Lane 1 Deposit MUST keep PoolState READ-ONLY (zero write-lock!)"
    );
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&dep_lane1)], 300_000),
        "Deposit onto Lane 1 (PoolState read-only)",
    );

    // 7d. Verify SelectiveDisclosureProof directly against authentic on-chain EpochPage bytes!
    let lane1_bytes = read_page_bytes(&svm, &audren_id, pool_id, lane1_page0);
    let alice_lane1_note =
        scan_and_decrypt_page(&svm, &audren_id, pool_id, lane1_page0, &alice, None)
            .pop()
            .unwrap();
    let disclosure = SelectiveDisclosureProof {
        version: 1,
        page_id: alice_lane1_note.page_id,
        slot_index: alice_lane1_note.slot_index as u8,
        stealth_pk_b58: bs58::encode(alice_lane1_note.stealth_pk).into_string(),
        asset_tag_b58: bs58::encode(alice_lane1_note.asset_tag).into_string(),
        commitment_b58: bs58::encode(alice_lane1_note.commitment).into_string(),
        mint_b58: bs58::encode(alice_lane1_note.mint).into_string(),
        amount: alice_lane1_note.amount,
        asset_blinding_b58: bs58::encode(alice_lane1_note.asset_blinding.to_bytes()).into_string(),
        value_blinding_b58: bs58::encode(alice_lane1_note.value_blinding.to_bytes()).into_string(),
    };
    assert!(
        disclosure.verify_against_page(&lane1_bytes).unwrap(),
        "Selective disclosure MUST verify against authentic on-chain EpochPage!"
    );
    let p0_bytes = read_page_bytes(&svm, &audren_id, pool_id, 0);
    assert!(
        !disclosure.verify_against_page(&p0_bytes).unwrap(),
        "Selective disclosure MUST reject wrong EpochPage!"
    );

    // 7e. Transfer from Lane 1 -> Lane 1 with `PoolState` READ-ONLY, then verify cross-lane
    //     double-spend (spending the same Lane 1 note into Lane 0) fails with NullifierAlreadySpent!
    let ring_lane1 = read_ring(&svm, &audren_id, pool_id, &[lane1_page0]);
    let (xfer_lane1, _, _) = build_transfer(
        audren_id,
        payer.pubkey(),
        pool_id,
        lane1_page0,
        &[lane1_page0],
        &ring_lane1,
        &alice_lane1_note,
        alice_lane1_note.slot_index,
        &bob.address(),
        &alice.address(),
        1_200_000_000,
        None,
        &[],
        &mut rng,
    )
    .unwrap();
    assert!(
        !xfer_lane1.accounts[1].is_writable,
        "Lane 1 Transfer MUST keep PoolState READ-ONLY!"
    );
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&xfer_lane1)], 900_000),
        "Transfer on Lane 1 (PoolState read-only)",
    );
    let (double_spend_lane0, _, _) = build_transfer(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &[lane1_page0],
        &ring_lane1,
        &alice_lane1_note,
        alice_lane1_note.slot_index,
        &bob.address(),
        &alice.address(),
        100_000_000,
        None,
        &[],
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&double_spend_lane0)],
            900_000,
        ),
        AudrenError::NullifierAlreadySpent,
        "Cross-lane double spend rejected by unified NullifierPDA",
    );

    // 7f. Fill Lane 1 page 0 to 28 entries and execute permissionless `OpenLanePage` (Tag 12)
    //     with `PoolState` READ-ONLY, verifying real `closed_slot` & `created_slot`!
    for _ in 0..25 {
        let (d, _) = build_deposit(
            audren_id,
            payer.pubkey(),
            pool_id,
            lane1_page0,
            &bob.address(),
            NATIVE_SOL_MINT,
            10_000,
            None,
            &mut rng,
        )
        .unwrap();
        expect_ok(
            send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&d)], 300_000),
            "Fill Lane 1 page 0 to rollover threshold",
        );
    }
    svm.warp_to_slot(42_500);
    let roll_lane1 = build_open_lane_page(audren_id, payer.pubkey(), pool_id, lane1_page0).unwrap();
    assert!(
        !roll_lane1.accounts[1].is_writable,
        "OpenLanePage MUST keep PoolState READ-ONLY!"
    );
    expect_ok(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&roll_lane1)], 300_000),
        "Permissionless OpenLanePage (Lane 1 -> page 1)",
    );
    let sealed_hdr =
        PageHeader::decode(&read_page_bytes(&svm, &audren_id, pool_id, lane1_page0)).unwrap();
    assert!(sealed_hdr.closed && sealed_hdr.closed_slot == 42_500);
    let lane1_page1 = audren_core::page_id_for_lane(1, 1).unwrap();
    let new_hdr =
        PageHeader::decode(&read_page_bytes(&svm, &audren_id, pool_id, lane1_page1)).unwrap();
    assert!(!new_hdr.closed && new_hdr.created_slot == 42_500);

    // 7g. Emergency pause blocks deposits AND partial withdrawals, while FULL withdrawal
    //     (`has_change = false`, read-only PoolState) ALWAYS succeeds as a non-custodial escape hatch!
    let pause_ix = build_set_paused(audren_id, authority.pubkey(), pool_id, true);
    expect_ok(
        send_ixs(&mut svm, &authority, &[], &[to_svm_ix(&pause_ix)], 100_000),
        "SetPaused(true)",
    );
    let (blocked_dep, _) = build_deposit(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &alice.address(),
        NATIVE_SOL_MINT,
        50_000,
        None,
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(&mut svm, &payer, &[], &[to_svm_ix(&blocked_dep)], 300_000),
        AudrenError::PoolPaused,
        "Deposit blocked while paused",
    );
    let ring_sealed = read_ring(&svm, &audren_id, pool_id, &[lane1_page0]);
    let bob_notes = scan_and_decrypt_page(&svm, &audren_id, pool_id, lane1_page0, &bob, None);
    let bob_big = bob_notes
        .iter()
        .find(|n| n.amount == 1_200_000_000)
        .expect("Bob received 1.2 SOL note on Lane 1");
    let (blocked_partial_wd, _) = build_withdraw(
        audren_id,
        payer.pubkey(),
        pool_id,
        lane1_page1,
        &[lane1_page0],
        &ring_sealed,
        bob_big,
        bob_big.slot_index,
        payer.pubkey(),
        &bob.address(),
        500_000_000,
        None,
        None,
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&blocked_partial_wd)],
            900_000,
        ),
        AudrenError::PoolPaused,
        "Partial withdraw blocked while paused",
    );
    let (escape_full_wd, _) = build_withdraw(
        audren_id,
        payer.pubkey(),
        pool_id,
        0,
        &[lane1_page0],
        &ring_sealed,
        bob_big,
        bob_big.slot_index,
        payer.pubkey(),
        &bob.address(),
        bob_big.amount,
        None,
        None,
        &mut rng,
    )
    .unwrap();
    assert!(
        !escape_full_wd.accounts[1].is_writable,
        "Full withdraw MUST keep PoolState READ-ONLY!"
    );
    expect_ok(
        send_ixs(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&escape_full_wd)],
            700_000,
        ),
        "Full Withdraw SUCCEEDS while Pool is Paused (non-custodial escape hatch!)",
    );
    println!("  [MULTI-LANE + PAUSE ESCAPE + REAL SLOTS PASSED]");
}

// ----------------------------------------------------------------------------
// TEST 8: v0.3.0 Universal DeFi Execution Rail, Native Relayer Fees,
//         Atomic WSOL Unwrap -> 0-Lamport Deterministic DeFi Session Wallet,
//         Pause Escape Hatch on Unwrap, and Zero-Dust `fee_from_amount` Sweep!
// ----------------------------------------------------------------------------
#[test]
fn test_v030_exec_fees_unwrap_wsol_defi_session_and_zero_dust_sweep() {
    use audren_core::WSOL_MINT;
    use solana_system_interface::instruction as sys_ix;
    use spl_token_2022_interface::instruction as token_ix;

    println!("\n=== TEST 8: v0.3.0 ExecViaEscrow Fees, Withdraw unwrap_wsol, DeFi Session B_0 & Zero-Dust Sweep ===");
    let mut rng = StdRng::seed_from_u64(0x0303_2026);
    let audren_id = Keypair::new().pubkey();
    let router_id = Keypair::new().pubkey();
    let mut svm = new_svm(audren_id, Some(router_id));

    let authority = Keypair::new();
    let relayer = Keypair::new();
    let fee_recipient = Keypair::new();
    svm.airdrop(&authority.pubkey(), 50_000_000_000).unwrap();
    svm.airdrop(&relayer.pubkey(), 50_000_000_000).unwrap();
    // Give fee_recipient minimal rent-exempt balance so SystemProgram transfers of any size succeed cleanly
    svm.airdrop(&fee_recipient.pubkey(), 1_000_000).unwrap();

    let master_seed = [0x33u8; 32];
    let alice = AudrenKeys::from_seed(&master_seed);
    let bob = AudrenKeys::random(&mut rng);
    let session_b0 = AudrenKeys::derive_defi_session_keypair(&master_seed, 0);
    let session_kp = Keypair::new_from_array(session_b0.secret_seed);
    let session_pubkey = session_kp.pubkey();
    assert_eq!(session_pubkey.to_bytes(), session_b0.pubkey);
    assert!(svm.get_account(&session_pubkey).is_none(), "B_0 starts with 0 lamports!");

    let pool_id = 30u32;
    let shard_id = 5u8;
    let page_rent_fee = 1_500_000u64;
    let init_ix = build_init_pool(
        audren_id,
        authority.pubkey(),
        pool_id,
        PoolMode::Permissionless,
        true,
        [0u8; 32],
        page_rent_fee,
    );
    expect_ok(
        send_ixs(&mut svm, &authority, &[], &[to_svm_ix(&init_ix)], 300_000),
        "InitPool (v0.3.0)",
    );

    let token_prog = Address::new_from_array(CLASSIC_TOKEN_PROGRAM_ID);
    let wsol_mint = Address::new_from_array(WSOL_MINT);
    // Ensure LiteSVM has the canonical genesis WSOL Mint account (82 bytes, decimals=9, initialized=true).
    {
        let mut wsol_mint_data = vec![0u8; 82];
        wsol_mint_data[44] = 9; // decimals = 9
        wsol_mint_data[45] = 1; // is_initialized = true
        svm.set_account(
            wsol_mint,
            Account {
                lamports: svm.minimum_balance_for_rent_exemption(82),
                data: wsol_mint_data,
                owner: token_prog,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    }
    let mint_usdc = create_mint(&mut svm, &relayer, &token_prog, 6);

    let (vault_auth, _) = derive_vault_auth_pda(&audren_id, pool_id);
    let (escrow_pda, _) = derive_escrow_pda(&audren_id, pool_id, shard_id);
    let (sol_vault, _) = derive_sol_vault_pda(&audren_id, pool_id);
    let (rent_vault, _) = derive_page_rent_vault_pda(&audren_id, pool_id);
    svm.airdrop(&escrow_pda, 1_000_000).unwrap();

    // Helper: create a real native WSOL Classic SPL token account funded with `lamports` of WSOL.
    let create_real_wsol_account = |svm: &mut LiteSVM, owner: &Address, wsol_amount: u64| -> Address {
        let acct = Keypair::new();
        let rent = svm.minimum_balance_for_rent_exemption(165);
        let c_ix = sys_ix::create_account(
            &relayer.pubkey(),
            &acct.pubkey(),
            rent + wsol_amount,
            165,
            &token_prog,
        );
        let init_ix = token_ix::initialize_account3(&token_prog, &acct.pubkey(), &wsol_mint, owner).unwrap();
        expect_ok(
            send_ixs(svm, &relayer, &[&acct], &[c_ix, init_ix], 200_000),
            "create real native WSOL token account",
        );
        acct.pubkey()
    };
    let create_real_wsol_ata = |svm: &mut LiteSVM, owner: &Address, wsol_amount: u64| -> Address {
        let ata = derive_ata(owner, &token_prog, &wsol_mint);
        let rent = svm.minimum_balance_for_rent_exemption(165);
        let mut data = vec![0u8; 165];
        data[0..32].copy_from_slice(wsol_mint.as_ref());
        data[32..64].copy_from_slice(owner.as_ref());
        data[64..72].copy_from_slice(&wsol_amount.to_le_bytes());
        // SPL Token Account layout: state(108)=1(Initialized), is_native(109..121)=Some(rent)
        data[108] = 1;
        data[109..113].copy_from_slice(&1u32.to_le_bytes());
        data[113..121].copy_from_slice(&rent.to_le_bytes());
        svm.set_account(
            ata,
            Account {
                lamports: rent + wsol_amount,
                data,
                owner: token_prog,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        ata
    };

    let payer_usdc = create_ata_with_balance(&mut svm, &token_prog, &mint_usdc.pubkey(), &relayer.pubkey(), 100_000_000);
    let vault_usdc = create_ata_with_balance(&mut svm, &token_prog, &mint_usdc.pubkey(), &vault_auth, 0);
    let vault_wsol = create_real_wsol_ata(&mut svm, &vault_auth, 0);
    let escrow_usdc = create_ata_with_balance(&mut svm, &token_prog, &mint_usdc.pubkey(), &escrow_pda, 0);
    let escrow_wsol = create_real_wsol_ata(&mut svm, &escrow_pda, 0);
    let relayer_usdc_ata = create_ata_with_balance(&mut svm, &token_prog, &mint_usdc.pubkey(), &fee_recipient.pubkey(), 0);
    let relayer_wsol_ata = create_real_wsol_ata(&mut svm, &fee_recipient.pubkey(), 0);
    let payer_wsol_src = create_real_wsol_account(&mut svm, &relayer.pubkey(), 3_000_000_000);

    let (mock_pool_auth, _) = Address::find_program_address(&[b"mock_pool"], &router_id);
    let mock_pool_usdc = create_ata_with_balance(&mut svm, &token_prog, &mint_usdc.pubkey(), &mock_pool_auth, 500_000_000);
    let mock_pool_wsol = create_real_wsol_ata(&mut svm, &mock_pool_auth, 10_000_000_000);

    // Deposit 50 USDC + 2.0 real WSOL for Alice
    let (dep_usdc, _) = build_deposit(
        audren_id,
        relayer.pubkey(),
        pool_id,
        0,
        &alice.address(),
        mint_usdc.pubkey().to_bytes(),
        50_000_000,
        Some((token_prog, payer_usdc, vault_usdc)),
        &mut rng,
    )
    .unwrap();
    expect_ok(send_ixs(&mut svm, &relayer, &[], &[to_svm_ix(&dep_usdc)], 300_000), "Deposit 50 USDC");

    let (dep_wsol, _) = build_deposit(
        audren_id,
        relayer.pubkey(),
        pool_id,
        0,
        &alice.address(),
        WSOL_MINT,
        2_000_000_000,
        Some((token_prog, payer_wsol_src, vault_wsol)),
        &mut rng,
    )
    .unwrap();
    expect_ok(send_ixs(&mut svm, &relayer, &[], &[to_svm_ix(&dep_wsol)], 300_000), "Deposit 2.0 real WSOL");

    let alice_notes = scan_and_decrypt_page(&svm, &audren_id, pool_id, 0, &alice, None);
    let alice_usdc = alice_notes.iter().find(|n| n.mint == mint_usdc.pubkey().to_bytes()).unwrap().clone();
    let alice_wsol = alice_notes.iter().find(|n| n.mint == WSOL_MINT).unwrap().clone();
    let ring = read_ring(&svm, &audren_id, pool_id, &[0]);

    let base_action_accs = vec![
        AudrenAccountMeta::readonly(mock_pool_auth),
        AudrenAccountMeta::writable(escrow_usdc),
        AudrenAccountMeta::writable(mock_pool_usdc),
        AudrenAccountMeta::writable_signer(escrow_pda),
        AudrenAccountMeta::writable(escrow_wsol),
        AudrenAccountMeta::writable(mock_pool_wsol),
        AudrenAccountMeta::readonly(token_prog),
        AudrenAccountMeta::readonly(token_prog),
        AudrenAccountMeta::readonly(mint_usdc.pubkey()),
        AudrenAccountMeta::readonly(wsol_mint),
    ];
    let (escrow_idx, escrow_in_idx, escrow_out_idx) =
        locate_escrow_indices(&base_action_accs, &escrow_pda, &escrow_usdc, &escrow_wsol).unwrap();
    let make_router_data = |spend_in: u64, pay_out: u64| {
        let mut d = Vec::with_capacity(19);
        d.push(0u8);
        d.extend_from_slice(&spend_in.to_le_bytes());
        d.extend_from_slice(&pay_out.to_le_bytes());
        d.push(6);
        d.push(9);
        d
    };

    // 8a-ADVERSARIAL: fee_recipient_ata aliased inside action_accounts -> InvalidAccount
    let mut aliased_accs = base_action_accs.clone();
    aliased_accs.push(AudrenAccountMeta::writable(relayer_usdc_ata));
    let rdata_29 = make_router_data(29_000_000, 250_000_000);
    let (bad_alias_ix, _, _, _) = build_exec_via_escrow(
        &ExecViaEscrowParams {
            program_id: audren_id,
            payer: relayer.pubkey(),
            pool_id,
            out_page_id: 0,
            shard_id,
            input_page_ids: &[0],
            ring: &ring,
            input_note: &alice_usdc,
            secret_index: alice_usdc.slot_index,
            mint_out: WSOL_MINT,
            token_program_in: token_prog,
            token_program_out: token_prog,
            amount_in: 30_000_000,
            min_amount_out: 200_000_000,
            relayer_fee: 1_000_000,
            fee_on_output: false,
            fee_recipient_ata: Some(relayer_usdc_ata),
            allow_partial_refund: false,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            target_program_id: router_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            target_ix_data: &rdata_29,
            action_accounts: &aliased_accs,
        },
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(&mut svm, &relayer, &[], &[to_svm_ix(&bad_alias_ix)], 800_000),
        AudrenError::InvalidAccount,
        "Reject fee_recipient_ata aliased into action_accounts",
    );

    // 8a-ADVERSARIAL: vault-owned fee_recipient_ata -> InvalidAccount
    let (bad_vault_fee_ix, _, _, _) = build_exec_via_escrow(
        &ExecViaEscrowParams {
            program_id: audren_id,
            payer: relayer.pubkey(),
            pool_id,
            out_page_id: 0,
            shard_id,
            input_page_ids: &[0],
            ring: &ring,
            input_note: &alice_usdc,
            secret_index: alice_usdc.slot_index,
            mint_out: WSOL_MINT,
            token_program_in: token_prog,
            token_program_out: token_prog,
            amount_in: 30_000_000,
            min_amount_out: 200_000_000,
            relayer_fee: 1_000_000,
            fee_on_output: false,
            fee_recipient_ata: Some(vault_usdc),
            allow_partial_refund: false,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            target_program_id: router_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            target_ix_data: &rdata_29,
            action_accounts: &base_action_accs,
        },
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(&mut svm, &relayer, &[], &[to_svm_ix(&bad_vault_fee_ix)], 800_000),
        AudrenError::InvalidAccount,
        "Reject vault_usdc as fee_recipient_ata",
    );

    // 8a-HAPPY: ExecViaEscrow with fee_on_output = false (1 USDC fee from 30 USDC input; 20 USDC change!)
    let (mut exec_in_fee_ix, _, _, _) = build_exec_via_escrow(
        &ExecViaEscrowParams {
            program_id: audren_id,
            payer: relayer.pubkey(),
            pool_id,
            out_page_id: 0,
            shard_id,
            input_page_ids: &[0],
            ring: &ring,
            input_note: &alice_usdc,
            secret_index: alice_usdc.slot_index,
            mint_out: WSOL_MINT,
            token_program_in: token_prog,
            token_program_out: token_prog,
            amount_in: 30_000_000,
            min_amount_out: 200_000_000,
            relayer_fee: 1_000_000,
            fee_on_output: false,
            fee_recipient_ata: Some(relayer_usdc_ata),
            allow_partial_refund: false,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            target_program_id: router_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            target_ix_data: &rdata_29,
            action_accounts: &base_action_accs,
        },
        &mut rng,
    )
    .unwrap();

    // Tampering fee_recipient_ata (account [15]) MUST fail Fiat-Shamir proof!
    let mut tampered_fee_ata = exec_in_fee_ix.clone();
    tampered_fee_ata.accounts[15].pubkey = payer_usdc;
    expect_custom_err(
        send_ixs(&mut svm, &relayer, &[], &[to_svm_ix(&tampered_fee_ata)], 800_000),
        AudrenError::InvalidTriptychProof,
        "Reject tampered fee_recipient_ata on ExecViaEscrow",
    );
    // Tampering relayer_fee byte MUST fail Fiat-Shamir proof!
    let mut tampered_fee_amt = exec_in_fee_ix.clone();
    tampered_fee_amt.data[20] ^= 0x01;
    expect_custom_err(
        send_ixs(&mut svm, &relayer, &[], &[to_svm_ix(&tampered_fee_amt)], 800_000),
        AudrenError::InvalidTriptychProof,
        "Reject tampered relayer_fee on ExecViaEscrow",
    );
    exec_in_fee_ix.accounts[15].pubkey = relayer_usdc_ata; // untouched
    expect_ok(
        send_ixs(&mut svm, &relayer, &[], &[to_svm_ix(&exec_in_fee_ix)], 900_000),
        "ExecViaEscrow (fee_on_output=false, 1 USDC fee -> relayer, 29 USDC -> escrow)",
    );
    assert_eq!(token_balance_of(&svm, &relayer_usdc_ata), 1_000_000);
    assert_eq!(token_balance_of(&svm, &vault_usdc), 20_000_000);
    assert_eq!(token_balance_of(&svm, &escrow_usdc), 0);
    assert_eq!(token_balance_of(&svm, &escrow_wsol), 0);
    assert_eq!(token_balance_of(&svm, &vault_wsol), 2_250_000_000); // 2.0 WSOL + 0.25 WSOL

    // 8b-HAPPY + SLIPPAGE: ExecViaEscrow with fee_on_output = true (spend Alice's 20 USDC change note!)
    let ring2 = read_ring(&svm, &audren_id, pool_id, &[0]);
    let alice_chg_usdc = scan_and_decrypt_page(&svm, &audren_id, pool_id, 0, &alice, None)
        .into_iter()
        .find(|n| n.mint == mint_usdc.pubkey().to_bytes() && n.amount == 20_000_000)
        .expect("Alice decrypts 20 USDC change note");
    let rdata_20 = make_router_data(20_000_000, 200_000_000);

    // Slippage check must apply AFTER subtracting relayer_fee (200_000_000 - 15_000_000 = 185_000_000 < 185_000_001)
    let (slip_after_fee_ix, _, _, _) = build_exec_via_escrow(
        &ExecViaEscrowParams {
            program_id: audren_id,
            payer: relayer.pubkey(),
            pool_id,
            out_page_id: 0,
            shard_id,
            input_page_ids: &[0],
            ring: &ring2,
            input_note: &alice_chg_usdc,
            secret_index: alice_chg_usdc.slot_index,
            mint_out: WSOL_MINT,
            token_program_in: token_prog,
            token_program_out: token_prog,
            amount_in: 20_000_000,
            min_amount_out: 185_000_001,
            relayer_fee: 15_000_000,
            fee_on_output: true,
            fee_recipient_ata: Some(relayer_wsol_ata),
            allow_partial_refund: false,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            target_program_id: router_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            target_ix_data: &rdata_20,
            action_accounts: &base_action_accs,
        },
        &mut rng,
    )
    .unwrap();
    expect_custom_err(
        send_ixs(&mut svm, &relayer, &[], &[to_svm_ix(&slip_after_fee_ix)], 900_000),
        AudrenError::SlippageExceeded,
        "Slippage check must enforce post-fee net_out >= min_amount_out",
    );

    let (exec_out_fee_ix, _, _, _) = build_exec_via_escrow(
        &ExecViaEscrowParams {
            program_id: audren_id,
            payer: relayer.pubkey(),
            pool_id,
            out_page_id: 0,
            shard_id,
            input_page_ids: &[0],
            ring: &ring2,
            input_note: &alice_chg_usdc,
            secret_index: alice_chg_usdc.slot_index,
            mint_out: WSOL_MINT,
            token_program_in: token_prog,
            token_program_out: token_prog,
            amount_in: 20_000_000,
            min_amount_out: 185_000_000,
            relayer_fee: 15_000_000,
            fee_on_output: true,
            fee_recipient_ata: Some(relayer_wsol_ata),
            allow_partial_refund: false,
            recipient: &bob.address(),
            change_addr: &alice.address(),
            auditor_pk: None,
            target_program_id: router_id,
            escrow_idx,
            escrow_in_idx,
            escrow_out_idx,
            target_ix_data: &rdata_20,
            action_accounts: &base_action_accs,
        },
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &relayer, &[], &[to_svm_ix(&exec_out_fee_ix)], 900_000),
        "ExecViaEscrow (fee_on_output=true, 15_000_000 WSOL -> relayer, 185_000_000 WSOL -> Bob)",
    );
    assert_eq!(token_balance_of(&svm, &relayer_wsol_ata), 15_000_000);
    assert_eq!(token_balance_of(&svm, &vault_wsol), 2_435_000_000);
    assert_eq!(token_balance_of(&svm, &escrow_wsol), 0);

    // 8c. Self-Paying Withdraw WITH atomic `unwrap_wsol = true` -> 0-lamport fresh DeFi Session B_0!
    // Alice splits 2.0 WSOL note: 900_000_000 lamports Native SOL -> fresh B_0,
    // 10_000_000 lamports Native SOL -> fee_recipient, and 1_090_000_000 WSOL shielded change -> Alice!
    let ring3 = read_ring(&svm, &audren_id, pool_id, &[0]);
    let fee_before = svm.get_account(&fee_recipient.pubkey()).unwrap().lamports;
    let (unwrap_part_ix, _) = build_withdraw_with_params(
        &WithdrawParams {
            program_id: audren_id,
            payer: relayer.pubkey(),
            pool_id,
            out_page_id: 0,
            input_page_ids: &[0],
            ring: &ring3,
            input_note: &alice_wsol,
            secret_index: alice_wsol.slot_index,
            recipient_account: session_pubkey,
            change_addr: &alice.address(),
            amount: 900_000_000,
            relayer_fee: 10_000_000,
            fee_recipient: Some(fee_recipient.pubkey()),
            unwrap_wsol: true,
            spl_token_program: Some(token_prog),
            auditor_pk: None,
        },
        &mut rng,
    )
    .unwrap();

    // Adversarial: tamper fee_recipient -> InvalidTriptychProof
    let mut bad_fee_rcpt = unwrap_part_ix.clone();
    bad_fee_rcpt.accounts[7].pubkey = authority.pubkey();
    expect_custom_err(
        send_ixs(&mut svm, &relayer, &[], &[to_svm_ix(&bad_fee_rcpt)], 900_000),
        AudrenError::InvalidTriptychProof,
        "Reject tampered fee_recipient on Withdraw(unwrap_wsol)",
    );

    let (unwrap_pda_addr, _) = derive_unwrap_pda(&audren_id, pool_id, alice_wsol.nullifier.as_ref().unwrap());
    expect_ok(
        send_ixs(&mut svm, &relayer, &[], &[to_svm_ix(&unwrap_part_ix)], 900_000),
        "Withdraw(unwrap_wsol=true, relayer_fee=0.01 SOL) -> 0-lamport DeFi Session B_0!",
    );
    assert_eq!(svm.get_account(&session_pubkey).unwrap().lamports, 900_000_000);
    assert_eq!(svm.get_account(&fee_recipient.pubkey()).unwrap().lamports, fee_before + 10_000_000);
    assert!(
        svm.get_account(&unwrap_pda_addr).map(|a| a.lamports).unwrap_or(0) == 0,
        "unwrap_pda MUST be closed with 0 residual lamports!"
    );

    // 8c-PAUSE: Pause pool & prove FULL Withdraw(unwrap_wsol = true, relayer_fee = 5_000_000) STILL SUCCEEDS!
    let pause_ix = build_set_paused(audren_id, authority.pubkey(), pool_id, true);
    expect_ok(send_ixs(&mut svm, &authority, &[], &[to_svm_ix(&pause_ix)], 100_000), "Pause pool");

    let ring4 = read_ring(&svm, &audren_id, pool_id, &[0]);
    let alice_wsol_chg = scan_and_decrypt_page(&svm, &audren_id, pool_id, 0, &alice, None)
        .into_iter()
        .find(|n| n.mint == WSOL_MINT && n.amount == 1_090_000_000)
        .expect("Alice decrypts 1.09 WSOL change note");
    let fee_before2 = svm.get_account(&fee_recipient.pubkey()).unwrap().lamports;
    let session_before2 = svm.get_account(&session_pubkey).unwrap().lamports;
    let (unwrap_escape_ix, _) = build_withdraw_with_params(
        &WithdrawParams {
            program_id: audren_id,
            payer: relayer.pubkey(),
            pool_id,
            out_page_id: 0,
            input_page_ids: &[0],
            ring: &ring4,
            input_note: &alice_wsol_chg,
            secret_index: alice_wsol_chg.slot_index,
            recipient_account: session_pubkey,
            change_addr: &alice.address(),
            amount: 1_085_000_000,
            relayer_fee: 5_000_000,
            fee_recipient: Some(fee_recipient.pubkey()),
            unwrap_wsol: true,
            spl_token_program: Some(token_prog),
            auditor_pk: None,
        },
        &mut rng,
    )
    .unwrap();
    assert!(!unwrap_escape_ix.accounts[1].is_writable, "Full unwrap_wsol must keep PoolState read-only");
    expect_ok(
        send_ixs(&mut svm, &relayer, &[], &[to_svm_ix(&unwrap_escape_ix)], 900_000),
        "Full Withdraw(unwrap_wsol=true, relayer_fee) SUCCEEDS while Pool is Paused!",
    );
    assert_eq!(svm.get_account(&session_pubkey).unwrap().lamports, session_before2 + 1_085_000_000);
    assert_eq!(svm.get_account(&fee_recipient.pubkey()).unwrap().lamports, fee_before2 + 5_000_000);

    // Unpause pool for zero-dust sweep deposits!
    let unpause_ix = build_set_paused(audren_id, authority.pubkey(), pool_id, false);
    expect_ok(send_ixs(&mut svm, &authority, &[], &[to_svm_ix(&unpause_ix)], 100_000), "Unpause pool");

    // 8d. Zero-Dust Native SOL Sweep Deposit (`fee_from_amount = true`) signed by B_0!
    // B_0 currently holds 1_985_000_000 lamports. B_0 signs its own retiring sweep tx (5_000 lamport tx fee)
    // and sweeps `balance - 5_000` with `fee_from_amount = true` -> B_0 lands on LITERALLY 0 LAMPORTS!
    let b0_bal = svm.get_account(&session_pubkey).unwrap().lamports;
    assert_eq!(b0_bal, 1_985_000_000);
    let sol_vault_before = svm.get_account(&sol_vault).map(|a| a.lamports).unwrap_or(0);
    let rent_vault_before = svm.get_account(&rent_vault).map(|a| a.lamports).unwrap_or(0);
    let sweep_gross = b0_bal - 5_000; // exact balance minus single-sig Solana base fee!
    let (sweep_ix, _) = build_deposit_with_options(
        audren_id,
        session_pubkey,
        pool_id,
        0,
        &alice.address(),
        NATIVE_SOL_MINT,
        sweep_gross,
        sweep_gross - page_rent_fee,
        true, // fee_from_amount = true!
        None,
        &[],
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &session_kp, &[], &[to_svm_ix(&sweep_ix)], 300_000),
        "Zero-dust sweep Deposit(fee_from_amount=true) signed by B_0 (rent vault charging fee)",
    );
    let b0_after = svm.get_account(&session_pubkey).map(|a| a.lamports).unwrap_or(0);
    assert_eq!(b0_after, 0, "Retiring DeFi Session wallet B_0 MUST finish with literally 0 lamports!");
    let sol_delta = svm.get_account(&sol_vault).unwrap().lamports - sol_vault_before;
    let rent_delta = svm.get_account(&rent_vault).unwrap().lamports - rent_vault_before;
    assert!(rent_delta > 0 && rent_delta <= page_rent_fee, "dynamic SIMD-0437 rent fee collected");
    assert_eq!(sol_delta, sweep_gross - rent_delta);

    // Verify Alice decrypts the dynamic sweep note using the measured `sol_delta` AND spends it!
    let alice_sweep = scan_and_decrypt_page(&svm, &audren_id, pool_id, 0, &alice, Some(sol_delta))
        .into_iter()
        .find(|n| n.mint == NATIVE_SOL_MINT && n.amount == sol_delta)
        .expect("Alice decrypts zero-dust sweep SOL note via sol_vault delta");
    assert!(alice_sweep.is_dynamic_output);

    let ring5 = read_ring(&svm, &audren_id, pool_id, &[0]);
    let fee_before3 = svm.get_account(&fee_recipient.pubkey()).unwrap().lamports;
    let (wd_sweep_ix, _) = build_withdraw_with_params(
        &WithdrawParams {
            program_id: audren_id,
            payer: relayer.pubkey(),
            pool_id,
            out_page_id: 0,
            input_page_ids: &[0],
            ring: &ring5,
            input_note: &alice_sweep,
            secret_index: alice_sweep.slot_index,
            recipient_account: authority.pubkey(),
            change_addr: &alice.address(),
            amount: alice_sweep.amount - 2_000_000,
            relayer_fee: 2_000_000,
            fee_recipient: Some(fee_recipient.pubkey()),
            unwrap_wsol: false,
            spl_token_program: None,
            auditor_pk: None,
        },
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &relayer, &[], &[to_svm_ix(&wd_sweep_ix)], 900_000),
        "Spend dynamic sweep SOL note via self-paying Native SOL Withdraw!",
    );
    assert_eq!(svm.get_account(&fee_recipient.pubkey()).unwrap().lamports, fee_before3 + 2_000_000);

    // 8d-FULL-RENT: Top up PageRentVault to full capacity (rent fee charged = 0) and sweep a fresh B_1 to 0 lamports!
    let session_b1 = AudrenKeys::derive_defi_session_keypair(&master_seed, 1);
    let b1_kp = Keypair::new_from_array(session_b1.secret_seed);
    svm.airdrop(&b1_kp.pubkey(), 250_000_000).unwrap();
    svm.airdrop(&rent_vault, 500_000_000).unwrap(); // PageRentVault now well above cap -> fee = 0!
    let sol_vault_before2 = svm.get_account(&sol_vault).unwrap().lamports;
    let sweep_b1_gross = 250_000_000 - 5_000;
    let (sweep_b1_ix, _) = build_deposit_with_options(
        audren_id,
        b1_kp.pubkey(),
        pool_id,
        0,
        &alice.address(),
        NATIVE_SOL_MINT,
        sweep_b1_gross,
        sweep_b1_gross,
        true,
        None,
        &[],
        &mut rng,
    )
    .unwrap();
    expect_ok(
        send_ixs(&mut svm, &b1_kp, &[], &[to_svm_ix(&sweep_b1_ix)], 300_000),
        "Zero-dust sweep Deposit(fee_from_amount=true) when PageRentVault is full (fee=0)",
    );
    assert_eq!(svm.get_account(&b1_kp.pubkey()).map(|a| a.lamports).unwrap_or(0), 0);
    assert_eq!(svm.get_account(&sol_vault).unwrap().lamports - sol_vault_before2, sweep_b1_gross);
    println!("  [v0.3.0 EXEC FEES + UNWRAP WSOL + DEFI SESSION B_0/B_1 + ZERO-DUST SWEEP PASSED]");
}
