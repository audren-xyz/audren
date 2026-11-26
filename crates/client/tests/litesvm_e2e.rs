//! End-to-End LiteSVM Integration & Security Regression Suite for Audren v1
//! (sBPFv3 + BN254 Groth16 + Transaction v1 `0x81`).
//!
//! Executes real compiled `audren.so`, `audren_mock_router.so`, and `audren_mock_hook.so`
//! sBPFv3 binaries inside LiteSVM (`agave-feature-set 4.3.0`) over real Solana Transaction v1
//! (`0x81`, `4,096 B`) wire messages.

use std::collections::BTreeSet;
use std::path::PathBuf;

use agave_feature_set::FeatureSet;
use ark_bn254::Fr;
use audren_client::{
    audren_circuits::{
        joinsplit::{JoinSplitInputWitness, JoinSplitOutputWitness},
        merkle::{zero_hashes_4ary, MerklePath4Ary},
        note::derive_stealth_owner,
        poseidon::fr_to_be_bytes,
    },
    audren_core::{
        instruction::{
            ASSET_MODE_PRIVATE, ASSET_MODE_PUBLIC, OPEN_PAGE_KIND_MEMO, OPEN_PAGE_KIND_SUBROOT,
            OPEN_PAGE_KIND_SUBTREE, VK_ID_DEFAULT,
        },
        layout::{
            read_32, read_u16, read_u64, GlobalRootHistory, LaneTreeHeader, PoolState,
            LN_OFF_NEXT_LEAF, MEMO_CT_LEN, MEMO_NOTES_PER_PAGE, MEMO_PAGE_LEN, MM_OFF_CIPHERTEXTS,
            MM_OFF_COUNT, MM_OFF_EPHEMERAL_PKS, MM_OFF_VIEW_TAGS, PL_OFF_PENDING_AUTHORITY,
            PL_OFF_RESERVED_24, ROOT_HISTORY_LEN, SB_OFF_LEAVES, SUBROOT_PAGE_LEN, SUBTREE_LEAVES,
            SUBTREE_PAGE_LEN,
        },
        ASSOCIATED_TOKEN_PROGRAM_ID, AUDREN_PROGRAM_ID, CLASSIC_TOKEN_PROGRAM_ID, CU_LIMIT_DEPOSIT,
        CU_LIMIT_DEPOSIT_HOOK, CU_LIMIT_EXEC_VIA_ESCROW_BASE, CU_LIMIT_INIT_LANE,
        CU_LIMIT_INIT_POOL, CU_LIMIT_INIT_ROOT_HISTORY, CU_LIMIT_OPEN_PAGE,
        CU_LIMIT_TRANSACT_FULL_EXIT, CU_LIMIT_TRANSACT_PRIVATE, CU_LIMIT_TRANSACT_WITHDRAW,
        CU_LIMIT_TRANSACT_WITHDRAW_HOOK,
        DEFAULT_ROOT_EPOCH_INTERVAL, EPOCH_RING_LEN, NUM_LANES, PROTOCOL_VERSION, ROOT_RING_EPOCH,
        ROOT_RING_SLOT, SLOT_RING_LEN, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, WSOL_MINT,
    },
    instructions::{
        build_auto_open_page_ixs, build_deposit, build_exec_via_escrow, build_init_lane,
        build_init_pool, build_init_root_history, build_open_page, build_set_paused,
        build_transact, build_update_pool, build_update_pool_params, compute_exec_ctx_hash,
        compute_page_rollovers, compute_transact_ctx_hash, deterministic_note_rent_fee,
        plan_auto_open_pages, recommended_cu_limit_deposit, recommended_cu_limit_exec_via_escrow,
        recommended_cu_limit_init_lane, recommended_cu_limit_init_pool,
        recommended_cu_limit_init_root_history, recommended_cu_limit_open_page,
        recommended_cu_limit_transact, AudrenAccountMeta, AudrenInstruction, UpdatePoolAction,
    },
    keys::{
        check_memo_view_tag, encrypt_note_memo, encrypt_note_memo_with_payment_id,
        prepare_dynamic_swap_memo, try_decrypt_and_verify_memo_entry, AudrenAddress, AudrenKeys,
    },
    pda::{
        derive_ata, derive_escrow_pda, derive_lane_pda, derive_lane_rent_pda, derive_memo_pda,
        derive_nf_page_pda, derive_nullifier_pda, derive_pool_pda, derive_roots_pda,
        derive_subtree_pda, derive_unwrap_pda, derive_vault_auth_pda,
    },
    prover::{asset_id_bytes_for_mint, asset_id_for_mint, AudrenProver},
    router::prepare_escrow_accounts_for_audren,
    scanner::{decode_global_root_history, reconstruct_witness_for_notes, reconstruct_witness_with},
    store::CompactWalletStore,
};
use litesvm::{types::TransactionResult, LiteSVM};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{
    v1::{self, TransactionConfig},
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

const POOL_ID: u32 = 0;
const ROOT_EPOCH_INTERVAL: u64 = DEFAULT_ROOT_EPOCH_INTERVAL;
const DEFAULT_LOADED_ACCOUNTS_DATA_SIZE: u32 = 64 * 1024 * 1024;

fn spl_token_id() -> Address {
    Address::new_from_array(CLASSIC_TOKEN_PROGRAM_ID)
}

fn token_2022_id() -> Address {
    Address::new_from_array(TOKEN_2022_PROGRAM_ID)
}

fn ata_program_id() -> Address {
    Address::new_from_array(ASSOCIATED_TOKEN_PROGRAM_ID)
}

fn sys_program_id() -> Address {
    Address::new_from_array(SYSTEM_PROGRAM_ID)
}

fn wsol_mint_id() -> Address {
    Address::new_from_array(WSOL_MINT)
}

fn deploy_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/deploy")
        .canonicalize()
        .expect("run scripts/build-sbf.py for audren, mock-router, and mock-hook first")
}

fn to_svm_ix(ix: &AudrenInstruction) -> Instruction {
    Instruction {
        program_id: Address::new_from_array(ix.program_id),
        accounts: ix
            .accounts
            .iter()
            .map(|m| AccountMeta {
                pubkey: Address::new_from_array(m.pubkey),
                is_signer: m.is_signer,
                is_writable: m.is_writable,
            })
            .collect(),
        data: ix.data.clone(),
    }
}

fn new_svm(
    audren_id: Address,
    router_id: Option<Address>,
    hook_id: Option<Address>,
) -> LiteSVM {
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
    if let Some(rid) = router_id {
        svm.add_program_from_file(rid, dir.join("audren_mock_router.so"))
            .expect("load audren_mock_router.so");
    }
    if let Some(hid) = hook_id {
        svm.add_program_from_file(hid, dir.join("audren_mock_hook.so"))
            .expect("load audren_mock_hook.so");
    }

    // Seed canonical Solana genesis WSOL Mint (82 B, decimals = 9, is_initialized = 1)
    let mut wsol_data = vec![0u8; 82];
    wsol_data[44] = 9;
    wsol_data[45] = 1;
    svm.set_account(
        wsol_mint_id(),
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(82),
            data: wsol_data,
            owner: spl_token_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    svm
}

#[allow(clippy::result_large_err)]
fn send_v1(
    svm: &mut LiteSVM,
    payer: &Keypair,
    extra_signers: &[&Keypair],
    ixs: &[Instruction],
    cu_limit: u32,
) -> TransactionResult {
    svm.expire_blockhash();
    let config = TransactionConfig::empty()
        .with_compute_unit_limit(cu_limit)
        .with_loaded_accounts_data_size_limit(DEFAULT_LOADED_ACCOUNTS_DATA_SIZE);
    let blockhash = svm.latest_blockhash();
    let msg = v1::Message::try_compile_with_config(&payer.pubkey(), ixs, blockhash, config)
        .expect("compile v1 message");
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra_signers);
    let tx = VersionedTransaction::try_new(VersionedMessage::V1(msg), &signers).expect("sign v1");
    let wire = wincode::serialize(&tx).expect("wincode-serialize v1");
    assert_eq!(wire[0], 0x81, "Solana Transaction v1 must start with 0x81");
    svm.send_transaction(tx)
}

fn expect_ok(res: TransactionResult, label: &str) -> u64 {
    match res {
        Ok(m) => m.compute_units_consumed,
        Err(e) => panic!("{label} FAILED: {:?} | logs: {:?}", e.err, e.meta.logs),
    }
}

fn expect_err_code(res: TransactionResult, code: u32, label: &str) {
    match res {
        Ok(_) => panic!("{label}: expected Custom({code}), but succeeded"),
        Err(e) => {
            let s = format!("{:?}", e.err);
            assert!(
                s.contains(&format!("Custom({code})")),
                "{label}: expected Custom({code}), got {s} | logs: {:?}",
                e.meta.logs
            );
        }
    }
}

fn create_canonical_ata(
    svm: &mut LiteSVM,
    payer: &Keypair,
    owner: Address,
    mint: Address,
    token_prog: Address,
) -> Address {
    let ata = derive_ata(&owner, &token_prog, &mint);
    let ix = Instruction {
        program_id: ata_program_id(),
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(ata, false),
            AccountMeta::new_readonly(owner, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(sys_program_id(), false),
            AccountMeta::new_readonly(token_prog, false),
        ],
        data: vec![1u8], // CreateIdempotent
    };
    expect_ok(send_v1(svm, payer, &[], &[ix], 200_000), "create canonical ATA");
    ata
}

fn create_spl_mint(svm: &mut LiteSVM, payer: &Keypair, decimals: u8) -> Address {
    let mint = Keypair::new();
    let rent = svm.minimum_balance_for_rent_exemption(Mint::LEN);
    let ixs = vec![
        sys_ix::create_account(
            &payer.pubkey(),
            &mint.pubkey(),
            rent,
            Mint::LEN as u64,
            &spl_token_id(),
        ),
        token_ix::initialize_mint(&spl_token_id(), &mint.pubkey(), &payer.pubkey(), None, decimals)
            .unwrap(),
    ];
    expect_ok(send_v1(svm, payer, &[&mint], &ixs, 200_000), "create SPL mint");
    mint.pubkey()
}

fn create_t22_fee_mint(
    svm: &mut LiteSVM,
    payer: &Keypair,
    decimals: u8,
    fee_bps: u16,
    max_fee: u64,
) -> Address {
    let mint = Keypair::new();
    let space = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::TransferFeeConfig,
    ])
    .unwrap();
    let rent = svm.minimum_balance_for_rent_exemption(space);
    let ixs = vec![
        sys_ix::create_account(
            &payer.pubkey(),
            &mint.pubkey(),
            rent,
            space as u64,
            &token_2022_id(),
        ),
        transfer_fee_ix::initialize_transfer_fee_config(
            &token_2022_id(),
            &mint.pubkey(),
            Some(&payer.pubkey()),
            Some(&payer.pubkey()),
            fee_bps,
            max_fee,
        )
        .unwrap(),
        token_ix::initialize_mint(
            &token_2022_id(),
            &mint.pubkey(),
            &payer.pubkey(),
            None,
            decimals,
        )
        .unwrap(),
    ];
    expect_ok(send_v1(svm, payer, &[&mint], &ixs, 250_000), "create T22 fee mint");
    mint.pubkey()
}

fn create_t22_hook_mint(
    svm: &mut LiteSVM,
    payer: &Keypair,
    decimals: u8,
    hook_prog: Address,
) -> Address {
    let mint = Keypair::new();
    let space = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::TransferHook,
    ])
    .unwrap();
    let rent = svm.minimum_balance_for_rent_exemption(space);
    let ixs = vec![
        sys_ix::create_account(
            &payer.pubkey(),
            &mint.pubkey(),
            rent,
            space as u64,
            &token_2022_id(),
        ),
        transfer_hook_ix::initialize(
            &token_2022_id(),
            &mint.pubkey(),
            Some(payer.pubkey()),
            Some(hook_prog),
        )
        .unwrap(),
        token_ix::initialize_mint(
            &token_2022_id(),
            &mint.pubkey(),
            &payer.pubkey(),
            None,
            decimals,
        )
        .unwrap(),
    ];
    expect_ok(send_v1(svm, payer, &[&mint], &ixs, 250_000), "create T22 hook mint");
    mint.pubkey()
}

/// Create a NON-CANONICAL (random Keypair-addressed) token account owned by `owner`.
/// Used for user source/DEX accounts and for adversarial non-canonical ATA injection tests.
fn create_non_canonical_token_acc(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint: Address,
    owner: Address,
    token_prog: Address,
    exts: &[ExtensionType],
) -> Address {
    let acc = Keypair::new();
    let space = if exts.is_empty() {
        TokenAccount::LEN
    } else {
        ExtensionType::try_calculate_account_len::<TokenAccount>(exts).unwrap()
    };
    let rent = svm.minimum_balance_for_rent_exemption(space);
    let ixs = vec![
        sys_ix::create_account(
            &payer.pubkey(),
            &acc.pubkey(),
            rent,
            space as u64,
            &token_prog,
        ),
        token_ix::initialize_account3(&token_prog, &acc.pubkey(), &mint, &owner).unwrap(),
    ];
    expect_ok(
        send_v1(svm, payer, &[&acc], &ixs, 200_000),
        "create non-canonical token account",
    );
    acc.pubkey()
}

fn mint_to(
    svm: &mut LiteSVM,
    payer: &Keypair,
    token_prog: Address,
    mint: Address,
    dest: Address,
    amount: u64,
) {
    let ix = token_ix::mint_to(&token_prog, &mint, &dest, &payer.pubkey(), &[], amount).unwrap();
    expect_ok(send_v1(svm, payer, &[], &[ix], 200_000), "mint_to");
}

fn token_balance(svm: &LiteSVM, acc: &Address) -> u64 {
    read_u64(&svm.get_account(acc).expect("token acc").data, 64)
}

fn lane_next_leaf(svm: &LiteSVM, program_id: &Address, lane: u8) -> u64 {
    let (pda, _) = derive_lane_pda(program_id, POOL_ID, lane);
    read_u64(&svm.get_account(&pda).unwrap().data, LN_OFF_NEXT_LEAF)
}

fn dex_pool_pda(router_id: &Address) -> Address {
    Address::find_program_address(&[b"dex_pool"], router_id).0
}

fn dex_init_ix(
    router_id: Address,
    payer: Address,
    rate_bps: u64,
    liquidity_lamports: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(17);
    data.push(0u8);
    data.extend_from_slice(&rate_bps.to_le_bytes());
    data.extend_from_slice(&liquidity_lamports.to_le_bytes());
    Instruction {
        program_id: router_id,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(dex_pool_pda(&router_id), false),
            AccountMeta::new_readonly(sys_program_id(), false),
        ],
        data,
    }
}

fn dex_swap_spl_to_spl_data(
    attack_mode: u8,
    amount_in: u64,
    out_amount: u64,
    dec_in: u8,
    dec_out: u8,
) -> Vec<u8> {
    let mut d = Vec::with_capacity(20);
    d.push(5u8);
    d.push(attack_mode);
    d.extend_from_slice(&amount_in.to_le_bytes());
    d.extend_from_slice(&out_amount.to_le_bytes());
    d.push(dec_in);
    d.push(dec_out);
    d
}

/// Bootstrap Pool #0 (with `GlobalRootHistory`) + `initial_lanes` active lanes + canonical WSOL `vault_ata`.
fn bootstrap_pool(
    svm: &mut LiteSVM,
    program_id: Address,
    payer: &Keypair,
    initial_lanes: u8,
) -> Address {
    expect_ok(
        send_v1(
            svm,
            payer,
            &[],
            &[to_svm_ix(&build_init_pool(
                program_id,
                payer.pubkey(),
                POOL_ID,
                ROOT_EPOCH_INTERVAL,
                2_000_000,
                500_000,
            ))],
            300_000,
        ),
        "InitPool",
    );
    for l in 0..initial_lanes {
        expect_ok(
            send_v1(
                svm,
                payer,
                &[],
                &[to_svm_ix(&build_init_lane(program_id, payer.pubkey(), POOL_ID, l))],
                300_000,
            ),
            "InitLane",
        );
    }
    let (va, _) = derive_vault_auth_pda(&program_id, POOL_ID);
    create_canonical_ata(svm, payer, va, wsol_mint_id(), spl_token_id())
}

// ----------------------------------------------------------------------------
// TEST 1: Dynamic active_lanes (0 -> 4 -> 8 -> 16), super_root continuity,
//         CompactWalletStore offline witness reload, Mode 1 & Mode 2 viewing,
//         payment_id round-trip, and double-spend rejection
// ----------------------------------------------------------------------------
#[test]
fn test_dynamic_lanes_expansion_and_compact_wallet_store() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let mut svm = new_svm(program_id, None, None);
    let prover = AudrenProver::from_canonical_pk();
    let payer = Keypair::new();
    let non_auth = Keypair::new();
    svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();
    svm.airdrop(&non_auth.pubkey(), 10_000_000_000).unwrap();
    svm.warp_to_slot(104); // epoch 13

    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_init_pool(
                program_id,
                payer.pubkey(),
                POOL_ID,
                ROOT_EPOCH_INTERVAL,
                2_000_000,
                500_000,
            ))],
            300_000,
        ),
        "InitPool",
    );

    let (pool_pda, _) = derive_pool_pda(&program_id, POOL_ID);
    let pool0 = PoolState::decode(&svm.get_account(&pool_pda).unwrap().data).unwrap();
    assert_eq!(pool0.version, PROTOCOL_VERSION);
    assert_eq!(pool0.active_lanes, 0);

    // Non-authority InitLane blocked (6028); out-of-order lane skip blocked (6003)
    expect_err_code(
        send_v1(
            &mut svm,
            &non_auth,
            &[],
            &[to_svm_ix(&build_init_lane(program_id, non_auth.pubkey(), POOL_ID, 0))],
            250_000,
        ),
        6028,
        "non-authority InitLane",
    );
    expect_err_code(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_init_lane(program_id, payer.pubkey(), POOL_ID, 1))],
            250_000,
        ),
        6003,
        "out-of-order InitLane",
    );

    for l in 0..4u8 {
        expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_init_lane(program_id, payer.pubkey(), POOL_ID, l))],
                250_000,
            ),
            "InitLane 0..4",
        );
    }

    let (va, _) = derive_vault_auth_pda(&program_id, POOL_ID);
    let vault_wsol = create_canonical_ata(&mut svm, &payer, va, wsol_mint_id(), spl_token_id());

    let alice = AudrenKeys::from_seed(&[0xA1u8; 32]);
    let fvk = alice.full_viewing_key();
    let asset_wsol = asset_id_for_mint(None);

    // Inactive lane 4 deposit blocked (6003)
    let (tw_bad, bl_bad, memo_bad) =
        encrypt_note_memo(&alice.view_pk, [0x09; 32], 5_000_000, &WSOL_MINT).unwrap();
    expect_err_code(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                wsol_mint_id(),
                payer.pubkey(),
                vault_wsol,
                spl_token_id(),
                4,
                0,
                0,
                0,
                None,
                None,
                true,
                false,
                5_000_000,
                derive_stealth_owner(alice.spend_pk, tw_bad),
                bl_bad,
                &memo_bad,
                &[],
            ))],
            200_000,
        ),
        6003,
        "deposit on inactive lane",
    );

    // Deposit Native SOL via unified `Deposit(DEPOSIT_FLAG_NATIVE_SOL)` into lanes 0..4
    let sample_payment_id = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 1, 2, 3, 4, 5, 6];
    for l in 0..4u8 {
        let (tw, bl, memo) = encrypt_note_memo_with_payment_id(
            &alice.view_pk,
            [0x10 + l; 32],
            25_000_000,
            &WSOL_MINT,
            sample_payment_id,
        )
        .unwrap();
        expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_deposit(
                    program_id,
                    payer.pubkey(),
                    POOL_ID,
                    wsol_mint_id(),
                    payer.pubkey(),
                    vault_wsol,
                    spl_token_id(),
                    l,
                    0,
                    0,
                    0,
                    None,
                    None,
                    true,
                    false,
                    25_000_000,
                    derive_stealth_owner(alice.spend_pk, tw),
                    bl,
                    &memo,
                    &[],
                ))],
                200_000,
            ),
            "deposit native SOL 4-lane",
        );
    }
    assert_eq!(token_balance(&svm, &vault_wsol), 100_000_000);

    let (roots_pda, _) = derive_roots_pda(&program_id, POOL_ID);
    let roots4 = decode_global_root_history(&svm.get_account(&roots_pda).unwrap().data).unwrap();
    assert_eq!(roots4.version, PROTOCOL_VERSION);
    let zeros = zero_hashes_4ary();
    for l in 4..NUM_LANES {
        assert_eq!(roots4.latest_lane_roots[l], fr_to_be_bytes(&zeros[18]));
    }

    // Expand 4 -> 8 -> 16 and verify bit-for-bit super_root continuity with zero external crank!
    for l in 4..8u8 {
        expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_init_lane(program_id, payer.pubkey(), POOL_ID, l))],
                250_000,
            ),
            "InitLane 4..8",
        );
    }
    let roots8 = decode_global_root_history(&svm.get_account(&roots_pda).unwrap().data).unwrap();
    assert_eq!(roots4.latest_super_root, roots8.latest_super_root);

    for l in 8..16u8 {
        expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_init_lane(program_id, payer.pubkey(), POOL_ID, l))],
                250_000,
            ),
            "InitLane 8..16",
        );
    }
    let roots16 = decode_global_root_history(&svm.get_account(&roots_pda).unwrap().data).unwrap();
    assert_eq!(roots8.latest_super_root, roots16.latest_super_root);

    // Immediately deposit into newly expanded Lane 4 & Lane 15 and verify instant spendability!
    for expanded_lane in [4u8, 15u8] {
        let (tw_e, bl_e, memo_e) =
            encrypt_note_memo(&alice.view_pk, [0x40 + expanded_lane; 32], 10_000_000, &WSOL_MINT)
                .unwrap();
        expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_deposit(
                    program_id,
                    payer.pubkey(),
                    POOL_ID,
                    wsol_mint_id(),
                    payer.pubkey(),
                    vault_wsol,
                    spl_token_id(),
                    expanded_lane,
                    0,
                    0,
                    0,
                    None,
                    None,
                    true,
                    false,
                    10_000_000,
                    derive_stealth_owner(alice.spend_pk, tw_e),
                    bl_e,
                    &memo_e,
                    &[],
                ))],
                200_000,
            ),
            "deposit into expanded lane 4/15",
        );
        let (path_e, rk_e, ri_e, sr_e) = reconstruct_witness_with(
            |a| svm.get_account(a).map(|x| x.data),
            &program_id,
            POOL_ID,
            expanded_lane,
            0,
            alice.view_sk,
        )
        .unwrap();
        let (tw_eo, bl_eo, memo_eo) =
            encrypt_note_memo(&alice.view_pk, [0x50 + expanded_lane; 32], 10_000_000, &WSOL_MINT)
                .unwrap();
        let ctx_e = compute_transact_ctx_hash(
            &program_id,
            POOL_ID,
            VK_ID_DEFAULT,
            expanded_lane,
            0b001,
            ASSET_MODE_PRIVATE,
            false,
            None,
            None,
            &[0u8; 32],
            0,
            0,
            &memo_eo,
        );
        let b_e = prover.build_and_prove(
            sr_e,
            asset_wsol,
            Fr::from(0u64),
            0,
            0,
            ctx_e,
            true,
            [
                JoinSplitInputWitness {
                    spend_sk: alice.spend_sk,
                    tweak: tw_e,
                    asset_id: asset_wsol,
                    amount: 10_000_000,
                    blinding: bl_e,
                    is_dummy: false,
                    merkle_path: path_e,
                },
                JoinSplitInputWitness {
                    spend_sk: alice.spend_sk,
                    tweak: Fr::from(0u64),
                    asset_id: asset_wsol,
                    amount: 0,
                    blinding: Fr::from(888u64),
                    is_dummy: true,
                    merkle_path: MerklePath4Ary::default(),
                },
            ],
            [
                JoinSplitOutputWitness {
                    stealth_owner: derive_stealth_owner(alice.spend_pk, tw_eo),
                    asset_id: asset_wsol,
                    amount: 10_000_000,
                    blinding: bl_eo,
                },
                JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(2u64)),
                JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
            ],
            [0x5A + expanded_lane; 32],
        );
        expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_transact(
                    program_id,
                    payer.pubkey(),
                    POOL_ID,
                    VK_ID_DEFAULT,
                    rk_e,
                    ri_e,
                    expanded_lane,
                    0,
                    0,
                    0,
                    0,
                    0b001,
                    ASSET_MODE_PRIVATE,
                    false,
                    None,
                    (None, None, None),
                    &b_e.proof_192,
                    &b_e.nf0,
                    &b_e.nf1,
                    &b_e.cm0,
                    &b_e.cm1,
                    &b_e.cm2,
                    0,
                    0,
                    payer.pubkey(),
                    payer.pubkey(),
                    &memo_eo,
                    &[],
                ))],
                300_000,
            ),
            "instant spend on expanded lane 4/15",
        );
    }
    let roots_after_exp =
        decode_global_root_history(&svm.get_account(&roots_pda).unwrap().data).unwrap();

    // Sync CompactWalletStore via sequential page ingestion, persist to JSON, reload, and spend
    // a 4-lane note under GlobalRootHistory into newly activated lane 14!
    let mut store = CompactWalletStore::new(POOL_ID, 0);
    for l in 0..4u8 {
        let sub_data = svm
            .get_account(&derive_subtree_pda(&program_id, POOL_ID, l, 0).0)
            .unwrap()
            .data;
        let memo_data = svm
            .get_account(&derive_memo_pda(&program_id, POOL_ID, l, 0).0)
            .unwrap()
            .data;
        let nf_data = svm
            .get_account(&derive_nf_page_pda(&program_id, POOL_ID, l, 0).0)
            .unwrap()
            .data;
        let found = store
            .ingest_lane_pages(&fvk, l, &[(0, &sub_data)], &[(0, &memo_data)], &[(0, &nf_data)])
            .unwrap();
        assert_eq!(found, 1);
    }
    assert_eq!(store.balances().get(&WSOL_MINT), Some(&100_000_000));
    assert_eq!(store.notes[0].payment_id, sample_payment_id);

    // Mode 1 SelectiveDisclosureProof verifies against SubtreePage leaf with zero keys
    let note0 = store.notes[0].clone();
    let sd_proof = note0.selective_disclosure_proof();
    let sub0_data = svm
        .get_account(&derive_subtree_pda(&program_id, POOL_ID, note0.lane_id, 0).0)
        .unwrap()
        .data;
    let onchain_leaf = read_32(&sub0_data, SB_OFF_LEAVES + (note0.leaf_index as usize) * 32);
    assert!(sd_proof.verify_against_leaf(&onchain_leaf));

    // Persist CompactWalletStore to JSON & reload -> reconstruct offline witness -> spend into lane 14!
    let persisted = store.to_json_bytes().unwrap();
    let reloaded = CompactWalletStore::from_json_bytes(&persisted).unwrap();
    let (choice0, super_root, path0) = reloaded
        .build_witness_from_root_history(&note0, &roots_after_exp)
        .unwrap();

    let (tw_o, bl_o, memo_o) =
        encrypt_note_memo(&alice.view_pk, [0x71; 32], 25_000_000, &WSOL_MINT).unwrap();
    let ctx = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        14,
        0b001,
        ASSET_MODE_PRIVATE,
        false,
        None,
        None,
        &[0u8; 32],
        0,
        0,
        &memo_o,
    );
    let bundle = prover.build_and_prove(
        super_root,
        asset_wsol,
        Fr::from(0u64),
        0,
        0,
        ctx,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: note0.tweak_fr().unwrap(),
                asset_id: asset_wsol,
                amount: note0.amount,
                blinding: note0.blinding_fr().unwrap(),
                is_dummy: false,
                merkle_path: path0,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_wsol,
                amount: 0,
                blinding: Fr::from(777u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_o),
                asset_id: asset_wsol,
                amount: 25_000_000,
                blinding: bl_o,
            },
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
        ],
        [0x55; 32],
    );

    // Advance 1 slot so `slot_ring[choice0.ring_idx]` stays preserved across the spend,
    // letting the exact replay below reach the NullifierPDA double-spend guard (`Custom(6012)`)!
    svm.warp_to_slot(105);
    let spend_cu = expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                payer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                choice0.ring_kind,
                choice0.ring_idx,
                14,
                0,
                0,
                0,
                0,
                0b001,
                ASSET_MODE_PRIVATE,
                false,
                None,
                (None, None, None),
                &bundle.proof_192,
                &bundle.nf0,
                &bundle.nf1,
                &bundle.cm0,
                &bundle.cm1,
                &bundle.cm2,
                0,
                0,
                payer.pubkey(),
                payer.pubkey(),
                &memo_o,
                &[],
            ))],
            300_000,
        ),
        "cross-expansion Transact into lane 14",
    );

    // Double-spend of exact same note blocked (6012)!
    expect_err_code(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                payer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                choice0.ring_kind,
                choice0.ring_idx,
                14,
                0,
                0,
                0,
                0,
                0b001,
                ASSET_MODE_PRIVATE,
                false,
                None,
                (None, None, None),
                &bundle.proof_192,
                &bundle.nf0,
                &bundle.nf1,
                &bundle.cm0,
                &bundle.cm1,
                &bundle.cm2,
                0,
                0,
                payer.pubkey(),
                payer.pubkey(),
                &memo_o,
                &[],
            ))],
            300_000,
        ),
        6012,
        "double spend",
    );

    // Verify FVK watch-only store detects the spend on lane 14!
    let mut store2 = reloaded;
    let sub14 = svm
        .get_account(&derive_subtree_pda(&program_id, POOL_ID, 14, 0).0)
        .unwrap()
        .data;
    let memo14 = svm
        .get_account(&derive_memo_pda(&program_id, POOL_ID, 14, 0).0)
        .unwrap()
        .data;
    let nf14 = svm
        .get_account(&derive_nf_page_pda(&program_id, POOL_ID, 14, 0).0)
        .unwrap()
        .data;
    let new_notes = store2
        .ingest_lane_pages(&fvk, 14, &[(0, &sub14)], &[(0, &memo14)], &[(0, &nf14)])
        .unwrap();
    assert_eq!(new_notes, 1);
    assert!(store2.notes[0].spent, "FVK must mark spent note via NullifierPage");
    assert_eq!(store2.balances().get(&WSOL_MINT), Some(&100_000_000));
    println!(
        "  [TEST 1 PASSED] 4->8->16 expansion (Lane 4 & 15 instant spend) | Cross-lane Spend={spend_cu} CU"
    );
}

// ----------------------------------------------------------------------------
// TEST 2: Zero-dust DEPOSIT_FLAG_NATIVE_SOL | DEPOSIT_FLAG_FEE_FROM_AMOUNT,
//         WITHDRAW_FLAG_UNWRAP_WSOL, DefiSessionKeypair 0-lamport recipient,
//         and Pause Escape Hatch
// ----------------------------------------------------------------------------
#[test]
fn test_zero_dust_sweep_wsol_unwrap_and_pause_escape() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let mut svm = new_svm(program_id, None, None);
    let prover = AudrenProver::from_canonical_pk();
    let payer = Keypair::new();
    let relayer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();
    svm.airdrop(&relayer.pubkey(), 50_000_000_000).unwrap();
    svm.warp_to_slot(104);
    let vault_wsol = bootstrap_pool(&mut svm, program_id, &payer, 4);

    let master_seed = [0x42u8; 32];
    let alice = AudrenKeys::from_seed(&master_seed);
    let session0 = AudrenKeys::derive_defi_session_keypair(&master_seed, 0);
    let session_addr = Address::new_from_array(session0.pubkey);
    assert!(svm.get_account(&session_addr).is_none());

    // Zero-dust sweep from a disposable wallet -> exact 0 final lamports!
    let sweeper = Keypair::new();
    let sweep_start = 10_000_000u64;
    svm.airdrop(&sweeper.pubkey(), sweep_start).unwrap();
    let per_note_fee = deterministic_note_rent_fee(
        2_000_000,
        svm.minimum_balance_for_rent_exemption(SUBTREE_PAGE_LEN),
        svm.minimum_balance_for_rent_exemption(SUBROOT_PAGE_LEN),
        svm.minimum_balance_for_rent_exemption(MEMO_PAGE_LEN),
    );
    let tx_fee = 5_000u64;
    let gross_sweep = sweep_start - tx_fee;
    let net_sweep = gross_sweep - per_note_fee;
    let (tw_s, bl_s, memo_s) =
        encrypt_note_memo(&alice.view_pk, [0x21; 32], net_sweep, &WSOL_MINT).unwrap();
    expect_ok(
        send_v1(
            &mut svm,
            &sweeper,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                sweeper.pubkey(),
                POOL_ID,
                wsol_mint_id(),
                sweeper.pubkey(),
                vault_wsol,
                spl_token_id(),
                0,
                0,
                0,
                0,
                None,
                None,
                true,
                true,
                gross_sweep,
                derive_stealth_owner(alice.spend_pk, tw_s),
                bl_s,
                &memo_s,
                &[],
            ))],
            200_000,
        ),
        "zero-dust fee_from_amount sweep",
    );
    assert_eq!(
        svm.get_account(&sweeper.pubkey()).map(|a| a.lamports).unwrap_or(0),
        0,
        "sweeper must end at exact 0 lamports"
    );

    // Deposit 2.0 WSOL (SPL path) into lane 1
    let payer_wsol =
        create_non_canonical_token_acc(&mut svm, &payer, wsol_mint_id(), payer.pubkey(), spl_token_id(), &[]);
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[
                sys_ix::transfer(&payer.pubkey(), &payer_wsol, 2_000_000_000),
                Instruction {
                    program_id: spl_token_id(),
                    accounts: vec![AccountMeta::new(payer_wsol, false)],
                    data: vec![17u8], // SyncNative
                },
            ],
            200_000,
        ),
        "wrap 2 WSOL",
    );

    let wsol_asset = asset_id_for_mint(Some(&wsol_mint_id()));
    let (tw_w, bl_w, memo_w) =
        encrypt_note_memo(&alice.view_pk, [0x22; 32], 2_000_000_000, &WSOL_MINT).unwrap();
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                wsol_mint_id(),
                payer_wsol,
                vault_wsol,
                spl_token_id(),
                1,
                0,
                0,
                0,
                None,
                None,
                false,
                false,
                2_000_000_000,
                derive_stealth_owner(alice.spend_pk, tw_w),
                bl_w,
                &memo_w,
                &[],
            ))],
            200_000,
        ),
        "deposit 2 WSOL",
    );

    // Relayed partial WSOL unwrap (instant spend, zero external checkpoint!):
    // 0.9 SOL -> fresh 0-lamport session0, 0.01 SOL -> relayer, 1.09 WSOL change -> alice
    let (path_w, rk_w, ri_w, sr) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        1,
        0,
        alice.view_sk,
    )
    .unwrap();
    let (tw_chg, bl_chg, memo_chg) =
        encrypt_note_memo(&alice.view_pk, [0x23; 32], 1_090_000_000, &WSOL_MINT).unwrap();
    let ctx_uw = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        1,
        0b001,
        ASSET_MODE_PUBLIC,
        true,
        Some(&session_addr),
        Some(&relayer.pubkey()),
        &fr_to_be_bytes(&wsol_asset),
        900_000_000,
        10_000_000,
        &memo_chg,
    );
    let b_uw = prover.build_and_prove(
        sr,
        wsol_asset,
        wsol_asset,
        900_000_000,
        10_000_000,
        ctx_uw,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_w,
                asset_id: wsol_asset,
                amount: 2_000_000_000,
                blinding: bl_w,
                is_dummy: false,
                merkle_path: path_w,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: wsol_asset,
                amount: 0,
                blinding: Fr::from(99u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_chg),
                asset_id: wsol_asset,
                amount: 1_090_000_000,
                blinding: bl_chg,
            },
            JoinSplitOutputWitness::dummy(wsol_asset, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(wsol_asset, Fr::from(3u64)),
        ],
        [0x61; 32],
    );

    // Verify output_mask != 0 MUST reject READ-ONLY roots_acc (Custom 6002)!
    let mut bad_ro_ix = to_svm_ix(&build_transact(
        program_id,
        relayer.pubkey(),
        POOL_ID,
        VK_ID_DEFAULT,
        rk_w,
        ri_w,
        1,
        0,
        0,
        0,
        0,
        0b001,
        ASSET_MODE_PUBLIC,
        true,
        Some((wsol_mint_id(), vault_wsol, spl_token_id())),
        (None, None, None),
        &b_uw.proof_192,
        &b_uw.nf0,
        &b_uw.nf1,
        &b_uw.cm0,
        &b_uw.cm1,
        &b_uw.cm2,
        900_000_000,
        10_000_000,
        session_addr,
        relayer.pubkey(),
        &memo_chg,
        &[],
    ));
    assert!(bad_ro_ix.accounts[2].is_writable);
    bad_ro_ix.accounts[2].is_writable = false;
    expect_err_code(
        send_v1(&mut svm, &relayer, &[], &[bad_ro_ix], 300_000),
        6002,
        "output_mask != 0 with read-only roots_acc MUST be rejected",
    );

    let cu_uw = expect_ok(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_w,
                ri_w,
                1,
                0,
                0,
                0,
                0,
                0b001,
                ASSET_MODE_PUBLIC,
                true,
                Some((wsol_mint_id(), vault_wsol, spl_token_id())),
                (None, None, None),
                &b_uw.proof_192,
                &b_uw.nf0,
                &b_uw.nf1,
                &b_uw.cm0,
                &b_uw.cm1,
                &b_uw.cm2,
                900_000_000,
                10_000_000,
                session_addr,
                relayer.pubkey(),
                &memo_chg,
                &[],
            ))],
            300_000,
        ),
        "relayed partial WSOL unwrap -> 0-SOL DeFi session",
    );
    assert_eq!(svm.get_account(&session_addr).unwrap().lamports, 900_000_000);
    assert_eq!(
        svm.get_account(&derive_unwrap_pda(&program_id, POOL_ID, &b_uw.nf0).0)
            .map(|a| a.lamports)
            .unwrap_or(0),
        0,
        "ephemeral audren_unwrap PDA must be destroyed"
    );

    // Pause pool + warp +500_000 idle slots with ZERO crank:
    // FULL WSOL unwrap exit (output_mask == 0) with READ-ONLY roots_acc bypasses pause AND idle expiry!
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_set_paused(program_id, payer.pubkey(), POOL_ID, true))],
            100_000,
        ),
        "SetPaused(true)",
    );
    svm.warp_to_slot(500_104); // +500_000 idle slots! Zero checkpoint crank!

    let (path_chg, rk_chg, ri_chg, sr2) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        1,
        1,
        alice.view_sk,
    )
    .unwrap();
    let ctx_full = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        1,
        0,
        ASSET_MODE_PUBLIC,
        true,
        Some(&session_addr),
        Some(&relayer.pubkey()),
        &fr_to_be_bytes(&wsol_asset),
        1_080_000_000,
        10_000_000,
        &[],
    );
    let b_full = prover.build_and_prove(
        sr2,
        wsol_asset,
        wsol_asset,
        1_080_000_000,
        10_000_000,
        ctx_full,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_chg,
                asset_id: wsol_asset,
                amount: 1_090_000_000,
                blinding: bl_chg,
                is_dummy: false,
                merkle_path: path_chg,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: wsol_asset,
                amount: 0,
                blinding: Fr::from(100u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness::dummy(wsol_asset, Fr::from(1u64)),
            JoinSplitOutputWitness::dummy(wsol_asset, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(wsol_asset, Fr::from(3u64)),
        ],
        [0x62; 32],
    );
    let full_exit_ix = to_svm_ix(&build_transact(
        program_id,
        relayer.pubkey(),
        POOL_ID,
        VK_ID_DEFAULT,
        rk_chg,
        ri_chg,
        1,
        0,
        0,
        0,
        0,
        0,
        ASSET_MODE_PUBLIC,
        true,
        Some((wsol_mint_id(), vault_wsol, spl_token_id())),
        (None, None, None),
        &b_full.proof_192,
        &b_full.nf0,
        &b_full.nf1,
        &b_full.cm0,
        &b_full.cm1,
        &b_full.cm2,
        1_080_000_000,
        10_000_000,
        session_addr,
        relayer.pubkey(),
        &[],
        &[],
    ));
    assert!(
        !full_exit_ix.accounts[2].is_writable,
        "full exit (output_mask == 0) MUST mark GlobalRootHistory READ-ONLY"
    );
    let cu_full = expect_ok(
        send_v1(&mut svm, &relayer, &[], &[full_exit_ix], 300_000),
        "pause-exempt FULL WSOL unwrap exit after +500_000 idle slots (read-only roots_acc)",
    );
    assert_eq!(svm.get_account(&session_addr).unwrap().lamports, 1_980_000_000);
    assert_eq!(token_balance(&svm, &vault_wsol), net_sweep);
    println!("  [TEST 2 PASSED] WSOL partial={cu_uw} CU | paused full exit={cu_full} CU");
}

// ----------------------------------------------------------------------------
// TEST 3: Token-2022 TransferFee net-delta + active TransferHook + ExecViaEscrow
//         firewall (adversarial CPI) + EXEC_FLAG_FEE_ON_OUTPUT (WSOL -> T22 2.5%)
// ----------------------------------------------------------------------------
#[test]
fn test_t22_hook_exec_firewall_and_fee_on_output() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let router_id = Keypair::new().pubkey();
    let hook_id = Keypair::new().pubkey();
    let mut svm = new_svm(program_id, Some(router_id), Some(hook_id));
    let prover = AudrenProver::from_canonical_pk();

    let payer = Keypair::new();
    let relayer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();
    svm.airdrop(&relayer.pubkey(), 50_000_000_000).unwrap();
    svm.warp_to_slot(104);
    let vault_wsol = bootstrap_pool(&mut svm, program_id, &payer, 4);

    let alice = AudrenKeys::from_seed(&[0x55u8; 32]);
    let fvk = alice.full_viewing_key();
    let (va, _) = derive_vault_auth_pda(&program_id, POOL_ID);
    let (esc0, _) = derive_escrow_pda(&program_id, POOL_ID, 0);
    svm.airdrop(&esc0, 2_000_000).unwrap();

    // 1. Active Token-2022 TransferHook deposit into canonical vault ATA
    let hook_mint = create_t22_hook_mint(&mut svm, &payer, 6, hook_id);
    let extra_meta_pda =
        Address::find_program_address(&[b"extra-account-metas", hook_mint.as_ref()], &hook_id).0;
    let hook_state_pda =
        Address::find_program_address(&[b"hook_state", hook_mint.as_ref()], &hook_id).0;
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[Instruction {
                program_id: hook_id,
                accounts: vec![
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new_readonly(hook_mint, false),
                    AccountMeta::new(extra_meta_pda, false),
                    AccountMeta::new(hook_state_pda, false),
                    AccountMeta::new_readonly(sys_program_id(), false),
                ],
                data: vec![0u8],
            }],
            200_000,
        ),
        "init mock TransferHook extra metas",
    );
    let payer_hk = create_canonical_ata(&mut svm, &payer, payer.pubkey(), hook_mint, token_2022_id());
    let vault_hk = create_canonical_ata(&mut svm, &payer, va, hook_mint, token_2022_id());
    mint_to(&mut svm, &payer, token_2022_id(), hook_mint, payer_hk, 50_000_000);
    let (tw_hk, bl_hk, memo_hk) =
        encrypt_note_memo(&alice.view_pk, [0x31; 32], 20_000_000, &hook_mint.to_bytes()).unwrap();
    let (roots_pda, _) = derive_roots_pda(&program_id, POOL_ID);
    let cu_hk_dep = expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                hook_mint,
                payer_hk,
                vault_hk,
                token_2022_id(),
                0,
                0,
                0,
                0,
                None,
                None,
                false,
                false,
                20_000_000,
                derive_stealth_owner(alice.spend_pk, tw_hk),
                bl_hk,
                &memo_hk,
                &[
                    AudrenAccountMeta::readonly(extra_meta_pda, false),
                    AudrenAccountMeta::writable(hook_state_pda, false),
                    // Pass roots_pda in trailing accounts to prove TransferHook CPI filters it out!
                    AudrenAccountMeta::writable(roots_pda, false),
                    AudrenAccountMeta::readonly(hook_id, false),
                ],
            ))],
            250_000,
        ),
        "Deposit active TransferHook (filtering roots_acc)",
    );
    assert_eq!(token_balance(&svm, &vault_hk), 20_000_000);

    // 2. Setup mock DEX + Classic SPL USDC + WSOL + Token-2022 2.5% TransferFee mint
    let usdc_mint = create_spl_mint(&mut svm, &payer, 6);
    let t22_mint = create_t22_fee_mint(&mut svm, &payer, 6, 250, 50_000_000);
    let dex_pool = dex_pool_pda(&router_id);
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[dex_init_ix(router_id, payer.pubkey(), 10_000, 10_000_000_000)],
            200_000,
        ),
        "init mock router",
    );
    let dex_t22 = create_canonical_ata(&mut svm, &payer, dex_pool, t22_mint, token_2022_id());
    let vault_t22 = create_canonical_ata(&mut svm, &payer, va, t22_mint, token_2022_id());
    let esc0_t22 = create_canonical_ata(&mut svm, &payer, esc0, t22_mint, token_2022_id());
    let relayer_t22 = create_canonical_ata(&mut svm, &payer, relayer.pubkey(), t22_mint, token_2022_id());
    mint_to(&mut svm, &payer, token_2022_id(), t22_mint, dex_t22, 500_000_000);

    let vault_usdc = create_canonical_ata(&mut svm, &payer, va, usdc_mint, spl_token_id());
    let esc0_usdc = create_canonical_ata(&mut svm, &payer, esc0, usdc_mint, spl_token_id());
    let dex_usdc = create_canonical_ata(&mut svm, &payer, dex_pool, usdc_mint, spl_token_id());
    let payer_usdc = create_canonical_ata(&mut svm, &payer, payer.pubkey(), usdc_mint, spl_token_id());
    mint_to(&mut svm, &payer, spl_token_id(), usdc_mint, payer_usdc, 200_000_000);

    let esc0_wsol = create_canonical_ata(&mut svm, &payer, esc0, wsol_mint_id(), spl_token_id());
    let dex_wsol = create_canonical_ata(&mut svm, &payer, dex_pool, wsol_mint_id(), spl_token_id());

    // Deposit 100M lamports Native SOL (shielded as WSOL) on lane 1 + 100M USDC on lane 2
    let (tw_s, bl_s, memo_s) =
        encrypt_note_memo(&alice.view_pk, [0x41; 32], 100_000_000, &WSOL_MINT).unwrap();
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                wsol_mint_id(),
                payer.pubkey(),
                vault_wsol,
                spl_token_id(),
                1,
                0,
                0,
                0,
                None,
                None,
                true,
                false,
                100_000_000,
                derive_stealth_owner(alice.spend_pk, tw_s),
                bl_s,
                &memo_s,
                &[],
            ))],
            200_000,
        ),
        "deposit 100M Native SOL",
    );
    let (tw_u, bl_u, memo_u) =
        encrypt_note_memo(&alice.view_pk, [0x42; 32], 100_000_000, &usdc_mint.to_bytes()).unwrap();
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                usdc_mint,
                payer_usdc,
                vault_usdc,
                spl_token_id(),
                2,
                0,
                0,
                0,
                None,
                None,
                false,
                false,
                100_000_000,
                derive_stealth_owner(alice.spend_pk, tw_u),
                bl_u,
                &memo_u,
                &[],
            ))],
            200_000,
        ),
        "deposit 100M USDC",
    );
    // 3. Adversarial CPI check: Mode 1 escrow Assign hijack MUST be blocked with Custom(6031),
    //    AND passing GlobalRootHistory (`roots_pda`) inside `router_accounts` MUST be blocked with Custom(6021)!
    let (path_u, rk_u, ri_u, sr_u) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        2,
        0,
        alice.view_sk,
    )
    .unwrap();
    let asset_wsol = asset_id_for_mint(None);
    let asset_usdc = asset_id_for_mint(Some(&usdc_mint));
    let asset_t22 = asset_id_for_mint(Some(&t22_mint));

    let (dtw, dbl, dhead, dmask) = prepare_dynamic_swap_memo(&alice.view_pk, [0x45; 32]).unwrap();
    let ost = fr_to_be_bytes(&derive_stealth_owner(alice.spend_pk, dtw));
    let obl = fr_to_be_bytes(&dbl);
    let hijack_data = dex_swap_spl_to_spl_data(1, 50_000_000, 50_000_000, 6, 6);
    let hijack_accs = vec![
        AudrenAccountMeta::writable(esc0, false),
        AudrenAccountMeta::writable(esc0_usdc, false),
        AudrenAccountMeta::writable(dex_usdc, false),
        AudrenAccountMeta::writable(dex_pool, false),
        AudrenAccountMeta::writable(dex_t22, false),
        AudrenAccountMeta::writable(esc0_t22, false),
        AudrenAccountMeta::readonly(usdc_mint, false),
        AudrenAccountMeta::readonly(t22_mint, false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::readonly(token_2022_id(), false),
        AudrenAccountMeta::readonly(sys_program_id(), false),
        AudrenAccountMeta::readonly(router_id, false),
    ];
    let ctx_hj = compute_exec_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        3,
        0,
        0,
        false,
        &fr_to_be_bytes(&asset_usdc),
        50_000_000,
        0,
        None,
        &fr_to_be_bytes(&asset_t22),
        1,
        &router_id,
        &hijack_accs,
        &[],
        &ost,
        &obl,
        &dhead,
        &dmask,
        &hijack_data,
        &[],
    );
    let b_hj = prover.build_and_prove(
        sr_u,
        asset_usdc,
        asset_usdc,
        50_000_000,
        0,
        ctx_hj,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_u,
                asset_id: asset_usdc,
                amount: 100_000_000,
                blinding: bl_u,
                is_dummy: false,
                merkle_path: path_u.clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_usdc,
                amount: 0,
                blinding: Fr::from(10u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, Fr::from(11u64)),
                asset_id: asset_usdc,
                amount: 50_000_000,
                blinding: Fr::from(12u64),
            },
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(3u64)),
        ],
        [0x70; 32],
    );
    expect_err_code(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_exec_via_escrow(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_u,
                ri_u,
                3,
                0,
                0,
                0,
                0,
                0,
                0,
                false,
                (usdc_mint, vault_usdc, esc0_usdc, spl_token_id()),
                (t22_mint, vault_t22, esc0_t22, token_2022_id()),
                0,
                None,
                (None, None, None),
                &b_hj.proof_192,
                &b_hj.nf0,
                &b_hj.nf1,
                &b_hj.cm0,
                &b_hj.cm1,
                &b_hj.cm2,
                50_000_000,
                1,
                &ost,
                &obl,
                &dhead,
                &dmask,
                router_id,
                &hijack_data,
                hijack_accs,
                &[],
                &[],
            ))],
            400_000,
        ),
        6031,
        "Mode 1 escrow Assign hijack blocked",
    );

    // 3b. Adversarial CPI check: passing GlobalRootHistory (`roots_pda`) in `router_accounts` MUST fail with Custom(6021)!
    let roots_in_router_accs = vec![
        AudrenAccountMeta::writable(esc0, false),
        AudrenAccountMeta::writable(esc0_usdc, false),
        AudrenAccountMeta::writable(dex_usdc, false),
        AudrenAccountMeta::writable(dex_pool, false),
        AudrenAccountMeta::writable(dex_t22, false),
        AudrenAccountMeta::writable(esc0_t22, false),
        AudrenAccountMeta::readonly(usdc_mint, false),
        AudrenAccountMeta::readonly(t22_mint, false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::readonly(token_2022_id(), false),
        AudrenAccountMeta::writable(roots_pda, false),
    ];
    let honest_u2t_data = dex_swap_spl_to_spl_data(0, 50_000_000, 50_000_000, 6, 6);
    let ctx_roots_atk = compute_exec_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        3,
        0,
        0,
        false,
        &fr_to_be_bytes(&asset_usdc),
        50_000_000,
        0,
        None,
        &fr_to_be_bytes(&asset_t22),
        1,
        &router_id,
        &roots_in_router_accs,
        &[],
        &ost,
        &obl,
        &dhead,
        &dmask,
        &honest_u2t_data,
        &[],
    );
    let b_roots_atk = prover.build_and_prove(
        sr_u,
        asset_usdc,
        asset_usdc,
        50_000_000,
        0,
        ctx_roots_atk,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_u,
                asset_id: asset_usdc,
                amount: 100_000_000,
                blinding: bl_u,
                is_dummy: false,
                merkle_path: path_u,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_usdc,
                amount: 0,
                blinding: Fr::from(10u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, Fr::from(11u64)),
                asset_id: asset_usdc,
                amount: 50_000_000,
                blinding: Fr::from(12u64),
            },
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(3u64)),
        ],
        [0x71; 32],
    );
    expect_err_code(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_exec_via_escrow(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_u,
                ri_u,
                3,
                0,
                0,
                0,
                0,
                0,
                0,
                false,
                (usdc_mint, vault_usdc, esc0_usdc, spl_token_id()),
                (t22_mint, vault_t22, esc0_t22, token_2022_id()),
                0,
                None,
                (None, None, None),
                &b_roots_atk.proof_192,
                &b_roots_atk.nf0,
                &b_roots_atk.nf1,
                &b_roots_atk.cm0,
                &b_roots_atk.cm1,
                &b_roots_atk.cm2,
                50_000_000,
                1,
                &ost,
                &obl,
                &dhead,
                &dmask,
                router_id,
                &honest_u2t_data,
                roots_in_router_accs,
                &[],
                &[],
            ))],
            400_000,
        ),
        6021,
        "ExecViaEscrow passing GlobalRootHistory in router_accounts blocked (6021)",
    );

    // 4. Positive EXEC_FLAG_FEE_ON_OUTPUT: WSOL (100M) -> Token-2022 2.5% TransferFee
    //    Router sends 100M gross -> escrow gets 97.5M -> relayer fee 5M (relayer nets 4,875,000) ->
    //    remaining 92.5M swept -> vault nets 90,187,500 committed & FVK recovered!
    let (path_s, rk_s, ri_s, sr_s) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        1,
        0,
        alice.view_sk,
    )
    .unwrap();
    let (dtw2, dbl2, dhead2, dmask2) = prepare_dynamic_swap_memo(&alice.view_pk, [0x49; 32]).unwrap();
    let ost2 = fr_to_be_bytes(&derive_stealth_owner(alice.spend_pk, dtw2));
    let obl2 = fr_to_be_bytes(&dbl2);
    let w2t_data = dex_swap_spl_to_spl_data(0, 100_000_000, 100_000_000, 9, 6);
    // Regression check for Jupiter ZeroFi behavior: router marks `escrow` as `is_signer: true,
    // is_writable: false`, while Solana promotes `escrow` writable tx-wide.
    let w2t_accs_raw = vec![
        AudrenAccountMeta::readonly(esc0, true),
        AudrenAccountMeta::writable(esc0_wsol, false),
        AudrenAccountMeta::writable(dex_wsol, false),
        AudrenAccountMeta::writable(dex_pool, false),
        AudrenAccountMeta::writable(dex_t22, false),
        AudrenAccountMeta::writable(esc0_t22, false),
        AudrenAccountMeta::readonly(wsol_mint_id(), false),
        AudrenAccountMeta::readonly(t22_mint, false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::readonly(token_2022_id(), false),
    ];
    let w2t_accs = prepare_escrow_accounts_for_audren(&w2t_accs_raw, &esc0, &[esc0_wsol, esc0_t22]);
    assert!(!w2t_accs[0].is_signer, "escrow signer bit must be stripped");
    assert!(w2t_accs[0].is_writable, "escrow must be promoted writable tx-wide");
    let ctx_w2t = compute_exec_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        3,
        0,
        0,
        true,
        &asset_id_bytes_for_mint(None),
        100_000_000,
        5_000_000,
        Some(&relayer_t22),
        &fr_to_be_bytes(&asset_t22),
        90_187_500,
        &router_id,
        &w2t_accs_raw,
        &[],
        &ost2,
        &obl2,
        &dhead2,
        &dmask2,
        &w2t_data,
        &[],
    );
    let ctx_w2t_norm = compute_exec_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        3,
        0,
        0,
        true,
        &asset_id_bytes_for_mint(None),
        100_000_000,
        5_000_000,
        Some(&relayer_t22),
        &fr_to_be_bytes(&asset_t22),
        90_187_500,
        &router_id,
        &w2t_accs,
        &[],
        &ost2,
        &obl2,
        &dhead2,
        &dmask2,
        &w2t_data,
        &[],
    );
    assert_eq!(ctx_w2t, ctx_w2t_norm);
    let b_w2t = prover.build_and_prove(
        sr_s,
        asset_wsol,
        asset_wsol,
        100_000_000,
        0,
        ctx_w2t,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_s,
                asset_id: asset_wsol,
                amount: 100_000_000,
                blinding: bl_s,
                is_dummy: false,
                merkle_path: path_s,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_wsol,
                amount: 0,
                blinding: Fr::from(19u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(1u64)),
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
        ],
        [0x79; 32],
    );
    let leaf_before = lane_next_leaf(&svm, &program_id, 3);
    let cu_w2t = expect_ok(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_exec_via_escrow(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_s,
                ri_s,
                3,
                0,
                0,
                0,
                0,
                0,
                0,
                true,
                (wsol_mint_id(), vault_wsol, esc0_wsol, spl_token_id()),
                (t22_mint, vault_t22, esc0_t22, token_2022_id()),
                5_000_000,
                Some(relayer_t22),
                (None, None, None),
                &b_w2t.proof_192,
                &b_w2t.nf0,
                &b_w2t.nf1,
                &b_w2t.cm0,
                &b_w2t.cm1,
                &b_w2t.cm2,
                100_000_000,
                90_187_500,
                &ost2,
                &obl2,
                &dhead2,
                &dmask2,
                router_id,
                &w2t_data,
                w2t_accs,
                &[],
                &[],
            ))],
            400_000,
        ),
        "WSOL -> Token-2022 2.5% TransferFee with EXEC_FLAG_FEE_ON_OUTPUT",
    );
    assert_eq!(token_balance(&svm, &relayer_t22), 4_875_000);
    assert_eq!(token_balance(&svm, &vault_t22), 90_187_500);
    assert_eq!(token_balance(&svm, &esc0_t22), 0);
    assert_eq!(token_balance(&svm, &esc0_wsol), 0);

    // Verify FVK recovers the exact dynamic Token-2022 note from XOR-masked 72 B MemoPage + SubtreePage!
    let sub3 = svm
        .get_account(&derive_subtree_pda(&program_id, POOL_ID, 3, 0).0)
        .unwrap()
        .data;
    let memo3 = svm
        .get_account(&derive_memo_pda(&program_id, POOL_ID, 3, 0).0)
        .unwrap()
        .data;
    let slot = leaf_before as usize;
    let cm_be = read_32(&sub3, SB_OFF_LEAVES + slot * 32);
    let vt = [
        memo3[MM_OFF_VIEW_TAGS + slot * 2],
        memo3[MM_OFF_VIEW_TAGS + slot * 2 + 1],
    ];
    let epk = read_32(&memo3, MM_OFF_EPHEMERAL_PKS + slot * 32);
    let ct: [u8; MEMO_CT_LEN] = memo3
        [MM_OFF_CIPHERTEXTS + slot * MEMO_CT_LEN..MM_OFF_CIPHERTEXTS + (slot + 1) * MEMO_CT_LEN]
        .try_into()
        .unwrap();
    let dec = try_decrypt_and_verify_memo_entry(&fvk, vt, &epk, &ct, &cm_be).unwrap();
    assert!(dec.is_dynamic);
    assert_eq!(dec.amount, 90_187_500);
    assert_eq!(dec.mint, t22_mint.to_bytes());
    println!(
        "  [TEST 3 PASSED] TransferHook Deposit={cu_hk_dep} CU | WSOL->T22 Fee-on-Output={cu_w2t} CU"
    );
}

// ----------------------------------------------------------------------------
// REGRESSION (a): Non-canonical ATA injection DoS rejected (Custom 6020)
//                 across Deposit, Transact, and ExecViaEscrow
// ----------------------------------------------------------------------------
#[test]
fn test_regression_a_non_canonical_ata_rejected_across_all_instructions() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let router_id = Keypair::new().pubkey();
    let mut svm = new_svm(program_id, Some(router_id), None);
    let prover = AudrenProver::from_canonical_pk();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();
    svm.warp_to_slot(104);
    let canon_vault_wsol = bootstrap_pool(&mut svm, program_id, &payer, 4);

    let (va, _) = derive_vault_auth_pda(&program_id, POOL_ID);
    let (esc0, _) = derive_escrow_pda(&program_id, POOL_ID, 0);
    let usdc_mint = create_spl_mint(&mut svm, &payer, 6);
    let canon_vault_usdc = create_canonical_ata(&mut svm, &payer, va, usdc_mint, spl_token_id());
    let canon_esc0_usdc = create_canonical_ata(&mut svm, &payer, esc0, usdc_mint, spl_token_id());
    let canon_esc0_wsol = create_canonical_ata(&mut svm, &payer, esc0, wsol_mint_id(), spl_token_id());
    let payer_usdc = create_canonical_ata(&mut svm, &payer, payer.pubkey(), usdc_mint, spl_token_id());
    mint_to(&mut svm, &payer, spl_token_id(), usdc_mint, payer_usdc, 200_000_000);

    // Attacker creates VALID `vault_auth`-owned & `escrow`-owned NON-CANONICAL token accounts!
    let rogue_vault_wsol =
        create_non_canonical_token_acc(&mut svm, &payer, wsol_mint_id(), va, spl_token_id(), &[]);
    let rogue_vault_usdc =
        create_non_canonical_token_acc(&mut svm, &payer, usdc_mint, va, spl_token_id(), &[]);
    let rogue_esc0_usdc =
        create_non_canonical_token_acc(&mut svm, &payer, usdc_mint, esc0, spl_token_id(), &[]);
    let rogue_esc0_wsol =
        create_non_canonical_token_acc(&mut svm, &payer, wsol_mint_id(), esc0, spl_token_id(), &[]);
    // Pre-fund rogue_vault_usdc so balance check alone would pass if canonical ATA check were absent!
    mint_to(&mut svm, &payer, spl_token_id(), usdc_mint, rogue_vault_usdc, 100_000_000);

    let alice = AudrenKeys::from_seed(&[0xB1u8; 32]);
    let (tw_s, bl_s, memo_s) =
        encrypt_note_memo(&alice.view_pk, [0xB2; 32], 50_000_000, &WSOL_MINT).unwrap();
    let (tw_u, bl_u, memo_u) =
        encrypt_note_memo(&alice.view_pk, [0xB3; 32], 50_000_000, &usdc_mint.to_bytes()).unwrap();

    // 1. Deposit (Native SOL) with non-canonical vault WSOL account -> MUST fail with 6020!
    expect_err_code(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                wsol_mint_id(),
                payer.pubkey(),
                rogue_vault_wsol,
                spl_token_id(),
                0,
                0,
                0,
                0,
                None,
                None,
                true,
                false,
                50_000_000,
                derive_stealth_owner(alice.spend_pk, tw_s),
                bl_s,
                &memo_s,
                &[],
            ))],
            200_000,
        ),
        6020,
        "Deposit(NATIVE_SOL) non-canonical vault ATA rejected",
    );

    // 2. Deposit (SPL) with non-canonical vault USDC account -> MUST fail with 6020!
    expect_err_code(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                usdc_mint,
                payer_usdc,
                rogue_vault_usdc,
                spl_token_id(),
                0,
                0,
                0,
                0,
                None,
                None,
                false,
                false,
                50_000_000,
                derive_stealth_owner(alice.spend_pk, tw_u),
                bl_u,
                &memo_u,
                &[],
            ))],
            200_000,
        ),
        6020,
        "Deposit(SPL) non-canonical vault ATA rejected",
    );

    // Legitimately deposit USDC into canonical vault ATA (immediately reflected in GlobalRootHistory!)
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                usdc_mint,
                payer_usdc,
                canon_vault_usdc,
                spl_token_id(),
                0,
                0,
                0,
                0,
                None,
                None,
                false,
                false,
                50_000_000,
                derive_stealth_owner(alice.spend_pk, tw_u),
                bl_u,
                &memo_u,
                &[],
            ))],
            200_000,
        ),
        "canonical Deposit(SPL)",
    );

    // 3. Transact (ASSET_MODE_PUBLIC) with non-canonical vault USDC account -> MUST fail with 6020!
    let (path, rk_a, ri_a, sr) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        0,
        0,
        alice.view_sk,
    )
    .unwrap();
    let asset_usdc = asset_id_for_mint(Some(&usdc_mint));
    let ctx_wd = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        1,
        0,
        ASSET_MODE_PUBLIC,
        false,
        Some(&payer_usdc),
        None,
        &fr_to_be_bytes(&asset_usdc),
        50_000_000,
        0,
        &[],
    );
    let b_wd = prover.build_and_prove(
        sr,
        asset_usdc,
        asset_usdc,
        50_000_000,
        0,
        ctx_wd,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_u,
                asset_id: asset_usdc,
                amount: 50_000_000,
                blinding: bl_u,
                is_dummy: false,
                merkle_path: path.clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_usdc,
                amount: 0,
                blinding: Fr::from(1u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(3u64)),
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(4u64)),
        ],
        [0x81; 32],
    );
    expect_err_code(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                payer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_a,
                ri_a,
                1,
                0,
                0,
                0,
                0,
                0,
                ASSET_MODE_PUBLIC,
                false,
                Some((usdc_mint, rogue_vault_usdc, spl_token_id())),
                (None, None, None),
                &b_wd.proof_192,
                &b_wd.nf0,
                &b_wd.nf1,
                &b_wd.cm0,
                &b_wd.cm1,
                &b_wd.cm2,
                50_000_000,
                0,
                payer_usdc,
                payer.pubkey(),
                &[],
                &[],
            ))],
            300_000,
        ),
        6020,
        "Transact(PUBLIC) non-canonical vault ATA rejected",
    );

    // 4. ExecViaEscrow with ANY non-canonical vault or escrow ATA -> ALL 4 MUST fail with 6020!
    let (dtw, dbl, dhead, dmask) = prepare_dynamic_swap_memo(&alice.view_pk, [0x82; 32]).unwrap();
    let ost = fr_to_be_bytes(&derive_stealth_owner(alice.spend_pk, dtw));
    let obl = fr_to_be_bytes(&dbl);
    let dummy_router_accs = vec![AudrenAccountMeta::writable(esc0, false)];
    let bad_legs = [
        (
            "non-canonical vault_in_ata",
            (usdc_mint, rogue_vault_usdc, canon_esc0_usdc, spl_token_id()),
            (wsol_mint_id(), canon_vault_wsol, canon_esc0_wsol, spl_token_id()),
        ),
        (
            "non-canonical escrow_in_ata",
            (usdc_mint, canon_vault_usdc, rogue_esc0_usdc, spl_token_id()),
            (wsol_mint_id(), canon_vault_wsol, canon_esc0_wsol, spl_token_id()),
        ),
        (
            "non-canonical vault_out_ata",
            (usdc_mint, canon_vault_usdc, canon_esc0_usdc, spl_token_id()),
            (wsol_mint_id(), rogue_vault_wsol, canon_esc0_wsol, spl_token_id()),
        ),
        (
            "non-canonical escrow_out_ata",
            (usdc_mint, canon_vault_usdc, canon_esc0_usdc, spl_token_id()),
            (wsol_mint_id(), canon_vault_wsol, rogue_esc0_wsol, spl_token_id()),
        ),
    ];
    for (label, in_leg, out_leg) in bad_legs {
        expect_err_code(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_exec_via_escrow(
                    program_id,
                    payer.pubkey(),
                    POOL_ID,
                    VK_ID_DEFAULT,
                    rk_a,
                    ri_a,
                    1,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    false,
                    in_leg,
                    out_leg,
                    0,
                    None,
                    (None, None, None),
                    &b_wd.proof_192,
                    &b_wd.nf0,
                    &b_wd.nf1,
                    &b_wd.cm0,
                    &b_wd.cm1,
                    &b_wd.cm2,
                    50_000_000,
                    1,
                    &ost,
                    &obl,
                    &dhead,
                    &dmask,
                    router_id,
                    &[0u8; 4],
                    dummy_router_accs.clone(),
                    &[],
                    &[],
                ))],
                300_000,
            ),
            6020,
            label,
        );
    }
    println!("  [REGRESSION (a) PASSED] Non-canonical ATA rejected across Deposit, Transact, and all 4 ExecViaEscrow legs");
}

// ----------------------------------------------------------------------------
// REGRESSION (b): SysvarRent exemption_threshold = 0.5 / 0.25 / 0.0 in LiteSVM
//                 + zero-rent `>= 1` lamport PDA & NullifierPDA anti-reaping floor
// ----------------------------------------------------------------------------
#[test]
fn test_regression_b_sysvar_rent_fractional_and_zero_thresholds() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let prover = AudrenProver::from_canonical_pk();
    const LPBY: u64 = 3_480;

    for (threshold, exp_pool_rent, exp_memo_rent) in [
        (0.5f64, 445_440u64, 18_040_320u64),
        (0.25f64, 222_720u64, 9_020_160u64),
        (0.0f64, 0u64, 0u64),
    ] {
        let mut svm = new_svm(program_id, None, None);
        #[allow(deprecated)]
        let custom_rent = Rent {
            lamports_per_byte: LPBY,
            exemption_threshold: threshold.to_le_bytes(),
            burn_percent: 50,
        };
        svm.set_sysvar(&custom_rent);
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
        svm.warp_to_slot(104);

        // Even at `exemption_threshold == 0.0`, NO pre-airdrop is required: `create_pda_safe` and
        // `ix_open_page` enforce a `>= 1` lamport floor so Solana never reaps PoolState, LaneRentVault,
        // pages, GlobalRootHistory, or NullifierPDA!
        let (pool_pda, _) = derive_pool_pda(&program_id, POOL_ID);
        let (roots_pda, _) = derive_roots_pda(&program_id, POOL_ID);
        let (lane_rent_pda, _) = derive_lane_rent_pda(&program_id, POOL_ID, 0);
        let (memo1_pda, _) = derive_memo_pda(&program_id, POOL_ID, 0, 1);

        let vault_wsol = bootstrap_pool(&mut svm, program_id, &payer, 1);
        let pool_lamports = svm.get_account(&pool_pda).unwrap().lamports;
        let expected_pool_actual = exp_pool_rent.max(1);
        assert_eq!(
            pool_lamports, expected_pool_actual,
            "PoolState lamports mismatch at exemption_threshold={threshold}"
        );
        assert!(
            svm.get_account(&roots_pda).unwrap().lamports >= 1,
            "GlobalRootHistory must survive at >= 1 lamport at exemption_threshold={threshold}"
        );

        let alice = AudrenKeys::from_seed(&[0xC1u8; 32]);
        let (tw, bl, memo) =
            encrypt_note_memo(&alice.view_pk, [0xC2; 32], 5_000_000, &WSOL_MINT).unwrap();
        expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_deposit(
                    program_id,
                    payer.pubkey(),
                    POOL_ID,
                    wsol_mint_id(),
                    payer.pubkey(),
                    vault_wsol,
                    spl_token_id(),
                    0,
                    0,
                    0,
                    0,
                    None,
                    None,
                    true,
                    false,
                    5_000_000,
                    derive_stealth_owner(alice.spend_pk, tw),
                    bl,
                    &memo,
                    &[],
                ))],
                200_000,
            ),
            "Deposit under custom Rent sysvar",
        );
        if exp_pool_rent == 0 {
            // `collect_lane_rent_fee` clamps `min_vault` and every `page_rent` with `.max(1)`
            // so `target_balance = 5`, `live_per_note = 3`, raising `LaneRentVault` from 1 -> 4 lamports!
            assert_eq!(
                svm.get_account(&lane_rent_pda).unwrap().lamports,
                4,
                "zero-rent collect_lane_rent_fee must fund LaneRentVault (1 -> 4 lamports)"
            );
        }

        // At next_leaf=1 (< 86), pre-opening MemoPage 1 must be rejected with PageSeqOutOfRange (6029)
        expect_err_code(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_open_page(
                    program_id,
                    payer.pubkey(),
                    OPEN_PAGE_KIND_MEMO,
                    POOL_ID,
                    0,
                    1,
                    u64::MAX,
                ))],
                200_000,
            ),
            6029,
            "OpenPage(MEMO, 1) below >=90% lookahead must fail with 6029",
        );

        // Temporarily advance lane0 next_leaf to 86 (>= 90% MemoPage threshold) to exercise
        // OpenPage(MEMO, 1) under custom Rent sysvar, then restore lane0 before Transact/sweep.
        let (lane0_pda, _) = derive_lane_pda(&program_id, POOL_ID, 0);
        let orig_lane0 = svm.get_account(&lane0_pda).unwrap();
        {
            let mut bumped = orig_lane0.clone();
            bumped.data[LN_OFF_NEXT_LEAF..LN_OFF_NEXT_LEAF + 8]
                .copy_from_slice(&86u64.to_le_bytes());
            svm.set_account(lane0_pda, bumped).unwrap();
        }
        expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_open_page(
                    program_id,
                    payer.pubkey(),
                    OPEN_PAGE_KIND_MEMO,
                    POOL_ID,
                    0,
                    1,
                    u64::MAX,
                ))],
                200_000,
            ),
            "OpenPage(MEMO, 1) under custom Rent sysvar",
        );
        svm.set_account(lane0_pda, orig_lane0).unwrap();
        let memo1_lamports = svm.get_account(&memo1_pda).unwrap().lamports;
        let expected_memo_actual = exp_memo_rent.max(1);
        assert_eq!(
            memo1_lamports, expected_memo_actual,
            "MemoPage lamports mismatch at exemption_threshold={threshold}"
        );
        assert!(
            svm.get_account(&lane_rent_pda).unwrap().lamports >= 1,
            "LaneRentVault sentinel must never be drained to 0 lamports"
        );
        if exp_pool_rent == 0 {
            assert_eq!(
                svm.get_account(&lane_rent_pda).unwrap().lamports,
                3,
                "zero-rent OpenPage(MEMO, 1) must be 100% subsidized by LaneRentVault (4 -> 3 lamports)"
            );
        }

        // Zero-rent NullifierPDA anti-reaping check: spend the note via Transact, verify NullifierPDA
        // survives with `lamports == 1`, and verify double-spend replay is rejected with Custom(6012)!
        if exp_pool_rent == 0 {
            let (path, rk_z, ri_z, sr) = reconstruct_witness_with(
                |a| svm.get_account(a).map(|x| x.data),
                &program_id,
                POOL_ID,
                0,
                0,
                alice.view_sk,
            )
            .unwrap();
            let asset_wsol = asset_id_for_mint(None);
            let (tw_out, bl_out, memo_out) =
                encrypt_note_memo(&alice.view_pk, [0xC3; 32], 5_000_000, &WSOL_MINT).unwrap();
            let ctx = compute_transact_ctx_hash(
                &program_id,
                POOL_ID,
                VK_ID_DEFAULT,
                0,
                0b001,
                ASSET_MODE_PRIVATE,
                false,
                None,
                None,
                &[0u8; 32],
                0,
                0,
                &memo_out,
            );
            let bundle = prover.build_and_prove(
                sr,
                asset_wsol,
                Fr::from(0u64),
                0,
                0,
                ctx,
                true,
                [
                    JoinSplitInputWitness {
                        spend_sk: alice.spend_sk,
                        tweak: tw,
                        asset_id: asset_wsol,
                        amount: 5_000_000,
                        blinding: bl,
                        is_dummy: false,
                        merkle_path: path,
                    },
                    JoinSplitInputWitness {
                        spend_sk: alice.spend_sk,
                        tweak: Fr::from(0u64),
                        asset_id: asset_wsol,
                        amount: 0,
                        blinding: Fr::from(1u64),
                        is_dummy: true,
                        merkle_path: MerklePath4Ary::default(),
                    },
                ],
                [
                    JoinSplitOutputWitness {
                        stealth_owner: derive_stealth_owner(alice.spend_pk, tw_out),
                        asset_id: asset_wsol,
                        amount: 5_000_000,
                        blinding: bl_out,
                    },
                    JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(2u64)),
                    JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
                ],
                [0xC4; 32],
            );
            let tx_ix = to_svm_ix(&build_transact(
                program_id,
                payer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_z,
                ri_z,
                0,
                0,
                0,
                0,
                0,
                0b001,
                ASSET_MODE_PRIVATE,
                false,
                None,
                (None, None, None),
                &bundle.proof_192,
                &bundle.nf0,
                &bundle.nf1,
                &bundle.cm0,
                &bundle.cm1,
                &bundle.cm2,
                0,
                0,
                payer.pubkey(),
                payer.pubkey(),
                &memo_out,
                &[],
            ));
            expect_ok(
                send_v1(&mut svm, &payer, &[], std::slice::from_ref(&tx_ix), 350_000),
                "Transact creating NullifierPDA under zero-rent sysvar",
            );
            let (nf0_pda, _) = derive_nullifier_pda(&program_id, POOL_ID, &bundle.nf0);
            let nf0_acc = svm
                .get_account(&nf0_pda)
                .expect("NullifierPDA MUST survive at >= 1 lamport on zero-rent cluster");
            assert_eq!(nf0_acc.lamports, 1);
            assert_eq!(nf0_acc.owner, program_id);
            expect_err_code(
                send_v1(&mut svm, &payer, &[], &[tx_ix], 350_000),
                6012,
                "NullifierPDA replay on zero-rent cluster MUST fail (not reaped)",
            );

            // Zero-rent `DEPOSIT_FLAG_NATIVE_SOL | DEPOSIT_FLAG_FEE_FROM_AMOUNT` parity:
            // `deterministic_note_rent_fee` clamps `sub_rent`, `sr_rent`, and `memo_rent` with
            // `.max(1)`, deducting exact `1 + 1 + 1 = 3` lamports (matching `collect_lane_rent_fee`).
            let zero_rent_fee = deterministic_note_rent_fee(
                2_000_000,
                svm.minimum_balance_for_rent_exemption(SUBTREE_PAGE_LEN),
                svm.minimum_balance_for_rent_exemption(SUBROOT_PAGE_LEN),
                svm.minimum_balance_for_rent_exemption(MEMO_PAGE_LEN),
            );
            assert_eq!(
                zero_rent_fee, 3,
                "deterministic_note_rent_fee must equal 1+1+1=3 on a zero-rent cluster"
            );
            let sweeper = Keypair::new();
            let sweep_start = 10_000_000u64;
            svm.airdrop(&sweeper.pubkey(), sweep_start).unwrap();
            let pre_vault_bal = token_balance(&svm, &vault_wsol);
            let pre_lane_rent_lamports = svm.get_account(&lane_rent_pda).unwrap().lamports;
            let gross_sweep = sweep_start - 5_000;
            let net_sweep = gross_sweep - zero_rent_fee;
            let (tw_z, bl_z, memo_z) =
                encrypt_note_memo(&alice.view_pk, [0xC5; 32], net_sweep, &WSOL_MINT).unwrap();
            expect_ok(
                send_v1(
                    &mut svm,
                    &sweeper,
                    &[],
                    &[to_svm_ix(&build_deposit(
                        program_id,
                        sweeper.pubkey(),
                        POOL_ID,
                        wsol_mint_id(),
                        sweeper.pubkey(),
                        vault_wsol,
                        spl_token_id(),
                        0,
                        0,
                        0,
                        0,
                        None,
                        None,
                        true,
                        true,
                        gross_sweep,
                        derive_stealth_owner(alice.spend_pk, tw_z),
                        bl_z,
                        &memo_z,
                        &[],
                    ))],
                    200_000,
                ),
                "Deposit(NATIVE_SOL | FEE_FROM_AMOUNT) under zero-rent sysvar",
            );
            assert_eq!(
                svm.get_account(&sweeper.pubkey()).map(|a| a.lamports).unwrap_or(0),
                0,
                "zero-rent fee_from_amount sweep must leave sweeper at exact 0 lamports"
            );
            assert_eq!(
                svm.get_account(&lane_rent_pda).unwrap().lamports - pre_lane_rent_lamports,
                3,
                "zero-rent Deposit(FEE_FROM_AMOUNT) must deduct exact 3 lamports into LaneRentVault"
            );
            assert_eq!(
                token_balance(&svm, &vault_wsol) - pre_vault_bal,
                net_sweep,
                "zero-rent Deposit(FEE_FROM_AMOUNT) must wrap exact gross_sweep - 3 lamports"
            );
            let mut z_store = CompactWalletStore::new(POOL_ID, 0);
            let sub0_z = svm
                .get_account(&derive_subtree_pda(&program_id, POOL_ID, 0, 0).0)
                .unwrap()
                .data;
            let memo0_z = svm
                .get_account(&derive_memo_pda(&program_id, POOL_ID, 0, 0).0)
                .unwrap()
                .data;
            let z_found = z_store
                .ingest_lane_pages(
                    &alice.full_viewing_key(),
                    0,
                    &[(0, &sub0_z)],
                    &[(0, &memo0_z)],
                    &[],
                )
                .unwrap();
            assert_eq!(
                z_found, 3,
                "expected 3 notes on lane 0 (initial deposit + transact output + zero-rent sweep)"
            );
            assert_eq!(
                z_store.notes[2].amount, net_sweep,
                "committed leaf & decrypted memo must match exact gross_sweep - 3 lamports"
            );
        }
    }
    println!("  [REGRESSION (b) PASSED] SysvarRent 0.5/0.25/0.0, zero-rent >=1 lamport NullifierPDA floor & 3-lamport FEE_FROM_AMOUNT parity verified");
}

// ----------------------------------------------------------------------------
// REGRESSION (c): Deposit(DEPOSIT_FLAG_NATIVE_SOL) with stray pre-donated lamports
//                 on canonical WSOL `vault_ata` commits exact `net_sol` (matching memo!)
// ----------------------------------------------------------------------------
#[test]
fn test_regression_c_native_sol_deposit_with_stray_donated_lamports() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let mut svm = new_svm(program_id, None, None);
    let payer = Keypair::new();
    let donor = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
    svm.airdrop(&donor.pubkey(), 10_000_000_000).unwrap();
    svm.warp_to_slot(104);
    let vault_wsol = bootstrap_pool(&mut svm, program_id, &payer, 4);

    // Attacker pre-donates 777_777 raw lamports directly to canonical WSOL `vault_ata` BEFORE deposit!
    let stray_donation = 777_777u64;
    expect_ok(
        send_v1(
            &mut svm,
            &donor,
            &[],
            &[sys_ix::transfer(&donor.pubkey(), &vault_wsol, stray_donation)],
            100_000,
        ),
        "donate stray lamports to vault WSOL ATA",
    );
    assert_eq!(token_balance(&svm, &vault_wsol), 0, "before SyncNative token balance is still 0");

    let alice = AudrenKeys::from_seed(&[0xD1u8; 32]);
    let fvk = alice.full_viewing_key();
    let deposit_amount = 50_000_000u64;
    let (tw, bl, memo) =
        encrypt_note_memo(&alice.view_pk, [0xD2; 32], deposit_amount, &WSOL_MINT).unwrap();
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                wsol_mint_id(),
                payer.pubkey(),
                vault_wsol,
                spl_token_id(),
                0,
                0,
                0,
                0,
                None,
                None,
                true,
                false,
                deposit_amount,
                derive_stealth_owner(alice.spend_pk, tw),
                bl,
                &memo,
                &[],
            ))],
            200_000,
        ),
        "Deposit(NATIVE_SOL) with stray pre-donated lamports",
    );

    // SyncNative wrapped BOTH deposit_amount AND stray_donation, leaving surplus backing in vault,
    // while the committed leaf & memo match EXACTLY `deposit_amount` (zero unrecoverable commitment drift)!
    assert_eq!(token_balance(&svm, &vault_wsol), deposit_amount + stray_donation);
    let mut store = CompactWalletStore::new(POOL_ID, 0);
    let sub0 = svm
        .get_account(&derive_subtree_pda(&program_id, POOL_ID, 0, 0).0)
        .unwrap()
        .data;
    let memo0 = svm
        .get_account(&derive_memo_pda(&program_id, POOL_ID, 0, 0).0)
        .unwrap()
        .data;
    let found = store
        .ingest_lane_pages(&fvk, 0, &[(0, &sub0)], &[(0, &memo0)], &[])
        .unwrap();
    assert_eq!(found, 1);
    assert_eq!(store.notes[0].amount, deposit_amount);
    assert_eq!(store.notes[0].mint, WSOL_MINT);

    // Also verify `DEPOSIT_FLAG_NATIVE_SOL | DEPOSIT_FLAG_FEE_FROM_AMOUNT` with another stray donation!
    expect_ok(
        send_v1(
            &mut svm,
            &donor,
            &[],
            &[sys_ix::transfer(&donor.pubkey(), &vault_wsol, 333_333)],
            100_000,
        ),
        "second stray donation",
    );
    let sweeper = Keypair::new();
    let sweep_start = 15_000_000u64;
    svm.airdrop(&sweeper.pubkey(), sweep_start).unwrap();
    let per_note_fee = deterministic_note_rent_fee(
        2_000_000,
        svm.minimum_balance_for_rent_exemption(SUBTREE_PAGE_LEN),
        svm.minimum_balance_for_rent_exemption(SUBROOT_PAGE_LEN),
        svm.minimum_balance_for_rent_exemption(MEMO_PAGE_LEN),
    );
    let gross_sweep = sweep_start - 5_000;
    let net_sweep = gross_sweep - per_note_fee;
    let (tw2, bl2, memo2) =
        encrypt_note_memo(&alice.view_pk, [0xD3; 32], net_sweep, &WSOL_MINT).unwrap();
    expect_ok(
        send_v1(
            &mut svm,
            &sweeper,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                sweeper.pubkey(),
                POOL_ID,
                wsol_mint_id(),
                sweeper.pubkey(),
                vault_wsol,
                spl_token_id(),
                0,
                0,
                0,
                0,
                None,
                None,
                true,
                true,
                gross_sweep,
                derive_stealth_owner(alice.spend_pk, tw2),
                bl2,
                &memo2,
                &[],
            ))],
            200_000,
        ),
        "zero-dust sweep with stray donation",
    );
    assert_eq!(svm.get_account(&sweeper.pubkey()).map(|a| a.lamports).unwrap_or(0), 0);
    let sub0_after = svm
        .get_account(&derive_subtree_pda(&program_id, POOL_ID, 0, 0).0)
        .unwrap()
        .data;
    let memo0_after = svm
        .get_account(&derive_memo_pda(&program_id, POOL_ID, 0, 0).0)
        .unwrap()
        .data;
    let found2 = store
        .ingest_lane_pages(&fvk, 0, &[(0, &sub0_after)], &[(0, &memo0_after)], &[])
        .unwrap();
    assert_eq!(found2, 1);
    assert_eq!(store.notes[1].amount, net_sweep);
    println!("  [REGRESSION (c) PASSED] Stray pre-donated lamports on WSOL vault_ata preserve exact net_sol commitment");
}

// ----------------------------------------------------------------------------
// REGRESSION (d): UpdatePool (UpdateParams, 2-step ProposeAuthority / AcceptAuthority,
//                 RenounceAuthority, and renounce-while-paused rejected!)
// ----------------------------------------------------------------------------
#[test]
fn test_regression_d_update_pool_governance_and_renounce_while_paused_blocked() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let mut svm = new_svm(program_id, None, None);
    let auth1 = Keypair::new();
    let auth2 = Keypair::new();
    let rando = Keypair::new();
    for kp in [&auth1, &auth2, &rando] {
        svm.airdrop(&kp.pubkey(), 100_000_000_000).unwrap();
    }
    svm.warp_to_slot(104);
    bootstrap_pool(&mut svm, program_id, &auth1, 2);
    let (pool_pda, _) = derive_pool_pda(&program_id, POOL_ID);

    // 1. UpdateParams: non-authority rejected (6028); valid succeeds while keeping root_epoch_interval immutable!
    expect_err_code(
        send_v1(
            &mut svm,
            &rando,
            &[],
            &[to_svm_ix(&build_update_pool(
                program_id,
                rando.pubkey(),
                POOL_ID,
                UpdatePoolAction::UpdateParams {
                    note_rent_fee: 1_000_000,
                    nf_rent_fee: 250_000,
                },
            ))],
            100_000,
        ),
        6028,
        "non-authority UpdateParams",
    );
    expect_ok(
        send_v1(
            &mut svm,
            &auth1,
            &[],
            &[to_svm_ix(&build_update_pool_params(
                program_id,
                auth1.pubkey(),
                POOL_ID,
                1_111_111,
                222_222,
            ))],
            100_000,
        ),
        "valid UpdateParams keeping immutable root_epoch_interval",
    );
    let ps = PoolState::decode(&svm.get_account(&pool_pda).unwrap().data).unwrap();
    assert_eq!(ps.root_epoch_interval, ROOT_EPOCH_INTERVAL);
    assert_eq!(ps.note_rent_fee, 1_111_111);
    assert_eq!(ps.nf_rent_fee, 222_222);

    // 2. Two-step ProposeAuthority -> AcceptAuthority
    expect_ok(
        send_v1(
            &mut svm,
            &auth1,
            &[],
            &[to_svm_ix(&build_update_pool(
                program_id,
                auth1.pubkey(),
                POOL_ID,
                UpdatePoolAction::ProposeAuthority {
                    pending_authority: auth2.pubkey(),
                },
            ))],
            100_000,
        ),
        "ProposeAuthority(auth2)",
    );
    let ps2 = PoolState::decode(&svm.get_account(&pool_pda).unwrap().data).unwrap();
    assert_eq!(ps2.authority, auth1.pubkey().to_bytes());
    assert_eq!(ps2.pending_authority, auth2.pubkey().to_bytes());

    // Wrong signer AcceptAuthority rejected (6028)
    expect_err_code(
        send_v1(
            &mut svm,
            &rando,
            &[],
            &[to_svm_ix(&build_update_pool(
                program_id,
                rando.pubkey(),
                POOL_ID,
                UpdatePoolAction::AcceptAuthority,
            ))],
            100_000,
        ),
        6028,
        "wrong signer AcceptAuthority",
    );

    // auth2 accepts -> becomes authority and pending_authority clears to zero!
    expect_ok(
        send_v1(
            &mut svm,
            &auth2,
            &[],
            &[to_svm_ix(&build_update_pool(
                program_id,
                auth2.pubkey(),
                POOL_ID,
                UpdatePoolAction::AcceptAuthority,
            ))],
            100_000,
        ),
        "AcceptAuthority(auth2)",
    );
    let ps3 = PoolState::decode(&svm.get_account(&pool_pda).unwrap().data).unwrap();
    assert_eq!(ps3.authority, auth2.pubkey().to_bytes());
    assert_eq!(ps3.pending_authority, [0u8; 32]);

    // Old auth1 is now unauthorized (6028)
    expect_err_code(
        send_v1(
            &mut svm,
            &auth1,
            &[],
            &[to_svm_ix(&build_set_paused(program_id, auth1.pubkey(), POOL_ID, true))],
            100_000,
        ),
        6028,
        "old authority SetPaused rejected",
    );

    // 3. RenounceAuthority while paused MUST be rejected with Custom(6027) (PoolPaused)!
    expect_ok(
        send_v1(
            &mut svm,
            &auth2,
            &[],
            &[to_svm_ix(&build_set_paused(program_id, auth2.pubkey(), POOL_ID, true))],
            100_000,
        ),
        "auth2 SetPaused(true)",
    );
    expect_err_code(
        send_v1(
            &mut svm,
            &auth2,
            &[],
            &[to_svm_ix(&build_update_pool(
                program_id,
                auth2.pubkey(),
                POOL_ID,
                UpdatePoolAction::RenounceAuthority,
            ))],
            100_000,
        ),
        6027,
        "RenounceAuthority while paused MUST be blocked",
    );

    // Unpause -> RenounceAuthority succeeds -> authority = [0; 32], all admin ops permanently locked!
    expect_ok(
        send_v1(
            &mut svm,
            &auth2,
            &[],
            &[to_svm_ix(&build_set_paused(program_id, auth2.pubkey(), POOL_ID, false))],
            100_000,
        ),
        "auth2 SetPaused(false)",
    );
    expect_ok(
        send_v1(
            &mut svm,
            &auth2,
            &[],
            &[to_svm_ix(&build_update_pool(
                program_id,
                auth2.pubkey(),
                POOL_ID,
                UpdatePoolAction::RenounceAuthority,
            ))],
            100_000,
        ),
        "RenounceAuthority when unpaused",
    );
    let ps4 = PoolState::decode(&svm.get_account(&pool_pda).unwrap().data).unwrap();
    assert_eq!(ps4.authority, [0u8; 32]);
    assert_eq!(ps4.pending_authority, [0u8; 32]);

    expect_err_code(
        send_v1(
            &mut svm,
            &auth2,
            &[],
            &[to_svm_ix(&build_set_paused(program_id, auth2.pubkey(), POOL_ID, true))],
            100_000,
        ),
        6028,
        "SetPaused after renounce",
    );
    expect_err_code(
        send_v1(
            &mut svm,
            &auth2,
            &[],
            &[to_svm_ix(&build_init_lane(program_id, auth2.pubkey(), POOL_ID, 2))],
            250_000,
        ),
        6028,
        "InitLane after renounce",
    );
    expect_err_code(
        send_v1(
            &mut svm,
            &auth2,
            &[],
            &[to_svm_ix(&build_update_pool(
                program_id,
                auth2.pubkey(),
                POOL_ID,
                UpdatePoolAction::UpdateParams {
                    note_rent_fee: 0,
                    nf_rent_fee: 0,
                },
            ))],
            100_000,
        ),
        6028,
        "UpdateParams after renounce",
    );
    expect_err_code(
        send_v1(
            &mut svm,
            &auth2,
            &[],
            &[to_svm_ix(&build_update_pool(
                program_id,
                auth2.pubkey(),
                POOL_ID,
                UpdatePoolAction::AcceptAuthority,
            ))],
            100_000,
        ),
        6028,
        "AcceptAuthority after renounce MUST be rejected",
    );
    // Even if a renounced pool (`authority == [0; 32]`) somehow carried a stale
    // `pending_authority`, `AcceptAuthority` MUST still fail with `Unauthorized`.
    {
        let mut pool_acc = svm.get_account(&pool_pda).unwrap();
        pool_acc.data[PL_OFF_PENDING_AUTHORITY..PL_OFF_PENDING_AUTHORITY + 32]
            .copy_from_slice(&auth2.pubkey().to_bytes());
        svm.set_account(pool_pda, pool_acc).unwrap();
    }
    expect_err_code(
        send_v1(
            &mut svm,
            &auth2,
            &[],
            &[to_svm_ix(&build_update_pool(
                program_id,
                auth2.pubkey(),
                POOL_ID,
                UpdatePoolAction::AcceptAuthority,
            ))],
            100_000,
        ),
        6028,
        "AcceptAuthority on renounced pool with synthetic pending_authority MUST be rejected",
    );
    println!("  [REGRESSION (d) PASSED] UpdatePool params, root_epoch_interval immutability, 2-step authority transfer, renounce-while-paused, and renounced AcceptAuthority guards verified");
}

// ----------------------------------------------------------------------------
// REGRESSION (e) & (f): X25519 low-order points (`[0;32]` & order-8) AND
//                       BIP-350 Bech32m `aud1...` typo/mixed-case/bad-version
//                       PLUS 96-note `MemoPage` rollover boundary on-chain!
// ----------------------------------------------------------------------------
#[test]
fn test_regression_e_f_low_order_x25519_bech32m_and_96_note_memo_rollover() {
    // (e) X25519 low-order rejection
    let alice = AudrenKeys::from_seed(&[0xE1u8; 32]);
    let fvk = alice.full_viewing_key();
    let zero_epk = [0u8; 32];
    let order_8_epk: [u8; 32] = [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ];
    for low_epk in [&zero_epk, &order_8_epk] {
        assert!(encrypt_note_memo(low_epk, [0xE2; 32], 1_000, &WSOL_MINT).is_err());
        assert!(prepare_dynamic_swap_memo(low_epk, [0xE2; 32]).is_err());
        assert!(!check_memo_view_tag(&fvk, [0, 0], low_epk));
        assert!(try_decrypt_and_verify_memo_entry(
            &fvk,
            [0, 0],
            low_epk,
            &[0u8; MEMO_CT_LEN],
            &[0u8; 32]
        )
        .is_none());
    }

    // (f) Bech32m `aud1...` typo, mixed-case, and bad-version rejection
    let encoded = alice.address().encode().unwrap();
    assert_eq!(encoded.len(), 114);
    assert_eq!(AudrenAddress::decode(&encoded).unwrap(), alice.address());
    assert_eq!(
        AudrenAddress::decode(&encoded.to_ascii_uppercase()).unwrap(),
        alice.address()
    );
    let mut typo = encoded.as_bytes().to_vec();
    typo[42] = if typo[42] == b'z' { b'r' } else { b'z' };
    assert!(AudrenAddress::decode(&String::from_utf8(typo).unwrap()).is_err());
    let mut mixed = encoded.as_bytes().to_vec();
    mixed[5] = mixed[5].to_ascii_uppercase();
    assert!(AudrenAddress::decode(&String::from_utf8(mixed).unwrap()).is_err());
    assert!(AudrenAddress::decode("aud1invalidversion").is_err());

    // On-chain 96-note `MemoPage` rollover test (leaf 95 -> leaf 96 -> MemoPage 1)
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let mut svm = new_svm(program_id, None, None);
    let prover = AudrenProver::from_canonical_pk();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();
    svm.warp_to_slot(104);
    let vault_wsol = bootstrap_pool(&mut svm, program_id, &payer, 1);

    // Premature OpenPage(MEMO, 1) at next_leaf=0 must be rejected with PageSeqOutOfRange (6029)
    expect_err_code(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_open_page(
                program_id,
                payer.pubkey(),
                OPEN_PAGE_KIND_MEMO,
                POOL_ID,
                0,
                1,
                u64::MAX,
            ))],
            200_000,
        ),
        6029,
        "Premature OpenPage(MEMO, 1) at 0% occupancy must fail with 6029",
    );

    // Fill 95 deposits (leaves 0..95) into MemoPage 0; open MemoPage 1 once >= 90% full (i == 86)
    let mut first_tw = Fr::from(0u64);
    let mut first_bl = Fr::from(0u64);
    for i in 0u64..95u64 {
        if i == 86 {
            expect_ok(
                send_v1(
                    &mut svm,
                    &payer,
                    &[],
                    &[to_svm_ix(&build_open_page(
                        program_id,
                        payer.pubkey(),
                        OPEN_PAGE_KIND_MEMO,
                        POOL_ID,
                        0,
                        1,
                        u64::MAX,
                    ))],
                    200_000,
                ),
                "OpenPage(MEMO, 1) at >=90% occupancy",
            );
        }
        let mut eph = [0x11u8; 32];
        eph[0] = (i & 0xff) as u8;
        let (tw, bl, memo) =
            encrypt_note_memo(&alice.view_pk, eph, 1_000_000, &WSOL_MINT).unwrap();
        if i == 0 {
            first_tw = tw;
            first_bl = bl;
        }
        expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_deposit(
                    program_id,
                    payer.pubkey(),
                    POOL_ID,
                    wsol_mint_id(),
                    payer.pubkey(),
                    vault_wsol,
                    spl_token_id(),
                    0,
                    0,
                    0,
                    0,
                    None,
                    None,
                    true,
                    false,
                    1_000_000,
                    derive_stealth_owner(alice.spend_pk, tw),
                    bl,
                    &memo,
                    &[],
                ))],
                200_000,
            ),
            "fill MemoPage 0",
        );
    }
    let memo0_pda = derive_memo_pda(&program_id, POOL_ID, 0, 0).0;
    let memo1_pda = derive_memo_pda(&program_id, POOL_ID, 0, 1).0;
    assert_eq!(read_u16(&svm.get_account(&memo0_pda).unwrap().data, MM_OFF_COUNT), 95);
    assert_eq!(read_u16(&svm.get_account(&memo1_pda).unwrap().data, MM_OFF_COUNT), 0);

    // Execute a 2-output private Transact crossing leaf 95 -> leaf 96 immediately (zero checkpoint)!
    let plan = compute_page_rollovers(95, 2, 0, 1);
    assert_eq!(plan.out_memo_seq, 0);
    assert_eq!(plan.next_memo_seq, Some(1));

    let (path0, rk_m, ri_m, sr) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        0,
        0,
        alice.view_sk,
    )
    .unwrap();
    let asset_wsol = asset_id_for_mint(None);
    let (tw_a, bl_a, memo_a) =
        encrypt_note_memo(&alice.view_pk, [0x91; 32], 600_000, &WSOL_MINT).unwrap();
    let (tw_b, bl_b, memo_b) =
        encrypt_note_memo(&alice.view_pk, [0x92; 32], 400_000, &WSOL_MINT).unwrap();
    let mut memos_2 = Vec::with_capacity(212);
    memos_2.extend_from_slice(&memo_a);
    memos_2.extend_from_slice(&memo_b);
    let ctx_roll = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        0,
        0b011,
        ASSET_MODE_PRIVATE,
        false,
        None,
        None,
        &[0u8; 32],
        0,
        0,
        &memos_2,
    );
    let b_roll = prover.build_and_prove(
        sr,
        asset_wsol,
        Fr::from(0u64),
        0,
        0,
        ctx_roll,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: first_tw,
                asset_id: asset_wsol,
                amount: 1_000_000,
                blinding: first_bl,
                is_dummy: false,
                merkle_path: path0,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_wsol,
                amount: 0,
                blinding: Fr::from(5u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_a),
                asset_id: asset_wsol,
                amount: 600_000,
                blinding: bl_a,
            },
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_b),
                asset_id: asset_wsol,
                amount: 400_000,
                blinding: bl_b,
            },
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
        ],
        [0x93; 32],
    );
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                payer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_m,
                ri_m,
                0,
                plan.out_sub_seq,
                plan.out_root_seq,
                plan.out_memo_seq,
                plan.nf_page_seq,
                0b011,
                ASSET_MODE_PRIVATE,
                false,
                None,
                (plan.next_sub_seq, plan.next_memo_seq, plan.next_nf_seq),
                &b_roll.proof_192,
                &b_roll.nf0,
                &b_roll.nf1,
                &b_roll.cm0,
                &b_roll.cm1,
                &b_roll.cm2,
                0,
                0,
                payer.pubkey(),
                payer.pubkey(),
                &memos_2,
                &[],
            ))],
            350_000,
        ),
        "2-output Transact rollover across 96-note MemoPage boundary",
    );
    assert_eq!(
        read_u16(&svm.get_account(&memo0_pda).unwrap().data, MM_OFF_COUNT),
        MEMO_NOTES_PER_PAGE as u16
    );
    assert_eq!(read_u16(&svm.get_account(&memo1_pda).unwrap().data, MM_OFF_COUNT), 1);
    let _ = (OPEN_PAGE_KIND_SUBTREE, LaneTreeHeader::decode, SUBTREE_LEAVES);
    println!("  [REGRESSIONS (e), (f) & 96-note MemoPage rollover PASSED]");
}

// ----------------------------------------------------------------------------
// REGRESSION (g): v1.2.1 On-Chain Hardening Suite
//   (g1) Economy-mode `nf1 = SYSTEM_PROGRAM_ID` + Token-2022 `TransferHook` referencing
//        `SYSTEM_PROGRAM_ID` (verifies SYSTEM_PROGRAM_ID is NOT stripped when !has_nf1)
//   (g2) `recipient` / `relayer_fee_recipient` aliasing `nf0`, `nf1`, `vault_ata`, or
//        non-canonical `vault_auth`-owned token account rejected (Custom 6002)
//   (g3) `!unwrap_wsol` Token-2022 `TransferFee` + `relayer_fee` exact vault solvency delta
//        check AND `OpenPage(SUBROOT, 0)` idempotency
// ----------------------------------------------------------------------------
#[test]
fn test_regression_g_v121_security_hardening() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let hook_id = Keypair::new().pubkey();
    let mut svm = new_svm(program_id, None, Some(hook_id));
    let prover = AudrenProver::from_canonical_pk();
    let payer = Keypair::new();
    let relayer = Keypair::new();
    let recipient_wallet = Keypair::new();
    for kp in [&payer, &relayer, &recipient_wallet] {
        svm.airdrop(&kp.pubkey(), 200_000_000_000).unwrap();
    }
    svm.warp_to_slot(104);
    let vault_wsol = bootstrap_pool(&mut svm, program_id, &payer, 4);
    let (va, _) = derive_vault_auth_pda(&program_id, POOL_ID);
    let alice = AudrenKeys::from_seed(&[0xF1u8; 32]);

    // --- (g3-a) OpenPage(SUBROOT, 0) idempotency (`page_seq <= cur_seq` succeeds as no-op) ---
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_open_page(
                program_id,
                payer.pubkey(),
                OPEN_PAGE_KIND_SUBROOT,
                POOL_ID,
                0,
                0,
                0,
            ))],
            200_000,
        ),
        "OpenPage(SUBROOT, 0) idempotency",
    );

    // --- (g1) Economy-mode `nf1 = SYSTEM_PROGRAM_ID` with Token-2022 TransferHook referencing SYSTEM_PROGRAM_ID ---
    let hook_mint = create_t22_hook_mint(&mut svm, &payer, 6, hook_id);
    let (extra_meta_pda, _) =
        Address::find_program_address(&[b"extra-account-metas", hook_mint.as_ref()], &hook_id);
    let (hook_state_pda, _) =
        Address::find_program_address(&[b"hook_state", hook_mint.as_ref()], &hook_id);
    // Init 2-entry ExtraAccountMetaList: [0] hook_state_pda (wr), [1] SYSTEM_PROGRAM_ID (patched to ro)
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[Instruction {
                program_id: hook_id,
                accounts: vec![
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new_readonly(hook_mint, false),
                    AccountMeta::new(extra_meta_pda, false),
                    AccountMeta::new(hook_state_pda, false),
                    AccountMeta::new_readonly(sys_program_id(), false),
                    AccountMeta::new_readonly(sys_program_id(), false),
                ],
                data: vec![0u8, 1u8],
            }],
            200_000,
        ),
        "init 2-entry TransferHook extra metas with SYSTEM_PROGRAM_ID",
    );
    // Patch entry 1's `is_writable` byte (offset 85) from 1 -> 0 so Token-2022 expects readonly SYSTEM_PROGRAM_ID
    let mut meta_acc = svm.get_account(&extra_meta_pda).unwrap();
    assert_eq!(&meta_acc.data[52..84], sys_program_id().as_ref());
    meta_acc.data[85] = 0;
    svm.set_account(extra_meta_pda, meta_acc).unwrap();

    let payer_hk = create_canonical_ata(&mut svm, &payer, payer.pubkey(), hook_mint, token_2022_id());
    let vault_hk = create_canonical_ata(&mut svm, &payer, va, hook_mint, token_2022_id());
    let recip_hk = create_canonical_ata(&mut svm, &payer, recipient_wallet.pubkey(), hook_mint, token_2022_id());
    let relayer_hk = create_canonical_ata(&mut svm, &payer, relayer.pubkey(), hook_mint, token_2022_id());
    mint_to(&mut svm, &payer, token_2022_id(), hook_mint, payer_hk, 50_000_000);

    let hook_metas = vec![
        AudrenAccountMeta::readonly(extra_meta_pda, false),
        AudrenAccountMeta::writable(hook_state_pda, false),
        AudrenAccountMeta::readonly(sys_program_id(), false),
        AudrenAccountMeta::readonly(hook_id, false),
    ];
    let (tw_hk, bl_hk, memo_hk) =
        encrypt_note_memo(&alice.view_pk, [0xF2; 32], 40_000_000, &hook_mint.to_bytes()).unwrap();
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                hook_mint,
                payer_hk,
                vault_hk,
                token_2022_id(),
                0,
                0,
                0,
                0,
                None,
                None,
                false,
                false,
                40_000_000,
                derive_stealth_owner(alice.spend_pk, tw_hk),
                bl_hk,
                &memo_hk,
                &hook_metas,
            ))],
            250_000,
        ),
        "Deposit TransferHook mint referencing SYSTEM_PROGRAM_ID",
    );
    assert_eq!(read_u64(&svm.get_account(&hook_state_pda).unwrap().data, 0), 1);

    // Also deposit Native SOL (lane 1), Classic SPL USDC (lane 2), and Token-2022 TransferFee (lane 3)
    let usdc_mint = create_spl_mint(&mut svm, &payer, 6);
    let payer_usdc = create_canonical_ata(&mut svm, &payer, payer.pubkey(), usdc_mint, spl_token_id());
    let vault_usdc = create_canonical_ata(&mut svm, &payer, va, usdc_mint, spl_token_id());
    let recip_usdc = create_canonical_ata(&mut svm, &payer, recipient_wallet.pubkey(), usdc_mint, spl_token_id());
    let relayer_usdc = create_canonical_ata(&mut svm, &payer, relayer.pubkey(), usdc_mint, spl_token_id());
    let rogue_vault_usdc =
        create_non_canonical_token_acc(&mut svm, &payer, usdc_mint, va, spl_token_id(), &[]);
    mint_to(&mut svm, &payer, spl_token_id(), usdc_mint, payer_usdc, 100_000_000);

    let t22_fee_mint = create_t22_fee_mint(&mut svm, &payer, 6, 250, 50_000_000);
    let payer_t22 = create_canonical_ata(&mut svm, &payer, payer.pubkey(), t22_fee_mint, token_2022_id());
    let vault_t22 = create_canonical_ata(&mut svm, &payer, va, t22_fee_mint, token_2022_id());
    let recip_t22 = create_canonical_ata(&mut svm, &payer, recipient_wallet.pubkey(), t22_fee_mint, token_2022_id());
    let relayer_t22 = create_canonical_ata(&mut svm, &payer, relayer.pubkey(), t22_fee_mint, token_2022_id());
    mint_to(&mut svm, &payer, token_2022_id(), t22_fee_mint, payer_t22, 100_000_000);

    let (tw_sol, bl_sol, memo_sol) =
        encrypt_note_memo(&alice.view_pk, [0xF3; 32], 50_000_000, &WSOL_MINT).unwrap();
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                wsol_mint_id(),
                payer.pubkey(),
                vault_wsol,
                spl_token_id(),
                1,
                0,
                0,
                0,
                None,
                None,
                true,
                false,
                50_000_000,
                derive_stealth_owner(alice.spend_pk, tw_sol),
                bl_sol,
                &memo_sol,
                &[],
            ))],
            200_000,
        ),
        "Deposit Native SOL lane 1",
    );
    let (tw_u, bl_u, memo_u) =
        encrypt_note_memo(&alice.view_pk, [0xF4; 32], 50_000_000, &usdc_mint.to_bytes()).unwrap();
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                usdc_mint,
                payer_usdc,
                vault_usdc,
                spl_token_id(),
                2,
                0,
                0,
                0,
                None,
                None,
                false,
                false,
                50_000_000,
                derive_stealth_owner(alice.spend_pk, tw_u),
                bl_u,
                &memo_u,
                &[],
            ))],
            200_000,
        ),
        "Deposit SPL USDC lane 2",
    );
    // T22 2.5% TransferFee: 40_000_000 gross -> 39_000_000 net received by vault_t22!
    let (tw_t22, bl_t22, memo_t22) =
        encrypt_note_memo(&alice.view_pk, [0xF5; 32], 39_000_000, &t22_fee_mint.to_bytes()).unwrap();
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                t22_fee_mint,
                payer_t22,
                vault_t22,
                token_2022_id(),
                3,
                0,
                0,
                0,
                None,
                None,
                false,
                false,
                40_000_000,
                derive_stealth_owner(alice.spend_pk, tw_t22),
                bl_t22,
                &memo_t22,
                &[],
            ))],
            200_000,
        ),
        "Deposit T22 TransferFee lane 3",
    );
    assert_eq!(token_balance(&svm, &vault_t22), 39_000_000);

    // Execute economy-mode (`omit_nf1 = true` => `nf1_acc = SYSTEM_PROGRAM_ID`) Transact withdraw
    // on the TransferHook mint referencing SYSTEM_PROGRAM_ID (instant via GlobalRootHistory)!
    let (path_hk, rk_hk, ri_hk, sr) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        0,
        0,
        alice.view_sk,
    )
    .unwrap();
    let asset_hk = asset_id_for_mint(Some(&hook_mint));
    let (tw_chg, bl_chg, memo_chg) =
        encrypt_note_memo(&alice.view_pk, [0xF6; 32], 18_000_000, &hook_mint.to_bytes()).unwrap();
    let ctx_hk = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        0,
        0b001,
        ASSET_MODE_PUBLIC,
        false,
        Some(&recip_hk),
        Some(&relayer_hk),
        &fr_to_be_bytes(&asset_hk),
        20_000_000,
        2_000_000,
        &memo_chg,
    );
    let b_hk = prover.build_and_prove(
        sr,
        asset_hk,
        asset_hk,
        20_000_000,
        2_000_000,
        ctx_hk,
        true, // economy mode: nf1 = [0; 32] -> nf1_acc = SYSTEM_PROGRAM_ID!
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_hk,
                asset_id: asset_hk,
                amount: 40_000_000,
                blinding: bl_hk,
                is_dummy: false,
                merkle_path: path_hk,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_hk,
                amount: 0,
                blinding: Fr::from(7u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_chg),
                asset_id: asset_hk,
                amount: 18_000_000,
                blinding: bl_chg,
            },
            JoinSplitOutputWitness::dummy(asset_hk, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_hk, Fr::from(3u64)),
        ],
        [0xF7; 32],
    );
    assert_eq!(b_hk.nf1, [0u8; 32]);
    expect_ok(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_hk,
                ri_hk,
                0,
                0,
                0,
                0,
                0,
                0b001,
                ASSET_MODE_PUBLIC,
                false,
                Some((hook_mint, vault_hk, token_2022_id())),
                (None, None, None),
                &b_hk.proof_192,
                &b_hk.nf0,
                &b_hk.nf1,
                &b_hk.cm0,
                &b_hk.cm1,
                &b_hk.cm2,
                20_000_000,
                2_000_000,
                recip_hk,
                relayer_hk,
                &memo_chg,
                &hook_metas,
            ))],
            400_000,
        ),
        "Economy-mode Transact withdraw with TransferHook referencing SYSTEM_PROGRAM_ID",
    );
    assert_eq!(token_balance(&svm, &vault_hk), 18_000_000);
    assert_eq!(token_balance(&svm, &recip_hk), 20_000_000);
    assert_eq!(token_balance(&svm, &relayer_hk), 2_000_000);
    assert_eq!(
        read_u64(&svm.get_account(&hook_state_pda).unwrap().data, 0),
        3,
        "hook must execute on both recipient and relayer_fee transfers"
    );

    // Full-exit (`output_mask == 0`) TransferHook withdraw where unused page slots `[7..=9]`
    // (`subtree_acc`, `subroot_acc`, `memo_acc`) are passed as dummy `SYSTEM_PROGRAM_ID`:
    // gating those entries in `blocked` on `num_outputs > 0` preserves `SYSTEM_PROGRAM_ID`
    // for the TransferHook CPI instead of falsely stripping it!
    let (path_hk_fe, rk_hk_fe, ri_hk_fe, sr_hk_fe) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        0,
        1,
        alice.view_sk,
    )
    .unwrap();
    let ctx_hk_fe = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        0,
        0,
        ASSET_MODE_PUBLIC,
        false,
        Some(&recip_hk),
        None,
        &fr_to_be_bytes(&asset_hk),
        18_000_000,
        0,
        &[],
    );
    let b_hk_fe = prover.build_and_prove(
        sr_hk_fe,
        asset_hk,
        asset_hk,
        18_000_000,
        0,
        ctx_hk_fe,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_chg,
                asset_id: asset_hk,
                amount: 18_000_000,
                blinding: bl_chg,
                is_dummy: false,
                merkle_path: path_hk_fe,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_hk,
                amount: 0,
                blinding: Fr::from(8u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness::dummy(asset_hk, Fr::from(4u64)),
            JoinSplitOutputWitness::dummy(asset_hk, Fr::from(5u64)),
            JoinSplitOutputWitness::dummy(asset_hk, Fr::from(6u64)),
        ],
        [0xF8; 32],
    );
    let mut fe_hk_ix = to_svm_ix(&build_transact(
        program_id,
        relayer.pubkey(),
        POOL_ID,
        VK_ID_DEFAULT,
        rk_hk_fe,
        ri_hk_fe,
        0,
        0,
        0,
        0,
        0,
        0,
        ASSET_MODE_PUBLIC,
        false,
        Some((hook_mint, vault_hk, token_2022_id())),
        (None, None, None),
        &b_hk_fe.proof_192,
        &b_hk_fe.nf0,
        &b_hk_fe.nf1,
        &b_hk_fe.cm0,
        &b_hk_fe.cm1,
        &b_hk_fe.cm2,
        18_000_000,
        0,
        recip_hk,
        relayer_hk,
        &[],
        &hook_metas,
    ));
    // Place dummy `SYSTEM_PROGRAM_ID` in unused output page slots (7=subtree, 8=subroot, 9=memo)
    fe_hk_ix.accounts[7] = AccountMeta::new_readonly(sys_program_id(), false);
    fe_hk_ix.accounts[8] = AccountMeta::new_readonly(sys_program_id(), false);
    fe_hk_ix.accounts[9] = AccountMeta::new_readonly(sys_program_id(), false);
    expect_ok(
        send_v1(&mut svm, &relayer, &[], &[fe_hk_ix], 400_000),
        "Full-exit TransferHook withdraw with dummy SYSTEM_PROGRAM_ID page slots",
    );
    assert_eq!(token_balance(&svm, &vault_hk), 0);
    assert_eq!(token_balance(&svm, &recip_hk), 38_000_000);
    assert_eq!(
        read_u64(&svm.get_account(&hook_state_pda).unwrap().data, 0),
        4,
        "hook must execute on full-exit withdraw even with dummy SYSTEM_PROGRAM_ID page slots"
    );

    // --- (g2) Aliasing checks: recipient / relayer_fee_recipient aliasing nf0, nf1, vault_ata,
    //          or non-canonical vault_auth-owned token account MUST be rejected with Custom(6002)! ---
    let (path_sol, rk_sol, ri_sol, sr_sol) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        1,
        0,
        alice.view_sk,
    )
    .unwrap();
    let asset_wsol = asset_id_for_mint(None);
    // Compute the exact 2-nullifier PDAs (omit_nf1 = false) so we can alias them cleanly!
    let dummy_in1 = JoinSplitInputWitness {
        spend_sk: alice.spend_sk,
        tweak: Fr::from(0u64),
        asset_id: asset_wsol,
        amount: 0,
        blinding: Fr::from(99u64),
        is_dummy: true,
        merkle_path: MerklePath4Ary::default(),
    };
    let probe_circuit = audren_client::audren_circuits::joinsplit::JoinSplit4AryCircuit::new_with_options(
        sr_sol,
        asset_wsol,
        asset_wsol,
        45_000_000,
        5_000_000,
        Fr::from(0u64),
        false,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_sol,
                asset_id: asset_wsol,
                amount: 50_000_000,
                blinding: bl_sol,
                is_dummy: false,
                merkle_path: path_sol.clone(),
            },
            dummy_in1.clone(),
        ],
        [
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(1u64)),
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
        ],
    );
    let probe_pub = probe_circuit.public_inputs();
    let nf0_sol_pda = derive_nullifier_pda(&program_id, POOL_ID, &fr_to_be_bytes(&probe_pub.nullifiers[0])).0;
    let nf1_sol_pda = derive_nullifier_pda(&program_id, POOL_ID, &fr_to_be_bytes(&probe_pub.nullifiers[1])).0;

    for (label, rec_addr, fee_addr) in [
        ("unwrap recipient == nf0", nf0_sol_pda, relayer.pubkey()),
        ("unwrap recipient == nf1", nf1_sol_pda, relayer.pubkey()),
        ("unwrap fee_recipient == nf0", recipient_wallet.pubkey(), nf0_sol_pda),
        ("unwrap fee_recipient == nf1", recipient_wallet.pubkey(), nf1_sol_pda),
    ] {
        let ctx_alias = compute_transact_ctx_hash(
            &program_id,
            POOL_ID,
            VK_ID_DEFAULT,
            1,
            0,
            ASSET_MODE_PUBLIC,
            true,
            Some(&rec_addr),
            Some(&fee_addr),
            &fr_to_be_bytes(&asset_wsol),
            45_000_000,
            5_000_000,
            &[],
        );
        let b_alias = prover.build_and_prove(
            sr_sol,
            asset_wsol,
            asset_wsol,
            45_000_000,
            5_000_000,
            ctx_alias,
            false,
            [
                JoinSplitInputWitness {
                    spend_sk: alice.spend_sk,
                    tweak: tw_sol,
                    asset_id: asset_wsol,
                    amount: 50_000_000,
                    blinding: bl_sol,
                    is_dummy: false,
                    merkle_path: path_sol.clone(),
                },
                dummy_in1.clone(),
            ],
            [
                JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(1u64)),
                JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(2u64)),
                JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
            ],
            [0xF8; 32],
        );
        expect_err_code(
            send_v1(
                &mut svm,
                &relayer,
                &[],
                &[to_svm_ix(&build_transact(
                    program_id,
                    relayer.pubkey(),
                    POOL_ID,
                    VK_ID_DEFAULT,
                    rk_sol,
                    ri_sol,
                    1,
                    0,
                    0,
                    0,
                    0,
                    0,
                    ASSET_MODE_PUBLIC,
                    true,
                    Some((wsol_mint_id(), vault_wsol, spl_token_id())),
                    (None, None, None),
                    &b_alias.proof_192,
                    &b_alias.nf0,
                    &b_alias.nf1,
                    &b_alias.cm0,
                    &b_alias.cm1,
                    &b_alias.cm2,
                    45_000_000,
                    5_000_000,
                    rec_addr,
                    fee_addr,
                    &[],
                    &[],
                ))],
                400_000,
            ),
            6002,
            label,
        );
    }

    // SPL !unwrap_wsol aliasing checks: vault_ata & rogue vault_auth-owned token account rejected (6002)
    let (path_u, rk_u, ri_u, sr_u) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        2,
        0,
        alice.view_sk,
    )
    .unwrap();
    let asset_usdc = asset_id_for_mint(Some(&usdc_mint));
    for (label, rec_addr, fee_addr) in [
        ("SPL recipient == vault_ata", vault_usdc, relayer_usdc),
        ("SPL fee_recipient == vault_ata", recip_usdc, vault_usdc),
        ("SPL recipient owned by vault_auth", rogue_vault_usdc, relayer_usdc),
        ("SPL fee_recipient owned by vault_auth", recip_usdc, rogue_vault_usdc),
    ] {
        let ctx_spl = compute_transact_ctx_hash(
            &program_id,
            POOL_ID,
            VK_ID_DEFAULT,
            2,
            0,
            ASSET_MODE_PUBLIC,
            false,
            Some(&rec_addr),
            Some(&fee_addr),
            &fr_to_be_bytes(&asset_usdc),
            45_000_000,
            5_000_000,
            &[],
        );
        let b_spl = prover.build_and_prove(
            sr_u,
            asset_usdc,
            asset_usdc,
            45_000_000,
            5_000_000,
            ctx_spl,
            true,
            [
                JoinSplitInputWitness {
                    spend_sk: alice.spend_sk,
                    tweak: tw_u,
                    asset_id: asset_usdc,
                    amount: 50_000_000,
                    blinding: bl_u,
                    is_dummy: false,
                    merkle_path: path_u.clone(),
                },
                JoinSplitInputWitness {
                    spend_sk: alice.spend_sk,
                    tweak: Fr::from(0u64),
                    asset_id: asset_usdc,
                    amount: 0,
                    blinding: Fr::from(4u64),
                    is_dummy: true,
                    merkle_path: MerklePath4Ary::default(),
                },
            ],
            [
                JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(1u64)),
                JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(2u64)),
                JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(3u64)),
            ],
            [0xF9; 32],
        );
        expect_err_code(
            send_v1(
                &mut svm,
                &relayer,
                &[],
                &[to_svm_ix(&build_transact(
                    program_id,
                    relayer.pubkey(),
                    POOL_ID,
                    VK_ID_DEFAULT,
                    rk_u,
                    ri_u,
                    2,
                    0,
                    0,
                    0,
                    0,
                    0,
                    ASSET_MODE_PUBLIC,
                    false,
                    Some((usdc_mint, vault_usdc, spl_token_id())),
                    (None, None, None),
                    &b_spl.proof_192,
                    &b_spl.nf0,
                    &b_spl.nf1,
                    &b_spl.cm0,
                    &b_spl.cm1,
                    &b_spl.cm2,
                    45_000_000,
                    5_000_000,
                    rec_addr,
                    fee_addr,
                    &[],
                    &[],
                ))],
                400_000,
            ),
            6002,
            label,
        );
    }

    // --- (g3-b) !unwrap_wsol Token-2022 TransferFee + relayer_fee exact vault solvency delta ---
    let (path_t22, rk_t22, ri_t22, sr_t22) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        3,
        0,
        alice.view_sk,
    )
    .unwrap();
    let asset_t22 = asset_id_for_mint(Some(&t22_fee_mint));
    let ctx_t22 = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        3,
        0,
        ASSET_MODE_PUBLIC,
        false,
        Some(&recip_t22),
        Some(&relayer_t22),
        &fr_to_be_bytes(&asset_t22),
        35_000_000,
        4_000_000,
        &[],
    );
    let b_t22 = prover.build_and_prove(
        sr_t22,
        asset_t22,
        asset_t22,
        35_000_000,
        4_000_000,
        ctx_t22,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_t22,
                asset_id: asset_t22,
                amount: 39_000_000,
                blinding: bl_t22,
                is_dummy: false,
                merkle_path: path_t22,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_t22,
                amount: 0,
                blinding: Fr::from(6u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness::dummy(asset_t22, Fr::from(1u64)),
            JoinSplitOutputWitness::dummy(asset_t22, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_t22, Fr::from(3u64)),
        ],
        [0xFA; 32],
    );
    let vault_before = token_balance(&svm, &vault_t22);
    expect_ok(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_t22,
                ri_t22,
                3,
                0,
                0,
                0,
                0,
                0,
                ASSET_MODE_PUBLIC,
                false,
                Some((t22_fee_mint, vault_t22, token_2022_id())),
                (None, None, None),
                &b_t22.proof_192,
                &b_t22.nf0,
                &b_t22.nf1,
                &b_t22.cm0,
                &b_t22.cm1,
                &b_t22.cm2,
                35_000_000,
                4_000_000,
                recip_t22,
                relayer_t22,
                &[],
                &[],
            ))],
            400_000,
        ),
        "!unwrap_wsol Token-2022 TransferFee withdraw passes exact vault solvency delta",
    );
    let vault_after = token_balance(&svm, &vault_t22);
    assert_eq!(vault_before - vault_after, 39_000_000);
    // 2.5% Token-2022 TransferFee withheld on each transfer: 35M -> 34,125,000; 4M -> 3,900,000
    assert_eq!(token_balance(&svm, &recip_t22), 34_125_000);
    assert_eq!(token_balance(&svm, &relayer_t22), 3_900_000);
    println!("  [REGRESSION (g) PASSED] Economy TransferHook+SYSTEM_PROGRAM_ID, recipient/fee aliasing, and !unwrap_wsol solvency delta verified");
}

#[test]
fn litesvm_r1_frozen_escrow_ata_and_confidential_transfer_ext_blocked() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let router_id = Keypair::new().pubkey();
    let mut svm = new_svm(program_id, Some(router_id), None);
    let prover = AudrenProver::from_canonical_pk();

    let payer = Keypair::new();
    let relayer = Keypair::new();
    let attacker = Keypair::new();
    svm.airdrop(&payer.pubkey(), 20_000_000_000).unwrap();
    svm.airdrop(&relayer.pubkey(), 5_000_000_000).unwrap();
    svm.airdrop(&attacker.pubkey(), 1_000_000_000).unwrap();

    svm.warp_to_slot(104); // epoch 13
    let _vault_wsol = bootstrap_pool(&mut svm, program_id, &payer, 4);
    let alice = AudrenKeys::from_seed(&[0x59u8; 32]);
    let (va, _) = derive_vault_auth_pda(&program_id, POOL_ID);
    let (esc0, _) = derive_escrow_pda(&program_id, POOL_ID, 0);
    svm.airdrop(&esc0, 2_000_000).unwrap();

    // Setup honest mock DEX + input/output SPL mints
    let usdc_mint = create_spl_mint(&mut svm, &payer, 6);
    let out_mint = create_spl_mint(&mut svm, &payer, 6);
    let dex_pool = dex_pool_pda(&router_id);
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[dex_init_ix(router_id, payer.pubkey(), 10_000, 10_000_000_000)],
            200_000,
        ),
        "init mock router",
    );

    let vault_usdc = create_canonical_ata(&mut svm, &payer, va, usdc_mint, spl_token_id());
    let esc0_usdc = create_canonical_ata(&mut svm, &payer, esc0, usdc_mint, spl_token_id());
    let dex_usdc = create_canonical_ata(&mut svm, &payer, dex_pool, usdc_mint, spl_token_id());
    let payer_usdc = create_canonical_ata(&mut svm, &payer, payer.pubkey(), usdc_mint, spl_token_id());
    mint_to(&mut svm, &payer, spl_token_id(), usdc_mint, payer_usdc, 200_000_000);

    let vault_out = create_canonical_ata(&mut svm, &payer, va, out_mint, spl_token_id());
    let esc0_out = create_canonical_ata(&mut svm, &payer, esc0, out_mint, spl_token_id());
    let dex_out = create_canonical_ata(&mut svm, &payer, dex_pool, out_mint, spl_token_id());
    mint_to(&mut svm, &payer, spl_token_id(), out_mint, dex_out, 200_000_000);

    // Deposit 100M USDC on lane 0 (instantly included in GlobalRootHistory)
    let (tw_u, bl_u, memo_u) =
        encrypt_note_memo(&alice.view_pk, [0x61; 32], 100_000_000, &usdc_mint.to_bytes()).unwrap();
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                usdc_mint,
                payer_usdc,
                vault_usdc,
                spl_token_id(),
                0,
                0,
                0,
                0,
                None,
                None,
                false,
                false,
                100_000_000,
                derive_stealth_owner(alice.spend_pk, tw_u),
                bl_u,
                &memo_u,
                &[],
            ))],
            200_000,
        ),
        "deposit 100M USDC",
    );

    let (path_u, rk_r1, ri_r1, sr) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        0,
        0,
        alice.view_sk,
    )
    .unwrap();
    let asset_usdc = asset_id_for_mint(Some(&usdc_mint));
    let asset_out = asset_id_for_mint(Some(&out_mint));

    // =========================================================================
    // R1-P1: Frozen SPL Token accounts (`data[108] == 2`)
    // =========================================================================
    // Create a Classic SPL mint WITH a freeze_authority so we can genuinely freeze ATAs via SPL Token!
    let freezable_mint_kp = Keypair::new();
    let mint_rent = svm.minimum_balance_for_rent_exemption(Mint::LEN);
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[&freezable_mint_kp],
            &[
                sys_ix::create_account(
                    &payer.pubkey(),
                    &freezable_mint_kp.pubkey(),
                    mint_rent,
                    Mint::LEN as u64,
                    &spl_token_id(),
                ),
                token_ix::initialize_mint(
                    &spl_token_id(),
                    &freezable_mint_kp.pubkey(),
                    &payer.pubkey(),
                    Some(&payer.pubkey()),
                    6,
                )
                .unwrap(),
            ],
            200_000,
        ),
        "create freezable SPL mint",
    );
    let freezable_mint = freezable_mint_kp.pubkey();
    let esc0_frozen = create_canonical_ata(&mut svm, &payer, esc0, freezable_mint, spl_token_id());
    let va_frozen = create_canonical_ata(&mut svm, &payer, va, freezable_mint, spl_token_id());
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[
                token_ix::freeze_account(
                    &spl_token_id(),
                    &esc0_frozen,
                    &freezable_mint,
                    &payer.pubkey(),
                    &[],
                )
                .unwrap(),
                token_ix::freeze_account(
                    &spl_token_id(),
                    &va_frozen,
                    &freezable_mint,
                    &payer.pubkey(),
                    &[],
                )
                .unwrap(),
            ],
            200_000,
        ),
        "freeze esc0 and vault_auth ATAs",
    );
    assert_eq!(svm.get_account(&esc0_frozen).unwrap().data[108], 2);
    assert_eq!(svm.get_account(&va_frozen).unwrap().data[108], 2);
    let frozen_rent_before = svm.get_account(&esc0_frozen).unwrap().lamports;

    // R1-P1a: Mode 7 CloseAccount rent theft on frozen unrelated `escrow`-owned ATA -> Custom(6032)!
    let (dtw1, dbl1, dhead1, dmask1) = prepare_dynamic_swap_memo(&alice.view_pk, [0x62; 32]).unwrap();
    let ost1 = fr_to_be_bytes(&derive_stealth_owner(alice.spend_pk, dtw1));
    let obl1 = fr_to_be_bytes(&dbl1);
    let close_frozen_data = dex_swap_spl_to_spl_data(7, 50_000_000, 50_000_000, 6, 6);
    let close_frozen_accs = vec![
        AudrenAccountMeta::writable(esc0, false),
        AudrenAccountMeta::writable(esc0_usdc, false),
        AudrenAccountMeta::writable(dex_usdc, false),
        AudrenAccountMeta::writable(dex_pool, false),
        AudrenAccountMeta::writable(dex_out, false),
        AudrenAccountMeta::writable(esc0_out, false),
        AudrenAccountMeta::readonly(usdc_mint, false),
        AudrenAccountMeta::readonly(out_mint, false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::writable(esc0_frozen, false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::writable(attacker.pubkey(), false),
    ];
    let ctx_p1a = compute_exec_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        1,
        0,
        0,
        false,
        &fr_to_be_bytes(&asset_usdc),
        50_000_000,
        0,
        None,
        &fr_to_be_bytes(&asset_out),
        1,
        &router_id,
        &close_frozen_accs,
        &[],
        &ost1,
        &obl1,
        &dhead1,
        &dmask1,
        &close_frozen_data,
        &[],
    );
    let b_p1a = prover.build_and_prove(
        sr,
        asset_usdc,
        asset_usdc,
        50_000_000,
        0,
        ctx_p1a,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_u,
                asset_id: asset_usdc,
                amount: 100_000_000,
                blinding: bl_u,
                is_dummy: false,
                merkle_path: path_u.clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_usdc,
                amount: 0,
                blinding: Fr::from(10u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, Fr::from(11u64)),
                asset_id: asset_usdc,
                amount: 50_000_000,
                blinding: Fr::from(12u64),
            },
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(3u64)),
        ],
        [0x71; 32],
    );
    expect_err_code(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_exec_via_escrow(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_r1,
                ri_r1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                false,
                (usdc_mint, vault_usdc, esc0_usdc, spl_token_id()),
                (out_mint, vault_out, esc0_out, spl_token_id()),
                0,
                None,
                (None, None, None),
                &b_p1a.proof_192,
                &b_p1a.nf0,
                &b_p1a.nf1,
                &b_p1a.cm0,
                &b_p1a.cm1,
                &b_p1a.cm2,
                50_000_000,
                1,
                &ost1,
                &obl1,
                &dhead1,
                &dmask1,
                router_id,
                &close_frozen_data,
                close_frozen_accs,
                &[],
                &[],
            ))],
            400_000,
        ),
        6032,
        "R1-P1a: frozen unrelated escrow ATA passed to ExecViaEscrow CloseAccount must be rejected (6032)",
    );
    assert_eq!(
        svm.get_account(&esc0_frozen).unwrap().lamports,
        frozen_rent_before,
        "R1-P1a: frozen escrow ATA rent must remain intact"
    );

    // R1-P1b: Frozen `vault_auth`-owned ATA passed in `router_accounts` -> Custom(6021)!
    let honest_data = dex_swap_spl_to_spl_data(0, 50_000_000, 50_000_000, 6, 6);
    let frozen_va_accs = vec![
        AudrenAccountMeta::writable(esc0, false),
        AudrenAccountMeta::writable(esc0_usdc, false),
        AudrenAccountMeta::writable(dex_usdc, false),
        AudrenAccountMeta::writable(dex_pool, false),
        AudrenAccountMeta::writable(dex_out, false),
        AudrenAccountMeta::writable(esc0_out, false),
        AudrenAccountMeta::readonly(usdc_mint, false),
        AudrenAccountMeta::readonly(out_mint, false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::readonly(va_frozen, false),
    ];
    let ctx_p1b = compute_exec_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        1,
        0,
        0,
        false,
        &fr_to_be_bytes(&asset_usdc),
        50_000_000,
        0,
        None,
        &fr_to_be_bytes(&asset_out),
        1,
        &router_id,
        &frozen_va_accs,
        &[],
        &ost1,
        &obl1,
        &dhead1,
        &dmask1,
        &honest_data,
        &[],
    );
    let b_p1b = prover.build_and_prove(
        sr,
        asset_usdc,
        asset_usdc,
        50_000_000,
        0,
        ctx_p1b,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_u,
                asset_id: asset_usdc,
                amount: 100_000_000,
                blinding: bl_u,
                is_dummy: false,
                merkle_path: path_u.clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_usdc,
                amount: 0,
                blinding: Fr::from(10u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, Fr::from(11u64)),
                asset_id: asset_usdc,
                amount: 50_000_000,
                blinding: Fr::from(12u64),
            },
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(3u64)),
        ],
        [0x72; 32],
    );
    expect_err_code(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_exec_via_escrow(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_r1,
                ri_r1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                false,
                (usdc_mint, vault_usdc, esc0_usdc, spl_token_id()),
                (out_mint, vault_out, esc0_out, spl_token_id()),
                0,
                None,
                (None, None, None),
                &b_p1b.proof_192,
                &b_p1b.nf0,
                &b_p1b.nf1,
                &b_p1b.cm0,
                &b_p1b.cm1,
                &b_p1b.cm2,
                50_000_000,
                1,
                &ost1,
                &obl1,
                &dhead1,
                &dmask1,
                router_id,
                &honest_data,
                frozen_va_accs,
                &[],
                &[],
            ))],
            400_000,
        ),
        6021,
        "R1-P1b: frozen vault_auth-owned ATA in router_accounts must be rejected (6021)",
    );

    // =========================================================================
    // Audit Hardening: Non-in/out watched escrow ATA balance & lamport guards
    // =========================================================================
    // Mode 13: Router tries to sweep unsolicited tokens from an unrelated third-party escrow ATA -> Custom(6032)!
    let other_mint = create_spl_mint(&mut svm, &payer, 6);
    let esc0_other = create_canonical_ata(&mut svm, &payer, esc0, other_mint, spl_token_id());
    let attacker_other =
        create_canonical_ata(&mut svm, &payer, attacker.pubkey(), other_mint, spl_token_id());
    mint_to(&mut svm, &payer, spl_token_id(), other_mint, esc0_other, 50_000);
    let sweep_other_data = dex_swap_spl_to_spl_data(13, 50_000_000, 50_000_000, 6, 6);
    let sweep_other_accs = vec![
        AudrenAccountMeta::writable(esc0, false),
        AudrenAccountMeta::writable(esc0_usdc, false),
        AudrenAccountMeta::writable(dex_usdc, false),
        AudrenAccountMeta::writable(dex_pool, false),
        AudrenAccountMeta::writable(dex_out, false),
        AudrenAccountMeta::writable(esc0_out, false),
        AudrenAccountMeta::readonly(usdc_mint, false),
        AudrenAccountMeta::readonly(out_mint, false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::writable(esc0_other, false),
        AudrenAccountMeta::readonly(other_mint, false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::writable(attacker_other, false),
    ];
    let ctx_m13 = compute_exec_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        1,
        0,
        0,
        false,
        &fr_to_be_bytes(&asset_usdc),
        50_000_000,
        0,
        None,
        &fr_to_be_bytes(&asset_out),
        1,
        &router_id,
        &sweep_other_accs,
        &[],
        &ost1,
        &obl1,
        &dhead1,
        &dmask1,
        &sweep_other_data,
        &[],
    );
    let b_m13 = prover.build_and_prove(
        sr,
        asset_usdc,
        asset_usdc,
        50_000_000,
        0,
        ctx_m13,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_u,
                asset_id: asset_usdc,
                amount: 100_000_000,
                blinding: bl_u,
                is_dummy: false,
                merkle_path: path_u.clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_usdc,
                amount: 0,
                blinding: Fr::from(10u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, Fr::from(11u64)),
                asset_id: asset_usdc,
                amount: 50_000_000,
                blinding: Fr::from(12u64),
            },
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(3u64)),
        ],
        [0x73; 32],
    );
    expect_err_code(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_exec_via_escrow(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_r1,
                ri_r1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                false,
                (usdc_mint, vault_usdc, esc0_usdc, spl_token_id()),
                (out_mint, vault_out, esc0_out, spl_token_id()),
                0,
                None,
                (None, None, None),
                &b_m13.proof_192,
                &b_m13.nf0,
                &b_m13.nf1,
                &b_m13.cm0,
                &b_m13.cm1,
                &b_m13.cm2,
                50_000_000,
                1,
                &ost1,
                &obl1,
                &dhead1,
                &dmask1,
                router_id,
                &sweep_other_data,
                sweep_other_accs,
                &[],
                &[],
            ))],
            400_000,
        ),
        6032,
        "Mode 13: router sweep of unrelated third-party escrow ATA balance MUST be rejected (6032)",
    );
    assert_eq!(token_balance(&svm, &esc0_other), 50_000);

    // Mode 14: Router closes + cleanly recreates an empty unrelated escrow ATA to skim excess
    //          lamports (owner/mint/amount/len stay identical -> caught ONLY by lamport guard!)
    let skim_mint = create_spl_mint(&mut svm, &payer, 6);
    let esc0_skim = create_canonical_ata(&mut svm, &payer, esc0, skim_mint, spl_token_id());
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[
                sys_ix::transfer(&payer.pubkey(), &esc0_skim, 100_000),
                sys_ix::transfer(&payer.pubkey(), &esc0, 3_000_000),
            ],
            100_000,
        ),
        "fund excess lamports on esc0_skim and rent float on esc0",
    );
    let skim_lamports_before = svm.get_account(&esc0_skim).unwrap().lamports;
    let skim_data = dex_swap_spl_to_spl_data(14, 50_000_000, 50_000_000, 6, 6);
    let skim_accs = vec![
        AudrenAccountMeta::writable(esc0, false),
        AudrenAccountMeta::writable(esc0_usdc, false),
        AudrenAccountMeta::writable(dex_usdc, false),
        AudrenAccountMeta::writable(dex_pool, false),
        AudrenAccountMeta::writable(dex_out, false),
        AudrenAccountMeta::writable(esc0_out, false),
        AudrenAccountMeta::readonly(usdc_mint, false),
        AudrenAccountMeta::readonly(out_mint, false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::writable(esc0_skim, false),
        AudrenAccountMeta::readonly(skim_mint, false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::writable(attacker.pubkey(), false),
        AudrenAccountMeta::readonly(sys_program_id(), false),
        AudrenAccountMeta::readonly(ata_program_id(), false),
    ];
    let ctx_m14 = compute_exec_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        1,
        0,
        0,
        false,
        &fr_to_be_bytes(&asset_usdc),
        50_000_000,
        0,
        None,
        &fr_to_be_bytes(&asset_out),
        1,
        &router_id,
        &skim_accs,
        &[],
        &ost1,
        &obl1,
        &dhead1,
        &dmask1,
        &skim_data,
        &[],
    );
    let b_m14 = prover.build_and_prove(
        sr,
        asset_usdc,
        asset_usdc,
        50_000_000,
        0,
        ctx_m14,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_u,
                asset_id: asset_usdc,
                amount: 100_000_000,
                blinding: bl_u,
                is_dummy: false,
                merkle_path: path_u.clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_usdc,
                amount: 0,
                blinding: Fr::from(10u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, Fr::from(11u64)),
                asset_id: asset_usdc,
                amount: 50_000_000,
                blinding: Fr::from(12u64),
            },
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(3u64)),
        ],
        [0x74; 32],
    );
    expect_err_code(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_exec_via_escrow(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_r1,
                ri_r1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                false,
                (usdc_mint, vault_usdc, esc0_usdc, spl_token_id()),
                (out_mint, vault_out, esc0_out, spl_token_id()),
                0,
                None,
                (None, None, None),
                &b_m14.proof_192,
                &b_m14.nf0,
                &b_m14.nf1,
                &b_m14.cm0,
                &b_m14.cm1,
                &b_m14.cm2,
                50_000_000,
                1,
                &ost1,
                &obl1,
                &dhead1,
                &dmask1,
                router_id,
                &skim_data,
                skim_accs,
                &[],
                &[],
            ))],
            400_000,
        ),
        6032,
        "Mode 14: close+recreate excess-lamport skim on watched escrow ATA MUST be rejected (6032)",
    );
    assert_eq!(svm.get_account(&esc0_skim).unwrap().lamports, skim_lamports_before);

    // =========================================================================
    // R1-P2: Token-2022 `ConfidentialTransferAccount` (`TLV 5`) on escrow & vault ATAs
    // =========================================================================
    let ct_mint_kp = Keypair::new();
    let ct_mint_rent = svm.minimum_balance_for_rent_exemption(Mint::LEN);
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[&ct_mint_kp],
            &[
                sys_ix::create_account(
                    &payer.pubkey(),
                    &ct_mint_kp.pubkey(),
                    ct_mint_rent,
                    Mint::LEN as u64,
                    &token_2022_id(),
                ),
                token_ix::initialize_mint(
                    &token_2022_id(),
                    &ct_mint_kp.pubkey(),
                    &payer.pubkey(),
                    None,
                    6,
                )
                .unwrap(),
            ],
            200_000,
        ),
        "create Token-2022 mint for ConfidentialTransferAccount test",
    );
    let ct_mint = ct_mint_kp.pubkey();
    let payer_ct = create_canonical_ata(&mut svm, &payer, payer.pubkey(), ct_mint, token_2022_id());
    let vault_ct = create_canonical_ata(&mut svm, &payer, va, ct_mint, token_2022_id());
    let esc0_ct = create_canonical_ata(&mut svm, &payer, esc0, ct_mint, token_2022_id());
    mint_to(&mut svm, &payer, token_2022_id(), ct_mint, payer_ct, 100_000_000);

    let attach_ct_ext = |svm: &mut LiteSVM, addr: Address| {
        let mut acc = svm.get_account(&addr).unwrap();
        // Token-2022 Account base (165 B) + AccountType::Account (1 B = 2) + TLV(type=5, len=295)
        let mut ext_data = Vec::with_capacity(166 + 4 + 295);
        ext_data.extend_from_slice(&acc.data[..165]);
        ext_data.push(2u8); // AccountType::Account
        ext_data.extend_from_slice(&5u16.to_le_bytes()); // ConfidentialTransferAccount
        ext_data.extend_from_slice(&295u16.to_le_bytes());
        ext_data.extend_from_slice(&[0u8; 295]); // allow_non_confidential_credits = 0 at offset 262
        acc.lamports = svm.minimum_balance_for_rent_exemption(ext_data.len());
        acc.data = ext_data;
        svm.set_account(addr, acc).unwrap();
    };
    attach_ct_ext(&mut svm, esc0_ct);

    // R1-P2a: Canonical `escrow_out_ata` carrying TLV 5 (`ConfidentialTransferAccount`) -> Custom(6020)!
    let asset_ct = asset_id_for_mint(Some(&ct_mint));
    let ct_out_accs = vec![
        AudrenAccountMeta::writable(esc0, false),
        AudrenAccountMeta::writable(esc0_usdc, false),
        AudrenAccountMeta::writable(dex_usdc, false),
        AudrenAccountMeta::writable(dex_pool, false),
        AudrenAccountMeta::writable(dex_out, false),
        AudrenAccountMeta::writable(esc0_ct, false),
        AudrenAccountMeta::readonly(usdc_mint, false),
        AudrenAccountMeta::readonly(ct_mint, false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::readonly(token_2022_id(), false),
    ];
    let ctx_p2a = compute_exec_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        1,
        0,
        0,
        false,
        &fr_to_be_bytes(&asset_usdc),
        50_000_000,
        0,
        None,
        &fr_to_be_bytes(&asset_ct),
        1,
        &router_id,
        &ct_out_accs,
        &[],
        &ost1,
        &obl1,
        &dhead1,
        &dmask1,
        &honest_data,
        &[],
    );
    let b_p2a = prover.build_and_prove(
        sr,
        asset_usdc,
        asset_usdc,
        50_000_000,
        0,
        ctx_p2a,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_u,
                asset_id: asset_usdc,
                amount: 100_000_000,
                blinding: bl_u,
                is_dummy: false,
                merkle_path: path_u.clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_usdc,
                amount: 0,
                blinding: Fr::from(10u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, Fr::from(11u64)),
                asset_id: asset_usdc,
                amount: 50_000_000,
                blinding: Fr::from(12u64),
            },
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(3u64)),
        ],
        [0x73; 32],
    );
    expect_err_code(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_exec_via_escrow(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_r1,
                ri_r1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                false,
                (usdc_mint, vault_usdc, esc0_usdc, spl_token_id()),
                (ct_mint, vault_ct, esc0_ct, token_2022_id()),
                0,
                None,
                (None, None, None),
                &b_p2a.proof_192,
                &b_p2a.nf0,
                &b_p2a.nf1,
                &b_p2a.cm0,
                &b_p2a.cm1,
                &b_p2a.cm2,
                50_000_000,
                1,
                &ost1,
                &obl1,
                &dhead1,
                &dmask1,
                router_id,
                &honest_data,
                ct_out_accs,
                &[],
                &[],
            ))],
            400_000,
        ),
        6020,
        "R1-P2a: canonical escrow_out_ata with ConfidentialTransferAccount (TLV 5) must be rejected (6020)",
    );

    // R1-P2b: Unrelated writable `escrow`-owned ATA carrying TLV 5 in `router_accounts` -> Custom(6032)!
    let ct_router_accs = vec![
        AudrenAccountMeta::writable(esc0, false),
        AudrenAccountMeta::writable(esc0_usdc, false),
        AudrenAccountMeta::writable(dex_usdc, false),
        AudrenAccountMeta::writable(dex_pool, false),
        AudrenAccountMeta::writable(dex_out, false),
        AudrenAccountMeta::writable(esc0_out, false),
        AudrenAccountMeta::readonly(usdc_mint, false),
        AudrenAccountMeta::readonly(out_mint, false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::writable(esc0_ct, false),
    ];
    let ctx_p2b = compute_exec_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        1,
        0,
        0,
        false,
        &fr_to_be_bytes(&asset_usdc),
        50_000_000,
        0,
        None,
        &fr_to_be_bytes(&asset_out),
        1,
        &router_id,
        &ct_router_accs,
        &[],
        &ost1,
        &obl1,
        &dhead1,
        &dmask1,
        &honest_data,
        &[],
    );
    let b_p2b = prover.build_and_prove(
        sr,
        asset_usdc,
        asset_usdc,
        50_000_000,
        0,
        ctx_p2b,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_u,
                asset_id: asset_usdc,
                amount: 100_000_000,
                blinding: bl_u,
                is_dummy: false,
                merkle_path: path_u.clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_usdc,
                amount: 0,
                blinding: Fr::from(10u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, Fr::from(11u64)),
                asset_id: asset_usdc,
                amount: 50_000_000,
                blinding: Fr::from(12u64),
            },
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(3u64)),
        ],
        [0x74; 32],
    );
    expect_err_code(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_exec_via_escrow(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_r1,
                ri_r1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                false,
                (usdc_mint, vault_usdc, esc0_usdc, spl_token_id()),
                (out_mint, vault_out, esc0_out, spl_token_id()),
                0,
                None,
                (None, None, None),
                &b_p2b.proof_192,
                &b_p2b.nf0,
                &b_p2b.nf1,
                &b_p2b.cm0,
                &b_p2b.cm1,
                &b_p2b.cm2,
                50_000_000,
                1,
                &ost1,
                &obl1,
                &dhead1,
                &dmask1,
                router_id,
                &honest_data,
                ct_router_accs,
                &[],
                &[],
            ))],
            400_000,
        ),
        6032,
        "R1-P2b: writable escrow ATA with ConfidentialTransferAccount (TLV 5) in router_accounts must be rejected (6032)",
    );

    // R1-P2c: Canonical `vault_ata` carrying TLV 5 (`ConfidentialTransferAccount`) on Deposit -> Custom(6020)!
    attach_ct_ext(&mut svm, vault_ct);
    let (tw_ct, bl_ct, memo_ct) =
        encrypt_note_memo(&alice.view_pk, [0x63; 32], 10_000_000, &ct_mint.to_bytes()).unwrap();
    expect_err_code(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                ct_mint,
                payer_ct,
                vault_ct,
                token_2022_id(),
                1,
                0,
                0,
                0,
                None,
                None,
                false,
                false,
                10_000_000,
                derive_stealth_owner(alice.spend_pk, tw_ct),
                bl_ct,
                &memo_ct,
                &[],
            ))],
            200_000,
        ),
        6020,
        "R1-P2c: Deposit into vault_ata carrying ConfidentialTransferAccount (TLV 5) must be rejected (6020)",
    );

    println!("  [REGRESSION R1-P1 & R1-P2 PASSED] Frozen escrow/vault ATAs & Token-2022 ConfidentialTransferAccount (TLV 5) blocked on-chain");

    // =========================================================================
    // R2-P1: ElGamal Registry program (`ELGAMAL_REGISTRY_PROGRAM_ID`) blocked
    //        as `router_prog` (6030), inside `router_accounts` (6021), and as
    //        owner of any account in `router_accounts` (6021).
    // =========================================================================
    let elgamal_reg_id = Address::new_from_array(audren_core::ELGAMAL_REGISTRY_PROGRAM_ID);
    // Register an executable program account at `elgamal_reg_id` so the explicit
    // denylist (not merely `!router_prog.executable()`) is exercised.
    let reg_prog_acc = svm.get_account(&router_id).unwrap();
    svm.set_account(elgamal_reg_id, reg_prog_acc).unwrap();

    let elgamal_reg_pda = Keypair::new().pubkey();
    let mut reg_pda_acc = svm.get_account(&esc0_usdc).unwrap();
    reg_pda_acc.owner = elgamal_reg_id;
    reg_pda_acc.data = vec![0u8; 64];
    reg_pda_acc.executable = false;
    svm.set_account(elgamal_reg_pda, reg_pda_acc).unwrap();

    let base_honest_accs = vec![
        AudrenAccountMeta::writable(esc0, false),
        AudrenAccountMeta::writable(esc0_usdc, false),
        AudrenAccountMeta::writable(dex_usdc, false),
        AudrenAccountMeta::writable(dex_pool, false),
        AudrenAccountMeta::writable(dex_out, false),
        AudrenAccountMeta::writable(esc0_out, false),
        AudrenAccountMeta::readonly(usdc_mint, false),
        AudrenAccountMeta::readonly(out_mint, false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
    ];

    // R2-P1a: `router_prog == ELGAMAL_REGISTRY_PROGRAM_ID` -> Custom(6030) (`InvalidTargetProgram`)
    let ctx_r2_p1a = compute_exec_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        1,
        0,
        0,
        false,
        &fr_to_be_bytes(&asset_usdc),
        50_000_000,
        0,
        None,
        &fr_to_be_bytes(&asset_out),
        1,
        &elgamal_reg_id,
        &base_honest_accs,
        &[],
        &ost1,
        &obl1,
        &dhead1,
        &dmask1,
        &honest_data,
        &[],
    );
    let b_r2_p1a = prover.build_and_prove(
        sr,
        asset_usdc,
        asset_usdc,
        50_000_000,
        0,
        ctx_r2_p1a,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_u,
                asset_id: asset_usdc,
                amount: 100_000_000,
                blinding: bl_u,
                is_dummy: false,
                merkle_path: path_u.clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_usdc,
                amount: 0,
                blinding: Fr::from(10u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, Fr::from(11u64)),
                asset_id: asset_usdc,
                amount: 50_000_000,
                blinding: Fr::from(12u64),
            },
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(3u64)),
        ],
        [0x75; 32],
    );
    expect_err_code(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_exec_via_escrow(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_r1,
                ri_r1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                false,
                (usdc_mint, vault_usdc, esc0_usdc, spl_token_id()),
                (out_mint, vault_out, esc0_out, spl_token_id()),
                0,
                None,
                (None, None, None),
                &b_r2_p1a.proof_192,
                &b_r2_p1a.nf0,
                &b_r2_p1a.nf1,
                &b_r2_p1a.cm0,
                &b_r2_p1a.cm1,
                &b_r2_p1a.cm2,
                50_000_000,
                1,
                &ost1,
                &obl1,
                &dhead1,
                &dmask1,
                elgamal_reg_id,
                &honest_data,
                base_honest_accs.clone(),
                &[],
                &[],
            ))],
            400_000,
        ),
        6030,
        "R2-P1a: ExecViaEscrow with ELGAMAL_REGISTRY_PROGRAM_ID as router_prog must be rejected (6030)",
    );

    // R2-P1b: `ELGAMAL_REGISTRY_PROGRAM_ID` inside `router_accounts` -> Custom(6021) (`ForbiddenRouterAccount`)
    let mut reg_in_accs = base_honest_accs.clone();
    reg_in_accs.push(AudrenAccountMeta::readonly(elgamal_reg_id, false));
    let ctx_r2_p1b = compute_exec_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        1,
        0,
        0,
        false,
        &fr_to_be_bytes(&asset_usdc),
        50_000_000,
        0,
        None,
        &fr_to_be_bytes(&asset_out),
        1,
        &router_id,
        &reg_in_accs,
        &[],
        &ost1,
        &obl1,
        &dhead1,
        &dmask1,
        &honest_data,
        &[],
    );
    let b_r2_p1b = prover.build_and_prove(
        sr,
        asset_usdc,
        asset_usdc,
        50_000_000,
        0,
        ctx_r2_p1b,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_u,
                asset_id: asset_usdc,
                amount: 100_000_000,
                blinding: bl_u,
                is_dummy: false,
                merkle_path: path_u.clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_usdc,
                amount: 0,
                blinding: Fr::from(10u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, Fr::from(11u64)),
                asset_id: asset_usdc,
                amount: 50_000_000,
                blinding: Fr::from(12u64),
            },
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(3u64)),
        ],
        [0x76; 32],
    );
    expect_err_code(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_exec_via_escrow(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_r1,
                ri_r1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                false,
                (usdc_mint, vault_usdc, esc0_usdc, spl_token_id()),
                (out_mint, vault_out, esc0_out, spl_token_id()),
                0,
                None,
                (None, None, None),
                &b_r2_p1b.proof_192,
                &b_r2_p1b.nf0,
                &b_r2_p1b.nf1,
                &b_r2_p1b.cm0,
                &b_r2_p1b.cm1,
                &b_r2_p1b.cm2,
                50_000_000,
                1,
                &ost1,
                &obl1,
                &dhead1,
                &dmask1,
                router_id,
                &honest_data,
                reg_in_accs,
                &[],
                &[],
            ))],
            400_000,
        ),
        6021,
        "R2-P1b: ELGAMAL_REGISTRY_PROGRAM_ID inside router_accounts must be rejected (6021)",
    );

    // R2-P1c: Account owned by `ELGAMAL_REGISTRY_PROGRAM_ID` inside `router_accounts` -> Custom(6021)
    let mut reg_pda_accs = base_honest_accs;
    reg_pda_accs.push(AudrenAccountMeta::writable(elgamal_reg_pda, false));
    let ctx_r2_p1c = compute_exec_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        1,
        0,
        0,
        false,
        &fr_to_be_bytes(&asset_usdc),
        50_000_000,
        0,
        None,
        &fr_to_be_bytes(&asset_out),
        1,
        &router_id,
        &reg_pda_accs,
        &[],
        &ost1,
        &obl1,
        &dhead1,
        &dmask1,
        &honest_data,
        &[],
    );
    let b_r2_p1c = prover.build_and_prove(
        sr,
        asset_usdc,
        asset_usdc,
        50_000_000,
        0,
        ctx_r2_p1c,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_u,
                asset_id: asset_usdc,
                amount: 100_000_000,
                blinding: bl_u,
                is_dummy: false,
                merkle_path: path_u,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_usdc,
                amount: 0,
                blinding: Fr::from(10u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, Fr::from(11u64)),
                asset_id: asset_usdc,
                amount: 50_000_000,
                blinding: Fr::from(12u64),
            },
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(3u64)),
        ],
        [0x77; 32],
    );
    expect_err_code(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_exec_via_escrow(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_r1,
                ri_r1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                false,
                (usdc_mint, vault_usdc, esc0_usdc, spl_token_id()),
                (out_mint, vault_out, esc0_out, spl_token_id()),
                0,
                None,
                (None, None, None),
                &b_r2_p1c.proof_192,
                &b_r2_p1c.nf0,
                &b_r2_p1c.nf1,
                &b_r2_p1c.cm0,
                &b_r2_p1c.cm1,
                &b_r2_p1c.cm2,
                50_000_000,
                1,
                &ost1,
                &obl1,
                &dhead1,
                &dmask1,
                router_id,
                &honest_data,
                reg_pda_accs,
                &[],
                &[],
            ))],
            400_000,
        ),
        6021,
        "R2-P1c: account owned by ELGAMAL_REGISTRY_PROGRAM_ID inside router_accounts must be rejected (6021)",
    );

    println!("  [REGRESSION R2-P1 PASSED] ElGamal Registry program & owned PDAs blocked in ExecViaEscrow (6030 / 6021)");
}

// ----------------------------------------------------------------------------
// V1.3.0 TEST A: Instant spendability, slot_ring 128-entry wrap under >130-slot
//                deposit spam, epoch_ring survival, error codes 6007/6008, and
//                zero wall-clock idle expiry (+500_000 idle slots)
// ----------------------------------------------------------------------------
#[test]
fn test_v130_slot_ring_wrap_epoch_ring_survival_and_zero_idle_expiry() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let mut svm = new_svm(program_id, None, None);
    let prover = AudrenProver::from_canonical_pk();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();
    svm.warp_to_slot(100);
    let vault_wsol = bootstrap_pool(&mut svm, program_id, &payer, 4);
    let (roots_pda, _) = derive_roots_pda(&program_id, POOL_ID);
    let alice = AudrenKeys::from_seed(&[0x31u8; 32]);
    let asset_wsol = asset_id_for_mint(None);

    // 1. Instant spendability after Deposit AND after Transact change in the VERY SAME slot (100)!
    let (tw0, bl0, memo0) =
        encrypt_note_memo(&alice.view_pk, [0x32; 32], 10_000_000, &WSOL_MINT).unwrap();
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                wsol_mint_id(),
                payer.pubkey(),
                vault_wsol,
                spl_token_id(),
                0,
                0,
                0,
                0,
                None,
                None,
                true,
                false,
                10_000_000,
                derive_stealth_owner(alice.spend_pk, tw0),
                bl0,
                &memo0,
                &[],
            ))],
            200_000,
        ),
        "instant Deposit at slot 100",
    );

    let (path0, rk0, ri0, sr0) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        0,
        0,
        alice.view_sk,
    )
    .unwrap();
    let (tw_chg, bl_chg, memo_chg) =
        encrypt_note_memo(&alice.view_pk, [0x33; 32], 10_000_000, &WSOL_MINT).unwrap();
    let ctx0 = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        0,
        0b001,
        ASSET_MODE_PRIVATE,
        false,
        None,
        None,
        &[0u8; 32],
        0,
        0,
        &memo_chg,
    );
    let b0 = prover.build_and_prove(
        sr0,
        asset_wsol,
        Fr::from(0u64),
        0,
        0,
        ctx0,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw0,
                asset_id: asset_wsol,
                amount: 10_000_000,
                blinding: bl0,
                is_dummy: false,
                merkle_path: path0,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_wsol,
                amount: 0,
                blinding: Fr::from(11u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_chg),
                asset_id: asset_wsol,
                amount: 10_000_000,
                blinding: bl_chg,
            },
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
        ],
        [0x34; 32],
    );
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                payer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk0,
                ri0,
                0,
                0,
                0,
                0,
                0,
                0b001,
                ASSET_MODE_PRIVATE,
                false,
                None,
                (None, None, None),
                &b0.proof_192,
                &b0.nf0,
                &b0.nf1,
                &b0.cm0,
                &b0.cm1,
                &b0.cm2,
                0,
                0,
                payer.pubkey(),
                payer.pubkey(),
                &memo_chg,
                &[],
            ))],
            300_000,
        ),
        "instant spend of Deposit in same slot 100",
    );

    // Spend the change note IMMEDIATELY in the VERY SAME slot 100!
    let (path_c, rk_c, ri_c, sr_c) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        0,
        1,
        alice.view_sk,
    )
    .unwrap();
    let (tw_c2, bl_c2, memo_c2) =
        encrypt_note_memo(&alice.view_pk, [0x35; 32], 10_000_000, &WSOL_MINT).unwrap();
    let ctx_c = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        0,
        0b001,
        ASSET_MODE_PRIVATE,
        false,
        None,
        None,
        &[0u8; 32],
        0,
        0,
        &memo_c2,
    );
    let b_c = prover.build_and_prove(
        sr_c,
        asset_wsol,
        Fr::from(0u64),
        0,
        0,
        ctx_c,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_chg,
                asset_id: asset_wsol,
                amount: 10_000_000,
                blinding: bl_chg,
                is_dummy: false,
                merkle_path: path_c,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_wsol,
                amount: 0,
                blinding: Fr::from(12u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_c2),
                asset_id: asset_wsol,
                amount: 10_000_000,
                blinding: bl_c2,
            },
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
        ],
        [0x36; 32],
    );
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                payer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_c,
                ri_c,
                0,
                0,
                0,
                0,
                0,
                0b001,
                ASSET_MODE_PRIVATE,
                false,
                None,
                (None, None, None),
                &b_c.proof_192,
                &b_c.nf0,
                &b_c.nf1,
                &b_c.cm0,
                &b_c.cm1,
                &b_c.cm2,
                0,
                0,
                payer.pubkey(),
                payer.pubkey(),
                &memo_c2,
                &[],
            ))],
            300_000,
        ),
        "instant spend of Transact change note in same slot 100",
    );

    // 2. slot_ring 128-entry wrapping under 135 distinct slots of deposit spam:
    //    Deposit Note A at slot 200 (epoch 6 -> rolls epoch_ring!).
    svm.warp_to_slot(200);
    let leaf_a = lane_next_leaf(&svm, &program_id, 0);
    let (tw_a, bl_a, memo_a) =
        encrypt_note_memo(&alice.view_pk, [0x37; 32], 20_000_000, &WSOL_MINT).unwrap();
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                wsol_mint_id(),
                payer.pubkey(),
                vault_wsol,
                spl_token_id(),
                0,
                0,
                0,
                0,
                None,
                None,
                true,
                false,
                20_000_000,
                derive_stealth_owner(alice.spend_pk, tw_a),
                bl_a,
                &memo_a,
                &[],
            ))],
            200_000,
        ),
        "deposit Note A at epoch boundary slot 200",
    );
    let roots_at_a = decode_global_root_history(&svm.get_account(&roots_pda).unwrap().data).unwrap();
    let slot_idx_a = roots_at_a.slot_cursor as u8;
    let epoch_idx_a = roots_at_a.epoch_cursor as u8;
    assert_eq!(roots_at_a.latest_super_root, roots_at_a.stable_super_root);

    let (path_a, rk_a, ri_a, sr_a) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        0,
        leaf_a,
        alice.view_sk,
    )
    .unwrap();
    assert_eq!(rk_a, ROOT_RING_EPOCH);
    assert_eq!(ri_a, epoch_idx_a);

    // Spam 135 distinct slots across lanes 1, 2, 3 (45/lane -> zero rollover, > 128 slot_ring entries!)
    for i in 0u64..135u64 {
        svm.warp_to_slot(201 + i);
        let spam_lane = 1u8 + (i % 3) as u8;
        let mut eph = [0x66u8; 32];
        eph[0] = (i & 0xff) as u8;
        eph[1] = (i >> 8) as u8;
        let (tw_s, bl_s, memo_s) =
            encrypt_note_memo(&alice.view_pk, eph, 1_000_000, &WSOL_MINT).unwrap();
        expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_deposit(
                    program_id,
                    payer.pubkey(),
                    POOL_ID,
                    wsol_mint_id(),
                    payer.pubkey(),
                    vault_wsol,
                    spl_token_id(),
                    spam_lane,
                    0,
                    0,
                    0,
                    None,
                    None,
                    true,
                    false,
                    1_000_000,
                    derive_stealth_owner(alice.spend_pk, tw_s),
                    bl_s,
                    &memo_s,
                    &[],
                ))],
                200_000,
            ),
            "spam deposit to wrap slot_ring",
        );
    }
    let roots_after_spam =
        decode_global_root_history(&svm.get_account(&roots_pda).unwrap().data).unwrap();
    assert_eq!(roots_after_spam.slot_count as usize, SLOT_RING_LEN);
    assert!(
        (roots_after_spam.epoch_count as usize) < EPOCH_RING_LEN,
        "epoch_ring must still retain Note A's epoch entry"
    );
    assert_ne!(
        roots_after_spam.slot_ring[slot_idx_a as usize].super_root,
        roots_at_a.latest_super_root,
        "slot_ring[slot_idx_a] must have been overwritten by >128 distinct slots of spam"
    );
    assert_eq!(
        roots_after_spam.epoch_ring[epoch_idx_a as usize].super_root,
        roots_at_a.stable_super_root,
        "epoch_ring[epoch_idx_a] must remain intact"
    );

    let (tw_ao, bl_ao, memo_ao) =
        encrypt_note_memo(&alice.view_pk, [0x38; 32], 20_000_000, &WSOL_MINT).unwrap();
    let ctx_a = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        0,
        0b001,
        ASSET_MODE_PRIVATE,
        false,
        None,
        None,
        &[0u8; 32],
        0,
        0,
        &memo_ao,
    );
    let b_a = prover.build_and_prove(
        sr_a,
        asset_wsol,
        Fr::from(0u64),
        0,
        0,
        ctx_a,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_a,
                asset_id: asset_wsol,
                amount: 20_000_000,
                blinding: bl_a,
                is_dummy: false,
                merkle_path: path_a,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_wsol,
                amount: 0,
                blinding: Fr::from(13u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_ao),
                asset_id: asset_wsol,
                amount: 20_000_000,
                blinding: bl_ao,
            },
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
        ],
        [0x39; 32],
    );

    // Invalid root_ring_kind (2) -> Custom(6007) InvalidRootRing!
    let mut bad_ring_ix = to_svm_ix(&build_transact(
        program_id,
        payer.pubkey(),
        POOL_ID,
        VK_ID_DEFAULT,
        ROOT_RING_EPOCH,
        epoch_idx_a,
        0,
        0,
        0,
        0,
        0,
        0b001,
        ASSET_MODE_PRIVATE,
        false,
        None,
        (None, None, None),
        &b_a.proof_192,
        &b_a.nf0,
        &b_a.nf1,
        &b_a.cm0,
        &b_a.cm1,
        &b_a.cm2,
        0,
        0,
        payer.pubkey(),
        payer.pubkey(),
        &memo_ao,
        &[],
    ));
    bad_ring_ix.data[10] = 2; // payload offset 9 -> raw ix data offset 10
    expect_err_code(
        send_v1(&mut svm, &payer, &[], &[bad_ring_ix], 300_000),
        6007,
        "InvalidRootRing (kind=2) MUST return Custom(6007)",
    );

    // Out-of-bounds epoch_ring index -> Custom(6008) RootIndexOutOfBounds!
    let mut bad_idx_ix = to_svm_ix(&build_transact(
        program_id,
        payer.pubkey(),
        POOL_ID,
        VK_ID_DEFAULT,
        ROOT_RING_EPOCH,
        epoch_idx_a,
        0,
        0,
        0,
        0,
        0,
        0b001,
        ASSET_MODE_PRIVATE,
        false,
        None,
        (None, None, None),
        &b_a.proof_192,
        &b_a.nf0,
        &b_a.nf1,
        &b_a.cm0,
        &b_a.cm1,
        &b_a.cm2,
        0,
        0,
        payer.pubkey(),
        payer.pubkey(),
        &memo_ao,
        &[],
    ));
    bad_idx_ix.data[11] = roots_after_spam.epoch_count as u8;
    expect_err_code(
        send_v1(&mut svm, &payer, &[], &[bad_idx_ix], 300_000),
        6008,
        "RootIndexOutOfBounds MUST return Custom(6008)",
    );

    // Evicted slot_ring entry -> Custom(6010) ProofVerificationFailed!
    expect_err_code(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                payer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                ROOT_RING_SLOT,
                slot_idx_a,
                0,
                0,
                0,
                0,
                0,
                0b001,
                ASSET_MODE_PRIVATE,
                false,
                None,
                (None, None, None),
                &b_a.proof_192,
                &b_a.nf0,
                &b_a.nf1,
                &b_a.cm0,
                &b_a.cm1,
                &b_a.cm2,
                0,
                0,
                payer.pubkey(),
                payer.pubkey(),
                &memo_ao,
                &[],
            ))],
            300_000,
        ),
        6010,
        "evicted slot_ring entry MUST fail with ProofVerificationFailed (6010)",
    );

    // Preserved epoch_ring entry -> SUCCEEDS!
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                payer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                ROOT_RING_EPOCH,
                epoch_idx_a,
                0,
                0,
                0,
                0,
                0,
                0b001,
                ASSET_MODE_PRIVATE,
                false,
                None,
                (None, None, None),
                &b_a.proof_192,
                &b_a.nf0,
                &b_a.nf1,
                &b_a.cm0,
                &b_a.cm1,
                &b_a.cm2,
                0,
                0,
                payer.pubkey(),
                payer.pubkey(),
                &memo_ao,
                &[],
            ))],
            300_000,
        ),
        "epoch_ring entry survives >130 distinct slots of slot_ring spam",
    );

    // 3. Zero wall-clock idle expiry: deposit Note B (epoch_ring) and Note C (slot_ring-only),
    //    warp +500_000 idle slots -> BOTH slot_ring and epoch_ring remain valid with zero crank!
    svm.warp_to_slot(416); // new epoch (416 / 32 = 13)
    let leaf_b = lane_next_leaf(&svm, &program_id, 0);
    let (tw_b, bl_b, memo_b) =
        encrypt_note_memo(&alice.view_pk, [0x3A; 32], 15_000_000, &WSOL_MINT).unwrap();
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                wsol_mint_id(),
                payer.pubkey(),
                vault_wsol,
                spl_token_id(),
                0,
                0,
                0,
                0,
                None,
                None,
                true,
                false,
                15_000_000,
                derive_stealth_owner(alice.spend_pk, tw_b),
                bl_b,
                &memo_b,
                &[],
            ))],
            200_000,
        ),
        "deposit Note B (epoch_ring)",
    );

    svm.warp_to_slot(417); // same epoch 13 -> only in slot_ring!
    let leaf_c = lane_next_leaf(&svm, &program_id, 0);
    let (tw_c, bl_c, memo_c) =
        encrypt_note_memo(&alice.view_pk, [0x3B; 32], 12_000_000, &WSOL_MINT).unwrap();
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                wsol_mint_id(),
                payer.pubkey(),
                vault_wsol,
                spl_token_id(),
                0,
                0,
                0,
                0,
                None,
                None,
                true,
                false,
                12_000_000,
                derive_stealth_owner(alice.spend_pk, tw_c),
                bl_c,
                &memo_c,
                &[],
            ))],
            200_000,
        ),
        "deposit Note C (slot_ring only)",
    );

    // Warp +500_000 slots with ZERO transactions and ZERO cranks!
    svm.warp_to_slot(500_417);

    let (path_b, rk_b, ri_b, sr_b) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        0,
        leaf_b,
        alice.view_sk,
    )
    .unwrap();
    assert_eq!(rk_b, ROOT_RING_EPOCH, "Note B should select stable epoch_ring");

    let (path_cc, rk_cc, ri_cc, sr_cc) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        0,
        leaf_c,
        alice.view_sk,
    )
    .unwrap();
    assert_eq!(rk_cc, ROOT_RING_SLOT, "Note C must fall back to latest slot_ring");

    // Spend Note B (epoch_ring) & Note C (slot_ring) after +500_000 idle slots!
    let recipient_idle = Keypair::new().pubkey();
    for (label, rk, ri, sr, path, tw, bl, amt, seed_byte) in [
        ("epoch_ring after +500_000 idle slots", rk_b, ri_b, sr_b, path_b, tw_b, bl_b, 15_000_000u64, 0x3Cu8),
        ("slot_ring after +500_000 idle slots", rk_cc, ri_cc, sr_cc, path_cc, tw_c, bl_c, 12_000_000u64, 0x3Du8),
    ] {
        let ctx_idle = compute_transact_ctx_hash(
            &program_id,
            POOL_ID,
            VK_ID_DEFAULT,
            0,
            0,
            ASSET_MODE_PUBLIC,
            true,
            Some(&recipient_idle),
            None,
            &fr_to_be_bytes(&asset_wsol),
            amt,
            0,
            &[],
        );
        let b_idle = prover.build_and_prove(
            sr,
            asset_wsol,
            asset_wsol,
            amt,
            0,
            ctx_idle,
            true,
            [
                JoinSplitInputWitness {
                    spend_sk: alice.spend_sk,
                    tweak: tw,
                    asset_id: asset_wsol,
                    amount: amt,
                    blinding: bl,
                    is_dummy: false,
                    merkle_path: path,
                },
                JoinSplitInputWitness {
                    spend_sk: alice.spend_sk,
                    tweak: Fr::from(0u64),
                    asset_id: asset_wsol,
                    amount: 0,
                    blinding: Fr::from(14u64),
                    is_dummy: true,
                    merkle_path: MerklePath4Ary::default(),
                },
            ],
            [
                JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(1u64)),
                JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(2u64)),
                JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
            ],
            [seed_byte; 32],
        );
        expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_transact(
                    program_id,
                    payer.pubkey(),
                    POOL_ID,
                    VK_ID_DEFAULT,
                    rk,
                    ri,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    ASSET_MODE_PUBLIC,
                    true,
                    Some((wsol_mint_id(), vault_wsol, spl_token_id())),
                    (None, None, None),
                    &b_idle.proof_192,
                    &b_idle.nf0,
                    &b_idle.nf1,
                    &b_idle.cm0,
                    &b_idle.cm1,
                    &b_idle.cm2,
                    amt,
                    0,
                    recipient_idle,
                    payer.pubkey(),
                    &[],
                    &[],
                ))],
                300_000,
            ),
            label,
        );
    }
    assert_eq!(svm.get_balance(&recipient_idle).unwrap(), 27_000_000);

    // Verify `update_global_root_history` rejects any regressed Clock::slot (`now < prev_latest_slot`)
    // with `AudrenError::RootHistoryMismatch` (`6009`).
    let (roots_pda_reg, _) = derive_roots_pda(&program_id, POOL_ID);
    let latest_slot_before =
        GlobalRootHistory::decode(&svm.get_account(&roots_pda_reg).unwrap().data)
            .unwrap()
            .latest_slot;
    assert!(latest_slot_before > 0);
    let (lane3_pda, _) = derive_lane_pda(&program_id, POOL_ID, 3);
    let lane3_hdr = LaneTreeHeader::decode(&svm.get_account(&lane3_pda).unwrap().data).unwrap();
    let lane3_roll = compute_page_rollovers(lane3_hdr.next_leaf, 1, lane3_hdr.nf_count, 0);
    svm.warp_to_slot(latest_slot_before - 1);
    let (tw_reg, bl_reg, memo_reg) =
        encrypt_note_memo(&alice.view_pk, [0x9F; 32], 1_000_000, &WSOL_MINT).unwrap();
    expect_err_code(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                wsol_mint_id(),
                payer.pubkey(),
                vault_wsol,
                spl_token_id(),
                3,
                lane3_roll.out_sub_seq,
                lane3_roll.out_root_seq,
                lane3_roll.out_memo_seq,
                lane3_roll.next_sub_seq,
                lane3_roll.next_memo_seq,
                true,
                false,
                1_000_000,
                derive_stealth_owner(alice.spend_pk, tw_reg),
                bl_reg,
                &memo_reg,
                &[],
            ))],
            200_000,
        ),
        6009,
        "update_global_root_history must reject clock slot regression with RootHistoryMismatch (6009)",
    );

    println!("  [V1.3.0 TEST A PASSED] Instant spend, 128-slot wrap vs epoch_ring survival, 6007/6008/6009 errors, and +500k idle slot zero-expiry verified");
}

// ----------------------------------------------------------------------------
// V1.3.0 TEST B: Same-slot 4-instruction batched Transact merge proving against
//                slot_ring[slot_cursor] (Challenge #3 same_slot_bumped guard) +
//                multi-note shared witness fallback (Challenge #2)
// ----------------------------------------------------------------------------
#[test]
fn test_v130_same_slot_batched_4_transacts_and_multi_note_witness() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let mut svm = new_svm(program_id, None, None);
    let prover = AudrenProver::from_canonical_pk();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();
    svm.warp_to_slot(1_000);
    let vault_wsol = bootstrap_pool(&mut svm, program_id, &payer, 4);
    let (roots_pda, _) = derive_roots_pda(&program_id, POOL_ID);
    let alice = AudrenKeys::from_seed(&[0x44u8; 32]);
    let asset_wsol = asset_id_for_mint(None);

    // Deposit 4 notes on Lane 0 all in slot 1_001 (new slot > init slot 1_000 -> same_slot_bumped == 0)
    svm.warp_to_slot(1_001);
    let mut in_notes = Vec::new();
    for i in 0u8..4u8 {
        let (tw, bl, memo) =
            encrypt_note_memo(&alice.view_pk, [0x45 + i; 32], 5_000_000, &WSOL_MINT).unwrap();
        expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_deposit(
                    program_id,
                    payer.pubkey(),
                    POOL_ID,
                    wsol_mint_id(),
                    payer.pubkey(),
                    vault_wsol,
                    spl_token_id(),
                    0,
                    0,
                    0,
                    0,
                    None,
                    None,
                    true,
                    false,
                    5_000_000,
                    derive_stealth_owner(alice.spend_pk, tw),
                    bl,
                    &memo,
                    &[],
                ))],
                200_000,
            ),
            "deposit 4 same-slot notes",
        );
        in_notes.push((i as u64, tw, bl));
    }

    let roots_pre = decode_global_root_history(&svm.get_account(&roots_pda).unwrap().data).unwrap();
    assert_eq!(roots_pre.latest_slot, 1_001);
    assert!(!roots_pre.same_slot_bumped);
    let pre_cursor = roots_pre.slot_cursor;

    // Build 4 Transact instructions ALL proving against slot_ring[pre_cursor] in the EXACT SAME slot 1_001!
    let (paths_4, rk_4, ri_4, sr_4) = reconstruct_witness_for_notes(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        &[(0, 0), (0, 1), (0, 2), (0, 3)],
        audren_client::scanner::WitnessOptions {
            privacy_mode: audren_client::scanner::SyncPrivacyMode::Strict,
            view_sk: Some(alice.view_sk),
            decoy_epoch_bucket: None,
        },
    )
    .unwrap();
    assert_eq!(rk_4, ROOT_RING_SLOT);
    assert_eq!(ri_4, pre_cursor as u8);

    let mut batch_ixs = Vec::with_capacity(4);
    for (idx, ((_, tw, bl), path)) in in_notes.into_iter().zip(paths_4).enumerate() {
        let (tw_o, bl_o, memo_o) =
            encrypt_note_memo(&alice.view_pk, [0x50 + idx as u8; 32], 5_000_000, &WSOL_MINT)
                .unwrap();
        let ctx = compute_transact_ctx_hash(
            &program_id,
            POOL_ID,
            VK_ID_DEFAULT,
            1,
            0b001,
            ASSET_MODE_PRIVATE,
            false,
            None,
            None,
            &[0u8; 32],
            0,
            0,
            &memo_o,
        );
        let b = prover.build_and_prove(
            sr_4,
            asset_wsol,
            Fr::from(0u64),
            0,
            0,
            ctx,
            true,
            [
                JoinSplitInputWitness {
                    spend_sk: alice.spend_sk,
                    tweak: tw,
                    asset_id: asset_wsol,
                    amount: 5_000_000,
                    blinding: bl,
                    is_dummy: false,
                    merkle_path: path,
                },
                JoinSplitInputWitness {
                    spend_sk: alice.spend_sk,
                    tweak: Fr::from(0u64),
                    asset_id: asset_wsol,
                    amount: 0,
                    blinding: Fr::from(20u64 + idx as u64),
                    is_dummy: true,
                    merkle_path: MerklePath4Ary::default(),
                },
            ],
            [
                JoinSplitOutputWitness {
                    stealth_owner: derive_stealth_owner(alice.spend_pk, tw_o),
                    asset_id: asset_wsol,
                    amount: 5_000_000,
                    blinding: bl_o,
                },
                JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(2u64)),
                JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
            ],
            [0x5A + idx as u8; 32],
        );
        batch_ixs.push(to_svm_ix(&build_transact(
            program_id,
            payer.pubkey(),
            POOL_ID,
            VK_ID_DEFAULT,
            rk_4,
            ri_4,
            1,
            0,
            0,
            0,
            0,
            0b001,
            ASSET_MODE_PRIVATE,
            false,
            None,
            (None, None, None),
            &b.proof_192,
            &b.nf0,
            &b.nf1,
            &b.cm0,
            &b.cm1,
            &b.cm2,
            0,
            0,
            payer.pubkey(),
            payer.pubkey(),
            &memo_o,
            &[],
        )));
    }
    let batch_cu = expect_ok(
        send_v1(&mut svm, &payer, &[], &batch_ixs, 1_400_000),
        "4 batched same-slot Transact instructions in 1 Tx v1 (same_slot_bumped guard)",
    );
    let roots_post = decode_global_root_history(&svm.get_account(&roots_pda).unwrap().data).unwrap();
    assert!(roots_post.same_slot_bumped);
    assert_eq!(roots_post.slot_cursor, (pre_cursor + 1) % SLOT_RING_LEN as u16);
    assert_eq!(lane_next_leaf(&svm, &program_id, 1), 4);

    // Challenge #2: 2-input JoinSplit combining an older stable-epoch note (Lane 2) AND a brand-new
    // slot-only note (Lane 3) using reconstruct_witness_for_notes!
    svm.warp_to_slot(1_056); // new epoch 33 -> snapshots Lane 2 note into epoch_ring
    let (tw_old, bl_old, memo_old) =
        encrypt_note_memo(&alice.view_pk, [0x61; 32], 7_000_000, &WSOL_MINT).unwrap();
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                wsol_mint_id(),
                payer.pubkey(),
                vault_wsol,
                spl_token_id(),
                2,
                0,
                0,
                0,
                None,
                None,
                true,
                false,
                7_000_000,
                derive_stealth_owner(alice.spend_pk, tw_old),
                bl_old,
                &memo_old,
                &[],
            ))],
            200_000,
        ),
        "deposit older note on lane 2 (stable epoch)",
    );

    svm.warp_to_slot(1_057); // same epoch 33 -> Lane 3 note is ONLY in slot_ring (latest)!
    let (tw_new, bl_new, memo_new) =
        encrypt_note_memo(&alice.view_pk, [0x62; 32], 8_000_000, &WSOL_MINT).unwrap();
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                wsol_mint_id(),
                payer.pubkey(),
                vault_wsol,
                spl_token_id(),
                3,
                0,
                0,
                0,
                None,
                None,
                true,
                false,
                8_000_000,
                derive_stealth_owner(alice.spend_pk, tw_new),
                bl_new,
                &memo_new,
                &[],
            ))],
            200_000,
        ),
        "deposit newer note on lane 3 (slot_ring only)",
    );

    let (paths_2, rk_2, ri_2, sr_2) = reconstruct_witness_for_notes(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        &[(2, 0), (3, 0)],
        audren_client::scanner::WitnessOptions {
            privacy_mode: audren_client::scanner::SyncPrivacyMode::Strict,
            view_sk: Some(alice.view_sk),
            decoy_epoch_bucket: None,
        },
    )
    .unwrap();
    assert_eq!(
        rk_2, ROOT_RING_SLOT,
        "mixed stable+latest 2-note batch MUST fall back to latest slot_ring"
    );
    let (tw_m, bl_m, memo_m) =
        encrypt_note_memo(&alice.view_pk, [0x63; 32], 15_000_000, &WSOL_MINT).unwrap();
    let ctx_m = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        2,
        0b001,
        ASSET_MODE_PRIVATE,
        false,
        None,
        None,
        &[0u8; 32],
        0,
        0,
        &memo_m,
    );
    let b_m = prover.build_and_prove(
        sr_2,
        asset_wsol,
        Fr::from(0u64),
        0,
        0,
        ctx_m,
        false, // 2 real inputs!
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_old,
                asset_id: asset_wsol,
                amount: 7_000_000,
                blinding: bl_old,
                is_dummy: false,
                merkle_path: paths_2[0].clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_new,
                asset_id: asset_wsol,
                amount: 8_000_000,
                blinding: bl_new,
                is_dummy: false,
                merkle_path: paths_2[1].clone(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_m),
                asset_id: asset_wsol,
                amount: 15_000_000,
                blinding: bl_m,
            },
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
        ],
        [0x64; 32],
    );
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                payer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_2,
                ri_2,
                2,
                0,
                0,
                0,
                0,
                0b001,
                ASSET_MODE_PRIVATE,
                false,
                None,
                (None, None, None),
                &b_m.proof_192,
                &b_m.nf0,
                &b_m.nf1,
                &b_m.cm0,
                &b_m.cm1,
                &b_m.cm2,
                0,
                0,
                payer.pubkey(),
                payer.pubkey(),
                &memo_m,
                &[],
            ))],
            350_000,
        ),
        "2-input JoinSplit merging stable-epoch + latest-slot notes",
    );
    println!(
        "  [V1.3.0 TEST B PASSED] 4-ix same-slot batch ({batch_cu} CU total) & mixed stable+latest 2-note witness verified"
    );
}

// ----------------------------------------------------------------------------
// V1.3.0 TEST C: One-shot `InitRootHistory` (Tag 4) migration on a legacy
//                populated 4-lane Pool #0 with zero lost notes
// ----------------------------------------------------------------------------
#[test]
fn test_v130_init_root_history_legacy_pool_migration() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let mut svm = new_svm(program_id, None, None);
    let prover = AudrenProver::from_canonical_pk();
    let authority = Keypair::new();
    let rando = Keypair::new();
    svm.airdrop(&authority.pubkey(), 200_000_000_000).unwrap();
    svm.airdrop(&rando.pubkey(), 50_000_000_000).unwrap();
    svm.warp_to_slot(500);
    let vault_wsol = bootstrap_pool(&mut svm, program_id, &authority, 4);

    let alice = AudrenKeys::from_seed(&[0x71u8; 32]);
    let asset_wsol = asset_id_for_mint(None);
    let mut legacy_notes = Vec::new();
    for lane in 0u8..4u8 {
        let amt = 10_000_000 + (lane as u64) * 1_000_000;
        let (tw, bl, memo) =
            encrypt_note_memo(&alice.view_pk, [0x72 + lane; 32], amt, &WSOL_MINT).unwrap();
        expect_ok(
            send_v1(
                &mut svm,
                &authority,
                &[],
                &[to_svm_ix(&build_deposit(
                    program_id,
                    authority.pubkey(),
                    POOL_ID,
                    wsol_mint_id(),
                    authority.pubkey(),
                    vault_wsol,
                    spl_token_id(),
                    lane,
                    0,
                    0,
                    0,
                    None,
                    None,
                    true,
                    false,
                    amt,
                    derive_stealth_owner(alice.spend_pk, tw),
                    bl,
                    &memo,
                    &[],
                ))],
                200_000,
            ),
            "seed legacy note on lane 0..4",
        );
        legacy_notes.push((lane, amt, tw, bl));
    }

    // Simulate exact pre-v1.3.0 Mainnet/Devnet Pool #0 state:
    // delete `roots_pda` and restore legacy `max_ckpt_age = 1536` bytes in `PL_OFF_RESERVED_24`!
    let (pool_pda, _) = derive_pool_pda(&program_id, POOL_ID);
    let (roots_pda, _) = derive_roots_pda(&program_id, POOL_ID);
    svm.set_account(roots_pda, Account::default()).unwrap();
    {
        let mut p_acc = svm.get_account(&pool_pda).unwrap();
        p_acc.data[PL_OFF_RESERVED_24..PL_OFF_RESERVED_24 + 8]
            .copy_from_slice(&1_536u64.to_le_bytes());
        svm.set_account(pool_pda, p_acc).unwrap();
    }

    // 1. Non-authority rejected (6028)
    expect_err_code(
        send_v1(
            &mut svm,
            &rando,
            &[],
            &[to_svm_ix(&build_init_root_history(
                program_id,
                rando.pubkey(),
                POOL_ID,
                32,
                4,
            ))],
            100_000,
        ),
        6028,
        "non-authority InitRootHistory MUST fail (6028)",
    );

    // 2. root_epoch_interval == 0 or > 256 rejected (6000)
    for bad_interval in [0u64, 257u64] {
        let mut bad_ix = to_svm_ix(&build_init_root_history(
            program_id,
            authority.pubkey(),
            POOL_ID,
            32,
            4,
        ));
        bad_ix.data[5..13].copy_from_slice(&bad_interval.to_le_bytes());
        expect_err_code(
            send_v1(&mut svm, &authority, &[], &[bad_ix], 100_000),
            6000,
            "invalid root_epoch_interval MUST fail (6000)",
        );
    }

    // 3. Wrong lane count rejected (6000)
    expect_err_code(
        send_v1(
            &mut svm,
            &authority,
            &[],
            &[to_svm_ix(&build_init_root_history(
                program_id,
                authority.pubkey(),
                POOL_ID,
                32,
                3,
            ))],
            100_000,
        ),
        6000,
        "wrong lane count InitRootHistory MUST fail (6000)",
    );

    // 4. Authority runs InitRootHistory(32, 4) -> SUCCEEDS!
    let cu_migrate = expect_ok(
        send_v1(
            &mut svm,
            &authority,
            &[],
            &[to_svm_ix(&build_init_root_history(
                program_id,
                authority.pubkey(),
                POOL_ID,
                DEFAULT_ROOT_EPOCH_INTERVAL,
                4,
            ))],
            recommended_cu_limit_init_root_history(),
        ),
        "authority InitRootHistory migration",
    );
    let pool_after = svm.get_account(&pool_pda).unwrap().data;
    assert_eq!(
        &pool_after[PL_OFF_RESERVED_24..PL_OFF_RESERVED_24 + 8],
        &[0u8; 8],
        "InitRootHistory must zero legacy PL_OFF_RESERVED_24"
    );
    let ps_after = PoolState::decode(&pool_after).unwrap();
    assert_eq!(ps_after.root_epoch_interval, DEFAULT_ROOT_EPOCH_INTERVAL);
    let rh_after = decode_global_root_history(&svm.get_account(&roots_pda).unwrap().data).unwrap();
    assert_eq!(rh_after.latest_lane_counts[0..4], [1, 1, 1, 1]);
    assert_eq!(rh_after.stable_lane_counts[0..4], [1, 1, 1, 1]);

    // 5. Second call MUST fail (strictly one-shot: roots_acc already exists -> Custom 6002)!
    expect_err_code(
        send_v1(
            &mut svm,
            &authority,
            &[],
            &[to_svm_ix(&build_init_root_history(
                program_id,
                authority.pubkey(),
                POOL_ID,
                DEFAULT_ROOT_EPOCH_INTERVAL,
                4,
            ))],
            100_000,
        ),
        6002,
        "second InitRootHistory MUST fail (one-shot)",
    );

    // 6. Immediately spend ALL 4 pre-existing legacy notes across lanes 0, 1, 2, 3!
    let recipient = Keypair::new().pubkey();
    let mut expected_total = 0u64;
    for (lane, amt, tw, bl) in legacy_notes {
        expected_total += amt;
        let (path, rk, ri, sr) = reconstruct_witness_with(
            |a| svm.get_account(a).map(|x| x.data),
            &program_id,
            POOL_ID,
            lane,
            0,
            alice.view_sk,
        )
        .unwrap();
        let ctx = compute_transact_ctx_hash(
            &program_id,
            POOL_ID,
            VK_ID_DEFAULT,
            lane,
            0,
            ASSET_MODE_PUBLIC,
            true,
            Some(&recipient),
            None,
            &fr_to_be_bytes(&asset_wsol),
            amt,
            0,
            &[],
        );
        let b = prover.build_and_prove(
            sr,
            asset_wsol,
            asset_wsol,
            amt,
            0,
            ctx,
            true,
            [
                JoinSplitInputWitness {
                    spend_sk: alice.spend_sk,
                    tweak: tw,
                    asset_id: asset_wsol,
                    amount: amt,
                    blinding: bl,
                    is_dummy: false,
                    merkle_path: path,
                },
                JoinSplitInputWitness {
                    spend_sk: alice.spend_sk,
                    tweak: Fr::from(0u64),
                    asset_id: asset_wsol,
                    amount: 0,
                    blinding: Fr::from(30u64 + lane as u64),
                    is_dummy: true,
                    merkle_path: MerklePath4Ary::default(),
                },
            ],
            [
                JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(1u64)),
                JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(2u64)),
                JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
            ],
            [0x7A + lane; 32],
        );
        expect_ok(
            send_v1(
                &mut svm,
                &authority,
                &[],
                &[to_svm_ix(&build_transact(
                    program_id,
                    authority.pubkey(),
                    POOL_ID,
                    VK_ID_DEFAULT,
                    rk,
                    ri,
                    lane,
                    0,
                    0,
                    0,
                    0,
                    0,
                    ASSET_MODE_PUBLIC,
                    true,
                    Some((wsol_mint_id(), vault_wsol, spl_token_id())),
                    (None, None, None),
                    &b.proof_192,
                    &b.nf0,
                    &b.nf1,
                    &b.cm0,
                    &b.cm1,
                    &b.cm2,
                    amt,
                    0,
                    recipient,
                    authority.pubkey(),
                    &[],
                    &[],
                ))],
                300_000,
            ),
            "spend pre-existing legacy note after InitRootHistory migration",
        );
    }
    assert_eq!(svm.get_balance(&recipient).unwrap(), expected_total);
    println!(
        "  [V1.3.0 TEST C PASSED] InitRootHistory ({cu_migrate} CU) migrated 4-lane legacy Pool #0; all 4 pre-existing notes spent cleanly"
    );
}

// ----------------------------------------------------------------------------
// V1.3.0 TEST D: Auto-OpenPage (>= 90% lookahead & exact rollover in same Tx v1,
//                100% LaneRentVault subsidy) + Empirical CU Measurement Table
// ----------------------------------------------------------------------------
#[test]
fn test_v130_auto_open_page_lookahead_and_empirical_cu_budgets() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let router_id = Keypair::new().pubkey();
    let hook_id = Keypair::new().pubkey();
    let mut svm = new_svm(program_id, Some(router_id), Some(hook_id));
    let prover = AudrenProver::from_canonical_pk();
    let payer = Keypair::new();
    let relayer = Keypair::new();
    let recipient = Keypair::new();
    svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();
    svm.airdrop(&relayer.pubkey(), 50_000_000_000).unwrap();
    svm.warp_to_slot(2_000);

    // Measure InitPool, InitLane, OpenPage
    let cu_init_pool = expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_init_pool(
                program_id,
                payer.pubkey(),
                POOL_ID,
                ROOT_EPOCH_INTERVAL,
                2_000_000,
                500_000,
            ))],
            600_000,
        ),
        "CU: InitPool",
    );
    let mut cu_init_lane = 0u64;
    for l in 0u8..4u8 {
        cu_init_lane = cu_init_lane.max(expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_init_lane(program_id, payer.pubkey(), POOL_ID, l))],
                600_000,
            ),
            "CU: InitLane",
        ));
    }
    let (va, _) = derive_vault_auth_pda(&program_id, POOL_ID);
    let (esc0, _) = derive_escrow_pda(&program_id, POOL_ID, 0);
    svm.airdrop(&esc0, 2_000_000).unwrap();
    let vault_wsol = create_canonical_ata(&mut svm, &payer, va, wsol_mint_id(), spl_token_id());
    let alice = AudrenKeys::from_seed(&[0x81u8; 32]);
    let asset_wsol = asset_id_for_mint(None);

    // 1. Auto-OpenPage >= 90% lookahead on Lane 0: fill 86 leaves (memo_rem = 96 - 86 = 10 <= 10!)
    let mut cu_deposit_sol = 0u64;
    let mut lane0_note0 = None;
    let mut lane0_note1 = None;
    for i in 0u64..86u64 {
        let mut eph = [0x82u8; 32];
        eph[0] = (i & 0xff) as u8;
        let (tw, bl, memo) =
            encrypt_note_memo(&alice.view_pk, eph, 2_000_000, &WSOL_MINT).unwrap();
        if i == 0 {
            lane0_note0 = Some((tw, bl));
        } else if i == 1 {
            lane0_note1 = Some((tw, bl));
        }
        let cu = expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_deposit(
                    program_id,
                    payer.pubkey(),
                    POOL_ID,
                    wsol_mint_id(),
                    payer.pubkey(),
                    vault_wsol,
                    spl_token_id(),
                    0,
                    0,
                    0,
                    0,
                    None,
                    None,
                    true,
                    false,
                    2_000_000,
                    derive_stealth_owner(alice.spend_pk, tw),
                    bl,
                    &memo,
                    &[],
                ))],
                600_000,
            ),
            "fill Lane 0 to 86 leaves",
        );
        cu_deposit_sol = cu_deposit_sol.max(cu);
    }

    let memo1_pda = derive_memo_pda(&program_id, POOL_ID, 0, 1).0;
    assert!(svm.get_account(&memo1_pda).is_none());
    let mut existing_pages = BTreeSet::new();
    for pda in [
        derive_subtree_pda(&program_id, POOL_ID, 0, 0).0,
        audren_client::pda::derive_subroot_pda(&program_id, POOL_ID, 0, 0).0,
        derive_memo_pda(&program_id, POOL_ID, 0, 0).0,
        derive_nf_page_pda(&program_id, POOL_ID, 0, 0).0,
    ] {
        if svm.get_account(&pda).is_some_and(|a| !a.data.is_empty()) {
            existing_pages.insert(pda);
        }
    }
    let specs =
        plan_auto_open_pages(&program_id, POOL_ID, 0, 86, 0, 1, 0, &existing_pages).unwrap();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].page_kind, OPEN_PAGE_KIND_MEMO);
    assert_eq!(specs[0].page_seq, 1);

    // Prepend Auto-OpenPage(MEMO, 1) in the SAME Tx v1 as Deposit #86!
    // Verify LaneRentVault subsidizes 100% of MemoPage 1 rent!
    let lane0_rent_pda = derive_lane_rent_pda(&program_id, POOL_ID, 0).0;
    let rent_vault_before = svm.get_account(&lane0_rent_pda).unwrap().lamports;
    let memo_rent_needed = svm.minimum_balance_for_rent_exemption(MEMO_PAGE_LEN);
    assert!(
        rent_vault_before > memo_rent_needed,
        "LaneRentVault must have accumulated enough fees by leaf 86 to 100% subsidize MemoPage 1"
    );
    let payer_before = svm.get_balance(&payer.pubkey()).unwrap();
    let auto_ixs =
        build_auto_open_page_ixs(program_id, payer.pubkey(), POOL_ID, 0, 86, 0, 1, 0, &existing_pages)
            .unwrap();
    let (tw86, bl86, memo86) =
        encrypt_note_memo(&alice.view_pk, [0x86; 32], 2_000_000, &WSOL_MINT).unwrap();
    let mut tx_ixs: Vec<Instruction> = auto_ixs.iter().map(to_svm_ix).collect();
    tx_ixs.push(to_svm_ix(&build_deposit(
        program_id,
        payer.pubkey(),
        POOL_ID,
        wsol_mint_id(),
        payer.pubkey(),
        vault_wsol,
        spl_token_id(),
        0,
        0,
        0,
        0,
        None,
        None,
        true,
        false,
        2_000_000,
        derive_stealth_owner(alice.spend_pk, tw86),
        bl86,
        &memo86,
        &[],
    )));
    // H-1 regression checks at next_leaf = 86 (MemoPage 0 at 86/96 >= 90%, SubtreePage 0 at 86/256 < 90%):
    // 1. cur_seq + 2 (MemoPage 2) is unconditionally rejected with PageSeqOutOfRange (6029)
    expect_err_code(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_open_page(
                program_id,
                payer.pubkey(),
                OPEN_PAGE_KIND_MEMO,
                POOL_ID,
                0,
                2,
                u64::MAX,
            ))],
            CU_LIMIT_OPEN_PAGE,
        ),
        6029,
        "H-1: OpenPage(MEMO, cur_seq+2) must fail with PageSeqOutOfRange (6029)",
    );
    // 2. SubtreePage 1 at 86/256 (< 230/256) is rejected with PageSeqOutOfRange (6029)
    expect_err_code(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_open_page(
                program_id,
                payer.pubkey(),
                OPEN_PAGE_KIND_SUBTREE,
                POOL_ID,
                0,
                1,
                u64::MAX,
            ))],
            CU_LIMIT_OPEN_PAGE,
        ),
        6029,
        "H-1: OpenPage(SUBTREE, 1) below 230/256 must fail with PageSeqOutOfRange (6029)",
    );
    // 3. TOCTOU protection: if LaneRentVault is underfunded, proactive max_payer_deficit = 0 reverts
    //    cleanly with InsufficientVaultBalance (6017) without draining payer!
    {
        let (rv0_pda, _) = derive_lane_rent_pda(&program_id, POOL_ID, 0);
        let orig_rv = svm.get_account(&rv0_pda).unwrap();
        let mut drained_rv = orig_rv.clone();
        drained_rv.lamports =
            svm.minimum_balance_for_rent_exemption(audren_core::layout::SENTINEL_LEN);
        svm.set_account(rv0_pda, drained_rv).unwrap();
        let payer_pre_toctou = svm.get_balance(&payer.pubkey()).unwrap();
        expect_err_code(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_open_page(
                    program_id,
                    payer.pubkey(),
                    OPEN_PAGE_KIND_MEMO,
                    POOL_ID,
                    0,
                    1,
                    0,
                ))],
                CU_LIMIT_OPEN_PAGE,
            ),
            6017,
            "H-1: OpenPage with max_payer_deficit=0 on drained LaneRentVault must fail with 6017",
        );
        let payer_post_toctou = svm.get_balance(&payer.pubkey()).unwrap();
        assert!(
            payer_pre_toctou.saturating_sub(payer_post_toctou) <= 10_000,
            "H-1: failed max_payer_deficit=0 OpenPage must not debit page rent from payer"
        );
        svm.set_account(rv0_pda, orig_rv).unwrap();
    }

    let cu_auto_dep = expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &tx_ixs,
            recommended_cu_limit_deposit(false, auto_ixs.len()),
        ),
        "Auto-OpenPage(MEMO, 1) + Deposit #86 in 1 Tx v1",
    );
    assert!(svm.get_account(&memo1_pda).is_some());
    let payer_after = svm.get_balance(&payer.pubkey()).unwrap();
    let payer_delta = payer_before - payer_after;
    assert!(
        payer_delta < 2_000_000 + 2_000_000 + 10_000,
        "payer must NOT pay MemoPage 1 rent ({memo_rent_needed}); actual delta={payer_delta}"
    );
    // Idempotent hit on already-open MemoPage 1 MUST succeed even with max_payer_deficit = 0
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_open_page(
                program_id,
                payer.pubkey(),
                OPEN_PAGE_KIND_MEMO,
                POOL_ID,
                0,
                1,
                0,
            ))],
            CU_LIMIT_OPEN_PAGE,
        ),
        "H-1: idempotent OpenPage(MEMO, 1) with max_payer_deficit=0 succeeds",
    );
    assert_eq!(CU_LIMIT_OPEN_PAGE, 40_000);
    assert_eq!(CU_LIMIT_TRANSACT_FULL_EXIT, 165_000);
    let mut cu_open_page = 0u64;

    // 2. Measure Classic SPL Deposit, Token-2022 TransferFee+TransferHook Deposit,
    //    Transact Private 2in/3out, Transact Withdraw SPL, Transact Withdraw WSOL Unwrap,
    //    Transact Full Exit (read-only roots), Transact Withdraw T22 Hook, and ExecViaEscrow!
    let usdc_mint = create_spl_mint(&mut svm, &payer, 6);
    let vault_usdc = create_canonical_ata(&mut svm, &payer, va, usdc_mint, spl_token_id());
    let payer_usdc = create_canonical_ata(&mut svm, &payer, payer.pubkey(), usdc_mint, spl_token_id());
    let recip_usdc = create_canonical_ata(&mut svm, &payer, recipient.pubkey(), usdc_mint, spl_token_id());
    let relayer_usdc = create_canonical_ata(&mut svm, &payer, relayer.pubkey(), usdc_mint, spl_token_id());
    mint_to(&mut svm, &payer, spl_token_id(), usdc_mint, payer_usdc, 200_000_000);

    let (tw_u, bl_u, memo_u) =
        encrypt_note_memo(&alice.view_pk, [0x91; 32], 50_000_000, &usdc_mint.to_bytes()).unwrap();
    let cu_deposit_spl = expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                usdc_mint,
                payer_usdc,
                vault_usdc,
                spl_token_id(),
                1,
                0,
                0,
                0,
                None,
                None,
                false,
                false,
                50_000_000,
                derive_stealth_owner(alice.spend_pk, tw_u),
                bl_u,
                &memo_u,
                &[],
            ))],
            600_000,
        ),
        "CU: Deposit SPL",
    );

    // Token-2022 TransferFee + TransferHook combined mint!
    let t22_fh_kp = Keypair::new();
    let fh_space = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::TransferFeeConfig,
        ExtensionType::TransferHook,
    ])
    .unwrap();
    let fh_rent = svm.minimum_balance_for_rent_exemption(fh_space);
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[&t22_fh_kp],
            &[
                sys_ix::create_account(
                    &payer.pubkey(),
                    &t22_fh_kp.pubkey(),
                    fh_rent,
                    fh_space as u64,
                    &token_2022_id(),
                ),
                transfer_fee_ix::initialize_transfer_fee_config(
                    &token_2022_id(),
                    &t22_fh_kp.pubkey(),
                    Some(&payer.pubkey()),
                    Some(&payer.pubkey()),
                    250,
                    50_000_000,
                )
                .unwrap(),
                transfer_hook_ix::initialize(
                    &token_2022_id(),
                    &t22_fh_kp.pubkey(),
                    Some(payer.pubkey()),
                    Some(hook_id),
                )
                .unwrap(),
                token_ix::initialize_mint(
                    &token_2022_id(),
                    &t22_fh_kp.pubkey(),
                    &payer.pubkey(),
                    None,
                    6,
                )
                .unwrap(),
            ],
            300_000,
        ),
        "create T22 TransferFee+TransferHook mint",
    );
    let fh_mint = t22_fh_kp.pubkey();
    let fh_extra = Address::find_program_address(&[b"extra-account-metas", fh_mint.as_ref()], &hook_id).0;
    let fh_state = Address::find_program_address(&[b"hook_state", fh_mint.as_ref()], &hook_id).0;
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[Instruction {
                program_id: hook_id,
                accounts: vec![
                    AccountMeta::new(payer.pubkey(), true),
                    AccountMeta::new_readonly(fh_mint, false),
                    AccountMeta::new(fh_extra, false),
                    AccountMeta::new(fh_state, false),
                    AccountMeta::new_readonly(sys_program_id(), false),
                ],
                data: vec![0u8],
            }],
            200_000,
        ),
        "init T22 Fee+Hook extra metas",
    );
    let payer_fh = create_canonical_ata(&mut svm, &payer, payer.pubkey(), fh_mint, token_2022_id());
    let vault_fh = create_canonical_ata(&mut svm, &payer, va, fh_mint, token_2022_id());
    let recip_fh = create_canonical_ata(&mut svm, &payer, recipient.pubkey(), fh_mint, token_2022_id());
    let relayer_fh = create_canonical_ata(&mut svm, &payer, relayer.pubkey(), fh_mint, token_2022_id());
    mint_to(&mut svm, &payer, token_2022_id(), fh_mint, payer_fh, 100_000_000);
    let fh_metas = vec![
        AudrenAccountMeta::readonly(fh_extra, false),
        AudrenAccountMeta::writable(fh_state, false),
        AudrenAccountMeta::readonly(hook_id, false),
    ];
    let (tw_fh, bl_fh, memo_fh) =
        encrypt_note_memo(&alice.view_pk, [0x92; 32], 39_000_000, &fh_mint.to_bytes()).unwrap();
    let cu_deposit_t22_fh = expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit(
                program_id,
                payer.pubkey(),
                POOL_ID,
                fh_mint,
                payer_fh,
                vault_fh,
                token_2022_id(),
                2,
                0,
                0,
                0,
                None,
                None,
                false,
                false,
                40_000_000,
                derive_stealth_owner(alice.spend_pk, tw_fh),
                bl_fh,
                &memo_fh,
                &fh_metas,
            ))],
            600_000,
        ),
        "CU: Deposit T22 Fee+Hook",
    );

    // Transact Private 2in/3out (worst-case 2 nullifiers + 3 outputs!)
    let (tw0, bl0) = lane0_note0.unwrap();
    let (tw1, bl1) = lane0_note1.unwrap();
    let (paths_2in, rk_p, ri_p, sr_p) = reconstruct_witness_for_notes(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        &[(0, 0), (0, 1)],
        audren_client::scanner::WitnessOptions {
            privacy_mode: audren_client::scanner::SyncPrivacyMode::Strict,
            view_sk: Some(alice.view_sk),
            decoy_epoch_bucket: None,
        },
    )
    .unwrap();
    let (tw_o0, bl_o0, memo_o0) =
        encrypt_note_memo(&alice.view_pk, [0xA1; 32], 1_500_000, &WSOL_MINT).unwrap();
    let (tw_o1, bl_o1, memo_o1) =
        encrypt_note_memo(&alice.view_pk, [0xA2; 32], 1_500_000, &WSOL_MINT).unwrap();
    let (tw_o2, bl_o2, memo_o2) =
        encrypt_note_memo(&alice.view_pk, [0xA3; 32], 1_000_000, &WSOL_MINT).unwrap();
    let mut memos_3 = Vec::with_capacity(318);
    memos_3.extend_from_slice(&memo_o0);
    memos_3.extend_from_slice(&memo_o1);
    memos_3.extend_from_slice(&memo_o2);
    let ctx_2in3out = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        3,
        0b111,
        ASSET_MODE_PRIVATE,
        false,
        None,
        None,
        &[0u8; 32],
        0,
        0,
        &memos_3,
    );
    let b_2in3out = prover.build_and_prove(
        sr_p,
        asset_wsol,
        Fr::from(0u64),
        0,
        0,
        ctx_2in3out,
        false,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw0,
                asset_id: asset_wsol,
                amount: 2_000_000,
                blinding: bl0,
                is_dummy: false,
                merkle_path: paths_2in[0].clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw1,
                asset_id: asset_wsol,
                amount: 2_000_000,
                blinding: bl1,
                is_dummy: false,
                merkle_path: paths_2in[1].clone(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_o0),
                asset_id: asset_wsol,
                amount: 1_500_000,
                blinding: bl_o0,
            },
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_o1),
                asset_id: asset_wsol,
                amount: 1_500_000,
                blinding: bl_o1,
            },
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_o2),
                asset_id: asset_wsol,
                amount: 1_000_000,
                blinding: bl_o2,
            },
        ],
        [0xA4; 32],
    );
    let cu_transact_2in3out = expect_ok(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_p,
                ri_p,
                3,
                0,
                0,
                0,
                0,
                0b111,
                ASSET_MODE_PRIVATE,
                false,
                None,
                (None, None, None),
                &b_2in3out.proof_192,
                &b_2in3out.nf0,
                &b_2in3out.nf1,
                &b_2in3out.cm0,
                &b_2in3out.cm1,
                &b_2in3out.cm2,
                0,
                0,
                relayer.pubkey(),
                relayer.pubkey(),
                &memos_3,
                &[],
            ))],
            600_000,
        ),
        "CU: Transact Private 2in/3out",
    );

    // Transact Withdraw SPL (partial 1in/1out + relayer fee)
    let (path_u, rk_u, ri_u, sr_u) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        1,
        0,
        alice.view_sk,
    )
    .unwrap();
    let asset_usdc = asset_id_for_mint(Some(&usdc_mint));
    let (tw_uc, bl_uc, memo_uc) =
        encrypt_note_memo(&alice.view_pk, [0xA5; 32], 20_000_000, &usdc_mint.to_bytes()).unwrap();
    let ctx_wd_spl = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        1,
        0b001,
        ASSET_MODE_PUBLIC,
        false,
        Some(&recip_usdc),
        Some(&relayer_usdc),
        &fr_to_be_bytes(&asset_usdc),
        28_000_000,
        2_000_000,
        &memo_uc,
    );
    let b_wd_spl = prover.build_and_prove(
        sr_u,
        asset_usdc,
        asset_usdc,
        28_000_000,
        2_000_000,
        ctx_wd_spl,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_u,
                asset_id: asset_usdc,
                amount: 50_000_000,
                blinding: bl_u,
                is_dummy: false,
                merkle_path: path_u,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_usdc,
                amount: 0,
                blinding: Fr::from(41u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_uc),
                asset_id: asset_usdc,
                amount: 20_000_000,
                blinding: bl_uc,
            },
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_usdc, Fr::from(3u64)),
        ],
        [0xA6; 32],
    );
    let cu_transact_wd_spl = expect_ok(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_u,
                ri_u,
                1,
                0,
                0,
                0,
                0,
                0b001,
                ASSET_MODE_PUBLIC,
                false,
                Some((usdc_mint, vault_usdc, spl_token_id())),
                (None, None, None),
                &b_wd_spl.proof_192,
                &b_wd_spl.nf0,
                &b_wd_spl.nf1,
                &b_wd_spl.cm0,
                &b_wd_spl.cm1,
                &b_wd_spl.cm2,
                28_000_000,
                2_000_000,
                recip_usdc,
                relayer_usdc,
                &memo_uc,
                &[],
            ))],
            600_000,
        ),
        "CU: Transact Withdraw SPL",
    );

    // Transact Withdraw WSOL Unwrap (partial 1in/1out + relayer fee)
    let (path_uw, rk_uw, ri_uw, sr_uw) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        3,
        0,
        alice.view_sk,
    )
    .unwrap();
    let (tw_uwc, bl_uwc, memo_uwc) =
        encrypt_note_memo(&alice.view_pk, [0xA7; 32], 500_000, &WSOL_MINT).unwrap();
    let ctx_wd_uw = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        3,
        0b001,
        ASSET_MODE_PUBLIC,
        true,
        Some(&recipient.pubkey()),
        Some(&relayer.pubkey()),
        &fr_to_be_bytes(&asset_wsol),
        900_000,
        100_000,
        &memo_uwc,
    );
    let b_wd_uw = prover.build_and_prove(
        sr_uw,
        asset_wsol,
        asset_wsol,
        900_000,
        100_000,
        ctx_wd_uw,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_o0,
                asset_id: asset_wsol,
                amount: 1_500_000,
                blinding: bl_o0,
                is_dummy: false,
                merkle_path: path_uw,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_wsol,
                amount: 0,
                blinding: Fr::from(42u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_uwc),
                asset_id: asset_wsol,
                amount: 500_000,
                blinding: bl_uwc,
            },
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
        ],
        [0xA8; 32],
    );
    let cu_transact_wd_unwrap = expect_ok(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_uw,
                ri_uw,
                3,
                0,
                0,
                0,
                0,
                0b001,
                ASSET_MODE_PUBLIC,
                true,
                Some((wsol_mint_id(), vault_wsol, spl_token_id())),
                (None, None, None),
                &b_wd_uw.proof_192,
                &b_wd_uw.nf0,
                &b_wd_uw.nf1,
                &b_wd_uw.cm0,
                &b_wd_uw.cm1,
                &b_wd_uw.cm2,
                900_000,
                100_000,
                recipient.pubkey(),
                relayer.pubkey(),
                &memo_uwc,
                &[],
            ))],
            600_000,
        ),
        "CU: Transact Withdraw WSOL Unwrap",
    );

    // Transact Full Exit (output_mask == 0, READ-ONLY roots_acc)
    let (path_fe, rk_fe, ri_fe, sr_fe) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        3,
        1,
        alice.view_sk,
    )
    .unwrap();
    let ctx_fe = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        3,
        0,
        ASSET_MODE_PUBLIC,
        true,
        Some(&recipient.pubkey()),
        Some(&relayer.pubkey()),
        &fr_to_be_bytes(&asset_wsol),
        1_400_000,
        100_000,
        &[],
    );
    let b_fe = prover.build_and_prove(
        sr_fe,
        asset_wsol,
        asset_wsol,
        1_400_000,
        100_000,
        ctx_fe,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_o1,
                asset_id: asset_wsol,
                amount: 1_500_000,
                blinding: bl_o1,
                is_dummy: false,
                merkle_path: path_fe,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_wsol,
                amount: 0,
                blinding: Fr::from(43u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(1u64)),
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
        ],
        [0xA9; 32],
    );
    let cu_transact_full_exit = expect_ok(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_fe,
                ri_fe,
                3,
                0,
                0,
                0,
                0,
                0,
                ASSET_MODE_PUBLIC,
                true,
                Some((wsol_mint_id(), vault_wsol, spl_token_id())),
                (None, None, None),
                &b_fe.proof_192,
                &b_fe.nf0,
                &b_fe.nf1,
                &b_fe.cm0,
                &b_fe.cm1,
                &b_fe.cm2,
                1_400_000,
                100_000,
                recipient.pubkey(),
                relayer.pubkey(),
                &[],
                &[],
            ))],
            600_000,
        ),
        "CU: Transact Full Exit read-only roots",
    );

    // Transact Withdraw T22 TransferFee + TransferHook
    let (path_fh, rk_fh, ri_fh, sr_fh) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        2,
        0,
        alice.view_sk,
    )
    .unwrap();
    let asset_fh = asset_id_for_mint(Some(&fh_mint));
    let ctx_fh = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        2,
        0,
        ASSET_MODE_PUBLIC,
        false,
        Some(&recip_fh),
        Some(&relayer_fh),
        &fr_to_be_bytes(&asset_fh),
        35_000_000,
        4_000_000,
        &[],
    );
    let b_fh = prover.build_and_prove(
        sr_fh,
        asset_fh,
        asset_fh,
        35_000_000,
        4_000_000,
        ctx_fh,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_fh,
                asset_id: asset_fh,
                amount: 39_000_000,
                blinding: bl_fh,
                is_dummy: false,
                merkle_path: path_fh,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_fh,
                amount: 0,
                blinding: Fr::from(44u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness::dummy(asset_fh, Fr::from(1u64)),
            JoinSplitOutputWitness::dummy(asset_fh, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_fh, Fr::from(3u64)),
        ],
        [0xAA; 32],
    );
    let cu_transact_wd_hook = expect_ok(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_fh,
                ri_fh,
                2,
                0,
                0,
                0,
                0,
                0,
                ASSET_MODE_PUBLIC,
                false,
                Some((fh_mint, vault_fh, token_2022_id())),
                (None, None, None),
                &b_fh.proof_192,
                &b_fh.nf0,
                &b_fh.nf1,
                &b_fh.cm0,
                &b_fh.cm1,
                &b_fh.cm2,
                35_000_000,
                4_000_000,
                recip_fh,
                relayer_fh,
                &[],
                &fh_metas,
            ))],
            600_000,
        ),
        "CU: Transact Withdraw T22 Hook",
    );

    // ExecViaEscrow (WSOL -> SPL USDC via mock router)
    let dex_pool = dex_pool_pda(&router_id);
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[dex_init_ix(router_id, payer.pubkey(), 10_000, 10_000_000_000)],
            200_000,
        ),
        "init mock router for CU bench",
    );
    let esc0_wsol = create_canonical_ata(&mut svm, &payer, esc0, wsol_mint_id(), spl_token_id());
    let dex_wsol = create_canonical_ata(&mut svm, &payer, dex_pool, wsol_mint_id(), spl_token_id());
    let esc0_usdc = create_canonical_ata(&mut svm, &payer, esc0, usdc_mint, spl_token_id());
    let dex_usdc = create_canonical_ata(&mut svm, &payer, dex_pool, usdc_mint, spl_token_id());
    mint_to(&mut svm, &payer, spl_token_id(), usdc_mint, dex_usdc, 50_000_000);

    let (path_ex, rk_ex, ri_ex, sr_ex) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        3,
        2,
        alice.view_sk,
    )
    .unwrap();
    let (dtw, dbl, dhead, dmask) = prepare_dynamic_swap_memo(&alice.view_pk, [0xAB; 32]).unwrap();
    let ost = fr_to_be_bytes(&derive_stealth_owner(alice.spend_pk, dtw));
    let obl = fr_to_be_bytes(&dbl);
    let swap_data = dex_swap_spl_to_spl_data(0, 1_000_000, 1_000_000, 9, 6);
    let swap_accs = vec![
        AudrenAccountMeta::writable(esc0, false),
        AudrenAccountMeta::writable(esc0_wsol, false),
        AudrenAccountMeta::writable(dex_wsol, false),
        AudrenAccountMeta::writable(dex_pool, false),
        AudrenAccountMeta::writable(dex_usdc, false),
        AudrenAccountMeta::writable(esc0_usdc, false),
        AudrenAccountMeta::readonly(wsol_mint_id(), false),
        AudrenAccountMeta::readonly(usdc_mint, false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
    ];
    let ctx_ex = compute_exec_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        3,
        0,
        0,
        false,
        &asset_id_bytes_for_mint(None),
        1_000_000,
        0,
        None,
        &fr_to_be_bytes(&asset_usdc),
        1_000_000,
        &router_id,
        &swap_accs,
        &[],
        &ost,
        &obl,
        &dhead,
        &dmask,
        &swap_data,
        &[],
    );
    let b_ex = prover.build_and_prove(
        sr_ex,
        asset_wsol,
        asset_wsol,
        1_000_000,
        0,
        ctx_ex,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_o2,
                asset_id: asset_wsol,
                amount: 1_000_000,
                blinding: bl_o2,
                is_dummy: false,
                merkle_path: path_ex,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_wsol,
                amount: 0,
                blinding: Fr::from(45u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(1u64)),
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
        ],
        [0xAC; 32],
    );
    let cu_exec = expect_ok(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_exec_via_escrow(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_ex,
                ri_ex,
                3,
                0,
                0,
                0,
                0,
                0,
                0,
                false,
                (wsol_mint_id(), vault_wsol, esc0_wsol, spl_token_id()),
                (usdc_mint, vault_usdc, esc0_usdc, spl_token_id()),
                0,
                None,
                (None, None, None),
                &b_ex.proof_192,
                &b_ex.nf0,
                &b_ex.nf1,
                &b_ex.cm0,
                &b_ex.cm1,
                &b_ex.cm2,
                1_000_000,
                1_000_000,
                &ost,
                &obl,
                &dhead,
                &dmask,
                router_id,
                &swap_data,
                swap_accs,
                &[],
                &[],
            ))],
            600_000,
        ),
        "CU: ExecViaEscrow",
    );

    // Also measure worst-case 256-leaf SubtreePage seal boundary Deposit (leaf 255 -> 256)
    // and worst-case 2in/2out Withdraw WSOL Unwrap + 2in/2out Withdraw SPL + 2in/2out T22 Hook!
    let mut lane0_note_a = None;
    let mut lane0_note_b = None;
    let mut lane0_note_c = None;
    let mut lane0_note_d = None;
    let mut lane0_note_e = None;
    let mut lane0_note_f = None;
    let mut lane0_note_g = None;
    let mut lane0_note_h = None;
    let mut lane0_note_i = None;
    let mut lane0_note_j = None;
    let mut cu_deposit_sol_seal_256 = 0u64;
    for i in 87u64..256u64 {
        if i == 182 {
            // Standalone OpenPage CU measurement at >=90% MemoPage 1 occupancy (182 % 96 == 86)
            cu_open_page = expect_ok(
                send_v1(
                    &mut svm,
                    &payer,
                    &[],
                    &[to_svm_ix(&build_open_page(
                        program_id,
                        payer.pubkey(),
                        OPEN_PAGE_KIND_MEMO,
                        POOL_ID,
                        0,
                        2,
                        u64::MAX,
                    ))],
                    CU_LIMIT_OPEN_PAGE,
                ),
                "CU: OpenPage(MEMO, 2) at >=90% occupancy",
            );
        }
        if i == 230 {
            expect_ok(
                send_v1(
                    &mut svm,
                    &payer,
                    &[],
                    &[to_svm_ix(&build_open_page(
                        program_id,
                        payer.pubkey(),
                        OPEN_PAGE_KIND_SUBTREE,
                        POOL_ID,
                        0,
                        1,
                        u64::MAX,
                    ))],
                    CU_LIMIT_OPEN_PAGE,
                ),
                "OpenPage(SUBTREE, 1) at >=90% occupancy (230/256)",
            );
        }
        let mut eph = [0xD0u8; 32];
        eph[0] = (i & 0xff) as u8;
        eph[1] = (i >> 8) as u8;
        let (tw, bl, memo) =
            encrypt_note_memo(&alice.view_pk, eph, 2_000_000, &WSOL_MINT).unwrap();
        match i {
            100 => lane0_note_a = Some((i, tw, bl)),
            101 => lane0_note_b = Some((i, tw, bl)),
            102 => lane0_note_c = Some((i, tw, bl)),
            103 => lane0_note_d = Some((i, tw, bl)),
            104 => lane0_note_e = Some((i, tw, bl)),
            105 => lane0_note_f = Some((i, tw, bl)),
            106 => lane0_note_g = Some((i, tw, bl)),
            107 => lane0_note_h = Some((i, tw, bl)),
            108 => lane0_note_i = Some((i, tw, bl)),
            109 => lane0_note_j = Some((i, tw, bl)),
            _ => {}
        }
        let sub_seq = i / (SUBTREE_LEAVES as u64);
        let memo_seq = i / (MEMO_NOTES_PER_PAGE as u64);
        let cu = expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_deposit(
                    program_id,
                    payer.pubkey(),
                    POOL_ID,
                    wsol_mint_id(),
                    payer.pubkey(),
                    vault_wsol,
                    spl_token_id(),
                    0,
                    sub_seq,
                    0,
                    memo_seq,
                    None,
                    None,
                    true,
                    false,
                    2_000_000,
                    derive_stealth_owner(alice.spend_pk, tw),
                    bl,
                    &memo,
                    &[],
                ))],
                600_000,
            ),
            "fill Lane 0 to 256-leaf seal boundary",
        );
        if i == 255 {
            cu_deposit_sol_seal_256 = cu;
        }
    }

    // Worst-case Transact Withdraw WSOL Unwrap (2in/2out + relayer fee)
    let ((la_idx, tw_la, bl_la), (lb_idx, tw_lb, bl_lb)) =
        (lane0_note_a.unwrap(), lane0_note_b.unwrap());
    let (paths_uw2, rk_uw2, ri_uw2, sr_uw2) = reconstruct_witness_for_notes(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        &[(0, la_idx), (0, lb_idx)],
        audren_client::scanner::WitnessOptions {
            privacy_mode: audren_client::scanner::SyncPrivacyMode::Strict,
            view_sk: Some(alice.view_sk),
            decoy_epoch_bucket: None,
        },
    )
    .unwrap();
    let (tw_u2a, bl_u2a, memo_u2a) =
        encrypt_note_memo(&alice.view_pk, [0xD1; 32], 1_000_000, &WSOL_MINT).unwrap();
    let (tw_u2b, bl_u2b, memo_u2b) =
        encrypt_note_memo(&alice.view_pk, [0xD2; 32], 1_000_000, &WSOL_MINT).unwrap();
    let mut memos_u2 = Vec::with_capacity(212);
    memos_u2.extend_from_slice(&memo_u2a);
    memos_u2.extend_from_slice(&memo_u2b);
    let ctx_uw2 = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        3,
        0b011,
        ASSET_MODE_PUBLIC,
        true,
        Some(&recipient.pubkey()),
        Some(&relayer.pubkey()),
        &fr_to_be_bytes(&asset_wsol),
        1_800_000,
        200_000,
        &memos_u2,
    );
    let b_uw2 = prover.build_and_prove(
        sr_uw2,
        asset_wsol,
        asset_wsol,
        1_800_000,
        200_000,
        ctx_uw2,
        false,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_la,
                asset_id: asset_wsol,
                amount: 2_000_000,
                blinding: bl_la,
                is_dummy: false,
                merkle_path: paths_uw2[0].clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_lb,
                asset_id: asset_wsol,
                amount: 2_000_000,
                blinding: bl_lb,
                is_dummy: false,
                merkle_path: paths_uw2[1].clone(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_u2a),
                asset_id: asset_wsol,
                amount: 1_000_000,
                blinding: bl_u2a,
            },
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_u2b),
                asset_id: asset_wsol,
                amount: 1_000_000,
                blinding: bl_u2b,
            },
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
        ],
        [0xD3; 32],
    );
    let cu_transact_wd_unwrap_2in2out = expect_ok(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_uw2,
                ri_uw2,
                3,
                0,
                0,
                0,
                0,
                0b011,
                ASSET_MODE_PUBLIC,
                true,
                Some((wsol_mint_id(), vault_wsol, spl_token_id())),
                (None, None, None),
                &b_uw2.proof_192,
                &b_uw2.nf0,
                &b_uw2.nf1,
                &b_uw2.cm0,
                &b_uw2.cm1,
                &b_uw2.cm2,
                1_800_000,
                200_000,
                recipient.pubkey(),
                relayer.pubkey(),
                &memos_u2,
                &[],
            ))],
            600_000,
        ),
        "CU: Transact Withdraw WSOL Unwrap 2in/2out",
    );

    // Worst-case Transact Withdraw WSOL Unwrap (2in/3out, output_mask = 0b111, DISTINCT fee_recipient != payer)
    let fee_treasury = Keypair::new();
    svm.airdrop(&fee_treasury.pubkey(), 1_000_000).unwrap();
    let recip_bal_before_3o = svm.get_balance(&recipient.pubkey()).unwrap();
    let fee_bal_before_3o = svm.get_balance(&fee_treasury.pubkey()).unwrap();
    let ((lc_idx, tw_lc, bl_lc), (ld_idx, tw_ld, bl_ld)) =
        (lane0_note_c.unwrap(), lane0_note_d.unwrap());
    let (paths_uw3, rk_uw3, ri_uw3, sr_uw3) = reconstruct_witness_for_notes(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        &[(0, lc_idx), (0, ld_idx)],
        audren_client::scanner::WitnessOptions {
            privacy_mode: audren_client::scanner::SyncPrivacyMode::Strict,
            view_sk: Some(alice.view_sk),
            decoy_epoch_bucket: None,
        },
    )
    .unwrap();
    let (tw_u3a, bl_u3a, memo_u3a) =
        encrypt_note_memo(&alice.view_pk, [0xE1; 32], 1_000_000, &WSOL_MINT).unwrap();
    let (tw_u3b, bl_u3b, memo_u3b) =
        encrypt_note_memo(&alice.view_pk, [0xE2; 32], 1_000_000, &WSOL_MINT).unwrap();
    let (tw_u3c, bl_u3c, memo_u3c) =
        encrypt_note_memo(&alice.view_pk, [0xE3; 32], 800_000, &WSOL_MINT).unwrap();
    let mut memos_u3 = Vec::with_capacity(318);
    memos_u3.extend_from_slice(&memo_u3a);
    memos_u3.extend_from_slice(&memo_u3b);
    memos_u3.extend_from_slice(&memo_u3c);
    let ctx_uw3 = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        3,
        0b111,
        ASSET_MODE_PUBLIC,
        true,
        Some(&recipient.pubkey()),
        Some(&fee_treasury.pubkey()),
        &fr_to_be_bytes(&asset_wsol),
        1_000_000,
        200_000,
        &memos_u3,
    );
    let b_uw3 = prover.build_and_prove(
        sr_uw3,
        asset_wsol,
        asset_wsol,
        1_000_000,
        200_000,
        ctx_uw3,
        false,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_lc,
                asset_id: asset_wsol,
                amount: 2_000_000,
                blinding: bl_lc,
                is_dummy: false,
                merkle_path: paths_uw3[0].clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_ld,
                asset_id: asset_wsol,
                amount: 2_000_000,
                blinding: bl_ld,
                is_dummy: false,
                merkle_path: paths_uw3[1].clone(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_u3a),
                asset_id: asset_wsol,
                amount: 1_000_000,
                blinding: bl_u3a,
            },
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_u3b),
                asset_id: asset_wsol,
                amount: 1_000_000,
                blinding: bl_u3b,
            },
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_u3c),
                asset_id: asset_wsol,
                amount: 800_000,
                blinding: bl_u3c,
            },
        ],
        [0xE4; 32],
    );
    let cu_transact_wd_unwrap_2in3out_fee = expect_ok(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_uw3,
                ri_uw3,
                3,
                0,
                0,
                0,
                0,
                0b111,
                ASSET_MODE_PUBLIC,
                true,
                Some((wsol_mint_id(), vault_wsol, spl_token_id())),
                (None, None, None),
                &b_uw3.proof_192,
                &b_uw3.nf0,
                &b_uw3.nf1,
                &b_uw3.cm0,
                &b_uw3.cm1,
                &b_uw3.cm2,
                1_000_000,
                200_000,
                recipient.pubkey(),
                fee_treasury.pubkey(),
                &memos_u3,
                &[],
            ))],
            600_000,
        ),
        "CU: Transact Withdraw WSOL Unwrap 2in/3out + distinct fee_recipient",
    );
    assert_eq!(
        svm.get_balance(&recipient.pubkey()).unwrap(),
        recip_bal_before_3o + 1_000_000
    );
    assert_eq!(
        svm.get_balance(&fee_treasury.pubkey()).unwrap(),
        fee_bal_before_3o + 200_000
    );

    // Worst-case Transact Full Exit WSOL Unwrap (2in/0out, READ-ONLY roots, DISTINCT fee_recipient != payer)
    let recip_bal_before_fe2 = svm.get_balance(&recipient.pubkey()).unwrap();
    let fee_bal_before_fe2 = svm.get_balance(&fee_treasury.pubkey()).unwrap();
    let ((li_idx, tw_li, bl_li), (lj_idx, tw_lj, bl_lj)) =
        (lane0_note_i.unwrap(), lane0_note_j.unwrap());
    let (paths_fe_wsol2, rk_few2, ri_few2, sr_few2) = reconstruct_witness_for_notes(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        &[(0, li_idx), (0, lj_idx)],
        audren_client::scanner::WitnessOptions {
            privacy_mode: audren_client::scanner::SyncPrivacyMode::Strict,
            view_sk: Some(alice.view_sk),
            decoy_epoch_bucket: None,
        },
    )
    .unwrap();
    let ctx_few2 = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        3,
        0,
        ASSET_MODE_PUBLIC,
        true,
        Some(&recipient.pubkey()),
        Some(&fee_treasury.pubkey()),
        &fr_to_be_bytes(&asset_wsol),
        3_800_000,
        200_000,
        &[],
    );
    let b_few2 = prover.build_and_prove(
        sr_few2,
        asset_wsol,
        asset_wsol,
        3_800_000,
        200_000,
        ctx_few2,
        false,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_li,
                asset_id: asset_wsol,
                amount: 2_000_000,
                blinding: bl_li,
                is_dummy: false,
                merkle_path: paths_fe_wsol2[0].clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_lj,
                asset_id: asset_wsol,
                amount: 2_000_000,
                blinding: bl_lj,
                is_dummy: false,
                merkle_path: paths_fe_wsol2[1].clone(),
            },
        ],
        [
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(1u64)),
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
        ],
        [0xF5; 32],
    );
    let fe_wsol2_ix = to_svm_ix(&build_transact(
        program_id,
        relayer.pubkey(),
        POOL_ID,
        VK_ID_DEFAULT,
        rk_few2,
        ri_few2,
        3,
        0,
        0,
        0,
        0,
        0,
        ASSET_MODE_PUBLIC,
        true,
        Some((wsol_mint_id(), vault_wsol, spl_token_id())),
        (None, None, None),
        &b_few2.proof_192,
        &b_few2.nf0,
        &b_few2.nf1,
        &b_few2.cm0,
        &b_few2.cm1,
        &b_few2.cm2,
        3_800_000,
        200_000,
        recipient.pubkey(),
        fee_treasury.pubkey(),
        &[],
        &[],
    ));
    assert!(
        !fe_wsol2_ix.accounts[2].is_writable,
        "2in/0out WSOL full exit must mark GlobalRootHistory READ-ONLY"
    );
    let cu_transact_full_exit_wsol_2in_fee = expect_ok(
        send_v1(&mut svm, &relayer, &[], &[fe_wsol2_ix], CU_LIMIT_TRANSACT_FULL_EXIT),
        "CU: Transact Full Exit WSOL 2in/0out + distinct fee_recipient",
    );
    assert_eq!(
        svm.get_balance(&recipient.pubkey()).unwrap(),
        recip_bal_before_fe2 + 3_800_000
    );
    assert_eq!(
        svm.get_balance(&fee_treasury.pubkey()).unwrap(),
        fee_bal_before_fe2 + 200_000
    );

    // Worst-case Transact Full Exit non-hook Token-2022 TransferFee (2in/0out, READ-ONLY roots, relayer fee > 0)
    let t22_fee_mint = create_t22_fee_mint(&mut svm, &payer, 6, 250, 5_000_000);
    let vault_t22f = create_canonical_ata(&mut svm, &payer, va, t22_fee_mint, token_2022_id());
    let payer_t22f =
        create_canonical_ata(&mut svm, &payer, payer.pubkey(), t22_fee_mint, token_2022_id());
    let recip_t22f =
        create_canonical_ata(&mut svm, &payer, recipient.pubkey(), t22_fee_mint, token_2022_id());
    let relayer_t22f =
        create_canonical_ata(&mut svm, &payer, relayer.pubkey(), t22_fee_mint, token_2022_id());
    mint_to(&mut svm, &payer, token_2022_id(), t22_fee_mint, payer_t22f, 40_000_000);
    let asset_t22f = asset_id_for_mint(Some(&t22_fee_mint));
    let t22f_idx0 = lane_next_leaf(&svm, &program_id, 1);
    let (tw_tf0, bl_tf0, memo_tf0) =
        encrypt_note_memo(&alice.view_pk, [0xF6; 32], 19_500_000, &t22_fee_mint.to_bytes()).unwrap();
    let (tw_tf1, bl_tf1, memo_tf1) =
        encrypt_note_memo(&alice.view_pk, [0xF7; 32], 19_500_000, &t22_fee_mint.to_bytes()).unwrap();
    for (tw, bl, memo) in [(tw_tf0, bl_tf0, &memo_tf0), (tw_tf1, bl_tf1, &memo_tf1)] {
        expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_deposit(
                    program_id,
                    payer.pubkey(),
                    POOL_ID,
                    t22_fee_mint,
                    payer_t22f,
                    vault_t22f,
                    token_2022_id(),
                    1,
                    0,
                    0,
                    0,
                    None,
                    None,
                    false,
                    false,
                    20_000_000,
                    derive_stealth_owner(alice.spend_pk, tw),
                    bl,
                    memo,
                    &[],
                ))],
                600_000,
            ),
            "deposit non-hook T22 TransferFee notes for 2in/0out full exit",
        );
    }
    let (paths_t22f, rk_t22f, ri_t22f, sr_t22f) = reconstruct_witness_for_notes(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        &[(1, t22f_idx0), (1, t22f_idx0 + 1)],
        audren_client::scanner::WitnessOptions {
            privacy_mode: audren_client::scanner::SyncPrivacyMode::Strict,
            view_sk: Some(alice.view_sk),
            decoy_epoch_bucket: None,
        },
    )
    .unwrap();
    let ctx_t22f = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        1,
        0,
        ASSET_MODE_PUBLIC,
        false,
        Some(&recip_t22f),
        Some(&relayer_t22f),
        &fr_to_be_bytes(&asset_t22f),
        35_000_000,
        4_000_000,
        &[],
    );
    let b_t22f = prover.build_and_prove(
        sr_t22f,
        asset_t22f,
        asset_t22f,
        35_000_000,
        4_000_000,
        ctx_t22f,
        false,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_tf0,
                asset_id: asset_t22f,
                amount: 19_500_000,
                blinding: bl_tf0,
                is_dummy: false,
                merkle_path: paths_t22f[0].clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_tf1,
                asset_id: asset_t22f,
                amount: 19_500_000,
                blinding: bl_tf1,
                is_dummy: false,
                merkle_path: paths_t22f[1].clone(),
            },
        ],
        [
            JoinSplitOutputWitness::dummy(asset_t22f, Fr::from(1u64)),
            JoinSplitOutputWitness::dummy(asset_t22f, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_t22f, Fr::from(3u64)),
        ],
        [0xF8; 32],
    );
    let fe_t22f_ix = to_svm_ix(&build_transact(
        program_id,
        relayer.pubkey(),
        POOL_ID,
        VK_ID_DEFAULT,
        rk_t22f,
        ri_t22f,
        1,
        0,
        0,
        0,
        0,
        0,
        ASSET_MODE_PUBLIC,
        false,
        Some((t22_fee_mint, vault_t22f, token_2022_id())),
        (None, None, None),
        &b_t22f.proof_192,
        &b_t22f.nf0,
        &b_t22f.nf1,
        &b_t22f.cm0,
        &b_t22f.cm1,
        &b_t22f.cm2,
        35_000_000,
        4_000_000,
        recip_t22f,
        relayer_t22f,
        &[],
        &[],
    ));
    assert!(
        !fe_t22f_ix.accounts[2].is_writable,
        "2in/0out non-hook T22 full exit must mark GlobalRootHistory READ-ONLY"
    );
    let cu_transact_full_exit_t22_fee_2in = expect_ok(
        send_v1(&mut svm, &relayer, &[], &[fe_t22f_ix], CU_LIMIT_TRANSACT_FULL_EXIT),
        "CU: Transact Full Exit non-hook T22 TransferFee 2in/0out",
    );
    assert_eq!(token_balance(&svm, &recip_t22f), 34_125_000);
    assert_eq!(token_balance(&svm, &relayer_t22f), 3_900_000);
    assert_eq!(token_balance(&svm, &vault_t22f), 0);

    // Worst-case Transact Withdraw T22 Fee+Hook (2in/2out + relayer fee)
    let (tw_fh2a, bl_fh2a, memo_fh2a) =
        encrypt_note_memo(&alice.view_pk, [0xD4; 32], 19_500_000, &fh_mint.to_bytes()).unwrap();
    let (tw_fh2b, bl_fh2b, memo_fh2b) =
        encrypt_note_memo(&alice.view_pk, [0xD5; 32], 19_500_000, &fh_mint.to_bytes()).unwrap();
    for (tw, bl, memo) in [(tw_fh2a, bl_fh2a, &memo_fh2a), (tw_fh2b, bl_fh2b, &memo_fh2b)] {
        expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_deposit(
                    program_id,
                    payer.pubkey(),
                    POOL_ID,
                    fh_mint,
                    payer_fh,
                    vault_fh,
                    token_2022_id(),
                    2,
                    0,
                    0,
                    0,
                    None,
                    None,
                    false,
                    false,
                    20_000_000,
                    derive_stealth_owner(alice.spend_pk, tw),
                    bl,
                    memo,
                    &fh_metas,
                ))],
                600_000,
            ),
            "deposit T22 Fee+Hook notes for 2in/2out withdraw",
        );
    }
    let (paths_fh2, rk_fh2, ri_fh2, sr_fh2) = reconstruct_witness_for_notes(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        &[(2, 1), (2, 2)],
        audren_client::scanner::WitnessOptions {
            privacy_mode: audren_client::scanner::SyncPrivacyMode::Strict,
            view_sk: Some(alice.view_sk),
            decoy_epoch_bucket: None,
        },
    )
    .unwrap();
    let (tw_fho0, bl_fho0, memo_fho0) =
        encrypt_note_memo(&alice.view_pk, [0xD6; 32], 5_000_000, &fh_mint.to_bytes()).unwrap();
    let (tw_fho1, bl_fho1, memo_fho1) =
        encrypt_note_memo(&alice.view_pk, [0xD7; 32], 5_000_000, &fh_mint.to_bytes()).unwrap();
    let mut memos_fh2 = Vec::with_capacity(212);
    memos_fh2.extend_from_slice(&memo_fho0);
    memos_fh2.extend_from_slice(&memo_fho1);
    let ctx_fh2 = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        2,
        0b011,
        ASSET_MODE_PUBLIC,
        false,
        Some(&recip_fh),
        Some(&relayer_fh),
        &fr_to_be_bytes(&asset_fh),
        27_000_000,
        2_000_000,
        &memos_fh2,
    );
    let b_fh2 = prover.build_and_prove(
        sr_fh2,
        asset_fh,
        asset_fh,
        27_000_000,
        2_000_000,
        ctx_fh2,
        false,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_fh2a,
                asset_id: asset_fh,
                amount: 19_500_000,
                blinding: bl_fh2a,
                is_dummy: false,
                merkle_path: paths_fh2[0].clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_fh2b,
                asset_id: asset_fh,
                amount: 19_500_000,
                blinding: bl_fh2b,
                is_dummy: false,
                merkle_path: paths_fh2[1].clone(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_fho0),
                asset_id: asset_fh,
                amount: 5_000_000,
                blinding: bl_fho0,
            },
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_fho1),
                asset_id: asset_fh,
                amount: 5_000_000,
                blinding: bl_fho1,
            },
            JoinSplitOutputWitness::dummy(asset_fh, Fr::from(3u64)),
        ],
        [0xD8; 32],
    );
    let cu_transact_wd_hook_2in2out = expect_ok(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_fh2,
                ri_fh2,
                2,
                0,
                0,
                0,
                0,
                0b011,
                ASSET_MODE_PUBLIC,
                false,
                Some((fh_mint, vault_fh, token_2022_id())),
                (None, None, None),
                &b_fh2.proof_192,
                &b_fh2.nf0,
                &b_fh2.nf1,
                &b_fh2.cm0,
                &b_fh2.cm1,
                &b_fh2.cm2,
                27_000_000,
                2_000_000,
                recip_fh,
                relayer_fh,
                &memos_fh2,
                &fh_metas,
            ))],
            600_000,
        ),
        "CU: Transact Withdraw T22 Hook 2in/2out",
    );

    // Worst-case Transact Withdraw T22 Fee+Hook (2in/3out, output_mask = 0b111 + relayer fee)
    mint_to(&mut svm, &payer, token_2022_id(), fh_mint, payer_fh, 40_000_000);
    let fh3_idx0 = lane_next_leaf(&svm, &program_id, 2);
    let (tw_fh3a, bl_fh3a, memo_fh3a) =
        encrypt_note_memo(&alice.view_pk, [0xE5; 32], 19_500_000, &fh_mint.to_bytes()).unwrap();
    let (tw_fh3b, bl_fh3b, memo_fh3b) =
        encrypt_note_memo(&alice.view_pk, [0xE6; 32], 19_500_000, &fh_mint.to_bytes()).unwrap();
    for (tw, bl, memo) in [(tw_fh3a, bl_fh3a, &memo_fh3a), (tw_fh3b, bl_fh3b, &memo_fh3b)] {
        expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_deposit(
                    program_id,
                    payer.pubkey(),
                    POOL_ID,
                    fh_mint,
                    payer_fh,
                    vault_fh,
                    token_2022_id(),
                    2,
                    0,
                    0,
                    0,
                    None,
                    None,
                    false,
                    false,
                    20_000_000,
                    derive_stealth_owner(alice.spend_pk, tw),
                    bl,
                    memo,
                    &fh_metas,
                ))],
                600_000,
            ),
            "deposit T22 Fee+Hook notes for 2in/3out withdraw",
        );
    }
    let (paths_fh3, rk_fh3, ri_fh3, sr_fh3) = reconstruct_witness_for_notes(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        &[(2, fh3_idx0), (2, fh3_idx0 + 1)],
        audren_client::scanner::WitnessOptions {
            privacy_mode: audren_client::scanner::SyncPrivacyMode::Strict,
            view_sk: Some(alice.view_sk),
            decoy_epoch_bucket: None,
        },
    )
    .unwrap();
    let (tw_fh3o0, bl_fh3o0, memo_fh3o0) =
        encrypt_note_memo(&alice.view_pk, [0xE7; 32], 5_000_000, &fh_mint.to_bytes()).unwrap();
    let (tw_fh3o1, bl_fh3o1, memo_fh3o1) =
        encrypt_note_memo(&alice.view_pk, [0xE8; 32], 5_000_000, &fh_mint.to_bytes()).unwrap();
    let (tw_fh3o2, bl_fh3o2, memo_fh3o2) =
        encrypt_note_memo(&alice.view_pk, [0xE9; 32], 5_000_000, &fh_mint.to_bytes()).unwrap();
    let mut memos_fh3 = Vec::with_capacity(318);
    memos_fh3.extend_from_slice(&memo_fh3o0);
    memos_fh3.extend_from_slice(&memo_fh3o1);
    memos_fh3.extend_from_slice(&memo_fh3o2);
    let ctx_fh3 = compute_transact_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        2,
        0b111,
        ASSET_MODE_PUBLIC,
        false,
        Some(&recip_fh),
        Some(&relayer_fh),
        &fr_to_be_bytes(&asset_fh),
        22_000_000,
        2_000_000,
        &memos_fh3,
    );
    let b_fh3 = prover.build_and_prove(
        sr_fh3,
        asset_fh,
        asset_fh,
        22_000_000,
        2_000_000,
        ctx_fh3,
        false,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_fh3a,
                asset_id: asset_fh,
                amount: 19_500_000,
                blinding: bl_fh3a,
                is_dummy: false,
                merkle_path: paths_fh3[0].clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_fh3b,
                asset_id: asset_fh,
                amount: 19_500_000,
                blinding: bl_fh3b,
                is_dummy: false,
                merkle_path: paths_fh3[1].clone(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_fh3o0),
                asset_id: asset_fh,
                amount: 5_000_000,
                blinding: bl_fh3o0,
            },
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_fh3o1),
                asset_id: asset_fh,
                amount: 5_000_000,
                blinding: bl_fh3o1,
            },
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_fh3o2),
                asset_id: asset_fh,
                amount: 5_000_000,
                blinding: bl_fh3o2,
            },
        ],
        [0xEA; 32],
    );
    let cu_transact_wd_hook_2in3out = expect_ok(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_fh3,
                ri_fh3,
                2,
                0,
                0,
                0,
                0,
                0b111,
                ASSET_MODE_PUBLIC,
                false,
                Some((fh_mint, vault_fh, token_2022_id())),
                (None, None, None),
                &b_fh3.proof_192,
                &b_fh3.nf0,
                &b_fh3.nf1,
                &b_fh3.cm0,
                &b_fh3.cm1,
                &b_fh3.cm2,
                22_000_000,
                2_000_000,
                recip_fh,
                relayer_fh,
                &memos_fh3,
                &fh_metas,
            ))],
            600_000,
        ),
        "CU: Transact Withdraw T22 Hook 2in/3out",
    );

    // Worst-case ExecViaEscrow: 2in / change_mask = 0b11 (2 change + 1 dynamic out) / relayer_fee > 0
    let ((le_idx, tw_le, bl_le), (lf_idx, tw_lf, bl_lf)) =
        (lane0_note_e.unwrap(), lane0_note_f.unwrap());
    let (paths_ex2, rk_ex2, ri_ex2, sr_ex2) = reconstruct_witness_for_notes(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        &[(0, le_idx), (0, lf_idx)],
        audren_client::scanner::WitnessOptions {
            privacy_mode: audren_client::scanner::SyncPrivacyMode::Strict,
            view_sk: Some(alice.view_sk),
            decoy_epoch_bucket: None,
        },
    )
    .unwrap();
    let (tw_ec0, bl_ec0, memo_ec0) =
        encrypt_note_memo(&alice.view_pk, [0xEB; 32], 1_000_000, &WSOL_MINT).unwrap();
    let (tw_ec1, bl_ec1, memo_ec1) =
        encrypt_note_memo(&alice.view_pk, [0xEC; 32], 1_000_000, &WSOL_MINT).unwrap();
    let mut chg_memos_2 = Vec::with_capacity(212);
    chg_memos_2.extend_from_slice(&memo_ec0);
    chg_memos_2.extend_from_slice(&memo_ec1);
    let (dtw_ex2, dbl_ex2, dhead_ex2, dmask_ex2) =
        prepare_dynamic_swap_memo(&alice.view_pk, [0xED; 32]).unwrap();
    let ost_ex2 = fr_to_be_bytes(&derive_stealth_owner(alice.spend_pk, dtw_ex2));
    let obl_ex2 = fr_to_be_bytes(&dbl_ex2);
    let swap_data_ex2 = dex_swap_spl_to_spl_data(0, 2_000_000, 2_000_000, 9, 6);
    let swap_accs_ex2 = vec![
        AudrenAccountMeta::writable(esc0, false),
        AudrenAccountMeta::writable(esc0_wsol, false),
        AudrenAccountMeta::writable(dex_wsol, false),
        AudrenAccountMeta::writable(dex_pool, false),
        AudrenAccountMeta::writable(dex_usdc, false),
        AudrenAccountMeta::writable(esc0_usdc, false),
        AudrenAccountMeta::readonly(wsol_mint_id(), false),
        AudrenAccountMeta::readonly(usdc_mint, false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
        AudrenAccountMeta::readonly(spl_token_id(), false),
    ];
    let ctx_ex2 = compute_exec_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        3,
        0,
        0b11,
        true,
        &asset_id_bytes_for_mint(None),
        2_000_000,
        200_000,
        Some(&relayer_usdc),
        &fr_to_be_bytes(&asset_usdc),
        1_800_000,
        &router_id,
        &swap_accs_ex2,
        &[],
        &ost_ex2,
        &obl_ex2,
        &dhead_ex2,
        &dmask_ex2,
        &swap_data_ex2,
        &chg_memos_2,
    );
    let b_ex2 = prover.build_and_prove(
        sr_ex2,
        asset_wsol,
        asset_wsol,
        2_000_000,
        0,
        ctx_ex2,
        false,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_le,
                asset_id: asset_wsol,
                amount: 2_000_000,
                blinding: bl_le,
                is_dummy: false,
                merkle_path: paths_ex2[0].clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_lf,
                asset_id: asset_wsol,
                amount: 2_000_000,
                blinding: bl_lf,
                is_dummy: false,
                merkle_path: paths_ex2[1].clone(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_ec0),
                asset_id: asset_wsol,
                amount: 1_000_000,
                blinding: bl_ec0,
            },
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_ec1),
                asset_id: asset_wsol,
                amount: 1_000_000,
                blinding: bl_ec1,
            },
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
        ],
        [0xEE; 32],
    );
    let relayer_usdc_before_ex2 = token_balance(&svm, &relayer_usdc);
    let vault_usdc_before_ex2 = token_balance(&svm, &vault_usdc);
    let cu_exec_2in_2chg_fee = expect_ok(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_exec_via_escrow(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_ex2,
                ri_ex2,
                3,
                0,
                0,
                0,
                0,
                0,
                0b11,
                true,
                (wsol_mint_id(), vault_wsol, esc0_wsol, spl_token_id()),
                (usdc_mint, vault_usdc, esc0_usdc, spl_token_id()),
                200_000,
                Some(relayer_usdc),
                (None, None, None),
                &b_ex2.proof_192,
                &b_ex2.nf0,
                &b_ex2.nf1,
                &b_ex2.cm0,
                &b_ex2.cm1,
                &b_ex2.cm2,
                2_000_000,
                1_800_000,
                &ost_ex2,
                &obl_ex2,
                &dhead_ex2,
                &dmask_ex2,
                router_id,
                &swap_data_ex2,
                swap_accs_ex2.clone(),
                &[],
                &chg_memos_2,
            ))],
            600_000,
        ),
        "CU: ExecViaEscrow 2in/2chg + relayer_fee (10 router accs)",
    );
    assert_eq!(token_balance(&svm, &relayer_usdc), relayer_usdc_before_ex2 + 200_000);
    assert_eq!(token_balance(&svm, &vault_usdc), vault_usdc_before_ex2 + 1_800_000);

    // Worst-case ExecViaEscrow with 30 router accounts (10 mock router + 20 extra readonly route accounts)
    let ((lg_idx, tw_lg, bl_lg), (lh_idx, tw_lh, bl_lh)) =
        (lane0_note_g.unwrap(), lane0_note_h.unwrap());
    let (paths_ex3, rk_ex3, ri_ex3, sr_ex3) = reconstruct_witness_for_notes(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        &[(0, lg_idx), (0, lh_idx)],
        audren_client::scanner::WitnessOptions {
            privacy_mode: audren_client::scanner::SyncPrivacyMode::Strict,
            view_sk: Some(alice.view_sk),
            decoy_epoch_bucket: None,
        },
    )
    .unwrap();
    let (tw_ec2, bl_ec2, memo_ec2) =
        encrypt_note_memo(&alice.view_pk, [0xF1; 32], 1_000_000, &WSOL_MINT).unwrap();
    let (tw_ec3, bl_ec3, memo_ec3) =
        encrypt_note_memo(&alice.view_pk, [0xF2; 32], 1_000_000, &WSOL_MINT).unwrap();
    let mut chg_memos_3 = Vec::with_capacity(212);
    chg_memos_3.extend_from_slice(&memo_ec2);
    chg_memos_3.extend_from_slice(&memo_ec3);
    let (dtw_ex3, dbl_ex3, dhead_ex3, dmask_ex3) =
        prepare_dynamic_swap_memo(&alice.view_pk, [0xF3; 32]).unwrap();
    let ost_ex3 = fr_to_be_bytes(&derive_stealth_owner(alice.spend_pk, dtw_ex3));
    let obl_ex3 = fr_to_be_bytes(&dbl_ex3);
    let mut swap_accs_ex3 = swap_accs_ex2;
    for _ in 0..20 {
        swap_accs_ex3.push(AudrenAccountMeta::readonly(Keypair::new().pubkey(), false));
    }
    let ctx_ex3 = compute_exec_ctx_hash(
        &program_id,
        POOL_ID,
        VK_ID_DEFAULT,
        3,
        0,
        0b11,
        true,
        &asset_id_bytes_for_mint(None),
        2_000_000,
        200_000,
        Some(&relayer_usdc),
        &fr_to_be_bytes(&asset_usdc),
        1_800_000,
        &router_id,
        &swap_accs_ex3,
        &[],
        &ost_ex3,
        &obl_ex3,
        &dhead_ex3,
        &dmask_ex3,
        &swap_data_ex2,
        &chg_memos_3,
    );
    let b_ex3 = prover.build_and_prove(
        sr_ex3,
        asset_wsol,
        asset_wsol,
        2_000_000,
        0,
        ctx_ex3,
        false,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_lg,
                asset_id: asset_wsol,
                amount: 2_000_000,
                blinding: bl_lg,
                is_dummy: false,
                merkle_path: paths_ex3[0].clone(),
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_lh,
                asset_id: asset_wsol,
                amount: 2_000_000,
                blinding: bl_lh,
                is_dummy: false,
                merkle_path: paths_ex3[1].clone(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_ec2),
                asset_id: asset_wsol,
                amount: 1_000_000,
                blinding: bl_ec2,
            },
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_ec3),
                asset_id: asset_wsol,
                amount: 1_000_000,
                blinding: bl_ec3,
            },
            JoinSplitOutputWitness::dummy(asset_wsol, Fr::from(3u64)),
        ],
        [0xF4; 32],
    );
    let cu_exec_2in_2chg_fee_30accs = expect_ok(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_exec_via_escrow(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                rk_ex3,
                ri_ex3,
                3,
                0,
                0,
                0,
                0,
                0,
                0b11,
                true,
                (wsol_mint_id(), vault_wsol, esc0_wsol, spl_token_id()),
                (usdc_mint, vault_usdc, esc0_usdc, spl_token_id()),
                200_000,
                Some(relayer_usdc),
                (None, None, None),
                &b_ex3.proof_192,
                &b_ex3.nf0,
                &b_ex3.nf1,
                &b_ex3.cm0,
                &b_ex3.cm1,
                &b_ex3.cm2,
                2_000_000,
                1_800_000,
                &ost_ex3,
                &obl_ex3,
                &dhead_ex3,
                &dmask_ex3,
                router_id,
                &swap_data_ex2,
                swap_accs_ex3,
                &[],
                &chg_memos_3,
            ))],
            600_000,
        ),
        "CU: ExecViaEscrow 2in/2chg + relayer_fee (30 router accs)",
    );

    // Also measure InitRootHistory (4 populated lanes) and worst-case InitRootHistory (16 active lanes)
    let (roots_pda_cu, _) = derive_roots_pda(&program_id, POOL_ID);
    svm.set_account(roots_pda_cu, Account::default()).unwrap();
    let cu_init_root_history = expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_init_root_history(
                program_id,
                payer.pubkey(),
                POOL_ID,
                ROOT_EPOCH_INTERVAL,
                4,
            ))],
            600_000,
        ),
        "CU: InitRootHistory (4 lanes)",
    );

    // Expand pool to all 16 active lanes and measure worst-case InitRootHistory (16 lanes)
    for l in 4u8..16u8 {
        expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_init_lane(program_id, payer.pubkey(), POOL_ID, l))],
                600_000,
            ),
            "InitLane 4..16 for InitRootHistory 16-lane CU bench",
        );
    }
    svm.set_account(roots_pda_cu, Account::default()).unwrap();
    let cu_init_root_history_16 = expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_init_root_history(
                program_id,
                payer.pubkey(),
                POOL_ID,
                ROOT_EPOCH_INTERVAL,
                16,
            ))],
            600_000,
        ),
        "CU: InitRootHistory (16 lanes)",
    );
    let roots_16 =
        GlobalRootHistory::decode(&svm.get_account(&roots_pda_cu).unwrap().data).unwrap();
    assert_eq!(roots_16.latest_lane_counts[0], 256);

    let _ = (
        GlobalRootHistory::decode,
        ROOT_HISTORY_LEN,
        recommended_cu_limit_init_pool,
        recommended_cu_limit_init_lane,
        recommended_cu_limit_open_page,
        recommended_cu_limit_transact,
        recommended_cu_limit_exec_via_escrow,
    );

    let rows: [(&str, u64, u32); 21] = [
        ("InitPool", cu_init_pool, CU_LIMIT_INIT_POOL),
        ("InitLane", cu_init_lane, CU_LIMIT_INIT_LANE),
        ("InitRootHistory (4 lanes)", cu_init_root_history, CU_LIMIT_INIT_ROOT_HISTORY),
        ("InitRootHistory (16 lanes)", cu_init_root_history_16, CU_LIMIT_INIT_ROOT_HISTORY),
        ("OpenPage (MEMO)", cu_open_page, CU_LIMIT_OPEN_PAGE),
        ("Deposit (Native SOL)", cu_deposit_sol, CU_LIMIT_DEPOSIT),
        ("Deposit (SOL 256-leaf seal)", cu_deposit_sol_seal_256, CU_LIMIT_DEPOSIT),
        ("Auto-OpenPage + Deposit", cu_auto_dep, recommended_cu_limit_deposit(false, 1)),
        ("Deposit (Classic SPL)", cu_deposit_spl, CU_LIMIT_DEPOSIT),
        ("Deposit (T22 Fee+Hook)", cu_deposit_t22_fh, CU_LIMIT_DEPOSIT_HOOK),
        ("Transact (Private 2in/3out)", cu_transact_2in3out, CU_LIMIT_TRANSACT_PRIVATE),
        ("Transact (Withdraw SPL 1in/1o)", cu_transact_wd_spl, CU_LIMIT_TRANSACT_WITHDRAW),
        ("Transact (Withdraw WSOL 1in/1o)", cu_transact_wd_unwrap, CU_LIMIT_TRANSACT_WITHDRAW),
        ("Transact (Withdraw WSOL 2in/2o)", cu_transact_wd_unwrap_2in2out, CU_LIMIT_TRANSACT_WITHDRAW),
        ("Transact (Withdraw WSOL 2in/3o+f)", cu_transact_wd_unwrap_2in3out_fee, CU_LIMIT_TRANSACT_WITHDRAW),
        ("Transact (Full Exit 1in/0o RO)", cu_transact_full_exit, CU_LIMIT_TRANSACT_FULL_EXIT),
        ("Transact (Full Exit WSOL 2in+f)", cu_transact_full_exit_wsol_2in_fee, CU_LIMIT_TRANSACT_FULL_EXIT),
        ("Transact (Full Exit T22Fee 2in)", cu_transact_full_exit_t22_fee_2in, CU_LIMIT_TRANSACT_FULL_EXIT),
        ("Transact (Withdraw T22 1in/0o)", cu_transact_wd_hook, CU_LIMIT_TRANSACT_WITHDRAW_HOOK),
        ("Transact (Withdraw T22 2in/2o)", cu_transact_wd_hook_2in2out, CU_LIMIT_TRANSACT_WITHDRAW_HOOK),
        ("Transact (Withdraw T22 2in/3o)", cu_transact_wd_hook_2in3out, CU_LIMIT_TRANSACT_WITHDRAW_HOOK),
    ];
    println!("\n  === EMPIRICAL LITESVM CU MEASUREMENT TABLE ===");
    let mut over_budget = Vec::new();
    for (name, measured, budget) in rows {
        let status = if measured <= budget as u64 { "OK" } else { "OVER BUDGET!" };
        println!("  | {name:<34} | measured={measured:>7} | budget={budget:>7} | {status}");
        if measured > budget as u64 {
            over_budget.push((name, measured, budget));
        }
    }
    for (name, measured) in [
        ("ExecViaEscrow (1in/0chg/0fee)", cu_exec),
        ("ExecViaEscrow (2in/2chg+fee,10a)", cu_exec_2in_2chg_fee),
        ("ExecViaEscrow (2in/2chg+fee,30a)", cu_exec_2in_2chg_fee_30accs),
    ] {
        let status = if measured <= CU_LIMIT_EXEC_VIA_ESCROW_BASE as u64 {
            "OK (incl. mock router CPI)"
        } else {
            "OVER BASE!"
        };
        println!(
            "  | {name:<34} | measured={measured:>7} | base  ={:>7} | {status}",
            CU_LIMIT_EXEC_VIA_ESCROW_BASE
        );
        if measured > CU_LIMIT_EXEC_VIA_ESCROW_BASE as u64 {
            over_budget.push((name, measured, CU_LIMIT_EXEC_VIA_ESCROW_BASE));
        }
    }
    println!("  ================================================\n");
    assert!(
        over_budget.is_empty(),
        "Some instructions exceeded tight CU_LIMIT_* budgets: {over_budget:?}"
    );
    println!("  [V1.3.0 TEST D PASSED] Auto-OpenPage >=90% lookahead (100% subsidized) & all CU limits verified");
}
