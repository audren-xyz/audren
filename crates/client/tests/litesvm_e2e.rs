//! End-to-End LiteSVM Integration & Security Regression Suite for Audren v1
//! (sBPFv3 + BN254 Groth16 + Transaction v1 `0x81`).
//!
//! Executes real compiled `audren.so`, `audren_mock_router.so`, and `audren_mock_hook.so`
//! sBPFv3 binaries inside LiteSVM (`agave-feature-set 4.3.0`) over real Solana Transaction v1
//! (`0x81`, `4,096 B`) wire messages.

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
            ASSET_MODE_PRIVATE, ASSET_MODE_PUBLIC, OPEN_PAGE_KIND_MEMO, OPEN_PAGE_KIND_SUBTREE,
            VK_ID_DEFAULT,
        },
        layout::{
            read_32, read_u16, read_u64, LaneTreeHeader, PoolState, LN_OFF_NEXT_LEAF, MEMO_CT_LEN,
            MEMO_NOTES_PER_PAGE, MEMO_PAGE_LEN, MM_OFF_CIPHERTEXTS, MM_OFF_COUNT,
            MM_OFF_EPHEMERAL_PKS, MM_OFF_VIEW_TAGS, SB_OFF_LEAVES,
            SUBROOT_PAGE_LEN, SUBTREE_LEAVES, SUBTREE_PAGE_LEN,
        },
        ASSOCIATED_TOKEN_PROGRAM_ID, AUDREN_PROGRAM_ID, CLASSIC_TOKEN_PROGRAM_ID, NUM_LANES,
        PROTOCOL_VERSION, SYSTEM_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, WSOL_MINT,
    },
    instructions::{
        build_deposit, build_exec_via_escrow, build_init_lane, build_init_pool, build_open_page,
        build_publish_checkpoint, build_set_paused, build_transact, build_update_pool,
        compute_exec_ctx_hash, compute_page_rollovers, compute_transact_ctx_hash,
        deterministic_note_rent_fee, AudrenAccountMeta, AudrenInstruction, UpdatePoolAction,
    },
    keys::{
        check_memo_view_tag, encrypt_note_memo, encrypt_note_memo_with_payment_id,
        prepare_dynamic_swap_memo, try_decrypt_and_verify_memo_entry, AudrenAddress, AudrenKeys,
    },
    pda::{
        derive_ata, derive_checkpoint_pda, derive_escrow_pda, derive_lane_pda, derive_memo_pda,
        derive_nf_page_pda, derive_pool_pda, derive_subtree_pda, derive_unwrap_pda,
        derive_vault_auth_pda,
    },
    prover::{asset_id_bytes_for_mint, asset_id_for_mint, AudrenProver},
    router::prepare_escrow_accounts_for_audren,
    scanner::{decode_root_checkpoint, reconstruct_witness_with},
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
const CKPT_INTERVAL: u64 = 8;
const MAX_CKPT_AGE: u64 = 1_536;
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

/// Bootstrap Pool #0 + `initial_lanes` active lanes + canonical WSOL `vault_ata`.
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
                CKPT_INTERVAL,
                MAX_CKPT_AGE,
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
                CKPT_INTERVAL,
                MAX_CKPT_AGE,
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

    // Wrong lane count in PublishCheckpoint rejected (6000)
    expect_err_code(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_publish_checkpoint(
                program_id,
                payer.pubkey(),
                POOL_ID,
                13,
                3,
            ))],
            200_000,
        ),
        6000,
        "wrong lane count checkpoint",
    );

    let cu_ckpt_4 = expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_publish_checkpoint(
                program_id,
                payer.pubkey(),
                POOL_ID,
                13,
                4,
            ))],
            200_000,
        ),
        "PublishCheckpoint 4-lane",
    );
    let ckpt4 = decode_root_checkpoint(
        &svm.get_account(&derive_checkpoint_pda(&program_id, POOL_ID, 13).0)
            .unwrap()
            .data,
    )
    .unwrap();
    assert_eq!(ckpt4.version, PROTOCOL_VERSION);
    let zeros = zero_hashes_4ary();
    for l in 4..NUM_LANES {
        assert_eq!(ckpt4.lane_roots[l], fr_to_be_bytes(&zeros[18]));
    }

    // Expand 4 -> 8 -> 16 and verify bit-for-bit super_root continuity!
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
    svm.warp_to_slot(112); // epoch 14
    let cu_ckpt_8 = expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_publish_checkpoint(
                program_id,
                payer.pubkey(),
                POOL_ID,
                14,
                8,
            ))],
            200_000,
        ),
        "PublishCheckpoint 8-lane",
    );
    let ckpt8 = decode_root_checkpoint(
        &svm.get_account(&derive_checkpoint_pda(&program_id, POOL_ID, 14).0)
            .unwrap()
            .data,
    )
    .unwrap();
    assert_eq!(ckpt4.super_root, ckpt8.super_root);

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
    svm.warp_to_slot(120); // epoch 15
    let cu_ckpt_16 = expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_publish_checkpoint(
                program_id,
                payer.pubkey(),
                POOL_ID,
                15,
                16,
            ))],
            200_000,
        ),
        "PublishCheckpoint 16-lane",
    );
    let ckpt16 = decode_root_checkpoint(
        &svm.get_account(&derive_checkpoint_pda(&program_id, POOL_ID, 15).0)
            .unwrap()
            .data,
    )
    .unwrap();
    assert_eq!(ckpt8.super_root, ckpt16.super_root);

    // Sync CompactWalletStore via sequential page ingestion, persist to JSON, reload, and spend
    // a 4-lane note under ckpt16 into newly activated lane 14!
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
    let (super_root, path0) = reloaded.build_witness_for_note(&note0, &ckpt16).unwrap();

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
                15,
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
                15,
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
        "  [TEST 1 PASSED] Ckpt 4/8/16={cu_ckpt_4}/{cu_ckpt_8}/{cu_ckpt_16} CU | Spend={spend_cu} CU"
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

    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_publish_checkpoint(
                program_id,
                payer.pubkey(),
                POOL_ID,
                13,
                4,
            ))],
            200_000,
        ),
        "PublishCheckpoint",
    );

    // Relayed partial WSOL unwrap: 0.9 SOL -> fresh 0-lamport session0, 0.01 SOL -> relayer, 1.09 WSOL change -> alice
    let (_, sr, path_w) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        13,
        1,
        0,
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
                13,
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

    // Pause pool: partial WSOL unwrap blocked (6027), FULL WSOL unwrap exit bypasses pause!
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
    svm.warp_to_slot(112); // epoch 14 — PublishCheckpoint is pause-exempt!
    expect_ok(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_publish_checkpoint(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                14,
                4,
            ))],
            200_000,
        ),
        "pause-exempt PublishCheckpoint",
    );

    let (_, sr2, path_chg) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        14,
        1,
        1,
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
    let cu_full = expect_ok(
        send_v1(
            &mut svm,
            &relayer,
            &[],
            &[to_svm_ix(&build_transact(
                program_id,
                relayer.pubkey(),
                POOL_ID,
                VK_ID_DEFAULT,
                14,
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
            ))],
            300_000,
        ),
        "pause-exempt FULL WSOL unwrap exit",
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
                    AudrenAccountMeta::readonly(hook_id, false),
                ],
            ))],
            250_000,
        ),
        "Deposit active TransferHook",
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
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_publish_checkpoint(
                program_id,
                payer.pubkey(),
                POOL_ID,
                13,
                4,
            ))],
            200_000,
        ),
        "PublishCheckpoint",
    );

    // 3. Adversarial CPI check: Mode 1 escrow Assign hijack MUST be blocked with Custom(6031)!
    let (_, sr_u, path_u) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        13,
        2,
        0,
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
                13,
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
            ))],
            400_000,
        ),
        6031,
        "Mode 1 escrow Assign hijack blocked",
    );

    // 4. Positive EXEC_FLAG_FEE_ON_OUTPUT: WSOL (100M) -> Token-2022 2.5% TransferFee
    //    Router sends 100M gross -> escrow gets 97.5M -> relayer fee 5M (relayer nets 4,875,000) ->
    //    remaining 92.5M swept -> vault nets 90,187,500 committed & FVK recovered!
    let (_, sr_s, path_s) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        13,
        1,
        0,
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
                13,
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

    // Legitimately deposit USDC into canonical vault ATA & publish checkpoint
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
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_publish_checkpoint(
                program_id,
                payer.pubkey(),
                POOL_ID,
                13,
                4,
            ))],
            200_000,
        ),
        "PublishCheckpoint",
    );

    // 3. Transact (ASSET_MODE_PUBLIC) with non-canonical vault USDC account -> MUST fail with 6020!
    let (_, sr, path) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        13,
        0,
        0,
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
                13,
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
                    13,
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
// ----------------------------------------------------------------------------
#[test]
fn test_regression_b_sysvar_rent_fractional_and_zero_thresholds() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
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

        // When exemption_threshold == 0.0, Solana garbage-collects 0-lamport accounts at tx end,
        // so pre-fund 1 lamport to exercise `create_pda_safe`'s exact `required = 0, deficit = 0` path!
        let (pool_pda, _) = derive_pool_pda(&program_id, POOL_ID);
        let (lane0_pda, _) = derive_lane_pda(&program_id, POOL_ID, 0);
        let (memo1_pda, _) = derive_memo_pda(&program_id, POOL_ID, 0, 1);
        if exp_pool_rent == 0 {
            for pda in [
                pool_pda,
                lane0_pda,
                audren_client::pda::derive_lane_rent_pda(&program_id, POOL_ID, 0).0,
                derive_subtree_pda(&program_id, POOL_ID, 0, 0).0,
                audren_client::pda::derive_subroot_pda(&program_id, POOL_ID, 0, 0).0,
                derive_memo_pda(&program_id, POOL_ID, 0, 0).0,
                derive_nf_page_pda(&program_id, POOL_ID, 0, 0).0,
                memo1_pda,
            ] {
                svm.airdrop(&pda, 1).unwrap();
            }
        }

        let vault_wsol = bootstrap_pool(&mut svm, program_id, &payer, 1);
        let pool_lamports = svm.get_account(&pool_pda).unwrap().lamports;
        let expected_pool_actual = if exp_pool_rent == 0 { 1 } else { exp_pool_rent };
        assert_eq!(
            pool_lamports, expected_pool_actual,
            "PoolState lamports mismatch at exemption_threshold={threshold}"
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
                ))],
                200_000,
            ),
            "OpenPage(MEMO, 1) under custom Rent sysvar",
        );
        let memo1_lamports = svm.get_account(&memo1_pda).unwrap().lamports;
        let expected_memo_actual = if exp_memo_rent == 0 { 1 } else { exp_memo_rent };
        assert_eq!(
            memo1_lamports, expected_memo_actual,
            "MemoPage lamports mismatch at exemption_threshold={threshold}"
        );
    }
    println!("  [REGRESSION (b) PASSED] SysvarRent exemption_threshold = 0.5 / 0.25 / 0.0 verified on-chain");
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

    // 1. UpdateParams: non-authority rejected (6028); invalid params rejected (6000); valid succeeds!
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
                    ckpt_interval: 16,
                    max_ckpt_age: 2_000,
                    note_rent_fee: 1_000_000,
                    nf_rent_fee: 250_000,
                },
            ))],
            100_000,
        ),
        6028,
        "non-authority UpdateParams",
    );
    expect_err_code(
        send_v1(
            &mut svm,
            &auth1,
            &[],
            &[to_svm_ix(&build_update_pool(
                program_id,
                auth1.pubkey(),
                POOL_ID,
                UpdatePoolAction::UpdateParams {
                    ckpt_interval: 8,
                    max_ckpt_age: 255 * 8, // must be strictly < 255 * ckpt_interval
                    note_rent_fee: 1_000_000,
                    nf_rent_fee: 250_000,
                },
            ))],
            100_000,
        ),
        6000,
        "ring-deadlock UpdateParams rejected",
    );
    expect_ok(
        send_v1(
            &mut svm,
            &auth1,
            &[],
            &[to_svm_ix(&build_update_pool(
                program_id,
                auth1.pubkey(),
                POOL_ID,
                UpdatePoolAction::UpdateParams {
                    ckpt_interval: 16,
                    max_ckpt_age: 2_048,
                    note_rent_fee: 1_111_111,
                    nf_rent_fee: 222_222,
                },
            ))],
            100_000,
        ),
        "valid UpdateParams",
    );
    let ps = PoolState::decode(&svm.get_account(&pool_pda).unwrap().data).unwrap();
    assert_eq!(ps.ckpt_interval, 16);
    assert_eq!(ps.max_ckpt_age, 2_048);
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
                    ckpt_interval: 8,
                    max_ckpt_age: 1_536,
                    note_rent_fee: 0,
                    nf_rent_fee: 0,
                },
            ))],
            100_000,
        ),
        6028,
        "UpdateParams after renounce",
    );
    println!("  [REGRESSION (d) PASSED] UpdatePool params, 2-step authority transfer, and renounce-while-paused guard verified");
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
    let encoded = alice.address().encode();
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

    // Pre-open MemoPage 1 via OpenPage (self-subsidized via LaneRentVault once funded)
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
            ))],
            200_000,
        ),
        "OpenPage(MEMO, 1)",
    );

    // Fill 95 deposits (leaves 0..95) into MemoPage 0
    let mut first_tw = Fr::from(0u64);
    let mut first_bl = Fr::from(0u64);
    for i in 0u64..95u64 {
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

    // Publish checkpoint and execute a 2-output private Transact crossing leaf 95 -> leaf 96!
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_publish_checkpoint(
                program_id,
                payer.pubkey(),
                POOL_ID,
                13,
                1,
            ))],
            200_000,
        ),
        "PublishCheckpoint at leaf 95",
    );
    let plan = compute_page_rollovers(95, 2, 0, 1);
    assert_eq!(plan.out_memo_seq, 0);
    assert_eq!(plan.next_memo_seq, Some(1));

    let (_, sr, path0) = reconstruct_witness_with(
        |a| svm.get_account(a).map(|x| x.data),
        &program_id,
        POOL_ID,
        13,
        0,
        0,
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
                13,
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
