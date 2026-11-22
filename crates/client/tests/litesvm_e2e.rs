//! End-to-End LiteSVM Integration Test Suite for Audren (sBPFv3 + BN254 Groth16 + Transaction v1).
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
            ASSET_MODE_PRIVATE, ASSET_MODE_SOL, ASSET_MODE_SPL, OPEN_PAGE_KIND_MEMO,
            OPEN_PAGE_KIND_SUBTREE, VK_ID_DEFAULT,
        },
        layout::{
            read_32, read_u16, read_u64, LaneTreeHeader, PoolState, LN_OFF_NEXT_LEAF, MEMO_CT_LEN,
            MEMO_NOTES_PER_PAGE, MM_OFF_CIPHERTEXTS, MM_OFF_EPHEMERAL_PKS, MM_OFF_VIEW_TAGS,
            SB_OFF_LEAVES, SUBTREE_LEAVES,
        },
        AUDREN_PROGRAM_ID, CLASSIC_TOKEN_PROGRAM_ID, NATIVE_SOL_MINT, NUM_LANES,
        TOKEN_2022_PROGRAM_ID, WSOL_MINT,
    },
    instructions::{
        build_deposit_sol, build_deposit_spl, build_exec_via_escrow, build_init_lane,
        build_init_pool, build_joinsplit, build_open_page, build_publish_checkpoint,
        build_set_paused, compute_exec_ctx_hash, compute_joinsplit_ctx_hash,
        deterministic_note_rent_fee, AudrenAccountMeta, AudrenInstruction,
    },
    keys::{
        encrypt_note_memo, prepare_dynamic_swap_memo, try_decrypt_and_verify_memo_entry,
        AudrenKeys,
    },
    pda::{
        derive_escrow_pda, derive_lane_pda, derive_lane_rent_pda, derive_memo_pda,
        derive_nf_page_pda, derive_pool_pda, derive_sol_vault_pda, derive_subtree_pda,
        derive_unwrap_pda, derive_vault_auth_pda,
    },
    prover::{asset_id_bytes_for_mint, asset_id_for_mint, AudrenProver},
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

fn create_token_acc(
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
    expect_ok(send_v1(svm, payer, &[&acc], &ixs, 200_000), "create token account");
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
            AccountMeta::new_readonly(Address::new_from_array([0u8; 32]), false),
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

fn dex_swap_sol_to_spl_data(
    amount_in: u64,
    out_amount: u64,
    decimals: u8,
    leave_dust: u64,
) -> Vec<u8> {
    let mut d = Vec::with_capacity(26);
    d.push(4u8);
    d.extend_from_slice(&amount_in.to_le_bytes());
    d.extend_from_slice(&out_amount.to_le_bytes());
    d.push(decimals);
    d.extend_from_slice(&leave_dust.to_le_bytes());
    d
}

fn bootstrap_pool(svm: &mut LiteSVM, program_id: Address, payer: &Keypair, initial_lanes: u8) {
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
}

// ----------------------------------------------------------------------------
// TEST 1: Dynamic active_lanes (0 -> 4 -> 8 -> 16), super_root continuity,
//         CompactWalletStore offline witness reload, Mode 1 & Mode 2 viewing
// ----------------------------------------------------------------------------
#[test]
fn test_dynamic_lanes_expansion_and_compact_wallet_store() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let mut svm = new_svm(program_id, None, None);
    let prover = AudrenProver::from_dev_setup();
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

    // Activate 4 initial lanes
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

    let alice = AudrenKeys::from_seed(&[0xA1u8; 32]);
    let fvk = alice.full_viewing_key();
    let asset_sol = asset_id_for_mint(None);

    // Inactive lane 4 deposit blocked (6003)
    let (tw_bad, bl_bad, memo_bad) =
        encrypt_note_memo(&alice.view_pk, [0x09; 32], 5_000_000, &NATIVE_SOL_MINT);
    expect_err_code(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit_sol(
                program_id,
                payer.pubkey(),
                POOL_ID,
                4,
                0,
                0,
                0,
                None,
                None,
                false,
                5_000_000,
                derive_stealth_owner(alice.spend_pk, tw_bad),
                bl_bad,
                &memo_bad,
            ))],
            200_000,
        ),
        6003,
        "deposit on inactive lane",
    );

    // Deposit into lanes 0..4
    for l in 0..4u8 {
        let (tw, bl, memo) =
            encrypt_note_memo(&alice.view_pk, [0x10 + l; 32], 25_000_000, &NATIVE_SOL_MINT);
        expect_ok(
            send_v1(
                &mut svm,
                &payer,
                &[],
                &[to_svm_ix(&build_deposit_sol(
                    program_id,
                    payer.pubkey(),
                    POOL_ID,
                    l,
                    0,
                    0,
                    0,
                    None,
                    None,
                    false,
                    25_000_000,
                    derive_stealth_owner(alice.spend_pk, tw),
                    bl,
                    &memo,
                ))],
                200_000,
            ),
            "deposit sol 4-lane",
        );
    }

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
        &svm.get_account(&audren_client::pda::derive_checkpoint_pda(&program_id, POOL_ID, 13).0)
            .unwrap()
            .data,
    )
    .unwrap();
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
        &svm.get_account(&audren_client::pda::derive_checkpoint_pda(&program_id, POOL_ID, 14).0)
            .unwrap()
            .data,
    )
    .unwrap();
    assert_eq!(
        ckpt4.super_root, ckpt8.super_root,
        "4 -> 8 expansion MUST preserve bit-for-bit super_root"
    );

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
        &svm.get_account(&audren_client::pda::derive_checkpoint_pda(&program_id, POOL_ID, 15).0)
            .unwrap()
            .data,
    )
    .unwrap();
    assert_eq!(
        ckpt8.super_root, ckpt16.super_root,
        "8 -> 16 expansion MUST preserve bit-for-bit super_root"
    );

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
    assert_eq!(store.balances().get(&NATIVE_SOL_MINT), Some(&100_000_000));

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
        encrypt_note_memo(&alice.view_pk, [0x71; 32], 25_000_000, &NATIVE_SOL_MINT);
    let ctx = compute_joinsplit_ctx_hash(
        &program_id,
        POOL_ID,
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
        asset_sol,
        Fr::from(0u64),
        0,
        0,
        ctx,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: note0.tweak_fr().unwrap(),
                asset_id: asset_sol,
                amount: note0.amount,
                blinding: note0.blinding_fr().unwrap(),
                is_dummy: false,
                merkle_path: path0,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_sol,
                amount: 0,
                blinding: Fr::from(777u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, tw_o),
                asset_id: asset_sol,
                amount: 25_000_000,
                blinding: bl_o,
            },
            JoinSplitOutputWitness::dummy(asset_sol, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_sol, Fr::from(3u64)),
        ],
        [0x55; 32],
    );

    let spend_cu = expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_joinsplit(
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
        "cross-expansion JoinSplit into lane 14",
    );

    // Double-spend of exact same note blocked (6012)!
    expect_err_code(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_joinsplit(
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
    assert_eq!(store2.balances().get(&NATIVE_SOL_MINT), Some(&100_000_000));
    println!(
        "  [TEST 1 PASSED] Ckpt 4/8/16={cu_ckpt_4}/{cu_ckpt_8}/{cu_ckpt_16} CU | Spend={spend_cu} CU"
    );
}

// ----------------------------------------------------------------------------
// TEST 2: Zero-dust DEPOSIT_FLAG_FEE_FROM_AMOUNT, WITHDRAW_FLAG_UNWRAP_WSOL,
//         DefiSessionKeypair 0-lamport recipient, and Pause Escape Hatch
// ----------------------------------------------------------------------------
#[test]
fn test_zero_dust_sweep_wsol_unwrap_and_pause_escape() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let mut svm = new_svm(program_id, None, None);
    let prover = AudrenProver::from_dev_setup();
    let payer = Keypair::new();
    let relayer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();
    svm.airdrop(&relayer.pubkey(), 50_000_000_000).unwrap();
    svm.warp_to_slot(104);
    bootstrap_pool(&mut svm, program_id, &payer, 4);

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
        svm.minimum_balance_for_rent_exemption(8_256),
        svm.minimum_balance_for_rent_exemption(9_664),
        svm.minimum_balance_for_rent_exemption(10_144),
    );
    let tx_fee = 5_000u64;
    let gross_sweep = sweep_start - tx_fee;
    let net_sweep = gross_sweep - per_note_fee;
    let (tw_s, bl_s, memo_s) =
        encrypt_note_memo(&alice.view_pk, [0x21; 32], net_sweep, &NATIVE_SOL_MINT);
    expect_ok(
        send_v1(
            &mut svm,
            &sweeper,
            &[],
            &[to_svm_ix(&build_deposit_sol(
                program_id,
                sweeper.pubkey(),
                POOL_ID,
                0,
                0,
                0,
                0,
                None,
                None,
                true,
                gross_sweep,
                derive_stealth_owner(alice.spend_pk, tw_s),
                bl_s,
                &memo_s,
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

    // Deposit 2.0 WSOL into lane 1
    let (va, _) = derive_vault_auth_pda(&program_id, POOL_ID);
    let payer_wsol = create_token_acc(&mut svm, &payer, wsol_mint_id(), payer.pubkey(), spl_token_id(), &[]);
    let vault_wsol = create_token_acc(&mut svm, &payer, wsol_mint_id(), va, spl_token_id(), &[]);
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
                    data: vec![17u8],
                },
            ],
            200_000,
        ),
        "wrap 2 WSOL",
    );

    let wsol_asset = asset_id_for_mint(Some(&wsol_mint_id()));
    let (tw_w, bl_w, memo_w) =
        encrypt_note_memo(&alice.view_pk, [0x22; 32], 2_000_000_000, &WSOL_MINT);
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit_spl(
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
        encrypt_note_memo(&alice.view_pk, [0x23; 32], 1_090_000_000, &WSOL_MINT);
    let ctx_uw = compute_joinsplit_ctx_hash(
        &program_id,
        POOL_ID,
        1,
        0b001,
        ASSET_MODE_SPL,
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
            &[to_svm_ix(&build_joinsplit(
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
                ASSET_MODE_SPL,
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
    let ctx_full = compute_joinsplit_ctx_hash(
        &program_id,
        POOL_ID,
        1,
        0,
        ASSET_MODE_SPL,
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
            &[to_svm_ix(&build_joinsplit(
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
                ASSET_MODE_SPL,
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
    assert_eq!(token_balance(&svm, &vault_wsol), 0);
    println!("  [TEST 2 PASSED] WSOL partial={cu_uw} CU | paused full exit={cu_full} CU");
}

// ----------------------------------------------------------------------------
// TEST 3: Token-2022 TransferFee net-delta + active TransferHook + ExecViaEscrow
//         firewall (adversarial CPI) + EXEC_FLAG_FEE_ON_OUTPUT (SOL & T22 2.5%)
// ----------------------------------------------------------------------------
#[test]
fn test_t22_hook_exec_firewall_and_fee_on_output() {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let router_id = Keypair::new().pubkey();
    let hook_id = Keypair::new().pubkey();
    let mut svm = new_svm(program_id, Some(router_id), Some(hook_id));
    let prover = AudrenProver::from_dev_setup();

    let payer = Keypair::new();
    let relayer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();
    svm.airdrop(&relayer.pubkey(), 50_000_000_000).unwrap();
    svm.warp_to_slot(104);
    bootstrap_pool(&mut svm, program_id, &payer, 4);

    let alice = AudrenKeys::from_seed(&[0x55u8; 32]);
    let fvk = alice.full_viewing_key();
    let (va, _) = derive_vault_auth_pda(&program_id, POOL_ID);
    let (esc0, _) = derive_escrow_pda(&program_id, POOL_ID, 0);
    svm.airdrop(&esc0, 2_000_000).unwrap();

    // 1. Active Token-2022 TransferHook deposit & withdraw
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
                    AccountMeta::new_readonly(Address::new_from_array([0u8; 32]), false),
                ],
                data: vec![0u8],
            }],
            200_000,
        ),
        "init mock TransferHook extra metas",
    );
    let payer_hk = create_token_acc(
        &mut svm,
        &payer,
        hook_mint,
        payer.pubkey(),
        token_2022_id(),
        &[ExtensionType::TransferHookAccount],
    );
    let vault_hk = create_token_acc(
        &mut svm,
        &payer,
        hook_mint,
        va,
        token_2022_id(),
        &[ExtensionType::TransferHookAccount],
    );
    mint_to(&mut svm, &payer, token_2022_id(), hook_mint, payer_hk, 50_000_000);
    let (tw_hk, bl_hk, memo_hk) =
        encrypt_note_memo(&alice.view_pk, [0x31; 32], 20_000_000, &hook_mint.to_bytes());
    let cu_hk_dep = expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit_spl(
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
        "DepositSpl active TransferHook",
    );
    assert_eq!(token_balance(&svm, &vault_hk), 20_000_000);

    // 2. Setup mock DEX + Classic SPL USDC + Token-2022 2.5% TransferFee mint
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
    let dex_t22 = create_token_acc(
        &mut svm,
        &payer,
        t22_mint,
        dex_pool,
        token_2022_id(),
        &[ExtensionType::TransferFeeAmount],
    );
    let vault_t22 = create_token_acc(
        &mut svm,
        &payer,
        t22_mint,
        va,
        token_2022_id(),
        &[ExtensionType::TransferFeeAmount],
    );
    let esc0_t22 = create_token_acc(
        &mut svm,
        &payer,
        t22_mint,
        esc0,
        token_2022_id(),
        &[ExtensionType::TransferFeeAmount],
    );
    let relayer_t22 = create_token_acc(
        &mut svm,
        &payer,
        t22_mint,
        relayer.pubkey(),
        token_2022_id(),
        &[ExtensionType::TransferFeeAmount],
    );
    mint_to(&mut svm, &payer, token_2022_id(), t22_mint, dex_t22, 500_000_000);

    let vault_usdc = create_token_acc(&mut svm, &payer, usdc_mint, va, spl_token_id(), &[]);
    let esc0_usdc = create_token_acc(&mut svm, &payer, usdc_mint, esc0, spl_token_id(), &[]);
    let dex_usdc = create_token_acc(&mut svm, &payer, usdc_mint, dex_pool, spl_token_id(), &[]);
    let payer_usdc = create_token_acc(&mut svm, &payer, usdc_mint, payer.pubkey(), spl_token_id(), &[]);
    mint_to(&mut svm, &payer, spl_token_id(), usdc_mint, payer_usdc, 200_000_000);

    // Deposit 100M lamports SOL note on lane 1 + 100M USDC note on lane 2
    let (tw_s, bl_s, memo_s) =
        encrypt_note_memo(&alice.view_pk, [0x41; 32], 100_000_000, &NATIVE_SOL_MINT);
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit_sol(
                program_id,
                payer.pubkey(),
                POOL_ID,
                1,
                0,
                0,
                0,
                None,
                None,
                false,
                100_000_000,
                derive_stealth_owner(alice.spend_pk, tw_s),
                bl_s,
                &memo_s,
            ))],
            200_000,
        ),
        "deposit 100M SOL",
    );
    let (tw_u, bl_u, memo_u) =
        encrypt_note_memo(&alice.view_pk, [0x42; 32], 100_000_000, &usdc_mint.to_bytes());
    expect_ok(
        send_v1(
            &mut svm,
            &payer,
            &[],
            &[to_svm_ix(&build_deposit_spl(
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
    let asset_sol = asset_id_for_mint(None);
    let asset_usdc = asset_id_for_mint(Some(&usdc_mint));
    let asset_t22 = asset_id_for_mint(Some(&t22_mint));

    let (dtw, dbl, dhead, dmask) = prepare_dynamic_swap_memo(&alice.view_pk, [0x45; 32]);
    let ost = fr_to_be_bytes(&derive_stealth_owner(alice.spend_pk, dtw));
    let obl = fr_to_be_bytes(&dbl);
    let hijack_data = dex_swap_spl_to_spl_data(1, 50_000_000, 50_000_000, 6, 6); // Mode 1 = SystemProgram::Assign(escrow)
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
        AudrenAccountMeta::readonly(Address::new_from_array([0u8; 32]), false),
        AudrenAccountMeta::readonly(router_id, false),
    ];
    let ctx_hj = compute_exec_ctx_hash(
        &program_id,
        POOL_ID,
        3,
        0,
        0,
        1,
        1,
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
                1,
                1,
                false,
                Some((usdc_mint, vault_usdc, esc0_usdc, spl_token_id())),
                Some((t22_mint, vault_t22, esc0_t22, token_2022_id())),
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

    // 4. Positive EXEC_FLAG_FEE_ON_OUTPUT: SOL (100M) -> Token-2022 2.5% TransferFee
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
    let (dtw2, dbl2, dhead2, dmask2) = prepare_dynamic_swap_memo(&alice.view_pk, [0x49; 32]);
    let ost2 = fr_to_be_bytes(&derive_stealth_owner(alice.spend_pk, dtw2));
    let obl2 = fr_to_be_bytes(&dbl2);
    let s2t_data = dex_swap_sol_to_spl_data(100_000_000, 100_000_000, 6, 0);
    let s2t_accs = vec![
        AudrenAccountMeta::writable(esc0, false),
        AudrenAccountMeta::writable(dex_pool, false),
        AudrenAccountMeta::writable(dex_t22, false),
        AudrenAccountMeta::writable(esc0_t22, false),
        AudrenAccountMeta::readonly(t22_mint, false),
        AudrenAccountMeta::readonly(token_2022_id(), false),
        AudrenAccountMeta::readonly(Address::new_from_array([0u8; 32]), false),
        AudrenAccountMeta::readonly(router_id, false),
    ];
    let ctx_s2t = compute_exec_ctx_hash(
        &program_id,
        POOL_ID,
        3,
        0,
        0,
        0,
        1,
        true,
        &asset_id_bytes_for_mint(None),
        100_000_000,
        5_000_000,
        Some(&relayer_t22),
        &fr_to_be_bytes(&asset_t22),
        90_187_500,
        &router_id,
        &s2t_accs,
        &ost2,
        &obl2,
        &dhead2,
        &dmask2,
        &s2t_data,
        &[],
    );
    let b_s2t = prover.build_and_prove(
        sr_s,
        asset_sol,
        asset_sol,
        100_000_000,
        0, // circuit relayer fee = 0 when EXEC_FLAG_FEE_ON_OUTPUT is set
        ctx_s2t,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw_s,
                asset_id: asset_sol,
                amount: 100_000_000,
                blinding: bl_s,
                is_dummy: false,
                merkle_path: path_s,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: asset_sol,
                amount: 0,
                blinding: Fr::from(19u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness::dummy(asset_sol, Fr::from(1u64)),
            JoinSplitOutputWitness::dummy(asset_sol, Fr::from(2u64)),
            JoinSplitOutputWitness::dummy(asset_sol, Fr::from(3u64)),
        ],
        [0x79; 32],
    );
    let leaf_before = lane_next_leaf(&svm, &program_id, 3);
    let cu_s2t = expect_ok(
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
                0,
                1,
                true,
                None,
                Some((t22_mint, vault_t22, esc0_t22, token_2022_id())),
                5_000_000,
                Some(relayer_t22),
                (None, None, None),
                &b_s2t.proof_192,
                &b_s2t.nf0,
                &b_s2t.nf1,
                &b_s2t.cm0,
                &b_s2t.cm1,
                &b_s2t.cm2,
                100_000_000,
                90_187_500,
                &ost2,
                &obl2,
                &dhead2,
                &dmask2,
                router_id,
                &s2t_data,
                s2t_accs,
                &[],
            ))],
            400_000,
        ),
        "SOL -> Token-2022 2.5% TransferFee with EXEC_FLAG_FEE_ON_OUTPUT",
    );
    assert_eq!(token_balance(&svm, &relayer_t22), 4_875_000);
    assert_eq!(token_balance(&svm, &vault_t22), 90_187_500);
    assert_eq!(token_balance(&svm, &esc0_t22), 0);

    // Verify FVK recovers the exact dynamic Token-2022 note from XOR-masked MemoPage + SubtreePage!
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
    let vt = [memo3[MM_OFF_VIEW_TAGS + slot * 2], memo3[MM_OFF_VIEW_TAGS + slot * 2 + 1]];
    let epk = read_32(&memo3, MM_OFF_EPHEMERAL_PKS + slot * 32);
    let ct: [u8; MEMO_CT_LEN] = memo3
        [MM_OFF_CIPHERTEXTS + slot * MEMO_CT_LEN..MM_OFF_CIPHERTEXTS + (slot + 1) * MEMO_CT_LEN]
        .try_into()
        .unwrap();
    let dec = try_decrypt_and_verify_memo_entry(&fvk, vt, &epk, &ct, &cm_be).unwrap();
    assert!(dec.is_dynamic);
    assert_eq!(dec.amount, 90_187_500);
    assert_eq!(dec.mint, t22_mint.to_bytes());
    let _ = (dex_swap_spl_to_spl_data, OPEN_PAGE_KIND_MEMO, OPEN_PAGE_KIND_SUBTREE, build_open_page, LaneTreeHeader::decode, ASSET_MODE_SOL, MEMO_NOTES_PER_PAGE, SUBTREE_LEAVES, read_u16, derive_lane_rent_pda, derive_sol_vault_pda);
    println!(
        "  [TEST 3 PASSED] TransferHook Deposit={cu_hk_dep} CU | SOL->T22 Fee-on-Output={cu_s2t} CU"
    );
}
