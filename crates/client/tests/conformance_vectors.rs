//! Canonical Cross-Language Conformance Vector Suite for Audren (`spec/test-vectors.json`).
//!
//! Verified byte-for-byte on every CI run by:
//! - Rust (`audren-client`)
//! - Native FFI (`audren-ffi`)
//! - TypeScript (`@audren/sdk` + `@audren/sdk/prover` WASM)
//! - Swift (`AudrenSDK`)
//! - Kotlin (`xyz.audren.sdk`)
//!
//! Regenerate intentionally after any protocol change with:
//! `AUDREN_REGEN_VECTORS=1 cargo test -p audren-client --test conformance_vectors`

use std::path::PathBuf;

use ark_bn254::Fr;
use audren_client::{
    audren_circuits::{
        joinsplit::{JoinSplit4AryCircuit, JoinSplitInputWitness, JoinSplitOutputWitness},
        merkle::{
            build_historical_witness_4ary, compute_subtree_256_root, compute_super_root_4ary,
            zero_hashes_4ary, MerklePath4Ary,
        },
        note::{
            compute_note_commitment, compute_real_nullifier, derive_asset_id,
            derive_stealth_owner,
        },
        poseidon::{fr_to_be_bytes, poseidon2, poseidon4, poseidon5},
    },
    audren_core::{
        instruction::{ASSET_MODE_PRIVATE, ASSET_MODE_SPL, VK_ID_DEFAULT},
        layout::{
            PoolState, CK_OFF_BUMP, CK_OFF_EPOCH_ID, CK_OFF_LANE_COUNTS, CK_OFF_LANE_ROOTS,
            CK_OFF_MAGIC, CK_OFF_POOL_ID, CK_OFF_PUBLISHED_SLOT, CK_OFF_SLOT_IDX,
            CK_OFF_SUPER_ROOT, CK_OFF_VERSION, CKPT_LEN, CKPT_MAGIC, PL_OFF_ACTIVE_LANES,
            PL_OFF_AUTHORITY, PL_OFF_BUMP, PL_OFF_CKPT_INTERVAL, PL_OFF_MAGIC,
            PL_OFF_MAX_CKPT_AGE, PL_OFF_MODE, PL_OFF_NF_RENT_FEE, PL_OFF_NOTE_RENT_FEE,
            PL_OFF_PAUSED, PL_OFF_POOL_ID, PL_OFF_SOL_VAULT_BUMP, PL_OFF_VAULT_AUTH_BUMP,
            PL_OFF_VERSION, POOL_MAGIC, POOL_STATE_LEN,
        },
        PoolMode, AUDREN_PROGRAM_ID, NATIVE_SOL_MINT, NUM_LANES, PROTOCOL_VERSION, WSOL_MINT,
    },
    instructions::{compute_exec_ctx_hash, compute_joinsplit_ctx_hash, AudrenAccountMeta},
    keys::{
        encrypt_note_memo, prepare_dynamic_swap_memo, try_decrypt_and_verify_memo_entry,
        AudrenAddress, AudrenKeys, SelectiveDisclosureProof,
    },
    pda::{
        derive_checkpoint_pda, derive_escrow_pda, derive_lane_pda, derive_lane_rent_pda,
        derive_memo_pda, derive_nf_page_pda, derive_nullifier_pda, derive_pool_pda,
        derive_sol_vault_pda, derive_subroot_pda, derive_subtree_pda, derive_unwrap_pda,
        derive_vault_auth_pda,
    },
    prover::AudrenProver,
};
use serde::{Deserialize, Serialize};
use solana_address::Address;

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct KeyVector {
    seed_hex: String,
    spend_sk_hex: String,
    spend_pk_hex: String,
    nk_hex: String,
    view_sk_hex: String,
    view_pk_hex: String,
    address: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct DefiSessionVector {
    session_index: u32,
    secret_seed_hex: String,
    pubkey_b58: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct PdaEntry {
    address: String,
    bump: u8,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct PdaVectors {
    pool_id: u32,
    lane_id: u8,
    page_seq: u64,
    slot_idx: u16,
    shard_id: u8,
    nullifier_hex: String,
    pool: PdaEntry,
    sol_vault: PdaEntry,
    vault_auth: PdaEntry,
    lane: PdaEntry,
    lane_rent: PdaEntry,
    subtree: PdaEntry,
    subroot: PdaEntry,
    memo: PdaEntry,
    nf_page: PdaEntry,
    checkpoint: PdaEntry,
    nullifier: PdaEntry,
    escrow: PdaEntry,
    unwrap: PdaEntry,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct PoseidonVectors {
    poseidon2_1_2_hex: String,
    poseidon4_zeros_hex: String,
    poseidon5_note_hex: String,
    zero_hash_level18_hex: String,
    zero_hash_level19_hex: String,
    zero_hash_level20_hex: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct AssetIdVectors {
    native_sol_asset_id_hex: String,
    wsol_asset_id_hex: String,
    usdc_mint_b58: String,
    usdc_asset_id_hex: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct MemoVector {
    eph_secret_hex: String,
    amount: u64,
    mint_hex: String,
    tweak_hex: String,
    blinding_hex: String,
    stealth_owner_hex: String,
    commitment_hex: String,
    memo_90_hex: String,
    dyn_head_34_hex: String,
    dyn_mask_56_hex: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CtxHashVectors {
    joinsplit_private_ctx_hash_hex: String,
    joinsplit_wsol_unwrap_ctx_hash_hex: String,
    exec_fee_on_output_ctx_hash_hex: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct Groth16Vector {
    vk_id: u8,
    super_root_hex: String,
    nf0_hex: String,
    nf1_hex: String,
    cm0_hex: String,
    cm1_hex: String,
    cm2_hex: String,
    public_input_hash_hex: String,
    proof_192_hex: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct PoolStateVector {
    raw_hex: String,
    pool_id: u32,
    active_lanes: u8,
    ckpt_interval: u64,
    max_ckpt_age: u64,
    note_rent_fee: u64,
    nf_rent_fee: u64,
    paused: bool,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct ConformanceVectors {
    protocol_version: u8,
    program_id: String,
    alice: KeyVector,
    alice_sub1: KeyVector,
    bob: KeyVector,
    defi_session_0: DefiSessionVector,
    defi_session_3: DefiSessionVector,
    poseidon: PoseidonVectors,
    asset_ids: AssetIdVectors,
    pdas: PdaVectors,
    memo: MemoVector,
    selective_disclosure: SelectiveDisclosureProof,
    ctx_hashes: CtxHashVectors,
    groth16: Groth16Vector,
    pool_state: PoolStateVector,
    checkpoint_raw_hex: String,
}

fn key_vec(seed: [u8; 32], keys: &AudrenKeys) -> KeyVector {
    KeyVector {
        seed_hex: to_hex(&seed),
        spend_sk_hex: to_hex(&fr_to_be_bytes(&keys.spend_sk)),
        spend_pk_hex: to_hex(&fr_to_be_bytes(&keys.spend_pk)),
        nk_hex: to_hex(&fr_to_be_bytes(&keys.nk)),
        view_sk_hex: to_hex(&keys.view_sk),
        view_pk_hex: to_hex(&keys.view_pk),
        address: keys.address().encode(),
    }
}

fn build_canonical_vectors() -> ConformanceVectors {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let alice_seed = [0x11u8; 32];
    let bob_seed = [0x22u8; 32];
    let alice = AudrenKeys::from_seed(&alice_seed);
    let alice_sub1 = AudrenKeys::from_seed_subaccount(&alice_seed, 1);
    let bob = AudrenKeys::from_seed(&bob_seed);

    let decoded_addr = AudrenAddress::decode(&alice.address().encode()).unwrap();
    assert_eq!(decoded_addr, alice.address());

    let sess0 = AudrenKeys::derive_defi_session_keypair(&alice_seed, 0);
    let sess3 = AudrenKeys::derive_defi_session_keypair(&alice_seed, 3);

    let usdc_addr: Address = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        .parse()
        .unwrap();
    let usdc_mint = usdc_addr.to_bytes();

    let sol_asset = derive_asset_id(&NATIVE_SOL_MINT);
    let wsol_asset = derive_asset_id(&WSOL_MINT);
    let usdc_asset = derive_asset_id(&usdc_mint);

    // Memo & note commitment
    let eph_secret = [0x33u8; 32];
    let amount = 1_500_000u64;
    let (tw, bl, memo_90) = encrypt_note_memo(&alice.view_pk, eph_secret, amount, &NATIVE_SOL_MINT);
    let stealth = derive_stealth_owner(alice.spend_pk, tw);
    let cm = compute_note_commitment(stealth, sol_asset, amount, bl);
    let cm_be = fr_to_be_bytes(&cm);
    let fvk = alice.full_viewing_key();
    let vt = [memo_90[0], memo_90[1]];
    let epk: [u8; 32] = memo_90[2..34].try_into().unwrap();
    let ct: [u8; 56] = memo_90[34..90].try_into().unwrap();
    let dec = try_decrypt_and_verify_memo_entry(&fvk, vt, &epk, &ct, &cm_be)
        .expect("FVK memo decrypt + commitment verify");
    assert_eq!(dec.amount, amount);
    assert_eq!(dec.mint, NATIVE_SOL_MINT);

    let (_, _, dyn_head, dyn_mask) = prepare_dynamic_swap_memo(&bob.view_pk, [0x44u8; 32]);

    // Selective disclosure proof
    let sd = SelectiveDisclosureProof {
        pool_id: 0,
        lane_id: 2,
        leaf_index: 5,
        stealth_owner: fr_to_be_bytes(&stealth),
        mint: NATIVE_SOL_MINT,
        amount,
        blinding: fr_to_be_bytes(&bl),
        commitment: cm_be,
    };
    assert!(sd.verify_against_leaf(&cm_be));

    // PDAs
    let nf_sample = fr_to_be_bytes(&compute_real_nullifier(alice.nk, cm, (2u64 << 36) | 5));
    let mk_pda = |(a, b): (Address, u8)| PdaEntry {
        address: a.to_string(),
        bump: b,
    };
    let pdas = PdaVectors {
        pool_id: 0,
        lane_id: 2,
        page_seq: 7,
        slot_idx: 13,
        shard_id: 5,
        nullifier_hex: to_hex(&nf_sample),
        pool: mk_pda(derive_pool_pda(&program_id, 0)),
        sol_vault: mk_pda(derive_sol_vault_pda(&program_id, 0)),
        vault_auth: mk_pda(derive_vault_auth_pda(&program_id, 0)),
        lane: mk_pda(derive_lane_pda(&program_id, 0, 2)),
        lane_rent: mk_pda(derive_lane_rent_pda(&program_id, 0, 2)),
        subtree: mk_pda(derive_subtree_pda(&program_id, 0, 2, 7)),
        subroot: mk_pda(derive_subroot_pda(&program_id, 0, 2, 7)),
        memo: mk_pda(derive_memo_pda(&program_id, 0, 2, 7)),
        nf_page: mk_pda(derive_nf_page_pda(&program_id, 0, 2, 7)),
        checkpoint: mk_pda(derive_checkpoint_pda(&program_id, 0, 13)),
        nullifier: mk_pda(derive_nullifier_pda(&program_id, 0, &nf_sample)),
        escrow: mk_pda(derive_escrow_pda(&program_id, 0, 5)),
        unwrap: mk_pda(derive_unwrap_pda(&program_id, 0, &nf_sample)),
    };

    // Context hashes
    let recip = Address::new_from_array(sess0.pubkey);
    let relayer = Address::new_from_array(sess3.pubkey);
    let ctx_priv = compute_joinsplit_ctx_hash(
        &program_id,
        0,
        2,
        0b111,
        ASSET_MODE_PRIVATE,
        false,
        None,
        None,
        &[0u8; 32],
        0,
        0,
        &memo_90,
    );
    let ctx_wsol = compute_joinsplit_ctx_hash(
        &program_id,
        0,
        2,
        0b000,
        ASSET_MODE_SPL,
        true,
        Some(&recip),
        Some(&relayer),
        &fr_to_be_bytes(&wsol_asset),
        1_000_000_000,
        5_000_000,
        &[],
    );
    let router_prog = Address::new_from_array([0x77u8; 32]);
    let router_accs = vec![
        AudrenAccountMeta::writable(Address::new_from_array([0x88u8; 32]), false),
        AudrenAccountMeta::readonly(Address::new_from_array([0x99u8; 32]), false),
    ];
    let ctx_exec = compute_exec_ctx_hash(
        &program_id,
        0,
        1,
        3,
        0b01,
        1,
        0,
        true,
        &fr_to_be_bytes(&usdc_asset),
        50_000_000,
        2_000_000,
        Some(&relayer),
        &fr_to_be_bytes(&sol_asset),
        400_000_000,
        &router_prog,
        &router_accs,
        &fr_to_be_bytes(&stealth),
        &fr_to_be_bytes(&bl),
        &dyn_head,
        &dyn_mask,
        &[1, 2, 3, 4],
        &memo_90,
    );

    // Deterministic tree + Groth16 proof vector
    let zeros = zero_hashes_4ary();
    let mut leaves = vec![Fr::from(0u64); 6];
    leaves[5] = cm;
    let sub0 = compute_subtree_256_root(&leaves, 6);
    let mut lroot = sub0;
    for h in 4..18 {
        lroot = poseidon4(lroot, zeros[h], zeros[h], zeros[h]);
    }
    let mut lane_roots = [zeros[18]; NUM_LANES];
    lane_roots[2] = lroot;
    let super_root = compute_super_root_4ary(&lane_roots);
    let path5 = build_historical_witness_4ary(2, 5, &lane_roots, 6, &[], &leaves, Some(&leaves));
    assert_eq!(path5.compute_root(cm), super_root);

    let prover = AudrenProver::from_dev_setup();
    let circuit = JoinSplit4AryCircuit::new_with_options(
        super_root,
        sol_asset,
        Fr::from(0u64),
        0,
        0,
        ctx_priv,
        true,
        [
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: tw,
                asset_id: sol_asset,
                amount,
                blinding: bl,
                is_dummy: false,
                merkle_path: path5,
            },
            JoinSplitInputWitness {
                spend_sk: alice.spend_sk,
                tweak: Fr::from(0u64),
                asset_id: sol_asset,
                amount: 0,
                blinding: Fr::from(0x5555u64),
                is_dummy: true,
                merkle_path: MerklePath4Ary::default(),
            },
        ],
        [
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(bob.spend_pk, Fr::from(0x101u64)),
                asset_id: sol_asset,
                amount: 1_000_000,
                blinding: Fr::from(0x201u64),
            },
            JoinSplitOutputWitness {
                stealth_owner: derive_stealth_owner(alice.spend_pk, Fr::from(0x102u64)),
                asset_id: sol_asset,
                amount: 500_000,
                blinding: Fr::from(0x202u64),
            },
            JoinSplitOutputWitness::dummy(sol_asset, Fr::from(0x203u64)),
        ],
    );
    let bundle = prover.prove_with_seed(circuit, [0x99u8; 32]);

    // Synthetic PoolState & RootCheckpoint raw bytes
    let (_, pool_bump) = derive_pool_pda(&program_id, 0);
    let (_, sv_bump) = derive_sol_vault_pda(&program_id, 0);
    let (_, va_bump) = derive_vault_auth_pda(&program_id, 0);
    let mut pool_raw = [0u8; POOL_STATE_LEN];
    pool_raw[PL_OFF_MAGIC..PL_OFF_MAGIC + 8].copy_from_slice(&POOL_MAGIC);
    pool_raw[PL_OFF_VERSION] = PROTOCOL_VERSION;
    pool_raw[PL_OFF_BUMP] = pool_bump;
    pool_raw[PL_OFF_PAUSED] = 0;
    pool_raw[PL_OFF_ACTIVE_LANES] = 4;
    pool_raw[PL_OFF_POOL_ID..PL_OFF_POOL_ID + 4].copy_from_slice(&0u32.to_le_bytes());
    pool_raw[PL_OFF_CKPT_INTERVAL..PL_OFF_CKPT_INTERVAL + 8].copy_from_slice(&8u64.to_le_bytes());
    pool_raw[PL_OFF_MAX_CKPT_AGE..PL_OFF_MAX_CKPT_AGE + 8]
        .copy_from_slice(&1_536u64.to_le_bytes());
    pool_raw[PL_OFF_AUTHORITY..PL_OFF_AUTHORITY + 32].copy_from_slice(&sess0.pubkey);
    pool_raw[PL_OFF_SOL_VAULT_BUMP] = sv_bump;
    pool_raw[PL_OFF_VAULT_AUTH_BUMP] = va_bump;
    pool_raw[PL_OFF_MODE] = PoolMode::Permissionless as u8;
    pool_raw[PL_OFF_NOTE_RENT_FEE..PL_OFF_NOTE_RENT_FEE + 8]
        .copy_from_slice(&1_500_000u64.to_le_bytes());
    pool_raw[PL_OFF_NF_RENT_FEE..PL_OFF_NF_RENT_FEE + 8]
        .copy_from_slice(&500_000u64.to_le_bytes());
    let decoded_pool = PoolState::decode(&pool_raw).unwrap();
    assert_eq!(decoded_pool.active_lanes, 4);

    let (_, ck_bump) = derive_checkpoint_pda(&program_id, 0, 13);
    let mut ck_raw = [0u8; CKPT_LEN];
    ck_raw[CK_OFF_MAGIC..CK_OFF_MAGIC + 8].copy_from_slice(&CKPT_MAGIC);
    ck_raw[CK_OFF_VERSION] = PROTOCOL_VERSION;
    ck_raw[CK_OFF_BUMP] = ck_bump;
    ck_raw[CK_OFF_SLOT_IDX..CK_OFF_SLOT_IDX + 2].copy_from_slice(&13u16.to_le_bytes());
    ck_raw[CK_OFF_POOL_ID..CK_OFF_POOL_ID + 4].copy_from_slice(&0u32.to_le_bytes());
    ck_raw[CK_OFF_EPOCH_ID..CK_OFF_EPOCH_ID + 8].copy_from_slice(&13u64.to_le_bytes());
    ck_raw[CK_OFF_PUBLISHED_SLOT..CK_OFF_PUBLISHED_SLOT + 8].copy_from_slice(&104u64.to_le_bytes());
    ck_raw[CK_OFF_SUPER_ROOT..CK_OFF_SUPER_ROOT + 32].copy_from_slice(&fr_to_be_bytes(&super_root));
    for l in 0..NUM_LANES {
        ck_raw[CK_OFF_LANE_ROOTS + l * 32..CK_OFF_LANE_ROOTS + (l + 1) * 32]
            .copy_from_slice(&fr_to_be_bytes(&lane_roots[l]));
    }
    ck_raw[CK_OFF_LANE_COUNTS + 2 * 8..CK_OFF_LANE_COUNTS + 3 * 8]
        .copy_from_slice(&6u64.to_le_bytes());

    ConformanceVectors {
        protocol_version: PROTOCOL_VERSION,
        program_id: program_id.to_string(),
        alice: key_vec(alice_seed, &alice),
        alice_sub1: key_vec(alice_seed, &alice_sub1),
        bob: key_vec(bob_seed, &bob),
        defi_session_0: DefiSessionVector {
            session_index: 0,
            secret_seed_hex: to_hex(&sess0.secret_seed),
            pubkey_b58: Address::new_from_array(sess0.pubkey).to_string(),
        },
        defi_session_3: DefiSessionVector {
            session_index: 3,
            secret_seed_hex: to_hex(&sess3.secret_seed),
            pubkey_b58: Address::new_from_array(sess3.pubkey).to_string(),
        },
        poseidon: PoseidonVectors {
            poseidon2_1_2_hex: to_hex(&fr_to_be_bytes(&poseidon2(Fr::from(1u64), Fr::from(2u64)))),
            poseidon4_zeros_hex: to_hex(&fr_to_be_bytes(&poseidon4(
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
            ))),
            poseidon5_note_hex: to_hex(&fr_to_be_bytes(&poseidon5(
                Fr::from(3u64),
                stealth,
                sol_asset,
                Fr::from(amount),
                bl,
            ))),
            zero_hash_level18_hex: to_hex(&fr_to_be_bytes(&zeros[18])),
            zero_hash_level19_hex: to_hex(&fr_to_be_bytes(&zeros[19])),
            zero_hash_level20_hex: to_hex(&fr_to_be_bytes(&zeros[20])),
        },
        asset_ids: AssetIdVectors {
            native_sol_asset_id_hex: to_hex(&fr_to_be_bytes(&sol_asset)),
            wsol_asset_id_hex: to_hex(&fr_to_be_bytes(&wsol_asset)),
            usdc_mint_b58: usdc_addr.to_string(),
            usdc_asset_id_hex: to_hex(&fr_to_be_bytes(&usdc_asset)),
        },
        pdas,
        memo: MemoVector {
            eph_secret_hex: to_hex(&eph_secret),
            amount,
            mint_hex: to_hex(&NATIVE_SOL_MINT),
            tweak_hex: to_hex(&fr_to_be_bytes(&tw)),
            blinding_hex: to_hex(&fr_to_be_bytes(&bl)),
            stealth_owner_hex: to_hex(&fr_to_be_bytes(&stealth)),
            commitment_hex: to_hex(&cm_be),
            memo_90_hex: to_hex(&memo_90),
            dyn_head_34_hex: to_hex(&dyn_head),
            dyn_mask_56_hex: to_hex(&dyn_mask),
        },
        selective_disclosure: sd,
        ctx_hashes: CtxHashVectors {
            joinsplit_private_ctx_hash_hex: to_hex(&fr_to_be_bytes(&ctx_priv)),
            joinsplit_wsol_unwrap_ctx_hash_hex: to_hex(&fr_to_be_bytes(&ctx_wsol)),
            exec_fee_on_output_ctx_hash_hex: to_hex(&fr_to_be_bytes(&ctx_exec)),
        },
        groth16: Groth16Vector {
            vk_id: VK_ID_DEFAULT,
            super_root_hex: to_hex(&fr_to_be_bytes(&super_root)),
            nf0_hex: to_hex(&bundle.nf0),
            nf1_hex: to_hex(&bundle.nf1),
            cm0_hex: to_hex(&bundle.cm0),
            cm1_hex: to_hex(&bundle.cm1),
            cm2_hex: to_hex(&bundle.cm2),
            public_input_hash_hex: to_hex(&bundle.public_input_hash),
            proof_192_hex: to_hex(&bundle.proof_192),
        },
        pool_state: PoolStateVector {
            raw_hex: to_hex(&pool_raw),
            pool_id: 0,
            active_lanes: 4,
            ckpt_interval: 8,
            max_ckpt_age: 1_536,
            note_rent_fee: 1_500_000,
            nf_rent_fee: 500_000,
            paused: false,
        },
        checkpoint_raw_hex: to_hex(&ck_raw),
    }
}

#[test]
fn conformance_vectors_match_spec_file() {
    let spec_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/test-vectors.json");
    let expected = build_canonical_vectors();

    if std::env::var("AUDREN_REGEN_VECTORS").as_deref() == Ok("1") {
        let json = serde_json::to_string_pretty(&expected).unwrap() + "\n";
        std::fs::write(&spec_path, json).expect("write spec/test-vectors.json");
        println!("Regenerated {}", spec_path.display());
        return;
    }

    let raw = std::fs::read_to_string(&spec_path).expect("read spec/test-vectors.json");
    let actual: ConformanceVectors =
        serde_json::from_str(&raw).expect("parse spec/test-vectors.json");
    assert_eq!(actual, expected, "spec/test-vectors.json drifted from audren-client");
}
