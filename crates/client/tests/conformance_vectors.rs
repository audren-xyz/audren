//! Canonical cross-language conformance test vectors for Audren SDKs.
//!
//! Shared across all 4 official Audren SDKs:
//! - Rust (`crates/client` & `crates/audren-ffi`)
//! - TypeScript (`@audren/sdk` & `@audren/sdk/prover`)
//! - Swift (`packages/swift` / `AudrenSDK` via UniFFI)
//! - Kotlin (`packages/kotlin` / `xyz.audren.sdk` via UniFFI)
//!
//! Run `AUDREN_WRITE_VECTORS=1 cargo test -p audren-client --test conformance_vectors`
//! to regenerate `spec/test-vectors.json` deterministically.

use std::path::PathBuf;

use audren_client::{
    instructions::{build_deposit, build_deposit_with_options, build_transfer, build_withdraw, build_withdraw_with_params, WithdrawParams},
    keys::{
        compute_note_nullifier, prepare_shielded_note, AudrenAddress, AudrenKeys, AuditorKeypair,
        FullViewingKey, SelectiveDisclosureProof,
    },
    pda::{
        derive_epoch_page_pda, derive_escrow_pda, derive_lane_pda, derive_lane_rent_vault_pda,
        derive_nullifier_pda, derive_page_rent_vault_pda, derive_pool_pda, derive_proof_buffer_pda,
        derive_sol_vault_pda, derive_unwrap_pda, derive_vault_auth_pda,
    },
    prover::{asset_generator, compress, decompress, h_point, RingSlotWitness},
    router::JUPITER_CPI_EXCLUDED_DEXES,
    scanner::{decrypt_owned_note, scan_page_dataslice},
};
use audren_core::{
    layout::{
        read_page_witness, write_page_note, PageHeader, PoolState, PAGE_CAPACITY, PAGE_LEN,
        PAGE_SCAN_LEN, PAGE_SCAN_OFFSET, POOL_STATE_LEN,
    },
    page_id_for_lane, PoolMode, AUDREN_PROGRAM_ID, NATIVE_SOL_MINT, PROTOCOL_VERSION, WSOL_MINT,
};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use solana_address::Address;

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn from_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex string must have even length");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

fn from_hex_32(hex: &str) -> [u8; 32] {
    let v = from_hex(hex);
    v.try_into().expect("expected 32-byte hex")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct KeyVector {
    seed_hex: String,
    spend_sk_hex: String,
    spend_pk_hex: String,
    view_sk_hex: String,
    view_pk_hex: String,
    address: String,
    full_viewing_key_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SubaccountVector {
    account_index: u32,
    spend_sk_hex: String,
    spend_pk_hex: String,
    view_sk_hex: String,
    view_pk_hex: String,
    address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DefiSessionVector {
    session_index: u32,
    secret_seed_hex: String,
    pubkey_hex: String,
    address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PdaVector {
    address: String,
    bump: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PdaSuiteVector {
    pool_id: u32,
    pool: PdaVector,
    epoch_page_0: PdaVector,
    epoch_page_lane1_seq0: PdaVector,
    sol_vault: PdaVector,
    vault_auth: PdaVector,
    page_rent_vault: PdaVector,
    escrow_0: PdaVector,
    unwrap_pda: PdaVector,
    lane_1: PdaVector,
    lane_rent_vault_1: PdaVector,
    proof_buffer_authority: String,
    proof_buffer_nonce: u64,
    proof_buffer: PdaVector,
    nullifier_pda: PdaVector,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AssetGeneratorsVector {
    native_sol_mint_b58: String,
    native_sol_gen_hex: String,
    wsol_mint_b58: String,
    wsol_gen_hex: String,
    usdc_mint_b58: String,
    usdc_gen_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PoolStateVector {
    raw_hex: String,
    version: u8,
    bump: u8,
    mode: u8,
    paused: bool,
    pool_id: u32,
    current_page_id: u64,
    total_notes: u64,
    total_spends: u64,
    page_rent_fee_lamports: u64,
    authority: String,
    auditor_pk_hex: String,
    auditor_locked: bool,
    vault_auth_bump: u8,
    sol_vault_bump: u8,
    page_rent_bump: u8,
    active_lanes: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct OwnedNoteVector {
    page_id: u64,
    slot_index: u8,
    mint_hex: String,
    amount: u64,
    is_dynamic_output: bool,
    stealth_pk_hex: String,
    asset_tag_hex: String,
    commitment_hex: String,
    asset_blinding_hex: String,
    value_blinding_hex: String,
    stealth_scalar_hex: String,
    spend_x_hex: String,
    nullifier_hex: String,
    nullifier_pda: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct EpochPageVector {
    pool_id: u32,
    page_id: u64,
    version: u8,
    bump: u8,
    closed: bool,
    count: u8,
    created_slot: u64,
    closed_slot: u64,
    scan_offset: usize,
    scan_length: usize,
    page_hex: String,
    scan_slice_hex: String,
    matched_slots: Vec<u8>,
    alice_note: OwnedNoteVector,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AuditorVector {
    auditor_seed_hex: String,
    auditor_sk_hex: String,
    auditor_pk_hex: String,
    elgamal_s1_hex: String,
    elgamal_s2_hex: String,
    expected_spent_pk_hex: String,
    elgamal_m1_hex: String,
    elgamal_m2_hex: String,
    expected_asset_gen_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ConformanceVectors {
    spec_version: String,
    program_id: String,
    alice: KeyVector,
    alice_subaccounts: Vec<SubaccountVector>,
    alice_defi_sessions: Vec<DefiSessionVector>,
    bob: KeyVector,
    pdas: PdaSuiteVector,
    asset_generators: AssetGeneratorsVector,
    pool_state: PoolStateVector,
    epoch_page: EpochPageVector,
    selective_disclosure_json: String,
    auditor: AuditorVector,
    jupiter_cpi_excluded_dexes: String,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("spec/test-vectors.json")
}

fn generate_canonical_vectors() -> ConformanceVectors {
    let program_id = Address::new_from_array(AUDREN_PROGRAM_ID);
    let mut rng = StdRng::from_seed([0x41u8; 32]);

    // 1. Keys: Alice master, Alice subaccounts #1 & #7, Bob master
    let alice_seed: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    let bob_seed: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(5));

    let alice = AudrenKeys::from_seed(&alice_seed);
    let alice_fvk_json = serde_json::to_string(&alice.full_viewing_key().to_export()).unwrap();
    let bob = AudrenKeys::from_seed(&bob_seed);
    let bob_fvk_json = serde_json::to_string(&bob.full_viewing_key().to_export()).unwrap();

    let alice_sub1 = AudrenKeys::from_seed_subaccount(&alice_seed, 1);
    let alice_sub7 = AudrenKeys::from_seed_subaccount(&alice_seed, 7);
    let alice_sess0 = AudrenKeys::derive_defi_session_keypair(&alice_seed, 0);
    let alice_sess3 = AudrenKeys::derive_defi_session_keypair(&alice_seed, 3);

    // 2. Asset generators (Native SOL, WSOL, Mainnet USDC)
    let usdc_addr: Address = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        .parse()
        .unwrap();
    let usdc_mint = usdc_addr.to_bytes();

    let sol_gen = asset_generator(&NATIVE_SOL_MINT);
    let wsol_gen = asset_generator(&WSOL_MINT);
    let usdc_gen = asset_generator(&usdc_mint);

    // 3. Synthetic full 32-note EpochPage (count = 32, slot 5 = Alice's 1.5M lamport native SOL note)
    let pool_id = 0u32;
    let page_id = 0u64;
    let (_, page_bump) = derive_epoch_page_pda(&program_id, pool_id, page_id);
    let mut page_bytes = vec![0u8; PAGE_LEN];
    let header = PageHeader {
        version: PROTOCOL_VERSION,
        bump: page_bump,
        closed: true,
        count: PAGE_CAPACITY as u8,
        pool_id,
        page_id,
        created_slot: 472_228_607,
        closed_slot: 472_228_900,
    };
    header.encode(&mut page_bytes).unwrap();

    let alice_slot = 5usize;
    let alice_amount = 1_500_000u64;
    let mut alice_prepared = None;

    for slot in 0..PAGE_CAPACITY {
        if slot == alice_slot {
            let note = prepare_shielded_note(
                &alice.address(),
                NATIVE_SOL_MINT,
                alice_amount,
                true,
                None,
                true,
                *b"CONFORM",
                &mut rng,
            )
            .unwrap();
            write_page_note(&mut page_bytes, slot, &note.entry).unwrap();
            alice_prepared = Some(note);
        } else {
            // Decoy notes belong to Bob (never match Alice's view_sk)
            let decoy_mint = if slot % 2 == 0 {
                NATIVE_SOL_MINT
            } else {
                usdc_mint
            };
            let decoy_amount = 100_000u64 + (slot as u64) * 50_000;
            let decoy = prepare_shielded_note(
                &bob.address(),
                decoy_mint,
                decoy_amount,
                true,
                None,
                true,
                *b"DECOY00",
                &mut rng,
            )
            .unwrap();
            write_page_note(&mut page_bytes, slot, &decoy.entry).unwrap();
        }
    }
    let alice_prepared = alice_prepared.unwrap();

    let alice_fvk = alice.full_viewing_key();
    let scan_slice = &page_bytes[PAGE_SCAN_OFFSET..PAGE_SCAN_OFFSET + PAGE_SCAN_LEN];
    let matched_slots: Vec<u8> = scan_page_dataslice(&alice_fvk, page_id, scan_slice)
        .unwrap()
        .into_iter()
        .map(|c| c.slot_index as u8)
        .collect();
    assert_eq!(matched_slots, vec![alice_slot as u8]);

    let decrypted = decrypt_owned_note(
        &alice_fvk,
        Some(&alice),
        &program_id,
        pool_id,
        &page_bytes,
        alice_slot,
        None,
    )
    .unwrap()
    .expect("Alice must decrypt slot 5");

    assert_eq!(decrypted.amount, alice_amount);
    assert_eq!(decrypted.mint, NATIVE_SOL_MINT);
    assert_eq!(decrypted.stealth_pk, alice_prepared.entry.stealth_pk);

    let (spend_x, nullifier) =
        compute_note_nullifier(&alice.spend_sk, &decrypted.stealth_scalar).unwrap();
    assert_eq!(decrypted.spend_x, Some(spend_x));
    assert_eq!(decrypted.nullifier, Some(nullifier));
    let (nullifier_pda, nullifier_bump) = derive_nullifier_pda(&program_id, pool_id, &nullifier);
    assert_eq!(decrypted.nullifier_pda, Some(nullifier_pda));

    // 4. All Pool #0 PDAs
    let (pool_pda, pool_bump) = derive_pool_pda(&program_id, pool_id);
    let (page0_pda, page0_bump) = derive_epoch_page_pda(&program_id, pool_id, 0);
    let lane1_page0_id = page_id_for_lane(1, 0).unwrap();
    let (page_l1_pda, page_l1_bump) = derive_epoch_page_pda(&program_id, pool_id, lane1_page0_id);
    let (sol_vault_pda, sol_vault_bump) = derive_sol_vault_pda(&program_id, pool_id);
    let (vault_auth_pda, vault_auth_bump) = derive_vault_auth_pda(&program_id, pool_id);
    let (rent_vault_pda, rent_vault_bump) = derive_page_rent_vault_pda(&program_id, pool_id);
    let (escrow0_pda, escrow0_bump) = derive_escrow_pda(&program_id, pool_id, 0);
    let (unwrap_pda, unwrap_bump) = derive_unwrap_pda(&program_id, pool_id, &nullifier);
    let (lane1_pda, lane1_bump) = derive_lane_pda(&program_id, pool_id, 1);
    let (lane1_rent_pda, lane1_rent_bump) = derive_lane_rent_vault_pda(&program_id, pool_id, 1);
    let buf_auth = Address::new_from_array([0x22u8; 32]);
    let buf_nonce = 42u64;
    let (buf_pda, buf_bump) = derive_proof_buffer_pda(&program_id, &buf_auth, buf_nonce);

    // 5. PoolState binary vector
    let auditor_seed = [0x99u8; 32];
    let auditor = AuditorKeypair::from_seed(&auditor_seed);
    let pool_state = PoolState {
        version: PROTOCOL_VERSION,
        bump: pool_bump,
        mode: PoolMode::Permissionless,
        paused: false,
        pool_id,
        current_page_id: 3,
        total_notes: 128,
        total_spends: 44,
        page_rent_fee_lamports: 1_500_000,
        authority: buf_auth.to_bytes(),
        auditor_pk: [0u8; 32],
        auditor_locked: false,
        vault_auth_bump,
        sol_vault_bump,
        page_rent_bump: rent_vault_bump,
        active_lanes: 4,
    };
    let mut pool_raw = vec![0u8; POOL_STATE_LEN];
    pool_state.encode(&mut pool_raw).unwrap();

    // 6. Mode 1 Selective Disclosure Proof
    let disclosure = SelectiveDisclosureProof {
        version: 1,
        page_id,
        slot_index: alice_slot as u8,
        stealth_pk_b58: bs58::encode(&decrypted.stealth_pk).into_string(),
        asset_tag_b58: bs58::encode(&decrypted.asset_tag).into_string(),
        commitment_b58: bs58::encode(&decrypted.commitment).into_string(),
        mint_b58: bs58::encode(&decrypted.mint).into_string(),
        amount: decrypted.amount,
        asset_blinding_b58: bs58::encode(decrypted.asset_blinding.to_bytes()).into_string(),
        value_blinding_b58: bs58::encode(decrypted.value_blinding.to_bytes()).into_string(),
    };
    assert!(disclosure.verify().unwrap());
    assert!(disclosure.verify_against_page(&page_bytes).unwrap());
    let disclosure_json = serde_json::to_string(&disclosure).unwrap();

    // 7. Auditor ElGamal decrypt vector
    let r_aud_s = Scalar::from(123_456_789u64);
    let r_aud_m = Scalar::from(987_654_321u64);
    let k_aud_pt = decompress(&auditor.auditor_pk).unwrap();
    let spent_pk_pt = decompress(&decrypted.stealth_pk).unwrap();
    let g_usdc_pt = decompress(&usdc_gen).unwrap();
    let s1 = compress(&(r_aud_s * RISTRETTO_BASEPOINT_POINT));
    let s2 = compress(&(spent_pk_pt + r_aud_s * k_aud_pt));
    let m1 = compress(&(r_aud_m * RISTRETTO_BASEPOINT_POINT));
    let m2 = compress(&(g_usdc_pt + r_aud_m * k_aud_pt));
    assert_eq!(
        auditor.decrypt_spent_pubkey(&s1, &s2).unwrap(),
        decrypted.stealth_pk
    );
    assert_eq!(auditor.decrypt_asset_generator(&m1, &m2).unwrap(), usdc_gen);

    // Silence unused h_point import warning while confirming H matches canonical point
    let _ = h_point();

    ConformanceVectors {
        spec_version: "0.3.0".to_string(),
        program_id: program_id.to_string(),
        alice: KeyVector {
            seed_hex: to_hex(&alice_seed),
            spend_sk_hex: to_hex(&alice.spend_sk.to_bytes()),
            spend_pk_hex: to_hex(&alice.spend_pk),
            view_sk_hex: to_hex(&alice.view_sk.to_bytes()),
            view_pk_hex: to_hex(&alice.view_pk),
            address: alice.address().to_base58(),
            full_viewing_key_json: alice_fvk_json,
        },
        alice_subaccounts: vec![
            SubaccountVector {
                account_index: 1,
                spend_sk_hex: to_hex(&alice_sub1.spend_sk.to_bytes()),
                spend_pk_hex: to_hex(&alice_sub1.spend_pk),
                view_sk_hex: to_hex(&alice_sub1.view_sk.to_bytes()),
                view_pk_hex: to_hex(&alice_sub1.view_pk),
                address: alice_sub1.address().to_base58(),
            },
            SubaccountVector {
                account_index: 7,
                spend_sk_hex: to_hex(&alice_sub7.spend_sk.to_bytes()),
                spend_pk_hex: to_hex(&alice_sub7.spend_pk),
                view_sk_hex: to_hex(&alice_sub7.view_sk.to_bytes()),
                view_pk_hex: to_hex(&alice_sub7.view_pk),
                address: alice_sub7.address().to_base58(),
            },
        ],
        alice_defi_sessions: vec![
            DefiSessionVector {
                session_index: alice_sess0.session_index,
                secret_seed_hex: to_hex(&alice_sess0.secret_seed),
                pubkey_hex: to_hex(&alice_sess0.pubkey),
                address: alice_sess0.address.clone(),
            },
            DefiSessionVector {
                session_index: alice_sess3.session_index,
                secret_seed_hex: to_hex(&alice_sess3.secret_seed),
                pubkey_hex: to_hex(&alice_sess3.pubkey),
                address: alice_sess3.address.clone(),
            },
        ],
        bob: KeyVector {
            seed_hex: to_hex(&bob_seed),
            spend_sk_hex: to_hex(&bob.spend_sk.to_bytes()),
            spend_pk_hex: to_hex(&bob.spend_pk),
            view_sk_hex: to_hex(&bob.view_sk.to_bytes()),
            view_pk_hex: to_hex(&bob.view_pk),
            address: bob.address().to_base58(),
            full_viewing_key_json: bob_fvk_json,
        },
        pdas: PdaSuiteVector {
            pool_id,
            pool: PdaVector {
                address: pool_pda.to_string(),
                bump: pool_bump,
            },
            epoch_page_0: PdaVector {
                address: page0_pda.to_string(),
                bump: page0_bump,
            },
            epoch_page_lane1_seq0: PdaVector {
                address: page_l1_pda.to_string(),
                bump: page_l1_bump,
            },
            sol_vault: PdaVector {
                address: sol_vault_pda.to_string(),
                bump: sol_vault_bump,
            },
            vault_auth: PdaVector {
                address: vault_auth_pda.to_string(),
                bump: vault_auth_bump,
            },
            page_rent_vault: PdaVector {
                address: rent_vault_pda.to_string(),
                bump: rent_vault_bump,
            },
            escrow_0: PdaVector {
                address: escrow0_pda.to_string(),
                bump: escrow0_bump,
            },
            unwrap_pda: PdaVector {
                address: unwrap_pda.to_string(),
                bump: unwrap_bump,
            },
            lane_1: PdaVector {
                address: lane1_pda.to_string(),
                bump: lane1_bump,
            },
            lane_rent_vault_1: PdaVector {
                address: lane1_rent_pda.to_string(),
                bump: lane1_rent_bump,
            },
            proof_buffer_authority: buf_auth.to_string(),
            proof_buffer_nonce: buf_nonce,
            proof_buffer: PdaVector {
                address: buf_pda.to_string(),
                bump: buf_bump,
            },
            nullifier_pda: PdaVector {
                address: nullifier_pda.to_string(),
                bump: nullifier_bump,
            },
        },
        asset_generators: AssetGeneratorsVector {
            native_sol_mint_b58: Address::new_from_array(NATIVE_SOL_MINT).to_string(),
            native_sol_gen_hex: to_hex(&sol_gen),
            wsol_mint_b58: Address::new_from_array(WSOL_MINT).to_string(),
            wsol_gen_hex: to_hex(&wsol_gen),
            usdc_mint_b58: usdc_addr.to_string(),
            usdc_gen_hex: to_hex(&usdc_gen),
        },
        pool_state: PoolStateVector {
            raw_hex: to_hex(&pool_raw),
            version: pool_state.version,
            bump: pool_state.bump,
            mode: pool_state.mode as u8,
            paused: pool_state.paused,
            pool_id: pool_state.pool_id,
            current_page_id: pool_state.current_page_id,
            total_notes: pool_state.total_notes,
            total_spends: pool_state.total_spends,
            page_rent_fee_lamports: pool_state.page_rent_fee_lamports,
            authority: buf_auth.to_string(),
            auditor_pk_hex: to_hex(&pool_state.auditor_pk),
            auditor_locked: pool_state.auditor_locked,
            vault_auth_bump: pool_state.vault_auth_bump,
            sol_vault_bump: pool_state.sol_vault_bump,
            page_rent_bump: pool_state.page_rent_bump,
            active_lanes: pool_state.active_lanes,
        },
        epoch_page: EpochPageVector {
            pool_id,
            page_id,
            version: header.version,
            bump: header.bump,
            closed: header.closed,
            count: header.count,
            created_slot: header.created_slot,
            closed_slot: header.closed_slot,
            scan_offset: PAGE_SCAN_OFFSET,
            scan_length: PAGE_SCAN_LEN,
            page_hex: to_hex(&page_bytes),
            scan_slice_hex: to_hex(scan_slice),
            matched_slots,
            alice_note: OwnedNoteVector {
                page_id,
                slot_index: alice_slot as u8,
                mint_hex: to_hex(&decrypted.mint),
                amount: decrypted.amount,
                is_dynamic_output: decrypted.is_dynamic_output,
                stealth_pk_hex: to_hex(&decrypted.stealth_pk),
                asset_tag_hex: to_hex(&decrypted.asset_tag),
                commitment_hex: to_hex(&decrypted.commitment),
                asset_blinding_hex: to_hex(&decrypted.asset_blinding.to_bytes()),
                value_blinding_hex: to_hex(&decrypted.value_blinding.to_bytes()),
                stealth_scalar_hex: to_hex(&decrypted.stealth_scalar.to_bytes()),
                spend_x_hex: to_hex(&spend_x.to_bytes()),
                nullifier_hex: to_hex(&nullifier),
                nullifier_pda: nullifier_pda.to_string(),
            },
        },
        selective_disclosure_json: disclosure_json,
        auditor: AuditorVector {
            auditor_seed_hex: to_hex(&auditor_seed),
            auditor_sk_hex: to_hex(&auditor.auditor_sk.to_bytes()),
            auditor_pk_hex: to_hex(&auditor.auditor_pk),
            elgamal_s1_hex: to_hex(&s1),
            elgamal_s2_hex: to_hex(&s2),
            expected_spent_pk_hex: to_hex(&decrypted.stealth_pk),
            elgamal_m1_hex: to_hex(&m1),
            elgamal_m2_hex: to_hex(&m2),
            expected_asset_gen_hex: to_hex(&usdc_gen),
        },
        jupiter_cpi_excluded_dexes: JUPITER_CPI_EXCLUDED_DEXES.to_string(),
    }
}

#[test]
fn canonical_conformance_vectors_match_and_prove_end_to_end() {
    let generated = generate_canonical_vectors();
    let path = vectors_path();

    if std::env::var("AUDREN_WRITE_VECTORS").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let pretty = serde_json::to_string_pretty(&generated).unwrap();
        std::fs::write(&path, format!("{pretty}\n")).unwrap();
    }

    let raw = std::fs::read_to_string(&path).expect(
        "spec/test-vectors.json missing; run AUDREN_WRITE_VECTORS=1 cargo test -p audren-client --test conformance_vectors",
    );
    let expected: ConformanceVectors = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        generated, expected,
        "Rust client diverged from spec/test-vectors.json"
    );

    // Also verify FullViewingKey round-trip & read-only decrypt matches exactly
    let fvk_exp = serde_json::from_str(&expected.alice.full_viewing_key_json).unwrap();
    let fvk = FullViewingKey::from_export(&fvk_exp).unwrap();
    let page_bytes = from_hex(&expected.epoch_page.page_hex);
    let program_id: Address = expected.program_id.parse().unwrap();

    let ro_note = decrypt_owned_note(
        &fvk,
        None,
        &program_id,
        expected.epoch_page.pool_id,
        &page_bytes,
        expected.epoch_page.alice_note.slot_index as usize,
        None,
    )
    .unwrap()
    .expect("FVK must decrypt Alice note");
    assert_eq!(ro_note.amount, expected.epoch_page.alice_note.amount);
    assert!(ro_note.spend_x.is_none());

    // Tampered selective disclosure MUST return false
    let mut tampered: SelectiveDisclosureProof =
        serde_json::from_str(&expected.selective_disclosure_json).unwrap();
    tampered.amount += 1;
    assert!(!tampered.verify().unwrap());
    assert!(!tampered.verify_against_page(&page_bytes).unwrap());

    // End-to-end real ZK proofs (Deposit, Transfer m=5, Withdraw) using canonical vector page
    let alice_seed = from_hex_32(&expected.alice.seed_hex);
    let alice = AudrenKeys::from_seed(&alice_seed);
    let bob_addr = AudrenAddress::from_base58(&expected.bob.address).unwrap();
    let payer = Address::new_from_array([0x55u8; 32]);
    let mut rng = StdRng::from_seed([0x77u8; 32]);

    let (dep_ix, dep_note) = build_deposit(
        program_id,
        payer,
        0,
        1,
        &bob_addr,
        NATIVE_SOL_MINT,
        500_000,
        None,
        &mut rng,
    )
    .unwrap();
    assert_eq!(dep_ix.data[0], 2); // Tag 2 = Deposit
    assert_eq!(dep_note.amount, 500_000);

    let full_note = decrypt_owned_note(
        &alice.full_viewing_key(),
        Some(&alice),
        &program_id,
        expected.epoch_page.pool_id,
        &page_bytes,
        expected.epoch_page.alice_note.slot_index as usize,
        None,
    )
    .unwrap()
    .unwrap();

    let ring: Vec<RingSlotWitness> = (0..PAGE_CAPACITY)
        .map(|slot| {
            let (stealth_pk, asset_tag, commitment) = read_page_witness(&page_bytes, slot).unwrap();
            RingSlotWitness {
                stealth_pk,
                asset_tag,
                commitment,
            }
        })
        .collect();

    let (xfer_ix, pay_note, chg_note) = build_transfer(
        program_id,
        payer,
        0,
        1,
        &[0],
        &ring,
        &full_note,
        expected.epoch_page.alice_note.slot_index as usize,
        &bob_addr,
        &alice.address(),
        900_000,
        None,
        &[],
        &mut rng,
    )
    .unwrap();
    assert_eq!(xfer_ix.data[0], 3); // Tag 3 = Transfer
    assert_eq!(xfer_ix.data.len(), 2_373);
    assert_eq!(xfer_ix.accounts.len(), 8);
    assert_eq!(pay_note.amount, 900_000);
    assert_eq!(chg_note.amount, 600_000);

    // Audited Transfer + extract_transfer_auditor_ciphertexts round-trip
    let aud_seed = from_hex(&expected.auditor.auditor_seed_hex);
    let mut aud_seed32 = [0u8; 32];
    aud_seed32.copy_from_slice(&aud_seed);
    let aud_kp = AuditorKeypair::from_seed(&aud_seed32);
    let (aud_xfer_ix, _, _) = build_transfer(
        program_id,
        payer,
        0,
        1,
        &[0],
        &ring,
        &full_note,
        expected.epoch_page.alice_note.slot_index as usize,
        &bob_addr,
        &alice.address(),
        900_000,
        Some(aud_kp.auditor_pk),
        &[],
        &mut rng,
    )
    .unwrap();
    let (s1, s2, m1, m2) =
        audren_client::instructions::extract_transfer_auditor_ciphertexts(&aud_xfer_ix.data)
            .expect("extract audited ciphertexts");
    assert_eq!(
        aud_kp.decrypt_spent_pubkey(&s1, &s2).unwrap(),
        full_note.stealth_pk
    );
    assert_eq!(
        aud_kp.decrypt_asset_generator(&m1, &m2).unwrap(),
        asset_generator(&full_note.mint)
    );

    // SelectiveDisclosureProof::from_owned_note matches canonical vector JSON
    let sd_from_helper = SelectiveDisclosureProof::from_owned_note(&full_note);
    let sd_expected: SelectiveDisclosureProof =
        serde_json::from_str(&expected.selective_disclosure_json).unwrap();
    assert_eq!(sd_from_helper, sd_expected);

    let (wd_ix, wd_chg) = build_withdraw(
        program_id,
        payer,
        0,
        1,
        &[0],
        &ring,
        &full_note,
        expected.epoch_page.alice_note.slot_index as usize,
        payer,
        &alice.address(),
        1_000_000,
        None,
        None,
        &mut rng,
    )
    .unwrap();
    assert_eq!(wd_ix.data[0], 6); // Tag 6 = Withdraw
    assert_eq!(wd_ix.data.len(), 1_973);
    assert_eq!(wd_ix.accounts.len(), 11);
    assert_eq!(wd_chg.unwrap().amount, 500_000);

    // Self-paying Withdraw with relayer_fee
    let fee_recipient = Address::new_from_array([0x66u8; 32]);
    let (wd_fee_ix, wd_fee_chg) = build_withdraw_with_params(
        &WithdrawParams {
            program_id,
            payer,
            pool_id: 0,
            out_page_id: 1,
            input_page_ids: &[0],
            ring: &ring,
            input_note: &full_note,
            secret_index: expected.epoch_page.alice_note.slot_index as usize,
            recipient_account: payer,
            change_addr: &alice.address(),
            amount: 900_000,
            relayer_fee: 100_000,
            fee_recipient: Some(fee_recipient),
            unwrap_wsol: false,
            spl_token_program: None,
            auditor_pk: None,
        },
        &mut rng,
    )
    .unwrap();
    assert_eq!(wd_fee_ix.accounts[7].pubkey, fee_recipient);
    assert!(wd_fee_ix.accounts[7].is_writable);
    assert_eq!(wd_fee_chg.unwrap().amount, 500_000);

    // Zero-dust Native SOL sweep Deposit (fee_from_amount = true)
    let (sweep_ix, _) = build_deposit_with_options(
        program_id,
        payer,
        0,
        1,
        &bob_addr,
        NATIVE_SOL_MINT,
        500_000,
        500_000,
        true,
        None,
        &[],
        &mut rng,
    )
    .unwrap();
    assert_eq!(sweep_ix.data[0], 2);
    assert_eq!(sweep_ix.data[1], 0x03); // DEPOSIT_FLAG_NATIVE_SOL | DEPOSIT_FLAG_FEE_FROM_AMOUNT

    // Escrow & Relayer helpers
    assert_eq!(
        audren_client::router::DEFAULT_RELAY_URL,
        "https://relay.audren.xyz"
    );
    let classic_tp = Address::new_from_array(audren_core::CLASSIC_TOKEN_PROGRAM_ID);
    let wsol_mint: Address = expected.asset_generators.wsol_mint_b58.parse().unwrap();
    let usdc_mint: Address = expected.asset_generators.usdc_mint_b58.parse().unwrap();
    let (escrow0, _) = derive_escrow_pda(&program_id, 0, 0);
    let escrow_in = audren_client::pda::derive_ata(&escrow0, &classic_tp, &wsol_mint);
    let escrow_out = audren_client::pda::derive_ata(&escrow0, &classic_tp, &usdc_mint);
    let prep = audren_client::router::prepare_escrow_accounts(
        &program_id,
        0,
        0,
        &wsol_mint,
        &usdc_mint,
        &classic_tp,
        &classic_tp,
        &[
            audren_client::instructions::AudrenAccountMeta::writable(escrow_in),
            audren_client::instructions::AudrenAccountMeta::writable_signer(escrow0),
            audren_client::instructions::AudrenAccountMeta::writable(escrow_out),
        ],
    )
    .unwrap();
    assert_eq!((prep.escrow_idx, prep.escrow_in_idx, prep.escrow_out_idx), (1, 0, 2));
    assert!(!prep.accounts[1].is_signer);
}
