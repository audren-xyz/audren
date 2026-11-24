//! Audren v1 Mobile & Native FFI Facade (UniFFI -> Swift for iOS/macOS & Kotlin for Android/JVM).
//!
//! Exposes all Audren v1 building blocks backed directly by `audren-core`, `audren-circuits`,
//! and `audren-client` with zero duplicated cryptography and zero transcript drift:
//! 1. Keys, BIP-350 Bech32m `aud1...` stealth addresses, Mode 2 `FullViewingKey`,
//!    and deterministic `DefiSessionKeypair`
//! 2. Canonical 12 `audren_*` PDAs, ATA derivation, and zero-copy account decoders
//! 3. Zero-indexer `CompactWalletStore` & versioned `106 B` AEAD memo encryption/decryption
//! 4. Local BN254 Groth16 proving (`17,861` R1CS) and all 9 v1 instruction builders (`0x00..=0x08`)
//! 5. Mode 1 `SelectiveDisclosureProof` verification (1 Poseidon check, zero keys revealed)
//! 6. Relayer & Jupiter CPI exclusion constants

use std::{collections::BTreeSet, sync::OnceLock};

use audren_circuits::{
    note::{compute_note_commitment, derive_asset_id, derive_stealth_owner},
    poseidon::{fr_from_be_bytes_strict, fr_to_be_bytes},
};
use audren_client::{
    instructions::{
        build_set_paused, build_update_pool, compute_page_rollovers, deterministic_note_rent_fee,
        plan_auto_open_pages as rust_plan_auto_open_pages,
        recommended_cu_limit_deposit_with_bumps as rust_recommended_cu_limit_deposit_with_bumps,
        recommended_cu_limit_exec_via_escrow_with_bumps as rust_recommended_cu_limit_exec_via_escrow_with_bumps,
        recommended_cu_limit_open_page_with_bumps as rust_recommended_cu_limit_open_page_with_bumps,
        recommended_cu_limit_transact_with_bumps as rust_recommended_cu_limit_transact_with_bumps,
        try_build_deposit, try_build_exec_via_escrow, try_build_init_lane, try_build_init_pool,
        try_build_init_root_history, try_build_open_page, try_build_transact,
        try_compute_exec_ctx_hash, try_compute_transact_ctx_hash, AudrenAccountMeta,
        AudrenInstruction, UpdatePoolAction,
    },
    keys::{
        check_memo_view_tag as rust_check_view_tag,
        encrypt_note_memo_with_payment_id as rust_encrypt_memo_with_pid,
        prepare_dynamic_swap_memo as rust_prepare_dyn_memo,
        try_decrypt_and_verify_memo_entry as rust_decrypt_memo, AudrenAddress, AudrenKeys,
        FullViewingKey, SelectiveDisclosureProof,
    },
    pda::{
        derive_ata as rust_derive_ata, derive_escrow_pda as rust_derive_escrow_pda,
        derive_lane_pda as rust_derive_lane_pda, derive_lane_rent_pda as rust_derive_lane_rent_pda,
        derive_memo_pda as rust_derive_memo_pda, derive_nf_page_pda as rust_derive_nf_page_pda,
        derive_nullifier_pda as rust_derive_nullifier_pda,
        derive_pool_pda as rust_derive_pool_pda, derive_roots_pda as rust_derive_roots_pda,
        derive_subroot_pda as rust_derive_subroot_pda,
        derive_subtree_pda as rust_derive_subtree_pda, derive_unwrap_pda as rust_derive_unwrap_pda,
        derive_vault_auth_pda as rust_derive_vault_auth_pda,
    },
    prover::AudrenProver,
    router::{DEFAULT_RELAY_URL, JUPITER_CPI_EXCLUDED_DEXES},
    scanner::{
        decode_global_root_history, decode_lane_header, decode_pool_state,
        validate_global_root_history,
    },
    store::CompactWalletStore,
    ClientError,
};
use audren_core::{
    instruction::{
        OPEN_PAGE_KIND_MEMO, OPEN_PAGE_KIND_NULLIFIER, OPEN_PAGE_KIND_SUBROOT,
        OPEN_PAGE_KIND_SUBTREE,
    },
    layout::{DYN_MEMO_HEAD_LEN, MEMO_CT_LEN, MEMO_ENTRY_WIRE_LEN, MEMO_PAYMENT_ID_LEN},
    AUDREN_PROGRAM_ID, NUM_ESCROW_SHARDS, NUM_LANES, PROTOCOL_VERSION,
};
use solana_address::Address;

uniffi::setup_scaffolding!();

static CANONICAL_PROVER: OnceLock<AudrenProver> = OnceLock::new();

fn canonical_prover() -> &'static AudrenProver {
    CANONICAL_PROVER.get_or_init(AudrenProver::from_canonical_pk)
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum AudrenFfiError {
    #[error("invalid input: {reason}")]
    InvalidInput { reason: String },
    #[error("cryptographic error: {reason}")]
    Crypto { reason: String },
}

impl From<ClientError> for AudrenFfiError {
    fn from(err: ClientError) -> Self {
        match err {
            ClientError::InvalidEncoding(m) | ClientError::InvalidProofInput(m) => {
                Self::InvalidInput {
                    reason: m.to_string(),
                }
            }
            ClientError::InvalidFieldElement => Self::Crypto {
                reason: "non-canonical BN254 Fr scalar".to_string(),
            },
            ClientError::Crypto(m) | ClientError::WitnessNotFound(m) => Self::Crypto {
                reason: m.to_string(),
            },
        }
    }
}

fn to_arr<const N: usize>(bytes: &[u8], label: &str) -> Result<[u8; N], AudrenFfiError> {
    if bytes.len() != N {
        return Err(AudrenFfiError::InvalidInput {
            reason: format!("{label} must be {N} bytes, got {}", bytes.len()),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn parse_addr(s: &str, label: &str) -> Result<Address, AudrenFfiError> {
    s.parse::<Address>().map_err(|_| AudrenFfiError::InvalidInput {
        reason: format!("invalid base58 pubkey for {label}"),
    })
}

fn validate_lane_id(lane_id: u8) -> Result<(), AudrenFfiError> {
    if (lane_id as usize) >= NUM_LANES {
        return Err(AudrenFfiError::InvalidInput {
            reason: format!("lane_id must be 0..{}, got {lane_id}", NUM_LANES - 1),
        });
    }
    Ok(())
}

fn validate_shard_id(shard_id: u8) -> Result<(), AudrenFfiError> {
    if (shard_id as usize) >= NUM_ESCROW_SHARDS {
        return Err(AudrenFfiError::InvalidInput {
            reason: format!(
                "shard_id must be 0..{}, got {shard_id}",
                NUM_ESCROW_SHARDS - 1
            ),
        });
    }
    Ok(())
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiAudrenKeys {
    pub spend_sk: Vec<u8>,
    pub spend_pk: Vec<u8>,
    pub nk: Vec<u8>,
    pub view_sk: Vec<u8>,
    pub view_pk: Vec<u8>,
    pub address: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiFullViewingKey {
    pub spend_pk: Vec<u8>,
    pub nk: Vec<u8>,
    pub view_sk: Vec<u8>,
    pub view_pk: Vec<u8>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiDefiSessionKeypair {
    pub session_index: u32,
    pub secret_seed: Vec<u8>,
    pub pubkey_b58: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiPdaResult {
    pub address: String,
    pub bump: u8,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiPoolState {
    pub version: u8,
    pub bump: u8,
    pub paused: bool,
    pub active_lanes: u8,
    pub pool_id: u32,
    pub root_epoch_interval: u64,
    pub authority_b58: String,
    pub vault_auth_bump: u8,
    pub note_rent_fee: u64,
    pub nf_rent_fee: u64,
    pub pending_authority_b58: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiLaneHeader {
    pub version: u8,
    pub lane_id: u8,
    pub bump: u8,
    pub rent_bump: u8,
    pub pool_id: u32,
    pub next_leaf: u64,
    pub nf_count: u64,
    pub current_root: Vec<u8>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiGlobalRootHistory {
    pub version: u8,
    pub bump: u8,
    pub pool_id: u32,
    pub slot_cursor: u16,
    pub epoch_cursor: u16,
    pub slot_count: u16,
    pub epoch_count: u16,
    pub same_slot_bumped: bool,
    pub latest_slot: u64,
    pub stable_epoch_id: u64,
    pub stable_slot: u64,
    pub epoch_interval: u64,
    pub latest_super_root: Vec<u8>,
    pub latest_lane_roots: Vec<Vec<u8>>,
    pub latest_lane_counts: Vec<u64>,
    pub stable_super_root: Vec<u8>,
    pub stable_lane_roots: Vec<Vec<u8>>,
    pub stable_lane_counts: Vec<u64>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiNoteCoord {
    pub lane_id: u8,
    pub leaf_index: u64,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiRootSnapshotChoice {
    pub ring_kind: u8,
    pub ring_idx: u8,
    pub slot: u64,
    pub super_root: Vec<u8>,
    pub lane_roots: Vec<Vec<u8>>,
    pub lane_counts: Vec<u64>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiOpenPageSpec {
    pub page_kind: u8,
    pub page_seq: u64,
    pub pda_b58: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiPageRolloverPlan {
    pub out_sub_seq: u64,
    pub out_root_seq: u64,
    pub out_memo_seq: u64,
    pub nf_page_seq: u64,
    pub next_sub_seq: Option<u64>,
    pub next_root_seq: Option<u64>,
    pub next_memo_seq: Option<u64>,
    pub next_nf_seq: Option<u64>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiEncryptedMemo {
    pub tweak: Vec<u8>,
    pub blinding: Vec<u8>,
    pub stealth_owner: Vec<u8>,
    pub commitment: Vec<u8>,
    pub memo_106: Vec<u8>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiDynamicMemoPrep {
    pub tweak: Vec<u8>,
    pub blinding: Vec<u8>,
    pub dyn_head_34: Vec<u8>,
    pub dyn_mask_72: Vec<u8>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiDecryptedMemo {
    pub tweak: Vec<u8>,
    pub blinding: Vec<u8>,
    pub amount: u64,
    pub mint: Vec<u8>,
    pub memo_version: u8,
    pub memo_flags: u8,
    pub payment_id: Vec<u8>,
    pub is_dynamic: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiSelectiveDisclosureProof {
    pub pool_id: u32,
    pub lane_id: u8,
    pub leaf_index: u64,
    pub stealth_owner: Vec<u8>,
    pub mint: Vec<u8>,
    pub amount: u64,
    pub blinding: Vec<u8>,
    pub commitment: Vec<u8>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiAccountMeta {
    pub pubkey_b58: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiInstruction {
    pub program_id_b58: String,
    pub accounts: Vec<FfiAccountMeta>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiGroth16ProofBundle {
    pub proof_192: Vec<u8>,
    pub nf0: Vec<u8>,
    pub nf1: Vec<u8>,
    pub cm0: Vec<u8>,
    pub cm1: Vec<u8>,
    pub cm2: Vec<u8>,
    pub public_input_hash: Vec<u8>,
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum FfiUpdatePoolAction {
    UpdateParams {
        note_rent_fee: u64,
        nf_rent_fee: u64,
    },
    ProposeAuthority {
        pending_authority: String,
    },
    AcceptAuthority,
    RenounceAuthority,
}

fn from_audren_ix(ix: AudrenInstruction) -> FfiInstruction {
    FfiInstruction {
        program_id_b58: Address::new_from_array(ix.program_id).to_string(),
        accounts: ix
            .accounts
            .into_iter()
            .map(|m| FfiAccountMeta {
                pubkey_b58: Address::new_from_array(m.pubkey).to_string(),
                is_signer: m.is_signer,
                is_writable: m.is_writable,
            })
            .collect(),
        data: ix.data,
    }
}

fn to_audren_metas(metas: &[FfiAccountMeta]) -> Result<Vec<AudrenAccountMeta>, AudrenFfiError> {
    metas
        .iter()
        .map(|m| {
            let a = parse_addr(&m.pubkey_b58, "account_meta")?;
            Ok(AudrenAccountMeta {
                pubkey: a.to_bytes(),
                is_signer: m.is_signer,
                is_writable: m.is_writable,
            })
        })
        .collect()
}

fn keys_to_ffi(k: &AudrenKeys) -> Result<FfiAudrenKeys, AudrenFfiError> {
    Ok(FfiAudrenKeys {
        spend_sk: fr_to_be_bytes(&k.spend_sk).to_vec(),
        spend_pk: fr_to_be_bytes(&k.spend_pk).to_vec(),
        nk: fr_to_be_bytes(&k.nk).to_vec(),
        view_sk: k.view_sk.to_vec(),
        view_pk: k.view_pk.to_vec(),
        address: k.address().encode()?,
    })
}

fn fvk_from_ffi(fvk: &FfiFullViewingKey) -> Result<FullViewingKey, AudrenFfiError> {
    Ok(FullViewingKey {
        spend_pk: to_arr::<32>(&fvk.spend_pk, "fvk.spend_pk")?,
        nk: to_arr::<32>(&fvk.nk, "fvk.nk")?,
        view_sk: to_arr::<32>(&fvk.view_sk, "fvk.view_sk")?,
        view_pk: to_arr::<32>(&fvk.view_pk, "fvk.view_pk")?,
    })
}

#[uniffi::export]
pub fn protocol_version() -> u8 {
    PROTOCOL_VERSION
}

#[uniffi::export]
pub fn canonical_program_id() -> String {
    Address::new_from_array(AUDREN_PROGRAM_ID).to_string()
}

#[uniffi::export]
pub fn default_relay_url() -> String {
    DEFAULT_RELAY_URL.to_string()
}

#[uniffi::export]
pub fn jupiter_cpi_excluded_dexes() -> Vec<String> {
    JUPITER_CPI_EXCLUDED_DEXES
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

#[uniffi::export]
pub fn derive_keys_from_seed(seed: Vec<u8>) -> Result<FfiAudrenKeys, AudrenFfiError> {
    let s = to_arr::<32>(&seed, "seed")?;
    keys_to_ffi(&AudrenKeys::from_seed(&s))
}

#[uniffi::export]
pub fn derive_subaccount_keys(
    seed: Vec<u8>,
    account_index: u32,
) -> Result<FfiAudrenKeys, AudrenFfiError> {
    let s = to_arr::<32>(&seed, "seed")?;
    keys_to_ffi(&AudrenKeys::from_seed_subaccount(&s, account_index))
}

#[uniffi::export]
pub fn export_full_viewing_key(seed: Vec<u8>) -> Result<FfiFullViewingKey, AudrenFfiError> {
    let s = to_arr::<32>(&seed, "seed")?;
    let fvk = AudrenKeys::from_seed(&s).full_viewing_key();
    Ok(FfiFullViewingKey {
        spend_pk: fvk.spend_pk.to_vec(),
        nk: fvk.nk.to_vec(),
        view_sk: fvk.view_sk.to_vec(),
        view_pk: fvk.view_pk.to_vec(),
    })
}

#[uniffi::export]
pub fn derive_defi_session_keypair(
    seed: Vec<u8>,
    session_index: u32,
) -> Result<FfiDefiSessionKeypair, AudrenFfiError> {
    let s = to_arr::<32>(&seed, "seed")?;
    let kp = AudrenKeys::derive_defi_session_keypair(&s, session_index);
    Ok(FfiDefiSessionKeypair {
        session_index: kp.session_index,
        secret_seed: kp.secret_seed.to_vec(),
        pubkey_b58: Address::new_from_array(kp.pubkey).to_string(),
    })
}

#[uniffi::export]
pub fn decode_audren_address(encoded: String) -> Result<Vec<Vec<u8>>, AudrenFfiError> {
    let addr = AudrenAddress::decode(&encoded)?;
    Ok(vec![addr.spend_pk.to_vec(), addr.view_pk.to_vec()])
}

#[uniffi::export]
pub fn derive_asset_id_bytes(mint_bytes: Vec<u8>) -> Result<Vec<u8>, AudrenFfiError> {
    let m = to_arr::<32>(&mint_bytes, "mint_bytes")?;
    Ok(fr_to_be_bytes(&derive_asset_id(&m)).to_vec())
}

#[uniffi::export]
pub fn derive_pool_pda(program_id: String, pool_id: u32) -> Result<FfiPdaResult, AudrenFfiError> {
    let (a, b) = rust_derive_pool_pda(&parse_addr(&program_id, "program_id")?, pool_id);
    Ok(FfiPdaResult {
        address: a.to_string(),
        bump: b,
    })
}

#[uniffi::export]
pub fn derive_vault_auth_pda(
    program_id: String,
    pool_id: u32,
) -> Result<FfiPdaResult, AudrenFfiError> {
    let (a, b) = rust_derive_vault_auth_pda(&parse_addr(&program_id, "program_id")?, pool_id);
    Ok(FfiPdaResult {
        address: a.to_string(),
        bump: b,
    })
}

#[uniffi::export]
pub fn derive_lane_pda(
    program_id: String,
    pool_id: u32,
    lane_id: u8,
) -> Result<FfiPdaResult, AudrenFfiError> {
    validate_lane_id(lane_id)?;
    let (a, b) = rust_derive_lane_pda(&parse_addr(&program_id, "program_id")?, pool_id, lane_id);
    Ok(FfiPdaResult {
        address: a.to_string(),
        bump: b,
    })
}

#[uniffi::export]
pub fn derive_lane_rent_pda(
    program_id: String,
    pool_id: u32,
    lane_id: u8,
) -> Result<FfiPdaResult, AudrenFfiError> {
    validate_lane_id(lane_id)?;
    let (a, b) =
        rust_derive_lane_rent_pda(&parse_addr(&program_id, "program_id")?, pool_id, lane_id);
    Ok(FfiPdaResult {
        address: a.to_string(),
        bump: b,
    })
}

#[uniffi::export]
pub fn derive_subtree_pda(
    program_id: String,
    pool_id: u32,
    lane_id: u8,
    page_seq: u64,
) -> Result<FfiPdaResult, AudrenFfiError> {
    validate_lane_id(lane_id)?;
    let (a, b) = rust_derive_subtree_pda(
        &parse_addr(&program_id, "program_id")?,
        pool_id,
        lane_id,
        page_seq,
    );
    Ok(FfiPdaResult {
        address: a.to_string(),
        bump: b,
    })
}

#[uniffi::export]
pub fn derive_subroot_pda(
    program_id: String,
    pool_id: u32,
    lane_id: u8,
    root_page_seq: u64,
) -> Result<FfiPdaResult, AudrenFfiError> {
    validate_lane_id(lane_id)?;
    let (a, b) = rust_derive_subroot_pda(
        &parse_addr(&program_id, "program_id")?,
        pool_id,
        lane_id,
        root_page_seq,
    );
    Ok(FfiPdaResult {
        address: a.to_string(),
        bump: b,
    })
}

#[uniffi::export]
pub fn derive_memo_pda(
    program_id: String,
    pool_id: u32,
    lane_id: u8,
    page_seq: u64,
) -> Result<FfiPdaResult, AudrenFfiError> {
    validate_lane_id(lane_id)?;
    let (a, b) = rust_derive_memo_pda(
        &parse_addr(&program_id, "program_id")?,
        pool_id,
        lane_id,
        page_seq,
    );
    Ok(FfiPdaResult {
        address: a.to_string(),
        bump: b,
    })
}

#[uniffi::export]
pub fn derive_nf_page_pda(
    program_id: String,
    pool_id: u32,
    lane_id: u8,
    page_seq: u64,
) -> Result<FfiPdaResult, AudrenFfiError> {
    validate_lane_id(lane_id)?;
    let (a, b) = rust_derive_nf_page_pda(
        &parse_addr(&program_id, "program_id")?,
        pool_id,
        lane_id,
        page_seq,
    );
    Ok(FfiPdaResult {
        address: a.to_string(),
        bump: b,
    })
}

#[uniffi::export]
pub fn derive_roots_pda(program_id: String, pool_id: u32) -> Result<FfiPdaResult, AudrenFfiError> {
    let (a, b) = rust_derive_roots_pda(&parse_addr(&program_id, "program_id")?, pool_id);
    Ok(FfiPdaResult {
        address: a.to_string(),
        bump: b,
    })
}

#[uniffi::export]
pub fn derive_nullifier_pda(
    program_id: String,
    pool_id: u32,
    nullifier: Vec<u8>,
) -> Result<FfiPdaResult, AudrenFfiError> {
    let nf = to_arr::<32>(&nullifier, "nullifier")?;
    let (a, b) = rust_derive_nullifier_pda(&parse_addr(&program_id, "program_id")?, pool_id, &nf);
    Ok(FfiPdaResult {
        address: a.to_string(),
        bump: b,
    })
}

#[uniffi::export]
pub fn derive_escrow_pda(
    program_id: String,
    pool_id: u32,
    shard_id: u8,
) -> Result<FfiPdaResult, AudrenFfiError> {
    validate_shard_id(shard_id)?;
    let (a, b) =
        rust_derive_escrow_pda(&parse_addr(&program_id, "program_id")?, pool_id, shard_id);
    Ok(FfiPdaResult {
        address: a.to_string(),
        bump: b,
    })
}

#[uniffi::export]
pub fn derive_unwrap_pda(
    program_id: String,
    pool_id: u32,
    nf0: Vec<u8>,
) -> Result<FfiPdaResult, AudrenFfiError> {
    let n = to_arr::<32>(&nf0, "nf0")?;
    let (a, b) = rust_derive_unwrap_pda(&parse_addr(&program_id, "program_id")?, pool_id, &n);
    Ok(FfiPdaResult {
        address: a.to_string(),
        bump: b,
    })
}

#[uniffi::export]
pub fn derive_ata(
    owner: String,
    token_program: String,
    mint: String,
) -> Result<String, AudrenFfiError> {
    Ok(rust_derive_ata(
        &parse_addr(&owner, "owner")?,
        &parse_addr(&token_program, "token_program")?,
        &parse_addr(&mint, "mint")?,
    )
    .to_string())
}

#[uniffi::export]
pub fn decode_pool_state_account(data: Vec<u8>) -> Result<FfiPoolState, AudrenFfiError> {
    let p = decode_pool_state(&data)?;
    Ok(FfiPoolState {
        version: p.version,
        bump: p.bump,
        paused: p.paused,
        active_lanes: p.active_lanes,
        pool_id: p.pool_id,
        root_epoch_interval: p.root_epoch_interval,
        authority_b58: Address::new_from_array(p.authority).to_string(),
        vault_auth_bump: p.vault_auth_bump,
        note_rent_fee: p.note_rent_fee,
        nf_rent_fee: p.nf_rent_fee,
        pending_authority_b58: Address::new_from_array(p.pending_authority).to_string(),
    })
}

#[uniffi::export]
pub fn decode_lane_header_account(data: Vec<u8>) -> Result<FfiLaneHeader, AudrenFfiError> {
    let l = decode_lane_header(&data)?;
    Ok(FfiLaneHeader {
        version: l.version,
        lane_id: l.lane_id,
        bump: l.bump,
        rent_bump: l.rent_bump,
        pool_id: l.pool_id,
        next_leaf: l.next_leaf,
        nf_count: l.nf_count,
        current_root: l.current_root.to_vec(),
    })
}

#[uniffi::export]
pub fn decode_global_root_history_account(
    data: Vec<u8>,
) -> Result<FfiGlobalRootHistory, AudrenFfiError> {
    let r = decode_global_root_history(&data)?;
    validate_global_root_history(&r, r.pool_id)?;
    Ok(FfiGlobalRootHistory {
        version: r.version,
        bump: r.bump,
        pool_id: r.pool_id,
        slot_cursor: r.slot_cursor,
        epoch_cursor: r.epoch_cursor,
        slot_count: r.slot_count,
        epoch_count: r.epoch_count,
        same_slot_bumped: r.same_slot_bumped,
        latest_slot: r.latest_slot,
        stable_epoch_id: r.stable_epoch_id,
        stable_slot: r.stable_slot,
        epoch_interval: r.epoch_interval,
        latest_super_root: r.latest_super_root.to_vec(),
        latest_lane_roots: r.latest_lane_roots.iter().map(|x| x.to_vec()).collect(),
        latest_lane_counts: r.latest_lane_counts.to_vec(),
        stable_super_root: r.stable_super_root.to_vec(),
        stable_lane_roots: r.stable_lane_roots.iter().map(|x| x.to_vec()).collect(),
        stable_lane_counts: r.stable_lane_counts.to_vec(),
    })
}

#[uniffi::export]
pub fn encrypt_note_memo(
    recipient_spend_pk: Vec<u8>,
    recipient_view_pk: Vec<u8>,
    eph_secret: Vec<u8>,
    amount: u64,
    mint: Vec<u8>,
    payment_id: Option<Vec<u8>>,
) -> Result<FfiEncryptedMemo, AudrenFfiError> {
    let spk_b = to_arr::<32>(&recipient_spend_pk, "recipient_spend_pk")?;
    let spk = fr_from_be_bytes_strict(&spk_b).ok_or(ClientError::InvalidFieldElement)?;
    let vpk = to_arr::<32>(&recipient_view_pk, "recipient_view_pk")?;
    let eph = to_arr::<32>(&eph_secret, "eph_secret")?;
    let m = to_arr::<32>(&mint, "mint")?;
    let pid = match payment_id {
        Some(b) => to_arr::<MEMO_PAYMENT_ID_LEN>(&b, "payment_id")?,
        None => [0u8; MEMO_PAYMENT_ID_LEN],
    };
    let (tw, bl, memo) = rust_encrypt_memo_with_pid(&vpk, eph, amount, &m, pid)?;
    let stealth = derive_stealth_owner(spk, tw);
    let cm = compute_note_commitment(stealth, derive_asset_id(&m), amount, bl);
    Ok(FfiEncryptedMemo {
        tweak: fr_to_be_bytes(&tw).to_vec(),
        blinding: fr_to_be_bytes(&bl).to_vec(),
        stealth_owner: fr_to_be_bytes(&stealth).to_vec(),
        commitment: fr_to_be_bytes(&cm).to_vec(),
        memo_106: memo.to_vec(),
    })
}

#[uniffi::export]
pub fn prepare_dynamic_swap_memo(
    recipient_view_pk: Vec<u8>,
    eph_secret: Vec<u8>,
) -> Result<FfiDynamicMemoPrep, AudrenFfiError> {
    let vpk = to_arr::<32>(&recipient_view_pk, "recipient_view_pk")?;
    let eph = to_arr::<32>(&eph_secret, "eph_secret")?;
    let (tw, bl, head, mask) = rust_prepare_dyn_memo(&vpk, eph)?;
    Ok(FfiDynamicMemoPrep {
        tweak: fr_to_be_bytes(&tw).to_vec(),
        blinding: fr_to_be_bytes(&bl).to_vec(),
        dyn_head_34: head.to_vec(),
        dyn_mask_72: mask.to_vec(),
    })
}

#[uniffi::export]
pub fn check_memo_view_tag(
    fvk: FfiFullViewingKey,
    view_tag: Vec<u8>,
    epk: Vec<u8>,
) -> Result<bool, AudrenFfiError> {
    let f = fvk_from_ffi(&fvk)?;
    let vt = to_arr::<2>(&view_tag, "view_tag")?;
    let e = to_arr::<32>(&epk, "epk")?;
    Ok(rust_check_view_tag(&f, vt, &e))
}

#[uniffi::export]
pub fn decrypt_and_verify_memo_entry(
    fvk: FfiFullViewingKey,
    memo_106: Vec<u8>,
    onchain_commitment: Vec<u8>,
) -> Result<Option<FfiDecryptedMemo>, AudrenFfiError> {
    let m = to_arr::<MEMO_ENTRY_WIRE_LEN>(&memo_106, "memo_106")?;
    let cm = to_arr::<32>(&onchain_commitment, "onchain_commitment")?;
    let f = fvk_from_ffi(&fvk)?;
    let vt = [m[0], m[1]];
    let mut epk = [0u8; 32];
    epk.copy_from_slice(&m[2..34]);
    let mut ct = [0u8; MEMO_CT_LEN];
    ct.copy_from_slice(&m[34..MEMO_ENTRY_WIRE_LEN]);
    Ok(rust_decrypt_memo(&f, vt, &epk, &ct, &cm).map(|d| FfiDecryptedMemo {
        tweak: fr_to_be_bytes(&d.tweak).to_vec(),
        blinding: fr_to_be_bytes(&d.blinding).to_vec(),
        amount: d.amount,
        mint: d.mint.to_vec(),
        memo_version: d.memo_version,
        memo_flags: d.memo_flags,
        payment_id: d.payment_id.to_vec(),
        is_dynamic: d.is_dynamic,
    }))
}

#[uniffi::export]
pub fn verify_selective_disclosure_proof(
    proof: FfiSelectiveDisclosureProof,
    onchain_subtree_leaf: Vec<u8>,
) -> Result<bool, AudrenFfiError> {
    let leaf = to_arr::<32>(&onchain_subtree_leaf, "onchain_subtree_leaf")?;
    let sd = SelectiveDisclosureProof {
        pool_id: proof.pool_id,
        lane_id: proof.lane_id,
        leaf_index: proof.leaf_index,
        stealth_owner: to_arr::<32>(&proof.stealth_owner, "stealth_owner")?,
        mint: to_arr::<32>(&proof.mint, "mint")?,
        amount: proof.amount,
        blinding: to_arr::<32>(&proof.blinding, "blinding")?,
        commitment: to_arr::<32>(&proof.commitment, "commitment")?,
    };
    Ok(sd.verify_against_leaf(&leaf))
}

#[uniffi::export]
pub fn compact_store_new_json(pool_id: u32, birthday_slot: u64) -> Result<String, AudrenFfiError> {
    let store = CompactWalletStore::new(pool_id, birthday_slot);
    String::from_utf8(store.to_json_bytes()?).map_err(|_| AudrenFfiError::Crypto {
        reason: "invalid UTF-8 JSON".to_string(),
    })
}

#[uniffi::export]
pub fn prove_joinsplit_witness_bytes(
    witness_4611: Vec<u8>,
    seed_32: Vec<u8>,
) -> Result<FfiGroth16ProofBundle, AudrenFfiError> {
    let seed = to_arr::<32>(&seed_32, "seed_32")?;
    let circuit = audren_circuits::decode_joinsplit_witness_bytes(&witness_4611).map_err(|c| {
        AudrenFfiError::InvalidInput {
            reason: format!("invalid binary witness (code {c})"),
        }
    })?;
    let b = canonical_prover().try_prove_with_seed(circuit, seed)?;
    Ok(FfiGroth16ProofBundle {
        proof_192: b.proof_192.to_vec(),
        nf0: b.nf0.to_vec(),
        nf1: b.nf1.to_vec(),
        cm0: b.cm0.to_vec(),
        cm1: b.cm1.to_vec(),
        cm2: b.cm2.to_vec(),
        public_input_hash: b.public_input_hash.to_vec(),
    })
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiTransactCtxHashParams {
    pub program_id: String,
    pub pool_id: u32,
    pub vk_id: u8,
    pub out_lane_id: u8,
    pub output_mask: u8,
    pub asset_mode: u8,
    pub unwrap_wsol: bool,
    pub recipient: Option<String>,
    pub relayer_fee_recipient: Option<String>,
    pub public_asset_id: Vec<u8>,
    pub public_amount_out: u64,
    pub relayer_fee_amount: u64,
    pub memos_bytes: Vec<u8>,
}

#[uniffi::export]
pub fn compute_transact_ctx_hash_ffi(
    params: FfiTransactCtxHashParams,
) -> Result<Vec<u8>, AudrenFfiError> {
    let pid = parse_addr(&params.program_id, "program_id")?;
    let recip = params
        .recipient
        .as_deref()
        .map(|s| parse_addr(s, "recipient"))
        .transpose()?;
    let fee_r = params
        .relayer_fee_recipient
        .as_deref()
        .map(|s| parse_addr(s, "relayer_fee_recipient"))
        .transpose()?;
    let paid = to_arr::<32>(&params.public_asset_id, "public_asset_id")?;
    let h = try_compute_transact_ctx_hash(
        &pid,
        params.pool_id,
        params.vk_id,
        params.out_lane_id,
        params.output_mask,
        params.asset_mode,
        params.unwrap_wsol,
        recip.as_ref(),
        fee_r.as_ref(),
        &paid,
        params.public_amount_out,
        params.relayer_fee_amount,
        &params.memos_bytes,
    )?;
    Ok(fr_to_be_bytes(&h).to_vec())
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiExecCtxHashParams {
    pub program_id: String,
    pub pool_id: u32,
    pub vk_id: u8,
    pub out_lane_id: u8,
    pub escrow_shard: u8,
    pub change_mask: u8,
    pub fee_on_output: bool,
    pub asset_in: Vec<u8>,
    pub amount_in: u64,
    pub relayer_fee_amount: u64,
    pub relayer_fee_recipient: Option<String>,
    pub asset_out: Vec<u8>,
    pub min_amount_out: u64,
    pub router_prog: String,
    pub router_accounts: Vec<FfiAccountMeta>,
    pub extra_writable_pubkeys: Vec<String>,
    pub out_stealth_owner: Vec<u8>,
    pub out_blinding: Vec<u8>,
    pub dyn_memo_head: Vec<u8>,
    pub dyn_mask_72: Vec<u8>,
    pub router_ix_data: Vec<u8>,
    pub change_memos: Vec<u8>,
}

#[uniffi::export]
pub fn compute_exec_ctx_hash_ffi(
    params: FfiExecCtxHashParams,
) -> Result<Vec<u8>, AudrenFfiError> {
    let pid = parse_addr(&params.program_id, "program_id")?;
    let rprog = parse_addr(&params.router_prog, "router_prog")?;
    let fee_r = params
        .relayer_fee_recipient
        .as_deref()
        .map(|s| parse_addr(s, "relayer_fee_recipient"))
        .transpose()?;
    let raccs = to_audren_metas(&params.router_accounts)?;
    let extra_writable: Vec<Address> = params
        .extra_writable_pubkeys
        .iter()
        .map(|s| parse_addr(s, "extra_writable_pubkeys"))
        .collect::<Result<_, _>>()?;
    let h = try_compute_exec_ctx_hash(
        &pid,
        params.pool_id,
        params.vk_id,
        params.out_lane_id,
        params.escrow_shard,
        params.change_mask,
        params.fee_on_output,
        &to_arr::<32>(&params.asset_in, "asset_in")?,
        params.amount_in,
        params.relayer_fee_amount,
        fee_r.as_ref(),
        &to_arr::<32>(&params.asset_out, "asset_out")?,
        params.min_amount_out,
        &rprog,
        &raccs,
        &extra_writable,
        &to_arr::<32>(&params.out_stealth_owner, "out_stealth_owner")?,
        &to_arr::<32>(&params.out_blinding, "out_blinding")?,
        &to_arr::<DYN_MEMO_HEAD_LEN>(&params.dyn_memo_head, "dyn_memo_head")?,
        &to_arr::<MEMO_CT_LEN>(&params.dyn_mask_72, "dyn_mask_72")?,
        &params.router_ix_data,
        &params.change_memos,
    )?;
    Ok(fr_to_be_bytes(&h).to_vec())
}

#[uniffi::export]
pub fn deterministic_note_rent_fee_ffi(
    pool_note_rent_fee_cap: u64,
    sub_rent: u64,
    sr_rent: u64,
    memo_rent: u64,
) -> u64 {
    deterministic_note_rent_fee(pool_note_rent_fee_cap, sub_rent, sr_rent, memo_rent)
}

#[uniffi::export]
pub fn compute_page_rollovers_ffi(
    leaf_count: u64,
    output_count: u32,
    nf_count: u64,
    spent_nullifiers: u32,
) -> FfiPageRolloverPlan {
    let p = compute_page_rollovers(
        leaf_count,
        output_count as usize,
        nf_count,
        spent_nullifiers as usize,
    );
    FfiPageRolloverPlan {
        out_sub_seq: p.out_sub_seq,
        out_root_seq: p.out_root_seq,
        out_memo_seq: p.out_memo_seq,
        nf_page_seq: p.nf_page_seq,
        next_sub_seq: p.next_sub_seq,
        next_root_seq: p.next_root_seq,
        next_memo_seq: p.next_memo_seq,
        next_nf_seq: p.next_nf_seq,
    }
}

#[uniffi::export]
pub fn build_init_pool_ix(
    program_id: String,
    payer: String,
    pool_id: u32,
    root_epoch_interval: u64,
    note_rent_fee: u64,
    nf_rent_fee: u64,
) -> Result<FfiInstruction, AudrenFfiError> {
    Ok(from_audren_ix(try_build_init_pool(
        parse_addr(&program_id, "program_id")?,
        parse_addr(&payer, "payer")?,
        pool_id,
        root_epoch_interval,
        note_rent_fee,
        nf_rent_fee,
    )?))
}

#[uniffi::export]
pub fn build_init_lane_ix(
    program_id: String,
    authority: String,
    pool_id: u32,
    lane_id: u8,
) -> Result<FfiInstruction, AudrenFfiError> {
    Ok(from_audren_ix(try_build_init_lane(
        parse_addr(&program_id, "program_id")?,
        parse_addr(&authority, "authority")?,
        pool_id,
        lane_id,
    )?))
}

#[uniffi::export]
pub fn build_open_page_ix(
    program_id: String,
    payer: String,
    page_kind: u8,
    pool_id: u32,
    lane_id: u8,
    page_seq: u64,
) -> Result<FfiInstruction, AudrenFfiError> {
    Ok(from_audren_ix(try_build_open_page(
        parse_addr(&program_id, "program_id")?,
        parse_addr(&payer, "payer")?,
        page_kind,
        pool_id,
        lane_id,
        page_seq,
    )?))
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiDepositParams {
    pub program_id: String,
    pub depositor: String,
    pub pool_id: u32,
    pub mint: String,
    pub source_account: String,
    pub vault_ata: String,
    pub token_prog: String,
    pub lane_id: u8,
    pub sub_page_seq: u64,
    pub root_page_seq: u64,
    pub memo_page_seq: u64,
    pub next_sub_seq: Option<u64>,
    pub next_memo_seq: Option<u64>,
    pub native_sol: bool,
    pub fee_from_amount: bool,
    pub amount: u64,
    pub stealth_owner: Vec<u8>,
    pub blinding: Vec<u8>,
    pub memo_106: Vec<u8>,
    pub transfer_hook_accounts: Vec<FfiAccountMeta>,
}

#[uniffi::export]
pub fn build_deposit_ix(params: FfiDepositParams) -> Result<FfiInstruction, AudrenFfiError> {
    let st = fr_from_be_bytes_strict(&to_arr::<32>(&params.stealth_owner, "stealth_owner")?)
        .ok_or(ClientError::InvalidFieldElement)?;
    let bl = fr_from_be_bytes_strict(&to_arr::<32>(&params.blinding, "blinding")?)
        .ok_or(ClientError::InvalidFieldElement)?;
    let m = to_arr::<MEMO_ENTRY_WIRE_LEN>(&params.memo_106, "memo_106")?;
    let hooks = to_audren_metas(&params.transfer_hook_accounts)?;
    Ok(from_audren_ix(try_build_deposit(
        parse_addr(&params.program_id, "program_id")?,
        parse_addr(&params.depositor, "depositor")?,
        params.pool_id,
        parse_addr(&params.mint, "mint")?,
        parse_addr(&params.source_account, "source_account")?,
        parse_addr(&params.vault_ata, "vault_ata")?,
        parse_addr(&params.token_prog, "token_prog")?,
        params.lane_id,
        params.sub_page_seq,
        params.root_page_seq,
        params.memo_page_seq,
        params.next_sub_seq,
        params.next_memo_seq,
        params.native_sol,
        params.fee_from_amount,
        params.amount,
        st,
        bl,
        &m,
        &hooks,
    )?))
}

#[uniffi::export]
pub fn build_init_root_history_ix(
    program_id: String,
    authority: String,
    pool_id: u32,
    root_epoch_interval: u64,
    active_lanes: u8,
) -> Result<FfiInstruction, AudrenFfiError> {
    Ok(from_audren_ix(try_build_init_root_history(
        parse_addr(&program_id, "program_id")?,
        parse_addr(&authority, "authority")?,
        pool_id,
        root_epoch_interval,
        active_lanes,
    )?))
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiTransactParams {
    pub program_id: String,
    pub payer: String,
    pub pool_id: u32,
    pub vk_id: u8,
    pub root_ring_kind: u8,
    pub root_ring_idx: u8,
    pub out_lane_id: u8,
    pub out_sub_seq: u64,
    pub out_root_seq: u64,
    pub out_memo_seq: u64,
    pub out_nf_seq: u64,
    pub next_sub_seq: Option<u64>,
    pub next_memo_seq: Option<u64>,
    pub next_nf_seq: Option<u64>,
    pub output_mask: u8,
    pub asset_mode: u8,
    pub unwrap_wsol: bool,
    pub public_mint: Option<String>,
    pub public_vault_ata: Option<String>,
    pub public_token_prog: Option<String>,
    pub proof_192: Vec<u8>,
    pub nf0: Vec<u8>,
    pub nf1: Vec<u8>,
    pub cm0: Vec<u8>,
    pub cm1: Vec<u8>,
    pub cm2: Vec<u8>,
    pub public_amount_out: u64,
    pub relayer_fee_amount: u64,
    pub recipient: String,
    pub relayer_fee_recipient: String,
    pub memos_bytes: Vec<u8>,
    pub transfer_hook_accounts: Vec<FfiAccountMeta>,
}

#[uniffi::export]
pub fn build_transact_ix(params: FfiTransactParams) -> Result<FfiInstruction, AudrenFfiError> {
    let pub_accs = match (
        params.public_mint,
        params.public_vault_ata,
        params.public_token_prog,
    ) {
        (Some(m), Some(v), Some(t)) => Some((
            parse_addr(&m, "public_mint")?,
            parse_addr(&v, "public_vault_ata")?,
            parse_addr(&t, "public_token_prog")?,
        )),
        (None, None, None) => None,
        _ => {
            return Err(AudrenFfiError::InvalidInput {
                reason: "public_mint, public_vault_ata, and public_token_prog must either all be Some or all be None".to_string(),
            });
        }
    };
    let hooks = to_audren_metas(&params.transfer_hook_accounts)?;
    Ok(from_audren_ix(try_build_transact(
        parse_addr(&params.program_id, "program_id")?,
        parse_addr(&params.payer, "payer")?,
        params.pool_id,
        params.vk_id,
        params.root_ring_kind,
        params.root_ring_idx,
        params.out_lane_id,
        params.out_sub_seq,
        params.out_root_seq,
        params.out_memo_seq,
        params.out_nf_seq,
        params.output_mask,
        params.asset_mode,
        params.unwrap_wsol,
        pub_accs,
        (params.next_sub_seq, params.next_memo_seq, params.next_nf_seq),
        &to_arr::<192>(&params.proof_192, "proof_192")?,
        &to_arr::<32>(&params.nf0, "nf0")?,
        &to_arr::<32>(&params.nf1, "nf1")?,
        &to_arr::<32>(&params.cm0, "cm0")?,
        &to_arr::<32>(&params.cm1, "cm1")?,
        &to_arr::<32>(&params.cm2, "cm2")?,
        params.public_amount_out,
        params.relayer_fee_amount,
        parse_addr(&params.recipient, "recipient")?,
        parse_addr(&params.relayer_fee_recipient, "relayer_fee_recipient")?,
        &params.memos_bytes,
        &hooks,
    )?))
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiExecViaEscrowParams {
    pub program_id: String,
    pub payer: String,
    pub pool_id: u32,
    pub vk_id: u8,
    pub root_ring_kind: u8,
    pub root_ring_idx: u8,
    pub out_lane_id: u8,
    pub out_sub_seq: u64,
    pub out_root_seq: u64,
    pub out_memo_seq: u64,
    pub out_nf_seq: u64,
    pub next_sub_seq: Option<u64>,
    pub next_memo_seq: Option<u64>,
    pub next_nf_seq: Option<u64>,
    pub escrow_shard: u8,
    pub change_mask: u8,
    pub fee_on_output: bool,
    pub in_leg: Vec<String>,
    pub out_leg: Vec<String>,
    pub relayer_fee_amount: u64,
    pub relayer_fee_recipient: Option<String>,
    pub proof_192: Vec<u8>,
    pub nf0: Vec<u8>,
    pub nf1: Vec<u8>,
    pub cm0: Vec<u8>,
    pub cm1: Vec<u8>,
    pub cm2: Vec<u8>,
    pub amount_in: u64,
    pub min_amount_out: u64,
    pub out_stealth_owner: Vec<u8>,
    pub out_blinding: Vec<u8>,
    pub dyn_memo_head: Vec<u8>,
    pub dyn_mask_72: Vec<u8>,
    pub router_prog: String,
    pub router_ix_data: Vec<u8>,
    pub router_accounts: Vec<FfiAccountMeta>,
    pub extra_writable_pubkeys: Vec<String>,
    pub change_memos: Vec<u8>,
}

#[uniffi::export]
pub fn build_exec_via_escrow_ix(
    params: FfiExecViaEscrowParams,
) -> Result<FfiInstruction, AudrenFfiError> {
    let parse_leg =
        |a: Vec<String>, label: &str| -> Result<(Address, Address, Address, Address), AudrenFfiError> {
            if a.len() != 4 {
                return Err(AudrenFfiError::InvalidInput {
                    reason: format!("{label} must have 4 pubkeys (mint, vault_ata, escrow_ata, token_prog)"),
                });
            }
            Ok((
                parse_addr(&a[0], label)?,
                parse_addr(&a[1], label)?,
                parse_addr(&a[2], label)?,
                parse_addr(&a[3], label)?,
            ))
        };
    let fee_r = params
        .relayer_fee_recipient
        .as_deref()
        .map(|s| parse_addr(s, "relayer_fee_recipient"))
        .transpose()?;
    let extra_writable: Vec<Address> = params
        .extra_writable_pubkeys
        .iter()
        .map(|s| parse_addr(s, "extra_writable_pubkeys"))
        .collect::<Result<_, _>>()?;
    Ok(from_audren_ix(try_build_exec_via_escrow(
        parse_addr(&params.program_id, "program_id")?,
        parse_addr(&params.payer, "payer")?,
        params.pool_id,
        params.vk_id,
        params.root_ring_kind,
        params.root_ring_idx,
        params.out_lane_id,
        params.out_sub_seq,
        params.out_root_seq,
        params.out_memo_seq,
        params.out_nf_seq,
        params.escrow_shard,
        params.change_mask,
        params.fee_on_output,
        parse_leg(params.in_leg, "in_leg")?,
        parse_leg(params.out_leg, "out_leg")?,
        params.relayer_fee_amount,
        fee_r,
        (params.next_sub_seq, params.next_memo_seq, params.next_nf_seq),
        &to_arr::<192>(&params.proof_192, "proof_192")?,
        &to_arr::<32>(&params.nf0, "nf0")?,
        &to_arr::<32>(&params.nf1, "nf1")?,
        &to_arr::<32>(&params.cm0, "cm0")?,
        &to_arr::<32>(&params.cm1, "cm1")?,
        &to_arr::<32>(&params.cm2, "cm2")?,
        params.amount_in,
        params.min_amount_out,
        &to_arr::<32>(&params.out_stealth_owner, "out_stealth_owner")?,
        &to_arr::<32>(&params.out_blinding, "out_blinding")?,
        &to_arr::<DYN_MEMO_HEAD_LEN>(&params.dyn_memo_head, "dyn_memo_head")?,
        &to_arr::<MEMO_CT_LEN>(&params.dyn_mask_72, "dyn_mask_72")?,
        parse_addr(&params.router_prog, "router_prog")?,
        &params.router_ix_data,
        to_audren_metas(&params.router_accounts)?,
        &extra_writable,
        &params.change_memos,
    )?))
}

#[uniffi::export]
pub fn build_set_paused_ix(
    program_id: String,
    authority: String,
    pool_id: u32,
    paused: bool,
) -> Result<FfiInstruction, AudrenFfiError> {
    Ok(from_audren_ix(build_set_paused(
        parse_addr(&program_id, "program_id")?,
        parse_addr(&authority, "authority")?,
        pool_id,
        paused,
    )))
}

#[uniffi::export]
pub fn build_update_pool_ix(
    program_id: String,
    signer: String,
    pool_id: u32,
    action: FfiUpdatePoolAction,
) -> Result<FfiInstruction, AudrenFfiError> {
    let rust_action = match action {
        FfiUpdatePoolAction::UpdateParams {
            note_rent_fee,
            nf_rent_fee,
        } => UpdatePoolAction::UpdateParams {
            note_rent_fee,
            nf_rent_fee,
        },
        FfiUpdatePoolAction::ProposeAuthority { pending_authority } => {
            UpdatePoolAction::ProposeAuthority {
                pending_authority: parse_addr(&pending_authority, "pending_authority")?,
            }
        }
        FfiUpdatePoolAction::AcceptAuthority => UpdatePoolAction::AcceptAuthority,
        FfiUpdatePoolAction::RenounceAuthority => UpdatePoolAction::RenounceAuthority,
    };
    Ok(from_audren_ix(build_update_pool(
        parse_addr(&program_id, "program_id")?,
        parse_addr(&signer, "signer")?,
        pool_id,
        rust_action,
    )))
}

#[uniffi::export]
pub fn select_root_snapshot_for_notes(
    root_history_data: Vec<u8>,
    expected_pool_id: u32,
    notes: Vec<FfiNoteCoord>,
) -> Result<FfiRootSnapshotChoice, AudrenFfiError> {
    let roots = decode_global_root_history(&root_history_data)?;
    validate_global_root_history(&roots, expected_pool_id)?;
    let mut coords = Vec::with_capacity(notes.len());
    for n in notes {
        validate_lane_id(n.lane_id)?;
        coords.push((n.lane_id, n.leaf_index));
    }
    let choice = roots
        .select_snapshot_for_notes(&coords)
        .ok_or(ClientError::WitnessNotFound(
            "notes not yet included in GlobalRootHistory",
        ))?;
    Ok(FfiRootSnapshotChoice {
        ring_kind: choice.ring_kind,
        ring_idx: choice.ring_idx,
        slot: choice.slot,
        super_root: choice.super_root.to_vec(),
        lane_roots: choice.lane_roots.iter().map(|r| r.to_vec()).collect(),
        lane_counts: choice.lane_counts.to_vec(),
    })
}

#[uniffi::export]
pub fn plan_auto_open_pages(
    program_id: String,
    pool_id: u32,
    lane_id: u8,
    next_leaf: u64,
    nf_count: u64,
    num_outputs: u8,
    num_nfs: u8,
    existing_pages: Vec<FfiOpenPageSpec>,
) -> Result<Vec<FfiOpenPageSpec>, AudrenFfiError> {
    validate_lane_id(lane_id)?;
    let pid = parse_addr(&program_id, "program_id")?;
    let mut existing = BTreeSet::new();
    for spec in existing_pages {
        if spec.page_kind > OPEN_PAGE_KIND_NULLIFIER {
            return Err(AudrenFfiError::InvalidInput {
                reason: format!("page_kind must be 0..=3, got {}", spec.page_kind),
            });
        }
        let addr = if spec.pda_b58.is_empty() {
            match spec.page_kind {
                OPEN_PAGE_KIND_SUBTREE => {
                    rust_derive_subtree_pda(&pid, pool_id, lane_id, spec.page_seq).0
                }
                OPEN_PAGE_KIND_SUBROOT => {
                    rust_derive_subroot_pda(&pid, pool_id, lane_id, spec.page_seq).0
                }
                OPEN_PAGE_KIND_MEMO => {
                    rust_derive_memo_pda(&pid, pool_id, lane_id, spec.page_seq).0
                }
                OPEN_PAGE_KIND_NULLIFIER => {
                    rust_derive_nf_page_pda(&pid, pool_id, lane_id, spec.page_seq).0
                }
                _ => {
                    return Err(AudrenFfiError::InvalidInput {
                        reason: format!("page_kind must be 0..=3, got {}", spec.page_kind),
                    });
                }
            }
        } else {
            parse_addr(&spec.pda_b58, "existing_pages.pda_b58")?
        };
        existing.insert(addr);
    }
    let specs = rust_plan_auto_open_pages(
        &pid,
        pool_id,
        lane_id,
        next_leaf,
        nf_count,
        num_outputs as usize,
        num_nfs as usize,
        &existing,
    )?;
    Ok(specs
        .into_iter()
        .map(|s| FfiOpenPageSpec {
            page_kind: s.page_kind,
            page_seq: s.page_seq,
            pda_b58: s.pda.to_string(),
        })
        .collect())
}

#[uniffi::export]
pub fn recommended_cu_limit_open_page(open_page_count: u32, bumps: Vec<u8>) -> u32 {
    rust_recommended_cu_limit_open_page_with_bumps(open_page_count as usize, &bumps)
}

#[uniffi::export]
pub fn recommended_cu_limit_deposit(
    has_transfer_hook: bool,
    open_page_count: u32,
    create_ata_count: u32,
    create_token_2022_ata_count: u32,
    bumps: Vec<u8>,
) -> u32 {
    rust_recommended_cu_limit_deposit_with_bumps(
        has_transfer_hook,
        open_page_count as usize,
        create_ata_count as usize,
        create_token_2022_ata_count as usize,
        &bumps,
    )
}

#[uniffi::export]
pub fn recommended_cu_limit_transact(
    is_public_withdraw: bool,
    has_transfer_hook: bool,
    output_mask: u8,
    open_page_count: u32,
    create_ata_count: u32,
    create_token_2022_ata_count: u32,
    bumps: Vec<u8>,
) -> u32 {
    rust_recommended_cu_limit_transact_with_bumps(
        is_public_withdraw,
        output_mask,
        has_transfer_hook,
        open_page_count as usize,
        create_ata_count as usize,
        create_token_2022_ata_count as usize,
        &bumps,
    )
}

#[uniffi::export]
pub fn recommended_cu_limit_exec_via_escrow(
    router_cu_limit: u32,
    has_token2022_leg: bool,
    open_page_count: u32,
    create_ata_count: u32,
    create_token_2022_ata_count: u32,
    bumps: Vec<u8>,
) -> u32 {
    rust_recommended_cu_limit_exec_via_escrow_with_bumps(
        router_cu_limit,
        has_token2022_leg,
        open_page_count as usize,
        create_ata_count as usize,
        create_token_2022_ata_count as usize,
        &bumps,
    )
}
