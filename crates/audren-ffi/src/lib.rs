//! Audren Mobile & Native FFI Facade (UniFFI -> Swift for iOS/macOS & Kotlin for Android/JVM).
//!
//! Exposes all Audren building blocks backed directly by `audren-core`, `audren-circuits`,
//! and `audren-client` with zero duplicated cryptography and zero transcript drift:
//! 1. Keys, `aud1...` stealth addresses, Mode 2 `FullViewingKey` (`spend_pk, nk, view_sk, view_pk`),
//!    and deterministic `DefiSessionKeypair`
//! 2. Canonical PDAs (`audren_v2_*`) and zero-copy account decoders
//! 3. Zero-indexer `CompactWalletStore` & authenticated `90 B` memo encryption/decryption
//! 4. Local BN254 Groth16 proving (`17,861` R1CS) and 9-instruction wire builders
//! 5. Mode 1 `SelectiveDisclosureProof` verification (1 Poseidon check, zero keys revealed)
//! 6. Relayer & Jupiter CPI exclusion constants

use std::sync::OnceLock;

use audren_circuits::{
    note::{compute_note_commitment, derive_asset_id, derive_stealth_owner},
    poseidon::{fr_from_be_bytes_strict, fr_to_be_bytes},
};
use audren_client::{
    instructions::{
        build_deposit_sol, build_deposit_spl, build_exec_via_escrow, build_init_lane,
        build_init_pool, build_joinsplit, build_open_page, build_publish_checkpoint,
        build_set_paused, compute_exec_ctx_hash, compute_joinsplit_ctx_hash,
        deterministic_note_rent_fee, AudrenAccountMeta, AudrenInstruction,
    },
    keys::{
        encrypt_note_memo as rust_encrypt_memo,
        prepare_dynamic_swap_memo as rust_prepare_dyn_memo,
        try_decrypt_and_verify_memo_entry as rust_decrypt_memo, AudrenAddress, AudrenKeys,
        FullViewingKey, SelectiveDisclosureProof,
    },
    pda::{
        derive_ata as rust_derive_ata, derive_checkpoint_pda as rust_derive_checkpoint_pda,
        derive_escrow_pda as rust_derive_escrow_pda, derive_lane_pda as rust_derive_lane_pda,
        derive_lane_rent_pda as rust_derive_lane_rent_pda,
        derive_memo_pda as rust_derive_memo_pda, derive_nf_page_pda as rust_derive_nf_page_pda,
        derive_nullifier_pda as rust_derive_nullifier_pda,
        derive_pool_pda as rust_derive_pool_pda,
        derive_sol_vault_pda as rust_derive_sol_vault_pda,
        derive_subroot_pda as rust_derive_subroot_pda,
        derive_subtree_pda as rust_derive_subtree_pda,
        derive_unwrap_pda as rust_derive_unwrap_pda,
        derive_vault_auth_pda as rust_derive_vault_auth_pda,
    },
    prover::AudrenProver,
    router::{DEFAULT_RELAY_URL, JUPITER_CPI_EXCLUDED_DEXES},
    scanner::{decode_lane_header, decode_pool_state, decode_root_checkpoint},
    store::CompactWalletStore,
    ClientError,
};
use audren_core::{AUDREN_PROGRAM_ID, PROTOCOL_VERSION};
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
    pub ckpt_interval: u64,
    pub max_ckpt_age: u64,
    pub authority_b58: String,
    pub sol_vault_bump: u8,
    pub vault_auth_bump: u8,
    pub mode: u8,
    pub note_rent_fee: u64,
    pub nf_rent_fee: u64,
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
pub struct FfiRootCheckpoint {
    pub version: u8,
    pub bump: u8,
    pub slot_idx: u16,
    pub pool_id: u32,
    pub epoch_id: u64,
    pub published_slot: u64,
    pub super_root: Vec<u8>,
    pub lane_roots: Vec<Vec<u8>>,
    pub lane_counts: Vec<u64>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiEncryptedMemo {
    pub tweak: Vec<u8>,
    pub blinding: Vec<u8>,
    pub stealth_owner: Vec<u8>,
    pub commitment: Vec<u8>,
    pub memo_90: Vec<u8>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiDynamicMemoPrep {
    pub tweak: Vec<u8>,
    pub blinding: Vec<u8>,
    pub dyn_head_34: Vec<u8>,
    pub dyn_mask_56: Vec<u8>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiDecryptedMemo {
    pub tweak: Vec<u8>,
    pub blinding: Vec<u8>,
    pub amount: u64,
    pub mint: Vec<u8>,
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

fn keys_to_ffi(k: &AudrenKeys) -> FfiAudrenKeys {
    FfiAudrenKeys {
        spend_sk: fr_to_be_bytes(&k.spend_sk).to_vec(),
        spend_pk: fr_to_be_bytes(&k.spend_pk).to_vec(),
        nk: fr_to_be_bytes(&k.nk).to_vec(),
        view_sk: k.view_sk.to_vec(),
        view_pk: k.view_pk.to_vec(),
        address: k.address().encode(),
    }
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
    Ok(keys_to_ffi(&AudrenKeys::from_seed(&s)))
}

#[uniffi::export]
pub fn derive_subaccount_keys(
    seed: Vec<u8>,
    account_index: u32,
) -> Result<FfiAudrenKeys, AudrenFfiError> {
    let s = to_arr::<32>(&seed, "seed")?;
    Ok(keys_to_ffi(&AudrenKeys::from_seed_subaccount(
        &s,
        account_index,
    )))
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
    Ok(FfiPdaResult { address: a.to_string(), bump: b })
}

#[uniffi::export]
pub fn derive_sol_vault_pda(
    program_id: String,
    pool_id: u32,
) -> Result<FfiPdaResult, AudrenFfiError> {
    let (a, b) = rust_derive_sol_vault_pda(&parse_addr(&program_id, "program_id")?, pool_id);
    Ok(FfiPdaResult { address: a.to_string(), bump: b })
}

#[uniffi::export]
pub fn derive_vault_auth_pda(
    program_id: String,
    pool_id: u32,
) -> Result<FfiPdaResult, AudrenFfiError> {
    let (a, b) = rust_derive_vault_auth_pda(&parse_addr(&program_id, "program_id")?, pool_id);
    Ok(FfiPdaResult { address: a.to_string(), bump: b })
}

#[uniffi::export]
pub fn derive_lane_pda(
    program_id: String,
    pool_id: u32,
    lane_id: u8,
) -> Result<FfiPdaResult, AudrenFfiError> {
    let (a, b) = rust_derive_lane_pda(&parse_addr(&program_id, "program_id")?, pool_id, lane_id);
    Ok(FfiPdaResult { address: a.to_string(), bump: b })
}

#[uniffi::export]
pub fn derive_lane_rent_pda(
    program_id: String,
    pool_id: u32,
    lane_id: u8,
) -> Result<FfiPdaResult, AudrenFfiError> {
    let (a, b) =
        rust_derive_lane_rent_pda(&parse_addr(&program_id, "program_id")?, pool_id, lane_id);
    Ok(FfiPdaResult { address: a.to_string(), bump: b })
}

#[uniffi::export]
pub fn derive_subtree_pda(
    program_id: String,
    pool_id: u32,
    lane_id: u8,
    page_seq: u64,
) -> Result<FfiPdaResult, AudrenFfiError> {
    let (a, b) = rust_derive_subtree_pda(
        &parse_addr(&program_id, "program_id")?,
        pool_id,
        lane_id,
        page_seq,
    );
    Ok(FfiPdaResult { address: a.to_string(), bump: b })
}

#[uniffi::export]
pub fn derive_subroot_pda(
    program_id: String,
    pool_id: u32,
    lane_id: u8,
    root_page_seq: u64,
) -> Result<FfiPdaResult, AudrenFfiError> {
    let (a, b) = rust_derive_subroot_pda(
        &parse_addr(&program_id, "program_id")?,
        pool_id,
        lane_id,
        root_page_seq,
    );
    Ok(FfiPdaResult { address: a.to_string(), bump: b })
}

#[uniffi::export]
pub fn derive_memo_pda(
    program_id: String,
    pool_id: u32,
    lane_id: u8,
    page_seq: u64,
) -> Result<FfiPdaResult, AudrenFfiError> {
    let (a, b) = rust_derive_memo_pda(
        &parse_addr(&program_id, "program_id")?,
        pool_id,
        lane_id,
        page_seq,
    );
    Ok(FfiPdaResult { address: a.to_string(), bump: b })
}

#[uniffi::export]
pub fn derive_nf_page_pda(
    program_id: String,
    pool_id: u32,
    lane_id: u8,
    page_seq: u64,
) -> Result<FfiPdaResult, AudrenFfiError> {
    let (a, b) = rust_derive_nf_page_pda(
        &parse_addr(&program_id, "program_id")?,
        pool_id,
        lane_id,
        page_seq,
    );
    Ok(FfiPdaResult { address: a.to_string(), bump: b })
}

#[uniffi::export]
pub fn derive_checkpoint_pda(
    program_id: String,
    pool_id: u32,
    slot_idx: u16,
) -> Result<FfiPdaResult, AudrenFfiError> {
    let (a, b) =
        rust_derive_checkpoint_pda(&parse_addr(&program_id, "program_id")?, pool_id, slot_idx);
    Ok(FfiPdaResult { address: a.to_string(), bump: b })
}

#[uniffi::export]
pub fn derive_nullifier_pda(
    program_id: String,
    pool_id: u32,
    nullifier: Vec<u8>,
) -> Result<FfiPdaResult, AudrenFfiError> {
    let nf = to_arr::<32>(&nullifier, "nullifier")?;
    let (a, b) = rust_derive_nullifier_pda(&parse_addr(&program_id, "program_id")?, pool_id, &nf);
    Ok(FfiPdaResult { address: a.to_string(), bump: b })
}

#[uniffi::export]
pub fn derive_escrow_pda(
    program_id: String,
    pool_id: u32,
    shard_id: u8,
) -> Result<FfiPdaResult, AudrenFfiError> {
    let (a, b) =
        rust_derive_escrow_pda(&parse_addr(&program_id, "program_id")?, pool_id, shard_id);
    Ok(FfiPdaResult { address: a.to_string(), bump: b })
}

#[uniffi::export]
pub fn derive_unwrap_pda(
    program_id: String,
    pool_id: u32,
    nf0: Vec<u8>,
) -> Result<FfiPdaResult, AudrenFfiError> {
    let n = to_arr::<32>(&nf0, "nf0")?;
    let (a, b) = rust_derive_unwrap_pda(&parse_addr(&program_id, "program_id")?, pool_id, &n);
    Ok(FfiPdaResult { address: a.to_string(), bump: b })
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
        ckpt_interval: p.ckpt_interval,
        max_ckpt_age: p.max_ckpt_age,
        authority_b58: Address::new_from_array(p.authority).to_string(),
        sol_vault_bump: p.sol_vault_bump,
        vault_auth_bump: p.vault_auth_bump,
        mode: p.mode,
        note_rent_fee: p.note_rent_fee,
        nf_rent_fee: p.nf_rent_fee,
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
pub fn decode_root_checkpoint_account(data: Vec<u8>) -> Result<FfiRootCheckpoint, AudrenFfiError> {
    let c = decode_root_checkpoint(&data)?;
    Ok(FfiRootCheckpoint {
        version: c.version,
        bump: c.bump,
        slot_idx: c.slot_idx,
        pool_id: c.pool_id,
        epoch_id: c.epoch_id,
        published_slot: c.published_slot,
        super_root: c.super_root.to_vec(),
        lane_roots: c.lane_roots.iter().map(|r| r.to_vec()).collect(),
        lane_counts: c.lane_counts.to_vec(),
    })
}

#[uniffi::export]
pub fn encrypt_note_memo(
    recipient_spend_pk: Vec<u8>,
    recipient_view_pk: Vec<u8>,
    eph_secret: Vec<u8>,
    amount: u64,
    mint: Vec<u8>,
) -> Result<FfiEncryptedMemo, AudrenFfiError> {
    let spk_b = to_arr::<32>(&recipient_spend_pk, "recipient_spend_pk")?;
    let spk = fr_from_be_bytes_strict(&spk_b).ok_or(ClientError::InvalidFieldElement)?;
    let vpk = to_arr::<32>(&recipient_view_pk, "recipient_view_pk")?;
    let eph = to_arr::<32>(&eph_secret, "eph_secret")?;
    let m = to_arr::<32>(&mint, "mint")?;
    let (tw, bl, memo) = rust_encrypt_memo(&vpk, eph, amount, &m);
    let stealth = derive_stealth_owner(spk, tw);
    let cm = compute_note_commitment(stealth, derive_asset_id(&m), amount, bl);
    Ok(FfiEncryptedMemo {
        tweak: fr_to_be_bytes(&tw).to_vec(),
        blinding: fr_to_be_bytes(&bl).to_vec(),
        stealth_owner: fr_to_be_bytes(&stealth).to_vec(),
        commitment: fr_to_be_bytes(&cm).to_vec(),
        memo_90: memo.to_vec(),
    })
}

#[uniffi::export]
pub fn prepare_dynamic_swap_memo(
    recipient_view_pk: Vec<u8>,
    eph_secret: Vec<u8>,
) -> Result<FfiDynamicMemoPrep, AudrenFfiError> {
    let vpk = to_arr::<32>(&recipient_view_pk, "recipient_view_pk")?;
    let eph = to_arr::<32>(&eph_secret, "eph_secret")?;
    let (tw, bl, head, mask) = rust_prepare_dyn_memo(&vpk, eph);
    Ok(FfiDynamicMemoPrep {
        tweak: fr_to_be_bytes(&tw).to_vec(),
        blinding: fr_to_be_bytes(&bl).to_vec(),
        dyn_head_34: head.to_vec(),
        dyn_mask_56: mask.to_vec(),
    })
}

#[uniffi::export]
pub fn decrypt_and_verify_memo_entry(
    fvk: FfiFullViewingKey,
    memo_90: Vec<u8>,
    onchain_commitment: Vec<u8>,
) -> Result<Option<FfiDecryptedMemo>, AudrenFfiError> {
    let m = to_arr::<90>(&memo_90, "memo_90")?;
    let cm = to_arr::<32>(&onchain_commitment, "onchain_commitment")?;
    let f = FullViewingKey {
        spend_pk: to_arr::<32>(&fvk.spend_pk, "fvk.spend_pk")?,
        nk: to_arr::<32>(&fvk.nk, "fvk.nk")?,
        view_sk: to_arr::<32>(&fvk.view_sk, "fvk.view_sk")?,
        view_pk: to_arr::<32>(&fvk.view_pk, "fvk.view_pk")?,
    };
    let vt = [m[0], m[1]];
    let epk: [u8; 32] = m[2..34].try_into().unwrap();
    let ct: [u8; 56] = m[34..90].try_into().unwrap();
    Ok(rust_decrypt_memo(&f, vt, &epk, &ct, &cm).map(|d| FfiDecryptedMemo {
        tweak: fr_to_be_bytes(&d.tweak).to_vec(),
        blinding: fr_to_be_bytes(&d.blinding).to_vec(),
        amount: d.amount,
        mint: d.mint.to_vec(),
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
    Ok(String::from_utf8(store.to_json_bytes()?).unwrap())
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
    let b = canonical_prover().prove_with_seed(circuit, seed);
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
pub struct FfiJoinSplitCtxHashParams {
    pub program_id: String,
    pub pool_id: u32,
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
pub fn compute_joinsplit_ctx_hash_ffi(
    params: FfiJoinSplitCtxHashParams,
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
    let h = compute_joinsplit_ctx_hash(
        &pid,
        params.pool_id,
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
    );
    Ok(fr_to_be_bytes(&h).to_vec())
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiExecCtxHashParams {
    pub program_id: String,
    pub pool_id: u32,
    pub out_lane_id: u8,
    pub escrow_shard: u8,
    pub change_mask: u8,
    pub in_kind: u8,
    pub out_kind: u8,
    pub fee_on_output: bool,
    pub asset_in: Vec<u8>,
    pub amount_in: u64,
    pub relayer_fee_amount: u64,
    pub relayer_fee_recipient: Option<String>,
    pub asset_out: Vec<u8>,
    pub min_amount_out: u64,
    pub router_prog: String,
    pub router_accounts: Vec<FfiAccountMeta>,
    pub out_stealth_owner: Vec<u8>,
    pub out_blinding: Vec<u8>,
    pub dyn_memo_head: Vec<u8>,
    pub dyn_mask_56: Vec<u8>,
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
    let h = compute_exec_ctx_hash(
        &pid,
        params.pool_id,
        params.out_lane_id,
        params.escrow_shard,
        params.change_mask,
        params.in_kind,
        params.out_kind,
        params.fee_on_output,
        &to_arr::<32>(&params.asset_in, "asset_in")?,
        params.amount_in,
        params.relayer_fee_amount,
        fee_r.as_ref(),
        &to_arr::<32>(&params.asset_out, "asset_out")?,
        params.min_amount_out,
        &rprog,
        &raccs,
        &to_arr::<32>(&params.out_stealth_owner, "out_stealth_owner")?,
        &to_arr::<32>(&params.out_blinding, "out_blinding")?,
        &to_arr::<34>(&params.dyn_memo_head, "dyn_memo_head")?,
        &to_arr::<56>(&params.dyn_mask_56, "dyn_mask_56")?,
        &params.router_ix_data,
        &params.change_memos,
    );
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
pub fn build_init_pool_ix(
    program_id: String,
    payer: String,
    pool_id: u32,
    ckpt_interval: u64,
    max_ckpt_age: u64,
    note_rent_fee: u64,
    nf_rent_fee: u64,
) -> Result<FfiInstruction, AudrenFfiError> {
    Ok(from_audren_ix(build_init_pool(
        parse_addr(&program_id, "program_id")?,
        parse_addr(&payer, "payer")?,
        pool_id,
        ckpt_interval,
        max_ckpt_age,
        note_rent_fee,
        nf_rent_fee,
    )))
}

#[uniffi::export]
pub fn build_init_lane_ix(
    program_id: String,
    authority: String,
    pool_id: u32,
    lane_id: u8,
) -> Result<FfiInstruction, AudrenFfiError> {
    Ok(from_audren_ix(build_init_lane(
        parse_addr(&program_id, "program_id")?,
        parse_addr(&authority, "authority")?,
        pool_id,
        lane_id,
    )))
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
    Ok(from_audren_ix(build_open_page(
        parse_addr(&program_id, "program_id")?,
        parse_addr(&payer, "payer")?,
        page_kind,
        pool_id,
        lane_id,
        page_seq,
    )))
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiDepositSolParams {
    pub program_id: String,
    pub depositor: String,
    pub pool_id: u32,
    pub lane_id: u8,
    pub sub_page_seq: u64,
    pub root_page_seq: u64,
    pub memo_page_seq: u64,
    pub fee_from_amount: bool,
    pub amount: u64,
    pub stealth_owner: Vec<u8>,
    pub blinding: Vec<u8>,
    pub memo_90: Vec<u8>,
}

#[uniffi::export]
pub fn build_deposit_sol_ix(params: FfiDepositSolParams) -> Result<FfiInstruction, AudrenFfiError> {
    let st = fr_from_be_bytes_strict(&to_arr::<32>(&params.stealth_owner, "stealth_owner")?)
        .ok_or(ClientError::InvalidFieldElement)?;
    let bl = fr_from_be_bytes_strict(&to_arr::<32>(&params.blinding, "blinding")?)
        .ok_or(ClientError::InvalidFieldElement)?;
    let m = to_arr::<90>(&params.memo_90, "memo_90")?;
    Ok(from_audren_ix(build_deposit_sol(
        parse_addr(&params.program_id, "program_id")?,
        parse_addr(&params.depositor, "depositor")?,
        params.pool_id,
        params.lane_id,
        params.sub_page_seq,
        params.root_page_seq,
        params.memo_page_seq,
        None,
        None,
        params.fee_from_amount,
        params.amount,
        st,
        bl,
        &m,
    )))
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiDepositSplParams {
    pub program_id: String,
    pub depositor: String,
    pub pool_id: u32,
    pub mint: String,
    pub depositor_ata: String,
    pub vault_ata: String,
    pub token_prog: String,
    pub lane_id: u8,
    pub sub_page_seq: u64,
    pub root_page_seq: u64,
    pub memo_page_seq: u64,
    pub amount: u64,
    pub stealth_owner: Vec<u8>,
    pub blinding: Vec<u8>,
    pub memo_90: Vec<u8>,
    pub transfer_hook_accounts: Vec<FfiAccountMeta>,
}

#[uniffi::export]
pub fn build_deposit_spl_ix(params: FfiDepositSplParams) -> Result<FfiInstruction, AudrenFfiError> {
    let st = fr_from_be_bytes_strict(&to_arr::<32>(&params.stealth_owner, "stealth_owner")?)
        .ok_or(ClientError::InvalidFieldElement)?;
    let bl = fr_from_be_bytes_strict(&to_arr::<32>(&params.blinding, "blinding")?)
        .ok_or(ClientError::InvalidFieldElement)?;
    let m = to_arr::<90>(&params.memo_90, "memo_90")?;
    let hooks = to_audren_metas(&params.transfer_hook_accounts)?;
    Ok(from_audren_ix(build_deposit_spl(
        parse_addr(&params.program_id, "program_id")?,
        parse_addr(&params.depositor, "depositor")?,
        params.pool_id,
        parse_addr(&params.mint, "mint")?,
        parse_addr(&params.depositor_ata, "depositor_ata")?,
        parse_addr(&params.vault_ata, "vault_ata")?,
        parse_addr(&params.token_prog, "token_prog")?,
        params.lane_id,
        params.sub_page_seq,
        params.root_page_seq,
        params.memo_page_seq,
        None,
        None,
        params.amount,
        st,
        bl,
        &m,
        &hooks,
    )))
}

#[uniffi::export]
pub fn build_publish_checkpoint_ix(
    program_id: String,
    payer: String,
    pool_id: u32,
    slot_idx: u16,
    active_lanes: u8,
) -> Result<FfiInstruction, AudrenFfiError> {
    Ok(from_audren_ix(build_publish_checkpoint(
        parse_addr(&program_id, "program_id")?,
        parse_addr(&payer, "payer")?,
        pool_id,
        slot_idx,
        active_lanes,
    )))
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiJoinSplitParams {
    pub program_id: String,
    pub payer: String,
    pub pool_id: u32,
    pub vk_id: u8,
    pub ckpt_slot_idx: u16,
    pub out_lane_id: u8,
    pub out_sub_seq: u64,
    pub out_root_seq: u64,
    pub out_memo_seq: u64,
    pub out_nf_seq: u64,
    pub output_mask: u8,
    pub asset_mode: u8,
    pub unwrap_wsol: bool,
    pub spl_mint: Option<String>,
    pub spl_vault_ata: Option<String>,
    pub spl_token_prog: Option<String>,
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
}

#[uniffi::export]
pub fn build_joinsplit_ix(params: FfiJoinSplitParams) -> Result<FfiInstruction, AudrenFfiError> {
    let spl = match (params.spl_mint, params.spl_vault_ata, params.spl_token_prog) {
        (Some(m), Some(v), Some(t)) => Some((
            parse_addr(&m, "spl_mint")?,
            parse_addr(&v, "spl_vault_ata")?,
            parse_addr(&t, "spl_token_prog")?,
        )),
        (None, None, None) => None,
        _ => {
            return Err(AudrenFfiError::InvalidInput {
                reason: "spl_mint, spl_vault_ata, and spl_token_prog must either all be Some or all be None".to_string(),
            });
        }
    };
    Ok(from_audren_ix(build_joinsplit(
        parse_addr(&params.program_id, "program_id")?,
        parse_addr(&params.payer, "payer")?,
        params.pool_id,
        params.vk_id,
        params.ckpt_slot_idx,
        params.out_lane_id,
        params.out_sub_seq,
        params.out_root_seq,
        params.out_memo_seq,
        params.out_nf_seq,
        params.output_mask,
        params.asset_mode,
        params.unwrap_wsol,
        spl,
        (None, None, None),
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
        &[],
    )))
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiExecViaEscrowParams {
    pub program_id: String,
    pub payer: String,
    pub pool_id: u32,
    pub vk_id: u8,
    pub ckpt_slot_idx: u16,
    pub out_lane_id: u8,
    pub out_sub_seq: u64,
    pub out_root_seq: u64,
    pub out_memo_seq: u64,
    pub out_nf_seq: u64,
    pub escrow_shard: u8,
    pub change_mask: u8,
    pub in_kind: u8,
    pub out_kind: u8,
    pub fee_on_output: bool,
    pub in_spl: Option<Vec<String>>,
    pub out_spl: Option<Vec<String>>,
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
    pub dyn_mask_56: Vec<u8>,
    pub router_prog: String,
    pub router_ix_data: Vec<u8>,
    pub router_accounts: Vec<FfiAccountMeta>,
    pub change_memos: Vec<u8>,
}

#[uniffi::export]
pub fn build_exec_via_escrow_ix(
    params: FfiExecViaEscrowParams,
) -> Result<FfiInstruction, AudrenFfiError> {
    let parse_leg = |v: Option<Vec<String>>, label: &str| -> Result<Option<(Address, Address, Address, Address)>, AudrenFfiError> {
        match v {
            None => Ok(None),
            Some(a) if a.len() == 4 => Ok(Some((
                parse_addr(&a[0], label)?,
                parse_addr(&a[1], label)?,
                parse_addr(&a[2], label)?,
                parse_addr(&a[3], label)?,
            ))),
            Some(_) => Err(AudrenFfiError::InvalidInput {
                reason: format!("{label} must have 4 pubkeys"),
            }),
        }
    };
    let fee_r = params
        .relayer_fee_recipient
        .as_deref()
        .map(|s| parse_addr(s, "relayer_fee_recipient"))
        .transpose()?;
    Ok(from_audren_ix(build_exec_via_escrow(
        parse_addr(&params.program_id, "program_id")?,
        parse_addr(&params.payer, "payer")?,
        params.pool_id,
        params.vk_id,
        params.ckpt_slot_idx,
        params.out_lane_id,
        params.out_sub_seq,
        params.out_root_seq,
        params.out_memo_seq,
        params.out_nf_seq,
        params.escrow_shard,
        params.change_mask,
        params.in_kind,
        params.out_kind,
        params.fee_on_output,
        parse_leg(params.in_spl, "in_spl")?,
        parse_leg(params.out_spl, "out_spl")?,
        params.relayer_fee_amount,
        fee_r,
        (None, None, None),
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
        &to_arr::<34>(&params.dyn_memo_head, "dyn_memo_head")?,
        &to_arr::<56>(&params.dyn_mask_56, "dyn_mask_56")?,
        parse_addr(&params.router_prog, "router_prog")?,
        &params.router_ix_data,
        to_audren_metas(&params.router_accounts)?,
        &params.change_memos,
    )))
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
