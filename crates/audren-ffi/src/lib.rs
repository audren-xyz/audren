//! Audren Mobile & Native FFI Facade (UniFFI -> Swift for iOS/macOS & Kotlin for Android/JVM).
//!
//! Exposes the exact same 6 Audren SDK building blocks backed directly by `audren-core` and
//! constant-time `audren-client` cryptography — zero duplicated crypto, zero transcript drift:
//! 1. Keys, `aud1...` stealth addresses & deterministic DeFi sessions (`derive_keys_from_seed`, `derive_subaccount_keys`, `derive_defi_session_keypair`, `export_full_viewing_key`)
//! 2. Canonical PDAs & account decoders (`derive_*_pda`, `decode_pool_state`, `decode_epoch_page_header`)
//! 3. Zero-indexer `dataSlice` scanning & note decryption (`page_scan_data_slice`, `scan_page_dataslice`, `scan_epoch_page`)
//! 4. Local proof generation & instruction builders (`Deposit`, `Transfer`, `Merge`, `ExecViaEscrow`, `Withdraw`, `ProofBuffer`)
//! 5. Selective disclosure receipts & institutional audit (`create_selective_disclosure_proof`, `verify_*`, `auditor_*`)
//! 6. Escrow & relayer helpers (`jupiter_cpi_excluded_dexes`, `default_relay_url`, `prepare_escrow_accounts`)

use audren_client::{
    instructions::{
        build_buffered_execution, build_close_proof_buffer, build_deposit_with_options,
        build_exec_via_escrow, build_merge, build_open_lane_page, build_open_page, build_transfer,
        build_withdraw_with_params, net_deposit_amount as rust_net_deposit_amount,
        AudrenAccountMeta, AudrenInstruction, ExecViaEscrowParams, WithdrawParams,
    },
    keys::{
        AudrenAddress, AudrenKeys, AuditorKeypair, FullViewingKey, SelectiveDisclosureProof,
    },
    pda::{
        derive_ata, derive_epoch_page_pda as rust_derive_epoch_page_pda,
        derive_escrow_pda as rust_derive_escrow_pda, derive_lane_pda as rust_derive_lane_pda,
        derive_lane_rent_vault_pda as rust_derive_lane_rent_vault_pda,
        derive_nullifier_pda as rust_derive_nullifier_pda,
        derive_page_rent_vault_pda as rust_derive_page_rent_vault_pda,
        derive_pool_pda as rust_derive_pool_pda,
        derive_proof_buffer_pda as rust_derive_proof_buffer_pda,
        derive_sol_vault_pda as rust_derive_sol_vault_pda,
        derive_unwrap_pda as rust_derive_unwrap_pda,
        derive_vault_auth_pda as rust_derive_vault_auth_pda,
    },
    prover::{asset_generator as rust_asset_generator, extract_ring_from_page},
    router::{locate_escrow_indices, DEFAULT_RELAY_URL, JUPITER_CPI_EXCLUDED_DEXES},
    scanner::{decrypt_owned_note as rust_decrypt_owned_note, scan_page_dataslice as rust_scan_slice, OwnedNote},
    ClientError,
};
use audren_core::{
    lane_of_page_id as core_lane_of_page_id,
    layout::{AppendLaneState, PageHeader, PoolState, PAGE_SCAN_LEN, PAGE_SCAN_OFFSET},
    page_id_for_lane as core_page_id_for_lane,
    seq_of_page_id as core_seq_of_page_id,
    AUDREN_PROGRAM_ID,
};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use solana_address::Address;

uniffi::setup_scaffolding!();

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
            ClientError::InvalidEncoding(msg) | ClientError::InvalidProofInput(msg) => {
                Self::InvalidInput {
                    reason: msg.to_string(),
                }
            }
            ClientError::InvalidPoint => Self::Crypto {
                reason: "invalid ristretto255 point".to_string(),
            },
            ClientError::Crypto(msg) => Self::Crypto {
                reason: msg.to_string(),
            },
        }
    }
}

fn to_arr32(bytes: &[u8], label: &str) -> Result<[u8; 32], AudrenFfiError> {
    if bytes.len() != 32 {
        return Err(AudrenFfiError::InvalidInput {
            reason: format!("{label} must be 32 bytes, got {}", bytes.len()),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn parse_address(s: &str, label: &str) -> Result<Address, AudrenFfiError> {
    let raw = bs58::decode(s)
        .into_vec()
        .map_err(|_| AudrenFfiError::InvalidInput {
            reason: format!("invalid base58 {label}"),
        })?;
    let arr = to_arr32(&raw, label)?;
    Ok(Address::new_from_array(arr))
}

fn parse_scalar(bytes: &[u8], label: &str) -> Result<Scalar, AudrenFfiError> {
    let arr = to_arr32(bytes, label)?;
    Option::from(Scalar::from_canonical_bytes(arr)).ok_or_else(|| AudrenFfiError::InvalidInput {
        reason: format!("non-canonical scalar for {label}"),
    })
}

fn default_program_id_or(program_id: &str) -> Result<Address, AudrenFfiError> {
    if program_id.is_empty() {
        Ok(Address::new_from_array(AUDREN_PROGRAM_ID))
    } else {
        parse_address(program_id, "program_id")
    }
}

fn keys_from_raw(spend_sk_32: &[u8], view_sk_32: &[u8]) -> Result<AudrenKeys, AudrenFfiError> {
    let spend_sk = parse_scalar(spend_sk_32, "spend_sk")?;
    let view_sk = parse_scalar(view_sk_32, "view_sk")?;
    let g = audren_client::prover::g_point();
    let spend_pk = audren_client::prover::compress(&(spend_sk * g));
    let view_pk = audren_client::prover::compress(&(view_sk * g));
    Ok(AudrenKeys {
        spend_sk,
        spend_pk,
        view_sk,
        view_pk,
    })
}

// ============================================================================
// 1. Keys, Sub-Accounts & Stealth Addresses
// ============================================================================

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiAudrenKeys {
    pub spend_sk: Vec<u8>,
    pub spend_pk: Vec<u8>,
    pub view_sk: Vec<u8>,
    pub view_pk: Vec<u8>,
    pub address: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiAudrenAddress {
    pub spend_pk: Vec<u8>,
    pub view_pk: Vec<u8>,
    pub encoded: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiFullViewingKey {
    pub version: u8,
    pub spend_pk_b58: String,
    pub view_sk_b58: String,
    pub view_pk_b58: String,
}

#[uniffi::export]
pub fn program_id() -> String {
    Address::new_from_array(AUDREN_PROGRAM_ID).to_string()
}

#[uniffi::export]
pub fn derive_keys_from_seed(seed_32: Vec<u8>) -> Result<FfiAudrenKeys, AudrenFfiError> {
    let seed = to_arr32(&seed_32, "seed")?;
    let k = AudrenKeys::from_seed(&seed);
    Ok(FfiAudrenKeys {
        spend_sk: k.spend_sk.to_bytes().to_vec(),
        spend_pk: k.spend_pk.to_vec(),
        view_sk: k.view_sk.to_bytes().to_vec(),
        view_pk: k.view_pk.to_vec(),
        address: k.address().to_base58(),
    })
}

#[uniffi::export]
pub fn derive_subaccount_keys(
    master_seed_32: Vec<u8>,
    account_index: u32,
) -> Result<FfiAudrenKeys, AudrenFfiError> {
    let seed = to_arr32(&master_seed_32, "master_seed")?;
    let k = AudrenKeys::from_seed_subaccount(&seed, account_index);
    Ok(FfiAudrenKeys {
        spend_sk: k.spend_sk.to_bytes().to_vec(),
        spend_pk: k.spend_pk.to_vec(),
        view_sk: k.view_sk.to_bytes().to_vec(),
        view_pk: k.view_pk.to_vec(),
        address: k.address().to_base58(),
    })
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiDefiSessionKeypair {
    pub session_index: u32,
    pub secret_seed: Vec<u8>,
    pub pubkey: Vec<u8>,
    pub keypair_bytes: Vec<u8>,
    pub address: String,
}

#[uniffi::export]
pub fn derive_defi_session_keypair(
    master_seed_32: Vec<u8>,
    session_index: u32,
) -> Result<FfiDefiSessionKeypair, AudrenFfiError> {
    let seed = to_arr32(&master_seed_32, "master_seed")?;
    let kp = AudrenKeys::derive_defi_session_keypair(&seed, session_index);
    Ok(FfiDefiSessionKeypair {
        session_index: kp.session_index,
        secret_seed: kp.secret_seed.to_vec(),
        pubkey: kp.pubkey.to_vec(),
        keypair_bytes: kp.keypair_bytes.to_vec(),
        address: kp.address,
    })
}

#[uniffi::export]
pub fn parse_audren_address(encoded: String) -> Result<FfiAudrenAddress, AudrenFfiError> {
    let addr = AudrenAddress::from_base58(&encoded)?;
    Ok(FfiAudrenAddress {
        spend_pk: addr.spend_pk.to_vec(),
        view_pk: addr.view_pk.to_vec(),
        encoded: addr.to_base58(),
    })
}

#[uniffi::export]
pub fn format_audren_address(
    spend_pk_32: Vec<u8>,
    view_pk_32: Vec<u8>,
) -> Result<String, AudrenFfiError> {
    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(&to_arr32(&spend_pk_32, "spend_pk")?);
    raw[32..].copy_from_slice(&to_arr32(&view_pk_32, "view_pk")?);
    let addr = AudrenAddress::from_bytes(&raw)?;
    Ok(addr.to_base58())
}

#[uniffi::export]
pub fn export_full_viewing_key(
    seed_32: Vec<u8>,
    account_index: u32,
) -> Result<FfiFullViewingKey, AudrenFfiError> {
    let seed = to_arr32(&seed_32, "seed")?;
    let exp = AudrenKeys::from_seed_subaccount(&seed, account_index)
        .full_viewing_key()
        .to_export();
    Ok(FfiFullViewingKey {
        version: exp.version,
        spend_pk_b58: exp.spend_pk_b58,
        view_sk_b58: exp.view_sk_b58,
        view_pk_b58: exp.view_pk_b58,
    })
}

#[uniffi::export]
pub fn asset_generator(mint_32: Vec<u8>) -> Result<Vec<u8>, AudrenFfiError> {
    let mint = to_arr32(&mint_32, "mint")?;
    Ok(rust_asset_generator(&mint).to_vec())
}

// ============================================================================
// 2. Canonical PDAs & Account Decoders
// ============================================================================

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiPda {
    pub address: String,
    pub bump: u8,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiPoolState {
    pub version: u8,
    pub bump: u8,
    pub mode: u8,
    pub paused: bool,
    pub pool_id: u32,
    pub current_page_id: u64,
    pub total_notes: u64,
    pub total_spends: u64,
    pub page_rent_fee_lamports: u64,
    pub authority: String,
    pub auditor_pk: Vec<u8>,
    pub auditor_locked: bool,
    pub vault_auth_bump: u8,
    pub sol_vault_bump: u8,
    pub page_rent_bump: u8,
    pub active_lanes: u8,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiEpochPageHeader {
    pub version: u8,
    pub bump: u8,
    pub closed: bool,
    pub count: u8,
    pub pool_id: u32,
    pub page_id: u64,
    pub created_slot: u64,
    pub closed_slot: u64,
}

fn pda_record((addr, bump): (Address, u8)) -> FfiPda {
    FfiPda {
        address: addr.to_string(),
        bump,
    }
}

#[uniffi::export]
pub fn derive_pool_pda(pool_id: u32, program_id: String) -> Result<FfiPda, AudrenFfiError> {
    let pid = default_program_id_or(&program_id)?;
    Ok(pda_record(rust_derive_pool_pda(&pid, pool_id)))
}

#[uniffi::export]
pub fn derive_epoch_page_pda(
    pool_id: u32,
    page_id: u64,
    program_id: String,
) -> Result<FfiPda, AudrenFfiError> {
    let pid = default_program_id_or(&program_id)?;
    Ok(pda_record(rust_derive_epoch_page_pda(&pid, pool_id, page_id)))
}

#[uniffi::export]
pub fn derive_sol_vault_pda(pool_id: u32, program_id: String) -> Result<FfiPda, AudrenFfiError> {
    let pid = default_program_id_or(&program_id)?;
    Ok(pda_record(rust_derive_sol_vault_pda(&pid, pool_id)))
}

#[uniffi::export]
pub fn derive_vault_auth_pda(pool_id: u32, program_id: String) -> Result<FfiPda, AudrenFfiError> {
    let pid = default_program_id_or(&program_id)?;
    Ok(pda_record(rust_derive_vault_auth_pda(&pid, pool_id)))
}

#[uniffi::export]
pub fn derive_page_rent_vault_pda(
    pool_id: u32,
    program_id: String,
) -> Result<FfiPda, AudrenFfiError> {
    let pid = default_program_id_or(&program_id)?;
    Ok(pda_record(rust_derive_page_rent_vault_pda(&pid, pool_id)))
}

#[uniffi::export]
pub fn derive_escrow_pda(
    pool_id: u32,
    shard_id: u8,
    program_id: String,
) -> Result<FfiPda, AudrenFfiError> {
    let pid = default_program_id_or(&program_id)?;
    Ok(pda_record(rust_derive_escrow_pda(&pid, pool_id, shard_id)))
}

#[uniffi::export]
pub fn derive_unwrap_pda(
    pool_id: u32,
    nullifier_32: Vec<u8>,
    program_id: String,
) -> Result<FfiPda, AudrenFfiError> {
    let pid = default_program_id_or(&program_id)?;
    let nf = to_arr32(&nullifier_32, "nullifier")?;
    Ok(pda_record(rust_derive_unwrap_pda(&pid, pool_id, &nf)))
}

#[uniffi::export]
pub fn derive_lane_pda(
    pool_id: u32,
    lane_id: u8,
    program_id: String,
) -> Result<FfiPda, AudrenFfiError> {
    let pid = default_program_id_or(&program_id)?;
    Ok(pda_record(rust_derive_lane_pda(&pid, pool_id, lane_id)))
}

#[uniffi::export]
pub fn derive_lane_rent_vault_pda(
    pool_id: u32,
    lane_id: u8,
    program_id: String,
) -> Result<FfiPda, AudrenFfiError> {
    let pid = default_program_id_or(&program_id)?;
    Ok(pda_record(rust_derive_lane_rent_vault_pda(
        &pid, pool_id, lane_id,
    )))
}

#[uniffi::export]
pub fn derive_nullifier_pda(
    pool_id: u32,
    nullifier_32: Vec<u8>,
    program_id: String,
) -> Result<FfiPda, AudrenFfiError> {
    let pid = default_program_id_or(&program_id)?;
    let nf = to_arr32(&nullifier_32, "nullifier")?;
    Ok(pda_record(rust_derive_nullifier_pda(&pid, pool_id, &nf)))
}

#[uniffi::export]
pub fn derive_proof_buffer_pda(
    authority_b58: String,
    nonce: u64,
    program_id: String,
) -> Result<FfiPda, AudrenFfiError> {
    let pid = default_program_id_or(&program_id)?;
    let auth = parse_address(&authority_b58, "authority")?;
    Ok(pda_record(rust_derive_proof_buffer_pda(&pid, &auth, nonce)))
}

#[uniffi::export]
pub fn decode_pool_state(data: Vec<u8>) -> Result<FfiPoolState, AudrenFfiError> {
    let st = PoolState::decode(&data).map_err(|_| AudrenFfiError::InvalidInput {
        reason: "invalid PoolState bytes".to_string(),
    })?;
    Ok(FfiPoolState {
        version: st.version,
        bump: st.bump,
        mode: st.mode as u8,
        paused: st.paused,
        pool_id: st.pool_id,
        current_page_id: st.current_page_id,
        total_notes: st.total_notes,
        total_spends: st.total_spends,
        page_rent_fee_lamports: st.page_rent_fee_lamports,
        authority: Address::new_from_array(st.authority).to_string(),
        auditor_pk: st.auditor_pk.to_vec(),
        auditor_locked: st.auditor_locked,
        vault_auth_bump: st.vault_auth_bump,
        sol_vault_bump: st.sol_vault_bump,
        page_rent_bump: st.page_rent_bump,
        active_lanes: st.active_lanes.max(1),
    })
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiAppendLaneState {
    pub version: u8,
    pub lane_id: u8,
    pub bump: u8,
    pub rent_vault_bump: u8,
    pub pool_id: u32,
    pub current_page_id: u64,
    pub created_slot: u64,
}

#[uniffi::export]
pub fn decode_epoch_page_header(data: Vec<u8>) -> Result<FfiEpochPageHeader, AudrenFfiError> {
    let hdr = PageHeader::decode(&data).map_err(|_| AudrenFfiError::InvalidInput {
        reason: "invalid EpochPage header bytes".to_string(),
    })?;
    Ok(FfiEpochPageHeader {
        version: hdr.version,
        bump: hdr.bump,
        closed: hdr.closed,
        count: hdr.count,
        pool_id: hdr.pool_id,
        page_id: hdr.page_id,
        created_slot: hdr.created_slot,
        closed_slot: hdr.closed_slot,
    })
}

#[uniffi::export]
pub fn decode_append_lane_state(data: Vec<u8>) -> Result<FfiAppendLaneState, AudrenFfiError> {
    let lane = AppendLaneState::decode(&data).map_err(|_| AudrenFfiError::InvalidInput {
        reason: "invalid AppendLaneState bytes".to_string(),
    })?;
    Ok(FfiAppendLaneState {
        version: lane.version,
        lane_id: lane.lane_id,
        bump: lane.bump,
        rent_vault_bump: lane.rent_vault_bump,
        pool_id: lane.pool_id,
        current_page_id: lane.current_page_id,
        created_slot: lane.created_slot,
    })
}

#[uniffi::export]
pub fn derive_associated_token_address(
    owner_b58: String,
    mint_b58: String,
    token_program_b58: String,
) -> Result<String, AudrenFfiError> {
    let owner = parse_address(&owner_b58, "owner")?;
    let mint = parse_address(&mint_b58, "mint")?;
    let tp = parse_address(&token_program_b58, "token_program")?;
    Ok(derive_ata(&owner, &tp, &mint).to_string())
}

#[uniffi::export]
pub fn page_id_for_lane(lane_id: u8, seq: u64) -> Result<u64, AudrenFfiError> {
    core_page_id_for_lane(lane_id, seq).ok_or_else(|| AudrenFfiError::InvalidInput {
        reason: format!("invalid lane_id ({lane_id}) or seq ({seq})"),
    })
}

#[uniffi::export]
pub fn lane_of_page_id(page_id: u64) -> u8 {
    core_lane_of_page_id(page_id)
}

#[uniffi::export]
pub fn seq_of_page_id(page_id: u64) -> u64 {
    core_seq_of_page_id(page_id)
}

#[uniffi::export]
pub fn net_deposit_amount(gross_amount: u64, fee_bps: u16, max_fee: u64) -> u64 {
    rust_net_deposit_amount(gross_amount, fee_bps, max_fee)
}

// ============================================================================
// 3. Zero-Indexer Scanning & Note Decryption
// ============================================================================

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiDataSlice {
    pub offset: u32,
    pub length: u32,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiOwnedNote {
    pub page_id: u64,
    pub slot_index: u8,
    pub mint: Vec<u8>,
    pub amount: u64,
    pub is_dynamic_output: bool,
    pub stealth_pk: Vec<u8>,
    pub asset_tag: Vec<u8>,
    pub commitment: Vec<u8>,
    pub asset_blinding: Vec<u8>,
    pub value_blinding: Vec<u8>,
    pub stealth_scalar: Vec<u8>,
    pub spend_x: Option<Vec<u8>>,
    pub nullifier: Option<Vec<u8>>,
    pub nullifier_pda: Option<String>,
}

fn owned_note_to_ffi(note: &OwnedNote) -> FfiOwnedNote {
    FfiOwnedNote {
        page_id: note.page_id,
        slot_index: note.slot_index as u8,
        mint: note.mint.to_vec(),
        amount: note.amount,
        is_dynamic_output: note.is_dynamic_output,
        stealth_pk: note.stealth_pk.to_vec(),
        asset_tag: note.asset_tag.to_vec(),
        commitment: note.commitment.to_vec(),
        asset_blinding: note.asset_blinding.to_bytes().to_vec(),
        value_blinding: note.value_blinding.to_bytes().to_vec(),
        stealth_scalar: note.stealth_scalar.to_bytes().to_vec(),
        spend_x: note.spend_x.map(|s| s.to_bytes().to_vec()),
        nullifier: note.nullifier.map(|n| n.to_vec()),
        nullifier_pda: note.nullifier_pda.map(|p| p.to_string()),
    }
}

fn owned_note_from_ffi(note: &FfiOwnedNote) -> Result<OwnedNote, AudrenFfiError> {
    Ok(OwnedNote {
        page_id: note.page_id,
        slot_index: note.slot_index as usize,
        mint: to_arr32(&note.mint, "mint")?,
        amount: note.amount,
        is_dynamic_output: note.is_dynamic_output,
        stealth_pk: to_arr32(&note.stealth_pk, "stealth_pk")?,
        asset_tag: to_arr32(&note.asset_tag, "asset_tag")?,
        commitment: to_arr32(&note.commitment, "commitment")?,
        asset_blinding: parse_scalar(&note.asset_blinding, "asset_blinding")?,
        value_blinding: parse_scalar(&note.value_blinding, "value_blinding")?,
        stealth_scalar: parse_scalar(&note.stealth_scalar, "stealth_scalar")?,
        spend_x: match &note.spend_x {
            Some(b) => Some(parse_scalar(b, "spend_x")?),
            None => None,
        },
        nullifier: match &note.nullifier {
            Some(b) => Some(to_arr32(b, "nullifier")?),
            None => None,
        },
        nullifier_pda: match &note.nullifier_pda {
            Some(s) => Some(parse_address(s, "nullifier_pda")?),
            None => None,
        },
    })
}

#[uniffi::export]
pub fn page_scan_data_slice() -> FfiDataSlice {
    FfiDataSlice {
        offset: PAGE_SCAN_OFFSET as u32,
        length: PAGE_SCAN_LEN as u32,
    }
}

#[uniffi::export]
pub fn scan_page_dataslice(
    page_id: u64,
    slice_1056: Vec<u8>,
    spend_pk_32: Vec<u8>,
    view_sk_32: Vec<u8>,
) -> Result<Vec<u8>, AudrenFfiError> {
    let view_sk = parse_scalar(&view_sk_32, "view_sk")?;
    let spend_pk = to_arr32(&spend_pk_32, "spend_pk")?;
    let view_pk = audren_client::prover::compress(&(view_sk * audren_client::prover::g_point()));
    let fvk = FullViewingKey {
        spend_pk,
        view_sk,
        view_pk,
    };
    let hits = rust_scan_slice(&fvk, page_id, &slice_1056)?;
    Ok(hits.into_iter().map(|h| h.slot_index as u8).collect())
}

#[uniffi::export]
pub fn scan_epoch_page(
    pool_id: u32,
    page_bytes: Vec<u8>,
    spend_sk_32: Option<Vec<u8>>,
    spend_pk_32: Vec<u8>,
    view_sk_32: Vec<u8>,
    program_id: String,
) -> Result<Vec<FfiOwnedNote>, AudrenFfiError> {
    let pid = default_program_id_or(&program_id)?;
    let hdr = PageHeader::decode(&page_bytes).map_err(|_| AudrenFfiError::InvalidInput {
        reason: "invalid EpochPage bytes".to_string(),
    })?;
    let view_sk = parse_scalar(&view_sk_32, "view_sk")?;
    let spend_pk = to_arr32(&spend_pk_32, "spend_pk")?;
    let view_pk = audren_client::prover::compress(&(view_sk * audren_client::prover::g_point()));
    let fvk = FullViewingKey {
        spend_pk,
        view_sk,
        view_pk,
    };
    let spend_keys = match spend_sk_32 {
        Some(sk) => Some(keys_from_raw(&sk, &view_sk_32)?),
        None => None,
    };
    let mut notes = Vec::new();
    for slot in 0..(hdr.count as usize) {
        // Isolate per-slot decode/decryption failures so one adversarial or corrupted decoy
        // slot on an EpochPage can never abort scanning and blind later owned notes.
        if let Ok(Some(owned)) = rust_decrypt_owned_note(
            &fvk,
            spend_keys.as_ref(),
            &pid,
            pool_id,
            &page_bytes,
            slot,
            None,
        ) {
            notes.push(owned_note_to_ffi(&owned));
        }
    }
    Ok(notes)
}

// ============================================================================
// 4. Local Proof Generation & Instruction Builders
// ============================================================================

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiAccountMeta {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiBuiltInstruction {
    pub program_id: String,
    pub accounts: Vec<FfiAccountMeta>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiBufferedExecutionPlan {
    pub nonce: u64,
    pub proof_buffer_pda: String,
    pub upload_chunks: Vec<FfiBuiltInstruction>,
    pub execute_ix: FfiBuiltInstruction,
}

fn ix_to_ffi(ix: &AudrenInstruction) -> FfiBuiltInstruction {
    FfiBuiltInstruction {
        program_id: ix.program_id.to_string(),
        accounts: ix
            .accounts
            .iter()
            .map(|a| FfiAccountMeta {
                pubkey: a.pubkey.to_string(),
                is_signer: a.is_signer,
                is_writable: a.is_writable,
            })
            .collect(),
        data: ix.data.clone(),
    }
}

fn ix_from_ffi(ix: &FfiBuiltInstruction) -> Result<AudrenInstruction, AudrenFfiError> {
    let program_id = parse_address(&ix.program_id, "program_id")?;
    let mut accounts = Vec::with_capacity(ix.accounts.len());
    for a in &ix.accounts {
        accounts.push(AudrenAccountMeta {
            pubkey: parse_address(&a.pubkey, "account.pubkey")?,
            is_signer: a.is_signer,
            is_writable: a.is_writable,
        });
    }
    Ok(AudrenInstruction {
        program_id,
        accounts,
        data: ix.data.clone(),
    })
}

fn extract_ring_from_pages(pages: &[Vec<u8>]) -> Result<Vec<audren_client::prover::RingSlotWitness>, AudrenFfiError> {
    let mut ring = Vec::with_capacity(pages.len() * 32);
    for p in pages {
        ring.extend(extract_ring_from_page(p)?);
    }
    Ok(ring)
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiDepositParams {
    pub program_id: String,
    pub depositor: String,
    pub pool_id: u32,
    pub active_page_id: u64,
    pub recipient_address: String,
    pub mint_32: Vec<u8>,
    pub gross_amount: u64,
    pub net_amount: u64,
    pub fee_from_amount: bool,
    pub token_program: Option<String>,
    pub depositor_ata: Option<String>,
    pub vault_ata: Option<String>,
}

#[uniffi::export]
pub fn build_deposit_instruction(
    params: FfiDepositParams,
) -> Result<FfiBuiltInstruction, AudrenFfiError> {
    let pid = default_program_id_or(&params.program_id)?;
    let depositor = parse_address(&params.depositor, "depositor")?;
    let recipient = AudrenAddress::from_base58(&params.recipient_address)?;
    let mint = to_arr32(&params.mint_32, "mint")?;
    let spl = match (params.token_program, params.depositor_ata, params.vault_ata) {
        (Some(tp), Some(da), Some(va)) => Some((
            parse_address(&tp, "token_program")?,
            parse_address(&da, "depositor_ata")?,
            parse_address(&va, "vault_ata")?,
        )),
        (None, None, None) => None,
        _ => {
            return Err(AudrenFfiError::InvalidInput {
                reason: "SPL deposit requires token_program, depositor_ata, and vault_ata"
                    .to_string(),
            });
        }
    };
    let (ix, _) = build_deposit_with_options(
        pid,
        depositor,
        params.pool_id,
        params.active_page_id,
        &recipient,
        mint,
        params.gross_amount,
        params.net_amount,
        params.fee_from_amount,
        spl,
        &[],
        &mut OsRng,
    )?;
    Ok(ix_to_ffi(&ix))
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiTransferParams {
    pub program_id: String,
    pub payer: String,
    pub pool_id: u32,
    pub out_page_id: u64,
    pub input_page_ids: Vec<u64>,
    pub input_pages_bytes: Vec<Vec<u8>>,
    pub input_note: FfiOwnedNote,
    pub secret_index: u32,
    pub recipient_address: String,
    pub change_address: String,
    pub pay_amount: u64,
    pub auditor_pk_32: Option<Vec<u8>>,
}

#[uniffi::export]
pub fn build_transfer_instruction(
    params: FfiTransferParams,
) -> Result<FfiBuiltInstruction, AudrenFfiError> {
    let pid = default_program_id_or(&params.program_id)?;
    let payer = parse_address(&params.payer, "payer")?;
    let ring = extract_ring_from_pages(&params.input_pages_bytes)?;
    let owned = owned_note_from_ffi(&params.input_note)?;
    let recipient = AudrenAddress::from_base58(&params.recipient_address)?;
    let change_addr = AudrenAddress::from_base58(&params.change_address)?;
    let auditor_pk = match params.auditor_pk_32 {
        Some(b) => Some(to_arr32(&b, "auditor_pk")?),
        None => None,
    };
    let (ix, _, _) = build_transfer(
        pid,
        payer,
        params.pool_id,
        params.out_page_id,
        &params.input_page_ids,
        &ring,
        &owned,
        params.secret_index as usize,
        &recipient,
        &change_addr,
        params.pay_amount,
        auditor_pk,
        &[],
        &mut OsRng,
    )?;
    Ok(ix_to_ffi(&ix))
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiMergeParams {
    pub program_id: String,
    pub payer: String,
    pub pool_id: u32,
    pub out_page_id: u64,
    pub input1_page_ids: Vec<u64>,
    pub input1_pages_bytes: Vec<Vec<u8>>,
    pub note1: FfiOwnedNote,
    pub secret_index1: u32,
    pub input2_page_ids: Vec<u64>,
    pub input2_pages_bytes: Vec<Vec<u8>>,
    pub note2: FfiOwnedNote,
    pub secret_index2: u32,
    pub owner_address: String,
    pub auditor_pk_32: Option<Vec<u8>>,
}

#[uniffi::export]
pub fn build_merge_instruction(
    params: FfiMergeParams,
) -> Result<FfiBuiltInstruction, AudrenFfiError> {
    let pid = default_program_id_or(&params.program_id)?;
    let payer = parse_address(&params.payer, "payer")?;
    let ring1 = extract_ring_from_pages(&params.input1_pages_bytes)?;
    let ring2 = extract_ring_from_pages(&params.input2_pages_bytes)?;
    let n1 = owned_note_from_ffi(&params.note1)?;
    let n2 = owned_note_from_ffi(&params.note2)?;
    let owner = AudrenAddress::from_base58(&params.owner_address)?;
    let auditor_pk = match params.auditor_pk_32 {
        Some(b) => Some(to_arr32(&b, "auditor_pk")?),
        None => None,
    };
    let (ix, _) = build_merge(
        pid,
        payer,
        params.pool_id,
        params.out_page_id,
        &params.input1_page_ids,
        &ring1,
        &n1,
        params.secret_index1 as usize,
        &params.input2_page_ids,
        &ring2,
        &n2,
        params.secret_index2 as usize,
        &owner,
        auditor_pk,
        &mut OsRng,
    )?;
    Ok(ix_to_ffi(&ix))
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiExecViaEscrowParams {
    pub program_id: String,
    pub payer: String,
    pub pool_id: u32,
    pub out_page_id: u64,
    pub shard_id: u8,
    pub input_page_ids: Vec<u64>,
    pub input_pages_bytes: Vec<Vec<u8>>,
    pub input_note: FfiOwnedNote,
    pub secret_index: u32,
    pub mint_out_32: Vec<u8>,
    pub token_program_in: String,
    pub token_program_out: String,
    pub amount_in: u64,
    pub min_amount_out: u64,
    pub relayer_fee: u64,
    pub fee_on_output: bool,
    pub fee_recipient_ata: Option<String>,
    pub allow_partial_refund: bool,
    pub recipient_address: String,
    pub change_address: String,
    pub auditor_pk_32: Option<Vec<u8>>,
    pub target_program_id: String,
    pub escrow_idx: u8,
    pub escrow_in_idx: u8,
    pub escrow_out_idx: u8,
    pub target_ix_data: Vec<u8>,
    pub action_accounts: Vec<FfiAccountMeta>,
}

#[uniffi::export]
pub fn build_exec_via_escrow_instruction(
    params: FfiExecViaEscrowParams,
) -> Result<FfiBuiltInstruction, AudrenFfiError> {
    let pid = default_program_id_or(&params.program_id)?;
    let payer = parse_address(&params.payer, "payer")?;
    let ring = extract_ring_from_pages(&params.input_pages_bytes)?;
    let owned = owned_note_from_ffi(&params.input_note)?;
    let mint_out = to_arr32(&params.mint_out_32, "mint_out")?;
    let tp_in = parse_address(&params.token_program_in, "token_program_in")?;
    let tp_out = parse_address(&params.token_program_out, "token_program_out")?;
    let fee_recipient_ata = match params.fee_recipient_ata {
        Some(s) => Some(parse_address(&s, "fee_recipient_ata")?),
        None => None,
    };
    let recipient = AudrenAddress::from_base58(&params.recipient_address)?;
    let change_addr = AudrenAddress::from_base58(&params.change_address)?;
    let auditor_pk = match params.auditor_pk_32 {
        Some(b) => Some(to_arr32(&b, "auditor_pk")?),
        None => None,
    };
    let target_pid = parse_address(&params.target_program_id, "target_program_id")?;
    let mut action_accounts = Vec::with_capacity(params.action_accounts.len());
    for a in &params.action_accounts {
        action_accounts.push(AudrenAccountMeta {
            pubkey: parse_address(&a.pubkey, "action_account.pubkey")?,
            is_signer: a.is_signer,
            is_writable: a.is_writable,
        });
    }
    let exec_params = ExecViaEscrowParams {
        program_id: pid,
        payer,
        pool_id: params.pool_id,
        out_page_id: params.out_page_id,
        shard_id: params.shard_id,
        input_page_ids: &params.input_page_ids,
        ring: &ring,
        input_note: &owned,
        secret_index: params.secret_index as usize,
        mint_out,
        token_program_in: tp_in,
        token_program_out: tp_out,
        amount_in: params.amount_in,
        min_amount_out: params.min_amount_out,
        relayer_fee: params.relayer_fee,
        fee_on_output: params.fee_on_output,
        fee_recipient_ata,
        allow_partial_refund: params.allow_partial_refund,
        recipient: &recipient,
        change_addr: &change_addr,
        auditor_pk,
        target_program_id: target_pid,
        escrow_idx: params.escrow_idx,
        escrow_in_idx: params.escrow_in_idx,
        escrow_out_idx: params.escrow_out_idx,
        target_ix_data: &params.target_ix_data,
        action_accounts: &action_accounts,
    };
    let (ix, _, _, _) = build_exec_via_escrow(&exec_params, &mut OsRng)?;
    Ok(ix_to_ffi(&ix))
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiWithdrawParams {
    pub program_id: String,
    pub payer: String,
    pub pool_id: u32,
    pub out_page_id: u64,
    pub input_page_ids: Vec<u64>,
    pub input_pages_bytes: Vec<Vec<u8>>,
    pub input_note: FfiOwnedNote,
    pub secret_index: u32,
    pub recipient_account: String,
    pub change_address: String,
    pub amount: u64,
    pub relayer_fee: u64,
    pub fee_recipient: Option<String>,
    pub unwrap_wsol: bool,
    pub spl_token_program: Option<String>,
    pub auditor_pk_32: Option<Vec<u8>>,
}

#[uniffi::export]
pub fn build_withdraw_instruction(
    params: FfiWithdrawParams,
) -> Result<FfiBuiltInstruction, AudrenFfiError> {
    let pid = default_program_id_or(&params.program_id)?;
    let payer = parse_address(&params.payer, "payer")?;
    let ring = extract_ring_from_pages(&params.input_pages_bytes)?;
    let owned = owned_note_from_ffi(&params.input_note)?;
    let recipient_account = parse_address(&params.recipient_account, "recipient_account")?;
    let change_addr = AudrenAddress::from_base58(&params.change_address)?;
    let fee_recipient = match params.fee_recipient {
        Some(s) => Some(parse_address(&s, "fee_recipient")?),
        None => None,
    };
    let spl_tp = match params.spl_token_program {
        Some(s) => Some(parse_address(&s, "spl_token_program")?),
        None => None,
    };
    let auditor_pk = match params.auditor_pk_32 {
        Some(b) => Some(to_arr32(&b, "auditor_pk")?),
        None => None,
    };
    let (ix, _) = build_withdraw_with_params(
        &WithdrawParams {
            program_id: pid,
            payer,
            pool_id: params.pool_id,
            out_page_id: params.out_page_id,
            input_page_ids: &params.input_page_ids,
            ring: &ring,
            input_note: &owned,
            secret_index: params.secret_index as usize,
            recipient_account,
            change_addr: &change_addr,
            amount: params.amount,
            relayer_fee: params.relayer_fee,
            fee_recipient,
            unwrap_wsol: params.unwrap_wsol,
            spl_token_program: spl_tp,
            auditor_pk,
        },
        &mut OsRng,
    )?;
    Ok(ix_to_ffi(&ix))
}

#[uniffi::export]
pub fn build_buffered_execution_plan(
    nonce: u64,
    inner: FfiBuiltInstruction,
) -> Result<FfiBufferedExecutionPlan, AudrenFfiError> {
    let inner_ix = ix_from_ffi(&inner)?;
    let plan = build_buffered_execution(&inner_ix, nonce)?;
    Ok(FfiBufferedExecutionPlan {
        nonce,
        proof_buffer_pda: plan.proof_buffer.to_string(),
        upload_chunks: plan.upload_chunks.iter().map(ix_to_ffi).collect(),
        execute_ix: ix_to_ffi(&plan.execute),
    })
}

#[uniffi::export]
pub fn build_close_proof_buffer_instruction(
    program_id: String,
    payer: String,
    nonce: u64,
) -> Result<FfiBuiltInstruction, AudrenFfiError> {
    let pid = default_program_id_or(&program_id)?;
    let payer_addr = parse_address(&payer, "payer")?;
    Ok(ix_to_ffi(&build_close_proof_buffer(pid, payer_addr, nonce)))
}

#[uniffi::export]
pub fn build_open_page_instruction(
    program_id: String,
    payer: String,
    pool_id: u32,
    current_page_id: u64,
) -> Result<FfiBuiltInstruction, AudrenFfiError> {
    let pid = default_program_id_or(&program_id)?;
    let payer_addr = parse_address(&payer, "payer")?;
    Ok(ix_to_ffi(&build_open_page(
        pid,
        payer_addr,
        pool_id,
        current_page_id,
    )))
}

#[uniffi::export]
pub fn build_open_lane_page_instruction(
    program_id: String,
    payer: String,
    pool_id: u32,
    current_page_id: u64,
) -> Result<FfiBuiltInstruction, AudrenFfiError> {
    let pid = default_program_id_or(&program_id)?;
    let payer_addr = parse_address(&payer, "payer")?;
    Ok(ix_to_ffi(&build_open_lane_page(
        pid,
        payer_addr,
        pool_id,
        current_page_id,
    )?))
}

// ============================================================================
// 5. Selective Disclosure & Institutional Audit
// ============================================================================

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiSelectiveDisclosureProof {
    pub version: u8,
    pub page_id: u64,
    pub slot_index: u8,
    pub stealth_pk_b58: String,
    pub asset_tag_b58: String,
    pub commitment_b58: String,
    pub mint_b58: String,
    pub amount: u64,
    pub asset_blinding_b58: String,
    pub value_blinding_b58: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiAuditorKeypair {
    pub auditor_sk: Vec<u8>,
    pub auditor_pk: Vec<u8>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiAuditorDecryptedNote {
    pub spent_stealth_pk: Vec<u8>,
    pub asset_generator: Vec<u8>,
}

#[uniffi::export]
pub fn create_selective_disclosure_proof(note: FfiOwnedNote) -> FfiSelectiveDisclosureProof {
    FfiSelectiveDisclosureProof {
        version: 1,
        page_id: note.page_id,
        slot_index: note.slot_index,
        stealth_pk_b58: bs58::encode(&note.stealth_pk).into_string(),
        asset_tag_b58: bs58::encode(&note.asset_tag).into_string(),
        commitment_b58: bs58::encode(&note.commitment).into_string(),
        mint_b58: bs58::encode(&note.mint).into_string(),
        amount: note.amount,
        asset_blinding_b58: bs58::encode(&note.asset_blinding).into_string(),
        value_blinding_b58: bs58::encode(&note.value_blinding).into_string(),
    }
}

fn sd_from_ffi(p: &FfiSelectiveDisclosureProof) -> SelectiveDisclosureProof {
    SelectiveDisclosureProof {
        version: p.version,
        page_id: p.page_id,
        slot_index: p.slot_index,
        stealth_pk_b58: p.stealth_pk_b58.clone(),
        asset_tag_b58: p.asset_tag_b58.clone(),
        commitment_b58: p.commitment_b58.clone(),
        mint_b58: p.mint_b58.clone(),
        amount: p.amount,
        asset_blinding_b58: p.asset_blinding_b58.clone(),
        value_blinding_b58: p.value_blinding_b58.clone(),
    }
}

#[uniffi::export]
pub fn verify_selective_disclosure_proof(
    proof: FfiSelectiveDisclosureProof,
) -> Result<bool, AudrenFfiError> {
    Ok(sd_from_ffi(&proof).verify()?)
}

#[uniffi::export]
pub fn verify_selective_disclosure_on_page(
    proof: FfiSelectiveDisclosureProof,
    page_bytes: Vec<u8>,
) -> Result<bool, AudrenFfiError> {
    Ok(sd_from_ffi(&proof).verify_against_page(&page_bytes)?)
}

#[uniffi::export]
pub fn derive_auditor_keypair(seed_32: Vec<u8>) -> Result<FfiAuditorKeypair, AudrenFfiError> {
    let seed = to_arr32(&seed_32, "auditor_seed")?;
    let kp = AuditorKeypair::from_seed(&seed);
    Ok(FfiAuditorKeypair {
        auditor_sk: kp.auditor_sk.to_bytes().to_vec(),
        auditor_pk: kp.auditor_pk.to_vec(),
    })
}

#[uniffi::export]
pub fn auditor_decrypt_note(
    auditor_sk_32: Vec<u8>,
    s1_32: Vec<u8>,
    s2_32: Vec<u8>,
    m1_32: Vec<u8>,
    m2_32: Vec<u8>,
) -> Result<FfiAuditorDecryptedNote, AudrenFfiError> {
    let sk = parse_scalar(&auditor_sk_32, "auditor_sk")?;
    let pk = audren_client::prover::compress(&(sk * audren_client::prover::g_point()));
    let kp = AuditorKeypair {
        auditor_sk: sk,
        auditor_pk: pk,
    };
    let spent = kp.decrypt_spent_pubkey(&to_arr32(&s1_32, "s1")?, &to_arr32(&s2_32, "s2")?)?;
    let g_mint =
        kp.decrypt_asset_generator(&to_arr32(&m1_32, "m1")?, &to_arr32(&m2_32, "m2")?)?;
    Ok(FfiAuditorDecryptedNote {
        spent_stealth_pk: spent.to_vec(),
        asset_generator: g_mint.to_vec(),
    })
}

// ============================================================================
// 6. Escrow & Relayer Helpers
// ============================================================================

#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiPreparedEscrowAccounts {
    pub escrow_pda: String,
    pub escrow_in_ata: String,
    pub escrow_out_ata: String,
    pub escrow_idx: u8,
    pub escrow_in_idx: u8,
    pub escrow_out_idx: u8,
    pub accounts: Vec<FfiAccountMeta>,
}

#[uniffi::export]
pub fn jupiter_cpi_excluded_dexes() -> Vec<String> {
    JUPITER_CPI_EXCLUDED_DEXES
        .split(',')
        .map(|s| s.to_string())
        .collect()
}

#[uniffi::export]
pub fn default_relay_url() -> String {
    DEFAULT_RELAY_URL.to_string()
}

#[uniffi::export]
pub fn prepare_escrow_accounts(
    pool_id: u32,
    shard_id: u8,
    input_mint_b58: String,
    output_mint_b58: String,
    input_token_program_b58: String,
    output_token_program_b58: String,
    action_accounts: Vec<FfiAccountMeta>,
    program_id: String,
) -> Result<FfiPreparedEscrowAccounts, AudrenFfiError> {
    let pid = default_program_id_or(&program_id)?;
    let (escrow_pda, _) = rust_derive_escrow_pda(&pid, pool_id, shard_id);
    let in_mint = parse_address(&input_mint_b58, "input_mint")?;
    let out_mint = parse_address(&output_mint_b58, "output_mint")?;
    let in_tp = parse_address(&input_token_program_b58, "input_token_program")?;
    let out_tp = parse_address(&output_token_program_b58, "output_token_program")?;
    let escrow_in_ata = derive_ata(&escrow_pda, &in_tp, &in_mint);
    let escrow_out_ata = derive_ata(&escrow_pda, &out_tp, &out_mint);

    let mut metas = Vec::with_capacity(action_accounts.len());
    for a in &action_accounts {
        metas.push(AudrenAccountMeta {
            pubkey: parse_address(&a.pubkey, "action_account.pubkey")?,
            is_signer: a.is_signer,
            is_writable: a.is_writable,
        });
    }
    let (escrow_idx, escrow_in_idx, escrow_out_idx) = locate_escrow_indices(
        &metas,
        &escrow_pda,
        &escrow_in_ata,
        &escrow_out_ata,
    )
    .ok_or_else(|| AudrenFfiError::InvalidInput {
        reason: "action accounts missing escrow_pda, escrow_in_ata, or escrow_out_ata"
            .to_string(),
    })?;

    let escrow_str = escrow_pda.to_string();
    let accounts = action_accounts
        .into_iter()
        .map(|mut a| {
            if a.pubkey == escrow_str {
                a.is_signer = false;
            }
            a
        })
        .collect();

    Ok(FfiPreparedEscrowAccounts {
        escrow_pda: escrow_str,
        escrow_in_ata: escrow_in_ata.to_string(),
        escrow_out_ata: escrow_out_ata.to_string(),
        escrow_idx,
        escrow_in_idx,
        escrow_out_idx,
        accounts,
    })
}
