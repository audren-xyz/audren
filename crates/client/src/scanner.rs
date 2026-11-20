//! Zero-Indexer Pure-RPC Scanner for Audren `EpochPage` PDAs and `NullifierPDA`s.
//!
//! Uses Solana's native `getMultipleAccounts(..., { dataSlice: { offset: 64, length: 1056 } })`
//! (and Agave 4.4 `programSubscribe` WebSocket `dataSlice` streaming) so a wallet scans up to
//! **100 pages (`3,200` notes)** per single RPC call (~`106 KB` total) without any centralized
//! indexing server or API key.

use crate::keys::{
    compute_note_nullifier, decrypt_note_memo, derive_stealth_from_shared, quick_view_tag_match,
    AudrenKeys, FullViewingKey, NOTE_FLAG_BLINDED_ASSET, NOTE_FLAG_BLINDED_VALUE,
    NOTE_FLAG_DYNAMIC_ONCHAIN_VALUE,
};
use crate::pda::{derive_epoch_page_pda, derive_nullifier_pda};
use crate::prover::{asset_generator, compress, decompress, h_point, Point};
use crate::ClientError;
use audren_core::layout::{
    read_page_note, PageHeader, PAGE_CAPACITY, PAGE_LEN, PAGE_MAGIC, PAGE_OFF_POOL_ID,
    PAGE_SCAN_LEN, PAGE_SCAN_OFFSET,
};
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use solana_address::Address;

/// Maximum accounts per Solana `getMultipleAccounts` RPC batch.
pub const RPC_MULTI_ACCOUNT_BATCH: usize = 100;

/// Persistent lightweight wallet cursor stored locally (starts at wallet `birth_page_id`).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct WalletScanCursor {
    pub birth_page_id: u64,
    pub next_page_id: u64,
}

/// Candidate slot discovered from the compact 1,056-byte `dataSlice` pass.
#[derive(Clone, Debug)]
pub struct ScanCandidate {
    pub page_id: u64,
    pub slot_index: usize,
    pub ephemeral_pk: Point,
}

/// Verified note owned by the user, ready to spend or display in balance view.
#[derive(Clone)]
pub struct OwnedNote {
    pub page_id: u64,
    pub slot_index: usize,
    pub mint: [u8; 32],
    /// Confirmed amount (`Some(amount)`) or `None` if `FLAG_DYNAMIC_ONCHAIN_VALUE` needs tx resolution.
    pub amount: u64,
    pub is_dynamic_output: bool,
    pub stealth_pk: Point,
    pub asset_tag: Point,
    pub commitment: Point,
    pub asset_blinding: Scalar,
    pub value_blinding: Scalar,
    pub stealth_scalar: Scalar,
    pub spend_x: Option<Scalar>,
    pub nullifier: Option<Point>,
    pub nullifier_pda: Option<Address>,
}

fn encode_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Build a pure Solana JSON-RPC `getMultipleAccounts` request using `dataSlice`
/// to scan up to 100 `EpochPage`s (`3,200` notes) in a single RPC call (~`106 KB`).
pub fn build_page_scan_rpc_request(
    rpc_id: u64,
    program_id: &Address,
    pool_id: u32,
    page_ids: &[u64],
) -> Value {
    let keys: Vec<String> = page_ids
        .iter()
        .take(RPC_MULTI_ACCOUNT_BATCH)
        .map(|&pid| derive_epoch_page_pda(program_id, pool_id, pid).0.to_string())
        .collect();
    json!({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "getMultipleAccounts",
        "params": [
            keys,
            {
                "encoding": "base64",
                "commitment": "confirmed",
                "dataSlice": {
                    "offset": PAGE_SCAN_OFFSET,
                    "length": PAGE_SCAN_LEN
                }
            }
        ]
    })
}

/// Build an Agave 4.4+ WebSocket `programSubscribe` request that streams real-time
/// `1,056 B` `EpochPage` scan slices (`dataSlice`) for a specific `pool_id`, saving ~83%
/// WebSocket bandwidth with zero custom indexing infrastructure.
pub fn build_page_subscribe_ws_request(
    rpc_id: u64,
    program_id: &Address,
    pool_id: u32,
) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "programSubscribe",
        "params": [
            program_id.to_string(),
            {
                "encoding": "base64",
                "commitment": "confirmed",
                "dataSlice": {
                    "offset": PAGE_SCAN_OFFSET,
                    "length": PAGE_SCAN_LEN
                },
                "filters": [
                    { "dataSize": PAGE_LEN },
                    {
                        "memcmp": {
                            "offset": 0,
                            "bytes": encode_base64(&PAGE_MAGIC),
                            "encoding": "base64"
                        }
                    },
                    {
                        "memcmp": {
                            "offset": PAGE_OFF_POOL_ID,
                            "bytes": encode_base64(&pool_id.to_le_bytes()),
                            "encoding": "base64"
                        }
                    }
                ]
            }
        ]
    })
}

/// Build a pure Solana JSON-RPC `getMultipleAccounts` request checking up to 100
/// deterministic `NullifierPDA`s (`dataSlice: 0` -> zero bytes transferred; non-null == spent).
pub fn build_nullifier_check_rpc_request(
    rpc_id: u64,
    program_id: &Address,
    pool_id: u32,
    nullifiers: &[Point],
) -> Value {
    let keys: Vec<String> = nullifiers
        .iter()
        .take(RPC_MULTI_ACCOUNT_BATCH)
        .map(|j| derive_nullifier_pda(program_id, pool_id, j).0.to_string())
        .collect();
    json!({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "getMultipleAccounts",
        "params": [
            keys,
            {
                "encoding": "base64",
                "commitment": "confirmed",
                "dataSlice": {
                    "offset": 0,
                    "length": 0
                }
            }
        ]
    })
}

/// Stage 1 (Fast Filter): Scan a single 1,056-byte `dataSlice` (`view_tags[32] + ephemeral_pks[32]`).
/// Skips `255/256` non-matching notes without fetching full `6,240 B` pages.
pub fn scan_page_dataslice(
    fvk: &FullViewingKey,
    page_id: u64,
    slice: &[u8],
) -> Result<Vec<ScanCandidate>, ClientError> {
    if slice.len() < PAGE_SCAN_LEN {
        return Err(ClientError::InvalidEncoding(
            "page dataSlice shorter than 1,056 bytes",
        ));
    }
    let view_tags = &slice[..PAGE_CAPACITY];
    let eph_base = PAGE_CAPACITY;
    let mut hits = Vec::new();
    for slot in 0..PAGE_CAPACITY {
        let mut eph = [0u8; 32];
        eph.copy_from_slice(&slice[eph_base + slot * 32..eph_base + (slot + 1) * 32]);
        if eph == [0u8; 32] {
            // Unpopulated tail slot — pages fill densely from 0..count.
            break;
        }
        if quick_view_tag_match(fvk, &eph, view_tags[slot]).is_some() {
            hits.push(ScanCandidate {
                page_id,
                slot_index: slot,
                ephemeral_pk: eph,
            });
        }
    }
    Ok(hits)
}

/// Stage 2 (Full Note Verification): Decrypt a matched slot from full `EpochPage` bytes,
/// verify its stealth pubkey + asset tag + value commitment, and (if spend keys are provided)
/// derive its unique spend nullifier `J` and `NullifierPDA`.
pub fn decrypt_owned_note(
    fvk: &FullViewingKey,
    spend_keys: Option<&AudrenKeys>,
    program_id: &Address,
    pool_id: u32,
    page_bytes: &[u8],
    slot_index: usize,
    resolved_dynamic_amount: Option<u64>,
) -> Result<Option<OwnedNote>, ClientError> {
    let hdr = PageHeader::decode(page_bytes)
        .map_err(|_| ClientError::InvalidEncoding("invalid epoch page header"))?;
    if slot_index >= hdr.count as usize {
        return Ok(None);
    }
    let entry = read_page_note(page_bytes, slot_index)
        .map_err(|_| ClientError::InvalidEncoding("invalid note slot"))?;

    let Some(shared) = quick_view_tag_match(fvk, &entry.ephemeral_pk, entry.view_tag) else {
        return Ok(None);
    };
    let mat = derive_stealth_from_shared(&fvk.spend_pk, entry.ephemeral_pk, &shared)?;
    if mat.stealth_pk != entry.stealth_pk {
        // 1/256 false positive on `view_tag`.
        return Ok(None);
    }

    let payload = decrypt_note_memo(&mat, &entry.ciphertext)?;
    let is_dynamic = (payload.flags & NOTE_FLAG_DYNAMIC_ONCHAIN_VALUE) != 0;
    let amount = if is_dynamic {
        resolved_dynamic_amount.unwrap_or(payload.amount)
    } else {
        payload.amount
    };

    let asset_blinding = if (payload.flags & NOTE_FLAG_BLINDED_ASSET) != 0 {
        mat.derived_asset_blinding
    } else {
        Scalar::ZERO
    };
    let value_blinding = if (payload.flags & NOTE_FLAG_BLINDED_VALUE) != 0 {
        mat.derived_value_blinding
    } else {
        Scalar::ZERO
    };

    // Cryptographically verify on-chain asset tag & commitment match decrypted secrets.
    let g_mint = decompress(&asset_generator(&payload.mint))?;
    let expected_a = g_mint + asset_blinding * h_point();
    if compress(&expected_a) != entry.asset_tag {
        return Ok(None);
    }
    if !is_dynamic || resolved_dynamic_amount.is_some() {
        let expected_v = Scalar::from(amount) * expected_a + value_blinding * h_point();
        if compress(&expected_v) != entry.commitment {
            return Ok(None);
        }
    }

    let (spend_x, nullifier, nullifier_pda) = if let Some(keys) = spend_keys {
        let (x, j) = compute_note_nullifier(&keys.spend_sk, &mat.stealth_scalar)?;
        let pda = derive_nullifier_pda(program_id, pool_id, &j).0;
        (Some(x), Some(j), Some(pda))
    } else {
        (None, None, None)
    };

    Ok(Some(OwnedNote {
        page_id: hdr.page_id,
        slot_index,
        mint: payload.mint,
        amount,
        is_dynamic_output: is_dynamic,
        stealth_pk: entry.stealth_pk,
        asset_tag: entry.asset_tag,
        commitment: entry.commitment,
        asset_blinding,
        value_blinding,
        stealth_scalar: mat.stealth_scalar,
        spend_x,
        nullifier,
        nullifier_pda,
    }))
}
