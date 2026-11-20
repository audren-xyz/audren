//! Router-Agnostic Private Swap & Stateless Relayer Wire Codecs.
//!
//! Works with any Solana DEX aggregator or AMM router (Jupiter, Orca, Raydium, Meteora,
//! Phoenix, Titan, DFlow, or custom routers) that emits a swap instruction signed by
//! Audren's isolated `swap_escrow` PDA.

use serde::{Deserialize, Serialize};
use solana_address::Address;

use crate::instructions::AudrenAccountMeta;

/// Standard aggregator `/quote` request payload (compatible with Jupiter v6 and similar APIs).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterQuoteRequest {
    pub input_mint: String,
    pub output_mint: String,
    pub amount: String,
    pub slippage_bps: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_direct_routes: Option<bool>,
}

/// Standard aggregator `/swap-instructions` request configured for Audren's sharded `swap_escrow` PDA.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterSwapInstructionsRequest {
    pub quote_response: serde_json::Value,
    /// Must be Audren's `derive_swap_escrow_pda(program_id, pool_id, shard_id)` address.
    pub user_public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrap_and_unwrap_sol: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_shared_accounts: Option<bool>,
}

impl RouterSwapInstructionsRequest {
    pub fn for_audren_escrow(quote_response: serde_json::Value, swap_escrow: &Address) -> Self {
        Self {
            quote_response,
            user_public_key: swap_escrow.to_string(),
            wrap_and_unwrap_sol: Some(false),
            use_shared_accounts: Some(false),
        }
    }
}

/// Decoded account metadata from a DEX aggregator's `swapInstruction` JSON object.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterAccountMeta {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

/// Decoded external router instruction returned by a DEX aggregator API.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterEncodedInstruction {
    pub program_id: String,
    pub accounts: Vec<RouterAccountMeta>,
    /// Base64-encoded raw router instruction data.
    pub data: String,
}

/// Locate `(escrow_idx, escrow_in_idx, escrow_out_idx)` inside an arbitrary router account list.
pub fn locate_escrow_indices(
    router_accounts: &[AudrenAccountMeta],
    swap_escrow: &Address,
    escrow_in: &Address,
    escrow_out: &Address,
) -> Option<(u8, u8, u8)> {
    let e_idx = router_accounts
        .iter()
        .position(|m| m.pubkey == *swap_escrow)?;
    let in_idx = router_accounts
        .iter()
        .position(|m| m.pubkey == *escrow_in)?;
    let out_idx = router_accounts
        .iter()
        .position(|m| m.pubkey == *escrow_out)?;
    Some((
        u8::try_from(e_idx).ok()?,
        u8::try_from(in_idx).ok()?,
        u8::try_from(out_idx).ok()?,
    ))
}

/// Stateless relayer submission envelope for gasless shielded sends/swaps/withdrawals.
/// The relayer pays Solana tx fees and `NullifierPDA` / `EpochPage` rent without ever
/// learning the sender's identity, note secret, or spend key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayerSubmitRequest {
    pub pool_id: u32,
    pub program_id: String,
    /// Base64-encoded Audren instruction bytes (`Transfer` / `Merge` / `SwapViaRouter` / `Withdraw`).
    pub instruction_data_b64: String,
    pub account_metas: Vec<RouterAccountMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_lookup_tables: Option<Vec<String>>,
    /// Optional priority fee ceiling in microlamports per CU.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_microlamports: Option<u64>,
}
