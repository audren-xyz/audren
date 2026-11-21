//! Router-Agnostic Private Swap & Stateless Relayer Wire Codecs.
//!
//! Works with compatible PDA-signing Solana routers that satisfy Audren custody
//! checks and transaction limits. Hosted route availability is provider-specific.

use serde::{Deserialize, Serialize};
use solana_address::Address;

use crate::instructions::AudrenAccountMeta;

/// Jupiter DEX labels that reject PDA CPI callers (e.g. `InvalidRealUser` / sysvar top-level
/// instruction introspection) and must be excluded when routing through `SwapViaRouter`.
pub const JUPITER_CPI_EXCLUDED_DEXES: &str =
    "Kipseli,Quantum,BisonFi,BisonFi Predict,BinaryFi,Obsidian,VaultLiquidUnstake,Sanctum Prop S";

/// Standard aggregator `/quote` request payload (compatible with Jupiter v1/v6 and similar APIs).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterQuoteRequest {
    pub input_mint: String,
    pub output_mint: String,
    pub amount: String,
    pub slippage_bps: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_direct_routes: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_dexes: Option<String>,
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

/// Setup ATA specification passed to `/v1/relay/submit` so the relayer can prepend
/// idempotent ATA creation when vault, escrow, fee, or recipient ATAs do not exist yet.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayerSetupAta {
    pub owner: String,
    pub mint: String,
    pub token_program: String,
}

/// Stateless relayer submission envelope matching `audren-relay` (`POST /v1/relay/submit`).
/// The relayer pays Solana tx fees and `NullifierPDA` / `EpochPage` rent without ever
/// learning the sender's identity, note secret, or spend key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayerSubmitRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
    /// Base64-encoded Audren instruction bytes (`Transfer` / `Merge` / `SwapViaRouter` / `Withdraw`).
    pub instruction_data_b64: String,
    pub accounts: Vec<RouterAccountMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_atas: Option<Vec<RelayerSetupAta>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compute_unit_limit: Option<u32>,
    /// Decimal string lamports for Solana v1 `priorityFeeLamports`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority_fee_lamports: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_out_ata: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollover_from_page_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}
