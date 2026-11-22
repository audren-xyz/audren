//! Protocol-Agnostic Shielded DeFi Execution (`ExecViaEscrow`) & Stateless Relayer Wire Codecs.
//!
//! Works with any compatible PDA-signing Solana program (DEX aggregators, supply lending,
//! yield vaults, liquid staking, perp LP, RWA mint/redeem) that satisfies Audren custody
//! isolation and transaction limits.

use serde::{Deserialize, Serialize};
use solana_address::Address;

use crate::instructions::AudrenAccountMeta;

/// Default open-source Audren privacy relayer endpoint (relayer-agnostic; any self-hosted
/// `apps/relay` instance implements the exact same HTTP contract).
pub const DEFAULT_RELAY_URL: &str = "https://relay.audren.xyz";

/// Jupiter DEX labels that reject PDA CPI callers (e.g. `InvalidRealUser` / sysvar top-level
/// instruction introspection) and must be excluded when routing through `ExecViaEscrow`.
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

/// Standard aggregator `/swap-instructions` request configured for Audren's sharded `escrow` PDA.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterSwapInstructionsRequest {
    pub quote_response: serde_json::Value,
    /// Must be Audren's `derive_escrow_pda(program_id, pool_id, shard_id)` address.
    pub user_public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrap_and_unwrap_sol: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_shared_accounts: Option<bool>,
}

impl RouterSwapInstructionsRequest {
    pub fn for_audren_escrow(quote_response: serde_json::Value, escrow_pda: &Address) -> Self {
        Self {
            quote_response,
            user_public_key: escrow_pda.to_string(),
            wrap_and_unwrap_sol: Some(false),
            use_shared_accounts: Some(false),
        }
    }
}

/// Decoded account metadata from an external program instruction JSON object.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterAccountMeta {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

/// Decoded external program instruction (target CPI action or zero-signer pre-instruction crank).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterEncodedInstruction {
    pub program_id: String,
    pub accounts: Vec<RouterAccountMeta>,
    /// Base64-encoded raw instruction data.
    pub data: String,
}

/// Locate `(escrow_idx, escrow_in_idx, escrow_out_idx)` inside an arbitrary action account list.
pub fn locate_escrow_indices(
    action_accounts: &[AudrenAccountMeta],
    escrow_pda: &Address,
    escrow_in: &Address,
    escrow_out: &Address,
) -> Option<(u8, u8, u8)> {
    let e_idx = action_accounts
        .iter()
        .position(|m| m.pubkey == *escrow_pda)?;
    let in_idx = action_accounts
        .iter()
        .position(|m| m.pubkey == *escrow_in)?;
    let out_idx = action_accounts
        .iter()
        .position(|m| m.pubkey == *escrow_out)?;
    Some((
        u8::try_from(e_idx).ok()?,
        u8::try_from(in_idx).ok()?,
        u8::try_from(out_idx).ok()?,
    ))
}

/// Prepared escrow accounts ready for [`crate::instructions::build_exec_via_escrow`].
/// Mirrors TypeScript `PreparedEscrowAccounts`, Swift `FfiPreparedEscrowAccounts`, and Kotlin.
#[derive(Clone, Debug)]
pub struct PreparedEscrowAccounts {
    pub escrow_pda: Address,
    pub escrow_in_ata: Address,
    pub escrow_out_ata: Address,
    pub escrow_idx: u8,
    pub escrow_in_idx: u8,
    pub escrow_out_idx: u8,
    pub accounts: Vec<AudrenAccountMeta>,
}

/// Derive `(escrow_pda, escrow_in_ata, escrow_out_ata)`, locate `(escrow_idx, escrow_in_idx, escrow_out_idx)`
/// inside `action_accounts`, and strip the external signer bit on `escrow_pda` (Audren signs via `invoke_signed`).
#[allow(clippy::too_many_arguments)]
pub fn prepare_escrow_accounts(
    program_id: &Address,
    pool_id: u32,
    shard_id: u8,
    input_mint: &Address,
    output_mint: &Address,
    input_token_program: &Address,
    output_token_program: &Address,
    action_accounts: &[AudrenAccountMeta],
) -> Result<PreparedEscrowAccounts, crate::ClientError> {
    let (escrow_pda, _) = crate::pda::derive_escrow_pda(program_id, pool_id, shard_id);
    let escrow_in_ata = crate::pda::derive_ata(&escrow_pda, input_token_program, input_mint);
    let escrow_out_ata = crate::pda::derive_ata(&escrow_pda, output_token_program, output_mint);
    let (escrow_idx, escrow_in_idx, escrow_out_idx) =
        locate_escrow_indices(action_accounts, &escrow_pda, &escrow_in_ata, &escrow_out_ata)
            .ok_or(crate::ClientError::InvalidProofInput(
                "action_accounts must contain escrow_pda, escrow_in_ata, and escrow_out_ata",
            ))?;
    let accounts = action_accounts
        .iter()
        .map(|m| AudrenAccountMeta {
            pubkey: m.pubkey,
            is_signer: if m.pubkey == escrow_pda {
                false
            } else {
                m.is_signer
            },
            is_writable: m.is_writable,
        })
        .collect();
    Ok(PreparedEscrowAccounts {
        escrow_pda,
        escrow_in_ata,
        escrow_out_ata,
        escrow_idx,
        escrow_in_idx,
        escrow_out_idx,
        accounts,
    })
}

/// Query parameters for `GET /v1/fee-quote` on `audren-relay`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayerFeeQuoteRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
    /// `"withdraw"` or `"exec_escrow"`.
    pub op: String,
    /// `"native"`, System Program ID, or base58 SPL / Token-2022 mint.
    pub mint: String,
    /// Base-unit decimal amount string.
    pub amount: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unwrap_wsol: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_change: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_ata_count: Option<u8>,
}

impl RelayerFeeQuoteRequest {
    /// Format query string for `GET /v1/fee-quote?...`.
    pub fn to_query_string(&self) -> String {
        let mut parts = vec![
            format!("op={}", self.op),
            format!("mint={}", self.mint),
            format!("amount={}", self.amount),
        ];
        if let Some(c) = &self.cluster {
            parts.push(format!("cluster={c}"));
        }
        if let Some(u) = self.unwrap_wsol {
            parts.push(format!("unwrapWsol={u}"));
        }
        if let Some(h) = self.has_change {
            parts.push(format!("hasChange={h}"));
        }
        if let Some(m) = self.missing_ata_count {
            parts.push(format!("missingAtaCount={m}"));
        }
        parts.join("&")
    }
}

/// Response from `GET /v1/fee-quote` matching `NativeFeeQuote` in `audren-relay`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayerFeeQuoteResponse {
    pub ok: bool,
    pub cluster: String,
    pub op: String,
    pub billing_mode: String,
    pub fee_mint: String,
    pub fee_token_program: Option<String>,
    pub fee_recipient: Option<String>,
    pub fee_recipient_exists: bool,
    pub needs_fee_ata_setup: bool,
    pub relayer_fee: String,
    pub fee_bps: u32,
    pub estimated_relay_cost_lamports: String,
    pub estimated_relay_cost_usd: Option<f64>,
    pub reason: String,
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
    /// Base64-encoded Audren instruction bytes (`Transfer` / `Merge` / `ExecViaEscrow` / `Withdraw`).
    pub instruction_data_b64: String,
    pub accounts: Vec<RouterAccountMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_atas: Option<Vec<RelayerSetupAta>>,
    /// Optional zero-signer pre-instructions (e.g. Kamino `refreshReserve` or Pyth crank)
    /// allowlisted strictly for `ExecViaEscrow` (`Tag 5`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_instructions: Option<Vec<RouterEncodedInstruction>>,
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
