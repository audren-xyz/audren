//! Aggregator & Relayer interoperability constants and `ExecViaEscrow` account-normalization
//! helpers synced across Rust, TypeScript, Relayer, and Web.

use std::collections::HashSet;

use solana_address::Address;

use crate::{
    instructions::AudrenAccountMeta,
    pda::{derive_ata, derive_escrow_pda},
    ClientError,
};

/// Default public reference Privacy Relayer endpoint (optional — Audren is permissionless and
/// supports direct self-pay Transaction v1 or any self-hosted `apps/relay` instance).
pub const DEFAULT_RELAY_URL: &str = "https://relay.audren.xyz";

/// DEX venues excluded from Jupiter CPI routes executed via PDA `invoke_signed` in `ExecViaEscrow`
/// (venues requiring non-PDA Ed25519 signers, incompatible account counts, or non-CPI-safe hooks).
///
/// MUST remain synced identically across:
/// - `crates/client/src/router.rs`
/// - `packages/sdk/src/swap.ts`
/// - `apps/relay/src/aggregators/jupiter.ts`
/// - `apps/web/worker/index.ts`
///
/// Verified automatically by `python3 idl/verify-idl.py`.
pub const JUPITER_CPI_EXCLUDED_DEXES: &[&str] = &[
    "Kipseli",
    "Quantum",
    "BisonFi",
    "BisonFi Predict",
    "BinaryFi",
    "Obsidian",
    "VaultLiquidUnstake",
    "Sanctum Prop S",
];

/// Strip the external signer bit on `escrow_address` AND promote `is_writable = true` on any
/// account whose pubkey is `escrow_address`, listed in `extra_writable`, or appears with
/// `is_writable = true` anywhere in `action_accounts` (matching Solana's transaction-wide
/// writability union so on-chain `hash_router_accounts_arena` matches `ctx_hash` bit-for-bit).
pub fn prepare_escrow_accounts_for_audren(
    action_accounts: &[AudrenAccountMeta],
    escrow_address: &Address,
    extra_writable: &[Address],
) -> Vec<AudrenAccountMeta> {
    let escrow_bytes = escrow_address.to_bytes();
    let mut writable: HashSet<[u8; 32]> = HashSet::with_capacity(
        1 + extra_writable.len() + action_accounts.len(),
    );
    writable.insert(escrow_bytes);
    for addr in extra_writable {
        writable.insert(addr.to_bytes());
    }
    for meta in action_accounts {
        if meta.is_writable {
            writable.insert(meta.pubkey);
        }
    }
    action_accounts
        .iter()
        .map(|meta| AudrenAccountMeta {
            pubkey: meta.pubkey,
            is_signer: if meta.pubkey == escrow_bytes {
                false
            } else {
                meta.is_signer
            },
            is_writable: meta.is_writable || writable.contains(&meta.pubkey),
        })
        .collect()
}

/// Prepared `ExecViaEscrow` router account bundle with resolved escrow indices and normalized
/// signer/writability flags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedEscrowAccounts {
    pub escrow_pda: Address,
    pub escrow_in_ata: Address,
    pub escrow_out_ata: Address,
    pub escrow_idx: usize,
    pub escrow_in_idx: usize,
    pub escrow_out_idx: usize,
    pub accounts: Vec<AudrenAccountMeta>,
}

/// Derive the sharded `escrow` PDA and its input/output ATAs, verify all three appear in
/// `action_accounts`, strip the external signer bit on `escrow`, and apply Solana's
/// transaction-wide writability promotion across `escrow`, escrow ATAs, and `extra_writable`.
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
    extra_writable: &[Address],
) -> Result<PreparedEscrowAccounts, ClientError> {
    let (escrow_pda, _) = derive_escrow_pda(program_id, pool_id, shard_id);
    let escrow_in_ata = derive_ata(&escrow_pda, input_token_program, input_mint);
    let escrow_out_ata = derive_ata(&escrow_pda, output_token_program, output_mint);

    let escrow_b = escrow_pda.to_bytes();
    let in_b = escrow_in_ata.to_bytes();
    let out_b = escrow_out_ata.to_bytes();

    let escrow_idx = action_accounts
        .iter()
        .position(|m| m.pubkey == escrow_b)
        .ok_or(ClientError::InvalidEncoding("escrow PDA missing from router accounts"))?;
    let escrow_in_idx = action_accounts
        .iter()
        .position(|m| m.pubkey == in_b)
        .ok_or(ClientError::InvalidEncoding("escrow input ATA missing from router accounts"))?;
    let escrow_out_idx = action_accounts
        .iter()
        .position(|m| m.pubkey == out_b)
        .ok_or(ClientError::InvalidEncoding("escrow output ATA missing from router accounts"))?;

    let mut all_extra = Vec::with_capacity(2 + extra_writable.len());
    all_extra.push(escrow_in_ata);
    all_extra.push(escrow_out_ata);
    all_extra.extend_from_slice(extra_writable);

    let accounts = prepare_escrow_accounts_for_audren(action_accounts, &escrow_pda, &all_extra);
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
