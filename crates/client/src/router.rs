//! Aggregator & Relayer interoperability constants and `ExecViaEscrow` account-normalization
//! helpers synced across Rust, TypeScript, Relayer, and Web.

use std::collections::HashSet;

use audren_core::{NUM_ESCROW_SHARDS, NUM_LANES};
use rand::{rngs::OsRng, Rng};
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

const TOKEN_2022_ACCOUNT_TYPE_OFFSET: usize = 165;
const TOKEN_2022_ACCOUNT_TYPE_MINT: u8 = 1;
const TOKEN_2022_TLV_START: usize = 166;
const EXT_TRANSFER_FEE_CONFIG: u16 = 1;

/// Active SPL Token-2022 `TransferFeeConfig` schedule for a given cluster epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token2022TransferFee {
    pub bps: u16,
    pub max_fee: u64,
    pub epoch: u64,
}

/// Parse a Token-2022 mint's `TransferFeeConfig` TLV extension (`type = 1`, `>= 108 B`)
/// and select the active fee schedule for `current_epoch` (`newer` if `current_epoch >= newer.epoch`,
/// else `older`). Returns `None` for Classic SPL mints, mints without `TransferFeeConfig`, or `bps == 0`.
pub fn parse_token2022_transfer_fee_config(
    mint_data: &[u8],
    current_epoch: u64,
) -> Option<Token2022TransferFee> {
    if mint_data.len() <= TOKEN_2022_TLV_START
        || mint_data[TOKEN_2022_ACCOUNT_TYPE_OFFSET] != TOKEN_2022_ACCOUNT_TYPE_MINT
    {
        return None;
    }
    let mut pos = TOKEN_2022_TLV_START;
    while pos + 4 <= mint_data.len() {
        let ext_type = u16::from_le_bytes([mint_data[pos], mint_data[pos + 1]]);
        if ext_type == 0 {
            break;
        }
        let ext_len = u16::from_le_bytes([mint_data[pos + 2], mint_data[pos + 3]]) as usize;
        let val_start = pos + 4;
        let val_end = val_start.checked_add(ext_len)?;
        if val_end > mint_data.len() {
            break;
        }
        if ext_type == EXT_TRANSFER_FEE_CONFIG && ext_len >= 108 {
            let older_epoch =
                u64::from_le_bytes(mint_data[val_start + 72..val_start + 80].try_into().ok()?);
            let older_max_fee =
                u64::from_le_bytes(mint_data[val_start + 80..val_start + 88].try_into().ok()?);
            let older_bps =
                u16::from_le_bytes(mint_data[val_start + 88..val_start + 90].try_into().ok()?);

            let newer_epoch =
                u64::from_le_bytes(mint_data[val_start + 90..val_start + 98].try_into().ok()?);
            let newer_max_fee =
                u64::from_le_bytes(mint_data[val_start + 98..val_start + 106].try_into().ok()?);
            let newer_bps =
                u16::from_le_bytes(mint_data[val_start + 106..val_start + 108].try_into().ok()?);

            let active = if current_epoch >= newer_epoch {
                Token2022TransferFee {
                    bps: newer_bps,
                    max_fee: newer_max_fee,
                    epoch: newer_epoch,
                }
            } else {
                Token2022TransferFee {
                    bps: older_bps,
                    max_fee: older_max_fee,
                    epoch: older_epoch,
                }
            };
            return (active.bps > 0).then_some(active);
        }
        pos = val_end;
    }
    None
}

/// Compute exact net received base units after SPL Token-2022 `TransferFee` ceiling deduction,
/// matching `computeToken2022NetAmount` in `@audren/sdk` bit-for-bit.
pub fn compute_token2022_net_amount(gross_amount: u64, fee: Option<Token2022TransferFee>) -> u64 {
    let Some(fee) = fee else {
        return gross_amount;
    };
    if fee.bps == 0 || gross_amount == 0 {
        return gross_amount;
    }
    let raw_fee: u64 = if fee.bps >= 10_000 {
        gross_amount
    } else {
        ((gross_amount as u128) * (fee.bps as u128)).div_ceil(10_000) as u64
    };
    let capped = raw_fee.min(fee.max_fee);
    gross_amount.saturating_sub(capped)
}

/// Compute the exact net input amount that arrives in `escrow_in_ata` after `ExecViaEscrow`
/// transfers `gross_amount_in` from `vault_in_ata` to `escrow_in_ata`, so external DEX router
/// quotes for Token-2022 fee-bearing input mints never exceed available escrow balance.
pub fn compute_exec_router_input_amount(
    gross_amount_in: u64,
    input_mint_data: Option<&[u8]>,
    current_epoch: u64,
) -> u64 {
    let fee = input_mint_data.and_then(|d| parse_token2022_transfer_fee_config(d, current_epoch));
    compute_token2022_net_amount(gross_amount_in, fee)
}

/// Sample an unbiased uniform output lane ID in `0..active_lanes`, independent of input notes.
pub fn pick_random_lane_id(active_lanes: u8) -> Result<u8, ClientError> {
    if active_lanes == 0 || (active_lanes as usize) > NUM_LANES {
        return Err(ClientError::InvalidEncoding("active_lanes out of range"));
    }
    Ok(OsRng.gen_range(0..active_lanes))
}

/// Sample an unbiased uniform `ExecViaEscrow` shard ID in `0..num_shards`, independent of input notes.
pub fn pick_random_escrow_shard(num_shards: u8) -> Result<u8, ClientError> {
    if num_shards == 0 || (num_shards as usize) > NUM_ESCROW_SHARDS {
        return Err(ClientError::InvalidEncoding("num_shards out of range"));
    }
    Ok(OsRng.gen_range(0..num_shards))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_t22_mint_with_transfer_fee(
        older_epoch: u64,
        older_max: u64,
        older_bps: u16,
        newer_epoch: u64,
        newer_max: u64,
        newer_bps: u16,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; 166 + 4 + 108];
        buf[44] = 6;
        buf[45] = 1;
        buf[TOKEN_2022_ACCOUNT_TYPE_OFFSET] = TOKEN_2022_ACCOUNT_TYPE_MINT;
        buf[166..168].copy_from_slice(&EXT_TRANSFER_FEE_CONFIG.to_le_bytes());
        buf[168..170].copy_from_slice(&108u16.to_le_bytes());
        let v = 170;
        buf[v + 72..v + 80].copy_from_slice(&older_epoch.to_le_bytes());
        buf[v + 80..v + 88].copy_from_slice(&older_max.to_le_bytes());
        buf[v + 88..v + 90].copy_from_slice(&older_bps.to_le_bytes());
        buf[v + 90..v + 98].copy_from_slice(&newer_epoch.to_le_bytes());
        buf[v + 98..v + 106].copy_from_slice(&newer_max.to_le_bytes());
        buf[v + 106..v + 108].copy_from_slice(&newer_bps.to_le_bytes());
        buf
    }

    #[test]
    fn token2022_transfer_fee_config_and_exec_router_input_deduction() {
        let mint = make_t22_mint_with_transfer_fee(100, 5_000, 100, 200, 10_000, 250);

        let fee_150 = parse_token2022_transfer_fee_config(&mint, 150);
        assert_eq!(
            fee_150,
            Some(Token2022TransferFee {
                bps: 100,
                max_fee: 5_000,
                epoch: 100,
            })
        );
        // ceil(10_001 * 100 / 10_000) = 101 -> net = 9_900
        assert_eq!(compute_token2022_net_amount(10_001, fee_150), 9_900);
        // capped at max_fee = 5_000 -> net = 995_000
        assert_eq!(compute_token2022_net_amount(1_000_000, fee_150), 995_000);
        assert_eq!(compute_exec_router_input_amount(10_001, Some(&mint), 150), 9_900);

        let fee_200 = parse_token2022_transfer_fee_config(&mint, 200);
        assert_eq!(
            fee_200,
            Some(Token2022TransferFee {
                bps: 250,
                max_fee: 10_000,
                epoch: 200,
            })
        );
        assert_eq!(compute_exec_router_input_amount(100_000, Some(&mint), 200), 97_500);

        // Classic SPL 82-byte mint or None -> unchanged
        let classic = vec![0u8; 82];
        assert_eq!(parse_token2022_transfer_fee_config(&classic, 200), None);
        assert_eq!(compute_exec_router_input_amount(100_000, Some(&classic), 200), 100_000);
        assert_eq!(compute_exec_router_input_amount(100_000, None, 200), 100_000);
    }

    #[test]
    fn random_lane_and_shard_helpers_validate_bounds() {
        for _ in 0..64 {
            assert!(pick_random_lane_id(4).unwrap() < 4);
            assert!(pick_random_escrow_shard(16).unwrap() < 16);
        }
        assert!(pick_random_lane_id(0).is_err());
        assert!(pick_random_lane_id(17).is_err());
        assert!(pick_random_escrow_shard(0).is_err());
        assert!(pick_random_escrow_shard(17).is_err());
    }
}
