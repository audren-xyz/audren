//! Aggregator & Relayer interoperability constants synced across Rust, TS, Relayer, and Web.

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
