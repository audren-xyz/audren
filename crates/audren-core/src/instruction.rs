//! Audren instruction tags (`0x00..=0x08`), flags, modes, and wire lengths.
//!
//! Single source of truth consumed by `program/`, `crates/client`, `crates/audren-ffi`,
//! `idl/generate-idl.py`, `idl/verify-idl.py`, `packages/sdk`, `apps/relay`, and `apps/web`.

/// 1-byte instruction discriminators (`0x00..=0x08`, 9 instructions total).
pub const TAG_INIT_POOL: u8 = 0x00;
pub const TAG_INIT_LANE: u8 = 0x01;
pub const TAG_OPEN_PAGE: u8 = 0x02;
pub const TAG_DEPOSIT_SOL: u8 = 0x03;
pub const TAG_DEPOSIT_SPL: u8 = 0x04;
pub const TAG_PUBLISH_CHECKPOINT: u8 = 0x05;
pub const TAG_JOINSPLIT: u8 = 0x06;
pub const TAG_EXEC_VIA_ESCROW: u8 = 0x07;
pub const TAG_SET_PAUSED: u8 = 0x08;

/// Total number of on-chain instructions.
pub const INSTRUCTION_COUNT: usize = 9;

/// Compressed BN254 Groth16 proof length: `(-A)_compressed[32] || B_be[128] || C_compressed[32]`.
pub const GROTH16_PROOF_LEN: usize = 192;

/// Default permissionless verifying key identifier (`JoinSplit4AryCircuit`, `DEPTH = 20`, `17,861` R1CS).
pub const VK_ID_DEFAULT: u8 = 0;

/// Page kinds accepted by `OpenPage` (`TAG_OPEN_PAGE`).
pub const OPEN_PAGE_KIND_SUBTREE: u8 = 0;
pub const OPEN_PAGE_KIND_SUBROOT: u8 = 1;
pub const OPEN_PAGE_KIND_MEMO: u8 = 2;
pub const OPEN_PAGE_KIND_NULLIFIER: u8 = 3;

/// `JoinSplit` (`TAG_JOINSPLIT`) asset outflow modes (`data[8] & 0x07`).
pub const ASSET_MODE_PRIVATE: u8 = 0;
pub const ASSET_MODE_SOL: u8 = 1;
pub const ASSET_MODE_SPL: u8 = 2;

/// `DepositSol` (`TAG_DEPOSIT_SOL`) flag in `data[5]`: deduct deterministic per-note
/// `LaneRentVault` fee from `amount` so callers can sweep wallets cleanly to exact `0` lamports.
pub const DEPOSIT_FLAG_FEE_FROM_AMOUNT: u8 = 1 << 2;

/// `JoinSplit` (`TAG_JOINSPLIT`) flag in `data[8]`: when `ASSET_MODE_SPL` with `mint == WSOL_MINT`
/// under Classic SPL Token, unwrap `public_amount_out` (and optional public `relayer_fee_amount`)
/// atomically through a 1-shot `audren_v2_unwrap` PDA into Native SOL (`output_mask == 0` bypasses pause).
pub const WITHDRAW_FLAG_UNWRAP_WSOL: u8 = 1 << 3;

/// `ExecViaEscrow` (`TAG_EXEC_VIA_ESCROW`) leg asset kinds.
pub const EXEC_KIND_SOL: u8 = 0;
pub const EXEC_KIND_SPL: u8 = 1;

/// `ExecViaEscrow` (`TAG_EXEC_VIA_ESCROW`) flag in `data[10]`: pay `relayer_fee_amount` out of
/// `asset_out` directly from escrow before sweeping remaining net user proceeds into `vault_out`.
pub const EXEC_FLAG_FEE_ON_OUTPUT: u8 = 1 << 3;

/// Domain tags for canonical `asset_id` and `ctx_hash` SHA-256 transcripts (bound inside `pub_hash`).
pub const ASSET_ID_DOMAIN: &[u8] = b"audren/v2/asset";
pub const CTX_DOMAIN_JOINSPLIT: &[u8] = b"audren/v2/joinsplit";
pub const CTX_DOMAIN_EXEC_VIA_ESCROW: &[u8] = b"audren/v2/exec_via_escrow";
pub const CTX_DOMAIN_ROUTER_ACCOUNTS: &[u8] = b"audren/v2/router_accs";
