//! Audren instruction tags (`0x00..=0x08`), flags, modes, domain separators, and wire lengths.
//!
//! Single source of truth consumed by `program/`, `crates/client`, `crates/audren-ffi`,
//! `idl/generate-idl.py`, `idl/verify-idl.py`, `packages/sdk`, `apps/relay`, and `apps/web`.

/// 1-byte instruction discriminators (`0x00..=0x08`, 9 instructions total).
pub const TAG_INIT_POOL: u8 = 0x00;
pub const TAG_INIT_LANE: u8 = 0x01;
pub const TAG_OPEN_PAGE: u8 = 0x02;
pub const TAG_DEPOSIT: u8 = 0x03;
pub const TAG_INIT_ROOT_HISTORY: u8 = 0x04;
pub const TAG_TRANSACT: u8 = 0x05;
pub const TAG_EXEC_VIA_ESCROW: u8 = 0x06;
pub const TAG_SET_PAUSED: u8 = 0x07;
pub const TAG_UPDATE_POOL: u8 = 0x08;

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

/// `OpenPage` (`TAG_OPEN_PAGE`) body length after the 1-byte tag (`22 B`; total wire length `23 B`):
/// `page_kind(1) || pool_id(4) || lane_id(1) || page_seq(8) || max_payer_deficit(8)`.
pub const OPEN_PAGE_DATA_LEN: usize = 22;
pub const OPEN_PAGE_WIRE_LEN: usize = 1 + OPEN_PAGE_DATA_LEN;

/// Minimum current-page occupancy slot required before `OpenPage` permits pre-opening `cur_seq + 1`
/// (`>= 90%` full across all four page types; `cur_seq + 2` is unconditionally rejected).
pub const OPEN_PAGE_SUBTREE_LOOKAHEAD_SLOT: u64 = 230;
pub const OPEN_PAGE_SUBROOT_LOOKAHEAD_SLOT: u64 = 280;
pub const OPEN_PAGE_MEMO_LOOKAHEAD_SLOT: u64 = 86;
pub const OPEN_PAGE_NF_LOOKAHEAD_SLOT: u64 = 540;

/// `Deposit` (`TAG_DEPOSIT`) flag in `data[5]`: deduct deterministic per-note `LaneRentVault` fee
/// from `amount` (valid only when `DEPOSIT_FLAG_NATIVE_SOL` is set) for exact zero-dust SOL sweeps.
pub const DEPOSIT_FLAG_FEE_FROM_AMOUNT: u8 = 1 << 2;

/// `Deposit` (`TAG_DEPOSIT`) flag in `data[5]`: deposit Native SOL by transferring lamports to
/// the canonical WSOL `vault_ata` and invoking Classic SPL `SyncNative` atomically.
pub const DEPOSIT_FLAG_NATIVE_SOL: u8 = 1 << 3;

/// `Transact` (`TAG_TRANSACT`) asset outflow modes (`data[7]`).
pub const ASSET_MODE_PRIVATE: u8 = 0;
pub const ASSET_MODE_PUBLIC: u8 = 1;

/// `Transact` (`TAG_TRANSACT`) flag in `data[8]`: when `ASSET_MODE_PUBLIC` with `mint == WSOL_MINT`
/// under Classic SPL Token, unwrap `public_amount_out` (and optional public `relayer_fee_amount`)
/// atomically through a 1-shot `audren_unwrap` PDA into Native SOL (`output_mask == 0` bypasses pause).
pub const WITHDRAW_FLAG_UNWRAP_WSOL: u8 = 1 << 3;

/// `ExecViaEscrow` (`TAG_EXEC_VIA_ESCROW`) flag in `data[8]`: pay `relayer_fee_amount` out of
/// `asset_out` directly from escrow before sweeping remaining net user proceeds into `vault_out`.
pub const EXEC_FLAG_FEE_ON_OUTPUT: u8 = 1 << 3;

/// `UpdatePool` (`TAG_UPDATE_POOL`) sub-actions (`data[4]`).
pub const UPDATE_POOL_PARAMS: u8 = 0;
pub const UPDATE_POOL_PROPOSE_AUTHORITY: u8 = 1;
pub const UPDATE_POOL_ACCEPT_AUTHORITY: u8 = 2;
pub const UPDATE_POOL_RENOUNCE_AUTHORITY: u8 = 3;

/// Canonical `audren/v1/*` domain tags for `asset_id`, `ctx_hash`, and ECDH/HKDF memo KDFs.
pub const ASSET_ID_DOMAIN: &[u8] = b"audren/v1/asset";
pub const CTX_DOMAIN_TRANSACT: &[u8] = b"audren/v1/ctx";
pub const CTX_DOMAIN_EXEC_VIA_ESCROW: &[u8] = b"audren/v1/exec_ctx";
pub const CTX_DOMAIN_ROUTER_ACCOUNTS: &[u8] = b"audren/v1/router_accs";
pub const KDF_DOMAIN_VIEW_TAG: &[u8] = b"audren/v1/vt";
pub const KDF_DOMAIN_MEMO_KEY: &[u8] = b"audren/v1/key";
pub const KDF_DOMAIN_MEMO_NONCE: &[u8] = b"audren/v1/nonce";
pub const KDF_DOMAIN_TWEAK: &[u8] = b"audren/v1/tweak";
pub const KDF_DOMAIN_BLIND: &[u8] = b"audren/v1/blind";
pub const KDF_DOMAIN_DYN_TWEAK: &[u8] = b"audren/v1/dyn_tweak";
pub const KDF_DOMAIN_DYN_BLIND: &[u8] = b"audren/v1/dyn_blind";
pub const KDF_DOMAIN_DYN_MASK: &[u8] = b"audren/v1/dyn_mask";
