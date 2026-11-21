//! Audren Rust Client SDK.
//!
//! Client library for private multi-asset settlement, protocol-agnostic shielded DeFi execution
//! (`ExecViaEscrow`), self-paying withdrawals (`Withdraw` + `unwrap_wsol`), deterministic DeFi
//! session wallets, and selective disclosure / institutional auditability on Solana:
//! - Deterministic stealth key hierarchy, `DefiSessionKeypair`, `FullViewingKey` (Mode 2),
//!   `SelectiveDisclosureProof` (Mode 1), and `AuditorKeypair` (`PoolMode::InstitutionalAudited`)
//! - Multi-Base Binary Triptych (`N = 32 / 64 / 128`), Auditor Asset Encryption, Cross-Base 1/2,
//!   and native Agave Batched Bulletproof provers
//! - Protocol-agnostic 1-tx `ExecViaEscrow` builder for compatible PDA-signing Solana programs
//!   (DEX swaps, supply lending, vaults, liquid staking, perp LP, RWA mint/redeem)
//! - Standard Solana RPC `getMultipleAccounts` (`dataSlice`) and WS `programSubscribe` scanner

pub mod instructions;
pub mod keys;
pub mod pda;
pub mod prover;
pub mod router;
pub mod scanner;

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    InvalidPoint,
    InvalidEncoding(&'static str),
    InvalidProofInput(&'static str),
    Crypto(&'static str),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPoint => write!(f, "invalid ristretto255 point"),
            Self::InvalidEncoding(msg) => write!(f, "invalid encoding: {msg}"),
            Self::InvalidProofInput(msg) => write!(f, "invalid proof input: {msg}"),
            Self::Crypto(msg) => write!(f, "cryptographic error: {msg}"),
        }
    }
}

impl std::error::Error for ClientError {}
