//! Audren Rust Client SDK.
//!
//! End-to-end client library for the Audren shielded multi-asset protocol on Solana:
//! - Deterministic stealth key hierarchy, `FullViewingKey` (Mode 2), `SelectiveDisclosureProof` (Mode 1),
//!   and `AuditorKeypair` (`PoolMode::InstitutionalAudited`)
//! - Multi-Base Binary Triptych (`N = 32 / 64 / 128`), Auditor Asset Encryption, Cross-Base 1/2,
//!   and Native Agave Batched Bulletproof provers
//! - Zero-indexer pure Solana RPC `getMultipleAccounts` (`dataSlice`) & WS `programSubscribe` scanner
//! - Router-agnostic 1-tx private swap builder (Jupiter, Orca, Raydium, Meteora, Phoenix, or any DEX router)

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
