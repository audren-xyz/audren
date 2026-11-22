//! Audren Rust SDK (`audren-client`).
//!
//! Provides zero-indexer ordinary-RPC state synchronization (`CompactWalletStore`),
//! BN254 Groth16 proving (`AudrenProver`), canonical key hierarchy (`AudrenKeys`,
//! `FullViewingKey`, Mode 1 `SelectiveDisclosureProof`, deterministic `DefiSessionKeypair`),
//! canonical PDA derivation, and builders for all 9 on-chain V2 instructions.

pub mod instructions;
pub mod keys;
pub mod pda;
pub mod prover;
pub mod router;
pub mod scanner;
pub mod store;

use core::fmt;

pub use audren_circuits;
pub use audren_core;

#[derive(Debug)]
pub enum ClientError {
    InvalidEncoding(&'static str),
    InvalidProofInput(&'static str),
    InvalidFieldElement,
    Crypto(&'static str),
    WitnessNotFound(&'static str),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncoding(m) => write!(f, "invalid encoding: {m}"),
            Self::InvalidProofInput(m) => write!(f, "invalid proof input: {m}"),
            Self::InvalidFieldElement => write!(f, "non-canonical BN254 Fr scalar"),
            Self::Crypto(m) => write!(f, "crypto error: {m}"),
            Self::WitnessNotFound(m) => write!(f, "witness not found: {m}"),
        }
    }
}

impl std::error::Error for ClientError {}
