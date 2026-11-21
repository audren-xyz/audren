//! Audren Core — shared `#![no_std]` layouts, PDA seeds, proof framing, and error codes.
//!
//! Consumed verbatim by both the sBPFv3 on-chain program (`program/`)
//! and off-chain clients (`crates/client`, TypeScript SDK, relayers) so account layouts,
//! proof byte counts, and domain separators can never drift.

#![no_std]

pub mod instruction;
pub mod layout;

/// A 32-byte Solana address or compressed Ristretto255 curve point.
pub type Bytes32 = [u8; 32];

/// Canonical Audren Mainnet & Devnet Program ID (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`).
pub const AUDREN_PROGRAM_ID: Bytes32 =
    decode_base58("AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3");

/// Current protocol version stored in `PoolState::protocol_version`.
/// Crypto-agile version hook: `1` = Ristretto255 Multi-Base Triptych + Agave Bulletproofs
/// with post-quantum `AES-256-GCM` / NIST `ML-KEM-768` note payload encryption;
/// future versions (`>= 2`) swap the verifier without changing vaults, escrow, or router CPI.
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum number of sharded `swap_escrow` PDAs per pool (prevents write-lock contention).
pub const MAX_ESCROW_SHARDS: u8 = 16;

/// Maximum number of independent concurrent append lanes per logical pool (`0..16`).
/// Lane `0` uses page IDs `0, 1, 2, ...` (`(0 << 56) | seq`, default pool lane).
/// Lanes `1..15` use page IDs `(lane_id << 56) | seq`, allowing lock-free parallel appends with
/// read-only `PoolState`, per-lane `LaneRentVault`, and a unified custody pool + `NullifierPDA` namespace.
pub const MAX_APPEND_LANES: u8 = 16;

/// Mask for the 56-bit per-lane page sequence number inside a `page_id: u64`.
pub const PAGE_SEQ_MASK: u64 = 0x00FF_FFFF_FFFF_FFFF;

/// Extract the append lane (`0..16`) from a `page_id`.
#[inline]
pub const fn lane_of_page_id(page_id: u64) -> u8 {
    (page_id >> 56) as u8
}

/// Extract the 56-bit sequence number within its lane from a `page_id`.
#[inline]
pub const fn seq_of_page_id(page_id: u64) -> u64 {
    page_id & PAGE_SEQ_MASK
}

/// Construct a globally unique `page_id` for `(lane_id, seq)`.
#[inline]
pub const fn page_id_for_lane(lane_id: u8, seq: u64) -> Option<u64> {
    if lane_id >= MAX_APPEND_LANES || seq > PAGE_SEQ_MASK {
        None
    } else {
        Some(((lane_id as u64) << 56) | seq)
    }
}

/// Classic SPL Token program ID.
pub const CLASSIC_TOKEN_PROGRAM_ID: Bytes32 =
    decode_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

/// SPL Token-2022 program ID.
pub const TOKEN_2022_PROGRAM_ID: Bytes32 =
    decode_base58("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

/// Associated Token Account program ID.
pub const ASSOCIATED_TOKEN_PROGRAM_ID: Bytes32 =
    decode_base58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/// System program ID (`11111111111111111111111111111111`).
pub const SYSTEM_PROGRAM_ID: Bytes32 = [0u8; 32];

/// Agave native ZK ElGamal Proof program ID (`ZkE1Gama1Proof11111111111111111111111111111`).
pub const ZK_ELGAMAL_PROOF_PROGRAM_ID: Bytes32 =
    decode_base58("ZkE1Gama1Proof11111111111111111111111111111");

/// Wrapped SOL mint address (used when swapping SOL through external DEX routers).
pub const WSOL_MINT: Bytes32 = decode_base58("So11111111111111111111111111111111111111112");

/// Canonical mint identifier for Native SOL inside Audren note commitments.
pub const NATIVE_SOL_MINT: Bytes32 = [0u8; 32];

/// PDA seed prefixes (all fixed ASCII bytes).
pub const POOL_SEED: &[u8] = b"audren_pool";
pub const PAGE_SEED: &[u8] = b"audren_page";
pub const NULLIFIER_SEED: &[u8] = b"audren_null";
pub const VAULT_AUTH_SEED: &[u8] = b"audren_vault";
pub const SOL_VAULT_SEED: &[u8] = b"audren_sol";
pub const PAGE_RENT_SEED: &[u8] = b"audren_rent";
pub const ESCROW_SEED: &[u8] = b"audren_escrow";
pub const PROOF_BUFFER_SEED: &[u8] = b"audren_buf";
pub const LANE_SEED: &[u8] = b"audren_lane";
pub const LANE_RENT_SEED: &[u8] = b"audren_lrent";

/// Protocol operating mode for a pool.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolMode {
    /// Permissionless full-private pool (`auditor_pk` unset). Users still retain
    /// per-tx selective disclosure (Mode 1) and read-only Full Viewing Keys (Mode 2).
    Permissionless = 0,
    /// Institutional full-private pool with a cryptographically enforced `auditor_pk`.
    /// Public chain sees only commitments/nullifiers; the on-chain Triptych verifier
    /// mathematically enforces verifiable ElGamal encryption of sender, asset, and amount
    /// to `auditor_pk` on every spend.
    InstitutionalAudited = 1,
}

impl PoolMode {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Permissionless),
            1 => Some(Self::InstitutionalAudited),
            _ => None,
        }
    }
}

/// Audren on-chain error codes returned as `ProgramError::Custom(code)`.
/// Codes are permanent once issued and must never be renumbered or reused.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AudrenError {
    InvalidInstruction = 1,
    InvalidAccount = 2,
    InvalidPda = 3,
    InvalidMagic = 4,
    UnsupportedVersion = 5,
    PoolPaused = 6,
    Unauthorized = 7,
    UnsupportedTokenProgram = 8,
    UnsafeMintExtension = 9,
    ZeroAmount = 10,
    PageFull = 11,
    PageNotReady = 12,
    PageEmpty = 13,
    DuplicateOrUnorderedPages = 14,
    WrongPool = 15,
    NullifierAlreadySpent = 16,
    InvalidPoint = 17,
    InvalidScalar = 18,
    InvalidTriptychProof = 19,
    InvalidCrossBaseProof = 20,
    InvalidRangeProof = 21,
    InvalidAuditorProof = 22,
    MissingAuditorKey = 23,
    InvalidEscrowShard = 24,
    InvalidRouterProgram = 25,
    EscrowAuthorityAltered = 26,
    EscrowAccountAltered = 27,
    SlippageExceeded = 28,
    UnexpectedPartialFill = 29,
    ArithmeticOverflow = 30,
    InsufficientPageRent = 31,
    InvalidProofBuffer = 32,
    InvalidLane = 33,
}

impl From<AudrenError> for u32 {
    #[inline]
    fn from(e: AudrenError) -> u32 {
        e as u32
    }
}

/// Compile-time base58 decoder for 32-byte Solana addresses.
pub const fn decode_base58(input: &str) -> Bytes32 {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let bytes = input.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < bytes.len() {
        let mut digit = 0usize;
        let mut found = false;
        while digit < 58 {
            if ALPHABET[digit] == bytes[i] {
                found = true;
                break;
            }
            digit += 1;
        }
        assert!(found, "invalid base58 character");
        let mut carry = digit;
        let mut j = 32;
        while j > 0 {
            j -= 1;
            carry += 58 * (out[j] as usize);
            out[j] = (carry & 0xff) as u8;
            carry >>= 8;
        }
        assert!(carry == 0, "base58 value overflows 32 bytes");
        i += 1;
    }
    out
}
