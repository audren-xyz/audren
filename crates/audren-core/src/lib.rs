//! Audren Core — shared `#![no_std]` constants, PDA seeds, account layouts,
//! instruction framing, Poseidon domain separators, and canonical error codes.
//!
//! Consumed verbatim by the sBPFv3 on-chain program (`program/`), the BN254 Groth16
//! circuit crate (`crates/audren-circuits`), the Rust SDK (`crates/client`), the
//! UniFFI mobile facade (`crates/audren-ffi`), and verified against IDLs, TypeScript,
//! Swift, Kotlin, Relayer, and Web layers by `idl/verify-idl.py`.

#![no_std]

pub mod instruction;
pub mod layout;

/// A 32-byte Solana address, BN254 scalar field element (big-endian), or hash digest.
pub type Bytes32 = [u8; 32];

/// Canonical Audren Mainnet & Devnet Program ID (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`).
pub const AUDREN_PROGRAM_ID: Bytes32 =
    decode_base58("AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3");

/// Protocol version stored in `PoolState.version` (`2` = BN254 Groth16 4-ary Depth-20 global MASP).
pub const PROTOCOL_VERSION: u8 = 2;

/// Maximum number of concurrent append lanes supported by the frozen 4-ary Depth-20 circuit (`0..16`).
/// Pools launch with `DEFAULT_INITIAL_LANES = 4` active lanes and expand monotonically
/// (`4 -> 8 -> 16`) via `InitLane` with zero circuit changes.
pub const NUM_LANES: usize = 16;

/// Recommended initial active lane count at pool creation (`~0.78 SOL` lane bootstrap float).
pub const DEFAULT_INITIAL_LANES: u8 = 4;

/// Maximum number of sharded `swap_escrow` PDAs per pool (`0..16`) for lock-free parallel DeFi CPIs.
pub const NUM_ESCROW_SHARDS: usize = 16;

/// Per-lane 4-ary Merkle tree depth (`4^18 = 68,719,476,736` notes per lane).
pub const LANE_DEPTH_4ARY: usize = 18;

/// Global super-root depth (`18` lane levels + `2` super-root levels = `20`, `4^20` global capacity).
pub const TOTAL_DEPTH_4ARY: usize = 20;

/// Fixed cyclic `RootCheckpoint` ring slots (`256` PDAs permanently — zero unbounded checkpoint growth).
pub const CHECKPOINT_RING_SLOTS: u64 = 256;

/// Classic SPL Token program ID (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`).
pub const CLASSIC_TOKEN_PROGRAM_ID: Bytes32 =
    decode_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

/// SPL Token-2022 program ID (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`).
pub const TOKEN_2022_PROGRAM_ID: Bytes32 =
    decode_base58("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

/// Associated Token Account program ID (`ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`).
pub const ASSOCIATED_TOKEN_PROGRAM_ID: Bytes32 =
    decode_base58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/// System program ID (`11111111111111111111111111111111`).
pub const SYSTEM_PROGRAM_ID: Bytes32 = [0u8; 32];

/// Wrapped SOL mint address (`So11111111111111111111111111111111111111112`).
pub const WSOL_MINT: Bytes32 = decode_base58("So11111111111111111111111111111111111111112");

/// Canonical 32-byte mint identifier for Native SOL inside Audren note commitments & memos.
pub const NATIVE_SOL_MINT: Bytes32 = [0u8; 32];

/// Canonical PDA seed prefixes on `AUDREN_PROGRAM_ID`.
pub const POOL_SEED: &[u8] = b"audren_v2_pool";
pub const LANE_SEED: &[u8] = b"audren_v2_lane";
pub const LANE_RENT_SEED: &[u8] = b"audren_v2_lrent";
pub const SUBTREE_SEED: &[u8] = b"audren_v2_sub";
pub const SUBROOT_SEED: &[u8] = b"audren_v2_sroot";
pub const MEMO_SEED: &[u8] = b"audren_v2_memo";
pub const NF_PAGE_SEED: &[u8] = b"audren_v2_nfpage";
pub const CKPT_SEED: &[u8] = b"audren_v2_ckpt";
pub const NULLIFIER_SEED: &[u8] = b"audren_v2_null";
pub const SOL_VAULT_SEED: &[u8] = b"audren_v2_sol";
pub const VAULT_AUTH_SEED: &[u8] = b"audren_v2_vault";
pub const ESCROW_SEED: &[u8] = b"audren_v2_escrow";
pub const UNWRAP_SEED: &[u8] = b"audren_v2_unwrap";

/// Canonical BN254 Poseidon domain separation tags (shared across circuit, on-chain, and all 4 SDKs).
pub const DOMAIN_PK: u64 = 1;
pub const DOMAIN_STEALTH: u64 = 2;
pub const DOMAIN_NOTE: u64 = 3;
pub const DOMAIN_NULLIFIER: u64 = 4;
pub const DOMAIN_DUMMY_NF: u64 = 5;
/// Reserved domain tag (never reused; dynamic swap outputs use user-supplied ECDH `out_blinding`).
pub const DOMAIN_DYN_BLIND: u64 = 6;
pub const DOMAIN_PUB_HASH_A: u64 = 7;
pub const DOMAIN_PUB_HASH_B: u64 = 8;
pub const DOMAIN_PUB_HASH_FINAL: u64 = 9;
pub const DOMAIN_NK: u64 = 10;

/// Canonical BN254 scalar field modulus `r` (big-endian):
/// `21888242871839275222246405745257275088548364400416034343698204186575808495617`.
pub const BN254_FR_MODULUS_BE: Bytes32 = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Precomputed 4-ary Poseidon4 zero-subtree hashes (`ZERO_HASHES_4ARY[0] = 0`,
/// `ZERO_HASHES_4ARY[h + 1] = Poseidon4(Z[h], Z[h], Z[h], Z[h])`) for depths `0..=20`.
pub const ZERO_HASHES_4ARY: [Bytes32; TOTAL_DEPTH_4ARY + 1] = [
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [5, 50, 253, 67, 110, 25, 199, 14, 81, 32, 150, 148, 217, 194, 21, 37, 9, 55, 146, 27, 139, 121, 6, 4, 136, 193, 32, 109, 183, 62, 153, 70],
    [30, 168, 219, 188, 161, 202, 58, 87, 75, 27, 135, 26, 173, 30, 139, 196, 117, 113, 199, 225, 26, 153, 166, 251, 37, 243, 241, 157, 75, 250, 211, 44],
    [27, 152, 236, 90, 153, 44, 211, 104, 142, 101, 90, 239, 134, 116, 56, 111, 78, 132, 240, 164, 66, 234, 171, 72, 64, 66, 126, 53, 156, 33, 77, 210],
    [15, 216, 58, 57, 57, 0, 89, 116, 213, 89, 193, 60, 101, 42, 49, 148, 47, 253, 97, 202, 185, 160, 56, 224, 66, 57, 175, 150, 202, 250, 238, 20],
    [17, 235, 84, 150, 122, 226, 92, 228, 34, 5, 34, 52, 97, 205, 169, 219, 177, 161, 129, 29, 179, 139, 113, 228, 4, 209, 253, 148, 201, 98, 119, 119],
    [28, 104, 42, 153, 152, 28, 241, 10, 33, 93, 39, 136, 114, 30, 12, 160, 96, 221, 192, 147, 44, 187, 4, 201, 3, 238, 227, 189, 137, 157, 207, 192],
    [43, 61, 225, 174, 142, 114, 214, 74, 92, 176, 57, 52, 6, 30, 63, 208, 55, 137, 39, 63, 55, 14, 50, 213, 118, 174, 84, 180, 203, 236, 167, 25],
    [27, 100, 237, 13, 197, 95, 128, 241, 243, 218, 37, 107, 69, 27, 175, 22, 17, 15, 194, 104, 49, 26, 19, 254, 144, 63, 135, 148, 91, 115, 72, 97],
    [6, 239, 180, 196, 165, 91, 2, 37, 253, 16, 136, 211, 87, 178, 67, 47, 66, 43, 5, 147, 1, 92, 87, 152, 14, 55, 62, 206, 249, 2, 156, 114],
    [38, 33, 56, 223, 244, 79, 83, 82, 210, 215, 236, 72, 70, 28, 119, 20, 68, 166, 192, 12, 118, 26, 50, 99, 115, 93, 10, 153, 20, 58, 81, 241],
    [7, 234, 17, 141, 134, 172, 225, 74, 142, 170, 38, 252, 24, 179, 111, 239, 231, 213, 245, 176, 14, 14, 185, 235, 253, 28, 136, 243, 113, 49, 193, 120],
    [12, 42, 74, 248, 26, 44, 215, 129, 89, 206, 47, 61, 126, 224, 83, 103, 252, 91, 60, 62, 27, 236, 234, 42, 134, 209, 230, 109, 210, 127, 251, 127],
    [26, 149, 58, 113, 12, 34, 247, 156, 54, 156, 151, 111, 201, 152, 31, 253, 191, 226, 54, 105, 82, 151, 254, 198, 88, 134, 230, 69, 230, 250, 40, 132],
    [22, 176, 197, 226, 134, 40, 110, 182, 196, 119, 74, 214, 41, 43, 79, 11, 220, 91, 54, 203, 120, 144, 178, 117, 68, 38, 136, 146, 174, 37, 94, 13],
    [45, 215, 24, 100, 73, 204, 130, 112, 47, 184, 242, 215, 250, 134, 224, 9, 82, 99, 248, 175, 181, 33, 225, 151, 111, 73, 158, 103, 160, 215, 203, 184],
    [21, 19, 153, 199, 36, 225, 116, 8, 167, 164, 60, 218, 219, 162, 252, 0, 13, 169, 51, 156, 86, 228, 212, 156, 108, 222, 230, 196, 53, 111, 188, 104],
    [25, 5, 213, 109, 198, 190, 97, 87, 182, 75, 128, 210, 26, 32, 123, 150, 232, 98, 174, 164, 182, 143, 70, 116, 206, 76, 27, 125, 180, 168, 188, 46],
    [22, 211, 58, 225, 229, 74, 251, 20, 83, 252, 84, 66, 6, 137, 157, 223, 62, 26, 91, 220, 127, 109, 137, 147, 85, 10, 166, 135, 106, 56, 3, 25],
    [22, 225, 149, 197, 112, 242, 36, 204, 134, 33, 149, 39, 9, 111, 165, 85, 22, 204, 158, 225, 185, 103, 100, 221, 38, 61, 176, 136, 73, 131, 253, 175],
    [44, 62, 59, 73, 160, 154, 241, 79, 193, 134, 167, 30, 160, 162, 151, 159, 5, 125, 179, 38, 59, 130, 201, 229, 89, 50, 36, 50, 120, 13, 83, 1],
];

/// Pool governance / privacy mode stored in `PoolState.mode`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolMode {
    /// Permissionless privacy pool (`vk_id = 0` minimal Groth16 circuit).
    Permissionless = 0,
    /// Reserved for opt-in institutional audited pools (`vk_id = 1`).
    InstitutionalAudited = 1,
}

/// Custom on-chain error codes returned via `ProgramError::Custom(code)` (`6000..=6032`).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AudrenError {
    InvalidInstruction = 6000,
    InvalidPda = 6001,
    InvalidAccount = 6002,
    InvalidLane = 6003,
    SubtreePageFull = 6004,
    SubtreePageMismatch = 6005,
    SubrootPageMismatch = 6006,
    CheckpointTooSoon = 6007,
    CheckpointExpired = 6008,
    CheckpointMismatch = 6009,
    ProofVerificationFailed = 6010,
    InvalidVkId = 6011,
    NullifierAlreadyUsed = 6012,
    PoseidonFailed = 6013,
    SlippageExceeded = 6014,
    CustodyInvariantViolated = 6015,
    Overflow = 6016,
    InsufficientVaultBalance = 6017,
    MemoPageFull = 6018,
    MemoPageMismatch = 6019,
    InvalidTokenAccount = 6020,
    ForbiddenRouterAccount = 6021,
    EscrowNotDrained = 6022,
    NullifierPageFull = 6023,
    NullifierPageMismatch = 6024,
    InvalidEscrowShard = 6025,
    InvalidFieldElement = 6026,
    PoolPaused = 6027,
    Unauthorized = 6028,
    PageSeqOutOfRange = 6029,
    InvalidTargetProgram = 6030,
    EscrowAuthorityAltered = 6031,
    EscrowAccountAltered = 6032,
}

/// Check whether a 32-byte big-endian integer is strictly `< BN254 Fr modulus`.
#[inline(always)]
pub fn is_canonical_fr(bytes: &Bytes32) -> bool {
    let mut i = 0;
    while i < 32 {
        if bytes[i] < BN254_FR_MODULUS_BE[i] {
            return true;
        }
        if bytes[i] > BN254_FR_MODULUS_BE[i] {
            return false;
        }
        i += 1;
    }
    false
}

/// Mask top 3 bits of a 32-byte digest so it is guaranteed `< BN254 Fr modulus`.
#[inline(always)]
pub const fn mask_to_fr_be(mut bytes: Bytes32) -> Bytes32 {
    bytes[0] &= 0x1F;
    bytes
}

/// Encode a `u64` into a 32-byte big-endian BN254 field element.
#[inline(always)]
pub const fn u64_to_be32(v: u64) -> Bytes32 {
    let b = v.to_be_bytes();
    let mut out = [0u8; 32];
    out[24] = b[0];
    out[25] = b[1];
    out[26] = b[2];
    out[27] = b[3];
    out[28] = b[4];
    out[29] = b[5];
    out[30] = b[6];
    out[31] = b[7];
    out
}

/// Injectively pack `(public_amount_out, relayer_fee_amount)` into one 32-byte BE BN254 Fr:
/// `packed = public_amount_out + relayer_fee_amount * 2^64`.
#[inline(always)]
pub const fn pack_u64_pair_be32(public_amount_out: u64, relayer_fee_amount: u64) -> Bytes32 {
    let f = relayer_fee_amount.to_be_bytes();
    let a = public_amount_out.to_be_bytes();
    let mut out = [0u8; 32];
    out[16] = f[0];
    out[17] = f[1];
    out[18] = f[2];
    out[19] = f[3];
    out[20] = f[4];
    out[21] = f[5];
    out[22] = f[6];
    out[23] = f[7];
    out[24] = a[0];
    out[25] = a[1];
    out[26] = a[2];
    out[27] = a[3];
    out[28] = a[4];
    out[29] = a[5];
    out[30] = a[6];
    out[31] = a[7];
    out
}

/// Compile-time Base58 decoder for 32-byte Solana addresses (zero runtime overhead).
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
