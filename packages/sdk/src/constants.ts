/**
 * Canonical Audren protocol constants matching `crates/audren-core/src/lib.rs`
 * and `layout.rs` byte-for-byte.
 */

/** Canonical Audren Program ID deployed identically on Solana Mainnet and Devnet. */
export const AUDREN_PROGRAM_ID = 'AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3';

export const PROTOCOL_VERSION = 1;
export const MAX_ESCROW_SHARDS = 16;
export const MAX_APPEND_LANES = 16;
export const PAGE_SEQ_MASK = 0x00ff_ffff_ffff_ffffn;

export function laneOfPageId(pageId: bigint): number {
  return Number((pageId >> 56n) & 0xffn);
}

export function seqOfPageId(pageId: bigint): bigint {
  return pageId & PAGE_SEQ_MASK;
}

export function pageIdForLane(laneId: number, seq: bigint): bigint {
  if (!Number.isInteger(laneId) || laneId < 0 || laneId >= MAX_APPEND_LANES) {
    throw new Error(`Invalid laneId: ${laneId}`);
  }
  if (seq < 0n || seq > PAGE_SEQ_MASK) {
    throw new Error(`Invalid lane sequence: ${seq.toString()}`);
  }
  return (BigInt(laneId) << 56n) | seq;
}

export const CLASSIC_TOKEN_PROGRAM_ID = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
export const TOKEN_2022_PROGRAM_ID = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
export const ASSOCIATED_TOKEN_PROGRAM_ID = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
export const SYSTEM_PROGRAM_ID = '11111111111111111111111111111111';
export const ZK_ELGAMAL_PROOF_PROGRAM_ID = 'ZkE1Gama1Proof11111111111111111111111111111';
export const WSOL_MINT = 'So11111111111111111111111111111111111111112';
/** Canonical Native SOL mint identifier (`[0u8; 32]`, base58 `"11111111111111111111111111111111"`). */
export const NATIVE_SOL_MINT = SYSTEM_PROGRAM_ID;

export const POOL_SEED = 'audren_pool';
export const PAGE_SEED = 'audren_page';
export const NULLIFIER_SEED = 'audren_null';
export const VAULT_AUTH_SEED = 'audren_vault';
export const SOL_VAULT_SEED = 'audren_sol';
export const PAGE_RENT_SEED = 'audren_rent';
export const ESCROW_SEED = 'audren_escrow';
export const UNWRAP_SEED = 'audren_unwrap';
export const PROOF_BUFFER_SEED = 'audren_buf';
export const LANE_SEED = 'audren_lane';
export const LANE_RENT_SEED = 'audren_lrent';

export const POOL_MAGIC = 'AUDRNPL1';
export const PAGE_MAGIC = 'AUDRNPG1';
export const SOL_VAULT_MAGIC = 'AUDRNSL1';
export const PAGE_RENT_MAGIC = 'AUDRNRN1';
export const PROOF_BUFFER_MAGIC = 'AUDRNBF1';
export const LANE_MAGIC = 'AUDRNLN1';
export const LANE_STATE_LEN = 64;
export const SENTINEL_ACCOUNT_LEN = 16;
export const PROOF_BUFFER_HEADER_LEN = 48;
export const PROOF_BUFFER_CHUNK_SIZE = 768;
export const PROOF_BUFFER_MAX_CHUNKS = 13;
export const PROOF_BUFFER_MAX_PAYLOAD = PROOF_BUFFER_CHUNK_SIZE * PROOF_BUFFER_MAX_CHUNKS;

export const POOL_STATE_LEN = 192;
/** Solana per-CPI account allocation cap (10 KiB; enforced pre- and post-Direct Mapping SIMD-0460). */
export const MAX_CPI_ACCOUNT_ALLOC = 10_240;
export const PAGE_CAPACITY = 32;
export const NOTE_CT_LEN = 64;
export const PAGE_HEADER_LEN = 64;
export const PAGE_OFF_POOL_ID = 12;

export const PAGE_OFF_VIEW_TAGS = 64;
export const PAGE_OFF_EPHEMERAL_PKS = 96;
export const PAGE_SCAN_OFFSET = 64;
export const PAGE_SCAN_LEN = 1_056;
export const PAGE_SCAN_DATA_SLICE = {
  offset: PAGE_SCAN_OFFSET,
  length: PAGE_SCAN_LEN,
} as const;
export const PAGE_OFF_STEALTH_PKS = 1_120;
export const PAGE_OFF_ASSET_TAGS = 2_144;
export const PAGE_OFF_COMMITMENTS = 3_168;
export const PAGE_OFF_CIPHERTEXTS = 4_192;
export const PAGE_LEN = 6_240;
export const PAGE_ROLLOVER_HEADROOM = 4;

export const NOTE_WIRE_LEN = 193;
export const DYNAMIC_OUTPUT_WIRE_LEN = 129;

export const TAG_INIT_POOL = 0;
export const TAG_OPEN_PAGE = 1;
export const TAG_DEPOSIT = 2;
export const TAG_TRANSFER = 3;
export const TAG_MERGE = 4;
export const TAG_EXEC_VIA_ESCROW = 5;
export const TAG_WITHDRAW = 6;
export const TAG_SET_PAUSED = 7;
export const TAG_WRITE_PROOF_BUFFER = 8;
export const TAG_EXEC_BUFFERED = 9;
export const TAG_CLOSE_PROOF_BUFFER = 10;
export const TAG_INIT_LANE = 11;
export const TAG_OPEN_LANE_PAGE = 12;

export const DEPOSIT_FLAG_NATIVE_SOL = 1 << 0;
export const DEPOSIT_FLAG_FEE_FROM_AMOUNT = 1 << 1;

export const EXEC_FLAG_HAS_CHANGE = 1 << 0;
export const EXEC_FLAG_ALLOW_PARTIAL_REFUND = 1 << 1;
export const EXEC_FLAG_FEE_ON_OUTPUT = 1 << 2;

export const WITHDRAW_FLAG_NATIVE_SOL = 1 << 0;
export const WITHDRAW_FLAG_HAS_CHANGE = 1 << 1;
export const WITHDRAW_FLAG_UNWRAP_WSOL = 1 << 2;

export const TRIPTYCH_M_ONE_PAGE = 5;
export const TRIPTYCH_M_TWO_PAGES = 6;
export const TRIPTYCH_M_FOUR_PAGES = 7;

export const CROSS_BASE_1_LEN = 128;
export const CROSS_BASE_2_LEN = 256;
export const AUDITOR_ASSET_PROOF_LEN = 192;
export const RANGE_U64_PROOF_LEN = 672;
export const RANGE_U128_PROOF_LEN = 736;

export enum PoolMode {
  Permissionless = 0,
  InstitutionalAudited = 1,
}

/**
 * Audren on-chain error codes returned as `ProgramError::Custom(code)`.
 * Matches `audren_core::AudrenError` (`1..=33`) byte-for-byte.
 */
export enum AudrenError {
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
  InvalidTargetProgram = 25,
  EscrowAuthorityAltered = 26,
  EscrowAccountAltered = 27,
  SlippageExceeded = 28,
  UnexpectedPartialFill = 29,
  ArithmeticOverflow = 30,
  InsufficientPageRent = 31,
  InvalidProofBuffer = 32,
  InvalidLane = 33,
}

export const MAX_MERGE_RING_SLOTS = 128;

export function triptychProofLen(m: 5 | 6 | 7, audited: boolean): number {
  const nPages = inputPagesForM(m);
  const base = nPages + (9 + 4 * m) * 32;
  const aud = audited ? (3 + 2 * m) * 32 : 0;
  return base + aud;
}

export function inputPagesForM(m: 5 | 6 | 7): 1 | 2 | 4 {
  if (m === 5) return 1;
  if (m === 6) return 2;
  if (m === 7) return 4;
  throw new RangeError(`Unsupported Triptych m=${String(m)} (expected 5, 6, or 7)`);
}

export function mForInputPages(pages: 1 | 2 | 4): 5 | 6 | 7 {
  if (pages === 1) return TRIPTYCH_M_ONE_PAGE;
  if (pages === 2) return TRIPTYCH_M_TWO_PAGES;
  if (pages === 4) return TRIPTYCH_M_FOUR_PAGES;
  throw new RangeError(`Unsupported input page count ${String(pages)} (expected 1, 2, or 4)`);
}
