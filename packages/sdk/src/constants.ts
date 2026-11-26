/**
 * Canonical Audren v1 constants matching `crates/audren-core` byte-for-byte.
 */

export const AUDREN_PROGRAM_ID = 'AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3';
export const PROTOCOL_VERSION = 1;

export const SYSTEM_PROGRAM_ID = '11111111111111111111111111111111';
export const CLASSIC_TOKEN_PROGRAM_ID = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
export const TOKEN_2022_PROGRAM_ID = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
export const ASSOCIATED_TOKEN_PROGRAM_ID = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
export const ELGAMAL_REGISTRY_PROGRAM_ID = 'regVYJW7tcT8zipN5YiBvHsvR5jXW1uLFxaHSbugABg';
export const WSOL_MINT = 'So11111111111111111111111111111111111111112';

export const NUM_LANES = 16;
export const DEFAULT_INITIAL_LANES = 4;
export const NUM_ESCROW_SHARDS = 16;
export const LANE_DEPTH_4ARY = 18;
export const TOTAL_DEPTH_4ARY = 20;
export const SUBTREE_LEVELS_4ARY = 4;

// GlobalRootHistory dual-ring parameters (10,216 B <= 10,240 B CPI cap)
export const SLOT_RING_LEN = 128;
export const EPOCH_RING_LEN = 89;
export const ROOT_ENTRY_LEN = 40;
export const DEFAULT_ROOT_EPOCH_INTERVAL = 32n;
export const MAX_ROOT_EPOCH_INTERVAL = 256n;
export const ROOT_RING_SLOT = 0;
export const ROOT_RING_EPOCH = 1;

// Canonical tight Compute Unit limits per Audren instruction (calibrated against
// empirical sBPFv3 LiteSVM measurements with ~15-20% worst-case rollover headroom)
export const CU_LIMIT_INIT_POOL = 45_000;
export const CU_LIMIT_INIT_LANE = 75_000;
export const CU_LIMIT_INIT_ROOT_HISTORY = 75_000;
export const CU_LIMIT_OPEN_PAGE = 40_000;
export const CU_LIMIT_DEPOSIT = 75_000;
export const CU_LIMIT_DEPOSIT_HOOK = 140_000;
export const CU_LIMIT_TRANSACT_PRIVATE = 235_000;
export const CU_LIMIT_TRANSACT_FULL_EXIT = 165_000;
export const CU_LIMIT_TRANSACT_WITHDRAW = 255_000;
export const CU_LIMIT_TRANSACT_WITHDRAW_HOOK = 295_000;
export const CU_LIMIT_EXEC_VIA_ESCROW_BASE = 285_000;
export const MAX_TX_CU_LIMIT = 1_400_000;

// Canonical 12 PDA seed prefixes (`audren_*`)
export const POOL_SEED = 'audren_pool';
export const VAULT_AUTH_SEED = 'audren_vault_auth';
export const LANE_SEED = 'audren_lane';
export const LANE_RENT_SEED = 'audren_lane_rent';
export const SUBTREE_SEED = 'audren_subtree';
export const SUBROOT_SEED = 'audren_subroot';
export const MEMO_SEED = 'audren_memo';
export const NF_PAGE_SEED = 'audren_nf_page';
export const NULLIFIER_SEED = 'audren_nf';
export const ROOTS_SEED = 'audren_roots';
export const ESCROW_SEED = 'audren_escrow';
export const UNWRAP_SEED = 'audren_unwrap';

// Instruction discriminators (0x00..=0x08; 9 instructions total)
export const TAG_INIT_POOL = 0x00;
export const TAG_INIT_LANE = 0x01;
export const TAG_OPEN_PAGE = 0x02;
export const TAG_DEPOSIT = 0x03;
export const TAG_INIT_ROOT_HISTORY = 0x04;
export const TAG_TRANSACT = 0x05;
export const TAG_EXEC_VIA_ESCROW = 0x06;
export const TAG_SET_PAUSED = 0x07;
export const TAG_UPDATE_POOL = 0x08;
export const INSTRUCTION_COUNT = 9;

export const GROTH16_PROOF_LEN = 192;
export const VK_ID_DEFAULT = 0;
export const CANONICAL_PK_BYTES = 3_927_280;
export const CANONICAL_PK_SHA256 =
  '2b22603e466c79b6710e01898dc8b458b09a3ee905b25db996f0c59e76187ee4';
export const CANONICAL_WASM_BYTES = 2_440_431;
export const CANONICAL_WASM_SHA256 =
  'b1316246118753e28d68442efb7412ebf20a65d80d4ced5a303705b76e627ab7';

export const OPEN_PAGE_KIND_SUBTREE = 0;
export const OPEN_PAGE_KIND_SUBROOT = 1;
export const OPEN_PAGE_KIND_MEMO = 2;
export const OPEN_PAGE_KIND_NULLIFIER = 3;
export const OPEN_PAGE_DATA_LEN = 22;
export const OPEN_PAGE_WIRE_LEN = 23;
export const OPEN_PAGE_SUBTREE_LOOKAHEAD_SLOT = 230n;
export const OPEN_PAGE_SUBROOT_LOOKAHEAD_SLOT = 280n;
export const OPEN_PAGE_MEMO_LOOKAHEAD_SLOT = 86n;
export const OPEN_PAGE_NF_LOOKAHEAD_SLOT = 540n;

export const DEPOSIT_FLAG_FEE_FROM_AMOUNT = 1 << 2;
export const DEPOSIT_FLAG_NATIVE_SOL = 1 << 3;

export const ASSET_MODE_PRIVATE = 0;
export const ASSET_MODE_PUBLIC = 1;

export const WITHDRAW_FLAG_UNWRAP_WSOL = 1 << 3;
export const EXEC_FLAG_FEE_ON_OUTPUT = 1 << 3;

export const UPDATE_POOL_PARAMS = 0;
export const UPDATE_POOL_PROPOSE_AUTHORITY = 1;
export const UPDATE_POOL_ACCEPT_AUTHORITY = 2;
export const UPDATE_POOL_RENOUNCE_AUTHORITY = 3;

// Canonical `audren/v1/*` domain tags (asset_id, ctx_hash, and ECDH/memo KDFs)
export const ASSET_ID_DOMAIN = 'audren/v1/asset';
export const CTX_DOMAIN_TRANSACT = 'audren/v1/ctx';
export const CTX_DOMAIN_EXEC_VIA_ESCROW = 'audren/v1/exec_ctx';
export const CTX_DOMAIN_ROUTER_ACCOUNTS = 'audren/v1/router_accs';
export const KDF_DOMAIN_VIEW_TAG = 'audren/v1/vt';
export const KDF_DOMAIN_MEMO_KEY = 'audren/v1/key';
export const KDF_DOMAIN_MEMO_NONCE = 'audren/v1/nonce';
export const KDF_DOMAIN_TWEAK = 'audren/v1/tweak';
export const KDF_DOMAIN_BLIND = 'audren/v1/blind';
export const KDF_DOMAIN_DYN_TWEAK = 'audren/v1/dyn_tweak';
export const KDF_DOMAIN_DYN_BLIND = 'audren/v1/dyn_blind';
export const KDF_DOMAIN_DYN_MASK = 'audren/v1/dyn_mask';

// Poseidon domain tags (tag 6 is reserved)
export const DOMAIN_PK = 1n;
export const DOMAIN_STEALTH = 2n;
export const DOMAIN_NOTE = 3n;
export const DOMAIN_NULLIFIER = 4n;
export const DOMAIN_DUMMY_NF = 5n;
export const DOMAIN_PUB_HASH_A = 7n;
export const DOMAIN_PUB_HASH_B = 8n;
export const DOMAIN_PUB_HASH_FINAL = 9n;
export const DOMAIN_NK = 10n;

// Fixed account layouts (all <= 10,240 B)
export const MAX_CPI_ACCOUNT_ALLOC = 10_240;
export const SUBTREE_LEAVES = 256;
export const SUBROOTS_PER_PAGE = 300;
export const MEMO_NOTES_PER_PAGE = 96;
export const MEMO_PLAINTEXT_LEN = 56;
export const MEMO_VERSION_V1 = 1;
export const MEMO_PAYMENT_ID_LEN = 14;
export const MEMO_CT_LEN = 72;
export const MEMO_ENTRY_WIRE_LEN = 106;
export const DYN_MEMO_HEAD_LEN = 34;
export const NF_PREFIX_LEN = 16;
export const NF_PER_PAGE = 600;

export const POOL_MAGIC = 'AUD1PL01';
export const LANE_RENT_MAGIC = 'AUD1RV01';
export const LANE_MAGIC = 'AUD1LN01';
export const SUBTREE_MAGIC = 'AUD1SB01';
export const SUBROOT_MAGIC = 'AUD1SR01';
export const MEMO_MAGIC = 'AUD1MM01';
export const NF_PAGE_MAGIC = 'AUD1NF01';
export const ROOTS_MAGIC = 'AUD1RT01';
export const DYN_MEMO_MAGIC = 'AUD1DYN1';

export const POOL_STATE_LEN = 128;
export const SENTINEL_LEN = 16;
export const LANE_STATE_LEN = 1_824;
export const SUBTREE_PAGE_LEN = 8_256;
export const SUBROOT_PAGE_LEN = 9_664;
export const MEMO_PAGE_LEN = 10_240;
export const NF_PAGE_LEN = 9_664;
export const ROOT_SNAPSHOT_LEN = 672;
export const ROOT_HISTORY_LEN = 10_216;

// Sentinel (LaneRentVault / NullifierPDA) offsets (16 B)
export const SN_OFF_MAGIC = 0;
export const SN_OFF_POOL_ID = 8;
export const SN_OFF_LANE_ID = 12;
export const SN_OFF_BUMP = 13;

// PoolState offsets (128 B)
export const PL_OFF_MAGIC = 0;
export const PL_OFF_VERSION = 8;
export const PL_OFF_BUMP = 9;
export const PL_OFF_PAUSED = 10;
export const PL_OFF_ACTIVE_LANES = 11;
export const PL_OFF_POOL_ID = 12;
export const PL_OFF_ROOT_EPOCH_INTERVAL = 16;
export const PL_OFF_RESERVED_24 = 24;
export const PL_OFF_AUTHORITY = 32;
export const PL_OFF_VAULT_AUTH_BUMP = 64;
export const PL_OFF_NOTE_RENT_FEE = 72;
export const PL_OFF_NF_RENT_FEE = 80;
export const PL_OFF_PENDING_AUTHORITY = 88;

// LaneTreeState offsets (1,824 B)
export const LN_OFF_MAGIC = 0;
export const LN_OFF_VERSION = 8;
export const LN_OFF_LANE_ID = 9;
export const LN_OFF_BUMP = 10;
export const LN_OFF_RENT_BUMP = 11;
export const LN_OFF_POOL_ID = 12;
export const LN_OFF_NEXT_LEAF = 16;
export const LN_OFF_NF_COUNT = 24;
export const LN_OFF_CURRENT_ROOT = 64;
export const LN_OFF_FRONTIER = 96;

// SubtreePage offsets (8,256 B)
export const SB_OFF_MAGIC = 0;
export const SB_OFF_LANE_ID = 8;
export const SB_OFF_BUMP = 9;
export const SB_OFF_COUNT = 10;
export const SB_OFF_POOL_ID = 12;
export const SB_OFF_PAGE_SEQ = 16;
export const SB_OFF_LEAVES = 64;

// SubtreeRootPage offsets (9,664 B)
export const SR_OFF_MAGIC = 0;
export const SR_OFF_LANE_ID = 8;
export const SR_OFF_BUMP = 9;
export const SR_OFF_COUNT = 10;
export const SR_OFF_POOL_ID = 12;
export const SR_OFF_ROOT_PAGE_SEQ = 16;
export const SR_OFF_ROOTS = 64;

// MemoPage offsets (10,240 B; Structure-of-Arrays)
export const MM_OFF_MAGIC = 0;
export const MM_OFF_LANE_ID = 8;
export const MM_OFF_BUMP = 9;
export const MM_OFF_COUNT = 10;
export const MM_OFF_POOL_ID = 12;
export const MM_OFF_PAGE_SEQ = 16;
export const MM_OFF_CREATED_SLOT = 24;
export const MM_OFF_CLOSED_SLOT = 32;
export const MM_OFF_VIEW_TAGS = 64;
export const MM_OFF_EPHEMERAL_PKS = 256;
export const MM_OFF_CIPHERTEXTS = 3_328;
export const MEMO_PAGE_HEADER_LEN = 64;
export const MEMO_PAGE_SCAN_SLICE_LEN = 3_328;

// NullifierPage offsets (9,664 B)
export const NF_OFF_MAGIC = 0;
export const NF_OFF_LANE_ID = 8;
export const NF_OFF_BUMP = 9;
export const NF_OFF_COUNT = 10;
export const NF_OFF_POOL_ID = 12;
export const NF_OFF_PAGE_SEQ = 16;
export const NF_OFF_CREATED_SLOT = 24;
export const NF_OFF_CLOSED_SLOT = 32;
export const NF_OFF_PREFIXES = 64;
export const NF_PAGE_HEADER_LEN = 64;

// GlobalRootHistory offsets (10,216 B <= 10,240 B CPI cap)
export const RT_OFF_MAGIC = 0;
export const RT_OFF_VERSION = 8;
export const RT_OFF_BUMP = 9;
export const RT_OFF_SLOT_CURSOR = 10;
export const RT_OFF_POOL_ID = 12;
export const RT_OFF_EPOCH_CURSOR = 16;
export const RT_OFF_SLOT_COUNT = 18;
export const RT_OFF_EPOCH_COUNT = 20;
export const RT_OFF_SAME_SLOT_BUMPED = 22;
export const RT_OFF_LATEST_SLOT = 24;
export const RT_OFF_STABLE_EPOCH_ID = 32;
export const RT_OFF_STABLE_SLOT = 40;
export const RT_OFF_EPOCH_INTERVAL = 48;
export const RT_OFF_GROUP_ROOTS = 64;
export const RT_OFF_LATEST_SUPER_ROOT = 192;
export const RT_OFF_LATEST_LANE_ROOTS = 224;
export const RT_OFF_LATEST_LANE_COUNTS = 736;
export const RT_OFF_STABLE_SUPER_ROOT = 864;
export const RT_OFF_STABLE_LANE_ROOTS = 896;
export const RT_OFF_STABLE_LANE_COUNTS = 1_408;
export const RT_OFF_SLOT_RING = 1_536;
export const RT_OFF_EPOCH_RING = 6_656;

/** BN254 scalar field modulus r */
export const BN254_FR_MODULUS =
  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

export const ZERO_HASHES_4ARY: readonly bigint[] = [
  0x0000000000000000000000000000000000000000000000000000000000000000n,
  0x0532fd436e19c70e51209694d9c215250937921b8b79060488c1206db73e9946n,
  0x1ea8dbbca1ca3a574b1b871aad1e8bc47571c7e11a99a6fb25f3f19d4bfad32cn,
  0x1b98ec5a992cd3688e655aef8674386f4e84f0a442eaab4840427e359c214dd2n,
  0x0fd83a3939005974d559c13c652a31942ffd61cab9a038e04239af96cafaee14n,
  0x11eb54967ae25ce42205223461cda9dbb1a1811db38b71e404d1fd94c9627777n,
  0x1c682a99981cf10a215d2788721e0ca060ddc0932cbb04c903eee3bd899dcfc0n,
  0x2b3de1ae8e72d64a5cb03934061e3fd03789273f370e32d576ae54b4cbeca719n,
  0x1b64ed0dc55f80f1f3da256b451baf16110fc268311a13fe903f87945b734861n,
  0x06efb4c4a55b0225fd1088d357b2432f422b0593015c57980e373ecef9029c72n,
  0x262138dff44f5352d2d7ec48461c771444a6c00c761a3263735d0a99143a51f1n,
  0x07ea118d86ace14a8eaa26fc18b36fefe7d5f5b00e0eb9ebfd1c88f37131c178n,
  0x0c2a4af81a2cd78159ce2f3d7ee05367fc5b3c3e1becea2a86d1e66dd27ffb7fn,
  0x1a953a710c22f79c369c976fc9981ffdbfe236695297fec65886e645e6fa2884n,
  0x16b0c5e286286eb6c4774ad6292b4f0bdc5b36cb7890b27544268892ae255e0dn,
  0x2dd7186449cc82702fb8f2d7fa86e0095263f8afb521e1976f499e67a0d7cbb8n,
  0x151399c724e17408a7a43cdadba2fc000da9339c56e4d49c6cdee6c4356fbc68n,
  0x1905d56dc6be6157b64b80d21a207b96e862aea4b68f4674ce4c1b7db4a8bc2en,
  0x16d33ae1e54afb1453fc544206899ddf3e1a5bdc7f6d8993550aa6876a380319n,
  0x16e195c570f224cc86219527096fa55516cc9ee1b96764dd263db0884983fdafn,
  0x2c3e3b49a09af14fc186a71ea0a2979f057db3263b82c9e559322432780d5301n,
];

export const AUDREN_ERRORS: Record<number, string> = {
  6000: 'InvalidInstruction',
  6001: 'InvalidPda',
  6002: 'InvalidAccount',
  6003: 'InvalidLane',
  6004: 'SubtreePageFull',
  6005: 'SubtreePageMismatch',
  6006: 'SubrootPageMismatch',
  6007: 'InvalidRootRing',
  6008: 'RootIndexOutOfBounds',
  6009: 'RootHistoryMismatch',
  6010: 'ProofVerificationFailed',
  6011: 'InvalidVkId',
  6012: 'NullifierAlreadyUsed',
  6013: 'PoseidonFailed',
  6014: 'SlippageExceeded',
  6015: 'CustodyInvariantViolated',
  6016: 'Overflow',
  6017: 'InsufficientVaultBalance',
  6018: 'MemoPageFull',
  6019: 'MemoPageMismatch',
  6020: 'InvalidTokenAccount',
  6021: 'ForbiddenRouterAccount',
  6022: 'EscrowNotDrained',
  6023: 'NullifierPageFull',
  6024: 'NullifierPageMismatch',
  6025: 'InvalidEscrowShard',
  6026: 'InvalidFieldElement',
  6027: 'PoolPaused',
  6028: 'Unauthorized',
  6029: 'PageSeqOutOfRange',
  6030: 'InvalidTargetProgram',
  6031: 'EscrowAuthorityAltered',
  6032: 'EscrowAccountAltered',
};

export const WITNESS_INPUT_BYTES = 2_077;
export const WITNESS_OUTPUT_BYTES = 104;
export const WITNESS_TOTAL_BYTES = 4_611;
export const PROVE_OUTPUT_BYTES = 384;
