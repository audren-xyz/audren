import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_PUBLIC,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  AUDREN_ANCHOR_IDL,
  AUDREN_CODAMA_IDL,
  AUDREN_ERRORS,
  AUDREN_PROGRAM_ID,
  AUTO_OPEN_MEMO_REM_THRESHOLD,
  AUTO_OPEN_NF_REM_THRESHOLD,
  AUTO_OPEN_SUBROOT_SLOT_THRESHOLD,
  AUTO_OPEN_SUBTREE_REM_THRESHOLD,
  AudrenRelayClient,
  BN254_FR_MODULUS,
  CLASSIC_TOKEN_PROGRAM_ID,
  CU_LIMIT_DEPOSIT,
  CU_LIMIT_DEPOSIT_HOOK,
  CU_LIMIT_EXEC_VIA_ESCROW_BASE,
  CU_LIMIT_INIT_LANE,
  CU_LIMIT_INIT_POOL,
  CU_LIMIT_INIT_ROOT_HISTORY,
  CU_LIMIT_OPEN_PAGE,
  CU_LIMIT_TRANSACT_FULL_EXIT,
  CU_LIMIT_TRANSACT_PRIVATE,
  CU_LIMIT_TRANSACT_WITHDRAW,
  CU_LIMIT_TRANSACT_WITHDRAW_HOOK,
  CompactWalletStore,
  DEFAULT_ROOT_EPOCH_INTERVAL,
  DEPOSIT_FLAG_FEE_FROM_AMOUNT,
  DEPOSIT_FLAG_NATIVE_SOL,
  DYN_MEMO_HEAD_LEN,
  DYN_MEMO_MAGIC,
  EPOCH_RING_LEN,
  GROTH16_PROOF_LEN,
  JUPITER_CPI_EXCLUDED_DEXES,
  LANE_MAGIC,
  LANE_STATE_LEN,
  LN_OFF_CURRENT_ROOT,
  LN_OFF_LANE_ID,
  LN_OFF_MAGIC,
  LN_OFF_NEXT_LEAF,
  LN_OFF_NF_COUNT,
  LN_OFF_VERSION,
  MAX_HRW_SEALED_SUBTREES,
  MAX_LEAVES_PER_LANE,
  MAX_ROOT_EPOCH_INTERVAL,
  MEMO_CT_LEN,
  MEMO_ENTRY_WIRE_LEN,
  MEMO_MAGIC,
  MEMO_NOTES_PER_PAGE,
  MEMO_PAGE_HEADER_LEN,
  MEMO_PAGE_LEN,
  MEMO_PAGE_SCAN_SLICE_LEN,
  MEMO_PAYMENT_ID_LEN,
  MEMO_VERSION_V1,
  MM_OFF_CIPHERTEXTS,
  MM_OFF_CLOSED_SLOT,
  MM_OFF_COUNT,
  MM_OFF_EPHEMERAL_PKS,
  MM_OFF_LANE_ID,
  MM_OFF_MAGIC,
  MM_OFF_PAGE_SEQ,
  MM_OFF_POOL_ID,
  MM_OFF_VIEW_TAGS,
  NF_OFF_CLOSED_SLOT,
  NF_OFF_COUNT,
  NF_OFF_LANE_ID,
  NF_OFF_MAGIC,
  NF_OFF_PAGE_SEQ,
  NF_OFF_POOL_ID,
  NF_OFF_PREFIXES,
  NF_PAGE_HEADER_LEN,
  NF_PAGE_LEN,
  NF_PAGE_MAGIC,
  NF_PER_PAGE,
  NF_PREFIX_LEN,
  NUM_ESCROW_SHARDS,
  NUM_LANES,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_NULLIFIER,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  PL_OFF_ACTIVE_LANES,
  PL_OFF_MAGIC,
  PL_OFF_VERSION,
  POOL_MAGIC,
  POOL_STATE_LEN,
  PROTOCOL_VERSION,
  PROVE_OUTPUT_BYTES,
  ROOTS_MAGIC,
  ROOT_ENTRY_LEN,
  ROOT_HISTORY_LEN,
  ROOT_RING_EPOCH,
  ROOT_RING_SLOT,
  ROOT_SNAPSHOT_LEN,
  RT_OFF_BUMP,
  RT_OFF_EPOCH_COUNT,
  RT_OFF_EPOCH_CURSOR,
  RT_OFF_EPOCH_INTERVAL,
  RT_OFF_EPOCH_RING,
  RT_OFF_GROUP_ROOTS,
  RT_OFF_LATEST_LANE_COUNTS,
  RT_OFF_LATEST_LANE_ROOTS,
  RT_OFF_LATEST_SLOT,
  RT_OFF_LATEST_SUPER_ROOT,
  RT_OFF_MAGIC,
  RT_OFF_POOL_ID,
  RT_OFF_SAME_SLOT_BUMPED,
  RT_OFF_SLOT_COUNT,
  RT_OFF_SLOT_CURSOR,
  RT_OFF_SLOT_RING,
  RT_OFF_STABLE_EPOCH_ID,
  RT_OFF_STABLE_LANE_COUNTS,
  RT_OFF_STABLE_LANE_ROOTS,
  RT_OFF_STABLE_SLOT,
  RT_OFF_STABLE_SUPER_ROOT,
  RT_OFF_VERSION,
  SB_OFF_COUNT,
  SB_OFF_LANE_ID,
  SB_OFF_LEAVES,
  SB_OFF_MAGIC,
  SB_OFF_PAGE_SEQ,
  SB_OFF_POOL_ID,
  SLOT_RING_LEN,
  SR_OFF_COUNT,
  SR_OFF_LANE_ID,
  SR_OFF_MAGIC,
  SR_OFF_POOL_ID,
  SR_OFF_ROOTS,
  SR_OFF_ROOT_PAGE_SEQ,
  SUBROOTS_PER_PAGE,
  SUBROOT_MAGIC,
  SUBROOT_PAGE_LEN,
  SUBTREE_LEAVES,
  SUBTREE_MAGIC,
  SUBTREE_PAGE_LEN,
  SYSTEM_PROGRAM_ID,
  TAG_DEPOSIT,
  TAG_EXEC_VIA_ESCROW,
  TAG_INIT_LANE,
  TAG_INIT_POOL,
  TAG_INIT_ROOT_HISTORY,
  TAG_OPEN_PAGE,
  TAG_SET_PAUSED,
  TAG_TRANSACT,
  TAG_UPDATE_POOL,
  TOKEN_2022_PROGRAM_ID,
  UPDATE_POOL_ACCEPT_AUTHORITY,
  UPDATE_POOL_PARAMS,
  UPDATE_POOL_PROPOSE_AUTHORITY,
  UPDATE_POOL_RENOUNCE_AUTHORITY,
  WITHDRAW_FLAG_UNWRAP_WSOL,
  WITNESS_TOTAL_BYTES,
  WSOL_MINT,
  ZERO_HASHES_4ARY,
  base58Decode,
  base58Encode,
  buildAutoOpenPageInstructions,
  buildCreateAtaIdempotentInstruction,
  buildDepositInstruction,
  buildExecViaEscrowInstruction,
  buildInitLaneInstruction,
  buildInitPoolInstruction,
  buildInitRootHistoryInstruction,
  buildOpenPageInstruction,
  buildSetPausedInstruction,
  buildTransactInstruction,
  buildUpdatePoolInstruction,
  buildUpdatePoolParamsInstruction,
  bytesToBigIntBe,
  chacha20Poly1305Decrypt,
  chacha20Poly1305Encrypt,
  checkMemoViewTag,
  compileV1Message,
  computeBumpCuMargin,
  computeExecCtxHash,
  computeMerkleRoot4Ary,
  computeNoteCommitment,
  computePageRollovers,
  computeSubtree256Root,
  computeSuperRoot4Ary,
  computeToken2022NetAmount,
  computeTransactCtxHash,
  decodeEpochRingEntry,
  createSolanaRpcBatchFetcher,
  decodeGlobalRootHistory,
  decodeLaneHeader,
  decodeMemoPage,
  decodeMemoPageHeader,
  decodeMemoPageScanSlice,
  decodeNullifierPage,
  decodeNullifierPageHeader,
  decodePoolState,
  decodeSlotRingEntry,
  decodeSubtreePage,
  decodeSubtreeRootPage,
  deriveAssetId,
  deriveAssociatedTokenAddressSync,
  deriveDefiSessionKeypair,
  deriveEscrowPdaSync,
  deriveKeysFromSeed,
  deriveLanePdaSync,
  deriveLaneRentVaultPdaSync,
  deriveMemoPdaSync,
  deriveNfPagePdaSync,
  deriveNullifierPdaSync,
  derivePoolPdaSync,
  deriveRootsPdaSync,
  deriveStealthOwner,
  deriveSubaccountKeys,
  deriveSubrootPdaSync,
  deriveSubtreePdaSync,
  deriveUnwrapPdaSync,
  deriveVaultAuthPdaSync,
  deterministicNoteRentFee,
  encryptNoteMemo,
  exportFullViewingKey,
  exportSelectiveDisclosureProof,
  fetchGlobalRootHistory,
  fetchPoolAndLanes,
  findProgramAddressSync,
  formatAudrenAddress,
  frFromBeBytesStrict,
  frToBeBytes,
  inspectToken2022UnsafeSelfPay,
  isCanonicalFr,
  isContributoryX25519Point,
  isOnEd25519Curve,
  packPublicAmounts,
  parseAudrenAddress,
  parseToken2022TransferFeeConfig,
  pickRandomEscrowShard,
  pickRandomLaneId,
  planAutoOpenPages,
  poseidon4,
  prepareDynamicSwapMemo,
  prepareEscrowAccounts,
  prepareEscrowAccountsForAudren,
  recommendedDepositCuLimit,
  recommendedExecViaEscrowCuLimit,
  recommendedOpenPageCuLimit,
  recommendedTransactCuLimit,
  reconstructWitness,
  selectHrwSealedDecoys,
  selectRootSnapshotForNotes,
  serializeV1Transaction,
  syncCompactStoreWithRpc,
  toPubkeyBytes,
  tryDecryptAndVerifyMemo,
  tryDecryptAndVerifyMemoEntry,
  validateGlobalRootHistory,
  validateRootSnapshotChoice,
  verifySelectiveDisclosureProof,
} from '../dist/index.js';
import {
  AudrenWasmProver,
  dummyInputWitness,
  dummyOutputWitness,
  encodeJoinsplitWitness,
} from '../dist/prover-entry.js';

const enc = new TextEncoder();
const WSOL_MINT_BYTES = base58Decode(WSOL_MINT);

function makeMemoPage(count) {
  const buf = new Uint8Array(MEMO_PAGE_LEN);
  buf.set(enc.encode(MEMO_MAGIC), MM_OFF_MAGIC);
  new DataView(buf.buffer).setUint16(MM_OFF_COUNT, count, true);
  return buf;
}

function writeMemoSlot(memoRaw, slot, memo106) {
  assert.equal(memo106.byteLength, MEMO_ENTRY_WIRE_LEN);
  memoRaw.set(memo106.subarray(0, 2), MM_OFF_VIEW_TAGS + slot * 2);
  memoRaw.set(memo106.subarray(2, 34), MM_OFF_EPHEMERAL_PKS + slot * 32);
  memoRaw.set(memo106.subarray(34, MEMO_ENTRY_WIRE_LEN), MM_OFF_CIPHERTEXTS + slot * MEMO_CT_LEN);
}

function makeT22MintWithExtensions(tlvs) {
  let totalTlv = 0;
  for (const { type, data } of tlvs) totalTlv += 4 + data.byteLength;
  const buf = new Uint8Array(166 + totalTlv);
  buf[44] = 6; // decimals
  buf[45] = 1; // is_initialized
  buf[165] = 1; // AccountType::Mint
  const dv = new DataView(buf.buffer);
  let off = 166;
  for (const { type, data } of tlvs) {
    dv.setUint16(off, type, true);
    dv.setUint16(off + 2, data.byteLength, true);
    buf.set(data, off + 4);
    off += 4 + data.byteLength;
  }
  return buf;
}

function makeTransferFeeConfigExt({ olderEpoch, olderMax, olderBps, newerEpoch, newerMax, newerBps }) {
  const data = new Uint8Array(108);
  const dv = new DataView(data.buffer);
  dv.setBigUint64(72, olderEpoch, true);
  dv.setBigUint64(80, olderMax, true);
  dv.setUint16(88, olderBps, true);
  dv.setBigUint64(90, newerEpoch, true);
  dv.setBigUint64(98, newerMax, true);
  dv.setUint16(106, newerBps, true);
  return { type: 1, data };
}

function bech32EncodeCustom(hrp, payloadBytes, constVal = 0x2bc830a3) {
  const charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  const polymod = (vals) => {
    let chk = 1;
    for (const v of vals) {
      const top = chk >>> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let b = 0; b < 5; b++) if ((top >>> b) & 1) chk ^= gen[b];
    }
    return chk >>> 0;
  };
  const hrpExp = [
    ...Array.from(hrp, (c) => c.charCodeAt(0) >>> 5),
    0,
    ...Array.from(hrp, (c) => c.charCodeAt(0) & 31),
  ];
  let acc = 0;
  let bits = 0;
  const data5 = [];
  for (const b of payloadBytes) {
    acc = ((acc << 8) | b) & 0xfff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      data5.push((acc >>> bits) & 31);
    }
  }
  if (bits > 0) data5.push((acc << (5 - bits)) & 31);
  const pmod = (polymod([...hrpExp, ...data5, 0, 0, 0, 0, 0, 0]) ^ constVal) >>> 0;
  const chk = Array.from({ length: 6 }, (_, i) => (pmod >>> (5 * (5 - i))) & 31);
  return `${hrp}1${[...data5, ...chk].map((v) => charset[v]).join('')}`;
}

test('BIP-350 Bech32m aud1... address codec enforces strict checksum, casing, version, length, and Fr modulus', () => {
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x55));
  const addr = alice.address;
  assert.equal(addr.startsWith('aud1'), true);
  assert.equal(addr.length, 114);

  // Lowercase & uppercase roundtrip
  const parsed = parseAudrenAddress(addr);
  assert.equal(parsed.encoded, addr);
  assert.deepEqual(parsed.spendPk, alice.spendPkBytes);
  assert.deepEqual(parsed.viewPk, alice.viewPk);

  const upper = parseAudrenAddress(addr.toUpperCase());
  assert.equal(upper.encoded, addr);
  assert.deepEqual(upper.spendPk, alice.spendPkBytes);
  assert.deepEqual(upper.viewPk, alice.viewPk);

  // Single-character typo detection across HRP, payload, and checksum
  const flipChar = (s, idx) => {
    const alt = s[idx] === 'q' ? 'p' : 'q';
    return s.slice(0, idx) + alt + s.slice(idx + 1);
  };
  assert.throws(() => parseAudrenAddress(flipChar(addr, 4)), /checksum/i);
  assert.throws(() => parseAudrenAddress(flipChar(addr, 50)), /checksum/i);
  assert.throws(() => parseAudrenAddress(flipChar(addr, addr.length - 1)), /checksum/i);

  // Mixed-case rejection
  assert.throws(() => parseAudrenAddress(`Aud1${addr.slice(4)}`), /Mixed case/);
  assert.throws(
    () => parseAudrenAddress(addr.slice(0, 10) + addr[10].toUpperCase() + addr.slice(11)),
    /Mixed case/,
  );

  // Wrong HRP rejection
  const validPayload = new Uint8Array(65);
  validPayload[0] = 1;
  validPayload.set(alice.spendPkBytes, 1);
  validPayload.set(alice.viewPk, 33);
  assert.throws(() => parseAudrenAddress(bech32EncodeCustom('btc', validPayload)), /HRP/);
  assert.throws(() => parseAudrenAddress(bech32EncodeCustom('sol', validPayload)), /HRP/);

  // Bech32 (v0, const = 1) instead of Bech32m (0x2bc830a3) rejected
  assert.throws(() => parseAudrenAddress(bech32EncodeCustom('aud', validPayload, 1)), /checksum/i);

  // Wrong version byte (0x02 and 0x00) rejected
  const badVer2 = new Uint8Array(validPayload);
  badVer2[0] = 2;
  assert.throws(() => parseAudrenAddress(bech32EncodeCustom('aud', badVer2)), /version/);
  const badVer0 = new Uint8Array(validPayload);
  badVer0[0] = 0;
  assert.throws(() => parseAudrenAddress(bech32EncodeCustom('aud', badVer0)), /version/);

  // Wrong payload length (64 B and 66 B) rejected
  assert.throws(() => parseAudrenAddress(bech32EncodeCustom('aud', validPayload.slice(0, 64))), /length/);
  const tooLong = new Uint8Array(66);
  tooLong.set(validPayload, 0);
  assert.throws(() => parseAudrenAddress(bech32EncodeCustom('aud', tooLong)), /length/);

  // Non-canonical spendPk (>= BN254 Fr modulus) rejected on encode AND decode
  const nonCanonical = new Uint8Array(32);
  let r = BN254_FR_MODULUS;
  for (let i = 31; i >= 0; i--) {
    nonCanonical[i] = Number(r & 0xffn);
    r >>= 8n;
  }
  assert.throws(() => formatAudrenAddress(nonCanonical, alice.viewPk), /canonical BN254 Fr/);
  const badFrPayload = new Uint8Array(65);
  badFrPayload[0] = 1;
  badFrPayload.set(nonCanonical, 1);
  badFrPayload.set(alice.viewPk, 33);
  assert.throws(() => parseAudrenAddress(bech32EncodeCustom('aud', badFrPayload)), /canonical BN254 Fr/);

  // Leading / trailing whitespace strictly rejected (matching Rust BIP-350)
  assert.throws(() => parseAudrenAddress(` ${addr}`), /Invalid character/);
  assert.throws(() => parseAudrenAddress(`${addr} `), /Invalid character/);
  assert.throws(() => parseAudrenAddress(`\n${addr}\t`), /Invalid character/);

  // Low-order X25519 viewPk ([0; 32] and RFC 7748 order-8 point) rejected on BOTH encode and decode
  const lowOrderViewPks = [
    new Uint8Array(32),
    Uint8Array.from([
      0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
      0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
    ]),
  ];
  for (const badVpk of lowOrderViewPks) {
    assert.throws(() => formatAudrenAddress(alice.spendPkBytes, badVpk), /contributory X25519/i);
    const badVpPayload = new Uint8Array(65);
    badVpPayload[0] = 1;
    badVpPayload.set(alice.spendPkBytes, 1);
    badVpPayload.set(badVpk, 33);
    assert.throws(() => parseAudrenAddress(bech32EncodeCustom('aud', badVpPayload)), /low-order X25519/i);
  }
});

test('Finding #18: verifySelectiveDisclosureProof enforces strict u64 amount, laneId, poolId, and byte lengths', () => {
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x57));
  const wsolAsset = deriveAssetId(WSOL_MINT_BYTES);
  const stealthFr = deriveStealthOwner(alice.spendPk, 77n);
  const blindFr = 99n;
  const realAmount = 1_500_000n;
  const cmBe = frToBeBytes(computeNoteCommitment(stealthFr, wsolAsset, realAmount, blindFr));

  const validProof = {
    poolId: 0,
    laneId: 2,
    leafIndex: 5n,
    stealthOwner: frToBeBytes(stealthFr),
    mint: WSOL_MINT_BYTES,
    amount: realAmount,
    blinding: frToBeBytes(blindFr),
    commitment: cmBe,
  };
  assert.equal(verifySelectiveDisclosureProof(validProof, cmBe), true);

  // Modular field aliasing attack: realAmount + k * BN254_FR_MODULUS MUST be rejected!
  assert.equal(verifySelectiveDisclosureProof({ ...validProof, amount: realAmount + BN254_FR_MODULUS }, cmBe), false);
  assert.equal(verifySelectiveDisclosureProof({ ...validProof, amount: realAmount + 2n * BN254_FR_MODULUS }, cmBe), false);
  assert.equal(verifySelectiveDisclosureProof({ ...validProof, amount: -1n }, cmBe), false);
  assert.equal(verifySelectiveDisclosureProof({ ...validProof, amount: (1n << 64n) }, cmBe), false);

  // Bounds on poolId, laneId, leafIndex, and 32-byte fields
  assert.equal(verifySelectiveDisclosureProof({ ...validProof, laneId: 16 }, cmBe), false);
  assert.equal(verifySelectiveDisclosureProof({ ...validProof, laneId: -1 }, cmBe), false);
  assert.equal(verifySelectiveDisclosureProof({ ...validProof, poolId: -1 }, cmBe), false);
  assert.equal(verifySelectiveDisclosureProof({ ...validProof, poolId: 0x1_0000_0000 }, cmBe), false);
  assert.equal(verifySelectiveDisclosureProof({ ...validProof, leafIndex: -1n }, cmBe), false);
  assert.equal(verifySelectiveDisclosureProof({ ...validProof, leafIndex: (1n << 64n) }, cmBe), false);
  assert.equal(verifySelectiveDisclosureProof({ ...validProof, mint: new Uint8Array(31) }, cmBe), false);
  assert.equal(verifySelectiveDisclosureProof({ ...validProof, commitment: new Uint8Array(31) }, cmBe), false);
});

test('X25519 low-order points (all-zero & order-8) are rejected across all memo primitives', () => {
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x31));
  const fvk = exportFullViewingKey(alice);
  const ephSec = new Uint8Array(32).fill(0x42);

  // Canonical Curve25519 low-order points (RFC 7748): 0, 1, order-8 generators
  const lowOrderPoints = [
    new Uint8Array(32), // all-zero
    Uint8Array.from([1, ...new Array(31).fill(0)]), // u = 1
    Uint8Array.from([
      0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
      0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
    ]), // order-8 point
    Uint8Array.from([
      0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ]), // order-2/4/8 boundary point (p - 1)
  ];

  const fakeMemo = new Uint8Array(MEMO_ENTRY_WIRE_LEN);
  const fakeCm = new Uint8Array(32);

  for (const badPk of lowOrderPoints) {
    assert.equal(checkMemoViewTag(alice.viewSk, new Uint8Array(2), badPk), false);
    fakeMemo.set(badPk, 2);
    assert.equal(tryDecryptAndVerifyMemo(fvk, fakeMemo, fakeCm), null);
    assert.throws(() => encryptNoteMemo(badPk, ephSec, 100n, WSOL_MINT_BYTES), /Low-order X25519/);
    assert.throws(() => prepareDynamicSwapMemo(badPk, ephSec), /Low-order X25519/);
  }
});

test('Versioned 72 B memo + 34 B AEAD AAD + paymentId roundtrip & 72 B AUD1DYN1 padding tamper rejection', () => {
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x61));
  const fvk = exportFullViewingKey(alice);
  const ephSec = new Uint8Array(32).fill(0x62);
  const wsolAsset = deriveAssetId(WSOL_MINT_BYTES);
  const paymentId = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);

  // 1. Static versioned memo roundtrip with explicit 14 B paymentId
  const staticEnc = encryptNoteMemo(alice.viewPk, ephSec, 4_200_000n, WSOL_MINT_BYTES, paymentId);
  assert.equal(staticEnc.memo.byteLength, MEMO_ENTRY_WIRE_LEN);
  const cmBe = frToBeBytes(
    computeNoteCommitment(
      deriveStealthOwner(alice.spendPk, staticEnc.tweak),
      wsolAsset,
      4_200_000n,
      staticEnc.blinding,
    ),
  );

  const dec = tryDecryptAndVerifyMemo(fvk, staticEnc.memo, cmBe);
  assert.ok(dec);
  assert.equal(dec.amount, 4_200_000n);
  assert.equal(dec.memoVersion, MEMO_VERSION_V1);
  assert.equal(dec.memoFlags, 0);
  assert.deepEqual(dec.paymentId, paymentId);
  assert.equal(dec.isDynamic, false);

  // Invalid paymentId length throws
  assert.throws(
    () => encryptNoteMemo(alice.viewPk, ephSec, 4_200_000n, WSOL_MINT_BYTES, new Uint8Array(13)),
    RangeError,
  );

  // AEAD AAD tamper rejection: mutating viewTag OR epk OR ciphertext fails Poly1305 verification
  const tamperedVt = new Uint8Array(staticEnc.memo);
  tamperedVt[0] ^= 0x01;
  assert.equal(tryDecryptAndVerifyMemo(fvk, tamperedVt, cmBe), null);

  const tamperedEpk = new Uint8Array(staticEnc.memo);
  tamperedEpk[2] ^= 0x80;
  assert.equal(tryDecryptAndVerifyMemo(fvk, tamperedEpk, cmBe), null);

  const tamperedCt = new Uint8Array(staticEnc.memo);
  tamperedCt[40] ^= 0x01;
  assert.equal(tryDecryptAndVerifyMemo(fvk, tamperedCt, cmBe), null);

  // 2. Dynamic 72 B AUD1DYN1 swap memo: domain separation + zero-padding tamper rejection
  const dynPrep = prepareDynamicSwapMemo(alice.viewPk, ephSec);
  assert.notEqual(dynPrep.tweak, staticEnc.tweak, 'dyn_tweak must be domain-separated from static tweak');
  assert.notEqual(dynPrep.blinding, staticEnc.blinding, 'dyn_blind must be domain-separated from static blinding');
  assert.equal(dynPrep.dynHead34.byteLength, 34);
  assert.equal(dynPrep.dynMask72.byteLength, MEMO_CT_LEN);

  const dynAmount = 987_654_321n;
  const plain72 = new Uint8Array(MEMO_CT_LEN);
  plain72.set(enc.encode(DYN_MEMO_MAGIC), 0);
  new DataView(plain72.buffer).setBigUint64(8, dynAmount, true);
  plain72.set(WSOL_MINT_BYTES, 16);
  // plain72[48..72] are all zeroes

  const stamped = new Uint8Array(MEMO_ENTRY_WIRE_LEN);
  stamped.set(dynPrep.dynHead34, 0);
  for (let i = 0; i < MEMO_CT_LEN; i++) {
    stamped[34 + i] = plain72[i] ^ dynPrep.dynMask72[i];
  }
  const dynCmBe = frToBeBytes(
    computeNoteCommitment(
      deriveStealthOwner(alice.spendPk, dynPrep.tweak),
      wsolAsset,
      dynAmount,
      dynPrep.blinding,
    ),
  );

  const dynDec = tryDecryptAndVerifyMemo(fvk, stamped, dynCmBe);
  assert.ok(dynDec);
  assert.equal(dynDec.isDynamic, true);
  assert.equal(dynDec.amount, dynAmount);
  assert.deepEqual(dynDec.mint, WSOL_MINT_BYTES);
  assert.deepEqual(dynDec.paymentId, new Uint8Array(MEMO_PAYMENT_ID_LEN));

  // Flipping ANY byte in trailing 24-byte zero padding [48..72] MUST be rejected!
  const tamperedPadStart = new Uint8Array(stamped);
  tamperedPadStart[34 + 48] ^= 0x01;
  assert.equal(tryDecryptAndVerifyMemo(fvk, tamperedPadStart, dynCmBe), null);

  const tamperedPadEnd = new Uint8Array(stamped);
  tamperedPadEnd[34 + 71] ^= 0x80;
  assert.equal(tryDecryptAndVerifyMemo(fvk, tamperedPadEnd, dynCmBe), null);
});

test('Package exports, IDLs, Transaction v1 compiler, and CompactWalletStore sealing/freezing (96 memos/page)', () => {
  assert.equal(AUDREN_CODAMA_IDL.program.publicKey, AUDREN_PROGRAM_ID);
  assert.equal(AUDREN_CODAMA_IDL.program.instructions.length, 9);
  assert.equal(AUDREN_ANCHOR_IDL.instructions.length, 9);
  assert.equal(JUPITER_CPI_EXCLUDED_DEXES.length, 8);
  assert.equal(MEMO_NOTES_PER_PAGE, 96);
  assert.equal(MEMO_PAGE_LEN, 10_240);
  assert.equal(MEMO_PAGE_SCAN_SLICE_LEN, 3_328);

  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x55));
  const fvk = exportFullViewingKey(alice);
  const wsolAsset = deriveAssetId(WSOL_MINT_BYTES);
  const payId = Uint8Array.from([0xaa, 0xbb, 0xcc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xdd]);

  // Build a sealed 256-leaf SubtreePage (with Alice's note at slot 7) + 3 MemoPages (96 + 96 + 64 = 256)
  const subRaw = new Uint8Array(SUBTREE_PAGE_LEN);
  subRaw.set(enc.encode(SUBTREE_MAGIC), SB_OFF_MAGIC);
  subRaw[SB_OFF_LANE_ID] = 1;
  new DataView(subRaw.buffer).setUint16(SB_OFF_COUNT, SUBTREE_LEAVES, true);

  const memo0 = makeMemoPageWithMeta(1, 0n, MEMO_NOTES_PER_PAGE); // 0..95
  const memo1 = makeMemoPageWithMeta(1, 1n, MEMO_NOTES_PER_PAGE); // 96..191
  const memo2 = makeMemoPageWithMeta(1, 2n, SUBTREE_LEAVES - 2 * MEMO_NOTES_PER_PAGE); // 192..255 (64)

  const leaves = [];
  for (let i = 0; i < SUBTREE_LEAVES; i++) {
    if (i === 7) {
      const { tweak, blinding, memo } = encryptNoteMemo(
        alice.viewPk,
        new Uint8Array(32).fill(0x66),
        2_500_000n,
        WSOL_MINT_BYTES,
        payId,
      );
      const cm = computeNoteCommitment(
        deriveStealthOwner(alice.spendPk, tweak),
        wsolAsset,
        2_500_000n,
        blinding,
      );
      leaves.push(cm);
      subRaw.set(frToBeBytes(cm), SB_OFF_LEAVES + i * 32);
      writeMemoSlot(memo0, i, memo);
    } else {
      const leaf = BigInt(i + 1);
      leaves.push(leaf);
      subRaw.set(frToBeBytes(leaf), SB_OFF_LEAVES + i * 32);
    }
  }

  const store = new CompactWalletStore(0, 0n);
  const discovered = store.ingestLanePages({
    fvk,
    laneId: 1,
    subtreePages: [{ pageSeq: 0n, raw: subRaw }],
    memoPages: [
      { pageSeq: 0n, raw: memo0 },
      { pageSeq: 1n, raw: memo1 },
      { pageSeq: 2n, raw: memo2 },
    ],
    nfPages: [],
  });
  assert.equal(discovered, 1);
  assert.equal(store.lanes[1].finalizedSubroots.length, 1);
  assert.equal(store.lanes[1].frontierSubSeq, 1n);
  assert.equal(store.lanes[1].frontierLeaves.length, 0);
  assert.ok(store.notes[0].frozenIntraSiblings, 'sealed page must freeze 12 intra-subtree siblings');
  assert.deepEqual(store.notes[0].paymentId, payId);

  // Round-trip JSON persistence (IndexedDB / disk) preserves paymentId
  const restored = CompactWalletStore.fromJSON(store.toJSON());
  assert.equal(restored.notes.length, 1);
  const note = restored.notes[0];
  assert.equal(note.amount, 2_500_000n);
  assert.deepEqual(note.paymentId, payId);
  assert.equal(verifySelectiveDisclosureProof(exportSelectiveDisclosureProof(note), note.commitment), true);

  // Build synthetic GlobalRootHistory at count = 256 and reconstruct offline witness
  let lroot = computeSubtree256Root(leaves, SUBTREE_LEAVES);
  for (let h = 4; h < 18; h++) {
    lroot = poseidon4(lroot, ZERO_HASHES_4ARY[h], ZERO_HASHES_4ARY[h], ZERO_HASHES_4ARY[h]);
  }
  const laneRoots = new Array(NUM_LANES).fill(ZERO_HASHES_4ARY[18]);
  laneRoots[1] = lroot;
  const laneCounts = new Array(NUM_LANES).fill(0n);
  laneCounts[1] = 256n;
  const { roots, superRoot, raw: rtRaw } = makeSyntheticRootHistory({ laneRoots, laneCounts });
  const { superRoot: sr, path, rootRingKind, rootRingIdx } = restored.buildWitnessForNote(note, roots);
  assert.equal(sr, superRoot);
  assert.equal(rootRingKind, ROOT_RING_EPOCH);
  assert.equal(rootRingIdx, 0);
  assert.equal(computeMerkleRoot4Ary(path, leaves[7]), superRoot);

  // Guard: buildWitnessForNote rejects missing frontier leaves when snapshot has unsealed tail
  const badCounts = [...laneCounts];
  badCounts[1] = 258n;
  const { roots: rtBad } = makeSyntheticRootHistory({ laneRoots, laneCounts: badCounts });
  assert.throws(
    () => restored.buildWitnessForNote(note, rtBad),
    /Missing frontier SubtreePage leaves/,
  );
  assert.equal(rtRaw.byteLength, ROOT_HISTORY_LEN);

  // Out-of-order NullifierPage ingestion still marks spent notes cleanly (page 1 before page 0)
  const nfRaw0 = makeNfPage(1, 0n, [note.nullifier.subarray(0, NF_PREFIX_LEN)]);
  const nfRaw1 = makeNfPage(1, 1n, [new Uint8Array(NF_PREFIX_LEN).fill(0xee)]);

  restored.ingestLanePages({
    fvk,
    laneId: 1,
    subtreePages: [],
    memoPages: [],
    nfPages: [
      { pageSeq: 1n, raw: nfRaw1 },
      { pageSeq: 0n, raw: nfRaw0 },
    ],
  });
  assert.equal(restored.unspentNotes().length, 0, 'out-of-order NullifierPage 0 must not be skipped');

  // Transaction v1 (0x81) compilation + wire serialization test with unified v1 Deposit
  const depIx = buildDepositInstruction({
    depositor: SYSTEM_PROGRAM_ID,
    poolId: 0,
    laneId: 0,
    subPageSeq: 0n,
    rootPageSeq: 0n,
    memoPageSeq: 0n,
    nativeSol: true,
    amount: 1_000_000n,
    stealthOwner: deriveStealthOwner(alice.spendPk, 1n),
    blinding: 2n,
    memo: new Uint8Array(MEMO_ENTRY_WIRE_LEN),
  });
  const compiled = compileV1Message({
    feePayer: toPubkeyBytes(SYSTEM_PROGRAM_ID),
    recentBlockhash: new Uint8Array(32).fill(7),
    instructions: [
      {
        programId: toPubkeyBytes(depIx.programId),
        accounts: depIx.accounts.map((a) => ({
          pubkey: toPubkeyBytes(a.pubkey),
          isSigner: a.isSigner,
          isWritable: a.isWritable,
        })),
        data: depIx.data,
      },
    ],
    config: { computeUnitLimit: 100_000 },
  });
  assert.equal(compiled.messageBytes[0], 0x81);
  const wire = serializeV1Transaction(compiled, [new Uint8Array(64).fill(0x42)]);
  assert.equal(wire[0], 0x81);
  assert.equal(wire.byteLength, compiled.messageBytes.byteLength + 64);
});

test('CompactWalletStore holds sealed SubtreePage until lagged MemoPages arrive (no sync stall)', () => {
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x77));
  const fvk = exportFullViewingKey(alice);
  const wsolAsset = deriveAssetId(WSOL_MINT_BYTES);

  const subRaw = new Uint8Array(SUBTREE_PAGE_LEN);
  subRaw.set(enc.encode(SUBTREE_MAGIC), SB_OFF_MAGIC);
  new DataView(subRaw.buffer).setUint16(SB_OFF_COUNT, SUBTREE_LEAVES, true);

  const memo0 = makeMemoPageWithMeta(0, 0n, MEMO_NOTES_PER_PAGE); // 0..95
  const memo1 = makeMemoPageWithMeta(0, 1n, MEMO_NOTES_PER_PAGE); // 96..191
  const memo2 = makeMemoPageWithMeta(0, 2n, SUBTREE_LEAVES - 2 * MEMO_NOTES_PER_PAGE); // 192..255

  for (let i = 0; i < SUBTREE_LEAVES; i++) {
    if (i === 150) {
      const { tweak, blinding, memo } = encryptNoteMemo(
        alice.viewPk,
        new Uint8Array(32).fill(0x88),
        5_000_000n,
        WSOL_MINT_BYTES,
      );
      const cm = computeNoteCommitment(
        deriveStealthOwner(alice.spendPk, tweak),
        wsolAsset,
        5_000_000n,
        blinding,
      );
      subRaw.set(frToBeBytes(cm), SB_OFF_LEAVES + i * 32);
      writeMemoSlot(memo1, i - MEMO_NOTES_PER_PAGE, memo);
    } else {
      subRaw.set(frToBeBytes(BigInt(i + 1)), SB_OFF_LEAVES + i * 32);
    }
  }

  const store = new CompactWalletStore(0, 0n);
  // Batch 1: SubtreePage #0 (256 leaves, sealed) + MemoPage #0 only (MemoPage #1 lags)
  const d1 = store.ingestLanePages({
    fvk,
    laneId: 0,
    subtreePages: [{ pageSeq: 0n, raw: subRaw }],
    memoPages: [{ pageSeq: 0n, raw: memo0 }],
    nfPages: [],
  });
  assert.equal(d1, 0);
  assert.equal(store.lanes[0].nextMemoLeaf, 96n);
  assert.equal(store.lanes[0].frontierSubSeq, 0n, 'must hold frontierSubSeq until memos reach 256');
  assert.equal(store.lanes[0].frontierLeaves.length, SUBTREE_LEAVES);

  // Batch 2: MemoPage #1 arrives WITHOUT re-supplying SubtreePage #0
  const d2 = store.ingestLanePages({
    fvk,
    laneId: 0,
    subtreePages: [],
    memoPages: [{ pageSeq: 1n, raw: memo1 }],
    nfPages: [],
  });
  assert.equal(d2, 1, 'Alice note at leaf 150 must be discovered from held frontier');
  assert.equal(store.lanes[0].nextMemoLeaf, 192n);
  assert.equal(store.notes[0].amount, 5_000_000n);
  assert.ok(store.notes[0].frozenIntraSiblings, 'newly discovered note in full page must freeze siblings');

  // Batch 3: MemoPage #2 completes leaf 255 -> frontier advances and raw 256 leaves are discarded
  const d3 = store.ingestLanePages({
    fvk,
    laneId: 0,
    subtreePages: [],
    memoPages: [{ pageSeq: 2n, raw: memo2 }],
    nfPages: [],
  });
  assert.equal(d3, 0);
  assert.equal(store.lanes[0].nextMemoLeaf, 256n);
  assert.equal(store.lanes[0].frontierSubSeq, 1n);
  assert.equal(store.lanes[0].frontierLeaves.length, 0);
});

test('All 9 v1 instruction builders, ctx_hash vkId binding, and ExecViaEscrow writability promotion', async () => {
  const usdcMint = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
  const payer = base58Encode(new Uint8Array(32).fill(0x11));
  const extraPool = base58Encode(new Uint8Array(32).fill(0x22));
  const readonlyAcc = base58Encode(new Uint8Array(32).fill(0x33));
  const routerProg = base58Encode(new Uint8Array(32).fill(0x44));
  const newAuth = base58Encode(new Uint8Array(32).fill(0x55));
  const vaultAuth = deriveVaultAuthPdaSync(0).address;
  const escrowPda = deriveEscrowPdaSync(0, 0).address;
  const escrowInAta = deriveAssociatedTokenAddressSync(escrowPda, usdcMint, CLASSIC_TOKEN_PROGRAM_ID).address;
  const escrowOutAta = deriveAssociatedTokenAddressSync(escrowPda, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address;
  const wsolVaultAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address;

  // deterministicNoteRentFee uses MEMO_NOTES_PER_PAGE = 96 + zero-rent `.max(1)` anti-reaping clamp
  assert.equal(
    deterministicNoteRentFee(10_000_000n, 256n * 100n, 76_800n * 10n, 96n * 200n),
    310n,
  );
  assert.equal(
    deterministicNoteRentFee(150n, 256n * 100n, 76_800n * 10n, 96n * 200n),
    150n,
  );
  assert.equal(deterministicNoteRentFee(10_000_000n, 0n, 0n, 0n), 3n);
  assert.equal(deterministicNoteRentFee(3n, 0n, 0n, 0n), 3n);
  assert.equal(deterministicNoteRentFee(2n, 0n, 0n, 0n), 2n);
  assert.equal(deterministicNoteRentFee(0n, 0n, 0n, 0n), 0n);
  assert.equal(deterministicNoteRentFee(10_000_000n, 0n, 76_800n * 5n, 0n), 7n);

  // Tag 0: InitPool (4 accounts incl. GlobalRootHistory, 29 B)
  const initPool = buildInitPoolInstruction({
    payer,
    poolId: 0,
    rootEpochInterval: DEFAULT_ROOT_EPOCH_INTERVAL,
    noteRentFee: 100n,
    nfRentFee: 50n,
  });
  assert.equal(initPool.data[0], TAG_INIT_POOL);
  assert.equal(initPool.data.byteLength, 29);
  assert.equal(initPool.accounts.length, 4);
  assert.equal(initPool.accounts[2].pubkey, deriveRootsPdaSync(0).address);
  assert.equal(initPool.accounts[2].isWritable, true);

  // Tag 1: InitLane (9 accounts, 6 B)
  const initLane = buildInitLaneInstruction({ authority: payer, poolId: 0, laneId: 0 });
  assert.equal(initLane.data[0], TAG_INIT_LANE);
  assert.equal(initLane.data.byteLength, 6);
  assert.equal(initLane.accounts.length, 9);

  // Tag 2: OpenPage (6 accounts, 23 B incl. maxPayerDeficit)
  const openPage = buildOpenPageInstruction({
    payer,
    pageKind: OPEN_PAGE_KIND_SUBTREE,
    poolId: 0,
    laneId: 0,
    pageSeq: 1n,
  });
  assert.equal(openPage.data[0], TAG_OPEN_PAGE);
  assert.equal(openPage.data.byteLength, 23);
  assert.equal(openPage.accounts.length, 6);

  // Tag 3: Unified Deposit — Native SOL path (185 B, 14 fixed accounts w/ writable roots at [2])
  const depSol = buildDepositInstruction({
    depositor: payer,
    poolId: 0,
    laneId: 0,
    subPageSeq: 0n,
    rootPageSeq: 0n,
    memoPageSeq: 0n,
    nativeSol: true,
    feeFromAmount: true,
    amount: 500_000n,
    stealthOwner: 1n,
    blinding: 2n,
    memo: new Uint8Array(MEMO_ENTRY_WIRE_LEN),
  });
  assert.equal(depSol.data[0], TAG_DEPOSIT);
  assert.equal(depSol.data.byteLength, 185);
  assert.equal(depSol.data[6], DEPOSIT_FLAG_NATIVE_SOL | DEPOSIT_FLAG_FEE_FROM_AMOUNT);
  assert.equal(depSol.accounts.length, 14);
  assert.equal(depSol.accounts[2].pubkey, deriveRootsPdaSync(0).address);
  assert.equal(depSol.accounts[2].isWritable, true);
  assert.equal(depSol.accounts[4].pubkey, WSOL_MINT);
  assert.equal(depSol.accounts[5].pubkey, payer);
  assert.equal(depSol.accounts[6].pubkey, wsolVaultAta);
  assert.equal(depSol.accounts[7].pubkey, CLASSIC_TOKEN_PROGRAM_ID);

  // Tag 3: Unified Deposit — SPL / Token-2022 path with rollover + hook accounts
  const depSpl = buildDepositInstruction({
    depositor: payer,
    poolId: 0,
    laneId: 0,
    subPageSeq: 0n,
    rootPageSeq: 0n,
    memoPageSeq: 0n,
    mint: usdcMint,
    sourceAccount: escrowInAta,
    tokenProgram: TOKEN_2022_PROGRAM_ID,
    rollover: { nextSubSeq: 1n, nextMemoSeq: 1n },
    amount: 1_000n,
    stealthOwner: 1n,
    blinding: 2n,
    memo: new Uint8Array(MEMO_ENTRY_WIRE_LEN),
    hookAccounts: [{ pubkey: extraPool, isSigner: false, isWritable: false }],
  });
  assert.equal(depSpl.data[0], TAG_DEPOSIT);
  assert.equal(depSpl.data.byteLength, 185);
  assert.equal(depSpl.data[6], 0b11);
  assert.equal(depSpl.accounts.length, 17); // 14 + 2 rollover + 1 hook
  assert.throws(
    () =>
      buildDepositInstruction({
        depositor: payer,
        poolId: 0,
        laneId: 0,
        subPageSeq: 0n,
        rootPageSeq: 0n,
        memoPageSeq: 0n,
        mint: usdcMint,
        sourceAccount: escrowInAta,
        feeFromAmount: true,
        amount: 1_000n,
        stealthOwner: 1n,
        blinding: 2n,
        memo: new Uint8Array(MEMO_ENTRY_WIRE_LEN),
      }),
    /feeFromAmount is only valid when nativeSol is true/,
  );

  // Tag 4: InitRootHistory (4 + activeLanes accounts, 13 B)
  const initRoots = buildInitRootHistoryInstruction({
    authority: payer,
    poolId: 0,
    rootEpochInterval: 32n,
    activeLanes: 4,
  });
  assert.equal(initRoots.data[0], TAG_INIT_ROOT_HISTORY);
  assert.equal(initRoots.data.byteLength, 13);
  assert.equal(initRoots.accounts.length, 8);
  assert.equal(initRoots.accounts[0].pubkey, payer);
  assert.equal(initRoots.accounts[0].isSigner, true);
  assert.equal(initRoots.accounts[0].isWritable, true);
  assert.equal(initRoots.accounts[1].isWritable, true);
  assert.equal(initRoots.accounts[2].pubkey, deriveRootsPdaSync(0).address);
  assert.equal(initRoots.accounts[2].isWritable, true);
  assert.equal(initRoots.accounts[4].pubkey, deriveLanePdaSync(0, 0).address);
  assert.equal(initRoots.accounts[7].pubkey, deriveLanePdaSync(0, 3).address);

  // Tag 5: Transact — private, public, WSOL unwrap, read-only vs writable roots, & vkId binding
  const ctxVk0 = computeTransactCtxHash({
    poolId: 0,
    vkId: 0,
    outLaneId: 0,
    outputMask: 0,
    assetMode: ASSET_MODE_PRIVATE,
    unwrapWsol: false,
    publicAssetId: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(0),
  });
  const ctxVk1 = computeTransactCtxHash({
    poolId: 0,
    vkId: 1,
    outLaneId: 0,
    outputMask: 0,
    assetMode: ASSET_MODE_PRIVATE,
    unwrapWsol: false,
    publicAssetId: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(0),
  });
  assert.notEqual(ctxVk0, ctxVk1, 'computeTransactCtxHash must cryptographically bind vkId');

  const nf0Bytes = new Uint8Array(32).fill(1);
  const transactUnwrap = buildTransactInstruction({
    payer,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 7,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: true,
    proof192: new Uint8Array(192),
    nf0: nf0Bytes,
    nf1: new Uint8Array(32),
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 100_000n,
    relayerFeeAmount: 5_000n,
    recipient: readonlyAcc,
    relayerFeeRecipient: payer,
    memosBytes: new Uint8Array(0),
  });
  assert.equal(transactUnwrap.data[0], TAG_TRANSACT);
  assert.equal(transactUnwrap.data.byteLength, 380);
  assert.equal(transactUnwrap.data[9], WITHDRAW_FLAG_UNWRAP_WSOL);
  assert.equal(transactUnwrap.data[10], ROOT_RING_EPOCH);
  assert.equal(transactUnwrap.data[11], 7);
  assert.equal(transactUnwrap.accounts[2].pubkey, deriveRootsPdaSync(0).address);
  assert.equal(transactUnwrap.accounts[2].isWritable, false, 'full exit (outputMask=0) keeps roots READ-ONLY');
  assert.equal(transactUnwrap.accounts.length, 19); // 12 head + 7 public w/ unwrap PDA
  assert.equal(transactUnwrap.accounts[18].pubkey, deriveUnwrapPdaSync(0, nf0Bytes).address);

  const transactPrivate = buildTransactInstruction({
    payer,
    poolId: 0,
    rootRingKind: ROOT_RING_SLOT,
    rootRingIdx: 127,
    outLaneId: 1,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b011,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: new Uint8Array(192),
    nf0: nf0Bytes,
    nf1: new Uint8Array(32),
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN),
  });
  assert.equal(transactPrivate.data.byteLength, 380 + 2 * MEMO_ENTRY_WIRE_LEN);
  assert.equal(transactPrivate.data[10], ROOT_RING_SLOT);
  assert.equal(transactPrivate.data[11], 127);
  assert.equal(transactPrivate.accounts[2].pubkey, deriveRootsPdaSync(0).address);
  assert.equal(transactPrivate.accounts[2].isWritable, true, 'outputMask != 0 marks roots WRITABLE');

  assert.throws(
    () =>
      buildTransactInstruction({
        payer,
        poolId: 0,
        rootRingKind: ROOT_RING_EPOCH,
        rootRingIdx: 0,
        outLaneId: 0,
        outSubSeq: 0n,
        outRootSeq: 0n,
        outMemoSeq: 0n,
        outNfSeq: 0n,
        outputMask: 0,
        assetMode: ASSET_MODE_PUBLIC,
        proof192: new Uint8Array(192),
        nf0: new Uint8Array(32).fill(1),
        nf1: new Uint8Array(32),
        cm0: new Uint8Array(32),
        cm1: new Uint8Array(32),
        cm2: new Uint8Array(32),
        publicAmountOut: 100n,
        relayerFeeAmount: 0n,
        memosBytes: new Uint8Array(0),
      }),
    /recipient is required/,
  );

  // Tag 6: ExecViaEscrow (SPL/T22 only, 560 B header, 72 B dynMemoMask, vkId binding & writability promotion)
  const rawRouterAccs = [
    { pubkey: escrowPda, isSigner: true, isWritable: false },
    { pubkey: escrowInAta, isSigner: false, isWritable: false },
    { pubkey: escrowOutAta, isSigner: false, isWritable: true },
    { pubkey: extraPool, isSigner: false, isWritable: false },
    { pubkey: extraPool, isSigner: false, isWritable: true },
    { pubkey: readonlyAcc, isSigner: false, isWritable: false },
  ];
  const normalized = prepareEscrowAccountsForAudren(rawRouterAccs, escrowPda, [payer, escrowInAta]);
  assert.equal(normalized[0].isSigner, false);
  assert.equal(normalized[0].isWritable, true);
  assert.equal(normalized[1].isWritable, true);
  assert.equal(normalized[3].isWritable, true);
  assert.equal(normalized[5].isWritable, false);

  const prepared = await prepareEscrowAccounts({
    poolId: 0,
    shardId: 0,
    inputMint: usdcMint,
    outputMint: WSOL_MINT,
    actionAccounts: rawRouterAccs,
    extraWritablePubkeys: [payer],
  });
  const execCtxBase = {
    poolId: 0,
    vkId: 0,
    outLaneId: 0,
    escrowShard: 0,
    changeMask: 0,
    feeOnOutput: true,
    assetIn: new Uint8Array(32).fill(1),
    amountIn: 10_000_000n,
    relayerFeeAmount: 50_000n,
    relayerFeeRecipient: payer,
    assetOut: new Uint8Array(32).fill(2),
    minAmountOut: 1_000n,
    routerProg,
    extraWritablePubkeys: [payer, escrowInAta, escrowOutAta],
    outStealthOwner: new Uint8Array(32).fill(3),
    outBlinding: new Uint8Array(32).fill(4),
    dynMemoHead: new Uint8Array(34).fill(5),
    dynMemoMask: new Uint8Array(MEMO_CT_LEN).fill(6),
    routerIxData: new Uint8Array([9, 8, 7]),
    changeMemos: new Uint8Array(0),
  };
  const hRaw = computeExecCtxHash({ ...execCtxBase, routerAccounts: rawRouterAccs });
  const hNorm = computeExecCtxHash({ ...execCtxBase, routerAccounts: prepared.accounts });
  const hVk1 = computeExecCtxHash({ ...execCtxBase, vkId: 1, routerAccounts: prepared.accounts });
  assert.equal(hRaw, hNorm, 'computeExecCtxHash must normalize Solana tx-wide writability');
  assert.notEqual(hRaw, hVk1, 'computeExecCtxHash must cryptographically bind vkId');

  const execIx = buildExecViaEscrowInstruction({
    payer,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 12,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    escrowShard: 0,
    changeMask: 0,
    feeOnOutput: true,
    inLeg: { mint: usdcMint, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    outLeg: { mint: WSOL_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    relayerFeeAmount: 50_000n,
    relayerFeeRecipient: payer,
    proof192: new Uint8Array(192),
    nf0: new Uint8Array(32).fill(1),
    nf1: new Uint8Array(32),
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    amountIn: 10_000_000n,
    minAmountOut: 1_000n,
    outStealthOwner: new Uint8Array(32).fill(3),
    outBlinding: new Uint8Array(32).fill(4),
    dynMemoHead: new Uint8Array(34).fill(5),
    dynMemoMask: new Uint8Array(MEMO_CT_LEN).fill(6),
    routerProg,
    routerIxData: new Uint8Array([9, 8, 7]),
    routerAccounts: rawRouterAccs,
    changeMemos: new Uint8Array(0),
  });
  assert.equal(execIx.data[0], TAG_EXEC_VIA_ESCROW);
  assert.equal(execIx.data.byteLength, 560 + 3);
  assert.equal(execIx.data[10], ROOT_RING_EPOCH);
  assert.equal(execIx.data[11], 12);
  assert.equal(execIx.accounts[2].pubkey, deriveRootsPdaSync(0).address);
  assert.equal(execIx.accounts[2].isWritable, true);
  const trailing = execIx.accounts.slice(-rawRouterAccs.length);
  assert.equal(trailing[0].isSigner, false);
  assert.equal(trailing[0].isWritable, true);
  assert.equal(trailing[1].isWritable, true);
  assert.equal(trailing[3].isWritable, true);

  // Tag 7: SetPaused (6 B)
  const setPaused = buildSetPausedInstruction({ authority: payer, poolId: 0, paused: true });
  assert.equal(setPaused.data[0], TAG_SET_PAUSED);
  assert.equal(setPaused.data.byteLength, 6);

  // Tag 8: UpdatePool (all 4 sub-actions + buildUpdatePoolParamsInstruction)
  const updParams = buildUpdatePoolInstruction({
    signer: payer,
    poolId: 0,
    action: { kind: 'params', noteRentFee: 200n, nfRentFee: 100n },
  });
  assert.equal(updParams.data[0], TAG_UPDATE_POOL);
  assert.equal(updParams.data[5], UPDATE_POOL_PARAMS);
  assert.equal(updParams.data.byteLength, 22);
  assert.equal(updParams.accounts.length, 2);

  const updParamsHelper = buildUpdatePoolParamsInstruction({
    authority: payer,
    poolId: 0,
    noteRentFee: 200n,
    nfRentFee: 100n,
  });
  assert.deepEqual(updParamsHelper, updParams);

  const updProp = buildUpdatePoolInstruction({
    signer: payer,
    poolId: 0,
    action: { kind: 'proposeAuthority', pendingAuthority: newAuth },
  });
  assert.equal(updProp.data[0], TAG_UPDATE_POOL);
  assert.equal(updProp.data[5], UPDATE_POOL_PROPOSE_AUTHORITY);
  assert.equal(updProp.data.byteLength, 38);

  const updAcc = buildUpdatePoolInstruction({
    signer: newAuth,
    poolId: 0,
    action: { kind: 'acceptAuthority' },
  });
  assert.equal(updAcc.data[0], TAG_UPDATE_POOL);
  assert.equal(updAcc.data[5], UPDATE_POOL_ACCEPT_AUTHORITY);
  assert.equal(updAcc.data.byteLength, 6);

  const updRen = buildUpdatePoolInstruction({
    signer: newAuth,
    poolId: 0,
    action: { kind: 'renounceAuthority' },
  });
  assert.equal(updRen.data[0], TAG_UPDATE_POOL);
  assert.equal(updRen.data[5], UPDATE_POOL_RENOUNCE_AUTHORITY);
  assert.equal(updRen.data.byteLength, 6);

  // CreateAtaIdempotent helper
  const ataIx = buildCreateAtaIdempotentInstruction({
    payer,
    ata: escrowInAta,
    owner: escrowPda,
    mint: usdcMint,
    tokenProgram: TOKEN_2022_PROGRAM_ID,
  });
  assert.equal(ataIx.programId, ASSOCIATED_TOKEN_PROGRAM_ID);
  assert.deepEqual(Array.from(ataIx.data), [1]);
  assert.equal(ataIx.accounts[5].pubkey, TOKEN_2022_PROGRAM_ID);
});

test('Token-2022 epoch-aware TransferFeeConfig parser, net calculation & self-pay safety inspector', () => {
  const mintFee = makeT22MintWithExtensions([
    makeTransferFeeConfigExt({
      olderEpoch: 100n,
      olderMax: 5_000n,
      olderBps: 100,
      newerEpoch: 200n,
      newerMax: 10_000n,
      newerBps: 250,
    }),
  ]);
  const feeAt150 = parseToken2022TransferFeeConfig(mintFee, 150);
  assert.deepEqual(feeAt150, { bps: 100n, maxFee: 5_000n, epoch: 100n });
  assert.equal(computeToken2022NetAmount(10_001n, feeAt150), 9_900n);
  assert.equal(computeToken2022NetAmount(1_000_000n, feeAt150), 995_000n);

  const feeAt200 = parseToken2022TransferFeeConfig(mintFee, 200n);
  assert.deepEqual(feeAt200, { bps: 250n, maxFee: 10_000n, epoch: 200n });
  assert.equal(computeToken2022NetAmount(100_000n, feeAt200), 97_500n);
  assert.equal(inspectToken2022UnsafeSelfPay(mintFee), false);

  const mintZeroNewer = makeT22MintWithExtensions([
    makeTransferFeeConfigExt({
      olderEpoch: 100n,
      olderMax: 5_000n,
      olderBps: 100,
      newerEpoch: 200n,
      newerMax: 0n,
      newerBps: 0,
    }),
  ]);
  assert.equal(parseToken2022TransferFeeConfig(mintZeroNewer, 200), null);
  assert.deepEqual(parseToken2022TransferFeeConfig(mintZeroNewer, 199), {
    bps: 100n,
    maxFee: 5_000n,
    epoch: 100n,
  });

  const mintHighFee = makeT22MintWithExtensions([
    makeTransferFeeConfigExt({
      olderEpoch: 0n,
      olderMax: 10_000n,
      olderBps: 501,
      newerEpoch: 0n,
      newerMax: 10_000n,
      newerBps: 501,
    }),
  ]);
  assert.equal(inspectToken2022UnsafeSelfPay(mintHighFee), true);
  assert.equal(inspectToken2022UnsafeSelfPay(makeT22MintWithExtensions([{ type: 9, data: new Uint8Array(0) }])), true);
  assert.equal(inspectToken2022UnsafeSelfPay(makeT22MintWithExtensions([{ type: 12, data: new Uint8Array(32) }])), true);

  const inactiveHook = new Uint8Array(64);
  assert.equal(inspectToken2022UnsafeSelfPay(makeT22MintWithExtensions([{ type: 14, data: inactiveHook }])), false);
  const activeHook = new Uint8Array(64);
  activeHook[32] = 1;
  assert.equal(inspectToken2022UnsafeSelfPay(makeT22MintWithExtensions([{ type: 14, data: activeHook }])), true);
  assert.equal(inspectToken2022UnsafeSelfPay(new Uint8Array(82)), false);
});

test('AudrenWasmProver rejects corrupted proving key when verifyPkHash is enabled', async () => {
  await assert.rejects(
    () => AudrenWasmProver.init({ pkCompressed: new Uint8Array(64).fill(0xaa), verifyPkHash: true }),
    /SHA-256 mismatch/,
  );
});

function makePoolState(activeLanes) {
  const buf = new Uint8Array(POOL_STATE_LEN);
  buf.set(enc.encode(POOL_MAGIC), PL_OFF_MAGIC);
  buf[PL_OFF_VERSION] = PROTOCOL_VERSION;
  buf[PL_OFF_ACTIVE_LANES] = activeLanes;
  return buf;
}

function makeLaneState(laneId, nextLeaf, nfCount, currentRoot = ZERO_HASHES_4ARY[18]) {
  const buf = new Uint8Array(LANE_STATE_LEN);
  buf.set(enc.encode(LANE_MAGIC), LN_OFF_MAGIC);
  buf[LN_OFF_VERSION] = PROTOCOL_VERSION;
  buf[LN_OFF_LANE_ID] = laneId;
  const dv = new DataView(buf.buffer);
  dv.setBigUint64(LN_OFF_NEXT_LEAF, nextLeaf, true);
  dv.setBigUint64(LN_OFF_NF_COUNT, nfCount, true);
  buf.set(frToBeBytes(currentRoot), LN_OFF_CURRENT_ROOT);
  return buf;
}

function makeSubtreePage(laneId, pageSeq, leavesFr) {
  const buf = new Uint8Array(SUBTREE_PAGE_LEN);
  buf.set(enc.encode(SUBTREE_MAGIC), SB_OFF_MAGIC);
  buf[SB_OFF_LANE_ID] = laneId;
  const dv = new DataView(buf.buffer);
  dv.setUint16(SB_OFF_COUNT, leavesFr.length, true);
  dv.setBigUint64(SB_OFF_PAGE_SEQ, pageSeq, true);
  for (let i = 0; i < leavesFr.length; i++) {
    buf.set(frToBeBytes(leavesFr[i]), SB_OFF_LEAVES + i * 32);
  }
  return buf;
}

function makeSubrootPage(laneId, rootPageSeq, rootsFr) {
  const buf = new Uint8Array(SUBROOT_PAGE_LEN);
  buf.set(enc.encode(SUBROOT_MAGIC), SR_OFF_MAGIC);
  buf[SR_OFF_LANE_ID] = laneId;
  const dv = new DataView(buf.buffer);
  dv.setUint16(SR_OFF_COUNT, rootsFr.length, true);
  dv.setBigUint64(SR_OFF_ROOT_PAGE_SEQ, rootPageSeq, true);
  for (let i = 0; i < rootsFr.length; i++) {
    buf.set(frToBeBytes(rootsFr[i]), SR_OFF_ROOTS + i * 32);
  }
  return buf;
}

function makeMemoPageWithMeta(laneId, pageSeq, count, closedSlot = 0n) {
  const buf = new Uint8Array(MEMO_PAGE_LEN);
  buf.set(enc.encode(MEMO_MAGIC), MM_OFF_MAGIC);
  buf[MM_OFF_LANE_ID] = laneId;
  const dv = new DataView(buf.buffer);
  dv.setUint16(MM_OFF_COUNT, count, true);
  dv.setBigUint64(MM_OFF_PAGE_SEQ, pageSeq, true);
  dv.setBigUint64(MM_OFF_CLOSED_SLOT, closedSlot, true);
  return buf;
}

function makeNfPage(laneId, pageSeq, prefixes) {
  const buf = new Uint8Array(NF_PAGE_LEN);
  buf.set(enc.encode(NF_PAGE_MAGIC), NF_OFF_MAGIC);
  buf[NF_OFF_LANE_ID] = laneId;
  const dv = new DataView(buf.buffer);
  dv.setUint16(NF_OFF_COUNT, prefixes.length, true);
  dv.setBigUint64(NF_OFF_PAGE_SEQ, pageSeq, true);
  for (let i = 0; i < prefixes.length; i++) {
    buf.set(prefixes[i].subarray(0, NF_PREFIX_LEN), NF_OFF_PREFIXES + i * NF_PREFIX_LEN);
  }
  return buf;
}

function computeLaneRootFromSubroots(finalizedSubroots, frontierLeaves = []) {
  let nodes = [...finalizedSubroots];
  if (frontierLeaves.length > 0) {
    nodes.push(computeSubtree256Root(frontierLeaves, frontierLeaves.length));
  }
  if (nodes.length === 0) return ZERO_HASHES_4ARY[18];
  for (let h = 4; h < 18; h++) {
    const z = ZERO_HASHES_4ARY[h];
    const next = [];
    const groups = Math.ceil(nodes.length / 4);
    for (let g = 0; g < groups; g++) {
      const b = g * 4;
      next.push(poseidon4(nodes[b] ?? z, nodes[b + 1] ?? z, nodes[b + 2] ?? z, nodes[b + 3] ?? z));
    }
    nodes = next;
  }
  return nodes[0];
}

function computeLaneRootFromLeaves(allLeaves) {
  const numFull = Math.floor(allLeaves.length / SUBTREE_LEAVES);
  const rem = allLeaves.length % SUBTREE_LEAVES;
  let nodes = [];
  for (let p = 0; p < numFull; p++) {
    nodes.push(computeSubtree256Root(allLeaves.slice(p * SUBTREE_LEAVES, (p + 1) * SUBTREE_LEAVES), SUBTREE_LEAVES));
  }
  if (rem > 0) {
    nodes.push(computeSubtree256Root(allLeaves.slice(numFull * SUBTREE_LEAVES), rem));
  }
  if (nodes.length === 0) return ZERO_HASHES_4ARY[18];
  for (let h = 4; h < 18; h++) {
    const z = ZERO_HASHES_4ARY[h];
    const next = [];
    const groups = Math.ceil(nodes.length / 4);
    for (let g = 0; g < groups; g++) {
      const b = g * 4;
      next.push(poseidon4(nodes[b] ?? z, nodes[b + 1] ?? z, nodes[b + 2] ?? z, nodes[b + 3] ?? z));
    }
    nodes = next;
  }
  return nodes[0];
}

function makeSyntheticRootHistory({
  poolId = 0,
  laneRoots,
  laneCounts,
  stableLaneRoots = laneRoots,
  stableLaneCounts = laneCounts,
  slotCursor = 0,
  slotCount = 1,
  epochCursor = 0,
  epochCount = 1,
  sameSlotBumped = 0,
  latestSlot = 100n,
  stableSlot = 96n,
  epochInterval = DEFAULT_ROOT_EPOCH_INTERVAL,
}) {
  const latestSuperRoot = computeSuperRoot4Ary(laneRoots);
  const stableSuperRoot = computeSuperRoot4Ary(stableLaneRoots);
  const raw = new Uint8Array(ROOT_HISTORY_LEN);
  const dv = new DataView(raw.buffer);
  raw.set(enc.encode(ROOTS_MAGIC), RT_OFF_MAGIC);
  raw[RT_OFF_VERSION] = PROTOCOL_VERSION;
  raw[RT_OFF_BUMP] = deriveRootsPdaSync(poolId).bump;
  dv.setUint16(RT_OFF_SLOT_CURSOR, slotCursor, true);
  dv.setUint32(RT_OFF_POOL_ID, poolId, true);
  dv.setUint16(RT_OFF_EPOCH_CURSOR, epochCursor, true);
  dv.setUint16(RT_OFF_SLOT_COUNT, slotCount, true);
  dv.setUint16(RT_OFF_EPOCH_COUNT, epochCount, true);
  raw[RT_OFF_SAME_SLOT_BUMPED] = sameSlotBumped;
  dv.setBigUint64(RT_OFF_LATEST_SLOT, latestSlot, true);
  dv.setBigUint64(RT_OFF_STABLE_EPOCH_ID, stableSlot / epochInterval, true);
  dv.setBigUint64(RT_OFF_STABLE_SLOT, stableSlot, true);
  dv.setBigUint64(RT_OFF_EPOCH_INTERVAL, epochInterval, true);

  for (let g = 0; g < 4; g++) {
    const gr = poseidon4(
      laneRoots[g * 4],
      laneRoots[g * 4 + 1],
      laneRoots[g * 4 + 2],
      laneRoots[g * 4 + 3],
    );
    raw.set(frToBeBytes(gr), RT_OFF_GROUP_ROOTS + g * 32);
  }
  const latestSrBe = frToBeBytes(latestSuperRoot);
  const stableSrBe = frToBeBytes(stableSuperRoot);
  raw.set(latestSrBe, RT_OFF_LATEST_SUPER_ROOT);
  raw.set(stableSrBe, RT_OFF_STABLE_SUPER_ROOT);
  for (let i = 0; i < NUM_LANES; i++) {
    raw.set(frToBeBytes(laneRoots[i]), RT_OFF_LATEST_LANE_ROOTS + i * 32);
    dv.setBigUint64(RT_OFF_LATEST_LANE_COUNTS + i * 8, laneCounts[i], true);
    raw.set(frToBeBytes(stableLaneRoots[i]), RT_OFF_STABLE_LANE_ROOTS + i * 32);
    dv.setBigUint64(RT_OFF_STABLE_LANE_COUNTS + i * 8, stableLaneCounts[i], true);
  }
  const slotOff = RT_OFF_SLOT_RING + slotCursor * ROOT_ENTRY_LEN;
  raw.set(latestSrBe, slotOff);
  dv.setBigUint64(slotOff + 32, latestSlot, true);
  const epochOff = RT_OFF_EPOCH_RING + epochCursor * ROOT_ENTRY_LEN;
  raw.set(stableSrBe, epochOff);
  dv.setBigUint64(epochOff + 32, stableSlot, true);

  return {
    roots: decodeGlobalRootHistory(raw),
    superRoot: latestSuperRoot,
    stableSuperRoot,
    raw,
  };
}

function makeSingleLaneRootHistory(laneId, laneRoot, laneCount) {
  const laneRoots = new Array(NUM_LANES).fill(ZERO_HASHES_4ARY[18]);
  laneRoots[laneId] = laneRoot;
  const laneCounts = new Array(NUM_LANES).fill(0n);
  laneCounts[laneId] = laneCount;
  return makeSyntheticRootHistory({ laneRoots, laneCounts });
}

test('2-pass cross-lane nullifier sync discards stranger prefixes & loads legacy seenNfPrefixes JSON', async () => {
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x21));
  const fvk = exportFullViewingKey(alice);
  const wsolAsset = deriveAssetId(WSOL_MINT_BYTES);

  const { tweak, blinding, memo } = encryptNoteMemo(
    alice.viewPk,
    new Uint8Array(32).fill(0x31),
    9_000_000n,
    WSOL_MINT_BYTES,
  );
  const cm = computeNoteCommitment(deriveStealthOwner(alice.spendPk, tweak), wsolAsset, 9_000_000n, blinding);
  const lane2Sub0 = makeSubtreePage(2, 0n, [cm]);
  const lane2Memo0 = makeMemoPageWithMeta(2, 0n, 1);
  writeMemoSlot(lane2Memo0, 0, memo);

  const probeStore = new CompactWalletStore(0, 0n);
  probeStore.ingestLanePages({
    fvk,
    laneId: 2,
    subtreePages: [{ pageSeq: 0n, raw: lane2Sub0 }],
    memoPages: [{ pageSeq: 0n, raw: lane2Memo0 }],
    nfPages: [],
  });
  const ownNfPrefix = probeStore.notes[0].nullifier.subarray(0, NF_PREFIX_LEN);

  const nfPrefixes = [];
  for (let i = 0; i < 50; i++) {
    const stranger = new Uint8Array(NF_PREFIX_LEN);
    stranger[0] = 0xaa;
    stranger[1] = i;
    nfPrefixes.push(stranger);
  }
  nfPrefixes.push(ownNfPrefix);
  const lane0Nf0 = makeNfPage(0, 0n, nfPrefixes);

  const accounts = new Map([
    [derivePoolPdaSync(0).address, makePoolState(4)],
    [deriveLanePdaSync(0, 0).address, makeLaneState(0, 0n, BigInt(nfPrefixes.length))],
    [deriveLanePdaSync(0, 1).address, makeLaneState(1, 0n, 0n)],
    [deriveLanePdaSync(0, 2).address, makeLaneState(2, 1n, 0n, computeLaneRootFromLeaves([cm]))],
    [deriveLanePdaSync(0, 3).address, makeLaneState(3, 0n, 0n)],
    [deriveSubtreePdaSync(0, 2, 0n).address, lane2Sub0],
    [deriveMemoPdaSync(0, 2, 0n).address, lane2Memo0],
    [deriveNfPagePdaSync(0, 0, 0n).address, lane0Nf0],
  ]);

  const fetchBatch = async (addrs, opts) =>
    addrs.map((a) => {
      const full = accounts.get(a) ?? null;
      if (!full || !opts?.dataSlice) return full;
      return full.slice(opts.dataSlice.offset, opts.dataSlice.offset + opts.dataSlice.length);
    });

  const store = new CompactWalletStore(0, 0n);
  const res = await syncCompactStoreWithRpc({ store, fvk, fetchBatch });
  assert.equal(res.discoveredNotes, 1);
  assert.equal(store.notes.length, 1);
  assert.equal(store.notes[0].spent, true);
  assert.equal(store.unspentNotes().length, 0);
  assert.equal(store.lanes[0].nextNfIndex, BigInt(nfPrefixes.length));

  const serialized = store.toJSON();
  const parsed = JSON.parse(serialized);
  assert.equal('seenNfPrefixes' in parsed, false);
  assert.equal(serialized.includes('aa00000000'), false);

  const legacyObj = JSON.parse(probeStore.toJSON());
  assert.equal(legacyObj.notes[0].spent, false);
  legacyObj.seenNfPrefixes = [
    'deadbeefdeadbeefdeadbeefdeadbeef',
    Array.from(ownNfPrefix, (b) => b.toString(16).padStart(2, '0')).join(''),
  ];
  const migrated = CompactWalletStore.fromJSON(JSON.stringify(legacyObj));
  assert.equal(migrated.notes[0].spent, true);
  assert.equal('seenNfPrefixes' in JSON.parse(migrated.toJSON()), false);
});

test('Pass 1D -> Pass 2 oracle regression: transient SubtreePage miss STILL executes Pass 2 unconditionally', async () => {
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x51));
  const aliceFvk = exportFullViewingKey(alice);
  const bob = deriveKeysFromSeed(new Uint8Array(32).fill(0x52));
  const bobFvk = exportFullViewingKey(bob);
  const wsolAsset = deriveAssetId(WSOL_MINT_BYTES);

  const { tweak, blinding, memo } = encryptNoteMemo(
    alice.viewPk,
    new Uint8Array(32).fill(0x53),
    6_000_000n,
    WSOL_MINT_BYTES,
  );
  const cm = computeNoteCommitment(deriveStealthOwner(alice.spendPk, tweak), wsolAsset, 6_000_000n, blinding);
  const sub0 = makeSubtreePage(0, 0n, [cm]);
  const memo0 = makeMemoPageWithMeta(0, 0n, 1);
  writeMemoSlot(memo0, 0, memo);

  const probe = new CompactWalletStore(0, 0n);
  probe.ingestLanePages({
    fvk: aliceFvk,
    laneId: 0,
    subtreePages: [{ pageSeq: 0n, raw: sub0 }],
    memoPages: [{ pageSeq: 0n, raw: memo0 }],
    nfPages: [],
  });
  const aliceNfPrefix = probe.notes[0].nullifier.subarray(0, NF_PREFIX_LEN);
  const nf0 = makeNfPage(0, 0n, [aliceNfPrefix]);

  const sub0Addr = deriveSubtreePdaSync(0, 0, 0n).address;
  const nf0Addr = deriveNfPagePdaSync(0, 0, 0n).address;
  const accounts = new Map([
    [derivePoolPdaSync(0).address, makePoolState(1)],
    [deriveLanePdaSync(0, 0).address, makeLaneState(0, 1n, 1n, computeLaneRootFromLeaves([cm]))],
    [sub0Addr, sub0],
    [deriveMemoPdaSync(0, 0, 0n).address, memo0],
    [nf0Addr, nf0],
  ]);

  let dropSub0 = true;
  const makeAdversarialFetcher = (log) => async (addrs) => {
    log.push([...addrs]);
    return addrs.map((a) => (dropSub0 && a === sub0Addr ? null : (accounts.get(a) ?? null)));
  };

  // Sync 1 (adversarial RPC drops SubtreePage 0):
  // Alice (hit on dropped SubtreePage) AND Bob (no hit) MUST both STILL run Pass 2 & fetch nf0Addr!
  const aliceLog1 = [];
  const aliceStore = new CompactWalletStore(0, 0n);
  await syncCompactStoreWithRpc({
    store: aliceStore,
    fvk: aliceFvk,
    fetchBatch: makeAdversarialFetcher(aliceLog1),
  });
  const bobLog1 = [];
  const bobStore = new CompactWalletStore(0, 0n);
  await syncCompactStoreWithRpc({
    store: bobStore,
    fvk: bobFvk,
    fetchBatch: makeAdversarialFetcher(bobLog1),
  });

  assert.deepEqual(
    aliceLog1,
    bobLog1,
    'Pass 1D SubtreePage drop must produce IDENTICAL RPC traffic (incl. Pass 2) for hit vs non-hit wallets',
  );
  assert.equal(aliceLog1.flat().includes(nf0Addr), true, 'Pass 2 MUST execute unconditionally after Pass 1D miss');
  assert.equal(aliceStore.lanes[0].nextMemoLeaf, 0n, 'nextMemoLeaf must remain capped on transient SubtreePage miss');
  assert.equal(aliceStore.lanes[0].nextNfIndex, 0n, 'nextNfIndex must be held until missed note is verified');

  // Sync 2 (healthy RPC returns SubtreePage 0): Alice discovers note AND Pass 2 marks it spent!
  dropSub0 = false;
  const aliceLog2 = [];
  const res2 = await syncCompactStoreWithRpc({
    store: aliceStore,
    fvk: aliceFvk,
    fetchBatch: makeAdversarialFetcher(aliceLog2),
  });
  assert.equal(res2.discoveredNotes, 1);
  assert.equal(aliceStore.notes[0].spent, true, 'missed note must be marked spent on subsequent healthy sync');
  assert.equal(aliceStore.lanes[0].nextMemoLeaf, 1n);
  assert.equal(aliceStore.lanes[0].nextNfIndex, 1n);
});

test('Post-seal GlobalRootHistory witness building via prevSealedLeaves & automatic pruning', () => {
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x41));
  const fvk = exportFullViewingKey(alice);
  const wsolAsset = deriveAssetId(WSOL_MINT_BYTES);

  const leaves = [];
  const memo0 = makeMemoPageWithMeta(0, 0n, MEMO_NOTES_PER_PAGE); // 0..95
  const memo1 = makeMemoPageWithMeta(0, 1n, MEMO_NOTES_PER_PAGE); // 96..191
  const memo2 = makeMemoPageWithMeta(0, 2n, SUBTREE_LEAVES - 2 * MEMO_NOTES_PER_PAGE); // 192..255

  for (let i = 0; i < SUBTREE_LEAVES; i++) {
    if (i === 200) {
      const { tweak, blinding, memo } = encryptNoteMemo(
        alice.viewPk,
        new Uint8Array(32).fill(0x42),
        7_500_000n,
        WSOL_MINT_BYTES,
      );
      const cm = computeNoteCommitment(deriveStealthOwner(alice.spendPk, tweak), wsolAsset, 7_500_000n, blinding);
      leaves.push(cm);
      writeMemoSlot(memo2, i - 2 * MEMO_NOTES_PER_PAGE, memo);
    } else {
      leaves.push(BigInt(i + 10));
    }
  }
  const sub0 = makeSubtreePage(0, 0n, leaves);

  const preSealRoot = computeLaneRootFromLeaves(leaves.slice(0, 250));
  const { roots: preSealRoots, superRoot: preSealSuper } = makeSingleLaneRootHistory(0, preSealRoot, 250n);

  const store = new CompactWalletStore(0, 0n);
  store.ingestLanePages({
    fvk,
    laneId: 0,
    subtreePages: [{ pageSeq: 0n, raw: sub0 }],
    memoPages: [
      { pageSeq: 0n, raw: memo0 },
      { pageSeq: 1n, raw: memo1 },
      { pageSeq: 2n, raw: memo2 },
    ],
    nfPages: [],
  });
  assert.equal(store.lanes[0].frontierSubSeq, 1n);
  assert.equal(store.lanes[0].frontierLeaves.length, 0);
  assert.equal(store.lanes[0].prevSealedSubSeq, 0n);
  assert.equal(store.lanes[0].prevSealedLeaves.length, SUBTREE_LEAVES);

  const reloaded = CompactWalletStore.fromJSON(store.toJSON());
  const note = reloaded.notes[0];
  const { superRoot: sr250, path: path250 } = reloaded.buildWitnessForNote(note, preSealRoots);
  assert.equal(sr250, preSealSuper);
  assert.equal(computeMerkleRoot4Ary(path250, leaves[200]), preSealSuper);
  assert.equal(reloaded.lanes[0].prevSealedSubSeq, 0n);

  const postSealRoot = computeLaneRootFromLeaves(leaves);
  const { roots: postSealRoots, superRoot: postSealSuper } = makeSingleLaneRootHistory(0, postSealRoot, 256n);
  const { superRoot: sr256, path: path256 } = reloaded.buildWitnessForNote(note, postSealRoots);
  assert.equal(sr256, postSealSuper);
  assert.equal(computeMerkleRoot4Ary(path256, leaves[200]), postSealSuper);
  assert.equal(reloaded.lanes[0].prevSealedSubSeq, null);
  assert.equal(reloaded.lanes[0].prevSealedLeaves.length, 0);
});

test('SubtreeRootPage fast sync + strict incremental sync + birthdaySlot binary search', async () => {
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x91));
  const fvk = exportFullViewingKey(alice);
  const wsolAsset = deriveAssetId(WSOL_MINT_BYTES);

  // Lane 0 has 780 leaves = 3 sealed SubtreePages (0, 1, 2) + 12 frontier leaves in SubtreePage 3.
  // MemoPages (96 notes/page): 0..7 sealed (768 leaves) + MemoPage 8 open (12 leaves) = 9 MemoPages (<= 25).
  // Alice owns ONLY 1 note at leaf 700 (SubtreePage 2, MemoPage 7, slot 28).
  const totalLeaves = 780;
  const allLeaves = [];
  const memoPages = new Map();
  const totalMemos = Math.ceil(totalLeaves / MEMO_NOTES_PER_PAGE); // 9 (0..8)
  for (let m = 0; m < totalMemos; m++) {
    const cnt = Math.min(MEMO_NOTES_PER_PAGE, totalLeaves - m * MEMO_NOTES_PER_PAGE);
    // Pages 0..5 sealed before slot 1000 (closedSlot = (m+1)*100); pages 6..7 closedSlot >= 1200; page 8 open (0)
    const closedSlot = cnt === MEMO_NOTES_PER_PAGE ? (m < 6 ? BigInt((m + 1) * 100) : BigInt(1200 + m)) : 0n;
    memoPages.set(BigInt(m), makeMemoPageWithMeta(0, BigInt(m), cnt, closedSlot));
  }

  for (let i = 0; i < totalLeaves; i++) {
    if (i === 700) {
      const { tweak, blinding, memo } = encryptNoteMemo(
        alice.viewPk,
        new Uint8Array(32).fill(0x92),
        12_345_678n,
        WSOL_MINT_BYTES,
      );
      const cm = computeNoteCommitment(deriveStealthOwner(alice.spendPk, tweak), wsolAsset, 12_345_678n, blinding);
      allLeaves.push(cm);
      const mSeq = BigInt(Math.floor(i / MEMO_NOTES_PER_PAGE));
      writeMemoSlot(memoPages.get(mSeq), i % MEMO_NOTES_PER_PAGE, memo);
    } else {
      allLeaves.push(BigInt(i + 1));
    }
  }

  const sub0 = makeSubtreePage(0, 0n, allLeaves.slice(0, 256));
  const sub1 = makeSubtreePage(0, 1n, allLeaves.slice(256, 512));
  const sub2 = makeSubtreePage(0, 2n, allLeaves.slice(512, 768));
  const sub3 = makeSubtreePage(0, 3n, allLeaves.slice(768, 780));
  const sr0 = makeSubrootPage(0, 0n, [
    computeSubtree256Root(allLeaves.slice(0, 256), 256),
    computeSubtree256Root(allLeaves.slice(256, 512), 256),
    computeSubtree256Root(allLeaves.slice(512, 768), 256),
  ]);

  const accounts = new Map([
    [derivePoolPdaSync(0).address, makePoolState(1)],
    [
      deriveLanePdaSync(0, 0).address,
      makeLaneState(0, BigInt(totalLeaves), 0n, computeLaneRootFromLeaves(allLeaves)),
    ],
    [deriveSubrootPdaSync(0, 0, 0n).address, sr0],
    [deriveSubtreePdaSync(0, 0, 0n).address, sub0],
    [deriveSubtreePdaSync(0, 0, 1n).address, sub1],
    [deriveSubtreePdaSync(0, 0, 2n).address, sub2],
    [deriveSubtreePdaSync(0, 0, 3n).address, sub3],
  ]);
  for (const [m, raw] of memoPages) {
    accounts.set(deriveMemoPdaSync(0, 0, m).address, raw);
  }

  const makeLoggingFetcher = (log) => async (addrs, opts) => {
    log.push({ addrs: [...addrs], dataSlice: opts?.dataSlice ?? null });
    return addrs.map((a) => {
      const full = accounts.get(a) ?? null;
      if (!full || !opts?.dataSlice) return full;
      return full.slice(opts.dataSlice.offset, opts.dataSlice.offset + opts.dataSlice.length);
    });
  };

  // Run 1: Default `'strict'` mode on <= 25 MemoPages -> ZERO dataSlice calls, uniform SubtreePages
  const strictLog = [];
  const storeStrict = new CompactWalletStore(0, 0n);
  const rStrict = await syncCompactStoreWithRpc({
    store: storeStrict,
    fvk,
    fetchBatch: makeLoggingFetcher(strictLog),
  });
  assert.equal(rStrict.discoveredNotes, 1);
  assert.equal(storeStrict.notes[0].leafIndex, 700n);
  assert.equal(storeStrict.notes[0].amount, 12_345_678n);
  assert.ok(storeStrict.notes[0].frozenIntraSiblings);
  assert.equal(storeStrict.lanes[0].finalizedSubroots.length, 3);
  assert.equal(storeStrict.lanes[0].frontierSubSeq, 3n);
  assert.equal(storeStrict.lanes[0].frontierLeaves.length, 12);
  assert.equal(strictLog.filter((e) => e.dataSlice !== null).length, 0);

  const strictAddrs = strictLog.flatMap((e) => e.addrs);
  for (let m = 0; m < totalMemos; m++) {
    const addr = deriveMemoPdaSync(0, 0, BigInt(m)).address;
    assert.equal(strictAddrs.filter((a) => a === addr).length, 1);
  }
  for (let s = 0; s < 4; s++) {
    assert.equal(strictAddrs.includes(deriveSubtreePdaSync(0, 0, BigInt(s)).address), true);
  }

  const { roots, superRoot } = makeSingleLaneRootHistory(0, computeLaneRootFromLeaves(allLeaves), BigInt(totalLeaves));
  const { path } = storeStrict.buildWitnessForNote(storeStrict.notes[0], roots);
  assert.equal(computeMerkleRoot4Ary(path, allLeaves[700]), superRoot);

  // Run 2: birthdaySlot = 1000 skips sealed MemoPages 0..5 via 64 B header probes, scans 6..8 in full
  const bdLog = [];
  const storeBd = new CompactWalletStore(0, 0n);
  const rBd = await syncCompactStoreWithRpc({
    store: storeBd,
    fvk,
    fetchBatch: makeLoggingFetcher(bdLog),
    birthdaySlot: 1000n,
  });
  assert.equal(rBd.discoveredNotes, 1);
  assert.equal(storeBd.lanes[0].finalizedSubroots.length, 3);
  assert.ok(bdLog.filter((e) => e.dataSlice?.length === MEMO_PAGE_HEADER_LEN).length >= 1);
  assert.equal(bdLog.filter((e) => e.dataSlice?.length === MEMO_PAGE_SCAN_SLICE_LEN).length, 0);
  const bdFullAddrs = bdLog.filter((e) => e.dataSlice === null).flatMap((e) => e.addrs);
  assert.equal(bdFullAddrs.includes(deriveMemoPdaSync(0, 0, 0n).address), false);
  assert.equal(bdFullAddrs.includes(deriveMemoPdaSync(0, 0, 5n).address), false);
  assert.equal(bdFullAddrs.includes(deriveMemoPdaSync(0, 0, 6n).address), true);
  assert.equal(bdFullAddrs.includes(deriveMemoPdaSync(0, 0, 8n).address), true);
  const { path: pathBd } = storeBd.buildWitnessForNote(storeBd.notes[0], roots);
  assert.equal(computeMerkleRoot4Ary(pathBd, allLeaves[700]), superRoot);

  // Run 3: Explicit `privacyMode: 'fast'` on <= 25 MemoPages STILL fetches full MemoPages directly
  const fastSmallLog = [];
  const storeFastSmall = new CompactWalletStore(0, 0n);
  const rFastSmall = await syncCompactStoreWithRpc({
    store: storeFastSmall,
    fvk,
    fetchBatch: makeLoggingFetcher(fastSmallLog),
    privacyMode: 'fast',
  });
  assert.equal(rFastSmall.discoveredNotes, 1);
  assert.equal(fastSmallLog.filter((e) => e.dataSlice?.length === MEMO_PAGE_SCAN_SLICE_LEN).length, 0);
  const fastSmallAddrs = fastSmallLog.flatMap((e) => e.addrs);
  assert.equal(fastSmallAddrs.includes(deriveSubtreePdaSync(0, 0, 0n).address), false);
  assert.equal(fastSmallAddrs.includes(deriveSubtreePdaSync(0, 0, 1n).address), false);
  assert.equal(fastSmallAddrs.includes(deriveSubtreePdaSync(0, 0, 2n).address), true);
  assert.equal(fastSmallAddrs.includes(deriveSubtreePdaSync(0, 0, 3n).address), true);
});

test('Finding #1 regression: Pass 2 streams ALL NullifierPages with zero early-exit (0 unspent & mid-stream spend)', async () => {
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0xa1));
  const aliceFvk = exportFullViewingKey(alice);
  const bob = deriveKeysFromSeed(new Uint8Array(32).fill(0xb2));
  const bobFvk = exportFullViewingKey(bob);
  const wsolAsset = deriveAssetId(WSOL_MINT_BYTES);

  const { tweak, blinding, memo } = encryptNoteMemo(
    alice.viewPk,
    new Uint8Array(32).fill(0xa2),
    3_000_000n,
    WSOL_MINT_BYTES,
  );
  const cm = computeNoteCommitment(deriveStealthOwner(alice.spendPk, tweak), wsolAsset, 3_000_000n, blinding);
  const lane0Sub0 = makeSubtreePage(0, 0n, [cm]);
  const lane0Memo0 = makeMemoPageWithMeta(0, 0n, 1);
  writeMemoSlot(lane0Memo0, 0, memo);

  const probeStore = new CompactWalletStore(0, 0n);
  probeStore.ingestLanePages({
    fvk: aliceFvk,
    laneId: 0,
    subtreePages: [{ pageSeq: 0n, raw: lane0Sub0 }],
    memoPages: [{ pageSeq: 0n, raw: lane0Memo0 }],
    nfPages: [],
  });
  const aliceNfPrefix = probeStore.notes[0].nullifier.subarray(0, NF_PREFIX_LEN);

  const lane0NfPagesCount = 121;
  const lane0NfTotal = BigInt((lane0NfPagesCount - 1) * NF_PER_PAGE + 5);
  const lane1NfPagesCount = 3;
  const lane1NfTotal = BigInt((lane1NfPagesCount - 1) * NF_PER_PAGE + 3);

  const fullStrangerPrefixes = Array.from({ length: NF_PER_PAGE }, (_, i) => {
    const p = new Uint8Array(NF_PREFIX_LEN);
    p[0] = 0xcc;
    p[1] = i & 0xff;
    p[2] = (i >> 8) & 0xff;
    return p;
  });
  const lane0Page0Prefixes = [...fullStrangerPrefixes];
  lane0Page0Prefixes[0] = aliceNfPrefix;

  const accounts = new Map([
    [derivePoolPdaSync(0).address, makePoolState(2)],
    [
      deriveLanePdaSync(0, 0).address,
      makeLaneState(0, 1n, lane0NfTotal, computeLaneRootFromLeaves([cm])),
    ],
    [deriveLanePdaSync(0, 1).address, makeLaneState(1, 0n, lane1NfTotal)],
    [deriveSubtreePdaSync(0, 0, 0n).address, lane0Sub0],
    [deriveMemoPdaSync(0, 0, 0n).address, lane0Memo0],
  ]);

  const expectedNfAddrs = new Set();

  for (let p = 0; p < lane0NfPagesCount; p++) {
    const addr = deriveNfPagePdaSync(0, 0, BigInt(p)).address;
    expectedNfAddrs.add(addr);
    accounts.set(
      addr,
      p === 0
        ? makeNfPage(0, 0n, lane0Page0Prefixes)
        : p === lane0NfPagesCount - 1
          ? makeNfPage(0, BigInt(p), fullStrangerPrefixes.slice(0, 5))
          : makeNfPage(0, BigInt(p), fullStrangerPrefixes),
    );
  }
  for (let p = 0; p < lane1NfPagesCount; p++) {
    const addr = deriveNfPagePdaSync(0, 1, BigInt(p)).address;
    expectedNfAddrs.add(addr);
    accounts.set(
      addr,
      p === lane1NfPagesCount - 1
        ? makeNfPage(1, BigInt(p), fullStrangerPrefixes.slice(0, 3))
        : makeNfPage(1, BigInt(p), fullStrangerPrefixes),
    );
  }

  const makeFetcher = (log) => async (addrs, opts) => {
    log.push({ addrs: [...addrs], dataSlice: opts?.dataSlice ?? null });
    return addrs.map((a) => accounts.get(a) ?? null);
  };

  // Case 1: Bob has 0 unspent notes -> STILL fetches all 124 NullifierPages!
  const bobLog = [];
  const bobStore = new CompactWalletStore(0, 0n);
  await syncCompactStoreWithRpc({ store: bobStore, fvk: bobFvk, fetchBatch: makeFetcher(bobLog) });
  assert.equal(bobStore.lanes[0].nextNfIndex, lane0NfTotal);
  assert.equal(bobStore.lanes[1].nextNfIndex, lane1NfTotal);
  assert.equal(new Set(bobLog.flatMap((e) => e.addrs).filter((a) => expectedNfAddrs.has(a))).size, expectedNfAddrs.size);

  // Case 2: Alice's ONLY note is spent on page 0 -> STILL fetches all 124 NullifierPages!
  const aliceLog = [];
  const aliceStore = new CompactWalletStore(0, 0n);
  await syncCompactStoreWithRpc({ store: aliceStore, fvk: aliceFvk, fetchBatch: makeFetcher(aliceLog) });
  assert.equal(aliceStore.notes[0].spent, true);
  assert.equal(aliceStore.lanes[0].nextNfIndex, lane0NfTotal);
  assert.equal(aliceStore.lanes[1].nextNfIndex, lane1NfTotal);
  assert.equal(new Set(aliceLog.flatMap((e) => e.addrs).filter((a) => expectedNfAddrs.has(a))).size, expectedNfAddrs.size);
});

test('Deterministic wallet-keyed decoy selection in strict large catch-up, decoy-padded reconstructWitness, & opt-in fast dataSlice', async () => {
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0xd1));
  const fvk = exportFullViewingKey(alice);
  const bob = deriveKeysFromSeed(new Uint8Array(32).fill(0xe2));
  const bobFvk = exportFullViewingKey(bob);
  const wsolAsset = deriveAssetId(WSOL_MINT_BYTES);

  const dummyLeafFrs = Array.from({ length: SUBTREE_LEAVES }, (_, i) => BigInt(i + 1));
  const dummySubRoot = computeSubtree256Root(dummyLeafFrs, SUBTREE_LEAVES);
  const dummyFrontierFrs = dummyLeafFrs.slice(0, 4);

  const { tweak, blinding, memo } = encryptNoteMemo(
    alice.viewPk,
    new Uint8Array(32).fill(0xd2),
    8_888_888n,
    WSOL_MINT_BYTES,
  );
  const aliceCm = computeNoteCommitment(deriveStealthOwner(alice.spendPk, tweak), wsolAsset, 8_888_888n, blinding);
  // Lane 2, leaf 300 -> sealed SubtreePage (2, 1, slot 44), MemoPage (2, 3, slot 12) under 96 notes/page
  const aliceLeafIdx = 300n;
  const aliceSubSeq = 1n;
  const aliceSubSlot = Number(aliceLeafIdx % BigInt(SUBTREE_LEAVES)); // 44
  const aliceMemoSeq = aliceLeafIdx / BigInt(MEMO_NOTES_PER_PAGE); // 3n
  const aliceMemoSlot = Number(aliceLeafIdx % BigInt(MEMO_NOTES_PER_PAGE)); // 12

  const hitSubLeaves = [...dummyLeafFrs];
  hitSubLeaves[aliceSubSlot] = aliceCm;
  const hitSubRoot = computeSubtree256Root(hitSubLeaves, SUBTREE_LEAVES);

  const hitSubRaw = makeSubtreePage(2, aliceSubSeq, hitSubLeaves);
  const hitMemoRaw = makeMemoPageWithMeta(2, aliceMemoSeq, MEMO_NOTES_PER_PAGE);
  writeMemoSlot(hitMemoRaw, aliceMemoSlot, memo);

  const probe = new CompactWalletStore(0, 0n);
  probe.recordVerifiedMemo({
    fvk,
    laneId: 2,
    leafIdx: aliceLeafIdx,
    decrypted: {
      amount: 8_888_888n,
      mint: WSOL_MINT_BYTES,
      tweak,
      blinding,
      memoVersion: MEMO_VERSION_V1,
      memoFlags: 0,
      paymentId: new Uint8Array(MEMO_PAYMENT_ID_LEN),
      isDynamic: false,
    },
    cmBe: frToBeBytes(aliceCm),
  });
  const aliceNfPrefix = probe.notes[0].nullifier.subarray(0, NF_PREFIX_LEN);

  const buildLargePoolFixture = (sealedPerLane) => {
    const activeLanes = 4;
    const leavesPerLane = sealedPerLane * SUBTREE_LEAVES + 4;
    const memosPerLane = Math.ceil(leavesPerLane / MEMO_NOTES_PER_PAGE);
    const nfPagesLane0 = 3;
    const nfTotalLane0 = BigInt((nfPagesLane0 - 1) * NF_PER_PAGE + 5);

    const accounts = new Map([[derivePoolPdaSync(0).address, makePoolState(activeLanes)]]);
    const sealedSubAddrs = new Set();
    const allSubAddrs = new Set();
    const allMemoAddrs = new Set();
    const allNfAddrs = new Set();
    const laneRoots = new Array(NUM_LANES).fill(ZERO_HASHES_4ARY[18]);
    const laneCounts = new Array(NUM_LANES).fill(0n);

    const strangerPrefixes = Array.from({ length: NF_PER_PAGE }, (_, i) => {
      const p = new Uint8Array(NF_PREFIX_LEN);
      p[0] = 0xdd;
      p[1] = i & 0xff;
      return p;
    });
    const nf0Prefixes = [...strangerPrefixes];
    nf0Prefixes[0] = aliceNfPrefix;

    for (let p = 0; p < nfPagesLane0; p++) {
      const addr = deriveNfPagePdaSync(0, 0, BigInt(p)).address;
      allNfAddrs.add(addr);
      accounts.set(
        addr,
        p === 0
          ? makeNfPage(0, 0n, nf0Prefixes)
          : makeNfPage(0, BigInt(p), p === nfPagesLane0 - 1 ? strangerPrefixes.slice(0, 5) : strangerPrefixes),
      );
    }

    for (let l = 0; l < activeLanes; l++) {
      laneCounts[l] = BigInt(leavesPerLane);
      const roots = Array.from({ length: sealedPerLane }, (_, s) =>
        l === 2 && BigInt(s) === aliceSubSeq ? hitSubRoot : dummySubRoot,
      );
      laneRoots[l] = computeLaneRootFromSubroots(roots, dummyFrontierFrs);
      accounts.set(
        deriveLanePdaSync(0, l).address,
        makeLaneState(l, BigInt(leavesPerLane), l === 0 ? nfTotalLane0 : 0n, laneRoots[l]),
      );
      accounts.set(deriveSubrootPdaSync(0, l, 0n).address, makeSubrootPage(l, 0n, roots));

      for (let s = 0; s < sealedPerLane; s++) {
        const addr = deriveSubtreePdaSync(0, l, BigInt(s)).address;
        sealedSubAddrs.add(addr);
        allSubAddrs.add(addr);
        const isHit = l === 2 && BigInt(s) === aliceSubSeq;
        accounts.set(addr, isHit ? hitSubRaw : makeSubtreePage(l, BigInt(s), dummyLeafFrs));
      }
      const fAddr = deriveSubtreePdaSync(0, l, BigInt(sealedPerLane)).address;
      allSubAddrs.add(fAddr);
      accounts.set(fAddr, makeSubtreePage(l, BigInt(sealedPerLane), dummyFrontierFrs));

      for (let m = 0; m < memosPerLane; m++) {
        const addr = deriveMemoPdaSync(0, l, BigInt(m)).address;
        allMemoAddrs.add(addr);
        const cnt = Math.min(MEMO_NOTES_PER_PAGE, leavesPerLane - m * MEMO_NOTES_PER_PAGE);
        if (l === 2 && BigInt(m) === aliceMemoSeq) {
          accounts.set(addr, hitMemoRaw);
        } else {
          accounts.set(addr, makeMemoPageWithMeta(l, BigInt(m), cnt));
        }
      }
    }

    const { superRoot, raw: rootsRaw } = makeSyntheticRootHistory({ laneRoots, laneCounts });
    accounts.set(deriveRootsPdaSync(0).address, rootsRaw);

    return {
      accounts,
      sealedSubAddrs,
      allSubAddrs,
      allMemoAddrs,
      allNfAddrs,
      nfTotalLane0,
      superRoot,
      hitSubAddr: deriveSubtreePdaSync(0, 2, aliceSubSeq).address,
      hitMemoAddr: deriveMemoPdaSync(0, 2, aliceMemoSeq).address,
    };
  };

  // Fixture A: 5 sealed subtrees/lane -> 20 total sealed subtrees (> 16), 56 total MemoPages (> 25)
  const fix20 = buildLargePoolFixture(5);
  assert.equal(fix20.sealedSubAddrs.size, 20);
  assert.equal(fix20.allMemoAddrs.size, 56);

  const makeSliceFetcher = (accounts, log) => async (addrs, opts) => {
    log.push({ addrs: [...addrs], dataSlice: opts?.dataSlice ?? null });
    return addrs.map((a) => {
      const full = accounts.get(a) ?? null;
      if (!full || !opts?.dataSlice) return full;
      return full.slice(opts.dataSlice.offset, opts.dataSlice.offset + opts.dataSlice.length);
    });
  };

  // A1: Repeated strict large catch-ups of the SAME wallet (Alice) fetch the EXACT SAME 16 sealed
  // SubtreePages in the EXACT SAME deterministic order (zero multi-sync intersection attack!)
  const strictRun1Log = [];
  const strictStore1 = new CompactWalletStore(0, 0n);
  const res1 = await syncCompactStoreWithRpc({
    store: strictStore1,
    fvk,
    fetchBatch: makeSliceFetcher(fix20.accounts, strictRun1Log),
  });
  assert.equal(res1.discoveredNotes, 1);
  assert.equal(strictStore1.notes[0].spent, true);
  assert.ok(strictStore1.notes[0].frozenIntraSiblings);

  const strictRun2Log = [];
  const strictStore2 = new CompactWalletStore(0, 0n);
  await syncCompactStoreWithRpc({
    store: strictStore2,
    fvk,
    fetchBatch: makeSliceFetcher(fix20.accounts, strictRun2Log),
  });

  const sealedRun1 = strictRun1Log.flatMap((e) => e.addrs).filter((a) => fix20.sealedSubAddrs.has(a));
  const sealedRun2 = strictRun2Log.flatMap((e) => e.addrs).filter((a) => fix20.sealedSubAddrs.has(a));
  assert.equal(sealedRun1.length, 16);
  assert.equal(sealedRun1.includes(fix20.hitSubAddr), true);
  assert.deepEqual(
    sealedRun1,
    sealedRun2,
    'deterministic wallet-keyed decoys must yield identical 16-page set & order across repeated syncs',
  );

  // A2: 0-hit wallet (Bob) on the SAME large catch-up ALSO fetches exactly 16 sealed SubtreePages
  // (uniform batch count independent of hit count) with a distinct wallet-keyed decoy set!
  const bobStrictLog = [];
  const bobStore = new CompactWalletStore(0, 0n);
  const bobRes = await syncCompactStoreWithRpc({
    store: bobStore,
    fvk: bobFvk,
    fetchBatch: makeSliceFetcher(fix20.accounts, bobStrictLog),
  });
  assert.equal(bobRes.discoveredNotes, 0);
  const bobSealed = bobStrictLog.flatMap((e) => e.addrs).filter((a) => fix20.sealedSubAddrs.has(a));
  assert.equal(
    bobSealed.length,
    16,
    '0-hit wallet on large strict catch-up must fetch same uniform 16-page sealed batch as 1-hit wallet',
  );
  assert.notDeepEqual(bobSealed, sealedRun1, 'distinct wallets must derive distinct deterministic decoy sets');

  // A3: Decoy-padded reconstructWitness() fetches ALL active lanes' SubtreeRootPages, ALL active
  // lanes' unsealed frontier SubtreePages (zero laneId leak), AND exactly 16 HRW sealed SubtreePages!
  const rwStrictLog = [];
  const rwStrict = await reconstructWitness({
    fetchBatch: makeSliceFetcher(fix20.accounts, rwStrictLog),
    poolId: 0,
    laneId: 2,
    leafIdx: aliceLeafIdx,
    viewSk: alice.viewSk,
  });
  assert.equal(rwStrict.superRoot, fix20.superRoot);
  assert.equal(rwStrict.rootRingKind, ROOT_RING_EPOCH);
  assert.equal(rwStrict.rootRingIdx, 0);
  assert.equal(computeMerkleRoot4Ary(rwStrict.path, aliceCm), fix20.superRoot);
  const rwFetchedAll = new Set(rwStrictLog.flatMap((e) => e.addrs));
  const rwFetchedSealed = new Set([...rwFetchedAll].filter((a) => fix20.sealedSubAddrs.has(a)));
  assert.equal(rwFetchedSealed.has(fix20.hitSubAddr), true);
  assert.equal(
    rwFetchedSealed.size,
    16,
    'reconstructWitness() in strict mode must fetch exactly min(16, totalSealed) = 16 sealed SubtreePages',
  );
  for (let l = 0; l < 4; l++) {
    assert.equal(
      rwFetchedAll.has(deriveSubtreePdaSync(0, l, 5n).address),
      true,
      `strict reconstructWitness must uniformly fetch active lane ${l}'s unsealed frontier`,
    );
    assert.equal(
      rwFetchedAll.has(deriveSubrootPdaSync(0, l, 0n).address),
      true,
      `strict reconstructWitness must uniformly fetch active lane ${l}'s SubtreeRootPage`,
    );
  }

  // Repeat reconstructWitness with same viewSk fetches the exact same SubtreePage set (intersection-resistant)
  const rwStrictLog2 = [];
  await reconstructWitness({
    fetchBatch: makeSliceFetcher(fix20.accounts, rwStrictLog2),
    poolId: 0,
    laneId: 2,
    leafIdx: aliceLeafIdx,
    viewSk: alice.viewSk,
  });
  const rwFetchedSubs2 = new Set(rwStrictLog2.flatMap((e) => e.addrs).filter((a) => fix20.allSubAddrs.has(a)));
  const rwFetchedSubs = new Set([...rwFetchedAll].filter((a) => fix20.allSubAddrs.has(a)));
  assert.deepEqual([...rwFetchedSubs].sort(), [...rwFetchedSubs2].sort());

  // Spending a DIFFERENT note in the SAME epoch uses witness-scoped decoys (no symmetric-difference intersection!)
  const rwOtherLog = [];
  await reconstructWitness({
    fetchBatch: makeSliceFetcher(fix20.accounts, rwOtherLog),
    poolId: 0,
    laneId: 0,
    leafIdx: 3n * BigInt(SUBTREE_LEAVES) + 10n,
    viewSk: alice.viewSk,
  });
  const rwOtherSealed = new Set(rwOtherLog.flatMap((e) => e.addrs).filter((a) => fix20.sealedSubAddrs.has(a)));
  assert.equal(rwOtherSealed.size, 16);
  const symDiff = new Set([
    ...[...rwFetchedSealed].filter((x) => !rwOtherSealed.has(x)),
    ...[...rwOtherSealed].filter((x) => !rwFetchedSealed.has(x)),
  ]);
  assert.ok(symDiff.size > 4, `witness-scoped HRW decoys must diverge across distinct spends (symDiff=${symDiff.size})`);

  // A3b: Pass 1D dropped-SubtreePage watermark rollback oracle closed (hit drop vs decoy drop):
  // Dropping EITHER the hit page OR a decoy page withholds nextMemoLeaf & nextNfIndex across ALL
  // lanes identically, and produces 100% IDENTICAL Sync #2 RPC batches!
  const decoyToDrop = sealedRun1.find((a) => a !== fix20.hitSubAddr);
  assert.ok(decoyToDrop);
  const makeDropFetcher = (dropAddr, log) => async (addrs, opts) => {
    log.push({ addrs: [...addrs], dataSlice: opts?.dataSlice ?? null });
    return addrs.map((a) => {
      if (a === dropAddr) return null;
      const full = fix20.accounts.get(a) ?? null;
      if (!full || !opts?.dataSlice) return full;
      return full.slice(opts.dataSlice.offset, opts.dataSlice.offset + opts.dataSlice.length);
    });
  };
  const hitDropStore = new CompactWalletStore(0, 0n);
  const hitDropRes = await syncCompactStoreWithRpc({
    store: hitDropStore,
    fvk,
    fetchBatch: makeDropFetcher(fix20.hitSubAddr, []),
  });
  const decoyDropStore = new CompactWalletStore(0, 0n);
  const decoyDropRes = await syncCompactStoreWithRpc({
    store: decoyDropStore,
    fvk,
    fetchBatch: makeDropFetcher(decoyToDrop, []),
  });
  assert.equal(hitDropRes.discoveredNotes, 0, 'R1-C3: Pass 1D hit drop must return discoveredNotes === 0');
  assert.equal(decoyDropRes.discoveredNotes, 0, 'R1-C3: Pass 1D decoy drop must return discoveredNotes === 0');
  assert.equal(hitDropStore.notes.length, 0, 'R1-C3: Pass 1D hit drop must leave store.notes untouched');
  assert.equal(decoyDropStore.notes.length, 0, 'R1-C3: Pass 1D decoy drop must leave store.notes untouched');
  for (let l = 0; l < 4; l++) {
    assert.equal(hitDropStore.lanes[l].nextMemoLeaf, 0n);
    assert.equal(decoyDropStore.lanes[l].nextMemoLeaf, 0n);
    assert.equal(hitDropStore.lanes[l].nextNfIndex, 0n);
    assert.equal(decoyDropStore.lanes[l].nextNfIndex, 0n);
  }
  const hitRetryLog = [];
  await syncCompactStoreWithRpc({ store: hitDropStore, fvk, fetchBatch: makeSliceFetcher(fix20.accounts, hitRetryLog) });
  const decoyRetryLog = [];
  await syncCompactStoreWithRpc({ store: decoyDropStore, fvk, fetchBatch: makeSliceFetcher(fix20.accounts, decoyRetryLog) });
  assert.deepEqual(
    hitRetryLog,
    decoyRetryLog,
    'Sync #2 RPC traffic MUST be 100% identical after Pass 1D hit drop vs decoy drop',
  );
  assert.equal(hitDropStore.notes[0].spent, true);
  assert.equal(decoyDropStore.notes[0].spent, true);

  // A3c: Dead-code fix regression — incremental sync (<= 25 memos & <= 25 subtrees) with an older
  // unfrozen note in a sealed subtree MUST decoy-pad to 16 sealed SubtreePages (never 1-page pinpoint!)
  const incStore = new CompactWalletStore(0, 0n);
  for (let l = 0; l < 4; l++) {
    incStore.lanes[l].nextMemoLeaf = BigInt(5 * SUBTREE_LEAVES + 4);
    incStore.lanes[l].finalizedSubroots = Array.from({ length: 5 }, (_, s) =>
      frToBeBytes(l === 2 && BigInt(s) === aliceSubSeq ? hitSubRoot : dummySubRoot),
    );
  }
  incStore.recordVerifiedMemo({
    fvk,
    laneId: 2,
    leafIdx: aliceLeafIdx, // older sealed SubtreePage (2, 1), NOT frozen yet!
    decrypted: {
      amount: 8_888_888n,
      mint: WSOL_MINT_BYTES,
      tweak,
      blinding,
      memoVersion: MEMO_VERSION_V1,
      memoFlags: 0,
      paymentId: new Uint8Array(MEMO_PAYMENT_ID_LEN),
      isDynamic: false,
    },
    cmBe: frToBeBytes(aliceCm),
  });
  assert.equal(incStore.notes[0].frozenIntraSiblings, null);
  const incUnfrozenLog = [];
  await syncCompactStoreWithRpc({
    store: incStore,
    fvk,
    fetchBatch: makeSliceFetcher(fix20.accounts, incUnfrozenLog),
  });
  const incSealedFetched = new Set(
    incUnfrozenLog.flatMap((e) => e.addrs).filter((a) => fix20.sealedSubAddrs.has(a)),
  );
  assert.equal(incSealedFetched.has(fix20.hitSubAddr), true);
  assert.equal(
    incSealedFetched.size,
    16,
    'incremental sync freezing an older sealed note MUST decoy-pad to 16 sealed SubtreePages',
  );
  assert.ok(incStore.notes[0].frozenIntraSiblings);

  // A3d: Rendezvous (HRW) stability across +1 sealed subtree growth within epochBucket = 0
  const hrw32 = selectHrwSealedDecoys({
    viewSk: new Uint8Array(32).fill(0x42),
    scope: new TextEncoder().encode('sync'),
    epochBucket: 0n,
    sealedByLane: [
      { laneId: 0, sealedCount: 8n },
      { laneId: 1, sealedCount: 8n },
      { laneId: 2, sealedCount: 8n },
      { laneId: 3, sealedCount: 8n },
    ],
    alreadySelected: new Set(),
    targetSealed: 16,
  });
  const hrw33 = selectHrwSealedDecoys({
    viewSk: new Uint8Array(32).fill(0x42),
    scope: new TextEncoder().encode('sync'),
    epochBucket: 0n,
    sealedByLane: [
      { laneId: 0, sealedCount: 9n },
      { laneId: 1, sealedCount: 8n },
      { laneId: 2, sealedCount: 8n },
      { laneId: 3, sealedCount: 8n },
    ],
    alreadySelected: new Set(),
    targetSealed: 16,
  });
  const set32 = new Set(hrw32.map((d) => `${d.laneId}:${d.pageSeq}`));
  const overlap32_33 = hrw33.filter((d) => set32.has(`${d.laneId}:${d.pageSeq}`)).length;
  assert.ok(overlap32_33 >= 15, `HRW +1 growth must preserve >= 15/16 decoys, got ${overlap32_33}/16`);

  // Opt-in fast reconstructWitness fetches minimal SubtreePages (target + frontier = 2)
  const rwFastLog = [];
  const rwFast = await reconstructWitness({
    fetchBatch: makeSliceFetcher(fix20.accounts, rwFastLog),
    poolId: 0,
    laneId: 2,
    leafIdx: aliceLeafIdx,
    privacyMode: 'fast',
  });
  assert.equal(computeMerkleRoot4Ary(rwFast.path, aliceCm), fix20.superRoot);
  const rwFastSubs = new Set(rwFastLog.flatMap((e) => e.addrs).filter((a) => fix20.allSubAddrs.has(a)));
  assert.equal(rwFastSubs.size, 2);

  // A4: Opt-in `privacyMode: 'fast'` on > 25 MemoPages uses 3,328 B dataSlice & still runs full Pass 2!
  const fast20Log = [];
  const fast20Store = new CompactWalletStore(0, 0n);
  const resFast20 = await syncCompactStoreWithRpc({
    store: fast20Store,
    fvk,
    fetchBatch: makeSliceFetcher(fix20.accounts, fast20Log),
    privacyMode: 'fast',
  });
  assert.equal(resFast20.discoveredNotes, 1);
  assert.equal(fast20Store.notes[0].spent, true);
  const fastSliceCalls = fast20Log.filter(
    (e) => e.dataSlice?.offset === 0 && e.dataSlice?.length === MEMO_PAGE_SCAN_SLICE_LEN,
  );
  assert.ok(fastSliceCalls.length >= 1, 'fast mode on > 25 MemoPages must use dataSlice(0, 3328)');
  assert.equal(new Set(fastSliceCalls.flatMap((e) => e.addrs)).size, 56);
  const fastFullMemos = fast20Log
    .filter((e) => e.dataSlice === null)
    .flatMap((e) => e.addrs)
    .filter((a) => fix20.allMemoAddrs.has(a));
  assert.deepEqual(fastFullMemos, [fix20.hitMemoAddr]);
  assert.equal(new Set(fast20Log.flatMap((e) => e.addrs).filter((a) => fix20.allNfAddrs.has(a))).size, 3);
});

test('computePageRollovers exact boundaries (93..96, 254..256, 598..600, 76798..76800)', () => {
  // MemoPage boundary (96) with 3 outputs
  assert.deepEqual(
    computePageRollovers({ leafCount: 93, outputCount: 3, nfCount: 0, spentNullifiers: 2 }),
    { outSubSeq: 0, outRootSeq: 0, outMemoSeq: 0, nfPageSeq: 0 },
  );
  assert.deepEqual(
    computePageRollovers({ leafCount: 94, outputCount: 3, nfCount: 0, spentNullifiers: 2 }),
    { outSubSeq: 0, outRootSeq: 0, outMemoSeq: 0, nfPageSeq: 0, nextMemoSeq: 1 },
  );
  assert.deepEqual(
    computePageRollovers({ leafCount: 95, outputCount: 3, nfCount: 0, spentNullifiers: 2 }),
    { outSubSeq: 0, outRootSeq: 0, outMemoSeq: 0, nfPageSeq: 0, nextMemoSeq: 1 },
  );
  assert.deepEqual(
    computePageRollovers({ leafCount: 96, outputCount: 3, nfCount: 0, spentNullifiers: 2 }),
    { outSubSeq: 0, outRootSeq: 0, outMemoSeq: 1, nfPageSeq: 0 },
  );
  // MemoPage boundary (96) with 2 outputs
  assert.deepEqual(
    computePageRollovers({ leafCount: 94, outputCount: 2, nfCount: 0, spentNullifiers: 1 }),
    { outSubSeq: 0, outRootSeq: 0, outMemoSeq: 0, nfPageSeq: 0 },
  );
  assert.deepEqual(
    computePageRollovers({ leafCount: 95, outputCount: 2, nfCount: 0, spentNullifiers: 1 }),
    { outSubSeq: 0, outRootSeq: 0, outMemoSeq: 0, nfPageSeq: 0, nextMemoSeq: 1 },
  );

  // SubtreePage boundary (256)
  assert.deepEqual(
    computePageRollovers({ leafCount: 254n, outputCount: 2, nfCount: 0n, spentNullifiers: 1 }),
    { outSubSeq: 0, outRootSeq: 0, outMemoSeq: 2, nfPageSeq: 0 },
  );
  assert.deepEqual(
    computePageRollovers({ leafCount: 254n, outputCount: 3, nfCount: 0n, spentNullifiers: 2 }),
    { outSubSeq: 0, outRootSeq: 0, outMemoSeq: 2, nfPageSeq: 0, nextSubSeq: 1 },
  );
  assert.deepEqual(
    computePageRollovers({ leafCount: 255n, outputCount: 2, nfCount: 0n, spentNullifiers: 2 }),
    { outSubSeq: 0, outRootSeq: 0, outMemoSeq: 2, nfPageSeq: 0, nextSubSeq: 1 },
  );
  assert.deepEqual(
    computePageRollovers({ leafCount: 256n, outputCount: 3, nfCount: 0n, spentNullifiers: 2 }),
    { outSubSeq: 1, outRootSeq: 0, outMemoSeq: 2, nfPageSeq: 0 },
  );

  // NullifierPage boundary (600)
  assert.deepEqual(
    computePageRollovers({ leafCount: 0, outputCount: 0, nfCount: 598, spentNullifiers: 2 }),
    { outSubSeq: 0, outRootSeq: 0, outMemoSeq: 0, nfPageSeq: 0 },
  );
  assert.deepEqual(
    computePageRollovers({ leafCount: 0, outputCount: 0, nfCount: 599, spentNullifiers: 2 }),
    { outSubSeq: 0, outRootSeq: 0, outMemoSeq: 0, nfPageSeq: 0, nextNfSeq: 1 },
  );
  assert.deepEqual(
    computePageRollovers({ leafCount: 0, outputCount: 0, nfCount: 599, spentNullifiers: 1 }),
    { outSubSeq: 0, outRootSeq: 0, outMemoSeq: 0, nfPageSeq: 0 },
  );
  assert.deepEqual(
    computePageRollovers({ leafCount: 0, outputCount: 0, nfCount: 600, spentNullifiers: 2 }),
    { outSubSeq: 0, outRootSeq: 0, outMemoSeq: 0, nfPageSeq: 1 },
  );

  // SubtreeRootPage boundary (300 * 256 = 76,800; 76,799 / 96 = 799 rem 95 -> also rolls MemoPage 799 -> 800!)
  assert.deepEqual(
    computePageRollovers({ leafCount: 76_799n, outputCount: 2, nfCount: 0n, spentNullifiers: 1 }),
    {
      outSubSeq: 299,
      outRootSeq: 0,
      outMemoSeq: 799,
      nfPageSeq: 0,
      nextSubSeq: 300,
      nextRootSeq: 1,
      nextMemoSeq: 800,
    },
  );
  assert.deepEqual(
    computePageRollovers({ leafCount: 76_800n, outputCount: 2, nfCount: 0n, spentNullifiers: 1 }),
    { outSubSeq: 300, outRootSeq: 1, outMemoSeq: 800, nfPageSeq: 0 },
  );
});

test('pickRandomLaneId and pickRandomEscrowShard sample uniformly within valid bounds', () => {
  const seenLanes = new Set();
  for (let i = 0; i < 200; i++) {
    const l = pickRandomLaneId(4);
    assert.ok(Number.isInteger(l) && l >= 0 && l < 4);
    seenLanes.add(l);
  }
  assert.equal(seenLanes.size, 4);

  const seenShards = new Set();
  for (let i = 0; i < 400; i++) {
    const s = pickRandomEscrowShard();
    assert.ok(Number.isInteger(s) && s >= 0 && s < NUM_ESCROW_SHARDS);
    seenShards.add(s);
  }
  assert.equal(seenShards.size, NUM_ESCROW_SHARDS);

  assert.equal(pickRandomLaneId(1), 0);
  assert.equal(pickRandomEscrowShard(1), 0);
  assert.throws(() => pickRandomLaneId(0), RangeError);
  assert.throws(() => pickRandomLaneId(17), RangeError);
  assert.throws(() => pickRandomEscrowShard(0), RangeError);
  assert.throws(() => pickRandomEscrowShard(17), RangeError);
});

test('AudrenRelayClient supports transfer privacy, zero-crank info, and multi-ix submitRelayedInstruction', async () => {
  const calls = [];
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    if (String(url).includes('/v1/info')) {
      return new Response(
        JSON.stringify({
          protocolVersion: 1,
          cluster: 'mainnet',
          relayerPubkey: SYSTEM_PROGRAM_ID,
          rootsPda: deriveRootsPdaSync(0).address,
          rootHistory: { rootsPda: deriveRootsPdaSync(0).address, slotCount: 12, epochCount: 3 },
          balanceSol: 5.0,
          rentSchedule: null,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    if (String(url).includes('/v1/relay/submit')) {
      return new Response(
        JSON.stringify({ signature: 'batchSig999', cluster: 'mainnet', relayerPubkey: SYSTEM_PROGRAM_ID }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    return new Response(
      JSON.stringify({
        ok: true,
        cluster: 'mainnet',
        op: 'transfer',
        billingMode: 'self_paying',
        feeSide: 'shielded_cm2',
        feeMint: WSOL_MINT,
        feeTokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
        feeRecipient: null,
        feeShieldedAddress: 'aud1test',
        feeRecipientExists: true,
        needsFeeAtaSetup: false,
        relayerFee: '5000000',
        feeBps: 0,
        estimatedRelayCostLamports: '5000000',
        estimatedRelayCostUsd: 0.75,
        reason: 'ok',
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  };

  try {
    const client = new AudrenRelayClient('https://relay.example.test');
    assert.equal('requestCheckpoint' in client, false, 'v1.3.0 relayer client has no checkpoint crank method');
    await client.getFeeQuote({
      cluster: 'mainnet',
      op: 'transfer',
      mint: WSOL_MINT,
      amount: '999999999',
      outputCount: 3,
      omitNf1: false,
    });
    const transferUrl = new URL(calls[0].url);
    assert.equal(transferUrl.pathname, '/v1/fee-quote');
    assert.equal(transferUrl.searchParams.has('amount'), false, 'transfer fee-quote must NEVER send amount');

    await client.getFeeQuote({
      op: 'withdraw',
      mint: WSOL_MINT,
      amount: '50000000',
      omitNf1: true,
      relayerPubkey: 'PinnedRelayer1111111111111111111111111111111',
    });
    const withdrawUrl = new URL(calls[1].url);
    assert.equal(withdrawUrl.searchParams.get('amount'), '50000000');
    assert.equal(withdrawUrl.searchParams.get('omitNf1'), 'true');
    assert.equal(
      withdrawUrl.searchParams.get('relayerPubkey'),
      'PinnedRelayer1111111111111111111111111111111',
    );

    await client.quoteSwap({
      inputMint: WSOL_MINT,
      outputMint: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
      amount: '1000000',
      relayerPubkey: 'PinnedRelayer1111111111111111111111111111111',
    });
    const swapQuoteUrl = new URL(calls[2].url);
    assert.equal(
      swapQuoteUrl.searchParams.get('relayerPubkey'),
      'PinnedRelayer1111111111111111111111111111111',
    );

    await client.buildSwapInstructions({
      provider: 'jupiter',
      quoteResponse: { route: [] },
      inputMint: WSOL_MINT,
      outputMint: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
      relayerPubkey: 'PinnedRelayer1111111111111111111111111111111',
    });
    assert.equal(
      JSON.parse(calls[3].init.body).relayerPubkey,
      'PinnedRelayer1111111111111111111111111111111',
    );

    const info = await client.getInfo('mainnet');
    assert.equal(info.rootsPda, deriveRootsPdaSync(0).address);
    assert.equal(info.rootHistory?.slotCount, 12);

    // Multi-ix batch submit (parallel 2 -> 1 private Transact merges in 1 Solana Tx v1)
    const batchRes = await client.submitRelayedInstruction({
      cluster: 'mainnet',
      instructions: [
        { instructionDataB64: 'AQID', accounts: [{ pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false }] },
        { instructionDataB64: 'BAUG', accounts: [{ pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false }] },
      ],
    });
    assert.equal(batchRes.signature, 'batchSig999');
    const submittedBody = JSON.parse(calls[5].init.body);
    assert.equal(submittedBody.instructions.length, 2);

    // Reject empty submit payload
    await assert.rejects(() => client.submitRelayedInstruction({ cluster: 'mainnet' }), /requires either/);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('R1-C1/C2/C4: strict reconstructWitness drop/truncation oracle, untrusted-RPC bounds, store validation, and HRW 63->64->65 stability', async () => {
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x5a));
  const fvk = exportFullViewingKey(alice);

  const dummyLeaves = Array.from({ length: SUBTREE_LEAVES }, (_, i) => BigInt(i + 5));
  const dummySubroot = computeSubtree256Root(dummyLeaves, SUBTREE_LEAVES);
  const dummyFrontier = dummyLeaves.slice(0, 4);

  // Build 4-lane fixture (5 sealed + 4 frontier per lane = 20 sealed total)
  const accounts = new Map();
  const sealedSubAddrs = new Set();
  const laneRoots = Array.from({ length: NUM_LANES }, () => ZERO_HASHES_4ARY[18]);
  const laneCounts = new Array(NUM_LANES).fill(0n);

  for (let l = 0; l < 4; l++) {
    const sealedCnt = 5;
    const leavesPerLane = sealedCnt * SUBTREE_LEAVES + 4;
    laneCounts[l] = BigInt(leavesPerLane);
    accounts.set(
      deriveSubrootPdaSync(0, l, 0n).address,
      makeSubrootPage(l, 0n, Array.from({ length: sealedCnt }, () => dummySubroot)),
    );
    const allLaneLeaves = [];
    for (let s = 0; s < sealedCnt; s++) {
      const addr = deriveSubtreePdaSync(0, l, BigInt(s)).address;
      sealedSubAddrs.add(addr);
      accounts.set(addr, makeSubtreePage(l, BigInt(s), dummyLeaves));
      allLaneLeaves.push(...dummyLeaves);
    }
    accounts.set(
      deriveSubtreePdaSync(0, l, BigInt(sealedCnt)).address,
      makeSubtreePage(l, BigInt(sealedCnt), dummyFrontier),
    );
    allLaneLeaves.push(...dummyFrontier);
    laneRoots[l] = computeLaneRootFromLeaves(allLaneLeaves);
  }
  const { superRoot, raw: rootsRaw } = makeSyntheticRootHistory({ laneRoots, laneCounts });
  const rootsAddr = deriveRootsPdaSync(0).address;
  accounts.set(rootsAddr, rootsRaw);

  const fetched = [];
  const baseFetch = async (addrs) => {
    fetched.push(...addrs);
    return addrs.map((a) => accounts.get(a) ?? null);
  };

  // R1-C1a: Missing viewSk in 'strict' mode MUST throw
  await assert.rejects(
    () =>
      reconstructWitness({
        fetchBatch: baseFetch,
        poolId: 0,
        laneId: 2,
        leafIdx: 300n,
      }),
    /viewSk/,
  );

  // Baseline succeeds with viewSk
  const okRes = await reconstructWitness({
    fetchBatch: baseFetch,
    poolId: 0,
    laneId: 2,
    leafIdx: 300n,
    viewSk: alice.viewSk,
  });
  assert.equal(okRes.superRoot, superRoot);

  const targetSubAddr = deriveSubtreePdaSync(0, 2, 1n).address;
  const decoySubToDrop = fetched.find((a) => sealedSubAddrs.has(a) && a !== targetSubAddr);
  assert.ok(decoySubToDrop);

  // R1-C1b: Dropping a DECOY SubtreePage MUST throw uniformly in 'strict' mode
  await assert.rejects(
    () =>
      reconstructWitness({
        fetchBatch: async (addrs) => addrs.map((a) => (a === decoySubToDrop ? null : accounts.get(a) ?? null)),
        poolId: 0,
        laneId: 2,
        leafIdx: 300n,
        viewSk: alice.viewSk,
      }),
    /SubtreePage missing/,
  );

  // R1-C1c: Dropping a non-target lane's SubtreeRootPage (lane 0 while spending lane 2) MUST throw
  const nonTargetSr = deriveSubrootPdaSync(0, 0, 0n).address;
  await assert.rejects(
    () =>
      reconstructWitness({
        fetchBatch: async (addrs) => addrs.map((a) => (a === nonTargetSr ? null : accounts.get(a) ?? null)),
        poolId: 0,
        laneId: 2,
        leafIdx: 300n,
        viewSk: alice.viewSk,
      }),
    /SubtreeRootPage missing/,
  );

  // R1-C1d: Truncated decoy SubtreePage count (< 256) MUST throw
  const truncDecoy = accounts.get(decoySubToDrop).slice();
  new DataView(truncDecoy.buffer).setUint16(SB_OFF_COUNT, 255, true);
  await assert.rejects(
    () =>
      reconstructWitness({
        fetchBatch: async (addrs) =>
          addrs.map((a) => (a === decoySubToDrop ? truncDecoy : accounts.get(a) ?? null)),
        poolId: 0,
        laneId: 2,
        leafIdx: 300n,
        viewSk: alice.viewSk,
      }),
    /SubtreePage truncated/,
  );

  // R1-C1e: Tampered GlobalRootHistory superRoot (matching ring entry but wrong Merkle rollup) MUST throw root mismatch
  const badRoots = rootsRaw.slice();
  const fakeSr = frToBeBytes(999_999n);
  badRoots.set(fakeSr, RT_OFF_STABLE_SUPER_ROOT);
  badRoots.set(fakeSr, RT_OFF_EPOCH_RING);
  await assert.rejects(
    () =>
      reconstructWitness({
        fetchBatch: async (addrs) => addrs.map((a) => (a === rootsAddr ? badRoots : accounts.get(a) ?? null)),
        poolId: 0,
        laneId: 2,
        leafIdx: 300n,
        viewSk: alice.viewSk,
      }),
    /Merkle root mismatch/,
  );

  // --- R1-C2: Untrusted RPC account decoders & store validation ---
  assert.throws(() => decodePoolState(makePoolState(17)), /activeLanes/);
  assert.throws(() => decodeLaneHeader(makeLaneState(16, 0n, 0n)), /laneId/);
  assert.throws(() => decodeLaneHeader(makeLaneState(0, (1n << 36n) + 1n, 0n)), /nextLeaf/);

  const hugeRoots = rootsRaw.slice();
  new DataView(hugeRoots.buffer).setBigUint64(RT_OFF_LATEST_LANE_COUNTS, (1n << 36n) + 1n, true);
  assert.throws(() => decodeGlobalRootHistory(hugeRoots), /latestLaneCounts/);
  const hugeStableRoots = rootsRaw.slice();
  new DataView(hugeStableRoots.buffer).setBigUint64(RT_OFF_STABLE_LANE_COUNTS, (1n << 36n) + 1n, true);
  assert.throws(() => decodeGlobalRootHistory(hugeStableRoots), /stableLaneCounts/);

  const badSub = makeSubtreePage(0, 0n, []);
  new DataView(badSub.buffer).setUint16(SB_OFF_COUNT, SUBTREE_LEAVES + 1, true);
  assert.throws(() => decodeSubtreePage(badSub), /count/);

  const badSr = makeSubrootPage(0, 0n, []);
  new DataView(badSr.buffer).setUint16(SR_OFF_COUNT, 301, true);
  assert.throws(() => decodeSubtreeRootPage(badSr), /count/);

  const badMemo = makeMemoPage(MEMO_NOTES_PER_PAGE + 1);
  assert.throws(() => decodeMemoPage(badMemo), /count/);
  assert.throws(() => decodeMemoPageScanSlice(badMemo.slice(0, MEMO_PAGE_SCAN_SLICE_LEN)), /count/);

  const badNf = makeNfPage(0, 0n, []);
  new DataView(badNf.buffer).setUint16(NF_OFF_COUNT, NF_PER_PAGE + 1, true);
  assert.throws(() => decodeNullifierPage(badNf), /count/);

  // fetchPoolAndLanes rejects lane_hdr.laneId !== expected_l
  const poolPda = derivePoolPdaSync(0).address;
  const lane0Pda = deriveLanePdaSync(0, 0).address;
  const lane1Pda = deriveLanePdaSync(0, 1).address;
  await assert.rejects(
    () =>
      fetchPoolAndLanes(async (addrs) =>
        addrs.map((a) => {
          if (a === poolPda) return makePoolState(2);
          if (a === lane0Pda) return makeLaneState(0, 0n, 0n);
          if (a === lane1Pda) return makeLaneState(5, 0n, 0n);
          return null;
        }),
      ),
    /laneId mismatch/,
  );

  // CompactWalletStore.fromJSON strictly requires lanes.length === 16 & rejects absurd pageSeq jumps
  assert.throws(
    () => CompactWalletStore.fromJSON(JSON.stringify({ poolId: 0, birthdaySlot: '0', lanes: [], notes: [] })),
    /expected 16 lanes/,
  );
  const storeJump = new CompactWalletStore(0, 0n);
  const validSr1 = makeSubrootPage(0, 10_000n, [dummySubroot]);
  assert.throws(
    () => storeJump.ingestSubrootPages({ laneId: 0, subrootPages: [{ rootPageSeq: 10_000n, raw: validSr1 }] }),
    /jump exceeds limit/,
  );

  // --- R1-C4: Default epochBucket = 0n retains >= 14/16 HRW decoy overlap across 63 -> 64 -> 65 ---
  const runSyncSealed = async (counts) => {
    const acc = new Map();
    const allSealed = new Set();
    acc.set(derivePoolPdaSync(0).address, makePoolState(4));
    for (let l = 0; l < 4; l++) {
      const sc = counts[l];
      const totalLeaves = sc * SUBTREE_LEAVES;
      const roots = Array.from({ length: sc }, () => dummySubroot);
      acc.set(
        deriveLanePdaSync(0, l).address,
        makeLaneState(l, BigInt(totalLeaves), 0n, computeLaneRootFromSubroots(roots)),
      );
      acc.set(deriveSubrootPdaSync(0, l, 0n).address, makeSubrootPage(l, 0n, roots));
      for (let s = 0; s < sc; s++) {
        const addr = deriveSubtreePdaSync(0, l, BigInt(s)).address;
        allSealed.add(addr);
        acc.set(addr, makeSubtreePage(l, BigInt(s), dummyLeaves));
      }
      const memos = Math.ceil(totalLeaves / MEMO_NOTES_PER_PAGE);
      for (let m = 0; m < memos; m++) {
        const cnt = Math.min(MEMO_NOTES_PER_PAGE, totalLeaves - m * MEMO_NOTES_PER_PAGE);
        acc.set(deriveMemoPdaSync(0, l, BigInt(m)).address, makeMemoPageWithMeta(l, BigInt(m), cnt));
      }
    }
    const fetchedSealed = new Set();
    const st = new CompactWalletStore(0, 0n);
    await syncCompactStoreWithRpc({
      store: st,
      fvk,
      fetchBatch: async (addrs) => {
        for (const a of addrs) if (allSealed.has(a)) fetchedSealed.add(a);
        return addrs.map((a) => acc.get(a) ?? null);
      },
    });
    assert.equal(fetchedSealed.size, 16);
    return fetchedSealed;
  };
  const s63 = await runSyncSealed([16, 16, 16, 15]);
  const s64 = await runSyncSealed([16, 16, 16, 16]);
  const s65 = await runSyncSealed([17, 16, 16, 16]);
  const ov63_64 = [...s63].filter((x) => s64.has(x)).length;
  const ov64_65 = [...s64].filter((x) => s65.has(x)).length;
  const ov63_65 = [...s63].filter((x) => s65.has(x)).length;
  assert.ok(ov63_64 >= 15, `R1-C4: 63->64 overlap must be >= 15/16, got ${ov63_64}/16`);
  assert.ok(ov64_65 >= 15, `R1-C4: 64->65 overlap must be >= 15/16, got ${ov64_65}/16`);
  assert.ok(ov63_65 >= 14, `R1-C4: 63->65 overlap must be >= 14/16, got ${ov63_65}/16`);
});

test('R1-C5 & R1-R7: WASM prover rc=-6 rejection, TS integer/bounds parity, and Token-2022 unsafe self-pay checks', async () => {
  const seed = new Uint8Array(32).fill(0x21);
  const alice = deriveKeysFromSeed(seed);
  const u32Overflow = 0x1_0000_0000;
  const u64Overflow = 1n << 64n;

  // R1-C5.2: keys.ts u32 bounds
  assert.throws(() => deriveSubaccountKeys(seed, u32Overflow), RangeError);
  assert.throws(() => deriveSubaccountKeys(seed, -1), RangeError);
  assert.throws(() => deriveDefiSessionKeypair(seed, u32Overflow), RangeError);
  assert.throws(() => deriveDefiSessionKeypair(seed, -1), RangeError);

  // R1-C5.2: crypto.ts u64 bounds
  assert.throws(
    () => encryptNoteMemo(alice.viewPk, new Uint8Array(32).fill(1), -1n, WSOL_MINT_BYTES),
    RangeError,
  );
  assert.throws(
    () => encryptNoteMemo(alice.viewPk, new Uint8Array(32).fill(1), u64Overflow, WSOL_MINT_BYTES),
    RangeError,
  );

  // R1-C5.2: prover.ts encodeJoinsplitWitness u64 & Merkle position bounds
  const asset = deriveAssetId(WSOL_MINT_BYTES);
  const makeBadWitness = (overrides = {}) => ({
    superRoot: 0n,
    txAssetId: asset,
    publicAssetId: asset,
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    ctxHash: 0n,
    omitNf1: true,
    inputs: [dummyInputWitness(alice.spendSk, asset, 1n), dummyInputWitness(alice.spendSk, asset, 2n)],
    outputs: [
      dummyOutputWitness(asset, 3n),
      dummyOutputWitness(asset, 4n),
      dummyOutputWitness(asset, 5n),
    ],
    ...overrides,
  });
  assert.throws(() => encodeJoinsplitWitness(makeBadWitness({ publicAmountOut: u64Overflow })), RangeError);
  assert.throws(() => encodeJoinsplitWitness(makeBadWitness({ relayerFeeAmount: -1n })), RangeError);
  const badIn = dummyInputWitness(alice.spendSk, asset, 1n);
  badIn.amount = u64Overflow;
  assert.throws(
    () => encodeJoinsplitWitness(makeBadWitness({ inputs: [badIn, dummyInputWitness(alice.spendSk, asset, 2n)] })),
    RangeError,
  );
  const badPosIn = dummyInputWitness(alice.spendSk, asset, 1n);
  badPosIn.merklePath.positions[0] = 4;
  assert.throws(
    () => encodeJoinsplitWitness(makeBadWitness({ inputs: [badPosIn, dummyInputWitness(alice.spendSk, asset, 2n)] })),
    RangeError,
  );

  // R1-C5.1: AudrenWasmProver rejects unsatisfied R1CS witness with exact rc=-6 error!
  const prover = await AudrenWasmProver.init();
  const unsatisfied = makeBadWitness({ publicAmountOut: 999_999n }); // 0 in != 999,999 out
  assert.throws(
    () => prover.proveJoinsplit(unsatisfied, new Uint8Array(32).fill(0x77)),
    /Groth16 witness failed off-chain R1CS verification \(rc=-6\)/,
  );

  // R1-C5.2: instructions.ts full Rust try_* parity bounds
  const z32 = new Uint8Array(32);
  const p192 = new Uint8Array(192);
  const head34 = new Uint8Array(34);
  const mask72 = new Uint8Array(72);

  assert.throws(
    () =>
      computeTransactCtxHash({
        poolId: 0,
        outLaneId: 0,
        outputMask: 0,
        assetMode: ASSET_MODE_PRIVATE,
        unwrapWsol: true,
        publicAssetId: z32,
        publicAmountOut: 0n,
        relayerFeeAmount: 0n,
        memosBytes: new Uint8Array(0),
      }),
    /unwrapWsol requires ASSET_MODE_PUBLIC/,
  );
  assert.throws(
    () =>
      computeTransactCtxHash({
        poolId: 0,
        outLaneId: 16,
        outputMask: 0,
        assetMode: ASSET_MODE_PRIVATE,
        unwrapWsol: false,
        publicAssetId: z32,
        publicAmountOut: 0n,
        relayerFeeAmount: 0n,
        memosBytes: new Uint8Array(0),
      }),
    RangeError,
  );
  assert.throws(
    () =>
      computeTransactCtxHash({
        poolId: 0,
        outLaneId: 0,
        outputMask: 8,
        assetMode: ASSET_MODE_PRIVATE,
        unwrapWsol: false,
        publicAssetId: z32,
        publicAmountOut: 0n,
        relayerFeeAmount: 0n,
        memosBytes: new Uint8Array(0),
      }),
    RangeError,
  );
  assert.throws(
    () =>
      buildTransactInstruction({
        payer: SYSTEM_PROGRAM_ID,
        poolId: 0,
        rootRingKind: ROOT_RING_EPOCH,
        rootRingIdx: 0,
        outLaneId: 0,
        outSubSeq: 0n,
        outRootSeq: 0n,
        outMemoSeq: 0n,
        outNfSeq: 0n,
        outputMask: 0,
        assetMode: ASSET_MODE_PRIVATE,
        unwrapWsol: true,
        proof192: p192,
        nf0: new Uint8Array(32).fill(1),
        nf1: z32,
        cm0: z32,
        cm1: z32,
        cm2: z32,
        publicAmountOut: 0n,
        relayerFeeAmount: 0n,
        memosBytes: new Uint8Array(0),
      }),
    /unwrapWsol requires ASSET_MODE_PUBLIC/,
  );
  // Strict rootRingKind / rootRingIdx validation in Transact & ExecViaEscrow
  for (const [badKind, badIdx] of [
    [2, 0],
    [-1, 0],
    [ROOT_RING_SLOT, SLOT_RING_LEN],
    [ROOT_RING_SLOT, -1],
    [ROOT_RING_EPOCH, EPOCH_RING_LEN],
    [ROOT_RING_EPOCH, -1],
  ]) {
    assert.throws(
      () =>
        buildTransactInstruction({
          payer: SYSTEM_PROGRAM_ID,
          poolId: 0,
          rootRingKind: badKind,
          rootRingIdx: badIdx,
          outLaneId: 0,
          outSubSeq: 0n,
          outRootSeq: 0n,
          outMemoSeq: 0n,
          outNfSeq: 0n,
          outputMask: 0,
          assetMode: ASSET_MODE_PRIVATE,
          proof192: p192,
          nf0: new Uint8Array(32).fill(1),
          nf1: z32,
          cm0: z32,
          cm1: z32,
          cm2: z32,
          publicAmountOut: 0n,
          relayerFeeAmount: 0n,
          memosBytes: new Uint8Array(0),
        }),
      RangeError,
    );
  }
  assert.throws(
    () =>
      computeExecCtxHash({
        poolId: 0,
        outLaneId: 0,
        escrowShard: 16,
        changeMask: 0,
        feeOnOutput: false,
        assetIn: z32,
        amountIn: 1n,
        relayerFeeAmount: 0n,
        assetOut: z32,
        minAmountOut: 1n,
        routerProg: SYSTEM_PROGRAM_ID,
        routerAccounts: [],
        outStealthOwner: z32,
        outBlinding: z32,
        dynMemoHead: head34,
        dynMemoMask: mask72,
        routerIxData: new Uint8Array(0),
        changeMemos: new Uint8Array(0),
      }),
    RangeError,
  );
  assert.throws(
    () =>
      computeExecCtxHash({
        poolId: 0,
        outLaneId: 0,
        escrowShard: 0,
        changeMask: 4,
        feeOnOutput: false,
        assetIn: z32,
        amountIn: 1n,
        relayerFeeAmount: 0n,
        assetOut: z32,
        minAmountOut: 1n,
        routerProg: SYSTEM_PROGRAM_ID,
        routerAccounts: [],
        outStealthOwner: z32,
        outBlinding: z32,
        dynMemoHead: head34,
        dynMemoMask: mask72,
        routerIxData: new Uint8Array(0),
        changeMemos: new Uint8Array(0),
      }),
    RangeError,
  );
  assert.throws(
    () =>
      computeExecCtxHash({
        poolId: 0,
        outLaneId: 0,
        escrowShard: 0,
        changeMask: 0,
        feeOnOutput: false,
        assetIn: z32,
        amountIn: 1n,
        relayerFeeAmount: 0n,
        assetOut: z32,
        minAmountOut: 1n,
        routerProg: SYSTEM_PROGRAM_ID,
        routerAccounts: [],
        outStealthOwner: z32,
        outBlinding: z32,
        dynMemoHead: head34,
        dynMemoMask: mask72,
        routerIxData: new Uint8Array(65_536),
        changeMemos: new Uint8Array(0),
      }),
    RangeError,
  );
  assert.throws(
    () =>
      buildInitPoolInstruction({
        payer: SYSTEM_PROGRAM_ID,
        poolId: u32Overflow,
        rootEpochInterval: 32n,
        noteRentFee: 0n,
        nfRentFee: 0n,
      }),
    RangeError,
  );
  assert.throws(
    () =>
      buildInitPoolInstruction({
        payer: SYSTEM_PROGRAM_ID,
        poolId: 0,
        rootEpochInterval: 0n,
        noteRentFee: 0n,
        nfRentFee: 0n,
      }),
    RangeError,
  );
  assert.throws(
    () =>
      buildInitPoolInstruction({
        payer: SYSTEM_PROGRAM_ID,
        poolId: 0,
        rootEpochInterval: MAX_ROOT_EPOCH_INTERVAL + 1n,
        noteRentFee: 0n,
        nfRentFee: 0n,
      }),
    RangeError,
  );
  assert.throws(
    () =>
      buildInitRootHistoryInstruction({
        authority: SYSTEM_PROGRAM_ID,
        poolId: 0,
        rootEpochInterval: 0n,
        activeLanes: 4,
      }),
    RangeError,
  );
  assert.throws(
    () =>
      buildInitRootHistoryInstruction({
        authority: SYSTEM_PROGRAM_ID,
        poolId: 0,
        rootEpochInterval: 32n,
        activeLanes: 17,
      }),
    RangeError,
  );
  assert.throws(
    () =>
      buildOpenPageInstruction({
        payer: SYSTEM_PROGRAM_ID,
        pageKind: OPEN_PAGE_KIND_SUBTREE,
        poolId: 0,
        laneId: 16,
        pageSeq: 0n,
      }),
    RangeError,
  );
  assert.throws(
    () =>
      buildUpdatePoolInstruction({
        signer: SYSTEM_PROGRAM_ID,
        poolId: 0,
        action: {
          kind: 'params',
          noteRentFee: u64Overflow,
          nfRentFee: 0n,
        },
      }),
    RangeError,
  );
  assert.throws(
    () =>
      buildDepositInstruction({
        depositor: SYSTEM_PROGRAM_ID,
        poolId: 0,
        laneId: 0,
        subPageSeq: 0n,
        rootPageSeq: 0n,
        memoPageSeq: 0n,
        nativeSol: true,
        amount: u64Overflow,
        stealthOwner: 1n,
        blinding: 2n,
        memo: new Uint8Array(MEMO_ENTRY_WIRE_LEN),
      }),
    RangeError,
  );

  // R1-R7: inspectToken2022UnsafeSelfPay checks
  const makeT22Mint = (exts) => {
    let total = 166;
    for (const e of exts) total += 4 + e.data.byteLength;
    const buf = new Uint8Array(total);
    buf[165] = 1; // AccountType::Mint
    const dv = new DataView(buf.buffer);
    let pos = 166;
    for (const e of exts) {
      dv.setUint16(pos, e.type, true);
      dv.setUint16(pos + 2, e.data.byteLength, true);
      buf.set(e.data, pos + 4);
      pos += 4 + e.data.byteLength;
    }
    return buf;
  };
  // Mutable TransferHook.authority (bytes[0..32] non-zero, program_id zero) -> UNSAFE (true)
  const mutableHookAuth = new Uint8Array(64);
  mutableHookAuth[0] = 1;
  assert.equal(inspectToken2022UnsafeSelfPay(makeT22Mint([{ type: 14, data: mutableHookAuth }])), true);
  // Truncated TransferHook (< 64 bytes) -> UNSAFE (true)
  assert.equal(inspectToken2022UnsafeSelfPay(makeT22Mint([{ type: 14, data: new Uint8Array(32) }])), true);
  // ScaledUiAmount (TLV 25) -> UNSAFE (true)
  assert.equal(inspectToken2022UnsafeSelfPay(makeT22Mint([{ type: 25, data: new Uint8Array(56) }])), true);
  // Truncated TransferFeeConfig (TLV 1, < 108 bytes) -> UNSAFE (true)
  assert.equal(inspectToken2022UnsafeSelfPay(makeT22Mint([{ type: 1, data: new Uint8Array(80) }])), true);
});

test('R2-C1/C2/C3/C4: Pass 1D & strict reconstructWitness content/Fr verification, untrusted RPC caps, Pass 1A anti-zero-fill, and header validation', async () => {
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x61));
  const fvk = exportFullViewingKey(alice);
  const wsolAsset = deriveAssetId(WSOL_MINT_BYTES);

  const dummyLeaves = Array.from({ length: SUBTREE_LEAVES }, (_, i) => BigInt(i + 10));
  const dummySubroot = computeSubtree256Root(dummyLeaves, SUBTREE_LEAVES);
  const dummyFrontier = Array.from({ length: 4 }, (_, i) => BigInt(i + 900));

  const aliceLeafIdx = BigInt(SUBTREE_LEAVES) + 7n; // lane 2, SubtreePage (2, 1), slot 7
  const { tweak, blinding, memo } = encryptNoteMemo(
    alice.viewPk,
    new Uint8Array(32).fill(0x62),
    3_333_333n,
    WSOL_MINT_BYTES,
  );
  const aliceCm = computeNoteCommitment(deriveStealthOwner(alice.spendPk, tweak), wsolAsset, 3_333_333n, blinding);
  const hitLeaves = [...dummyLeaves];
  hitLeaves[7] = aliceCm;
  const hitSubroot = computeSubtree256Root(hitLeaves, SUBTREE_LEAVES);

  const sealedPerLane = 5;
  const leavesPerLane = sealedPerLane * SUBTREE_LEAVES + 4;
  const memosPerLane = Math.ceil(leavesPerLane / MEMO_NOTES_PER_PAGE);

  const accounts = new Map();
  const poolPda = derivePoolPdaSync(0).address;
  accounts.set(poolPda, makePoolState(4));

  const sealedAddrs = new Set();
  const nfAddrs = new Set();
  const laneRoots = Array.from({ length: NUM_LANES }, () => ZERO_HASHES_4ARY[18]);
  const laneCounts = new Array(NUM_LANES).fill(0n);

  for (let l = 0; l < 4; l++) {
    laneCounts[l] = BigInt(leavesPerLane);
    const roots = Array.from({ length: sealedPerLane }, (_, s) => (l === 2 && s === 1 ? hitSubroot : dummySubroot));
    laneRoots[l] = computeLaneRootFromSubroots(roots, dummyFrontier);
    accounts.set(
      deriveLanePdaSync(0, l).address,
      makeLaneState(l, BigInt(leavesPerLane), l === 0 ? 2n : 0n, laneRoots[l]),
    );
    accounts.set(deriveSubrootPdaSync(0, l, 0n).address, makeSubrootPage(l, 0n, roots));

    for (let s = 0; s < sealedPerLane; s++) {
      const addr = deriveSubtreePdaSync(0, l, BigInt(s)).address;
      sealedAddrs.add(addr);
      const ls = l === 2 && s === 1 ? hitLeaves : dummyLeaves;
      accounts.set(addr, makeSubtreePage(l, BigInt(s), ls));
    }
    accounts.set(deriveSubtreePdaSync(0, l, BigInt(sealedPerLane)).address, makeSubtreePage(l, BigInt(sealedPerLane), dummyFrontier));

    for (let m = 0; m < memosPerLane; m++) {
      const cnt = Math.min(MEMO_NOTES_PER_PAGE, leavesPerLane - m * MEMO_NOTES_PER_PAGE);
      const mraw = makeMemoPageWithMeta(l, BigInt(m), cnt);
      new DataView(mraw.buffer).setBigUint64(MM_OFF_CLOSED_SLOT, BigInt((m + 1) * 50), true);
      if (l === 2 && m === Math.floor(Number(aliceLeafIdx) / MEMO_NOTES_PER_PAGE)) {
        writeMemoSlot(mraw, Number(aliceLeafIdx) % MEMO_NOTES_PER_PAGE, memo);
      }
      accounts.set(deriveMemoPdaSync(0, l, BigInt(m)).address, mraw);
    }
  }

  const nf0Addr = deriveNfPagePdaSync(0, 0, 0n).address;
  nfAddrs.add(nf0Addr);
  accounts.set(nf0Addr, makeNfPage(0, 0n, [new Uint8Array(NF_PREFIX_LEN).fill(0x11), new Uint8Array(NF_PREFIX_LEN).fill(0x22)]));

  const buildRootsRaw = (lroots, lcounts) =>
    makeSyntheticRootHistory({ laneRoots: lroots, laneCounts: lcounts }).raw;
  const rootsAddr = deriveRootsPdaSync(0).address;
  accounts.set(rootsAddr, buildRootsRaw(laneRoots, laneCounts));

  // Baseline sync captures deterministic sealed SubtreePage set (16 pages)
  const baselineStore = new CompactWalletStore(0, 0n);
  const fetchedSealed = [];
  const baseRes = await syncCompactStoreWithRpc({
    store: baselineStore,
    fvk,
    fetchBatch: async (addrs, opts) => {
      for (const a of addrs) if (sealedAddrs.has(a)) fetchedSealed.push(a);
      return addrs.map((a) => {
        const full = accounts.get(a) ?? null;
        if (!full || !opts?.dataSlice) return full;
        return full.slice(opts.dataSlice.offset, opts.dataSlice.offset + opts.dataSlice.length);
      });
    },
  });
  assert.equal(baseRes.discoveredNotes, 1);
  assert.equal(fetchedSealed.length, 16);
  const hitSubAddr = deriveSubtreePdaSync(0, 2, 1n).address;
  const decoySubAddr = fetchedSealed.find((a) => a !== hitSubAddr);
  assert.ok(decoySubAddr);

  // === R2-C1: Pass 1D non-canonical Fr & 1-bit canonical tamper on decoy AND hit ===
  for (const [label, targetAddr, nonCanonical] of [
    ['decoy non-canonical Fr', decoySubAddr, true],
    ['hit non-canonical Fr', hitSubAddr, true],
    ['decoy 1-bit canonical tamper', decoySubAddr, false],
    ['hit 1-bit canonical tamper', hitSubAddr, false],
  ]) {
    const tampered = accounts.get(targetAddr).slice();
    if (nonCanonical) {
      tampered.fill(0xff, SB_OFF_LEAVES, SB_OFF_LEAVES + 32);
    } else {
      tampered[SB_OFF_LEAVES + 31] ^= 0x01;
    }
    const st = new CompactWalletStore(0, 0n);
    let pass2Called = false;
    await assert.rejects(
      () =>
        syncCompactStoreWithRpc({
          store: st,
          fvk,
          fetchBatch: async (addrs, opts) => {
            if (addrs.some((a) => nfAddrs.has(a))) pass2Called = true;
            return addrs.map((a) => {
              const full = a === targetAddr ? tampered : (accounts.get(a) ?? null);
              if (!full || !opts?.dataSlice) return full;
              return full.slice(opts.dataSlice.offset, opts.dataSlice.offset + opts.dataSlice.length);
            });
          },
        }),
      new RegExp('field element|root mismatch'),
      `R2-C1 (${label}) must throw`,
    );
    assert.equal(pass2Called, false, `R2-C1 (${label}): must reject in Pass 1D before Pass 2`);
    assert.equal(st.notes.length, 0, `R2-C1 (${label}): store.notes must remain untouched`);
    for (let l = 0; l < 4; l++) {
      assert.equal(st.lanes[l].nextMemoLeaf, 0n);
      assert.equal(st.lanes[l].finalizedSubroots.length, 0);
    }
  }

  // === R2-C2: Strict reconstructWitness content-tampering & non-canonical Fr ===
  const witFetchedSealed = [];
  await reconstructWitness({
    fetchBatch: async (addrs) => {
      for (const a of addrs) if (sealedAddrs.has(a)) witFetchedSealed.push(a);
      return addrs.map((a) => accounts.get(a) ?? null);
    },
    poolId: 0,
    laneId: 2,
    leafIdx: aliceLeafIdx,
    viewSk: alice.viewSk,
  });
  const witDecoy = witFetchedSealed.find((a) => a !== hitSubAddr);
  const nonTargetSr = deriveSubrootPdaSync(0, 0, 0n).address;
  const nonTargetFrontier = deriveSubtreePdaSync(0, 0, BigInt(sealedPerLane)).address;

  const decoyNonCanon = accounts.get(witDecoy).slice();
  decoyNonCanon.fill(0xff, SB_OFF_LEAVES, SB_OFF_LEAVES + 32);
  const decoyBitflip = accounts.get(witDecoy).slice();
  decoyBitflip[SB_OFF_LEAVES + 31] ^= 0x01;
  const srNonCanon = accounts.get(nonTargetSr).slice();
  srNonCanon.fill(0xff, SR_OFF_ROOTS, SR_OFF_ROOTS + 32);
  const srBitflip = accounts.get(nonTargetSr).slice();
  srBitflip[SR_OFF_ROOTS + 31] ^= 0x01;
  const frontierBitflip = accounts.get(nonTargetFrontier).slice();
  frontierBitflip[SB_OFF_LEAVES + 31] ^= 0x01;
  const badEmptyLaneRoots = [...laneRoots];
  badEmptyLaneRoots[5] = poseidon4(1n, 2n, 3n, 4n);
  const rootsBadEmptyLane = buildRootsRaw(badEmptyLaneRoots, laneCounts);

  for (const [label, overrideAddr, overrideBytes] of [
    ['decoy SubtreePage non-canonical Fr', witDecoy, decoyNonCanon],
    ['decoy SubtreePage 1-bit canonical tamper', witDecoy, decoyBitflip],
    ['non-target SubtreeRootPage non-canonical Fr', nonTargetSr, srNonCanon],
    ['non-target SubtreeRootPage 1-bit canonical tamper', nonTargetSr, srBitflip],
    ['non-target frontier SubtreePage 1-bit tamper', nonTargetFrontier, frontierBitflip],
    ['empty lane roots.laneRoots[5] tamper', rootsAddr, rootsBadEmptyLane],
  ]) {
    await assert.rejects(
      () =>
        reconstructWitness({
          fetchBatch: async (addrs) => addrs.map((a) => (a === overrideAddr ? overrideBytes : (accounts.get(a) ?? null))),
          poolId: 0,
          laneId: 2,
          leafIdx: aliceLeafIdx,
          viewSk: alice.viewSk,
        }),
      /.+/,
      `R2-C2 (${label}): strict reconstructWitness must reject`,
    );
  }

  // === R2-C3: Untrusted RPC nfCount = u64::MAX, nextLeaf = 1 << 36, HRW cap ===
  const lane0Pda = deriveLanePdaSync(0, 0).address;
  const U64_MAX = (1n << 64n) - 1n;

  const stNfZero = new CompactWalletStore(0, 0n);
  let nfZeroCalls = 0;
  await syncCompactStoreWithRpc({
    store: stNfZero,
    fvk,
    fetchBatch: async (addrs) => {
      nfZeroCalls++;
      return addrs.map((a) => {
        if (a === poolPda) return makePoolState(1);
        if (a === lane0Pda) return makeLaneState(0, 0n, U64_MAX);
        return null;
      });
    },
  });
  assert.ok(nfZeroCalls <= 4, `R2-C3: lazy NF streaming must halt immediately on missing pages (got ${nfZeroCalls})`);

  const stNfBday = new CompactWalletStore(0, 1000n);
  let bdayCalls = 0;
  let probeLo = 0n;
  const probeHi = (U64_MAX - 1n) / BigInt(NF_PER_PAGE) + 1n;
  await syncCompactStoreWithRpc({
    store: stNfBday,
    fvk,
    fetchBatch: async (addrs, opts) => {
      bdayCalls++;
      return addrs.map((a) => {
        if (a === poolPda) return makePoolState(1);
        if (a === lane0Pda) return makeLaneState(0, 0n, U64_MAX);
        if (opts?.dataSlice && probeLo < probeHi) {
          const mid = probeLo + (probeHi - probeLo) / 2n;
          probeLo = mid + 1n;
          const hdr = new Uint8Array(NF_PAGE_HEADER_LEN);
          hdr.set(enc.encode(NF_PAGE_MAGIC), NF_OFF_MAGIC);
          hdr[NF_OFF_LANE_ID] = 0;
          const dv = new DataView(hdr.buffer);
          dv.setUint16(NF_OFF_COUNT, NF_PER_PAGE, true);
          dv.setBigUint64(NF_OFF_PAGE_SEQ, mid, true);
          dv.setBigUint64(NF_OFF_CLOSED_SLOT, 500n, true);
          return hdr;
        }
        return null;
      });
    },
  });
  assert.equal(stNfBday.lanes[0].nextNfIndex, U64_MAX, 'R2-C3: Pass 2 birthdaySlot must clamp to U64_MAX');
  assert.ok(bdayCalls <= 70, `R2-C3: binary search + lazy stream must stay bounded (got ${bdayCalls})`);

  const stHugeLeaf = new CompactWalletStore(0, 0n);
  let hugeCalls = 0;
  await syncCompactStoreWithRpc({
    store: stHugeLeaf,
    fvk,
    fetchBatch: async (addrs) => {
      hugeCalls++;
      return addrs.map((a) => {
        if (a === poolPda) return makePoolState(1);
        if (a === lane0Pda) return makeLaneState(0, MAX_LEAVES_PER_LANE, 0n);
        return null;
      });
    },
  });
  assert.ok(hugeCalls <= 10, `R2-C3 + H-3: nextLeaf=1<<36 must lazily bound Pass 1D without OOM/spin or mature-pool HRW DoS (got ${hugeCalls})`);

  const stLargeLeaf = new CompactWalletStore(0, 0n);
  let largeCalls = 0;
  await syncCompactStoreWithRpc({
    store: stLargeLeaf,
    fvk,
    fetchBatch: async (addrs) => {
      largeCalls++;
      return addrs.map((a) => {
        if (a === poolPda) return makePoolState(1);
        if (a === lane0Pda) return makeLaneState(0, 10_000_000n, 0n);
        return null;
      });
    },
  });
  assert.ok(largeCalls <= 10, `R2-C3: lazy Pass 1A/1C on 10M leaves must halt on first missing batch (got ${largeCalls})`);

  const maxCounts = new Array(NUM_LANES).fill(0n);
  maxCounts[0] = MAX_LEAVES_PER_LANE;
  const maxLaneRoots = new Array(NUM_LANES).fill(ZERO_HASHES_4ARY[18]);
  maxLaneRoots[0] = laneRoots[0];
  const maxRootsRaw = buildRootsRaw(maxLaneRoots, maxCounts);
  for (const privacyMode of ['strict', 'fast']) {
    await assert.rejects(
      () =>
        reconstructWitness({
          fetchBatch: async (addrs) => addrs.map((a) => (a === rootsAddr ? maxRootsRaw : null)),
          poolId: 0,
          laneId: 0,
          leafIdx: 0n,
          privacyMode,
          viewSk: alice.viewSk,
        }),
      /exceeds witness bound|exceeds safe bound|exceeds max/,
      `R2-C3: reconstructWitness (${privacyMode}) must reject MAX_LEAVES_PER_LANE before OOM/spin`,
    );
  }
  assert.throws(
    () =>
      selectHrwSealedDecoys({
        viewSk: alice.viewSk,
        scope: enc.encode('sync'),
        epochBucket: 0n,
        sealedByLane: [{ laneId: 0, sealedCount: BigInt(MAX_HRW_SEALED_SUBTREES) + 1n }],
        alreadySelected: new Set(),
        targetSealed: 16,
      }),
    RangeError,
  );

  // === R2-C4: Pass 1A missing/lagged rp=0 never zero-fills; Pass 1A/1B zero-mutation on 1D miss; header checks ===
  const sr0Pda = deriveSubrootPdaSync(0, 0, 0n).address;
  const sr1Pda = deriveSubrootPdaSync(0, 0, 1n).address;
  const sr1_10 = makeSubrootPage(0, 1n, Array.from({ length: 10 }, () => dummySubroot));

  const stGap0 = new CompactWalletStore(0, 0n);
  await syncCompactStoreWithRpc({
    store: stGap0,
    fvk,
    fetchBatch: async (addrs) =>
      addrs.map((a) => {
        if (a === poolPda) return makePoolState(1);
        if (a === lane0Pda) return makeLaneState(0, 310n * BigInt(SUBTREE_LEAVES), 0n);
        if (a === sr1Pda) return sr1_10;
        return null;
      }),
  });
  assert.equal(stGap0.lanes[0].finalizedSubroots.length, 0, 'R2-C4: missing rp=0 must never zero-fill');

  const sr0_299 = makeSubrootPage(0, 0n, Array.from({ length: SUBROOTS_PER_PAGE - 1 }, () => dummySubroot));
  const stLag299 = new CompactWalletStore(0, 0n);
  stLag299.lanes[0].nextMemoLeaf = 310n * BigInt(SUBTREE_LEAVES);
  await syncCompactStoreWithRpc({
    store: stLag299,
    fvk,
    fetchBatch: async (addrs) =>
      addrs.map((a) => {
        if (a === poolPda) return makePoolState(1);
        if (a === lane0Pda) return makeLaneState(0, 310n * BigInt(SUBTREE_LEAVES), 0n);
        if (a === sr0Pda) return sr0_299;
        if (a === sr1Pda) return sr1_10;
        return null;
      }),
  });
  assert.equal(
    stLag299.lanes[0].finalizedSubroots.length,
    0,
    'R2-C4 + F1: lagged rp=0 (299/300) must neither zero-fill slot 299 nor commit unverified partial subroots',
  );

  // Pass 1A + 1B zero-mutation when a Pass 1D decoy SubtreePage is missing
  const st1dDrop = new CompactWalletStore(0, 200n);
  let droppedOne = false;
  await syncCompactStoreWithRpc({
    store: st1dDrop,
    fvk,
    fetchBatch: async (addrs, opts) =>
      addrs.map((a) => {
        if (!droppedOne && sealedAddrs.has(a)) {
          droppedOne = true;
          return null;
        }
        const full = accounts.get(a) ?? null;
        if (!full || !opts?.dataSlice) return full;
        return full.slice(opts.dataSlice.offset, opts.dataSlice.offset + opts.dataSlice.length);
      }),
  });
  assert.equal(droppedOne, true);
  for (let l = 0; l < 4; l++) {
    assert.equal(st1dDrop.lanes[l].finalizedSubroots.length, 0, 'R2-C4: Pass 1A must not mutate store on 1D miss');
    assert.equal(st1dDrop.lanes[l].nextMemoLeaf, 0n, 'R2-C4: Pass 1B must not mutate store on 1D miss');
  }

  // Header (poolId, laneId, pageSeq) mismatch rejected across Pass 1A, 1B, 1C, 1D, 2
  const badSr = accounts.get(sr0Pda).slice();
  new DataView(badSr.buffer).setUint32(SR_OFF_POOL_ID, 99, true);
  const badMemo0Addr = deriveMemoPdaSync(0, 0, 0n).address;
  const badMemo0 = accounts.get(badMemo0Addr).slice();
  new DataView(badMemo0.buffer).setUint32(MM_OFF_POOL_ID, 99, true);
  const badMemo7Addr = deriveMemoPdaSync(0, 0, 7n).address;
  const badMemo7 = accounts.get(badMemo7Addr).slice();
  new DataView(badMemo7.buffer).setUint32(MM_OFF_POOL_ID, 99, true);
  const badSub = accounts.get(decoySubAddr).slice();
  new DataView(badSub.buffer).setUint32(SB_OFF_POOL_ID, 99, true);
  const badNf = accounts.get(nf0Addr).slice();
  new DataView(badNf.buffer).setUint32(NF_OFF_POOL_ID, 99, true);

  for (const [label, bday, badAddr, badBytes] of [
    ['Pass 1A SubtreeRootPage poolId', 0n, sr0Pda, badSr],
    ['Pass 1C MemoPage poolId', 0n, badMemo0Addr, badMemo0],
    ['Pass 1B MemoPage birthday header poolId', 200n, badMemo7Addr, badMemo7],
    ['Pass 1D SubtreePage poolId', 0n, decoySubAddr, badSub],
    ['Pass 2 NullifierPage poolId', 0n, nf0Addr, badNf],
  ]) {
    const st = new CompactWalletStore(0, bday);
    await assert.rejects(
      () =>
        syncCompactStoreWithRpc({
          store: st,
          fvk,
          fetchBatch: async (addrs, opts) =>
            addrs.map((a) => {
              const full = a === badAddr ? badBytes : (accounts.get(a) ?? null);
              if (!full || !opts?.dataSlice) return full;
              return full.slice(opts.dataSlice.offset, opts.dataSlice.offset + opts.dataSlice.length);
            }),
        }),
      /header mismatch/,
      `R2-C4 (${label}) must reject`,
    );
  }

  // Store direct ingestion header checks
  const stHdr = new CompactWalletStore(7, 0n);
  assert.throws(
    () => stHdr.ingestSubrootPages({ laneId: 1, subrootPages: [{ rootPageSeq: 0n, raw: makeSubrootPage(1, 0n, [dummySubroot]) }] }),
    /header mismatch/,
  );
  assert.throws(
    () => stHdr.ingestNullifierPage({ laneId: 1, pageSeq: 0n, raw: makeNfPage(1, 0n, []) }),
    /header mismatch/,
  );
  assert.throws(
    () => stHdr.ingestLanePages({ fvk, laneId: 1, subtreePages: [{ pageSeq: 0n, raw: makeSubtreePage(1, 0n, [1n]) }] }),
    /header mismatch/,
  );
});

test('R2-C5/C6/C7/C8: CompactWalletStore.fromJSON strictness, PDA bounds, WASM input validation, Token-2022 parity, and AEAD key/nonce checks', async () => {
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x88));
  const fvk = exportFullViewingKey(alice);

  // === R2-C5: CompactWalletStore.fromJSON strict hex, decimal u64, booleans, & bounds ===
  const baseStore = new CompactWalletStore(0, 0n);
  const validBaseCm = frToBeBytes(
    computeNoteCommitment(
      deriveStealthOwner(alice.spendPk, 1n),
      deriveAssetId(WSOL_MINT_BYTES),
      1234n,
      2n,
    ),
  );
  baseStore.recordVerifiedMemo({
    fvk,
    laneId: 0,
    leafIdx: 5n,
    decrypted: {
      amount: 1234n,
      mint: WSOL_MINT_BYTES,
      tweak: 1n,
      blinding: 2n,
      memoVersion: MEMO_VERSION_V1,
      memoFlags: 0,
      paymentId: new Uint8Array(MEMO_PAYMENT_ID_LEN),
      isDynamic: false,
    },
    cmBe: validBaseCm,
  });
  const baseObj = JSON.parse(baseStore.toJSON());

  const cloneMut = (mutator) => {
    const obj = structuredClone(baseObj);
    mutator(obj);
    return JSON.stringify(obj);
  };

  // Non-hex, odd-length hex, wrong-length hex
  assert.throws(() => CompactWalletStore.fromJSON(cloneMut((o) => { o.notes[0].mint = 'ZZ'.repeat(32); })), /hex/);
  assert.throws(() => CompactWalletStore.fromJSON(cloneMut((o) => { o.notes[0].mint = 'abc'; })), /hex|length/);
  assert.throws(() => CompactWalletStore.fromJSON(cloneMut((o) => { o.notes[0].mint = '00'.repeat(31); })), /hex characters/);
  assert.throws(() => CompactWalletStore.fromJSON(cloneMut((o) => { o.notes[0].paymentId = '00'.repeat(13); })), /hex characters/);

  // Negative & > U64_MAX BigInt fields
  assert.throws(() => CompactWalletStore.fromJSON(cloneMut((o) => { o.notes[0].amount = '-100'; })), /unsigned decimal|u64/);
  assert.throws(() => CompactWalletStore.fromJSON(cloneMut((o) => { o.notes[0].amount = '18446744073709551616'; })), /unsigned decimal|u64/);
  assert.throws(() => CompactWalletStore.fromJSON(cloneMut((o) => { o.birthdaySlot = '-1'; })), /unsigned decimal|u64/);
  assert.throws(() => CompactWalletStore.fromJSON(cloneMut((o) => { o.lanes[0].nextMemoLeaf = '0x10'; })), /unsigned decimal|u64/);
  assert.throws(() => CompactWalletStore.fromJSON(cloneMut((o) => { o.lanes[0].nextMemoLeaf = (MAX_LEAVES_PER_LANE + 1n).toString(); })), /nextMemoLeaf|out of range/);
  assert.throws(() => CompactWalletStore.fromJSON(cloneMut((o) => { o.lanes[0].frontierSubSeq = ((MAX_LEAVES_PER_LANE / BigInt(SUBTREE_LEAVES)) + 1n).toString(); })), /frontierSubSeq/);

  // Invalid note poolId, laneId, booleans, paired frozen siblings/positions, p >= 4
  assert.throws(() => CompactWalletStore.fromJSON(cloneMut((o) => { o.notes[0].poolId = -1; })), /poolId/);
  assert.throws(() => CompactWalletStore.fromJSON(cloneMut((o) => { o.notes[0].laneId = 16; })), /laneId/);
  assert.throws(() => CompactWalletStore.fromJSON(cloneMut((o) => { o.notes[0].spent = 'false'; })), /spent/);
  assert.throws(() => CompactWalletStore.fromJSON(cloneMut((o) => { o.notes[0].isDynamic = 0; })), /isDynamic/);
  assert.throws(() => CompactWalletStore.fromJSON(cloneMut((o) => { o.notes[0].frozenIntraPositions = [0, 1, 2, 3]; })), /both be present or both null/);
  assert.throws(
    () =>
      CompactWalletStore.fromJSON(
        cloneMut((o) => {
          o.notes[0].frozenIntraSiblings = Array.from({ length: 4 }, () =>
            Array.from({ length: 3 }, () => '00'.repeat(32)),
          );
          o.notes[0].frozenIntraPositions = [4, 0, 0, 0];
        }),
      ),
    /frozenIntraPositions/,
  );

  // computeMerkleRoot4Ary rejects pos >= 4 instead of silently defaulting to branch 3
  assert.throws(
    () =>
      computeMerkleRoot4Ary(
        {
          siblings: Array.from({ length: 20 }, () => [0n, 0n, 0n]),
          positions: [4, ...new Array(19).fill(0)],
        },
        1n,
      ),
    RangeError,
  );

  // === R2-C6: pda.ts bounds & base58Decode cap + prover.ts poseidonHashWasm 32-byte assertion ===
  assert.throws(() => deriveLanePdaSync(0, -1), RangeError);
  assert.throws(() => deriveLanePdaSync(0, 16), RangeError);
  assert.throws(() => deriveLanePdaSync(0x1_0000_0000, 0), RangeError);
  assert.throws(() => deriveLaneRentVaultPdaSync(0, 256), RangeError);
  assert.throws(() => deriveSubtreePdaSync(0, 16, 0n), RangeError);
  assert.throws(() => deriveSubtreePdaSync(0, 0, -1n), RangeError);
  assert.throws(() => deriveSubtreePdaSync(0, 0, 1n << 64n), RangeError);
  assert.throws(() => deriveSubrootPdaSync(0, -1, 0n), RangeError);
  assert.throws(() => deriveMemoPdaSync(0, 16, 0n), RangeError);
  assert.throws(() => deriveNfPagePdaSync(0, 16, 0n), RangeError);
  assert.throws(() => deriveNfPagePdaSync(-1, 0, 0n), RangeError);
  assert.throws(() => base58Decode('1'.repeat(300)), RangeError);

  const prover = await AudrenWasmProver.init();
  assert.throws(() => prover.poseidonHashWasm([new Uint8Array(31)]), RangeError);
  assert.throws(() => prover.poseidonHashWasm([new Uint8Array(33)]), RangeError);
  assert.throws(() => prover.poseidonHashWasm([new Uint8Array(32), new Uint8Array(16)]), RangeError);

  // === R2-C7: token2022.ts inspectToken2022UnsafeSelfPay synced with apps/relay ===
  const makeT22Mint = (exts, extraTrailing = 0) => {
    let total = 166 + extraTrailing;
    for (const e of exts) total += 4 + e.data.byteLength;
    const buf = new Uint8Array(total);
    buf[165] = 1; // AccountType::Mint
    const dv = new DataView(buf.buffer);
    let pos = 166;
    for (const e of exts) {
      dv.setUint16(pos, e.type, true);
      dv.setUint16(pos + 2, e.data.byteLength, true);
      buf.set(e.data, pos + 4);
      pos += 4 + e.data.byteLength;
    }
    return buf;
  };
  // Bare 82-byte mint is safe; invalid lengths (81, 83, 165) are unsafe
  assert.equal(inspectToken2022UnsafeSelfPay(new Uint8Array(82)), false);
  assert.equal(inspectToken2022UnsafeSelfPay(new Uint8Array(81)), true);
  assert.equal(inspectToken2022UnsafeSelfPay(new Uint8Array(83)), true);
  assert.equal(inspectToken2022UnsafeSelfPay(new Uint8Array(165)), true);
  // Wrong AccountType byte at 165 -> unsafe
  const wrongAcctType = makeT22Mint([]);
  wrongAcctType[165] = 2;
  assert.equal(inspectToken2022UnsafeSelfPay(wrongAcctType), true);
  // Non-zero padding in [82..165] -> unsafe
  const dirtyPad = makeT22Mint([]);
  dirtyPad[100] = 1;
  assert.equal(inspectToken2022UnsafeSelfPay(dirtyPad), true);
  // Trailing 1..3 partial TLV header bytes -> unsafe
  assert.equal(inspectToken2022UnsafeSelfPay(makeT22Mint([], 1)), true);
  assert.equal(inspectToken2022UnsafeSelfPay(makeT22Mint([], 2)), true);
  assert.equal(inspectToken2022UnsafeSelfPay(makeT22Mint([], 3)), true);
  // Pausable (TLV 26) -> unsafe
  assert.equal(inspectToken2022UnsafeSelfPay(makeT22Mint([{ type: 26, data: new Uint8Array(33) }])), true);
  // DefaultAccountState (TLV 6): truncated or Frozen (2) -> unsafe; Initialized (1) -> safe
  assert.equal(inspectToken2022UnsafeSelfPay(makeT22Mint([{ type: 6, data: new Uint8Array(0) }])), true);
  assert.equal(inspectToken2022UnsafeSelfPay(makeT22Mint([{ type: 6, data: Uint8Array.of(2) }])), true);
  assert.equal(inspectToken2022UnsafeSelfPay(makeT22Mint([{ type: 6, data: Uint8Array.of(1) }])), false);
  // TransferFeeConfig (TLV 1): mutable authority ([0..32] non-zero) -> unsafe; zero auth + zero bps -> safe
  const mutableFeeCfg = new Uint8Array(108);
  mutableFeeCfg[0] = 1;
  assert.equal(inspectToken2022UnsafeSelfPay(makeT22Mint([{ type: 1, data: mutableFeeCfg }])), true);
  assert.equal(inspectToken2022UnsafeSelfPay(makeT22Mint([{ type: 1, data: new Uint8Array(108) }])), false);

  // === R2-C8: crypto.ts exact 32-byte key & 12-byte nonce checks ===
  const k32 = new Uint8Array(32).fill(1);
  const n12 = new Uint8Array(12).fill(2);
  const aad = new Uint8Array(4);
  const pt = new Uint8Array(8);
  assert.throws(() => chacha20Poly1305Encrypt(new Uint8Array(31), n12, pt, aad), RangeError);
  assert.throws(() => chacha20Poly1305Encrypt(new Uint8Array(33), n12, pt, aad), RangeError);
  assert.throws(() => chacha20Poly1305Encrypt(k32, new Uint8Array(11), pt, aad), RangeError);
  assert.throws(() => chacha20Poly1305Encrypt(k32, new Uint8Array(13), pt, aad), RangeError);
  const ct = chacha20Poly1305Encrypt(k32, n12, pt, aad);
  assert.throws(() => chacha20Poly1305Decrypt(new Uint8Array(31), n12, ct, aad), RangeError);
  assert.throws(() => chacha20Poly1305Decrypt(new Uint8Array(33), n12, ct, aad), RangeError);
  assert.throws(() => chacha20Poly1305Decrypt(k32, new Uint8Array(11), ct, aad), RangeError);
  assert.throws(() => chacha20Poly1305Decrypt(k32, new Uint8Array(13), ct, aad), RangeError);
  assert.deepEqual(chacha20Poly1305Decrypt(k32, n12, ct, aad), pt);
});

test('R3-C1/C2/C3: Pass 2 rollback on error, sealed SubtreePage subroot verification, and monotonic frontier/prevSealed guards', async () => {
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x73));
  const fvk = exportFullViewingKey(alice);
  const wsolAsset = deriveAssetId(WSOL_MINT_BYTES);

  const sliceFetch = (accounts) => async (addrs, opts) =>
    addrs.map((a) => {
      const full = accounts.get(a) ?? null;
      if (!full || !opts?.dataSlice) return full;
      return full.slice(opts.dataSlice.offset, opts.dataSlice.offset + opts.dataSlice.length);
    });

  // =========================================================================
  // R3-C1: Pass 1 incomplete (`!allLanesCaughtUp`) + Pass 2 fails mid-stream
  //        (both bad NF page AND thrown RPC network error) -> `nextNfIndex`
  //        strictly restored for BOTH `birthdaySlot = 0n` AND `birthdaySlot > 0n`!
  // =========================================================================
  {
    const { tweak, blinding, memo } = encryptNoteMemo(
      alice.viewPk,
      new Uint8Array(32).fill(0x74),
      5_555_555n,
      WSOL_MINT_BYTES,
    );
    const cm = computeNoteCommitment(deriveStealthOwner(alice.spendPk, tweak), wsolAsset, 5_555_555n, blinding);
    const sub0Addr = deriveSubtreePdaSync(0, 0, 0n).address;
    const sub0Raw = makeSubtreePage(0, 0n, [cm]);
    const memo0Raw = makeMemoPageWithMeta(0, 0n, 1);
    writeMemoSlot(memo0Raw, 0, memo);

    const probe = new CompactWalletStore(0, 0n);
    probe.ingestLanePages({
      fvk,
      laneId: 0,
      subtreePages: [{ pageSeq: 0n, raw: sub0Raw }],
      memoPages: [{ pageSeq: 0n, raw: memo0Raw }],
      nfPages: [],
    });
    const aliceNfPrefix = probe.notes[0].nullifier.subarray(0, NF_PREFIX_LEN);

    const strangerPrefixes = Array.from({ length: NF_PER_PAGE }, (_, i) => {
      const p = new Uint8Array(NF_PREFIX_LEN);
      p[0] = 0xee;
      p[1] = i & 0xff;
      p[2] = (i >> 8) & 0xff;
      return p;
    });
    const nf3Prefixes = [...strangerPrefixes];
    nf3Prefixes[10] = aliceNfPrefix;

    const nfPagesTotal = 5;
    const nfTotal = BigInt((nfPagesTotal - 1) * NF_PER_PAGE + 5);
    const accounts = new Map([
      [derivePoolPdaSync(0).address, makePoolState(1)],
      [deriveLanePdaSync(0, 0).address, makeLaneState(0, 1n, nfTotal, computeLaneRootFromLeaves([cm]))],
      [sub0Addr, sub0Raw],
      [deriveMemoPdaSync(0, 0, 0n).address, memo0Raw],
    ]);
    for (let p = 0; p < nfPagesTotal; p++) {
      const addr = deriveNfPagePdaSync(0, 0, BigInt(p)).address;
      const raw =
        p === 3
          ? makeNfPage(0, BigInt(p), nf3Prefixes)
          : makeNfPage(0, BigInt(p), p === nfPagesTotal - 1 ? strangerPrefixes.slice(0, 5) : strangerPrefixes);
      const closedSlot = p === 0 ? 100n : p === 1 ? 200n : p === 2 ? 300n : p === 3 ? 1200n : 0n;
      new DataView(raw.buffer).setBigUint64(NF_OFF_CLOSED_SLOT, closedSlot, true);
      accounts.set(addr, raw);
    }

    const nf1Addr = deriveNfPagePdaSync(0, 0, 1n).address;
    const badNf1 = accounts.get(nf1Addr).slice();
    new DataView(badNf1.buffer).setUint32(NF_OFF_POOL_ID, 77, true);

    // 1a. `birthdaySlot = 0n`, pre-sync `nextNfIndex = 5n`, bad NF page 1 -> rolled back to 5n
    const st0 = new CompactWalletStore(0, 0n);
    st0.lanes[0].nextNfIndex = 5n;
    await assert.rejects(
      () =>
        syncCompactStoreWithRpc({
          store: st0,
          fvk,
          fetchBatch: async (addrs, opts) =>
            addrs.map((a) => {
              if (a === sub0Addr) return null;
              const full = a === nf1Addr ? badNf1 : (accounts.get(a) ?? null);
              if (!full || !opts?.dataSlice) return full;
              return full.slice(opts.dataSlice.offset, opts.dataSlice.offset + opts.dataSlice.length);
            }),
        }),
      /header mismatch/,
    );
    assert.equal(st0.lanes[0].nextNfIndex, 5n, 'R3-C1 (bday=0 bad page): nextNfIndex must roll back to 5n');

    // 1b. `birthdaySlot = 1000n`, pre-sync `nextNfIndex = 0n`, bad NF page 4 -> rolled back to 0n
    const nf4Addr = deriveNfPagePdaSync(0, 0, 4n).address;
    const badNf4 = accounts.get(nf4Addr).slice();
    new DataView(badNf4.buffer).setUint32(NF_OFF_POOL_ID, 88, true);

    const stBday = new CompactWalletStore(0, 1000n);
    await assert.rejects(
      () =>
        syncCompactStoreWithRpc({
          store: stBday,
          fvk,
          fetchBatch: async (addrs, opts) =>
            addrs.map((a) => {
              if (a === sub0Addr) return null;
              const full = a === nf4Addr && !opts?.dataSlice ? badNf4 : (accounts.get(a) ?? null);
              if (!full || !opts?.dataSlice) return full;
              return full.slice(opts.dataSlice.offset, opts.dataSlice.offset + opts.dataSlice.length);
            }),
        }),
      /header mismatch/,
    );
    assert.equal(stBday.lanes[0].nextNfIndex, 0n, 'R3-C1 (bday>0 bad page): nextNfIndex must roll back to 0n');

    // 1c. `birthdaySlot = 1000n`, thrown network error mid-Pass 2 -> rolled back to 0n
    const stNet = new CompactWalletStore(0, 1000n);
    await assert.rejects(
      () =>
        syncCompactStoreWithRpc({
          store: stNet,
          fvk,
          fetchBatch: async (addrs, opts) => {
            if (!opts?.dataSlice && addrs.includes(nf4Addr)) {
              throw new Error('simulated RPC timeout during Pass 2');
            }
            return addrs.map((a) => {
              if (a === sub0Addr) return null;
              const full = accounts.get(a) ?? null;
              if (!full || !opts?.dataSlice) return full;
              return full.slice(opts.dataSlice.offset, opts.dataSlice.offset + opts.dataSlice.length);
            });
          },
        }),
      /simulated RPC timeout/,
    );
    assert.equal(stNet.lanes[0].nextNfIndex, 0n, 'R3-C1 (bday>0 network error): nextNfIndex must roll back to 0n');

    // Healthy retry recovers Alice's note AND marks it spent!
    const retryRes = await syncCompactStoreWithRpc({
      store: stBday,
      fvk,
      fetchBatch: sliceFetch(accounts),
    });
    assert.equal(retryRes.discoveredNotes, 1);
    assert.equal(stBday.notes[0].spent, true);
    assert.equal(stBday.lanes[0].nextNfIndex, nfTotal);
  }

  // =========================================================================
  // R3-C2: Sealed `SubtreePage` when `SubtreeRootPage` is missing/lagged
  //        (`count = 0`) -> uniform `anyPass1dSubtreeMissing = true`, zero store
  //        mutation, `frozenIntraSiblings` NOT poisoned (hit & decoy lanes),
  //        plus defense-in-depth commitment match check!
  // =========================================================================
  {
    const dummyLeaves = Array.from({ length: SUBTREE_LEAVES }, (_, i) => BigInt(i + 30));
    const dummySubroot = computeSubtree256Root(dummyLeaves, SUBTREE_LEAVES);
    const dummyFrontier = Array.from({ length: 4 }, (_, i) => BigInt(i + 500));

    const aliceLeafIdx = BigInt(SUBTREE_LEAVES) + 7n; // lane 2, subtree 1, slot 7
    const { tweak, blinding, memo } = encryptNoteMemo(
      alice.viewPk,
      new Uint8Array(32).fill(0x75),
      4_444_444n,
      WSOL_MINT_BYTES,
    );
    const aliceCm = computeNoteCommitment(deriveStealthOwner(alice.spendPk, tweak), wsolAsset, 4_444_444n, blinding);
    const hitLeaves = [...dummyLeaves];
    hitLeaves[7] = aliceCm;
    const hitSubroot = computeSubtree256Root(hitLeaves, SUBTREE_LEAVES);

    const sealedPerLane = 5;
    const leavesPerLane = sealedPerLane * SUBTREE_LEAVES + 4;
    const memosPerLane = Math.ceil(leavesPerLane / MEMO_NOTES_PER_PAGE);

    const accounts = new Map([[derivePoolPdaSync(0).address, makePoolState(4)]]);
    const sealedAddrs = new Set();
    for (let l = 0; l < 4; l++) {
      const roots = Array.from({ length: sealedPerLane }, (_, s) => (l === 2 && s === 1 ? hitSubroot : dummySubroot));
      const laneRoot = computeLaneRootFromSubroots(roots, dummyFrontier);
      accounts.set(
        deriveLanePdaSync(0, l).address,
        makeLaneState(l, BigInt(leavesPerLane), l === 0 ? 2n : 0n, laneRoot),
      );
      accounts.set(deriveSubrootPdaSync(0, l, 0n).address, makeSubrootPage(l, 0n, roots));
      for (let s = 0; s < sealedPerLane; s++) {
        const addr = deriveSubtreePdaSync(0, l, BigInt(s)).address;
        sealedAddrs.add(addr);
        accounts.set(addr, makeSubtreePage(l, BigInt(s), l === 2 && s === 1 ? hitLeaves : dummyLeaves));
      }
      accounts.set(deriveSubtreePdaSync(0, l, BigInt(sealedPerLane)).address, makeSubtreePage(l, BigInt(sealedPerLane), dummyFrontier));
      for (let m = 0; m < memosPerLane; m++) {
        const cnt = Math.min(MEMO_NOTES_PER_PAGE, leavesPerLane - m * MEMO_NOTES_PER_PAGE);
        const mraw = makeMemoPageWithMeta(l, BigInt(m), cnt);
        if (l === 2 && m === Math.floor(Number(aliceLeafIdx) / MEMO_NOTES_PER_PAGE)) {
          writeMemoSlot(mraw, Number(aliceLeafIdx) % MEMO_NOTES_PER_PAGE, memo);
        }
        accounts.set(deriveMemoPdaSync(0, l, BigInt(m)).address, mraw);
      }
    }
    const nf0Addr = deriveNfPagePdaSync(0, 0, 0n).address;
    accounts.set(nf0Addr, makeNfPage(0, 0n, [new Uint8Array(NF_PREFIX_LEN).fill(0x11), new Uint8Array(NF_PREFIX_LEN).fill(0x22)]));

    const probeStore = new CompactWalletStore(0, 0n);
    const probeSealed = new Set();
    await syncCompactStoreWithRpc({
      store: probeStore,
      fvk,
      fetchBatch: async (addrs, opts) => {
        for (const a of addrs) if (sealedAddrs.has(a)) probeSealed.add(a);
        return (await sliceFetch(accounts)(addrs, opts));
      },
    });
    const decoyLane = [0, 1, 3].find((l) =>
      Array.from({ length: sealedPerLane }, (_, s) => deriveSubtreePdaSync(0, l, BigInt(s)).address).some((a) =>
        probeSealed.has(a),
      ),
    );
    assert.notEqual(decoyLane, undefined);

    const hitSrAddr = deriveSubrootPdaSync(0, 2, 0n).address;
    const decoySrAddr = deriveSubrootPdaSync(0, decoyLane, 0n).address;
    const laggedHitSr = makeSubrootPage(2, 0n, []);
    const laggedDecoySr = makeSubrootPage(decoyLane, 0n, []);

    const retryLogs = [];
    for (const [label, targetSr, replacement] of [
      ['hit lane lagged count=0', hitSrAddr, laggedHitSr],
      ['decoy lane lagged count=0', decoySrAddr, laggedDecoySr],
      ['hit lane missing null', hitSrAddr, null],
      ['decoy lane missing null', decoySrAddr, null],
    ]) {
      const st = new CompactWalletStore(0, 0n);
      let pass2Seen = false;
      const res = await syncCompactStoreWithRpc({
        store: st,
        fvk,
        fetchBatch: async (addrs, opts) => {
          if (addrs.includes(nf0Addr)) pass2Seen = true;
          return addrs.map((a) => {
            if (a === targetSr) return replacement;
            const full = accounts.get(a) ?? null;
            if (!full || !opts?.dataSlice) return full;
            return full.slice(opts.dataSlice.offset, opts.dataSlice.offset + opts.dataSlice.length);
          });
        },
      });
      assert.equal(res.discoveredNotes, 0, `R3-C2 (${label}): discoveredNotes must be 0`);
      assert.equal(pass2Seen, true, `R3-C2 (${label}): Pass 2 must still execute unconditionally`);
      assert.equal(st.notes.length, 0, `R3-C2 (${label}): store.notes must stay untouched`);
      for (let l = 0; l < 4; l++) {
        assert.equal(st.lanes[l].finalizedSubroots.length, 0, `R3-C2 (${label}): finalizedSubroots untouched`);
        assert.equal(st.lanes[l].nextMemoLeaf, 0n, `R3-C2 (${label}): nextMemoLeaf untouched`);
        assert.equal(st.lanes[l].nextNfIndex, 0n, `R3-C2 (${label}): nextNfIndex rolled back`);
      }

      const retryLog = [];
      const retryRes = await syncCompactStoreWithRpc({
        store: st,
        fvk,
        fetchBatch: async (addrs, opts) => {
          retryLog.push([...addrs]);
          return sliceFetch(accounts)(addrs, opts);
        },
      });
      assert.equal(retryRes.discoveredNotes, 1);
      assert.ok(st.notes[0].frozenIntraSiblings);
      retryLogs.push(retryLog);
    }
    assert.deepEqual(
      retryLogs[0],
      retryLogs[1],
      'R3-C2: Sync #2 traffic must be identical after hit-lane vs decoy-lane lagged SubtreeRootPage',
    );
    assert.deepEqual(
      retryLogs[2],
      retryLogs[3],
      'R3-C2: Sync #2 traffic must be identical after hit-lane vs decoy-lane missing SubtreeRootPage',
    );

    // Existing unfrozen owned note must NOT be frozen from poisoned SubtreePage when SubtreeRootPage is lagged
    const poisonedHitLeaves = [...hitLeaves];
    poisonedHitLeaves[0] = 9_999_999n;
    const poisonedHitSub = makeSubtreePage(2, 1n, poisonedHitLeaves);
    const hitSubAddr = deriveSubtreePdaSync(0, 2, 1n).address;

    const stPoison = new CompactWalletStore(0, 0n);
    for (let l = 0; l < 4; l++) stPoison.lanes[l].nextMemoLeaf = BigInt(leavesPerLane);
    stPoison.recordVerifiedMemo({
      fvk,
      laneId: 2,
      leafIdx: aliceLeafIdx,
      decrypted: {
        amount: 4_444_444n,
        mint: WSOL_MINT_BYTES,
        tweak,
        blinding,
        memoVersion: MEMO_VERSION_V1,
        memoFlags: 0,
        paymentId: new Uint8Array(MEMO_PAYMENT_ID_LEN),
        isDynamic: false,
      },
      cmBe: frToBeBytes(aliceCm),
    });
    assert.equal(stPoison.notes[0].frozenIntraSiblings, null);

    await syncCompactStoreWithRpc({
      store: stPoison,
      fvk,
      fetchBatch: async (addrs, opts) =>
        addrs.map((a) => {
          if (a === hitSrAddr) return laggedHitSr;
          if (a === hitSubAddr) return poisonedHitSub;
          const full = accounts.get(a) ?? null;
          if (!full || !opts?.dataSlice) return full;
          return full.slice(opts.dataSlice.offset, opts.dataSlice.offset + opts.dataSlice.length);
        }),
    });
    assert.equal(
      stPoison.notes[0].frozenIntraSiblings,
      null,
      'R3-C2: poisoned SubtreePage with lagged SubtreeRootPage must NEVER freeze note',
    );

    // Defense-in-depth: forged matching (SubtreeRootPage, SubtreePage) is rejected against honest
    // LaneTreeState.currentRoot; even if LaneTreeState is ALSO forged, commitment mismatch still
    // prevents freezing an existing note!
    const wrongCmLeaves = [...dummyLeaves];
    wrongCmLeaves[7] = 123_456n;
    const wrongCmSubroot = computeSubtree256Root(wrongCmLeaves, SUBTREE_LEAVES);
    const wrongCmSub = makeSubtreePage(2, 1n, wrongCmLeaves);
    const wrongCmRoots = [dummySubroot, wrongCmSubroot, dummySubroot, dummySubroot, dummySubroot];
    const wrongCmSr = makeSubrootPage(2, 0n, wrongCmRoots);
    const forgedLane2Pda = deriveLanePdaSync(0, 2).address;
    const forgedLane2 = makeLaneState(
      2,
      BigInt(leavesPerLane),
      0n,
      computeLaneRootFromSubroots(wrongCmRoots, dummyFrontier),
    );

    await assert.rejects(
      () =>
        syncCompactStoreWithRpc({
          store: stPoison,
          fvk,
          fetchBatch: async (addrs, opts) =>
            addrs.map((a) => {
              if (a === hitSrAddr) return wrongCmSr;
              if (a === hitSubAddr) return wrongCmSub;
              const full = accounts.get(a) ?? null;
              if (!full || !opts?.dataSlice) return full;
              return full.slice(opts.dataSlice.offset, opts.dataSlice.offset + opts.dataSlice.length);
            }),
        }),
      /Lane #2 root mismatch/,
      'F1: forged (SubtreeRootPage, SubtreePage) against honest LaneTreeState must be rejected',
    );

    await syncCompactStoreWithRpc({
      store: stPoison,
      fvk,
      fetchBatch: async (addrs, opts) =>
        addrs.map((a) => {
          if (a === forgedLane2Pda) return forgedLane2;
          if (a === hitSrAddr) return wrongCmSr;
          if (a === hitSubAddr) return wrongCmSub;
          const full = accounts.get(a) ?? null;
          if (!full || !opts?.dataSlice) return full;
          return full.slice(opts.dataSlice.offset, opts.dataSlice.offset + opts.dataSlice.length);
        }),
    });
    assert.equal(
      stPoison.notes[0].frozenIntraSiblings,
      null,
      'R3-C2 defense-in-depth: leaf commitment mismatch must prevent freezing existing note',
    );

    // Defense-in-depth: lagging LaneTreeState (`nextLeaf = 250`, `fc = 0`) paired with a 256-leaf
    // live-advancing frontier SubtreePage (matching `currentRoot` on `0..250`) must NEVER freeze
    // an unfrozen owned note AND must cap committed frontierLeaves to 250!
    const stUnverified256 = new CompactWalletStore(0, 0n);
    stUnverified256.lanes[0].nextMemoLeaf = 250n;
    const unverifiedLeaves = [...dummyLeaves];
    unverifiedLeaves[7] = aliceCm;
    const unverifiedSub0 = makeSubtreePage(0, 0n, unverifiedLeaves);
    const lane0_250Root = computeLaneRootFromLeaves(unverifiedLeaves.slice(0, 250));
    stUnverified256.recordVerifiedMemo({
      fvk,
      laneId: 0,
      leafIdx: 7n,
      decrypted: {
        amount: 4_444_444n,
        mint: WSOL_MINT_BYTES,
        tweak,
        blinding,
        memoVersion: MEMO_VERSION_V1,
        memoFlags: 0,
        paymentId: new Uint8Array(MEMO_PAYMENT_ID_LEN),
        isDynamic: false,
      },
      cmBe: frToBeBytes(aliceCm),
    });
    await syncCompactStoreWithRpc({
      store: stUnverified256,
      fvk,
      fetchBatch: async (addrs) =>
        addrs.map((a) => {
          if (a === derivePoolPdaSync(0).address) return makePoolState(1);
          if (a === deriveLanePdaSync(0, 0).address) return makeLaneState(0, 250n, 0n, lane0_250Root);
          if (a === deriveSubtreePdaSync(0, 0, 0n).address) return unverifiedSub0;
          return null;
        }),
    });
    assert.equal(
      stUnverified256.notes[0].frozenIntraSiblings,
      null,
      'R3-C2 defense-in-depth: unverified frontier SubtreePage with 256 leaves must NEVER freeze note',
    );
    assert.equal(
      stUnverified256.lanes[0].frontierLeaves.length,
      250,
      'F1: live-advancing frontier commit must be capped to verified frontierRem (250)',
    );
  }

  // =========================================================================
  // R3-C3: Monotonicity guards for `frontierSubSeq`, `frontierLeaves`, and
  //        `prevSealedSubSeq` against lagging RPC replicas!
  // =========================================================================
  {
    const totalLeaves520 = 520;
    const { tweak: tw200, blinding: bl200, memo: memo200 } = encryptNoteMemo(
      alice.viewPk,
      new Uint8Array(32).fill(0x76),
      2_000_000n,
      WSOL_MINT_BYTES,
    );
    const cm200 = computeNoteCommitment(deriveStealthOwner(alice.spendPk, tw200), wsolAsset, 2_000_000n, bl200);
    const { tweak: tw257, blinding: bl257, memo: memo257 } = encryptNoteMemo(
      alice.viewPk,
      new Uint8Array(32).fill(0x77),
      3_000_000n,
      WSOL_MINT_BYTES,
    );
    const cm257 = computeNoteCommitment(deriveStealthOwner(alice.spendPk, tw257), wsolAsset, 3_000_000n, bl257);
    const { tweak: tw515, blinding: bl515, memo: memo515 } = encryptNoteMemo(
      alice.viewPk,
      new Uint8Array(32).fill(0x78),
      4_000_000n,
      WSOL_MINT_BYTES,
    );
    const cm515 = computeNoteCommitment(deriveStealthOwner(alice.spendPk, tw515), wsolAsset, 4_000_000n, bl515);

    const allLeaves = Array.from({ length: totalLeaves520 }, (_, i) =>
      i === 200 ? cm200 : i === 257 ? cm257 : i === 515 ? cm515 : BigInt(i + 1),
    );
    const srRoot0 = computeSubtree256Root(allLeaves.slice(0, 256), 256);
    const srRoot1 = computeSubtree256Root(allLeaves.slice(256, 512), 256);

    const buildSnapshot = (nextLeaf) => {
      const acc = new Map([
        [derivePoolPdaSync(0).address, makePoolState(1)],
        [
          deriveLanePdaSync(0, 0).address,
          makeLaneState(0, BigInt(nextLeaf), 0n, computeLaneRootFromLeaves(allLeaves.slice(0, nextLeaf))),
        ],
      ]);
      const fc = Math.floor(nextLeaf / SUBTREE_LEAVES);
      const frem = nextLeaf % SUBTREE_LEAVES;
      const roots = [];
      if (fc >= 1) roots.push(srRoot0);
      if (fc >= 2) roots.push(srRoot1);
      acc.set(deriveSubrootPdaSync(0, 0, 0n).address, makeSubrootPage(0, 0n, roots));
      for (let s = 0; s < fc; s++) {
        acc.set(
          deriveSubtreePdaSync(0, 0, BigInt(s)).address,
          makeSubtreePage(0, BigInt(s), allLeaves.slice(s * SUBTREE_LEAVES, (s + 1) * SUBTREE_LEAVES)),
        );
      }
      if (frem > 0) {
        acc.set(
          deriveSubtreePdaSync(0, 0, BigInt(fc)).address,
          makeSubtreePage(0, BigInt(fc), allLeaves.slice(fc * SUBTREE_LEAVES, fc * SUBTREE_LEAVES + frem)),
        );
      }
      const memos = Math.ceil(nextLeaf / MEMO_NOTES_PER_PAGE);
      for (let m = 0; m < memos; m++) {
        const cnt = Math.min(MEMO_NOTES_PER_PAGE, nextLeaf - m * MEMO_NOTES_PER_PAGE);
        const mraw = makeMemoPageWithMeta(0, BigInt(m), cnt);
        for (const [idx, memoBytes] of [
          [200, memo200],
          [257, memo257],
          [515, memo515],
        ]) {
          if (idx < nextLeaf && Math.floor(idx / MEMO_NOTES_PER_PAGE) === m) {
            writeMemoSlot(mraw, idx % MEMO_NOTES_PER_PAGE, memoBytes);
          }
        }
        acc.set(deriveMemoPdaSync(0, 0, BigInt(m)).address, mraw);
      }
      return acc;
    };

    const snap260 = buildSnapshot(260);
    const store = new CompactWalletStore(0, 0n);
    const res1 = await syncCompactStoreWithRpc({ store, fvk, fetchBatch: sliceFetch(snap260) });
    assert.equal(res1.discoveredNotes, 2);
    assert.equal(store.lanes[0].finalizedSubroots.length, 1);
    assert.equal(store.lanes[0].frontierSubSeq, 1n);
    assert.equal(store.lanes[0].frontierLeaves.length, 4);
    assert.equal(store.lanes[0].prevSealedSubSeq, 0n);
    assert.equal(store.lanes[0].prevSealedLeaves.length, SUBTREE_LEAVES);

    const { roots: roots260, superRoot: sr260 } = makeSingleLaneRootHistory(
      0,
      computeLaneRootFromLeaves(allLeaves.slice(0, 260)),
      260n,
    );
    const { roots: roots250, superRoot: sr250 } = makeSingleLaneRootHistory(
      0,
      computeLaneRootFromLeaves(allLeaves.slice(0, 250)),
      250n,
    );
    const note257 = store.notes.find((n) => n.leafIndex === 257n);
    const note200 = store.notes.find((n) => n.leafIndex === 200n);
    assert.ok(note257 && note200);

    for (const laggedLeaf of [254, 256, 258]) {
      const laggedSnap = buildSnapshot(laggedLeaf);
      await syncCompactStoreWithRpc({ store, fvk, fetchBatch: sliceFetch(laggedSnap) });
      assert.equal(store.lanes[0].frontierSubSeq, 1n, `R3-C3 (lag=${laggedLeaf}): frontierSubSeq must not regress`);
      assert.equal(store.lanes[0].frontierLeaves.length, 4, `R3-C3 (lag=${laggedLeaf}): frontierLeaves must not truncate/clear`);
      assert.equal(store.lanes[0].prevSealedSubSeq, 0n, `R3-C3 (lag=${laggedLeaf}): prevSealedSubSeq must not regress`);
      assert.equal(store.lanes[0].prevSealedLeaves.length, SUBTREE_LEAVES);

      // Verify offline witness building against BOTH pre-seal (250) and frontier (260) GlobalRootHistory snapshots
      // on a round-tripped copy (so `buildWitnessForNote`'s post-seal pruning doesn't clear prevSealed between iterations).
      const snapCopy = CompactWalletStore.fromJSON(store.toJSON());
      const w250 = snapCopy.buildWitnessForNote(snapCopy.notes.find((n) => n.leafIndex === 200n), roots250);
      assert.equal(w250.superRoot, sr250);
      assert.equal(computeMerkleRoot4Ary(w250.path, cm200), sr250);
      const w260 = snapCopy.buildWitnessForNote(snapCopy.notes.find((n) => n.leafIndex === 257n), roots260);
      assert.equal(w260.superRoot, sr260);
      assert.equal(computeMerkleRoot4Ary(w260.path, cm257), sr260);
    }
    const w260Direct = store.buildWitnessForNote(note257, roots260);
    assert.equal(w260Direct.superRoot, sr260);
    assert.equal(computeMerkleRoot4Ary(w260Direct.path, cm257), sr260);

    // Advance to 520 (`prevSealedSubSeq = 1n`, `frontierSubSeq = 2n`, 8 frontier leaves),
    // then sync against lagging RPC at 260 -> `prevSealedSubSeq` must stay `1n`!
    const snap520 = buildSnapshot(520);
    await syncCompactStoreWithRpc({ store, fvk, fetchBatch: sliceFetch(snap520) });
    assert.equal(store.lanes[0].finalizedSubroots.length, 2);
    assert.equal(store.lanes[0].frontierSubSeq, 2n);
    assert.equal(store.lanes[0].frontierLeaves.length, 8);
    assert.equal(store.lanes[0].prevSealedSubSeq, 1n);

    await syncCompactStoreWithRpc({ store, fvk, fetchBatch: sliceFetch(snap260) });
    assert.equal(store.lanes[0].frontierSubSeq, 2n);
    assert.equal(store.lanes[0].frontierLeaves.length, 8);
    assert.equal(store.lanes[0].prevSealedSubSeq, 1n, 'R3-C3: lagging RPC at 260 must not regress prevSealedSubSeq to 0n');

    const { roots: roots520, superRoot: sr520 } = makeSingleLaneRootHistory(
      0,
      computeLaneRootFromLeaves(allLeaves),
      520n,
    );
    const note515 = store.notes.find((n) => n.leafIndex === 515n);
    assert.ok(note515);
    const w520 = store.buildWitnessForNote(note515, roots520);
    assert.equal(w520.superRoot, sr520);
    assert.equal(computeMerkleRoot4Ary(w520.path, cm515), sr520);
  }
});

test('R4-C2/C3/C4 & relayer.ts: deriveSubaccountKeys 32B check, freeze commitment guard, MAX_LEAVES_PER_LANE cap, Phase 0 atomic 17-account batch, and extraAtaMints/feeDecimals/outputTransferFee', async () => {
  // =========================================================================
  // R4-C2: deriveSubaccountKeys strictly enforces 32-byte masterSeed32
  // =========================================================================
  assert.throws(
    () => deriveSubaccountKeys(new Uint8Array(0), 1),
    (err) => err instanceof RangeError && /Master seed must be 32 bytes/.test(err.message),
  );
  assert.throws(
    () => deriveSubaccountKeys(new Uint8Array(0), 0),
    (err) => err instanceof RangeError && /Master seed must be 32 bytes/.test(err.message),
  );
  assert.throws(
    () => deriveSubaccountKeys(new Uint8Array(64), 1),
    (err) => err instanceof RangeError && /Master seed must be 32 bytes/.test(err.message),
  );
  assert.throws(
    () => deriveSubaccountKeys(new Uint8Array(31), 2),
    (err) => err instanceof RangeError && /Master seed must be 32 bytes/.test(err.message),
  );
  const validSeed = new Uint8Array(32).fill(0x88);
  const sub0 = deriveSubaccountKeys(validSeed, 0);
  const sub1 = deriveSubaccountKeys(validSeed, 1);
  assert.notEqual(sub0.address, sub1.address);

  // =========================================================================
  // R4-C3: CompactWalletStore freeze commitment guard & MAX_LEAVES_PER_LANE cap
  // =========================================================================
  const fvk = exportFullViewingKey(sub0);
  const wsolAsset = deriveAssetId(WSOL_MINT_BYTES);
  const { tweak, blinding, memo } = encryptNoteMemo(
    sub0.viewPk,
    new Uint8Array(32).fill(0x89),
    5_555_555n,
    WSOL_MINT_BYTES,
  );
  const cmFr = computeNoteCommitment(deriveStealthOwner(sub0.spendPk, tweak), wsolAsset, 5_555_555n, blinding);
  const cmBe = frToBeBytes(cmFr);

  const partialLeaves = Array.from({ length: 10 }, (_, i) => (i === 7 ? cmFr : BigInt(i + 1)));
  const subPartial = makeSubtreePage(0, 0n, partialLeaves);
  const memoPartial = makeMemoPageWithMeta(0, 0n, 10);
  writeMemoSlot(memoPartial, 7, memo);

  const store = new CompactWalletStore(0, 0n);
  const d0 = store.ingestLanePages({
    fvk,
    laneId: 0,
    subtreePages: [{ pageSeq: 0n, raw: subPartial }],
    memoPages: [{ pageSeq: 0n, raw: memoPartial }],
    nfPages: [],
  });
  assert.equal(d0, 1);
  assert.equal(store.notes.length, 1);
  assert.equal(store.notes[0].frozenIntraSiblings, null);

  // 1. Direct freezeOwnedNotesInSubtreePage with mismatched leaf at offset 7 MUST skip!
  const forgedFrLeaves = Array.from({ length: SUBTREE_LEAVES }, (_, i) => BigInt(i + 100));
  const forgedBeLeaves = forgedFrLeaves.map((x) => frToBeBytes(x));
  store.freezeOwnedNotesInSubtreePage(0, 0n, forgedBeLeaves);
  assert.equal(
    store.notes[0].frozenIntraSiblings,
    null,
    'R4-C3: forged direct freezeOwnedNotesInSubtreePage must skip mismatched commitment',
  );
  assert.equal(store.notes[0].frozenIntraPositions, null);

  // 2. ingestLanePages with forged sealed SubtreePage #0 MUST also skip freezing!
  const forgedSealedSub = makeSubtreePage(0, 0n, forgedFrLeaves);
  store.ingestLanePages({
    fvk,
    laneId: 0,
    subtreePages: [{ pageSeq: 0n, raw: forgedSealedSub }],
    memoPages: [],
    nfPages: [],
  });
  assert.equal(
    store.notes[0].frozenIntraSiblings,
    null,
    'R4-C3: forged sealed SubtreePage via ingestLanePages must skip mismatched commitment',
  );

  // 3. Matching commitment at offset 7 freezes cleanly!
  const validBeLeaves = [...forgedBeLeaves];
  validBeLeaves[7] = cmBe;
  store.freezeOwnedNotesInSubtreePage(0, 0n, validBeLeaves);
  assert.notEqual(store.notes[0].frozenIntraSiblings, null);
  assert.notEqual(store.notes[0].frozenIntraPositions, null);

  // 4. ingestLanePages breaks cleanly at MAX_LEAVES_PER_LANE without overflowing nextMemoLeaf
  const capStore = new CompactWalletStore(0, 0n);
  capStore.lanes[0].nextMemoLeaf = MAX_LEAVES_PER_LANE;
  const maxMemoSeq = MAX_LEAVES_PER_LANE / BigInt(MEMO_NOTES_PER_PAGE);
  const memoAtMax = makeMemoPageWithMeta(0, maxMemoSeq, MEMO_NOTES_PER_PAGE);
  const dCap = capStore.ingestLanePages({
    fvk,
    laneId: 0,
    subtreePages: [],
    memoPages: [{ pageSeq: maxMemoSeq, raw: memoAtMax }],
    nfPages: [],
  });
  assert.equal(dCap, 0);
  assert.equal(capStore.lanes[0].nextMemoLeaf, MAX_LEAVES_PER_LANE);

  // =========================================================================
  // R4-C4: Phase 0 fetches [poolPda, lane_0..lane_15] in ONE atomic 17-account batch
  // =========================================================================
  const poolPda = derivePoolPdaSync(0).address;
  const allLanePdas = Array.from({ length: NUM_LANES }, (_, l) => deriveLanePdaSync(0, l).address);

  const cmFrLane0Root = computeLaneRootFromLeaves([cmFr]);
  for (const activeLanes of [4, 8]) {
    const accounts = new Map([[poolPda, makePoolState(activeLanes)]]);
    for (let l = 0; l < activeLanes; l++) {
      accounts.set(
        allLanePdas[l],
        l === 0 ? makeLaneState(0, 1n, 0n, cmFrLane0Root) : makeLaneState(l, 0n, 0n),
      );
    }
    accounts.set(deriveSubtreePdaSync(0, 0, 0n).address, makeSubtreePage(0, 0n, [cmFr]));
    const m0 = makeMemoPageWithMeta(0, 0n, 1);
    writeMemoSlot(m0, 0, memo);
    accounts.set(deriveMemoPdaSync(0, 0, 0n).address, m0);

    // Direct fetchPoolAndLanes -> strictly 1 call of 17 addresses
    const directCalls = [];
    const directRes = await fetchPoolAndLanes(async (addrs) => {
      directCalls.push([...addrs]);
      return addrs.map((a) => accounts.get(a) ?? null);
    });
    assert.equal(directCalls.length, 1, 'R4-C4: fetchPoolAndLanes must issue exactly 1 batch call');
    assert.equal(directCalls[0].length, 1 + NUM_LANES);
    assert.equal(directCalls[0][0], poolPda);
    for (let l = 0; l < NUM_LANES; l++) {
      assert.equal(directCalls[0][1 + l], allLanePdas[l]);
    }
    assert.equal(directRes.pool.activeLanes, activeLanes);
    assert.equal(directRes.lanes.length, activeLanes);

    // Full syncCompactStoreWithRpc -> Phase 0 is strictly 1 call of 17 addresses, never re-fetching lanes
    const syncCalls = [];
    const syncStore = new CompactWalletStore(0, 0n);
    const syncRes = await syncCompactStoreWithRpc({
      store: syncStore,
      fvk,
      fetchBatch: async (addrs) => {
        syncCalls.push([...addrs]);
        return addrs.map((a) => accounts.get(a) ?? null);
      },
    });
    assert.equal(syncRes.pool.activeLanes, activeLanes);
    assert.equal(syncRes.lanes.length, activeLanes);
    assert.equal(syncRes.discoveredNotes, 1);
    assert.equal(syncCalls[0].length, 1 + NUM_LANES);
    assert.equal(syncCalls[0][0], poolPda);
    for (let i = 1; i < syncCalls.length; i++) {
      for (const addr of syncCalls[i]) {
        assert.equal(allLanePdas.includes(addr), false, 'R4-C4: no second Phase 0 lane fetch');
      }
    }
  }

  // Missing active lane in 17-account batch rejects cleanly
  await assert.rejects(
    () =>
      fetchPoolAndLanes(async (addrs) =>
        addrs.map((a) => {
          if (a === poolPda) return makePoolState(4);
          if (a === allLanePdas[0] || a === allLanePdas[1] || a === allLanePdas[2]) {
            return makeLaneState(allLanePdas.indexOf(a), 0n, 0n);
          }
          return null;
        }),
      ),
    /LaneTreeState #3 missing/,
  );

  // =========================================================================
  // relayer.ts: extraAtaMints query param, feeDecimals, and outputTransferFee
  // =========================================================================
  const relayCalls = [];
  const origFetch = globalThis.fetch;
  const pyusdMint = '2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo';
  const usdcMint = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
  globalThis.fetch = async (url, init) => {
    relayCalls.push({ url: String(url), init });
    if (String(url).includes('/v1/swap/quote')) {
      return new Response(
        JSON.stringify({
          ok: true,
          cluster: 'mainnet',
          provider: 'jupiter',
          quote: { provider: 'jupiter', outAmount: '9750000' },
          netInputAmount: '10000000',
          inputTransferFeeBps: 0,
          outputTransferFee: { bps: 250, maxFee: '5000000' },
          mints: {
            input: { decimals: 6, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
            output: { decimals: 6, tokenProgram: TOKEN_2022_PROGRAM_ID },
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    return new Response(
      JSON.stringify({
        ok: true,
        cluster: 'mainnet',
        op: 'exec_escrow',
        billingMode: 'self_paying',
        feeSide: 'out',
        feeMint: WSOL_MINT,
        feeTokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
        feeDecimals: 9,
        feeRecipient: SYSTEM_PROGRAM_ID,
        feeShieldedAddress: null,
        feeRecipientExists: true,
        needsFeeAtaSetup: false,
        relayerFee: '4870000',
        feeBps: 0,
        estimatedRelayCostLamports: '4420000',
        estimatedRelayCostUsd: 0.65,
        reason: 'ok',
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  };
  try {
    const client = new AudrenRelayClient('https://relay.example.test');
    const fq = await client.getFeeQuote({
      cluster: 'mainnet',
      op: 'exec_escrow',
      mint: WSOL_MINT,
      amount: '100000000',
      feeOnOutput: true,
      missingAtaCount: 2,
      extraAtaMints: [pyusdMint, usdcMint],
    });
    const fqUrl = new URL(relayCalls[0].url);
    assert.equal(fqUrl.pathname, '/v1/fee-quote');
    assert.equal(fqUrl.searchParams.get('extraAtaMints'), `${pyusdMint},${usdcMint}`);
    assert.equal(fqUrl.searchParams.get('missingAtaCount'), '2');
    assert.equal(fq.feeDecimals, 9);

    // Empty extraAtaMints array omits the query parameter cleanly
    await client.getFeeQuote({
      op: 'exec_escrow',
      mint: WSOL_MINT,
      extraAtaMints: [],
    });
    const fqEmptyUrl = new URL(relayCalls[1].url);
    assert.equal(fqEmptyUrl.searchParams.has('extraAtaMints'), false);

    // quoteSwap preserves outputTransferFee
    const sq = await client.quoteSwap({
      cluster: 'mainnet',
      inputMint: usdcMint,
      outputMint: pyusdMint,
      amount: '10000000',
    });
    assert.deepEqual(sq.outputTransferFee, { bps: 250, maxFee: '5000000' });
    assert.equal(sq.quote?.outAmount, '9750000');
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('v1.3.0 GlobalRootHistory: PDA derivation, strict bounds, multi-note snapshot selection, fetchGlobalRootHistory fallback, Auto-OpenPage & CU limits', async () => {
  // 1. Canonical roots PDA derivation + u32 bounds enforcement
  const rootsPda0 = deriveRootsPdaSync(0);
  assert.equal(rootsPda0.address, '249YJTuRtiKAnh346Tc18kF9bHrktdrTzyJMtvUKUgC7');
  assert.equal(rootsPda0.bump, 254);
  for (const badPoolId of [-1, 0x1_0000_0000, 1.5, Number.NaN]) {
    assert.throws(() => deriveRootsPdaSync(badPoolId), /u32|range|integer/i);
  }

  // 2. Constants & error codes match Wave 1
  assert.equal(ROOT_HISTORY_LEN, 10_216);
  assert.equal(ROOT_SNAPSHOT_LEN, 672);
  assert.equal(ROOT_ENTRY_LEN, 40);
  assert.equal(SLOT_RING_LEN, 128);
  assert.equal(EPOCH_RING_LEN, 89);
  assert.equal(DEFAULT_ROOT_EPOCH_INTERVAL, 32n);
  assert.equal(MAX_ROOT_EPOCH_INTERVAL, 256n);
  assert.equal(ROOT_RING_SLOT, 0);
  assert.equal(ROOT_RING_EPOCH, 1);
  assert.equal(TAG_INIT_ROOT_HISTORY, 0x04);
  assert.equal(AUDREN_ERRORS[6007], 'InvalidRootRing');
  assert.equal(AUDREN_ERRORS[6008], 'RootIndexOutOfBounds');
  assert.equal(AUDREN_ERRORS[6009], 'RootHistoryMismatch');

  // 3. decodeGlobalRootHistory strict header, ring & lane count validation
  const leaf0 = 777n;
  const leaf1 = 888n;
  const stableLane0Root = computeLaneRootFromLeaves([leaf0]);
  const latestLane0Root = computeLaneRootFromLeaves([leaf0, leaf1]);
  const stableLaneRoots = new Array(NUM_LANES).fill(ZERO_HASHES_4ARY[18]);
  stableLaneRoots[0] = stableLane0Root;
  const latestLaneRoots = new Array(NUM_LANES).fill(ZERO_HASHES_4ARY[18]);
  latestLaneRoots[0] = latestLane0Root;
  const stableLaneCounts = new Array(NUM_LANES).fill(0n);
  stableLaneCounts[0] = 1n;
  const latestLaneCounts = new Array(NUM_LANES).fill(0n);
  latestLaneCounts[0] = 2n;

  const {
    roots: dualRoots,
    superRoot: latestSuperRoot,
    stableSuperRoot,
    raw: dualRaw,
  } = makeSyntheticRootHistory({
    poolId: 0,
    laneRoots: latestLaneRoots,
    laneCounts: latestLaneCounts,
    stableLaneRoots,
    stableLaneCounts,
    slotCursor: 5,
    slotCount: 6,
    epochCursor: 2,
    epochCount: 3,
    sameSlotBumped: 1,
    latestSlot: 130n,
    stableSlot: 96n,
    epochInterval: 32n,
  });

  assert.equal(dualRoots.poolId, 0);
  assert.equal(dualRoots.bump, 254);
  assert.equal(dualRoots.slotCursor, 5);
  assert.equal(dualRoots.slotCount, 6);
  assert.equal(dualRoots.epochCursor, 2);
  assert.equal(dualRoots.epochCount, 3);
  assert.equal(dualRoots.sameSlotBumped, true);
  assert.equal(dualRoots.latestSlot, 130n);
  assert.equal(dualRoots.stableSlot, 96n);
  assert.equal(dualRoots.epochInterval, 32n);
  assert.deepEqual(decodeSlotRingEntry(dualRaw, 5).superRoot, frToBeBytes(latestSuperRoot));
  assert.equal(decodeSlotRingEntry(dualRaw, 5).slot, 130n);
  assert.deepEqual(decodeEpochRingEntry(dualRaw, 2).superRoot, frToBeBytes(stableSuperRoot));
  assert.equal(decodeEpochRingEntry(dualRaw, 2).slot, 96n);
  assert.throws(() => decodeSlotRingEntry(dualRaw, SLOT_RING_LEN), /ring|index|bounds/i);
  assert.throws(() => decodeEpochRingEntry(dualRaw, EPOCH_RING_LEN), /ring|index|bounds/i);

  const mutate = (fn) => {
    const copy = dualRaw.slice();
    fn(copy, new DataView(copy.buffer));
    return copy;
  };
  assert.throws(() => decodeGlobalRootHistory(dualRaw.subarray(0, ROOT_HISTORY_LEN - 1)), /Invalid GlobalRootHistory account \(len=10215\)/);
  assert.throws(() => decodeGlobalRootHistory(mutate((b) => { b[0] ^= 1; })), /Invalid GlobalRootHistory account/);
  assert.throws(() => decodeGlobalRootHistory(mutate((_, dv) => dv.setUint16(RT_OFF_SLOT_COUNT, 0, true))), /slotCount/i);
  assert.throws(
    () => decodeGlobalRootHistory(mutate((_, dv) => dv.setUint16(RT_OFF_SLOT_COUNT, SLOT_RING_LEN + 1, true))),
    /slotCount/i,
  );
  assert.throws(() => decodeGlobalRootHistory(mutate((_, dv) => dv.setUint16(RT_OFF_SLOT_CURSOR, 6, true))), /slotCursor/i);
  assert.throws(() => decodeGlobalRootHistory(mutate((_, dv) => dv.setUint16(RT_OFF_EPOCH_COUNT, 0, true))), /epochCount/i);
  assert.throws(
    () => decodeGlobalRootHistory(mutate((_, dv) => dv.setUint16(RT_OFF_EPOCH_COUNT, EPOCH_RING_LEN + 1, true))),
    /epochCount/i,
  );
  assert.throws(() => decodeGlobalRootHistory(mutate((_, dv) => dv.setUint16(RT_OFF_EPOCH_CURSOR, 3, true))), /epochCursor/i);
  assert.throws(() => decodeGlobalRootHistory(mutate((b) => { b[RT_OFF_SAME_SLOT_BUMPED] = 2; })), /sameSlotBumped/i);
  assert.throws(
    () => decodeGlobalRootHistory(mutate((_, dv) => dv.setBigUint64(RT_OFF_EPOCH_INTERVAL, 0n, true))),
    /epochInterval/i,
  );
  assert.throws(
    () =>
      decodeGlobalRootHistory(
        mutate((_, dv) => dv.setBigUint64(RT_OFF_EPOCH_INTERVAL, MAX_ROOT_EPOCH_INTERVAL + 1n, true)),
      ),
    /epochInterval/i,
  );
  assert.throws(
    () =>
      decodeGlobalRootHistory(
        mutate((_, dv) => dv.setBigUint64(RT_OFF_LATEST_LANE_COUNTS, MAX_LEAVES_PER_LANE + 1n, true)),
      ),
    /latestLaneCounts/i,
  );
  assert.throws(
    () =>
      decodeGlobalRootHistory(
        mutate((_, dv) => dv.setBigUint64(RT_OFF_STABLE_LANE_COUNTS, MAX_LEAVES_PER_LANE + 1n, true)),
      ),
    /stableLaneCounts/i,
  );

  // 4. selectRootSnapshotForNotes: prefers stable epoch ring, falls back to latest slot ring for fresh notes
  const stableChoice = selectRootSnapshotForNotes(dualRoots, [{ laneId: 0, leafIndex: 0n }]);
  assert.ok(stableChoice);
  assert.equal(stableChoice.ringKind, ROOT_RING_EPOCH);
  assert.equal(stableChoice.ringIdx, 2);
  assert.equal(stableChoice.slot, 96n);
  assert.deepEqual(stableChoice.superRoot, frToBeBytes(stableSuperRoot));

  // Two notes where one is only in latest -> both share latest slot ring!
  const latestChoice = selectRootSnapshotForNotes(dualRoots, [
    { laneId: 0, leafIndex: 0n },
    { laneId: 0, leafIndex: 1n },
  ]);
  assert.ok(latestChoice);
  assert.equal(latestChoice.ringKind, ROOT_RING_SLOT);
  assert.equal(latestChoice.ringIdx, 5);
  assert.equal(latestChoice.slot, 130n);
  assert.deepEqual(latestChoice.superRoot, frToBeBytes(latestSuperRoot));

  // Uncovered note or out-of-range lane returns null
  assert.equal(selectRootSnapshotForNotes(dualRoots, [{ laneId: 0, leafIndex: 2n }]), null);
  assert.equal(selectRootSnapshotForNotes(dualRoots, [{ laneId: NUM_LANES, leafIndex: 0n }]), null);
  assert.equal(selectRootSnapshotForNotes(dualRoots, [{ laneId: 0, leafIndex: -1n }]), null);

  // 5. reconstructWitness header/ring tamper rejection + multi-note shared snapshot parity
  const viewSk = new Uint8Array(32).fill(0x42);
  const sub0Addr = deriveSubtreePdaSync(0, 0, 0n).address;
  const sub0TwoLeaves = makeSubtreePage(0, 0n, [leaf0, leaf1]);

  const wrongPoolRaw = mutate((_, dv) => dv.setUint32(RT_OFF_POOL_ID, 1, true));
  const tamperedSlotRingRaw = mutate((b) => { b[RT_OFF_SLOT_RING + 5 * ROOT_ENTRY_LEN] ^= 1; });
  const tamperedEpochRingRaw = mutate((b) => { b[RT_OFF_EPOCH_RING + 2 * ROOT_ENTRY_LEN] ^= 1; });

  for (const [label, badRaw, pattern] of [
    ['wrong poolId', wrongPoolRaw, /GlobalRootHistory header mismatch/i],
    ['tampered slotRing cursor entry', tamperedSlotRingRaw, /slotRing\[slotCursor\] superRoot mismatch/i],
    ['tampered epochRing cursor entry', tamperedEpochRingRaw, /epochRing\[epochCursor\] superRoot mismatch/i],
  ]) {
    for (const privacyMode of ['strict', 'fast']) {
      await assert.rejects(
        () =>
          reconstructWitness({
            fetchBatch: async (addrs) =>
              addrs.map((a) => {
                if (a === rootsPda0.address) return badRaw;
                if (a === sub0Addr) return sub0TwoLeaves;
                return null;
              }),
            poolId: 0,
            laneId: 0,
            leafIdx: 0n,
            privacyMode,
            viewSk: privacyMode === 'strict' ? viewSk : undefined,
          }),
        pattern,
        `reconstructWitness (${label}, ${privacyMode}) must reject`,
      );
    }
  }

  // Multi-note witness reconstruction: note 0 + note 1 via allInputNotes MUST pick identical latest snapshot!
  const fetchDual = async (addrs) =>
    addrs.map((a) => {
      if (a === rootsPda0.address) return dualRaw;
      if (a === sub0Addr) return sub0TwoLeaves;
      return null;
    });
  const sharedInputs = [
    { laneId: 0, leafIndex: 0n },
    { laneId: 0, leafIndex: 1n },
  ];
  const w0 = await reconstructWitness({
    fetchBatch: fetchDual,
    poolId: 0,
    laneId: 0,
    leafIdx: 0n,
    allInputNotes: sharedInputs,
    viewSk,
  });
  const w1 = await reconstructWitness({
    fetchBatch: fetchDual,
    poolId: 0,
    laneId: 0,
    leafIdx: 1n,
    rootHistory: w0.roots,
    rootSnapshot: w0.snapshot,
    viewSk,
  });
  assert.equal(w0.rootRingKind, ROOT_RING_SLOT);
  assert.equal(w0.rootRingIdx, 5);
  assert.equal(w1.rootRingKind, w0.rootRingKind);
  assert.equal(w1.rootRingIdx, w0.rootRingIdx);
  assert.equal(w0.superRoot, latestSuperRoot);
  assert.equal(w1.superRoot, latestSuperRoot);
  assert.equal(computeMerkleRoot4Ary(w0.path, leaf0), latestSuperRoot);
  assert.equal(computeMerkleRoot4Ary(w1.path, leaf1), latestSuperRoot);

  // Single older note (leaf 0 only) picks stable epoch ring (kind=1, idx=2)!
  const wStable = await reconstructWitness({
    fetchBatch: fetchDual,
    poolId: 0,
    laneId: 0,
    leafIdx: 0n,
    viewSk,
  });
  assert.equal(wStable.rootRingKind, ROOT_RING_EPOCH);
  assert.equal(wStable.rootRingIdx, 2);
  assert.equal(wStable.superRoot, stableSuperRoot);
  assert.equal(computeMerkleRoot4Ary(wStable.path, leaf0), stableSuperRoot);

  // 5b. CompactWalletStore.buildWitnessForNote strict GlobalRootHistory & RootSnapshotChoice validation
  {
    const store = new CompactWalletStore(0);
    store.lanes[0].frontierSubSeq = 0n;
    store.lanes[0].frontierLeaves = [frToBeBytes(leaf0), frToBeBytes(leaf1)];
    const validNote = {
      poolId: 0,
      laneId: 0,
      leafIndex: 0n,
      globalLeafIndex: 0n,
      mint: new Uint8Array(32),
      amount: 100n,
      tweak: new Uint8Array(32),
      blinding: new Uint8Array(32),
      stealthOwner: new Uint8Array(32),
      commitment: frToBeBytes(leaf0),
      nullifier: new Uint8Array(32),
      paymentId: new Uint8Array(8),
      isDynamic: false,
      spent: false,
      frozenIntraSiblings: null,
      frozenIntraPositions: null,
    };

    // Baseline succeeds and selects stable epoch ring (kind=1, idx=2)
    const okWitness = store.buildWitnessForNote(validNote, dualRoots);
    assert.equal(okWitness.rootRingKind, ROOT_RING_EPOCH);
    assert.equal(okWitness.rootRingIdx, 2);
    assert.equal(okWitness.superRoot, stableSuperRoot);

    // Tampered epochRing[epochCursor].superRoot MUST throw (no silent stable -> latest downgrade!)
    const tamperedEpochHistory = decodeGlobalRootHistory(tamperedEpochRingRaw);
    assert.throws(
      () => store.buildWitnessForNote(validNote, tamperedEpochHistory),
      /epochRing\[epochCursor\] superRoot mismatch/i,
    );

    // Tampered slotRing[slotCursor].superRoot MUST throw
    const tamperedSlotHistory = decodeGlobalRootHistory(tamperedSlotRingRaw);
    assert.throws(
      () => store.buildWitnessForNote(validNote, tamperedSlotHistory),
      /slotRing\[slotCursor\] superRoot mismatch/i,
    );

    // All-zero latestSuperRoot / stableSuperRoot MUST throw
    const zeroStableHistory = {
      ...dualRoots,
      stableSuperRoot: new Uint8Array(32),
      epochRing: dualRoots.epochRing.map((e, idx) =>
        idx === dualRoots.epochCursor ? { ...e, superRoot: new Uint8Array(32) } : e,
      ),
    };
    assert.throws(
      () => store.buildWitnessForNote(validNote, zeroStableHistory),
      /stableSuperRoot must be a non-zero/i,
    );
    const zeroLatestHistory = {
      ...dualRoots,
      latestSuperRoot: new Uint8Array(32),
      slotRing: dualRoots.slotRing.map((e, idx) =>
        idx === dualRoots.slotCursor ? { ...e, superRoot: new Uint8Array(32) } : e,
      ),
    };
    assert.throws(
      () => store.buildWitnessForNote(validNote, zeroLatestHistory),
      /latestSuperRoot must be a non-zero/i,
    );

    // Out-of-bounds cursor / count MUST throw
    assert.throws(
      () => store.buildWitnessForNote(validNote, { ...dualRoots, slotCursor: dualRoots.slotCount }),
      /ring cursor or count out of bounds/i,
    );
    assert.throws(
      () => store.buildWitnessForNote(validNote, { ...dualRoots, epochCount: 90 }),
      /ring cursor or count out of bounds/i,
    );

    // Wrong poolId on GlobalRootHistory or note MUST throw (even if note.poolId === history.poolId !== store.poolId!)
    const wrongPoolHistory = decodeGlobalRootHistory(wrongPoolRaw);
    assert.throws(
      () => store.buildWitnessForNote(validNote, wrongPoolHistory),
      /GlobalRootHistory header mismatch/i,
    );
    assert.throws(
      () => store.buildWitnessForNote({ ...validNote, poolId: 1 }, wrongPoolHistory),
      /Note poolId mismatch/i,
    );

    // Round-2 regression: tampered/non-canonical/forged stable snapshot with stableLaneCounts=[0n;16] & genuine latest
    // MUST throw in store.buildWitnessForNote (NO silent stable -> latest downgrade!), and tampered latest MUST throw too!
    const forgedFrBytes = frToBeBytes(999_999n);
    const nonCanonBytes = new Uint8Array(32).fill(0xff);
    const zeroCounts16 = Array.from({ length: NUM_LANES }, () => 0n);

    const nonCanonStableHistory = {
      ...dualRoots,
      stableSuperRoot: nonCanonBytes,
      stableLaneCounts: zeroCounts16,
      epochRing: dualRoots.epochRing.map((e, idx) =>
        idx === dualRoots.epochCursor ? { ...e, superRoot: nonCanonBytes } : e,
      ),
    };
    assert.throws(
      () => store.buildWitnessForNote(validNote, nonCanonStableHistory),
      /field|canonical|modulus|Fr/i,
    );

    const forgedStableHistory = {
      ...dualRoots,
      stableSuperRoot: forgedFrBytes,
      stableLaneCounts: zeroCounts16,
      epochRing: dualRoots.epochRing.map((e, idx) =>
        idx === dualRoots.epochCursor ? { ...e, superRoot: forgedFrBytes } : e,
      ),
    };
    assert.throws(
      () => store.buildWitnessForNote(validNote, forgedStableHistory),
      /Reconstructed Merkle root mismatch/i,
    );

    const tamperedLatestHistory = {
      ...dualRoots,
      latestSuperRoot: forgedFrBytes,
      slotRing: dualRoots.slotRing.map((e, idx) =>
        idx === dualRoots.slotCursor ? { ...e, superRoot: forgedFrBytes } : e,
      ),
    };
    assert.throws(
      () => store.buildWitnessForNote(validNote, tamperedLatestHistory),
      /Reconstructed Merkle root mismatch/i,
    );

    // Caller-supplied GlobalRootHistory with short ring array or laneCounts > MAX_LEAVES_PER_LANE MUST throw
    assert.throws(
      () => store.buildWitnessForNote(validNote, { ...dualRoots, slotRing: dualRoots.slotRing.slice(0, 1) }),
      /ring cursor or count out of bounds/i,
    );
    assert.throws(
      () =>
        store.buildWitnessForNote(validNote, {
          ...dualRoots,
          stableLaneCounts: dualRoots.stableLaneCounts.map((c, i) =>
            i === 0 ? MAX_LEAVES_PER_LANE + 1n : c,
          ),
        }),
      RangeError,
    );

    // Out-of-range or non-integer laneId MUST throw RangeError (both GlobalRootHistory and RootSnapshotChoice branches)
    for (const badLane of [-1, 16, 1.5, Number.NaN]) {
      assert.throws(
        () => store.buildWitnessForNote({ ...validNote, laneId: badLane }, dualRoots),
        RangeError,
      );
      assert.throws(
        () => store.buildWitnessForNote({ ...validNote, laneId: badLane }, w0.snapshot),
        RangeError,
      );
    }

    // Direct RootSnapshotChoice: snapCount > MAX_LEAVES_PER_LANE & all-zero superRoot MUST throw RangeError
    assert.throws(
      () =>
        store.buildWitnessForNote(validNote, {
          ...w0.snapshot,
          laneCounts: w0.snapshot.laneCounts.map((c, i) => (i === 0 ? MAX_LEAVES_PER_LANE + 1n : c)),
        }),
      RangeError,
    );
    assert.throws(
      () =>
        store.buildWitnessForNote(validNote, {
          ...w0.snapshot,
          superRoot: new Uint8Array(32),
        }),
      RangeError,
    );

    // CompactWalletStore.fromJSON MUST reject any note with note.poolId !== store.poolId
    const storeWithNote = new CompactWalletStore(0);
    storeWithNote.notes.push({
      ...validNote,
      paymentId: new Uint8Array(MEMO_PAYMENT_ID_LEN),
    });
    const parsedJson = JSON.parse(storeWithNote.toJSON());
    parsedJson.notes[0].poolId = 1;
    assert.throws(
      () => CompactWalletStore.fromJSON(JSON.stringify(parsedJson)),
      /does not match store poolId/i,
    );

    // Invalid RootSnapshotChoice ringKind or ringIdx out of bounds MUST throw RangeError
    assert.throws(
      () => store.buildWitnessForNote(validNote, { ...w0.snapshot, ringKind: 2 }),
      RangeError,
    );
    assert.throws(
      () => store.buildWitnessForNote(validNote, { ...w0.snapshot, ringKind: -1 }),
      RangeError,
    );
    assert.throws(
      () =>
        store.buildWitnessForNote(validNote, {
          ...w0.snapshot,
          ringKind: ROOT_RING_SLOT,
          ringIdx: 128,
        }),
      RangeError,
    );
    assert.throws(
      () =>
        store.buildWitnessForNote(validNote, {
          ...w0.snapshot,
          ringKind: ROOT_RING_SLOT,
          ringIdx: -1,
        }),
      RangeError,
    );
    assert.throws(
      () =>
        store.buildWitnessForNote(validNote, {
          ...w0.snapshot,
          ringKind: ROOT_RING_EPOCH,
          ringIdx: 89,
        }),
      RangeError,
    );
  }

  // 6. fetchGlobalRootHistory: finalized-first + confirmed-fallback when freshly deposited note isn't finalized yet
  const { raw: finalizedOnlyLeaf0Raw } = makeSingleLaneRootHistory(0, stableLane0Root, 1n);
  const fetchCommitmentLog = [];
  const fetchFinalized = async (addrs) => {
    assert.deepEqual(addrs, [rootsPda0.address]);
    fetchCommitmentLog.push('finalized');
    return [finalizedOnlyLeaf0Raw];
  };
  const fetchConfirmed = async (addrs) => {
    assert.deepEqual(addrs, [rootsPda0.address]);
    fetchCommitmentLog.push('confirmed');
    return [dualRaw];
  };
  // Note 0 is already in finalized -> strictly 1 finalized call!
  const finOnly = await fetchGlobalRootHistory({
    fetchFinalized,
    fetchConfirmed,
    poolId: 0,
    requiredNotes: [{ laneId: 0, leafIndex: 0n }],
  });
  assert.equal(finOnly.commitment, 'finalized');
  assert.deepEqual(fetchCommitmentLog, ['finalized']);
  assert.equal(finOnly.snapshot.ringKind, ROOT_RING_EPOCH);

  // Note 1 is only in confirmed -> automatically falls back to confirmed!
  fetchCommitmentLog.length = 0;
  const confFallback = await fetchGlobalRootHistory({
    fetchFinalized,
    fetchConfirmed,
    poolId: 0,
    requiredNotes: [
      { laneId: 0, leafIndex: 0n },
      { laneId: 0, leafIndex: 1n },
    ],
  });
  assert.equal(confFallback.commitment, 'confirmed');
  assert.deepEqual(fetchCommitmentLog, ['finalized', 'confirmed']);
  assert.equal(confFallback.snapshot.ringKind, ROOT_RING_SLOT);
  assert.equal(confFallback.snapshot.ringIdx, 5);

  // 6b. Round-2 regression: tampered/non-canonical/forged unchosen snapshot MUST reject immediately
  //     in BOTH fetchGlobalRootHistory (NO silent finalized -> confirmed fallback!) and reconstructWitness
  //     (NO silent stable -> latest downgrade!).
  {
    const nonCanon = new Uint8Array(32).fill(0xff);
    const forged = frToBeBytes(777_777n);

    // Non-canonical stable + zero stableLaneCounts + genuine latest
    const downgradeNonCanonRaw = mutate((b, dv) => {
      b.set(nonCanon, RT_OFF_STABLE_SUPER_ROOT);
      b.set(nonCanon, RT_OFF_EPOCH_RING + 2 * ROOT_ENTRY_LEN);
      for (let l = 0; l < NUM_LANES; l++) {
        dv.setBigUint64(RT_OFF_STABLE_LANE_COUNTS + l * 8, 0n, true);
      }
    });

    // Forged canonical stable + zero stableLaneCounts + genuine latest
    const downgradeForgedRaw = mutate((b, dv) => {
      b.set(forged, RT_OFF_STABLE_SUPER_ROOT);
      b.set(forged, RT_OFF_EPOCH_RING + 2 * ROOT_ENTRY_LEN);
      for (let l = 0; l < NUM_LANES; l++) {
        dv.setBigUint64(RT_OFF_STABLE_LANE_COUNTS + l * 8, 0n, true);
      }
    });

    // Both snapshots forged + ALL laneCounts = 0 (selectRootSnapshotForNotes would return null -> must reject BEFORE confirmed!)
    const forgedZeroCountsRaw = mutate((b, dv) => {
      b.set(forged, RT_OFF_STABLE_SUPER_ROOT);
      b.set(forged, RT_OFF_EPOCH_RING + 2 * ROOT_ENTRY_LEN);
      b.set(forged, RT_OFF_LATEST_SUPER_ROOT);
      b.set(forged, RT_OFF_SLOT_RING + 5 * ROOT_ENTRY_LEN);
      for (let l = 0; l < NUM_LANES; l++) {
        dv.setBigUint64(RT_OFF_STABLE_LANE_COUNTS + l * 8, 0n, true);
        dv.setBigUint64(RT_OFF_LATEST_LANE_COUNTS + l * 8, 0n, true);
      }
    });

    // Valid stable covering leaf 0 + tampered non-canonical latest
    const tamperedLatestValidStableRaw = mutate((b) => {
      b.set(nonCanon, RT_OFF_LATEST_SUPER_ROOT);
      b.set(nonCanon, RT_OFF_SLOT_RING + 5 * ROOT_ENTRY_LEN);
    });

    for (const [label, badRaw] of [
      ['non-canonical stable + genuine latest', downgradeNonCanonRaw],
      ['forged stable + genuine latest', downgradeForgedRaw],
      ['tampered finalized with zero counts', forgedZeroCountsRaw],
      ['valid stable + non-canonical latest', tamperedLatestValidStableRaw],
    ]) {
      let confirmedHit = false;
      await assert.rejects(
        () =>
          fetchGlobalRootHistory({
            fetchFinalized: async () => [badRaw],
            fetchConfirmed: async () => {
              confirmedHit = true;
              return [dualRaw];
            },
            poolId: 0,
            requiredNotes: [{ laneId: 0, leafIndex: 0n }],
          }),
        /Merkle root mismatch|field|canonical|modulus|Fr/i,
        `fetchGlobalRootHistory (${label}) must reject`,
      );
      assert.equal(
        confirmedHit,
        false,
        `fetchGlobalRootHistory (${label}) must NOT silently fall back to confirmed`,
      );

      await assert.rejects(
        () =>
          reconstructWitness({
            fetchBatch: async (addrs) =>
              addrs.map((a) => {
                if (a === rootsPda0.address) return badRaw;
                if (a === sub0Addr) return sub0TwoLeaves;
                return null;
              }),
            poolId: 0,
            laneId: 0,
            leafIdx: 0n,
            privacyMode: 'fast',
          }),
        /Merkle root mismatch|field|canonical|modulus|Fr/i,
        `reconstructWitness (${label}) must reject`,
      );
    }

    // Caller-supplied rootHistory with OOB cursor/count or laneCounts > MAX_LEAVES_PER_LANE rejected in reconstructWitness
    await assert.rejects(
      () =>
        reconstructWitness({
          fetchBatch: fetchDual,
          poolId: 0,
          laneId: 0,
          leafIdx: 0n,
          rootHistory: { ...dualRoots, slotCursor: dualRoots.slotCount },
          privacyMode: 'fast',
        }),
      /ring cursor or count out of bounds/i,
    );
    await assert.rejects(
      () =>
        reconstructWitness({
          fetchBatch: fetchDual,
          poolId: 0,
          laneId: 0,
          leafIdx: 0n,
          rootHistory: {
            ...dualRoots,
            latestLaneCounts: dualRoots.latestLaneCounts.map((c, i) =>
              i === 0 ? MAX_LEAVES_PER_LANE + 1n : c,
            ),
          },
          privacyMode: 'fast',
        }),
      RangeError,
    );
  }

  // 7. Zero-Crank Auto-OpenPage planner (`planAutoOpenPages` & `buildAutoOpenPageInstructions`)
  const freshPlan = planAutoOpenPages({
    poolId: 0,
    laneId: 0,
    nextLeaf: 0n,
    nfCount: 0n,
    numOutputs: 1,
    numNfs: 1,
  });
  assert.equal(freshPlan.length, 0);

  // Exact rollover boundaries: nextLeaf=96 (memo page 1)
  const rolloverMemo = planAutoOpenPages({
    poolId: 0,
    laneId: 2,
    nextLeaf: BigInt(MEMO_NOTES_PER_PAGE),
    nfCount: 0n,
    numOutputs: 1,
    numNfs: 0,
  });
  assert.deepEqual(
    rolloverMemo.map((t) => [t.pageKind, t.pageSeq]),
    [[OPEN_PAGE_KIND_MEMO, 1n]],
  );

  // >= 90% headroom thresholds: subRem <= 26, memoRem <= 10, nfRem <= 60, subrootSlot >= 280
  const nearSubAndMemo = planAutoOpenPages({
    poolId: 0,
    laneId: 1,
    nextLeaf: BigInt(SUBTREE_LEAVES - AUTO_OPEN_SUBTREE_REM_THRESHOLD), // 230: subRem=26, memoRem=58
    nfCount: BigInt(NF_PER_PAGE - AUTO_OPEN_NF_REM_THRESHOLD), // 540: nfRem=60
    numOutputs: 1,
    numNfs: 1,
  });
  assert.deepEqual(
    nearSubAndMemo.map((t) => [t.pageKind, t.pageSeq]),
    [
      [OPEN_PAGE_KIND_SUBTREE, 1n],
      [OPEN_PAGE_KIND_NULLIFIER, 1n],
    ],
  );

  // Subroot >= 90% threshold (subrootSlot = 280 -> nextLeaf = 280 * 256)
  const nearSubroot = planAutoOpenPages({
    poolId: 0,
    laneId: 0,
    nextLeaf: BigInt(AUTO_OPEN_SUBROOT_SLOT_THRESHOLD) * BigInt(SUBTREE_LEAVES),
    nfCount: 0n,
    numOutputs: 1,
    numNfs: 0,
  });
  assert.equal(
    nearSubroot.some((t) => t.pageKind === OPEN_PAGE_KIND_SUBROOT && t.pageSeq === 1n),
    true,
  );
  assert.equal(
    nearSubroot.some((t) => t.pageKind === OPEN_PAGE_KIND_SUBTREE && t.pageSeq === BigInt(AUTO_OPEN_SUBROOT_SLOT_THRESHOLD)),
    true,
  );

  // Memo >= 90% threshold (memoRem = 10 -> nextLeaf = 86)
  const nearMemo = planAutoOpenPages({
    poolId: 0,
    laneId: 1,
    nextLeaf: BigInt(MEMO_NOTES_PER_PAGE - AUTO_OPEN_MEMO_REM_THRESHOLD),
    nfCount: 0n,
    numOutputs: 1,
    numNfs: 0,
  });
  assert.deepEqual(
    nearMemo.map((t) => [t.pageKind, t.pageSeq]),
    [[OPEN_PAGE_KIND_MEMO, 1n]],
  );

  // existingPages filters out already-initialized pages at simultaneous subtree+memo rollover (lcm(256,96)-1 = 767)
  const filtered = planAutoOpenPages({
    poolId: 0,
    laneId: 1,
    nextLeaf: 767n,
    nfCount: BigInt(NF_PER_PAGE - 1),
    numOutputs: 1,
    numNfs: 1,
    existingPages: new Set([deriveSubtreePdaSync(0, 1, 3n).address]),
  });
  assert.equal(
    filtered.some((t) => t.pageKind === OPEN_PAGE_KIND_SUBTREE),
    false,
  );
  assert.equal(
    filtered.some((t) => t.pageKind === OPEN_PAGE_KIND_MEMO && t.pageSeq === 8n),
    true,
  );
  assert.equal(
    filtered.some((t) => t.pageKind === OPEN_PAGE_KIND_NULLIFIER && t.pageSeq === 1n),
    true,
  );

  const withdrawOnlyPlan = planAutoOpenPages({
    poolId: 0,
    laneId: 1,
    nextLeaf: BigInt(SUBTREE_LEAVES - 1),
    nfCount: BigInt(NF_PER_PAGE - AUTO_OPEN_NF_REM_THRESHOLD),
    numOutputs: 0,
    numNfs: 1,
  });
  assert.deepEqual(
    withdrawOnlyPlan.map((t) => [t.pageKind, t.pageSeq]),
    [[OPEN_PAGE_KIND_NULLIFIER, 1n]],
  );

  const payerPubkey = deriveDefiSessionKeypair(new Uint8Array(32).fill(0x55), 0).pubkeyBase58;
  const autoIxs = buildAutoOpenPageInstructions({
    payer: payerPubkey,
    poolId: 0,
    laneId: 1,
    nextLeaf: BigInt(SUBTREE_LEAVES - AUTO_OPEN_SUBTREE_REM_THRESHOLD),
    nfCount: BigInt(NF_PER_PAGE - AUTO_OPEN_NF_REM_THRESHOLD),
    numOutputs: 1,
    numNfs: 1,
  });
  assert.equal(autoIxs.length, 2);
  assert.equal(autoIxs[0].data[0], TAG_OPEN_PAGE);
  assert.equal(autoIxs[0].data[1], OPEN_PAGE_KIND_SUBTREE);
  assert.equal(autoIxs[1].data[1], OPEN_PAGE_KIND_NULLIFIER);

  // True MAX_LEAVES_PER_LANE (4^18 = 68,719,476,736) ceiling in planAutoOpenPages:
  // - SubtreePage #4096 (leaf 1,048,575 / 1,048,576) MUST still be emitted!
  const at4096Lookahead = planAutoOpenPages({
    poolId: 0,
    laneId: 0,
    nextLeaf: 4096n * 256n - 1n,
    nfCount: 0n,
    numOutputs: 1,
    numNfs: 0,
  });
  assert.equal(
    at4096Lookahead.some((t) => t.pageKind === OPEN_PAGE_KIND_SUBTREE && t.pageSeq === 4096n),
    true,
    'SubtreePage #4096 MUST still be emitted (true MAX_LEAVES_PER_LANE = 4^18, not 2^20)',
  );

  // - Last valid pages (Subtree #268_435_455, Subroot #894_784, Memo #715_827_882) ARE emitted
  const maxSubPages = MAX_LEAVES_PER_LANE / BigInt(SUBTREE_LEAVES); // 268_435_456n
  const maxSrPages = (maxSubPages + BigInt(SUBROOTS_PER_PAGE) - 1n) / BigInt(SUBROOTS_PER_PAGE); // 894_785n
  const maxMemoPages = (MAX_LEAVES_PER_LANE + BigInt(MEMO_NOTES_PER_PAGE) - 1n) / BigInt(MEMO_NOTES_PER_PAGE); // 715_827_883n
  assert.equal(maxSubPages, 268_435_456n);
  assert.equal(maxSrPages, 894_785n);
  assert.equal(maxMemoPages, 715_827_883n);

  const lastValidSub = planAutoOpenPages({
    poolId: 0,
    laneId: 0,
    nextLeaf: (maxSubPages - 1n) * BigInt(SUBTREE_LEAVES),
    nfCount: 0n,
    numOutputs: 1,
    numNfs: 0,
  });
  assert.equal(
    lastValidSub.some((t) => t.pageKind === OPEN_PAGE_KIND_SUBTREE && t.pageSeq === maxSubPages - 1n),
    true,
  );

  const lastValidSr = planAutoOpenPages({
    poolId: 0,
    laneId: 0,
    nextLeaf:
      ((maxSrPages - 2n) * BigInt(SUBROOTS_PER_PAGE) + BigInt(AUTO_OPEN_SUBROOT_SLOT_THRESHOLD)) *
      BigInt(SUBTREE_LEAVES),
    nfCount: 0n,
    numOutputs: 1,
    numNfs: 0,
  });
  assert.equal(
    lastValidSr.some((t) => t.pageKind === OPEN_PAGE_KIND_SUBROOT && t.pageSeq === maxSrPages - 1n),
    true,
  );

  const lastValidMemo = planAutoOpenPages({
    poolId: 0,
    laneId: 0,
    nextLeaf: (maxMemoPages - 1n) * BigInt(MEMO_NOTES_PER_PAGE),
    nfCount: 0n,
    numOutputs: 1,
    numNfs: 0,
  });
  assert.equal(
    lastValidMemo.some((t) => t.pageKind === OPEN_PAGE_KIND_MEMO && t.pageSeq === maxMemoPages - 1n),
    true,
  );

  // - At MAX_LEAVES_PER_LANE - 1: unreachable Subtree #268_435_456 / Subroot #894_785 / Memo #715_827_883 MUST NOT be emitted!
  for (const numOutputs of [1, 100]) {
    const atMaxMinus1 = planAutoOpenPages({
      poolId: 0,
      laneId: 0,
      nextLeaf: MAX_LEAVES_PER_LANE - 1n,
      nfCount: 0n,
      numOutputs,
      numNfs: 0,
    });
    assert.equal(atMaxMinus1.length, 0);
  }

  // - At MAX_LEAVES_PER_LANE: skip ALL output pages while still planning NullifierPage
  const atMaxLeaf = planAutoOpenPages({
    poolId: 0,
    laneId: 0,
    nextLeaf: MAX_LEAVES_PER_LANE,
    nfCount: BigInt(NF_PER_PAGE - AUTO_OPEN_NF_REM_THRESHOLD),
    numOutputs: 1,
    numNfs: 1,
  });
  assert.deepEqual(
    atMaxLeaf.map((t) => [t.pageKind, t.pageSeq]),
    [[OPEN_PAGE_KIND_NULLIFIER, 1n]],
  );

  // 8. Tight CU limit helpers match finalized empirical constants + OpenPage/ATA/T22-leg headroom
  assert.equal(CU_LIMIT_INIT_POOL, 45_000);
  assert.equal(CU_LIMIT_INIT_LANE, 75_000);
  assert.equal(CU_LIMIT_INIT_ROOT_HISTORY, 75_000);
  assert.equal(CU_LIMIT_OPEN_PAGE, 40_000);
  assert.equal(CU_LIMIT_DEPOSIT, 75_000);
  assert.equal(CU_LIMIT_DEPOSIT_HOOK, 140_000);
  assert.equal(CU_LIMIT_TRANSACT_PRIVATE, 235_000);
  assert.equal(CU_LIMIT_TRANSACT_FULL_EXIT, 165_000);
  assert.equal(CU_LIMIT_TRANSACT_WITHDRAW, 255_000);
  assert.equal(CU_LIMIT_TRANSACT_WITHDRAW_HOOK, 295_000);
  assert.equal(CU_LIMIT_EXEC_VIA_ESCROW_BASE, 285_000);

  assert.equal(recommendedDepositCuLimit({}), 75_000);
  assert.equal(recommendedDepositCuLimit({ hasTransferHook: true, openPageCount: 2 }), 220_000);
  assert.equal(
    recommendedDepositCuLimit({ openPageCount: 1, createAtaCount: 1, createToken2022AtaCount: 1 }),
    75_000 + 40_000 + 30_000 + 45_000,
  );
  assert.equal(recommendedTransactCuLimit({ assetMode: ASSET_MODE_PRIVATE }), 235_000);
  assert.equal(recommendedTransactCuLimit({ assetMode: ASSET_MODE_PUBLIC }), 255_000);
  assert.equal(recommendedTransactCuLimit({ assetMode: ASSET_MODE_PUBLIC, outputMask: 0 }), 165_000);
  assert.equal(
    recommendedTransactCuLimit({ assetMode: ASSET_MODE_PUBLIC, hasTransferHook: true, openPageCount: 1 }),
    335_000,
  );
  assert.equal(
    recommendedTransactCuLimit({
      assetMode: ASSET_MODE_PUBLIC,
      outputMask: 0b011,
      createAtaCount: 1,
      createToken2022AtaCount: 1,
    }),
    255_000 + 30_000 + 45_000,
  );
  assert.equal(
    recommendedExecViaEscrowCuLimit({ routerCuLimit: 300_000, openPageCount: 2 }),
    285_000 + 300_000 + 80_000,
  );
  assert.equal(
    recommendedExecViaEscrowCuLimit({
      routerCuLimit: 300_000,
      hasToken2022Leg: true,
      openPageCount: 1,
      createAtaCount: 1,
      createToken2022AtaCount: 2,
    }),
    285_000 + 25_000 + 300_000 + 40_000 + 30_000 + 90_000,
  );
  assert.equal(
    recommendedExecViaEscrowCuLimit({
      routerCuLimit: 1_300_000,
      hasToken2022Leg: true,
      openPageCount: 4,
      createToken2022AtaCount: 2,
    }),
    1_400_000,
  );

  // 9. UpdatePool params (22 B) & InitRootHistory (13 B, 4 + activeLanes accounts)
  const initRhIx = buildInitRootHistoryInstruction({
    authority: payerPubkey,
    poolId: 0,
    activeLanes: 4,
    rootEpochInterval: 32n,
  });
  assert.equal(initRhIx.data.byteLength, 13);
  assert.equal(initRhIx.data[0], TAG_INIT_ROOT_HISTORY);
  assert.equal(initRhIx.accounts.length, 8);
  assert.equal(initRhIx.accounts[2].pubkey, rootsPda0.address);
  assert.equal(initRhIx.accounts[2].isWritable, true);

  const updParamsIx = buildUpdatePoolParamsInstruction({
    authority: payerPubkey,
    poolId: 0,
    noteRentFee: 1_500_000n,
    nfRentFee: 500_000n,
  });
  assert.equal(updParamsIx.data.byteLength, 22);
  assert.equal(updParamsIx.data[0], TAG_UPDATE_POOL);
  assert.equal(updParamsIx.data[5], UPDATE_POOL_PARAMS);
});

test('v1.3.0 Round-3 audit regressions: GlobalRootHistory full invariants, safe TS shape guards, validated pruning & recordVerifiedMemo bounds', async () => {
  const rootsPda0 = deriveRootsPdaSync(0);
  const sub0Addr = deriveSubtreePdaSync(0, 0, 0n).address;
  const viewSk = new Uint8Array(32).fill(0x63);

  const leaf0 = 1111n;
  const leaf1 = 2222n;
  const stableLane0Root = computeLaneRootFromLeaves([leaf0]);
  const latestLane0Root = computeLaneRootFromLeaves([leaf0, leaf1]);
  const stableLaneRoots = new Array(NUM_LANES).fill(ZERO_HASHES_4ARY[18]);
  stableLaneRoots[0] = stableLane0Root;
  const latestLaneRoots = new Array(NUM_LANES).fill(ZERO_HASHES_4ARY[18]);
  latestLaneRoots[0] = latestLane0Root;
  const stableLaneCounts = new Array(NUM_LANES).fill(0n);
  stableLaneCounts[0] = 1n;
  const latestLaneCounts = new Array(NUM_LANES).fill(0n);
  latestLaneCounts[0] = 2n;

  const { roots: validRoots, raw: validRaw } = makeSyntheticRootHistory({
    poolId: 0,
    laneRoots: latestLaneRoots,
    laneCounts: latestLaneCounts,
    stableLaneRoots,
    stableLaneCounts,
    slotCursor: 5,
    slotCount: 6,
    epochCursor: 2,
    epochCount: 3,
    latestSlot: 130n,
    stableSlot: 96n,
    epochInterval: 32n,
  });
  const sub0TwoLeaves = makeSubtreePage(0, 0n, [leaf0, leaf1]);
  const validSnap = selectRootSnapshotForNotes(validRoots, [{ laneId: 0, leafIndex: 0n }]);
  assert.ok(validSnap);
  assert.equal(validSnap.ringKind, ROOT_RING_EPOCH);

  const mutateRaw = (fn) => {
    const copy = validRaw.slice();
    fn(copy, new DataView(copy.buffer));
    return copy;
  };

  // Helper asserting a clean Error/RangeError is thrown (NEVER an uncaught TypeError or ReferenceError!)
  const assertCleanError = (fn, label) => {
    let caught = null;
    try {
      fn();
    } catch (e) {
      caught = e;
    }
    assert.ok(caught instanceof Error, `${label}: expected Error to be thrown`);
    assert.equal(caught instanceof TypeError, false, `${label}: must NOT throw TypeError (got ${caught})`);
    assert.equal(caught instanceof ReferenceError, false, `${label}: must NOT throw ReferenceError (got ${caught})`);
  };

  // 1. Finding #1 HIGH: 8-byte stable downgrade, 16-byte finalized fallback, header & monotonicity violations
  const eightByteDowngradeRaw = mutateRaw((_, dv) => {
    dv.setBigUint64(RT_OFF_STABLE_LANE_COUNTS, 0n, true);
  });
  const sixteenByteFallbackRaw = mutateRaw((_, dv) => {
    dv.setBigUint64(RT_OFF_STABLE_LANE_COUNTS, 0n, true);
    dv.setBigUint64(RT_OFF_LATEST_LANE_COUNTS, 0n, true);
  });
  const stableGtLatestCntRaw = mutateRaw((_, dv) => {
    dv.setBigUint64(RT_OFF_STABLE_LANE_COUNTS, 999n, true);
  });
  const equalCntDiffRootRaw = mutateRaw((_, dv) => {
    dv.setBigUint64(RT_OFF_STABLE_LANE_COUNTS, 2n, true);
  });
  const stableGtLatestSlotRaw = mutateRaw((_, dv) => {
    dv.setBigUint64(RT_OFF_STABLE_SLOT, 200n, true);
    dv.setBigUint64(RT_OFF_EPOCH_RING + 2 * ROOT_ENTRY_LEN + 32, 200n, true);
    dv.setBigUint64(RT_OFF_STABLE_EPOCH_ID, 200n / 32n, true);
  });
  const badSlotRingSlotRaw = mutateRaw((_, dv) => {
    dv.setBigUint64(RT_OFF_SLOT_RING + 5 * ROOT_ENTRY_LEN + 32, 129n, true);
  });
  const badEpochRingSlotRaw = mutateRaw((_, dv) => {
    dv.setBigUint64(RT_OFF_EPOCH_RING + 2 * ROOT_ENTRY_LEN + 32, 95n, true);
  });
  const badStableEpochIdRaw = mutateRaw((_, dv) => {
    dv.setBigUint64(RT_OFF_STABLE_EPOCH_ID, 99n, true);
  });

  for (const [label, badRaw] of [
    ['8-byte stable_lane_counts[0]=0 downgrade', eightByteDowngradeRaw],
    ['16-byte finalized counts=0 fallback', sixteenByteFallbackRaw],
    ['stable_lane_counts > latest_lane_counts', stableGtLatestCntRaw],
    ['equal counts with differing lane roots', equalCntDiffRootRaw],
    ['stable_slot > latest_slot', stableGtLatestSlotRaw],
    ['slotRing[slotCursor].slot mismatch', badSlotRingSlotRaw],
    ['epochRing[epochCursor].slot mismatch', badEpochRingSlotRaw],
    ['wrong stableEpochId', badStableEpochIdRaw],
  ]) {
    const decodedBad = decodeGlobalRootHistory(badRaw);
    assertCleanError(() => validateGlobalRootHistory(decodedBad, 0), `validateGlobalRootHistory (${label})`);

    let confirmedHit = false;
    await assert.rejects(
      () =>
        fetchGlobalRootHistory({
          fetchFinalized: async () => [badRaw],
          fetchConfirmed: async () => {
            confirmedHit = true;
            return [validRaw];
          },
          poolId: 0,
          requiredNotes: [{ laneId: 0, leafIndex: 0n }],
        }),
      Error,
      `fetchGlobalRootHistory (${label}) must reject`,
    );
    assert.equal(
      confirmedHit,
      false,
      `fetchGlobalRootHistory (${label}) must NOT silently fall back to confirmed`,
    );

    for (const privacyMode of ['strict', 'fast']) {
      await assert.rejects(
        () =>
          reconstructWitness({
            fetchBatch: async (addrs) =>
              addrs.map((a) => {
                if (a === rootsPda0.address) return badRaw;
                if (a === sub0Addr) return sub0TwoLeaves;
                return null;
              }),
            poolId: 0,
            laneId: 0,
            leafIdx: 0n,
            privacyMode,
            viewSk: privacyMode === 'strict' ? viewSk : undefined,
          }),
        Error,
        `reconstructWitness (${label}, ${privacyMode}) must reject`,
      );
    }
  }

  // Direct selectRootSnapshotForNotes hard preconditions: zero silent stable -> latest downgrade & NaN rejection!
  assert.equal(
    selectRootSnapshotForNotes(decodeGlobalRootHistory(eightByteDowngradeRaw), [{ laneId: 0, leafIndex: 0n }]),
    null,
  );
  assert.equal(
    selectRootSnapshotForNotes(decodeGlobalRootHistory(stableGtLatestCntRaw), [{ laneId: 0, leafIndex: 0n }]),
    null,
  );
  assert.equal(
    selectRootSnapshotForNotes(decodeGlobalRootHistory(equalCntDiffRootRaw), [{ laneId: 0, leafIndex: 0n }]),
    null,
  );
  assert.equal(
    selectRootSnapshotForNotes(decodeGlobalRootHistory(stableGtLatestSlotRaw), [{ laneId: 0, leafIndex: 0n }]),
    null,
  );
  assert.equal(
    selectRootSnapshotForNotes(decodeGlobalRootHistory(badSlotRingSlotRaw), [{ laneId: 0, leafIndex: 0n }]),
    null,
  );
  assert.equal(
    selectRootSnapshotForNotes(decodeGlobalRootHistory(badEpochRingSlotRaw), [{ laneId: 0, leafIndex: 0n }]),
    null,
  );
  assert.equal(
    selectRootSnapshotForNotes(
      {
        ...validRoots,
        epochRing: validRoots.epochRing.map((e, i) =>
          i === validRoots.epochCursor ? { ...e, superRoot: new Uint8Array(32).fill(1) } : e,
        ),
      },
      [{ laneId: 0, leafIndex: 0n }],
    ),
    null,
  );
  assert.equal(
    selectRootSnapshotForNotes(
      {
        ...validRoots,
        stableSuperRoot: new Uint8Array(32),
        epochRing: validRoots.epochRing.map((e, i) =>
          i === validRoots.epochCursor ? { ...e, superRoot: new Uint8Array(32) } : e,
        ),
      },
      [{ laneId: 0, leafIndex: 0n }],
    ),
    null,
  );
  for (const field of ['slotCount', 'slotCursor', 'epochCount', 'epochCursor']) {
    assert.equal(
      selectRootSnapshotForNotes({ ...validRoots, [field]: Number.NaN }, [{ laneId: 0, leafIndex: 0n }]),
      null,
      `selectRootSnapshotForNotes must return null on NaN ${field}`,
    );
    assert.equal(
      selectRootSnapshotForNotes({ ...validRoots, [field]: 1.5 }, [{ laneId: 0, leafIndex: 0n }]),
      null,
      `selectRootSnapshotForNotes must return null on non-integer ${field}`,
    );
  }

  // Caller-supplied epochInterval == 0 or > MAX_ROOT_EPOCH_INTERVAL rejected by validateGlobalRootHistory
  assertCleanError(
    () => validateGlobalRootHistory({ ...validRoots, epochInterval: 0n }, 0),
    'epochInterval=0n',
  );
  assertCleanError(
    () => validateGlobalRootHistory({ ...validRoots, epochInterval: MAX_ROOT_EPOCH_INTERVAL + 1n }, 0),
    'epochInterval>MAX',
  );

  // 2. Finding #2 MEDIUM: malformed/null GlobalRootHistory & RootSnapshotChoice never throw TypeError!
  for (const [label, fn] of [
    ['validateGlobalRootHistory(null, 0)', () => validateGlobalRootHistory(null, 0)],
    ['validateGlobalRootHistory(undefined, 0)', () => validateGlobalRootHistory(undefined, 0)],
    ['validateGlobalRootHistory(valid, -1)', () => validateGlobalRootHistory(validRoots, -1)],
    ['validateGlobalRootHistory(poolId=-1, -1)', () => validateGlobalRootHistory({ ...validRoots, poolId: -1 }, -1)],
    ['validateGlobalRootHistory(poolId=NaN, 0)', () => validateGlobalRootHistory({ ...validRoots, poolId: Number.NaN }, 0)],
    ['validateGlobalRootHistory(slotRing=null)', () => validateGlobalRootHistory({ ...validRoots, slotRing: null }, 0)],
    ['validateGlobalRootHistory(epochRing=null)', () => validateGlobalRootHistory({ ...validRoots, epochRing: null }, 0)],
    ['validateGlobalRootHistory(latestSuperRoot=null)', () => validateGlobalRootHistory({ ...validRoots, latestSuperRoot: null }, 0)],
    ['validateGlobalRootHistory(stableSuperRoot=null)', () => validateGlobalRootHistory({ ...validRoots, stableSuperRoot: null }, 0)],
    ['validateGlobalRootHistory(latestLaneRoots=null)', () => validateGlobalRootHistory({ ...validRoots, latestLaneRoots: null }, 0)],
    ['validateGlobalRootHistory(stableLaneCounts=null)', () => validateGlobalRootHistory({ ...validRoots, stableLaneCounts: null }, 0)],
    ['validateRootSnapshotChoice(null)', () => validateRootSnapshotChoice(null)],
    ['validateRootSnapshotChoice(undefined)', () => validateRootSnapshotChoice(undefined)],
    ['validateRootSnapshotChoice(superRoot=null)', () => validateRootSnapshotChoice({ ...validSnap, superRoot: null })],
    ['validateRootSnapshotChoice(laneRoots=null)', () => validateRootSnapshotChoice({ ...validSnap, laneRoots: null })],
    ['validateRootSnapshotChoice(laneCounts=null)', () => validateRootSnapshotChoice({ ...validSnap, laneCounts: null })],
    [
      'validateRootSnapshotChoice(laneRoots[0]=null)',
      () => validateRootSnapshotChoice({ ...validSnap, laneRoots: validSnap.laneRoots.map((r, i) => (i === 0 ? null : r)) }),
    ],
    [
      'validateRootSnapshotChoice(count=0 with non-Z18 root)',
      () => validateRootSnapshotChoice({ ...validSnap, laneCounts: validSnap.laneCounts.map((c, i) => (i === 0 ? 0n : c)) }),
    ],
    [
      'validateRootSnapshotChoice(forged superRoot)',
      () => validateRootSnapshotChoice({ ...validSnap, superRoot: frToBeBytes(123_456n) }),
    ],
  ]) {
    assertCleanError(fn, label);
  }

  // selectRootSnapshotForNotes returns null cleanly on null/malformed inputs (never TypeError!)
  for (const [label, h, notes] of [
    ['null history', null, [{ laneId: 0, leafIndex: 0n }]],
    ['null notes', validRoots, null],
    ['null note element', validRoots, [null]],
    ['null epochRing', { ...validRoots, epochRing: null }, [{ laneId: 0, leafIndex: 0n }]],
    ['null slotRing', { ...validRoots, slotRing: null }, [{ laneId: 0, leafIndex: 0n }]],
    ['null stableSuperRoot', { ...validRoots, stableSuperRoot: null }, [{ laneId: 0, leafIndex: 0n }]],
    ['null latestSuperRoot', { ...validRoots, latestSuperRoot: null }, [{ laneId: 0, leafIndex: 0n }]],
    ['null stableLaneCounts', { ...validRoots, stableLaneCounts: null }, [{ laneId: 0, leafIndex: 0n }]],
    ['null latestLaneCounts', { ...validRoots, latestLaneCounts: null }, [{ laneId: 0, leafIndex: 0n }]],
    ['null stableLaneRoots', { ...validRoots, stableLaneRoots: null }, [{ laneId: 0, leafIndex: 0n }]],
    ['null latestLaneRoots', { ...validRoots, latestLaneRoots: null }, [{ laneId: 0, leafIndex: 0n }]],
  ]) {
    assert.equal(selectRootSnapshotForNotes(h, notes), null, `selectRootSnapshotForNotes (${label}) must return null`);
  }

  // CompactWalletStore.buildWitnessForNote & pruneSealedBeforeSnapshot & syncCompactStoreWithRpc
  const store = new CompactWalletStore(0);
  store.lanes[0].frontierSubSeq = 0n;
  store.lanes[0].frontierLeaves = [frToBeBytes(leaf0), frToBeBytes(leaf1)];
  store.lanes[0].prevSealedSubSeq = 0n;
  store.lanes[0].prevSealedLeaves = Array.from({ length: SUBTREE_LEAVES }, () => frToBeBytes(leaf0));
  const validNote = {
    poolId: 0,
    laneId: 0,
    leafIndex: 0n,
    globalLeafIndex: 0n,
    mint: new Uint8Array(32),
    amount: 100n,
    tweak: new Uint8Array(32),
    blinding: new Uint8Array(32),
    stealthOwner: new Uint8Array(32),
    commitment: frToBeBytes(leaf0),
    nullifier: new Uint8Array(32),
    paymentId: new Uint8Array(MEMO_PAYMENT_ID_LEN),
    isDynamic: false,
    spent: false,
    frozenIntraSiblings: null,
    frozenIntraPositions: null,
  };

  for (const [label, badSrc] of [
    ['null', null],
    ['undefined', undefined],
    ['superRoot=null', { ...validSnap, superRoot: null }],
    ['laneRoots=null', { ...validSnap, laneRoots: null }],
    ['laneCounts=null', { ...validSnap, laneCounts: null }],
    ['laneRoots[0]=null', { ...validSnap, laneRoots: validSnap.laneRoots.map((r, i) => (i === 0 ? null : r)) }],
    ['count=0 with non-Z18 root', { ...validSnap, laneCounts: validSnap.laneCounts.map((c, i) => (i === 0 ? 0n : c)) }],
  ]) {
    assertCleanError(() => store.buildWitnessForNote(validNote, badSrc), `buildWitnessForNote(${label})`);
    assertCleanError(() => store.pruneSealedBeforeSnapshot(badSrc), `pruneSealedBeforeSnapshot(${label})`);
  }

  // Wrong-pool GlobalRootHistory must NOT prune prevSealedLeaves (and must throw clean Error)
  const wrongPoolHighCounts = makeSyntheticRootHistory({
    poolId: 1,
    laneRoots: latestLaneRoots,
    laneCounts: latestLaneCounts.map((c, i) => (i === 0 ? 512n : c)),
  }).roots;
  assertCleanError(
    () => store.pruneSealedBeforeSnapshot(wrongPoolHighCounts),
    'pruneSealedBeforeSnapshot(wrong poolId)',
  );
  assert.equal(store.lanes[0].prevSealedSubSeq, 0n, 'wrong-pool history must not prune prevSealedSubSeq');
  assert.equal(store.lanes[0].prevSealedLeaves.length, SUBTREE_LEAVES);

  // syncCompactStoreWithRpc rejects malformed / wrong-pool latestRootHistory cleanly (no TypeError, no pruning!)
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x9a));
  const fvk = exportFullViewingKey(alice);
  for (const badLatest of [null, wrongPoolHighCounts, { ...validSnap, laneRoots: null }]) {
    let caught = null;
    try {
      await syncCompactStoreWithRpc({
        store,
        fvk,
        fetchBatch: async () => [],
        latestRootHistory: badLatest,
      });
    } catch (e) {
      caught = e;
    }
    assert.ok(caught instanceof Error, 'syncCompactStoreWithRpc must reject bad latestRootHistory');
    assert.equal(caught instanceof TypeError, false, `syncCompactStoreWithRpc must not throw TypeError (got ${caught})`);
  }
  assert.equal(store.lanes[0].prevSealedSubSeq, 0n);

  // 3. Finding #3 LOW: recordVerifiedMemo leafIdx < MAX_LEAVES_PER_LANE & integer laneId guards
  const dummyDecrypted = {
    tweak: 1n,
    blinding: 2n,
    amount: 100n,
    mint: new Uint8Array(32),
    paymentId: new Uint8Array(MEMO_PAYMENT_ID_LEN),
    isDynamic: false,
  };
  const cmBe = frToBeBytes(leaf0);
  for (const badLeafIdx of [-1n, MAX_LEAVES_PER_LANE, MAX_LEAVES_PER_LANE + 1n, 0, Number.NaN, null]) {
    assert.throws(
      () => store.recordVerifiedMemo({ fvk, laneId: 0, leafIdx: badLeafIdx, decrypted: dummyDecrypted, cmBe }),
      RangeError,
      `recordVerifiedMemo must reject leafIdx=${String(badLeafIdx)}`,
    );
  }
  for (const badLaneId of [-1, NUM_LANES, 1.5, Number.NaN]) {
    assert.throws(
      () => store.recordVerifiedMemo({ fvk, laneId: badLaneId, leafIdx: 0n, decrypted: dummyDecrypted, cmBe }),
      RangeError,
      `recordVerifiedMemo must reject laneId=${String(badLaneId)}`,
    );
    assert.throws(
      () => store.freezeOwnedNotesInSubtreePage(badLaneId, 0n, []),
      RangeError,
      `freezeOwnedNotesInSubtreePage must reject laneId=${String(badLaneId)}`,
    );
    assert.throws(
      () => store.ingestNullifierPages({ laneId: badLaneId, nfPages: [] }),
      RangeError,
      `ingestNullifierPages must reject laneId=${String(badLaneId)}`,
    );
    assert.throws(
      () => store.ingestLanePages({ fvk, laneId: badLaneId, subtreePages: [], memoPages: [], nfPages: [] }),
      RangeError,
      `ingestLanePages must reject laneId=${String(badLaneId)}`,
    );
  }
  assert.equal(store.notes.length, 0);

  // 4. R4 Finding #1 (HIGH): biconditional count <-> root invariants block 1-byte downgrade & 2-byte pruning DoS
  const rhSameRoot = makeSyntheticRootHistory({
    poolId: 0,
    laneRoots: latestLaneRoots,
    laneCounts: latestLaneCounts.map((c, i) => (i === 0 ? 6n : c)),
    stableLaneRoots: latestLaneRoots,
    stableLaneCounts: latestLaneCounts.map((c, i) => (i === 0 ? 6n : c)),
  }).roots;
  // Valid equal counts + equal roots works
  validateGlobalRootHistory(rhSameRoot, 0);
  // 1-byte decrement: sc = 5 < lc = 6 while stableLaneRoots[0] == latestLaneRoots[0]
  const oneByteDowngrade = {
    ...rhSameRoot,
    stableLaneCounts: rhSameRoot.stableLaneCounts.map((c, i) => (i === 0 ? 5n : c)),
  };
  assertCleanError(() => validateGlobalRootHistory(oneByteDowngrade, 0), '1-byte sc < lc with sr == lr');
  assert.equal(selectRootSnapshotForNotes(oneByteDowngrade, [{ laneId: 0, leafIndex: 5n }]), null);

  // 2-byte inflation on empty lane (root == ZERO_HASHES_4ARY[18] with count > 0)
  const twoByteZeroRoot = {
    ...rhSameRoot,
    stableLaneCounts: rhSameRoot.stableLaneCounts.map((c, i) => (i === 1 ? 256n : c)),
    latestLaneCounts: rhSameRoot.latestLaneCounts.map((c, i) => (i === 1 ? 300n : c)),
  };
  assertCleanError(() => validateGlobalRootHistory(twoByteZeroRoot, 0), 'count > 0 with ZERO_HASHES_4ARY[18]');
  assert.equal(selectRootSnapshotForNotes(twoByteZeroRoot, [{ laneId: 0, leafIndex: 0n }]), null);
  assertCleanError(
    () =>
      validateRootSnapshotChoice({
        ...validSnap,
        laneCounts: validSnap.laneCounts.map((c, i) => (i === 1 ? 1n : c)),
      }),
    'RootSnapshotChoice count > 0 with ZERO_HASHES_4ARY[18]',
  );

  // 5. R4 Finding #2 (LOW): invalid privacyMode fails closed with RangeError (never silently disables strict)
  for (const badMode of ['STRICT', 'invalid', '', 123, null]) {
    await assert.rejects(
      () =>
        syncCompactStoreWithRpc({
          store,
          fvk,
          fetchBatch: async () => [],
          privacyMode: badMode,
        }),
      RangeError,
      `syncCompactStoreWithRpc must reject privacyMode=${String(badMode)}`,
    );
    await assert.rejects(
      () =>
        reconstructWitness({
          fetchBatch: async () => [],
          poolId: 0,
          laneId: 0,
          leafIdx: 0n,
          rootSnapshot: validSnap,
          privacyMode: badMode,
        }),
      RangeError,
      `reconstructWitness must reject privacyMode=${String(badMode)}`,
    );
  }

  // 6. R4 Finding #3 (LOW): verifySelectiveDisclosureProof returns false (never throws TypeError) on malformed inputs
  const zero32 = new Uint8Array(32);
  for (const [badProof, badLeaf] of [
    [null, zero32],
    [undefined, zero32],
    [{}, zero32],
    [{ stealthOwner: null, mint: zero32, blinding: zero32, commitment: zero32 }, zero32],
    [{ stealthOwner: zero32, mint: zero32, blinding: zero32, commitment: zero32 }, null],
    [{ stealthOwner: zero32, mint: zero32, blinding: zero32, commitment: zero32 }, undefined],
  ]) {
    assert.equal(verifySelectiveDisclosureProof(badProof, badLeaf), false);
  }

  // 7. R5 Finding #2 (LOW): boolean & try* verifiers handle malformed/non-Uint8Array JS inputs cleanly (0 TypeError)
  assert.equal(checkMemoViewTag(null, new Uint8Array(2), zero32), false);
  assert.equal(checkMemoViewTag(zero32, undefined, zero32), false);
  assert.equal(checkMemoViewTag(zero32, new Uint8Array(2), { byteLength: 32 }), false);
  assert.equal(isCanonicalFr(null), false);
  assert.equal(isCanonicalFr({ byteLength: 32 }), false);
  assert.equal(isContributoryX25519Point(null), false);
  assert.equal(isContributoryX25519Point({ byteLength: 32 }), false);
  assert.equal(isOnEd25519Curve(null), false);
  assert.equal(isOnEd25519Curve({ byteLength: 32 }), false);
  assert.equal(inspectToken2022UnsafeSelfPay(null), false);
  assert.equal(inspectToken2022UnsafeSelfPay(undefined), false);
  assert.equal(inspectToken2022UnsafeSelfPay({ byteLength: 82 }), true);
  assert.equal(inspectToken2022UnsafeSelfPay({ byteLength: 166, 165: 1 }), true);
  assert.equal(parseToken2022TransferFeeConfig({ byteLength: 200, 165: 1 }, 0n), null);
  assert.equal(tryDecryptAndVerifyMemo(null, new Uint8Array(106), zero32), null);
  assert.equal(tryDecryptAndVerifyMemo(fvk, null, zero32), null);
  assert.equal(tryDecryptAndVerifyMemo(fvk, { byteLength: 106 }, zero32), null);
  assert.equal(tryDecryptAndVerifyMemoEntry(null, new Uint8Array(2), zero32, new Uint8Array(72), zero32), null);
  assert.equal(tryDecryptAndVerifyMemoEntry({ viewSk: null, spendPk: zero32 }, new Uint8Array(2), zero32, new Uint8Array(72), zero32), null);
  assert.equal(tryDecryptAndVerifyMemoEntry(fvk, new Uint8Array(2), zero32, { byteLength: 72 }, zero32), null);

  // 8. R6 Findings #1-#3 (LOW): decode* / frFromBeBytesStrict Int8Array & non-Uint8Array guards,
  // chacha20Poly1305Decrypt/Encrypt Uint8Array guards, parseToken2022TransferFeeConfig u64 epoch guard,
  // and parseAudrenAddress non-string guard (0 uncaught TypeErrors, 0 fail-open bypasses)
  const int8Pool = new Int8Array(POOL_STATE_LEN);
  int8Pool.set(enc.encode(POOL_MAGIC), 0);
  int8Pool[11] = -1; // 0xff signed byte must NOT pass activeLanes <= 16
  for (const [label, fn] of [
    ['decodePoolState(null)', () => decodePoolState(null)],
    ['decodePoolState(Int8Array)', () => decodePoolState(int8Pool)],
    ['decodeLaneHeader(null)', () => decodeLaneHeader(null)],
    ['decodeSlotRingEntry(null)', () => decodeSlotRingEntry(null, 0)],
    ['decodeEpochRingEntry(null)', () => decodeEpochRingEntry(null, 0)],
    ['decodeGlobalRootHistory(null)', () => decodeGlobalRootHistory(null)],
    ['decodeSubtreePage(null)', () => decodeSubtreePage(null)],
    ['decodeSubtreeRootPage(null)', () => decodeSubtreeRootPage(null)],
    ['decodeMemoPage(null)', () => decodeMemoPage(null)],
    ['decodeMemoPageHeader(false)', () => decodeMemoPageHeader(false)],
    ['decodeMemoPageScanSlice({})', () => decodeMemoPageScanSlice({})],
    ['decodeNullifierPageHeader(42)', () => decodeNullifierPageHeader(42)],
    ['decodeNullifierPage(null)', () => decodeNullifierPage(null)],
    ['frFromBeBytesStrict(null)', () => frFromBeBytesStrict(null)],
    ['frFromBeBytesStrict(Int8Array)', () => frFromBeBytesStrict(new Int8Array(32).fill(-1))],
    ['parseAudrenAddress(null)', () => parseAudrenAddress(null)],
    ['parseAudrenAddress(123)', () => parseAudrenAddress(123)],
  ]) {
    assertCleanError(fn, label);
  }

  const k32 = new Uint8Array(32);
  const n12 = new Uint8Array(12);
  assert.equal(chacha20Poly1305Decrypt(k32, n12, null), null);
  assert.equal(chacha20Poly1305Decrypt(k32, n12, { byteLength: 32 }), null);
  assert.equal(chacha20Poly1305Decrypt(k32, n12, new Uint8Array(32), null), null);
  assert.throws(() => chacha20Poly1305Decrypt(null, n12, new Uint8Array(32)), RangeError);
  assert.throws(() => chacha20Poly1305Encrypt(k32, n12, null), RangeError);
  assert.throws(() => chacha20Poly1305Encrypt(k32, n12, new Uint8Array(4), null), RangeError);

  for (const badEpoch of [null, undefined, -1, -1n, '', [], false, Number.NaN, 1.5, (1n << 64n)]) {
    assert.throws(
      () => parseToken2022TransferFeeConfig(null, badEpoch),
      RangeError,
      `parseToken2022TransferFeeConfig must reject currentEpoch=${String(badEpoch)}`,
    );
  }
});

test('v1.3.0 Audit Round 7 regressions: strict Uint8Array byte boundaries, u64 coercion, PDA MAX_SEED_LEN, UpdatePool default, base58Decode', async () => {
  const makeBadBytes = (byteLen) => {
    const ab = new ArrayBuffer(byteLen);
    new Uint8Array(ab).fill(0x42);
    const i8 = new Int8Array(byteLen).fill(-1);
    const dv = new DataView(ab);
    const out = [
      [`ArrayBuffer(${byteLen})`, ab],
      [`Int8Array(${byteLen})`, i8],
      [`DataView(${byteLen})`, dv],
      [`Uint8ClampedArray(${byteLen})`, new Uint8ClampedArray(byteLen).fill(0x42)],
      [`fake { byteLength: ${byteLen} }`, { byteLength: byteLen }],
      ['null', null],
    ];
    if (byteLen % 4 === 0) {
      out.push([`Uint32Array(${byteLen / 4})`, new Uint32Array(byteLen / 4).fill(0x42424242)]);
    } else if (byteLen % 2 === 0) {
      out.push([`Uint16Array(${byteLen / 2})`, new Uint16Array(byteLen / 2).fill(0x4242)]);
    }
    return out;
  };

  const keys = deriveKeysFromSeed(new Uint8Array(32).fill(0x71));
  const fvk = exportFullViewingKey(keys);
  const valid32 = new Uint8Array(32).fill(0x11);
  const validMemo = new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x22);
  const validProof192 = new Uint8Array(GROTH16_PROOF_LEN).fill(0x33);
  const validDynHead = new Uint8Array(DYN_MEMO_HEAD_LEN).fill(0x44);
  const validDynMask = new Uint8Array(MEMO_CT_LEN).fill(0x55);
  const validPayId = new Uint8Array(MEMO_PAYMENT_ID_LEN).fill(0x66);
  const validSig64 = new Uint8Array(64).fill(0x77);
  const payerStr = base58Encode(valid32);
  const mintStr = WSOL_MINT;
  const routerProgStr = AUDREN_PROGRAM_ID;

  // 1. instructions.ts: buildDepositInstruction, buildUpdatePoolInstruction, buildTransactInstruction,
  //    buildExecViaEscrowInstruction, computeTransactCtxHash, computeExecCtxHash
  for (const [label, bad32] of makeBadBytes(32)) {
    assert.throws(
      () =>
        buildDepositInstruction({
          depositor: payerStr,
          poolId: 0,
          laneId: 0,
          subPageSeq: 0n,
          rootPageSeq: 0n,
          memoPageSeq: 0n,
          nativeSol: true,
          amount: 1_000n,
          stealthOwner: bad32,
          blinding: valid32,
          memo: validMemo,
        }),
      RangeError,
      `buildDepositInstruction stealthOwner (${label}) must throw RangeError`,
    );
    assert.throws(
      () =>
        buildDepositInstruction({
          depositor: payerStr,
          poolId: 0,
          laneId: 0,
          subPageSeq: 0n,
          rootPageSeq: 0n,
          memoPageSeq: 0n,
          nativeSol: true,
          amount: 1_000n,
          stealthOwner: valid32,
          blinding: bad32,
          memo: validMemo,
        }),
      RangeError,
      `buildDepositInstruction blinding (${label}) must throw RangeError`,
    );
    assert.throws(
      () =>
        buildUpdatePoolInstruction({
          signer: payerStr,
          poolId: 0,
          action: { kind: 'proposeAuthority', pendingAuthority: bad32 },
        }),
      RangeError,
      `buildUpdatePoolInstruction pendingAuthority (${label}) must throw RangeError`,
    );
    assert.throws(
      () =>
        computeTransactCtxHash({
          poolId: 0,
          outLaneId: 0,
          outputMask: 1,
          assetMode: ASSET_MODE_PRIVATE,
          unwrapWsol: false,
          publicAssetId: bad32,
          publicAmountOut: 0n,
          relayerFeeAmount: 0n,
          memosBytes: validMemo,
        }),
      RangeError,
      `computeTransactCtxHash publicAssetId (${label}) must throw RangeError`,
    );
    assert.throws(
      () =>
        buildTransactInstruction({
          payer: payerStr,
          poolId: 0,
          rootRingKind: ROOT_RING_SLOT,
          rootRingIdx: 0,
          outLaneId: 0,
          outSubSeq: 0n,
          outRootSeq: 0n,
          outMemoSeq: 0n,
          outNfSeq: 0n,
          outputMask: 1,
          assetMode: ASSET_MODE_PRIVATE,
          proof192: validProof192,
          nf0: bad32,
          nf1: new Uint8Array(32),
          cm0: valid32,
          cm1: new Uint8Array(32),
          cm2: new Uint8Array(32),
          publicAmountOut: 0n,
          relayerFeeAmount: 0n,
          memosBytes: validMemo,
        }),
      RangeError,
      `buildTransactInstruction nf0 (${label}) must throw RangeError`,
    );
    assert.throws(
      () =>
        buildExecViaEscrowInstruction({
          payer: payerStr,
          poolId: 0,
          rootRingKind: ROOT_RING_SLOT,
          rootRingIdx: 0,
          outLaneId: 0,
          outSubSeq: 0n,
          outRootSeq: 0n,
          outMemoSeq: 0n,
          outNfSeq: 0n,
          escrowShard: 0,
          changeMask: 0,
          inLeg: { mint: mintStr },
          outLeg: { mint: mintStr },
          relayerFeeAmount: 0n,
          proof192: validProof192,
          nf0: valid32,
          nf1: new Uint8Array(32),
          cm0: valid32,
          cm1: new Uint8Array(32),
          cm2: new Uint8Array(32),
          amountIn: 100n,
          minAmountOut: 90n,
          outStealthOwner: bad32,
          outBlinding: valid32,
          dynMemoHead: validDynHead,
          dynMemoMask: validDynMask,
          routerProg: routerProgStr,
          routerIxData: new Uint8Array([1, 2, 3]),
          routerAccounts: [],
          changeMemos: new Uint8Array(0),
        }),
      RangeError,
      `buildExecViaEscrowInstruction outStealthOwner (${label}) must throw RangeError`,
    );
    assert.throws(
      () =>
        computeExecCtxHash({
          poolId: 0,
          outLaneId: 0,
          escrowShard: 0,
          changeMask: 0,
          feeOnOutput: false,
          assetIn: valid32,
          amountIn: 100n,
          relayerFeeAmount: 0n,
          assetOut: valid32,
          minAmountOut: 90n,
          routerProg: routerProgStr,
          routerAccounts: [],
          outStealthOwner: valid32,
          outBlinding: valid32,
          dynMemoHead: validDynHead,
          dynMemoMask: validDynMask,
          routerIxData: bad32,
          changeMemos: new Uint8Array(0),
        }),
      RangeError,
      `computeExecCtxHash routerIxData (${label}) must throw RangeError`,
    );
  }

  for (const [label, badMemo] of makeBadBytes(MEMO_ENTRY_WIRE_LEN)) {
    assert.throws(
      () =>
        buildDepositInstruction({
          depositor: payerStr,
          poolId: 0,
          laneId: 0,
          subPageSeq: 0n,
          rootPageSeq: 0n,
          memoPageSeq: 0n,
          nativeSol: true,
          amount: 1_000n,
          stealthOwner: valid32,
          blinding: valid32,
          memo: badMemo,
        }),
      RangeError,
      `buildDepositInstruction memo (${label}) must throw RangeError`,
    );
    assert.throws(
      () =>
        computeTransactCtxHash({
          poolId: 0,
          outLaneId: 0,
          outputMask: 1,
          assetMode: ASSET_MODE_PRIVATE,
          unwrapWsol: false,
          publicAssetId: valid32,
          publicAmountOut: 0n,
          relayerFeeAmount: 0n,
          memosBytes: badMemo,
        }),
      RangeError,
      `computeTransactCtxHash memosBytes (${label}) must throw RangeError`,
    );
    assert.throws(
      () =>
        buildTransactInstruction({
          payer: payerStr,
          poolId: 0,
          rootRingKind: ROOT_RING_SLOT,
          rootRingIdx: 0,
          outLaneId: 0,
          outSubSeq: 0n,
          outRootSeq: 0n,
          outMemoSeq: 0n,
          outNfSeq: 0n,
          outputMask: 1,
          assetMode: ASSET_MODE_PRIVATE,
          proof192: validProof192,
          nf0: valid32,
          nf1: new Uint8Array(32),
          cm0: valid32,
          cm1: new Uint8Array(32),
          cm2: new Uint8Array(32),
          publicAmountOut: 0n,
          relayerFeeAmount: 0n,
          memosBytes: badMemo,
        }),
      RangeError,
      `buildTransactInstruction memosBytes (${label}) must throw RangeError`,
    );
    assert.throws(
      () =>
        buildExecViaEscrowInstruction({
          payer: payerStr,
          poolId: 0,
          rootRingKind: ROOT_RING_SLOT,
          rootRingIdx: 0,
          outLaneId: 0,
          outSubSeq: 0n,
          outRootSeq: 0n,
          outMemoSeq: 0n,
          outNfSeq: 0n,
          escrowShard: 0,
          changeMask: 1,
          inLeg: { mint: mintStr },
          outLeg: { mint: mintStr },
          relayerFeeAmount: 0n,
          proof192: validProof192,
          nf0: valid32,
          nf1: new Uint8Array(32),
          cm0: valid32,
          cm1: new Uint8Array(32),
          cm2: new Uint8Array(32),
          amountIn: 100n,
          minAmountOut: 90n,
          outStealthOwner: valid32,
          outBlinding: valid32,
          dynMemoHead: validDynHead,
          dynMemoMask: validDynMask,
          routerProg: routerProgStr,
          routerIxData: new Uint8Array([1, 2, 3]),
          routerAccounts: [],
          changeMemos: badMemo,
        }),
      RangeError,
      `buildExecViaEscrowInstruction changeMemos (${label}) must throw RangeError`,
    );
  }

  for (const [label, badProof] of makeBadBytes(GROTH16_PROOF_LEN)) {
    assert.throws(
      () =>
        buildTransactInstruction({
          payer: payerStr,
          poolId: 0,
          rootRingKind: ROOT_RING_SLOT,
          rootRingIdx: 0,
          outLaneId: 0,
          outSubSeq: 0n,
          outRootSeq: 0n,
          outMemoSeq: 0n,
          outNfSeq: 0n,
          outputMask: 0,
          assetMode: ASSET_MODE_PRIVATE,
          proof192: badProof,
          nf0: valid32,
          nf1: new Uint8Array(32),
          cm0: new Uint8Array(32),
          cm1: new Uint8Array(32),
          cm2: new Uint8Array(32),
          publicAmountOut: 0n,
          relayerFeeAmount: 0n,
          memosBytes: new Uint8Array(0),
        }),
      RangeError,
      `buildTransactInstruction proof192 (${label}) must throw RangeError`,
    );
  }

  // buildUpdatePoolInstruction unknown action kind & null action
  assert.throws(
    () => buildUpdatePoolInstruction({ signer: payerStr, poolId: 0, action: { kind: 'bogus' } }),
    RangeError,
    'buildUpdatePoolInstruction must throw RangeError on unknown action kind',
  );
  assert.throws(
    () => buildUpdatePoolInstruction({ signer: payerStr, poolId: 0, action: null }),
    RangeError,
    'buildUpdatePoolInstruction must throw RangeError on null action',
  );

  // 2. poseidon.ts: deriveAssetId & bytesToBigIntBe
  for (const [label, bad32] of makeBadBytes(32)) {
    assert.throws(
      () => deriveAssetId(bad32),
      RangeError,
      `deriveAssetId(${label}) must throw RangeError`,
    );
    assert.throws(
      () => bytesToBigIntBe(bad32),
      RangeError,
      `bytesToBigIntBe(${label}) must throw RangeError`,
    );
  }

  // 3. crypto.ts: encryptNoteMemo & prepareDynamicSwapMemo
  const validEphSk = new Uint8Array(32).fill(0x5a);
  for (const [label, bad32] of makeBadBytes(32)) {
    assert.throws(
      () => encryptNoteMemo(bad32, validEphSk, 100n, WSOL_MINT_BYTES),
      RangeError,
      `encryptNoteMemo recipientViewPk (${label}) must throw RangeError`,
    );
    assert.throws(
      () => encryptNoteMemo(keys.viewPk, bad32, 100n, WSOL_MINT_BYTES),
      RangeError,
      `encryptNoteMemo ephSecret32 (${label}) must throw RangeError`,
    );
    assert.throws(
      () => encryptNoteMemo(keys.viewPk, validEphSk, 100n, bad32),
      RangeError,
      `encryptNoteMemo mint32 (${label}) must throw RangeError`,
    );
    assert.throws(
      () => prepareDynamicSwapMemo(bad32, validEphSk),
      RangeError,
      `prepareDynamicSwapMemo recipientViewPk (${label}) must throw RangeError`,
    );
    assert.throws(
      () => prepareDynamicSwapMemo(keys.viewPk, bad32),
      RangeError,
      `prepareDynamicSwapMemo ephSecret32 (${label}) must throw RangeError`,
    );
  }
  for (const [label, badPayId] of makeBadBytes(MEMO_PAYMENT_ID_LEN)) {
    assert.throws(
      () => encryptNoteMemo(keys.viewPk, validEphSk, 100n, WSOL_MINT_BYTES, badPayId),
      RangeError,
      `encryptNoteMemo paymentId (${label}) must throw RangeError`,
    );
  }
  // Sanity: valid paymentId still works
  assert.equal(
    encryptNoteMemo(keys.viewPk, validEphSk, 100n, WSOL_MINT_BYTES, validPayId).memo.byteLength,
    MEMO_ENTRY_WIRE_LEN,
  );

  // 4. pda.ts: toPubkeyBytes, base58Encode, base58Decode, formatAudrenAddress,
  //    findProgramAddressSync (seed type + MAX_SEED_LEN=32 + max 15 caller seeds),
  //    deriveNullifierPdaSync, deriveUnwrapPdaSync, deriveAssociatedTokenAddressSync
  for (const [label, bad32] of makeBadBytes(32)) {
    assert.throws(() => toPubkeyBytes(bad32), RangeError, `toPubkeyBytes(${label}) must throw RangeError`);
    assert.throws(() => base58Encode(bad32), RangeError, `base58Encode(${label}) must throw RangeError`);
    assert.throws(
      () => formatAudrenAddress(bad32, keys.viewPk),
      RangeError,
      `formatAudrenAddress spendPk (${label}) must throw RangeError`,
    );
    assert.throws(
      () => formatAudrenAddress(keys.spendPkBytes, bad32),
      RangeError,
      `formatAudrenAddress viewPk (${label}) must throw RangeError`,
    );
    assert.throws(
      () => findProgramAddressSync([bad32]),
      RangeError,
      `findProgramAddressSync([${label}]) must throw RangeError`,
    );
    assert.throws(
      () => deriveNullifierPdaSync(0, bad32),
      RangeError,
      `deriveNullifierPdaSync(${label}) must throw RangeError`,
    );
    assert.throws(
      () => deriveUnwrapPdaSync(0, bad32),
      RangeError,
      `deriveUnwrapPdaSync(${label}) must throw RangeError`,
    );
    assert.throws(
      () => deriveAssociatedTokenAddressSync(bad32, WSOL_MINT),
      RangeError,
      `deriveAssociatedTokenAddressSync owner (${label}) must throw RangeError`,
    );
  }
  for (const badB58 of [123, {}, null, undefined, true, false, ['1', '1']]) {
    let caught = null;
    try {
      base58Decode(badB58);
    } catch (e) {
      caught = e;
    }
    assert.ok(caught instanceof Error, `base58Decode(${String(badB58)}) must throw Error`);
    assert.equal(caught instanceof TypeError, false, `base58Decode(${String(badB58)}) must NOT throw TypeError`);
    assert.equal(caught instanceof ReferenceError, false, `base58Decode(${String(badB58)}) must NOT throw ReferenceError`);
  }
  assert.throws(
    () => findProgramAddressSync([new Uint8Array(33)]),
    RangeError,
    'findProgramAddressSync must reject 33-byte seed (> Solana MAX_SEED_LEN=32)',
  );
  assert.throws(
    () => findProgramAddressSync(Array.from({ length: 16 }, () => new Uint8Array([1]))),
    RangeError,
    'findProgramAddressSync must reject 16 caller seeds',
  );
  // Sanity: 32-byte seed succeeds
  assert.equal(findProgramAddressSync([new Uint8Array(32).fill(7)]).addressBytes.byteLength, 32);

  // 5. keys.ts & store.ts byte boundaries
  for (const [label, bad32] of makeBadBytes(32)) {
    assert.throws(() => deriveKeysFromSeed(bad32), RangeError, `deriveKeysFromSeed(${label})`);
    assert.throws(() => deriveSubaccountKeys(bad32, 1), RangeError, `deriveSubaccountKeys(${label})`);
    assert.throws(() => deriveDefiSessionKeypair(bad32, 0), RangeError, `deriveDefiSessionKeypair(${label})`);
    assert.throws(
      () => exportFullViewingKey({ ...keys, spendPkBytes: bad32 }),
      RangeError,
      `exportFullViewingKey(${label})`,
    );
    assert.throws(
      () =>
        exportSelectiveDisclosureProof({
          poolId: 0,
          laneId: 0,
          leafIndex: 0n,
          stealthOwner: bad32,
          mint: valid32,
          amount: 1n,
          blinding: valid32,
          commitment: valid32,
        }),
      RangeError,
      `exportSelectiveDisclosureProof(${label})`,
    );
  }

  // 6. scanner.ts: selectHrwSealedDecoys, reconstructWitness, syncCompactStoreWithRpc
  const syncStore = new CompactWalletStore(0, 0n);
  const validScope = enc.encode('sync');
  for (const [label, bad32] of makeBadBytes(32)) {
    assert.throws(
      () =>
        selectHrwSealedDecoys({
          viewSk: bad32,
          scope: validScope,
          epochBucket: 0n,
          sealedByLane: [{ laneId: 0, sealedCount: 32n }],
          alreadySelected: new Set(),
          targetSealed: 16,
        }),
      RangeError,
      `selectHrwSealedDecoys viewSk (${label}) must throw RangeError`,
    );
    assert.throws(
      () =>
        selectHrwSealedDecoys({
          viewSk: keys.viewSk,
          scope: bad32,
          epochBucket: 0n,
          sealedByLane: [{ laneId: 0, sealedCount: 32n }],
          alreadySelected: new Set(),
          targetSealed: 16,
        }),
      RangeError,
      `selectHrwSealedDecoys scope (${label}) must throw RangeError`,
    );
    await assert.rejects(
      () =>
        reconstructWitness({
          fetchBatch: async () => [],
          poolId: 0,
          laneId: 0,
          leafIdx: 0n,
          privacyMode: 'strict',
          viewSk: bad32,
        }),
      RangeError,
      `reconstructWitness viewSk (${label}) must reject with RangeError`,
    );
    await assert.rejects(
      () =>
        syncCompactStoreWithRpc({
          store: syncStore,
          fvk: { ...fvk, viewSk: bad32 },
          fetchBatch: async () => [],
        }),
      RangeError,
      `syncCompactStoreWithRpc fvk.viewSk (${label}) must reject with RangeError`,
    );
    await assert.rejects(
      () =>
        syncCompactStoreWithRpc({
          store: syncStore,
          fvk: { ...fvk, spendPk: bad32 },
          fetchBatch: async () => [],
        }),
      RangeError,
      `syncCompactStoreWithRpc fvk.spendPk (${label}) must reject with RangeError`,
    );
  }

  // 7. tx-v1.ts: compileV1Message & serializeV1Transaction byte boundaries + priorityFeeLamports
  const feePayer32 = new Uint8Array(32).fill(0x01);
  const blockhash32 = new Uint8Array(32).fill(0x02);
  const prog32 = new Uint8Array(32).fill(0x03);
  const validCompiled = compileV1Message({
    feePayer: feePayer32,
    recentBlockhash: blockhash32,
    instructions: [
      {
        programId: prog32,
        accounts: [{ pubkey: feePayer32, isSigner: true, isWritable: true }],
        data: new Uint8Array([1, 2, 3]),
      },
    ],
    config: { computeUnitLimit: 100_000, priorityFeeLamports: 1_000n },
  });
  assert.equal(serializeV1Transaction(validCompiled, [validSig64]).byteLength, validCompiled.messageBytes.byteLength + 64);

  for (const [label, bad32] of makeBadBytes(32)) {
    assert.throws(
      () =>
        compileV1Message({
          feePayer: bad32,
          recentBlockhash: blockhash32,
          instructions: [{ programId: prog32, accounts: [], data: new Uint8Array([1]) }],
          config: { computeUnitLimit: 100_000 },
        }),
      RangeError,
      `compileV1Message feePayer (${label}) must throw RangeError`,
    );
    assert.throws(
      () =>
        compileV1Message({
          feePayer: feePayer32,
          recentBlockhash: bad32,
          instructions: [{ programId: prog32, accounts: [], data: new Uint8Array([1]) }],
          config: { computeUnitLimit: 100_000 },
        }),
      RangeError,
      `compileV1Message recentBlockhash (${label}) must throw RangeError`,
    );
    assert.throws(
      () =>
        compileV1Message({
          feePayer: feePayer32,
          recentBlockhash: blockhash32,
          instructions: [
            {
              programId: prog32,
              accounts: [{ pubkey: bad32, isSigner: false, isWritable: false }],
              data: new Uint8Array([1]),
            },
          ],
          config: { computeUnitLimit: 100_000 },
        }),
      RangeError,
      `compileV1Message account.pubkey (${label}) must throw RangeError`,
    );
    assert.throws(
      () =>
        compileV1Message({
          feePayer: feePayer32,
          recentBlockhash: blockhash32,
          instructions: [{ programId: bad32, accounts: [], data: new Uint8Array([1]) }],
          config: { computeUnitLimit: 100_000 },
        }),
      RangeError,
      `compileV1Message programId (${label}) must throw RangeError`,
    );
    assert.throws(
      () =>
        compileV1Message({
          feePayer: feePayer32,
          recentBlockhash: blockhash32,
          instructions: [{ programId: prog32, accounts: [], data: bad32 }],
          config: { computeUnitLimit: 100_000 },
        }),
      RangeError,
      `compileV1Message ix.data (${label}) must throw RangeError`,
    );
    assert.throws(
      () => serializeV1Transaction({ ...validCompiled, messageBytes: bad32 }, [validSig64]),
      RangeError,
      `serializeV1Transaction messageBytes (${label}) must throw RangeError`,
    );
  }
  for (const [label, bad64] of makeBadBytes(64)) {
    assert.throws(
      () => serializeV1Transaction(validCompiled, [bad64]),
      RangeError,
      `serializeV1Transaction signature (${label}) must throw RangeError`,
    );
  }
  for (const badFee of [0, 100, '100', '', false, null, [], -1n, 1n << 64n]) {
    assert.throws(
      () =>
        compileV1Message({
          feePayer: feePayer32,
          recentBlockhash: blockhash32,
          instructions: [{ programId: prog32, accounts: [], data: new Uint8Array([1]) }],
          config: { computeUnitLimit: 100_000, priorityFeeLamports: badFee },
        }),
      RangeError,
      `compileV1Message priorityFeeLamports=${String(badFee)} must throw RangeError`,
    );
  }

  // 8. Strict u64 validation (zero silent BigInt(false/""/[]) -> 0n coercion)
  for (const badU64 of [false, true, '', '0', 'abc', [], -1, -1n, null, undefined, Number.NaN, 1.5, 1n << 64n]) {
    assert.throws(
      () => computePageRollovers({ leafCount: badU64, outputCount: 1, nfCount: 0, spentNullifiers: 1 }),
      RangeError,
      `computePageRollovers leafCount=${String(badU64)} must throw RangeError`,
    );
    assert.throws(
      () => computePageRollovers({ leafCount: 0, outputCount: 1, nfCount: badU64, spentNullifiers: 1 }),
      RangeError,
      `computePageRollovers nfCount=${String(badU64)} must throw RangeError`,
    );
    assert.throws(
      () =>
        planAutoOpenPages({
          poolId: 0,
          laneId: 0,
          nextLeaf: badU64,
          nfCount: 0,
          numOutputs: 1,
          numNfs: 1,
        }),
      RangeError,
      `planAutoOpenPages nextLeaf=${String(badU64)} must throw RangeError`,
    );
    assert.throws(
      () =>
        planAutoOpenPages({
          poolId: 0,
          laneId: 0,
          nextLeaf: 0,
          nfCount: badU64,
          numOutputs: 1,
          numNfs: 1,
        }),
      RangeError,
      `planAutoOpenPages nfCount=${String(badU64)} must throw RangeError`,
    );
    if (badU64 !== undefined) {
      await assert.rejects(
        () =>
          syncCompactStoreWithRpc({
            store: syncStore,
            fvk,
            fetchBatch: async () => [],
            birthdaySlot: badU64,
          }),
        RangeError,
        `syncCompactStoreWithRpc birthdaySlot=${String(badU64)} must reject with RangeError`,
      );
    }
  }

  // 9. prover.ts: proveJoinsplit seed32, loadProvingKeyCompressed pkCompressed, encodeJoinsplitWitness
  const prover = await AudrenWasmProver.init();
  const baseWitness = {
    superRoot: 0n,
    txAssetId: 0n,
    publicAssetId: 0n,
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    ctxHash: 0n,
    omitNf1: false,
    inputs: [dummyInputWitness(1n, 0n, 2n), dummyInputWitness(1n, 0n, 3n)],
    outputs: [dummyOutputWitness(0n, 4n), dummyOutputWitness(0n, 5n), dummyOutputWitness(0n, 6n)],
  };
  for (const [label, bad32] of makeBadBytes(32)) {
    assert.throws(
      () => prover.proveJoinsplit(baseWitness, bad32),
      RangeError,
      `proveJoinsplit seed32 (${label}) must throw RangeError`,
    );
    assert.throws(
      () => prover.loadProvingKeyCompressed(bad32),
      RangeError,
      `loadProvingKeyCompressed (${label}) must throw RangeError`,
    );
    assert.throws(
      () => encodeJoinsplitWitness({ ...baseWitness, superRoot: bad32 }),
      RangeError,
      `encodeJoinsplitWitness superRoot (${label}) must throw RangeError`,
    );
    assert.throws(
      () =>
        encodeJoinsplitWitness({
          ...baseWitness,
          outputs: [
            { ...baseWitness.outputs[0], stealthOwner: bad32 },
            baseWitness.outputs[1],
            baseWitness.outputs[2],
          ],
        }),
      RangeError,
      `encodeJoinsplitWitness stealthOwner (${label}) must throw RangeError`,
    );
  }
  assert.throws(
    () => prover.loadProvingKeyCompressed(new Uint8Array(0)),
    RangeError,
    'loadProvingKeyCompressed must reject empty Uint8Array',
  );
});

test('v1.3.0 Wave-2 fixes: lagged finalized ROOT_RING_SLOT upgrade, pruneSealedBeforeSnapshot slot-ring guard, stable->latest fallback, buildWitnessesForNotes & bump-aware CU margins', async () => {
  // === 1. Item 6: fetchGlobalRootHistory upgrades lagged finalized ROOT_RING_SLOT ===
  const l0 = 101n;
  const l1 = 202n;
  const l2 = 303n;
  const makeLaneRoots = (leaves) => {
    const arr = new Array(NUM_LANES).fill(ZERO_HASHES_4ARY[18]);
    arr[0] = computeLaneRootFromLeaves(leaves);
    return arr;
  };
  const makeLaneCounts = (n) => {
    const arr = new Array(NUM_LANES).fill(0n);
    arr[0] = n;
    return arr;
  };
  const r1 = makeLaneRoots([l0]);
  const r2 = makeLaneRoots([l0, l1]);
  const r3 = makeLaneRoots([l0, l1, l2]);
  const c1 = makeLaneCounts(1n);
  const c2 = makeLaneCounts(2n);
  const c3 = makeLaneCounts(3n);

  const fin = makeSyntheticRootHistory({
    poolId: 0,
    laneRoots: r2,
    laneCounts: c2,
    stableLaneRoots: r1,
    stableLaneCounts: c1,
    slotCursor: 5,
    slotCount: 6,
    epochCursor: 2,
    epochCount: 3,
    latestSlot: 104n,
    stableSlot: 96n,
  });

  // (a) finalized ROOT_RING_EPOCH returns immediately without calling confirmed
  let confCalls = 0;
  const resEpoch = await fetchGlobalRootHistory({
    poolId: 0,
    requiredNotes: [{ laneId: 0, leafIndex: 0n }],
    fetchFinalized: async () => [fin.raw],
    fetchConfirmed: async () => {
      confCalls++;
      return [fin.raw];
    },
  });
  assert.equal(confCalls, 0);
  assert.equal(resEpoch.commitment, 'finalized');
  assert.equal(resEpoch.snapshot.ringKind, ROOT_RING_EPOCH);
  assert.equal(resEpoch.snapshot.ringIdx, 2);

  // (b) finalized ROOT_RING_SLOT fetches confirmed and upgrades to confirmed ROOT_RING_EPOCH
  const confEpoch = makeSyntheticRootHistory({
    poolId: 0,
    laneRoots: r3,
    laneCounts: c3,
    stableLaneRoots: r2,
    stableLaneCounts: c2,
    slotCursor: 8,
    slotCount: 9,
    epochCursor: 3,
    epochCount: 4,
    latestSlot: 135n,
    stableSlot: 128n,
  });
  confCalls = 0;
  const resUpEpoch = await fetchGlobalRootHistory({
    poolId: 0,
    requiredNotes: [{ laneId: 0, leafIndex: 1n }],
    fetchFinalized: async () => [fin.raw],
    fetchConfirmed: async () => {
      confCalls++;
      return [confEpoch.raw];
    },
  });
  assert.equal(confCalls, 1);
  assert.equal(resUpEpoch.commitment, 'confirmed');
  assert.equal(resUpEpoch.snapshot.ringKind, ROOT_RING_EPOCH);
  assert.equal(resUpEpoch.snapshot.ringIdx, 3);
  assert.equal(resUpEpoch.snapshot.slot, 128n);

  // (c) finalized ROOT_RING_SLOT upgrades to newer confirmed ROOT_RING_SLOT (slot or ringIdx advanced)
  const confNewerSlot = makeSyntheticRootHistory({
    poolId: 0,
    laneRoots: r3,
    laneCounts: c3,
    stableLaneRoots: r1,
    stableLaneCounts: c1,
    slotCursor: 6,
    slotCount: 7,
    epochCursor: 2,
    epochCount: 3,
    latestSlot: 110n,
    stableSlot: 96n,
  });
  const resNewerSlot = await fetchGlobalRootHistory({
    poolId: 0,
    requiredNotes: [{ laneId: 0, leafIndex: 1n }],
    fetchFinalized: async () => [fin.raw],
    fetchConfirmed: async () => [confNewerSlot.raw],
  });
  assert.equal(resNewerSlot.commitment, 'confirmed');
  assert.equal(resNewerSlot.snapshot.ringKind, ROOT_RING_SLOT);
  assert.equal(resNewerSlot.snapshot.ringIdx, 6);
  assert.equal(resNewerSlot.snapshot.slot, 110n);

  const confBumpedIdx = makeSyntheticRootHistory({
    poolId: 0,
    laneRoots: r3,
    laneCounts: c3,
    stableLaneRoots: r1,
    stableLaneCounts: c1,
    slotCursor: 6,
    slotCount: 7,
    epochCursor: 2,
    epochCount: 3,
    latestSlot: 104n,
    stableSlot: 96n,
  });
  const resBumpedIdx = await fetchGlobalRootHistory({
    poolId: 0,
    requiredNotes: [{ laneId: 0, leafIndex: 1n }],
    fetchFinalized: async () => [fin.raw],
    fetchConfirmed: async () => [confBumpedIdx.raw],
  });
  assert.equal(resBumpedIdx.commitment, 'confirmed');
  assert.equal(resBumpedIdx.snapshot.ringKind, ROOT_RING_SLOT);
  assert.equal(resBumpedIdx.snapshot.ringIdx, 6);

  // (d) evicted finalized slotRing[5] (same ringIdx=5, same slot=104, overwritten superRoot!) upgrades to confirmed
  const confEvicted = makeSyntheticRootHistory({
    poolId: 0,
    laneRoots: r3,
    laneCounts: c3,
    stableLaneRoots: r1,
    stableLaneCounts: c1,
    slotCursor: 5,
    slotCount: 6,
    epochCursor: 2,
    epochCount: 3,
    latestSlot: 104n,
    stableSlot: 96n,
  });
  const resEvicted = await fetchGlobalRootHistory({
    poolId: 0,
    requiredNotes: [{ laneId: 0, leafIndex: 1n }],
    fetchFinalized: async () => [fin.raw],
    fetchConfirmed: async () => [confEvicted.raw],
  });
  assert.equal(resEvicted.commitment, 'confirmed');
  assert.equal(resEvicted.snapshot.ringKind, ROOT_RING_SLOT);
  assert.equal(resEvicted.snapshot.ringIdx, 5);
  assert.deepEqual(resEvicted.snapshot.superRoot, frToBeBytes(confEvicted.superRoot));

  // (e) unchanged live slot entry in confirmed or missing confirmed keeps finalized
  const resSame = await fetchGlobalRootHistory({
    poolId: 0,
    requiredNotes: [{ laneId: 0, leafIndex: 1n }],
    fetchFinalized: async () => [fin.raw],
    fetchConfirmed: async () => [fin.raw],
  });
  assert.equal(resSame.commitment, 'finalized');
  assert.equal(resSame.snapshot.ringKind, ROOT_RING_SLOT);
  assert.equal(resSame.snapshot.ringIdx, 5);

  const resMissingConf = await fetchGlobalRootHistory({
    poolId: 0,
    requiredNotes: [{ laneId: 0, leafIndex: 1n }],
    fetchFinalized: async () => [fin.raw],
    fetchConfirmed: async () => [null],
  });
  assert.equal(resMissingConf.commitment, 'finalized');
  assert.equal(resMissingConf.snapshot.ringKind, ROOT_RING_SLOT);

  // (f) tampered confirmed payload when upgrading from finalized ROOT_RING_SLOT MUST still reject
  const badConfRaw = confEpoch.raw.slice();
  badConfRaw[RT_OFF_EPOCH_RING + 3 * ROOT_ENTRY_LEN] ^= 0xff;
  await assert.rejects(
    () =>
      fetchGlobalRootHistory({
        poolId: 0,
        requiredNotes: [{ laneId: 0, leafIndex: 1n }],
        fetchFinalized: async () => [fin.raw],
        fetchConfirmed: async () => [badConfRaw],
      }),
    Error,
  );

  // (g) cross-slot lagging confirmed replica (`confirmed.latestSlot < fin.latestSlot`) MUST NOT downgrade finalized
  const finSlot200 = makeSyntheticRootHistory({
    poolId: 0,
    laneRoots: r3,
    laneCounts: c3,
    stableLaneRoots: r1,
    stableLaneCounts: c1,
    slotCursor: 5,
    slotCount: 6,
    epochCursor: 2,
    epochCount: 3,
    latestSlot: 200n,
    stableSlot: 96n,
  });
  const confLagging198 = makeSyntheticRootHistory({
    poolId: 0,
    laneRoots: r2,
    laneCounts: c2,
    stableLaneRoots: r1,
    stableLaneCounts: c1,
    slotCursor: 3,
    slotCount: 4,
    epochCursor: 2,
    epochCount: 3,
    latestSlot: 198n,
    stableSlot: 96n,
  });
  const resCrossSlotLag = await fetchGlobalRootHistory({
    poolId: 0,
    requiredNotes: [{ laneId: 0, leafIndex: 1n }],
    fetchFinalized: async () => [finSlot200.raw],
    fetchConfirmed: async () => [confLagging198.raw],
  });
  assert.equal(resCrossSlotLag.commitment, 'finalized');
  assert.equal(resCrossSlotLag.snapshot.ringKind, ROOT_RING_SLOT);
  assert.equal(resCrossSlotLag.snapshot.ringIdx, 5);
  assert.equal(resCrossSlotLag.snapshot.slot, 200n);
  assert.deepEqual(resCrossSlotLag.snapshot.superRoot, frToBeBytes(finSlot200.superRoot));

  // (h1) same-slot mid-slot lagging confirmed replica (in-place overwrite: fin post-Tx-2 c3/r3 vs confirmed pre-Tx-2 c2/r2)
  const resSameSlotOverwriteLag = await fetchGlobalRootHistory({
    poolId: 0,
    requiredNotes: [{ laneId: 0, leafIndex: 1n }],
    fetchFinalized: async () => [confEvicted.raw],
    fetchConfirmed: async () => [fin.raw],
  });
  assert.equal(resSameSlotOverwriteLag.commitment, 'finalized');
  assert.equal(resSameSlotOverwriteLag.snapshot.ringKind, ROOT_RING_SLOT);
  assert.equal(resSameSlotOverwriteLag.snapshot.ringIdx, 5);
  assert.equal(resSameSlotOverwriteLag.snapshot.slot, 104n);
  assert.deepEqual(resSameSlotOverwriteLag.snapshot.superRoot, frToBeBytes(confEvicted.superRoot));

  // (h2) same-slot mid-slot lagging confirmed replica (same_slot_bumped: fin ringIdx=6 c3/r3 vs confirmed ringIdx=5 c2/r2)
  const resSameSlotBumpLag = await fetchGlobalRootHistory({
    poolId: 0,
    requiredNotes: [{ laneId: 0, leafIndex: 1n }],
    fetchFinalized: async () => [confBumpedIdx.raw],
    fetchConfirmed: async () => [fin.raw],
  });
  assert.equal(resSameSlotBumpLag.commitment, 'finalized');
  assert.equal(resSameSlotBumpLag.snapshot.ringKind, ROOT_RING_SLOT);
  assert.equal(resSameSlotBumpLag.snapshot.ringIdx, 6);
  assert.equal(resSameSlotBumpLag.snapshot.slot, 104n);
  assert.deepEqual(resSameSlotBumpLag.snapshot.superRoot, frToBeBytes(confBumpedIdx.superRoot));

  // (i) non-monotonic multi-lane confirmed replica (slot & lane0 ahead, lane1 behind finalized) MUST NOT downgrade
  const rFinMl = r2.slice();
  rFinMl[1] = computeLaneRootFromLeaves([l0]);
  const cFinMl = c2.slice();
  cFinMl[1] = 1n;
  const finMl = makeSyntheticRootHistory({
    poolId: 0,
    laneRoots: rFinMl,
    laneCounts: cFinMl,
    stableLaneRoots: r1,
    stableLaneCounts: c1,
    slotCursor: 5,
    slotCount: 6,
    epochCursor: 2,
    epochCount: 3,
    latestSlot: 104n,
    stableSlot: 96n,
  });
  const resNonMonotonicLane = await fetchGlobalRootHistory({
    poolId: 0,
    requiredNotes: [{ laneId: 0, leafIndex: 1n }],
    fetchFinalized: async () => [finMl.raw],
    fetchConfirmed: async () => [confNewerSlot.raw],
  });
  assert.equal(resNonMonotonicLane.commitment, 'finalized');
  assert.equal(resNonMonotonicLane.snapshot.ringKind, ROOT_RING_SLOT);
  assert.equal(resNonMonotonicLane.snapshot.ringIdx, 5);
  assert.equal(resNonMonotonicLane.snapshot.slot, 104n);
  assert.deepEqual(resNonMonotonicLane.snapshot.superRoot, frToBeBytes(finMl.superRoot));

  // === 2. Item 7: pruneSealedBeforeSnapshot refuses ROOT_RING_SLOT, stable->latest fallback, buildWitnessesForNotes ===
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0xd1));
  const fvk = exportFullViewingKey(alice);
  const wsolAsset = deriveAssetId(WSOL_MINT_BYTES);

  const memo0 = makeMemoPageWithMeta(0, 0n, MEMO_NOTES_PER_PAGE);
  const memo1 = makeMemoPageWithMeta(0, 1n, MEMO_NOTES_PER_PAGE);
  const memo2 = makeMemoPageWithMeta(0, 2n, SUBTREE_LEAVES - 2 * MEMO_NOTES_PER_PAGE);
  const page0Leaves = [];
  for (let i = 0; i < SUBTREE_LEAVES; i++) {
    if (i === 10) {
      const m = encryptNoteMemo(alice.viewPk, new Uint8Array(32).fill(0xd2), 3_000_000n, WSOL_MINT_BYTES);
      const cm = computeNoteCommitment(deriveStealthOwner(alice.spendPk, m.tweak), wsolAsset, 3_000_000n, m.blinding);
      page0Leaves.push(cm);
      writeMemoSlot(memo0, i, m.memo);
    } else if (i === 200) {
      const m = encryptNoteMemo(alice.viewPk, new Uint8Array(32).fill(0xd3), 4_000_000n, WSOL_MINT_BYTES);
      const cm = computeNoteCommitment(deriveStealthOwner(alice.spendPk, m.tweak), wsolAsset, 4_000_000n, m.blinding);
      page0Leaves.push(cm);
      writeMemoSlot(memo2, i - 2 * MEMO_NOTES_PER_PAGE, m.memo);
    } else {
      page0Leaves.push(BigInt(i + 50));
    }
  }
  const sub0Raw = makeSubtreePage(0, 0n, page0Leaves);
  const store = new CompactWalletStore(0, 0n);
  const found = store.ingestLanePages({
    fvk,
    laneId: 0,
    subtreePages: [{ pageSeq: 0n, raw: sub0Raw }],
    memoPages: [
      { pageSeq: 0n, raw: memo0 },
      { pageSeq: 1n, raw: memo1 },
      { pageSeq: 2n, raw: memo2 },
    ],
    nfPages: [],
  });
  assert.equal(found, 2);
  assert.equal(store.lanes[0].prevSealedSubSeq, 0n);
  assert.equal(store.lanes[0].prevSealedLeaves.length, SUBTREE_LEAVES);

  const hist250vs256 = makeSyntheticRootHistory({
    poolId: 0,
    laneRoots: makeLaneRoots(page0Leaves),
    laneCounts: makeLaneCounts(256n),
    stableLaneRoots: makeLaneRoots(page0Leaves.slice(0, 250)),
    stableLaneCounts: makeLaneCounts(250n),
    slotCursor: 2,
    slotCount: 3,
    epochCursor: 1,
    epochCount: 2,
    latestSlot: 105n,
    stableSlot: 96n,
  });

  // pruneSealedBeforeSnapshot MUST NOT prune on ROOT_RING_SLOT even when count=256 crosses page 0!
  const slotChoice256 = {
    ringKind: ROOT_RING_SLOT,
    ringIdx: 2,
    slot: 105n,
    superRoot: hist250vs256.roots.latestSuperRoot,
    laneRoots: hist250vs256.roots.latestLaneRoots,
    laneCounts: hist250vs256.roots.latestLaneCounts,
  };
  store.pruneSealedBeforeSnapshot(slotChoice256);
  assert.equal(store.lanes[0].prevSealedSubSeq, 0n);
  assert.equal(store.lanes[0].prevSealedLeaves.length, SUBTREE_LEAVES);

  // While prevSealedLeaves is present, buildWitnessForNote & buildWitnessesForNotes use stable (ROOT_RING_EPOCH)
  const noteA = store.notes[0];
  const noteB = store.notes[1];
  const directRes = store.buildWitnessForNote(noteA, hist250vs256.roots);
  assert.equal(directRes.rootRingKind, ROOT_RING_EPOCH);
  assert.equal(directRes.superRoot, hist250vs256.stableSuperRoot);

  // Clear prevSealedLeaves (simulating exact-256 / multi-page sync past page 0) -> triggers stable->latest fallback!
  store.lanes[0].prevSealedSubSeq = null;
  store.lanes[0].prevSealedLeaves = [];

  const fbSingle = store.buildWitnessForNote(noteA, hist250vs256.roots);
  assert.equal(fbSingle.rootRingKind, ROOT_RING_SLOT);
  assert.equal(fbSingle.rootRingIdx, 2);
  assert.equal(fbSingle.superRoot, hist250vs256.superRoot);
  assert.equal(computeMerkleRoot4Ary(fbSingle.path, page0Leaves[10]), hist250vs256.superRoot);

  const fbMulti = store.buildWitnessesForNotes([noteA, noteB], hist250vs256.roots);
  assert.equal(fbMulti.rootRingKind, ROOT_RING_SLOT);
  assert.equal(fbMulti.rootRingIdx, 2);
  assert.equal(fbMulti.snapshot.ringKind, ROOT_RING_SLOT);
  assert.equal(fbMulti.superRoot, hist250vs256.superRoot);
  assert.equal(fbMulti.paths.length, 2);
  assert.equal(computeMerkleRoot4Ary(fbMulti.paths[0], page0Leaves[10]), hist250vs256.superRoot);
  assert.equal(computeMerkleRoot4Ary(fbMulti.paths[1], page0Leaves[200]), hist250vs256.superRoot);

  // Empty notes rejected cleanly; missing both stable & latest throws Error
  assert.throws(() => store.buildWitnessesForNotes([], hist250vs256.roots), RangeError);
  const staleStore = CompactWalletStore.fromJSON(store.toJSON());
  staleStore.lanes[0].finalizedSubroots = [];
  assert.throws(() => staleStore.buildWitnessForNote(noteA, hist250vs256.roots), Error);
  assert.throws(() => staleStore.buildWitnessesForNotes([noteA, noteB], hist250vs256.roots), Error);

  // ROOT_RING_EPOCH snapshot crossing page 0 DOES prune prevSealedLeaves
  const epochStore = CompactWalletStore.fromJSON(store.toJSON());
  epochStore.lanes[0].prevSealedSubSeq = 0n;
  epochStore.lanes[0].prevSealedLeaves = page0Leaves.map((x) => frToBeBytes(x));
  epochStore.pruneSealedBeforeSnapshot({
    ...slotChoice256,
    ringKind: ROOT_RING_EPOCH,
    ringIdx: 1,
  });
  assert.equal(epochStore.lanes[0].prevSealedSubSeq, null);
  assert.equal(epochStore.lanes[0].prevSealedLeaves.length, 0);

  // === 3. Item 15: computeBumpCuMargin & bump-aware recommended*CuLimit helpers ===
  assert.equal(computeBumpCuMargin([]), 0);
  assert.equal(computeBumpCuMargin([255]), 0);
  assert.equal(computeBumpCuMargin([254, 250]), 9_000);
  assert.equal(computeBumpCuMargin(new Array(10).fill(0)), 1_400_000);
  for (const badBumps of [
    null,
    undefined,
    '255',
    [256],
    [-1],
    [254.5],
    [Number.NaN],
    ['250'],
    [0, 0, 0, 0, -1],
    [0, 0, 0, 0, 999],
    [0, 0, 0, 0, Number.NaN],
    [0, 0, 0, 0, 254.5],
  ]) {
    assert.throws(() => computeBumpCuMargin(badBumps), RangeError);
  }
  assert.equal(recommendedOpenPageCuLimit(), 40_000);
  assert.equal(recommendedOpenPageCuLimit({ openPageCount: 2, bumps: [250] }), 87_500);
  assert.equal(
    recommendedDepositCuLimit({ openPageCount: 1, createAtaCount: 1, bumps: [253, 252] }),
    75_000 + 40_000 + 30_000 + 7_500,
  );
  assert.equal(
    recommendedTransactCuLimit({ assetMode: ASSET_MODE_PUBLIC, outputMask: 0, bumps: [245] }),
    165_000 + 15_000,
  );
  assert.equal(
    recommendedExecViaEscrowCuLimit({
      routerCuLimit: 300_000,
      hasToken2022Leg: true,
      openPageCount: 1,
      createAtaCount: 1,
      bumps: [240, 255],
    }),
    285_000 + 25_000 + 300_000 + 40_000 + 30_000 + 22_500,
  );
  assert.equal(
    recommendedExecViaEscrowCuLimit({ routerCuLimit: 1_300_000, bumps: [0, 0] }),
    1_400_000,
  );
});

test('ingestLanePages rejects lagging SubtreePage truncation and preserves held 256-leaf sealed page', () => {
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0xe1));
  const fvk = exportFullViewingKey(alice);
  const wsolAsset = deriveAssetId(WSOL_MINT_BYTES);

  // --- Case 1: Lagging RPC SubtreePage #0 (count = 150) MUST NOT truncate live frontierLeaves (count = 200) ---
  const leaves200 = [];
  const memo0_200 = makeMemoPageWithMeta(0, 0n, MEMO_NOTES_PER_PAGE);
  const memo1_200 = makeMemoPageWithMeta(0, 1n, MEMO_NOTES_PER_PAGE);
  const memo2_200 = makeMemoPageWithMeta(0, 2n, 200 - 2 * MEMO_NOTES_PER_PAGE);
  for (let i = 0; i < 200; i++) {
    if (i === 10) {
      const m = encryptNoteMemo(alice.viewPk, new Uint8Array(32).fill(0xe2), 1_500_000n, WSOL_MINT_BYTES);
      const cm = computeNoteCommitment(deriveStealthOwner(alice.spendPk, m.tweak), wsolAsset, 1_500_000n, m.blinding);
      leaves200.push(cm);
      writeMemoSlot(memo0_200, i, m.memo);
    } else if (i === 180) {
      const m = encryptNoteMemo(alice.viewPk, new Uint8Array(32).fill(0xe3), 2_500_000n, WSOL_MINT_BYTES);
      const cm = computeNoteCommitment(deriveStealthOwner(alice.spendPk, m.tweak), wsolAsset, 2_500_000n, m.blinding);
      leaves200.push(cm);
      writeMemoSlot(memo1_200, i - MEMO_NOTES_PER_PAGE, m.memo);
    } else {
      leaves200.push(BigInt(i + 100));
    }
  }
  const sub0_200 = makeSubtreePage(0, 0n, leaves200);
  const sub0_150 = makeSubtreePage(0, 0n, leaves200.slice(0, 150));

  const liveStore = new CompactWalletStore(0, 0n);
  const foundLive = liveStore.ingestLanePages({
    fvk,
    laneId: 0,
    subtreePages: [{ pageSeq: 0n, raw: sub0_200 }],
    memoPages: [
      { pageSeq: 0n, raw: memo0_200 },
      { pageSeq: 1n, raw: memo1_200 },
      { pageSeq: 2n, raw: memo2_200 },
    ],
    nfPages: [],
  });
  assert.equal(foundLive, 2);
  assert.equal(liveStore.lanes[0].frontierSubSeq, 0n);
  assert.equal(liveStore.lanes[0].frontierLeaves.length, 200);
  assert.equal(liveStore.lanes[0].nextMemoLeaf, 200n);

  // Lagging replica returns SubtreePage #0 (count = 150) -> MUST NOT truncate live frontierLeaves
  const foundLagLive = liveStore.ingestLanePages({
    fvk,
    laneId: 0,
    subtreePages: [{ pageSeq: 0n, raw: sub0_150 }],
    memoPages: [
      { pageSeq: 0n, raw: memo0_200 },
      { pageSeq: 1n, raw: memo1_200 },
    ],
    nfPages: [],
  });
  assert.equal(foundLagLive, 0);
  assert.equal(liveStore.lanes[0].frontierSubSeq, 0n);
  assert.equal(
    liveStore.lanes[0].frontierLeaves.length,
    200,
    'lagging SubtreePage #0 (count=150) must not truncate live frontierLeaves (count=200)',
  );

  // Witness build (both single & batch) against count = 200 GlobalRootHistory MUST succeed!
  const hist200 = makeSingleLaneRootHistory(0, computeLaneRootFromLeaves(leaves200), 200n);
  const liveBatch = liveStore.buildWitnessesForNotes([liveStore.notes[0], liveStore.notes[1]], hist200.roots);
  assert.equal(liveBatch.superRoot, hist200.superRoot);
  assert.equal(liveBatch.paths.length, 2);
  assert.equal(computeMerkleRoot4Ary(liveBatch.paths[0], leaves200[10]), hist200.superRoot);
  assert.equal(computeMerkleRoot4Ary(liveBatch.paths[1], leaves200[180]), hist200.superRoot);

  // --- Case 2: Lagging RPC SubtreePage #0 (count = 150) + MemoPage #1 MUST NOT destroy held 256-leaf sealed page
  //             and MUST verify memos beyond index 150 using the 256 held leaves ---
  const leaves256 = [];
  const memo0_256 = makeMemoPageWithMeta(0, 0n, MEMO_NOTES_PER_PAGE);
  const memo1_256 = makeMemoPageWithMeta(0, 1n, MEMO_NOTES_PER_PAGE);
  const memo2_256 = makeMemoPageWithMeta(0, 2n, SUBTREE_LEAVES - 2 * MEMO_NOTES_PER_PAGE);
  for (let i = 0; i < SUBTREE_LEAVES; i++) {
    if (i === 160) {
      const m = encryptNoteMemo(alice.viewPk, new Uint8Array(32).fill(0xe4), 3_500_000n, WSOL_MINT_BYTES);
      const cm = computeNoteCommitment(deriveStealthOwner(alice.spendPk, m.tweak), wsolAsset, 3_500_000n, m.blinding);
      leaves256.push(cm);
      writeMemoSlot(memo1_256, i - MEMO_NOTES_PER_PAGE, m.memo);
    } else if (i === 220) {
      const m = encryptNoteMemo(alice.viewPk, new Uint8Array(32).fill(0xe5), 4_500_000n, WSOL_MINT_BYTES);
      const cm = computeNoteCommitment(deriveStealthOwner(alice.spendPk, m.tweak), wsolAsset, 4_500_000n, m.blinding);
      leaves256.push(cm);
      writeMemoSlot(memo2_256, i - 2 * MEMO_NOTES_PER_PAGE, m.memo);
    } else {
      leaves256.push(BigInt(i + 300));
    }
  }
  const sub0Sealed = makeSubtreePage(0, 0n, leaves256);
  const sub0Lag150 = makeSubtreePage(0, 0n, leaves256.slice(0, 150));

  const heldStore = new CompactWalletStore(0, 0n);
  // Batch 1: sealed SubtreePage #0 (256 leaves) + MemoPage #0 only (MemoPage #1,#2 lag)
  assert.equal(
    heldStore.ingestLanePages({
      fvk,
      laneId: 0,
      subtreePages: [{ pageSeq: 0n, raw: sub0Sealed }],
      memoPages: [{ pageSeq: 0n, raw: memo0_256 }],
      nfPages: [],
    }),
    0,
  );
  assert.equal(heldStore.lanes[0].nextMemoLeaf, 96n);
  assert.equal(heldStore.lanes[0].frontierSubSeq, 0n);
  assert.equal(heldStore.lanes[0].frontierLeaves.length, SUBTREE_LEAVES);

  // Batch 2: lagging SubtreePage #0 (count = 150) + MemoPage #1 (leaves 96..192, owned note at 160 > 150)
  assert.equal(
    heldStore.ingestLanePages({
      fvk,
      laneId: 0,
      subtreePages: [{ pageSeq: 0n, raw: sub0Lag150 }],
      memoPages: [{ pageSeq: 1n, raw: memo1_256 }],
      nfPages: [],
    }),
    1,
  );
  assert.equal(heldStore.lanes[0].nextMemoLeaf, 192n);
  assert.equal(heldStore.lanes[0].frontierSubSeq, 0n);
  assert.equal(
    heldStore.lanes[0].frontierLeaves.length,
    SUBTREE_LEAVES,
    'lagging SubtreePage #0 (count=150) must not destroy held 256-leaf sealed page',
  );
  assert.equal(heldStore.notes.length, 1);
  assert.equal(heldStore.notes[0].leafIndex, 160n);
  assert.equal(heldStore.notes[0].amount, 3_500_000n);
  assert.ok(heldStore.notes[0].frozenIntraSiblings, 'note discovered beyond index 150 must be frozen against held 256 leaves');

  // Batch 3: lagging SubtreePage #0 (count = 150) + MemoPage #2 (leaves 192..256, owned note at 220)
  // completes page 0, freezes note 220, promotes page 0 to prevSealed, and advances frontierSubSeq -> 1n!
  assert.equal(
    heldStore.ingestLanePages({
      fvk,
      laneId: 0,
      subtreePages: [{ pageSeq: 0n, raw: sub0Lag150 }],
      memoPages: [{ pageSeq: 2n, raw: memo2_256 }],
      nfPages: [],
    }),
    1,
  );
  assert.equal(heldStore.lanes[0].nextMemoLeaf, 256n);
  assert.equal(heldStore.lanes[0].frontierSubSeq, 1n);
  assert.equal(heldStore.lanes[0].frontierLeaves.length, 0);
  assert.equal(heldStore.lanes[0].prevSealedSubSeq, 0n);
  assert.equal(heldStore.lanes[0].prevSealedLeaves.length, SUBTREE_LEAVES);
  assert.equal(heldStore.notes.length, 2);
  assert.equal(heldStore.notes[1].leafIndex, 220n);
  assert.ok(heldStore.notes[1].frozenIntraSiblings);

  // Witness build for both sealed notes against count = 256 GlobalRootHistory MUST succeed!
  const hist256 = makeSingleLaneRootHistory(0, computeLaneRootFromLeaves(leaves256), 256n);
  const sealedBatch = heldStore.buildWitnessesForNotes([heldStore.notes[0], heldStore.notes[1]], hist256.roots);
  assert.equal(sealedBatch.superRoot, hist256.superRoot);
  assert.equal(sealedBatch.paths.length, 2);
  assert.equal(computeMerkleRoot4Ary(sealedBatch.paths[0], leaves256[160]), hist256.superRoot);
  assert.equal(computeMerkleRoot4Ary(sealedBatch.paths[1], leaves256[220]), hist256.superRoot);

  // Extra guard: stale sealed SubtreePage #0 must not regress frontierSubSeq = 1n when memoSubSeq = 0n
  const aheadStore = new CompactWalletStore(0, 0n);
  aheadStore.lanes[0].nextMemoLeaf = 96n;
  aheadStore.lanes[0].frontierSubSeq = 1n;
  aheadStore.lanes[0].frontierLeaves = Array.from({ length: 5 }, () => new Uint8Array(32).fill(1));
  aheadStore.ingestLanePages({
    fvk,
    laneId: 0,
    subtreePages: [{ pageSeq: 0n, raw: sub0Sealed }],
    memoPages: [],
    nfPages: [],
  });
  assert.equal(aheadStore.lanes[0].frontierSubSeq, 1n);
  assert.equal(aheadStore.lanes[0].frontierLeaves.length, 5);

  // Extra guard: duplicate same-seq MemoPage in one batch keeps the fuller count (monotonic)
  const memo1Lag10 = makeMemoPageWithMeta(0, 1n, 10);
  const dupMemoStore = new CompactWalletStore(0, 0n);
  const foundDupMemo = dupMemoStore.ingestLanePages({
    fvk,
    laneId: 0,
    subtreePages: [{ pageSeq: 0n, raw: sub0_200 }],
    memoPages: [
      { pageSeq: 0n, raw: memo0_200 },
      { pageSeq: 1n, raw: memo1_200 }, // fuller (96 entries, owns leaf 180)
      { pageSeq: 1n, raw: memo1Lag10 }, // lagging duplicate (10 entries) MUST NOT overwrite fuller copy
      { pageSeq: 2n, raw: memo2_200 },
    ],
    nfPages: [],
  });
  assert.equal(foundDupMemo, 2);
  assert.equal(dupMemoStore.lanes[0].nextMemoLeaf, 200n);
  assert.equal(dupMemoStore.notes.length, 2);
  assert.equal(dupMemoStore.notes[1].leafIndex, 180n);
});

test('AudrenWasmProver safe WASM allocation and finally cleanup preserve WebAssembly.RuntimeError and scrub secrets', () => {
  const secretWitness = {
    superRoot: 0x1111n,
    txAssetId: 0x2222n,
    publicAssetId: 0x3333n,
    publicAmountOut: 1_000n,
    relayerFeeAmount: 50n,
    ctxHash: 0x4444n,
    omitNf1: false,
    inputs: [
      dummyInputWitness(0x123456789abcdef0123456789abcdef0n, 0x2222n, 0xaaaa1111n),
      dummyInputWitness(0xfedcba9876543210fedcba9876543210n, 0x2222n, 0xbbbb2222n),
    ],
    outputs: [
      dummyOutputWitness(0x2222n, 0xcccc3333n),
      dummyOutputWitness(0x2222n, 0xdddd4444n),
      dummyOutputWitness(0x2222n, 0xeeee5555n),
    ],
  };

  function makeMockProver(overrides = {}) {
    const memory = new WebAssembly.Memory({ initial: 1 });
    let nextPtr = 64;
    const allocs = [];
    const deallocs = [];
    const exports = {
      memory,
      wasm_alloc(len) {
        if (overrides.onAlloc) {
          return overrides.onAlloc(len, allocs, () => {
            const p = nextPtr;
            nextPtr += len;
            allocs.push([p, len]);
            return p;
          });
        }
        const p = nextPtr;
        nextPtr += len;
        allocs.push([p, len]);
        return p;
      },
      wasm_dealloc(ptr, len) {
        deallocs.push([ptr, len]);
        if (overrides.onDealloc) {
          overrides.onDealloc(ptr, len);
        }
      },
      wasm_load_pk_compressed(ptr, len) {
        if (overrides.onLoadPk) return overrides.onLoadPk(ptr, len);
        return 0;
      },
      wasm_prove_joinsplit(wPtr, wLen, sPtr, oPtr) {
        if (overrides.onProve) return overrides.onProve(wPtr, wLen, sPtr, oPtr, memory);
        return 0;
      },
      wasm_poseidon_hash(arity, inPtr, outPtr) {
        if (overrides.onPoseidon) return overrides.onPoseidon(arity, inPtr, outPtr, memory);
        return 0;
      },
    };
    if (overrides.memoryGetter) {
      Object.defineProperty(exports, 'memory', {
        get: overrides.memoryGetter,
      });
    }
    const prover = new AudrenWasmProver(exports);
    if (overrides.pkReady !== false) {
      prover.pkReady = true;
    }
    return { prover, memory, allocs, deallocs };
  }

  // (1) proveJoinsplit traps with WebAssembly.RuntimeError AND wasm_dealloc ALSO throws:
  //     exact RuntimeError propagates unmasked, JS witnessBytes + generated seed are zeroed,
  //     and all three WASM buffers (wPtr, sPtr, oPtr) are zeroed and independently dealloc-attempted.
  {
    const trapErr = new WebAssembly.RuntimeError('unreachable in wasm_prove_joinsplit');
    let proveSawNonZeroWitness = false;
    let proveSawNonZeroSeed = false;
    let capturedWitnessBytes = null;
    let capturedSeed = null;

    const { prover, memory, allocs, deallocs } = makeMockProver({
      onProve(wPtr, wLen, sPtr, oPtr, mem) {
        const wView = new Uint8Array(mem.buffer, wPtr, wLen);
        const sView = new Uint8Array(mem.buffer, sPtr, 32);
        proveSawNonZeroWitness = wView.some((b) => b !== 0);
        proveSawNonZeroSeed = sView.every((b) => b === 0x5a);
        // Dirty output slice before trapping to confirm oPtr is also zeroed in finally.
        new Uint8Array(mem.buffer, oPtr, PROVE_OUTPUT_BYTES).fill(0xab);
        throw trapErr;
      },
      onDealloc() {
        throw new Error('secondary wasm_dealloc failure after trap');
      },
    });

    const origGetRandomValues = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
    const origSet = Uint8Array.prototype.set;
    globalThis.crypto.getRandomValues = (arr) => {
      if (arr instanceof Uint8Array && arr.byteLength === 32) {
        arr.fill(0x5a);
        capturedSeed = arr;
        return arr;
      }
      return origGetRandomValues(arr);
    };
    Uint8Array.prototype.set = function patchedSet(src, offset) {
      if (src instanceof Uint8Array && src.byteLength === WITNESS_TOTAL_BYTES) {
        capturedWitnessBytes = src;
      }
      return origSet.call(this, src, offset);
    };

    try {
      let caught = null;
      try {
        prover.proveJoinsplit(secretWitness);
      } catch (err) {
        caught = err;
      }
      assert.strictEqual(caught, trapErr, 'exact WebAssembly.RuntimeError must propagate unmasked');
      assert.ok(caught instanceof WebAssembly.RuntimeError);
    } finally {
      globalThis.crypto.getRandomValues = origGetRandomValues;
      Uint8Array.prototype.set = origSet;
    }

    assert.equal(proveSawNonZeroWitness, true);
    assert.equal(proveSawNonZeroSeed, true);
    assert.ok(capturedWitnessBytes instanceof Uint8Array);
    assert.ok(
      capturedWitnessBytes.every((b) => b === 0),
      'JS witnessBytes buffer must be scrubbed to all zeros after WASM trap',
    );
    assert.ok(capturedSeed instanceof Uint8Array);
    assert.ok(
      capturedSeed.every((b) => b === 0),
      'JS generated seed buffer must be scrubbed to all zeros after WASM trap',
    );
    assert.equal(allocs.length, 3);
    const [[wPtr, wLen], [sPtr, sLen], [oPtr, oLen]] = allocs;
    assert.ok(new Uint8Array(memory.buffer, wPtr, wLen).every((b) => b === 0), 'WASM wPtr zeroed');
    assert.ok(new Uint8Array(memory.buffer, sPtr, sLen).every((b) => b === 0), 'WASM sPtr zeroed');
    assert.ok(new Uint8Array(memory.buffer, oPtr, oLen).every((b) => b === 0), 'WASM oPtr zeroed');
    assert.deepEqual(
      deallocs,
      [
        [oPtr, PROVE_OUTPUT_BYTES],
        [sPtr, 32],
        [wPtr, WITNESS_TOTAL_BYTES],
      ],
      'all three WASM buffers must have independent dealloc guards',
    );
  }

  // (2) proveJoinsplit traps AND memory.buffer getter itself throws in finally:
  //     JS secret witness/seed buffers are STILL zeroed FIRST and exact RuntimeError propagates.
  {
    const trapErr = new WebAssembly.RuntimeError('wasm memory corrupted');
    const backing = new WebAssembly.Memory({ initial: 1 });
    let poisonMemory = false;
    let capturedWitnessBytes = null;
    let capturedSeed = null;

    const { prover } = makeMockProver({
      memoryGetter() {
        if (poisonMemory) throw new Error('detached/trapped WASM memory');
        return backing;
      },
      onProve() {
        poisonMemory = true;
        throw trapErr;
      },
    });

    const origGetRandomValues = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
    const origSet = Uint8Array.prototype.set;
    globalThis.crypto.getRandomValues = (arr) => {
      if (arr instanceof Uint8Array && arr.byteLength === 32) {
        arr.fill(0x6b);
        capturedSeed = arr;
        return arr;
      }
      return origGetRandomValues(arr);
    };
    Uint8Array.prototype.set = function patchedSet(src, offset) {
      if (src instanceof Uint8Array && src.byteLength === WITNESS_TOTAL_BYTES) {
        capturedWitnessBytes = src;
      }
      return origSet.call(this, src, offset);
    };

    try {
      let caught = null;
      try {
        prover.proveJoinsplit(secretWitness);
      } catch (err) {
        caught = err;
      }
      assert.strictEqual(caught, trapErr);
    } finally {
      globalThis.crypto.getRandomValues = origGetRandomValues;
      Uint8Array.prototype.set = origSet;
    }

    assert.ok(capturedWitnessBytes && capturedWitnessBytes.every((b) => b === 0));
    assert.ok(capturedSeed && capturedSeed.every((b) => b === 0));
  }

  // (3) proveJoinsplit OOM/trap on 2nd and 3rd wasm_alloc cleans up earlier pointers without leaking
  //     and scrubs generated seed.
  for (const failOnAllocIdx of [1, 2]) {
    const allocTrap = new WebAssembly.RuntimeError(`OOM on alloc #${failOnAllocIdx + 1}`);
    let capturedSeed = null;
    const { prover, allocs, deallocs } = makeMockProver({
      onAlloc(len, prevAllocs, doAlloc) {
        if (prevAllocs.length === failOnAllocIdx) {
          throw allocTrap;
        }
        return doAlloc();
      },
    });
    const origGetRandomValues = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
    globalThis.crypto.getRandomValues = (arr) => {
      if (arr instanceof Uint8Array && arr.byteLength === 32) {
        arr.fill(0x7c);
        capturedSeed = arr;
        return arr;
      }
      return origGetRandomValues(arr);
    };
    try {
      let caught = null;
      try {
        prover.proveJoinsplit(secretWitness);
      } catch (err) {
        caught = err;
      }
      assert.strictEqual(caught, allocTrap);
    } finally {
      globalThis.crypto.getRandomValues = origGetRandomValues;
    }
    assert.ok(capturedSeed && capturedSeed.every((b) => b === 0));
    assert.equal(allocs.length, failOnAllocIdx);
    assert.deepEqual(
      deallocs,
      allocs.slice().reverse(),
      `alloc failure #${failOnAllocIdx + 1} must dealloc all earlier allocations and never ptr=0`,
    );
  }

  // (4) poseidonHashWasm: 2nd wasm_alloc trap cleans up inPtr; hash trap + throwing dealloc
  //     preserves exact WebAssembly.RuntimeError and zeroes both WASM buffers.
  {
    const allocTrap = new WebAssembly.RuntimeError('OOM on poseidon outPtr');
    const { prover, allocs, deallocs } = makeMockProver({
      onAlloc(len, prevAllocs, doAlloc) {
        if (prevAllocs.length === 1) throw allocTrap;
        return doAlloc();
      },
    });
    let caught = null;
    try {
      prover.poseidonHashWasm([new Uint8Array(32).fill(0x11)]);
    } catch (err) {
      caught = err;
    }
    assert.strictEqual(caught, allocTrap);
    assert.equal(allocs.length, 1);
    assert.deepEqual(deallocs, allocs);
  }
  {
    const hashTrap = new WebAssembly.RuntimeError('unreachable in wasm_poseidon_hash');
    const { prover, memory, allocs, deallocs } = makeMockProver({
      onPoseidon(_arity, _inPtr, outPtr, mem) {
        new Uint8Array(mem.buffer, outPtr, 32).fill(0xdd);
        throw hashTrap;
      },
      onDealloc() {
        throw new Error('poseidon dealloc failed');
      },
    });
    let caught = null;
    try {
      prover.poseidonHashWasm([new Uint8Array(32).fill(0x22), new Uint8Array(32).fill(0x33)]);
    } catch (err) {
      caught = err;
    }
    assert.strictEqual(caught, hashTrap);
    assert.equal(allocs.length, 2);
    const [[inPtr, inLen], [outPtr, outLen]] = allocs;
    assert.ok(new Uint8Array(memory.buffer, inPtr, inLen).every((b) => b === 0));
    assert.ok(new Uint8Array(memory.buffer, outPtr, outLen).every((b) => b === 0));
    assert.deepEqual(deallocs, [
      [outPtr, 32],
      [inPtr, 64],
    ]);
  }

  // (5) loadProvingKeyCompressed: alloc trap does not call dealloc; load trap + throwing dealloc
  //     preserves exact WebAssembly.RuntimeError, zeroes WASM buffer, and leaves pkReady=false.
  {
    const allocTrap = new WebAssembly.RuntimeError('OOM on pk alloc');
    const { prover, deallocs } = makeMockProver({
      pkReady: false,
      onAlloc() {
        throw allocTrap;
      },
    });
    let caught = null;
    try {
      prover.loadProvingKeyCompressed(new Uint8Array(64).fill(0x44), { allowCustomPk: true });
    } catch (err) {
      caught = err;
    }
    assert.strictEqual(caught, allocTrap);
    assert.equal(deallocs.length, 0);
    assert.equal(prover.pkReady, false);
  }
  {
    const pkTrap = new WebAssembly.RuntimeError('unreachable in wasm_load_pk_compressed');
    const { prover, memory, allocs, deallocs } = makeMockProver({
      pkReady: false,
      onLoadPk() {
        throw pkTrap;
      },
      onDealloc() {
        throw new Error('pk dealloc failed');
      },
    });
    let caught = null;
    try {
      prover.loadProvingKeyCompressed(new Uint8Array(64).fill(0x55), { allowCustomPk: true });
    } catch (err) {
      caught = err;
    }
    assert.strictEqual(caught, pkTrap);
    assert.equal(prover.pkReady, false);
    assert.equal(allocs.length, 1);
    const [[ptr, len]] = allocs;
    assert.ok(new Uint8Array(memory.buffer, ptr, len).every((b) => b === 0));
    assert.deepEqual(deallocs, [[ptr, 64]]);
  }
});

test('fetchGlobalRootHistory rejects lagging confirmed snapshot when fresh note is missing from finalized', async () => {
  const leaf0 = 101n;
  const leaf1 = 202n;
  const leafLane1 = 303n;
  const lane0R1 = computeLaneRootFromLeaves([leaf0]);
  const lane0R2 = computeLaneRootFromLeaves([leaf0, leaf1]);
  const lane1R1 = computeLaneRootFromLeaves([leafLane1]);

  const makeRoots = (l0Count, l1Count) => {
    const laneRoots = new Array(NUM_LANES).fill(ZERO_HASHES_4ARY[18]);
    const laneCounts = new Array(NUM_LANES).fill(0n);
    if (l0Count === 1n) laneRoots[0] = lane0R1;
    else if (l0Count === 2n) laneRoots[0] = lane0R2;
    if (l1Count === 1n) laneRoots[1] = lane1R1;
    laneCounts[0] = l0Count;
    laneCounts[1] = l1Count;
    return { laneRoots, laneCounts };
  };

  const buildRh = (latestL0, latestL1, stableL0, stableL1, latestSlot, stableSlot) => {
    const latest = makeRoots(latestL0, latestL1);
    const stable = makeRoots(stableL0, stableL1);
    return makeSyntheticRootHistory({
      poolId: 0,
      laneRoots: latest.laneRoots,
      laneCounts: latest.laneCounts,
      stableLaneRoots: stable.laneRoots,
      stableLaneCounts: stable.laneCounts,
      slotCursor: 5,
      slotCount: 6,
      epochCursor: 2,
      epochCount: 3,
      latestSlot,
      stableSlot,
    });
  };

  // Note (lane 0, leafIndex 1n) is absent from finalized (lane 0 count = 1n, so
  // selectRootSnapshotForNotes returns null) and present in confirmed (lane 0 count = 2n).
  // Every inconsistent/lagging confirmed replica MUST fail closed instead of being accepted.
  const laggingCases = [
    [
      'confirmed.latestSlot < fin.latestSlot',
      buildRh(1n, 0n, 1n, 0n, 200n, 96n),
      buildRh(2n, 0n, 1n, 0n, 198n, 96n),
    ],
    [
      'confirmed.stableSlot < fin.stableSlot',
      buildRh(1n, 0n, 1n, 0n, 150n, 128n),
      buildRh(2n, 0n, 1n, 0n, 160n, 96n),
    ],
    [
      'confirmed.latestLaneCounts[1] < fin.latestLaneCounts[1]',
      buildRh(1n, 1n, 1n, 0n, 150n, 96n),
      buildRh(2n, 0n, 1n, 0n, 160n, 96n),
    ],
    [
      'confirmed.stableLaneCounts[1] < fin.stableLaneCounts[1]',
      buildRh(1n, 1n, 1n, 1n, 150n, 128n),
      buildRh(2n, 1n, 1n, 0n, 160n, 128n),
    ],
  ];

  for (const [label, fin, conf] of laggingCases) {
    await assert.rejects(
      () =>
        fetchGlobalRootHistory({
          poolId: 0,
          requiredNotes: [{ laneId: 0, leafIndex: 1n }],
          fetchFinalized: async () => [fin.raw],
          fetchConfirmed: async () => [conf.raw],
        }),
      /Confirmed GlobalRootHistory lags behind finalized snapshot/,
      `fetchGlobalRootHistory must reject lagging confirmed snapshot (${label})`,
    );
  }

  // Positive control: monotonic confirmed snapshot containing the fresh note (0, 1n) succeeds.
  const finOk = buildRh(1n, 1n, 1n, 1n, 150n, 128n);
  const confOk = buildRh(2n, 1n, 1n, 1n, 160n, 128n);
  const resOk = await fetchGlobalRootHistory({
    poolId: 0,
    requiredNotes: [{ laneId: 0, leafIndex: 1n }],
    fetchFinalized: async () => [finOk.raw],
    fetchConfirmed: async () => [confOk.raw],
  });
  assert.equal(resOk.commitment, 'confirmed');
  assert.equal(resOk.snapshot.ringKind, ROOT_RING_SLOT);
  assert.equal(resOk.snapshot.ringIdx, 5);
  assert.equal(resOk.snapshot.slot, 160n);
  assert.deepEqual(resOk.snapshot.superRoot, frToBeBytes(confOk.superRoot));
});

test('v1.3.0 audit fixes #1-#6: lane currentRoot verification, RPC batch strictness, root parity, prover/poseidon/relayer/nk hardening', async () => {
  // === Fix #1: Pass 1A SubtreeRootPage + frontier SubtreePage verified against LaneTreeState.currentRoot ===
  {
    const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x9d));
    const fvk = exportFullViewingKey(alice);
    const wsolAsset = deriveAssetId(WSOL_MINT_BYTES);

    const sealedLeaves = Array.from({ length: SUBTREE_LEAVES }, (_, i) => BigInt(i + 100));
    const sealedSubroot = computeSubtree256Root(sealedLeaves, SUBTREE_LEAVES);

    const { tweak, blinding, memo } = encryptNoteMemo(
      alice.viewPk,
      new Uint8Array(32).fill(0x9e),
      5_555_555n,
      WSOL_MINT_BYTES,
    );
    const aliceCm = computeNoteCommitment(deriveStealthOwner(alice.spendPk, tweak), wsolAsset, 5_555_555n, blinding);
    const frontier3 = [701n, aliceCm, 703n];
    const frontier4Live = [701n, aliceCm, 703n, 704n];
    const nextLeaf = BigInt(SUBTREE_LEAVES + 3);
    const realLaneRoot = computeLaneRootFromSubroots([sealedSubroot], frontier3);

    const poolPda = derivePoolPdaSync(0).address;
    const lane0Pda = deriveLanePdaSync(0, 0).address;
    const sr0Pda = deriveSubrootPdaSync(0, 0, 0n).address;
    const sub0Pda = deriveSubtreePdaSync(0, 0, 0n).address;
    const sub1Pda = deriveSubtreePdaSync(0, 0, 1n).address;

    const baseAccounts = new Map([
      [poolPda, makePoolState(1)],
      [lane0Pda, makeLaneState(0, nextLeaf, 0n, realLaneRoot)],
      [sr0Pda, makeSubrootPage(0, 0n, [sealedSubroot])],
      [sub0Pda, makeSubtreePage(0, 0n, sealedLeaves)],
      [sub1Pda, makeSubtreePage(0, 1n, frontier3)],
    ]);
    const totalMemoPages = Math.ceil(Number(nextLeaf) / MEMO_NOTES_PER_PAGE);
    const targetLeaf = SUBTREE_LEAVES + 1;
    for (let m = 0; m < totalMemoPages; m++) {
      const cnt = Math.min(MEMO_NOTES_PER_PAGE, Number(nextLeaf) - m * MEMO_NOTES_PER_PAGE);
      const mraw = makeMemoPageWithMeta(0, BigInt(m), cnt);
      if (Math.floor(targetLeaf / MEMO_NOTES_PER_PAGE) === m) {
        writeMemoSlot(mraw, targetLeaf % MEMO_NOTES_PER_PAGE, memo);
      }
      baseAccounts.set(deriveMemoPdaSync(0, 0, BigInt(m)).address, mraw);
    }

    // (a) Tampered/fork-skewed frontier SubtreePage (len == frontierRem and len == frontierRem + 1)
    for (const [label, badFrontier] of [
      ['tampered frontier (len == frontierRem)', [701n, 999_999n, 703n]],
      ['tampered frontier (len == frontierRem + 1)', [701n, 999_999n, 703n, 704n]],
    ]) {
      const badAccounts = new Map(baseAccounts);
      badAccounts.set(sub1Pda, makeSubtreePage(0, 1n, badFrontier));
      const st = new CompactWalletStore(0, 0n);
      await assert.rejects(
        () =>
          syncCompactStoreWithRpc({
            store: st,
            fvk,
            fetchBatch: async (addrs) => addrs.map((a) => badAccounts.get(a) ?? null),
          }),
        /Lane #0 root mismatch/,
        `${label} must be rejected`,
      );
      assert.equal(st.lanes[0].nextMemoLeaf, 0n);
      assert.equal(st.lanes[0].frontierLeaves.length, 0);
      assert.equal(st.lanes[0].finalizedSubroots.length, 0);
      assert.equal(st.notes.length, 0);
    }

    // (b) Tampered Pass 1A SubtreeRootPage in 'fast' mode (0 hits, frontierRem == 0 -> 0 SubtreePages fetched)
    {
      const sealedOnlyRoot = computeLaneRootFromSubroots([sealedSubroot]);
      const badSrAccounts = new Map([
        [poolPda, makePoolState(1)],
        [lane0Pda, makeLaneState(0, BigInt(SUBTREE_LEAVES), 0n, sealedOnlyRoot)],
        [sr0Pda, makeSubrootPage(0, 0n, [42_424_242n])],
      ]);
      for (let m = 0; m < Math.ceil(SUBTREE_LEAVES / MEMO_NOTES_PER_PAGE); m++) {
        const cnt = Math.min(MEMO_NOTES_PER_PAGE, SUBTREE_LEAVES - m * MEMO_NOTES_PER_PAGE);
        badSrAccounts.set(deriveMemoPdaSync(0, 0, BigInt(m)).address, makeMemoPageWithMeta(0, BigInt(m), cnt));
      }
      const st = new CompactWalletStore(0, 0n);
      await assert.rejects(
        () =>
          syncCompactStoreWithRpc({
            store: st,
            fvk,
            privacyMode: 'fast',
            fetchBatch: async (addrs) => addrs.map((a) => badSrAccounts.get(a) ?? null),
          }),
        /Lane #0 root mismatch/,
        'tampered Pass 1A SubtreeRootPage must be rejected',
      );
      assert.equal(st.lanes[0].finalizedSubroots.length, 0);
      assert.equal(st.lanes[0].nextMemoLeaf, 0n);
    }

    // (c) Live-advancing frontier SubtreePage (`frontierRem + 1` leaves matching first `frontierRem` leaves)
    {
      const liveAccounts = new Map(baseAccounts);
      liveAccounts.set(sub1Pda, makeSubtreePage(0, 1n, frontier4Live));
      const st = new CompactWalletStore(0, 0n);
      const res = await syncCompactStoreWithRpc({
        store: st,
        fvk,
        fetchBatch: async (addrs) => addrs.map((a) => liveAccounts.get(a) ?? null),
      });
      assert.equal(res.discoveredNotes, 1);
      assert.equal(st.notes.length, 1);
      assert.equal(st.notes[0].leafIndex, BigInt(SUBTREE_LEAVES + 1));
      assert.equal(st.lanes[0].nextMemoLeaf, nextLeaf);
      assert.equal(st.lanes[0].finalizedSubroots.length, 1);
      assert.equal(st.lanes[0].frontierSubSeq, 1n);
      assert.equal(
        st.lanes[0].frontierLeaves.length,
        3,
        'unverified trailing live leaf beyond frontierRem must NOT be committed',
      );
      for (let i = 0; i < frontier3.length; i++) {
        assert.deepEqual(st.lanes[0].frontierLeaves[i], frToBeBytes(frontier3[i]));
      }
    }
  }

  // === Fix #2: createSolanaRpcBatchFetcher validates JSON-RPC response shape and value.length ===
  {
    const origFetch = globalThis.fetch;
    try {
      const fetcher = createSolanaRpcBatchFetcher('https://rpc.example.invalid', 'confirmed');
      const addrs = [derivePoolPdaSync(0).address, deriveLanePdaSync(0, 0).address];

      for (const [label, body] of [
        ['null body', null],
        ['string body', 'oops'],
        ['array body', []],
        ['empty object', {}],
        ['result null', { result: null }],
        ['result missing value', { result: {} }],
        ['truncated value array', { result: { value: [null] } }],
        ['oversized value array', { result: { value: [null, null, null] } }],
        ['rpc error object', { error: { message: 'rate limited' } }],
        ['malformed non-null account entry', { result: { value: [{}, null] } }],
      ]) {
        globalThis.fetch = async () => new Response(JSON.stringify(body), { status: 200 });
        await assert.rejects(() => fetcher(addrs), Error, `createSolanaRpcBatchFetcher must reject ${label}`);
      }

      const b64 = Buffer.from([0xde, 0xad, 0xbe, 0xef]).toString('base64');
      globalThis.fetch = async () =>
        new Response(JSON.stringify({ result: { value: [null, { data: [b64, 'base64'] }] } }), { status: 200 });
      const okRes = await fetcher(addrs);
      assert.equal(okRes.length, 2);
      assert.equal(okRes[0], null);
      assert.deepEqual(okRes[1], new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
    } finally {
      globalThis.fetch = origFetch;
    }
  }

  // === Fix #3: fetchGlobalRootHistory enforces epochInterval & all 4 equal-count lane_roots pairings ===
  {
    const l0_1 = computeLaneRootFromLeaves([11n]);
    const l0_2 = computeLaneRootFromLeaves([11n, 22n]);
    const l0_3 = computeLaneRootFromLeaves([11n, 22n, 33n]);
    const l1_a1 = computeLaneRootFromLeaves([101n]);
    const l1_a2 = computeLaneRootFromLeaves([101n, 102n]);
    const l1_b1 = computeLaneRootFromLeaves([201n]);
    const l1_b2 = computeLaneRootFromLeaves([201n, 202n]);
    const l1_b3 = computeLaneRootFromLeaves([201n, 202n, 203n]);
    const z0 = [0n, ZERO_HASHES_4ARY[18]];

    const makeState = (l0, l1) => {
      const laneRoots = new Array(NUM_LANES).fill(ZERO_HASHES_4ARY[18]);
      const laneCounts = new Array(NUM_LANES).fill(0n);
      if (l0[0] > 0n) {
        laneCounts[0] = l0[0];
        laneRoots[0] = l0[1];
      }
      if (l1[0] > 0n) {
        laneCounts[1] = l1[0];
        laneRoots[1] = l1[1];
      }
      return { laneRoots, laneCounts };
    };
    const buildRh = (latestL0, latestL1, stableL0, stableL1, latestSlot, stableSlot, epochInterval) => {
      const latest = makeState(latestL0, latestL1);
      const stable = makeState(stableL0, stableL1);
      return makeSyntheticRootHistory({
        poolId: 0,
        laneRoots: latest.laneRoots,
        laneCounts: latest.laneCounts,
        stableLaneRoots: stable.laneRoots,
        stableLaneCounts: stable.laneCounts,
        slotCursor: 5,
        slotCount: 6,
        epochCursor: 2,
        epochCount: 3,
        latestSlot,
        stableSlot,
        epochInterval,
      });
    };

    const mismatchCases = [
      [
        'epochInterval mismatch',
        buildRh([2n, l0_2], z0, [1n, l0_1], z0, 150n, 128n, 32n),
        buildRh([3n, l0_3], z0, [2n, l0_2], z0, 160n, 128n, 64n),
      ],
      [
        'latest == latest laneRoots mismatch',
        buildRh([2n, l0_2], [1n, l1_a1], [1n, l0_1], z0, 150n, 128n, 32n),
        buildRh([3n, l0_3], [1n, l1_b1], [2n, l0_2], z0, 160n, 128n, 32n),
      ],
      [
        'stable == stable laneRoots mismatch',
        buildRh([2n, l0_2], [2n, l1_a2], [1n, l0_1], [1n, l1_a1], 150n, 128n, 32n),
        buildRh([3n, l0_3], [3n, l1_b3], [2n, l0_2], [1n, l1_b1], 160n, 128n, 32n),
      ],
      [
        'conf.stable == fin.latest laneRoots mismatch',
        buildRh([2n, l0_2], [1n, l1_a1], [1n, l0_1], z0, 150n, 128n, 32n),
        buildRh([3n, l0_3], [2n, l1_b2], [2n, l0_2], [1n, l1_b1], 160n, 128n, 32n),
      ],
      [
        'conf.latest == fin.stable laneRoots mismatch',
        buildRh([2n, l0_2], [1n, l1_a1], [1n, l0_1], [1n, l1_a1], 150n, 128n, 32n),
        buildRh([3n, l0_3], [1n, l1_b1], [2n, l0_2], [1n, l1_b1], 160n, 128n, 32n),
      ],
    ];

    for (const [label, fin, conf] of mismatchCases) {
      // Branch 1: note (0, 1n) has finalizedSlotFallback -> falls back to finalized
      const fb = await fetchGlobalRootHistory({
        poolId: 0,
        requiredNotes: [{ laneId: 0, leafIndex: 1n }],
        fetchFinalized: async () => [fin.raw],
        fetchConfirmed: async () => [conf.raw],
      });
      assert.equal(fb.commitment, 'finalized', `${label}: must fall back to finalizedSlotFallback`);
      assert.equal(fb.snapshot.slot, 150n, label);
      assert.deepEqual(fb.snapshot.superRoot, frToBeBytes(fin.superRoot), label);

      // Branch 2: note (0, 2n) missing from finalized -> fails closed
      await assert.rejects(
        () =>
          fetchGlobalRootHistory({
            poolId: 0,
            requiredNotes: [{ laneId: 0, leafIndex: 2n }],
            fetchFinalized: async () => [fin.raw],
            fetchConfirmed: async () => [conf.raw],
          }),
        /Confirmed GlobalRootHistory lags behind finalized snapshot/,
        `${label}: must fail closed when finalized has no fallback`,
      );
    }
  }

  // === Fix #4: AudrenWasmProver.init validates wasmBytes & pkCompressed synchronously before any fetch() ===
  {
    const origFetch = globalThis.fetch;
    let fetchCalls = 0;
    try {
      globalThis.fetch = async () => {
        fetchCalls++;
        throw new Error('fetch should never have been initiated');
      };
      await assert.rejects(
        () =>
          AudrenWasmProver.init({
            wasmUrl: 'https://example.invalid/audren_circuits.wasm',
            pkCompressed: 'not-bytes',
          }),
        RangeError,
      );
      assert.equal(fetchCalls, 0, 'invalid pkCompressed must throw before initiating wasmUrl fetch()');

      await assert.rejects(
        () =>
          AudrenWasmProver.init({
            wasmBytes: 'not-bytes',
            pkUrl: 'https://example.invalid/audren_joinsplit.pk',
          }),
        RangeError,
      );
      assert.equal(fetchCalls, 0, 'invalid wasmBytes must throw before initiating pkUrl fetch()');
    } finally {
      globalThis.fetch = origFetch;
    }
  }

  // === Fix #5: encodeJoinsplitWitness enforces canonical Fr in 0..r-1 & packPublicAmounts enforces u64 ===
  {
    const makeValidWitness = () => ({
      superRoot: 1n,
      txAssetId: 2n,
      publicAssetId: 3n,
      publicAmountOut: 100n,
      relayerFeeAmount: 10n,
      ctxHash: 4n,
      omitNf1: false,
      inputs: [dummyInputWitness(5n, 2n, 6n), dummyInputWitness(7n, 2n, 8n)],
      outputs: [
        dummyOutputWitness(2n, 9n),
        dummyOutputWitness(2n, 10n),
        dummyOutputWitness(2n, 11n),
      ],
    });
    assert.equal(encodeJoinsplitWitness(makeValidWitness()).byteLength, 4611);

    for (const badFr of [-1n, BN254_FR_MODULUS, BN254_FR_MODULUS + 1n]) {
      assert.throws(
        () => encodeJoinsplitWitness({ ...makeValidWitness(), ctxHash: badFr }),
        RangeError,
        `encodeJoinsplitWitness must reject non-canonical ctxHash=${badFr}`,
      );
      assert.throws(
        () => encodeJoinsplitWitness({ ...makeValidWitness(), superRoot: badFr }),
        RangeError,
        `encodeJoinsplitWitness must reject non-canonical superRoot=${badFr}`,
      );
      const wBadInp = makeValidWitness();
      wBadInp.inputs[0].spendSk = badFr;
      assert.throws(
        () => encodeJoinsplitWitness(wBadInp),
        RangeError,
        `encodeJoinsplitWitness must reject non-canonical inputs[0].spendSk=${badFr}`,
      );
      const wBadOut = makeValidWitness();
      wBadOut.outputs[0].blinding = badFr;
      assert.throws(
        () => encodeJoinsplitWitness(wBadOut),
        RangeError,
        `encodeJoinsplitWitness must reject non-canonical outputs[0].blinding=${badFr}`,
      );
    }

    const u64Max = (1n << 64n) - 1n;
    assert.equal(packPublicAmounts(0n, 0n), 0n);
    assert.equal(packPublicAmounts(u64Max, u64Max), u64Max + (u64Max << 64n));
    for (const badU64 of [-1n, u64Max + 1n]) {
      assert.throws(() => packPublicAmounts(badU64, 0n), RangeError);
      assert.throws(() => packPublicAmounts(0n, badU64), RangeError);
    }
  }

  // === Fix #6: syncCompactStoreWithRpc requires fvk.nk upfront & AudrenRelayClient throws on HTTP 200 invalid JSON ===
  {
    const keys = deriveKeysFromSeed(new Uint8Array(32).fill(0xab));
    const fvk = exportFullViewingKey(keys);
    const store = new CompactWalletStore(0, 0n);
    let fetchCalls = 0;
    for (const badNk of [undefined, null, 'bad', new Uint8Array(31), new Uint8Array(33)]) {
      await assert.rejects(
        () =>
          syncCompactStoreWithRpc({
            store,
            fvk: { ...fvk, nk: badNk },
            fetchBatch: async () => {
              fetchCalls++;
              return [];
            },
          }),
        RangeError,
        `syncCompactStoreWithRpc must reject fvk.nk=${String(badNk)} upfront`,
      );
    }
    assert.equal(fetchCalls, 0, 'invalid fvk.nk must fail BEFORE any RPC call');

    const origFetch = globalThis.fetch;
    try {
      const relay = new AudrenRelayClient('https://relay.example.invalid');
      globalThis.fetch = async () => new Response('<html>captive portal</html>', { status: 200 });
      await assert.rejects(
        () => relay.getInfo('mainnet'),
        /Relay returned invalid JSON/,
        'HTTP 200 non-JSON relay body must throw instead of returning null',
      );

      globalThis.fetch = async () => new Response('<html>bad gateway</html>', { status: 502 });
      await assert.rejects(() => relay.getInfo('mainnet'), /Relay HTTP 502/);

      globalThis.fetch = async () =>
        new Response(JSON.stringify({ error: 'rate limited' }), { status: 429 });
      await assert.rejects(() => relay.getInfo('mainnet'), /rate limited/);
    } finally {
      globalThis.fetch = origFetch;
    }
  }
});

test('Audit remediation regressions: OpenPage maxPayerDeficit, windowed HRW, batched witness, ctx_hash promotion, tx-v1 bounds, prover PK pin & dispose', async () => {
  // 1. H-1 & M-3: OpenPage 23 B layout + mandatory vs proactive lookahead separation
  const payer = base58Encode(new Uint8Array(32).fill(0x22));
  const lookahead = planAutoOpenPages({
    poolId: 0,
    laneId: 0,
    nextLeaf: 86n,
    nfCount: 540n,
    numOutputs: 1,
    numNfs: 1,
  });
  assert.equal(lookahead.length, 2);
  assert.equal(lookahead.every((t) => t.mandatory === false), true);
  const proactiveIxs = buildAutoOpenPageInstructions({
    payer,
    poolId: 0,
    laneId: 0,
    nextLeaf: 86n,
    nfCount: 540n,
    numOutputs: 1,
    numNfs: 1,
  });
  for (const ix of proactiveIxs) {
    assert.equal(ix.data.byteLength, 23);
    // Proactive lookahead MUST encode maxPayerDeficit = 0n
    const dv = new DataView(ix.data.buffer, ix.data.byteOffset, ix.data.byteLength);
    assert.equal(dv.getBigUint64(15, true), 0n);
  }
  const skippedProactive = buildAutoOpenPageInstructions({
    payer,
    poolId: 0,
    laneId: 0,
    nextLeaf: 86n,
    nfCount: 540n,
    numOutputs: 1,
    numNfs: 1,
    includeProactive: false,
  });
  assert.equal(skippedProactive.length, 0);

  const mandatoryRoll = planAutoOpenPages({
    poolId: 0,
    laneId: 0,
    nextLeaf: 96n,
    nfCount: 600n,
    numOutputs: 1,
    numNfs: 1,
  });
  assert.equal(mandatoryRoll.length, 2);
  assert.equal(mandatoryRoll.every((t) => t.mandatory === true), true);

  // 2. H-3: Windowed HRW decoys strictly fall inside [startSeq .. sealedCount) & reject duplicate lanes
  const vsk = new Uint8Array(32).fill(0x42);
  const scope = new TextEncoder().encode('sync-window-test');
  const winDecoys = selectHrwSealedDecoys({
    viewSk: vsk,
    scope,
    epochBucket: 0n,
    sealedByLane: [
      { laneId: 0, startSeq: 10_000n, sealedCount: 10_010n },
      { laneId: 1, startSeq: 10_000n, sealedCount: 10_010n },
    ],
    alreadySelected: new Set(['0:10005']),
    targetSealed: 16,
  });
  assert.equal(winDecoys.length, 15);
  for (const d of winDecoys) {
    assert.ok(d.pageSeq >= 10_000n && d.pageSeq < 10_010n, 'decoy must stay inside scanned window');
  }
  assert.throws(
    () =>
      selectHrwSealedDecoys({
        viewSk: vsk,
        scope,
        epochBucket: 0n,
        sealedByLane: [
          { laneId: 0, sealedCount: 5n },
          { laneId: 0, sealedCount: 10n },
        ],
        alreadySelected: new Set(),
        targetSealed: 4,
      }),
    RangeError,
  );
  // R1-2 Low: reject startSeq / sealedCount > U64_MAX
  assert.throws(
    () =>
      selectHrwSealedDecoys({
        viewSk: vsk,
        scope,
        epochBucket: 0n,
        sealedByLane: [{ laneId: 0, startSeq: 1n << 64n, sealedCount: (1n << 64n) + 1n }],
        alreadySelected: new Set(),
        targetSealed: 4,
      }),
    RangeError,
  );
  assert.throws(
    () =>
      selectHrwSealedDecoys({
        viewSk: vsk,
        scope,
        epochBucket: 0n,
        sealedByLane: [{ laneId: 0, startSeq: 0n, sealedCount: 1n << 64n }],
        alreadySelected: new Set(),
        targetSealed: 4,
      }),
    RangeError,
  );

  // R1-2 High & Medium: End-to-end Pass 1D Case 2 uniform window [19..30) + 5 tail decoys,
  // AND MAX_SYNC_PAGES_PER_CALL (4,096 MemoPages -> 1,536 subtrees) planned ceiling cap!
  {
    const aliceH3 = deriveKeysFromSeed(new Uint8Array(32).fill(0x7a));
    const fvkH3 = exportFullViewingKey(aliceH3);
    const dummyLeaves = Array.from({ length: SUBTREE_LEAVES }, (_, i) => BigInt(i + 500));
    const dummySubroot = computeSubtree256Root(dummyLeaves, SUBTREE_LEAVES);
    const encHit = encryptNoteMemo(aliceH3.viewPk, new Uint8Array(32).fill(0x7b), 1_234_567n, WSOL_MINT_BYTES);
    const hitCm = computeNoteCommitment(
      deriveStealthOwner(aliceH3.spendPk, encHit.tweak),
      deriveAssetId(WSOL_MINT_BYTES),
      1_234_567n,
      encHit.blinding,
    );
    const hitLeaves = [...dummyLeaves];
    hitLeaves[42] = hitCm;
    const hitSubroot = computeSubtree256Root(hitLeaves, SUBTREE_LEAVES);

    const poolPdaH3 = derivePoolPdaSync(0).address;
    const lane0PdaH3 = deriveLanePdaSync(0, 0).address;

    const runCase2 = async (includeHit) => {
      const totalSubs = 30;
      const startSub = 19;
      const hitSub = 25;
      const hitLeaf = hitSub * SUBTREE_LEAVES + 42;
      const nextLeaf = BigInt(totalSubs * SUBTREE_LEAVES);
      const subroots = Array.from({ length: totalSubs }, (_, s) =>
        includeHit && s === hitSub ? hitSubroot : dummySubroot,
      );
      const laneRoot = computeLaneRootFromSubroots(subroots);

      const subByAddr = new Map();
      for (let s = 0; s < totalSubs; s++) {
        subByAddr.set(deriveSubtreePdaSync(0, 0, BigInt(s)).address, {
          seq: s,
          bytes: makeSubtreePage(0, BigInt(s), includeHit && s === hitSub ? hitLeaves : dummyLeaves),
        });
      }
      const accounts = new Map([
        [poolPdaH3, makePoolState(1)],
        [lane0PdaH3, makeLaneState(0, nextLeaf, 0n, laneRoot)],
        [deriveSubrootPdaSync(0, 0, 0n).address, makeSubrootPage(0, 0n, subroots)],
      ]);
      const totalMemos = Math.ceil(Number(nextLeaf) / MEMO_NOTES_PER_PAGE);
      for (let m = 0; m < totalMemos; m++) {
        const cnt = Math.min(MEMO_NOTES_PER_PAGE, Number(nextLeaf) - m * MEMO_NOTES_PER_PAGE);
        const mraw = makeMemoPageWithMeta(0, BigInt(m), cnt);
        if (includeHit && Math.floor(hitLeaf / MEMO_NOTES_PER_PAGE) === m) {
          writeMemoSlot(mraw, hitLeaf % MEMO_NOTES_PER_PAGE, encHit.memo);
        }
        accounts.set(deriveMemoPdaSync(0, 0, BigInt(m)).address, mraw);
      }

      const stH3 = new CompactWalletStore(0, 0n);
      stH3.lanes[0].nextMemoLeaf = BigInt(startSub * SUBTREE_LEAVES);
      stH3.lanes[0].finalizedSubroots = subroots.slice(0, startSub).map((r) => frToBeBytes(r));

      const fetchedSubs = [];
      const res = await syncCompactStoreWithRpc({
        store: stH3,
        fvk: fvkH3,
        fetchBatch: async (addrs) =>
          addrs.map((a) => {
            const sub = subByAddr.get(a);
            if (sub) {
              fetchedSubs.push(sub.seq);
              return sub.bytes;
            }
            return accounts.get(a) ?? null;
          }),
      });
      assert.equal(res.discoveredNotes, includeHit ? 1 : 0);
      return fetchedSubs.sort((a, b) => a - b);
    };

    const subsHit = await runCase2(true);
    const subsNoHit = await runCase2(false);
    assert.equal(subsHit.length, 16, 'Case 2 must fetch exactly 16 sealed subtrees');
    assert.deepEqual(subsHit, subsNoHit, 'Case 2 hit vs 0-hit fetch set must be identical');
    for (let s = 19; s < 30; s++) {
      assert.ok(subsHit.includes(s), `Case 2 must uniformly fetch window subtree ${s}`);
    }
    assert.equal(subsHit.filter((s) => s < 19).length, 5, 'Case 2 must draw exactly 5 tail decoys');

    // Planned MAX_SYNC_PAGES_PER_CALL (4,096 MemoPages -> 1,536 subtrees) ceiling test
    const capSubs = 1_875;
    const capNextLeaf = BigInt(capSubs * SUBTREE_LEAVES);
    const capSubroots = Array.from({ length: capSubs }, () => dummySubroot);
    const capLaneRoot = computeLaneRootFromSubroots(capSubroots);
    const capPoolBytes = makePoolState(1);
    const capLaneBytes = makeLaneState(0, capNextLeaf, 0n, capLaneRoot);
    const capSubByAddr = new Map();
    for (let s = 0; s < capSubs; s++) {
      capSubByAddr.set(deriveSubtreePdaSync(0, 0, BigInt(s)).address, s);
    }
    const capMemoByAddr = new Map();
    for (let m = 0; m < 5_000; m++) {
      capMemoByAddr.set(deriveMemoPdaSync(0, 0, BigInt(m)).address, m);
    }
    const capStore = new CompactWalletStore(0, 0n);
    capStore.lanes[0].finalizedSubroots = capSubroots.map((r) => frToBeBytes(r));
    const capFetchedSubs = [];
    await syncCompactStoreWithRpc({
      store: capStore,
      fvk: fvkH3,
      fetchBatch: async (addrs) =>
        addrs.map((a) => {
          if (a === poolPdaH3) return capPoolBytes;
          if (a === lane0PdaH3) return capLaneBytes;
          const seq = capSubByAddr.get(a);
          if (seq !== undefined) {
            capFetchedSubs.push(seq);
            return makeSubtreePage(0, BigInt(seq), dummyLeaves);
          }
          const m = capMemoByAddr.get(a);
          if (m !== undefined) {
            return makeMemoPageWithMeta(0, BigInt(m), MEMO_NOTES_PER_PAGE);
          }
          return null;
        }),
    });
    assert.equal(capFetchedSubs.length, 16, 'Capped catch-up must fetch exactly 16 sealed decoys');
    for (const seq of capFetchedSubs) {
      assert.ok(seq < 1_536, `Decoy subtree ${seq} leaked past MAX_SYNC_PAGES_PER_CALL ceiling 1536`);
    }

    // R2-2 High-1: Multi-lane Pass 1C early-stop spillover (Lane 0 drops MemoPage 10 -> stops at
    // sub 4 and spills into Lane 1's 200 MemoPages [0..75) with hit at (1, 10)). MUST fetch
    // exact 16 sealed subtrees, all Lane 0 decoys < 4, and mix (1, 10) with Lane 1 decoys!
    {
      const lane0Subs = 1_875;
      const lane1Subs = 75;
      const hitSub = 10;
      const hitLeaf = hitSub * SUBTREE_LEAVES + 42;
      const lane0Subroots = Array.from({ length: lane0Subs }, () => dummySubroot);
      const lane1Subroots = Array.from({ length: lane1Subs }, (_, s) =>
        s === hitSub ? hitSubroot : dummySubroot,
      );
      const lane0Root = computeLaneRootFromSubroots(lane0Subroots);
      const lane1Root = computeLaneRootFromSubroots(lane1Subroots);
      const lane1PdaH3 = deriveLanePdaSync(0, 1).address;
      const spillPoolBytes = makePoolState(2);
      const spillLane0Bytes = makeLaneState(0, BigInt(lane0Subs * SUBTREE_LEAVES), 0n, lane0Root);
      const spillLane1Bytes = makeLaneState(1, BigInt(lane1Subs * SUBTREE_LEAVES), 0n, lane1Root);

      const spillSubMap = new Map();
      for (let s = 0; s < lane0Subs; s++) {
        spillSubMap.set(deriveSubtreePdaSync(0, 0, BigInt(s)).address, { laneId: 0, seq: s });
      }
      for (let s = 0; s < lane1Subs; s++) {
        spillSubMap.set(deriveSubtreePdaSync(0, 1, BigInt(s)).address, { laneId: 1, seq: s });
      }
      const spillMemoMap = new Map();
      for (let m = 0; m < 100; m++) {
        spillMemoMap.set(deriveMemoPdaSync(0, 0, BigInt(m)).address, { laneId: 0, m });
      }
      for (let m = 0; m < 200; m++) {
        spillMemoMap.set(deriveMemoPdaSync(0, 1, BigInt(m)).address, { laneId: 1, m });
      }
      const spillStore = new CompactWalletStore(0, 0n);
      spillStore.lanes[0].finalizedSubroots = lane0Subroots.map((r) => frToBeBytes(r));
      spillStore.lanes[1].finalizedSubroots = lane1Subroots.map((r) => frToBeBytes(r));
      const spillFetched = [];
      const spillRes = await syncCompactStoreWithRpc({
        store: spillStore,
        fvk: fvkH3,
        fetchBatch: async (addrs) =>
          addrs.map((a) => {
            if (a === poolPdaH3) return spillPoolBytes;
            if (a === lane0PdaH3) return spillLane0Bytes;
            if (a === lane1PdaH3) return spillLane1Bytes;
            const sub = spillSubMap.get(a);
            if (sub) {
              spillFetched.push(sub);
              return makeSubtreePage(
                sub.laneId,
                BigInt(sub.seq),
                sub.laneId === 1 && sub.seq === hitSub ? hitLeaves : dummyLeaves,
              );
            }
            const mm = spillMemoMap.get(a);
            if (mm) {
              if (mm.laneId === 0 && mm.m === 10) return null;
              const mraw = makeMemoPageWithMeta(mm.laneId, BigInt(mm.m), MEMO_NOTES_PER_PAGE);
              if (mm.laneId === 1 && Math.floor(hitLeaf / MEMO_NOTES_PER_PAGE) === mm.m) {
                writeMemoSlot(mraw, hitLeaf % MEMO_NOTES_PER_PAGE, encHit.memo);
              }
              return mraw;
            }
            return null;
          }),
      });
      assert.equal(spillRes.discoveredNotes, 1);
      assert.equal(spillFetched.length, 16, 'Early-stop spillover MUST fetch exact 16 sealed subtrees');
      let lane1Count = 0;
      for (const item of spillFetched) {
        if (item.laneId === 0) {
          assert.ok(item.seq < 4, `Lane 0 decoy ${item.seq} leaked past early-stop scanned ceiling 4`);
        } else {
          assert.equal(item.laneId, 1);
          assert.ok(item.seq < 75);
          lane1Count++;
        }
      }
      assert.ok(lane1Count >= 12, `Spilled Lane 1 hit must be surrounded by Lane 1 decoys (got ${lane1Count})`);
    }
  }

  // 3. H-10: computeExecCtxHash promotes payer / escrowInAta / escrowOutAta / vaultInAta / vaultOutAta
  const escrowIn = base58Encode(new Uint8Array(32).fill(0xaa));
  const routerProg = base58Encode(new Uint8Array(32).fill(0x77));
  const commonExec = {
    poolId: 0,
    outLaneId: 0,
    escrowShard: 1,
    changeMask: 0,
    feeOnOutput: false,
    assetIn: new Uint8Array(32).fill(1),
    amountIn: 100n,
    relayerFeeAmount: 0n,
    assetOut: new Uint8Array(32).fill(2),
    minAmountOut: 50n,
    routerProg,
    outStealthOwner: new Uint8Array(32).fill(3),
    outBlinding: new Uint8Array(32).fill(4),
    dynMemoHead: new Uint8Array(34).fill(5),
    dynMemoMask: new Uint8Array(72).fill(6),
    routerIxData: new Uint8Array([1, 2]),
    changeMemos: new Uint8Array(0),
  };
  const hAuto = computeExecCtxHash({
    ...commonExec,
    escrowInAta: escrowIn,
    routerAccounts: [{ pubkey: escrowIn, isSigner: false, isWritable: false }],
  });
  const hExplicit = computeExecCtxHash({
    ...commonExec,
    routerAccounts: [{ pubkey: escrowIn, isSigner: false, isWritable: true }],
  });
  assert.equal(hAuto, hExplicit);

  // 4. H-11: deferPk + loadProvingKeyCompressed enforces CANONICAL_PK_SHA256 & dispose() blocks reuse
  const deferred = await AudrenWasmProver.init({ deferPk: true });
  assert.throws(
    () => deferred.loadProvingKeyCompressed(new Uint8Array(64).fill(0xee)),
    /SHA-256 mismatch/,
  );
  deferred.dispose();
  assert.throws(
    () => deferred.poseidonHashWasm([new Uint8Array(32)]),
    /disposed/,
  );

  // 5. M-4 & L-1 & M-12: leafIndex >= MAX_LEAVES_PER_LANE, recordVerifiedMemo mismatch, tx-v1 >12 signers
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x55));
  const fvk = exportFullViewingKey(alice);
  const st = new CompactWalletStore(0, 0n);
  assert.throws(
    () =>
      st.recordVerifiedMemo({
        fvk,
        laneId: 0,
        leafIdx: 0n,
        decrypted: {
          amount: 10n,
          mint: WSOL_MINT_BYTES,
          tweak: 1n,
          blinding: 2n,
          memoVersion: MEMO_VERSION_V1,
          memoFlags: 0,
          paymentId: new Uint8Array(MEMO_PAYMENT_ID_LEN),
          isDynamic: false,
        },
        cmBe: new Uint8Array(32).fill(0x99),
      }),
    /Note commitment mismatch/,
  );
  const cmValid = frToBeBytes(
    computeNoteCommitment(deriveStealthOwner(alice.spendPk, 1n), deriveAssetId(WSOL_MINT_BYTES), 10n, 2n),
  );
  assert.equal(
    verifySelectiveDisclosureProof(
      {
        poolId: 0,
        laneId: 0,
        leafIndex: 1n << 36n,
        stealthOwner: frToBeBytes(deriveStealthOwner(alice.spendPk, 1n)),
        mint: WSOL_MINT_BYTES,
        amount: 10n,
        blinding: frToBeBytes(2n),
        commitment: cmValid,
      },
      cmValid,
    ),
    false,
  );
  const manySigners = Array.from({ length: 13 }, (_, idx) => {
    const pk = new Uint8Array(32);
    pk[0] = idx + 1;
    return { pubkey: pk, isSigner: true, isWritable: false };
  });
  assert.throws(
    () =>
      compileV1Message({
        feePayer: manySigners[0].pubkey,
        recentBlockhash: new Uint8Array(32).fill(7),
        instructions: [
          { programId: new Uint8Array(32).fill(9), accounts: manySigners, data: new Uint8Array([1]) },
        ],
        config: { computeUnitLimit: 100_000 },
      }),
    RangeError,
  );
  assert.throws(() => recommendedDepositCuLimit({ openPageCount: Number.NaN }), RangeError);
});
