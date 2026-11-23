import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_PUBLIC,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  AUDREN_ANCHOR_IDL,
  AUDREN_CODAMA_IDL,
  AUDREN_PROGRAM_ID,
  AudrenRelayClient,
  BN254_FR_MODULUS,
  CKPT_LEN,
  CKPT_MAGIC,
  CK_OFF_LANE_COUNTS,
  CK_OFF_LANE_ROOTS,
  CK_OFF_MAGIC,
  CK_OFF_SUPER_ROOT,
  CK_OFF_VERSION,
  CLASSIC_TOKEN_PROGRAM_ID,
  CompactWalletStore,
  DEPOSIT_FLAG_FEE_FROM_AMOUNT,
  DEPOSIT_FLAG_NATIVE_SOL,
  DYN_MEMO_MAGIC,
  JUPITER_CPI_EXCLUDED_DEXES,
  LANE_MAGIC,
  LANE_STATE_LEN,
  LN_OFF_LANE_ID,
  LN_OFF_MAGIC,
  LN_OFF_NEXT_LEAF,
  LN_OFF_NF_COUNT,
  LN_OFF_VERSION,
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
  MM_OFF_VIEW_TAGS,
  NF_OFF_COUNT,
  NF_OFF_LANE_ID,
  NF_OFF_MAGIC,
  NF_OFF_PAGE_SEQ,
  NF_OFF_PREFIXES,
  NF_PAGE_LEN,
  NF_PAGE_MAGIC,
  NF_PER_PAGE,
  NF_PREFIX_LEN,
  NUM_ESCROW_SHARDS,
  NUM_LANES,
  OPEN_PAGE_KIND_SUBTREE,
  PL_OFF_ACTIVE_LANES,
  PL_OFF_MAGIC,
  PL_OFF_VERSION,
  POOL_MAGIC,
  POOL_STATE_LEN,
  PROTOCOL_VERSION,
  SB_OFF_COUNT,
  SB_OFF_LANE_ID,
  SB_OFF_LEAVES,
  SB_OFF_MAGIC,
  SB_OFF_PAGE_SEQ,
  SR_OFF_COUNT,
  SR_OFF_LANE_ID,
  SR_OFF_MAGIC,
  SR_OFF_ROOTS,
  SR_OFF_ROOT_PAGE_SEQ,
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
  TAG_OPEN_PAGE,
  TAG_PUBLISH_CHECKPOINT,
  TAG_SET_PAUSED,
  TAG_TRANSACT,
  TAG_UPDATE_POOL,
  TOKEN_2022_PROGRAM_ID,
  UPDATE_POOL_ACCEPT_AUTHORITY,
  UPDATE_POOL_PARAMS,
  UPDATE_POOL_PROPOSE_AUTHORITY,
  UPDATE_POOL_RENOUNCE_AUTHORITY,
  WITHDRAW_FLAG_UNWRAP_WSOL,
  WSOL_MINT,
  ZERO_HASHES_4ARY,
  base58Decode,
  base58Encode,
  buildCreateAtaIdempotentInstruction,
  buildDepositInstruction,
  buildExecViaEscrowInstruction,
  buildInitLaneInstruction,
  buildInitPoolInstruction,
  buildOpenPageInstruction,
  buildPublishCheckpointInstruction,
  buildSetPausedInstruction,
  buildTransactInstruction,
  buildUpdatePoolInstruction,
  checkMemoViewTag,
  compileV1Message,
  computeExecCtxHash,
  computeMerkleRoot4Ary,
  computeNoteCommitment,
  computePageRollovers,
  computeSubtree256Root,
  computeSuperRoot4Ary,
  computeToken2022NetAmount,
  computeTransactCtxHash,
  decodeRootCheckpoint,
  deriveAssetId,
  deriveAssociatedTokenAddressSync,
  deriveCheckpointPdaSync,
  deriveEscrowPdaSync,
  deriveKeysFromSeed,
  deriveLanePdaSync,
  deriveMemoPdaSync,
  deriveNfPagePdaSync,
  derivePoolPdaSync,
  deriveStealthOwner,
  deriveSubrootPdaSync,
  deriveSubtreePdaSync,
  deriveUnwrapPdaSync,
  deriveVaultAuthPdaSync,
  deterministicNoteRentFee,
  encryptNoteMemo,
  exportFullViewingKey,
  exportSelectiveDisclosureProof,
  formatAudrenAddress,
  frToBeBytes,
  inspectToken2022UnsafeSelfPay,
  parseAudrenAddress,
  parseToken2022TransferFeeConfig,
  pickRandomEscrowShard,
  pickRandomLaneId,
  poseidon4,
  prepareDynamicSwapMemo,
  prepareEscrowAccounts,
  prepareEscrowAccountsForAudren,
  reconstructWitness,
  selectHrwSealedDecoys,
  serializeV1Transaction,
  syncCompactStoreWithRpc,
  toPubkeyBytes,
  tryDecryptAndVerifyMemo,
  verifySelectiveDisclosureProof,
} from '../dist/index.js';
import { AudrenWasmProver } from '../dist/prover-entry.js';

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
  new DataView(subRaw.buffer).setUint16(SB_OFF_COUNT, SUBTREE_LEAVES, true);

  const memo0 = makeMemoPage(MEMO_NOTES_PER_PAGE); // 0..95
  const memo1 = makeMemoPage(MEMO_NOTES_PER_PAGE); // 96..191
  const memo2 = makeMemoPage(SUBTREE_LEAVES - 2 * MEMO_NOTES_PER_PAGE); // 192..255 (64)

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

  // Build synthetic RootCheckpoint at count = 256 and reconstruct offline witness
  let lroot = computeSubtree256Root(leaves, SUBTREE_LEAVES);
  for (let h = 4; h < 18; h++) {
    lroot = poseidon4(lroot, ZERO_HASHES_4ARY[h], ZERO_HASHES_4ARY[h], ZERO_HASHES_4ARY[h]);
  }
  const laneRoots = new Array(NUM_LANES).fill(ZERO_HASHES_4ARY[18]);
  laneRoots[1] = lroot;
  const superRoot = computeSuperRoot4Ary(laneRoots);

  const ckRaw = new Uint8Array(CKPT_LEN);
  ckRaw.set(enc.encode(CKPT_MAGIC), CK_OFF_MAGIC);
  ckRaw[CK_OFF_VERSION] = PROTOCOL_VERSION;
  ckRaw.set(frToBeBytes(superRoot), CK_OFF_SUPER_ROOT);
  const ckv = new DataView(ckRaw.buffer);
  for (let i = 0; i < NUM_LANES; i++) {
    ckRaw.set(frToBeBytes(laneRoots[i]), CK_OFF_LANE_ROOTS + i * 32);
    ckv.setBigUint64(CK_OFF_LANE_COUNTS + i * 8, i === 1 ? 256n : 0n, true);
  }
  const ckpt = decodeRootCheckpoint(ckRaw);
  const { superRoot: sr, path } = restored.buildWitnessForNote(note, ckpt);
  assert.equal(sr, superRoot);
  assert.equal(computeMerkleRoot4Ary(path, leaves[7]), superRoot);

  // Guard: buildWitnessForNote rejects missing frontier leaves when checkpoint has unsealed tail
  const ckBadRaw = new Uint8Array(ckRaw);
  new DataView(ckBadRaw.buffer).setBigUint64(CK_OFF_LANE_COUNTS + 1 * 8, 258n, true);
  assert.throws(
    () => restored.buildWitnessForNote(note, decodeRootCheckpoint(ckBadRaw)),
    /Missing frontier SubtreePage leaves/,
  );

  // Out-of-order NullifierPage ingestion still marks spent notes cleanly (page 1 before page 0)
  const nfRaw0 = new Uint8Array(NF_PAGE_LEN);
  nfRaw0.set(enc.encode(NF_PAGE_MAGIC), NF_OFF_MAGIC);
  new DataView(nfRaw0.buffer).setUint16(NF_OFF_COUNT, 1, true);
  nfRaw0.set(note.nullifier.subarray(0, NF_PREFIX_LEN), NF_OFF_PREFIXES);

  const nfRaw1 = new Uint8Array(NF_PAGE_LEN);
  nfRaw1.set(enc.encode(NF_PAGE_MAGIC), NF_OFF_MAGIC);
  new DataView(nfRaw1.buffer).setUint16(NF_OFF_COUNT, 1, true);
  nfRaw1.set(new Uint8Array(NF_PREFIX_LEN).fill(0xee), NF_OFF_PREFIXES);

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

  const memo0 = makeMemoPage(MEMO_NOTES_PER_PAGE); // 0..95
  const memo1 = makeMemoPage(MEMO_NOTES_PER_PAGE); // 96..191
  const memo2 = makeMemoPage(SUBTREE_LEAVES - 2 * MEMO_NOTES_PER_PAGE); // 192..255

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

  // deterministicNoteRentFee uses MEMO_NOTES_PER_PAGE = 96
  assert.equal(
    deterministicNoteRentFee(10_000_000n, 256n * 100n, 76_800n * 10n, 96n * 200n),
    310n,
  );
  assert.equal(
    deterministicNoteRentFee(150n, 256n * 100n, 76_800n * 10n, 96n * 200n),
    150n,
  );

  // Tag 0: InitPool (3 accounts, 37 B)
  const initPool = buildInitPoolInstruction({
    payer,
    poolId: 0,
    ckptInterval: 8n,
    maxCkptAge: 1536n,
    noteRentFee: 100n,
    nfRentFee: 50n,
  });
  assert.equal(initPool.data[0], TAG_INIT_POOL);
  assert.equal(initPool.data.byteLength, 37);
  assert.equal(initPool.accounts.length, 3);

  // Tag 1: InitLane (9 accounts, 6 B)
  const initLane = buildInitLaneInstruction({ authority: payer, poolId: 0, laneId: 0 });
  assert.equal(initLane.data[0], TAG_INIT_LANE);
  assert.equal(initLane.data.byteLength, 6);
  assert.equal(initLane.accounts.length, 9);

  // Tag 2: OpenPage (6 accounts, 15 B)
  const openPage = buildOpenPageInstruction({
    payer,
    pageKind: OPEN_PAGE_KIND_SUBTREE,
    poolId: 0,
    laneId: 0,
    pageSeq: 1n,
  });
  assert.equal(openPage.data[0], TAG_OPEN_PAGE);
  assert.equal(openPage.data.byteLength, 15);
  assert.equal(openPage.accounts.length, 6);

  // Tag 3: Unified Deposit — Native SOL path (185 B, 13 fixed accounts)
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
  assert.equal(depSol.accounts.length, 13);
  assert.equal(depSol.accounts[3].pubkey, WSOL_MINT);
  assert.equal(depSol.accounts[4].pubkey, payer);
  assert.equal(depSol.accounts[5].pubkey, wsolVaultAta);
  assert.equal(depSol.accounts[6].pubkey, CLASSIC_TOKEN_PROGRAM_ID);

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
  assert.equal(depSpl.accounts.length, 16); // 13 + 2 rollover + 1 hook
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

  // Tag 4: PublishCheckpoint (5 B)
  const pubCkpt = buildPublishCheckpointInstruction({ payer, poolId: 0, slotIdx: 0, activeLanes: 4 });
  assert.equal(pubCkpt.data[0], TAG_PUBLISH_CHECKPOINT);
  assert.equal(pubCkpt.data.byteLength, 5);
  assert.equal(pubCkpt.accounts.length, 8);

  // Tag 5: Transact — private, public, WSOL unwrap, & vkId binding in ctx_hash
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
    ckptSlotIdx: 0,
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
  assert.equal(transactUnwrap.data.byteLength, 378);
  assert.equal(transactUnwrap.data[9], WITHDRAW_FLAG_UNWRAP_WSOL);
  assert.equal(transactUnwrap.accounts.length, 19); // 12 head + 7 public w/ unwrap PDA
  assert.equal(transactUnwrap.accounts[18].pubkey, deriveUnwrapPdaSync(0, nf0Bytes).address);

  assert.throws(
    () =>
      buildTransactInstruction({
        payer,
        poolId: 0,
        ckptSlotIdx: 0,
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

  // Tag 6: ExecViaEscrow (SPL/T22 only, 558 B header, 72 B dynMemoMask, vkId binding & writability promotion)
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
    ckptSlotIdx: 1,
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
  assert.equal(execIx.data.byteLength, 558 + 3);
  const trailing = execIx.accounts.slice(-rawRouterAccs.length);
  assert.equal(trailing[0].isSigner, false);
  assert.equal(trailing[0].isWritable, true);
  assert.equal(trailing[1].isWritable, true);
  assert.equal(trailing[3].isWritable, true);

  // Tag 7: SetPaused (6 B)
  const setPaused = buildSetPausedInstruction({ authority: payer, poolId: 0, paused: true });
  assert.equal(setPaused.data[0], TAG_SET_PAUSED);
  assert.equal(setPaused.data.byteLength, 6);

  // Tag 8: UpdatePool (all 4 sub-actions)
  const updParams = buildUpdatePoolInstruction({
    signer: payer,
    poolId: 0,
    action: { kind: 'params', ckptInterval: 16n, maxCkptAge: 2048n, noteRentFee: 200n, nfRentFee: 100n },
  });
  assert.equal(updParams.data[0], TAG_UPDATE_POOL);
  assert.equal(updParams.data[5], UPDATE_POOL_PARAMS);
  assert.equal(updParams.data.byteLength, 38);
  assert.equal(updParams.accounts.length, 2);

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

function makeLaneState(laneId, nextLeaf, nfCount) {
  const buf = new Uint8Array(LANE_STATE_LEN);
  buf.set(enc.encode(LANE_MAGIC), LN_OFF_MAGIC);
  buf[LN_OFF_VERSION] = PROTOCOL_VERSION;
  buf[LN_OFF_LANE_ID] = laneId;
  const dv = new DataView(buf.buffer);
  dv.setBigUint64(LN_OFF_NEXT_LEAF, nextLeaf, true);
  dv.setBigUint64(LN_OFF_NF_COUNT, nfCount, true);
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

function makeSyntheticCheckpoint(laneId, laneRoot, laneCount) {
  const laneRoots = new Array(NUM_LANES).fill(ZERO_HASHES_4ARY[18]);
  laneRoots[laneId] = laneRoot;
  const superRoot = computeSuperRoot4Ary(laneRoots);
  const ckRaw = new Uint8Array(CKPT_LEN);
  ckRaw.set(enc.encode(CKPT_MAGIC), CK_OFF_MAGIC);
  ckRaw[CK_OFF_VERSION] = PROTOCOL_VERSION;
  ckRaw.set(frToBeBytes(superRoot), CK_OFF_SUPER_ROOT);
  const ckv = new DataView(ckRaw.buffer);
  for (let i = 0; i < NUM_LANES; i++) {
    ckRaw.set(frToBeBytes(laneRoots[i]), CK_OFF_LANE_ROOTS + i * 32);
    ckv.setBigUint64(CK_OFF_LANE_COUNTS + i * 8, i === laneId ? laneCount : 0n, true);
  }
  return { ckpt: decodeRootCheckpoint(ckRaw), superRoot, ckRaw };
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
    [deriveLanePdaSync(0, 2).address, makeLaneState(2, 1n, 0n)],
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
    [deriveLanePdaSync(0, 0).address, makeLaneState(0, 1n, 1n)],
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

test('Post-seal checkpoint witness building via prevSealedLeaves & automatic pruning', () => {
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
  const { ckpt: preSealCkpt, superRoot: preSealSuper } = makeSyntheticCheckpoint(0, preSealRoot, 250n);

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
  const { superRoot: sr250, path: path250 } = reloaded.buildWitnessForNote(note, preSealCkpt);
  assert.equal(sr250, preSealSuper);
  assert.equal(computeMerkleRoot4Ary(path250, leaves[200]), preSealSuper);
  assert.equal(reloaded.lanes[0].prevSealedSubSeq, 0n);

  const postSealRoot = computeLaneRootFromLeaves(leaves);
  const { ckpt: postSealCkpt, superRoot: postSealSuper } = makeSyntheticCheckpoint(0, postSealRoot, 256n);
  const { superRoot: sr256, path: path256 } = reloaded.buildWitnessForNote(note, postSealCkpt);
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
    [deriveLanePdaSync(0, 0).address, makeLaneState(0, BigInt(totalLeaves), 0n)],
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

  const { ckpt, superRoot } = makeSyntheticCheckpoint(0, computeLaneRootFromLeaves(allLeaves), BigInt(totalLeaves));
  const { path } = storeStrict.buildWitnessForNote(storeStrict.notes[0], ckpt);
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
  const { path: pathBd } = storeBd.buildWitnessForNote(storeBd.notes[0], ckpt);
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
    [deriveLanePdaSync(0, 0).address, makeLaneState(0, 1n, lane0NfTotal)],
    [deriveLanePdaSync(0, 1).address, makeLaneState(1, 0n, lane1NfTotal)],
    [deriveSubtreePdaSync(0, 0, 0n).address, lane0Sub0],
    [deriveMemoPdaSync(0, 0, 0n).address, lane0Memo0],
  ]);

  const expectedNfAddrs = new Set();
  const reusableLane0Full = makeNfPage(0, 1n, fullStrangerPrefixes);
  const lane0Tail = makeNfPage(0, BigInt(lane0NfPagesCount - 1), fullStrangerPrefixes.slice(0, 5));
  const reusableLane1Full = makeNfPage(1, 0n, fullStrangerPrefixes);
  const lane1Tail = makeNfPage(1, BigInt(lane1NfPagesCount - 1), fullStrangerPrefixes.slice(0, 3));

  for (let p = 0; p < lane0NfPagesCount; p++) {
    const addr = deriveNfPagePdaSync(0, 0, BigInt(p)).address;
    expectedNfAddrs.add(addr);
    accounts.set(
      addr,
      p === 0 ? makeNfPage(0, 0n, lane0Page0Prefixes) : p === lane0NfPagesCount - 1 ? lane0Tail : reusableLane0Full,
    );
  }
  for (let p = 0; p < lane1NfPagesCount; p++) {
    const addr = deriveNfPagePdaSync(0, 1, BigInt(p)).address;
    expectedNfAddrs.add(addr);
    accounts.set(addr, p === lane1NfPagesCount - 1 ? lane1Tail : reusableLane1Full);
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
      accounts.set(
        deriveLanePdaSync(0, l).address,
        makeLaneState(l, BigInt(leavesPerLane), l === 0 ? nfTotalLane0 : 0n),
      );
      const roots = Array.from({ length: sealedPerLane }, (_, s) =>
        l === 2 && BigInt(s) === aliceSubSeq ? hitSubRoot : dummySubRoot,
      );
      accounts.set(deriveSubrootPdaSync(0, l, 0n).address, makeSubrootPage(l, 0n, roots));

      const allLaneLeaves = [];
      const genericSealed = makeSubtreePage(l, 0n, dummyLeafFrs);
      for (let s = 0; s < sealedPerLane; s++) {
        const addr = deriveSubtreePdaSync(0, l, BigInt(s)).address;
        sealedSubAddrs.add(addr);
        allSubAddrs.add(addr);
        const isHit = l === 2 && BigInt(s) === aliceSubSeq;
        accounts.set(addr, isHit ? hitSubRaw : genericSealed);
        allLaneLeaves.push(...(isHit ? hitSubLeaves : dummyLeafFrs));
      }
      const fAddr = deriveSubtreePdaSync(0, l, BigInt(sealedPerLane)).address;
      allSubAddrs.add(fAddr);
      accounts.set(fAddr, makeSubtreePage(l, BigInt(sealedPerLane), dummyFrontierFrs));
      allLaneLeaves.push(...dummyFrontierFrs);
      laneRoots[l] = computeLaneRootFromLeaves(allLaneLeaves);

      const fullEmptyMemo = makeMemoPageWithMeta(l, 0n, MEMO_NOTES_PER_PAGE);
      for (let m = 0; m < memosPerLane; m++) {
        const addr = deriveMemoPdaSync(0, l, BigInt(m)).address;
        allMemoAddrs.add(addr);
        const cnt = Math.min(MEMO_NOTES_PER_PAGE, leavesPerLane - m * MEMO_NOTES_PER_PAGE);
        if (l === 2 && BigInt(m) === aliceMemoSeq) {
          accounts.set(addr, hitMemoRaw);
        } else if (cnt === MEMO_NOTES_PER_PAGE) {
          accounts.set(addr, fullEmptyMemo);
        } else {
          accounts.set(addr, makeMemoPageWithMeta(l, BigInt(m), cnt));
        }
      }
    }

    const superRoot = computeSuperRoot4Ary(laneRoots);
    const ckRaw = new Uint8Array(CKPT_LEN);
    ckRaw.set(enc.encode(CKPT_MAGIC), CK_OFF_MAGIC);
    ckRaw[CK_OFF_VERSION] = PROTOCOL_VERSION;
    ckRaw.set(frToBeBytes(superRoot), CK_OFF_SUPER_ROOT);
    const ckv = new DataView(ckRaw.buffer);
    for (let i = 0; i < NUM_LANES; i++) {
      ckRaw.set(frToBeBytes(laneRoots[i]), CK_OFF_LANE_ROOTS + i * 32);
      ckv.setBigUint64(CK_OFF_LANE_COUNTS + i * 8, laneCounts[i], true);
    }
    accounts.set(deriveCheckpointPdaSync(0, 0).address, ckRaw);

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
    ckptSlotIdx: 0,
    laneId: 2,
    leafIdx: aliceLeafIdx,
    viewSk: alice.viewSk,
  });
  assert.equal(rwStrict.superRoot, fix20.superRoot);
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
    ckptSlotIdx: 0,
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
    ckptSlotIdx: 0,
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
  await syncCompactStoreWithRpc({ store: hitDropStore, fvk, fetchBatch: makeDropFetcher(fix20.hitSubAddr, []) });
  const decoyDropStore = new CompactWalletStore(0, 0n);
  await syncCompactStoreWithRpc({ store: decoyDropStore, fvk, fetchBatch: makeDropFetcher(decoyToDrop, []) });
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
    incStore.lanes[l].finalizedSubroots = Array.from({ length: 5 }, () => new Uint8Array(32));
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
    ckptSlotIdx: 0,
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

test('AudrenRelayClient supports transfer privacy, requestCheckpoint, and multi-ix submitRelayedInstruction', async () => {
  const calls = [];
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    if (String(url).includes('/v1/checkpoint')) {
      return new Response(
        JSON.stringify({ ok: true, cluster: 'devnet', status: 'published', signature: 'sig123', epoch: 7 }),
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

    const ckRes = await client.requestCheckpoint({ cluster: 'devnet', poolId: 0 });
    assert.equal(ckRes.status, 'published');
    assert.equal(ckRes.signature, 'sig123');

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
