import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hkdfSync } from 'node:crypto';
import {
  pageIdForLane,
  laneOfPageId,
  seqOfPageId,
  encodeInitLaneData,
  encodeOpenLanePageData,
  decodeAppendLaneState,
  deriveSubAccountSeed,
  derivePoolPda,
  deriveEpochPagePda,
  deriveVaultAuthPda,
  deriveSolVaultPda,
  deriveSwapEscrowPda,
  deriveLanePda,
  deriveAssociatedTokenAddress,
  parseAudrenAddress,
  formatAudrenAddress,
  isValidRistretto255Point,
  findProgramAddress,
  base58Encode,
  base58Decode,
  AudrenRelayClient,
  calculateTransferFee,
  compileV1Message,
  serializeV1Transaction,
  AUDREN_PROGRAM_ID,
  SYSTEM_PROGRAM_ID,
  WSOL_MINT,
  AudrenError,
  JUPITER_CPI_EXCLUDED_DEXES,
} from '@audren/sdk';

test('built package imports in ordinary Node and encodes the lane wire contract', () => {
  assert.equal(AUDREN_PROGRAM_ID, 'AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3');
  assert.equal(AudrenError.InvalidLane, 33);
  assert.ok(JUPITER_CPI_EXCLUDED_DEXES.includes('Kipseli'));
  assert.deepEqual([...encodeInitLaneData(15)], [11, 15]);
  assert.deepEqual([...encodeOpenLanePageData(1)], [12, 1]);
  assert.equal(pageIdForLane(15, 7n), 0x0f00000000000007n);
  assert.equal(laneOfPageId(0x0f00000000000007n), 15);
  assert.equal(seqOfPageId(0x0f00000000000007n), 7n);
  assert.throws(() => encodeInitLaneData(16));

  const laneBuf = new Uint8Array(64);
  laneBuf.set(new TextEncoder().encode('AUDRNLN1'), 0);
  laneBuf[8] = 1;
  laneBuf[9] = 3;
  laneBuf[10] = 251;
  laneBuf[11] = 249;
  const dv = new DataView(laneBuf.buffer);
  dv.setUint32(12, 0, true);
  dv.setBigUint64(16, pageIdForLane(3, 7n), true);
  dv.setBigUint64(24, 471_852_922n, true);
  const lane = decodeAppendLaneState(laneBuf);
  assert.equal(lane.laneId, 3);
  assert.equal(lane.currentPageId, pageIdForLane(3, 7n));
  assert.equal(lane.createdSlot, 471_852_922n);
});

test('deriveSubAccountSeed matches RFC 5869 HKDF-SHA256 and Rust from_seed_subaccount', async () => {
  const master = new Uint8Array(32).map((_, i) => i + 1);
  const s0 = await deriveSubAccountSeed(master, 0);
  assert.deepEqual(s0, master);
  assert.notEqual(s0, master);

  const s1 = await deriveSubAccountSeed(master, 1);
  const expected1 = new Uint8Array(
    hkdfSync('sha256', master, Buffer.from('audren/v1/subaccount'), Buffer.from([1, 0, 0, 0]), 32),
  );
  assert.deepEqual(s1, expected1);

  const s2 = await deriveSubAccountSeed(master, 2);
  assert.notDeepEqual(s1, s2);
  await assert.rejects(() => deriveSubAccountSeed(new Uint8Array(31), 1), RangeError);
  await assert.rejects(() => deriveSubAccountSeed(master, -1), RangeError);
});

test('zero-dependency PDA derivations match deployed Solana Mainnet PDAs byte-for-byte', async () => {
  const [pool0, page0, vaultAuth, solVault, escrow0, lane1] = await Promise.all([
    derivePoolPda(0),
    deriveEpochPagePda(0, 0n),
    deriveVaultAuthPda(0),
    deriveSolVaultPda(0),
    deriveSwapEscrowPda(0, 0),
    deriveLanePda(0, 1),
  ]);
  assert.equal(pool0.address, '5Bvt5f5QMfsVb9TyX8bzkRMvAX6JSWwRtnymGveF9U3G');
  assert.equal(page0.address, 'iounHJYNJqhLzSyjcXF5yfyvrVuPgFJ7BwCGqCy1JJg');
  assert.equal(vaultAuth.address, '7rQ6vQNMwBwzAFK1gcwFuJwK4DybLUGVBfxJfgVw8X9o');
  assert.equal(solVault.address, 'EhVt54eHXmWzDqngDiBXhw6ePWa9eEoBAHsMfnNCn5nr');
  assert.equal(escrow0.address, 'AJFrTGiSbJsiXfQA5cZQVF566NEU15yBYzLRTU7J2Hay');
  assert.equal(lane1.addressBytes.byteLength, 32);

  // Base58 roundtrip (including all-zero System Program ID) & ATA derivation
  assert.equal(base58Encode(new Uint8Array(32)), SYSTEM_PROGRAM_ID);
  assert.equal(base58Encode(new Uint8Array([0])), '1');
  assert.equal(base58Decode(SYSTEM_PROGRAM_ID).byteLength, 32);
  assert.equal(base58Encode(base58Decode(AUDREN_PROGRAM_ID)), AUDREN_PROGRAM_ID);
  const escrowWsolAta = await deriveAssociatedTokenAddress(escrow0.address, WSOL_MINT);
  assert.equal(escrowWsolAta.addressBytes.byteLength, 32);
  await assert.rejects(
    () => findProgramAddress(Array.from({ length: 16 }, () => new Uint8Array([1]))),
    RangeError,
  );

  // aud1... address format & RFC 9496 Ristretto255 validation roundtrip
  const sample = 'aud136et2wsvTXKWMrmEQDrG7nRTofxBdSw6ZkwzmUT9vARfpCkY8YR9ENm9QV9WoUW3Nb1tp3BGejPA8BG8PWCWrwFL';
  const parsed = parseAudrenAddress(sample);
  assert.equal(parsed.spendPk.byteLength, 32);
  assert.equal(parsed.viewPk.byteLength, 32);
  assert.equal(isValidRistretto255Point(parsed.spendPk), true);
  assert.equal(isValidRistretto255Point(parsed.viewPk), true);
  assert.equal(formatAudrenAddress(parsed.spendPk, parsed.viewPk), sample);
  assert.equal(parseAudrenAddress(sample.slice(4)).encoded, sample);
  // Reject non-canonical Ristretto255 encoding (odd lowest bit is invalid per RFC 9496 §4.3.1)
  const corrupted = new Uint8Array(64);
  corrupted.set(parsed.spendPk, 0);
  corrupted.set(parsed.viewPk, 32);
  corrupted[0] ^= 1;
  assert.equal(isValidRistretto255Point(corrupted.slice(0, 32)), false);
  assert.throws(() => parseAudrenAddress(`aud1${base58Encode(corrupted)}`));
  assert.throws(() => formatAudrenAddress(new Uint8Array(32), parsed.viewPk));
  assert.throws(() => parseAudrenAddress('invalid'));

  // Relay client URL normalization
  const relay = new AudrenRelayClient('https://relay.audren.xyz///');
  assert.equal(relay.baseUrl, 'https://relay.audren.xyz');
});
test('transfer fee rounding and cap match token fee semantics', () => {
  assert.equal(calculateTransferFee(1n, 1, 100n), 1n);
  assert.equal(calculateTransferFee(10000n, 100, 50n), 50n);
  assert.equal(calculateTransferFee(10000n, 0, 50n), 0n);
});
test('v1 compiler preserves message prefix and rejects invalid signatures', () => {
  const key = n => new Uint8Array(32).fill(n);
  const compiled = compileV1Message({ feePayer: key(1), recentBlockhash: key(2), instructions: [{ programId: key(3), accounts: [], data: new Uint8Array([11, 1]) }], config: { computeUnitLimit: 100000 } });
  assert.equal(compiled.messageBytes[0], 0x81);
  assert.equal(compiled.numRequiredSignatures, 1);
  assert.throws(() => serializeV1Transaction(compiled, []));
  assert.throws(() => serializeV1Transaction(compiled, [new Uint8Array(63)]));
  const wire = serializeV1Transaction(compiled, [new Uint8Array(64)]);
  assert.equal(wire.length, compiled.messageBytes.length + 64);
  assert.deepEqual(wire.subarray(0, compiled.messageBytes.length), compiled.messageBytes);
});
