import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pageIdForLane, laneOfPageId, seqOfPageId, encodeInitLaneData, encodeOpenLanePageData, calculateTransferFee, compileV1Message, serializeV1Transaction, AUDREN_PROGRAM_ID } from '@audren/sdk';

test('built package imports in ordinary Node and encodes the lane wire contract', () => {
  assert.equal(AUDREN_PROGRAM_ID, 'AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3');
  assert.deepEqual([...encodeInitLaneData(15)], [11, 15]);
  assert.deepEqual([...encodeOpenLanePageData(1)], [12, 1]);
  assert.equal(pageIdForLane(15, 7n), 0x0f00000000000007n);
  assert.equal(laneOfPageId(0x0f00000000000007n), 15);
  assert.equal(seqOfPageId(0x0f00000000000007n), 7n);
  assert.throws(() => encodeInitLaneData(16));
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
