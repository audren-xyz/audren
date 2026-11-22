import test from 'node:test';
import assert from 'node:assert/strict';

import {
  AUDREN_CODAMA_IDL,
  AUDREN_ANCHOR_IDL,
  AUDREN_PROGRAM_ID,
  CKPT_LEN,
  CKPT_MAGIC,
  CK_OFF_LANE_COUNTS,
  CK_OFF_LANE_ROOTS,
  CK_OFF_MAGIC,
  CK_OFF_SUPER_ROOT,
  CK_OFF_VERSION,
  CompactWalletStore,
  JUPITER_CPI_EXCLUDED_DEXES,
  MEMO_MAGIC,
  MEMO_PAGE_LEN,
  MM_OFF_CIPHERTEXTS,
  MM_OFF_COUNT,
  MM_OFF_EPHEMERAL_PKS,
  MM_OFF_MAGIC,
  MM_OFF_VIEW_TAGS,
  NATIVE_SOL_MINT_BYTES,
  NF_OFF_COUNT,
  NF_OFF_MAGIC,
  NF_OFF_PREFIXES,
  NF_PAGE_LEN,
  NF_PAGE_MAGIC,
  NF_PREFIX_LEN,
  NUM_LANES,
  PROTOCOL_VERSION,
  SB_OFF_COUNT,
  SB_OFF_LEAVES,
  SB_OFF_MAGIC,
  SUBTREE_LEAVES,
  SUBTREE_MAGIC,
  SUBTREE_PAGE_LEN,
  ZERO_HASHES_4ARY,
  buildDepositSolInstruction,
  compileV1Message,
  computeMerkleRoot4Ary,
  computeNoteCommitment,
  computeSubtree256Root,
  computeSuperRoot4Ary,
  decodeRootCheckpoint,
  deriveAssetId,
  deriveKeysFromSeed,
  deriveStealthOwner,
  encryptNoteMemo,
  exportFullViewingKey,
  exportSelectiveDisclosureProof,
  frToBeBytes,
  poseidon4,
  toPubkeyBytes,
  verifySelectiveDisclosureProof,
} from '../dist/index.js';

const enc = new TextEncoder();

test('Package exports, IDLs, Transaction v1 compiler, and CompactWalletStore sealing/freezing', () => {
  assert.equal(AUDREN_CODAMA_IDL.program.publicKey, AUDREN_PROGRAM_ID);
  assert.equal(AUDREN_CODAMA_IDL.program.instructions.length, 9);
  assert.equal(AUDREN_ANCHOR_IDL.instructions.length, 9);
  assert.equal(JUPITER_CPI_EXCLUDED_DEXES.length, 8);

  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x55));
  const fvk = exportFullViewingKey(alice);
  const solAsset = deriveAssetId(NATIVE_SOL_MINT_BYTES);

  // Build a sealed 256-leaf SubtreePage (with Alice's note at slot 7) + MemoPage 0
  const subRaw = new Uint8Array(SUBTREE_PAGE_LEN);
  subRaw.set(enc.encode(SUBTREE_MAGIC), SB_OFF_MAGIC);
  new DataView(subRaw.buffer).setUint16(SB_OFF_COUNT, SUBTREE_LEAVES, true);

  const memoRaw = new Uint8Array(MEMO_PAGE_LEN);
  memoRaw.set(enc.encode(MEMO_MAGIC), MM_OFF_MAGIC);
  new DataView(memoRaw.buffer).setUint16(MM_OFF_COUNT, 112, true);

  const leaves = [];
  for (let i = 0; i < SUBTREE_LEAVES; i++) {
    if (i === 7) {
      const { tweak, blinding, memo90 } = encryptNoteMemo(
        alice.viewPk,
        new Uint8Array(32).fill(0x66),
        2_500_000n,
        NATIVE_SOL_MINT_BYTES,
      );
      const cm = computeNoteCommitment(
        deriveStealthOwner(alice.spendPk, tweak),
        solAsset,
        2_500_000n,
        blinding,
      );
      leaves.push(cm);
      subRaw.set(frToBeBytes(cm), SB_OFF_LEAVES + i * 32);
      memoRaw.set(memo90.subarray(0, 2), MM_OFF_VIEW_TAGS + i * 2);
      memoRaw.set(memo90.subarray(2, 34), MM_OFF_EPHEMERAL_PKS + i * 32);
      memoRaw.set(memo90.subarray(34, 90), MM_OFF_CIPHERTEXTS + i * 56);
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
    memoPages: [{ pageSeq: 0n, raw: memoRaw }],
    nfPages: [],
  });
  assert.equal(discovered, 1);
  assert.equal(store.lanes[1].finalizedSubroots.length, 1);
  assert.equal(store.lanes[1].frontierSubSeq, 1n);
  assert.equal(store.lanes[1].frontierLeaves.length, 0);
  assert.ok(store.notes[0].frozenIntraSiblings, 'sealed page must freeze 12 intra-subtree siblings');

  // Round-trip JSON persistence (IndexedDB / disk)
  const restored = CompactWalletStore.fromJSON(store.toJSON());
  assert.equal(restored.notes.length, 1);
  const note = restored.notes[0];
  assert.equal(note.amount, 2_500_000n);
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

  // NullifierPage ingestion marks note spent locally (0 NullifierPDA RPC lookups!)
  const nfRaw = new Uint8Array(NF_PAGE_LEN);
  nfRaw.set(enc.encode(NF_PAGE_MAGIC), NF_OFF_MAGIC);
  new DataView(nfRaw.buffer).setUint16(NF_OFF_COUNT, 1, true);
  nfRaw.set(note.nullifier.subarray(0, NF_PREFIX_LEN), NF_OFF_PREFIXES);
  restored.ingestLanePages({
    fvk,
    laneId: 1,
    subtreePages: [],
    memoPages: [],
    nfPages: [{ pageSeq: 0n, raw: nfRaw }],
  });
  assert.equal(restored.unspentNotes().length, 0);

  // Transaction v1 (0x81) compilation test
  const depIx = buildDepositSolInstruction({
    depositor: '11111111111111111111111111111111',
    poolId: 0,
    laneId: 0,
    subPageSeq: 0n,
    rootPageSeq: 0n,
    memoPageSeq: 0n,
    amount: 1_000_000n,
    stealthOwner: deriveStealthOwner(alice.spendPk, 1n),
    blinding: 2n,
    memo90: new Uint8Array(90),
  });
  const compiled = compileV1Message({
    feePayer: toPubkeyBytes('11111111111111111111111111111111'),
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
});
