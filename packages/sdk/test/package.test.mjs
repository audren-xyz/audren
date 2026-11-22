import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ASSET_MODE_SOL,
  ASSET_MODE_SPL,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  AUDREN_ANCHOR_IDL,
  AUDREN_CODAMA_IDL,
  AUDREN_PROGRAM_ID,
  CKPT_LEN,
  CKPT_MAGIC,
  CK_OFF_LANE_COUNTS,
  CK_OFF_LANE_ROOTS,
  CK_OFF_MAGIC,
  CK_OFF_SUPER_ROOT,
  CK_OFF_VERSION,
  CLASSIC_TOKEN_PROGRAM_ID,
  CompactWalletStore,
  EXEC_KIND_SPL,
  JUPITER_CPI_EXCLUDED_DEXES,
  MEMO_MAGIC,
  MEMO_NOTES_PER_PAGE,
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
  OPEN_PAGE_KIND_SUBTREE,
  PROTOCOL_VERSION,
  SB_OFF_COUNT,
  SB_OFF_LEAVES,
  SB_OFF_MAGIC,
  SUBTREE_LEAVES,
  SUBTREE_MAGIC,
  SUBTREE_PAGE_LEN,
  SYSTEM_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  WSOL_MINT,
  ZERO_HASHES_4ARY,
  base58Encode,
  buildCreateAtaIdempotentInstruction,
  buildDepositSolInstruction,
  buildDepositSplInstruction,
  buildExecViaEscrowInstruction,
  buildInitLaneInstruction,
  buildInitPoolInstruction,
  buildJoinsplitInstruction,
  buildOpenPageInstruction,
  buildPublishCheckpointInstruction,
  buildSetPausedInstruction,
  compileV1Message,
  computeExecCtxHash,
  computeMerkleRoot4Ary,
  computeNoteCommitment,
  computeSubtree256Root,
  computeSuperRoot4Ary,
  computeToken2022NetAmount,
  decodeRootCheckpoint,
  deriveAssetId,
  deriveAssociatedTokenAddressSync,
  deriveEscrowPdaSync,
  deriveKeysFromSeed,
  deriveStealthOwner,
  encryptNoteMemo,
  exportFullViewingKey,
  exportSelectiveDisclosureProof,
  frToBeBytes,
  inspectToken2022UnsafeSelfPay,
  parseToken2022TransferFeeConfig,
  poseidon4,
  prepareEscrowAccounts,
  prepareEscrowAccountsForAudren,
  serializeV1Transaction,
  toPubkeyBytes,
  verifySelectiveDisclosureProof,
} from '../dist/index.js';
import { AudrenWasmProver } from '../dist/prover-entry.js';

const enc = new TextEncoder();

function makeMemoPage(count) {
  const buf = new Uint8Array(MEMO_PAGE_LEN);
  buf.set(enc.encode(MEMO_MAGIC), MM_OFF_MAGIC);
  new DataView(buf.buffer).setUint16(MM_OFF_COUNT, count, true);
  return buf;
}

function writeMemoSlot(memoRaw, slot, memo90) {
  memoRaw.set(memo90.subarray(0, 2), MM_OFF_VIEW_TAGS + slot * 2);
  memoRaw.set(memo90.subarray(2, 34), MM_OFF_EPHEMERAL_PKS + slot * 32);
  memoRaw.set(memo90.subarray(34, 90), MM_OFF_CIPHERTEXTS + slot * 56);
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

test('Package exports, IDLs, Transaction v1 compiler, and CompactWalletStore sealing/freezing', () => {
  assert.equal(AUDREN_CODAMA_IDL.program.publicKey, AUDREN_PROGRAM_ID);
  assert.equal(AUDREN_CODAMA_IDL.program.instructions.length, 9);
  assert.equal(AUDREN_ANCHOR_IDL.instructions.length, 9);
  assert.equal(JUPITER_CPI_EXCLUDED_DEXES.length, 8);

  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x55));
  const fvk = exportFullViewingKey(alice);
  const solAsset = deriveAssetId(NATIVE_SOL_MINT_BYTES);

  // Build a sealed 256-leaf SubtreePage (with Alice's note at slot 7) + all 3 MemoPages (256 slots)
  const subRaw = new Uint8Array(SUBTREE_PAGE_LEN);
  subRaw.set(enc.encode(SUBTREE_MAGIC), SB_OFF_MAGIC);
  new DataView(subRaw.buffer).setUint16(SB_OFF_COUNT, SUBTREE_LEAVES, true);

  const memo0 = makeMemoPage(MEMO_NOTES_PER_PAGE); // 0..111
  const memo1 = makeMemoPage(MEMO_NOTES_PER_PAGE); // 112..223
  const memo2 = makeMemoPage(SUBTREE_LEAVES - 2 * MEMO_NOTES_PER_PAGE); // 224..255 (32)

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
      writeMemoSlot(memo0, i, memo90);
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

  // Transaction v1 (0x81) compilation + wire serialization test
  const depIx = buildDepositSolInstruction({
    depositor: SYSTEM_PROGRAM_ID,
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
  const solAsset = deriveAssetId(NATIVE_SOL_MINT_BYTES);

  const subRaw = new Uint8Array(SUBTREE_PAGE_LEN);
  subRaw.set(enc.encode(SUBTREE_MAGIC), SB_OFF_MAGIC);
  new DataView(subRaw.buffer).setUint16(SB_OFF_COUNT, SUBTREE_LEAVES, true);

  const memo0 = makeMemoPage(MEMO_NOTES_PER_PAGE); // 0..111
  const memo1 = makeMemoPage(MEMO_NOTES_PER_PAGE); // 112..223
  const memo2 = makeMemoPage(SUBTREE_LEAVES - 2 * MEMO_NOTES_PER_PAGE); // 224..255

  for (let i = 0; i < SUBTREE_LEAVES; i++) {
    if (i === 150) {
      const { tweak, blinding, memo90 } = encryptNoteMemo(
        alice.viewPk,
        new Uint8Array(32).fill(0x88),
        5_000_000n,
        NATIVE_SOL_MINT_BYTES,
      );
      const cm = computeNoteCommitment(
        deriveStealthOwner(alice.spendPk, tweak),
        solAsset,
        5_000_000n,
        blinding,
      );
      subRaw.set(frToBeBytes(cm), SB_OFF_LEAVES + i * 32);
      writeMemoSlot(memo1, i - MEMO_NOTES_PER_PAGE, memo90);
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
  assert.equal(store.lanes[0].nextMemoLeaf, 112n);
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
  assert.equal(store.lanes[0].nextMemoLeaf, 224n);
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

test('ExecViaEscrow Solana transaction-wide writability promotion & instruction builders', async () => {
  const usdcMint = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
  const payer = base58Encode(new Uint8Array(32).fill(0x11));
  const extraPool = base58Encode(new Uint8Array(32).fill(0x22));
  const readonlyAcc = base58Encode(new Uint8Array(32).fill(0x33));
  const routerProg = base58Encode(new Uint8Array(32).fill(0x44));
  const escrowPda = deriveEscrowPdaSync(0, 0).address;
  const escrowInAta = deriveAssociatedTokenAddressSync(escrowPda, usdcMint, CLASSIC_TOKEN_PROGRAM_ID).address;
  const escrowOutAta = deriveAssociatedTokenAddressSync(escrowPda, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address;

  // Simulate live Mainnet Jupiter ZeroFi returning escrowPda as isSigner:true, isWritable:false
  // plus a duplicate pubkey appearing readonly once and writable once.
  const rawRouterAccs = [
    { pubkey: escrowPda, isSigner: true, isWritable: false },
    { pubkey: escrowInAta, isSigner: false, isWritable: false },
    { pubkey: escrowOutAta, isSigner: false, isWritable: true },
    { pubkey: extraPool, isSigner: false, isWritable: false },
    { pubkey: extraPool, isSigner: false, isWritable: true },
    { pubkey: readonlyAcc, isSigner: false, isWritable: false },
  ];

  const normalized = prepareEscrowAccountsForAudren(rawRouterAccs, escrowPda, [payer, escrowInAta]);
  assert.equal(normalized[0].isSigner, false, 'escrow signer bit must be stripped');
  assert.equal(normalized[0].isWritable, true, 'escrow must be promoted writable');
  assert.equal(normalized[1].isWritable, true, 'extraWritablePubkeys must promote escrowInAta');
  assert.equal(normalized[3].isWritable, true, 'duplicate writable pubkey must promote readonly copy');
  assert.equal(normalized[5].isWritable, false, 'unrelated readonly account stays readonly');

  const prepared = await prepareEscrowAccounts({
    poolId: 0,
    shardId: 0,
    inputMint: usdcMint,
    outputMint: WSOL_MINT,
    actionAccounts: rawRouterAccs,
    extraWritablePubkeys: [payer],
  });
  assert.equal(prepared.accounts[0].isWritable, true);
  assert.equal(prepared.accounts[1].isWritable, true);

  // computeExecCtxHash with unnormalized routerAccounts matches normalized hash bit-for-bit!
  const ctxArgs = {
    poolId: 0,
    outLaneId: 0,
    escrowShard: 0,
    changeMask: 0,
    inKind: EXEC_KIND_SPL,
    outKind: EXEC_KIND_SPL,
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
    dynMask56: new Uint8Array(56).fill(6),
    routerIxData: new Uint8Array([9, 8, 7]),
    changeMemos: new Uint8Array(0),
  };
  const hRaw = computeExecCtxHash({ ...ctxArgs, routerAccounts: rawRouterAccs });
  const hNorm = computeExecCtxHash({ ...ctxArgs, routerAccounts: prepared.accounts });
  assert.equal(hRaw, hNorm, 'computeExecCtxHash must normalize Solana tx-wide writability');

  // buildExecViaEscrowInstruction also normalizes trailing router accounts
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
    inKind: EXEC_KIND_SPL,
    outKind: EXEC_KIND_SPL,
    feeOnOutput: true,
    inSpl: { mint: usdcMint, vaultAta: readonlyAcc, escrowAta: escrowInAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    outSpl: { mint: WSOL_MINT, vaultAta: readonlyAcc, escrowAta: escrowOutAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
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
    dynMask56: new Uint8Array(56).fill(6),
    routerProg,
    routerIxData: new Uint8Array([9, 8, 7]),
    routerAccounts: rawRouterAccs,
    changeMemos: new Uint8Array(0),
  });
  const trailing = execIx.accounts.slice(-rawRouterAccs.length);
  assert.equal(trailing[0].isSigner, false);
  assert.equal(trailing[0].isWritable, true);
  assert.equal(trailing[1].isWritable, true);
  assert.equal(trailing[3].isWritable, true);

  // Smoke-test remaining instruction builders & CreateAtaIdempotent
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

  assert.equal(buildInitPoolInstruction({ payer, poolId: 0, ckptInterval: 8n, maxCkptAge: 1536n, noteRentFee: 100n, nfRentFee: 50n }).data[0], 0);
  assert.equal(buildInitLaneInstruction({ authority: payer, poolId: 0, laneId: 0 }).data[0], 1);
  assert.equal(buildOpenPageInstruction({ payer, pageKind: OPEN_PAGE_KIND_SUBTREE, poolId: 0, laneId: 0, pageSeq: 1n }).data[0], 2);
  assert.equal(buildDepositSplInstruction({ depositor: payer, poolId: 0, mint: usdcMint, depositorAta: escrowInAta, vaultAta: escrowOutAta, tokenProgram: TOKEN_2022_PROGRAM_ID, laneId: 0, subPageSeq: 0n, rootPageSeq: 0n, memoPageSeq: 0n, amount: 1000n, stealthOwner: 1n, blinding: 2n, memo90: new Uint8Array(90) }).data[0], 4);
  assert.equal(buildPublishCheckpointInstruction({ payer, poolId: 0, slotIdx: 0, activeLanes: 4 }).data[0], 5);
  assert.equal(buildSetPausedInstruction({ authority: payer, poolId: 0, paused: true }).data[0], 8);
  assert.throws(
    () =>
      buildJoinsplitInstruction({
        payer,
        poolId: 0,
        ckptSlotIdx: 0,
        outLaneId: 0,
        outSubSeq: 0n,
        outRootSeq: 0n,
        outMemoSeq: 0n,
        outNfSeq: 0n,
        outputMask: 0,
        assetMode: ASSET_MODE_SOL,
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
  assert.throws(
    () =>
      buildJoinsplitInstruction({
        payer,
        poolId: 0,
        ckptSlotIdx: 0,
        outLaneId: 0,
        outSubSeq: 0n,
        outRootSeq: 0n,
        outMemoSeq: 0n,
        outNfSeq: 0n,
        outputMask: 0,
        assetMode: ASSET_MODE_SPL,
        splWithdrawAccs: { mint: usdcMint, vaultAta: escrowInAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
        proof192: new Uint8Array(192),
        nf0: new Uint8Array(31), // invalid length
        nf1: new Uint8Array(32),
        cm0: new Uint8Array(32),
        cm1: new Uint8Array(32),
        cm2: new Uint8Array(32),
        publicAmountOut: 100n,
        relayerFeeAmount: 0n,
        recipient: payer,
        memosBytes: new Uint8Array(0),
      }),
    /nf0 must be 32 bytes/,
  );
});

test('Token-2022 epoch-aware TransferFeeConfig parser, net calculation & self-pay safety inspector', () => {
  // Epoch 100 -> older (100 bps, max 5000); Epoch 200 -> newer (250 bps, max 10_000)
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
  assert.equal(computeToken2022NetAmount(10_001n, feeAt150), 9_900n); // ceil(10001 * 100 / 10000) = 101
  assert.equal(computeToken2022NetAmount(1_000_000n, feeAt150), 995_000n); // capped at maxFee=5000

  const feeAt200 = parseToken2022TransferFeeConfig(mintFee, 200n);
  assert.deepEqual(feeAt200, { bps: 250n, maxFee: 10_000n, epoch: 200n });
  assert.equal(computeToken2022NetAmount(100_000n, feeAt200), 97_500n);
  assert.equal(inspectToken2022UnsafeSelfPay(mintFee), false);

  // Zero-bps active schedule returns null
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

  // High transfer fee (> 500 bps), PermanentDelegate (12), NonTransferable (9), active TransferHook (14)
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
