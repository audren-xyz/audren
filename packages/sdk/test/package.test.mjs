import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ASSET_MODE_SOL,
  ASSET_MODE_SPL,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  AUDREN_ANCHOR_IDL,
  AUDREN_CODAMA_IDL,
  AUDREN_PROGRAM_ID,
  AudrenRelayClient,
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
  LANE_MAGIC,
  LANE_STATE_LEN,
  LN_OFF_LANE_ID,
  LN_OFF_MAGIC,
  LN_OFF_NEXT_LEAF,
  LN_OFF_NF_COUNT,
  LN_OFF_VERSION,
  MEMO_MAGIC,
  MEMO_NOTES_PER_PAGE,
  MEMO_PAGE_HEADER_LEN,
  MEMO_PAGE_LEN,
  MEMO_PAGE_SCAN_SLICE_LEN,
  MM_OFF_CIPHERTEXTS,
  MM_OFF_CLOSED_SLOT,
  MM_OFF_COUNT,
  MM_OFF_EPHEMERAL_PKS,
  MM_OFF_LANE_ID,
  MM_OFF_MAGIC,
  MM_OFF_PAGE_SEQ,
  MM_OFF_VIEW_TAGS,
  NATIVE_SOL_MINT_BYTES,
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
  computePageRollovers,
  computeSubtree256Root,
  computeSuperRoot4Ary,
  computeToken2022NetAmount,
  decodeRootCheckpoint,
  deriveAssetId,
  deriveAssociatedTokenAddressSync,
  deriveEscrowPdaSync,
  deriveKeysFromSeed,
  deriveLanePdaSync,
  deriveMemoPdaSync,
  deriveNfPagePdaSync,
  derivePoolPdaSync,
  deriveStealthOwner,
  deriveSubrootPdaSync,
  deriveSubtreePdaSync,
  encryptNoteMemo,
  exportFullViewingKey,
  exportSelectiveDisclosureProof,
  frToBeBytes,
  inspectToken2022UnsafeSelfPay,
  parseToken2022TransferFeeConfig,
  pickRandomEscrowShard,
  pickRandomLaneId,
  poseidon4,
  prepareEscrowAccounts,
  prepareEscrowAccountsForAudren,
  serializeV1Transaction,
  syncCompactStoreWithRpc,
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
  return { ckpt: decodeRootCheckpoint(ckRaw), superRoot };
}

test('2-pass cross-lane nullifier sync discards stranger prefixes & loads legacy seenNfPrefixes JSON', async () => {
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x21));
  const fvk = exportFullViewingKey(alice);
  const solAsset = deriveAssetId(NATIVE_SOL_MINT_BYTES);

  // Note created on Lane 2 (leaf 0), spent on Lane 0 (NullifierPage 0 alongside 50 stranger prefixes).
  // In a naive 1-pass lane loop (0 -> 1 -> 2), Lane 0 nullifiers run BEFORE Lane 2 notes are discovered!
  const { tweak, blinding, memo90 } = encryptNoteMemo(
    alice.viewPk,
    new Uint8Array(32).fill(0x31),
    9_000_000n,
    NATIVE_SOL_MINT_BYTES,
  );
  const cm = computeNoteCommitment(deriveStealthOwner(alice.spendPk, tweak), solAsset, 9_000_000n, blinding);
  const lane2Sub0 = makeSubtreePage(2, 0n, [cm]);
  const lane2Memo0 = makeMemoPageWithMeta(2, 0n, 1);
  writeMemoSlot(lane2Memo0, 0, memo90);

  // Discover note's exact nullifier using a scratch store, then place it into Lane 0's NullifierPage
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
  assert.equal(store.notes[0].spent, true, '2-pass sync must mark Lane 2 note spent via Lane 0 NullifierPage');
  assert.equal(store.unspentNotes().length, 0);
  assert.equal(store.lanes[0].nextNfIndex, BigInt(nfPrefixes.length));

  // Verify ZERO stranger prefixes persisted in toJSON()
  const serialized = store.toJSON();
  const parsed = JSON.parse(serialized);
  assert.equal('seenNfPrefixes' in parsed, false, 'toJSON() must NOT persist seenNfPrefixes');
  assert.equal(serialized.includes('aa00000000'), false, 'stranger prefix bytes must not appear in JSON');

  // Verify backwards-compatible loading of legacy JSON containing seenNfPrefixes
  const legacyObj = JSON.parse(probeStore.toJSON());
  assert.equal(legacyObj.notes[0].spent, false);
  legacyObj.seenNfPrefixes = [
    'deadbeefdeadbeefdeadbeefdeadbeef',
    Array.from(ownNfPrefix, (b) => b.toString(16).padStart(2, '0')).join(''),
  ];
  const migrated = CompactWalletStore.fromJSON(JSON.stringify(legacyObj));
  assert.equal(migrated.notes[0].spent, true, 'legacy seenNfPrefixes must be applied during migration');
  assert.equal('seenNfPrefixes' in JSON.parse(migrated.toJSON()), false);
});

test('Post-seal checkpoint witness building via prevSealedLeaves & automatic pruning', () => {
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x41));
  const fvk = exportFullViewingKey(alice);
  const solAsset = deriveAssetId(NATIVE_SOL_MINT_BYTES);

  // Build 256 leaves in SubtreePage #0 (Alice's note at leaf 200)
  const leaves = [];
  const memo0 = makeMemoPageWithMeta(0, 0n, MEMO_NOTES_PER_PAGE);
  const memo1 = makeMemoPageWithMeta(0, 1n, MEMO_NOTES_PER_PAGE);
  const memo2 = makeMemoPageWithMeta(0, 2n, SUBTREE_LEAVES - 2 * MEMO_NOTES_PER_PAGE);

  for (let i = 0; i < SUBTREE_LEAVES; i++) {
    if (i === 200) {
      const { tweak, blinding, memo90 } = encryptNoteMemo(
        alice.viewPk,
        new Uint8Array(32).fill(0x42),
        7_500_000n,
        NATIVE_SOL_MINT_BYTES,
      );
      const cm = computeNoteCommitment(deriveStealthOwner(alice.spendPk, tweak), solAsset, 7_500_000n, blinding);
      leaves.push(cm);
      writeMemoSlot(memo1, i - MEMO_NOTES_PER_PAGE, memo90);
    } else {
      leaves.push(BigInt(i + 10));
    }
  }
  const sub0 = makeSubtreePage(0, 0n, leaves);

  // Checkpoint published BEFORE page #0 sealed (at leaf count = 250)
  const preSealRoot = computeLaneRootFromLeaves(leaves.slice(0, 250));
  const { ckpt: preSealCkpt, superRoot: preSealSuper } = makeSyntheticCheckpoint(0, preSealRoot, 250n);

  // Store ingests full sealed page #0 (256 leaves) -> frontier advances to seq=1 (empty!),
  // while prevSealedSubSeq=0 retains the 256 leaves for the pre-seal checkpoint!
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

  // Persist & reload JSON -> prevSealedLeaves survives round-trip and builds valid witness at ckptCount=250!
  const reloaded = CompactWalletStore.fromJSON(store.toJSON());
  const note = reloaded.notes[0];
  const { superRoot: sr250, path: path250 } = reloaded.buildWitnessForNote(note, preSealCkpt);
  assert.equal(sr250, preSealSuper);
  assert.equal(computeMerkleRoot4Ary(path250, leaves[200]), preSealSuper);
  assert.equal(reloaded.lanes[0].prevSealedSubSeq, 0n, 'must retain prevSealed until crossed');

  // Once a newer checkpoint crosses page #0 (ckptCount = 256), witness uses frozenIntraSiblings & prunes prevSealedLeaves!
  const postSealRoot = computeLaneRootFromLeaves(leaves);
  const { ckpt: postSealCkpt, superRoot: postSealSuper } = makeSyntheticCheckpoint(0, postSealRoot, 256n);
  const { superRoot: sr256, path: path256 } = reloaded.buildWitnessForNote(note, postSealCkpt);
  assert.equal(sr256, postSealSuper);
  assert.equal(computeMerkleRoot4Ary(path256, leaves[200]), postSealSuper);
  assert.equal(reloaded.lanes[0].prevSealedSubSeq, null, 'prevSealedSubSeq must prune once checkpoint crosses');
  assert.equal(reloaded.lanes[0].prevSealedLeaves.length, 0);
});

test('SubtreeRootPage fast sync + MemoPage SoA dataSlice + birthdaySlot binary search', async () => {
  const alice = deriveKeysFromSeed(new Uint8Array(32).fill(0x91));
  const fvk = exportFullViewingKey(alice);
  const solAsset = deriveAssetId(NATIVE_SOL_MINT_BYTES);

  // Lane 0 has 780 leaves = 3 sealed SubtreePages (0, 1, 2) + 12 frontier leaves in SubtreePage 3.
  // MemoPages: 0..5 (sealed, 112 each, leaves 0..671) + MemoPage 6 (108 leaves, 672..779).
  // Alice owns ONLY 1 note at leaf 700 (SubtreePage 2, MemoPage 6).
  // Sealed SubtreePages 0 and 1 have ZERO owned notes and must NEVER be downloaded!
  const totalLeaves = 780;
  const allLeaves = [];
  const memoPages = new Map();
  const totalMemos = Math.ceil(totalLeaves / MEMO_NOTES_PER_PAGE); // 7 (0..6)
  for (let m = 0; m < totalMemos; m++) {
    const cnt = Math.min(MEMO_NOTES_PER_PAGE, totalLeaves - m * MEMO_NOTES_PER_PAGE);
    // Pages 0..4 sealed before slot 1000 (closedSlot = (m+1)*100); page 5 closedSlot = 1200; page 6 open (0)
    const closedSlot = cnt === MEMO_NOTES_PER_PAGE ? (m < 5 ? BigInt((m + 1) * 100) : 1200n) : 0n;
    memoPages.set(BigInt(m), makeMemoPageWithMeta(0, BigInt(m), cnt, closedSlot));
  }

  for (let i = 0; i < totalLeaves; i++) {
    if (i === 700) {
      const { tweak, blinding, memo90 } = encryptNoteMemo(
        alice.viewPk,
        new Uint8Array(32).fill(0x92),
        12_345_678n,
        NATIVE_SOL_MINT_BYTES,
      );
      const cm = computeNoteCommitment(deriveStealthOwner(alice.spendPk, tweak), solAsset, 12_345_678n, blinding);
      allLeaves.push(cm);
      const mSeq = BigInt(Math.floor(i / MEMO_NOTES_PER_PAGE));
      writeMemoSlot(memoPages.get(mSeq), i % MEMO_NOTES_PER_PAGE, memo90);
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

  const fetchLog = [];
  const sliceAwareFetcher = async (addrs, opts) => {
    fetchLog.push({ addrs: [...addrs], dataSlice: opts?.dataSlice ?? null });
    return addrs.map((a) => {
      const full = accounts.get(a) ?? null;
      if (!full || !opts?.dataSlice) return full;
      return full.slice(opts.dataSlice.offset, opts.dataSlice.offset + opts.dataSlice.length);
    });
  };

  // Run 1: Full sync with dataSlice (no birthdaySlot)
  const storeFull = new CompactWalletStore(0, 0n);
  const rFull = await syncCompactStoreWithRpc({ store: storeFull, fvk, fetchBatch: sliceAwareFetcher });
  assert.equal(rFull.discoveredNotes, 1);
  assert.equal(storeFull.notes[0].leafIndex, 700n);
  assert.equal(storeFull.notes[0].amount, 12_345_678n);
  assert.ok(storeFull.notes[0].frozenIntraSiblings, 'owned note in sealed SubtreePage 2 must freeze siblings');
  assert.equal(storeFull.lanes[0].finalizedSubroots.length, 3);
  assert.equal(storeFull.lanes[0].frontierSubSeq, 3n);
  assert.equal(storeFull.lanes[0].frontierLeaves.length, 12);

  // Verify SubtreePages 0 & 1 were NEVER fetched (SubtreeRootPage fast sync!)
  const allFetchedAddrs = fetchLog.flatMap((e) => e.addrs);
  assert.equal(allFetchedAddrs.includes(deriveSubtreePdaSync(0, 0, 0n).address), false, 'SubtreePage 0 must not be fetched');
  assert.equal(allFetchedAddrs.includes(deriveSubtreePdaSync(0, 0, 1n).address), false, 'SubtreePage 1 must not be fetched');
  assert.equal(allFetchedAddrs.includes(deriveSubtreePdaSync(0, 0, 2n).address), true, 'SubtreePage 2 fetched for owned note');
  assert.equal(allFetchedAddrs.includes(deriveSubtreePdaSync(0, 0, 3n).address), true, 'Frontier SubtreePage 3 fetched');

  // Verify MemoPages were scanned via 3,872 B dataSlice and ONLY MemoPage 6 was fetched in full!
  const memoSliceCalls = fetchLog.filter((e) => e.dataSlice?.length === MEMO_PAGE_SCAN_SLICE_LEN);
  assert.ok(memoSliceCalls.length >= 1, 'MemoPage scan must pass 3,872 B dataSlice');
  const fullMemoCalls = fetchLog.filter(
    (e) => e.dataSlice === null && e.addrs.some((a) => a === deriveMemoPdaSync(0, 0, 6n).address),
  );
  assert.equal(fullMemoCalls.length, 1, 'only view-tag matched MemoPage 6 should be fetched in full');
  assert.equal(
    fullMemoCalls[0].addrs.includes(deriveMemoPdaSync(0, 0, 0n).address),
    false,
    'unmatched MemoPage 0 must never be fetched in full',
  );

  // Verify offline witness against checkpoint at leaf count = 780 passes bit-for-bit!
  const { ckpt, superRoot } = makeSyntheticCheckpoint(0, computeLaneRootFromLeaves(allLeaves), BigInt(totalLeaves));
  const { path } = storeFull.buildWitnessForNote(storeFull.notes[0], ckpt);
  assert.equal(computeMerkleRoot4Ary(path, allLeaves[700]), superRoot);

  // Run 2: birthdaySlot = 1000 skips sealed MemoPages 0..4 via 64 B header binary search, still syncs all 3 SubtreeRoots!
  const bdLog = [];
  const bdFetcher = async (addrs, opts) => {
    bdLog.push({ addrs: [...addrs], dataSlice: opts?.dataSlice ?? null });
    return sliceAwareFetcher(addrs, opts);
  };
  const storeBd = new CompactWalletStore(0, 0n);
  const rBd = await syncCompactStoreWithRpc({
    store: storeBd,
    fvk,
    fetchBatch: bdFetcher,
    birthdaySlot: 1000n,
  });
  assert.equal(rBd.discoveredNotes, 1);
  assert.equal(storeBd.lanes[0].finalizedSubroots.length, 3, 'SubtreeRootPage still synced across all subtrees');
  const headerProbes = bdLog.filter((e) => e.dataSlice?.length === MEMO_PAGE_HEADER_LEN);
  assert.ok(headerProbes.length >= 1, 'birthdaySlot binary search must use 64 B header probes');
  const bdMemoSlices = bdLog
    .filter((e) => e.dataSlice?.length === MEMO_PAGE_SCAN_SLICE_LEN)
    .flatMap((e) => e.addrs);
  assert.equal(bdMemoSlices.includes(deriveMemoPdaSync(0, 0, 0n).address), false, 'pre-birthday MemoPage 0 skipped');
  assert.equal(bdMemoSlices.includes(deriveMemoPdaSync(0, 0, 4n).address), false, 'pre-birthday MemoPage 4 skipped');
  assert.equal(bdMemoSlices.includes(deriveMemoPdaSync(0, 0, 5n).address), true, 'post-birthday MemoPage 5 scanned');
  assert.equal(bdMemoSlices.includes(deriveMemoPdaSync(0, 0, 6n).address), true, 'open MemoPage 6 scanned');
  const { path: pathBd } = storeBd.buildWitnessForNote(storeBd.notes[0], ckpt);
  assert.equal(computeMerkleRoot4Ary(pathBd, allLeaves[700]), superRoot);

  // Run 3: Legacy/mock fetcher that ignores `dataSlice` (always returns full 10,144 B bytes) still works cleanly!
  const fullOnlyCalls = [];
  const legacyFetcher = async (addrs) => {
    fullOnlyCalls.push([...addrs]);
    return addrs.map((a) => accounts.get(a) ?? null);
  };
  const storeLegacy = new CompactWalletStore(0, 0n);
  const rLegacy = await syncCompactStoreWithRpc({ store: storeLegacy, fvk, fetchBatch: legacyFetcher });
  assert.equal(rLegacy.discoveredNotes, 1);
  assert.equal(storeLegacy.notes[0].amount, 12_345_678n);
  // MemoPage 6 should NOT be fetched twice since legacyFetcher already returned full 10,144 B!
  const memo6Count = fullOnlyCalls.flat().filter((a) => a === deriveMemoPdaSync(0, 0, 6n).address).length;
  assert.equal(memo6Count, 1);
});

test('computePageRollovers exact boundaries (110..112, 254..256, 598..600, 76798..76800)', () => {
  // MemoPage boundary (112) with 3 outputs (uniform private transfer)
  assert.deepEqual(
    computePageRollovers({ leafCount: 109, outputCount: 3, nfCount: 0, spentNullifiers: 2 }),
    { outSubSeq: 0, outRootSeq: 0, outMemoSeq: 0, nfPageSeq: 0 },
  );
  assert.deepEqual(
    computePageRollovers({ leafCount: 110, outputCount: 3, nfCount: 0, spentNullifiers: 2 }),
    { outSubSeq: 0, outRootSeq: 0, outMemoSeq: 0, nfPageSeq: 0, nextMemoSeq: 1 },
  );
  assert.deepEqual(
    computePageRollovers({ leafCount: 111, outputCount: 3, nfCount: 0, spentNullifiers: 2 }),
    { outSubSeq: 0, outRootSeq: 0, outMemoSeq: 0, nfPageSeq: 0, nextMemoSeq: 1 },
  );
  assert.deepEqual(
    computePageRollovers({ leafCount: 112, outputCount: 3, nfCount: 0, spentNullifiers: 2 }),
    { outSubSeq: 0, outRootSeq: 0, outMemoSeq: 1, nfPageSeq: 0 },
  );
  // MemoPage boundary with 2 outputs
  assert.deepEqual(
    computePageRollovers({ leafCount: 110, outputCount: 2, nfCount: 0, spentNullifiers: 1 }),
    { outSubSeq: 0, outRootSeq: 0, outMemoSeq: 0, nfPageSeq: 0 },
  );
  assert.deepEqual(
    computePageRollovers({ leafCount: 111, outputCount: 2, nfCount: 0, spentNullifiers: 1 }),
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

  // SubtreeRootPage boundary (300 * 256 = 76,800)
  assert.deepEqual(
    computePageRollovers({ leafCount: 76_799n, outputCount: 2, nfCount: 0n, spentNullifiers: 1 }),
    {
      outSubSeq: 299,
      outRootSeq: 0,
      outMemoSeq: 685,
      nfPageSeq: 0,
      nextSubSeq: 300,
      nextRootSeq: 1,
    },
  );
  assert.deepEqual(
    computePageRollovers({ leafCount: 76_800n, outputCount: 2, nfCount: 0n, spentNullifiers: 1 }),
    { outSubSeq: 300, outRootSeq: 1, outMemoSeq: 685, nfPageSeq: 0 },
  );
});

test('pickRandomLaneId and pickRandomEscrowShard sample uniformly within valid bounds', () => {
  const seenLanes = new Set();
  for (let i = 0; i < 200; i++) {
    const l = pickRandomLaneId(4);
    assert.ok(Number.isInteger(l) && l >= 0 && l < 4);
    seenLanes.add(l);
  }
  assert.equal(seenLanes.size, 4, 'must cover all 4 active lanes across 200 unbiased samples');

  const seenShards = new Set();
  for (let i = 0; i < 400; i++) {
    const s = pickRandomEscrowShard();
    assert.ok(Number.isInteger(s) && s >= 0 && s < NUM_ESCROW_SHARDS);
    seenShards.add(s);
  }
  assert.equal(seenShards.size, NUM_ESCROW_SHARDS, 'must cover all 16 escrow shards');

  assert.equal(pickRandomLaneId(1), 0);
  assert.equal(pickRandomEscrowShard(1), 0);
  assert.throws(() => pickRandomLaneId(0), RangeError);
  assert.throws(() => pickRandomLaneId(17), RangeError);
  assert.throws(() => pickRandomEscrowShard(0), RangeError);
  assert.throws(() => pickRandomEscrowShard(17), RangeError);
});

test('AudrenRelayClient.getFeeQuote omits amount on transfer & requestCheckpoint calls POST /v1/checkpoint', async () => {
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
    return new Response(
      JSON.stringify({
        ok: true,
        cluster: 'mainnet',
        op: 'transfer',
        billingMode: 'self_paying',
        feeSide: 'shielded_cm2',
        feeMint: SYSTEM_PROGRAM_ID,
        feeTokenProgram: null,
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
    // Even if a caller supplies `amount`, op='transfer' MUST omit `amount` from the URL query!
    await client.getFeeQuote({
      cluster: 'mainnet',
      op: 'transfer',
      mint: SYSTEM_PROGRAM_ID,
      amount: '999999999',
      outputCount: 3,
      omitNf1: false,
    });
    const transferUrl = new URL(calls[0].url);
    assert.equal(transferUrl.pathname, '/v1/fee-quote');
    assert.equal(transferUrl.searchParams.get('op'), 'transfer');
    assert.equal(transferUrl.searchParams.has('amount'), false, 'transfer fee-quote must NEVER send amount');
    assert.equal(transferUrl.searchParams.get('omitNf1'), 'false');
    assert.equal(transferUrl.searchParams.get('outputCount'), '3');

    // op='withdraw' includes amount & omitNf1
    await client.getFeeQuote({
      op: 'withdraw',
      mint: SYSTEM_PROGRAM_ID,
      amount: '50000000',
      omitNf1: true,
    });
    const withdrawUrl = new URL(calls[1].url);
    assert.equal(withdrawUrl.searchParams.get('amount'), '50000000');
    assert.equal(withdrawUrl.searchParams.get('omitNf1'), 'true');

    // requestCheckpoint -> POST /v1/checkpoint
    const ckRes = await client.requestCheckpoint({ cluster: 'devnet', poolId: 0 });
    assert.equal(ckRes.status, 'published');
    assert.equal(ckRes.signature, 'sig123');
    assert.equal(calls[2].url, 'https://relay.example.test/v1/checkpoint');
    assert.equal(calls[2].init.method, 'POST');
    assert.deepEqual(JSON.parse(calls[2].init.body), { cluster: 'devnet', poolId: 0 });
  } finally {
    globalThis.fetch = origFetch;
  }
});
