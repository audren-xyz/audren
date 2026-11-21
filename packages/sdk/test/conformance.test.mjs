import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import * as core from '../dist/index.js';
import * as prover from '../dist/prover-entry.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(resolve(__dirname, '../../../spec/test-vectors.json'), 'utf8'),
);

function hexToBytes(hex) {
  return prover.fromHex(hex);
}

function bytesToHex(bytes) {
  return prover.toHex(bytes);
}

test('1. keys: master keys, sub-accounts, FVK, addresses & asset generators match Rust byte-for-byte', async () => {
  assert.equal(core.AUDREN_PROGRAM_ID, vectors.program_id);
  assert.equal(prover.AUDREN_PROGRAM_ID_STR, vectors.program_id);

  const aliceSeed = hexToBytes(vectors.alice.seed_hex);
  const alice = await prover.deriveKeysFromSeed(aliceSeed);
  assert.equal(bytesToHex(prover.scalarToBytes32LE(alice.spendSk)), vectors.alice.spend_sk_hex);
  assert.equal(bytesToHex(alice.spendPk), vectors.alice.spend_pk_hex);
  assert.equal(bytesToHex(prover.scalarToBytes32LE(alice.viewSk)), vectors.alice.view_sk_hex);
  assert.equal(bytesToHex(alice.viewPk), vectors.alice.view_pk_hex);
  assert.equal(alice.address, vectors.alice.address);

  const parsed = core.parseAudrenAddress(alice.address);
  assert.equal(bytesToHex(parsed.spendPk), vectors.alice.spend_pk_hex);
  assert.equal(bytesToHex(parsed.viewPk), vectors.alice.view_pk_hex);
  assert.equal(core.formatAudrenAddress(parsed.spendPk, parsed.viewPk), vectors.alice.address);

  const fvk = prover.exportFullViewingKey(alice);
  const expectedFvk = JSON.parse(vectors.alice.full_viewing_key_json);
  assert.equal(fvk.version, expectedFvk.version);
  assert.equal(fvk.spendPkB58, expectedFvk.spend_pk_b58);
  assert.equal(fvk.viewSkB58, expectedFvk.view_sk_b58);
  assert.equal(fvk.viewPkB58, expectedFvk.view_pk_b58);

  for (const sub of vectors.alice_subaccounts) {
    const derived = await prover.deriveSubaccountKeys(aliceSeed, sub.account_index);
    assert.equal(bytesToHex(prover.scalarToBytes32LE(derived.spendSk)), sub.spend_sk_hex);
    assert.equal(bytesToHex(derived.spendPk), sub.spend_pk_hex);
    assert.equal(bytesToHex(prover.scalarToBytes32LE(derived.viewSk)), sub.view_sk_hex);
    assert.equal(bytesToHex(derived.viewPk), sub.view_pk_hex);
    assert.equal(derived.address, sub.address);
  }

  for (const sess of vectors.alice_defi_sessions) {
    const seedOnly = await core.deriveDefiSessionSeed(aliceSeed, sess.session_index);
    assert.equal(bytesToHex(seedOnly), sess.secret_seed_hex);
    const derived = await prover.deriveDefiSessionKeypair(aliceSeed, sess.session_index);
    assert.equal(bytesToHex(derived.secretSeed), sess.secret_seed_hex);
    assert.equal(bytesToHex(derived.pubkey), sess.pubkey_hex);
    assert.equal(derived.address, sess.address);
  }

  const solGen = await prover.assetGenerator(prover.NATIVE_SOL_MINT);
  assert.equal(bytesToHex(solGen), vectors.asset_generators.native_sol_gen_hex);

  const wsolGen = await prover.assetGenerator(prover.WSOL_MINT);
  assert.equal(bytesToHex(wsolGen), vectors.asset_generators.wsol_gen_hex);

  const usdcGen = await prover.assetGenerator(
    core.base58Decode(vectors.asset_generators.usdc_mint_b58),
  );
  assert.equal(bytesToHex(usdcGen), vectors.asset_generators.usdc_gen_hex);
});

test('2. pdas & layouts: all 11 Pool #0 PDAs, PoolState and EpochPageHeader match Rust byte-for-byte', async () => {
  const p = vectors.pdas;
  const pool = await core.derivePoolPda(p.pool_id);
  assert.equal(pool.address, p.pool.address);
  assert.equal(pool.bump, p.pool.bump);

  const page0 = await core.deriveEpochPagePda(p.pool_id, 0n);
  assert.equal(page0.address, p.epoch_page_0.address);
  assert.equal(page0.bump, p.epoch_page_0.bump);

  const pageL1 = await core.deriveEpochPagePda(p.pool_id, core.pageIdForLane(1, 0n));
  assert.equal(pageL1.address, p.epoch_page_lane1_seq0.address);
  assert.equal(pageL1.bump, p.epoch_page_lane1_seq0.bump);

  const solVault = await core.deriveSolVaultPda(p.pool_id);
  assert.equal(solVault.address, p.sol_vault.address);
  assert.equal(solVault.bump, p.sol_vault.bump);

  const vaultAuth = await core.deriveVaultAuthPda(p.pool_id);
  assert.equal(vaultAuth.address, p.vault_auth.address);
  assert.equal(vaultAuth.bump, p.vault_auth.bump);

  const rentVault = await core.derivePageRentVaultPda(p.pool_id);
  assert.equal(rentVault.address, p.page_rent_vault.address);
  assert.equal(rentVault.bump, p.page_rent_vault.bump);

  const escrow0 = await core.deriveEscrowPda(p.pool_id, 0);
  assert.equal(escrow0.address, p.escrow_0.address);
  assert.equal(escrow0.bump, p.escrow_0.bump);

  const unwrapPda = await core.deriveUnwrapPda(
    p.pool_id,
    hexToBytes(vectors.epoch_page.alice_note.nullifier_hex),
  );
  assert.equal(unwrapPda.address, p.unwrap_pda.address);
  assert.equal(unwrapPda.bump, p.unwrap_pda.bump);

  const lane1 = await core.deriveLanePda(p.pool_id, 1);
  assert.equal(lane1.address, p.lane_1.address);
  assert.equal(lane1.bump, p.lane_1.bump);

  const lane1Rent = await core.deriveLaneRentVaultPda(p.pool_id, 1);
  assert.equal(lane1Rent.address, p.lane_rent_vault_1.address);
  assert.equal(lane1Rent.bump, p.lane_rent_vault_1.bump);

  const proofBuf = await core.deriveProofBufferPda(
    p.proof_buffer_authority,
    BigInt(p.proof_buffer_nonce),
  );
  assert.equal(proofBuf.address, p.proof_buffer.address);
  assert.equal(proofBuf.bump, p.proof_buffer.bump);

  const nullifierPda = await core.deriveNullifierPda(
    p.pool_id,
    hexToBytes(vectors.epoch_page.alice_note.nullifier_hex),
  );
  assert.equal(nullifierPda.address, p.nullifier_pda.address);
  assert.equal(nullifierPda.bump, p.nullifier_pda.bump);

  // PoolState binary decoding
  const ps = core.decodePoolState(hexToBytes(vectors.pool_state.raw_hex));
  assert.equal(ps.version, vectors.pool_state.version);
  assert.equal(ps.bump, vectors.pool_state.bump);
  assert.equal(ps.mode, vectors.pool_state.mode);
  assert.equal(ps.paused, vectors.pool_state.paused);
  assert.equal(ps.poolId, vectors.pool_state.pool_id);
  assert.equal(ps.currentPageId, BigInt(vectors.pool_state.current_page_id));
  assert.equal(ps.totalNotes, BigInt(vectors.pool_state.total_notes));
  assert.equal(ps.totalSpends, BigInt(vectors.pool_state.total_spends));
  assert.equal(ps.pageRentFeeLamports, BigInt(vectors.pool_state.page_rent_fee_lamports));
  assert.equal(core.base58Encode(ps.authority), vectors.pool_state.authority);
  assert.equal(ps.activeLanes, vectors.pool_state.active_lanes);
});

test('3. scanner: dataSlice view-tag filter & note decryption match Rust byte-for-byte', async () => {
  assert.equal(core.PAGE_SCAN_OFFSET, vectors.epoch_page.scan_offset);
  assert.equal(core.PAGE_SCAN_LEN, vectors.epoch_page.scan_length);

  const alice = await prover.deriveKeysFromSeed(hexToBytes(vectors.alice.seed_hex));
  const pageBytes = hexToBytes(vectors.epoch_page.page_hex);
  const sliceBytes = hexToBytes(vectors.epoch_page.scan_slice_hex);

  const hdr = core.decodePageHeader(pageBytes);
  assert.equal(hdr.version, vectors.epoch_page.version);
  assert.equal(hdr.bump, vectors.epoch_page.bump);
  assert.equal(hdr.closed, vectors.epoch_page.closed);
  assert.equal(hdr.count, vectors.epoch_page.count);
  assert.equal(hdr.poolId, vectors.epoch_page.pool_id);
  assert.equal(hdr.pageId, BigInt(vectors.epoch_page.page_id));
  assert.equal(hdr.createdSlot, BigInt(vectors.epoch_page.created_slot));
  assert.equal(hdr.closedSlot, BigInt(vectors.epoch_page.closed_slot));

  const hits = await prover.scanPageScanSlice(alice, sliceBytes);
  assert.deepEqual(hits, vectors.epoch_page.matched_slots);

  // Read-only FullViewingKeyExport works directly in BOTH scanPageScanSlice AND scanEpochPage,
  // AND corrupted decoy slots never blind subsequent slots!
  const fvk = prover.exportFullViewingKey(alice);
  assert.deepEqual(await prover.scanPageScanSlice(fvk, sliceBytes), vectors.epoch_page.matched_slots);
  const poisonedPage = new Uint8Array(pageBytes);
  poisonedPage.fill(0xff, 96, 128);
  const fvkOwned = await prover.scanEpochPage(fvk, poisonedPage, vectors.epoch_page.pool_id);
  assert.equal(fvkOwned.length, 1);
  assert.equal(fvkOwned[0].slotIndex, vectors.epoch_page.alice_note.slot_index);
  assert.equal(fvkOwned[0].amount, BigInt(vectors.epoch_page.alice_note.amount));
  assert.equal(fvkOwned[0].nullifier, undefined);

  const owned = await prover.scanEpochPageSpendable(alice, pageBytes, vectors.epoch_page.pool_id);
  assert.equal(owned.length, 1);
  const note = owned[0];
  const exp = vectors.epoch_page.alice_note;
  assert.equal(note.slotIndex, exp.slot_index);
  assert.equal(note.amount, BigInt(exp.amount));
  assert.equal(bytesToHex(note.mint), exp.mint_hex);
  assert.equal(bytesToHex(note.stealthPk), exp.stealth_pk_hex);
  assert.equal(bytesToHex(note.assetTag), exp.asset_tag_hex);
  assert.equal(bytesToHex(note.commitment), exp.commitment_hex);
  assert.equal(bytesToHex(prover.scalarToBytes32LE(note.assetBlinding)), exp.asset_blinding_hex);
  assert.equal(bytesToHex(prover.scalarToBytes32LE(note.valueBlinding)), exp.value_blinding_hex);
  assert.equal(bytesToHex(prover.scalarToBytes32LE(note.stealthScalar)), exp.stealth_scalar_hex);
  assert.equal(bytesToHex(prover.scalarToBytes32LE(note.spendX)), exp.spend_x_hex);
  assert.equal(bytesToHex(note.nullifier), exp.nullifier_hex);
  assert.equal(note.nullifierPdaB58, exp.nullifier_pda);
});

test('4. prover: exact wire lengths & accounts for Deposit, Transfer, Merge, ProofBuffer, Close & Withdraw', async () => {
  const alice = await prover.deriveKeysFromSeed(hexToBytes(vectors.alice.seed_hex));
  const payer = core.base58Decode(vectors.pdas.proof_buffer_authority);
  const pageBytes = hexToBytes(vectors.epoch_page.page_hex);

  // Token-2022 ceiling fee parity (including maxFee=0 guard)
  assert.equal(prover.netDepositAmount(1_000_000n, 250, 10_000n), 990_000n);
  assert.equal(prover.netDepositAmount(1_000_000n, 250, 0n), 1_000_000n);

  // Builders accept aud1... strings directly without separate parseAudrenAddress aliasing!
  const { instructions: depIxs, note: depNote } = await prover.buildDepositInstruction({
    depositor: payer,
    poolId: 0,
    activePageId: 1n,
    recipient: vectors.bob.address,
    mint: prover.NATIVE_SOL_MINT,
    amount: 500_000n,
  });
  assert.equal(depIxs.length, 1);
  assert.equal(depIxs[0].data[0], core.TAG_DEPOSIT);
  assert.equal(depIxs[0].data.length, 139);
  assert.equal(depIxs[0].accounts.length, 6);
  assert.equal(depNote.amount, 500_000n);

  const [ownedNote] = await prover.scanEpochPageSpendable(alice, pageBytes, 0);
  const ring = prover.extractRingFromPage(pageBytes);
  assert.equal(ring.length, 32);

  const { instruction: xferIx, payNote, changeNote, nullifier } =
    await prover.buildTransferInstruction({
      payer,
      poolId: 0,
      outPageId: 1n,
      inputPageIds: [0n],
      ring,
      inputNote: ownedNote,
      secretIndex: vectors.epoch_page.alice_note.slot_index,
      recipient: vectors.bob.address,
      changeAddr: vectors.alice.address,
      payAmount: 900_000n,
    });
  assert.equal(xferIx.data[0], core.TAG_TRANSFER);
  assert.equal(xferIx.data.length, 2_373);
  assert.equal(xferIx.accounts.length, 8);
  assert.equal(payNote.amount, 900_000n);
  assert.equal(changeNote.amount, 600_000n);
  assert.equal(bytesToHex(nullifier), vectors.epoch_page.alice_note.nullifier_hex);

  // Merge two distinct Bob SOL notes + assert self-merge rejection!
  const bob = await prover.deriveKeysFromSeed(hexToBytes(vectors.bob.seed_hex));
  const bobSolNotes = (await prover.scanEpochPageSpendable(bob, pageBytes, 0)).filter(
    (n) => n.isNativeSol,
  );
  assert.ok(bobSolNotes.length >= 2);
  await assert.rejects(
    prover.buildMergeInstruction({
      payer,
      poolId: 0,
      outPageId: 1n,
      input1PageIds: [0n],
      ring1: ring,
      note1: ownedNote,
      secretIndex1: vectors.epoch_page.alice_note.slot_index,
      input2PageIds: [0n],
      ring2: ring,
      note2: ownedNote,
      secretIndex2: vectors.epoch_page.alice_note.slot_index,
      ownerAddr: vectors.alice.address,
    }),
  );
  const { instruction: mergeIx } = await prover.buildMergeInstruction({
    payer,
    poolId: 0,
    outPageId: 1n,
    input1PageIds: [0n],
    ring1: ring,
    note1: bobSolNotes[0],
    secretIndex1: bobSolNotes[0].slotIndex,
    input2PageIds: [0n],
    ring2: ring,
    note2: bobSolNotes[1],
    secretIndex2: bobSolNotes[1].slotIndex,
    ownerAddr: vectors.bob.address,
  });
  assert.equal(mergeIx.data[0], core.TAG_MERGE);
  assert.equal(mergeIx.data.length, 2_950);
  assert.equal(mergeIx.accounts.length, 10);

  const bufPlan = await prover.buildBufferedExecutionPlan(xferIx, 42n);
  assert.equal(bufPlan.uploadChunks.length, 4);
  assert.deepEqual(Array.from(bufPlan.executeIx.data), [core.TAG_EXEC_BUFFERED, core.TAG_TRANSFER]);
  assert.equal(core.base58Encode(bufPlan.proofBufferPda), vectors.pdas.proof_buffer.address);

  const closeIx = prover.buildCloseProofBufferInstruction({
    payer,
    proofBufferPda: bufPlan.proofBufferPda,
  });
  assert.deepEqual(Array.from(closeIx.data), [core.TAG_CLOSE_PROOF_BUFFER]);
  assert.equal(closeIx.accounts.length, 2);

  const { instruction: wdIx, changeNote: wdChg } = await prover.buildWithdrawInstruction({
    payer,
    poolId: 0,
    outPageId: 1n,
    inputPageIds: [0n],
    ring,
    inputNote: ownedNote,
    secretIndex: vectors.epoch_page.alice_note.slot_index,
    recipientAccount: payer,
    changeAddr: vectors.alice.address,
    amount: 1_000_000n,
  });
  assert.equal(wdIx.data[0], core.TAG_WITHDRAW);
  assert.equal(wdIx.data.length, 1_973);
  assert.equal(wdIx.accounts.length, 11);
  assert.equal(wdChg.amount, 500_000n);

  const { instruction: wdFullIx } = await prover.buildWithdrawInstruction({
    payer,
    poolId: 0,
    outPageId: 1n,
    inputPageIds: [0n],
    ring,
    inputNote: ownedNote,
    secretIndex: vectors.epoch_page.alice_note.slot_index,
    recipientAccount: payer,
    changeAddr: vectors.alice.address,
    amount: ownedNote.amount,
  });
  assert.equal(wdFullIx.data[0], core.TAG_WITHDRAW);
  assert.equal(wdFullIx.data.length, 948);
  assert.equal(wdFullIx.accounts[1].isWritable, false);
});

test('5. disclosure & auditor: Rust-generated SelectiveDisclosure, odd Lane 1 page_id & Auditor ElGamal verify in TS', async () => {
  const alice = await prover.deriveKeysFromSeed(hexToBytes(vectors.alice.seed_hex));
  const pageBytes = hexToBytes(vectors.epoch_page.page_hex);
  const receipt = JSON.parse(vectors.selective_disclosure_json);

  // TS-generated canonical SelectiveDisclosureProof matches Rust byte-for-byte!
  const [note] = await prover.scanEpochPageSpendable(alice, pageBytes, vectors.epoch_page.pool_id);
  const tsProof = prover.createSelectiveDisclosureProof(note);
  assert.deepEqual(tsProof, receipt);

  // Parallel append lane 1 odd page_id (> Number.MAX_SAFE_INTEGER) stays lossless!
  const oddLane1PageId = core.pageIdForLane(1, 1n); // 72057594037927937n
  const oddProof = prover.createSelectiveDisclosureProof({ ...note, pageId: oddLane1PageId });
  assert.equal(oddProof.page_id, oddLane1PageId.toString());
  assert.equal((await prover.verifySelectiveDisclosureReceipt(oddProof)).valid, true);

  // Rust-generated SelectiveDisclosureProof verifies standalone AND on-page in pure TS!
  assert.equal((await prover.verifySelectiveDisclosureReceipt(receipt)).valid, true);
  assert.equal((await prover.verifySelectiveDisclosureOnPage(receipt, pageBytes)).valid, true);

  // Tampered receipt MUST fail verification
  const tampered = { ...receipt, amount: receipt.amount + 1 };
  assert.equal((await prover.verifySelectiveDisclosureReceipt(tampered)).valid, false);
  assert.equal((await prover.verifySelectiveDisclosureOnPage(tampered, pageBytes)).valid, false);

  // Institutional auditor ElGamal decryption matches Rust byte-for-byte
  const aud = await prover.deriveAuditorKeypair(hexToBytes(vectors.auditor.auditor_seed_hex));
  assert.equal(bytesToHex(aud.auditorSkBytes), vectors.auditor.auditor_sk_hex);
  assert.equal(bytesToHex(aud.auditorPk), vectors.auditor.auditor_pk_hex);

  const decrypted = prover.auditorDecryptNote({
    auditorSk: aud.auditorSk,
    s1: hexToBytes(vectors.auditor.elgamal_s1_hex),
    s2: hexToBytes(vectors.auditor.elgamal_s2_hex),
    m1: hexToBytes(vectors.auditor.elgamal_m1_hex),
    m2: hexToBytes(vectors.auditor.elgamal_m2_hex),
  });
  assert.equal(bytesToHex(decrypted.spentStealthPk), vectors.auditor.expected_spent_pk_hex);
  assert.equal(bytesToHex(decrypted.assetGenerator), vectors.auditor.expected_asset_gen_hex);
});

test('6. escrow & relayer: Jupiter CPI excluded DEXes, default relay URL, dataSlice & prepareEscrowAccounts', async () => {
  assert.equal(core.JUPITER_CPI_EXCLUDED_DEXES.join(','), vectors.jupiter_cpi_excluded_dexes);
  assert.equal(core.AUDREN_DEFAULT_RELAY_URL, 'https://relay.audren.xyz');
  assert.deepEqual(core.PAGE_SCAN_DATA_SLICE, {
    offset: vectors.epoch_page.scan_offset,
    length: vectors.epoch_page.scan_length,
  });

  const escrow0 = vectors.pdas.escrow_0.address;
  const wsol = vectors.asset_generators.wsol_mint_b58;
  const usdc = vectors.asset_generators.usdc_mint_b58;
  const { address: escrowInAta } = await core.deriveAssociatedTokenAddress(escrow0, wsol);
  const { address: escrowOutAta } = await core.deriveAssociatedTokenAddress(escrow0, usdc);
  const prep = await core.prepareEscrowAccounts({
    poolId: 0,
    shardId: 0,
    inputMint: wsol,
    outputMint: usdc,
    actionAccounts: [
      { pubkey: escrowInAta, isSigner: false, isWritable: true },
      { pubkey: escrow0, isSigner: true, isWritable: true },
      { pubkey: escrowOutAta, isSigner: false, isWritable: true },
    ],
  });
  assert.equal(prep.escrowPda, escrow0);
  assert.equal(prep.escrowInAta, escrowInAta);
  assert.equal(prep.escrowOutAta, escrowOutAta);
  assert.deepEqual([prep.escrowIdx, prep.escrowInIdx, prep.escrowOutIdx], [1, 0, 2]);
  assert.equal(prep.accounts[1].isSigner, false);
});
