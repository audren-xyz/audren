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

  const solGen = await prover.assetGenerator(prover.NATIVE_SOL_MINT);
  assert.equal(bytesToHex(solGen), vectors.asset_generators.native_sol_gen_hex);

  const wsolGen = await prover.assetGenerator(prover.WSOL_MINT);
  assert.equal(bytesToHex(wsolGen), vectors.asset_generators.wsol_gen_hex);

  const usdcGen = await prover.assetGenerator(
    core.base58Decode(vectors.asset_generators.usdc_mint_b58),
  );
  assert.equal(bytesToHex(usdcGen), vectors.asset_generators.usdc_gen_hex);
});

test('2. pdas & layouts: all 10 Pool #0 PDAs, PoolState and EpochPageHeader match Rust byte-for-byte', async () => {
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

  const escrow0 = await core.deriveSwapEscrowPda(p.pool_id, 0);
  assert.equal(escrow0.address, p.swap_escrow_0.address);
  assert.equal(escrow0.bump, p.swap_escrow_0.bump);

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

test('4. prover: pure-TS Deposit, Transfer (m=5 Triptych + Bulletproofs U128), ProofBuffer & Withdraw', async () => {
  const alice = await prover.deriveKeysFromSeed(hexToBytes(vectors.alice.seed_hex));
  const bobAddr = prover.parseAudrenAddress(vectors.bob.address);
  const aliceAddr = prover.parseAudrenAddress(vectors.alice.address);
  const payer = core.base58Decode(vectors.pdas.proof_buffer_authority);
  const pageBytes = hexToBytes(vectors.epoch_page.page_hex);

  const { instructions: depIxs, note: depNote } = await prover.buildDepositInstruction({
    depositor: payer,
    poolId: 0,
    activePageId: 1n,
    recipient: bobAddr,
    mint: prover.NATIVE_SOL_MINT,
    amount: 500_000n,
  });
  assert.equal(depIxs.length, 1);
  assert.equal(depIxs[0].data[0], core.TAG_DEPOSIT);
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
      recipient: bobAddr,
      changeAddr: aliceAddr,
      payAmount: 900_000n,
    });
  assert.equal(xferIx.data[0], core.TAG_TRANSFER);
  assert.ok(xferIx.data.length > 2_000);
  assert.equal(payNote.amount, 900_000n);
  assert.equal(changeNote.amount, 600_000n);
  assert.equal(bytesToHex(nullifier), vectors.epoch_page.alice_note.nullifier_hex);

  const bufPlan = await prover.buildBufferedExecutionPlan(xferIx, 42n);
  assert.ok(bufPlan.uploadChunks.length >= 3);
  assert.equal(bufPlan.executeIx.data[0], core.TAG_EXEC_BUFFERED);

  const { instruction: wdIx, changeNote: wdChg } = await prover.buildWithdrawInstruction({
    payer,
    poolId: 0,
    outPageId: 1n,
    inputPageIds: [0n],
    ring,
    inputNote: ownedNote,
    secretIndex: vectors.epoch_page.alice_note.slot_index,
    recipientAccount: payer,
    changeAddr: aliceAddr,
    amount: 1_000_000n,
  });
  assert.equal(wdIx.data[0], core.TAG_WITHDRAW);
  assert.ok(wdIx.data.length > 1_800);
  assert.equal(wdChg.amount, 500_000n);
});

test('5. disclosure & auditor: Rust-generated SelectiveDisclosure & Auditor ElGamal verify in TS', async () => {
  const alice = await prover.deriveKeysFromSeed(hexToBytes(vectors.alice.seed_hex));
  const pageBytes = hexToBytes(vectors.epoch_page.page_hex);
  const receipt = JSON.parse(vectors.selective_disclosure_json);

  // TS-generated canonical SelectiveDisclosureProof matches Rust byte-for-byte!
  const [note] = await prover.scanEpochPageSpendable(alice, pageBytes, vectors.epoch_page.pool_id);
  const tsProof = prover.createSelectiveDisclosureProof(note);
  assert.deepEqual(tsProof, receipt);

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

test('6. router & relayer: Jupiter CPI excluded DEXes, default relay URL & dataSlice match canonical constants', () => {
  assert.equal(core.JUPITER_CPI_EXCLUDED_DEXES.join(','), vectors.jupiter_cpi_excluded_dexes);
  assert.equal(core.AUDREN_DEFAULT_RELAY_URL, 'https://relay.audren.xyz');
  assert.deepEqual(core.PAGE_SCAN_DATA_SLICE, {
    offset: vectors.epoch_page.scan_offset,
    length: vectors.epoch_page.scan_length,
  });
});
