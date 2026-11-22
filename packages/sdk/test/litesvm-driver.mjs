#!/usr/bin/env node
/**
 * JSON stdin -> stdout driver for `crates/audren-ffi/tests/cross_sdk_litesvm.rs`.
 *
 * Calls the REAL compiled `@audren/sdk` and `@audren/sdk/prover` bundles to build
 * production Solana instructions (Deposit, Transfer, Merge, ExecViaEscrow, Withdraw,
 * ProofBuffer) that Rust executes directly against the real sBPFv3 `audren.so` and
 * `audren_mock_router.so` binaries inside LiteSVM.
 */
import fs from 'node:fs';
import {
  PAGE_SCAN_OFFSET,
  PAGE_SCAN_LEN,
  prepareEscrowAccounts,
} from '../dist/index.js';
import {
  base58Decode,
  base58Encode,
  buildBufferedExecutionPlan,
  buildCloseProofBufferInstruction,
  buildDepositInstruction,
  buildExecViaEscrowInstruction,
  buildMergeInstruction,
  buildTransferInstruction,
  buildWithdrawInstruction,
  createSelectiveDisclosureProof,
  deriveKeysFromSeed,
  exportFullViewingKey,
  extractRingFromPage,
  scanEpochPage,
  scanEpochPageSpendable,
  scanPageScanSlice,
  verifySelectiveDisclosureOnPage,
} from '../dist/prover-entry.js';

function fromHex(h) {
  return new Uint8Array(Buffer.from(h, 'hex'));
}

function toHex(u8) {
  return Buffer.from(u8).toString('hex');
}

function serializeIx(ix) {
  return {
    programId: base58Encode(ix.programId),
    accounts: ix.accounts.map((k) => ({
      pubkey: base58Encode(k.pubkey),
      isSigner: k.isSigner,
      isWritable: k.isWritable,
    })),
    dataHex: toHex(ix.data),
  };
}

function serializeNote(n) {
  return {
    pageId: n.pageId.toString(),
    slotIndex: n.slotIndex,
    mintHex: toHex(n.mint),
    amount: n.amount.toString(),
    isDynamicOutput: n.isDynamicOutput,
    amountResolved: n.amountResolved,
    stealthPkHex: toHex(n.stealthPk),
    assetTagHex: toHex(n.assetTag),
    commitmentHex: toHex(n.commitment),
    nullifierHex: n.nullifier ? toHex(n.nullifier) : null,
    nullifierPdaB58: n.nullifierPdaB58 ?? null,
  };
}

const raw = fs.readFileSync(0, 'utf8');
const req = JSON.parse(raw);

let out;
switch (req.op) {
  case 'deposit': {
    const res = await buildDepositInstruction({
      depositor: base58Decode(req.depositor),
      poolId: req.poolId,
      activePageId: BigInt(req.activePageId),
      recipient: req.recipientAddr,
      mint: fromHex(req.mintHex),
      amount: BigInt(req.amount),
      feeFromAmount: Boolean(req.feeFromAmount),
      tokenProgram: req.tokenProgram ? base58Decode(req.tokenProgram) : undefined,
      memoText: req.memoText ?? 'TS',
      createVaultAtaIfMissing: Boolean(req.createVaultAtaIfMissing),
    });
    out = {
      instructions: res.instructions.map(serializeIx),
      stealthPkHex: toHex(res.note.stealthPk),
    };
    break;
  }

  case 'scan': {
    const keys = await deriveKeysFromSeed(fromHex(req.seedHex));
    const fvk = exportFullViewingKey(keys);
    const pageBytes = fromHex(req.pageHex);
    const slice = pageBytes.subarray(PAGE_SCAN_OFFSET, PAGE_SCAN_OFFSET + PAGE_SCAN_LEN);
    const sliceHits = await scanPageScanSlice(fvk, slice);
    const knownDynamic = req.knownDynamic
      ? Object.fromEntries(Object.entries(req.knownDynamic).map(([k, v]) => [k, BigInt(v)]))
      : undefined;
    const fvkNotes = await scanEpochPage(fvk, pageBytes, req.poolId, knownDynamic);
    const spendNotes = await scanEpochPageSpendable(keys, pageBytes, req.poolId, knownDynamic);
    out = {
      address: keys.address,
      sliceHits,
      fvkNotes: fvkNotes.map(serializeNote),
      spendNotes: spendNotes.map(serializeNote),
    };
    break;
  }

  case 'transfer': {
    const keys = await deriveKeysFromSeed(fromHex(req.seedHex));
    const pages = req.pagesHex.map(fromHex);
    const inputPageIds = req.inputPageIds.map((p) => BigInt(p));
    const ring = pages.flatMap((p) => extractRingFromPage(p));
    const owned = await scanEpochPageSpendable(keys, pages[req.notePagePos ?? 0], req.poolId);
    const note = owned.find((n) => n.slotIndex === req.noteSlot);
    if (!note) throw new Error(`TS scan did not find note at slot ${req.noteSlot}`);
    const res = await buildTransferInstruction({
      payer: base58Decode(req.payer),
      poolId: req.poolId,
      outPageId: BigInt(req.outPageId),
      inputPageIds,
      ring,
      inputNote: note,
      secretIndex: req.secretIndex,
      recipient: req.recipientAddr,
      changeAddr: req.changeAddr,
      payAmount: BigInt(req.payAmount),
      memoText: req.memoText ?? 'TSXFER',
    });
    out = {
      instruction: serializeIx(res.instruction),
      nullifierHex: toHex(res.nullifier),
    };
    break;
  }

  case 'merge': {
    const keys = await deriveKeysFromSeed(fromHex(req.seedHex));
    const pages1 = req.pages1Hex.map(fromHex);
    const pages2 = req.pages2Hex.map(fromHex);
    const ring1 = pages1.flatMap((p) => extractRingFromPage(p));
    const ring2 = pages2.flatMap((p) => extractRingFromPage(p));
    const owned1 = await scanEpochPageSpendable(keys, pages1[0], req.poolId);
    const owned2 = await scanEpochPageSpendable(keys, pages2[0], req.poolId);
    const note1 = owned1.find((n) => n.slotIndex === req.slot1);
    const note2 = owned2.find((n) => n.slotIndex === req.slot2);
    if (!note1 || !note2) throw new Error('TS scan did not find merge notes');
    const res = await buildMergeInstruction({
      payer: base58Decode(req.payer),
      poolId: req.poolId,
      outPageId: BigInt(req.outPageId),
      input1PageIds: req.input1PageIds.map((p) => BigInt(p)),
      ring1,
      note1,
      secretIndex1: req.secretIndex1,
      input2PageIds: req.input2PageIds.map((p) => BigInt(p)),
      ring2,
      note2,
      secretIndex2: req.secretIndex2,
      ownerAddr: req.ownerAddr,
      memoText: 'TSMRG',
    });
    out = {
      instruction: serializeIx(res.instruction),
      nullifier1Hex: toHex(res.nullifier1),
      nullifier2Hex: toHex(res.nullifier2),
    };
    break;
  }

  case 'exec_escrow':
  case 'swap': {
    const keys = await deriveKeysFromSeed(fromHex(req.seedHex));
    const pages = req.pagesHex.map(fromHex);
    const ring = pages.flatMap((p) => extractRingFromPage(p));
    const owned = await scanEpochPageSpendable(keys, pages[0], req.poolId);
    const note = owned.find((n) => n.slotIndex === req.noteSlot);
    if (!note) throw new Error(`TS scan did not find exec_escrow note at slot ${req.noteSlot}`);
    const prep = await prepareEscrowAccounts({
      poolId: req.poolId,
      shardId: req.shardId,
      inputMint: req.inputMintB58,
      outputMint: req.outputMintB58,
      inputTokenProgram: req.tokenProgramIn,
      outputTokenProgram: req.tokenProgramOut,
      actionAccounts: req.actionAccounts ?? req.routerAccounts,
    });
    const res = await buildExecViaEscrowInstruction({
      payer: base58Decode(req.payer),
      poolId: req.poolId,
      outPageId: BigInt(req.outPageId),
      shardId: req.shardId,
      inputPageIds: req.inputPageIds.map((p) => BigInt(p)),
      ring,
      inputNote: note,
      secretIndex: req.secretIndex,
      mintOut: base58Decode(req.outputMintB58),
      tokenProgramIn: base58Decode(req.tokenProgramIn),
      tokenProgramOut: base58Decode(req.tokenProgramOut),
      amountIn: BigInt(req.amountIn),
      minAmountOut: BigInt(req.minAmountOut),
      relayerFee: req.relayerFee ? BigInt(req.relayerFee) : 0n,
      feeOnOutput: Boolean(req.feeOnOutput),
      feeRecipientAta: req.feeRecipientAta ? base58Decode(req.feeRecipientAta) : undefined,
      allowPartialRefund: Boolean(req.allowPartialRefund),
      recipient: req.recipientAddr,
      changeAddr: req.changeAddr,
      targetProgramId: base58Decode(req.targetProgramId ?? req.routerProgramId),
      targetIxData: fromHex(req.targetIxDataHex ?? req.routerIxDataHex),
      actionAccounts: prep.accounts.map((a) => ({
        pubkey: base58Decode(a.pubkey),
        isSigner: a.isSigner,
        isWritable: a.isWritable,
      })),
      escrowIdx: prep.escrowIdx,
      escrowInIdx: prep.escrowInIdx,
      escrowOutIdx: prep.escrowOutIdx,
      memoText: 'TSEXEC',
    });
    out = {
      instruction: serializeIx(res.instruction),
      outStealthPkB58: base58Encode(res.outDesc.stealthPk),
      nullifierHex: toHex(res.nullifier),
    };
    break;
  }

  case 'withdraw': {
    const keys = await deriveKeysFromSeed(fromHex(req.seedHex));
    const pages = req.pagesHex.map(fromHex);
    const ring = pages.flatMap((p) => extractRingFromPage(p));
    const owned = await scanEpochPageSpendable(keys, pages[0], req.poolId);
    const note = owned.find((n) => n.slotIndex === req.noteSlot);
    if (!note) throw new Error(`TS scan did not find withdraw note at slot ${req.noteSlot}`);
    const res = await buildWithdrawInstruction({
      payer: base58Decode(req.payer),
      poolId: req.poolId,
      outPageId: BigInt(req.outPageId),
      inputPageIds: req.inputPageIds.map((p) => BigInt(p)),
      ring,
      inputNote: note,
      secretIndex: req.secretIndex,
      recipientAccount: base58Decode(req.recipientAccount),
      changeAddr: req.changeAddr,
      amount: BigInt(req.amount),
      relayerFee: req.relayerFee ? BigInt(req.relayerFee) : 0n,
      feeRecipient: req.feeRecipient ? base58Decode(req.feeRecipient) : undefined,
      unwrapWsol: Boolean(req.unwrapWsol),
      splTokenProgram: req.splTokenProgram ? base58Decode(req.splTokenProgram) : undefined,
    });
    out = {
      instruction: serializeIx(res.instruction),
      nullifierHex: toHex(res.nullifier),
    };
    break;
  }

  case 'buffered_transfer': {
    const keys = await deriveKeysFromSeed(fromHex(req.seedHex));
    const pages = req.pagesHex.map(fromHex);
    const ring = pages.flatMap((p) => extractRingFromPage(p));
    const owned = await scanEpochPageSpendable(keys, pages[0], req.poolId);
    const note = owned.find((n) => n.slotIndex === req.noteSlot);
    if (!note) throw new Error(`TS scan did not find buffered note at slot ${req.noteSlot}`);
    const xfer = await buildTransferInstruction({
      payer: base58Decode(req.payer),
      poolId: req.poolId,
      outPageId: BigInt(req.outPageId),
      inputPageIds: req.inputPageIds.map((p) => BigInt(p)),
      ring,
      inputNote: note,
      secretIndex: req.secretIndex,
      recipient: req.recipientAddr,
      changeAddr: req.changeAddr,
      payAmount: BigInt(req.payAmount),
      memoText: 'TSBUF',
    });
    const plan = await buildBufferedExecutionPlan(xfer.instruction, BigInt(req.nonce));
    const closeIx = buildCloseProofBufferInstruction({
      payer: base58Decode(req.payer),
      proofBufferPda: plan.proofBufferPda,
    });
    out = {
      proofBufferPda: base58Encode(plan.proofBufferPda),
      uploadChunks: plan.uploadChunks.map(serializeIx),
      executeIx: serializeIx(plan.executeIx),
      closeIx: serializeIx(closeIx),
    };
    break;
  }

  case 'disclosure': {
    const keys = await deriveKeysFromSeed(fromHex(req.seedHex));
    const pageBytes = fromHex(req.pageHex);
    const owned = await scanEpochPageSpendable(keys, pageBytes, req.poolId);
    const note = owned.find((n) => n.slotIndex === req.noteSlot);
    if (!note) throw new Error(`TS scan did not find disclosure note at slot ${req.noteSlot}`);
    const proof = createSelectiveDisclosureProof(note);
    const onPage = await verifySelectiveDisclosureOnPage(proof, pageBytes);
    const tampered = { ...proof, amount: (BigInt(proof.amount) + 1n).toString() };
    const tamperedCheck = await verifySelectiveDisclosureOnPage(tampered, pageBytes);
    out = {
      proof,
      onPageValid: onPage.valid,
      tamperedValid: tamperedCheck.valid,
    };
    break;
  }

  case 'verify_disclosure': {
    const pageBytes = fromHex(req.pageHex);
    const onPage = await verifySelectiveDisclosureOnPage(req.proof, pageBytes);
    out = { valid: onPage.valid, reason: onPage.reason };
    break;
  }

  default:
    throw new Error(`Unknown op: ${req.op}`);
}

process.stdout.write(JSON.stringify(out));
