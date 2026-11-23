/**
 * Live Cross-SDK LiteSVM Driver for `crates/audren-ffi/tests/cross_sdk_litesvm.rs`.
 *
 * Reads a JSON request from stdin describing on-chain `RootCheckpoint` + `SubtreePage` + `MemoPage`
 * raw bytes from a live LiteSVM instance, ingests them via TypeScript `CompactWalletStore`,
 * builds a real BN254 Groth16 proof inside `@audren/sdk/prover` WASM, compiles a complete
 * Audren v1 instruction (`Deposit` / `Transact`), and writes the resulting instruction JSON
 * to stdout for Rust LiteSVM to execute on-chain against `audren.so`.
 */

import { readFileSync } from 'node:fs';
import {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_PUBLIC,
  CLASSIC_TOKEN_PROGRAM_ID,
  CompactWalletStore,
  MEMO_ENTRY_WIRE_LEN,
  WSOL_MINT,
  base58Decode,
  buildDepositInstruction,
  buildTransactInstruction,
  computeTransactCtxHash,
  decodeRootCheckpoint,
  deriveAssetId,
  deriveKeysFromSeed,
  deriveStealthOwner,
  encryptNoteMemo,
  exportFullViewingKey,
  frFromBeBytesStrict,
  frToBeBytes,
} from '../dist/index.js';
import {
  AudrenWasmProver,
  dummyInputWitness,
  dummyOutputWitness,
} from '../dist/prover-entry.js';

const fromHex = (h) => new Uint8Array(Buffer.from(h, 'hex'));
const toHex = (b) => Buffer.from(b).toString('hex');
const WSOL_MINT_BYTES = base58Decode(WSOL_MINT);

const req = JSON.parse(readFileSync(0, 'utf8'));

if (req.action === 'deposit_sol') {
  const recip = deriveKeysFromSeed(fromHex(req.recipient_seed_hex));
  const { tweak, blinding, memo } = encryptNoteMemo(
    recip.viewPk,
    fromHex(req.eph_secret_hex),
    BigInt(req.amount),
    WSOL_MINT_BYTES,
  );
  const stealth = deriveStealthOwner(recip.spendPk, tweak);
  const ix = buildDepositInstruction({
    programId: req.program_id,
    depositor: req.depositor,
    poolId: req.pool_id,
    laneId: req.lane_id,
    subPageSeq: BigInt(req.sub_page_seq),
    rootPageSeq: BigInt(req.root_page_seq),
    memoPageSeq: BigInt(req.memo_page_seq),
    nativeSol: true,
    feeFromAmount: Boolean(req.fee_from_amount),
    amount: BigInt(req.amount),
    stealthOwner: stealth,
    blinding,
    memo,
  });
  process.stdout.write(
    JSON.stringify({
      program_id: ix.programId,
      accounts: ix.accounts.map((a) => ({
        pubkey: a.pubkey,
        is_signer: a.isSigner,
        is_writable: a.isWritable,
      })),
      data_hex: toHex(ix.data),
    }),
  );
} else if (req.action === 'transact_transfer') {
  const sender = deriveKeysFromSeed(fromHex(req.sender_seed_hex));
  const recip = deriveKeysFromSeed(fromHex(req.recipient_seed_hex));
  const fvk = exportFullViewingKey(sender);

  const store = new CompactWalletStore(req.pool_id, 0n);
  store.ingestLanePages({
    fvk,
    laneId: req.in_lane_id,
    subtreePages: [{ pageSeq: BigInt(req.in_sub_seq), raw: fromHex(req.subtree_raw_hex) }],
    memoPages: [{ pageSeq: BigInt(req.in_memo_seq), raw: fromHex(req.memo_raw_hex) }],
    nfPages: [],
  });

  const note = store.unspentNotes()[0];
  if (!note) throw new Error('TS CompactWalletStore found no unspent note');

  const ckpt = decodeRootCheckpoint(fromHex(req.checkpoint_raw_hex));
  const { superRoot, path } = store.buildWitnessForNote(note, ckpt);
  const wsolAsset = deriveAssetId(WSOL_MINT_BYTES);

  const sendAmt = BigInt(req.send_amount);
  const changeAmt = note.amount - sendAmt;

  const out0 = encryptNoteMemo(
    recip.viewPk,
    fromHex(req.eph0_hex),
    sendAmt,
    WSOL_MINT_BYTES,
  );
  const out1 = encryptNoteMemo(
    sender.viewPk,
    fromHex(req.eph1_hex),
    changeAmt,
    WSOL_MINT_BYTES,
  );
  const memosBytes = new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN);
  memosBytes.set(out0.memo, 0);
  memosBytes.set(out1.memo, MEMO_ENTRY_WIRE_LEN);

  const ctxHash = computeTransactCtxHash({
    programId: req.program_id,
    poolId: req.pool_id,
    vkId: 0,
    outLaneId: req.out_lane_id,
    outputMask: 0b011,
    assetMode: ASSET_MODE_PRIVATE,
    unwrapWsol: false,
    publicAssetId: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes,
  });

  const prover = await AudrenWasmProver.init();
  const res = prover.proveJoinsplit(
    {
      superRoot,
      txAssetId: wsolAsset,
      publicAssetId: 0n,
      publicAmountOut: 0n,
      relayerFeeAmount: 0n,
      ctxHash,
      omitNf1: true,
      inputs: [
        {
          spendSk: sender.spendSk,
          tweak: frFromBeBytesStrict(note.tweak),
          assetId: wsolAsset,
          amount: note.amount,
          blinding: frFromBeBytesStrict(note.blinding),
          isDummy: false,
          merklePath: path,
        },
        dummyInputWitness(sender.spendSk, wsolAsset, 0x7777n),
      ],
      outputs: [
        {
          stealthOwner: deriveStealthOwner(recip.spendPk, out0.tweak),
          assetId: wsolAsset,
          amount: sendAmt,
          blinding: out0.blinding,
        },
        {
          stealthOwner: deriveStealthOwner(sender.spendPk, out1.tweak),
          assetId: wsolAsset,
          amount: changeAmt,
          blinding: out1.blinding,
        },
        dummyOutputWitness(wsolAsset, 0x8888n),
      ],
    },
    new Uint8Array(32).fill(0xab),
  );

  const ix = buildTransactInstruction({
    programId: req.program_id,
    payer: req.payer,
    poolId: req.pool_id,
    vkId: 0,
    ckptSlotIdx: req.ckpt_slot_idx,
    outLaneId: req.out_lane_id,
    outSubSeq: BigInt(req.out_sub_seq),
    outRootSeq: BigInt(req.out_root_seq),
    outMemoSeq: BigInt(req.out_memo_seq),
    outNfSeq: BigInt(req.out_nf_seq),
    outputMask: 0b011,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: res.proof192,
    nf0: res.nf0,
    nf1: res.nf1,
    cm0: res.cm0,
    cm1: res.cm1,
    cm2: res.cm2,
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes,
  });

  process.stdout.write(
    JSON.stringify({
      program_id: ix.programId,
      accounts: ix.accounts.map((a) => ({
        pubkey: a.pubkey,
        is_signer: a.isSigner,
        is_writable: a.isWritable,
      })),
      data_hex: toHex(ix.data),
      nf0_hex: toHex(res.nf0),
      cm0_hex: toHex(res.cm0),
      cm1_hex: toHex(res.cm1),
    }),
  );
} else if (req.action === 'transact_withdraw_sol') {
  const sender = deriveKeysFromSeed(fromHex(req.sender_seed_hex));
  const fvk = exportFullViewingKey(sender);
  const store = new CompactWalletStore(req.pool_id, 0n);
  store.ingestLanePages({
    fvk,
    laneId: req.in_lane_id,
    subtreePages: [{ pageSeq: BigInt(req.in_sub_seq), raw: fromHex(req.subtree_raw_hex) }],
    memoPages: [{ pageSeq: BigInt(req.in_memo_seq), raw: fromHex(req.memo_raw_hex) }],
    nfPages: [],
  });
  const note = store.unspentNotes()[0];
  if (!note) throw new Error('TS CompactWalletStore found no unspent note for withdraw');

  const ckpt = decodeRootCheckpoint(fromHex(req.checkpoint_raw_hex));
  const { superRoot, path } = store.buildWitnessForNote(note, ckpt);
  const wsolAsset = deriveAssetId(WSOL_MINT_BYTES);
  const feeAmt = BigInt(req.relayer_fee_amount);
  const pubOut = note.amount - feeAmt;

  const ctxHash = computeTransactCtxHash({
    programId: req.program_id,
    poolId: req.pool_id,
    vkId: 0,
    outLaneId: req.out_lane_id,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: true,
    recipient: req.recipient,
    relayerFeeRecipient: req.relayer_fee_recipient,
    publicAssetId: frToBeBytes(wsolAsset),
    publicAmountOut: pubOut,
    relayerFeeAmount: feeAmt,
    memosBytes: new Uint8Array(0),
  });

  const prover = await AudrenWasmProver.init();
  const res = prover.proveJoinsplit(
    {
      superRoot,
      txAssetId: wsolAsset,
      publicAssetId: wsolAsset,
      publicAmountOut: pubOut,
      relayerFeeAmount: feeAmt,
      ctxHash,
      omitNf1: true,
      inputs: [
        {
          spendSk: sender.spendSk,
          tweak: frFromBeBytesStrict(note.tweak),
          assetId: wsolAsset,
          amount: note.amount,
          blinding: frFromBeBytesStrict(note.blinding),
          isDummy: false,
          merklePath: path,
        },
        dummyInputWitness(sender.spendSk, wsolAsset, 0x9999n),
      ],
      outputs: [
        dummyOutputWitness(wsolAsset, 0xa1n),
        dummyOutputWitness(wsolAsset, 0xa2n),
        dummyOutputWitness(wsolAsset, 0xa3n),
      ],
    },
    new Uint8Array(32).fill(0xcd),
  );

  const ix = buildTransactInstruction({
    programId: req.program_id,
    payer: req.payer,
    poolId: req.pool_id,
    vkId: 0,
    ckptSlotIdx: req.ckpt_slot_idx,
    outLaneId: req.out_lane_id,
    outSubSeq: BigInt(req.out_sub_seq),
    outRootSeq: BigInt(req.out_root_seq),
    outMemoSeq: BigInt(req.out_memo_seq),
    outNfSeq: BigInt(req.out_nf_seq),
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: true,
    publicOutflow: {
      mint: WSOL_MINT,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    },
    proof192: res.proof192,
    nf0: res.nf0,
    nf1: res.nf1,
    cm0: res.cm0,
    cm1: res.cm1,
    cm2: res.cm2,
    publicAmountOut: pubOut,
    relayerFeeAmount: feeAmt,
    recipient: req.recipient,
    relayerFeeRecipient: req.relayer_fee_recipient,
    memosBytes: new Uint8Array(0),
  });

  process.stdout.write(
    JSON.stringify({
      program_id: ix.programId,
      accounts: ix.accounts.map((a) => ({
        pubkey: a.pubkey,
        is_signer: a.isSigner,
        is_writable: a.isWritable,
      })),
      data_hex: toHex(ix.data),
      public_amount_out: pubOut.toString(),
    }),
  );
} else {
  throw new Error(`Unknown action ${req.action}`);
}
