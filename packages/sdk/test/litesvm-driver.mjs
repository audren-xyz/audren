/**
 * Live Cross-SDK LiteSVM Driver for `crates/audren-ffi/tests/cross_sdk_litesvm.rs`.
 *
 * Reads a JSON request from stdin describing on-chain `RootCheckpoint` + `SubtreePage` + `MemoPage`
 * raw bytes from a live LiteSVM instance, ingests them via TypeScript `CompactWalletStore`,
 * builds a real BN254 Groth16 proof inside `@audren/sdk/prover` WASM, compiles a complete
 * Audren `JoinSplit` instruction (private transfer or public withdrawal), and writes the
 * resulting instruction JSON to stdout for Rust LiteSVM to execute on-chain against `audren.so`!
 */

import { readFileSync } from 'node:fs';
import {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_SOL,
  CompactWalletStore,
  NATIVE_SOL_MINT_BYTES,
  buildDepositSolInstruction,
  buildJoinsplitInstruction,
  computeJoinsplitCtxHash,
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

const req = JSON.parse(readFileSync(0, 'utf8'));

if (req.action === 'deposit_sol') {
  const recip = deriveKeysFromSeed(fromHex(req.recipient_seed_hex));
  const { tweak, blinding, memo90 } = encryptNoteMemo(
    recip.viewPk,
    fromHex(req.eph_secret_hex),
    BigInt(req.amount),
    NATIVE_SOL_MINT_BYTES,
  );
  const stealth = deriveStealthOwner(recip.spendPk, tweak);
  const ix = buildDepositSolInstruction({
    programId: req.program_id,
    depositor: req.depositor,
    poolId: req.pool_id,
    laneId: req.lane_id,
    subPageSeq: BigInt(req.sub_page_seq),
    rootPageSeq: BigInt(req.root_page_seq),
    memoPageSeq: BigInt(req.memo_page_seq),
    feeFromAmount: Boolean(req.fee_from_amount),
    amount: BigInt(req.amount),
    stealthOwner: stealth,
    blinding,
    memo90,
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
} else if (req.action === 'joinsplit_transfer') {
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
  const solAsset = deriveAssetId(NATIVE_SOL_MINT_BYTES);

  const sendAmt = BigInt(req.send_amount);
  const changeAmt = note.amount - sendAmt;

  const out0 = encryptNoteMemo(
    recip.viewPk,
    fromHex(req.eph0_hex),
    sendAmt,
    NATIVE_SOL_MINT_BYTES,
  );
  const out1 = encryptNoteMemo(
    sender.viewPk,
    fromHex(req.eph1_hex),
    changeAmt,
    NATIVE_SOL_MINT_BYTES,
  );
  const memosBytes = new Uint8Array(180);
  memosBytes.set(out0.memo90, 0);
  memosBytes.set(out1.memo90, 90);

  const ctxHash = computeJoinsplitCtxHash({
    programId: req.program_id,
    poolId: req.pool_id,
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
      txAssetId: solAsset,
      publicAssetId: 0n,
      publicAmountOut: 0n,
      relayerFeeAmount: 0n,
      ctxHash,
      omitNf1: true,
      inputs: [
        {
          spendSk: sender.spendSk,
          tweak: frFromBeBytesStrict(note.tweak),
          assetId: solAsset,
          amount: note.amount,
          blinding: frFromBeBytesStrict(note.blinding),
          isDummy: false,
          merklePath: path,
        },
        dummyInputWitness(sender.spendSk, solAsset, 0x7777n),
      ],
      outputs: [
        {
          stealthOwner: deriveStealthOwner(recip.spendPk, out0.tweak),
          assetId: solAsset,
          amount: sendAmt,
          blinding: out0.blinding,
        },
        {
          stealthOwner: deriveStealthOwner(sender.spendPk, out1.tweak),
          assetId: solAsset,
          amount: changeAmt,
          blinding: out1.blinding,
        },
        dummyOutputWitness(solAsset, 0x8888n),
      ],
    },
    new Uint8Array(32).fill(0xab),
  );

  const ix = buildJoinsplitInstruction({
    programId: req.program_id,
    payer: req.payer,
    poolId: req.pool_id,
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
} else if (req.action === 'joinsplit_withdraw_sol') {
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
  const solAsset = deriveAssetId(NATIVE_SOL_MINT_BYTES);
  const feeAmt = BigInt(req.relayer_fee_amount);
  const pubOut = note.amount - feeAmt;

  const ctxHash = computeJoinsplitCtxHash({
    programId: req.program_id,
    poolId: req.pool_id,
    outLaneId: req.out_lane_id,
    outputMask: 0,
    assetMode: ASSET_MODE_SOL,
    unwrapWsol: false,
    recipient: req.recipient,
    relayerFeeRecipient: req.relayer_fee_recipient,
    publicAssetId: frToBeBytes(solAsset),
    publicAmountOut: pubOut,
    relayerFeeAmount: feeAmt,
    memosBytes: new Uint8Array(0),
  });

  const prover = await AudrenWasmProver.init();
  const res = prover.proveJoinsplit(
    {
      superRoot,
      txAssetId: solAsset,
      publicAssetId: solAsset,
      publicAmountOut: pubOut,
      relayerFeeAmount: feeAmt,
      ctxHash,
      omitNf1: true,
      inputs: [
        {
          spendSk: sender.spendSk,
          tweak: frFromBeBytesStrict(note.tweak),
          assetId: solAsset,
          amount: note.amount,
          blinding: frFromBeBytesStrict(note.blinding),
          isDummy: false,
          merklePath: path,
        },
        dummyInputWitness(sender.spendSk, solAsset, 0x9999n),
      ],
      outputs: [
        dummyOutputWitness(solAsset, 0xa1n),
        dummyOutputWitness(solAsset, 0xa2n),
        dummyOutputWitness(solAsset, 0xa3n),
      ],
    },
    new Uint8Array(32).fill(0xcd),
  );

  const ix = buildJoinsplitInstruction({
    programId: req.program_id,
    payer: req.payer,
    poolId: req.pool_id,
    ckptSlotIdx: req.ckpt_slot_idx,
    outLaneId: req.out_lane_id,
    outSubSeq: BigInt(req.out_sub_seq),
    outRootSeq: BigInt(req.out_root_seq),
    outMemoSeq: BigInt(req.out_memo_seq),
    outNfSeq: BigInt(req.out_nf_seq),
    outputMask: 0,
    assetMode: ASSET_MODE_SOL,
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
