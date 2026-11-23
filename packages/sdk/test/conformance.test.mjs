import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_PUBLIC,
  AUDREN_PROGRAM_ID,
  MEMO_VERSION_V1,
  NUM_LANES,
  PROTOCOL_VERSION,
  WSOL_MINT,
  ZERO_HASHES_4ARY,
  base58Decode,
  base58Encode,
  buildHistoricalWitness4Ary,
  checkMemoViewTag,
  computeExecCtxHash,
  computeMerkleRoot4Ary,
  computeNoteCommitment,
  computePublicInputHash,
  computeRealNullifier,
  computeSubtree256Root,
  computeSuperRoot4Ary,
  computeTransactCtxHash,
  decodePoolState,
  decodeRootCheckpoint,
  deriveAssetId,
  deriveAssetIdBytes,
  deriveCheckpointPdaSync,
  deriveDefiSessionKeypair,
  deriveEscrowPdaSync,
  deriveKeysFromSeed,
  deriveLanePdaSync,
  deriveLaneRentVaultPdaSync,
  deriveMemoPdaSync,
  deriveNfPagePdaSync,
  deriveNullifierPdaSync,
  derivePoolPdaSync,
  deriveStealthOwner,
  deriveSubaccountKeys,
  deriveSubrootPdaSync,
  deriveSubtreePdaSync,
  deriveUnwrapPdaSync,
  deriveVaultAuthPdaSync,
  encryptNoteMemo,
  exportFullViewingKey,
  frToBeBytes,
  parseAudrenAddress,
  poseidon2,
  poseidon4,
  prepareDynamicSwapMemo,
  tryDecryptAndVerifyMemo,
  verifySelectiveDisclosureProof,
} from '../dist/index.js';
import {
  AudrenWasmProver,
  dummyInputWitness,
  dummyOutputWitness,
} from '../dist/prover-entry.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(path.resolve(__dirname, '../../../spec/test-vectors.json'), 'utf8'),
);

const toHex = (bytes) => Buffer.from(bytes).toString('hex');
const fromHex = (hex) => new Uint8Array(Buffer.from(hex, 'hex'));

test('TypeScript @audren/sdk & @audren/sdk/prover WASM match spec/test-vectors.json byte-for-byte', async () => {
  assert.equal(PROTOCOL_VERSION, vectors.protocol_version);
  assert.equal(AUDREN_PROGRAM_ID, vectors.program_id);

  // 1. Keys, subaccounts, Bech32m aud1... address, DefiSessionKeypair
  const aliceSeed = fromHex(vectors.alice.seed_hex);
  const bobSeed = fromHex(vectors.bob.seed_hex);
  const alice = deriveKeysFromSeed(aliceSeed);
  const aliceSub1 = deriveSubaccountKeys(aliceSeed, 1);
  const bob = deriveKeysFromSeed(bobSeed);

  for (const [k, exp] of [
    [alice, vectors.alice],
    [aliceSub1, vectors.alice_sub1],
    [bob, vectors.bob],
  ]) {
    assert.equal(toHex(k.spendSkBytes), exp.spend_sk_hex);
    assert.equal(toHex(k.spendPkBytes), exp.spend_pk_hex);
    assert.equal(toHex(k.nkBytes), exp.nk_hex);
    assert.equal(toHex(k.viewSk), exp.view_sk_hex);
    assert.equal(toHex(k.viewPk), exp.view_pk_hex);
    assert.equal(k.address, exp.address);
    assert.equal(k.address.length, 114);
    const parsed = parseAudrenAddress(k.address);
    assert.equal(toHex(parsed.spendPk), exp.spend_pk_hex);
    assert.equal(toHex(parsed.viewPk), exp.view_pk_hex);
  }

  const sess0 = deriveDefiSessionKeypair(aliceSeed, 0);
  const sess3 = deriveDefiSessionKeypair(aliceSeed, 3);
  assert.equal(toHex(sess0.secretSeed), vectors.defi_session_0.secret_seed_hex);
  assert.equal(sess0.pubkeyBase58, vectors.defi_session_0.pubkey_b58);
  assert.equal(toHex(sess3.secretSeed), vectors.defi_session_3.secret_seed_hex);
  assert.equal(sess3.pubkeyBase58, vectors.defi_session_3.pubkey_b58);

  // 2. Pure-TS Circom BN254 Poseidon & ZERO_HASHES_4ARY
  assert.equal(toHex(frToBeBytes(poseidon2(1n, 2n))), vectors.poseidon.poseidon2_1_2_hex);
  assert.equal(toHex(frToBeBytes(poseidon4(0n, 0n, 0n, 0n))), vectors.poseidon.poseidon4_zeros_hex);
  assert.equal(toHex(frToBeBytes(ZERO_HASHES_4ARY[18])), vectors.poseidon.zero_hash_level18_hex);
  assert.equal(toHex(frToBeBytes(ZERO_HASHES_4ARY[19])), vectors.poseidon.zero_hash_level19_hex);
  assert.equal(toHex(frToBeBytes(ZERO_HASHES_4ARY[20])), vectors.poseidon.zero_hash_level20_hex);

  // 3. Asset IDs (WSOL & USDC under audren/v1/asset)
  const wsolMintBytes = base58Decode(WSOL_MINT);
  const wsolAsset = deriveAssetId(wsolMintBytes);
  const usdcAsset = deriveAssetId(base58Decode(vectors.asset_ids.usdc_mint_b58));
  assert.equal(toHex(frToBeBytes(wsolAsset)), vectors.asset_ids.wsol_asset_id_hex);
  assert.equal(toHex(deriveAssetIdBytes(wsolMintBytes)), vectors.asset_ids.wsol_asset_id_hex);
  assert.equal(toHex(frToBeBytes(usdcAsset)), vectors.asset_ids.usdc_asset_id_hex);

  // 4. Versioned 106 B memo encryption, AEAD AAD, FVK decryption + commitment check, dynamic 72 B memo & low-order X25519
  const ephSec = fromHex(vectors.memo.eph_secret_hex);
  const amount = BigInt(vectors.memo.amount);
  const mint = fromHex(vectors.memo.mint_hex);
  const paymentId = fromHex(vectors.memo.payment_id_hex);
  const { tweak, blinding, memo } = encryptNoteMemo(alice.viewPk, ephSec, amount, mint, paymentId);
  const stealth = deriveStealthOwner(alice.spendPk, tweak);
  const cm = computeNoteCommitment(stealth, deriveAssetId(mint), amount, blinding);
  const cmBe = frToBeBytes(cm);

  assert.equal(toHex(frToBeBytes(tweak)), vectors.memo.tweak_hex);
  assert.equal(toHex(frToBeBytes(blinding)), vectors.memo.blinding_hex);
  assert.equal(toHex(frToBeBytes(stealth)), vectors.memo.stealth_owner_hex);
  assert.equal(toHex(cmBe), vectors.memo.commitment_hex);
  assert.equal(toHex(cmBe), vectors.poseidon.poseidon5_note_hex);
  assert.equal(toHex(memo), vectors.memo.memo_106_hex);

  const fvk = exportFullViewingKey(alice);
  const dec = tryDecryptAndVerifyMemo(fvk, memo, cmBe);
  assert.ok(dec);
  assert.equal(dec.amount, amount);
  assert.equal(dec.memoVersion, MEMO_VERSION_V1);
  assert.equal(dec.memoFlags, 0);
  assert.equal(toHex(dec.paymentId), vectors.memo.payment_id_hex);
  assert.equal(dec.isDynamic, false);
  // Forged commitment MUST be rejected
  const badCm = new Uint8Array(cmBe);
  badCm[31] ^= 1;
  assert.equal(tryDecryptAndVerifyMemo(fvk, memo, badCm), null);

  // Domain-separated 72 B dynamic swap memo
  const dyn = prepareDynamicSwapMemo(bob.viewPk, fromHex(vectors.memo.dyn_eph_secret_hex));
  assert.equal(toHex(frToBeBytes(dyn.tweak)), vectors.memo.dyn_tweak_hex);
  assert.equal(toHex(frToBeBytes(dyn.blinding)), vectors.memo.dyn_blinding_hex);
  assert.equal(toHex(dyn.dynHead34), vectors.memo.dyn_head_34_hex);
  assert.equal(toHex(dyn.dynMask72), vectors.memo.dyn_mask_72_hex);
  const bobFvk = exportFullViewingKey(bob);
  const dynDec = tryDecryptAndVerifyMemo(
    bobFvk,
    fromHex(vectors.memo.dyn_stamped_memo_106_hex),
    fromHex(vectors.memo.dyn_commitment_hex),
  );
  assert.ok(dynDec);
  assert.equal(dynDec.isDynamic, true);
  assert.equal(dynDec.amount, BigInt(vectors.memo.dyn_amount));
  assert.equal(toHex(dynDec.mint), vectors.memo.dyn_mint_hex);

  // Low-order X25519 points MUST be rejected
  if (vectors.low_order_x25519) {
    for (const badHex of [vectors.low_order_x25519.all_zero_epk_hex, vectors.low_order_x25519.order_8_epk_hex]) {
      const badEpk = fromHex(badHex);
      assert.equal(checkMemoViewTag(alice.viewSk, new Uint8Array(2), badEpk), false);
      assert.throws(() => encryptNoteMemo(badEpk, ephSec, 1n, wsolMintBytes));
      assert.throws(() => prepareDynamicSwapMemo(badEpk, ephSec));
    }
  }

  // 5. Mode 1 Selective Disclosure
  const sd = {
    poolId: vectors.selective_disclosure.pool_id,
    laneId: vectors.selective_disclosure.lane_id,
    leafIndex: BigInt(vectors.selective_disclosure.leaf_index),
    stealthOwner: new Uint8Array(vectors.selective_disclosure.stealth_owner),
    mint: new Uint8Array(vectors.selective_disclosure.mint),
    amount: BigInt(vectors.selective_disclosure.amount),
    blinding: new Uint8Array(vectors.selective_disclosure.blinding),
    commitment: new Uint8Array(vectors.selective_disclosure.commitment),
  };
  assert.equal(verifySelectiveDisclosureProof(sd, cmBe), true);
  assert.equal(verifySelectiveDisclosureProof(sd, badCm), false);

  // 6. All 12 canonical v1 PDAs (`audren_*`)
  const nfSample = frToBeBytes(computeRealNullifier(alice.nk, cm, (2n << 36n) | 5n));
  assert.equal(toHex(nfSample), vectors.pdas.nullifier_hex);
  const checkPda = (got, exp) => {
    assert.equal(got.address, exp.address);
    assert.equal(got.bump, exp.bump);
  };
  checkPda(derivePoolPdaSync(0), vectors.pdas.pool);
  checkPda(deriveVaultAuthPdaSync(0), vectors.pdas.vault_auth);
  checkPda(deriveLanePdaSync(0, 2), vectors.pdas.lane);
  checkPda(deriveLaneRentVaultPdaSync(0, 2), vectors.pdas.lane_rent);
  checkPda(deriveSubtreePdaSync(0, 2, 7n), vectors.pdas.subtree);
  checkPda(deriveSubrootPdaSync(0, 2, 7n), vectors.pdas.subroot);
  checkPda(deriveMemoPdaSync(0, 2, 7n), vectors.pdas.memo);
  checkPda(deriveNfPagePdaSync(0, 2, 7n), vectors.pdas.nf_page);
  checkPda(deriveCheckpointPdaSync(0, 13), vectors.pdas.checkpoint);
  checkPda(deriveNullifierPdaSync(0, nfSample), vectors.pdas.nullifier);
  checkPda(deriveEscrowPdaSync(0, 5), vectors.pdas.escrow);
  checkPda(deriveUnwrapPdaSync(0, nfSample), vectors.pdas.unwrap);

  // 7. All 3 v1 ctx_hash transcripts (with vkId bound!)
  const ctxPriv = computeTransactCtxHash({
    poolId: 0,
    vkId: 0,
    outLaneId: 2,
    outputMask: 0b111,
    assetMode: ASSET_MODE_PRIVATE,
    unwrapWsol: false,
    publicAssetId: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: memo,
  });
  assert.equal(toHex(frToBeBytes(ctxPriv)), vectors.ctx_hashes.transact_private_ctx_hash_hex);

  const ctxWsol = computeTransactCtxHash({
    poolId: 0,
    vkId: 0,
    outLaneId: 2,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: true,
    recipient: sess0.pubkeyBase58,
    relayerFeeRecipient: sess3.pubkeyBase58,
    publicAssetId: frToBeBytes(wsolAsset),
    publicAmountOut: 1_000_000_000n,
    relayerFeeAmount: 5_000_000n,
    memosBytes: new Uint8Array(0),
  });
  assert.equal(toHex(frToBeBytes(ctxWsol)), vectors.ctx_hashes.transact_wsol_unwrap_ctx_hash_hex);

  const ctxExec = computeExecCtxHash({
    poolId: 0,
    vkId: 0,
    outLaneId: 1,
    escrowShard: 3,
    changeMask: 0b01,
    feeOnOutput: true,
    assetIn: frToBeBytes(usdcAsset),
    amountIn: 50_000_000n,
    relayerFeeAmount: 2_000_000n,
    relayerFeeRecipient: sess3.pubkeyBase58,
    assetOut: frToBeBytes(wsolAsset),
    minAmountOut: 400_000_000n,
    routerProg: base58Encode(new Uint8Array(32).fill(0x77)),
    routerAccounts: [
      { pubkey: base58Encode(new Uint8Array(32).fill(0x88)), isSigner: false, isWritable: true },
      { pubkey: base58Encode(new Uint8Array(32).fill(0x99)), isSigner: false, isWritable: false },
    ],
    outStealthOwner: frToBeBytes(stealth),
    outBlinding: frToBeBytes(blinding),
    dynMemoHead: dyn.dynHead34,
    dynMemoMask: dyn.dynMask72,
    routerIxData: new Uint8Array([1, 2, 3, 4]),
    changeMemos: memo,
  });
  assert.equal(toHex(frToBeBytes(ctxExec)), vectors.ctx_hashes.exec_fee_on_output_ctx_hash_hex);

  // 8. PoolState (v1 with pendingAuthority) & RootCheckpoint decoding
  const decodedPool = decodePoolState(fromHex(vectors.pool_state.raw_hex));
  assert.equal(decodedPool.version, PROTOCOL_VERSION);
  assert.equal(decodedPool.poolId, vectors.pool_state.pool_id);
  assert.equal(decodedPool.activeLanes, vectors.pool_state.active_lanes);
  assert.equal(decodedPool.ckptInterval, BigInt(vectors.pool_state.ckpt_interval));
  assert.equal(decodedPool.maxCkptAge, BigInt(vectors.pool_state.max_ckpt_age));
  assert.equal(decodedPool.noteRentFee, BigInt(vectors.pool_state.note_rent_fee));
  assert.equal(decodedPool.nfRentFee, BigInt(vectors.pool_state.nf_rent_fee));
  assert.equal(decodedPool.paused, vectors.pool_state.paused);
  if (vectors.pool_state.pending_authority_b58) {
    assert.equal(base58Encode(decodedPool.pendingAuthority), vectors.pool_state.pending_authority_b58);
  }

  const decodedCkpt = decodeRootCheckpoint(fromHex(vectors.checkpoint_raw_hex));
  assert.equal(toHex(decodedCkpt.superRoot), vectors.groth16.super_root_hex);
  assert.equal(decodedCkpt.laneCounts[2], 6n);

  // 9. Historical Merkle witness + LIVE WASM BN254 Groth16 proving byte-for-byte parity!
  const leaves = [0n, 0n, 0n, 0n, 0n, cm];
  const sub0 = computeSubtree256Root(leaves, 6);
  let lroot = sub0;
  for (let h = 4; h < 18; h++) {
    lroot = poseidon4(lroot, ZERO_HASHES_4ARY[h], ZERO_HASHES_4ARY[h], ZERO_HASHES_4ARY[h]);
  }
  const laneRoots = new Array(NUM_LANES).fill(ZERO_HASHES_4ARY[18]);
  laneRoots[2] = lroot;
  const superRoot = computeSuperRoot4Ary(laneRoots);
  assert.equal(toHex(frToBeBytes(superRoot)), vectors.groth16.super_root_hex);

  const path5 = buildHistoricalWitness4Ary({
    laneId: 2,
    targetLeafIdx: 5n,
    ckptLaneRoots: laneRoots,
    ckptLaneLeafCount: 6n,
    finalizedSubtreeRoots: [],
    targetPageLeaves: leaves,
    frontierPageLeaves: leaves,
  });
  assert.equal(computeMerkleRoot4Ary(path5, cm), superRoot);

  const prover = await AudrenWasmProver.init();
  const wasmPoseidon2 = prover.poseidonHashWasm([frToBeBytes(1n), frToBeBytes(2n)]);
  assert.equal(toHex(wasmPoseidon2), vectors.poseidon.poseidon2_1_2_hex);

  const out0Stealth = deriveStealthOwner(bob.spendPk, 0x101n);
  const out1Stealth = deriveStealthOwner(alice.spendPk, 0x102n);
  assert.equal(vectors.groth16.vk_id, 0);
  assert.equal(toHex(frToBeBytes(out0Stealth)), vectors.groth16.out0_stealth_owner_hex);
  assert.equal(toHex(frToBeBytes(out1Stealth)), vectors.groth16.out1_stealth_owner_hex);

  const t0 = performance.now();
  const proofRes = prover.proveJoinsplit(
    {
      superRoot,
      txAssetId: wsolAsset,
      publicAssetId: 0n,
      publicAmountOut: 0n,
      relayerFeeAmount: 0n,
      ctxHash: ctxPriv,
      omitNf1: true,
      inputs: [
        {
          spendSk: alice.spendSk,
          tweak,
          assetId: wsolAsset,
          amount,
          blinding,
          isDummy: false,
          merklePath: path5,
        },
        dummyInputWitness(alice.spendSk, wsolAsset, 0x5555n),
      ],
      outputs: [
        {
          stealthOwner: out0Stealth,
          assetId: wsolAsset,
          amount: 1_000_000n,
          blinding: 0x201n,
        },
        {
          stealthOwner: out1Stealth,
          assetId: wsolAsset,
          amount: 500_000n,
          blinding: 0x202n,
        },
        dummyOutputWitness(wsolAsset, 0x203n),
      ],
    },
    new Uint8Array(32).fill(0x99),
  );
  const proveMs = Math.round(performance.now() - t0);

  assert.equal(toHex(proofRes.nf0), vectors.groth16.nf0_hex);
  assert.equal(toHex(proofRes.nf1), vectors.groth16.nf1_hex);
  assert.equal(toHex(proofRes.cm0), vectors.groth16.cm0_hex);
  assert.equal(toHex(proofRes.cm1), vectors.groth16.cm1_hex);
  assert.equal(toHex(proofRes.cm2), vectors.groth16.cm2_hex);
  assert.equal(toHex(proofRes.publicInputHash), vectors.groth16.public_input_hash_hex);
  assert.equal(toHex(proofRes.proof192), vectors.groth16.proof_192_hex);

  const localPubHash = computePublicInputHash({
    superRoot,
    nf0: BigInt(`0x${vectors.groth16.nf0_hex}`),
    nf1: 0n,
    cm0: BigInt(`0x${vectors.groth16.cm0_hex}`),
    cm1: BigInt(`0x${vectors.groth16.cm1_hex}`),
    cm2: BigInt(`0x${vectors.groth16.cm2_hex}`),
    publicAssetId: 0n,
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    ctxHash: ctxPriv,
  });
  assert.equal(toHex(frToBeBytes(localPubHash)), vectors.groth16.public_input_hash_hex);
  console.log(`WASM Groth16 proveJoinsplit verified byte-for-byte in ${proveMs} ms`);
});
