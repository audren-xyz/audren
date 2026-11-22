#!/usr/bin/env node
/**
 * Live Cluster Pool #0 Initializer & Full Empirical On-Chain E2E Suite.
 *
 * Uses `@audren/sdk` + `@audren/sdk/prover` (WASM) over real Solana Transaction v1 (`0x81`)
 * against Devnet or Mainnet:
 *   1. Idempotent `InitPool` (Pool #0, ckpt_interval=16, max_ckpt_age=3600) + `InitLane` (0..=3)
 *   2. Live `DepositSol` (Tag 3)
 *   3. Live `PublishCheckpoint` (Tag 5)
 *   4. Zero-indexer ordinary-RPC `CompactWalletStore` sync + SubtreePage verification
 *   5. Live `JoinSplit` Private Transfer (Tag 6, 192 B BN254 Groth16 proved in WASM)
 *   6. Live `PublishCheckpoint` (Tag 5) + `CompactWalletStore` resync (NullifierPage spend detection)
 *   7. Live `JoinSplit` Withdraw (Tag 6, 192 B BN254 Groth16) returning SOL to payer
 *
 * Reads `DEVNET_RPC_URL` / `MAINNET_RPC_URL` and `AUDREN_KEYPAIR_PATH` from environment
 * (or gitignored `.credentials/operator.env` / `.credentials/funder.json`). Never logs secrets.
 */

import { readFileSync, existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '../packages/sdk/node_modules/@noble/curves/ed25519.js';
import {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_SOL,
  AUDREN_PROGRAM_ID,
  CHECKPOINT_RING_SLOTS,
  CompactWalletStore,
  DEFAULT_INITIAL_LANES,
  MEMO_NOTES_PER_PAGE,
  NATIVE_SOL_MINT_BYTES,
  NF_PER_PAGE,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_NULLIFIER,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  SUBROOTS_PER_PAGE,
  SUBTREE_LEAVES,
  base58Decode,
  base58Encode,
  buildDepositSolInstruction,
  buildInitLaneInstruction,
  buildInitPoolInstruction,
  buildJoinsplitInstruction,
  buildOpenPageInstruction,
  buildPublishCheckpointInstruction,
  bytes32ToFrMasked,
  compileV1Message,
  computeJoinsplitCtxHash,
  decodeLaneHeader,
  decodePoolState,
  decodeRootCheckpoint,
  deriveAssetId,
  deriveCheckpointPdaSync,
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
  frFromBeBytesStrict,
  frToBeBytes,
  reconstructWitness,
  serializeV1Transaction,
  syncCompactStoreWithRpc,
} from '../packages/sdk/dist/index.js';
import {
  AudrenWasmProver,
  dummyInputWitness,
  dummyOutputWitness,
} from '../packages/sdk/dist/prover-entry.js';

const fromBase64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const toBase64 = (b) => Buffer.from(b).toString('base64');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function loadOperatorEnv() {
  const envPath = path.join(ROOT, '.credentials', 'operator.env');
  if (!existsSync(envPath)) return;
  for (const rawLine of readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim().replace(/^export\s+/, '');
    let val = line.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (!process.env[key]) process.env[key] = val;
  }
}

loadOperatorEnv();

const clusterArgIdx = process.argv.indexOf('--cluster');
const CLUSTER = clusterArgIdx !== -1 ? process.argv[clusterArgIdx + 1] : 'devnet';
if (CLUSTER !== 'devnet' && CLUSTER !== 'mainnet') {
  throw new Error('Usage: node scripts/live-cluster-e2e.mjs --cluster <devnet|mainnet> [--init-only]');
}
const INIT_ONLY = process.argv.includes('--init-only');
const RPC_URL = CLUSTER === 'mainnet' ? process.env.MAINNET_RPC_URL : process.env.DEVNET_RPC_URL;
if (!RPC_URL) throw new Error(`Missing ${CLUSTER.toUpperCase()}_RPC_URL`);

const KEYPAIR_PATH = process.env.AUDREN_KEYPAIR_PATH || path.join(ROOT, '.credentials', 'funder.json');
const keyBytes = Uint8Array.from(JSON.parse(readFileSync(KEYPAIR_PATH, 'utf8')));
const secret32 = keyBytes.subarray(0, 32);
const payerPubkey = ed25519.getPublicKey(secret32);
const payerStr = base58Encode(payerPubkey);

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function randomFr() {
  return bytes32ToFrMasked(new Uint8Array(randomBytes(32)));
}

async function rpc(method, params) {
  const res = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const json = await res.json();
  if (json.error) throw new Error(`RPC ${method}: ${JSON.stringify(json.error)}`);
  return json.result;
}

const fetchBatch = async (addresses) => {
  const out = new Array(addresses.length).fill(null);
  for (let off = 0; off < addresses.length; off += 100) {
    const chunk = addresses.slice(off, off + 100);
    const res = await rpc('getMultipleAccounts', [chunk, { encoding: 'base64', commitment: 'confirmed' }]);
    for (let i = 0; i < chunk.length; i++) {
      const d = res.value[i]?.data?.[0];
      out[off + i] = d ? fromBase64(d) : null;
    }
  }
  return out;
};

function toV1Ix(ix) {
  return {
    programId: base58Decode(ix.programId),
    accounts: ix.accounts.map((a) => ({
      pubkey: base58Decode(a.pubkey),
      isSigner: a.isSigner,
      isWritable: a.isWritable,
    })),
    data: ix.data,
  };
}

async function sendV1(ixs, computeUnitLimit = 300_000, priorityFeeLamports = 25_000n) {
  const bh = await rpc('getLatestBlockhash', [{ commitment: 'confirmed' }]);
  const compiled = compileV1Message({
    feePayer: payerPubkey,
    recentBlockhash: base58Decode(bh.value.blockhash),
    instructions: ixs.map(toV1Ix),
    config: { computeUnitLimit, priorityFeeLamports },
  });
  const sigBytes = ed25519.sign(compiled.messageBytes, secret32);
  const wire = serializeV1Transaction(compiled, [sigBytes]);
  const sig = await rpc('sendTransaction', [
    toBase64(wire),
    { encoding: 'base64', preflightCommitment: 'confirmed', maxRetries: 4 },
  ]);

  let slot = 0;
  let confirmed = false;
  for (let i = 0; i < 60; i++) {
    await sleep(600);
    const st = await rpc('getSignatureStatuses', [[sig], { searchTransactionHistory: true }]);
    const v = st.value[0];
    if (v?.err) throw new Error(`Tx ${sig} failed on-chain: ${JSON.stringify(v.err)}`);
    if (v?.confirmationStatus === 'confirmed' || v?.confirmationStatus === 'finalized') {
      slot = v.slot ?? 0;
      confirmed = true;
      break;
    }
  }
  if (!confirmed) {
    throw new Error(`Tx ${sig} was not confirmed within 36s`);
  }
  let cu = null;
  for (let i = 0; i < 6; i++) {
    const tx = await rpc('getTransaction', [
      sig,
      { encoding: 'json', commitment: 'confirmed', maxSupportedTransactionVersion: 1 },
    ]);
    if (tx?.meta) {
      cu = tx.meta.computeUnitsConsumed ?? null;
      slot = tx.slot ?? slot;
      break;
    }
    await sleep(500);
  }
  return { signature: sig, slot, cu, wireBytes: wire.byteLength };
}

async function publishFreshCheckpoint(poolId, pool) {
  for (let attempt = 0; attempt < 25; attempt++) {
    const curSlot = await rpc('getSlot', [{ commitment: 'confirmed' }]);
    const epoch = BigInt(curSlot) / pool.ckptInterval;
    const slotIdx = Number(epoch % BigInt(CHECKPOINT_RING_SLOTS));
    const ckptPda = deriveCheckpointPdaSync(poolId, slotIdx, AUDREN_PROGRAM_ID).address;
    const [existingRaw] = await fetchBatch([ckptPda]);
    if (existingRaw) {
      const existing = decodeRootCheckpoint(existingRaw);
      if (existing.epochId >= epoch) {
        const nextEpochSlot = (epoch + 1n) * pool.ckptInterval;
        const waitSlots = Number(nextEpochSlot - BigInt(curSlot)) + 1;
        await sleep(Math.max(1200, waitSlots * 450));
        continue;
      }
    }
    try {
      const ix = buildPublishCheckpointInstruction({
        payer: payerStr,
        poolId,
        slotIdx,
        activeLanes: pool.activeLanes,
      });
      const res = await sendV1([ix], 120_000);
      return { ...res, slotIdx, epoch };
    } catch (err) {
      if (String(err).includes('Custom') || String(err).includes('InvalidPda')) {
        await sleep(1500);
        continue;
      }
      throw err;
    }
  }
  throw new Error('Failed to publish fresh RootCheckpoint after retries');
}

async function ensurePages(poolId, laneId, nextLeaf, nfCount, notesToAppend = 1, nfsToAppend = 0) {
  const subSeq = nextLeaf / BigInt(SUBTREE_LEAVES);
  const rootSeq = subSeq / BigInt(SUBROOTS_PER_PAGE);
  const memoSeq = nextLeaf / BigInt(MEMO_NOTES_PER_PAGE);
  const nfSeq = nfCount / BigInt(NF_PER_PAGE);
  const lastLeaf = nextLeaf + BigInt(Math.max(0, notesToAppend - 1));
  const lastSubSeq = lastLeaf / BigInt(SUBTREE_LEAVES);
  const lastMemoSeq = lastLeaf / BigInt(MEMO_NOTES_PER_PAGE);
  const lastNfSeq = (nfCount + BigInt(Math.max(0, nfsToAppend - 1))) / BigInt(NF_PER_PAGE);
  const needNextSub = lastSubSeq > subSeq;
  const needNextMemo = lastMemoSeq > memoSeq;
  const needNextNf = lastNfSeq > nfSeq;

  const queries = [
    deriveSubtreePdaSync(poolId, laneId, subSeq, AUDREN_PROGRAM_ID).address,
    deriveSubrootPdaSync(poolId, laneId, rootSeq, AUDREN_PROGRAM_ID).address,
    deriveMemoPdaSync(poolId, laneId, memoSeq, AUDREN_PROGRAM_ID).address,
    deriveNfPagePdaSync(poolId, laneId, nfSeq, AUDREN_PROGRAM_ID).address,
  ];
  if (needNextSub) queries.push(deriveSubtreePdaSync(poolId, laneId, subSeq + 1n, AUDREN_PROGRAM_ID).address);
  if (needNextMemo) queries.push(deriveMemoPdaSync(poolId, laneId, memoSeq + 1n, AUDREN_PROGRAM_ID).address);
  if (needNextNf) queries.push(deriveNfPagePdaSync(poolId, laneId, nfSeq + 1n, AUDREN_PROGRAM_ID).address);
  const raws = await fetchBatch(queries);
  const ixs = [];
  if (!raws[0]) ixs.push(buildOpenPageInstruction({ payer: payerStr, pageKind: OPEN_PAGE_KIND_SUBTREE, poolId, laneId, pageSeq: subSeq }));
  if (!raws[1]) ixs.push(buildOpenPageInstruction({ payer: payerStr, pageKind: OPEN_PAGE_KIND_SUBROOT, poolId, laneId, pageSeq: rootSeq }));
  if (!raws[2]) ixs.push(buildOpenPageInstruction({ payer: payerStr, pageKind: OPEN_PAGE_KIND_MEMO, poolId, laneId, pageSeq: memoSeq }));
  if (!raws[3]) ixs.push(buildOpenPageInstruction({ payer: payerStr, pageKind: OPEN_PAGE_KIND_NULLIFIER, poolId, laneId, pageSeq: nfSeq }));
  let idx = 4;
  if (needNextSub) {
    if (!raws[idx++]) ixs.push(buildOpenPageInstruction({ payer: payerStr, pageKind: OPEN_PAGE_KIND_SUBTREE, poolId, laneId, pageSeq: subSeq + 1n }));
  }
  if (needNextMemo) {
    if (!raws[idx++]) ixs.push(buildOpenPageInstruction({ payer: payerStr, pageKind: OPEN_PAGE_KIND_MEMO, poolId, laneId, pageSeq: memoSeq + 1n }));
  }
  if (needNextNf) {
    if (!raws[idx++]) ixs.push(buildOpenPageInstruction({ payer: payerStr, pageKind: OPEN_PAGE_KIND_NULLIFIER, poolId, laneId, pageSeq: nfSeq + 1n }));
  }
  if (ixs.length > 0) await sendV1(ixs, 250_000);
  return {
    subSeq,
    rootSeq,
    memoSeq,
    nfSeq,
    nextSubSeq: needNextSub ? subSeq + 1n : undefined,
    nextMemoSeq: needNextMemo ? memoSeq + 1n : undefined,
    nextNfSeq: needNextNf ? nfSeq + 1n : undefined,
  };
}

async function main() {
  const poolId = 0;
  const poolPda = derivePoolPdaSync(poolId, AUDREN_PROGRAM_ID).address;
  const bal = await rpc('getBalance', [payerStr, { commitment: 'confirmed' }]);
  console.log(`\n=== Audren Live Empirical E2E (${CLUSTER.toUpperCase()}) ===`);
  console.log(`Program ID : ${AUDREN_PROGRAM_ID}`);
  console.log(`Pool #0 PDA: ${poolPda}`);
  console.log(`Authority  : ${payerStr} (${(bal.value / 1e9).toFixed(4)} SOL)`);

  const results = { cluster: CLUSTER, poolPda, txs: {} };

  // 1. Idempotent InitPool + InitLane 0..3
  let [poolRaw] = await fetchBatch([poolPda]);
  if (!poolRaw) {
    console.log('\n[1] Initializing Pool #0 (ckpt_interval=16, max_ckpt_age=3600, note_rent_fee=1_000_000, nf_rent_fee=120_000)...');
    const initPoolIx = buildInitPoolInstruction({
      payer: payerStr,
      poolId,
      ckptInterval: 16n,
      maxCkptAge: 3600n,
      noteRentFee: 1_000_000n,
      nfRentFee: 120_000n,
    });
    const res = await sendV1([initPoolIx], 120_000);
    console.log(`  InitPool confirmed: sig=${res.signature} slot=${res.slot} cu=${res.cu} wire=${res.wireBytes}B`);
    results.txs.initPool = res;
    [poolRaw] = await fetchBatch([poolPda]);
  } else {
    console.log('\n[1] Pool #0 already initialized.');
  }
  let pool = decodePoolState(poolRaw);
  console.log(`  Pool state: active_lanes=${pool.activeLanes}, paused=${pool.paused}, ckpt_interval=${pool.ckptInterval}, max_ckpt_age=${pool.maxCkptAge}`);

  for (let lane = pool.activeLanes; lane < DEFAULT_INITIAL_LANES; lane++) {
    console.log(`  Initializing Lane #${lane}...`);
    const laneIx = buildInitLaneInstruction({ authority: payerStr, poolId, laneId: lane });
    const res = await sendV1([laneIx], 250_000);
    console.log(`    InitLane #${lane} confirmed: sig=${res.signature} slot=${res.slot} cu=${res.cu}`);
    results.txs[`initLane${lane}`] = res;
  }
  [poolRaw] = await fetchBatch([poolPda]);
  pool = decodePoolState(poolRaw);
  if (pool.activeLanes < DEFAULT_INITIAL_LANES) {
    throw new Error(`Expected ${DEFAULT_INITIAL_LANES} active lanes, got ${pool.activeLanes}`);
  }

  if (INIT_ONLY) {
    const ck = await publishFreshCheckpoint(poolId, pool);
    console.log(`  Initial PublishCheckpoint: sig=${ck.signature} slot=${ck.slot} cu=${ck.cu}`);
    return;
  }

  // Load WASM Groth16 prover
  const wasmPath = path.join(ROOT, 'packages', 'sdk', 'wasm', 'audren_circuits.wasm');
  const prover = await AudrenWasmProver.init({ wasmBytes: readFileSync(wasmPath) });

  // Fresh ephemeral test wallets for this empirical run
  const alice = deriveKeysFromSeed(new Uint8Array(randomBytes(32)));
  const bob = deriveKeysFromSeed(new Uint8Array(randomBytes(32)));
  const depositAmount = 5_000_000n; // 0.005 SOL

  // 2. DepositSol (Tag 3) into Lane 0
  const depositLane = 0;
  const [lane0Raw] = await fetchBatch([deriveLanePdaSync(poolId, depositLane, AUDREN_PROGRAM_ID).address]);
  const lane0 = decodeLaneHeader(lane0Raw);
  const depPages = await ensurePages(poolId, depositLane, lane0.nextLeaf, lane0.nfCount);
  const depMemo = encryptNoteMemo(alice.viewPk, new Uint8Array(randomBytes(32)), depositAmount, NATIVE_SOL_MINT_BYTES);
  const depOwner = deriveStealthOwner(alice.spendPk, depMemo.tweak);
  const depIx = buildDepositSolInstruction({
    depositor: payerStr,
    poolId,
    laneId: depositLane,
    subPageSeq: depPages.subSeq,
    rootPageSeq: depPages.rootSeq,
    memoPageSeq: depPages.memoSeq,
    amount: depositAmount,
    stealthOwner: depOwner,
    blinding: depMemo.blinding,
    memo90: depMemo.memo90,
  });
  console.log('\n[2] Executing live DepositSol (0.005 SOL, Tag 3)...');
  const depRes = await sendV1([depIx], 150_000);
  console.log(`  DepositSol confirmed: sig=${depRes.signature} slot=${depRes.slot} cu=${depRes.cu} wire=${depRes.wireBytes}B`);
  results.txs.depositSol = depRes;

  // 3. PublishCheckpoint (Tag 5)
  console.log('\n[3] Publishing fresh RootCheckpoint (Tag 5)...');
  const ck1 = await publishFreshCheckpoint(poolId, pool);
  console.log(`  PublishCheckpoint confirmed: sig=${ck1.signature} slot=${ck1.slot} cu=${ck1.cu} slotIdx=${ck1.slotIdx}`);
  results.txs.checkpoint1 = ck1;

  // 4. Zero-indexer ordinary-RPC CompactWalletStore sync
  console.log('\n[4] Syncing Alice CompactWalletStore via ordinary Solana RPC getMultipleAccounts...');
  const aliceStore = new CompactWalletStore(poolId);
  await syncCompactStoreWithRpc({
    fetchBatch,
    store: aliceStore,
    fvk: exportFullViewingKey(alice),
  });
  const unspent1 = aliceStore.unspentNotes();
  if (unspent1.length !== 1 || unspent1[0].amount !== depositAmount) {
    throw new Error(`Expected 1 unspent note of ${depositAmount}, found ${unspent1.length}`);
  }
  const note0 = unspent1[0];
  console.log(`  Discovered Alice note: lane=${note0.laneId} leaf=${note0.leafIndex} amount=${note0.amount} (verified against SubtreePage)`);

  // 5. JoinSplit Private Transfer (Tag 6, 192 B BN254 Groth16)
  console.log('\n[5] Reconstructing witness & proving JoinSplit Private Transfer (Tag 6, 192 B Groth16 in WASM)...');
  const w1 = await reconstructWitness({
    fetchBatch,
    poolId,
    ckptSlotIdx: ck1.slotIdx,
    laneId: note0.laneId,
    leafIdx: note0.leafIndex,
  });
  const transferLane = 1;
  const [lane1Raw] = await fetchBatch([deriveLanePdaSync(poolId, transferLane, AUDREN_PROGRAM_ID).address]);
  const lane1 = decodeLaneHeader(lane1Raw);
  const trPages = await ensurePages(poolId, transferLane, lane1.nextLeaf, lane1.nfCount, 2, 1);

  const sendAmt = 2_000_000n;
  const changeAmt = depositAmount - sendAmt; // 3_000_000n
  const assetSol = deriveAssetId(NATIVE_SOL_MINT_BYTES);
  const mBob = encryptNoteMemo(bob.viewPk, new Uint8Array(randomBytes(32)), sendAmt, NATIVE_SOL_MINT_BYTES);
  const bobOwner = deriveStealthOwner(bob.spendPk, mBob.tweak);
  const mCh = encryptNoteMemo(alice.viewPk, new Uint8Array(randomBytes(32)), changeAmt, NATIVE_SOL_MINT_BYTES);
  const chOwner = deriveStealthOwner(alice.spendPk, mCh.tweak);
  const trMemos = new Uint8Array(mBob.memo90.byteLength + mCh.memo90.byteLength);
  trMemos.set(mBob.memo90, 0);
  trMemos.set(mCh.memo90, mBob.memo90.byteLength);

  const trCtx = computeJoinsplitCtxHash({
    poolId,
    outLaneId: transferLane,
    outputMask: 0b011,
    assetMode: ASSET_MODE_PRIVATE,
    unwrapWsol: false,
    recipient: null,
    relayerFeeRecipient: null,
    publicAssetId: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: trMemos,
  });

  const t0 = performance.now();
  const trProof = prover.proveJoinsplit({
    superRoot: w1.superRoot,
    txAssetId: assetSol,
    publicAssetId: 0n,
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    ctxHash: trCtx,
    omitNf1: true,
    inputs: [
      {
        isDummy: false,
        spendSk: alice.spendSk,
        tweak: frFromBeBytesStrict(note0.tweak),
        assetId: assetSol,
        amount: note0.amount,
        blinding: frFromBeBytesStrict(note0.blinding),
        merklePath: w1.path,
      },
      dummyInputWitness(alice.spendSk, assetSol, randomFr()),
    ],
    outputs: [
      { stealthOwner: bobOwner, assetId: assetSol, amount: sendAmt, blinding: mBob.blinding },
      { stealthOwner: chOwner, assetId: assetSol, amount: changeAmt, blinding: mCh.blinding },
      dummyOutputWitness(assetSol, randomFr()),
    ],
  });
  console.log(`  WASM Groth16 proof generated in ${Math.round(performance.now() - t0)} ms (${trProof.proof192.byteLength} B)`);

  const trIx = buildJoinsplitInstruction({
    payer: payerStr,
    poolId,
    ckptSlotIdx: ck1.slotIdx,
    outLaneId: transferLane,
    outSubSeq: trPages.subSeq,
    outRootSeq: trPages.rootSeq,
    outMemoSeq: trPages.memoSeq,
    outNfSeq: trPages.nfSeq,
    rollover: {
      nextSubSeq: trPages.nextSubSeq ?? null,
      nextMemoSeq: trPages.nextMemoSeq ?? null,
      nextNfSeq: trPages.nextNfSeq ?? null,
    },
    outputMask: 0b011,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: trProof.proof192,
    nf0: trProof.nf0,
    nf1: trProof.nf1,
    cm0: trProof.cm0,
    cm1: trProof.cm1,
    cm2: trProof.cm2,
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: trMemos,
  });
  const trRes = await sendV1([trIx], 260_000);
  console.log(`  JoinSplit Private Transfer confirmed: sig=${trRes.signature} slot=${trRes.slot} cu=${trRes.cu} wire=${trRes.wireBytes}B`);
  results.txs.transfer = trRes;

  // 6. PublishCheckpoint #2 + resync Alice & Bob CompactWalletStore
  console.log('\n[6] Publishing RootCheckpoint #2 & verifying NullifierPage spend detection...');
  const ck2 = await publishFreshCheckpoint(poolId, pool);
  console.log(`  PublishCheckpoint #2 confirmed: sig=${ck2.signature} slot=${ck2.slot} cu=${ck2.cu} slotIdx=${ck2.slotIdx}`);
  results.txs.checkpoint2 = ck2;

  await syncCompactStoreWithRpc({ fetchBatch, store: aliceStore, fvk: exportFullViewingKey(alice) });
  const aliceUnspent2 = aliceStore.unspentNotes();
  if (aliceUnspent2.length !== 1 || aliceUnspent2[0].amount !== changeAmt) {
    throw new Error(`Expected Alice to have 1 unspent change note (${changeAmt}), got ${aliceUnspent2.length}`);
  }
  const bobStore = new CompactWalletStore(poolId);
  await syncCompactStoreWithRpc({ fetchBatch, store: bobStore, fvk: exportFullViewingKey(bob) });
  const bobUnspent = bobStore.unspentNotes();
  if (bobUnspent.length !== 1 || bobUnspent[0].amount !== sendAmt) {
    throw new Error(`Expected Bob to receive 1 note (${sendAmt}), got ${bobUnspent.length}`);
  }
  console.log(`  CompactWalletStore verified: Alice spent note0 & holds ${changeAmt} change; Bob discovered ${sendAmt} shielded note!`);

  // 7. JoinSplit Withdraw (Tag 6, ASSET_MODE_SOL) returning Alice's 3_000_000 change note to payer
  console.log('\n[7] Proving & executing live JoinSplit Withdraw (Tag 6, ASSET_MODE_SOL)...');
  const noteChange = aliceUnspent2[0];
  const w2 = await reconstructWitness({
    fetchBatch,
    poolId,
    ckptSlotIdx: ck2.slotIdx,
    laneId: noteChange.laneId,
    leafIdx: noteChange.leafIndex,
  });
  const withdrawLane = 2;
  const [lane2Raw] = await fetchBatch([deriveLanePdaSync(poolId, withdrawLane, AUDREN_PROGRAM_ID).address]);
  const lane2 = decodeLaneHeader(lane2Raw);
  const wdPages = await ensurePages(poolId, withdrawLane, lane2.nextLeaf, lane2.nfCount, 0, 1);

  const wdCtx = computeJoinsplitCtxHash({
    poolId,
    outLaneId: withdrawLane,
    outputMask: 0,
    assetMode: ASSET_MODE_SOL,
    unwrapWsol: false,
    recipient: payerStr,
    relayerFeeRecipient: null,
    publicAssetId: frToBeBytes(assetSol),
    publicAmountOut: changeAmt,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(0),
  });
  const t1 = performance.now();
  const wdProof = prover.proveJoinsplit({
    superRoot: w2.superRoot,
    txAssetId: assetSol,
    publicAssetId: assetSol,
    publicAmountOut: changeAmt,
    relayerFeeAmount: 0n,
    ctxHash: wdCtx,
    omitNf1: true,
    inputs: [
      {
        isDummy: false,
        spendSk: alice.spendSk,
        tweak: frFromBeBytesStrict(noteChange.tweak),
        assetId: assetSol,
        amount: noteChange.amount,
        blinding: frFromBeBytesStrict(noteChange.blinding),
        merklePath: w2.path,
      },
      dummyInputWitness(alice.spendSk, assetSol, randomFr()),
    ],
    outputs: [
      dummyOutputWitness(assetSol, randomFr()),
      dummyOutputWitness(assetSol, randomFr()),
      dummyOutputWitness(assetSol, randomFr()),
    ],
  });
  console.log(`  WASM Groth16 withdraw proof generated in ${Math.round(performance.now() - t1)} ms`);

  const wdIx = buildJoinsplitInstruction({
    payer: payerStr,
    poolId,
    ckptSlotIdx: ck2.slotIdx,
    outLaneId: withdrawLane,
    outSubSeq: wdPages.subSeq,
    outRootSeq: wdPages.rootSeq,
    outMemoSeq: wdPages.memoSeq,
    outNfSeq: wdPages.nfSeq,
    rollover: {
      nextSubSeq: wdPages.nextSubSeq ?? null,
      nextMemoSeq: wdPages.nextMemoSeq ?? null,
      nextNfSeq: wdPages.nextNfSeq ?? null,
    },
    outputMask: 0,
    assetMode: ASSET_MODE_SOL,
    proof192: wdProof.proof192,
    nf0: wdProof.nf0,
    nf1: wdProof.nf1,
    cm0: wdProof.cm0,
    cm1: wdProof.cm1,
    cm2: wdProof.cm2,
    publicAmountOut: changeAmt,
    relayerFeeAmount: 0n,
    recipient: payerStr,
    memosBytes: new Uint8Array(0),
  });
  const wdRes = await sendV1([wdIx], 260_000);
  console.log(`  JoinSplit Withdraw confirmed: sig=${wdRes.signature} slot=${wdRes.slot} cu=${wdRes.cu} wire=${wdRes.wireBytes}B`);
  results.txs.withdraw = wdRes;

  console.log('\n=== SUMMARY JSON ===');
  console.log(JSON.stringify(results, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
