#!/usr/bin/env node
/**
 * Live Cluster Pool #0 Initializer & Full Empirical On-Chain Audren v1 E2E Suite.
 *
 * Uses `@audren/sdk` + `@audren/sdk/prover` (WASM) over real Solana Transaction v1 (`0x81`)
 * against Devnet or Mainnet:
 *   1. Idempotent `InitPool` (Tag 0, Pool #0, ckpt_interval=8, max_ckpt_age=1800) + `InitLane` (Tag 1, 0..=3)
 *      + idempotent canonical `vault_auth(0)` WSOL ATA creation (`CreateIdempotent`)
 *   2. Live `UpdatePool` (Tag 8) parameter check (when running as pool authority)
 *   3. Live unified `Deposit` (Tag 3, `DEPOSIT_FLAG_NATIVE_SOL` via atomic `SyncNative` WSOL)
 *      + optional SPL / Token-2022 `Deposit` when `--spl-mint` / `AUDREN_E2E_SPL_MINT` is provided
 *   4. Live `PublishCheckpoint` (Tag 4)
 *   5. Zero-indexer ordinary-RPC `CompactWalletStore` sync + `SubtreePage` & `14 B` `paymentId` verification
 *   6. Live `Transact` Private Transfer (Tag 5, `ASSET_MODE_PRIVATE`, 192 B BN254 Groth16 proved in WASM)
 *   7. Live `PublishCheckpoint` (Tag 4) + `CompactWalletStore` resync (`NullifierPage` spend detection)
 *   8. Live `Transact` Public Withdraw with `WITHDRAW_FLAG_UNWRAP_WSOL` (Tag 5, `ASSET_MODE_PUBLIC`,
 *      atomic 1-shot `audren_unwrap` PDA returning Native SOL to payer)
 *   9. Optional Mainnet `ExecViaEscrow` Jupiter Swap (Tag 6, when `--with-swap` / `AUDREN_E2E_SWAP=1`)
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
  ASSET_MODE_PUBLIC,
  AUDREN_PROGRAM_ID,
  CHECKPOINT_RING_SLOTS,
  CLASSIC_TOKEN_PROGRAM_ID,
  CompactWalletStore,
  DEFAULT_INITIAL_LANES,
  JUPITER_CPI_EXCLUDED_DEXES,
  MEMO_NOTES_PER_PAGE,
  NF_PER_PAGE,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_NULLIFIER,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  SUBROOTS_PER_PAGE,
  SUBTREE_LEAVES,
  TOKEN_2022_PROGRAM_ID,
  WSOL_MINT,
  base58Decode,
  base58Encode,
  buildCreateAtaIdempotentInstruction,
  buildDepositInstruction,
  buildExecViaEscrowInstruction,
  buildInitLaneInstruction,
  buildInitPoolInstruction,
  buildOpenPageInstruction,
  buildPublishCheckpointInstruction,
  buildTransactInstruction,
  buildUpdatePoolInstruction,
  bytes32ToFrMasked,
  compileV1Message,
  computeExecCtxHash,
  computeTransactCtxHash,
  decodeLaneHeader,
  decodePoolState,
  decodeRootCheckpoint,
  deriveAssetId,
  deriveAssociatedTokenAddressSync,
  deriveCheckpointPdaSync,
  deriveEscrowPdaSync,
  deriveKeysFromSeed,
  deriveLanePdaSync,
  deriveMemoPdaSync,
  deriveNfPagePdaSync,
  derivePoolPdaSync,
  deriveStealthOwner,
  deriveSubrootPdaSync,
  deriveSubtreePdaSync,
  deriveVaultAuthPdaSync,
  encryptNoteMemo,
  exportFullViewingKey,
  frFromBeBytesStrict,
  frToBeBytes,
  prepareDynamicSwapMemo,
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
const MAINNET_USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';

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

function argValue(flag) {
  const idx = process.argv.indexOf(flag);
  return idx !== -1 && idx + 1 < process.argv.length ? process.argv[idx + 1] : null;
}

const CLUSTER = argValue('--cluster') ?? 'devnet';
if (CLUSTER !== 'devnet' && CLUSTER !== 'mainnet') {
  throw new Error(
    'Usage: node scripts/live-cluster-e2e.mjs --cluster <devnet|mainnet> [--init-only] [--with-swap] [--spl-mint <mint>] [--spl-amount <u64>]',
  );
}
const INIT_ONLY = process.argv.includes('--init-only');
const WITH_SWAP = process.argv.includes('--with-swap') || process.env.AUDREN_E2E_SWAP === '1';
const SPL_MINT = argValue('--spl-mint') || process.env.AUDREN_E2E_SPL_MINT || null;
const SPL_AMOUNT = BigInt(argValue('--spl-amount') || process.env.AUDREN_E2E_SPL_AMOUNT || '100000');

const RPC_URL = CLUSTER === 'mainnet' ? process.env.MAINNET_RPC_URL : process.env.DEVNET_RPC_URL;
if (!RPC_URL) throw new Error(`Missing ${CLUSTER.toUpperCase()}_RPC_URL`);

const KEYPAIR_PATH = process.env.AUDREN_KEYPAIR_PATH || path.join(ROOT, '.credentials', 'funder.json');
const keyBytes = Uint8Array.from(JSON.parse(readFileSync(KEYPAIR_PATH, 'utf8')));
const secret32 = keyBytes.subarray(0, 32);
const payerPubkey = ed25519.getPublicKey(secret32);
const payerStr = base58Encode(payerPubkey);
const wsolMintBytes = base58Decode(WSOL_MINT);

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function randomFr() {
  return bytes32ToFrMasked(new Uint8Array(randomBytes(32)));
}

function bytesEqual(a, b) {
  if (!a || !b || a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
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

async function sendV1(
  ixs,
  computeUnitLimit = 300_000,
  priorityFeeLamports = 25_000n,
  preflightCommitment = 'confirmed',
) {
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
    { encoding: 'base64', preflightCommitment, maxRetries: 4 },
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

async function ensureAtaExists(owner, mint, tokenProgram = CLASSIC_TOKEN_PROGRAM_ID) {
  const ata = deriveAssociatedTokenAddressSync(owner, mint, tokenProgram).address;
  const [raw] = await fetchBatch([ata]);
  if (raw) return { ata, created: false };
  const ix = buildCreateAtaIdempotentInstruction({
    payer: payerStr,
    ata,
    owner,
    mint,
    tokenProgram,
  });
  const res = await sendV1([ix], 80_000);
  return { ata, created: true, tx: res };
}

async function publishFreshCheckpoint(poolId, pool) {
  for (let attempt = 0; attempt < 25; attempt++) {
    const curSlot = await rpc('getSlot', [{ commitment: 'processed' }]);
    const rem = BigInt(curSlot) % pool.ckptInterval;
    if (pool.ckptInterval <= 16n && rem >= pool.ckptInterval - 3n) {
      await sleep(Number(pool.ckptInterval - rem) * 420 + 150);
      continue;
    }
    const epoch = BigInt(curSlot) / pool.ckptInterval;
    const slotIdx = Number(epoch % BigInt(CHECKPOINT_RING_SLOTS));
    const ckptPda = deriveCheckpointPdaSync(poolId, slotIdx, AUDREN_PROGRAM_ID).address;
    const [existingRaw] = await fetchBatch([ckptPda]);
    if (existingRaw) {
      const existing = decodeRootCheckpoint(existingRaw);
      const curSlotBig = BigInt(curSlot);
      if (existing.epochId >= epoch || curSlotBig <= existing.publishedSlot + pool.maxCkptAge) {
        const nextEpochSlot = (epoch + 1n) * pool.ckptInterval;
        const waitSlots = Number(nextEpochSlot - curSlotBig) + 1;
        await sleep(Math.max(800, waitSlots * 420));
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
      // Match the `processed` slot used to derive `slotIdx` so preflight never lags across an 8-slot boundary.
      const res = await sendV1([ix], 120_000, 50_000n, 'processed');
      return { ...res, slotIdx, epoch };
    } catch (err) {
      if (
        String(err).includes('Custom') ||
        String(err).includes('InvalidPda') ||
        String(err).includes('CheckpointTooSoon') ||
        String(err).includes('custom program error')
      ) {
        await sleep(700);
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

async function fetchJupiterSwapRoute({ inputMint, outputMint, amount, slippageBps, escrowAddress }) {
  const base = (process.env.JUPITER_API_URL || 'https://api.jup.ag/swap/v1').replace(/\/$/, '');
  const headers = { 'content-type': 'application/json' };
  if (process.env.JUPITER_API_KEY) {
    headers['x-api-key'] = process.env.JUPITER_API_KEY;
  }
  const qs = new URLSearchParams({
    inputMint,
    outputMint,
    amount: amount.toString(),
    slippageBps: String(slippageBps),
    maxAccounts: '20',
    onlyDirectRoutes: 'true',
    excludeDexes: JUPITER_CPI_EXCLUDED_DEXES.join(','),
  });
  const quoteRes = await fetch(`${base}/quote?${qs.toString()}`, { headers });
  if (!quoteRes.ok) {
    throw new Error(`Jupiter /quote failed: HTTP ${quoteRes.status}`);
  }
  const quote = await quoteRes.json();
  const swapRes = await fetch(`${base}/swap-instructions`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      quoteResponse: quote,
      userPublicKey: escrowAddress,
      wrapAndUnwrapSol: false,
      useSharedAccounts: false,
      dynamicComputeUnitLimit: false,
      skipUserAccountsRpcCalls: true,
    }),
  });
  if (!swapRes.ok) {
    throw new Error(`Jupiter /swap-instructions failed: HTTP ${swapRes.status}`);
  }
  const swap = await swapRes.json();
  return { quote, swap };
}

async function main() {
  const poolId = 0;
  const poolPda = derivePoolPdaSync(poolId, AUDREN_PROGRAM_ID).address;
  const vaultAuthPda = deriveVaultAuthPdaSync(poolId, AUDREN_PROGRAM_ID).address;
  const vaultWsolAta = deriveAssociatedTokenAddressSync(
    vaultAuthPda,
    WSOL_MINT,
    CLASSIC_TOKEN_PROGRAM_ID,
  ).address;
  const bal = await rpc('getBalance', [payerStr, { commitment: 'confirmed' }]);

  console.log(`\n=== Audren v1 Live Empirical E2E (${CLUSTER.toUpperCase()}) ===`);
  console.log(`Program ID     : ${AUDREN_PROGRAM_ID}`);
  console.log(`Pool #0 PDA    : ${poolPda}`);
  console.log(`Vault Auth PDA : ${vaultAuthPda}`);
  console.log(`Vault WSOL ATA : ${vaultWsolAta}`);
  console.log(`Authority      : ${payerStr} (${(bal.value / 1e9).toFixed(4)} SOL)`);

  const results = { cluster: CLUSTER, poolPda, vaultAuthPda, vaultWsolAta, txs: {} };

  // 1. Idempotent InitPool (Tag 0) + InitLane 0..3 (Tag 1) + canonical vault_auth(0) WSOL ATA
  let [poolRaw] = await fetchBatch([poolPda]);
  if (!poolRaw) {
    console.log(
      '\n[1] Initializing Pool #0 (ckpt_interval=8, max_ckpt_age=1800, note_rent_fee=1_000_000, nf_rent_fee=120_000)...',
    );
    const initPoolIx = buildInitPoolInstruction({
      payer: payerStr,
      poolId,
      ckptInterval: 8n,
      maxCkptAge: 1800n,
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
  console.log(
    `  Pool state: version=${pool.version}, active_lanes=${pool.activeLanes}, paused=${pool.paused}, ` +
      `ckpt_interval=${pool.ckptInterval}, max_ckpt_age=${pool.maxCkptAge}, ` +
      `note_rent_fee=${pool.noteRentFee}, nf_rent_fee=${pool.nfRentFee}`,
  );

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

  const wsolAtaRes = await ensureAtaExists(vaultAuthPda, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID);
  if (wsolAtaRes.created) {
    console.log(
      `  Created canonical vault_auth(0) WSOL ATA: ${wsolAtaRes.ata} (sig=${wsolAtaRes.tx.signature})`,
    );
    results.txs.createVaultWsolAta = wsolAtaRes.tx;
  } else {
    console.log(`  Canonical vault_auth(0) WSOL ATA ready: ${wsolAtaRes.ata}`);
  }

  // Optional UpdatePool (Tag 8) no-op params verification if signer is pool authority
  // (`ckpt_interval` is immutable after InitPool and MUST remain equal to `pool.ckptInterval`).
  if (pool.authority === payerStr && !INIT_ONLY) {
    console.log('\n[1b] Verifying UpdatePool (Tag 8, params no-op)...');
    const updIx = buildUpdatePoolInstruction({
      signer: payerStr,
      poolId,
      action: {
        kind: 'params',
        ckptInterval: pool.ckptInterval,
        maxCkptAge: pool.maxCkptAge,
        noteRentFee: pool.noteRentFee,
        nfRentFee: pool.nfRentFee,
      },
    });
    const updRes = await sendV1([updIx], 80_000);
    console.log(`  UpdatePool confirmed: sig=${updRes.signature} slot=${updRes.slot} cu=${updRes.cu}`);
    results.txs.updatePool = updRes;
  }

  if (INIT_ONLY) {
    const ck = await publishFreshCheckpoint(poolId, pool);
    console.log(`  Initial PublishCheckpoint (Tag 4): sig=${ck.signature} slot=${ck.slot} cu=${ck.cu}`);
    results.txs.initialCheckpoint = ck;
    console.log('\n=== INIT SUMMARY JSON ===');
    console.log(JSON.stringify(results, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2));
    return;
  }

  // Load WASM Groth16 prover
  const wasmPath = path.join(ROOT, 'packages', 'sdk', 'wasm', 'audren_circuits.wasm');
  const prover = await AudrenWasmProver.init({ wasmBytes: readFileSync(wasmPath) });

  // Fresh ephemeral test wallets for this empirical run
  const alice = deriveKeysFromSeed(new Uint8Array(randomBytes(32)));
  const bob = deriveKeysFromSeed(new Uint8Array(randomBytes(32)));
  console.log(`  Alice aud1 address: ${alice.address}`);
  console.log(`  Bob   aud1 address: ${bob.address}`);
  const depositAmount = 5_000_000n; // 0.005 SOL

  // 2. Unified Deposit (Tag 3, DEPOSIT_FLAG_NATIVE_SOL) into Lane 0
  const depositLane = 0;
  const [lane0Raw] = await fetchBatch([deriveLanePdaSync(poolId, depositLane, AUDREN_PROGRAM_ID).address]);
  const lane0 = decodeLaneHeader(lane0Raw);
  const depPages = await ensurePages(poolId, depositLane, lane0.nextLeaf, lane0.nfCount);
  const depPaymentId = new Uint8Array(randomBytes(14));
  const depMemo = encryptNoteMemo(
    alice.viewPk,
    new Uint8Array(randomBytes(32)),
    depositAmount,
    wsolMintBytes,
    depPaymentId,
  );
  const depOwner = deriveStealthOwner(alice.spendPk, depMemo.tweak);
  const depIx = buildDepositInstruction({
    depositor: payerStr,
    poolId,
    laneId: depositLane,
    subPageSeq: depPages.subSeq,
    rootPageSeq: depPages.rootSeq,
    memoPageSeq: depPages.memoSeq,
    nativeSol: true,
    rollover: {
      nextSubSeq: depPages.nextSubSeq ?? null,
      nextMemoSeq: depPages.nextMemoSeq ?? null,
    },
    amount: depositAmount,
    stealthOwner: depOwner,
    blinding: depMemo.blinding,
    memo: depMemo.memo,
  });
  console.log('\n[2] Executing live Deposit (0.005 Native SOL -> SyncNative WSOL, Tag 3)...');
  const depRes = await sendV1([depIx], 180_000);
  console.log(`  Deposit (Native SOL) confirmed: sig=${depRes.signature} slot=${depRes.slot} cu=${depRes.cu} wire=${depRes.wireBytes}B`);
  results.txs.depositNativeSol = depRes;

  // 2b. Optional SPL / Token-2022 Deposit (Tag 3) when configured
  if (SPL_MINT) {
    console.log(`\n[2b] Executing live SPL / Token-2022 Deposit (${SPL_MINT}, amount=${SPL_AMOUNT}, Tag 3)...`);
    const mintInfo = await rpc('getAccountInfo', [SPL_MINT, { encoding: 'base64', commitment: 'confirmed' }]);
    if (!mintInfo?.value) throw new Error(`Configured --spl-mint ${SPL_MINT} does not exist on ${CLUSTER}`);
    const tokenProgram =
      mintInfo.value.owner === TOKEN_2022_PROGRAM_ID
        ? TOKEN_2022_PROGRAM_ID
        : CLASSIC_TOKEN_PROGRAM_ID;
    await ensureAtaExists(vaultAuthPda, SPL_MINT, tokenProgram);
    const depositorAta = deriveAssociatedTokenAddressSync(payerStr, SPL_MINT, tokenProgram).address;
    const [lane0NowRaw] = await fetchBatch([deriveLanePdaSync(poolId, depositLane, AUDREN_PROGRAM_ID).address]);
    const lane0Now = decodeLaneHeader(lane0NowRaw);
    const splPages = await ensurePages(poolId, depositLane, lane0Now.nextLeaf, lane0Now.nfCount);
    const splMemo = encryptNoteMemo(
      bob.viewPk,
      new Uint8Array(randomBytes(32)),
      SPL_AMOUNT,
      base58Decode(SPL_MINT),
    );
    const splOwner = deriveStealthOwner(bob.spendPk, splMemo.tweak);
    const splDepIx = buildDepositInstruction({
      depositor: payerStr,
      poolId,
      laneId: depositLane,
      subPageSeq: splPages.subSeq,
      rootPageSeq: splPages.rootSeq,
      memoPageSeq: splPages.memoSeq,
      nativeSol: false,
      mint: SPL_MINT,
      sourceAccount: depositorAta,
      tokenProgram,
      rollover: {
        nextSubSeq: splPages.nextSubSeq ?? null,
        nextMemoSeq: splPages.nextMemoSeq ?? null,
      },
      amount: SPL_AMOUNT,
      stealthOwner: splOwner,
      blinding: splMemo.blinding,
      memo: splMemo.memo,
    });
    const splDepRes = await sendV1([splDepIx], 200_000);
    console.log(`  Deposit (SPL/T22) confirmed: sig=${splDepRes.signature} slot=${splDepRes.slot} cu=${splDepRes.cu}`);
    results.txs.depositSpl = splDepRes;
  }

  // 3. PublishCheckpoint (Tag 4)
  console.log('\n[3] Publishing fresh RootCheckpoint (Tag 4)...');
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
  if (!bytesEqual(note0.paymentId, depPaymentId)) {
    throw new Error('Decrypted note0 paymentId mismatch');
  }
  console.log(
    `  Discovered Alice note: lane=${note0.laneId} leaf=${note0.leafIndex} amount=${note0.amount} (SubtreePage + 14 B paymentId verified)`,
  );

  // 5. Transact Private Transfer (Tag 5, ASSET_MODE_PRIVATE, 192 B BN254 Groth16)
  console.log('\n[5] Reconstructing witness & proving Transact Private Transfer (Tag 5, 192 B Groth16 in WASM)...');
  const w1 = await reconstructWitness({
    fetchBatch,
    poolId,
    ckptSlotIdx: ck1.slotIdx,
    laneId: note0.laneId,
    leafIdx: note0.leafIndex,
    viewSk: alice.viewSk,
  });
  const transferLane = 1;
  const [lane1Raw] = await fetchBatch([deriveLanePdaSync(poolId, transferLane, AUDREN_PROGRAM_ID).address]);
  const lane1 = decodeLaneHeader(lane1Raw);
  const trPages = await ensurePages(poolId, transferLane, lane1.nextLeaf, lane1.nfCount, 2, 1);

  const sendAmt = 2_000_000n;
  const changeAmt = depositAmount - sendAmt; // 3_000_000n
  const assetWsol = deriveAssetId(wsolMintBytes);
  const bobPaymentId = new Uint8Array(randomBytes(14));
  const mBob = encryptNoteMemo(
    bob.viewPk,
    new Uint8Array(randomBytes(32)),
    sendAmt,
    wsolMintBytes,
    bobPaymentId,
  );
  const bobOwner = deriveStealthOwner(bob.spendPk, mBob.tweak);
  const mCh = encryptNoteMemo(alice.viewPk, new Uint8Array(randomBytes(32)), changeAmt, wsolMintBytes);
  const chOwner = deriveStealthOwner(alice.spendPk, mCh.tweak);
  const trMemos = new Uint8Array(mBob.memo.byteLength + mCh.memo.byteLength);
  trMemos.set(mBob.memo, 0);
  trMemos.set(mCh.memo, mBob.memo.byteLength);

  const trCtx = computeTransactCtxHash({
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
    txAssetId: assetWsol,
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
        assetId: assetWsol,
        amount: note0.amount,
        blinding: frFromBeBytesStrict(note0.blinding),
        merklePath: w1.path,
      },
      dummyInputWitness(alice.spendSk, assetWsol, randomFr()),
    ],
    outputs: [
      { stealthOwner: bobOwner, assetId: assetWsol, amount: sendAmt, blinding: mBob.blinding },
      { stealthOwner: chOwner, assetId: assetWsol, amount: changeAmt, blinding: mCh.blinding },
      dummyOutputWitness(assetWsol, randomFr()),
    ],
  });
  console.log(`  WASM Groth16 proof generated in ${Math.round(performance.now() - t0)} ms (${trProof.proof192.byteLength} B)`);

  const trIx = buildTransactInstruction({
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
  console.log(`  Transact Private Transfer confirmed: sig=${trRes.signature} slot=${trRes.slot} cu=${trRes.cu} wire=${trRes.wireBytes}B`);
  results.txs.transfer = trRes;

  // 6. PublishCheckpoint #2 (Tag 4) + resync Alice & Bob CompactWalletStore
  console.log('\n[6] Publishing RootCheckpoint #2 (Tag 4) & verifying NullifierPage spend detection...');
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
  const bobWsolNotes = bobStore.unspentNotes().filter((n) => bytesEqual(n.mint, wsolMintBytes));
  if (bobWsolNotes.length !== 1 || bobWsolNotes[0].amount !== sendAmt) {
    throw new Error(`Expected Bob to receive 1 WSOL note (${sendAmt}), got ${bobWsolNotes.length}`);
  }
  if (!bytesEqual(bobWsolNotes[0].paymentId, bobPaymentId)) {
    throw new Error('Decrypted Bob note paymentId mismatch');
  }
  console.log(
    `  CompactWalletStore verified: Alice spent note0 & holds ${changeAmt} change; Bob discovered ${sendAmt} shielded note + paymentId!`,
  );

  // 7. Transact Public Withdraw with WITHDRAW_FLAG_UNWRAP_WSOL (Tag 5, ASSET_MODE_PUBLIC)
  console.log('\n[7] Proving & executing live Transact Withdraw + WITHDRAW_FLAG_UNWRAP_WSOL (Tag 5, ASSET_MODE_PUBLIC)...');
  const noteChange = aliceUnspent2[0];
  const w2 = await reconstructWitness({
    fetchBatch,
    poolId,
    ckptSlotIdx: ck2.slotIdx,
    laneId: noteChange.laneId,
    leafIdx: noteChange.leafIndex,
    viewSk: alice.viewSk,
  });
  const withdrawLane = 2;
  const [lane2Raw] = await fetchBatch([deriveLanePdaSync(poolId, withdrawLane, AUDREN_PROGRAM_ID).address]);
  const lane2 = decodeLaneHeader(lane2Raw);
  const wdPages = await ensurePages(poolId, withdrawLane, lane2.nextLeaf, lane2.nfCount, 0, 1);

  const wdCtx = computeTransactCtxHash({
    poolId,
    outLaneId: withdrawLane,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: true,
    recipient: payerStr,
    relayerFeeRecipient: null,
    publicAssetId: frToBeBytes(assetWsol),
    publicAmountOut: changeAmt,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(0),
  });
  const t1 = performance.now();
  const wdProof = prover.proveJoinsplit({
    superRoot: w2.superRoot,
    txAssetId: assetWsol,
    publicAssetId: assetWsol,
    publicAmountOut: changeAmt,
    relayerFeeAmount: 0n,
    ctxHash: wdCtx,
    omitNf1: true,
    inputs: [
      {
        isDummy: false,
        spendSk: alice.spendSk,
        tweak: frFromBeBytesStrict(noteChange.tweak),
        assetId: assetWsol,
        amount: noteChange.amount,
        blinding: frFromBeBytesStrict(noteChange.blinding),
        merklePath: w2.path,
      },
      dummyInputWitness(alice.spendSk, assetWsol, randomFr()),
    ],
    outputs: [
      dummyOutputWitness(assetWsol, randomFr()),
      dummyOutputWitness(assetWsol, randomFr()),
      dummyOutputWitness(assetWsol, randomFr()),
    ],
  });
  console.log(`  WASM Groth16 withdraw proof generated in ${Math.round(performance.now() - t1)} ms`);

  const wdIx = buildTransactInstruction({
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
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: true,
    publicOutflow: { mint: WSOL_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
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
  const wdRes = await sendV1([wdIx], 280_000);
  console.log(`  Transact Withdraw (Unwrap WSOL -> Native SOL) confirmed: sig=${wdRes.signature} slot=${wdRes.slot} cu=${wdRes.cu} wire=${wdRes.wireBytes}B`);
  results.txs.withdrawUnwrapSol = wdRes;

  // 8. Optional ExecViaEscrow (Tag 6) Jupiter Swap on Mainnet
  if (WITH_SWAP && CLUSTER === 'mainnet') {
    const swapOutMint = process.env.AUDREN_E2E_SWAP_OUT_MINT || MAINNET_USDC_MINT;
    const escrowShard = 0;
    const swapLane = 3;
    const escrowPda = deriveEscrowPdaSync(poolId, escrowShard, AUDREN_PROGRAM_ID).address;
    console.log(`\n[8] Executing live ExecViaEscrow Jupiter Swap (Tag 6, WSOL -> ${swapOutMint}, shard=${escrowShard})...`);

    await ensureAtaExists(vaultAuthPda, swapOutMint, CLASSIC_TOKEN_PROGRAM_ID);
    const { ata: escrowInAta } = await ensureAtaExists(escrowPda, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID);
    const { ata: escrowOutAta } = await ensureAtaExists(escrowPda, swapOutMint, CLASSIC_TOKEN_PROGRAM_ID);

    const bobNote = bobWsolNotes[0];
    const w3 = await reconstructWitness({
      fetchBatch,
      poolId,
      ckptSlotIdx: ck2.slotIdx,
      laneId: bobNote.laneId,
      leafIdx: bobNote.leafIndex,
      viewSk: bob.viewSk,
    });
    const [lane3Raw] = await fetchBatch([deriveLanePdaSync(poolId, swapLane, AUDREN_PROGRAM_ID).address]);
    const lane3 = decodeLaneHeader(lane3Raw);
    const swPages = await ensurePages(poolId, swapLane, lane3.nextLeaf, lane3.nfCount, 1, 1);

    const { quote, swap } = await fetchJupiterSwapRoute({
      inputMint: WSOL_MINT,
      outputMint: swapOutMint,
      amount: bobNote.amount,
      slippageBps: 200,
      escrowAddress: escrowPda,
    });
    const minAmountOut = (BigInt(quote.otherAmountThreshold || quote.outAmount) * 95n) / 100n;
    const outMintBytes = base58Decode(swapOutMint);
    const assetOut = deriveAssetId(outMintBytes);
    const dyn = prepareDynamicSwapMemo(bob.viewPk, new Uint8Array(randomBytes(32)));
    const swapOutOwner = frToBeBytes(deriveStealthOwner(bob.spendPk, dyn.tweak));
    const swapOutBlinding = frToBeBytes(dyn.blinding);
    const routerIxData = fromBase64(swap.swapInstruction.data);
    const routerAccounts = swap.swapInstruction.accounts;

    const execCtx = computeExecCtxHash({
      poolId,
      outLaneId: swapLane,
      escrowShard,
      changeMask: 0,
      feeOnOutput: false,
      assetIn: frToBeBytes(assetWsol),
      amountIn: bobNote.amount,
      relayerFeeAmount: 0n,
      relayerFeeRecipient: null,
      assetOut: frToBeBytes(assetOut),
      minAmountOut,
      routerProg: swap.swapInstruction.programId,
      routerAccounts,
      extraWritablePubkeys: [payerStr, escrowInAta, escrowOutAta],
      outStealthOwner: swapOutOwner,
      outBlinding: swapOutBlinding,
      dynMemoHead: dyn.dynHead34,
      dynMemoMask: dyn.dynMask72,
      routerIxData,
      changeMemos: new Uint8Array(0),
    });

    const t2 = performance.now();
    const swProof = prover.proveJoinsplit({
      superRoot: w3.superRoot,
      txAssetId: assetWsol,
      publicAssetId: assetWsol,
      publicAmountOut: bobNote.amount,
      relayerFeeAmount: 0n,
      ctxHash: execCtx,
      omitNf1: true,
      inputs: [
        {
          isDummy: false,
          spendSk: bob.spendSk,
          tweak: frFromBeBytesStrict(bobNote.tweak),
          assetId: assetWsol,
          amount: bobNote.amount,
          blinding: frFromBeBytesStrict(bobNote.blinding),
          merklePath: w3.path,
        },
        dummyInputWitness(bob.spendSk, assetWsol, randomFr()),
      ],
      outputs: [
        dummyOutputWitness(assetWsol, randomFr()),
        dummyOutputWitness(assetWsol, randomFr()),
        dummyOutputWitness(assetWsol, randomFr()),
      ],
    });
    console.log(`  WASM Groth16 swap proof generated in ${Math.round(performance.now() - t2)} ms`);

    const execIx = buildExecViaEscrowInstruction({
      payer: payerStr,
      poolId,
      ckptSlotIdx: ck2.slotIdx,
      outLaneId: swapLane,
      outSubSeq: swPages.subSeq,
      outRootSeq: swPages.rootSeq,
      outMemoSeq: swPages.memoSeq,
      outNfSeq: swPages.nfSeq,
      escrowShard,
      changeMask: 0,
      feeOnOutput: false,
      inLeg: { mint: WSOL_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
      outLeg: { mint: swapOutMint, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
      relayerFeeAmount: 0n,
      rollover: {
        nextSubSeq: swPages.nextSubSeq ?? null,
        nextMemoSeq: swPages.nextMemoSeq ?? null,
        nextNfSeq: swPages.nextNfSeq ?? null,
      },
      proof192: swProof.proof192,
      nf0: swProof.nf0,
      nf1: swProof.nf1,
      cm0: swProof.cm0,
      cm1: swProof.cm1,
      cm2: swProof.cm2,
      amountIn: bobNote.amount,
      minAmountOut,
      outStealthOwner: swapOutOwner,
      outBlinding: swapOutBlinding,
      dynMemoHead: dyn.dynHead34,
      dynMemoMask: dyn.dynMask72,
      routerProg: swap.swapInstruction.programId,
      routerIxData,
      routerAccounts,
      changeMemos: new Uint8Array(0),
    });
    const swRes = await sendV1([execIx], 900_000);
    console.log(`  ExecViaEscrow Jupiter Swap confirmed: sig=${swRes.signature} slot=${swRes.slot} cu=${swRes.cu} wire=${swRes.wireBytes}B`);
    results.txs.execViaEscrowSwap = swRes;

    const ck3 = await publishFreshCheckpoint(poolId, pool);
    results.txs.checkpoint3 = ck3;
    await syncCompactStoreWithRpc({ fetchBatch, store: bobStore, fvk: exportFullViewingKey(bob) });
    const bobOutNotes = bobStore.unspentNotes().filter((n) => bytesEqual(n.mint, outMintBytes));
    if (bobOutNotes.length !== 1 || bobOutNotes[0].amount < minAmountOut) {
      throw new Error(`Expected Bob to discover swapped output note >= ${minAmountOut}, found ${bobOutNotes.length}`);
    }
    console.log(
      `  CompactWalletStore verified: Bob discovered dynamic AUD1DYN1 output note (${bobOutNotes[0].amount} base units of ${swapOutMint})!`,
    );
  } else if (WITH_SWAP) {
    console.log('\n[8] Skipping --with-swap (Jupiter live swap requires --cluster mainnet).');
  }

  console.log('\n=== SUMMARY JSON ===');
  console.log(JSON.stringify(results, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
