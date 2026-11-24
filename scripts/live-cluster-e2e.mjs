#!/usr/bin/env node
/**
 * Live Cluster Pool #0 Initializer, v1.3.0 `GlobalRootHistory` Migrator & Full Empirical On-Chain E2E Suite.
 *
 * Uses `@audren/sdk` + `@audren/sdk/prover` (WASM) over real Solana Transaction v1 (`0x81`)
 * against Devnet or Mainnet:
 *   1. Idempotent `InitPool` (Tag 0, Pool #0, `root_epoch_interval=32`, atomically initializes
 *      `GlobalRootHistory` PDA `249YJTuRtiKAnh346Tc18kF9bHrktdrTzyJMtvUKUgC7`) + `InitLane`
 *      (Tag 1, 0..=3) + idempotent `InitRootHistory` (Tag 4, one-shot upgrade via `--init-root-history`)
 *      + idempotent canonical `vault_auth(0)` WSOL ATA creation (`CreateIdempotent`)
 *   2. Live `UpdatePool` (Tag 8) parameter check (when running as pool authority)
 *   3. Live unified `Deposit` (Tag 3, `DEPOSIT_FLAG_NATIVE_SOL` via atomic `SyncNative` WSOL)
 *      + inline zero-crank auto-`OpenPage` pre-instructions + optional SPL / Token-2022 `Deposit`
 *   4. Zero-indexer ordinary-RPC `CompactWalletStore` sync + immediate `GlobalRootHistory` fetch
 *      (`finalized`-first + `confirmed`-fallback, verifying instant spendability with zero crank tx)
 *   5. Live `Transact` Private Transfer (Tag 5, `ASSET_MODE_PRIVATE`, 192 B BN254 Groth16 in WASM,
 *      dual-ring `(rootRingKind, rootRingIdx)` + inline root history update + calibrated tight CU)
 *   6. Immediate `CompactWalletStore` resync (`NullifierPage` spend detection + recipient discovery)
 *   7. Live `Transact` Public Withdraw Full Exit with `WITHDRAW_FLAG_UNWRAP_WSOL` (Tag 5,
 *      `ASSET_MODE_PUBLIC`, `outputMask=0` with read-only `GlobalRootHistory` at account `[2]`,
 *      atomic 1-shot `audren_unwrap` PDA returning Native SOL to payer)
 *   8. Optional Mainnet `ExecViaEscrow` Jupiter Swap (Tag 6, when `--with-swap` / `AUDREN_E2E_SWAP=1`)
 *   9. Optional frozen `v1.3.0` Pool #0 ALT creation (`--create-pool0-alt`: 73 entries = 40 base +
 *      `GlobalRootHistory` + 16 escrow WSOL ATAs + 16 escrow USDC ATAs, extended in batches of `<= 25`
 *      and permanently frozen)
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
  ASSOCIATED_TOKEN_PROGRAM_ID,
  AUDREN_PROGRAM_ID,
  CLASSIC_TOKEN_PROGRAM_ID,
  CU_LIMIT_INIT_LANE,
  CU_LIMIT_INIT_POOL,
  CU_LIMIT_INIT_ROOT_HISTORY,
  CU_LIMIT_OPEN_PAGE,
  CompactWalletStore,
  DEFAULT_INITIAL_LANES,
  DEFAULT_ROOT_EPOCH_INTERVAL,
  JUPITER_CPI_EXCLUDED_DEXES,
  NUM_ESCROW_SHARDS,
  ROOT_RING_EPOCH,
  ROOT_RING_SLOT,
  SYSTEM_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  WSOL_MINT,
  base58Decode,
  base58Encode,
  buildAutoOpenPageInstructions,
  buildCreateAtaIdempotentInstruction,
  buildDepositInstruction,
  buildExecViaEscrowInstruction,
  buildInitLaneInstruction,
  buildInitPoolInstruction,
  buildInitRootHistoryInstruction,
  buildTransactInstruction,
  buildUpdatePoolInstruction,
  bytes32ToFrMasked,
  compileV1Message,
  computeExecCtxHash,
  computePageRollovers,
  computeTransactCtxHash,
  decodeGlobalRootHistory,
  decodeLaneHeader,
  decodePoolState,
  deriveAssetId,
  deriveAssociatedTokenAddressSync,
  deriveEscrowPdaSync,
  deriveKeysFromSeed,
  deriveLanePdaSync,
  deriveLaneRentVaultPdaSync,
  derivePoolPdaSync,
  deriveRootsPdaSync,
  deriveStealthOwner,
  deriveSubrootPdaSync,
  deriveVaultAuthPdaSync,
  encryptNoteMemo,
  exportFullViewingKey,
  fetchGlobalRootHistory,
  findProgramAddressSync,
  frFromBeBytesStrict,
  frToBeBytes,
  planAutoOpenPages,
  prepareDynamicSwapMemo,
  recommendedDepositCuLimit,
  recommendedExecViaEscrowCuLimit,
  recommendedTransactCuLimit,
  reconstructWitness,
  selectRootSnapshotForNotes,
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
const DEVNET_USDC_MINT = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
const COMPUTE_BUDGET_PROGRAM_ID = 'ComputeBudget111111111111111111111111111111';
const ADDRESS_LOOKUP_TABLE_PROGRAM_ID = 'AddressLookupTab1e1111111111111111111111111';
const ALT_EXTEND_BATCH_SIZE = 25;
const ALT_META_SIZE = 56;

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
    'Usage: node scripts/live-cluster-e2e.mjs --cluster <devnet|mainnet> [--init-root-history] [--create-pool0-alt] [--root-epoch-interval <u64>] [--init-only] [--with-swap] [--spl-mint <mint>] [--spl-amount <u64>]',
  );
}
const INIT_ROOT_HISTORY = process.argv.includes('--init-root-history');
const CREATE_POOL0_ALT = process.argv.includes('--create-pool0-alt');
const ROOT_EPOCH_INTERVAL = BigInt(
  argValue('--root-epoch-interval') || DEFAULT_ROOT_EPOCH_INTERVAL.toString(),
);
const INIT_ONLY = process.argv.includes('--init-only');
const WITH_SWAP = process.argv.includes('--with-swap') || process.env.AUDREN_E2E_SWAP === '1';
const SPL_MINT = argValue('--spl-mint') || process.env.AUDREN_E2E_SPL_MINT || null;
const SPL_AMOUNT = BigInt(argValue('--spl-amount') || process.env.AUDREN_E2E_SPL_AMOUNT || '100000');
const PROGRAM_ID = process.env.AUDREN_PROGRAM_ID?.trim() || AUDREN_PROGRAM_ID;
if (base58Decode(PROGRAM_ID).byteLength !== 32) {
  throw new Error(`Invalid AUDREN_PROGRAM_ID (expected 32-byte base58 pubkey): ${PROGRAM_ID}`);
}

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

function ringName(ringKind) {
  if (ringKind === ROOT_RING_EPOCH) return 'EPOCH';
  if (ringKind === ROOT_RING_SLOT) return 'SLOT';
  return `UNKNOWN(${ringKind})`;
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

function makeFetchBatch(commitment) {
  return async (addresses, options) => {
    const out = new Array(addresses.length).fill(null);
    const cfg = { encoding: 'base64', commitment };
    if (options?.dataSlice) {
      cfg.dataSlice = {
        offset: options.dataSlice.offset,
        length: options.dataSlice.length,
      };
    }
    for (let off = 0; off < addresses.length; off += 100) {
      const chunk = addresses.slice(off, off + 100);
      const res = await rpc('getMultipleAccounts', [chunk, cfg]);
      for (let i = 0; i < chunk.length; i++) {
        const d = res.value[i]?.data?.[0];
        out[off + i] = d ? fromBase64(d) : null;
      }
    }
    return out;
  };
}

const fetchBatchConfirmed = makeFetchBatch('confirmed');
const fetchBatchFinalized = makeFetchBatch('finalized');
const fetchBatch = fetchBatchConfirmed;

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
  computeUnitLimit = 235_000,
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

/**
 * Build the canonical 73-entry `v1.3.0` Pool #0 Address Lookup Table entries:
 *   - 40 canonical base entries (program, pool, vault_auth, vault WSOL/USDC ATAs, core programs,
 *     WSOL/USDC mints, lanes 0..3 + LaneRentVault 0..3 + SubtreeRootPage(0) 0..3, escrows 0..15)
 *   - + 1 `GlobalRootHistory` PDA (`249YJTuRtiKAnh346Tc18kF9bHrktdrTzyJMtvUKUgC7`)
 *   - + 16 canonical Pool #0 escrow WSOL ATAs (`shard 0..15`)
 *   - + 16 canonical Pool #0 escrow USDC ATAs (`shard 0..15`)
 */
function buildPool0AltEntries(cluster) {
  const poolId = 0;
  const usdcMint = cluster === 'mainnet' ? MAINNET_USDC_MINT : DEVNET_USDC_MINT;
  const poolPda = derivePoolPdaSync(poolId, PROGRAM_ID).address;
  const vaultAuthPda = deriveVaultAuthPdaSync(poolId, PROGRAM_ID).address;
  const rootsPda = deriveRootsPdaSync(poolId, PROGRAM_ID).address;
  const vaultWsolAta = deriveAssociatedTokenAddressSync(
    vaultAuthPda,
    WSOL_MINT,
    CLASSIC_TOKEN_PROGRAM_ID,
  ).address;
  const vaultUsdcAta = deriveAssociatedTokenAddressSync(
    vaultAuthPda,
    usdcMint,
    CLASSIC_TOKEN_PROGRAM_ID,
  ).address;

  const entries = [
    PROGRAM_ID,
    poolPda,
    vaultAuthPda,
    vaultWsolAta,
    vaultUsdcAta,
    SYSTEM_PROGRAM_ID,
    CLASSIC_TOKEN_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID,
    ASSOCIATED_TOKEN_PROGRAM_ID,
    COMPUTE_BUDGET_PROGRAM_ID,
    WSOL_MINT,
    usdcMint,
  ];
  for (let lane = 0; lane < DEFAULT_INITIAL_LANES; lane++) {
    entries.push(deriveLanePdaSync(poolId, lane, PROGRAM_ID).address);
    entries.push(deriveLaneRentVaultPdaSync(poolId, lane, PROGRAM_ID).address);
    entries.push(deriveSubrootPdaSync(poolId, lane, 0n, PROGRAM_ID).address);
  }
  const escrowPdas = [];
  for (let shard = 0; shard < NUM_ESCROW_SHARDS; shard++) {
    const escrow = deriveEscrowPdaSync(poolId, shard, PROGRAM_ID).address;
    escrowPdas.push(escrow);
    entries.push(escrow);
  }
  entries.push(rootsPda);
  for (const escrow of escrowPdas) {
    entries.push(
      deriveAssociatedTokenAddressSync(escrow, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address,
    );
  }
  for (const escrow of escrowPdas) {
    entries.push(
      deriveAssociatedTokenAddressSync(escrow, usdcMint, CLASSIC_TOKEN_PROGRAM_ID).address,
    );
  }
  if (entries.length !== 73 || new Set(entries).size !== 73) {
    throw new Error(
      `Expected 73 unique v1.3.0 Pool #0 ALT entries, got ${entries.length} (${new Set(entries).size} unique)`,
    );
  }
  return entries;
}

function deriveLookupTablePda(authorityStr, recentSlot) {
  const slotLe = new Uint8Array(8);
  new DataView(slotLe.buffer).setBigUint64(0, recentSlot, true);
  const { address, bump } = findProgramAddressSync(
    [base58Decode(authorityStr), slotLe],
    ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
  );
  return { address, bump };
}

function buildCreateLookupTableIx(authorityStr, payerStrArg, recentSlot) {
  const { address: lookupTableAddress, bump } = deriveLookupTablePda(authorityStr, recentSlot);
  const data = new Uint8Array(13);
  const dv = new DataView(data.buffer);
  dv.setUint32(0, 0, true); // ProgramInstruction::CreateLookupTable
  dv.setBigUint64(4, recentSlot, true);
  data[12] = bump;
  return {
    lookupTableAddress,
    bump,
    ix: {
      programId: ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
      accounts: [
        { pubkey: lookupTableAddress, isSigner: false, isWritable: true },
        { pubkey: authorityStr, isSigner: true, isWritable: false },
        { pubkey: payerStrArg, isSigner: true, isWritable: true },
        { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
      ],
      data,
    },
  };
}

function buildExtendLookupTableIx(lookupTableAddress, authorityStr, payerStrArg, addresses) {
  if (addresses.length === 0 || addresses.length > ALT_EXTEND_BATCH_SIZE) {
    throw new Error(
      `ALT extend batch size must be in 1..=${ALT_EXTEND_BATCH_SIZE}, got ${addresses.length}`,
    );
  }
  const data = new Uint8Array(4 + 8 + addresses.length * 32);
  const dv = new DataView(data.buffer);
  dv.setUint32(0, 2, true); // ProgramInstruction::ExtendLookupTable
  dv.setBigUint64(4, BigInt(addresses.length), true);
  for (let i = 0; i < addresses.length; i++) {
    const pk = base58Decode(addresses[i]);
    if (pk.byteLength !== 32) {
      throw new Error(`Invalid 32-byte ALT entry at index ${i}: ${addresses[i]}`);
    }
    data.set(pk, 12 + i * 32);
  }
  return {
    programId: ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
    accounts: [
      { pubkey: lookupTableAddress, isSigner: false, isWritable: true },
      { pubkey: authorityStr, isSigner: true, isWritable: false },
      { pubkey: payerStrArg, isSigner: true, isWritable: true },
      { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data,
  };
}

function buildFreezeLookupTableIx(lookupTableAddress, authorityStr) {
  const data = new Uint8Array(4);
  new DataView(data.buffer).setUint32(0, 1, true); // ProgramInstruction::FreezeLookupTable
  return {
    programId: ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
    accounts: [
      { pubkey: lookupTableAddress, isSigner: false, isWritable: true },
      { pubkey: authorityStr, isSigner: true, isWritable: false },
    ],
    data,
  };
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
  const res = await sendV1([ix], 45_000);
  return { ata, created: true, tx: res };
}

async function ensureGlobalRootHistory(poolId, pool, rootEpochInterval) {
  const rootsPda = deriveRootsPdaSync(poolId, PROGRAM_ID).address;
  const [rootsRaw] = await fetchBatch([rootsPda]);
  if (rootsRaw) {
    const history = decodeGlobalRootHistory(rootsRaw);
    return { rootsPda, created: false, history };
  }
  if (pool.authority !== payerStr) {
    throw new Error(
      `GlobalRootHistory missing at ${rootsPda} and signer ${payerStr} != pool authority ${pool.authority}`,
    );
  }
  const ix = buildInitRootHistoryInstruction({
    programId: PROGRAM_ID,
    authority: payerStr,
    poolId,
    rootEpochInterval,
    activeLanes: pool.activeLanes,
  });
  const tx = await sendV1([ix], CU_LIMIT_INIT_ROOT_HISTORY);
  const [afterRaw] = await fetchBatch([rootsPda]);
  if (!afterRaw) {
    throw new Error(`GlobalRootHistory still missing at ${rootsPda} after InitRootHistory ${tx.signature}`);
  }
  return { rootsPda, created: true, tx, history: decodeGlobalRootHistory(afterRaw) };
}

/**
 * Plan rollover page sequences and zero-crank idempotent Auto-`OpenPage` pre-instructions
 * (`planAutoOpenPages` / `buildAutoOpenPageInstructions`) so rollover boundaries and `>= 90%`
 * lookahead pages open inline in the same Transaction v1 (`0x81`).
 */
async function planLanePages(poolId, laneId, nextLeaf, nfCount, numOutputs, numNfs) {
  const roll = computePageRollovers({
    leafCount: nextLeaf,
    outputCount: numOutputs,
    nfCount,
    spentNullifiers: numNfs,
  });
  const candidates = planAutoOpenPages({
    programId: PROGRAM_ID,
    poolId,
    laneId,
    nextLeaf,
    nfCount,
    numOutputs,
    numNfs,
  });
  const existingPages = new Set();
  if (candidates.length > 0) {
    const raws = await fetchBatch(candidates.map((c) => c.pda));
    for (let i = 0; i < candidates.length; i++) {
      if (raws[i]) existingPages.add(candidates[i].pda);
    }
  }
  const autoOpenIxs = buildAutoOpenPageInstructions({
    programId: PROGRAM_ID,
    payer: payerStr,
    poolId,
    laneId,
    nextLeaf,
    nfCount,
    numOutputs,
    numNfs,
    existingPages,
  });
  return {
    subSeq: BigInt(roll.outSubSeq),
    rootSeq: BigInt(roll.outRootSeq),
    memoSeq: BigInt(roll.outMemoSeq),
    nfSeq: BigInt(roll.nfPageSeq),
    nextSubSeq: roll.nextSubSeq !== undefined ? BigInt(roll.nextSubSeq) : null,
    nextMemoSeq: roll.nextMemoSeq !== undefined ? BigInt(roll.nextMemoSeq) : null,
    nextNfSeq: roll.nextNfSeq !== undefined ? BigInt(roll.nextNfSeq) : null,
    autoOpenIxs,
  };
}

/**
 * Fetch `GlobalRootHistory` (`finalized`-first + `confirmed`-fallback) and pick the optimal
 * dual-ring `(rootRingKind, rootRingIdx)` snapshot via `selectRootSnapshotForNotes` with zero
 * checkpoint transactions.
 */
async function fetchAndSelectRootSnapshot(poolId, requiredNotes) {
  const fetched = await fetchGlobalRootHistory({
    programId: PROGRAM_ID,
    poolId,
    fetchFinalized: fetchBatchFinalized,
    fetchConfirmed: fetchBatchConfirmed,
    requiredNotes,
  });
  const selected = selectRootSnapshotForNotes(fetched.history, requiredNotes);
  if (!selected) {
    throw new Error('selectRootSnapshotForNotes returned null after fetchGlobalRootHistory');
  }
  return {
    history: fetched.history,
    snapshot: selected,
    commitment: fetched.commitment,
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
  const poolPda = derivePoolPdaSync(poolId, PROGRAM_ID).address;
  const rootsPda = deriveRootsPdaSync(poolId, PROGRAM_ID).address;
  const vaultAuthPda = deriveVaultAuthPdaSync(poolId, PROGRAM_ID).address;
  const vaultWsolAta = deriveAssociatedTokenAddressSync(
    vaultAuthPda,
    WSOL_MINT,
    CLASSIC_TOKEN_PROGRAM_ID,
  ).address;
  const bal = await rpc('getBalance', [payerStr, { commitment: 'confirmed' }]);

  console.log(`\n=== Audren v1.3.0 Live Empirical E2E (${CLUSTER.toUpperCase()}) ===`);
  console.log(`Program ID     : ${PROGRAM_ID}`);
  console.log(`Pool #0 PDA    : ${poolPda}`);
  console.log(`Roots PDA      : ${rootsPda}`);
  console.log(`Vault Auth PDA : ${vaultAuthPda}`);
  console.log(`Vault WSOL ATA : ${vaultWsolAta}`);
  console.log(`Authority      : ${payerStr} (${(bal.value / 1e9).toFixed(4)} SOL)`);

  const results = {
    cluster: CLUSTER,
    programId: PROGRAM_ID,
    poolPda,
    rootsPda,
    vaultAuthPda,
    vaultWsolAta,
    txs: {},
  };

  // Dedicated v1.3.0 Pool #0 frozen ALT creator: `--create-pool0-alt`
  if (CREATE_POOL0_ALT) {
    const entries = buildPool0AltEntries(CLUSTER);
    const recentSlot = BigInt(await rpc('getSlot', [{ commitment: 'finalized' }]));
    const { lookupTableAddress, ix: createIx } = buildCreateLookupTableIx(
      payerStr,
      payerStr,
      recentSlot,
    );
    console.log(
      `\n[CreatePool0ALT] Creating frozen v1.3.0 Pool #0 ALT on ${CLUSTER.toUpperCase()} (${entries.length} entries, recentSlot=${recentSlot})...`,
    );
    console.log(`  Derived ALT address : ${lookupTableAddress}`);

    const createTx = await sendV1([createIx], 60_000);
    console.log(
      `  CreateLookupTable confirmed: sig=${createTx.signature} slot=${createTx.slot} cu=${createTx.cu} wire=${createTx.wireBytes}B`,
    );

    const extendTxs = [];
    for (let off = 0; off < entries.length; off += ALT_EXTEND_BATCH_SIZE) {
      const batch = entries.slice(off, off + ALT_EXTEND_BATCH_SIZE);
      const extendIx = buildExtendLookupTableIx(lookupTableAddress, payerStr, payerStr, batch);
      const extTx = await sendV1([extendIx], 60_000);
      console.log(
        `  ExtendLookupTable [${off}..${off + batch.length - 1}] (${batch.length} entries) confirmed: sig=${extTx.signature} slot=${extTx.slot} cu=${extTx.cu}`,
      );
      extendTxs.push(extTx);
    }

    const freezeIx = buildFreezeLookupTableIx(lookupTableAddress, payerStr);
    const freezeTx = await sendV1([freezeIx], 30_000);
    console.log(
      `  FreezeLookupTable confirmed: sig=${freezeTx.signature} slot=${freezeTx.slot} cu=${freezeTx.cu}`,
    );

    // Round-trip verify on-chain ALT account layout (56 B meta, frozen authority tag == 0, all 73 entries),
    // retrying briefly on 1-slot RPC replica lag after permanent freeze.
    const expectedLen = ALT_META_SIZE + entries.length * 32;
    let altRaw = null;
    for (let attempt = 1; attempt <= 6; attempt++) {
      const [fetched] = await fetchBatch([lookupTableAddress]);
      if (fetched && fetched.byteLength === expectedLen && fetched[21] === 0) {
        altRaw = fetched;
        break;
      }
      altRaw = fetched ?? null;
      if (attempt < 6) {
        await new Promise((r) => setTimeout(r, 1_200));
      }
    }
    if (!altRaw || altRaw.byteLength !== expectedLen) {
      throw new Error(
        `ALT round-trip verification failed: expected ${expectedLen} B at ${lookupTableAddress}, got ${altRaw?.byteLength ?? 0} B`,
      );
    }
    const typeDisc = new DataView(altRaw.buffer, altRaw.byteOffset, altRaw.byteLength).getUint32(
      0,
      true,
    );
    if (typeDisc !== 1 || altRaw[21] !== 0) {
      throw new Error(
        `ALT round-trip verification failed: expected frozen LookupTable (type=1, authorityTag=0), got type=${typeDisc} authorityTag=${altRaw[21]}`,
      );
    }
    for (let i = 0; i < entries.length; i++) {
      const onChainAddr = base58Encode(
        altRaw.subarray(ALT_META_SIZE + i * 32, ALT_META_SIZE + (i + 1) * 32),
      );
      if (onChainAddr !== entries[i]) {
        throw new Error(
          `ALT entry[${i}] mismatch: on-chain ${onChainAddr} != expected ${entries[i]}`,
        );
      }
    }
    console.log(
      `  Verified on-chain frozen ALT ${lookupTableAddress} (${entries.length} entries, ${altRaw.byteLength} B, immutable authority=None).`,
    );

    const altSummary = {
      cluster: CLUSTER,
      programId: PROGRAM_ID,
      address: lookupTableAddress,
      frozen: true,
      entryCount: entries.length,
      entries,
      txs: {
        create: createTx,
        extend: extendTxs,
        freeze: freezeTx,
      },
    };
    console.log('\n=== POOL #0 ALT PROTOCOL.TS JSON ===');
    console.log(JSON.stringify({ address: lookupTableAddress, entries }, null, 2));
    console.log('\n=== CREATE POOL #0 ALT SUMMARY JSON ===');
    console.log(JSON.stringify(altSummary, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2));
    return;
  }

  // Dedicated one-shot migration path: `--init-root-history`
  if (INIT_ROOT_HISTORY) {
    const [poolRaw] = await fetchBatch([poolPda]);
    if (!poolRaw) {
      throw new Error(`Pool #0 does not exist at ${poolPda}; run --init-only first.`);
    }
    const pool = decodePoolState(poolRaw);
    console.log(
      `\n[InitRootHistory] Pool #0 active_lanes=${pool.activeLanes}, authority=${pool.authority}, target root_epoch_interval=${ROOT_EPOCH_INTERVAL}`,
    );
    const rootInit = await ensureGlobalRootHistory(poolId, pool, ROOT_EPOCH_INTERVAL);
    if (rootInit.created) {
      console.log(
        `  InitRootHistory (Tag 4) confirmed: sig=${rootInit.tx.signature} slot=${rootInit.tx.slot} cu=${rootInit.tx.cu} wire=${rootInit.tx.wireBytes}B`,
      );
      results.txs.initRootHistory = rootInit.tx;
    } else {
      console.log(
        `  GlobalRootHistory already initialized: latestSlot=${rootInit.history.latestSlot}, stableEpochId=${rootInit.history.stableEpochId}, epochInterval=${rootInit.history.epochInterval}`,
      );
    }
    console.log('\n=== INIT ROOT HISTORY SUMMARY JSON ===');
    console.log(JSON.stringify(results, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2));
    return;
  }

  // 1. Idempotent InitPool (Tag 0) + InitLane 0..3 (Tag 1) + InitRootHistory (Tag 4) + canonical WSOL ATA
  let [poolRaw] = await fetchBatch([poolPda]);
  if (!poolRaw) {
    console.log(
      `\n[1] Initializing Pool #0 (root_epoch_interval=${ROOT_EPOCH_INTERVAL}, note_rent_fee=1_000_000, nf_rent_fee=120_000)...`,
    );
    const initPoolIx = buildInitPoolInstruction({
      programId: PROGRAM_ID,
      payer: payerStr,
      poolId,
      rootEpochInterval: ROOT_EPOCH_INTERVAL,
      noteRentFee: 1_000_000n,
      nfRentFee: 120_000n,
    });
    const res = await sendV1([initPoolIx], CU_LIMIT_INIT_POOL);
    console.log(`  InitPool confirmed: sig=${res.signature} slot=${res.slot} cu=${res.cu} wire=${res.wireBytes}B`);
    results.txs.initPool = res;
    [poolRaw] = await fetchBatch([poolPda]);
  } else {
    console.log('\n[1] Pool #0 already initialized.');
  }
  let pool = decodePoolState(poolRaw);
  console.log(
    `  Pool state: version=${pool.version}, active_lanes=${pool.activeLanes}, paused=${pool.paused}, ` +
      `root_epoch_interval=${pool.rootEpochInterval}, note_rent_fee=${pool.noteRentFee}, nf_rent_fee=${pool.nfRentFee}`,
  );

  for (let lane = pool.activeLanes; lane < DEFAULT_INITIAL_LANES; lane++) {
    console.log(`  Initializing Lane #${lane}...`);
    const laneIx = buildInitLaneInstruction({
      programId: PROGRAM_ID,
      authority: payerStr,
      poolId,
      laneId: lane,
    });
    const res = await sendV1([laneIx], CU_LIMIT_INIT_LANE);
    console.log(`    InitLane #${lane} confirmed: sig=${res.signature} slot=${res.slot} cu=${res.cu}`);
    results.txs[`initLane${lane}`] = res;
  }
  [poolRaw] = await fetchBatch([poolPda]);
  pool = decodePoolState(poolRaw);
  if (pool.activeLanes < DEFAULT_INITIAL_LANES) {
    throw new Error(`Expected ${DEFAULT_INITIAL_LANES} active lanes, got ${pool.activeLanes}`);
  }

  const rootInit = await ensureGlobalRootHistory(poolId, pool, ROOT_EPOCH_INTERVAL);
  if (rootInit.created) {
    console.log(
      `  InitRootHistory (Tag 4) confirmed: sig=${rootInit.tx.signature} slot=${rootInit.tx.slot} cu=${rootInit.tx.cu}`,
    );
    results.txs.initRootHistory = rootInit.tx;
  } else {
    console.log(
      `  GlobalRootHistory ready: slotCount=${rootInit.history.slotCount} epochCount=${rootInit.history.epochCount} epochInterval=${rootInit.history.epochInterval}`,
    );
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
  if (pool.authority === payerStr && !INIT_ONLY) {
    console.log('\n[1b] Verifying UpdatePool (Tag 8, params no-op)...');
    const updIx = buildUpdatePoolInstruction({
      programId: PROGRAM_ID,
      signer: payerStr,
      poolId,
      action: {
        kind: 'params',
        noteRentFee: pool.noteRentFee,
        nfRentFee: pool.nfRentFee,
      },
    });
    const updRes = await sendV1([updIx], CU_LIMIT_OPEN_PAGE);
    console.log(`  UpdatePool confirmed: sig=${updRes.signature} slot=${updRes.slot} cu=${updRes.cu}`);
    results.txs.updatePool = updRes;
  }

  if (INIT_ONLY) {
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

  // 2. Unified Deposit (Tag 3, DEPOSIT_FLAG_NATIVE_SOL) into Lane 0 with inline auto-OpenPage
  const depositLane = 0;
  const [lane0Raw] = await fetchBatch([deriveLanePdaSync(poolId, depositLane, PROGRAM_ID).address]);
  const lane0 = decodeLaneHeader(lane0Raw);
  const depPages = await planLanePages(poolId, depositLane, lane0.nextLeaf, lane0.nfCount, 1, 0);
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
    programId: PROGRAM_ID,
    depositor: payerStr,
    poolId,
    laneId: depositLane,
    subPageSeq: depPages.subSeq,
    rootPageSeq: depPages.rootSeq,
    memoPageSeq: depPages.memoSeq,
    nativeSol: true,
    rollover: {
      nextSubSeq: depPages.nextSubSeq,
      nextMemoSeq: depPages.nextMemoSeq,
    },
    amount: depositAmount,
    stealthOwner: depOwner,
    blinding: depMemo.blinding,
    memo: depMemo.memo,
  });
  const depCu = recommendedDepositCuLimit({ openPageCount: depPages.autoOpenIxs.length });
  console.log(
    `\n[2] Executing live Deposit (0.005 Native SOL -> SyncNative WSOL, Tag 3, autoOpen=${depPages.autoOpenIxs.length}, cuLimit=${depCu})...`,
  );
  const depRes = await sendV1([...depPages.autoOpenIxs, depIx], depCu);
  console.log(
    `  Deposit (Native SOL) confirmed: sig=${depRes.signature} slot=${depRes.slot} cu=${depRes.cu} wire=${depRes.wireBytes}B`,
  );
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
    const [lane0NowRaw] = await fetchBatch([deriveLanePdaSync(poolId, depositLane, PROGRAM_ID).address]);
    const lane0Now = decodeLaneHeader(lane0NowRaw);
    const splPages = await planLanePages(poolId, depositLane, lane0Now.nextLeaf, lane0Now.nfCount, 1, 0);
    const splMemo = encryptNoteMemo(
      bob.viewPk,
      new Uint8Array(randomBytes(32)),
      SPL_AMOUNT,
      base58Decode(SPL_MINT),
    );
    const splOwner = deriveStealthOwner(bob.spendPk, splMemo.tweak);
    const splDepIx = buildDepositInstruction({
      programId: PROGRAM_ID,
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
        nextSubSeq: splPages.nextSubSeq,
        nextMemoSeq: splPages.nextMemoSeq,
      },
      amount: SPL_AMOUNT,
      stealthOwner: splOwner,
      blinding: splMemo.blinding,
      memo: splMemo.memo,
    });
    const splDepCu = recommendedDepositCuLimit({
      hasTransferHook: tokenProgram === TOKEN_2022_PROGRAM_ID,
      openPageCount: splPages.autoOpenIxs.length,
    });
    const splDepRes = await sendV1([...splPages.autoOpenIxs, splDepIx], splDepCu);
    console.log(
      `  Deposit (SPL/T22) confirmed: sig=${splDepRes.signature} slot=${splDepRes.slot} cu=${splDepRes.cu} cuLimit=${splDepCu}`,
    );
    results.txs.depositSpl = splDepRes;
  }

  // 3. Zero-indexer ordinary-RPC CompactWalletStore sync + immediate GlobalRootHistory fetch (zero crank!)
  console.log('\n[3] Syncing Alice CompactWalletStore & fetching GlobalRootHistory (instant spendability, 0 crank tx)...');
  const aliceStore = new CompactWalletStore(poolId);
  await syncCompactStoreWithRpc({
    programId: PROGRAM_ID,
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
  const root1 = await fetchAndSelectRootSnapshot(poolId, [
    { laneId: note0.laneId, leafIndex: note0.leafIndex },
  ]);
  console.log(
    `  Discovered Alice note: lane=${note0.laneId} leaf=${note0.leafIndex} amount=${note0.amount} (14 B paymentId verified)`,
  );
  console.log(
    `  Selected GlobalRootHistory snapshot: commitment=${root1.commitment} ring=${ringName(root1.snapshot.ringKind)} idx=${root1.snapshot.ringIdx} slot=${root1.snapshot.slot}`,
  );

  // 4. Transact Private Transfer (Tag 5, ASSET_MODE_PRIVATE, 192 B BN254 Groth16)
  console.log('\n[4] Reconstructing witness & proving Transact Private Transfer (Tag 5, 192 B Groth16 in WASM)...');
  const w1 = await reconstructWitness({
    programId: PROGRAM_ID,
    fetchBatch,
    poolId,
    rootHistory: root1.history,
    rootSnapshot: root1.snapshot,
    laneId: note0.laneId,
    leafIdx: note0.leafIndex,
    viewSk: alice.viewSk,
  });
  const transferLane = 1;
  const [lane1Raw] = await fetchBatch([deriveLanePdaSync(poolId, transferLane, PROGRAM_ID).address]);
  const lane1 = decodeLaneHeader(lane1Raw);
  const trPages = await planLanePages(poolId, transferLane, lane1.nextLeaf, lane1.nfCount, 2, 1);

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
    programId: PROGRAM_ID,
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
    programId: PROGRAM_ID,
    payer: payerStr,
    poolId,
    rootRingKind: w1.rootRingKind,
    rootRingIdx: w1.rootRingIdx,
    outLaneId: transferLane,
    outSubSeq: trPages.subSeq,
    outRootSeq: trPages.rootSeq,
    outMemoSeq: trPages.memoSeq,
    outNfSeq: trPages.nfSeq,
    rollover: {
      nextSubSeq: trPages.nextSubSeq,
      nextMemoSeq: trPages.nextMemoSeq,
      nextNfSeq: trPages.nextNfSeq,
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
  if (!trIx.accounts[2].isWritable) {
    throw new Error('Expected writable GlobalRootHistory on outputMask != 0 Transact');
  }
  const trCu = recommendedTransactCuLimit({
    assetMode: ASSET_MODE_PRIVATE,
    outputMask: 0b011,
    openPageCount: trPages.autoOpenIxs.length,
  });
  const trRes = await sendV1([...trPages.autoOpenIxs, trIx], trCu);
  console.log(
    `  Transact Private Transfer confirmed: sig=${trRes.signature} slot=${trRes.slot} cu=${trRes.cu} cuLimit=${trCu} wire=${trRes.wireBytes}B`,
  );
  results.txs.transfer = trRes;

  // 5. Immediate resync of Alice & Bob CompactWalletStore (zero crank!)
  console.log('\n[5] Immediately resyncing Alice & Bob CompactWalletStore (verifying NullifierPage spend & instant root update)...');
  await syncCompactStoreWithRpc({
    programId: PROGRAM_ID,
    fetchBatch,
    store: aliceStore,
    fvk: exportFullViewingKey(alice),
  });
  const aliceUnspent2 = aliceStore.unspentNotes();
  if (aliceUnspent2.length !== 1 || aliceUnspent2[0].amount !== changeAmt) {
    throw new Error(`Expected Alice to have 1 unspent change note (${changeAmt}), got ${aliceUnspent2.length}`);
  }
  const bobStore = new CompactWalletStore(poolId);
  await syncCompactStoreWithRpc({
    programId: PROGRAM_ID,
    fetchBatch,
    store: bobStore,
    fvk: exportFullViewingKey(bob),
  });
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

  // 6. Transact Public Withdraw Full Exit with WITHDRAW_FLAG_UNWRAP_WSOL (Tag 5, outputMask=0, read-only roots)
  console.log(
    '\n[6] Proving & executing live Transact Full-Exit Withdraw + WITHDRAW_FLAG_UNWRAP_WSOL (Tag 5, read-only roots)...',
  );
  const noteChange = aliceUnspent2[0];
  const root2 = await fetchAndSelectRootSnapshot(poolId, [
    { laneId: noteChange.laneId, leafIndex: noteChange.leafIndex },
  ]);
  console.log(
    `  Selected GlobalRootHistory snapshot: commitment=${root2.commitment} ring=${ringName(root2.snapshot.ringKind)} idx=${root2.snapshot.ringIdx} slot=${root2.snapshot.slot}`,
  );
  const w2 = await reconstructWitness({
    programId: PROGRAM_ID,
    fetchBatch,
    poolId,
    rootHistory: root2.history,
    rootSnapshot: root2.snapshot,
    laneId: noteChange.laneId,
    leafIdx: noteChange.leafIndex,
    viewSk: alice.viewSk,
  });
  const withdrawLane = 2;
  const [lane2Raw] = await fetchBatch([deriveLanePdaSync(poolId, withdrawLane, PROGRAM_ID).address]);
  const lane2 = decodeLaneHeader(lane2Raw);
  const wdPages = await planLanePages(poolId, withdrawLane, lane2.nextLeaf, lane2.nfCount, 0, 1);

  const wdCtx = computeTransactCtxHash({
    programId: PROGRAM_ID,
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
    programId: PROGRAM_ID,
    payer: payerStr,
    poolId,
    rootRingKind: w2.rootRingKind,
    rootRingIdx: w2.rootRingIdx,
    outLaneId: withdrawLane,
    outSubSeq: wdPages.subSeq,
    outRootSeq: wdPages.rootSeq,
    outMemoSeq: wdPages.memoSeq,
    outNfSeq: wdPages.nfSeq,
    rollover: {
      nextSubSeq: wdPages.nextSubSeq,
      nextMemoSeq: wdPages.nextMemoSeq,
      nextNfSeq: wdPages.nextNfSeq,
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
  if (wdIx.accounts[2].isWritable) {
    throw new Error('Expected read-only GlobalRootHistory on outputMask === 0 full-exit Transact');
  }
  const wdCu = recommendedTransactCuLimit({
    assetMode: ASSET_MODE_PUBLIC,
    outputMask: 0,
    openPageCount: wdPages.autoOpenIxs.length,
  });
  const wdRes = await sendV1([...wdPages.autoOpenIxs, wdIx], wdCu);
  console.log(
    `  Transact Withdraw (Unwrap WSOL -> Native SOL) confirmed: sig=${wdRes.signature} slot=${wdRes.slot} cu=${wdRes.cu} cuLimit=${wdCu} wire=${wdRes.wireBytes}B`,
  );
  results.txs.withdrawUnwrapSol = wdRes;

  // 7. Optional ExecViaEscrow (Tag 6) Jupiter Swap on Mainnet
  if (WITH_SWAP && CLUSTER === 'mainnet') {
    const swapOutMint = process.env.AUDREN_E2E_SWAP_OUT_MINT || MAINNET_USDC_MINT;
    const escrowShard = 0;
    const swapLane = 3;
    const escrowPda = deriveEscrowPdaSync(poolId, escrowShard, PROGRAM_ID).address;
    console.log(`\n[7] Executing live ExecViaEscrow Jupiter Swap (Tag 6, WSOL -> ${swapOutMint}, shard=${escrowShard})...`);

    const { ata: vaultInAta } = await ensureAtaExists(vaultAuthPda, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID);
    const { ata: vaultOutAta } = await ensureAtaExists(vaultAuthPda, swapOutMint, CLASSIC_TOKEN_PROGRAM_ID);
    const { ata: escrowInAta } = await ensureAtaExists(escrowPda, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID);
    const { ata: escrowOutAta } = await ensureAtaExists(escrowPda, swapOutMint, CLASSIC_TOKEN_PROGRAM_ID);

    const bobNote = bobWsolNotes[0];
    const root3 = await fetchAndSelectRootSnapshot(poolId, [
      { laneId: bobNote.laneId, leafIndex: bobNote.leafIndex },
    ]);
    const w3 = await reconstructWitness({
      programId: PROGRAM_ID,
      fetchBatch,
      poolId,
      rootHistory: root3.history,
      rootSnapshot: root3.snapshot,
      laneId: bobNote.laneId,
      leafIdx: bobNote.leafIndex,
      viewSk: bob.viewSk,
    });
    const [lane3Raw] = await fetchBatch([deriveLanePdaSync(poolId, swapLane, PROGRAM_ID).address]);
    const lane3 = decodeLaneHeader(lane3Raw);
    const swPages = await planLanePages(poolId, swapLane, lane3.nextLeaf, lane3.nfCount, 1, 1);

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
      programId: PROGRAM_ID,
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
      payer: payerStr,
      escrowInAta,
      escrowOutAta,
      vaultInAta,
      vaultOutAta,
      extraWritablePubkeys: [payerStr, escrowInAta, escrowOutAta, vaultInAta, vaultOutAta],
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
      programId: PROGRAM_ID,
      payer: payerStr,
      poolId,
      rootRingKind: w3.rootRingKind,
      rootRingIdx: w3.rootRingIdx,
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
        nextSubSeq: swPages.nextSubSeq,
        nextMemoSeq: swPages.nextMemoSeq,
        nextNfSeq: swPages.nextNfSeq,
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
    const swCu = recommendedExecViaEscrowCuLimit({
      routerCuLimit: 600_000,
      openPageCount: swPages.autoOpenIxs.length,
    });
    const swRes = await sendV1([...swPages.autoOpenIxs, execIx], swCu);
    console.log(
      `  ExecViaEscrow Jupiter Swap confirmed: sig=${swRes.signature} slot=${swRes.slot} cu=${swRes.cu} cuLimit=${swCu} wire=${swRes.wireBytes}B`,
    );
    results.txs.execViaEscrowSwap = swRes;

    // Immediate post-swap resync + root history verification (zero crank!)
    await syncCompactStoreWithRpc({
      programId: PROGRAM_ID,
      fetchBatch,
      store: bobStore,
      fvk: exportFullViewingKey(bob),
    });
    const bobOutNotes = bobStore.unspentNotes().filter((n) => bytesEqual(n.mint, outMintBytes));
    if (bobOutNotes.length !== 1 || bobOutNotes[0].amount < minAmountOut) {
      throw new Error(`Expected Bob to discover swapped output note >= ${minAmountOut}, found ${bobOutNotes.length}`);
    }
    const root4 = await fetchAndSelectRootSnapshot(poolId, [
      { laneId: bobOutNotes[0].laneId, leafIndex: bobOutNotes[0].leafIndex },
    ]);
    console.log(
      `  CompactWalletStore verified: Bob discovered dynamic AUD1DYN1 output note (${bobOutNotes[0].amount} base units of ${swapOutMint}), immediately spendable via ${ringName(root4.snapshot.ringKind)}[${root4.snapshot.ringIdx}]!`,
    );
  } else if (WITH_SWAP) {
    console.log('\n[7] Skipping --with-swap (Jupiter live swap requires --cluster mainnet).');
  }

  console.log('\n=== SUMMARY JSON ===');
  console.log(JSON.stringify(results, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
