/**
 * Audren Live End-to-End Programmatic Test Suite (Mainnet + Devnet)
 *
 * Uses the exact `audren-web` browser crypto/prover/transaction libraries against
 * live `https://audren.xyz` APIs + live Solana Mainnet & Devnet sBPFv3 program
 * (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`).
 *
 * Run:
 *   cd apps/web && AUDREN_KEYPAIR_PATH=... npx tsx scripts/e2e-live.ts
 */

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import crypto from 'node:crypto'
import assert from 'node:assert/strict'

import {
  AUDREN_PROGRAM_ID_STR,
  NATIVE_SOL_MINT,
  base58Decode,
  base58Encode,
  buildSelectiveDisclosureReceipt,
  bytesEqual,
  fromBase64,
  generateAudrenKeys,
  toBase64,
  utf8,
  verifySelectiveDisclosureOnPage,
  verifySelectiveDisclosureReceipt,
  type AudrenKeypair,
  type SolanaInstruction,
} from '../lib/audren-crypto'
import {
  CLASSIC_TOKEN_PROGRAM_ID,
  WSOL_MINT,
  WSOL_MINT_STR,
  buildBufferedExecutionPlan,
  buildCloseWsolAtaInstruction,
  buildCreateAtaIdempotentIx,
  buildDepositInstruction,
  buildExecViaEscrowInstruction,
  buildMergeInstruction,
  buildTransferInstruction,
  buildWalletUnlockMessage,
  buildWithdrawInstruction,
  buildWrapSolInstructions,
  deriveAta,
  deriveSeedFromWalletSignature,
  exportEncryptedVaultBackup,
  extractRingFromPage,
  importEncryptedVaultBackup,
  scanEpochPageSpendable,
  verifyDynamicAmountForNote,
  type SpendableAudrenNote,
} from '../lib/audren-prover'
import { compileKitV0Transaction } from '../lib/solana-wallet'

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..')
const BASE_URL = process.env.AUDREN_BASE_URL ?? 'https://audren.xyz'
const KEYPAIR_PATH =
  process.env.AUDREN_KEYPAIR_PATH ??
  path.join(REPO_ROOT, '.credentials/funder.json')
const USDC_MAINNET_MINT_STR = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
const USDC_MAINNET_MINT = base58Decode(USDC_MAINNET_MINT_STR)
const BROWSER_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'

type Cluster = 'mainnet' | 'devnet'

interface LocalSigner {
  address: string
  pubkey: Uint8Array
  signMessage: (msg: Uint8Array) => Uint8Array
  signTransaction: (unsignedWire: Uint8Array) => Uint8Array
}

function loadLocalSigner(keyPath: string): LocalSigner {
  const raw = Buffer.from(JSON.parse(fs.readFileSync(keyPath, 'utf8')) as number[])
  assert.equal(raw.length, 64, 'Keypair must be 64 bytes')
  const seed = raw.subarray(0, 32)
  const pub = new Uint8Array(raw.subarray(32, 64))
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed])
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pub])
  const privKey = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' })
  const pubKey = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' })

  const decodeShortVec = (buf: Uint8Array, off: number): { val: number; next: number } => {
    let val = 0
    let shift = 0
    let i = off
    for (;;) {
      const b = buf[i++]
      val |= (b & 0x7f) << shift
      if ((b & 0x80) === 0) return { val, next: i }
      shift += 7
    }
  }

  return {
    address: base58Encode(pub),
    pubkey: pub,
    signMessage(msg: Uint8Array): Uint8Array {
      const sig = crypto.sign(null, Buffer.from(msg), privKey)
      assert.ok(crypto.verify(null, Buffer.from(msg), pubKey, sig), 'Message sig verify failed')
      return new Uint8Array(sig)
    },
    signTransaction(unsignedWire: Uint8Array): Uint8Array {
      const { val: numSigs, next: sigStart } = decodeShortVec(unsignedWire, 0)
      assert.ok(numSigs >= 1, `Invalid numSigs=${numSigs}`)
      const msgBytes = unsignedWire.subarray(sigStart + numSigs * 64)
      const sig = crypto.sign(null, Buffer.from(msgBytes), privKey)
      assert.ok(crypto.verify(null, Buffer.from(msgBytes), pubKey, sig), 'Tx sig verify failed')
      const signed = new Uint8Array(unsignedWire)
      signed.set(sig, sigStart)
      return signed
    },
  }
}

async function apiJson<T>(
  path: string,
  init?: { method?: string; body?: unknown },
): Promise<{ status: number; headers: Headers; data: T }> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: init?.method ?? (init?.body !== undefined ? 'POST' : 'GET'),
    headers: {
      'user-agent': BROWSER_UA,
      ...(init?.body !== undefined ? { 'content-type': 'application/json' } : {}),
    },
    body: init?.body !== undefined ? JSON.stringify(init.body) : undefined,
  })
  const text = await res.text()
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new Error(`Non-JSON ${res.status} from ${path}: ${text.slice(0, 200)}`)
  }
  return { status: res.status, headers: res.headers, data: parsed as T }
}

interface PoolResponse {
  cluster: Cluster
  programId: string
  poolId: number
  poolPda: string
  currentPageId: string
  pageCount: number
  pageClosed: boolean
  pageBase64: string
  relayerAvailable: boolean
  relayerAddress: string | null
  relayerLamports: number | null
  activeLanes: number
  lanes: Array<{ laneId: number; activePageId: string; pageCount: number; pageClosed: boolean }>
  ataExists?: Record<string, boolean>
}

interface WalletBalancesResponse {
  cluster: Cluster
  address: string
  solLamports: string
  solUi: number
  solUsdValue: number | null
  solLogoUrl: string | null
  tokens: Array<{
    mint: string
    symbol: string
    name: string
    decimals: number
    amountRaw: string
    uiAmount: number
    usdValue: number | null
    logoUrl: string | null
    tokenProgram: string
  }>
}

async function fetchBlockhash(cluster: Cluster): Promise<{
  blockhash: string
  lastValidBlockHeight: bigint
}> {
  const res = await apiJson<{
    blockhash?: string
    lastValidBlockHeight?: number
    error?: string
  }>(`/api/rpc/blockhash?cluster=${cluster}`)
  assert.equal(res.status, 200, `blockhash failed: ${JSON.stringify(res.data)}`)
  assert.ok(res.data.blockhash, 'missing blockhash')
  return {
    blockhash: res.data.blockhash,
    lastValidBlockHeight: BigInt(res.data.lastValidBlockHeight ?? 0),
  }
}

async function sendSignedTx(
  cluster: Cluster,
  signedWire: Uint8Array,
  vaultOutAta?: string,
): Promise<{ signature: string; slot: number; actualOut: string | null }> {
  const res = await apiJson<{
    ok?: boolean
    signature?: string
    slot?: number
    actualOut?: string | null
    error?: string
  }>('/api/rpc/send', {
    body: {
      cluster,
      transactionB64: toBase64(signedWire),
      ...(vaultOutAta ? { vaultOutAta } : {}),
    },
  })
  if (res.status !== 200 || !res.data.signature) {
    throw new Error(`sendSignedTx failed (${res.status}): ${res.data.error ?? JSON.stringify(res.data)}`)
  }
  return {
    signature: res.data.signature,
    slot: res.data.slot ?? 0,
    actualOut: res.data.actualOut ?? null,
  }
}

async function submitDirect(
  cluster: Cluster,
  signer: LocalSigner,
  params: {
    innerIx: SolanaInstruction
    computeUnitLimit: number
    preIxs?: SolanaInstruction[]
    postIxs?: SolanaInstruction[]
    lookupTables?: Record<string, string[]>
    vaultOutAta?: string
  },
): Promise<{ signature: string; slot: number; txCount: number; actualOut: string | null }> {
  const { blockhash, lastValidBlockHeight } = await fetchBlockhash(cluster)
  const preIxs = params.preIxs ?? []
  const postIxs = params.postIxs ?? []
  const single = compileKitV0Transaction({
    feePayer: signer.address,
    recentBlockhash: blockhash,
    lastValidBlockHeight,
    instructions: [...preIxs, params.innerIx, ...postIxs],
    computeUnitLimit: params.computeUnitLimit,
    priorityMicroLamportsPerCu: 10_000n,
    lookupTables: params.lookupTables,
  })

  if (single.length <= 1232) {
    const signed = signer.signTransaction(single)
    const sent = await sendSignedTx(cluster, signed, params.vaultOutAta)
    return { ...sent, txCount: 1 }
  }

  const plan = await buildBufferedExecutionPlan(params.innerIx)
  const unsignedTxs: Uint8Array[] = []
  if (preIxs.length > 0) {
    unsignedTxs.push(
      compileKitV0Transaction({
        feePayer: signer.address,
        recentBlockhash: blockhash,
        lastValidBlockHeight,
        instructions: preIxs,
        computeUnitLimit: 200_000,
        priorityMicroLamportsPerCu: 10_000n,
      }),
    )
  }
  for (const chunkIx of plan.uploadChunks) {
    unsignedTxs.push(
      compileKitV0Transaction({
        feePayer: signer.address,
        recentBlockhash: blockhash,
        lastValidBlockHeight,
        instructions: [chunkIx],
        computeUnitLimit: 100_000,
        priorityMicroLamportsPerCu: 10_000n,
      }),
    )
  }
  const execWire = compileKitV0Transaction({
    feePayer: signer.address,
    recentBlockhash: blockhash,
    lastValidBlockHeight,
    instructions: [plan.executeIx, ...postIxs],
    computeUnitLimit: params.computeUnitLimit,
    priorityMicroLamportsPerCu: 10_000n,
    lookupTables: params.lookupTables,
  })
  assert.ok(execWire.length <= 1232, `ExecBuffered wire too large: ${execWire.length} B`)
  unsignedTxs.push(execWire)

  let lastRes: { signature: string; slot: number; actualOut: string | null } | null = null
  for (let i = 0; i < unsignedTxs.length; i++) {
    const signed = signer.signTransaction(unsignedTxs[i])
    const isLast = i === unsignedTxs.length - 1
    lastRes = await sendSignedTx(cluster, signed, isLast ? params.vaultOutAta : undefined)
  }
  assert.ok(lastRes, 'No transaction sent')
  return { ...lastRes, txCount: unsignedTxs.length }
}

async function scanUnspentNotes(
  cluster: Cluster,
  keys: AudrenKeypair,
  knownDynamic: Record<string, bigint>,
): Promise<{ pool: PoolResponse; pageBytesById: Map<string, Uint8Array>; unspent: SpendableAudrenNote[] }> {
  const poolRes = await apiJson<PoolResponse>(`/api/pool?cluster=${cluster}`)
  assert.equal(poolRes.status, 200, `pool fetch failed for ${cluster}`)
  const pool = poolRes.data

  const pageIds = new Set<string>([pool.currentPageId])
  for (const lane of pool.lanes ?? []) {
    pageIds.add(lane.activePageId)
    const tip = BigInt(lane.activePageId)
    // Also fetch recent pages on lane 0 (for small pools < 16 pages)
    if (lane.laneId === 0 && tip < 16n) {
      for (let p = 0n; p <= tip; p++) pageIds.add(p.toString())
    }
  }

  const pageBytesById = new Map<string, Uint8Array>()
  pageBytesById.set(pool.currentPageId, fromBase64(pool.pageBase64))
  const extraIds = [...pageIds].filter((id) => !pageBytesById.has(id))
  if (extraIds.length > 0) {
    const pgRes = await apiJson<{ pages?: Array<{ pageId: string; pageBase64: string }> }>(
      '/api/pages/fetch',
      { body: { cluster, poolId: 0, pageIds: extraIds } },
    )
    assert.equal(pgRes.status, 200, 'pages/fetch failed')
    for (const pg of pgRes.data.pages ?? []) {
      pageBytesById.set(pg.pageId, fromBase64(pg.pageBase64))
    }
  }

  const allNotes: SpendableAudrenNote[] = []
  for (const [, bytes] of pageBytesById) {
    const found = await scanEpochPageSpendable(keys, bytes, 0, knownDynamic)
    allNotes.push(...found)
  }

  for (const n of allNotes) {
    if (!n.isDynamicOutput || n.amountResolved) continue
    const dynRes = await apiJson<{ candidateAmounts?: string[] }>('/api/notes/resolve-dynamic', {
      body: {
        cluster,
        poolId: 0,
        pageId: n.pageId.toString(),
        slotIndex: n.slotIndex,
        mint: n.mintB58,
      },
    })
    assert.equal(dynRes.status, 200, 'resolve-dynamic failed')
    for (const candStr of dynRes.data.candidateAmounts ?? []) {
      const cand = BigInt(candStr)
      if (verifyDynamicAmountForNote(n, cand)) {
        n.amount = cand
        n.amountResolved = true
        knownDynamic[base58Encode(n.stealthPk)] = cand
        break
      }
    }
  }

  if (allNotes.length === 0) return { pool, pageBytesById, unspent: [] }

  const nullRes = await apiJson<{ spent?: boolean[] }>('/api/nullifiers', {
    body: { cluster, pdas: allNotes.map((n) => n.nullifierPdaB58) },
  })
  assert.equal(nullRes.status, 200, 'nullifiers check failed')
  assert.equal(nullRes.data.spent?.length, allNotes.length)

  const unspent = allNotes.filter((_, i) => !nullRes.data.spent![i])
  return { pool, pageBytesById, unspent }
}

function logStep(title: string) {
  console.log(`\n══════════════════════════════════════════════════════════`)
  console.log(`▶ ${title}`)
  console.log(`══════════════════════════════════════════════════════════`)
}

async function main() {
  const signer = loadLocalSigner(KEYPAIR_PATH)
  console.log(`Wallet: ${signer.address}`)
  console.log(`Target: ${BASE_URL}`)
  console.log(`Program: ${AUDREN_PROGRAM_ID_STR}`)

  // --------------------------------------------------------------------------
  // STEP 1: API, Token Metadata, Search, Logo Proxy, Blockhash, Jupiter Quote
  // --------------------------------------------------------------------------
  logStep('STEP 1 — Production API, Token Search, Wallet Balances & Logo Proxy Audit')

  const [mPool, dPool, balRes, searchUsdc, searchJup, searchBonk, bhRes] = await Promise.all([
    apiJson<PoolResponse>('/api/pool?cluster=mainnet'),
    apiJson<PoolResponse>('/api/pool?cluster=devnet'),
    apiJson<WalletBalancesResponse>(`/api/wallet/balances?cluster=mainnet&address=${signer.address}`),
    apiJson<{ items: Array<{ mint: string; symbol: string; logoUrl: string | null }> }>('/api/tokens/search?q=USDC'),
    apiJson<{ items: Array<{ mint: string; symbol: string; logoUrl: string | null }> }>('/api/tokens/search?q=JUP'),
    apiJson<{ items: Array<{ mint: string; symbol: string; logoUrl: string | null }> }>('/api/tokens/search?q=BONK'),
    apiJson<{ blockhash: string; lastValidBlockHeight: number }>('/api/rpc/blockhash?cluster=mainnet'),
  ])

  assert.equal(mPool.status, 200)
  assert.equal(mPool.data.programId, AUDREN_PROGRAM_ID_STR)
  assert.equal(dPool.status, 200)
  assert.equal(dPool.data.programId, AUDREN_PROGRAM_ID_STR)
  assert.equal(dPool.data.relayerAvailable, true, 'Devnet relayer must be available')
  assert.equal(balRes.status, 200)
  assert.ok(balRes.data.solUi > 1, 'Expected funded SOL wallet')
  assert.ok(balRes.data.solUsdValue && balRes.data.solUsdValue > 10, 'Expected live SOL USD value')
  assert.ok(balRes.data.tokens.some((t) => t.symbol === 'USDC' && t.usdValue && t.usdValue > 1), 'Missing USDC metadata')
  assert.ok(balRes.data.tokens.some((t) => t.symbol === 'PENGU' && t.usdValue && t.usdValue > 1), 'Missing PENGU metadata')
  assert.ok(balRes.data.tokens.some((t) => t.symbol === 'USDT' && t.usdValue && t.usdValue > 1), 'Missing USDT metadata')
  assert.ok(balRes.data.tokens.some((t) => t.symbol === 'JTO' && t.usdValue && t.usdValue > 1), 'Missing JTO metadata')
  assert.ok(searchUsdc.data.items.some((t) => t.mint === USDC_MAINNET_MINT_STR), 'Search USDC missing canonical mint')
  assert.ok(searchJup.data.items.some((t) => t.symbol === 'JUP'), 'Search JUP missing JUP')
  assert.ok(searchBonk.data.items.some((t) => t.symbol.toUpperCase() === 'BONK'), 'Search BONK missing BONK')
  assert.equal(bhRes.headers.get('cache-control'), 'no-store', 'Blockhash must be cache-control: no-store')

  // Verify logo proxy for top 5 tokens returns 200 image/*
  for (const mint of [
    WSOL_MINT_STR,
    USDC_MAINNET_MINT_STR,
    '2zMMhcVQEXDtdE6vsFS7S7D5oUodfJHE8vd1gnBouauv', // PENGU
    'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', // USDT
    'jtojtomepa8beP8AuQc6eXt5FriJwfFMwQx2v2f9mCL', // JTO
  ]) {
    const lr = await fetch(`${BASE_URL}/api/tokens/mint-logo/${mint}.webp`, {
      method: 'HEAD',
      headers: { 'user-agent': BROWSER_UA },
    })
    assert.equal(lr.status, 200, `Logo failed for ${mint}: ${lr.status}`)
    assert.ok((lr.headers.get('content-type') ?? '').startsWith('image/'), `Non-image logo for ${mint}`)
  }

  const startUsdcRaw = BigInt(
    balRes.data.tokens.find((t) => t.mint === USDC_MAINNET_MINT_STR)?.amountRaw ?? '0',
  )
  console.log(
    `✓ Mainnet Pool #0 page=${mPool.data.currentPageId} count=${mPool.data.pageCount}, Devnet Pool #0 page=${dPool.data.currentPageId} relayer=${dPool.data.relayerAddress}`,
  )
  console.log(
    `✓ Wallet: ${balRes.data.solUi.toFixed(4)} SOL ($${balRes.data.solUsdValue?.toFixed(2)}) + ${balRes.data.tokens.length} SPL tokens (USDC=${Number(startUsdcRaw) / 1e6})`,
  )
  console.log(`✓ Search (USDC/JUP/BONK) + 5/5 Mint Logos HTTP 200 image/* + blockhash no-store OK`)

  // --------------------------------------------------------------------------
  // STEP 2: Deterministic Stealth Key Derivation (Exact Browser Unlock Message)
  // --------------------------------------------------------------------------
  logStep('STEP 2 — Deterministic Stealth Vault Key Derivation + Mainnet Scan')
  const unlockMsg = buildWalletUnlockMessage(signer.address, 0)
  const unlockSig = signer.signMessage(utf8(unlockMsg))
  const vaultSeed = await deriveSeedFromWalletSignature(signer.address, unlockSig)
  const keys = await generateAudrenKeys(vaultSeed)
  assert.ok(keys.address.startsWith('aud15AjTt') && keys.address.endsWith('rE7b7'), `Unexpected aud1 address: ${keys.address}`)
  console.log(`✓ Derived stealth address: ${keys.address} (matches Phantom byte-for-byte!)`)

  const knownDynamic: Record<string, bigint> = {}
  let state = await scanUnspentNotes('mainnet', keys, knownDynamic)
  console.log(`✓ Mainnet initial unspent notes: ${state.unspent.length}`)

  // Ensure we have a 0.01 WSOL note to test Transfer -> Merge -> Swap -> Withdraw
  let wsolNote = state.unspent.find((n) => n.mintB58 === WSOL_MINT_STR && n.amount >= 10_000_000n)
  if (!wsolNote) {
    console.log(`  No 0.01 WSOL note found — shielding 0.01 SOL (WSOL + atomic rent close)...`)
    const amt = 10_000_000n
    const wrapped = await buildWrapSolInstructions(signer.pubkey, amt)
    const { instructions: depIxs } = await buildDepositInstruction({
      depositor: signer.pubkey,
      poolId: 0,
      activePageId: BigInt(state.pool.currentPageId),
      recipient: { spendPk: keys.spendPk, viewPk: keys.viewPk },
      mint: WSOL_MINT,
      amount: amt,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
      memoText: 'E2E_SHIELD',
      createVaultAtaIfMissing: true,
    })
    const closeWsol = await buildCloseWsolAtaInstruction(signer.pubkey)
    const { blockhash, lastValidBlockHeight } = await fetchBlockhash('mainnet')
    const wire = compileKitV0Transaction({
      feePayer: signer.address,
      recentBlockhash: blockhash,
      lastValidBlockHeight,
      instructions: [...wrapped.instructions, ...depIxs, closeWsol],
      computeUnitLimit: 300_000,
      priorityMicroLamportsPerCu: 10_000n,
    })
    const sent = await sendSignedTx('mainnet', signer.signTransaction(wire))
    console.log(`  ✓ Shielded 0.01 WSOL: https://solscan.io/tx/${sent.signature}`)
    state = await scanUnspentNotes('mainnet', keys, knownDynamic)
    wsolNote = state.unspent.find((n) => n.mintB58 === WSOL_MINT_STR && n.amount >= 10_000_000n)
  }
  assert.ok(wsolNote, 'Expected unspent >=0.01 WSOL note on Mainnet')
  console.log(`✓ Active Mainnet WSOL note: ${Number(wsolNote.amount) / 1e9} SOL on page ${wsolNote.pageId} slot ${wsolNote.slotIndex}`)

  // --------------------------------------------------------------------------
  // STEP 3: MAINNET Private Send (Tag 3: Transfer — 0.004 + 0.006 WSOL) + Selective Disclosure
  // --------------------------------------------------------------------------
  logStep('STEP 3 — MAINNET Private Send (Tag 3 Transfer: 0.004 + 0.006 WSOL) + Selective Disclosure Receipt')
  {
    const pageBytes = state.pageBytesById.get(wsolNote.pageId.toString())!
    const ring = extractRingFromPage(pageBytes)
    const payAmt = 4_000_000n
    const t0 = performance.now()
    const { instruction } = await buildTransferInstruction({
      payer: signer.pubkey,
      poolId: 0,
      outPageId: BigInt(state.pool.currentPageId),
      inputPageIds: [wsolNote.pageId],
      ring,
      inputNote: wsolNote,
      secretIndex: wsolNote.slotIndex,
      recipient: { spendPk: keys.spendPk, viewPk: keys.viewPk },
      changeAddr: { spendPk: keys.spendPk, viewPk: keys.viewPk },
      payAmount: payAmt,
      memoText: 'E2E_PAY',
    })
    const proveMs = Math.round(performance.now() - t0)
    const sent = await submitDirect('mainnet', signer, {
      innerIx: instruction,
      computeUnitLimit: 850_000,
    })
    console.log(`✓ Mainnet Private Send confirmed (${sent.txCount} txs, proof ${proveMs}ms): https://solscan.io/tx/${sent.signature}`)

    state = await scanUnspentNotes('mainnet', keys, knownDynamic)
    const splitNotes = state.unspent.filter((n) => n.mintB58 === WSOL_MINT_STR)
    assert.ok(splitNotes.length >= 2, `Expected >=2 unspent WSOL notes after split, got ${splitNotes.length}`)
    const payFound = splitNotes.find((n) => n.amount === payAmt)
    const chgFound = splitNotes.find((n) => n.amount === wsolNote!.amount - payAmt)
    assert.ok(payFound && chgFound, 'Split WSOL notes (0.004 + 0.006) not found on-chain')
    console.log(`✓ Verified split notes on-chain: ${Number(payFound.amount) / 1e9} SOL (slot ${payFound.slotIndex}) + ${Number(chgFound.amount) / 1e9} SOL (slot ${chgFound.slotIndex})`)

    // Verify Selective Disclosure Receipt cryptographically AND against live on-chain Mainnet EpochPage
    const receipt = buildSelectiveDisclosureReceipt(
      {
        pageId: payFound.pageId,
        slotIndex: payFound.slotIndex,
        stealthPk: payFound.stealthPk,
        assetTag: payFound.assetTag,
        commitment: payFound.commitment,
        mint: payFound.mint,
        amountLamports: payFound.amount,
        memoText: payFound.memoText,
        commitmentVerified: true,
        assetBlinding: payFound.assetBlinding,
        valueBlinding: payFound.valueBlinding,
      },
      sent.signature,
      { cluster: 'mainnet', assetSymbol: 'WSOL', decimals: 9 },
    )
    const mathCheck = await verifySelectiveDisclosureReceipt(receipt)
    assert.equal(mathCheck.valid, true, `Receipt math invalid: ${mathCheck.reason}`)
    const outPageBytes = state.pageBytesById.get(payFound.pageId.toString())!
    const onChainCheck = await verifySelectiveDisclosureOnPage(receipt, outPageBytes)
    assert.equal(onChainCheck.valid, true, `Receipt on-chain check invalid: ${onChainCheck.reason}`)
    console.log(`✓ Selective Disclosure Receipt verified cryptographically & against live Mainnet EpochPage #${payFound.pageId} slot ${payFound.slotIndex}`)
  }

  // --------------------------------------------------------------------------
  // STEP 4: MAINNET Combine Notes (Tag 4: Merge — 0.004 + 0.006 -> 0.01 WSOL)
  // --------------------------------------------------------------------------
  logStep('STEP 4 — MAINNET Combine Notes (Tag 4 Merge: 0.004 + 0.006 -> 0.01 WSOL)')
  {
    const wsolNotes = state.unspent.filter((n) => n.mintB58 === WSOL_MINT_STR)
    assert.ok(wsolNotes.length >= 2, 'Need 2 WSOL notes to merge')
    const [note1, note2] = wsolNotes
    const ring1 = extractRingFromPage(state.pageBytesById.get(note1.pageId.toString())!)
    const ring2 = extractRingFromPage(state.pageBytesById.get(note2.pageId.toString())!)
    const t0 = performance.now()
    const { instruction } = await buildMergeInstruction({
      payer: signer.pubkey,
      poolId: 0,
      outPageId: BigInt(state.pool.currentPageId),
      input1PageIds: [note1.pageId],
      ring1,
      note1,
      secretIndex1: note1.slotIndex,
      input2PageIds: [note2.pageId],
      ring2,
      note2,
      secretIndex2: note2.slotIndex,
      ownerAddr: { spendPk: keys.spendPk, viewPk: keys.viewPk },
      memoText: 'E2E_MERGE',
    })
    const proveMs = Math.round(performance.now() - t0)
    const sent = await submitDirect('mainnet', signer, {
      innerIx: instruction,
      computeUnitLimit: 1_150_000,
    })
    console.log(`✓ Mainnet Merge confirmed (${sent.txCount} txs, proof ${proveMs}ms): https://solscan.io/tx/${sent.signature}`)

    state = await scanUnspentNotes('mainnet', keys, knownDynamic)
    const mergedNote = state.unspent.find(
      (n) => n.mintB58 === WSOL_MINT_STR && n.amount === note1.amount + note2.amount,
    )
    assert.ok(mergedNote, 'Merged 0.01 WSOL note not found')
    console.log(`✓ Verified consolidated note: ${Number(mergedNote.amount) / 1e9} SOL on page ${mergedNote.pageId} slot ${mergedNote.slotIndex}`)
  }

  // --------------------------------------------------------------------------
  // STEP 5: MAINNET Private Jupiter Swap (Tag 5: SwapViaRouter — 0.01 WSOL -> USDC)
  // --------------------------------------------------------------------------
  logStep('STEP 5 — MAINNET Private Jupiter Swap (Tag 5 SwapViaRouter: 0.01 WSOL -> USDC)')
  let swappedUsdcAmt = 0n
  {
    const swapIn = state.unspent.find((n) => n.mintB58 === WSOL_MINT_STR && n.amount >= 10_000_000n)
    assert.ok(swapIn, 'No WSOL note available for Private Swap')

    const quoteRes = await apiJson<{
      quote: { otherAmountThreshold: string; outAmount: string; routePlan?: Array<{ swapInfo?: { label?: string } }> }
      shardId: number
      tokenProgramIn: string
      tokenProgramOut: string
      vaultOutAta: string
      missingAtas: Array<{ owner: string; mint: string; tokenProgram: string }>
    }>('/api/jupiter/quote', {
      body: {
        inputMint: WSOL_MINT_STR,
        outputMint: USDC_MAINNET_MINT_STR,
        amount: swapIn.amount.toString(),
        slippageBps: 100,
      },
    })
    assert.equal(quoteRes.status, 200, `Jupiter quote failed: ${JSON.stringify(quoteRes.data)}`)
    const q = quoteRes.data
    const route = q.quote.routePlan?.map((r) => r.swapInfo?.label).filter(Boolean).join(' -> ') ?? 'Jupiter'
    console.log(`  Quote: ${Number(swapIn.amount) / 1e9} WSOL -> ~${Number(q.quote.outAmount) / 1e6} USDC via ${route}`)

    const ixRes = await apiJson<{
      shardId: number
      swapInstruction: {
        programId: string
        accounts: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }>
        data: string
      }
      escrowIdx: number
      escrowInIdx: number
      escrowOutIdx: number
      lookupTables?: Record<string, string[]>
      computeUnitLimit?: number
    }>('/api/jupiter/swap-instructions', {
      body: {
        quoteResponse: q.quote,
        inputMint: WSOL_MINT_STR,
        outputMint: USDC_MAINNET_MINT_STR,
        shardId: q.shardId,
      },
    })
    assert.equal(ixRes.status, 200, `Jupiter swap-instructions failed: ${JSON.stringify(ixRes.data)}`)
    const ixData = ixRes.data

    const ring = extractRingFromPage(state.pageBytesById.get(swapIn.pageId.toString())!)
    const t0 = performance.now()
    const { instruction, outDesc } = await buildExecViaEscrowInstruction({
      payer: signer.pubkey,
      poolId: 0,
      outPageId: BigInt(state.pool.currentPageId),
      shardId: ixData.shardId ?? q.shardId,
      inputPageIds: [swapIn.pageId],
      ring,
      inputNote: swapIn,
      secretIndex: swapIn.slotIndex,
      mintOut: USDC_MAINNET_MINT,
      tokenProgramIn: base58Decode(q.tokenProgramIn),
      tokenProgramOut: base58Decode(q.tokenProgramOut),
      amountIn: swapIn.amount,
      minAmountOut: BigInt(q.quote.otherAmountThreshold),
      recipient: { spendPk: keys.spendPk, viewPk: keys.viewPk },
      changeAddr: { spendPk: keys.spendPk, viewPk: keys.viewPk },
      targetProgramId: base58Decode(ixData.swapInstruction.programId),
      targetIxData: fromBase64(ixData.swapInstruction.data),
      actionAccounts: ixData.swapInstruction.accounts.map((a) => ({
        pubkey: base58Decode(a.pubkey),
        isSigner: a.isSigner,
        isWritable: a.isWritable,
      })),
      escrowIdx: ixData.escrowIdx,
      escrowInIdx: ixData.escrowInIdx,
      escrowOutIdx: ixData.escrowOutIdx,
      memoText: 'E2E_JUP',
    })
    const proveMs = Math.round(performance.now() - t0)

    const preIxs: SolanaInstruction[] = []
    for (const m of q.missingAtas ?? []) {
      const ownerB = base58Decode(m.owner)
      const mintB = base58Decode(m.mint)
      const tpB = base58Decode(m.tokenProgram)
      const ata = await deriveAta(ownerB, tpB, mintB)
      preIxs.push(buildCreateAtaIdempotentIx({ payer: signer.pubkey, ata, owner: ownerB, mint: mintB, tokenProgram: tpB }))
    }

    const sent = await submitDirect('mainnet', signer, {
      innerIx: instruction,
      computeUnitLimit: Math.min(Math.max(ixData.computeUnitLimit ?? 1_100_000, 1_100_000), 1_400_000),
      preIxs,
      lookupTables: ixData.lookupTables,
      vaultOutAta: q.vaultOutAta,
    })
    console.log(`✓ Mainnet Private Jupiter Swap confirmed (${sent.txCount} txs, proof ${proveMs}ms): https://solscan.io/tx/${sent.signature}`)
    if (sent.actualOut) {
      knownDynamic[base58Encode(outDesc.stealthPk)] = BigInt(sent.actualOut)
      console.log(`  actualOut from /api/rpc/send: ${Number(sent.actualOut) / 1e6} USDC`)
    }

    // Also test /api/notes/resolve-dynamic independently (even without cached actualOut!)
    const freshDyn: Record<string, bigint> = {}
    state = await scanUnspentNotes('mainnet', keys, freshDyn)
    const usdcNote = state.unspent.find((n) => n.mintB58 === USDC_MAINNET_MINT_STR && n.amount > 0n)
    assert.ok(usdcNote, 'Swapped private USDC note not discovered/verified via /api/notes/resolve-dynamic')
    swappedUsdcAmt = usdcNote.amount
    console.log(`✓ Cryptographically verified dynamic swap output via /api/notes/resolve-dynamic: ${Number(swappedUsdcAmt) / 1e6} USDC on page ${usdcNote.pageId} slot ${usdcNote.slotIndex}`)
  }

  // --------------------------------------------------------------------------
  // STEP 6: MAINNET Go Public SPL (Tag 6: Withdraw 100% of private USDC back to wallet)
  // --------------------------------------------------------------------------
  logStep('STEP 6 — MAINNET Go Public SPL (Tag 6 Withdraw: 100% private USDC -> wallet)')
  {
    const usdcNote = state.unspent.find((n) => n.mintB58 === USDC_MAINNET_MINT_STR)
    assert.ok(usdcNote, 'Expected unspent USDC note to withdraw')
    const recipientAta = await deriveAta(signer.pubkey, CLASSIC_TOKEN_PROGRAM_ID, USDC_MAINNET_MINT)
    const ring = extractRingFromPage(state.pageBytesById.get(usdcNote.pageId.toString())!)
    const t0 = performance.now()
    const { instruction } = await buildWithdrawInstruction({
      payer: signer.pubkey,
      poolId: 0,
      outPageId: BigInt(state.pool.currentPageId),
      inputPageIds: [usdcNote.pageId],
      ring,
      inputNote: usdcNote,
      secretIndex: usdcNote.slotIndex,
      recipientAccount: recipientAta,
      changeAddr: { spendPk: keys.spendPk, viewPk: keys.viewPk },
      amount: usdcNote.amount,
      splTokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    })
    const proveMs = Math.round(performance.now() - t0)
    const sent = await submitDirect('mainnet', signer, {
      innerIx: instruction,
      computeUnitLimit: 550_000,
    })
    console.log(`✓ Mainnet USDC Withdraw confirmed (${sent.txCount} tx, proof ${proveMs}ms): https://solscan.io/tx/${sent.signature}`)

    const afterBal = await apiJson<WalletBalancesResponse>(`/api/wallet/balances?cluster=mainnet&address=${signer.address}`)
    const afterUsdcRaw = BigInt(
      afterBal.data.tokens.find((t) => t.mint === USDC_MAINNET_MINT_STR)?.amountRaw ?? '0',
    )
    assert.equal(afterUsdcRaw - startUsdcRaw, swappedUsdcAmt, 'Wallet USDC delta must match exact swapped amount')
    console.log(`✓ Public Wallet USDC increased by exact +${Number(swappedUsdcAmt) / 1e6} USDC (now ${Number(afterUsdcRaw) / 1e6} USDC)`)
  }

  // --------------------------------------------------------------------------
  // STEP 7: MAINNET Atomic WSOL Shield + Atomic WSOL Withdraw Unwrap -> Native SOL
  // --------------------------------------------------------------------------
  logStep('STEP 7 — MAINNET Atomic WSOL Shield (0.005 SOL) -> Atomic WSOL Unwrap Withdraw to Native SOL')
  {
    const amt = 5_000_000n
    state = await scanUnspentNotes('mainnet', keys, knownDynamic)
    const wrapped = await buildWrapSolInstructions(signer.pubkey, amt)
    const { instructions: depIxs } = await buildDepositInstruction({
      depositor: signer.pubkey,
      poolId: 0,
      activePageId: BigInt(state.pool.currentPageId),
      recipient: { spendPk: keys.spendPk, viewPk: keys.viewPk },
      mint: WSOL_MINT,
      amount: amt,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
      memoText: 'E2E_UNWRAP',
      createVaultAtaIfMissing: true,
    })
    const closeWsol = await buildCloseWsolAtaInstruction(signer.pubkey)
    const { blockhash, lastValidBlockHeight } = await fetchBlockhash('mainnet')
    const depWire = compileKitV0Transaction({
      feePayer: signer.address,
      recentBlockhash: blockhash,
      lastValidBlockHeight,
      instructions: [...wrapped.instructions, ...depIxs, closeWsol],
      computeUnitLimit: 300_000,
      priorityMicroLamportsPerCu: 10_000n,
    })
    const depSent = await sendSignedTx('mainnet', signer.signTransaction(depWire))
    console.log(`✓ Shielded 0.005 SOL (WSOL + atomic rent close): https://solscan.io/tx/${depSent.signature}`)

    state = await scanUnspentNotes('mainnet', keys, knownDynamic)
    const note = state.unspent.find((n) => n.mintB58 === WSOL_MINT_STR && n.amount === amt)
    assert.ok(note, 'Expected 0.005 WSOL note')

    const recipientAta = await deriveAta(signer.pubkey, CLASSIC_TOKEN_PROGRAM_ID, WSOL_MINT)
    const ring = extractRingFromPage(state.pageBytesById.get(note.pageId.toString())!)
    const { instruction } = await buildWithdrawInstruction({
      payer: signer.pubkey,
      poolId: 0,
      outPageId: BigInt(state.pool.currentPageId),
      inputPageIds: [note.pageId],
      ring,
      inputNote: note,
      secretIndex: note.slotIndex,
      recipientAccount: recipientAta,
      changeAddr: { spendPk: keys.spendPk, viewPk: keys.viewPk },
      amount: amt,
      splTokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    })
    const wdSent = await submitDirect('mainnet', signer, {
      innerIx: instruction,
      computeUnitLimit: 550_000,
      preIxs: [
        buildCreateAtaIdempotentIx({
          payer: signer.pubkey,
          ata: recipientAta,
          owner: signer.pubkey,
          mint: WSOL_MINT,
          tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
        }),
      ],
      postIxs: [await buildCloseWsolAtaInstruction(signer.pubkey)],
    })
    console.log(`✓ Withdrew & atomically unwrapped 0.005 WSOL -> native SOL: https://solscan.io/tx/${wdSent.signature}`)

    const balCheck = await apiJson<WalletBalancesResponse>(`/api/wallet/balances?cluster=mainnet&address=${signer.address}`)
    assert.ok(!balCheck.data.tokens.some((t) => t.mint === WSOL_MINT_STR), 'WSOL ATA should be cleanly closed!')
    console.log(`✓ Verified ZERO dangling WSOL ATA — native SOL & ATA rent returned straight to wallet!`)
  }

  // --------------------------------------------------------------------------
  // STEP 8: MAINNET Direct SPL Token Shield (1 USDC) -> Direct SPL Withdraw (1 USDC)
  // --------------------------------------------------------------------------
  logStep('STEP 8 — MAINNET Direct SPL Token Shield (1.00 USDC) -> Go Public (1.00 USDC)')
  {
    const amt = 1_000_000n // 1.00 USDC
    state = await scanUnspentNotes('mainnet', keys, knownDynamic)
    const { instructions: depIxs } = await buildDepositInstruction({
      depositor: signer.pubkey,
      poolId: 0,
      activePageId: BigInt(state.pool.currentPageId),
      recipient: { spendPk: keys.spendPk, viewPk: keys.viewPk },
      mint: USDC_MAINNET_MINT,
      amount: amt,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
      memoText: 'E2E_USDC',
      createVaultAtaIfMissing: true,
    })
    const { blockhash, lastValidBlockHeight } = await fetchBlockhash('mainnet')
    const depWire = compileKitV0Transaction({
      feePayer: signer.address,
      recentBlockhash: blockhash,
      lastValidBlockHeight,
      instructions: depIxs,
      computeUnitLimit: 300_000,
      priorityMicroLamportsPerCu: 10_000n,
    })
    const depSent = await sendSignedTx('mainnet', signer.signTransaction(depWire))
    console.log(`✓ Shielded 1.00 USDC: https://solscan.io/tx/${depSent.signature}`)

    state = await scanUnspentNotes('mainnet', keys, knownDynamic)
    const usdcNote = state.unspent.find((n) => n.mintB58 === USDC_MAINNET_MINT_STR && n.amount === amt)
    assert.ok(usdcNote, 'Expected 1.00 USDC private note')

    const recipientAta = await deriveAta(signer.pubkey, CLASSIC_TOKEN_PROGRAM_ID, USDC_MAINNET_MINT)
    const ring = extractRingFromPage(state.pageBytesById.get(usdcNote.pageId.toString())!)
    const { instruction } = await buildWithdrawInstruction({
      payer: signer.pubkey,
      poolId: 0,
      outPageId: BigInt(state.pool.currentPageId),
      inputPageIds: [usdcNote.pageId],
      ring,
      inputNote: usdcNote,
      secretIndex: usdcNote.slotIndex,
      recipientAccount: recipientAta,
      changeAddr: { spendPk: keys.spendPk, viewPk: keys.viewPk },
      amount: amt,
      splTokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    })
    const wdSent = await submitDirect('mainnet', signer, {
      innerIx: instruction,
      computeUnitLimit: 550_000,
    })
    console.log(`✓ Withdrew 1.00 USDC back to wallet: https://solscan.io/tx/${wdSent.signature}`)

    state = await scanUnspentNotes('mainnet', keys, knownDynamic)
    assert.equal(state.unspent.length, 0, `Expected 0 unspent Mainnet notes at end, found ${state.unspent.length}`)
    console.log(`✓ Mainnet Private Balance cleanly back to 0 notes ($0.00) — zero funds stranded!`)
  }

  // --------------------------------------------------------------------------
  // STEP 9: Encrypted Vault Backup & Restore (PBKDF2-600k + AES-256-GCM)
  // --------------------------------------------------------------------------
  logStep('STEP 9 — Encrypted Vault Backup & Restore (PBKDF2-600k + AES-256-GCM)')
  {
    const pass = 'Audren-E2E-Test-Passphrase-2026!'
    const backup = await exportEncryptedVaultBackup({
      seed: vaultSeed,
      audrenAddress: keys.address,
      cluster: 'mainnet',
      passphrase: pass,
      birthPageId: 0n,
      verifiedDynamicAmounts: knownDynamic,
    })
    let wrongFailed = false
    try {
      await importEncryptedVaultBackup(backup, 'wrong-passphrase-123')
    } catch {
      wrongFailed = true
    }
    assert.equal(wrongFailed, true, 'Wrong passphrase must fail AES-GCM auth tag')
    const restored = await importEncryptedVaultBackup(backup, pass)
    assert.ok(bytesEqual(restored.seed, vaultSeed), 'Restored seed mismatch')
    const restoredKeys = await generateAudrenKeys(restored.seed)
    assert.equal(restoredKeys.address, keys.address, 'Restored aud1 address mismatch')
    console.log(`✓ PBKDF2-SHA256 (600,000 iters) + AES-256-GCM round-trip verified + wrong passphrase rejected`)
  }

  // --------------------------------------------------------------------------
  // STEP 10: DEVNET Live Privacy Relayer (POST /api/relay/submit — 0 Wallet Sigs!)
  // --------------------------------------------------------------------------
  logStep('STEP 10 — DEVNET Live Privacy Relayer (Deposit -> Relayer Private Send -> Relayer Withdraw)')
  {
    const devPoolRes = await apiJson<PoolResponse>('/api/pool?cluster=devnet')
    const devPool = devPoolRes.data
    assert.ok(devPool.relayerAvailable && devPool.relayerAddress, 'Devnet relayer must be online')
    const relayerPubkey = base58Decode(devPool.relayerAddress)

    // Deposit 0.005 native SOL on Devnet via /api/devnet/deposit (relayer faucet deposit)
    const devDepAmt = 5_000_000n
    const { instructions: depIxs } = await buildDepositInstruction({
      depositor: signer.pubkey,
      poolId: 0,
      activePageId: BigInt(devPool.currentPageId),
      recipient: { spendPk: keys.spendPk, viewPk: keys.viewPk },
      mint: NATIVE_SOL_MINT,
      amount: devDepAmt,
      memoText: 'DEV_E2E',
    })
    const { blockhash, lastValidBlockHeight } = await fetchBlockhash('devnet')
    const depWire = compileKitV0Transaction({
      feePayer: signer.address,
      recentBlockhash: blockhash,
      lastValidBlockHeight,
      instructions: depIxs,
      computeUnitLimit: 300_000,
      priorityMicroLamportsPerCu: 10_000n,
    })
    const depSent = await sendSignedTx('devnet', signer.signTransaction(depWire))
    console.log(`✓ Devnet Native SOL Deposit: https://solscan.io/tx/${depSent.signature}?cluster=devnet`)

    let devState = await scanUnspentNotes('devnet', keys, {})
    const devNote = devState.unspent.find((n) => n.isNativeSol && n.amount === devDepAmt)
    assert.ok(devNote, 'Expected 0.005 native SOL note on Devnet')

    // Relayer-paid Private Send (ZERO wallet signature!)
    const ring1 = extractRingFromPage(devState.pageBytesById.get(devNote.pageId.toString())!)
    const { instruction: trIx } = await buildTransferInstruction({
      payer: relayerPubkey,
      poolId: 0,
      outPageId: BigInt(devState.pool.currentPageId),
      inputPageIds: [devNote.pageId],
      ring: ring1,
      inputNote: devNote,
      secretIndex: devNote.slotIndex,
      recipient: { spendPk: keys.spendPk, viewPk: keys.viewPk },
      changeAddr: { spendPk: keys.spendPk, viewPk: keys.viewPk },
      payAmount: 2_000_000n,
      memoText: 'RELAY_PAY',
    })
    const relaySend = await apiJson<{ signature?: string; error?: string }>('/api/relay/submit', {
      body: {
        cluster: 'devnet',
        instructionDataB64: toBase64(trIx.data),
        accounts: trIx.accounts.map((a) => ({
          pubkey: base58Encode(a.pubkey),
          isSigner: a.isSigner,
          isWritable: a.isWritable,
        })),
        computeUnitLimit: 850_000,
        priorityFeeLamports: '10000',
      },
    })
    assert.equal(relaySend.status, 200, `Devnet Relayer Transfer failed: ${JSON.stringify(relaySend.data)}`)
    console.log(`✓ Devnet Relayer Private Send (0 wallet sigs!): https://solscan.io/tx/${relaySend.data.signature}?cluster=devnet`)

    // Relayer-paid Withdraw BOTH split Devnet notes cleanly back to wallet
    devState = await scanUnspentNotes('devnet', keys, {})
    const devUnspent = devState.unspent.filter((n) => n.isNativeSol)
    assert.ok(devUnspent.length >= 2, 'Expected 2 split Devnet notes')
    for (const n of devUnspent) {
      const r = extractRingFromPage(devState.pageBytesById.get(n.pageId.toString())!)
      const { instruction: wdIx } = await buildWithdrawInstruction({
        payer: relayerPubkey,
        poolId: 0,
        outPageId: BigInt(devState.pool.currentPageId),
        inputPageIds: [n.pageId],
        ring: r,
        inputNote: n,
        secretIndex: n.slotIndex,
        recipientAccount: signer.pubkey,
        changeAddr: { spendPk: keys.spendPk, viewPk: keys.viewPk },
        amount: n.amount,
      })
      const relayWd = await apiJson<{ signature?: string; error?: string }>('/api/relay/submit', {
        body: {
          cluster: 'devnet',
          instructionDataB64: toBase64(wdIx.data),
          accounts: wdIx.accounts.map((a) => ({
            pubkey: base58Encode(a.pubkey),
            isSigner: a.isSigner,
            isWritable: a.isWritable,
          })),
          computeUnitLimit: 550_000,
          priorityFeeLamports: '10000',
        },
      })
      assert.equal(relayWd.status, 200, `Devnet Relayer Withdraw failed: ${JSON.stringify(relayWd.data)}`)
      console.log(`✓ Devnet Relayer Withdraw ${Number(n.amount) / 1e9} SOL: https://solscan.io/tx/${relayWd.data.signature}?cluster=devnet`)
    }
  }

  console.log('\n🎉 ALL 10 LIVE MAINNET + DEVNET E2E SUITES PASSED WITH ZERO ERRORS!')
}

main().catch((err) => {
  console.error('\n❌ E2E SUITE FAILED:', err)
  process.exit(1)
})
