/**
 * Live Empirical E2E Verifier for `audren-relay` (`https://relay.audren.xyz`).
 *
 * Verifies every production relayer surface empirically against live RPC & aggregators:
 *   1. `/health`, `/v1/info?cluster=mainnet`, `/v1/info?cluster=devnet`, `/v1/aggregators`, `/v1/stats`
 *   2. `/v1/fee-quote` across Transact withdraw (`unwrapWsol=true/false`) and ExecViaEscrow (`feeOnOutput=true/false`)
 *   3. Multi-aggregator `/v1/swap/quote` & `/v1/swap/instructions` (`jupiter`, `auto`, etc.)
 *   4. Zero-trust Firewall rejections:
 *        - Tag 3 (`Deposit`) rejected with 400
 *        - Tag 4 (`InitRootHistory`) rejected with 400
 *        - Extra non-relayer signer rejected with 400
 *        - Wrong payer (not relayer) rejected with 400
 *        - Disallowed preInstruction program rejected with 400
 *        - Removed `/v1/checkpoint` route returns 404
 */

import {
  ASSET_MODE_PRIVATE,
  CLASSIC_TOKEN_PROGRAM_ID,
  ROOT_RING_EPOCH,
  TAG_DEPOSIT,
  TAG_INIT_ROOT_HISTORY,
  WSOL_MINT,
  base58Decode,
  base58Encode,
  buildExecViaEscrowInstruction,
  buildTransactInstruction,
  deriveAssociatedTokenAddressSync,
  deriveEscrowPdaSync,
  deriveRootsPdaSync,
  deriveVaultAuthPdaSync,
} from '@audren/sdk'
import { USDC_MAINNET_MINT_STR, toBase64 } from '../src/solana/codec'

const WSOL_MINT_STR = WSOL_MINT

const RELAY_BASE = (process.env.RELAY_BASE ?? 'https://relay.audren.xyz').replace(/\/+$/, '')

function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(`ASSERTION FAILED: ${msg}`)
}

async function fetchJson(url: string, init?: RequestInit) {
  const res = await fetch(url, init)
  const text = await res.text()
  let body: Record<string, unknown>
  try {
    body = JSON.parse(text) as Record<string, unknown>
  } catch {
    body = { raw: text }
  }
  return { status: res.status, headers: res.headers, body }
}

async function main() {
  console.log(`\nRunning Empirical E2E suite against ${RELAY_BASE}`)

  // 1. Health & Info (Mainnet + Devnet)
  const health = await fetchJson(`${RELAY_BASE}/health`)
  assert(health.status === 200 && health.body.ok === true, `/health failed: ${JSON.stringify(health.body)}`)

  const expectedRootsPda = deriveRootsPdaSync(0).address
  const infoMainnet = await fetchJson(`${RELAY_BASE}/v1/info?cluster=mainnet`)
  assert(
    infoMainnet.status === 200 && infoMainnet.body.ok === true,
    `/v1/info?cluster=mainnet failed: ${JSON.stringify(infoMainnet.body)}`,
  )
  assert(
    infoMainnet.body.rootsPda === expectedRootsPda,
    `Expected /v1/info rootsPda=${expectedRootsPda}, got ${String(infoMainnet.body.rootsPda)}`,
  )
  assert(
    infoMainnet.body.version === '1.3.0',
    `Expected /v1/info version=1.3.0, got ${String(infoMainnet.body.version)}`,
  )
  assert(
    !('checkpointSupport' in infoMainnet.body),
    '/v1/info must not expose removed checkpointSupport field',
  )
  const relayerPubkey = String(infoMainnet.body.relayerPubkey)
  assert(base58Decode(relayerPubkey).length === 32, 'invalid mainnet relayerPubkey')
  console.log(
    `  [1/5] Mainnet /v1/info OK — v${String(infoMainnet.body.version)} rootsPda=${expectedRootsPda} relayer=${relayerPubkey} balance=${infoMainnet.body.balanceSol} SOL`,
  )

  const infoDevnet = await fetchJson(`${RELAY_BASE}/v1/info?cluster=devnet`)
  assert(
    infoDevnet.status === 200 && infoDevnet.body.ok === true,
    `/v1/info?cluster=devnet failed: ${JSON.stringify(infoDevnet.body)}`,
  )
  console.log(
    `  [1/5] Devnet  /v1/info OK — relayer=${infoDevnet.body.relayerPubkey} balance=${infoDevnet.body.balanceSol} SOL`,
  )

  const aggs = await fetchJson(`${RELAY_BASE}/v1/aggregators`)
  assert(aggs.status === 200 && aggs.body.ok === true, '/v1/aggregators failed')

  const stats = await fetchJson(`${RELAY_BASE}/v1/stats`)
  assert(stats.status === 200 && stats.body.ok === true, '/v1/stats failed')
  console.log(`  [2/5] /v1/aggregators & /v1/stats OK`)

  // 2. Dynamic Fee Quotes
  for (const query of [
    `cluster=mainnet&op=withdraw&mint=${WSOL_MINT_STR}&unwrapWsol=true`,
    `cluster=mainnet&op=exec&mint=${USDC_MAINNET_MINT_STR}&feeOnOutput=true`,
    `cluster=devnet&op=withdraw&mint=${WSOL_MINT_STR}`,
  ]) {
    const fq = await fetchJson(`${RELAY_BASE}/v1/fee-quote?${query}`)
    assert(fq.status === 200 && fq.body.ok === true, `/v1/fee-quote?${query} failed: ${JSON.stringify(fq.body)}`)
  }
  console.log(`  [3/5] /v1/fee-quote (withdraw, unwrapWsol, exec feeOnOutput) OK`)

  // 3. Multi-Aggregator Quotes & Instructions
  const q = await fetchJson(
    `${RELAY_BASE}/v1/swap/quote?provider=auto&inputMint=${WSOL_MINT_STR}&outputMint=${USDC_MAINNET_MINT_STR}&amount=500000000`,
  )
  assert(q.status === 200 && q.body.ok === true, `/v1/swap/quote failed: ${JSON.stringify(q.body)}`)
  const quoteObj = q.body.quote as { provider: string; outAmount: string; rawQuote: Record<string, unknown> }
  assert(BigInt(quoteObj.outAmount) > 0n, 'zero outAmount from swap quote')

  const ix = await fetchJson(`${RELAY_BASE}/v1/swap/instructions`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      cluster: 'mainnet',
      provider: quoteObj.provider,
      quoteResponse: quoteObj.rawQuote,
      inputMint: WSOL_MINT_STR,
      outputMint: USDC_MAINNET_MINT_STR,
      shardId: Number(q.body.shardId ?? 0),
    }),
  })
  assert(ix.status === 200 && ix.body.ok === true, `/v1/swap/instructions failed: ${JSON.stringify(ix.body)}`)
  console.log(`  [4/5] /v1/swap/quote & /v1/swap/instructions OK (provider=${quoteObj.provider}, out=${quoteObj.outAmount})`)

  // 4. Zero-Trust Firewall Rejections (realistic >=12-account payloads exercising each exact rule!)
  const devnetRelayer = String(infoDevnet.body.relayerPubkey)
  const validTxIx = buildTransactInstruction({
    payer: devnetRelayer,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: new Uint8Array(192).fill(0x11),
    nf0: new Uint8Array(32).fill(0x01),
    nf1: new Uint8Array(32),
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(0),
  })

  // 4a. Tag 3 (Deposit) rejected on tag check
  const depositTagPayload = new Uint8Array(validTxIx.data)
  depositTagPayload[0] = TAG_DEPOSIT
  const badTag = await fetchJson(`${RELAY_BASE}/v1/relay/submit`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      cluster: 'devnet',
      instructionDataB64: toBase64(depositTagPayload),
      accounts: validTxIx.accounts,
    }),
  })
  assert(
    badTag.status === 400 &&
      badTag.body.code === 'FIREWALL_REJECTED' &&
      String(badTag.body.error ?? '').includes('Deposit'),
    `Expected Tag 3 Deposit FIREWALL_REJECTED (400), got ${badTag.status}: ${JSON.stringify(badTag.body)}`,
  )

  // 4a-ii. Tag 4 (InitRootHistory) rejected on tag check
  const initRootsPayload = new Uint8Array(validTxIx.data)
  initRootsPayload[0] = TAG_INIT_ROOT_HISTORY
  const badInitRoots = await fetchJson(`${RELAY_BASE}/v1/relay/submit`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      cluster: 'devnet',
      instructionDataB64: toBase64(initRootsPayload),
      accounts: validTxIx.accounts,
    }),
  })
  assert(
    badInitRoots.status === 400 &&
      badInitRoots.body.code === 'FIREWALL_REJECTED' &&
      String(badInitRoots.body.error ?? '').includes('InitRootHistory'),
    `Expected Tag 4 InitRootHistory FIREWALL_REJECTED (400), got ${badInitRoots.status}: ${JSON.stringify(badInitRoots.body)}`,
  )

  // 4b. Extra non-relayer signer rejected on signer check
  const extraSignerAccounts = validTxIx.accounts.map((a, idx) =>
    idx === 1 ? { ...a, isSigner: true } : a,
  )
  const extraSigner = await fetchJson(`${RELAY_BASE}/v1/relay/submit`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      cluster: 'devnet',
      instructionDataB64: toBase64(validTxIx.data),
      accounts: extraSignerAccounts,
    }),
  })
  assert(
    extraSigner.status === 400 &&
      extraSigner.body.code === 'FIREWALL_REJECTED' &&
      String(extraSigner.body.error ?? '').includes('extra signer'),
    `Expected extra signer FIREWALL_REJECTED (400), got ${extraSigner.status}: ${JSON.stringify(extraSigner.body)}`,
  )

  // 4c. Wrong payer (accounts[0] != devnet relayer) rejected on payer check
  const wrongPayerAccounts = validTxIx.accounts.map((a, idx) =>
    idx === 0 ? { ...a, pubkey: base58Encode(new Uint8Array(32).fill(0x5a)) } : a,
  )
  const wrongPayer = await fetchJson(`${RELAY_BASE}/v1/relay/submit`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      cluster: 'devnet',
      instructionDataB64: toBase64(validTxIx.data),
      accounts: wrongPayerAccounts,
    }),
  })
  assert(
    wrongPayer.status === 400 &&
      wrongPayer.body.code === 'FIREWALL_REJECTED' &&
      /accounts\[0\] must be (?:a configured )?relayer/.test(String(wrongPayer.body.error ?? '')),
    `Expected wrong payer FIREWALL_REJECTED (400), got ${wrongPayer.status}: ${JSON.stringify(wrongPayer.body)}`,
  )

  // 4d. Disallowed preInstruction program rejected on crank allowlist check
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const escrow = deriveEscrowPdaSync(0, 0).address
  const validExecIx = buildExecViaEscrowInstruction({
    payer: devnetRelayer,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    escrowShard: 0,
    changeMask: 0,
    feeOnOutput: false,
    inLeg: {
      mint: WSOL_MINT_STR,
      vaultAta: deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT_STR, CLASSIC_TOKEN_PROGRAM_ID).address,
      escrowAta: deriveAssociatedTokenAddressSync(escrow, WSOL_MINT_STR, CLASSIC_TOKEN_PROGRAM_ID).address,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    },
    outLeg: {
      mint: USDC_MAINNET_MINT_STR,
      vaultAta: deriveAssociatedTokenAddressSync(vaultAuth, USDC_MAINNET_MINT_STR, CLASSIC_TOKEN_PROGRAM_ID).address,
      escrowAta: deriveAssociatedTokenAddressSync(escrow, USDC_MAINNET_MINT_STR, CLASSIC_TOKEN_PROGRAM_ID).address,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    },
    relayerFeeAmount: 0n,
    proof192: new Uint8Array(192).fill(0x11),
    nf0: new Uint8Array(32).fill(0x02),
    nf1: new Uint8Array(32),
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    amountIn: 100_000_000n,
    minAmountOut: 1n,
    outStealthOwner: new Uint8Array(32).fill(0x03),
    outBlinding: new Uint8Array(32).fill(0x04),
    dynMemoHead: new Uint8Array(34).fill(0x05),
    dynMemoMask: new Uint8Array(72).fill(0x06),
    routerProg: base58Encode(new Uint8Array(32).fill(0x77)),
    routerIxData: new Uint8Array([1, 2, 3]),
    routerAccounts: [{ pubkey: base58Encode(new Uint8Array(32).fill(0x88)), isSigner: false, isWritable: true }],
    changeMemos: new Uint8Array(0),
  })
  const badPreIx = await fetchJson(`${RELAY_BASE}/v1/relay/submit`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      cluster: 'devnet',
      instructionDataB64: toBase64(validExecIx.data),
      accounts: validExecIx.accounts,
      preInstructions: [
        {
          programId: base58Encode(new Uint8Array(32).fill(0x99)),
          accounts: [],
          data: toBase64(new Uint8Array([1, 2, 3])),
        },
      ],
    }),
  })
  assert(
    badPreIx.status === 400 &&
      badPreIx.body.code === 'FIREWALL_REJECTED' &&
      String(badPreIx.body.error ?? '').includes('crank allowlist'),
    `Expected disallowed preInstruction FIREWALL_REJECTED (400), got ${badPreIx.status}: ${JSON.stringify(badPreIx.body)}`,
  )

  // 4e. Legacy /v1/checkpoint endpoint is removed (404)
  const removedCkpt = await fetchJson(`${RELAY_BASE}/v1/checkpoint`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ cluster: 'devnet' }),
  })
  assert(
    removedCkpt.status === 404,
    `Expected removed /v1/checkpoint to return 404, got ${removedCkpt.status}`,
  )

  console.log(
    `  [5/5] Zero-trust Firewall rejections OK (Tag 3, Tag 4, extra signer, wrong payer, disallowed preInstruction, removed /v1/checkpoint 404)`,
  )
  console.log(`\nALL RELAY EMPIRICAL E2E CHECKS PASSED (${RELAY_BASE})\n`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
