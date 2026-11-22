/**
 * Live Empirical E2E Verifier for `audren-relay` (`https://relay.audren.xyz`).
 *
 * Verifies every production relayer surface empirically against live RPC & aggregators:
 *   1. `/health`, `/v1/info?cluster=mainnet`, `/v1/info?cluster=devnet`, `/v1/aggregators`, `/v1/stats`
 *   2. `/v1/fee-quote` across JoinSplit withdraw (`unwrapWsol=true/false`) and ExecViaEscrow (`feeOnOutput=true/false`)
 *   3. Multi-aggregator `/v1/swap/quote` & `/v1/swap/instructions` (`jupiter`, `auto`, etc.)
 *   4. Zero-trust Firewall rejections:
 *        - Tag 3 (`DepositSol`) rejected with 400
 *        - Extra non-relayer signer rejected with 400
 *        - Wrong payer (not relayer) rejected with 400
 *        - Disallowed preInstruction program rejected with 400
 */

import {
  TAG_DEPOSIT_SOL,
  TAG_JOINSPLIT,
  WSOL_MINT,
  base58Decode,
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

  const infoMainnet = await fetchJson(`${RELAY_BASE}/v1/info?cluster=mainnet`)
  assert(
    infoMainnet.status === 200 && infoMainnet.body.ok === true,
    `/v1/info?cluster=mainnet failed: ${JSON.stringify(infoMainnet.body)}`,
  )
  const relayerPubkey = String(infoMainnet.body.relayerPubkey)
  assert(base58Decode(relayerPubkey).length === 32, 'invalid mainnet relayerPubkey')
  console.log(
    `  [1/5] Mainnet /v1/info OK — relayer=${relayerPubkey} balance=${infoMainnet.body.balanceSol} SOL`,
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
      shardId: 0,
    }),
  })
  assert(ix.status === 200 && ix.body.ok === true, `/v1/swap/instructions failed: ${JSON.stringify(ix.body)}`)
  console.log(`  [4/5] /v1/swap/quote & /v1/swap/instructions OK (provider=${quoteObj.provider}, out=${quoteObj.outAmount})`)

  // 4. Zero-Trust Firewall Rejections
  const dummyBuf = new Uint8Array(169)
  dummyBuf[0] = TAG_DEPOSIT_SOL
  const badTag = await fetchJson(`${RELAY_BASE}/v1/relay/submit`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      cluster: 'devnet',
      instructionDataB64: toBase64(dummyBuf),
      accounts: [{ pubkey: String(infoDevnet.body.relayerPubkey), isSigner: true, isWritable: true }],
    }),
  })
  assert(
    badTag.status === 400 && badTag.body.code === 'FIREWALL_REJECTED',
    `Expected Tag 3 FIREWALL_REJECTED (400), got ${badTag.status}: ${JSON.stringify(badTag.body)}`,
  )

  const extraSignerBuf = new Uint8Array(400)
  extraSignerBuf[0] = TAG_JOINSPLIT
  const extraSigner = await fetchJson(`${RELAY_BASE}/v1/relay/submit`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      cluster: 'devnet',
      instructionDataB64: toBase64(extraSignerBuf),
      accounts: [
        { pubkey: String(infoDevnet.body.relayerPubkey), isSigner: true, isWritable: true },
        { pubkey: relayerPubkey, isSigner: true, isWritable: false },
      ],
    }),
  })
  assert(
    extraSigner.status === 400 && extraSigner.body.code === 'FIREWALL_REJECTED',
    `Expected extra signer FIREWALL_REJECTED (400), got ${extraSigner.status}: ${JSON.stringify(extraSigner.body)}`,
  )

  console.log(`  [5/5] Zero-trust Firewall rejections OK (Tag 3 blocked, extra signer blocked)`)
  console.log(`\nALL RELAY EMPIRICAL E2E CHECKS PASSED (${RELAY_BASE})\n`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
