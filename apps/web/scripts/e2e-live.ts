/**
 * Live API smoke verifier for the Audren Cloudflare Worker (`apps/web/worker/index.ts`).
 *
 * Usage:
 *   BASE_URL=https://audren.xyz pnpm --dir apps/web e2e:api
 */

import { AUDREN_PROGRAM_ID, PROTOCOL_VERSION, derivePoolPdaSync, deriveVaultAuthPdaSync } from '../lib/audren-crypto'
import { AUDREN } from '../lib/protocol'

const BASE_URL = (process.env.BASE_URL ?? 'http://127.0.0.1:8787').replace(/\/+$/, '')

async function assertOkJson(path: string, init?: RequestInit): Promise<Record<string, unknown>> {
  const res = await fetch(`${BASE_URL}${path}`, init)
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>
  if (!res.ok) {
    throw new Error(`${path} returned HTTP ${res.status}: ${JSON.stringify(body)}`)
  }
  return body
}

async function main() {
  const expectedPool0 = derivePoolPdaSync(0, AUDREN_PROGRAM_ID).address
  const expectedVaultAuth = deriveVaultAuthPdaSync(0, AUDREN_PROGRAM_ID).address
  if (expectedPool0 !== AUDREN.pool0Pda || expectedVaultAuth !== AUDREN.vaultAuthPda) {
    throw new Error('AUDREN protocol register PDAs drifted from canonical v1 PDA derivation')
  }
  if ('solVaultPda' in AUDREN) {
    throw new Error('AUDREN protocol register must not contain removed solVaultPda')
  }
  if (
    AUDREN.version !== '1.2.1' ||
    AUDREN.mainnet.pool0Alt.entries.length !== 40 ||
    AUDREN.devnet.pool0Alt.entries.length !== 40
  ) {
    throw new Error('AUDREN protocol register missing v1.2.1 version or 40-entry frozen Pool #0 ALTs')
  }

  const pool = await assertOkJson('/api/pool?cluster=devnet&poolId=0')
  if (
    pool.programId !== AUDREN_PROGRAM_ID ||
    pool.poolPda !== expectedPool0 ||
    pool.vaultAuthPda !== expectedVaultAuth ||
    'solVaultPda' in pool
  ) {
    throw new Error(`Pool mismatch: ${JSON.stringify(pool)}`)
  }
  const devnetPool = await assertOkJson('/api/devnet/pool')
  if (devnetPool.protocolVersion !== PROTOCOL_VERSION) {
    throw new Error(
      `Expected protocolVersion=${PROTOCOL_VERSION}, got ${String(devnetPool.protocolVersion)}`,
    )
  }
  const bh = await assertOkJson('/api/rpc/blockhash?cluster=devnet')
  if (typeof bh.blockhash !== 'string' || bh.blockhash.length < 32) {
    throw new Error(`Invalid blockhash response: ${JSON.stringify(bh)}`)
  }
  const wasmRes = await fetch(`${BASE_URL}/wasm/audren_circuits.wasm`, { method: 'HEAD' })
  if (!wasmRes.ok) {
    throw new Error(`Missing /wasm/audren_circuits.wasm: HTTP ${wasmRes.status}`)
  }
  const workerRes = await fetch(`${BASE_URL}/wasm/prover-worker.js`, { method: 'HEAD' })
  if (!workerRes.ok) {
    throw new Error(`Missing /wasm/prover-worker.js: HTTP ${workerRes.status}`)
  }
  console.log(`Audren ${AUDREN.releaseTag} API smoke check PASSED against ${BASE_URL}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
