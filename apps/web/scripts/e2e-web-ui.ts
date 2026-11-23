/**
 * Route availability, v1 copy hygiene, and WASM / Web Worker artifact verifier
 * for the Audren static export + Cloudflare Worker.
 *
 * Usage:
 *   BASE_URL=http://127.0.0.1:3040 pnpm --dir apps/web e2e:ui
 */

const BASE_URL = (process.env.BASE_URL ?? 'http://127.0.0.1:3040').replace(/\/+$/, '')

const ROUTES = [
  '/',
  '/how-it-works/',
  '/compare/',
  '/architecture/',
  '/developers/',
  '/demo/',
  '/faq/',
  '/privacy/',
  '/terms/',
] as const

const FORBIDDEN_SNIPPETS = [
  ['Mainnet', 'Beta'].join('-'),
  'solVaultPda',
  'DepositSol',
  'DepositSpl',
  'audren_v2_',
] as const

async function main() {
  for (const route of ROUTES) {
    const res = await fetch(`${BASE_URL}${route}`)
    if (!res.ok) {
      throw new Error(`Route ${route} returned HTTP ${res.status}`)
    }
    const html = await res.text()
    if (!html.includes('Audren')) {
      throw new Error(`Route ${route} missing expected Audren title/copy`)
    }
    for (const forbidden of FORBIDDEN_SNIPPETS) {
      if (html.includes(forbidden)) {
        throw new Error(`Route ${route} contains disallowed string: ${forbidden}`)
      }
    }
  }
  const wasmRes = await fetch(`${BASE_URL}/wasm/audren_circuits.wasm`)
  if (!wasmRes.ok) {
    throw new Error(`/wasm/audren_circuits.wasm returned HTTP ${wasmRes.status}`)
  }
  const wasmBytes = new Uint8Array(await wasmRes.arrayBuffer())
  if (wasmBytes.byteLength < 500_000 || wasmBytes[0] !== 0x00 || wasmBytes[1] !== 0x61) {
    throw new Error(`Invalid WASM binary header or size (${wasmBytes.byteLength} bytes)`)
  }
  const workerRes = await fetch(`${BASE_URL}/wasm/prover-worker.js`)
  if (!workerRes.ok) {
    throw new Error(`/wasm/prover-worker.js returned HTTP ${workerRes.status}`)
  }
  const workerJs = await workerRes.text()
  if (!workerJs.includes('wasm_prove_joinsplit') || !workerJs.includes('wasm_load_pk_compressed')) {
    throw new Error('Invalid /wasm/prover-worker.js payload')
  }
  console.log(
    `Audren v1.2.0 Web UI route, WASM (${wasmBytes.byteLength} B), & Web Worker check PASSED (${ROUTES.length} routes)`,
  )
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
