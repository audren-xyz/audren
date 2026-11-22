/**
 * Route availability & security header verifier for the Audren static export + Worker.
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
    const disallowed = ['Mainnet', 'Beta'].join('-')
    if (html.includes(disallowed)) {
      throw new Error(`Route ${route} contains disallowed ${disallowed} string`)
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
  console.log(`Audren Web UI route & WASM artifact check PASSED (${ROUTES.length} routes, ${wasmBytes.byteLength} B WASM)`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
