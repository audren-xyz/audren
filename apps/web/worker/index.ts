import { ed25519 } from '@noble/curves/ed25519.js'
import {
  AUDREN_PROGRAM_ID,
  AUDREN_PROGRAM_ID_STR,
  NOTE_CT_LEN,
  SYSTEM_PROGRAM_ID,
  base58Decode,
  base58Encode,
  buildAndSignV1Transaction,
  bytesEqual,
  concatBytes,
  decodeEpochPageHeader,
  deriveEpochPagePda,
  derivePageRentVaultPda,
  derivePoolPda,
  deriveSolVaultPda,
  extractEpochPageNotes,
  fromBase64,
  fromHex,
  isNonZeroPoint,
  readU64le,
  toBase64,
  toHex,
  u64le,
  type SolanaAccountMeta,
  type SolanaInstruction,
} from '../lib/audren-crypto'
import {
  CLASSIC_TOKEN_PROGRAM_ID,
  CLASSIC_TOKEN_PROGRAM_ID_STR,
  MAX_APPEND_LANES,
  MAX_ESCROW_SHARDS,
  PAGE_SCAN_LEN,
  PAGE_SCAN_OFFSET,
  TAG_MERGE,
  TAG_OPEN_LANE_PAGE,
  TAG_OPEN_PAGE,
  TAG_SWAP_VIA_ROUTER,
  TAG_TRANSFER,
  TAG_WITHDRAW,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID_STR,
  USDC_MAINNET_MINT_STR,
  WSOL_MINT,
  WSOL_MINT_STR,
  buildCreateAtaIdempotentIx,
  decodeAppendLaneState,
  deriveAta,
  deriveLanePda,
  deriveLaneRentVaultPda,
  deriveSwapEscrowPda,
  deriveVaultAuthPda,
  laneOfPageId,
  pageIdForLane,
  seqOfPageId,
} from '../lib/audren-prover'

interface ServiceBinding {
  fetch(input: Request | URL | string, init?: RequestInit): Promise<Response>
}

interface Env {
  ASSETS: ServiceBinding
  /** Optional Cloudflare Worker service bindings for custom token metadata/logo gateway. */
  GATEWAY?: ServiceBinding
  GATEWAY_SEARCH?: ServiceBinding
  /** Optional origin header used when forwarding to `GATEWAY` / `GATEWAY_SEARCH`. */
  TOKEN_GATEWAY_ORIGIN?: string
  /** Optional canonical production hostname (e.g. `audren.xyz`) for `www.` redirect. */
  CANONICAL_HOST?: string
  DEVNET_RPC_URL?: string
  DEVNET_DEMO_SECRET_B64?: string
  MAINNET_RPC_URL?: string
  JUPITER_API_URL?: string
  JUPITER_API_KEY?: string
}

type Cluster = 'mainnet' | 'devnet'

const DEFAULT_GATEWAY_ORIGIN = 'https://gateway.internal'
const MAX_DEMO_DEPOSIT_LAMPORTS = 5_000_000n
const MIN_DEMO_DEPOSIT_LAMPORTS = 100_000n
const RATE_WINDOW_MS = 10 * 60 * 1000
const RATE_MAX_REQUESTS = 8
const RELAY_RATE_MAX = 6
const PAGE_ROLLOVER_THRESHOLD = 28

interface GatewayTokenCard {
  mint: string
  symbol: string | null
  name: string | null
  decimals: number | null
  logo: string | null
  logoUrl?: string | null
  tokenProgram: 'spl-token' | 'token-2022' | null
  trust?: {
    tier: number | null
    reasons?: string[] | null
    flags?: string[] | null
  }
  price?: {
    bid?: number
    ask?: number
    mid?: number
    asOf?: string | null
  } | null
  liquidityUsd?: number | null
}

interface ResolvedTokenInfo {
  mint: string
  symbol: string
  name: string
  decimals: number | null
  tokenProgram: string
  logoUrl: string | null
  priceUsd: number | null
  liquidityUsd: number | null
  verified: boolean
  flagged: boolean
}

const SHA256_RE = /^[0-9a-f]{64}$/

function shortMint(mint: string): string {
  return mint.length > 10 ? `${mint.slice(0, 4)}…${mint.slice(-4)}` : mint
}

function normalizeGatewayCard(mint: string, card: GatewayTokenCard): ResolvedTokenInfo {
  const flags = Array.isArray(card.trust?.flags) ? card.trust.flags : []
  const flagged = flags.length > 0
  const tier = typeof card.trust?.tier === 'number' ? card.trust.tier : null
  const logoSha = !flagged && typeof card.logo === 'string' && SHA256_RE.test(card.logo) ? card.logo : null
  const mid =
    typeof card.price?.mid === 'number' && Number.isFinite(card.price.mid) && card.price.mid > 0
      ? card.price.mid
      : null
  const tokenProgram =
    card.tokenProgram === 'token-2022' ? TOKEN_2022_PROGRAM_ID_STR : CLASSIC_TOKEN_PROGRAM_ID_STR
  const fallbackSymbol = shortMint(mint)
  return {
    mint,
    symbol: !flagged && card.symbol?.trim() ? card.symbol.trim() : fallbackSymbol,
    name: !flagged && card.name?.trim() ? card.name.trim() : 'Solana Token',
    decimals: typeof card.decimals === 'number' && Number.isSafeInteger(card.decimals) ? card.decimals : null,
    tokenProgram,
    logoUrl: logoSha ? `/api/tokens/logo/${logoSha}.webp` : null,
    priceUsd: mid,
    liquidityUsd:
      typeof card.liquidityUsd === 'number' && Number.isFinite(card.liquidityUsd) && card.liquidityUsd > 0
        ? card.liquidityUsd
        : null,
    verified: !flagged && tier !== null && tier <= 2,
    flagged,
  }
}

interface JupiterTokenV2 {
  id: string
  name?: string | null
  symbol?: string | null
  icon?: string | null
  decimals?: number | null
  tokenProgram?: string | null
  usdPrice?: number | null
  liquidity?: number | null
  isVerified?: boolean | null
  audit?: { isSus?: boolean | null } | null
}

const POPULAR_TOKEN_MINTS = [
  'So11111111111111111111111111111111111111112', // SOL
  'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', // USDC
  'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', // USDT
  'JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN', // JUP
  '2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo', // PYUSD
  'J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn', // JitoSOL
  'DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263', // BONK
  'EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm', // WIF
  '4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R', // RAY
  'cbbtcf3aa214zXHbiAZQwf4122FBYbraNdFqgw4iMij', // cbBTC
  'USDSwr9ApdHk5bvJKMjzff41FfuX8bSxdKcR81vTwcA', // USDS
]

interface MintIconMeta {
  iconUrl: string
  symbol: string
}

const MINT_ICON_CACHE = new Map<string, MintIconMeta>()

function rememberMintIcon(mint: string, iconUrl: string, symbol: string): void {
  if (MINT_ICON_CACHE.size >= 1_000) {
    const firstKey = MINT_ICON_CACHE.keys().next().value
    if (firstKey) MINT_ICON_CACHE.delete(firstKey)
  }
  const meta: MintIconMeta = { iconUrl, symbol }
  MINT_ICON_CACHE.set(mint, meta)
  const edgeCache = (caches as unknown as { default?: Cache }).default
  if (edgeCache) {
    const metaKey = new Request(`https://audren.xyz/_internal/mint-icon-meta/${mint}`, { method: 'GET' })
    const metaRes = new Response(JSON.stringify(meta), {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'cache-control': 'public, max-age=86400',
      },
    })
    edgeCache.put(metaKey, metaRes).catch(() => {})
  }
}

function escapeXmlText(raw: string): string {
  return raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function buildMonogramLogoSvg(symbolHint: string | null | undefined, mint: string): string {
  const clean = (symbolHint ?? '').replace(/[^A-Za-z0-9]/g, '').toUpperCase()
  const label = (clean || mint.slice(0, 2).toUpperCase()).slice(0, 3) || '?'
  const fontSize = label.length >= 3 ? 11 : 13
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40"><rect width="40" height="40" rx="20" fill="#eef1ec"/><rect x="0.75" y="0.75" width="38.5" height="38.5" rx="19.25" fill="none" stroke="#c8d0c6" stroke-width="1.5"/><text x="50%" y="53%" text-anchor="middle" dominant-baseline="middle" font-family="ui-monospace,SFMono-Regular,Menlo,monospace" font-size="${fontSize}" font-weight="700" fill="#18221b">${escapeXmlText(label)}</text></svg>`
}

function normalizeJupiterTokenV2(tok: JupiterTokenV2): ResolvedTokenInfo {
  const flagged = tok.audit?.isSus === true
  const fallbackSymbol = shortMint(tok.id)
  const symbol = !flagged && tok.symbol?.trim() ? tok.symbol.trim() : fallbackSymbol
  const priceUsd =
    typeof tok.usdPrice === 'number' && Number.isFinite(tok.usdPrice) && tok.usdPrice > 0
      ? tok.usdPrice
      : null
  const liquidityUsd =
    typeof tok.liquidity === 'number' && Number.isFinite(tok.liquidity) && tok.liquidity > 0
      ? tok.liquidity
      : null
  const tokenProgram =
    tok.tokenProgram === TOKEN_2022_PROGRAM_ID_STR
      ? TOKEN_2022_PROGRAM_ID_STR
      : CLASSIC_TOKEN_PROGRAM_ID_STR
  const hasSafeIcon = !flagged && typeof tok.icon === 'string' && isSafeExternalIconUrl(tok.icon)
  if (hasSafeIcon && tok.icon) {
    rememberMintIcon(tok.id, tok.icon, symbol)
  }
  const symParam = encodeURIComponent(symbol.replace(/[^A-Za-z0-9]/g, '').slice(0, 4) || tok.id.slice(0, 2))
  return {
    mint: tok.id,
    symbol,
    name: !flagged && tok.name?.trim() ? tok.name.trim() : 'Solana Token',
    decimals: typeof tok.decimals === 'number' && Number.isSafeInteger(tok.decimals) ? tok.decimals : null,
    tokenProgram,
    logoUrl: hasSafeIcon ? `/api/tokens/mint-logo/${tok.id}.webp?s=${symParam}` : null,
    priceUsd,
    liquidityUsd,
    verified: !flagged && tok.isVerified === true,
    flagged,
  }
}

async function fetchJupiterTokensV2Path(
  env: Env,
  pathAndQuery: string,
  timeoutMs = 5_000,
  opts?: { cacheTtlSec?: number },
): Promise<JupiterTokenV2[]> {
  if (!env.JUPITER_API_KEY?.trim() && !env.JUPITER_API_URL?.trim()) {
    return []
  }
  const cacheTtlSec = opts?.cacheTtlSec ?? 60
  const edgeCache = (caches as unknown as { default?: Cache }).default
  const cacheKey = new Request(
    `https://audren.xyz/_internal/jup-tokens-v2/${encodeURIComponent(pathAndQuery)}`,
    { method: 'GET' },
  )
  if (edgeCache && cacheTtlSec > 0) {
    const hit = await edgeCache.match(cacheKey)
    if (hit) {
      try {
        const cached = (await hit.json()) as unknown
        if (Array.isArray(cached)) return cached as JupiterTokenV2[]
      } catch {
        // Ignore corrupt cache entry
      }
    }
  }

  const base = (env.JUPITER_API_URL?.trim() || 'https://api.jup.ag')
    .replace(/\/+$/, '')
    .replace(/\/swap\/v1$/, '')
  const headers: Record<string, string> = {
    accept: 'application/json',
    ...(env.JUPITER_API_KEY?.trim() ? { 'x-api-key': env.JUPITER_API_KEY.trim() } : {}),
  }

  try {
    const res = await fetch(`${base}/tokens/v2/${pathAndQuery}`, {
      headers,
      signal: AbortSignal.timeout(timeoutMs),
    })
    if (!res.ok) return []
    const data = (await res.json()) as unknown
    if (Array.isArray(data)) {
      if (edgeCache && cacheTtlSec > 0 && data.length > 0) {
        edgeCache
          .put(
            cacheKey,
            new Response(JSON.stringify(data), {
              status: 200,
              headers: {
                'content-type': 'application/json',
                'cache-control': `public, max-age=${cacheTtlSec}`,
              },
            }),
          )
          .catch(() => {})
      }
      return data as JupiterTokenV2[]
    }
  } catch {
    // Upstream token metadata lookup failed — caller falls back cleanly
  }
  return []
}

async function fetchGatewayTokensByMints(
  env: Env,
  mints: string[],
  clientIp?: string,
): Promise<Map<string, ResolvedTokenInfo>> {
  const out = new Map<string, ResolvedTokenInfo>()
  const unique = [...new Set(mints)].filter((m) => {
    try {
      return base58Decode(m).length === 32
    } catch {
      return false
    }
  })
  if (unique.length === 0) return out

  // Tier 1: optional Worker service binding for fast in-network token metadata & prices
  if (env.GATEWAY_SEARCH) {
    const gwOrigin = (env.TOKEN_GATEWAY_ORIGIN ?? DEFAULT_GATEWAY_ORIGIN).replace(/\/+$/, '')
    const batches: string[][] = []
    for (let i = 0; i < unique.length; i += 100) batches.push(unique.slice(i, i + 100))

    await Promise.all(
      batches.map(async (batch) => {
        try {
          const headers: Record<string, string> = {
            'content-type': 'application/json',
            accept: 'application/json',
          }
          if (clientIp && clientIp !== 'unknown') headers['CF-Connecting-IP'] = clientIp
          const res = await env.GATEWAY_SEARCH!.fetch(`${gwOrigin}/v1/assets/get`, {
            method: 'POST',
            headers,
            body: JSON.stringify({ mints: batch }),
            signal: AbortSignal.timeout(4_500),
          })
          if (!res.ok) return
          const json = (await res.json()) as { data?: { items?: Record<string, GatewayTokenCard> } }
          const items = json.data?.items
          if (!items || typeof items !== 'object') return
          for (const [m, card] of Object.entries(items)) {
            if (card && typeof card === 'object') out.set(m, normalizeGatewayCard(m, card))
          }
        } catch {
          // Fall through seamlessly to Tier 2 Jupiter Tokens V2
        }
      }),
    )
  }

  // Tier 2: Automatic Jupiter Tokens V2 fallback for any unresolved mints (zero single point of failure)
  const missing = unique.filter((m) => !out.has(m))
  if (missing.length > 0) {
    const jupBatches: string[][] = []
    for (let i = 0; i < missing.length; i += 50) jupBatches.push(missing.slice(i, i + 50))
    await Promise.all(
      jupBatches.map(async (batch) => {
        const list = await fetchJupiterTokensV2Path(
          env,
          `search?query=${encodeURIComponent(batch.join(','))}`,
          5_000,
        )
        for (const tok of list) {
          if (tok?.id && !out.has(tok.id)) {
            out.set(tok.id, normalizeJupiterTokenV2(tok))
          }
        }
      }),
    )
  }

  return out
}

const rateBuckets = new Map<string, number[]>()

function checkRateLimit(bucketKey: string, maxReqs: number): { allowed: boolean; retryAfterSec: number } {
  const now = Date.now()
  const recent = (rateBuckets.get(bucketKey) ?? []).filter((ts) => now - ts < RATE_WINDOW_MS)
  if (recent.length >= maxReqs) {
    const oldest = recent[0] ?? now
    return {
      allowed: false,
      retryAfterSec: Math.max(1, Math.ceil((RATE_WINDOW_MS - (now - oldest)) / 1000)),
    }
  }
  recent.push(now)
  rateBuckets.set(bucketKey, recent)
  if (rateBuckets.size > 1500) {
    for (const [k, v] of rateBuckets.entries()) {
      if (v.every((ts) => now - ts >= RATE_WINDOW_MS)) rateBuckets.delete(k)
    }
  }
  return { allowed: true, retryAfterSec: 0 }
}

function getClientIp(request: Request): string {
  return (
    request.headers.get('cf-connecting-ip') ??
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    'unknown'
  )
}

function sanitizeError(err: unknown, fallback: string): string {
  const msg = err instanceof Error ? err.message : fallback
  return msg.replace(/https?:\/\/[^\s]+/gi, '[rpc]').slice(0, 260)
}

function jsonResponse(payload: unknown, status = 200, extraHeaders?: Record<string, string>) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      ...extraHeaders,
    },
  })
}

function parseCluster(raw: string | null | undefined, fallback: Cluster = 'mainnet'): Cluster {
  return raw === 'devnet' ? 'devnet' : raw === 'mainnet' ? 'mainnet' : fallback
}

function getRpcUrl(env: Env, cluster: Cluster): string | null {
  return cluster === 'mainnet' ? env.MAINNET_RPC_URL ?? null : env.DEVNET_RPC_URL ?? null
}

function getRelayerSecret(env: Env, cluster: Cluster): Uint8Array | null {
  // Wallet-mode Mainnet & Devnet relaying is served by the standalone `audren-relay` Worker (`https://relay.audren.xyz`).
  // `audren-web` holds only the Devnet Sandbox faucet key (`DEVNET_DEMO_SECRET_B64`).
  const b64 = cluster === 'devnet' ? env.DEVNET_DEMO_SECRET_B64 : undefined
  if (!b64) return null
  try {
    const raw = fromBase64(b64)
    return raw.length === 32 ? raw : null
  } catch {
    return null
  }
}

async function rpcCall<T>(rpcUrl: string, method: string, params: unknown[]): Promise<T> {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  })
  if (!res.ok) {
    throw new Error(`Solana RPC HTTP ${res.status}`)
  }
  const body = (await res.json()) as { result?: T; error?: { message?: string; data?: unknown } }
  if (body.error) {
    throw new Error(body.error.message ?? 'Solana RPC error')
  }
  return body.result as T
}

async function fetchAccountBytes(
  rpcUrl: string,
  addressB58: string,
): Promise<{ bytes: Uint8Array; lamports: number }> {
  const res = await rpcCall<{ value: { data: [string, string]; lamports: number } | null }>(
    rpcUrl,
    'getAccountInfo',
    [addressB58, { encoding: 'base64', commitment: 'confirmed' }],
  )
  if (!res.value) throw new Error(`Account ${addressB58} not found`)
  return {
    bytes: fromBase64(res.value.data[0]),
    lamports: res.value.lamports,
  }
}

async function fetchBalance(rpcUrl: string, addressB58: string): Promise<number> {
  const res = await rpcCall<{ value: number }>(rpcUrl, 'getBalance', [
    addressB58,
    { commitment: 'confirmed' },
  ])
  return res.value
}

function decodePoolState(bytes: Uint8Array) {
  if (bytes.length < 48) throw new Error('PoolState too short')
  const mode = bytes[10]
  const paused = bytes[11] !== 0
  const currentPageId = readU64le(bytes, 16)
  const totalNotes = readU64le(bytes, 24)
  const totalSpends = readU64le(bytes, 32)
  const pageRentFeeLamports = readU64le(bytes, 40)
  const rawLanes = bytes.length > 116 ? bytes[116] : 1
  const activeLanes = rawLanes >= 1 ? Math.min(rawLanes, MAX_APPEND_LANES) : 1
  return { mode, paused, currentPageId, totalNotes, totalSpends, pageRentFeeLamports, activeLanes }
}

const IMMUTABLE_CACHE_CONTROL = 'public, max-age=31536000, immutable'

async function getEdgeCache(): Promise<Cache | null> {
  try {
    const cacheStorage = (globalThis as unknown as { caches?: { default?: Cache } }).caches
    return cacheStorage?.default ?? null
  } catch {
    return null
  }
}

function formatPublicNotes(pageBytes: Uint8Array) {
  return extractEpochPageNotes(pageBytes).map((n) => ({
    slotIndex: n.slotIndex,
    viewTag: n.viewTag,
    ephemeralPk: base58Encode(n.ephemeralPk),
    stealthPk: base58Encode(n.stealthPk),
    assetTag: base58Encode(n.assetTag),
    commitment: base58Encode(n.commitment),
    ciphertextHex: toHex(n.ciphertext),
  }))
}

async function waitForConfirmation(rpcUrl: string, signature: string): Promise<{ slot: number }> {
  for (let attempt = 0; attempt < 30; attempt++) {
    const res = await rpcCall<{
      value: Array<{
        slot: number
        err: unknown
        confirmationStatus?: string
      } | null>
    }>(rpcUrl, 'getSignatureStatuses', [[signature], { searchTransactionHistory: true }])

    const status = res.value[0]
    if (status) {
      if (status.err) {
        throw new Error(`Transaction failed on-chain: ${JSON.stringify(status.err)}`)
      }
      if (status.confirmationStatus === 'confirmed' || status.confirmationStatus === 'finalized') {
        return { slot: status.slot }
      }
    }
    await new Promise((r) => setTimeout(r, 750))
  }
  throw new Error('Timed out waiting for confirmation — inspect signature on Solscan')
}

function solscanTxUrl(signature: string, cluster: Cluster): string {
  return cluster === 'mainnet'
    ? `https://solscan.io/tx/${signature}`
    : `https://solscan.io/tx/${signature}?cluster=devnet`
}

function explorerTxUrl(signature: string, cluster: Cluster): string {
  return cluster === 'mainnet'
    ? `https://explorer.solana.com/tx/${signature}`
    : `https://explorer.solana.com/tx/${signature}?cluster=devnet`
}

// ============================================================================
// GET /api/pool?cluster=mainnet|devnet (& GET /api/devnet/pool)
// ============================================================================

async function handleGetPool(request: Request, env: Env, forcedCluster?: Cluster): Promise<Response> {
  const url = new URL(request.url)
  const cluster = forcedCluster ?? parseCluster(url.searchParams.get('cluster'), 'mainnet')
  const rpcUrl = getRpcUrl(env, cluster)
  if (!rpcUrl) {
    return jsonResponse({ error: `${cluster} RPC is not configured` }, 503)
  }

  try {
    const [poolPda, solVaultPda, vaultAuthPda, escrow0Pda] = await Promise.all([
      derivePoolPda(0),
      deriveSolVaultPda(0),
      deriveVaultAuthPda(0),
      deriveSwapEscrowPda(0, 0),
    ])
    const poolB58 = base58Encode(poolPda.address)
    const solVaultB58 = base58Encode(solVaultPda.address)
    const vaultAuthB58 = base58Encode(vaultAuthPda.address)
    const escrow0B58 = base58Encode(escrow0Pda.address)

    const [poolAcc, solVaultLamports] = await Promise.all([
      fetchAccountBytes(rpcUrl, poolB58),
      fetchBalance(rpcUrl, solVaultB58),
    ])

    const pool = decodePoolState(poolAcc.bytes)
    const reqPageParam = url.searchParams.get('pageId')
    const targetPageId =
      reqPageParam !== null && /^\d+$/.test(reqPageParam) ? BigInt(reqPageParam) : pool.currentPageId

    // Fetch all pages up to currentPageId (capped at latest 16 pages) in ONE getMultipleAccounts call
    const startPage = pool.currentPageId > 15n ? pool.currentPageId - 15n : 0n
    const pageIds: bigint[] = []
    for (let pid = startPage; pid <= pool.currentPageId; pid++) {
      pageIds.push(pid)
    }
    if (!pageIds.includes(targetPageId)) pageIds.push(targetPageId)

    const pagePdaPairs = await Promise.all(
      pageIds.map(async (pid) => ({
        pageId: pid,
        pdaB58: base58Encode((await deriveEpochPagePda(0, pid)).address),
      })),
    )

    // Also check USDC & WSOL vault/escrow ATAs on Mainnet in the same batch!
    const usdcMint = base58Decode(
      cluster === 'mainnet' ? USDC_MAINNET_MINT_STR : '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
    )
    const [vaultUsdc, vaultWsol, escrowUsdc, escrowWsol] = await Promise.all([
      deriveAta(vaultAuthPda.address, CLASSIC_TOKEN_PROGRAM_ID, usdcMint),
      deriveAta(vaultAuthPda.address, CLASSIC_TOKEN_PROGRAM_ID, WSOL_MINT),
      deriveAta(escrow0Pda.address, CLASSIC_TOKEN_PROGRAM_ID, usdcMint),
      deriveAta(escrow0Pda.address, CLASSIC_TOKEN_PROGRAM_ID, WSOL_MINT),
    ])
    const ataCheckKeys = [
      base58Encode(vaultUsdc),
      base58Encode(vaultWsol),
      base58Encode(escrowUsdc),
      base58Encode(escrowWsol),
    ]

    // Also discover any active parallel append lanes (1..activeLanes-1) in the same batch!
    const extraLaneIds: number[] = []
    for (let lid = 1; lid < pool.activeLanes; lid++) extraLaneIds.push(lid)
    const extraLanePdas = await Promise.all(
      extraLaneIds.map(async (lid) => ({
        laneId: lid,
        pdaB58: base58Encode((await deriveLanePda(0, lid)).address),
      })),
    )

    const multiRes = await rpcCall<{ value: Array<{ data: [string, string]; lamports: number } | null> }>(
      rpcUrl,
      'getMultipleAccounts',
      [
        [
          ...pagePdaPairs.map((p) => p.pdaB58),
          ...ataCheckKeys,
          ...extraLanePdas.map((l) => l.pdaB58),
        ],
        { encoding: 'base64', commitment: 'confirmed' },
      ],
    )

    const pages: Array<{
      pageId: string
      pagePda: string
      count: number
      closed: boolean
      pageBase64: string
      notes: ReturnType<typeof formatPublicNotes>
    }> = []

    for (let i = 0; i < pagePdaPairs.length; i++) {
      const acc = multiRes.value[i]
      if (!acc) continue
      const raw = fromBase64(acc.data[0])
      const hdr = decodeEpochPageHeader(raw)
      pages.push({
        pageId: pagePdaPairs[i].pageId.toString(),
        pagePda: pagePdaPairs[i].pdaB58,
        count: hdr.count,
        closed: hdr.closed,
        pageBase64: acc.data[0],
        notes: formatPublicNotes(raw),
      })
    }

    const activePage =
      pages.find((p) => p.pageId === targetPageId.toString()) ?? pages[pages.length - 1]
    if (!activePage) throw new Error('Active EpochPage not found')
    const lane0TipPage =
      pages.find((p) => p.pageId === pool.currentPageId.toString()) ?? activePage

    const ataOffset = pagePdaPairs.length
    const ataExists = {
      vaultUsdc: multiRes.value[ataOffset] !== null,
      vaultWsol: multiRes.value[ataOffset + 1] !== null,
      escrowUsdc: multiRes.value[ataOffset + 2] !== null,
      escrowWsol: multiRes.value[ataOffset + 3] !== null,
    }

    // Build parallel lane directory (always includes Lane 0 + any live Lanes 1..15)
    const laneOffset = ataOffset + ataCheckKeys.length
    const lanes: Array<{
      laneId: number
      activePageId: string
      pageCount: number
      pageClosed: boolean
      createdSlot?: string
    }> = [
      {
        laneId: 0,
        activePageId: pool.currentPageId.toString(),
        pageCount: lane0TipPage.count,
        pageClosed: lane0TipPage.closed,
      },
    ]

    const extraLaneTips: Array<{ laneId: number; activePageId: bigint; createdSlot: bigint; pdaB58: string }> = []
    for (let i = 0; i < extraLanePdas.length; i++) {
      const acc = multiRes.value[laneOffset + i]
      if (!acc) continue
      const st = decodeAppendLaneState(fromBase64(acc.data[0]))
      if (!st) continue
      const tipPda = base58Encode((await deriveEpochPagePda(0, st.activePageId)).address)
      extraLaneTips.push({
        laneId: st.laneId,
        activePageId: st.activePageId,
        createdSlot: st.createdSlot,
        pdaB58: tipPda,
      })
    }
    if (extraLaneTips.length > 0) {
      const tipRes = await rpcCall<{ value: Array<{ data: [string, string] } | null> }>(
        rpcUrl,
        'getMultipleAccounts',
        [
          extraLaneTips.map((t) => t.pdaB58),
          { encoding: 'base64', commitment: 'confirmed', dataSlice: { offset: 0, length: 64 } },
        ],
      )
      for (let i = 0; i < extraLaneTips.length; i++) {
        const acc = tipRes.value?.[i]
        if (!acc) continue
        const raw = fromBase64(acc.data[0])
        if (raw.length < 64) continue
        if (String.fromCharCode(...raw.subarray(0, 8)) !== 'AUDRNPG1') continue
        lanes.push({
          laneId: extraLaneTips[i].laneId,
          activePageId: extraLaneTips[i].activePageId.toString(),
          pageCount: raw[11],
          pageClosed: raw[10] !== 0,
          createdSlot: extraLaneTips[i].createdSlot.toString(),
        })
      }
    }

    const relayerSecret = getRelayerSecret(env, cluster)
    let relayerAddress: string | null = null
    let relayerLamports: number | null = null
    if (relayerSecret) {
      relayerAddress = base58Encode(ed25519.getPublicKey(relayerSecret))
      relayerLamports = await fetchBalance(rpcUrl, relayerAddress)
    }

    return jsonResponse({
      cluster,
      programId: AUDREN_PROGRAM_ID_STR,
      poolId: 0,
      poolPda: poolB58,
      solVaultPda: solVaultB58,
      vaultAuthPda: vaultAuthB58,
      swapEscrow0Pda: escrow0B58,
      solVaultLamports,
      faucetLamports: cluster === 'devnet' ? relayerLamports : null,
      relayerAvailable: relayerSecret !== null && (relayerLamports ?? 0) >= 5_000_000,
      relayerAddress,
      relayerLamports,
      pageRentFeeLamports: pool.pageRentFeeLamports.toString(),
      activeLanes: pool.activeLanes,
      lanes,
      currentPageId: pool.currentPageId.toString(),
      viewingPageId: activePage.pageId,
      pagePda: activePage.pagePda,
      pageCount: activePage.count,
      pageClosed: activePage.closed,
      totalNotes: pool.totalNotes.toString(),
      totalSpends: pool.totalSpends.toString(),
      paused: pool.paused,
      ataExists,
      pageBase64: activePage.pageBase64,
      notes: activePage.notes,
      pages: pages.map((p) => ({
        pageId: p.pageId,
        pagePda: p.pagePda,
        count: p.count,
        closed: p.closed,
        pageBase64: p.pageBase64,
      })),
    })
  } catch (err) {
    return jsonResponse({ error: sanitizeError(err, 'Failed to load pool state') }, 502)
  }
}

// ============================================================================
// GET /api/wallet/balances?cluster=mainnet|devnet&address=<pubkey>
// ============================================================================

async function handleWalletBalances(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url)
  const cluster = parseCluster(url.searchParams.get('cluster'), 'mainnet')
  const addr = (url.searchParams.get('address') ?? '').trim()
  const rpcUrl = getRpcUrl(env, cluster)
  if (!rpcUrl) return jsonResponse({ error: `${cluster} RPC not configured` }, 503)

  try {
    const decoded = base58Decode(addr)
    if (decoded.length !== 32) return jsonResponse({ error: 'Invalid Solana wallet address' }, 400)
  } catch {
    return jsonResponse({ error: 'Invalid Solana wallet address' }, 400)
  }

  try {
    type TokenAccItem = {
      pubkey: string
      account: {
        data: {
          parsed: {
            info: {
              mint: string
              tokenAmount: {
                amount: string
                decimals: number
                uiAmountString: string
              }
            }
          }
        }
      }
    }

    const [solLamports, splRes, t22Res, bhRes] = await Promise.all([
      fetchBalance(rpcUrl, addr),
      rpcCall<{ value: TokenAccItem[] }>(rpcUrl, 'getTokenAccountsByOwner', [
        addr,
        { programId: CLASSIC_TOKEN_PROGRAM_ID_STR },
        { encoding: 'jsonParsed', commitment: 'confirmed' },
      ]),
      rpcCall<{ value: TokenAccItem[] }>(rpcUrl, 'getTokenAccountsByOwner', [
        addr,
        { programId: TOKEN_2022_PROGRAM_ID_STR },
        { encoding: 'jsonParsed', commitment: 'confirmed' },
      ]),
      rpcCall<{ value: { blockhash: string; lastValidBlockHeight: number } }>(
        rpcUrl,
        'getLatestBlockhash',
        [{ commitment: 'confirmed' }],
      ),
    ])

    const tokensByMint = new Map<
      string,
      {
        mint: string
        decimals: number
        amountRaw: bigint
        tokenProgram: string
        ata: string
      }
    >()

    const ingest = (items: TokenAccItem[], tokenProgram: string) => {
      for (const item of items) {
        const info = item.account?.data?.parsed?.info
        if (!info) continue
        const raw = BigInt(info.tokenAmount.amount || '0')
        if (raw <= 0n) continue
        const prev = tokensByMint.get(info.mint)
        if (prev) {
          prev.amountRaw += raw
        } else {
          tokensByMint.set(info.mint, {
            mint: info.mint,
            decimals: info.tokenAmount.decimals,
            amountRaw: raw,
            tokenProgram,
            ata: item.pubkey,
          })
        }
      }
    }

    ingest(splRes.value ?? [], CLASSIC_TOKEN_PROGRAM_ID_STR)
    ingest(t22Res.value ?? [], TOKEN_2022_PROGRAM_ID_STR)

    // Hydrate every held mint + SOL live from the configured token metadata registry (logos, names, symbols, prices)
    // AND inspect Token-2022 mint extensions (TransferFeeConfig, active TransferHook, NonTransferable)
    // so deposits always commit exact net amounts and never silently fail on unsupported extensions.
    const heldMints = Array.from(tokensByMint.keys())
    const t22Mints = Array.from(tokensByMint.values())
      .filter((t) => t.tokenProgram === TOKEN_2022_PROGRAM_ID_STR)
      .map((t) => t.mint)

    interface T22MintFlags {
      hasActiveTransferFee: boolean
      transferFeeBps: number
      transferFeeMax: string
      hasActiveTransferHook: boolean
      isNonTransferable: boolean
    }
    const t22FlagsMap = new Map<string, T22MintFlags>()

    const [registry] = await Promise.all([
      cluster === 'mainnet'
        ? fetchGatewayTokensByMints(env, [WSOL_MINT_STR, ...heldMints], getClientIp(request))
        : fetchGatewayTokensByMints(env, [WSOL_MINT_STR], getClientIp(request)),
      (async () => {
        if (t22Mints.length === 0) return
        type ParsedMintAcc = {
          data?: {
            parsed?: {
              info?: {
                extensions?: Array<{
                  extension?: string
                  state?: Record<string, unknown>
                }>
              }
            }
          }
        } | null
        for (let i = 0; i < t22Mints.length; i += 100) {
          const chunk = t22Mints.slice(i, i + 100)
          try {
            const res = await rpcCall<{ value: ParsedMintAcc[] }>(rpcUrl, 'getMultipleAccounts', [
              chunk,
              { encoding: 'jsonParsed', commitment: 'confirmed' },
            ])
            for (let j = 0; j < chunk.length; j++) {
              const exts = res.value?.[j]?.data?.parsed?.info?.extensions ?? []
              let hasActiveTransferFee = false
              let transferFeeBps = 0
              let transferFeeMax = '0'
              let hasActiveTransferHook = false
              let isNonTransferable = false

              for (const ext of exts) {
                if (ext.extension === 'nonTransferable') {
                  isNonTransferable = true
                } else if (ext.extension === 'transferHook') {
                  const hookProg = ext.state?.programId
                  if (typeof hookProg === 'string' && hookProg.length > 0) {
                    hasActiveTransferHook = true
                  }
                } else if (ext.extension === 'transferFeeConfig') {
                  const newer = ext.state?.newerTransferFee as
                    | { epoch?: number; transferFeeBasisPoints?: number; maximumFee?: string | number }
                    | undefined
                  const older = ext.state?.olderTransferFee as
                    | { epoch?: number; transferFeeBasisPoints?: number; maximumFee?: string | number }
                    | undefined
                  const newerBps = Number(newer?.transferFeeBasisPoints ?? 0)
                  const newerMax = BigInt(newer?.maximumFee ?? 0)
                  const olderBps = Number(older?.transferFeeBasisPoints ?? 0)
                  const olderMax = BigInt(older?.maximumFee ?? 0)
                  const activeFee =
                    newerBps > 0 && newerMax > 0n
                      ? { bps: newerBps, max: newerMax }
                      : olderBps > 0 && olderMax > 0n
                        ? { bps: olderBps, max: olderMax }
                        : null
                  if (activeFee) {
                    hasActiveTransferFee = true
                    transferFeeBps = activeFee.bps
                    transferFeeMax = activeFee.max.toString()
                  }
                }
              }

              t22FlagsMap.set(chunk[j], {
                hasActiveTransferFee,
                transferFeeBps,
                transferFeeMax,
                hasActiveTransferHook,
                isNonTransferable,
              })
            }
          } catch {
            // Leave defaults if RPC extension inspection fails transiently
          }
        }
      })(),
    ])
    const solMeta = registry.get(WSOL_MINT_STR)

    const tokens = Array.from(tokensByMint.values())
      .map((t) => {
        const uiAmount = Number(t.amountRaw) / 10 ** t.decimals
        const info = registry.get(t.mint)
        const priceUsd = info?.priceUsd ?? null
        const usdValue = priceUsd !== null ? uiAmount * priceUsd : null
        const t22Flags = t22FlagsMap.get(t.mint)
        return {
          mint: t.mint,
          symbol: info?.symbol ?? shortMint(t.mint),
          name:
            info?.name ??
            (t.tokenProgram === TOKEN_2022_PROGRAM_ID_STR ? 'Token-2022 Asset' : 'SPL Token'),
          decimals: t.decimals,
          amountRaw: t.amountRaw.toString(),
          uiAmount,
          tokenProgram: t.tokenProgram,
          ata: t.ata,
          logoUrl: info?.logoUrl ?? null,
          priceUsd,
          usdValue,
          verified: info?.verified ?? false,
          flagged: info?.flagged ?? false,
          hasActiveTransferFee: t22Flags?.hasActiveTransferFee ?? false,
          transferFeeBps: t22Flags?.transferFeeBps ?? 0,
          transferFeeMax: t22Flags?.transferFeeMax ?? '0',
          hasActiveTransferHook: t22Flags?.hasActiveTransferHook ?? false,
          isNonTransferable: t22Flags?.isNonTransferable ?? false,
        }
      })
      .sort((a, b) => {
        // Non-flagged first, then highest USD value, then verified, then balance
        if (a.flagged !== b.flagged) return a.flagged ? 1 : -1
        const av = a.usdValue ?? -1
        const bv = b.usdValue ?? -1
        if (av !== bv) return bv - av
        if (a.verified !== b.verified) return a.verified ? -1 : 1
        return b.uiAmount - a.uiAmount
      })

    const solUi = solLamports / 1e9
    return jsonResponse({
      cluster,
      address: addr,
      solLamports: solLamports.toString(),
      solUi,
      solPriceUsd: solMeta?.priceUsd ?? null,
      solUsdValue: solMeta?.priceUsd ? solUi * solMeta.priceUsd : null,
      solLogoUrl: solMeta?.logoUrl ?? null,
      tokens,
      blockhash: bhRes.value.blockhash,
      lastValidBlockHeight: bhRes.value.lastValidBlockHeight,
    })
  } catch (err) {
    return jsonResponse({ error: sanitizeError(err, 'Failed to fetch wallet balances') }, 502)
  }
}

// ============================================================================
// GET /api/tokens/search?q=&limit=  (Live token search via optional gateway binding or Jupiter API)
// POST /api/tokens/resolve { mints } (Batch token lookup via Gateway)
// GET /api/tokens/logo/:sha256.webp  (R2 token logo proxy via Gateway)
// ============================================================================

async function handleTokenSearch(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url)
  const q = (url.searchParams.get('q') ?? '').trim().slice(0, 100)
  const rawLimit = Number(url.searchParams.get('limit') ?? '20')
  const limit = Number.isFinite(rawLimit) ? Math.min(Math.max(1, Math.trunc(rawLimit)), 50) : 20

  // Tier 1: optional Worker service binding for token search
  if (env.GATEWAY_SEARCH) {
    const gwOrigin = (env.TOKEN_GATEWAY_ORIGIN ?? DEFAULT_GATEWAY_ORIGIN).replace(/\/+$/, '')
    const params = new URLSearchParams({ limit: String(limit) })
    if (q) params.set('q', q)
    try {
      const headers: Record<string, string> = { accept: 'application/json' }
      const ip = getClientIp(request)
      if (ip && ip !== 'unknown') headers['CF-Connecting-IP'] = ip
      const res = await env.GATEWAY_SEARCH.fetch(`${gwOrigin}/v1/assets/search?${params}`, {
        headers,
        signal: AbortSignal.timeout(5_000),
      })
      if (res.ok) {
        const json = (await res.json()) as {
          data?: { items?: GatewayTokenCard[]; address?: string }
        }
        const items = (json.data?.items ?? []).map((card) => normalizeGatewayCard(card.mint, card))
        return jsonResponse({ items, address: json.data?.address ?? null })
      }
    } catch {
      // Seamless fallback to Tier 2 Jupiter Tokens V2
    }
  }

  // Tier 2: Jupiter Tokens V2 fallback (always returns symbols, logos, USD prices, verified flags)
  try {
    if (q) {
      const raw = await fetchJupiterTokensV2Path(env, `search?query=${encodeURIComponent(q)}`, 6_500)
      const items = raw
        .filter((t) => t?.id && t.audit?.isSus !== true)
        .slice(0, limit)
        .map(normalizeJupiterTokenV2)
      let exactAddress: string | null = null
      try {
        if (base58Decode(q).length === 32) exactAddress = q
      } catch {
        exactAddress = null
      }
      return jsonResponse({ items, address: exactAddress })
    }

    // Empty query: show curated liquid staples (SOL, USDC, USDT, JUP, PYUSD, ...) + top 24h traded
    const [popularRaw, trendingRaw] = await Promise.all([
      fetchJupiterTokensV2Path(
        env,
        `search?query=${encodeURIComponent(POPULAR_TOKEN_MINTS.join(','))}`,
        5_000,
      ),
      fetchJupiterTokensV2Path(env, `toptraded/24h?limit=${Math.min(limit, 25)}`, 5_000),
    ])
    const byMint = new Map<string, ResolvedTokenInfo>()
    const popularIndex = new Map(POPULAR_TOKEN_MINTS.map((m, i) => [m, i]))
    const orderedPopular = [...popularRaw].sort(
      (a, b) => (popularIndex.get(a.id) ?? 999) - (popularIndex.get(b.id) ?? 999),
    )
    for (const tok of [...orderedPopular, ...trendingRaw]) {
      if (!tok?.id || tok.audit?.isSus === true || byMint.has(tok.id)) continue
      byMint.set(tok.id, normalizeJupiterTokenV2(tok))
      if (byMint.size >= limit) break
    }
    return jsonResponse({ items: [...byMint.values()], address: null })
  } catch (err) {
    return jsonResponse({ error: sanitizeError(err, 'Token search unavailable') }, 503)
  }
}

async function handleTokenResolve(request: Request, env: Env): Promise<Response> {
  let body: { mints?: string[] }
  try {
    body = (await request.json()) as { mints?: string[] }
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, 400)
  }
  const mints = Array.isArray(body.mints) ? body.mints.slice(0, 100) : []
  if (mints.length === 0) return jsonResponse({ items: {} })
  const resolved = await fetchGatewayTokensByMints(env, mints, getClientIp(request))
  return jsonResponse({ items: Object.fromEntries(resolved.entries()) })
}

async function handleTokenLogo(env: Env, sha256: string, isHead = false): Promise<Response> {
  if (!SHA256_RE.test(sha256) || !env.GATEWAY) {
    return new Response(null, { status: 404 })
  }
  const gwOrigin = (env.TOKEN_GATEWAY_ORIGIN ?? DEFAULT_GATEWAY_ORIGIN).replace(/\/+$/, '')
  try {
    const res = await env.GATEWAY.fetch(`${gwOrigin}/public/logos/k/${sha256}/128.webp`, {
      signal: AbortSignal.timeout(4_000),
    })
    if (!res.ok || !res.headers.get('content-type')?.startsWith('image/webp')) {
      return new Response(null, { status: 404 })
    }
    return new Response(isHead ? null : res.body, {
      status: 200,
      headers: {
        'content-type': 'image/webp',
        'cache-control': 'public, max-age=31536000, immutable',
      },
    })
  } catch {
    return new Response(null, { status: 502 })
  }
}

function isSafeExternalIconUrl(raw: string): boolean {
  try {
    const u = new URL(raw)
    if (u.protocol !== 'https:') return false
    const h = u.hostname.toLowerCase()
    if (
      h === 'localhost' ||
      h.endsWith('.local') ||
      h.endsWith('.internal') ||
      /^\d+\.\d+\.\d+\.\d+$/.test(h) ||
      h.includes(':')
    ) {
      return false
    }
    return true
  } catch {
    return false
  }
}

async function handleMintLogo(
  env: Env,
  mint: string,
  isHead = false,
  symbolHint?: string | null,
): Promise<Response> {
  try {
    if (base58Decode(mint).length !== 32) return new Response(null, { status: 400 })
  } catch {
    return new Response(null, { status: 400 })
  }

  const edgeCache = (caches as unknown as { default?: Cache }).default
  const cacheKey = new Request(`https://audren.xyz/api/tokens/mint-logo/${mint}.webp`, { method: 'GET' })
  if (edgeCache && !isHead) {
    const hit = await edgeCache.match(cacheKey)
    if (hit) return hit
  }

  const fallbackMonogram = (sym?: string | null): Response => {
    const svg = buildMonogramLogoSvg(sym ?? symbolHint, mint)
    const out = new Response(isHead ? null : svg, {
      status: 200,
      headers: {
        'content-type': 'image/svg+xml; charset=utf-8',
        'cache-control': 'public, max-age=3600',
        'x-content-type-options': 'nosniff',
      },
    })
    if (edgeCache && !isHead) edgeCache.put(cacheKey, out.clone()).catch(() => {})
    return out
  }

  // Tier 1: optional Worker service binding for cached token logos
  if (env.GATEWAY) {
    const gwOrigin = (env.TOKEN_GATEWAY_ORIGIN ?? DEFAULT_GATEWAY_ORIGIN).replace(/\/+$/, '')
    try {
      const res = await env.GATEWAY.fetch(`${gwOrigin}/public/logos/${mint}.webp`, {
        signal: AbortSignal.timeout(3_500),
      })
      const ct = res.headers.get('content-type') ?? ''
      if (res.ok && ct.startsWith('image/')) {
        const bytes = await res.arrayBuffer()
        const out = new Response(isHead ? null : bytes, {
          status: 200,
          headers: {
            'content-type': ct,
            'cache-control': 'public, max-age=86400',
          },
        })
        if (edgeCache && !isHead) edgeCache.put(cacheKey, out.clone()).catch(() => {})
        return out
      }
    } catch {
      // Fall through to Tier 2 cached icon URL proxy
    }
  }

  // Tier 2: Resolve upstream icon URL from in-memory or Edge Cache first (ZERO Jupiter API calls!)
  let iconUrl: string | null = null
  let resolvedSymbol: string | null = symbolHint ?? null

  const memMeta = MINT_ICON_CACHE.get(mint)
  if (memMeta) {
    iconUrl = memMeta.iconUrl
    resolvedSymbol = resolvedSymbol || memMeta.symbol
  } else if (edgeCache) {
    try {
      const metaKey = new Request(`https://audren.xyz/_internal/mint-icon-meta/${mint}`, { method: 'GET' })
      const metaHit = await edgeCache.match(metaKey)
      if (metaHit) {
        const parsed = (await metaHit.json()) as Partial<MintIconMeta>
        if (typeof parsed.iconUrl === 'string' && isSafeExternalIconUrl(parsed.iconUrl)) {
          iconUrl = parsed.iconUrl
          resolvedSymbol = resolvedSymbol || (typeof parsed.symbol === 'string' ? parsed.symbol : null)
          MINT_ICON_CACHE.set(mint, { iconUrl, symbol: resolvedSymbol ?? mint.slice(0, 2) })
        }
      }
    } catch {
      // Ignore cache read error
    }
  }

  // On a cold miss, look up token metadata via Jupiter API (if JUPITER_API_KEY / JUPITER_API_URL is configured)
  if (!iconUrl) {
    try {
      const found = await fetchJupiterTokensV2Path(
        env,
        `search?query=${encodeURIComponent(mint)}`,
        3_500,
        { cacheTtlSec: 3600 },
      )
      const tok = found.find((t) => t?.id === mint)
      if (tok && tok.audit?.isSus !== true && tok.icon && isSafeExternalIconUrl(tok.icon)) {
        iconUrl = tok.icon
        resolvedSymbol = resolvedSymbol || tok.symbol?.trim() || null
        rememberMintIcon(mint, tok.icon, resolvedSymbol ?? mint.slice(0, 2))
      }
    } catch {
      // Fall through to clean SVG monogram
    }
  }

  if (!iconUrl) {
    return fallbackMonogram(resolvedSymbol)
  }

  // Server-side proxy of upstream icon (keeps strict browser CSP `img-src 'self' data:`)
  try {
    const imgRes = await fetch(iconUrl, { signal: AbortSignal.timeout(3_500) })
    const ct = imgRes.headers.get('content-type') ?? ''
    if (!imgRes.ok || !ct.startsWith('image/')) {
      return fallbackMonogram(resolvedSymbol)
    }
    const bytes = await imgRes.arrayBuffer()
    if (bytes.byteLength === 0 || bytes.byteLength > 512 * 1024) {
      return fallbackMonogram(resolvedSymbol)
    }
    const out = new Response(isHead ? null : bytes, {
      status: 200,
      headers: {
        'content-type': ct.split(';')[0]!,
        'cache-control': 'public, max-age=86400',
      },
    })
    if (edgeCache && !isHead) edgeCache.put(cacheKey, out.clone()).catch(() => {})
    return out
  } catch {
    return fallbackMonogram(resolvedSymbol)
  }
}

// ============================================================================
// GET /api/pages/slices?cluster=mainnet|devnet&from=0&to=99&lane=0&sealed=1
// Stage-1 compact 1,056 B dataSlice discovery across arbitrary page history.
// When `sealed=1` and every page in `[from..to]` is strictly `< activeTip`,
// responses are permanently immutable and served from Cloudflare Edge Cache!
// ============================================================================

async function handleGetPageSlices(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url)
  const cluster = parseCluster(url.searchParams.get('cluster'), 'mainnet')
  const rpcUrl = getRpcUrl(env, cluster)
  if (!rpcUrl) return jsonResponse({ error: `${cluster} RPC not configured` }, 503)

  const fromStr = url.searchParams.get('from') ?? '0'
  const toStr = url.searchParams.get('to') ?? '0'
  const laneRaw = Number(url.searchParams.get('lane') ?? '0')
  const wantSealedCache = url.searchParams.get('sealed') === '1'
  if (!Number.isInteger(laneRaw) || laneRaw < 0 || laneRaw >= MAX_APPEND_LANES) {
    return jsonResponse({ error: `Invalid lane (must be 0..${MAX_APPEND_LANES - 1})` }, 400)
  }
  if (!/^\d+$/.test(fromStr) || !/^\d+$/.test(toStr)) {
    return jsonResponse({ error: 'Invalid from/to page bounds' }, 400)
  }
  const fromSeq = BigInt(fromStr)
  const toSeq = BigInt(toStr)
  if (toSeq < fromSeq || toSeq - fromSeq >= 100n) {
    return jsonResponse({ error: 'Page slice range must span 1..=100 pages' }, 400)
  }

  // Fast-path edge CDN cache hit for strictly sealed page ranges (0 RPC calls!)
  const cache = wantSealedCache ? await getEdgeCache() : null
  const cacheReq = cache ? new Request(url.toString(), { method: 'GET' }) : null
  if (cache && cacheReq) {
    const hit = await cache.match(cacheReq)
    if (hit) return hit
  }

  try {
    const pageIds: bigint[] = []
    for (let seq = fromSeq; seq <= toSeq; seq++) {
      pageIds.push(pageIdForLane(laneRaw, seq))
    }
    const pdas = await Promise.all(
      pageIds.map(async (pid) => ({
        pageId: pid.toString(),
        pdaB58: base58Encode((await deriveEpochPagePda(0, pid)).address),
      })),
    )

    // If caller requested immutable caching, verify against live tip that ALL pages are permanently sealed
    const tipCheckPromise = wantSealedCache
      ? (async (): Promise<boolean> => {
          const tipPda =
            laneRaw === 0
              ? base58Encode((await derivePoolPda(0)).address)
              : base58Encode((await deriveLanePda(0, laneRaw)).address)
          const tipAcc = await rpcCall<{ value: { data: [string, string] } | null }>(
            rpcUrl,
            'getAccountInfo',
            [tipPda, { encoding: 'base64', commitment: 'finalized', dataSlice: { offset: 0, length: 48 } }],
          )
          if (!tipAcc.value) return false
          const raw = fromBase64(tipAcc.value.data[0])
          if (raw.length < 24) return false
          const expectedMagic = laneRaw === 0 ? 'AUDRNPL1' : 'AUDRNLN1'
          if (String.fromCharCode(...raw.subarray(0, 8)) !== expectedMagic) return false
          const activeTipId = readU64le(raw, 16)
          const activeTipSeq = seqOfPageId(activeTipId)
          return toSeq < activeTipSeq
        })().catch(() => false)
      : Promise.resolve(false)

    const [res, allConfirmedSealed] = await Promise.all([
      rpcCall<{
        value: Array<{ data: [string, string]; owner: string } | null>
      }>(rpcUrl, 'getMultipleAccounts', [
        pdas.map((p) => p.pdaB58),
        {
          encoding: 'base64',
          commitment: wantSealedCache ? 'finalized' : 'confirmed',
          dataSlice: { offset: PAGE_SCAN_OFFSET, length: PAGE_SCAN_LEN },
        },
      ]),
      tipCheckPromise,
    ])
    if (!Array.isArray(res.value) || res.value.length !== pdas.length) {
      return jsonResponse({ error: 'Incomplete page slice batch from RPC' }, 502)
    }

    const slices = pdas.map((p, idx) => {
      const acc = res.value[idx]
      if (!acc || acc.owner !== AUDREN_PROGRAM_ID_STR) return null
      return { pageId: p.pageId, sliceBase64: acc.data[0] }
    })

    const allPresent = slices.every((s) => s !== null)
    const immutable = allConfirmedSealed && allPresent
    const response = jsonResponse(
      { cluster, lane: laneRaw, immutable, slices },
      200,
      immutable ? { 'cache-control': IMMUTABLE_CACHE_CONTROL } : undefined,
    )
    if (immutable && cache && cacheReq) {
      await cache.put(cacheReq, response.clone())
    }
    return response
  } catch (err) {
    return jsonResponse({ error: sanitizeError(err, 'Failed to fetch page scan slices') }, 502)
  }
}

// ============================================================================
// GET /api/pages/sealed?cluster=mainnet|devnet&ids=0,1,2,3
// Immutable CDN-cached full 6,240 B EpochPage fetch for sealed pages ONLY
// (ideal for multi-page 64/128 decoy rings & Stage-2 historical decryption!)
// ============================================================================

async function handleGetSealedPages(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url)
  const cluster = parseCluster(url.searchParams.get('cluster'), 'mainnet')
  const rpcUrl = getRpcUrl(env, cluster)
  if (!rpcUrl) return jsonResponse({ error: `${cluster} RPC not configured` }, 503)

  const rawIds = (url.searchParams.get('ids') ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
  if (rawIds.length === 0 || rawIds.length > 16) {
    return jsonResponse({ error: 'ids must contain 1..=16 comma-separated numeric page IDs' }, 400)
  }
  const uniqueIds: bigint[] = []
  const seen = new Set<string>()
  for (const s of rawIds) {
    if (!/^\d+$/.test(s)) return jsonResponse({ error: `Invalid pageId: ${s}` }, 400)
    if (!seen.has(s)) {
      seen.add(s)
      uniqueIds.push(BigInt(s))
    }
  }
  // Canonicalize cache key by sorted numeric page IDs so identical sets share 1 edge cache entry
  uniqueIds.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
  const canonicalUrl = `${url.origin}${url.pathname}?cluster=${cluster}&ids=${uniqueIds.map((id) => id.toString()).join(',')}`

  const cache = await getEdgeCache()
  const cacheReq = cache ? new Request(canonicalUrl, { method: 'GET' }) : null
  if (cache && cacheReq) {
    const hit = await cache.match(cacheReq)
    if (hit) return hit
  }

  try {
    const pdas = await Promise.all(
      uniqueIds.map(async (pid) => ({
        pageId: pid.toString(),
        pdaB58: base58Encode((await deriveEpochPagePda(0, pid)).address),
      })),
    )
    const res = await rpcCall<{
      value: Array<{ data: [string, string]; owner: string } | null>
    }>(rpcUrl, 'getMultipleAccounts', [
      pdas.map((p) => p.pdaB58),
      { encoding: 'base64', commitment: 'finalized' },
    ])
    if (!Array.isArray(res.value) || res.value.length !== pdas.length) {
      return jsonResponse({ error: 'Incomplete page batch from RPC' }, 502)
    }

    const pages: Array<{
      pageId: string
      pagePda: string
      count: number
      closed: boolean
      pageBase64: string
    }> = []
    let allClosed = true
    for (let i = 0; i < pdas.length; i++) {
      const acc = res.value[i]
      if (!acc || acc.owner !== AUDREN_PROGRAM_ID_STR) {
        allClosed = false
        continue
      }
      const raw = fromBase64(acc.data[0])
      const hdr = decodeEpochPageHeader(raw)
      if (!hdr.closed) allClosed = false
      pages.push({
        pageId: pdas[i].pageId,
        pagePda: pdas[i].pdaB58,
        count: hdr.count,
        closed: hdr.closed,
        pageBase64: acc.data[0],
      })
    }

    const immutable = allClosed && pages.length === pdas.length
    const response = jsonResponse(
      { cluster, immutable, pages },
      200,
      immutable ? { 'cache-control': IMMUTABLE_CACHE_CONTROL } : undefined,
    )
    if (immutable && cache && cacheReq) {
      await cache.put(cacheReq, response.clone())
    }
    return response
  } catch (err) {
    return jsonResponse({ error: sanitizeError(err, 'Failed to fetch sealed pages') }, 502)
  }
}

// ============================================================================
// POST /api/buffers/check — Verify whether pending self-pay ProofBuffer PDAs
// still exist on-chain so the UI can offer 1-click rent reclaim (Tag 10)
// ============================================================================

async function handleCheckBuffers(request: Request, env: Env): Promise<Response> {
  let body: { cluster?: string; pdas?: string[] }
  try {
    body = (await request.json()) as typeof body
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400)
  }
  const cluster = parseCluster(body.cluster, 'mainnet')
  const rpcUrl = getRpcUrl(env, cluster)
  if (!rpcUrl) return jsonResponse({ error: `${cluster} RPC not configured` }, 503)

  if (!Array.isArray(body.pdas) || body.pdas.length === 0) {
    return jsonResponse({ buffers: [] })
  }
  if (body.pdas.length > 16) {
    return jsonResponse({ error: 'Maximum 16 ProofBuffer PDAs per request' }, 400)
  }
  for (const p of body.pdas) {
    try {
      if (typeof p !== 'string' || base58Decode(p).length !== 32) {
        return jsonResponse({ error: 'Invalid ProofBuffer PDA' }, 400)
      }
    } catch {
      return jsonResponse({ error: 'Invalid ProofBuffer PDA' }, 400)
    }
  }

  try {
    const res = await rpcCall<{ value: Array<{ owner?: string; lamports?: number } | null> }>(
      rpcUrl,
      'getMultipleAccounts',
      [body.pdas, { encoding: 'base64', commitment: 'confirmed', dataSlice: { offset: 0, length: 0 } }],
    )
    const buffers = body.pdas.map((pda, i) => {
      const acc = res.value?.[i]
      const exists = acc !== null && acc !== undefined && acc.owner === AUDREN_PROGRAM_ID_STR
      return { pda, exists, lamports: exists ? Number(acc?.lamports ?? 0) : 0 }
    })
    return jsonResponse({ cluster, buffers })
  } catch (err) {
    return jsonResponse({ error: sanitizeError(err, 'Failed to check ProofBuffers') }, 502)
  }
}

// ============================================================================
// POST /api/pages/fetch — Fetch exact full 6,240 B EpochPages by pageId
// Used for Stage-2 decryption (only matched pages) and on-demand spend inputs
// ============================================================================

async function handleFetchPages(request: Request, env: Env): Promise<Response> {
  let body: { cluster?: string; pageIds?: Array<string | number> }
  try {
    body = (await request.json()) as typeof body
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400)
  }
  const cluster = parseCluster(body.cluster, 'mainnet')
  const rpcUrl = getRpcUrl(env, cluster)
  if (!rpcUrl) return jsonResponse({ error: `${cluster} RPC not configured` }, 503)

  if (!Array.isArray(body.pageIds) || body.pageIds.length === 0 || body.pageIds.length > 32) {
    return jsonResponse({ error: 'pageIds must contain 1..=32 page IDs' }, 400)
  }

  const uniqueIds: bigint[] = []
  const seen = new Set<string>()
  for (const raw of body.pageIds) {
    const s = String(raw).trim()
    if (!/^\d+$/.test(s)) return jsonResponse({ error: `Invalid pageId: ${s}` }, 400)
    if (!seen.has(s)) {
      seen.add(s)
      uniqueIds.push(BigInt(s))
    }
  }

  try {
    const pdas = await Promise.all(
      uniqueIds.map(async (pid) => ({
        pageId: pid.toString(),
        pdaB58: base58Encode((await deriveEpochPagePda(0, pid)).address),
      })),
    )

    const res = await rpcCall<{
      value: Array<{ data: [string, string]; owner: string } | null>
    }>(rpcUrl, 'getMultipleAccounts', [
      pdas.map((p) => p.pdaB58),
      { encoding: 'base64', commitment: 'confirmed' },
    ])
    if (!Array.isArray(res.value) || res.value.length !== pdas.length) {
      return jsonResponse({ error: 'Incomplete page batch from RPC' }, 502)
    }

    const pages: Array<{
      pageId: string
      pagePda: string
      count: number
      closed: boolean
      pageBase64: string
    }> = []
    for (let i = 0; i < pdas.length; i++) {
      const acc = res.value[i]
      if (!acc || acc.owner !== AUDREN_PROGRAM_ID_STR) continue
      const raw = fromBase64(acc.data[0])
      const hdr = decodeEpochPageHeader(raw)
      pages.push({
        pageId: pdas[i].pageId,
        pagePda: pdas[i].pdaB58,
        count: hdr.count,
        closed: hdr.closed,
        pageBase64: acc.data[0],
      })
    }

    return jsonResponse({ cluster, pages })
  } catch (err) {
    return jsonResponse({ error: sanitizeError(err, 'Failed to fetch pages') }, 502)
  }
}

// ============================================================================
// POST /api/notes/resolve-dynamic — Recover candidate vault net inflows for a
// dynamic swap output note on a fresh device (client verifies V == amt * A!)
// ============================================================================

async function handleResolveDynamicNote(request: Request, env: Env): Promise<Response> {
  let body: { cluster?: string; pageId?: string; slotIndex?: number; mint?: string }
  try {
    body = (await request.json()) as typeof body
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400)
  }
  const cluster = parseCluster(body.cluster, 'mainnet')
  const rpcUrl = getRpcUrl(env, cluster)
  if (!rpcUrl) return jsonResponse({ error: `${cluster} RPC not configured` }, 503)

  if (!body.pageId || !/^\d+$/.test(body.pageId) || !body.mint) {
    return jsonResponse({ error: 'Missing numeric pageId or mint' }, 400)
  }
  let mintBytes: Uint8Array
  try {
    mintBytes = base58Decode(body.mint)
    if (mintBytes.length !== 32) return jsonResponse({ error: 'Invalid mint' }, 400)
  } catch {
    return jsonResponse({ error: 'Invalid mint' }, 400)
  }

  try {
    // 1. Resolve exact token program for `mint` in 1 RPC call so we derive ONE vault ATA (never 2x subrequests!)
    const [pagePda, vaultAuthPda, mintInfo] = await Promise.all([
      deriveEpochPagePda(0, BigInt(body.pageId)),
      deriveVaultAuthPda(0),
      rpcCall<{ value: { owner?: string } | null }>(rpcUrl, 'getAccountInfo', [
        body.mint,
        { encoding: 'base64', commitment: 'confirmed', dataSlice: { offset: 0, length: 0 } },
      ]),
    ])
    const tokenProgBytes =
      mintInfo.value?.owner === TOKEN_2022_PROGRAM_ID_STR
        ? TOKEN_2022_PROGRAM_ID
        : CLASSIC_TOKEN_PROGRAM_ID
    const vaultAta = await deriveAta(vaultAuthPda.address, tokenProgBytes, mintBytes)
    const vaultB58 = base58Encode(vaultAta)
    const pageB58 = base58Encode(pagePda.address)

    // 2. Fetch at most 36 confirmed signatures on this EpochPage (stays safely within CF Workers' 50-subrequest budget)
    const sigs = await rpcCall<Array<{ signature: string; err: unknown | null }>>(
      rpcUrl,
      'getSignaturesForAddress',
      [pageB58, { limit: 36, commitment: 'confirmed' }],
    )
    const okSigs = (sigs ?? []).filter((s) => !s.err).slice(0, 36)
    const candidateAmounts = new Set<string>()
    const targetSlot =
      typeof body.slotIndex === 'number' && Number.isInteger(body.slotIndex) ? body.slotIndex : null
    const logRe = new RegExp(
      `audren:swap_router page=${body.pageId} idx=(\\d+) net_out=(\\d+) net_refund=(\\d+)`,
    )

    type TxInspect = {
      meta?: {
        logMessages?: string[]
        preTokenBalances?: Array<{ accountIndex: number; uiTokenAmount: { amount: string } }>
        postTokenBalances?: Array<{ accountIndex: number; uiTokenAmount: { amount: string } }>
        loadedAddresses?: { writable?: string[]; readonly?: string[] }
      }
      transaction?: { message?: { accountKeys?: Array<string | { pubkey: string }> } }
    } | null

    // Process in bounded concurrent batches of 6 so worst-case latency is ~6 RTTs and total subrequests <= 38
    for (let i = 0; i < okSigs.length; i += 6) {
      const batch = okSigs.slice(i, i + 6)
      const txs = await Promise.all(
        batch.map((s) =>
          rpcCall<TxInspect>(rpcUrl, 'getTransaction', [
            s.signature,
            { encoding: 'json', commitment: 'confirmed', maxSupportedTransactionVersion: 1 },
          ]).catch(() => null),
        ),
      )

      let exactHit = false
      for (const tx of txs) {
        if (!tx?.meta) continue
        for (const line of tx.meta.logMessages ?? []) {
          const m = logRe.exec(line)
          if (!m) continue
          const idxOut = Number(m[1])
          const netOut = m[2]
          const netRefund = m[3]
          if (netOut !== '0') candidateAmounts.add(netOut)
          if (netRefund !== '0') candidateAmounts.add(netRefund)
          if (targetSlot !== null && idxOut === targetSlot) {
            exactHit = true
          }
        }
        if (tx.transaction?.message?.accountKeys) {
          const staticKeys = tx.transaction.message.accountKeys.map((k) =>
            typeof k === 'string' ? k : k.pubkey,
          )
          const fullKeys = [
            ...staticKeys,
            ...(tx.meta.loadedAddresses?.writable ?? []),
            ...(tx.meta.loadedAddresses?.readonly ?? []),
          ]
          const idx = fullKeys.indexOf(vaultB58)
          if (idx >= 0) {
            const pre = BigInt(
              tx.meta.preTokenBalances?.find((b) => b.accountIndex === idx)?.uiTokenAmount.amount ??
                '0',
            )
            const post = BigInt(
              tx.meta.postTokenBalances?.find((b) => b.accountIndex === idx)?.uiTokenAmount
                .amount ?? '0',
            )
            if (post > pre) candidateAmounts.add((post - pre).toString())
          }
        }
      }
      if (exactHit) break
    }

    return jsonResponse({
      cluster,
      pageId: body.pageId,
      mint: body.mint,
      candidateAmounts: Array.from(candidateAmounts),
    })
  } catch (err) {
    return jsonResponse({ error: sanitizeError(err, 'Failed to resolve dynamic note') }, 502)
  }
}

// ============================================================================
// POST /api/nullifiers — Batch check NullifierPDAs with strict owner & length
// validation (automatically chunks > 100 PDAs into 100-account RPC calls)
// ============================================================================

async function handleNullifierCheck(request: Request, env: Env): Promise<Response> {
  let body: { cluster?: string; pdas?: string[] }
  try {
    body = (await request.json()) as typeof body
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400)
  }
  const cluster = parseCluster(body.cluster, 'mainnet')
  const rpcUrl = getRpcUrl(env, cluster)
  if (!rpcUrl) return jsonResponse({ error: `${cluster} RPC not configured` }, 503)

  if (!Array.isArray(body.pdas)) {
    return jsonResponse({ error: 'pdas must be an array' }, 400)
  }
  if (body.pdas.length === 0) return jsonResponse({ spent: [] })
  if (body.pdas.length > 1000) {
    return jsonResponse({ error: 'Maximum 1,000 nullifier PDAs per request' }, 400)
  }

  for (const p of body.pdas) {
    try {
      if (typeof p !== 'string' || base58Decode(p).length !== 32) {
        return jsonResponse({ error: 'Invalid PDA' }, 400)
      }
    } catch {
      return jsonResponse({ error: 'Invalid PDA' }, 400)
    }
  }

  try {
    const spent: boolean[] = []
    for (let i = 0; i < body.pdas.length; i += 100) {
      const chunk = body.pdas.slice(i, i + 100)
      const res = await rpcCall<{ value: Array<{ owner?: string } | null> }>(
        rpcUrl,
        'getMultipleAccounts',
        [chunk, { encoding: 'base64', commitment: 'confirmed', dataSlice: { offset: 0, length: 0 } }],
      )
      if (!Array.isArray(res.value) || res.value.length !== chunk.length) {
        return jsonResponse({ error: 'Incomplete nullifier status response from RPC' }, 502)
      }
      for (const acc of res.value) {
        // Match on-chain program/src/lib.rs::claim_nullifier: spent iff owned by Audren program
        spent.push(acc !== null && acc.owner === AUDREN_PROGRAM_ID_STR)
      }
    }
    return jsonResponse({ spent })
  } catch (err) {
    return jsonResponse({ error: sanitizeError(err, 'Nullifier check failed') }, 502)
  }
}

// ============================================================================
// GET /api/rpc/blockhash & POST /api/rpc/send — for @solana/kit Self-Pay txs
// ============================================================================

async function handleGetBlockhash(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url)
  const cluster = parseCluster(url.searchParams.get('cluster'), 'mainnet')
  const rpcUrl = getRpcUrl(env, cluster)
  if (!rpcUrl) return jsonResponse({ error: `${cluster} RPC not configured` }, 503)

  try {
    const res = await rpcCall<{ value: { blockhash: string; lastValidBlockHeight: number } }>(
      rpcUrl,
      'getLatestBlockhash',
      [{ commitment: 'confirmed' }],
    )
    return jsonResponse({
      cluster,
      blockhash: res.value.blockhash,
      lastValidBlockHeight: res.value.lastValidBlockHeight,
    })
  } catch (err) {
    return jsonResponse({ error: sanitizeError(err, 'Failed to fetch blockhash') }, 502)
  }
}

async function resolveVaultOutDelta(
  rpcUrl: string,
  signature: string,
  vaultOutB58: string,
  maxAttempts = 4,
): Promise<string | null> {
  type TxMeta = {
    meta?: {
      preTokenBalances?: Array<{ accountIndex: number; uiTokenAmount: { amount: string } }>
      postTokenBalances?: Array<{ accountIndex: number; uiTokenAmount: { amount: string } }>
      loadedAddresses?: {
        writable?: string[]
        readonly?: string[]
      }
    }
    transaction?: {
      message?: {
        accountKeys?: Array<string | { pubkey: string }>
      }
    }
  } | null

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      const tx = await rpcCall<TxMeta>(rpcUrl, 'getTransaction', [
        signature,
        { encoding: 'json', commitment: 'confirmed', maxSupportedTransactionVersion: 1 },
      ])
      if (!tx?.meta || !tx.transaction?.message?.accountKeys) {
        if (attempt + 1 < maxAttempts) {
          await new Promise((r) => setTimeout(r, 350 * (attempt + 1)))
          continue
        }
        return null
      }
      const staticKeys = tx.transaction.message.accountKeys.map((k) =>
        typeof k === 'string' ? k : k.pubkey,
      )
      const fullKeys = [
        ...staticKeys,
        ...(tx.meta.loadedAddresses?.writable ?? []),
        ...(tx.meta.loadedAddresses?.readonly ?? []),
      ]
      const idx = fullKeys.indexOf(vaultOutB58)
      if (idx < 0) return null
      const pre = BigInt(
        tx.meta.preTokenBalances?.find((b) => b.accountIndex === idx)?.uiTokenAmount.amount ?? '0',
      )
      const post = BigInt(
        tx.meta.postTokenBalances?.find((b) => b.accountIndex === idx)?.uiTokenAmount.amount ?? '0',
      )
      return post > pre ? (post - pre).toString() : null
    } catch {
      if (attempt + 1 < maxAttempts) {
        await new Promise((r) => setTimeout(r, 350 * (attempt + 1)))
        continue
      }
      return null
    }
  }
  return null
}

async function handleRpcSend(request: Request, env: Env): Promise<Response> {
  let body: { cluster?: string; transactionB64?: string; vaultOutAta?: string }
  try {
    body = (await request.json()) as typeof body
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400)
  }
  const cluster = parseCluster(body.cluster, 'mainnet')
  const rpcUrl = getRpcUrl(env, cluster)
  if (!rpcUrl) return jsonResponse({ error: `${cluster} RPC not configured` }, 503)
  if (!body.transactionB64) return jsonResponse({ error: 'Missing transactionB64' }, 400)

  let raw: Uint8Array
  try {
    raw = fromBase64(body.transactionB64)
  } catch {
    return jsonResponse({ error: 'Invalid base64 transaction' }, 400)
  }
  if (raw.length === 0 || raw.length > 4096) {
    return jsonResponse({ error: `Transaction length ${raw.length} B out of bounds` }, 400)
  }

  try {
    const signature = await rpcCall<string>(rpcUrl, 'sendTransaction', [
      body.transactionB64,
      { encoding: 'base64', preflightCommitment: 'confirmed', maxRetries: 3 },
    ])
    const { slot } = await waitForConfirmation(rpcUrl, signature)
    const actualOut = body.vaultOutAta
      ? await resolveVaultOutDelta(rpcUrl, signature, body.vaultOutAta)
      : null

    return jsonResponse({
      ok: true,
      cluster,
      signature,
      slot,
      actualOut,
      solscanUrl: solscanTxUrl(signature, cluster),
      explorerUrl: explorerTxUrl(signature, cluster),
    })
  } catch (err) {
    return jsonResponse({ error: sanitizeError(err, 'Failed to broadcast transaction') }, 502)
  }
}

// ============================================================================
// POST /api/jupiter/quote & POST /api/jupiter/swap-instructions
// Uses JUPITER_API_KEY secret strictly on the server (NEVER exposed to browser)
// ============================================================================

function jupiterBaseUrl(env: Env): { base: string; headers: Record<string, string> } {
  if (!env.JUPITER_API_KEY?.trim() && !env.JUPITER_API_URL?.trim()) {
    throw new Error('Jupiter API not configured (set JUPITER_API_KEY or JUPITER_API_URL)')
  }
  const raw = (env.JUPITER_API_URL?.trim() || 'https://api.jup.ag').replace(/\/+$/, '')
  const base = raw.endsWith('/swap/v1') ? raw : `${raw}/swap/v1`
  return {
    base,
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      ...(env.JUPITER_API_KEY?.trim() ? { 'x-api-key': env.JUPITER_API_KEY.trim() } : {}),
    },
  }
}

async function fetchJupiterSwapApi(
  env: Env,
  pathAndQuery: string,
  init?: { method?: string; body?: string },
): Promise<Response> {
  const { base, headers } = jupiterBaseUrl(env)
  const retryDelaysMs = [350, 850]
  let lastRes: Response | null = null

  for (let attempt = 0; attempt <= retryDelaysMs.length; attempt++) {
    const res = await fetch(`${base}${pathAndQuery}`, {
      method: init?.method ?? 'GET',
      headers,
      body: init?.body,
      signal: AbortSignal.timeout(10_000),
    })
    if (res.ok || (res.status !== 429 && res.status < 500)) {
      return res
    }
    lastRes = res
    if (attempt < retryDelaysMs.length) {
      const retryAfterSec = Number(res.headers.get('retry-after') ?? '')
      const delayMs =
        Number.isFinite(retryAfterSec) && retryAfterSec > 0
          ? Math.min(Math.max(retryAfterSec * 1000, 300), 1_500)
          : retryDelaysMs[attempt]!
      await new Promise((r) => setTimeout(r, delayMs))
    }
  }

  return lastRes!
}

async function resolveMintTokenPrograms(
  rpcUrl: string | null,
  mintA: string,
  mintB: string,
): Promise<[string, string]> {
  if (!rpcUrl) return [CLASSIC_TOKEN_PROGRAM_ID_STR, CLASSIC_TOKEN_PROGRAM_ID_STR]
  const infos = await rpcCall<{ value: Array<{ owner: string } | null> }>(
    rpcUrl,
    'getMultipleAccounts',
    [[mintA, mintB], { encoding: 'base64', commitment: 'confirmed', dataSlice: { offset: 0, length: 0 } }],
  )
  const ownerA = infos.value[0]?.owner
  const ownerB = infos.value[1]?.owner
  const progA =
    ownerA === TOKEN_2022_PROGRAM_ID_STR || ownerA === CLASSIC_TOKEN_PROGRAM_ID_STR
      ? ownerA
      : CLASSIC_TOKEN_PROGRAM_ID_STR
  const progB =
    ownerB === TOKEN_2022_PROGRAM_ID_STR || ownerB === CLASSIC_TOKEN_PROGRAM_ID_STR
      ? ownerB
      : CLASSIC_TOKEN_PROGRAM_ID_STR
  return [progA, progB]
}

// Venues whose on-chain programs reject or penalize wrapped PDA-CPI callers (`SwapViaRouter`):
// - Kipseli: inspects Sysvar1nstructions and throws Custom(6022) InvalidRealUser unless user signed top-level
// - Quantum / BisonFi: allowlist top-level callers and reject wrapping programs (Custom(9) / Custom(53))
// - BinaryFi / Obsidian: levy unlisted top-level caller penalty fees that diverge from top-level quotes
// - VaultLiquidUnstake / Sanctum Prop S: require System-owned signer lamports or keeper-signed direct swaps
const JUPITER_CPI_EXCLUDED_DEXES = [
  'Kipseli',
  'Quantum',
  'BisonFi',
  'BisonFi Predict',
  'BinaryFi',
  'Obsidian',
  'VaultLiquidUnstake',
  'Sanctum Prop S',
].join(',')

async function handleJupiterQuote(request: Request, env: Env): Promise<Response> {
  let body: {
    inputMint?: string
    outputMint?: string
    amount?: string
    slippageBps?: number
    onlyDirectRoutes?: boolean
    shardId?: number
  }
  try {
    body = (await request.json()) as typeof body
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400)
  }

  if (!body.inputMint || !body.outputMint || !body.amount || !/^\d+$/.test(body.amount)) {
    return jsonResponse({ error: 'Missing inputMint, outputMint, or numeric amount' }, 400)
  }
  if (body.inputMint === body.outputMint) {
    return jsonResponse({ error: 'Input and output mints must differ' }, 400)
  }
  const explicitShard =
    typeof body.shardId === 'number' &&
    Number.isInteger(body.shardId) &&
    body.shardId >= 0 &&
    body.shardId < MAX_ESCROW_SHARDS
      ? body.shardId
      : null

  const rawSlippage = body.slippageBps === undefined ? 50 : Number(body.slippageBps)
  if (!Number.isFinite(rawSlippage)) {
    return jsonResponse({ error: 'slippageBps must be a finite number' }, 400)
  }
  const slippageBps = Math.min(Math.max(Math.trunc(rawSlippage), 10), 500)

  const fetchQuote = async (directOnly: boolean) => {
    const qs = new URLSearchParams({
      inputMint: body.inputMint!,
      outputMint: body.outputMint!,
      amount: body.amount!,
      slippageBps: String(slippageBps),
      excludeDexes: JUPITER_CPI_EXCLUDED_DEXES,
      ...(directOnly ? { onlyDirectRoutes: 'true', maxAccounts: '24' } : { maxAccounts: '28' }),
    })
    const res = await fetchJupiterSwapApi(env, `/quote?${qs.toString()}`)
    if (!res.ok) {
      const txt = await res.text().catch(() => '')
      throw new Error(`Jupiter quote HTTP ${res.status}: ${txt.slice(0, 120)}`)
    }
    return (await res.json()) as Record<string, unknown>
  }

  try {
    let quote: Record<string, unknown>
    let usedDirectOnly = body.onlyDirectRoutes ?? true
    try {
      quote = await fetchQuote(usedDirectOnly)
    } catch {
      if (usedDirectOnly) {
        usedDirectOnly = false
        quote = await fetchQuote(false)
      } else {
        throw new Error('No Jupiter liquidity route found for this pair and amount')
      }
    }

    const vaultAuthPda = await deriveVaultAuthPda(0)

    // Check which vault & escrow ATAs already exist on Mainnet.
    // When caller does not pin `shardId`, probe shards 0..7 in ONE batch and randomly
    // load-balance across shards whose escrow ATAs are already warm (zero extra rent!).
    const rpcUrl = getRpcUrl(env, 'mainnet')
    const mintInBytes = base58Decode(body.inputMint)
    const mintOutBytes = base58Decode(body.outputMint)
    const [tokenProgInStr, tokenProgOutStr] = await resolveMintTokenPrograms(
      rpcUrl,
      body.inputMint,
      body.outputMint,
    )
    const tokenProgIn = base58Decode(tokenProgInStr)
    const tokenProgOut = base58Decode(tokenProgOutStr)

    const [vaultIn, vaultOut] = await Promise.all([
      deriveAta(vaultAuthPda.address, tokenProgIn, mintInBytes),
      deriveAta(vaultAuthPda.address, tokenProgOut, mintOutBytes),
    ])

    const candidateShards = explicitShard !== null ? [explicitShard] : [0, 1, 2, 3, 4, 5, 6, 7]
    const shardInfo = await Promise.all(
      candidateShards.map(async (sid) => {
        const escrowPda = (await deriveSwapEscrowPda(0, sid)).address
        const [escrowIn, escrowOut] = await Promise.all([
          deriveAta(escrowPda, tokenProgIn, mintInBytes),
          deriveAta(escrowPda, tokenProgOut, mintOutBytes),
        ])
        return {
          shardId: sid,
          escrowPda,
          escrowB58: base58Encode(escrowPda),
          escrowIn,
          escrowInB58: base58Encode(escrowIn),
          escrowOut,
          escrowOutB58: base58Encode(escrowOut),
        }
      }),
    )

    let chosen = shardInfo[0]
    const missingAtas: Array<{
      label: string
      ata: string
      owner: string
      mint: string
      tokenProgram: string
    }> = []

    if (rpcUrl) {
      const vaultInB58 = base58Encode(vaultIn)
      const vaultOutB58 = base58Encode(vaultOut)
      const probeKeys = [
        vaultInB58,
        vaultOutB58,
        ...shardInfo.flatMap((s) => [s.escrowInB58, s.escrowOutB58]),
      ]
      const accs = await rpcCall<{ value: Array<unknown | null> }>(rpcUrl, 'getMultipleAccounts', [
        probeKeys,
        { encoding: 'base64', commitment: 'confirmed', dataSlice: { offset: 0, length: 0 } },
      ])
      const vaultInExists = accs.value[0] !== null
      const vaultOutExists = accs.value[1] !== null

      const warmShards = shardInfo.filter((_, i) => {
        const inOk = accs.value[2 + i * 2] !== null
        const outOk = accs.value[2 + i * 2 + 1] !== null
        return inOk && outOk
      })
      if (warmShards.length > 0) {
        const randIdx = crypto.getRandomValues(new Uint8Array(1))[0] % warmShards.length
        chosen = warmShards[randIdx]
      }
      const chosenIdx = shardInfo.findIndex((s) => s.shardId === chosen.shardId)
      const escrowInExists = accs.value[2 + chosenIdx * 2] !== null
      const escrowOutExists = accs.value[2 + chosenIdx * 2 + 1] !== null

      if (!vaultInExists) {
        missingAtas.push({
          label: 'vault_in',
          ata: vaultInB58,
          owner: base58Encode(vaultAuthPda.address),
          mint: body.inputMint,
          tokenProgram: tokenProgInStr,
        })
      }
      if (!vaultOutExists) {
        missingAtas.push({
          label: 'vault_out',
          ata: vaultOutB58,
          owner: base58Encode(vaultAuthPda.address),
          mint: body.outputMint,
          tokenProgram: tokenProgOutStr,
        })
      }
      if (!escrowInExists) {
        missingAtas.push({
          label: 'escrow_in',
          ata: chosen.escrowInB58,
          owner: chosen.escrowB58,
          mint: body.inputMint,
          tokenProgram: tokenProgInStr,
        })
      }
      if (!escrowOutExists) {
        missingAtas.push({
          label: 'escrow_out',
          ata: chosen.escrowOutB58,
          owner: chosen.escrowB58,
          mint: body.outputMint,
          tokenProgram: tokenProgOutStr,
        })
      }
    }

    return jsonResponse({
      quote,
      usedDirectOnly,
      shardId: chosen.shardId,
      swapEscrowPda: chosen.escrowB58,
      vaultAuthPda: base58Encode(vaultAuthPda.address),
      escrowInAta: chosen.escrowInB58,
      escrowOutAta: chosen.escrowOutB58,
      vaultInAta: base58Encode(vaultIn),
      vaultOutAta: base58Encode(vaultOut),
      tokenProgramIn: tokenProgInStr,
      tokenProgramOut: tokenProgOutStr,
      missingAtas,
    })
  } catch (err) {
    return jsonResponse({ error: sanitizeError(err, 'Jupiter quote failed') }, 502)
  }
}

async function handleJupiterSwapInstructions(request: Request, env: Env): Promise<Response> {
  let body: {
    quoteResponse?: Record<string, unknown>
    inputMint?: string
    outputMint?: string
    shardId?: number
  }
  try {
    body = (await request.json()) as typeof body
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400)
  }
  if (!body.quoteResponse || !body.inputMint || !body.outputMint) {
    return jsonResponse({ error: 'Missing quoteResponse, inputMint, or outputMint' }, 400)
  }
  const shardId =
    typeof body.shardId === 'number' &&
    Number.isInteger(body.shardId) &&
    body.shardId >= 0 &&
    body.shardId < MAX_ESCROW_SHARDS
      ? body.shardId
      : 0

  try {
    const escrowPda = (await deriveSwapEscrowPda(0, shardId)).address
    const escrowB58 = base58Encode(escrowPda)
    const rpcUrl = getRpcUrl(env, 'mainnet')
    const [tokenProgInStr, tokenProgOutStr] = await resolveMintTokenPrograms(
      rpcUrl,
      body.inputMint,
      body.outputMint,
    )
    const [escrowIn, escrowOut] = await Promise.all([
      deriveAta(escrowPda, base58Decode(tokenProgInStr), base58Decode(body.inputMint)),
      deriveAta(escrowPda, base58Decode(tokenProgOutStr), base58Decode(body.outputMint)),
    ])
    const escrowInB58 = base58Encode(escrowIn)
    const escrowOutB58 = base58Encode(escrowOut)

    const res = await fetchJupiterSwapApi(env, '/swap-instructions', {
      method: 'POST',
      body: JSON.stringify({
        quoteResponse: body.quoteResponse,
        userPublicKey: escrowB58,
        wrapAndUnwrapSol: false,
        useSharedAccounts: false,
        skipUserAccountsRpcCalls: true,
        dynamicComputeUnitLimit: false,
      }),
    })
    if (!res.ok) {
      const txt = await res.text().catch(() => '')
      throw new Error(`Jupiter swap-instructions HTTP ${res.status}: ${txt.slice(0, 150)}`)
    }
    const payload = (await res.json()) as {
      swapInstruction?: {
        programId: string
        accounts: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }>
        data: string
      }
      addressLookupTableAddresses?: string[]
      computeUnitLimit?: number
    }
    const swapIx = payload.swapInstruction
    if (!swapIx) {
      throw new Error('Jupiter did not return swapInstruction')
    }

    const escrowIdx = swapIx.accounts.findIndex((a) => a.pubkey === escrowB58)
    const escrowInIdx = swapIx.accounts.findIndex((a) => a.pubkey === escrowInB58)
    const escrowOutIdx = swapIx.accounts.findIndex((a) => a.pubkey === escrowOutB58)
    if (escrowIdx < 0 || escrowInIdx < 0 || escrowOutIdx < 0) {
      throw new Error(
        `Jupiter route accounts missing escrow PDA/ATAs (escrow=${escrowIdx}, in=${escrowInIdx}, out=${escrowOutIdx})`,
      )
    }

    // Resolve Jupiter Address Lookup Tables server-side so @solana/kit v0 self-pay
    // ExecBuffered transactions compress cleanly well under 1,232 bytes.
    const lookupTables: Record<string, string[]> = {}
    const altAddrs = (payload.addressLookupTableAddresses ?? []).slice(0, 8)
    if (rpcUrl && altAddrs.length > 0) {
      const altInfos = await rpcCall<{ value: Array<{ data: [string, string] } | null> }>(
        rpcUrl,
        'getMultipleAccounts',
        [altAddrs, { encoding: 'base64', commitment: 'confirmed' }],
      )
      altAddrs.forEach((altAddr, idx) => {
        const info = altInfos.value[idx]
        if (!info) return
        const raw = fromBase64(info.data[0])
        if (raw.length < 56) return
        const addrs: string[] = []
        for (let off = 56; off + 32 <= raw.length; off += 32) {
          addrs.push(base58Encode(raw.subarray(off, off + 32)))
        }
        if (addrs.length > 0) lookupTables[altAddr] = addrs
      })
    }

    return jsonResponse({
      shardId,
      swapInstruction: swapIx,
      escrowIdx,
      escrowInIdx,
      escrowOutIdx,
      swapEscrowPda: escrowB58,
      escrowInAta: escrowInB58,
      escrowOutAta: escrowOutB58,
      lookupTables,
      computeUnitLimit: Math.min(Math.max((payload.computeUnitLimit ?? 400_000) + 700_000, 1_100_000), 1_400_000),
    })
  } catch (err) {
    return jsonResponse({ error: sanitizeError(err, 'Jupiter swap-instructions failed') }, 502)
  }
}

// ============================================================================
// POST /api/relay/submit — Stateless Solana v1 (0x81) Privacy Relayer
// Strictly allowlists Audren Spend/Swap/Withdraw instructions only (zero open signing!)
// ============================================================================

async function handleRelaySubmit(request: Request, env: Env): Promise<Response> {
  const ip = getClientIp(request)
  const limit = checkRateLimit(`relay:${ip}`, RELAY_RATE_MAX)
  if (!limit.allowed) {
    return jsonResponse(
      { error: `Relayer rate limit reached. Try again in ${limit.retryAfterSec}s.` },
      429,
      { 'retry-after': String(limit.retryAfterSec) },
    )
  }

  let body: {
    cluster?: string
    instructionDataB64?: string
    accounts?: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }>
    setupAtas?: Array<{ owner: string; mint: string; tokenProgram: string }>
    computeUnitLimit?: number
    priorityFeeLamports?: string
    vaultOutAta?: string
    rolloverFromPageId?: string
  }
  try {
    body = (await request.json()) as typeof body
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400)
  }

  const cluster = parseCluster(body.cluster, 'mainnet')
  const rpcUrl = getRpcUrl(env, cluster)
  const relayerSecret = getRelayerSecret(env, cluster)
  if (!rpcUrl || !relayerSecret) {
    return jsonResponse(
      {
        error:
          cluster === 'mainnet'
            ? 'Mainnet wallet relaying is served by the standalone Audren Privacy Relayer (https://relay.audren.xyz/v1/relay/submit) or any self-hosted relayer.'
            : 'Devnet sandbox relayer is not configured',
      },
      503,
    )
  }

  if (!body.instructionDataB64 || !Array.isArray(body.accounts) || body.accounts.length < 7) {
    return jsonResponse({ error: 'Invalid Audren instruction payload' }, 400)
  }

  let ixData: Uint8Array
  try {
    ixData = fromBase64(body.instructionDataB64)
  } catch {
    return jsonResponse({ error: 'Invalid base64 instructionDataB64' }, 400)
  }
  const tag = ixData[0]
  if (
    tag !== TAG_TRANSFER &&
    tag !== TAG_MERGE &&
    tag !== TAG_SWAP_VIA_ROUTER &&
    tag !== TAG_WITHDRAW
  ) {
    return jsonResponse(
      {
        error: `Relayer only permits Transfer (3), Merge (4), SwapViaRouter (5), or Withdraw (6); got tag ${tag}`,
      },
      400,
    )
  }

  const relayerPubkey = ed25519.getPublicKey(relayerSecret)
  const relayerB58 = base58Encode(relayerPubkey)

  // Strict account firewall: ONLY accounts[0] may be signer and MUST equal relayerPubkey!
  let decodedAccounts: SolanaAccountMeta[]
  try {
    decodedAccounts = body.accounts.map((a, idx) => {
      const pubkey = base58Decode(a.pubkey)
      if (pubkey.length !== 32) throw new Error(`Bad account #${idx}`)
      if (idx === 0) {
        if (!bytesEqual(pubkey, relayerPubkey) || !a.isSigner || !a.isWritable) {
          throw new Error(`accounts[0] must be relayer ${relayerB58} (writable signer)`)
        }
      } else if (a.isSigner) {
        throw new Error(`Unexpected extra signer at accounts[${idx}]`)
      }
      return { pubkey, isSigner: a.isSigner, isWritable: a.isWritable }
    })
  } catch (err) {
    return jsonResponse({ error: sanitizeError(err, 'Invalid account metas') }, 400)
  }

  try {
    const instructions: SolanaInstruction[] = []
    let prependedRollover = false

    // Automatic permissionless page rollover on BOTH Lane 0 (`Tag 1: OpenPage`) AND
    // parallel lanes 1..15 (`Tag 12: OpenLanePage` with READ-ONLY PoolState!) whenever
    // the active page has reached `count >= 28` or `closed` and `out_page` targets `nextPageId`.
    const writesOutput =
      tag === TAG_TRANSFER ||
      tag === TAG_MERGE ||
      tag === TAG_SWAP_VIA_ROUTER ||
      (tag === TAG_WITHDRAW && ixData.length >= 4 && ixData[3] !== 0)
    if (writesOutput && decodedAccounts.length >= 3) {
      const requestedFromId =
        body.rolloverFromPageId !== undefined && /^\d+$/.test(body.rolloverFromPageId)
          ? BigInt(body.rolloverFromPageId)
          : null
      const requestedLane = requestedFromId !== null ? laneOfPageId(requestedFromId) : 0
      const poolPda = await derivePoolPda(0)

      if (requestedLane === 0) {
        const rentVaultPda = await derivePageRentVaultPda(0)
        const poolAcc = await fetchAccountBytes(rpcUrl, base58Encode(poolPda.address))
        const pool = decodePoolState(poolAcc.bytes)
        const [curPagePda, nextPagePda] = await Promise.all([
          deriveEpochPagePda(0, pool.currentPageId),
          deriveEpochPagePda(0, pool.currentPageId + 1n),
        ])
        if (bytesEqual(decodedAccounts[2].pubkey, nextPagePda.address)) {
          const curPageAcc = await fetchAccountBytes(rpcUrl, base58Encode(curPagePda.address))
          const curHdr = decodeEpochPageHeader(curPageAcc.bytes)
          if (curHdr.closed || curHdr.count >= PAGE_ROLLOVER_THRESHOLD) {
            instructions.push({
              programId: AUDREN_PROGRAM_ID,
              accounts: [
                { pubkey: relayerPubkey, isSigner: true, isWritable: true },
                { pubkey: poolPda.address, isSigner: false, isWritable: true },
                { pubkey: curPagePda.address, isSigner: false, isWritable: true },
                { pubkey: nextPagePda.address, isSigner: false, isWritable: true },
                { pubkey: rentVaultPda.address, isSigner: false, isWritable: true },
                { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
              ],
              data: new Uint8Array([TAG_OPEN_PAGE]),
            })
            prependedRollover = true
          }
        }
      } else if (requestedLane < MAX_APPEND_LANES) {
        const [lanePda, laneRentVaultPda] = await Promise.all([
          deriveLanePda(0, requestedLane),
          deriveLaneRentVaultPda(0, requestedLane),
        ])
        const laneAcc = await fetchAccountBytes(rpcUrl, base58Encode(lanePda.address))
        const laneState = decodeAppendLaneState(laneAcc.bytes)
        if (laneState) {
          const curId = laneState.activePageId
          const nextId = pageIdForLane(requestedLane, seqOfPageId(curId) + 1n)
          const [curPagePda, nextPagePda] = await Promise.all([
            deriveEpochPagePda(0, curId),
            deriveEpochPagePda(0, nextId),
          ])
          if (bytesEqual(decodedAccounts[2].pubkey, nextPagePda.address)) {
            const curPageAcc = await fetchAccountBytes(rpcUrl, base58Encode(curPagePda.address))
            const curHdr = decodeEpochPageHeader(curPageAcc.bytes)
            if (curHdr.closed || curHdr.count >= PAGE_ROLLOVER_THRESHOLD) {
              instructions.push({
                programId: AUDREN_PROGRAM_ID,
                accounts: [
                  { pubkey: relayerPubkey, isSigner: true, isWritable: true },
                  { pubkey: poolPda.address, isSigner: false, isWritable: false },
                  { pubkey: lanePda.address, isSigner: false, isWritable: true },
                  { pubkey: curPagePda.address, isSigner: false, isWritable: true },
                  { pubkey: nextPagePda.address, isSigner: false, isWritable: true },
                  { pubkey: laneRentVaultPda.address, isSigner: false, isWritable: true },
                  { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
                ],
                data: new Uint8Array([TAG_OPEN_LANE_PAGE, requestedLane & 0xff]),
              })
              prependedRollover = true
            }
          }
        }
      }
    }

    // Permit idempotent ATA setup ONLY for:
    //  (a) Audren's own vault_auth or ANY swap_escrow shard (0..15) PDA, OR
    //  (b) The exact recipient_ata (accounts[10]) of an SPL/Token-2022 Withdraw (atomic revert on invalid proof)
    if (Array.isArray(body.setupAtas) && body.setupAtas.length > 0) {
      const [vaultAuthPda, ...escrowPdas] = await Promise.all([
        deriveVaultAuthPda(0),
        ...Array.from({ length: MAX_ESCROW_SHARDS }, (_, sid) => deriveSwapEscrowPda(0, sid)),
      ])
      const allowedOwners = new Set([
        base58Encode(vaultAuthPda.address),
        ...escrowPdas.map((p) => base58Encode(p.address)),
      ])
      const isSplWithdraw =
        tag === TAG_WITHDRAW && ixData.length >= 3 && ixData[2] === 0 && decodedAccounts.length >= 12
      for (const req of body.setupAtas.slice(0, 4)) {
        if (
          req.tokenProgram !== CLASSIC_TOKEN_PROGRAM_ID_STR &&
          req.tokenProgram !== TOKEN_2022_PROGRAM_ID_STR
        ) {
          return jsonResponse({ error: 'Unsupported tokenProgram in setupAtas' }, 400)
        }
        let ownerBytes: Uint8Array
        let mintBytes: Uint8Array
        let tpBytes: Uint8Array
        try {
          ownerBytes = base58Decode(req.owner)
          mintBytes = base58Decode(req.mint)
          tpBytes = base58Decode(req.tokenProgram)
        } catch {
          return jsonResponse({ error: 'Invalid base58 pubkey in setupAtas' }, 400)
        }
        if (ownerBytes.length !== 32 || mintBytes.length !== 32 || tpBytes.length !== 32) {
          return jsonResponse({ error: 'Invalid pubkey length in setupAtas' }, 400)
        }
        const ata = await deriveAta(ownerBytes, tpBytes, mintBytes)
        const isAllowedPda = allowedOwners.has(req.owner)
        const isWithdrawRecipientAta =
          isSplWithdraw &&
          bytesEqual(ata, decodedAccounts[10].pubkey) &&
          bytesEqual(mintBytes, decodedAccounts[8].pubkey) &&
          bytesEqual(tpBytes, decodedAccounts[11].pubkey)
        if (!isAllowedPda && !isWithdrawRecipientAta) {
          return jsonResponse(
            { error: 'Relayer setupAtas only allowed for Audren vault/escrow PDAs or SPL Withdraw recipient ATA' },
            400,
          )
        }
        instructions.push(
          buildCreateAtaIdempotentIx({
            payer: relayerPubkey,
            ata,
            owner: ownerBytes,
            mint: mintBytes,
            tokenProgram: tpBytes,
          }),
        )
      }
    }

    instructions.push({
      programId: AUDREN_PROGRAM_ID,
      accounts: decodedAccounts,
      data: ixData,
    })

    const rawCu = body.computeUnitLimit === undefined ? 850_000 : Number(body.computeUnitLimit)
    if (!Number.isFinite(rawCu)) {
      return jsonResponse({ error: 'computeUnitLimit must be a finite integer' }, 400)
    }
    const requestedCu = Math.trunc(rawCu) + (prependedRollover ? 50_000 : 0)
    const cuLimit = Math.min(Math.max(requestedCu, 200_000), 1_400_000)
    const rawPrio = body.priorityFeeLamports ?? '5000'
    if (typeof rawPrio !== 'string' || !/^\d+$/.test(rawPrio)) {
      return jsonResponse({ error: 'priorityFeeLamports must be a non-negative integer string' }, 400)
    }
    const priorityFee = BigInt(rawPrio)
    const cappedPriority = priorityFee > 50_000n ? 50_000n : priorityFee

    const bhRes = await rpcCall<{ value: { blockhash: string } }>(rpcUrl, 'getLatestBlockhash', [
      { commitment: 'confirmed' },
    ])

    const signed = buildAndSignV1Transaction(relayerSecret, bhRes.value.blockhash, instructions, {
      computeUnitLimit: cuLimit,
      priorityFeeLamports: cappedPriority,
    })

    const sentSig = await rpcCall<string>(rpcUrl, 'sendTransaction', [
      toBase64(signed.wireBytes),
      { encoding: 'base64', preflightCommitment: 'confirmed', maxRetries: 3 },
    ])
    const { slot } = await waitForConfirmation(rpcUrl, sentSig)
    const actualOut = body.vaultOutAta
      ? await resolveVaultOutDelta(rpcUrl, sentSig, body.vaultOutAta)
      : null

    return jsonResponse({
      ok: true,
      cluster,
      txVersion: signed.version,
      txWireBytes: signed.wireLen,
      relayerPubkey: relayerB58,
      priorityFeeLamports: cappedPriority.toString(),
      computeUnitLimit: cuLimit,
      signature: sentSig,
      slot,
      actualOut,
      solscanUrl: solscanTxUrl(sentSig, cluster),
      explorerUrl: explorerTxUrl(sentSig, cluster),
    })
  } catch (err) {
    return jsonResponse({ error: sanitizeError(err, 'Relayer submission failed') }, 502)
  }
}

// ============================================================================
// POST /api/devnet/deposit — Free no-wallet Devnet faucet deposit (Solana v1)
// ============================================================================

async function handleDevnetDeposit(request: Request, env: Env): Promise<Response> {
  if (!env.DEVNET_RPC_URL || !env.DEVNET_DEMO_SECRET_B64) {
    return jsonResponse({ error: 'Live Devnet demo service is not configured' }, 503)
  }

  const limit = checkRateLimit(`demo:${getClientIp(request)}`, RATE_MAX_REQUESTS)
  if (!limit.allowed) {
    return jsonResponse(
      { error: `Demo rate limit reached. Try again in ${limit.retryAfterSec}s.` },
      429,
      { 'retry-after': String(limit.retryAfterSec) },
    )
  }

  let body: {
    amountLamports?: string | number
    viewTag?: number
    ephemeralPkHex?: string
    stealthPkHex?: string
    ciphertextHex?: string
  }
  try {
    body = (await request.json()) as typeof body
  } catch {
    return jsonResponse({ error: 'Invalid JSON request body' }, 400)
  }

  let amountLamports: bigint
  try {
    amountLamports = BigInt(body.amountLamports ?? 0)
  } catch {
    return jsonResponse({ error: 'Invalid amountLamports' }, 400)
  }
  if (amountLamports < MIN_DEMO_DEPOSIT_LAMPORTS || amountLamports > MAX_DEMO_DEPOSIT_LAMPORTS) {
    return jsonResponse(
      { error: 'Demo deposit amount must be between 0.0001 SOL and 0.005 SOL' },
      400,
    )
  }

  const viewTag = Number(body.viewTag)
  if (!Number.isInteger(viewTag) || viewTag < 0 || viewTag > 255) {
    return jsonResponse({ error: 'Invalid viewTag (must be 0..255)' }, 400)
  }

  let ephemeralPk: Uint8Array
  let stealthPk: Uint8Array
  let ciphertext: Uint8Array
  try {
    ephemeralPk = fromHex(body.ephemeralPkHex ?? '')
    stealthPk = fromHex(body.stealthPkHex ?? '')
    ciphertext = fromHex(body.ciphertextHex ?? '')
  } catch {
    return jsonResponse({ error: 'Invalid hex-encoded note fields' }, 400)
  }

  if (ephemeralPk.length !== 32 || !isNonZeroPoint(ephemeralPk)) {
    return jsonResponse({ error: 'ephemeralPk must be a valid non-zero 32-byte Ristretto255 point' }, 400)
  }
  if (stealthPk.length !== 32 || !isNonZeroPoint(stealthPk)) {
    return jsonResponse({ error: 'stealthPk must be a valid non-zero 32-byte Ristretto255 point' }, 400)
  }
  if (ciphertext.length !== NOTE_CT_LEN) {
    return jsonResponse({ error: 'ciphertext must be exactly 64 bytes (AES-256-GCM)' }, 400)
  }

  try {
    const secret32 = fromBase64(env.DEVNET_DEMO_SECRET_B64)
    if (secret32.length !== 32) return jsonResponse({ error: 'Invalid demo signer key' }, 500)
    const payerPubkey = ed25519.getPublicKey(secret32)

    const [poolPda, solVaultPda, rentVaultPda] = await Promise.all([
      derivePoolPda(0),
      deriveSolVaultPda(0),
      derivePageRentVaultPda(0),
    ])
    const poolB58 = base58Encode(poolPda.address)
    const poolAcc = await fetchAccountBytes(env.DEVNET_RPC_URL, poolB58)
    const pool = decodePoolState(poolAcc.bytes)
    if (pool.paused) return jsonResponse({ error: 'Devnet pool is temporarily paused' }, 503)

    const curPagePda = await deriveEpochPagePda(0, pool.currentPageId)
    const curPageAcc = await fetchAccountBytes(env.DEVNET_RPC_URL, base58Encode(curPagePda.address))
    const curHdr = decodeEpochPageHeader(curPageAcc.bytes)

    const instructions: SolanaInstruction[] = []
    let targetPageId = pool.currentPageId
    let targetPagePda = curPagePda
    let expectedSlotIndex = curHdr.count

    if (curHdr.closed || curHdr.count >= PAGE_ROLLOVER_THRESHOLD) {
      const nextPageId = pool.currentPageId + 1n
      const nextPagePda = await deriveEpochPagePda(0, nextPageId)
      instructions.push({
        programId: AUDREN_PROGRAM_ID,
        accounts: [
          { pubkey: payerPubkey, isSigner: true, isWritable: true },
          { pubkey: poolPda.address, isSigner: false, isWritable: true },
          { pubkey: curPagePda.address, isSigner: false, isWritable: true },
          { pubkey: nextPagePda.address, isSigner: false, isWritable: true },
          { pubkey: rentVaultPda.address, isSigner: false, isWritable: true },
          { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
        ],
        data: new Uint8Array([1]),
      })
      targetPageId = nextPageId
      targetPagePda = nextPagePda
      expectedSlotIndex = 0
    }

    const depositData = concatBytes(
      new Uint8Array([2, 1]),
      u64le(amountLamports),
      new Uint8Array([viewTag]),
      ephemeralPk,
      stealthPk,
      ciphertext,
    )

    instructions.push({
      programId: AUDREN_PROGRAM_ID,
      accounts: [
        { pubkey: payerPubkey, isSigner: true, isWritable: true },
        { pubkey: poolPda.address, isSigner: false, isWritable: true },
        { pubkey: targetPagePda.address, isSigner: false, isWritable: true },
        { pubkey: solVaultPda.address, isSigner: false, isWritable: true },
        { pubkey: rentVaultPda.address, isSigner: false, isWritable: true },
        { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
      ],
      data: depositData,
    })

    const bhRes = await rpcCall<{ value: { blockhash: string } }>(
      env.DEVNET_RPC_URL,
      'getLatestBlockhash',
      [{ commitment: 'confirmed' }],
    )

    const signed = buildAndSignV1Transaction(secret32, bhRes.value.blockhash, instructions, {
      computeUnitLimit: 300_000,
      priorityFeeLamports: 1_000n,
    })

    const sentSig = await rpcCall<string>(env.DEVNET_RPC_URL, 'sendTransaction', [
      toBase64(signed.wireBytes),
      { encoding: 'base64', preflightCommitment: 'confirmed', maxRetries: 3 },
    ])

    const { slot } = await waitForConfirmation(env.DEVNET_RPC_URL, sentSig)

    const targetPageB58 = base58Encode(targetPagePda.address)
    const updatedPageAcc = await fetchAccountBytes(env.DEVNET_RPC_URL, targetPageB58)
    const updatedNotes = formatPublicNotes(updatedPageAcc.bytes)
    const targetStealthB58 = base58Encode(stealthPk)
    const matchedNote =
      updatedNotes.find((n) => n.stealthPk === targetStealthB58) ??
      updatedNotes[expectedSlotIndex] ??
      updatedNotes[updatedNotes.length - 1]

    return jsonResponse({
      ok: true,
      cluster: 'devnet',
      txVersion: signed.version,
      txWireBytes: signed.wireLen,
      signature: sentSig,
      slot,
      amountLamports: amountLamports.toString(),
      programId: AUDREN_PROGRAM_ID_STR,
      poolPda: poolB58,
      pageId: targetPageId.toString(),
      pagePda: targetPageB58,
      slotIndex: matchedNote?.slotIndex ?? expectedSlotIndex,
      solscanUrl: solscanTxUrl(sentSig, 'devnet'),
      explorerUrl: explorerTxUrl(sentSig, 'devnet'),
      note: matchedNote,
      pageBase64: toBase64(updatedPageAcc.bytes),
    })
  } catch (err) {
    return jsonResponse({ error: sanitizeError(err, 'Devnet deposit failed') }, 502)
  }
}

async function handleTxInspect(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url)
  const cluster = parseCluster(url.searchParams.get('cluster'), 'mainnet')
  const signature = (url.searchParams.get('signature') ?? '').trim()
  const rpcUrl = getRpcUrl(env, cluster)
  if (!rpcUrl) return jsonResponse({ error: `${cluster} RPC not configured` }, 503)
  if (!/^[1-9A-HJ-NP-Za-km-z]{64,96}$/.test(signature)) {
    return jsonResponse({ error: 'Invalid transaction signature' }, 400)
  }

  type ParsedKey = string | { pubkey: string; signer?: boolean; writable?: boolean }
  type ParsedIx = { programId?: string }
  type RawTx = {
    slot?: number
    version?: number | 'legacy'
    transaction?: {
      message?: {
        accountKeys?: ParsedKey[]
        instructions?: ParsedIx[]
      }
    }
    meta?: {
      err?: unknown | null
      fee?: number
      computeUnitsConsumed?: number | null
      loadedAddresses?: { writable?: string[]; readonly?: string[] }
    }
  } | null

  try {
    let tx: RawTx = null
    for (let attempt = 0; attempt < 4; attempt++) {
      tx = await rpcCall<RawTx>(rpcUrl, 'getTransaction', [
        signature,
        { encoding: 'jsonParsed', commitment: 'confirmed', maxSupportedTransactionVersion: 1 },
      ])
      if (tx?.transaction?.message?.accountKeys) break
      await new Promise((r) => setTimeout(r, 450))
    }
    if (!tx?.transaction?.message?.accountKeys) {
      return jsonResponse({ error: 'Transaction not indexed yet' }, 404)
    }

    const staticEntries = tx.transaction.message.accountKeys
    const signers: string[] = []
    const staticKeys: string[] = []
    for (const k of staticEntries) {
      if (typeof k === 'string') {
        staticKeys.push(k)
      } else if (k?.pubkey) {
        staticKeys.push(k.pubkey)
        if (k.signer) signers.push(k.pubkey)
      }
    }
    const accountKeys = [
      ...staticKeys,
      ...(tx.meta?.loadedAddresses?.writable ?? []),
      ...(tx.meta?.loadedAddresses?.readonly ?? []),
    ]
    const programIds = Array.from(
      new Set(
        (tx.transaction.message.instructions ?? [])
          .map((ix) => ix.programId)
          .filter((p): p is string => typeof p === 'string' && p.length > 0),
      ),
    )

    return jsonResponse({
      ok: true,
      cluster,
      signature,
      slot: tx.slot ?? 0,
      version: tx.version ?? 'legacy',
      err: tx.meta?.err ?? null,
      feeLamports: tx.meta?.fee ?? 0,
      computeUnitsConsumed: tx.meta?.computeUnitsConsumed ?? null,
      signers,
      accountKeys,
      programIds,
    })
  } catch (err) {
    return jsonResponse({ error: sanitizeError(err, 'Failed to inspect transaction') }, 502)
  }
}

const worker = {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)

    const canonicalHost = env.CANONICAL_HOST?.trim()
    if (
      url.hostname !== 'localhost' &&
      url.hostname !== '127.0.0.1' &&
      (url.protocol === 'http:' || (canonicalHost && url.hostname === `www.${canonicalHost}`))
    ) {
      url.protocol = 'https:'
      if (canonicalHost && url.hostname === `www.${canonicalHost}`) {
        url.hostname = canonicalHost
      }
      return Response.redirect(url.toString(), 301)
    }

    if (url.pathname === '/api/pool' && request.method === 'GET') {
      return handleGetPool(request, env)
    }
    if (url.pathname === '/api/devnet/pool' && request.method === 'GET') {
      return handleGetPool(request, env, 'devnet')
    }
    if (url.pathname === '/api/devnet/deposit' && request.method === 'POST') {
      return handleDevnetDeposit(request, env)
    }
    if (url.pathname === '/api/wallet/balances' && request.method === 'GET') {
      return handleWalletBalances(request, env)
    }
    if (url.pathname === '/api/tokens/search' && request.method === 'GET') {
      return handleTokenSearch(request, env)
    }
    if (url.pathname === '/api/tokens/resolve' && request.method === 'POST') {
      return handleTokenResolve(request, env)
    }
    const logoMatch = /^\/api\/tokens\/logo\/([0-9a-f]{64})\.webp$/.exec(url.pathname)
    if (logoMatch && (request.method === 'GET' || request.method === 'HEAD')) {
      return handleTokenLogo(env, logoMatch[1], request.method === 'HEAD')
    }
    const mintLogoMatch = /^\/api\/tokens\/mint-logo\/([1-9A-HJ-NP-Za-km-z]{32,44})\.webp$/.exec(
      url.pathname,
    )
    if (mintLogoMatch && (request.method === 'GET' || request.method === 'HEAD')) {
      return handleMintLogo(
        env,
        mintLogoMatch[1],
        request.method === 'HEAD',
        url.searchParams.get('s'),
      )
    }
    if (url.pathname === '/api/pages/slices' && request.method === 'GET') {
      return handleGetPageSlices(request, env)
    }
    if (url.pathname === '/api/pages/sealed' && request.method === 'GET') {
      return handleGetSealedPages(request, env)
    }
    if (url.pathname === '/api/pages/fetch' && request.method === 'POST') {
      return handleFetchPages(request, env)
    }
    if (url.pathname === '/api/buffers/check' && request.method === 'POST') {
      return handleCheckBuffers(request, env)
    }
    if (url.pathname === '/api/notes/resolve-dynamic' && request.method === 'POST') {
      return handleResolveDynamicNote(request, env)
    }
    if (url.pathname === '/api/nullifiers' && request.method === 'POST') {
      return handleNullifierCheck(request, env)
    }
    if (url.pathname === '/api/rpc/blockhash' && request.method === 'GET') {
      return handleGetBlockhash(request, env)
    }
    if (url.pathname === '/api/rpc/send' && request.method === 'POST') {
      return handleRpcSend(request, env)
    }
    if (url.pathname === '/api/jupiter/quote' && request.method === 'POST') {
      return handleJupiterQuote(request, env)
    }
    if (url.pathname === '/api/jupiter/swap-instructions' && request.method === 'POST') {
      return handleJupiterSwapInstructions(request, env)
    }
    if (url.pathname === '/api/relay/submit' && request.method === 'POST') {
      return handleRelaySubmit(request, env)
    }
    if (url.pathname === '/api/tx/inspect' && request.method === 'GET') {
      return handleTxInspect(request, env)
    }

    return env.ASSETS.fetch(request)
  },
}

export default worker
