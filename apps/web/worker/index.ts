import { ed25519 } from '@noble/curves/ed25519.js'
import {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_PUBLIC,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  AUDREN_PROGRAM_ID,
  CLASSIC_TOKEN_PROGRAM_ID,
  CU_LIMIT_OPEN_PAGE,
  CU_LIMIT_TRANSACT_FULL_EXIT,
  EPOCH_RING_LEN,
  MEMO_ENTRY_WIRE_LEN,
  MEMO_NOTES_PER_PAGE,
  MEMO_PAGE_LEN,
  NUM_ESCROW_SHARDS,
  NUM_LANES,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_NULLIFIER,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  PROTOCOL_VERSION,
  ROOT_RING_EPOCH,
  ROOT_RING_SLOT,
  SLOT_RING_LEN,
  SUBROOTS_PER_PAGE,
  SUBROOT_PAGE_LEN,
  SUBTREE_LEAVES,
  SUBTREE_PAGE_LEN,
  TAG_DEPOSIT,
  TAG_EXEC_VIA_ESCROW,
  TAG_OPEN_PAGE,
  TAG_TRANSACT,
  TOKEN_2022_PROGRAM_ID,
  VK_ID_DEFAULT,
  WITHDRAW_FLAG_UNWRAP_WSOL,
  WSOL_MINT,
  audrenInstructionToSolana,
  base58Decode,
  base58Encode,
  buildCreateAtaIdempotentInstruction,
  buildDepositInstruction,
  buildOpenPageInstruction,
  bytesEqual,
  compileV1Message,
  computeNoteCommitment,
  computePageRollovers,
  computeToken2022NetAmount,
  decodeGlobalRootHistory,
  decodeLaneHeader,
  decodePoolState,
  decodeSubtreePage,
  deriveAssetId,
  deriveAssociatedTokenAddressSync,
  deriveEscrowPdaSync,
  deriveLanePdaSync,
  deriveMemoPdaSync,
  deriveNfPagePdaSync,
  derivePoolPdaSync,
  deriveRootsPdaSync,
  deriveStealthOwner,
  deriveSubrootPdaSync,
  deriveSubtreePdaSync,
  deriveVaultAuthPdaSync,
  encryptNoteMemo,
  frFromBeBytesStrict,
  frToBeBytes,
  fromBase64,
  parseAudrenAddress,
  parseToken2022TransferFeeConfig,
  pickRandomLaneId,
  planAutoOpenPages,
  recommendedDepositCuLimit,
  recommendedTransactCuLimit,
  serializeV1Transaction,
  toBase64,
  toHex,
  type AudrenInstruction,
  type V1Instruction,
} from '../lib/audren-crypto'

interface ServiceBinding {
  fetch(input: Request | URL | string, init?: RequestInit): Promise<Response>
}

interface Env {
  ASSETS: ServiceBinding
  GATEWAY?: ServiceBinding
  TOKEN_GATEWAY_ORIGIN?: string
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
const MAX_JSON_BODY_BYTES = 65_536
const RATE_WINDOW_SHORT_MS = 60 * 1000
const RATE_MAX_READ_PER_MIN = 120
const RATE_MAX_JUPITER_PER_MIN = 40
const RATE_MAX_RPC_SEND_PER_MIN = 30
const RATE_WINDOW_MS = 10 * 60 * 1000
const RATE_MAX_REQUESTS = 8
const RELAY_RATE_MAX = 8
const RATE_BUCKETS_SWEEP_THRESHOLD = 512
const RATE_BUCKETS_MAX_ENTRIES = 2_048

const COMPUTE_BUDGET_PROGRAM_ID = 'ComputeBudget111111111111111111111111111111'
const RPC_SEND_ALLOWED_COMPANION_PROGRAMS = new Set<string>([
  AUDREN_PROGRAM_ID,
  COMPUTE_BUDGET_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
])
const RPC_SEND_ALLOWED_AUDREN_TAGS = new Set<number>([
  TAG_OPEN_PAGE,
  TAG_DEPOSIT,
  TAG_TRANSACT,
  TAG_EXEC_VIA_ESCROW,
])

class TxConfirmationTimeoutError extends Error {
  readonly signature: string
  constructor(signature: string) {
    super('Transaction confirmation timed out')
    this.name = 'TxConfirmationTimeoutError'
    this.signature = signature
  }
}

class PayloadTooLargeError extends Error {
  readonly maxBytes: number
  constructor(maxBytes: number) {
    super(`Request body exceeds ${maxBytes}-byte limit`)
    this.name = 'PayloadTooLargeError'
    this.maxBytes = maxBytes
  }
}

async function readJsonBodyBounded<T>(
  request: Request,
  maxBytes = MAX_JSON_BODY_BYTES,
): Promise<T | null> {
  const contentLength = request.headers.get('content-length')
  if (contentLength !== null) {
    const parsedLen = Number(contentLength)
    if (Number.isFinite(parsedLen) && parsedLen > maxBytes) {
      throw new PayloadTooLargeError(maxBytes)
    }
  }
  if (!request.body) return null
  const reader = request.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      if (!value) continue
      total += value.byteLength
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined)
        throw new PayloadTooLargeError(maxBytes)
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  if (total === 0) return null
  const buf = new Uint8Array(total)
  let off = 0
  for (const chunk of chunks) {
    buf.set(chunk, off)
    off += chunk.byteLength
  }
  try {
    return JSON.parse(new TextDecoder().decode(buf)) as T
  } catch {
    return null
  }
}

function decodePubkeyChecked(s: unknown): Uint8Array | null {
  if (typeof s !== 'string' || s.length < 32 || s.length > 44) return null
  try {
    const decoded = base58Decode(s)
    return decoded.byteLength === 32 ? decoded : null
  } catch {
    return null
  }
}

function isValidPubkeyStr(s: unknown): s is string {
  return decodePubkeyChecked(s) !== null
}

function readShortVec(bytes: Uint8Array, start: number): [number, number] {
  let len = 0
  let size = 0
  let off = start
  for (;;) {
    if (off >= bytes.byteLength || size >= 3) {
      throw new Error('Malformed compact-u16 in transaction')
    }
    const elem = bytes[off++]!
    if (size === 2 && (elem & 0xfc) !== 0) {
      throw new Error('Overflow in compact-u16')
    }
    len |= (elem & 0x7f) << (size * 7)
    size += 1
    if ((elem & 0x80) === 0) break
  }
  return [len, off]
}

interface ParsedWireInstruction {
  programId: string
  data: Uint8Array
}

/**
 * Decode a signed Solana legacy, v0 (`0x80`), or v1 (`0x81`) wire transaction and return
 * the ordered list of top-level instructions (`programId` + raw instruction `data`).
 */
function extractTransactionInstructions(wire: Uint8Array): ParsedWireInstruction[] {
  if (wire.byteLength < 42 || wire.byteLength > 4_096) {
    throw new Error(`Invalid transaction byte length (${wire.byteLength})`)
  }
  const instructions: ParsedWireInstruction[] = []

  // Solana Transaction v1 (SIMD-0385, `0x81`): messageBytes || signatures
  if (wire[0] === 0x81) {
    const numReqSigs = wire[1]!
    const numRoSigned = wire[2]!
    const numRoUnsigned = wire[3]!
    if (numReqSigs === 0 || numReqSigs > 64) {
      throw new Error('Invalid v1 transaction signature count')
    }
    const dv = new DataView(wire.buffer, wire.byteOffset, wire.byteLength)
    const configMask = dv.getUint32(4, true)
    const numInstructions = wire[40]!
    const numAddresses = wire[41]!
    if (
      numInstructions === 0 ||
      numInstructions > 64 ||
      numAddresses === 0 ||
      numAddresses > 64 ||
      numRoSigned > numReqSigs ||
      numReqSigs + numRoUnsigned > numAddresses
    ) {
      throw new Error('Invalid v1 transaction header counts')
    }
    let off = 42
    if (off + numAddresses * 32 > wire.byteLength) {
      throw new Error('Truncated v1 account keys')
    }
    const keys: string[] = []
    for (let i = 0; i < numAddresses; i++) {
      keys.push(base58Encode(wire.subarray(off, off + 32)))
      off += 32
    }
    let mask = configMask >>> 0
    let configSlots = 0
    while (mask !== 0) {
      configSlots += mask & 1
      mask >>>= 1
    }
    off += configSlots * 4
    if (off + numInstructions * 4 > wire.byteLength) {
      throw new Error('Truncated v1 instruction headers')
    }
    const headers: Array<{ programId: string; numAccs: number; dataLen: number }> = []
    for (let i = 0; i < numInstructions; i++) {
      const programIdx = wire[off]!
      const numAccs = wire[off + 1]!
      const dataLen = dv.getUint16(off + 2, true)
      if (programIdx === 0 || programIdx >= numAddresses) {
        throw new Error('Invalid v1 instruction program index')
      }
      headers.push({ programId: keys[programIdx]!, numAccs, dataLen })
      off += 4
    }
    for (const h of headers) {
      if (off + h.numAccs + h.dataLen > wire.byteLength) {
        throw new Error('Truncated v1 instruction payload')
      }
      off += h.numAccs
      const data = wire.subarray(off, off + h.dataLen)
      off += h.dataLen
      instructions.push({ programId: h.programId, data })
    }
    if (off + numReqSigs * 64 !== wire.byteLength) {
      throw new Error('Malformed v1 transaction payload or signature length')
    }
    return instructions
  }

  // Solana legacy or v0 (`0x80`) wire transaction: short_vec(sigs) || message
  if (wire.byteLength < 64 || wire.byteLength > 1_232) {
    throw new Error(`Invalid legacy/v0 transaction byte length (${wire.byteLength})`)
  }
  const [numSigs, afterSigsLen] = readShortVec(wire, 0)
  if (numSigs === 0 || numSigs > 64) {
    throw new Error('Invalid transaction signature count')
  }
  let off = afterSigsLen + numSigs * 64
  if (off >= wire.byteLength) {
    throw new Error('Truncated transaction signatures')
  }
  let isV0 = false
  if ((wire[off]! & 0x80) !== 0) {
    if (wire[off]! !== 0x80) {
      throw new Error(`Unsupported Solana transaction version (${wire[off]! & 0x7f})`)
    }
    isV0 = true
    off += 1
  }
  if (off + 3 > wire.byteLength) {
    throw new Error('Truncated message header')
  }
  const numReqSigs = wire[off]!
  if (numReqSigs !== numSigs) {
    throw new Error('Transaction signature count does not match message header')
  }
  off += 3
  const [numStaticKeys, afterKeysLen] = readShortVec(wire, off)
  off = afterKeysLen
  if (numStaticKeys === 0 || off + numStaticKeys * 32 + 32 > wire.byteLength) {
    throw new Error('Truncated transaction static account keys')
  }
  const staticKeys: string[] = []
  for (let i = 0; i < numStaticKeys; i++) {
    staticKeys.push(base58Encode(wire.subarray(off, off + 32)))
    off += 32
  }
  // Skip 32-byte recentBlockhash
  off += 32

  const [numIxs, afterIxLen] = readShortVec(wire, off)
  off = afterIxLen
  if (numIxs === 0 || numIxs > 64) {
    throw new Error('Invalid transaction instruction count')
  }
  for (let i = 0; i < numIxs; i++) {
    if (off >= wire.byteLength) throw new Error('Truncated transaction instruction')
    const programIdx = wire[off++]!
    if (programIdx >= numStaticKeys) {
      throw new Error('Invalid transaction instruction program index')
    }
    const programId = staticKeys[programIdx]!
    const [accLen, afterAccLen] = readShortVec(wire, off)
    off = afterAccLen + accLen
    if (off > wire.byteLength) throw new Error('Truncated instruction account indices')
    const [dataLen, afterDataLen] = readShortVec(wire, off)
    off = afterDataLen + dataLen
    if (off > wire.byteLength) throw new Error('Truncated instruction data')
    instructions.push({ programId, data: wire.subarray(afterDataLen, off) })
  }

  if (isV0) {
    const [numLookups, afterLookupsLen] = readShortVec(wire, off)
    off = afterLookupsLen
    for (let i = 0; i < numLookups; i++) {
      off += 32
      if (off > wire.byteLength) throw new Error('Truncated ALT lookup table address')
      const [wLen, afterW] = readShortVec(wire, off)
      off = afterW + wLen
      const [rLen, afterR] = readShortVec(wire, off)
      off = afterR + rLen
      if (off > wire.byteLength) throw new Error('Truncated ALT lookup indices')
    }
  }

  if (off !== wire.byteLength) {
    throw new Error('Unexpected trailing bytes in serialized transaction')
  }
  return instructions
}

function resolveSafeJupiterBaseUrl(env: Env): string {
  const raw = env.JUPITER_API_URL?.trim() || 'https://api.jup.ag'
  let parsed: URL
  try {
    parsed = new URL(raw)
  } catch {
    throw new Error('Invalid JUPITER_API_URL configuration')
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
    throw new Error('JUPITER_API_URL must be an HTTPS URL without credentials')
  }
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (
    !host ||
    host === 'localhost' ||
    host === '0.0.0.0' ||
    host === '::' ||
    host === '::1' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    /^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host) ||
    host.startsWith('::ffff:') ||
    /^0{1,4}(:0{1,4}){0,7}$/.test(host) ||
    /^0{1,4}(:0{1,4}){6}:0{0,3}1$/.test(host) ||
    /^f[cd][0-9a-f]{0,2}:/.test(host) ||
    /^fe[89ab][0-9a-f]?:/.test(host)
  ) {
    throw new Error('JUPITER_API_URL must point to a public HTTPS host')
  }
  return raw.replace(/\/+$/, '').replace(/\/swap\/v1$/, '')
}

// Kept byte-for-byte in sync with crates/client/src/router.rs,
// packages/sdk/src/swap.ts, and apps/relay/src/aggregators/jupiter.ts.
const JUPITER_CPI_EXCLUDED_DEXES = [
  'Kipseli',
  'Quantum',
  'BisonFi',
  'BisonFi Predict',
  'BinaryFi',
  'Obsidian',
  'VaultLiquidUnstake',
  'Sanctum Prop S',
]

const RATE_BUCKETS = new Map<string, { count: number; resetAt: number }>()

interface GatewayTokenCard {
  mint: string
  symbol: string | null
  name: string | null
  decimals: number | null
  logo: string | null
  tokenProgram: 'spl-token' | 'token-2022' | null
  trust?: { tier: number | null; flags?: string[] | null }
  price?: { mid?: number } | null
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

interface PoolRootHistorySummary {
  slotCursor: number
  epochCursor: number
  slotCount: number
  epochCount: number
  latestSlot: string
  stableSlot: string
  stableEpochId: string
  epochInterval: string
  latestSuperRoot: string
  stableSuperRoot: string
  latestLaneCounts: string[]
  stableLaneCounts: string[]
}

interface InitializedPoolSnapshot {
  initialized: true
  cluster: Cluster
  protocolVersion: number
  programId: string
  poolId: number
  poolPda: string
  rootsPda: string
  vaultAuthPda: string
  wsolVaultAta: string
  wsolVaultLamports: string
  paused: boolean
  activeLanes: number
  rootEpochInterval: string
  noteRentFee: string
  deterministicNoteRentFee: string
  nfRentFee: string
  currentSlot: string
  currentEpoch: string
  totalNotes: string
  totalNullifiers: string
  lanes: Array<{
    laneId: number
    lanePda: string
    nextLeaf: string
    nfCount: string
    currentRootHex: string
  } | null>
  rootHistory: PoolRootHistorySummary | null
}

interface UninitializedPoolSnapshot {
  initialized: false
  cluster: Cluster
  protocolVersion: number
  programId: string
  poolId: number
  poolPda: string
  rootsPda: string
  vaultAuthPda: string
  wsolVaultAta: string
  wsolVaultLamports: string
}

function jsonResponse(body: unknown, status = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...extraHeaders,
    },
  })
}

function shortMint(mint: string): string {
  return mint.length > 10 ? `${mint.slice(0, 4)}…${mint.slice(-4)}` : mint
}

function checkRateLimit(
  ip: string,
  bucket: string,
  maxRequests: number,
  windowMs = RATE_WINDOW_MS,
): { allowed: boolean; retryAfterSec: number } {
  const key = `${bucket}:${ip}`
  const now = Date.now()
  if (RATE_BUCKETS.size > RATE_BUCKETS_SWEEP_THRESHOLD) {
    for (const [k, v] of RATE_BUCKETS) {
      if (v.resetAt <= now) RATE_BUCKETS.delete(k)
    }
  }
  const cur = RATE_BUCKETS.get(key)
  if (!cur || cur.resetAt <= now) {
    if (cur) {
      RATE_BUCKETS.delete(key)
    } else if (RATE_BUCKETS.size >= RATE_BUCKETS_MAX_ENTRIES) {
      const oldestKey = RATE_BUCKETS.keys().next().value
      if (oldestKey !== undefined) RATE_BUCKETS.delete(oldestKey)
    }
    RATE_BUCKETS.set(key, { count: 1, resetAt: now + windowMs })
    return { allowed: true, retryAfterSec: Math.max(1, Math.ceil(windowMs / 1000)) }
  }
  const retryAfterSec = Math.max(1, Math.ceil((cur.resetAt - now) / 1000))
  if (cur.count >= maxRequests) return { allowed: false, retryAfterSec }
  cur.count += 1
  return { allowed: true, retryAfterSec }
}

function getClientIp(request: Request): string {
  const cf = request.headers.get('cf-connecting-ip')?.trim()
  if (cf) return cf
  const xff = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
  return xff || 'local'
}

function enforceRateLimit(
  request: Request,
  bucket: string,
  maxRequests: number,
  windowMs: number,
  errorMessage: string,
): Response | null {
  const rl = checkRateLimit(getClientIp(request), bucket, maxRequests, windowMs)
  if (!rl.allowed) {
    return jsonResponse({ error: errorMessage }, 429, {
      'retry-after': String(rl.retryAfterSec),
    })
  }
  return null
}

function parseCluster(raw: string | null | undefined): Cluster {
  return raw === 'devnet' ? 'devnet' : 'mainnet'
}

function getRpcUrl(env: Env, cluster: Cluster): string {
  const url = cluster === 'devnet' ? env.DEVNET_RPC_URL?.trim() : env.MAINNET_RPC_URL?.trim()
  if (!url) {
    throw new Error(
      cluster === 'devnet'
        ? 'DEVNET_RPC_URL secret is not configured on this Worker'
        : 'MAINNET_RPC_URL secret is not configured on this Worker',
    )
  }
  return url
}

async function solanaRpc<T>(env: Env, cluster: Cluster, method: string, params: unknown[]): Promise<T> {
  const rpcUrl = getRpcUrl(env, cluster)
  let res: Response
  try {
    res = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    })
  } catch {
    throw new Error(`Solana RPC ${method} transport error`)
  }
  if (!res.ok) throw new Error(`Solana RPC ${method} HTTP ${res.status}`)
  let json: { result?: T; error?: { message?: string } }
  try {
    json = (await res.json()) as { result?: T; error?: { message?: string } }
  } catch {
    throw new Error(`Solana RPC ${method} invalid JSON response`)
  }
  if (json.error) throw new Error(`Solana RPC ${method}: ${json.error.message ?? 'unknown error'}`)
  return json.result as T
}

function decodeDemoKeypair(env: Env): { secretSeed: Uint8Array; pubkeyBytes: Uint8Array; pubkeyStr: string } | null {
  const raw = env.DEVNET_DEMO_SECRET_B64?.trim()
  if (!raw) return null
  const bytes = fromBase64(raw)
  const secretSeed = bytes.byteLength >= 32 ? bytes.subarray(0, 32) : null
  if (!secretSeed) return null
  const pubkeyBytes = ed25519.getPublicKey(secretSeed)
  return { secretSeed, pubkeyBytes, pubkeyStr: base58Encode(pubkeyBytes) }
}

function toV1Ix(ix: AudrenInstruction): V1Instruction {
  const sol = audrenInstructionToSolana(ix)
  return {
    programId: sol.programId,
    accounts: sol.accounts,
    data: sol.data,
  }
}

async function sendAndConfirmV1(
  env: Env,
  cluster: Cluster,
  signer: { secretSeed: Uint8Array; pubkeyBytes: Uint8Array },
  instructions: V1Instruction[],
  computeUnitLimit: number,
  options?: { preflightCommitment?: 'processed' | 'confirmed' },
): Promise<{ signature: string; slot: number; wireBytes: number }> {
  const preflightCommitment = options?.preflightCommitment ?? 'confirmed'
  const bh = await solanaRpc<{ value: { blockhash: string } }>(env, cluster, 'getLatestBlockhash', [
    { commitment: 'confirmed' },
  ])
  const compiled = compileV1Message({
    feePayer: signer.pubkeyBytes,
    recentBlockhash: base58Decode(bh.value.blockhash),
    instructions,
    config: { computeUnitLimit, priorityFeeLamports: 1_000n },
  })
  const sig = ed25519.sign(compiled.messageBytes, signer.secretSeed)
  const wire = serializeV1Transaction(compiled, [sig])
  const txSig = await solanaRpc<string>(env, cluster, 'sendTransaction', [
    toBase64(wire),
    { encoding: 'base64', preflightCommitment, maxRetries: 3 },
  ])

  let slot = 0
  let confirmed = false
  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 800))
    let st: {
      value: Array<{ confirmationStatus?: string | null; err?: unknown; slot?: number } | null>
    }
    try {
      st = await solanaRpc<{
        value: Array<{ confirmationStatus?: string | null; err?: unknown; slot?: number } | null>
      }>(env, cluster, 'getSignatureStatuses', [[txSig]])
    } catch {
      continue
    }
    const cur = st.value?.[0]
    if (cur?.err) throw new Error(`Transaction failed on-chain: ${JSON.stringify(cur.err)}`)
    if (cur?.confirmationStatus === 'confirmed' || cur?.confirmationStatus === 'finalized') {
      slot = cur.slot ?? 0
      confirmed = true
      break
    }
  }
  if (!confirmed) {
    throw new TxConfirmationTimeoutError(txSig)
  }
  return { signature: txSig, slot, wireBytes: wire.byteLength }
}

function readSplTokenAmount(b64: string | undefined): bigint {
  if (!b64) return 0n
  const bytes = fromBase64(b64)
  if (bytes.byteLength < 72) return 0n
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(64, true)
}

async function fetchPoolSnapshot(
  env: Env,
  cluster: Cluster,
  poolId: number,
): Promise<InitializedPoolSnapshot | UninitializedPoolSnapshot> {
  const poolPda = derivePoolPdaSync(poolId, AUDREN_PROGRAM_ID).address
  const rootsPda = deriveRootsPdaSync(poolId, AUDREN_PROGRAM_ID).address
  const vaultAuthPda = deriveVaultAuthPdaSync(poolId, AUDREN_PROGRAM_ID).address
  const wsolVaultAta = deriveAssociatedTokenAddressSync(
    vaultAuthPda,
    WSOL_MINT,
    CLASSIC_TOKEN_PROGRAM_ID,
  ).address
  const allLanePdas: string[] = []
  for (let l = 0; l < NUM_LANES; l++) {
    allLanePdas.push(deriveLanePdaSync(poolId, l, AUDREN_PROGRAM_ID).address)
  }

  // Fetch [poolPda, rootsPda, wsolVaultAta, lane_0..lane_15] atomically in ONE batched RPC call
  const head = await solanaRpc<{
    value: Array<{ data: [string, string]; lamports: number } | null>
  }>(env, cluster, 'getMultipleAccounts', [
    [poolPda, rootsPda, wsolVaultAta, ...allLanePdas],
    { encoding: 'base64', commitment: 'confirmed' },
  ])

  const poolAcc = head.value[0]
  const rootsAcc = head.value[1]
  const wsolVaultLamports = readSplTokenAmount(head.value[2]?.data?.[0]).toString()
  if (!poolAcc?.data?.[0]) {
    return {
      initialized: false,
      cluster,
      protocolVersion: PROTOCOL_VERSION,
      programId: AUDREN_PROGRAM_ID,
      poolId,
      poolPda,
      rootsPda,
      vaultAuthPda,
      wsolVaultAta,
      wsolVaultLamports,
    }
  }

  const pool = decodePoolState(fromBase64(poolAcc.data[0]))
  const [epochInfo, subRent, srRent, memoRent] = await Promise.all([
    solanaRpc<{ epoch: number; absoluteSlot: number }>(env, cluster, 'getEpochInfo', [
      { commitment: 'confirmed' },
    ]),
    solanaRpc<number>(env, cluster, 'getMinimumBalanceForRentExemption', [SUBTREE_PAGE_LEN]),
    solanaRpc<number>(env, cluster, 'getMinimumBalanceForRentExemption', [SUBROOT_PAGE_LEN]),
    solanaRpc<number>(env, cluster, 'getMinimumBalanceForRentExemption', [MEMO_PAGE_LEN]),
  ])
  const currentSlot = epochInfo.absoluteSlot
  const currentEpoch = epochInfo.epoch
  const divCeil = (a: bigint, b: bigint) => (a + b - 1n) / b
  const clampRent = (n: number) => {
    const v = BigInt(n)
    return v > 0n ? v : 1n
  }
  const livePerNote =
    divCeil(clampRent(subRent), BigInt(SUBTREE_LEAVES)) +
    divCeil(clampRent(srRent), BigInt(SUBTREE_LEAVES * SUBROOTS_PER_PAGE)) +
    divCeil(clampRent(memoRent), BigInt(MEMO_NOTES_PER_PAGE))
  const deterministicNoteRentFee =
    pool.noteRentFee === 0n ? 0n : pool.noteRentFee < livePerNote ? pool.noteRentFee : livePerNote

  const lanes = allLanePdas.slice(0, pool.activeLanes).map((pda, idx) => {
    const acc = head.value[3 + idx]
    if (!acc?.data?.[0]) return null
    const hdr = decodeLaneHeader(fromBase64(acc.data[0]))
    return {
      laneId: hdr.laneId,
      lanePda: pda,
      nextLeaf: hdr.nextLeaf.toString(),
      nfCount: hdr.nfCount.toString(),
      currentRootHex: toHex(hdr.currentRoot),
    }
  })

  let rootHistory: PoolRootHistorySummary | null = null
  if (rootsAcc?.data?.[0]) {
    const rh = decodeGlobalRootHistory(fromBase64(rootsAcc.data[0]))
    rootHistory = {
      slotCursor: rh.slotCursor,
      epochCursor: rh.epochCursor,
      slotCount: rh.slotCount,
      epochCount: rh.epochCount,
      latestSlot: rh.latestSlot.toString(),
      stableSlot: rh.stableSlot.toString(),
      stableEpochId: rh.stableEpochId.toString(),
      epochInterval: rh.epochInterval.toString(),
      latestSuperRoot: toHex(rh.latestSuperRoot),
      stableSuperRoot: toHex(rh.stableSuperRoot),
      latestLaneCounts: rh.latestLaneCounts.map((c) => c.toString()),
      stableLaneCounts: rh.stableLaneCounts.map((c) => c.toString()),
    }
  }

  const totalNotes = lanes.reduce((acc, l) => acc + BigInt(l?.nextLeaf ?? '0'), 0n)
  const totalNullifiers = lanes.reduce((acc, l) => acc + BigInt(l?.nfCount ?? '0'), 0n)

  return {
    initialized: true,
    cluster,
    protocolVersion: PROTOCOL_VERSION,
    programId: AUDREN_PROGRAM_ID,
    poolId,
    poolPda,
    rootsPda,
    vaultAuthPda,
    wsolVaultAta,
    wsolVaultLamports,
    paused: pool.paused,
    activeLanes: pool.activeLanes,
    rootEpochInterval: pool.rootEpochInterval.toString(),
    noteRentFee: pool.noteRentFee.toString(),
    deterministicNoteRentFee: deterministicNoteRentFee.toString(),
    nfRentFee: pool.nfRentFee.toString(),
    currentSlot: String(currentSlot),
    currentEpoch: String(currentEpoch),
    totalNotes: totalNotes.toString(),
    totalNullifiers: totalNullifiers.toString(),
    lanes,
    rootHistory,
  }
}

async function handleRpcAccounts(request: Request, env: Env): Promise<Response> {
  const body = await readJsonBodyBounded<{
    cluster?: string
    addresses?: unknown
    commitment?: 'confirmed' | 'finalized'
    dataSlice?: { offset?: unknown; length?: unknown } | null
  }>(request)
  if (!body || !Array.isArray(body.addresses) || body.addresses.length === 0 || body.addresses.length > 200) {
    return jsonResponse({ error: 'addresses must be a non-empty array of <= 200 Solana pubkeys' }, 400)
  }
  const addresses: string[] = []
  for (let i = 0; i < body.addresses.length; i++) {
    const raw = body.addresses[i]
    if (!isValidPubkeyStr(raw)) {
      return jsonResponse({ error: `Invalid Solana pubkey at addresses[${i}]` }, 400)
    }
    addresses.push(raw)
  }
  const cluster = parseCluster(body.cluster)
  const commitment = body.commitment === 'finalized' ? 'finalized' : 'confirmed'
  let dataSlice: { offset: number; length: number } | undefined
  if (body.dataSlice && typeof body.dataSlice === 'object') {
    const offset = Number(body.dataSlice.offset)
    const length = Number(body.dataSlice.length)
    if (
      Number.isInteger(offset) &&
      Number.isInteger(length) &&
      offset >= 0 &&
      length > 0 &&
      length <= 16_384
    ) {
      dataSlice = { offset, length }
    }
  }
  const out: Array<string | null> = []
  const owners: Array<string | null> = []
  const rpcCfg: { encoding: 'base64'; commitment: 'confirmed' | 'finalized'; dataSlice?: { offset: number; length: number } } = {
    encoding: 'base64',
    commitment,
    ...(dataSlice ? { dataSlice } : {}),
  }
  for (let off = 0; off < addresses.length; off += 100) {
    const chunk = addresses.slice(off, off + 100)
    const res = await solanaRpc<{
      value: Array<{ data: [string, string]; owner?: string } | null>
    }>(env, cluster, 'getMultipleAccounts', [chunk, rpcCfg])
    for (let i = 0; i < chunk.length; i++) {
      out.push(res.value[i]?.data?.[0] ?? null)
      owners.push(res.value[i]?.owner ?? null)
    }
  }
  return jsonResponse({ cluster, accounts: out, owners })
}

async function handleWalletBalances(url: URL, env: Env): Promise<Response> {
  const cluster = parseCluster(url.searchParams.get('cluster'))
  const owner = url.searchParams.get('owner')?.trim()
  if (!owner) return jsonResponse({ error: 'owner query parameter is required' }, 400)
  if (!isValidPubkeyStr(owner)) {
    return jsonResponse({ error: 'Invalid owner Solana pubkey' }, 400)
  }

  const [balRes, splRes, t22Res] = await Promise.all([
    solanaRpc<{ value: number }>(env, cluster, 'getBalance', [owner, { commitment: 'confirmed' }]),
    solanaRpc<{
      value: Array<{
        pubkey: string
        account: { data: { parsed: { info: { mint: string; tokenAmount: { amount: string; decimals: number; uiAmountString: string } } } } }
      }>
    }>(env, cluster, 'getTokenAccountsByOwner', [
      owner,
      { programId: CLASSIC_TOKEN_PROGRAM_ID },
      { encoding: 'jsonParsed', commitment: 'confirmed' },
    ]),
    solanaRpc<{
      value: Array<{
        pubkey: string
        account: { data: { parsed: { info: { mint: string; tokenAmount: { amount: string; decimals: number; uiAmountString: string } } } } }
      }>
    }>(env, cluster, 'getTokenAccountsByOwner', [
      owner,
      { programId: TOKEN_2022_PROGRAM_ID },
      { encoding: 'jsonParsed', commitment: 'confirmed' },
    ]),
  ])

  const tokens = [
    ...splRes.value.map((row) => ({
      ata: row.pubkey,
      mint: row.account.data.parsed.info.mint,
      amount: row.account.data.parsed.info.tokenAmount.amount,
      decimals: row.account.data.parsed.info.tokenAmount.decimals,
      uiAmountString: row.account.data.parsed.info.tokenAmount.uiAmountString,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    })),
    ...t22Res.value.map((row) => ({
      ata: row.pubkey,
      mint: row.account.data.parsed.info.mint,
      amount: row.account.data.parsed.info.tokenAmount.amount,
      decimals: row.account.data.parsed.info.tokenAmount.decimals,
      uiAmountString: row.account.data.parsed.info.tokenAmount.uiAmountString,
      tokenProgram: TOKEN_2022_PROGRAM_ID,
    })),
  ].filter((t) => BigInt(t.amount) > 0n)

  return jsonResponse({
    cluster,
    owner,
    solLamports: String(balRes.value ?? 0),
    tokens,
  })
}

async function handleRpcBlockhash(url: URL, env: Env): Promise<Response> {
  const cluster = parseCluster(url.searchParams.get('cluster'))
  const res = await solanaRpc<{ value: { blockhash: string; lastValidBlockHeight: number } }>(
    env,
    cluster,
    'getLatestBlockhash',
    [{ commitment: 'confirmed' }],
  )
  return jsonResponse({
    cluster,
    blockhash: res.value.blockhash,
    lastValidBlockHeight: String(res.value.lastValidBlockHeight),
  })
}

function readU16Le(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(offset, true)
}

function readU32Le(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, true)
}

function popcountMask(mask: number): number {
  let n = 0
  let v = mask >>> 0
  while (v !== 0) {
    n += v & 1
    v >>>= 1
  }
  return n
}

function validateRpcSendAudrenInstruction(data: Uint8Array): string | null {
  if (data.byteLength < 1 || !RPC_SEND_ALLOWED_AUDREN_TAGS.has(data[0]!)) {
    return 'RPC broadcast proxy only accepts Audren OpenPage, Deposit, Transact, or ExecViaEscrow instructions'
  }
  const tag = data[0]!
  if (tag === TAG_OPEN_PAGE) {
    if (data.byteLength !== 15) {
      return `Invalid OpenPage instruction length (${data.byteLength}; expected 15)`
    }
    if (data[1]! > OPEN_PAGE_KIND_NULLIFIER) {
      return `Invalid OpenPage kind (${data[1]!})`
    }
    const poolId = readU32Le(data, 2)
    if (poolId !== 0) {
      return `Only canonical Pool #0 is permitted in OpenPage (got pool_id=${poolId})`
    }
    if (data[6]! >= NUM_LANES) {
      return `Invalid OpenPage lane_id (${data[6]!})`
    }
    return null
  }
  if (tag === TAG_DEPOSIT) {
    if (data.byteLength !== 185) {
      return `Invalid Deposit instruction length (${data.byteLength}; expected 185)`
    }
    const poolId = readU32Le(data, 1)
    if (poolId !== 0) {
      return `Only canonical Pool #0 is permitted in Deposit (got pool_id=${poolId})`
    }
    if (data[5]! >= NUM_LANES) {
      return `Invalid Deposit lane_id (${data[5]!})`
    }
    return null
  }
  if (tag === TAG_TRANSACT) {
    if (data.byteLength < 380) {
      return `Invalid Transact instruction length (${data.byteLength}; minimum 380)`
    }
    const poolId = readU32Le(data, 1)
    if (poolId !== 0) {
      return `Only canonical Pool #0 is permitted in Transact (got pool_id=${poolId})`
    }
    if (data[5]! !== VK_ID_DEFAULT) {
      return `Unsupported Transact vk_id (${data[5]!})`
    }
    if (data[6]! >= NUM_LANES) {
      return `Invalid Transact out_lane_id (${data[6]!})`
    }
    const outputMask = data[7]!
    if (outputMask > 0b111) {
      return `Invalid Transact output_mask (${outputMask})`
    }
    const assetMode = data[8]!
    if (assetMode !== ASSET_MODE_PRIVATE && assetMode !== ASSET_MODE_PUBLIC) {
      return `Invalid Transact asset_mode (${assetMode})`
    }
    const expectedLen = 380 + popcountMask(outputMask) * MEMO_ENTRY_WIRE_LEN
    if (data.byteLength !== expectedLen) {
      return `Invalid Transact instruction length (${data.byteLength}; expected ${expectedLen})`
    }
    return null
  }
  if (tag === TAG_EXEC_VIA_ESCROW) {
    if (data.byteLength < 560) {
      return `Invalid ExecViaEscrow instruction length (${data.byteLength}; minimum 560)`
    }
    const poolId = readU32Le(data, 1)
    if (poolId !== 0) {
      return `Only canonical Pool #0 is permitted in ExecViaEscrow (got pool_id=${poolId})`
    }
    if (data[5]! !== VK_ID_DEFAULT) {
      return `Unsupported ExecViaEscrow vk_id (${data[5]!})`
    }
    if (data[6]! >= NUM_LANES) {
      return `Invalid ExecViaEscrow out_lane_id (${data[6]!})`
    }
    if (data[7]! >= NUM_ESCROW_SHARDS) {
      return `Invalid ExecViaEscrow escrow_shard (${data[7]!})`
    }
    const changeMask = data[8]!
    if (changeMask > 0b11) {
      return `Invalid ExecViaEscrow change_mask (${changeMask})`
    }
    const routerIxDataLen = readU16Le(data, 558)
    const expectedLen = 560 + routerIxDataLen + popcountMask(changeMask) * MEMO_ENTRY_WIRE_LEN
    if (data.byteLength !== expectedLen) {
      return `Invalid ExecViaEscrow instruction length (${data.byteLength}; expected ${expectedLen})`
    }
    return null
  }
  return 'RPC broadcast proxy only accepts Audren OpenPage, Deposit, Transact, or ExecViaEscrow instructions'
}

async function handleRpcSend(request: Request, env: Env): Promise<Response> {
  const rlRes = enforceRateLimit(
    request,
    'rpc_send',
    RATE_MAX_RPC_SEND_PER_MIN,
    RATE_WINDOW_SHORT_MS,
    'RPC broadcast rate limit exceeded; retry shortly',
  )
  if (rlRes) return rlRes

  const body = await readJsonBodyBounded<{
    cluster?: string
    transactionB64?: string
  }>(request)
  if (
    !body?.transactionB64 ||
    typeof body.transactionB64 !== 'string' ||
    body.transactionB64.length > 2_000
  ) {
    return jsonResponse({ error: 'Valid transactionB64 is required' }, 400)
  }
  let wire: Uint8Array
  try {
    wire = fromBase64(body.transactionB64)
  } catch (err) {
    return jsonResponse(
      { error: err instanceof Error ? err.message : 'Malformed Solana transaction wire payload' },
      400,
    )
  }
  if (wire.byteLength > 0 && wire[0] === 0x81) {
    return jsonResponse(
      { error: 'RPC broadcast proxy only accepts legacy or v0 Direct Self-Pay transactions' },
      403,
    )
  }
  let instructions: ParsedWireInstruction[]
  try {
    instructions = extractTransactionInstructions(wire)
  } catch (err) {
    return jsonResponse(
      { error: err instanceof Error ? err.message : 'Malformed Solana transaction wire payload' },
      400,
    )
  }
  let audrenCount = 0
  let ataCreateIdempotentCount = 0
  for (const ix of instructions) {
    if (!RPC_SEND_ALLOWED_COMPANION_PROGRAMS.has(ix.programId)) {
      return jsonResponse(
        { error: `Disallowed companion program in RPC broadcast proxy: ${ix.programId}` },
        403,
      )
    }
    if (ix.programId === ASSOCIATED_TOKEN_PROGRAM_ID) {
      if (ix.data.byteLength !== 1 || ix.data[0] !== 1) {
        return jsonResponse(
          { error: 'Only Associated Token Program CreateIdempotent instructions are permitted' },
          403,
        )
      }
      ataCreateIdempotentCount += 1
    } else if (ix.programId === AUDREN_PROGRAM_ID) {
      const audrenErr = validateRpcSendAudrenInstruction(ix.data)
      if (audrenErr) {
        return jsonResponse({ error: audrenErr }, 403)
      }
      audrenCount += 1
    }
  }
  if (ataCreateIdempotentCount > 3 || (audrenCount === 0 && ataCreateIdempotentCount < 1)) {
    return jsonResponse(
      {
        error:
          'RPC broadcast proxy only accepts Audren transactions or 1..3 idempotent ATA setup transactions',
      },
      403,
    )
  }

  const cluster = parseCluster(body.cluster)
  const signature = await solanaRpc<string>(env, cluster, 'sendTransaction', [
    body.transactionB64,
    { encoding: 'base64', preflightCommitment: 'confirmed', maxRetries: 3 },
  ])
  let slot = 0
  let confirmed = false
  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 800))
    let st: {
      value: Array<{ confirmationStatus?: string | null; err?: unknown; slot?: number } | null>
    }
    try {
      st = await solanaRpc<{
        value: Array<{ confirmationStatus?: string | null; err?: unknown; slot?: number } | null>
      }>(env, cluster, 'getSignatureStatuses', [[signature]])
    } catch {
      continue
    }
    const cur = st.value?.[0]
    if (cur?.err) return jsonResponse({ error: `On-chain error: ${JSON.stringify(cur.err)}`, signature }, 400)
    if (cur?.confirmationStatus === 'confirmed' || cur?.confirmationStatus === 'finalized') {
      slot = cur.slot ?? 0
      confirmed = true
      break
    }
  }
  if (!confirmed) {
    return jsonResponse(
      { error: 'Transaction confirmation timed out', signature, timedOut: true },
      504,
    )
  }
  return jsonResponse({ cluster, signature, slot })
}

function normalizeGatewayCard(mint: string, card: GatewayTokenCard): ResolvedTokenInfo {
  const flagged = Array.isArray(card.trust?.flags) && card.trust!.flags!.length > 0
  const tier = typeof card.trust?.tier === 'number' ? card.trust.tier : null
  return {
    mint,
    symbol: !flagged && card.symbol?.trim() ? card.symbol.trim() : shortMint(mint),
    name: !flagged && card.name?.trim() ? card.name.trim() : 'Solana Token',
    decimals: typeof card.decimals === 'number' ? card.decimals : null,
    tokenProgram: card.tokenProgram === 'token-2022' ? TOKEN_2022_PROGRAM_ID : CLASSIC_TOKEN_PROGRAM_ID,
    logoUrl: null,
    priceUsd: typeof card.price?.mid === 'number' && card.price.mid > 0 ? card.price.mid : null,
    liquidityUsd: typeof card.liquidityUsd === 'number' && card.liquidityUsd > 0 ? card.liquidityUsd : null,
    verified: !flagged && tier !== null && tier <= 2,
    flagged,
  }
}

function normalizeJupiterToken(tok: JupiterTokenV2): ResolvedTokenInfo {
  const flagged = tok.audit?.isSus === true
  const symbol = !flagged && tok.symbol?.trim() ? tok.symbol.trim() : shortMint(tok.id)
  return {
    mint: tok.id,
    symbol,
    name: !flagged && tok.name?.trim() ? tok.name.trim() : 'Solana Token',
    decimals: typeof tok.decimals === 'number' ? tok.decimals : null,
    tokenProgram: tok.tokenProgram === TOKEN_2022_PROGRAM_ID ? TOKEN_2022_PROGRAM_ID : CLASSIC_TOKEN_PROGRAM_ID,
    logoUrl: null,
    priceUsd: typeof tok.usdPrice === 'number' && tok.usdPrice > 0 ? tok.usdPrice : null,
    liquidityUsd: typeof tok.liquidity === 'number' && tok.liquidity > 0 ? tok.liquidity : null,
    verified: !flagged && tok.isVerified === true,
    flagged,
  }
}

async function fetchJupiterTokens(env: Env, pathAndQuery: string): Promise<JupiterTokenV2[]> {
  const apiKey = env.JUPITER_API_KEY?.trim()
  if (!apiKey) return []
  let base: string
  try {
    base = resolveSafeJupiterBaseUrl(env)
  } catch {
    return []
  }
  const headers: Record<string, string> = {
    accept: 'application/json',
    'x-api-key': apiKey,
  }
  try {
    const res = await fetch(`${base}/tokens/v2/${pathAndQuery}`, { headers })
    if (!res.ok) return []
    const data = (await res.json()) as unknown
    return Array.isArray(data) ? (data as JupiterTokenV2[]) : []
  } catch {
    return []
  }
}

function isInitializedSplMint(owner: string, bytes: Uint8Array): boolean {
  if (bytes.byteLength < 82 || bytes[45] !== 1) return false
  if (owner === CLASSIC_TOKEN_PROGRAM_ID) {
    return bytes.byteLength === 82
  }
  if (owner === TOKEN_2022_PROGRAM_ID) {
    if (bytes.byteLength === 82) return true
    if (bytes.byteLength < 166 || bytes[165] !== 1) return false
    for (let i = 82; i < 165; i++) {
      if (bytes[i] !== 0) return false
    }
    return true
  }
  return false
}

async function handleTokensResolve(request: Request, env: Env): Promise<Response> {
  const body = await readJsonBodyBounded<{ mints?: unknown; cluster?: string }>(request)
  const mints = Array.isArray(body?.mints) ? body!.mints.slice(0, 40).filter(isValidPubkeyStr) : []
  const cluster = parseCluster(body?.cluster)
  if (mints.length === 0) return jsonResponse({ tokens: {} })
  const out: Record<string, ResolvedTokenInfo> = {}
  if (env.GATEWAY) {
    try {
      const origin = env.TOKEN_GATEWAY_ORIGIN?.trim() || DEFAULT_GATEWAY_ORIGIN
      const res = await env.GATEWAY.fetch(`${origin}/tokens?mints=${encodeURIComponent(mints.join(','))}`)
      if (res.ok) {
        const map = (await res.json()) as Record<string, GatewayTokenCard>
        for (const [m, card] of Object.entries(map)) out[m] = normalizeGatewayCard(m, card)
      }
    } catch {
      // fall through
    }
  }
  const missingMeta = mints.filter((m) => !out[m])
  if (missingMeta.length > 0) {
    const rows = await fetchJupiterTokens(env, `search?query=${encodeURIComponent(missingMeta.join(','))}`)
    for (const r of rows) out[r.id] = normalizeJupiterToken(r)
  }
  // Always hydrate on-chain decimals & tokenProgram for any mint still missing metadata or decimals
  const needsChain = mints.filter((m) => !out[m] || out[m]!.decimals === null)
  if (needsChain.length > 0) {
    try {
      const res = await solanaRpc<{
        value: Array<{ data: [string, string]; owner: string } | null>
      }>(env, cluster, 'getMultipleAccounts', [needsChain, { encoding: 'base64', commitment: 'confirmed' }])
      needsChain.forEach((mint, idx) => {
        const acc = res.value[idx]
        if (!acc?.data?.[0]) return
        const bytes = fromBase64(acc.data[0])
        if (!isInitializedSplMint(acc.owner, bytes)) return
        const decimals = bytes[44]!
        const tokenProgram = acc.owner === TOKEN_2022_PROGRAM_ID ? TOKEN_2022_PROGRAM_ID : CLASSIC_TOKEN_PROGRAM_ID
        const prev = out[mint]
        out[mint] = prev
          ? { ...prev, decimals: prev.decimals ?? decimals, tokenProgram }
          : {
              mint,
              symbol: shortMint(mint),
              name: 'Solana Token',
              decimals,
              tokenProgram,
              logoUrl: null,
              priceUsd: null,
              liquidityUsd: null,
              verified: false,
              flagged: false,
            }
      })
    } catch {
      // Cluster RPC may be unconfigured in local preview
    }
  }
  return jsonResponse({ tokens: out })
}

async function handleJupiterQuote(request: Request, env: Env): Promise<Response> {
  const body = await readJsonBodyBounded<{
    cluster?: string
    inputMint?: string
    outputMint?: string
    amount?: string
    amountIsNet?: boolean
    slippageBps?: number
    maxAccounts?: number
    onlyDirectRoutes?: boolean
  }>(request)
  if (!body?.inputMint || !body.outputMint || !body.amount) {
    return jsonResponse({ error: 'inputMint, outputMint, and amount are required' }, 400)
  }
  if (!isValidPubkeyStr(body.inputMint) || !isValidPubkeyStr(body.outputMint)) {
    return jsonResponse({ error: 'inputMint and outputMint must be valid 32-byte Solana pubkeys' }, 400)
  }
  if (typeof body.amount !== 'string' || body.amount.length > 20 || !/^\d+$/.test(body.amount) || BigInt(body.amount) <= 0n) {
    return jsonResponse({ error: 'amount must be a positive integer string' }, 400)
  }
  const cluster = parseCluster(body.cluster)
  if (cluster !== 'mainnet') {
    return jsonResponse({ error: 'Jupiter swap routing is available on Mainnet only' }, 400)
  }

  let quoteAmount = body.amount
  let inputTransferFeeBps = 0
  let inputDecimals: number | null = body.inputMint === WSOL_MINT ? 9 : null
  let inputTokenProgram: string | null = body.inputMint === WSOL_MINT ? CLASSIC_TOKEN_PROGRAM_ID : null
  let outputDecimals: number | null = body.outputMint === WSOL_MINT ? 9 : null
  let outputTokenProgram: string | null = body.outputMint === WSOL_MINT ? CLASSIC_TOKEN_PROGRAM_ID : null
  const needInputMeta = body.inputMint !== WSOL_MINT
  const needInputFeeCheck = !body.amountIsNet && body.inputMint !== WSOL_MINT
  const needOutputMeta = body.outputMint !== WSOL_MINT
  if (needInputMeta || needOutputMeta) {
    try {
      const mintsToFetch = [
        ...(needInputMeta ? [body.inputMint] : []),
        ...(needOutputMeta ? [body.outputMint] : []),
      ]
      const [accRes, epochInfo] = await Promise.all([
        solanaRpc<{ value: Array<{ data: [string, string]; owner: string } | null> }>(
          env,
          cluster,
          'getMultipleAccounts',
          [mintsToFetch, { encoding: 'base64', commitment: 'confirmed' }],
        ),
        needInputFeeCheck
          ? solanaRpc<{ epoch: number }>(env, cluster, 'getEpochInfo', [{ commitment: 'confirmed' }])
          : Promise.resolve(null),
      ])
      let inputNetZero = false
      let idx = 0
      if (needInputMeta) {
        const inAcc = accRes.value[idx++]
        if (inAcc?.data?.[0]) {
          const inBytes = fromBase64(inAcc.data[0])
          if (isInitializedSplMint(inAcc.owner, inBytes)) {
            inputDecimals = inBytes[44]!
            inputTokenProgram = inAcc.owner
            if (needInputFeeCheck && inAcc.owner === TOKEN_2022_PROGRAM_ID && epochInfo) {
              const fee = parseToken2022TransferFeeConfig(inBytes, epochInfo.epoch)
              if (fee) {
                const gross = BigInt(body.amount)
                const net = computeToken2022NetAmount(gross, fee)
                if (net <= 0n) {
                  inputNetZero = true
                } else {
                  quoteAmount = net.toString()
                  inputTransferFeeBps = Number(fee.bps)
                }
              }
            }
          }
        }
      }
      if (needOutputMeta) {
        const outAcc = accRes.value[idx]
        if (outAcc?.data?.[0]) {
          const outBytes = fromBase64(outAcc.data[0])
          if (isInitializedSplMint(outAcc.owner, outBytes)) {
            outputDecimals = outBytes[44]!
            outputTokenProgram = outAcc.owner
          }
        }
      }
      if (inputNetZero) {
        return jsonResponse(
          { error: 'Net swap input after Token-2022 TransferFeeConfig must be > 0' },
          400,
          {
            ...(inputDecimals !== null ? { 'x-audren-input-decimals': String(inputDecimals) } : {}),
            ...(inputTokenProgram ? { 'x-audren-input-token-program': inputTokenProgram } : {}),
            ...(outputDecimals !== null ? { 'x-audren-output-decimals': String(outputDecimals) } : {}),
            ...(outputTokenProgram ? { 'x-audren-output-token-program': outputTokenProgram } : {}),
          },
        )
      }
    } catch {
      // Proceed with requested amount if RPC secret is unconfigured in local preview
    }
  }

  const apiKey = env.JUPITER_API_KEY?.trim()
  if (!apiKey) {
    return jsonResponse({ error: 'JUPITER_API_KEY is not configured on this Worker' }, 503)
  }
  let base: string
  try {
    base = resolveSafeJupiterBaseUrl(env)
  } catch (err) {
    return jsonResponse({ error: err instanceof Error ? err.message : 'Invalid JUPITER_API_URL' }, 503)
  }
  const qs = new URLSearchParams({
    inputMint: body.inputMint,
    outputMint: body.outputMint,
    amount: quoteAmount,
    slippageBps: String(body.slippageBps ?? 100),
    maxAccounts: String(Math.min(28, body.maxAccounts ?? 28)),
    excludeDexes: JUPITER_CPI_EXCLUDED_DEXES.join(','),
    ...(body.onlyDirectRoutes ? { onlyDirectRoutes: 'true' } : {}),
  })
  const headers: Record<string, string> = {
    accept: 'application/json',
    'x-api-key': apiKey,
  }
  const res = await fetch(`${base}/swap/v1/quote?${qs.toString()}`, { headers })
  const data = await res.json().catch(() => ({ error: `Jupiter HTTP ${res.status}` }))
  return jsonResponse(data, res.status, {
    'x-audren-net-input-amount': quoteAmount,
    'x-audren-input-transfer-fee-bps': String(inputTransferFeeBps),
    ...(inputDecimals !== null ? { 'x-audren-input-decimals': String(inputDecimals) } : {}),
    ...(inputTokenProgram ? { 'x-audren-input-token-program': inputTokenProgram } : {}),
    ...(outputDecimals !== null ? { 'x-audren-output-decimals': String(outputDecimals) } : {}),
    ...(outputTokenProgram ? { 'x-audren-output-token-program': outputTokenProgram } : {}),
  })
}

async function handleJupiterSwapInstructions(request: Request, env: Env): Promise<Response> {
  const body = await readJsonBodyBounded<{
    cluster?: string
    quoteResponse?: unknown
    poolId?: number
    shardId?: number
    inputMint?: string
    outputMint?: string
    tokenProgramIn?: string
    tokenProgramOut?: string
  }>(request)
  if (!body?.quoteResponse || !body.inputMint || !body.outputMint) {
    return jsonResponse({ error: 'quoteResponse, inputMint, and outputMint are required' }, 400)
  }
  if (!isValidPubkeyStr(body.inputMint) || !isValidPubkeyStr(body.outputMint)) {
    return jsonResponse({ error: 'inputMint and outputMint must be valid 32-byte Solana pubkeys' }, 400)
  }
  const cluster = parseCluster(body.cluster)
  if (cluster !== 'mainnet') {
    return jsonResponse({ error: 'Jupiter swap routing is available on Mainnet only' }, 400)
  }
  const tpIn = body.tokenProgramIn ?? CLASSIC_TOKEN_PROGRAM_ID
  const tpOut = body.tokenProgramOut ?? CLASSIC_TOKEN_PROGRAM_ID
  if (
    !isValidPubkeyStr(tpIn) ||
    !isValidPubkeyStr(tpOut) ||
    (tpIn !== CLASSIC_TOKEN_PROGRAM_ID && tpIn !== TOKEN_2022_PROGRAM_ID) ||
    (tpOut !== CLASSIC_TOKEN_PROGRAM_ID && tpOut !== TOKEN_2022_PROGRAM_ID)
  ) {
    return jsonResponse({ error: 'tokenProgramIn and tokenProgramOut must be SPL Token or Token-2022' }, 400)
  }
  const apiKey = env.JUPITER_API_KEY?.trim()
  if (!apiKey) {
    return jsonResponse({ error: 'JUPITER_API_KEY is not configured on this Worker' }, 503)
  }
  let base: string
  try {
    base = resolveSafeJupiterBaseUrl(env)
  } catch (err) {
    return jsonResponse({ error: err instanceof Error ? err.message : 'Invalid JUPITER_API_URL' }, 503)
  }
  const poolId =
    typeof body.poolId === 'number' && Number.isInteger(body.poolId) && body.poolId >= 0 && body.poolId <= 0xffff_ffff
      ? body.poolId
      : 0
  const shardId =
    (typeof body.shardId === 'number' && Number.isInteger(body.shardId) && body.shardId >= 0 ? body.shardId : 0) %
    NUM_ESCROW_SHARDS
  const escrowPda = deriveEscrowPdaSync(poolId, shardId, AUDREN_PROGRAM_ID).address
  const vaultAuth = deriveVaultAuthPdaSync(poolId, AUDREN_PROGRAM_ID).address
  const escrowInAta = deriveAssociatedTokenAddressSync(escrowPda, body.inputMint, tpIn).address
  const escrowOutAta = deriveAssociatedTokenAddressSync(escrowPda, body.outputMint, tpOut).address
  const vaultInAta = deriveAssociatedTokenAddressSync(vaultAuth, body.inputMint, tpIn).address
  const vaultOutAta = deriveAssociatedTokenAddressSync(vaultAuth, body.outputMint, tpOut).address

  const headers: Record<string, string> = {
    'content-type': 'application/json',
    accept: 'application/json',
    'x-api-key': apiKey,
  }
  const res = await fetch(`${base}/swap/v1/swap-instructions`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      quoteResponse: body.quoteResponse,
      userPublicKey: escrowPda,
      wrapAndUnwrapSol: false,
      useSharedAccounts: false,
      skipUserAccountsRpcCalls: true,
      dynamicComputeUnitLimit: false,
    }),
  })
  const jup = (await res.json().catch(() => ({ error: `Jupiter HTTP ${res.status}` }))) as {
    swapInstruction?: unknown
    addressLookupTableAddresses?: string[]
    computeUnitLimit?: unknown
    error?: string
  }
  if (!res.ok || !jup.swapInstruction) {
    return jsonResponse({ error: jup.error ?? `Jupiter swap-instructions HTTP ${res.status}` }, res.status)
  }
  const computeUnitLimit =
    typeof jup.computeUnitLimit === 'number' &&
    Number.isInteger(jup.computeUnitLimit) &&
    jup.computeUnitLimit > 0
      ? jup.computeUnitLimit
      : undefined

  // Resolve Address Lookup Tables for Direct Self-Pay v0 transaction compression
  const altAddresses = (jup.addressLookupTableAddresses ?? []).slice(0, 8)
  const lookupTables: Record<string, string[]> = {}
  if (altAddresses.length > 0) {
    try {
      const altRes = await solanaRpc<{
        value: Array<{ data: [string, string] } | null>
      }>(env, cluster, 'getMultipleAccounts', [altAddresses, { encoding: 'base64', commitment: 'confirmed' }])
      altAddresses.forEach((altAddr, idx) => {
        const raw = altRes.value[idx]?.data?.[0]
        if (!raw) return
        const bytes = fromBase64(raw)
        if (bytes.byteLength < 56) return
        const addrs: string[] = []
        for (let off = 56; off + 32 <= bytes.byteLength; off += 32) {
          addrs.push(base58Encode(bytes.subarray(off, off + 32)))
        }
        if (addrs.length > 0) lookupTables[altAddr] = addrs
      })
    } catch {
      // Proceed without resolved ALTs if RPC lookup fails
    }
  }

  return jsonResponse({
    provider: 'jupiter',
    escrowPda,
    vaultAuth,
    escrowInAta,
    escrowOutAta,
    vaultInAta,
    vaultOutAta,
    swapInstruction: jup.swapInstruction,
    addressLookupTableAddresses: jup.addressLookupTableAddresses ?? [],
    lookupTables,
    ...(computeUnitLimit !== undefined ? { computeUnitLimit } : {}),
    excludedDexes: JUPITER_CPI_EXCLUDED_DEXES,
  })
}

async function locateConfirmedDepositLeafIndex(
  env: Env,
  poolId: number,
  laneId: number,
  minLeafIndex: bigint,
  commitmentBytes: Uint8Array,
): Promise<bigint | null> {
  const subLeaves = BigInt(SUBTREE_LEAVES)
  const startPageSeq = minLeafIndex / subLeaves
  const startOffset = Number(minLeafIndex % subLeaves)
  const targets: Array<{ pageSeq: bigint; startOffset: number; pda: string }> = [
    {
      pageSeq: startPageSeq,
      startOffset,
      pda: deriveSubtreePdaSync(poolId, laneId, startPageSeq, AUDREN_PROGRAM_ID).address,
    },
    {
      pageSeq: startPageSeq + 1n,
      startOffset: 0,
      pda: deriveSubtreePdaSync(poolId, laneId, startPageSeq + 1n, AUDREN_PROGRAM_ID).address,
    },
  ]
  const pdas = targets.map((t) => t.pda)
  for (let attempt = 0; attempt < 5; attempt++) {
    if (attempt > 0) {
      await new Promise((r) => setTimeout(r, 500))
    }
    try {
      const res = await solanaRpc<{
        value: Array<{ data?: [string, string]; owner?: string } | null>
      }>(env, 'devnet', 'getMultipleAccounts', [
        pdas,
        { encoding: 'base64', commitment: 'confirmed' },
      ])
      for (let i = 0; i < targets.length; i++) {
        const acc = res.value[i]
        if (!acc?.data?.[0] || acc.owner !== AUDREN_PROGRAM_ID) continue
        const page = decodeSubtreePage(fromBase64(acc.data[0]))
        const target = targets[i]!
        if (
          page.poolId !== poolId ||
          page.laneId !== laneId ||
          page.pageSeq !== target.pageSeq
        ) {
          continue
        }
        for (let off = target.startOffset; off < page.count; off++) {
          if (bytesEqual(page.leaves[off]!, commitmentBytes)) {
            return target.pageSeq * subLeaves + BigInt(off)
          }
        }
      }
    } catch {
      // Retry on transient RPC read error or 1-slot replica lag
    }
  }
  return null
}

async function handleDevnetDeposit(request: Request, env: Env): Promise<Response> {
  const demo = decodeDemoKeypair(env)
  if (!demo) return jsonResponse({ error: 'Devnet sandbox faucet is not configured on this Worker' }, 503)
  const rlRes = enforceRateLimit(
    request,
    'devnet_deposit',
    RATE_MAX_REQUESTS,
    RATE_WINDOW_MS,
    'Devnet sandbox rate limit exceeded; retry in a few minutes',
  )
  if (rlRes) return rlRes

  const body = await readJsonBodyBounded<{
    recipientAddress?: string
    amountLamports?: string
    poolId?: number
  }>(request)
  if (
    !body?.recipientAddress ||
    typeof body.recipientAddress !== 'string' ||
    body.recipientAddress.length > 128
  ) {
    return jsonResponse({ error: 'recipientAddress (aud1...) is required' }, 400)
  }
  let parsedAddr: ReturnType<typeof parseAudrenAddress>
  try {
    parsedAddr = parseAudrenAddress(body.recipientAddress)
  } catch {
    return jsonResponse({ error: 'Invalid recipientAddress (aud1...)' }, 400)
  }
  const amountRaw = body.amountLamports ?? '1000000'
  if (typeof amountRaw !== 'string' || amountRaw.length > 20 || !/^\d+$/.test(amountRaw)) {
    return jsonResponse({ error: 'amountLamports must be a positive integer string' }, 400)
  }
  const amount = BigInt(amountRaw)
  if (amount < MIN_DEMO_DEPOSIT_LAMPORTS || amount > MAX_DEMO_DEPOSIT_LAMPORTS) {
    return jsonResponse({ error: 'Devnet sandbox deposit must be 0.0001..0.005 SOL' }, 400)
  }

  if (body.poolId !== undefined && body.poolId !== 0) {
    return jsonResponse({ error: 'Only Devnet Pool #0 is supported' }, 400)
  }
  const poolId = 0
  const snap = await fetchPoolSnapshot(env, 'devnet', poolId)
  if (!snap.initialized) {
    return jsonResponse({ error: 'Devnet Pool #0 is not initialized yet' }, 503)
  }
  if (!snap.rootHistory) {
    return jsonResponse(
      { error: 'Pool #0 GlobalRootHistory migration in progress; retry shortly' },
      503,
    )
  }
  if (snap.paused) {
    return jsonResponse({ error: 'Devnet Pool #0 is currently paused' }, 503)
  }
  if (!Number.isInteger(snap.activeLanes) || snap.activeLanes <= 0 || snap.activeLanes > NUM_LANES) {
    return jsonResponse({ error: 'Devnet Pool #0 has no active lanes yet' }, 503)
  }
  const laneId = pickRandomLaneId(snap.activeLanes)
  const lane = snap.lanes[laneId]
  if (!lane) return jsonResponse({ error: `Lane #${laneId} missing` }, 503)

  const nextLeaf = BigInt(lane.nextLeaf)
  const nfCount = BigInt(lane.nfCount)
  const subPageSeq = nextLeaf / BigInt(SUBTREE_LEAVES)
  const rootPageSeq = subPageSeq / BigInt(SUBROOTS_PER_PAGE)
  const memoPageSeq = nextLeaf / BigInt(MEMO_NOTES_PER_PAGE)

  const vaultAuth = deriveVaultAuthPdaSync(poolId, AUDREN_PROGRAM_ID).address
  const wsolVaultAta = deriveAssociatedTokenAddressSync(
    vaultAuth,
    WSOL_MINT,
    CLASSIC_TOKEN_PROGRAM_ID,
  ).address

  const pageCandidates: Array<{ pageKind: number; pageSeq: bigint; pda: string }> = [
    {
      pageKind: OPEN_PAGE_KIND_SUBTREE,
      pageSeq: subPageSeq,
      pda: deriveSubtreePdaSync(poolId, laneId, subPageSeq, AUDREN_PROGRAM_ID).address,
    },
    {
      pageKind: OPEN_PAGE_KIND_SUBROOT,
      pageSeq: rootPageSeq,
      pda: deriveSubrootPdaSync(poolId, laneId, rootPageSeq, AUDREN_PROGRAM_ID).address,
    },
    {
      pageKind: OPEN_PAGE_KIND_MEMO,
      pageSeq: memoPageSeq,
      pda: deriveMemoPdaSync(poolId, laneId, memoPageSeq, AUDREN_PROGRAM_ID).address,
    },
  ]
  const autoOpenTargets = planAutoOpenPages({
    programId: AUDREN_PROGRAM_ID,
    poolId,
    laneId,
    nextLeaf,
    nfCount,
    numOutputs: 1,
    numNfs: 0,
  })
  const seenCandidatePdas = new Set(pageCandidates.map((c) => c.pda))
  for (const t of autoOpenTargets) {
    if (!seenCandidatePdas.has(t.pda)) {
      seenCandidatePdas.add(t.pda)
      pageCandidates.push(t)
    }
  }

  const reqAccounts = [...pageCandidates.map((c) => c.pda), wsolVaultAta]
  const pageCheck = await solanaRpc<{ value: Array<unknown | null> }>(env, 'devnet', 'getMultipleAccounts', [
    reqAccounts,
    { encoding: 'base64', commitment: 'confirmed' },
  ])

  const ixs: V1Instruction[] = []
  let openPageCount = 0
  let createAtaCount = 0
  for (let i = 0; i < pageCandidates.length; i++) {
    if (!pageCheck.value[i]) {
      const c = pageCandidates[i]!
      ixs.push(
        toV1Ix(
          buildOpenPageInstruction({
            poolId,
            laneId,
            pageKind: c.pageKind,
            pageSeq: c.pageSeq,
            payer: demo.pubkeyStr,
          }),
        ),
      )
      openPageCount += 1
    }
  }
  if (!pageCheck.value[pageCandidates.length]) {
    ixs.push(
      toV1Ix(
        buildCreateAtaIdempotentInstruction({
          payer: demo.pubkeyStr,
          ata: wsolVaultAta,
          owner: vaultAuth,
          mint: WSOL_MINT,
          tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
        }),
      ),
    )
    createAtaCount += 1
  }

  const mintBytes = base58Decode(WSOL_MINT)
  const { tweak, blinding, memo } = encryptNoteMemo(
    parsedAddr.viewPk,
    crypto.getRandomValues(new Uint8Array(32)),
    amount,
    mintBytes,
  )
  const spendPkFr = frFromBeBytesStrict(parsedAddr.spendPk)
  const stealthOwner = deriveStealthOwner(spendPkFr, tweak)
  const assetId = deriveAssetId(mintBytes)
  const commitment = computeNoteCommitment(stealthOwner, assetId, amount, blinding)

  ixs.push(
    toV1Ix(
      buildDepositInstruction({
        poolId,
        laneId,
        subPageSeq,
        rootPageSeq,
        memoPageSeq,
        depositor: demo.pubkeyStr,
        nativeSol: true,
        amount,
        stealthOwner,
        blinding,
        memo,
      }),
    ),
  )

  const cuLimit = recommendedDepositCuLimit({ openPageCount, createAtaCount })
  const tx = await sendAndConfirmV1(env, 'devnet', demo, ixs, cuLimit)

  const commitmentBytes = frToBeBytes(commitment)
  const verifiedLeafIndex = await locateConfirmedDepositLeafIndex(
    env,
    poolId,
    laneId,
    nextLeaf,
    commitmentBytes,
  )
  if (verifiedLeafIndex === null) {
    return jsonResponse(
      {
        error:
          'Confirmed Devnet deposit commitment was not yet visible in SubtreePage; retry shortly',
        signature: tx.signature,
      },
      503,
    )
  }

  return jsonResponse({
    cluster: 'devnet',
    poolId,
    laneId,
    leafIndex: verifiedLeafIndex.toString(),
    amountLamports: amount.toString(),
    commitmentHex: toHex(commitmentBytes),
    memoB64: toBase64(memo),
    ...tx,
  })
}

async function handleDevnetRelaySubmit(request: Request, env: Env): Promise<Response> {
  const demo = decodeDemoKeypair(env)
  if (!demo) return jsonResponse({ error: 'Devnet sandbox relayer is not configured on this Worker' }, 503)
  const rlRes = enforceRateLimit(
    request,
    'devnet_relay',
    RELAY_RATE_MAX,
    RATE_WINDOW_MS,
    'Devnet sandbox relay rate limit exceeded',
  )
  if (rlRes) return rlRes

  const body = await readJsonBodyBounded<{
    cluster?: string
    instructionDataB64?: string
    accounts?: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }>
    computeUnitLimit?: number
  }>(request)
  if (body?.cluster && body.cluster !== 'devnet') {
    return jsonResponse({ error: 'apps/web only relays Devnet sandbox transactions; use relay.audren.xyz for Mainnet' }, 403)
  }
  if (
    !body?.instructionDataB64 ||
    typeof body.instructionDataB64 !== 'string' ||
    body.instructionDataB64.length > 5_400 ||
    !Array.isArray(body.accounts) ||
    body.accounts.length < 12 ||
    body.accounts.length > 62
  ) {
    return jsonResponse({ error: 'Valid instructionDataB64 and 12..62 accounts are required' }, 400)
  }

  let ixData: Uint8Array
  try {
    ixData = fromBase64(body.instructionDataB64)
  } catch {
    return jsonResponse({ error: 'instructionDataB64 must be valid base64' }, 400)
  }
  if (ixData.byteLength < 12) {
    return jsonResponse({ error: `Instruction data too short (${ixData.byteLength} B)` }, 400)
  }
  const tag = ixData[0]
  if (tag !== TAG_TRANSACT) {
    return jsonResponse(
      { error: 'Devnet sandbox relay only accepts private Audren Transact (Tag 5) instructions' },
      403,
    )
  }
  const transactAssetMode = ixData[8]!
  if (transactAssetMode !== ASSET_MODE_PRIVATE) {
    return jsonResponse(
      { error: 'Devnet sandbox relay only accepts private Transact (ASSET_MODE_PRIVATE) instructions' },
      403,
    )
  }
  if (ixData.byteLength < 380 || ixData.byteLength > 4_000) {
    return jsonResponse(
      { error: `Instruction data length out of bounds (${ixData.byteLength}; expected 380..4000)` },
      400,
    )
  }
  const dv = new DataView(ixData.buffer, ixData.byteOffset, ixData.byteLength)
  const poolId = dv.getUint32(1, true)
  if (poolId !== 0) {
    return jsonResponse({ error: `Only canonical Pool #0 is permitted (got pool_id=${poolId})` }, 400)
  }
  if (ixData[5] !== 0) {
    return jsonResponse({ error: `Unsupported vk_id (${ixData[5]}); only vk_id=0 is permitted` }, 400)
  }
  const outLaneId = ixData[6]!
  const maskByte = ixData[7]!
  if ((maskByte & ~0b111) !== 0) {
    return jsonResponse({ error: `Invalid output mask byte (${maskByte})` }, 400)
  }
  const rootRingKind = ixData[10]!
  const rootRingIdx = ixData[11]!
  if (rootRingKind === ROOT_RING_SLOT) {
    if (rootRingIdx >= SLOT_RING_LEN) {
      return jsonResponse({ error: `rootRingIdx ${rootRingIdx} out of bounds for slot ring` }, 400)
    }
  } else if (rootRingKind === ROOT_RING_EPOCH) {
    if (rootRingIdx >= EPOCH_RING_LEN) {
      return jsonResponse({ error: `rootRingIdx ${rootRingIdx} out of bounds for epoch ring` }, 400)
    }
  } else {
    return jsonResponse({ error: `Invalid rootRingKind (${rootRingKind})` }, 400)
  }

  const maskPopcount =
    ((maskByte & 1) !== 0 ? 1 : 0) +
    ((maskByte & 2) !== 0 ? 1 : 0) +
    ((maskByte & 4) !== 0 ? 1 : 0)
  const flagsByte = ixData[9]!
  if ((flagsByte & WITHDRAW_FLAG_UNWRAP_WSOL) !== 0) {
    return jsonResponse({ error: 'WITHDRAW_FLAG_UNWRAP_WSOL is not permitted on private Transact' }, 403)
  }
  if ((flagsByte & ~0x0f) !== 0) {
    return jsonResponse({ error: `Invalid Transact flags byte (${flagsByte})` }, 400)
  }
  const expectedLen = 380 + maskPopcount * 106
  if (ixData.byteLength !== expectedLen) {
    return jsonResponse(
      { error: `Invalid Transact instruction length (${ixData.byteLength} != ${expectedLen})` },
      400,
    )
  }
  const rolloverCount =
    ((flagsByte & 1) !== 0 ? 1 : 0) +
    ((flagsByte & 2) !== 0 ? 1 : 0) +
    ((flagsByte & 4) !== 0 ? 1 : 0)
  const expectedAccounts = 12 + rolloverCount
  if (body.accounts.length !== expectedAccounts) {
    return jsonResponse(
      { error: `Private Transact requires exactly ${expectedAccounts} accounts (got ${body.accounts.length})` },
      400,
    )
  }

  const payerAcc = body.accounts[0]
  if (!payerAcc || payerAcc.pubkey !== demo.pubkeyStr || !payerAcc.isSigner || !payerAcc.isWritable) {
    return jsonResponse(
      { error: `accounts[0] must be Devnet sandbox relayer ${demo.pubkeyStr} (writable signer)` },
      400,
    )
  }
  const pool0Pda = derivePoolPdaSync(0, AUDREN_PROGRAM_ID).address
  if (body.accounts[1]?.pubkey !== pool0Pda) {
    return jsonResponse({ error: `accounts[1] must be canonical Pool #0 (${pool0Pda})` }, 400)
  }
  const rootsPda = deriveRootsPdaSync(0, AUDREN_PROGRAM_ID).address
  if (body.accounts[2]?.pubkey !== rootsPda) {
    return jsonResponse({ error: `accounts[2] must be canonical GlobalRootHistory (${rootsPda})` }, 400)
  }
  const expectRootsWritable = maskByte !== 0
  if (Boolean(body.accounts[2]?.isWritable) !== expectRootsWritable) {
    return jsonResponse(
      {
        error: expectRootsWritable
          ? 'accounts[2] (GlobalRootHistory) must be writable when outputs are created'
          : 'accounts[2] (GlobalRootHistory) must be read-only when output_mask is 0',
      },
      400,
    )
  }

  const snap = await fetchPoolSnapshot(env, 'devnet', 0)
  if (!snap.initialized) {
    return jsonResponse({ error: 'Devnet Pool #0 is not initialized yet' }, 503)
  }
  if (!snap.rootHistory) {
    return jsonResponse(
      { error: 'Pool #0 GlobalRootHistory migration in progress; retry shortly' },
      503,
    )
  }
  if (snap.paused) {
    return jsonResponse(
      { error: 'Devnet Pool #0 is currently paused; private sends are temporarily disabled' },
      503,
    )
  }
  if (outLaneId >= snap.activeLanes) {
    return jsonResponse(
      { error: `out_lane_id ${outLaneId} out of bounds (active_lanes=${snap.activeLanes})` },
      400,
    )
  }
  const expectedLanePda = deriveLanePdaSync(0, outLaneId, AUDREN_PROGRAM_ID).address
  if (body.accounts[5]?.pubkey !== expectedLanePda) {
    return jsonResponse(
      { error: `accounts[5] must match lane #${outLaneId} PDA (${expectedLanePda})` },
      400,
    )
  }

  const decodedAccounts: V1Instruction['accounts'] = []
  for (let i = 0; i < body.accounts.length; i++) {
    const a = body.accounts[i]
    if (!a || typeof a.pubkey !== 'string') {
      return jsonResponse({ error: `Missing pubkey at accounts[${i}]` }, 400)
    }
    if (i > 0 && a.isSigner) {
      return jsonResponse({ error: 'Only accounts[0] (relayer fee payer) may sign a relayed transaction' }, 400)
    }
    if (i !== 2 && a.pubkey === rootsPda) {
      return jsonResponse(
        { error: `GlobalRootHistory (${rootsPda}) is only permitted at accounts[2] (duplicate at accounts[${i}])` },
        400,
      )
    }
    const pk = decodePubkeyChecked(a.pubkey)
    if (!pk) {
      return jsonResponse({ error: `Invalid 32-byte Solana pubkey at accounts[${i}]` }, 400)
    }
    decodedAccounts.push({ pubkey: pk, isSigner: Boolean(a.isSigner), isWritable: Boolean(a.isWritable) })
  }

  // Ensure primary, atomic rollover, and >=90% lookahead pages exist on Devnet Pool #0 outLaneId
  const preIxs: V1Instruction[] = []
  const outputCount = maskPopcount
  const nf1Off = 236
  let hasNf1 = false
  for (let i = 0; i < 32; i++) {
    if (ixData[nf1Off + i] !== 0) {
      hasNf1 = true
      break
    }
  }
  const spentNullifiers = hasNf1 ? 2 : 1
  const laneRes = await solanaRpc<{ value: Array<{ data: [string, string] } | null> }>(
    env,
    'devnet',
    'getMultipleAccounts',
    [[expectedLanePda], { encoding: 'base64', commitment: 'confirmed' }],
  )
  const laneRaw = laneRes.value[0]?.data?.[0]
  if (laneRaw) {
    const hdr = decodeLaneHeader(fromBase64(laneRaw))
    const roll = computePageRollovers({
      leafCount: hdr.nextLeaf,
      outputCount,
      nfCount: hdr.nfCount,
      spentNullifiers,
    })
    const neededPages: Array<{ pageKind: number; pageSeq: bigint; pda: string }> = []
    const seenPagePdas = new Set<string>()
    const addPage = (pageKind: number, pageSeq: bigint, pda: string) => {
      if (seenPagePdas.has(pda)) return
      seenPagePdas.add(pda)
      neededPages.push({ pageKind, pageSeq, pda })
    }
    if (outputCount > 0) {
      addPage(
        OPEN_PAGE_KIND_SUBTREE,
        BigInt(roll.outSubSeq),
        deriveSubtreePdaSync(0, outLaneId, BigInt(roll.outSubSeq), AUDREN_PROGRAM_ID).address,
      )
      addPage(
        OPEN_PAGE_KIND_SUBROOT,
        BigInt(roll.outRootSeq),
        deriveSubrootPdaSync(0, outLaneId, BigInt(roll.outRootSeq), AUDREN_PROGRAM_ID).address,
      )
      addPage(
        OPEN_PAGE_KIND_MEMO,
        BigInt(roll.outMemoSeq),
        deriveMemoPdaSync(0, outLaneId, BigInt(roll.outMemoSeq), AUDREN_PROGRAM_ID).address,
      )
    }
    addPage(
      OPEN_PAGE_KIND_NULLIFIER,
      BigInt(roll.nfPageSeq),
      deriveNfPagePdaSync(0, outLaneId, BigInt(roll.nfPageSeq), AUDREN_PROGRAM_ID).address,
    )
    if (outputCount > 0 && roll.nextSubSeq !== undefined) {
      const s = BigInt(roll.nextSubSeq)
      addPage(OPEN_PAGE_KIND_SUBTREE, s, deriveSubtreePdaSync(0, outLaneId, s, AUDREN_PROGRAM_ID).address)
    }
    if (outputCount > 0 && roll.nextRootSeq !== undefined) {
      const s = BigInt(roll.nextRootSeq)
      addPage(OPEN_PAGE_KIND_SUBROOT, s, deriveSubrootPdaSync(0, outLaneId, s, AUDREN_PROGRAM_ID).address)
    }
    if (outputCount > 0 && roll.nextMemoSeq !== undefined) {
      const s = BigInt(roll.nextMemoSeq)
      addPage(OPEN_PAGE_KIND_MEMO, s, deriveMemoPdaSync(0, outLaneId, s, AUDREN_PROGRAM_ID).address)
    }
    if (roll.nextNfSeq !== undefined) {
      const s = BigInt(roll.nextNfSeq)
      addPage(OPEN_PAGE_KIND_NULLIFIER, s, deriveNfPagePdaSync(0, outLaneId, s, AUDREN_PROGRAM_ID).address)
    }
    for (const target of planAutoOpenPages({
      programId: AUDREN_PROGRAM_ID,
      poolId: 0,
      laneId: outLaneId,
      nextLeaf: hdr.nextLeaf,
      nfCount: hdr.nfCount,
      numOutputs: outputCount,
      numNfs: spentNullifiers,
    })) {
      addPage(target.pageKind, target.pageSeq, target.pda)
    }
    const pageCheck = await solanaRpc<{ value: Array<unknown | null> }>(
      env,
      'devnet',
      'getMultipleAccounts',
      [neededPages.map((p) => p.pda), { encoding: 'base64', commitment: 'confirmed' }],
    )
    for (let i = 0; i < neededPages.length; i++) {
      if (!pageCheck.value[i]) {
        const p = neededPages[i]!
        preIxs.push(
          toV1Ix(
            buildOpenPageInstruction({
              poolId: 0,
              laneId: outLaneId,
              pageKind: p.pageKind,
              pageSeq: p.pageSeq,
              payer: demo.pubkeyStr,
            }),
          ),
        )
      }
    }
  }

  const ix: V1Instruction = {
    programId: base58Decode(AUDREN_PROGRAM_ID),
    accounts: decodedAccounts,
    data: ixData,
  }
  const defaultCu = recommendedTransactCuLimit({
    assetMode: ASSET_MODE_PRIVATE,
    outputMask: maskByte,
    hasTransferHook: false,
    openPageCount: preIxs.length,
  })
  const rawCu =
    typeof body.computeUnitLimit === 'number' && Number.isFinite(body.computeUnitLimit)
      ? Math.trunc(body.computeUnitLimit) + preIxs.length * CU_LIMIT_OPEN_PAGE
      : defaultCu
  const cuLimit = Math.min(1_400_000, Math.max(CU_LIMIT_TRANSACT_FULL_EXIT, rawCu))
  const tx = await sendAndConfirmV1(env, 'devnet', demo, [...preIxs, ix], cuLimit)
  return jsonResponse({ cluster: 'devnet', relayerPubkey: demo.pubkeyStr, ...tx })
}

const worker = {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)

    const canonicalHost = env.CANONICAL_HOST?.trim().toLowerCase()
    if (canonicalHost && url.hostname.toLowerCase() === `www.${canonicalHost}`) {
      url.hostname = canonicalHost
      return Response.redirect(url.toString(), 301)
    }

    try {
      if (url.pathname === '/api/pool' && request.method === 'GET') {
        const rlRes = enforceRateLimit(
          request,
          'api_read',
          RATE_MAX_READ_PER_MIN,
          RATE_WINDOW_SHORT_MS,
          'API read rate limit exceeded; retry shortly',
        )
        if (rlRes) return rlRes
        const cluster = parseCluster(url.searchParams.get('cluster'))
        const poolId = Number(url.searchParams.get('poolId') ?? '0')
        const safePoolId = Number.isInteger(poolId) && poolId >= 0 && poolId <= 0xffff_ffff ? poolId : 0
        return jsonResponse(await fetchPoolSnapshot(env, cluster, safePoolId))
      }

      if (url.pathname === '/api/devnet/pool' && request.method === 'GET') {
        const rlRes = enforceRateLimit(
          request,
          'api_read',
          RATE_MAX_READ_PER_MIN,
          RATE_WINDOW_SHORT_MS,
          'API read rate limit exceeded; retry shortly',
        )
        if (rlRes) return rlRes
        const demo = decodeDemoKeypair(env)
        const snap = await fetchPoolSnapshot(env, 'devnet', 0)
        let faucetLamports: number | null = null
        if (demo && env.DEVNET_RPC_URL?.trim()) {
          const bal = await solanaRpc<{ value: number }>(env, 'devnet', 'getBalance', [
            demo.pubkeyStr,
            { commitment: 'confirmed' },
          ]).catch(() => null)
          faucetLamports = bal?.value ?? null
        }
        return jsonResponse({
          ...snap,
          relayerAvailable: Boolean(demo),
          relayerAddress: demo?.pubkeyStr ?? null,
          faucetLamports,
        })
      }

      if (url.pathname === '/api/devnet/deposit' && request.method === 'POST') {
        return await handleDevnetDeposit(request, env)
      }

      if (url.pathname === '/api/rpc/accounts' && request.method === 'POST') {
        const rlRes = enforceRateLimit(
          request,
          'api_read',
          RATE_MAX_READ_PER_MIN,
          RATE_WINDOW_SHORT_MS,
          'API read rate limit exceeded; retry shortly',
        )
        if (rlRes) return rlRes
        return await handleRpcAccounts(request, env)
      }

      if (url.pathname === '/api/wallet/balances' && request.method === 'GET') {
        const rlRes = enforceRateLimit(
          request,
          'api_read',
          RATE_MAX_READ_PER_MIN,
          RATE_WINDOW_SHORT_MS,
          'API read rate limit exceeded; retry shortly',
        )
        if (rlRes) return rlRes
        return await handleWalletBalances(url, env)
      }

      if (url.pathname === '/api/rpc/blockhash' && request.method === 'GET') {
        const rlRes = enforceRateLimit(
          request,
          'api_read',
          RATE_MAX_READ_PER_MIN,
          RATE_WINDOW_SHORT_MS,
          'API read rate limit exceeded; retry shortly',
        )
        if (rlRes) return rlRes
        return await handleRpcBlockhash(url, env)
      }

      if (url.pathname === '/api/rpc/send' && request.method === 'POST') {
        return await handleRpcSend(request, env)
      }

      if (url.pathname === '/api/tokens/resolve' && request.method === 'POST') {
        const rlRes = enforceRateLimit(
          request,
          'api_read',
          RATE_MAX_READ_PER_MIN,
          RATE_WINDOW_SHORT_MS,
          'API read rate limit exceeded; retry shortly',
        )
        if (rlRes) return rlRes
        return await handleTokensResolve(request, env)
      }

      if (url.pathname === '/api/jupiter/quote' && request.method === 'POST') {
        const rlRes = enforceRateLimit(
          request,
          'api_jupiter',
          RATE_MAX_JUPITER_PER_MIN,
          RATE_WINDOW_SHORT_MS,
          'Swap quote rate limit exceeded; retry shortly',
        )
        if (rlRes) return rlRes
        return await handleJupiterQuote(request, env)
      }

      if (url.pathname === '/api/jupiter/swap-instructions' && request.method === 'POST') {
        const rlRes = enforceRateLimit(
          request,
          'api_jupiter',
          RATE_MAX_JUPITER_PER_MIN,
          RATE_WINDOW_SHORT_MS,
          'Swap routing rate limit exceeded; retry shortly',
        )
        if (rlRes) return rlRes
        return await handleJupiterSwapInstructions(request, env)
      }

      if (url.pathname === '/api/relay/submit' && request.method === 'POST') {
        return await handleDevnetRelaySubmit(request, env)
      }

      return env.ASSETS.fetch(request)
    } catch (err) {
      if (err instanceof PayloadTooLargeError) {
        return jsonResponse({ error: err.message }, 413)
      }
      if (err instanceof TxConfirmationTimeoutError) {
        return jsonResponse(
          { error: err.message, signature: err.signature, timedOut: true },
          504,
        )
      }
      const rawMsg = err instanceof Error ? err.message : String(err)
      const msg = rawMsg.replace(/https?:\/\/\S+/gi, '[redacted-url]')
      return jsonResponse({ error: msg }, 500)
    }
  },
}

export default worker
