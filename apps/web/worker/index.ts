import { ed25519 } from '@noble/curves/ed25519.js'
import {
  AUDREN_PROGRAM_ID,
  CHECKPOINT_RING_SLOTS,
  CLASSIC_TOKEN_PROGRAM_ID,
  MEMO_NOTES_PER_PAGE,
  MEMO_PAGE_LEN,
  NUM_ESCROW_SHARDS,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_NULLIFIER,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  PROTOCOL_VERSION,
  SUBROOTS_PER_PAGE,
  SUBROOT_PAGE_LEN,
  SUBTREE_LEAVES,
  SUBTREE_PAGE_LEN,
  TAG_EXEC_VIA_ESCROW,
  TAG_TRANSACT,
  TOKEN_2022_PROGRAM_ID,
  WSOL_MINT,
  audrenInstructionToSolana,
  base58Decode,
  base58Encode,
  buildCreateAtaIdempotentInstruction,
  buildDepositInstruction,
  buildOpenPageInstruction,
  buildPublishCheckpointInstruction,
  compileV1Message,
  computeNoteCommitment,
  computePageRollovers,
  computeToken2022NetAmount,
  decodeLaneHeader,
  decodePoolState,
  decodeRootCheckpoint,
  deriveAssetId,
  deriveAssociatedTokenAddressSync,
  deriveCheckpointPdaSync,
  deriveEscrowPdaSync,
  deriveLanePdaSync,
  deriveMemoPdaSync,
  deriveNfPagePdaSync,
  derivePoolPdaSync,
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
const RATE_WINDOW_MS = 10 * 60 * 1000
const RATE_MAX_REQUESTS = 8
const RELAY_RATE_MAX = 8

const RPC_SEND_ALLOWED_COMPANION_PROGRAMS = new Set<string>([
  AUDREN_PROGRAM_ID,
  'ComputeBudget111111111111111111111111111111',
  '11111111111111111111111111111111',
  CLASSIC_TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL',
  'AddressLookupTab1e1111111111111111111111111',
])

class TxConfirmationTimeoutError extends Error {
  readonly signature: string
  constructor(signature: string) {
    super('Transaction confirmation timed out')
    this.name = 'TxConfirmationTimeoutError'
    this.signature = signature
  }
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

/**
 * Decode a signed Solana legacy, v0 (`0x80`), or v1 (`0x81`) wire transaction and return
 * the ordered list of top-level instruction program IDs.
 */
function extractTransactionProgramIds(wire: Uint8Array): string[] {
  if (wire.byteLength < 42 || wire.byteLength > 4_096) {
    throw new Error(`Invalid transaction byte length (${wire.byteLength})`)
  }
  const programIds: string[] = []

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
    let payloadBytes = 0
    for (let i = 0; i < numInstructions; i++) {
      const programIdx = wire[off]!
      const numAccs = wire[off + 1]!
      const dataLen = dv.getUint16(off + 2, true)
      if (programIdx === 0 || programIdx >= numAddresses) {
        throw new Error('Invalid v1 instruction program index')
      }
      programIds.push(keys[programIdx]!)
      payloadBytes += numAccs + dataLen
      off += 4
    }
    if (off + payloadBytes + numReqSigs * 64 !== wire.byteLength) {
      throw new Error('Malformed v1 transaction payload or signature length')
    }
    return programIds
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
    programIds.push(staticKeys[programIdx]!)
    const [accLen, afterAccLen] = readShortVec(wire, off)
    off = afterAccLen + accLen
    if (off > wire.byteLength) throw new Error('Truncated instruction account indices')
    const [dataLen, afterDataLen] = readShortVec(wire, off)
    off = afterDataLen + dataLen
    if (off > wire.byteLength) throw new Error('Truncated instruction data')
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
  return programIds
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
  const host = parsed.hostname.toLowerCase()
  if (
    host === 'localhost' ||
    host === '127.0.0.1' ||
    host === '::1' ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host)
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

interface InitializedPoolSnapshot {
  initialized: true
  cluster: Cluster
  protocolVersion: number
  programId: string
  poolId: number
  poolPda: string
  vaultAuthPda: string
  wsolVaultAta: string
  wsolVaultLamports: string
  paused: boolean
  activeLanes: number
  ckptInterval: string
  maxCkptAge: string
  noteRentFee: string
  deterministicNoteRentFee: string
  nfRentFee: string
  currentSlot: string
  currentEpoch: string
  lastPublishedSlot: string | null
  totalNotes: string
  totalNullifiers: string
  lanes: Array<{
    laneId: number
    lanePda: string
    nextLeaf: string
    nfCount: string
    currentRootHex: string
  } | null>
  latestCheckpoint: {
    slotIndex: number
    pda: string
    epochId: string
    publishedSlot: string
    superRootHex: string
    laneCounts: string[]
  } | null
}

interface UninitializedPoolSnapshot {
  initialized: false
  cluster: Cluster
  protocolVersion: number
  programId: string
  poolId: number
  poolPda: string
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

function checkRateLimit(ip: string, bucket: string, maxRequests: number): boolean {
  const key = `${bucket}:${ip}`
  const now = Date.now()
  const cur = RATE_BUCKETS.get(key)
  if (!cur || cur.resetAt <= now) {
    RATE_BUCKETS.set(key, { count: 1, resetAt: now + RATE_WINDOW_MS })
    return true
  }
  if (cur.count >= maxRequests) return false
  cur.count += 1
  return true
}

function getClientIp(request: Request): string {
  return request.headers.get('cf-connecting-ip') ?? request.headers.get('x-forwarded-for') ?? 'local'
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
  const res = await fetch(getRpcUrl(env, cluster), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  })
  if (!res.ok) throw new Error(`Solana RPC ${method} HTTP ${res.status}`)
  const json = (await res.json()) as { result?: T; error?: { message?: string } }
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
    const st = await solanaRpc<{
      value: Array<{ confirmationStatus?: string | null; err?: unknown; slot?: number } | null>
    }>(env, cluster, 'getSignatureStatuses', [[txSig]])
    const cur = st.value[0]
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
  const vaultAuthPda = deriveVaultAuthPdaSync(poolId, AUDREN_PROGRAM_ID).address
  const wsolVaultAta = deriveAssociatedTokenAddressSync(
    vaultAuthPda,
    WSOL_MINT,
    CLASSIC_TOKEN_PROGRAM_ID,
  ).address

  const head = await solanaRpc<{
    value: Array<{ data: [string, string]; lamports: number } | null>
  }>(env, cluster, 'getMultipleAccounts', [
    [poolPda, wsolVaultAta],
    { encoding: 'base64', commitment: 'confirmed' },
  ])

  const wsolVaultLamports = readSplTokenAmount(head.value[1]?.data?.[0]).toString()
  const poolAcc = head.value[0]
  if (!poolAcc?.data?.[0]) {
    return {
      initialized: false,
      cluster,
      protocolVersion: PROTOCOL_VERSION,
      programId: AUDREN_PROGRAM_ID,
      poolId,
      poolPda,
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
  const livePerNote =
    divCeil(BigInt(subRent), BigInt(SUBTREE_LEAVES)) +
    divCeil(BigInt(srRent), BigInt(SUBTREE_LEAVES * SUBROOTS_PER_PAGE)) +
    divCeil(BigInt(memoRent), BigInt(MEMO_NOTES_PER_PAGE))
  const deterministicNoteRentFee =
    pool.noteRentFee === 0n ? 0n : pool.noteRentFee < livePerNote ? pool.noteRentFee : livePerNote

  const curEpoch = BigInt(currentSlot) / (pool.ckptInterval > 0n ? pool.ckptInterval : 1n)

  const lanePdas: string[] = []
  for (let l = 0; l < pool.activeLanes; l++) {
    lanePdas.push(deriveLanePdaSync(poolId, l, AUDREN_PROGRAM_ID).address)
  }

  // Probe the most recent ring slots in the first batch alongside lanes (<= 100 accounts).
  // Scan the remaining ring slots unless a non-expired checkpoint from the probed epoch window was found.
  const orderedSlots: number[] = []
  const orderedPdas: string[] = []
  for (let back = 0; back < CHECKPOINT_RING_SLOTS; back++) {
    const ep = curEpoch >= BigInt(back) ? curEpoch - BigInt(back) : 0n
    const slotIdx = Number(ep % BigInt(CHECKPOINT_RING_SLOTS))
    if (!orderedSlots.includes(slotIdx)) {
      orderedSlots.push(slotIdx)
      orderedPdas.push(deriveCheckpointPdaSync(poolId, slotIdx, AUDREN_PROGRAM_ID).address)
    }
  }
  const firstBatchCount = Math.min(orderedPdas.length, 100 - lanePdas.length)
  const firstCkptPdas = orderedPdas.slice(0, firstBatchCount)

  const laneAndCkpt = await solanaRpc<{
    value: Array<{ data: [string, string]; lamports: number } | null>
  }>(env, cluster, 'getMultipleAccounts', [
    [...lanePdas, ...firstCkptPdas],
    { encoding: 'base64', commitment: 'confirmed' },
  ])

  const lanes = lanePdas.map((pda, idx) => {
    const acc = laneAndCkpt.value[idx]
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

  let latestCheckpoint: InitializedPoolSnapshot['latestCheckpoint'] = null
  let bestSlot = -1n
  let bestEpoch = -1n
  let bestAnySlot = -1n
  const curSlotBig = BigInt(currentSlot)
  const scanCkptAccounts = (pdas: string[], vals: Array<{ data: [string, string] } | null>) => {
    for (let i = 0; i < pdas.length; i++) {
      const acc = vals[i]
      if (!acc?.data?.[0]) continue
      const ck = decodeRootCheckpoint(fromBase64(acc.data[0]))
      if (ck.publishedSlot > bestAnySlot) bestAnySlot = ck.publishedSlot
      const age = curSlotBig >= ck.publishedSlot ? curSlotBig - ck.publishedSlot : 0n
      if (
        age <= pool.maxCkptAge &&
        (ck.publishedSlot > bestSlot || (ck.publishedSlot === bestSlot && ck.epochId > bestEpoch))
      ) {
        bestSlot = ck.publishedSlot
        bestEpoch = ck.epochId
        latestCheckpoint = {
          slotIndex: ck.slotIdx,
          pda: pdas[i]!,
          epochId: ck.epochId.toString(),
          publishedSlot: ck.publishedSlot.toString(),
          superRootHex: toHex(ck.superRoot),
          laneCounts: ck.laneCounts.map((c) => c.toString()),
        }
      }
    }
  }

  scanCkptAccounts(firstCkptPdas, laneAndCkpt.value.slice(lanePdas.length))
  const minRecentEpoch =
    firstBatchCount > 0 && curEpoch >= BigInt(firstBatchCount - 1)
      ? curEpoch - BigInt(firstBatchCount - 1)
      : 0n
  const hasRecentCheckpoint = bestSlot >= 0n && bestEpoch >= minRecentEpoch
  if (!hasRecentCheckpoint && orderedPdas.length > firstBatchCount) {
    const restPdas = orderedPdas.slice(firstBatchCount)
    const chunks: string[][] = []
    for (let off = 0; off < restPdas.length; off += 100) {
      chunks.push(restPdas.slice(off, off + 100))
    }
    const restRes = await Promise.all(
      chunks.map((c) =>
        solanaRpc<{ value: Array<{ data: [string, string] } | null> }>(env, cluster, 'getMultipleAccounts', [
          c,
          { encoding: 'base64', commitment: 'confirmed' },
        ]),
      ),
    )
    for (let ci = 0; ci < chunks.length; ci++) {
      scanCkptAccounts(chunks[ci]!, restRes[ci]!.value)
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
    vaultAuthPda,
    wsolVaultAta,
    wsolVaultLamports,
    paused: pool.paused,
    activeLanes: pool.activeLanes,
    ckptInterval: pool.ckptInterval.toString(),
    maxCkptAge: pool.maxCkptAge.toString(),
    noteRentFee: pool.noteRentFee.toString(),
    deterministicNoteRentFee: deterministicNoteRentFee.toString(),
    nfRentFee: pool.nfRentFee.toString(),
    currentSlot: String(currentSlot),
    currentEpoch: String(currentEpoch),
    lastPublishedSlot: bestAnySlot >= 0n ? bestAnySlot.toString() : null,
    totalNotes: totalNotes.toString(),
    totalNullifiers: totalNullifiers.toString(),
    lanes,
    latestCheckpoint,
  }
}

async function handleRpcAccounts(request: Request, env: Env): Promise<Response> {
  const body = (await request.json().catch(() => null)) as {
    cluster?: string
    addresses?: unknown
    commitment?: 'confirmed' | 'finalized'
    dataSlice?: { offset?: unknown; length?: unknown } | null
  } | null
  if (!body || !Array.isArray(body.addresses) || body.addresses.length === 0 || body.addresses.length > 200) {
    return jsonResponse({ error: 'addresses must be a non-empty array of <= 200 Solana pubkeys' }, 400)
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
  const addresses = body.addresses.map((a) => String(a))
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
  try {
    base58Decode(owner)
  } catch {
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

async function handleRpcSend(request: Request, env: Env): Promise<Response> {
  const body = (await request.json().catch(() => null)) as {
    cluster?: string
    transactionB64?: string
  } | null
  if (
    !body?.transactionB64 ||
    typeof body.transactionB64 !== 'string' ||
    body.transactionB64.length > 6_000
  ) {
    return jsonResponse({ error: 'Valid transactionB64 is required' }, 400)
  }
  let wire: Uint8Array
  let programIds: string[]
  try {
    wire = fromBase64(body.transactionB64)
    programIds = extractTransactionProgramIds(wire)
  } catch (err) {
    return jsonResponse(
      { error: err instanceof Error ? err.message : 'Malformed Solana transaction wire payload' },
      400,
    )
  }
  if (!programIds.includes(AUDREN_PROGRAM_ID)) {
    return jsonResponse(
      { error: 'RPC broadcast proxy only accepts transactions targeting the Audren program' },
      403,
    )
  }
  const disallowed = programIds.find((pid) => !RPC_SEND_ALLOWED_COMPANION_PROGRAMS.has(pid))
  if (disallowed) {
    return jsonResponse(
      { error: `Disallowed companion program in RPC broadcast proxy: ${disallowed}` },
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
    const st = await solanaRpc<{
      value: Array<{ confirmationStatus?: string | null; err?: unknown; slot?: number } | null>
    }>(env, cluster, 'getSignatureStatuses', [[signature]])
    const cur = st.value[0]
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

async function handleTokensResolve(request: Request, env: Env): Promise<Response> {
  const body = (await request.json().catch(() => null)) as { mints?: unknown; cluster?: string } | null
  const mints = Array.isArray(body?.mints) ? body!.mints.map(String).slice(0, 40) : []
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
        if (bytes.byteLength < 45) return
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
  const body = (await request.json().catch(() => null)) as {
    cluster?: string
    inputMint?: string
    outputMint?: string
    amount?: string
    amountIsNet?: boolean
    slippageBps?: number
    maxAccounts?: number
    onlyDirectRoutes?: boolean
  } | null
  if (!body?.inputMint || !body.outputMint || !body.amount) {
    return jsonResponse({ error: 'inputMint, outputMint, and amount are required' }, 400)
  }
  if (!/^\d+$/.test(body.amount) || BigInt(body.amount) <= 0n) {
    return jsonResponse({ error: 'amount must be a positive integer string' }, 400)
  }

  let quoteAmount = body.amount
  let inputTransferFeeBps = 0
  if (!body.amountIsNet && body.inputMint !== WSOL_MINT) {
    try {
      const cluster = parseCluster(body.cluster)
      const [accRes, epochInfo] = await Promise.all([
        solanaRpc<{ value: Array<{ data: [string, string]; owner: string } | null> }>(
          env,
          cluster,
          'getMultipleAccounts',
          [[body.inputMint], { encoding: 'base64', commitment: 'confirmed' }],
        ),
        solanaRpc<{ epoch: number }>(env, cluster, 'getEpochInfo', [{ commitment: 'confirmed' }]),
      ])
      const mintAcc = accRes.value[0]
      if (mintAcc?.owner === TOKEN_2022_PROGRAM_ID && mintAcc.data?.[0]) {
        const fee = parseToken2022TransferFeeConfig(fromBase64(mintAcc.data[0]), epochInfo.epoch)
        if (fee) {
          const gross = BigInt(body.amount)
          const net = computeToken2022NetAmount(gross, fee)
          if (net <= 0n) {
            return jsonResponse(
              { error: 'Net swap input after Token-2022 TransferFeeConfig must be > 0' },
              400,
            )
          }
          quoteAmount = net.toString()
          inputTransferFeeBps = Number(fee.bps)
        }
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
  })
}

async function handleJupiterSwapInstructions(request: Request, env: Env): Promise<Response> {
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
  const body = (await request.json().catch(() => null)) as {
    cluster?: string
    quoteResponse?: unknown
    poolId?: number
    shardId?: number
    inputMint?: string
    outputMint?: string
    tokenProgramIn?: string
    tokenProgramOut?: string
  } | null
  if (!body?.quoteResponse || !body.inputMint || !body.outputMint) {
    return jsonResponse({ error: 'quoteResponse, inputMint, and outputMint are required' }, 400)
  }
  const cluster = parseCluster(body.cluster)
  const poolId = body.poolId ?? 0
  const shardId = (body.shardId ?? 0) % NUM_ESCROW_SHARDS
  const escrowPda = deriveEscrowPdaSync(poolId, shardId, AUDREN_PROGRAM_ID).address
  const vaultAuth = deriveVaultAuthPdaSync(poolId, AUDREN_PROGRAM_ID).address
  const tpIn = body.tokenProgramIn ?? CLASSIC_TOKEN_PROGRAM_ID
  const tpOut = body.tokenProgramOut ?? CLASSIC_TOKEN_PROGRAM_ID
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
    error?: string
  }
  if (!res.ok || !jup.swapInstruction) {
    return jsonResponse({ error: jup.error ?? `Jupiter swap-instructions HTTP ${res.status}` }, res.status)
  }

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
    excludedDexes: JUPITER_CPI_EXCLUDED_DEXES,
  })
}

async function publishDevnetCheckpointWithRetry(
  env: Env,
  demo: { secretSeed: Uint8Array; pubkeyBytes: Uint8Array; pubkeyStr: string },
  poolId: number,
  activeLanes: number,
  ckptInterval: bigint,
): Promise<{ slotIdx: number; signature: string; slot: number; wireBytes: number }> {
  const interval = ckptInterval > 0n ? ckptInterval : 1n
  for (let attempt = 0; attempt < 2; attempt++) {
    let curSlot = await solanaRpc<number>(env, 'devnet', 'getSlot', [{ commitment: 'processed' }])
    if (interval <= 16n && BigInt(curSlot) % interval >= interval - 3n) {
      const waitSlots = Number(interval - (BigInt(curSlot) % interval))
      await new Promise((r) => setTimeout(r, waitSlots * 420 + 150))
      curSlot = await solanaRpc<number>(env, 'devnet', 'getSlot', [{ commitment: 'processed' }])
    }
    const slotIdx = Number((BigInt(curSlot) / interval) % BigInt(CHECKPOINT_RING_SLOTS))
    const ckIx = toV1Ix(
      buildPublishCheckpointInstruction({
        poolId,
        slotIdx,
        activeLanes,
        payer: demo.pubkeyStr,
      }),
    )
    try {
      const ckTx = await sendAndConfirmV1(env, 'devnet', demo, [ckIx], 120_000, {
        preflightCommitment: 'processed',
      })
      return { slotIdx, ...ckTx }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      const isInvalidPda = msg.includes('6001') || msg.includes('0x1771')
      if (attempt === 0 && isInvalidPda) {
        continue
      }
      throw err
    }
  }
  throw new Error('Failed to publish Devnet checkpoint')
}

async function handleDevnetDeposit(request: Request, env: Env): Promise<Response> {
  const demo = decodeDemoKeypair(env)
  if (!demo) return jsonResponse({ error: 'Devnet sandbox faucet is not configured on this Worker' }, 503)
  if (!checkRateLimit(getClientIp(request), 'devnet_deposit', RATE_MAX_REQUESTS)) {
    return jsonResponse({ error: 'Devnet sandbox rate limit exceeded; retry in a few minutes' }, 429)
  }

  const body = (await request.json().catch(() => null)) as {
    recipientAddress?: string
    amountLamports?: string
    poolId?: number
  } | null
  if (!body?.recipientAddress) return jsonResponse({ error: 'recipientAddress (aud1...) is required' }, 400)
  const parsedAddr = parseAudrenAddress(body.recipientAddress)
  const amount = BigInt(body.amountLamports ?? '1000000')
  if (amount < MIN_DEMO_DEPOSIT_LAMPORTS || amount > MAX_DEMO_DEPOSIT_LAMPORTS) {
    return jsonResponse({ error: 'Devnet sandbox deposit must be 0.0001..0.005 SOL' }, 400)
  }

  const poolId = body.poolId ?? 0
  const snap = await fetchPoolSnapshot(env, 'devnet', poolId)
  if (!snap.initialized) {
    return jsonResponse({ error: 'Devnet Pool #0 is not initialized yet' }, 503)
  }
  const laneId = Number(BigInt(snap.totalNotes) % BigInt(snap.activeLanes))
  const lane = snap.lanes[laneId]
  if (!lane) return jsonResponse({ error: `Lane #${laneId} missing` }, 503)

  const nextLeaf = BigInt(lane.nextLeaf)
  const subPageSeq = nextLeaf / BigInt(SUBTREE_LEAVES)
  const rootPageSeq = subPageSeq / BigInt(SUBROOTS_PER_PAGE)
  const memoPageSeq = nextLeaf / BigInt(MEMO_NOTES_PER_PAGE)

  const vaultAuth = deriveVaultAuthPdaSync(poolId, AUDREN_PROGRAM_ID).address
  const wsolVaultAta = deriveAssociatedTokenAddressSync(
    vaultAuth,
    WSOL_MINT,
    CLASSIC_TOKEN_PROGRAM_ID,
  ).address

  const reqAccounts = [
    deriveSubtreePdaSync(poolId, laneId, subPageSeq, AUDREN_PROGRAM_ID).address,
    deriveSubrootPdaSync(poolId, laneId, rootPageSeq, AUDREN_PROGRAM_ID).address,
    deriveMemoPdaSync(poolId, laneId, memoPageSeq, AUDREN_PROGRAM_ID).address,
    wsolVaultAta,
  ]
  const pageCheck = await solanaRpc<{ value: Array<unknown | null> }>(env, 'devnet', 'getMultipleAccounts', [
    reqAccounts,
    { encoding: 'base64', commitment: 'confirmed' },
  ])

  const ixs: V1Instruction[] = []
  if (!pageCheck.value[0]) {
    ixs.push(
      toV1Ix(
        buildOpenPageInstruction({
          poolId,
          laneId,
          pageKind: OPEN_PAGE_KIND_SUBTREE,
          pageSeq: subPageSeq,
          payer: demo.pubkeyStr,
        }),
      ),
    )
  }
  if (!pageCheck.value[1]) {
    ixs.push(
      toV1Ix(
        buildOpenPageInstruction({
          poolId,
          laneId,
          pageKind: OPEN_PAGE_KIND_SUBROOT,
          pageSeq: rootPageSeq,
          payer: demo.pubkeyStr,
        }),
      ),
    )
  }
  if (!pageCheck.value[2]) {
    ixs.push(
      toV1Ix(
        buildOpenPageInstruction({
          poolId,
          laneId,
          pageKind: OPEN_PAGE_KIND_MEMO,
          pageSeq: memoPageSeq,
          payer: demo.pubkeyStr,
        }),
      ),
    )
  }
  if (!pageCheck.value[3]) {
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

  const tx = await sendAndConfirmV1(env, 'devnet', demo, ixs, 250_000)

  // Best-effort RootCheckpoint publish after Deposit settles (never fails the deposit on CheckpointTooSoon)
  let checkpointSignature: string | null = null
  let checkpointSlotIndex: number | null = null
  try {
    const ck = await publishDevnetCheckpointWithRetry(
      env,
      demo,
      poolId,
      snap.activeLanes,
      BigInt(snap.ckptInterval),
    )
    checkpointSignature = ck.signature
    checkpointSlotIndex = ck.slotIdx
  } catch {
    // Checkpoint already published in this epoch or slot advanced; deposit succeeded cleanly.
  }

  return jsonResponse({
    cluster: 'devnet',
    poolId,
    laneId,
    leafIndex: nextLeaf.toString(),
    amountLamports: amount.toString(),
    commitmentHex: toHex(frToBeBytes(commitment)),
    memoB64: toBase64(memo),
    checkpointSignature,
    checkpointSlotIndex,
    ...tx,
  })
}

async function handleDevnetCheckpoint(request: Request, env: Env): Promise<Response> {
  const demo = decodeDemoKeypair(env)
  if (!demo) return jsonResponse({ error: 'Devnet sandbox relayer is not configured on this Worker' }, 503)
  if (!checkRateLimit(getClientIp(request), 'devnet_ckpt', RATE_MAX_REQUESTS)) {
    return jsonResponse({ error: 'Devnet checkpoint rate limit exceeded; retry shortly' }, 429)
  }
  const snap = await fetchPoolSnapshot(env, 'devnet', 0)
  if (!snap.initialized) {
    return jsonResponse({ error: 'Devnet Pool #0 is not initialized yet' }, 503)
  }
  const ck = await publishDevnetCheckpointWithRetry(
    env,
    demo,
    0,
    snap.activeLanes,
    BigInt(snap.ckptInterval),
  )
  return jsonResponse({
    cluster: 'devnet',
    ...ck,
  })
}

async function handleDevnetRelaySubmit(request: Request, env: Env): Promise<Response> {
  const demo = decodeDemoKeypair(env)
  if (!demo) return jsonResponse({ error: 'Devnet sandbox relayer is not configured on this Worker' }, 503)
  if (!checkRateLimit(getClientIp(request), 'devnet_relay', RELAY_RATE_MAX)) {
    return jsonResponse({ error: 'Devnet sandbox relay rate limit exceeded' }, 429)
  }

  const body = (await request.json().catch(() => null)) as {
    cluster?: string
    instructionDataB64?: string
    accounts?: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }>
    computeUnitLimit?: number
  } | null
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
  const tag = ixData[0]
  if (tag !== TAG_TRANSACT && tag !== TAG_EXEC_VIA_ESCROW) {
    return jsonResponse({ error: 'Only Audren Transact (Tag 5) and ExecViaEscrow (Tag 6) may be relayed' }, 400)
  }
  const minDataLen = tag === TAG_TRANSACT ? 378 : 558
  if (ixData.byteLength < minDataLen || ixData.byteLength > 4_000) {
    return jsonResponse(
      { error: `Instruction data length out of bounds (${ixData.byteLength}; expected ${minDataLen}..4000)` },
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
  const maskByte = tag === TAG_TRANSACT ? ixData[7]! : ixData[8]!
  if ((maskByte & ~0b111) !== 0) {
    return jsonResponse({ error: `Invalid output/change mask byte (${maskByte})` }, 400)
  }
  const maskPopcount =
    ((maskByte & 1) !== 0 ? 1 : 0) +
    ((maskByte & 2) !== 0 ? 1 : 0) +
    ((maskByte & 4) !== 0 ? 1 : 0)
  if (tag === TAG_TRANSACT) {
    const assetMode = ixData[8]!
    if (assetMode !== 0 && assetMode !== 1) {
      return jsonResponse({ error: `Invalid Transact asset_mode (${assetMode})` }, 400)
    }
    const expectedLen = 378 + maskPopcount * 106
    if (ixData.byteLength !== expectedLen) {
      return jsonResponse(
        { error: `Invalid Transact instruction length (${ixData.byteLength} != ${expectedLen})` },
        400,
      )
    }
    const minAccounts = assetMode === 1 ? 18 : 12
    if (body.accounts.length < minAccounts) {
      return jsonResponse(
        { error: `Transact requires at least ${minAccounts} accounts (got ${body.accounts.length})` },
        400,
      )
    }
  } else {
    const escrowShard = ixData[7]!
    if (escrowShard >= NUM_ESCROW_SHARDS) {
      return jsonResponse({ error: `Invalid escrow_shard (${escrowShard})` }, 400)
    }
    const routerIxLen = dv.getUint16(556, true)
    const expectedLen = 558 + routerIxLen + maskPopcount * 106
    if (ixData.byteLength !== expectedLen) {
      return jsonResponse(
        { error: `Invalid ExecViaEscrow instruction length (${ixData.byteLength} != ${expectedLen})` },
        400,
      )
    }
    if (body.accounts.length < 23) {
      return jsonResponse(
        { error: `ExecViaEscrow requires at least 23 accounts (got ${body.accounts.length})` },
        400,
      )
    }
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

  const snap = await fetchPoolSnapshot(env, 'devnet', 0)
  if (!snap.initialized) {
    return jsonResponse({ error: 'Devnet Pool #0 is not initialized yet' }, 503)
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
    let pk: Uint8Array
    try {
      pk = base58Decode(a.pubkey)
    } catch {
      return jsonResponse({ error: `Invalid base58 pubkey at accounts[${i}]` }, 400)
    }
    if (pk.byteLength !== 32) {
      return jsonResponse({ error: `accounts[${i}] must be a 32-byte Solana pubkey` }, 400)
    }
    decodedAccounts.push({ pubkey: pk, isSigner: Boolean(a.isSigner), isWritable: Boolean(a.isWritable) })
  }

  // Ensure primary and atomic rollover output/nullifier pages exist on Devnet Pool #0 outLaneId
  const preIxs: V1Instruction[] = []
  const outputCount = tag === TAG_TRANSACT ? maskPopcount : 1 + maskPopcount
  const nf1Off = 234
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
    const neededPages: Array<{ kind: number; seq: bigint; pda: string }> = [
      {
        kind: OPEN_PAGE_KIND_SUBTREE,
        seq: BigInt(roll.outSubSeq),
        pda: deriveSubtreePdaSync(0, outLaneId, BigInt(roll.outSubSeq), AUDREN_PROGRAM_ID).address,
      },
      {
        kind: OPEN_PAGE_KIND_SUBROOT,
        seq: BigInt(roll.outRootSeq),
        pda: deriveSubrootPdaSync(0, outLaneId, BigInt(roll.outRootSeq), AUDREN_PROGRAM_ID).address,
      },
      {
        kind: OPEN_PAGE_KIND_MEMO,
        seq: BigInt(roll.outMemoSeq),
        pda: deriveMemoPdaSync(0, outLaneId, BigInt(roll.outMemoSeq), AUDREN_PROGRAM_ID).address,
      },
      {
        kind: OPEN_PAGE_KIND_NULLIFIER,
        seq: BigInt(roll.nfPageSeq),
        pda: deriveNfPagePdaSync(0, outLaneId, BigInt(roll.nfPageSeq), AUDREN_PROGRAM_ID).address,
      },
    ]
    if (roll.nextSubSeq !== undefined) {
      const s = BigInt(roll.nextSubSeq)
      neededPages.push({
        kind: OPEN_PAGE_KIND_SUBTREE,
        seq: s,
        pda: deriveSubtreePdaSync(0, outLaneId, s, AUDREN_PROGRAM_ID).address,
      })
    }
    if (roll.nextRootSeq !== undefined) {
      const s = BigInt(roll.nextRootSeq)
      neededPages.push({
        kind: OPEN_PAGE_KIND_SUBROOT,
        seq: s,
        pda: deriveSubrootPdaSync(0, outLaneId, s, AUDREN_PROGRAM_ID).address,
      })
    }
    if (roll.nextMemoSeq !== undefined) {
      const s = BigInt(roll.nextMemoSeq)
      neededPages.push({
        kind: OPEN_PAGE_KIND_MEMO,
        seq: s,
        pda: deriveMemoPdaSync(0, outLaneId, s, AUDREN_PROGRAM_ID).address,
      })
    }
    if (roll.nextNfSeq !== undefined) {
      const s = BigInt(roll.nextNfSeq)
      neededPages.push({
        kind: OPEN_PAGE_KIND_NULLIFIER,
        seq: s,
        pda: deriveNfPagePdaSync(0, outLaneId, s, AUDREN_PROGRAM_ID).address,
      })
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
              pageKind: p.kind,
              pageSeq: p.seq,
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
  const rawCu = typeof body.computeUnitLimit === 'number' && Number.isFinite(body.computeUnitLimit)
    ? Math.trunc(body.computeUnitLimit)
    : 400_000
  const cuLimit = Math.min(1_200_000, Math.max(200_000, rawCu))
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
        const cluster = parseCluster(url.searchParams.get('cluster'))
        const poolId = Number(url.searchParams.get('poolId') ?? '0')
        return jsonResponse(await fetchPoolSnapshot(env, cluster, Number.isFinite(poolId) ? poolId : 0))
      }

      if (url.pathname === '/api/devnet/pool' && request.method === 'GET') {
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

      if (url.pathname === '/api/devnet/checkpoint' && request.method === 'POST') {
        return await handleDevnetCheckpoint(request, env)
      }

      if (url.pathname === '/api/rpc/accounts' && request.method === 'POST') {
        return await handleRpcAccounts(request, env)
      }

      if (url.pathname === '/api/wallet/balances' && request.method === 'GET') {
        return await handleWalletBalances(url, env)
      }

      if (url.pathname === '/api/rpc/blockhash' && request.method === 'GET') {
        return await handleRpcBlockhash(url, env)
      }

      if (url.pathname === '/api/rpc/send' && request.method === 'POST') {
        return await handleRpcSend(request, env)
      }

      if (url.pathname === '/api/tokens/resolve' && request.method === 'POST') {
        return await handleTokensResolve(request, env)
      }

      if (url.pathname === '/api/jupiter/quote' && request.method === 'POST') {
        return await handleJupiterQuote(request, env)
      }

      if (url.pathname === '/api/jupiter/swap-instructions' && request.method === 'POST') {
        return await handleJupiterSwapInstructions(request, env)
      }

      if (url.pathname === '/api/relay/submit' && request.method === 'POST') {
        return await handleDevnetRelaySubmit(request, env)
      }

      return env.ASSETS.fetch(request)
    } catch (err) {
      if (err instanceof TxConfirmationTimeoutError) {
        return jsonResponse(
          { error: err.message, signature: err.signature, timedOut: true },
          504,
        )
      }
      const msg = err instanceof Error ? err.message : String(err)
      return jsonResponse({ error: msg }, 500)
    }
  },
}

export default worker
