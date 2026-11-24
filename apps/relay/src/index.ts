import { parseToken2022TransferFeeConfig } from '@audren/sdk'
import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import {
  getAggregatorAdapter,
  listAggregators,
  quoteWithSelection,
} from './aggregators/registry'
import { runAutoRefill } from './cron/refill'
import {
  getRelayerFvk,
  getRelayerSecretsB64,
  getRpcUrl,
  loadPolicyConfig,
  type Env,
} from './env'
import {
  FirewallError,
  MAX_BATCH_INSTRUCTIONS,
  resolveShieldedCm2Fees,
  validateRelaySubmission,
  type ValidatedAudrenInstruction,
} from './policy/firewall'
import { RelayGuard } from './policy/guard-do'
import {
  computeNativeFeeQuote,
  computeSwapFeePlan,
  estimateAtaRentLamports,
  fetchMintPricesUsd,
} from './policy/pricing'
import {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_PUBLIC,
  AUDREN_PROGRAM_ID,
  AUDREN_PROGRAM_ID_STR,
  CU_LIMIT_EXEC_VIA_ESCROW_BASE,
  CU_LIMIT_OPEN_PAGE,
  CU_LIMIT_TRANSACT_FULL_EXIT,
  CU_LIMIT_TRANSACT_PRIVATE,
  CU_LIMIT_TRANSACT_WITHDRAW,
  CU_LIMIT_TRANSACT_WITHDRAW_HOOK,
  NF_PER_PAGE,
  NUM_ESCROW_SHARDS,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  PROTOCOL_VERSION,
  TAG_DEPOSIT,
  TAG_EXEC_VIA_ESCROW,
  TAG_TRANSACT,
  buildOpenPageSolanaIx,
  computeOpenPageIxCuLimit,
  computeToken2022AtaByteLen,
  decodePoolState,
  deriveEscrowPda,
  deriveLanePda,
  deriveLaneRentVaultPda,
  derivePoolPda,
  deriveRootsPda,
  deriveVaultAuthPda,
  deterministicNoteRentFee,
  listProactiveLookaheadCandidates,
  listReferencedPageSlots,
  pickRandomEscrowShard,
  planBatchMissingOpenPageIxs,
  type FetchedAccountMeta,
  type MissingPagePlanResult,
} from './solana/audren'
import {
  CLASSIC_TOKEN_PROGRAM_ID_STR,
  SOLANA_TX_V1_MAX_ACCOUNTS,
  SOLANA_TX_V1_MAX_SIZE,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID_STR,
  WSOL_MINT_STR,
  base58Decode,
  base58Encode,
  buildAndSignV1Transaction,
  buildCreateAtaIdempotentIx,
  bytesEqual,
  decodeRelayerSecret,
  deriveAta,
  isValidPubkey,
  readSplTokenAccountAmount,
  toBase64,
  toHex,
  utf8,
} from './solana/codec'
import {
  TransactionFailedOnChainError,
  applyToken2022FeeHaircut,
  explorerTxUrl,
  fetchBalance,
  fetchCurrentEpoch,
  fetchLiveRentSchedule,
  fetchMintMetas,
  fetchMintMetasWithData,
  fetchMultipleAccounts,
  fetchMultipleAccountsWithContext,
  getCachedLiveRentSchedule,
  resolveLookupTables,
  resolveSwapInputTransferFee,
  resolveVaultOutDelta,
  rpcCall,
  simulateV1Transaction,
  solscanTxUrl,
  waitForConfirmation,
} from './solana/rpc'
import type {
  AggregatorId,
  AggregatorSelection,
  AudrenOpKind,
  Cluster,
  MissingAtaPlan,
  RelaySubmitRequest,
  SolanaInstruction,
} from './types'

export { RelayGuard }

export const RELAY_VERSION = '1.3.0'
export const DEFAULT_EXEC_ROUTER_CU_HEADROOM = 350_000
export const CU_LIMIT_EXEC_TOKEN_2022_EXTRA = 25_000
export const CU_LIMIT_SETUP_ATA_CLASSIC = 30_000
export const CU_LIMIT_SETUP_ATA_TOKEN_2022 = 45_000
export const PROACTIVE_OPEN_PAGE_WIRE_BYTES = 57
export const MAX_RELAY_TX_CU_LIMIT = 1_400_000
export const MAX_RELAY_PRIORITY_FEE_LAMPORTS = 50_000n
export const MAX_UNAUDITED_ROUTER_PRIORITY_FEE_LAMPORTS = 5_000n

/**
 * Compute exact Solana Transaction v1 (`0x81`) serialized wire length and unique account count
 * for a given fee payer and instruction list (assuming inline priorityFee + cuLimit + loadedDataSize
 * config = 16 B, matching `buildAndSignV1Transaction` byte-for-byte).
 */
export function estimateV1TxWireLen(
  feePayerPubkey: Uint8Array,
  instructions: readonly SolanaInstruction[],
): { wireLen: number; uniqueAccountCount: number } {
  const uniqueAccounts = new Set<string>([toHex(feePayerPubkey)])
  let ixBytes = 0
  for (const ix of instructions) {
    uniqueAccounts.add(toHex(ix.programId))
    for (const acc of ix.accounts) {
      uniqueAccounts.add(toHex(acc.pubkey))
    }
    ixBytes += 4 + ix.accounts.length + ix.data.length
  }
  // 1 (prefix) + 3 (header) + 4 (configMask) + 32 (blockhash) + 2 (ixCount, accCount)
  // + 16 (priorityFee 8 + cuLimit 4 + loadedDataSize 4) + 64 (ed25519 signature) = 122 B
  const wireLen = 122 + uniqueAccounts.size * 32 + ixBytes
  return { wireLen, uniqueAccountCount: uniqueAccounts.size }
}

/**
 * Calibrated tight Compute Unit budget per Audren v1.3.0 instruction
 * (matching empirical sBPFv3 LiteSVM measurements with safe worst-case rollover headroom).
 */
export function computeAudrenInstructionCuLimit(
  entry: Pick<ValidatedAudrenInstruction, 'transactMeta' | 'execMeta'>,
): { defaultCu: number; minFloorCu: number } {
  if (entry.transactMeta) {
    if (entry.transactMeta.assetMode === ASSET_MODE_PRIVATE) {
      return {
        defaultCu: CU_LIMIT_TRANSACT_PRIVATE,
        minFloorCu: CU_LIMIT_TRANSACT_PRIVATE,
      }
    }
    const isHookOrToken2022 =
      entry.transactMeta.tokenProgram === TOKEN_2022_PROGRAM_ID_STR ||
      entry.transactMeta.hasTrailingHookAccounts
    if (isHookOrToken2022) {
      return {
        defaultCu: CU_LIMIT_TRANSACT_WITHDRAW_HOOK,
        minFloorCu: CU_LIMIT_TRANSACT_WITHDRAW_HOOK,
      }
    }
    if (entry.transactMeta.outputMask === 0) {
      return {
        defaultCu: CU_LIMIT_TRANSACT_FULL_EXIT,
        minFloorCu: CU_LIMIT_TRANSACT_FULL_EXIT,
      }
    }
    return {
      defaultCu: CU_LIMIT_TRANSACT_WITHDRAW,
      minFloorCu: CU_LIMIT_TRANSACT_WITHDRAW,
    }
  }
  const hasToken2022Leg = Boolean(
    entry.execMeta &&
      (entry.execMeta.tokenProgIn === TOKEN_2022_PROGRAM_ID_STR ||
        entry.execMeta.tokenProgOut === TOKEN_2022_PROGRAM_ID_STR),
  )
  const execBase =
    CU_LIMIT_EXEC_VIA_ESCROW_BASE + (hasToken2022Leg ? CU_LIMIT_EXEC_TOKEN_2022_EXTRA : 0)
  return {
    defaultCu: execBase + DEFAULT_EXEC_ROUTER_CU_HEADROOM,
    minFloorCu: execBase,
  }
}

export type RolloverOpenPagePlanResult =
  | {
      ok: true
      /** Mandatory `OpenPage` instructions for missing primary / exact boundary rollover pages. */
      exactOpenPageIxs: SolanaInstruction[]
      /** Optional `>= 90%` lookahead `OpenPage` instructions (strictly 0 relayer deficit). */
      proactiveOpenPageIxs: SolanaInstruction[]
      /** Unique lane IDs requiring mandatory exact rollover `OpenPage` locks. */
      exactLaneIds: number[]
      /** Optional proactive `OpenPage` instructions grouped by `laneId` for opportunistic locking. */
      proactiveLaneMap: Map<number, SolanaInstruction[]>
      /** Combined deduplicated instruction list (`[...exactOpenPageIxs, ...proactiveOpenPageIxs]`). */
      openPageIxs: SolanaInstruction[]
    }
  | { ok: false; error: string }

/**
 * Plan idempotent `OpenPage` (`Tag 2`) pre-instructions inside the SAME Solana Transaction v1:
 *   1. Exact primary & boundary rollover pages referenced by the submitted instruction(s)
 *      (always prepended when missing, with full `openPageDeficitFloor` accounting).
 *   2. Proactive `>= 90%` lane occupancy lookahead pages (`subRem <= 26`, `memoRem <= 10`,
 *      `nfRem <= 60`, `subrootSlot >= 280`) prepended ONLY when live rent is known
 *      (`allowProactive !== false`), the target page is uninitialized, `LaneRentVault` covers
 *      100% of the rent (`0n` relayer deficit), and account / wire-size (`4,096 B`) / CU
 *      (`1,400,000`) budgets permit.
 */
export async function planRolloverOpenPages(params: {
  rpcUrl: string
  payerB58: string
  entries: Array<{
    poolId: number
    outLaneId: number
    outputCount: number
    nullifierCount: number
    pages: ValidatedAudrenInstruction['pages']
  }>
  fetchedAccounts: Map<string, FetchedAccountMeta | null>
  preAccountInfoMap: Map<string, { bytes: Uint8Array; lamports: number; owner: string } | null>
  rentFloors: {
    laneRentVaultReserveFloor: bigint
    subRentFloor: bigint
    srRentFloor: bigint
    memoRentFloor: bigint
    nfPageRentFloor: bigint
  }
  /** Optional precomputed exact rollover plan (avoids running `planBatchMissingOpenPageIxs` twice). */
  exactPlan?: MissingPagePlanResult
  /** When `false` (e.g., cold isolate with `rentSchedule === null`), skip proactive lookahead completely. */
  allowProactive?: boolean
  /** Optional ceiling on new unique accounts proactive lookahead may add (keeps Solana v1 <= 64 accounts). */
  maxExtraAccounts?: number
  /** Optional ceiling on proactive `OpenPage` count allowed by remaining 4,096 B v1 wire budget (`57 B`/page). */
  maxExtraByBytes?: number
  /** Optional ceiling on proactive `OpenPage` count allowed by remaining 1,400,000 CU budget (`40,000` CU/page). */
  maxExtraByCu?: number
  /** Optional exact remaining CU budget for bump-aware proactive `OpenPage` instructions. */
  maxExtraCu?: number
}): Promise<RolloverOpenPagePlanResult> {
  const {
    rpcUrl,
    payerB58,
    entries,
    fetchedAccounts,
    preAccountInfoMap,
    rentFloors,
    allowProactive = true,
    maxExtraAccounts = Number.POSITIVE_INFINITY,
    maxExtraByBytes = Number.POSITIVE_INFINITY,
    maxExtraByCu = Number.POSITIVE_INFINITY,
    maxExtraCu = Number.POSITIVE_INFINITY,
  } = params
  const exactPlan =
    params.exactPlan ??
    planBatchMissingOpenPageIxs({
      payerB58,
      entries,
      fetchedAccounts,
    })
  if (!exactPlan.ok) return exactPlan

  const exactOpenPageIxs: SolanaInstruction[] = [...exactPlan.openPageIxs]
  const exactLaneIds = [...new Set(exactOpenPageIxs.map((ix) => ix.data[6]!))]
  const proactiveOpenPageIxs: SolanaInstruction[] = []
  const proactiveLaneMap = new Map<number, SolanaInstruction[]>()

  const buildResult = (): RolloverOpenPagePlanResult => ({
    ok: true,
    exactOpenPageIxs,
    proactiveOpenPageIxs,
    exactLaneIds,
    proactiveLaneMap,
    openPageIxs: [...exactOpenPageIxs, ...proactiveOpenPageIxs],
  })

  const maxProactiveCount = allowProactive
    ? Math.max(0, Math.min(maxExtraAccounts, maxExtraByBytes, maxExtraByCu))
    : 0
  if (maxProactiveCount <= 0) {
    return buildResult()
  }

  const alreadyScheduledPdas = new Set<string>(
    exactOpenPageIxs.map((ix) => base58Encode(ix.accounts[4]!.pubkey)),
  )

  const pageRentForKind = (pageKind: number): bigint =>
    pageKind === OPEN_PAGE_KIND_SUBTREE
      ? rentFloors.subRentFloor
      : pageKind === OPEN_PAGE_KIND_SUBROOT
        ? rentFloors.srRentFloor
        : pageKind === OPEN_PAGE_KIND_MEMO
          ? rentFloors.memoRentFloor
          : rentFloors.nfPageRentFloor

  // Compute remaining per-lane available `LaneRentVault` balance after exact rollover subsidies.
  const laneVaultAvail = new Map<string, bigint>()
  const getVaultAvail = (vaultPdaB58: string): bigint => {
    const existing = laneVaultAvail.get(vaultPdaB58)
    if (existing !== undefined) return existing
    const vaultAcc = preAccountInfoMap.get(vaultPdaB58)
    const rawVault = BigInt(vaultAcc?.lamports ?? 0)
    const avail =
      rawVault > rentFloors.laneRentVaultReserveFloor
        ? rawVault - rentFloors.laneRentVaultReserveFloor
        : 0n
    laneVaultAvail.set(vaultPdaB58, avail)
    return avail
  }

  for (const openIx of exactOpenPageIxs) {
    const pagePdaB58 = base58Encode(openIx.accounts[4]!.pubkey)
    const pageAcc = preAccountInfoMap.get(pagePdaB58)
    if (pageAcc?.owner === AUDREN_PROGRAM_ID_STR && pageAcc.bytes.length > 0) continue
    const vaultPdaB58 = base58Encode(openIx.accounts[3]!.pubkey)
    const avail = getVaultAvail(vaultPdaB58)
    const pageRent = pageRentForKind(openIx.data[1]!)
    const existingLamports = BigInt(pageAcc?.lamports ?? 0)
    const needed = pageRent > existingLamports ? pageRent - existingLamports : 0n
    const subsidy = avail < needed ? avail : needed
    laneVaultAvail.set(vaultPdaB58, avail - subsidy)
  }

  const lookaheadCandidates = listProactiveLookaheadCandidates({
    entries,
    fetchedAccounts,
    alreadyScheduledPdas,
  })
  if (lookaheadCandidates.length === 0) {
    return buildResult()
  }

  // Only inspect candidates whose `LaneRentVault` can cover full page rent (0 relayer deficit).
  const affordableCandidates = lookaheadCandidates.filter(
    (cand) => getVaultAvail(cand.laneRentVaultPda) >= pageRentForKind(cand.pageKind),
  )
  if (affordableCandidates.length === 0) {
    return buildResult()
  }

  const unfetchedPdas: string[] = []
  for (const cand of affordableCandidates) {
    if (!preAccountInfoMap.has(cand.pda) && !unfetchedPdas.includes(cand.pda)) {
      unfetchedPdas.push(cand.pda)
    }
  }
  if (unfetchedPdas.length > 0) {
    try {
      const fetched = await fetchMultipleAccounts(rpcUrl, unfetchedPdas, {
        dataSlice: { offset: 0, length: 8 },
      })
      unfetchedPdas.forEach((pda, idx) => {
        const acc = fetched[idx] ?? null
        preAccountInfoMap.set(pda, acc)
        fetchedAccounts.set(pda, acc ? { bytes: acc.bytes, owner: acc.owner } : null)
      })
    } catch {
      // Proactive lookahead is best-effort; never fail a valid relay submission if lookahead check fails.
      return buildResult()
    }
  }

  let usedProactiveCu = 0
  for (const cand of affordableCandidates) {
    if (proactiveOpenPageIxs.length >= maxProactiveCount) break
    const pageAcc = preAccountInfoMap.get(cand.pda)
    if (pageAcc?.owner === AUDREN_PROGRAM_ID_STR && pageAcc.bytes.length > 0) {
      continue
    }
    const pageRent = pageRentForKind(cand.pageKind)
    const needed = pageRent
    const avail = getVaultAvail(cand.laneRentVaultPda)
    if (needed > avail) {
      continue
    }
    const openIx = buildOpenPageSolanaIx({
      payer: payerB58,
      pageKind: cand.pageKind,
      poolId: cand.poolId,
      laneId: cand.laneId,
      pageSeq: cand.pageSeq,
    })
    const pageCu = computeOpenPageIxCuLimit(openIx)
    if (usedProactiveCu + pageCu > maxExtraCu) {
      continue
    }
    usedProactiveCu += pageCu
    laneVaultAvail.set(cand.laneRentVaultPda, avail - needed)
    alreadyScheduledPdas.add(cand.pda)
    proactiveOpenPageIxs.push(openIx)
    const laneBucket = proactiveLaneMap.get(cand.laneId)
    if (laneBucket) {
      laneBucket.push(openIx)
    } else {
      proactiveLaneMap.set(cand.laneId, [openIx])
    }
  }

  return buildResult()
}

// ============================================================================
// HTTP Helpers & CORS
// ============================================================================

export const MAX_POST_BODY_BYTES = 64 * 1024

type BoundedBodyResult =
  | { ok: true; text: string }
  | { ok: false; status: 413; error: string }

async function readBoundedBodyText(
  request: Request,
  maxBytes = MAX_POST_BODY_BYTES,
): Promise<BoundedBodyResult> {
  const clHeader = request.headers.get('content-length')
  if (clHeader !== null) {
    const cl = Number(clHeader)
    if (Number.isFinite(cl) && cl > maxBytes) {
      return {
        ok: false,
        status: 413,
        error: `Request body exceeds ${maxBytes} byte limit`,
      }
    }
  }
  if (!request.body) {
    return { ok: true, text: '' }
  }
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
        await reader.cancel().catch(() => {})
        return {
          ok: false,
          status: 413,
          error: `Request body exceeds ${maxBytes} byte limit`,
        }
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  const merged = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    merged.set(chunk, offset)
    offset += chunk.byteLength
  }
  return { ok: true, text: new TextDecoder().decode(merged) }
}

type BoundedJsonResult<T> =
  | { ok: true; data: T }
  | { ok: false; status: 400 | 413; code?: string; error: string }

async function readBoundedJson<T>(
  request: Request,
  maxBytes = MAX_POST_BODY_BYTES,
): Promise<BoundedJsonResult<T>> {
  const raw = await readBoundedBodyText(request, maxBytes)
  if (!raw.ok) {
    return { ok: false, status: 413, code: 'PAYLOAD_TOO_LARGE', error: raw.error }
  }
  try {
    const parsed = JSON.parse(raw.text) as T
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { ok: false, status: 400, error: 'Invalid JSON body' }
    }
    return { ok: true, data: parsed }
  } catch {
    return { ok: false, status: 400, error: 'Invalid JSON body' }
  }
}

function parseCluster(raw: unknown, fallback: Cluster = 'mainnet'): Cluster {
  return typeof raw === 'string' && raw.trim().toLowerCase() === 'devnet' ? 'devnet' : fallback
}

function parseProvider(raw: unknown): AggregatorSelection | undefined {
  if (typeof raw !== 'string') return undefined
  const v = raw.trim().toLowerCase()
  if (
    v === 'auto' ||
    v === 'jupiter' ||
    v === 'bedrock' ||
    v === 'dflow' ||
    v === 'titan' ||
    v === 'okx'
  ) {
    return v
  }
  return undefined
}

function corsHeaders(request: Request, allowedOrigins: string[]): Record<string, string> {
  const origin = request.headers.get('origin')
  let allowOrigin = '*'
  if (!allowedOrigins.includes('*')) {
    allowOrigin = origin && allowedOrigins.includes(origin) ? origin : allowedOrigins[0] ?? 'https://audren.xyz'
  }
  return {
    'access-control-allow-origin': allowOrigin,
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'content-type, authorization, x-admin-token',
    'access-control-max-age': '86400',
    ...(allowOrigin !== '*' ? { vary: 'Origin' } : {}),
  }
}

function json(
  request: Request,
  allowedOrigins: string[],
  data: unknown,
  status = 200,
  extraHeaders?: Record<string, string>,
): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...corsHeaders(request, allowedOrigins),
      ...extraHeaders,
    },
  })
}

function getGuardStub(env: Env): DurableObjectStub<RelayGuard> {
  const id = env.RELAY_GUARD.idFromName('audren-relay-global-v1')
  return env.RELAY_GUARD.get(id)
}

function extractClientIp(request: Request): string {
  return (
    request.headers.get('cf-connecting-ip') ??
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    'unknown'
  )
}

function pickUniformIndex(length: number): number {
  if (length <= 1) return 0
  const maxUnbiased = Math.floor(0x1_0000_0000 / length) * length
  const buf = new Uint32Array(1)
  for (;;) {
    crypto.getRandomValues(buf)
    const v = buf[0]!
    if (v < maxUnbiased) return v % length
  }
}

function resolveShardId(
  raw: unknown,
): { ok: true; shardId: number } | { ok: false; error: string } {
  if (raw === undefined || raw === null || raw === '') {
    return { ok: true, shardId: pickRandomEscrowShard() }
  }
  const n = Number(raw)
  if (!Number.isFinite(n)) {
    return { ok: false, error: 'shardId must be a finite integer' }
  }
  return { ok: true, shardId: Math.min(Math.max(Math.trunc(n), 0), NUM_ESCROW_SHARDS - 1) }
}

function sanitizeError(err: unknown, fallback: string): string {
  const raw = err instanceof Error ? err.message : typeof err === 'string' ? err : fallback
  return raw.replace(/https?:\/\/\S+/gi, '[redacted-url]').slice(0, 320)
}

/**
 * Return `true` strictly when an ATA account exists AND is owned by `expectedTokenProgram`
 * (defending against pre-funded System-owned dust accounts at uninitialized canonical ATAs).
 */
function isInitializedAta(
  acc: { owner: string } | null | undefined,
  expectedTokenProgram: string,
): boolean {
  return acc !== null && acc !== undefined && acc.owner === expectedTokenProgram
}

interface RelayerSignerEntry {
  secret32: Uint8Array
  pubkey: Uint8Array
  pubkeyB58: string
}

function getRelayerPoolForCluster(env: Env, cluster: Cluster): RelayerSignerEntry[] {
  const secrets = getRelayerSecretsB64(env, cluster)
  const out: RelayerSignerEntry[] = []
  for (const raw of secrets) {
    const secret32 = decodeRelayerSecret(raw)
    if (!secret32) continue
    const pubkey = ed25519.getPublicKey(secret32)
    out.push({ secret32, pubkey, pubkeyB58: base58Encode(pubkey) })
  }
  return out
}

function getRelayerPubkeyForCluster(
  env: Env,
  cluster: Cluster,
  requestedPubkeyB58?: string,
): RelayerSignerEntry | null {
  const pool = getRelayerPoolForCluster(env, cluster)
  if (pool.length === 0) return null
  if (requestedPubkeyB58) {
    const matched = pool.find((r) => r.pubkeyB58 === requestedPubkeyB58)
    if (matched) return matched
  }
  return pool[pickUniformIndex(pool.length)]!
}

// ============================================================================
// Route Handlers
// ============================================================================

async function handleInfo(request: Request, env: Env): Promise<Response> {
  const cfg = loadPolicyConfig(env)
  const url = new URL(request.url)
  const requestedCluster = parseCluster(url.searchParams.get('cluster'), 'mainnet')

  const clusterInfo = async (cluster: Cluster) => {
    const rpcUrl = getRpcUrl(env, cluster)
    const pool = getRelayerPoolForCluster(env, cluster)
    const relayer = pool.length > 0 ? pool[pickUniformIndex(pool.length)]! : null
    const fvkInfo = getRelayerFvk(env, cluster)
    if (!rpcUrl || !relayer) {
      return {
        configured: false,
        relayerPubkey: null as string | null,
        relayerPubkeys: [] as string[],
        relayerShieldedAddress: fvkInfo?.shieldedAddress ?? null,
        balanceSol: null as number | null,
        lowBalance: false,
      }
    }
    let balanceSol: number | null = null
    try {
      balanceSol = Number(((await fetchBalance(rpcUrl, relayer.pubkeyB58)) / 1e9).toFixed(6))
    } catch {
      balanceSol = null
    }
    return {
      configured: true,
      relayerPubkey: relayer.pubkeyB58,
      relayerPubkeys: pool.map((p) => p.pubkeyB58),
      relayerShieldedAddress: fvkInfo?.shieldedAddress ?? null,
      balanceSol,
      lowBalance: balanceSol !== null && balanceSol < cfg.refillMinSol,
    }
  }

  const rpcUrl = getRpcUrl(env, requestedCluster)
  const [mainnet, devnet, rentSchedule] = await Promise.all([
    clusterInfo('mainnet'),
    clusterInfo('devnet'),
    rpcUrl ? fetchLiveRentSchedule(rpcUrl).catch(() => null) : Promise.resolve(null),
  ])

  const activeCluster = requestedCluster === 'devnet' ? devnet : mainnet
  const rootsPda = base58Encode(deriveRootsPda(0).address)
  return json(request, cfg.corsOrigins, {
    ok: true,
    version: RELAY_VERSION,
    protocolVersion: PROTOCOL_VERSION,
    service: 'audren-relay',
    domain: url.host,
    programId: AUDREN_PROGRAM_ID_STR,
    rootsPda,
    cluster: requestedCluster,
    configured: activeCluster.configured,
    relayerPubkey: activeCluster.relayerPubkey,
    relayerPubkeys: activeCluster.relayerPubkeys,
    relayerShieldedAddress: activeCluster.relayerShieldedAddress,
    balanceSol: activeCluster.balanceSol,
    clusters: { mainnet, devnet },
    supportedOperations: {
      transfer: {
        tag: TAG_TRANSACT,
        assetMode: ASSET_MODE_PRIVATE,
        maxBatchSize: MAX_BATCH_INSTRUCTIONS,
        shieldedCm2Fee: activeCluster.relayerShieldedAddress !== null,
        flatFee: true,
        requiresAmount: false,
        defaultNullifiers: 2,
        supportsOmitNf1: true,
        sponsored: true,
      },
      withdraw: {
        tag: TAG_TRANSACT,
        assetMode: ASSET_MODE_PUBLIC,
        defaultNullifiers: 2,
        supportsOmitNf1: true,
        selfPaying: true,
        nativeRelayerFee: true,
        supportsUnwrapWsol: true,
        sponsored: true,
      },
      exec_escrow: {
        tag: TAG_EXEC_VIA_ESCROW,
        defaultNullifiers: 2,
        supportsOmitNf1: true,
        selfPaying: true,
        nativeRelayerFee: true,
        supportsFeeOnOutput: true,
        supportsPreInstructions: true,
        microSwapSubsidy: cfg.allowMicroSwapSubsidy,
      },
      deposit: {
        tags: [TAG_DEPOSIT],
        sponsored: false,
        reason: 'Deposits (Deposit Tag 3) are naturally public; sign directly.',
      },
    },
    allowedPreIxPrograms: Array.from(cfg.allowedPreIxPrograms),
    auditedSwapRouterPrograms: Array.from(cfg.auditedSwapRouterPrograms),
    selfPayFeeMints: Array.from(cfg.selfPayFeeMints),
    aggregators: listAggregators(env, cfg),
    policy: {
      defaultAggregator: cfg.defaultAggregator,
      baseSwapFeeBps: cfg.baseSwapFeeBps,
      maxSelfPayBps: cfg.maxSelfPayBps,
      microSwapFeeBps: cfg.microSwapFeeBps,
      selfPayMarginBps: cfg.selfPayMarginBps,
      sponsoredPerIpPerHour: cfg.sponsoredPerIpPerHour,
      sponsoredPerIpPerDay: cfg.sponsoredPerIpPerDay,
      sponsoredCooldownSec: cfg.sponsoredCooldownSec,
      dailySponsoredBudgetSol: {
        mainnet: Number(cfg.maxDailySponsoredLamports.mainnet) / 1e9,
        devnet: Number(cfg.maxDailySponsoredLamports.devnet) / 1e9,
      },
    },
    rentSchedule: rentSchedule
      ? {
          nullifierRentLamports: rentSchedule.nullifierRentLamports.toString(),
          nfPageRentPerNfLamports: rentSchedule.nfPageRentPerNfLamports.toString(),
          noteRentPerLeafLamports: rentSchedule.pageRentPerNoteLamports.toString(),
          pageRentPerNoteLamports: rentSchedule.pageRentPerNoteLamports.toString(),
          ataRentLamports: rentSchedule.ataRentLamports.toString(),
          swapBaselineLamports: rentSchedule.swapBaselineLamports.toString(),
        }
      : null,
  })
}

async function handleStats(request: Request, env: Env): Promise<Response> {
  const cfg = loadPolicyConfig(env)
  const guard = getGuardStub(env)
  const stats = await guard.stats({
    mainnet: Number(cfg.maxDailySponsoredLamports.mainnet) / 1e9,
    devnet: Number(cfg.maxDailySponsoredLamports.devnet) / 1e9,
  })
  return json(request, cfg.corsOrigins, { ok: true, ...stats })
}

async function handleFeeQuote(request: Request, env: Env): Promise<Response> {
  const cfg = loadPolicyConfig(env)
  const u = new URL(request.url)
  const cluster = parseCluster(u.searchParams.get('cluster'), 'mainnet')
  const rawOp = (u.searchParams.get('op') ?? u.searchParams.get('action') ?? 'withdraw')
    .trim()
    .toLowerCase()
  const op: AudrenOpKind =
    rawOp === 'exec' || rawOp === 'exec_escrow' || rawOp === 'swap'
      ? 'exec_escrow'
      : rawOp === 'transfer'
        ? 'transfer'
        : 'withdraw'
  const rawMint = (u.searchParams.get('mint') ?? WSOL_MINT_STR).trim()
  if (!isValidPubkey(rawMint)) {
    return json(request, cfg.corsOrigins, { error: 'Invalid mint pubkey' }, 400)
  }
  const unwrapWsol = u.searchParams.get('unwrapWsol') === 'true'
  if (op === 'withdraw' && unwrapWsol && rawMint !== WSOL_MINT_STR) {
    return json(
      request,
      cfg.corsOrigins,
      { error: `unwrapWsol is only valid when mint is WSOL (${WSOL_MINT_STR})` },
      400,
    )
  }
  const feeOnOutput = u.searchParams.get('feeOnOutput') === 'true'
  const rawOmitNf1 = u.searchParams.get('omitNf1')?.trim().toLowerCase()
  // Default `omitNf1 = false` (2 nullifiers) across ALL ops (`transfer`, `withdraw`, `exec_escrow`).
  const omitNf1 = rawOmitNf1 === 'true' || rawOmitNf1 === '1'
  const rawOutputs = u.searchParams.get('outputCount')
  const hasChange = u.searchParams.get('hasChange') === 'true'
  const outputCount =
    rawOutputs && /^\d+$/.test(rawOutputs)
      ? Math.min(3, Math.max(0, Number(rawOutputs)))
      : op === 'transfer'
        ? 3
        : op === 'exec_escrow'
          ? hasChange
            ? 2
            : 1
          : hasChange
            ? 1
            : 0
  const rawMissingAtas = u.searchParams.get('missingAtaCount') ?? '0'
  const missingAtaCount = /^\d+$/.test(rawMissingAtas)
    ? Math.min(6, Math.max(0, Number(rawMissingAtas)))
    : 0
  const rawExtraAtaMints = u.searchParams.get('extraAtaMints')
  const extraAtaMints: string[] = []
  if (rawExtraAtaMints !== null && rawExtraAtaMints.trim() !== '') {
    const parts = rawExtraAtaMints.split(',').map((s) => s.trim())
    if (parts.length > 6) {
      return json(
        request,
        cfg.corsOrigins,
        { error: 'extraAtaMints cannot contain more than 6 mint pubkeys' },
        400,
      )
    }
    for (const part of parts) {
      if (!isValidPubkey(part)) {
        return json(
          request,
          cfg.corsOrigins,
          { error: 'extraAtaMints must contain valid base58 mint pubkeys' },
          400,
        )
      }
      extraAtaMints.push(part)
    }
  }

  let shardId: number | undefined
  let escrowPda: string | undefined
  if (op === 'exec_escrow') {
    const resolved = resolveShardId(u.searchParams.get('shardId'))
    if (!resolved.ok) {
      return json(request, cfg.corsOrigins, { error: resolved.error }, 400)
    }
    shardId = resolved.shardId
    escrowPda = base58Encode(deriveEscrowPda(0, shardId).address)
  }

  // For private transfers (`op === 'transfer'`), `amount` is optional and completely ignored
  // (never read, validated, logged, or persisted) — fees are flat per mint.
  let amount: bigint | undefined
  if (op !== 'transfer') {
    const rawAmount = (u.searchParams.get('amount') ?? '0').trim()
    if (!/^\d+$/.test(rawAmount)) {
      return json(request, cfg.corsOrigins, { error: 'amount must be a non-negative integer string' }, 400)
    }
    amount = BigInt(rawAmount)
  }

  const rpcUrl = getRpcUrl(env, cluster)
  const requestedRelayer = u.searchParams.get('relayerPubkey')?.trim() || undefined
  const relayer = getRelayerPubkeyForCluster(env, cluster, requestedRelayer)
  const fvkInfo = getRelayerFvk(env, cluster)
  if (!rpcUrl) {
    return json(request, cfg.corsOrigins, { error: `${cluster} RPC is not configured` }, 503)
  }

  const feeSide = op === 'transfer' ? 'shielded_cm2' : feeOnOutput ? 'out' : 'in'

  try {
    const resolveExtraAtaRent = (
      mintMap: Record<string, Awaited<ReturnType<typeof fetchMintMetasWithData>>[string]>,
      ataRentLamports: bigint,
      feeTokenProgram: string | null,
      feeAtaByteLen: number,
    ): { ok: true; extraAtaRentLamports: bigint | undefined } | { ok: false; error: string } => {
      if (extraAtaMints.length === 0) {
        return { ok: true, extraAtaRentLamports: undefined }
      }
      let total = 0n
      for (const extraMint of extraAtaMints) {
        const extraEntry = mintMap[extraMint]
        const extraMeta = extraEntry?.meta
        if (!extraMeta?.isValidMint) {
          return {
            ok: false,
            error: 'extraAtaMints must contain valid on-chain SPL or Token-2022 mints',
          }
        }
        const extraAtaByteLen =
          extraMeta.safety?.ataByteLen ??
          computeToken2022AtaByteLen(extraMeta.tokenProgram, extraEntry?.rawBytes)
        total += estimateAtaRentLamports(ataRentLamports, extraMeta.tokenProgram, extraAtaByteLen)
      }
      if (missingAtaCount > extraAtaMints.length) {
        const feeAtaRent = estimateAtaRentLamports(ataRentLamports, feeTokenProgram, feeAtaByteLen)
        total += BigInt(missingAtaCount - extraAtaMints.length) * feeAtaRent
      }
      return { ok: true, extraAtaRentLamports: total }
    }

    // Atomic WSOL unwrap withdraw pays relayer fee directly in native SOL lamports to `relayerPubkey`.
    if (op === 'withdraw' && unwrapWsol) {
      const [extraMintMetas, rentSchedule, prices] = await Promise.all([
        extraAtaMints.length > 0
          ? fetchMintMetasWithData(rpcUrl, extraAtaMints)
          : Promise.resolve({} as Awaited<ReturnType<typeof fetchMintMetasWithData>>),
        fetchLiveRentSchedule(rpcUrl),
        cluster === 'mainnet'
          ? fetchMintPricesUsd(env, [WSOL_MINT_STR])
          : Promise.resolve({} as Record<string, number>),
      ])
      const extraRent = resolveExtraAtaRent(extraMintMetas, rentSchedule.ataRentLamports, null, 165)
      if (!extraRent.ok) {
        return json(request, cfg.corsOrigins, { error: extraRent.error }, 400)
      }
      const quote = computeNativeFeeQuote({
        cluster,
        op,
        cfg,
        rentSchedule,
        unwrapWsol: true,
        feeSide,
        feeMint: WSOL_MINT_STR,
        feeTokenProgram: null,
        feeDecimals: 9,
        amount,
        outputCount,
        omitNf1,
        missingAtaCount,
        extraAtaRentLamports: extraRent.extraAtaRentLamports,
        relayerPubkey: relayer?.pubkeyB58 ?? null,
        feeRecipient: relayer?.pubkeyB58 ?? null,
        feeShieldedAddress: fvkInfo?.shieldedAddress ?? null,
        feeRecipientExists: relayer !== null,
        solPriceUsd: prices[WSOL_MINT_STR] ?? null,
        feeTokenPriceUsd: prices[WSOL_MINT_STR] ?? null,
      })
      return json(request, cfg.corsOrigins, quote)
    }

    // Fast path for shielded WSOL transfers (WSOL is canonical Classic SPL with 9 decimals, 1:1 SOL).
    if (op === 'transfer' && rawMint === WSOL_MINT_STR) {
      const [extraMintMetas, rentSchedule, prices] = await Promise.all([
        extraAtaMints.length > 0
          ? fetchMintMetasWithData(rpcUrl, extraAtaMints)
          : Promise.resolve({} as Awaited<ReturnType<typeof fetchMintMetasWithData>>),
        fetchLiveRentSchedule(rpcUrl),
        cluster === 'mainnet'
          ? fetchMintPricesUsd(env, [WSOL_MINT_STR])
          : Promise.resolve({} as Record<string, number>),
      ])
      const extraRent = resolveExtraAtaRent(
        extraMintMetas,
        rentSchedule.ataRentLamports,
        CLASSIC_TOKEN_PROGRAM_ID_STR,
        165,
      )
      if (!extraRent.ok) {
        return json(request, cfg.corsOrigins, { error: extraRent.error }, 400)
      }
      const quote = computeNativeFeeQuote({
        cluster,
        op,
        cfg,
        rentSchedule,
        unwrapWsol: false,
        feeSide,
        feeMint: WSOL_MINT_STR,
        feeTokenProgram: CLASSIC_TOKEN_PROGRAM_ID_STR,
        feeDecimals: 9,
        outputCount,
        omitNf1,
        missingAtaCount,
        extraAtaRentLamports: extraRent.extraAtaRentLamports,
        relayerPubkey: relayer?.pubkeyB58 ?? null,
        feeRecipient: null,
        feeShieldedAddress: fvkInfo?.shieldedAddress ?? null,
        feeRecipientExists: true,
        solPriceUsd: prices[WSOL_MINT_STR] ?? null,
        feeTokenPriceUsd: prices[WSOL_MINT_STR] ?? null,
      })
      return json(request, cfg.corsOrigins, quote)
    }

    const [mintMetasWithData, rentSchedule, prices] = await Promise.all([
      fetchMintMetasWithData(rpcUrl, [rawMint, ...extraAtaMints]),
      fetchLiveRentSchedule(rpcUrl),
      cluster === 'mainnet'
        ? fetchMintPricesUsd(env, [WSOL_MINT_STR, rawMint])
        : Promise.resolve({} as Record<string, number>),
    ])
    const entry = mintMetasWithData[rawMint]
    const meta = entry?.meta
    if (!meta?.isValidMint) {
      return json(
        request,
        cfg.corsOrigins,
        { error: 'mint must be a valid on-chain SPL or Token-2022 mint' },
        400,
      )
    }
    const hasTransferFeeExt = Boolean(meta.safety?.hasTransferFeeConfigExt)
    const feeAtaByteLen =
      meta.safety?.ataByteLen ?? computeToken2022AtaByteLen(meta.tokenProgram, entry?.rawBytes)
    const extraRent = resolveExtraAtaRent(
      mintMetasWithData,
      rentSchedule.ataRentLamports,
      meta.tokenProgram,
      feeAtaByteLen,
    )
    if (!extraRent.ok) {
      return json(request, cfg.corsOrigins, { error: extraRent.error }, 400)
    }
    const needsEpoch =
      meta.tokenProgram === TOKEN_2022_PROGRAM_ID_STR &&
      hasTransferFeeExt &&
      entry?.rawBytes !== null &&
      entry.rawBytes.byteLength > 166
    let feeRecipient: string | null = null
    if (relayer && op !== 'transfer') {
      feeRecipient = base58Encode(
        deriveAta(relayer.pubkey, base58Decode(meta.tokenProgram), base58Decode(rawMint)),
      )
    }
    const [feeAccs, currentEpoch] = await Promise.all([
      feeRecipient
        ? fetchMultipleAccounts(rpcUrl, [feeRecipient], { dataSlice: { offset: 0, length: 0 } })
        : Promise.resolve([]),
      needsEpoch ? fetchCurrentEpoch(rpcUrl) : Promise.resolve(0n),
    ])
    const feeRecipientExists =
      feeRecipient !== null && isInitializedAta(feeAccs[0], meta.tokenProgram)
    const transferFee =
      needsEpoch && entry?.rawBytes
        ? parseToken2022TransferFeeConfig(entry.rawBytes, currentEpoch)
        : null
    const quote = computeNativeFeeQuote({
      cluster,
      op,
      cfg,
      rentSchedule,
      unwrapWsol: false,
      feeSide,
      feeMint: rawMint,
      feeTokenProgram: meta.tokenProgram,
      feeDecimals: meta.decimals,
      amount,
      outputCount,
      omitNf1,
      missingAtaCount,
      extraAtaRentLamports: extraRent.extraAtaRentLamports,
      hasUnsafeSelfPayExt: meta.hasUnsafeSelfPayExt,
      hasTransferFeeExt,
      feeAtaByteLen,
      transferFee,
      relayerPubkey: relayer?.pubkeyB58 ?? null,
      feeRecipient,
      feeShieldedAddress: fvkInfo?.shieldedAddress ?? null,
      feeRecipientExists,
      shardId,
      escrowPda,
      solPriceUsd: prices[WSOL_MINT_STR] ?? null,
      feeTokenPriceUsd: prices[rawMint] ?? null,
    })
    return json(request, cfg.corsOrigins, quote)
  } catch (err) {
    return json(request, cfg.corsOrigins, { error: sanitizeError(err, 'Fee quote failed') }, 502)
  }
}

async function handleSwapQuote(request: Request, env: Env): Promise<Response> {
  const cfg = loadPolicyConfig(env)
  let params: {
    cluster?: string
    provider?: string
    inputMint?: string
    outputMint?: string
    amount?: string
    slippageBps?: number | string
    shardId?: number | string
    relayerPubkey?: string
    onlyDirectRoutes?: boolean | string
    maxAccounts?: number | string
    includeFee?: boolean | string
  }

  if (request.method === 'GET') {
    const u = new URL(request.url)
    params = {
      cluster: u.searchParams.get('cluster') ?? undefined,
      provider: u.searchParams.get('provider') ?? undefined,
      inputMint: u.searchParams.get('inputMint') ?? undefined,
      outputMint: u.searchParams.get('outputMint') ?? undefined,
      amount: u.searchParams.get('amount') ?? undefined,
      slippageBps: u.searchParams.get('slippageBps') ?? undefined,
      shardId: u.searchParams.get('shardId') ?? undefined,
      relayerPubkey: u.searchParams.get('relayerPubkey') ?? undefined,
      onlyDirectRoutes: u.searchParams.get('onlyDirectRoutes') ?? undefined,
      maxAccounts: u.searchParams.get('maxAccounts') ?? undefined,
      includeFee: u.searchParams.get('includeFee') ?? undefined,
    }
  } else {
    const parsed = await readBoundedJson<typeof params>(request)
    if (!parsed.ok) {
      return json(
        request,
        cfg.corsOrigins,
        { error: parsed.error, ...(parsed.code ? { code: parsed.code } : {}) },
        parsed.status,
      )
    }
    params = parsed.data
  }

  if (params.cluster !== undefined && typeof params.cluster !== 'string') {
    return json(request, cfg.corsOrigins, { error: 'cluster must be a string' }, 400)
  }
  const cluster = parseCluster(params.cluster, 'mainnet')
  const rpcUrl = getRpcUrl(env, cluster)
  if (!rpcUrl) {
    return json(request, cfg.corsOrigins, { error: `${cluster} RPC is not configured` }, 503)
  }

  const inputMint = typeof params.inputMint === 'string' ? params.inputMint.trim() : ''
  const outputMint = typeof params.outputMint === 'string' ? params.outputMint.trim() : ''
  const amount =
    typeof params.amount === 'string'
      ? params.amount.trim()
      : typeof params.amount === 'number' && Number.isSafeInteger(params.amount)
        ? String(params.amount)
        : ''
  if (!isValidPubkey(inputMint) || !isValidPubkey(outputMint)) {
    return json(request, cfg.corsOrigins, { error: 'Invalid inputMint or outputMint pubkey' }, 400)
  }
  if (inputMint === outputMint) {
    return json(request, cfg.corsOrigins, { error: 'inputMint and outputMint must differ' }, 400)
  }
  if (!/^\d+$/.test(amount) || BigInt(amount) <= 0n) {
    return json(request, cfg.corsOrigins, { error: 'amount must be a positive integer string' }, 400)
  }

  const rawSlippage = params.slippageBps === undefined ? 100 : Number(params.slippageBps)
  if (!Number.isFinite(rawSlippage)) {
    return json(request, cfg.corsOrigins, { error: 'slippageBps must be a finite number' }, 400)
  }
  const slippageBps = Math.min(Math.max(Math.trunc(rawSlippage), 1), 5000)

  const resolvedShard = resolveShardId(params.shardId)
  if (!resolvedShard.ok) {
    return json(request, cfg.corsOrigins, { error: resolvedShard.error }, 400)
  }
  const shardId = resolvedShard.shardId
  const onlyDirectRoutes =
    params.onlyDirectRoutes === false || params.onlyDirectRoutes === 'false' ? false : true
  let maxAccounts: number | undefined
  if (params.maxAccounts !== undefined && params.maxAccounts !== '') {
    const rawMax = Number(params.maxAccounts)
    if (!Number.isFinite(rawMax)) {
      return json(request, cfg.corsOrigins, { error: 'maxAccounts must be a finite integer' }, 400)
    }
    maxAccounts = Math.min(Math.max(Math.trunc(rawMax), 12), 48)
  }
  // Default `includeFee = false` so swaps pay via atomic protocol-enforced `EXEC_FLAG_FEE_ON_OUTPUT`
  // (`relayerFee > 0n`) rather than unenforced router-side `platformFeeBps`.
  const includeFee = params.includeFee === true || params.includeFee === 'true'

  if (params.provider !== undefined) {
    if (typeof params.provider !== 'string') {
      return json(
        request,
        cfg.corsOrigins,
        { error: 'provider must be a string. Valid: jupiter, bedrock, dflow, titan, okx, auto' },
        400,
      )
    }
    if (params.provider.trim() !== '' && !parseProvider(params.provider)) {
      return json(
        request,
        cfg.corsOrigins,
        { error: `Unknown provider "${params.provider}". Valid: jupiter, bedrock, dflow, titan, okx, auto` },
        400,
      )
    }
  }
  const providerSelection = parseProvider(params.provider)

  if (params.relayerPubkey !== undefined && typeof params.relayerPubkey !== 'string') {
    return json(request, cfg.corsOrigins, { error: 'relayerPubkey must be a string' }, 400)
  }
  const requestedRelayerPubkey =
    typeof params.relayerPubkey === 'string' ? params.relayerPubkey.trim() || undefined : undefined
  const relayer = getRelayerPubkeyForCluster(env, cluster, requestedRelayerPubkey)
  const escrowPubkey = base58Encode(deriveEscrowPda(0, shardId).address)

  try {
    // Dynamically fetch on-chain mint metadata (tokenProgram + decimals + Token-2022 TLV bytes),
    // live rent schedule, and live USD prices — ZERO hardcoded mint lists or rent estimates!
    const [mintMetasWithData, rentSchedule, prices] = await Promise.all([
      fetchMintMetasWithData(rpcUrl, [inputMint, outputMint]),
      fetchLiveRentSchedule(rpcUrl),
      cluster === 'mainnet'
        ? fetchMintPricesUsd(env, [WSOL_MINT_STR, inputMint, outputMint])
        : Promise.resolve({} as Record<string, number>),
    ])

    const inEntry = mintMetasWithData[inputMint]
    const outEntry = mintMetasWithData[outputMint]
    const inMeta = inEntry?.meta
    const outMeta = outEntry?.meta
    if (!inMeta?.isValidMint || !outMeta?.isValidMint) {
      return json(
        request,
        cfg.corsOrigins,
        { error: 'inputMint and outputMint must be valid on-chain SPL or Token-2022 mints' },
        400,
      )
    }

    // Account for Token-2022 TransferFeeConfig on the vault_in_ata -> escrow_in_ata transfer
    // that runs BEFORE the external DEX router CPI inside ExecViaEscrow.
    // Classic SPL and WSOL mints pass through unchanged (`netInputAmount === amount`).
    const inputTransferFee = await resolveSwapInputTransferFee(
      rpcUrl,
      inMeta,
      inEntry?.rawBytes ?? null,
      BigInt(amount),
    )
    const quoteInputAmount = inputTransferFee.netInputAmount
    if (BigInt(quoteInputAmount) <= 0n) {
      return json(
        request,
        cfg.corsOrigins,
        { error: 'amount is too small to cover Token-2022 input transfer fee into escrow' },
        400,
      )
    }

    // Check canonical vault/escrow ATAs AND relayer fee ATA in one batched RPC call so
    // missing vault/escrow ATA rent is accurately priced into `/v1/swap/quote`.
    const vaultAuthBytes = deriveVaultAuthPda(0).address
    const escrowBytes = deriveEscrowPda(0, shardId).address
    const inMintBytes = base58Decode(inputMint)
    const outMintBytes = base58Decode(outputMint)
    const inTpBytes = base58Decode(inMeta.tokenProgram)
    const outTpBytes = base58Decode(outMeta.tokenProgram)
    const vaultInAta = base58Encode(deriveAta(vaultAuthBytes, inTpBytes, inMintBytes))
    const vaultOutAta = base58Encode(deriveAta(vaultAuthBytes, outTpBytes, outMintBytes))
    const escrowInAta = base58Encode(deriveAta(escrowBytes, inTpBytes, inMintBytes))
    const escrowOutAta = base58Encode(deriveAta(escrowBytes, outTpBytes, outMintBytes))

    const relayerFeeAtaB58: string | null = relayer
      ? base58Encode(deriveAta(relayer.pubkey, outTpBytes, outMintBytes))
      : null
    const ataCheckList = [vaultInAta, vaultOutAta, escrowInAta, escrowOutAta]
    if (relayerFeeAtaB58) ataCheckList.push(relayerFeeAtaB58)
    const outHasTransferFeeExt = Boolean(outMeta.safety?.hasTransferFeeConfigExt)
    const inAtaByteLen =
      inMeta.safety?.ataByteLen ?? computeToken2022AtaByteLen(inMeta.tokenProgram, inEntry?.rawBytes)
    const outAtaByteLen =
      outMeta.safety?.ataByteLen ?? computeToken2022AtaByteLen(outMeta.tokenProgram, outEntry?.rawBytes)
    const needsOutEpoch =
      outMeta.tokenProgram === TOKEN_2022_PROGRAM_ID_STR &&
      outHasTransferFeeExt &&
      outEntry?.rawBytes !== null &&
      outEntry.rawBytes.byteLength > 166
    const [ataInfos, outEpoch] = await Promise.all([
      fetchMultipleAccounts(rpcUrl, ataCheckList, {
        dataSlice: { offset: 0, length: 0 },
      }),
      needsOutEpoch ? fetchCurrentEpoch(rpcUrl) : Promise.resolve(0n),
    ])
    const outputTransferFee =
      needsOutEpoch && outEntry?.rawBytes
        ? parseToken2022TransferFeeConfig(outEntry.rawBytes, outEpoch)
        : null
    const vaultInExists = isInitializedAta(ataInfos[0], inMeta.tokenProgram)
    const vaultOutExists = isInitializedAta(ataInfos[1], outMeta.tokenProgram)
    const escrowInExists = isInitializedAta(ataInfos[2], inMeta.tokenProgram)
    const escrowOutExists = isInitializedAta(ataInfos[3], outMeta.tokenProgram)
    const missingInAtaCount = (vaultInExists ? 0 : 1) + (escrowInExists ? 0 : 1)
    const missingOutAtaCount = (vaultOutExists ? 0 : 1) + (escrowOutExists ? 0 : 1)
    const missingVaultEscrowAtaCount = missingInAtaCount + missingOutAtaCount
    const extraAtaRentLamports =
      BigInt(missingInAtaCount) *
        estimateAtaRentLamports(
          rentSchedule.ataRentLamports,
          inMeta.tokenProgram,
          inAtaByteLen,
        ) +
      BigInt(missingOutAtaCount) *
        estimateAtaRentLamports(
          rentSchedule.ataRentLamports,
          outMeta.tokenProgram,
          outAtaByteLen,
        )
    const feeAccountExists =
      relayerFeeAtaB58 !== null && isInitializedAta(ataInfos[4], outMeta.tokenProgram)

    const solPriceUsd = prices[WSOL_MINT_STR] ?? null
    const inPriceUsd = prices[inputMint] ?? null
    const outPriceUsd = prices[outputMint] ?? null

    // Estimate output amount from live USD prices when available so we only make 1 aggregator call
    let preEstimatedOut: bigint | null = null
    if (inPriceUsd && outPriceUsd && inPriceUsd > 0 && outPriceUsd > 0) {
      const inUi = Number(quoteInputAmount) / Math.pow(10, inMeta.decimals)
      const estOutUi = (inUi * inPriceUsd) / outPriceUsd
      if (Number.isFinite(estOutUi) && estOutUi > 0) {
        preEstimatedOut = BigInt(Math.max(1, Math.floor(estOutUi * Math.pow(10, outMeta.decimals))))
      }
    }

    let feePlan = computeSwapFeePlan({
      cfg,
      rentSchedule,
      outputMint,
      outputDecimals: outMeta.decimals,
      estimatedOutAmount: preEstimatedOut ?? 0n,
      solPriceUsd,
      outputTokenPriceUsd: outPriceUsd,
      feeAccount: relayerFeeAtaB58,
      feeAccountExists,
      hasUnsafeSelfPayExt: outMeta.hasUnsafeSelfPayExt,
      outputTokenProgram: outMeta.tokenProgram,
      outputHasTransferFeeExt: outHasTransferFeeExt,
      outputAtaByteLen: outAtaByteLen,
      outputTransferFee,
      extraAtaCount: missingVaultEscrowAtaCount,
      extraAtaRentLamports,
    })

    // If USD prices weren't available before quoting, fetch a baseline quote first to know real outAmount
    let quoteResult: Awaited<ReturnType<typeof quoteWithSelection>>
    if (preEstimatedOut === null) {
      const baseline = await quoteWithSelection(env, cfg, providerSelection, {
        inputMint,
        outputMint,
        amount: quoteInputAmount,
        slippageBps,
        onlyDirectRoutes,
        maxAccounts,
        platformFeeBps: 0,
        escrowPubkey,
      })
      feePlan = computeSwapFeePlan({
        cfg,
        rentSchedule,
        outputMint,
        outputDecimals: outMeta.decimals,
        estimatedOutAmount: BigInt(baseline.winner.outAmount),
        solPriceUsd,
        outputTokenPriceUsd: outPriceUsd,
        feeAccount: relayerFeeAtaB58,
        feeAccountExists,
        hasUnsafeSelfPayExt: outMeta.hasUnsafeSelfPayExt,
        outputTokenProgram: outMeta.tokenProgram,
        outputHasTransferFeeExt: outHasTransferFeeExt,
        outputAtaByteLen: outAtaByteLen,
        outputTransferFee,
        extraAtaCount: missingVaultEscrowAtaCount,
        extraAtaRentLamports,
      })
      if (feePlan.platformFeeBps > 0 && includeFee && relayer) {
        quoteResult = await quoteWithSelection(env, cfg, baseline.winner.provider, {
          inputMint,
          outputMint,
          amount: quoteInputAmount,
          slippageBps,
          onlyDirectRoutes,
          maxAccounts,
          platformFeeBps: feePlan.platformFeeBps,
          relayerOwner: relayer.pubkeyB58,
          relayerFeeAta: feePlan.feeAccount ?? undefined,
          escrowPubkey,
        })
      } else {
        quoteResult = baseline
      }
    } else {
      quoteResult = await quoteWithSelection(env, cfg, providerSelection, {
        inputMint,
        outputMint,
        amount: quoteInputAmount,
        slippageBps,
        onlyDirectRoutes,
        maxAccounts,
        platformFeeBps: includeFee ? feePlan.platformFeeBps : 0,
        relayerOwner: includeFee ? relayer?.pubkeyB58 : undefined,
        relayerFeeAta: includeFee ? (feePlan.feeAccount ?? undefined) : undefined,
        escrowPubkey,
      })
      // When `includeFee === false` (default native EXEC_FLAG_FEE_ON_OUTPUT), recompute feePlan
      // against the exact DEX `outAmount` so Token-2022 ATA rent & 2x TransferFee gross-up match
      // the quoted swap output precisely.
      if (!includeFee && /^\d+$/.test(quoteResult.winner.outAmount)) {
        feePlan = computeSwapFeePlan({
          cfg,
          rentSchedule,
          outputMint,
          outputDecimals: outMeta.decimals,
          estimatedOutAmount: BigInt(quoteResult.winner.outAmount),
          solPriceUsd,
          outputTokenPriceUsd: outPriceUsd,
          feeAccount: relayerFeeAtaB58,
          feeAccountExists,
          hasUnsafeSelfPayExt: outMeta.hasUnsafeSelfPayExt,
          outputTokenProgram: outMeta.tokenProgram,
          outputHasTransferFeeExt: outHasTransferFeeExt,
          outputAtaByteLen: outAtaByteLen,
          outputTransferFee,
          extraAtaCount: missingVaultEscrowAtaCount,
          extraAtaRentLamports,
        })
      } else {
        // Refine feePlan USD numbers against the actual quoted outAmount & platformFee
        const actualSwapUsd =
          outPriceUsd && outPriceUsd > 0
            ? (Number(quoteResult.winner.outAmount) / Math.pow(10, outMeta.decimals)) * outPriceUsd
            : feePlan.estimatedSwapUsd
        const actualFeeUsd =
          quoteResult.winner.platformFee?.amount && outPriceUsd && outPriceUsd > 0
            ? (Number(quoteResult.winner.platformFee.amount) / Math.pow(10, outMeta.decimals)) *
              outPriceUsd
            : actualSwapUsd !== null
              ? (actualSwapUsd * feePlan.platformFeeBps) / 10_000
              : feePlan.estimatedFeeUsd
        feePlan = {
          ...feePlan,
          estimatedSwapUsd: actualSwapUsd,
          estimatedFeeUsd: actualFeeUsd,
        }
      }
    }

    return json(request, cfg.corsOrigins, {
      ok: true,
      cluster,
      provider: quoteResult.winner.provider,
      quote: quoteResult.winner,
      candidates: quoteResult.candidates,
      feePlan,
      relayerPubkey: relayer?.pubkeyB58 ?? null,
      escrowPda: escrowPubkey,
      shardId,
      grossInputAmount: inputTransferFee.grossInputAmount,
      netInputAmount: inputTransferFee.netInputAmount,
      inputTransferFeeBps: inputTransferFee.inputTransferFeeBps,
      inputTransferFee: inputTransferFee.inputTransferFee,
      outputTransferFee: outputTransferFee
        ? {
            bps: Number(outputTransferFee.bps),
            maxFee: outputTransferFee.maxFee.toString(),
          }
        : null,
      mints: {
        input: inMeta,
        output: outMeta,
      },
    })
  } catch (err) {
    return json(request, cfg.corsOrigins, { error: sanitizeError(err, 'Swap quote failed') }, 502)
  }
}

async function handleSwapInstructions(request: Request, env: Env): Promise<Response> {
  const cfg = loadPolicyConfig(env)
  const parsed = await readBoundedJson<{
    cluster?: string
    provider?: AggregatorId
    quoteResponse?: Record<string, unknown>
    inputMint?: string
    outputMint?: string
    shardId?: number
    relayerPubkey?: string
    includeFee?: boolean
  }>(request)
  if (!parsed.ok) {
    return json(
      request,
      cfg.corsOrigins,
      { error: parsed.error, ...(parsed.code ? { code: parsed.code } : {}) },
      parsed.status,
    )
  }
  const body = parsed.data

  if (body.cluster !== undefined && typeof body.cluster !== 'string') {
    return json(request, cfg.corsOrigins, { error: 'cluster must be a string' }, 400)
  }
  const cluster = parseCluster(body.cluster, 'mainnet')
  const rpcUrl = getRpcUrl(env, cluster)
  if (!rpcUrl) {
    return json(request, cfg.corsOrigins, { error: `${cluster} RPC is not configured` }, 503)
  }

  if (body.provider !== undefined && typeof body.provider !== 'string') {
    return json(request, cfg.corsOrigins, { error: 'provider must be a string' }, 400)
  }
  const provider = (
    typeof body.provider === 'string' ? body.provider.trim().toLowerCase() : cfg.defaultAggregator
  ) as AggregatorId
  if (!cfg.enabledAggregators.has(provider)) {
    return json(request, cfg.corsOrigins, { error: `Aggregator "${provider}" is disabled` }, 400)
  }
  const adapter = getAggregatorAdapter(provider)
  if (!adapter.isConfigured(env)) {
    return json(
      request,
      cfg.corsOrigins,
      { error: `Aggregator "${provider}" is not configured on this relay` },
      503,
    )
  }

  if (!body.quoteResponse || typeof body.quoteResponse !== 'object' || Array.isArray(body.quoteResponse)) {
    return json(request, cfg.corsOrigins, { error: 'Missing quoteResponse' }, 400)
  }

  const rawInputMint =
    body.inputMint !== undefined ? body.inputMint : body.quoteResponse.inputMint
  const rawOutputMint =
    body.outputMint !== undefined ? body.outputMint : body.quoteResponse.outputMint
  const inputMint = typeof rawInputMint === 'string' ? rawInputMint.trim() : ''
  const outputMint = typeof rawOutputMint === 'string' ? rawOutputMint.trim() : ''
  if (!isValidPubkey(inputMint) || !isValidPubkey(outputMint)) {
    return json(request, cfg.corsOrigins, { error: 'Invalid inputMint or outputMint' }, 400)
  }

  const resolvedShard = resolveShardId(body.shardId)
  if (!resolvedShard.ok) {
    return json(request, cfg.corsOrigins, { error: resolvedShard.error }, 400)
  }
  const shardId = resolvedShard.shardId
  const escrowBytes = deriveEscrowPda(0, shardId).address
  const vaultAuthBytes = deriveVaultAuthPda(0).address
  const escrowPubkey = base58Encode(escrowBytes)
  const vaultAuthPubkey = base58Encode(vaultAuthBytes)
  if (body.relayerPubkey !== undefined && typeof body.relayerPubkey !== 'string') {
    return json(request, cfg.corsOrigins, { error: 'relayerPubkey must be a string' }, 400)
  }
  const requestedRelayerPubkey =
    typeof body.relayerPubkey === 'string' ? body.relayerPubkey.trim() || undefined : undefined
  const relayer = getRelayerPubkeyForCluster(env, cluster, requestedRelayerPubkey)

  // Detect whether the quote carries a platformFeeBps > 0.
  // Default `includeFee = false` so swaps pay via atomic protocol-enforced `EXEC_FLAG_FEE_ON_OUTPUT` (`relayerFee > 0`).
  const rawPlatformFee = body.quoteResponse.platformFee as { feeBps?: number } | null | undefined
  const rawBedrockFee = body.quoteResponse.fee as { feeBps?: number } | null | undefined
  const rawQuotedFeeBps = Number(rawPlatformFee?.feeBps ?? rawBedrockFee?.feeBps ?? 0)
  const quotedFeeBps = Number.isFinite(rawQuotedFeeBps) ? rawQuotedFeeBps : 0
  const collectFee = body.includeFee === true && quotedFeeBps > 0 && relayer !== null

  try {
    const mintMetas = await fetchMintMetas(rpcUrl, [inputMint, outputMint])
    const inMeta = mintMetas[inputMint]
    const outMeta = mintMetas[outputMint]
    if (!inMeta?.isValidMint || !outMeta?.isValidMint) {
      return json(
        request,
        cfg.corsOrigins,
        { error: 'inputMint and outputMint must be valid on-chain SPL or Token-2022 mints' },
        400,
      )
    }

    const inMintBytes = base58Decode(inputMint)
    const outMintBytes = base58Decode(outputMint)
    const inTpBytes = base58Decode(inMeta.tokenProgram)
    const outTpBytes = base58Decode(outMeta.tokenProgram)

    const vaultInAta = base58Encode(deriveAta(vaultAuthBytes, inTpBytes, inMintBytes))
    const vaultOutAta = base58Encode(deriveAta(vaultAuthBytes, outTpBytes, outMintBytes))
    const escrowInAta = base58Encode(deriveAta(escrowBytes, inTpBytes, inMintBytes))
    const escrowOutAta = base58Encode(deriveAta(escrowBytes, outTpBytes, outMintBytes))
    const relayerFeeAta =
      collectFee && relayer
        ? base58Encode(deriveAta(relayer.pubkey, outTpBytes, outMintBytes))
        : null

    const checkList = [vaultInAta, vaultOutAta, escrowInAta, escrowOutAta]
    if (relayerFeeAta) checkList.push(relayerFeeAta)

    const [built, ataInfos] = await Promise.all([
      adapter.swapInstructions(env, {
        quoteResponse: body.quoteResponse,
        escrowPubkey,
        inputMint,
        outputMint,
        feeAccountAta: relayerFeeAta ?? undefined,
        feeOwnerWallet: collectFee && relayer ? relayer.pubkeyB58 : undefined,
        platformFeeBps: quotedFeeBps,
      }),
      fetchMultipleAccounts(rpcUrl, checkList, { dataSlice: { offset: 0, length: 0 } }),
    ])

    const lookupTables = await resolveLookupTables(rpcUrl, built.addressLookupTableAddresses)

    const missingAtas: MissingAtaPlan[] = []
    if (!isInitializedAta(ataInfos[0], inMeta.tokenProgram)) {
      missingAtas.push({
        label: 'vaultIn',
        ata: vaultInAta,
        owner: vaultAuthPubkey,
        mint: inputMint,
        tokenProgram: inMeta.tokenProgram,
      })
    }
    if (!isInitializedAta(ataInfos[1], outMeta.tokenProgram)) {
      missingAtas.push({
        label: 'vaultOut',
        ata: vaultOutAta,
        owner: vaultAuthPubkey,
        mint: outputMint,
        tokenProgram: outMeta.tokenProgram,
      })
    }
    if (!isInitializedAta(ataInfos[2], inMeta.tokenProgram)) {
      missingAtas.push({
        label: 'escrowIn',
        ata: escrowInAta,
        owner: escrowPubkey,
        mint: inputMint,
        tokenProgram: inMeta.tokenProgram,
      })
    }
    if (!isInitializedAta(ataInfos[3], outMeta.tokenProgram)) {
      missingAtas.push({
        label: 'escrowOut',
        ata: escrowOutAta,
        owner: escrowPubkey,
        mint: outputMint,
        tokenProgram: outMeta.tokenProgram,
      })
    }
    if (relayerFeeAta && relayer && !isInitializedAta(ataInfos[4], outMeta.tokenProgram)) {
      missingAtas.push({
        label: 'relayerFee',
        ata: relayerFeeAta,
        owner: relayer.pubkeyB58,
        mint: outputMint,
        tokenProgram: outMeta.tokenProgram,
      })
    }

    const hasToken2022Leg =
      inMeta.tokenProgram === TOKEN_2022_PROGRAM_ID_STR ||
      outMeta.tokenProgram === TOKEN_2022_PROGRAM_ID_STR
    const swapComputeUnitLimit = Math.min(
      built.computeUnitLimit + (hasToken2022Leg ? CU_LIMIT_EXEC_TOKEN_2022_EXTRA : 0),
      MAX_RELAY_TX_CU_LIMIT,
    )

    return json(request, cfg.corsOrigins, {
      ok: true,
      cluster,
      provider: built.provider,
      shardId,
      relayerPubkey: relayer?.pubkeyB58 ?? null,
      escrowPda: escrowPubkey,
      vaultAuth: vaultAuthPubkey,
      inputMint,
      outputMint,
      tokenProgramIn: inMeta.tokenProgram,
      tokenProgramOut: outMeta.tokenProgram,
      vaultInAta,
      vaultOutAta,
      escrowInAta,
      escrowOutAta,
      relayerFeeAta,
      platformFeeBps: collectFee ? quotedFeeBps : 0,
      swapInstruction: built.swapInstruction,
      computeUnitLimit: swapComputeUnitLimit,
      addressLookupTableAddresses: built.addressLookupTableAddresses,
      lookupTables,
      missingAtas,
    })
  } catch (err) {
    return json(
      request,
      cfg.corsOrigins,
      { error: sanitizeError(err, `${provider} swap-instructions failed`) },
      502,
    )
  }
}

async function handleRelaySubmit(request: Request, env: Env): Promise<Response> {
  const cfg = loadPolicyConfig(env)
  const parsed = await readBoundedJson<RelaySubmitRequest>(request)
  if (!parsed.ok) {
    return json(
      request,
      cfg.corsOrigins,
      { error: parsed.error, ...(parsed.code ? { code: parsed.code } : {}) },
      parsed.status,
    )
  }
  const body = parsed.data

  if (body.cluster !== undefined && typeof body.cluster !== 'string') {
    return json(request, cfg.corsOrigins, { error: 'cluster must be a string' }, 400)
  }
  const cluster = parseCluster(body.cluster, 'mainnet')
  const rpcUrl = getRpcUrl(env, cluster)
  const relayerPool = getRelayerPoolForCluster(env, cluster)
  const fvkInfo = getRelayerFvk(env, cluster)
  if (!rpcUrl || relayerPool.length === 0) {
    const reqHost = new URL(request.url).host
    return json(
      request,
      cfg.corsOrigins,
      { error: `${cluster} privacy relayer is not configured on ${reqHost}` },
      503,
    )
  }

  const firstBatchAccounts =
    Array.isArray(body.instructions) && Array.isArray(body.instructions[0]?.accounts)
      ? body.instructions[0]!.accounts
      : undefined
  const requestedPayer =
    typeof firstBatchAccounts?.[0]?.pubkey === 'string'
      ? firstBatchAccounts[0]!.pubkey
      : Array.isArray(body.accounts) && typeof body.accounts[0]?.pubkey === 'string'
        ? body.accounts[0]!.pubkey
        : undefined
  const relayer = requestedPayer
    ? relayerPool.find((r) => r.pubkeyB58 === requestedPayer) ?? null
    : null
  if (!relayer) {
    return json(
      request,
      cfg.corsOrigins,
      {
        error: `accounts[0] must be a configured relayer fee-payer (${relayerPool.map((p) => p.pubkeyB58).join(', ')}); got ${requestedPayer ?? 'missing'}`,
        code: 'FIREWALL_REJECTED',
      },
      400,
    )
  }

  // 1. Strict Zero-Trust Audren v1 Firewall (permits Transact Tag 5, 1..=4 private Transact batches,
  //    & ExecViaEscrow Tag 6; enforces vk_id === 0 and canonical ATAs; rejects Deposit Tag 3).
  //    Expensive Mode 1 `cm2` crypto (X25519 + ChaCha20 + Poseidon) is deferred until AFTER `guard.begin()`.
  let verdict: ReturnType<typeof validateRelaySubmission>
  try {
    verdict = validateRelaySubmission(
      body,
      relayer.pubkey,
      cfg.allowedPreIxPrograms,
      null,
      {
        relayerPoolPubkeys: relayerPool.map((r) => r.pubkey),
        selfPayFeeMints: cfg.selfPayFeeMints,
        deferCm2Verification: true,
      },
    )
  } catch (err) {
    if (err instanceof FirewallError) {
      return json(request, cfg.corsOrigins, { error: err.message, code: 'FIREWALL_REJECTED' }, err.status)
    }
    return json(request, cfg.corsOrigins, { error: sanitizeError(err, 'Firewall error') }, 400)
  }

  const cuBudgets = verdict.audrenInstructions.map((entry) => computeAudrenInstructionCuLimit(entry))
  const defaultCu = Math.min(
    cuBudgets.reduce((sum, b) => sum + b.defaultCu, 0),
    MAX_RELAY_TX_CU_LIMIT,
  )
  const minAudrenCuFloor = Math.min(
    cuBudgets.reduce((sum, b) => sum + b.minFloorCu, 0),
    MAX_RELAY_TX_CU_LIMIT,
  )
  const rawCu = body.computeUnitLimit === undefined ? defaultCu : Number(body.computeUnitLimit)
  if (!Number.isFinite(rawCu) || rawCu < 0) {
    return json(request, cfg.corsOrigins, { error: 'computeUnitLimit must be a non-negative number' }, 400)
  }
  const rawPriorityStr =
    body.priorityFeeLamports === undefined
      ? '5000'
      : typeof body.priorityFeeLamports === 'string'
        ? body.priorityFeeLamports.trim()
        : typeof body.priorityFeeLamports === 'number' && Number.isSafeInteger(body.priorityFeeLamports)
          ? String(body.priorityFeeLamports)
          : ''
  if (!/^\d+$/.test(rawPriorityStr)) {
    return json(request, cfg.corsOrigins, { error: 'priorityFeeLamports must be a non-negative integer string' }, 400)
  }
  const parsedPriority = BigInt(rawPriorityStr)
  const hasUntrustedCpiTarget =
    (verdict.execMeta !== null &&
      (!cfg.auditedSwapRouterPrograms.has(verdict.execMeta.targetProgramId) ||
        (verdict.execMeta.tokenProgIn === TOKEN_2022_PROGRAM_ID_STR &&
          !cfg.selfPayFeeMints.has(verdict.execMeta.mintIn)) ||
        (verdict.execMeta.tokenProgOut === TOKEN_2022_PROGRAM_ID_STR &&
          !cfg.selfPayFeeMints.has(verdict.execMeta.mintOut)))) ||
    Boolean(verdict.transactMeta?.hasTrailingHookAccounts)
  const maxPriorityFeeLamports = hasUntrustedCpiTarget
    ? MAX_UNAUDITED_ROUTER_PRIORITY_FEE_LAMPORTS
    : MAX_RELAY_PRIORITY_FEE_LAMPORTS
  const cappedPriority =
    parsedPriority > maxPriorityFeeLamports ? maxPriorityFeeLamports : parsedPriority

  const clientIp = extractClientIp(request)
  const guard = getGuardStub(env)

  // Pre-simulation guard: hashes IP inside DO using ephemeral in-memory daily 32-byte random salt,
  // atomically deduplicates all nullifiers across the single ix or batch without linking IP to nullifiers,
  // and short-circuits already revert-blocked IPs (plus concurrent untrusted-CPI bursts) before RPC simulation.
  const beginDecision = await guard.begin({
    clientIp,
    nullifiers: verdict.nullifiers,
    cluster,
    hasUntrustedCpiTarget,
    limits: {
      ipCooldownSec: cfg.sponsoredCooldownSec[cluster],
      ipMaxSponsoredPerHour: cfg.sponsoredPerIpPerHour[cluster],
      ipMaxSponsoredPerDay: cfg.sponsoredPerIpPerDay[cluster],
    },
  })
  if (!beginDecision.allowed) {
    return json(
      request,
      cfg.corsOrigins,
      {
        error: beginDecision.reason ?? 'Relay anti-abuse limit reached',
        code: beginDecision.code ?? 'RATE_LIMITED',
        retryAfterSec: beginDecision.retryAfterSec,
      },
      beginDecision.status ?? 429,
      beginDecision.retryAfterSec
        ? { 'retry-after': String(beginDecision.retryAfterSec) }
        : undefined,
    )
  }
  const ipHash = beginDecision.ipHash ?? ''

  let lockHeld = true
  let reservationId: string | undefined
  let exactOpenPageLockLease: { poolId: number; laneIds: number[]; leaseId: string } | null = null
  let proactiveOpenPageLockLease: { poolId: number; laneIds: number[]; leaseId: string } | null = null
  let openPageBroadcasted = false
  let openPageConfirmed = false
  let openPageFailedOnChain = false
  try {
    // Now that per-IP rate limits & nullifier dedup passed, decrypt & verify Mode 1 shielded `cm2` fee notes.
    resolveShieldedCm2Fees(verdict, fvkInfo?.fvk ?? null)

    // 2. Fetch blockhash + pre-simulation balances (with `context.slot`) + PoolState + all touched
    //    LaneTreeStates, LaneRentVaults, primary/rollover page PDAs, and setupAtas in ONE RPC batch.
    const baseWatchAddresses = [relayer.pubkeyB58]
    const watchedFeeAtaIdx = verdict.watchedRelayerFeeAta
      ? baseWatchAddresses.push(verdict.watchedRelayerFeeAta) - 1
      : -1
    const watchedNativeRecipientIdx =
      verdict.nativeSolFeeToRelayer > 0n &&
      verdict.nativeSolFeeRecipient &&
      verdict.nativeSolFeeRecipient !== relayer.pubkeyB58
        ? baseWatchAddresses.push(verdict.nativeSolFeeRecipient) - 1
        : -1

    const preFetchAddresses: string[] = [...baseWatchAddresses]
    const seenFetch = new Set<string>(baseWatchAddresses)
    const enqueueFetch = (addr: string) => {
      if (!seenFetch.has(addr)) {
        seenFetch.add(addr)
        preFetchAddresses.push(addr)
      }
    }

    const pool0PdaB58 = base58Encode(derivePoolPda(0).address)
    enqueueFetch(pool0PdaB58)

    for (const entry of verdict.audrenInstructions) {
      enqueueFetch(base58Encode(deriveLanePda(entry.poolId, entry.outLaneId).address))
      enqueueFetch(base58Encode(deriveLaneRentVaultPda(entry.poolId, entry.outLaneId).address))
      for (const slot of listReferencedPageSlots(entry.pages)) {
        enqueueFetch(slot.pda)
      }
    }
    for (const s of verdict.setupAtas) {
      enqueueFetch(base58Encode(s.ata))
      if (base58Encode(s.tokenProgram) === TOKEN_2022_PROGRAM_ID_STR) {
        enqueueFetch(base58Encode(s.mint))
      }
    }

    const [bhRes, initialPreCtx, liveRentSchedule] = await Promise.all([
      rpcCall<{ value: { blockhash: string } }>(rpcUrl, 'getLatestBlockhash', [
        { commitment: 'confirmed' },
      ]),
      fetchMultipleAccountsWithContext(rpcUrl, preFetchAddresses),
      fetchLiveRentSchedule(rpcUrl).catch(() => null),
    ])

    let preCtx = initialPreCtx
    let preCtxCommitment: 'confirmed' | 'processed' = 'confirmed'
    let preAccounts = [...preCtx.accounts]
    const preFetchIndexByAddr = new Map<string, number>()
    preFetchAddresses.forEach((addr, idx) => preFetchIndexByAddr.set(addr, idx))
    const fetchedMap = new Map<string, FetchedAccountMeta | null>()
    const preAccountInfoMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string } | null>()
    const syncPreAccountsFromCtx = (ctx: typeof preCtx) => {
      preAccounts = [...ctx.accounts]
      fetchedMap.clear()
      preAccountInfoMap.clear()
      preFetchAddresses.forEach((addr, idx) => {
        const acc = preAccounts[idx] ?? null
        preAccountInfoMap.set(addr, acc)
        fetchedMap.set(addr, acc ? { bytes: acc.bytes, owner: acc.owner } : null)
      })
    }
    const mergePinnedAccounts = (
      addrs: string[],
      ctx: typeof preCtx,
      commitment: 'confirmed' | 'processed' = 'processed',
    ) => {
      addrs.forEach((addr, idx) => {
        const acc = ctx.accounts[idx] ?? null
        preAccountInfoMap.set(addr, acc)
        fetchedMap.set(addr, acc ? { bytes: acc.bytes, owner: acc.owner } : null)
        const preIdx = preFetchIndexByAddr.get(addr)
        if (preIdx !== undefined) {
          preAccounts[preIdx] = acc
        }
      })
      preCtx = { slot: ctx.slot, accounts: preAccounts }
      preCtxCommitment = commitment
    }
    syncPreAccountsFromCtx(preCtx)

    const rentSchedule = liveRentSchedule ?? getCachedLiveRentSchedule(rpcUrl)
    const nullifierRentFloorUnit = rentSchedule?.nullifierRentLamports ?? 890_880n
    const laneRentVaultReserveFloor = rentSchedule?.laneRentVaultReserveLamports ?? 1_002_240n
    const ataRentFloorUnit = rentSchedule?.ataRentLamports ?? 2_039_280n
    // Exact Mainnet `6960 * (len + 128)` cold-isolate fallback page rents:
    //   SubtreePage (8,256 B) = 58_352_640n, SubtreeRootPage (9,664 B) = 68_152_320n,
    //   MemoPage (10,240 B)   = 72_161_280n, NullifierPage (9,664 B)   = 68_152_320n.
    const subRentFloor = rentSchedule?.subtreePageRentLamports ?? 58_352_640n
    const srRentFloor = rentSchedule?.subrootPageRentLamports ?? 68_152_320n
    const memoRentFloor = rentSchedule?.memoPageRentLamports ?? 72_161_280n
    const nfPageRentFloor = rentSchedule?.nfPageRentLamports ?? 68_152_320n

    const setupAtaInstructions: SolanaInstruction[] = verdict.setupAtas.map((s) =>
      buildCreateAtaIdempotentIx({
        payer: relayer.pubkey,
        ata: s.ata,
        owner: s.owner,
        mint: s.mint,
        tokenProgram: s.tokenProgram,
      }),
    )
    const setupAtasCu = verdict.setupAtas.reduce(
      (sum, s) =>
        sum +
        (bytesEqual(s.tokenProgram, TOKEN_2022_PROGRAM_ID)
          ? CU_LIMIT_SETUP_ATA_TOKEN_2022
          : CU_LIMIT_SETUP_ATA_CLASSIC),
      0,
    )
    const audrenSolanaInstructions: SolanaInstruction[] = verdict.audrenInstructions.map((entry) => ({
      programId: AUDREN_PROGRAM_ID,
      accounts: entry.decodedAccounts,
      data: entry.ixData,
    }))

    const pageEntries = verdict.audrenInstructions.map((entry) => ({
      poolId: entry.poolId,
      outLaneId: entry.outLaneId,
      outputCount: entry.outputCount,
      nullifierCount: entry.nullifiers.length,
      pages: entry.pages,
    }))
    const exactPlan = planBatchMissingOpenPageIxs({
      payerB58: relayer.pubkeyB58,
      entries: pageEntries,
      fetchedAccounts: fetchedMap,
    })
    if (!exactPlan.ok) {
      await guard.release({
        ipHash,
        cluster,
        nullifiers: verdict.nullifiers,
        recordFailure: true,
      })
      lockHeld = false
      return json(
        request,
        cfg.corsOrigins,
        { error: exactPlan.error, code: 'INVALID_PAGE_PDA' },
        400,
      )
    }

    // Compute exact non-proactive Transaction v1 account count, wire bytes, and CU budget so
    // proactive >= 90% lookahead NEVER overflows 64 accounts, 4,096 B wire size, or 1,400,000 CU.
    const baseInstructionsWithoutProactive: SolanaInstruction[] = [
      ...setupAtaInstructions,
      ...exactPlan.openPageIxs,
      ...verdict.preInstructions,
      ...audrenSolanaInstructions,
    ]
    const { wireLen: baseWireLen, uniqueAccountCount: baseUniqueAccountCount } = estimateV1TxWireLen(
      relayer.pubkey,
      baseInstructionsWithoutProactive,
    )
    const baseCu = Math.max(Math.trunc(rawCu), minAudrenCuFloor)
    const exactOpenPagesCu = exactPlan.openPageIxs.reduce(
      (sum, ix) => sum + computeOpenPageIxCuLimit(ix),
      0,
    )
    const baseNonProactiveCu =
      baseCu +
      verdict.preInstructions.length * 40_000 +
      setupAtasCu +
      exactOpenPagesCu
    const maxLookaheadExtraAccounts = Math.max(0, SOLANA_TX_V1_MAX_ACCOUNTS - baseUniqueAccountCount)
    const maxExtraByBytes = Math.min(
      Math.floor(Math.max(0, SOLANA_TX_V1_MAX_SIZE - baseWireLen) / PROACTIVE_OPEN_PAGE_WIRE_BYTES),
      Math.max(0, 64 - baseInstructionsWithoutProactive.length),
    )
    const maxExtraCu = Math.max(0, MAX_RELAY_TX_CU_LIMIT - baseNonProactiveCu)
    const maxExtraByCu = Math.floor(maxExtraCu / CU_LIMIT_OPEN_PAGE)

    // 3. Auto-prepend deduplicated `OpenPage` (Tag 2, reimbursed from `LaneRentVault`) for:
    //    - exact missing primary / boundary rollover page PDAs across all touched lanes, AND
    //    - proactive `>= 90%` lookahead pages (`subRem <= 26`, `memoRem <= 10`, `nfRem <= 60`,
    //      `subrootSlot >= 280`) strictly when live rent is known (`rentSchedule !== null`),
    //      `LaneRentVault` covers 100% of page rent (0 deficit), and account/wire/CU caps permit.
    const pagePlan = await planRolloverOpenPages({
      rpcUrl,
      payerB58: relayer.pubkeyB58,
      entries: pageEntries,
      fetchedAccounts: fetchedMap,
      preAccountInfoMap,
      rentFloors: {
        laneRentVaultReserveFloor,
        subRentFloor,
        srRentFloor,
        memoRentFloor,
        nfPageRentFloor,
      },
      exactPlan,
      allowProactive: rentSchedule !== null,
      maxExtraAccounts: maxLookaheadExtraAccounts,
      maxExtraByBytes,
      maxExtraByCu,
      maxExtraCu,
    })
    if (!pagePlan.ok) {
      await guard.release({
        ipHash,
        cluster,
        nullifiers: verdict.nullifiers,
        recordFailure: true,
      })
      lockHeld = false
      return json(
        request,
        cfg.corsOrigins,
        { error: pagePlan.error, code: 'INVALID_PAGE_PDA' },
        400,
      )
    }

    const openPagePoolId = verdict.audrenInstructions[0]?.poolId ?? 0
    const exactOpenPageIxs = pagePlan.exactOpenPageIxs
    const exactLaneIds = pagePlan.exactLaneIds
    const exactLaneSet = new Set<number>(exactLaneIds)

    // Acquire mandatory `openPageLock` strictly for exact rollover lanes first — return
    // `503 LANE_ROLLOVER_BUSY` ONLY if an exact rollover lane is locked.
    if (exactLaneIds.length > 0) {
      const exactLeaseId = crypto.randomUUID()
      const exactLock = await guard.acquireOpenPageLock({
        cluster,
        poolId: openPagePoolId,
        laneIds: exactLaneIds,
        leaseId: exactLeaseId,
        ttlMs: 45_000,
      })
      if (!exactLock.allowed) {
        await guard.release({
          ipHash,
          cluster,
          nullifiers: verdict.nullifiers,
          recordFailure: false,
        })
        lockHeld = false
        return json(
          request,
          cfg.corsOrigins,
          {
            error: `Lane ${exactLock.busyLaneId ?? exactLaneIds[0]} page rollover is already in progress; please retry shortly`,
            code: 'LANE_ROLLOVER_BUSY',
            retryAfterSec: 2,
          },
          503,
          { 'retry-after': '2' },
        )
      }
      exactOpenPageLockLease = { poolId: openPagePoolId, laneIds: exactLaneIds, leaseId: exactLeaseId }
    }

    // For proactive-only lanes (NOT in `exactLaneIds`), acquire `openPageLock` opportunistically
    // per lane; if a lane is busy, drop that lane's optional proactive `OpenPage`(s) and proceed!
    let activeProactiveIxs: SolanaInstruction[] = []
    if (pagePlan.proactiveLaneMap.size > 0) {
      const proactiveLeaseId = crypto.randomUUID()
      const acquiredProactiveOnlyLanes: number[] = []
      for (const [laneId, laneIxs] of pagePlan.proactiveLaneMap.entries()) {
        if (exactLaneSet.has(laneId)) {
          activeProactiveIxs.push(...laneIxs)
          continue
        }
        const proLock = await guard.acquireOpenPageLock({
          cluster,
          poolId: openPagePoolId,
          laneIds: [laneId],
          leaseId: proactiveLeaseId,
          ttlMs: 45_000,
        })
        if (proLock.allowed) {
          acquiredProactiveOnlyLanes.push(laneId)
          proactiveOpenPageLockLease = {
            poolId: openPagePoolId,
            laneIds: acquiredProactiveOnlyLanes,
            leaseId: proactiveLeaseId,
          }
          activeProactiveIxs.push(...laneIxs)
        }
      }
    }

    const dropProactiveOpenPages = async () => {
      activeProactiveIxs = []
      if (proactiveOpenPageLockLease) {
        const lease = proactiveOpenPageLockLease
        proactiveOpenPageLockLease = null
        await guard
          .releaseOpenPageLock({
            cluster,
            poolId: lease.poolId,
            laneIds: lease.laneIds,
            leaseId: lease.leaseId,
          })
          .catch(() => {})
      }
    }

    // 4 & 5. Build instruction list, compute calibrated CU limit, and compile & sign Solana v1 (0x81)
    const buildTxAttempt = (openPageIxs: SolanaInstruction[]) => {
      const attemptWatchAddresses = [...baseWatchAddresses]
      for (const openIx of openPageIxs) {
        const vaultPdaB58 = base58Encode(openIx.accounts[3]!.pubkey)
        if (!attemptWatchAddresses.includes(vaultPdaB58)) {
          attemptWatchAddresses.push(vaultPdaB58)
        }
      }
      const instructions: SolanaInstruction[] = [
        ...setupAtaInstructions,
        ...openPageIxs,
        ...verdict.preInstructions,
        ...audrenSolanaInstructions,
      ]
      const openPagesCu = openPageIxs.reduce((sum, ix) => sum + computeOpenPageIxCuLimit(ix), 0)
      const requestedCu =
        baseCu +
        verdict.preInstructions.length * 40_000 +
        setupAtasCu +
        openPagesCu
      const cuLimit = Math.min(requestedCu, MAX_RELAY_TX_CU_LIMIT)
      const signed = buildAndSignV1Transaction(relayer.secret32, bhRes.value.blockhash, instructions, {
        computeUnitLimit: cuLimit,
        priorityFeeLamports: cappedPriority,
      })
      return {
        openPageIxs,
        watchAddresses: attemptWatchAddresses,
        cuLimit,
        signed,
        priorityFeeLamports: cappedPriority,
      }
    }

    let activeOpenPageIxs: SolanaInstruction[] = [...exactOpenPageIxs, ...activeProactiveIxs]
    let txAttempt: ReturnType<typeof buildTxAttempt>
    try {
      txAttempt = buildTxAttempt(activeOpenPageIxs)
    } catch (txErr) {
      if (activeProactiveIxs.length > 0) {
        await dropProactiveOpenPages()
        activeOpenPageIxs = [...exactOpenPageIxs]
        try {
          txAttempt = buildTxAttempt(activeOpenPageIxs)
        } catch (retryErr) {
          await guard.release({
            ipHash,
            cluster,
            nullifiers: verdict.nullifiers,
            recordFailure: true,
          })
          lockHeld = false
          return json(
            request,
            cfg.corsOrigins,
            {
              error: sanitizeError(retryErr, 'Transaction exceeds Solana v1 size or account limits'),
              code: 'TX_TOO_LARGE',
            },
            400,
          )
        }
      } else {
        await guard.release({
          ipHash,
          cluster,
          nullifiers: verdict.nullifiers,
          recordFailure: true,
        })
        lockHeld = false
        return json(
          request,
          cfg.corsOrigins,
          {
            error: sanitizeError(txErr, 'Transaction exceeds Solana v1 size or account limits'),
            code: 'TX_TOO_LARGE',
          },
          400,
        )
      }
    }

    const pageRentForKind = (pageKind: number): bigint =>
      pageKind === OPEN_PAGE_KIND_SUBTREE
        ? subRentFloor
        : pageKind === OPEN_PAGE_KIND_SUBROOT
          ? srRentFloor
          : pageKind === OPEN_PAGE_KIND_MEMO
            ? memoRentFloor
            : nfPageRentFloor

    // Track per-lane available `LaneRentVault` balance (reserving `SENTINEL_LEN = 16 B` rent and
    // treating a missing vault as `0n` lamports) separately for exact vs proactive `OpenPage`s.
    // Exact rollover pages subtract pre-funded lamports; optional proactive pages require
    // `LaneRentVault` alone to cover full `pageRent` so un-pinned `unfetchedPdas` lamports can
    // never mask a multi-page proactive deficit.
    const computeOpenPageDeficits = (
      exactIxs: SolanaInstruction[],
      proactiveIxs: SolanaInstruction[],
    ): { exactDeficitFloor: bigint; proactiveDeficitFloor: bigint; totalDeficitFloor: bigint } => {
      const laneVaultAvail = new Map<string, bigint>()
      const consumeOpenIx = (openIx: SolanaInstruction, subtractExistingLamports: boolean): bigint => {
        const pagePdaB58 = base58Encode(openIx.accounts[4]!.pubkey)
        const pageAcc = preAccountInfoMap.get(pagePdaB58)
        if (pageAcc?.owner === AUDREN_PROGRAM_ID_STR && pageAcc.bytes.length > 0) {
          return 0n
        }
        const vaultPdaB58 = base58Encode(openIx.accounts[3]!.pubkey)
        if (!laneVaultAvail.has(vaultPdaB58)) {
          const vaultAcc = preAccountInfoMap.get(vaultPdaB58)
          const rawVault = BigInt(vaultAcc?.lamports ?? 0)
          laneVaultAvail.set(
            vaultPdaB58,
            rawVault > laneRentVaultReserveFloor ? rawVault - laneRentVaultReserveFloor : 0n,
          )
        }
        const pageRent = pageRentForKind(openIx.data[1]!)
        const existingPageLamports = subtractExistingLamports ? BigInt(pageAcc?.lamports ?? 0) : 0n
        const needed = pageRent > existingPageLamports ? pageRent - existingPageLamports : 0n
        const avail = laneVaultAvail.get(vaultPdaB58) ?? 0n
        const subsidy = avail < needed ? avail : needed
        laneVaultAvail.set(vaultPdaB58, avail - subsidy)
        return needed - subsidy
      }

      let exactDeficitFloor = 0n
      for (const openIx of exactIxs) {
        exactDeficitFloor += consumeOpenIx(openIx, true)
      }
      let proactiveDeficitFloor = 0n
      for (const openIx of proactiveIxs) {
        proactiveDeficitFloor += consumeOpenIx(openIx, false)
      }
      return {
        exactDeficitFloor,
        proactiveDeficitFloor,
        totalDeficitFloor: exactDeficitFloor + proactiveDeficitFloor,
      }
    }

    // 6. Pre-flight simulation on Solana RPC before committing lamports:
    //    measures exact SOL outflow and exact protocol-enforced fee token/SOL inflow directly from Solana runtime.
    //    Pin `preCtx.slot === sim.slot` via up to 3 parallel small-watch (`< 1 KB`, omitting `LaneTreeState`
    //    and existing page accounts) `Promise.all` attempts at `processed` commitment so pre-sim balances,
    //    LaneRentVault lamports, setupAtas, and fee ATA balances are evaluated against the exact simulated slot.
    const runPinnedSimulation = async (
      attempt: ReturnType<typeof buildTxAttempt>,
      opts?: { skipPin?: boolean; commitment?: 'processed' | 'confirmed' },
    ) => {
      const MAX_SLOT_PIN_ATTEMPTS = 3
      let attemptSim = await simulateV1Transaction(
        rpcUrl,
        attempt.signed.wireBytes,
        attempt.watchAddresses,
        opts?.commitment ? { commitment: opts.commitment } : undefined,
      )
      if (
        !opts?.skipPin &&
        !attemptSim.err &&
        (preCtx.slot === null || attemptSim.slot === null || preCtx.slot !== attemptSim.slot)
      ) {
        const pinAddresses: string[] = []
        const seenPin = new Set<string>()
        const addPin = (addr: string) => {
          if (!seenPin.has(addr)) {
            seenPin.add(addr)
            pinAddresses.push(addr)
          }
        }
        for (const addr of attempt.watchAddresses) addPin(addr)
        addPin(pool0PdaB58)
        for (const s of verdict.setupAtas) addPin(base58Encode(s.ata))
        for (const openIx of attempt.openPageIxs) {
          addPin(base58Encode(openIx.accounts[3]!.pubkey))
          addPin(base58Encode(openIx.accounts[4]!.pubkey))
        }

        for (let attemptIdx = 0; attemptIdx < MAX_SLOT_PIN_ATTEMPTS; attemptIdx++) {
          const [pinnedPreCtx, pinnedSim] = await Promise.all([
            fetchMultipleAccountsWithContext(rpcUrl, pinAddresses, { commitment: 'processed' }),
            simulateV1Transaction(rpcUrl, attempt.signed.wireBytes, attempt.watchAddresses, {
              commitment: 'processed',
            }),
          ])
          mergePinnedAccounts(pinAddresses, pinnedPreCtx, 'processed')
          attemptSim = pinnedSim
          if (
            attemptSim.err ||
            (preCtx.slot !== null && attemptSim.slot !== null && preCtx.slot === attemptSim.slot)
          ) {
            break
          }
        }
      }
      return attemptSim
    }

    let sim = await runPinnedSimulation(txAttempt)

    const hasNonProactiveSlotSensitiveState =
      exactOpenPageIxs.length > 0 ||
      verdict.setupAtas.length > 0 ||
      watchedFeeAtaIdx >= 0 ||
      watchedNativeRecipientIdx >= 0

    // Guarantee zero relayer deficit and zero false rejections from optional proactive `OpenPage`s:
    // if post-pin `proactiveDeficitFloor > 0n`, or `SLOT_SKEW` occurred solely due to proactive
    // pages, or simulation errored while proactive pages were attached, drop ALL proactive pages,
    // release proactive-only locks immediately, and recompile/re-simulate with exact pages only
    // (preserving `preCtxCommitment` so a promoted `'processed'` snapshot never regresses to `'confirmed'`).
    if (activeProactiveIxs.length > 0) {
      const slotSkewed =
        preCtx.slot === null || sim.slot === null || preCtx.slot !== sim.slot
      const proactiveOnlySlotSkew =
        !sim.err &&
        preCtx.slot !== null &&
        sim.slot !== null &&
        preCtx.slot !== sim.slot &&
        !hasNonProactiveSlotSensitiveState
      const proactiveDeficit =
        !sim.err && !slotSkewed
          ? computeOpenPageDeficits(exactOpenPageIxs, activeProactiveIxs).proactiveDeficitFloor
          : 0n
      if (sim.err || proactiveOnlySlotSkew || proactiveDeficit > 0n) {
        await dropProactiveOpenPages()
        activeOpenPageIxs = [...exactOpenPageIxs]
        txAttempt = buildTxAttempt(activeOpenPageIxs)
        sim = await runPinnedSimulation(txAttempt, {
          skipPin: proactiveOnlySlotSkew,
          commitment: preCtxCommitment,
        })
      }
    }

    if (sim.err) {
      await guard.release({
        ipHash,
        cluster,
        nullifiers: verdict.nullifiers,
        recordFailure: true,
      })
      lockHeld = false
      return json(
        request,
        cfg.corsOrigins,
        {
          error: `Transaction simulation failed: ${JSON.stringify(sim.err)}`,
          code: 'SIMULATION_FAILED',
          logs: sim.logs.slice(-8),
          unitsConsumed: sim.unitsConsumed,
        },
        400,
      )
    }

    const hasSlotSensitiveState =
      hasNonProactiveSlotSensitiveState || activeProactiveIxs.length > 0
    if (
      preCtx.slot === null ||
      sim.slot === null ||
      (hasSlotSensitiveState && preCtx.slot !== sim.slot)
    ) {
      await guard.release({
        ipHash,
        cluster,
        nullifiers: verdict.nullifiers,
        recordFailure: false,
      })
      lockHeld = false
      return json(
        request,
        cfg.corsOrigins,
        {
          error: `Pre-simulation account state slot (${preCtx.slot}) did not match simulation slot (${sim.slot}); please retry`,
          code: 'SLOT_SKEW',
          retryAfterSec: 1,
        },
        503,
        { 'retry-after': '1' },
      )
    }

    if (sim.accounts[0] === null || sim.accounts[0] === undefined) {
      await guard.release({
        ipHash,
        cluster,
        nullifiers: verdict.nullifiers,
        recordFailure: true,
      })
      lockHeld = false
      return json(
        request,
        cfg.corsOrigins,
        {
          error: 'Simulation failed to return post-execution relayer account state',
          code: 'SIMULATION_INCOMPLETE',
        },
        502,
      )
    }
    if (watchedFeeAtaIdx >= 0 && !sim.accounts[watchedFeeAtaIdx]) {
      await guard.release({
        ipHash,
        cluster,
        nullifiers: verdict.nullifiers,
        recordFailure: true,
      })
      lockHeld = false
      return json(
        request,
        cfg.corsOrigins,
        {
          error: 'Simulation failed to return post-execution relayer fee ATA state',
          code: 'SIMULATION_INCOMPLETE',
        },
        502,
      )
    }
    if (watchedNativeRecipientIdx >= 0 && !sim.accounts[watchedNativeRecipientIdx]) {
      await guard.release({
        ipHash,
        cluster,
        nullifiers: verdict.nullifiers,
        recordFailure: true,
      })
      lockHeld = false
      return json(
        request,
        cfg.corsOrigins,
        {
          error: 'Simulation failed to return post-execution relayer native SOL fee recipient state',
          code: 'SIMULATION_INCOMPLETE',
        },
        502,
      )
    }

    // Compute deterministic protocol-side `minExpectedCostLamports` floor strictly from parsed tx
    // structure + live rent/PoolState so concurrent SOL inflows into `relayerPubkey` between
    // `preSlot` and `simSlot` can NEVER erase simulated outflow.
    const divCeil = (a: bigint, b: bigint) => (a + b - 1n) / b

    const poolAcc = preAccountInfoMap.get(pool0PdaB58)
    let poolNoteRentUnit = rentSchedule?.pageRentPerNoteLamports ?? 0n
    let poolNfRentUnit = rentSchedule?.nfPageRentPerNfLamports ?? 0n
    let poolDecodedOk = false
    if (poolAcc && poolAcc.owner === AUDREN_PROGRAM_ID_STR && poolAcc.bytes.length > 0) {
      try {
        const decodedPool = decodePoolState(poolAcc.bytes)
        poolDecodedOk = true
        poolNoteRentUnit =
          decodedPool.noteRentFee > 0n
            ? deterministicNoteRentFee(decodedPool.noteRentFee, subRentFloor, srRentFloor, memoRentFloor)
            : 0n
        const livePerNf = divCeil(nfPageRentFloor, BigInt(NF_PER_PAGE))
        poolNfRentUnit = decodedPool.nfRentFee < livePerNf ? decodedPool.nfRentFee : livePerNf
      } catch {
        // Ignore malformed mock pool bytes; cached rent defaults remain active
      }
    }

    const totalOutputs = verdict.audrenInstructions.reduce((sum, ix) => sum + ix.outputCount, 0)
    // Count EVERY uninitialized setupAta (missing, System-owned / wrong owner, or 0-byte dust-prefunded)
    // by its exact remaining rent deficit `max(0, ataRent - existingLamports)` using `estimateAtaRentLamports`
    // (`165 B` classic SPL, `170 B+` Token-2022 with exact per-extension byte length) so dust
    // pre-funding or same-slot SOL inflows cannot bypass the floor.
    let setupAtaDeficitFloor = 0n
    for (const s of verdict.setupAtas) {
      const ataB58 = base58Encode(s.ata)
      const tpB58 = base58Encode(s.tokenProgram)
      const acc = preAccountInfoMap.get(ataB58)
      if (!acc || acc.owner !== tpB58 || acc.bytes.length === 0) {
        const existingLamports = BigInt(acc?.lamports ?? 0)
        const mintAcc =
          tpB58 === TOKEN_2022_PROGRAM_ID_STR
            ? preAccountInfoMap.get(base58Encode(s.mint))
            : null
        const ataByteLen = computeToken2022AtaByteLen(tpB58, mintAcc?.bytes)
        const floorUnit = estimateAtaRentLamports(ataRentFloorUnit, tpB58, ataByteLen)
        if (floorUnit > existingLamports) {
          setupAtaDeficitFloor += floorUnit - existingLamports
        }
      }
    }

    const { totalDeficitFloor: openPageDeficitFloor } = computeOpenPageDeficits(
      exactOpenPageIxs,
      activeProactiveIxs,
    )

    const minExpectedCostLamports =
      5_000n +
      cappedPriority +
      BigInt(verdict.nullifiers.length) * (nullifierRentFloorUnit + poolNfRentUnit) +
      setupAtaDeficitFloor +
      BigInt(totalOutputs) * poolNoteRentUnit +
      openPageDeficitFloor

    const preRelayerLamports = BigInt(preAccounts[0]?.lamports ?? 0)
    const postRelayerLamports = BigInt(sim.accounts[0].lamports)
    const samePayerNativeFee =
      verdict.nativeSolFeeToRelayer > 0n && verdict.nativeSolFeeRecipient === relayer.pubkeyB58
    // Gross SOL outflow before native SOL fee offset:
    //   - When unwrapWsol credits the tx fee-payer directly (`samePayerNativeFee`), add back the
    //     protocol-enforced `nativeSolFeeToRelayer` to recover exact gross tx debit.
    const rawOutflowLamports = samePayerNativeFee
      ? preRelayerLamports + verdict.nativeSolFeeToRelayer > postRelayerLamports
        ? preRelayerLamports + verdict.nativeSolFeeToRelayer - postRelayerLamports
        : 0n
      : preRelayerLamports > postRelayerLamports
        ? preRelayerLamports - postRelayerLamports
        : 0n
    // When no slot-sensitive state remains (`openPageIxs.length === 0`, `setupAtas.length === 0`,
    // no watched fee ATA / external native fee recipient), `preCtx.slot !== sim.slot` is allowed
    // to proceed (e.g. after `proactiveOnlySlotSkew`). When live rent and `PoolState` both decoded
    // cleanly, `minExpectedCostLamports` is already the exact protocol upper bound (`relayer` is
    // blocked from `preInstructions` and `payer` `is_signer` is stripped on external CPIs), so use
    // it directly rather than cross-slot `rawOutflowLamports` which would absorb concurrent users'
    // relayer lamport debits from other slots.
    const useDeterministicCrossSlotBound =
      !hasSlotSensitiveState &&
      preCtx.slot !== sim.slot &&
      rentSchedule !== null &&
      poolDecodedOk
    const simulatedCostLamports = useDeterministicCrossSlotBound
      ? minExpectedCostLamports
      : rawOutflowLamports > minExpectedCostLamports
        ? rawOutflowLamports
        : minExpectedCostLamports

    // Measure & strictly cap protocol-enforced SPL/Token-2022 fee tokens earned by the relayer
    // during simulation: ONLY protocol-native `relayerFee > 0n` (Mode 2 / Mode 3, capped strictly at
    // parsed `relayerFee`) earns fee credit so concurrent inflows or unenforced router fees can never
    // grant `self_paying` status.
    const preFeeUnits =
      watchedFeeAtaIdx >= 0 ? readSplTokenAccountAmount(preAccounts[watchedFeeAtaIdx]?.bytes ?? null) : 0n
    const postFeeUnits =
      watchedFeeAtaIdx >= 0 && sim.accounts[watchedFeeAtaIdx]
        ? readSplTokenAccountAmount(sim.accounts[watchedFeeAtaIdx]!.bytes)
        : 0n
    const rawSimulatedFeeUnits = postFeeUnits > preFeeUnits ? postFeeUnits - preFeeUnits : 0n
    let simulatedFeeUnits = 0n
    if (verdict.transactMeta && verdict.transactMeta.relayerFee > 0n && !verdict.transactMeta.unwrapWsol) {
      simulatedFeeUnits =
        rawSimulatedFeeUnits > verdict.transactMeta.relayerFee
          ? verdict.transactMeta.relayerFee
          : rawSimulatedFeeUnits
    } else if (verdict.execMeta && verdict.execMeta.relayerFee > 0n) {
      simulatedFeeUnits =
        rawSimulatedFeeUnits > verdict.execMeta.relayerFee
          ? verdict.execMeta.relayerFee
          : rawSimulatedFeeUnits
    }

    // Dynamically value verified fee earnings in lamports (Modes 1 single/batch, 2, & 3!)
    // Enforces `SELF_PAY_FEE_MINTS` allowlist, `parseMintSafetyInfo` (via `hasUnsafeSelfPayExt`),
    // AND active Token-2022 `TransferFeeConfig` haircut (`2x` on Mode 1 pre-receipt notes; `1x`
    // liquidation-hop haircut on Mode 2/3 simulated ATA deltas already net of 1x receipt fee).
    let feeEquivalentLamports = 0n
    let combinedCm2SingleMint: string | null = null
    let combinedCm2SingleMintAmount = 0n

    if (verdict.nativeSolFeeToRelayer > 0n) {
      // Mode 2 atomic `WITHDRAW_FLAG_UNWRAP_WSOL` pays lamports directly to a configured relayer pool pubkey.
      if (samePayerNativeFee) {
        feeEquivalentLamports = verdict.nativeSolFeeToRelayer
      } else if (watchedNativeRecipientIdx >= 0 && sim.accounts[watchedNativeRecipientIdx]) {
        const preRecipLamports = BigInt(preAccounts[watchedNativeRecipientIdx]?.lamports ?? 0)
        const postRecipLamports = BigInt(sim.accounts[watchedNativeRecipientIdx]!.lamports)
        const recipDelta =
          postRecipLamports > preRecipLamports ? postRecipLamports - preRecipLamports : 0n
        feeEquivalentLamports =
          recipDelta > verdict.nativeSolFeeToRelayer ? verdict.nativeSolFeeToRelayer : recipDelta
      }
    } else if (verdict.shieldedCm2Fees.length > 0) {
      // Mode 1 Private Transfer (single or multi-ix merge batch): sum FVK-verified shielded `cm2` fee notes
      // strictly for allowlisted, safety-vetted `SELF_PAY_FEE_MINTS`.
      const amountByMint = new Map<string, bigint>()
      for (const fee of verdict.shieldedCm2Fees) {
        amountByMint.set(fee.mint, (amountByMint.get(fee.mint) ?? 0n) + fee.amount)
      }
      if (amountByMint.size === 1) {
        const [[onlyMint, onlyAmt]] = Array.from(amountByMint.entries())
        combinedCm2SingleMint = onlyMint!
        combinedCm2SingleMintAmount = onlyAmt!
      }
      if (cfg.selfPayFeeMints.has(WSOL_MINT_STR)) {
        const wsolAmt = amountByMint.get(WSOL_MINT_STR) ?? 0n
        feeEquivalentLamports += wsolAmt
      }

      const otherAllowedMints = Array.from(amountByMint.keys()).filter(
        (m) => m !== WSOL_MINT_STR && cfg.selfPayFeeMints.has(m),
      )
      if (otherAllowedMints.length > 0 && cluster === 'mainnet') {
        const [mintMetasWithData, prices] = await Promise.all([
          fetchMintMetasWithData(rpcUrl, otherAllowedMints),
          fetchMintPricesUsd(env, [WSOL_MINT_STR, ...otherAllowedMints]),
        ])
        const solUsd = prices[WSOL_MINT_STR]
        if (solUsd && solUsd > 0) {
          const needsEpoch = otherAllowedMints.some((m) => {
            const entry = mintMetasWithData[m]
            return (
              entry?.meta.tokenProgram === TOKEN_2022_PROGRAM_ID_STR &&
              entry.rawBytes !== null &&
              entry.rawBytes.byteLength > 166
            )
          })
          const currentEpoch = needsEpoch ? await fetchCurrentEpoch(rpcUrl) : 0n
          for (const cm2Mint of otherAllowedMints) {
            const entry = mintMetasWithData[cm2Mint]
            const feeMeta = entry?.meta
            const feeUsdPrice = prices[cm2Mint]
            const cm2Amt = amountByMint.get(cm2Mint) ?? 0n
            if (
              feeMeta &&
              feeMeta.isValidMint &&
              !feeMeta.hasUnsafeSelfPayExt &&
              feeUsdPrice &&
              feeUsdPrice > 0 &&
              cm2Amt > 0n
            ) {
              const { netAmount } = applyToken2022FeeHaircut({
                tokenProgram: feeMeta.tokenProgram,
                mintData: entry?.rawBytes ?? null,
                currentEpoch,
                grossAmount: cm2Amt,
                hops: 2,
              })
              if (netAmount > 0n) {
                const feeUsd = (Number(netAmount) / Math.pow(10, feeMeta.decimals)) * feeUsdPrice
                feeEquivalentLamports += BigInt(Math.max(0, Math.floor((feeUsd / solUsd) * 1e9)))
              }
            }
          }
        }
      }
    } else if (
      simulatedFeeUnits > 0n &&
      verdict.watchedRelayerFeeMint &&
      cfg.selfPayFeeMints.has(verdict.watchedRelayerFeeMint)
    ) {
      if (verdict.watchedRelayerFeeMint === WSOL_MINT_STR) {
        feeEquivalentLamports = simulatedFeeUnits
      } else if (cluster === 'mainnet') {
        const [mintMetasWithData, prices] = await Promise.all([
          fetchMintMetasWithData(rpcUrl, [verdict.watchedRelayerFeeMint]),
          fetchMintPricesUsd(env, [WSOL_MINT_STR, verdict.watchedRelayerFeeMint]),
        ])
        const entry = mintMetasWithData[verdict.watchedRelayerFeeMint]
        const feeMeta = entry?.meta
        const solUsd = prices[WSOL_MINT_STR]
        const feeUsdPrice = prices[verdict.watchedRelayerFeeMint]
        if (
          feeMeta &&
          feeMeta.isValidMint &&
          !feeMeta.hasUnsafeSelfPayExt &&
          solUsd &&
          feeUsdPrice &&
          solUsd > 0 &&
          feeUsdPrice > 0
        ) {
          const needsEpoch =
            feeMeta.tokenProgram === TOKEN_2022_PROGRAM_ID_STR &&
            entry?.rawBytes !== null &&
            entry.rawBytes.byteLength > 166
          const currentEpoch = needsEpoch ? await fetchCurrentEpoch(rpcUrl) : 0n
          // `simulatedFeeUnits = postFeeUnits - preFeeUnits` is already net of 1x on-chain
          // Token-2022 receipt fee from `vault/escrow -> relayerFeeAta`; apply 1x liquidation haircut.
          const { netAmount } = applyToken2022FeeHaircut({
            tokenProgram: feeMeta.tokenProgram,
            mintData: entry?.rawBytes ?? null,
            currentEpoch,
            grossAmount: simulatedFeeUnits,
            hops: 1,
          })
          if (netAmount > 0n) {
            const feeUsd = (Number(netAmount) / Math.pow(10, feeMeta.decimals)) * feeUsdPrice
            const feeSol = feeUsd / solUsd
            feeEquivalentLamports = BigInt(Math.max(0, Math.floor(feeSol * 1e9)))
          }
        }
      }
    }

    // Apply `cfg.selfPayMarginBps` (`>= 10000`) at submit time: `isSelfPaying` requires verified
    // haircut fee value >= `ceil(simulatedCostLamports * selfPayMarginBps / 10000)`.
    const marginBps = BigInt(Math.max(cfg.selfPayMarginBps, 10_000))
    const requiredSelfPayLamports = (simulatedCostLamports * marginBps + 9_999n) / 10_000n
    const isSelfPaying =
      feeEquivalentLamports > 0n && feeEquivalentLamports >= requiredSelfPayLamports
    const netSponsoredLamports = isSelfPaying
      ? 0n
      : simulatedCostLamports > feeEquivalentLamports
        ? simulatedCostLamports - feeEquivalentLamports
        : requiredSelfPayLamports - feeEquivalentLamports

    // Hard per-tx outflow safety ceiling (protects against runaway sponsored rent creation)
    const MAX_TX_OUTFLOW_LAMPORTS = 50_000_000n // 0.05 SOL hard per-tx sponsored ceiling
    const maxRawOutflowLamports =
      isSelfPaying && activeOpenPageIxs.length > 0 ? 300_000_000n : MAX_TX_OUTFLOW_LAMPORTS
    if (
      netSponsoredLamports > MAX_TX_OUTFLOW_LAMPORTS ||
      simulatedCostLamports > maxRawOutflowLamports
    ) {
      await guard.release({
        ipHash,
        cluster,
        nullifiers: verdict.nullifiers,
        recordFailure: true,
      })
      lockHeld = false
      return json(
        request,
        cfg.corsOrigins,
        {
          error: `Simulated relayer SOL outflow (${simulatedCostLamports.toString()} lamports) exceeds per-tx safety ceiling`,
          code: 'COST_CEILING_EXCEEDED',
        },
        400,
      )
    }

    // Unconditionally block sponsored (`!isSelfPaying`) withdrawals from funding user-owned
    // `isWithdrawRecipientAta` setupAtas on ANY mint (preventing direct SOL extraction via
    // CloseAccount). Zero-SOL WSOL withdrawals already use `WITHDRAW_FLAG_UNWRAP_WSOL`.
    if (verdict.hasWithdrawRecipientAta && !isSelfPaying) {
      await guard.release({
        ipHash,
        cluster,
        nullifiers: verdict.nullifiers,
        recordFailure: true,
      })
      lockHeld = false
      return json(
        request,
        cfg.corsOrigins,
        {
          error:
            'Withdraw recipient ATA setup cannot be funded by the relay without full self-pay fee coverage.',
          code: 'FEE_REQUIRED',
          simulatedCostLamports: simulatedCostLamports.toString(),
          feeEquivalentLamports: feeEquivalentLamports.toString(),
        },
        402,
      )
    }

    // Multi-instruction private `Transact` batches (2..=4 merges) UNCONDITIONALLY require
    // `isSelfPaying === true` (regardless of whether `*_RELAYER_FVK_JSON` or `allowMicroSwapSubsidy` is set).
    if (verdict.audrenInstructions.length > 1 && !isSelfPaying) {
      await guard.release({
        ipHash,
        cluster,
        nullifiers: verdict.nullifiers,
        recordFailure: true,
      })
      lockHeld = false
      return json(
        request,
        cfg.corsOrigins,
        {
          error:
            'Combined shielded cm2 relayer fees across multi-instruction batch did not cover simulated Solana rent/gas (including margin and any auto-prepended OpenPage instructions).',
          code: 'FEE_REQUIRED',
          simulatedCostLamports: simulatedCostLamports.toString(),
          feeEquivalentLamports: feeEquivalentLamports.toString(),
        },
        402,
      )
    }

    if (verdict.execMeta && !isSelfPaying && !cfg.allowMicroSwapSubsidy) {
      await guard.release({
        ipHash,
        cluster,
        nullifiers: verdict.nullifiers,
        recordFailure: true,
      })
      lockHeld = false
      return json(
        request,
        cfg.corsOrigins,
        {
          error:
            'ExecViaEscrow relay fee did not cover simulated Solana rent/gas and micro-action subsidy is disabled.',
          code: 'FEE_REQUIRED',
          simulatedCostLamports: simulatedCostLamports.toString(),
          feeEquivalentLamports: feeEquivalentLamports.toString(),
        },
        402,
      )
    }

    // 7. Post-simulation guard: atomically reserve simulated net sponsored cost against daily budget & IP limits
    const reservation = await guard.authorizeSpend({
      ipHash,
      cluster,
      opKind: verdict.opKind,
      nullifiers: verdict.nullifiers,
      sponsoredLamports: Number(netSponsoredLamports),
      selfPaying: isSelfPaying,
      hasUntrustedCpiTarget,
      maxRevertBurnLamports: Number(5_000n + txAttempt.priorityFeeLamports),
      limits: {
        maxDailySponsoredLamports: Number(cfg.maxDailySponsoredLamports[cluster]),
        ipMaxSponsoredPerHour: cfg.sponsoredPerIpPerHour[cluster],
        ipMaxSponsoredPerDay: cfg.sponsoredPerIpPerDay[cluster],
        ipCooldownSec: cfg.sponsoredCooldownSec[cluster],
        selfPayPerIpPer10m: cfg.selfPayPerIpPer10m,
      },
    })
    if (!reservation.allowed) {
      lockHeld = false
      return json(
        request,
        cfg.corsOrigins,
        {
          error: reservation.reason ?? 'Relay anti-abuse limit reached',
          code: reservation.code ?? 'RATE_LIMITED',
          retryAfterSec: reservation.retryAfterSec,
        },
        reservation.status ?? 429,
        reservation.retryAfterSec ? { 'retry-after': String(reservation.retryAfterSec) } : undefined,
      )
    }
    reservationId = reservation.reservationId

    // 8. Broadcast & confirm on Solana via RPC
    const sentSig = await rpcCall<string>(rpcUrl, 'sendTransaction', [
      toBase64(txAttempt.signed.wireBytes),
      { encoding: 'base64', preflightCommitment: 'confirmed', maxRetries: 3 },
    ])
    openPageBroadcasted = true
    let slot = 0
    try {
      const conf = await waitForConfirmation(rpcUrl, sentSig)
      slot = conf.slot
      openPageConfirmed = true
    } catch (confErr) {
      if (confErr instanceof TransactionFailedOnChainError) {
        // Confirmed on-chain revert: relayer burned `5_000 + priorityFeeLamports` with zero fee
        // return even when quoted `selfPaying: true`. Charge burned fee to `daily_budgets`, record
        // a failure strike (`failed = 1`), and release `open_page_locks` immediately since no
        // `LaneRentVault` spend occurred.
        openPageFailedOnChain = true
        const burnedFeeLamports = Number(5_000n + txAttempt.priorityFeeLamports)
        await guard
          .commit({
            reservationId,
            ipHash,
            cluster,
            opKind: verdict.opKind,
            nullifiers: verdict.nullifiers,
            sponsoredLamports: burnedFeeLamports,
            selfPaying: false,
            recordFailure: true,
          })
          .catch(() => {})
      } else {
        // Transaction was already broadcast and confirmation timed out/errored transiently —
        // it may still land on-chain, so commit conservatively and retain the 10s grace lease.
        await guard
          .commit({
            reservationId,
            ipHash,
            cluster,
            opKind: verdict.opKind,
            nullifiers: verdict.nullifiers,
            sponsoredLamports: Number(netSponsoredLamports),
            selfPaying: isSelfPaying,
          })
          .catch(() => {})
      }
      lockHeld = false
      reservationId = undefined
      throw confErr
    }

    // 9. Commit EXACT simulated cost into SQLite Durable Object & clear pending reservation
    await guard.commit({
      reservationId,
      ipHash,
      cluster,
      opKind: verdict.opKind,
      nullifiers: verdict.nullifiers,
      sponsoredLamports: Number(netSponsoredLamports),
      selfPaying: isSelfPaying,
    })
    lockHeld = false
    reservationId = undefined

    const releaseLeaseNow = async (
      lease: { poolId: number; laneIds: number[]; leaseId: string } | null,
    ) => {
      if (!lease) return
      await guard
        .releaseOpenPageLock({
          cluster,
          poolId: lease.poolId,
          laneIds: lease.laneIds,
          leaseId: lease.leaseId,
        })
        .catch(() => {})
    }
    const exactToRelease = exactOpenPageLockLease
    exactOpenPageLockLease = null
    const proactiveToRelease = proactiveOpenPageLockLease
    proactiveOpenPageLockLease = null
    await Promise.all([releaseLeaseNow(exactToRelease), releaseLeaseNow(proactiveToRelease)])

    const actualOut =
      typeof body.vaultOutAta === 'string' && isValidPubkey(body.vaultOutAta)
        ? await resolveVaultOutDelta(rpcUrl, sentSig, body.vaultOutAta)
        : null

    return json(request, cfg.corsOrigins, {
      ok: true,
      cluster,
      opKind: verdict.opKind,
      instructionCount: verdict.audrenInstructions.length,
      billingMode: isSelfPaying ? 'self_paying' : 'sponsored',
      txVersion: txAttempt.signed.version,
      txWireBytes: txAttempt.signed.wireLen,
      accountCount: txAttempt.signed.accountCount,
      relayerPubkey: relayer.pubkeyB58,
      priorityFeeLamports: cappedPriority.toString(),
      computeUnitLimit: txAttempt.cuLimit,
      openedPagesCount: activeOpenPageIxs.length,
      simulatedUnitsConsumed: sim.unitsConsumed,
      simulatedCostLamports: simulatedCostLamports.toString(),
      simulatedFeeUnits:
        verdict.nativeSolFeeToRelayer > 0n
          ? feeEquivalentLamports.toString()
          : verdict.shieldedCm2Fees.length > 0
            ? (combinedCm2SingleMint !== null
                ? combinedCm2SingleMintAmount
                : feeEquivalentLamports
              ).toString()
            : simulatedFeeUnits.toString(),
      simulatedFeeMint:
        verdict.nativeSolFeeToRelayer > 0n
          ? WSOL_MINT_STR
          : verdict.shieldedCm2Fees.length > 0
            ? combinedCm2SingleMint ?? WSOL_MINT_STR
            : verdict.watchedRelayerFeeMint,
      simulatedFeeAccount:
        verdict.nativeSolFeeToRelayer > 0n
          ? verdict.nativeSolFeeRecipient ?? relayer.pubkeyB58
          : verdict.shieldedCm2Fees.length > 0
            ? fvkInfo?.shieldedAddress ?? null
            : verdict.watchedRelayerFeeAta,
      netSponsoredLamports: netSponsoredLamports.toString(),
      signature: sentSig,
      slot,
      actualOut,
      solscanUrl: solscanTxUrl(sentSig, cluster),
      explorerUrl: explorerTxUrl(sentSig, cluster),
    })
  } catch (err) {
    if (lockHeld) {
      await guard
        .release({
          reservationId,
          ipHash,
          cluster,
          nullifiers: verdict.nullifiers,
          recordFailure: false,
        })
        .catch(() => {})
    }
    return json(
      request,
      cfg.corsOrigins,
      { error: sanitizeError(err, 'Privacy relay submission failed') },
      502,
    )
  } finally {
    const activeLeases = [exactOpenPageLockLease, proactiveOpenPageLockLease].filter(
      (l): l is { poolId: number; laneIds: number[]; leaseId: string } => l !== null,
    )
    exactOpenPageLockLease = null
    proactiveOpenPageLockLease = null
    for (const lease of activeLeases) {
      if (openPageBroadcasted && !openPageConfirmed && !openPageFailedOnChain) {
        // Broadcast succeeded but confirmation timed out/errored — keep a short 10s grace lease
        // so concurrent submissions cannot race the unconfirmed `LaneRentVault` spend.
        await guard
          .releaseOpenPageLock({
            cluster,
            poolId: lease.poolId,
            laneIds: lease.laneIds,
            leaseId: lease.leaseId,
            graceTtlMs: 10_000,
          })
          .catch(() => {})
      } else {
        await guard
          .releaseOpenPageLock({
            cluster,
            poolId: lease.poolId,
            laneIds: lease.laneIds,
            leaseId: lease.leaseId,
          })
          .catch(() => {})
      }
    }
  }
}

function timingSafeEqualStrings(a: string, b: string): boolean {
  const ha = sha256(utf8(a))
  const hb = sha256(utf8(b))
  let diff = 0
  for (let i = 0; i < 32; i++) diff |= ha[i]! ^ hb[i]!
  return diff === 0
}

async function handleAdminRefill(request: Request, env: Env): Promise<Response> {
  const cfg = loadPolicyConfig(env)
  const expected = env.RELAY_ADMIN_TOKEN?.trim()
  const provided = request.headers.get('x-admin-token')?.trim()
  if (!expected || !provided || !timingSafeEqualStrings(provided, expected)) {
    return json(request, cfg.corsOrigins, { error: 'Unauthorized' }, 401)
  }
  const report = await runAutoRefill(env, cfg)
  return json(request, cfg.corsOrigins, { ok: true, report })
}

const RELAY_ENDPOINTS = [
  'GET  /health',
  'GET  /v1/info?cluster=mainnet|devnet',
  'GET  /v1/fee-quote?op=transfer|withdraw|exec_escrow&mint=...(&amount=...&omitNf1=true|false)',
  'GET  /v1/aggregators',
  'GET  /v1/stats',
  'GET|POST /v1/swap/quote',
  'POST /v1/swap/instructions',
  'POST /v1/relay/submit',
] as const

// ============================================================================
// Worker Entrypoint (`fetch` + `scheduled` Cron Trigger)
// ============================================================================

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const cfg = loadPolicyConfig(env)
    const url = new URL(request.url)

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request, cfg.corsOrigins) })
    }

    if (request.method === 'POST') {
      const clHeader = request.headers.get('content-length')
      if (clHeader !== null) {
        const cl = Number(clHeader)
        if (Number.isFinite(cl) && cl > MAX_POST_BODY_BYTES) {
          return json(
            request,
            cfg.corsOrigins,
            {
              error: `Request body exceeds ${MAX_POST_BODY_BYTES} byte limit`,
              code: 'PAYLOAD_TOO_LARGE',
            },
            413,
          )
        }
      }
    }

    if ((url.pathname === '/' || url.pathname === '/health') && request.method === 'GET') {
      return json(request, cfg.corsOrigins, {
        ok: true,
        version: RELAY_VERSION,
        service: 'audren-relay',
        domain: url.host,
        programId: AUDREN_PROGRAM_ID_STR,
        rootsPda: base58Encode(deriveRootsPda(0).address),
        timestamp: new Date().toISOString(),
        ...(url.pathname === '/' ? { endpoints: RELAY_ENDPOINTS } : {}),
      })
    }

    if (url.pathname === '/v1/info' && request.method === 'GET') {
      return handleInfo(request, env)
    }

    if (url.pathname === '/v1/aggregators' && request.method === 'GET') {
      return json(request, cfg.corsOrigins, {
        ok: true,
        defaultAggregator: cfg.defaultAggregator,
        aggregators: listAggregators(env, cfg),
      })
    }

    if (url.pathname === '/v1/stats' && request.method === 'GET') {
      return handleStats(request, env)
    }

    if (url.pathname === '/v1/fee-quote' && request.method === 'GET') {
      return handleFeeQuote(request, env)
    }

    if (
      url.pathname === '/v1/swap/quote' &&
      (request.method === 'GET' || request.method === 'POST')
    ) {
      return handleSwapQuote(request, env)
    }

    if (url.pathname === '/v1/swap/instructions' && request.method === 'POST') {
      return handleSwapInstructions(request, env)
    }

    if (url.pathname === '/v1/relay/submit' && request.method === 'POST') {
      return handleRelaySubmit(request, env)
    }

    if (url.pathname === '/v1/admin/refill' && request.method === 'POST') {
      return handleAdminRefill(request, env)
    }

    return json(
      request,
      cfg.corsOrigins,
      {
        error: `Not found: ${request.method} ${url.pathname}`,
        endpoints: RELAY_ENDPOINTS,
      },
      404,
    )
  },

  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    const cfg = loadPolicyConfig(env)
    ctx.waitUntil(
      runAutoRefill(env, cfg)
        .then((report) => {
          console.log('[audren-relay cron refill]', JSON.stringify(report))
        })
        .catch((err) => {
          console.error('[audren-relay cron error]', err)
        }),
    )
  },
} satisfies ExportedHandler<Env>
