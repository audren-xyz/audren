import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import {
  getAggregatorAdapter,
  listAggregators,
  quoteWithSelection,
} from './aggregators/registry'
import { runAutoRefill, runMaintenanceCrank } from './cron/refill'
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
} from './policy/firewall'
import { RelayGuard } from './policy/guard-do'
import { computeNativeFeeQuote, computeSwapFeePlan, fetchMintPricesUsd } from './policy/pricing'
import {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_PUBLIC,
  AUDREN_PROGRAM_ID,
  AUDREN_PROGRAM_ID_STR,
  NF_PER_PAGE,
  NUM_ESCROW_SHARDS,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  PROTOCOL_VERSION,
  TAG_DEPOSIT,
  TAG_EXEC_VIA_ESCROW,
  TAG_PUBLISH_CHECKPOINT,
  TAG_TRANSACT,
  decodePoolState,
  deriveEscrowPda,
  deriveLanePda,
  deriveLaneRentVaultPda,
  derivePoolPda,
  deriveVaultAuthPda,
  deterministicNoteRentFee,
  listReferencedPageSlots,
  pickRandomEscrowShard,
  planBatchMissingOpenPageIxs,
  type FetchedAccountMeta,
} from './solana/audren'
import {
  CheckpointError,
  publishCheckpointIfNeeded,
  type CheckpointLockAdapter,
} from './solana/checkpoint'
import {
  CLASSIC_TOKEN_PROGRAM_ID_STR,
  TOKEN_2022_PROGRAM_ID_STR,
  WSOL_MINT_STR,
  base58Decode,
  base58Encode,
  buildAndSignV1Transaction,
  buildCreateAtaIdempotentIx,
  decodeRelayerSecret,
  deriveAta,
  isValidPubkey,
  readSplTokenAccountAmount,
  toBase64,
  utf8,
} from './solana/codec'
import {
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

// ============================================================================
// HTTP Helpers & CORS
// ============================================================================

function parseCluster(raw: string | null | undefined, fallback: Cluster = 'mainnet'): Cluster {
  return raw?.trim().toLowerCase() === 'devnet' ? 'devnet' : fallback
}

function parseProvider(raw: string | null | undefined): AggregatorSelection | undefined {
  if (!raw) return undefined
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
  return json(request, cfg.corsOrigins, {
    ok: true,
    protocolVersion: PROTOCOL_VERSION,
    service: 'audren-relay',
    domain: url.host,
    programId: AUDREN_PROGRAM_ID_STR,
    cluster: requestedCluster,
    configured: activeCluster.configured,
    checkpointSupport: true,
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
      checkpoint: {
        tag: TAG_PUBLISH_CHECKPOINT,
        permissionless: true,
        endpoint: '/v1/checkpoint',
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
    // Atomic WSOL unwrap withdraw pays relayer fee directly in native SOL lamports to `relayerPubkey`.
    if (op === 'withdraw' && unwrapWsol) {
      const [rentSchedule, prices] = await Promise.all([
        fetchLiveRentSchedule(rpcUrl),
        cluster === 'mainnet'
          ? fetchMintPricesUsd(env, [WSOL_MINT_STR])
          : Promise.resolve({} as Record<string, number>),
      ])
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
      const [rentSchedule, prices] = await Promise.all([
        fetchLiveRentSchedule(rpcUrl),
        cluster === 'mainnet'
          ? fetchMintPricesUsd(env, [WSOL_MINT_STR])
          : Promise.resolve({} as Record<string, number>),
      ])
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
        relayerPubkey: relayer?.pubkeyB58 ?? null,
        feeRecipient: null,
        feeShieldedAddress: fvkInfo?.shieldedAddress ?? null,
        feeRecipientExists: true,
        solPriceUsd: prices[WSOL_MINT_STR] ?? null,
        feeTokenPriceUsd: prices[WSOL_MINT_STR] ?? null,
      })
      return json(request, cfg.corsOrigins, quote)
    }

    const [mintMetas, rentSchedule, prices] = await Promise.all([
      fetchMintMetas(rpcUrl, [rawMint]),
      fetchLiveRentSchedule(rpcUrl),
      cluster === 'mainnet'
        ? fetchMintPricesUsd(env, [WSOL_MINT_STR, rawMint])
        : Promise.resolve({} as Record<string, number>),
    ])
    const meta = mintMetas[rawMint]
    if (!meta?.isValidMint) {
      return json(
        request,
        cfg.corsOrigins,
        { error: 'mint must be a valid on-chain SPL or Token-2022 mint' },
        400,
      )
    }
    let feeRecipient: string | null = null
    let feeRecipientExists = false
    if (relayer && op !== 'transfer') {
      feeRecipient = base58Encode(
        deriveAta(relayer.pubkey, base58Decode(meta.tokenProgram), base58Decode(rawMint)),
      )
      const [acc] = await fetchMultipleAccounts(rpcUrl, [feeRecipient], {
        dataSlice: { offset: 0, length: 0 },
      })
      feeRecipientExists = acc !== null
    }
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
      hasUnsafeSelfPayExt: meta.hasUnsafeSelfPayExt,
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
    try {
      params = (await request.json()) as typeof params
    } catch {
      return json(request, cfg.corsOrigins, { error: 'Invalid JSON body' }, 400)
    }
  }

  const cluster = parseCluster(params.cluster, 'mainnet')
  const rpcUrl = getRpcUrl(env, cluster)
  if (!rpcUrl) {
    return json(request, cfg.corsOrigins, { error: `${cluster} RPC is not configured` }, 503)
  }

  const inputMint = params.inputMint?.trim() ?? ''
  const outputMint = params.outputMint?.trim() ?? ''
  const amount = String(params.amount ?? '').trim()
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
  const includeFee = params.includeFee === false || params.includeFee === 'false' ? false : true

  if (params.provider && !parseProvider(params.provider)) {
    return json(
      request,
      cfg.corsOrigins,
      { error: `Unknown provider "${params.provider}". Valid: jupiter, bedrock, dflow, titan, okx, auto` },
      400,
    )
  }
  const providerSelection = parseProvider(params.provider)

  const relayer = getRelayerPubkeyForCluster(env, cluster, params.relayerPubkey?.trim() || undefined)
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

    let relayerFeeAtaB58: string | null = null
    if (includeFee && relayer) {
      relayerFeeAtaB58 = base58Encode(deriveAta(relayer.pubkey, outTpBytes, outMintBytes))
    }
    const ataCheckList = [vaultInAta, vaultOutAta, escrowInAta, escrowOutAta]
    if (relayerFeeAtaB58) ataCheckList.push(relayerFeeAtaB58)
    const ataInfos = await fetchMultipleAccounts(rpcUrl, ataCheckList, {
      dataSlice: { offset: 0, length: 0 },
    })
    const missingVaultEscrowAtaCount = [0, 1, 2, 3].filter((i) => !ataInfos[i]).length
    const feeAccountExists = relayerFeeAtaB58 !== null && ataInfos[4] !== null

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
      feeAccount: includeFee ? relayerFeeAtaB58 : null,
      feeAccountExists,
      hasUnsafeSelfPayExt: outMeta.hasUnsafeSelfPayExt,
      extraAtaCount: missingVaultEscrowAtaCount,
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
        feeAccount: includeFee ? relayerFeeAtaB58 : null,
        feeAccountExists,
        hasUnsafeSelfPayExt: outMeta.hasUnsafeSelfPayExt,
        extraAtaCount: missingVaultEscrowAtaCount,
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
        relayerOwner: relayer?.pubkeyB58,
        relayerFeeAta: feePlan.feeAccount ?? undefined,
        escrowPubkey,
      })
      // Refine feePlan USD numbers against the actual quoted outAmount & platformFee
      const actualSwapUsd =
        outPriceUsd && outPriceUsd > 0
          ? (Number(quoteResult.winner.outAmount) / Math.pow(10, outMeta.decimals)) * outPriceUsd
          : feePlan.estimatedSwapUsd
      const actualFeeUsd =
        quoteResult.winner.platformFee?.amount && outPriceUsd && outPriceUsd > 0
          ? (Number(quoteResult.winner.platformFee.amount) / Math.pow(10, outMeta.decimals)) *
            outPriceUsd
          : feePlan.estimatedFeeUsd
      feePlan = {
        ...feePlan,
        estimatedSwapUsd: actualSwapUsd,
        estimatedFeeUsd: actualFeeUsd,
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
  let body: {
    cluster?: string
    provider?: AggregatorId
    quoteResponse?: Record<string, unknown>
    inputMint?: string
    outputMint?: string
    shardId?: number
    relayerPubkey?: string
    includeFee?: boolean
  }
  try {
    body = (await request.json()) as typeof body
  } catch {
    return json(request, cfg.corsOrigins, { error: 'Invalid JSON body' }, 400)
  }

  const cluster = parseCluster(body.cluster, 'mainnet')
  const rpcUrl = getRpcUrl(env, cluster)
  if (!rpcUrl) {
    return json(request, cfg.corsOrigins, { error: `${cluster} RPC is not configured` }, 503)
  }

  const provider = (body.provider ?? cfg.defaultAggregator) as AggregatorId
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

  if (!body.quoteResponse || typeof body.quoteResponse !== 'object') {
    return json(request, cfg.corsOrigins, { error: 'Missing quoteResponse' }, 400)
  }

  const inputMint = (body.inputMint ?? String(body.quoteResponse.inputMint ?? '')).trim()
  const outputMint = (body.outputMint ?? String(body.quoteResponse.outputMint ?? '')).trim()
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
  const relayer = getRelayerPubkeyForCluster(env, cluster, body.relayerPubkey?.trim() || undefined)

  // Detect whether the quote carries a platformFeeBps > 0
  const rawPlatformFee = body.quoteResponse.platformFee as { feeBps?: number } | null | undefined
  const rawBedrockFee = body.quoteResponse.fee as { feeBps?: number } | null | undefined
  const quotedFeeBps = Number(rawPlatformFee?.feeBps ?? rawBedrockFee?.feeBps ?? 0)
  const collectFee = body.includeFee !== false && quotedFeeBps > 0 && relayer !== null

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
    if (!ataInfos[0]) {
      missingAtas.push({
        label: 'vaultIn',
        ata: vaultInAta,
        owner: vaultAuthPubkey,
        mint: inputMint,
        tokenProgram: inMeta.tokenProgram,
      })
    }
    if (!ataInfos[1]) {
      missingAtas.push({
        label: 'vaultOut',
        ata: vaultOutAta,
        owner: vaultAuthPubkey,
        mint: outputMint,
        tokenProgram: outMeta.tokenProgram,
      })
    }
    if (!ataInfos[2]) {
      missingAtas.push({
        label: 'escrowIn',
        ata: escrowInAta,
        owner: escrowPubkey,
        mint: inputMint,
        tokenProgram: inMeta.tokenProgram,
      })
    }
    if (!ataInfos[3]) {
      missingAtas.push({
        label: 'escrowOut',
        ata: escrowOutAta,
        owner: escrowPubkey,
        mint: outputMint,
        tokenProgram: outMeta.tokenProgram,
      })
    }
    if (relayerFeeAta && relayer && !ataInfos[4]) {
      missingAtas.push({
        label: 'relayerFee',
        ata: relayerFeeAta,
        owner: relayer.pubkeyB58,
        mint: outputMint,
        tokenProgram: outMeta.tokenProgram,
      })
    }

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
      computeUnitLimit: built.computeUnitLimit,
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
  let body: RelaySubmitRequest
  try {
    body = (await request.json()) as RelaySubmitRequest
  } catch {
    return json(request, cfg.corsOrigins, { error: 'Invalid JSON body' }, 400)
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

  const requestedPayer =
    Array.isArray(body.instructions) && typeof body.instructions[0]?.accounts?.[0]?.pubkey === 'string'
      ? body.instructions[0]!.accounts[0]!.pubkey
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
        auditedSwapRouterPrograms: cfg.auditedSwapRouterPrograms,
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

  const defaultCu =
    verdict.audrenInstructions.length > 1
      ? Math.min(verdict.audrenInstructions.length * 320_000, 1_400_000)
      : 850_000
  const rawCu = body.computeUnitLimit === undefined ? defaultCu : Number(body.computeUnitLimit)
  if (!Number.isFinite(rawCu) || rawCu < 0) {
    return json(request, cfg.corsOrigins, { error: 'computeUnitLimit must be a non-negative number' }, 400)
  }
  const rawPriorityStr =
    body.priorityFeeLamports === undefined ? '5000' : String(body.priorityFeeLamports).trim()
  if (!/^\d+$/.test(rawPriorityStr)) {
    return json(request, cfg.corsOrigins, { error: 'priorityFeeLamports must be a non-negative integer string' }, 400)
  }
  const parsedPriority = BigInt(rawPriorityStr)
  const cappedPriority = parsedPriority > 50_000n ? 50_000n : parsedPriority

  const clientIp = extractClientIp(request)
  const guard = getGuardStub(env)

  // Pre-simulation guard: hashes IP inside DO using ephemeral in-memory daily 32-byte random salt,
  // atomically deduplicates all nullifiers across the single ix or batch without linking IP to nullifiers.
  const beginDecision = await guard.begin({ clientIp, nullifiers: verdict.nullifiers })
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
  try {
    // Now that per-IP rate limits & nullifier dedup passed, decrypt & verify Mode 1 shielded `cm2` fee notes.
    resolveShieldedCm2Fees(verdict, fvkInfo?.fvk ?? null)

    // 2. Fetch blockhash + pre-simulation balances (with `context.slot`) + PoolState + all touched
    //    LaneTreeStates, LaneRentVaults, primary/rollover page PDAs, and setupAtas in ONE RPC batch.
    const watchAddresses = [relayer.pubkeyB58]
    const watchedFeeAtaIdx = verdict.watchedRelayerFeeAta ? watchAddresses.push(verdict.watchedRelayerFeeAta) - 1 : -1
    const watchedNativeRecipientIdx =
      verdict.nativeSolFeeToRelayer > 0n &&
      verdict.nativeSolFeeRecipient &&
      verdict.nativeSolFeeRecipient !== relayer.pubkeyB58
        ? watchAddresses.push(verdict.nativeSolFeeRecipient) - 1
        : -1

    const preFetchAddresses: string[] = [...watchAddresses]
    const seenFetch = new Set<string>(watchAddresses)
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
    }

    const [bhRes, preCtx] = await Promise.all([
      rpcCall<{ value: { blockhash: string } }>(rpcUrl, 'getLatestBlockhash', [
        { commitment: 'confirmed' },
      ]),
      fetchMultipleAccountsWithContext(rpcUrl, preFetchAddresses),
    ])

    let preSlot = preCtx.slot
    const preAccounts = [...preCtx.accounts]
    const fetchedMap = new Map<string, FetchedAccountMeta | null>()
    const preAccountInfoMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string } | null>()
    preFetchAddresses.forEach((addr, idx) => {
      const acc = preAccounts[idx] ?? null
      preAccountInfoMap.set(addr, acc)
      fetchedMap.set(addr, acc ? { bytes: acc.bytes, owner: acc.owner } : null)
    })

    // 3. Auto-prepend deduplicated `OpenPage` (Tag 2, reimbursed from `LaneRentVault`) for any missing
    //    primary or genuinely near-rollover page PDAs across all lanes touched by the single ix or batch.
    const pagePlan = planBatchMissingOpenPageIxs({
      payerB58: relayer.pubkeyB58,
      entries: verdict.audrenInstructions.map((entry) => ({
        poolId: entry.poolId,
        outLaneId: entry.outLaneId,
        outputCount: entry.outputCount,
        nullifierCount: entry.nullifiers.length,
        pages: entry.pages,
      })),
      fetchedAccounts: fetchedMap,
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

    // 4. Build full instruction list (setupAtas + OpenPage Tag 2 + allowlisted preInstructions + Audren ix(s))
    const instructions: SolanaInstruction[] = []

    for (const s of verdict.setupAtas) {
      instructions.push(
        buildCreateAtaIdempotentIx({
          payer: relayer.pubkey,
          ata: s.ata,
          owner: s.owner,
          mint: s.mint,
          tokenProgram: s.tokenProgram,
        }),
      )
    }

    for (const openIx of pagePlan.openPageIxs) {
      instructions.push(openIx)
    }

    // Prepend strictly-allowlisted zero-signer DeFi refresh cranks (Tag 6 only)
    for (const preIx of verdict.preInstructions) {
      instructions.push(preIx)
    }

    for (const entry of verdict.audrenInstructions) {
      instructions.push({
        programId: AUDREN_PROGRAM_ID,
        accounts: entry.decodedAccounts,
        data: entry.ixData,
      })
    }

    const baseCu = Math.max(Math.trunc(rawCu), 200_000)
    const requestedCu =
      baseCu +
      verdict.preInstructions.length * 40_000 +
      pagePlan.openPageIxs.length * 20_000
    const cuLimit = Math.min(requestedCu, 1_400_000)

    // 5. Compile & sign Solana v1 (0x81) single transaction (strictly <= 4,096 B and <= 64 accounts)
    let signed: ReturnType<typeof buildAndSignV1Transaction>
    try {
      signed = buildAndSignV1Transaction(relayer.secret32, bhRes.value.blockhash, instructions, {
        computeUnitLimit: cuLimit,
        priorityFeeLamports: cappedPriority,
      })
    } catch (txErr) {
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

    // 6. Pre-flight simulation on Solana RPC before committing lamports:
    //    measures exact SOL outflow and exact fee token/SOL inflow directly from Solana runtime.
    let sim = await simulateV1Transaction(rpcUrl, signed.wireBytes, watchAddresses)

    // For zero-protocol-fee (`relayerFee === 0`) allowlisted aggregator swaps, pin pre-balance read
    // and simulation to the exact same `context.slot` (retrying once if the slot ticked between calls)
    // so concurrent inflows into the relayer fee ATA between slots can never be replayed as fee credit.
    if (
      !sim.err &&
      verdict.isZeroFeeAuditedRouterSwap &&
      verdict.watchedRelayerFeeAta &&
      preSlot !== null &&
      sim.slot !== null &&
      sim.slot !== preSlot
    ) {
      const refreshed = await fetchMultipleAccountsWithContext(rpcUrl, watchAddresses)
      const refreshedSim = await simulateV1Transaction(rpcUrl, signed.wireBytes, watchAddresses)
      preSlot = refreshed.slot
      for (let wi = 0; wi < watchAddresses.length; wi++) {
        preAccounts[wi] = refreshed.accounts[wi] ?? null
      }
      sim = refreshedSim
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
    const cachedRent = getCachedLiveRentSchedule(rpcUrl)
    const nullifierRentFloorUnit = cachedRent?.nullifierRentLamports ?? 890_880n
    const ataRentFloorUnit = cachedRent?.ataRentLamports ?? 2_039_280n
    const subRentFloor = cachedRent?.subtreePageRentLamports ?? 58_340_000n
    const srRentFloor = cachedRent?.subrootPageRentLamports ?? 68_140_000n
    const memoRentFloor = cachedRent?.memoPageRentLamports ?? 72_149_760n
    const nfPageRentFloor = cachedRent?.nfPageRentLamports ?? 68_140_000n
    const divCeil = (a: bigint, b: bigint) => (a + b - 1n) / b

    const poolAcc = preAccountInfoMap.get(pool0PdaB58)
    let poolNoteRentUnit = cachedRent?.pageRentPerNoteLamports ?? 0n
    let poolNfRentUnit = cachedRent?.nfPageRentPerNfLamports ?? 0n
    if (poolAcc && poolAcc.owner === AUDREN_PROGRAM_ID_STR && poolAcc.bytes.length > 0) {
      try {
        const decodedPool = decodePoolState(poolAcc.bytes)
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
    const uncreatedSetupAtasCount = verdict.setupAtas.filter(
      (s) => preAccountInfoMap.get(base58Encode(s.ata)) === null,
    ).length

    // Track per-lane available `LaneRentVault` balance to compute exact unsubsidized OpenPage deficit floor
    let openPageDeficitFloor = 0n
    const laneVaultAvail = new Map<string, bigint>()
    for (const openIx of pagePlan.openPageIxs) {
      const vaultPdaB58 = base58Encode(openIx.accounts[3]!.pubkey)
      const vaultAcc = preAccountInfoMap.get(vaultPdaB58)
      if (!vaultAcc) continue
      if (!laneVaultAvail.has(vaultPdaB58)) {
        const rawVault = BigInt(vaultAcc.lamports)
        laneVaultAvail.set(
          vaultPdaB58,
          rawVault > nullifierRentFloorUnit ? rawVault - nullifierRentFloorUnit : 0n,
        )
      }
      const pageKind = openIx.data[1]!
      const pageRent =
        pageKind === OPEN_PAGE_KIND_SUBTREE
          ? subRentFloor
          : pageKind === OPEN_PAGE_KIND_SUBROOT
            ? srRentFloor
            : pageKind === OPEN_PAGE_KIND_MEMO
              ? memoRentFloor
              : nfPageRentFloor
      const pagePdaB58 = base58Encode(openIx.accounts[4]!.pubkey)
      const existingPageLamports = BigInt(preAccountInfoMap.get(pagePdaB58)?.lamports ?? 0)
      const needed = pageRent > existingPageLamports ? pageRent - existingPageLamports : 0n
      const avail = laneVaultAvail.get(vaultPdaB58) ?? 0n
      const subsidy = avail < needed ? avail : needed
      laneVaultAvail.set(vaultPdaB58, avail - subsidy)
      openPageDeficitFloor += needed - subsidy
    }

    const minExpectedCostLamports =
      5_000n +
      cappedPriority +
      BigInt(verdict.nullifiers.length) * (nullifierRentFloorUnit + poolNfRentUnit) +
      BigInt(uncreatedSetupAtasCount) * ataRentFloorUnit +
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
    const simulatedCostLamports =
      rawOutflowLamports > minExpectedCostLamports ? rawOutflowLamports : minExpectedCostLamports

    // Measure & strictly cap SPL/Token-2022 fee tokens earned by the relayer during simulation:
    //   - Protocol-native `relayerFee > 0n` (Mode 2 / Mode 3): capped strictly at parsed `relayerFee`
    //     so concurrent token inflows between `preSlot` and `simSlot` can never inflate fee credit.
    //   - Zero-protocol-fee (`relayerFee === 0n`) allowlisted router swap: requires `sim.slot === preSlot`
    //     so concurrent token inflows between slots can never be replayed.
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
    } else if (verdict.isZeroFeeAuditedRouterSwap) {
      simulatedFeeUnits =
        preSlot !== null && sim.slot !== null && sim.slot === preSlot ? rawSimulatedFeeUnits : 0n
    }

    // Dynamically value verified fee earnings in lamports (Modes 1 single/batch, 2, & 3!)
    // Enforces `SELF_PAY_FEE_MINTS` allowlist, `parseMintSafetyInfo` (via `hasUnsafeSelfPayExt`),
    // AND conservative `2x` active Token-2022 `TransferFeeConfig` haircut at submit time.
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
          const { netAmount } = applyToken2022FeeHaircut({
            tokenProgram: feeMeta.tokenProgram,
            mintData: entry?.rawBytes ?? null,
            currentEpoch,
            grossAmount: simulatedFeeUnits,
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
      isSelfPaying && pagePlan.openPageIxs.length > 0 ? 300_000_000n : MAX_TX_OUTFLOW_LAMPORTS
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

    // Never allow unvetted (non-allowlisted) mint withdrawals to siphon relayer SOL into attacker-owned
    // `isWithdrawRecipientAta` setupAtas without self-pay coverage.
    if (
      verdict.hasWithdrawRecipientAta &&
      !isSelfPaying &&
      verdict.transactMeta?.mint &&
      !cfg.selfPayFeeMints.has(verdict.transactMeta.mint)
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
          error:
            'Withdraw recipient ATA setup for non-allowlisted mints cannot be funded by the relay without allowlisted self-pay coverage.',
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
      toBase64(signed.wireBytes),
      { encoding: 'base64', preflightCommitment: 'confirmed', maxRetries: 3 },
    ])
    let slot = 0
    try {
      const conf = await waitForConfirmation(rpcUrl, sentSig)
      slot = conf.slot
    } catch (confErr) {
      // Transaction was already broadcast and may still land on-chain — commit conservatively
      // instead of releasing the pending budget reservation.
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

    const actualOut = body.vaultOutAta
      ? await resolveVaultOutDelta(rpcUrl, sentSig, body.vaultOutAta)
      : null

    return json(request, cfg.corsOrigins, {
      ok: true,
      cluster,
      opKind: verdict.opKind,
      instructionCount: verdict.audrenInstructions.length,
      billingMode: isSelfPaying ? 'self_paying' : 'sponsored',
      txVersion: signed.version,
      txWireBytes: signed.wireLen,
      accountCount: signed.accountCount,
      relayerPubkey: relayer.pubkeyB58,
      priorityFeeLamports: cappedPriority.toString(),
      computeUnitLimit: cuLimit,
      openedPagesCount: pagePlan.openPageIxs.length,
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
  }
}

function timingSafeEqualStrings(a: string, b: string): boolean {
  const ha = sha256(utf8(a))
  const hb = sha256(utf8(b))
  let diff = 0
  for (let i = 0; i < 32; i++) diff |= ha[i]! ^ hb[i]!
  return diff === 0
}

function makeCheckpointLockAdapter(guard: DurableObjectStub<RelayGuard>): CheckpointLockAdapter {
  return {
    acquire: (req) => guard.acquireCheckpointLock(req),
    release: (req) => guard.releaseCheckpointLock(req),
  }
}

async function handleCheckpoint(request: Request, env: Env): Promise<Response> {
  const cfg = loadPolicyConfig(env)
  let body: { cluster?: string; poolId?: number } = {}
  const rawText = await request.text()
  if (rawText.trim().length > 0) {
    try {
      const parsed = JSON.parse(rawText) as unknown
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return json(request, cfg.corsOrigins, { error: 'Request body must be a JSON object' }, 400)
      }
      body = parsed as { cluster?: string; poolId?: number }
    } catch {
      return json(request, cfg.corsOrigins, { error: 'Invalid JSON body' }, 400)
    }
  }

  const cluster = parseCluster(body.cluster, 'mainnet')
  const rawPoolId = body.poolId === undefined ? 0 : Number(body.poolId)
  if (!Number.isInteger(rawPoolId) || rawPoolId < 0) {
    return json(request, cfg.corsOrigins, { error: 'poolId must be a non-negative integer' }, 400)
  }
  if (rawPoolId !== 0) {
    return json(
      request,
      cfg.corsOrigins,
      { error: 'Only canonical Pool #0 is permitted on this relay' },
      400,
    )
  }

  const rpcUrl = getRpcUrl(env, cluster)
  const relayer = getRelayerPubkeyForCluster(env, cluster)
  if (!rpcUrl || !relayer) {
    const reqHost = new URL(request.url).host
    return json(
      request,
      cfg.corsOrigins,
      { error: `${cluster} privacy relayer is not configured on ${reqHost}` },
      503,
    )
  }

  const clientIp = extractClientIp(request)
  const guard = getGuardStub(env)
  const rateDecision = await guard.checkCheckpointRateLimit({ clientIp, cluster })
  if (!rateDecision.allowed) {
    return json(
      request,
      cfg.corsOrigins,
      {
        error: rateDecision.reason ?? 'Checkpoint rate limit reached',
        code: rateDecision.code ?? 'CHECKPOINT_RATE_LIMITED',
        retryAfterSec: rateDecision.retryAfterSec,
      },
      rateDecision.status ?? 429,
      rateDecision.retryAfterSec ? { 'retry-after': String(rateDecision.retryAfterSec) } : undefined,
    )
  }

  try {
    const result = await publishCheckpointIfNeeded({
      rpcUrl,
      cluster,
      poolId: rawPoolId,
      relayerSecret32: relayer.secret32,
      lock: makeCheckpointLockAdapter(guard),
      confirm: true,
    })
    return json(request, cfg.corsOrigins, result)
  } catch (err) {
    if (err instanceof CheckpointError) {
      return json(
        request,
        cfg.corsOrigins,
        {
          error: err.message,
          ...(err.code ? { code: err.code } : {}),
          ...(err.retryAfterSec ? { retryAfterSec: err.retryAfterSec } : {}),
        },
        err.status,
        err.retryAfterSec ? { 'retry-after': String(err.retryAfterSec) } : undefined,
      )
    }
    return json(
      request,
      cfg.corsOrigins,
      { error: sanitizeError(err, 'Checkpoint publish failed') },
      502,
    )
  }
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
  'POST /v1/checkpoint',
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

    if ((url.pathname === '/' || url.pathname === '/health') && request.method === 'GET') {
      return json(request, cfg.corsOrigins, {
        ok: true,
        service: 'audren-relay',
        domain: url.host,
        programId: AUDREN_PROGRAM_ID_STR,
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

    if (url.pathname === '/v1/checkpoint' && request.method === 'POST') {
      return handleCheckpoint(request, env)
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
    const ckptLock = makeCheckpointLockAdapter(getGuardStub(env))
    ctx.waitUntil(
      Promise.all([
        runAutoRefill(env, cfg).then((report) => {
          console.log('[audren-relay cron refill]', JSON.stringify(report))
        }),
        runMaintenanceCrank(env, 'mainnet', ckptLock).then((crank) => {
          console.log('[audren-relay cron crank mainnet]', JSON.stringify(crank))
        }),
        runMaintenanceCrank(env, 'devnet', ckptLock).then((crank) => {
          console.log('[audren-relay cron crank devnet]', JSON.stringify(crank))
        }),
      ]).catch((err) => {
        console.error('[audren-relay cron error]', err)
      }),
    )
  },
} satisfies ExportedHandler<Env>
