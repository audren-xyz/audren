import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import {
  getAggregatorAdapter,
  listAggregators,
  quoteWithSelection,
} from './aggregators/registry'
import { runAutoRefill, runV2MaintenanceCrank } from './cron/refill'
import {
  getRelayerFvk,
  getRelayerSecretsB64,
  getRpcUrl,
  loadPolicyConfig,
  type Env,
} from './env'
import { FirewallError, validateRelaySubmission } from './policy/firewall'
import { RelayGuard } from './policy/guard-do'
import { computeNativeFeeQuote, computeSwapFeePlan, fetchMintPricesUsd } from './policy/pricing'
import {
  AUDREN_PROGRAM_ID,
  AUDREN_PROGRAM_ID_STR,
  MAX_ESCROW_SHARDS,
  PROTOCOL_VERSION,
  deriveEscrowPda,
  deriveVaultAuthPda,
} from './solana/audren'
import {
  SYSTEM_PROGRAM_ID_STR,
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
  toHex,
  utf8,
} from './solana/codec'
import {
  explorerTxUrl,
  fetchBalance,
  fetchLiveRentSchedule,
  fetchMintMetas,
  fetchMultipleAccounts,
  resolveLookupTables,
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

function hashClientIp(request: Request, salt: string): string {
  const ip =
    request.headers.get('cf-connecting-ip') ??
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    'unknown'
  return toHex(sha256(utf8(`${ip}|${salt}`))).slice(0, 32)
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
  return pool[0]!
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
    const relayer = pool[0] ?? null
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
    domain: 'relay.audren.xyz',
    programId: AUDREN_PROGRAM_ID_STR,
    cluster: requestedCluster,
    configured: activeCluster.configured,
    relayerPubkey: activeCluster.relayerPubkey,
    relayerPubkeys: activeCluster.relayerPubkeys,
    relayerShieldedAddress: activeCluster.relayerShieldedAddress,
    balanceSol: activeCluster.balanceSol,
    clusters: { mainnet, devnet },
    supportedOperations: {
      transfer: {
        tag: 6,
        assetMode: 0,
        shieldedCm2Fee: activeCluster.relayerShieldedAddress !== null,
        sponsored: true,
      },
      withdraw: {
        tag: 6,
        selfPaying: true,
        nativeRelayerFee: true,
        supportsUnwrapWsol: true,
        sponsored: true,
      },
      exec_escrow: {
        tag: 7,
        selfPaying: true,
        nativeRelayerFee: true,
        supportsFeeOnOutput: true,
        supportsPreInstructions: true,
        microSwapSubsidy: cfg.allowMicroSwapSubsidy,
      },
      deposit: {
        tags: [3, 4],
        sponsored: false,
        reason: 'Deposits (DepositSol / DepositSpl) are naturally public; sign directly.',
      },
    },
    allowedPreIxPrograms: Array.from(cfg.allowedPreIxPrograms),
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
    rawOp === 'exec_escrow' || rawOp === 'swap'
      ? 'exec_escrow'
      : rawOp === 'transfer'
        ? 'transfer'
        : 'withdraw'
  const rawMint = (u.searchParams.get('mint') ?? 'native').trim()
  const rawAmount = (u.searchParams.get('amount') ?? '0').trim()
  const unwrapWsol = u.searchParams.get('unwrapWsol') === 'true'
  const feeOnOutput = u.searchParams.get('feeOnOutput') === 'true'
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

  if (!/^\d+$/.test(rawAmount)) {
    return json(request, cfg.corsOrigins, { error: 'amount must be a non-negative integer string' }, 400)
  }
  const amount = BigInt(rawAmount)

  const rpcUrl = getRpcUrl(env, cluster)
  const relayer = getRelayerPubkeyForCluster(env, cluster)
  const fvkInfo = getRelayerFvk(env, cluster)
  if (!rpcUrl) {
    return json(request, cfg.corsOrigins, { error: `${cluster} RPC is not configured` }, 503)
  }

  const isNativeSolFee =
    rawMint === 'native' ||
    rawMint === SYSTEM_PROGRAM_ID_STR ||
    (op === 'withdraw' && unwrapWsol)
  const feeSide = op === 'transfer' ? 'shielded_cm2' : feeOnOutput ? 'out' : 'in'

  try {
    if (isNativeSolFee) {
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
        isNativeSolFee: true,
        feeSide,
        feeMint: SYSTEM_PROGRAM_ID_STR,
        feeTokenProgram: null,
        feeDecimals: 9,
        amount,
        outputCount,
        missingAtaCount,
        feeRecipient: relayer?.pubkeyB58 ?? null,
        feeShieldedAddress: fvkInfo?.shieldedAddress ?? null,
        feeRecipientExists: relayer !== null,
        solPriceUsd: prices[WSOL_MINT_STR] ?? null,
        feeTokenPriceUsd: prices[WSOL_MINT_STR] ?? null,
      })
      return json(request, cfg.corsOrigins, quote)
    }

    if (!isValidPubkey(rawMint)) {
      return json(request, cfg.corsOrigins, { error: 'Invalid mint pubkey' }, 400)
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
      isNativeSolFee: false,
      feeSide,
      feeMint: rawMint,
      feeTokenProgram: meta.tokenProgram,
      feeDecimals: meta.decimals,
      amount,
      outputCount,
      missingAtaCount,
      hasUnsafeSelfPayExt: meta.hasUnsafeSelfPayExt,
      feeRecipient,
      feeShieldedAddress: fvkInfo?.shieldedAddress ?? null,
      feeRecipientExists,
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

  const rawShard = params.shardId === undefined ? 0 : Number(params.shardId)
  if (!Number.isFinite(rawShard)) {
    return json(request, cfg.corsOrigins, { error: 'shardId must be a finite integer' }, 400)
  }
  const shardId = Math.min(Math.max(Math.trunc(rawShard), 0), MAX_ESCROW_SHARDS - 1)
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

  const relayer = getRelayerPubkeyForCluster(env, cluster)
  const escrowPubkey = base58Encode(deriveEscrowPda(0, shardId).address)

  try {
    // Dynamically fetch on-chain mint metadata (tokenProgram + decimals), live rent schedule,
    // and live USD prices — ZERO hardcoded mint lists or rent estimates!
    const [mintMetas, rentSchedule, prices] = await Promise.all([
      fetchMintMetas(rpcUrl, [inputMint, outputMint]),
      fetchLiveRentSchedule(rpcUrl),
      cluster === 'mainnet'
        ? fetchMintPricesUsd(env, [WSOL_MINT_STR, inputMint, outputMint])
        : Promise.resolve({} as Record<string, number>),
    ])

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

    let relayerFeeAtaB58: string | null = null
    let feeAccountExists = false
    if (includeFee && relayer) {
      const feeAtaBytes = deriveAta(
        relayer.pubkey,
        base58Decode(outMeta.tokenProgram),
        base58Decode(outputMint),
      )
      relayerFeeAtaB58 = base58Encode(feeAtaBytes)
      const [feeAcc] = await fetchMultipleAccounts(rpcUrl, [relayerFeeAtaB58], {
        dataSlice: { offset: 0, length: 0 },
      })
      feeAccountExists = feeAcc !== null
    }

    const solPriceUsd = prices[WSOL_MINT_STR] ?? null
    const inPriceUsd = prices[inputMint] ?? null
    const outPriceUsd = prices[outputMint] ?? null

    // Estimate output amount from live USD prices when available so we only make 1 aggregator call
    let preEstimatedOut: bigint | null = null
    if (inPriceUsd && outPriceUsd && inPriceUsd > 0 && outPriceUsd > 0) {
      const inUi = Number(amount) / Math.pow(10, inMeta.decimals)
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
    })

    // If USD prices weren't available before quoting, fetch a baseline quote first to know real outAmount
    let quoteResult: Awaited<ReturnType<typeof quoteWithSelection>>
    if (preEstimatedOut === null) {
      const baseline = await quoteWithSelection(env, cfg, providerSelection, {
        inputMint,
        outputMint,
        amount,
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
      })
      if (feePlan.platformFeeBps > 0 && includeFee && relayer) {
        quoteResult = await quoteWithSelection(env, cfg, baseline.winner.provider, {
          inputMint,
          outputMint,
          amount,
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
        amount,
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
      escrowPda: escrowPubkey,
      shardId,
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

  const rawShard = body.shardId === undefined ? 0 : Number(body.shardId)
  if (!Number.isFinite(rawShard)) {
    return json(request, cfg.corsOrigins, { error: 'shardId must be a finite integer' }, 400)
  }
  const shardId = Math.min(Math.max(Math.trunc(rawShard), 0), MAX_ESCROW_SHARDS - 1)
  const escrowBytes = deriveEscrowPda(0, shardId).address
  const vaultAuthBytes = deriveVaultAuthPda(0).address
  const escrowPubkey = base58Encode(escrowBytes)
  const vaultAuthPubkey = base58Encode(vaultAuthBytes)
  const relayer = getRelayerPubkeyForCluster(env, cluster)

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
  const requestedPayer =
    Array.isArray(body.accounts) && typeof body.accounts[0]?.pubkey === 'string'
      ? body.accounts[0]!.pubkey
      : undefined
  const relayer = getRelayerPubkeyForCluster(env, cluster, requestedPayer)
  const fvkInfo = getRelayerFvk(env, cluster)
  if (!rpcUrl || !relayer) {
    return json(
      request,
      cfg.corsOrigins,
      { error: `${cluster} privacy relayer is not configured on relay.audren.xyz` },
      503,
    )
  }

  // 1. Strict Zero-Trust Audren Firewall (permits JoinSplit Tag 6 & ExecViaEscrow Tag 7; rejects Deposits)
  let verdict: ReturnType<typeof validateRelaySubmission>
  try {
    verdict = validateRelaySubmission(
      body,
      relayer.pubkey,
      cfg.allowedPreIxPrograms,
      fvkInfo?.fvk ?? null,
    )
  } catch (err) {
    if (err instanceof FirewallError) {
      return json(request, cfg.corsOrigins, { error: err.message, code: 'FIREWALL_REJECTED' }, err.status)
    }
    return json(request, cfg.corsOrigins, { error: sanitizeError(err, 'Firewall error') }, 400)
  }

  const rawCu = body.computeUnitLimit === undefined ? 850_000 : Number(body.computeUnitLimit)
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

  const ipHash = hashClientIp(request, relayer.pubkeyB58)
  const guard = getGuardStub(env)

  // Pre-simulation guard: deduplicate concurrent nullifiers and block failure floods before RPC
  const beginDecision = await guard.begin({ ipHash, nullifiers: verdict.nullifiers })
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

  let lockHeld = true
  let reservationId: string | undefined
  try {
    // 2. Build full instruction list (validated setupAtas + strictly allowlisted preInstructions + Audren ix)
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

    // Prepend strictly-allowlisted zero-signer DeFi refresh cranks (Tag 7 only)
    for (const preIx of verdict.preInstructions) {
      instructions.push(preIx)
    }

    instructions.push({
      programId: AUDREN_PROGRAM_ID,
      accounts: verdict.decodedAccounts,
      data: verdict.ixData,
    })

    const requestedCu = Math.trunc(rawCu) + verdict.preInstructions.length * 40_000
    const cuLimit = Math.min(Math.max(requestedCu, 200_000), 1_400_000)

    // 3. Fetch blockhash + pre-simulation balances in ONE parallel RPC batch
    const watchAddresses = [relayer.pubkeyB58]
    if (verdict.watchedRelayerFeeAta) watchAddresses.push(verdict.watchedRelayerFeeAta)

    const [bhRes, preAccounts] = await Promise.all([
      rpcCall<{ value: { blockhash: string } }>(rpcUrl, 'getLatestBlockhash', [
        { commitment: 'confirmed' },
      ]),
      fetchMultipleAccounts(rpcUrl, watchAddresses),
    ])

    const preRelayerLamports = BigInt(preAccounts[0]?.lamports ?? 0)
    const preFeeUnits = verdict.watchedRelayerFeeAta
      ? readSplTokenAccountAmount(preAccounts[1]?.bytes ?? null)
      : 0n

    // 4. Compile & sign Solana v1 (0x81) single transaction
    const signed = buildAndSignV1Transaction(relayer.secret32, bhRes.value.blockhash, instructions, {
      computeUnitLimit: cuLimit,
      priorityFeeLamports: cappedPriority,
    })

    // 5. Pre-flight simulation on Solana RPC before committing lamports:
    //    measures exact SOL outflow and exact fee token/SOL inflow directly from Solana runtime.
    const sim = await simulateV1Transaction(rpcUrl, signed.wireBytes, watchAddresses)
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
    if (verdict.watchedRelayerFeeAta && !sim.accounts[1]) {
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

    const postRelayerLamports = BigInt(sim.accounts[0].lamports)
    const rawOutflowLamports =
      preRelayerLamports > postRelayerLamports ? preRelayerLamports - postRelayerLamports : 0n
    // Enforce a minimum gas floor (5,000 signature + priority fee) when not offset by native SOL fee
    // and cap maximum per-tx relayer outflow to protect against runaway rent creation.
    const minBaselineLamports = 5_000n + cappedPriority
    const simulatedCostLamports =
      verdict.nativeSolFeeToRelayer > 0n
        ? rawOutflowLamports
        : rawOutflowLamports > minBaselineLamports
          ? rawOutflowLamports
          : minBaselineLamports

    const MAX_TX_OUTFLOW_LAMPORTS = 50_000_000n // 0.05 SOL hard per-tx safety ceiling
    if (simulatedCostLamports > MAX_TX_OUTFLOW_LAMPORTS) {
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
          error: `Simulated relayer SOL outflow (${simulatedCostLamports.toString()} lamports) exceeds per-tx safety ceiling`,
          code: 'COST_CEILING_EXCEEDED',
        },
        400,
      )
    }

    // Measure exact SPL/Token-2022 fee tokens earned by the relayer during simulation
    const postFeeUnits =
      verdict.watchedRelayerFeeAta && sim.accounts[1]
        ? readSplTokenAccountAmount(sim.accounts[1].bytes)
        : 0n
    const simulatedFeeUnits = postFeeUnits > preFeeUnits ? postFeeUnits - preFeeUnits : 0n

    // Dynamically value simulated fee earnings in lamports (Modes 1, 2 & 3!)
    let feeEquivalentLamports = 0n
    if (verdict.nativeSolFeeToRelayer > 0n) {
      // Mode 2/3 Native SOL or `unwrap_wsol` Withdraw paid lamports directly to `relayerPubkey`!
      feeEquivalentLamports = verdict.nativeSolFeeToRelayer
    } else if (verdict.shieldedCm2Fee) {
      // Mode 1 Private Transfer: shielded `cm2` fee note cryptographically verified via read-only FVK!
      const { mint: cm2Mint, amount: cm2Amt } = verdict.shieldedCm2Fee
      if (cm2Mint === SYSTEM_PROGRAM_ID_STR || cm2Mint === WSOL_MINT_STR) {
        feeEquivalentLamports = cm2Amt
      } else if (cluster === 'mainnet') {
        const [mintMetas, prices] = await Promise.all([
          fetchMintMetas(rpcUrl, [cm2Mint]),
          fetchMintPricesUsd(env, [WSOL_MINT_STR, cm2Mint]),
        ])
        const feeMeta = mintMetas[cm2Mint]
        const solUsd = prices[WSOL_MINT_STR]
        const feeUsdPrice = prices[cm2Mint]
        if (
          feeMeta &&
          feeMeta.isValidMint &&
          !feeMeta.hasUnsafeSelfPayExt &&
          solUsd &&
          feeUsdPrice &&
          solUsd > 0 &&
          feeUsdPrice > 0
        ) {
          const feeUsd = (Number(cm2Amt) / Math.pow(10, feeMeta.decimals)) * feeUsdPrice
          feeEquivalentLamports = BigInt(Math.max(0, Math.floor((feeUsd / solUsd) * 1e9)))
        }
      }
    } else if (simulatedFeeUnits > 0n && verdict.watchedRelayerFeeMint) {
      if (verdict.watchedRelayerFeeMint === WSOL_MINT_STR) {
        feeEquivalentLamports = simulatedFeeUnits
      } else if (cluster === 'mainnet') {
        const [mintMetas, prices] = await Promise.all([
          fetchMintMetas(rpcUrl, [verdict.watchedRelayerFeeMint]),
          fetchMintPricesUsd(env, [WSOL_MINT_STR, verdict.watchedRelayerFeeMint]),
        ])
        const feeMeta = mintMetas[verdict.watchedRelayerFeeMint]
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
          const feeUsd = (Number(simulatedFeeUnits) / Math.pow(10, feeMeta.decimals)) * feeUsdPrice
          const feeSol = feeUsd / solUsd
          feeEquivalentLamports = BigInt(Math.max(0, Math.floor(feeSol * 1e9)))
        }
      }
    }

    // Net lamports subsidized by the relay (strict 100% coverage required for `isSelfPaying`):
    //   - For Native SOL / `unwrap_wsol` Withdraw fees, `simulatedCostLamports` is ALREADY post-fee net outflow.
    //   - For SPL/Token-2022 fees, subtract `feeEquivalentLamports` from `simulatedCostLamports`.
    const netSponsoredLamports =
      verdict.nativeSolFeeToRelayer > 0n
        ? simulatedCostLamports
        : simulatedCostLamports > feeEquivalentLamports
          ? simulatedCostLamports - feeEquivalentLamports
          : 0n
    const isSelfPaying =
      verdict.nativeSolFeeToRelayer > 0n
        ? netSponsoredLamports === 0n
        : feeEquivalentLamports > 0n && netSponsoredLamports === 0n

    if (verdict.execMeta && !isSelfPaying && !cfg.allowMicroSwapSubsidy) {
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
          error:
            'ExecViaEscrow relay fee did not cover simulated Solana rent/gas and micro-action subsidy is disabled.',
          code: 'FEE_REQUIRED',
          simulatedCostLamports: simulatedCostLamports.toString(),
          feeEquivalentLamports: feeEquivalentLamports.toString(),
        },
        402,
      )
    }

    // 6. Post-simulation guard: atomically reserve simulated net sponsored cost against daily budget & IP limits
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

    // 7. Broadcast & confirm on Solana via RPC
    let txBroadcast = false
    const sentSig = await rpcCall<string>(rpcUrl, 'sendTransaction', [
      toBase64(signed.wireBytes),
      { encoding: 'base64', preflightCommitment: 'confirmed', maxRetries: 3 },
    ])
    txBroadcast = true
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
    void txBroadcast

    // 8. Commit EXACT simulated cost into SQLite Durable Object & clear pending reservation
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
      billingMode: isSelfPaying ? 'self_paying' : 'sponsored',
      txVersion: signed.version,
      txWireBytes: signed.wireLen,
      accountCount: signed.accountCount,
      relayerPubkey: relayer.pubkeyB58,
      priorityFeeLamports: cappedPriority.toString(),
      computeUnitLimit: cuLimit,
      simulatedUnitsConsumed: sim.unitsConsumed,
      simulatedCostLamports: simulatedCostLamports.toString(),
      simulatedFeeUnits:
        verdict.nativeSolFeeToRelayer > 0n
          ? verdict.nativeSolFeeToRelayer.toString()
          : simulatedFeeUnits.toString(),
      simulatedFeeMint:
        verdict.nativeSolFeeToRelayer > 0n
          ? SYSTEM_PROGRAM_ID_STR
          : verdict.watchedRelayerFeeMint,
      simulatedFeeAccount:
        verdict.nativeSolFeeToRelayer > 0n ? relayer.pubkeyB58 : verdict.watchedRelayerFeeAta,
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
        domain: 'relay.audren.xyz',
        programId: AUDREN_PROGRAM_ID_STR,
        timestamp: new Date().toISOString(),
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
        endpoints: [
          'GET  /health',
          'GET  /v1/info?cluster=mainnet|devnet',
          'GET  /v1/fee-quote?op=withdraw|exec_escrow&mint=...&amount=...',
          'GET  /v1/aggregators',
          'GET  /v1/stats',
          'GET|POST /v1/swap/quote',
          'POST /v1/swap/instructions',
          'POST /v1/relay/submit',
        ],
      },
      404,
    )
  },

  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    const cfg = loadPolicyConfig(env)
    ctx.waitUntil(
      Promise.all([
        runAutoRefill(env, cfg).then((report) => {
          console.log('[audren-relay cron refill]', JSON.stringify(report))
        }),
        runV2MaintenanceCrank(env, 'mainnet').then((crank) => {
          console.log('[audren-relay cron crank mainnet]', JSON.stringify(crank))
        }),
        runV2MaintenanceCrank(env, 'devnet').then((crank) => {
          console.log('[audren-relay cron crank devnet]', JSON.stringify(crank))
        }),
      ]).catch((err) => {
        console.error('[audren-relay cron error]', err)
      }),
    )
  },
} satisfies ExportedHandler<Env>
