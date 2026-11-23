import type { Env } from '../env'
import type { NormalizedQuote, NormalizedSwapInstructions, RouteLegSummary } from '../types'
import type {
  AdapterQuoteRequest,
  AdapterSwapInstructionsRequest,
  AggregatorAdapter,
} from './types'

function jupiterBaseUrl(env: Env): string {
  const raw = (env.JUPITER_API_URL?.trim() || 'https://api.jup.ag').replace(/\/+$/, '')
  return raw.endsWith('/swap/v1') ? raw : `${raw}/swap/v1`
}

function jupiterHeaders(env: Env): Record<string, string> {
  return {
    accept: 'application/json',
    'content-type': 'application/json',
    ...(env.JUPITER_API_KEY?.trim() ? { 'x-api-key': env.JUPITER_API_KEY.trim() } : {}),
  }
}

async function fetchJupiterWithRetry(
  env: Env,
  pathAndQuery: string,
  init?: { method?: string; body?: string },
): Promise<Response> {
  if (!env.JUPITER_API_KEY?.trim() && !env.JUPITER_API_URL?.trim()) {
    throw new Error('Jupiter adapter not configured (set JUPITER_API_KEY or JUPITER_API_URL)')
  }
  const base = jupiterBaseUrl(env)
  const headers = jupiterHeaders(env)

  const retryDelays = [350, 850]
  let lastRes: Response | null = null

  for (let attempt = 0; attempt <= retryDelays.length; attempt++) {
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
    if (attempt < retryDelays.length) {
      const retryAfter = Number(res.headers.get('retry-after') ?? '')
      const delayMs =
        Number.isFinite(retryAfter) && retryAfter > 0
          ? Math.min(Math.max(retryAfter * 1000, 300), 1_500)
          : retryDelays[attempt]!
      await new Promise((r) => setTimeout(r, delayMs))
    }
  }

  return lastRes!
}

interface JupRoutePlanItem {
  swapInfo?: {
    ammKey?: string
    label?: string
    inputMint?: string
    outputMint?: string
    inAmount?: string
    outAmount?: string
  }
  percent?: number
}

interface JupQuoteRaw extends Record<string, unknown> {
  inputMint?: string
  outputMint?: string
  inAmount?: string
  outAmount?: string
  otherAmountThreshold?: string
  slippageBps?: number
  priceImpactPct?: string
  contextSlot?: number
  platformFee?: { amount?: string; feeBps?: number } | null
  routePlan?: JupRoutePlanItem[]
}

// Venues whose on-chain programs reject or penalize wrapped PDA-CPI callers (`ExecViaEscrow`):
// - Kipseli: inspects Sysvar1nstructions and throws Custom(6022) InvalidRealUser unless user signed top-level
// - Quantum / BisonFi: allowlist top-level callers and reject wrapping programs (Custom(9) / Custom(53))
// - BinaryFi / Obsidian: levy unlisted top-level caller penalty fees that diverge from top-level quotes
// - VaultLiquidUnstake / Sanctum Prop S: require System-owned signer lamports or keeper-signed direct swaps
export const JUPITER_CPI_EXCLUDED_DEXES = [
  'Kipseli',
  'Quantum',
  'BisonFi',
  'BisonFi Predict',
  'BinaryFi',
  'Obsidian',
  'VaultLiquidUnstake',
  'Sanctum Prop S',
].join(',')

export const jupiterAdapter: AggregatorAdapter = {
  id: 'jupiter',
  name: 'Jupiter Swap v1',
  capabilities: {
    supportsPlatformFeeBps: true,
    supportsSwapInstructions: true,
    quoteRequiresUserPubkey: false,
    feeSide: 'output',
    feeAccountStyle: 'ata',
  },

  isConfigured(env: Env): boolean {
    return Boolean(env.JUPITER_API_KEY?.trim() || env.JUPITER_API_URL?.trim())
  },

  async quote(env: Env, req: AdapterQuoteRequest): Promise<NormalizedQuote> {
    const t0 = Date.now()
    const doFetch = async (directOnly: boolean): Promise<JupQuoteRaw> => {
      const qs = new URLSearchParams({
        inputMint: req.inputMint,
        outputMint: req.outputMint,
        amount: req.amount,
        slippageBps: String(req.slippageBps),
        maxAccounts: String(req.maxAccounts ?? (directOnly ? 24 : 28)),
        excludeDexes: JUPITER_CPI_EXCLUDED_DEXES,
        ...(directOnly ? { onlyDirectRoutes: 'true' } : {}),
        ...(req.platformFeeBps && req.platformFeeBps > 0
          ? { platformFeeBps: String(req.platformFeeBps) }
          : {}),
      })
      const res = await fetchJupiterWithRetry(env, `/quote?${qs.toString()}`)
      if (!res.ok) {
        const txt = await res.text().catch(() => '')
        throw new Error(`Jupiter quote HTTP ${res.status}: ${txt.slice(0, 140)}`)
      }
      return (await res.json()) as JupQuoteRaw
    }

    let raw: JupQuoteRaw
    const wantDirect = req.onlyDirectRoutes ?? true
    try {
      raw = await doFetch(wantDirect)
    } catch (err) {
      if (wantDirect) {
        raw = await doFetch(false)
      } else {
        throw err
      }
    }

    if (!raw.outAmount || !/^\d+$/.test(raw.outAmount) || BigInt(raw.outAmount) <= 0n) {
      throw new Error('Jupiter returned zero outAmount')
    }

    const routePlan = (raw.routePlan ?? []).map((item) => {
      const si = item.swapInfo ?? {}
      const leg: RouteLegSummary = {
        label: si.label ?? 'Jupiter',
        ammKey: si.ammKey,
        inputMint: si.inputMint ?? req.inputMint,
        outputMint: si.outputMint ?? req.outputMint,
        inAmount: si.inAmount ?? req.amount,
        outAmount: si.outAmount ?? raw.outAmount!,
        percent: item.percent,
      }
      return { swapInfo: leg, percent: item.percent }
    })

    return {
      provider: 'jupiter',
      inputMint: raw.inputMint ?? req.inputMint,
      outputMint: raw.outputMint ?? req.outputMint,
      inAmount: raw.inAmount ?? req.amount,
      outAmount: raw.outAmount,
      otherAmountThreshold: raw.otherAmountThreshold ?? raw.outAmount,
      slippageBps: raw.slippageBps ?? req.slippageBps,
      priceImpactPct: raw.priceImpactPct ?? null,
      platformFee: raw.platformFee?.amount
        ? {
            amount: raw.platformFee.amount,
            feeBps: raw.platformFee.feeBps ?? req.platformFeeBps ?? 0,
            mint: req.outputMint,
          }
        : null,
      routePlan,
      contextSlot: raw.contextSlot ?? null,
      latencyMs: Date.now() - t0,
      rawQuote: raw,
    }
  },

  async swapInstructions(
    env: Env,
    req: AdapterSwapInstructionsRequest,
  ): Promise<NormalizedSwapInstructions> {
    const body: Record<string, unknown> = {
      quoteResponse: req.quoteResponse,
      userPublicKey: req.escrowPubkey,
      wrapAndUnwrapSol: false,
      useSharedAccounts: false,
      skipUserAccountsRpcCalls: true,
      dynamicComputeUnitLimit: false,
    }
    if (req.feeAccountAta) {
      body.feeAccount = req.feeAccountAta
    }

    const res = await fetchJupiterWithRetry(env, '/swap-instructions', {
      method: 'POST',
      body: JSON.stringify(body),
    })
    if (!res.ok) {
      const txt = await res.text().catch(() => '')
      throw new Error(`Jupiter swap-instructions HTTP ${res.status}: ${txt.slice(0, 160)}`)
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
    if (!payload.swapInstruction) {
      throw new Error('Jupiter did not return swapInstruction')
    }

    return {
      provider: 'jupiter',
      swapInstruction: payload.swapInstruction,
      addressLookupTableAddresses: payload.addressLookupTableAddresses ?? [],
      computeUnitLimit: Math.min(
        Math.max((payload.computeUnitLimit ?? 400_000) + 700_000, 1_100_000),
        1_400_000,
      ),
      feeAccount: req.feeAccountAta ?? null,
    }
  },
}
