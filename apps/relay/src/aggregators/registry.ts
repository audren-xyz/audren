import type { Env, RelayPolicyConfig } from '../env'
import type { AggregatorId, AggregatorSelection, NormalizedQuote } from '../types'
import { bedrockAdapter } from './bedrock'
import { dflowAdapter } from './dflow'
import { jupiterAdapter, JUPITER_CPI_EXCLUDED_DEXES } from './jupiter'
import { okxAdapter } from './okx'
import { titanAdapter } from './titan'
import type { AdapterQuoteRequest, AggregatorAdapter } from './types'

const CPI_EXCLUDED_VENUE_LIST = JUPITER_CPI_EXCLUDED_DEXES.split(',')
  .map((s) => s.trim())
  .filter(Boolean)

function normalizeVenueName(raw: string): string {
  return raw.toLowerCase().replace(/[^a-z0-9]/g, '')
}

const CPI_EXCLUDED_NORMALIZED = CPI_EXCLUDED_VENUE_LIST.map((name) => ({
  name,
  norm: normalizeVenueName(name),
}))

/**
 * Returns the first PDA-CPI-hostile venue label present in `quote.routePlan`, or `null`
 * if every leg is safe to execute through Audren's `ExecViaEscrow` (`Tag 7`) PDA CPI.
 */
export function findExcludedCpiVenue(quote: Pick<NormalizedQuote, 'routePlan'>): string | null {
  for (const leg of quote.routePlan ?? []) {
    const label = leg?.swapInfo?.label?.trim()
    if (!label) continue
    const norm = normalizeVenueName(label)
    if (!norm) continue
    for (const ex of CPI_EXCLUDED_NORMALIZED) {
      if (norm === ex.norm || norm.includes(ex.norm)) {
        return label
      }
    }
  }
  return null
}

const ALL_ADAPTERS: readonly AggregatorAdapter[] = [
  jupiterAdapter,
  bedrockAdapter,
  dflowAdapter,
  titanAdapter,
  okxAdapter,
]

const ADAPTER_BY_ID = new Map<AggregatorId, AggregatorAdapter>(
  ALL_ADAPTERS.map((a) => [a.id, a]),
)

export function getAggregatorAdapter(id: AggregatorId): AggregatorAdapter {
  const adapter = ADAPTER_BY_ID.get(id)
  if (!adapter) throw new Error(`Unknown aggregator "${id}"`)
  return adapter
}

export function listAggregators(env: Env, cfg: RelayPolicyConfig) {
  return ALL_ADAPTERS.map((a) => ({
    id: a.id,
    name: a.name,
    enabled: cfg.enabledAggregators.has(a.id) && a.isConfigured(env),
    configured: a.isConfigured(env),
    isDefault: a.id === cfg.defaultAggregator,
    capabilities: a.capabilities,
  }))
}

function resolveActiveAdapters(env: Env, cfg: RelayPolicyConfig): AggregatorAdapter[] {
  return ALL_ADAPTERS.filter((a) => cfg.enabledAggregators.has(a.id) && a.isConfigured(env))
}

/**
 * Fetch quote from either an explicit aggregator (`jupiter` | `bedrock` | `dflow` | `titan` | `okx`)
 * or race all active aggregators in parallel (`auto`) and return the highest net `outAmount`.
 */
export async function quoteWithSelection(
  env: Env,
  cfg: RelayPolicyConfig,
  selection: AggregatorSelection | undefined,
  req: AdapterQuoteRequest,
): Promise<{
  winner: NormalizedQuote
  candidates: Array<{ provider: AggregatorId; outAmount?: string; latencyMs?: number; error?: string }>
}> {
  const chosen = selection ?? cfg.defaultAggregator
  if (chosen !== 'auto') {
    const adapter = getAggregatorAdapter(chosen)
    if (!cfg.enabledAggregators.has(chosen)) {
      throw new Error(`Aggregator "${chosen}" is disabled by relay policy`)
    }
    if (!adapter.isConfigured(env)) {
      throw new Error(`Aggregator "${chosen}" credentials are not configured on this relay`)
    }
    const quote = await adapter.quote(env, req)
    const excluded = findExcludedCpiVenue(quote)
    if (excluded) {
      throw new Error(`Aggregator "${chosen}" routed via PDA-CPI-excluded venue "${excluded}"`)
    }
    return {
      winner: quote,
      candidates: [{ provider: chosen, outAmount: quote.outAmount, latencyMs: quote.latencyMs }],
    }
  }

  const active = resolveActiveAdapters(env, cfg)
  if (active.length === 0) {
    throw new Error('No swap aggregators are enabled and configured on this relay')
  }

  const settled = await Promise.allSettled(active.map((a) => a.quote(env, req)))
  const quotes: NormalizedQuote[] = []
  const candidates: Array<{
    provider: AggregatorId
    outAmount?: string
    latencyMs?: number
    error?: string
  }> = []

  settled.forEach((res, idx) => {
    const id = active[idx]!.id
    if (res.status === 'fulfilled') {
      const excluded = findExcludedCpiVenue(res.value)
      if (excluded) {
        candidates.push({
          provider: id,
          latencyMs: res.value.latencyMs,
          error: `Rejected PDA-CPI-excluded venue "${excluded}"`,
        })
        return
      }
      quotes.push(res.value)
      candidates.push({
        provider: id,
        outAmount: res.value.outAmount,
        latencyMs: res.value.latencyMs,
      })
    } else {
      candidates.push({
        provider: id,
        error: res.reason instanceof Error ? res.reason.message : String(res.reason),
      })
    }
  })

  if (quotes.length === 0) {
    throw new Error(
      `All active aggregators failed: ${candidates.map((c) => `${c.provider}: ${c.error}`).join('; ')}`,
    )
  }

  quotes.sort((a, b) => {
    const diff = BigInt(b.outAmount) - BigInt(a.outAmount)
    if (diff !== 0n) return diff > 0n ? 1 : -1
    return a.latencyMs - b.latencyMs
  })

  return { winner: quotes[0]!, candidates }
}
