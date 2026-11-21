import type { Env } from '../env'
import type {
  EncodedRouterInstruction,
  NormalizedQuote,
  NormalizedSwapInstructions,
  RouteLegSummary,
} from '../types'
import type {
  AdapterQuoteRequest,
  AdapterSwapInstructionsRequest,
  AggregatorAdapter,
} from './types'

/**
 * Titan Meta-Aggregator Adapter.
 *
 * Titan's `/quote/swap` returns both quotes and pre-built swap instructions for `userPublicKey`
 * (our isolated `swap_escrow` PDA) in a single round-trip, optionally charging `feeBps` into
 * `feeAccount`. Because Titan builds instructions at quote time, `quote()` caches the winning
 * provider's swap instruction inside `rawQuote` and `swapInstructions()` unwraps it cleanly.
 */
interface TitanAccountJson {
  pubkey?: string
  p?: string
  isSigner?: boolean
  s?: boolean
  isWritable?: boolean
  w?: boolean
}

interface TitanInstructionJson {
  programId?: string
  p?: string
  accounts?: TitanAccountJson[]
  a?: TitanAccountJson[]
  data?: string
  d?: string
}

interface TitanRouteJson {
  inAmount?: string | number
  outAmount?: string | number
  slippageBps?: number
  contextSlot?: number
  computeUnits?: number
  steps?: Array<{
    ammKey?: string
    label?: string
    inputMint?: string
    outputMint?: string
    inAmount?: string | number
    outAmount?: string | number
  }>
  instructions?: TitanInstructionJson[]
  addressLookupTables?: string[]
}

interface TitanQuoteResponseJson extends Record<string, unknown> {
  inputMint?: string
  outputMint?: string
  metadata?: { ExpectedWinner?: string }
  quotes?: Record<string, TitanRouteJson>
}

const COMPUTE_BUDGET_PROGRAM = 'ComputeBudget111111111111111111111111111111'
const ATA_PROGRAM = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'
const SYSTEM_PROGRAM = '11111111111111111111111111111111'

function normalizeTitanInstruction(ix: TitanInstructionJson): EncodedRouterInstruction | null {
  const programId = ix.programId ?? ix.p
  const data = ix.data ?? ix.d
  const rawAccs = ix.accounts ?? ix.a
  if (!programId || !data || !Array.isArray(rawAccs)) return null
  return {
    programId,
    data,
    accounts: rawAccs.map((a) => ({
      pubkey: a.pubkey ?? a.p ?? '',
      isSigner: Boolean(a.isSigner ?? a.s),
      isWritable: Boolean(a.isWritable ?? a.w),
    })),
  }
}

export const titanAdapter: AggregatorAdapter = {
  id: 'titan',
  name: 'Titan Meta-Aggregator',
  capabilities: {
    supportsPlatformFeeBps: true,
    supportsSwapInstructions: true,
    quoteRequiresUserPubkey: true,
    feeSide: 'output',
    feeAccountStyle: 'ata',
  },

  isConfigured(env: Env): boolean {
    return Boolean(env.TITAN_API_URL?.trim())
  },

  async quote(env: Env, req: AdapterQuoteRequest): Promise<NormalizedQuote> {
    const base = env.TITAN_API_URL?.trim().replace(/\/+$/, '')
    if (!base) throw new Error('Titan adapter not configured (set TITAN_API_URL)')
    if (!req.escrowPubkey) throw new Error('Titan requires escrowPubkey at quote time')

    const t0 = Date.now()
    const qs = new URLSearchParams({
      inputMint: req.inputMint,
      outputMint: req.outputMint,
      amount: req.amount,
      slippageBps: String(req.slippageBps),
      userPublicKey: req.escrowPubkey,
      ...(req.onlyDirectRoutes ? { onlyDirectRoutes: 'true' } : {}),
      ...(req.platformFeeBps && req.platformFeeBps > 0 && req.relayerFeeAta
        ? { feeBps: String(req.platformFeeBps), feeAccount: req.relayerFeeAta }
        : {}),
    })

    const res = await fetch(`${base}/quote/swap?${qs.toString()}`, {
      headers: {
        accept: 'application/json',
        ...(env.TITAN_API_KEY ? { authorization: `Bearer ${env.TITAN_API_KEY}`, 'x-api-key': env.TITAN_API_KEY } : {}),
      },
      signal: AbortSignal.timeout(10_000),
    })
    if (!res.ok) {
      const txt = await res.text().catch(() => '')
      throw new Error(`Titan quote HTTP ${res.status}: ${txt.slice(0, 140)}`)
    }

    const decoded = (await res.json()) as TitanQuoteResponseJson
    const quotesMap = decoded.quotes ?? {}
    const winnerId = decoded.metadata?.ExpectedWinner
    let winnerKey = winnerId && quotesMap[winnerId] ? winnerId : ''
    let route = winnerKey ? quotesMap[winnerKey] : undefined
    if (!route) {
      let bestOut = -1n
      for (const [k, r] of Object.entries(quotesMap)) {
        const out = BigInt(String(r.outAmount ?? '0'))
        if (out > bestOut) {
          bestOut = out
          winnerKey = k
          route = r
        }
      }
    }
    if (!route || BigInt(String(route.outAmount ?? '0')) <= 0n) {
      throw new Error('Titan returned no valid quotes')
    }

    const outAmount = String(route.outAmount)
    const minOut = (
      (BigInt(outAmount) * BigInt(10_000 - req.slippageBps)) /
      10_000n
    ).toString()

    const steps = route.steps ?? []
    const routePlan =
      steps.length > 0
        ? steps.map((s) => {
            const info: RouteLegSummary = {
              label: s.label ?? winnerKey ?? 'Titan',
              ammKey: s.ammKey,
              inputMint: s.inputMint ?? req.inputMint,
              outputMint: s.outputMint ?? req.outputMint,
              inAmount: String(s.inAmount ?? req.amount),
              outAmount: String(s.outAmount ?? outAmount),
            }
            return { swapInfo: info, percent: 100 }
          })
        : [
            {
              swapInfo: {
                label: winnerKey || 'Titan',
                inputMint: req.inputMint,
                outputMint: req.outputMint,
                inAmount: req.amount,
                outAmount,
              },
              percent: 100,
            },
          ]

    return {
      provider: 'titan',
      inputMint: decoded.inputMint ?? req.inputMint,
      outputMint: decoded.outputMint ?? req.outputMint,
      inAmount: String(route.inAmount ?? req.amount),
      outAmount,
      otherAmountThreshold: minOut,
      slippageBps: route.slippageBps ?? req.slippageBps,
      platformFee:
        req.platformFeeBps && req.platformFeeBps > 0
          ? {
              amount: ((BigInt(outAmount) * BigInt(req.platformFeeBps)) / 10_000n).toString(),
              feeBps: req.platformFeeBps,
              mint: req.outputMint,
            }
          : null,
      routePlan,
      contextSlot: route.contextSlot ?? null,
      latencyMs: Date.now() - t0,
      rawQuote: {
        winner: winnerKey,
        escrowPubkey: req.escrowPubkey,
        route,
        platformFee:
          req.platformFeeBps && req.platformFeeBps > 0 ? { feeBps: req.platformFeeBps } : null,
      },
    }
  },

  async swapInstructions(
    _env: Env,
    req: AdapterSwapInstructionsRequest,
  ): Promise<NormalizedSwapInstructions> {
    const raw = req.quoteResponse as {
      escrowPubkey?: string
      route?: TitanRouteJson
    }
    if (raw.escrowPubkey && raw.escrowPubkey !== req.escrowPubkey) {
      throw new Error(`Titan quote was built for ${raw.escrowPubkey}, not ${req.escrowPubkey}`)
    }
    const ixs = (raw.route?.instructions ?? [])
      .map(normalizeTitanInstruction)
      .filter((x): x is EncodedRouterInstruction => x !== null)

    // Pick the primary router swap instruction (exclude ComputeBudget / ATA / System wrappers)
    const swapIx = ixs.find(
      (ix) =>
        ix.programId !== COMPUTE_BUDGET_PROGRAM &&
        ix.programId !== ATA_PROGRAM &&
        ix.programId !== SYSTEM_PROGRAM &&
        ix.accounts.some((a) => a.pubkey === req.escrowPubkey),
    )
    if (!swapIx) {
      throw new Error('Titan route did not expose a single escrow-signed swapInstruction')
    }

    return {
      provider: 'titan',
      swapInstruction: swapIx,
      addressLookupTableAddresses: raw.route?.addressLookupTables ?? [],
      computeUnitLimit: Math.min(
        Math.max((raw.route?.computeUnits ?? 400_000) + 700_000, 1_100_000),
        1_400_000,
      ),
      feeAccount: req.feeAccountAta ?? null,
    }
  },
}
