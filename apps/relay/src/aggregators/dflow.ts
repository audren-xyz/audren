import type { Env } from '../env'
import type { NormalizedQuote, NormalizedSwapInstructions, RouteLegSummary } from '../types'
import type {
  AdapterQuoteRequest,
  AdapterSwapInstructionsRequest,
  AggregatorAdapter,
} from './types'

/**
 * DFlow Trading API Adapter (`https://quote-api.dflow.net`).
 *
 * Uses DFlow imperative flow:
 *   - GET  /quote?inputMint&outputMint&amount&slippageBps&platformFeeBps&transactionVersion=v1
 *   - POST /swap-instructions { userPublicKey, quoteResponse, wrapAndUnwrapSol: false, feeAccount }
 */
interface DflowLeg {
  venue?: string
  marketKey?: string
  inputMint?: string
  outputMint?: string
  inAmount?: string
  outAmount?: string
}

interface DflowQuoteRaw extends Record<string, unknown> {
  inputMint?: string
  outputMint?: string
  inAmount?: string
  outAmount?: string
  minOutAmount?: string
  otherAmountThreshold?: string
  slippageBps?: number
  priceImpactPct?: string
  contextSlot?: number
  platformFee?: { amount?: string; feeBps?: number } | null
  routePlan?: DflowLeg[]
}

function dflowHeaders(env: Env): Record<string, string> {
  return {
    accept: 'application/json',
    'content-type': 'application/json',
    ...(env.DFLOW_API_KEY ? { 'x-api-key': env.DFLOW_API_KEY } : {}),
  }
}

export const dflowAdapter: AggregatorAdapter = {
  id: 'dflow',
  name: 'DFlow Trading API',
  capabilities: {
    supportsPlatformFeeBps: true,
    supportsSwapInstructions: true,
    quoteRequiresUserPubkey: false,
    feeSide: 'output',
    feeAccountStyle: 'ata',
  },

  isConfigured(env: Env): boolean {
    return Boolean(env.DFLOW_API_KEY?.trim() || env.DFLOW_API_URL?.trim())
  },

  async quote(env: Env, req: AdapterQuoteRequest): Promise<NormalizedQuote> {
    const base = (env.DFLOW_API_URL?.trim() || 'https://quote-api.dflow.net').replace(/\/+$/, '')
    const t0 = Date.now()
    const qs = new URLSearchParams({
      inputMint: req.inputMint,
      outputMint: req.outputMint,
      amount: req.amount,
      slippageBps: String(req.slippageBps),
      transactionVersion: 'v1',
      ...(req.onlyDirectRoutes ? { onlyDirectRoutes: 'true' } : {}),
      ...(req.platformFeeBps && req.platformFeeBps > 0
        ? { platformFeeBps: String(req.platformFeeBps) }
        : {}),
    })

    const res = await fetch(`${base}/quote?${qs.toString()}`, {
      headers: dflowHeaders(env),
      signal: AbortSignal.timeout(10_000),
    })
    if (!res.ok) {
      const txt = await res.text().catch(() => '')
      throw new Error(`DFlow quote HTTP ${res.status}: ${txt.slice(0, 140)}`)
    }
    const raw = (await res.json()) as DflowQuoteRaw
    if (!raw.outAmount || !/^\d+$/.test(String(raw.outAmount)) || BigInt(raw.outAmount) <= 0n) {
      throw new Error('DFlow returned zero outAmount')
    }

    const legs = raw.routePlan ?? []
    const flowByMint = new Map<string, bigint>()
    for (const leg of legs) {
      const m = leg.inputMint ?? req.inputMint
      flowByMint.set(m, (flowByMint.get(m) ?? 0n) + BigInt(leg.inAmount ?? '0'))
    }

    const routePlan = legs.map((leg) => {
      const m = leg.inputMint ?? req.inputMint
      const total = flowByMint.get(m) ?? 0n
      const pct = total > 0n ? Number((BigInt(leg.inAmount ?? '0') * 10_000n) / total) / 100 : 100
      const info: RouteLegSummary = {
        label: leg.venue ?? 'DFlow',
        ammKey: leg.marketKey,
        inputMint: m,
        outputMint: leg.outputMint ?? req.outputMint,
        inAmount: String(leg.inAmount ?? req.amount),
        outAmount: String(leg.outAmount ?? raw.outAmount),
        percent: pct,
      }
      return { swapInfo: info, percent: pct }
    })

    return {
      provider: 'dflow',
      inputMint: raw.inputMint ?? req.inputMint,
      outputMint: raw.outputMint ?? req.outputMint,
      inAmount: String(raw.inAmount ?? req.amount),
      outAmount: String(raw.outAmount),
      otherAmountThreshold: String(raw.minOutAmount ?? raw.otherAmountThreshold ?? raw.outAmount),
      slippageBps: raw.slippageBps ?? req.slippageBps,
      priceImpactPct: raw.priceImpactPct ?? null,
      platformFee: raw.platformFee?.amount
        ? {
            amount: String(raw.platformFee.amount),
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
    const base = (env.DFLOW_API_URL?.trim() || 'https://quote-api.dflow.net').replace(/\/+$/, '')
    const res = await fetch(`${base}/swap-instructions`, {
      method: 'POST',
      headers: dflowHeaders(env),
      body: JSON.stringify({
        userPublicKey: req.escrowPubkey,
        quoteResponse: req.quoteResponse,
        wrapAndUnwrapSol: false,
        transactionVersion: 'v1',
        ...(req.feeAccountAta ? { feeAccount: req.feeAccountAta } : {}),
      }),
      signal: AbortSignal.timeout(10_000),
    })
    if (!res.ok) {
      const txt = await res.text().catch(() => '')
      throw new Error(`DFlow swap-instructions HTTP ${res.status}: ${txt.slice(0, 160)}`)
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
      throw new Error('DFlow did not return swapInstruction')
    }
    return {
      provider: 'dflow',
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
