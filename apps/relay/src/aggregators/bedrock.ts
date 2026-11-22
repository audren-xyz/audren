import type { Env } from '../env'
import type { NormalizedQuote, NormalizedSwapInstructions, RouteLegSummary } from '../types'
import type {
  AdapterQuoteRequest,
  AdapterSwapInstructionsRequest,
  AggregatorAdapter,
} from './types'

/**
 * Bedrock Aggregator Adapter.
 *
 *   - GET  /quote?inputMint&outputMint&amount&swapMode=ExactIn&slippageBps&platformFeeBps&feeAccount&programAuthority=true&wrapAndUnwrapSol=false
 *   - POST /swap-instructions { userPublicKey, quoteResponse, programAuthority: true, wrapAndUnwrapSol: false, skipUserAccountsRpcCalls: true }
 *
 * Note: Bedrock sets `feeAccount` to the fee collector OWNER wallet (not the ATA) and
 * emits a single zero-ALT `trade` instruction compatible with Audren's `ExecViaEscrow` PDA CPI.
 */
interface BedrockQuoteRaw extends Record<string, unknown> {
  inputMint?: string
  outputMint?: string
  inAmount?: string
  outAmount?: string
  otherAmountThreshold?: string
  slippageBps?: number | string
  priceImpactPct?: string
  contextSlot?: number
  fee?: { amount?: string; feeBps?: number; mint?: string } | null
  platformFee?: { amount?: string; feeBps?: number } | null
  routePlan?: Array<{
    swapInfo?: {
      ammKey?: string
      label?: string
      inputMint?: string
      outputMint?: string
      inAmount?: string
      outAmount?: string
    }
    percent?: number
  }>
}

function bedrockHeaders(env: Env): Record<string, string> {
  return {
    accept: 'application/json',
    'content-type': 'application/json',
    ...(env.BEDROCK_API_KEY ? { authorization: `Bearer ${env.BEDROCK_API_KEY}`, 'x-api-key': env.BEDROCK_API_KEY } : {}),
  }
}

export const bedrockAdapter: AggregatorAdapter = {
  id: 'bedrock',
  name: 'Bedrock',
  capabilities: {
    supportsPlatformFeeBps: true,
    supportsSwapInstructions: true,
    quoteRequiresUserPubkey: false,
    feeSide: 'either',
    feeAccountStyle: 'owner_wallet',
  },

  isConfigured(env: Env): boolean {
    return Boolean(env.BEDROCK_API_URL?.trim())
  },

  async quote(env: Env, req: AdapterQuoteRequest): Promise<NormalizedQuote> {
    const base = env.BEDROCK_API_URL?.trim().replace(/\/+$/, '')
    if (!base) throw new Error('Bedrock adapter not configured (set BEDROCK_API_URL)')

    const t0 = Date.now()
    const qs = new URLSearchParams({
      inputMint: req.inputMint,
      outputMint: req.outputMint,
      amount: req.amount,
      swapMode: 'ExactIn',
      slippageBps: String(req.slippageBps),
      programAuthority: 'true',
      wrapAndUnwrapSol: 'false',
      maxAccounts: String(req.maxAccounts ?? 28),
      ...(req.onlyDirectRoutes ? { onlyDirectRoutes: 'true' } : {}),
      ...(req.platformFeeBps && req.platformFeeBps > 0 && req.relayerOwner
        ? {
            platformFeeBps: String(req.platformFeeBps),
            feeAccount: req.relayerOwner,
          }
        : { platformFeeBps: '0' }),
    })

    const res = await fetch(`${base}/quote?${qs.toString()}`, {
      headers: bedrockHeaders(env),
      signal: AbortSignal.timeout(10_000),
    })
    if (!res.ok) {
      const txt = await res.text().catch(() => '')
      throw new Error(`Bedrock quote HTTP ${res.status}: ${txt.slice(0, 140)}`)
    }
    const raw = (await res.json()) as BedrockQuoteRaw
    if (!raw.outAmount || !/^\d+$/.test(raw.outAmount) || BigInt(raw.outAmount) <= 0n) {
      throw new Error('Bedrock returned zero outAmount')
    }

    const routePlan = (raw.routePlan ?? []).map((item) => {
      const si = item.swapInfo ?? {}
      const leg: RouteLegSummary = {
        label: si.label ?? 'Bedrock',
        ammKey: si.ammKey,
        inputMint: si.inputMint ?? req.inputMint,
        outputMint: si.outputMint ?? req.outputMint,
        inAmount: si.inAmount ?? req.amount,
        outAmount: si.outAmount ?? raw.outAmount!,
        percent: item.percent,
      }
      return { swapInfo: leg, percent: item.percent }
    })

    const feeObj = raw.fee ?? raw.platformFee
    return {
      provider: 'bedrock',
      inputMint: raw.inputMint ?? req.inputMint,
      outputMint: raw.outputMint ?? req.outputMint,
      inAmount: raw.inAmount ?? req.amount,
      outAmount: raw.outAmount,
      otherAmountThreshold: raw.otherAmountThreshold ?? raw.outAmount,
      slippageBps: Number(raw.slippageBps ?? req.slippageBps),
      priceImpactPct: raw.priceImpactPct ?? null,
      platformFee: feeObj?.amount
        ? {
            amount: feeObj.amount,
            feeBps: feeObj.feeBps ?? req.platformFeeBps ?? 0,
            mint: (raw.fee?.mint ?? req.outputMint),
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
    const base = env.BEDROCK_API_URL?.trim().replace(/\/+$/, '')
    if (!base) throw new Error('Bedrock adapter not configured (set BEDROCK_API_URL)')

    const res = await fetch(`${base}/swap-instructions`, {
      method: 'POST',
      headers: bedrockHeaders(env),
      body: JSON.stringify({
        userPublicKey: req.escrowPubkey,
        quoteResponse: req.quoteResponse,
        programAuthority: true,
        wrapAndUnwrapSol: false,
        skipUserAccountsRpcCalls: true,
      }),
      signal: AbortSignal.timeout(10_000),
    })
    if (!res.ok) {
      const txt = await res.text().catch(() => '')
      throw new Error(`Bedrock swap-instructions HTTP ${res.status}: ${txt.slice(0, 160)}`)
    }
    const payload = (await res.json()) as {
      swapInstruction?: {
        programId: string
        accounts: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }>
        data: string
      }
      transactionConfig?: { computeUnitLimit?: number }
      addressLookupTableAddresses?: string[]
    }
    if (!payload.swapInstruction) {
      throw new Error('Bedrock did not return swapInstruction')
    }

    const baseCu = payload.transactionConfig?.computeUnitLimit ?? 350_000
    return {
      provider: 'bedrock',
      swapInstruction: payload.swapInstruction,
      addressLookupTableAddresses: payload.addressLookupTableAddresses ?? [],
      computeUnitLimit: Math.min(Math.max(baseCu + 700_000, 1_050_000), 1_400_000),
      feeAccount: req.feeAccountAta ?? req.feeOwnerWallet ?? null,
    }
  },
}
