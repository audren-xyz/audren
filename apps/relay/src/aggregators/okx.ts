import { toBase64, utf8 } from '../solana/codec'
import type { Env } from '../env'
import type {
  EncodedRouterInstruction,
  NormalizedQuote,
  NormalizedSwapInstructions,
  RouteLegSummary,
} from '../types'
import {
  computeAggregatorExecCuLimit,
  type AdapterQuoteRequest,
  type AdapterSwapInstructionsRequest,
  type AggregatorAdapter,
} from './types'

/**
 * OKX DEX Aggregator Adapter (Solana `chainIndex=501`).
 *
 * Uses OKX's `/api/v6/dex/aggregator/swap-instruction` endpoint with WebCrypto HMAC-SHA256
 * authentication (`OK-ACCESS-SIGN`) and native referrer fee (`feePercent` +
 * `toTokenReferrerWalletAddress`).
 */
const OKX_CHAIN_INDEX = '501'
const OKX_SWAP_IX_PATH = '/api/v6/dex/aggregator/swap-instruction'

async function signOkxHeaders(
  env: Env,
  method: string,
  requestPath: string,
  queryString: string,
): Promise<Record<string, string>> {
  const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z')
  const prehash = `${timestamp}${method.toUpperCase()}${requestPath}${queryString}`
  const keyBytes = new Uint8Array(utf8(env.OKX_SECRET_KEY ?? ''))
  const prehashBytes = new Uint8Array(utf8(prehash))
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, prehashBytes))
  return {
    'OK-ACCESS-KEY': env.OKX_API_KEY ?? '',
    'OK-ACCESS-SIGN': toBase64(sig),
    'OK-ACCESS-TIMESTAMP': timestamp,
    'OK-ACCESS-PASSPHRASE': env.OKX_PASSPHRASE ?? '',
    accept: 'application/json',
  }
}

interface OkxIxAccount {
  pubkey: string
  isSigner: boolean
  isWritable: boolean
}

interface OkxSwapIxData {
  instructionLists?: Array<{
    programId: string
    data: string
    accounts: OkxIxAccount[]
  }>
  addressLookupTableAccount?: string[]
  routerResult?: {
    toTokenAmount?: string
    fromTokenAmount?: string
    priceImpactPercentage?: string
    dexRouterList?: Array<{
      dexProtocol?: { dexName?: string; percent?: string }
      fromToken?: { tokenContractAddress?: string }
      toToken?: { tokenContractAddress?: string }
    }>
  }
}

interface OkxSwapIxResponse {
  code?: string
  msg?: string
  data?: OkxSwapIxData | OkxSwapIxData[]
}

export const okxAdapter: AggregatorAdapter = {
  id: 'okx',
  name: 'OKX DEX Aggregator',
  capabilities: {
    supportsPlatformFeeBps: true,
    supportsSwapInstructions: true,
    quoteRequiresUserPubkey: true,
    feeSide: 'output',
    feeAccountStyle: 'owner_wallet',
  },

  isConfigured(env: Env): boolean {
    return Boolean(env.OKX_API_KEY?.trim() && env.OKX_SECRET_KEY?.trim() && env.OKX_PASSPHRASE?.trim())
  },

  async quote(env: Env, req: AdapterQuoteRequest): Promise<NormalizedQuote> {
    if (!this.isConfigured(env)) {
      throw new Error('OKX adapter not configured (set OKX_API_KEY, OKX_SECRET_KEY, OKX_PASSPHRASE)')
    }
    if (!req.escrowPubkey) throw new Error('OKX requires escrowPubkey at quote time')

    const base = (env.OKX_API_URL?.trim() || 'https://web3.okx.com').replace(/\/+$/, '')
    const t0 = Date.now()
    const qs = new URLSearchParams({
      chainIndex: OKX_CHAIN_INDEX,
      amount: req.amount,
      // Keep WSOL mint literal as-is so OKX swaps SPL WSOL directly without native SOL wrap/unwrap
      fromTokenAddress: req.inputMint,
      toTokenAddress: req.outputMint,
      slippagePercent: (req.slippageBps / 100).toString(),
      userWalletAddress: req.escrowPubkey,
      swapMode: 'exactIn',
      ...(req.platformFeeBps && req.platformFeeBps > 0 && req.relayerOwner
        ? {
            feePercent: (req.platformFeeBps / 100).toFixed(4).replace(/\.?0+$/, ''),
            toTokenReferrerWalletAddress: req.relayerOwner,
          }
        : {}),
    })
    const queryString = `?${qs.toString()}`
    const headers = await signOkxHeaders(env, 'GET', OKX_SWAP_IX_PATH, queryString)

    const res = await fetch(`${base}${OKX_SWAP_IX_PATH}${queryString}`, {
      headers,
      signal: AbortSignal.timeout(10_000),
    })
    if (!res.ok) {
      const txt = await res.text().catch(() => '')
      throw new Error(`OKX swap-instruction HTTP ${res.status}: ${txt.slice(0, 140)}`)
    }
    const body = (await res.json()) as OkxSwapIxResponse
    const entry = Array.isArray(body.data) ? body.data[0] : body.data
    if (body.code !== '0' || !entry?.routerResult?.toTokenAmount) {
      throw new Error(`OKX API error: ${body.msg ?? 'No route returned'}`)
    }

    const rr = entry.routerResult
    const outAmount = rr.toTokenAmount!
    const minOut = ((BigInt(outAmount) * BigInt(10_000 - req.slippageBps)) / 10_000n).toString()

    const hops = rr.dexRouterList ?? []
    const routePlan =
      hops.length > 0
        ? hops.map((h) => {
            const info: RouteLegSummary = {
              label: h.dexProtocol?.dexName ?? 'OKX',
              inputMint: h.fromToken?.tokenContractAddress ?? req.inputMint,
              outputMint: h.toToken?.tokenContractAddress ?? req.outputMint,
              inAmount: req.amount,
              outAmount,
              percent: Number(h.dexProtocol?.percent ?? 100),
            }
            return { swapInfo: info, percent: info.percent }
          })
        : [
            {
              swapInfo: {
                label: 'OKX Aggregator',
                inputMint: req.inputMint,
                outputMint: req.outputMint,
                inAmount: req.amount,
                outAmount,
              },
              percent: 100,
            },
          ]

    return {
      provider: 'okx',
      inputMint: req.inputMint,
      outputMint: req.outputMint,
      inAmount: req.amount,
      outAmount,
      otherAmountThreshold: minOut,
      slippageBps: req.slippageBps,
      priceImpactPct: rr.priceImpactPercentage ?? null,
      platformFee:
        req.platformFeeBps && req.platformFeeBps > 0
          ? {
              amount: ((BigInt(outAmount) * BigInt(req.platformFeeBps)) / 10_000n).toString(),
              feeBps: req.platformFeeBps,
              mint: req.outputMint,
            }
          : null,
      routePlan,
      contextSlot: null,
      latencyMs: Date.now() - t0,
      rawQuote: {
        escrowPubkey: req.escrowPubkey,
        instructionLists: entry.instructionLists ?? [],
        addressLookupTableAccount: entry.addressLookupTableAccount ?? [],
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
      instructionLists?: EncodedRouterInstruction[]
      addressLookupTableAccount?: string[]
    }
    if (raw.escrowPubkey && raw.escrowPubkey !== req.escrowPubkey) {
      throw new Error(`OKX quote was built for ${raw.escrowPubkey}, not ${req.escrowPubkey}`)
    }
    const ixs = raw.instructionLists ?? []
    const swapIx = ixs.find(
      (ix) =>
        ix.programId !== 'ComputeBudget111111111111111111111111111111' &&
        ix.programId !== 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL' &&
        ix.programId !== '11111111111111111111111111111111' &&
        ix.programId !== 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA' &&
        ix.programId !== 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb' &&
        ix.accounts.some((a) => a.pubkey === req.escrowPubkey),
    )
    if (!swapIx) {
      throw new Error('OKX response did not include an escrow-signed swap instruction')
    }
    return {
      provider: 'okx',
      swapInstruction: swapIx,
      addressLookupTableAddresses: Array.isArray(raw.addressLookupTableAccount)
        ? raw.addressLookupTableAccount
        : [],
      computeUnitLimit: computeAggregatorExecCuLimit({ forceMultiHopHeadroom: true }),
      feeAccount: req.feeOwnerWallet ?? req.feeAccountAta ?? null,
    }
  },
}
