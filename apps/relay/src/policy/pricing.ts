import type { Env, RelayPolicyConfig } from '../env'
import { WSOL_MINT_STR } from '../solana/codec'
import type { LiveRentSchedule } from '../solana/rpc'
import type { SwapFeePlan } from '../types'

interface CachedPrice {
  usd: number
  fetchedAt: number
}

const PRICE_CACHE = new Map<string, CachedPrice>()
const PRICE_TTL_MS = 60_000

/**
 * Dynamically fetch live USD prices for ANY set of Solana mints via Jupiter Price API v3
 * (`JUPITER_API_URL` / `https://api.jup.ag` with `JUPITER_API_KEY`). Zero hardcoded token lists or decimals.
 */
export async function fetchMintPricesUsd(
  env: Env,
  mints: string[],
): Promise<Record<string, number>> {
  const now = Date.now()
  const out: Record<string, number> = {}
  const missing: string[] = []

  for (const m of mints) {
    const cached = PRICE_CACHE.get(m)
    if (cached && now - cached.fetchedAt < PRICE_TTL_MS) {
      out[m] = cached.usd
    } else if (!missing.includes(m)) {
      missing.push(m)
    }
  }

  if (missing.length > 0 && (env.JUPITER_API_KEY?.trim() || env.JUPITER_API_URL?.trim())) {
    const ids = missing.join(',')
    const base = (env.JUPITER_API_URL?.trim() || 'https://api.jup.ag')
      .replace(/\/+$/, '')
      .replace(/\/swap\/v1$/, '')
    const headers: Record<string, string> = {
      accept: 'application/json',
      ...(env.JUPITER_API_KEY?.trim() ? { 'x-api-key': env.JUPITER_API_KEY.trim() } : {}),
    }

    try {
      const res = await fetch(`${base}/price/v3?ids=${encodeURIComponent(ids)}`, {
        headers,
        signal: AbortSignal.timeout(4_000),
      })
      if (res.ok) {
        const body = (await res.json()) as Record<
          string,
          { usdPrice?: number; price?: string | number }
        >
        const map =
          (body as { data?: Record<string, { usdPrice?: number; price?: string | number }> })
            .data ?? body
        for (const m of missing) {
          const entry = map[m]
          const val = Number(entry?.usdPrice ?? entry?.price ?? NaN)
          if (Number.isFinite(val) && val > 0) {
            out[m] = val
            PRICE_CACHE.set(m, { usd: val, fetchedAt: now })
          }
        }
      }
    } catch {
      // Price feed unavailable — caller falls back cleanly (WSOL still self-prices natively)
    }
  }

  return out
}

/**
 * Compute the dynamic swap fee plan for any Solana output mint (Classic SPL or Token-2022)
 * using live on-chain rent from Solana RPC and live token USD prices.
 *
 * Works for ANY token on Solana — ZERO hardcoded mint list, ZERO hardcoded rent numbers:
 *   - If `feeAccountExists` is true: cost = `rentSchedule.swapBaselineLamports` (+ priority buffer).
 *   - If `feeAccountExists` is false (brand-new output mint):
 *       - If the swap's max fee covers `(swapBaseline + ataRent)` on-chain, the relay sets
 *         `needsFeeAtaSetup = true` so the client includes `relayerFeeAta` in `setupAtas` and the
 *         relayer creates its fee ATA atomically inside the swap tx!
 *       - Otherwise (small swap into an uninitialized mint where ATA rent exceeds the fee),
 *         `platformFeeBps = 0` (`billingMode = 'sponsored'`) so ANY token swap still succeeds!
 */
export function computeSwapFeePlan(params: {
  cfg: RelayPolicyConfig
  rentSchedule: LiveRentSchedule
  outputMint: string
  outputDecimals: number
  estimatedOutAmount: bigint
  solPriceUsd: number | null
  outputTokenPriceUsd: number | null
  feeAccount: string | null
  feeAccountExists: boolean
}): SwapFeePlan {
  const {
    cfg,
    rentSchedule,
    outputMint,
    outputDecimals,
    estimatedOutAmount,
    solPriceUsd,
    outputTokenPriceUsd,
    feeAccount,
    feeAccountExists,
  } = params

  // Include 15,000 lamport priority fee cushion in the pre-simulation quote estimate;
  // at `/v1/relay/submit` time, exact lamports come straight from `simulateTransaction`!
  const baseSwapLamports = rentSchedule.swapBaselineLamports + 15_000n
  const totalLamportsIfCreatingAta = baseSwapLamports + rentSchedule.ataRentLamports
  const costSol = Number(baseSwapLamports) / 1e9
  const estimatedRelayCostUsd =
    solPriceUsd && solPriceUsd > 0 ? costSol * solPriceUsd : null

  if (!feeAccount) {
    return {
      billingMode: 'sponsored',
      platformFeeBps: 0,
      feeMint: outputMint,
      feeSide: 'output',
      feeAccount: null,
      feeAccountExists: false,
      needsFeeAtaSetup: false,
      estimatedRelayCostLamports: baseSwapLamports.toString(),
      estimatedRelayCostUsd,
      estimatedSwapUsd: null,
      estimatedFeeUsd: 0,
      reason: 'Relayer fee account unavailable on this cluster; swap sponsored under rate limits.',
    }
  }

  // If swapping directly INTO WSOL, we know the exact SOL value without needing any USD oracle!
  let swapSolValue: number | null = null
  if (outputMint === WSOL_MINT_STR) {
    swapSolValue = Number(estimatedOutAmount) / 1e9
  } else if (
    solPriceUsd &&
    solPriceUsd > 0 &&
    outputTokenPriceUsd &&
    outputTokenPriceUsd > 0
  ) {
    const uiOut = Number(estimatedOutAmount) / Math.pow(10, Math.max(0, outputDecimals))
    if (Number.isFinite(uiOut) && uiOut > 0) {
      swapSolValue = (uiOut * outputTokenPriceUsd) / solPriceUsd
    }
  }

  const estimatedSwapUsd =
    swapSolValue !== null && solPriceUsd && solPriceUsd > 0
      ? swapSolValue * solPriceUsd
      : null

  const marginMult = cfg.selfPayMarginBps / 10_000

  // Case 1: Relayer fee ATA does NOT exist yet for this output mint
  if (!feeAccountExists) {
    const neededSolWithAta = (Number(totalLamportsIfCreatingAta) / 1e9) * marginMult
    if (swapSolValue !== null && swapSolValue > 0) {
      const reqBpsWithAta = Math.ceil((neededSolWithAta / swapSolValue) * 10_000)
      if (reqBpsWithAta <= cfg.maxSelfPayBps) {
        const feeBps = Math.max(cfg.baseSwapFeeBps, reqBpsWithAta)
        const estimatedFeeUsd =
          estimatedSwapUsd !== null ? (estimatedSwapUsd * feeBps) / 10_000 : null
        return {
          billingMode: 'self_paying',
          platformFeeBps: feeBps,
          feeMint: outputMint,
          feeSide: 'output',
          feeAccount,
          feeAccountExists: false,
          needsFeeAtaSetup: true,
          estimatedRelayCostLamports: totalLamportsIfCreatingAta.toString(),
          estimatedRelayCostUsd:
            solPriceUsd && solPriceUsd > 0
              ? (Number(totalLamportsIfCreatingAta) / 1e9) * solPriceUsd
              : null,
          estimatedSwapUsd,
          estimatedFeeUsd,
          reason: `${(feeBps / 100).toFixed(2)}% relay fee covers first-time fee ATA creation + Solana rent — zero SOL needed.`,
        }
      }
    }
    // Small swap into a mint with no existing relayer fee ATA: don't burn ATA rent, sponsor cleanly!
    return {
      billingMode: 'sponsored',
      platformFeeBps: 0,
      feeMint: outputMint,
      feeSide: 'output',
      feeAccount: null,
      feeAccountExists: false,
      needsFeeAtaSetup: false,
      estimatedRelayCostLamports: baseSwapLamports.toString(),
      estimatedRelayCostUsd,
      estimatedSwapUsd,
      estimatedFeeUsd: 0,
      reason: 'Small swap into new output mint; relay sponsors Solana rent under rate limits.',
    }
  }

  // Case 2: Relayer fee ATA already exists on-chain (zero ATA rent!)
  if (swapSolValue === null || swapSolValue <= 0) {
    return {
      billingMode: 'sponsored',
      platformFeeBps: cfg.baseSwapFeeBps,
      feeMint: outputMint,
      feeSide: 'output',
      feeAccount,
      feeAccountExists: true,
      needsFeeAtaSetup: false,
      estimatedRelayCostLamports: baseSwapLamports.toString(),
      estimatedRelayCostUsd,
      estimatedSwapUsd: null,
      estimatedFeeUsd: null,
      reason: `${(cfg.baseSwapFeeBps / 100).toFixed(2)}% relay fee (price feed unavailable for this token; guarded by sponsor limits).`,
    }
  }

  const requiredBps = Math.ceil(((costSol * marginMult) / swapSolValue) * 10_000)
  if (requiredBps <= cfg.maxSelfPayBps) {
    const feeBps = Math.max(cfg.baseSwapFeeBps, requiredBps)
    const estimatedFeeUsd =
      estimatedSwapUsd !== null ? (estimatedSwapUsd * feeBps) / 10_000 : null
    return {
      billingMode: 'self_paying',
      platformFeeBps: feeBps,
      feeMint: outputMint,
      feeSide: 'output',
      feeAccount,
      feeAccountExists: true,
      needsFeeAtaSetup: false,
      estimatedRelayCostLamports: baseSwapLamports.toString(),
      estimatedRelayCostUsd,
      estimatedSwapUsd,
      estimatedFeeUsd,
      reason: `${(feeBps / 100).toFixed(2)}% relay fee fully covers Solana rent & gas — zero SOL needed.`,
    }
  }

  const feeBps = cfg.allowMicroSwapSubsidy ? cfg.microSwapFeeBps : cfg.maxSelfPayBps
  const estimatedFeeUsd =
    estimatedSwapUsd !== null ? (estimatedSwapUsd * feeBps) / 10_000 : null
  return {
    billingMode: 'sponsored',
    platformFeeBps: feeBps,
    feeMint: outputMint,
    feeSide: 'output',
    feeAccount,
    feeAccountExists: true,
    needsFeeAtaSetup: false,
    estimatedRelayCostLamports: baseSwapLamports.toString(),
    estimatedRelayCostUsd,
    estimatedSwapUsd,
    estimatedFeeUsd,
    reason: `${(feeBps / 100).toFixed(2)}% relay fee + relay rent subsidy for small swap (rate-limited).`,
  }
}
