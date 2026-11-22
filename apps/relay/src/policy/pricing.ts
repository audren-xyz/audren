import type { Env, RelayPolicyConfig } from '../env'
import { WSOL_MINT_STR } from '../solana/codec'
import type { LiveRentSchedule } from '../solana/rpc'
import type { Cluster, NativeFeeQuote, SwapFeePlan } from '../types'

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
      reason: 'Relayer fee account unavailable on this cluster; action sponsored under rate limits.',
    }
  }

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

/**
 * Compute an exact native protocol fee quote (`GET /v1/fee-quote`) for either:
 *   - `withdraw` (Native SOL, atomic `unwrap_wsol`, or SPL/Token-2022)
 *   - `exec_escrow` (any DEX swap, Kamino supply, yield vault, LST mint, RWA vault, etc.)
 *
 * Uses live on-chain rent from RPC + live token prices; falls back to `sponsored` cleanly
 * when an action is too small to self-pay without exceeding `maxSelfPayBps`.
 */
export function computeNativeFeeQuote(params: {
  cluster: Cluster
  op: 'transfer' | 'withdraw' | 'exec_escrow'
  cfg: RelayPolicyConfig
  rentSchedule: LiveRentSchedule
  isNativeSolFee: boolean
  feeSide?: 'in' | 'out' | 'shielded_cm2'
  feeMint: string
  feeTokenProgram: string | null
  feeDecimals: number
  amount: bigint
  outputCount?: number
  missingAtaCount?: number
  hasUnsafeSelfPayExt?: boolean
  feeRecipient: string | null
  feeShieldedAddress?: string | null
  feeRecipientExists: boolean
  solPriceUsd: number | null
  feeTokenPriceUsd: number | null
}): NativeFeeQuote {
  const {
    cluster,
    op,
    cfg,
    rentSchedule,
    isNativeSolFee,
    feeSide = op === 'transfer' ? 'shielded_cm2' : 'in',
    feeMint,
    feeTokenProgram,
    feeDecimals,
    amount,
    outputCount = op === 'transfer' ? 3 : op === 'exec_escrow' ? 2 : 0,
    missingAtaCount = 0,
    hasUnsafeSelfPayExt = false,
    feeRecipient,
    feeShieldedAddress = null,
    feeRecipientExists,
    solPriceUsd,
    feeTokenPriceUsd,
  } = params

  const clampedOutputs = BigInt(Math.max(0, Math.min(3, Math.trunc(outputCount))))
  const noteRent = clampedOutputs * rentSchedule.pageRentPerNoteLamports
  const extraAtas = BigInt(Math.max(0, Math.min(6, Math.trunc(missingAtaCount)))) * rentSchedule.ataRentLamports
  const txBaseLamports =
    rentSchedule.nullifierRentLamports + noteRent + extraAtas + 20_000n
  const withAtaLamports = txBaseLamports + rentSchedule.ataRentLamports
  const marginMult = cfg.selfPayMarginBps / 10_000

  const costUsd = (lamports: bigint) =>
    solPriceUsd && solPriceUsd > 0 ? (Number(lamports) / 1e9) * solPriceUsd : null

  const activeTarget = op === 'transfer' ? feeShieldedAddress : feeRecipient
  if (!activeTarget || amount <= 0n || hasUnsafeSelfPayExt) {
    return {
      ok: true,
      cluster,
      op,
      billingMode: 'sponsored',
      feeSide,
      feeMint,
      feeTokenProgram,
      feeRecipient: hasUnsafeSelfPayExt ? feeRecipient : null,
      feeShieldedAddress,
      feeRecipientExists: hasUnsafeSelfPayExt ? feeRecipientExists : false,
      needsFeeAtaSetup: false,
      relayerFee: '0',
      feeBps: 0,
      estimatedRelayCostLamports: txBaseLamports.toString(),
      estimatedRelayCostUsd: costUsd(txBaseLamports),
      reason: hasUnsafeSelfPayExt
        ? 'Token-2022 mint carries extensions excluded from self-pay fee credit; sponsored under rate limits.'
        : 'Relayer fee target unavailable; sponsored under rate limits.',
    }
  }

  // Native SOL fee (Native SOL Withdraw, atomic `unwrap_wsol`, SOL ExecViaEscrow, or Mode 1 shielded SOL `cm2` note)
  if (isNativeSolFee) {
    const neededLamports = BigInt(Math.ceil(Number(txBaseLamports) * marginMult))
    const pctFee = (amount * BigInt(cfg.baseSwapFeeBps)) / 10_000n
    const candidateFee = neededLamports > pctFee ? neededLamports : pctFee
    const effBps = Number((candidateFee * 10_000n) / amount)
    if (candidateFee < amount && effBps <= cfg.maxSelfPayBps) {
      return {
        ok: true,
        cluster,
        op,
        billingMode: 'self_paying',
        feeSide,
        feeMint,
        feeTokenProgram: null,
        feeRecipient: op === 'transfer' ? null : feeRecipient,
        feeShieldedAddress: op === 'transfer' ? feeShieldedAddress : null,
        feeRecipientExists: true,
        needsFeeAtaSetup: false,
        relayerFee: candidateFee.toString(),
        feeBps: Math.max(1, effBps),
        estimatedRelayCostLamports: txBaseLamports.toString(),
        estimatedRelayCostUsd: costUsd(txBaseLamports),
        reason:
          op === 'transfer'
            ? 'Self-paying shielded cm2 SOL relay fee verified via read-only relayer FVK — zero public wallet exposure.'
            : 'Self-paying Native SOL relay fee covers nullifier rent & gas — zero SOL needed in caller wallet.',
      }
    }
    return {
      ok: true,
      cluster,
      op,
      billingMode: 'sponsored',
      feeSide,
      feeMint,
      feeTokenProgram: null,
      feeRecipient: op === 'transfer' ? null : feeRecipient,
      feeShieldedAddress: op === 'transfer' ? feeShieldedAddress : null,
      feeRecipientExists: true,
      needsFeeAtaSetup: false,
      relayerFee: '0',
      feeBps: 0,
      estimatedRelayCostLamports: txBaseLamports.toString(),
      estimatedRelayCostUsd: costUsd(txBaseLamports),
      reason: 'Small action sponsored under relay rate limits.',
    }
  }

  // SPL / Token-2022 fee mint (WSOL self-prices 1:1 with SOL; other mints use live USD price)
  const needsAta = op !== 'transfer' && !feeRecipientExists
  const effectiveLamports = needsAta ? withAtaLamports : txBaseLamports
  const neededSol = (Number(effectiveLamports) / 1e9) * marginMult
  let neededTokenUnits: bigint | null = null
  if (feeMint === WSOL_MINT_STR) {
    neededTokenUnits = BigInt(Math.ceil(neededSol * 1e9))
  } else if (solPriceUsd && solPriceUsd > 0 && feeTokenPriceUsd && feeTokenPriceUsd > 0) {
    const neededUi = (neededSol * solPriceUsd) / feeTokenPriceUsd
    if (Number.isFinite(neededUi) && neededUi > 0) {
      neededTokenUnits = BigInt(Math.max(1, Math.ceil(neededUi * Math.pow(10, feeDecimals))))
    }
  }

  if (neededTokenUnits !== null) {
    const pctFee = (amount * BigInt(cfg.baseSwapFeeBps)) / 10_000n
    const candidateFee = neededTokenUnits > pctFee ? neededTokenUnits : pctFee
    const effBps = Number((candidateFee * 10_000n) / amount)
    if (candidateFee < amount && effBps <= cfg.maxSelfPayBps) {
      return {
        ok: true,
        cluster,
        op,
        billingMode: 'self_paying',
        feeSide,
        feeMint,
        feeTokenProgram,
        feeRecipient: op === 'transfer' ? null : feeRecipient,
        feeShieldedAddress: op === 'transfer' ? feeShieldedAddress : null,
        feeRecipientExists: op === 'transfer' ? true : feeRecipientExists,
        needsFeeAtaSetup: needsAta,
        relayerFee: candidateFee.toString(),
        feeBps: Math.max(1, effBps),
        estimatedRelayCostLamports: effectiveLamports.toString(),
        estimatedRelayCostUsd: costUsd(effectiveLamports),
        reason:
          op === 'transfer'
            ? 'Self-paying shielded cm2 SPL relay fee verified via read-only relayer FVK.'
            : feeRecipientExists
              ? 'Self-paying protocol relay fee fully covers Solana rent & gas.'
              : 'Self-paying protocol relay fee covers first-time relayer fee ATA creation + Solana rent.',
      }
    }
  }

  return {
    ok: true,
    cluster,
    op,
    billingMode: 'sponsored',
    feeSide,
    feeMint,
    feeTokenProgram,
    feeRecipient: op === 'transfer' ? null : feeRecipient,
    feeShieldedAddress: op === 'transfer' ? feeShieldedAddress : null,
    feeRecipientExists: op === 'transfer' ? true : feeRecipientExists,
    needsFeeAtaSetup: false,
    relayerFee: '0',
    feeBps: 0,
    estimatedRelayCostLamports: txBaseLamports.toString(),
    estimatedRelayCostUsd: costUsd(txBaseLamports),
    reason: 'Small or unpriced token action sponsored under relay rate limits.',
  }
}
