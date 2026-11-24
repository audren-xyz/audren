import { computeToken2022NetAmount, type Token2022TransferFee } from '@audren/sdk'
import type { Env, RelayPolicyConfig } from '../env'
import { TOKEN_2022_PROGRAM_ID_STR, WSOL_MINT_STR } from '../solana/codec'
import type { LiveRentSchedule } from '../solana/rpc'
import type { Cluster, NativeFeeQuote, SwapFeePlan } from '../types'

/**
 * Estimate exact rent-exemption lamports for a canonical SPL or Token-2022 ATA:
 *   - Classic SPL (`165 B` -> `293` storage bytes): `ataRent` (`2_039_280` lamports at mainnet rent)
 *   - Token-2022 base (`165 + 1 + 4 = 170 B` `ImmutableOwner` -> `298` storage bytes):
 *     `ceil(ataRent * 298 / 293)` (`2_074_080` lamports)
 *   - Token-2022 with required account extensions (e.g. `TransferFeeAmount` `182 B`,
 *     `TransferHookAccount` `175 B`, `TransferFeeAmount + TransferHookAccount` `187 B`,
 *     `PausableAccount` / `NonTransferableAccount` `+4 B`):
 *     `ceil(ataRent * (ataByteLen + 128) / 293)`
 */
export function estimateAtaRentLamports(
  ataRent: bigint,
  tokenProgram: string | null | undefined,
  ataByteLenOrHasTransferFeeExt: number | boolean = false,
): bigint {
  if (ataRent <= 0n) return 0n
  if (tokenProgram === TOKEN_2022_PROGRAM_ID_STR) {
    const byteLen =
      typeof ataByteLenOrHasTransferFeeExt === 'number'
        ? Math.max(170, Math.trunc(ataByteLenOrHasTransferFeeExt))
        : ataByteLenOrHasTransferFeeExt
          ? 182
          : 170
    return (ataRent * BigInt(byteLen + 128) + 292n) / 293n
  }
  if (typeof ataByteLenOrHasTransferFeeExt === 'number') {
    const byteLen = Math.max(165, Math.trunc(ataByteLenOrHasTransferFeeExt))
    return byteLen === 165 ? ataRent : (ataRent * BigInt(byteLen + 128) + 292n) / 293n
  }
  return ataRent
}

/**
 * Gross up a required net token-unit fee to survive `hops` (`2` = receipt + liquidation) of an
 * active Token-2022 `TransferFeeConfig` schedule so BOTH:
 *   - Mode 1 (`gross - 2 * singleFee(gross)`) >= `netRequired`
 *   - Mode 2 / Mode 3 (`net(net(gross))`) >= `netRequired`
 */
export function grossUpToken2022Amount(
  netRequired: bigint,
  fee: Token2022TransferFee | null | undefined,
  hops: 1 | 2 = 2,
): bigint {
  if (netRequired <= 0n) return 0n
  if (!fee || fee.bps <= 0n) return netRequired
  const hopMult = BigInt(hops)
  const effectiveBps = fee.bps * hopMult
  if (effectiveBps >= 10_000n) {
    return netRequired + hopMult * fee.maxFee
  }
  const denom = 10_000n - effectiveBps
  const byBps = (netRequired * 10_000n + denom - 1n) / denom
  const byCap = netRequired + hopMult * fee.maxFee
  let gross = byBps < byCap ? byBps : byCap
  const netAfterHops = (g: bigint): bigint => {
    const afterOne = computeToken2022NetAmount(g, fee)
    const singleFee = g > afterOne ? g - afterOne : 0n
    const totalFee = hops === 1 ? singleFee : singleFee * 2n
    return g > totalFee ? g - totalFee : 0n
  }
  for (let i = 0; i < 6 && netAfterHops(gross) < netRequired; i++) {
    gross += 1n
  }
  return gross
}

function lamportsToGrossTokenUnits(params: {
  costLamports: bigint
  marginBps: number
  mint: string
  decimals: number
  solPriceUsd: number | null
  tokenPriceUsd: number | null
  transferFee?: Token2022TransferFee | null
}): bigint | null {
  const { costLamports, marginBps, mint, decimals, solPriceUsd, tokenPriceUsd, transferFee } = params
  const clampedMarginBps = BigInt(Math.max(marginBps, 10_000))
  const requiredLamports = (costLamports * clampedMarginBps + 9_999n) / 10_000n
  if (mint === WSOL_MINT_STR) {
    return requiredLamports
  }
  if (!solPriceUsd || solPriceUsd <= 0 || !tokenPriceUsd || tokenPriceUsd <= 0) {
    return null
  }
  const scale = Math.pow(10, Math.max(0, decimals))
  const neededUi = ((Number(requiredLamports) / 1e9) * solPriceUsd) / tokenPriceUsd
  if (!Number.isFinite(neededUi) || neededUi <= 0) return null
  let netUnits = BigInt(Math.max(1, Math.ceil(neededUi * scale)))
  const valuedLamports = (u: bigint) =>
    BigInt(Math.max(0, Math.floor((((Number(u) / scale) * tokenPriceUsd) / solPriceUsd) * 1e9)))
  if (valuedLamports(netUnits) < requiredLamports) {
    netUnits += 1n
  }
  return grossUpToken2022Amount(netUnits, transferFee, 2)
}

interface CachedPrice {
  usd: number
  fetchedAt: number
}

const PRICE_CACHE = new Map<string, CachedPrice>()
const PRICE_TTL_MS = 60_000
export const PRICE_CACHE_MAX_ENTRIES = 512

function setBoundedPriceCache(key: string, entry: CachedPrice, now: number): void {
  if (PRICE_CACHE.has(key)) {
    PRICE_CACHE.delete(key)
  }
  if (PRICE_CACHE.size >= PRICE_CACHE_MAX_ENTRIES) {
    for (const [k, v] of PRICE_CACHE) {
      if (now - v.fetchedAt >= PRICE_TTL_MS) {
        PRICE_CACHE.delete(k)
      }
    }
  }
  while (PRICE_CACHE.size >= PRICE_CACHE_MAX_ENTRIES) {
    const oldestKey = PRICE_CACHE.keys().next().value
    if (oldestKey === undefined) break
    PRICE_CACHE.delete(oldestKey)
  }
  PRICE_CACHE.set(key, entry)
}

export function getPriceCacheSize(): number {
  return PRICE_CACHE.size
}

export function clearPriceCache(): void {
  PRICE_CACHE.clear()
}

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
    } else {
      if (cached) PRICE_CACHE.delete(m)
      if (!missing.includes(m)) {
        missing.push(m)
      }
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
            setBoundedPriceCache(m, { usd: val, fetchedAt: now }, now)
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
  hasUnsafeSelfPayExt?: boolean
  /** Token program of `outputMint` (and `feeAccount` since `feeSide === 'output'`). Defaults to Classic SPL. */
  outputTokenProgram?: string | null
  /** True when `outputMint` is a Token-2022 mint carrying `TransferFeeConfig` (182 B ATA vs 170 B). */
  outputHasTransferFeeExt?: boolean
  /** Exact expected byte length of `outputMint` ATAs (`165 B` Classic SPL, `170 B+` Token-2022). */
  outputAtaByteLen?: number
  /** Active epoch Token-2022 `TransferFeeConfig` schedule for `outputMint` (grossed up 2x in required bps). */
  outputTransferFee?: Token2022TransferFee | null
  /** Number of missing canonical vault/escrow ATAs (`0..4`) whose creation rent is priced into the quote. */
  extraAtaCount?: number
  /**
   * Optional exact pre-computed rent lamports for missing vault/escrow ATAs (summing per-ATA
   * `estimateAtaRentLamports` for each missing input/output ATA). When omitted, falls back to
   * `extraAtaCount * estimateAtaRentLamports(ataRentLamports, outputTokenProgram, outputAtaByteLen ?? outputHasTransferFeeExt)`.
   */
  extraAtaRentLamports?: bigint
  /** Omit second nullifier (`nf1 = 0`). Defaults to `false` (2 nullifiers, padded spend). */
  omitNf1?: boolean
  /** Shielded output note count (change + dynamic output). Defaults to `2`. */
  outputCount?: number
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
    hasUnsafeSelfPayExt = false,
    outputTokenProgram = null,
    outputHasTransferFeeExt = false,
    outputAtaByteLen,
    outputTransferFee = null,
    extraAtaCount = 0,
    extraAtaRentLamports,
    omitNf1 = false,
    outputCount,
  } = params

  const hasCustomShape = omitNf1 || outputCount !== undefined
  const feeAtaRentLamports = estimateAtaRentLamports(
    rentSchedule.ataRentLamports,
    outputTokenProgram,
    outputAtaByteLen ?? (outputHasTransferFeeExt || Boolean(outputTransferFee)),
  )
  const extraAtaLamports =
    extraAtaRentLamports !== undefined
      ? extraAtaRentLamports > 0n
        ? extraAtaRentLamports
        : 0n
      : BigInt(Math.max(0, Math.min(4, Math.trunc(extraAtaCount)))) * feeAtaRentLamports
  const baseSwapLamports =
    (hasCustomShape
      ? BigInt(omitNf1 ? 1 : 2) *
          (rentSchedule.nullifierRentLamports + rentSchedule.nfPageRentPerNfLamports) +
        BigInt(Math.max(0, Math.min(3, Math.trunc(outputCount ?? 2)))) *
          rentSchedule.pageRentPerNoteLamports +
        20_000n
      : rentSchedule.swapBaselineLamports) + extraAtaLamports
  const totalLamportsIfCreatingAta = baseSwapLamports + feeAtaRentLamports
  const costSol = Number(baseSwapLamports) / 1e9
  const estimatedRelayCostUsd =
    solPriceUsd && solPriceUsd > 0 ? costSol * solPriceUsd : null
  const mintAllowedForSelfPay = cfg.selfPayFeeMints.has(outputMint)

  if (!feeAccount || hasUnsafeSelfPayExt || !mintAllowedForSelfPay) {
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
      reason: !mintAllowedForSelfPay
        ? 'Output mint is not in the relayer self-pay fee allowlist; sponsored under rate limits.'
        : hasUnsafeSelfPayExt
          ? 'Output mint carries unsafe authority or Token-2022 extensions excluded from self-pay fee credit; sponsored under rate limits.'
          : 'Relayer fee account unavailable on this cluster; action sponsored under rate limits.',
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
  const computeRequiredSwapBps = (costLamports: bigint, fallbackSolValue: number): number => {
    if (outputTransferFee && outputTransferFee.bps > 0n && estimatedOutAmount > 0n) {
      const grossUnits = lamportsToGrossTokenUnits({
        costLamports,
        marginBps: cfg.selfPayMarginBps,
        mint: outputMint,
        decimals: outputDecimals,
        solPriceUsd,
        tokenPriceUsd: outputTokenPriceUsd,
        transferFee: outputTransferFee,
      })
      if (grossUnits !== null) {
        return Number((grossUnits * 10_000n + estimatedOutAmount - 1n) / estimatedOutAmount)
      }
    }
    const neededSol = (Number(costLamports) / 1e9) * marginMult
    return Math.ceil((neededSol / fallbackSolValue) * 10_000)
  }

  if (!feeAccountExists) {
    if (swapSolValue !== null && swapSolValue > 0) {
      const reqBpsWithAta = computeRequiredSwapBps(totalLamportsIfCreatingAta, swapSolValue)
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

  const requiredBps = computeRequiredSwapBps(baseSwapLamports, swapSolValue)
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
 * Compute an exact protocol fee quote (`GET /v1/fee-quote`) for:
 *   - `transfer` (`ASSET_MODE_PRIVATE`): flat per-mint shielded `cm2` fee independent of `amount`
 *   - `withdraw` (`ASSET_MODE_PUBLIC`: atomic `unwrap_wsol` or SPL/Token-2022)
 *   - `exec_escrow` (SPL/Token-2022 DEX swap, Kamino supply, yield vault, LST mint, RWA vault, etc.)
 *
 * Defaults `omitNf1 = false` (2 nullifiers) across ALL ops so 1-nullifier spends are never encouraged
 * by default. Uses live on-chain rent from RPC + live token prices; falls back to `sponsored` cleanly
 * when an action is too small to self-pay without exceeding `maxSelfPayBps` or when a mint has no live USD price.
 */
export function computeNativeFeeQuote(params: {
  cluster: Cluster
  op: 'transfer' | 'withdraw' | 'exec_escrow'
  cfg: RelayPolicyConfig
  rentSchedule: LiveRentSchedule
  /** True strictly for `op === 'withdraw'` with `WITHDRAW_FLAG_UNWRAP_WSOL` (pays SOL lamports to relayerPubkey). */
  unwrapWsol?: boolean
  feeSide?: 'in' | 'out' | 'shielded_cm2'
  feeMint: string
  feeTokenProgram: string | null
  feeDecimals: number
  /** Used for `withdraw` / `exec_escrow` self-pay sizing; optional and ignored for `transfer`. */
  amount?: bigint
  outputCount?: number
  /** Omit second nullifier (`nf1 = 0`). Defaults to `false` (2 nullifiers) across ALL ops. */
  omitNf1?: boolean
  missingAtaCount?: number
  /**
   * Optional exact pre-computed rent lamports for missing ATAs (e.g. summed per mint from
   * `extraAtaMints`). When omitted, falls back to `missingAtaCount * effectiveAtaRent`.
   */
  extraAtaRentLamports?: bigint
  hasUnsafeSelfPayExt?: boolean
  /** True when `feeMint` is a Token-2022 mint carrying `TransferFeeConfig` (182 B ATA vs 170 B). */
  hasTransferFeeExt?: boolean
  /** Exact expected byte length of `feeMint` ATAs (`165 B` Classic SPL, `170 B+` Token-2022). */
  feeAtaByteLen?: number
  /** Active epoch Token-2022 `TransferFeeConfig` schedule for `feeMint` (grossed up 2x in quoted `relayerFee`). */
  transferFee?: Token2022TransferFee | null
  relayerPubkey?: string | null
  feeRecipient: string | null
  feeShieldedAddress?: string | null
  feeRecipientExists: boolean
  shardId?: number
  escrowPda?: string
  solPriceUsd: number | null
  feeTokenPriceUsd: number | null
}): NativeFeeQuote {
  const {
    cluster,
    op,
    cfg,
    rentSchedule,
    unwrapWsol = false,
    feeSide = op === 'transfer' ? 'shielded_cm2' : 'in',
    feeMint,
    feeTokenProgram,
    feeDecimals,
    outputCount = op === 'transfer' ? 3 : op === 'exec_escrow' ? 2 : 0,
    omitNf1 = false,
    missingAtaCount = 0,
    extraAtaRentLamports,
    hasUnsafeSelfPayExt = false,
    hasTransferFeeExt = false,
    feeAtaByteLen,
    transferFee = null,
    relayerPubkey = null,
    feeRecipient,
    feeShieldedAddress = null,
    feeRecipientExists,
    shardId,
    escrowPda,
    solPriceUsd,
    feeTokenPriceUsd,
  } = params

  const isDirectLamportPayout = op === 'withdraw' && unwrapWsol
  const mintAllowedForSelfPay = isDirectLamportPayout || cfg.selfPayFeeMints.has(feeMint)
  const nullifierCount = omitNf1 ? 1n : 2n
  const clampedOutputs = BigInt(Math.max(0, Math.min(3, Math.trunc(outputCount))))
  const nullifierRent =
    nullifierCount * (rentSchedule.nullifierRentLamports + rentSchedule.nfPageRentPerNfLamports)
  const noteRent = clampedOutputs * rentSchedule.pageRentPerNoteLamports
  const effectiveAtaRent = estimateAtaRentLamports(
    rentSchedule.ataRentLamports,
    feeTokenProgram,
    feeAtaByteLen ?? (hasTransferFeeExt || Boolean(transferFee)),
  )
  const extraAtas =
    extraAtaRentLamports !== undefined
      ? extraAtaRentLamports > 0n
        ? extraAtaRentLamports
        : 0n
      : BigInt(Math.max(0, Math.min(6, Math.trunc(missingAtaCount)))) * effectiveAtaRent
  const txBaseLamports = nullifierRent + noteRent + extraAtas + 20_000n
  const withAtaLamports = txBaseLamports + effectiveAtaRent
  const marginBps = BigInt(Math.max(cfg.selfPayMarginBps, 10_000))

  const costUsd = (lamports: bigint) =>
    solPriceUsd && solPriceUsd > 0 ? (Number(lamports) / 1e9) * solPriceUsd : null

  const metaFields = {
    ...(relayerPubkey !== null ? { relayerPubkey } : {}),
    ...(shardId !== undefined ? { shardId } : {}),
    ...(escrowPda !== undefined ? { escrowPda } : {}),
  }

  // Private transfers quote a strictly flat per-mint shielded cm2 fee; plaintext `amount` is never required or consulted.
  if (op === 'transfer') {
    if (!feeShieldedAddress || hasUnsafeSelfPayExt || !mintAllowedForSelfPay) {
      return {
        ok: true,
        cluster,
        op,
        billingMode: 'sponsored',
        feeSide: 'shielded_cm2',
        feeMint,
        feeTokenProgram,
        feeDecimals,
        feeRecipient: null,
        feeShieldedAddress,
        feeRecipientExists: false,
        needsFeeAtaSetup: false,
        relayerFee: '0',
        feeBps: 0,
        flatFee: true,
        nullifierCount: Number(nullifierCount),
        ...metaFields,
        estimatedRelayCostLamports: txBaseLamports.toString(),
        estimatedRelayCostUsd: costUsd(txBaseLamports),
        reason: !mintAllowedForSelfPay
          ? 'Mint is not in the relayer self-pay fee allowlist; sponsored under rate limits.'
          : hasUnsafeSelfPayExt
            ? 'Mint carries unsafe authority or Token-2022 extensions excluded from self-pay fee credit; sponsored under rate limits.'
            : 'Relayer shielded FVK target unavailable; sponsored under rate limits.',
      }
    }

    const flatTokenUnits = lamportsToGrossTokenUnits({
      costLamports: txBaseLamports,
      marginBps: cfg.selfPayMarginBps,
      mint: feeMint,
      decimals: feeDecimals,
      solPriceUsd,
      tokenPriceUsd: feeTokenPriceUsd,
      transferFee,
    })

    if (flatTokenUnits !== null) {
      return {
        ok: true,
        cluster,
        op,
        billingMode: 'self_paying',
        feeSide: 'shielded_cm2',
        feeMint,
        feeTokenProgram,
        feeDecimals,
        feeRecipient: null,
        feeShieldedAddress,
        feeRecipientExists: true,
        needsFeeAtaSetup: false,
        relayerFee: flatTokenUnits.toString(),
        feeBps: 0,
        flatFee: true,
        nullifierCount: Number(nullifierCount),
        ...metaFields,
        estimatedRelayCostLamports: txBaseLamports.toString(),
        estimatedRelayCostUsd: costUsd(txBaseLamports),
        reason:
          feeMint === WSOL_MINT_STR
            ? 'Flat shielded cm2 WSOL relay fee covering exact nullifier & page rent + gas (verified via read-only relayer FVK; transfer amount not required).'
            : 'Flat shielded cm2 SPL/Token-2022 relay fee covering exact nullifier & page rent + gas (verified via read-only relayer FVK; transfer amount not required).',
      }
    }

    return {
      ok: true,
      cluster,
      op,
      billingMode: 'sponsored',
      feeSide: 'shielded_cm2',
      feeMint,
      feeTokenProgram,
      feeDecimals,
      feeRecipient: null,
      feeShieldedAddress,
      feeRecipientExists: true,
      needsFeeAtaSetup: false,
      relayerFee: '0',
      feeBps: 0,
      flatFee: true,
      nullifierCount: Number(nullifierCount),
      ...metaFields,
      estimatedRelayCostLamports: txBaseLamports.toString(),
      estimatedRelayCostUsd: costUsd(txBaseLamports),
      reason: 'Unpriced token transfer sponsored under relay rate limits.',
    }
  }

  const amount = params.amount ?? 0n

  if (!feeRecipient || amount <= 0n || hasUnsafeSelfPayExt || !mintAllowedForSelfPay) {
    return {
      ok: true,
      cluster,
      op,
      billingMode: 'sponsored',
      feeSide,
      feeMint,
      feeTokenProgram: isDirectLamportPayout ? null : feeTokenProgram,
      feeDecimals,
      feeRecipient: hasUnsafeSelfPayExt || !mintAllowedForSelfPay ? feeRecipient : null,
      feeShieldedAddress,
      feeRecipientExists: hasUnsafeSelfPayExt || !mintAllowedForSelfPay ? feeRecipientExists : false,
      needsFeeAtaSetup: false,
      relayerFee: '0',
      feeBps: 0,
      flatFee: false,
      nullifierCount: Number(nullifierCount),
      ...metaFields,
      estimatedRelayCostLamports: txBaseLamports.toString(),
      estimatedRelayCostUsd: costUsd(txBaseLamports),
      reason: !mintAllowedForSelfPay
        ? 'Mint is not in the relayer self-pay fee allowlist; sponsored under rate limits.'
        : hasUnsafeSelfPayExt
          ? 'Mint carries unsafe authority or Token-2022 extensions excluded from self-pay fee credit; sponsored under rate limits.'
          : 'Relayer fee target unavailable; sponsored under rate limits.',
    }
  }

  // Atomic WSOL unwrap Withdraw (`WITHDRAW_FLAG_UNWRAP_WSOL`): relayer fee paid directly in SOL lamports to `relayerPubkey`
  if (isDirectLamportPayout) {
    const neededLamports = (txBaseLamports * marginBps + 9_999n) / 10_000n
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
        feeDecimals,
        feeRecipient,
        feeShieldedAddress: null,
        feeRecipientExists: true,
        needsFeeAtaSetup: false,
        relayerFee: candidateFee.toString(),
        feeBps: Math.max(1, effBps),
        flatFee: false,
        nullifierCount: Number(nullifierCount),
        ...metaFields,
        estimatedRelayCostLamports: txBaseLamports.toString(),
        estimatedRelayCostUsd: costUsd(txBaseLamports),
        reason:
          'Self-paying atomic WSOL-unwrap relay fee covers nullifier rent & gas — zero SOL needed in caller wallet.',
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
      feeDecimals,
      feeRecipient,
      feeShieldedAddress: null,
      feeRecipientExists: true,
      needsFeeAtaSetup: false,
      relayerFee: '0',
      feeBps: 0,
      flatFee: false,
      nullifierCount: Number(nullifierCount),
      ...metaFields,
      estimatedRelayCostLamports: txBaseLamports.toString(),
      estimatedRelayCostUsd: costUsd(txBaseLamports),
      reason: 'Small action sponsored under relay rate limits.',
    }
  }

  // SPL / Token-2022 fee mint (WSOL self-prices 1:1 with SOL; other mints use live USD price)
  const needsAta = !feeRecipientExists
  const effectiveLamports = needsAta ? withAtaLamports : txBaseLamports
  const neededTokenUnits = lamportsToGrossTokenUnits({
    costLamports: effectiveLamports,
    marginBps: cfg.selfPayMarginBps,
    mint: feeMint,
    decimals: feeDecimals,
    solPriceUsd,
    tokenPriceUsd: feeTokenPriceUsd,
    transferFee,
  })

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
        feeDecimals,
        feeRecipient,
        feeShieldedAddress: null,
        feeRecipientExists,
        needsFeeAtaSetup: needsAta,
        relayerFee: candidateFee.toString(),
        feeBps: Math.max(1, effBps),
        flatFee: false,
        nullifierCount: Number(nullifierCount),
        ...metaFields,
        estimatedRelayCostLamports: effectiveLamports.toString(),
        estimatedRelayCostUsd: costUsd(effectiveLamports),
        reason: feeRecipientExists
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
    feeDecimals,
    feeRecipient,
    feeShieldedAddress: null,
    feeRecipientExists,
    needsFeeAtaSetup: false,
    relayerFee: '0',
    feeBps: 0,
    flatFee: false,
    nullifierCount: Number(nullifierCount),
    ...metaFields,
    estimatedRelayCostLamports: txBaseLamports.toString(),
    estimatedRelayCostUsd: costUsd(txBaseLamports),
    reason: 'Small or unpriced token action sponsored under relay rate limits.',
  }
}
