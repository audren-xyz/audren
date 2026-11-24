import { CU_LIMIT_EXEC_VIA_ESCROW_BASE } from '../solana/audren'
import type { Env } from '../env'
import type {
  AggregatorId,
  NormalizedQuote,
  NormalizedSwapInstructions,
} from '../types'

export const SINGLE_HOP_ROUTER_CU_HEADROOM = 350_000
export const MULTI_HOP_ROUTER_CU_HEADROOM = 550_000
export const MAX_AGGREGATOR_TX_CU_LIMIT = 1_400_000

/**
 * Compute calibrated `ExecViaEscrow` (`Tag 6`) transaction CU budget for an aggregator swap:
 *   - Keeps `350_000` default router headroom for single-hop direct routes (`routeHopCount === 1`).
 *   - Uses `>= 550_000` router headroom for multi-hop routes (`routeHopCount > 1`), OKX, or
 *     routes with unknown hop count and missing provider `computeUnitLimit`.
 *   - Clamps total transaction CU strictly to Solana's `1_400_000` cap.
 */
export function computeAggregatorExecCuLimit(params: {
  reportedRouterCu?: number
  routeHopCount?: number | null
  forceMultiHopHeadroom?: boolean
}): number {
  const reported =
    typeof params.reportedRouterCu === 'number' &&
    Number.isFinite(params.reportedRouterCu) &&
    params.reportedRouterCu > 0
      ? Math.trunc(params.reportedRouterCu)
      : null
  const hopCount =
    typeof params.routeHopCount === 'number' &&
    Number.isFinite(params.routeHopCount) &&
    params.routeHopCount > 0
      ? Math.trunc(params.routeHopCount)
      : null
  const isSingleHopDirect = !params.forceMultiHopHeadroom && hopCount === 1
  const useMultiHopFloor =
    params.forceMultiHopHeadroom === true ||
    (hopCount !== null && hopCount > 1) ||
    (!isSingleHopDirect && reported === null)
  const minHeadroom = useMultiHopFloor
    ? MULTI_HOP_ROUTER_CU_HEADROOM
    : SINGLE_HOP_ROUTER_CU_HEADROOM
  const routerCu = Math.max(reported ?? minHeadroom, minHeadroom)
  return Math.min(CU_LIMIT_EXEC_VIA_ESCROW_BASE + routerCu, MAX_AGGREGATOR_TX_CU_LIMIT)
}

export interface AggregatorCapabilities {
  supportsPlatformFeeBps: boolean
  supportsSwapInstructions: boolean
  /** Whether the quote itself takes `userPublicKey` (e.g. Titan, OKX) or only `/swap-instructions` does. */
  quoteRequiresUserPubkey: boolean
  /** Fee side taken by this aggregator in ExactIn mode. */
  feeSide: 'output' | 'input' | 'either'
  /** Whether `feeAccount` expects the owner wallet pubkey (Bedrock/OKX) vs the token ATA (Jupiter/DFlow/Titan). */
  feeAccountStyle: 'ata' | 'owner_wallet'
}

export interface AdapterQuoteRequest {
  inputMint: string
  outputMint: string
  amount: string
  slippageBps: number
  onlyDirectRoutes?: boolean
  maxAccounts?: number
  platformFeeBps?: number
  /** Owner wallet pubkey of the relayer (used by aggregators with `feeAccountStyle: 'owner_wallet'`). */
  relayerOwner?: string
  /** Relayer fee ATA for the fee mint (used by aggregators with `feeAccountStyle: 'ata'`). */
  relayerFeeAta?: string
  /** Swap escrow PDA (passed when `quoteRequiresUserPubkey` is true, e.g. Titan/OKX). */
  escrowPubkey?: string
}

export interface AdapterSwapInstructionsRequest {
  quoteResponse: Record<string, unknown>
  escrowPubkey: string
  inputMint: string
  outputMint: string
  /** Relayer fee ATA (for `feeAccountStyle: 'ata'`). */
  feeAccountAta?: string
  /** Relayer owner wallet (for `feeAccountStyle: 'owner_wallet'`). */
  feeOwnerWallet?: string
  platformFeeBps?: number
}

export interface AggregatorAdapter {
  readonly id: AggregatorId
  readonly name: string
  readonly capabilities: AggregatorCapabilities
  isConfigured(env: Env): boolean
  quote(env: Env, req: AdapterQuoteRequest): Promise<NormalizedQuote>
  swapInstructions(env: Env, req: AdapterSwapInstructionsRequest): Promise<NormalizedSwapInstructions>
}
