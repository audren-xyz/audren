import type { Env } from '../env'
import type {
  AggregatorId,
  NormalizedQuote,
  NormalizedSwapInstructions,
} from '../types'

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
