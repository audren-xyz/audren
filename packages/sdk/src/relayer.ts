/**
 * HTTP client for any Audren Privacy Relayer (`https://relay.audren.xyz` or self-hosted).
 *
 * Supports all three V2 fee settlement modes:
 * 1. `transfer` (`ASSET_MODE_PRIVATE`): shielded `cm2` fee note verified via relayer read-only FVK.
 * 2. `withdraw` (`ASSET_MODE_SOL` / `ASSET_MODE_SPL` / `WITHDRAW_FLAG_UNWRAP_WSOL`): public fee deduction.
 * 3. `exec_escrow` (`ExecViaEscrow` Tag 7): input-leg fee or `EXEC_FLAG_FEE_ON_OUTPUT`.
 */

import type { RouterAccountMeta, RouterSwapInstruction } from './swap.ts';

export type RelayCluster = 'mainnet' | 'devnet';
export type RelayAggregatorId = 'jupiter' | 'bedrock' | 'dflow' | 'titan' | 'okx';
export type RelayAggregatorProvider = 'auto' | RelayAggregatorId;
export type RelayOperation = 'transfer' | 'withdraw' | 'exec_escrow';

export interface RelayRentSchedule {
  nullifierRentLamports: string;
  noteRentPerLeafLamports: string;
  ataRentLamports: string;
  swapBaselineLamports: string;
}

export interface RelayInfoResponse {
  protocolVersion: number;
  cluster: RelayCluster;
  relayerPubkey: string | null;
  relayerPubkeys?: string[];
  relayerShieldedAddress?: string | null;
  balanceSol: number | null;
  rentSchedule: RelayRentSchedule | null;
  aggregators?: unknown;
  allowedPreIxPrograms?: string[];
  [key: string]: unknown;
}

export interface RelayFeeQuoteRequest {
  cluster?: RelayCluster;
  op: RelayOperation;
  mint: string;
  amount: string;
  unwrapWsol?: boolean;
  feeOnOutput?: boolean;
  outputCount?: number;
  missingAtaCount?: number;
}

export interface RelayFeeQuoteResponse {
  ok: boolean;
  cluster: RelayCluster;
  op: RelayOperation;
  billingMode: 'self_paying' | 'sponsored';
  feeSide: 'in' | 'out' | 'shielded_cm2';
  feeMint: string;
  feeTokenProgram: string | null;
  feeRecipient: string | null;
  feeShieldedAddress: string | null;
  feeRecipientExists: boolean;
  needsFeeAtaSetup: boolean;
  relayerFee: string;
  feeBps: number;
  estimatedRelayCostLamports: string;
  estimatedRelayCostUsd: number | null;
  reason: string;
  [key: string]: unknown;
}

export interface RelaySwapQuoteRequest {
  inputMint: string;
  outputMint: string;
  amount: string;
  slippageBps?: number;
  provider?: RelayAggregatorProvider;
  cluster?: RelayCluster;
  shardId?: number;
  onlyDirectRoutes?: boolean;
  maxAccounts?: number;
  includeFee?: boolean;
}

export interface RelaySwapInstructionsRequest {
  provider: RelayAggregatorId;
  quoteResponse: unknown;
  inputMint: string;
  outputMint: string;
  cluster?: RelayCluster;
  shardId?: number;
  includeFee?: boolean;
}

export interface RelayMissingAtaPlan {
  label: string;
  ata: string;
  owner: string;
  mint: string;
  tokenProgram: string;
}

export interface RelaySwapInstructionsResponse {
  provider: RelayAggregatorId;
  swapInstruction: RouterSwapInstruction;
  missingAtas: RelayMissingAtaPlan[];
  addressLookupTableAddresses?: string[];
  lookupTables?: Record<string, string[]>;
  computeUnitLimit?: number;
  escrowPda?: string;
  vaultAuth?: string;
  vaultInAta?: string;
  vaultOutAta?: string;
  escrowInAta?: string;
  escrowOutAta?: string;
  tokenProgramIn?: string;
  tokenProgramOut?: string;
  relayerFeeAta?: string | null;
  platformFeeBps?: number;
  [key: string]: unknown;
}

export interface RelaySetupAta {
  owner: string;
  mint: string;
  tokenProgram: string;
}

export interface RelaySubmitRequest {
  cluster?: RelayCluster;
  instructionDataB64: string;
  accounts: RouterAccountMeta[];
  setupAtas?: RelaySetupAta[];
  /** Optional zero-signer crank pre-instructions allowlisted strictly for `ExecViaEscrow` (Tag 7). */
  preInstructions?: RouterSwapInstruction[];
  computeUnitLimit?: number;
  priorityFeeLamports?: string;
  provider?: RelayAggregatorId;
}

export interface RelaySubmitResponse {
  signature: string;
  cluster: RelayCluster;
  relayerPubkey: string;
  [key: string]: unknown;
}

export const AUDREN_DEFAULT_RELAY_URL = 'https://relay.audren.xyz';
export const DEFAULT_RELAY_URL = AUDREN_DEFAULT_RELAY_URL;

export class AudrenRelayClient {
  readonly baseUrl: string;

  constructor(baseUrl: string = AUDREN_DEFAULT_RELAY_URL) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  private async requestJson<T>(path: string, init?: RequestInit): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, init);
    const text = await res.text();
    let parsed: unknown = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      // fall through
    }
    if (!res.ok) {
      const msg =
        parsed && typeof parsed === 'object' && 'error' in parsed
          ? String((parsed as { error: unknown }).error)
          : `Relay HTTP ${res.status}`;
      throw new Error(msg);
    }
    return parsed as T;
  }

  async getInfo(cluster: RelayCluster = 'mainnet'): Promise<RelayInfoResponse> {
    return this.requestJson<RelayInfoResponse>(`/v1/info?cluster=${encodeURIComponent(cluster)}`);
  }

  async getAggregators(): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>('/v1/aggregators');
  }

  async getStats(): Promise<Record<string, unknown>> {
    return this.requestJson<Record<string, unknown>>('/v1/stats');
  }

  async getFeeQuote(params: RelayFeeQuoteRequest): Promise<RelayFeeQuoteResponse> {
    const qs = new URLSearchParams({
      op: params.op,
      mint: params.mint,
      amount: params.amount,
      ...(params.cluster ? { cluster: params.cluster } : {}),
      ...(params.unwrapWsol !== undefined ? { unwrapWsol: String(params.unwrapWsol) } : {}),
      ...(params.feeOnOutput !== undefined ? { feeOnOutput: String(params.feeOnOutput) } : {}),
      ...(params.outputCount !== undefined ? { outputCount: String(params.outputCount) } : {}),
      ...(params.missingAtaCount !== undefined
        ? { missingAtaCount: String(params.missingAtaCount) }
        : {}),
    });
    return this.requestJson<RelayFeeQuoteResponse>(`/v1/fee-quote?${qs.toString()}`);
  }

  async quoteSwap(params: RelaySwapQuoteRequest): Promise<Record<string, unknown>> {
    const qs = new URLSearchParams({
      inputMint: params.inputMint,
      outputMint: params.outputMint,
      amount: params.amount,
      ...(params.slippageBps !== undefined ? { slippageBps: String(params.slippageBps) } : {}),
      ...(params.provider ? { provider: params.provider } : {}),
      ...(params.cluster ? { cluster: params.cluster } : {}),
      ...(params.shardId !== undefined ? { shardId: String(params.shardId) } : {}),
      ...(params.onlyDirectRoutes !== undefined
        ? { onlyDirectRoutes: String(params.onlyDirectRoutes) }
        : {}),
      ...(params.maxAccounts !== undefined ? { maxAccounts: String(params.maxAccounts) } : {}),
      ...(params.includeFee !== undefined ? { includeFee: String(params.includeFee) } : {}),
    });
    return this.requestJson<Record<string, unknown>>(`/v1/swap/quote?${qs.toString()}`);
  }

  async buildSwapInstructions(
    params: RelaySwapInstructionsRequest,
  ): Promise<RelaySwapInstructionsResponse> {
    return this.requestJson<RelaySwapInstructionsResponse>('/v1/swap/instructions', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(params),
    });
  }

  async submitRelayedInstruction(params: RelaySubmitRequest): Promise<RelaySubmitResponse> {
    return this.requestJson<RelaySubmitResponse>('/v1/relay/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(params),
    });
  }
}
