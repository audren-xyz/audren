/**
 * Zero-dependency HTTP client for any Audren-compatible Privacy Relayer
 * (such as `https://relay.audren.xyz` or a self-hosted `audren-relay` instance).
 *
 * Types match `audren-relay/src/types.ts` and `audren-relay/src/index.ts` exactly.
 */

import type { RouterAccountMeta, RouterSwapInstruction } from './swap.ts';

export type RelayCluster = 'mainnet' | 'devnet';
export type RelayAggregatorId = 'jupiter' | 'bedrock' | 'dflow' | 'titan' | 'okx';
export type RelayAggregatorProvider = 'auto' | RelayAggregatorId;

export interface RelayRentSchedule {
  nullifierRentLamports: string;
  pageRentPerNoteLamports: string;
  ataRentLamports: string;
  swapBaselineLamports: string;
}

export interface RelayInfoResponse {
  cluster: RelayCluster;
  relayerPubkey: string | null;
  balanceSol: number | null;
  rentSchedule: RelayRentSchedule | null;
  aggregators?: unknown;
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
  lookupTables?: string[];
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
  computeUnitLimit?: number;
  priorityFeeLamports?: string;
  vaultOutAta?: string;
  rolloverFromPageId?: string;
  provider?: RelayAggregatorId;
}

export interface RelaySubmitResponse {
  signature: string;
  cluster: RelayCluster;
  relayerPubkey: string;
  [key: string]: unknown;
}

export class AudrenRelayClient {
  readonly baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  private async requestJson<T>(path: string, init?: RequestInit): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, init);
    const text = await res.text();
    let parsed: unknown = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      // fall through to HTTP status error below
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
