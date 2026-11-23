/**
 * HTTP client for any Audren Privacy Relayer (`https://relay.audren.xyz` or self-hosted).
 *
 * Supports all three protocol fee settlement modes:
 * 1. `transfer` (`ASSET_MODE_PRIVATE`): shielded `cm2` fee note verified via relayer read-only FVK.
 * 2. `withdraw` (`ASSET_MODE_PUBLIC` / `WITHDRAW_FLAG_UNWRAP_WSOL`): public fee deduction.
 * 3. `exec_escrow` (`ExecViaEscrow` Tag 6): input-leg fee or `EXEC_FLAG_FEE_ON_OUTPUT`.
 */

import type { RouterAccountMeta, RouterSwapInstruction } from './swap.ts';

export type RelayCluster = 'mainnet' | 'devnet';
export type RelayAggregatorId = 'jupiter' | 'bedrock' | 'dflow' | 'titan' | 'okx';
export type RelayAggregatorProvider = 'auto' | RelayAggregatorId;
export type RelayOperation = 'transfer' | 'withdraw' | 'exec_escrow';

export interface RelayRentSchedule {
  nullifierRentLamports: string;
  noteRentPerLeafLamports: string;
  pageRentPerNoteLamports?: string;
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
  amount?: string;
  unwrapWsol?: boolean;
  feeOnOutput?: boolean;
  outputCount?: number;
  omitNf1?: boolean;
  missingAtaCount?: number;
}

export interface RelayCheckpointResponse {
  ok: boolean;
  cluster: RelayCluster;
  status: 'published' | 'up_to_date' | 'cooldown';
  signature?: string;
  epoch?: number;
  slotsRemaining?: number;
  waitMs?: number;
  [key: string]: unknown;
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

export interface RelayInstructionPayload {
  instructionDataB64: string;
  accounts: RouterAccountMeta[];
}

export interface RelaySubmitRequest {
  cluster?: RelayCluster;
  /** Single-instruction wire payload (omit when passing batched `instructions`). */
  instructionDataB64?: string;
  /** Single-instruction accounts (omit when passing batched `instructions`). */
  accounts?: RouterAccountMeta[];
  /**
   * Optional multi-instruction batch (up to 4 parallel `2 -> 1` private `Transact` merges
   * packed into one Solana Transaction v1 `0x81`).
   */
  instructions?: RelayInstructionPayload[];
  setupAtas?: RelaySetupAta[];
  /** Optional zero-signer crank pre-instructions allowlisted strictly for `ExecViaEscrow` (Tag 6). */
  preInstructions?: RouterSwapInstruction[];
  computeUnitLimit?: number;
  priorityFeeLamports?: string;
  vaultOutAta?: string;
  provider?: RelayAggregatorId;
}

export interface RelaySubmitResponse {
  signature: string;
  cluster: RelayCluster;
  relayerPubkey: string;
  [key: string]: unknown;
}

export const AUDREN_DEFAULT_RELAY_URL = 'https://relay.audren.xyz';

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
    const query: Record<string, string> = {
      op: params.op,
      mint: params.mint,
    };
    // Privacy invariant: NEVER transmit private transfer amounts to the relayer.
    if (params.op !== 'transfer' && params.amount !== undefined) {
      query.amount = params.amount;
    }
    if (params.cluster) query.cluster = params.cluster;
    if (params.unwrapWsol !== undefined) query.unwrapWsol = String(params.unwrapWsol);
    if (params.feeOnOutput !== undefined) query.feeOnOutput = String(params.feeOnOutput);
    if (params.outputCount !== undefined) query.outputCount = String(params.outputCount);
    if (params.omitNf1 !== undefined) query.omitNf1 = String(params.omitNf1);
    if (params.missingAtaCount !== undefined) {
      query.missingAtaCount = String(params.missingAtaCount);
    }
    const qs = new URLSearchParams(query);
    return this.requestJson<RelayFeeQuoteResponse>(`/v1/fee-quote?${qs.toString()}`);
  }

  async requestCheckpoint(params?: {
    cluster?: RelayCluster;
    poolId?: number;
  }): Promise<RelayCheckpointResponse> {
    return this.requestJson<RelayCheckpointResponse>('/v1/checkpoint', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        ...(params?.cluster ? { cluster: params.cluster } : {}),
        ...(params?.poolId !== undefined ? { poolId: params.poolId } : {}),
      }),
    });
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
    const hasBatch = Array.isArray(params.instructions) && params.instructions.length > 0;
    const hasSingle = Boolean(params.instructionDataB64 && params.accounts);
    if (!hasBatch && !hasSingle) {
      throw new Error('RelaySubmitRequest requires either (instructionDataB64, accounts) or non-empty instructions');
    }
    return this.requestJson<RelaySubmitResponse>('/v1/relay/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(params),
    });
  }
}
