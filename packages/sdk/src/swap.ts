/**
 * Router-Agnostic Private Swap Client & Stateless Relayer Helper.
 *
 * Works with compatible PDA-signing Solana routers that satisfy Audren custody
 * checks and transaction limits. Hosted route availability is provider-specific.
 */

/**
 * Jupiter DEX labels that reject PDA CPI callers (e.g. `InvalidRealUser` / top-level
 * instruction sysvar introspection) and are excluded by default when routing through
 * Audren's isolated `swap_escrow` PDA.
 */
export const JUPITER_CPI_EXCLUDED_DEXES: readonly string[] = [
  'Kipseli',
  'Quantum',
  'BisonFi',
  'BisonFi Predict',
  'BinaryFi',
  'Obsidian',
  'VaultLiquidUnstake',
  'Sanctum Prop S',
];

export interface RouterQuoteParams {
  inputMint: string;
  outputMint: string;
  amount: string;
  slippageBps: number;
  onlyDirectRoutes?: boolean;
  /** Override DEX exclusions (defaults to `JUPITER_CPI_EXCLUDED_DEXES`; pass `[]` to disable). */
  excludeDexes?: readonly string[];
}

export interface RouterAccountMeta {
  pubkey: string;
  isSigner: boolean;
  isWritable: boolean;
}

export interface RouterSwapInstruction {
  programId: string;
  accounts: RouterAccountMeta[];
  data: string; // base64
}

export interface RouterSwapInstructionsResponse {
  swapInstruction: RouterSwapInstruction;
  addressLookupTableAddresses?: string[];
  computeUnitLimit?: number;
}

export interface ResolvedEscrowIndices {
  escrowIdx: number;
  escrowInIdx: number;
  escrowOutIdx: number;
}

/**
 * Request a quote + `swap-instructions` payload from a Jupiter-compatible aggregator API
 * targeting Audren's shared sharded `swap_escrow` PDA (e.g. `https://lite-api.jup.ag/swap/v1`
 * or any self-hosted / custom aggregator endpoint).
 */
export async function fetchAggregatorPrivateSwapRoute(
  aggregatorBaseUrl: string,
  quoteParams: RouterQuoteParams,
  swapEscrowAddress: string,
): Promise<{
  quote: Record<string, unknown>;
  swap: RouterSwapInstructionsResponse;
}> {
  const base = aggregatorBaseUrl.replace(/\/$/, '');
  const excluded = quoteParams.excludeDexes ?? JUPITER_CPI_EXCLUDED_DEXES;
  const qs = new URLSearchParams({
    inputMint: quoteParams.inputMint,
    outputMint: quoteParams.outputMint,
    amount: quoteParams.amount,
    slippageBps: String(quoteParams.slippageBps),
    ...(quoteParams.onlyDirectRoutes ? { onlyDirectRoutes: 'true' } : {}),
    ...(excluded.length > 0 ? { excludeDexes: excluded.join(',') } : {}),
  });
  const quoteRes = await fetch(`${base}/quote?${qs.toString()}`);
  if (!quoteRes.ok) {
    throw new Error(`Aggregator /quote failed: HTTP ${quoteRes.status}`);
  }
  const quote = (await quoteRes.json()) as Record<string, unknown>;

  const swapRes = await fetch(`${base}/swap-instructions`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      quoteResponse: quote,
      userPublicKey: swapEscrowAddress,
      wrapAndUnwrapSol: false,
      useSharedAccounts: false,
    }),
  });
  if (!swapRes.ok) {
    throw new Error(`Aggregator /swap-instructions failed: HTTP ${swapRes.status}`);
  }
  const swap = (await swapRes.json()) as RouterSwapInstructionsResponse;
  return { quote, swap };
}

/**
 * Locate `(escrowIdx, escrowInIdx, escrowOutIdx)` inside an arbitrary external router
 * account list for compatible PDA-signing routes accepted by Audren's `SwapViaRouter` instruction.
 */
export function resolveRouterEscrowIndices(
  routerAccounts: readonly RouterAccountMeta[],
  swapEscrowAddress: string,
  escrowInAta: string,
  escrowOutAta: string,
): ResolvedEscrowIndices {
  const escrowIdx = routerAccounts.findIndex((m) => m.pubkey === swapEscrowAddress);
  const escrowInIdx = routerAccounts.findIndex((m) => m.pubkey === escrowInAta);
  const escrowOutIdx = routerAccounts.findIndex((m) => m.pubkey === escrowOutAta);
  if (escrowIdx < 0 || escrowInIdx < 0 || escrowOutIdx < 0) {
    throw new Error(
      `Missing escrow account in router instruction (escrow=${escrowIdx}, in=${escrowInIdx}, out=${escrowOutIdx})`,
    );
  }
  return { escrowIdx, escrowInIdx, escrowOutIdx };
}

/**
 * Strip the external signer bit on `swapEscrowAddress` before attaching router accounts
 * to Audren's `SwapViaRouter` instruction (Audren signs `swap_escrow` via `invoke_signed`).
 */
export function prepareRouterAccountsForAudren(
  routerAccounts: readonly RouterAccountMeta[],
  swapEscrowAddress: string,
): RouterAccountMeta[] {
  return routerAccounts.map((meta) => ({
    pubkey: meta.pubkey,
    isSigner: meta.pubkey === swapEscrowAddress ? false : meta.isSigner,
    isWritable: meta.isWritable,
  }));
}
