import { AUDREN_PROGRAM_ID, CLASSIC_TOKEN_PROGRAM_ID } from './constants.ts';
import { deriveAssociatedTokenAddress, deriveEscrowPda } from './pda.ts';

/**
 * Protocol-Agnostic Shielded DeFi Execution (`ExecViaEscrow`) & Aggregator Route Helpers.
 *
 * Works with any compatible PDA-signing Solana program (DEX aggregators, supply lending,
 * yield vaults, liquid staking, perp LP, RWA mint/redeem) that satisfies Audren custody
 * checks and transaction limits.
 */

/**
 * Jupiter DEX labels that reject PDA CPI callers (e.g. `InvalidRealUser` / top-level
 * instruction sysvar introspection) and are excluded by default when routing through
 * Audren's isolated `escrow` PDA.
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
  /** Cap total route accounts to fit inside Solana Transaction v1's 64-account budget (default 28). */
  maxAccounts?: number;
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
 * targeting Audren's shared sharded `escrow` PDA (e.g. `https://api.jup.ag/swap/v1`
 * or any self-hosted / custom aggregator endpoint).
 */
export async function fetchAggregatorPrivateSwapRoute(
  aggregatorBaseUrl: string,
  quoteParams: RouterQuoteParams,
  escrowAddress: string,
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
    maxAccounts: String(quoteParams.maxAccounts ?? 28),
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
      userPublicKey: escrowAddress,
      wrapAndUnwrapSol: false,
      useSharedAccounts: false,
      dynamicComputeUnitLimit: false,
      skipUserAccountsRpcCalls: true,
    }),
  });
  if (!swapRes.ok) {
    throw new Error(`Aggregator /swap-instructions failed: HTTP ${swapRes.status}`);
  }
  const swap = (await swapRes.json()) as RouterSwapInstructionsResponse;
  return { quote, swap };
}

/**
 * Locate `(escrowIdx, escrowInIdx, escrowOutIdx)` inside an arbitrary external program
 * account list for compatible PDA-signing instructions accepted by Audren's `ExecViaEscrow`.
 */
export function resolveEscrowIndices(
  actionAccounts: readonly RouterAccountMeta[],
  escrowAddress: string,
  escrowInAta: string,
  escrowOutAta: string,
): ResolvedEscrowIndices {
  const escrowIdx = actionAccounts.findIndex((m) => m.pubkey === escrowAddress);
  const escrowInIdx = actionAccounts.findIndex((m) => m.pubkey === escrowInAta);
  const escrowOutIdx = actionAccounts.findIndex((m) => m.pubkey === escrowOutAta);
  if (escrowIdx < 0 || escrowInIdx < 0 || escrowOutIdx < 0) {
    throw new Error(
      `Missing escrow account in action instruction (escrow=${escrowIdx}, in=${escrowInIdx}, out=${escrowOutIdx})`,
    );
  }
  return { escrowIdx, escrowInIdx, escrowOutIdx };
}

/**
 * Strip the external signer bit on `escrowAddress` before attaching action accounts
 * to Audren's `ExecViaEscrow` instruction (Audren signs `escrow` via `invoke_signed`).
 */
export function prepareEscrowAccountsForAudren(
  actionAccounts: readonly RouterAccountMeta[],
  escrowAddress: string,
): RouterAccountMeta[] {
  return actionAccounts.map((meta) => ({
    pubkey: meta.pubkey,
    isSigner: meta.pubkey === escrowAddress ? false : meta.isSigner,
    isWritable: meta.isWritable,
  }));
}

export interface PreparedEscrowAccounts {
  escrowPda: string;
  escrowInAta: string;
  escrowOutAta: string;
  escrowIdx: number;
  escrowInIdx: number;
  escrowOutIdx: number;
  accounts: RouterAccountMeta[];
}

/**
 * High-level cross-SDK helper (mirrors Rust `prepare_escrow_accounts`, Swift `prepareEscrowAccounts`,
 * and Kotlin `prepareEscrowAccounts`): derives the sharded `escrow` PDA and its input/output
 * ATAs, locates `(escrowIdx, escrowInIdx, escrowOutIdx)`, and strips the external signer bit on
 * `escrow` so Audren can sign via `invoke_signed`.
 */
export async function prepareEscrowAccounts(params: {
  poolId: number;
  shardId: number;
  inputMint: string;
  outputMint: string;
  inputTokenProgram?: string;
  outputTokenProgram?: string;
  actionAccounts: readonly RouterAccountMeta[];
  programId?: string;
}): Promise<PreparedEscrowAccounts> {
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const inputTp = params.inputTokenProgram ?? CLASSIC_TOKEN_PROGRAM_ID;
  const outputTp = params.outputTokenProgram ?? CLASSIC_TOKEN_PROGRAM_ID;
  const { address: escrowPda } = await deriveEscrowPda(params.poolId, params.shardId, programId);
  const { address: escrowInAta } = await deriveAssociatedTokenAddress(
    escrowPda,
    params.inputMint,
    inputTp,
  );
  const { address: escrowOutAta } = await deriveAssociatedTokenAddress(
    escrowPda,
    params.outputMint,
    outputTp,
  );
  const { escrowIdx, escrowInIdx, escrowOutIdx } = resolveEscrowIndices(
    params.actionAccounts,
    escrowPda,
    escrowInAta,
    escrowOutAta,
  );
  const accounts = prepareEscrowAccountsForAudren(params.actionAccounts, escrowPda);
  return {
    escrowPda,
    escrowInAta,
    escrowOutAta,
    escrowIdx,
    escrowInIdx,
    escrowOutIdx,
    accounts,
  };
}
