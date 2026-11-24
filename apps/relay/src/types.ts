export type Cluster = 'mainnet' | 'devnet'

export type AggregatorId = 'jupiter' | 'bedrock' | 'dflow' | 'titan' | 'okx'
export type AggregatorSelection = AggregatorId | 'auto'

export type AudrenOpKind = 'transfer' | 'withdraw' | 'exec_escrow'

export type BillingMode = 'self_paying' | 'sponsored'

export interface SolanaAccountMeta {
  pubkey: Uint8Array
  isSigner: boolean
  isWritable: boolean
}

export interface SolanaAccountMetaJson {
  pubkey: string
  isSigner: boolean
  isWritable: boolean
}

export interface SolanaInstruction {
  programId: Uint8Array
  accounts: SolanaAccountMeta[]
  data: Uint8Array
}

export interface EncodedRouterInstruction {
  programId: string
  accounts: SolanaAccountMetaJson[]
  data: string // base64
}

export interface RouteLegSummary {
  label: string
  ammKey?: string
  inputMint: string
  outputMint: string
  inAmount: string
  outAmount: string
  percent?: number
}

export interface SwapFeePlan {
  billingMode: BillingMode
  platformFeeBps: number
  feeMint: string
  feeSide: 'output' | 'input'
  feeAccount: string | null
  feeAccountExists: boolean
  needsFeeAtaSetup: boolean
  estimatedRelayCostLamports: string
  estimatedRelayCostUsd: number | null
  estimatedSwapUsd: number | null
  estimatedFeeUsd: number | null
  reason: string
}

export interface NativeFeeQuote {
  ok: true
  cluster: Cluster
  op: AudrenOpKind
  billingMode: BillingMode
  feeSide: 'in' | 'out' | 'shielded_cm2'
  feeMint: string
  feeTokenProgram: string | null
  feeDecimals: number
  feeRecipient: string | null
  feeShieldedAddress: string | null
  feeRecipientExists: boolean
  needsFeeAtaSetup: boolean
  /** Exact raw fee in base units of `feeMint` (lamports for WSOL / `unwrap_wsol` / shielded WSOL note). */
  relayerFee: string
  /**
   * Minimum flat fee floor in base units of `feeMint` (`ceil(costLamports * marginBps)` converted to
   * gross fee-mint base units), independent of `amount` / percentage bps.
   */
  minFlatFeeUnits?: string
  feeBps: number
  /** True when the fee is a flat per-mint rent/gas fee independent of transfer amount (`op === 'transfer'`). */
  flatFee?: boolean
  /** Number of NullifierPDA accounts priced into the quote (`1` when `omitNf1=true`, `2` when `omitNf1=false`). */
  nullifierCount?: number
  /** Selected relayer fee-payer pubkey (rotated across configured `relayerPubkeys`). */
  relayerPubkey?: string | null
  /** Randomly assigned or requested `ExecViaEscrow` shard ID (`0..15`, populated for `op === 'exec_escrow'`). */
  shardId?: number
  /** Derived `ExecViaEscrow` escrow PDA for `shardId` (populated for `op === 'exec_escrow'`). */
  escrowPda?: string
  estimatedRelayCostLamports: string
  estimatedRelayCostUsd: number | null
  reason: string
}

export interface MissingAtaPlan {
  label: string
  ata: string
  owner: string
  mint: string
  tokenProgram: string
}

export interface NormalizedQuote {
  provider: AggregatorId
  inputMint: string
  outputMint: string
  inAmount: string
  outAmount: string
  otherAmountThreshold: string
  slippageBps: number
  priceImpactPct?: string | null
  platformFee?: {
    amount: string
    feeBps: number
    mint?: string
  } | null
  routePlan: Array<{ swapInfo: RouteLegSummary; percent?: number }>
  contextSlot?: number | null
  latencyMs: number
  rawQuote: Record<string, unknown>
}

export interface NormalizedSwapInstructions {
  provider: AggregatorId
  swapInstruction: EncodedRouterInstruction
  addressLookupTableAddresses: string[]
  computeUnitLimit: number
  feeAccount: string | null
}

export interface RelayInstructionPayload {
  instructionDataB64: string
  accounts: SolanaAccountMetaJson[]
}

export interface RelaySubmitRequest {
  cluster?: Cluster
  /** Single-instruction wire payload (omit when submitting batched `instructions`). */
  instructionDataB64?: string
  /** Single-instruction accounts (omit when submitting batched `instructions`). */
  accounts?: SolanaAccountMetaJson[]
  /**
   * Optional multi-instruction batch (1..=4 parallel `2 -> 1` private `Transact` merges
   * submitted atomically inside one Solana Transaction v1 `0x81`).
   */
  instructions?: RelayInstructionPayload[]
  setupAtas?: Array<{ owner: string; mint: string; tokenProgram: string }>
  /**
   * Optional strictly-allowlisted zero-signer DeFi refresh cranks prepended BEFORE
   * Tag 6 (`ExecViaEscrow`), e.g. Kamino `RefreshReserve` / Pyth oracle updates.
   */
  preInstructions?: EncodedRouterInstruction[]
  computeUnitLimit?: number
  priorityFeeLamports?: string
  vaultOutAta?: string
  provider?: AggregatorId
}
