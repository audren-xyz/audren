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
  feeRecipient: string | null
  feeShieldedAddress: string | null
  feeRecipientExists: boolean
  needsFeeAtaSetup: boolean
  /** Exact raw fee in base units of `feeMint` (lamports for Native SOL / unwrap_wsol / shielded SOL note). */
  relayerFee: string
  feeBps: number
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

export interface RelaySubmitRequest {
  cluster?: Cluster
  instructionDataB64: string
  accounts: SolanaAccountMetaJson[]
  setupAtas?: Array<{ owner: string; mint: string; tokenProgram: string }>
  /**
   * Optional strictly-allowlisted zero-signer DeFi refresh cranks prepended BEFORE
   * Tag 7 (`ExecViaEscrow`), e.g. Kamino `RefreshReserve` / Pyth oracle updates.
   */
  preInstructions?: EncodedRouterInstruction[]
  computeUnitLimit?: number
  priorityFeeLamports?: string
  vaultOutAta?: string
  provider?: AggregatorId
}
