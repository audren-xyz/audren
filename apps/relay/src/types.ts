export type Cluster = 'mainnet' | 'devnet'

export type AggregatorId = 'jupiter' | 'bedrock' | 'dflow' | 'titan' | 'okx'
export type AggregatorSelection = AggregatorId | 'auto'

export type AudrenOpKind = 'transfer' | 'merge' | 'exec_escrow' | 'withdraw'

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
  /** True when the action is large enough to fund first-time creation of `feeAccount` atomically. */
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
  op: 'withdraw' | 'exec_escrow'
  billingMode: BillingMode
  feeMint: string
  feeTokenProgram: string | null
  feeRecipient: string | null
  feeRecipientExists: boolean
  needsFeeAtaSetup: boolean
  /** Native on-chain `relayer_fee` in raw base units of `feeMint` (lamports for Native SOL / unwrap_wsol). */
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
  /** Opaque provider quote object passed back to `/v1/swap/instructions`. */
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
   * Tag 5 (`ExecViaEscrow`), e.g. Kamino `RefreshReserve` / Pyth oracle updates.
   */
  preInstructions?: EncodedRouterInstruction[]
  computeUnitLimit?: number
  priorityFeeLamports?: string
  vaultOutAta?: string
  rolloverFromPageId?: string
  provider?: AggregatorId
}
