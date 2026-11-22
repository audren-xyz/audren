import type { AggregatorId, Cluster } from './types'
import type { RelayGuard } from './policy/guard-do'

export interface Env {
  RELAY_GUARD: DurableObjectNamespace<RelayGuard>

  // Secrets (configured exclusively via `wrangler secret put`)
  MAINNET_RPC_URL?: string
  DEVNET_RPC_URL?: string
  MAINNET_RELAYER_SECRET_B64?: string
  DEVNET_RELAYER_SECRET_B64?: string

  // Aggregator API credentials (configure the providers you want active via `wrangler secret put`)
  JUPITER_API_URL?: string
  JUPITER_API_KEY?: string
  BEDROCK_API_URL?: string
  BEDROCK_API_KEY?: string
  DFLOW_API_URL?: string
  DFLOW_API_KEY?: string
  TITAN_API_URL?: string
  TITAN_API_KEY?: string
  OKX_API_URL?: string
  OKX_API_KEY?: string
  OKX_SECRET_KEY?: string
  OKX_PASSPHRASE?: string

  // Optional internal admin bearer token for manual refill / diagnostics
  RELAY_ADMIN_TOKEN?: string

  // Non-secret tunable policy vars (from wrangler.jsonc)
  DEFAULT_AGGREGATOR?: string
  ENABLED_AGGREGATORS?: string
  ALLOWED_PRE_IX_PROGRAMS?: string
  BASE_SWAP_FEE_BPS?: string
  MAX_SELF_PAY_BPS?: string
  MICRO_SWAP_FEE_BPS?: string
  ALLOW_MICRO_SWAP_SUBSIDY?: string
  SELF_PAY_MARGIN_BPS?: string
  MAX_DAILY_SPONSORED_SOL_MAINNET?: string
  MAX_DAILY_SPONSORED_SOL_DEVNET?: string
  SPONSORED_PER_IP_PER_HOUR_MAINNET?: string
  SPONSORED_PER_IP_PER_DAY_MAINNET?: string
  SPONSORED_COOLDOWN_SEC_MAINNET?: string
  SELF_PAY_PER_IP_PER_10M?: string
  REFILL_MIN_SOL?: string
  REFILL_MIN_TOKEN_USD?: string
  CORS_ORIGINS?: string
}

export interface RelayPolicyConfig {
  defaultAggregator: AggregatorId
  enabledAggregators: Set<AggregatorId>
  /** Strictly allowlisted zero-signer crank programs permitted in `preInstructions` before Tag 5. */
  allowedPreIxPrograms: Set<string>
  baseSwapFeeBps: number
  maxSelfPayBps: number
  microSwapFeeBps: number
  allowMicroSwapSubsidy: boolean
  /** Basis points multiplier over raw lamport cost (11000 = 1.10x). */
  selfPayMarginBps: number
  maxDailySponsoredLamports: Record<Cluster, bigint>
  sponsoredPerIpPerHour: Record<Cluster, number>
  sponsoredPerIpPerDay: Record<Cluster, number>
  sponsoredCooldownSec: Record<Cluster, number>
  selfPayPerIpPer10m: number
  refillMinSol: number
  refillMinTokenUsd: number
  corsOrigins: string[]
}

const VALID_AGGREGATORS: readonly AggregatorId[] = ['jupiter', 'bedrock', 'dflow', 'titan', 'okx']

/**
 * Default zero-signer DeFi refresh/oracle crank programs permitted in `preInstructions`
 * immediately before Audren Tag 5 (`ExecViaEscrow`):
 *   - Kamino Lending (`KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD`) — `RefreshReserve`
 *   - Kamino Vaults (`kvauTFR8qm1dhniz6pYuBZkuene3Hfrs1VQhVRgCNrr`)
 *   - Pyth Solana Receiver (`rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ`)
 *   - Sanctum S Controller (`5ocnV1qiCgaQR8Jb8xWnVbApfaygJ8tNoZfgPwsgx9kx`)
 */
export const DEFAULT_ALLOWED_PRE_IX_PROGRAMS: readonly string[] = [
  'KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD',
  'kvauTFR8qm1dhniz6pYuBZkuene3Hfrs1VQhVRgCNrr',
  'rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ',
  '5ocnV1qiCgaQR8Jb8xWnVbApfaygJ8tNoZfgPwsgx9kx',
]

function parseNum(raw: string | undefined, fallback: number, min: number, max: number): number {
  const n = Number(raw)
  if (!Number.isFinite(n)) return fallback
  return Math.min(Math.max(n, min), max)
}

function parseSolToLamports(raw: string | undefined, fallbackSol: number): bigint {
  const sol = parseNum(raw, fallbackSol, 0, 100)
  return BigInt(Math.round(sol * 1_000_000_000))
}

export function loadPolicyConfig(env: Env): RelayPolicyConfig {
  const rawDefault = (env.DEFAULT_AGGREGATOR ?? 'jupiter').trim().toLowerCase() as AggregatorId
  const defaultAggregator: AggregatorId = VALID_AGGREGATORS.includes(rawDefault)
    ? rawDefault
    : 'jupiter'

  const rawEnabled = (env.ENABLED_AGGREGATORS ?? 'jupiter,bedrock,dflow,titan,okx')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter((s): s is AggregatorId => VALID_AGGREGATORS.includes(s as AggregatorId))

  const rawPreIx = (env.ALLOWED_PRE_IX_PROGRAMS ?? DEFAULT_ALLOWED_PRE_IX_PROGRAMS.join(','))
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)

  const corsOrigins = (env.CORS_ORIGINS ?? '*')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)

  return {
    defaultAggregator,
    enabledAggregators: new Set(rawEnabled.length > 0 ? rawEnabled : ['jupiter']),
    allowedPreIxPrograms: new Set(rawPreIx),
    baseSwapFeeBps: Math.trunc(parseNum(env.BASE_SWAP_FEE_BPS, 25, 0, 1000)),
    maxSelfPayBps: Math.trunc(parseNum(env.MAX_SELF_PAY_BPS, 450, 25, 2000)),
    microSwapFeeBps: Math.trunc(parseNum(env.MICRO_SWAP_FEE_BPS, 50, 0, 1000)),
    allowMicroSwapSubsidy: (env.ALLOW_MICRO_SWAP_SUBSIDY ?? 'true').toLowerCase() !== 'false',
    selfPayMarginBps: Math.trunc(parseNum(env.SELF_PAY_MARGIN_BPS, 11_000, 10_000, 20_000)),
    maxDailySponsoredLamports: {
      mainnet: parseSolToLamports(env.MAX_DAILY_SPONSORED_SOL_MAINNET, 0.05),
      devnet: parseSolToLamports(env.MAX_DAILY_SPONSORED_SOL_DEVNET, 1.0),
    },
    sponsoredPerIpPerHour: {
      mainnet: Math.trunc(parseNum(env.SPONSORED_PER_IP_PER_HOUR_MAINNET, 12, 1, 500)),
      devnet: 40,
    },
    sponsoredPerIpPerDay: {
      mainnet: Math.trunc(parseNum(env.SPONSORED_PER_IP_PER_DAY_MAINNET, 25, 1, 2000)),
      devnet: 150,
    },
    sponsoredCooldownSec: {
      mainnet: Math.trunc(parseNum(env.SPONSORED_COOLDOWN_SEC_MAINNET, 12, 0, 3600)),
      devnet: 2,
    },
    selfPayPerIpPer10m: Math.trunc(parseNum(env.SELF_PAY_PER_IP_PER_10M, 40, 1, 2000)),
    refillMinSol: parseNum(env.REFILL_MIN_SOL, 0.08, 0.01, 50),
    refillMinTokenUsd: parseNum(env.REFILL_MIN_TOKEN_USD, 5.0, 0.5, 10_000),
    corsOrigins,
  }
}

export function getRpcUrl(env: Env, cluster: Cluster): string | null {
  return cluster === 'mainnet' ? env.MAINNET_RPC_URL ?? null : env.DEVNET_RPC_URL ?? null
}

export function getRelayerSecretB64(env: Env, cluster: Cluster): string | null {
  return cluster === 'mainnet'
    ? env.MAINNET_RELAYER_SECRET_B64 ?? null
    : env.DEVNET_RELAYER_SECRET_B64 ?? null
}
