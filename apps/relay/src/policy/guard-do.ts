import { DurableObject } from 'cloudflare:workers'
import { sha256 } from '@noble/hashes/sha2.js'
import type { Env } from '../env'
import { toHex, utf8 } from '../solana/codec'
import type { AudrenOpKind, Cluster } from '../types'

export interface GuardBeginRequest {
  /** Raw client IP hashed inside `RelayGuard` using its ephemeral per-day 32-byte secret salt. */
  clientIp?: string
  /** Optional pre-hashed identifier (used only by unit mocks; production callers pass `clientIp`). */
  ipHash?: string
  nullifiers: string[]
  /** Optional cluster for pre-simulation revert-burn short-circuiting. */
  cluster?: Cluster
  /** True when the tx invokes an untrusted CPI target (includes in-flight burn-risk reservations pre-sim). */
  hasUntrustedCpiTarget?: boolean
  /** Optional per-IP revert-burn limits enforced pre-simulation when `cluster` is also provided. */
  limits?: {
    ipCooldownSec: number
    ipMaxSponsoredPerHour: number
    ipMaxSponsoredPerDay: number
  }
}

export interface GuardAuthorizeRequest {
  ipHash: string
  cluster: Cluster
  opKind: AudrenOpKind
  nullifiers: string[]
  sponsoredLamports: number
  selfPaying: boolean
  /** True when the tx invokes an untrusted CPI target (unaudited router, non-allowlisted Token-2022 leg, or TransferHook). */
  hasUntrustedCpiTarget?: boolean
  /** Worst-case relayer fee burn (`5_000 + priorityFeeLamports`) if the tx reverts on-chain. */
  maxRevertBurnLamports?: number
  limits: {
    maxDailySponsoredLamports: number
    ipMaxSponsoredPerHour: number
    ipMaxSponsoredPerDay: number
    ipCooldownSec: number
    selfPayPerIpPer10m: number
  }
}

export interface GuardDecision {
  allowed: boolean
  /** Ephemeral daily-salted client IP hash computed inside `RelayGuard` (returned by `begin`). */
  ipHash?: string
  reservationId?: string
  status?: number
  code?: string
  reason?: string
  retryAfterSec?: number
}

export interface GuardCommitRequest {
  reservationId?: string
  ipHash: string
  cluster: Cluster
  opKind: AudrenOpKind
  nullifiers: string[]
  sponsoredLamports: number
  selfPaying: boolean
  /**
   * When true (confirmed on-chain revert), records `failed = 1` in `ip_events` alongside the
   * burned fee debit in `daily_budgets` and clears `inflight_nullifiers` immediately.
   */
  recordFailure?: boolean
}

export interface GuardReleaseRequest {
  reservationId?: string
  ipHash: string
  cluster: Cluster
  nullifiers: string[]
  recordFailure?: boolean
}

export interface OpenPageLockAcquireRequest {
  cluster: Cluster
  poolId: number
  laneIds: number[]
  leaseId: string
  ttlMs?: number
}

export interface OpenPageLockAcquireResult {
  allowed: boolean
  busyLaneId?: number
  retryAfterSec?: number
}

export interface OpenPageLockReleaseRequest {
  cluster: Cluster
  poolId: number
  laneIds: number[]
  leaseId: string
  /**
   * Optional post-broadcast grace TTL (ms). When > 0, keeps the lease active for this
   * short window instead of deleting immediately so concurrent callers cannot race an
   * unconfirmed `OpenPage` transaction's `LaneRentVault` spend.
   */
  graceTtlMs?: number
}

export interface OpenPageLockAdapter {
  acquire(req: OpenPageLockAcquireRequest): Promise<OpenPageLockAcquireResult>
  release(req: OpenPageLockReleaseRequest): Promise<void>
}

export interface GuardStatsResponse {
  day: string
  clusters: Record<
    Cluster,
    {
      totalTxs: number
      sponsoredTxs: number
      selfPayingTxs: number
      sponsoredSolSpent: number
      dailyBudgetSol: number
      remainingBudgetSol: number
    }
  >
  activeInflightNullifiers: number
}

const TEN_MIN_MS = 600_000
const HOUR_MS = 3_600_000
const DAY_MS = 86_400_000
const INFLIGHT_TTL_MS = 45_000
const MAX_FAILED_ATTEMPTS_PER_HOUR = 30
export const OPEN_PAGE_LOCK_TTL_MS = 45_000

const IP_HASH_DOMAIN_SEP = 'audren/relay/ip-salt'

function utcDayKey(nowMs: number): string {
  return new Date(nowMs).toISOString().slice(0, 10)
}

function nextUtcMidnightMs(nowMs: number): number {
  const d = new Date(nowMs)
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1, 0, 0, 1)
}

/**
 * Strongly consistent SQLite Durable Object protecting `relay.audren.xyz`
 * against rent-drain / ping-pong / simulation-spam abuse:
 *   - Ephemeral per-day random 32-byte secret IP-hash salt held STRICTLY in DO memory
 *     (never written to SQLite disk; auto-purged on UTC day rollover and via UTC midnight `alarm()`)
 *   - Domain-separated relay IP hashing (`audren/relay/ip-salt`)
 *   - Zero IP-hash linkage on `inflight_nullifiers` (stores only `(nullifier, expires_at)`)
 *   - Global daily sponsored SOL budget cap per cluster
 *   - Per-IP sliding-window hourly & daily sponsored tx limits
 *   - Per-IP cooldown between sponsored txs (prevents rapid back-and-forth ping-pong)
 *   - Per-IP self-paying burst cap & failed-attempt flood guard
 *   - Atomic in-flight nullifier deduplication across single & batched transactions
 *   - Per-lane `open_page_locks` mutual exclusion for concurrent auto-`OpenPage` rollovers
 */
export class RelayGuard extends DurableObject<Env> {
  private readonly sql: SqlStorage
  /** Ephemeral UTC-day-keyed 32-byte random secret salts kept strictly in memory (never on disk). */
  private readonly dailySalts = new Map<string, string>()
  private scheduledAlarmAt = 0

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env)
    this.sql = ctx.storage.sql
    ctx.blockConcurrencyWhile(async () => {
      this.sql.exec(`
        DROP TABLE IF EXISTS daily_ip_salts;
        DROP TABLE IF EXISTS checkpoint_locks;
        DROP TABLE IF EXISTS checkpoint_ip_hits;

        CREATE TABLE IF NOT EXISTS ip_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ip_hash TEXT NOT NULL,
          cluster TEXT NOT NULL,
          op_kind TEXT NOT NULL,
          sponsored_lamports INTEGER NOT NULL,
          self_paying INTEGER NOT NULL,
          failed INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ip_events_ip_time ON ip_events (ip_hash, created_at);
        CREATE INDEX IF NOT EXISTS idx_ip_events_time ON ip_events (created_at);

        CREATE TABLE IF NOT EXISTS daily_budgets (
          day TEXT NOT NULL,
          cluster TEXT NOT NULL,
          sponsored_lamports INTEGER NOT NULL DEFAULT 0,
          sponsored_txs INTEGER NOT NULL DEFAULT 0,
          self_paying_txs INTEGER NOT NULL DEFAULT 0,
          total_txs INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (day, cluster)
        );

        CREATE TABLE IF NOT EXISTS inflight_nullifiers (
          nullifier TEXT PRIMARY KEY,
          expires_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS pending_reservations (
          id TEXT PRIMARY KEY,
          day TEXT NOT NULL,
          ip_hash TEXT NOT NULL,
          cluster TEXT NOT NULL,
          sponsored_lamports INTEGER NOT NULL,
          self_paying INTEGER NOT NULL,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_pending_cluster_day ON pending_reservations (day, cluster);
        CREATE INDEX IF NOT EXISTS idx_pending_ip ON pending_reservations (ip_hash, cluster);

        CREATE TABLE IF NOT EXISTS open_page_locks (
          lane_key TEXT PRIMARY KEY,
          lease_id TEXT NOT NULL,
          expires_at INTEGER NOT NULL
        );
      `)

      // Privacy migration: drop & recreate legacy `inflight_nullifiers` if it carried `ip_hash`
      // so nullifiers are NEVER linked to client IP hashes in DO storage.
      const nfCols = this.sql.exec('PRAGMA table_info(inflight_nullifiers)').toArray()
      if (nfCols.some((c) => String(c.name) === 'ip_hash')) {
        this.sql.exec('DROP TABLE inflight_nullifiers')
        this.sql.exec(`
          CREATE TABLE inflight_nullifiers (
            nullifier TEXT PRIMARY KEY,
            expires_at INTEGER NOT NULL
          );
        `)
      }

      await this.scheduleNextUtcMidnightAlarm(Date.now())
    })
  }

  private async scheduleNextUtcMidnightAlarm(now: number): Promise<void> {
    const target = nextUtcMidnightMs(now)
    if (this.scheduledAlarmAt === target) return
    const storage = this.ctx?.storage as { setAlarm?: (scheduledTime: number | Date) => Promise<void> } | undefined
    if (typeof storage?.setAlarm === 'function') {
      this.scheduledAlarmAt = target
      await storage.setAlarm(target).catch(() => {
        this.scheduledAlarmAt = 0
      })
    }
  }

  private purgeStaleSalts(day: string): void {
    for (const k of this.dailySalts.keys()) {
      if (k < day) this.dailySalts.delete(k)
    }
  }

  /**
   * UTC midnight Durable Object alarm: purges prior-day in-memory IP salts, prunes expired
   * rate-limit rows, and reschedules itself for the next UTC midnight.
   */
  async alarm(): Promise<void> {
    await this.runUtcRolloverMaintenance(Date.now())
  }

  /** Execute UTC rollover maintenance (purges prior-day in-memory IP salts & reschedules alarm). */
  async runUtcRolloverMaintenance(nowMs: number = Date.now()): Promise<void> {
    const day = utcDayKey(nowMs)
    this.purgeStaleSalts(day)
    this.prune(nowMs)
    this.scheduledAlarmAt = 0
    await this.scheduleNextUtcMidnightAlarm(nowMs)
  }

  /**
   * Load or generate the current UTC day's random 32-byte secret salt strictly in DO memory
   * (zero SQLite persistence), purging salts from prior UTC days so historical IP hashes
   * cannot be inverted even from a DO storage snapshot.
   */
  private getOrCreateDailySaltHex(now: number): string {
    const day = utcDayKey(now)
    this.purgeStaleSalts(day)
    const existing = this.dailySalts.get(day)
    if (existing && existing.length === 64) {
      return existing
    }
    const randomSalt = new Uint8Array(32)
    crypto.getRandomValues(randomSalt)
    const saltHex = toHex(randomSalt)
    this.dailySalts.set(day, saltHex)
    void this.scheduleNextUtcMidnightAlarm(now)
    return saltHex
  }

  private computeDailyIpHash(clientIp: string, now: number): string {
    const saltHex = this.getOrCreateDailySaltHex(now)
    return toHex(sha256(utf8(`${IP_HASH_DOMAIN_SEP}|${saltHex}|${clientIp}`))).slice(0, 32)
  }

  private prune(now: number): void {
    const day = utcDayKey(now)
    this.purgeStaleSalts(day)
    this.sql.exec('DELETE FROM inflight_nullifiers WHERE expires_at < ?', now)
    this.sql.exec('DELETE FROM pending_reservations WHERE expires_at < ?', now)
    this.sql.exec('DELETE FROM ip_events WHERE created_at < ?', now - DAY_MS - HOUR_MS)
    this.sql.exec('DELETE FROM open_page_locks WHERE expires_at <= ?', now)
  }

  /**
   * Hash a client IP inside `RelayGuard` using the current UTC day's ephemeral in-memory
   * 32-byte random salt (`audren/relay/ip-salt`).
   */
  async hashClientIp(clientIp: string, nowMs: number = Date.now()): Promise<string> {
    return this.computeDailyIpHash(clientIp || 'unknown', nowMs)
  }

  /**
   * Enforce per-IP confirmed on-chain revert burn limits (`ip_events` with
   * `failed = 1 AND self_paying = 0 AND sponsored_lamports > 0`), optionally combined with
   * in-flight burn-risk self-pay reservations (`pending_reservations` with
   * `self_paying = 1 AND sponsored_lamports > 0`).
   *
   * Pre-simulation rejections (`sponsored_lamports = 0`), honest sponsored txs (`failed = 0`),
   * and honest audited in-flight self-pay swaps (`pending_reservations` with `sponsored_lamports = 0`)
   * are strictly excluded.
   */
  private checkPerIpRevertBurnLimits(params: {
    ipHash: string
    cluster: Cluster
    now: number
    includePendingBurnRisk: boolean
    hasUntrustedCpiTarget?: boolean
    limits: {
      ipCooldownSec: number
      ipMaxSponsoredPerHour: number
      ipMaxSponsoredPerDay: number
    }
  }): { denied: GuardDecision | null; revertBurnsDay: number } {
    const { ipHash, cluster, now, includePendingBurnRisk, hasUntrustedCpiTarget, limits } = params

    const committedRevertBurnsDay = Number(
      this.sql
        .exec(
          'SELECT COUNT(*) AS cnt FROM ip_events WHERE ip_hash = ? AND cluster = ? AND failed = 1 AND self_paying = 0 AND sponsored_lamports > 0 AND created_at >= ?',
          ipHash,
          cluster,
          now - DAY_MS,
        )
        .one().cnt ?? 0,
    )
    const isBurnRiskCaller = hasUntrustedCpiTarget === true || committedRevertBurnsDay > 0
    const checkPending = includePendingBurnRisk || isBurnRiskCaller

    if (limits.ipCooldownSec > 0) {
      const committedLastRevertTs = Number(
        this.sql
          .exec(
            'SELECT MAX(created_at) AS last_ts FROM ip_events WHERE ip_hash = ? AND cluster = ? AND failed = 1 AND self_paying = 0 AND sponsored_lamports > 0',
            ipHash,
            cluster,
          )
          .toArray()[0]?.last_ts ?? 0,
      )
      const pendingBurnRiskLastTs = checkPending
        ? Number(
            this.sql
              .exec(
                isBurnRiskCaller
                  ? 'SELECT MAX(created_at) AS last_ts FROM pending_reservations WHERE ip_hash = ? AND cluster = ? AND sponsored_lamports > 0'
                  : 'SELECT MAX(created_at) AS last_ts FROM pending_reservations WHERE ip_hash = ? AND cluster = ? AND self_paying = 1 AND sponsored_lamports > 0',
                ipHash,
                cluster,
              )
              .toArray()[0]?.last_ts ?? 0,
          )
        : 0
      const lastRevertTs = Math.max(committedLastRevertTs, pendingBurnRiskLastTs)
      const elapsedMs = now - lastRevertTs
      const cooldownMs = limits.ipCooldownSec * 1000
      if (lastRevertTs > 0 && elapsedMs < cooldownMs) {
        const waitSec = Math.max(1, Math.ceil((cooldownMs - elapsedMs) / 1000))
        return {
          denied: {
            allowed: false,
            status: 429,
            code: 'SPONSOR_COOLDOWN',
            reason:
              pendingBurnRiskLastTs > committedLastRevertTs
                ? `Please wait ${waitSec}s while a high-risk transaction is in flight before retrying.`
                : `Please wait ${waitSec}s after a failed on-chain transaction before retrying.`,
            retryAfterSec: waitSec,
          },
          revertBurnsDay: 0,
        }
      }
    }

    const committedRevertBurnsHour = Number(
      this.sql
        .exec(
          'SELECT COUNT(*) AS cnt FROM ip_events WHERE ip_hash = ? AND cluster = ? AND failed = 1 AND self_paying = 0 AND sponsored_lamports > 0 AND created_at >= ?',
          ipHash,
          cluster,
          now - HOUR_MS,
        )
        .one().cnt ?? 0,
    )
    const pendingBurnRiskHour = checkPending
      ? Number(
          this.sql
            .exec(
              isBurnRiskCaller
                ? 'SELECT COUNT(*) AS cnt FROM pending_reservations WHERE ip_hash = ? AND cluster = ? AND sponsored_lamports > 0 AND created_at >= ?'
                : 'SELECT COUNT(*) AS cnt FROM pending_reservations WHERE ip_hash = ? AND cluster = ? AND self_paying = 1 AND sponsored_lamports > 0 AND created_at >= ?',
              ipHash,
              cluster,
              now - HOUR_MS,
            )
            .one().cnt ?? 0,
        )
      : 0
    const revertBurnsHour = committedRevertBurnsHour + pendingBurnRiskHour
    if (revertBurnsHour >= limits.ipMaxSponsoredPerHour) {
      return {
        denied: {
          allowed: false,
          status: 429,
          code: 'IP_HOURLY_SPONSOR_LIMIT',
          reason: `Hourly failed-transaction burn limit (${limits.ipMaxSponsoredPerHour}/hr) reached for this IP.`,
          retryAfterSec: 600,
        },
        revertBurnsDay: 0,
      }
    }

    const pendingBurnRiskDay = checkPending
      ? Number(
          this.sql
            .exec(
              isBurnRiskCaller
                ? 'SELECT COUNT(*) AS cnt FROM pending_reservations WHERE ip_hash = ? AND cluster = ? AND sponsored_lamports > 0 AND created_at >= ?'
                : 'SELECT COUNT(*) AS cnt FROM pending_reservations WHERE ip_hash = ? AND cluster = ? AND self_paying = 1 AND sponsored_lamports > 0 AND created_at >= ?',
              ipHash,
              cluster,
              now - DAY_MS,
            )
            .one().cnt ?? 0,
        )
      : 0
    const revertBurnsDay = committedRevertBurnsDay + pendingBurnRiskDay
    if (revertBurnsDay >= limits.ipMaxSponsoredPerDay) {
      return {
        denied: {
          allowed: false,
          status: 429,
          code: 'IP_DAILY_SPONSOR_LIMIT',
          reason: `Daily failed-transaction burn limit (${limits.ipMaxSponsoredPerDay}/day) reached for this IP.`,
          retryAfterSec: 3600,
        },
        revertBurnsDay,
      }
    }

    return { denied: null, revertBurnsDay }
  }

  /**
   * Pre-simulation guard (before RPC simulation):
   * Atomically dedup concurrent nullifiers (without storing any IP association on nullifiers),
   * block IPs flooding invalid payloads, and short-circuit already revert-blocked IPs (plus
   * concurrent untrusted-CPI bursts) before burning RPC simulation capacity.
   */
  async begin(req: GuardBeginRequest): Promise<GuardDecision> {
    const now = Date.now()
    this.prune(now)
    const ipHash = req.ipHash ?? this.computeDailyIpHash(req.clientIp ?? 'unknown', now)

    const seenInReq = new Set<string>()
    for (const nf of req.nullifiers) {
      if (seenInReq.has(nf)) {
        return {
          allowed: false,
          ipHash,
          status: 400,
          code: 'DUPLICATE_NULLIFIER',
          reason: 'Duplicate nullifier detected within the submitted transaction batch.',
        }
      }
      seenInReq.add(nf)
      const existing = this.sql
        .exec('SELECT nullifier FROM inflight_nullifiers WHERE nullifier = ?', nf)
        .toArray()
      if (existing.length > 0) {
        return {
          allowed: false,
          ipHash,
          status: 409,
          code: 'DUPLICATE_NULLIFIER',
          reason: 'This private note nullifier is already being submitted to Solana.',
        }
      }
    }

    const failedRow = this.sql
      .exec(
        'SELECT COUNT(*) AS cnt FROM ip_events WHERE ip_hash = ? AND failed = 1 AND created_at >= ?',
        ipHash,
        now - HOUR_MS,
      )
      .one()
    if (Number(failedRow.cnt ?? 0) >= MAX_FAILED_ATTEMPTS_PER_HOUR) {
      return {
        allowed: false,
        ipHash,
        status: 429,
        code: 'TOO_MANY_FAILURES',
        reason: 'Too many invalid relay attempts from this IP. Please wait before retrying.',
        retryAfterSec: 300,
      }
    }

    if (req.cluster && req.limits) {
      const revertCheck = this.checkPerIpRevertBurnLimits({
        ipHash,
        cluster: req.cluster,
        now,
        includePendingBurnRisk: req.hasUntrustedCpiTarget === true,
        hasUntrustedCpiTarget: req.hasUntrustedCpiTarget,
        limits: req.limits,
      })
      if (revertCheck.denied) {
        return { ...revertCheck.denied, ipHash }
      }
    }

    const expiresAt = now + INFLIGHT_TTL_MS
    for (const nf of req.nullifiers) {
      this.sql.exec(
        'INSERT OR REPLACE INTO inflight_nullifiers (nullifier, expires_at) VALUES (?, ?)',
        nf,
        expiresAt,
      )
    }

    return { allowed: true, ipHash }
  }

  /**
   * Post-simulation reservation (after `simulateTransaction` returns exact lamport cost & fee revenue):
   * Enforce daily sponsored budget, per-IP cooldown, hourly/daily limits, and self-pay burst caps.
   * Automatically releases the nullifier lock if denied.
   */
  async authorizeSpend(req: GuardAuthorizeRequest): Promise<GuardDecision> {
    const now = Date.now()
    const day = utcDayKey(now)
    this.prune(now)

    const deny = (decision: GuardDecision): GuardDecision => {
      for (const nf of req.nullifiers) {
        this.sql.exec('DELETE FROM inflight_nullifiers WHERE nullifier = ?', nf)
      }
      return decision
    }

    if (req.selfPaying || req.sponsoredLamports <= 0) {
      const committedBurst = Number(
        this.sql
          .exec(
            'SELECT COUNT(*) AS cnt FROM ip_events WHERE ip_hash = ? AND failed = 0 AND self_paying = 1 AND created_at >= ?',
            req.ipHash,
            now - TEN_MIN_MS,
          )
          .one().cnt ?? 0,
      )
      const pendingBurst = Number(
        this.sql
          .exec(
            'SELECT COUNT(*) AS cnt FROM pending_reservations WHERE ip_hash = ? AND self_paying = 1 AND created_at >= ?',
            req.ipHash,
            now - TEN_MIN_MS,
          )
          .one().cnt ?? 0,
      )
      if (committedBurst + pendingBurst >= req.limits.selfPayPerIpPer10m) {
        return deny({
          allowed: false,
          status: 429,
          code: 'SELF_PAY_BURST_LIMIT',
          reason: `Self-paying swap burst limit (${req.limits.selfPayPerIpPer10m}/10m) reached for this IP.`,
          retryAfterSec: 60,
        })
      }

      // Enforce confirmed on-chain revert burn limits (`failed = 1 AND self_paying = 0 AND sponsored_lamports > 0`)
      // PLUS in-flight burn-risk reservations (`pending_reservations` with `self_paying = 1 AND sponsored_lamports > 0`)
      // on `selfPaying: true` requests so concurrent or sequential reverting self-pay txs cannot bypass
      // cooldown, hourly/daily limits, or the global daily sponsored SOL cap. Honest audited self-paying
      // swaps (`revertBurnsDay === 0 && !hasUntrustedCpiTarget`) store `sponsored_lamports = 0` in
      // `pending_reservations`, and pre-sim rejections (`sponsored_lamports = 0`) & honest sponsored txs
      // (`failed = 0`) are excluded.
      const revertCheck = this.checkPerIpRevertBurnLimits({
        ipHash: req.ipHash,
        cluster: req.cluster,
        now,
        includePendingBurnRisk: true,
        hasUntrustedCpiTarget: req.hasUntrustedCpiTarget,
        limits: req.limits,
      })
      if (revertCheck.denied) {
        return deny(revertCheck.denied)
      }
      const revertBurnsDay = revertCheck.revertBurnsDay

      const checkRevertBudget = revertBurnsDay > 0 || req.hasUntrustedCpiTarget === true
      const burnRiskLamports = checkRevertBudget
        ? typeof req.maxRevertBurnLamports === 'number' &&
          Number.isFinite(req.maxRevertBurnLamports) &&
          req.maxRevertBurnLamports > 0
          ? Math.trunc(req.maxRevertBurnLamports)
          : 10_000
        : 0
      if (checkRevertBudget) {
        const budgetRows = this.sql
          .exec(
            'SELECT sponsored_lamports FROM daily_budgets WHERE day = ? AND cluster = ?',
            day,
            req.cluster,
          )
          .toArray()
        const spentToday = Number(budgetRows[0]?.sponsored_lamports ?? 0)
        const pendingToday = Number(
          this.sql
            .exec(
              'SELECT COALESCE(SUM(sponsored_lamports), 0) AS lamports FROM pending_reservations WHERE day = ? AND cluster = ?',
              day,
              req.cluster,
            )
            .one().lamports ?? 0,
        )
        if (spentToday + pendingToday + burnRiskLamports > req.limits.maxDailySponsoredLamports) {
          return deny({
            allowed: false,
            status: 429,
            code: 'DAILY_SPONSOR_BUDGET_REACHED',
            reason:
              'Daily sponsored relay budget has been reached. Audited self-paying swaps without recent failed transactions remain available or try again after UTC midnight.',
            retryAfterSec: 3600,
          })
        }
      }

      const reservationId = crypto.randomUUID()
      this.sql.exec(
        'INSERT INTO pending_reservations (id, day, ip_hash, cluster, sponsored_lamports, self_paying, created_at, expires_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?)',
        reservationId,
        day,
        req.ipHash,
        req.cluster,
        burnRiskLamports,
        now,
        now + INFLIGHT_TTL_MS,
      )
      return { allowed: true, reservationId }
    }

    if (req.sponsoredLamports > 0) {
      const budgetRows = this.sql
        .exec(
          'SELECT sponsored_lamports FROM daily_budgets WHERE day = ? AND cluster = ?',
          day,
          req.cluster,
        )
        .toArray()
      const spentToday = Number(budgetRows[0]?.sponsored_lamports ?? 0)
      const pendingToday = Number(
        this.sql
          .exec(
            'SELECT COALESCE(SUM(sponsored_lamports), 0) AS lamports FROM pending_reservations WHERE day = ? AND cluster = ?',
            day,
            req.cluster,
          )
          .one().lamports ?? 0,
      )
      if (spentToday + pendingToday + req.sponsoredLamports > req.limits.maxDailySponsoredLamports) {
        return deny({
          allowed: false,
          status: 429,
          code: 'DAILY_SPONSOR_BUDGET_REACHED',
          reason:
            'Daily sponsored relay budget has been reached. Self-paying swaps remain available or try again after UTC midnight.',
          retryAfterSec: 3600,
        })
      }

      if (req.limits.ipCooldownSec > 0) {
        const lastCommitted = Number(
          this.sql
            .exec(
              'SELECT MAX(created_at) AS last_ts FROM ip_events WHERE ip_hash = ? AND cluster = ? AND self_paying = 0 AND sponsored_lamports > 0',
              req.ipHash,
              req.cluster,
            )
            .toArray()[0]?.last_ts ?? 0,
        )
        const lastPending = Number(
          this.sql
            .exec(
              'SELECT MAX(created_at) AS last_ts FROM pending_reservations WHERE ip_hash = ? AND cluster = ? AND sponsored_lamports > 0',
              req.ipHash,
              req.cluster,
            )
            .toArray()[0]?.last_ts ?? 0,
        )
        const lastTs = Math.max(lastCommitted, lastPending)
        const elapsedMs = now - lastTs
        const cooldownMs = req.limits.ipCooldownSec * 1000
        if (lastTs > 0 && elapsedMs < cooldownMs) {
          const waitSec = Math.max(1, Math.ceil((cooldownMs - elapsedMs) / 1000))
          return deny({
            allowed: false,
            status: 429,
            code: 'SPONSOR_COOLDOWN',
            reason: `Please wait ${waitSec}s between sponsored private transactions.`,
            retryAfterSec: waitSec,
          })
        }
      }

      const committedHour = Number(
        this.sql
          .exec(
            'SELECT COUNT(*) AS cnt FROM ip_events WHERE ip_hash = ? AND cluster = ? AND self_paying = 0 AND sponsored_lamports > 0 AND created_at >= ?',
            req.ipHash,
            req.cluster,
            now - HOUR_MS,
          )
          .one().cnt ?? 0,
      )
      const pendingHour = Number(
        this.sql
          .exec(
            'SELECT COUNT(*) AS cnt FROM pending_reservations WHERE ip_hash = ? AND cluster = ? AND sponsored_lamports > 0 AND created_at >= ?',
            req.ipHash,
            req.cluster,
            now - HOUR_MS,
          )
          .one().cnt ?? 0,
      )
      if (committedHour + pendingHour >= req.limits.ipMaxSponsoredPerHour) {
        return deny({
          allowed: false,
          status: 429,
          code: 'IP_HOURLY_SPONSOR_LIMIT',
          reason: `Hourly sponsored transaction limit (${req.limits.ipMaxSponsoredPerHour}/hr) reached for this IP. Self-paying swaps remain available.`,
          retryAfterSec: 600,
        })
      }

      const committedDay = Number(
        this.sql
          .exec(
            'SELECT COUNT(*) AS cnt FROM ip_events WHERE ip_hash = ? AND cluster = ? AND self_paying = 0 AND sponsored_lamports > 0 AND created_at >= ?',
            req.ipHash,
            req.cluster,
            now - DAY_MS,
          )
          .one().cnt ?? 0,
      )
      const pendingDay = Number(
        this.sql
          .exec(
            'SELECT COUNT(*) AS cnt FROM pending_reservations WHERE ip_hash = ? AND cluster = ? AND sponsored_lamports > 0 AND created_at >= ?',
            req.ipHash,
            req.cluster,
            now - DAY_MS,
          )
          .one().cnt ?? 0,
      )
      if (committedDay + pendingDay >= req.limits.ipMaxSponsoredPerDay) {
        return deny({
          allowed: false,
          status: 429,
          code: 'IP_DAILY_SPONSOR_LIMIT',
          reason: `Daily sponsored transaction limit (${req.limits.ipMaxSponsoredPerDay}/day) reached for this IP. Self-paying swaps remain available.`,
          retryAfterSec: 3600,
        })
      }

      const reservationId = crypto.randomUUID()
      this.sql.exec(
        'INSERT INTO pending_reservations (id, day, ip_hash, cluster, sponsored_lamports, self_paying, created_at, expires_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?)',
        reservationId,
        day,
        req.ipHash,
        req.cluster,
        req.sponsoredLamports,
        now,
        now + INFLIGHT_TTL_MS,
      )
      return { allowed: true, reservationId }
    }

    return { allowed: true }
  }

  async commit(req: GuardCommitRequest): Promise<void> {
    const now = Date.now()
    const day = utcDayKey(now)
    const isFailed = req.recordFailure === true ? 1 : 0
    const isSelf = !isFailed && req.selfPaying ? 1 : 0
    const isSponsored = (!req.selfPaying || isFailed === 1) && req.sponsoredLamports > 0 ? 1 : 0
    const lamports = isSponsored ? req.sponsoredLamports : 0

    if (req.reservationId) {
      this.sql.exec('DELETE FROM pending_reservations WHERE id = ?', req.reservationId)
    }

    this.sql.exec(
      'INSERT INTO ip_events (ip_hash, cluster, op_kind, sponsored_lamports, self_paying, failed, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      req.ipHash,
      req.cluster,
      req.opKind,
      lamports,
      isSelf,
      isFailed,
      now,
    )

    this.sql.exec(
      `INSERT INTO daily_budgets (day, cluster, sponsored_lamports, sponsored_txs, self_paying_txs, total_txs)
       VALUES (?, ?, ?, ?, ?, 1)
       ON CONFLICT (day, cluster) DO UPDATE SET
         sponsored_lamports = sponsored_lamports + excluded.sponsored_lamports,
         sponsored_txs = sponsored_txs + excluded.sponsored_txs,
         self_paying_txs = self_paying_txs + excluded.self_paying_txs,
         total_txs = total_txs + 1`,
      day,
      req.cluster,
      lamports,
      isSponsored,
      isSelf,
    )

    if (isFailed) {
      for (const nf of req.nullifiers) {
        this.sql.exec('DELETE FROM inflight_nullifiers WHERE nullifier = ?', nf)
      }
      return
    }

    const grace = now + 10_000
    for (const nf of req.nullifiers) {
      this.sql.exec(
        'UPDATE inflight_nullifiers SET expires_at = ? WHERE nullifier = ?',
        grace,
        nf,
      )
    }
  }

  async release(req: GuardReleaseRequest): Promise<void> {
    const now = Date.now()
    if (req.reservationId) {
      this.sql.exec('DELETE FROM pending_reservations WHERE id = ?', req.reservationId)
    }
    for (const nf of req.nullifiers) {
      this.sql.exec('DELETE FROM inflight_nullifiers WHERE nullifier = ?', nf)
    }
    if (req.recordFailure) {
      this.sql.exec(
        'INSERT INTO ip_events (ip_hash, cluster, op_kind, sponsored_lamports, self_paying, failed, created_at) VALUES (?, ?, ?, 0, 0, 1, ?)',
        req.ipHash,
        req.cluster,
        'rejected',
        now,
      )
    }
  }

  /**
   * Atomically acquire a short-TTL per-`(cluster, poolId, laneId)` `OpenPage` lease across all
   * requested lanes (all-or-nothing) so concurrent rollovers cannot race the same
   * `LaneRentVault` balance.
   */
  async acquireOpenPageLock(req: OpenPageLockAcquireRequest): Promise<OpenPageLockAcquireResult> {
    const uniqueLanes = [
      ...new Set(req.laneIds.map((l) => Math.trunc(l)).filter((l) => Number.isInteger(l) && l >= 0)),
    ]
    if (uniqueLanes.length === 0) return { allowed: true }

    const now = Date.now()
    this.sql.exec('DELETE FROM open_page_locks WHERE expires_at <= ?', now)

    for (const laneId of uniqueLanes) {
      const key = `${req.cluster}:${req.poolId}:${laneId}`
      const rows = this.sql
        .exec('SELECT lease_id, expires_at FROM open_page_locks WHERE lane_key = ?', key)
        .toArray()
      const row = rows[0]
      if (row && String(row.lease_id) !== req.leaseId && Number(row.expires_at ?? 0) > now) {
        const remainingMs = Math.max(1_000, Number(row.expires_at) - now)
        return {
          allowed: false,
          busyLaneId: laneId,
          retryAfterSec: Math.min(Math.max(Math.ceil(remainingMs / 1000), 1), 15),
        }
      }
    }

    const rawTtl =
      typeof req.ttlMs === 'number' && Number.isFinite(req.ttlMs)
        ? req.ttlMs
        : OPEN_PAGE_LOCK_TTL_MS
    const ttlMs = Math.min(Math.max(Math.trunc(rawTtl), 1), 60_000)
    const expiresAt = now + ttlMs
    for (const laneId of uniqueLanes) {
      const key = `${req.cluster}:${req.poolId}:${laneId}`
      this.sql.exec(
        `INSERT INTO open_page_locks (lane_key, lease_id, expires_at)
         VALUES (?, ?, ?)
         ON CONFLICT (lane_key) DO UPDATE SET
           lease_id = excluded.lease_id,
           expires_at = excluded.expires_at`,
        key,
        req.leaseId,
        expiresAt,
      )
    }
    return { allowed: true }
  }

  async releaseOpenPageLock(req: OpenPageLockReleaseRequest): Promise<void> {
    const uniqueLanes = [
      ...new Set(req.laneIds.map((l) => Math.trunc(l)).filter((l) => Number.isInteger(l) && l >= 0)),
    ]
    if (uniqueLanes.length === 0) return

    const now = Date.now()
    if (typeof req.graceTtlMs === 'number' && Number.isFinite(req.graceTtlMs) && req.graceTtlMs > 0) {
      const graceMs = Math.min(Math.max(Math.trunc(req.graceTtlMs), 1), 30_000)
      const expiresAt = now + graceMs
      for (const laneId of uniqueLanes) {
        const key = `${req.cluster}:${req.poolId}:${laneId}`
        this.sql.exec(
          'UPDATE open_page_locks SET expires_at = ? WHERE lane_key = ? AND lease_id = ?',
          expiresAt,
          key,
          req.leaseId,
        )
      }
      return
    }

    for (const laneId of uniqueLanes) {
      const key = `${req.cluster}:${req.poolId}:${laneId}`
      this.sql.exec(
        'DELETE FROM open_page_locks WHERE lane_key = ? AND lease_id = ?',
        key,
        req.leaseId,
      )
    }
  }

  async stats(dailyBudgetsSol: Record<Cluster, number>): Promise<GuardStatsResponse> {
    const now = Date.now()
    const day = utcDayKey(now)
    this.prune(now)

    const rows = this.sql
      .exec(
        'SELECT cluster, sponsored_lamports, sponsored_txs, self_paying_txs, total_txs FROM daily_budgets WHERE day = ?',
        day,
      )
      .toArray()

    const mk = (c: Cluster) => {
      const r = rows.find((x) => x.cluster === c)
      const spentSol = Number(r?.sponsored_lamports ?? 0) / 1e9
      const budget = dailyBudgetsSol[c]
      return {
        totalTxs: Number(r?.total_txs ?? 0),
        sponsoredTxs: Number(r?.sponsored_txs ?? 0),
        selfPayingTxs: Number(r?.self_paying_txs ?? 0),
        sponsoredSolSpent: Number(spentSol.toFixed(6)),
        dailyBudgetSol: budget,
        remainingBudgetSol: Number(Math.max(0, budget - spentSol).toFixed(6)),
      }
    }

    const inflightRow = this.sql
      .exec('SELECT COUNT(*) AS cnt FROM inflight_nullifiers WHERE expires_at >= ?', now)
      .one()

    return {
      day,
      clusters: {
        mainnet: mk('mainnet'),
        devnet: mk('devnet'),
      },
      activeInflightNullifiers: Number(inflightRow.cnt ?? 0),
    }
  }
}
