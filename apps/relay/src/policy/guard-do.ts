import { DurableObject } from 'cloudflare:workers'
import type { Env } from '../env'
import type { AudrenOpKind, Cluster } from '../types'

export interface GuardBeginRequest {
  ipHash: string
  nullifiers: string[]
}

export interface GuardAuthorizeRequest {
  ipHash: string
  cluster: Cluster
  opKind: AudrenOpKind
  nullifiers: string[]
  sponsoredLamports: number
  selfPaying: boolean
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
}

export interface GuardReleaseRequest {
  reservationId?: string
  ipHash: string
  cluster: Cluster
  nullifiers: string[]
  recordFailure?: boolean
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

function utcDayKey(nowMs: number): string {
  return new Date(nowMs).toISOString().slice(0, 10)
}

/**
 * Strongly consistent SQLite Durable Object protecting `relay.audren.xyz`
 * against rent-drain / ping-pong / simulation-spam abuse:
 *   - Global daily sponsored SOL budget cap per cluster
 *   - Per-IP sliding-window hourly & daily sponsored tx limits
 *   - Per-IP cooldown between sponsored txs (prevents rapid back-and-forth ping-pong)
 *   - Per-IP self-paying burst cap & failed-attempt flood guard
 *   - Atomic in-flight nullifier deduplication
 */
export class RelayGuard extends DurableObject<Env> {
  private readonly sql: SqlStorage

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env)
    this.sql = ctx.storage.sql
    ctx.blockConcurrencyWhile(async () => {
      this.sql.exec(`
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
          ip_hash TEXT NOT NULL,
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
      `)
    })
  }

  private prune(now: number): void {
    this.sql.exec('DELETE FROM inflight_nullifiers WHERE expires_at < ?', now)
    this.sql.exec('DELETE FROM pending_reservations WHERE expires_at < ?', now)
    this.sql.exec('DELETE FROM ip_events WHERE created_at < ?', now - DAY_MS - HOUR_MS)
  }

  /**
   * Pre-simulation guard (before RPC simulation):
   * Atomically dedup concurrent nullifiers and block IPs flooding invalid payloads.
   */
  async begin(req: GuardBeginRequest): Promise<GuardDecision> {
    const now = Date.now()
    this.prune(now)

    for (const nf of req.nullifiers) {
      const existing = this.sql
        .exec('SELECT nullifier FROM inflight_nullifiers WHERE nullifier = ?', nf)
        .toArray()
      if (existing.length > 0) {
        return {
          allowed: false,
          status: 409,
          code: 'DUPLICATE_NULLIFIER',
          reason: 'This private note nullifier is already being submitted to Solana.',
        }
      }
    }

    const failedRow = this.sql
      .exec(
        'SELECT COUNT(*) AS cnt FROM ip_events WHERE ip_hash = ? AND failed = 1 AND created_at >= ?',
        req.ipHash,
        now - HOUR_MS,
      )
      .one()
    if (Number(failedRow.cnt ?? 0) >= MAX_FAILED_ATTEMPTS_PER_HOUR) {
      return {
        allowed: false,
        status: 429,
        code: 'TOO_MANY_FAILURES',
        reason: 'Too many invalid relay attempts from this IP. Please wait before retrying.',
        retryAfterSec: 300,
      }
    }

    const expiresAt = now + INFLIGHT_TTL_MS
    for (const nf of req.nullifiers) {
      this.sql.exec(
        'INSERT OR REPLACE INTO inflight_nullifiers (nullifier, ip_hash, expires_at) VALUES (?, ?, ?)',
        nf,
        req.ipHash,
        expiresAt,
      )
    }

    return { allowed: true }
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
      const reservationId = crypto.randomUUID()
      this.sql.exec(
        'INSERT INTO pending_reservations (id, day, ip_hash, cluster, sponsored_lamports, self_paying, created_at, expires_at) VALUES (?, ?, ?, ?, 0, 1, ?, ?)',
        reservationId,
        day,
        req.ipHash,
        req.cluster,
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
            'SELECT COALESCE(SUM(sponsored_lamports), 0) AS lamports FROM pending_reservations WHERE day = ? AND cluster = ? AND self_paying = 0',
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
              'SELECT MAX(created_at) AS last_ts FROM ip_events WHERE ip_hash = ? AND cluster = ? AND failed = 0 AND self_paying = 0 AND sponsored_lamports > 0',
              req.ipHash,
              req.cluster,
            )
            .toArray()[0]?.last_ts ?? 0,
        )
        const lastPending = Number(
          this.sql
            .exec(
              'SELECT MAX(created_at) AS last_ts FROM pending_reservations WHERE ip_hash = ? AND cluster = ? AND self_paying = 0 AND sponsored_lamports > 0',
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
            'SELECT COUNT(*) AS cnt FROM ip_events WHERE ip_hash = ? AND cluster = ? AND failed = 0 AND self_paying = 0 AND sponsored_lamports > 0 AND created_at >= ?',
            req.ipHash,
            req.cluster,
            now - HOUR_MS,
          )
          .one().cnt ?? 0,
      )
      const pendingHour = Number(
        this.sql
          .exec(
            'SELECT COUNT(*) AS cnt FROM pending_reservations WHERE ip_hash = ? AND cluster = ? AND self_paying = 0 AND sponsored_lamports > 0 AND created_at >= ?',
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
            'SELECT COUNT(*) AS cnt FROM ip_events WHERE ip_hash = ? AND cluster = ? AND failed = 0 AND self_paying = 0 AND sponsored_lamports > 0 AND created_at >= ?',
            req.ipHash,
            req.cluster,
            now - DAY_MS,
          )
          .one().cnt ?? 0,
      )
      const pendingDay = Number(
        this.sql
          .exec(
            'SELECT COUNT(*) AS cnt FROM pending_reservations WHERE ip_hash = ? AND cluster = ? AND self_paying = 0 AND sponsored_lamports > 0 AND created_at >= ?',
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
    const isSelf = req.selfPaying ? 1 : 0
    const isSponsored = !req.selfPaying && req.sponsoredLamports > 0 ? 1 : 0
    const lamports = isSponsored ? req.sponsoredLamports : 0

    if (req.reservationId) {
      this.sql.exec('DELETE FROM pending_reservations WHERE id = ?', req.reservationId)
    }

    this.sql.exec(
      'INSERT INTO ip_events (ip_hash, cluster, op_kind, sponsored_lamports, self_paying, failed, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)',
      req.ipHash,
      req.cluster,
      req.opKind,
      lamports,
      isSelf,
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
