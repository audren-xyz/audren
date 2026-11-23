import { DurableObject } from 'cloudflare:workers'
import { sha256 } from '@noble/hashes/sha2.js'
import type { Env } from '../env'
import type { CheckpointLockAcquireResult } from '../solana/checkpoint'
import { toHex, utf8 } from '../solana/codec'
import type { AudrenOpKind, Cluster } from '../types'

export interface GuardBeginRequest {
  /** Raw client IP hashed inside `RelayGuard` using its ephemeral per-day 32-byte secret salt. */
  clientIp?: string
  /** Optional pre-hashed identifier (used only by unit mocks; production callers pass `clientIp`). */
  ipHash?: string
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
const CHECKPOINT_IP_WINDOW_MS = 60_000
const CHECKPOINT_MAX_PER_IP_PER_MIN = 30
const CHECKPOINT_LOCK_TTL_MS = 15_000
const CHECKPOINT_RECENT_PUBLISH_GRACE_MS = 10_000

function utcDayKey(nowMs: number): string {
  return new Date(nowMs).toISOString().slice(0, 10)
}

/**
 * Strongly consistent SQLite Durable Object protecting `relay.audren.xyz`
 * against rent-drain / ping-pong / simulation-spam abuse:
 *   - Ephemeral per-day random 32-byte secret IP-hash salt persisted strictly inside DO storage
 *     (never derived from any public key or env constant; rotated & purged daily at UTC midnight)
 *   - Zero IP-hash linkage on `inflight_nullifiers` (stores only `(nullifier, expires_at)`)
 *   - Global daily sponsored SOL budget cap per cluster
 *   - Per-IP sliding-window hourly & daily sponsored tx limits
 *   - Per-IP cooldown between sponsored txs (prevents rapid back-and-forth ping-pong)
 *   - Per-IP self-paying burst cap & failed-attempt flood guard
 *   - Atomic in-flight nullifier deduplication across single & batched transactions
 */
export class RelayGuard extends DurableObject<Env> {
  private readonly sql: SqlStorage

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env)
    this.sql = ctx.storage.sql
    ctx.blockConcurrencyWhile(async () => {
      this.sql.exec(`
        CREATE TABLE IF NOT EXISTS daily_ip_salts (
          day TEXT PRIMARY KEY,
          salt_hex TEXT NOT NULL
        );

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

        CREATE TABLE IF NOT EXISTS checkpoint_locks (
          cluster_pool TEXT PRIMARY KEY,
          locked_until INTEGER NOT NULL DEFAULT 0,
          last_published_at INTEGER NOT NULL DEFAULT 0,
          last_epoch INTEGER NOT NULL DEFAULT -1,
          last_signature TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS checkpoint_ip_hits (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ip_hash TEXT NOT NULL,
          cluster TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ckpt_ip_hits ON checkpoint_ip_hits (ip_hash, cluster, created_at);
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
    })
  }

  /**
   * Load or generate the current UTC day's random 32-byte secret salt inside DO storage,
   * purging salts from prior UTC days so historical IP hashes cannot be inverted.
   */
  private getOrCreateDailySaltHex(now: number): string {
    const day = utcDayKey(now)
    this.sql.exec('DELETE FROM daily_ip_salts WHERE day < ?', day)
    const rows = this.sql
      .exec('SELECT salt_hex FROM daily_ip_salts WHERE day = ?', day)
      .toArray()
    const existing = rows[0]?.salt_hex
    if (typeof existing === 'string' && existing.length === 64) {
      return existing
    }
    const randomSalt = new Uint8Array(32)
    crypto.getRandomValues(randomSalt)
    const saltHex = toHex(randomSalt)
    this.sql.exec(
      'INSERT OR IGNORE INTO daily_ip_salts (day, salt_hex) VALUES (?, ?)',
      day,
      saltHex,
    )
    const persisted = this.sql
      .exec('SELECT salt_hex FROM daily_ip_salts WHERE day = ?', day)
      .one().salt_hex
    return String(persisted)
  }

  private computeDailyIpHash(clientIp: string, now: number): string {
    const saltHex = this.getOrCreateDailySaltHex(now)
    return toHex(sha256(utf8(`${saltHex}|${clientIp}`))).slice(0, 32)
  }

  private prune(now: number): void {
    const day = utcDayKey(now)
    this.sql.exec('DELETE FROM daily_ip_salts WHERE day < ?', day)
    this.sql.exec('DELETE FROM inflight_nullifiers WHERE expires_at < ?', now)
    this.sql.exec('DELETE FROM pending_reservations WHERE expires_at < ?', now)
    this.sql.exec('DELETE FROM ip_events WHERE created_at < ?', now - DAY_MS - HOUR_MS)
    this.sql.exec('DELETE FROM checkpoint_ip_hits WHERE created_at < ?', now - CHECKPOINT_IP_WINDOW_MS)
  }

  /**
   * Hash a client IP inside `RelayGuard` using the current UTC day's ephemeral 32-byte random salt.
   * The secret salt never leaves Durable Object storage.
   */
  async hashClientIp(clientIp: string, nowMs: number = Date.now()): Promise<string> {
    return this.computeDailyIpHash(clientIp || 'unknown', nowMs)
  }

  /**
   * Pre-simulation guard (before RPC simulation):
   * Atomically dedup concurrent nullifiers (without storing any IP association on nullifiers)
   * and block IPs flooding invalid payloads.
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

  async checkCheckpointRateLimit(req: {
    clientIp?: string
    ipHash?: string
    cluster: Cluster
    maxPerMinute?: number
  }): Promise<GuardDecision> {
    const now = Date.now()
    const ipHash = req.ipHash ?? this.computeDailyIpHash(req.clientIp ?? 'unknown', now)
    const limit = req.maxPerMinute ?? CHECKPOINT_MAX_PER_IP_PER_MIN
    this.sql.exec('DELETE FROM checkpoint_ip_hits WHERE created_at < ?', now - CHECKPOINT_IP_WINDOW_MS)
    const cnt = Number(
      this.sql
        .exec(
          'SELECT COUNT(*) AS cnt FROM checkpoint_ip_hits WHERE ip_hash = ? AND cluster = ? AND created_at >= ?',
          ipHash,
          req.cluster,
          now - CHECKPOINT_IP_WINDOW_MS,
        )
        .one().cnt ?? 0,
    )
    if (cnt >= limit) {
      return {
        allowed: false,
        ipHash,
        status: 429,
        code: 'CHECKPOINT_RATE_LIMITED',
        reason: 'Too many checkpoint requests from this IP. Please retry shortly.',
        retryAfterSec: 15,
      }
    }
    this.sql.exec(
      'INSERT INTO checkpoint_ip_hits (ip_hash, cluster, created_at) VALUES (?, ?, ?)',
      ipHash,
      req.cluster,
      now,
    )
    return { allowed: true, ipHash }
  }

  async acquireCheckpointLock(req: {
    cluster: Cluster
    poolId: number
    epoch: number
    lockTtlMs?: number
  }): Promise<CheckpointLockAcquireResult> {
    const now = Date.now()
    const key = `${req.cluster}:${req.poolId}`
    const rows = this.sql
      .exec(
        'SELECT locked_until, last_published_at, last_epoch, last_signature FROM checkpoint_locks WHERE cluster_pool = ?',
        key,
      )
      .toArray()
    const row = rows[0]
    if (row) {
      const lockedUntil = Number(row.locked_until ?? 0)
      if (lockedUntil > now) {
        return {
          allowed: false,
          inFlight: true,
          waitMs: Math.min(Math.max(lockedUntil - now, 1_000), 4_000),
        }
      }
      const lastEpoch = Number(row.last_epoch ?? -1)
      const lastPublishedAt = Number(row.last_published_at ?? 0)
      if (lastEpoch >= req.epoch && now - lastPublishedAt < CHECKPOINT_RECENT_PUBLISH_GRACE_MS) {
        return {
          allowed: false,
          alreadyPublished: true,
          lastEpoch,
          lastSignature: String(row.last_signature ?? '') || undefined,
        }
      }
    }

    const lockedUntil = now + (req.lockTtlMs ?? CHECKPOINT_LOCK_TTL_MS)
    this.sql.exec(
      `INSERT INTO checkpoint_locks (cluster_pool, locked_until, last_published_at, last_epoch, last_signature)
       VALUES (?, ?, 0, -1, '')
       ON CONFLICT (cluster_pool) DO UPDATE SET locked_until = excluded.locked_until`,
      key,
      lockedUntil,
    )
    return { allowed: true }
  }

  async releaseCheckpointLock(req: {
    cluster: Cluster
    poolId: number
    published: boolean
    epoch?: number
    signature?: string
  }): Promise<void> {
    const now = Date.now()
    const key = `${req.cluster}:${req.poolId}`
    if (req.published && req.epoch !== undefined) {
      this.sql.exec(
        `INSERT INTO checkpoint_locks (cluster_pool, locked_until, last_published_at, last_epoch, last_signature)
         VALUES (?, 0, ?, ?, ?)
         ON CONFLICT (cluster_pool) DO UPDATE SET
           locked_until = 0,
           last_published_at = excluded.last_published_at,
           last_epoch = excluded.last_epoch,
           last_signature = excluded.last_signature`,
        key,
        now,
        req.epoch,
        req.signature ?? '',
      )
    } else {
      this.sql.exec('UPDATE checkpoint_locks SET locked_until = 0 WHERE cluster_pool = ?', key)
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
