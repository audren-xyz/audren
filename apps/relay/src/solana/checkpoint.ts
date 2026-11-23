import { ed25519 } from '@noble/curves/ed25519.js'
import {
  CHECKPOINT_RING_SLOTS,
  buildPublishCheckpointSolanaIx,
  decodeLaneHeader,
  decodePoolState,
  decodeRootCheckpoint,
  deriveCheckpointPda,
  deriveLanePda,
  derivePoolPda,
  type DecodedLaneHeader,
  type DecodedPoolState,
  type DecodedRootCheckpoint,
} from './audren'
import { base58Encode, buildAndSignV1Transaction, toBase64 } from './codec'
import {
  explorerTxUrl,
  fetchAccountBytes,
  fetchMultipleAccounts,
  rpcCall,
  simulateV1Transaction,
  solscanTxUrl,
  waitForConfirmation,
} from './rpc'
import type { CheckpointResponse, Cluster } from '../types'

export const SLOT_DURATION_MS = 400

export class CheckpointError extends Error {
  readonly status: number
  readonly code?: string
  readonly retryAfterSec?: number
  constructor(message: string, status = 400, code?: string, retryAfterSec?: number) {
    super(message)
    this.name = 'CheckpointError'
    this.status = status
    this.code = code
    this.retryAfterSec = retryAfterSec
  }
}

export interface CheckpointLockAcquireResult {
  allowed: boolean
  status?: number
  code?: string
  reason?: string
  retryAfterSec?: number
  inFlight?: boolean
  waitMs?: number
  alreadyPublished?: boolean
  lastEpoch?: number
  lastSignature?: string
}

export interface CheckpointLockAdapter {
  acquire(req: {
    cluster: Cluster
    poolId: number
    epoch: number
  }): Promise<CheckpointLockAcquireResult>
  release(req: {
    cluster: Cluster
    poolId: number
    published: boolean
    epoch?: number
    signature?: string
  }): Promise<void>
}

export interface PoolCheckpointSnapshot {
  pool: DecodedPoolState
  lanes: DecodedLaneHeader[]
  latestCkpt: DecodedRootCheckpoint | null
  targetSlotCkpt: DecodedRootCheckpoint | null
  currentSlot: bigint
}

export type CheckpointEvaluation =
  | {
      action: 'up_to_date'
      epoch: number
      slotIdx?: number
      totalLeaves: bigint
      lastCkptTotalLeaves: bigint
    }
  | {
      action: 'cooldown'
      epoch: number
      slotsRemaining: number
      waitMs: number
      nextCkptSlot: bigint
      totalLeaves: bigint
      lastCkptTotalLeaves: bigint
    }
  | {
      action: 'publish'
      epoch: number
      slotIdx: number
      totalLeaves: bigint
      lastCkptTotalLeaves: bigint
    }

/**
 * Pure state-machine evaluation matching on-chain `ix_publish_checkpoint` (`Tag 5`) semantics:
 *   - `up_to_date`: no uncheckpointed leaves exist across active lanes (and latest checkpoint is not expired).
 *   - `cooldown`: uncheckpointed leaves (or an expired checkpoint on a non-empty pool) exist, but
 *     `currentSlot < nextCkptSlot` (either current epoch was already published or ring slot cooldown applies).
 *   - `publish`: uncheckpointed leaves exist AND `currentSlot >= nextCkptSlot`.
 */
export function evaluateCheckpointState(params: {
  pool: DecodedPoolState
  lanes: DecodedLaneHeader[]
  latestCkpt: DecodedRootCheckpoint | null
  targetSlotCkpt: DecodedRootCheckpoint | null
  currentSlot: bigint | number
}): CheckpointEvaluation {
  const { pool, lanes, latestCkpt, targetSlotCkpt } = params
  const curSlot = BigInt(params.currentSlot)
  const ckptInterval = pool.ckptInterval > 0n ? pool.ckptInterval : 1n
  const curEpoch = curSlot / ckptInterval
  const curSlotIdx = Number(curEpoch % BigInt(CHECKPOINT_RING_SLOTS))

  let totalLeaves = 0n
  let hasLaneDelta = false
  for (const lane of lanes) {
    totalLeaves += lane.nextLeaf
    const ckptLaneCount = latestCkpt ? (latestCkpt.laneCounts[lane.laneId] ?? 0n) : 0n
    if (lane.nextLeaf > ckptLaneCount) hasLaneDelta = true
  }

  let lastCkptTotalLeaves = 0n
  if (latestCkpt) {
    for (let l = 0; l < pool.activeLanes; l++) {
      lastCkptTotalLeaves += latestCkpt.laneCounts[l] ?? 0n
    }
  }

  const hasUncheckpointedLeaves = totalLeaves > lastCkptTotalLeaves || hasLaneDelta
  const latestCkptExpired =
    latestCkpt !== null &&
    curSlot > latestCkpt.publishedSlot &&
    curSlot - latestCkpt.publishedSlot > pool.maxCkptAge

  if (!hasUncheckpointedLeaves && !(latestCkptExpired && totalLeaves > 0n)) {
    return {
      action: 'up_to_date',
      epoch: Number(latestCkpt ? latestCkpt.epochId : curEpoch),
      slotIdx: latestCkpt?.slotIdx,
      totalLeaves,
      lastCkptTotalLeaves,
    }
  }

  let nextCkptSlot = curSlot
  if (latestCkpt && curEpoch <= latestCkpt.epochId) {
    // Current epoch already published: wait for the start of `latestCkpt.epochId + 1`.
    nextCkptSlot = (latestCkpt.epochId + 1n) * ckptInterval
  } else if (targetSlotCkpt) {
    // Reusing an older ring slot: on-chain enforces `epoch_id > prev_epoch` and `slot - prev_slot > max_ckpt_age`.
    if (curEpoch <= targetSlotCkpt.epochId) {
      const afterTargetEpoch = (targetSlotCkpt.epochId + 1n) * ckptInterval
      if (afterTargetEpoch > nextCkptSlot) nextCkptSlot = afterTargetEpoch
    } else {
      const afterTargetAge = targetSlotCkpt.publishedSlot + pool.maxCkptAge + 1n
      if (afterTargetAge > nextCkptSlot) nextCkptSlot = afterTargetAge
    }
  }

  if (curSlot < nextCkptSlot) {
    const slotsRemaining = Number(nextCkptSlot - curSlot)
    return {
      action: 'cooldown',
      epoch: Number(curEpoch),
      slotsRemaining,
      waitMs: slotsRemaining * SLOT_DURATION_MS,
      nextCkptSlot,
      totalLeaves,
      lastCkptTotalLeaves,
    }
  }

  return {
    action: 'publish',
    epoch: Number(curEpoch),
    slotIdx: curSlotIdx,
    totalLeaves,
    lastCkptTotalLeaves,
  }
}

/**
 * Fetch `PoolState`, current slot, active `LaneTreeState`s, and the latest + target-slot
 * `RootCheckpoint` PDAs using minimal batched `getMultipleAccounts` RPC calls.
 */
export async function fetchPoolCheckpointSnapshot(
  rpcUrl: string,
  poolId = 0,
): Promise<PoolCheckpointSnapshot | null> {
  const poolPda = base58Encode(derivePoolPda(poolId).address)
  const [poolAcc, rawSlot] = await Promise.all([
    fetchAccountBytes(rpcUrl, poolPda).catch(() => null),
    rpcCall<number>(rpcUrl, 'getSlot', [{ commitment: 'confirmed' }]),
  ])
  if (!poolAcc) return null

  const pool = decodePoolState(poolAcc.bytes)
  const currentSlot = BigInt(rawSlot)
  if (pool.activeLanes === 0) {
    return { pool, lanes: [], latestCkpt: null, targetSlotCkpt: null, currentSlot }
  }

  const ckptInterval = pool.ckptInterval > 0n ? pool.ckptInterval : 1n
  const curEpoch = currentSlot / ckptInterval

  const lanePdas = Array.from({ length: pool.activeLanes }, (_, l) =>
    base58Encode(deriveLanePda(poolId, l).address),
  )

  const seenSlots = new Set<number>()
  const orderedCkptPdas: string[] = []
  for (let back = 0; back < CHECKPOINT_RING_SLOTS; back++) {
    const ep = curEpoch >= BigInt(back) ? curEpoch - BigInt(back) : 0n
    const slotIdx = Number(ep % BigInt(CHECKPOINT_RING_SLOTS))
    if (!seenSlots.has(slotIdx)) {
      seenSlots.add(slotIdx)
      orderedCkptPdas.push(base58Encode(deriveCheckpointPda(poolId, slotIdx).address))
    }
  }

  const firstBatchCount = Math.min(orderedCkptPdas.length, 100 - lanePdas.length)
  const firstCkptPdas = orderedCkptPdas.slice(0, firstBatchCount)
  const firstBatch = await fetchMultipleAccounts(rpcUrl, [...lanePdas, ...firstCkptPdas])

  const lanes: DecodedLaneHeader[] = []
  for (let i = 0; i < lanePdas.length; i++) {
    const acc = firstBatch[i]
    if (acc?.bytes) {
      lanes.push(decodeLaneHeader(acc.bytes))
    }
  }

  const scanState: {
    latestCkpt: DecodedRootCheckpoint | null
    targetSlotCkpt: DecodedRootCheckpoint | null
  } = {
    latestCkpt: null,
    targetSlotCkpt: null,
  }

  const scanCheckpoints = (
    accounts: Array<{ bytes: Uint8Array } | null>,
    isFirstBatch: boolean,
  ) => {
    for (let i = 0; i < accounts.length; i++) {
      const acc = accounts[i]
      if (!acc?.bytes) continue
      let ckpt: DecodedRootCheckpoint
      try {
        ckpt = decodeRootCheckpoint(acc.bytes)
      } catch {
        continue
      }
      if (isFirstBatch && i === 0) {
        scanState.targetSlotCkpt = ckpt
      }
      if (
        !scanState.latestCkpt ||
        ckpt.publishedSlot > scanState.latestCkpt.publishedSlot ||
        (ckpt.publishedSlot === scanState.latestCkpt.publishedSlot &&
          ckpt.epochId > scanState.latestCkpt.epochId)
      ) {
        scanState.latestCkpt = ckpt
      }
    }
  }

  scanCheckpoints(firstBatch.slice(lanePdas.length), true)

  // Only skip scanning the rest of the 256-slot ring when a genuine recent checkpoint
  // (`epochId >= minRecentEpoch`) was found in `firstBatch`. An ancient wrapped checkpoint
  // from a previous ring cycle (`epochId < minRecentEpoch`) must NOT short-circuit the scan.
  const minRecentEpoch =
    firstBatchCount > 0 && curEpoch >= BigInt(firstBatchCount - 1)
      ? curEpoch - BigInt(firstBatchCount - 1)
      : 0n
  const foundRecentInFirstBatch =
    scanState.latestCkpt !== null && scanState.latestCkpt.epochId >= minRecentEpoch

  if (!foundRecentInFirstBatch && orderedCkptPdas.length > firstBatchCount) {
    const restAccs = await fetchMultipleAccounts(rpcUrl, orderedCkptPdas.slice(firstBatchCount))
    scanCheckpoints(restAccs, false)
  }

  return {
    pool,
    lanes,
    latestCkpt: scanState.latestCkpt,
    targetSlotCkpt: scanState.targetSlotCkpt,
    currentSlot,
  }
}

/**
 * Permissionless on-demand `PublishCheckpoint` (`Tag 5`) coordinator used by both
 * `POST /v1/checkpoint` and the scheduled maintenance crank (`runV2MaintenanceCrank`).
 */
export async function publishCheckpointIfNeeded(params: {
  rpcUrl: string
  cluster: Cluster
  poolId?: number
  relayerSecret32: Uint8Array
  lock?: CheckpointLockAdapter
  confirm?: boolean
}): Promise<CheckpointResponse> {
  const { rpcUrl, cluster, poolId = 0, relayerSecret32, lock, confirm = true } = params
  const snapshot = await fetchPoolCheckpointSnapshot(rpcUrl, poolId)
  if (!snapshot || snapshot.pool.activeLanes === 0) {
    throw new CheckpointError('Audren pool is not initialized on this cluster', 404, 'POOL_NOT_FOUND')
  }

  const evalRes = evaluateCheckpointState(snapshot)
  if (evalRes.action === 'up_to_date') {
    return {
      ok: true,
      cluster,
      poolId,
      status: 'up_to_date',
      epoch: evalRes.epoch,
      ...(evalRes.slotIdx !== undefined ? { slotIdx: evalRes.slotIdx } : {}),
      totalLeaves: evalRes.totalLeaves.toString(),
      lastCkptTotalLeaves: evalRes.lastCkptTotalLeaves.toString(),
    }
  }

  if (evalRes.action === 'cooldown') {
    return {
      ok: true,
      cluster,
      poolId,
      status: 'cooldown',
      epoch: evalRes.epoch,
      slotsRemaining: evalRes.slotsRemaining,
      waitMs: evalRes.waitMs,
      totalLeaves: evalRes.totalLeaves.toString(),
      lastCkptTotalLeaves: evalRes.lastCkptTotalLeaves.toString(),
    }
  }

  // Acquire per-(cluster, poolId) single-flight lock before spending relayer SOL.
  let lockHeld = false
  if (lock) {
    const acquired = await lock.acquire({ cluster, poolId, epoch: evalRes.epoch })
    if (!acquired.allowed) {
      if (acquired.inFlight) {
        const waitMs = acquired.waitMs ?? 2_000
        return {
          ok: true,
          cluster,
          poolId,
          status: 'cooldown',
          epoch: evalRes.epoch,
          slotsRemaining: Math.max(1, Math.ceil(waitMs / SLOT_DURATION_MS)),
          waitMs,
          inFlight: true,
          totalLeaves: evalRes.totalLeaves.toString(),
          lastCkptTotalLeaves: evalRes.lastCkptTotalLeaves.toString(),
        }
      }
      if (acquired.alreadyPublished) {
        return {
          ok: true,
          cluster,
          poolId,
          status: 'up_to_date',
          epoch: acquired.lastEpoch ?? evalRes.epoch,
          ...(acquired.lastSignature ? { signature: acquired.lastSignature } : {}),
          totalLeaves: evalRes.totalLeaves.toString(),
          lastCkptTotalLeaves: evalRes.lastCkptTotalLeaves.toString(),
        }
      }
      throw new CheckpointError(
        acquired.reason ?? 'Checkpoint rate limit reached',
        acquired.status ?? 429,
        acquired.code ?? 'CHECKPOINT_RATE_LIMITED',
        acquired.retryAfterSec,
      )
    }
    lockHeld = true
  }

  const relayerPubkey = ed25519.getPublicKey(relayerSecret32)
  const relayerB58 = base58Encode(relayerPubkey)
  let published = false
  let publishEpoch = evalRes.epoch
  let publishSlotIdx = evalRes.slotIdx
  let sentSig: string | undefined

  const buildAndSimulate = async (slotIdx: number) => {
    const ckIx = buildPublishCheckpointSolanaIx({
      payer: relayerB58,
      poolId,
      slotIdx,
      activeLanes: snapshot.pool.activeLanes,
    })
    const bh = await rpcCall<{ value: { blockhash: string } }>(rpcUrl, 'getLatestBlockhash', [
      { commitment: 'confirmed' },
    ])
    const signed = buildAndSignV1Transaction(relayerSecret32, bh.value.blockhash, [ckIx], {
      computeUnitLimit: 120_000,
      priorityFeeLamports: 5_000n,
    })
    const sim = await simulateV1Transaction(rpcUrl, signed.wireBytes, [relayerB58])
    return { signed, sim }
  }

  try {
    let { signed, sim } = await buildAndSimulate(publishSlotIdx)

    // Handle slot boundary tick or concurrent publisher race gracefully.
    if (sim.err) {
      const freshSlot = BigInt(await rpcCall<number>(rpcUrl, 'getSlot', [{ commitment: 'confirmed' }]))
      const ckptInterval = snapshot.pool.ckptInterval > 0n ? snapshot.pool.ckptInterval : 1n
      const freshEpoch = Number(freshSlot / ckptInterval)
      const freshSlotIdx = Number((freshSlot / ckptInterval) % BigInt(CHECKPOINT_RING_SLOTS))
      if (freshEpoch > publishEpoch) {
        publishEpoch = freshEpoch
        publishSlotIdx = freshSlotIdx
        const retried = await buildAndSimulate(publishSlotIdx)
        signed = retried.signed
        sim = retried.sim
      }
    }

    if (sim.err) {
      // Another publisher may have landed the checkpoint in this epoch; re-check cleanly.
      const freshSnap = await fetchPoolCheckpointSnapshot(rpcUrl, poolId).catch(() => null)
      if (freshSnap) {
        const reEval = evaluateCheckpointState(freshSnap)
        if (reEval.action === 'up_to_date') {
          return {
            ok: true,
            cluster,
            poolId,
            status: 'up_to_date',
            epoch: reEval.epoch,
            ...(reEval.slotIdx !== undefined ? { slotIdx: reEval.slotIdx } : {}),
            totalLeaves: reEval.totalLeaves.toString(),
            lastCkptTotalLeaves: reEval.lastCkptTotalLeaves.toString(),
          }
        }
        if (reEval.action === 'cooldown') {
          return {
            ok: true,
            cluster,
            poolId,
            status: 'cooldown',
            epoch: reEval.epoch,
            slotsRemaining: reEval.slotsRemaining,
            waitMs: reEval.waitMs,
            totalLeaves: reEval.totalLeaves.toString(),
            lastCkptTotalLeaves: reEval.lastCkptTotalLeaves.toString(),
          }
        }
      }
      throw new CheckpointError(
        `PublishCheckpoint simulation failed: ${JSON.stringify(sim.err)}`,
        502,
        'CHECKPOINT_SIMULATION_FAILED',
      )
    }

    sentSig = await rpcCall<string>(rpcUrl, 'sendTransaction', [
      toBase64(signed.wireBytes),
      { encoding: 'base64', preflightCommitment: 'confirmed', maxRetries: 2 },
    ])

    let confirmedSlot: number | undefined
    if (confirm) {
      const conf = await waitForConfirmation(rpcUrl, sentSig)
      confirmedSlot = conf.slot
    }

    published = true
    return {
      ok: true,
      cluster,
      poolId,
      status: 'published',
      signature: sentSig,
      epoch: publishEpoch,
      slotIdx: publishSlotIdx,
      ...(confirmedSlot !== undefined ? { slot: confirmedSlot } : {}),
      totalLeaves: evalRes.totalLeaves.toString(),
      lastCkptTotalLeaves: evalRes.lastCkptTotalLeaves.toString(),
      solscanUrl: solscanTxUrl(sentSig, cluster),
      explorerUrl: explorerTxUrl(sentSig, cluster),
    }
  } finally {
    if (lock && lockHeld) {
      await lock
        .release({
          cluster,
          poolId,
          published,
          epoch: published ? publishEpoch : undefined,
          signature: published ? sentSig : undefined,
        })
        .catch(() => {})
    }
  }
}
