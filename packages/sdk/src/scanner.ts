/**
 * Indexer-free ordinary Solana RPC (`getMultipleAccounts`) sync & historical witness reconstruction.
 */

import {
  AUDREN_PROGRAM_ID,
  MEMO_NOTES_PER_PAGE,
  NF_PER_PAGE,
  SUBROOTS_PER_PAGE,
  SUBTREE_LEAVES,
} from './constants.ts';
import type { FullViewingKey } from './keys.ts';
import {
  decodeLaneHeader,
  decodePoolState,
  decodeRootCheckpoint,
  decodeSubtreePage,
  decodeSubtreeRootPage,
  type DecodedLaneHeader,
  type DecodedPoolState,
  type DecodedRootCheckpoint,
} from './layout.ts';
import {
  deriveCheckpointPdaSync,
  deriveLanePdaSync,
  deriveMemoPdaSync,
  deriveNfPagePdaSync,
  derivePoolPdaSync,
  deriveSubrootPdaSync,
  deriveSubtreePdaSync,
} from './pda.ts';
import { frFromBeBytesStrict } from './poseidon.ts';
import {
  buildHistoricalWitness4Ary,
  type CompactWalletStore,
  type MerklePath4Ary,
} from './store.ts';

export type AccountBatchFetcher = (addresses: readonly string[]) => Promise<(Uint8Array | null)[]>;

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Ordinary Solana JSON-RPC `getMultipleAccounts` batch fetcher (chunks by 100 accounts). */
export function createSolanaRpcBatchFetcher(
  rpcUrl: string,
  commitment: 'confirmed' | 'finalized' = 'confirmed',
): AccountBatchFetcher {
  return async (addresses: readonly string[]) => {
    const out: (Uint8Array | null)[] = new Array(addresses.length).fill(null);
    for (let off = 0; off < addresses.length; off += 100) {
      const chunk = addresses.slice(off, off + 100);
      const res = await fetch(rpcUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'getMultipleAccounts',
          params: [chunk, { encoding: 'base64', commitment }],
        }),
      });
      if (!res.ok) throw new Error(`Solana RPC getMultipleAccounts HTTP ${res.status}`);
      const json = (await res.json()) as {
        result?: { value: Array<{ data: [string, string] } | null> };
        error?: { message?: string };
      };
      if (json.error) throw new Error(`Solana RPC error: ${json.error.message ?? 'unknown'}`);
      const values = json.result?.value ?? [];
      for (let i = 0; i < chunk.length; i++) {
        const acc = values[i];
        out[off + i] = acc?.data?.[0] ? base64ToBytes(acc.data[0]) : null;
      }
    }
    return out;
  };
}

/** Fetch `PoolState` + all active `LaneTreeState` headers in 2 batched RPC calls. */
export async function fetchPoolAndLanes(
  fetchBatch: AccountBatchFetcher,
  poolId = 0,
  programId = AUDREN_PROGRAM_ID,
): Promise<{ pool: DecodedPoolState; lanes: DecodedLaneHeader[] }> {
  const poolPda = derivePoolPdaSync(poolId, programId).address;
  const [poolRaw] = await fetchBatch([poolPda]);
  if (!poolRaw) throw new Error(`PoolState account missing at ${poolPda}`);
  const pool = decodePoolState(poolRaw);

  const lanePdas: string[] = [];
  for (let l = 0; l < pool.activeLanes; l++) {
    lanePdas.push(deriveLanePdaSync(poolId, l, programId).address);
  }
  const laneRaws = await fetchBatch(lanePdas);
  const lanes = laneRaws.map((raw, l) => {
    if (!raw) throw new Error(`LaneTreeState #${l} missing`);
    return decodeLaneHeader(raw);
  });
  return { pool, lanes };
}

/**
 * Incrementally sync `CompactWalletStore` across all active lanes via ordinary `getMultipleAccounts`
 * calls (zero indexer, zero targeted per-note or per-nullifier queries).
 */
export async function syncCompactStoreWithRpc(params: {
  store: CompactWalletStore;
  fvk: FullViewingKey;
  fetchBatch: AccountBatchFetcher;
  programId?: string;
}): Promise<{ pool: DecodedPoolState; lanes: DecodedLaneHeader[]; discoveredNotes: number }> {
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const { pool, lanes } = await fetchPoolAndLanes(params.fetchBatch, params.store.poolId, programId);
  let discoveredNotes = 0;

  for (const laneHdr of lanes) {
    const l = laneHdr.laneId;
    const laneState = params.store.lanes[l]!;

    const targetSubMax = laneHdr.nextLeaf / BigInt(SUBTREE_LEAVES);
    const targetMemoMax = laneHdr.nextLeaf / BigInt(MEMO_NOTES_PER_PAGE);
    const targetNfMax = laneHdr.nfCount / BigInt(NF_PER_PAGE);

    const startSub = laneState.frontierSubSeq;
    const startMemo = laneState.nextMemoLeaf / BigInt(MEMO_NOTES_PER_PAGE);
    const startNf = laneState.nextNfIndex / BigInt(NF_PER_PAGE);

    const addrs: string[] = [];
    const subSeqs: bigint[] = [];
    const memoSeqs: bigint[] = [];
    const nfSeqs: bigint[] = [];

    if (laneHdr.nextLeaf > 0n) {
      for (let s = startSub; s <= targetSubMax; s++) {
        subSeqs.push(s);
        addrs.push(deriveSubtreePdaSync(params.store.poolId, l, s, programId).address);
      }
      for (let m = startMemo; m <= targetMemoMax; m++) {
        memoSeqs.push(m);
        addrs.push(deriveMemoPdaSync(params.store.poolId, l, m, programId).address);
      }
    }
    if (laneHdr.nfCount > 0n) {
      for (let n = startNf; n <= targetNfMax; n++) {
        nfSeqs.push(n);
        addrs.push(deriveNfPagePdaSync(params.store.poolId, l, n, programId).address);
      }
    }
    if (addrs.length === 0) continue;

    const raws = await params.fetchBatch(addrs);
    let idx = 0;
    const subtreePages: Array<{ pageSeq: bigint; raw: Uint8Array }> = [];
    for (const s of subSeqs) {
      const r = raws[idx++];
      if (r) subtreePages.push({ pageSeq: s, raw: r });
    }
    const memoPages: Array<{ pageSeq: bigint; raw: Uint8Array }> = [];
    for (const m of memoSeqs) {
      const r = raws[idx++];
      if (r) memoPages.push({ pageSeq: m, raw: r });
    }
    const nfPages: Array<{ pageSeq: bigint; raw: Uint8Array }> = [];
    for (const n of nfSeqs) {
      const r = raws[idx++];
      if (r) nfPages.push({ pageSeq: n, raw: r });
    }

    discoveredNotes += params.store.ingestLanePages({
      fvk: params.fvk,
      laneId: l,
      subtreePages,
      memoPages,
      nfPages,
    });
  }

  return { pool, lanes, discoveredNotes };
}

/** Stateless witness reconstruction for `(laneId, leafIdx)` at `RootCheckpoint(ckptSlotIdx)`. */
export async function reconstructWitness(params: {
  fetchBatch: AccountBatchFetcher;
  poolId: number;
  ckptSlotIdx: number;
  laneId: number;
  leafIdx: bigint;
  programId?: string;
}): Promise<{ ckpt: DecodedRootCheckpoint; superRoot: bigint; path: MerklePath4Ary }> {
  const programId = params.programId ?? AUDREN_PROGRAM_ID;
  const ckptAddr = deriveCheckpointPdaSync(params.poolId, params.ckptSlotIdx, programId).address;
  const [ckptRaw] = await params.fetchBatch([ckptAddr]);
  if (!ckptRaw) throw new Error(`RootCheckpoint #${params.ckptSlotIdx} missing`);
  const ckpt = decodeRootCheckpoint(ckptRaw);

  const ckptCount = ckpt.laneCounts[params.laneId]!;
  if (params.leafIdx >= ckptCount) throw new Error('leafIdx >= checkpoint lane count');

  const targetPageIdx = params.leafIdx / BigInt(SUBTREE_LEAVES);
  const frontierPageIdx = ckptCount / BigInt(SUBTREE_LEAVES);
  const frontierRem = Number(ckptCount % BigInt(SUBTREE_LEAVES));
  const neededSrPages = Math.ceil(Number(frontierPageIdx) / SUBROOTS_PER_PAGE);

  const addrs: string[] = [];
  for (let rp = 0; rp < neededSrPages; rp++) {
    addrs.push(deriveSubrootPdaSync(params.poolId, params.laneId, BigInt(rp), programId).address);
  }
  const targetSubAddr = deriveSubtreePdaSync(
    params.poolId,
    params.laneId,
    targetPageIdx,
    programId,
  ).address;
  addrs.push(targetSubAddr);
  const needDistinctFrontier = frontierRem > 0 && frontierPageIdx !== targetPageIdx;
  if (needDistinctFrontier) {
    addrs.push(
      deriveSubtreePdaSync(params.poolId, params.laneId, frontierPageIdx, programId).address,
    );
  }

  const raws = await params.fetchBatch(addrs);
  let cursor = 0;
  const finalizedRoots: bigint[] = [];
  for (let rp = 0; rp < neededSrPages; rp++) {
    const srRaw = raws[cursor++];
    if (!srRaw) throw new Error(`SubtreeRootPage #${rp} missing`);
    const sr = decodeSubtreeRootPage(srRaw);
    for (const r of sr.roots) {
      if (finalizedRoots.length === Number(frontierPageIdx)) break;
      finalizedRoots.push(frFromBeBytesStrict(r));
    }
  }
  const targetSubRaw = raws[cursor++];
  if (!targetSubRaw) throw new Error(`SubtreePage #${targetPageIdx} missing`);
  const targetLeaves = decodeSubtreePage(targetSubRaw).leaves.map((b) => frFromBeBytesStrict(b));

  let frontierLeaves: bigint[] | undefined;
  if (frontierRem > 0) {
    if (needDistinctFrontier) {
      const fRaw = raws[cursor++];
      if (!fRaw) throw new Error(`Frontier SubtreePage #${frontierPageIdx} missing`);
      frontierLeaves = decodeSubtreePage(fRaw).leaves.map((b) => frFromBeBytesStrict(b));
    } else {
      frontierLeaves = targetLeaves;
    }
  }

  const path = buildHistoricalWitness4Ary({
    laneId: params.laneId,
    targetLeafIdx: params.leafIdx,
    ckptLaneRoots: ckpt.laneRoots.map((b) => frFromBeBytesStrict(b)),
    ckptLaneLeafCount: ckptCount,
    finalizedSubtreeRoots: finalizedRoots,
    targetPageLeaves: targetLeaves,
    frontierPageLeaves: frontierLeaves,
  });
  return { ckpt, superRoot: frFromBeBytesStrict(ckpt.superRoot), path };
}
