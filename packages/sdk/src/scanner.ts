/**
 * Zero-Indexer Pure Solana RPC `getMultipleAccounts` & Agave 4.4 `programSubscribe` (`dataSlice`) Scanner.
 * Scans up to 100 `EpochPage` PDAs (`3,200` shielded notes) per single RPC call (~`106 KB` total)
 * and resolves live spent/unspent state via 0-byte `NullifierPDA` existence checks.
 */

import {
  PAGE_LEN,
  PAGE_MAGIC,
  PAGE_OFF_POOL_ID,
  PAGE_SCAN_LEN,
  PAGE_SCAN_OFFSET,
} from './constants.ts';
import { decodePageScanSlice, type PageScanSlice } from './layout.ts';

export const MAX_RPC_MULTI_ACCOUNTS = 100;

export interface RpcMultipleAccountsRequest {
  jsonrpc: '2.0';
  id: number;
  method: 'getMultipleAccounts';
  params: [
    string[],
    {
      encoding: 'base64';
      commitment: 'confirmed' | 'finalized';
      dataSlice: { offset: number; length: number };
    },
  ];
}

export interface RpcProgramSubscribeRequest {
  jsonrpc: '2.0';
  id: number;
  method: 'programSubscribe';
  params: [
    string,
    {
      encoding: 'base64';
      commitment: 'confirmed' | 'finalized';
      dataSlice: { offset: number; length: number };
      filters: Array<
        | { dataSize: number }
        | { memcmp: { offset: number; bytes: string; encoding: 'base64' } }
      >;
    },
  ];
}

function encodeBase64(bytes: Uint8Array): string {
  if (typeof globalThis.btoa === 'function') {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    return globalThis.btoa(bin);
  }
  const buf = (globalThis as { Buffer?: { from(b: Uint8Array): { toString(enc: string): string } } })
    .Buffer;
  if (!buf) throw new Error('No base64 encoder available');
  return buf.from(bytes).toString('base64');
}

/**
 * Build an Agave 4.4+ WebSocket `programSubscribe` payload that streams real-time
 * `1,056 B` `EpochPage` scan slices (`dataSlice`) for a given `poolId` (~83% less WS bandwidth).
 */
export function buildPageSubscribeWsPayload(
  programId: string,
  poolId: number,
  id = 3,
  commitment: 'confirmed' | 'finalized' = 'confirmed',
): RpcProgramSubscribeRequest {
  const magicBytes = new TextEncoder().encode(PAGE_MAGIC);
  const poolIdBytes = new Uint8Array(4);
  new DataView(poolIdBytes.buffer).setUint32(0, poolId, true);
  return {
    jsonrpc: '2.0',
    id,
    method: 'programSubscribe',
    params: [
      programId,
      {
        encoding: 'base64',
        commitment,
        dataSlice: {
          offset: PAGE_SCAN_OFFSET,
          length: PAGE_SCAN_LEN,
        },
        filters: [
          { dataSize: PAGE_LEN },
          { memcmp: { offset: 0, bytes: encodeBase64(magicBytes), encoding: 'base64' } },
          { memcmp: { offset: PAGE_OFF_POOL_ID, bytes: encodeBase64(poolIdBytes), encoding: 'base64' } },
        ],
      },
    ],
  };
}

export function buildPageScanRpcPayload(
  pageAddresses: readonly string[],
  id = 1,
  commitment: 'confirmed' | 'finalized' = 'confirmed',
): RpcMultipleAccountsRequest {
  if (pageAddresses.length > MAX_RPC_MULTI_ACCOUNTS) {
    throw new Error(`Batch exceeds Solana getMultipleAccounts limit (${MAX_RPC_MULTI_ACCOUNTS})`);
  }
  return {
    jsonrpc: '2.0',
    id,
    method: 'getMultipleAccounts',
    params: [
      [...pageAddresses],
      {
        encoding: 'base64',
        commitment,
        dataSlice: {
          offset: PAGE_SCAN_OFFSET,
          length: PAGE_SCAN_LEN,
        },
      },
    ],
  };
}

export function buildNullifierCheckRpcPayload(
  nullifierAddresses: readonly string[],
  id = 2,
  commitment: 'confirmed' | 'finalized' = 'confirmed',
): RpcMultipleAccountsRequest {
  if (nullifierAddresses.length > MAX_RPC_MULTI_ACCOUNTS) {
    throw new Error(`Batch exceeds Solana getMultipleAccounts limit (${MAX_RPC_MULTI_ACCOUNTS})`);
  }
  return {
    jsonrpc: '2.0',
    id,
    method: 'getMultipleAccounts',
    params: [
      [...nullifierAddresses],
      {
        encoding: 'base64',
        commitment,
        dataSlice: { offset: 0, length: 0 },
      },
    ],
  };
}

function decodeBase64(b64: string): Uint8Array {
  if (typeof globalThis.atob === 'function') {
    const bin = globalThis.atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }
  // Node.js fallback without importing node:buffer into browser bundles.
  const buf = (globalThis as { Buffer?: { from(s: string, enc: string): Uint8Array } }).Buffer;
  if (!buf) throw new Error('No base64 decoder available');
  return new Uint8Array(buf.from(b64, 'base64'));
}

interface RpcAccountEntry {
  data: [string, string];
  lamports: number;
  owner: string;
}

/**
 * Fetch up to 100 `EpochPage` scan slices (`3,200` notes, ~`106 KB`) in a single pure Solana RPC call.
 */
export async function fetchPageScanSlices(
  rpcUrl: string,
  pageAddresses: readonly string[],
  commitment: 'confirmed' | 'finalized' = 'confirmed',
): Promise<(PageScanSlice | null)[]> {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(buildPageScanRpcPayload(pageAddresses, 1, commitment)),
  });
  if (!res.ok) {
    throw new Error(`Solana RPC error: HTTP ${res.status}`);
  }
  const json = (await res.json()) as {
    result?: { value: (RpcAccountEntry | null)[] };
    error?: { message: string };
  };
  if (json.error || !json.result) {
    throw new Error(json.error?.message ?? 'Missing getMultipleAccounts result');
  }
  return json.result.value.map((acc) => {
    if (!acc) return null;
    return decodePageScanSlice(decodeBase64(acc.data[0]));
  });
}

/**
 * Check up to 100 deterministic `NullifierPDA`s in one pure Solana RPC call (`true` == spent).
 */
export async function checkNullifiersSpent(
  rpcUrl: string,
  nullifierAddresses: readonly string[],
  commitment: 'confirmed' | 'finalized' = 'confirmed',
): Promise<boolean[]> {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(buildNullifierCheckRpcPayload(nullifierAddresses, 2, commitment)),
  });
  if (!res.ok) {
    throw new Error(`Solana RPC error: HTTP ${res.status}`);
  }
  const json = (await res.json()) as {
    result?: { value: (RpcAccountEntry | null)[] };
    error?: { message: string };
  };
  if (json.error || !json.result) {
    throw new Error(json.error?.message ?? 'Missing getMultipleAccounts result');
  }
  return json.result.value.map((acc) => acc !== null);
}
