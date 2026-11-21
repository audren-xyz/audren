/**
 * Zero-copy binary decoders for Audren `PoolState` (192 B), `AppendLaneState` (64 B),
 * and SoA `EpochPage` (6,240 B).
 */

import {
  LANE_MAGIC,
  LANE_STATE_LEN,
  NOTE_CT_LEN,
  PAGE_CAPACITY,
  PAGE_LEN,
  PAGE_MAGIC,
  PAGE_OFF_ASSET_TAGS,
  PAGE_OFF_CIPHERTEXTS,
  PAGE_OFF_COMMITMENTS,
  PAGE_OFF_EPHEMERAL_PKS,
  PAGE_OFF_STEALTH_PKS,
  PAGE_OFF_VIEW_TAGS,
  PAGE_SCAN_LEN,
  POOL_MAGIC,
  POOL_STATE_LEN,
  PoolMode,
} from './constants.ts';

export interface PoolState {
  version: number;
  bump: number;
  mode: PoolMode;
  paused: boolean;
  poolId: number;
  currentPageId: bigint;
  totalNotes: bigint;
  totalSpends: bigint;
  pageRentFeeLamports: bigint;
  authority: Uint8Array;
  auditorPk: Uint8Array;
  auditorLocked: boolean;
  vaultAuthBump: number;
  solVaultBump: number;
  pageRentBump: number;
  activeLanes: number;
}

export interface PageHeader {
  version: number;
  bump: number;
  closed: boolean;
  count: number;
  poolId: number;
  pageId: bigint;
  createdSlot: bigint;
  closedSlot: bigint;
}

export interface AppendLaneState {
  version: number;
  laneId: number;
  bump: number;
  rentVaultBump: number;
  poolId: number;
  currentPageId: bigint;
  createdSlot: bigint;
}

export interface NoteEntry {
  viewTag: number;
  ephemeralPk: Uint8Array;
  stealthPk: Uint8Array;
  assetTag: Uint8Array;
  commitment: Uint8Array;
  ciphertext: Uint8Array;
}

export interface PageScanSlice {
  viewTags: Uint8Array;
  ephemeralPks: Uint8Array[];
}

const asciiDecoder = new TextDecoder('ascii');

function readAscii(bytes: Uint8Array, offset: number, length: number): string {
  return asciiDecoder.decode(bytes.subarray(offset, offset + length));
}

export function decodePoolState(data: Uint8Array): PoolState {
  if (data.byteLength !== POOL_STATE_LEN) {
    throw new Error(`PoolState must be ${POOL_STATE_LEN} bytes, got ${data.byteLength}`);
  }
  const magic = readAscii(data, 0, 8);
  if (magic !== POOL_MAGIC) {
    throw new Error(`Invalid PoolState magic: ${magic}`);
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const modeVal = data[10];
  if (modeVal !== PoolMode.Permissionless && modeVal !== PoolMode.InstitutionalAudited) {
    throw new Error(`Unknown PoolMode: ${modeVal}`);
  }
  return {
    version: data[8],
    bump: data[9],
    mode: modeVal,
    paused: data[11] !== 0,
    poolId: view.getUint32(12, true),
    currentPageId: view.getBigUint64(16, true),
    totalNotes: view.getBigUint64(24, true),
    totalSpends: view.getBigUint64(32, true),
    pageRentFeeLamports: view.getBigUint64(40, true),
    authority: data.slice(48, 80),
    auditorPk: data.slice(80, 112),
    auditorLocked: data[112] !== 0,
    vaultAuthBump: data[113],
    solVaultBump: data[114],
    pageRentBump: data[115],
    activeLanes: Math.max(1, data[116]),
  };
}

export function decodeAppendLaneState(data: Uint8Array): AppendLaneState {
  if (data.byteLength !== LANE_STATE_LEN) {
    throw new Error(`AppendLaneState must be ${LANE_STATE_LEN} bytes, got ${data.byteLength}`);
  }
  const magic = readAscii(data, 0, 8);
  if (magic !== LANE_MAGIC) {
    throw new Error(`Invalid AppendLaneState magic: ${magic}`);
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return {
    version: data[8],
    laneId: data[9],
    bump: data[10],
    rentVaultBump: data[11],
    poolId: view.getUint32(12, true),
    currentPageId: view.getBigUint64(16, true),
    createdSlot: view.getBigUint64(24, true),
  };
}

export function decodePageHeader(data: Uint8Array): PageHeader {
  if (data.byteLength !== PAGE_LEN) {
    throw new Error(`EpochPage must be ${PAGE_LEN} bytes, got ${data.byteLength}`);
  }
  const magic = readAscii(data, 0, 8);
  if (magic !== PAGE_MAGIC) {
    throw new Error(`Invalid EpochPage magic: ${magic}`);
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const count = data[11];
  if (count > PAGE_CAPACITY) {
    throw new Error(`Invalid EpochPage count: ${count}`);
  }
  return {
    version: data[8],
    bump: data[9],
    closed: data[10] !== 0,
    count,
    poolId: view.getUint32(12, true),
    pageId: view.getBigUint64(16, true),
    createdSlot: view.getBigUint64(24, true),
    closedSlot: view.getBigUint64(32, true),
  };
}

export function readPageNote(data: Uint8Array, slot: number): NoteEntry {
  if (data.byteLength !== PAGE_LEN || slot < 0 || slot >= PAGE_CAPACITY) {
    throw new RangeError(`Invalid EpochPage buffer or slot ${slot}`);
  }
  const off32 = slot * 32;
  const offCt = slot * NOTE_CT_LEN;
  return {
    viewTag: data[PAGE_OFF_VIEW_TAGS + slot],
    ephemeralPk: data.slice(PAGE_OFF_EPHEMERAL_PKS + off32, PAGE_OFF_EPHEMERAL_PKS + off32 + 32),
    stealthPk: data.slice(PAGE_OFF_STEALTH_PKS + off32, PAGE_OFF_STEALTH_PKS + off32 + 32),
    assetTag: data.slice(PAGE_OFF_ASSET_TAGS + off32, PAGE_OFF_ASSET_TAGS + off32 + 32),
    commitment: data.slice(PAGE_OFF_COMMITMENTS + off32, PAGE_OFF_COMMITMENTS + off32 + 32),
    ciphertext: data.slice(PAGE_OFF_CIPHERTEXTS + offCt, PAGE_OFF_CIPHERTEXTS + offCt + NOTE_CT_LEN),
  };
}

/**
 * Decode the compact 1,056-byte `dataSlice` returned by pure-RPC `getMultipleAccounts`
 * or Agave 4.4 `programSubscribe` (`offset: 64, length: 1056`) into `viewTags[32]` and active `ephemeralPks`.
 */
export function decodePageScanSlice(slice: Uint8Array): PageScanSlice {
  if (slice.byteLength < PAGE_SCAN_LEN) {
    throw new Error(`Page scan slice must be >= ${PAGE_SCAN_LEN} bytes`);
  }
  const viewTags = slice.slice(0, PAGE_CAPACITY);
  const ephemeralPks: Uint8Array[] = [];
  for (let i = 0; i < PAGE_CAPACITY; i++) {
    const start = PAGE_CAPACITY + i * 32;
    const pk = slice.slice(start, start + 32);
    let isZero = true;
    for (let b = 0; b < 32; b++) {
      if (pk[b] !== 0) {
        isZero = false;
        break;
      }
    }
    if (isZero) break;
    ephemeralPks.push(pk);
  }
  return { viewTags, ephemeralPks };
}
