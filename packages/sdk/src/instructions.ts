/**
 * Wire encoders for Audren's non-ZK instructions (`InitPool`, `OpenPage`, `Deposit`, `SetPaused`)
 * including third-party confidential deposits (`encodeDepositData`).
 *
 * Zero-knowledge proving instructions (`Transfer`, `Merge`, `SwapViaRouter`, `Withdraw`)
 * invoke the compiled Rust/WASM prover in `programs/audren/crates/client`.
 */

import {
  DYNAMIC_OUTPUT_WIRE_LEN,
  NOTE_CT_LEN,
  PROOF_BUFFER_CHUNK_SIZE,
  PROOF_BUFFER_MAX_PAYLOAD,
  PoolMode,
  TAG_CLOSE_PROOF_BUFFER,
  TAG_DEPOSIT,
  TAG_EXEC_BUFFERED,
  TAG_INIT_POOL,
  TAG_OPEN_PAGE,
  TAG_SET_PAUSED,
  TAG_WRITE_PROOF_BUFFER,
} from './constants.ts';

export interface DynamicOutputDescriptor {
  viewTag: number;
  ephemeralPk: Uint8Array; // 32 B
  stealthPk: Uint8Array; // 32 B
  ciphertext: Uint8Array; // 64 B (AES-256-GCM)
}

function assertLen(name: string, buf: Uint8Array, expected: number): void {
  if (buf.byteLength !== expected) {
    throw new Error(`${name} must be ${expected} bytes, got ${buf.byteLength}`);
  }
}

export function encodeInitPoolData(params: {
  poolId: number;
  mode: PoolMode;
  auditorLocked: boolean;
  pageRentFeeLamports: bigint;
  auditorPk?: Uint8Array;
}): Uint8Array {
  const auditorPk = params.auditorPk ?? new Uint8Array(32);
  assertLen('auditorPk', auditorPk, 32);
  const out = new Uint8Array(47);
  const view = new DataView(out.buffer);
  out[0] = TAG_INIT_POOL;
  view.setUint32(1, params.poolId, true);
  out[5] = params.mode;
  out[6] = params.auditorLocked ? 1 : 0;
  view.setBigUint64(7, params.pageRentFeeLamports, true);
  out.set(auditorPk, 15);
  return out;
}

export function encodeOpenPageData(): Uint8Array {
  return new Uint8Array([TAG_OPEN_PAGE]);
}

/**
 * Encode Tag 2 (`Deposit`) data (`139 B`).
 * Designed for both self-shielding and third-party regulated onramps:
 * no user spend key or ZK proof is required; the on-chain program computes `G_mint`
 * and `V = amount * G_mint` directly.
 */
export function encodeDepositData(params: {
  isNativeSol: boolean;
  amount: bigint;
  output: DynamicOutputDescriptor;
}): Uint8Array {
  assertLen('ephemeralPk', params.output.ephemeralPk, 32);
  assertLen('stealthPk', params.output.stealthPk, 32);
  assertLen('ciphertext', params.output.ciphertext, NOTE_CT_LEN);

  const out = new Uint8Array(1 + 9 + DYNAMIC_OUTPUT_WIRE_LEN);
  const view = new DataView(out.buffer);
  out[0] = TAG_DEPOSIT;
  out[1] = params.isNativeSol ? 1 : 0;
  view.setBigUint64(2, params.amount, true);
  out[10] = params.output.viewTag & 0xff;
  out.set(params.output.ephemeralPk, 11);
  out.set(params.output.stealthPk, 43);
  out.set(params.output.ciphertext, 75);
  return out;
}

export function encodeSetPausedData(paused: boolean): Uint8Array {
  return new Uint8Array([TAG_SET_PAUSED, paused ? 1 : 0]);
}

/**
 * Split a large instruction payload (without its 1-byte inner tag) into `<= 768 B`
 * `Tag 8` (`WriteProofBuffer`) instruction data frames so every upload tx fits below
 * Solana's `1,232 B` packet MTU. Chunks may be submitted in parallel / out of order.
 */
export function encodeWriteProofBufferChunks(params: {
  nonce: bigint;
  payload: Uint8Array;
}): Uint8Array[] {
  const { nonce, payload } = params;
  if (payload.byteLength === 0 || payload.byteLength > PROOF_BUFFER_MAX_PAYLOAD) {
    throw new Error(
      `ProofBuffer payload must be 1..=${PROOF_BUFFER_MAX_PAYLOAD} bytes, got ${payload.byteLength}`,
    );
  }
  const chunks: Uint8Array[] = [];
  for (let idx = 0, off = 0; off < payload.byteLength; idx++, off += PROOF_BUFFER_CHUNK_SIZE) {
    const slice = payload.subarray(off, Math.min(off + PROOF_BUFFER_CHUNK_SIZE, payload.byteLength));
    const out = new Uint8Array(14 + slice.byteLength);
    const view = new DataView(out.buffer);
    out[0] = TAG_WRITE_PROOF_BUFFER;
    view.setBigUint64(1, nonce, true);
    view.setUint32(9, payload.byteLength, true);
    out[13] = idx;
    out.set(slice, 14);
    chunks.push(out);
  }
  return chunks;
}

/** Encode Tag 9 (`ExecBuffered`, 2 bytes total) — executes inner payload and refunds 100% rent. */
export function encodeExecBufferedData(innerTag: number): Uint8Array {
  return new Uint8Array([TAG_EXEC_BUFFERED, innerTag & 0xff]);
}

/**
 * Compute the SPL Token-2022 transfer fee withheld on a gross transfer of `amount`
 * using Token-2022's exact ceiling division (`feeBps / 10_000`, capped at `maxFee`).
 */
export function calculateTransferFee(amount: bigint, feeBps: number, maxFee: bigint): bigint {
  if (feeBps <= 0 || amount <= 0n) return 0n;
  const bps = BigInt(Math.min(Math.floor(feeBps), 10_000));
  const raw = bps === 10_000n ? amount : (amount * bps + 9_999n) / 10_000n;
  const capped = raw < maxFee ? raw : maxFee;
  return capped < amount ? capped : amount;
}

/**
 * Net amount credited to the Audren vault on a gross `Deposit` of `amount` for a Token-2022
 * mint with `TransferFeeConfig`.
 */
export function netDepositAmount(amount: bigint, feeBps: number, maxFee: bigint): bigint {
  return amount - calculateTransferFee(amount, feeBps, maxFee);
}

/** Encode Tag 10 (`CloseProofBuffer`, 1 byte) — reclaims 100% rent from an abandoned buffer. */
export function encodeCloseProofBufferData(): Uint8Array {
  return new Uint8Array([TAG_CLOSE_PROOF_BUFFER]);
}
