/**
 * Zero-dependency Solana Transaction Version 1 (SIMD-0385 / `0x81`) compiler and wire serializer.
 *
 * Wire layout (`<= 4,096 B` total):
 *   wireBytes    = messageBytes || signatures (fixed-len `numRequiredSignatures * 64 B`, no short_vec)
 *   messageBytes = 0x81
 *                | header(3 B: numRequiredSignatures, numReadonlySigned, numReadonlyUnsigned)
 *                | configMask(u32 LE)
 *                | lifetimeSpecifier(recentBlockhash: 32 B)
 *                | numInstructions(u8) | numAddresses(u8)
 *                | accountKeys(numAddresses * 32 B)
 *                | configValues (bit order: priorityFee u64 LE, computeUnitLimit u32 LE,
 *                                loadedAccountsDataSizeLimit u32 LE, heapSize u32 LE)
 *                | instructionHeaders(numInstructions * 4 B: programIdx u8, numAccounts u8, dataLen u16 LE)
 *                | instructionPayloads(for each ix: accountIndices || data)
 *
 * Compute budget limits and priority fees are carried natively inside the v1 header
 * without separate `ComputeBudgetInstruction`s.
 */

export const SOLANA_TX_V1_PREFIX = 0x81;
export const SOLANA_TX_V1_MAX_SIZE = 4_096;
export const SOLANA_TX_V1_DEFAULT_LOADED_ACCOUNTS_DATA_SIZE = 64 * 1024 * 1024;

const CONFIG_MASK_PRIORITY_FEE = 0b11;
const CONFIG_MASK_COMPUTE_UNIT_LIMIT = 0b100;
const CONFIG_MASK_LOADED_ACCOUNTS_DATA_SIZE = 0b1000;
const CONFIG_MASK_HEAP_SIZE = 0b10000;

export interface V1AccountMeta {
  pubkey: Uint8Array; // 32 bytes
  isSigner: boolean;
  isWritable: boolean;
}

export interface V1Instruction {
  programId: Uint8Array; // 32 bytes
  accounts: V1AccountMeta[];
  data: Uint8Array;
}

export interface V1TransactionConfig {
  /** Required in Solana v1 (unset budgets 0 CU). */
  computeUnitLimit: number;
  /** Required in Solana v1 (unset budgets 0 bytes). Defaults to 64 MiB. */
  loadedAccountsDataSizeLimit?: number;
  /** Optional total priority fee in lamports (u64 LE). */
  priorityFeeLamports?: bigint;
  /** Optional heap size in bytes (multiple of 1024, 32 KiB..=256 KiB). */
  heapSize?: number;
}

export interface CompiledV1Message {
  messageBytes: Uint8Array;
  numRequiredSignatures: number;
  signerPubkeys: Uint8Array[];
}

const U64_MAX = 0xffff_ffff_ffff_ffffn;

function bytesToHex(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array)) {
    throw new RangeError(`Expected Uint8Array, got ${String(bytes)}`);
  }
  let out = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    out += bytes[i]!.toString(16).padStart(2, '0');
  }
  return out;
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) {
    if (!(c instanceof Uint8Array)) {
      throw new RangeError(`Expected Uint8Array chunk, got ${String(c)}`);
    }
    total += c.byteLength;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

function u16le(n: number): Uint8Array {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, n, true);
  return out;
}

function u32le(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, true);
  return out;
}

function u64le(n: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, n, true);
  return out;
}

/**
 * Compile instructions and inline `TransactionConfig` into the exact Solana Transaction v1
 * message byte buffer (`0x81...`) that signers sign with Ed25519.
 */
export function compileV1Message(params: {
  feePayer: Uint8Array;
  recentBlockhash: Uint8Array;
  instructions: V1Instruction[];
  config: V1TransactionConfig;
}): CompiledV1Message {
  if (!params || typeof params !== 'object') {
    throw new RangeError('compileV1Message params must be an object');
  }
  const { feePayer, recentBlockhash, instructions, config } = params;
  if (!(feePayer instanceof Uint8Array) || feePayer.byteLength !== 32) {
    throw new RangeError(
      `feePayer must be a 32-byte Uint8Array, got ${feePayer instanceof Uint8Array ? feePayer.byteLength : String(feePayer)}`,
    );
  }
  if (!(recentBlockhash instanceof Uint8Array) || recentBlockhash.byteLength !== 32) {
    throw new RangeError(
      `recentBlockhash must be a 32-byte Uint8Array, got ${recentBlockhash instanceof Uint8Array ? recentBlockhash.byteLength : String(recentBlockhash)}`,
    );
  }
  if (!Array.isArray(instructions) || instructions.length === 0 || instructions.length > 64) {
    throw new RangeError(
      `V1 instruction count must be 1..=64, got ${Array.isArray(instructions) ? instructions.length : String(instructions)}`,
    );
  }
  if (!config || typeof config !== 'object') {
    throw new RangeError('config must be an object');
  }

  const map = new Map<string, V1AccountMeta>();
  const addMeta = (m: V1AccountMeta) => {
    if (!m || typeof m !== 'object' || !(m.pubkey instanceof Uint8Array) || m.pubkey.byteLength !== 32) {
      throw new RangeError(
        `account pubkey must be a 32-byte Uint8Array, got ${m && m.pubkey instanceof Uint8Array ? m.pubkey.byteLength : String(m?.pubkey)}`,
      );
    }
    const k = bytesToHex(m.pubkey);
    const prev = map.get(k);
    if (!prev) {
      map.set(k, { pubkey: m.pubkey, isSigner: m.isSigner, isWritable: m.isWritable });
    } else {
      prev.isSigner = prev.isSigner || m.isSigner;
      prev.isWritable = prev.isWritable || m.isWritable;
    }
  };

  addMeta({ pubkey: feePayer, isSigner: true, isWritable: true });
  for (const ix of instructions) {
    if (!ix || typeof ix !== 'object' || !Array.isArray(ix.accounts)) {
      throw new RangeError('Each V1Instruction must be an object with an accounts array');
    }
    if (!(ix.programId instanceof Uint8Array) || ix.programId.byteLength !== 32) {
      throw new RangeError(
        `instruction programId must be a 32-byte Uint8Array, got ${ix.programId instanceof Uint8Array ? ix.programId.byteLength : String(ix.programId)}`,
      );
    }
    if (!(ix.data instanceof Uint8Array)) {
      throw new RangeError(`instruction data must be a Uint8Array, got ${String(ix.data)}`);
    }
    for (const acc of ix.accounts) addMeta(acc);
    addMeta({ pubkey: ix.programId, isSigner: false, isWritable: false });
  }

  const feeHex = bytesToHex(feePayer);
  const metas = Array.from(map.values()).sort((a, b) => {
    const aIsFee = bytesToHex(a.pubkey) === feeHex ? 0 : 1;
    const bIsFee = bytesToHex(b.pubkey) === feeHex ? 0 : 1;
    if (aIsFee !== bIsFee) return aIsFee - bIsFee;
    const rank = (m: V1AccountMeta) => (m.isSigner ? 0 : 2) + (m.isWritable ? 0 : 1);
    const diff = rank(a) - rank(b);
    if (diff !== 0) return diff;
    return bytesToHex(a.pubkey).localeCompare(bytesToHex(b.pubkey));
  });

  if (metas.length > 64) {
    throw new Error(`V1 address count ${metas.length} exceeds 64`);
  }

  const numRequiredSignatures = metas.filter((m) => m.isSigner).length;
  const numReadonlySigned = metas.filter((m) => m.isSigner && !m.isWritable).length;
  const numReadonlyUnsigned = metas.filter((m) => !m.isSigner && !m.isWritable).length;

  const indexByHex = new Map<string, number>();
  metas.forEach((m, idx) => indexByHex.set(bytesToHex(m.pubkey), idx));

  let configMask = 0;
  const configValues: Uint8Array[] = [];
  if (config.priorityFeeLamports !== undefined) {
    if (
      typeof config.priorityFeeLamports !== 'bigint' ||
      config.priorityFeeLamports < 0n ||
      config.priorityFeeLamports > U64_MAX
    ) {
      throw new RangeError(
        `Invalid priorityFeeLamports (must be u64 bigint): ${String(config.priorityFeeLamports)}`,
      );
    }
    configMask |= CONFIG_MASK_PRIORITY_FEE;
    configValues.push(u64le(config.priorityFeeLamports));
  }
  if (!Number.isInteger(config.computeUnitLimit) || config.computeUnitLimit < 0 || config.computeUnitLimit > 0xffff_ffff) {
    throw new RangeError(`Invalid computeUnitLimit (must be u32): ${config.computeUnitLimit}`);
  }
  configMask |= CONFIG_MASK_COMPUTE_UNIT_LIMIT;
  configValues.push(u32le(config.computeUnitLimit));

  const loadedLimit =
    config.loadedAccountsDataSizeLimit ?? SOLANA_TX_V1_DEFAULT_LOADED_ACCOUNTS_DATA_SIZE;
  if (!Number.isInteger(loadedLimit) || loadedLimit < 0 || loadedLimit > 0xffff_ffff) {
    throw new RangeError(`Invalid loadedAccountsDataSizeLimit (must be u32): ${loadedLimit}`);
  }
  configMask |= CONFIG_MASK_LOADED_ACCOUNTS_DATA_SIZE;
  configValues.push(u32le(loadedLimit));

  if (config.heapSize !== undefined) {
    if (
      !Number.isInteger(config.heapSize) ||
      config.heapSize % 1024 !== 0 ||
      config.heapSize < 32 * 1024 ||
      config.heapSize > 256 * 1024
    ) {
      throw new RangeError(`Invalid V1 heapSize: ${String(config.heapSize)}`);
    }
    configMask |= CONFIG_MASK_HEAP_SIZE;
    configValues.push(u32le(config.heapSize));
  }

  const ixHeaders: Uint8Array[] = [];
  const ixPayloads: Uint8Array[] = [];
  for (const ix of instructions) {
    const programIdIndex = indexByHex.get(bytesToHex(ix.programId))!;
    if (programIdIndex === 0) {
      throw new Error('Program ID cannot be fee payer in a V1 transaction');
    }
    if (ix.accounts.length > 255) {
      throw new Error(`Instruction account count ${ix.accounts.length} exceeds 255`);
    }
    if (ix.data.byteLength > 65_535) {
      throw new RangeError(`Instruction data length ${ix.data.byteLength} exceeds 65,535`);
    }
    const accIndices = new Uint8Array(ix.accounts.map((a) => indexByHex.get(bytesToHex(a.pubkey))!));
    ixHeaders.push(
      concatBytes(new Uint8Array([programIdIndex, accIndices.length]), u16le(ix.data.byteLength)),
    );
    ixPayloads.push(accIndices, ix.data);
  }

  const messageBytes = concatBytes(
    new Uint8Array([SOLANA_TX_V1_PREFIX]),
    new Uint8Array([numRequiredSignatures, numReadonlySigned, numReadonlyUnsigned]),
    u32le(configMask),
    recentBlockhash,
    new Uint8Array([instructions.length, metas.length]),
    ...metas.map((m) => m.pubkey),
    ...configValues,
    ...ixHeaders,
    ...ixPayloads,
  );

  const wireLen = messageBytes.byteLength + numRequiredSignatures * 64;
  if (wireLen > SOLANA_TX_V1_MAX_SIZE) {
    throw new Error(`Compiled V1 transaction size ${wireLen} B exceeds ${SOLANA_TX_V1_MAX_SIZE} B limit`);
  }

  return {
    messageBytes,
    numRequiredSignatures,
    signerPubkeys: metas.slice(0, numRequiredSignatures).map((m) => m.pubkey),
  };
}

/**
 * Assemble a finalized Solana Transaction v1 wire packet (`messageBytes || signatures`).
 * Each signature must be a 64-byte Ed25519 signature over `compiled.messageBytes`.
 */
export function serializeV1Transaction(
  compiled: CompiledV1Message,
  signatures: Uint8Array[],
): Uint8Array {
  if (!compiled || typeof compiled !== 'object') {
    throw new RangeError('compiled must be a CompiledV1Message object');
  }
  if (!(compiled.messageBytes instanceof Uint8Array)) {
    throw new RangeError(
      `compiled.messageBytes must be a Uint8Array, got ${String(compiled.messageBytes)}`,
    );
  }
  if (!Number.isInteger(compiled.numRequiredSignatures) || compiled.numRequiredSignatures < 0) {
    throw new RangeError(
      `compiled.numRequiredSignatures must be a non-negative integer, got ${String(compiled.numRequiredSignatures)}`,
    );
  }
  if (!Array.isArray(signatures)) {
    throw new RangeError('signatures must be an array of 64-byte Uint8Arrays');
  }
  if (signatures.length !== compiled.numRequiredSignatures) {
    throw new RangeError(
      `Expected ${compiled.numRequiredSignatures} signatures, got ${signatures.length}`,
    );
  }
  for (const sig of signatures) {
    if (!(sig instanceof Uint8Array) || sig.byteLength !== 64) {
      throw new RangeError(
        `Signature must be a 64-byte Uint8Array, got ${sig instanceof Uint8Array ? sig.byteLength : String(sig)}`,
      );
    }
  }
  const wireBytes = concatBytes(compiled.messageBytes, ...signatures);
  if (wireBytes.byteLength > SOLANA_TX_V1_MAX_SIZE) {
    throw new Error(`V1 transaction size ${wireBytes.byteLength} B exceeds ${SOLANA_TX_V1_MAX_SIZE} B limit`);
  }
  return wireBytes;
}
