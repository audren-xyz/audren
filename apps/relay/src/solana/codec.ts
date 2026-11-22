import { buildCreateAtaIdempotentInstruction } from '@audren/sdk'
import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import type { SolanaAccountMeta, SolanaInstruction } from '../types'

// ============================================================================
// Byte, Base58, Base64, Integer & Hex Helpers
// ============================================================================

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const BASE58_MAP = new Int16Array(128).fill(-1)
for (let i = 0; i < BASE58_ALPHABET.length; i++) {
  BASE58_MAP[BASE58_ALPHABET.charCodeAt(i)] = i
}

export function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return ''
  let zeros = 0
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++
  if (zeros === bytes.length) return '1'.repeat(zeros)
  const digits: number[] = [0]
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i]!
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8
      digits[j] = carry % 58
      carry = (carry / 58) | 0
    }
    while (carry > 0) {
      digits.push(carry % 58)
      carry = (carry / 58) | 0
    }
  }
  let out = '1'.repeat(zeros)
  for (let i = digits.length - 1; i >= 0; i--) {
    out += BASE58_ALPHABET[digits[i]!]!
  }
  return out
}

export function base58Decode(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0)
  let zeros = 0
  while (zeros < str.length && str[zeros] === '1') zeros++
  const bytes: number[] = []
  for (let i = zeros; i < str.length; i++) {
    const code = str.charCodeAt(i)
    const val = code < 128 ? BASE58_MAP[code]! : -1
    if (val < 0) throw new Error(`Invalid base58 character at index ${i}`)
    let carry = val
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j]! * 58
      bytes[j] = carry & 0xff
      carry >>= 8
    }
    while (carry > 0) {
      bytes.push(carry & 0xff)
      carry >>= 8
    }
  }
  const out = new Uint8Array(zeros + bytes.length)
  for (let i = 0; i < bytes.length; i++) {
    out[zeros + i] = bytes[bytes.length - 1 - i]!
  }
  return out
}

export function toBase64(bytes: Uint8Array): string {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!)
  return btoa(bin)
}

export function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export function toHex(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i++) out += bytes[i]!.toString(16).padStart(2, '0')
  return out
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0
  for (const p of parts) total += p.length
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

export function u16le(n: number): Uint8Array {
  const b = new Uint8Array(2)
  b[0] = n & 0xff
  b[1] = (n >>> 8) & 0xff
  return b
}

export function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4)
  b[0] = n & 0xff
  b[1] = (n >>> 8) & 0xff
  b[2] = (n >>> 16) & 0xff
  b[3] = (n >>> 24) & 0xff
  return b
}

export function u64le(v: bigint): Uint8Array {
  const b = new Uint8Array(8)
  let x = v
  for (let i = 0; i < 8; i++) {
    b[i] = Number(x & 0xffn)
    x >>= 8n
  }
  return b
}

export function readU16le(buf: Uint8Array, offset: number): number {
  return buf[offset]! | (buf[offset + 1]! << 8)
}

export function readU32le(buf: Uint8Array, offset: number): number {
  return (
    (buf[offset]! |
      (buf[offset + 1]! << 8) |
      (buf[offset + 2]! << 16) |
      (buf[offset + 3]! << 24)) >>>
    0
  )
}

export function readU64le(buf: Uint8Array, offset: number): bigint {
  let v = 0n
  for (let i = 7; i >= 0; i--) {
    v = (v << 8n) | BigInt(buf[offset + i]!)
  }
  return v
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

export function isValidPubkey(raw: string): boolean {
  try {
    return base58Decode(raw).length === 32
  } catch {
    return false
  }
}

// ============================================================================
// Solana PDA Derivation (Ed25519 off-curve check)
// ============================================================================

const PDA_MARKER = utf8('ProgramDerivedAddress')

function isOnEd25519Curve(bytes: Uint8Array): boolean {
  try {
    ed25519.Point.fromBytes(bytes)
    return true
  } catch {
    return false
  }
}

export function findProgramAddressSync(
  seeds: Uint8Array[],
  programId: Uint8Array,
): { address: Uint8Array; bump: number } {
  for (let bump = 255; bump >= 0; bump--) {
    const hash = sha256(concatBytes(...seeds, new Uint8Array([bump]), programId, PDA_MARKER))
    if (!isOnEd25519Curve(hash)) {
      return { address: hash, bump }
    }
  }
  throw new Error('Unable to derive off-curve PDA')
}

// ============================================================================
// SPL Token & Associated Token Account Builders
// ============================================================================

export const SYSTEM_PROGRAM_ID_STR = '11111111111111111111111111111111'
export const SYSTEM_PROGRAM_ID = base58Decode(SYSTEM_PROGRAM_ID_STR)
export const CLASSIC_TOKEN_PROGRAM_ID_STR = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
export const CLASSIC_TOKEN_PROGRAM_ID = base58Decode(CLASSIC_TOKEN_PROGRAM_ID_STR)
export const TOKEN_2022_PROGRAM_ID_STR = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
export const TOKEN_2022_PROGRAM_ID = base58Decode(TOKEN_2022_PROGRAM_ID_STR)
export const ASSOCIATED_TOKEN_PROGRAM_ID_STR = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'
export const ASSOCIATED_TOKEN_PROGRAM_ID = base58Decode(ASSOCIATED_TOKEN_PROGRAM_ID_STR)

export const WSOL_MINT_STR = 'So11111111111111111111111111111111111111112'
export const WSOL_MINT = base58Decode(WSOL_MINT_STR)
export const USDC_MAINNET_MINT_STR = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'

export function deriveAta(
  owner: Uint8Array,
  tokenProgramId: Uint8Array,
  mint: Uint8Array,
): Uint8Array {
  return findProgramAddressSync([owner, tokenProgramId, mint], ASSOCIATED_TOKEN_PROGRAM_ID).address
}

export function buildCreateAtaIdempotentIx(params: {
  payer: Uint8Array
  ata: Uint8Array
  owner: Uint8Array
  mint: Uint8Array
  tokenProgram: Uint8Array
}): SolanaInstruction {
  const sdkIx = buildCreateAtaIdempotentInstruction({
    payer: base58Encode(params.payer),
    ata: base58Encode(params.ata),
    owner: base58Encode(params.owner),
    mint: base58Encode(params.mint),
    tokenProgram: base58Encode(params.tokenProgram),
  })
  return {
    programId: base58Decode(sdkIx.programId),
    accounts: sdkIx.accounts.map((a) => ({
      pubkey: base58Decode(a.pubkey),
      isSigner: a.isSigner,
      isWritable: a.isWritable,
    })),
    data: sdkIx.data,
  }
}

export function buildCloseTokenAccountIx(params: {
  account: Uint8Array
  destination: Uint8Array
  authority: Uint8Array
  tokenProgram?: Uint8Array
}): SolanaInstruction {
  return {
    programId: params.tokenProgram ?? CLASSIC_TOKEN_PROGRAM_ID,
    accounts: [
      { pubkey: params.account, isSigner: false, isWritable: true },
      { pubkey: params.destination, isSigner: false, isWritable: true },
      { pubkey: params.authority, isSigner: true, isWritable: false },
    ],
    data: new Uint8Array([9]), // SPL Token CloseAccount
  }
}

// ============================================================================
// Solana Transaction Version 1 (SIMD-0385 / 0x81) Single-Transaction Compiler
// Verified byte-for-byte against solana-core 4.4.0 (4,096 B / 64 accounts)
// ============================================================================

export const SOLANA_TX_V1_PREFIX = 0x81
export const SOLANA_TX_V1_MAX_SIZE = 4096
export const SOLANA_TX_V1_MAX_ACCOUNTS = 64
export const SOLANA_TX_V1_DEFAULT_LOADED_ACCOUNTS_DATA_SIZE = 64 * 1024 * 1024

const CONFIG_MASK_PRIORITY_FEE = 0b11
const CONFIG_MASK_COMPUTE_UNIT_LIMIT = 0b100
const CONFIG_MASK_LOADED_ACCOUNTS_DATA_SIZE = 0b1000
const CONFIG_MASK_HEAP_SIZE = 0b10000

export interface SolanaV1TxConfig {
  computeUnitLimit: number
  loadedAccountsDataSizeLimit?: number
  priorityFeeLamports?: bigint
  heapSize?: number
}

export function buildAndSignV1Transaction(
  feePayerSecret32: Uint8Array,
  recentBlockhashB58: string,
  instructions: SolanaInstruction[],
  config: SolanaV1TxConfig = {
    computeUnitLimit: 400_000,
    loadedAccountsDataSizeLimit: SOLANA_TX_V1_DEFAULT_LOADED_ACCOUNTS_DATA_SIZE,
  },
): {
  version: 1
  wireBytes: Uint8Array
  wireLen: number
  accountCount: number
  signatureB58: string
  feePayerPubkey: Uint8Array
} {
  const feePayerPubkey = ed25519.getPublicKey(feePayerSecret32)
  const recentBlockhash = base58Decode(recentBlockhashB58)
  if (recentBlockhash.length !== 32) throw new Error('Invalid recentBlockhash')
  if (instructions.length === 0 || instructions.length > 64) {
    throw new Error(`V1 transaction instruction count out of range: ${instructions.length}`)
  }

  const map = new Map<string, SolanaAccountMeta>()
  const addMeta = (m: SolanaAccountMeta) => {
    const k = toHex(m.pubkey)
    const prev = map.get(k)
    if (!prev) {
      map.set(k, { ...m })
    } else {
      prev.isSigner = prev.isSigner || m.isSigner
      prev.isWritable = prev.isWritable || m.isWritable
    }
  }

  addMeta({ pubkey: feePayerPubkey, isSigner: true, isWritable: true })
  for (const ix of instructions) {
    for (const acc of ix.accounts) addMeta(acc)
    addMeta({ pubkey: ix.programId, isSigner: false, isWritable: false })
  }

  const feeHex = toHex(feePayerPubkey)
  const metas = Array.from(map.values()).sort((a, b) => {
    const aIsFee = toHex(a.pubkey) === feeHex ? 0 : 1
    const bIsFee = toHex(b.pubkey) === feeHex ? 0 : 1
    if (aIsFee !== bIsFee) return aIsFee - bIsFee
    const rank = (m: SolanaAccountMeta) => (m.isSigner ? 0 : 2) + (m.isWritable ? 0 : 1)
    const diff = rank(a) - rank(b)
    if (diff !== 0) return diff
    return toHex(a.pubkey).localeCompare(toHex(b.pubkey))
  })

  if (metas.length > SOLANA_TX_V1_MAX_ACCOUNTS) {
    throw new Error(
      `V1 transaction address count ${metas.length} exceeds ${SOLANA_TX_V1_MAX_ACCOUNTS} (use direct routes)`,
    )
  }

  const numRequiredSignatures = metas.filter((m) => m.isSigner).length
  const numReadonlySigned = metas.filter((m) => m.isSigner && !m.isWritable).length
  const numReadonlyUnsigned = metas.filter((m) => !m.isSigner && !m.isWritable).length
  if (numRequiredSignatures !== 1) {
    throw new Error(`Expected exactly 1 signer (relayer), got ${numRequiredSignatures}`)
  }

  const indexByHex = new Map<string, number>()
  metas.forEach((m, idx) => indexByHex.set(toHex(m.pubkey), idx))

  let configMask = 0
  const configChunks: Uint8Array[] = []
  if (config.priorityFeeLamports !== undefined) {
    configMask |= CONFIG_MASK_PRIORITY_FEE
    configChunks.push(u64le(config.priorityFeeLamports))
  }
  configMask |= CONFIG_MASK_COMPUTE_UNIT_LIMIT
  configChunks.push(u32le(config.computeUnitLimit))

  const loadedLimit =
    config.loadedAccountsDataSizeLimit ?? SOLANA_TX_V1_DEFAULT_LOADED_ACCOUNTS_DATA_SIZE
  configMask |= CONFIG_MASK_LOADED_ACCOUNTS_DATA_SIZE
  configChunks.push(u32le(loadedLimit))

  if (config.heapSize !== undefined) {
    if (config.heapSize % 1024 !== 0 || config.heapSize < 32 * 1024 || config.heapSize > 256 * 1024) {
      throw new Error(`Invalid V1 heapSize: ${config.heapSize}`)
    }
    configMask |= CONFIG_MASK_HEAP_SIZE
    configChunks.push(u32le(config.heapSize))
  }

  const ixHeaders: Uint8Array[] = []
  const ixPayloads: Uint8Array[] = []
  for (const ix of instructions) {
    const programIdIndex = indexByHex.get(toHex(ix.programId))!
    if (programIdIndex === 0) throw new Error('Program ID cannot be fee payer')
    if (ix.accounts.length > 255) throw new Error(`Instruction account count ${ix.accounts.length} > 255`)
    if (ix.data.length > 65535) throw new Error(`Instruction data length ${ix.data.length} > 65535`)
    const accIndices = new Uint8Array(ix.accounts.map((a) => indexByHex.get(toHex(a.pubkey))!))
    ixHeaders.push(concatBytes(new Uint8Array([programIdIndex, accIndices.length]), u16le(ix.data.length)))
    ixPayloads.push(accIndices, ix.data)
  }

  const messageBytes = concatBytes(
    new Uint8Array([SOLANA_TX_V1_PREFIX]),
    new Uint8Array([numRequiredSignatures, numReadonlySigned, numReadonlyUnsigned]),
    u32le(configMask),
    recentBlockhash,
    new Uint8Array([instructions.length, metas.length]),
    ...metas.map((m) => m.pubkey),
    ...configChunks,
    ...ixHeaders,
    ...ixPayloads,
  )

  const signature = ed25519.sign(messageBytes, feePayerSecret32)
  const wireBytes = concatBytes(messageBytes, signature)
  if (wireBytes.length > SOLANA_TX_V1_MAX_SIZE) {
    throw new Error(`V1 transaction size ${wireBytes.length} B exceeds ${SOLANA_TX_V1_MAX_SIZE} B limit`)
  }

  return {
    version: 1,
    wireBytes,
    wireLen: wireBytes.length,
    accountCount: metas.length,
    signatureB58: base58Encode(signature),
    feePayerPubkey,
  }
}

export function decodeRelayerSecret(b64: string | null): Uint8Array | null {
  if (!b64) return null
  try {
    const raw = fromBase64(b64.trim())
    if (raw.length === 32) return raw
    if (raw.length === 64) return raw.subarray(0, 32)
    return null
  } catch {
    return null
  }
}

/** Read SPL Token / Token-2022 account amount (u64 LE at byte offset 64). */
export function readSplTokenAccountAmount(accountData: Uint8Array | null): bigint {
  if (!accountData || accountData.length < 72) return 0n
  return readU64le(accountData, 64)
}
