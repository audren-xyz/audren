// Canonical zero-WASM Audren cryptography, PDAs, layouts, CompactWalletStore, and Transaction v1.
import { base58Decode, type AudrenInstruction } from '@audren/sdk'

export * from '@audren/sdk'
export {
  buildDepositInstruction,
  buildTransactInstruction,
  buildUpdatePoolInstruction,
  computePageRollovers,
  computeToken2022NetAmount,
  computeTransactCtxHash,
  parseToken2022TransferFeeConfig,
  pickRandomEscrowShard,
  pickRandomLaneId,
  tryDecryptAndVerifyMemo,
} from '@audren/sdk'

const utf8Encoder = new TextEncoder()

export interface SolanaAccountMeta {
  pubkey: Uint8Array
  isSigner: boolean
  isWritable: boolean
}

export interface SolanaInstruction {
  programId: Uint8Array
  accounts: SolanaAccountMeta[]
  data: Uint8Array
}

export function audrenInstructionToSolana(ix: AudrenInstruction): SolanaInstruction {
  return {
    programId: base58Decode(ix.programId),
    accounts: ix.accounts.map((a) => ({
      pubkey: base58Decode(a.pubkey),
      isSigner: a.isSigner,
      isWritable: a.isWritable,
    })),
    data: ix.data,
  }
}

export function utf8(text: string): Uint8Array {
  return utf8Encoder.encode(text)
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let len = 0
  for (const p of parts) len += p.byteLength
  const out = new Uint8Array(len)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.byteLength
  }
  return out
}

export function u32le(n: number): Uint8Array {
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, n, true)
  return out
}

export function u64le(n: bigint): Uint8Array {
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigUint64(0, n, true)
  return out
}

export function toBase64(bytes: Uint8Array): string {
  let bin = ''
  for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]!)
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
  for (let i = 0; i < bytes.byteLength; i++) out += bytes[i]!.toString(16).padStart(2, '0')
  return out
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.trim().replace(/^0x/i, '')
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) throw new Error('Invalid hex')
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.byteLength; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false
  let diff = 0
  for (let i = 0; i < a.byteLength; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}
