import { ed25519, ristretto255 } from '@noble/curves/ed25519.js'

export const AUDREN_PROGRAM_ID_STR = 'AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3'
export const SYSTEM_PROGRAM_ID_STR = '11111111111111111111111111111111'

export const NATIVE_SOL_MINT = new Uint8Array(32)
export const PAGE_CAPACITY = 32
export const PAGE_LEN = 6240
export const PAGE_HEADER_LEN = 64
export const VIEW_TAGS_OFFSET = 64
export const EPH_PKS_OFFSET = 96
export const STEALTH_PKS_OFFSET = 1120
export const ASSET_TAGS_OFFSET = 2144
export const COMMITMENTS_OFFSET = 3168
export const CIPHERTEXTS_OFFSET = 4192
export const NOTE_CT_LEN = 64

// Ristretto255 prime group order L = 2^252 + 27742317777372353535851937790883648493
export const RISTRETTO_L =
  7237005577332262213973186563042994240857116359379907606001950938285454250989n
const L = RISTRETTO_L

// Solana ZK ElGamal Pedersen blinding base H = HashToRistretto(Sha3_512(G))
export const PEDERSEN_H_BYTES = new Uint8Array([
  140, 146, 64, 180, 86, 169, 230, 220, 101, 195, 119, 161, 4, 141, 116, 95,
  148, 160, 140, 219, 127, 68, 203, 205, 123, 70, 243, 64, 72, 135, 17, 52,
])
const PAGE_MAGIC_BYTES = new TextEncoder().encode('AUDRNPG1')

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const B58_MAP = new Map<string, number>(
  Array.from(B58_ALPHABET).map((ch, idx) => [ch, idx]),
)

const encoder = new TextEncoder()
const decoder = new TextDecoder()

export function utf8(s: string): Uint8Array {
  return encoder.encode(s)
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((acc, p) => acc + p.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.trim().toLowerCase()
  if (clean.length % 2 !== 0 || !/^[0-9a-f]*$/.test(clean)) {
    throw new Error('Invalid hex string')
  }
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

export function toBase64(bytes: Uint8Array): string {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin)
}

export function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return ''
  let zeros = 0
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++
  let value = 0n
  for (const b of bytes) value = (value << 8n) | BigInt(b)
  const chars: string[] = []
  while (value > 0n) {
    const rem = Number(value % 58n)
    value /= 58n
    chars.push(B58_ALPHABET[rem])
  }
  for (let i = 0; i < zeros; i++) chars.push('1')
  return chars.reverse().join('')
}

export function base58Decode(str: string): Uint8Array {
  if (!str) return new Uint8Array(0)
  let zeros = 0
  while (zeros < str.length && str[zeros] === '1') zeros++
  let value = 0n
  for (let i = 0; i < str.length; i++) {
    const digit = B58_MAP.get(str[i])
    if (digit === undefined) throw new Error(`Invalid base58 char: ${str[i]}`)
    value = value * 58n + BigInt(digit)
  }
  const rev: number[] = []
  while (value > 0n) {
    rev.push(Number(value & 0xffn))
    value >>= 8n
  }
  const out = new Uint8Array(zeros + rev.length)
  for (let i = 0; i < rev.length; i++) {
    out[zeros + i] = rev[rev.length - 1 - i]
  }
  return out
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

export function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, n, true)
  return b
}

export function u64le(n: bigint): Uint8Array {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, n, true)
  return b
}

export function readU32le(bytes: Uint8Array, off: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset + off, 4).getUint32(0, true)
}

export function readU64le(bytes: Uint8Array, off: number): bigint {
  return new DataView(bytes.buffer, bytes.byteOffset + off, 8).getBigUint64(0, true)
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return copy.buffer
}

export async function sha256(...chunks: Uint8Array[]): Promise<Uint8Array> {
  const merged = concatBytes(...chunks)
  const digest = await crypto.subtle.digest('SHA-256', toArrayBuffer(merged))
  return new Uint8Array(digest)
}

async function hkdfExpand(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', toArrayBuffer(ikm), 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: toArrayBuffer(salt),
      info: toArrayBuffer(info),
    },
    key,
    length * 8,
  )
  return new Uint8Array(bits)
}

export function scalarFromWideLE(bytes64: Uint8Array): bigint {
  let acc = 0n
  for (let i = bytes64.length - 1; i >= 0; i--) {
    acc = (acc << 8n) | BigInt(bytes64[i])
  }
  return acc % L
}

export function scalarToBytes32LE(s: bigint): Uint8Array {
  let v = ((s % L) + L) % L
  const out = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

export type RistrettoPoint = ReturnType<typeof ristretto255.Point.fromBytes>

export function mulRistretto(pt: RistrettoPoint, scalar: bigint): RistrettoPoint {
  const norm = ((scalar % L) + L) % L
  if (norm === 0n) return ristretto255.Point.ZERO
  return pt.multiply(norm)
}

export async function hkdfExpandBytes(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  return hkdfExpand(ikm, salt, info, length)
}

export function isValidRistrettoPoint(bytes: Uint8Array): boolean {
  if (bytes.length !== 32) return false
  try {
    ristretto255.Point.fromBytes(bytes)
    return true
  } catch {
    return false
  }
}

export function isNonZeroPoint(bytes: Uint8Array): boolean {
  return bytes.some((b) => b !== 0) && isValidRistrettoPoint(bytes)
}

export async function hashToScalar(slices: Uint8Array[]): Promise<bigint> {
  const h0 = await sha256(utf8('audren/v1/fs/0'), ...slices)
  const h1 = await sha256(utf8('audren/v1/fs/1'), ...slices)
  return scalarFromWideLE(concatBytes(h0, h1))
}

export async function hashToPoint(domain: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  for (let ctr = 0; ctr < 10_000; ctr++) {
    const cand = await sha256(domain, data, u32le(ctr))
    cand[0] &= 0xfe
    cand[31] &= 0x7f
    if (isNonZeroPoint(cand)) return cand
  }
  throw new Error('hashToPoint failed to converge')
}

export async function assetGenerator(mintBytes: Uint8Array = NATIVE_SOL_MINT): Promise<Uint8Array> {
  return hashToPoint(utf8('audren/v1/mint'), mintBytes)
}

// ============================================================================
// Solana PDA Derivation (exact match to Pubkey::find_program_address)
// ============================================================================

function isOnEd25519Curve(bytes: Uint8Array): boolean {
  try {
    ed25519.Point.fromBytes(bytes)
    return true
  } catch {
    return false
  }
}

export async function findProgramAddress(
  seeds: Uint8Array[],
  programId: Uint8Array,
): Promise<{ address: Uint8Array; bump: number }> {
  const marker = utf8('ProgramDerivedAddress')
  for (let bump = 255; bump >= 0; bump--) {
    const candidate = await sha256(...seeds, new Uint8Array([bump]), programId, marker)
    if (!isOnEd25519Curve(candidate)) {
      return { address: candidate, bump }
    }
  }
  throw new Error('Unable to find viable PDA bump')
}

export const AUDREN_PROGRAM_ID = base58Decode(AUDREN_PROGRAM_ID_STR)
export const SYSTEM_PROGRAM_ID = new Uint8Array(32)

export async function derivePoolPda(poolId = 0) {
  return findProgramAddress([utf8('audren_pool'), u32le(poolId)], AUDREN_PROGRAM_ID)
}

export async function deriveEpochPagePda(poolId: number, pageId: bigint) {
  return findProgramAddress([utf8('audren_page'), u32le(poolId), u64le(pageId)], AUDREN_PROGRAM_ID)
}

export async function deriveSolVaultPda(poolId = 0) {
  return findProgramAddress([utf8('audren_sol'), u32le(poolId)], AUDREN_PROGRAM_ID)
}

export async function derivePageRentVaultPda(poolId = 0) {
  return findProgramAddress([utf8('audren_rent'), u32le(poolId)], AUDREN_PROGRAM_ID)
}

// ============================================================================
// Audren Stealth Keypair, Note Encryption, Scanning & Selective Disclosure
// ============================================================================

export interface AudrenKeypair {
  seedHex: string
  spendSk: bigint
  spendPk: Uint8Array
  viewSk: bigint
  viewPk: Uint8Array
  address: string
  viewingKeyB58: string
}

export async function generateAudrenKeys(seedInput?: Uint8Array): Promise<AudrenKeypair> {
  const seed = seedInput ?? crypto.getRandomValues(new Uint8Array(32))
  const spendWide = await hkdfExpand(seed, utf8('audren/v1/root'), utf8('audren/v1/spend_sk'), 64)
  const viewWide = await hkdfExpand(seed, utf8('audren/v1/root'), utf8('audren/v1/view_sk'), 64)
  const spendSk = scalarFromWideLE(spendWide)
  const viewSk = scalarFromWideLE(viewWide)
  const spendPk = mulRistretto(ristretto255.Point.BASE, spendSk).toBytes()
  const viewPk = mulRistretto(ristretto255.Point.BASE, viewSk).toBytes()
  const address = `aud1${base58Encode(concatBytes(spendPk, viewPk))}`
  const viewingKeyB58 = base58Encode(scalarToBytes32LE(viewSk))
  return {
    seedHex: toHex(seed),
    spendSk,
    spendPk,
    viewSk,
    viewPk,
    address,
    viewingKeyB58,
  }
}

export interface StealthMaterial {
  ephemeralPk: Uint8Array
  stealthPk: Uint8Array
  viewTag: number
  aesKey: Uint8Array
  aesNonce: Uint8Array
}

async function deriveStealthFromShared(
  recipientSpendPk: Uint8Array,
  ephemeralPk: Uint8Array,
  sharedBytes: Uint8Array,
): Promise<StealthMaterial> {
  const vtHash = await sha256(utf8('audren/v1/view_tag'), sharedBytes)
  const viewTag = vtHash[0]
  const stealthScalar = await hashToScalar([utf8('audren/v1/stealth_x'), sharedBytes])
  const spendPt = ristretto255.Point.fromBytes(recipientSpendPk)
  const stealthPk = spendPt.add(mulRistretto(ristretto255.Point.BASE, stealthScalar)).toBytes()

  const aesKey = await hkdfExpand(sharedBytes, utf8('audren/v1/note_kdf'), utf8('aes256gcm_key'), 32)
  const aesNonce = await hkdfExpand(sharedBytes, utf8('audren/v1/note_kdf'), utf8('aes256gcm_nonce'), 12)
  return { ephemeralPk, stealthPk, viewTag, aesKey, aesNonce }
}

export interface PreparedDepositNote {
  viewTag: number
  ephemeralPk: Uint8Array
  stealthPk: Uint8Array
  ciphertext: Uint8Array
  expectedAssetTag: Uint8Array
  expectedCommitment: Uint8Array
  amountLamports: bigint
  memoText: string
}

export async function prepareSolDepositNote(
  recipientSpendPk: Uint8Array,
  recipientViewPk: Uint8Array,
  amountLamports: bigint,
  memoText: string,
): Promise<PreparedDepositNote> {
  const randWide = crypto.getRandomValues(new Uint8Array(64))
  const rEph = scalarFromWideLE(randWide) || 1n
  const ephemeralPk = mulRistretto(ristretto255.Point.BASE, rEph).toBytes()
  const viewPt = ristretto255.Point.fromBytes(recipientViewPk)
  const sharedBytes = mulRistretto(viewPt, rEph).toBytes()

  const mat = await deriveStealthFromShared(recipientSpendPk, ephemeralPk, sharedBytes)

  const plaintext = new Uint8Array(48)
  plaintext.set(NATIVE_SOL_MINT, 0)
  plaintext.set(u64le(amountLamports), 32)
  plaintext[40] = 0 // unblinded Deposit note (flags = 0)
  const memoBytes = utf8(memoText.trim()).slice(0, 7)
  plaintext.set(memoBytes, 41)

  const key = await crypto.subtle.importKey('raw', toArrayBuffer(mat.aesKey), 'AES-GCM', false, ['encrypt'])
  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(mat.aesNonce),
      additionalData: toArrayBuffer(mat.stealthPk),
    },
    key,
    toArrayBuffer(plaintext),
  )
  const ciphertext = new Uint8Array(encrypted)
  if (ciphertext.length !== NOTE_CT_LEN) {
    throw new Error(`Unexpected ciphertext length ${ciphertext.length}`)
  }

  const gSol = await assetGenerator(NATIVE_SOL_MINT)
  const commitment = mulRistretto(ristretto255.Point.fromBytes(gSol), amountLamports).toBytes()

  return {
    viewTag: mat.viewTag,
    ephemeralPk: mat.ephemeralPk,
    stealthPk: mat.stealthPk,
    ciphertext,
    expectedAssetTag: gSol,
    expectedCommitment: commitment,
    amountLamports,
    memoText: decoder.decode(memoBytes).replace(/\0+$/, ''),
  }
}

export interface OnChainNoteSummary {
  slotIndex: number
  viewTag: number
  ephemeralPk: Uint8Array
  stealthPk: Uint8Array
  assetTag: Uint8Array
  commitment: Uint8Array
  ciphertext: Uint8Array
}

export interface DecryptedAudrenNote {
  pageId: bigint
  slotIndex: number
  mint: Uint8Array
  amountLamports: bigint
  memoText: string
  stealthPk: Uint8Array
  assetTag: Uint8Array
  commitment: Uint8Array
  commitmentVerified: boolean
}

export function decodeEpochPageHeader(pageBytes: Uint8Array) {
  if (pageBytes.length < PAGE_HEADER_LEN) throw new Error('EpochPage too small')
  const magic = decoder.decode(pageBytes.slice(0, 8))
  const version = pageBytes[8]
  const bump = pageBytes[9]
  const closed = pageBytes[10] !== 0
  const count = pageBytes[11]
  const poolId = readU32le(pageBytes, 12)
  const pageId = readU64le(pageBytes, 16)
  return { magic, version, bump, closed, count, poolId, pageId }
}

export function extractEpochPageNotes(pageBytes: Uint8Array): OnChainNoteSummary[] {
  const hdr = decodeEpochPageHeader(pageBytes)
  const notes: OnChainNoteSummary[] = []
  for (let i = 0; i < Math.min(hdr.count, PAGE_CAPACITY); i++) {
    notes.push({
      slotIndex: i,
      viewTag: pageBytes[VIEW_TAGS_OFFSET + i],
      ephemeralPk: pageBytes.slice(EPH_PKS_OFFSET + i * 32, EPH_PKS_OFFSET + (i + 1) * 32),
      stealthPk: pageBytes.slice(STEALTH_PKS_OFFSET + i * 32, STEALTH_PKS_OFFSET + (i + 1) * 32),
      assetTag: pageBytes.slice(ASSET_TAGS_OFFSET + i * 32, ASSET_TAGS_OFFSET + (i + 1) * 32),
      commitment: pageBytes.slice(COMMITMENTS_OFFSET + i * 32, COMMITMENTS_OFFSET + (i + 1) * 32),
      ciphertext: pageBytes.slice(CIPHERTEXTS_OFFSET + i * NOTE_CT_LEN, CIPHERTEXTS_OFFSET + (i + 1) * NOTE_CT_LEN),
    })
  }
  return notes
}

export async function scanEpochPageForOwner(
  keys: Pick<AudrenKeypair, 'spendPk' | 'viewSk'>,
  pageBytes: Uint8Array,
): Promise<{
  scannedCount: number
  viewTagMatches: number
  ownedNotes: DecryptedAudrenNote[]
}> {
  const hdr = decodeEpochPageHeader(pageBytes)
  const notes = extractEpochPageNotes(pageBytes)
  const ownedNotes: DecryptedAudrenNote[] = []
  let viewTagMatches = 0

  for (const n of notes) {
    if (!isNonZeroPoint(n.ephemeralPk)) continue
    const ephPt = ristretto255.Point.fromBytes(n.ephemeralPk)
    const sharedBytes = mulRistretto(ephPt, keys.viewSk).toBytes()
    const expectedTag = (await sha256(utf8('audren/v1/view_tag'), sharedBytes))[0]
    if (expectedTag !== n.viewTag) continue
    viewTagMatches++

    const mat = await deriveStealthFromShared(keys.spendPk, n.ephemeralPk, sharedBytes)
    if (!bytesEqual(mat.stealthPk, n.stealthPk)) continue

    try {
      const key = await crypto.subtle.importKey('raw', toArrayBuffer(mat.aesKey), 'AES-GCM', false, ['decrypt'])
      const plainBuf = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: toArrayBuffer(mat.aesNonce),
          additionalData: toArrayBuffer(n.stealthPk),
        },
        key,
        toArrayBuffer(n.ciphertext),
      )
      const pt = new Uint8Array(plainBuf)
      if (pt.length !== 48) continue
      const mint = pt.slice(0, 32)
      const amountLamports = readU64le(pt, 32)
      const memoRaw = pt.slice(41, 48)
      const memoText = decoder.decode(memoRaw).replace(/\0+$/, '')

      const gMint = await assetGenerator(mint)
      const expectedV = mulRistretto(ristretto255.Point.fromBytes(gMint), amountLamports).toBytes()
      const commitmentVerified = bytesEqual(n.assetTag, gMint) && bytesEqual(n.commitment, expectedV)

      ownedNotes.push({
        pageId: hdr.pageId,
        slotIndex: n.slotIndex,
        mint,
        amountLamports,
        memoText,
        stealthPk: n.stealthPk,
        assetTag: n.assetTag,
        commitment: n.commitment,
        commitmentVerified,
      })
    } catch {
      // Tag collided on another user's note (1/256 rate); ignore cleanly.
    }
  }

  return {
    scannedCount: notes.length,
    viewTagMatches,
    ownedNotes,
  }
}

export interface SelectiveDisclosureReceipt {
  version: 1
  cluster: 'devnet' | 'mainnet'
  programId: string
  pageId: string
  slotIndex: number
  signature: string
  stealthPk: string
  assetTag: string
  commitment: string
  mint: string
  assetSymbol: string
  amountLamports: string
  amountSol: string
  assetBlinding: string
  valueBlinding: string
}

export function buildSelectiveDisclosureReceipt(
  note: DecryptedAudrenNote & {
    assetBlinding?: bigint
    valueBlinding?: bigint
  },
  signature: string,
  options?: {
    cluster?: 'devnet' | 'mainnet'
    assetSymbol?: string
    decimals?: number
  },
): SelectiveDisclosureReceipt {
  const isSol = bytesEqual(note.mint, NATIVE_SOL_MINT)
  const decimals = options?.decimals ?? (isSol ? 9 : 6)
  const assetBlinding = note.assetBlinding
    ? scalarToBytes32LE(note.assetBlinding)
    : new Uint8Array(32)
  const valueBlinding = note.valueBlinding
    ? scalarToBytes32LE(note.valueBlinding)
    : new Uint8Array(32)
  return {
    version: 1,
    cluster: options?.cluster ?? 'devnet',
    programId: AUDREN_PROGRAM_ID_STR,
    pageId: note.pageId.toString(),
    slotIndex: note.slotIndex,
    signature,
    stealthPk: base58Encode(note.stealthPk),
    assetTag: base58Encode(note.assetTag),
    commitment: base58Encode(note.commitment),
    mint: isSol ? 'Native SOL (11111111111111111111111111111111)' : base58Encode(note.mint),
    assetSymbol: options?.assetSymbol ?? (isSol ? 'SOL' : 'SPL'),
    amountLamports: note.amountLamports.toString(),
    amountSol: (Number(note.amountLamports) / 10 ** decimals).toFixed(4),
    assetBlinding: base58Encode(assetBlinding),
    valueBlinding: base58Encode(valueBlinding),
  }
}

function decodeCanonicalScalar32(b58: string, label: string): bigint {
  const raw = base58Decode(b58)
  if (raw.length !== 32) throw new Error(`${label} must be 32 bytes`)
  let value = 0n
  for (let i = 31; i >= 0; i--) value = (value << 8n) | BigInt(raw[i])
  if (value >= RISTRETTO_L) throw new Error(`${label} is non-canonical`)
  return value
}

const MAX_SAFE_U64 = BigInt(Number.MAX_SAFE_INTEGER)

function encodeSafeU64Json(v: bigint | number | string): number | string {
  const bi = typeof v === 'bigint' ? v : BigInt(v)
  return bi >= 0n && bi <= MAX_SAFE_U64 ? Number(bi) : bi.toString()
}

function formatLamportsAsSol(raw: bigint | number | string): string {
  const bi = typeof raw === 'bigint' ? raw : BigInt(raw)
  const neg = bi < 0n ? '-' : ''
  const abs = bi < 0n ? -bi : bi
  const whole = abs / 1_000_000_000n
  const frac4 = ((abs % 1_000_000_000n) * 10_000n + 500_000_000n) / 1_000_000_000n
  if (frac4 >= 10_000n) {
    return `${neg}${(whole + 1n).toString()}.0000`
  }
  return `${neg}${whole.toString()}.${frac4.toString().padStart(4, '0')}`
}

/**
 * Canonical cross-language Mode 1 Selective Disclosure Proof (matches Rust
 * `SelectiveDisclosureProof`, Swift `FfiSelectiveDisclosureProof`, and Kotlin).
 *
 * `page_id` and `amount` are emitted as exact JSON `number` when `<= Number.MAX_SAFE_INTEGER`
 * and as lossless base-10 `string` when `> Number.MAX_SAFE_INTEGER` (e.g. parallel append
 * lanes `1..=15` where `page_id = (lane_id << 56) | seq`).
 */
export interface SelectiveDisclosureProof {
  version: number
  page_id: number | bigint | string
  slot_index: number
  stealth_pk_b58: string
  asset_tag_b58: string
  commitment_b58: string
  mint_b58: string
  amount: number | bigint | string
  asset_blinding_b58: string
  value_blinding_b58: string
}

export function createSelectiveDisclosureProof(note: {
  pageId: bigint | number | string
  slotIndex: number
  stealthPk: Uint8Array
  assetTag: Uint8Array
  commitment: Uint8Array
  mint: Uint8Array
  amount?: bigint | number | string
  amountLamports?: bigint | number | string
  assetBlinding?: bigint
  valueBlinding?: bigint
}): SelectiveDisclosureProof {
  const amt = note.amount ?? note.amountLamports ?? 0n
  const aBlind = note.assetBlinding
    ? scalarToBytes32LE(note.assetBlinding)
    : new Uint8Array(32)
  const vBlind = note.valueBlinding
    ? scalarToBytes32LE(note.valueBlinding)
    : new Uint8Array(32)
  return {
    version: 1,
    page_id: encodeSafeU64Json(note.pageId),
    slot_index: note.slotIndex,
    stealth_pk_b58: base58Encode(note.stealthPk),
    asset_tag_b58: base58Encode(note.assetTag),
    commitment_b58: base58Encode(note.commitment),
    mint_b58: base58Encode(note.mint),
    amount: encodeSafeU64Json(amt),
    asset_blinding_b58: base58Encode(aBlind),
    value_blinding_b58: base58Encode(vBlind),
  }
}

function normalizeDisclosureInput(
  input: SelectiveDisclosureReceipt | SelectiveDisclosureProof,
): SelectiveDisclosureReceipt {
  if ('stealth_pk_b58' in input) {
    return {
      version: 1,
      cluster: 'mainnet',
      programId: AUDREN_PROGRAM_ID_STR,
      pageId: BigInt(input.page_id).toString(),
      slotIndex: input.slot_index,
      signature: '',
      stealthPk: input.stealth_pk_b58,
      assetTag: input.asset_tag_b58,
      commitment: input.commitment_b58,
      mint: input.mint_b58,
      assetSymbol: input.mint_b58 === SYSTEM_PROGRAM_ID_STR ? 'SOL' : 'SPL',
      amountLamports: BigInt(input.amount).toString(),
      amountSol: formatLamportsAsSol(input.amount),
      assetBlinding: input.asset_blinding_b58,
      valueBlinding: input.value_blinding_b58,
    }
  }
  return input
}

export async function verifySelectiveDisclosureReceipt(
  input: SelectiveDisclosureReceipt | SelectiveDisclosureProof,
): Promise<{ valid: boolean; reason: string }> {
  const receipt = normalizeDisclosureInput(input)
  try {
    const mintBytes = receipt.mint.startsWith('Native SOL')
      ? NATIVE_SOL_MINT
      : base58Decode(receipt.mint)
    const amount = BigInt(receipt.amountLamports)
    if (amount < 0n || amount > 0xffff_ffff_ffff_ffffn) {
      return { valid: false, reason: 'Amount out of u64 range' }
    }
    const assetTag = base58Decode(receipt.assetTag)
    const commitment = base58Decode(receipt.commitment)
    const aBlind = decodeCanonicalScalar32(receipt.assetBlinding, 'assetBlinding')
    const vBlind = decodeCanonicalScalar32(receipt.valueBlinding, 'valueBlinding')

    const gMint = ristretto255.Point.fromBytes(await assetGenerator(mintBytes))
    const hPt = ristretto255.Point.fromBytes(PEDERSEN_H_BYTES)
    const expectedA =
      aBlind === 0n ? gMint : gMint.add(mulRistretto(hPt, aBlind))
    if (!bytesEqual(assetTag, expectedA.toBytes())) {
      return { valid: false, reason: 'Asset tag T does not match G_mint + r_a * H' }
    }
    const vBase = mulRistretto(expectedA, amount)
    const expectedV =
      vBlind === 0n ? vBase : vBase.add(mulRistretto(hPt, vBlind))
    if (!bytesEqual(commitment, expectedV.toBytes())) {
      return { valid: false, reason: 'Commitment V does not match amount * T + r_v * H' }
    }
    return {
      valid: true,
      reason: `Cryptographically verified Pedersen opening: ${receipt.amountSol} ${receipt.assetSymbol} (note on EpochPage #${receipt.pageId} slot #${receipt.slotIndex}).`,
    }
  } catch (e) {
    return { valid: false, reason: e instanceof Error ? e.message : 'Verification error' }
  }
}

/**
 * Full on-chain Selective Disclosure verifier: verifies BOTH the cryptographic
 * Pedersen opening AND exact inclusion inside an authentic on-chain `EpochPage`
 * account (`page_id`, `slotIndex < count`, `stealthPk`, `assetTag`, `commitment`).
 */
export async function verifySelectiveDisclosureOnPage(
  input: SelectiveDisclosureReceipt | SelectiveDisclosureProof,
  pageBytes: Uint8Array,
): Promise<{ valid: boolean; reason: string }> {
  const receipt = normalizeDisclosureInput(input)
  const cryptoCheck = await verifySelectiveDisclosureReceipt(receipt)
  if (!cryptoCheck.valid) return cryptoCheck
  if (pageBytes.length < PAGE_LEN) {
    return { valid: false, reason: `EpochPage too short (${pageBytes.length} < ${PAGE_LEN} B)` }
  }
  for (let i = 0; i < 8; i++) {
    if (pageBytes[i] !== PAGE_MAGIC_BYTES[i]) {
      return { valid: false, reason: 'Invalid EpochPage magic header' }
    }
  }
  const hdr = decodeEpochPageHeader(pageBytes)
  if (hdr.pageId.toString() !== receipt.pageId) {
    return {
      valid: false,
      reason: `EpochPage ID mismatch (on-chain ${hdr.pageId.toString()} != receipt ${receipt.pageId})`,
    }
  }
  if (!Number.isInteger(receipt.slotIndex) || receipt.slotIndex < 0 || receipt.slotIndex >= hdr.count) {
    return {
      valid: false,
      reason: `Slot index #${receipt.slotIndex} out of bounds (page has ${hdr.count} notes)`,
    }
  }
  const slot = receipt.slotIndex
  const onStealthPk = pageBytes.subarray(STEALTH_PKS_OFFSET + slot * 32, STEALTH_PKS_OFFSET + (slot + 1) * 32)
  const onAssetTag = pageBytes.subarray(ASSET_TAGS_OFFSET + slot * 32, ASSET_TAGS_OFFSET + (slot + 1) * 32)
  const onCommitment = pageBytes.subarray(COMMITMENTS_OFFSET + slot * 32, COMMITMENTS_OFFSET + (slot + 1) * 32)
  const claimStealthPk = base58Decode(receipt.stealthPk)
  const claimAssetTag = base58Decode(receipt.assetTag)
  const claimCommitment = base58Decode(receipt.commitment)
  if (
    !bytesEqual(onStealthPk, claimStealthPk) ||
    !bytesEqual(onAssetTag, claimAssetTag) ||
    !bytesEqual(onCommitment, claimCommitment)
  ) {
    return {
      valid: false,
      reason: `Receipt points do not match on-chain EpochPage #${receipt.pageId} slot #${slot}`,
    }
  }
  return {
    valid: true,
    reason: `Cryptographically AND on-chain verified: ${receipt.amountSol} ${receipt.assetSymbol} confirmed at EpochPage #${receipt.pageId} slot #${slot}.`,
  }
}

// ============================================================================
// Solana Transaction Version 1 (SIMD-0385 / TxV1) Serializer & Ed25519 Signer
// Exact wire format verified against solana-message 5.1.0 & solana-transaction 5.1.0:
//   wireBytes = messageBytes (starts with 0x81) || signatures (fixed-len, no short_vec)
//   max wireBytes = 4,096 bytes; compute budget carried inline in v1 message header.
// ============================================================================

export const SOLANA_TX_V1_PREFIX = 0x81
export const SOLANA_TX_V1_MAX_SIZE = 4096
export const SOLANA_TX_V1_DEFAULT_LOADED_ACCOUNTS_DATA_SIZE = 64 * 1024 * 1024

const CONFIG_MASK_PRIORITY_FEE = 0b11
const CONFIG_MASK_COMPUTE_UNIT_LIMIT = 0b100
const CONFIG_MASK_LOADED_ACCOUNTS_DATA_SIZE = 0b1000
const CONFIG_MASK_HEAP_SIZE = 0b10000

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

export interface SolanaV1TxConfig {
  /** Carried inline in the v1 header. Required — unset budgets 0 CU in v1. */
  computeUnitLimit: number
  /** Carried inline in the v1 header. Required — unset budgets 0 bytes in v1. */
  loadedAccountsDataSizeLimit?: number
  /** Optional total priority fee in lamports (u64 LE). */
  priorityFeeLamports?: bigint
  /** Optional heap size in bytes (multiple of 1024, 32 KiB..=256 KiB). */
  heapSize?: number
}

function u16le(n: number): Uint8Array {
  const b = new Uint8Array(2)
  b[0] = n & 0xff
  b[1] = (n >>> 8) & 0xff
  return b
}

export function buildAndSignV1Transaction(
  feePayerSecret32: Uint8Array,
  recentBlockhashB58: string,
  instructions: SolanaInstruction[],
  config: SolanaV1TxConfig = {
    computeUnitLimit: 200_000,
    loadedAccountsDataSizeLimit: SOLANA_TX_V1_DEFAULT_LOADED_ACCOUNTS_DATA_SIZE,
  },
): {
  version: 1
  wireBytes: Uint8Array
  wireLen: number
  signatureB58: string
  feePayerPubkey: Uint8Array
} {
  const feePayerPubkey = ed25519.getPublicKey(feePayerSecret32)
  const recentBlockhash = base58Decode(recentBlockhashB58)
  if (recentBlockhash.length !== 32) throw new Error('Invalid recentBlockhash')
  if (instructions.length === 0 || instructions.length > 64) {
    throw new Error(`V1 transaction instruction count out of range: ${instructions.length}`)
  }

  // Aggregate unique account keys with highest signer/writable privileges.
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

  // Canonical Solana account ordering:
  // 1. writable signers (fee payer first)
  // 2. readonly signers
  // 3. writable non-signers
  // 4. readonly non-signers
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

  if (metas.length > 64) {
    throw new Error(`V1 transaction address count ${metas.length} exceeds 64`)
  }

  const numRequiredSignatures = metas.filter((m) => m.isSigner).length
  const numReadonlySigned = metas.filter((m) => m.isSigner && !m.isWritable).length
  const numReadonlyUnsigned = metas.filter((m) => !m.isSigner && !m.isWritable).length

  if (numRequiredSignatures !== 1) {
    throw new Error(`Expected 1 signer, got ${numRequiredSignatures}`)
  }

  const indexByHex = new Map<string, number>()
  metas.forEach((m, idx) => indexByHex.set(toHex(m.pubkey), idx))

  // Build TransactionConfigMask and ordered ConfigValues (priority_fee, cu_limit, loaded_data, heap_size)
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
    if (programIdIndex === 0) {
      throw new Error('Program ID cannot be fee payer in V1 transaction')
    }
    if (ix.accounts.length > 255) {
      throw new Error(`Instruction account count ${ix.accounts.length} exceeds 255`)
    }
    if (ix.data.length > 65535) {
      throw new Error(`Instruction data length ${ix.data.length} exceeds 65535`)
    }
    const accIndices = new Uint8Array(ix.accounts.map((a) => indexByHex.get(toHex(a.pubkey))!))
    ixHeaders.push(concatBytes(new Uint8Array([programIdIndex, accIndices.length]), u16le(ix.data.length)))
    ixPayloads.push(accIndices, ix.data)
  }

  // Exact V1 signed message bytes:
  // 0x81 | LegacyHeader(3) | ConfigMask(4 LE) | Blockhash(32) | NumIx(1) | NumAddr(1)
  // | Addresses(32*N) | ConfigValues | WireIxHeaders(4*M) | IxPayloads
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
  // V1 wire format: messageBytes FIRST, then fixed-length signatures (NO short_vec prefix!)
  const wireBytes = concatBytes(messageBytes, signature)
  if (wireBytes.length > SOLANA_TX_V1_MAX_SIZE) {
    throw new Error(`V1 transaction size ${wireBytes.length} B exceeds 4,096 B limit`)
  }

  return {
    version: 1,
    wireBytes,
    wireLen: wireBytes.length,
    signatureB58: base58Encode(signature),
    feePayerPubkey,
  }
}

/**
 * Canonical unified key helpers (matching Rust `AudrenKeys`, Swift, and Kotlin SDKs).
 */
export async function deriveKeysFromSeed(seed32: Uint8Array): Promise<AudrenKeypair> {
  if (seed32.byteLength !== 32) {
    throw new RangeError(`seed must be 32 bytes, got ${seed32.byteLength}`)
  }
  return generateAudrenKeys(seed32)
}

export async function deriveSubaccountKeys(
  masterSeed32: Uint8Array,
  accountIndex: number,
): Promise<AudrenKeypair> {
  if (masterSeed32.byteLength !== 32) {
    throw new RangeError(`masterSeed must be 32 bytes, got ${masterSeed32.byteLength}`)
  }
  if (!Number.isInteger(accountIndex) || accountIndex < 0 || accountIndex > 0xffff_ffff) {
    throw new RangeError(`accountIndex must be a u32 integer, got ${accountIndex}`)
  }
  if (accountIndex === 0) {
    return generateAudrenKeys(masterSeed32)
  }
  const childSeed = await hkdfExpandBytes(
    masterSeed32,
    utf8('audren/v1/subaccount'),
    u32le(accountIndex),
    32,
  )
  return generateAudrenKeys(childSeed)
}

export interface FullViewingKeyExport {
  version: 1
  spendPkB58: string
  viewSkB58: string
  viewPkB58: string
}

export function exportFullViewingKey(keys: AudrenKeypair): FullViewingKeyExport {
  return {
    version: 1,
    spendPkB58: base58Encode(keys.spendPk),
    viewSkB58: base58Encode(scalarToBytes32LE(keys.viewSk)),
    viewPkB58: base58Encode(keys.viewPk),
  }
}

export interface ParsedFullViewingKey {
  spendPk: Uint8Array
  viewSk: bigint
  viewPk: Uint8Array
}

export function parseFullViewingKey(fvk: FullViewingKeyExport): ParsedFullViewingKey {
  const spendPk = base58Decode(fvk.spendPkB58)
  if (spendPk.length !== 32) {
    throw new Error('FullViewingKey spendPkB58 must decode to 32 bytes')
  }
  const viewSk = decodeCanonicalScalar32(fvk.viewSkB58, 'viewSkB58')
  const viewPk = base58Decode(fvk.viewPkB58)
  if (viewPk.length !== 32) {
    throw new Error('FullViewingKey viewPkB58 must decode to 32 bytes')
  }
  return { spendPk, viewSk, viewPk }
}

export interface AuditorKeypair {
  auditorSk: bigint
  auditorSkBytes: Uint8Array
  auditorPk: Uint8Array
}

export async function deriveAuditorKeypair(seed32: Uint8Array): Promise<AuditorKeypair> {
  if (seed32.byteLength !== 32) {
    throw new RangeError(`auditor seed must be 32 bytes, got ${seed32.byteLength}`)
  }
  const wide = await hkdfExpandBytes(
    seed32,
    utf8('audren/v1/auditor'),
    utf8('audren/v1/auditor_sk'),
    64,
  )
  const auditorSk = scalarFromWideLE(wide)
  const auditorPk = mulRistretto(ristretto255.Point.BASE, auditorSk).toBytes()
  return {
    auditorSk,
    auditorSkBytes: scalarToBytes32LE(auditorSk),
    auditorPk,
  }
}

export function auditorDecryptNote(params: {
  auditorSk: bigint
  s1: Uint8Array
  s2: Uint8Array
  m1: Uint8Array
  m2: Uint8Array
}): { spentStealthPk: Uint8Array; assetGenerator: Uint8Array } {
  const pS1 = ristretto255.Point.fromBytes(params.s1)
  const pS2 = ristretto255.Point.fromBytes(params.s2)
  const pM1 = ristretto255.Point.fromBytes(params.m1)
  const pM2 = ristretto255.Point.fromBytes(params.m2)
  const spentStealthPk = pS2.subtract(mulRistretto(pS1, params.auditorSk)).toBytes()
  const assetGenerator = pM2.subtract(mulRistretto(pM1, params.auditorSk)).toBytes()
  return { spentStealthPk, assetGenerator }
}
