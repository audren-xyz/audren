/**
 * Pure TypeScript Audren Client Prover, Scanner & Instruction Builders.
 *
 * Implements 100% browser-native cryptography matching `program/`
 * and `solana-zk-sdk 8.0.1` byte-for-byte — zero WASM, zero server key custody:
 * - Multi-Base Binary Triptych (`m = 5 | 6 | 7` -> 32 / 64 / 128 note anonymity set)
 * - Cross-Base Bridges (`CrossBase1` 128 B, `CrossBase2` 256 B)
 * - Native Solana Batched Bulletproofs (`BatchedRangeProofU64` 672 B, `U128` 736 B)
 *   with exact Merlin / Strobe-128 transcript & SHAKE256 generator chains
 * - All user instructions: `Deposit`, `Transfer`, `SwapViaRouter`, `Withdraw`,
 *   plus automatic `WriteProofBuffer` + `ExecBuffered` chunking for v0 wallet signing.
 */

import { ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js'
import { keccakP, shake256 } from '@noble/hashes/sha3.js'
import {
  AUDREN_PROGRAM_ID,
  NATIVE_SOL_MINT,
  NOTE_CT_LEN,
  PAGE_CAPACITY,
  RISTRETTO_L,
  SYSTEM_PROGRAM_ID,
  assetGenerator,
  base58Decode,
  base58Encode,
  bytesEqual,
  concatBytes,
  decodeEpochPageHeader,
  deriveEpochPagePda,
  derivePageRentVaultPda,
  derivePoolPda,
  deriveSolVaultPda,
  extractEpochPageNotes,
  findProgramAddress,
  hashToPoint,
  hashToScalar,
  hkdfExpandBytes,
  isNonZeroPoint,
  mulRistretto,
  parseFullViewingKey,
  readU64le,
  scalarFromWideLE,
  scalarToBytes32LE,
  sha256,
  u32le,
  u64le,
  utf8,
  type AudrenKeypair,
  type FullViewingKeyExport,
  type SolanaAccountMeta,
  type SolanaInstruction,
} from './crypto.ts'

// ============================================================================
// Constants & Program IDs (verified against crates/audren-core/src/lib.rs)
// ============================================================================

export const CLASSIC_TOKEN_PROGRAM_ID_STR = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
export const TOKEN_2022_PROGRAM_ID_STR = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
export const ASSOCIATED_TOKEN_PROGRAM_ID_STR = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'
export const ZK_ELGAMAL_PROOF_PROGRAM_ID_STR = 'ZkE1Gama1Proof11111111111111111111111111111'
export const WSOL_MINT_STR = 'So11111111111111111111111111111111111111112'
export const USDC_MAINNET_MINT_STR = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'

export const CLASSIC_TOKEN_PROGRAM_ID = base58Decode(CLASSIC_TOKEN_PROGRAM_ID_STR)
export const TOKEN_2022_PROGRAM_ID = base58Decode(TOKEN_2022_PROGRAM_ID_STR)
export const ASSOCIATED_TOKEN_PROGRAM_ID = base58Decode(ASSOCIATED_TOKEN_PROGRAM_ID_STR)
export const ZK_ELGAMAL_PROOF_PROGRAM_ID = base58Decode(ZK_ELGAMAL_PROOF_PROGRAM_ID_STR)
export const WSOL_MINT = base58Decode(WSOL_MINT_STR)

export const TAG_OPEN_PAGE = 1
export const TAG_DEPOSIT = 2
export const TAG_TRANSFER = 3
export const TAG_MERGE = 4
export const TAG_SWAP_VIA_ROUTER = 5
export const TAG_WITHDRAW = 6
export const TAG_WRITE_PROOF_BUFFER = 8
export const TAG_EXEC_BUFFERED = 9
export const TAG_CLOSE_PROOF_BUFFER = 10
export const TAG_INIT_LANE = 11
export const TAG_OPEN_LANE_PAGE = 12

export const MAX_APPEND_LANES = 16
export const MAX_ESCROW_SHARDS = 16
export const MAX_MERGE_RING_SLOTS = 128
export const PAGE_SEQ_MASK = 0x00ff_ffff_ffff_ffffn
export const LANE_STATE_LEN = 64

export function laneOfPageId(pageId: bigint): number {
  return Number((pageId >> 56n) & 0xffn)
}

export function seqOfPageId(pageId: bigint): bigint {
  return pageId & PAGE_SEQ_MASK
}

export function pageIdForLane(laneId: number, seq: bigint): bigint {
  if (!Number.isInteger(laneId) || laneId < 0 || laneId >= MAX_APPEND_LANES) {
    throw new Error(`Invalid laneId ${laneId} (must be 0..${MAX_APPEND_LANES - 1})`)
  }
  if (seq < 0n || seq > PAGE_SEQ_MASK) {
    throw new Error(`Invalid lane sequence ${seq.toString()}`)
  }
  return (BigInt(laneId) << 56n) | seq
}

export interface AppendLaneState {
  version: number
  laneId: number
  bump: number
  rentVaultBump: number
  poolId: number
  activePageId: bigint
  createdSlot: bigint
}

export function decodeAppendLaneState(data: Uint8Array): AppendLaneState | null {
  if (data.length < LANE_STATE_LEN) return null
  const magic = String.fromCharCode(...data.subarray(0, 8))
  if (magic !== 'AUDRNLN1') return null
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  return {
    version: data[8],
    laneId: data[9],
    bump: data[10],
    rentVaultBump: data[11],
    poolId: view.getUint32(12, true),
    activePageId: view.getBigUint64(16, true),
    createdSlot: view.getBigUint64(24, true),
  }
}

export const NOTE_FLAG_BLINDED_ASSET = 1 << 0
export const NOTE_FLAG_BLINDED_VALUE = 1 << 1
export const NOTE_FLAG_DYNAMIC_ONCHAIN_VALUE = 1 << 2

export const PROOF_BUFFER_CHUNK_SIZE = 768
export const PROOF_BUFFER_MAX_PAYLOAD = 9_984
export const PAGE_ROLLOVER_HEADROOM = 4
export const PAGE_ROLLOVER_THRESHOLD = PAGE_CAPACITY - PAGE_ROLLOVER_HEADROOM // 28
export const PAGE_SCAN_OFFSET = 64
export const PAGE_SCAN_LEN = PAGE_CAPACITY + PAGE_CAPACITY * 32 // 1,056 B

/**
 * Compute SPL Token-2022 transfer fee withheld on a gross transfer of `amount`
 * using Token-2022's exact ceiling division (`feeBps / 10_000`, capped at `maxFee`).
 */
export function calculateTransferFee(amount: bigint, feeBps: number, maxFee: bigint): bigint {
  if (feeBps <= 0 || amount <= 0n || maxFee <= 0n) return 0n
  const bps = BigInt(Math.min(Math.floor(feeBps), 10_000))
  const raw = bps === 10_000n ? amount : (amount * bps + 9_999n) / 10_000n
  const capped = raw < maxFee ? raw : maxFee
  return capped < amount ? capped : amount
}

/**
 * Exact net amount credited to the Audren vault on a gross `Deposit` of `amount`
 * for a Token-2022 mint with `TransferFeeConfig`.
 */
export function netDepositAmount(amount: bigint, feeBps: number, maxFee: bigint): bigint {
  return amount - calculateTransferFee(amount, feeBps, maxFee)
}

export const IDENTITY_BYTES = new Uint8Array(32)

// Solana ZK ElGamal Pedersen base H = HashToRistretto(Sha3_512(G))
const H_BYTES = new Uint8Array([
  140, 146, 64, 180, 86, 169, 230, 220, 101, 195, 119, 161, 4, 141, 116, 95,
  148, 160, 140, 219, 127, 68, 203, 205, 123, 70, 243, 64, 72, 135, 17, 52,
])

type RPoint = typeof ristretto255.Point.BASE

const G_PT: RPoint = ristretto255.Point.BASE
const H_PT: RPoint = ristretto255.Point.fromBytes(H_BYTES)
const ZERO_PT: RPoint = ristretto255.Point.ZERO
const L = RISTRETTO_L
const decoder = new TextDecoder()

// ============================================================================
// Scalar Arithmetic mod L
// ============================================================================

function modL(a: bigint): bigint {
  const r = a % L
  return r >= 0n ? r : r + L
}

function addL(a: bigint, b: bigint): bigint {
  return modL(a + b)
}

function subL(a: bigint, b: bigint): bigint {
  return modL(a - b)
}

function mulL(a: bigint, b: bigint): bigint {
  return modL(a * b)
}

function invL(a: bigint): bigint {
  let t = 0n
  let newT = 1n
  let r = L
  let newR = modL(a)
  if (newR === 0n) throw new Error('Cannot invert zero scalar')
  while (newR !== 0n) {
    const q = r / newR
    ;[t, newT] = [newT, t - q * newT]
    ;[r, newR] = [newR, r - q * newR]
  }
  return modL(t)
}

function randomScalar(): bigint {
  const buf = crypto.getRandomValues(new Uint8Array(64))
  return scalarFromWideLE(buf) || 1n
}

function decompressPoint(bytes: Uint8Array): RPoint {
  if (bytes.every((b) => b === 0)) return ZERO_PT
  return ristretto255.Point.fromBytes(bytes)
}

function compressPoint(pt: RPoint): Uint8Array {
  return pt.toBytes()
}

function msm(scalars: bigint[], points: RPoint[]): RPoint {
  let acc = ZERO_PT
  for (let i = 0; i < scalars.length; i++) {
    const s = modL(scalars[i])
    if (s !== 0n && !points[i].equals(ZERO_PT)) {
      acc = acc.add(points[i].multiply(s))
    }
  }
  return acc
}

function u16le(n: number): Uint8Array {
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff])
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return copy.buffer
}

// ============================================================================
// Additional Audren & SPL PDAs
// ============================================================================

export async function deriveVaultAuthPda(poolId = 0) {
  return findProgramAddress([utf8('audren_vault'), u32le(poolId)], AUDREN_PROGRAM_ID)
}

export async function deriveSwapEscrowPda(poolId = 0, shardId = 0) {
  return findProgramAddress(
    [utf8('audren_escrow'), u32le(poolId), new Uint8Array([shardId & 0xff])],
    AUDREN_PROGRAM_ID,
  )
}

export async function deriveNullifierPda(poolId: number, nullifier: Uint8Array) {
  return findProgramAddress([utf8('audren_null'), u32le(poolId), nullifier], AUDREN_PROGRAM_ID)
}

export async function deriveProofBufferPda(authority: Uint8Array, nonce: bigint) {
  return findProgramAddress([utf8('audren_buf'), authority, u64le(nonce)], AUDREN_PROGRAM_ID)
}

export async function deriveLanePda(poolId: number, laneId: number) {
  return findProgramAddress(
    [utf8('audren_lane'), u32le(poolId), new Uint8Array([laneId & 0xff])],
    AUDREN_PROGRAM_ID,
  )
}

export async function deriveLaneRentVaultPda(poolId: number, laneId: number) {
  return findProgramAddress(
    [utf8('audren_lrent'), u32le(poolId), new Uint8Array([laneId & 0xff])],
    AUDREN_PROGRAM_ID,
  )
}

async function resolveOutLaneRentVault(poolId: number, outPageId: bigint) {
  const outLane = laneOfPageId(outPageId)
  const rentVault =
    outLane === 0
      ? (await derivePageRentVaultPda(poolId)).address
      : (await deriveLaneRentVaultPda(poolId, outLane)).address
  return { outLane, poolWritable: outLane === 0, rentVault }
}

export async function deriveAta(
  owner: Uint8Array,
  tokenProgram: Uint8Array,
  mint: Uint8Array,
): Promise<Uint8Array> {
  return (await findProgramAddress([owner, tokenProgram, mint], ASSOCIATED_TOKEN_PROGRAM_ID))
    .address
}

// ============================================================================
// Audren Address Parsing & Key Derivation from Connected Wallet Signature
// ============================================================================

export interface AudrenAddress {
  encoded?: string
  spendPk: Uint8Array
  viewPk: Uint8Array
}

export type AudrenRecipient = AudrenAddress | string

export function parseAudrenAddress(encoded: string): AudrenAddress & { encoded: string } {
  const clean = encoded.trim()
  const body = clean.startsWith('aud1') ? clean.slice(4) : clean
  const raw = base58Decode(body)
  if (raw.length !== 64) {
    throw new Error('Audren address must decode to 64 bytes (aud1…)')
  }
  const spendPk = raw.slice(0, 32)
  const viewPk = raw.slice(32, 64)
  if (!isNonZeroPoint(spendPk) || !isNonZeroPoint(viewPk)) {
    throw new Error('Invalid Ristretto255 points in Audren address')
  }
  return { encoded: `aud1${body}`, spendPk, viewPk }
}

function resolveAudrenAddress(recipient: AudrenRecipient): AudrenAddress {
  return typeof recipient === 'string' ? parseAudrenAddress(recipient) : recipient
}

/**
 * Deterministically derive a 32-byte Audren vault seed from a wallet `signMessage` signature.
 * Reconnecting the same Phantom/Solflare/Backpack wallet recovers the exact same private vault.
 */
export async function deriveSeedFromWalletSignature(
  walletAddress: string,
  signatureBytes: Uint8Array,
): Promise<Uint8Array> {
  return sha256(utf8('audren/v1/wallet_seed'), utf8(walletAddress), signatureBytes)
}

export function buildWalletUnlockMessage(walletAddress: string, poolId = 0): string {
  return [
    'Audren Private Vault Unlock (v1)',
    `Wallet: ${walletAddress}`,
    `Pool: ${poolId}`,
    '',
    'Sign this free off-chain message to derive your local-only spend & view keys.',
    'Keys stay strictly inside your browser memory. No funds move.',
  ].join('\n')
}

// ============================================================================
// Merlin / Strobe-128 Transcript (exact match to `merlin 3.0.0`)
// ============================================================================

const STROBE_R = 166
const FLAG_I = 1
const FLAG_A = 1 << 1
const FLAG_C = 1 << 2
const FLAG_M = 1 << 4
const FLAG_K = 1 << 5

class Strobe128 {
  private readonly buf = new Uint8Array(200)
  private readonly words = new Uint32Array(this.buf.buffer)
  private pos = 0
  private posBegin = 0
  private curFlags = 0

  constructor(protocolLabel: Uint8Array) {
    this.buf.set([1, STROBE_R + 2, 1, 0, 1, 96], 0)
    this.buf.set(utf8('STROBEv1.0.2'), 6)
    keccakP(this.words, 24)
    this.metaAd(protocolLabel, false)
  }

  private runF() {
    this.buf[this.pos] ^= this.posBegin
    this.buf[this.pos + 1] ^= 0x04
    this.buf[STROBE_R + 1] ^= 0x80
    keccakP(this.words, 24)
    this.pos = 0
    this.posBegin = 0
  }

  private absorb(data: Uint8Array) {
    for (let i = 0; i < data.length; i++) {
      this.buf[this.pos] ^= data[i]
      this.pos++
      if (this.pos === STROBE_R) this.runF()
    }
  }

  private squeeze(out: Uint8Array) {
    for (let i = 0; i < out.length; i++) {
      out[i] = this.buf[this.pos]
      this.buf[this.pos] = 0
      this.pos++
      if (this.pos === STROBE_R) this.runF()
    }
  }

  private beginOp(flags: number, more: boolean) {
    if (more) {
      if (this.curFlags !== flags) throw new Error('Strobe flag mismatch')
      return
    }
    const oldBegin = this.posBegin
    this.posBegin = this.pos + 1
    this.curFlags = flags
    this.absorb(new Uint8Array([oldBegin, flags]))
    const forceF = (flags & (FLAG_C | FLAG_K)) !== 0
    if (forceF && this.pos !== 0) this.runF()
  }

  metaAd(data: Uint8Array, more: boolean) {
    this.beginOp(FLAG_M | FLAG_A, more)
    this.absorb(data)
  }

  ad(data: Uint8Array, more: boolean) {
    this.beginOp(FLAG_A, more)
    this.absorb(data)
  }

  prf(out: Uint8Array, more: boolean) {
    this.beginOp(FLAG_I | FLAG_A | FLAG_C, more)
    this.squeeze(out)
  }
}

class MerlinTranscript {
  private readonly strobe: Strobe128

  constructor(domainLabel: Uint8Array) {
    this.strobe = new Strobe128(utf8('Merlin v1.0'))
    this.appendMessage(utf8('dom-sep'), domainLabel)
  }

  appendMessage(label: Uint8Array, message: Uint8Array) {
    this.strobe.metaAd(label, false)
    this.strobe.metaAd(u32le(message.length), true)
    this.strobe.ad(message, false)
  }

  appendU64(label: Uint8Array, x: bigint) {
    this.appendMessage(label, u64le(x))
  }

  appendPoint(label: Uint8Array, ptBytes: Uint8Array) {
    this.appendMessage(label, ptBytes)
  }

  appendScalar(label: Uint8Array, s: bigint) {
    this.appendMessage(label, scalarToBytes32LE(s))
  }

  challengeScalar(label: Uint8Array): bigint {
    const buf = new Uint8Array(64)
    this.strobe.metaAd(label, false)
    this.strobe.metaAd(u32le(64), true)
    this.strobe.prf(buf, false)
    return scalarFromWideLE(buf)
  }
}

// ============================================================================
// Native Solana Bulletproofs (`BatchedRangeProofU64` 672 B / `U128` 736 B)
// Exact match to `solana-zk-sdk 8.0.1` (`ZkE1Gama1Proof11111111111111111111111111111`)
// ============================================================================

let cachedBpGens: { G: RPoint[]; H: RPoint[] } | null = null

function getRangeProofGens(nm: number): { G: RPoint[]; H: RPoint[] } {
  if (!cachedBpGens || cachedBpGens.G.length < nm) {
    const cap = Math.max(nm, 128)
    const gStream = shake256(utf8('GeneratorsChainG'), { dkLen: cap * 64 })
    const hStream = shake256(utf8('GeneratorsChainH'), { dkLen: cap * 64 })
    const G: RPoint[] = new Array(cap)
    const H: RPoint[] = new Array(cap)
    const deriveToCurve = ristretto255_hasher.deriveToCurve
    if (!deriveToCurve) {
      throw new Error('ristretto255_hasher.deriveToCurve is unavailable')
    }
    for (let i = 0; i < cap; i++) {
      G[i] = deriveToCurve(gStream.subarray(i * 64, (i + 1) * 64))
      H[i] = deriveToCurve(hStream.subarray(i * 64, (i + 1) * 64))
    }
    cachedBpGens = { G, H }
  }
  return {
    G: cachedBpGens.G.slice(0, nm),
    H: cachedBpGens.H.slice(0, nm),
  }
}

function innerProductScalars(a: bigint[], b: bigint[]): bigint {
  let acc = 0n
  for (let i = 0; i < a.length; i++) acc = addL(acc, mulL(a[i], b[i]))
  return acc
}

function createInnerProductProof(
  Q: RPoint,
  GFactors: bigint[],
  HFactors: bigint[],
  GVec: RPoint[],
  HVec: RPoint[],
  aVec: bigint[],
  bVec: bigint[],
  transcript: MerlinTranscript,
): { LVec: Uint8Array[]; RVec: Uint8Array[]; a: bigint; b: bigint } {
  let n = GVec.length
  transcript.appendMessage(utf8('dom-sep'), utf8('inner-product'))
  transcript.appendU64(utf8('n'), BigInt(n))

  const LVec: Uint8Array[] = []
  const RVec: Uint8Array[] = []

  let G = GVec.slice()
  let H = HVec.slice()
  let a = aVec.slice()
  let b = bVec.slice()

  if (n !== 1) {
    n = n >>> 1
    const aL = a.slice(0, n)
    const aR = a.slice(n, 2 * n)
    const bL = b.slice(0, n)
    const bR = b.slice(n, 2 * n)
    const GL = G.slice(0, n)
    const GR = G.slice(n, 2 * n)
    const HL = H.slice(0, n)
    const HR = H.slice(n, 2 * n)

    const cL = innerProductScalars(aL, bR)
    const cR = innerProductScalars(aR, bL)

    const lScalars: bigint[] = []
    const lPoints: RPoint[] = []
    for (let i = 0; i < n; i++) {
      lScalars.push(mulL(aL[i], GFactors[n + i]))
      lPoints.push(GR[i])
    }
    for (let i = 0; i < n; i++) {
      lScalars.push(mulL(bR[i], HFactors[i]))
      lPoints.push(HL[i])
    }
    lScalars.push(cL)
    lPoints.push(Q)
    const LPt = compressPoint(msm(lScalars, lPoints))

    const rScalars: bigint[] = []
    const rPoints: RPoint[] = []
    for (let i = 0; i < n; i++) {
      rScalars.push(mulL(aR[i], GFactors[i]))
      rPoints.push(GL[i])
    }
    for (let i = 0; i < n; i++) {
      rScalars.push(mulL(bL[i], HFactors[n + i]))
      rPoints.push(HR[i])
    }
    rScalars.push(cR)
    rPoints.push(Q)
    const RPt = compressPoint(msm(rScalars, rPoints))

    LVec.push(LPt)
    RVec.push(RPt)
    transcript.appendPoint(utf8('L'), LPt)
    transcript.appendPoint(utf8('R'), RPt)

    const u = transcript.challengeScalar(utf8('u'))
    const uInv = invL(u)

    const nextA = new Array<bigint>(n)
    const nextB = new Array<bigint>(n)
    const nextG = new Array<RPoint>(n)
    const nextH = new Array<RPoint>(n)
    for (let i = 0; i < n; i++) {
      nextA[i] = addL(mulL(aL[i], u), mulL(uInv, aR[i]))
      nextB[i] = addL(mulL(bL[i], uInv), mulL(u, bR[i]))
      nextG[i] = msm([mulL(uInv, GFactors[i]), mulL(u, GFactors[n + i])], [GL[i], GR[i]])
      nextH[i] = msm([mulL(u, HFactors[i]), mulL(uInv, HFactors[n + i])], [HL[i], HR[i]])
    }
    a = nextA
    b = nextB
    G = nextG
    H = nextH
  }

  while (n !== 1) {
    n = n >>> 1
    const aL = a.slice(0, n)
    const aR = a.slice(n, 2 * n)
    const bL = b.slice(0, n)
    const bR = b.slice(n, 2 * n)
    const GL = G.slice(0, n)
    const GR = G.slice(n, 2 * n)
    const HL = H.slice(0, n)
    const HR = H.slice(n, 2 * n)

    const cL = innerProductScalars(aL, bR)
    const cR = innerProductScalars(aR, bL)

    const LPt = compressPoint(msm([...aL, ...bR, cL], [...GR, ...HL, Q]))
    const RPt = compressPoint(msm([...aR, ...bL, cR], [...GL, ...HR, Q]))

    LVec.push(LPt)
    RVec.push(RPt)
    transcript.appendPoint(utf8('L'), LPt)
    transcript.appendPoint(utf8('R'), RPt)

    const u = transcript.challengeScalar(utf8('u'))
    const uInv = invL(u)

    const nextA = new Array<bigint>(n)
    const nextB = new Array<bigint>(n)
    const nextG = new Array<RPoint>(n)
    const nextH = new Array<RPoint>(n)
    for (let i = 0; i < n; i++) {
      nextA[i] = addL(mulL(aL[i], u), mulL(uInv, aR[i]))
      nextB[i] = addL(mulL(bL[i], uInv), mulL(u, bR[i]))
      nextG[i] = msm([uInv, u], [GL[i], GR[i]])
      nextH[i] = msm([u, uInv], [HL[i], HR[i]])
    }
    a = nextA
    b = nextB
    G = nextG
    H = nextH
  }

  return { LVec, RVec, a: a[0], b: b[0] }
}

function proveBatchedRange(
  amounts: bigint[],
  bitLengths: number[],
  openings: bigint[],
): { proof: Uint8Array; commitments: Uint8Array[] } {
  const m = amounts.length
  const nm = bitLengths.reduce((acc, x) => acc + x, 0)
  const commitments = amounts.map((v, idx) =>
    compressPoint(mulRistretto(G_PT, v).add(mulRistretto(H_PT, openings[idx]))),
  )

  // Context: 8 * 32 B commitments (zero-padded) + 8 * 1 B bit_lengths (zero-padded)
  const ctxCommitments = new Uint8Array(8 * 32)
  const ctxBitLengths = new Uint8Array(8)
  for (let i = 0; i < m; i++) {
    ctxCommitments.set(commitments[i], i * 32)
    ctxBitLengths[i] = bitLengths[i]
  }

  const transcript = new MerlinTranscript(utf8('solana-zk-elgamal-proof-program-v1'))
  transcript.appendMessage(utf8('dom-sep'), utf8('batched-range-proof-instruction'))
  transcript.appendMessage(utf8('commitments'), ctxCommitments)
  transcript.appendMessage(utf8('bit-lengths'), ctxBitLengths)

  const gens = getRangeProofGens(nm)
  transcript.appendMessage(utf8('dom-sep'), utf8('range-proof'))
  transcript.appendU64(utf8('n'), BigInt(nm))

  // A = a_blinding * H + sum(bit==1 ? G_ij : -H_ij)
  const aBlinding = randomScalar()
  let APt = mulRistretto(H_PT, aBlinding)
  let flatIdx = 0
  for (let k = 0; k < m; k++) {
    const amt = amounts[k]
    for (let j = 0; j < bitLengths[k]; j++) {
      const bit = (amt >> BigInt(j)) & 1n
      APt = APt.add(bit === 1n ? gens.G[flatIdx] : gens.H[flatIdx].negate())
      flatIdx++
    }
  }
  const ABytes = compressPoint(APt)

  const sL = Array.from({ length: nm }, () => randomScalar())
  const sR = Array.from({ length: nm }, () => randomScalar())
  const sBlinding = randomScalar()
  const SBytes = compressPoint(msm([sBlinding, ...sL, ...sR], [H_PT, ...gens.G, ...gens.H]))

  transcript.appendPoint(utf8('A'), ABytes)
  transcript.appendPoint(utf8('S'), SBytes)

  const y = transcript.challengeScalar(utf8('y'))
  const z = transcript.challengeScalar(utf8('z'))

  const l0 = new Array<bigint>(nm)
  const l1 = new Array<bigint>(nm)
  const r0 = new Array<bigint>(nm)
  const r1 = new Array<bigint>(nm)

  let idx = 0
  let expZ = mulL(z, z)
  let expY = 1n
  for (let k = 0; k < m; k++) {
    let exp2 = 1n
    const amt = amounts[k]
    for (let j = 0; j < bitLengths[k]; j++) {
      const aLj = (amt >> BigInt(j)) & 1n
      const aRj = subL(aLj, 1n)
      l0[idx] = subL(aLj, z)
      l1[idx] = sL[idx]
      r0[idx] = addL(mulL(expY, addL(aRj, z)), mulL(expZ, exp2))
      r1[idx] = mulL(expY, sR[idx])
      expY = mulL(expY, y)
      exp2 = addL(exp2, exp2)
      idx++
    }
    expZ = mulL(expZ, z)
  }

  const t0 = innerProductScalars(l0, r0)
  const t2 = innerProductScalars(l1, r1)
  const t1 = addL(innerProductScalars(l0, r1), innerProductScalars(l1, r0))

  const t1Blinding = randomScalar()
  const t2Blinding = randomScalar()
  const T1Bytes = compressPoint(mulRistretto(G_PT, t1).add(mulRistretto(H_PT, t1Blinding)))
  const T2Bytes = compressPoint(mulRistretto(G_PT, t2).add(mulRistretto(H_PT, t2Blinding)))

  transcript.appendPoint(utf8('T_1'), T1Bytes)
  transcript.appendPoint(utf8('T_2'), T2Bytes)

  const x = transcript.challengeScalar(utf8('x'))

  let aggOpening = 0n
  let expZOpen = z
  for (let k = 0; k < m; k++) {
    expZOpen = mulL(expZOpen, z)
    aggOpening = addL(aggOpening, mulL(expZOpen, openings[k]))
  }

  const x2 = mulL(x, x)
  const tX = addL(t0, addL(mulL(t1, x), mulL(t2, x2)))
  const tXBlinding = addL(aggOpening, addL(mulL(t1Blinding, x), mulL(t2Blinding, x2)))

  transcript.appendScalar(utf8('t_x'), tX)
  transcript.appendScalar(utf8('t_x_blinding'), tXBlinding)

  const eBlinding = addL(aBlinding, mulL(sBlinding, x))
  transcript.appendScalar(utf8('e_blinding'), eBlinding)

  const lVec = l0.map((v, i) => addL(v, mulL(l1[i], x)))
  const rVec = r0.map((v, i) => addL(v, mulL(r1[i], x)))

  const w = transcript.challengeScalar(utf8('w'))
  const Q = mulRistretto(G_PT, w)

  const GFactors = new Array<bigint>(nm).fill(1n)
  const yInv = invL(y)
  const HFactors = new Array<bigint>(nm)
  let yInvPow = 1n
  for (let i = 0; i < nm; i++) {
    HFactors[i] = yInvPow
    yInvPow = mulL(yInvPow, yInv)
  }

  // Legacy challenge `c` kept in Solana ZK ElGamal verifier transcript
  transcript.challengeScalar(utf8('c'))

  const ipp = createInnerProductProof(Q, GFactors, HFactors, gens.G, gens.H, lVec, rVec, transcript)

  transcript.appendScalar(utf8('ipp_a'), ipp.a)
  transcript.appendScalar(utf8('ipp_b'), ipp.b)
  transcript.challengeScalar(utf8('d'))

  const ippParts: Uint8Array[] = []
  for (let i = 0; i < ipp.LVec.length; i++) {
    ippParts.push(ipp.LVec[i], ipp.RVec[i])
  }
  ippParts.push(scalarToBytes32LE(ipp.a), scalarToBytes32LE(ipp.b))

  const proof = concatBytes(
    ABytes,
    SBytes,
    T1Bytes,
    T2Bytes,
    scalarToBytes32LE(tX),
    scalarToBytes32LE(tXBlinding),
    scalarToBytes32LE(eBlinding),
    ...ippParts,
  )

  return { proof, commitments }
}

export function proveRangeU64(amount: bigint, opening: bigint): { proof: Uint8Array; commitment: Uint8Array } {
  const res = proveBatchedRange([amount], [64], [opening])
  if (res.proof.length !== 672) throw new Error(`Expected 672 B u64 proof, got ${res.proof.length}`)
  return { proof: res.proof, commitment: res.commitments[0] }
}

export function proveRangeU128(
  amount1: bigint,
  opening1: bigint,
  amount2: bigint,
  opening2: bigint,
): { proof: Uint8Array; commitment1: Uint8Array; commitment2: Uint8Array } {
  const res = proveBatchedRange([amount1, amount2], [64, 64], [opening1, opening2])
  if (res.proof.length !== 736) throw new Error(`Expected 736 B u128 proof, got ${res.proof.length}`)
  return {
    proof: res.proof,
    commitment1: res.commitments[0],
    commitment2: res.commitments[1],
  }
}

// ============================================================================
// Audren Generators, Triptych & Cross-Base Provers
// ============================================================================

let cachedNullifierGen: Uint8Array | null = null
const cachedBitGens = new Map<number, RPoint>()

async function getNullifierGenerator(): Promise<Uint8Array> {
  if (!cachedNullifierGen) {
    cachedNullifierGen = await hashToPoint(utf8('audren/v1/U'), utf8('nullifier'))
  }
  return cachedNullifierGen
}

async function getBitGenerator(j: number): Promise<RPoint> {
  const existing = cachedBitGens.get(j)
  if (existing) return existing
  const bytes = await hashToPoint(utf8('audren/v1/triptych/H'), u32le(j))
  const pt = decompressPoint(bytes)
  cachedBitGens.set(j, pt)
  return pt
}

export interface RingSlotWitness {
  stealthPk: Uint8Array
  assetTag: Uint8Array
  commitment: Uint8Array
}

export function extractRingFromPage(pageBytes: Uint8Array): RingSlotWitness[] {
  const notes = extractEpochPageNotes(pageBytes)
  const ring: RingSlotWitness[] = new Array(PAGE_CAPACITY)
  for (let i = 0; i < PAGE_CAPACITY; i++) {
    if (i < notes.length) {
      ring[i] = {
        stealthPk: notes[i].stealthPk,
        assetTag: notes[i].assetTag,
        commitment: notes[i].commitment,
      }
    } else {
      ring[i] = {
        stealthPk: IDENTITY_BYTES,
        assetTag: IDENTITY_BYTES,
        commitment: IDENTITY_BYTES,
      }
    }
  }
  return ring
}

function computePolyCoeffs(m: number, l: number, a: bigint[]): bigint[][] {
  const n = 1 << m
  const coeffs: bigint[][] = Array.from({ length: n }, () => new Array<bigint>(m + 1).fill(0n))
  for (let k = 0; k < n; k++) {
    const poly = coeffs[k]
    poly[0] = 1n
    let deg = 0
    for (let j = 0; j < m; j++) {
      const lBit = (l >> j) & 1
      const kBit = (k >> j) & 1
      const c1 = kBit === 1 ? BigInt(lBit) : BigInt(1 - lBit)
      const c0 = kBit === 1 ? a[j] : modL(-a[j])
      for (let d = deg; d >= 0; d--) {
        const prev = poly[d]
        poly[d + 1] = addL(poly[d + 1], mulL(prev, c1))
        poly[d] = mulL(prev, c0)
      }
      deg++
    }
  }
  return coeffs
}

export async function proveTriptych(params: {
  m: number
  inputPageIds: bigint[]
  secretIndex: number
  ring: RingSlotWitness[]
  spendX: bigint
  aNoteBlinding: bigint
  value: bigint
  vNoteBlinding: bigint
  aSpend: Uint8Array
  aSpendBlinding: bigint
  vSpend: Uint8Array
  vSpendEffBlinding: bigint
  ctxHash: Uint8Array
}): Promise<{ proof: Uint8Array; nullifier: Uint8Array }> {
  const { m, inputPageIds, secretIndex, ring, spendX, ctxHash } = params
  const n = 1 << m
  const nPages = m === 5 ? 1 : m === 6 ? 2 : m === 7 ? 4 : 0
  if (nPages === 0 || inputPageIds.length !== nPages) {
    throw new Error(`Invalid inputPageIds count ${inputPageIds.length} for m=${m}`)
  }
  if (ring.length !== n || secretIndex < 0 || secretIndex >= n) {
    throw new Error(`Invalid Triptych ring length ${ring.length} for m=${m}`)
  }
  if (modL(spendX) === 0n) throw new Error('spendX cannot be zero')

  // Compute per-page immutable prefix counts & strong Fiat-Shamir `ringRoot`
  // matching `program/src/crypto.rs::verify_triptych` byte-for-byte.
  const prefixCounts = new Uint8Array(nPages)
  const pageHashes: Uint8Array[] = []
  for (let pIdx = 0; pIdx < nPages; pIdx++) {
    const baseK = pIdx * PAGE_CAPACITY
    let prefix = 0
    while (prefix < PAGE_CAPACITY && !bytesEqual(ring[baseK + prefix].stealthPk, IDENTITY_BYTES)) {
      prefix++
    }
    if (prefix === 0) {
      throw new Error(`Input page ${inputPageIds[pIdx].toString()} has no populated notes`)
    }
    for (let slot = prefix; slot < PAGE_CAPACITY; slot++) {
      const s = ring[baseK + slot]
      if (
        !bytesEqual(s.stealthPk, IDENTITY_BYTES) ||
        !bytesEqual(s.assetTag, IDENTITY_BYTES) ||
        !bytesEqual(s.commitment, IDENTITY_BYTES)
      ) {
        throw new Error('Ring slots within a page must be densely populated from 0..prefix')
      }
    }
    prefixCounts[pIdx] = prefix
    const stealthBuf = new Uint8Array(prefix * 32)
    const assetBuf = new Uint8Array(prefix * 32)
    const commitBuf = new Uint8Array(prefix * 32)
    for (let slot = 0; slot < prefix; slot++) {
      const entry = ring[baseK + slot]
      stealthBuf.set(entry.stealthPk, slot * 32)
      assetBuf.set(entry.assetTag, slot * 32)
      commitBuf.set(entry.commitment, slot * 32)
    }
    pageHashes.push(
      await sha256(
        utf8('audren/v1/ring/page'),
        u64le(inputPageIds[pIdx]),
        new Uint8Array([prefix]),
        stealthBuf,
        assetBuf,
        commitBuf,
      ),
    )
  }
  if (secretIndex % PAGE_CAPACITY >= prefixCounts[Math.floor(secretIndex / PAGE_CAPACITY)]) {
    throw new Error('secretIndex points outside page prefixCount')
  }
  const ringRoot = await sha256(
    utf8('audren/v1/triptych/ring'),
    new Uint8Array([m, 0]), // browser client targets permissionless (audited=0) pools
    IDENTITY_BYTES,
    ...pageHashes,
  )

  const uPt = decompressPoint(await getNullifierGenerator())
  const jPt = mulRistretto(uPt, invL(spendX))
  const jBytes = compressPoint(jPt)

  const hBits: RPoint[] = []
  for (let j = 0; j < m; j++) hBits.push(await getBitGenerator(j))

  const ringP = ring.map((s) => decompressPoint(s.stealthPk))
  const ringA = ring.map((s) => decompressPoint(s.assetTag))
  const ringV = ring.map((s) => decompressPoint(s.commitment))

  const alpha = await hashToScalar([
    utf8('triptych/alpha'),
    ctxHash,
    ringRoot,
    params.aSpend,
    params.vSpend,
  ])
  const alphaBytes = scalarToBytes32LE(alpha)

  const vNoteEffBlind = addL(mulL(params.value, params.aNoteBlinding), params.vNoteBlinding)
  const delta = addL(
    subL(params.aNoteBlinding, params.aSpendBlinding),
    mulL(alpha, subL(vNoteEffBlind, params.vSpendEffBlinding)),
  )

  const rA = randomScalar()
  const rB = randomScalar()
  const rC = randomScalar()
  const rD = randomScalar()
  const aBits = Array.from({ length: m }, () => randomScalar())

  let ptA = mulRistretto(H_PT, rA)
  let ptB = mulRistretto(H_PT, rB)
  let ptC = mulRistretto(H_PT, rC)
  let ptD = mulRistretto(H_PT, rD)
  for (let j = 0; j < m; j++) {
    const lj = BigInt((secretIndex >> j) & 1)
    const aj = aBits[j]
    ptA = ptA.add(mulRistretto(hBits[j], aj))
    ptB = ptB.add(mulRistretto(hBits[j], lj))
    ptC = ptC.add(mulRistretto(hBits[j], mulL(aj, subL(1n, mulL(2n, lj)))))
    ptD = ptD.add(mulRistretto(hBits[j], modL(-mulL(aj, aj))))
  }

  const poly = computePolyCoeffs(m, secretIndex, aBits)
  const rhos: bigint[] = []
  const taus: bigint[] = []
  const xs: Uint8Array[] = []
  const ys: Uint8Array[] = []
  const ws: Uint8Array[] = []

  for (let j = 0; j < m; j++) {
    const rho = randomScalar()
    const tau = randomScalar()
    rhos.push(rho)
    taus.push(tau)

    let xAcc = mulRistretto(G_PT, rho)
    let wAcc = mulRistretto(H_PT, tau)
    for (let k = 0; k < n; k++) {
      const pkj = poly[k][j]
      if (pkj === 0n) continue
      if (!ringP[k].equals(ZERO_PT)) xAcc = xAcc.add(mulRistretto(ringP[k], pkj))
      if (!ringA[k].equals(ZERO_PT)) wAcc = wAcc.add(mulRistretto(ringA[k], pkj))
      if (!ringV[k].equals(ZERO_PT)) wAcc = wAcc.add(mulRistretto(ringV[k], mulL(pkj, alpha)))
    }
    xs.push(compressPoint(xAcc))
    ys.push(compressPoint(mulRistretto(jPt, rho)))
    ws.push(compressPoint(wAcc))
  }

  const aBytes = compressPoint(ptA)
  const bBytes = compressPoint(ptB)
  const cBytes = compressPoint(ptC)
  const dBytes = compressPoint(ptD)

  const xi = await hashToScalar([
    utf8('triptych/xi'),
    ringRoot,
    alphaBytes,
    jBytes,
    aBytes,
    bBytes,
    cBytes,
    dBytes,
    ...xs,
    ...ys,
    ...ws,
  ])

  const fs: Uint8Array[] = []
  for (let j = 0; j < m; j++) {
    const lj = BigInt((secretIndex >> j) & 1)
    fs.push(scalarToBytes32LE(addL(mulL(lj, xi), aBits[j])))
  }
  const zA = addL(mulL(rB, xi), rA)
  const zC = addL(mulL(rC, xi), rD)

  let xiPow = 1n
  let rhoSum = 0n
  let tauSum = 0n
  for (let j = 0; j < m; j++) {
    rhoSum = addL(rhoSum, mulL(rhos[j], xiPow))
    tauSum = addL(tauSum, mulL(taus[j], xiPow))
    xiPow = mulL(xiPow, xi)
  }
  const xiM = xiPow
  const zX = subL(mulL(spendX, xiM), rhoSum)
  const zQ = subL(mulL(delta, xiM), tauSum)

  const proof = concatBytes(
    prefixCounts,
    jBytes,
    aBytes,
    bBytes,
    cBytes,
    dBytes,
    ...xs,
    ...ys,
    ...ws,
    ...fs,
    scalarToBytes32LE(zA),
    scalarToBytes32LE(zC),
    scalarToBytes32LE(zX),
    scalarToBytes32LE(zQ),
  )

  return { proof, nullifier: jBytes }
}

async function proveCrossBase1(
  aPtBytes: Uint8Array,
  vPtBytes: Uint8Array,
  cPtBytes: Uint8Array,
  v: bigint,
  t: bigint,
  s: bigint,
  ctxHash: Uint8Array,
): Promise<Uint8Array> {
  const aPt = decompressPoint(aPtBytes)
  const kv = randomScalar()
  const kt = randomScalar()
  const ks = randomScalar()
  const rv = compressPoint(mulRistretto(aPt, kv).add(mulRistretto(H_PT, kt)))
  const rc = compressPoint(mulRistretto(G_PT, kv).add(mulRistretto(H_PT, ks)))

  const c = await hashToScalar([utf8('xbase1'), ctxHash, aPtBytes, vPtBytes, cPtBytes, rv, rc])
  const zV = addL(kv, mulL(c, v))
  const zT = addL(kt, mulL(c, t))
  const zS = addL(ks, mulL(c, s))

  return concatBytes(
    scalarToBytes32LE(c),
    scalarToBytes32LE(zV),
    scalarToBytes32LE(zT),
    scalarToBytes32LE(zS),
  )
}

async function proveCrossBase2(
  a1Bytes: Uint8Array,
  v1Bytes: Uint8Array,
  c1Bytes: Uint8Array,
  v1: bigint,
  t1: bigint,
  s1: bigint,
  a2Bytes: Uint8Array,
  v2Bytes: Uint8Array,
  c2Bytes: Uint8Array,
  v2: bigint,
  t2: bigint,
  s2: bigint,
  aDiff: bigint,
  ctxHash: Uint8Array,
): Promise<Uint8Array> {
  const a1Pt = decompressPoint(a1Bytes)
  const a2Pt = decompressPoint(a2Bytes)
  const kv1 = randomScalar()
  const kt1 = randomScalar()
  const ks1 = randomScalar()
  const kv2 = randomScalar()
  const kt2 = randomScalar()
  const ks2 = randomScalar()
  const kd = randomScalar()

  const rv1 = compressPoint(mulRistretto(a1Pt, kv1).add(mulRistretto(H_PT, kt1)))
  const rc1 = compressPoint(mulRistretto(G_PT, kv1).add(mulRistretto(H_PT, ks1)))
  const rv2 = compressPoint(mulRistretto(a2Pt, kv2).add(mulRistretto(H_PT, kt2)))
  const rc2 = compressPoint(mulRistretto(G_PT, kv2).add(mulRistretto(H_PT, ks2)))
  const rd = compressPoint(mulRistretto(H_PT, kd))

  const c = await hashToScalar([
    utf8('xbase2'),
    ctxHash,
    a1Bytes,
    v1Bytes,
    c1Bytes,
    a2Bytes,
    v2Bytes,
    c2Bytes,
    rv1,
    rc1,
    rv2,
    rc2,
    rd,
  ])

  return concatBytes(
    scalarToBytes32LE(c),
    scalarToBytes32LE(addL(kv1, mulL(c, v1))),
    scalarToBytes32LE(addL(kt1, mulL(c, t1))),
    scalarToBytes32LE(addL(ks1, mulL(c, s1))),
    scalarToBytes32LE(addL(kv2, mulL(c, v2))),
    scalarToBytes32LE(addL(kt2, mulL(c, t2))),
    scalarToBytes32LE(addL(ks2, mulL(c, s2))),
    scalarToBytes32LE(addL(kd, mulL(c, aDiff))),
  )
}

// ============================================================================
// Stealth Note Preparation & Full Scanner (Deposits, Transfers, Swap Outputs)
// ============================================================================

interface FullStealthMaterial {
  ephemeralPk: Uint8Array
  stealthPk: Uint8Array
  stealthScalar: bigint
  viewTag: number
  aesKey: Uint8Array
  aesNonce: Uint8Array
  derivedAssetBlinding: bigint
  derivedValueBlinding: bigint
}

async function deriveFullStealthFromShared(
  recipientSpendPk: Uint8Array,
  ephemeralPk: Uint8Array,
  sharedBytes: Uint8Array,
): Promise<FullStealthMaterial> {
  const viewTag = (await sha256(utf8('audren/v1/view_tag'), sharedBytes))[0]
  const stealthScalar = await hashToScalar([utf8('audren/v1/stealth_x'), sharedBytes])
  const spendPt = decompressPoint(recipientSpendPk)
  const stealthPk = compressPoint(spendPt.add(mulRistretto(G_PT, stealthScalar)))

  const aesKey = await hkdfExpandBytes(sharedBytes, utf8('audren/v1/note_kdf'), utf8('aes256gcm_key'), 32)
  const aesNonce = await hkdfExpandBytes(
    sharedBytes,
    utf8('audren/v1/note_kdf'),
    utf8('aes256gcm_nonce'),
    12,
  )
  const derivedAssetBlinding = await hashToScalar([utf8('audren/v1/note_a_blind'), sharedBytes])
  const derivedValueBlinding = await hashToScalar([utf8('audren/v1/note_r_blind'), sharedBytes])

  return {
    ephemeralPk,
    stealthPk,
    stealthScalar,
    viewTag,
    aesKey,
    aesNonce,
    derivedAssetBlinding,
    derivedValueBlinding,
  }
}

async function encryptNoteMemo(
  mat: FullStealthMaterial,
  mint: Uint8Array,
  amount: bigint,
  flags: number,
  memoText: string,
): Promise<Uint8Array> {
  const plaintext = new Uint8Array(48)
  plaintext.set(mint, 0)
  plaintext.set(u64le(amount), 32)
  plaintext[40] = flags & 0xff
  const memoBytes = utf8(memoText.trim()).slice(0, 7)
  plaintext.set(memoBytes, 41)

  const key = await crypto.subtle.importKey('raw', toArrayBuffer(mat.aesKey), 'AES-GCM', false, [
    'encrypt',
  ])
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(mat.aesNonce), additionalData: toArrayBuffer(mat.stealthPk) },
    key,
    toArrayBuffer(plaintext),
  )
  const ct = new Uint8Array(encrypted)
  if (ct.length !== NOTE_CT_LEN) throw new Error(`Bad ciphertext len ${ct.length}`)
  return ct
}

export interface PreparedFullNote {
  viewTag: number
  ephemeralPk: Uint8Array
  stealthPk: Uint8Array
  assetTag: Uint8Array
  commitment: Uint8Array
  ciphertext: Uint8Array
  mint: Uint8Array
  amount: bigint
  assetBlinding: bigint
  valueBlinding: bigint
  stealthScalar: bigint
}

export async function prepareShieldedNote(params: {
  recipient: AudrenRecipient
  mint: Uint8Array
  amount: bigint
  blindAsset: boolean
  blindValue: boolean
  memoText?: string
}): Promise<PreparedFullNote> {
  const recipient = resolveAudrenAddress(params.recipient)
  const rEph = randomScalar()
  const ephemeralPk = compressPoint(mulRistretto(G_PT, rEph))
  const sharedBytes = compressPoint(mulRistretto(decompressPoint(recipient.viewPk), rEph))
  const mat = await deriveFullStealthFromShared(recipient.spendPk, ephemeralPk, sharedBytes)

  const gMint = decompressPoint(await assetGenerator(params.mint))
  const assetBlinding = params.blindAsset ? mat.derivedAssetBlinding : 0n
  const aPt = gMint.add(mulRistretto(H_PT, assetBlinding))
  const assetTag = compressPoint(aPt)

  const valueBlinding = params.blindValue ? mat.derivedValueBlinding : 0n
  const vPt = mulRistretto(aPt, params.amount).add(mulRistretto(H_PT, valueBlinding))
  const commitment = compressPoint(vPt)

  let flags = 0
  if (params.blindAsset) flags |= NOTE_FLAG_BLINDED_ASSET
  if (params.blindValue) flags |= NOTE_FLAG_BLINDED_VALUE

  const ciphertext = await encryptNoteMemo(
    mat,
    params.mint,
    params.amount,
    flags,
    params.memoText ?? '',
  )

  return {
    viewTag: mat.viewTag,
    ephemeralPk: mat.ephemeralPk,
    stealthPk: mat.stealthPk,
    assetTag,
    commitment,
    ciphertext,
    mint: params.mint,
    amount: params.amount,
    assetBlinding,
    valueBlinding,
    stealthScalar: mat.stealthScalar,
  }
}

export interface PreparedDynamicOutput {
  viewTag: number
  ephemeralPk: Uint8Array
  stealthPk: Uint8Array
  ciphertext: Uint8Array
  stealthScalar: bigint
}

export async function prepareDynamicSwapOutput(params: {
  recipient: AudrenRecipient
  mintOut: Uint8Array
  minAmountOut: bigint
  memoText?: string
}): Promise<PreparedDynamicOutput> {
  const recipient = resolveAudrenAddress(params.recipient)
  const rEph = randomScalar()
  const ephemeralPk = compressPoint(mulRistretto(G_PT, rEph))
  const sharedBytes = compressPoint(mulRistretto(decompressPoint(recipient.viewPk), rEph))
  const mat = await deriveFullStealthFromShared(recipient.spendPk, ephemeralPk, sharedBytes)

  const ciphertext = await encryptNoteMemo(
    mat,
    params.mintOut,
    params.minAmountOut,
    NOTE_FLAG_DYNAMIC_ONCHAIN_VALUE,
    params.memoText ?? 'JUP',
  )

  return {
    viewTag: mat.viewTag,
    ephemeralPk: mat.ephemeralPk,
    stealthPk: mat.stealthPk,
    ciphertext,
    stealthScalar: mat.stealthScalar,
  }
}

function encodeNoteWire(n: PreparedFullNote): Uint8Array {
  return concatBytes(
    new Uint8Array([n.viewTag]),
    n.ephemeralPk,
    n.stealthPk,
    n.assetTag,
    n.commitment,
    n.ciphertext,
  )
}

function encodeDynamicWire(n: PreparedDynamicOutput): Uint8Array {
  return concatBytes(new Uint8Array([n.viewTag]), n.ephemeralPk, n.stealthPk, n.ciphertext)
}

export async function computeNoteNullifier(
  spendSk: bigint,
  stealthScalar: bigint,
): Promise<{ spendX: bigint; nullifier: Uint8Array }> {
  const spendX = addL(spendSk, stealthScalar)
  if (spendX === 0n) throw new Error('Degenerate zero stealth spend key')
  const uPt = decompressPoint(await getNullifierGenerator())
  const nullifier = compressPoint(mulRistretto(uPt, invL(spendX)))
  return { spendX, nullifier }
}

/**
 * Full owned note decrypted from an on-chain `EpochPage` (supports Deposits,
 * blinded Transfers/Change notes, AND dynamic SwapViaRouter output notes).
 */
export interface SpendableAudrenNote {
  pageId: bigint
  slotIndex: number
  mint: Uint8Array
  mintB58: string
  isNativeSol: boolean
  amount: bigint
  isDynamicOutput: boolean
  amountResolved: boolean
  memoText: string
  stealthPk: Uint8Array
  assetTag: Uint8Array
  commitment: Uint8Array
  assetBlinding: bigint
  valueBlinding: bigint
  stealthScalar: bigint
  spendX: bigint
  nullifier: Uint8Array
  nullifierPdaB58: string
}

export type AudrenScanKeys =
  | (Pick<AudrenKeypair, 'spendPk' | 'viewSk'> & Partial<Pick<AudrenKeypair, 'spendSk'>>)
  | FullViewingKeyExport

function resolveViewSk(keys: Pick<AudrenKeypair, 'viewSk'> | FullViewingKeyExport): bigint {
  if ('viewSkB58' in keys) {
    return parseFullViewingKey(keys).viewSk
  }
  if (typeof keys.viewSk !== 'bigint') {
    throw new Error('scanPageScanSlice requires a valid viewSk bigint or FullViewingKeyExport')
  }
  return keys.viewSk
}

function resolveScanKeys(keys: AudrenScanKeys): {
  spendPk: Uint8Array
  viewSk: bigint
  spendSk?: bigint
} {
  if ('viewSkB58' in keys) {
    const parsed = parseFullViewingKey(keys)
    return { spendPk: parsed.spendPk, viewSk: parsed.viewSk }
  }
  if (!(keys.spendPk instanceof Uint8Array) || keys.spendPk.length !== 32) {
    throw new Error('scanEpochPage requires a 32-byte spendPk or FullViewingKeyExport')
  }
  if (typeof keys.viewSk !== 'bigint') {
    throw new Error('scanEpochPage requires a valid viewSk bigint or FullViewingKeyExport')
  }
  return { spendPk: keys.spendPk, viewSk: keys.viewSk, spendSk: keys.spendSk }
}

/**
 * Stage 1 (Fast Compact Filter): Scan a `1,056 B` `EpochPage` `dataSlice[64..1120]`
 * (`view_tags[32] || ephemeral_pks[32]`) and return matched candidate slot indices.
 * Accepts either an `AudrenKeypair` / `{ viewSk }` or an exported `FullViewingKeyExport`.
 * Never aborts on zero or malformed slots (`continue` per slot).
 */
export async function scanPageScanSlice(
  keys: Pick<AudrenKeypair, 'viewSk'> | FullViewingKeyExport,
  sliceBytes: Uint8Array,
): Promise<number[]> {
  const viewSk = resolveViewSk(keys)
  if (sliceBytes.length < PAGE_SCAN_LEN) return []
  const hits: number[] = []
  for (let slot = 0; slot < PAGE_CAPACITY; slot++) {
    const eph = sliceBytes.subarray(PAGE_CAPACITY + slot * 32, PAGE_CAPACITY + (slot + 1) * 32)
    if (!isNonZeroPoint(eph)) continue
    try {
      const ephPt = decompressPoint(eph)
      const sharedBytes = compressPoint(mulRistretto(ephPt, viewSk))
      const expectedTag = (await sha256(utf8('audren/v1/view_tag'), sharedBytes))[0]
      if (expectedTag === sliceBytes[slot]) {
        hits.push(slot)
      }
    } catch {
      // Malformed slot bytes; skip without blinding later positions on this page
    }
  }
  return hits
}

/**
 * Cryptographically verify whether `candidateAmount` matches a dynamic output note's
 * on-chain commitment `V == candidateAmount * A` (unblinded value commitment).
 */
export function verifyDynamicAmountForNote(
  note: Pick<SpendableAudrenNote, 'assetTag' | 'commitment'>,
  candidateAmount: bigint,
): boolean {
  if (candidateAmount < 0n) return false
  try {
    const aPt = decompressPoint(note.assetTag)
    const expectedV = compressPoint(mulRistretto(aPt, candidateAmount))
    return bytesEqual(expectedV, note.commitment)
  } catch {
    return false
  }
}

export interface OwnedAudrenNote {
  pageId: bigint
  slotIndex: number
  mint: Uint8Array
  mintB58: string
  isNativeSol: boolean
  amount: bigint
  isDynamicOutput: boolean
  amountResolved: boolean
  memoText: string
  stealthPk: Uint8Array
  assetTag: Uint8Array
  commitment: Uint8Array
  assetBlinding: bigint
  valueBlinding: bigint
  stealthScalar: bigint
  spendX?: bigint
  nullifier?: Uint8Array
  nullifierPdaB58?: string
}

/**
 * Scan a full `EpochPage` for all notes owned by a `FullViewingKey` (`spendPk + viewSk`)
 * or full keypair (`spendPk + viewSk + spendSk`), including blinded `Transfer`/`Merge`
 * notes and dynamic `SwapViaRouter` outputs.
 *
 * When `spendSk` is omitted (read-only viewing key / watch-only wallet / compliance auditor),
 * `spendX`, `nullifier`, and `nullifierPdaB58` are `undefined`.
 */
export async function scanEpochPage(
  keys: AudrenScanKeys,
  pageBytes: Uint8Array,
  poolId = 0,
  knownDynamicAmounts?: Record<string, bigint>,
): Promise<OwnedAudrenNote[]> {
  const resolved = resolveScanKeys(keys)
  const hdr = decodeEpochPageHeader(pageBytes)
  const notes = extractEpochPageNotes(pageBytes)
  const owned: OwnedAudrenNote[] = []

  for (const n of notes) {
    if (!isNonZeroPoint(n.ephemeralPk)) continue
    try {
      const ephPt = decompressPoint(n.ephemeralPk)
      const sharedBytes = compressPoint(mulRistretto(ephPt, resolved.viewSk))
      const expectedTag = (await sha256(utf8('audren/v1/view_tag'), sharedBytes))[0]
      if (expectedTag !== n.viewTag) continue

      const mat = await deriveFullStealthFromShared(resolved.spendPk, n.ephemeralPk, sharedBytes)
      if (!bytesEqual(mat.stealthPk, n.stealthPk)) continue

      const aesKey = await crypto.subtle.importKey('raw', toArrayBuffer(mat.aesKey), 'AES-GCM', false, [
        'decrypt',
      ])
      const plainBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: toArrayBuffer(mat.aesNonce), additionalData: toArrayBuffer(n.stealthPk) },
        aesKey,
        toArrayBuffer(n.ciphertext),
      )
      const pt = new Uint8Array(plainBuf)
      if (pt.length !== 48) continue

      const mint = pt.slice(0, 32)
      const memoAmount = readU64le(pt, 32)
      const flags = pt[40]
      const memoText = decoder.decode(pt.slice(41, 48)).replace(/\0+$/, '')

      const isDynamic = (flags & NOTE_FLAG_DYNAMIC_ONCHAIN_VALUE) !== 0
      const assetBlinding = (flags & NOTE_FLAG_BLINDED_ASSET) !== 0 ? mat.derivedAssetBlinding : 0n
      const valueBlinding = (flags & NOTE_FLAG_BLINDED_VALUE) !== 0 ? mat.derivedValueBlinding : 0n

      const gMint = decompressPoint(await assetGenerator(mint))
      const expectedA = gMint.add(mulRistretto(H_PT, assetBlinding))
      if (!bytesEqual(compressPoint(expectedA), n.assetTag)) continue

      const stealthB58 = base58Encode(n.stealthPk)
      let amount = memoAmount
      let amountResolved = !isDynamic

      if (isDynamic) {
        const known = knownDynamicAmounts?.[stealthB58]
        if (known !== undefined) {
          const expectedV = mulRistretto(expectedA, known)
          if (bytesEqual(compressPoint(expectedV), n.commitment)) {
            amount = known
            amountResolved = true
          }
        }
        if (!amountResolved) {
          const minV = mulRistretto(expectedA, memoAmount)
          if (bytesEqual(compressPoint(minV), n.commitment)) {
            amount = memoAmount
            amountResolved = true
          }
        }
      } else {
        const expectedV = mulRistretto(expectedA, amount).add(mulRistretto(H_PT, valueBlinding))
        if (!bytesEqual(compressPoint(expectedV), n.commitment)) continue
      }

      const isNativeSol = bytesEqual(mint, NATIVE_SOL_MINT)
      let spendX: bigint | undefined
      let nullifier: Uint8Array | undefined
      let nullifierPdaB58: string | undefined
      if (resolved.spendSk !== undefined) {
        const spend = await computeNoteNullifier(resolved.spendSk, mat.stealthScalar)
        spendX = spend.spendX
        nullifier = spend.nullifier
        nullifierPdaB58 = base58Encode((await deriveNullifierPda(poolId, spend.nullifier)).address)
      }

      owned.push({
        pageId: hdr.pageId,
        slotIndex: n.slotIndex,
        mint,
        mintB58: isNativeSol ? 'SOL' : base58Encode(mint),
        isNativeSol,
        amount,
        isDynamicOutput: isDynamic,
        amountResolved,
        memoText,
        stealthPk: n.stealthPk,
        assetTag: n.assetTag,
        commitment: n.commitment,
        assetBlinding,
        valueBlinding,
        stealthScalar: mat.stealthScalar,
        spendX,
        nullifier,
        nullifierPdaB58,
      })
    } catch {
      // 1/256 view_tag collision or malformed slot; continue cleanly
    }
  }

  return owned
}

/**
 * Scan a full `EpochPage` for all spendable notes owned by `keys` (requires `spendSk`
 * and always populates `spendX`, `nullifier`, and `nullifierPdaB58`).
 */
export async function scanEpochPageSpendable(
  keys: Pick<AudrenKeypair, 'spendSk' | 'spendPk' | 'viewSk'>,
  pageBytes: Uint8Array,
  poolId = 0,
  knownDynamicAmounts?: Record<string, bigint>,
): Promise<SpendableAudrenNote[]> {
  return (await scanEpochPage(keys, pageBytes, poolId, knownDynamicAmounts)) as SpendableAudrenNote[]
}

// ============================================================================
// Instruction Builders (Deposit, Transfer, SwapViaRouter, Withdraw, ProofBuffer)
// ============================================================================

export function buildCreateAtaIdempotentIx(params: {
  payer: Uint8Array
  ata: Uint8Array
  owner: Uint8Array
  mint: Uint8Array
  tokenProgram: Uint8Array
}): SolanaInstruction {
  return {
    programId: ASSOCIATED_TOKEN_PROGRAM_ID,
    accounts: [
      { pubkey: params.payer, isSigner: true, isWritable: true },
      { pubkey: params.ata, isSigner: false, isWritable: true },
      { pubkey: params.owner, isSigner: false, isWritable: false },
      { pubkey: params.mint, isSigner: false, isWritable: false },
      { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: params.tokenProgram, isSigner: false, isWritable: false },
    ],
    data: new Uint8Array([1]), // CreateIdempotent
  }
}

/**
 * Wrap native SOL into the user's WSOL ATA so they can deposit Swap-Ready WSOL into Audren
 * in the exact same transaction.
 */
export async function buildWrapSolInstructions(
  owner: Uint8Array,
  lamports: bigint,
): Promise<{ wsolAta: Uint8Array; instructions: SolanaInstruction[] }> {
  const wsolAta = await deriveAta(owner, CLASSIC_TOKEN_PROGRAM_ID, WSOL_MINT)
  const createIx = buildCreateAtaIdempotentIx({
    payer: owner,
    ata: wsolAta,
    owner,
    mint: WSOL_MINT,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  })
  // SystemProgram::Transfer = discriminant u32(2) + lamports u64 LE
  const transferIx: SolanaInstruction = {
    programId: SYSTEM_PROGRAM_ID,
    accounts: [
      { pubkey: owner, isSigner: true, isWritable: true },
      { pubkey: wsolAta, isSigner: false, isWritable: true },
    ],
    data: concatBytes(u32le(2), u64le(lamports)),
  }
  // SPL Token SyncNative = discriminant u8(17)
  const syncIx: SolanaInstruction = {
    programId: CLASSIC_TOKEN_PROGRAM_ID,
    accounts: [{ pubkey: wsolAta, isSigner: false, isWritable: true }],
    data: new Uint8Array([17]),
  }
  return { wsolAta, instructions: [createIx, transferIx, syncIx] }
}

/**
 * Unwrap WSOL back into native SOL and reclaim the 0.00203928 SOL ATA rent in one atomic step
 * via SPL Token `CloseAccount` (discriminant u8(9)) on the owner's WSOL ATA.
 */
export async function buildCloseWsolAtaInstruction(
  owner: Uint8Array,
): Promise<SolanaInstruction> {
  const wsolAta = await deriveAta(owner, CLASSIC_TOKEN_PROGRAM_ID, WSOL_MINT)
  return {
    programId: CLASSIC_TOKEN_PROGRAM_ID,
    accounts: [
      { pubkey: wsolAta, isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: true, isWritable: false },
    ],
    data: new Uint8Array([9]),
  }
}

/**
 * Tag 1: `OpenPage` — permissionless self-funding page rollover sealing `currentPageId`
 * and allocating `currentPageId + 1` once `currentPage` is closed or at >= 28 notes.
 */
export async function buildOpenPageInstruction(params: {
  payer: Uint8Array
  poolId: number
  currentPageId: bigint
}): Promise<SolanaInstruction> {
  const nextPageId = params.currentPageId + 1n
  const [poolPda, curPagePda, nextPagePda, rentVaultPda] = await Promise.all([
    derivePoolPda(params.poolId),
    deriveEpochPagePda(params.poolId, params.currentPageId),
    deriveEpochPagePda(params.poolId, nextPageId),
    derivePageRentVaultPda(params.poolId),
  ])
  return {
    programId: AUDREN_PROGRAM_ID,
    accounts: [
      { pubkey: params.payer, isSigner: true, isWritable: true },
      { pubkey: poolPda.address, isSigner: false, isWritable: true },
      { pubkey: curPagePda.address, isSigner: false, isWritable: true },
      { pubkey: nextPagePda.address, isSigner: false, isWritable: true },
      { pubkey: rentVaultPda.address, isSigner: false, isWritable: true },
      { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data: new Uint8Array([TAG_OPEN_PAGE]),
  }
}

/**
 * Tag 12: `OpenLanePage` — permissionless rollover for parallel append lanes `1..15`.
 * Keeps `PoolState` strictly READ-ONLY so lane rollovers never contend with other lanes!
 */
export async function buildOpenLanePageInstruction(params: {
  payer: Uint8Array
  poolId: number
  currentPageId: bigint
}): Promise<SolanaInstruction> {
  const laneId = laneOfPageId(params.currentPageId)
  if (laneId === 0) {
    return buildOpenPageInstruction(params)
  }
  const nextPageId = pageIdForLane(laneId, seqOfPageId(params.currentPageId) + 1n)
  const [poolPda, lanePda, curPagePda, nextPagePda, laneRentVaultPda] = await Promise.all([
    derivePoolPda(params.poolId),
    deriveLanePda(params.poolId, laneId),
    deriveEpochPagePda(params.poolId, params.currentPageId),
    deriveEpochPagePda(params.poolId, nextPageId),
    deriveLaneRentVaultPda(params.poolId, laneId),
  ])
  return {
    programId: AUDREN_PROGRAM_ID,
    accounts: [
      { pubkey: params.payer, isSigner: true, isWritable: true },
      { pubkey: poolPda.address, isSigner: false, isWritable: false },
      { pubkey: lanePda.address, isSigner: false, isWritable: true },
      { pubkey: curPagePda.address, isSigner: false, isWritable: true },
      { pubkey: nextPagePda.address, isSigner: false, isWritable: true },
      { pubkey: laneRentVaultPda.address, isSigner: false, isWritable: true },
      { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data: new Uint8Array([TAG_OPEN_LANE_PAGE, laneId & 0xff]),
  }
}

/**
 * Tag 10: `CloseProofBuffer` — reclaims 100% of rent from an abandoned/interrupted
 * self-pay `ProofBuffer` PDA back to `payer`.
 */
export function buildCloseProofBufferInstruction(params: {
  payer: Uint8Array
  proofBufferPda: Uint8Array
}): SolanaInstruction {
  return {
    programId: AUDREN_PROGRAM_ID,
    accounts: [
      { pubkey: params.payer, isSigner: true, isWritable: true },
      { pubkey: params.proofBufferPda, isSigner: false, isWritable: true },
    ],
    data: new Uint8Array([TAG_CLOSE_PROOF_BUFFER]),
  }
}

/**
 * Tag 2: `Deposit` — shield Native SOL, Classic SPL, or Token-2022 directly from user's wallet.
 * For Token-2022 mints with an active `TransferFeeConfig`, pass `netAmount` (from
 * `netDepositAmount`) so the encrypted memo matches the exact on-chain net vault delta.
 */
export async function buildDepositInstruction(params: {
  depositor: Uint8Array
  poolId: number
  activePageId: bigint
  recipient: AudrenRecipient
  mint: Uint8Array
  amount: bigint
  netAmount?: bigint
  tokenProgram?: Uint8Array
  memoText?: string
  createVaultAtaIfMissing?: boolean
}): Promise<{ instructions: SolanaInstruction[]; note: PreparedFullNote }> {
  const isNative = bytesEqual(params.mint, NATIVE_SOL_MINT)
  const noteAmount = params.netAmount ?? params.amount
  const note = await prepareShieldedNote({
    recipient: params.recipient,
    mint: params.mint,
    amount: noteAmount,
    blindAsset: false,
    blindValue: false,
    memoText: params.memoText ?? 'SHIELD',
  })

  const [poolPda, outPagePda, laneTarget] = await Promise.all([
    derivePoolPda(params.poolId),
    deriveEpochPagePda(params.poolId, params.activePageId),
    resolveOutLaneRentVault(params.poolId, params.activePageId),
  ])

  const data = concatBytes(
    new Uint8Array([TAG_DEPOSIT, isNative ? 1 : 0]),
    u64le(params.amount),
    new Uint8Array([note.viewTag]),
    note.ephemeralPk,
    note.stealthPk,
    note.ciphertext,
  )

  const instructions: SolanaInstruction[] = []

  if (isNative) {
    const solVaultPda = await deriveSolVaultPda(params.poolId)
    instructions.push({
      programId: AUDREN_PROGRAM_ID,
      accounts: [
        { pubkey: params.depositor, isSigner: true, isWritable: true },
        { pubkey: poolPda.address, isSigner: false, isWritable: laneTarget.poolWritable },
        { pubkey: outPagePda.address, isSigner: false, isWritable: true },
        { pubkey: solVaultPda.address, isSigner: false, isWritable: true },
        { pubkey: laneTarget.rentVault, isSigner: false, isWritable: true },
        { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
      ],
      data,
    })
  } else {
    const tokenProg = params.tokenProgram ?? CLASSIC_TOKEN_PROGRAM_ID
    const vaultAuth = (await deriveVaultAuthPda(params.poolId)).address
    const [depositorAta, vaultAta] = await Promise.all([
      deriveAta(params.depositor, tokenProg, params.mint),
      deriveAta(vaultAuth, tokenProg, params.mint),
    ])
    if (params.createVaultAtaIfMissing) {
      instructions.push(
        buildCreateAtaIdempotentIx({
          payer: params.depositor,
          ata: vaultAta,
          owner: vaultAuth,
          mint: params.mint,
          tokenProgram: tokenProg,
        }),
      )
    }
    instructions.push({
      programId: AUDREN_PROGRAM_ID,
      accounts: [
        { pubkey: params.depositor, isSigner: true, isWritable: true },
        { pubkey: poolPda.address, isSigner: false, isWritable: laneTarget.poolWritable },
        { pubkey: outPagePda.address, isSigner: false, isWritable: true },
        { pubkey: params.mint, isSigner: false, isWritable: false },
        { pubkey: depositorAta, isSigner: false, isWritable: true },
        { pubkey: vaultAta, isSigner: false, isWritable: true },
        { pubkey: tokenProg, isSigner: false, isWritable: false },
        { pubkey: laneTarget.rentVault, isSigner: false, isWritable: true },
        { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
      ],
      data,
    })
  }

  return { instructions, note }
}

/**
 * Tag 3: `Transfer` — private multi-asset transfer (1 input -> 2 blinded outputs: pay + change).
 * Runs Triptych + CrossBase2 + native Solana BatchedRangeProofU128 100% locally in browser!
 */
export async function buildTransferInstruction(params: {
  payer: Uint8Array
  poolId: number
  outPageId: bigint
  inputPageIds: bigint[]
  ring: RingSlotWitness[]
  inputNote: SpendableAudrenNote
  secretIndex: number
  recipient: AudrenRecipient
  changeAddr: AudrenRecipient
  payAmount: bigint
  memoText?: string
}): Promise<{
  instruction: SolanaInstruction
  payNote: PreparedFullNote
  changeNote: PreparedFullNote
  nullifier: Uint8Array
}> {
  if (params.payAmount > params.inputNote.amount) {
    throw new Error('Insufficient note balance')
  }
  const chgAmount = params.inputNote.amount - params.payAmount
  const m = params.inputPageIds.length === 1 ? 5 : params.inputPageIds.length === 2 ? 6 : 7

  const [payNote, changeNote] = await Promise.all([
    prepareShieldedNote({
      recipient: params.recipient,
      mint: params.inputNote.mint,
      amount: params.payAmount,
      blindAsset: true,
      blindValue: true,
      memoText: params.memoText ?? 'PAY',
    }),
    prepareShieldedNote({
      recipient: params.changeAddr,
      mint: params.inputNote.mint,
      amount: chgAmount,
      blindAsset: true,
      blindValue: true,
      memoText: 'CHANGE',
    }),
  ])

  const aSpend = payNote.assetTag
  const aSpendBlinding = payNote.assetBlinding
  const vSpend = compressPoint(
    decompressPoint(payNote.commitment).add(decompressPoint(changeNote.commitment)),
  )
  const vSpendEffBlinding = addL(
    addL(mulL(params.payAmount, payNote.assetBlinding), payNote.valueBlinding),
    addL(mulL(chgAmount, changeNote.assetBlinding), changeNote.valueBlinding),
  )

  const sPay = randomScalar()
  const sChg = randomScalar()
  const range128 = proveRangeU128(params.payAmount, sPay, chgAmount, sChg)

  const notesWire = concatBytes(encodeNoteWire(payNote), encodeNoteWire(changeNote))
  const ctxHash = await sha256(
    utf8('audren/v1/transfer'),
    AUDREN_PROGRAM_ID,
    u32le(params.poolId),
    new Uint8Array([m]),
    notesWire,
    range128.commitment1,
    range128.commitment2,
  )

  const [triptych, xbase2] = await Promise.all([
    proveTriptych({
      m,
      inputPageIds: params.inputPageIds,
      secretIndex: params.secretIndex,
      ring: params.ring,
      spendX: params.inputNote.spendX,
      aNoteBlinding: params.inputNote.assetBlinding,
      value: params.inputNote.amount,
      vNoteBlinding: params.inputNote.valueBlinding,
      aSpend,
      aSpendBlinding,
      vSpend,
      vSpendEffBlinding,
      ctxHash,
    }),
    proveCrossBase2(
      payNote.assetTag,
      payNote.commitment,
      range128.commitment1,
      params.payAmount,
      payNote.valueBlinding,
      sPay,
      changeNote.assetTag,
      changeNote.commitment,
      range128.commitment2,
      chgAmount,
      changeNote.valueBlinding,
      sChg,
      subL(changeNote.assetBlinding, payNote.assetBlinding),
      ctxHash,
    ),
  ])

  const data = concatBytes(
    new Uint8Array([TAG_TRANSFER, m]),
    notesWire,
    range128.commitment1,
    range128.commitment2,
    triptych.proof,
    xbase2,
    range128.proof,
  )

  const [poolPda, outPagePda, nullifierPda, laneTarget, ...inputPagePdas] = await Promise.all([
    derivePoolPda(params.poolId),
    deriveEpochPagePda(params.poolId, params.outPageId),
    deriveNullifierPda(params.poolId, triptych.nullifier),
    resolveOutLaneRentVault(params.poolId, params.outPageId),
    ...params.inputPageIds.map((pid) => deriveEpochPagePda(params.poolId, pid)),
  ])

  const accounts: SolanaAccountMeta[] = [
    { pubkey: params.payer, isSigner: true, isWritable: true },
    { pubkey: poolPda.address, isSigner: false, isWritable: laneTarget.poolWritable },
    { pubkey: outPagePda.address, isSigner: false, isWritable: true },
    { pubkey: nullifierPda.address, isSigner: false, isWritable: true },
    { pubkey: laneTarget.rentVault, isSigner: false, isWritable: true },
    { pubkey: ZK_ELGAMAL_PROOF_PROGRAM_ID, isSigner: false, isWritable: false },
    { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
    ...inputPagePdas.map((p) => ({ pubkey: p.address, isSigner: false, isWritable: false })),
  ]

  return {
    instruction: { programId: AUDREN_PROGRAM_ID, accounts, data },
    payNote,
    changeNote,
    nullifier: triptych.nullifier,
  }
}

/**
 * Tag 4: `Merge` — consolidate 2 same-asset shielded notes into 1 larger shielded note.
 * Enforces `MAX_MERGE_RING_SLOTS = 128` (max 64 + 64 slots) to stay well within Solana's 1.4M CU cap.
 */
export async function buildMergeInstruction(params: {
  payer: Uint8Array
  poolId: number
  outPageId: bigint
  input1PageIds: bigint[]
  ring1: RingSlotWitness[]
  note1: SpendableAudrenNote
  secretIndex1: number
  input2PageIds: bigint[]
  ring2: RingSlotWitness[]
  note2: SpendableAudrenNote
  secretIndex2: number
  ownerAddr: AudrenRecipient
  memoText?: string
}): Promise<{
  instruction: SolanaInstruction
  outNote: PreparedFullNote
  nullifier1: Uint8Array
  nullifier2: Uint8Array
}> {
  if (!bytesEqual(params.note1.mint, params.note2.mint)) {
    throw new Error('Merge inputs must share the same mint')
  }
  if (bytesEqual(params.note1.nullifier, params.note2.nullifier)) {
    throw new Error('Cannot merge a note with itself')
  }
  const totalAmount = params.note1.amount + params.note2.amount
  if (totalAmount > 0xffff_ffff_ffff_ffffn) {
    throw new Error('Merged amount exceeds u64 range')
  }
  const m1 = params.input1PageIds.length === 1 ? 5 : params.input1PageIds.length === 2 ? 6 : 7
  const m2 = params.input2PageIds.length === 1 ? 5 : params.input2PageIds.length === 2 ? 6 : 7
  if ((1 << m1) + (1 << m2) > MAX_MERGE_RING_SLOTS) {
    throw new Error('Combined merge ring width exceeds 128 slots (max 64 + 64)')
  }

  const outNote = await prepareShieldedNote({
    recipient: params.ownerAddr,
    mint: params.note1.mint,
    amount: totalAmount,
    blindAsset: true,
    blindValue: true,
    memoText: params.memoText ?? 'MERGE',
  })

  const aOutPt = decompressPoint(outNote.assetTag)
  const rIn1 = randomScalar()
  const rIn2 = subL(outNote.valueBlinding, rIn1)
  const vIn1 = compressPoint(mulRistretto(aOutPt, params.note1.amount).add(mulRistretto(H_PT, rIn1)))
  const vIn2 = compressPoint(mulRistretto(aOutPt, params.note2.amount).add(mulRistretto(H_PT, rIn2)))
  const vIn1Eff = addL(mulL(params.note1.amount, outNote.assetBlinding), rIn1)
  const vIn2Eff = addL(mulL(params.note2.amount, outNote.assetBlinding), rIn2)

  const sOut = randomScalar()
  const range64 = proveRangeU64(totalAmount, sOut)
  const outWire = encodeNoteWire(outNote)

  const ctxBase = await sha256(
    utf8('audren/v1/merge'),
    AUDREN_PROGRAM_ID,
    u32le(params.poolId),
    new Uint8Array([m1, m2]),
    outWire,
    vIn1,
    vIn2,
    range64.commitment,
  )
  const [ctx1, ctx2] = await Promise.all([
    sha256(utf8('leg1'), ctxBase),
    sha256(utf8('leg2'), ctxBase),
  ])

  const [t1, t2, xbase1] = await Promise.all([
    proveTriptych({
      m: m1,
      inputPageIds: params.input1PageIds,
      secretIndex: params.secretIndex1,
      ring: params.ring1,
      spendX: params.note1.spendX,
      aNoteBlinding: params.note1.assetBlinding,
      value: params.note1.amount,
      vNoteBlinding: params.note1.valueBlinding,
      aSpend: outNote.assetTag,
      aSpendBlinding: outNote.assetBlinding,
      vSpend: vIn1,
      vSpendEffBlinding: vIn1Eff,
      ctxHash: ctx1,
    }),
    proveTriptych({
      m: m2,
      inputPageIds: params.input2PageIds,
      secretIndex: params.secretIndex2,
      ring: params.ring2,
      spendX: params.note2.spendX,
      aNoteBlinding: params.note2.assetBlinding,
      value: params.note2.amount,
      vNoteBlinding: params.note2.valueBlinding,
      aSpend: outNote.assetTag,
      aSpendBlinding: outNote.assetBlinding,
      vSpend: vIn2,
      vSpendEffBlinding: vIn2Eff,
      ctxHash: ctx2,
    }),
    proveCrossBase1(
      outNote.assetTag,
      outNote.commitment,
      range64.commitment,
      totalAmount,
      outNote.valueBlinding,
      sOut,
      ctxBase,
    ),
  ])

  const data = concatBytes(
    new Uint8Array([TAG_MERGE, m1, m2]),
    outWire,
    vIn1,
    vIn2,
    range64.commitment,
    t1.proof,
    t2.proof,
    xbase1,
    range64.proof,
  )

  const [poolPda, outPagePda, n1Pda, n2Pda, laneTarget, ...allInputPagePdas] = await Promise.all([
    derivePoolPda(params.poolId),
    deriveEpochPagePda(params.poolId, params.outPageId),
    deriveNullifierPda(params.poolId, t1.nullifier),
    deriveNullifierPda(params.poolId, t2.nullifier),
    resolveOutLaneRentVault(params.poolId, params.outPageId),
    ...params.input1PageIds.map((pid) => deriveEpochPagePda(params.poolId, pid)),
    ...params.input2PageIds.map((pid) => deriveEpochPagePda(params.poolId, pid)),
  ])

  const accounts: SolanaAccountMeta[] = [
    { pubkey: params.payer, isSigner: true, isWritable: true },
    { pubkey: poolPda.address, isSigner: false, isWritable: laneTarget.poolWritable },
    { pubkey: outPagePda.address, isSigner: false, isWritable: true },
    { pubkey: n1Pda.address, isSigner: false, isWritable: true },
    { pubkey: n2Pda.address, isSigner: false, isWritable: true },
    { pubkey: laneTarget.rentVault, isSigner: false, isWritable: true },
    { pubkey: ZK_ELGAMAL_PROOF_PROGRAM_ID, isSigner: false, isWritable: false },
    { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
    ...allInputPagePdas.map((p) => ({ pubkey: p.address, isSigner: false, isWritable: false })),
  ]

  return {
    instruction: { programId: AUDREN_PROGRAM_ID, accounts, data },
    outNote,
    nullifier1: t1.nullifier,
    nullifier2: t2.nullifier,
  }
}

/**
 * Tag 5: `SwapViaRouter` — 1-tx non-custodial private DEX swap (Jupiter, Orca, Raydium, etc.).
 * When `amountIn === inputNote.amount` (full spend), requires ZERO Bulletproofs (~25 ms)!
 */
export async function buildSwapViaRouterInstruction(params: {
  payer: Uint8Array
  poolId: number
  outPageId: bigint
  shardId: number
  inputPageIds: bigint[]
  ring: RingSlotWitness[]
  inputNote: SpendableAudrenNote
  secretIndex: number
  mintOut: Uint8Array
  tokenProgramIn: Uint8Array
  tokenProgramOut: Uint8Array
  amountIn: bigint
  minAmountOut: bigint
  recipient: AudrenRecipient
  changeAddr: AudrenRecipient
  routerProgramId: Uint8Array
  routerIxData: Uint8Array
  routerAccounts: SolanaAccountMeta[]
  escrowIdx: number
  escrowInIdx: number
  escrowOutIdx: number
  memoText?: string
}): Promise<{
  instruction: SolanaInstruction
  outDesc: PreparedDynamicOutput
  changeNote: PreparedFullNote | null
  nullifier: Uint8Array
}> {
  if (params.amountIn <= 0n || params.amountIn > params.inputNote.amount) {
    throw new Error('Invalid swap amountIn')
  }
  if (params.minAmountOut <= 0n) {
    throw new Error('minAmountOut must be > 0')
  }
  const m = params.inputPageIds.length === 1 ? 5 : params.inputPageIds.length === 2 ? 6 : 7
  const chgAmount = params.inputNote.amount - params.amountIn
  const hasChange = chgAmount > 0n
  const flags = hasChange ? 1 : 0

  const outDesc = await prepareDynamicSwapOutput({
    recipient: params.recipient,
    mintOut: params.mintOut,
    minAmountOut: params.minAmountOut,
    memoText: params.memoText ?? 'JUP',
  })
  const outDescWire = encodeDynamicWire(outDesc)

  const gInBytes = await assetGenerator(params.inputNote.mint)
  const gInPt = decompressPoint(gInBytes)

  let changeNote: PreparedFullNote | null = null
  let cChg: Uint8Array | null = null
  let range64Proof: Uint8Array | null = null
  let sChg = 0n
  let vSpend: Uint8Array
  let vSpendEffBlinding: bigint

  if (hasChange) {
    changeNote = await prepareShieldedNote({
      recipient: params.changeAddr,
      mint: params.inputNote.mint,
      amount: chgAmount,
      blindAsset: false,
      blindValue: true,
      memoText: 'CHG',
    })
    sChg = randomScalar()
    const range = proveRangeU64(chgAmount, sChg)
    range64Proof = range.proof
    cChg = range.commitment
    vSpend = compressPoint(
      mulRistretto(gInPt, params.amountIn).add(decompressPoint(changeNote.commitment)),
    )
    vSpendEffBlinding = changeNote.valueBlinding
  } else {
    vSpend = compressPoint(mulRistretto(gInPt, params.amountIn))
    vSpendEffBlinding = 0n
  }

  const chgWireSlice = changeNote ? encodeNoteWire(changeNote) : new Uint8Array(0)
  const cChgSlice = cChg ?? new Uint8Array(0)
  const ctxHash = await sha256(
    utf8('audren/v1/swap_router'),
    AUDREN_PROGRAM_ID,
    u32le(params.poolId),
    new Uint8Array([m, params.shardId & 0xff, flags]),
    params.routerProgramId,
    params.inputNote.mint,
    params.mintOut,
    u64le(params.amountIn),
    u64le(params.minAmountOut),
    outDescWire,
    chgWireSlice,
    cChgSlice,
  )

  const triptych = await proveTriptych({
    m,
    inputPageIds: params.inputPageIds,
    secretIndex: params.secretIndex,
    ring: params.ring,
    spendX: params.inputNote.spendX,
    aNoteBlinding: params.inputNote.assetBlinding,
    value: params.inputNote.amount,
    vNoteBlinding: params.inputNote.valueBlinding,
    aSpend: gInBytes,
    aSpendBlinding: 0n,
    vSpend,
    vSpendEffBlinding,
    ctxHash,
  })

  const dataParts: Uint8Array[] = [
    new Uint8Array([TAG_SWAP_VIA_ROUTER, m, params.shardId & 0xff, flags]),
    u64le(params.amountIn),
    u64le(params.minAmountOut),
    new Uint8Array([params.escrowIdx, params.escrowInIdx, params.escrowOutIdx]),
    u16le(params.routerIxData.length),
    outDescWire,
  ]

  if (changeNote && cChg && range64Proof) {
    const xbase1 = await proveCrossBase1(
      changeNote.assetTag,
      changeNote.commitment,
      cChg,
      chgAmount,
      changeNote.valueBlinding,
      sChg,
      ctxHash,
    )
    dataParts.push(encodeNoteWire(changeNote), cChg, xbase1, range64Proof)
  }

  dataParts.push(triptych.proof, params.routerIxData)
  const data = concatBytes(...dataParts)

  const [poolPda, vaultAuthPda, escrowPda, outPagePda, nullifierPda, laneTarget, ...inputPagePdas] =
    await Promise.all([
      derivePoolPda(params.poolId),
      deriveVaultAuthPda(params.poolId),
      deriveSwapEscrowPda(params.poolId, params.shardId),
      deriveEpochPagePda(params.poolId, params.outPageId),
      deriveNullifierPda(params.poolId, triptych.nullifier),
      resolveOutLaneRentVault(params.poolId, params.outPageId),
      ...params.inputPageIds.map((pid) => deriveEpochPagePda(params.poolId, pid)),
    ])

  const [vaultIn, vaultOut] = await Promise.all([
    deriveAta(vaultAuthPda.address, params.tokenProgramIn, params.inputNote.mint),
    deriveAta(vaultAuthPda.address, params.tokenProgramOut, params.mintOut),
  ])

  const accounts: SolanaAccountMeta[] = [
    { pubkey: params.payer, isSigner: true, isWritable: true },
    { pubkey: poolPda.address, isSigner: false, isWritable: laneTarget.poolWritable },
    { pubkey: outPagePda.address, isSigner: false, isWritable: true },
    { pubkey: nullifierPda.address, isSigner: false, isWritable: true },
    { pubkey: laneTarget.rentVault, isSigner: false, isWritable: true },
    { pubkey: ZK_ELGAMAL_PROOF_PROGRAM_ID, isSigner: false, isWritable: false },
    { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
    { pubkey: vaultAuthPda.address, isSigner: false, isWritable: false },
    { pubkey: params.inputNote.mint, isSigner: false, isWritable: false },
    { pubkey: vaultIn, isSigner: false, isWritable: true },
    { pubkey: params.tokenProgramIn, isSigner: false, isWritable: false },
    { pubkey: params.mintOut, isSigner: false, isWritable: false },
    { pubkey: vaultOut, isSigner: false, isWritable: true },
    { pubkey: params.tokenProgramOut, isSigner: false, isWritable: false },
    { pubkey: params.routerProgramId, isSigner: false, isWritable: false },
    ...inputPagePdas.map((p) => ({ pubkey: p.address, isSigner: false, isWritable: false })),
    ...params.routerAccounts.map((meta) => ({
      pubkey: meta.pubkey,
      isSigner: bytesEqual(meta.pubkey, escrowPda.address) ? false : meta.isSigner,
      isWritable: meta.isWritable,
    })),
  ]

  return {
    instruction: { programId: AUDREN_PROGRAM_ID, accounts, data },
    outDesc,
    changeNote,
    nullifier: triptych.nullifier,
  }
}

/**
 * Tag 6: `Withdraw` — unshield exact amount to any public Solana wallet (full or partial).
 * Full note withdraw requires ZERO Bulletproofs (~25 ms in browser)!
 */
export async function buildWithdrawInstruction(params: {
  payer: Uint8Array
  poolId: number
  outPageId: bigint
  inputPageIds: bigint[]
  ring: RingSlotWitness[]
  inputNote: SpendableAudrenNote
  secretIndex: number
  recipientAccount: Uint8Array // wallet pubkey for SOL, or recipient ATA for SPL/Token-2022
  changeAddr: AudrenRecipient
  amount: bigint
  splTokenProgram?: Uint8Array
}): Promise<{
  instruction: SolanaInstruction
  changeNote: PreparedFullNote | null
  nullifier: Uint8Array
}> {
  if (params.amount <= 0n || params.amount > params.inputNote.amount) {
    throw new Error('Invalid withdraw amount')
  }
  const m = params.inputPageIds.length === 1 ? 5 : params.inputPageIds.length === 2 ? 6 : 7
  const isNative = params.inputNote.isNativeSol
  const chgAmount = params.inputNote.amount - params.amount
  const hasChange = chgAmount > 0n

  const gMintBytes = await assetGenerator(params.inputNote.mint)
  const gMintPt = decompressPoint(gMintBytes)

  let changeNote: PreparedFullNote | null = null
  let cChg: Uint8Array | null = null
  let range64Proof: Uint8Array | null = null
  let sChg = 0n
  let vSpend: Uint8Array
  let vSpendEffBlinding: bigint

  if (hasChange) {
    changeNote = await prepareShieldedNote({
      recipient: params.changeAddr,
      mint: params.inputNote.mint,
      amount: chgAmount,
      blindAsset: false,
      blindValue: true,
      memoText: 'CHG',
    })
    sChg = randomScalar()
    const range = proveRangeU64(chgAmount, sChg)
    range64Proof = range.proof
    cChg = range.commitment
    vSpend = compressPoint(
      mulRistretto(gMintPt, params.amount).add(decompressPoint(changeNote.commitment)),
    )
    vSpendEffBlinding = changeNote.valueBlinding
  } else {
    vSpend = compressPoint(mulRistretto(gMintPt, params.amount))
    vSpendEffBlinding = 0n
  }

  const chgWireSlice = changeNote ? encodeNoteWire(changeNote) : new Uint8Array(0)
  const cChgSlice = cChg ?? new Uint8Array(0)
  const ctxHash = await sha256(
    utf8('audren/v1/withdraw'),
    AUDREN_PROGRAM_ID,
    u32le(params.poolId),
    new Uint8Array([m, isNative ? 1 : 0, hasChange ? 1 : 0]),
    params.inputNote.mint,
    params.recipientAccount,
    u64le(params.amount),
    chgWireSlice,
    cChgSlice,
  )

  const triptych = await proveTriptych({
    m,
    inputPageIds: params.inputPageIds,
    secretIndex: params.secretIndex,
    ring: params.ring,
    spendX: params.inputNote.spendX,
    aNoteBlinding: params.inputNote.assetBlinding,
    value: params.inputNote.amount,
    vNoteBlinding: params.inputNote.valueBlinding,
    aSpend: gMintBytes,
    aSpendBlinding: 0n,
    vSpend,
    vSpendEffBlinding,
    ctxHash,
  })

  const dataParts: Uint8Array[] = [
    new Uint8Array([TAG_WITHDRAW, m, isNative ? 1 : 0, hasChange ? 1 : 0]),
    u64le(params.amount),
  ]

  if (changeNote && cChg && range64Proof) {
    const xbase1 = await proveCrossBase1(
      changeNote.assetTag,
      changeNote.commitment,
      cChg,
      chgAmount,
      changeNote.valueBlinding,
      sChg,
      ctxHash,
    )
    dataParts.push(encodeNoteWire(changeNote), cChg, xbase1, range64Proof)
  }
  dataParts.push(triptych.proof)
  const data = concatBytes(...dataParts)

  const [poolPda, outPagePda, nullifierPda, laneTarget, poolRentVaultPda, ...inputPagePdas] =
    await Promise.all([
      derivePoolPda(params.poolId),
      deriveEpochPagePda(params.poolId, params.outPageId),
      deriveNullifierPda(params.poolId, triptych.nullifier),
      resolveOutLaneRentVault(params.poolId, params.outPageId),
      derivePageRentVaultPda(params.poolId),
      ...params.inputPageIds.map((pid) => deriveEpochPagePda(params.poolId, pid)),
    ])

  // Full withdrawals (!hasChange) always pass canonical Pool PageRentVault (read-only) to match
  // on-chain `check_page_rent_vault`, while keeping PoolState & out_page strictly read-only!
  const rentVaultAddress = hasChange ? laneTarget.rentVault : poolRentVaultPda.address

  const accounts: SolanaAccountMeta[] = [
    { pubkey: params.payer, isSigner: true, isWritable: true },
    // Full withdrawals keep PoolState strictly READ-ONLY (non-custodial pause escape hatch + zero contention!)
    { pubkey: poolPda.address, isSigner: false, isWritable: hasChange && laneTarget.poolWritable },
    { pubkey: outPagePda.address, isSigner: false, isWritable: hasChange },
    { pubkey: nullifierPda.address, isSigner: false, isWritable: true },
    { pubkey: rentVaultAddress, isSigner: false, isWritable: hasChange },
    { pubkey: ZK_ELGAMAL_PROOF_PROGRAM_ID, isSigner: false, isWritable: false },
    { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
  ]

  if (isNative) {
    const solVault = (await deriveSolVaultPda(params.poolId)).address
    accounts.push(
      { pubkey: solVault, isSigner: false, isWritable: true },
      { pubkey: params.recipientAccount, isSigner: false, isWritable: true },
    )
  } else {
    const tokenProg = params.splTokenProgram ?? CLASSIC_TOKEN_PROGRAM_ID
    const vaultAuth = (await deriveVaultAuthPda(params.poolId)).address
    const vaultAta = await deriveAta(vaultAuth, tokenProg, params.inputNote.mint)
    accounts.push(
      { pubkey: vaultAuth, isSigner: false, isWritable: false },
      { pubkey: params.inputNote.mint, isSigner: false, isWritable: false },
      { pubkey: vaultAta, isSigner: false, isWritable: true },
      { pubkey: params.recipientAccount, isSigner: false, isWritable: true },
      { pubkey: tokenProg, isSigner: false, isWritable: false },
    )
  }

  for (const p of inputPagePdas) {
    accounts.push({ pubkey: p.address, isSigner: false, isWritable: false })
  }

  return {
    instruction: { programId: AUDREN_PROGRAM_ID, accounts, data },
    changeNote,
    nullifier: triptych.nullifier,
  }
}

/**
 * Tag 8 (`WriteProofBuffer`) + Tag 9 (`ExecBuffered`) splitter.
 * Used automatically when self-paying via Phantom/Solflare over standard v0 (<= 1,232 B)
 * OR if a multi-hop swap exceeds Solana v1's 4,096 B limit.
 * `ExecBuffered` closes the ephemeral PDA and refunds 100% of rent to `payer` atomically.
 */
export async function buildBufferedExecutionPlan(
  inner: SolanaInstruction,
  nonce?: bigint,
): Promise<{
  nonce: bigint
  proofBufferPda: Uint8Array
  uploadChunks: SolanaInstruction[]
  executeIx: SolanaInstruction
}> {
  if (inner.data.length < 2) throw new Error('Empty inner instruction')
  const innerTag = inner.data[0]
  const payload = inner.data.subarray(1)
  if (payload.length > PROOF_BUFFER_MAX_PAYLOAD) {
    throw new Error(`Payload ${payload.length} B exceeds ProofBuffer 9,984 B cap`)
  }
  const payer = inner.accounts[0].pubkey
  const bufNonce =
    nonce ?? readU64le(crypto.getRandomValues(new Uint8Array(8)), 0)
  const proofBufferPda = (await deriveProofBufferPda(payer, bufNonce)).address

  const uploadChunks: SolanaInstruction[] = []
  for (let idx = 0, off = 0; off < payload.length; idx++, off += PROOF_BUFFER_CHUNK_SIZE) {
    const chunk = payload.subarray(off, Math.min(off + PROOF_BUFFER_CHUNK_SIZE, payload.length))
    uploadChunks.push({
      programId: AUDREN_PROGRAM_ID,
      accounts: [
        { pubkey: payer, isSigner: true, isWritable: true },
        { pubkey: proofBufferPda, isSigner: false, isWritable: true },
        { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
      ],
      data: concatBytes(
        new Uint8Array([TAG_WRITE_PROOF_BUFFER]),
        u64le(bufNonce),
        u32le(payload.length),
        new Uint8Array([idx]),
        chunk,
      ),
    })
  }

  const executeIx: SolanaInstruction = {
    programId: AUDREN_PROGRAM_ID,
    accounts: [{ pubkey: proofBufferPda, isSigner: false, isWritable: true }, ...inner.accounts],
    data: new Uint8Array([TAG_EXEC_BUFFERED, innerTag]),
  }

  return { nonce: bufNonce, proofBufferPda, uploadChunks, executeIx }
}
