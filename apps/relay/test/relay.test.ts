import test from 'node:test'
import assert from 'node:assert/strict'
import { registerHooks } from 'node:module'
import { DatabaseSync } from 'node:sqlite'
import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_PUBLIC,
  AUDREN_PROGRAM_ID,
  CKPT_LEN,
  CKPT_MAGIC,
  CK_OFF_EPOCH_ID,
  CK_OFF_LANE_COUNTS,
  CK_OFF_POOL_ID,
  CK_OFF_PUBLISHED_SLOT,
  CK_OFF_SLOT_IDX,
  CK_OFF_VERSION,
  CLASSIC_TOKEN_PROGRAM_ID,
  LANE_MAGIC,
  LANE_STATE_LEN,
  LN_OFF_LANE_ID,
  LN_OFF_NEXT_LEAF,
  LN_OFF_NF_COUNT,
  LN_OFF_POOL_ID,
  LN_OFF_VERSION,
  MEMO_ENTRY_WIRE_LEN,
  MEMO_NOTES_PER_PAGE,
  MEMO_PAGE_LEN,
  NF_PAGE_LEN,
  NUM_ESCROW_SHARDS,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_NULLIFIER,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  PL_OFF_ACTIVE_LANES,
  PL_OFF_CKPT_INTERVAL,
  PL_OFF_MAX_CKPT_AGE,
  PL_OFF_NF_RENT_FEE,
  PL_OFF_NOTE_RENT_FEE,
  PL_OFF_POOL_ID,
  PL_OFF_VERSION,
  POOL_MAGIC,
  POOL_STATE_LEN,
  PROTOCOL_VERSION,
  SUBROOT_PAGE_LEN,
  SUBTREE_PAGE_LEN,
  SYSTEM_PROGRAM_ID,
  TAG_DEPOSIT,
  TAG_EXEC_VIA_ESCROW,
  TAG_OPEN_PAGE,
  TAG_PUBLISH_CHECKPOINT,
  TAG_TRANSACT,
  TOKEN_2022_PROGRAM_ID,
  WSOL_MINT,
  base58Encode,
  buildDepositInstruction,
  buildExecViaEscrowInstruction,
  buildTransactInstruction,
  computeNoteCommitment,
  deriveAssetId,
  deriveAssociatedTokenAddressSync,
  deriveCheckpointPdaSync,
  deriveEscrowPdaSync,
  deriveKeysFromSeed,
  deriveLanePdaSync,
  deriveLaneRentVaultPdaSync,
  deriveMemoPdaSync,
  deriveNfPagePdaSync,
  derivePoolPdaSync,
  deriveStealthOwner,
  deriveSubrootPdaSync,
  deriveSubtreePdaSync,
  deriveVaultAuthPdaSync,
  encryptNoteMemo,
  exportFullViewingKey,
  frToBeBytes,
} from '@audren/sdk'
import { DEFAULT_ALLOWED_PRE_IX_PROGRAMS, getRelayerFvk, loadPolicyConfig, type Env } from '../src/env'
import { okxAdapter } from '../src/aggregators/okx'
import { findExcludedCpiVenue } from '../src/aggregators/registry'
import { titanAdapter } from '../src/aggregators/titan'
import { FirewallError, validateRelaySubmission } from '../src/policy/firewall'
import { computeNativeFeeQuote, computeSwapFeePlan } from '../src/policy/pricing'
import { parseExecEscrowMeta, parseTransactMeta } from '../src/solana/audren'
import { evaluateCheckpointState, fetchPoolCheckpointSnapshot } from '../src/solana/checkpoint'
import {
  base58Decode,
  fromBase64,
  readU16le,
  readU32le,
  readU64le,
  toBase64,
  toHex,
  utf8,
} from '../src/solana/codec'
import { computeSwapInputTransferFee, fetchLiveRentSchedule } from '../src/solana/rpc'

// Provide a lightweight stub for Cloudflare's `cloudflare:workers` built-in module when
// exercising the full Worker HTTP router (`src/index.ts`) and `RelayGuard` DO inside Node's test runner.
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'cloudflare:workers') {
      return { url: 'node:cloudflare-workers-stub', shortCircuit: true }
    }
    return nextResolve(specifier, context)
  },
  load(url, context, nextLoad) {
    if (url === 'node:cloudflare-workers-stub') {
      return {
        format: 'module',
        shortCircuit: true,
        source: 'export class DurableObject { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }',
      }
    }
    return nextLoad(url, context)
  },
})

let cachedWorker: { fetch(request: Request, env: Env): Promise<Response> } | null = null
async function getWorker() {
  if (!cachedWorker) {
    const mod = await import('../src/index')
    cachedWorker = mod.default
  }
  return cachedWorker
}

async function getRelayGuardClass() {
  const mod = await import('../src/policy/guard-do')
  return mod.RelayGuard
}

/** Real SQLite adapter matching Cloudflare Durable Object `SqlStorage` using `node:sqlite`. */
function createSqliteDoHarness(preInitSql?: string) {
  const db = new DatabaseSync(':memory:')
  if (preInitSql) db.exec(preInitSql)

  const sql = {
    exec(query: string, ...bindings: unknown[]) {
      const trimmed = query.trim()
      // Multi-statement DDL batches (e.g. constructor schema init) have no bindings.
      if (bindings.length === 0 && trimmed.includes(';') && trimmed.indexOf(';') < trimmed.length - 1) {
        db.exec(query)
        return {
          toArray: () => [],
          one: () => ({}),
        }
      }
      const stmt = db.prepare(query)
      const upper = trimmed.toUpperCase()
      const isRead = upper.startsWith('SELECT') || upper.startsWith('PRAGMA')
      if (isRead) {
        const rows = stmt.all(...(bindings as never[])) as Array<Record<string, unknown>>
        return {
          toArray: () => rows,
          one: () => {
            if (rows.length === 0) throw new Error(`Expected 1 row for query: ${query}`)
            return rows[0]!
          },
        }
      }
      stmt.run(...(bindings as never[]))
      return {
        toArray: () => [],
        one: () => ({}),
      }
    },
  }

  let initPromise: Promise<void> = Promise.resolve()
  const ctx = {
    storage: { sql },
    blockConcurrencyWhile<T>(fn: () => Promise<T>): Promise<T> {
      const p = fn()
      initPromise = p.then(() => undefined)
      return p
    },
  } as unknown as DurableObjectState

  return { db, ctx, ready: () => initPromise }
}

const relayerSecret = new Uint8Array(32).fill(0x42)
const relayerPubkey = ed25519.getPublicKey(relayerSecret)
const relayerB58 = base58Encode(relayerPubkey)

const relayerShieldedKeys = deriveKeysFromSeed(new Uint8Array(32).fill(0x91))
const relayerFvk = exportFullViewingKey(relayerShieldedKeys)
const allowedPre = new Set(DEFAULT_ALLOWED_PRE_IX_PROGRAMS)

const nf0 = new Uint8Array(32).fill(0x01)
const nf1NonZero = new Uint8Array(32).fill(0x02)
const nf1Zero = new Uint8Array(32)
const dummyProof = new Uint8Array(192).fill(0xaa)
const wsolMintBytes = base58Decode(WSOL_MINT)
const USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'

function makeShieldedFeeCm2(feeAmount: bigint, mint32: Uint8Array = wsolMintBytes, ephFill = 0x77) {
  const { tweak, blinding, memo } = encryptNoteMemo(
    relayerShieldedKeys.viewPk,
    new Uint8Array(32).fill(ephFill),
    feeAmount,
    mint32,
  )
  const stealth = deriveStealthOwner(relayerShieldedKeys.spendPk, tweak)
  const asset = deriveAssetId(mint32)
  const cm2 = frToBeBytes(computeNoteCommitment(stealth, asset, feeAmount, blinding))
  return { cm2, memo }
}

test('Canonical v1 Pool #0 PDAs and constants match spec', () => {
  assert.equal(PROTOCOL_VERSION, 1)
  assert.equal(MEMO_PAGE_LEN, 10_240)
  assert.equal(MEMO_NOTES_PER_PAGE, 96)
  assert.equal(MEMO_ENTRY_WIRE_LEN, 106)
  assert.equal(derivePoolPdaSync(0).address, '5Bvt5f5QMfsVb9TyX8bzkRMvAX6JSWwRtnymGveF9U3G')
  assert.equal(deriveVaultAuthPdaSync(0).address, '3aMtBvVMatfBvoBWQaTxCPwQ2SWyW5ejceVgLFTtk2WF')
})

test('Firewall rejects Deposit (Tag 3), extra signers, and non-zero vk_id', () => {
  const depIx = buildDepositInstruction({
    depositor: relayerB58,
    poolId: 0,
    laneId: 0,
    subPageSeq: 0n,
    rootPageSeq: 0n,
    memoPageSeq: 0n,
    nativeSol: true,
    amount: 1_000_000n,
    stealthOwner: 1n,
    blinding: 2n,
    memo: new Uint8Array(MEMO_ENTRY_WIRE_LEN),
  })
  assert.equal(depIx.data[0], TAG_DEPOSIT)
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructionDataB64: toBase64(depIx.data), accounts: depIx.accounts },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('Deposit Tag 3'),
  )

  // Non-zero vk_id on Transact (Tag 5) MUST be rejected!
  const badVkTx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    vkId: 1,
    ckptSlotIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b001,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: dummyProof,
    nf0,
    nf1: nf1NonZero,
    cm0: new Uint8Array(32).fill(0x10),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x11),
  })
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructionDataB64: toBase64(badVkTx.data), accounts: badVkTx.accounts },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('vk_id'),
  )

  // Extra signer on Transact MUST be rejected!
  const validTx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    ckptSlotIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b001,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: dummyProof,
    nf0,
    nf1: nf1NonZero,
    cm0: new Uint8Array(32).fill(0x10),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x11),
  })
  const extraSignerAccs = validTx.accounts.map((a, idx) => (idx === 1 ? { ...a, isSigner: true } : a))
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructionDataB64: toBase64(validTx.data), accounts: extraSignerAccs },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('extra signer'),
  )
})

test('Firewall Mode 1: Transact (Tag 5) verifies 106 B shielded cm2 fee note via read-only FVK, rejects forged cm2 and bad memo length', () => {
  const feeAmount = 2_000_000n
  const { cm2, memo } = makeShieldedFeeCm2(feeAmount, wsolMintBytes)

  // outputMask = 0b101 (outputs 0 and 2 active => memos = 2 * 106 = 212 B)
  const memos = new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN)
  memos.set(new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x11), 0)
  memos.set(memo, MEMO_ENTRY_WIRE_LEN)

  const ix = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    ckptSlotIdx: 1,
    outLaneId: 2,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b101,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: dummyProof,
    nf0,
    nf1: nf1NonZero,
    cm0: new Uint8Array(32).fill(0x10),
    cm1: new Uint8Array(32),
    cm2,
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: memos,
  })

  const verdict = validateRelaySubmission(
    { instructionDataB64: toBase64(ix.data), accounts: ix.accounts },
    relayerPubkey,
    allowedPre,
    relayerFvk,
  )
  assert.equal(verdict.opKind, 'transfer')
  assert.equal(verdict.tag, TAG_TRANSACT)
  assert.equal(verdict.outLaneId, 2)
  assert.equal(verdict.nullifiers.length, 2)
  assert.ok(verdict.shieldedCm2Fee)
  assert.equal(verdict.shieldedCm2Fee.mint, WSOL_MINT)
  assert.equal(verdict.shieldedCm2Fee.amount, feeAmount)

  // Forged cm2 commitment MUST NOT earn shielded fee credit
  const badCm2 = new Uint8Array(cm2)
  badCm2[31] ^= 1
  const badIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    ckptSlotIdx: 1,
    outLaneId: 2,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b101,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: dummyProof,
    nf0,
    nf1: nf1NonZero,
    cm0: new Uint8Array(32).fill(0x10),
    cm1: new Uint8Array(32),
    cm2: badCm2,
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: memos,
  })
  const badVerdict = validateRelaySubmission(
    { instructionDataB64: toBase64(badIx.data), accounts: badIx.accounts },
    relayerPubkey,
    allowedPre,
    relayerFvk,
  )
  assert.equal(badVerdict.shieldedCm2Fee, null)

  // Truncated memo length (not a multiple of 106 B) MUST be rejected
  const truncatedData = ix.data.slice(0, ix.data.length - 16)
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructionDataB64: toBase64(truncatedData), accounts: ix.accounts },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    FirewallError,
  )
})

test('Firewall Mode 2: Transact (Tag 5) WSOL unwrap withdraw & SPL withdraw + canonical ATA & fee recipient enforcement', () => {
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const vaultWsolAta = deriveAssociatedTokenAddressSync(
    vaultAuth,
    WSOL_MINT,
    CLASSIC_TOKEN_PROGRAM_ID,
  ).address
  const recipient = base58Encode(new Uint8Array(32).fill(0x33))

  // 1. Atomic WSOL unwrap withdraw (ASSET_MODE_PUBLIC + WITHDRAW_FLAG_UNWRAP_WSOL)
  const ix = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    ckptSlotIdx: 2,
    outLaneId: 1,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: true,
    publicOutflow: {
      mint: WSOL_MINT,
      vaultAta: vaultWsolAta,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    },
    proof192: dummyProof,
    nf0,
    nf1: nf1NonZero,
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 1_000_000_000n,
    relayerFeeAmount: 10_000_000n,
    recipient,
    relayerFeeRecipient: relayerB58,
    memosBytes: new Uint8Array(0),
  })
  const v = validateRelaySubmission(
    { instructionDataB64: toBase64(ix.data), accounts: ix.accounts },
    relayerPubkey,
    allowedPre,
    relayerFvk,
  )
  assert.equal(v.opKind, 'withdraw')
  assert.equal(v.nativeSolFeeToRelayer, 10_000_000n)

  // 2. Spoofed fee recipient on WSOL unwrap withdraw MUST be rejected
  const spoofed = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    ckptSlotIdx: 2,
    outLaneId: 1,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: true,
    publicOutflow: {
      mint: WSOL_MINT,
      vaultAta: vaultWsolAta,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    },
    proof192: dummyProof,
    nf0,
    nf1: nf1NonZero,
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 1_000_000_000n,
    relayerFeeAmount: 10_000_000n,
    recipient,
    relayerFeeRecipient: recipient,
    memosBytes: new Uint8Array(0),
  })
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructionDataB64: toBase64(spoofed.data), accounts: spoofed.accounts },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    FirewallError,
  )

  // 3. SPL withdraw (USDC) watches canonical relayer USDC ATA and rejects non-canonical vault ATA
  const vaultUsdcAta = deriveAssociatedTokenAddressSync(vaultAuth, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const recipientUsdcAta = deriveAssociatedTokenAddressSync(recipient, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const relayerUsdcAta = deriveAssociatedTokenAddressSync(relayerB58, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const splIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    ckptSlotIdx: 2,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: false,
    publicOutflow: {
      mint: USDC_MINT,
      vaultAta: vaultUsdcAta,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    },
    proof192: dummyProof,
    nf0,
    nf1: nf1NonZero,
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 50_000_000n,
    relayerFeeAmount: 500_000n,
    recipient: recipientUsdcAta,
    relayerFeeRecipient: relayerUsdcAta,
    memosBytes: new Uint8Array(0),
  })
  const splVerdict = validateRelaySubmission(
    { instructionDataB64: toBase64(splIx.data), accounts: splIx.accounts },
    relayerPubkey,
    allowedPre,
    relayerFvk,
  )
  assert.equal(splVerdict.opKind, 'withdraw')
  assert.equal(splVerdict.watchedRelayerFeeAta, relayerUsdcAta)
  assert.equal(splVerdict.watchedRelayerFeeMint, USDC_MINT)

  // Non-canonical vault ATA (accounts[14]) MUST be rejected!
  const nonCanonicalVaultAccs = splIx.accounts.map((a, idx) =>
    idx === 14 ? { ...a, pubkey: recipientUsdcAta } : a,
  )
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructionDataB64: toBase64(splIx.data), accounts: nonCanonicalVaultAccs },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    FirewallError,
  )
})

test('Firewall Mode 3: ExecViaEscrow (Tag 6) SPL/T22-only, 72 B dyn_memo_mask, EXEC_FLAG_FEE_ON_OUTPUT, canonical ATAs, and vk_id != 0 rejection', () => {
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const escrow = deriveEscrowPdaSync(0, 3).address
  const vaultInAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowInAta = deriveAssociatedTokenAddressSync(escrow, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultOutAta = deriveAssociatedTokenAddressSync(vaultAuth, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowOutAta = deriveAssociatedTokenAddressSync(escrow, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const relayerOutAta = deriveAssociatedTokenAddressSync(relayerB58, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address

  const ix = buildExecViaEscrowInstruction({
    payer: relayerB58,
    poolId: 0,
    ckptSlotIdx: 4,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    escrowShard: 3,
    changeMask: 0b01,
    feeOnOutput: true,
    inLeg: {
      mint: WSOL_MINT,
      vaultAta: vaultInAta,
      escrowAta: escrowInAta,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    },
    outLeg: {
      mint: USDC_MINT,
      vaultAta: vaultOutAta,
      escrowAta: escrowOutAta,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    },
    relayerFeeAmount: 500_000n,
    relayerFeeRecipient: relayerOutAta,
    proof192: dummyProof,
    nf0,
    nf1: nf1NonZero,
    cm0: new Uint8Array(32).fill(0x21),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    amountIn: 500_000_000n,
    minAmountOut: 50_000_000n,
    outStealthOwner: new Uint8Array(32).fill(0x02),
    outBlinding: new Uint8Array(32).fill(0x03),
    dynMemoHead: new Uint8Array(34).fill(0x04),
    dynMemoMask: new Uint8Array(72).fill(0x05),
    routerProg: base58Encode(new Uint8Array(32).fill(0x55)),
    routerIxData: new Uint8Array([1, 2, 3]),
    routerAccounts: [
      { pubkey: base58Encode(new Uint8Array(32).fill(0x66)), isSigner: false, isWritable: true },
    ],
    changeMemos: new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x09),
  })

  // Exact v1 wire size: 558 + 3 (routerIxData) + 106 (1 change memo) = 667 B
  assert.equal(ix.data[0], TAG_EXEC_VIA_ESCROW)
  assert.equal(ix.data.length, 558 + 3 + MEMO_ENTRY_WIRE_LEN)

  const v = validateRelaySubmission(
    { instructionDataB64: toBase64(ix.data), accounts: ix.accounts },
    relayerPubkey,
    allowedPre,
    relayerFvk,
  )
  assert.equal(v.opKind, 'exec_escrow')
  assert.equal(v.execMeta?.feeOnOutput, true)
  assert.equal(v.execMeta?.mintIn, WSOL_MINT)
  assert.equal(v.execMeta?.mintOut, USDC_MINT)
  assert.equal(v.watchedRelayerFeeAta, relayerOutAta)
  assert.equal(v.watchedRelayerFeeMint, USDC_MINT)

  // Non-zero vk_id on ExecViaEscrow (Tag 6) MUST be rejected!
  const badVkData = new Uint8Array(ix.data)
  badVkData[5] = 2
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructionDataB64: toBase64(badVkData), accounts: ix.accounts },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('vk_id'),
  )

  // Non-canonical escrow_in_ata (accounts[17]) MUST be rejected!
  const spoofedEscrowAccs = ix.accounts.map((a, idx) =>
    idx === 17 ? { ...a, pubkey: relayerOutAta } : a,
  )
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructionDataB64: toBase64(ix.data), accounts: spoofedEscrowAccs },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    FirewallError,
  )
})

test('3-mode dynamic pricing computes self_paying shielded_cm2, withdraw, and exec_escrow quotes with default omitNf1=false across ALL ops', () => {
  const cfg = loadPolicyConfig({} as never)
  const rentSchedule = {
    nullifierRentLamports: 890_880n,
    nfPageRentPerNfLamports: 113_567n,
    pageRentPerNoteLamports: 1_500_000n,
    ataRentLamports: 2_039_280n,
    baseTxFeeLamports: 5_000n,
    swapBaselineLamports: 2n * (890_880n + 113_567n) + 2n * 1_500_000n + 20_000n,
    fetchedAt: Date.now(),
  }

  // Transfer defaults to 2 nullifiers (omitNf1 = false)
  const qTransfer = computeNativeFeeQuote({
    cluster: 'mainnet',
    op: 'transfer',
    cfg,
    rentSchedule,
    feeSide: 'shielded_cm2',
    feeMint: WSOL_MINT,
    feeTokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    feeDecimals: 9,
    amount: 1_000_000_000n,
    outputCount: 3,
    feeRecipient: null,
    feeShieldedAddress: relayerShieldedKeys.address,
    feeRecipientExists: true,
    solPriceUsd: 150,
    feeTokenPriceUsd: 150,
  })
  assert.equal(qTransfer.billingMode, 'self_paying')
  assert.equal(qTransfer.feeSide, 'shielded_cm2')
  assert.equal(qTransfer.nullifierCount, 2)
  assert.equal(qTransfer.feeShieldedAddress, relayerShieldedKeys.address)
  assert.ok(BigInt(qTransfer.relayerFee) > 5_000_000n)

  // Withdraw ALSO defaults to 2 nullifiers (omitNf1 = false)
  const qWithdraw = computeNativeFeeQuote({
    cluster: 'mainnet',
    op: 'withdraw',
    cfg,
    rentSchedule,
    unwrapWsol: true,
    feeSide: 'in',
    feeMint: WSOL_MINT,
    feeTokenProgram: null,
    feeDecimals: 9,
    amount: 2_000_000_000n,
    outputCount: 0,
    feeRecipient: relayerB58,
    feeRecipientExists: true,
    solPriceUsd: 150,
    feeTokenPriceUsd: 150,
  })
  assert.equal(qWithdraw.billingMode, 'self_paying')
  assert.equal(qWithdraw.nullifierCount, 2)
  assert.equal(qWithdraw.relayerFee, '5000000') // 25 bps of 2 SOL > 1.1x 2-nf rent

  // ExecViaEscrow ALSO defaults to 2 nullifiers (omitNf1 = false)
  const qExec = computeNativeFeeQuote({
    cluster: 'mainnet',
    op: 'exec_escrow',
    cfg,
    rentSchedule,
    feeSide: 'out',
    feeMint: USDC_MINT,
    feeTokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    feeDecimals: 6,
    amount: 500_000_000n,
    feeRecipient: deriveAssociatedTokenAddressSync(relayerB58, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address,
    feeRecipientExists: true,
    solPriceUsd: 150,
    feeTokenPriceUsd: 1,
  })
  assert.equal(qExec.billingMode, 'self_paying')
  assert.equal(qExec.nullifierCount, 2)

  // Unsafe Token-2022 output mints must never be billed as self_paying in swap fee plans
  const unsafePlan = computeSwapFeePlan({
    cfg,
    rentSchedule,
    outputMint: USDC_MINT,
    outputDecimals: 6,
    estimatedOutAmount: 500_000_000n,
    solPriceUsd: 150,
    outputTokenPriceUsd: 1,
    feeAccount: relayerB58,
    feeAccountExists: true,
    hasUnsafeSelfPayExt: true,
  })
  assert.equal(unsafePlan.billingMode, 'sponsored')
  assert.equal(unsafePlan.platformFeeBps, 0)
  assert.equal(unsafePlan.feeAccount, null)
})

test('getRelayerFvk accepts both *Hex and short field names', () => {
  const canonicalJson = JSON.stringify({
    spendPkHex: toHex(relayerFvk.spendPk),
    nkHex: toHex(relayerFvk.nk),
    viewSkHex: toHex(relayerFvk.viewSk),
    viewPkHex: toHex(relayerFvk.viewPk),
  })
  const shortJson = JSON.stringify({
    spendPk: toHex(relayerFvk.spendPk),
    nk: toHex(relayerFvk.nk),
    viewSk: toHex(relayerFvk.viewSk),
    viewPk: toHex(relayerFvk.viewPk),
  })
  const parsedCanonical = getRelayerFvk({ MAINNET_RELAYER_FVK_JSON: canonicalJson } as never, 'mainnet')
  const parsedShort = getRelayerFvk({ MAINNET_RELAYER_FVK_JSON: shortJson } as never, 'mainnet')
  assert.ok(parsedCanonical)
  assert.ok(parsedShort)
  assert.equal(parsedCanonical.shieldedAddress, relayerShieldedKeys.address)
  assert.equal(parsedShort.shieldedAddress, relayerShieldedKeys.address)
})

test('OKX and Titan swapInstructions skip SPL Token / Token-2022 wrapper instructions', async () => {
  const escrowPubkey = deriveEscrowPdaSync(0, 0).address
  const routerProg = base58Encode(new Uint8Array(32).fill(0x55))
  const tokenSyncIx = {
    programId: CLASSIC_TOKEN_PROGRAM_ID,
    data: toBase64(new Uint8Array([17])),
    accounts: [{ pubkey: escrowPubkey, isSigner: true, isWritable: true }],
  }
  const realSwapIx = {
    programId: routerProg,
    data: toBase64(new Uint8Array([1, 2, 3])),
    accounts: [{ pubkey: escrowPubkey, isSigner: true, isWritable: true }],
  }

  const okxBuilt = await okxAdapter.swapInstructions({} as never, {
    escrowPubkey,
    inputMint: WSOL_MINT,
    outputMint: USDC_MINT,
    quoteResponse: {
      escrowPubkey,
      instructionLists: [tokenSyncIx, realSwapIx],
    },
  })
  assert.equal(okxBuilt.swapInstruction.programId, routerProg)

  const titanBuilt = await titanAdapter.swapInstructions({} as never, {
    escrowPubkey,
    inputMint: WSOL_MINT,
    outputMint: USDC_MINT,
    quoteResponse: {
      escrowPubkey,
      route: { instructions: [tokenSyncIx, realSwapIx] },
    },
  })
  assert.equal(titanBuilt.swapInstruction.programId, routerProg)
})

test('findExcludedCpiVenue rejects BisonFi/Quantum/Kipseli and allows CPI-safe venues', () => {
  const mkRoute = (label: string) => ({
    routePlan: [
      {
        swapInfo: {
          label,
          inputMint: WSOL_MINT,
          outputMint: USDC_MINT,
          inAmount: '5000000',
          outAmount: '350000',
        },
        percent: 100,
      },
    ],
  })
  assert.equal(findExcludedCpiVenue(mkRoute('BisonFi')), 'BisonFi')
  assert.equal(findExcludedCpiVenue(mkRoute('BisonFi Predict')), 'BisonFi Predict')
  assert.equal(findExcludedCpiVenue(mkRoute('Quantum')), 'Quantum')
  assert.equal(findExcludedCpiVenue(mkRoute('Kipseli AMM')), 'Kipseli AMM')
  assert.equal(findExcludedCpiVenue(mkRoute('ZeroFi')), null)
  assert.equal(findExcludedCpiVenue(mkRoute('Raydium CLMM')), null)
  assert.equal(findExcludedCpiVenue(mkRoute('Orca Whirlpool')), null)
})

// ============================================================================
// Binary Fixture Builders & Mock Helpers
// ============================================================================

function writeAscii(buf: Uint8Array, offset: number, text: string): void {
  for (let i = 0; i < text.length; i++) buf[offset + i] = text.charCodeAt(i)
}

function makePoolStateBytes(params: {
  poolId?: number
  activeLanes?: number
  ckptInterval?: bigint
  maxCkptAge?: bigint
  noteRentFee?: bigint
  nfRentFee?: bigint
}): Uint8Array {
  const buf = new Uint8Array(POOL_STATE_LEN)
  const dv = new DataView(buf.buffer)
  writeAscii(buf, 0, POOL_MAGIC)
  buf[PL_OFF_VERSION] = PROTOCOL_VERSION
  buf[PL_OFF_ACTIVE_LANES] = params.activeLanes ?? 4
  dv.setUint32(PL_OFF_POOL_ID, params.poolId ?? 0, true)
  dv.setBigUint64(PL_OFF_CKPT_INTERVAL, params.ckptInterval ?? 16n, true)
  dv.setBigUint64(PL_OFF_MAX_CKPT_AGE, params.maxCkptAge ?? 3600n, true)
  dv.setBigUint64(PL_OFF_NOTE_RENT_FEE, params.noteRentFee ?? 1_000_000n, true)
  dv.setBigUint64(PL_OFF_NF_RENT_FEE, params.nfRentFee ?? 0n, true)
  return buf
}

function makeLaneStateBytes(params: {
  poolId?: number
  laneId: number
  nextLeaf: bigint
  nfCount?: bigint
}): Uint8Array {
  const buf = new Uint8Array(LANE_STATE_LEN)
  const dv = new DataView(buf.buffer)
  writeAscii(buf, 0, LANE_MAGIC)
  buf[LN_OFF_VERSION] = PROTOCOL_VERSION
  buf[LN_OFF_LANE_ID] = params.laneId
  dv.setUint32(LN_OFF_POOL_ID, params.poolId ?? 0, true)
  dv.setBigUint64(LN_OFF_NEXT_LEAF, params.nextLeaf, true)
  dv.setBigUint64(LN_OFF_NF_COUNT, params.nfCount ?? 0n, true)
  return buf
}

function makeCheckpointBytes(params: {
  poolId?: number
  slotIdx: number
  epochId: bigint
  publishedSlot: bigint
  laneCounts: bigint[]
}): Uint8Array {
  const buf = new Uint8Array(CKPT_LEN)
  const dv = new DataView(buf.buffer)
  writeAscii(buf, 0, CKPT_MAGIC)
  buf[CK_OFF_VERSION] = PROTOCOL_VERSION
  dv.setUint16(CK_OFF_SLOT_IDX, params.slotIdx, true)
  dv.setUint32(CK_OFF_POOL_ID, params.poolId ?? 0, true)
  dv.setBigUint64(CK_OFF_EPOCH_ID, params.epochId, true)
  dv.setBigUint64(CK_OFF_PUBLISHED_SLOT, params.publishedSlot, true)
  for (let i = 0; i < params.laneCounts.length; i++) {
    dv.setBigUint64(CK_OFF_LANE_COUNTS + i * 8, params.laneCounts[i]!, true)
  }
  return buf
}

function makeClassicMintBytes(decimals: number): Uint8Array {
  const buf = new Uint8Array(82)
  buf[44] = decimals
  buf[45] = 1 // is_initialized
  return buf
}

function makeToken2022TransferFeeMintBytes(params: {
  decimals: number
  olderEpoch: bigint
  olderMaxFee: bigint
  olderBps: number
  newerEpoch: bigint
  newerMaxFee: bigint
  newerBps: number
}): Uint8Array {
  // 82 B Mint + 83 B zero padding + 1 B AccountType(1 = Mint) + 4 B TLV header + 108 B TransferFeeConfig
  const buf = new Uint8Array(166 + 4 + 108)
  const dv = new DataView(buf.buffer)
  buf[44] = params.decimals
  buf[45] = 1 // is_initialized
  buf[165] = 1 // AccountType::Mint
  dv.setUint16(166, 1, true) // ExtensionType::TransferFeeConfig = 1
  dv.setUint16(168, 108, true) // length = 108
  const valStart = 170
  dv.setBigUint64(valStart + 72, params.olderEpoch, true)
  dv.setBigUint64(valStart + 80, params.olderMaxFee, true)
  dv.setUint16(valStart + 88, params.olderBps, true)
  dv.setBigUint64(valStart + 90, params.newerEpoch, true)
  dv.setBigUint64(valStart + 98, params.newerMaxFee, true)
  dv.setUint16(valStart + 106, params.newerBps, true)
  return buf
}

function createMockGuard(overrides?: Partial<{
  rateDecision: { allowed: boolean; status?: number; code?: string; reason?: string; retryAfterSec?: number }
  acquireResult: {
    allowed: boolean
    inFlight?: boolean
    waitMs?: number
    alreadyPublished?: boolean
    lastEpoch?: number
    lastSignature?: string
  }
}>) {
  const releasedCalls: Array<Record<string, unknown>> = []
  const acquireCalls: Array<Record<string, unknown>> = []
  const relayBeginCalls: Array<Record<string, unknown>> = []
  const relayReleaseCalls: Array<Record<string, unknown>> = []
  const relayAuthorizeCalls: Array<Record<string, unknown>> = []
  const relayCommitCalls: Array<Record<string, unknown>> = []
  const stub = {
    async begin(req: Record<string, unknown>) {
      relayBeginCalls.push(req)
      return { allowed: true, ipHash: 'mock-ephemeral-ip-hash' }
    },
    async authorizeSpend(req: Record<string, unknown>) {
      relayAuthorizeCalls.push(req)
      return { allowed: true, reservationId: 'mock-res-1' }
    },
    async commit(req: Record<string, unknown>) {
      relayCommitCalls.push(req)
    },
    async release(req: Record<string, unknown>) {
      relayReleaseCalls.push(req)
    },
    async checkCheckpointRateLimit() {
      return overrides?.rateDecision ?? { allowed: true, ipHash: 'mock-ephemeral-ip-hash' }
    },
    async acquireCheckpointLock(req: Record<string, unknown>) {
      acquireCalls.push(req)
      return overrides?.acquireResult ?? { allowed: true }
    },
    async releaseCheckpointLock(req: Record<string, unknown>) {
      releasedCalls.push(req)
    },
  }
  return {
    namespace: {
      idFromName: () => ({} as DurableObjectId),
      get: () => stub,
    } as unknown as Env['RELAY_GUARD'],
    acquireCalls,
    releasedCalls,
    relayBeginCalls,
    relayReleaseCalls,
    relayAuthorizeCalls,
    relayCommitCalls,
  }
}

async function withMockFetch<T>(
  handler: (input: string, init?: RequestInit) => Promise<Response> | Response,
  fn: () => Promise<T>,
): Promise<T> {
  const orig = globalThis.fetch
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    return handler(url, init)
  }) as typeof fetch
  try {
    return await fn()
  } finally {
    globalThis.fetch = orig
  }
}

// ============================================================================
// 1. RelayGuard DO Privacy Hardening (ephemeral daily salt + zero ip_hash on nullifiers)
// ============================================================================

test('RelayGuard DO: ephemeral per-day 32-byte random IP salt (not derived from pubkey) and ZERO ip_hash on inflight_nullifiers', async () => {
  const RelayGuard = await getRelayGuardClass()

  // Test fresh DO + legacy table migration (pre-populated with old `ip_hash` column!)
  const harness = createSqliteDoHarness(`
    CREATE TABLE inflight_nullifiers (
      nullifier TEXT PRIMARY KEY,
      ip_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
  `)
  const guard = new RelayGuard(harness.ctx, {} as Env)
  await harness.ready()

  // 1. Verify `inflight_nullifiers` schema has ZERO `ip_hash` column after constructor migration
  const cols = harness.db
    .prepare('PRAGMA table_info(inflight_nullifiers)')
    .all() as Array<{ name: string }>
  const colNames = cols.map((c) => c.name)
  assert.deepEqual(colNames, ['nullifier', 'expires_at'])
  assert.ok(!colNames.includes('ip_hash'), 'inflight_nullifiers must NEVER contain ip_hash')

  // 2. Verify ephemeral daily 32-byte random salt rotates by UTC day and NEVER equals pubkey-derived hash
  const clientIp = '203.0.113.42'
  const day1Ms = Date.UTC(2026, 10, 22, 12, 0, 0)
  const day2Ms = Date.UTC(2026, 10, 23, 0, 5, 0)
  const hashDay1A = await guard.hashClientIp(clientIp, day1Ms)
  const hashDay1B = await guard.hashClientIp(clientIp, day1Ms + 60_000)
  assert.equal(hashDay1A, hashDay1B, 'same IP on same UTC day must hash deterministically')
  assert.equal(hashDay1A.length, 32)

  // Must NEVER match legacy pubkey-salted hash
  const legacyPubkeyHash = toHex(sha256(utf8(`${clientIp}|${relayerB58}`))).slice(0, 32)
  assert.notEqual(hashDay1A, legacyPubkeyHash)

  // Verify persisted 32-byte (64-hex) random salt exists in `daily_ip_salts`
  const saltsDay1 = harness.db
    .prepare('SELECT day, salt_hex FROM daily_ip_salts')
    .all() as Array<{ day: string; salt_hex: string }>
  assert.equal(saltsDay1.length, 1)
  assert.equal(saltsDay1[0]!.day, '2026-11-22')
  assert.match(saltsDay1[0]!.salt_hex, /^[0-9a-f]{64}$/)

  // Day 2 rotation: generates fresh salt, purges Day 1 salt, produces different hash for same IP
  const hashDay2 = await guard.hashClientIp(clientIp, day2Ms)
  assert.notEqual(hashDay2, hashDay1A, 'UTC day rollover must rotate ephemeral salt')
  const saltsDay2 = harness.db
    .prepare('SELECT day, salt_hex FROM daily_ip_salts')
    .all() as Array<{ day: string; salt_hex: string }>
  assert.equal(saltsDay2.length, 1, 'prior day salt must be purged on rotation')
  assert.equal(saltsDay2[0]!.day, '2026-11-23')
  assert.notEqual(saltsDay2[0]!.salt_hex, saltsDay1[0]!.salt_hex)

  // 3. Verify `begin()` reserves all nullifiers atomically with ZERO IP association stored
  const nfA = base58Encode(new Uint8Array(32).fill(0x51))
  const nfB = base58Encode(new Uint8Array(32).fill(0x52))
  const beginRes = await guard.begin({ clientIp, nullifiers: [nfA, nfB] })
  assert.equal(beginRes.allowed, true)
  assert.ok(beginRes.ipHash && beginRes.ipHash.length === 32)

  const nfRows = harness.db
    .prepare('SELECT * FROM inflight_nullifiers ORDER BY nullifier')
    .all() as Array<Record<string, unknown>>
  assert.equal(nfRows.length, 2)
  for (const row of nfRows) {
    assert.equal('ip_hash' in row, false)
    assert.deepEqual(Object.keys(row).sort(), ['expires_at', 'nullifier'])
  }

  // Concurrent duplicate nullifier MUST be blocked with 409
  const dupRes = await guard.begin({ clientIp: '198.51.100.9', nullifiers: [nfB] })
  assert.equal(dupRes.allowed, false)
  assert.equal(dupRes.status, 409)
  assert.equal(dupRes.code, 'DUPLICATE_NULLIFIER')
})

// ============================================================================
// 2. Transfer fee-quote privacy (optional/ignored amount + default omitNf1=false),
//    random default shardId, and relayer pubkey rotation
// ============================================================================

test('computeNativeFeeQuote: op=transfer ignores amount, prices omitNf1, and ALL ops default omitNf1=false', () => {
  const cfg = loadPolicyConfig({} as never)
  const rentSchedule = {
    nullifierRentLamports: 890_880n,
    nfPageRentPerNfLamports: 113_567n,
    pageRentPerNoteLamports: 1_500_000n,
    ataRentLamports: 2_039_280n,
    baseTxFeeLamports: 5_000n,
    swapBaselineLamports: 2n * (890_880n + 113_567n) + 2n * 1_500_000n + 20_000n,
    fetchedAt: Date.now(),
  }

  // Default transfer (no amount, omitNf1 omitted => 2 nullifiers, 3 outputs)
  const q2 = computeNativeFeeQuote({
    cluster: 'mainnet',
    op: 'transfer',
    cfg,
    rentSchedule,
    feeSide: 'shielded_cm2',
    feeMint: WSOL_MINT,
    feeTokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    feeDecimals: 9,
    feeRecipient: null,
    feeShieldedAddress: relayerShieldedKeys.address,
    feeRecipientExists: true,
    solPriceUsd: 150,
    feeTokenPriceUsd: 150,
  })
  assert.equal(q2.billingMode, 'self_paying')
  assert.equal(q2.flatFee, true)
  assert.equal(q2.feeBps, 0)
  assert.equal(q2.nullifierCount, 2)
  const expectedCost2 = 2n * (890_880n + 113_567n) + 3n * 1_500_000n + 20_000n
  assert.equal(q2.estimatedRelayCostLamports, expectedCost2.toString())
  assert.equal(q2.relayerFee, BigInt(Math.ceil(Number(expectedCost2) * 1.1)).toString())

  // Explicit economy mode (omitNf1 = true => 1 nullifier, 3 outputs)
  const q1 = computeNativeFeeQuote({
    cluster: 'mainnet',
    op: 'transfer',
    cfg,
    rentSchedule,
    feeSide: 'shielded_cm2',
    feeMint: WSOL_MINT,
    feeTokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    feeDecimals: 9,
    omitNf1: true,
    feeRecipient: null,
    feeShieldedAddress: relayerShieldedKeys.address,
    feeRecipientExists: true,
    solPriceUsd: 150,
    feeTokenPriceUsd: 150,
  })
  assert.equal(q1.billingMode, 'self_paying')
  assert.equal(q1.nullifierCount, 1)
  assert.equal(
    BigInt(q2.estimatedRelayCostLamports) - BigInt(q1.estimatedRelayCostLamports),
    rentSchedule.nullifierRentLamports + rentSchedule.nfPageRentPerNfLamports,
  )
  assert.ok(BigInt(q2.relayerFee) > BigInt(q1.relayerFee))

  // Legacy caller passing huge amount MUST produce identical flat fee
  const qLegacyHuge = computeNativeFeeQuote({
    cluster: 'mainnet',
    op: 'transfer',
    cfg,
    rentSchedule,
    feeSide: 'shielded_cm2',
    feeMint: WSOL_MINT,
    feeTokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    feeDecimals: 9,
    amount: 500_000_000_000n,
    feeRecipient: null,
    feeShieldedAddress: relayerShieldedKeys.address,
    feeRecipientExists: true,
    solPriceUsd: 150,
    feeTokenPriceUsd: 150,
  })
  assert.equal(qLegacyHuge.relayerFee, q2.relayerFee)
  assert.equal(qLegacyHuge.estimatedRelayCostLamports, q2.estimatedRelayCostLamports)

  // Withdraw defaults to 2 nullifiers (omitNf1 = false)
  const qWithdraw = computeNativeFeeQuote({
    cluster: 'mainnet',
    op: 'withdraw',
    cfg,
    rentSchedule,
    unwrapWsol: true,
    feeSide: 'in',
    feeMint: WSOL_MINT,
    feeTokenProgram: null,
    feeDecimals: 9,
    amount: 2_000_000_000n,
    outputCount: 0,
    feeRecipient: relayerB58,
    feeRecipientExists: true,
    solPriceUsd: 150,
    feeTokenPriceUsd: 150,
  })
  assert.equal(qWithdraw.billingMode, 'self_paying')
  assert.equal(qWithdraw.flatFee, false)
  assert.equal(qWithdraw.nullifierCount, 2)
  assert.equal(qWithdraw.relayerFee, '5000000') // 25 bps of 2 SOL > 1.1x rent
})

test('HTTP /v1/fee-quote defaults omitNf1=false across ALL ops, randomizes omitted shardId, and rotates configured relayerPubkeys', async () => {
  const worker = await getWorker()
  const mockRpc = 'https://mock-rpc.local/fee-quote-http'
  const fvkJson = JSON.stringify({
    spendPkHex: toHex(relayerFvk.spendPk),
    nkHex: toHex(relayerFvk.nk),
    viewSkHex: toHex(relayerFvk.viewSk),
    viewPkHex: toHex(relayerFvk.viewPk),
  })
  const poolSecrets = [
    new Uint8Array(32).fill(0x41),
    new Uint8Array(32).fill(0x42),
    new Uint8Array(32).fill(0x43),
    new Uint8Array(32).fill(0x44),
  ]
  const poolPubkeys = poolSecrets.map((s) => base58Encode(ed25519.getPublicKey(s)))

  const guard = createMockGuard()
  const env = {
    RELAY_GUARD: guard.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRETS_JSON: JSON.stringify(poolSecrets.map((s) => toBase64(s))),
    MAINNET_RELAYER_FVK_JSON: fvkJson,
  } as Env

  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n })
  const classicWsolBytes = makeClassicMintBytes(9)
  const classicUsdcBytes = makeClassicMintBytes(6)

  await withMockFetch(
    async (url, init) => {
      assert.equal(url, mockRpc)
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        const rentMap: Record<number, number> = {
          0: 890_880,
          165: 2_039_280,
          [SUBTREE_PAGE_LEN]: 58_340_000,
          [SUBROOT_PAGE_LEN]: 68_140_000,
          [MEMO_PAGE_LEN]: 72_149_760,
        }
        return Response.json({ jsonrpc: '2.0', id: 1, result: rentMap[len] ?? 1_000_000 })
      }
      if (body.method === 'getAccountInfo' && body.params[0] === poolPda) {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { data: [toBase64(poolBytes), 'base64'], lamports: 2_000_000, owner: AUDREN_PROGRAM_ID } },
        })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        const value = addrs.map((addr) => {
          if (addr === WSOL_MINT) {
            return { data: [toBase64(classicWsolBytes), 'base64'], lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID }
          }
          if (addr === USDC_MINT) {
            return { data: [toBase64(classicUsdcBytes), 'base64'], lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID }
          }
          return { data: ['', 'base64'], lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }
        })
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value } })
      }
      if (body.method === 'getBalance') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: 500_000_000 } })
      }
      throw new Error(`Unexpected RPC method in fee-quote test: ${body.method}`)
    },
    async () => {
      // 1. op=transfer with WSOL mint & NO amount param (default 2 nullifiers)
      const res2 = await worker.fetch(
        new Request(`https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=transfer&mint=${WSOL_MINT}`),
        env,
      )
      assert.equal(res2.status, 200)
      assert.equal(res2.headers.get('access-control-allow-origin'), '*')
      const q2 = (await res2.json()) as Record<string, unknown>
      assert.equal(q2.ok, true)
      assert.equal(q2.billingMode, 'self_paying')
      assert.equal(q2.flatFee, true)
      assert.equal(q2.nullifierCount, 2)
      assert.equal(q2.feeBps, 0)
      assert.equal(q2.feeMint, WSOL_MINT)
      assert.equal(q2.feeShieldedAddress, relayerShieldedKeys.address)

      // 2. op=transfer with omitNf1=true (1 nullifier)
      const res1 = await worker.fetch(
        new Request(`https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=transfer&mint=${WSOL_MINT}&omitNf1=true`),
        env,
      )
      assert.equal(res1.status, 200)
      const q1 = (await res1.json()) as Record<string, unknown>
      assert.equal(q1.billingMode, 'self_paying')
      assert.equal(q1.nullifierCount, 1)
      assert.equal(
        BigInt(String(q2.estimatedRelayCostLamports)) - BigInt(String(q1.estimatedRelayCostLamports)),
        890_880n,
      )

      // 3. op=transfer ignores any legacy amount param
      const resLegacy = await worker.fetch(
        new Request(`https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=transfer&mint=${WSOL_MINT}&amount=999999999`),
        env,
      )
      assert.equal(resLegacy.status, 200)
      const qLegacy = (await resLegacy.json()) as Record<string, unknown>
      assert.equal(qLegacy.relayerFee, q2.relayerFee)

      // 4. op=withdraw and op=exec_escrow default to omitNf1=false (nullifierCount === 2)!
      const resWithdraw = await worker.fetch(
        new Request(`https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=withdraw&mint=${WSOL_MINT}&unwrapWsol=true&amount=500000000`),
        env,
      )
      assert.equal(resWithdraw.status, 200)
      const qWithdraw = (await resWithdraw.json()) as Record<string, unknown>
      assert.equal(qWithdraw.nullifierCount, 2)

      // 5. op=exec_escrow randomizes omitted shardId (0..15, NEVER stuck at 0!)
      const seenShards = new Set<number>()
      for (let i = 0; i < 24; i++) {
        const resExec = await worker.fetch(
          new Request(`https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=exec_escrow&mint=${WSOL_MINT}&amount=500000000`),
          env,
        )
        assert.equal(resExec.status, 200)
        const qExec = (await resExec.json()) as {
          nullifierCount: number
          shardId: number
          escrowPda: string
        }
        assert.equal(qExec.nullifierCount, 2)
        assert.ok(Number.isInteger(qExec.shardId) && qExec.shardId >= 0 && qExec.shardId < NUM_ESCROW_SHARDS)
        assert.equal(qExec.escrowPda, deriveEscrowPdaSync(0, qExec.shardId).address)
        seenShards.add(qExec.shardId)
      }
      assert.ok(seenShards.size >= 2, `Expected varied random shardIds, got ${Array.from(seenShards)}`)

      // 6. GET /v1/info reports v1 tags, maxBatchSize=4, defaultNullifiers=2, AND rotates relayerPubkey across pool!
      const seenRelayers = new Set<string>()
      let lastInfo: {
        protocolVersion: number
        relayerPubkey: string
        relayerPubkeys: string[]
        checkpointSupport: boolean
        supportedOperations: {
          transfer: { tag: number; maxBatchSize: number; flatFee: boolean; requiresAmount: boolean; defaultNullifiers: number }
          withdraw: { tag: number; defaultNullifiers: number }
          exec_escrow: { tag: number; defaultNullifiers: number }
          checkpoint: { tag: number; permissionless: boolean; endpoint: string }
          deposit: { tags: number[] }
        }
      } | null = null
      for (let i = 0; i < 24; i++) {
        const infoRes = await worker.fetch(
          new Request('https://relay.audren.xyz/v1/info?cluster=mainnet'),
          env,
        )
        assert.equal(infoRes.status, 200)
        lastInfo = (await infoRes.json()) as typeof lastInfo
        assert.ok(poolPubkeys.includes(lastInfo!.relayerPubkey))
        seenRelayers.add(lastInfo!.relayerPubkey)
      }
      assert.ok(seenRelayers.size >= 2, `Expected rotated relayerPubkeys across pool, got ${Array.from(seenRelayers)}`)
      assert.equal(lastInfo!.protocolVersion, PROTOCOL_VERSION)
      assert.deepEqual(lastInfo!.relayerPubkeys, poolPubkeys)
      assert.equal(lastInfo!.checkpointSupport, true)
      assert.equal(lastInfo!.supportedOperations.transfer.tag, TAG_TRANSACT)
      assert.equal(lastInfo!.supportedOperations.transfer.maxBatchSize, 4)
      assert.equal(lastInfo!.supportedOperations.transfer.flatFee, true)
      assert.equal(lastInfo!.supportedOperations.transfer.requiresAmount, false)
      assert.equal(lastInfo!.supportedOperations.transfer.defaultNullifiers, 2)
      assert.equal(lastInfo!.supportedOperations.withdraw.tag, TAG_TRANSACT)
      assert.equal(lastInfo!.supportedOperations.withdraw.defaultNullifiers, 2)
      assert.equal(lastInfo!.supportedOperations.exec_escrow.tag, TAG_EXEC_VIA_ESCROW)
      assert.equal(lastInfo!.supportedOperations.exec_escrow.defaultNullifiers, 2)
      assert.equal(lastInfo!.supportedOperations.checkpoint.tag, TAG_PUBLISH_CHECKPOINT)
      assert.equal(lastInfo!.supportedOperations.checkpoint.endpoint, '/v1/checkpoint')
      assert.deepEqual(lastInfo!.supportedOperations.deposit.tags, [TAG_DEPOSIT])

      // 7. Root index documents POST /v1/checkpoint
      const rootRes = await worker.fetch(new Request('https://relay.audren.xyz/'), env)
      const rootJson = (await rootRes.json()) as { endpoints: string[] }
      assert.ok(rootJson.endpoints.some((e) => e.includes('POST /v1/checkpoint')))
    },
  )
})

// ============================================================================
// 3. Permissionless on-demand POST /v1/checkpoint (up_to_date / cooldown / published)
// ============================================================================

test('evaluateCheckpointState and HTTP POST /v1/checkpoint handle up_to_date, cooldown, published, lock, and rate limit', async () => {
  const worker = await getWorker()
  const poolPda = derivePoolPdaSync(0).address
  const lanePdas = [0, 1, 2, 3].map((l) => deriveLanePdaSync(0, l).address)
  const poolBytes = makePoolStateBytes({ activeLanes: 4, ckptInterval: 16n, maxCkptAge: 3600n })

  const ckptEpoch100 = makeCheckpointBytes({
    slotIdx: 100,
    epochId: 100n,
    publishedSlot: 1600n,
    laneCounts: [3n, 2n, 0n, 0n],
  })
  const ckptPda100 = deriveCheckpointPdaSync(0, 100).address

  async function runCheckpointScenario(params: {
    rpcUrl: string
    currentSlot: number
    laneLeaves: bigint[]
    guardOverrides?: Parameters<typeof createMockGuard>[0]
  }) {
    let sendTxCount = 0
    let lastSentWireBytes: Uint8Array | null = null
    const guard = createMockGuard(params.guardOverrides)
    const env = {
      RELAY_GUARD: guard.namespace,
      MAINNET_RPC_URL: params.rpcUrl,
      MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    } as Env

    const accMap = new Map<string, { bytes: Uint8Array; owner: string }>()
    accMap.set(poolPda, { bytes: poolBytes, owner: AUDREN_PROGRAM_ID })
    lanePdas.forEach((pda, l) => {
      accMap.set(pda, {
        bytes: makeLaneStateBytes({ laneId: l, nextLeaf: params.laneLeaves[l] ?? 0n }),
        owner: AUDREN_PROGRAM_ID,
      })
    })
    accMap.set(ckptPda100, { bytes: ckptEpoch100, owner: AUDREN_PROGRAM_ID })

    const response = await withMockFetch(
      async (url, init) => {
        assert.equal(url, params.rpcUrl)
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getAccountInfo') {
          const hit = accMap.get(String(body.params[0]))
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              value: hit
                ? { data: [toBase64(hit.bytes), 'base64'], lamports: 5_000_000, owner: hit.owner }
                : null,
            },
          })
        }
        if (body.method === 'getSlot') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: params.currentSlot })
        }
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          const value = addrs.map((addr) => {
            const hit = accMap.get(addr)
            return hit
              ? { data: [toBase64(hit.bytes), 'base64'], lamports: 5_000_000, owner: hit.owner }
              : null
          })
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value } })
        }
        if (body.method === 'getLatestBlockhash') {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x11)) } },
          })
        }
        if (body.method === 'simulateTransaction') {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              value: {
                err: null,
                logs: ['Program log: PublishCheckpoint OK'],
                unitsConsumed: 18_500,
                accounts: [{ lamports: 499_990_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }],
              },
            },
          })
        }
        if (body.method === 'sendTransaction') {
          sendTxCount++
          lastSentWireBytes = fromBase64(String(body.params[0]))
          return Response.json({ jsonrpc: '2.0', id: 1, result: '5CkptMockSig11111111111111111111111111111111111' })
        }
        if (body.method === 'getSignatureStatuses') {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              value: [{ slot: params.currentSlot + 1, err: null, confirmationStatus: 'confirmed' }],
            },
          })
        }
        throw new Error(`Unexpected RPC method in checkpoint test: ${body.method}`)
      },
      async () =>
        worker.fetch(
          new Request('https://relay.audren.xyz/v1/checkpoint', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ cluster: 'mainnet', poolId: 0 }),
          }),
          env,
        ),
    )

    return {
      status: response.status,
      headers: response.headers,
      body: (await response.json()) as Record<string, unknown>,
      sendTxCount,
      lastSentWireBytes,
      guard,
    }
  }

  // Case A: up_to_date
  const upToDate = await runCheckpointScenario({
    rpcUrl: 'https://mock-rpc.local/ckpt-up-to-date',
    currentSlot: 1608,
    laneLeaves: [3n, 2n, 0n, 0n],
  })
  assert.equal(upToDate.status, 200)
  assert.equal(upToDate.headers.get('access-control-allow-origin'), '*')
  assert.equal(upToDate.body.ok, true)
  assert.equal(upToDate.body.status, 'up_to_date')
  assert.equal(upToDate.body.epoch, 100)
  assert.equal(upToDate.sendTxCount, 0)

  // Case B: cooldown
  const cooldown = await runCheckpointScenario({
    rpcUrl: 'https://mock-rpc.local/ckpt-cooldown',
    currentSlot: 1605,
    laneLeaves: [3n, 2n, 1n, 0n],
  })
  assert.equal(cooldown.status, 200)
  assert.equal(cooldown.body.status, 'cooldown')
  assert.equal(cooldown.body.slotsRemaining, 11)
  assert.equal(cooldown.body.waitMs, 4400)
  assert.equal(cooldown.sendTxCount, 0)

  // Case C: published
  const published = await runCheckpointScenario({
    rpcUrl: 'https://mock-rpc.local/ckpt-published',
    currentSlot: 1616,
    laneLeaves: [3n, 2n, 1n, 0n],
  })
  assert.equal(published.status, 200)
  assert.equal(published.body.status, 'published')
  assert.equal(published.body.epoch, 101)
  assert.equal(published.sendTxCount, 1)
  assert.ok(published.lastSentWireBytes)
  assert.equal(published.lastSentWireBytes[0], 0x81)
  assert.equal(base58Encode(published.lastSentWireBytes.subarray(42, 74)), relayerB58)

  // Case D: concurrent in-flight lock
  const inFlight = await runCheckpointScenario({
    rpcUrl: 'https://mock-rpc.local/ckpt-inflight',
    currentSlot: 1616,
    laneLeaves: [3n, 2n, 1n, 0n],
    guardOverrides: { acquireResult: { allowed: false, inFlight: true, waitMs: 2000 } },
  })
  assert.equal(inFlight.status, 200)
  assert.equal(inFlight.body.status, 'cooldown')
  assert.equal(inFlight.body.inFlight, true)

  // Case E: per-IP rate limit
  const rateLimited = await runCheckpointScenario({
    rpcUrl: 'https://mock-rpc.local/ckpt-ratelimit',
    currentSlot: 1616,
    laneLeaves: [3n, 2n, 1n, 0n],
    guardOverrides: {
      rateDecision: {
        allowed: false,
        status: 429,
        code: 'CHECKPOINT_RATE_LIMITED',
        reason: 'Too many checkpoint requests',
        retryAfterSec: 15,
      },
    },
  })
  assert.equal(rateLimited.status, 429)
  assert.equal(rateLimited.headers.get('retry-after'), '15')

  // Pure evaluator sanity check on expired checkpoint refresh (v1 DecodedPoolState)
  const expiredEval = evaluateCheckpointState({
    pool: {
      version: PROTOCOL_VERSION,
      bump: 255,
      paused: false,
      activeLanes: 4,
      poolId: 0,
      ckptInterval: 16n,
      maxCkptAge: 3600n,
      authority: relayerB58,
      authorityBytes: relayerPubkey,
      vaultAuthBump: 255,
      noteRentFee: 1_000_000n,
      nfRentFee: 120_000n,
      pendingAuthority: new Uint8Array(32),
    },
    lanes: [
      {
        version: PROTOCOL_VERSION,
        laneId: 0,
        bump: 0,
        rentBump: 0,
        poolId: 0,
        nextLeaf: 2n,
        nfCount: 0n,
        currentRoot: new Uint8Array(32),
      },
    ],
    latestCkpt: {
      version: PROTOCOL_VERSION,
      bump: 0,
      slotIdx: 100,
      poolId: 0,
      epochId: 100n,
      publishedSlot: 1600n,
      superRoot: new Uint8Array(32),
      laneRoots: [],
      laneCounts: [2n, 0n, 0n, 0n],
    },
    targetSlotCkpt: null,
    currentSlot: 6000n,
  })
  assert.equal(expiredEval.action, 'publish')
})

// ============================================================================
// 4. Token-2022 TransferFeeConfig input deduction + random default shardId on /v1/swap/quote
// ============================================================================

test('computeSwapInputTransferFee deducts active epoch Token-2022 transfer fee and leaves Classic SPL/WSOL unchanged', () => {
  const t22MintBytes = makeToken2022TransferFeeMintBytes({
    decimals: 6,
    olderEpoch: 10n,
    olderMaxFee: 500_000n,
    olderBps: 100,
    newerEpoch: 500n,
    newerMaxFee: 10_000_000n,
    newerBps: 250,
  })

  const before = computeSwapInputTransferFee({
    tokenProgram: TOKEN_2022_PROGRAM_ID,
    mintData: t22MintBytes,
    currentEpoch: 499n,
    grossAmount: 1_000_001n,
  })
  assert.equal(before.grossInputAmount, '1000001')
  assert.equal(before.inputTransferFeeBps, 100)
  assert.equal(before.netInputAmount, '990000')
  assert.equal(before.inputTransferFeeAmount, '10001')

  const after = computeSwapInputTransferFee({
    tokenProgram: TOKEN_2022_PROGRAM_ID,
    mintData: t22MintBytes,
    currentEpoch: 500n,
    grossAmount: 1_000_000n,
  })
  assert.equal(after.inputTransferFeeBps, 250)
  assert.equal(after.netInputAmount, '975000')

  const capped = computeSwapInputTransferFee({
    tokenProgram: TOKEN_2022_PROGRAM_ID,
    mintData: t22MintBytes,
    currentEpoch: 500n,
    grossAmount: 1_000_000_000n,
  })
  assert.equal(capped.netInputAmount, '990000000')

  const classic = computeSwapInputTransferFee({
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    mintData: makeClassicMintBytes(9),
    currentEpoch: 500n,
    grossAmount: 1_000_000_000n,
  })
  assert.equal(classic.grossInputAmount, '1000000000')
  assert.equal(classic.netInputAmount, '1000000000')
  assert.equal(classic.inputTransferFeeBps, 0)
})

test('HTTP GET /v1/swap/quote deducts Token-2022 transfer fee and picks uniformly random shardId when omitted', async () => {
  const worker = await getWorker()
  const mockRpc = 'https://mock-rpc.local/swap-t22-test'
  const mockJup = 'https://mock-jup.local'
  const t22Mint = base58Encode(new Uint8Array(32).fill(0x22))

  const t22MintBytes = makeToken2022TransferFeeMintBytes({
    decimals: 6,
    olderEpoch: 10n,
    olderMaxFee: 500_000n,
    olderBps: 100,
    newerEpoch: 500n,
    newerMaxFee: 10_000_000n,
    newerBps: 250,
  })
  const classicUsdcBytes = makeClassicMintBytes(6)
  const classicWsolBytes = makeClassicMintBytes(9)
  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n })

  const guard = createMockGuard()
  const env = {
    RELAY_GUARD: guard.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    JUPITER_API_URL: mockJup,
  } as Env

  const jupQuotedAmounts: string[] = []
  let epochInfoCalls = 0

  await withMockFetch(
    async (url, init) => {
      if (url.startsWith(`${mockJup}/price/v3`)) {
        return Response.json({
          [WSOL_MINT]: { usdPrice: 150 },
          [t22Mint]: { usdPrice: 1 },
          [USDC_MINT]: { usdPrice: 1 },
        })
      }
      if (url.startsWith(`${mockJup}/swap/v1/quote`)) {
        const u = new URL(url)
        const quotedAmt = u.searchParams.get('amount') ?? ''
        jupQuotedAmounts.push(quotedAmt)
        return Response.json({
          inputMint: u.searchParams.get('inputMint'),
          outputMint: u.searchParams.get('outputMint'),
          inAmount: quotedAmt,
          outAmount: String(BigInt(quotedAmt) * 2n),
          otherAmountThreshold: String(BigInt(quotedAmt) * 2n),
          slippageBps: 100,
          routePlan: [
            {
              swapInfo: {
                label: 'Orca Whirlpool',
                inputMint: u.searchParams.get('inputMint'),
                outputMint: u.searchParams.get('outputMint'),
                inAmount: quotedAmt,
                outAmount: String(BigInt(quotedAmt) * 2n),
              },
              percent: 100,
            },
          ],
        })
      }
      if (url === mockRpc) {
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getEpochInfo') {
          epochInfoCalls++
          return Response.json({ jsonrpc: '2.0', id: 1, result: { epoch: 512 } })
        }
        if (body.method === 'getMinimumBalanceForRentExemption') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: 890_880 })
        }
        if (body.method === 'getAccountInfo' && body.params[0] === poolPda) {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: { value: { data: [toBase64(poolBytes), 'base64'], lamports: 2_000_000, owner: AUDREN_PROGRAM_ID } },
          })
        }
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          const value = addrs.map((addr) => {
            if (addr === t22Mint) {
              return { data: [toBase64(t22MintBytes), 'base64'], lamports: 2_000_000, owner: TOKEN_2022_PROGRAM_ID }
            }
            if (addr === USDC_MINT) {
              return { data: [toBase64(classicUsdcBytes), 'base64'], lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID }
            }
            if (addr === WSOL_MINT) {
              return { data: [toBase64(classicWsolBytes), 'base64'], lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID }
            }
            return { data: ['', 'base64'], lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }
          })
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value } })
        }
      }
      throw new Error(`Unexpected fetch URL in swap quote test: ${url}`)
    },
    async () => {
      // 1. Token-2022 input mint with active 250 bps TransferFeeConfig
      const t22Res = await worker.fetch(
        new Request(
          `https://relay.audren.xyz/v1/swap/quote?cluster=mainnet&provider=jupiter&inputMint=${t22Mint}&outputMint=${USDC_MINT}&amount=1000000`,
        ),
        env,
      )
      assert.equal(t22Res.status, 200)
      const t22Body = (await t22Res.json()) as {
        ok: boolean
        shardId: number
        escrowPda: string
        grossInputAmount: string
        netInputAmount: string
        inputTransferFeeBps: number
        quote: { inAmount: string }
      }
      assert.equal(t22Body.ok, true)
      assert.equal(t22Body.grossInputAmount, '1000000')
      assert.equal(t22Body.netInputAmount, '975000')
      assert.equal(t22Body.inputTransferFeeBps, 250)
      assert.equal(t22Body.quote.inAmount, '975000')
      assert.equal(jupQuotedAmounts[0], '975000')
      assert.equal(epochInfoCalls, 1)

      // 2. Classic SPL / WSOL input mint unchanged + verify random default shardId across calls!
      const swapShards = new Set<number>([t22Body.shardId])
      for (let i = 0; i < 16; i++) {
        const wsolRes = await worker.fetch(
          new Request(
            `https://relay.audren.xyz/v1/swap/quote?cluster=mainnet&provider=jupiter&inputMint=${WSOL_MINT}&outputMint=${USDC_MINT}&amount=1000000000`,
          ),
          env,
        )
        assert.equal(wsolRes.status, 200)
        const wsolBody = (await wsolRes.json()) as {
          ok: boolean
          shardId: number
          escrowPda: string
          grossInputAmount: string
          netInputAmount: string
          inputTransferFeeBps: number
          quote: { inAmount: string }
        }
        assert.equal(wsolBody.ok, true)
        assert.equal(wsolBody.grossInputAmount, '1000000000')
        assert.equal(wsolBody.netInputAmount, '1000000000')
        assert.equal(wsolBody.inputTransferFeeBps, 0)
        assert.ok(Number.isInteger(wsolBody.shardId) && wsolBody.shardId >= 0 && wsolBody.shardId < NUM_ESCROW_SHARDS)
        assert.equal(wsolBody.escrowPda, deriveEscrowPdaSync(0, wsolBody.shardId).address)
        swapShards.add(wsolBody.shardId)
      }
      assert.equal(epochInfoCalls, 1)
      assert.ok(swapShards.size >= 2, `Expected random default shardIds on /v1/swap/quote, got ${Array.from(swapShards)}`)
    },
  )
})

// ============================================================================
// 5. Wire Parser & Rollover OpenPage (96 notes/page) & Rent Schedule & Ring Wrap
// ============================================================================

/** Decode a compiled Solana Transaction v1 (`0x81`) wire payload back into instructions + CU limit. */
function decodeV1Tx(wireBytes: Uint8Array): {
  computeUnitLimit: number | null
  accounts: string[]
  instructions: Array<{ programId: string; accounts: string[]; data: Uint8Array }>
} {
  assert.equal(wireBytes[0], 0x81, 'expected Solana Transaction v1 (0x81)')
  const configMask = readU32le(wireBytes, 4)
  const numIxs = wireBytes[40]!
  const numAccs = wireBytes[41]!
  const accounts: string[] = []
  let off = 42
  for (let i = 0; i < numAccs; i++) {
    accounts.push(base58Encode(wireBytes.subarray(off, off + 32)))
    off += 32
  }
  if ((configMask & 0b11) !== 0) off += 8 // priorityFeeLamports
  let computeUnitLimit: number | null = null
  if ((configMask & 0b100) !== 0) {
    computeUnitLimit = readU32le(wireBytes, off)
    off += 4
  }
  if ((configMask & 0b1000) !== 0) off += 4 // loadedAccountsDataSizeLimit
  if ((configMask & 0b10000) !== 0) off += 4 // heapSize

  const headers: Array<{ progIdx: number; accCnt: number; dataLen: number }> = []
  for (let i = 0; i < numIxs; i++) {
    headers.push({
      progIdx: wireBytes[off]!,
      accCnt: wireBytes[off + 1]!,
      dataLen: readU16le(wireBytes, off + 2),
    })
    off += 4
  }
  const instructions: Array<{ programId: string; accounts: string[]; data: Uint8Array }> = []
  for (const h of headers) {
    const ixAccs: string[] = []
    for (let j = 0; j < h.accCnt; j++) {
      ixAccs.push(accounts[wireBytes[off++]!]!)
    }
    const data = wireBytes.subarray(off, off + h.dataLen)
    off += h.dataLen
    instructions.push({ programId: accounts[h.progIdx]!, accounts: ixAccs, data })
  }
  return { computeUnitLimit, accounts, instructions }
}

test('parseTransactMeta & parseExecEscrowMeta reject unknown flags and missing rollover accounts', () => {
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const vaultWsolAta = deriveAssociatedTokenAddressSync(
    vaultAuth,
    WSOL_MINT,
    CLASSIC_TOKEN_PROGRAM_ID,
  ).address
  const recipient = base58Encode(new Uint8Array(32).fill(0x33))

  // Valid Transact (WSOL unwrap + all 3 rollovers: nextSub, nextMemo, nextNf)
  const validUnwrapRoll = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    ckptSlotIdx: 2,
    outLaneId: 1,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: true,
    publicOutflow: {
      mint: WSOL_MINT,
      vaultAta: vaultWsolAta,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    },
    rollover: { nextSubSeq: 1n, nextMemoSeq: 1n, nextNfSeq: 1n },
    proof192: dummyProof,
    nf0,
    nf1: nf1NonZero,
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 500_000_000n,
    relayerFeeAmount: 2_500_000n,
    recipient,
    relayerFeeRecipient: relayerB58,
    memosBytes: new Uint8Array(0),
  })
  const decodedAccs = validUnwrapRoll.accounts.map((a) => ({
    pubkey: base58Decode(a.pubkey),
    isSigner: a.isSigner,
    isWritable: a.isWritable,
  }))
  const parsed = parseTransactMeta(validUnwrapRoll.data, decodedAccs)
  assert.ok(parsed)
  assert.equal(parsed.poolId, 0)
  assert.equal(parsed.outLaneId, 1)
  assert.equal(parsed.unwrapWsol, true)
  assert.equal(parsed.nextSub, deriveSubtreePdaSync(0, 1, 1n).address)
  assert.equal(parsed.nextMemo, deriveMemoPdaSync(0, 1, 1n).address)
  assert.equal(parsed.nextNf, deriveNfPagePdaSync(0, 1, 1n).address)

  // Unknown flag bits MUST be rejected
  for (const badBit of [0x10, 0x20, 0x40, 0x80]) {
    const badData = new Uint8Array(validUnwrapRoll.data)
    badData[9] = (badData[9]! | badBit) & 0xff
    assert.equal(parseTransactMeta(badData, decodedAccs), null)
    assert.throws(
      () =>
        validateRelaySubmission(
          { instructionDataB64: toBase64(badData), accounts: validUnwrapRoll.accounts },
          relayerPubkey,
          allowedPre,
          relayerFvk,
        ),
      FirewallError,
    )
  }

  // Truncated rollover accounts MUST fail
  assert.equal(parseTransactMeta(validUnwrapRoll.data, decodedAccs.slice(0, -1)), null)

  // Single rollover bit in private transfer with missing trailing account MUST fail
  const privRoll = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    ckptSlotIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b001,
    assetMode: ASSET_MODE_PRIVATE,
    rollover: { nextMemoSeq: 1n },
    proof192: dummyProof,
    nf0,
    nf1: nf1Zero,
    cm0: new Uint8Array(32).fill(0x11),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x22),
  })
  const privAccs = privRoll.accounts.map((a) => ({
    pubkey: base58Decode(a.pubkey),
    isSigner: a.isSigner,
    isWritable: a.isWritable,
  }))
  assert.equal(parseTransactMeta(privRoll.data, privAccs)?.nextMemo, deriveMemoPdaSync(0, 0, 1n).address)
  assert.equal(parseTransactMeta(privRoll.data, privAccs.slice(0, -1)), null)

  // ExecViaEscrow (Tag 6): unknown flag bits and rollover without router accounts MUST fail
  const escrow = deriveEscrowPdaSync(0, 2).address
  const vaultInAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowInAta = deriveAssociatedTokenAddressSync(escrow, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultOutAta = deriveAssociatedTokenAddressSync(vaultAuth, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowOutAta = deriveAssociatedTokenAddressSync(escrow, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const execRoll = buildExecViaEscrowInstruction({
    payer: relayerB58,
    poolId: 0,
    ckptSlotIdx: 1,
    outLaneId: 2,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    escrowShard: 2,
    changeMask: 0,
    inLeg: {
      mint: WSOL_MINT,
      vaultAta: vaultInAta,
      escrowAta: escrowInAta,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    },
    outLeg: {
      mint: USDC_MINT,
      vaultAta: vaultOutAta,
      escrowAta: escrowOutAta,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    },
    relayerFeeAmount: 0n,
    rollover: { nextSubSeq: 1n, nextMemoSeq: 1n },
    proof192: dummyProof,
    nf0,
    nf1: nf1Zero,
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    amountIn: 100_000_000n,
    minAmountOut: 10_000_000n,
    outStealthOwner: new Uint8Array(32).fill(0x02),
    outBlinding: new Uint8Array(32).fill(0x03),
    dynMemoHead: new Uint8Array(34).fill(0x04),
    dynMemoMask: new Uint8Array(72).fill(0x05),
    routerProg: base58Encode(new Uint8Array(32).fill(0x55)),
    routerIxData: new Uint8Array([1, 2, 3]),
    routerAccounts: [
      { pubkey: base58Encode(new Uint8Array(32).fill(0x66)), isSigner: false, isWritable: true },
    ],
    changeMemos: new Uint8Array(0),
  })
  const execAccs = execRoll.accounts.map((a) => ({
    pubkey: base58Decode(a.pubkey),
    isSigner: a.isSigner,
    isWritable: a.isWritable,
  }))
  const parsedExec = parseExecEscrowMeta(execRoll.data, execAccs)
  assert.ok(parsedExec)
  assert.equal(parsedExec.nextSub, deriveSubtreePdaSync(0, 2, 1n).address)
  assert.equal(parsedExec.nextMemo, deriveMemoPdaSync(0, 2, 1n).address)
  assert.equal(parsedExec.nextNf, null)

  const badExecData = new Uint8Array(execRoll.data)
  badExecData[9] = (badExecData[9]! | 0x40) & 0xff
  assert.equal(parseExecEscrowMeta(badExecData, execAccs), null)
  // Removing the sole router account leaves 0 router accounts -> must fail
  assert.equal(parseExecEscrowMeta(execRoll.data, execAccs.slice(0, -1)), null)
})

test('handleRelaySubmit auto-prepends OpenPage (Tag 2) at 96-note MemoPage rollover boundary in 1 batch and rejects spoofed PDAs', async () => {
  const worker = await getWorker()
  const mockRpc = 'https://mock-rpc.local/open-page-submit'
  const outLaneId = 1
  const lanePda = deriveLanePdaSync(0, outLaneId).address
  const laneRentVault = deriveLaneRentVaultPdaSync(0, outLaneId).address
  const poolPda = derivePoolPdaSync(0).address
  const sub0 = deriveSubtreePdaSync(0, outLaneId, 0n).address
  const sr0 = deriveSubrootPdaSync(0, outLaneId, 0n).address
  const memo0 = deriveMemoPdaSync(0, outLaneId, 0n).address
  const memo1 = deriveMemoPdaSync(0, outLaneId, 1n).address
  const nfPage0 = deriveNfPagePdaSync(0, outLaneId, 0n).address
  const nfPage1 = deriveNfPagePdaSync(0, outLaneId, 1n).address

  // Lane is at nextLeaf = 95 (96-note MemoPage 0 has 1 slot left!) and nfCount = 599 (nf page 0 has 1 slot left).
  const laneBytes = makeLaneStateBytes({ laneId: outLaneId, nextLeaf: BigInt(MEMO_NOTES_PER_PAGE - 1), nfCount: 599n })
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)

  const transferIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    ckptSlotIdx: 1,
    outLaneId,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b011,
    assetMode: ASSET_MODE_PRIVATE,
    rollover: { nextMemoSeq: 1n, nextNfSeq: 1n },
    proof192: dummyProof,
    nf0,
    nf1: nf1NonZero,
    cm0: new Uint8Array(32).fill(0x10),
    cm1: new Uint8Array(32).fill(0x20),
    cm2: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN).fill(0x33),
  })

  // Case A: nextMemo (memo1) missing & nextNf (nfPage1) 1-lamport System-owned
  const guardA = createMockGuard()
  const envA = {
    RELAY_GUARD: guardA.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
  } as Env

  let getMultiCalls = 0
  let sentWire: Uint8Array | null = null
  const accMapA = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [lanePda, { bytes: laneBytes, lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [sub0, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
    [sr0, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    [memo0, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
    [nfPage0, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    [nfPage1, { bytes: new Uint8Array(0), lamports: 1, owner: SYSTEM_PROGRAM_ID }],
  ])

  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x44)) } },
        })
      }
      if (body.method === 'getMultipleAccounts') {
        getMultiCalls++
        const addrs = body.params[0] as string[]
        assert.ok(addrs.includes(lanePda))
        assert.ok(addrs.includes(memo1))
        assert.ok(addrs.includes(nfPage1))
        const value = addrs.map((a) => {
          const hit = accMapA.get(a)
          return hit
            ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner }
            : null
        })
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value } })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: {
              err: null,
              logs: ['OpenPage OK', 'OpenPage OK', 'Transact OK'],
              unitsConsumed: 185_000,
              accounts: [
                { lamports: 498_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        sentWire = fromBase64(String(body.params[0]))
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5OpenPageMockSig11111111111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: [{ slot: 9999, err: null, confirmationStatus: 'confirmed' }] },
        })
      }
      throw new Error(`Unexpected RPC method: ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(transferIx.data),
            accounts: transferIx.accounts,
            computeUnitLimit: 300_000,
          }),
        }),
        envA,
      )
      assert.equal(res.status, 200)
      const jsonBody = (await res.json()) as {
        ok: boolean
        openedPagesCount: number
        computeUnitLimit: number
      }
      assert.equal(jsonBody.ok, true)
      assert.equal(jsonBody.openedPagesCount, 2)
      assert.equal(jsonBody.computeUnitLimit, 340_000)
      assert.equal(getMultiCalls, 1)
      assert.ok(sentWire)

      const decoded = decodeV1Tx(sentWire)
      assert.equal(decoded.instructions.length, 3)
      const ix0 = decoded.instructions[0]!
      assert.equal(ix0.data[0], TAG_OPEN_PAGE)
      assert.equal(ix0.data[1], OPEN_PAGE_KIND_MEMO)
      assert.equal(readU64le(ix0.data, 7), 1n)
      assert.deepEqual(ix0.accounts, [relayerB58, poolPda, lanePda, laneRentVault, memo1, SYSTEM_PROGRAM_ID])

      const ix1 = decoded.instructions[1]!
      assert.equal(ix1.data[0], TAG_OPEN_PAGE)
      assert.equal(ix1.data[1], OPEN_PAGE_KIND_NULLIFIER)
      assert.equal(readU64le(ix1.data, 7), 1n)
      assert.deepEqual(ix1.accounts, [relayerB58, poolPda, lanePda, laneRentVault, nfPage1, SYSTEM_PROGRAM_ID])

      assert.equal(decoded.instructions[2]!.data[0], TAG_TRANSACT)
    },
  )

  // Case B: Spoofed rollover PDA MUST be rejected with 400 INVALID_PAGE_PDA
  const spoofedAccounts = transferIx.accounts.map((a) => ({ ...a }))
  spoofedAccounts[spoofedAccounts.length - 2] = {
    pubkey: deriveMemoPdaSync(0, outLaneId, 9n).address,
    isSigner: false,
    isWritable: true,
  }
  const guardB = createMockGuard()
  const envB = {
    RELAY_GUARD: guardB.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
  } as Env

  let simCalled = 0
  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x44)) } },
        })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        const value = addrs.map((a) => {
          const hit = accMapA.get(a)
          return hit
            ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner }
            : null
        })
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value } })
      }
      if (body.method === 'simulateTransaction') simCalled++
      throw new Error(`Unexpected RPC call after spoofed PDA: ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(transferIx.data),
            accounts: spoofedAccounts,
          }),
        }),
        envB,
      )
      assert.equal(res.status, 400)
      const errBody = (await res.json()) as { code: string }
      assert.equal(errBody.code, 'INVALID_PAGE_PDA')
      assert.equal(simCalled, 0)
      assert.equal(guardB.relayReleaseCalls.length, 1)
      assert.equal(guardB.relayReleaseCalls[0]?.recordFailure, true)
    },
  )

  // Case C: Missing primary pages (`outSub` 300 & `outRoot` 1 at `nextLeaf = 76_800`, `memoSeq = 76_800 / 96 = 800`)
  const laneAt76800 = makeLaneStateBytes({ laneId: outLaneId, nextLeaf: 76_800n, nfCount: 10n })
  const sub300 = deriveSubtreePdaSync(0, outLaneId, 300n).address
  const sr1 = deriveSubrootPdaSync(0, outLaneId, 1n).address
  const memo800 = deriveMemoPdaSync(0, outLaneId, 800n).address
  const primaryMissingIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    ckptSlotIdx: 1,
    outLaneId,
    outSubSeq: 300n,
    outRootSeq: 1n,
    outMemoSeq: 800n,
    outNfSeq: 0n,
    outputMask: 0b001,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: dummyProof,
    nf0,
    nf1: nf1NonZero,
    cm0: new Uint8Array(32).fill(0x19),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x39),
  })
  const guardD = createMockGuard()
  const envD = {
    RELAY_GUARD: guardD.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
  } as Env
  let sentWireD: Uint8Array | null = null
  const accMapD = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [lanePda, { bytes: laneAt76800, lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [memo800, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
    [nfPage0, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
  ])
  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x46)) } },
        })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        const value = addrs.map((a) => {
          const hit = accMapD.get(a)
          return hit
            ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner }
            : null
        })
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value } })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: {
              err: null,
              logs: ['OpenPage OK', 'OpenPage OK', 'Transact OK'],
              unitsConsumed: 190_000,
              accounts: [{ lamports: 499_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        sentWireD = fromBase64(String(body.params[0]))
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5PrimaryOpenPageSig11111111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: [{ slot: 10002, err: null, confirmationStatus: 'confirmed' }] },
        })
      }
      throw new Error(`Unexpected RPC method: ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(primaryMissingIx.data),
            accounts: primaryMissingIx.accounts,
          }),
        }),
        envD,
      )
      assert.equal(res.status, 200)
      assert.ok(sentWireD)
      const decoded = decodeV1Tx(sentWireD)
      assert.equal(decoded.instructions.length, 3)
      assert.equal(decoded.instructions[0]!.data[0], TAG_OPEN_PAGE)
      assert.equal(decoded.instructions[0]!.data[1], OPEN_PAGE_KIND_SUBTREE)
      assert.equal(decoded.instructions[0]!.accounts[4], sub300)
      assert.equal(decoded.instructions[1]!.data[0], TAG_OPEN_PAGE)
      assert.equal(decoded.instructions[1]!.data[1], OPEN_PAGE_KIND_SUBROOT)
      assert.equal(decoded.instructions[1]!.accounts[4], sr1)
      assert.equal(decoded.instructions[2]!.data[0], TAG_TRANSACT)
    },
  )
})

test('Live rent schedule (10,240 B / 96 notes MemoPage) & 2-nullifier WSOL-unwrap withdrawal stays strictly self_paying', async () => {
  const worker = await getWorker()
  const mockRpc = 'https://mock-rpc.local/nf-rent-fee-test'
  const mockRpcCapped = 'https://mock-rpc.local/nf-rent-fee-capped-test'
  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_500_000n, nfRentFee: 120_000n })
  const poolBytesCapped = makePoolStateBytes({ noteRentFee: 1_500_000n, nfRentFee: 80_000n })

  const rentMap: Record<number, number> = {
    0: 890_880,
    165: 2_039_280,
    [SUBTREE_PAGE_LEN]: 58_340_000,
    [SUBROOT_PAGE_LEN]: 68_140_000, // livePerNf = ceil(68_140_000 / 600) = 113_567
    [MEMO_PAGE_LEN]: 72_149_760, // ceil(72_149_760 / 96) = 751_560
    [NF_PAGE_LEN]: 68_140_000,
  }
  const expectedLivePerNf = 113_567n
  // ceil(58_340_000 / 256) + ceil(68_140_000 / 76_800) + ceil(72_149_760 / 96)
  const expectedLivePerNote = 227_891n + 888n + 751_560n // 980_339n
  const expectedSwapBaseline =
    2n * (890_880n + expectedLivePerNf) + 2n * expectedLivePerNote + 20_000n

  await withMockFetch(
    async (url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: rentMap[Number(body.params[0])] ?? 1_000_000 })
      }
      if (body.method === 'getAccountInfo' && body.params[0] === poolPda) {
        const bytes = url === mockRpcCapped ? poolBytesCapped : poolBytes
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { data: [toBase64(bytes), 'base64'], lamports: 2_000_000, owner: AUDREN_PROGRAM_ID } },
        })
      }
      throw new Error(`Unexpected RPC call in rent schedule test: ${body.method}`)
    },
    async () => {
      const sched = await fetchLiveRentSchedule(mockRpc)
      assert.equal(sched.nfPageRentPerNfLamports, expectedLivePerNf)
      assert.equal(sched.pageRentPerNoteLamports, expectedLivePerNote)
      assert.equal(sched.swapBaselineLamports, expectedSwapBaseline)

      const schedCapped = await fetchLiveRentSchedule(mockRpcCapped)
      assert.equal(schedCapped.nfPageRentPerNfLamports, 80_000n)
    },
  )

  const guard = createMockGuard()
  const env = {
    RELAY_GUARD: guard.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
  } as Env

  const lanePda = deriveLanePdaSync(0, 0).address
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)
  const sub0 = deriveSubtreePdaSync(0, 0, 0n).address
  const sr0 = deriveSubrootPdaSync(0, 0, 0n).address
  const memo0 = deriveMemoPdaSync(0, 0, 0n).address
  const nfPage0 = deriveNfPagePdaSync(0, 0, 0n).address
  const preRelayerLamports = 500_000_000n
  const actualOnChainDebit = 2n * 890_880n + 2n * expectedLivePerNf + 5_000n + 5_000n
  let quotedRelayerFee = 0n

  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: rentMap[Number(body.params[0])] ?? 1_000_000 })
      }
      if (body.method === 'getAccountInfo' && body.params[0] === poolPda) {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { data: [toBase64(poolBytes), 'base64'], lamports: 2_000_000, owner: AUDREN_PROGRAM_ID } },
        })
      }
      if (body.method === 'getBalance') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: Number(preRelayerLamports) } })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x55)) } },
        })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        const value = addrs.map((a) => {
          if (a === relayerB58) {
            return { data: ['', 'base64'], lamports: Number(preRelayerLamports), owner: SYSTEM_PROGRAM_ID }
          }
          if (a === lanePda) {
            return {
              data: [toBase64(makeLaneStateBytes({ laneId: 0, nextLeaf: 1n, nfCount: 1n })), 'base64'],
              lamports: 15_000_000,
              owner: AUDREN_PROGRAM_ID,
            }
          }
          if (a === sub0 || a === sr0 || a === memo0 || a === nfPage0) {
            return { data: [toBase64(dummyPageBytes), 'base64'], lamports: 58_000_000, owner: AUDREN_PROGRAM_ID }
          }
          return null
        })
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value } })
      }
      if (body.method === 'simulateTransaction') {
        const postLamports = preRelayerLamports - actualOnChainDebit + quotedRelayerFee
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: {
              err: null,
              logs: ['Transact Withdraw OK'],
              unitsConsumed: 150_000,
              accounts: [{ lamports: Number(postLamports), owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5SelfPayWithdrawSig11111111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: [{ slot: 12345, err: null, confirmationStatus: 'confirmed' }] },
        })
      }
      throw new Error(`Unexpected RPC method: ${body.method}`)
    },
    async () => {
      // Quote default (omitNf1 omitted => 2 nullifiers!) full WSOL-unwrap withdrawal
      const quoteRes = await worker.fetch(
        new Request(
          `https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=withdraw&mint=${WSOL_MINT}&unwrapWsol=true&amount=500000000&outputCount=0`,
        ),
        env,
      )
      assert.equal(quoteRes.status, 200)
      const q = (await quoteRes.json()) as {
        billingMode: string
        nullifierCount: number
        relayerFee: string
      }
      assert.equal(q.billingMode, 'self_paying')
      assert.equal(q.nullifierCount, 2)
      quotedRelayerFee = BigInt(q.relayerFee)
      assert.ok(quotedRelayerFee > actualOnChainDebit)

      const recipient = base58Encode(new Uint8Array(32).fill(0x77))
      const withdrawIx = buildTransactInstruction({
        payer: relayerB58,
        poolId: 0,
        ckptSlotIdx: 0,
        outLaneId: 0,
        outSubSeq: 0n,
        outRootSeq: 0n,
        outMemoSeq: 0n,
        outNfSeq: 0n,
        outputMask: 0,
        assetMode: ASSET_MODE_PUBLIC,
        unwrapWsol: true,
        publicOutflow: { mint: WSOL_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
        proof192: dummyProof,
        nf0,
        nf1: nf1NonZero,
        cm0: new Uint8Array(32),
        cm1: new Uint8Array(32),
        cm2: new Uint8Array(32),
        publicAmountOut: 500_000_000n - quotedRelayerFee,
        relayerFeeAmount: quotedRelayerFee,
        recipient,
        relayerFeeRecipient: relayerB58,
        memosBytes: new Uint8Array(0),
      })
      const submitRes = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(withdrawIx.data),
            accounts: withdrawIx.accounts,
          }),
        }),
        env,
      )
      assert.equal(submitRes.status, 200)
      const submitBody = (await submitRes.json()) as {
        ok: boolean
        billingMode: string
        netSponsoredLamports: string
        simulatedFeeMint: string
      }
      assert.equal(submitBody.ok, true)
      assert.equal(submitBody.billingMode, 'self_paying')
      assert.equal(submitBody.netSponsoredLamports, '0')
      assert.equal(submitBody.simulatedFeeMint, WSOL_MINT)
      assert.equal(guard.relayAuthorizeCalls[0]?.selfPaying, true)
    },
  )
})

// ============================================================================
// 6. Multi-ix 2..4 parallel `2 -> 1` private `Transact` merge batching
// ============================================================================

test('POST /v1/relay/submit supports up to 4 parallel 2 -> 1 private Transact merges with deduplicated OpenPage and rejects invalid batches', async () => {
  const worker = await getWorker()
  const mockRpc = 'https://mock-rpc.local/multi-merge-batch'
  const fvkJson = JSON.stringify({
    spendPkHex: toHex(relayerFvk.spendPk),
    nkHex: toHex(relayerFvk.nk),
    viewSkHex: toHex(relayerFvk.viewSk),
    viewPkHex: toHex(relayerFvk.viewPk),
  })

  const makeMergeIx = (params: {
    seed: number
    outLaneId: number
    outMemoSeq?: bigint
    nextMemoSeq?: bigint | null
    feeLamports?: bigint
    vkId?: number
  }) => {
    const aNf0 = new Uint8Array(32).fill(0x10 + params.seed * 2)
    const aNf1 = new Uint8Array(32).fill(0x11 + params.seed * 2)
    const hasFee = (params.feeLamports ?? 0n) > 0n
    const outputMask = hasFee ? 0b101 : 0b001
    let cm2 = new Uint8Array(32)
    let memosBytes: Uint8Array
    if (hasFee) {
      const feeNote = makeShieldedFeeCm2(params.feeLamports!, wsolMintBytes, 0x80 + params.seed)
      cm2 = feeNote.cm2
      memosBytes = new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN)
      memosBytes.set(new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x30 + params.seed), 0)
      memosBytes.set(feeNote.memo, MEMO_ENTRY_WIRE_LEN)
    } else {
      memosBytes = new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x30 + params.seed)
    }
    const ix = buildTransactInstruction({
      payer: relayerB58,
      poolId: 0,
      vkId: params.vkId ?? 0,
      ckptSlotIdx: 0,
      outLaneId: params.outLaneId,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: params.outMemoSeq ?? 0n,
      outNfSeq: 0n,
      outputMask,
      assetMode: ASSET_MODE_PRIVATE,
      rollover: params.nextMemoSeq != null ? { nextMemoSeq: params.nextMemoSeq } : undefined,
      proof192: dummyProof,
      nf0: aNf0,
      nf1: aNf1,
      cm0: new Uint8Array(32).fill(0x40 + params.seed),
      cm1: new Uint8Array(32),
      cm2,
      publicAmountOut: 0n,
      relayerFeeAmount: 0n,
      memosBytes,
    })
    return { instructionDataB64: toBase64(ix.data), accounts: ix.accounts }
  }

  // Case A: Valid 4-ix parallel `2 -> 1` merge batch spanning lanes 0 & 1 with rollover on lane 0!
  // Lane 0 starts at nextLeaf = 95 (1 slot left in memo(0)):
  //   - ix 0 (lane 0): writes leaf 95 into memo(0)
  //   - ix 1 (lane 0): writes leaf 96 -> rolls into memo(1) (missing on-chain -> auto-prepend OpenPage!)
  //   - ix 2 (lane 0): writes leaf 97 -> also references memo(1) (deduplicated -> only ONE OpenPage!)
  //   - ix 3 (lane 1): writes leaf 2 + cm2 fee (14,000,000 lamports covering full batch cost!)
  const batch4 = [
    makeMergeIx({ seed: 0, outLaneId: 0, outMemoSeq: 0n }),
    makeMergeIx({ seed: 1, outLaneId: 0, outMemoSeq: 1n }),
    makeMergeIx({ seed: 2, outLaneId: 0, outMemoSeq: 1n, feeLamports: 6_000_000n }),
    makeMergeIx({ seed: 3, outLaneId: 1, outMemoSeq: 0n, feeLamports: 8_000_000n }),
  ]

  const guardA = createMockGuard()
  const envA = {
    RELAY_GUARD: guardA.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    MAINNET_RELAYER_FVK_JSON: fvkJson,
  } as Env

  const dummyPageBytes = new Uint8Array(64).fill(0x5a)
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane1Pda = deriveLanePdaSync(0, 1).address
  const memo0L0 = deriveMemoPdaSync(0, 0, 0n).address
  const memo1L0 = deriveMemoPdaSync(0, 0, 1n).address // MISSING on-chain!
  const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 95n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane1Pda, { bytes: makeLaneStateBytes({ laneId: 1, nextLeaf: 2n, nfCount: 4n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    [memo0L0, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 1, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 1, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 1, 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 1, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
  ])

  let sentBatchWire: Uint8Array | null = null
  const simulatedBatchOutflow = 12_500_000n // < combined 14,000,000 lamports cm2 fees!
  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x71)) } },
        })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        const value = addrs.map((a) => {
          const hit = accMap.get(a)
          return hit
            ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner }
            : null
        })
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value } })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: {
              err: null,
              logs: ['OpenPage OK', 'Transact 0 OK', 'Transact 1 OK', 'Transact 2 OK', 'Transact 3 OK'],
              unitsConsumed: 860_000,
              accounts: [
                { lamports: Number(500_000_000n - simulatedBatchOutflow), owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        sentBatchWire = fromBase64(String(body.params[0]))
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5BatchMergeMockSig111111111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: [{ slot: 20001, err: null, confirmationStatus: 'confirmed' }] },
        })
      }
      throw new Error(`Unexpected RPC method: ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructions: batch4,
          }),
        }),
        envA,
      )
      assert.equal(res.status, 200)
      const body = (await res.json()) as {
        ok: boolean
        instructionCount: number
        openedPagesCount: number
        billingMode: string
        txWireBytes: number
        simulatedFeeUnits: string
        netSponsoredLamports: string
      }
      assert.equal(body.ok, true)
      assert.equal(body.instructionCount, 4)
      assert.equal(body.openedPagesCount, 1, 'memo1 on lane 0 must be opened ONCE (deduplicated across ix 1 & ix 2)')
      assert.equal(body.billingMode, 'self_paying')
      assert.equal(body.simulatedFeeUnits, '14000000')
      assert.equal(body.netSponsoredLamports, '0')
      assert.ok(body.txWireBytes <= 4_096, `Tx v1 wire bytes (${body.txWireBytes}) must be <= 4,096 B`)

      // All 8 nullifiers must be reserved atomically in ONE guard.begin() call!
      assert.equal(guardA.relayBeginCalls.length, 1)
      assert.equal((guardA.relayBeginCalls[0]!.nullifiers as string[]).length, 8)

      assert.ok(sentBatchWire)
      const decoded = decodeV1Tx(sentBatchWire)
      assert.equal(decoded.instructions.length, 5)
      assert.equal(decoded.instructions[0]!.data[0], TAG_OPEN_PAGE)
      assert.equal(decoded.instructions[0]!.data[1], OPEN_PAGE_KIND_MEMO)
      assert.equal(decoded.instructions[0]!.accounts[4], memo1L0)
      for (let i = 1; i <= 4; i++) {
        assert.equal(decoded.instructions[i]!.data[0], TAG_TRANSACT)
      }
    },
  )

  // Case B: Insufficient combined cm2 fees on 2-ix batch -> 402 FEE_REQUIRED
  const underpaidBatch2 = [
    makeMergeIx({ seed: 0, outLaneId: 1, outMemoSeq: 0n, feeLamports: 1_000_000n }),
    makeMergeIx({ seed: 1, outLaneId: 1, outMemoSeq: 0n, feeLamports: 1_000_000n }),
  ]
  const guardB = createMockGuard()
  const envB = {
    RELAY_GUARD: guardB.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    MAINNET_RELAYER_FVK_JSON: fvkJson,
  } as Env
  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x72)) } },
        })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: addrs.map((a) => {
              const hit = accMap.get(a)
              return hit
                ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner }
                : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: {
              err: null,
              logs: ['Transact 0 OK', 'Transact 1 OK'],
              unitsConsumed: 400_000,
              accounts: [{ lamports: 493_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }],
            },
          },
        })
      }
      throw new Error(`Unexpected RPC method: ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ cluster: 'mainnet', instructions: underpaidBatch2 }),
        }),
        envB,
      )
      assert.equal(res.status, 402)
      const errBody = (await res.json()) as { code: string }
      assert.equal(errBody.code, 'FEE_REQUIRED')
      assert.equal(guardB.relayReleaseCalls.length, 1)
    },
  )

  // Case C: Reject empty batch, >4 batch, mixed public withdraw, duplicate nullifiers, and non-zero vk_id
  // 1. Empty batch
  assert.throws(
    () => validateRelaySubmission({ instructions: [] }, relayerPubkey, allowedPre, relayerFvk),
    FirewallError,
  )
  // 2. 5 instructions (> 4)
  assert.throws(
    () =>
      validateRelaySubmission(
        {
          instructions: [0, 1, 2, 3, 4].map((seed) => makeMergeIx({ seed, outLaneId: 0 })),
        },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('at most 4'),
  )
  // 3. Mixed non-private withdraw inside batch
  const pubWithdraw = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    ckptSlotIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: true,
    publicOutflow: { mint: WSOL_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x91),
    nf1: new Uint8Array(32).fill(0x92),
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 100_000_000n,
    relayerFeeAmount: 0n,
    recipient: base58Encode(new Uint8Array(32).fill(0x33)),
    memosBytes: new Uint8Array(0),
  })
  assert.throws(
    () =>
      validateRelaySubmission(
        {
          instructions: [
            makeMergeIx({ seed: 0, outLaneId: 0 }),
            { instructionDataB64: toBase64(pubWithdraw.data), accounts: pubWithdraw.accounts },
          ],
        },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('ASSET_MODE_PRIVATE'),
  )
  // 4. Duplicate nullifiers across two instructions in batch
  assert.throws(
    () =>
      validateRelaySubmission(
        {
          instructions: [
            makeMergeIx({ seed: 0, outLaneId: 0 }),
            makeMergeIx({ seed: 0, outLaneId: 1 }),
          ],
        },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('Duplicate nullifier'),
  )
  // 5. Non-zero vk_id inside batch
  assert.throws(
    () =>
      validateRelaySubmission(
        {
          instructions: [
            makeMergeIx({ seed: 0, outLaneId: 0 }),
            makeMergeIx({ seed: 1, outLaneId: 0, vkId: 3 }),
          ],
        },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('vk_id'),
  )
})

test('fetchPoolCheckpointSnapshot scans remaining ring slots when firstBatch only contains an ancient wrapped checkpoint', async () => {
  const mockRpcWrap = 'https://mock-rpc.local/ckpt-ring-wrap'
  const mockRpcRecent = 'https://mock-rpc.local/ckpt-ring-recent'
  const poolPda = derivePoolPdaSync(0).address
  const lanePdas = [0, 1, 2, 3].map((l) => deriveLanePdaSync(0, l).address)
  const poolBytes = makePoolStateBytes({ activeLanes: 4, ckptInterval: 16n, maxCkptAge: 3600n })

  const ancientSlotIdx = 1000 % 256
  const newerSlotIdx = 850 % 256
  const recentBoundarySlotIdx = 905 % 256

  const ancientCkptPda = deriveCheckpointPdaSync(0, ancientSlotIdx).address
  const newerCkptPda = deriveCheckpointPdaSync(0, newerSlotIdx).address
  const recentBoundaryPda = deriveCheckpointPdaSync(0, recentBoundarySlotIdx).address

  const ancientCkptBytes = makeCheckpointBytes({
    slotIdx: ancientSlotIdx,
    epochId: 744n,
    publishedSlot: 744n * 16n,
    laneCounts: [1n, 0n, 0n, 0n],
  })
  const newerCkptBytes = makeCheckpointBytes({
    slotIdx: newerSlotIdx,
    epochId: 850n,
    publishedSlot: 850n * 16n,
    laneCounts: [5n, 3n, 0n, 0n],
  })
  const recentBoundaryBytes = makeCheckpointBytes({
    slotIdx: recentBoundarySlotIdx,
    epochId: 905n,
    publishedSlot: 905n * 16n,
    laneCounts: [7n, 3n, 0n, 0n],
  })

  let multiCallsWrap = 0
  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getAccountInfo' && body.params[0] === poolPda) {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { data: [toBase64(poolBytes), 'base64'], lamports: 5_000_000, owner: AUDREN_PROGRAM_ID } },
        })
      }
      if (body.method === 'getSlot') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: 16_000 })
      }
      if (body.method === 'getMultipleAccounts') {
        multiCallsWrap++
        const addrs = body.params[0] as string[]
        const value = addrs.map((addr) => {
          const laneIdx = lanePdas.indexOf(addr)
          if (laneIdx >= 0) {
            return {
              data: [toBase64(makeLaneStateBytes({ laneId: laneIdx, nextLeaf: laneIdx === 0 ? 5n : laneIdx === 1 ? 3n : 0n })), 'base64'],
              lamports: 5_000_000,
              owner: AUDREN_PROGRAM_ID,
            }
          }
          if (addr === ancientCkptPda) {
            return { data: [toBase64(ancientCkptBytes), 'base64'], lamports: 5_000_000, owner: AUDREN_PROGRAM_ID }
          }
          if (addr === newerCkptPda) {
            return { data: [toBase64(newerCkptBytes), 'base64'], lamports: 5_000_000, owner: AUDREN_PROGRAM_ID }
          }
          return null
        })
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value } })
      }
      throw new Error(`Unexpected RPC call in ring-wrap test: ${body.method}`)
    },
    async () => {
      const snap = await fetchPoolCheckpointSnapshot(mockRpcWrap, 0)
      assert.ok(snap)
      assert.ok(multiCallsWrap > 1)
      assert.equal(snap.latestCkpt?.epochId, 850n)
      assert.equal(snap.latestCkpt?.slotIdx, newerSlotIdx)
      assert.equal(snap.targetSlotCkpt?.epochId, 744n)
    },
  )

  let multiCallsRecent = 0
  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getAccountInfo' && body.params[0] === poolPda) {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { data: [toBase64(poolBytes), 'base64'], lamports: 5_000_000, owner: AUDREN_PROGRAM_ID } },
        })
      }
      if (body.method === 'getSlot') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: 16_000 })
      }
      if (body.method === 'getMultipleAccounts') {
        multiCallsRecent++
        const addrs = body.params[0] as string[]
        const value = addrs.map((addr) => {
          const laneIdx = lanePdas.indexOf(addr)
          if (laneIdx >= 0) {
            return {
              data: [toBase64(makeLaneStateBytes({ laneId: laneIdx, nextLeaf: 0n })), 'base64'],
              lamports: 5_000_000,
              owner: AUDREN_PROGRAM_ID,
            }
          }
          if (addr === ancientCkptPda) {
            return { data: [toBase64(ancientCkptBytes), 'base64'], lamports: 5_000_000, owner: AUDREN_PROGRAM_ID }
          }
          if (addr === recentBoundaryPda) {
            return { data: [toBase64(recentBoundaryBytes), 'base64'], lamports: 5_000_000, owner: AUDREN_PROGRAM_ID }
          }
          return null
        })
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value } })
      }
      throw new Error(`Unexpected RPC call in recent ring test: ${body.method}`)
    },
    async () => {
      const snap = await fetchPoolCheckpointSnapshot(mockRpcRecent, 0)
      assert.ok(snap)
      assert.equal(multiCallsRecent, 1)
      assert.equal(snap.latestCkpt?.epochId, 905n)
    },
  )
})
