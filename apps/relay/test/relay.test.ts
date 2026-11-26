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
  CLASSIC_TOKEN_PROGRAM_ID,
  CU_LIMIT_EXEC_VIA_ESCROW_BASE,
  CU_LIMIT_OPEN_PAGE,
  CU_LIMIT_TRANSACT_FULL_EXIT,
  CU_LIMIT_TRANSACT_PRIVATE,
  CU_LIMIT_TRANSACT_WITHDRAW,
  CU_LIMIT_TRANSACT_WITHDRAW_HOOK,
  EPOCH_RING_LEN,
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
  PL_OFF_NF_RENT_FEE,
  PL_OFF_NOTE_RENT_FEE,
  PL_OFF_POOL_ID,
  PL_OFF_ROOT_EPOCH_INTERVAL,
  PL_OFF_VERSION,
  POOL_MAGIC,
  POOL_STATE_LEN,
  PROTOCOL_VERSION,
  ROOTS_MAGIC,
  ROOT_HISTORY_LEN,
  ROOT_RING_EPOCH,
  ROOT_RING_SLOT,
  RT_OFF_BUMP,
  RT_OFF_EPOCH_COUNT,
  RT_OFF_EPOCH_CURSOR,
  RT_OFF_EPOCH_INTERVAL,
  RT_OFF_LATEST_SLOT,
  RT_OFF_POOL_ID,
  RT_OFF_SLOT_COUNT,
  RT_OFF_SLOT_CURSOR,
  RT_OFF_STABLE_EPOCH_ID,
  RT_OFF_STABLE_SLOT,
  RT_OFF_VERSION,
  SLOT_RING_LEN,
  SUBROOT_PAGE_LEN,
  SUBTREE_PAGE_LEN,
  SYSTEM_PROGRAM_ID,
  TAG_DEPOSIT,
  TAG_EXEC_VIA_ESCROW,
  TAG_INIT_ROOT_HISTORY,
  TAG_OPEN_PAGE,
  TAG_TRANSACT,
  TOKEN_2022_PROGRAM_ID,
  WSOL_MINT,
  base58Encode,
  buildDepositInstruction,
  buildExecViaEscrowInstruction,
  buildTransactInstruction,
  computeNoteCommitment,
  computeToken2022NetAmount,
  deriveAssetId,
  deriveAssociatedTokenAddressSync,
  deriveEscrowPdaSync,
  deriveKeysFromSeed,
  deriveLanePdaSync,
  deriveLaneRentVaultPdaSync,
  deriveMemoPdaSync,
  deriveNfPagePdaSync,
  derivePoolPdaSync,
  deriveRootsPdaSync,
  deriveStealthOwner,
  deriveSubrootPdaSync,
  deriveSubtreePdaSync,
  deriveVaultAuthPdaSync,
  encryptNoteMemo,
  exportFullViewingKey,
  frToBeBytes,
} from '@audren/sdk'
import {
  DEFAULT_ALLOWED_PRE_IX_PROGRAMS,
  DEFAULT_AUDITED_SWAP_ROUTER_PROGRAMS,
  DEFAULT_SELF_PAY_FEE_MINTS,
  TRUSTED_FREEZE_AUTHORITY_MINTS,
  getRelayerFvk,
  loadPolicyConfig,
  type Env,
} from '../src/env'
import { runAutoRefill } from '../src/cron/refill'
import { bedrockAdapter } from '../src/aggregators/bedrock'
import { dflowAdapter } from '../src/aggregators/dflow'
import { jupiterAdapter } from '../src/aggregators/jupiter'
import { okxAdapter } from '../src/aggregators/okx'
import { findExcludedCpiVenue } from '../src/aggregators/registry'
import { titanAdapter } from '../src/aggregators/titan'
import {
  MULTI_HOP_ROUTER_CU_HEADROOM,
  SINGLE_HOP_ROUTER_CU_HEADROOM,
  computeAggregatorExecCuLimit,
} from '../src/aggregators/types'
import { FirewallError, validateRelaySubmission } from '../src/policy/firewall'
import {
  PRICE_CACHE_MAX_ENTRIES,
  clearPriceCache,
  computeNativeFeeQuote,
  computeSwapFeePlan,
  estimateAtaRentLamports,
  fetchMintPricesUsd,
  getPriceCacheSize,
  grossUpToken2022Amount,
} from '../src/policy/pricing'
import {
  buildOpenPageSolanaIx,
  computeOpenPageCuLimitForBump,
  computeOpenPageIxCuLimit,
  computeToken2022AtaByteLen,
  decodeGlobalRootHistoryHeader,
  deriveOpenPageBumpFromIx,
  deterministicNoteRentFee,
  parseExecEscrowMeta,
  parseMintSafetyInfo,
  parseTransactMeta,
  planMissingOpenPageIxs,
} from '../src/solana/audren'
import {
  BASE58_DEFAULT_MAX_LEN,
  base58Decode,
  buildAndSignV1Transaction,
  fromBase64,
  isValidBase58PubkeyLen,
  isValidPubkey,
  readU16le,
  readU32le,
  readU64le,
  toBase64,
  toHex,
  u64le,
  utf8,
} from '../src/solana/codec'
import {
  ADDRESS_LOOKUP_TABLE_PROGRAM_ID_STR,
  ALT_HEADER_LEN,
  ALT_MAX_DATA_LEN,
  MINT_META_CACHE_MAX_ENTRIES,
  TransactionFailedOnChainError,
  applyToken2022FeeHaircut,
  clearLiveRentScheduleCache,
  computeSwapInputTransferFee,
  fetchLiveRentSchedule,
  fetchMintMetasWithData,
  getMintMetaCacheSize,
  resolveLookupTables,
  rpcCall,
  waitForConfirmation,
} from '../src/solana/rpc'

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

  const scheduledAlarms: number[] = []
  let initPromise: Promise<void> = Promise.resolve()
  const ctx = {
    storage: {
      sql,
      async setAlarm(t: number | Date) {
        scheduledAlarms.push(typeof t === 'number' ? t : t.getTime())
      },
    },
    blockConcurrencyWhile<T>(fn: () => Promise<T>): Promise<T> {
      const p = fn()
      initPromise = p.then(() => undefined)
      return p
    },
  } as unknown as DurableObjectState

  return { db, ctx, scheduledAlarms, ready: () => initPromise }
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

test('Canonical v1.3.0 Pool #0 PDAs and constants match spec', () => {
  assert.equal(PROTOCOL_VERSION, 1)
  assert.equal(MEMO_PAGE_LEN, 10_240)
  assert.equal(MEMO_NOTES_PER_PAGE, 96)
  assert.equal(MEMO_ENTRY_WIRE_LEN, 106)
  assert.equal(ROOT_HISTORY_LEN, 10_216)
  assert.equal(SLOT_RING_LEN, 128)
  assert.equal(EPOCH_RING_LEN, 89)
  assert.equal(derivePoolPdaSync(0).address, '5Bvt5f5QMfsVb9TyX8bzkRMvAX6JSWwRtnymGveF9U3G')
  assert.equal(deriveVaultAuthPdaSync(0).address, '3aMtBvVMatfBvoBWQaTxCPwQ2SWyW5ejceVgLFTtk2WF')
  const roots0 = deriveRootsPdaSync(0)
  assert.equal(roots0.address, '249YJTuRtiKAnh346Tc18kF9bHrktdrTzyJMtvUKUgC7')
  assert.equal(roots0.bump, 254)
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
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
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
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
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
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 1,
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
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 1,
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
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 2,
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
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 2,
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
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 2,
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
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 4,
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

  // Exact v1.3.0 wire size: 560 + 3 (routerIxData) + 106 (1 change memo) = 669 B
  assert.equal(ix.data[0], TAG_EXEC_VIA_ESCROW)
  assert.equal(ix.data.length, 560 + 3 + MEMO_ENTRY_WIRE_LEN)

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
  rootEpochInterval?: bigint
  noteRentFee?: bigint
  nfRentFee?: bigint
}): Uint8Array {
  const buf = new Uint8Array(POOL_STATE_LEN)
  const dv = new DataView(buf.buffer)
  writeAscii(buf, 0, POOL_MAGIC)
  buf[PL_OFF_VERSION] = PROTOCOL_VERSION
  buf[PL_OFF_ACTIVE_LANES] = params.activeLanes ?? 4
  dv.setUint32(PL_OFF_POOL_ID, params.poolId ?? 0, true)
  dv.setBigUint64(PL_OFF_ROOT_EPOCH_INTERVAL, params.rootEpochInterval ?? 32n, true)
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

function makeRootHistoryHeaderBytes(params?: {
  poolId?: number
  slotCursor?: number
  epochCursor?: number
  slotCount?: number
  epochCount?: number
  latestSlot?: bigint
  stableEpochId?: bigint
  stableSlot?: bigint
  epochInterval?: bigint
}): Uint8Array {
  const buf = new Uint8Array(64)
  const dv = new DataView(buf.buffer)
  writeAscii(buf, 0, ROOTS_MAGIC)
  buf[RT_OFF_VERSION] = PROTOCOL_VERSION
  buf[RT_OFF_BUMP] = 254
  dv.setUint16(RT_OFF_SLOT_CURSOR, params?.slotCursor ?? 0, true)
  dv.setUint32(RT_OFF_POOL_ID, params?.poolId ?? 0, true)
  dv.setUint16(RT_OFF_EPOCH_CURSOR, params?.epochCursor ?? 0, true)
  dv.setUint16(RT_OFF_SLOT_COUNT, params?.slotCount ?? 1, true)
  dv.setUint16(RT_OFF_EPOCH_COUNT, params?.epochCount ?? 1, true)
  dv.setBigUint64(RT_OFF_LATEST_SLOT, params?.latestSlot ?? 100n, true)
  dv.setBigUint64(RT_OFF_STABLE_EPOCH_ID, params?.stableEpochId ?? 3n, true)
  dv.setBigUint64(RT_OFF_STABLE_SLOT, params?.stableSlot ?? 96n, true)
  dv.setBigUint64(RT_OFF_EPOCH_INTERVAL, params?.epochInterval ?? 32n, true)
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
  openPageAcquireResult: {
    allowed: boolean
    busyLaneId?: number
    retryAfterSec?: number
  }
}>) {
  const relayBeginCalls: Array<Record<string, unknown>> = []
  const relayReleaseCalls: Array<Record<string, unknown>> = []
  const relayAuthorizeCalls: Array<Record<string, unknown>> = []
  const relayCommitCalls: Array<Record<string, unknown>> = []
  const openPageAcquireCalls: Array<Record<string, unknown>> = []
  const openPageReleaseCalls: Array<Record<string, unknown>> = []
  const openPageLocks = new Map<string, { leaseId: string; expiresAt: number }>()
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
    async acquireOpenPageLock(req: {
      cluster: string
      poolId: number
      laneIds: number[]
      leaseId: string
      ttlMs?: number
    }) {
      openPageAcquireCalls.push(req)
      if (overrides?.openPageAcquireResult) return overrides.openPageAcquireResult
      const now = Date.now()
      for (const [k, v] of openPageLocks) {
        if (v.expiresAt <= now) openPageLocks.delete(k)
      }
      const uniqueLanes = [...new Set(req.laneIds)]
      for (const laneId of uniqueLanes) {
        const key = `${req.cluster}:${req.poolId}:${laneId}`
        const cur = openPageLocks.get(key)
        if (cur && cur.leaseId !== req.leaseId && cur.expiresAt > now) {
          return { allowed: false, busyLaneId: laneId, retryAfterSec: 2 }
        }
      }
      const expiresAt = now + (req.ttlMs ?? 15_000)
      for (const laneId of uniqueLanes) {
        openPageLocks.set(`${req.cluster}:${req.poolId}:${laneId}`, { leaseId: req.leaseId, expiresAt })
      }
      return { allowed: true }
    },
    async releaseOpenPageLock(req: {
      cluster: string
      poolId: number
      laneIds: number[]
      leaseId: string
      graceTtlMs?: number
    }) {
      openPageReleaseCalls.push(req)
      const now = Date.now()
      for (const laneId of [...new Set(req.laneIds)]) {
        const key = `${req.cluster}:${req.poolId}:${laneId}`
        const cur = openPageLocks.get(key)
        if (!cur || cur.leaseId !== req.leaseId) continue
        if (req.graceTtlMs && req.graceTtlMs > 0) {
          openPageLocks.set(key, { leaseId: req.leaseId, expiresAt: now + req.graceTtlMs })
        } else {
          openPageLocks.delete(key)
        }
      }
    },
  }
  return {
    namespace: {
      idFromName: () => ({} as DurableObjectId),
      get: () => stub,
    } as unknown as Env['RELAY_GUARD'],
    relayBeginCalls,
    relayReleaseCalls,
    relayAuthorizeCalls,
    relayCommitCalls,
    openPageAcquireCalls,
    openPageReleaseCalls,
    openPageLocks,
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

test('RelayGuard DO: strictly in-memory ephemeral daily IP salt (zero SQLite salt), drops legacy checkpoint tables, UTC midnight alarm, and ZERO ip_hash on inflight_nullifiers', async () => {
  const RelayGuard = await getRelayGuardClass()

  // Test fresh DO + legacy migrations (pre-populated `daily_ip_salts`, `checkpoint_locks`, `checkpoint_ip_hits`, AND `inflight_nullifiers.ip_hash`!)
  const harness = createSqliteDoHarness(`
    CREATE TABLE daily_ip_salts (
      day TEXT PRIMARY KEY,
      salt_hex TEXT NOT NULL
    );
    INSERT INTO daily_ip_salts (day, salt_hex) VALUES ('2026-11-22', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    CREATE TABLE checkpoint_locks (
      cluster_pool TEXT PRIMARY KEY,
      locked_until INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE checkpoint_ip_hits (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip_hash TEXT NOT NULL
    );
    CREATE TABLE inflight_nullifiers (
      nullifier TEXT PRIMARY KEY,
      ip_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
  `)
  const guard = new RelayGuard(harness.ctx, {} as Env)
  await harness.ready()

  // 1. Verify legacy `daily_ip_salts`, `checkpoint_locks`, and `checkpoint_ip_hits` tables were scrubbed!
  const scrubbedTables = harness.db
    .prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('daily_ip_salts', 'checkpoint_locks', 'checkpoint_ip_hits')",
    )
    .all()
  assert.equal(scrubbedTables.length, 0, 'legacy salt and checkpoint tables must NOT exist in DO SQLite storage')
  assert.ok(harness.scheduledAlarms.length >= 1, 'UTC midnight alarm must be scheduled on init')

  // 2. Verify `inflight_nullifiers` schema has ZERO `ip_hash` column after constructor migration
  const cols = harness.db
    .prepare('PRAGMA table_info(inflight_nullifiers)')
    .all() as Array<{ name: string }>
  const colNames = cols.map((c) => c.name)
  assert.deepEqual(colNames, ['nullifier', 'expires_at', 'owner_token'])
  assert.ok(!colNames.includes('ip_hash'), 'inflight_nullifiers must NEVER contain ip_hash')

  // 3. Verify ephemeral in-memory daily salt rotates by UTC day and NEVER equals pubkey-derived hash
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

  // Day 2 rollover via UTC alarm + rollover purges Day 1 salt and produces a different hash
  const alarmsBeforeRollover = harness.scheduledAlarms.length
  await guard.runUtcRolloverMaintenance(day2Ms)
  assert.ok(harness.scheduledAlarms.length > alarmsBeforeRollover, 'alarm rollover must reschedule next UTC midnight')
  const hashDay2 = await guard.hashClientIp(clientIp, day2Ms)
  assert.notEqual(hashDay2, hashDay1A, 'UTC day rollover must rotate ephemeral salt')

  // Even after generating Day 2 salt, SQLite STILL has zero `daily_ip_salts` table
  assert.equal(
    harness.db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'daily_ip_salts'")
      .all().length,
    0,
  )

  // 4. Verify `begin()` hashes IP ephemerally without writing `ip_hash` onto `inflight_nullifiers`
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
    assert.deepEqual(Object.keys(row).sort(), ['expires_at', 'nullifier', 'owner_token'])
  }

  // Concurrent duplicate nullifier MUST be blocked with 409
  const dupRes = await guard.begin({ clientIp: '198.51.100.9', nullifiers: [nfB] })
  assert.equal(dupRes.allowed, false)
  assert.equal(dupRes.status, 409)
  assert.equal(dupRes.code, 'DUPLICATE_NULLIFIER')

  // Lock ownership protection: a stale lockOwner CANNOT delete a newer request's lock
  assert.ok(beginRes.lockOwner && beginRes.lockOwner.length > 0)
  await guard.release({
    ipHash: beginRes.ipHash!,
    lockOwner: 'wrong-stale-owner-token',
    cluster: 'mainnet',
    nullifiers: [nfA, nfB],
  })
  const stillLocked = await guard.begin({ clientIp: '198.51.100.9', nullifiers: [nfA] })
  assert.equal(stillLocked.allowed, false)
  assert.equal(stillLocked.code, 'DUPLICATE_NULLIFIER')
  await guard.release({
    ipHash: beginRes.ipHash!,
    lockOwner: beginRes.lockOwner,
    cluster: 'mainnet',
    nullifiers: [nfA, nfB],
  })
  const unlockedNow = await guard.begin({ clientIp: '198.51.100.9', nullifiers: [nfA] })
  assert.equal(unlockedNow.allowed, true)

  // Durable pending_broadcasts reconciliation (confirmed, failed revert-burn, expired)
  await guard.recordPendingBroadcast({
    signature: 'sigPendingFail111111111111111111111111111111',
    cluster: 'mainnet',
    payerPubkey: 'Payer11111111111111111111111111111111111111',
    ipHash: beginRes.ipHash!,
    opKind: 'exec_escrow',
    selfPaying: true,
    sponsoredLamports: 0,
    burnedFeeLamports: 10_000,
    lastValidBlockHeight: 100,
  })
  const pendingList = await guard.listPendingBroadcasts('mainnet')
  assert.equal(pendingList.length, 1)
  assert.equal(
    await guard.settlePendingBroadcast({
      signature: 'sigPendingFail111111111111111111111111111111',
      outcome: 'failed',
    }),
    true,
  )
  const burnedRow = harness.db
    .prepare('SELECT burned_lamports, revert_count FROM daily_revert_burns WHERE cluster = ?')
    .get('mainnet') as { burned_lamports: number; revert_count: number }
  assert.equal(burnedRow.burned_lamports, 10_000)
  assert.equal(burnedRow.revert_count, 1)

  // Refill lock mutual exclusion
  assert.equal(await guard.acquireRefillLock({ lockKey: 'global-refill', leaseId: 'lease-a' }), true)
  assert.equal(await guard.acquireRefillLock({ lockKey: 'global-refill', leaseId: 'lease-b' }), false)
  await guard.releaseRefillLock({ lockKey: 'global-refill', leaseId: 'lease-b' })
  assert.equal(await guard.acquireRefillLock({ lockKey: 'global-refill', leaseId: 'lease-b' }), false)
  await guard.releaseRefillLock({ lockKey: 'global-refill', leaseId: 'lease-a' })
  assert.equal(await guard.acquireRefillLock({ lockKey: 'global-refill', leaseId: 'lease-b' }), true)
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

      // 6. GET /v1/info reports v1.3.0, canonical rootsPda, maxBatchSize=4, defaultNullifiers=2, ZERO checkpoint fields, AND rotates relayerPubkey across pool!
      const seenRelayers = new Set<string>()
      let lastInfo: {
        version: string
        protocolVersion: number
        rootsPda: string
        relayerPubkey: string
        relayerPubkeys: string[]
        checkpointSupport?: unknown
        supportedOperations: {
          transfer: { tag: number; maxBatchSize: number; flatFee: boolean; requiresAmount: boolean; defaultNullifiers: number }
          withdraw: { tag: number; defaultNullifiers: number }
          exec_escrow: { tag: number; defaultNullifiers: number }
          checkpoint?: unknown
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
      assert.equal(lastInfo!.version, '1.3.0')
      assert.equal(lastInfo!.protocolVersion, PROTOCOL_VERSION)
      assert.equal(lastInfo!.rootsPda, '249YJTuRtiKAnh346Tc18kF9bHrktdrTzyJMtvUKUgC7')
      assert.deepEqual(lastInfo!.relayerPubkeys, poolPubkeys)
      assert.equal('checkpointSupport' in lastInfo!, false)
      assert.equal('checkpoint' in lastInfo!.supportedOperations, false)
      assert.equal(lastInfo!.supportedOperations.transfer.tag, TAG_TRANSACT)
      assert.equal(lastInfo!.supportedOperations.transfer.maxBatchSize, 4)
      assert.equal(lastInfo!.supportedOperations.transfer.flatFee, true)
      assert.equal(lastInfo!.supportedOperations.transfer.requiresAmount, false)
      assert.equal(lastInfo!.supportedOperations.transfer.defaultNullifiers, 2)
      assert.equal(lastInfo!.supportedOperations.withdraw.tag, TAG_TRANSACT)
      assert.equal(lastInfo!.supportedOperations.withdraw.defaultNullifiers, 2)
      assert.equal(lastInfo!.supportedOperations.exec_escrow.tag, TAG_EXEC_VIA_ESCROW)
      assert.equal(lastInfo!.supportedOperations.exec_escrow.defaultNullifiers, 2)
      assert.deepEqual(lastInfo!.supportedOperations.deposit.tags, [TAG_DEPOSIT])

      // 7. Root index omits removed POST /v1/checkpoint and POST /v1/checkpoint returns HTTP 404
      const rootRes = await worker.fetch(new Request('https://relay.audren.xyz/'), env)
      const rootJson = (await rootRes.json()) as { version: string; rootsPda: string; endpoints: string[] }
      assert.equal(rootJson.version, '1.3.0')
      assert.equal(rootJson.rootsPda, '249YJTuRtiKAnh346Tc18kF9bHrktdrTzyJMtvUKUgC7')
      assert.equal(rootJson.endpoints.some((e) => e.includes('checkpoint')), false)
      const removedCkptRes = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/checkpoint', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ cluster: 'mainnet' }),
        }),
        env,
      )
      assert.equal(removedCkptRes.status, 404)
    },
  )
})

// ============================================================================
// 3. v1.3.0 GlobalRootHistory Firewall, Dual-Ring Validation, Proactive >= 90%
//    Auto-OpenPage, and Calibrated Tight CU Budgets
// ============================================================================

test('v1.3.0 GlobalRootHistory: header decoder, dual-ring bounds, accounts[2] writability, Tag 4 rejection, and rootsPda isolation', () => {
  const rootsPda = deriveRootsPdaSync(0).address
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const vaultWsolAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultUsdcAta = deriveAssociatedTokenAddressSync(vaultAuth, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrow = deriveEscrowPdaSync(0, 1).address
  const escrowInAta = deriveAssociatedTokenAddressSync(escrow, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowOutAta = deriveAssociatedTokenAddressSync(escrow, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const recipient = base58Encode(new Uint8Array(32).fill(0x33))

  // 1. decodeGlobalRootHistoryHeader parses valid 64 B header and rejects malformed magic/counters
  const hdrBytes = makeRootHistoryHeaderBytes({
    slotCursor: 5,
    epochCursor: 2,
    slotCount: 10,
    epochCount: 4,
    latestSlot: 500n,
    stableEpochId: 15n,
    stableSlot: 480n,
    epochInterval: 32n,
  })
  const decodedHdr = decodeGlobalRootHistoryHeader(hdrBytes)
  assert.equal(decodedHdr.slotCursor, 5)
  assert.equal(decodedHdr.epochCursor, 2)
  assert.equal(decodedHdr.slotCount, 10)
  assert.equal(decodedHdr.epochCount, 4)
  assert.equal(decodedHdr.latestSlot, 500n)
  assert.equal(decodedHdr.stableEpochId, 15n)
  assert.equal(decodedHdr.stableSlot, 480n)
  assert.equal(decodedHdr.epochInterval, 32n)
  const badMagic = new Uint8Array(hdrBytes)
  badMagic[0] = 0x00
  assert.throws(() => decodeGlobalRootHistoryHeader(badMagic))

  // 2. Tag 4 (InitRootHistory) is rejected by the relay firewall
  const fullExitIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_SLOT,
    rootRingIdx: SLOT_RING_LEN - 1,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: true,
    publicOutflow: { mint: WSOL_MINT, vaultAta: vaultWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    proof192: dummyProof,
    nf0,
    nf1: nf1NonZero,
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 100_000_000n,
    relayerFeeAmount: 3_000_000n,
    recipient,
    relayerFeeRecipient: relayerB58,
    memosBytes: new Uint8Array(0),
  })
  assert.equal(fullExitIx.data.length, 380)
  assert.equal(fullExitIx.accounts[2]!.pubkey, rootsPda)
  assert.equal(fullExitIx.accounts[2]!.isWritable, false)

  const tag4Data = new Uint8Array(fullExitIx.data)
  tag4Data[0] = TAG_INIT_ROOT_HISTORY
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructionDataB64: toBase64(tag4Data), accounts: fullExitIx.accounts },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('InitRootHistory'),
  )

  // 3. Dual-ring bounds validation: slot ring [0..127], epoch ring [0..88]; reject out-of-bounds & kind >= 2
  const validFullExit = validateRelaySubmission(
    { instructionDataB64: toBase64(fullExitIx.data), accounts: fullExitIx.accounts },
    relayerPubkey,
    allowedPre,
    relayerFvk,
  )
  assert.equal(validFullExit.transactMeta?.rootRingKind, ROOT_RING_SLOT)
  assert.equal(validFullExit.transactMeta?.rootRingIdx, SLOT_RING_LEN - 1)

  for (const [kind, idx] of [
    [ROOT_RING_SLOT, SLOT_RING_LEN],
    [ROOT_RING_EPOCH, EPOCH_RING_LEN],
    [2, 0],
  ] as const) {
    const badRingData = new Uint8Array(fullExitIx.data)
    badRingData[10] = kind
    badRingData[11] = idx
    assert.throws(
      () =>
        validateRelaySubmission(
          { instructionDataB64: toBase64(badRingData), accounts: fullExitIx.accounts },
          relayerPubkey,
          allowedPre,
          relayerFvk,
        ),
      FirewallError,
    )
  }

  // 4. Exact accounts[2] (`rootsPda`) identity & writability checks:
  //    - Full exit (`outputMask === 0`) MUST be read-only (`isWritable === false`)
  const writableFullExitAccs = fullExitIx.accounts.map((a, idx) =>
    idx === 2 ? { ...a, isWritable: true } : a,
  )
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructionDataB64: toBase64(fullExitIx.data), accounts: writableFullExitAccs },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('read-only'),
  )

  //    - Wrong accounts[2] pubkey MUST be rejected
  const wrongRootsAccs = fullExitIx.accounts.map((a, idx) =>
    idx === 2 ? { ...a, pubkey: derivePoolPdaSync(0).address } : a,
  )
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructionDataB64: toBase64(fullExitIx.data), accounts: wrongRootsAccs },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('GlobalRootHistory'),
  )

  //    - Transact with outputs (`outputMask !== 0`) MUST mark accounts[2] writable (`isWritable === true`)
  const privTx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: EPOCH_RING_LEN - 1,
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
    memosBytes: new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x22),
  })
  assert.equal(privTx.accounts[2]!.isWritable, true)
  const roPrivAccs = privTx.accounts.map((a, idx) => (idx === 2 ? { ...a, isWritable: false } : a))
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructionDataB64: toBase64(privTx.data), accounts: roPrivAccs },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('writable'),
  )

  // 5. ExecViaEscrow (`560 B` header): requires writable `rootsPda` at [2], validates ring bounds,
  //    and blocks `rootsPda` in `router_accounts`, `preInstructions`, and `setupAtas`!
  const execBase = buildExecViaEscrowInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    escrowShard: 1,
    changeMask: 0,
    inLeg: { mint: WSOL_MINT, vaultAta: vaultWsolAta, escrowAta: escrowInAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    outLeg: { mint: USDC_MINT, vaultAta: vaultUsdcAta, escrowAta: escrowOutAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    relayerFeeAmount: 0n,
    proof192: dummyProof,
    nf0,
    nf1: nf1NonZero,
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    amountIn: 100_000_000n,
    minAmountOut: 1_000_000n,
    outStealthOwner: new Uint8Array(32).fill(0x02),
    outBlinding: new Uint8Array(32).fill(0x03),
    dynMemoHead: new Uint8Array(34).fill(0x04),
    dynMemoMask: new Uint8Array(72).fill(0x05),
    routerProg: base58Encode(new Uint8Array(32).fill(0x55)),
    routerIxData: new Uint8Array([1, 2, 3]),
    routerAccounts: [{ pubkey: base58Encode(new Uint8Array(32).fill(0x66)), isSigner: false, isWritable: true }],
    changeMemos: new Uint8Array(0),
  })
  assert.equal(execBase.data.length, 560 + 3)

  // Read-only rootsPda on ExecViaEscrow MUST fail
  const roExecAccs = execBase.accounts.map((a, idx) => (idx === 2 ? { ...a, isWritable: false } : a))
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructionDataB64: toBase64(execBase.data), accounts: roExecAccs },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('writable'),
  )

  // Invalid root ring on ExecViaEscrow MUST fail
  const badExecRing = new Uint8Array(execBase.data)
  badExecRing[10] = ROOT_RING_EPOCH
  badExecRing[11] = EPOCH_RING_LEN
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructionDataB64: toBase64(badExecRing), accounts: execBase.accounts },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    FirewallError,
  )

  // rootsPda inside router_accounts MUST fail
  const execWithRootsRouter = buildExecViaEscrowInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    escrowShard: 1,
    changeMask: 0,
    inLeg: { mint: WSOL_MINT, vaultAta: vaultWsolAta, escrowAta: escrowInAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    outLeg: { mint: USDC_MINT, vaultAta: vaultUsdcAta, escrowAta: escrowOutAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    relayerFeeAmount: 0n,
    proof192: dummyProof,
    nf0,
    nf1: nf1NonZero,
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    amountIn: 100_000_000n,
    minAmountOut: 1_000_000n,
    outStealthOwner: new Uint8Array(32).fill(0x02),
    outBlinding: new Uint8Array(32).fill(0x03),
    dynMemoHead: new Uint8Array(34).fill(0x04),
    dynMemoMask: new Uint8Array(72).fill(0x05),
    routerProg: base58Encode(new Uint8Array(32).fill(0x55)),
    routerIxData: new Uint8Array([1, 2, 3]),
    routerAccounts: [{ pubkey: rootsPda, isSigner: false, isWritable: false }],
    changeMemos: new Uint8Array(0),
  })
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructionDataB64: toBase64(execWithRootsRouter.data), accounts: execWithRootsRouter.accounts },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('router_accounts'),
  )

  // rootsPda inside preInstructions MUST fail
  assert.throws(
    () =>
      validateRelaySubmission(
        {
          instructionDataB64: toBase64(execBase.data),
          accounts: execBase.accounts,
          preInstructions: [
            {
              programId: DEFAULT_ALLOWED_PRE_IX_PROGRAMS[0]!,
              accounts: [{ pubkey: rootsPda, isSigner: false, isWritable: false }],
              data: toBase64(new Uint8Array([1, 2, 3])),
            },
          ],
        },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('GlobalRootHistory'),
  )

  // rootsPda inside setupAtas MUST fail
  assert.throws(
    () =>
      validateRelaySubmission(
        {
          instructionDataB64: toBase64(execBase.data),
          accounts: execBase.accounts,
          setupAtas: [{ owner: rootsPda, mint: WSOL_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID }],
        },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('GlobalRootHistory'),
  )
})

test('v1.3.0 Auto-OpenPage (>= 90% lookahead when LaneRentVault funded, 0 deficit) & Calibrated Tight CU Budgets', async () => {
  const worker = await getWorker()
  const poolPda = derivePoolPdaSync(0).address
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const vaultWsolAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultUsdcAta = deriveAssociatedTokenAddressSync(vaultAuth, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)
  const poolBytes = makePoolStateBytes({ activeLanes: 4, rootEpochInterval: 32n, noteRentFee: 1_000_000n, nfRentFee: 113_567n })

  // 1. Proactive >= 90% lookahead (`nextLeaf = 86` -> memoRem = 10 <= 10, `flags = 0`) prepends OpenPage(MEMO, 1)
  //    ONLY when LaneRentVault covers full rent (0 deficit), and skips cleanly when underfunded!
  const memo0 = deriveMemoPdaSync(0, 0, 0n).address
  const memo1 = deriveMemoPdaSync(0, 0, 1n).address
  const sub0 = deriveSubtreePdaSync(0, 0, 0n).address
  const sr0 = deriveSubrootPdaSync(0, 0, 0n).address
  const nfPage0 = deriveNfPagePdaSync(0, 0, 0n).address

  const { cm2: feeCm2, memo: feeMemo } = makeShieldedFeeCm2(3_500_000n, wsolMintBytes, 0x31)
  const privLookaheadIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b101,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x91),
    nf1: new Uint8Array(32).fill(0x92),
    cm0: new Uint8Array(32).fill(0x10),
    cm1: new Uint8Array(32),
    cm2: feeCm2,
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: (() => {
      const m = new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN)
      m.set(new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x11), 0)
      m.set(feeMemo, MEMO_ENTRY_WIRE_LEN)
      return m
    })(),
  })

  const runSubmitScenario = async (params: {
    rpcUrl: string
    ix: { data: Uint8Array; accounts: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }> }
    nextLeaf: bigint
    nfCount: bigint
    vaultLamports: number
    subSeq?: bigint
    rootSeq?: bigint
    memoSeq?: bigint
    nfSeq?: bigint
    setupAtas?: Array<{ owner: string; mint: string; tokenProgram: string }>
    extraPreAccounts?: Array<[string, { bytes: Uint8Array; lamports: number; owner: string }]>
    extraSimAccounts?: Array<{ lamports: number; owner: string; data: [string, string] }>
  }) => {
    const guard = createMockGuard()
    const env = {
      RELAY_GUARD: guard.namespace,
      MAINNET_RPC_URL: params.rpcUrl,
      MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
      MAINNET_RELAYER_FVK_JSON: JSON.stringify({
        spendPkHex: toHex(relayerFvk.spendPk),
        nkHex: toHex(relayerFvk.nk),
        viewSkHex: toHex(relayerFvk.viewSk),
        viewPkHex: toHex(relayerFvk.viewPk),
      }),
    } as Env
    const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
      [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
      [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: params.nextLeaf, nfCount: params.nfCount }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0RentVault, { bytes: new Uint8Array(16), lamports: params.vaultLamports, owner: AUDREN_PROGRAM_ID }],
      [deriveSubtreePdaSync(0, 0, params.subSeq ?? 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
      [deriveSubrootPdaSync(0, 0, params.rootSeq ?? 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
      [deriveMemoPdaSync(0, 0, params.memoSeq ?? 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
      [deriveNfPagePdaSync(0, 0, params.nfSeq ?? 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
      ...(params.extraPreAccounts ?? []),
    ])
    let sentWire: Uint8Array | null = null
    const res = await withMockFetch(
      async (_url, init) => {
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getMinimumBalanceForRentExemption') {
          const len = Number(body.params[0])
          const rent =
            len === 0 ? 890_880 : len === 16 ? 1_002_240 : len === 165 ? 2_039_280 : len === SUBTREE_PAGE_LEN ? 58_340_000 : len === MEMO_PAGE_LEN ? 72_149_760 : 68_140_000
          return Response.json({ jsonrpc: '2.0', id: 1, result: rent })
        }
        if (body.method === 'getAccountInfo') {
          const hit = accMap.get(String(body.params[0]))
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: { value: hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null },
          })
        }
        if (body.method === 'getLatestBlockhash') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x71)) } } })
        }
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 50_000 },
              value: addrs.map((a) => {
                const hit = accMap.get(a)
                return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
              }),
            },
          })
        }
        if (body.method === 'simulateTransaction') {
          const simAccs = [
            { lamports: 497_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
            ...(params.extraSimAccounts ?? []),
          ]
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: { context: { slot: 50_000 }, value: { err: null, logs: ['OK'], unitsConsumed: 150_000, accounts: simAccs } },
          })
        }
        if (body.method === 'sendTransaction') {
          sentWire = fromBase64(String(body.params[0]))
          return Response.json({ jsonrpc: '2.0', id: 1, result: '5V130AutoOpenCuMockSig1111111111111111111111' })
        }
        if (body.method === 'getSignatureStatuses') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 50_001, err: null, confirmationStatus: 'confirmed' }] } })
        }
        throw new Error(`Unexpected RPC in v1.3.0 CU/lookahead test: ${body.method}`)
      },
      async () =>
        worker.fetch(
          new Request('https://relay.audren.xyz/v1/relay/submit', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              cluster: 'mainnet',
              instructionDataB64: toBase64(params.ix.data),
              accounts: params.ix.accounts,
              ...(params.setupAtas ? { setupAtas: params.setupAtas } : {}),
            }),
          }),
          env,
        ),
    )
    const jsonBody = (await res.json()) as { ok: boolean; openedPagesCount: number; computeUnitLimit: number; billingMode: string }
    assert.equal(res.status, 200, `Expected 200, got ${res.status}: ${JSON.stringify(jsonBody)}`)
    assert.ok(sentWire)
    return { jsonBody, decoded: decodeV1Tx(sentWire) }
  }

  // Case 1A: Funded LaneRentVault at `nextLeaf = 86` (`memoRem = 10 <= 10`) -> auto-prepends OpenPage(MEMO, 1) + tight CU `235_000 + 40_000 = 275_000`!
  const lookaheadFunded = await runSubmitScenario({
    rpcUrl: 'https://mock-rpc.local/v130-lookahead-funded',
    ix: privLookaheadIx,
    nextLeaf: 86n,
    nfCount: 10n,
    vaultLamports: 100_000_000,
    extraSimAccounts: [{ lamports: 27_850_240, owner: AUDREN_PROGRAM_ID, data: ['', 'base64'] }],
  })
  assert.equal(lookaheadFunded.jsonBody.openedPagesCount, 1)
  assert.equal(lookaheadFunded.jsonBody.computeUnitLimit, CU_LIMIT_TRANSACT_PRIVATE + CU_LIMIT_OPEN_PAGE)
  assert.equal(lookaheadFunded.decoded.computeUnitLimit, 275_000)
  assert.equal(lookaheadFunded.decoded.instructions.length, 2)
  assert.equal(lookaheadFunded.decoded.instructions[0]!.data[0], TAG_OPEN_PAGE)
  assert.equal(lookaheadFunded.decoded.instructions[0]!.data[1], OPEN_PAGE_KIND_MEMO)
  assert.equal(lookaheadFunded.decoded.instructions[0]!.accounts[4], memo1)
  assert.equal(lookaheadFunded.decoded.instructions[1]!.data[0], TAG_TRANSACT)

  // Case 1B: Underfunded LaneRentVault at `nextLeaf = 86` -> skips proactive lookahead cleanly (`openedPagesCount === 0`, tight CU `235_000`, 0 deficit)!
  const lookaheadUnderfunded = await runSubmitScenario({
    rpcUrl: 'https://mock-rpc.local/v130-lookahead-underfunded',
    ix: privLookaheadIx,
    nextLeaf: 86n,
    nfCount: 10n,
    vaultLamports: 10_000_000,
  })
  assert.equal(lookaheadUnderfunded.jsonBody.openedPagesCount, 0)
  assert.equal(lookaheadUnderfunded.jsonBody.computeUnitLimit, CU_LIMIT_TRANSACT_PRIVATE)
  assert.equal(lookaheadUnderfunded.decoded.computeUnitLimit, 235_000)
  assert.equal(lookaheadUnderfunded.decoded.instructions.length, 1)
  assert.equal(memo0.length > 0 && sub0.length > 0 && sr0.length > 0 && nfPage0.length > 0, true)

  // Case 1C: Proactive lookahead at `nextLeaf = 230` (`subRem = 26`), `nfCount = 540` (`nfRem = 60`), and `subrootSlot = 280` (`nextLeaf = 71_680`)!
  const subNfIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 2n,
    outNfSeq: 0n,
    outputMask: 0b001,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x93),
    nf1: new Uint8Array(32).fill(0x94),
    cm0: new Uint8Array(32).fill(0x10),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x22),
  })
  const lookaheadSubNf = await runSubmitScenario({
    rpcUrl: 'https://mock-rpc.local/v130-lookahead-sub-nf',
    ix: subNfIx,
    nextLeaf: 230n, // subRem = 26 <= 26, memoSeq = 2 (memoUsed = 38 -> memoRem = 58 > 10)
    nfCount: 540n, // nfRem = 60 <= 60
    memoSeq: 2n,
    vaultLamports: 200_000_000,
    extraSimAccounts: [{ lamports: 73_520_000, owner: AUDREN_PROGRAM_ID, data: ['', 'base64'] }],
  })
  assert.equal(lookaheadSubNf.jsonBody.openedPagesCount, 2)
  assert.equal(lookaheadSubNf.jsonBody.computeUnitLimit, CU_LIMIT_TRANSACT_PRIVATE + 2 * CU_LIMIT_OPEN_PAGE)
  const openedKinds = lookaheadSubNf.decoded.instructions
    .filter((ix) => ix.data[0] === TAG_OPEN_PAGE)
    .map((ix) => ix.data[1]!)
    .sort()
  assert.deepEqual(openedKinds, [OPEN_PAGE_KIND_SUBTREE, OPEN_PAGE_KIND_NULLIFIER])

  // Case 1D: Proactive subrootSlot >= 280 lookahead (`nextLeaf = 280 * 256 = 71_680` -> `subrootSlot = 280`) prepends OpenPage(SUBROOT, 1)!
  const subrootLookaheadIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 280n,
    outRootSeq: 0n,
    outMemoSeq: 746n, // 71680 / 96 = 746 rem 64 -> memoRem = 32 > 10
    outNfSeq: 0n,
    outputMask: 0b001,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x9d),
    nf1: new Uint8Array(32).fill(0x9e),
    cm0: new Uint8Array(32).fill(0x10),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x22),
  })
  const lookaheadSubroot = await runSubmitScenario({
    rpcUrl: 'https://mock-rpc.local/v130-lookahead-subroot',
    ix: subrootLookaheadIx,
    nextLeaf: 71_680n,
    nfCount: 10n,
    subSeq: 280n,
    rootSeq: 0n,
    memoSeq: 746n,
    vaultLamports: 100_000_000,
    extraSimAccounts: [{ lamports: 31_860_000, owner: AUDREN_PROGRAM_ID, data: ['', 'base64'] }],
  })
  assert.equal(lookaheadSubroot.jsonBody.openedPagesCount, 1)
  assert.equal(lookaheadSubroot.decoded.instructions[0]!.data[0], TAG_OPEN_PAGE)
  assert.equal(lookaheadSubroot.decoded.instructions[0]!.data[1], OPEN_PAGE_KIND_SUBROOT)
  assert.equal(readU64le(lookaheadSubroot.decoded.instructions[0]!.data, 7), 1n)

  // Case 2: Calibrated Tight CU Budgets across all Audren v1.3.0 transaction shapes:
  const recipient = base58Encode(new Uint8Array(32).fill(0x39))

  // 2A. Single Transact Full Exit (`outputMask === 0`, classic WSOL unwrap, RO roots) -> `165_000` CU
  const fullExitCuIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: true,
    publicOutflow: { mint: WSOL_MINT, vaultAta: vaultWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x95),
    nf1: new Uint8Array(32).fill(0x96),
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 100_000_000n,
    relayerFeeAmount: 3_000_000n,
    recipient,
    relayerFeeRecipient: relayerB58,
    memosBytes: new Uint8Array(0),
  })
  const fullExitRes = await runSubmitScenario({
    rpcUrl: 'https://mock-rpc.local/v130-cu-full-exit',
    ix: fullExitCuIx,
    nextLeaf: 1n,
    nfCount: 1n,
    vaultLamports: 100_000_000,
  })
  assert.equal(fullExitRes.jsonBody.computeUnitLimit, CU_LIMIT_TRANSACT_FULL_EXIT)
  assert.equal(fullExitRes.decoded.computeUnitLimit, 165_000)

  // 2B. Single Transact Withdraw with change (`outputMask !== 0`, classic WSOL unwrap) -> `255_000` CU
  const withdrawChangeCuIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b001,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: true,
    publicOutflow: { mint: WSOL_MINT, vaultAta: vaultWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x97),
    nf1: new Uint8Array(32).fill(0x98),
    cm0: new Uint8Array(32).fill(0x11),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 100_000_000n,
    relayerFeeAmount: 3_000_000n,
    recipient,
    relayerFeeRecipient: relayerB58,
    memosBytes: new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x44),
  })
  const withdrawChangeRes = await runSubmitScenario({
    rpcUrl: 'https://mock-rpc.local/v130-cu-withdraw-change',
    ix: withdrawChangeCuIx,
    nextLeaf: 1n,
    nfCount: 1n,
    vaultLamports: 100_000_000,
  })
  assert.equal(withdrawChangeRes.jsonBody.computeUnitLimit, CU_LIMIT_TRANSACT_WITHDRAW)
  assert.equal(withdrawChangeRes.decoded.computeUnitLimit, 255_000)

  // 2C. Single Transact Withdraw (Token-2022 / TransferHook) -> `295_000` CU
  const t22Mint = base58Encode(new Uint8Array(32).fill(0xc4))
  const vaultT22Ata = deriveAssociatedTokenAddressSync(vaultAuth, t22Mint, TOKEN_2022_PROGRAM_ID).address
  const recipT22Ata = deriveAssociatedTokenAddressSync(recipient, t22Mint, TOKEN_2022_PROGRAM_ID).address
  const withdrawHookCuIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: false,
    publicOutflow: { mint: t22Mint, vaultAta: vaultT22Ata, tokenProgram: TOKEN_2022_PROGRAM_ID },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x99),
    nf1: new Uint8Array(32).fill(0x9a),
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 100_000_000n,
    relayerFeeAmount: 0n,
    recipient: recipT22Ata,
    relayerFeeRecipient: SYSTEM_PROGRAM_ID,
    memosBytes: new Uint8Array(0),
    hookAccounts: [{ pubkey: base58Encode(new Uint8Array(32).fill(0xc5)), isSigner: false, isWritable: false }],
  })
  const withdrawHookRes = await runSubmitScenario({
    rpcUrl: 'https://mock-rpc.local/v130-cu-withdraw-hook',
    ix: withdrawHookCuIx,
    nextLeaf: 1n,
    nfCount: 1n,
    vaultLamports: 100_000_000,
  })
  assert.equal(withdrawHookRes.jsonBody.computeUnitLimit, CU_LIMIT_TRANSACT_WITHDRAW_HOOK)
  assert.equal(withdrawHookRes.decoded.computeUnitLimit, 295_000)

  // 2D. Single Classic SPL ExecViaEscrow (+ 1 Classic SPL setupAta) -> `285_000 + 350_000 + 30_000 = 665_000` CU
  const escrow1 = deriveEscrowPdaSync(0, 1).address
  const escrowInAta = deriveAssociatedTokenAddressSync(escrow1, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowOutAta = deriveAssociatedTokenAddressSync(escrow1, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const execCuIx = buildExecViaEscrowInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    escrowShard: 1,
    changeMask: 0,
    inLeg: { mint: WSOL_MINT, vaultAta: vaultWsolAta, escrowAta: escrowInAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    outLeg: { mint: USDC_MINT, vaultAta: vaultUsdcAta, escrowAta: escrowOutAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    relayerFeeAmount: 0n,
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x9b),
    nf1: new Uint8Array(32).fill(0x9c),
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    amountIn: 100_000_000n,
    minAmountOut: 1_000_000n,
    outStealthOwner: new Uint8Array(32).fill(0x02),
    outBlinding: new Uint8Array(32).fill(0x03),
    dynMemoHead: new Uint8Array(34).fill(0x04),
    dynMemoMask: new Uint8Array(72).fill(0x05),
    routerProg: base58Encode(new Uint8Array(32).fill(0x55)),
    routerIxData: new Uint8Array([1, 2, 3]),
    routerAccounts: [{ pubkey: base58Encode(new Uint8Array(32).fill(0x66)), isSigner: false, isWritable: true }],
    changeMemos: new Uint8Array(0),
  })
  const execCuRes = await runSubmitScenario({
    rpcUrl: 'https://mock-rpc.local/v130-cu-exec',
    ix: execCuIx,
    nextLeaf: 1n,
    nfCount: 1n,
    vaultLamports: 100_000_000,
    setupAtas: [{ owner: escrow1, mint: USDC_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID }],
  })
  assert.equal(execCuRes.jsonBody.computeUnitLimit, CU_LIMIT_EXEC_VIA_ESCROW_BASE + 350_000 + 30_000)
  assert.equal(execCuRes.decoded.computeUnitLimit, 665_000)

  // 2E. Multi-ix Private Transact batch (2 instructions) sums tight per-ix CU (`2 * 235_000 = 470_000`)!
  const { cm2: bCm2A, memo: bMemoA } = makeShieldedFeeCm2(5_000_000n, wsolMintBytes, 0x41)
  const { cm2: bCm2B, memo: bMemoB } = makeShieldedFeeCm2(5_000_000n, wsolMintBytes, 0x42)
  const mkBatchCuIx = (seed: number, cm2: Uint8Array, memo: Uint8Array) =>
    buildTransactInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: 0,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: 0n,
      outNfSeq: 0n,
      outputMask: 0b101,
      assetMode: ASSET_MODE_PRIVATE,
      proof192: dummyProof,
      nf0: new Uint8Array(32).fill(seed),
      nf1: new Uint8Array(32).fill(seed + 1),
      cm0: new Uint8Array(32).fill(0x10),
      cm1: new Uint8Array(32),
      cm2,
      publicAmountOut: 0n,
      relayerFeeAmount: 0n,
      memosBytes: (() => {
        const m = new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN)
        m.set(new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x11), 0)
        m.set(memo, MEMO_ENTRY_WIRE_LEN)
        return m
      })(),
    })
  const bIx1 = mkBatchCuIx(0xa1, bCm2A, bMemoA)
  const bIx2 = mkBatchCuIx(0xa3, bCm2B, bMemoB)
  const guardBatch = createMockGuard()
  const envBatch = {
    RELAY_GUARD: guardBatch.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/v130-cu-batch-2',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    MAINNET_RELAYER_FVK_JSON: JSON.stringify({
      spendPkHex: toHex(relayerFvk.spendPk),
      nkHex: toHex(relayerFvk.nk),
      viewSkHex: toHex(relayerFvk.viewSk),
      viewPkHex: toHex(relayerFvk.viewPk),
    }),
  } as Env
  let batchSentWire: Uint8Array | null = null
  const batchAccMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 1n, nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0RentVault, { bytes: new Uint8Array(16), lamports: 100_000_000, owner: AUDREN_PROGRAM_ID }],
    [sub0, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
    [sr0, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    [memo0, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
    [nfPage0, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
  ])
  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: len === 0 ? 890_880 : len === 16 ? 1_002_240 : len === 165 ? 2_039_280 : len === SUBTREE_PAGE_LEN ? 58_340_000 : len === MEMO_PAGE_LEN ? 72_149_760 : 68_140_000,
        })
      }
      if (body.method === 'getAccountInfo') {
        const hit = batchAccMap.get(String(body.params[0]))
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null } })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x72)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 50_010 },
            value: addrs.map((a) => {
              const hit = batchAccMap.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { context: { slot: 50_010 }, value: { err: null, logs: ['OK'], unitsConsumed: 390_000, accounts: [{ lamports: 493_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }] } },
        })
      }
      if (body.method === 'sendTransaction') {
        batchSentWire = fromBase64(String(body.params[0]))
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5V130BatchCuMockSig1111111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 50_011, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in batch CU test: ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructions: [
              { instructionDataB64: toBase64(bIx1.data), accounts: bIx1.accounts },
              { instructionDataB64: toBase64(bIx2.data), accounts: bIx2.accounts },
            ],
          }),
        }),
        envBatch,
      )
      assert.equal(res.status, 200)
      const jb = (await res.json()) as { computeUnitLimit: number; instructionCount: number }
      assert.equal(jb.instructionCount, 2)
      assert.equal(jb.computeUnitLimit, 2 * CU_LIMIT_TRANSACT_PRIVATE)
      assert.ok(batchSentWire)
      assert.equal(decodeV1Tx(batchSentWire).computeUnitLimit, 470_000)
    },
  )
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
  priorityFeeLamports: bigint | null
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
  let priorityFeeLamports: bigint | null = null
  if ((configMask & 0b11) !== 0) {
    priorityFeeLamports = readU64le(wireBytes, off)
    off += 8
  }
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
  return { priorityFeeLamports, computeUnitLimit, accounts, instructions }
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
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 2,
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
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
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
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 1,
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
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 1,
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
    [laneRentVault, { bytes: new Uint8Array(16), lamports: 200_000_000, owner: AUDREN_PROGRAM_ID }],
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
        return Response.json({ jsonrpc: '2.0', id: 1, result: { context: { slot: 9998 }, value } })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 9998 },
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
      assert.equal(jsonBody.computeUnitLimit, 300_000 + 2 * CU_LIMIT_OPEN_PAGE)
      assert.equal(jsonBody.computeUnitLimit, 380_000)
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
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 1,
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
    [laneRentVault, { bytes: new Uint8Array(16), lamports: 200_000_000, owner: AUDREN_PROGRAM_ID }],
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
        return Response.json({ jsonrpc: '2.0', id: 1, result: { context: { slot: 9998 }, value } })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 9998 },
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
        return Response.json({ jsonrpc: '2.0', id: 1, result: { context: { slot: 12344 }, value } })
      }
      if (body.method === 'simulateTransaction') {
        const postLamports = preRelayerLamports - actualOnChainDebit + quotedRelayerFee
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 12344 },
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
        rootRingKind: ROOT_RING_EPOCH,
        rootRingIdx: 0,
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
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
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
    [deriveLaneRentVaultPdaSync(0, 0).address, { bytes: new Uint8Array(16), lamports: 200_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane1Pda, { bytes: makeLaneStateBytes({ laneId: 1, nextLeaf: 2n, nfCount: 4n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveLaneRentVaultPdaSync(0, 1).address, { bytes: new Uint8Array(16), lamports: 200_000_000, owner: AUDREN_PROGRAM_ID }],
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
        return Response.json({ jsonrpc: '2.0', id: 1, result: { context: { slot: 20000 }, value } })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 20000 },
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
            context: { slot: 20000 },
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
            context: { slot: 20000 },
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
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
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

// ============================================================================
// 7. v1.2.1 Security & Solvency Hardening Regression Suite (Findings #6 – #13)
// ============================================================================

const JUPITER_V6_ROUTER = 'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4'

function makeTokenAccountBytes(mintB58: string, ownerB58: string, amount: bigint): Uint8Array {
  const buf = new Uint8Array(165)
  buf.set(base58Decode(mintB58), 0)
  buf.set(base58Decode(ownerB58), 32)
  buf.set(u64le(amount), 64)
  buf[108] = 1 // AccountState::Initialized
  return buf
}

function makeClassicMintWithFreeze(decimals: number, freezeAuthFill: number): Uint8Array {
  const buf = makeClassicMintBytes(decimals)
  const dv = new DataView(buf.buffer)
  dv.setUint32(46, 1, true) // COption::Some
  buf.fill(freezeAuthFill, 50, 82)
  return buf
}

function makeToken2022PausableMintBytes(decimals: number): Uint8Array {
  // 82 B Mint + 83 B zero padding + 1 B AccountType(1 = Mint) + 4 B TLV header (type=26, len=33) + 33 B PausableConfig
  const buf = new Uint8Array(166 + 4 + 33)
  const dv = new DataView(buf.buffer)
  buf[44] = decimals
  buf[45] = 1
  buf[165] = 1
  dv.setUint16(166, 26, true) // ExtensionType::Pausable = 26
  dv.setUint16(168, 33, true)
  buf.fill(0x11, 170, 202)
  buf[202] = 0
  return buf
}

function makeToken2022MutableTransferFeeMintBytes(params: {
  decimals: number
  bps: number
  mutableAuthority: boolean
}): Uint8Array {
  const buf = makeToken2022TransferFeeMintBytes({
    decimals: params.decimals,
    olderEpoch: 0n,
    olderMaxFee: 10_000_000n,
    olderBps: params.bps,
    newerEpoch: 0n,
    newerMaxFee: 10_000_000n,
    newerBps: params.bps,
  })
  if (params.mutableAuthority) {
    buf.fill(0x55, 170, 202) // non-zero transfer_fee_config_authority
  }
  return buf
}

function buildTestExecSwapIx(params: {
  payerB58: string
  routerProg: string
  feeAta: string
  feeAtaWritable: boolean
  relayerFeeAmount?: bigint
  feeOnOutput?: boolean
  outMint?: string
  outTokenProg?: string
  feeRecipient?: string
  nf0Seed?: number
}) {
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const escrow = deriveEscrowPdaSync(0, 1).address
  const outMint = params.outMint ?? USDC_MINT
  const outTp = params.outTokenProg ?? CLASSIC_TOKEN_PROGRAM_ID
  const vaultInAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowInAta = deriveAssociatedTokenAddressSync(escrow, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultOutAta = deriveAssociatedTokenAddressSync(vaultAuth, outMint, outTp).address
  const escrowOutAta = deriveAssociatedTokenAddressSync(escrow, outMint, outTp).address

  return buildExecViaEscrowInstruction({
    payer: params.payerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    escrowShard: 1,
    changeMask: 0,
    feeOnOutput: params.feeOnOutput ?? false,
    inLeg: {
      mint: WSOL_MINT,
      vaultAta: vaultInAta,
      escrowAta: escrowInAta,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    },
    outLeg: {
      mint: outMint,
      vaultAta: vaultOutAta,
      escrowAta: escrowOutAta,
      tokenProgram: outTp,
    },
    relayerFeeAmount: params.relayerFeeAmount ?? 0n,
    relayerFeeRecipient: params.feeRecipient,
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(params.nf0Seed ?? 0x61),
    nf1: nf1NonZero,
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    amountIn: 500_000_000n,
    minAmountOut: 10_000_000n,
    outStealthOwner: new Uint8Array(32).fill(0x02),
    outBlinding: new Uint8Array(32).fill(0x03),
    dynMemoHead: new Uint8Array(34).fill(0x04),
    dynMemoMask: new Uint8Array(72).fill(0x05),
    routerProg: params.routerProg,
    routerIxData: new Uint8Array([1, 2, 3]),
    routerAccounts: [
      { pubkey: params.feeAta, isSigner: false, isWritable: params.feeAtaWritable },
    ],
    changeMemos: new Uint8Array(0),
  })
}

test('Finding #6 / R1-R1: zero-fee ExecViaEscrow (relayerFee === 0) NEVER earns self-pay credit even on audited routers; protocol-enforced EXEC_FLAG_FEE_ON_OUTPUT required', async () => {
  const worker = await getWorker()
  const customRouter = base58Encode(new Uint8Array(32).fill(0x5a))
  const relayerUsdcAta = deriveAssociatedTokenAddressSync(
    relayerB58,
    USDC_MINT,
    CLASSIC_TOKEN_PROGRAM_ID,
  ).address

  // 1. Custom unaudited router with relayerFee === 0 and writable relayer ATA -> firewall does NOT watch ATA
  const customIx = buildTestExecSwapIx({
    payerB58: relayerB58,
    routerProg: customRouter,
    feeAta: relayerUsdcAta,
    feeAtaWritable: true,
    relayerFeeAmount: 0n,
  })
  const customVerdict = validateRelaySubmission(
    { instructionDataB64: toBase64(customIx.data), accounts: customIx.accounts },
    relayerPubkey,
    allowedPre,
    relayerFvk,
  )
  assert.equal(customVerdict.watchedRelayerFeeAta, null)
  assert.equal(customVerdict.watchedRelayerFeeMint, null)

  // setupAtas for zero-fee router relayer fee ATA MUST be rejected (custom OR audited Jupiter!)
  for (const ix of [
    customIx,
    buildTestExecSwapIx({
      payerB58: relayerB58,
      routerProg: JUPITER_V6_ROUTER,
      feeAta: relayerUsdcAta,
      feeAtaWritable: true,
      relayerFeeAmount: 0n,
    }),
  ]) {
    assert.throws(
      () =>
        validateRelaySubmission(
          {
            instructionDataB64: toBase64(ix.data),
            accounts: ix.accounts,
            setupAtas: [{ owner: relayerB58, mint: USDC_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID }],
          },
          relayerPubkey,
          allowedPre,
          relayerFvk,
        ),
      FirewallError,
    )
  }

  // 2. Audited router (Jupiter v6) with relayerFee === 0 and WRITABLE relayer ATA -> STILL NOT watched!
  //    On-chain ExecViaEscrow enforces zero fee transfer when relayer_fee_amount == 0 (R1-R1).
  const jupWritableIx = buildTestExecSwapIx({
    payerB58: relayerB58,
    routerProg: JUPITER_V6_ROUTER,
    feeAta: relayerUsdcAta,
    feeAtaWritable: true,
    relayerFeeAmount: 0n,
  })
  const jupWrVerdict = validateRelaySubmission(
    { instructionDataB64: toBase64(jupWritableIx.data), accounts: jupWritableIx.accounts },
    relayerPubkey,
    allowedPre,
    relayerFvk,
  )
  assert.equal(jupWrVerdict.watchedRelayerFeeAta, null)
  assert.equal(jupWrVerdict.watchedRelayerFeeMint, null)

  // 3. Protocol-enforced EXEC_FLAG_FEE_ON_OUTPUT (`relayerFee > 0n`) DOES watch canonical relayer fee ATA!
  const nativeOutFeeIx = buildTestExecSwapIx({
    payerB58: relayerB58,
    routerProg: JUPITER_V6_ROUTER,
    feeAta: relayerUsdcAta,
    feeAtaWritable: false,
    relayerFeeAmount: 2_000_000n,
    feeOnOutput: true,
    feeRecipient: relayerUsdcAta,
  })
  const nativeOutVerdict = validateRelaySubmission(
    {
      instructionDataB64: toBase64(nativeOutFeeIx.data),
      accounts: nativeOutFeeIx.accounts,
      setupAtas: [{ owner: relayerB58, mint: USDC_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID }],
    },
    relayerPubkey,
    allowedPre,
    relayerFvk,
  )
  assert.equal(nativeOutVerdict.watchedRelayerFeeAta, relayerUsdcAta)
  assert.equal(nativeOutVerdict.watchedRelayerFeeMint, USDC_MINT)
  assert.equal(nativeOutVerdict.setupAtas.length, 1)

  // 4. `AUDITED_SWAP_ROUTER_PROGRAMS` config still loads custom routers for automated treasury refill
  const customCfg = loadPolicyConfig({ AUDITED_SWAP_ROUTER_PROGRAMS: customRouter } as Env)
  assert.equal(customCfg.auditedSwapRouterPrograms.has(customRouter), true)

  // 5. End-to-end HTTP submit with custom router (`ALLOW_MICRO_SWAP_SUBSIDY: 'false'`) rejects with 402 + recordFailure=true
  const mockRpc = 'https://mock-rpc.local/finding6-custom-router'
  const guard = createMockGuard()
  const env = {
    RELAY_GUARD: guard.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    ALLOW_MICRO_SWAP_SUBSIDY: 'false',
  } as Env
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)
  const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [deriveLanePdaSync(0, 0).address, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 2n, nfCount: 2n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
  ])

  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x41)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 500 },
            value: addrs.map((a) => {
              const hit = accMap.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 500 },
            value: {
              err: null,
              logs: ['ExecViaEscrow OK'],
              unitsConsumed: 220_000,
              accounts: [{ lamports: 496_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }],
            },
          },
        })
      }
      throw new Error(`Unexpected RPC method in Finding #6 test: ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(customIx.data),
            accounts: customIx.accounts,
          }),
        }),
        env,
      )
      assert.equal(res.status, 402)
      const errBody = (await res.json()) as { code: string; feeEquivalentLamports: string }
      assert.equal(errBody.code, 'FEE_REQUIRED')
      assert.equal(errBody.feeEquivalentLamports, '0')
      assert.equal(guard.relayReleaseCalls[0]?.recordFailure, true)
    },
  )
})

test('Finding #7: unvetted junk fee-mints never earn self_paying credit, parseMintSafetyInfo rejects Pausable / mutable TransferFee / untrusted FreezeAuthority', async () => {
  const worker = await getWorker()
  const junkMint = base58Encode(new Uint8Array(32).fill(0x9b))
  const cfg = loadPolicyConfig({} as Env)
  assert.equal(cfg.selfPayFeeMints.has(junkMint), false)
  assert.equal(cfg.selfPayFeeMints.has(USDC_MINT), true)
  assert.equal(cfg.selfPayFeeMints.has('2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo'), false)
  assert.equal(DEFAULT_SELF_PAY_FEE_MINTS.length, 11)
  assert.ok(DEFAULT_AUDITED_SWAP_ROUTER_PROGRAMS.includes(JUPITER_V6_ROUTER))

  // 1. `parseMintSafetyInfo` checks on raw mint account bytes
  const pausableRes = parseMintSafetyInfo(
    USDC_MINT,
    TOKEN_2022_PROGRAM_ID,
    makeToken2022PausableMintBytes(6),
  )
  assert.equal(pausableRes.safeForSelfPay, false)
  assert.equal(pausableRes.hasPausableExt, true)

  const mutableFeeRes = parseMintSafetyInfo(
    USDC_MINT,
    TOKEN_2022_PROGRAM_ID,
    makeToken2022MutableTransferFeeMintBytes({ decimals: 6, bps: 100, mutableAuthority: true }),
  )
  assert.equal(mutableFeeRes.safeForSelfPay, false)
  assert.equal(mutableFeeRes.hasMutableTransferFeeAuthority, true)

  const immutableFeeRes = parseMintSafetyInfo(
    USDC_MINT,
    TOKEN_2022_PROGRAM_ID,
    makeToken2022MutableTransferFeeMintBytes({ decimals: 6, bps: 100, mutableAuthority: false }),
  )
  assert.equal(immutableFeeRes.safeForSelfPay, true)

  // Trusted regulated stablecoin (USDC) with FreezeAuthority is allowed; unknown mint with FreezeAuthority is rejected!
  const usdcFreezeRes = parseMintSafetyInfo(
    USDC_MINT,
    CLASSIC_TOKEN_PROGRAM_ID,
    makeClassicMintWithFreeze(6, 0x22),
  )
  assert.equal(usdcFreezeRes.safeForSelfPay, true)
  assert.equal(usdcFreezeRes.hasFreezeAuthority, true)
  assert.equal(usdcFreezeRes.hasUntrustedFreezeAuthority, false)

  const customFreezeRes = parseMintSafetyInfo(
    'JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN',
    CLASSIC_TOKEN_PROGRAM_ID,
    makeClassicMintWithFreeze(6, 0x22),
  )
  assert.equal(customFreezeRes.safeForSelfPay, false)
  assert.equal(customFreezeRes.hasUntrustedFreezeAuthority, true)

  // 2. Pricing refuses self_paying for non-allowlisted junk mint even with huge oracle price
  const rentSchedule = {
    nullifierRentLamports: 890_880n,
    nfPageRentPerNfLamports: 113_567n,
    pageRentPerNoteLamports: 1_500_000n,
    ataRentLamports: 2_039_280n,
    baseTxFeeLamports: 5_000n,
    swapBaselineLamports: 2n * (890_880n + 113_567n) + 2n * 1_500_000n + 20_000n,
    fetchedAt: Date.now(),
  }
  const junkSwapPlan = computeSwapFeePlan({
    cfg,
    rentSchedule,
    outputMint: junkMint,
    outputDecimals: 6,
    estimatedOutAmount: 1_000_000_000n,
    solPriceUsd: 150,
    outputTokenPriceUsd: 100_000,
    feeAccount: relayerB58,
    feeAccountExists: true,
  })
  assert.equal(junkSwapPlan.billingMode, 'sponsored')
  assert.equal(junkSwapPlan.platformFeeBps, 0)
  assert.equal(junkSwapPlan.feeAccount, null)

  const junkNativeQuote = computeNativeFeeQuote({
    cluster: 'mainnet',
    op: 'withdraw',
    cfg,
    rentSchedule,
    feeMint: junkMint,
    feeTokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    feeDecimals: 6,
    amount: 1_000_000_000n,
    feeRecipient: relayerB58,
    feeRecipientExists: true,
    solPriceUsd: 150,
    feeTokenPriceUsd: 100_000,
  })
  assert.equal(junkNativeQuote.billingMode, 'sponsored')
  assert.equal(junkNativeQuote.relayerFee, '0')

  // 3. End-to-end HTTP submit: junk mint withdraw trying to drain SOL via `setupAtas: [recipientAta]`
  //    with manipulated $1M Jupiter price MUST NOT earn self_paying credit and MUST reject with 402!
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const vaultJunkAta = deriveAssociatedTokenAddressSync(vaultAuth, junkMint, CLASSIC_TOKEN_PROGRAM_ID).address
  const attackerWallet = base58Encode(new Uint8Array(32).fill(0xee))
  const attackerJunkAta = deriveAssociatedTokenAddressSync(attackerWallet, junkMint, CLASSIC_TOKEN_PROGRAM_ID).address
  const relayerJunkAta = deriveAssociatedTokenAddressSync(relayerB58, junkMint, CLASSIC_TOKEN_PROGRAM_ID).address

  const withdrawJunkIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: false,
    publicOutflow: { mint: junkMint, vaultAta: vaultJunkAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x71),
    nf1: nf1NonZero,
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 1_000_000n,
    relayerFeeAmount: 500_000n,
    recipient: attackerJunkAta,
    relayerFeeRecipient: relayerJunkAta,
    memosBytes: new Uint8Array(0),
  })

  const mockRpc = 'https://mock-rpc.local/finding7-junk-mint'
  const mockJup = 'https://mock-jup-f7.local'
  const guard = createMockGuard()
  const env = {
    RELAY_GUARD: guard.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    JUPITER_API_URL: mockJup,
  } as Env
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)
  const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [relayerJunkAta, { bytes: makeTokenAccountBytes(junkMint, relayerB58, 0n), lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }],
    [deriveLanePdaSync(0, 0).address, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 1n, nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
  ])

  await withMockFetch(
    async (url, init) => {
      if (url.startsWith(`${mockJup}/price/v3`)) {
        return Response.json({ [WSOL_MINT]: { usdPrice: 150 }, [junkMint]: { usdPrice: 1_000_000 } })
      }
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x42)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 600 },
            value: addrs.map((a) => {
              const hit = accMap.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 600 },
            value: {
              err: null,
              logs: ['Withdraw OK'],
              unitsConsumed: 160_000,
              accounts: [
                { lamports: 496_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(junkMint, relayerB58, 500_000n)), 'base64'] },
              ],
            },
          },
        })
      }
      throw new Error(`Unexpected RPC call in Finding #7 test: ${url} ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(withdrawJunkIx.data),
            accounts: withdrawJunkIx.accounts,
            setupAtas: [{ owner: attackerWallet, mint: junkMint, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID }],
          }),
        }),
        env,
      )
      assert.equal(res.status, 402)
      const errBody = (await res.json()) as { code: string; feeEquivalentLamports: string }
      assert.equal(errBody.code, 'FEE_REQUIRED')
      assert.equal(errBody.feeEquivalentLamports, '0')
      assert.equal(guard.relayReleaseCalls[0]?.recordFailure, true)
    },
  )
})

test('Finding #8 / R1-R1 / R1-R2: deterministic minExpectedCostLamports defeats SOL inflow erasure, caps native relayerFee credit, blocks sponsored recipient ATA setup on allowlisted mints, and enforces relayerFee > 0 for ExecViaEscrow self-pay', async () => {
  const worker = await getWorker()
  const mockJup = 'https://mock-jup-f8.local'
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)
  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n })
  const relayerUsdcAta = deriveAssociatedTokenAddressSync(relayerB58, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const recipient = base58Encode(new Uint8Array(32).fill(0x88))
  const recipientUsdcAta = deriveAssociatedTokenAddressSync(recipient, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const vaultUsdcAta = deriveAssociatedTokenAddressSync(vaultAuth, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address

  // Case A: SPL Withdraw where attacker sends concurrent +1 SOL to relayer AND +50 USDC to relayer ATA
  // between preSlot and simSlot while only setting parsed relayerFee = 100_000 (0.10 USDC ~ 0.00066 SOL).
  //   - A1: With `setupAtas: [recipientUsdcAta]` on allowlisted USDC -> MUST reject 402 FEE_REQUIRED
  //         with exact `simulatedCostLamports = 4_058_174` and `recordFailure: true` (R1-R2)!
  //   - A2: Without `setupAtas` -> floor MUST stay >= 2_018_894 AND credited fee MUST be capped at 100_000!
  const withdrawIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: false,
    publicOutflow: { mint: USDC_MINT, vaultAta: vaultUsdcAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x72),
    nf1: nf1NonZero,
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 1_000_000n,
    relayerFeeAmount: 100_000n,
    recipient: recipientUsdcAta,
    relayerFeeRecipient: relayerUsdcAta,
    memosBytes: new Uint8Array(0),
  })

  const guardA = createMockGuard()
  const mockRpcA = 'https://mock-rpc.local/finding8-cap-floor'
  const envA = {
    RELAY_GUARD: guardA.namespace,
    MAINNET_RPC_URL: mockRpcA,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    JUPITER_API_URL: mockJup,
  } as Env
  const accMapA = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [relayerUsdcAta, { bytes: makeTokenAccountBytes(USDC_MINT, relayerB58, 0n), lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }],
    [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
    [USDC_MINT, { bytes: makeClassicMintBytes(6), lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID }],
    [deriveLanePdaSync(0, 0).address, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 1n, nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
  ])

  await withMockFetch(
    async (url, init) => {
      if (url.startsWith(`${mockJup}/price/v3`)) {
        return Response.json({ [WSOL_MINT]: { usdPrice: 150 }, [USDC_MINT]: { usdPrice: 1 } })
      }
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x43)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 700 },
            value: addrs.map((a) => {
              const hit = accMapA.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        // Concurrent same-slot +1 SOL inflow into relayer (erasing rawOutflow!) + 50 USDC inflow into fee ATA!
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 700 },
            value: {
              err: null,
              logs: ['Withdraw OK'],
              unitsConsumed: 150_000,
              accounts: [
                { lamports: 1_497_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 50_000_000n)), 'base64'] },
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5Finding8WithdrawSig1111111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 702, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC call in Finding #8A: ${url} ${body.method}`)
    },
    async () => {
      // A1: Sponsored recipient ATA setup on allowlisted USDC MUST be rejected 402 FEE_REQUIRED (R1-R2)
      const resRejected = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(withdrawIx.data),
            accounts: withdrawIx.accounts,
            setupAtas: [{ owner: recipient, mint: USDC_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID }],
          }),
        }),
        envA,
      )
      assert.equal(resRejected.status, 402)
      const errBody = (await resRejected.json()) as {
        code: string
        simulatedCostLamports: string
        feeEquivalentLamports: string
      }
      assert.equal(errBody.code, 'FEE_REQUIRED')
      // minExpectedCostLamports = 5_000 + 5_000 + 2*(890_880 + 113_567) + 1*2_039_280 = 4_058_174
      assert.equal(BigInt(errBody.simulatedCostLamports), 4_058_174n)
      assert.equal(guardA.relayReleaseCalls[0]?.recordFailure, true)

      // A2: Without recipient setupAta, sponsored withdraw succeeds with exact floor & capped relayerFee
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(withdrawIx.data),
            accounts: withdrawIx.accounts,
          }),
        }),
        envA,
      )
      assert.equal(res.status, 200)
      const body = (await res.json()) as {
        billingMode: string
        simulatedCostLamports: string
        simulatedFeeUnits: string
        netSponsoredLamports: string
      }
      // minExpectedCostLamports = 5_000 + 5_000 + 2*(890_880 + 113_567) = 2_018_894
      assert.equal(BigInt(body.simulatedCostLamports), 2_018_894n)
      // Credited fee units MUST be capped at parsed relayerFee = 100_000 (NEVER inflated to 50_000_000!)
      assert.equal(body.simulatedFeeUnits, '100000')
      assert.equal(body.billingMode, 'sponsored')
      assert.ok(BigInt(body.netSponsoredLamports) > 1_000_000n)
    },
  )

  // Case B: Jupiter swap with `relayerFee === 0n` NEVER earns self-pay credit even on same-slot
  // simulation showing +2 USDC in relayer ATA (R1-R1); protocol-enforced `EXEC_FLAG_FEE_ON_OUTPUT`
  // (`relayerFeeAmount: 2_000_000n`) DOES settle `self_paying`!
  const jupZeroFeeIx = buildTestExecSwapIx({
    payerB58: relayerB58,
    routerProg: JUPITER_V6_ROUTER,
    feeAta: relayerUsdcAta,
    feeAtaWritable: true,
    relayerFeeAmount: 0n,
    nf0Seed: 0x73,
  })
  const jupNativeFeeIx = buildTestExecSwapIx({
    payerB58: relayerB58,
    routerProg: JUPITER_V6_ROUTER,
    feeAta: relayerUsdcAta,
    feeAtaWritable: false,
    relayerFeeAmount: 2_000_000n,
    feeOnOutput: true,
    feeRecipient: relayerUsdcAta,
    nf0Seed: 0x7a,
  })

  for (const useProtocolFee of [false, true]) {
    const guardB = createMockGuard()
    const mockRpcB = `https://mock-rpc.local/finding8-jup-${useProtocolFee}`
    const envB = {
      RELAY_GUARD: guardB.namespace,
      MAINNET_RPC_URL: mockRpcB,
      MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
      JUPITER_API_URL: mockJup,
      ALLOW_MICRO_SWAP_SUBSIDY: 'false',
    } as Env
    const ixToSend = useProtocolFee ? jupNativeFeeIx : jupZeroFeeIx

    await withMockFetch(
      async (url, init) => {
        if (url.startsWith(`${mockJup}/price/v3`)) {
          return Response.json({ [WSOL_MINT]: { usdPrice: 150 }, [USDC_MINT]: { usdPrice: 1 } })
        }
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getLatestBlockhash') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x44)) } } })
        }
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 801 },
              value: addrs.map((a) => {
                const hit = accMapA.get(a)
                return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
              }),
            },
          })
        }
        if (body.method === 'simulateTransaction') {
          const watchAddrs = (body.params[1] as { accounts?: { addresses?: string[] } })?.accounts?.addresses ?? []
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 801 },
              value: {
                err: null,
                logs: ['Jupiter ExecViaEscrow OK'],
                unitsConsumed: 280_000,
                accounts: watchAddrs.map((addr) =>
                  addr === relayerUsdcAta
                    ? { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 2_000_000n)), 'base64'] }
                    : { lamports: 496_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                ),
              },
            },
          })
        }
        if (body.method === 'sendTransaction') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: '5Finding8JupNativeFeeSig11111111111111111111' })
        }
        if (body.method === 'getSignatureStatuses') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 803, err: null, confirmationStatus: 'confirmed' }] } })
        }
        throw new Error(`Unexpected RPC call in Finding #8B: ${url} ${body.method}`)
      },
      async () => {
        const res = await worker.fetch(
          new Request('https://relay.audren.xyz/v1/relay/submit', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              cluster: 'mainnet',
              instructionDataB64: toBase64(ixToSend.data),
              accounts: ixToSend.accounts,
            }),
          }),
          envB,
        )
        if (!useProtocolFee) {
          assert.equal(res.status, 402)
          const errBody = (await res.json()) as { code: string; feeEquivalentLamports: string }
          assert.equal(errBody.code, 'FEE_REQUIRED')
          assert.equal(errBody.feeEquivalentLamports, '0')
        } else {
          assert.equal(res.status, 200)
          const okBody = (await res.json()) as { billingMode: string; simulatedFeeUnits: string }
          assert.equal(okBody.billingMode, 'self_paying')
          assert.equal(okBody.simulatedFeeUnits, '2000000')
        }
      },
    )
  }
})

test('Finding #10: premature rollover OpenPage (flags=0x07 at nextLeaf=0, nfCount=0) is rejected', async () => {
  const worker = await getWorker()
  const outLaneId = 0
  const lanePda = deriveLanePdaSync(0, outLaneId).address
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)

  // Unit-level test on `planMissingOpenPageIxs`
  const sub0 = deriveSubtreePdaSync(0, outLaneId, 0n).address
  const sr0 = deriveSubrootPdaSync(0, outLaneId, 0n).address
  const memo0 = deriveMemoPdaSync(0, outLaneId, 0n).address
  const nf0Page = deriveNfPagePdaSync(0, outLaneId, 0n).address
  const sub1 = deriveSubtreePdaSync(0, outLaneId, 1n).address
  const memo1 = deriveMemoPdaSync(0, outLaneId, 1n).address
  const nf1Page = deriveNfPagePdaSync(0, outLaneId, 1n).address

  const prematureRes = planMissingOpenPageIxs({
    payerB58: relayerB58,
    poolId: 0,
    outLaneId,
    laneAcc: { bytes: makeLaneStateBytes({ laneId: outLaneId, nextLeaf: 0n, nfCount: 0n }), owner: AUDREN_PROGRAM_ID },
    pages: { outSub: sub0, outRoot: sr0, outMemo: memo0, nfPage: nf0Page, nextSub: sub1, nextMemo: memo1, nextNf: nf1Page },
    pageSlots: [
      { slot: 'outSub', pda: sub0 },
      { slot: 'outRoot', pda: sr0 },
      { slot: 'outMemo', pda: memo0 },
      { slot: 'nfPage', pda: nf0Page },
      { slot: 'nextSub', pda: sub1 },
      { slot: 'nextMemo', pda: memo1 },
      { slot: 'nextNf', pda: nf1Page },
    ],
    pageAccs: [
      { bytes: dummyPageBytes, owner: AUDREN_PROGRAM_ID },
      { bytes: dummyPageBytes, owner: AUDREN_PROGRAM_ID },
      { bytes: dummyPageBytes, owner: AUDREN_PROGRAM_ID },
      { bytes: dummyPageBytes, owner: AUDREN_PROGRAM_ID },
      null,
      null,
      null,
    ],
    outputCount: 2,
    nullifierCount: 2,
  })
  assert.equal(prematureRes.ok, false)
  assert.match(prematureRes.error, /Premature rollover OpenPage rejected/)

  // HTTP /v1/relay/submit with flags=0x07 at leaf 0, nfCount 0 MUST reject with 400 INVALID_PAGE_PDA & zero sim calls
  const prematureIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b001,
    assetMode: ASSET_MODE_PRIVATE,
    rollover: { nextSubSeq: 1n, nextMemoSeq: 1n, nextNfSeq: 1n },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x74),
    nf1: nf1NonZero,
    cm0: new Uint8Array(32).fill(0x12),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x21),
  })
  const guard = createMockGuard()
  const env = {
    RELAY_GUARD: guard.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/finding10-premature-openpage',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
  } as Env
  const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [lanePda, { bytes: makeLaneStateBytes({ laneId: outLaneId, nextLeaf: 0n, nfCount: 0n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [sub0, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
    [sr0, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    [memo0, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
    [nf0Page, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
  ])

  let simCalled = 0
  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x45)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 900 },
            value: addrs.map((a) => {
              const hit = accMap.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') simCalled++
      throw new Error(`Unexpected RPC method in Finding #10: ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(prematureIx.data),
            accounts: prematureIx.accounts,
          }),
        }),
        env,
      )
      assert.equal(res.status, 400)
      const errBody = (await res.json()) as { code: string; error: string }
      assert.equal(errBody.code, 'INVALID_PAGE_PDA')
      assert.match(errBody.error, /Premature rollover OpenPage/)
      assert.equal(simCalled, 0)
      assert.equal(guard.relayReleaseCalls[0]?.recordFailure, true)
    },
  )
})

test('Finding #11: multi-payer relayerPool pinning on quote endpoints + cross-payer Mode 2 & Mode 3 acceptance and exact signer matching', async () => {
  const worker = await getWorker()
  const poolSecrets = [
    new Uint8Array(32).fill(0xa1),
    new Uint8Array(32).fill(0xa2),
    new Uint8Array(32).fill(0xa3),
  ]
  const poolPubkeys = poolSecrets.map((s) => ed25519.getPublicKey(s))
  const poolB58 = poolPubkeys.map((pk) => base58Encode(pk))
  const [p0, p1, p2] = poolB58 as [string, string, string]

  // 1. Firewall accepts cross-payer Mode 2 unwrapWsol (accounts[0]=p1, feeRecipient=p2) and Mode 3 (accounts[0]=p2, feeAta=ATA(p0))
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const vaultWsolAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const recipient = base58Encode(new Uint8Array(32).fill(0x37))
  const crossUnwrapIx = buildTransactInstruction({
    payer: p1,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: true,
    publicOutflow: { mint: WSOL_MINT, vaultAta: vaultWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x75),
    nf1: nf1NonZero,
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 500_000_000n,
    relayerFeeAmount: 5_000_000n,
    recipient,
    relayerFeeRecipient: p2,
    memosBytes: new Uint8Array(0),
  })
  const vUnwrap = validateRelaySubmission(
    { instructionDataB64: toBase64(crossUnwrapIx.data), accounts: crossUnwrapIx.accounts },
    poolPubkeys[1]!,
    allowedPre,
    null,
    { relayerPoolPubkeys: poolPubkeys },
  )
  assert.equal(vUnwrap.nativeSolFeeToRelayer, 5_000_000n)
  assert.equal(vUnwrap.nativeSolFeeRecipient, p2)

  const p0UsdcAta = deriveAssociatedTokenAddressSync(p0, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const crossExecIx = buildTestExecSwapIx({
    payerB58: p2,
    routerProg: JUPITER_V6_ROUTER,
    feeAta: p0UsdcAta,
    feeAtaWritable: false,
    relayerFeeAmount: 2_000_000n,
    feeOnOutput: true,
    feeRecipient: p0UsdcAta,
    nf0Seed: 0x76,
  })
  const vExec = validateRelaySubmission(
    { instructionDataB64: toBase64(crossExecIx.data), accounts: crossExecIx.accounts },
    poolPubkeys[2]!,
    allowedPre,
    null,
    { relayerPoolPubkeys: poolPubkeys },
  )
  assert.equal(vExec.watchedRelayerFeeAta, p0UsdcAta)
  assert.equal(vExec.watchedRelayerFeeMint, USDC_MINT)

  // 2. HTTP /v1/fee-quote pins requested relayerPubkey=p2, and HTTP /v1/relay/submit signs with exact accounts[0]=p1
  //    while verifying native SOL fee inflow to p2 (and rejects unknown accounts[0] with 400)!
  const guard = createMockGuard()
  const mockRpc = 'https://mock-rpc.local/finding11-multipayer'
  const env = {
    RELAY_GUARD: guard.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRETS_JSON: JSON.stringify(poolSecrets.map((s) => toBase64(s))),
  } as Env
  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n })
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)
  const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [p1, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [p2, { bytes: new Uint8Array(0), lamports: 400_000_000, owner: SYSTEM_PROGRAM_ID }],
    [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveLanePdaSync(0, 0).address, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 1n, nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
  ])

  let sentWire: Uint8Array | null = null
  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
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
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x46)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 950 },
            value: addrs.map((a) => {
              const hit = accMap.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 950 },
            value: {
              err: null,
              logs: ['Cross-payer Withdraw OK'],
              unitsConsumed: 145_000,
              accounts: [
                { lamports: 497_981_106, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }, // p1 paid ~2_018_894
                { lamports: 405_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }, // p2 received 5_000_000
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        sentWire = fromBase64(String(body.params[0]))
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5MultiPayerSig1111111111111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 951, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC method in Finding #11: ${body.method}`)
    },
    async () => {
      // Pinning relayerPubkey=p2 on /v1/fee-quote returns p2 deterministically
      const fqRes = await worker.fetch(
        new Request(`https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=withdraw&mint=${WSOL_MINT}&unwrapWsol=true&amount=500000000&relayerPubkey=${p2}`),
        env,
      )
      assert.equal(fqRes.status, 200)
      const fq = (await fqRes.json()) as { relayerPubkey: string; feeRecipient: string }
      assert.equal(fq.relayerPubkey, p2)
      assert.equal(fq.feeRecipient, p2)

      // Submitting cross-payer withdraw signs with p1 and settles self_paying via p2's SOL inflow
      const subRes = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(crossUnwrapIx.data),
            accounts: crossUnwrapIx.accounts,
          }),
        }),
        env,
      )
      assert.equal(subRes.status, 200)
      const subBody = (await subRes.json()) as {
        billingMode: string
        relayerPubkey: string
        simulatedFeeAccount: string
        simulatedFeeUnits: string
        netSponsoredLamports: string
      }
      assert.equal(subBody.billingMode, 'self_paying')
      assert.equal(subBody.relayerPubkey, p1)
      assert.equal(subBody.simulatedFeeAccount, p2)
      assert.equal(subBody.simulatedFeeUnits, '5000000')
      assert.equal(subBody.netSponsoredLamports, '0')
      assert.ok(sentWire)
      // Verify compiled v1 tx fee payer (bytes 42..74) is p1 and trailing Ed25519 signature verifies under p1!
      assert.equal(base58Encode(sentWire.subarray(42, 74)), p1)
      const msgBytes = sentWire.subarray(0, sentWire.length - 64)
      const sigBytes = sentWire.subarray(sentWire.length - 64)
      assert.equal(ed25519.verify(sigBytes, msgBytes, poolPubkeys[1]!), true)

      // Unknown accounts[0] NOT in relayerPool MUST be rejected with 400 FIREWALL_REJECTED
      const badAccs = crossUnwrapIx.accounts.map((a, i) => (i === 0 ? { ...a, pubkey: recipient } : a))
      const badRes = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(crossUnwrapIx.data),
            accounts: badAccs,
          }),
        }),
        env,
      )
      assert.equal(badRes.status, 400)
      const badBody = (await badRes.json()) as { code: string }
      assert.equal(badBody.code, 'FIREWALL_REJECTED')
    },
  )
})

test('Finding #12: multi-ix batch unconditionally requires isSelfPaying=true even when FVK is unset, and caps each batch ix to outputCount <= 2', async () => {
  const worker = await getWorker()
  const makePrivIx = (seed: number, outputMask: number) => {
    const outCount = (outputMask & 1) + ((outputMask >> 1) & 1) + ((outputMask >> 2) & 1)
    const ix = buildTransactInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: 0,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: 0n,
      outNfSeq: 0n,
      outputMask,
      assetMode: ASSET_MODE_PRIVATE,
      proof192: dummyProof,
      nf0: new Uint8Array(32).fill(0x20 + seed * 2),
      nf1: new Uint8Array(32).fill(0x21 + seed * 2),
      cm0: new Uint8Array(32).fill(0x31),
      cm1: new Uint8Array(32).fill(0x32),
      cm2: new Uint8Array(32).fill(0x33),
      publicAmountOut: 0n,
      relayerFeeAmount: 0n,
      memosBytes: new Uint8Array(outCount * MEMO_ENTRY_WIRE_LEN).fill(0x41),
    })
    return { instructionDataB64: toBase64(ix.data), accounts: ix.accounts }
  }

  // 1. Multi-ix batch with outputCount === 3 (outputMask = 0b111) MUST be rejected by firewall!
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructions: [makePrivIx(0, 0b001), makePrivIx(1, 0b111)] },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('at most 2 outputs'),
  )

  // 2. 2-ix batch submitted with MAINNET_RELAYER_FVK_JSON UNSET + ALLOW_MICRO_SWAP_SUBSIDY='true'
  //    MUST still be rejected with 402 FEE_REQUIRED + recordFailure=true!
  const guard = createMockGuard()
  const env = {
    RELAY_GUARD: guard.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/finding12-no-fvk-batch',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    ALLOW_MICRO_SWAP_SUBSIDY: 'true',
    // MAINNET_RELAYER_FVK_JSON deliberately unset!
  } as Env
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)
  const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [deriveLanePdaSync(0, 0).address, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 2n, nfCount: 2n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
  ])

  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x47)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 960 },
            value: addrs.map((a) => {
              const hit = accMap.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 960 },
            value: {
              err: null,
              logs: ['Batch OK'],
              unitsConsumed: 360_000,
              accounts: [{ lamports: 495_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }],
            },
          },
        })
      }
      throw new Error(`Unexpected RPC method in Finding #12: ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructions: [makePrivIx(0, 0b001), makePrivIx(1, 0b001)],
          }),
        }),
        env,
      )
      assert.equal(res.status, 402)
      const errBody = (await res.json()) as { code: string }
      assert.equal(errBody.code, 'FEE_REQUIRED')
      assert.equal(guard.relayReleaseCalls[0]?.recordFailure, true)
    },
  )
})

test('Finding #13: submit-time margin + 2x Token-2022 TransferFee haircut, missing vault/escrow ATA rent in swap quote, deferred cm2 verification, and cron/refill hardening', async () => {
  const worker = await getWorker()

  // 1. `applyToken2022FeeHaircut` applies exact 2x active Token-2022 TransferFee haircut
  const t22Immutable400Bps = makeToken2022MutableTransferFeeMintBytes({
    decimals: 6,
    bps: 400, // 4% per hop => 8% (2x) haircut!
    mutableAuthority: false,
  })
  const hc = applyToken2022FeeHaircut({
    tokenProgram: TOKEN_2022_PROGRAM_ID,
    mintData: t22Immutable400Bps,
    currentEpoch: 100n,
    grossAmount: 1_000_000n,
  })
  assert.equal(hc.activeTransferFeeBps, 400)
  assert.equal(hc.haircutAmount, 80_000n)
  assert.equal(hc.netAmount, 920_000n)

  // 2. Submit-time margin (`SELF_PAY_MARGIN_BPS = 11000`) + 2x T22 haircut + deferred cm2 verification + recordFailure on COST_CEILING_EXCEEDED
  const t22FeeMint = base58Encode(new Uint8Array(32).fill(0xc4))
  const relayerT22Ata = deriveAssociatedTokenAddressSync(relayerB58, t22FeeMint, TOKEN_2022_PROGRAM_ID).address
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const vaultT22Ata = deriveAssociatedTokenAddressSync(vaultAuth, t22FeeMint, TOKEN_2022_PROGRAM_ID).address
  const recipient = base58Encode(new Uint8Array(32).fill(0x49))
  const recipientT22Ata = deriveAssociatedTokenAddressSync(recipient, t22FeeMint, TOKEN_2022_PROGRAM_ID).address
  const mockJup = 'https://mock-jup-f13.local'
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)

  // Cost = 10_000_000 lamports (0.01 SOL = $1.50 at $150/SOL).
  // With 1.1x margin, required net value = 11_000_000 lamports ($1.65).
  // With 2x 4% = 8% T22 haircut, gross $1.70 (1_700_000 units at $1/token) nets $1.564 -> < $1.65 => NOT self_paying!
  const withdrawT22Ix = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: false,
    publicOutflow: { mint: t22FeeMint, vaultAta: vaultT22Ata, tokenProgram: TOKEN_2022_PROGRAM_ID },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x78),
    nf1: nf1NonZero,
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 10_000_000n,
    relayerFeeAmount: 1_700_000n,
    recipient: recipientT22Ata,
    relayerFeeRecipient: relayerT22Ata,
    memosBytes: new Uint8Array(0),
  })

  const guardHaircut = createMockGuard()
  const mockRpcHaircut = 'https://mock-rpc.local/finding13-haircut'
  const envHaircut = {
    RELAY_GUARD: guardHaircut.namespace,
    MAINNET_RPC_URL: mockRpcHaircut,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    JUPITER_API_URL: mockJup,
    SELF_PAY_FEE_MINTS: `${WSOL_MINT},${t22FeeMint}`,
    SELF_PAY_MARGIN_BPS: '11000',
  } as Env
  const accMapHaircut = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [relayerT22Ata, { bytes: makeTokenAccountBytes(t22FeeMint, relayerB58, 0n), lamports: 2_039_280, owner: TOKEN_2022_PROGRAM_ID }],
    [t22FeeMint, { bytes: t22Immutable400Bps, lamports: 2_000_000, owner: TOKEN_2022_PROGRAM_ID }],
    [deriveLanePdaSync(0, 0).address, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 1n, nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
  ])

  await withMockFetch(
    async (url, init) => {
      if (url.startsWith(`${mockJup}/price/v3`)) {
        return Response.json({ [WSOL_MINT]: { usdPrice: 150 }, [t22FeeMint]: { usdPrice: 1 } })
      }
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getEpochInfo') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { epoch: 500 } })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x48)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 970 },
            value: addrs.map((a) => {
              const hit = accMapHaircut.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 970 },
            value: {
              err: null,
              logs: ['T22 Withdraw OK'],
              unitsConsumed: 150_000,
              accounts: [
                { lamports: 490_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }, // 10_000_000 outflow
                { lamports: 2_039_280, owner: TOKEN_2022_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(t22FeeMint, relayerB58, 1_700_000n)), 'base64'] },
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5HaircutWithdrawSig11111111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 971, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in Finding #13 haircut: ${url} ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(withdrawT22Ix.data),
            accounts: withdrawT22Ix.accounts,
          }),
        }),
        envHaircut,
      )
      assert.equal(res.status, 200)
      const body = (await res.json()) as { billingMode: string; netSponsoredLamports: string }
      // Gross 1.70 USDC covers 100% of $1.50 cost, but after 2x 4% T22 haircut ($1.564) < 1.1x margin ($1.65) -> NOT self_paying!
      assert.equal(body.billingMode, 'sponsored')
      assert.ok(BigInt(body.netSponsoredLamports) > 0n)
    },
  )

  // 3. COST_CEILING_EXCEEDED records failure (`recordFailure: true`)!
  const guardCeil = createMockGuard()
  const envCeil = {
    RELAY_GUARD: guardCeil.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/finding13-ceiling',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
  } as Env
  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x49)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 975 },
            value: addrs.map((a) => {
              const hit = accMapHaircut.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 975 },
            value: {
              err: null,
              logs: ['Huge Outflow'],
              unitsConsumed: 150_000,
              accounts: [
                { lamports: 400_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }, // 100_000_000 > 50_000_000 ceiling!
                { lamports: 2_039_280, owner: TOKEN_2022_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(t22FeeMint, relayerB58, 0n)), 'base64'] },
              ],
            },
          },
        })
      }
      throw new Error(`Unexpected RPC in Finding #13 ceiling: ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(withdrawT22Ix.data),
            accounts: withdrawT22Ix.accounts,
          }),
        }),
        envCeil,
      )
      assert.equal(res.status, 400)
      const errBody = (await res.json()) as { code: string }
      assert.equal(errBody.code, 'COST_CEILING_EXCEEDED')
      assert.equal(guardCeil.relayReleaseCalls[0]?.recordFailure, true)
    },
  )

  // 4. Deferred cm2 verification: rate-limited `guard.begin()` rejects 429 BEFORE RPC/cm2 crypto!
  const { cm2, memo } = makeShieldedFeeCm2(3_000_000n, wsolMintBytes)
  const privTransferIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b100,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x79),
    nf1: nf1NonZero,
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2,
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: memo,
  })
  const blockingGuard = {
    idFromName: () => ({} as DurableObjectId),
    get: () => ({
      async begin() {
        return { allowed: false, status: 429, code: 'TOO_MANY_FAILURES', reason: 'Rate limited', retryAfterSec: 300 }
      },
    }),
  } as unknown as Env['RELAY_GUARD']
  let rpcCallsAfterRateLimit = 0
  await withMockFetch(
    async () => {
      rpcCallsAfterRateLimit++
      throw new Error('RPC should never be called when guard.begin() denies!')
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(privTransferIx.data),
            accounts: privTransferIx.accounts,
          }),
        }),
        {
          RELAY_GUARD: blockingGuard,
          MAINNET_RPC_URL: 'https://mock-rpc.local/finding13-blocked',
          MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
          MAINNET_RELAYER_FVK_JSON: JSON.stringify({
            spendPkHex: toHex(relayerFvk.spendPk),
            nkHex: toHex(relayerFvk.nk),
            viewSkHex: toHex(relayerFvk.viewSk),
            viewPkHex: toHex(relayerFvk.viewPk),
          }),
        } as Env,
      )
      assert.equal(res.status, 429)
      assert.equal(rpcCallsAfterRateLimit, 0)
    },
  )

  // 5. Missing vault/escrow ATA rent is priced into `/v1/swap/quote`!
  const mockRpcSwapAta = 'https://mock-rpc.local/finding13-swap-ata-rent'
  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n })
  const guardSwap = createMockGuard()
  const envSwap = {
    RELAY_GUARD: guardSwap.namespace,
    MAINNET_RPC_URL: mockRpcSwapAta,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    JUPITER_API_URL: mockJup,
  } as Env
  await withMockFetch(
    async (url, init) => {
      if (url.startsWith(`${mockJup}/price/v3`)) {
        return Response.json({ [WSOL_MINT]: { usdPrice: 150 }, [USDC_MINT]: { usdPrice: 1 } })
      }
      if (url.startsWith(`${mockJup}/swap/v1/quote`)) {
        return Response.json({
          inputMint: WSOL_MINT,
          outputMint: USDC_MINT,
          inAmount: '5000000000',
          outAmount: '750000000',
          otherAmountThreshold: '740000000',
          slippageBps: 100,
          routePlan: [{ swapInfo: { label: 'Raydium CLMM', inputMint: WSOL_MINT, outputMint: USDC_MINT, inAmount: '5000000000', outAmount: '750000000' }, percent: 100 }],
        })
      }
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        return Response.json({ jsonrpc: '2.0', id: 1, result: len === 165 ? 2_039_280 : len === 0 ? 890_880 : 60_000_000 })
      }
      if (body.method === 'getAccountInfo' && body.params[0] === poolPda) {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { data: [toBase64(poolBytes), 'base64'], lamports: 2_000_000, owner: AUDREN_PROGRAM_ID } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        // Return mints as valid; for the 5-account ATA check [vaultIn, vaultOut, escrowIn, escrowOut, relayerFee],
        // mark vaultOut & escrowOut (indices 1 & 3) as missing (`null`)!
        if (addrs.includes(WSOL_MINT) || addrs.includes(USDC_MINT)) {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              value: addrs.map((a) => ({
                data: [toBase64(makeClassicMintBytes(a === WSOL_MINT ? 9 : 6)), 'base64'],
                lamports: 2_000_000,
                owner: CLASSIC_TOKEN_PROGRAM_ID,
              })),
            },
          })
        }
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: addrs.map((_a, idx) =>
              idx === 1 || idx === 3
                ? null
                : { data: ['', 'base64'], lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID },
            ),
          },
        })
      }
      throw new Error(`Unexpected fetch in Finding #13 swap quote: ${url}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request(`https://relay.audren.xyz/v1/swap/quote?cluster=mainnet&provider=jupiter&inputMint=${WSOL_MINT}&outputMint=${USDC_MINT}&amount=5000000000&shardId=0`),
        envSwap,
      )
      assert.equal(res.status, 200)
      const q = (await res.json()) as { feePlan: { billingMode: string; estimatedRelayCostLamports: string } }
      assert.equal(q.feePlan.billingMode, 'self_paying')
      // Must include 2 * 2_039_280 = 4_078_560 lamports on top of baseline swap rent!
      const sched = await fetchLiveRentSchedule(mockRpcSwapAta)
      assert.equal(
        BigInt(q.feePlan.estimatedRelayCostLamports),
        sched.swapBaselineLamports + 2n * 2_039_280n,
      )
    },
  )

  // 6. `runAutoRefill` strictly restricts swaps to `SELF_PAY_FEE_MINTS` + `AUDITED_SWAP_ROUTER_PROGRAMS`!
  const mockRpcRefill = 'https://mock-rpc.local/finding13-refill-allowlist'
  const junkAirdropMint = base58Encode(new Uint8Array(32).fill(0xd7))
  const evilRouter = base58Encode(new Uint8Array(32).fill(0xee))
  const refillEnv = {
    MAINNET_RPC_URL: mockRpcRefill,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    JUPITER_API_URL: mockJup,
  } as Env
  const refillCfg = loadPolicyConfig(refillEnv)
  let refillSendCalls = 0
  const quotedRefillInputMints: string[] = []

  await withMockFetch(
    async (url, init) => {
      if (url.startsWith(`${mockJup}/price/v3`)) {
        return Response.json({
          [WSOL_MINT]: { usdPrice: 150 },
          [USDC_MINT]: { usdPrice: 1 },
          [junkAirdropMint]: { usdPrice: 500 },
        })
      }
      if (url.startsWith(`${mockJup}/swap/v1/quote`)) {
        const u = new URL(url)
        quotedRefillInputMints.push(u.searchParams.get('inputMint') ?? '')
        return Response.json({
          inputMint: u.searchParams.get('inputMint'),
          outputMint: WSOL_MINT,
          inAmount: u.searchParams.get('amount'),
          outAmount: '100000000',
          otherAmountThreshold: '99000000',
          slippageBps: 100,
          routePlan: [{ swapInfo: { label: 'Orca Whirlpool', inputMint: USDC_MINT, outputMint: WSOL_MINT, inAmount: '15000000', outAmount: '100000000' }, percent: 100 }],
        })
      }
      if (url.startsWith(`${mockJup}/swap/v1/swap-instructions`)) {
        // Compromised/rogue aggregator returns an UNAUDITED router programId -> refill MUST reject it!
        return Response.json({
          swapInstruction: {
            programId: evilRouter,
            accounts: [{ pubkey: relayerB58, isSigner: true, isWritable: true }],
            data: toBase64(new Uint8Array([1, 2, 3])),
          },
          addressLookupTableAddresses: [],
        })
      }
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getBalance') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: 20_000_000 } }) // 0.02 SOL < 0.08 threshold
      }
      if (body.method === 'getTokenAccountsByOwner') {
        const filter = body.params[1] as { programId: string }
        if (filter.programId === CLASSIC_TOKEN_PROGRAM_ID) {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              value: [
                {
                  pubkey: deriveAssociatedTokenAddressSync(relayerB58, junkAirdropMint, CLASSIC_TOKEN_PROGRAM_ID).address,
                  account: { owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(junkAirdropMint, relayerB58, 100_000_000n)), 'base64'] },
                },
                {
                  pubkey: deriveAssociatedTokenAddressSync(relayerB58, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address,
                  account: { owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 15_000_000n)), 'base64'] },
                },
              ],
            },
          })
        }
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [] } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: addrs.map(() => ({ data: [toBase64(makeClassicMintBytes(6)), 'base64'], lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID })),
          },
        })
      }
      if (body.method === 'sendTransaction') {
        refillSendCalls++
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5ShouldNeverSendRefill111111111111111111111' })
      }
      throw new Error(`Unexpected RPC in Finding #13 refill: ${url} ${body.method}`)
    },
    async () => {
      const report = await runAutoRefill(refillEnv, refillCfg)
      // Junk airdropped mint MUST NEVER even be quoted; USDC quote returned evilRouter -> MUST be skipped!
      assert.deepEqual(quotedRefillInputMints, [USDC_MINT])
      assert.equal(refillSendCalls, 0)
      assert.equal(report.signatures.length, 0)
      assert.ok(report.details.some((d) => d.includes('not in AUDITED_SWAP_ROUTER_PROGRAMS')))
    },
  )
})

// ============================================================================
// Round 1 Security Audit Regression Tests (R1-R1 through R1-R7)
// ============================================================================

test('R1-R1: ExecViaEscrow relayerFee===0 never qualifies as self_paying (even with setupAtas or Jupiter platformFee), and /v1/swap/* defaults includeFee=false', async () => {
  const worker = await getWorker()
  const mockJup = 'https://mock-jup-r1r1.local'
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const escrow1 = deriveEscrowPdaSync(0, 1).address
  const relayerWsolAta = deriveAssociatedTokenAddressSync(relayerB58, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const relayerUsdcAta = deriveAssociatedTokenAddressSync(relayerB58, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)

  // 1. /v1/swap/quote and /v1/swap/instructions default includeFee to false so swaps settle via native EXEC_FLAG_FEE_ON_OUTPUT
  const quoteUrlsSeen: string[] = []
  const swapIxBodiesSeen: Array<Record<string, unknown>> = []
  const mockRpcSwap = 'https://mock-rpc.local/r1r1-swap-default-include-fee'
  const guardSwap = createMockGuard()
  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n })
  const envSwap = {
    RELAY_GUARD: guardSwap.namespace,
    MAINNET_RPC_URL: mockRpcSwap,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    JUPITER_API_URL: mockJup,
  } as Env

  await withMockFetch(
    async (url, init) => {
      if (url.startsWith(`${mockJup}/price/v3`)) {
        return Response.json({ [WSOL_MINT]: { usdPrice: 150 }, [USDC_MINT]: { usdPrice: 1 } })
      }
      if (url.startsWith(`${mockJup}/swap/v1/quote`)) {
        quoteUrlsSeen.push(url)
        return Response.json({
          inputMint: WSOL_MINT,
          outputMint: USDC_MINT,
          inAmount: '5000000000',
          outAmount: '750000000',
          otherAmountThreshold: '740000000',
          slippageBps: 100,
          platformFee: { feeBps: 25, amount: '1875000' },
          routePlan: [{ swapInfo: { label: 'Raydium CLMM', inputMint: WSOL_MINT, outputMint: USDC_MINT, inAmount: '5000000000', outAmount: '750000000' }, percent: 100 }],
        })
      }
      if (url.startsWith(`${mockJup}/swap/v1/swap-instructions`)) {
        swapIxBodiesSeen.push(JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>)
        return Response.json({
          swapInstruction: {
            programId: JUPITER_V6_ROUTER,
            accounts: [{ pubkey: escrow1, isSigner: true, isWritable: true }],
            data: toBase64(new Uint8Array([1, 2, 3])),
          },
          addressLookupTableAddresses: [],
        })
      }
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        return Response.json({ jsonrpc: '2.0', id: 1, result: len === 165 ? 2_039_280 : len === 16 ? 1_002_240 : len === 0 ? 890_880 : 60_000_000 })
      }
      if (body.method === 'getAccountInfo' && body.params[0] === poolPda) {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { data: [toBase64(poolBytes), 'base64'], lamports: 2_000_000, owner: AUDREN_PROGRAM_ID } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        if (addrs.includes(WSOL_MINT) || addrs.includes(USDC_MINT)) {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              value: addrs.map((a) => ({
                data: [toBase64(makeClassicMintBytes(a === WSOL_MINT ? 9 : 6)), 'base64'],
                lamports: 2_000_000,
                owner: CLASSIC_TOKEN_PROGRAM_ID,
              })),
            },
          })
        }
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: addrs.map(() => ({ data: ['', 'base64'], lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID })) },
        })
      }
      throw new Error(`Unexpected fetch in R1-R1 swap default test: ${url}`)
    },
    async () => {
      // Default /v1/swap/quote (no includeFee param) MUST NOT pass platformFeeBps to Jupiter
      const qRes = await worker.fetch(
        new Request(`https://relay.audren.xyz/v1/swap/quote?cluster=mainnet&provider=jupiter&inputMint=${WSOL_MINT}&outputMint=${USDC_MINT}&amount=5000000000&shardId=1`),
        envSwap,
      )
      assert.equal(qRes.status, 200)
      assert.equal(new URL(quoteUrlsSeen[0]!).searchParams.get('platformFeeBps'), null)

      // Default /v1/swap/instructions (no includeFee param) MUST NOT inject feeAccount even if quoteResponse has platformFee
      const ixRes = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/swap/instructions', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            provider: 'jupiter',
            shardId: 1,
            inputMint: WSOL_MINT,
            outputMint: USDC_MINT,
            quoteResponse: { inputMint: WSOL_MINT, outputMint: USDC_MINT, platformFee: { feeBps: 25 } },
          }),
        }),
        envSwap,
      )
      assert.equal(ixRes.status, 200)
      const ixBody = (await ixRes.json()) as { relayerFeeAta: string | null; platformFeeBps: number }
      assert.equal(ixBody.relayerFeeAta, null)
      assert.equal(ixBody.platformFeeBps, 0)
      assert.equal(swapIxBodiesSeen[0]?.feeAccount, undefined)
    },
  )

  // 2. ExecViaEscrow with relayerFee === 0n + setupAtas (vault/escrow) + Jupiter writable relayer ATA
  //    MUST run strictly as `sponsored` (consuming sponsored budget) when ALLOW_MICRO_SWAP_SUBSIDY='true',
  //    NEVER as `self_paying` even if simulation shows a huge ATA balance jump!
  const jupZeroFeeIx = buildTestExecSwapIx({
    payerB58: relayerB58,
    routerProg: JUPITER_V6_ROUTER,
    feeAta: relayerUsdcAta,
    feeAtaWritable: true,
    relayerFeeAmount: 0n,
    nf0Seed: 0x81,
  })
  const guardZero = createMockGuard()
  const mockRpcZero = 'https://mock-rpc.local/r1r1-zero-fee-sponsored'
  const envZero = {
    RELAY_GUARD: guardZero.namespace,
    MAINNET_RPC_URL: mockRpcZero,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    JUPITER_API_URL: mockJup,
    ALLOW_MICRO_SWAP_SUBSIDY: 'true',
  } as Env
  const accMapZero = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [relayerWsolAta, { bytes: makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n), lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }],
    [relayerUsdcAta, { bytes: makeTokenAccountBytes(USDC_MINT, relayerB58, 0n), lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }],
    [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveLanePdaSync(0, 0).address, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 1n, nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
  ])

  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x51)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 901 },
            value: addrs.map((a) => {
              const hit = accMapZero.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 901 },
            value: {
              err: null,
              logs: ['ExecViaEscrow OK'],
              unitsConsumed: 220_000,
              accounts: [{ lamports: 493_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5R1R1SponsoredMicroSwapSig111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 902, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R1-R1 sponsored test: ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(jupZeroFeeIx.data),
            accounts: jupZeroFeeIx.accounts,
            setupAtas: [
              { owner: vaultAuth, mint: WSOL_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
              { owner: escrow1, mint: USDC_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
            ],
          }),
        }),
        envZero,
      )
      assert.equal(res.status, 200)
      const body = (await res.json()) as {
        billingMode: string
        simulatedFeeUnits: string
        netSponsoredLamports: string
      }
      assert.equal(body.billingMode, 'sponsored')
      assert.equal(body.simulatedFeeUnits, '0')
      assert.ok(BigInt(body.netSponsoredLamports) >= 7_000_000n)
    },
  )
})

test('R1-R2: sponsored Withdraw recipient ATA setup is unconditionally rejected (402 FEE_REQUIRED) on allowlisted mints (WSOL & USDC), while self-paying recipient ATA setup succeeds', async () => {
  const worker = await getWorker()
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const attackerWallet = base58Encode(new Uint8Array(32).fill(0xef))
  const attackerWsolAta = deriveAssociatedTokenAddressSync(attackerWallet, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const relayerWsolAta = deriveAssociatedTokenAddressSync(relayerB58, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultWsolAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)
  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n })

  // 1. Sponsored WSOL withdraw (`unwrapWsol: false, relayerFee: 0`) trying to create attacker's WSOL ATA -> 402!
  const wsolDrainIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: false,
    publicOutflow: { mint: WSOL_MINT, vaultAta: vaultWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x82),
    nf1: nf1NonZero,
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 1n,
    relayerFeeAmount: 0n,
    recipient: attackerWsolAta,
    relayerFeeRecipient: relayerWsolAta,
    memosBytes: new Uint8Array(0),
  })

  // 2. Self-paying WSOL withdraw (`relayerFeeAmount: 6_000_000n` > 1.1x cost including ATA rent) -> 200 self_paying!
  const wsolSelfPayIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: false,
    publicOutflow: { mint: WSOL_MINT, vaultAta: vaultWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x83),
    nf1: nf1NonZero,
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 100_000_000n,
    relayerFeeAmount: 6_000_000n,
    recipient: attackerWsolAta,
    relayerFeeRecipient: relayerWsolAta,
    memosBytes: new Uint8Array(0),
  })

  const guard = createMockGuard()
  const mockRpc = 'https://mock-rpc.local/r1r2-wsol-ata-drain'
  const env = {
    RELAY_GUARD: guard.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
  } as Env
  const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [relayerWsolAta, { bytes: makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n), lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }],
    [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveLanePdaSync(0, 0).address, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 1n, nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
  ])

  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x52)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 910 },
            value: addrs.map((a) => {
              const hit = accMap.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        const watchAddrs = (body.params[1] as { accounts?: { addresses?: string[] } })?.accounts?.addresses ?? []
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 910 },
            value: {
              err: null,
              logs: ['Withdraw OK'],
              unitsConsumed: 150_000,
              accounts: watchAddrs.map((a) =>
                a === relayerWsolAta
                  ? { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 6_000_000n)), 'base64'] }
                  : { lamports: 495_900_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
              ),
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5R1R2SelfPayWsolAtaSig11111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 911, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R1-R2 test: ${body.method}`)
    },
    async () => {
      // Sponsored WSOL recipient ATA setup MUST reject 402 FEE_REQUIRED + recordFailure=true
      const drainRes = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(wsolDrainIx.data),
            accounts: wsolDrainIx.accounts,
            setupAtas: [{ owner: attackerWallet, mint: WSOL_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID }],
          }),
        }),
        env,
      )
      assert.equal(drainRes.status, 402)
      const drainBody = (await drainRes.json()) as { code: string }
      assert.equal(drainBody.code, 'FEE_REQUIRED')
      assert.equal(guard.relayReleaseCalls[0]?.recordFailure, true)

      // Self-paying WSOL recipient ATA setup succeeds
      const okRes = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(wsolSelfPayIx.data),
            accounts: wsolSelfPayIx.accounts,
            setupAtas: [{ owner: attackerWallet, mint: WSOL_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID }],
          }),
        }),
        env,
      )
      assert.equal(okRes.status, 200)
      const okBody = (await okRes.json()) as { billingMode: string }
      assert.equal(okBody.billingMode, 'self_paying')
    },
  )
})

test('R1-R3: refillSinglePayer enforces 95% oracle min-SOL-out floor, falls back to multi-hop on thin direct pool, blocks pre-existing WSOL masking, and pins simulation slot', async () => {
  const mockJup = 'https://mock-jup-r1r3.local'
  const wsolAta = deriveAssociatedTokenAddressSync(relayerB58, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const usdcAta = deriveAssociatedTokenAddressSync(relayerB58, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address

  async function runRefillCase(opts: {
    rpcUrl: string
    solUsd: number | null
    directMinOut: string
    multiHopMinOut: string
    preWsolTotalLamports: number
    preWsolAmount: bigint
    postRelayerLamports: number
    postWsolLamports: number
    slotSequence?: Array<{ preSlot: number; simSlot: number }>
  }) {
    const refillEnv = {
      MAINNET_RPC_URL: opts.rpcUrl,
      MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
      JUPITER_API_URL: mockJup,
    } as Env
    const refillCfg = loadPolicyConfig(refillEnv)
    const directFlagsSeen: Array<string | null> = []
    let sendCalls = 0
    let preReadIdx = 0
    let simIdx = 0

    const report = await withMockFetch(
      async (url, init) => {
        if (url.startsWith(`${mockJup}/price/v3`)) {
          return Response.json({
            ...(opts.solUsd !== null ? { [WSOL_MINT]: { usdPrice: opts.solUsd } } : {}),
            [USDC_MINT]: { usdPrice: 1 },
          })
        }
        if (url.startsWith(`${mockJup}/swap/v1/quote`)) {
          const u = new URL(url)
          const directFlag = u.searchParams.get('onlyDirectRoutes')
          directFlagsSeen.push(directFlag)
          const minOut = directFlag === 'true' ? opts.directMinOut : opts.multiHopMinOut
          return Response.json({
            inputMint: USDC_MINT,
            outputMint: WSOL_MINT,
            inAmount: '15000000',
            outAmount: minOut,
            otherAmountThreshold: minOut,
            slippageBps: 100,
            routePlan: [{ swapInfo: { label: 'Orca Whirlpool', inputMint: USDC_MINT, outputMint: WSOL_MINT, inAmount: '15000000', outAmount: minOut }, percent: 100 }],
          })
        }
        if (url.startsWith(`${mockJup}/swap/v1/swap-instructions`)) {
          return Response.json({
            swapInstruction: {
              programId: JUPITER_V6_ROUTER,
              accounts: [{ pubkey: relayerB58, isSigner: true, isWritable: true }],
              data: toBase64(new Uint8Array([1, 2, 3])),
            },
            addressLookupTableAddresses: [],
          })
        }
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getBalance') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: 20_000_000 } })
        }
        if (body.method === 'getTokenAccountsByOwner') {
          const filter = body.params[1] as { programId: string }
          if (filter.programId === CLASSIC_TOKEN_PROGRAM_ID) {
            return Response.json({
              jsonrpc: '2.0',
              id: 1,
              result: {
                value: [
                  ...(opts.preWsolAmount > 0n
                    ? [{ pubkey: wsolAta, account: { owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, opts.preWsolAmount)), 'base64'] } }]
                    : []),
                  { pubkey: usdcAta, account: { owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 15_000_000n)), 'base64'] } },
                ],
              },
            })
          }
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [] } })
        }
        if (body.method === 'getLatestBlockhash') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x53)) } } })
        }
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          if (addrs.includes(USDC_MINT)) {
            return Response.json({
              jsonrpc: '2.0',
              id: 1,
              result: { context: { slot: 1000 }, value: addrs.map(() => ({ data: [toBase64(makeClassicMintBytes(6)), 'base64'], lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID })) },
            })
          }
          const slot = opts.slotSequence?.[Math.min(preReadIdx, opts.slotSequence.length - 1)]?.preSlot ?? 1000
          preReadIdx++
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot },
              value: addrs.map((a) =>
                a === relayerB58
                  ? { data: ['', 'base64'], lamports: 20_000_000, owner: SYSTEM_PROGRAM_ID }
                  : a === wsolAta
                    ? { data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, opts.preWsolAmount)), 'base64'], lamports: opts.preWsolTotalLamports, owner: CLASSIC_TOKEN_PROGRAM_ID }
                    : a === usdcAta
                      ? { data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 15_000_000n)), 'base64'], lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }
                      : null,
              ),
            },
          })
        }
        if (body.method === 'simulateTransaction') {
          const slot = opts.slotSequence?.[Math.min(simIdx, opts.slotSequence.length - 1)]?.simSlot ?? 1000
          simIdx++
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot },
              value: {
                err: null,
                logs: ['Refill Swap OK'],
                unitsConsumed: 180_000,
                accounts: [
                  { lamports: opts.postRelayerLamports, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                  { lamports: opts.postWsolLamports, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n)), 'base64'] },
                  { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 0n)), 'base64'] },
                ],
              },
            },
          })
        }
        if (body.method === 'sendTransaction') {
          sendCalls++
          return Response.json({ jsonrpc: '2.0', id: 1, result: '5R1R3RefillMultiHopSig11111111111111111111111' })
        }
        if (body.method === 'getSignatureStatuses') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 1005, err: null, confirmationStatus: 'confirmed' }] } })
        }
        throw new Error(`Unexpected RPC in R1-R3 test: ${url} ${body.method}`)
      },
      () => runAutoRefill(refillEnv, refillCfg),
    )
    return { report, directFlagsSeen, sendCalls, simIdx }
  }

  // Case 1: Thin direct route (`1_000_000` < 95M floor) AND thin multi-hop (`50_000_000` < 95M floor) -> rejected!
  const thinBoth = await runRefillCase({
    rpcUrl: 'https://mock-rpc.local/r1r3-thin-both',
    solUsd: 150,
    directMinOut: '1000000',
    multiHopMinOut: '50000000',
    preWsolTotalLamports: 2_039_280,
    preWsolAmount: 0n,
    postRelayerLamports: 118_000_000,
    postWsolLamports: 2_039_280,
  })
  assert.deepEqual(thinBoth.directFlagsSeen, ['true', null])
  assert.equal(thinBoth.sendCalls, 0)
  assert.ok(thinBoth.report.details.some((d) => d.includes('95% oracle floor')))

  // Case 2: Thin direct route (`1_000_000`), healthy multi-hop (`98_000_000` >= 95M floor),
  //         AND pre-existing 0.004 WSOL (`4_000_000` < 5M Step-1 threshold) masking a 0-output swap -> REJECTED!
  const maskedWsol = await runRefillCase({
    rpcUrl: 'https://mock-rpc.local/r1r3-wsol-mask',
    solUsd: 150,
    directMinOut: '1000000',
    multiHopMinOut: '98000000',
    preWsolTotalLamports: 2_039_280 + 4_000_000,
    preWsolAmount: 4_000_000n,
    postRelayerLamports: 20_000_000 + 3_975_000, // ONLY unwrapped pre-existing 4M WSOL (0 swap output!)
    postWsolLamports: 2_039_280,
  })
  assert.deepEqual(maskedWsol.directFlagsSeen, ['true', null])
  assert.equal(maskedWsol.sendCalls, 0)
  assert.ok(maskedWsol.report.details.some((d) => d.includes('simulated net SOL gain')))

  // Case 3: Thin direct route falls back to healthy multi-hop (`98_000_000`), slot mismatch on attempt 1
  //         (1000 vs 1001) retries cleanly to pinned slot (1001 vs 1001), net gain >= floor -> SUCCEEDS!
  const multiHopOk = await runRefillCase({
    rpcUrl: 'https://mock-rpc.local/r1r3-multihop-ok',
    solUsd: 150,
    directMinOut: '1000000',
    multiHopMinOut: '98000000',
    preWsolTotalLamports: 2_039_280 + 4_000_000,
    preWsolAmount: 4_000_000n,
    postRelayerLamports: 20_000_000 + 4_000_000 + 98_000_000 - 25_000,
    postWsolLamports: 2_039_280,
    slotSequence: [
      { preSlot: 1000, simSlot: 1001 },
      { preSlot: 1001, simSlot: 1001 },
    ],
  })
  assert.deepEqual(multiHopOk.directFlagsSeen, ['true', null])
  assert.equal(multiHopOk.simIdx, 2)
  assert.equal(multiHopOk.sendCalls, 1)
  assert.equal(multiHopOk.report.action, 'swapped_fees')

  // Case 4: Missing WSOL USD price -> skips refill swap safely with zero sendTransaction calls
  clearPriceCache()
  const missingSolPrice = await runRefillCase({
    rpcUrl: 'https://mock-rpc.local/r1r3-no-sol-price',
    solUsd: null,
    directMinOut: '98000000',
    multiHopMinOut: '98000000',
    preWsolTotalLamports: 2_039_280,
    preWsolAmount: 0n,
    postRelayerLamports: 118_000_000,
    postWsolLamports: 2_039_280,
  })
  assert.equal(missingSolPrice.directFlagsSeen.length, 0)
  assert.equal(missingSolPrice.sendCalls, 0)
  assert.ok(missingSolPrice.report.details.some((d) => d.includes('WSOL USD price unavailable')))
})

test('R1-R4: 64 KB POST body cap (413), O(1) base58Decode length guard, preInstructions.data base64 pre-check, and bounded 512-entry caches', async () => {
  const worker = await getWorker()
  const guard = createMockGuard()
  const env = {
    RELAY_GUARD: guard.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/r1r4-dos',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    JUPITER_API_URL: 'https://mock-jup-r1r4.local',
  } as Env

  // 1. Oversized POST bodies (> 64 KB) return 413 Payload Too Large across ALL POST endpoints
  //    both WITH Content-Length and via chunked stream WITHOUT Content-Length!
  const oversizedPayload = JSON.stringify({ pad: 'a'.repeat(70_000) })
  for (const path of ['/v1/relay/submit', '/v1/swap/quote', '/v1/swap/instructions']) {
    const resCl = await worker.fetch(
      new Request(`https://relay.audren.xyz${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': String(oversizedPayload.length) },
        body: oversizedPayload,
      }),
      env,
    )
    assert.equal(resCl.status, 413, `${path} with Content-Length > 64KB must return 413`)

    // Streamed body without Content-Length header
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const chunk = new Uint8Array(16_384).fill(0x61)
        for (let i = 0; i < 5; i++) controller.enqueue(chunk)
        controller.close()
      },
    })
    const resStream = await worker.fetch(
      new Request(`https://relay.audren.xyz${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: stream,
        duplex: 'half',
      } as RequestInit),
      env,
    )
    assert.equal(resStream.status, 413, `${path} streamed body > 64KB must return 413`)
  }

  // 2. O(1) base58Decode length guard + isValidBase58PubkeyLen guard against quadratic CPU DoS
  const hugeBase58 = 'z'.repeat(50_000)
  const t0 = performance.now()
  assert.equal(isValidBase58PubkeyLen(hugeBase58), false)
  assert.equal(isValidPubkey(hugeBase58), false)
  assert.throws(() => base58Decode(hugeBase58), new RegExp(`exceeds limit ${BASE58_DEFAULT_MAX_LEN}`))
  const fqBadMint = await worker.fetch(
    new Request(`https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=withdraw&mint=${'z'.repeat(5_000)}`),
    env,
  )
  assert.equal(fqBadMint.status, 400)
  const elapsedMs = performance.now() - t0
  assert.ok(elapsedMs < 50, `Length-guarded base58Decode must reject huge input in <50ms (took ${elapsedMs}ms)`)

  // 3. preInstructions[0].data > 700 base64 chars rejected BEFORE fromBase64
  const relayerUsdcAta = deriveAssociatedTokenAddressSync(relayerB58, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const execIx = buildTestExecSwapIx({
    payerB58: relayerB58,
    routerProg: JUPITER_V6_ROUTER,
    feeAta: relayerUsdcAta,
    feeAtaWritable: false,
    relayerFeeAmount: 1_000_000n,
    feeOnOutput: true,
    feeRecipient: relayerUsdcAta,
    nf0Seed: 0x84,
  })
  assert.throws(
    () =>
      validateRelaySubmission(
        {
          instructionDataB64: toBase64(execIx.data),
          accounts: execIx.accounts,
          preInstructions: [
            {
              programId: DEFAULT_ALLOWED_PRE_IX_PROGRAMS[0]!,
              accounts: [],
              data: 'A'.repeat(704), // valid base64, > 700 chars -> rejected pre-decode!
            },
          ],
        },
        relayerPubkey,
        allowedPre,
      ),
    FirewallError,
  )

  // 4. MINT_META_CACHE & PRICE_CACHE stay strictly bounded <= 512 entries across 600 distinct mints
  const mints600 = Array.from({ length: 600 }, (_, i) => {
    const b = new Uint8Array(32)
    b[0] = 0x99
    b[1] = (i >> 8) & 0xff
    b[2] = i & 0xff
    return base58Encode(b)
  })
  await withMockFetch(
    async (url, init) => {
      if (url.startsWith('https://mock-jup-r1r4.local/price/v3')) {
        const ids = new URL(url).searchParams.get('ids')?.split(',') ?? []
        const resp: Record<string, { usdPrice: number }> = {}
        for (const id of ids) resp[id] = { usdPrice: 1.25 }
        return Response.json(resp)
      }
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 1100 },
            value: addrs.map(() => ({
              data: [toBase64(makeClassicMintBytes(6)), 'base64'],
              lamports: 2_000_000,
              owner: CLASSIC_TOKEN_PROGRAM_ID,
            })),
          },
        })
      }
      throw new Error(`Unexpected fetch in R1-R4 cache test: ${url}`)
    },
    async () => {
      await fetchMintMetasWithData('https://mock-rpc.local/r1r4-cache', mints600)
      assert.ok(
        getMintMetaCacheSize() <= MINT_META_CACHE_MAX_ENTRIES,
        `MINT_META_CACHE size ${getMintMetaCacheSize()} exceeded ${MINT_META_CACHE_MAX_ENTRIES}`,
      )
      assert.equal(getMintMetaCacheSize(), MINT_META_CACHE_MAX_ENTRIES)

      for (let off = 0; off < mints600.length; off += 100) {
        await fetchMintPricesUsd(env, mints600.slice(off, off + 100))
      }
      assert.ok(
        getPriceCacheSize() <= PRICE_CACHE_MAX_ENTRIES,
        `PRICE_CACHE size ${getPriceCacheSize()} exceeded ${PRICE_CACHE_MAX_ENTRIES}`,
      )
      assert.equal(getPriceCacheSize(), PRICE_CACHE_MAX_ENTRIES)
    },
  )
})

test('R1-R5: dust-prefunded setupAtas count exact deficit, SENTINEL_LEN (16 B) reserve applies to LaneRentVault, and missing vaultAcc adds full OpenPage deficit', async () => {
  const worker = await getWorker()
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const escrow1 = deriveEscrowPdaSync(0, 1).address
  const vaultInAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowOutAta = deriveAssociatedTokenAddressSync(escrow1, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const relayerUsdcAta = deriveAssociatedTokenAddressSync(relayerB58, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n })
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)

  // 1. Live rent schedule fetches getMinimumBalanceForRentExemption(16) for SENTINEL_LEN
  const mockRpcRent = 'https://mock-rpc.local/r1r5-sentinel-rent'
  const queriedLengths: number[] = []
  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        queriedLengths.push(len)
        const map: Record<number, number> = {
          0: 890_880,
          16: 1_002_240,
          165: 2_039_280,
          [SUBTREE_PAGE_LEN]: 58_340_000,
          [SUBROOT_PAGE_LEN]: 68_140_000,
          [MEMO_PAGE_LEN]: 72_149_760,
          [NF_PAGE_LEN]: 68_140_000,
        }
        return Response.json({ jsonrpc: '2.0', id: 1, result: map[len] ?? 1_000_000 })
      }
      if (body.method === 'getAccountInfo') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { data: [toBase64(poolBytes), 'base64'], lamports: 2_000_000, owner: AUDREN_PROGRAM_ID } } })
      }
      throw new Error(`Unexpected RPC in R1-R5 rent test: ${body.method}`)
    },
    async () => {
      const sched = await fetchLiveRentSchedule(mockRpcRent)
      assert.ok(queriedLengths.includes(16), 'fetchLiveRentSchedule must query SENTINEL_LEN (16 B)')
      assert.equal(sched.laneRentVaultReserveLamports, 1_002_240n)
    },
  )

  // 2. Dust-prefunded setupAtas (1 lamport, owner=SystemProgram, 0 bytes) MUST still count
  //    `2_039_280 - 1 = 2_039_279` lamports each in minExpectedCostLamports even under concurrent +1 SOL inflow!
  const execIx = buildTestExecSwapIx({
    payerB58: relayerB58,
    routerProg: JUPITER_V6_ROUTER,
    feeAta: relayerUsdcAta,
    feeAtaWritable: false,
    relayerFeeAmount: 100_000n, // tiny fee -> NOT self-paying
    feeOnOutput: true,
    feeRecipient: relayerUsdcAta,
    nf0Seed: 0x85,
  })
  const guardDust = createMockGuard()
  const envDust = {
    RELAY_GUARD: guardDust.namespace,
    MAINNET_RPC_URL: mockRpcRent,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    JUPITER_API_URL: 'https://mock-jup-r1r5.local',
    ALLOW_MICRO_SWAP_SUBSIDY: 'false',
  } as Env

  const accMapDust = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [relayerUsdcAta, { bytes: makeTokenAccountBytes(USDC_MINT, relayerB58, 0n), lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }],
    [vaultInAta, { bytes: new Uint8Array(0), lamports: 1, owner: SYSTEM_PROGRAM_ID }], // 1-lamport dust prefund!
    [escrowOutAta, { bytes: new Uint8Array(0), lamports: 5, owner: SYSTEM_PROGRAM_ID }], // 5-lamport dust prefund!
    [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
    [USDC_MINT, { bytes: makeClassicMintBytes(6), lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID }],
    [deriveLanePdaSync(0, 0).address, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 1n, nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
  ])

  await withMockFetch(
    async (url, init) => {
      if (url.startsWith('https://mock-jup-r1r5.local/price/v3')) {
        return Response.json({ [WSOL_MINT]: { usdPrice: 150 }, [USDC_MINT]: { usdPrice: 1 } })
      }
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x54)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 1200 },
            value: addrs.map((a) => {
              const hit = accMapDust.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 1200 },
            value: {
              err: null,
              logs: ['ExecViaEscrow OK'],
              unitsConsumed: 220_000,
              accounts: [
                // Concurrent +1 SOL inflow erases rawOutflowLamports to 0!
                { lamports: 1_500_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 100_000n)), 'base64'] },
              ],
            },
          },
        })
      }
      throw new Error(`Unexpected RPC in R1-R5 dust test: ${url} ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(execIx.data),
            accounts: execIx.accounts,
            setupAtas: [
              { owner: vaultAuth, mint: WSOL_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
              { owner: escrow1, mint: USDC_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
            ],
          }),
        }),
        envDust,
      )
      assert.equal(res.status, 402)
      const body = (await res.json()) as { code: string; simulatedCostLamports: string }
      assert.equal(body.code, 'FEE_REQUIRED')
      // Live noteRent = ceil(58_340_000/256) + ceil(68_140_000/76_800) + ceil(72_149_760/96) = 980_339 (< pool 1_000_000)
      // Floor = 5_000 + 5_000 + 2*(890_880 + 113_567) + 1*980_339 + (2_039_280 - 1) + (2_039_280 - 5)
      const expectedFloor = 5_000n + 5_000n + 2n * (890_880n + 113_567n) + 980_339n + 2_039_279n + 2_039_275n
      assert.equal(BigInt(body.simulatedCostLamports), expectedFloor)
    },
  )

  // 2b. SENTINEL_LEN (16 B = 1_002_240) LaneRentVault reserve: vault funded with exact
  //     `memoPageRent + 890_880` still has `111_360` lamports deficit (`1_002_240 - 890_880`),
  //     NOT 0 deficit as under the old 0-byte `890_880` reserve!
  const lanePda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const rolloverSentinelIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b011,
    assetMode: ASSET_MODE_PRIVATE,
    rollover: { nextMemoSeq: 1n },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x87),
    nf1: nf1NonZero,
    cm0: new Uint8Array(32).fill(0x11),
    cm1: new Uint8Array(32).fill(0x22),
    cm2: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN).fill(0x33),
  })
  const guardSentinel = createMockGuard()
  const envSentinel = {
    RELAY_GUARD: guardSentinel.namespace,
    MAINNET_RPC_URL: mockRpcRent,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
  } as Env
  const accMapSentinel = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
    [lanePda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: BigInt(MEMO_NOTES_PER_PAGE - 1), nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    // Vault has memoPageRent (72_149_760) + old 0-byte rent (890_880) -> leaves 111_360 deficit under 16-byte SENTINEL_LEN!
    [lane0RentVault, { bytes: new Uint8Array(16), lamports: 72_149_760 + 890_880, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
  ])

  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x59)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 1205 },
            value: addrs.map((a) => {
              const hit = accMapSentinel.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 1205 },
            value: {
              err: null,
              logs: ['OpenPage OK', 'Transact OK'],
              unitsConsumed: 200_000,
              accounts: [{ lamports: 1_500_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5R1R5SentinelReserveSig1111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 1206, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R1-R5 sentinel test: ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(rolloverSentinelIx.data),
            accounts: rolloverSentinelIx.accounts,
          }),
        }),
        envSentinel,
      )
      assert.equal(res.status, 200)
      const body = (await res.json()) as { simulatedCostLamports: string }
      // Expected floor = 5_000 + 5_000 + 2*(890_880 + 113_567) + 2*980_339 + 111_360 (SENTINEL_LEN reserve deficit!)
      const expectedSentinelFloor =
        5_000n + 5_000n + 2n * (890_880n + 113_567n) + 2n * 980_339n + 111_360n
      assert.equal(BigInt(body.simulatedCostLamports), expectedSentinelFloor)
    },
  )

  // 3. Missing LaneRentVault (`vaultAcc === null`) during auto-prepended OpenPage MUST treat vault
  //    as 0n lamports and add full pageRent to `openPageDeficitFloor` (-> COST_CEILING_EXCEEDED)!
  const rolloverIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b011,
    assetMode: ASSET_MODE_PRIVATE,
    rollover: { nextMemoSeq: 1n },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x86),
    nf1: nf1NonZero,
    cm0: new Uint8Array(32).fill(0x11),
    cm1: new Uint8Array(32).fill(0x22),
    cm2: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN).fill(0x33),
  })
  const guardMissingVault = createMockGuard()
  const envMissingVault = {
    RELAY_GUARD: guardMissingVault.namespace,
    MAINNET_RPC_URL: mockRpcRent,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
  } as Env
  const accMapMissingVault = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
    [lanePda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: BigInt(MEMO_NOTES_PER_PAGE - 1), nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    // LaneRentVault deliberately OMITTED (null)!
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
  ])

  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x55)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 1210 },
            value: addrs.map((a) => {
              const hit = accMapMissingVault.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 1210 },
            value: {
              err: null,
              logs: ['OpenPage OK', 'Transact OK'],
              unitsConsumed: 200_000,
              accounts: [{ lamports: 499_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }],
            },
          },
        })
      }
      throw new Error(`Unexpected RPC in R1-R5 missing vault test: ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(rolloverIx.data),
            accounts: rolloverIx.accounts,
          }),
        }),
        envMissingVault,
      )
      // Full 72_149_760 MemoPage deficit exceeds 50_000_000 ceiling -> 400 COST_CEILING_EXCEEDED!
      assert.equal(res.status, 400)
      const errBody = (await res.json()) as { code: string }
      assert.equal(errBody.code, 'COST_CEILING_EXCEEDED')
    },
  )
})

test('R1-R6: rpcCall preserves error.data details in thrown Error.message', async () => {
  await withMockFetch(
    async () =>
      Response.json({
        jsonrpc: '2.0',
        id: 1,
        error: {
          code: -32002,
          message: 'Transaction simulation failed: custom program error: 0x1771',
          data: { err: { InstructionError: [0, { Custom: 6001 }] } },
        },
      }),
    async () => {
      await assert.rejects(
        () => rpcCall('https://mock-rpc.local/r1r6-errdata', 'sendTransaction', []),
        (err: unknown) =>
          err instanceof Error &&
          err.message.includes('0x1771') &&
          err.message.includes('"Custom":6001'),
      )
    },
  )
})

test('R1-R7: parseMintSafetyInfo rejects mutable TransferHook.authority, truncated TransferHook/TransferFeeConfig, and ScaledUiAmount (TLV 25)', () => {
  const makeT22ExtMint = (extType: number, extPayload: Uint8Array): Uint8Array => {
    const buf = new Uint8Array(166 + 4 + extPayload.length)
    buf[44] = 6 // decimals
    buf[45] = 1 // is_initialized
    buf[165] = 1 // AccountType::Mint
    const dv = new DataView(buf.buffer)
    dv.setUint16(166, extType, true)
    dv.setUint16(168, extPayload.length, true)
    buf.set(extPayload, 170)
    return buf
  }

  // 1. TransferHook (14) with non-zero mutable authority [0..32] and all-zero program_id [32..64] -> UNSAFE!
  const hookMutableAuth = new Uint8Array(64)
  hookMutableAuth[0] = 0x42
  const resHookAuth = parseMintSafetyInfo(USDC_MINT, TOKEN_2022_PROGRAM_ID, makeT22ExtMint(14, hookMutableAuth))
  assert.equal(resHookAuth.safeForSelfPay, false)
  assert.equal(resHookAuth.hasUnsafeToken2022Ext, true)

  // 2. TransferHook (14) with all-zero authority [0..32] and non-zero program_id [32..64] -> UNSAFE!
  const hookActiveProg = new Uint8Array(64)
  hookActiveProg[32] = 0x77
  const resHookProg = parseMintSafetyInfo(USDC_MINT, TOKEN_2022_PROGRAM_ID, makeT22ExtMint(14, hookActiveProg))
  assert.equal(resHookProg.safeForSelfPay, false)
  assert.equal(resHookProg.hasUnsafeToken2022Ext, true)

  // 3. Truncated TransferHook (14, extLen < 64) -> UNSAFE!
  const resHookTrunc = parseMintSafetyInfo(USDC_MINT, TOKEN_2022_PROGRAM_ID, makeT22ExtMint(14, new Uint8Array(32)))
  assert.equal(resHookTrunc.safeForSelfPay, false)
  assert.equal(resHookTrunc.hasUnsafeToken2022Ext, true)

  // 4. Permanently disabled TransferHook (14, extLen == 64, all zeros) -> SAFE!
  const resHookDisabled = parseMintSafetyInfo(USDC_MINT, TOKEN_2022_PROGRAM_ID, makeT22ExtMint(14, new Uint8Array(64)))
  assert.equal(resHookDisabled.safeForSelfPay, true)

  // 5. ScaledUiAmount (25) -> UNSAFE!
  const resScaled = parseMintSafetyInfo(USDC_MINT, TOKEN_2022_PROGRAM_ID, makeT22ExtMint(25, new Uint8Array(56)))
  assert.equal(resScaled.safeForSelfPay, false)
  assert.equal(resScaled.hasUnsafeToken2022Ext, true)

  // 6. Truncated TransferFeeConfig (1, extLen < 108) -> UNSAFE!
  const resFeeTrunc = parseMintSafetyInfo(USDC_MINT, TOKEN_2022_PROGRAM_ID, makeT22ExtMint(1, new Uint8Array(64)))
  assert.equal(resFeeTrunc.safeForSelfPay, false)
  assert.equal(resFeeTrunc.hasUnsafeToken2022Ext, true)
})

// ============================================================================
// Round 2 Security Audit Regression Tests (R2-R1 through R2-R4)
// ============================================================================

test('R2-R1: refillSinglePayer ignores permissionlessly planted non-ATA WSOL & fee-token accounts', async () => {
  const mockJup = 'https://mock-jup-r2r1.local'
  const wsolAta = deriveAssociatedTokenAddressSync(relayerB58, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const usdcAta = deriveAssociatedTokenAddressSync(relayerB58, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const plantedWsolNonAta = base58Encode(new Uint8Array(32).fill(0xc1))
  const plantedUsdcNonAta = base58Encode(new Uint8Array(32).fill(0xc2))

  // Case 1: Planted 1-lamport non-ATA WSOL account appears FIRST before canonical WSOL ATA (0.09 WSOL).
  // Step 1 MUST ignore the planted non-ATA account and unwrap canonical `wsolAta`!
  let unwrapSendCalls = 0
  let getBalCalls1 = 0
  const env1 = {
    MAINNET_RPC_URL: 'https://mock-rpc.local/r2r1-wsol-planted',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    JUPITER_API_URL: mockJup,
  } as Env
  const cfg1 = loadPolicyConfig(env1)

  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getBalance') {
        getBalCalls1++
        // First two calls (initial balance + pre-unwrap balance): 0.02 SOL; post-unwrap: 0.11 SOL (>= 0.08)
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: getBalCalls1 <= 2 ? 20_000_000 : 110_000_000 } })
      }
      if (body.method === 'getTokenAccountsByOwner') {
        const filter = body.params[1] as { programId: string }
        if (filter.programId === CLASSIC_TOKEN_PROGRAM_ID) {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              value: [
                // Attacker planted 1-lamport auxiliary WSOL account first to shadow canonical WSOL ATA!
                {
                  pubkey: plantedWsolNonAta,
                  account: { owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 1n)), 'base64'] },
                },
                // Canonical WSOL ATA with 0.09 WSOL
                {
                  pubkey: wsolAta,
                  account: { owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 90_000_000n)), 'base64'] },
                },
              ],
            },
          })
        }
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [] } })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x61)) } } })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 2100 },
            value: {
              err: null,
              logs: ['CloseAccount OK', 'CreateAtaIdempotent OK'],
              unitsConsumed: 20_000,
              accounts: [{ lamports: 109_985_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        unwrapSendCalls++
        // Verify the signed v1 wire tx contains canonical `wsolAta` pubkey and NOT `plantedWsolNonAta`!
        const wireBytes = fromBase64(String(body.params[0]))
        const wsolHex = toHex(base58Decode(wsolAta))
        const plantedHex = toHex(base58Decode(plantedWsolNonAta))
        const wireHex = toHex(wireBytes)
        assert.ok(wireHex.includes(wsolHex), 'Unwrap tx must reference canonical wsolAta')
        assert.ok(!wireHex.includes(plantedHex), 'Unwrap tx must NOT reference planted non-ATA WSOL account')
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5R2R1UnwrapCanonicalWsolSig11111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 2101, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R2-R1 Case 1: ${body.method}`)
    },
    async () => {
      const report = await runAutoRefill(env1, cfg1)
      assert.equal(report.action, 'unwrapped_wsol')
      assert.equal(unwrapSendCalls, 1)
      assert.equal(report.signatures.length, 1)
    },
  )

  // Case 2: Planted large non-ATA WSOL (0.05 WSOL) + planted non-ATA USDC ($100) + canonical USDC ATA ($15).
  // Step 1 MUST NOT unwrap the planted non-ATA WSOL account; Step 2 MUST quote & swap ONLY canonical USDC ATA ($15)!
  const quotedAmounts: string[] = []
  let swapSendCalls = 0
  let getBalCalls2 = 0
  const env2 = {
    MAINNET_RPC_URL: 'https://mock-rpc.local/r2r1-usdc-planted',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    JUPITER_API_URL: mockJup,
  } as Env
  const cfg2 = loadPolicyConfig(env2)

  await withMockFetch(
    async (url, init) => {
      if (url.startsWith(`${mockJup}/price/v3`)) {
        return Response.json({ [WSOL_MINT]: { usdPrice: 150 }, [USDC_MINT]: { usdPrice: 1 } })
      }
      if (url.startsWith(`${mockJup}/swap/v1/quote`)) {
        const u = new URL(url)
        quotedAmounts.push(u.searchParams.get('amount') ?? '')
        return Response.json({
          inputMint: USDC_MINT,
          outputMint: WSOL_MINT,
          inAmount: u.searchParams.get('amount'),
          outAmount: '99000000',
          otherAmountThreshold: '98000000',
          slippageBps: 100,
          routePlan: [{ swapInfo: { label: 'Orca Whirlpool', inputMint: USDC_MINT, outputMint: WSOL_MINT, inAmount: '15000000', outAmount: '99000000' }, percent: 100 }],
        })
      }
      if (url.startsWith(`${mockJup}/swap/v1/swap-instructions`)) {
        return Response.json({
          swapInstruction: {
            programId: JUPITER_V6_ROUTER,
            accounts: [{ pubkey: relayerB58, isSigner: true, isWritable: true }],
            data: toBase64(new Uint8Array([1, 2, 3])),
          },
          addressLookupTableAddresses: [],
        })
      }
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getBalance') {
        getBalCalls2++
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: getBalCalls2 <= 2 ? 20_000_000 : 118_000_000 } })
      }
      if (body.method === 'getTokenAccountsByOwner') {
        const filter = body.params[1] as { programId: string }
        if (filter.programId === CLASSIC_TOKEN_PROGRAM_ID) {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              value: [
                // Planted non-ATA WSOL account with 0.05 WSOL -> MUST be ignored!
                {
                  pubkey: plantedWsolNonAta,
                  account: { owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 50_000_000n)), 'base64'] },
                },
                // Planted non-ATA USDC account with $100 USDC -> MUST be ignored!
                {
                  pubkey: plantedUsdcNonAta,
                  account: { owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 100_000_000n)), 'base64'] },
                },
                // Canonical USDC ATA with $15 USDC -> ONLY account allowed to swap!
                {
                  pubkey: usdcAta,
                  account: { owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 15_000_000n)), 'base64'] },
                },
              ],
            },
          })
        }
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [] } })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x62)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        if (addrs.includes(USDC_MINT)) {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: { context: { slot: 2110 }, value: addrs.map(() => ({ data: [toBase64(makeClassicMintBytes(6)), 'base64'], lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID })) },
          })
        }
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 2110 },
            value: addrs.map((a) =>
              a === relayerB58
                ? { data: ['', 'base64'], lamports: 20_000_000, owner: SYSTEM_PROGRAM_ID }
                : a === wsolAta
                  ? { data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n)), 'base64'], lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }
                  : a === usdcAta
                    ? { data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 15_000_000n)), 'base64'], lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }
                    : a === plantedWsolNonAta
                      ? { data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 50_000_000n)), 'base64'], lamports: 52_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }
                      : a === plantedUsdcNonAta
                        ? { data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 100_000_000n)), 'base64'], lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }
                        : null,
            ),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        const opts = body.params[1] as { accounts?: { addresses?: string[] } }
        const watchAddrs = opts?.accounts?.addresses ?? [relayerB58, wsolAta, usdcAta]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 2110 },
            value: {
              err: null,
              logs: ['Swap OK'],
              unitsConsumed: 180_000,
              accounts: watchAddrs.map((a) =>
                a === relayerB58
                  ? { lamports: 118_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }
                  : a === wsolAta
                    ? { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n)), 'base64'] }
                    : a === usdcAta
                      ? { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 0n)), 'base64'] }
                      : a === plantedWsolNonAta
                        ? { lamports: 52_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 50_000_000n)), 'base64'] }
                        : a === plantedUsdcNonAta
                          ? { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 100_000_000n)), 'base64'] }
                          : null,
              ),
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        swapSendCalls++
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5R2R1CanonicalUsdcSwapSig111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 2111, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R2-R1 Case 2: ${url} ${body.method}`)
    },
    async () => {
      const report = await runAutoRefill(env2, cfg2)
      assert.equal(report.action, 'swapped_fees')
      assert.equal(swapSendCalls, 1)
      assert.deepEqual(quotedAmounts, ['15000000'])
    },
  )
})

test('R2-R2: handleRelaySubmit watches LaneRentVault, retries slot skew to pin preCtx.slot === sim.slot, fails closed 503 SLOT_SKEW on persistent skew, and tightens Token-2022 setupAta floor', async () => {
  const worker = await getWorker()
  const poolPda = derivePoolPdaSync(0).address
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n })
  const dummyPageBytes = new Uint8Array(64).fill(0x5b)
  const mockRpc = 'https://mock-rpc.local/r2r2-slot-pin'

  // Seed live rent cache for mockRpc
  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        const map: Record<number, number> = {
          0: 890_880,
          16: 1_002_240,
          165: 2_039_280,
          [SUBTREE_PAGE_LEN]: 58_340_000,
          [SUBROOT_PAGE_LEN]: 68_140_000,
          [MEMO_PAGE_LEN]: 72_149_760,
          [NF_PAGE_LEN]: 68_140_000,
        }
        return Response.json({ jsonrpc: '2.0', id: 1, result: map[len] ?? 1_000_000 })
      }
      if (body.method === 'getAccountInfo') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { data: [toBase64(poolBytes), 'base64'], lamports: 2_000_000, owner: AUDREN_PROGRAM_ID } } })
      }
      throw new Error(`Unexpected RPC in R2-R2 rent seed: ${body.method}`)
    },
    () => fetchLiveRentSchedule(mockRpc),
  )

  const makeRolloverIx = (nfSeed: number) =>
    buildTransactInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: 0,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: 0n,
      outNfSeq: 0n,
      outputMask: 0b011,
      assetMode: ASSET_MODE_PRIVATE,
      rollover: { nextMemoSeq: 1n },
      proof192: dummyProof,
      nf0: new Uint8Array(32).fill(nfSeed),
      nf1: nf1NonZero,
      cm0: new Uint8Array(32).fill(0x11),
      cm1: new Uint8Array(32).fill(0x22),
      cm2: new Uint8Array(32),
      publicAmountOut: 0n,
      relayerFeeAmount: 0n,
      memosBytes: new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN).fill(0x33),
    })

  // Case 1: Attempt 1 sees preSlot=2000 (vault funded with 80M) vs simSlot=2001 -> retries once,
  //         re-fetches preCtx at slot 2001 (vault now has only memoPageRent + 890_880 -> 111_360 deficit!),
  //         pins slot 2001 === 2001, includes LaneRentVault in watchAddresses, and uses refreshed deficit!
  const guard1 = createMockGuard()
  const env1 = {
    RELAY_GUARD: guard1.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
  } as Env
  let preCalls1 = 0
  let simCalls1 = 0
  const watchedAddrsSeen: string[][] = []

  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x63)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        preCalls1++
        const addrs = body.params[0] as string[]
        const slot = preCalls1 === 1 ? 2000 : 2001
        // Between slot 2000 and 2001, vault balance dropped from 80_000_000 to 72_149_760 + 890_880!
        const vaultLamports = preCalls1 === 1 ? 80_000_000 : 72_149_760 + 890_880
        const map = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
          [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
          [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
          [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: BigInt(MEMO_NOTES_PER_PAGE - 1), nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
          [lane0RentVault, { bytes: new Uint8Array(16), lamports: vaultLamports, owner: AUDREN_PROGRAM_ID }],
          [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
          [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
          [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
          [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
        ])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot },
            value: addrs.map((a) => {
              const hit = map.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        simCalls1++
        const simCfg = body.params[1] as { accounts?: { addresses?: string[] } }
        watchedAddrsSeen.push(simCfg.accounts?.addresses ?? [])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 2001 },
            value: {
              err: null,
              logs: ['OpenPage OK', 'Transact OK'],
              unitsConsumed: 200_000,
              accounts: [
                { lamports: 1_500_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                { lamports: 3_000_000, owner: AUDREN_PROGRAM_ID, data: [toBase64(new Uint8Array(16)), 'base64'] },
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5R2R2PinnedRetrySig1111111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 2002, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R2-R2 Case 1: ${body.method}`)
    },
    async () => {
      const ix = makeRolloverIx(0x91)
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ cluster: 'mainnet', instructionDataB64: toBase64(ix.data), accounts: ix.accounts }),
        }),
        env1,
      )
      assert.equal(res.status, 200)
      assert.equal(preCalls1, 2, 'must re-fetch preFetchAddresses on slot skew')
      assert.equal(simCalls1, 2, 'must re-simulate once to pin preCtx.slot === sim.slot')
      assert.ok(
        watchedAddrsSeen[0]?.includes(lane0RentVault),
        'watchAddresses must include touched LaneRentVault PDA when OpenPage is prepended',
      )
      const body = (await res.json()) as { simulatedCostLamports: string }
      // Refreshed slot-2001 vault deficit = 111_360 lamports!
      const expectedRefreshedFloor =
        5_000n + 5_000n + 2n * (890_880n + 113_567n) + 2n * 980_339n + 111_360n
      assert.equal(BigInt(body.simulatedCostLamports), expectedRefreshedFloor)
    },
  )

  // Case 2: Persistent slot skew (preSlot !== simSlot across initial + all 3 parallel retries) fails closed with
  //         503 SLOT_SKEW, Retry-After: 1, releases DO nullifier lock (recordFailure: false), and releases OpenPage lock!
  const guard2 = createMockGuard()
  const env2 = {
    RELAY_GUARD: guard2.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
  } as Env
  let preCalls2 = 0
  let simCalls2 = 0
  let sendCalls2 = 0

  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x64)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        preCalls2++
        const addrs = body.params[0] as string[]
        const map = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
          [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
          [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
          [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: BigInt(MEMO_NOTES_PER_PAGE - 1), nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
          [lane0RentVault, { bytes: new Uint8Array(16), lamports: 80_000_000, owner: AUDREN_PROGRAM_ID }],
          [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
          [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
          [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
          [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
        ])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: preCalls2 === 1 ? 2010 : 2012 },
            value: addrs.map((a) => {
              const hit = map.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        simCalls2++
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: simCalls2 === 1 ? 2011 : 2013 },
            value: {
              err: null,
              logs: ['OpenPage OK', 'Transact OK'],
              unitsConsumed: 200_000,
              accounts: [
                { lamports: 498_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                { lamports: 8_000_000, owner: AUDREN_PROGRAM_ID, data: [toBase64(new Uint8Array(16)), 'base64'] },
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        sendCalls2++
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5ShouldNeverSendSlotSkew11111111111111111111' })
      }
      throw new Error(`Unexpected RPC in R2-R2 Case 2: ${body.method}`)
    },
    async () => {
      const ix = makeRolloverIx(0x92)
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ cluster: 'mainnet', instructionDataB64: toBase64(ix.data), accounts: ix.accounts }),
        }),
        env2,
      )
      assert.equal(res.status, 503)
      assert.equal(res.headers.get('retry-after'), '1')
      const errBody = (await res.json()) as { code: string }
      assert.equal(errBody.code, 'SLOT_SKEW')
      assert.equal(preCalls2, 4)
      assert.equal(simCalls2, 4)
      assert.equal(sendCalls2, 0)
      assert.equal(guard2.relayReleaseCalls.length, 1)
      assert.equal(guard2.relayReleaseCalls[0]?.recordFailure, false)
      assert.equal(guard2.openPageReleaseCalls.length, 1)
      assert.equal(guard2.openPageLocks.size, 0, 'OpenPage lock must be cleanly released on SLOT_SKEW')
    },
  )

  // Case 3: Token-2022 setupAta deficit floor uses 170-byte (298 storage bytes -> 2_074_080) rent floor!
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const t22Mint = base58Encode(new Uint8Array(32).fill(0xd9))
  const recipient = base58Encode(new Uint8Array(32).fill(0xe9))
  const vaultT22Ata = deriveAssociatedTokenAddressSync(vaultAuth, t22Mint, TOKEN_2022_PROGRAM_ID).address
  const recipientT22Ata = deriveAssociatedTokenAddressSync(recipient, t22Mint, TOKEN_2022_PROGRAM_ID).address
  const relayerT22Ata = deriveAssociatedTokenAddressSync(relayerB58, t22Mint, TOKEN_2022_PROGRAM_ID).address
  const t22WithdrawIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: false,
    publicOutflow: { mint: t22Mint, vaultAta: vaultT22Ata, tokenProgram: TOKEN_2022_PROGRAM_ID },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x93),
    nf1: nf1NonZero,
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 1_000_000n,
    relayerFeeAmount: 0n,
    recipient: recipientT22Ata,
    relayerFeeRecipient: relayerT22Ata,
    memosBytes: new Uint8Array(0),
  })
  const guard3 = createMockGuard()
  const env3 = {
    RELAY_GUARD: guard3.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
  } as Env

  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x65)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        const map = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
          [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
          [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
          [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 1n, nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
          [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
          [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
          [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
          [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
        ])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 2020 },
            value: addrs.map((a) => {
              const hit = map.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 2020 },
            value: {
              err: null,
              logs: ['Withdraw OK'],
              unitsConsumed: 150_000,
              // Same-slot concurrent SOL inflow erases rawOutflowLamports to 0
              accounts: [{ lamports: 1_500_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }],
            },
          },
        })
      }
      throw new Error(`Unexpected RPC in R2-R2 Case 3: ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(t22WithdrawIx.data),
            accounts: t22WithdrawIx.accounts,
            setupAtas: [{ owner: recipient, mint: t22Mint, tokenProgram: TOKEN_2022_PROGRAM_ID }],
          }),
        }),
        env3,
      )
      assert.equal(res.status, 402)
      const body = (await res.json()) as { code: string; simulatedCostLamports: string }
      assert.equal(body.code, 'FEE_REQUIRED')
      // Token-2022 170-byte ATA floor = ceil(2_039_280 * 298 / 293) = 2_074_080 (NOT classic 2_039_280!)
      const expectedT22Floor = 5_000n + 5_000n + 2n * (890_880n + 113_567n) + 2_074_080n
      assert.equal(BigInt(body.simulatedCostLamports), expectedT22Floor)
    },
  )
})

test('R2-R3: RelayGuard per-lane OpenPage lock blocks concurrent rollovers (503 LANE_ROLLOVER_BUSY) and retains unconfirmed grace lease', async () => {
  const RelayGuard = await getRelayGuardClass()
  const worker = await getWorker()
  const harness = createSqliteDoHarness()
  const guardDo = new RelayGuard(harness.ctx, {} as Env)
  await harness.ready()

  // 1. Direct SQLite RelayGuard DO unit verification: atomic multi-lane lock, wrong-lease isolation, & grace TTL
  const acq1 = await guardDo.acquireOpenPageLock({
    cluster: 'mainnet',
    poolId: 0,
    laneIds: [0],
    leaseId: 'lease-a',
    ttlMs: 15_000,
  })
  assert.equal(acq1.allowed, true)

  // Contention on same (mainnet, 0, 0)
  const acqContend = await guardDo.acquireOpenPageLock({
    cluster: 'mainnet',
    poolId: 0,
    laneIds: [0],
    leaseId: 'lease-b',
    ttlMs: 15_000,
  })
  assert.equal(acqContend.allowed, false)
  assert.equal(acqContend.busyLaneId, 0)

  // Atomic all-or-nothing across [1, 0]: MUST fail on lane 0 and MUST NOT leave lane 1 locked!
  const acqMultiFail = await guardDo.acquireOpenPageLock({
    cluster: 'mainnet',
    poolId: 0,
    laneIds: [1, 0],
    leaseId: 'lease-b',
    ttlMs: 15_000,
  })
  assert.equal(acqMultiFail.allowed, false)
  assert.equal(acqMultiFail.busyLaneId, 0)

  const acqLane1 = await guardDo.acquireOpenPageLock({
    cluster: 'mainnet',
    poolId: 0,
    laneIds: [1],
    leaseId: 'lease-c',
    ttlMs: 15_000,
  })
  assert.equal(acqLane1.allowed, true)
  await guardDo.releaseOpenPageLock({ cluster: 'mainnet', poolId: 0, laneIds: [1], leaseId: 'lease-c' })

  // Different cluster is independent
  const acqDevnet = await guardDo.acquireOpenPageLock({
    cluster: 'devnet',
    poolId: 0,
    laneIds: [0],
    leaseId: 'lease-dev',
    ttlMs: 15_000,
  })
  assert.equal(acqDevnet.allowed, true)
  await guardDo.releaseOpenPageLock({ cluster: 'devnet', poolId: 0, laneIds: [0], leaseId: 'lease-dev' })

  // Wrong leaseId MUST NOT release lease-a
  await guardDo.releaseOpenPageLock({ cluster: 'mainnet', poolId: 0, laneIds: [0], leaseId: 'lease-wrong' })
  assert.equal(
    (await guardDo.acquireOpenPageLock({ cluster: 'mainnet', poolId: 0, laneIds: [0], leaseId: 'lease-b' })).allowed,
    false,
  )

  // Short graceTtlMs keeps lock busy immediately, then expires cleanly
  await guardDo.releaseOpenPageLock({
    cluster: 'mainnet',
    poolId: 0,
    laneIds: [0],
    leaseId: 'lease-a',
    graceTtlMs: 35,
  })
  assert.equal(
    (await guardDo.acquireOpenPageLock({ cluster: 'mainnet', poolId: 0, laneIds: [0], leaseId: 'lease-b' })).allowed,
    false,
  )
  await new Promise((r) => setTimeout(r, 50))
  const acqAfterExpiry = await guardDo.acquireOpenPageLock({
    cluster: 'mainnet',
    poolId: 0,
    laneIds: [0],
    leaseId: 'lease-b',
    ttlMs: 15_000,
  })
  assert.equal(acqAfterExpiry.allowed, true)
  await guardDo.releaseOpenPageLock({ cluster: 'mainnet', poolId: 0, laneIds: [0], leaseId: 'lease-b' })

  // 2. End-to-end concurrent `handleRelaySubmit` rollover contention backed by real SQLite `RelayGuard`
  const realGuardNamespace = {
    idFromName: () => ({} as DurableObjectId),
    get: () => guardDo,
  } as unknown as Env['RELAY_GUARD']

  const poolPda = derivePoolPdaSync(0).address
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const poolBytes = makePoolStateBytes({ activeLanes: 1, rootEpochInterval: 32n, noteRentFee: 1_000_000n, nfRentFee: 113_567n })
  const dummyPageBytes = new Uint8Array(64).fill(0x5c)
  const mockRpc = 'https://mock-rpc.local/r2r3-lock'

  const env = {
    RELAY_GUARD: realGuardNamespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    SPONSORED_COOLDOWN_SEC_MAINNET: '0',
  } as Env

  const makeRolloverIx = (nf0Fill: number, nf1Fill: number) =>
    buildTransactInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: 0,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: 0n,
      outNfSeq: 0n,
      outputMask: 0b011,
      assetMode: ASSET_MODE_PRIVATE,
      rollover: { nextMemoSeq: 1n },
      proof192: dummyProof,
      nf0: new Uint8Array(32).fill(nf0Fill),
      nf1: new Uint8Array(32).fill(nf1Fill),
      cm0: new Uint8Array(32).fill(0x11),
      cm1: new Uint8Array(32).fill(0x22),
      cm2: new Uint8Array(32),
      publicAmountOut: 0n,
      relayerFeeAmount: 0n,
      memosBytes: new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN).fill(0x33),
    })

  let releaseFirstSim!: () => void
  let resolveFirstSimEntered!: () => void
  const firstSimEntered = new Promise<void>((resolve) => {
    resolveFirstSimEntered = resolve
  })
  const firstSimGate = new Promise<void>((resolve) => {
    releaseFirstSim = resolve
  })
  let simCount = 0
  let sendCount = 0
  let failFirstSim = true
  let failConfirm = false

  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x66)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        const map = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
          [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
          [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
          [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: BigInt(MEMO_NOTES_PER_PAGE - 1), nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
          [lane0RentVault, { bytes: new Uint8Array(16), lamports: 80_000_000, owner: AUDREN_PROGRAM_ID }],
          [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
          [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
          [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
          [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
        ])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 2200 },
            value: addrs.map((a) => {
              const hit = map.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        simCount++
        if (simCount === 1) {
          resolveFirstSimEntered()
          await firstSimGate
          if (failFirstSim) {
            return Response.json({
              jsonrpc: '2.0',
              id: 1,
              result: { context: { slot: 2200 }, value: { err: { Custom: 6001 }, logs: ['Sim fail'], unitsConsumed: 50_000, accounts: [] } },
            })
          }
        }
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 2200 },
            value: {
              err: null,
              logs: ['OpenPage OK', 'Transact OK'],
              unitsConsumed: 180_000,
              accounts: [
                { lamports: 496_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                { lamports: 7_850_240, owner: AUDREN_PROGRAM_ID, data: [toBase64(new Uint8Array(16)), 'base64'] },
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        sendCount++
        return Response.json({ jsonrpc: '2.0', id: 1, result: `5R2R3OpenPageLockSig${sendCount}111111111111111111111` })
      }
      if (body.method === 'getSignatureStatuses') {
        if (failConfirm) {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            error: { code: -32005, message: 'RPC node overloaded during confirmation' },
          })
        }
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 2201, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R2-R3 submit test: ${body.method}`)
    },
    async () => {
      const ix1 = makeRolloverIx(0xa1, 0xb1)
      const ix2 = makeRolloverIx(0xa2, 0xb2)
      const ix3 = makeRolloverIx(0xa3, 0xb3)

      // Launch Req 1 (acquires lane 0 lock and pauses inside simulateTransaction)
      const req1Promise = worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.10' },
          body: JSON.stringify({ cluster: 'mainnet', instructionDataB64: toBase64(ix1.data), accounts: ix1.accounts }),
        }),
        env,
      )
      await firstSimEntered

      // While Req 1 holds lane 0's lock, Req 2 MUST fail fast with 503 LANE_ROLLOVER_BUSY + Retry-After: 2!
      const req2Busy = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.11' },
          body: JSON.stringify({ cluster: 'mainnet', instructionDataB64: toBase64(ix2.data), accounts: ix2.accounts }),
        }),
        env,
      )
      assert.equal(req2Busy.status, 503)
      assert.equal(req2Busy.headers.get('retry-after'), '2')
      const busyBody = (await req2Busy.json()) as { code: string }
      assert.equal(busyBody.code, 'LANE_ROLLOVER_BUSY')
      assert.equal(simCount, 1, 'Contended Req 2 must never run simulateTransaction')

      // Let Req 1 fail simulation -> MUST release lane 0 lock cleanly in finally!
      releaseFirstSim()
      const req1Res = await req1Promise
      assert.equal(req1Res.status, 400)

      // Retrying Req 2 with the exact same nullifiers MUST now acquire lane 0 lock and succeed (200)!
      const req2Ok = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.11' },
          body: JSON.stringify({ cluster: 'mainnet', instructionDataB64: toBase64(ix2.data), accounts: ix2.accounts }),
        }),
        env,
      )
      assert.equal(req2Ok.status, 200)
      assert.equal(sendCount, 1)

      // Confirmed Req 2 released lane 0 lock; now test unconfirmed broadcast grace lease on Req 3!
      failConfirm = true
      const req3Unconfirmed = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.12' },
          body: JSON.stringify({ cluster: 'mainnet', instructionDataB64: toBase64(ix3.data), accounts: ix3.accounts }),
        }),
        env,
      )
      assert.equal(req3Unconfirmed.status, 502)
      assert.equal(sendCount, 2)
      // Lane 0 MUST still be locked under the short post-broadcast grace lease!
      const probeAfterUnconfirmed = await guardDo.acquireOpenPageLock({
        cluster: 'mainnet',
        poolId: 0,
        laneIds: [0],
        leaseId: 'probe-after-unconfirmed',
      })
      assert.equal(probeAfterUnconfirmed.allowed, false)
    },
  )
})

test('R2-R4: parseMintSafetyInfo rejects Token-2022 DefaultAccountState (TLV 6) = Frozen (2) and truncated payloads, while allowing Initialized (1)', () => {
  const makeT22ExtMint = (extType: number, extPayload: Uint8Array): Uint8Array => {
    const buf = new Uint8Array(166 + 4 + extPayload.length)
    buf[44] = 6 // decimals
    buf[45] = 1 // is_initialized
    buf[165] = 1 // AccountType::Mint
    const dv = new DataView(buf.buffer)
    dv.setUint16(166, extType, true)
    dv.setUint16(168, extPayload.length, true)
    buf.set(extPayload, 170)
    return buf
  }

  // 1. DefaultAccountState (6) = Frozen (2) -> UNSAFE!
  const resFrozen = parseMintSafetyInfo(USDC_MINT, TOKEN_2022_PROGRAM_ID, makeT22ExtMint(6, new Uint8Array([2])))
  assert.equal(resFrozen.safeForSelfPay, false)
  assert.equal(resFrozen.hasUnsafeToken2022Ext, true)

  // 2. DefaultAccountState (6) truncated (extLen === 0) -> UNSAFE!
  const resTrunc = parseMintSafetyInfo(USDC_MINT, TOKEN_2022_PROGRAM_ID, makeT22ExtMint(6, new Uint8Array(0)))
  assert.equal(resTrunc.safeForSelfPay, false)
  assert.equal(resTrunc.hasUnsafeToken2022Ext, true)

  // 3. DefaultAccountState (6) = Initialized (1) -> SAFE!
  const resInit = parseMintSafetyInfo(USDC_MINT, TOKEN_2022_PROGRAM_ID, makeT22ExtMint(6, new Uint8Array([1])))
  assert.equal(resInit.safeForSelfPay, true)
  assert.equal(resInit.hasUnsafeToken2022Ext, false)
})

test('R3-R1: pre-funded System-owned ATA griefing is detected as missing in /v1/fee-quote, /v1/swap/quote, and /v1/swap/instructions', async () => {
  const worker = await getWorker()
  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n })
  const mockRpc = 'https://mock-rpc.local/r3r1-prefunded-ata'
  const mockJup = 'https://mock-jup-r3r1.local'
  const env = {
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    JUPITER_API_URL: mockJup,
  } as Env

  const classicWsolBytes = makeClassicMintBytes(9)
  const classicUsdcBytes = makeClassicMintBytes(6)
  // Dust-prefunded System-owned account (890,880 lamports, owner = SYSTEM_PROGRAM_ID)
  const systemDustAccount = { data: ['', 'base64'], lamports: 890_880, owner: SYSTEM_PROGRAM_ID }
  // Control: genuine SPL-initialized ATA
  const initializedSplAccount = { data: ['', 'base64'], lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }

  let ataResponseMode: 'system_dust' | 'initialized' = 'system_dust'

  await withMockFetch(
    async (url, init) => {
      if (url.startsWith(`${mockJup}/price/v3`)) {
        return Response.json({ [WSOL_MINT]: { usdPrice: 150 }, [USDC_MINT]: { usdPrice: 1 } })
      }
      if (url.startsWith(`${mockJup}/swap/v1/quote`)) {
        return Response.json({
          inputMint: WSOL_MINT,
          outputMint: USDC_MINT,
          inAmount: '5000000000',
          outAmount: '750000000',
          otherAmountThreshold: '740000000',
          slippageBps: 100,
          routePlan: [{ swapInfo: { label: 'Raydium CLMM', inputMint: WSOL_MINT, outputMint: USDC_MINT, inAmount: '5000000000', outAmount: '750000000' }, percent: 100 }],
        })
      }
      if (url.startsWith(`${mockJup}/swap/v1/swap-instructions`)) {
        return Response.json({
          swapInstruction: {
            programId: JUPITER_V6_ROUTER,
            accounts: [{ pubkey: deriveEscrowPdaSync(0, 0).address, isSigner: true, isWritable: true }],
            data: toBase64(new Uint8Array([1, 2, 3])),
          },
          addressLookupTableAddresses: [],
        })
      }
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        const map: Record<number, number> = {
          0: 890_880,
          16: 1_002_240,
          165: 2_039_280,
          [SUBTREE_PAGE_LEN]: 58_340_000,
          [SUBROOT_PAGE_LEN]: 68_140_000,
          [MEMO_PAGE_LEN]: 72_149_760,
          [NF_PAGE_LEN]: 68_140_000,
        }
        return Response.json({ jsonrpc: '2.0', id: 1, result: map[len] ?? 1_000_000 })
      }
      if (body.method === 'getAccountInfo' && body.params[0] === poolPda) {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { data: [toBase64(poolBytes), 'base64'], lamports: 2_000_000, owner: AUDREN_PROGRAM_ID } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: addrs.map((addr) => {
              if (addr === WSOL_MINT) {
                return { data: [toBase64(classicWsolBytes), 'base64'], lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID }
              }
              if (addr === USDC_MINT) {
                return { data: [toBase64(classicUsdcBytes), 'base64'], lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID }
              }
              return ataResponseMode === 'system_dust' ? systemDustAccount : initializedSplAccount
            }),
          },
        })
      }
      throw new Error(`Unexpected RPC in R3-R1 test: ${url} ${body.method}`)
    },
    async () => {
      const sched = await fetchLiveRentSchedule(mockRpc)

      // 1. /v1/fee-quote: dust-prefunded System-owned feeRecipient ATA MUST be treated as missing!
      ataResponseMode = 'system_dust'
      const fqDustRes = await worker.fetch(
        new Request(`https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=withdraw&mint=${USDC_MINT}&amount=100000000`),
        env,
      )
      assert.equal(fqDustRes.status, 200)
      const fqDust = (await fqDustRes.json()) as {
        billingMode: string
        feeRecipientExists: boolean
        needsFeeAtaSetup: boolean
        estimatedRelayCostLamports: string
      }
      assert.equal(fqDust.billingMode, 'self_paying')
      assert.equal(fqDust.feeRecipientExists, false, 'System-owned dust ATA must NOT be treated as initialized')
      assert.equal(fqDust.needsFeeAtaSetup, true)

      // 2. /v1/swap/quote: all 4 vault/escrow + fee ATAs dust-prefunded with SystemProgram owner MUST be priced as missing!
      const sqDustRes = await worker.fetch(
        new Request(`https://relay.audren.xyz/v1/swap/quote?cluster=mainnet&provider=jupiter&inputMint=${WSOL_MINT}&outputMint=${USDC_MINT}&amount=5000000000&shardId=0`),
        env,
      )
      assert.equal(sqDustRes.status, 200)
      const sqDust = (await sqDustRes.json()) as {
        feePlan: {
          billingMode: string
          feeAccountExists: boolean
          needsFeeAtaSetup: boolean
          estimatedRelayCostLamports: string
        }
      }
      assert.equal(sqDust.feePlan.billingMode, 'self_paying')
      assert.equal(sqDust.feePlan.feeAccountExists, false)
      assert.equal(sqDust.feePlan.needsFeeAtaSetup, true)
      // Must include all 5 ATAs (4 vault/escrow + 1 relayerFee) on top of swapBaselineLamports!
      assert.equal(
        BigInt(sqDust.feePlan.estimatedRelayCostLamports),
        sched.swapBaselineLamports + 5n * 2_039_280n,
      )

      // 3. /v1/swap/instructions: all 5 System-owned dust ATAs MUST appear in `missingAtas`!
      const siDustRes = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/swap/instructions', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            provider: 'jupiter',
            inputMint: WSOL_MINT,
            outputMint: USDC_MINT,
            shardId: 0,
            includeFee: true,
            quoteResponse: { inputMint: WSOL_MINT, outputMint: USDC_MINT, platformFee: { feeBps: 50 } },
          }),
        }),
        env,
      )
      assert.equal(siDustRes.status, 200)
      const siDust = (await siDustRes.json()) as { missingAtas: Array<{ label: string }> }
      assert.deepEqual(
        siDust.missingAtas.map((m) => m.label),
        ['vaultIn', 'vaultOut', 'escrowIn', 'escrowOut', 'relayerFee'],
      )

      // 4. Control: genuinely SPL-owned ATAs are treated as existing across all 3 endpoints!
      ataResponseMode = 'initialized'
      const fqInitRes = await worker.fetch(
        new Request(`https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=withdraw&mint=${USDC_MINT}&amount=100000000`),
        env,
      )
      const fqInit = (await fqInitRes.json()) as { feeRecipientExists: boolean; needsFeeAtaSetup: boolean }
      assert.equal(fqInit.feeRecipientExists, true)
      assert.equal(fqInit.needsFeeAtaSetup, false)

      const siInitRes = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/swap/instructions', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            provider: 'jupiter',
            inputMint: WSOL_MINT,
            outputMint: USDC_MINT,
            shardId: 0,
            includeFee: true,
            quoteResponse: { inputMint: WSOL_MINT, outputMint: USDC_MINT, platformFee: { feeBps: 50 } },
          }),
        }),
        env,
      )
      const siInit = (await siInitRes.json()) as { missingAtas: Array<{ label: string }> }
      assert.equal(siInit.missingAtas.length, 0)
    },
  )
})

test('R3-R2: openPageLock uses 45s TTL and guards NaN/Infinity TTL inputs safely', async () => {
  const guardMod = await import('../src/policy/guard-do')
  const { RelayGuard, OPEN_PAGE_LOCK_TTL_MS } = guardMod
  assert.equal(OPEN_PAGE_LOCK_TTL_MS, 45_000)

  const harness = createSqliteDoHarness()
  const guardDo = new RelayGuard(harness.ctx, {} as Env)
  await harness.ready()

  // 1. Default openPageLock TTL is 45,000 ms (outlasting worst-case 25.2s+ waitForConfirmation)
  const t0 = Date.now()
  const defaultAcq = await guardDo.acquireOpenPageLock({
    cluster: 'mainnet',
    poolId: 0,
    laneIds: [1],
    leaseId: 'default-ttl-lease',
  })
  assert.equal(defaultAcq.allowed, true)
  const defaultRow = harness.db
    .prepare('SELECT expires_at FROM open_page_locks WHERE lane_key = ?')
    .get('mainnet:0:1') as { expires_at: number }
  assert.ok(defaultRow.expires_at - t0 >= 44_000 && defaultRow.expires_at - t0 <= 46_000)
  await guardDo.releaseOpenPageLock({
    cluster: 'mainnet',
    poolId: 0,
    laneIds: [1],
    leaseId: 'default-ttl-lease',
  })

  // 2. Non-finite ttlMs (NaN / Infinity) on acquireOpenPageLock falls back cleanly to 45_000 ms (no SQLite NOT NULL failure)
  for (const badTtl of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
    const before = Date.now()
    const acq = await guardDo.acquireOpenPageLock({
      cluster: 'mainnet',
      poolId: 0,
      laneIds: [2],
      leaseId: `bad-ttl-${String(badTtl)}`,
      ttlMs: badTtl,
    })
    assert.equal(acq.allowed, true)
    const row = harness.db
      .prepare('SELECT expires_at FROM open_page_locks WHERE lane_key = ?')
      .get('mainnet:0:2') as { expires_at: number }
    assert.ok(Number.isFinite(row.expires_at))
    assert.ok(row.expires_at - before >= 44_000 && row.expires_at - before <= 46_000)
    // Non-finite graceTtlMs (NaN / Infinity) MUST cleanly delete the lock rather than writing NaN or bogus grace!
    await guardDo.releaseOpenPageLock({
      cluster: 'mainnet',
      poolId: 0,
      laneIds: [2],
      leaseId: `bad-ttl-${String(badTtl)}`,
      graceTtlMs: badTtl,
    })
    const deleted = harness.db
      .prepare('SELECT expires_at FROM open_page_locks WHERE lane_key = ?')
      .get('mainnet:0:2')
    assert.equal(deleted, undefined)
  }

  // 3. Verify `handleRelaySubmit` passes `ttlMs: 45_000` to `acquireOpenPageLock`
  const worker = await getWorker()
  const mockGuard = createMockGuard()
  const poolPda = derivePoolPdaSync(0).address
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n })
  const dummyPageBytes = new Uint8Array(64).fill(0x5d)
  const rolloverIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b011,
    assetMode: ASSET_MODE_PRIVATE,
    rollover: { nextMemoSeq: 1n },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0xd1),
    nf1: nf1NonZero,
    cm0: new Uint8Array(32).fill(0x11),
    cm1: new Uint8Array(32).fill(0x22),
    cm2: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN).fill(0x33),
  })
  const env = {
    RELAY_GUARD: mockGuard.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/r3r2-submit-ttl',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
  } as Env

  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x68)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        const map = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
          [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
          [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
          [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: BigInt(MEMO_NOTES_PER_PAGE - 1), nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
          [lane0RentVault, { bytes: new Uint8Array(16), lamports: 80_000_000, owner: AUDREN_PROGRAM_ID }],
          [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
          [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
          [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
          [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
        ])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 3100 },
            value: addrs.map((a) => {
              const hit = map.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 3100 },
            value: {
              err: null,
              logs: ['OpenPage OK', 'Transact OK'],
              unitsConsumed: 180_000,
              accounts: [
                { lamports: 496_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                { lamports: 7_850_240, owner: AUDREN_PROGRAM_ID, data: [toBase64(new Uint8Array(16)), 'base64'] },
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5R3R2OpenPageTtl45sSig1111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 3101, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R3-R2 test: ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ cluster: 'mainnet', instructionDataB64: toBase64(rolloverIx.data), accounts: rolloverIx.accounts }),
        }),
        env,
      )
      assert.equal(res.status, 200)
      assert.equal(mockGuard.openPageAcquireCalls.length, 1)
      assert.equal(mockGuard.openPageAcquireCalls[0]?.ttlMs, 45_000)
    },
  )
})

test('R3-R3: Token-2022 ATA rent (170B / 182B) & TransferFeeConfig 2x quote gross-up + Mode 2/3 1x haircut exact quote->submit self-pay parity', async () => {
  // 1. Pure unit assertions for `estimateAtaRentLamports`, `applyToken2022FeeHaircut`, & `grossUpToken2022Amount`
  assert.equal(estimateAtaRentLamports(2_039_280n, CLASSIC_TOKEN_PROGRAM_ID, false), 2_039_280n)
  assert.equal(estimateAtaRentLamports(2_039_280n, TOKEN_2022_PROGRAM_ID, false), 2_074_080n) // 170 B (298/293)
  assert.equal(estimateAtaRentLamports(2_039_280n, TOKEN_2022_PROGRAM_ID, true), 2_157_600n) // 182 B (310/293)
  assert.equal(estimateAtaRentLamports(0n, TOKEN_2022_PROGRAM_ID, true), 0n)

  const t22Mint100BpsBytes = makeToken2022MutableTransferFeeMintBytes({
    decimals: 6,
    bps: 100, // 1% active TransferFeeConfig, immutable authority
    mutableAuthority: false,
  })
  const tf100 = { bps: 100n, maxFee: 10_000_000n, epoch: 0n }
  const hc1 = applyToken2022FeeHaircut({
    tokenProgram: TOKEN_2022_PROGRAM_ID,
    mintData: t22Mint100BpsBytes,
    currentEpoch: 500n,
    grossAmount: 1_000_000n,
    hops: 1,
  })
  assert.equal(hc1.haircutAmount, 10_000n)
  assert.equal(hc1.netAmount, 990_000n)

  const hc2 = applyToken2022FeeHaircut({
    tokenProgram: TOKEN_2022_PROGRAM_ID,
    mintData: t22Mint100BpsBytes,
    currentEpoch: 500n,
    grossAmount: 1_000_000n,
    hops: 2,
  })
  assert.equal(hc2.haircutAmount, 20_000n)
  assert.equal(hc2.netAmount, 980_000n)

  // `grossUpToken2022Amount` survives BOTH Mode 1 (2x singleFee) AND Mode 2/3 (sequential net -> 1x haircut)
  for (const target of [1n, 100n, 690_772n, 1_000_000n]) {
    const gross = grossUpToken2022Amount(target, tf100, 2)
    const afterMode1 = applyToken2022FeeHaircut({
      tokenProgram: TOKEN_2022_PROGRAM_ID,
      mintData: t22Mint100BpsBytes,
      currentEpoch: 500n,
      grossAmount: gross,
      hops: 2,
    }).netAmount
    assert.ok(afterMode1 >= target, `Mode 1 net (${afterMode1}) must cover target (${target})`)
    const afterReceipt = computeToken2022NetAmount(gross, tf100)
    const afterMode23 = applyToken2022FeeHaircut({
      tokenProgram: TOKEN_2022_PROGRAM_ID,
      mintData: t22Mint100BpsBytes,
      currentEpoch: 500n,
      grossAmount: afterReceipt,
      hops: 1,
    }).netAmount
    assert.ok(afterMode23 >= target, `Mode 2/3 net (${afterMode23}) must cover target (${target})`)
  }
  // Max-fee cap bound check
  const tfCapped = { bps: 500n, maxFee: 100n, epoch: 0n }
  assert.equal(grossUpToken2022Amount(1_000_000n, tfCapped, 2), 1_000_200n)

  // 2. End-to-end exact `/v1/fee-quote` -> `/v1/relay/submit` parity tests:
  //    - Token-2022 0-bps (bare 82 B mint, 170 B ATA = 2_074_080) Mode 2 Withdraw w/ missing fee ATA
  //    - Token-2022 100-bps (TransferFeeConfig, 182 B ATA = 2_157_600) Mode 1 Private Transfer
  //    - Token-2022 100-bps (TransferFeeConfig, 182 B ATA = 2_157_600) Mode 2 Public Withdraw w/ missing fee ATA
  //    - Token-2022 100-bps (TransferFeeConfig, 182 B ATA = 2_157_600) Mode 3 ExecViaEscrow + /v1/swap/quote
  const worker = await getWorker()
  const mockRpc = 'https://mock-rpc.local/r3r3-t22-parity'
  const mockJup = 'https://mock-jup-r3r3.local'
  const poolPda = derivePoolPdaSync(0).address
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n })
  const dummyPageBytes = new Uint8Array(64).fill(0x5e)
  const vaultAuth = deriveVaultAuthPdaSync(0).address

  const t22Mint0 = base58Encode(new Uint8Array(32).fill(0xe1))
  const t22Mint0Bytes = makeClassicMintBytes(6) // 82 B bare Token-2022 mint (0 bps, no TransferFeeConfig -> 170 B ATA)
  const t22Mint100 = base58Encode(new Uint8Array(32).fill(0xe2))
  const t22Mint100Bytes32 = base58Decode(t22Mint100)

  const relayerT22Ata0 = deriveAssociatedTokenAddressSync(relayerB58, t22Mint0, TOKEN_2022_PROGRAM_ID).address
  const vaultT22Ata0 = deriveAssociatedTokenAddressSync(vaultAuth, t22Mint0, TOKEN_2022_PROGRAM_ID).address
  const recipient = base58Encode(new Uint8Array(32).fill(0x4b))
  const recipientT22Ata0 = deriveAssociatedTokenAddressSync(recipient, t22Mint0, TOKEN_2022_PROGRAM_ID).address

  const relayerT22Ata100 = deriveAssociatedTokenAddressSync(relayerB58, t22Mint100, TOKEN_2022_PROGRAM_ID).address
  const vaultT22Ata100 = deriveAssociatedTokenAddressSync(vaultAuth, t22Mint100, TOKEN_2022_PROGRAM_ID).address
  const recipientT22Ata100 = deriveAssociatedTokenAddressSync(recipient, t22Mint100, TOKEN_2022_PROGRAM_ID).address
  const escrow1 = deriveEscrowPdaSync(0, 1).address
  const vaultWsolAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowWsolAta = deriveAssociatedTokenAddressSync(escrow1, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowT22Ata100 = deriveAssociatedTokenAddressSync(escrow1, t22Mint100, TOKEN_2022_PROGRAM_ID).address

  const fvkJson = JSON.stringify({
    spendPkHex: toHex(relayerFvk.spendPk),
    nkHex: toHex(relayerFvk.nk),
    viewSkHex: toHex(relayerFvk.viewSk),
    viewPkHex: toHex(relayerFvk.viewPk),
  })
  const guard = createMockGuard()
  const env = {
    RELAY_GUARD: guard.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    MAINNET_RELAYER_FVK_JSON: fvkJson,
    JUPITER_API_URL: mockJup,
    SELF_PAY_FEE_MINTS: `${WSOL_MINT},${t22Mint0},${t22Mint100}`,
    SELF_PAY_MARGIN_BPS: '11000',
    SPONSORED_COOLDOWN_SEC_MAINNET: '0',
  } as Env

  let nextSimRelayerLamports = 500_000_000
  let nextSimFeeAtaMint = t22Mint0
  let nextSimFeeAtaBalance = 0n
  let nextSimWatchCount = 1

  await withMockFetch(
    async (url, init) => {
      if (url.startsWith(`${mockJup}/price/v3`)) {
        return Response.json({
          [WSOL_MINT]: { usdPrice: 150 },
          [t22Mint0]: { usdPrice: 1 },
          [t22Mint100]: { usdPrice: 1 },
        })
      }
      if (url.startsWith(`${mockJup}/swap/v1/quote`)) {
        return Response.json({
          inputMint: WSOL_MINT,
          outputMint: t22Mint100,
          inAmount: '5000000000',
          outAmount: '750000000',
          otherAmountThreshold: '740000000',
          slippageBps: 100,
          routePlan: [{ swapInfo: { label: 'Raydium CLMM', inputMint: WSOL_MINT, outputMint: t22Mint100, inAmount: '5000000000', outAmount: '750000000' }, percent: 100 }],
        })
      }
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getEpochInfo') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { epoch: 500 } })
      }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        const map: Record<number, number> = {
          0: 890_880,
          16: 1_002_240,
          165: 2_039_280,
          [SUBTREE_PAGE_LEN]: 58_340_000,
          [SUBROOT_PAGE_LEN]: 68_140_000,
          [MEMO_PAGE_LEN]: 72_149_760,
          [NF_PAGE_LEN]: 68_140_000,
        }
        return Response.json({ jsonrpc: '2.0', id: 1, result: map[len] ?? 1_000_000 })
      }
      if (body.method === 'getAccountInfo' && body.params[0] === poolPda) {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { data: [toBase64(poolBytes), 'base64'], lamports: 2_000_000, owner: AUDREN_PROGRAM_ID } } })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x69)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        const map = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
          [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
          [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
          [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 1n, nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
          [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
          [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
          [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
          [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
          [WSOL_MINT, { bytes: makeClassicMintBytes(9), lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID }],
          [t22Mint0, { bytes: t22Mint0Bytes, lamports: 2_000_000, owner: TOKEN_2022_PROGRAM_ID }],
          [t22Mint100, { bytes: t22Mint100BpsBytes, lamports: 2_000_000, owner: TOKEN_2022_PROGRAM_ID }],
          // Only vaultWsolAta exists; escrowWsolAta, vaultT22Ata100, escrowT22Ata100, & relayer fee ATAs are missing!
          [vaultWsolAta, { bytes: makeTokenAccountBytes(WSOL_MINT, vaultAuth, 0n), lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }],
        ])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 4100 },
            value: addrs.map((a) => {
              const hit = map.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        const accounts = [
          { lamports: nextSimRelayerLamports, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
          ...(nextSimWatchCount > 1
            ? [
                {
                  lamports: 2_157_600,
                  owner: TOKEN_2022_PROGRAM_ID,
                  data: [toBase64(makeTokenAccountBytes(nextSimFeeAtaMint, relayerB58, nextSimFeeAtaBalance)), 'base64'],
                },
              ]
            : []),
        ]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { context: { slot: 4100 }, value: { err: null, logs: ['T22 OK'], unitsConsumed: 180_000, accounts } },
        })
      }
      if (body.method === 'sendTransaction') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5R3R3ExactT22ParitySig1111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 4101, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R3-R3 test: ${url} ${body.method}`)
    },
    async () => {
      const sched = await fetchLiveRentSchedule(mockRpc)

      // Case A: Bare Token-2022 (0 bps, no TransferFeeConfig) Mode 2 Withdraw with missing fee ATA -> exact 170 B ATA rent (2_074_080)
      const q0Res = await worker.fetch(
        new Request(`https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=withdraw&mint=${t22Mint0}&amount=50000000`),
        env,
      )
      assert.equal(q0Res.status, 200)
      const q0 = (await q0Res.json()) as {
        billingMode: string
        needsFeeAtaSetup: boolean
        relayerFee: string
        estimatedRelayCostLamports: string
      }
      assert.equal(q0.billingMode, 'self_paying')
      assert.equal(q0.needsFeeAtaSetup, true)
      const expectedCost0 = 2n * (sched.nullifierRentLamports + sched.nfPageRentPerNfLamports) + 20_000n + 2_074_080n
      assert.equal(BigInt(q0.estimatedRelayCostLamports), expectedCost0)

      const withdraw0Ix = buildTransactInstruction({
        payer: relayerB58,
        poolId: 0,
        rootRingKind: ROOT_RING_EPOCH,
        rootRingIdx: 0,
        outLaneId: 0,
        outSubSeq: 0n,
        outRootSeq: 0n,
        outMemoSeq: 0n,
        outNfSeq: 0n,
        outputMask: 0,
        assetMode: ASSET_MODE_PUBLIC,
        unwrapWsol: false,
        publicOutflow: { mint: t22Mint0, vaultAta: vaultT22Ata0, tokenProgram: TOKEN_2022_PROGRAM_ID },
        proof192: dummyProof,
        nf0: new Uint8Array(32).fill(0xd2),
        nf1: nf1NonZero,
        cm0: new Uint8Array(32),
        cm1: new Uint8Array(32),
        cm2: new Uint8Array(32),
        publicAmountOut: 50_000_000n,
        relayerFeeAmount: BigInt(q0.relayerFee),
        recipient: recipientT22Ata0,
        relayerFeeRecipient: relayerT22Ata0,
        memosBytes: new Uint8Array(0),
      })
      nextSimRelayerLamports = 500_000_000 - Number(expectedCost0)
      nextSimFeeAtaMint = t22Mint0
      nextSimFeeAtaBalance = BigInt(q0.relayerFee) // 0 bps -> full receipt
      nextSimWatchCount = 2
      const sub0Res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(withdraw0Ix.data),
            accounts: withdraw0Ix.accounts,
            setupAtas: [{ owner: relayerB58, mint: t22Mint0, tokenProgram: TOKEN_2022_PROGRAM_ID }],
            priorityFeeLamports: '15000',
          }),
        }),
        env,
      )
      assert.equal(sub0Res.status, 200)
      const sub0 = (await sub0Res.json()) as { billingMode: string; netSponsoredLamports: string; simulatedCostLamports: string }
      assert.equal(sub0.billingMode, 'self_paying', 'Exact 0-bps Token-2022 /v1/fee-quote MUST pass isSelfPaying on Mode 2 submit')
      assert.equal(sub0.netSponsoredLamports, '0')
      assert.equal(BigInt(sub0.simulatedCostLamports), expectedCost0)

      // Case B: Token-2022 100-bps TransferFeeConfig — Mode 1 Private Transfer exact quote -> submit parity
      const q1Res = await worker.fetch(
        new Request(`https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=transfer&mint=${t22Mint100}`),
        env,
      )
      assert.equal(q1Res.status, 200)
      const q1 = (await q1Res.json()) as { billingMode: string; relayerFee: string; estimatedRelayCostLamports: string }
      assert.equal(q1.billingMode, 'self_paying')
      const quotedMode1Fee = BigInt(q1.relayerFee)
      const feeCm2 = makeShieldedFeeCm2(quotedMode1Fee, t22Mint100Bytes32, 0x81)
      const transfer100Ix = buildTransactInstruction({
        payer: relayerB58,
        poolId: 0,
        rootRingKind: ROOT_RING_EPOCH,
        rootRingIdx: 0,
        outLaneId: 0,
        outSubSeq: 0n,
        outRootSeq: 0n,
        outMemoSeq: 0n,
        outNfSeq: 0n,
        outputMask: 0b111,
        assetMode: ASSET_MODE_PRIVATE,
        proof192: dummyProof,
        nf0: new Uint8Array(32).fill(0xd3),
        nf1: nf1NonZero,
        cm0: new Uint8Array(32).fill(0x11),
        cm1: new Uint8Array(32).fill(0x22),
        cm2: feeCm2.cm2,
        publicAmountOut: 0n,
        relayerFeeAmount: 0n,
        memosBytes: new Uint8Array([
          ...new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x12),
          ...new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x23),
          ...feeCm2.memo,
        ]),
      })
      nextSimRelayerLamports = 500_000_000 - Number(q1.estimatedRelayCostLamports)
      nextSimWatchCount = 1
      const sub1Res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(transfer100Ix.data),
            accounts: transfer100Ix.accounts,
            priorityFeeLamports: '15000',
          }),
        }),
        env,
      )
      assert.equal(sub1Res.status, 200)
      const sub1 = (await sub1Res.json()) as { billingMode: string; netSponsoredLamports: string }
      assert.equal(sub1.billingMode, 'self_paying', 'Exact 100-bps Token-2022 /v1/fee-quote MUST pass isSelfPaying on Mode 1 submit')
      assert.equal(sub1.netSponsoredLamports, '0')

      // Case C: Token-2022 100-bps TransferFeeConfig — Mode 2 Public Withdraw w/ missing fee ATA (182 B = 2_157_600)
      const q2Res = await worker.fetch(
        new Request(`https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=withdraw&mint=${t22Mint100}&amount=50000000`),
        env,
      )
      assert.equal(q2Res.status, 200)
      const q2 = (await q2Res.json()) as {
        billingMode: string
        needsFeeAtaSetup: boolean
        relayerFee: string
        estimatedRelayCostLamports: string
      }
      assert.equal(q2.billingMode, 'self_paying')
      assert.equal(q2.needsFeeAtaSetup, true)
      const expectedCost100 = 2n * (sched.nullifierRentLamports + sched.nfPageRentPerNfLamports) + 20_000n + 2_157_600n
      assert.equal(BigInt(q2.estimatedRelayCostLamports), expectedCost100)

      const quotedMode2Fee = BigInt(q2.relayerFee)
      // Simulate exact on-chain 1% Token-2022 TransferFee deducted on vault -> relayerFeeAta receipt!
      const receivedAfterOnChainReceipt = computeToken2022NetAmount(quotedMode2Fee, tf100)
      assert.ok(receivedAfterOnChainReceipt < quotedMode2Fee)

      const withdraw100Ix = buildTransactInstruction({
        payer: relayerB58,
        poolId: 0,
        rootRingKind: ROOT_RING_EPOCH,
        rootRingIdx: 0,
        outLaneId: 0,
        outSubSeq: 0n,
        outRootSeq: 0n,
        outMemoSeq: 0n,
        outNfSeq: 0n,
        outputMask: 0,
        assetMode: ASSET_MODE_PUBLIC,
        unwrapWsol: false,
        publicOutflow: { mint: t22Mint100, vaultAta: vaultT22Ata100, tokenProgram: TOKEN_2022_PROGRAM_ID },
        proof192: dummyProof,
        nf0: new Uint8Array(32).fill(0xd4),
        nf1: nf1NonZero,
        cm0: new Uint8Array(32),
        cm1: new Uint8Array(32),
        cm2: new Uint8Array(32),
        publicAmountOut: 50_000_000n,
        relayerFeeAmount: quotedMode2Fee,
        recipient: recipientT22Ata100,
        relayerFeeRecipient: relayerT22Ata100,
        memosBytes: new Uint8Array(0),
      })
      // Test same-slot SOL inflow (erasing rawOutflow) to ALSO prove setupAtaDeficitFloor uses exact 182 B (2_157_600) rent!
      nextSimRelayerLamports = 1_500_000_000
      nextSimFeeAtaMint = t22Mint100
      nextSimFeeAtaBalance = receivedAfterOnChainReceipt
      nextSimWatchCount = 2
      const sub2Res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(withdraw100Ix.data),
            accounts: withdraw100Ix.accounts,
            setupAtas: [{ owner: relayerB58, mint: t22Mint100, tokenProgram: TOKEN_2022_PROGRAM_ID }],
            priorityFeeLamports: '15000',
          }),
        }),
        env,
      )
      assert.equal(sub2Res.status, 200)
      const sub2 = (await sub2Res.json()) as { billingMode: string; netSponsoredLamports: string; simulatedCostLamports: string }
      assert.equal(BigInt(sub2.simulatedCostLamports), expectedCost100, 'setupAtaDeficitFloor must use exact 182 B (2_157_600) rent for TransferFeeConfig mint')
      assert.equal(sub2.billingMode, 'self_paying', 'Exact 100-bps Token-2022 /v1/fee-quote MUST pass isSelfPaying on Mode 2 submit (1x post-receipt haircut)')
      assert.equal(sub2.netSponsoredLamports, '0')

      // Case D: Token-2022 100-bps TransferFeeConfig — /v1/swap/quote per-ATA rent parity & Mode 3 ExecViaEscrow submit parity
      const sqRes = await worker.fetch(
        new Request(
          `https://relay.audren.xyz/v1/swap/quote?cluster=mainnet&provider=jupiter&inputMint=${WSOL_MINT}&outputMint=${t22Mint100}&amount=5000000000&shardId=1`,
        ),
        env,
      )
      assert.equal(sqRes.status, 200)
      const sq = (await sqRes.json()) as {
        quote: { outAmount: string }
        feePlan: {
          billingMode: string
          platformFeeBps: number
          needsFeeAtaSetup: boolean
          estimatedRelayCostLamports: string
        }
      }
      assert.equal(sq.feePlan.billingMode, 'self_paying')
      assert.equal(sq.feePlan.needsFeeAtaSetup, true)
      // Missing ATAs: escrowIn (WSOL classic 2_039_280) + vaultOut & escrowOut (T22 182 B = 2 * 2_157_600) + relayerFee (T22 182 B = 2_157_600)!
      const expectedSwapCost = sched.swapBaselineLamports + 2_039_280n + 3n * 2_157_600n
      assert.equal(BigInt(sq.feePlan.estimatedRelayCostLamports), expectedSwapCost)

      const q3Res = await worker.fetch(
        new Request(
          `https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=exec_escrow&feeOnOutput=true&mint=${t22Mint100}&amount=50000000&outputCount=1&missingAtaCount=2`,
        ),
        env,
      )
      assert.equal(q3Res.status, 200)
      const q3 = (await q3Res.json()) as { billingMode: string; relayerFee: string; estimatedRelayCostLamports: string }
      assert.equal(q3.billingMode, 'self_paying')
      const quotedMode3Fee = BigInt(q3.relayerFee)
      const mode3Received = computeToken2022NetAmount(quotedMode3Fee, tf100)
      const exec100Ix = buildTestExecSwapIx({
        payerB58: relayerB58,
        routerProg: JUPITER_V6_ROUTER,
        feeAta: relayerT22Ata100,
        feeAtaWritable: false,
        relayerFeeAmount: quotedMode3Fee,
        feeOnOutput: true,
        outMint: t22Mint100,
        outTokenProg: TOKEN_2022_PROGRAM_ID,
        feeRecipient: relayerT22Ata100,
        nf0Seed: 0xd5,
      })
      nextSimRelayerLamports = 500_000_000 - Number(q3.estimatedRelayCostLamports)
      nextSimFeeAtaMint = t22Mint100
      nextSimFeeAtaBalance = mode3Received
      nextSimWatchCount = 2
      const sub3Res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(exec100Ix.data),
            accounts: exec100Ix.accounts,
            setupAtas: [
              { owner: vaultAuth, mint: t22Mint100, tokenProgram: TOKEN_2022_PROGRAM_ID },
              { owner: escrow1, mint: t22Mint100, tokenProgram: TOKEN_2022_PROGRAM_ID },
              { owner: relayerB58, mint: t22Mint100, tokenProgram: TOKEN_2022_PROGRAM_ID },
            ],
            priorityFeeLamports: '15000',
          }),
        }),
        env,
      )
      assert.equal(sub3Res.status, 200)
      const sub3 = (await sub3Res.json()) as { billingMode: string; netSponsoredLamports: string }
      assert.equal(sub3.billingMode, 'self_paying', 'Exact 100-bps Token-2022 /v1/fee-quote MUST pass isSelfPaying on Mode 3 ExecViaEscrow submit')
      assert.equal(sub3.netSponsoredLamports, '0')
    },
  )
})

test('R3-R4: parallel small-watch slot pinning (up to 3 processed attempts, excluding LaneTreeState & existing pages) in handleRelaySubmit & refillSinglePayer', async () => {
  const worker = await getWorker()
  const poolPda = derivePoolPdaSync(0).address
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const existingSubPda = deriveSubtreePdaSync(0, 0, 0n).address
  const existingRootPda = deriveSubrootPdaSync(0, 0, 0n).address
  const existingMemoPda = deriveMemoPdaSync(0, 0, 0n).address
  const existingNfPda = deriveNfPagePdaSync(0, 0, 0n).address
  const newMemoPda = deriveMemoPdaSync(0, 0, 1n).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n })
  const dummyPageBytes = new Uint8Array(64).fill(0x5f)
  const mockRpc = 'https://mock-rpc.local/r3r4-parallel-pin'

  const rolloverIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b011,
    assetMode: ASSET_MODE_PRIVATE,
    rollover: { nextMemoSeq: 1n },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0xd6),
    nf1: nf1NonZero,
    cm0: new Uint8Array(32).fill(0x11),
    cm1: new Uint8Array(32).fill(0x22),
    cm2: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN).fill(0x33),
  })

  // 1. handleRelaySubmit: skews on initial + parallel retries 1 & 2, pins on parallel retry 3!
  //    Verify retries run in parallel (`Promise.all`) at `processed` commitment and OMIT LaneTreeState + existing pages!
  const guard = createMockGuard()
  const env = {
    RELAY_GUARD: guard.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
  } as Env
  let preCalls = 0
  let simCalls = 0
  let inFlightRetryCalls = 0
  let maxConcurrentRetryCalls = 0
  const retryAddrBatches: string[][] = []
  const retryCommitments: Array<{ method: string; commitment: string }> = []
  // Slot schedule: attempt 0 (initial): 5000 vs 5001; retry 1: 5002 vs 5003; retry 2: 5004 vs 5005; retry 3: 5006 === 5006!
  const preSlots = [5000, 5002, 5004, 5006]
  const simSlots = [5001, 5003, 5005, 5006]

  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x6a)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const idx = preCalls++
        const addrs = body.params[0] as string[]
        const opts = body.params[1] as { commitment?: string } | undefined
        if (idx > 0) {
          retryAddrBatches.push(addrs)
          retryCommitments.push({ method: 'getMultipleAccounts', commitment: opts?.commitment ?? '' })
          inFlightRetryCalls++
          maxConcurrentRetryCalls = Math.max(maxConcurrentRetryCalls, inFlightRetryCalls)
          await new Promise((r) => setTimeout(r, 15))
          inFlightRetryCalls--
        }
        const map = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
          [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
          [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
          [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: BigInt(MEMO_NOTES_PER_PAGE - 1), nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
          [lane0RentVault, { bytes: new Uint8Array(16), lamports: 80_000_000, owner: AUDREN_PROGRAM_ID }],
          [existingSubPda, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
          [existingRootPda, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
          [existingMemoPda, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
          [existingNfPda, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
        ])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: preSlots[idx] ?? 5006 },
            value: addrs.map((a) => {
              const hit = map.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        const idx = simCalls++
        const opts = body.params[1] as { commitment?: string } | undefined
        if (idx > 0) {
          retryCommitments.push({ method: 'simulateTransaction', commitment: opts?.commitment ?? '' })
          inFlightRetryCalls++
          maxConcurrentRetryCalls = Math.max(maxConcurrentRetryCalls, inFlightRetryCalls)
          await new Promise((r) => setTimeout(r, 15))
          inFlightRetryCalls--
        }
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: simSlots[idx] ?? 5006 },
            value: {
              err: null,
              logs: ['OpenPage OK', 'Transact OK'],
              unitsConsumed: 180_000,
              accounts: [
                { lamports: 496_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                { lamports: 7_850_240, owner: AUDREN_PROGRAM_ID, data: [toBase64(new Uint8Array(16)), 'base64'] },
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5R3R4ParallelPinThirdAttemptSig1111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 5007, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R3-R4 submit test: ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ cluster: 'mainnet', instructionDataB64: toBase64(rolloverIx.data), accounts: rolloverIx.accounts }),
        }),
        env,
      )
      assert.equal(res.status, 200, 'Must succeed when 3rd parallel small-watch retry pins slot')
      assert.equal(preCalls, 4)
      assert.equal(simCalls, 4)
      assert.equal(maxConcurrentRetryCalls, 2, 'Retry getMultipleAccounts + simulateTransaction MUST execute concurrently via Promise.all')
      assert.equal(retryAddrBatches.length, 3)
      for (const batch of retryAddrBatches) {
        assert.ok(batch.includes(relayerB58))
        assert.ok(batch.includes(poolPda))
        assert.ok(batch.includes(lane0RentVault))
        assert.ok(batch.includes(newMemoPda))
        // Must OMIT bulky LaneTreeState (38+ KB) and already-initialized page PDAs (8-10 KB each)!
        assert.equal(batch.includes(lane0Pda), false, 'pinAddresses must NOT re-fetch LaneTreeState')
        assert.equal(batch.includes(existingSubPda), false, 'pinAddresses must NOT re-fetch existing SubtreePage')
        assert.equal(batch.includes(existingRootPda), false, 'pinAddresses must NOT re-fetch existing SubtreeRootPage')
        assert.equal(batch.includes(existingMemoPda), false, 'pinAddresses must NOT re-fetch existing MemoPage')
        assert.equal(batch.includes(existingNfPda), false, 'pinAddresses must NOT re-fetch existing NullifierPage')
      }
      assert.ok(
        retryCommitments.every((c) => c.commitment === 'processed'),
        `All parallel pin retries must use processed commitment, got ${JSON.stringify(retryCommitments)}`,
      )
    },
  )

  // 2. refillSinglePayer: parallel `Promise.all` pinning succeeds on 3rd parallel retry attempt (and skips cleanly on 4th skew)
  const mockJupRefill = 'https://mock-jup-r3r4-refill.local'
  const wsolAta = deriveAssociatedTokenAddressSync(relayerB58, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const usdcAta = deriveAssociatedTokenAddressSync(relayerB58, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const refillEnv = {
    MAINNET_RPC_URL: 'https://mock-rpc.local/r3r4-refill-pin',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    JUPITER_API_URL: mockJupRefill,
  } as Env
  const refillCfg = loadPolicyConfig(refillEnv)

  let refillPreCalls = 0
  let refillSimCalls = 0
  let refillConcurrent = 0
  let refillMaxConcurrent = 0
  let refillSendCalls = 0
  const refillPreSlots = [6000, 6002, 6004, 6006]
  const refillSimSlots = [6001, 6003, 6005, 6006]

  const refillReport = await withMockFetch(
    async (url, init) => {
      if (url.startsWith(`${mockJupRefill}/price/v3`)) {
        return Response.json({ [WSOL_MINT]: { usdPrice: 150 }, [USDC_MINT]: { usdPrice: 1 } })
      }
      if (url.startsWith(`${mockJupRefill}/swap/v1/quote`)) {
        return Response.json({
          inputMint: USDC_MINT,
          outputMint: WSOL_MINT,
          inAmount: '15000000',
          outAmount: '98000000',
          otherAmountThreshold: '98000000',
          slippageBps: 100,
          routePlan: [{ swapInfo: { label: 'Orca Whirlpool', inputMint: USDC_MINT, outputMint: WSOL_MINT, inAmount: '15000000', outAmount: '98000000' }, percent: 100 }],
        })
      }
      if (url.startsWith(`${mockJupRefill}/swap/v1/swap-instructions`)) {
        return Response.json({
          swapInstruction: {
            programId: JUPITER_V6_ROUTER,
            accounts: [{ pubkey: relayerB58, isSigner: true, isWritable: true }],
            data: toBase64(new Uint8Array([1, 2, 3])),
          },
          addressLookupTableAddresses: [],
        })
      }
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getBalance') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: 20_000_000 } })
      }
      if (body.method === 'getTokenAccountsByOwner') {
        const filter = body.params[1] as { programId: string }
        if (filter.programId === CLASSIC_TOKEN_PROGRAM_ID) {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              value: [
                { pubkey: usdcAta, account: { owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 15_000_000n)), 'base64'] } },
              ],
            },
          })
        }
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [] } })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x6b)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        if (addrs.includes(USDC_MINT)) {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: { context: { slot: 6000 }, value: addrs.map(() => ({ data: [toBase64(makeClassicMintBytes(6)), 'base64'], lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID })) },
          })
        }
        const idx = refillPreCalls++
        if (idx > 0) {
          refillConcurrent++
          refillMaxConcurrent = Math.max(refillMaxConcurrent, refillConcurrent)
          await new Promise((r) => setTimeout(r, 15))
          refillConcurrent--
        }
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: refillPreSlots[idx] ?? 6006 },
            value: addrs.map((a) =>
              a === relayerB58
                ? { data: ['', 'base64'], lamports: 20_000_000, owner: SYSTEM_PROGRAM_ID }
                : a === wsolAta
                  ? { data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n)), 'base64'], lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }
                  : a === usdcAta
                    ? { data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 15_000_000n)), 'base64'], lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }
                    : null,
            ),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        const idx = refillSimCalls++
        if (idx > 0) {
          refillConcurrent++
          refillMaxConcurrent = Math.max(refillMaxConcurrent, refillConcurrent)
          await new Promise((r) => setTimeout(r, 15))
          refillConcurrent--
        }
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: refillSimSlots[idx] ?? 6006 },
            value: {
              err: null,
              logs: ['Refill Swap OK'],
              unitsConsumed: 180_000,
              accounts: [
                { lamports: 117_975_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n)), 'base64'] },
                { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 0n)), 'base64'] },
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        refillSendCalls++
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5R3R4RefillParallelPinSig1111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 6007, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R3-R4 refill test: ${url} ${body.method}`)
    },
    () => runAutoRefill(refillEnv, refillCfg),
  )
  assert.equal(refillReport.action, 'swapped_fees')
  assert.equal(refillPreCalls, 4)
  assert.equal(refillSimCalls, 4)
  assert.equal(refillMaxConcurrent, 2, 'refillSinglePayer retries MUST run getMultipleAccounts & simulateTransaction in parallel')
  assert.equal(refillSendCalls, 1)
})

test('R3-W5: canonical Circle Mainnet EURC mint address is configured in DEFAULT_SELF_PAY_FEE_MINTS and TRUSTED_FREEZE_AUTHORITY_MINTS', () => {
  const CANONICAL_EURC_MINT = 'HzwqbKZw8HxMN6bF2yFZNrht3c2iXXzpKcFu7uBEDKtr'
  const CORRUPTED_EURC_MINT = 'HzwqbKZw8HxMN6bF2yFZNrht3c2iXXdi3ragP28x6W36'

  assert.ok(DEFAULT_SELF_PAY_FEE_MINTS.includes(CANONICAL_EURC_MINT))
  assert.equal(DEFAULT_SELF_PAY_FEE_MINTS.includes(CORRUPTED_EURC_MINT), false)

  assert.ok(TRUSTED_FREEZE_AUTHORITY_MINTS.has(CANONICAL_EURC_MINT))
  assert.equal(TRUSTED_FREEZE_AUTHORITY_MINTS.has(CORRUPTED_EURC_MINT), false)

  // Canonical EURC carrying Circle's FreezeAuthority MUST be accepted as safe for self-pay
  const eurcWithFreeze = makeClassicMintWithFreeze(6, 0x33)
  const eurcSafety = parseMintSafetyInfo(CANONICAL_EURC_MINT, CLASSIC_TOKEN_PROGRAM_ID, eurcWithFreeze)
  assert.equal(eurcSafety.safeForSelfPay, true)
  assert.equal(eurcSafety.hasFreezeAuthority, true)
  assert.equal(eurcSafety.hasUntrustedFreezeAuthority, false)

  // Corrupted mint address MUST NOT be trusted
  const corruptedSafety = parseMintSafetyInfo(CORRUPTED_EURC_MINT, CLASSIC_TOKEN_PROGRAM_ID, eurcWithFreeze)
  assert.equal(corruptedSafety.safeForSelfPay, false)
  assert.equal(corruptedSafety.hasUntrustedFreezeAuthority, true)
})

test('R4-R1: cold isolate fetches live 5,080 lamports/byte rent in handleRelaySubmit (2-ix batch passes isSelfPaying) and already-initialized page contributes 0n to openPageDeficitFloor', async () => {
  const worker = await getWorker()
  const mockRpc = 'https://mock-rpc.local/r4r1-cold-isolate'
  const mockJup = 'https://mock-jup-r4r1.local'
  const poolPda = derivePoolPdaSync(0).address
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const sub0Pda = deriveSubtreePdaSync(0, 0, 0n).address
  const root0Pda = deriveSubrootPdaSync(0, 0, 0n).address
  const memo0Pda = deriveMemoPdaSync(0, 0, 0n).address
  const nf0PagePda = deriveNfPagePdaSync(0, 0, 0n).address
  const memo1Pda = deriveMemoPdaSync(0, 0, 1n).address
  const dummyPageBytes = new Uint8Array(64).fill(0x41)
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n })

  // Simulated post-SIMD-0194 cluster at 5,080 lamports/byte (vs stale hardcoded 6,960 lamports/byte)
  const rentAt5080 = (dataLen: number): number => (dataLen + 128) * 5_080

  const fvkJson = JSON.stringify({
    spendPkHex: toHex(relayerFvk.spendPk),
    nkHex: toHex(relayerFvk.nk),
    viewSkHex: toHex(relayerFvk.viewSk),
    viewPkHex: toHex(relayerFvk.viewPk),
  })
  const guard = createMockGuard()
  const env = {
    RELAY_GUARD: guard.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    MAINNET_RELAYER_FVK_JSON: fvkJson,
    JUPITER_API_URL: mockJup,
    SELF_PAY_MARGIN_BPS: '11000',
    SPONSORED_COOLDOWN_SEC_MAINNET: '0',
  } as Env

  let rentRpcCalls = 0
  let scenario: 'batch' | 'concurrent_page' = 'batch'
  let concurrentPreCalls = 0
  let concurrentSimCalls = 0

  await withMockFetch(
    async (url, init) => {
      if (url.startsWith(`${mockJup}/price/v3`)) {
        return Response.json({ [WSOL_MINT]: { usdPrice: 150 } })
      }
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        rentRpcCalls++
        return Response.json({ jsonrpc: '2.0', id: 1, result: rentAt5080(Number(body.params[0])) })
      }
      if (body.method === 'getAccountInfo' && body.params[0] === poolPda) {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { data: [toBase64(poolBytes), 'base64'], lamports: 2_000_000, owner: AUDREN_PROGRAM_ID } },
        })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x71)) } },
        })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        if (scenario === 'batch') {
          const map = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
            [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
            [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
            [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 1n, nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
            [lane0RentVault, { bytes: new Uint8Array(16), lamports: 20_000_000, owner: AUDREN_PROGRAM_ID }],
            [sub0Pda, { bytes: dummyPageBytes, lamports: rentAt5080(SUBTREE_PAGE_LEN), owner: AUDREN_PROGRAM_ID }],
            [root0Pda, { bytes: dummyPageBytes, lamports: rentAt5080(SUBROOT_PAGE_LEN), owner: AUDREN_PROGRAM_ID }],
            [memo0Pda, { bytes: dummyPageBytes, lamports: rentAt5080(MEMO_PAGE_LEN), owner: AUDREN_PROGRAM_ID }],
            [nf0PagePda, { bytes: dummyPageBytes, lamports: rentAt5080(NF_PAGE_LEN), owner: AUDREN_PROGRAM_ID }],
          ])
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 7000 },
              value: addrs.map((a) => {
                const hit = map.get(a)
                return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
              }),
            },
          })
        }
        // `concurrent_page`: initial fetch (slot 7100) sees memo1Pda missing & LaneRentVault empty (0 lamports);
        // slot-pin retry (slot 7101) sees memo1Pda ALREADY initialized by a concurrent tx!
        const callIdx = concurrentPreCalls++
        const slot = callIdx === 0 ? 7100 : 7101
        const map = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
          [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
          [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
          [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: BigInt(MEMO_NOTES_PER_PAGE - 1), nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
          [lane0RentVault, { bytes: new Uint8Array(16), lamports: 0, owner: AUDREN_PROGRAM_ID }],
          [sub0Pda, { bytes: dummyPageBytes, lamports: rentAt5080(SUBTREE_PAGE_LEN), owner: AUDREN_PROGRAM_ID }],
          [root0Pda, { bytes: dummyPageBytes, lamports: rentAt5080(SUBROOT_PAGE_LEN), owner: AUDREN_PROGRAM_ID }],
          [memo0Pda, { bytes: dummyPageBytes, lamports: rentAt5080(MEMO_PAGE_LEN), owner: AUDREN_PROGRAM_ID }],
          [nf0PagePda, { bytes: dummyPageBytes, lamports: rentAt5080(NF_PAGE_LEN), owner: AUDREN_PROGRAM_ID }],
          ...(callIdx > 0
            ? [[memo1Pda, { bytes: dummyPageBytes, lamports: 1_000_000, owner: AUDREN_PROGRAM_ID }] as const]
            : []),
        ])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot },
            value: addrs.map((a) => {
              const hit = map.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        if (scenario === 'batch') {
          // Simulate a concurrent SOL inflow so `minExpectedCostLamports` drives `simulatedCostLamports`
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 7000 },
              value: {
                err: null,
                logs: ['Batch OK'],
                unitsConsumed: 320_000,
                accounts: [{ lamports: 600_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }],
              },
            },
          })
        }
        const simIdx = concurrentSimCalls++
        const slot = simIdx === 0 ? 7101 : 7101
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot },
            value: {
              err: null,
              logs: ['Idempotent OpenPage OK', 'Transact OK'],
              unitsConsumed: 180_000,
              accounts: [
                { lamports: 600_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                { lamports: 0, owner: AUDREN_PROGRAM_ID, data: [toBase64(new Uint8Array(16)), 'base64'] },
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5R4R1ColdIsolateLiveRentSig11111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 7002, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R4-R1 test: ${body.method}`)
    },
    async () => {
      // Part A: Warm isolate quotes 2-output transfer at live 5,080 lamports/byte
      const quoteRes = await worker.fetch(
        new Request(`https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=transfer&mint=${WSOL_MINT}&outputCount=2`),
        env,
      )
      assert.equal(quoteRes.status, 200)
      const q = (await quoteRes.json()) as { billingMode: string; relayerFee: string; estimatedRelayCostLamports: string; feeDecimals: number }
      assert.equal(q.billingMode, 'self_paying')
      assert.equal(q.feeDecimals, 9)
      const perIxFee = BigInt(q.relayerFee)
      const expectedSingleCost5080 = BigInt(q.estimatedRelayCostLamports)
      assert.ok(expectedSingleCost5080 < 3_500_000n, `Expected 5,080 rent single-ix cost < 3.5M, got ${expectedSingleCost5080}`)

      // Build 2-ix private merge batch where each ix carries its warm-quoted cm2 fee (total 2 * perIxFee)
      const cm2a = makeShieldedFeeCm2(perIxFee, wsolMintBytes, 0x91)
      const cm2b = makeShieldedFeeCm2(perIxFee, wsolMintBytes, 0x92)
      const batchIxA = buildTransactInstruction({
        payer: relayerB58,
        poolId: 0,
        rootRingKind: ROOT_RING_EPOCH,
        rootRingIdx: 0,
        outLaneId: 0,
        outSubSeq: 0n,
        outRootSeq: 0n,
        outMemoSeq: 0n,
        outNfSeq: 0n,
        outputMask: 0b101,
        assetMode: ASSET_MODE_PRIVATE,
        proof192: dummyProof,
        nf0: new Uint8Array(32).fill(0xa1),
        nf1: new Uint8Array(32).fill(0xa2),
        cm0: new Uint8Array(32).fill(0x11),
        cm1: new Uint8Array(32),
        cm2: cm2a.cm2,
        publicAmountOut: 0n,
        relayerFeeAmount: 0n,
        memosBytes: new Uint8Array([...new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x11), ...cm2a.memo]),
      })
      const batchIxB = buildTransactInstruction({
        payer: relayerB58,
        poolId: 0,
        rootRingKind: ROOT_RING_EPOCH,
        rootRingIdx: 0,
        outLaneId: 0,
        outSubSeq: 0n,
        outRootSeq: 0n,
        outMemoSeq: 0n,
        outNfSeq: 0n,
        outputMask: 0b101,
        assetMode: ASSET_MODE_PRIVATE,
        proof192: dummyProof,
        nf0: new Uint8Array(32).fill(0xa3),
        nf1: new Uint8Array(32).fill(0xa4),
        cm0: new Uint8Array(32).fill(0x22),
        cm1: new Uint8Array(32),
        cm2: cm2b.cm2,
        publicAmountOut: 0n,
        relayerFeeAmount: 0n,
        memosBytes: new Uint8Array([...new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x22), ...cm2b.memo]),
      })

      // Clear RENT_CACHE to simulate a cold Worker isolate!
      clearLiveRentScheduleCache()
      const rentCallsBeforeColdSubmit = rentRpcCalls

      const coldSubRes = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructions: [
              { instructionDataB64: toBase64(batchIxA.data), accounts: batchIxA.accounts },
              { instructionDataB64: toBase64(batchIxB.data), accounts: batchIxB.accounts },
            ],
            priorityFeeLamports: '15000',
          }),
        }),
        env,
      )
      assert.equal(coldSubRes.status, 200, 'Cold isolate MUST fetch live 5,080 rent so warm 2-ix batch passes isSelfPaying without false 402')
      const coldSub = (await coldSubRes.json()) as { billingMode: string; netSponsoredLamports: string; simulatedCostLamports: string }
      assert.equal(coldSub.billingMode, 'self_paying')
      assert.equal(coldSub.netSponsoredLamports, '0')
      assert.ok(rentRpcCalls > rentCallsBeforeColdSubmit, 'Cold isolate submit must fetch live SysvarRent')
      // Exact 2-ix batch cost at 5,080 lamports/byte: 2 * (expectedSingleCost5080 - 20_000n) + 20_000n
      const expectedBatchCost5080 = 2n * (expectedSingleCost5080 - 20_000n) + 20_000n
      assert.equal(BigInt(coldSub.simulatedCostLamports), expectedBatchCost5080)

      // Part B: Warm isolate does 0 extra rent RPCs AND concurrently initialized AUDREN page in openPageDeficitFloor contributes 0n!
      const rentCallsBeforeWarmSubmit = rentRpcCalls
      scenario = 'concurrent_page'
      const cm2c = makeShieldedFeeCm2(perIxFee, wsolMintBytes, 0x93)
      const rolloverIx = buildTransactInstruction({
        payer: relayerB58,
        poolId: 0,
        rootRingKind: ROOT_RING_EPOCH,
        rootRingIdx: 0,
        outLaneId: 0,
        outSubSeq: 0n,
        outRootSeq: 0n,
        outMemoSeq: 0n,
        outNfSeq: 0n,
        outputMask: 0b101,
        assetMode: ASSET_MODE_PRIVATE,
        rollover: { nextMemoSeq: 1n },
        proof192: dummyProof,
        nf0: new Uint8Array(32).fill(0xa5),
        nf1: new Uint8Array(32).fill(0xa6),
        cm0: new Uint8Array(32).fill(0x33),
        cm1: new Uint8Array(32),
        cm2: cm2c.cm2,
        publicAmountOut: 0n,
        relayerFeeAmount: 0n,
        memosBytes: new Uint8Array([...new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x33), ...cm2c.memo]),
      })
      const concRes = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(rolloverIx.data),
            accounts: rolloverIx.accounts,
            priorityFeeLamports: '15000',
          }),
        }),
        env,
      )
      assert.equal(concRes.status, 200)
      const concBody = (await concRes.json()) as { billingMode: string; simulatedCostLamports: string }
      assert.equal(rentRpcCalls, rentCallsBeforeWarmSubmit, 'Warm RENT_CACHE must incur 0 extra rent RPCs on submit')
      assert.equal(BigInt(concBody.simulatedCostLamports), expectedSingleCost5080, 'Concurrently initialized AUDREN page MUST contribute 0n deficit to openPageDeficitFloor')
      assert.equal(concBody.billingMode, 'self_paying')
    },
  )
})

test('R4-R2: /v1/fee-quote extraAtaMints (170B / 182B / 187B), Token-2022 non-fee ATA extension rent sizing, feeDecimals, and /v1/swap/quote exact ataByteLen', async () => {
  // Helper to construct Token-2022 mint bytes with arbitrary TLV extensions
  const makeT22MultiExtMint = (
    decimals: number,
    exts: Array<{ type: number; payload: Uint8Array }>,
  ): Uint8Array => {
    const tlvLen = exts.reduce((acc, e) => acc + 4 + e.payload.byteLength, 0)
    const buf = new Uint8Array(166 + tlvLen)
    buf[44] = decimals
    buf[45] = 1
    buf[165] = 1 // AccountType::Mint
    const dv = new DataView(buf.buffer)
    let pos = 166
    for (const e of exts) {
      dv.setUint16(pos, e.type, true)
      dv.setUint16(pos + 2, e.payload.byteLength, true)
      buf.set(e.payload, pos + 4)
      pos += 4 + e.payload.byteLength
    }
    return buf
  }

  const tf100Payload = new Uint8Array(108)
  {
    const dv = new DataView(tf100Payload.buffer)
    dv.setBigUint64(72, 0n, true)
    dv.setBigUint64(80, 10_000_000n, true)
    dv.setUint16(88, 100, true)
    dv.setBigUint64(90, 0n, true)
    dv.setBigUint64(98, 10_000_000n, true)
    dv.setUint16(106, 100, true)
  }
  const disabledHookPayload = new Uint8Array(64) // authority=0, program_id=0 (permanently disabled, safe for self-pay!)
  const permDelegatePayload = new Uint8Array(32).fill(0x55)
  const pausablePayload = new Uint8Array(33)

  const classicBytes = makeClassicMintBytes(9)
  const t22BareBytes = makeClassicMintBytes(8) // 82 B bare Token-2022 mint -> 170 B ATA
  const t22Fee182Bytes = makeT22MultiExtMint(6, [{ type: 1, payload: tf100Payload }]) // 182 B ATA
  const t22Pyusd175Bytes = makeT22MultiExtMint(6, [
    { type: 12, payload: permDelegatePayload }, // PermanentDelegate (+0 B)
    { type: 14, payload: disabledHookPayload }, // TransferHook (+5 B -> 175 B)
  ])
  const t22FeeHook187Bytes = makeT22MultiExtMint(6, [
    { type: 1, payload: tf100Payload }, // TransferFeeConfig (+12 B)
    { type: 14, payload: disabledHookPayload }, // TransferHook (+5 B -> 187 B)
  ])
  const t22Pausable174Bytes = makeT22MultiExtMint(6, [{ type: 26, payload: pausablePayload }])
  const t22NonTrans174Bytes = makeT22MultiExtMint(6, [{ type: 9, payload: new Uint8Array(0) }])
  const t22All195Bytes = makeT22MultiExtMint(6, [
    { type: 1, payload: tf100Payload },
    { type: 9, payload: new Uint8Array(0) },
    { type: 14, payload: disabledHookPayload },
    { type: 26, payload: pausablePayload },
  ])

  // 1. Pure unit checks for computeToken2022AtaByteLen & estimateAtaRentLamports
  assert.equal(computeToken2022AtaByteLen(CLASSIC_TOKEN_PROGRAM_ID, classicBytes), 165)
  assert.equal(computeToken2022AtaByteLen(TOKEN_2022_PROGRAM_ID, t22BareBytes), 170)
  assert.equal(computeToken2022AtaByteLen(TOKEN_2022_PROGRAM_ID, t22Pausable174Bytes), 174)
  assert.equal(computeToken2022AtaByteLen(TOKEN_2022_PROGRAM_ID, t22NonTrans174Bytes), 174)
  assert.equal(computeToken2022AtaByteLen(TOKEN_2022_PROGRAM_ID, t22Pyusd175Bytes), 175)
  assert.equal(computeToken2022AtaByteLen(TOKEN_2022_PROGRAM_ID, t22Fee182Bytes), 182)
  assert.equal(computeToken2022AtaByteLen(TOKEN_2022_PROGRAM_ID, t22FeeHook187Bytes), 187)
  assert.equal(computeToken2022AtaByteLen(TOKEN_2022_PROGRAM_ID, t22All195Bytes), 195)

  assert.equal(estimateAtaRentLamports(2_039_280n, CLASSIC_TOKEN_PROGRAM_ID, 165), 2_039_280n)
  assert.equal(estimateAtaRentLamports(2_039_280n, TOKEN_2022_PROGRAM_ID, 170), 2_074_080n)
  assert.equal(estimateAtaRentLamports(2_039_280n, TOKEN_2022_PROGRAM_ID, 174), 2_101_920n)
  assert.equal(estimateAtaRentLamports(2_039_280n, TOKEN_2022_PROGRAM_ID, 175), 2_108_880n)
  assert.equal(estimateAtaRentLamports(2_039_280n, TOKEN_2022_PROGRAM_ID, 182), 2_157_600n)
  assert.equal(estimateAtaRentLamports(2_039_280n, TOKEN_2022_PROGRAM_ID, 187), 2_192_400n)
  assert.equal(estimateAtaRentLamports(2_039_280n, TOKEN_2022_PROGRAM_ID, 195), 2_248_080n)

  // 2. End-to-end HTTP `/v1/fee-quote` + `/v1/relay/submit` + `/v1/swap/quote`
  const worker = await getWorker()
  const mockRpc = 'https://mock-rpc.local/r4r2-extra-ata-mints'
  const mockJup = 'https://mock-jup-r4r2.local'
  const poolPda = derivePoolPdaSync(0).address
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const escrow1 = deriveEscrowPdaSync(0, 1).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n })
  const dummyPageBytes = new Uint8Array(64).fill(0x42)

  const mint170 = base58Encode(new Uint8Array(32).fill(0xf1))
  const mint182 = base58Encode(new Uint8Array(32).fill(0xf2))
  const mint187 = base58Encode(new Uint8Array(32).fill(0xf3))
  const mintPyusd175 = base58Encode(new Uint8Array(32).fill(0xf4))
  const nonMintPubkey = base58Encode(new Uint8Array(32).fill(0xf5))

  const relayerWsolAta = deriveAssociatedTokenAddressSync(relayerB58, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultWsolAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowWsolAta = deriveAssociatedTokenAddressSync(escrow1, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address

  const guard = createMockGuard()
  const env = {
    RELAY_GUARD: guard.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    JUPITER_API_URL: mockJup,
    SELF_PAY_FEE_MINTS: `${WSOL_MINT},${mint170},${mint182},${mint187}`,
    SELF_PAY_MARGIN_BPS: '11000',
    ALLOW_MICRO_SWAP_SUBSIDY: 'false',
  } as Env

  let simFeeUnits = 0n
  await withMockFetch(
    async (url, init) => {
      if (url.startsWith(`${mockJup}/price/v3`)) {
        return Response.json({
          [WSOL_MINT]: { usdPrice: 150 },
          [mint170]: { usdPrice: 1 },
          [mint182]: { usdPrice: 1 },
          [mint187]: { usdPrice: 1 },
          [mintPyusd175]: { usdPrice: 1 },
        })
      }
      if (url.startsWith(`${mockJup}/swap/v1/quote`)) {
        return Response.json({
          inputMint: WSOL_MINT,
          outputMint: mintPyusd175,
          inAmount: '5000000000',
          outAmount: '750000000',
          otherAmountThreshold: '740000000',
          slippageBps: 100,
          routePlan: [{ swapInfo: { label: 'Orca Whirlpool', inputMint: WSOL_MINT, outputMint: mintPyusd175, inAmount: '5000000000', outAmount: '750000000' }, percent: 100 }],
        })
      }
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getEpochInfo') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { epoch: 500 } })
      }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        const map: Record<number, number> = {
          0: 890_880,
          16: 1_002_240,
          165: 2_039_280,
          [SUBTREE_PAGE_LEN]: 58_340_000,
          [SUBROOT_PAGE_LEN]: 68_140_000,
          [MEMO_PAGE_LEN]: 72_149_760,
          [NF_PAGE_LEN]: 68_140_000,
        }
        return Response.json({ jsonrpc: '2.0', id: 1, result: map[len] ?? 1_000_000 })
      }
      if (body.method === 'getAccountInfo' && body.params[0] === poolPda) {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { data: [toBase64(poolBytes), 'base64'], lamports: 2_000_000, owner: AUDREN_PROGRAM_ID } } })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x72)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        const map = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
          [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
          [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
          [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 1n, nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
          [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
          [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
          [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_149_760, owner: AUDREN_PROGRAM_ID }],
          [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
          [WSOL_MINT, { bytes: classicBytes, lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID }],
          [mint170, { bytes: t22BareBytes, lamports: 2_000_000, owner: TOKEN_2022_PROGRAM_ID }],
          [mint182, { bytes: t22Fee182Bytes, lamports: 2_000_000, owner: TOKEN_2022_PROGRAM_ID }],
          [mint187, { bytes: t22FeeHook187Bytes, lamports: 2_000_000, owner: TOKEN_2022_PROGRAM_ID }],
          [mintPyusd175, { bytes: t22Pyusd175Bytes, lamports: 2_000_000, owner: TOKEN_2022_PROGRAM_ID }],
          [relayerWsolAta, { bytes: makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n), lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }],
          [vaultWsolAta, { bytes: makeTokenAccountBytes(WSOL_MINT, vaultAuth, 0n), lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }],
          [escrowWsolAta, { bytes: makeTokenAccountBytes(WSOL_MINT, escrow1, 0n), lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }],
        ])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 7200 },
            value: addrs.map((a) => {
              const hit = map.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 7200 },
            value: {
              err: null,
              logs: ['Exec OK'],
              unitsConsumed: 180_000,
              accounts: [
                // Concurrent SOL inflow forces setupAtaDeficitFloor to drive simulatedCostLamports
                { lamports: 600_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, simFeeUnits)), 'base64'] },
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5R4R2ExtraAtaMintsExactParitySig111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 7201, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R4-R2 test: ${body.method}`)
    },
    async () => {
      const sched = await fetchLiveRentSchedule(mockRpc)
      const baseExec1Out =
        2n * (sched.nullifierRentLamports + sched.nfPageRentPerNfLamports) +
        sched.pageRentPerNoteLamports +
        20_000n

      // Validation errors -> 400
      const badInvalid = await worker.fetch(
        new Request(`https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=exec_escrow&mint=${WSOL_MINT}&amount=500000000&extraAtaMints=not-a-pubkey`),
        env,
      )
      assert.equal(badInvalid.status, 400)

      const badTrailingComma = await worker.fetch(
        new Request(`https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=exec_escrow&mint=${WSOL_MINT}&amount=500000000&extraAtaMints=${mint170},`),
        env,
      )
      assert.equal(badTrailingComma.status, 400)

      const sevenMints = Array(7).fill(WSOL_MINT).join(',')
      const badTooMany = await worker.fetch(
        new Request(`https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=exec_escrow&mint=${WSOL_MINT}&amount=500000000&extraAtaMints=${sevenMints}`),
        env,
      )
      assert.equal(badTooMany.status, 400)

      const badNonMint = await worker.fetch(
        new Request(`https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=exec_escrow&mint=${WSOL_MINT}&amount=500000000&extraAtaMints=${nonMintPubkey}`),
        env,
      )
      assert.equal(badNonMint.status, 400)

      // 8-decimal mint returns `feeDecimals: 8`
      const dec8Res = await worker.fetch(
        new Request(`https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=withdraw&mint=${mint170}&amount=5000000000`),
        env,
      )
      assert.equal(dec8Res.status, 200)
      const dec8 = (await dec8Res.json()) as { feeDecimals: number; billingMode: string }
      assert.equal(dec8.feeDecimals, 8)
      assert.equal(dec8.billingMode, 'self_paying')

      // Cross-program /v1/fee-quote?op=exec_escrow&mint=WSOL&missingAtaCount=1&extraAtaMints=<170B|182B|187B>
      const cases = [
        { mint: mint170, expectedAtaRent: 2_074_080n, label: '170 B bare Token-2022' },
        { mint: mint182, expectedAtaRent: 2_157_600n, label: '182 B TransferFeeConfig' },
        { mint: mint187, expectedAtaRent: 2_192_400n, label: '187 B TransferFeeConfig + TransferHook' },
      ]
      let quote187Fee = 0n
      let quote187Cost = 0n
      for (const c of cases) {
        const res = await worker.fetch(
          new Request(
            `https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=exec_escrow&mint=${WSOL_MINT}&amount=500000000&outputCount=1&missingAtaCount=1&extraAtaMints=${c.mint}`,
          ),
          env,
        )
        assert.equal(res.status, 200)
        const q = (await res.json()) as {
          billingMode: string
          feeDecimals: number
          relayerFee: string
          estimatedRelayCostLamports: string
        }
        assert.equal(q.billingMode, 'self_paying')
        assert.equal(q.feeDecimals, 9)
        assert.equal(
          BigInt(q.estimatedRelayCostLamports),
          baseExec1Out + c.expectedAtaRent,
          `Exact extraAtaMints rent mismatch for ${c.label}`,
        )
        if (c.mint === mint187) {
          quote187Fee = BigInt(q.relayerFee)
          quote187Cost = BigInt(q.estimatedRelayCostLamports)
        }
      }

      // missingAtaCount (2) > extraAtaMints.length (1) -> adds 1 * feeMint ATA rent (2_039_280n) for remainder
      const remRes = await worker.fetch(
        new Request(
          `https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=exec_escrow&mint=${WSOL_MINT}&amount=500000000&outputCount=1&missingAtaCount=2&extraAtaMints=${mint187}`,
        ),
        env,
      )
      assert.equal(remRes.status, 200)
      const remQ = (await remRes.json()) as { estimatedRelayCostLamports: string }
      assert.equal(BigInt(remQ.estimatedRelayCostLamports), baseExec1Out + 2_192_400n + 2_039_280n)

      // Exact submit parity for WSOL-fee ExecViaEscrow creating missing 187 B Token-2022 output ATA (no false 402!)
      const execIx = buildTestExecSwapIx({
        payerB58: relayerB58,
        routerProg: JUPITER_V6_ROUTER,
        feeAta: relayerWsolAta,
        feeAtaWritable: false,
        relayerFeeAmount: quote187Fee,
        feeOnOutput: false,
        outMint: mint187,
        outTokenProg: TOKEN_2022_PROGRAM_ID,
        feeRecipient: relayerWsolAta,
        nf0Seed: 0xe7,
      })
      simFeeUnits = quote187Fee
      const subRes = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(execIx.data),
            accounts: execIx.accounts,
            setupAtas: [{ owner: escrow1, mint: mint187, tokenProgram: TOKEN_2022_PROGRAM_ID }],
            priorityFeeLamports: '15000',
          }),
        }),
        env,
      )
      assert.equal(subRes.status, 200, 'Cross-program /v1/fee-quote with extraAtaMints=187B T22 MUST pass isSelfPaying without 402')
      const sub = (await subRes.json()) as { billingMode: string; simulatedCostLamports: string; netSponsoredLamports: string }
      assert.equal(sub.billingMode, 'self_paying')
      assert.equal(sub.netSponsoredLamports, '0')
      assert.equal(BigInt(sub.simulatedCostLamports), quote187Cost)

      // /v1/swap/quote uses exact per-mint 175 B ATA rent for PYUSD-like (PermanentDelegate + TransferHook) mint!
      const pyusdSwapRes = await worker.fetch(
        new Request(
          `https://relay.audren.xyz/v1/swap/quote?cluster=mainnet&provider=jupiter&inputMint=${WSOL_MINT}&outputMint=${mintPyusd175}&amount=5000000000&shardId=1`,
        ),
        env,
      )
      assert.equal(pyusdSwapRes.status, 200)
      const pyusdSwap = (await pyusdSwapRes.json()) as {
        feePlan: { estimatedRelayCostLamports: string }
        mints: { output: { safety?: { ataByteLen?: number } } }
      }
      assert.equal(pyusdSwap.mints.output.safety?.ataByteLen, 175)
      // Missing ATAs: vaultOut + escrowOut (2 * 175 B = 2 * 2_108_880n; sponsored because PermanentDelegate)
      assert.equal(BigInt(pyusdSwap.feePlan.estimatedRelayCostLamports), sched.swapBaselineLamports + 2n * 2_108_880n)
    },
  )
})

test('R4-W1: /v1/swap/quote returns outputTransferFee ({ bps, maxFee } | null) for Token-2022 TransferFeeConfig and non-fee output mints', async () => {
  const worker = await getWorker()
  const mockRpc = 'https://mock-rpc.local/r4w1-output-transfer-fee'
  const mockJup = 'https://mock-jup-r4w1.local'
  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n })

  const t22FeeMint = base58Encode(new Uint8Array(32).fill(0xc1))
  const t22BareMint = base58Encode(new Uint8Array(32).fill(0xc2))
  const t22FeeBytes = makeToken2022TransferFeeMintBytes({
    decimals: 6,
    olderEpoch: 10n,
    olderMaxFee: 500_000n,
    olderBps: 100,
    newerEpoch: 500n,
    newerMaxFee: 7_500_000n,
    newerBps: 250,
  })
  const t22BareBytes = makeClassicMintBytes(6)
  const classicWsolBytes = makeClassicMintBytes(9)
  const classicUsdcBytes = makeClassicMintBytes(6)

  const guard = createMockGuard()
  const env = {
    RELAY_GUARD: guard.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    JUPITER_API_URL: mockJup,
  } as Env

  await withMockFetch(
    async (url, init) => {
      if (url.startsWith(`${mockJup}/price/v3`)) {
        return Response.json({
          [WSOL_MINT]: { usdPrice: 150 },
          [USDC_MINT]: { usdPrice: 1 },
          [t22FeeMint]: { usdPrice: 1 },
          [t22BareMint]: { usdPrice: 1 },
        })
      }
      if (url.startsWith(`${mockJup}/swap/v1/quote`)) {
        const u = new URL(url)
        const inAmt = u.searchParams.get('amount') ?? '1000000'
        return Response.json({
          inputMint: u.searchParams.get('inputMint'),
          outputMint: u.searchParams.get('outputMint'),
          inAmount: inAmt,
          outAmount: '500000000',
          otherAmountThreshold: '495000000',
          slippageBps: 100,
          routePlan: [{ swapInfo: { label: 'Raydium CLMM', inputMint: u.searchParams.get('inputMint'), outputMint: u.searchParams.get('outputMint'), inAmount: inAmt, outAmount: '500000000' }, percent: 100 }],
        })
      }
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getEpochInfo') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { epoch: 512 } })
      }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: 2_039_280 })
      }
      if (body.method === 'getAccountInfo' && body.params[0] === poolPda) {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { data: [toBase64(poolBytes), 'base64'], lamports: 2_000_000, owner: AUDREN_PROGRAM_ID } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: addrs.map((a) => {
              if (a === t22FeeMint) return { data: [toBase64(t22FeeBytes), 'base64'], lamports: 2_000_000, owner: TOKEN_2022_PROGRAM_ID }
              if (a === t22BareMint) return { data: [toBase64(t22BareBytes), 'base64'], lamports: 2_000_000, owner: TOKEN_2022_PROGRAM_ID }
              if (a === WSOL_MINT) return { data: [toBase64(classicWsolBytes), 'base64'], lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID }
              if (a === USDC_MINT) return { data: [toBase64(classicUsdcBytes), 'base64'], lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID }
              return null
            }),
          },
        })
      }
      throw new Error(`Unexpected RPC in R4-W1 test: ${body.method}`)
    },
    async () => {
      // 1. Token-2022 TransferFeeConfig output mint -> outputTransferFee: { bps: 250, maxFee: '7500000' }
      const outFeeRes = await worker.fetch(
        new Request(
          `https://relay.audren.xyz/v1/swap/quote?cluster=mainnet&provider=jupiter&inputMint=${WSOL_MINT}&outputMint=${t22FeeMint}&amount=5000000000&shardId=1`,
        ),
        env,
      )
      assert.equal(outFeeRes.status, 200)
      const outFeeBody = (await outFeeRes.json()) as {
        inputTransferFee: { bps: number; maxFee: string } | null
        outputTransferFee: { bps: number; maxFee: string } | null
      }
      assert.equal(outFeeBody.inputTransferFee, null)
      assert.deepEqual(outFeeBody.outputTransferFee, { bps: 250, maxFee: '7500000' })

      // 2. Classic SPL output mint (with T22 TransferFeeConfig input mint) -> outputTransferFee: null, inputTransferFee populated
      const classicOutRes = await worker.fetch(
        new Request(
          `https://relay.audren.xyz/v1/swap/quote?cluster=mainnet&provider=jupiter&inputMint=${t22FeeMint}&outputMint=${USDC_MINT}&amount=50000000&shardId=1`,
        ),
        env,
      )
      assert.equal(classicOutRes.status, 200)
      const classicOutBody = (await classicOutRes.json()) as {
        inputTransferFee: { bps: number; maxFee: string } | null
        outputTransferFee: { bps: number; maxFee: string } | null
      }
      assert.deepEqual(classicOutBody.inputTransferFee, { bps: 250, maxFee: '7500000' })
      assert.equal(classicOutBody.outputTransferFee, null)

      // 3. Bare Token-2022 output mint (no TransferFeeConfig) -> outputTransferFee: null
      const bareOutRes = await worker.fetch(
        new Request(
          `https://relay.audren.xyz/v1/swap/quote?cluster=mainnet&provider=jupiter&inputMint=${WSOL_MINT}&outputMint=${t22BareMint}&amount=5000000000&shardId=1`,
        ),
        env,
      )
      assert.equal(bareOutRes.status, 200)
      const bareOutBody = (await bareOutRes.json()) as {
        outputTransferFee: { bps: number; maxFee: string } | null
      }
      assert.equal(bareOutBody.outputTransferFee, null)
    },
  )
})

test('R4-R3: refillSinglePayer computes 95% oracle minSolOutLamports floor on 1x net amount for 500-bps Token-2022 mint while quoting full gross balance', async () => {
  const mockRpc = 'https://mock-rpc.local/r4r3-refill-500bps'
  const mockJup = 'https://mock-jup-r4r3.local'
  const t22Mint500 = base58Encode(new Uint8Array(32).fill(0xb9))
  const t22Mint500Bytes = makeToken2022MutableTransferFeeMintBytes({
    decimals: 6,
    bps: 500, // 5% active immutable TransferFeeConfig
    mutableAuthority: false,
  })
  const wsolAta = deriveAssociatedTokenAddressSync(relayerB58, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const t22Ata = deriveAssociatedTokenAddressSync(relayerB58, t22Mint500, TOKEN_2022_PROGRAM_ID).address

  const refillEnv = {
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    JUPITER_API_URL: mockJup,
    SELF_PAY_FEE_MINTS: `${WSOL_MINT},${t22Mint500}`,
  } as Env
  const refillCfg = loadPolicyConfig(refillEnv)

  // Balance: 15_000_000 units ($15 gross at $1/token, SOL=$150 -> 100_000_000 lamports gross).
  // 1x 500-bps net = 14_250_000 units ($14.25 -> 95_000_000 lamports net).
  // 95% oracle floor on 1x net = 90_250_000 lamports (90.25% of gross).
  // Quote returns otherAmountThreshold = 93_555_000 (fails old 95M gross floor, passes new 90.25M net floor!).
  const quotedAmounts: string[] = []
  let epochCalls = 0
  let sendCalls = 0
  let mockOtherAmountThreshold = '93555000'

  const runScenario = () =>
    withMockFetch(
      async (url, init) => {
        if (url.startsWith(`${mockJup}/price/v3`)) {
          return Response.json({
            [WSOL_MINT]: { usdPrice: 150 },
            [t22Mint500]: { usdPrice: 1 },
          })
        }
        if (url.startsWith(`${mockJup}/swap/v1/quote`)) {
          const u = new URL(url)
          quotedAmounts.push(u.searchParams.get('amount') ?? '')
          return Response.json({
            inputMint: t22Mint500,
            outputMint: WSOL_MINT,
            inAmount: u.searchParams.get('amount') ?? '15000000',
            outAmount: '94500000',
            otherAmountThreshold: mockOtherAmountThreshold,
            slippageBps: 100,
            routePlan: [{ swapInfo: { label: 'Raydium CLMM', inputMint: t22Mint500, outputMint: WSOL_MINT, inAmount: '15000000', outAmount: '94500000' }, percent: 100 }],
          })
        }
        if (url.startsWith(`${mockJup}/swap/v1/swap-instructions`)) {
          return Response.json({
            swapInstruction: {
              programId: JUPITER_V6_ROUTER,
              accounts: [{ pubkey: relayerB58, isSigner: true, isWritable: true }],
              data: toBase64(new Uint8Array([4, 5, 6])),
            },
            addressLookupTableAddresses: [],
          })
        }
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getEpochInfo') {
          epochCalls++
          return Response.json({ jsonrpc: '2.0', id: 1, result: { epoch: 500 } })
        }
        if (body.method === 'getBalance') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: 20_000_000 } })
        }
        if (body.method === 'getTokenAccountsByOwner') {
          const filter = body.params[1] as { programId: string }
          if (filter.programId === TOKEN_2022_PROGRAM_ID) {
            return Response.json({
              jsonrpc: '2.0',
              id: 1,
              result: {
                value: [
                  {
                    pubkey: t22Ata,
                    account: {
                      owner: TOKEN_2022_PROGRAM_ID,
                      data: [toBase64(makeTokenAccountBytes(t22Mint500, relayerB58, 15_000_000n)), 'base64'],
                    },
                  },
                ],
              },
            })
          }
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [] } })
        }
        if (body.method === 'getLatestBlockhash') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x73)) } } })
        }
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          if (addrs.includes(t22Mint500)) {
            return Response.json({
              jsonrpc: '2.0',
              id: 1,
              result: {
                context: { slot: 8000 },
                value: addrs.map((a) =>
                  a === t22Mint500
                    ? { data: [toBase64(t22Mint500Bytes), 'base64'], lamports: 2_000_000, owner: TOKEN_2022_PROGRAM_ID }
                    : null,
                ),
              },
            })
          }
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 8000 },
              value: addrs.map((a) =>
                a === relayerB58
                  ? { data: ['', 'base64'], lamports: 20_000_000, owner: SYSTEM_PROGRAM_ID }
                  : a === wsolAta
                    ? { data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n)), 'base64'], lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }
                    : a === t22Ata
                      ? { data: [toBase64(makeTokenAccountBytes(t22Mint500, relayerB58, 15_000_000n)), 'base64'], lamports: 2_039_280, owner: TOKEN_2022_PROGRAM_ID }
                      : null,
              ),
            },
          })
        }
        if (body.method === 'simulateTransaction') {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 8000 },
              value: {
                err: null,
                logs: ['Refill 500bps T22 OK'],
                unitsConsumed: 180_000,
                accounts: [
                  // Net SOL gain = 94_475_000 lamports (>= 90_150_000 minNetLamports)
                  { lamports: 114_475_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                  { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n)), 'base64'] },
                  { lamports: 2_039_280, owner: TOKEN_2022_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(t22Mint500, relayerB58, 0n)), 'base64'] },
                ],
              },
            },
          })
        }
        if (body.method === 'sendTransaction') {
          sendCalls++
          return Response.json({ jsonrpc: '2.0', id: 1, result: '5R4R3Refill500BpsT22SuccessSig11111111111111' })
        }
        if (body.method === 'getSignatureStatuses') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 8001, err: null, confirmationStatus: 'confirmed' }] } })
        }
        throw new Error(`Unexpected RPC in R4-R3 test: ${url} ${body.method}`)
      },
      () => runAutoRefill(refillEnv, refillCfg),
    )

  // 1. Valid 500-bps Token-2022 quote (93.555M >= 90.25M net floor) succeeds and quotes full gross 15_000_000!
  const okReport = await runScenario()
  assert.equal(okReport.action, 'swapped_fees', `Expected 500-bps Token-2022 refill to succeed, got details: ${JSON.stringify(okReport.details)}`)
  assert.equal(okReport.signatures.length, 1)
  assert.equal(sendCalls, 1)
  assert.equal(epochCalls, 1)
  assert.ok(quotedAmounts.length >= 1 && quotedAmounts.every((a) => a === '15000000'), 'DEX quote MUST receive full gross balance')

  // 2. Manipulated quote below 90.25% net floor (89M < 90.25M) is STILL skipped cleanly!
  mockOtherAmountThreshold = '89000000'
  sendCalls = 0
  const skipReport = await runScenario()
  assert.equal(skipReport.action, 'no_fees_to_swap')
  assert.equal(sendCalls, 0)
  assert.ok(
    skipReport.details.some((d) => d.includes('90250000')),
    `Expected skip detail to report exact 90_250_000 net oracle floor, got ${JSON.stringify(skipReport.details)}`,
  )
})

test('R5-R1: fetchLiveRentSchedule honors decodedPool.noteRentFee === 0n governance override (yields 0n) and falls back to livePerNote only when PoolState is absent', async () => {
  clearLiveRentScheduleCache()
  const poolPda = derivePoolPdaSync(0).address
  const mockRpcZeroNote = 'https://mock-rpc.local/r5-r1-note-rent-zero'
  const mockRpcMissingPool = 'https://mock-rpc.local/r5-r1-missing-pool'
  const mockRpcCappedNote = 'https://mock-rpc.local/r5-r1-capped-note'

  const poolZeroNote = makePoolStateBytes({ noteRentFee: 0n, nfRentFee: 0n })
  const poolCappedNote = makePoolStateBytes({ noteRentFee: 500_000n, nfRentFee: 80_000n })

  const rentMap: Record<number, number> = {
    0: 890_880,
    16: 1_002_240,
    165: 2_039_280,
    [SUBTREE_PAGE_LEN]: 58_340_000,
    [SUBROOT_PAGE_LEN]: 68_140_000,
    [MEMO_PAGE_LEN]: 72_149_760,
    [NF_PAGE_LEN]: 68_140_000,
  }
  // ceil(58_340_000 / 256) + ceil(68_140_000 / 76_800) + ceil(72_149_760 / 96) = 980_339n
  const expectedLivePerNote = 227_891n + 888n + 751_560n
  const expectedLivePerNf = 113_567n

  try {
    await withMockFetch(
      async (url, init) => {
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getMinimumBalanceForRentExemption') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: rentMap[Number(body.params[0])] ?? 1_000_000 })
        }
        if (body.method === 'getAccountInfo' && body.params[0] === poolPda) {
          if (url === mockRpcMissingPool) {
            return Response.json({ jsonrpc: '2.0', id: 1, result: { value: null } })
          }
          const bytes = url === mockRpcZeroNote ? poolZeroNote : poolCappedNote
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              value: {
                data: [toBase64(bytes), 'base64'],
                lamports: 2_000_000,
                owner: AUDREN_PROGRAM_ID,
              },
            },
          })
        }
        throw new Error(`Unexpected RPC call in R5-R1 test: ${body.method}`)
      },
      async () => {
        // 1. Governance override noteRentFee === 0n MUST yield pageRentPerNoteLamports === 0n (NOT livePerNote!)
        const schedZero = await fetchLiveRentSchedule(mockRpcZeroNote)
        assert.equal(schedZero.pageRentPerNoteLamports, 0n)
        assert.equal(schedZero.nfPageRentPerNfLamports, 0n)
        assert.equal(schedZero.swapBaselineLamports, 2n * 890_880n + 20_000n)

        // 2. Missing PoolState still falls back cleanly to livePerNote / livePerNf
        const schedMissing = await fetchLiveRentSchedule(mockRpcMissingPool)
        assert.equal(schedMissing.pageRentPerNoteLamports, expectedLivePerNote)
        assert.equal(schedMissing.nfPageRentPerNfLamports, expectedLivePerNf)

        // 3. Positive noteRentFee < livePerNote uses deterministicNoteRentFee (min with livePerNote)
        const schedCapped = await fetchLiveRentSchedule(mockRpcCappedNote)
        assert.equal(schedCapped.pageRentPerNoteLamports, 500_000n)
        assert.equal(schedCapped.nfPageRentPerNfLamports, 80_000n)
      },
    )
  } finally {
    clearLiveRentScheduleCache()
  }
})

test('R5-R2: non-string JSON fields across POST /v1/swap/quote, /v1/swap/instructions, and /v1/relay/submit return HTTP 400 with CORS headers (never TypeError 500)', async () => {
  const worker = await getWorker()
  const guard = createMockGuard()
  const env = {
    RELAY_GUARD: guard.namespace,
    CORS_ORIGINS: 'https://audren.xyz',
    MAINNET_RPC_URL: 'https://mock-rpc.local/r5-r2-non-string',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    JUPITER_API_KEY: 'test-jup-key',
  } as Env

  const postJson = async (path: string, payload: Record<string, unknown>) => {
    const res = await worker.fetch(
      new Request(`https://relay.audren.xyz${path}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          origin: 'https://audren.xyz',
        },
        body: JSON.stringify(payload),
      }),
      env,
    )
    const body = (await res.json()) as { error?: string; code?: string }
    return { res, body }
  }

  const assertBadRequestWithCors = (
    label: string,
    result: { res: Response; body: { error?: string; code?: string } },
  ) => {
    assert.equal(
      result.res.status,
      400,
      `${label}: expected HTTP 400, got ${result.res.status} (${JSON.stringify(result.body)})`,
    )
    assert.equal(
      result.res.headers.get('access-control-allow-origin'),
      'https://audren.xyz',
      `${label}: expected CORS allow-origin header on 400 response`,
    )
    assert.equal(typeof result.body.error, 'string', `${label}: expected string error message`)
    assert.ok((result.body.error?.length ?? 0) > 0, `${label}: expected non-empty error message`)
  }

  const cases: Array<[string, string, Record<string, unknown>]> = [
    // /v1/swap/quote
    ['swap/quote cluster=123', '/v1/swap/quote', { cluster: 123 }],
    ['swap/quote cluster=null', '/v1/swap/quote', { cluster: null }],
    [
      'swap/quote inputMint=123',
      '/v1/swap/quote',
      { cluster: 'mainnet', inputMint: 123, outputMint: USDC_MINT, amount: '1000000' },
    ],
    [
      'swap/quote outputMint=456',
      '/v1/swap/quote',
      { cluster: 'mainnet', inputMint: WSOL_MINT, outputMint: 456, amount: '1000000' },
    ],
    [
      'swap/quote amount=[1000]',
      '/v1/swap/quote',
      { cluster: 'mainnet', inputMint: WSOL_MINT, outputMint: USDC_MINT, amount: [1000] },
    ],
    [
      'swap/quote provider=123',
      '/v1/swap/quote',
      { cluster: 'mainnet', inputMint: WSOL_MINT, outputMint: USDC_MINT, amount: '1000000', provider: 123 },
    ],
    [
      'swap/quote provider=false',
      '/v1/swap/quote',
      { cluster: 'mainnet', inputMint: WSOL_MINT, outputMint: USDC_MINT, amount: '1000000', provider: false },
    ],
    [
      'swap/quote relayerPubkey=123',
      '/v1/swap/quote',
      { cluster: 'mainnet', inputMint: WSOL_MINT, outputMint: USDC_MINT, amount: '1000000', relayerPubkey: 123 },
    ],

    // /v1/swap/instructions
    ['swap/instructions cluster=123', '/v1/swap/instructions', { cluster: 123 }],
    [
      'swap/instructions provider=123',
      '/v1/swap/instructions',
      { cluster: 'mainnet', provider: 123, quoteResponse: {} },
    ],
    [
      'swap/instructions quoteResponse=[]',
      '/v1/swap/instructions',
      { cluster: 'mainnet', provider: 'jupiter', quoteResponse: [] },
    ],
    [
      'swap/instructions inputMint=123',
      '/v1/swap/instructions',
      {
        cluster: 'mainnet',
        provider: 'jupiter',
        inputMint: 123,
        outputMint: USDC_MINT,
        quoteResponse: { inputMint: WSOL_MINT, outputMint: USDC_MINT },
      },
    ],
    [
      'swap/instructions outputMint=123',
      '/v1/swap/instructions',
      {
        cluster: 'mainnet',
        provider: 'jupiter',
        inputMint: WSOL_MINT,
        outputMint: 123,
        quoteResponse: { inputMint: WSOL_MINT, outputMint: USDC_MINT },
      },
    ],
    [
      'swap/instructions quoteResponse.inputMint=123',
      '/v1/swap/instructions',
      {
        cluster: 'mainnet',
        provider: 'jupiter',
        quoteResponse: { inputMint: 123, outputMint: USDC_MINT },
      },
    ],
    [
      'swap/instructions relayerPubkey=123',
      '/v1/swap/instructions',
      {
        cluster: 'mainnet',
        provider: 'jupiter',
        inputMint: WSOL_MINT,
        outputMint: USDC_MINT,
        relayerPubkey: 123,
        quoteResponse: {},
      },
    ],

    // /v1/relay/submit
    ['relay/submit cluster=123', '/v1/relay/submit', { cluster: 123 }],
    ['relay/submit cluster=null', '/v1/relay/submit', { cluster: null }],
    [
      'relay/submit wrong payer matches R5-R3 pattern',
      '/v1/relay/submit',
      {
        cluster: 'mainnet',
        accounts: [{ pubkey: base58Encode(new Uint8Array(32).fill(0x5a)), isSigner: true, isWritable: true }],
      },
    ],
  ]

  for (const [label, path, payload] of cases) {
    const res = await postJson(path, payload)
    assertBadRequestWithCors(label, res)
    if (label.includes('R5-R3')) {
      assert.equal(res.body.code, 'FIREWALL_REJECTED')
      assert.ok(
        /accounts\[0\] must be (?:a configured )?relayer/.test(String(res.body.error ?? '')),
        `Expected wrong payer message to match R5-R3 regex, got: ${res.body.error}`,
      )
    }
  }
})

// ============================================================================
// v1.3.0 Audit Round 1 Fixes (#1–#6)
// ============================================================================

test('v1.3.0 R1-F1: opportunistic proactive OpenPage locking never 503s busy lanes, keeps free lanes, and still 503s exact rollovers', async () => {
  const worker = await getWorker()
  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({
    activeLanes: 4,
    rootEpochInterval: 32n,
    noteRentFee: 1_000_000n,
    nfRentFee: 113_567n,
  })
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)

  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const lane1Pda = deriveLanePdaSync(0, 1).address
  const lane1RentVault = deriveLaneRentVaultPdaSync(0, 1).address

  const buildPrivIx = (laneId: number, nfSeed: number, memoSeq = 0n, nextMemoSeq?: bigint) => {
    const { cm2, memo } = makeShieldedFeeCm2(6_000_000n, wsolMintBytes, nfSeed)
    const memos = new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN)
    memos.set(new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x11), 0)
    memos.set(memo, MEMO_ENTRY_WIRE_LEN)
    return buildTransactInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: laneId,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: memoSeq,
      outNfSeq: 0n,
      rollover: nextMemoSeq !== undefined ? { nextMemoSeq } : undefined,
      outputMask: 0b101,
      assetMode: ASSET_MODE_PRIVATE,
      proof192: dummyProof,
      nf0: new Uint8Array(32).fill(nfSeed),
      nf1: new Uint8Array(32).fill(nfSeed + 1),
      cm0: new Uint8Array(32).fill(0x10),
      cm1: new Uint8Array(32),
      cm2,
      publicAmountOut: 0n,
      relayerFeeAmount: 0n,
      memosBytes: memos,
    })
  }

  const fvkJson = JSON.stringify({
    spendPkHex: toHex(relayerFvk.spendPk),
    nkHex: toHex(relayerFvk.nk),
    viewSkHex: toHex(relayerFvk.viewSk),
    viewPkHex: toHex(relayerFvk.viewPk),
  })

  const mockRentRpc = (
    accMap: Map<string, { bytes: Uint8Array; lamports: number; owner: string }>,
    onSend?: (wire: Uint8Array) => void,
    simRelayerPostLamports = 496_000_000,
  ) =>
    async (_url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        const rent =
          len === 0
            ? 890_880
            : len === 16
              ? 1_002_240
              : len === 165
                ? 2_039_280
                : len === SUBTREE_PAGE_LEN
                  ? 58_352_640
                  : len === MEMO_PAGE_LEN
                    ? 72_161_280
                    : 68_152_320
        return Response.json({ jsonrpc: '2.0', id: 1, result: rent })
      }
      if (body.method === 'getAccountInfo') {
        const hit = accMap.get(String(body.params[0]))
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: hit
              ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner }
              : null,
          },
        })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x73)) } },
        })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 80_000 },
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
        const cfgObj = body.params[1] as { accounts?: { addresses?: string[] } }
        const watchCount = cfgObj?.accounts?.addresses?.length ?? 1
        const simAccs = [
          { lamports: simRelayerPostLamports, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
          ...Array.from({ length: Math.max(0, watchCount - 1) }, () => ({
            lamports: 27_800_000,
            owner: AUDREN_PROGRAM_ID,
            data: ['', 'base64'],
          })),
        ]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 80_000 },
            value: { err: null, logs: ['OK'], unitsConsumed: 150_000, accounts: simAccs },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        onSend?.(fromBase64(String(body.params[0])))
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: '5V130R1F1MockSig11111111111111111111111111111',
        })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: [{ slot: 80_001, err: null, confirmationStatus: 'confirmed' }] },
        })
      }
      throw new Error(`Unexpected RPC in R1-F1 test: ${body.method}`)
    }

  // Case A: Single tx on lane 0 at `nextLeaf = 86` (proactive MemoPage 1), lane 0 ALREADY locked by another tx!
  // MUST NOT return 503 LANE_ROLLOVER_BUSY — must drop optional proactive OpenPage and return 200!
  const guardA = createMockGuard()
  guardA.openPageLocks.set('mainnet:0:0', { leaseId: 'other-tx-lease', expiresAt: Date.now() + 30_000 })
  const envA = {
    RELAY_GUARD: guardA.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/r1-f1-proactive-busy',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    MAINNET_RELAYER_FVK_JSON: fvkJson,
  } as Env
  const accMapA = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 86n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0RentVault, { bytes: new Uint8Array(16), lamports: 100_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
  ])
  const ixA = buildPrivIx(0, 0xb1)
  let sentWireA: Uint8Array | null = null
  const resA = await withMockFetch(mockRentRpc(accMapA, (w) => { sentWireA = w }), () =>
    worker.fetch(
      new Request('https://relay.audren.xyz/v1/relay/submit', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          cluster: 'mainnet',
          instructionDataB64: toBase64(ixA.data),
          accounts: ixA.accounts,
        }),
      }),
      envA,
    ),
  )
  assert.equal(resA.status, 200)
  const bodyA = (await resA.json()) as { openedPagesCount: number; computeUnitLimit: number }
  assert.equal(bodyA.openedPagesCount, 0)
  assert.equal(bodyA.computeUnitLimit, CU_LIMIT_TRANSACT_PRIVATE)
  assert.ok(sentWireA)
  assert.equal(decodeV1Tx(sentWireA).instructions.length, 1)
  assert.equal(decodeV1Tx(sentWireA).instructions[0]!.data[0], TAG_TRANSACT)
  assert.equal(guardA.openPageLocks.get('mainnet:0:0')?.leaseId, 'other-tx-lease')

  // Case B: 2-ix batch across lane 0 (locked) and lane 1 (free), both at `nextLeaf = 86` ->
  // drops lane 0 proactive page, opens lane 1 proactive page, returns 200, releases lane 1 lock, preserves lane 0 lock!
  const guardB = createMockGuard()
  guardB.openPageLocks.set('mainnet:0:0', { leaseId: 'other-tx-lease', expiresAt: Date.now() + 30_000 })
  const envB = {
    RELAY_GUARD: guardB.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/r1-f1-batch-mixed',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    MAINNET_RELAYER_FVK_JSON: fvkJson,
  } as Env
  const accMapB = new Map(accMapA)
  accMapB.set(lane1Pda, { bytes: makeLaneStateBytes({ laneId: 1, nextLeaf: 86n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID })
  accMapB.set(lane1RentVault, { bytes: new Uint8Array(16), lamports: 100_000_000, owner: AUDREN_PROGRAM_ID })
  accMapB.set(deriveSubtreePdaSync(0, 1, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID })
  accMapB.set(deriveSubrootPdaSync(0, 1, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID })
  accMapB.set(deriveMemoPdaSync(0, 1, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID })
  accMapB.set(deriveNfPagePdaSync(0, 1, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID })
  const ixB0 = buildPrivIx(0, 0xb3)
  const ixB1 = buildPrivIx(1, 0xb5)
  let sentWireB: Uint8Array | null = null
  const resB = await withMockFetch(mockRentRpc(accMapB, (w) => { sentWireB = w }, 492_000_000), () =>
    worker.fetch(
      new Request('https://relay.audren.xyz/v1/relay/submit', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          cluster: 'mainnet',
          instructions: [
            { instructionDataB64: toBase64(ixB0.data), accounts: ixB0.accounts },
            { instructionDataB64: toBase64(ixB1.data), accounts: ixB1.accounts },
          ],
        }),
      }),
      envB,
    ),
  )
  assert.equal(resB.status, 200)
  const bodyB = (await resB.json()) as { openedPagesCount: number; computeUnitLimit: number }
  assert.equal(bodyB.openedPagesCount, 1)
  assert.equal(bodyB.computeUnitLimit, 2 * CU_LIMIT_TRANSACT_PRIVATE + CU_LIMIT_OPEN_PAGE)
  assert.ok(sentWireB)
  const decB = decodeV1Tx(sentWireB)
  assert.equal(decB.instructions.length, 3)
  assert.equal(decB.instructions[0]!.data[0], TAG_OPEN_PAGE)
  assert.equal(decB.instructions[0]!.data[6], 1, 'Only unlocked lane 1 proactive OpenPage must be included')
  assert.equal(guardB.openPageLocks.get('mainnet:0:0')?.leaseId, 'other-tx-lease')
  assert.equal(guardB.openPageLocks.has('mainnet:0:1'), false, 'Lane 1 proactive lock must be released after confirm')

  // Case C: Exact rollover on locked lane 0 STILL returns 503 LANE_ROLLOVER_BUSY!
  const guardC = createMockGuard()
  guardC.openPageLocks.set('mainnet:0:0', { leaseId: 'other-tx-lease', expiresAt: Date.now() + 30_000 })
  const envC = {
    RELAY_GUARD: guardC.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/r1-f1-exact-busy',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    MAINNET_RELAYER_FVK_JSON: fvkJson,
  } as Env
  const accMapC = new Map(accMapA)
  accMapC.set(lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 95n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID })
  const ixC = buildPrivIx(0, 0xb7, 0n, 1n) // crosses 96-note MemoPage boundary -> exact OpenPage(MEMO, 1)
  const resC = await withMockFetch(mockRentRpc(accMapC), () =>
    worker.fetch(
      new Request('https://relay.audren.xyz/v1/relay/submit', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          cluster: 'mainnet',
          instructionDataB64: toBase64(ixC.data),
          accounts: ixC.accounts,
        }),
      }),
      envC,
    ),
  )
  assert.equal(resC.status, 503)
  const bodyC = (await resC.json()) as { code: string }
  assert.equal(bodyC.code, 'LANE_ROLLOVER_BUSY')
  assert.equal(resC.headers.get('retry-after'), '2')
})

test('v1.3.0 R1-F2: post-pin proactive deficit drops proactive without draining relayer, proactive-only SLOT_SKEW recovers cleanly, and cold isolate uses exact fallback rents while skipping proactive', async () => {
  const worker = await getWorker()
  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({
    activeLanes: 4,
    rootEpochInterval: 32n,
    noteRentFee: 1_000_000n,
    nfRentFee: 113_567n,
  })
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const fvkJson = JSON.stringify({
    spendPkHex: toHex(relayerFvk.spendPk),
    nkHex: toHex(relayerFvk.nk),
    viewSkHex: toHex(relayerFvk.viewSk),
    viewPkHex: toHex(relayerFvk.viewPk),
  })

  const buildPrivIx = (nfSeed: number, feeLamports = 5_000_000n, nextMemoSeq?: bigint) => {
    const { cm2, memo } = makeShieldedFeeCm2(feeLamports, wsolMintBytes, nfSeed)
    const memos = new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN)
    memos.set(new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x11), 0)
    memos.set(memo, MEMO_ENTRY_WIRE_LEN)
    return buildTransactInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: 0,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: 0n,
      outNfSeq: 0n,
      rollover: nextMemoSeq !== undefined ? { nextMemoSeq } : undefined,
      outputMask: 0b101,
      assetMode: ASSET_MODE_PRIVATE,
      proof192: dummyProof,
      nf0: new Uint8Array(32).fill(nfSeed),
      nf1: new Uint8Array(32).fill(nfSeed + 1),
      cm0: new Uint8Array(32).fill(0x10),
      cm1: new Uint8Array(32),
      cm2,
      publicAmountOut: 0n,
      relayerFeeAmount: 0n,
      memosBytes: memos,
    })
  }

  // Case A: Concurrent `LaneRentVault` drain between `confirmed` pre-fetch (100M) and `processed` slot-pin (41.65M).
  // Must detect `proactiveDeficitFloor > 0n`, drop proactive OpenPage, release proactive lock, recompile/re-sim,
  // and keep `billingMode === 'self_paying'` with ZERO relayer SOL drained!
  const guardDrain = createMockGuard()
  const envDrain = {
    RELAY_GUARD: guardDrain.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/r1-f2-post-pin-drain',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    MAINNET_RELAYER_FVK_JSON: fvkJson,
  } as Env
  const accMapDrain = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 86n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0RentVault, { bytes: new Uint8Array(16), lamports: 100_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
  ])
  let simCountDrain = 0
  let sentWireDrain: Uint8Array | null = null
  const resDrain = await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result:
            len === 0
              ? 890_880
              : len === 16
                ? 1_002_240
                : len === 165
                  ? 2_039_280
                  : len === SUBTREE_PAGE_LEN
                    ? 58_352_640
                    : len === MEMO_PAGE_LEN
                      ? 72_161_280
                      : 68_152_320,
        })
      }
      if (body.method === 'getAccountInfo') {
        const hit = accMapDrain.get(String(body.params[0]))
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: hit
              ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner }
              : null,
          },
        })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x74)) } },
        })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        const opts = body.params[1] as { commitment?: string }
        const isProcessed = opts?.commitment === 'processed'
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: isProcessed ? 90_002 : 90_000 },
            value: addrs.map((a) => {
              if (isProcessed && a === lane0RentVault) {
                // Concurrent direct-wallet tx drained LaneRentVault down to 41.65M!
                return { data: [toBase64(new Uint8Array(16)), 'base64'], lamports: 41_650_000, owner: AUDREN_PROGRAM_ID }
              }
              const hit = accMapDrain.get(a)
              return hit
                ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner }
                : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        simCountDrain++
        const wire = fromBase64(String(body.params[0]))
        const dec = decodeV1Tx(wire)
        const hasOpenPage = dec.instructions.some((ix) => ix.data[0] === TAG_OPEN_PAGE)
        const opts = body.params[1] as { commitment?: string; accounts?: { addresses?: string[] } }
        const watchCount = opts?.accounts?.addresses?.length ?? 1
        // First call (confirmed) returns skewed slot 90_001 -> triggers processed pin at 90_002!
        const simSlot = simCountDrain === 1 ? 90_001 : 90_002
        // With drained vault + proactive OpenPage, relayer loses ~34.5M lamports; without OpenPage, only ~3.8M!
        const postRelayer = hasOpenPage ? 465_500_000 : 496_200_000
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: simSlot },
            value: {
              err: null,
              logs: ['OK'],
              unitsConsumed: 150_000,
              accounts: [
                { lamports: postRelayer, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                ...Array.from({ length: Math.max(0, watchCount - 1) }, () => ({
                  lamports: 1_002_240,
                  owner: AUDREN_PROGRAM_ID,
                  data: ['', 'base64'],
                })),
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        sentWireDrain = fromBase64(String(body.params[0]))
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5V130R1F2DrainSig111111111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 90_003, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R1-F2 drain test: ${body.method}`)
    },
    () => {
      const ix = buildPrivIx(0xc1)
      return worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(ix.data),
            accounts: ix.accounts,
          }),
        }),
        envDrain,
      )
    },
  )
  assert.equal(resDrain.status, 200)
  const bodyDrain = (await resDrain.json()) as {
    billingMode: string
    netSponsoredLamports: string
    openedPagesCount: number
    computeUnitLimit: number
  }
  assert.equal(bodyDrain.billingMode, 'self_paying', 'Proactive deficit must NEVER flip self_paying to sponsored')
  assert.equal(bodyDrain.netSponsoredLamports, '0')
  assert.equal(bodyDrain.openedPagesCount, 0)
  assert.equal(bodyDrain.computeUnitLimit, CU_LIMIT_TRANSACT_PRIVATE)
  assert.ok(sentWireDrain)
  assert.equal(decodeV1Tx(sentWireDrain).instructions.length, 1)
  assert.equal(guardDrain.openPageLocks.size, 0, 'Proactive lock must be released immediately on drop')

  // Case B: Persistent SLOT_SKEW caused SOLELY by optional proactive OpenPage -> drops proactive and returns 200 (never 503 SLOT_SKEW)!
  const guardSkew = createMockGuard()
  const envSkew = {
    RELAY_GUARD: guardSkew.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/r1-f2-proactive-skew',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    MAINNET_RELAYER_FVK_JSON: fvkJson,
  } as Env
  let skewSlotCounter = 0
  let sentWireSkew: Uint8Array | null = null
  const resSkew = await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result:
            len === 0
              ? 890_880
              : len === 16
                ? 1_002_240
                : len === 165
                  ? 2_039_280
                  : len === SUBTREE_PAGE_LEN
                    ? 58_352_640
                    : len === MEMO_PAGE_LEN
                      ? 72_161_280
                      : 68_152_320,
        })
      }
      if (body.method === 'getAccountInfo') {
        const hit = accMapDrain.get(String(body.params[0]))
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: hit
              ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner }
              : null,
          },
        })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x75)) } },
        })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        skewSlotCounter++
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 91_000 + skewSlotCounter },
            value: addrs.map((a) => {
              const hit = accMapDrain.get(a)
              return hit
                ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner }
                : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        const opts = body.params[1] as { accounts?: { addresses?: string[] } }
        const watchCount = opts?.accounts?.addresses?.length ?? 1
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 99_999 }, // always skewed vs getMultipleAccounts!
            value: {
              err: null,
              logs: ['OK'],
              unitsConsumed: 150_000,
              accounts: [
                { lamports: 496_200_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                ...Array.from({ length: Math.max(0, watchCount - 1) }, () => ({
                  lamports: 27_800_000,
                  owner: AUDREN_PROGRAM_ID,
                  data: ['', 'base64'],
                })),
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        sentWireSkew = fromBase64(String(body.params[0]))
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5V130R1F2SkewSig1111111111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 100_000, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R1-F2 skew test: ${body.method}`)
    },
    () => {
      const ix = buildPrivIx(0xc3)
      return worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(ix.data),
            accounts: ix.accounts,
          }),
        }),
        envSkew,
      )
    },
  )
  assert.equal(resSkew.status, 200, 'Proactive-only SLOT_SKEW must drop proactive pages and succeed')
  const bodySkew = (await resSkew.json()) as { openedPagesCount: number }
  assert.equal(bodySkew.openedPagesCount, 0)
  assert.ok(sentWireSkew)
  assert.equal(decodeV1Tx(sentWireSkew).instructions.length, 1)
  assert.equal(guardSkew.openPageLocks.size, 0)

  // Case C: Cold isolate (`rentSchedule === null`):
  //   1. Skips proactive lookahead completely (`openedPagesCount === 0`) even when LaneRentVault has 100M.
  //   2. Uses exact Mainnet fallback page rent (`72_161_280n`, NOT `72_149_760n`) for exact rollover deficit floor.
  clearLiveRentScheduleCache()
  const guardColdPro = createMockGuard()
  const envColdPro = {
    RELAY_GUARD: guardColdPro.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/r1-f2-cold-rent-null-proactive',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    MAINNET_RELAYER_FVK_JSON: fvkJson,
  } as Env
  const coldMockFetch =
    (accMap: Map<string, { bytes: Uint8Array; lamports: number; owner: string }>) =>
    async (_url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        // Force cold isolate `fetchLiveRentSchedule` -> null!
        return Response.json({ jsonrpc: '2.0', id: 1, error: { code: -32005, message: 'RPC rate limited' } })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x76)) } },
        })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 92_000 },
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
        const opts = body.params[1] as { accounts?: { addresses?: string[] } }
        const watchCount = opts?.accounts?.addresses?.length ?? 1
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 92_000 },
            value: {
              err: null,
              logs: ['OK'],
              unitsConsumed: 150_000,
              accounts: [
                { lamports: 499_990_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                ...Array.from({ length: Math.max(0, watchCount - 1) }, () => ({
                  lamports: 1_002_240,
                  owner: AUDREN_PROGRAM_ID,
                  data: ['', 'base64'],
                })),
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5V130R1F2ColdSig1111111111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 92_001, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R1-F2 cold test: ${body.method}`)
    }

  const resColdPro = await withMockFetch(coldMockFetch(accMapDrain), () => {
    const ix = buildPrivIx(0xc5)
    return worker.fetch(
      new Request('https://relay.audren.xyz/v1/relay/submit', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          cluster: 'mainnet',
          instructionDataB64: toBase64(ix.data),
          accounts: ix.accounts,
        }),
      }),
      envColdPro,
    )
  })
  assert.equal(resColdPro.status, 200)
  const bodyColdPro = (await resColdPro.json()) as { openedPagesCount: number }
  assert.equal(bodyColdPro.openedPagesCount, 0, 'Cold isolate (rentSchedule === null) MUST skip proactive lookahead')

  // Exact rollover on cold isolate with vault = old underestimated fallback (72_149_760 + 1_002_240):
  // Exact fallback 72_161_280n MUST detect exact 11_520n deficit!
  const guardColdExact = createMockGuard()
  const envColdExact = {
    RELAY_GUARD: guardColdExact.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/r1-f2-cold-rent-null-exact',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    MAINNET_RELAYER_FVK_JSON: fvkJson,
  } as Env
  const accMapColdExact = new Map(accMapDrain)
  accMapColdExact.set(lane0Pda, {
    bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 95n, nfCount: 10n }),
    lamports: 15_000_000,
    owner: AUDREN_PROGRAM_ID,
  })
  accMapColdExact.set(lane0RentVault, {
    bytes: new Uint8Array(16),
    lamports: 72_149_760 + 1_002_240, // 11_520 lamports short of exact 72_161_280 + 1_002_240!
    owner: AUDREN_PROGRAM_ID,
  })
  const resColdExact = await withMockFetch(coldMockFetch(accMapColdExact), () => {
    const ix = buildPrivIx(0xc7, 6_000_000n, 1n)
    return worker.fetch(
      new Request('https://relay.audren.xyz/v1/relay/submit', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          cluster: 'mainnet',
          instructionDataB64: toBase64(ix.data),
          accounts: ix.accounts,
        }),
      }),
      envColdExact,
    )
  })
  assert.equal(resColdExact.status, 200)
  const bodyColdExact = (await resColdExact.json()) as {
    openedPagesCount: number
    simulatedCostLamports: string
  }
  assert.equal(bodyColdExact.openedPagesCount, 1)
  // Expected floor: 5_000 (sig) + 5_000 (prio) + 2*(890_880 + 113_567) + 2*980_565 + 11_520 (exact MemoPage deficit)
  // Compute exact expected deterministic noteRentFee under exact fallbacks:
  // ceil(58_352_640/256) + ceil(68_152_320/76_800) + ceil(72_161_280/96) = 227_940 + 888 + 751_680 = 980_508
  const expectedColdExactCost =
    5_000n +
    5_000n +
    2n * (890_880n + 113_567n) +
    2n * 980_508n +
    11_520n
  assert.equal(BigInt(bodyColdExact.simulatedCostLamports), expectedColdExactCost)
})

test('v1.3.0 R1-F3: proactive lookahead obeys Solana v1 4,096 B wire cap and 1,400,000 CU cap without false TX_TOO_LARGE or CU theft', async () => {
  const indexMod = await import('../src/index')
  const worker = indexMod.default
  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({
    activeLanes: 4,
    rootEpochInterval: 32n,
    noteRentFee: 1_000_000n,
    nfRentFee: 113_567n,
  })
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)
  const fvkJson = JSON.stringify({
    spendPkHex: toHex(relayerFvk.spendPk),
    nkHex: toHex(relayerFvk.nk),
    viewSkHex: toHex(relayerFvk.viewSk),
    viewPkHex: toHex(relayerFvk.viewPk),
  })

  // 1. 4-ix private merge batch across 4 lanes where EVERY lane triggers 3 proactive lookahead pages
  //    (nextLeaf = 766 -> subSeq = 2 rem 254 (subRem=2), memoSeq = 7 rem 94 (memoRem=2), nfCount = 550 (nfRem=50)
  //     => 12 proactive pages total = +684 B, which WOULD overflow 4,096 B without `maxExtraByBytes`!).
  const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
  ])
  const batchIxs = [0, 1, 2, 3].map((laneId) => {
    const lanePda = deriveLanePdaSync(0, laneId).address
    const laneRent = deriveLaneRentVaultPdaSync(0, laneId).address
    accMap.set(lanePda, {
      bytes: makeLaneStateBytes({ laneId, nextLeaf: 766n, nfCount: 550n }),
      lamports: 15_000_000,
      owner: AUDREN_PROGRAM_ID,
    })
    accMap.set(laneRent, {
      bytes: new Uint8Array(16),
      lamports: 400_000_000,
      owner: AUDREN_PROGRAM_ID,
    })
    accMap.set(deriveSubtreePdaSync(0, laneId, 2n).address, {
      bytes: dummyPageBytes,
      lamports: 58_352_640,
      owner: AUDREN_PROGRAM_ID,
    })
    accMap.set(deriveSubrootPdaSync(0, laneId, 0n).address, {
      bytes: dummyPageBytes,
      lamports: 68_152_320,
      owner: AUDREN_PROGRAM_ID,
    })
    accMap.set(deriveMemoPdaSync(0, laneId, 7n).address, {
      bytes: dummyPageBytes,
      lamports: 72_161_280,
      owner: AUDREN_PROGRAM_ID,
    })
    accMap.set(deriveNfPagePdaSync(0, laneId, 0n).address, {
      bytes: dummyPageBytes,
      lamports: 68_152_320,
      owner: AUDREN_PROGRAM_ID,
    })
    const seed = 0xd0 + laneId * 2
    const { cm2, memo } = makeShieldedFeeCm2(8_000_000n, wsolMintBytes, seed)
    const memos = new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN)
    memos.set(new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x11), 0)
    memos.set(memo, MEMO_ENTRY_WIRE_LEN)
    return buildTransactInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: laneId,
      outSubSeq: 2n,
      outRootSeq: 0n,
      outMemoSeq: 7n,
      outNfSeq: 0n,
      outputMask: 0b101,
      assetMode: ASSET_MODE_PRIVATE,
      proof192: dummyProof,
      nf0: new Uint8Array(32).fill(seed),
      nf1: new Uint8Array(32).fill(seed + 1),
      cm0: new Uint8Array(32).fill(0x10),
      cm1: new Uint8Array(32),
      cm2,
      publicAmountOut: 0n,
      relayerFeeAmount: 0n,
      memosBytes: memos,
    })
  })

  const guardWire = createMockGuard()
  const envWire = {
    RELAY_GUARD: guardWire.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/r1-f3-wire-cap',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    MAINNET_RELAYER_FVK_JSON: fvkJson,
  } as Env
  let sentWireBatch: Uint8Array | null = null
  const resWire = await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result:
            len === 0
              ? 890_880
              : len === 16
                ? 1_002_240
                : len === 165
                  ? 2_039_280
                  : len === SUBTREE_PAGE_LEN
                    ? 58_352_640
                    : len === MEMO_PAGE_LEN
                      ? 72_161_280
                      : 68_152_320,
        })
      }
      if (body.method === 'getAccountInfo') {
        const hit = accMap.get(String(body.params[0]))
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: hit
              ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner }
              : null,
          },
        })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x77)) } },
        })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 93_000 },
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
        const opts = body.params[1] as { accounts?: { addresses?: string[] } }
        const watchCount = opts?.accounts?.addresses?.length ?? 1
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 93_000 },
            value: {
              err: null,
              logs: ['OK'],
              unitsConsumed: 820_000,
              accounts: [
                { lamports: 484_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                ...Array.from({ length: Math.max(0, watchCount - 1) }, () => ({
                  lamports: 200_000_000,
                  owner: AUDREN_PROGRAM_ID,
                  data: ['', 'base64'],
                })),
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        sentWireBatch = fromBase64(String(body.params[0]))
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5V130R1F3WireSig1111111111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 93_001, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R1-F3 wire test: ${body.method}`)
    },
    () =>
      worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructions: batchIxs.map((ix) => ({
              instructionDataB64: toBase64(ix.data),
              accounts: ix.accounts,
            })),
          }),
        }),
        envWire,
      ),
  )
  assert.equal(resWire.status, 200, '4-ix batch with 12 proactive candidates MUST cap by wire bytes instead of failing 400 TX_TOO_LARGE')
  const bodyWire = (await resWire.json()) as {
    txWireBytes: number
    openedPagesCount: number
    computeUnitLimit: number
  }
  assert.ok(bodyWire.txWireBytes <= 4096, `Expected wireLen <= 4096, got ${bodyWire.txWireBytes}`)
  assert.ok(bodyWire.openedPagesCount > 0 && bodyWire.openedPagesCount < 12)
  assert.ok(sentWireBatch)
  assert.equal(sentWireBatch.length, bodyWire.txWireBytes)

  // 2. CU cap near 1,400,000: base tx asks for 1_360_000 CU on lane 0 with 3 proactive candidates ->
  //    at most `floor((1_400_000 - 1_360_000) / 40_000) = 1` proactive page allowed (1_400_000 <= 1_400_000)!
  const guardCu = createMockGuard()
  const envCu = {
    RELAY_GUARD: guardCu.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/r1-f3-cu-cap',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    MAINNET_RELAYER_FVK_JSON: fvkJson,
  } as Env
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const escrow1 = deriveEscrowPdaSync(0, 1).address
  const vaultWsolAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultUsdcAta = deriveAssociatedTokenAddressSync(vaultAuth, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowInAta = deriveAssociatedTokenAddressSync(escrow1, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowOutAta = deriveAssociatedTokenAddressSync(escrow1, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const execNearCap = buildExecViaEscrowInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 2n,
    outRootSeq: 0n,
    outMemoSeq: 7n,
    outNfSeq: 0n,
    escrowShard: 1,
    changeMask: 0,
    inLeg: { mint: WSOL_MINT, vaultAta: vaultWsolAta, escrowAta: escrowInAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    outLeg: { mint: USDC_MINT, vaultAta: vaultUsdcAta, escrowAta: escrowOutAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    relayerFeeAmount: 0n,
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0xd9),
    nf1: new Uint8Array(32).fill(0xda),
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    amountIn: 100_000_000n,
    minAmountOut: 1_000_000n,
    outStealthOwner: new Uint8Array(32).fill(0x02),
    outBlinding: new Uint8Array(32).fill(0x03),
    dynMemoHead: new Uint8Array(34).fill(0x04),
    dynMemoMask: new Uint8Array(72).fill(0x05),
    routerProg: base58Encode(new Uint8Array(32).fill(0x55)),
    routerIxData: new Uint8Array([1, 2, 3]),
    routerAccounts: [{ pubkey: base58Encode(new Uint8Array(32).fill(0x66)), isSigner: false, isWritable: true }],
    changeMemos: new Uint8Array(0),
  })
  const resCu = await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result:
            len === 0
              ? 890_880
              : len === 16
                ? 1_002_240
                : len === 165
                  ? 2_039_280
                  : len === SUBTREE_PAGE_LEN
                    ? 58_352_640
                    : len === MEMO_PAGE_LEN
                      ? 72_161_280
                      : 68_152_320,
        })
      }
      if (body.method === 'getAccountInfo') {
        const hit = accMap.get(String(body.params[0]))
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: hit
              ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner }
              : null,
          },
        })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x78)) } },
        })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 93_010 },
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
        const opts = body.params[1] as { accounts?: { addresses?: string[] } }
        const watchCount = opts?.accounts?.addresses?.length ?? 1
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 93_010 },
            value: {
              err: null,
              logs: ['OK'],
              unitsConsumed: 1_250_000,
              accounts: [
                { lamports: 496_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                ...Array.from({ length: Math.max(0, watchCount - 1) }, () => ({
                  lamports: 340_000_000,
                  owner: AUDREN_PROGRAM_ID,
                  data: ['', 'base64'],
                })),
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5V130R1F3CuSig111111111111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 93_011, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R1-F3 CU test: ${body.method}`)
    },
    () =>
      worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            computeUnitLimit: 1_360_000,
            instructionDataB64: toBase64(execNearCap.data),
            accounts: execNearCap.accounts,
          }),
        }),
        envCu,
      ),
  )
  assert.equal(resCu.status, 200)
  const bodyCu = (await resCu.json()) as { openedPagesCount: number; computeUnitLimit: number }
  assert.equal(bodyCu.openedPagesCount, 1, 'Only 1 proactive OpenPage fits in remaining 40,000 CU headroom')
  assert.equal(bodyCu.computeUnitLimit, 1_400_000)

  // 3. Direct unit check of `estimateV1TxWireLen` matching `buildAndSignV1Transaction` byte-for-byte!
  const solIx = {
    programId: base58Decode(AUDREN_PROGRAM_ID),
    accounts: execNearCap.accounts.map((a) => ({
      pubkey: base58Decode(a.pubkey),
      isSigner: a.isSigner,
      isWritable: a.isWritable,
    })),
    data: execNearCap.data,
  }
  const est = indexMod.estimateV1TxWireLen(relayerPubkey, [solIx])
  const signed = buildAndSignV1Transaction(
    relayerSecret,
    base58Encode(new Uint8Array(32).fill(0x79)),
    [solIx],
    { computeUnitLimit: 615_000, priorityFeeLamports: 5_000n },
  )
  assert.equal(est.wireLen, signed.wireLen)
  assert.equal(est.uniqueAccountCount, signed.accountCount)

  // 4. Direct unit check of `planRolloverOpenPages` split shape & explicit `maxExtraByBytes` / `maxExtraByCu` / `allowProactive` caps
  const directFetched = new Map<string, { bytes: Uint8Array; owner: string } | null>()
  const directPre = new Map<string, { bytes: Uint8Array; lamports: number; owner: string } | null>()
  for (const [k, v] of accMap.entries()) {
    directFetched.set(k, { bytes: v.bytes, owner: v.owner })
    directPre.set(k, v)
  }
  const directEntry = {
    poolId: 0,
    outLaneId: 0,
    outputCount: 2,
    nullifierCount: 2,
    pages: {
      outSub: deriveSubtreePdaSync(0, 0, 2n).address,
      outRoot: deriveSubrootPdaSync(0, 0, 0n).address,
      outMemo: deriveMemoPdaSync(0, 0, 7n).address,
      nfPage: deriveNfPagePdaSync(0, 0, 0n).address,
      nextSub: null,
      nextMemo: null,
      nextNf: null,
    },
  }
  const directRentFloors = {
    laneRentVaultReserveFloor: 1_002_240n,
    subRentFloor: 58_352_640n,
    srRentFloor: 68_152_320n,
    memoRentFloor: 72_161_280n,
    nfPageRentFloor: 68_152_320n,
  }
  await withMockFetch(
    async () => Response.json({ jsonrpc: '2.0', id: 1, result: { context: { slot: 93_020 }, value: [null, null, null] } }),
    async () => {
      const byteCapped = await indexMod.planRolloverOpenPages({
        rpcUrl: 'https://mock-rpc.local/r1-f3-direct-bytes',
        payerB58: relayerB58,
        entries: [directEntry],
        fetchedAccounts: new Map(directFetched),
        preAccountInfoMap: new Map(directPre),
        rentFloors: directRentFloors,
        maxExtraByBytes: 1,
        maxExtraByCu: 5,
      })
      assert.equal(byteCapped.ok, true)
      if (byteCapped.ok) {
        assert.equal(byteCapped.exactOpenPageIxs.length, 0)
        assert.deepEqual(byteCapped.exactLaneIds, [])
        assert.equal(byteCapped.proactiveOpenPageIxs.length, 1)
        assert.equal(byteCapped.proactiveLaneMap.get(0)?.length, 1)
      }

      const cuCapped = await indexMod.planRolloverOpenPages({
        rpcUrl: 'https://mock-rpc.local/r1-f3-direct-cu',
        payerB58: relayerB58,
        entries: [directEntry],
        fetchedAccounts: new Map(directFetched),
        preAccountInfoMap: new Map(directPre),
        rentFloors: directRentFloors,
        maxExtraByBytes: 5,
        maxExtraByCu: 2,
      })
      assert.equal(cuCapped.ok, true)
      if (cuCapped.ok) {
        assert.equal(cuCapped.proactiveOpenPageIxs.length, 2)
        assert.equal(cuCapped.proactiveLaneMap.get(0)?.length, 2)
      }

      const disabledPro = await indexMod.planRolloverOpenPages({
        rpcUrl: 'https://mock-rpc.local/r1-f3-direct-disabled',
        payerB58: relayerB58,
        entries: [directEntry],
        fetchedAccounts: new Map(directFetched),
        preAccountInfoMap: new Map(directPre),
        rentFloors: directRentFloors,
        allowProactive: false,
      })
      assert.equal(disabledPro.ok, true)
      if (disabledPro.ok) {
        assert.equal(disabledPro.proactiveOpenPageIxs.length, 0)
        assert.equal(disabledPro.proactiveLaneMap.size, 0)
      }
    },
  )
})

test('v1.3.0 R1-F4: worst-case CU budgets for 2in/3out withdraw, Token-2022 ExecViaEscrow, multi-hop/OKX aggregators, and Token-2022 setupAtas', async () => {
  const indexMod = await import('../src/index')
  const worker = indexMod.default
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const escrow1 = deriveEscrowPdaSync(0, 1).address
  const recipient = base58Encode(new Uint8Array(32).fill(0x3a))
  const t22Mint = base58Encode(new Uint8Array(32).fill(0xe4))
  const vaultWsolAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultUsdcAta = deriveAssociatedTokenAddressSync(vaultAuth, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultT22Ata = deriveAssociatedTokenAddressSync(vaultAuth, t22Mint, TOKEN_2022_PROGRAM_ID).address
  const escrowWsolAta = deriveAssociatedTokenAddressSync(escrow1, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowUsdcAta = deriveAssociatedTokenAddressSync(escrow1, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowT22Ata = deriveAssociatedTokenAddressSync(escrow1, t22Mint, TOKEN_2022_PROGRAM_ID).address

  // 1. `2in/3out` Public WSOL Withdraw (`outputMask = 0b111`) -> `CU_LIMIT_TRANSACT_WITHDRAW = 255_000`
  assert.equal(CU_LIMIT_TRANSACT_WITHDRAW, 255_000)
  assert.equal(CU_LIMIT_TRANSACT_WITHDRAW_HOOK, 295_000)
  assert.equal(CU_LIMIT_EXEC_VIA_ESCROW_BASE, 285_000)
  const withdraw3OutIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b111,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: true,
    publicOutflow: { mint: WSOL_MINT, vaultAta: vaultWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0xe1),
    nf1: new Uint8Array(32).fill(0xe2),
    cm0: new Uint8Array(32).fill(0x11),
    cm1: new Uint8Array(32).fill(0x12),
    cm2: new Uint8Array(32).fill(0x13),
    publicAmountOut: 100_000_000n,
    relayerFeeAmount: 3_000_000n,
    recipient,
    relayerFeeRecipient: relayerB58,
    memosBytes: new Uint8Array(3 * MEMO_ENTRY_WIRE_LEN).fill(0x44),
  })
  const w3Verdict = validateRelaySubmission(
    { instructionDataB64: toBase64(withdraw3OutIx.data), accounts: withdraw3OutIx.accounts },
    relayerPubkey,
    allowedPre,
  )
  assert.deepEqual(indexMod.computeAudrenInstructionCuLimit(w3Verdict.audrenInstructions[0]!), {
    defaultCu: 255_000,
    minFloorCu: 255_000,
  })

  // 2. `ExecViaEscrow` Classic SPL vs Token-2022 leg (`+25_000`)
  const mkExec = (outMint: string, outVault: string, outEscrow: string, outTp: string, seed: number) =>
    buildExecViaEscrowInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: 0,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: 0n,
      outNfSeq: 0n,
      escrowShard: 1,
      changeMask: 0b11,
      inLeg: { mint: WSOL_MINT, vaultAta: vaultWsolAta, escrowAta: escrowWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
      outLeg: { mint: outMint, vaultAta: outVault, escrowAta: outEscrow, tokenProgram: outTp },
      relayerFeeAmount: 0n,
      proof192: dummyProof,
      nf0: new Uint8Array(32).fill(seed),
      nf1: new Uint8Array(32).fill(seed + 1),
      cm0: new Uint8Array(32).fill(0x01),
      cm1: new Uint8Array(32).fill(0x02),
      cm2: new Uint8Array(32),
      amountIn: 100_000_000n,
      minAmountOut: 1_000_000n,
      outStealthOwner: new Uint8Array(32).fill(0x02),
      outBlinding: new Uint8Array(32).fill(0x03),
      dynMemoHead: new Uint8Array(34).fill(0x04),
      dynMemoMask: new Uint8Array(72).fill(0x05),
      routerProg: base58Encode(new Uint8Array(32).fill(0x55)),
      routerIxData: new Uint8Array([1, 2, 3]),
      routerAccounts: [{ pubkey: base58Encode(new Uint8Array(32).fill(0x66)), isSigner: false, isWritable: true }],
      changeMemos: new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN).fill(0x22),
    })

  const classicExecVerdict = validateRelaySubmission(
    {
      instructionDataB64: toBase64(mkExec(USDC_MINT, vaultUsdcAta, escrowUsdcAta, CLASSIC_TOKEN_PROGRAM_ID, 0xe5).data),
      accounts: mkExec(USDC_MINT, vaultUsdcAta, escrowUsdcAta, CLASSIC_TOKEN_PROGRAM_ID, 0xe5).accounts,
    },
    relayerPubkey,
    allowedPre,
  )
  assert.deepEqual(indexMod.computeAudrenInstructionCuLimit(classicExecVerdict.audrenInstructions[0]!), {
    defaultCu: 285_000 + 350_000,
    minFloorCu: 285_000,
  })

  const t22ExecIx = mkExec(t22Mint, vaultT22Ata, escrowT22Ata, TOKEN_2022_PROGRAM_ID, 0xe7)
  const t22ExecVerdict = validateRelaySubmission(
    { instructionDataB64: toBase64(t22ExecIx.data), accounts: t22ExecIx.accounts },
    relayerPubkey,
    allowedPre,
  )
  assert.deepEqual(indexMod.computeAudrenInstructionCuLimit(t22ExecVerdict.audrenInstructions[0]!), {
    defaultCu: 285_000 + 25_000 + 350_000,
    minFloorCu: 285_000 + 25_000,
  })

  // 3. Aggregator CU helper & adapters (single-hop 350k vs multi-hop/OKX/unknown 550k, clamped at 1_400_000)
  assert.equal(SINGLE_HOP_ROUTER_CU_HEADROOM, 350_000)
  assert.equal(MULTI_HOP_ROUTER_CU_HEADROOM, 550_000)
  assert.equal(computeAggregatorExecCuLimit({ routeHopCount: 1 }), 285_000 + 350_000)
  assert.equal(computeAggregatorExecCuLimit({ routeHopCount: 2 }), 285_000 + 550_000)
  assert.equal(computeAggregatorExecCuLimit({ routeHopCount: 2, reportedRouterCu: 400_000 }), 285_000 + 550_000)
  assert.equal(computeAggregatorExecCuLimit({ routeHopCount: 2, reportedRouterCu: 720_000 }), 285_000 + 720_000)
  assert.equal(computeAggregatorExecCuLimit({ routeHopCount: null }), 285_000 + 550_000)
  assert.equal(computeAggregatorExecCuLimit({ forceMultiHopHeadroom: true }), 285_000 + 550_000)
  assert.equal(computeAggregatorExecCuLimit({ routeHopCount: 2, reportedRouterCu: 1_300_000 }), 1_400_000)

  const routerProg = base58Encode(new Uint8Array(32).fill(0x55))
  const mockSwapIx = {
    programId: routerProg,
    data: toBase64(new Uint8Array([1, 2, 3])),
    accounts: [{ pubkey: escrow1, isSigner: true, isWritable: true }],
  }
  await withMockFetch(
    async () => Response.json({ swapInstruction: mockSwapIx, addressLookupTableAddresses: [] }),
    async () => {
      const jup1 = await jupiterAdapter.swapInstructions(
        { JUPITER_API_URL: 'https://mock-jup.local' } as Env,
        {
          escrowPubkey: escrow1,
          inputMint: WSOL_MINT,
          outputMint: USDC_MINT,
          quoteResponse: { routePlan: [{ swapInfo: { label: 'Raydium' } }] },
        },
      )
      assert.equal(jup1.computeUnitLimit, 635_000)

      const jup2 = await jupiterAdapter.swapInstructions(
        { JUPITER_API_URL: 'https://mock-jup.local' } as Env,
        {
          escrowPubkey: escrow1,
          inputMint: WSOL_MINT,
          outputMint: USDC_MINT,
          quoteResponse: { routePlan: [{ swapInfo: { label: 'Orca' } }, { swapInfo: { label: 'Meteora' } }] },
        },
      )
      assert.equal(jup2.computeUnitLimit, 835_000)

      const bed2 = await bedrockAdapter.swapInstructions(
        { BEDROCK_API_URL: 'https://mock-bed.local' } as Env,
        {
          escrowPubkey: escrow1,
          inputMint: WSOL_MINT,
          outputMint: USDC_MINT,
          quoteResponse: { routePlan: [{ swapInfo: { label: 'A' } }, { swapInfo: { label: 'B' } }] },
        },
      )
      assert.equal(bed2.computeUnitLimit, 835_000)

      const df1 = await dflowAdapter.swapInstructions(
        { DFLOW_API_URL: 'https://mock-dflow.local' } as Env,
        {
          escrowPubkey: escrow1,
          inputMint: WSOL_MINT,
          outputMint: USDC_MINT,
          quoteResponse: { routePlan: [{ venue: 'Orca' }] },
        },
      )
      assert.equal(df1.computeUnitLimit, 635_000)

      const dfUnknown = await dflowAdapter.swapInstructions(
        { DFLOW_API_URL: 'https://mock-dflow.local' } as Env,
        {
          escrowPubkey: escrow1,
          inputMint: WSOL_MINT,
          outputMint: USDC_MINT,
          quoteResponse: {},
        },
      )
      assert.equal(dfUnknown.computeUnitLimit, 835_000)
    },
  )

  const titan1 = await titanAdapter.swapInstructions({} as never, {
    escrowPubkey: escrow1,
    inputMint: WSOL_MINT,
    outputMint: USDC_MINT,
    quoteResponse: { escrowPubkey: escrow1, route: { steps: [{ label: 'Orca' }], instructions: [mockSwapIx] } },
  })
  assert.equal(titan1.computeUnitLimit, 635_000)

  const titan2 = await titanAdapter.swapInstructions({} as never, {
    escrowPubkey: escrow1,
    inputMint: WSOL_MINT,
    outputMint: USDC_MINT,
    quoteResponse: {
      escrowPubkey: escrow1,
      route: { steps: [{ label: 'Orca' }, { label: 'Raydium' }], instructions: [mockSwapIx] },
    },
  })
  assert.equal(titan2.computeUnitLimit, 835_000)

  const okxBuilt = await okxAdapter.swapInstructions({} as never, {
    escrowPubkey: escrow1,
    inputMint: WSOL_MINT,
    outputMint: USDC_MINT,
    quoteResponse: { escrowPubkey: escrow1, instructionLists: [mockSwapIx] },
  })
  assert.equal(okxBuilt.computeUnitLimit, 835_000)

  // 4. End-to-end `/v1/relay/submit` with Token-2022 `ExecViaEscrow` + 1 Token-2022 `setupAta` + 1 Classic `setupAta`:
  //    `285_000 + 25_000 (T22 leg) + 350_000 (default router) + 45_000 (T22 setupAta) + 30_000 (Classic setupAta) = 735_000` CU!
  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({ activeLanes: 4, rootEpochInterval: 32n, noteRentFee: 1_000_000n, nfRentFee: 113_567n })
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)
  const accMapT22 = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveLanePdaSync(0, 0).address, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 1n, nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveLaneRentVaultPdaSync(0, 0).address, { bytes: new Uint8Array(16), lamports: 100_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
  ])
  const guardT22 = createMockGuard()
  const envT22 = {
    RELAY_GUARD: guardT22.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/r1-f4-t22-setup-ata-cu',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
  } as Env
  let sentWireT22: Uint8Array | null = null
  const resT22 = await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result:
            len === 0 ? 890_880 : len === 16 ? 1_002_240 : len === 165 ? 2_039_280 : len === SUBTREE_PAGE_LEN ? 58_352_640 : len === MEMO_PAGE_LEN ? 72_161_280 : 68_152_320,
        })
      }
      if (body.method === 'getAccountInfo') {
        const hit = accMapT22.get(String(body.params[0]))
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null },
        })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x7a)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 94_000 },
            value: addrs.map((a) => {
              const hit = accMapT22.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 94_000 },
            value: {
              err: null,
              logs: ['OK'],
              unitsConsumed: 520_000,
              accounts: [{ lamports: 492_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        sentWireT22 = fromBase64(String(body.params[0]))
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5V130R1F4T22Sig11111111111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 94_001, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R1-F4 T22 test: ${body.method}`)
    },
    () =>
      worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(t22ExecIx.data),
            accounts: t22ExecIx.accounts,
            setupAtas: [
              { owner: escrow1, mint: t22Mint, tokenProgram: TOKEN_2022_PROGRAM_ID },
              { owner: escrow1, mint: WSOL_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
            ],
          }),
        }),
        envT22,
      ),
  )
  assert.equal(resT22.status, 200)
  const bodyT22 = (await resT22.json()) as { computeUnitLimit: number }
  assert.equal(bodyT22.computeUnitLimit, 285_000 + 25_000 + 350_000 + 45_000 + 30_000)
  assert.ok(sentWireT22)
  assert.equal(decodeV1Tx(sentWireT22).computeUnitLimit, 735_000)
})

test('v1.3.0 R1-F5: firewall allows 63..96-entry ExecViaEscrow (<= 64 unique tx accounts) and rejects > 96 accounts', () => {
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const escrow1 = deriveEscrowPdaSync(0, 1).address
  const vaultWsolAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultUsdcAta = deriveAssociatedTokenAddressSync(vaultAuth, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowInAta = deriveAssociatedTokenAddressSync(escrow1, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowOutAta = deriveAssociatedTokenAddressSync(escrow1, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address

  // Build 48 router accounts where 18 duplicate escrow/mint/tokenProgram accounts + 30 distinct AMM accounts:
  // Total payload.accounts = 24 Audren prefix + 48 router = 72 entries (in 63..96),
  // while unique Solana v1 accounts = ~50 <= 64!
  const routerAccounts = [
    ...Array.from({ length: 18 }, (_, i) => ({
      pubkey:
        i % 3 === 0
          ? escrowInAta
          : i % 3 === 1
            ? escrowOutAta
            : CLASSIC_TOKEN_PROGRAM_ID,
      isSigner: false,
      isWritable: i % 3 !== 2,
    })),
    ...Array.from({ length: 30 }, (_, i) => ({
      pubkey: base58Encode(new Uint8Array(32).fill(0x20 + i)),
      isSigner: false,
      isWritable: i < 10,
    })),
  ]
  const exec72 = buildExecViaEscrowInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    escrowShard: 1,
    changeMask: 0,
    inLeg: { mint: WSOL_MINT, vaultAta: vaultWsolAta, escrowAta: escrowInAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    outLeg: { mint: USDC_MINT, vaultAta: vaultUsdcAta, escrowAta: escrowOutAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    relayerFeeAmount: 0n,
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0xf1),
    nf1: new Uint8Array(32).fill(0xf2),
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    amountIn: 100_000_000n,
    minAmountOut: 1_000_000n,
    outStealthOwner: new Uint8Array(32).fill(0x02),
    outBlinding: new Uint8Array(32).fill(0x03),
    dynMemoHead: new Uint8Array(34).fill(0x04),
    dynMemoMask: new Uint8Array(72).fill(0x05),
    routerProg: base58Encode(new Uint8Array(32).fill(0x55)),
    routerIxData: new Uint8Array([1, 2, 3]),
    routerAccounts,
    changeMemos: new Uint8Array(0),
  })
  assert.equal(exec72.accounts.length, 72)

  const verdict72 = validateRelaySubmission(
    { instructionDataB64: toBase64(exec72.data), accounts: exec72.accounts },
    relayerPubkey,
    allowedPre,
  )
  assert.equal(verdict72.decodedAccounts.length, 72)

  // Verify Solana Transaction v1 compiles cleanly with <= 64 unique accounts!
  const signed72 = buildAndSignV1Transaction(
    relayerSecret,
    base58Encode(new Uint8Array(32).fill(0x7b)),
    [
      {
        programId: base58Decode(AUDREN_PROGRAM_ID),
        accounts: verdict72.decodedAccounts,
        data: verdict72.ixData,
      },
    ],
    { computeUnitLimit: 815_000, priorityFeeLamports: 5_000n },
  )
  assert.ok(signed72.accountCount <= 64, `Expected <= 64 unique tx accounts, got ${signed72.accountCount}`)

  // > 96 accounts MUST be rejected by firewall!
  const accounts97 = [
    ...exec72.accounts,
    ...Array.from({ length: 97 - exec72.accounts.length }, () => ({
      pubkey: CLASSIC_TOKEN_PROGRAM_ID,
      isSigner: false,
      isWritable: false,
    })),
  ]
  assert.equal(accounts97.length, 97)
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructionDataB64: toBase64(exec72.data), accounts: accounts97 },
        relayerPubkey,
        allowedPre,
      ),
    (err: unknown) =>
      err instanceof FirewallError && err.message.includes('Invalid Audren account count (97)'),
  )
})

test('v1.3.0 R1-F6: Transact (Tag 5) rejects roots0Pda outside accounts[2] and rejects trailing accounts outside Token-2022 public withdrawals', () => {
  const roots0Pda = deriveRootsPdaSync(0).address
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const recipient = base58Encode(new Uint8Array(32).fill(0x3c))
  const vaultWsolAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const recipWsolAta = deriveAssociatedTokenAddressSync(recipient, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const t22Mint = base58Encode(new Uint8Array(32).fill(0xf8))
  const vaultT22Ata = deriveAssociatedTokenAddressSync(vaultAuth, t22Mint, TOKEN_2022_PROGRAM_ID).address
  const recipT22Ata = deriveAssociatedTokenAddressSync(recipient, t22Mint, TOKEN_2022_PROGRAM_ID).address
  const benignExtraAcc = { pubkey: base58Encode(new Uint8Array(32).fill(0xf9)), isSigner: false, isWritable: false }

  // 1. Token-2022 Full Exit (`outputMask === 0`, RO roots at [2]) with `{ roots0Pda, isWritable: true }`
  //    appended as a trailing hook account -> MUST BE REJECTED!
  const t22FullExitWithRootsTrailing = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: false,
    publicOutflow: { mint: t22Mint, vaultAta: vaultT22Ata, tokenProgram: TOKEN_2022_PROGRAM_ID },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0xf3),
    nf1: new Uint8Array(32).fill(0xf4),
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 100_000_000n,
    relayerFeeAmount: 0n,
    recipient: recipT22Ata,
    relayerFeeRecipient: SYSTEM_PROGRAM_ID,
    memosBytes: new Uint8Array(0),
    hookAccounts: [{ pubkey: roots0Pda, isSigner: false, isWritable: true }],
  })
  assert.throws(
    () =>
      validateRelaySubmission(
        {
          instructionDataB64: toBase64(t22FullExitWithRootsTrailing.data),
          accounts: t22FullExitWithRootsTrailing.accounts,
        },
        relayerPubkey,
        allowedPre,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('GlobalRootHistory'),
  )

  // 2. Private Transact with ANY trailing account -> REJECTED!
  const privWithTrailing = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b001,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0xf5),
    nf1: new Uint8Array(32).fill(0xf6),
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
        {
          instructionDataB64: toBase64(privWithTrailing.data),
          accounts: [...privWithTrailing.accounts, benignExtraAcc],
        },
        relayerPubkey,
        allowedPre,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('trailing accounts'),
  )

  // 3. WSOL unwrap Full Exit with trailing account (including writable roots0Pda or benign) -> REJECTED!
  const wsolUnwrapFullExit = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: true,
    publicOutflow: { mint: WSOL_MINT, vaultAta: vaultWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0xf7),
    nf1: new Uint8Array(32),
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 100_000_000n,
    relayerFeeAmount: 0n,
    recipient,
    relayerFeeRecipient: SYSTEM_PROGRAM_ID,
    memosBytes: new Uint8Array(0),
  })
  assert.throws(
    () =>
      validateRelaySubmission(
        {
          instructionDataB64: toBase64(wsolUnwrapFullExit.data),
          accounts: [...wsolUnwrapFullExit.accounts, benignExtraAcc],
        },
        relayerPubkey,
        allowedPre,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('trailing accounts'),
  )
  assert.throws(
    () =>
      validateRelaySubmission(
        {
          instructionDataB64: toBase64(wsolUnwrapFullExit.data),
          accounts: [...wsolUnwrapFullExit.accounts, { pubkey: roots0Pda, isSigner: false, isWritable: true }],
        },
        relayerPubkey,
        allowedPre,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('GlobalRootHistory'),
  )

  // 4. Classic SPL Withdraw with trailing account -> REJECTED!
  const classicWithdraw = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: false,
    publicOutflow: { mint: WSOL_MINT, vaultAta: vaultWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0xfa),
    nf1: new Uint8Array(32),
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 100_000_000n,
    relayerFeeAmount: 0n,
    recipient: recipWsolAta,
    relayerFeeRecipient: SYSTEM_PROGRAM_ID,
    memosBytes: new Uint8Array(0),
  })
  assert.throws(
    () =>
      validateRelaySubmission(
        {
          instructionDataB64: toBase64(classicWithdraw.data),
          accounts: [...classicWithdraw.accounts, benignExtraAcc],
        },
        relayerPubkey,
        allowedPre,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('trailing accounts'),
  )

  // 5. Token-2022 non-unwrap public withdraw WITH benign TransferHook trailing account -> ACCEPTED!
  const validT22Hook = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: false,
    publicOutflow: { mint: t22Mint, vaultAta: vaultT22Ata, tokenProgram: TOKEN_2022_PROGRAM_ID },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0xfb),
    nf1: new Uint8Array(32),
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 100_000_000n,
    relayerFeeAmount: 0n,
    recipient: recipT22Ata,
    relayerFeeRecipient: SYSTEM_PROGRAM_ID,
    memosBytes: new Uint8Array(0),
    hookAccounts: [benignExtraAcc],
  })
  const okVerdict = validateRelaySubmission(
    { instructionDataB64: toBase64(validT22Hook.data), accounts: validT22Hook.accounts },
    relayerPubkey,
    allowedPre,
  )
  assert.equal(okVerdict.transactMeta?.hasTrailingHookAccounts, true)
})

test('v1.3.0 R2-F1: proactiveOnlySlotSkew dropped-proactive retry simulates at processed commitment matching pinned preAccounts[0]', async () => {
  const worker = await getWorker()
  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({
    activeLanes: 4,
    rootEpochInterval: 32n,
    noteRentFee: 1_000_000n,
    nfRentFee: 113_567n,
  })
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const fvkJson = JSON.stringify({
    spendPkHex: toHex(relayerFvk.spendPk),
    nkHex: toHex(relayerFvk.nk),
    viewSkHex: toHex(relayerFvk.viewSk),
    viewPkHex: toHex(relayerFvk.viewPk),
  })

  const { cm2, memo } = makeShieldedFeeCm2(5_000_000n, wsolMintBytes, 0x61)
  const memos = new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN)
  memos.set(new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x11), 0)
  memos.set(memo, MEMO_ENTRY_WIRE_LEN)
  const privIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b101,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x61),
    nf1: new Uint8Array(32).fill(0x62),
    cm0: new Uint8Array(32).fill(0x10),
    cm1: new Uint8Array(32),
    cm2,
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: memos,
  })

  // Confirmed relayer balance is 500M; between S_conf and S_proc an auto-refill credits +100M
  // (processed balance = 600M). All 3 processed pin attempts skew, triggering proactiveOnlySlotSkew.
  // The dropped-proactive retry MUST simulate at `processed` commitment (post = 596.2M, delta = 3.8M),
  // NOT default `confirmed` (post = 496.2M -> false delta 103.8M > 50M COST_CEILING_EXCEEDED)!
  const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 86n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0RentVault, { bytes: new Uint8Array(16), lamports: 100_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
  ])

  const guard = createMockGuard()
  const env = {
    RELAY_GUARD: guard.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/v130-r2-f1-proactive-skew-commitment',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    MAINNET_RELAYER_FVK_JSON: fvkJson,
  } as Env

  let processedFetchCount = 0
  let simCount = 0
  const simCalls: Array<{ commitment: string | undefined; hasOpenPage: boolean }> = []
  let sentWire: Uint8Array | null = null

  const res = await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result:
            len === 0
              ? 890_880
              : len === 16
                ? 1_002_240
                : len === 165
                  ? 2_039_280
                  : len === SUBTREE_PAGE_LEN
                    ? 58_352_640
                    : len === MEMO_PAGE_LEN
                      ? 72_161_280
                      : 68_152_320,
        })
      }
      if (body.method === 'getAccountInfo') {
        const hit = accMap.get(String(body.params[0]))
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: hit
              ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner }
              : null,
          },
        })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x81)) } },
        })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        const opts = body.params[1] as { commitment?: string }
        const isProcessed = opts?.commitment === 'processed'
        if (isProcessed) processedFetchCount++
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: isProcessed ? 95_010 + processedFetchCount : 95_000 },
            value: addrs.map((a) => {
              if (isProcessed && a === relayerB58) {
                // +0.1 SOL credited between S_conf and S_proc
                return { data: ['', 'base64'], lamports: 600_000_000, owner: SYSTEM_PROGRAM_ID }
              }
              const hit = accMap.get(a)
              return hit
                ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner }
                : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        simCount++
        const wire = fromBase64(String(body.params[0]))
        const dec = decodeV1Tx(wire)
        const hasOpenPage = dec.instructions.some((ix) => ix.data[0] === TAG_OPEN_PAGE)
        const opts = body.params[1] as { commitment?: string; accounts?: { addresses?: string[] } }
        const watchCount = opts?.accounts?.addresses?.length ?? 1
        simCalls.push({ commitment: opts?.commitment, hasOpenPage })
        const isProcessed = opts?.commitment === 'processed'
        // Confirmed balance was 500M; processed balance is 600M -> post reflects the queried commitment!
        const postRelayer = isProcessed ? 596_200_000 : 496_200_000
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 95_900 + simCount }, // always skewed across pin attempts
            value: {
              err: null,
              logs: ['OK'],
              unitsConsumed: 150_000,
              accounts: [
                { lamports: postRelayer, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                ...Array.from({ length: Math.max(0, watchCount - 1) }, () => ({
                  lamports: 27_800_000,
                  owner: AUDREN_PROGRAM_ID,
                  data: ['', 'base64'],
                })),
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        sentWire = fromBase64(String(body.params[0]))
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5V130R2F1ProcCommitSig111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 95_910, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R2-F1 test: ${body.method}`)
    },
    () =>
      worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(privIx.data),
            accounts: privIx.accounts,
          }),
        }),
        env,
      ),
  )

  const body = (await res.json()) as {
    ok: boolean
    code?: string
    billingMode: string
    netSponsoredLamports: string
    openedPagesCount: number
    simulatedCostLamports: string
  }
  assert.equal(res.status, 200, `Expected 200 (not false COST_CEILING_EXCEEDED), got ${res.status}: ${JSON.stringify(body)}`)
  assert.equal(body.openedPagesCount, 0)
  assert.equal(body.billingMode, 'self_paying')
  assert.equal(body.netSponsoredLamports, '0')
  assert.ok(BigInt(body.simulatedCostLamports) <= 5_000_000n, `Expected cost <= 5M, got ${body.simulatedCostLamports}`)
  // 1 initial confirmed sim + 3 processed pin attempts (with proactive OpenPage) + 1 dropped-proactive processed sim
  assert.equal(simCalls.length, 5)
  assert.deepEqual(simCalls[0], { commitment: 'confirmed', hasOpenPage: true })
  assert.deepEqual(simCalls[4], { commitment: 'processed', hasOpenPage: false })
  assert.ok(sentWire)
  assert.equal(decodeV1Tx(sentWire).instructions.length, 1)
  assert.equal(guard.openPageLocks.size, 0)
})

test('v1.3.0 R2-F2: refillSinglePayer uses calibrated Math.min(1_400_000, Math.max(600_000, built.computeUnitLimit)) for multi-hop/large-CU swaps', async () => {
  const mockJup = 'https://mock-jup-r2f2.local'
  const wsolAta = deriveAssociatedTokenAddressSync(relayerB58, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const usdcAta = deriveAssociatedTokenAddressSync(relayerB58, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address

  async function runRefillCuCase(opts: {
    rpcUrl: string
    directMinOut: string
    multiHopMinOut: string
    multiHopRouteHops: number
    reportedRouterCu?: number
    minSimCuRequired?: number
  }) {
    clearPriceCache()
    const refillEnv = {
      MAINNET_RPC_URL: opts.rpcUrl,
      MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
      JUPITER_API_URL: mockJup,
    } as Env
    const refillCfg = loadPolicyConfig(refillEnv)
    const simCuLimits: number[] = []
    const sentCuLimits: number[] = []

    const report = await withMockFetch(
      async (url, init) => {
        if (url.startsWith(`${mockJup}/price/v3`)) {
          return Response.json({
            [WSOL_MINT]: { usdPrice: 150 },
            [USDC_MINT]: { usdPrice: 1 },
          })
        }
        if (url.startsWith(`${mockJup}/swap/v1/quote`)) {
          const u = new URL(url)
          const isDirect = u.searchParams.get('onlyDirectRoutes') === 'true'
          const minOut = isDirect ? opts.directMinOut : opts.multiHopMinOut
          const hopCount = isDirect ? 1 : opts.multiHopRouteHops
          const routePlan = Array.from({ length: hopCount }, (_, i) => ({
            swapInfo: {
              label: i === 0 ? 'Orca Whirlpool' : 'Meteora DLMM',
              inputMint: USDC_MINT,
              outputMint: WSOL_MINT,
              inAmount: '15000000',
              outAmount: minOut,
            },
            percent: 100,
          }))
          return Response.json({
            inputMint: USDC_MINT,
            outputMint: WSOL_MINT,
            inAmount: '15000000',
            outAmount: minOut,
            otherAmountThreshold: minOut,
            slippageBps: 100,
            routePlan,
          })
        }
        if (url.startsWith(`${mockJup}/swap/v1/swap-instructions`)) {
          return Response.json({
            swapInstruction: {
              programId: JUPITER_V6_ROUTER,
              accounts: [{ pubkey: relayerB58, isSigner: true, isWritable: true }],
              data: toBase64(new Uint8Array([1, 2, 3])),
            },
            addressLookupTableAddresses: [],
            ...(opts.reportedRouterCu !== undefined ? { computeUnitLimit: opts.reportedRouterCu } : {}),
          })
        }
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getBalance') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: 20_000_000 } })
        }
        if (body.method === 'getTokenAccountsByOwner') {
          const filter = body.params[1] as { programId: string }
          if (filter.programId === CLASSIC_TOKEN_PROGRAM_ID) {
            return Response.json({
              jsonrpc: '2.0',
              id: 1,
              result: {
                value: [
                  {
                    pubkey: usdcAta,
                    account: {
                      owner: CLASSIC_TOKEN_PROGRAM_ID,
                      data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 15_000_000n)), 'base64'],
                    },
                  },
                ],
              },
            })
          }
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [] } })
        }
        if (body.method === 'getLatestBlockhash') {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x82)) } },
          })
        }
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          if (addrs.includes(USDC_MINT)) {
            return Response.json({
              jsonrpc: '2.0',
              id: 1,
              result: {
                context: { slot: 2000 },
                value: addrs.map(() => ({
                  data: [toBase64(makeClassicMintBytes(6)), 'base64'],
                  lamports: 2_000_000,
                  owner: CLASSIC_TOKEN_PROGRAM_ID,
                })),
              },
            })
          }
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 2000 },
              value: addrs.map((a) =>
                a === relayerB58
                  ? { data: ['', 'base64'], lamports: 20_000_000, owner: SYSTEM_PROGRAM_ID }
                  : a === wsolAta
                    ? {
                        data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n)), 'base64'],
                        lamports: 2_039_280,
                        owner: CLASSIC_TOKEN_PROGRAM_ID,
                      }
                    : a === usdcAta
                      ? {
                          data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 15_000_000n)), 'base64'],
                          lamports: 2_039_280,
                          owner: CLASSIC_TOKEN_PROGRAM_ID,
                        }
                      : null,
              ),
            },
          })
        }
        if (body.method === 'simulateTransaction') {
          const dec = decodeV1Tx(fromBase64(String(body.params[0])))
          simCuLimits.push(dec.computeUnitLimit)
          const oogs = opts.minSimCuRequired !== undefined && dec.computeUnitLimit < opts.minSimCuRequired
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 2000 },
              value: {
                err: oogs ? 'ComputeBudgetExceeded' : null,
                logs: [oogs ? 'Program failed to complete: exceeded CU meter' : 'Refill Swap OK'],
                unitsConsumed: opts.minSimCuRequired ?? 580_000,
                accounts: [
                  { lamports: 20_000_000 + 98_000_000 - 25_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                  {
                    lamports: 2_039_280,
                    owner: CLASSIC_TOKEN_PROGRAM_ID,
                    data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n)), 'base64'],
                  },
                  {
                    lamports: 2_039_280,
                    owner: CLASSIC_TOKEN_PROGRAM_ID,
                    data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 0n)), 'base64'],
                  },
                ],
              },
            },
          })
        }
        if (body.method === 'sendTransaction') {
          const dec = decodeV1Tx(fromBase64(String(body.params[0])))
          sentCuLimits.push(dec.computeUnitLimit)
          return Response.json({ jsonrpc: '2.0', id: 1, result: '5V130R2F2RefillCuSig11111111111111111111111' })
        }
        if (body.method === 'getSignatureStatuses') {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: { value: [{ slot: 2001, err: null, confirmationStatus: 'confirmed' }] },
          })
        }
        throw new Error(`Unexpected RPC in R2-F2 test: ${url} ${body.method}`)
      },
      () => runAutoRefill(refillEnv, refillCfg),
    )
    return { report, simCuLimits, sentCuLimits }
  }

  // 1. Multi-hop fallback (2 hops -> built.computeUnitLimit = 285_000 + 550_000 = 835_000):
  //    must NOT OOG at 600_000 when multi-hop route needs 720_000 CU!
  const multiHop = await runRefillCuCase({
    rpcUrl: 'https://mock-rpc.local/v130-r2-f2-multihop',
    directMinOut: '1000000',
    multiHopMinOut: '98000000',
    multiHopRouteHops: 2,
    minSimCuRequired: 720_000,
  })
  assert.equal(multiHop.report.action, 'swapped_fees')
  assert.deepEqual(multiHop.simCuLimits, [835_000])
  assert.deepEqual(multiHop.sentCuLimits, [835_000])

  // 2. Large reported router CU (1_200_000 -> clamped to 1_400_000)
  const largeCu = await runRefillCuCase({
    rpcUrl: 'https://mock-rpc.local/v130-r2-f2-large-cu',
    directMinOut: '98000000',
    multiHopMinOut: '98000000',
    multiHopRouteHops: 2,
    reportedRouterCu: 1_200_000,
    minSimCuRequired: 1_300_000,
  })
  assert.equal(largeCu.report.action, 'swapped_fees')
  assert.deepEqual(largeCu.simCuLimits, [1_400_000])
  assert.deepEqual(largeCu.sentCuLimits, [1_400_000])

  // 3. Single-hop direct route (1 hop -> built.computeUnitLimit = 635_000 >= 600_000 floor)
  const singleHop = await runRefillCuCase({
    rpcUrl: 'https://mock-rpc.local/v130-r2-f2-singlehop',
    directMinOut: '98000000',
    multiHopMinOut: '98000000',
    multiHopRouteHops: 1,
  })
  assert.equal(singleHop.report.action, 'swapped_fees')
  assert.deepEqual(singleHop.simCuLimits, [635_000])
  assert.deepEqual(singleHop.sentCuLimits, [635_000])
})

test('v1.3.0 R2-F3: proactive pages require LaneRentVault alone to cover full pageRent without subtracting un-pinned existingLamports (exact rollover still subtracts)', async () => {
  const indexMod = await import('../src/index')
  const worker = indexMod.default
  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({
    activeLanes: 4,
    rootEpochInterval: 32n,
    noteRentFee: 1_000_000n,
    nfRentFee: 113_567n,
  })
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const fvkJson = JSON.stringify({
    spendPkHex: toHex(relayerFvk.spendPk),
    nkHex: toHex(relayerFvk.nk),
    viewSkHex: toHex(relayerFvk.viewSk),
    viewPkHex: toHex(relayerFvk.viewPk),
  })

  // 1. Direct `planRolloverOpenPages` unit check:
  //    At `nextLeaf = 762` (`subSeq = 2, subRem = 6 <= 26`; `memoSeq = 7, memoRem = 6 <= 10`):
  //    LaneRentVault has `avail = 120_000_000` (fits sub 58.35M or memo 72.16M individually, NOT 130.51M jointly).
  //    Even if un-pinned `unfetchedPdas` returns `sub3` pre-funded with 20M lamports, `planRolloverOpenPages`
  //    MUST deduct full `58_352_640` for `sub3` (leaving `61_647_360 < 72_161_280`) and schedule ONLY 1 proactive page!
  const sub2 = deriveSubtreePdaSync(0, 0, 2n).address
  const sub3 = deriveSubtreePdaSync(0, 0, 3n).address
  const sr0 = deriveSubrootPdaSync(0, 0, 0n).address
  const memo7 = deriveMemoPdaSync(0, 0, 7n).address
  const memo8 = deriveMemoPdaSync(0, 0, 8n).address
  const nf0Page = deriveNfPagePdaSync(0, 0, 0n).address

  const directPre = new Map<string, { bytes: Uint8Array; lamports: number; owner: string } | null>([
    [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 762n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0RentVault, { bytes: new Uint8Array(16), lamports: 120_000_000 + 1_002_240, owner: AUDREN_PROGRAM_ID }],
    [sub2, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
    [sr0, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
    [memo7, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
    [nf0Page, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
  ])
  const directFetched = new Map<string, { bytes: Uint8Array; owner: string } | null>()
  for (const [k, v] of directPre.entries()) {
    directFetched.set(k, v ? { bytes: v.bytes, owner: v.owner } : null)
  }

  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      assert.equal(body.method, 'getMultipleAccounts')
      const addrs = body.params[0] as string[]
      return Response.json({
        jsonrpc: '2.0',
        id: 1,
        result: {
          context: { slot: 96_500 },
          value: addrs.map((a) =>
            a === sub3
              ? { data: ['', 'base64'], lamports: 20_000_000, owner: SYSTEM_PROGRAM_ID } // un-pinned pre-fund!
              : null,
          ),
        },
      })
    },
    async () => {
      const plan = await indexMod.planRolloverOpenPages({
        rpcUrl: 'https://mock-rpc.local/v130-r2-f3-direct',
        payerB58: relayerB58,
        entries: [
          {
            poolId: 0,
            outLaneId: 0,
            outputCount: 1,
            nullifierCount: 2,
            pages: {
              outSub: sub2,
              outRoot: sr0,
              outMemo: memo7,
              nfPage: nf0Page,
              nextSub: null,
              nextMemo: null,
              nextNf: null,
            },
          },
        ],
        fetchedAccounts: directFetched,
        preAccountInfoMap: directPre,
        rentFloors: {
          laneRentVaultReserveFloor: 1_002_240n,
          subRentFloor: 58_352_640n,
          srRentFloor: 68_152_320n,
          memoRentFloor: 72_161_280n,
          nfPageRentFloor: 68_152_320n,
        },
      })
      assert.equal(plan.ok, true)
      if (plan.ok) {
        assert.equal(plan.exactOpenPageIxs.length, 0)
        assert.equal(
          plan.proactiveOpenPageIxs.length,
          1,
          'Un-pinned existingLamports on sub3 MUST NOT allow scheduling memo8 when vault lacks full sub+memo rent',
        )
        assert.equal(base58Encode(plan.proactiveOpenPageIxs[0]!.accounts[4]!.pubkey), sub3)
        assert.notEqual(base58Encode(plan.proactiveOpenPageIxs[0]!.accounts[4]!.pubkey), memo8)
      }
    },
  )

  // 2. End-to-end `/v1/relay/submit` check of `computeOpenPageDeficits` proactive loop:
  //    Pre-fetch has vault = 100M (`nextLeaf = 86`, proactive `memo1` rent = 72_161_280).
  //    Un-pinned `memo1` has 30M pre-funded lamports. Post-pin `processed` vault drops to 50M + reserve:
  //    `avail (50M) + existing (30M) > 72.16M`, yet `avail (50M) < full pageRent (72.16M)`!
  //    `computeOpenPageDeficits` MUST compute `proactiveDeficitFloor > 0n` (NOT subtracting 30M),
  //    drop the proactive page cleanly (`openedPagesCount === 0`), and keep `self_paying`!
  const memo1 = deriveMemoPdaSync(0, 0, 1n).address
  const { cm2: cm2Pro, memo: memoPro } = makeShieldedFeeCm2(5_000_000n, wsolMintBytes, 0x63)
  const memosPro = new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN)
  memosPro.set(new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x11), 0)
  memosPro.set(memoPro, MEMO_ENTRY_WIRE_LEN)
  const proIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b101,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x63),
    nf1: new Uint8Array(32).fill(0x64),
    cm0: new Uint8Array(32).fill(0x10),
    cm1: new Uint8Array(32),
    cm2: cm2Pro,
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: memosPro,
  })
  const accMapPro = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 86n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0RentVault, { bytes: new Uint8Array(16), lamports: 100_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
    [sr0, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
    [nf0Page, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
  ])
  const guardPro = createMockGuard()
  const envPro = {
    RELAY_GUARD: guardPro.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/v130-r2-f3-submit-proactive',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    MAINNET_RELAYER_FVK_JSON: fvkJson,
  } as Env
  let simCountPro = 0
  const resPro = await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result:
            len === 0
              ? 890_880
              : len === 16
                ? 1_002_240
                : len === 165
                  ? 2_039_280
                  : len === SUBTREE_PAGE_LEN
                    ? 58_352_640
                    : len === MEMO_PAGE_LEN
                      ? 72_161_280
                      : 68_152_320,
        })
      }
      if (body.method === 'getAccountInfo') {
        const hit = accMapPro.get(String(body.params[0]))
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: hit
              ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner }
              : null,
          },
        })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x83)) } },
        })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        const opts = body.params[1] as { commitment?: string }
        const isProcessed = opts?.commitment === 'processed'
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: isProcessed ? 96_002 : 96_000 },
            value: addrs.map((a) => {
              if (a === memo1) {
                // Pre-funded with 30M lamports (System-owned, 0 bytes)
                return { data: ['', 'base64'], lamports: 30_000_000, owner: SYSTEM_PROGRAM_ID }
              }
              if (isProcessed && a === lane0RentVault) {
                // Post-pin vault has avail = 50M (< full 72_161_280, even though 50M + 30M > 72.16M)
                return { data: [toBase64(new Uint8Array(16)), 'base64'], lamports: 50_000_000 + 1_002_240, owner: AUDREN_PROGRAM_ID }
              }
              const hit = accMapPro.get(a)
              return hit
                ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner }
                : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        simCountPro++
        const opts = body.params[1] as { accounts?: { addresses?: string[] } }
        const watchCount = opts?.accounts?.addresses?.length ?? 1
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: simCountPro === 1 ? 96_001 : 96_002 },
            value: {
              err: null,
              logs: ['OK'],
              unitsConsumed: 150_000,
              accounts: [
                { lamports: 496_200_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                ...Array.from({ length: Math.max(0, watchCount - 1) }, () => ({
                  lamports: 1_002_240,
                  owner: AUDREN_PROGRAM_ID,
                  data: ['', 'base64'],
                })),
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5V130R2F3ProDropSig111111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 96_003, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R2-F3 proactive test: ${body.method}`)
    },
    () =>
      worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(proIx.data),
            accounts: proIx.accounts,
          }),
        }),
        envPro,
      ),
  )
  assert.equal(resPro.status, 200)
  const bodyPro = (await resPro.json()) as {
    openedPagesCount: number
    billingMode: string
    netSponsoredLamports: string
  }
  assert.equal(
    bodyPro.openedPagesCount,
    0,
    'computeOpenPageDeficits MUST drop proactive page when vault < full pageRent despite pre-funded existingLamports',
  )
  assert.equal(bodyPro.billingMode, 'self_paying')
  assert.equal(bodyPro.netSponsoredLamports, '0')

  // 3. Exact mandatory rollover (`nextLeaf = 95`, `rollover: { nextMemoSeq: 1n }`) STILL subtracts
  //    pre-funded lamports on `memo1` (`22_161_280` pre-funded + `50_000_000` vault avail = exact `72_161_280` -> 0n deficit)!
  const { cm2: cm2Exact, memo: memoExact } = makeShieldedFeeCm2(5_000_000n, wsolMintBytes, 0x65)
  const memosExact = new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN)
  memosExact.set(new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x11), 0)
  memosExact.set(memoExact, MEMO_ENTRY_WIRE_LEN)
  const exactIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    rollover: { nextMemoSeq: 1n },
    outputMask: 0b101,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x65),
    nf1: new Uint8Array(32).fill(0x66),
    cm0: new Uint8Array(32).fill(0x10),
    cm1: new Uint8Array(32),
    cm2: cm2Exact,
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: memosExact,
  })
  const accMapExact = new Map(accMapPro)
  accMapExact.set(lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 95n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID })
  accMapExact.set(lane0RentVault, { bytes: new Uint8Array(16), lamports: 50_000_000 + 1_002_240, owner: AUDREN_PROGRAM_ID })
  accMapExact.set(memo1, { bytes: new Uint8Array(0), lamports: 22_161_280, owner: SYSTEM_PROGRAM_ID })
  const guardExact = createMockGuard()
  const envExact = {
    RELAY_GUARD: guardExact.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/v130-r2-f3-submit-exact',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    MAINNET_RELAYER_FVK_JSON: fvkJson,
  } as Env
  const resExact = await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result:
            len === 0
              ? 890_880
              : len === 16
                ? 1_002_240
                : len === 165
                  ? 2_039_280
                  : len === SUBTREE_PAGE_LEN
                    ? 58_352_640
                    : len === MEMO_PAGE_LEN
                      ? 72_161_280
                      : 68_152_320,
        })
      }
      if (body.method === 'getAccountInfo') {
        const hit = accMapExact.get(String(body.params[0]))
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: hit
              ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner }
              : null,
          },
        })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x84)) } },
        })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 96_100 },
            value: addrs.map((a) => {
              const hit = accMapExact.get(a)
              return hit
                ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner }
                : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        const opts = body.params[1] as { accounts?: { addresses?: string[] } }
        const watchCount = opts?.accounts?.addresses?.length ?? 1
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 96_100 },
            value: {
              err: null,
              logs: ['OK'],
              unitsConsumed: 185_000,
              accounts: [
                { lamports: 496_200_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                ...Array.from({ length: Math.max(0, watchCount - 1) }, () => ({
                  lamports: 1_002_240,
                  owner: AUDREN_PROGRAM_ID,
                  data: ['', 'base64'],
                })),
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5V130R2F3ExactSubSig11111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 96_101, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in R2-F3 exact test: ${body.method}`)
    },
    () =>
      worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(exactIx.data),
            accounts: exactIx.accounts,
          }),
        }),
        envExact,
      ),
  )
  assert.equal(resExact.status, 200)
  const bodyExact = (await resExact.json()) as {
    openedPagesCount: number
    billingMode: string
    simulatedCostLamports: string
  }
  assert.equal(bodyExact.openedPagesCount, 1)
  assert.equal(bodyExact.billingMode, 'self_paying')
  // Zero exact OpenPage deficit (pre-funded 22_161_280 + 50_000_000 vault avail == 72_161_280 full rent)
  const expectedNoDeficitFloor = 5_000n + 5_000n + 2n * (890_880n + 113_567n) + 2n * 980_508n
  assert.equal(BigInt(bodyExact.simulatedCostLamports), expectedNoDeficitFloor)
})

// ============================================================================
// Wave 2 Security & Robustness Audit Tests (Items 4, 8, 9, 10A-E)
// ============================================================================

test('v1.3.0 Wave2 Item 8: confirmed on-chain revert charges burned fee to daily_budgets, records failure strike, immediately releases open_page_locks, and caps unaudited ExecViaEscrow router priority fee', async () => {
  // 1. `waitForConfirmation` throws typed `TransactionFailedOnChainError` carrying signature, err, and slot
  const failErr = { InstructionError: [1, { Custom: 6014 }] }
  await withMockFetch(
    async () =>
      Response.json({
        jsonrpc: '2.0',
        id: 1,
        result: { value: [{ slot: 77_123, err: failErr, confirmationStatus: 'confirmed' }] },
      }),
    async () => {
      await assert.rejects(
        () => waitForConfirmation('https://mock-rpc.local/item8-wait', '5RevertedSig1111111111111111111111111111111'),
        (err: unknown) => {
          assert.ok(err instanceof TransactionFailedOnChainError)
          assert.equal(err.signature, '5RevertedSig1111111111111111111111111111111')
          assert.deepEqual(err.err, failErr)
          assert.equal(err.slot, 77_123)
          return true
        },
      )
    },
  )

  // 2. End-to-end `/v1/relay/submit` with real SQLite `RelayGuard` DO:
  //    a) Unaudited custom ExecViaEscrow router requesting `priorityFeeLamports: '50000'` is capped
  //       to `5_000n` (so worst-case revert burn = `5_000 + 5_000 = 10_000` lamports = 0.00001 SOL!).
  //    b) Even though the swap was quoted `selfPaying: true` and held an exact rollover `open_page_locks`
  //       lease, a confirmed on-chain revert (`TransactionFailedOnChainError`) MUST:
  //         - charge `burnedFeeLamports = 10_000` to `daily_budgets` (`self_paying_txs = 0`, `sponsored_txs = 1`),
  //         - insert `failed = 1` in `ip_events` (failure strike),
  //         - delete `inflight_nullifiers` immediately, AND
  //         - delete `open_page_locks` immediately (`graceTtlMs = 0`, ZERO 10s starvation!).
  //    c) Audited router (`JUPITER_V6_ROUTER`) requesting `priorityFeeLamports: '35000'` keeps full `35_000n`.
  const worker = await getWorker()
  const { RelayGuard } = await import('../src/policy/guard-do')
  const harness = createSqliteDoHarness()
  const guardDo = new RelayGuard(harness.ctx, {} as Env)
  await harness.ready()
  const doNamespace = {
    idFromName: () => ({} as DurableObjectId),
    get: () => guardDo,
  } as unknown as DurableObjectNamespace<InstanceType<typeof RelayGuard>>

  const poolPda = derivePoolPdaSync(0).address
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const escrow1 = deriveEscrowPdaSync(0, 1).address
  const vaultWsolAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultUsdcAta = deriveAssociatedTokenAddressSync(vaultAuth, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowWsolAta = deriveAssociatedTokenAddressSync(escrow1, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowUsdcAta = deriveAssociatedTokenAddressSync(escrow1, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const relayerWsolAta = deriveAssociatedTokenAddressSync(relayerB58, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n })
  const dummyPageBytes = new Uint8Array(64).fill(0x5c)
  const customRouterProg = base58Encode(new Uint8Array(32).fill(0xab))

  const buildSelfPayExec = (routerProg: string, seed: number, withMemoRollover: boolean) =>
    buildExecViaEscrowInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: 0,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: 0n,
      outNfSeq: 0n,
      ...(withMemoRollover ? { rollover: { nextMemoSeq: 1n } } : {}),
      escrowShard: 1,
      changeMask: 0,
      inLeg: { mint: WSOL_MINT, vaultAta: vaultWsolAta, escrowAta: escrowWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
      outLeg: { mint: USDC_MINT, vaultAta: vaultUsdcAta, escrowAta: escrowUsdcAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
      relayerFeeAmount: 10_000_000n,
      relayerFeeRecipient: relayerWsolAta,
      feeOnOutput: false,
      proof192: dummyProof,
      nf0: new Uint8Array(32).fill(seed),
      nf1: new Uint8Array(32).fill(seed + 1),
      cm0: new Uint8Array(32),
      cm1: new Uint8Array(32),
      cm2: new Uint8Array(32),
      amountIn: 100_000_000n,
      minAmountOut: 1_000_000n,
      outStealthOwner: new Uint8Array(32).fill(0x02),
      outBlinding: new Uint8Array(32).fill(0x03),
      dynMemoHead: new Uint8Array(34).fill(0x04),
      dynMemoMask: new Uint8Array(72).fill(0x05),
      routerProg,
      routerIxData: new Uint8Array([1, 2, 3]),
      routerAccounts: [{ pubkey: base58Encode(new Uint8Array(32).fill(0x66)), isSigner: false, isWritable: true }],
      changeMemos: new Uint8Array(0),
    })

  const customExecIx = buildSelfPayExec(customRouterProg, 0x81, true)
  const auditedExecIx = buildSelfPayExec(JUPITER_V6_ROUTER, 0x83, false)

  const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [relayerWsolAta, { bytes: makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n), lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }],
    [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 95n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0RentVault, { bytes: new Uint8Array(16), lamports: 200_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
  ])

  const env = {
    RELAY_GUARD: doNamespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/item8-e2e',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
  } as Env

  let confirmMode: 'revert' | 'ok' = 'revert'
  const sentWires: Uint8Array[] = []
  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result:
            len === 0
              ? 890_880
              : len === 16
                ? 1_002_240
                : len === 165
                  ? 2_039_280
                  : len === SUBTREE_PAGE_LEN
                    ? 58_352_640
                    : len === MEMO_PAGE_LEN
                      ? 72_161_280
                      : 68_152_320,
        })
      }
      if (body.method === 'getAccountInfo') {
        const hit = accMap.get(String(body.params[0]))
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null },
        })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x91)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 99_000 },
            value: addrs.map((a) => {
              const hit = accMap.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        const opts = body.params[1] as { accounts?: { addresses?: string[] } }
        const watchAddrs = opts?.accounts?.addresses ?? [relayerB58, relayerWsolAta]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 99_000 },
            value: {
              err: null,
              logs: ['Exec OK'],
              unitsConsumed: 450_000,
              accounts: watchAddrs.map((a) =>
                a === relayerB58
                  ? { lamports: 496_900_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }
                  : a === relayerWsolAta
                    ? { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 10_000_000n)), 'base64'] }
                    : { lamports: 127_838_720, owner: AUDREN_PROGRAM_ID, data: [toBase64(new Uint8Array(16)), 'base64'] },
              ),
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        sentWires.push(fromBase64(String(body.params[0])))
        return Response.json({ jsonrpc: '2.0', id: 1, result: `5Item8Sig${sentWires.length}1111111111111111111111111111111` })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: [
              confirmMode === 'revert'
                ? { slot: 99_001, err: failErr, confirmationStatus: 'confirmed' }
                : { slot: 99_002, err: null, confirmationStatus: 'confirmed' },
            ],
          },
        })
      }
      throw new Error(`Unexpected RPC in Item 8 test: ${body.method}`)
    },
    async () => {
      // 2a. Unaudited router requesting 50_000 priority fee reverts on-chain
      confirmMode = 'revert'
      const revRes = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.8' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(customExecIx.data),
            accounts: customExecIx.accounts,
            priorityFeeLamports: '50000',
          }),
        }),
        env,
      )
      assert.equal(revRes.status, 502)
      assert.equal(sentWires.length, 1)
      const decodedCustom = decodeV1Tx(sentWires[0]!)
      assert.equal(
        decodedCustom.priorityFeeLamports,
        5_000n,
        'Unaudited ExecViaEscrow router MUST cap priorityFeeLamports at 5_000n',
      )

      // Verify `daily_budgets` charged exact `5_000 + 5_000 = 10_000` lamports even though tx was `self_paying`!
      const budgetRow = harness.db
        .prepare('SELECT sponsored_lamports, sponsored_txs, self_paying_txs, total_txs FROM daily_budgets WHERE cluster = ?')
        .get('mainnet') as { sponsored_lamports: number; sponsored_txs: number; self_paying_txs: number; total_txs: number }
      assert.equal(budgetRow.sponsored_lamports, 10_000)
      assert.equal(budgetRow.sponsored_txs, 1)
      assert.equal(budgetRow.self_paying_txs, 0)
      assert.equal(budgetRow.total_txs, 1)

      // Verify failure strike (`failed = 1`) recorded in `ip_events`
      const failEvent = harness.db
        .prepare('SELECT sponsored_lamports, self_paying, failed FROM ip_events ORDER BY id DESC LIMIT 1')
        .get() as { sponsored_lamports: number; self_paying: number; failed: number }
      assert.equal(failEvent.failed, 1)
      assert.equal(failEvent.self_paying, 0)
      assert.equal(failEvent.sponsored_lamports, 10_000)

      // Verify `inflight_nullifiers` and `open_page_locks` were BOTH released IMMEDIATELY (zero 10s grace lock!)
      const inflightCount = harness.db.prepare('SELECT COUNT(*) AS cnt FROM inflight_nullifiers').get() as { cnt: number }
      assert.equal(inflightCount.cnt, 0)
      const lockCount = harness.db.prepare('SELECT COUNT(*) AS cnt FROM open_page_locks').get() as { cnt: number }
      assert.equal(lockCount.cnt, 0, 'Confirmed on-chain revert MUST immediately release open_page_locks without 10s grace')

      // 2b. Audited router (`JUPITER_V6_ROUTER`) retains full `35_000n` priority fee!
      confirmMode = 'ok'
      accMap.set(lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 10n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID })
      const okRes = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.9' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(auditedExecIx.data),
            accounts: auditedExecIx.accounts,
            priorityFeeLamports: '35000',
          }),
        }),
        env,
      )
      assert.equal(okRes.status, 200)
      const okBody = (await okRes.json()) as { priorityFeeLamports: string }
      assert.equal(okBody.priorityFeeLamports, '35000')
      assert.equal(decodeV1Tx(sentWires[1]!).priorityFeeLamports, 35_000n)
    },
  )
})

test('v1.3.0 Wave2 Item 9: refillSinglePayer blocks cross-ATA drain via account allowlist, extra signer check, and post-simulation balance/owner/close verification', async () => {
  const mockJup = 'https://mock-jup-item9.local'
  const USDT_MINT = 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB'
  const wsolAta = deriveAssociatedTokenAddressSync(relayerB58, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const usdcAta = deriveAssociatedTokenAddressSync(relayerB58, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const usdtAta = deriveAssociatedTokenAddressSync(relayerB58, USDT_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const randomExtraSigner = base58Encode(new Uint8Array(32).fill(0x7c))

  const runRefillCrossAtaCase = async (opts: {
    rpcUrl: string
    swapAccounts: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }>
    includeNonZeroUsdt: boolean
    postUsdtOverride?: {
      closed?: boolean
      owner?: string
      amount?: bigint
      closeAuthorityByte?: number
    }
  }) => {
    const refillEnv = {
      MAINNET_RPC_URL: opts.rpcUrl,
      MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
      JUPITER_API_URL: mockJup,
    } as Env
    const refillCfg = loadPolicyConfig(refillEnv)
    let simCalls = 0
    let sendCalls = 0
    let watchedAddressesSeen: string[] = []

    const makeUsdtBytes = (amt: bigint, closeOpt?: number) => {
      const b = makeTokenAccountBytes(USDT_MINT, relayerB58, amt)
      if (closeOpt !== undefined) {
        b[129] = closeOpt
        b.fill(0xee, 133, 165)
      }
      return b
    }

    const report = await withMockFetch(
      async (url, init) => {
        if (url.startsWith(`${mockJup}/price/v3`)) {
          return Response.json({
            [WSOL_MINT]: { usdPrice: 150 },
            [USDC_MINT]: { usdPrice: 1 },
            [USDT_MINT]: { usdPrice: 1 },
          })
        }
        if (url.startsWith(`${mockJup}/swap/v1/quote`)) {
          const u = new URL(url)
          return Response.json({
            inputMint: u.searchParams.get('inputMint'),
            outputMint: WSOL_MINT,
            inAmount: u.searchParams.get('amount'),
            outAmount: '100000000',
            otherAmountThreshold: '98000000',
            slippageBps: 100,
            routePlan: [{ swapInfo: { label: 'Orca' }, percent: 100 }],
          })
        }
        if (url.startsWith(`${mockJup}/swap/v1/swap-instructions`)) {
          return Response.json({
            swapInstruction: {
              programId: JUPITER_V6_ROUTER,
              accounts: opts.swapAccounts,
              data: toBase64(new Uint8Array([1, 2, 3])),
            },
            addressLookupTableAddresses: [],
          })
        }
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getBalance') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: 20_000_000 } })
        }
        if (body.method === 'getTokenAccountsByOwner') {
          const filter = body.params[1] as { programId: string }
          if (filter.programId === CLASSIC_TOKEN_PROGRAM_ID) {
            return Response.json({
              jsonrpc: '2.0',
              id: 1,
              result: {
                value: [
                  {
                    pubkey: usdcAta,
                    account: { owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 15_000_000n)), 'base64'] },
                  },
                  ...(opts.includeNonZeroUsdt
                    ? [
                        {
                          pubkey: usdtAta,
                          account: { owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeUsdtBytes(50_000_000n)), 'base64'] },
                        },
                      ]
                    : []),
                ],
              },
            })
          }
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [] } })
        }
        if (body.method === 'getLatestBlockhash') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x92)) } } })
        }
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          if (addrs.includes(USDC_MINT) || addrs.includes(USDT_MINT)) {
            return Response.json({
              jsonrpc: '2.0',
              id: 1,
              result: {
                context: { slot: 3000 },
                value: addrs.map(() => ({ data: [toBase64(makeClassicMintBytes(6)), 'base64'], lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID })),
              },
            })
          }
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 3000 },
              value: addrs.map((a) =>
                a === relayerB58
                  ? { data: ['', 'base64'], lamports: 20_000_000, owner: SYSTEM_PROGRAM_ID }
                  : a === wsolAta
                    ? { data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n)), 'base64'], lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }
                    : a === usdtAta
                      ? { data: [toBase64(makeUsdtBytes(50_000_000n)), 'base64'], lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }
                      : a === usdcAta
                        ? { data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 15_000_000n)), 'base64'], lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }
                        : null,
              ),
            },
          })
        }
        if (body.method === 'simulateTransaction') {
          simCalls++
          const simOpts = body.params[1] as { accounts?: { addresses?: string[] } }
          watchedAddressesSeen = simOpts?.accounts?.addresses ?? []
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 3000 },
              value: {
                err: null,
                logs: ['Refill Swap OK'],
                unitsConsumed: 180_000,
                accounts: watchedAddressesSeen.map((a) => {
                  if (a === relayerB58) {
                    return { lamports: 118_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }
                  }
                  if (a === wsolAta) {
                    return { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n)), 'base64'] }
                  }
                  if (a === usdtAta) {
                    if (opts.postUsdtOverride?.closed) return null
                    return {
                      lamports: 2_039_280,
                      owner: opts.postUsdtOverride?.owner ?? CLASSIC_TOKEN_PROGRAM_ID,
                      data: [
                        toBase64(
                          makeUsdtBytes(
                            opts.postUsdtOverride?.amount ?? 50_000_000n,
                            opts.postUsdtOverride?.closeAuthorityByte,
                          ),
                        ),
                        'base64',
                      ],
                    }
                  }
                  if (a === usdcAta) {
                    return { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 15_000_000n)), 'base64'] }
                  }
                  return null
                }),
              },
            },
          })
        }
        if (body.method === 'sendTransaction') {
          sendCalls++
          return Response.json({ jsonrpc: '2.0', id: 1, result: '5Item9RefillCleanSig11111111111111111111111' })
        }
        if (body.method === 'getSignatureStatuses') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 3001, err: null, confirmationStatus: 'confirmed' }] } })
        }
        throw new Error(`Unexpected RPC in Item 9 test: ${url} ${body.method}`)
      },
      () => runAutoRefill(refillEnv, refillCfg),
    )
    return { report, simCalls, sendCalls, watchedAddressesSeen }
  }

  // Case A: Swap instruction references another canonical selfPayFeeMints ATA (USDT) -> rejected BEFORE simulation!
  const caseA = await runRefillCrossAtaCase({
    rpcUrl: 'https://mock-rpc.local/item9-other-ata',
    includeNonZeroUsdt: false,
    swapAccounts: [
      { pubkey: relayerB58, isSigner: true, isWritable: true },
      { pubkey: usdcAta, isSigner: false, isWritable: true },
      { pubkey: usdtAta, isSigner: false, isWritable: true },
    ],
  })
  assert.equal(caseA.simCalls, 0)
  assert.equal(caseA.sendCalls, 0)
  assert.ok(caseA.report.details.some((d) => d.includes('other relayer-owned token account')))

  // Case B: Swap instruction marks an account other than relayerB58 as isSigner -> rejected BEFORE simulation!
  const caseB = await runRefillCrossAtaCase({
    rpcUrl: 'https://mock-rpc.local/item9-extra-signer',
    includeNonZeroUsdt: false,
    swapAccounts: [
      { pubkey: relayerB58, isSigner: true, isWritable: true },
      { pubkey: randomExtraSigner, isSigner: true, isWritable: false },
    ],
  })
  assert.equal(caseB.simCalls, 0)
  assert.equal(caseB.sendCalls, 0)
  assert.ok(caseB.report.details.some((d) => d.includes('unexpected signer')))

  // Case C: Post-simulation cross-ATA balance decrease on watched non-zero USDT ATA -> rejected before send!
  const caseC = await runRefillCrossAtaCase({
    rpcUrl: 'https://mock-rpc.local/item9-balance-drop',
    includeNonZeroUsdt: true,
    swapAccounts: [
      { pubkey: relayerB58, isSigner: true, isWritable: true },
      { pubkey: usdcAta, isSigner: false, isWritable: true },
    ],
    postUsdtOverride: { amount: 40_000_000n },
  })
  assert.ok(caseC.watchedAddressesSeen.includes(usdtAta), 'Non-zero other owned ATA MUST be watched in simulation')
  assert.equal(caseC.sendCalls, 0)
  assert.ok(caseC.report.details.some((d) => d.includes('balance decreased')))

  // Case D: Post-simulation cross-ATA close or close_authority mutation -> rejected before send!
  const caseDClosed = await runRefillCrossAtaCase({
    rpcUrl: 'https://mock-rpc.local/item9-ata-closed',
    includeNonZeroUsdt: true,
    swapAccounts: [{ pubkey: relayerB58, isSigner: true, isWritable: true }],
    postUsdtOverride: { closed: true },
  })
  assert.equal(caseDClosed.sendCalls, 0)
  assert.ok(caseDClosed.report.details.some((d) => d.includes('missing or closed')))

  const caseDCloseAuth = await runRefillCrossAtaCase({
    rpcUrl: 'https://mock-rpc.local/item9-close-auth',
    includeNonZeroUsdt: true,
    swapAccounts: [{ pubkey: relayerB58, isSigner: true, isWritable: true }],
    postUsdtOverride: { closeAuthorityByte: 1 },
  })
  assert.equal(caseDCloseAuth.sendCalls, 0)
  assert.ok(caseDCloseAuth.report.details.some((d) => d.includes('close authority')))

  // Case E: Clean swap where watched non-zero USDT ATA is untouched succeeds!
  const caseE = await runRefillCrossAtaCase({
    rpcUrl: 'https://mock-rpc.local/item9-clean',
    includeNonZeroUsdt: true,
    swapAccounts: [{ pubkey: relayerB58, isSigner: true, isWritable: true }],
  })
  assert.equal(caseE.report.action, 'swapped_fees')
  assert.ok(caseE.sendCalls >= 1)
})

test('v1.3.0 Wave2 Item 10A: preCtxCommitment preserves processed commitment on proactiveDeficit and sim.err proactive-drop retries', async () => {
  const worker = await getWorker()
  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({ activeLanes: 4, rootEpochInterval: 32n, noteRentFee: 1_000_000n, nfRentFee: 113_567n })
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const fvkJson = JSON.stringify({
    spendPkHex: toHex(relayerFvk.spendPk),
    nkHex: toHex(relayerFvk.nk),
    viewSkHex: toHex(relayerFvk.viewSk),
    viewPkHex: toHex(relayerFvk.viewPk),
  })

  const runProactiveDropCommitmentCase = async (mode: 'deficit' | 'sim_err') => {
    const seed = mode === 'deficit' ? 0x71 : 0x73
    const { cm2, memo } = makeShieldedFeeCm2(5_000_000n, wsolMintBytes, seed)
    const memos = new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN)
    memos.set(new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x11), 0)
    memos.set(memo, MEMO_ENTRY_WIRE_LEN)
    const privIx = buildTransactInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: 0,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: 0n,
      outNfSeq: 0n,
      outputMask: 0b101,
      assetMode: ASSET_MODE_PRIVATE,
      proof192: dummyProof,
      nf0: new Uint8Array(32).fill(seed),
      nf1: new Uint8Array(32).fill(seed + 1),
      cm0: new Uint8Array(32).fill(0x10),
      cm1: new Uint8Array(32),
      cm2,
      publicAmountOut: 0n,
      relayerFeeAmount: 0n,
      memosBytes: memos,
    })

    const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
      [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
      [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 86n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0RentVault, { bytes: new Uint8Array(16), lamports: 100_000_000, owner: AUDREN_PROGRAM_ID }],
      [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
      [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
      [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
      [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
    ])

    const guard = createMockGuard()
    const env = {
      RELAY_GUARD: guard.namespace,
      MAINNET_RPC_URL: `https://mock-rpc.local/item10a-${mode}`,
      MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
      MAINNET_RELAYER_FVK_JSON: fvkJson,
    } as Env

    let simIdx = 0
    const retryCommitments: Array<string | undefined> = []

    const res = await withMockFetch(
      async (_url, init) => {
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getMinimumBalanceForRentExemption') {
          const len = Number(body.params[0])
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result:
              len === 0
                ? 890_880
                : len === 16
                  ? 1_002_240
                  : len === 165
                    ? 2_039_280
                    : len === SUBTREE_PAGE_LEN
                      ? 58_352_640
                      : len === MEMO_PAGE_LEN
                        ? 72_161_280
                        : 68_152_320,
          })
        }
        if (body.method === 'getAccountInfo') {
          const hit = accMap.get(String(body.params[0]))
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: { value: hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null },
          })
        }
        if (body.method === 'getLatestBlockhash') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(seed)) } } })
        }
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          const opts = body.params[1] as { commitment?: string }
          const isProcessed = opts?.commitment === 'processed'
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: isProcessed ? 97_002 : 97_000 },
              value: addrs.map((a) => {
                if (isProcessed && a === relayerB58) {
                  // +0.1 SOL credited between confirmed and processed!
                  return { data: ['', 'base64'], lamports: 600_000_000, owner: SYSTEM_PROGRAM_ID }
                }
                if (isProcessed && mode === 'deficit' && a === lane0RentVault) {
                  // Vault dropped below memo rent at processed -> triggers `proactiveDeficit > 0n`!
                  return { data: [toBase64(new Uint8Array(16)), 'base64'], lamports: 10_000_000, owner: AUDREN_PROGRAM_ID }
                }
                const hit = accMap.get(a)
                return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
              }),
            },
          })
        }
        if (body.method === 'simulateTransaction') {
          simIdx++
          const wire = fromBase64(String(body.params[0]))
          const hasOpenPage = decodeV1Tx(wire).instructions.some((ix) => ix.data[0] === TAG_OPEN_PAGE)
          const opts = body.params[1] as { commitment?: string; accounts?: { addresses?: string[] } }
          const watchCount = opts?.accounts?.addresses?.length ?? 1
          if (!hasOpenPage) retryCommitments.push(opts?.commitment)
          const isProcessed = opts?.commitment === 'processed'
          // Sim #1 (confirmed, with OpenPage): slot 97_001 != preCtx 97_000 -> triggers processed pinning
          // Sim #2 (processed, with OpenPage):
          //   - mode === 'deficit': succeeds at slot 97_002, then `proactiveDeficit > 0n` drops proactive page
          //   - mode === 'sim_err': fails with `InstructionError` at slot 97_002, then drops proactive page
          // Sim #3 (dropped proactive): MUST run at `processed` (postRelayer = 596.2M matching pre = 600M)!
          // If it regressed to `confirmed`, postRelayer would be 496.2M -> delta 103.8M -> 400 COST_CEILING_EXCEEDED!
          const returnErr = mode === 'sim_err' && simIdx === 2 ? { InstructionError: [0, 'Custom'] } : null
          const postRelayer = isProcessed ? 596_200_000 : 496_200_000
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: simIdx === 1 ? 97_001 : isProcessed ? 97_002 : 97_000 },
              value: {
                err: returnErr,
                logs: [returnErr ? 'Proactive OpenPage failed' : 'OK'],
                unitsConsumed: 150_000,
                accounts: [
                  { lamports: postRelayer, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                  ...Array.from({ length: Math.max(0, watchCount - 1) }, () => ({
                    lamports: 1_002_240,
                    owner: AUDREN_PROGRAM_ID,
                    data: ['', 'base64'],
                  })),
                ],
              },
            },
          })
        }
        if (body.method === 'sendTransaction') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: `5Item10ASig${mode}11111111111111111111111` })
        }
        if (body.method === 'getSignatureStatuses') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 97_003, err: null, confirmationStatus: 'confirmed' }] } })
        }
        throw new Error(`Unexpected RPC in Item 10A (${mode}): ${body.method}`)
      },
      () =>
        worker.fetch(
          new Request('https://relay.audren.xyz/v1/relay/submit', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              cluster: 'mainnet',
              instructionDataB64: toBase64(privIx.data),
              accounts: privIx.accounts,
            }),
          }),
          env,
        ),
    )
    assert.equal(res.status, 200, `Item 10A (${mode}) retry MUST preserve processed commitment and succeed`)
    const jsonBody = (await res.json()) as { openedPagesCount: number; billingMode: string }
    assert.equal(jsonBody.openedPagesCount, 0)
    assert.equal(jsonBody.billingMode, 'self_paying')
    assert.deepEqual(retryCommitments, ['processed'])
  }

  await runProactiveDropCommitmentCase('deficit')
  await runProactiveDropCommitmentCase('sim_err')
})

test('v1.3.0 Wave2 Item 10B: handleRelaySubmit (503 SLOT_SKEW) and refillSinglePayer fail CLOSED when preCtx.slot or sim.slot is null', async () => {
  const worker = await getWorker()
  const poolPda = derivePoolPdaSync(0).address
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n })
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)

  const privIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0b001,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x75),
    nf1: new Uint8Array(32).fill(0x76),
    cm0: new Uint8Array(32).fill(0x11),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x22),
  })

  const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 1n, nfCount: 1n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0RentVault, { bytes: new Uint8Array(16), lamports: 100_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
  ])

  for (const nullSide of ['pre', 'sim'] as const) {
    const guard = createMockGuard()
    const env = {
      RELAY_GUARD: guard.namespace,
      MAINNET_RPC_URL: `https://mock-rpc.local/item10b-submit-${nullSide}`,
      MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    } as Env
    let simCalls = 0
    let sendCalls = 0
    const res = await withMockFetch(
      async (_url, init) => {
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getMinimumBalanceForRentExemption') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: 890_880 })
        }
        if (body.method === 'getAccountInfo') {
          const hit = accMap.get(String(body.params[0]))
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null } })
        }
        if (body.method === 'getLatestBlockhash') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x77)) } } })
        }
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              ...(nullSide === 'pre' ? {} : { context: { slot: 98_000 } }),
              value: addrs.map((a) => {
                const hit = accMap.get(a)
                return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
              }),
            },
          })
        }
        if (body.method === 'simulateTransaction') {
          simCalls++
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              ...(nullSide === 'sim' ? {} : { context: { slot: 98_000 } }),
              value: {
                err: null,
                logs: ['OK'],
                unitsConsumed: 150_000,
                accounts: [{ lamports: 497_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }],
              },
            },
          })
        }
        if (body.method === 'sendTransaction') {
          sendCalls++
          return Response.json({ jsonrpc: '2.0', id: 1, result: '5ShouldNeverSendNullSlot111111111111111111' })
        }
        throw new Error(`Unexpected RPC in Item 10B submit (${nullSide}): ${body.method}`)
      },
      () =>
        worker.fetch(
          new Request('https://relay.audren.xyz/v1/relay/submit', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              cluster: 'mainnet',
              instructionDataB64: toBase64(privIx.data),
              accounts: privIx.accounts,
            }),
          }),
          env,
        ),
    )
    assert.equal(res.status, 503, `handleRelaySubmit MUST fail closed 503 when ${nullSide} slot is null`)
    const errBody = (await res.json()) as { code: string }
    assert.equal(errBody.code, 'SLOT_SKEW')
    assert.equal(simCalls, 4, 'Null slot MUST execute initial sim + 3 pin retries before failing closed')
    assert.equal(sendCalls, 0)
  }

  // 2. `refillSinglePayer` fails closed (skips swap, 0 sendTransaction) when `sim.slot === null`!
  const mockJup = 'https://mock-jup-item10b.local'
  const wsolAta = deriveAssociatedTokenAddressSync(relayerB58, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const usdcAta = deriveAssociatedTokenAddressSync(relayerB58, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const refillEnv = {
    MAINNET_RPC_URL: 'https://mock-rpc.local/item10b-refill-null-slot',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    JUPITER_API_URL: mockJup,
  } as Env
  const refillCfg = loadPolicyConfig(refillEnv)
  let refillSimCalls = 0
  let refillSendCalls = 0
  const refillReport = await withMockFetch(
    async (url, init) => {
      if (url.startsWith(`${mockJup}/price/v3`)) {
        return Response.json({ [WSOL_MINT]: { usdPrice: 150 }, [USDC_MINT]: { usdPrice: 1 } })
      }
      if (url.startsWith(`${mockJup}/swap/v1/quote`)) {
        return Response.json({
          inputMint: USDC_MINT,
          outputMint: WSOL_MINT,
          inAmount: '15000000',
          outAmount: '100000000',
          otherAmountThreshold: '98000000',
          slippageBps: 100,
          routePlan: [{ swapInfo: { label: 'Orca' }, percent: 100 }],
        })
      }
      if (url.startsWith(`${mockJup}/swap/v1/swap-instructions`)) {
        return Response.json({
          swapInstruction: {
            programId: JUPITER_V6_ROUTER,
            accounts: [{ pubkey: relayerB58, isSigner: true, isWritable: true }],
            data: toBase64(new Uint8Array([1, 2, 3])),
          },
          addressLookupTableAddresses: [],
        })
      }
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getBalance') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: 20_000_000 } })
      }
      if (body.method === 'getTokenAccountsByOwner') {
        const filter = body.params[1] as { programId: string }
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value:
              filter.programId === CLASSIC_TOKEN_PROGRAM_ID
                ? [{ pubkey: usdcAta, account: { owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 15_000_000n)), 'base64'] } }]
                : [],
          },
        })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x78)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        if (addrs.includes(USDC_MINT)) {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: { context: { slot: 4000 }, value: addrs.map(() => ({ data: [toBase64(makeClassicMintBytes(6)), 'base64'], lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID })) },
          })
        }
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 4000 },
            value: addrs.map((a) =>
              a === relayerB58
                ? { data: ['', 'base64'], lamports: 20_000_000, owner: SYSTEM_PROGRAM_ID }
                : a === wsolAta
                  ? { data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n)), 'base64'], lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }
                  : null,
            ),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        refillSimCalls++
        // Omit `context.slot` -> `sim.slot === null`!
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: {
              err: null,
              logs: ['OK'],
              unitsConsumed: 180_000,
              accounts: [
                { lamports: 118_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n)), 'base64'] },
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        refillSendCalls++
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5ShouldNeverSendRefillNullSlot11111111111' })
      }
      throw new Error(`Unexpected RPC in Item 10B refill: ${url} ${body.method}`)
    },
    () => runAutoRefill(refillEnv, refillCfg),
  )
  assert.equal(refillReport.action, 'no_fees_to_swap')
  assert.equal(refillSimCalls, 4)
  assert.equal(refillSendCalls, 0)
  assert.ok(refillReport.details.some((d) => d.includes('missing slot context')))
})

test('v1.3.0 Wave2 Item 10C: planMissingOpenPageIxs skips nextSub and nextMemo on Full Exits (outputCount === 0) while preserving nextNf and spoofed-PDA rejection', () => {
  const laneAcc = {
    bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 255n, nfCount: 599n }),
    owner: AUDREN_PROGRAM_ID,
  }
  const initPage = { bytes: new Uint8Array(64).fill(0x5a), owner: AUDREN_PROGRAM_ID }
  const outSub = deriveSubtreePdaSync(0, 0, 0n).address
  const outRoot = deriveSubrootPdaSync(0, 0, 0n).address
  const outMemo = deriveMemoPdaSync(0, 0, 2n).address
  const nfPage = deriveNfPagePdaSync(0, 0, 0n).address
  const nextSub = deriveSubtreePdaSync(0, 0, 1n).address
  const nextMemo = deriveMemoPdaSync(0, 0, 3n).address
  const nextNf = deriveNfPagePdaSync(0, 0, 1n).address

  const pages = { outSub, outRoot, outMemo, nfPage, nextSub, nextMemo, nextNf }
  const pageSlots = [
    { slot: 'outSub' as const, pda: outSub },
    { slot: 'outRoot' as const, pda: outRoot },
    { slot: 'outMemo' as const, pda: outMemo },
    { slot: 'nfPage' as const, pda: nfPage },
    { slot: 'nextSub' as const, pda: nextSub },
    { slot: 'nextMemo' as const, pda: nextMemo },
    { slot: 'nextNf' as const, pda: nextNf },
  ]
  const pageAccs = [initPage, initPage, initPage, initPage, null, null, null]

  // 1. Full Exit (`outputCount === 0`, `nullifierCount === 2`) skips `nextSub` & `nextMemo`, opening ONLY `nextNf`!
  const fullExitPlan = planMissingOpenPageIxs({
    payerB58: relayerB58,
    poolId: 0,
    outLaneId: 0,
    laneAcc,
    pages,
    pageSlots,
    pageAccs,
    outputCount: 0,
    nullifierCount: 2,
  })
  assert.equal(fullExitPlan.ok, true)
  if (fullExitPlan.ok) {
    assert.equal(fullExitPlan.openPageIxs.length, 1, 'Full Exit MUST skip nextSub and nextMemo and open ONLY nextNf')
    assert.equal(fullExitPlan.openPageIxs[0]!.data[1], OPEN_PAGE_KIND_NULLIFIER)
    assert.equal(base58Encode(fullExitPlan.openPageIxs[0]!.accounts[4]!.pubkey), nextNf)
  }

  // 2. Spoofed `nextSub` PDA on Full Exit is STILL rejected (`ok: false`)!
  const spoofedSub = base58Encode(new Uint8Array(32).fill(0xfe))
  const spoofedPlan = planMissingOpenPageIxs({
    payerB58: relayerB58,
    poolId: 0,
    outLaneId: 0,
    laneAcc,
    pages: { ...pages, nextSub: spoofedSub },
    pageSlots: pageSlots.map((s) => (s.slot === 'nextSub' ? { slot: 'nextSub' as const, pda: spoofedSub } : s)),
    pageAccs,
    outputCount: 0,
    nullifierCount: 2,
  })
  assert.equal(spoofedPlan.ok, false)
})

test('v1.3.0 Wave2 Item 10D: ExecViaEscrow firewall rejects duplicate GlobalRootHistory (audren_roots) at ANY index i !== 2', () => {
  const allowedPre = new Set(DEFAULT_ALLOWED_PRE_IX_PROGRAMS)
  const rootsPda = deriveRootsPdaSync(0).address
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const escrow1 = deriveEscrowPdaSync(0, 1).address
  const vaultWsolAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultUsdcAta = deriveAssociatedTokenAddressSync(vaultAuth, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowWsolAta = deriveAssociatedTokenAddressSync(escrow1, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowUsdcAta = deriveAssociatedTokenAddressSync(escrow1, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address

  const buildBaseExec = (routerProg: string, overrideAccIdx?: number) => {
    const ix = buildExecViaEscrowInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: 0,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: 0n,
      outNfSeq: 0n,
      rollover: { nextMemoSeq: 1n },
      escrowShard: 1,
      changeMask: 0,
      inLeg: { mint: WSOL_MINT, vaultAta: vaultWsolAta, escrowAta: escrowWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
      outLeg: { mint: USDC_MINT, vaultAta: vaultUsdcAta, escrowAta: escrowUsdcAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
      relayerFeeAmount: 0n,
      proof192: dummyProof,
      nf0: new Uint8Array(32).fill(0x91),
      nf1: new Uint8Array(32).fill(0x92),
      cm0: new Uint8Array(32),
      cm1: new Uint8Array(32),
      cm2: new Uint8Array(32),
      amountIn: 100_000_000n,
      minAmountOut: 1_000_000n,
      outStealthOwner: new Uint8Array(32).fill(0x02),
      outBlinding: new Uint8Array(32).fill(0x03),
      dynMemoHead: new Uint8Array(34).fill(0x04),
      dynMemoMask: new Uint8Array(72).fill(0x05),
      routerProg,
      routerIxData: new Uint8Array([1, 2, 3]),
      routerAccounts: [{ pubkey: base58Encode(new Uint8Array(32).fill(0x66)), isSigner: false, isWritable: true }],
      changeMemos: new Uint8Array(0),
    })
    const accounts = ix.accounts.map((a, i) =>
      overrideAccIdx !== undefined && i === overrideAccIdx ? { ...a, pubkey: rootsPda } : a,
    )
    return { data: ix.data, accounts }
  }

  // 1. `roots0Pda` placed at `accounts[12]` (`router_prog`, BEFORE `routerAccountsStartIdx`) MUST be rejected!
  const rootsAsRouterProg = buildBaseExec(rootsPda)
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructionDataB64: toBase64(rootsAsRouterProg.data), accounts: rootsAsRouterProg.accounts },
        relayerPubkey,
        allowedPre,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('GlobalRootHistory') && err.message.includes('accounts[12]'),
  )

  // 2. `roots0Pda` placed in rollover slot `accounts[24]` (`nextMemo`, BEFORE `routerAccountsStartIdx = 25`) MUST be rejected!
  const rootsInRollover = buildBaseExec(base58Encode(new Uint8Array(32).fill(0x55)), 24)
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructionDataB64: toBase64(rootsInRollover.data), accounts: rootsInRollover.accounts },
        relayerPubkey,
        allowedPre,
      ),
    (err: unknown) => err instanceof FirewallError && err.message.includes('GlobalRootHistory') && err.message.includes('accounts[24]'),
  )
})

test('v1.3.0 Wave2 Item 10E: resolveLookupTables validates pubkeys, caps <= 8, slices data <= 8,249 B, enforces ALT owner and length/alignment bounds', async () => {
  const validAlt1 = base58Encode(new Uint8Array(32).fill(0x11))
  const wrongOwnerAlt = base58Encode(new Uint8Array(32).fill(0x22))
  const truncatedAlt = base58Encode(new Uint8Array(32).fill(0x33))
  const unalignedAlt = base58Encode(new Uint8Array(32).fill(0x44))
  const oversizedAlt = base58Encode(new Uint8Array(32).fill(0x55))
  const extraAlts = Array.from({ length: 6 }, (_, i) => base58Encode(new Uint8Array(32).fill(0x60 + i)))
  const targetEntryA = base58Encode(new Uint8Array(32).fill(0xa1))
  const targetEntryB = base58Encode(new Uint8Array(32).fill(0xa2))

  const validAltBytes = new Uint8Array(ALT_HEADER_LEN + 64)
  validAltBytes.set(base58Decode(targetEntryA), ALT_HEADER_LEN)
  validAltBytes.set(base58Decode(targetEntryB), ALT_HEADER_LEN + 32)

  let capturedAddrs: string[] = []
  let capturedOpts: Record<string, unknown> = {}

  const resolved = await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      assert.equal(body.method, 'getMultipleAccounts')
      capturedAddrs = body.params[0] as string[]
      capturedOpts = body.params[1] as Record<string, unknown>
      return Response.json({
        jsonrpc: '2.0',
        id: 1,
        result: {
          context: { slot: 55_000 },
          value: capturedAddrs.map((a) => {
            if (a === validAlt1) {
              return { data: [toBase64(validAltBytes), 'base64'], lamports: 5_000_000, owner: ADDRESS_LOOKUP_TABLE_PROGRAM_ID_STR }
            }
            if (a === wrongOwnerAlt) {
              // Malicious BPF Loader account masquerading as ALT
              return { data: [toBase64(validAltBytes), 'base64'], lamports: 5_000_000, owner: 'BPFLoaderUpgradeab1e11111111111111111111111' }
            }
            if (a === truncatedAlt) {
              return { data: [toBase64(new Uint8Array(55)), 'base64'], lamports: 5_000_000, owner: ADDRESS_LOOKUP_TABLE_PROGRAM_ID_STR }
            }
            if (a === unalignedAlt) {
              return { data: [toBase64(new Uint8Array(ALT_HEADER_LEN + 33)), 'base64'], lamports: 5_000_000, owner: ADDRESS_LOOKUP_TABLE_PROGRAM_ID_STR }
            }
            if (a === oversizedAlt) {
              return { data: [toBase64(new Uint8Array(ALT_MAX_DATA_LEN + 1)), 'base64'], lamports: 5_000_000, owner: ADDRESS_LOOKUP_TABLE_PROGRAM_ID_STR }
            }
            return null
          }),
        },
      })
    },
    () =>
      resolveLookupTables('https://mock-rpc.local/item10e-alt', [
        'not-a-valid-pubkey!!!',
        '',
        validAlt1,
        validAlt1, // duplicate
        wrongOwnerAlt,
        truncatedAlt,
        unalignedAlt,
        oversizedAlt,
        ...extraAlts, // pushes count beyond 8 -> MUST be capped at 8!
      ]),
  )

  assert.equal(capturedAddrs.length, 8, 'resolveLookupTables MUST filter invalid/duplicate keys and cap at 8')
  assert.equal(capturedOpts.encoding, 'base64')
  assert.deepEqual(capturedOpts.dataSlice, { offset: 0, length: ALT_MAX_DATA_LEN + 1 })
  assert.deepEqual(Object.keys(resolved), [validAlt1])
  assert.deepEqual(resolved[validAlt1], [targetEntryA, targetEntryB])
})

test('v1.3.0 Wave2 Item 4: bump-aware OpenPage CU padding keeps 40k for bump >= 240 and pads (240 - bump) * 1_500 for rare low-bump pages', async () => {
  // 1. Direct formula verification across the full bump range [0..255]
  assert.equal(computeOpenPageCuLimitForBump(255), 40_000)
  assert.equal(computeOpenPageCuLimitForBump(240), 40_000)
  assert.equal(computeOpenPageCuLimitForBump(239), 41_500)
  assert.equal(computeOpenPageCuLimitForBump(220), 70_000)
  assert.equal(computeOpenPageCuLimitForBump(0), 400_000)

  // 2. Real low-bump MemoPage PDA: `deriveMemoPdaSync(0, 0, 5905n)` has `bump = 238` (< 240 -> +3,000 CU = 43,000 CU!)
  const lowBumpMemoSeq = 5905n
  const lowBumpMemo = deriveMemoPdaSync(0, 0, lowBumpMemoSeq)
  assert.equal(lowBumpMemo.bump, 238)
  const lowBumpOpenIx = buildOpenPageSolanaIx({
    payer: relayerB58,
    pageKind: OPEN_PAGE_KIND_MEMO,
    poolId: 0,
    laneId: 0,
    pageSeq: lowBumpMemoSeq,
  })
  assert.equal(deriveOpenPageBumpFromIx(lowBumpOpenIx), 238)
  assert.equal(computeOpenPageIxCuLimit(lowBumpOpenIx), 43_000)

  // 3. `planRolloverOpenPages` honors exact bump-aware `maxExtraCu` so a 43k low-bump proactive page
  //    is skipped when only 41k CU remains (even though 41k >= 40k base)!
  const indexMod = await import('../src/index')
  const prevMemoSeq = lowBumpMemoSeq - 1n // 5904
  const nextLeafNearLowBump = lowBumpMemoSeq * BigInt(MEMO_NOTES_PER_PAGE) - 5n // memoRem = 5 <= 10 (proactive!)
  const curSubSeq = nextLeafNearLowBump / 256n
  const curRootSeq = curSubSeq / 300n
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)
  const subPda = deriveSubtreePdaSync(0, 0, curSubSeq).address
  const srPda = deriveSubrootPdaSync(0, 0, curRootSeq).address
  const prevMemoPda = deriveMemoPdaSync(0, 0, prevMemoSeq).address
  const nf0Pda = deriveNfPagePdaSync(0, 0, 0n).address

  const buildMaps = () => {
    const pre = new Map<string, { bytes: Uint8Array; lamports: number; owner: string } | null>([
      [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: nextLeafNearLowBump, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0RentVault, { bytes: new Uint8Array(16), lamports: 200_000_000, owner: AUDREN_PROGRAM_ID }],
      [subPda, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
      [srPda, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
      [prevMemoPda, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
      [nf0Pda, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
      [lowBumpMemo.address, null],
    ])
    const fetched = new Map<string, { bytes: Uint8Array; owner: string } | null>()
    for (const [k, v] of pre.entries()) fetched.set(k, v ? { bytes: v.bytes, owner: v.owner } : null)
    return { pre, fetched }
  }
  const rentFloors = {
    laneRentVaultReserveFloor: 1_002_240n,
    subRentFloor: 58_352_640n,
    srRentFloor: 68_152_320n,
    memoRentFloor: 72_161_280n,
    nfPageRentFloor: 68_152_320n,
  }
  const entry = {
    poolId: 0,
    outLaneId: 0,
    outputCount: 1,
    nullifierCount: 2,
    pages: { outSub: subPda, outRoot: srPda, outMemo: prevMemoPda, nfPage: nf0Pda, nextSub: null, nextMemo: null, nextNf: null },
  }

  const tightMaps = buildMaps()
  const skippedTight = await indexMod.planRolloverOpenPages({
    rpcUrl: 'https://mock-rpc.local/item4-tight',
    payerB58: relayerB58,
    entries: [entry],
    fetchedAccounts: tightMaps.fetched,
    preAccountInfoMap: tightMaps.pre,
    rentFloors,
    maxExtraByCu: 1,
    maxExtraCu: 41_000, // < 43_000 required for bump 238!
  })
  assert.equal(skippedTight.ok, true)
  if (skippedTight.ok) {
    assert.equal(skippedTight.proactiveOpenPageIxs.length, 0, '43k low-bump proactive OpenPage MUST be skipped when maxExtraCu = 41_000')
  }

  // 4. End-to-end `/v1/relay/submit` with exact rollover onto low-bump `MemoPage(5905)` emits `235_000 + 43_000 = 278_000` CU!
  const worker = indexMod.default
  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({ activeLanes: 4, rootEpochInterval: 32n, noteRentFee: 1_000_000n, nfRentFee: 113_567n })
  const exactLowBumpLeaf = lowBumpMemoSeq * BigInt(MEMO_NOTES_PER_PAGE) - 1n
  const exactSubSeq = exactLowBumpLeaf / 256n
  const exactRootSeq = exactSubSeq / 300n
  const exactLowBumpIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: exactSubSeq,
    outRootSeq: exactRootSeq,
    outMemoSeq: prevMemoSeq,
    outNfSeq: 0n,
    rollover: { nextMemoSeq: lowBumpMemoSeq },
    outputMask: 0b011,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0x9a),
    nf1: new Uint8Array(32).fill(0x9b),
    cm0: new Uint8Array(32).fill(0x11),
    cm1: new Uint8Array(32).fill(0x22),
    cm2: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(2 * MEMO_ENTRY_WIRE_LEN).fill(0x33),
  })
  const accMapSubmit = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [poolPda, { bytes: poolBytes, lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: exactLowBumpLeaf, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0RentVault, { bytes: new Uint8Array(16), lamports: 200_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, exactSubSeq).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, exactRootSeq).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
    [prevMemoPda, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
    [nf0Pda, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
  ])
  const guardLowBump = createMockGuard()
  const envLowBump = {
    RELAY_GUARD: guardLowBump.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/item4-low-bump-submit',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
  } as Env
  let sentLowBumpWire: Uint8Array | null = null
  const lowBumpRes = await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result:
            len === 0
              ? 890_880
              : len === 16
                ? 1_002_240
                : len === 165
                  ? 2_039_280
                  : len === SUBTREE_PAGE_LEN
                    ? 58_352_640
                    : len === MEMO_PAGE_LEN
                      ? 72_161_280
                      : 68_152_320,
        })
      }
      if (body.method === 'getAccountInfo') {
        const hit = accMapSubmit.get(String(body.params[0]))
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null } })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x9c)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 99_500 },
            value: addrs.map((a) => {
              const hit = accMapSubmit.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        const opts = body.params[1] as { accounts?: { addresses?: string[] } }
        const watchCount = opts?.accounts?.addresses?.length ?? 1
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 99_500 },
            value: {
              err: null,
              logs: ['OpenPage OK', 'Transact OK'],
              unitsConsumed: 190_000,
              accounts: [
                { lamports: 496_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                ...Array.from({ length: Math.max(0, watchCount - 1) }, () => ({
                  lamports: 127_838_720,
                  owner: AUDREN_PROGRAM_ID,
                  data: ['', 'base64'],
                })),
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        sentLowBumpWire = fromBase64(String(body.params[0]))
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5Item4LowBumpMemoSig11111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 99_501, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in Item 4 test: ${body.method}`)
    },
    () =>
      worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(exactLowBumpIx.data),
            accounts: exactLowBumpIx.accounts,
          }),
        }),
        envLowBump,
      ),
  )
  assert.equal(lowBumpRes.status, 200)
  const lowBumpBody = (await lowBumpRes.json()) as { openedPagesCount: number; computeUnitLimit: number }
  assert.equal(lowBumpBody.openedPagesCount, 1)
  assert.equal(lowBumpBody.computeUnitLimit, CU_LIMIT_TRANSACT_PRIVATE + 43_000)
  assert.ok(sentLowBumpWire)
  assert.equal(decodeV1Tx(sentLowBumpWire).computeUnitLimit, 278_000)
})

// ============================================================================
// Systems Audit Round 1 Fixes (Relay #1-#4 + Zero-Rent .max(1) Parity)
// ============================================================================

test('v1.3.0 SysAudit-R1 #1: refillSinglePayer watches acc.ata at index 2 (<= 62 watch addrs) and blocks live over-debit skim, delegate/close_authority/length/lamports hijack, and shifted cross-ATA drops', async () => {
  const mockJup = 'https://mock-jup-sysr1-refill.local'
  const USDT_MINT = 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB'
  const wsolAta = deriveAssociatedTokenAddressSync(relayerB58, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const usdcAta = deriveAssociatedTokenAddressSync(relayerB58, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const usdtAta = deriveAssociatedTokenAddressSync(relayerB58, USDT_MINT, CLASSIC_TOKEN_PROGRAM_ID).address

  const runInputAtaCase = async (opts: {
    rpcUrl: string
    preUsdcAmount: bigint
    postUsdcAmount: bigint
    postUsdcClosed?: boolean
    postUsdcOwner?: string
    postUsdcLamports?: number
    postUsdcMutate?: (bytes: Uint8Array) => Uint8Array
    extraOtherCount?: number
    postUsdtAmount?: bigint
  }) => {
    const refillEnv = {
      MAINNET_RPC_URL: opts.rpcUrl,
      MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
      JUPITER_API_URL: mockJup,
    } as Env
    const refillCfg = loadPolicyConfig(refillEnv)
    let sendCalls = 0
    let watchedAddressesSeen: string[] = []

    const extraAtas = Array.from({ length: opts.extraOtherCount ?? 0 }, (_, idx) => {
      const m = base58Encode(new Uint8Array(32).fill(0x20 + idx))
      const ata = base58Encode(new Uint8Array(32).fill(0x70 + idx))
      return { mint: m, ata }
    })

    const report = await withMockFetch(
      async (url, init) => {
        if (url.startsWith(`${mockJup}/price/v3`)) {
          return Response.json({
            [WSOL_MINT]: { usdPrice: 150 },
            [USDC_MINT]: { usdPrice: 1 },
            [USDT_MINT]: { usdPrice: 1 },
          })
        }
        if (url.startsWith(`${mockJup}/swap/v1/quote`)) {
          const u = new URL(url)
          return Response.json({
            inputMint: u.searchParams.get('inputMint'),
            outputMint: WSOL_MINT,
            inAmount: u.searchParams.get('amount'),
            outAmount: '100000000',
            otherAmountThreshold: '98000000',
            slippageBps: 100,
            routePlan: [{ swapInfo: { label: 'Orca' }, percent: 100 }],
          })
        }
        if (url.startsWith(`${mockJup}/swap/v1/swap-instructions`)) {
          return Response.json({
            swapInstruction: {
              programId: JUPITER_V6_ROUTER,
              accounts: [
                { pubkey: relayerB58, isSigner: true, isWritable: true },
                { pubkey: usdcAta, isSigner: false, isWritable: true },
              ],
              data: toBase64(new Uint8Array([1, 2, 3])),
            },
            addressLookupTableAddresses: [],
          })
        }
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getBalance') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: 20_000_000 } })
        }
        if (body.method === 'getTokenAccountsByOwner') {
          const filter = body.params[1] as { programId: string }
          if (filter.programId === CLASSIC_TOKEN_PROGRAM_ID) {
            return Response.json({
              jsonrpc: '2.0',
              id: 1,
              result: {
                value: [
                  // Initial discovery snapshot sees 15_000_000n ($15 USDC) in canonical usdcAta
                  {
                    pubkey: usdcAta,
                    account: {
                      owner: CLASSIC_TOKEN_PROGRAM_ID,
                      data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 15_000_000n)), 'base64'],
                    },
                  },
                  {
                    pubkey: usdtAta,
                    account: {
                      owner: CLASSIC_TOKEN_PROGRAM_ID,
                      data: [toBase64(makeTokenAccountBytes(USDT_MINT, relayerB58, 50_000_000n)), 'base64'],
                    },
                  },
                  ...extraAtas.map((e) => ({
                    pubkey: e.ata,
                    account: {
                      owner: CLASSIC_TOKEN_PROGRAM_ID,
                      data: [toBase64(makeTokenAccountBytes(e.mint, relayerB58, 1_000_000n)), 'base64'],
                    },
                  })),
                ],
              },
            })
          }
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [] } })
        }
        if (body.method === 'getLatestBlockhash') {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0xa1)) } },
          })
        }
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          if (addrs.includes(USDC_MINT) || addrs.includes(USDT_MINT)) {
            return Response.json({
              jsonrpc: '2.0',
              id: 1,
              result: {
                context: { slot: 5000 },
                value: addrs.map(() => ({
                  data: [toBase64(makeClassicMintBytes(6)), 'base64'],
                  lamports: 2_000_000,
                  owner: CLASSIC_TOKEN_PROGRAM_ID,
                })),
              },
            })
          }
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 5000 },
              value: addrs.map((a) => {
                if (a === relayerB58) {
                  return { data: ['', 'base64'], lamports: 20_000_000, owner: SYSTEM_PROGRAM_ID }
                }
                if (a === wsolAta) {
                  return {
                    data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n)), 'base64'],
                    lamports: 2_039_280,
                    owner: CLASSIC_TOKEN_PROGRAM_ID,
                  }
                }
                if (a === usdcAta) {
                  return {
                    data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, opts.preUsdcAmount)), 'base64'],
                    lamports: 2_039_280,
                    owner: CLASSIC_TOKEN_PROGRAM_ID,
                  }
                }
                if (a === usdtAta) {
                  return {
                    data: [toBase64(makeTokenAccountBytes(USDT_MINT, relayerB58, 50_000_000n)), 'base64'],
                    lamports: 2_039_280,
                    owner: CLASSIC_TOKEN_PROGRAM_ID,
                  }
                }
                const extra = extraAtas.find((e) => e.ata === a)
                if (extra) {
                  return {
                    data: [toBase64(makeTokenAccountBytes(extra.mint, relayerB58, 1_000_000n)), 'base64'],
                    lamports: 2_039_280,
                    owner: CLASSIC_TOKEN_PROGRAM_ID,
                  }
                }
                return null
              }),
            },
          })
        }
        if (body.method === 'simulateTransaction') {
          const simOpts = body.params[1] as { accounts?: { addresses?: string[] } }
          watchedAddressesSeen = simOpts?.accounts?.addresses ?? []
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 5000 },
              value: {
                err: null,
                logs: ['Refill Swap OK'],
                unitsConsumed: 180_000,
                accounts: watchedAddressesSeen.map((a) => {
                  if (a === relayerB58) {
                    return { lamports: 118_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }
                  }
                  if (a === wsolAta) {
                    return {
                      lamports: 2_039_280,
                      owner: CLASSIC_TOKEN_PROGRAM_ID,
                      data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n)), 'base64'],
                    }
                  }
                  if (a === usdcAta) {
                    if (opts.postUsdcClosed) return null
                    let postBytes = makeTokenAccountBytes(USDC_MINT, relayerB58, opts.postUsdcAmount)
                    if (opts.postUsdcMutate) postBytes = opts.postUsdcMutate(postBytes)
                    return {
                      lamports: opts.postUsdcLamports ?? 2_039_280,
                      owner: opts.postUsdcOwner ?? CLASSIC_TOKEN_PROGRAM_ID,
                      data: [toBase64(postBytes), 'base64'],
                    }
                  }
                  if (a === usdtAta) {
                    return {
                      lamports: 2_039_280,
                      owner: CLASSIC_TOKEN_PROGRAM_ID,
                      data: [toBase64(makeTokenAccountBytes(USDT_MINT, relayerB58, opts.postUsdtAmount ?? 50_000_000n)), 'base64'],
                    }
                  }
                  const extra = extraAtas.find((e) => e.ata === a)
                  if (extra) {
                    return {
                      lamports: 2_039_280,
                      owner: CLASSIC_TOKEN_PROGRAM_ID,
                      data: [toBase64(makeTokenAccountBytes(extra.mint, relayerB58, 1_000_000n)), 'base64'],
                    }
                  }
                  return null
                }),
              },
            },
          })
        }
        if (body.method === 'sendTransaction') {
          sendCalls++
          return Response.json({ jsonrpc: '2.0', id: 1, result: '5SysR1RefillInputAtaOkSig1111111111111111111' })
        }
        if (body.method === 'getSignatureStatuses') {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: { value: [{ slot: 5001, err: null, confirmationStatus: 'confirmed' }] },
          })
        }
        throw new Error(`Unexpected RPC in SysAudit-R1 #1: ${url} ${body.method}`)
      },
      () => runAutoRefill(refillEnv, refillCfg),
    )
    return { report, sendCalls, watchedAddressesSeen }
  }

  // 1. Live over-debit skim: acc.ata grew from $15 -> $210 before sim, rogue route debits all $210 -> REJECTED!
  const overDebit = await runInputAtaCase({
    rpcUrl: 'https://mock-rpc.local/sysr1-1-overdebit',
    preUsdcAmount: 210_000_000n,
    postUsdcAmount: 0n,
  })
  assert.equal(overDebit.watchedAddressesSeen[0], relayerB58)
  assert.equal(overDebit.watchedAddressesSeen[1], wsolAta)
  assert.equal(overDebit.watchedAddressesSeen[2], usdcAta)
  assert.equal(overDebit.watchedAddressesSeen[3], usdtAta)
  assert.equal(overDebit.sendCalls, 0)
  assert.ok(overDebit.report.details.some((d) => d.includes('over-debited')))

  // 2. Delegate hijack (Approve on acc.ata mutating [72..108] + [121..129]) -> REJECTED!
  const delegateHijack = await runInputAtaCase({
    rpcUrl: 'https://mock-rpc.local/sysr1-1-delegate',
    preUsdcAmount: 15_000_000n,
    postUsdcAmount: 0n,
    postUsdcMutate: (b) => {
      b[72] = 1
      b.fill(0xde, 76, 108)
      b.set(u64le(999_999_999n), 121)
      return b
    },
  })
  assert.equal(delegateHijack.sendCalls, 0)
  assert.ok(delegateHijack.report.details.some((d) => d.includes('changed delegate, state, or close authority')))

  // 3. Delegated amount only mutation ([121..129]) -> REJECTED!
  const delegatedAmtHijack = await runInputAtaCase({
    rpcUrl: 'https://mock-rpc.local/sysr1-1-delegated-amt',
    preUsdcAmount: 15_000_000n,
    postUsdcAmount: 0n,
    postUsdcMutate: (b) => {
      b.set(u64le(123n), 121)
      return b
    },
  })
  assert.equal(delegatedAmtHijack.sendCalls, 0)
  assert.ok(delegatedAmtHijack.report.details.some((d) => d.includes('changed delegate, state, or close authority')))

  // 4. Close authority mutation ([129..165]) & Token-2022 realloc length change -> REJECTED!
  const closeAuthHijack = await runInputAtaCase({
    rpcUrl: 'https://mock-rpc.local/sysr1-1-close-auth',
    preUsdcAmount: 15_000_000n,
    postUsdcAmount: 0n,
    postUsdcMutate: (b) => {
      b[129] = 1
      b.fill(0xef, 133, 165)
      return b
    },
  })
  assert.equal(closeAuthHijack.sendCalls, 0)
  assert.ok(closeAuthHijack.report.details.some((d) => d.includes('changed delegate, state, or close authority')))

  const reallocHijack = await runInputAtaCase({
    rpcUrl: 'https://mock-rpc.local/sysr1-1-realloc',
    preUsdcAmount: 15_000_000n,
    postUsdcAmount: 0n,
    postUsdcMutate: (b) => {
      const extended = new Uint8Array(b.length + 6)
      extended.set(b, 0)
      return extended
    },
  })
  assert.equal(reallocHijack.sendCalls, 0)
  assert.ok(reallocHijack.report.details.some((d) => d.includes('changed owner, length, or token metadata')))

  // 5. Lamports drop & closed acc.ata -> REJECTED!
  const lamportDrop = await runInputAtaCase({
    rpcUrl: 'https://mock-rpc.local/sysr1-1-lamports',
    preUsdcAmount: 15_000_000n,
    postUsdcAmount: 0n,
    postUsdcLamports: 1_500_000,
  })
  assert.equal(lamportDrop.sendCalls, 0)
  assert.ok(lamportDrop.report.details.some((d) => d.includes('lamports decreased')))

  const closedInput = await runInputAtaCase({
    rpcUrl: 'https://mock-rpc.local/sysr1-1-closed',
    preUsdcAmount: 15_000_000n,
    postUsdcAmount: 0n,
    postUsdcClosed: true,
  })
  assert.equal(closedInput.sendCalls, 0)
  assert.ok(closedInput.report.details.some((d) => d.includes('missing or closed')))

  // 6. Shifted index (3 + i) still catches cross-ATA drop on usdtAta when acc.ata is clean!
  const shiftedCrossAta = await runInputAtaCase({
    rpcUrl: 'https://mock-rpc.local/sysr1-1-shifted-other',
    preUsdcAmount: 15_000_000n,
    postUsdcAmount: 0n,
    postUsdtAmount: 49_000_000n,
  })
  assert.equal(shiftedCrossAta.sendCalls, 0)
  assert.ok(shiftedCrossAta.report.details.some((d) => d.includes('cross-ATA invariant violated')))

  // 7. Honest swap with live deposit ($15 -> $210, debits exact $15 -> $195) AND 70 extra ATAs stays <= 62 watch addrs & succeeds!
  const honestWithCap = await runInputAtaCase({
    rpcUrl: 'https://mock-rpc.local/sysr1-1-honest-cap',
    preUsdcAmount: 210_000_000n,
    postUsdcAmount: 195_000_000n,
    extraOtherCount: 70,
  })
  assert.equal(honestWithCap.watchedAddressesSeen.length, 62, 'watchAddresses MUST cap at 3 + 59 = 62 (<= 64)')
  assert.equal(honestWithCap.watchedAddressesSeen[2], usdcAta)
  assert.equal(honestWithCap.watchedAddressesSeen[3], usdtAta)
  assert.equal(honestWithCap.report.action, 'swapped_fees')
  assert.equal(honestWithCap.sendCalls, 1)
})

test('v1.3.0 SysAudit-R1 #2: Full Exits (outputCount === 0) skip outSub/outRoot/outMemo at exact page boundaries (nextLeaf = 96, 256, 76800) while preserving canonical PDA checks, nfPage opens, and underfunded escape-hatch /v1/relay/submit', async () => {
  const initPage = { bytes: new Uint8Array(64).fill(0x5a), owner: AUDREN_PROGRAM_ID }

  // 1. Exact MemoPage boundary (`nextLeaf = 96n`, `MemoPage(1)` unopened) -> 0 OpenPage ixs!
  const at96 = (() => {
    const outSub = deriveSubtreePdaSync(0, 0, 0n).address
    const outRoot = deriveSubrootPdaSync(0, 0, 0n).address
    const outMemo = deriveMemoPdaSync(0, 0, 1n).address
    const nfPage = deriveNfPagePdaSync(0, 0, 0n).address
    return planMissingOpenPageIxs({
      payerB58: relayerB58,
      poolId: 0,
      outLaneId: 0,
      laneAcc: { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 96n, nfCount: 10n }), owner: AUDREN_PROGRAM_ID },
      pages: { outSub, outRoot, outMemo, nfPage, nextSub: null, nextMemo: null, nextNf: null },
      pageSlots: [
        { slot: 'outSub', pda: outSub },
        { slot: 'outRoot', pda: outRoot },
        { slot: 'outMemo', pda: outMemo },
        { slot: 'nfPage', pda: nfPage },
      ],
      pageAccs: [initPage, initPage, null, initPage],
      outputCount: 0,
      nullifierCount: 2,
    })
  })()
  assert.equal(at96.ok, true)
  if (at96.ok) assert.equal(at96.openPageIxs.length, 0)

  // 2. Exact SubtreePage boundary (`nextLeaf = 256n`, `SubtreePage(1)` unopened) -> 0 OpenPage ixs!
  const at256 = (() => {
    const outSub = deriveSubtreePdaSync(0, 0, 1n).address
    const outRoot = deriveSubrootPdaSync(0, 0, 0n).address
    const outMemo = deriveMemoPdaSync(0, 0, 2n).address
    const nfPage = deriveNfPagePdaSync(0, 0, 0n).address
    return planMissingOpenPageIxs({
      payerB58: relayerB58,
      poolId: 0,
      outLaneId: 0,
      laneAcc: { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 256n, nfCount: 10n }), owner: AUDREN_PROGRAM_ID },
      pages: { outSub, outRoot, outMemo, nfPage, nextSub: null, nextMemo: null, nextNf: null },
      pageSlots: [
        { slot: 'outSub', pda: outSub },
        { slot: 'outRoot', pda: outRoot },
        { slot: 'outMemo', pda: outMemo },
        { slot: 'nfPage', pda: nfPage },
      ],
      pageAccs: [null, initPage, initPage, initPage],
      outputCount: 0,
      nullifierCount: 2,
    })
  })()
  assert.equal(at256.ok, true)
  if (at256.ok) assert.equal(at256.openPageIxs.length, 0)

  // 3. Exact triple boundary (`nextLeaf = 76_800n` => outSub=300, outRoot=1, outMemo=800 ALL unopened) + `nfCount = 600n` (`nfPage=1` unopened):
  //    Full Exit skips all 3 note/memo pages and opens ONLY `NullifierPage(1)`!
  const sub300 = deriveSubtreePdaSync(0, 0, 300n).address
  const root1 = deriveSubrootPdaSync(0, 0, 1n).address
  const memo800 = deriveMemoPdaSync(0, 0, 800n).address
  const nf1 = deriveNfPagePdaSync(0, 0, 1n).address
  const at76800 = planMissingOpenPageIxs({
    payerB58: relayerB58,
    poolId: 0,
    outLaneId: 0,
    laneAcc: { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 76_800n, nfCount: 600n }), owner: AUDREN_PROGRAM_ID },
    pages: { outSub: sub300, outRoot: root1, outMemo: memo800, nfPage: nf1, nextSub: null, nextMemo: null, nextNf: null },
    pageSlots: [
      { slot: 'outSub', pda: sub300 },
      { slot: 'outRoot', pda: root1 },
      { slot: 'outMemo', pda: memo800 },
      { slot: 'nfPage', pda: nf1 },
    ],
    pageAccs: [null, null, null, null],
    outputCount: 0,
    nullifierCount: 2,
  })
  assert.equal(at76800.ok, true)
  if (at76800.ok) {
    assert.equal(at76800.openPageIxs.length, 1, 'Full Exit at 76_800 MUST skip outSub/outRoot/outMemo and open ONLY nfPage')
    assert.equal(at76800.openPageIxs[0]!.data[1], OPEN_PAGE_KIND_NULLIFIER)
    assert.equal(base58Encode(at76800.openPageIxs[0]!.accounts[4]!.pubkey), nf1)
  }

  // 4. Spoofed `outMemo` PDA at `nextLeaf = 96n` on Full Exit is STILL rejected (`ok: false`)!
  const spoofedMemo = base58Encode(new Uint8Array(32).fill(0xfd))
  const spoofedAt96 = planMissingOpenPageIxs({
    payerB58: relayerB58,
    poolId: 0,
    outLaneId: 0,
    laneAcc: { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 96n, nfCount: 10n }), owner: AUDREN_PROGRAM_ID },
    pages: {
      outSub: deriveSubtreePdaSync(0, 0, 0n).address,
      outRoot: deriveSubrootPdaSync(0, 0, 0n).address,
      outMemo: spoofedMemo,
      nfPage: deriveNfPagePdaSync(0, 0, 0n).address,
      nextSub: null,
      nextMemo: null,
      nextNf: null,
    },
    pageSlots: [{ slot: 'outMemo', pda: spoofedMemo }],
    pageAccs: [null],
    outputCount: 0,
    nullifierCount: 2,
  })
  assert.equal(spoofedAt96.ok, false)

  // 5. End-to-end `/v1/relay/submit` escape-hatch Full Exit at `nextLeaf = 96n` (`MemoPage(1)` unopened)
  //    with underfunded `LaneRentVault` (`1_002_240` lamports -> 0 available) succeeds 200 with 0 opened pages!
  const worker = await getWorker()
  const guard = createMockGuard()
  const poolPda = derivePoolPdaSync(0).address
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const vaultWsolAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const recipSol = base58Encode(new Uint8Array(32).fill(0x55))
  const fullExitIx = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 1n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: true,
    publicOutflow: { mint: WSOL_MINT, vaultAta: vaultWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0xa3),
    nf1: new Uint8Array(32).fill(0xa4),
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 100_000_000n,
    relayerFeeAmount: 0n,
    recipient: recipSol,
    relayerFeeRecipient: SYSTEM_PROGRAM_ID,
    memosBytes: new Uint8Array(0),
  })
  const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [poolPda, { bytes: makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n }), lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 96n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0RentVault, { bytes: new Uint8Array(16), lamports: 1_002_240, owner: AUDREN_PROGRAM_ID }], // 0 available!
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: initPage.bytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: initPage.bytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: initPage.bytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
  ])
  const env = {
    RELAY_GUARD: guard.namespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/sysr1-2-fullexit-96',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
  } as Env
  const submitRes = await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result:
            len === 0
              ? 890_880
              : len === 16
                ? 1_002_240
                : len === 165
                  ? 2_039_280
                  : len === SUBTREE_PAGE_LEN
                    ? 58_352_640
                    : len === MEMO_PAGE_LEN
                      ? 72_161_280
                      : 68_152_320,
        })
      }
      if (body.method === 'getAccountInfo') {
        const hit = accMap.get(String(body.params[0]))
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null } })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0xa5)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 88_000 },
            value: addrs.map((a) => {
              const hit = accMap.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 88_000 },
            value: {
              err: null,
              logs: ['Full Exit OK'],
              unitsConsumed: 120_000,
              accounts: [{ lamports: 497_981_106, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5SysR1FullExitEscapeHatchSig1111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 88_001, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in SysAudit-R1 #2: ${body.method}`)
    },
    () =>
      worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(fullExitIx.data),
            accounts: fullExitIx.accounts,
          }),
        }),
        env,
      ),
  )
  assert.equal(submitRes.status, 200, 'Escape-hatch Full Exit at nextLeaf=96 with underfunded LaneRentVault MUST succeed')
  const submitJson = (await submitRes.json()) as { openedPagesCount: number }
  assert.equal(submitJson.openedPagesCount, 0)
})

test('v1.3.0 SysAudit-R1 #3: RelayGuard counts confirmed on-chain revert burns (failed=1, sponsored_lamports>0) toward SPONSOR_COOLDOWN, IP_HOURLY_SPONSOR_LIMIT, and IP_DAILY_SPONSOR_LIMIT while excluding pre-sim rejections (sponsored_lamports=0)', async () => {
  const RelayGuard = await getRelayGuardClass()
  const harness = createSqliteDoHarness()
  const guard = new RelayGuard(harness.ctx, {} as Env)
  await harness.ready()

  const baseLimits = {
    maxDailySponsoredLamports: 100_000_000,
    ipMaxSponsoredPerHour: 2,
    ipMaxSponsoredPerDay: 3,
    ipCooldownSec: 12,
    selfPayPerIpPer10m: 60,
  }

  // 1. Pre-simulation rejection (`release({ recordFailure: true })` => `sponsored_lamports = 0, failed = 1`)
  //    MUST NOT trigger SPONSOR_COOLDOWN, hourly, or daily sponsored limits!
  const b0 = await guard.begin({ clientIp: '198.51.100.10', nullifiers: ['nf-presim-0'] })
  assert.equal(b0.allowed, true)
  const ipHash = b0.ipHash!
  await guard.release({ ipHash, cluster: 'mainnet', nullifiers: ['nf-presim-0'], recordFailure: true })

  const b1 = await guard.begin({ clientIp: '198.51.100.10', nullifiers: ['nf-rev-1'] })
  assert.equal(b1.allowed, true)
  const authAfterPreSim = await guard.authorizeSpend({
    ipHash,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-rev-1'],
    sponsoredLamports: 10_000,
    selfPaying: false,
    limits: baseLimits,
  })
  assert.equal(authAfterPreSim.allowed, true, 'Pre-sim rejection (sponsored_lamports=0) MUST NOT trigger SPONSOR_COOLDOWN')

  // 2. Confirmed on-chain revert burn (`commit({ recordFailure: true, sponsoredLamports: 10_000, selfPaying: false })`)
  //    MUST immediately trigger `SPONSOR_COOLDOWN` on the very next sponsored attempt!
  await guard.commit({
    reservationId: authAfterPreSim.reservationId,
    ipHash,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-rev-1'],
    sponsoredLamports: 10_000,
    selfPaying: false,
    recordFailure: true,
  })
  const b2 = await guard.begin({ clientIp: '198.51.100.10', nullifiers: ['nf-rev-2'] })
  assert.equal(b2.allowed, true)
  const cooldownDenied = await guard.authorizeSpend({
    ipHash,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-rev-2'],
    sponsoredLamports: 10_000,
    selfPaying: false,
    limits: baseLimits,
  })
  assert.equal(cooldownDenied.allowed, false)
  assert.equal(cooldownDenied.status, 429)
  assert.equal(cooldownDenied.code, 'SPONSOR_COOLDOWN')

  // 3. With cooldown=0, a second confirmed revert burn reaches `ipMaxSponsoredPerHour = 2` -> 3rd attempt hits `IP_HOURLY_SPONSOR_LIMIT`!
  const b3 = await guard.begin({ clientIp: '198.51.100.10', nullifiers: ['nf-rev-3'] })
  assert.equal(b3.allowed, true)
  const auth2 = await guard.authorizeSpend({
    ipHash,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-rev-3'],
    sponsoredLamports: 10_000,
    selfPaying: false,
    limits: { ...baseLimits, ipCooldownSec: 0 },
  })
  assert.equal(auth2.allowed, true)
  await guard.commit({
    reservationId: auth2.reservationId,
    ipHash,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-rev-3'],
    sponsoredLamports: 10_000,
    selfPaying: false,
    recordFailure: true,
  })
  const b4 = await guard.begin({ clientIp: '198.51.100.10', nullifiers: ['nf-rev-4'] })
  assert.equal(b4.allowed, true)
  const hourlyDenied = await guard.authorizeSpend({
    ipHash,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-rev-4'],
    sponsoredLamports: 10_000,
    selfPaying: false,
    limits: { ...baseLimits, ipCooldownSec: 0 },
  })
  assert.equal(hourlyDenied.allowed, false)
  assert.equal(hourlyDenied.status, 429)
  assert.equal(hourlyDenied.code, 'IP_HOURLY_SPONSOR_LIMIT')

  // 4. Backdate existing revert burns by 2 hours (outside 1h window, inside 24h window) + add 1 more -> reaches `ipMaxSponsoredPerDay = 3` -> `IP_DAILY_SPONSOR_LIMIT`!
  const twoHoursAgo = Date.now() - 2 * 3_600_000
  harness.db.prepare('UPDATE ip_events SET created_at = ? WHERE ip_hash = ? AND sponsored_lamports > 0').run(twoHoursAgo, ipHash)

  const b5 = await guard.begin({ clientIp: '198.51.100.10', nullifiers: ['nf-rev-5'] })
  assert.equal(b5.allowed, true)
  const auth3 = await guard.authorizeSpend({
    ipHash,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-rev-5'],
    sponsoredLamports: 10_000,
    selfPaying: false,
    limits: { ...baseLimits, ipCooldownSec: 0 },
  })
  assert.equal(auth3.allowed, true)
  await guard.commit({
    reservationId: auth3.reservationId,
    ipHash,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-rev-5'],
    sponsoredLamports: 10_000,
    selfPaying: false,
    recordFailure: true,
  })

  const b6 = await guard.begin({ clientIp: '198.51.100.10', nullifiers: ['nf-rev-6'] })
  assert.equal(b6.allowed, true)
  const dailyDenied = await guard.authorizeSpend({
    ipHash,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-rev-6'],
    sponsoredLamports: 10_000,
    selfPaying: false,
    limits: { ...baseLimits, ipCooldownSec: 0 },
  })
  assert.equal(dailyDenied.allowed, false)
  assert.equal(dailyDenied.status, 429)
  assert.equal(dailyDenied.code, 'IP_DAILY_SPONSOR_LIMIT')
})

test('v1.3.0 SysAudit-R1 #4: hasUntrustedCpiTarget caps priorityFeeLamports at 5_000n for TransferHook Transact and non-allowlisted Token-2022 ExecViaEscrow legs while allowing allowlisted Token-2022 (PYUSD) audited swaps', async () => {
  const worker = await getWorker()
  const PYUSD_MINT = '2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo'
  const unallowlistedT22Mint = base58Encode(new Uint8Array(32).fill(0xd9))
  const poolPda = derivePoolPdaSync(0).address
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const escrow1 = deriveEscrowPdaSync(0, 1).address
  const relayerWsolAta = deriveAssociatedTokenAddressSync(relayerB58, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultWsolAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowWsolAta = deriveAssociatedTokenAddressSync(escrow1, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultUnallowT22Ata = deriveAssociatedTokenAddressSync(vaultAuth, unallowlistedT22Mint, TOKEN_2022_PROGRAM_ID).address
  const escrowUnallowT22Ata = deriveAssociatedTokenAddressSync(escrow1, unallowlistedT22Mint, TOKEN_2022_PROGRAM_ID).address
  const vaultPyusdAta = deriveAssociatedTokenAddressSync(vaultAuth, PYUSD_MINT, TOKEN_2022_PROGRAM_ID).address
  const escrowPyusdAta = deriveAssociatedTokenAddressSync(escrow1, PYUSD_MINT, TOKEN_2022_PROGRAM_ID).address
  const recipUnallowT22Ata = deriveAssociatedTokenAddressSync(base58Encode(new Uint8Array(32).fill(0x41)), unallowlistedT22Mint, TOKEN_2022_PROGRAM_ID).address
  const dummyPageBytes = new Uint8Array(64).fill(0x5c)

  const submitAndCapturePriority = async (
    label: string,
    ix: { data: Uint8Array; accounts: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }> },
    requestedPriority: string,
    creditRelayerWsolFee: boolean,
    extraEnv?: Partial<Env>,
  ): Promise<bigint> => {
    const guard = createMockGuard()
    const env = {
      RELAY_GUARD: guard.namespace,
      MAINNET_RPC_URL: `https://mock-rpc.local/sysr1-4-${label}`,
      MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
      ...extraEnv,
    } as Env
    const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
      [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
      [relayerWsolAta, { bytes: makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n), lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }],
      [poolPda, { bytes: makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n }), lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 10n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0RentVault, { bytes: new Uint8Array(16), lamports: 200_000_000, owner: AUDREN_PROGRAM_ID }],
      [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
      [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
      [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
      [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
    ])
    let sentWire: Uint8Array | null = null
    const res = await withMockFetch(
      async (_url, init) => {
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getMinimumBalanceForRentExemption') {
          const len = Number(body.params[0])
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result:
              len === 0
                ? 890_880
                : len === 16
                  ? 1_002_240
                  : len === 165
                    ? 2_039_280
                    : len === SUBTREE_PAGE_LEN
                      ? 58_352_640
                      : len === MEMO_PAGE_LEN
                        ? 72_161_280
                        : 68_152_320,
          })
        }
        if (body.method === 'getAccountInfo') {
          const hit = accMap.get(String(body.params[0]))
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null } })
        }
        if (body.method === 'getLatestBlockhash') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0xb1)) } } })
        }
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 91_000 },
              value: addrs.map((a) => {
                const hit = accMap.get(a)
                return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
              }),
            },
          })
        }
        if (body.method === 'simulateTransaction') {
          const opts = body.params[1] as { accounts?: { addresses?: string[] } }
          const watchAddrs = opts?.accounts?.addresses ?? [relayerB58]
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 91_000 },
              value: {
                err: null,
                logs: ['OK'],
                unitsConsumed: 220_000,
                accounts: watchAddrs.map((a) =>
                  a === relayerB58
                    ? { lamports: 496_900_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }
                    : a === relayerWsolAta
                      ? {
                          lamports: 2_039_280,
                          owner: CLASSIC_TOKEN_PROGRAM_ID,
                          data: [
                            toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, creditRelayerWsolFee ? 10_000_000n : 0n)),
                            'base64',
                          ],
                        }
                      : { lamports: 1_002_240, owner: AUDREN_PROGRAM_ID, data: ['', 'base64'] },
                ),
              },
            },
          })
        }
        if (body.method === 'sendTransaction') {
          sentWire = fromBase64(String(body.params[0]))
          return Response.json({ jsonrpc: '2.0', id: 1, result: `5SysR1Cap${label}Sig11111111111111111111111` })
        }
        if (body.method === 'getSignatureStatuses') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 91_001, err: null, confirmationStatus: 'confirmed' }] } })
        }
        throw new Error(`Unexpected RPC in SysAudit-R1 #4 (${label}): ${body.method}`)
      },
      () =>
        worker.fetch(
          new Request('https://relay.audren.xyz/v1/relay/submit', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              cluster: 'mainnet',
              instructionDataB64: toBase64(ix.data),
              accounts: ix.accounts,
              priorityFeeLamports: requestedPriority,
            }),
          }),
          env,
        ),
    )
    assert.equal(res.status, 200, `Case ${label} expected HTTP 200`)
    const jsonBody = (await res.json()) as { priorityFeeLamports: string }
    assert.ok(sentWire)
    const wirePriority = decodeV1Tx(sentWire).priorityFeeLamports
    assert.equal(BigInt(jsonBody.priorityFeeLamports), wirePriority)
    return wirePriority
  }

  // 1. Transact (Tag 5) Token-2022 withdrawal with trailing TransferHook accounts -> capped at 5_000n!
  const t22HookWithdraw = buildTransactInstruction({
    payer: relayerB58,
    poolId: 0,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: false,
    publicOutflow: { mint: unallowlistedT22Mint, vaultAta: vaultUnallowT22Ata, tokenProgram: TOKEN_2022_PROGRAM_ID },
    proof192: dummyProof,
    nf0: new Uint8Array(32).fill(0xc1),
    nf1: new Uint8Array(32).fill(0xc2),
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 100_000_000n,
    relayerFeeAmount: 0n,
    recipient: recipUnallowT22Ata,
    relayerFeeRecipient: SYSTEM_PROGRAM_ID,
    memosBytes: new Uint8Array(0),
    hookAccounts: [{ pubkey: base58Encode(new Uint8Array(32).fill(0xe1)), isSigner: false, isWritable: false }],
  })
  assert.equal(await submitAndCapturePriority('t22hook', t22HookWithdraw, '50000', false), 5_000n)

  const buildAuditedExec = (
    inLeg: { mint: string; vaultAta: string; escrowAta: string; tokenProgram: string },
    outLeg: { mint: string; vaultAta: string; escrowAta: string; tokenProgram: string },
    feeOnOutput: boolean,
    seed: number,
  ) =>
    buildExecViaEscrowInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: 0,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: 0n,
      outNfSeq: 0n,
      escrowShard: 1,
      changeMask: 0,
      inLeg,
      outLeg,
      relayerFeeAmount: 10_000_000n,
      relayerFeeRecipient: relayerWsolAta,
      feeOnOutput,
      proof192: dummyProof,
      nf0: new Uint8Array(32).fill(seed),
      nf1: new Uint8Array(32).fill(seed + 1),
      cm0: new Uint8Array(32),
      cm1: new Uint8Array(32),
      cm2: new Uint8Array(32),
      amountIn: 100_000_000n,
      minAmountOut: 1_000_000n,
      outStealthOwner: new Uint8Array(32).fill(0x02),
      outBlinding: new Uint8Array(32).fill(0x03),
      dynMemoHead: new Uint8Array(34).fill(0x04),
      dynMemoMask: new Uint8Array(72).fill(0x05),
      routerProg: JUPITER_V6_ROUTER,
      routerIxData: new Uint8Array([1, 2, 3]),
      routerAccounts: [{ pubkey: base58Encode(new Uint8Array(32).fill(0x66)), isSigner: false, isWritable: true }],
      changeMemos: new Uint8Array(0),
    })

  // 2. Audited router ExecViaEscrow with non-allowlisted Token-2022 OUTPUT leg -> capped at 5_000n!
  const execUnallowOut = buildAuditedExec(
    { mint: WSOL_MINT, vaultAta: vaultWsolAta, escrowAta: escrowWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    { mint: unallowlistedT22Mint, vaultAta: vaultUnallowT22Ata, escrowAta: escrowUnallowT22Ata, tokenProgram: TOKEN_2022_PROGRAM_ID },
    false,
    0xc3,
  )
  assert.equal(await submitAndCapturePriority('execout', execUnallowOut, '50000', true), 5_000n)

  // 3. Audited router ExecViaEscrow with non-allowlisted Token-2022 INPUT leg -> capped at 5_000n!
  const execUnallowIn = buildAuditedExec(
    { mint: unallowlistedT22Mint, vaultAta: vaultUnallowT22Ata, escrowAta: escrowUnallowT22Ata, tokenProgram: TOKEN_2022_PROGRAM_ID },
    { mint: WSOL_MINT, vaultAta: vaultWsolAta, escrowAta: escrowWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    true,
    0xc5,
  )
  assert.equal(await submitAndCapturePriority('execin', execUnallowIn, '50000', true), 5_000n)

  // 4. Control: PYUSD is excluded from default allowlist (capped at 5_000n), while an explicitly
  //    operator-allowlisted Token-2022 output leg retains 35_000n!
  const execAllowPyusd = buildAuditedExec(
    { mint: WSOL_MINT, vaultAta: vaultWsolAta, escrowAta: escrowWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
    { mint: PYUSD_MINT, vaultAta: vaultPyusdAta, escrowAta: escrowPyusdAta, tokenProgram: TOKEN_2022_PROGRAM_ID },
    false,
    0xc7,
  )
  assert.equal(await submitAndCapturePriority('execpyusd-default', execAllowPyusd, '35000', true), 5_000n)
  assert.equal(
    await submitAndCapturePriority('execpyusd-allowlisted', execAllowPyusd, '35000', true, {
      SELF_PAY_FEE_MINTS: [...DEFAULT_SELF_PAY_FEE_MINTS, PYUSD_MINT].join(','),
    }),
    35_000n,
  )
})

test('v1.3.0 SysAudit-R1 #5: fetchLiveRentSchedule clamps subRent/srRent/memoRent/nfRent to >= 1n on zero-rent clusters matching on-chain collect_lane_rent_fee and deterministic_note_rent_fee', async () => {
  clearLiveRentScheduleCache()
  const poolPda = derivePoolPdaSync(0).address
  const rpcNoPool = 'https://mock-rpc.local/sysr1-5-zero-rent-no-pool'
  const rpcFundedPool = 'https://mock-rpc.local/sysr1-5-zero-rent-pool'
  const rpcZeroGovPool = 'https://mock-rpc.local/sysr1-5-zero-rent-gov-zero'
  const poolFunded = makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n })
  const poolGovZero = makePoolStateBytes({ noteRentFee: 0n, nfRentFee: 0n })

  try {
    await withMockFetch(
      async (url, init) => {
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getMinimumBalanceForRentExemption') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: 0 })
        }
        if (body.method === 'getAccountInfo' && body.params[0] === poolPda) {
          if (url === rpcNoPool) {
            return Response.json({ jsonrpc: '2.0', id: 1, result: { value: null } })
          }
          const bytes = url === rpcZeroGovPool ? poolGovZero : poolFunded
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: { value: { data: [toBase64(bytes), 'base64'], lamports: 1, owner: AUDREN_PROGRAM_ID } },
          })
        }
        throw new Error(`Unexpected RPC in SysAudit-R1 #5: ${body.method}`)
      },
      async () => {
        // 1. Missing PoolState on zero-rent cluster: each page rent clamps to 1n -> livePerNote = 3n, livePerNf = 1n!
        const schedNoPool = await fetchLiveRentSchedule(rpcNoPool)
        assert.equal(schedNoPool.subtreePageRentLamports, 1n)
        assert.equal(schedNoPool.subrootPageRentLamports, 1n)
        assert.equal(schedNoPool.memoPageRentLamports, 1n)
        assert.equal(schedNoPool.nfPageRentLamports, 1n)
        assert.equal(schedNoPool.pageRentPerNoteLamports, 3n)
        assert.equal(schedNoPool.nfPageRentPerNfLamports, 1n)

        // 2. PoolState with positive noteRentFee/nfRentFee caps at clamped live floor (3n / 1n, NOT 0n!)
        const schedFunded = await fetchLiveRentSchedule(rpcFundedPool)
        assert.equal(schedFunded.pageRentPerNoteLamports, 3n)
        assert.equal(schedFunded.nfPageRentPerNfLamports, 1n)

        // 3. Governance zero override (noteRentFee=0, nfRentFee=0) still returns 0n / 0n!
        const schedGovZero = await fetchLiveRentSchedule(rpcZeroGovPool)
        assert.equal(schedGovZero.pageRentPerNoteLamports, 0n)
        assert.equal(schedGovZero.nfPageRentPerNfLamports, 0n)
      },
    )
  } finally {
    clearLiveRentScheduleCache()
  }
})

test('v1.3.0 SysAudit-R2 #1: RelayGuard enforces confirmed revert burn limits & daily sponsor budget on selfPaying: true requests while keeping honest self-paying users unaffected even when daily budget is exhausted', async () => {
  const RelayGuard = await getRelayGuardClass()
  const harness = createSqliteDoHarness()
  const guard = new RelayGuard(harness.ctx, {} as Env)
  await harness.ready()

  const baseLimits = {
    maxDailySponsoredLamports: 100_000,
    ipMaxSponsoredPerHour: 2,
    ipMaxSponsoredPerDay: 3,
    ipCooldownSec: 12,
    selfPayPerIpPer10m: 60,
  }

  // 1. Pre-sim rejection (sponsored_lamports=0, failed=1) + honest sponsored tx (failed=0, sponsored_lamports>0)
  //    MUST NOT trigger cooldown, hourly/daily limits, or daily budget blocks on honest selfPaying: true requests!
  const bPre = await guard.begin({ clientIp: '198.51.100.20', nullifiers: ['nf-r2-presim'] })
  assert.equal(bPre.allowed, true)
  const ipAttacker = bPre.ipHash!
  await guard.release({ ipHash: ipAttacker, cluster: 'mainnet', nullifiers: ['nf-r2-presim'], recordFailure: true })

  const bHonestSp = await guard.begin({ clientIp: '198.51.100.20', nullifiers: ['nf-r2-honest-sp'] })
  assert.equal(bHonestSp.allowed, true)
  const authHonestSp = await guard.authorizeSpend({
    ipHash: ipAttacker,
    cluster: 'mainnet',
    opKind: 'transfer',
    nullifiers: ['nf-r2-honest-sp'],
    sponsoredLamports: 20_000,
    selfPaying: false,
    limits: baseLimits,
  })
  assert.equal(authHonestSp.allowed, true)
  await guard.commit({
    reservationId: authHonestSp.reservationId,
    ipHash: ipAttacker,
    cluster: 'mainnet',
    opKind: 'transfer',
    nullifiers: ['nf-r2-honest-sp'],
    sponsoredLamports: 20_000,
    selfPaying: false,
  })

  // Immediate selfPaying: true right after honest sponsored tx + pre-sim failure MUST still succeed!
  const bSpOk = await guard.begin({ clientIp: '198.51.100.20', nullifiers: ['nf-r2-sp-ok-1'] })
  assert.equal(bSpOk.allowed, true)
  const authSpOk = await guard.authorizeSpend({
    ipHash: ipAttacker,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r2-sp-ok-1'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: false,
    maxRevertBurnLamports: 10_000,
    limits: baseLimits,
  })
  assert.equal(authSpOk.allowed, true, 'Honest sponsored tx (failed=0) & pre-sim rejection must not block selfPaying: true')

  // 2. Confirmed on-chain revert burn on a selfPaying: true request -> immediate `429 SPONSOR_COOLDOWN` on replay!
  await guard.commit({
    reservationId: authSpOk.reservationId,
    ipHash: ipAttacker,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r2-sp-ok-1'],
    sponsoredLamports: 10_000,
    selfPaying: false,
    recordFailure: true,
  })
  const bCool = await guard.begin({ clientIp: '198.51.100.20', nullifiers: ['nf-r2-sp-cool'] })
  assert.equal(bCool.allowed, true)
  const deniedCool = await guard.authorizeSpend({
    ipHash: ipAttacker,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r2-sp-cool'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: false,
    maxRevertBurnLamports: 10_000,
    limits: baseLimits,
  })
  assert.equal(deniedCool.allowed, false)
  assert.equal(deniedCool.status, 429)
  assert.equal(deniedCool.code, 'SPONSOR_COOLDOWN')
  assert.ok((deniedCool.retryAfterSec ?? 0) >= 1)

  // Verify `deny()` released `inflight_nullifiers` so nullifier isn't leaked!
  const bCoolRetry = await guard.begin({ clientIp: '198.51.100.20', nullifiers: ['nf-r2-sp-cool'] })
  assert.equal(bCoolRetry.allowed, true, 'Denied selfPaying request must release inflight_nullifiers')

  // 3. Second confirmed revert burn (with cooldown=0) reaches `ipMaxSponsoredPerHour = 2` -> 3rd `selfPaying: true` hits `429 IP_HOURLY_SPONSOR_LIMIT`!
  const authRev2 = await guard.authorizeSpend({
    ipHash: ipAttacker,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r2-sp-cool'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: false,
    maxRevertBurnLamports: 10_000,
    limits: { ...baseLimits, ipCooldownSec: 0 },
  })
  assert.equal(authRev2.allowed, true)
  await guard.commit({
    reservationId: authRev2.reservationId,
    ipHash: ipAttacker,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r2-sp-cool'],
    sponsoredLamports: 10_000,
    selfPaying: false,
    recordFailure: true,
  })

  const bHr = await guard.begin({ clientIp: '198.51.100.20', nullifiers: ['nf-r2-sp-hr'] })
  assert.equal(bHr.allowed, true)
  const deniedHr = await guard.authorizeSpend({
    ipHash: ipAttacker,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r2-sp-hr'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: false,
    maxRevertBurnLamports: 10_000,
    limits: { ...baseLimits, ipCooldownSec: 0 },
  })
  assert.equal(deniedHr.allowed, false)
  assert.equal(deniedHr.status, 429)
  assert.equal(deniedHr.code, 'IP_HOURLY_SPONSOR_LIMIT')

  // 4. Backdate revert burns by 2h (outside 1h window, inside 24h window) + 1 more revert -> reaches `ipMaxSponsoredPerDay = 3` -> `429 IP_DAILY_SPONSOR_LIMIT`!
  const twoHoursAgo = Date.now() - 2 * 3_600_000
  harness.db
    .prepare('UPDATE ip_events SET created_at = ? WHERE ip_hash = ? AND failed = 1 AND sponsored_lamports > 0')
    .run(twoHoursAgo, ipAttacker)

  const bDay3 = await guard.begin({ clientIp: '198.51.100.20', nullifiers: ['nf-r2-sp-day3'] })
  assert.equal(bDay3.allowed, true)
  const authRev3 = await guard.authorizeSpend({
    ipHash: ipAttacker,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r2-sp-day3'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: false,
    maxRevertBurnLamports: 10_000,
    limits: { ...baseLimits, ipCooldownSec: 0 },
  })
  assert.equal(authRev3.allowed, true)
  await guard.commit({
    reservationId: authRev3.reservationId,
    ipHash: ipAttacker,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r2-sp-day3'],
    sponsoredLamports: 10_000,
    selfPaying: false,
    recordFailure: true,
  })

  const bDayDeny = await guard.begin({ clientIp: '198.51.100.20', nullifiers: ['nf-r2-sp-day-deny'] })
  assert.equal(bDayDeny.allowed, true)
  const deniedDay = await guard.authorizeSpend({
    ipHash: ipAttacker,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r2-sp-day-deny'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: false,
    maxRevertBurnLamports: 10_000,
    limits: { ...baseLimits, ipCooldownSec: 0 },
  })
  assert.equal(deniedDay.allowed, false)
  assert.equal(deniedDay.status, 429)
  assert.equal(deniedDay.code, 'IP_DAILY_SPONSOR_LIMIT')

  // 5. Exhaust daily sponsor budget 100% (spentToday = 100_000 === maxDailySponsoredLamports):
  //    (a) IP with `revertBurnsDay > 0` (even with higher daily IP limit & `hasUntrustedCpiTarget: false`) -> `429 DAILY_SPONSOR_BUDGET_REACHED`!
  //    (b) Fresh IP with `revertBurnsDay === 0` AND `hasUntrustedCpiTarget: true` -> `429 DAILY_SPONSOR_BUDGET_REACHED`!
  //    (c) Honest fresh IP with `revertBurnsDay === 0` AND `hasUntrustedCpiTarget: false` -> STILL ALLOWED (`allowed === true`)!
  const todayKey = new Date().toISOString().slice(0, 10)
  harness.db
    .prepare('UPDATE daily_budgets SET sponsored_lamports = ? WHERE day = ? AND cluster = ?')
    .run(100_000, todayKey, 'mainnet')

  const bBudgetRev = await guard.begin({ clientIp: '198.51.100.20', nullifiers: ['nf-r2-budget-rev'] })
  assert.equal(bBudgetRev.allowed, true)
  const deniedBudgetRev = await guard.authorizeSpend({
    ipHash: ipAttacker,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r2-budget-rev'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: false,
    maxRevertBurnLamports: 10_000,
    limits: { ...baseLimits, ipCooldownSec: 0, ipMaxSponsoredPerHour: 10, ipMaxSponsoredPerDay: 10 },
  })
  assert.equal(deniedBudgetRev.allowed, false)
  assert.equal(deniedBudgetRev.status, 429)
  assert.equal(deniedBudgetRev.code, 'DAILY_SPONSOR_BUDGET_REACHED')

  const bBudgetUntrusted = await guard.begin({ clientIp: '198.51.100.21', nullifiers: ['nf-r2-budget-untrusted'] })
  assert.equal(bBudgetUntrusted.allowed, true)
  const deniedBudgetUntrusted = await guard.authorizeSpend({
    ipHash: bBudgetUntrusted.ipHash!,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r2-budget-untrusted'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: true,
    maxRevertBurnLamports: 10_000,
    limits: baseLimits,
  })
  assert.equal(deniedBudgetUntrusted.allowed, false)
  assert.equal(deniedBudgetUntrusted.status, 429)
  assert.equal(deniedBudgetUntrusted.code, 'DAILY_SPONSOR_BUDGET_REACHED')

  const bHonestFresh = await guard.begin({ clientIp: '198.51.100.22', nullifiers: ['nf-r2-honest-exhausted'] })
  assert.equal(bHonestFresh.allowed, true)
  const allowedHonestFresh = await guard.authorizeSpend({
    ipHash: bHonestFresh.ipHash!,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r2-honest-exhausted'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: false,
    maxRevertBurnLamports: 55_000,
    limits: baseLimits,
  })
  assert.equal(
    allowedHonestFresh.allowed,
    true,
    'Honest selfPaying: true user (revertBurnsDay===0 && !hasUntrustedCpiTarget) MUST succeed even when daily_budgets is 100% exhausted',
  )

  // 6. Concurrent untrusted CPI self-pay reservations account for `pending_reservations` against `daily_budgets`!
  harness.db
    .prepare('UPDATE daily_budgets SET sponsored_lamports = ? WHERE day = ? AND cluster = ?')
    .run(90_000, todayKey, 'mainnet')
  const bConc1 = await guard.begin({ clientIp: '198.51.100.23', nullifiers: ['nf-r2-conc-1'] })
  assert.equal(bConc1.allowed, true)
  const authConc1 = await guard.authorizeSpend({
    ipHash: bConc1.ipHash!,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r2-conc-1'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: true,
    maxRevertBurnLamports: 10_000,
    limits: baseLimits,
  })
  assert.equal(authConc1.allowed, true, 'First concurrent untrusted CPI tx fits remaining 10_000 lamports')
  const bConc2 = await guard.begin({ clientIp: '198.51.100.24', nullifiers: ['nf-r2-conc-2'] })
  assert.equal(bConc2.allowed, true)
  const deniedConc2 = await guard.authorizeSpend({
    ipHash: bConc2.ipHash!,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r2-conc-2'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: true,
    maxRevertBurnLamports: 10_000,
    limits: baseLimits,
  })
  assert.equal(deniedConc2.allowed, false, 'Second concurrent untrusted CPI tx must see pending burn reservation')
  assert.equal(deniedConc2.status, 429)
  assert.equal(deniedConc2.code, 'DAILY_SPONSOR_BUDGET_REACHED')

  // 7. End-to-end handleRelaySubmit wiring: passes `hasUntrustedCpiTarget` and `maxRevertBurnLamports` into `guard.authorizeSpend`!
  const worker = await getWorker()
  const poolPda = derivePoolPdaSync(0).address
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const escrow1 = deriveEscrowPdaSync(0, 1).address
  const relayerWsolAta = deriveAssociatedTokenAddressSync(relayerB58, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultWsolAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowWsolAta = deriveAssociatedTokenAddressSync(escrow1, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultUsdcAta = deriveAssociatedTokenAddressSync(vaultAuth, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowUsdcAta = deriveAssociatedTokenAddressSync(escrow1, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const dummyPageBytes = new Uint8Array(64).fill(0x5e)

  const submitAndInspectAuth = async (label: string, routerProg: string, requestedPriority: string, seed: number) => {
    const mockGuard = createMockGuard()
    const env = {
      RELAY_GUARD: mockGuard.namespace,
      MAINNET_RPC_URL: `https://mock-rpc.local/sysr2-1-${label}`,
      MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    } as Env
    const ix = buildExecViaEscrowInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: 0,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: 0n,
      outNfSeq: 0n,
      escrowShard: 1,
      changeMask: 0,
      inLeg: { mint: WSOL_MINT, vaultAta: vaultWsolAta, escrowAta: escrowWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
      outLeg: { mint: USDC_MINT, vaultAta: vaultUsdcAta, escrowAta: escrowUsdcAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
      relayerFeeAmount: 10_000_000n,
      relayerFeeRecipient: relayerWsolAta,
      feeOnOutput: false,
      proof192: dummyProof,
      nf0: new Uint8Array(32).fill(seed),
      nf1: new Uint8Array(32).fill(seed + 1),
      cm0: new Uint8Array(32),
      cm1: new Uint8Array(32),
      cm2: new Uint8Array(32),
      amountIn: 100_000_000n,
      minAmountOut: 1_000_000n,
      outStealthOwner: new Uint8Array(32).fill(0x02),
      outBlinding: new Uint8Array(32).fill(0x03),
      dynMemoHead: new Uint8Array(34).fill(0x04),
      dynMemoMask: new Uint8Array(72).fill(0x05),
      routerProg,
      routerIxData: new Uint8Array([1, 2, 3]),
      routerAccounts: [{ pubkey: base58Encode(new Uint8Array(32).fill(0x66)), isSigner: false, isWritable: true }],
      changeMemos: new Uint8Array(0),
    })
    const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
      [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
      [relayerWsolAta, { bytes: makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n), lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }],
      [poolPda, { bytes: makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n }), lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 10n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0RentVault, { bytes: new Uint8Array(16), lamports: 200_000_000, owner: AUDREN_PROGRAM_ID }],
      [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
      [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
      [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
      [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
    ])
    const res = await withMockFetch(
      async (_url, init) => {
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getMinimumBalanceForRentExemption') {
          const len = Number(body.params[0])
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: len === 0 ? 890_880 : len === 16 ? 1_002_240 : len === 165 ? 2_039_280 : len === SUBTREE_PAGE_LEN ? 58_352_640 : len === MEMO_PAGE_LEN ? 72_161_280 : 68_152_320,
          })
        }
        if (body.method === 'getAccountInfo') {
          const hit = accMap.get(String(body.params[0]))
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null } })
        }
        if (body.method === 'getLatestBlockhash') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0xb2)) } } })
        }
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 92_000 },
              value: addrs.map((a) => {
                const hit = accMap.get(a)
                return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
              }),
            },
          })
        }
        if (body.method === 'simulateTransaction') {
          const opts = body.params[1] as { accounts?: { addresses?: string[] } }
          const watchAddrs = opts?.accounts?.addresses ?? [relayerB58]
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 92_000 },
              value: {
                err: null,
                logs: ['OK'],
                unitsConsumed: 220_000,
                accounts: watchAddrs.map((a) =>
                  a === relayerB58
                    ? { lamports: 496_900_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }
                    : a === relayerWsolAta
                      ? { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 10_000_000n)), 'base64'] }
                      : { lamports: 1_002_240, owner: AUDREN_PROGRAM_ID, data: ['', 'base64'] },
                ),
              },
            },
          })
        }
        if (body.method === 'sendTransaction') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: `5SysR2Auth${label}Sig11111111111111111111` })
        }
        if (body.method === 'getSignatureStatuses') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 92_001, err: null, confirmationStatus: 'confirmed' }] } })
        }
        throw new Error(`Unexpected RPC in SysAudit-R2 #1 (${label}): ${body.method}`)
      },
      () =>
        worker.fetch(
          new Request('https://relay.audren.xyz/v1/relay/submit', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              cluster: 'mainnet',
              instructionDataB64: toBase64(ix.data),
              accounts: ix.accounts,
              priorityFeeLamports: requestedPriority,
            }),
          }),
          env,
        ),
    )
    assert.equal(res.status, 200)
    assert.equal(mockGuard.relayAuthorizeCalls.length, 1)
    return mockGuard.relayAuthorizeCalls[0]!
  }

  const untrustedAuth = await submitAndInspectAuth('untrusted', base58Encode(new Uint8Array(32).fill(0x77)), '50000', 0xd1)
  assert.equal(untrustedAuth.selfPaying, true)
  assert.equal(untrustedAuth.hasUntrustedCpiTarget, true)
  assert.equal(untrustedAuth.maxRevertBurnLamports, 10_000)

  const auditedAuth = await submitAndInspectAuth('audited', JUPITER_V6_ROUTER, '35000', 0xd3)
  assert.equal(auditedAuth.selfPaying, true)
  assert.equal(auditedAuth.hasUntrustedCpiTarget, false)
  assert.equal(auditedAuth.maxRevertBurnLamports, 40_000)
})

test('v1.3.0 SysAudit-R2 #2: fetchLiveRentSchedule clamps nullifierRentLamports and laneRentVaultReserveLamports to >= 1n on zero-rent clusters', async () => {
  clearLiveRentScheduleCache()
  const poolPda = derivePoolPdaSync(0).address
  const rpcZeroRent = 'https://mock-rpc.local/sysr2-2-zero-rent'
  const rpcZeroRentGovZero = 'https://mock-rpc.local/sysr2-2-zero-rent-gov-zero'
  const rpcNormalRent = 'https://mock-rpc.local/sysr2-2-normal-rent'
  const poolGovZero = makePoolStateBytes({ noteRentFee: 0n, nfRentFee: 0n })

  try {
    await withMockFetch(
      async (url, init) => {
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getMinimumBalanceForRentExemption') {
          if (url === rpcNormalRent) {
            const len = Number(body.params[0])
            return Response.json({
              jsonrpc: '2.0',
              id: 1,
              result: len === 0 ? 890_880 : len === 16 ? 1_002_240 : len === 165 ? 2_039_280 : 58_352_640,
            })
          }
          return Response.json({ jsonrpc: '2.0', id: 1, result: 0 })
        }
        if (body.method === 'getAccountInfo' && body.params[0] === poolPda) {
          if (url === rpcZeroRentGovZero) {
            return Response.json({
              jsonrpc: '2.0',
              id: 1,
              result: { value: { data: [toBase64(poolGovZero), 'base64'], lamports: 1, owner: AUDREN_PROGRAM_ID } },
            })
          }
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: null } })
        }
        throw new Error(`Unexpected RPC in SysAudit-R2 #2: ${body.method}`)
      },
      async () => {
        const schedZero = await fetchLiveRentSchedule(rpcZeroRent)
        assert.equal(schedZero.nullifierRentLamports, 1n)
        assert.equal(schedZero.laneRentVaultReserveLamports, 1n)
        assert.equal(schedZero.swapBaselineLamports, 2n * (1n + 1n) + 2n * 3n + 20_000n)

        const schedGovZero = await fetchLiveRentSchedule(rpcZeroRentGovZero)
        assert.equal(schedGovZero.nullifierRentLamports, 1n)
        assert.equal(schedGovZero.laneRentVaultReserveLamports, 1n)
        assert.equal(schedGovZero.swapBaselineLamports, 2n * (1n + 0n) + 2n * 0n + 20_000n)

        const schedNormal = await fetchLiveRentSchedule(rpcNormalRent)
        assert.equal(schedNormal.nullifierRentLamports, 890_880n)
        assert.equal(schedNormal.laneRentVaultReserveLamports, 1_002_240n)
      },
    )
  } finally {
    clearLiveRentScheduleCache()
  }
})

test('v1.3.0 Polish Medium #3: RelayGuard blocks concurrent selfPaying burn-risk bursts via pending_reservations and short-circuits revert-blocked IPs in begin() pre-simulation', async () => {
  const RelayGuard = await getRelayGuardClass()
  const harness = createSqliteDoHarness()
  const guard = new RelayGuard(harness.ctx, {} as Env)
  await harness.ready()

  const baseLimits = {
    maxDailySponsoredLamports: 1_000_000,
    ipMaxSponsoredPerHour: 2,
    ipMaxSponsoredPerDay: 3,
    ipCooldownSec: 12,
    selfPayPerIpPer10m: 60,
  }

  // 1. Concurrent selfPaying burst with `hasUntrustedCpiTarget: true` from same IP:
  //    1st request creates burn-risk `pending_reservations` (`self_paying=1, sponsored_lamports=10_000`);
  //    2nd concurrent request is blocked by cooldown, hourly, AND daily limits via `pending_reservations`!
  const bUntrusted1 = await guard.begin({ clientIp: '198.51.100.40', nullifiers: ['nf-m3-untrusted-1'] })
  assert.equal(bUntrusted1.allowed, true)
  const ipUntrusted = bUntrusted1.ipHash!
  const authUntrusted1 = await guard.authorizeSpend({
    ipHash: ipUntrusted,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-m3-untrusted-1'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: true,
    maxRevertBurnLamports: 10_000,
    limits: baseLimits,
  })
  assert.equal(authUntrusted1.allowed, true)

  // 1a. Concurrent 2nd request blocked by `SPONSOR_COOLDOWN`
  const bUntrusted2 = await guard.begin({ clientIp: '198.51.100.40', nullifiers: ['nf-m3-untrusted-2'] })
  assert.equal(bUntrusted2.allowed, true)
  const deniedUntrustedCool = await guard.authorizeSpend({
    ipHash: ipUntrusted,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-m3-untrusted-2'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: true,
    maxRevertBurnLamports: 10_000,
    limits: baseLimits,
  })
  assert.equal(deniedUntrustedCool.allowed, false)
  assert.equal(deniedUntrustedCool.status, 429)
  assert.equal(deniedUntrustedCool.code, 'SPONSOR_COOLDOWN')
  assert.ok((deniedUntrustedCool.retryAfterSec ?? 0) >= 1)

  // Verify denied concurrent request released `inflight_nullifiers`
  const nf2Row = harness.db
    .prepare('SELECT nullifier FROM inflight_nullifiers WHERE nullifier = ?')
    .get('nf-m3-untrusted-2')
  assert.equal(nf2Row, undefined, 'Denied concurrent selfPaying request must release inflight_nullifiers')

  // 1b. Concurrent 2nd request with cooldown=0 & ipMaxSponsoredPerHour=1 blocked by `IP_HOURLY_SPONSOR_LIMIT`
  const bUntrustedHr = await guard.begin({ clientIp: '198.51.100.40', nullifiers: ['nf-m3-untrusted-hr'] })
  assert.equal(bUntrustedHr.allowed, true)
  const deniedUntrustedHr = await guard.authorizeSpend({
    ipHash: ipUntrusted,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-m3-untrusted-hr'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: true,
    maxRevertBurnLamports: 10_000,
    limits: { ...baseLimits, ipCooldownSec: 0, ipMaxSponsoredPerHour: 1, ipMaxSponsoredPerDay: 5 },
  })
  assert.equal(deniedUntrustedHr.allowed, false)
  assert.equal(deniedUntrustedHr.status, 429)
  assert.equal(deniedUntrustedHr.code, 'IP_HOURLY_SPONSOR_LIMIT')

  // 1c. Concurrent 2nd request with cooldown=0 & ipMaxSponsoredPerDay=1 blocked by `IP_DAILY_SPONSOR_LIMIT`
  const bUntrustedDay = await guard.begin({ clientIp: '198.51.100.40', nullifiers: ['nf-m3-untrusted-day'] })
  assert.equal(bUntrustedDay.allowed, true)
  const deniedUntrustedDay = await guard.authorizeSpend({
    ipHash: ipUntrusted,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-m3-untrusted-day'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: true,
    maxRevertBurnLamports: 10_000,
    limits: { ...baseLimits, ipCooldownSec: 0, ipMaxSponsoredPerHour: 5, ipMaxSponsoredPerDay: 1 },
  })
  assert.equal(deniedUntrustedDay.allowed, false)
  assert.equal(deniedUntrustedDay.status, 429)
  assert.equal(deniedUntrustedDay.code, 'IP_DAILY_SPONSOR_LIMIT')

  // 2. Concurrent selfPaying burst after 1 confirmed revert (even with `hasUntrustedCpiTarget: false`):
  const bAfterRev0 = await guard.begin({ clientIp: '198.51.100.41', nullifiers: ['nf-m3-rev-0'] })
  assert.equal(bAfterRev0.allowed, true)
  const ipAfterRev = bAfterRev0.ipHash!
  await guard.commit({
    ipHash: ipAfterRev,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-m3-rev-0'],
    sponsoredLamports: 10_000,
    selfPaying: false,
    recordFailure: true,
  })
  // Backdate confirmed revert by 60s (past 12s cooldown, still inside 1h and 24h)
  harness.db
    .prepare('UPDATE ip_events SET created_at = ? WHERE ip_hash = ? AND failed = 1 AND sponsored_lamports > 0')
    .run(Date.now() - 60_000, ipAfterRev)

  // 1st concurrent audited selfPaying request succeeds (1 committed < 2) and writes burn-risk pending reservation
  const bAfterRev1 = await guard.begin({ clientIp: '198.51.100.41', nullifiers: ['nf-m3-rev-1'] })
  assert.equal(bAfterRev1.allowed, true)
  const authAfterRev1 = await guard.authorizeSpend({
    ipHash: ipAfterRev,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-m3-rev-1'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: false,
    maxRevertBurnLamports: 10_000,
    limits: { ...baseLimits, ipCooldownSec: 12, ipMaxSponsoredPerHour: 2, ipMaxSponsoredPerDay: 2 },
  })
  assert.equal(authAfterRev1.allowed, true)

  // 2nd concurrent audited request while 1st is still pending:
  // 2a. Blocked by `SPONSOR_COOLDOWN` via fresh `pendingBurnRiskLastTs`
  const bAfterRev2a = await guard.begin({ clientIp: '198.51.100.41', nullifiers: ['nf-m3-rev-2a'] })
  assert.equal(bAfterRev2a.allowed, true)
  const deniedRev2a = await guard.authorizeSpend({
    ipHash: ipAfterRev,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-m3-rev-2a'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: false,
    maxRevertBurnLamports: 10_000,
    limits: { ...baseLimits, ipCooldownSec: 12, ipMaxSponsoredPerHour: 5, ipMaxSponsoredPerDay: 5 },
  })
  assert.equal(deniedRev2a.allowed, false)
  assert.equal(deniedRev2a.code, 'SPONSOR_COOLDOWN')

  // 2b. Blocked by `IP_HOURLY_SPONSOR_LIMIT` (1 committed + 1 pending = 2 >= 2)
  const bAfterRev2b = await guard.begin({ clientIp: '198.51.100.41', nullifiers: ['nf-m3-rev-2b'] })
  assert.equal(bAfterRev2b.allowed, true)
  const deniedRev2b = await guard.authorizeSpend({
    ipHash: ipAfterRev,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-m3-rev-2b'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: false,
    maxRevertBurnLamports: 10_000,
    limits: { ...baseLimits, ipCooldownSec: 0, ipMaxSponsoredPerHour: 2, ipMaxSponsoredPerDay: 5 },
  })
  assert.equal(deniedRev2b.allowed, false)
  assert.equal(deniedRev2b.code, 'IP_HOURLY_SPONSOR_LIMIT')

  // 2c. Backdate confirmed revert by 2h (outside 1h, inside 24h) -> blocked by `IP_DAILY_SPONSOR_LIMIT` (1 committed + 1 pending = 2 >= 2)
  harness.db
    .prepare('UPDATE ip_events SET created_at = ? WHERE ip_hash = ? AND failed = 1 AND sponsored_lamports > 0')
    .run(Date.now() - 2 * 3_600_000, ipAfterRev)
  const bAfterRev2c = await guard.begin({ clientIp: '198.51.100.41', nullifiers: ['nf-m3-rev-2c'] })
  assert.equal(bAfterRev2c.allowed, true)
  const deniedRev2c = await guard.authorizeSpend({
    ipHash: ipAfterRev,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-m3-rev-2c'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: false,
    maxRevertBurnLamports: 10_000,
    limits: { ...baseLimits, ipCooldownSec: 0, ipMaxSponsoredPerHour: 5, ipMaxSponsoredPerDay: 2 },
  })
  assert.equal(deniedRev2c.allowed, false)
  assert.equal(deniedRev2c.code, 'IP_DAILY_SPONSOR_LIMIT')

  // 3. Honest audited `selfPaying` concurrent burst (fresh IP, `revertBurnsDay === 0 && !hasUntrustedCpiTarget`)
  //    stores `sponsored_lamports = 0` in `pending_reservations` -> concurrent requests remain ALLOWED!
  const bHonest1 = await guard.begin({ clientIp: '198.51.100.42', nullifiers: ['nf-m3-honest-1'] })
  assert.equal(bHonest1.allowed, true)
  const ipHonest = bHonest1.ipHash!
  const authHonest1 = await guard.authorizeSpend({
    ipHash: ipHonest,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-m3-honest-1'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: false,
    maxRevertBurnLamports: 40_000,
    limits: { ...baseLimits, ipCooldownSec: 12, ipMaxSponsoredPerHour: 1, ipMaxSponsoredPerDay: 1 },
  })
  assert.equal(authHonest1.allowed, true)

  const bHonest2 = await guard.begin({
    clientIp: '198.51.100.42',
    nullifiers: ['nf-m3-honest-2'],
    cluster: 'mainnet',
    hasUntrustedCpiTarget: false,
    limits: { ipCooldownSec: 12, ipMaxSponsoredPerHour: 1, ipMaxSponsoredPerDay: 1 },
  })
  assert.equal(bHonest2.allowed, true, 'Honest audited concurrent burst MUST pass begin()')
  const authHonest2 = await guard.authorizeSpend({
    ipHash: ipHonest,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-m3-honest-2'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: false,
    maxRevertBurnLamports: 40_000,
    limits: { ...baseLimits, ipCooldownSec: 12, ipMaxSponsoredPerHour: 1, ipMaxSponsoredPerDay: 1 },
  })
  assert.equal(
    authHonest2.allowed,
    true,
    'Honest audited concurrent selfPaying swaps (pending sponsored_lamports=0) MUST NOT block each other',
  )

  // 4. `guard.begin()` pre-sim short-circuit checks:
  // 4a. Concurrent untrusted CPI tx in `begin()` is short-circuited BEFORE inserting `inflight_nullifiers`!
  const beginUntrustedDenied = await guard.begin({
    clientIp: '198.51.100.40',
    nullifiers: ['nf-m3-begin-untrusted'],
    cluster: 'mainnet',
    hasUntrustedCpiTarget: true,
    limits: { ipCooldownSec: 12, ipMaxSponsoredPerHour: 5, ipMaxSponsoredPerDay: 5 },
  })
  assert.equal(beginUntrustedDenied.allowed, false)
  assert.equal(beginUntrustedDenied.status, 429)
  assert.equal(beginUntrustedDenied.code, 'SPONSOR_COOLDOWN')
  assert.equal(
    harness.db.prepare('SELECT nullifier FROM inflight_nullifiers WHERE nullifier = ?').get('nf-m3-begin-untrusted'),
    undefined,
    'begin() rejection MUST NOT insert inflight_nullifiers',
  )

  // 4b. Confirmed revert-blocked IP short-circuits in `begin()` across cooldown, hourly, and daily limits!
  const ipPreBlocked = await guard.hashClientIp('198.51.100.43')
  await guard.commit({
    ipHash: ipPreBlocked,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-m3-pre-rev-1'],
    sponsoredLamports: 10_000,
    selfPaying: false,
    recordFailure: true,
  })
  const beginCool = await guard.begin({
    clientIp: '198.51.100.43',
    nullifiers: ['nf-m3-pre-blocked-cool'],
    cluster: 'mainnet',
    hasUntrustedCpiTarget: false,
    limits: { ipCooldownSec: 12, ipMaxSponsoredPerHour: 5, ipMaxSponsoredPerDay: 5 },
  })
  assert.equal(beginCool.allowed, false)
  assert.equal(beginCool.status, 429)
  assert.equal(beginCool.code, 'SPONSOR_COOLDOWN')
  assert.equal(
    harness.db.prepare('SELECT nullifier FROM inflight_nullifiers WHERE nullifier = ?').get('nf-m3-pre-blocked-cool'),
    undefined,
  )

  const beginHr = await guard.begin({
    clientIp: '198.51.100.43',
    nullifiers: ['nf-m3-pre-blocked-hr'],
    cluster: 'mainnet',
    hasUntrustedCpiTarget: false,
    limits: { ipCooldownSec: 0, ipMaxSponsoredPerHour: 1, ipMaxSponsoredPerDay: 5 },
  })
  assert.equal(beginHr.allowed, false)
  assert.equal(beginHr.status, 429)
  assert.equal(beginHr.code, 'IP_HOURLY_SPONSOR_LIMIT')
  assert.equal(
    harness.db.prepare('SELECT nullifier FROM inflight_nullifiers WHERE nullifier = ?').get('nf-m3-pre-blocked-hr'),
    undefined,
  )

  harness.db
    .prepare('UPDATE ip_events SET created_at = ? WHERE ip_hash = ? AND failed = 1 AND sponsored_lamports > 0')
    .run(Date.now() - 2 * 3_600_000, ipPreBlocked)
  const beginDay = await guard.begin({
    clientIp: '198.51.100.43',
    nullifiers: ['nf-m3-pre-blocked-day'],
    cluster: 'mainnet',
    hasUntrustedCpiTarget: false,
    limits: { ipCooldownSec: 0, ipMaxSponsoredPerHour: 5, ipMaxSponsoredPerDay: 1 },
  })
  assert.equal(beginDay.allowed, false)
  assert.equal(beginDay.status, 429)
  assert.equal(beginDay.code, 'IP_DAILY_SPONSOR_LIMIT')
  assert.equal(
    harness.db.prepare('SELECT nullifier FROM inflight_nullifiers WHERE nullifier = ?').get('nf-m3-pre-blocked-day'),
    undefined,
  )

  // 4c. Honest (`failed = 0`) sponsored tx MUST NOT cause `begin()` to block a subsequent self-paying request!
  const ipHonestSp = await guard.hashClientIp('198.51.100.44')
  await guard.commit({
    ipHash: ipHonestSp,
    cluster: 'mainnet',
    opKind: 'transfer',
    nullifiers: ['nf-m3-honest-sp-1'],
    sponsoredLamports: 25_000,
    selfPaying: false,
  })
  const beginAfterHonestSp = await guard.begin({
    clientIp: '198.51.100.44',
    nullifiers: ['nf-m3-honest-sp-next'],
    cluster: 'mainnet',
    hasUntrustedCpiTarget: false,
    limits: { ipCooldownSec: 12, ipMaxSponsoredPerHour: 1, ipMaxSponsoredPerDay: 1 },
  })
  assert.equal(
    beginAfterHonestSp.allowed,
    true,
    'begin() MUST NOT block honest selfPaying request after an honest (failed=0) sponsored tx',
  )

  // 5. End-to-end `handleRelaySubmit` with real SQLite `RelayGuard`:
  //    (a) Already revert-blocked IP returns 429 BEFORE any RPC (`simulateTransaction` === 0) and inserts 0 `inflight_nullifiers`!
  //    (b) Honest self-paying swap right after an honest (`failed=0`) sponsored tx passes `begin()` and returns 200!
  const worker = await getWorker()
  const e2eHarness = createSqliteDoHarness()
  const e2eGuard = new RelayGuard(e2eHarness.ctx, {} as Env)
  await e2eHarness.ready()
  const e2eGuardNamespace = {
    idFromName: () => ({} as DurableObjectId),
    get: () => e2eGuard,
  } as unknown as Env['RELAY_GUARD']

  const blockedClientIp = '203.0.113.77'
  const blockedIpHash = await e2eGuard.hashClientIp(blockedClientIp)
  await e2eGuard.commit({
    ipHash: blockedIpHash,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-e2e-prior-revert'],
    sponsoredLamports: 10_000,
    selfPaying: false,
    recordFailure: true,
  })

  const honestClientIp = '203.0.113.78'
  const honestIpHash = await e2eGuard.hashClientIp(honestClientIp)
  await e2eGuard.commit({
    ipHash: honestIpHash,
    cluster: 'mainnet',
    opKind: 'transfer',
    nullifiers: ['nf-e2e-prior-honest-sp'],
    sponsoredLamports: 25_000,
    selfPaying: false,
  })

  const poolPda = derivePoolPdaSync(0).address
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const escrow1 = deriveEscrowPdaSync(0, 1).address
  const relayerWsolAta = deriveAssociatedTokenAddressSync(relayerB58, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultWsolAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowWsolAta = deriveAssociatedTokenAddressSync(escrow1, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const vaultUsdcAta = deriveAssociatedTokenAddressSync(vaultAuth, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowUsdcAta = deriveAssociatedTokenAddressSync(escrow1, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const dummyPageBytes = new Uint8Array(64).fill(0x5e)

  const makeAuditedExecIx = (nfSeed: number) =>
    buildExecViaEscrowInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: 0,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: 0n,
      outNfSeq: 0n,
      escrowShard: 1,
      changeMask: 0,
      inLeg: { mint: WSOL_MINT, vaultAta: vaultWsolAta, escrowAta: escrowWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
      outLeg: { mint: USDC_MINT, vaultAta: vaultUsdcAta, escrowAta: escrowUsdcAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
      relayerFeeAmount: 10_000_000n,
      relayerFeeRecipient: relayerWsolAta,
      feeOnOutput: false,
      proof192: dummyProof,
      nf0: new Uint8Array(32).fill(nfSeed),
      nf1: new Uint8Array(32).fill(nfSeed + 1),
      cm0: new Uint8Array(32),
      cm1: new Uint8Array(32),
      cm2: new Uint8Array(32),
      amountIn: 100_000_000n,
      minAmountOut: 1_000_000n,
      outStealthOwner: new Uint8Array(32).fill(0x02),
      outBlinding: new Uint8Array(32).fill(0x03),
      dynMemoHead: new Uint8Array(34).fill(0x04),
      dynMemoMask: new Uint8Array(72).fill(0x05),
      routerProg: JUPITER_V6_ROUTER,
      routerIxData: new Uint8Array([1, 2, 3]),
      routerAccounts: [{ pubkey: base58Encode(new Uint8Array(32).fill(0x66)), isSigner: false, isWritable: true }],
      changeMemos: new Uint8Array(0),
    })

  const e2eEnv = {
    RELAY_GUARD: e2eGuardNamespace,
    MAINNET_RPC_URL: 'https://mock-rpc.local/polish-m3-e2e',
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
    SPONSORED_COOLDOWN_SEC_MAINNET: '12',
    SPONSORED_PER_IP_PER_HOUR_MAINNET: '1',
    SPONSORED_PER_IP_PER_DAY_MAINNET: '1',
  } as Env

  // 5a. Revert-blocked IP: ZERO RPC calls, HTTP 429 SPONSOR_COOLDOWN, ZERO inflight_nullifiers inserted!
  const blockedIx = makeAuditedExecIx(0xe1)
  let blockedRpcCalls = 0
  const blockedRes = await withMockFetch(
    async () => {
      blockedRpcCalls++
      throw new Error('RPC must NEVER be called when guard.begin() short-circuits a revert-blocked IP!')
    },
    () =>
      worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'cf-connecting-ip': blockedClientIp },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(blockedIx.data),
            accounts: blockedIx.accounts,
          }),
        }),
        e2eEnv,
      ),
  )
  assert.equal(blockedRes.status, 429)
  const blockedBody = (await blockedRes.json()) as { code?: string; retryAfterSec?: number }
  assert.equal(blockedBody.code, 'SPONSOR_COOLDOWN')
  assert.ok((blockedBody.retryAfterSec ?? 0) >= 1)
  assert.equal(blockedRpcCalls, 0, 'simulateTransaction & all RPC calls MUST be skipped pre-sim')
  const remainingInflight = e2eHarness.db
    .prepare('SELECT COUNT(*) AS cnt FROM inflight_nullifiers')
    .get() as { cnt: number }
  assert.equal(remainingInflight.cnt, 0, 'Zero inflight_nullifiers may be inserted on pre-sim rejection')

  // 5b. Honest IP after honest (`failed=0`) sponsored tx: passes `begin()`, simulates, and succeeds with 200!
  const honestIx = makeAuditedExecIx(0xe3)
  const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [relayerWsolAta, { bytes: makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n), lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }],
    [poolPda, { bytes: makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n }), lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 10n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [lane0RentVault, { bytes: new Uint8Array(16), lamports: 200_000_000, owner: AUDREN_PROGRAM_ID }],
    [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
    [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
    [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
    [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
  ])
  let honestSimCalls = 0
  const honestRes = await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: len === 0 ? 890_880 : len === 16 ? 1_002_240 : len === 165 ? 2_039_280 : len === SUBTREE_PAGE_LEN ? 58_352_640 : len === MEMO_PAGE_LEN ? 72_161_280 : 68_152_320,
        })
      }
      if (body.method === 'getAccountInfo') {
        const hit = accMap.get(String(body.params[0]))
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null } })
      }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0xb3)) } } })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 93_000 },
            value: addrs.map((a) => {
              const hit = accMap.get(a)
              return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
            }),
          },
        })
      }
      if (body.method === 'simulateTransaction') {
        honestSimCalls++
        const opts = body.params[1] as { accounts?: { addresses?: string[] } }
        const watchAddrs = opts?.accounts?.addresses ?? [relayerB58]
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            context: { slot: 93_000 },
            value: {
              err: null,
              logs: ['OK'],
              unitsConsumed: 220_000,
              accounts: watchAddrs.map((a) =>
                a === relayerB58
                  ? { lamports: 496_900_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }
                  : a === relayerWsolAta
                    ? { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 10_000_000n)), 'base64'] }
                    : { lamports: 1_002_240, owner: AUDREN_PROGRAM_ID, data: ['', 'base64'] },
              ),
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5PolishM3HonestSelfPaySig1111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 93_001, err: null, confirmationStatus: 'confirmed' }] } })
      }
      throw new Error(`Unexpected RPC in Polish Medium #3 e2e: ${body.method}`)
    },
    () =>
      worker.fetch(
        new Request('https://relay.audren.xyz/v1/relay/submit', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'cf-connecting-ip': honestClientIp },
          body: JSON.stringify({
            cluster: 'mainnet',
            instructionDataB64: toBase64(honestIx.data),
            accounts: honestIx.accounts,
          }),
        }),
        e2eEnv,
      ),
  )
  assert.equal(honestRes.status, 200, 'Honest selfPaying tx after honest (failed=0) sponsored tx MUST succeed')
  assert.equal(honestSimCalls, 1)
})

test('v1.3.0 Polish Low #3: refillSinglePayer crossAtaViolation catches bytes.length change and delegated_amount tampering on watched other ATAs', async () => {
  const mockJup = 'https://mock-jup-polish-low3.local'
  const USDT_MINT = 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB'
  const wsolAta = deriveAssociatedTokenAddressSync(relayerB58, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const usdcAta = deriveAssociatedTokenAddressSync(relayerB58, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const usdtAta = deriveAssociatedTokenAddressSync(relayerB58, USDT_MINT, CLASSIC_TOKEN_PROGRAM_ID).address

  const runCrossAtaCase = async (opts: {
    rpcUrl: string
    postUsdtMutate?: (bytes: Uint8Array) => Uint8Array
  }) => {
    const refillEnv = {
      MAINNET_RPC_URL: opts.rpcUrl,
      MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
      JUPITER_API_URL: mockJup,
    } as Env
    const refillCfg = loadPolicyConfig(refillEnv)
    let sendCalls = 0

    const report = await withMockFetch(
      async (url, init) => {
        if (url.startsWith(`${mockJup}/price/v3`)) {
          return Response.json({
            [WSOL_MINT]: { usdPrice: 150 },
            [USDC_MINT]: { usdPrice: 1 },
            [USDT_MINT]: { usdPrice: 1 },
          })
        }
        if (url.startsWith(`${mockJup}/swap/v1/quote`)) {
          const u = new URL(url)
          return Response.json({
            inputMint: u.searchParams.get('inputMint'),
            outputMint: WSOL_MINT,
            inAmount: u.searchParams.get('amount'),
            outAmount: '100000000',
            otherAmountThreshold: '98000000',
            slippageBps: 100,
            routePlan: [{ swapInfo: { label: 'Orca' }, percent: 100 }],
          })
        }
        if (url.startsWith(`${mockJup}/swap/v1/swap-instructions`)) {
          return Response.json({
            swapInstruction: {
              programId: JUPITER_V6_ROUTER,
              accounts: [
                { pubkey: relayerB58, isSigner: true, isWritable: true },
                { pubkey: usdcAta, isSigner: false, isWritable: true },
              ],
              data: toBase64(new Uint8Array([1, 2, 3])),
            },
            addressLookupTableAddresses: [],
          })
        }
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getBalance') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: 20_000_000 } })
        }
        if (body.method === 'getTokenAccountsByOwner') {
          const filter = body.params[1] as { programId: string }
          if (filter.programId === CLASSIC_TOKEN_PROGRAM_ID) {
            return Response.json({
              jsonrpc: '2.0',
              id: 1,
              result: {
                value: [
                  {
                    pubkey: usdcAta,
                    account: {
                      owner: CLASSIC_TOKEN_PROGRAM_ID,
                      data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 15_000_000n)), 'base64'],
                    },
                  },
                  {
                    pubkey: usdtAta,
                    account: {
                      owner: CLASSIC_TOKEN_PROGRAM_ID,
                      data: [toBase64(makeTokenAccountBytes(USDT_MINT, relayerB58, 50_000_000n)), 'base64'],
                    },
                  },
                ],
              },
            })
          }
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [] } })
        }
        if (body.method === 'getLatestBlockhash') {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0xa7)) } },
          })
        }
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          if (addrs.includes(USDC_MINT) || addrs.includes(USDT_MINT)) {
            return Response.json({
              jsonrpc: '2.0',
              id: 1,
              result: {
                context: { slot: 6000 },
                value: addrs.map(() => ({
                  data: [toBase64(makeClassicMintBytes(6)), 'base64'],
                  lamports: 2_000_000,
                  owner: CLASSIC_TOKEN_PROGRAM_ID,
                })),
              },
            })
          }
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 6000 },
              value: addrs.map((a) => {
                if (a === relayerB58) {
                  return { data: ['', 'base64'], lamports: 20_000_000, owner: SYSTEM_PROGRAM_ID }
                }
                if (a === wsolAta) {
                  return {
                    data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n)), 'base64'],
                    lamports: 2_039_280,
                    owner: CLASSIC_TOKEN_PROGRAM_ID,
                  }
                }
                if (a === usdcAta) {
                  return {
                    data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 15_000_000n)), 'base64'],
                    lamports: 2_039_280,
                    owner: CLASSIC_TOKEN_PROGRAM_ID,
                  }
                }
                if (a === usdtAta) {
                  return {
                    data: [toBase64(makeTokenAccountBytes(USDT_MINT, relayerB58, 50_000_000n)), 'base64'],
                    lamports: 2_039_280,
                    owner: CLASSIC_TOKEN_PROGRAM_ID,
                  }
                }
                return null
              }),
            },
          })
        }
        if (body.method === 'simulateTransaction') {
          const simOpts = body.params[1] as { accounts?: { addresses?: string[] } }
          const watchAddrs = simOpts?.accounts?.addresses ?? []
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 6000 },
              value: {
                err: null,
                logs: ['Refill Swap OK'],
                unitsConsumed: 180_000,
                accounts: watchAddrs.map((a) => {
                  if (a === relayerB58) {
                    return { lamports: 118_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] }
                  }
                  if (a === wsolAta) {
                    return {
                      lamports: 2_039_280,
                      owner: CLASSIC_TOKEN_PROGRAM_ID,
                      data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n)), 'base64'],
                    }
                  }
                  if (a === usdcAta) {
                    return {
                      lamports: 2_039_280,
                      owner: CLASSIC_TOKEN_PROGRAM_ID,
                      data: [toBase64(makeTokenAccountBytes(USDC_MINT, relayerB58, 0n)), 'base64'],
                    }
                  }
                  if (a === usdtAta) {
                    let postBytes = makeTokenAccountBytes(USDT_MINT, relayerB58, 50_000_000n)
                    if (opts.postUsdtMutate) postBytes = opts.postUsdtMutate(postBytes)
                    return {
                      lamports: 2_039_280,
                      owner: CLASSIC_TOKEN_PROGRAM_ID,
                      data: [toBase64(postBytes), 'base64'],
                    }
                  }
                  return null
                }),
              },
            },
          })
        }
        if (body.method === 'sendTransaction') {
          sendCalls++
          return Response.json({ jsonrpc: '2.0', id: 1, result: '5PolishLow3CrossAtaOkSig11111111111111111' })
        }
        if (body.method === 'getSignatureStatuses') {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: { value: [{ slot: 6001, err: null, confirmationStatus: 'confirmed' }] },
          })
        }
        throw new Error(`Unexpected RPC in Polish Low #3: ${url} ${body.method}`)
      },
      () => runAutoRefill(refillEnv, refillCfg),
    )
    return { report, sendCalls }
  }

  // 1. Token-2022 Reallocate / bytes.length change on watched other ATA -> REJECTED!
  const lengthChange = await runCrossAtaCase({
    rpcUrl: 'https://mock-rpc.local/polish-low3-length',
    postUsdtMutate: (b) => {
      const extended = new Uint8Array(b.length + 6)
      extended.set(b, 0)
      return extended
    },
  })
  assert.equal(lengthChange.sendCalls, 0)
  assert.ok(
    lengthChange.report.details.some(
      (d) => d.includes('cross-ATA invariant violated') && d.includes('changed owner, length, or token metadata'),
    ),
  )

  // 2. `delegated_amount` (`bytes[121..129]`) tampering on watched other ATA -> REJECTED!
  const delegatedAmtChange = await runCrossAtaCase({
    rpcUrl: 'https://mock-rpc.local/polish-low3-delegated-amt',
    postUsdtMutate: (b) => {
      b.set(u64le(123n), 121)
      return b
    },
  })
  assert.equal(delegatedAmtChange.sendCalls, 0)
  assert.ok(
    delegatedAmtChange.report.details.some(
      (d) => d.includes('cross-ATA invariant violated') && d.includes('changed delegate, state, or close authority'),
    ),
  )

  // 3. Clean watched other ATA -> succeeds!
  const clean = await runCrossAtaCase({
    rpcUrl: 'https://mock-rpc.local/polish-low3-clean',
  })
  assert.equal(clean.sendCalls, 1)
  assert.equal(clean.report.action, 'swapped_fees')
})

test('v1.3.0 Final-R1 #1: proactiveOnlySlotSkew cross-slot concurrent relayer debit uses deterministic minExpectedCostLamports instead of false 402/400/downgrade', async () => {
  const worker = await getWorker()
  const poolPda = derivePoolPdaSync(0).address
  const poolNoteRentFee = 1_000_000n
  const poolNfRentFee = 113_567n
  const poolBytes = makePoolStateBytes({
    activeLanes: 4,
    rootEpochInterval: 32n,
    noteRentFee: poolNoteRentFee,
    nfRentFee: poolNfRentFee,
  })
  const dummyPageBytes = new Uint8Array(64).fill(0x5b)
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const lane1Pda = deriveLanePdaSync(0, 1).address
  const lane1RentVault = deriveLaneRentVaultPdaSync(0, 1).address
  const fvkJson = JSON.stringify({
    spendPkHex: toHex(relayerFvk.spendPk),
    nkHex: toHex(relayerFvk.nk),
    viewSkHex: toHex(relayerFvk.viewSk),
    viewPkHex: toHex(relayerFvk.viewPk),
  })

  const subRent = 58_352_640n
  const srRent = 68_152_320n
  const memoRent = 72_161_280n
  const nfPageRent = 68_152_320n
  const nullifierRent = 890_880n
  const noteRentUnit = deterministicNoteRentFee(poolNoteRentFee, subRent, srRent, memoRent)
  const expectedBatchMinCost =
    5_000n +
    5_000n + // default priorityFeeLamports
    4n * (nullifierRent + poolNfRentFee) + // 2 ix * 2 nullifiers
    4n * noteRentUnit // 2 ix * 2 outputs (0b101)
  const expectedSingleMinCost =
    5_000n +
    5_000n +
    2n * (nullifierRent + poolNfRentFee) +
    2n * noteRentUnit

  async function runCrossSlotCase(opts: {
    rpcUrl: string
    mode: 'batch' | 'single'
    concurrentRelayerDebit: number
    sameSlot?: boolean
    malformedPool?: boolean
    nfSeed: number
  }) {
    clearLiveRentScheduleCache()
    const guard = createMockGuard()
    const env = {
      RELAY_GUARD: guard.namespace,
      MAINNET_RPC_URL: opts.rpcUrl,
      MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
      MAINNET_RELAYER_FVK_JSON: fvkJson,
      MAX_DAILY_SPONSORED_SOL_MAINNET: '0',
    } as Env

    // Tight honest fees covering ~1.15x exact minExpectedCostLamports (well below cost + 0.005 SOL!)
    const batchPerIxFee = (expectedBatchMinCost * 115n) / 200n
    const singleFee = (expectedSingleMinCost * 115n) / 100n
    const cm2a = makeShieldedFeeCm2(opts.mode === 'batch' ? batchPerIxFee : singleFee, wsolMintBytes, opts.nfSeed)
    const ixA = buildTransactInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: 0,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: 0n,
      outNfSeq: 0n,
      outputMask: 0b101,
      assetMode: ASSET_MODE_PRIVATE,
      proof192: dummyProof,
      nf0: new Uint8Array(32).fill(opts.nfSeed),
      nf1: new Uint8Array(32).fill(opts.nfSeed + 1),
      cm0: new Uint8Array(32).fill(0x11),
      cm1: new Uint8Array(32),
      cm2: cm2a.cm2,
      publicAmountOut: 0n,
      relayerFeeAmount: 0n,
      memosBytes: new Uint8Array([...new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x11), ...cm2a.memo]),
    })
    const cm2b = makeShieldedFeeCm2(batchPerIxFee, wsolMintBytes, opts.nfSeed + 2)
    const ixB = buildTransactInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: 1,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: 0n,
      outNfSeq: 0n,
      outputMask: 0b101,
      assetMode: ASSET_MODE_PRIVATE,
      proof192: dummyProof,
      nf0: new Uint8Array(32).fill(opts.nfSeed + 2),
      nf1: new Uint8Array(32).fill(opts.nfSeed + 3),
      cm0: new Uint8Array(32).fill(0x22),
      cm1: new Uint8Array(32),
      cm2: cm2b.cm2,
      publicAmountOut: 0n,
      relayerFeeAmount: 0n,
      memosBytes: new Uint8Array([...new Uint8Array(MEMO_ENTRY_WIRE_LEN).fill(0x22), ...cm2b.memo]),
    })

    // Lane 0 is at >= 90% MemoPage (`nextLeaf = 86` -> `memoRem = 10`), triggering optional proactive OpenPage
    // which then hits `proactiveOnlySlotSkew` when `sameSlot` is false!
    const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
      [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
      [
        poolPda,
        {
          bytes: opts.malformedPool ? new Uint8Array(8).fill(0xde) : poolBytes,
          lamports: 2_000_000,
          owner: AUDREN_PROGRAM_ID,
        },
      ],
      [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 86n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0RentVault, { bytes: new Uint8Array(16), lamports: 200_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane1Pda, { bytes: makeLaneStateBytes({ laneId: 1, nextLeaf: 10n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane1RentVault, { bytes: new Uint8Array(16), lamports: 200_000_000, owner: AUDREN_PROGRAM_ID }],
      [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
      [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
      [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
      [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
      [deriveSubtreePdaSync(0, 1, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
      [deriveSubrootPdaSync(0, 1, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
      [deriveMemoPdaSync(0, 1, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
      [deriveNfPagePdaSync(0, 1, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
    ])

    let procFetchIdx = 0
    let simIdx = 0
    const ownTxCost = Number(opts.mode === 'batch' ? expectedBatchMinCost : expectedSingleMinCost)
    const reqPayload =
      opts.mode === 'batch'
        ? {
            cluster: 'mainnet',
            instructions: [
              { instructionDataB64: toBase64(ixA.data), accounts: ixA.accounts },
              { instructionDataB64: toBase64(ixB.data), accounts: ixB.accounts },
            ],
          }
        : {
            cluster: 'mainnet',
            instructionDataB64: toBase64(ixA.data),
            accounts: ixA.accounts,
          }

    const res = await withMockFetch(
      async (_url, init) => {
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getMinimumBalanceForRentExemption') {
          const len = Number(body.params[0])
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result:
              len === 0
                ? 890_880
                : len === 16
                  ? 1_002_240
                  : len === 165
                    ? 2_039_280
                    : len === SUBTREE_PAGE_LEN
                      ? Number(subRent)
                      : len === MEMO_PAGE_LEN
                        ? Number(memoRent)
                        : Number(nfPageRent),
          })
        }
        if (body.method === 'getAccountInfo') {
          const hit = accMap.get(String(body.params[0]))
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              value: hit
                ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner }
                : null,
            },
          })
        }
        if (body.method === 'getLatestBlockhash') {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x9a)) } },
          })
        }
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          const rpcOpts = body.params[1] as { commitment?: string }
          const isProc = rpcOpts?.commitment === 'processed'
          if (isProc) procFetchIdx++
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: opts.sameSlot ? 99_000 : isProc ? 99_010 + procFetchIdx : 99_000 },
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
          simIdx++
          const rpcOpts = body.params[1] as { accounts?: { addresses?: string[] } }
          const watchCount = rpcOpts?.accounts?.addresses?.length ?? 1
          // Post-sim relayer balance reflects own tx cost PLUS concurrent user's SOL debit!
          const postRelayer = 500_000_000 - ownTxCost - opts.concurrentRelayerDebit
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: opts.sameSlot ? 99_000 : 99_500 + simIdx },
              value: {
                err: null,
                logs: ['OK'],
                unitsConsumed: 180_000,
                accounts: [
                  { lamports: postRelayer, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                  ...Array.from({ length: Math.max(0, watchCount - 1) }, () => ({
                    lamports: 127_800_000,
                    owner: AUDREN_PROGRAM_ID,
                    data: ['', 'base64'],
                  })),
                ],
              },
            },
          })
        }
        if (body.method === 'sendTransaction') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: `5FinalR1CrossSlot${opts.mode}${opts.nfSeed}1111111111` })
        }
        if (body.method === 'getSignatureStatuses') {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: { value: [{ slot: 99_600, err: null, confirmationStatus: 'confirmed' }] },
          })
        }
        throw new Error(`Unexpected RPC in Final-R1 #1: ${body.method}`)
      },
      () =>
        worker.fetch(
          new Request('https://relay.audren.xyz/v1/relay/submit', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(reqPayload),
          }),
          env,
        ),
    )
    const body = (await res.json()) as {
      ok?: boolean
      code?: string
      billingMode?: string
      netSponsoredLamports?: string
      openedPagesCount?: number
      simulatedCostLamports?: string
    }
    return { status: res.status, body }
  }

  // 1. 2-ix merge batch under proactiveOnlySlotSkew + 0.005 SOL concurrent relayer debit -> 200 self_paying (NOT 402 FEE_REQUIRED)!
  const batch5m = await runCrossSlotCase({
    rpcUrl: 'https://mock-rpc.local/final-r1-f1-batch-5m',
    mode: 'batch',
    concurrentRelayerDebit: 5_000_000,
    nfSeed: 0x31,
  })
  assert.equal(batch5m.status, 200, `Expected 200 self_paying batch, got ${batch5m.status}: ${JSON.stringify(batch5m.body)}`)
  assert.equal(batch5m.body.billingMode, 'self_paying')
  assert.equal(batch5m.body.netSponsoredLamports, '0')
  assert.equal(batch5m.body.openedPagesCount, 0)
  assert.equal(BigInt(batch5m.body.simulatedCostLamports!), expectedBatchMinCost)

  // 2. 2-ix merge batch under proactiveOnlySlotSkew + 0.060 SOL concurrent rollover debit -> 200 self_paying (NOT 400 COST_CEILING_EXCEEDED)!
  const batch60m = await runCrossSlotCase({
    rpcUrl: 'https://mock-rpc.local/final-r1-f1-batch-60m',
    mode: 'batch',
    concurrentRelayerDebit: 60_000_000,
    nfSeed: 0x35,
  })
  assert.equal(batch60m.status, 200, `Expected 200 self_paying batch under 0.06 SOL concurrent debit, got ${batch60m.status}: ${JSON.stringify(batch60m.body)}`)
  assert.equal(batch60m.body.billingMode, 'self_paying')
  assert.equal(BigInt(batch60m.body.simulatedCostLamports!), expectedBatchMinCost)

  // 3. Mode 1 single transfer under proactiveOnlySlotSkew + 0.005 SOL concurrent debit -> stays self_paying (NOT downgraded to sponsored / 429)!
  const single5m = await runCrossSlotCase({
    rpcUrl: 'https://mock-rpc.local/final-r1-f1-single-5m',
    mode: 'single',
    concurrentRelayerDebit: 5_000_000,
    nfSeed: 0x39,
  })
  assert.equal(single5m.status, 200, `Expected 200 self_paying single transfer, got ${single5m.status}: ${JSON.stringify(single5m.body)}`)
  assert.equal(single5m.body.billingMode, 'self_paying')
  assert.equal(single5m.body.netSponsoredLamports, '0')
  assert.equal(BigInt(single5m.body.simulatedCostLamports!), expectedSingleMinCost)

  // 4. Same-slot (`preCtx.slot === sim.slot`) MUST still enforce `max(rawOutflowLamports, minExpectedCostLamports)` -> 400 COST_CEILING_EXCEEDED!
  const sameSlot60m = await runCrossSlotCase({
    rpcUrl: 'https://mock-rpc.local/final-r1-f1-sameslot-60m',
    mode: 'single',
    concurrentRelayerDebit: 60_000_000,
    sameSlot: true,
    nfSeed: 0x3d,
  })
  assert.equal(sameSlot60m.status, 400)
  assert.equal(sameSlot60m.body.code, 'COST_CEILING_EXCEEDED')

  // 5. Malformed `PoolState` (`!poolDecodedOk`) under cross-slot MUST still retain `max(rawOutflowLamports, minExpectedCostLamports)` -> 400 COST_CEILING_EXCEEDED!
  const malformedPool60m = await runCrossSlotCase({
    rpcUrl: 'https://mock-rpc.local/final-r1-f1-badpool-60m',
    mode: 'single',
    concurrentRelayerDebit: 60_000_000,
    malformedPool: true,
    nfSeed: 0x41,
  })
  assert.equal(malformedPool60m.status, 400)
  assert.equal(malformedPool60m.body.code, 'COST_CEILING_EXCEEDED')
})

test('v1.3.0 Final-R1 #2: RelayGuard authorizeSpend sponsored branch counts in-flight self_paying=1 burn-risk reservations while excluding honest audited self_paying (sponsored_lamports=0)', async () => {
  const RelayGuard = await getRelayGuardClass()
  const harness = createSqliteDoHarness()
  const guard = new RelayGuard(harness.ctx, {} as Env)
  await harness.ready()

  const baseLimits = {
    maxDailySponsoredLamports: 1_000_000,
    ipMaxSponsoredPerHour: 2,
    ipMaxSponsoredPerDay: 3,
    ipCooldownSec: 12,
    selfPayPerIpPer10m: 60,
  }

  // 1. In-flight untrusted-CPI `selfPaying: true` reservation (`self_paying=1, sponsored_lamports=10_000`):
  //    MUST block an overlapping `sponsored` (`selfPaying: false`) request from the same IP across cooldown, hourly, AND daily limits!
  const bUntrusted = await guard.begin({ clientIp: '198.51.100.70', nullifiers: ['nf-r1f2-untrusted-1'] })
  assert.equal(bUntrusted.allowed, true)
  const ipUntrusted = bUntrusted.ipHash!
  const authUntrusted = await guard.authorizeSpend({
    ipHash: ipUntrusted,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r1f2-untrusted-1'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: true,
    maxRevertBurnLamports: 10_000,
    limits: baseLimits,
  })
  assert.equal(authUntrusted.allowed, true)

  // 1a. Overlapping sponsored request blocked by `SPONSOR_COOLDOWN`
  const bSpCool = await guard.begin({ clientIp: '198.51.100.70', nullifiers: ['nf-r1f2-sp-cool'] })
  assert.equal(bSpCool.allowed, true)
  const deniedSpCool = await guard.authorizeSpend({
    ipHash: ipUntrusted,
    cluster: 'mainnet',
    opKind: 'transfer',
    nullifiers: ['nf-r1f2-sp-cool'],
    sponsoredLamports: 25_000,
    selfPaying: false,
    limits: { ...baseLimits, ipCooldownSec: 12, ipMaxSponsoredPerHour: 5, ipMaxSponsoredPerDay: 5 },
  })
  assert.equal(deniedSpCool.allowed, false)
  assert.equal(deniedSpCool.status, 429)
  assert.equal(deniedSpCool.code, 'SPONSOR_COOLDOWN')

  // 1b. Overlapping sponsored request blocked by `IP_HOURLY_SPONSOR_LIMIT` (1 in-flight burn-risk >= 1/hr)
  const bSpHr = await guard.begin({ clientIp: '198.51.100.70', nullifiers: ['nf-r1f2-sp-hr'] })
  assert.equal(bSpHr.allowed, true)
  const deniedSpHr = await guard.authorizeSpend({
    ipHash: ipUntrusted,
    cluster: 'mainnet',
    opKind: 'transfer',
    nullifiers: ['nf-r1f2-sp-hr'],
    sponsoredLamports: 25_000,
    selfPaying: false,
    limits: { ...baseLimits, ipCooldownSec: 0, ipMaxSponsoredPerHour: 1, ipMaxSponsoredPerDay: 5 },
  })
  assert.equal(deniedSpHr.allowed, false)
  assert.equal(deniedSpHr.status, 429)
  assert.equal(deniedSpHr.code, 'IP_HOURLY_SPONSOR_LIMIT')

  // 1c. Overlapping sponsored request blocked by `IP_DAILY_SPONSOR_LIMIT` (1 in-flight burn-risk >= 1/day)
  const bSpDay = await guard.begin({ clientIp: '198.51.100.70', nullifiers: ['nf-r1f2-sp-day'] })
  assert.equal(bSpDay.allowed, true)
  const deniedSpDay = await guard.authorizeSpend({
    ipHash: ipUntrusted,
    cluster: 'mainnet',
    opKind: 'transfer',
    nullifiers: ['nf-r1f2-sp-day'],
    sponsoredLamports: 25_000,
    selfPaying: false,
    limits: { ...baseLimits, ipCooldownSec: 0, ipMaxSponsoredPerHour: 5, ipMaxSponsoredPerDay: 1 },
  })
  assert.equal(deniedSpDay.allowed, false)
  assert.equal(deniedSpDay.status, 429)
  assert.equal(deniedSpDay.code, 'IP_DAILY_SPONSOR_LIMIT')

  // 2. Attacker at `ipMaxSponsoredPerHour - 1` (1 committed revert burn + 1 in-flight untrusted-CPI selfPaying):
  //    overlapping `sponsored` tx MUST NOT bypass `ipMaxSponsoredPerHour = 2`!
  const ipBoundary = await guard.hashClientIp('198.51.100.71')
  await guard.commit({
    ipHash: ipBoundary,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r1f2-bound-rev'],
    sponsoredLamports: 10_000,
    selfPaying: false,
    recordFailure: true,
  })
  harness.db
    .prepare('UPDATE ip_events SET created_at = ? WHERE ip_hash = ? AND failed = 1')
    .run(Date.now() - 60_000, ipBoundary)
  const bBound1 = await guard.begin({ clientIp: '198.51.100.71', nullifiers: ['nf-r1f2-bound-1'] })
  assert.equal(bBound1.allowed, true)
  const authBound1 = await guard.authorizeSpend({
    ipHash: ipBoundary,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r1f2-bound-1'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: true,
    maxRevertBurnLamports: 10_000,
    limits: { ...baseLimits, ipCooldownSec: 12, ipMaxSponsoredPerHour: 2, ipMaxSponsoredPerDay: 5 },
  })
  assert.equal(authBound1.allowed, true)
  const bBound2 = await guard.begin({ clientIp: '198.51.100.71', nullifiers: ['nf-r1f2-bound-2'] })
  assert.equal(bBound2.allowed, true)
  const deniedBoundSp = await guard.authorizeSpend({
    ipHash: ipBoundary,
    cluster: 'mainnet',
    opKind: 'transfer',
    nullifiers: ['nf-r1f2-bound-2'],
    sponsoredLamports: 25_000,
    selfPaying: false,
    limits: { ...baseLimits, ipCooldownSec: 0, ipMaxSponsoredPerHour: 2, ipMaxSponsoredPerDay: 5 },
  })
  assert.equal(deniedBoundSp.allowed, false)
  assert.equal(deniedBoundSp.code, 'IP_HOURLY_SPONSOR_LIMIT')

  // 3. In-flight honest audited `selfPaying: true` reservation (`self_paying=1, sponsored_lamports=0`):
  //    MUST NOT block an overlapping `sponsored` request from the same IP!
  const bHonestSelf = await guard.begin({ clientIp: '198.51.100.72', nullifiers: ['nf-r1f2-honest-self'] })
  assert.equal(bHonestSelf.allowed, true)
  const ipHonest = bHonestSelf.ipHash!
  const authHonestSelf = await guard.authorizeSpend({
    ipHash: ipHonest,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r1f2-honest-self'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: false,
    maxRevertBurnLamports: 40_000,
    limits: { ...baseLimits, ipCooldownSec: 12, ipMaxSponsoredPerHour: 1, ipMaxSponsoredPerDay: 1 },
  })
  assert.equal(authHonestSelf.allowed, true)

  const bHonestSp = await guard.begin({ clientIp: '198.51.100.72', nullifiers: ['nf-r1f2-honest-sp'] })
  assert.equal(bHonestSp.allowed, true)
  const authHonestSp = await guard.authorizeSpend({
    ipHash: ipHonest,
    cluster: 'mainnet',
    opKind: 'transfer',
    nullifiers: ['nf-r1f2-honest-sp'],
    sponsoredLamports: 25_000,
    selfPaying: false,
    limits: { ...baseLimits, ipCooldownSec: 12, ipMaxSponsoredPerHour: 1, ipMaxSponsoredPerDay: 1 },
  })
  assert.equal(
    authHonestSp.allowed,
    true,
    'Honest audited selfPaying reservation (sponsored_lamports=0) MUST NOT block overlapping sponsored tx',
  )

  // 4. Reciprocal guarantee (`checkPerIpRevertBurnLimits` retains `AND self_paying = 1`):
  //    An in-flight honest `sponsored` reservation (`self_paying=0, sponsored_lamports=25_000`) MUST NOT block
  //    an overlapping honest audited `selfPaying: true` swap from the same IP!
  const bHonestSelf2 = await guard.begin({ clientIp: '198.51.100.72', nullifiers: ['nf-r1f2-honest-self-2'] })
  assert.equal(bHonestSelf2.allowed, true)
  const authHonestSelf2 = await guard.authorizeSpend({
    ipHash: ipHonest,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r1f2-honest-self-2'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: false,
    maxRevertBurnLamports: 40_000,
    limits: { ...baseLimits, ipCooldownSec: 12, ipMaxSponsoredPerHour: 1, ipMaxSponsoredPerDay: 1 },
  })
  assert.equal(
    authHonestSelf2.allowed,
    true,
    'In-flight honest sponsored tx MUST NOT block overlapping honest audited selfPaying swap',
  )

  // 5. Symmetric reverse-order race (Round 2 #1): while a sponsored tx (`self_paying=0, sponsored_lamports>0`)
  //    is in flight, a burn-risk `selfPaying: true` request (`hasUntrustedCpiTarget: true` OR post-revert IP)
  //    MUST be blocked in BOTH `begin()` and `authorizeSpend()`!
  const bUntrustedWhileSp = await guard.begin({
    clientIp: '198.51.100.72',
    nullifiers: ['nf-r2f1-untrusted-while-sp'],
    cluster: 'mainnet',
    hasUntrustedCpiTarget: true,
    limits: { ipCooldownSec: 12, ipMaxSponsoredPerHour: 10, ipMaxSponsoredPerDay: 20 },
  })
  assert.equal(bUntrustedWhileSp.allowed, false)
  assert.equal(bUntrustedWhileSp.code, 'SPONSOR_COOLDOWN')

  const bUntrustedAuth = await guard.begin({
    clientIp: '198.51.100.72',
    nullifiers: ['nf-r2f1-untrusted-auth'],
  })
  assert.equal(bUntrustedAuth.allowed, true)
  const authUntrustedWhileSp = await guard.authorizeSpend({
    ipHash: ipHonest,
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-r2f1-untrusted-auth'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: true,
    maxRevertBurnLamports: 10_000,
    limits: { ...baseLimits, ipCooldownSec: 0, ipMaxSponsoredPerHour: 1, ipMaxSponsoredPerDay: 10 },
  })
  assert.equal(authUntrustedWhileSp.allowed, false)
  assert.equal(authUntrustedWhileSp.code, 'IP_HOURLY_SPONSOR_LIMIT')
})

test('Audit remediation regressions (H-1, H-2, H-6, M-2, M-5, M-6, M-7, L-3): OpenPage maxPayerDeficit, H-2 setupAtas dedup, maxBatchSize, omitted transfer mint, IPv6 /64 + revert-burn circuit breaker, read rate limit, ambiguous sendTransaction, & u64 clamps', async () => {
  const worker = await getWorker()
  const { resetReadRateLimits, PROACTIVE_OPEN_PAGE_WIRE_BYTES } = await import('../src/index')
  const { normalizeClientIpForRateLimit, RelayGuard } = await import('../src/policy/guard-do')
  const { buildOpenPageSolanaIx } = await import('../src/solana/audren')
  const { waitForConfirmation } = await import('../src/solana/rpc')
  resetReadRateLimits()

  // H-1: 23 B OpenPage wire layout with explicit `maxPayerDeficit` + 65 B proactive wire estimate
  assert.equal(PROACTIVE_OPEN_PAGE_WIRE_BYTES, 65)
  const openIxZero = buildOpenPageSolanaIx({
    payer: base58Encode(new Uint8Array(32).fill(0x11)),
    pageKind: OPEN_PAGE_KIND_MEMO,
    poolId: 0,
    laneId: 0,
    pageSeq: 1n,
    maxPayerDeficit: 0n,
  })
  assert.equal(openIxZero.data.length, 23)
  assert.equal(
    new DataView(openIxZero.data.buffer, openIxZero.data.byteOffset, openIxZero.data.byteLength).getBigUint64(15, true),
    0n,
  )

  // L-3: PYUSD removed from default self-pay allowlist & trusted freeze authority mints
  const PYUSD_MINT = '2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo'
  assert.equal(DEFAULT_SELF_PAY_FEE_MINTS.includes(PYUSD_MINT), false)
  assert.equal(TRUSTED_FREEZE_AUTHORITY_MINTS.has(PYUSD_MINT), false)

  // M-5 (IPv6 /64 normalization + IPv4-mapped unwrapping)
  assert.equal(
    normalizeClientIpForRateLimit('2001:db8:abcd:0012:1111:2222:3333:4444'),
    normalizeClientIpForRateLimit('2001:0db8:abcd:12::9999'),
  )
  assert.equal(
    normalizeClientIpForRateLimit('2001:db8:abcd:0012::1'),
    '2001:0db8:abcd:0012::/64',
  )
  assert.equal(
    normalizeClientIpForRateLimit('::ffff:198.51.100.42'),
    '198.51.100.42',
  )
  assert.equal(
    normalizeClientIpForRateLimit('[2001:db8:abcd:12::5]:443'),
    '2001:0db8:abcd:0012::/64',
  )

  // M-5 (Persistent SQLite global revert-burn circuit breaker across BOTH sponsored & fresh-IP audited selfPaying)
  const harness = createSqliteDoHarness()
  const guardDo = new RelayGuard(harness.ctx, {} as Env)
  const h1 = await guardDo.hashClientIp('2001:db8:abcd:12::1')
  const h2 = await guardDo.hashClientIp('2001:db8:abcd:12:ffff::99')
  assert.equal(h1, h2, 'Different hosts inside the same IPv6 /64 MUST share one ipHash')

  const breakerLimits = {
    maxDailySponsoredLamports: 100_000,
    ipMaxSponsoredPerHour: 10,
    ipMaxSponsoredPerDay: 20,
    ipCooldownSec: 0,
    selfPayPerIpPer10m: 40,
  }
  for (let i = 0; i < 2; i++) {
    const botIp = `203.0.113.${10 + i}`
    const b = await guardDo.begin({ clientIp: botIp, nullifiers: [`nf-bot-${i}`], cluster: 'mainnet', limits: breakerLimits })
    assert.equal(b.allowed, true)
    const a = await guardDo.authorizeSpend({
      ipHash: b.ipHash!,
      cluster: 'mainnet',
      opKind: 'exec_escrow',
      nullifiers: [`nf-bot-${i}`],
      sponsoredLamports: 0,
      selfPaying: true,
      hasUntrustedCpiTarget: false,
      maxRevertBurnLamports: 50_000,
      limits: breakerLimits,
    })
    assert.equal(a.allowed, true)
    await guardDo.commit({
      reservationId: a.reservationId,
      ipHash: b.ipHash!,
      cluster: 'mainnet',
      opKind: 'exec_escrow',
      nullifiers: [`nf-bot-${i}`],
      sponsoredLamports: 50_000,
      selfPaying: false,
      recordFailure: true,
    })
  }
  // 100_000 lamports burned in daily_revert_burns -> brand-new fresh IP MUST be halted on BOTH begin() and authorizeSpend()!
  const bFreshBlocked = await guardDo.begin({
    clientIp: '198.51.100.250',
    nullifiers: ['nf-fresh-blocked'],
    cluster: 'mainnet',
    limits: breakerLimits,
  })
  assert.equal(bFreshBlocked.allowed, false)
  assert.equal(bFreshBlocked.code, 'REVERT_BURN_CIRCUIT_BREAKER')
  const authFreshSelfBlocked = await guardDo.authorizeSpend({
    ipHash: 'fresh-ip-hash',
    cluster: 'mainnet',
    opKind: 'exec_escrow',
    nullifiers: ['nf-fresh-blocked-2'],
    sponsoredLamports: 0,
    selfPaying: true,
    hasUntrustedCpiTarget: false,
    maxRevertBurnLamports: 10_000,
    limits: breakerLimits,
  })
  assert.equal(authFreshSelfBlocked.allowed, false)
  assert.equal(authFreshSelfBlocked.code, 'REVERT_BURN_CIRCUIT_BREAKER')

  // H-6: /v1/info advertises maxBatchSize=1 without FVK and maxBatchSize=4 with FVK
  const relayerSecret = new Uint8Array(32).fill(0x5a)
  const relayerPub = ed25519.getPublicKey(relayerSecret)
  const relayerB58 = base58Encode(relayerPub)
  const fvkKeys = deriveKeysFromSeed(new Uint8Array(32).fill(0x5b))
  const fvkObj = exportFullViewingKey(fvkKeys)
  const fvkJson = JSON.stringify({
    spendPkHex: toHex(fvkObj.spendPk),
    nkHex: toHex(fvkObj.nk),
    viewSkHex: toHex(fvkObj.viewSk),
    viewPkHex: toHex(fvkObj.viewPk),
  })

  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getBalance') return Response.json({ jsonrpc: '2.0', id: 1, result: { value: 500_000_000 } })
      if (body.method === 'getMinimumBalanceForRentExemption') return Response.json({ jsonrpc: '2.0', id: 1, result: 890_880 })
      if (body.method === 'getAccountInfo') return Response.json({ jsonrpc: '2.0', id: 1, result: { value: null } })
      throw new Error(`Unexpected RPC in H-6 /v1/info: ${body.method}`)
    },
    async () => {
      const infoNoFvkRes = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/info?cluster=mainnet'),
        { MAINNET_RPC_URL: 'https://mock-rpc.local/h6-no-fvk', MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret) } as Env,
      )
      assert.equal(infoNoFvkRes.status, 200)
      const infoNoFvk = (await infoNoFvkRes.json()) as { supportedOperations: { transfer: { maxBatchSize: number } } }
      assert.equal(infoNoFvk.supportedOperations.transfer.maxBatchSize, 1)

      const infoWithFvkRes = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/info?cluster=mainnet'),
        {
          MAINNET_RPC_URL: 'https://mock-rpc.local/h6-with-fvk',
          MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
          MAINNET_RELAYER_FVK_JSON: fvkJson,
        } as Env,
      )
      assert.equal(infoWithFvkRes.status, 200)
      const infoWithFvk = (await infoWithFvkRes.json()) as { supportedOperations: { transfer: { maxBatchSize: number } } }
      assert.equal(infoWithFvk.supportedOperations.transfer.maxBatchSize, 4)
    },
  )

  // M-2: GET /v1/fee-quote?op=transfer with omitted mint and no FVK returns sponsored quote with ZERO mint RPC fetches
  let feeQuoteMultiAccountCalls = 0
  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMultipleAccounts') {
        feeQuoteMultiAccountCalls += 1
        throw new Error('Must NOT query mint accounts when op=transfer omits mint and FVK is unset')
      }
      if (body.method === 'getMinimumBalanceForRentExemption') return Response.json({ jsonrpc: '2.0', id: 1, result: 890_880 })
      if (body.method === 'getAccountInfo') return Response.json({ jsonrpc: '2.0', id: 1, result: { value: null } })
      throw new Error(`Unexpected RPC in M-2 fee-quote: ${body.method}`)
    },
    async () => {
      const res = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=transfer', {
          headers: { 'cf-connecting-ip': '198.51.100.77' },
        }),
        { MAINNET_RPC_URL: 'https://mock-rpc.local/m2-no-mint', MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret) } as Env,
      )
      assert.equal(res.status, 200)
      const body = (await res.json()) as { billingMode: string; feeMint: string; relayerFee: string }
      assert.equal(body.billingMode, 'sponsored')
      assert.equal(body.feeMint, '')
      assert.equal(body.relayerFee, '0')
      assert.equal(feeQuoteMultiAccountCalls, 0)
    },
  )

  // L-3: Overlong / >u64::MAX decimal strings rejected with 400
  const hugeDecimal = '9'.repeat(25)
  const overU64 = '18446744073709551616'
  const badFeeRes = await worker.fetch(
    new Request(`https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=withdraw&mint=${WSOL_MINT}&amount=${overU64}`, {
      headers: { 'cf-connecting-ip': '198.51.100.78' },
    }),
    { MAINNET_RPC_URL: 'https://mock-rpc.local/l3-bad-amount' } as Env,
  )
  assert.equal(badFeeRes.status, 400)
  const badSwapRes = await worker.fetch(
    new Request(`https://relay.audren.xyz/v1/swap/quote?cluster=mainnet&inputMint=${WSOL_MINT}&outputMint=${USDC_MINT}&amount=${hugeDecimal}`, {
      headers: { 'cf-connecting-ip': '198.51.100.78' },
    }),
    { MAINNET_RPC_URL: 'https://mock-rpc.local/l3-bad-swap' } as Env,
  )
  assert.equal(badSwapRes.status, 400)

  // M-6: Per-IP rate limit on /v1/swap/quote collapses IPv6 /64 hosts into one bucket
  resetReadRateLimits()
  for (let i = 0; i < 60; i++) {
    const r = await worker.fetch(
      new Request(`https://relay.audren.xyz/v1/swap/quote?cluster=mainnet&inputMint=invalid`, {
        headers: { 'cf-connecting-ip': `2001:db8:feed:cafe::${(i + 1).toString(16)}` },
      }),
      { MAINNET_RPC_URL: 'https://mock-rpc.local/m6-rl' } as Env,
    )
    assert.equal(r.status, 400, `Request ${i + 1}/60 should pass rate limiter`)
  }
  const r61 = await worker.fetch(
    new Request(`https://relay.audren.xyz/v1/swap/quote?cluster=mainnet&inputMint=invalid`, {
      headers: { 'cf-connecting-ip': '2001:db8:feed:cafe:9999::ffff' },
    }),
    { MAINNET_RPC_URL: 'https://mock-rpc.local/m6-rl' } as Env,
  )
  assert.equal(r61.status, 429, '61st request from same IPv6 /64 MUST hit 429 RATE_LIMITED')
  resetReadRateLimits()

  // H-2 + H-1 (preflightCommitment) + M-7 (ambiguous sendTransaction vs definite preflight rejection)
  const poolPda = derivePoolPdaSync(0).address
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const vaultUsdcAta = deriveAssociatedTokenAddressSync(vaultAuth, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const recipOwner = base58Encode(new Uint8Array(32).fill(0x71))
  const recipUsdcAta = deriveAssociatedTokenAddressSync(recipOwner, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const relayerUsdcAta = deriveAssociatedTokenAddressSync(relayerB58, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const dummyPageBytes = new Uint8Array(64).fill(0x5c)
  const makeWithdraw = (nfByte: number) =>
    buildTransactInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: 0,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: 0n,
      outNfSeq: 0n,
      outputMask: 0,
      assetMode: ASSET_MODE_PUBLIC,
      unwrapWsol: false,
      publicOutflow: { mint: USDC_MINT, vaultAta: vaultUsdcAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
      nf0: new Uint8Array(32).fill(nfByte),
      nf1: new Uint8Array(32).fill(nfByte + 1),
      cm0: new Uint8Array(32),
      cm1: new Uint8Array(32),
      cm2: new Uint8Array(32),
      proof192: new Uint8Array(192).fill(0x22),
      memosBytes: new Uint8Array(0),
      recipient: recipUsdcAta,
      relayerFeeRecipient: SYSTEM_PROGRAM_ID,
      publicAmountOut: 1_000_000n,
      relayerFeeAmount: 0n,
    })

  // Case A (H-2): setupAtas contains an ALREADY-INITIALIZED withdraw recipient ATA on a self-paying
  // WSOL withdraw -> MUST NOT compile CreateIdempotent (closes close-after-sim TOCTOU rent drain)!
  // Also verifies `preflightCommitment: 'confirmed'` when neither setupAtaInstructions nor OpenPage exists.
  {
    const guard = createMockGuard()
    const vaultWsolAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
    const recipWsolAta = deriveAssociatedTokenAddressSync(recipOwner, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
    const relayerWsolAta = deriveAssociatedTokenAddressSync(relayerB58, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
    const ix = buildTransactInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: 0,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: 0n,
      outNfSeq: 0n,
      outputMask: 0,
      assetMode: ASSET_MODE_PUBLIC,
      unwrapWsol: false,
      publicOutflow: { mint: WSOL_MINT, vaultAta: vaultWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
      nf0: new Uint8Array(32).fill(0xd1),
      nf1: new Uint8Array(32).fill(0xd2),
      cm0: new Uint8Array(32),
      cm1: new Uint8Array(32),
      cm2: new Uint8Array(32),
      proof192: new Uint8Array(192).fill(0x22),
      memosBytes: new Uint8Array(0),
      recipient: recipWsolAta,
      relayerFeeRecipient: relayerWsolAta,
      publicAmountOut: 100_000_000n,
      relayerFeeAmount: 5_000_000n,
    })
    let sentWire: Uint8Array | null = null
    let observedPreflight: string | undefined
    const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
      [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
      [relayerWsolAta, { bytes: makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n), lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }],
      [recipWsolAta, { bytes: makeTokenAccountBytes(WSOL_MINT, recipOwner, 0n), lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }],
      [poolPda, { bytes: makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n }), lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 10n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0RentVault, { bytes: new Uint8Array(16), lamports: 200_000_000, owner: AUDREN_PROGRAM_ID }],
      [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
      [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
      [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
      [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
    ])
    const res = await withMockFetch(
      async (_url, init) => {
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getMinimumBalanceForRentExemption') return Response.json({ jsonrpc: '2.0', id: 1, result: 890_880 })
        if (body.method === 'getAccountInfo') {
          const hit = accMap.get(String(body.params[0]))
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null } })
        }
        if (body.method === 'getLatestBlockhash') return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0xb2)) } } })
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 95_000 },
              value: addrs.map((a) => {
                const hit = accMap.get(a)
                return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
              }),
            },
          })
        }
        if (body.method === 'simulateTransaction') {
          const opts = body.params[1] as { accounts?: { addresses?: string[] } }
          const watchAddrs = opts?.accounts?.addresses ?? [relayerB58]
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 95_000 },
              value: {
                err: null,
                logs: ['OK'],
                unitsConsumed: 220_000,
                accounts: watchAddrs.map((a) =>
                  a === relayerWsolAta
                    ? {
                        lamports: 2_039_280,
                        owner: CLASSIC_TOKEN_PROGRAM_ID,
                        data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 5_000_000n)), 'base64'],
                      }
                    : { lamports: 498_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                ),
              },
            },
          })
        }
        if (body.method === 'sendTransaction') {
          sentWire = fromBase64(String(body.params[0]))
          observedPreflight = (body.params[1] as { preflightCommitment?: string })?.preflightCommitment
          return Response.json({ jsonrpc: '2.0', id: 1, result: '5H2DedupSig11111111111111111111111111111' })
        }
        if (body.method === 'getSignatureStatuses') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 95_001, err: null, confirmationStatus: 'confirmed' }] } })
        }
        throw new Error(`Unexpected RPC in H-2 test: ${body.method}`)
      },
      () =>
        worker.fetch(
          new Request('https://relay.audren.xyz/v1/relay/submit', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              cluster: 'mainnet',
              instructionDataB64: toBase64(ix.data),
              accounts: ix.accounts,
              setupAtas: [{ owner: recipOwner, mint: WSOL_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID }],
            }),
          }),
          {
            RELAY_GUARD: guard.namespace,
            MAINNET_RPC_URL: 'https://mock-rpc.local/h2-dedup',
            MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
          } as Env,
        ),
    )
    assert.equal(res.status, 200)
    assert.ok(sentWire)
    const decoded = decodeV1Tx(sentWire)
    assert.equal(decoded.instructions.length, 1, 'Already-existing setupAta MUST NOT compile CreateIdempotent')
    assert.equal(observedPreflight, 'confirmed')
  }

  // Case B (M-7 + H-1 preflightCommitment='processed'): Ambiguous HTTP 503 on sendTransaction retains locks!
  {
    const guard = createMockGuard()
    const ix = makeWithdraw(0xd5)
    let observedPreflight: string | undefined
    const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
      [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
      [poolPda, { bytes: makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n }), lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 10n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0RentVault, { bytes: new Uint8Array(16), lamports: 200_000_000, owner: AUDREN_PROGRAM_ID }],
      [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
      [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
      [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
      // Missing nfPage -> triggers mandatory OpenPage (`activeOpenPageIxs.length > 0`)!
    ])
    const res = await withMockFetch(
      async (_url, init) => {
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getMinimumBalanceForRentExemption') return Response.json({ jsonrpc: '2.0', id: 1, result: 890_880 })
        if (body.method === 'getAccountInfo') {
          const hit = accMap.get(String(body.params[0]))
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null } })
        }
        if (body.method === 'getLatestBlockhash') return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0xb3)) } } })
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 96_000 },
              value: addrs.map((a) => {
                const hit = accMap.get(a)
                return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
              }),
            },
          })
        }
        if (body.method === 'simulateTransaction') {
          const opts = body.params[1] as { accounts?: { addresses?: string[] } }
          const watchAddrs = opts?.accounts?.addresses ?? [relayerB58]
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 96_000 },
              value: {
                err: null,
                logs: ['OK'],
                unitsConsumed: 260_000,
                accounts: watchAddrs.map(() => ({ lamports: 498_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] })),
              },
            },
          })
        }
        if (body.method === 'sendTransaction') {
          observedPreflight = (body.params[1] as { preflightCommitment?: string })?.preflightCommitment
          return new Response('Gateway Timeout', { status: 504 })
        }
        throw new Error(`Unexpected RPC in M-7 ambiguous test: ${body.method}`)
      },
      () =>
        worker.fetch(
          new Request('https://relay.audren.xyz/v1/relay/submit', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              cluster: 'mainnet',
              instructionDataB64: toBase64(ix.data),
              accounts: ix.accounts,
            }),
          }),
          {
            RELAY_GUARD: guard.namespace,
            MAINNET_RPC_URL: 'https://mock-rpc.local/m7-ambiguous',
            MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
          } as Env,
        ),
    )
    assert.equal(res.status, 502)
    const body = (await res.json()) as { code?: string }
    assert.equal(body.code, 'BROADCAST_AMBIGUOUS')
    assert.equal(observedPreflight, 'processed', 'H-1: OpenPage tx MUST broadcast with preflightCommitment=processed')
    assert.equal(guard.relayReleaseCalls.length, 0, 'M-7: Ambiguous 504 sendTransaction MUST NOT release reservation/nullifier locks')
    assert.equal(guard.openPageReleaseCalls[0]?.graceTtlMs, 10_000, 'M-7: Ambiguous 504 MUST retain 10s grace lease on open_page_locks')
  }

  // Case C (M-7 control): Definite JSON-RPC -32002 preflight failure DOES release reservation/nullifiers cleanly!
  {
    const guard = createMockGuard()
    const ix = makeWithdraw(0xd9)
    const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
      [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
      [poolPda, { bytes: makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n }), lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 10n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0RentVault, { bytes: new Uint8Array(16), lamports: 200_000_000, owner: AUDREN_PROGRAM_ID }],
      [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
      [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
      [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
      [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
    ])
    const res = await withMockFetch(
      async (_url, init) => {
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getMinimumBalanceForRentExemption') return Response.json({ jsonrpc: '2.0', id: 1, result: 890_880 })
        if (body.method === 'getAccountInfo') {
          const hit = accMap.get(String(body.params[0]))
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null } })
        }
        if (body.method === 'getLatestBlockhash') return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0xb4)) } } })
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 97_000 },
              value: addrs.map((a) => {
                const hit = accMap.get(a)
                return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
              }),
            },
          })
        }
        if (body.method === 'simulateTransaction') {
          const opts = body.params[1] as { accounts?: { addresses?: string[] } }
          const watchAddrs = opts?.accounts?.addresses ?? [relayerB58]
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 97_000 },
              value: {
                err: null,
                logs: ['OK'],
                unitsConsumed: 220_000,
                accounts: watchAddrs.map(() => ({ lamports: 498_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] })),
              },
            },
          })
        }
        if (body.method === 'sendTransaction') {
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            error: { code: -32002, message: 'Transaction simulation failed: Blockhash not found' },
          })
        }
        throw new Error(`Unexpected RPC in M-7 preflight test: ${body.method}`)
      },
      () =>
        worker.fetch(
          new Request('https://relay.audren.xyz/v1/relay/submit', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              cluster: 'mainnet',
              instructionDataB64: toBase64(ix.data),
              accounts: ix.accounts,
            }),
          }),
          {
            RELAY_GUARD: guard.namespace,
            MAINNET_RPC_URL: 'https://mock-rpc.local/m7-preflight',
            MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
          } as Env,
        ),
    )
    assert.equal(res.status, 502)
    assert.equal(guard.relayReleaseCalls.length, 1, 'Definite -32002 preflight rejection MUST release reservation/nullifiers')
  }

  // L-3: waitForConfirmation honors bounded wall-clock maxWaitMs
  await withMockFetch(
    async () => Response.json({ jsonrpc: '2.0', id: 1, result: { value: [null] } }),
    async () => {
      const start = Date.now()
      await assert.rejects(
        () => waitForConfirmation('https://mock-rpc.local/l3-timeout', '5SigTimeout', 1_000),
        /Timed out waiting for confirmation/i,
      )
      assert.ok(Date.now() - start < 2_500, 'waitForConfirmation must stop promptly at maxWaitMs')
    },
  )
})

test('Round-1 review fixes: exact OpenPage deficit tightening, multi-pass setupAta convergence & fail-closed SLOT_SKEW, Wave-1 burn_risk circuit breaker, self-pay-only revert cap, & minFlatFeeUnits', async () => {
  const worker = await getWorker()
  const { RelayGuard } = await import('../src/policy/guard-do')
  const relayerSecret = new Uint8Array(32).fill(0x6b)
  const relayerPub = ed25519.getPublicKey(relayerSecret)
  const relayerB58 = base58Encode(relayerPub)
  const poolPda = derivePoolPdaSync(0).address
  const lane0Pda = deriveLanePdaSync(0, 0).address
  const lane0RentVault = deriveLaneRentVaultPdaSync(0, 0).address
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const vaultWsolAta = deriveAssociatedTokenAddressSync(vaultAuth, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const relayerWsolAta = deriveAssociatedTokenAddressSync(relayerB58, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const recipOwner = base58Encode(new Uint8Array(32).fill(0x88))
  const recipWsolAta = deriveAssociatedTokenAddressSync(recipOwner, WSOL_MINT, CLASSIC_TOKEN_PROGRAM_ID).address
  const dummyPageBytes = new Uint8Array(64).fill(0x5d)

  // 1. R1-4 #1: `minFlatFeeUnits` returned accurately for WSOL unwrap & SPL USDC across self_paying & sponsored
  {
    const cfg = loadPolicyConfig({} as Env)
    const rent = {
      nullifierRentLamports: 890_880n,
      nfPageRentPerNfLamports: 113_588n,
      pageRentPerNoteLamports: 1_000_000n,
      noteRentPerLeafLamports: 1_000_000n,
      ataRentLamports: 2_039_280n,
      laneRentVaultReserveLamports: 1_002_240n,
      subtreePageRentLamports: 58_352_640n,
      subrootPageRentLamports: 68_152_320n,
      memoPageRentLamports: 72_161_280n,
      nfPageRentLamports: 68_152_320n,
      swapBaselineLamports: 2_000_000n,
    }
    const qLargeUsdc = computeNativeFeeQuote({
      cfg,
      cluster: 'mainnet',
      op: 'withdraw',
      feeMint: USDC_MINT,
      feeDecimals: 6,
      feeTokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
      amount: 1_000_000_000_000_000n, // huge percentage-regime probe
      unwrapWsol: false,
      outputCount: 0,
      omitNf1: false,
      missingAtaCount: 0,
      feeRecipient: deriveAssociatedTokenAddressSync(relayerB58, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address,
      feeRecipientExists: true,
      feeShieldedAddress: null,
      solPriceUsd: 200,
      feeTokenPriceUsd: 1,
      rentSchedule: rent,
      hasUnsafeSelfPayExt: false,
      transferFee: null,
    })
    assert.equal(qLargeUsdc.billingMode, 'self_paying')
    assert.ok(qLargeUsdc.minFlatFeeUnits, 'minFlatFeeUnits must be present on priced SPL withdraw')
    assert.ok(
      BigInt(qLargeUsdc.minFlatFeeUnits) < BigInt(qLargeUsdc.relayerFee),
      'minFlatFeeUnits must report flat rent floor, NOT percentage fee on large probe',
    )

    const qSmallUsdc = computeNativeFeeQuote({
      cfg,
      cluster: 'mainnet',
      op: 'withdraw',
      feeMint: USDC_MINT,
      feeDecimals: 6,
      feeTokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
      amount: 100n, // sponsored tiny withdraw
      unwrapWsol: false,
      outputCount: 0,
      omitNf1: false,
      missingAtaCount: 0,
      feeRecipient: deriveAssociatedTokenAddressSync(relayerB58, USDC_MINT, CLASSIC_TOKEN_PROGRAM_ID).address,
      feeRecipientExists: true,
      feeShieldedAddress: null,
      solPriceUsd: 200,
      feeTokenPriceUsd: 1,
      rentSchedule: rent,
      hasUnsafeSelfPayExt: false,
      transferFee: null,
    })
    assert.equal(qSmallUsdc.billingMode, 'sponsored')
    assert.equal(
      qSmallUsdc.minFlatFeeUnits,
      qLargeUsdc.minFlatFeeUnits,
      'minFlatFeeUnits must be identical across large and tiny probes',
    )

    const qUnwrap = computeNativeFeeQuote({
      cfg,
      cluster: 'mainnet',
      op: 'withdraw',
      feeMint: WSOL_MINT,
      feeDecimals: 9,
      feeTokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
      amount: 10_000_000_000n,
      unwrapWsol: true,
      outputCount: 0,
      omitNf1: false,
      missingAtaCount: 0,
      feeRecipient: relayerB58,
      feeRecipientExists: true,
      feeShieldedAddress: null,
      solPriceUsd: 200,
      feeTokenPriceUsd: 200,
      rentSchedule: rent,
      hasUnsafeSelfPayExt: false,
      transferFee: null,
    })
    assert.equal(qUnwrap.billingMode, 'self_paying')
    assert.ok(qUnwrap.minFlatFeeUnits && BigInt(qUnwrap.minFlatFeeUnits) > 0n)
    assert.ok(BigInt(qUnwrap.minFlatFeeUnits) < BigInt(qUnwrap.relayerFee))
  }

  // 2. R1-3 Medium #3 & #4: Wave-1 pending `burn_risk_lamports` cap + self-pay-only `MAX_DAILY_SPONSORED_SOL_MAINNET=0`
  {
    const selfPayOnlyCfg = loadPolicyConfig({
      MAX_DAILY_SPONSORED_SOL_MAINNET: '0',
      MAX_DAILY_REVERT_BURN_SOL_MAINNET: '',
    } as Env)
    assert.equal(selfPayOnlyCfg.maxDailySponsoredLamports.mainnet, 0n)
    assert.equal(
      selfPayOnlyCfg.maxDailyRevertBurnLamports.mainnet,
      50_000_000n,
      'Self-pay-only relay (including empty MAX_DAILY_REVERT_BURN_SOL_MAINNET="") must default maxDailyRevertBurnLamports to 0.05 SOL instead of 0',
    )

    // R2-3 Medium-2: Explicit rawCap === 0 MUST still serialize Wave-1 concurrent bursts via pending_reservations.burn_risk_lamports
    {
      const zHarness = createSqliteDoHarness()
      const zGuard = new RelayGuard(zHarness.ctx, {} as Env)
      const zeroCapLimits = {
        maxDailySponsoredLamports: 0,
        maxDailyRevertBurnLamports: 0,
        ipMaxSponsoredPerHour: 10,
        ipMaxSponsoredPerDay: 20,
        ipCooldownSec: 0,
        selfPayPerIpPer10m: 40,
      }
      const b1 = await zGuard.begin({
        clientIp: '198.51.100.70',
        nullifiers: ['nf-zcap-1'],
        cluster: 'mainnet',
        limits: zeroCapLimits,
      })
      assert.equal(b1.allowed, true)
      const a1 = await zGuard.authorizeSpend({
        ipHash: b1.ipHash!,
        cluster: 'mainnet',
        opKind: 'exec_escrow',
        nullifiers: ['nf-zcap-1'],
        sponsoredLamports: 0,
        selfPaying: true,
        hasUntrustedCpiTarget: false,
        maxRevertBurnLamports: 50_000,
        limits: zeroCapLimits,
      })
      assert.equal(a1.allowed, true)
      // 2nd concurrent fresh IP MUST be blocked while tx 1 is in flight (`pendingBurnRiskToday > 0`)!
      const b2 = await zGuard.begin({
        clientIp: '198.51.100.71',
        nullifiers: ['nf-zcap-2'],
        cluster: 'mainnet',
        limits: zeroCapLimits,
      })
      assert.equal(b2.allowed, false)
      assert.equal(b2.code, 'REVERT_BURN_CIRCUIT_BREAKER')
      assert.equal(b2.retryAfterSec, 5, 'Transient in-flight serialization must emit short retryAfterSec=5 (not 3600)')
    }

    const harness = createSqliteDoHarness()
    const guardDo = new RelayGuard(harness.ctx, {} as Env)

    // Wave-1 concurrent botnet burst (`burnedToday === 0`): 2 in-flight 50k txs fill 100k cap -> 3rd fresh IP blocked!
    const waveLimits = {
      maxDailySponsoredLamports: 0,
      maxDailyRevertBurnLamports: 100_000,
      ipMaxSponsoredPerHour: 10,
      ipMaxSponsoredPerDay: 20,
      ipCooldownSec: 0,
      selfPayPerIpPer10m: 40,
    }
    const resIds: string[] = []
    for (let i = 0; i < 2; i++) {
      const b = await guardDo.begin({
        clientIp: `198.51.100.${50 + i}`,
        nullifiers: [`nf-wave1-${i}`],
        cluster: 'mainnet',
        limits: waveLimits,
      })
      assert.equal(b.allowed, true)
      const a = await guardDo.authorizeSpend({
        ipHash: b.ipHash!,
        cluster: 'mainnet',
        opKind: 'exec_escrow',
        nullifiers: [`nf-wave1-${i}`],
        sponsoredLamports: 0,
        selfPaying: true,
        hasUntrustedCpiTarget: false,
        maxRevertBurnLamports: 50_000,
        limits: waveLimits,
      })
      assert.equal(a.allowed, true)
      resIds.push(a.reservationId!)
    }
    // 3rd concurrent fresh IP hits REVERT_BURN_CIRCUIT_BREAKER on BOTH begin() and authorizeSpend()!
    const bWave3 = await guardDo.begin({
      clientIp: '198.51.100.52',
      nullifiers: ['nf-wave1-2'],
      cluster: 'mainnet',
      limits: waveLimits,
    })
    assert.equal(bWave3.allowed, false)
    assert.equal(bWave3.code, 'REVERT_BURN_CIRCUIT_BREAKER')

    // Release reservations & simulate 1 single 5,000-lamport revert under self-pay-only config -> fresh IP STILL allowed!
    await guardDo.release({ reservationId: resIds[0], ipHash: 'h0', cluster: 'mainnet', nullifiers: ['nf-wave1-0'] })
    await guardDo.release({ reservationId: resIds[1], ipHash: 'h1', cluster: 'mainnet', nullifiers: ['nf-wave1-1'] })
    await guardDo.commit({
      ipHash: 'h-one-revert',
      cluster: 'mainnet',
      opKind: 'exec_escrow',
      nullifiers: ['nf-one-revert'],
      sponsoredLamports: 5_000,
      selfPaying: false,
      recordFailure: true,
    })
    const bAfterSingleRevert = await guardDo.begin({
      clientIp: '198.51.100.99',
      nullifiers: ['nf-after-one-revert'],
      cluster: 'mainnet',
      limits: waveLimits,
    })
    assert.equal(bAfterSingleRevert.allowed, true, 'Self-pay-only relay must survive a single 5k revert')
    const aAfterSingleRevert = await guardDo.authorizeSpend({
      ipHash: bAfterSingleRevert.ipHash!,
      cluster: 'mainnet',
      opKind: 'exec_escrow',
      nullifiers: ['nf-after-one-revert'],
      sponsoredLamports: 0,
      selfPaying: true,
      hasUntrustedCpiTarget: false,
      maxRevertBurnLamports: 55_000,
      limits: waveLimits,
    })
    assert.equal(aAfterSingleRevert.allowed, true)
  }

  // 3. R1-3 High #1: Exact OpenPage `max_payer_deficit` tightened from 300M down to `0n` (fully funded)
  //    AND exact deficit `D_i` (partially funded) on the broadcast wire transaction!
  const runExactOpenPageTightenTest = async (vaultLamports: number, expectedDeficit: bigint, nfSeed: number) => {
    const guard = createMockGuard()
    const ix = buildTransactInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: 0,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: 0n,
      outNfSeq: 0n,
      outputMask: 0,
      assetMode: ASSET_MODE_PUBLIC,
      unwrapWsol: false,
      publicOutflow: { mint: WSOL_MINT, vaultAta: vaultWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
      nf0: new Uint8Array(32).fill(nfSeed),
      nf1: new Uint8Array(32).fill(nfSeed + 1),
      cm0: new Uint8Array(32),
      cm1: new Uint8Array(32),
      cm2: new Uint8Array(32),
      proof192: new Uint8Array(192).fill(0x22),
      memosBytes: new Uint8Array(0),
      recipient: recipWsolAta,
      relayerFeeRecipient: relayerWsolAta,
      publicAmountOut: 1_000_000_000n,
      relayerFeeAmount: 100_000_000n, // ample self-pay coverage
    })
    let sentWire: Uint8Array | null = null
    // Missing NullifierPage #0 -> triggers mandatory exact OpenPage
    const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
      [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
      [relayerWsolAta, { bytes: makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n), lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }],
      [recipWsolAta, { bytes: makeTokenAccountBytes(WSOL_MINT, recipOwner, 0n), lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }],
      [poolPda, { bytes: makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n }), lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 10n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0RentVault, { bytes: new Uint8Array(16), lamports: vaultLamports, owner: AUDREN_PROGRAM_ID }],
      [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
      [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
      [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
    ])
    const res = await withMockFetch(
      async (_url, init) => {
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getMinimumBalanceForRentExemption') {
          const sz = Number(body.params[0])
          return Response.json({ jsonrpc: '2.0', id: 1, result: 6_960 * (sz + 128) })
        }
        if (body.method === 'getLatestBlockhash') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0xc1)) } } })
        }
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 99_100 },
              value: addrs.map((a) => {
                const hit = accMap.get(a)
                return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
              }),
            },
          })
        }
        if (body.method === 'simulateTransaction') {
          const opts = body.params[1] as { accounts?: { addresses?: string[] } }
          const watchAddrs = opts?.accounts?.addresses ?? [relayerB58]
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 99_100 },
              value: {
                err: null,
                logs: ['OK'],
                unitsConsumed: 260_000,
                accounts: watchAddrs.map((a) =>
                  a === relayerWsolAta
                    ? {
                        lamports: 2_039_280,
                        owner: CLASSIC_TOKEN_PROGRAM_ID,
                        data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 100_000_000n)), 'base64'],
                      }
                    : { lamports: 500_000_000 - Number(expectedDeficit) - 2_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                ),
              },
            },
          })
        }
        if (body.method === 'sendTransaction') {
          sentWire = fromBase64(String(body.params[0]))
          return Response.json({ jsonrpc: '2.0', id: 1, result: '5TightenSig111111111111111111111111111111' })
        }
        if (body.method === 'getSignatureStatuses') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 99_101, err: null, confirmationStatus: 'confirmed' }] } })
        }
        throw new Error(`Unexpected RPC in tighten test: ${body.method}`)
      },
      () =>
        worker.fetch(
          new Request('https://relay.audren.xyz/v1/relay/submit', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              cluster: 'mainnet',
              instructionDataB64: toBase64(ix.data),
              accounts: ix.accounts,
            }),
          }),
          {
            RELAY_GUARD: guard.namespace,
            MAINNET_RPC_URL: `https://mock-rpc.local/r1-tighten-${nfSeed}`,
            MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
          } as Env,
        ),
    )
    assert.equal(res.status, 200)
    assert.ok(sentWire)
    const decoded = decodeV1Tx(sentWire)
    const openIx = decoded.instructions.find((i) => i.data[0] === TAG_OPEN_PAGE)
    assert.ok(openIx, 'Exact OpenPage must be compiled')
    assert.equal(openIx.data.length, 23)
    const wireMaxDeficit = new DataView(openIx.data.buffer, openIx.data.byteOffset, openIx.data.byteLength).getBigUint64(15, true)
    assert.equal(
      wireMaxDeficit,
      expectedDeficit,
      `Exact OpenPage max_payer_deficit must be tightened to ${expectedDeficit}`,
    )
  }
  // Vault has 200M lamports -> covers full 68,152,320 NfPage rent -> tightened to 0n
  await runExactOpenPageTightenTest(200_000_000, 0n, 0xe1)
  // Vault has 51,002,240 lamports (avail = 50,000,000 after 1,002,240 reserve) -> deficit = 68,152,320 - 50,000,000 = 18,152,320
  await runExactOpenPageTightenTest(51_002_240, 18_152_320n, 0xe3)

  // 4. R1-3 High #2 + Low #5: Multi-pass post-pin convergence strips 2 staggered setupAtas AND
  //    clears `hasActiveWithdrawRecipientAta` once recipient ATA is proven initialized, plus fail-closed 503 SLOT_SKEW!
  {
    const guard = createMockGuard()
    const ix = buildTransactInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: 0,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: 0n,
      outNfSeq: 0n,
      outputMask: 0,
      assetMode: ASSET_MODE_PUBLIC,
      unwrapWsol: false,
      publicOutflow: { mint: WSOL_MINT, vaultAta: vaultWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
      nf0: new Uint8Array(32).fill(0xe5),
      nf1: new Uint8Array(32).fill(0xe6),
      cm0: new Uint8Array(32),
      cm1: new Uint8Array(32),
      cm2: new Uint8Array(32),
      proof192: new Uint8Array(192).fill(0x22),
      memosBytes: new Uint8Array(0),
      recipient: recipWsolAta,
      relayerFeeRecipient: relayerWsolAta,
      publicAmountOut: 10_000_000n,
      relayerFeeAmount: 100n, // tiny fee -> sponsored! Would fail with 402 FEE_REQUIRED unless recipWsolAta is stripped!
    })
    let getMultiCount = 0
    let simCount = 0
    let sentWire: Uint8Array | null = null
    let observedPreflight: string | undefined
    const baseAccs = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
      [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
      [poolPda, { bytes: makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n }), lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 10n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0RentVault, { bytes: new Uint8Array(16), lamports: 200_000_000, owner: AUDREN_PROGRAM_ID }],
      [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
      [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
      [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
      [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
    ])
    const res = await withMockFetch(
      async (_url, init) => {
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getMinimumBalanceForRentExemption') return Response.json({ jsonrpc: '2.0', id: 1, result: 890_880 })
        if (body.method === 'getLatestBlockhash') return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0xc2)) } } })
        if (body.method === 'getMultipleAccounts') {
          getMultiCount += 1
          const addrs = body.params[0] as string[]
          // Call 1 (initial confirmed): neither ATA exists (slot 100)
          // Call 2 (pin #1): relayerWsolAta now exists (slot 101)
          // Call 3 (pin #2 after strip #1): recipWsolAta ALSO now exists (slot 102)
          const slot = 99 + getMultiCount
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot },
              value: addrs.map((a) => {
                if (a === relayerWsolAta && getMultiCount >= 2) {
                  return { data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n)), 'base64'], lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }
                }
                if (a === recipWsolAta && getMultiCount >= 3) {
                  return { data: [toBase64(makeTokenAccountBytes(WSOL_MINT, recipOwner, 0n)), 'base64'], lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }
                }
                const hit = baseAccs.get(a)
                return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
              }),
            },
          })
        }
        if (body.method === 'simulateTransaction') {
          simCount += 1
          // Sim 1 (slot 101 != 100 -> triggers pin #1 at slot 101)
          // Sim 2 (pin #1 at slot 101 -> matches -> pass 0 strips relayerWsolAta)
          // Sim 3 (after strip #1, slot 102 != 101 -> triggers pin #2 at slot 102)
          // Sim 4 (pin #2 at slot 102 -> matches -> pass 1 strips recipWsolAta)
          // Sim 5 (after strip #2, slot 102 === 102 -> converges cleanly!)
          const simSlot = simCount <= 2 ? 101 : 102
          const opts = body.params[1] as { accounts?: { addresses?: string[] } }
          const watchAddrs = opts?.accounts?.addresses ?? [relayerB58]
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: simSlot },
              value: {
                err: null,
                logs: ['OK'],
                unitsConsumed: 220_000,
                accounts: watchAddrs.map((a) =>
                  a === relayerWsolAta
                    ? { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 100n)), 'base64'] }
                    : { lamports: 498_000_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                ),
              },
            },
          })
        }
        if (body.method === 'sendTransaction') {
          sentWire = fromBase64(String(body.params[0]))
          observedPreflight = (body.params[1] as { preflightCommitment?: string })?.preflightCommitment
          return Response.json({ jsonrpc: '2.0', id: 1, result: '5StaggerStripSig1111111111111111111111111' })
        }
        if (body.method === 'getSignatureStatuses') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: [{ slot: 103, err: null, confirmationStatus: 'confirmed' }] } })
        }
        throw new Error(`Unexpected RPC in staggered strip test: ${body.method}`)
      },
      () =>
        worker.fetch(
          new Request('https://relay.audren.xyz/v1/relay/submit', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              cluster: 'mainnet',
              instructionDataB64: toBase64(ix.data),
              accounts: ix.accounts,
              setupAtas: [
                { owner: relayerB58, mint: WSOL_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
                { owner: recipOwner, mint: WSOL_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
              ],
            }),
          }),
          {
            RELAY_GUARD: guard.namespace,
            MAINNET_RPC_URL: 'https://mock-rpc.local/r1-stagger-2ata',
            MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
          } as Env,
        ),
    )
    assert.equal(res.status, 200, 'Sponsored withdraw MUST succeed once existing recipWsolAta is stripped across 2 passes')
    assert.ok(sentWire)
    assert.equal(
      observedPreflight,
      'processed',
      'R2-3 Medium-1: preflightCommitment MUST stay processed when slot-pinning promoted preCtxCommitment to processed and stripped all setupAtas',
    )
    const decoded = decodeV1Tx(sentWire)
    assert.equal(decoded.instructions.length, 1, 'BOTH staggered existing ATAs must be stripped (0 CreateIdempotent)')
  }

  // 5. R3-3 High: Pre-funded uninitialized System-owned 0-byte `isWithdrawRecipientAta` MUST NOT
  //    subtract `existingLamports` from `setupAtaDeficitFloor` (defeats post-sim CreateIdempotent +
  //    CloseAccount rent drain attack -> rejected with 402 FEE_REQUIRED when fee omits ATA rent)!
  {
    const guard = createMockGuard()
    const ix = buildTransactInstruction({
      payer: relayerB58,
      poolId: 0,
      rootRingKind: ROOT_RING_EPOCH,
      rootRingIdx: 0,
      outLaneId: 0,
      outSubSeq: 0n,
      outRootSeq: 0n,
      outMemoSeq: 0n,
      outNfSeq: 0n,
      outputMask: 0,
      assetMode: ASSET_MODE_PUBLIC,
      unwrapWsol: false,
      publicOutflow: { mint: WSOL_MINT, vaultAta: vaultWsolAta, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID },
      nf0: new Uint8Array(32).fill(0xf1),
      nf1: new Uint8Array(32).fill(0xf2),
      cm0: new Uint8Array(32),
      cm1: new Uint8Array(32),
      cm2: new Uint8Array(32),
      proof192: new Uint8Array(192).fill(0x22),
      memosBytes: new Uint8Array(0),
      recipient: recipWsolAta,
      relayerFeeRecipient: relayerWsolAta,
      publicAmountOut: 100_000_000n,
      // Covers ~1.1x non-ATA cost (2x nfRent + base fee ≈ 2.2M) but NOT the 2,039,280 recipient ATA rent!
      relayerFeeAmount: 2_500_000n,
    })
    const accMap = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
      [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
      [relayerWsolAta, { bytes: makeTokenAccountBytes(WSOL_MINT, relayerB58, 0n), lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }],
      // Pre-funded System-owned 0-byte recipient ATA with full 2,039,280 lamports!
      [recipWsolAta, { bytes: new Uint8Array(0), lamports: 2_039_280, owner: SYSTEM_PROGRAM_ID }],
      [poolPda, { bytes: makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 113_567n }), lamports: 2_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0Pda, { bytes: makeLaneStateBytes({ laneId: 0, nextLeaf: 10n, nfCount: 10n }), lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
      [lane0RentVault, { bytes: new Uint8Array(16), lamports: 200_000_000, owner: AUDREN_PROGRAM_ID }],
      [deriveSubtreePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 58_352_640, owner: AUDREN_PROGRAM_ID }],
      [deriveSubrootPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
      [deriveMemoPdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 72_161_280, owner: AUDREN_PROGRAM_ID }],
      [deriveNfPagePdaSync(0, 0, 0n).address, { bytes: dummyPageBytes, lamports: 68_152_320, owner: AUDREN_PROGRAM_ID }],
    ])
    const res = await withMockFetch(
      async (_url, init) => {
        const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
        if (body.method === 'getMinimumBalanceForRentExemption') {
          const sz = Number(body.params[0])
          return Response.json({ jsonrpc: '2.0', id: 1, result: 6_960 * (sz + 128) })
        }
        if (body.method === 'getLatestBlockhash') {
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0xc9)) } } })
        }
        if (body.method === 'getMultipleAccounts') {
          const addrs = body.params[0] as string[]
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 99_500 },
              value: addrs.map((a) => {
                const hit = accMap.get(a)
                return hit ? { data: [toBase64(hit.bytes), 'base64'], lamports: hit.lamports, owner: hit.owner } : null
              }),
            },
          })
        }
        if (body.method === 'simulateTransaction') {
          const opts = body.params[1] as { accounts?: { addresses?: string[] } }
          const watchAddrs = opts?.accounts?.addresses ?? [relayerB58]
          return Response.json({
            jsonrpc: '2.0',
            id: 1,
            result: {
              context: { slot: 99_500 },
              value: {
                err: null,
                logs: ['OK'],
                unitsConsumed: 220_000,
                accounts: watchAddrs.map((a) =>
                  a === relayerWsolAta
                    ? { lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID, data: [toBase64(makeTokenAccountBytes(WSOL_MINT, relayerB58, 2_500_000n)), 'base64'] }
                    // Simulated debit excludes the 2,039,280 pre-funded recipient ATA rent!
                    : { lamports: 500_000_000 - 2_020_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
                ),
              },
            },
          })
        }
        throw new Error(`Unexpected RPC in pre-funded recipient ATA test (must NOT broadcast): ${body.method}`)
      },
      () =>
        worker.fetch(
          new Request('https://relay.audren.xyz/v1/relay/submit', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              cluster: 'mainnet',
              instructionDataB64: toBase64(ix.data),
              accounts: ix.accounts,
              setupAtas: [{ owner: recipOwner, mint: WSOL_MINT, tokenProgram: CLASSIC_TOKEN_PROGRAM_ID }],
            }),
          }),
          {
            RELAY_GUARD: guard.namespace,
            MAINNET_RPC_URL: 'https://mock-rpc.local/r3-prefunded-recip-ata',
            MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
          } as Env,
        ),
    )
    assert.equal(
      res.status,
      402,
      'Pre-funded uninitialized isWithdrawRecipientAta MUST require full ATA rent coverage (402 FEE_REQUIRED)',
    )
    const body = (await res.json()) as { code?: string }
    assert.equal(body.code, 'FEE_REQUIRED')
  }
})
