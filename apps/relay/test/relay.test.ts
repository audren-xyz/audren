import test from 'node:test'
import assert from 'node:assert/strict'
import { registerHooks } from 'node:module'
import { ed25519 } from '@noble/curves/ed25519.js'
import {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_SOL,
  ASSET_MODE_SPL,
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
  EXEC_KIND_SOL,
  EXEC_KIND_SPL,
  LANE_MAGIC,
  LANE_STATE_LEN,
  LN_OFF_LANE_ID,
  LN_OFF_NEXT_LEAF,
  LN_OFF_NF_COUNT,
  LN_OFF_POOL_ID,
  LN_OFF_VERSION,
  NATIVE_SOL_MINT_BYTES,
  PL_OFF_ACTIVE_LANES,
  PL_OFF_CKPT_INTERVAL,
  PL_OFF_MAX_CKPT_AGE,
  PL_OFF_NOTE_RENT_FEE,
  PL_OFF_POOL_ID,
  PL_OFF_VERSION,
  POOL_MAGIC,
  POOL_STATE_LEN,
  TOKEN_2022_PROGRAM_ID,
  WSOL_MINT,
  base58Encode,
  buildDepositSolInstruction,
  buildExecViaEscrowInstruction,
  buildJoinsplitInstruction,
  computeNoteCommitment,
  deriveAssetId,
  deriveAssociatedTokenAddressSync,
  deriveCheckpointPdaSync,
  deriveEscrowPdaSync,
  deriveKeysFromSeed,
  deriveLanePdaSync,
  derivePoolPdaSync,
  deriveStealthOwner,
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
import { evaluateCheckpointState } from '../src/solana/checkpoint'
import { fromBase64, toBase64, toHex } from '../src/solana/codec'
import { computeSwapInputTransferFee } from '../src/solana/rpc'

// Provide a lightweight stub for Cloudflare's `cloudflare:workers` built-in module when
// exercising the full Worker HTTP router (`src/index.ts`) inside Node's test runner.
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

const relayerSecret = new Uint8Array(32).fill(0x42)
const relayerPubkey = ed25519.getPublicKey(relayerSecret)
const relayerB58 = base58Encode(relayerPubkey)

const relayerShieldedKeys = deriveKeysFromSeed(new Uint8Array(32).fill(0x91))
const relayerFvk = exportFullViewingKey(relayerShieldedKeys)
const allowedPre = new Set(DEFAULT_ALLOWED_PRE_IX_PROGRAMS)

const nf0 = new Uint8Array(32).fill(0x01)
const nf1Zero = new Uint8Array(32)
const dummyProof = new Uint8Array(192).fill(0xaa)

test('Firewall rejects DepositSol (Tag 3) and extra signers', () => {
  const depIx = buildDepositSolInstruction({
    depositor: relayerB58,
    poolId: 0,
    laneId: 0,
    subPageSeq: 0n,
    rootPageSeq: 0n,
    memoPageSeq: 0n,
    amount: 1_000_000n,
    stealthOwner: 1n,
    blinding: 2n,
    memo90: new Uint8Array(90),
  })
  assert.throws(
    () =>
      validateRelaySubmission(
        { instructionDataB64: toBase64(depIx.data), accounts: depIx.accounts },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    FirewallError,
  )
})

test('Firewall Mode 1: verifies shielded cm2 fee note via read-only relayer FVK and rejects forged cm2', () => {
  const feeAmount = 2_000_000n
  const { tweak, blinding, memo90 } = encryptNoteMemo(
    relayerShieldedKeys.viewPk,
    new Uint8Array(32).fill(0x77),
    feeAmount,
    NATIVE_SOL_MINT_BYTES,
  )
  const stealth = deriveStealthOwner(relayerShieldedKeys.spendPk, tweak)
  const solAsset = deriveAssetId(NATIVE_SOL_MINT_BYTES)
  const cm2 = frToBeBytes(computeNoteCommitment(stealth, solAsset, feeAmount, blinding))

  // outputMask = 0b101 (outputs 0 and 2 active => memos = [memo0, memo2])
  const memos = new Uint8Array(180)
  memos.set(new Uint8Array(90).fill(0x11), 0)
  memos.set(memo90, 90)

  const ix = buildJoinsplitInstruction({
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
    nf1: nf1Zero,
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
  assert.equal(verdict.outLaneId, 2)
  assert.ok(verdict.shieldedCm2Fee)
  assert.equal(verdict.shieldedCm2Fee.amount, feeAmount)

  // Forged cm2 commitment MUST NOT earn shielded fee credit
  const badCm2 = new Uint8Array(cm2)
  badCm2[31] ^= 1
  const badIx = buildJoinsplitInstruction({
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
    nf1: nf1Zero,
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
})

test('Firewall Mode 2: Withdraw WSOL Unwrap & Native SOL fee enforcement', () => {
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const vaultWsolAta = deriveAssociatedTokenAddressSync(
    vaultAuth,
    WSOL_MINT,
    CLASSIC_TOKEN_PROGRAM_ID,
  ).address
  const recipient = base58Encode(new Uint8Array(32).fill(0x33))

  const ix = buildJoinsplitInstruction({
    payer: relayerB58,
    poolId: 0,
    ckptSlotIdx: 2,
    outLaneId: 1,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_SPL,
    unwrapWsol: true,
    splWithdrawAccs: {
      mint: WSOL_MINT,
      vaultAta: vaultWsolAta,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    },
    proof192: dummyProof,
    nf0,
    nf1: nf1Zero,
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

  // Spoofed fee recipient must be rejected!
  const spoofed = buildJoinsplitInstruction({
    payer: relayerB58,
    poolId: 0,
    ckptSlotIdx: 2,
    outLaneId: 1,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    outputMask: 0,
    assetMode: ASSET_MODE_SOL,
    proof192: dummyProof,
    nf0,
    nf1: nf1Zero,
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
})

test('Firewall Mode 3: ExecViaEscrow EXEC_FLAG_FEE_ON_OUTPUT watches output relayer ATA', () => {
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const escrow = deriveEscrowPdaSync(0, 3).address
  const usdcMint = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
  const vaultOutAta = deriveAssociatedTokenAddressSync(vaultAuth, usdcMint, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowOutAta = deriveAssociatedTokenAddressSync(escrow, usdcMint, CLASSIC_TOKEN_PROGRAM_ID).address
  const relayerOutAta = deriveAssociatedTokenAddressSync(relayerB58, usdcMint, CLASSIC_TOKEN_PROGRAM_ID).address

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
    changeMask: 0,
    inKind: EXEC_KIND_SOL,
    outKind: EXEC_KIND_SPL,
    feeOnOutput: true,
    outSpl: {
      mint: usdcMint,
      vaultAta: vaultOutAta,
      escrowAta: escrowOutAta,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    },
    relayerFeeAmount: 500_000n,
    relayerFeeRecipient: relayerOutAta,
    proof192: dummyProof,
    nf0,
    nf1: nf1Zero,
    cm0: new Uint8Array(32),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    amountIn: 500_000_000n,
    minAmountOut: 50_000_000n,
    outStealthOwner: new Uint8Array(32).fill(0x02),
    outBlinding: new Uint8Array(32).fill(0x03),
    dynMemoHead: new Uint8Array(34).fill(0x04),
    dynMask56: new Uint8Array(56).fill(0x05),
    routerProg: base58Encode(new Uint8Array(32).fill(0x55)),
    routerIxData: new Uint8Array([1, 2, 3]),
    routerAccounts: [
      { pubkey: base58Encode(new Uint8Array(32).fill(0x66)), isSigner: false, isWritable: true },
    ],
    changeMemos: new Uint8Array(0),
  })

  const v = validateRelaySubmission(
    { instructionDataB64: toBase64(ix.data), accounts: ix.accounts },
    relayerPubkey,
    allowedPre,
    relayerFvk,
  )
  assert.equal(v.opKind, 'exec_escrow')
  assert.equal(v.execMeta?.feeOnOutput, true)
  assert.equal(v.watchedRelayerFeeAta, relayerOutAta)
  assert.equal(v.watchedRelayerFeeMint, usdcMint)
})

test('3-mode dynamic pricing computes self_paying shielded_cm2, withdraw, and exec_escrow quotes', () => {
  const cfg = loadPolicyConfig({} as never)
  const rentSchedule = {
    nullifierRentLamports: 890_880n,
    pageRentPerNoteLamports: 1_500_000n,
    ataRentLamports: 2_039_280n,
    baseTxFeeLamports: 5_000n,
    swapBaselineLamports: 2_395_880n,
    fetchedAt: Date.now(),
  }
  const qTransfer = computeNativeFeeQuote({
    cluster: 'mainnet',
    op: 'transfer',
    cfg,
    rentSchedule,
    isNativeSolFee: true,
    feeSide: 'shielded_cm2',
    feeMint: '11111111111111111111111111111111',
    feeTokenProgram: null,
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
  assert.equal(qTransfer.feeShieldedAddress, relayerShieldedKeys.address)
  assert.ok(BigInt(qTransfer.relayerFee) > 5_000_000n)

  // Unsafe Token-2022 output mints must never be billed as self_paying in swap fee plans
  const unsafePlan = computeSwapFeePlan({
    cfg,
    rentSchedule,
    outputMint: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
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
    outputMint: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
    quoteResponse: {
      escrowPubkey,
      instructionLists: [tokenSyncIx, realSwapIx],
    },
  })
  assert.equal(okxBuilt.swapInstruction.programId, routerProg)

  const titanBuilt = await titanAdapter.swapInstructions({} as never, {
    escrowPubkey,
    inputMint: WSOL_MINT,
    outputMint: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
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
          outputMint: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
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
}): Uint8Array {
  const buf = new Uint8Array(POOL_STATE_LEN)
  const dv = new DataView(buf.buffer)
  writeAscii(buf, 0, POOL_MAGIC)
  buf[PL_OFF_VERSION] = 3
  buf[PL_OFF_ACTIVE_LANES] = params.activeLanes ?? 4
  dv.setUint32(PL_OFF_POOL_ID, params.poolId ?? 0, true)
  dv.setBigUint64(PL_OFF_CKPT_INTERVAL, params.ckptInterval ?? 16n, true)
  dv.setBigUint64(PL_OFF_MAX_CKPT_AGE, params.maxCkptAge ?? 3600n, true)
  dv.setBigUint64(PL_OFF_NOTE_RENT_FEE, params.noteRentFee ?? 1_000_000n, true)
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
  buf[LN_OFF_VERSION] = 3
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
  buf[CK_OFF_VERSION] = 3
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
  const stub = {
    async checkCheckpointRateLimit() {
      return overrides?.rateDecision ?? { allowed: true }
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
// 1. Transfer fee-quote privacy (optional/ignored amount + omitNf1 1 vs 2) & /v1/info
// ============================================================================

test('computeNativeFeeQuote: op=transfer ignores amount and prices 1 vs 2 nullifiers via omitNf1', () => {
  const cfg = loadPolicyConfig({} as never)
  const rentSchedule = {
    nullifierRentLamports: 890_880n,
    pageRentPerNoteLamports: 1_500_000n,
    ataRentLamports: 2_039_280n,
    baseTxFeeLamports: 5_000n,
    swapBaselineLamports: 2_395_880n,
    fetchedAt: Date.now(),
  }

  // Default transfer (no amount, omitNf1 omitted => 2 nullifiers, 3 outputs)
  const q2 = computeNativeFeeQuote({
    cluster: 'mainnet',
    op: 'transfer',
    cfg,
    rentSchedule,
    isNativeSolFee: true,
    feeSide: 'shielded_cm2',
    feeMint: '11111111111111111111111111111111',
    feeTokenProgram: null,
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
  const expectedCost2 = 2n * 890_880n + 3n * 1_500_000n + 20_000n
  assert.equal(q2.estimatedRelayCostLamports, expectedCost2.toString())
  assert.equal(q2.relayerFee, BigInt(Math.ceil(Number(expectedCost2) * 1.1)).toString())

  // Economy mode (omitNf1 = true => 1 nullifier, 3 outputs)
  const q1 = computeNativeFeeQuote({
    cluster: 'mainnet',
    op: 'transfer',
    cfg,
    rentSchedule,
    isNativeSolFee: true,
    feeSide: 'shielded_cm2',
    feeMint: '11111111111111111111111111111111',
    feeTokenProgram: null,
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
    rentSchedule.nullifierRentLamports,
  )
  assert.ok(BigInt(q2.relayerFee) > BigInt(q1.relayerFee))

  // Legacy caller passing huge or tiny amount MUST produce identical flat fee
  const qLegacyHuge = computeNativeFeeQuote({
    cluster: 'mainnet',
    op: 'transfer',
    cfg,
    rentSchedule,
    isNativeSolFee: true,
    feeSide: 'shielded_cm2',
    feeMint: '11111111111111111111111111111111',
    feeTokenProgram: null,
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

  // Withdraw remains backwards-compatible (uses amount & defaults to 1 nullifier)
  const qWithdraw = computeNativeFeeQuote({
    cluster: 'mainnet',
    op: 'withdraw',
    cfg,
    rentSchedule,
    isNativeSolFee: true,
    feeSide: 'in',
    feeMint: '11111111111111111111111111111111',
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
  assert.equal(qWithdraw.nullifierCount, 1)
  assert.equal(qWithdraw.relayerFee, '5000000') // 25 bps of 2 SOL > 1.1x rent
})

test('HTTP GET /v1/fee-quote?op=transfer succeeds without amount and prices omitNf1, plus /v1/info & index', async () => {
  const worker = await getWorker()
  const mockRpc = 'https://mock-rpc.local/fee-quote-http'
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
  } as Env

  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n })

  await withMockFetch(
    async (url, init) => {
      assert.equal(url, mockRpc)
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getMinimumBalanceForRentExemption') {
        const len = Number(body.params[0])
        const rentMap: Record<number, number> = {
          0: 890_880,
          165: 2_039_280,
          8256: 58_340_000,
          9664: 68_140_000,
          10144: 71_480_000,
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
      if (body.method === 'getBalance') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: { value: 500_000_000 } })
      }
      throw new Error(`Unexpected RPC method in fee-quote test: ${body.method}`)
    },
    async () => {
      // 1. op=transfer with NO amount param (default 2 nullifiers)
      const res2 = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=transfer&mint=native'),
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
      assert.equal(q2.feeShieldedAddress, relayerShieldedKeys.address)

      // 2. op=transfer with omitNf1=true (1 nullifier)
      const res1 = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=transfer&mint=native&omitNf1=true'),
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

      // 3. op=transfer ignores any legacy amount param (even arbitrary string)
      const resLegacy = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=transfer&mint=native&amount=999999999'),
        env,
      )
      assert.equal(resLegacy.status, 200)
      const qLegacy = (await resLegacy.json()) as Record<string, unknown>
      assert.equal(qLegacy.relayerFee, q2.relayerFee)

      // 4. GET /v1/info reports checkpointSupport + flat fee transfer metadata
      const infoRes = await worker.fetch(
        new Request('https://relay.audren.xyz/v1/info?cluster=mainnet'),
        env,
      )
      assert.equal(infoRes.status, 200)
      const info = (await infoRes.json()) as {
        checkpointSupport: boolean
        supportedOperations: {
          transfer: { flatFee: boolean; requiresAmount: boolean; defaultNullifiers: number }
          checkpoint: { tag: number; permissionless: boolean; endpoint: string }
        }
      }
      assert.equal(info.checkpointSupport, true)
      assert.equal(info.supportedOperations.transfer.flatFee, true)
      assert.equal(info.supportedOperations.transfer.requiresAmount, false)
      assert.equal(info.supportedOperations.transfer.defaultNullifiers, 2)
      assert.equal(info.supportedOperations.checkpoint.endpoint, '/v1/checkpoint')

      // 5. Root index & 404 document POST /v1/checkpoint
      const rootRes = await worker.fetch(new Request('https://relay.audren.xyz/'), env)
      const rootJson = (await rootRes.json()) as { endpoints: string[] }
      assert.ok(rootJson.endpoints.some((e) => e.includes('POST /v1/checkpoint')))
    },
  )
})

// ============================================================================
// 2. Permissionless on-demand POST /v1/checkpoint (up_to_date / cooldown / published)
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

  // Helper to run POST /v1/checkpoint against a configurable mock RPC snapshot
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
                accounts: [{ lamports: 499_990_000, owner: '11111111111111111111111111111111', data: ['', 'base64'] }],
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

  // Case A: up_to_date (totalLeaves === lastCkptTotalLeaves === 5, zero tx sent)
  const upToDate = await runCheckpointScenario({
    rpcUrl: 'https://mock-rpc.local/ckpt-up-to-date',
    currentSlot: 1608,
    laneLeaves: [3n, 2n, 0n, 0n],
  })
  assert.equal(upToDate.status, 200)
  assert.equal(upToDate.headers.get('access-control-allow-origin'), '*')
  assert.equal(upToDate.body.ok, true)
  assert.equal(upToDate.body.cluster, 'mainnet')
  assert.equal(upToDate.body.status, 'up_to_date')
  assert.equal(upToDate.body.epoch, 100)
  assert.equal(upToDate.sendTxCount, 0)

  // Case B: cooldown (uncheckpointed leaf on lane 2, slot 1605 < nextCkptSlot 1616 => 11 slots = 4400 ms)
  const cooldown = await runCheckpointScenario({
    rpcUrl: 'https://mock-rpc.local/ckpt-cooldown',
    currentSlot: 1605,
    laneLeaves: [3n, 2n, 1n, 0n],
  })
  assert.equal(cooldown.status, 200)
  assert.equal(cooldown.body.ok, true)
  assert.equal(cooldown.body.status, 'cooldown')
  assert.equal(cooldown.body.slotsRemaining, 11)
  assert.equal(cooldown.body.waitMs, 4400)
  assert.equal(cooldown.sendTxCount, 0)

  // Case C: published (uncheckpointed leaf + currentSlot 1616 >= nextCkptSlot 1616 => epoch 101)
  const published = await runCheckpointScenario({
    rpcUrl: 'https://mock-rpc.local/ckpt-published',
    currentSlot: 1616,
    laneLeaves: [3n, 2n, 1n, 0n],
  })
  assert.equal(published.status, 200)
  assert.equal(published.body.ok, true)
  assert.equal(published.body.status, 'published')
  assert.equal(published.body.epoch, 101)
  assert.equal(published.body.signature, '5CkptMockSig11111111111111111111111111111111111')
  assert.equal(published.sendTxCount, 1)
  assert.equal(published.guard.acquireCalls.length, 1)
  assert.equal(published.guard.releasedCalls.length, 1)
  assert.equal(published.guard.releasedCalls[0]?.published, true)
  // Verify Solana v1 (0x81) tx is signed by relayer fee payer (accounts[0] starts at byte 42)
  assert.ok(published.lastSentWireBytes)
  assert.equal(published.lastSentWireBytes[0], 0x81)
  assert.equal(base58Encode(published.lastSentWireBytes.subarray(42, 74)), relayerB58)

  // Case D: concurrent in-flight lock coalesces cleanly into cooldown without double-sending
  const inFlight = await runCheckpointScenario({
    rpcUrl: 'https://mock-rpc.local/ckpt-inflight',
    currentSlot: 1616,
    laneLeaves: [3n, 2n, 1n, 0n],
    guardOverrides: { acquireResult: { allowed: false, inFlight: true, waitMs: 2000 } },
  })
  assert.equal(inFlight.status, 200)
  assert.equal(inFlight.body.status, 'cooldown')
  assert.equal(inFlight.body.inFlight, true)
  assert.equal(inFlight.body.waitMs, 2000)
  assert.equal(inFlight.sendTxCount, 0)

  // Case E: per-IP rate limit blocks abuse cleanly with 429 + retry-after
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
  assert.equal(rateLimited.sendTxCount, 0)

  // Pure evaluator sanity check on expired checkpoint refresh
  const expiredEval = evaluateCheckpointState({
    pool: {
      version: 3,
      bump: 0,
      paused: false,
      activeLanes: 4,
      poolId: 0,
      ckptInterval: 16n,
      maxCkptAge: 3600n,
      authority: relayerB58,
      authorityBytes: relayerPubkey,
      solVaultBump: 0,
      vaultAuthBump: 0,
      mode: 0,
      noteRentFee: 1_000_000n,
      nfRentFee: 120_000n,
      auditorPk: new Uint8Array(32),
    },
    lanes: [
      { version: 3, laneId: 0, bump: 0, rentBump: 0, poolId: 0, nextLeaf: 2n, nfCount: 0n, currentRoot: new Uint8Array(32) },
    ],
    latestCkpt: {
      version: 3,
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
// 3. Token-2022 TransferFeeConfig input deduction on ExecViaEscrow swap quotes
// ============================================================================

test('computeSwapInputTransferFee deducts active epoch Token-2022 transfer fee and leaves Classic SPL/WSOL unchanged', () => {
  const t22MintBytes = makeToken2022TransferFeeMintBytes({
    decimals: 6,
    olderEpoch: 10n,
    olderMaxFee: 500_000n,
    olderBps: 100, // 1.00%
    newerEpoch: 500n,
    newerMaxFee: 10_000_000n,
    newerBps: 250, // 2.50%
  })

  // Before newerEpoch -> uses older_transfer_fee (100 bps, ceiling deduction)
  const before = computeSwapInputTransferFee({
    tokenProgram: TOKEN_2022_PROGRAM_ID,
    mintData: t22MintBytes,
    currentEpoch: 499n,
    grossAmount: 1_000_001n,
  })
  assert.equal(before.grossInputAmount, '1000001')
  assert.equal(before.inputTransferFeeBps, 100)
  // ceil(1_000_001 * 100 / 10_000) = 10_001 => net = 990_000
  assert.equal(before.netInputAmount, '990000')
  assert.equal(before.inputTransferFeeAmount, '10001')

  // At/after newerEpoch -> uses newer_transfer_fee (250 bps), capped by newerMaxFee
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
    grossAmount: 1_000_000_000n, // 2.5% = 25_000_000 > newerMaxFee (10_000_000)
  })
  assert.equal(capped.netInputAmount, '990000000')

  // Classic SPL / WSOL is 100% unchanged
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

test('HTTP GET /v1/swap/quote passes netInputAmount to aggregator for Token-2022 fee mint and keeps WSOL unchanged', async () => {
  const worker = await getWorker()
  const mockRpc = 'https://mock-rpc.local/swap-t22-test'
  const mockJup = 'https://mock-jup.local'
  const t22Mint = base58Encode(new Uint8Array(32).fill(0x22))
  const usdcMint = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'

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
          [usdcMint]: { usdPrice: 1 },
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
            if (addr === usdcMint) {
              return { data: [toBase64(classicUsdcBytes), 'base64'], lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID }
            }
            if (addr === WSOL_MINT) {
              return { data: [toBase64(classicWsolBytes), 'base64'], lamports: 2_000_000, owner: CLASSIC_TOKEN_PROGRAM_ID }
            }
            // Existing relayer fee ATA
            return { data: ['', 'base64'], lamports: 2_039_280, owner: CLASSIC_TOKEN_PROGRAM_ID }
          })
          return Response.json({ jsonrpc: '2.0', id: 1, result: { value } })
        }
      }
      throw new Error(`Unexpected fetch URL in swap quote test: ${url}`)
    },
    async () => {
      // 1. Token-2022 input mint with active 250 bps TransferFeeConfig (gross 1_000_000 -> net 975_000)
      const t22Res = await worker.fetch(
        new Request(
          `https://relay.audren.xyz/v1/swap/quote?cluster=mainnet&provider=jupiter&inputMint=${t22Mint}&outputMint=${usdcMint}&amount=1000000`,
        ),
        env,
      )
      assert.equal(t22Res.status, 200)
      const t22Body = (await t22Res.json()) as {
        ok: boolean
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

      // 2. Classic SPL / WSOL input mint is 100% unchanged and makes ZERO extra getEpochInfo calls
      const wsolRes = await worker.fetch(
        new Request(
          `https://relay.audren.xyz/v1/swap/quote?cluster=mainnet&provider=jupiter&inputMint=${WSOL_MINT}&outputMint=${usdcMint}&amount=1000000000`,
        ),
        env,
      )
      assert.equal(wsolRes.status, 200)
      const wsolBody = (await wsolRes.json()) as {
        ok: boolean
        grossInputAmount: string
        netInputAmount: string
        inputTransferFeeBps: number
        quote: { inAmount: string }
      }
      assert.equal(wsolBody.ok, true)
      assert.equal(wsolBody.grossInputAmount, '1000000000')
      assert.equal(wsolBody.netInputAmount, '1000000000')
      assert.equal(wsolBody.inputTransferFeeBps, 0)
      assert.equal(wsolBody.quote.inAmount, '1000000000')
      assert.equal(jupQuotedAmounts[1], '1000000000')
      assert.equal(epochInfoCalls, 1) // no extra getEpochInfo for WSOL
    },
  )
})
