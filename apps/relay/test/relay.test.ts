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
  SYSTEM_PROGRAM_ID,
  TAG_EXEC_VIA_ESCROW,
  TAG_JOINSPLIT,
  TAG_OPEN_PAGE,
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
import { parseExecEscrowMeta, parseJoinSplitMeta } from '../src/solana/audren'
import { evaluateCheckpointState, fetchPoolCheckpointSnapshot } from '../src/solana/checkpoint'
import { base58Decode, fromBase64, readU16le, readU32le, readU64le, toBase64, toHex } from '../src/solana/codec'
import { computeSwapInputTransferFee, fetchLiveRentSchedule } from '../src/solana/rpc'

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
    nfPageRentPerNfLamports: 113_567n,
    pageRentPerNoteLamports: 1_500_000n,
    ataRentLamports: 2_039_280n,
    baseTxFeeLamports: 5_000n,
    swapBaselineLamports: 2n * (890_880n + 113_567n) + 2n * 1_500_000n + 20_000n,
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
  nfRentFee?: bigint
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
  const relayReleaseCalls: Array<Record<string, unknown>> = []
  const relayAuthorizeCalls: Array<Record<string, unknown>> = []
  const relayCommitCalls: Array<Record<string, unknown>> = []
  const stub = {
    async begin() {
      return { allowed: true }
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
// 1. Transfer fee-quote privacy (optional/ignored amount + omitNf1 1 vs 2) & /v1/info
// ============================================================================

test('computeNativeFeeQuote: op=transfer ignores amount and prices 1 vs 2 nullifiers via omitNf1', () => {
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
  const expectedCost2 = 2n * (890_880n + 113_567n) + 3n * 1_500_000n + 20_000n
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
    rentSchedule.nullifierRentLamports + rentSchedule.nfPageRentPerNfLamports,
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

// ============================================================================
// 4. Regression Tests for Critical / High / Medium / Low Relay Fixes
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

test('Finding #6.1: parseJoinSplitMeta & parseExecEscrowMeta reject unknown flags and missing rollover accounts', () => {
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const vaultWsolAta = deriveAssociatedTokenAddressSync(
    vaultAuth,
    WSOL_MINT,
    CLASSIC_TOKEN_PROGRAM_ID,
  ).address
  const recipient = base58Encode(new Uint8Array(32).fill(0x33))
  const nf1 = new Uint8Array(32).fill(0x02)

  // Valid JoinSplit (WSOL unwrap + all 3 rollovers: nextSub, nextMemo, nextNf)
  const validUnwrapRoll = buildJoinsplitInstruction({
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
    rollover: { nextSubSeq: 1n, nextMemoSeq: 1n, nextNfSeq: 1n },
    proof192: dummyProof,
    nf0,
    nf1,
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
  const parsed = parseJoinSplitMeta(validUnwrapRoll.data, decodedAccs)
  assert.ok(parsed)
  assert.equal(parsed.poolId, 0)
  assert.equal(parsed.outLaneId, 1)
  assert.equal(parsed.unwrapWsol, true)
  assert.equal(parsed.outSub, deriveSubtreePdaSync(0, 1, 0n).address)
  assert.equal(parsed.outRoot, deriveSubrootPdaSync(0, 1, 0n).address)
  assert.equal(parsed.outMemo, deriveMemoPdaSync(0, 1, 0n).address)
  assert.equal(parsed.nfPage, deriveNfPagePdaSync(0, 1, 0n).address)
  assert.equal(parsed.nextSub, deriveSubtreePdaSync(0, 1, 1n).address)
  assert.equal(parsed.nextMemo, deriveMemoPdaSync(0, 1, 1n).address)
  assert.equal(parsed.nextNf, deriveNfPagePdaSync(0, 1, 1n).address)

  // Unknown flag bits (e.g., bit 4 = 0x10, bit 7 = 0x80) MUST be rejected
  for (const badBit of [0x10, 0x20, 0x40, 0x80]) {
    const badData = new Uint8Array(validUnwrapRoll.data)
    badData[9] = (badData[9]! | badBit) & 0xff
    assert.equal(parseJoinSplitMeta(badData, decodedAccs), null)
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

  // Truncated rollover accounts (flags = 0x07 | 0x08 expects 19 + 3 = 22 accounts; 21 must fail)
  assert.equal(parseJoinSplitMeta(validUnwrapRoll.data, decodedAccs.slice(0, -1)), null)
  assert.throws(
    () =>
      validateRelaySubmission(
        {
          instructionDataB64: toBase64(validUnwrapRoll.data),
          accounts: validUnwrapRoll.accounts.slice(0, -1),
        },
        relayerPubkey,
        allowedPre,
        relayerFvk,
      ),
    FirewallError,
  )

  // Single rollover bit set in private transfer with missing trailing account MUST fail
  const privRoll = buildJoinsplitInstruction({
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
    memosBytes: new Uint8Array(90).fill(0x22),
  })
  const privAccs = privRoll.accounts.map((a) => ({
    pubkey: base58Decode(a.pubkey),
    isSigner: a.isSigner,
    isWritable: a.isWritable,
  }))
  assert.equal(parseJoinSplitMeta(privRoll.data, privAccs)?.nextMemo, deriveMemoPdaSync(0, 0, 1n).address)
  assert.equal(parseJoinSplitMeta(privRoll.data, privAccs.slice(0, -1)), null)

  // ExecViaEscrow: unknown flag bits and rollover without router accounts MUST fail
  const escrow = deriveEscrowPdaSync(0, 2).address
  const usdcMint = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
  const vaultOutAta = deriveAssociatedTokenAddressSync(vaultAuth, usdcMint, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowOutAta = deriveAssociatedTokenAddressSync(escrow, usdcMint, CLASSIC_TOKEN_PROGRAM_ID).address
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
    inKind: EXEC_KIND_SOL,
    outKind: EXEC_KIND_SPL,
    outSpl: {
      mint: usdcMint,
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
    dynMask56: new Uint8Array(56).fill(0x05),
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
  badExecData[11] = (badExecData[11]! | 0x40) & 0xff
  assert.equal(parseExecEscrowMeta(badExecData, execAccs), null)
  // Removing the sole router account leaves 0 router accounts -> must fail
  assert.equal(parseExecEscrowMeta(execRoll.data, execAccs.slice(0, -1)), null)
})

test('Finding #2: handleRelaySubmit auto-prepends OpenPage (Tag 2) for missing rollover & primary pages in 1 batch and rejects spoofed PDAs', async () => {
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
  const nf1 = new Uint8Array(32).fill(0x02)

  // Lane is at nextLeaf = 111 (memo page 0 has 1 slot left) and nfCount = 599 (nf page 0 has 1 slot left).
  // A 2-output, 2-nullifier transfer rolls over BOTH memo (0 -> 1) and nfPage (0 -> 1)!
  const laneBytes = makeLaneStateBytes({ laneId: outLaneId, nextLeaf: 111n, nfCount: 599n })
  const dummyPageBytes = new Uint8Array(64).fill(0x5a)

  const transferIx = buildJoinsplitInstruction({
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
    nf1,
    cm0: new Uint8Array(32).fill(0x10),
    cm1: new Uint8Array(32).fill(0x20),
    cm2: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(180).fill(0x33),
  })

  // Case A: nextMemo (memo1) is missing (null) and nextNf (nfPage1) is 1-lamport pre-funded System-owned (still unopened!)
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
    [memo0, { bytes: dummyPageBytes, lamports: 71_480_000, owner: AUDREN_PROGRAM_ID }],
    [nfPage0, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    // 1-lamport pre-funded System-owned PDA must still be detected as unopened!
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
        assert.ok(addrs.includes(lanePda), 'single batch must include LaneTreeState')
        assert.ok(addrs.includes(memo1), 'single batch must include nextMemo rollover PDA')
        assert.ok(addrs.includes(nfPage1), 'single batch must include nextNf rollover PDA')
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
              logs: ['OpenPage OK', 'OpenPage OK', 'JoinSplit OK'],
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
      assert.equal(jsonBody.computeUnitLimit, 340_000) // 300k + 2 * 20k CU headroom
      assert.equal(getMultiCalls, 1, 'must use ZERO extra RPC round-trips')
      assert.ok(sentWire)

      const decoded = decodeV1Tx(sentWire)
      assert.equal(decoded.computeUnitLimit, 340_000)
      assert.equal(decoded.instructions.length, 3)

      // ix[0]: OpenPage (Tag 2) for MemoPage seq 1
      const ix0 = decoded.instructions[0]!
      assert.equal(ix0.programId, AUDREN_PROGRAM_ID)
      assert.equal(ix0.data.length, 15)
      assert.equal(ix0.data[0], TAG_OPEN_PAGE)
      assert.equal(ix0.data[1], OPEN_PAGE_KIND_MEMO)
      assert.equal(readU32le(ix0.data, 2), 0)
      assert.equal(ix0.data[6], outLaneId)
      assert.equal(readU64le(ix0.data, 7), 1n)
      assert.deepEqual(ix0.accounts, [
        relayerB58,
        poolPda,
        lanePda,
        laneRentVault,
        memo1,
        SYSTEM_PROGRAM_ID,
      ])

      // ix[1]: OpenPage (Tag 2) for NullifierPage seq 1
      const ix1 = decoded.instructions[1]!
      assert.equal(ix1.programId, AUDREN_PROGRAM_ID)
      assert.equal(ix1.data[0], TAG_OPEN_PAGE)
      assert.equal(ix1.data[1], OPEN_PAGE_KIND_NULLIFIER)
      assert.equal(readU32le(ix1.data, 2), 0)
      assert.equal(ix1.data[6], outLaneId)
      assert.equal(readU64le(ix1.data, 7), 1n)
      assert.deepEqual(ix1.accounts, [
        relayerB58,
        poolPda,
        lanePda,
        laneRentVault,
        nfPage1,
        SYSTEM_PROGRAM_ID,
      ])

      // ix[2]: Original JoinSplit (Tag 6)
      assert.equal(decoded.instructions[2]!.programId, AUDREN_PROGRAM_ID)
      assert.equal(decoded.instructions[2]!.data[0], TAG_JOINSPLIT)
    },
  )

  // Case B: Spoofed rollover PDA (e.g. arbitrary pubkey or wrong seq/lane) MUST be rejected with 400
  // before simulation or send, and must release the guard nullifier lock with recordFailure=true!
  const spoofedAccounts = transferIx.accounts.map((a) => ({ ...a }))
  // Replace nextMemo (second-to-last account) with a spoofed pubkey (memo seq 9 instead of seq 1)
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
  let sendCalled = 0
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
      if (body.method === 'sendTransaction') sendCalled++
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
      const errBody = (await res.json()) as { code: string; error: string }
      assert.equal(errBody.code, 'INVALID_PAGE_PDA')
      assert.equal(simCalled, 0)
      assert.equal(sendCalled, 0)
      assert.equal(guardB.relayReleaseCalls.length, 1)
      assert.equal(guardB.relayReleaseCalls[0]?.recordFailure, true)
    },
  )

  // Case C: Concurrent rollover race (lane advanced to nextLeaf = 112 => curMemo = 1 while client built
  // with outMemo = memo(0) existing & nextMemo = memo(1) missing) opens memo(1) cleanly; also ExecViaEscrow Tag 7
  // with missing nextSub opens SubtreePage seq 1 before Tag 7!
  const vaultAuth = deriveVaultAuthPdaSync(0).address
  const escrow = deriveEscrowPdaSync(0, 0).address
  const usdcMint = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
  const vaultOutAta = deriveAssociatedTokenAddressSync(vaultAuth, usdcMint, CLASSIC_TOKEN_PROGRAM_ID).address
  const escrowOutAta = deriveAssociatedTokenAddressSync(escrow, usdcMint, CLASSIC_TOKEN_PROGRAM_ID).address
  const sub1 = deriveSubtreePdaSync(0, outLaneId, 1n).address
  const laneAt256 = makeLaneStateBytes({ laneId: outLaneId, nextLeaf: 256n, nfCount: 10n })
  const execRaceIx = buildExecViaEscrowInstruction({
    payer: relayerB58,
    poolId: 0,
    ckptSlotIdx: 1,
    outLaneId,
    outSubSeq: 0n, // client saw nextLeaf=255 before concurrent tx advanced to 256
    outRootSeq: 0n,
    outMemoSeq: 2n,
    outNfSeq: 0n,
    escrowShard: 0,
    changeMask: 0,
    inKind: EXEC_KIND_SOL,
    outKind: EXEC_KIND_SPL,
    outSpl: {
      mint: usdcMint,
      vaultAta: vaultOutAta,
      escrowAta: escrowOutAta,
      tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
    },
    relayerFeeAmount: 0n,
    rollover: { nextSubSeq: 1n },
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
    dynMask56: new Uint8Array(56).fill(0x05),
    routerProg: base58Encode(new Uint8Array(32).fill(0x55)),
    routerIxData: new Uint8Array([1, 2, 3]),
    routerAccounts: [
      { pubkey: base58Encode(new Uint8Array(32).fill(0x66)), isSigner: false, isWritable: true },
    ],
    changeMemos: new Uint8Array(0),
  })
  const memo2 = deriveMemoPdaSync(0, outLaneId, 2n).address
  const guardC = createMockGuard()
  const envC = {
    RELAY_GUARD: guardC.namespace,
    MAINNET_RPC_URL: mockRpc,
    MAINNET_RELAYER_SECRET_B64: toBase64(relayerSecret),
  } as Env
  let sentWireC: Uint8Array | null = null
  const accMapC = new Map<string, { bytes: Uint8Array; lamports: number; owner: string }>([
    [relayerB58, { bytes: new Uint8Array(0), lamports: 500_000_000, owner: SYSTEM_PROGRAM_ID }],
    [lanePda, { bytes: laneAt256, lamports: 15_000_000, owner: AUDREN_PROGRAM_ID }],
    [sub0, { bytes: dummyPageBytes, lamports: 58_340_000, owner: AUDREN_PROGRAM_ID }],
    [sr0, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    [memo2, { bytes: dummyPageBytes, lamports: 71_480_000, owner: AUDREN_PROGRAM_ID }],
    [nfPage0, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    // sub1 is missing (null) on-chain!
  ])
  await withMockFetch(
    async (_url, init) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { method: string; params: unknown[] }
      if (body.method === 'getLatestBlockhash') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: { blockhash: base58Encode(new Uint8Array(32).fill(0x45)) } },
        })
      }
      if (body.method === 'getMultipleAccounts') {
        const addrs = body.params[0] as string[]
        const value = addrs.map((a) => {
          const hit = accMapC.get(a)
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
              logs: ['OpenPage OK', 'ExecViaEscrow OK'],
              unitsConsumed: 220_000,
              accounts: [
                { lamports: 498_500_000, owner: SYSTEM_PROGRAM_ID, data: ['', 'base64'] },
              ],
            },
          },
        })
      }
      if (body.method === 'sendTransaction') {
        sentWireC = fromBase64(String(body.params[0]))
        return Response.json({ jsonrpc: '2.0', id: 1, result: '5ExecOpenPageSig11111111111111111111111111111' })
      }
      if (body.method === 'getSignatureStatuses') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: { value: [{ slot: 10001, err: null, confirmationStatus: 'confirmed' }] },
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
            instructionDataB64: toBase64(execRaceIx.data),
            accounts: execRaceIx.accounts,
            computeUnitLimit: 400_000,
          }),
        }),
        envC,
      )
      assert.equal(res.status, 200)
      assert.ok(sentWireC)
      const decoded = decodeV1Tx(sentWireC)
      assert.equal(decoded.instructions.length, 2)
      assert.equal(decoded.instructions[0]!.data[0], TAG_OPEN_PAGE)
      assert.equal(decoded.instructions[0]!.data[1], OPEN_PAGE_KIND_SUBTREE)
      assert.equal(readU64le(decoded.instructions[0]!.data, 7), 1n)
      assert.equal(decoded.instructions[0]!.accounts[4], sub1)
      assert.equal(decoded.instructions[1]!.data[0], TAG_EXEC_VIA_ESCROW)
    },
  )

  // Case D: Missing primary pages (`outSub` seq 300 & `outRoot` seq 1 at `nextLeaf = 76_800 = 256 * 300`)
  // auto-prepend OpenPage(SUBTREE, 300) and OpenPage(SUBROOT, 1)!
  const laneAt76800 = makeLaneStateBytes({ laneId: outLaneId, nextLeaf: 76_800n, nfCount: 10n })
  const sub300 = deriveSubtreePdaSync(0, outLaneId, 300n).address
  const sr1 = deriveSubrootPdaSync(0, outLaneId, 1n).address
  const memo685 = deriveMemoPdaSync(0, outLaneId, 685n).address // floor(76800 / 112) = 685
  const primaryMissingIx = buildJoinsplitInstruction({
    payer: relayerB58,
    poolId: 0,
    ckptSlotIdx: 1,
    outLaneId,
    outSubSeq: 300n,
    outRootSeq: 1n,
    outMemoSeq: 685n,
    outNfSeq: 0n,
    outputMask: 0b001,
    assetMode: ASSET_MODE_PRIVATE,
    proof192: dummyProof,
    nf0,
    nf1: nf1Zero,
    cm0: new Uint8Array(32).fill(0x19),
    cm1: new Uint8Array(32),
    cm2: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: new Uint8Array(90).fill(0x39),
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
    [memo685, { bytes: dummyPageBytes, lamports: 71_480_000, owner: AUDREN_PROGRAM_ID }],
    [nfPage0, { bytes: dummyPageBytes, lamports: 68_140_000, owner: AUDREN_PROGRAM_ID }],
    // Both primary outSub (300) and primary outRoot (1) are missing (null) on-chain!
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
              logs: ['OpenPage OK', 'OpenPage OK', 'JoinSplit OK'],
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
      assert.equal(readU64le(decoded.instructions[0]!.data, 7), 300n)
      assert.equal(decoded.instructions[0]!.accounts[4], sub300)
      assert.equal(decoded.instructions[1]!.data[0], TAG_OPEN_PAGE)
      assert.equal(decoded.instructions[1]!.data[1], OPEN_PAGE_KIND_SUBROOT)
      assert.equal(readU64le(decoded.instructions[1]!.data, 7), 1n)
      assert.equal(decoded.instructions[1]!.accounts[4], sr1)
      assert.equal(decoded.instructions[2]!.data[0], TAG_JOINSPLIT)
    },
  )
})

test('Finding #3: nfPageRentPerNfLamports keeps 2-nullifier full withdrawal strictly self_paying and fixes 2-nullifier swapBaselineLamports', async () => {
  const worker = await getWorker()
  const mockRpc = 'https://mock-rpc.local/nf-rent-fee-test'
  const mockRpcCapped = 'https://mock-rpc.local/nf-rent-fee-capped-test'
  const poolPda = derivePoolPdaSync(0).address
  const poolBytes = makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 120_000n })
  const poolBytesCapped = makePoolStateBytes({ noteRentFee: 1_000_000n, nfRentFee: 80_000n })

  const rentMap: Record<number, number> = {
    0: 890_880,
    165: 2_039_280,
    8256: 58_340_000,
    9664: 68_140_000, // livePerNf = ceil(68_140_000 / 600) = 113_567
    10144: 71_480_000,
  }
  const expectedLivePerNf = 113_567n
  const expectedLivePerNote = 227_891n + 888n + 638_215n // 866_994n (< pool noteRentFee 1_000_000n)
  const expectedSwapBaseline =
    2n * (890_880n + expectedLivePerNf) + 2n * expectedLivePerNote + 20_000n

  // 1. Verify fetchLiveRentSchedule caps nfPageRentPerNfLamports at min(pool.nfRentFee, livePerNf)
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
      assert.equal(
        schedCapped.swapBaselineLamports,
        2n * (890_880n + 80_000n) + 2n * expectedLivePerNote + 20_000n,
      )

      // computeSwapFeePlan uses exact 2-nullifier + 2-output swapBaselineLamports (no stale +15k)
      const cfg = loadPolicyConfig({} as never)
      const planDefault = computeSwapFeePlan({
        cfg,
        rentSchedule: sched,
        outputMint: WSOL_MINT,
        outputDecimals: 9,
        estimatedOutAmount: 1_000_000_000n,
        solPriceUsd: 150,
        outputTokenPriceUsd: 150,
        feeAccount: relayerB58,
        feeAccountExists: true,
      })
      assert.equal(planDefault.billingMode, 'self_paying')
      assert.equal(planDefault.estimatedRelayCostLamports, expectedSwapBaseline.toString())

      // Optional omitNf1=true, outputCount=1 override prices 1 nullifier + 1 output
      const planEconomy = computeSwapFeePlan({
        cfg,
        rentSchedule: sched,
        outputMint: WSOL_MINT,
        outputDecimals: 9,
        estimatedOutAmount: 1_000_000_000n,
        solPriceUsd: 150,
        outputTokenPriceUsd: 150,
        feeAccount: relayerB58,
        feeAccountExists: true,
        omitNf1: true,
        outputCount: 1,
      })
      assert.equal(
        planEconomy.estimatedRelayCostLamports,
        (890_880n + expectedLivePerNf + expectedLivePerNote + 20_000n).toString(),
      )
    },
  )

  // 2. End-to-end HTTP /v1/info + /v1/fee-quote (2-nullifier full withdrawal at 10% margin) -> /v1/relay/submit
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
  // Actual on-chain debit for 2-nullifier full withdrawal (0 outputs):
  // 2 * NullifierPDA (890,880) + 2 * nf_rent_fee (113,567) + base sig (5,000) + priority (5,000) = 2,018,894 lamports
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
        // Exact post-execution relayer balance = pre - actualOnChainDebit + quotedRelayerFee
        const postLamports = preRelayerLamports - actualOnChainDebit + quotedRelayerFee
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: {
            value: {
              err: null,
              logs: ['JoinSplit Withdraw OK'],
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
      throw new Error(`Unexpected RPC method in Finding #3 HTTP test: ${body.method}`)
    },
    async () => {
      // /v1/info exposes nfPageRentPerNfLamports and updated 2-nullifier swapBaselineLamports
      const infoRes = await worker.fetch(new Request('https://relay.audren.xyz/v1/info?cluster=mainnet'), env)
      assert.equal(infoRes.status, 200)
      const info = (await infoRes.json()) as {
        rentSchedule: { nfPageRentPerNfLamports: string; swapBaselineLamports: string }
      }
      assert.equal(info.rentSchedule.nfPageRentPerNfLamports, expectedLivePerNf.toString())
      assert.equal(info.rentSchedule.swapBaselineLamports, expectedSwapBaseline.toString())

      // Quote a 2-nullifier full SOL withdrawal (`outputCount=0&omitNf1=false`) at 10% selfPayMarginBps
      const quoteRes = await worker.fetch(
        new Request(
          'https://relay.audren.xyz/v1/fee-quote?cluster=mainnet&op=withdraw&mint=native&amount=500000000&outputCount=0&omitNf1=false',
        ),
        env,
      )
      assert.equal(quoteRes.status, 200)
      const q = (await quoteRes.json()) as {
        billingMode: string
        nullifierCount: number
        estimatedRelayCostLamports: string
        relayerFee: string
      }
      assert.equal(q.billingMode, 'self_paying')
      assert.equal(q.nullifierCount, 2)
      const expectedTxBase = 2n * (890_880n + expectedLivePerNf) + 20_000n // 2_028_894n
      assert.equal(q.estimatedRelayCostLamports, expectedTxBase.toString())
      quotedRelayerFee = BigInt(q.relayerFee)
      assert.ok(quotedRelayerFee > actualOnChainDebit, '1.1x quoted fee must exceed actual 2-nf on-chain debit')

      // Submit the exact quoted 2-nullifier full withdrawal and verify billingMode === 'self_paying'
      const recipient = base58Encode(new Uint8Array(32).fill(0x77))
      const withdrawIx = buildJoinsplitInstruction({
        payer: relayerB58,
        poolId: 0,
        ckptSlotIdx: 0,
        outLaneId: 0,
        outSubSeq: 0n,
        outRootSeq: 0n,
        outMemoSeq: 0n,
        outNfSeq: 0n,
        outputMask: 0,
        assetMode: ASSET_MODE_SOL,
        proof192: dummyProof,
        nf0,
        nf1: new Uint8Array(32).fill(0x02),
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
      }
      assert.equal(submitBody.ok, true)
      assert.equal(submitBody.billingMode, 'self_paying')
      assert.equal(submitBody.netSponsoredLamports, '0')
      assert.equal(guard.relayAuthorizeCalls[0]?.selfPaying, true)
    },
  )
})

test('Finding #5: fetchPoolCheckpointSnapshot scans remaining ring slots when firstBatch only contains an ancient wrapped checkpoint', async () => {
  const mockRpcWrap = 'https://mock-rpc.local/ckpt-ring-wrap'
  const mockRpcRecent = 'https://mock-rpc.local/ckpt-ring-recent'
  const poolPda = derivePoolPdaSync(0).address
  const lanePdas = [0, 1, 2, 3].map((l) => deriveLanePdaSync(0, l).address)
  const poolBytes = makePoolStateBytes({ activeLanes: 4, ckptInterval: 16n, maxCkptAge: 3600n })

  // currentSlot = 16_000 => curEpoch = 1000, firstBatchCount = 100 - 4 = 96 => minRecentEpoch = 905
  // Ancient wrapped checkpoint sits in slotIdx = 1000 % 256 = 232 (epochId = 744 < 905)
  // Real newer checkpoint sits in slotIdx = 850 % 256 = 82 (epochId = 850, 150 epochs ago => in second batch!)
  const ancientSlotIdx = 1000 % 256 // 232
  const newerSlotIdx = 850 % 256 // 82
  const recentBoundarySlotIdx = 905 % 256 // 137 (exact minRecentEpoch boundary)

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

  // Case A: firstBatch contains ONLY ancient wrapped epoch 744 -> MUST scan rest of ring and find epoch 850!
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
      assert.ok(multiCallsWrap > 1, `expected second-batch ring scan, got ${multiCallsWrap} getMultipleAccounts call(s)`)
      assert.equal(snap.latestCkpt?.epochId, 850n)
      assert.equal(snap.latestCkpt?.slotIdx, newerSlotIdx)
      assert.equal(snap.targetSlotCkpt?.epochId, 744n)
    },
  )

  // Case B: firstBatch contains a genuine recent checkpoint (epoch 905 === minRecentEpoch) -> MUST skip rest of ring!
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
      assert.equal(multiCallsRecent, 1, 'recent checkpoint in firstBatch should preserve single-batch fast path')
      assert.equal(snap.latestCkpt?.epochId, 905n)
    },
  )
})
