import test from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_SOL,
  ASSET_MODE_SPL,
  CLASSIC_TOKEN_PROGRAM_ID,
  EXEC_KIND_SOL,
  EXEC_KIND_SPL,
  NATIVE_SOL_MINT_BYTES,
  WSOL_MINT,
  base58Encode,
  buildDepositSolInstruction,
  buildExecViaEscrowInstruction,
  buildJoinsplitInstruction,
  computeNoteCommitment,
  deriveAssetId,
  deriveAssociatedTokenAddressSync,
  deriveEscrowPdaSync,
  deriveKeysFromSeed,
  deriveStealthOwner,
  deriveVaultAuthPdaSync,
  encryptNoteMemo,
  exportFullViewingKey,
  frToBeBytes,
} from '@audren/sdk'
import { DEFAULT_ALLOWED_PRE_IX_PROGRAMS, loadPolicyConfig } from '../src/env'
import { FirewallError, validateRelaySubmission } from '../src/policy/firewall'
import { computeNativeFeeQuote } from '../src/policy/pricing'
import { toBase64 } from '../src/solana/codec'

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
})
