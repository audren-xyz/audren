/**
 * End-to-end cryptographic & WASM prover audit check for `apps/web`.
 *
 * Verifies local key derivation, BIP-350 Bech32m `aud1...` address checksums,
 * versioned 72 B AEAD (106 B SoA) memo encryption/decryption, 4-ary Depth-20 Merkle path,
 * real WASM BN254 Groth16 proving for `Transact` (`Tag 5`), and Mode 1 selective disclosure.
 */

import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import {
  ASSET_MODE_PRIVATE,
  AUDREN_PROGRAM_ID,
  MEMO_ENTRY_WIRE_LEN,
  NUM_LANES,
  VK_ID_DEFAULT,
  WSOL_MINT,
  ZERO_HASHES_4ARY,
  audrenInstructionToSolana,
  base58Decode,
  buildTransactInstruction,
  buildWitnessFromFrozenSubsiblings,
  computeMerkleRoot4Ary,
  computeNoteCommitment,
  computeSubtree256Root,
  computeTransactCtxHash,
  deriveAssetId,
  deriveKeysFromSeed,
  deriveStealthOwner,
  encryptNoteMemo,
  exportFullViewingKey,
  extractIntraSubtreeSiblings,
  formatAudrenAddress,
  frToBeBytes,
  parseAudrenAddress,
  tryDecryptAndVerifyMemo,
  verifySelectiveDisclosureProof,
} from '../lib/audren-crypto'
import { AudrenWasmProver, dummyInputWitness, dummyOutputWitness } from '../lib/audren-prover'
import { AUDREN, getPool0LookupTable } from '../lib/protocol'
import { compileKitV0Transaction } from '../lib/solana-wallet'

async function main() {
  const seed = new Uint8Array(32).fill(7)
  const keys = deriveKeysFromSeed(seed)
  const fvk = exportFullViewingKey(keys)

  // Verify canonical 114-char lowercase BIP-350 Bech32m `aud1...` codec & typo rejection
  if (!keys.address.startsWith('aud1') || keys.address.length !== 114) {
    throw new Error(`Expected 114-char Bech32m aud1 address, got ${keys.address.length}`)
  }
  const parsedAddr = parseAudrenAddress(keys.address)
  const reencoded = formatAudrenAddress(parsedAddr.spendPk, parsedAddr.viewPk)
  if (reencoded !== keys.address) {
    throw new Error('Bech32m aud1 round-trip mismatch')
  }
  const typoAddr =
    keys.address.slice(0, -1) + (keys.address.endsWith('q') ? 'p' : 'q')
  let typoRejected = false
  try {
    parseAudrenAddress(typoAddr)
  } catch {
    typoRejected = true
  }
  if (!typoRejected) {
    throw new Error('Bech32m checksum failed to reject 1-character typo')
  }

  const mint = base58Decode(WSOL_MINT)
  const assetId = deriveAssetId(mint)
  const amount = 5_000_000n

  const { tweak, blinding, memo } = encryptNoteMemo(
    keys.viewPk,
    new Uint8Array(32).fill(9),
    amount,
    mint,
  )
  if (memo.byteLength !== MEMO_ENTRY_WIRE_LEN) {
    throw new Error(`Expected ${MEMO_ENTRY_WIRE_LEN}-byte memo, got ${memo.byteLength}`)
  }
  const stealthOwner = deriveStealthOwner(keys.spendPk, tweak)
  const commitment = computeNoteCommitment(stealthOwner, assetId, amount, blinding)

  const dec = tryDecryptAndVerifyMemo(fvk, memo, frToBeBytes(commitment))
  if (!dec || dec.amount !== amount) {
    throw new Error('106 B versioned memo decryption/verification mismatch')
  }

  const leaves = [commitment]
  const { siblings, positions } = extractIntraSubtreeSiblings(leaves, 1, 0)
  const lane0Root = computeSubtree256Root(leaves, 1)
  const ckptLaneRoots = Array.from({ length: NUM_LANES }, (_, i) =>
    i === 0 ? lane0Root : ZERO_HASHES_4ARY[18]!,
  )
  const path = buildWitnessFromFrozenSubsiblings({
    laneId: 0,
    targetLeafIdx: 0n,
    intraSiblings: siblings,
    intraPositions: positions,
    ckptLaneRoots,
    ckptLaneLeafCount: 1n,
    finalizedSubtreeRoots: [],
    frontierPageLeaves: leaves,
  })
  const superRoot = computeMerkleRoot4Ary(path, commitment)

  const wasmBytes = await readFile(resolve(process.cwd(), 'public/wasm/audren_circuits.wasm'))
  const pkCompressed = await readFile(resolve(process.cwd(), 'public/wasm/audren_joinsplit.pk'))
  const prover = await AudrenWasmProver.init({ wasmBytes, pkCompressed })
  const ctxHash = computeTransactCtxHash({
    poolId: 0,
    vkId: VK_ID_DEFAULT,
    outLaneId: 1,
    outputMask: 0b001,
    assetMode: ASSET_MODE_PRIVATE,
    unwrapWsol: false,
    recipient: null,
    relayerFeeRecipient: null,
    publicAssetId: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: memo,
  })
  const t0 = performance.now()
  const proved = prover.proveJoinsplit({
    superRoot,
    txAssetId: assetId,
    publicAssetId: 0n,
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    ctxHash,
    omitNf1: false,
    inputs: [
      {
        isDummy: false,
        spendSk: keys.spendSk,
        tweak,
        assetId,
        amount,
        blinding,
        merklePath: path,
      },
      dummyInputWitness(keys.spendSk, assetId, 11n),
    ],
    outputs: [
      { stealthOwner, assetId, amount, blinding },
      dummyOutputWitness(assetId, 12n),
      dummyOutputWitness(assetId, 13n),
    ],
  })
  const ms = Math.round(performance.now() - t0)
  if (proved.proof192.byteLength !== 192) {
    throw new Error(`Expected 192-byte Groth16 proof, got ${proved.proof192.byteLength}`)
  }

  const sdpOk = verifySelectiveDisclosureProof(
    {
      poolId: 0,
      laneId: 0,
      leafIndex: 0n,
      stealthOwner: frToBeBytes(stealthOwner),
      mint,
      amount,
      blinding: frToBeBytes(blinding),
      commitment: frToBeBytes(commitment),
    },
    frToBeBytes(commitment),
  )
  if (!sdpOk) throw new Error('SelectiveDisclosureProof failed')

  // Reject forged u64::MAX + 1 amount in Mode 1 SelectiveDisclosureProof
  const forgedAmountOk = verifySelectiveDisclosureProof(
    {
      poolId: 0,
      laneId: 0,
      leafIndex: 0n,
      stealthOwner: frToBeBytes(stealthOwner),
      mint,
      amount: 0x1_0000_0000_0000_0000n,
      blinding: frToBeBytes(blinding),
      commitment: frToBeBytes(commitment),
    },
    frToBeBytes(commitment),
  )
  if (forgedAmountOk) throw new Error('SelectiveDisclosureProof failed to reject amount > u64::MAX')

  // Verify v1.2.1 register, frozen Pool #0 ALTs (40 entries each), prover-worker.js, & v0 ALT compression <= 1,232 B
  if (AUDREN.version !== '1.2.1' || AUDREN.releaseTag !== 'v1.2.1') {
    throw new Error(`Expected AUDREN version 1.2.1 / v1.2.1, got ${AUDREN.version} / ${AUDREN.releaseTag}`)
  }
  for (const cluster of ['mainnet', 'devnet'] as const) {
    const alt = AUDREN[cluster].pool0Alt
    if (alt.entries.length !== 40 || alt.entries[0] !== AUDREN_PROGRAM_ID) {
      throw new Error(`Invalid ${cluster} Pool #0 ALT register`)
    }
    for (const addr of alt.entries) {
      if (base58Decode(addr).byteLength !== 32) {
        throw new Error(`Invalid pubkey in ${cluster} Pool #0 ALT: ${addr}`)
      }
    }
  }
  const workerSrc = await readFile(resolve(process.cwd(), 'public/wasm/prover-worker.js'), 'utf8')
  if (!workerSrc.includes('?v=1.2.1') || !workerSrc.includes('WebAssembly.RuntimeError')) {
    throw new Error('prover-worker.js missing v1.2.1 cache-buster or RuntimeError reset')
  }
  const sampleMemos = new Uint8Array(MEMO_ENTRY_WIRE_LEN * 3)
  sampleMemos.set(memo, 0)
  sampleMemos.set(memo, MEMO_ENTRY_WIRE_LEN)
  sampleMemos.set(memo, MEMO_ENTRY_WIRE_LEN * 2)
  const sampleIx = buildTransactInstruction({
    poolId: 0,
    vkId: VK_ID_DEFAULT,
    outLaneId: 0,
    ckptSlotIdx: 0,
    outSubSeq: 0n,
    outRootSeq: 0n,
    outMemoSeq: 0n,
    outNfSeq: 0n,
    payer: AUDREN.mainnetRelayer,
    proof192: proved.proof192,
    nf0: proved.nf0,
    nf1: proved.nf1,
    cm0: proved.cm0,
    cm1: proved.cm1,
    cm2: proved.cm2,
    outputMask: 0b111,
    assetMode: ASSET_MODE_PRIVATE,
    unwrapWsol: false,
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: sampleMemos,
  })
  const v0Wire = compileKitV0Transaction({
    feePayer: AUDREN.mainnetRelayer,
    recentBlockhash: '11111111111111111111111111111111',
    lastValidBlockHeight: 1n,
    instructions: [audrenInstructionToSolana(sampleIx)],
    computeUnitLimit: 350_000,
    lookupTables: getPool0LookupTable('mainnet'),
  })
  if (v0Wire.byteLength > 1232) {
    throw new Error(`Direct Self-Pay v0 Transact with Pool #0 ALT exceeded 1,232 B (${v0Wire.byteLength} B)`)
  }

  console.log(
    `Audren v1.2.1 full crypto + Bech32m + Pool #0 ALT (${v0Wire.byteLength} B v0) + WASM prover audit PASSED (192 B Groth16 in ${ms} ms)`,
  )
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
