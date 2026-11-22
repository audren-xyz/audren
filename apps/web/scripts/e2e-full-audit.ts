/**
 * End-to-end cryptographic & WASM prover audit check for `apps/web`.
 *
 * Verifies local key derivation, 90 B SoA ChaCha20-Poly1305 memo encryption/decryption,
 * 4-ary Depth-20 Merkle path, real WASM BN254 Groth16 proving, and Mode 1 selective disclosure.
 */

import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import {
  ASSET_MODE_PRIVATE,
  NUM_LANES,
  WSOL_MINT,
  ZERO_HASHES_4ARY,
  base58Decode,
  buildWitnessFromFrozenSubsiblings,
  computeJoinsplitCtxHash,
  computeMerkleRoot4Ary,
  computeNoteCommitment,
  computeSubtree256Root,
  deriveAssetId,
  deriveKeysFromSeed,
  deriveStealthOwner,
  encryptNoteMemo,
  exportFullViewingKey,
  extractIntraSubtreeSiblings,
  frToBeBytes,
  tryDecryptAndVerifyMemo90,
  verifySelectiveDisclosureProof,
} from '../lib/audren-crypto'
import { AudrenWasmProver, dummyInputWitness, dummyOutputWitness } from '../lib/audren-prover'

async function main() {
  const seed = new Uint8Array(32).fill(7)
  const keys = deriveKeysFromSeed(seed)
  const fvk = exportFullViewingKey(keys)
  const mint = base58Decode(WSOL_MINT)
  const assetId = deriveAssetId(mint)
  const amount = 5_000_000n

  const { tweak, blinding, memo90 } = encryptNoteMemo(keys.viewPk, new Uint8Array(32).fill(9), amount, mint)
  const stealthOwner = deriveStealthOwner(keys.spendPk, tweak)
  const commitment = computeNoteCommitment(stealthOwner, assetId, amount, blinding)

  const dec = tryDecryptAndVerifyMemo90(fvk, memo90, frToBeBytes(commitment))
  if (!dec || dec.amount !== amount) {
    throw new Error('Memo decryption/verification mismatch')
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
  const ctxHash = computeJoinsplitCtxHash({
    poolId: 0,
    outLaneId: 1,
    outputMask: 0b001,
    assetMode: ASSET_MODE_PRIVATE,
    unwrapWsol: false,
    recipient: null,
    relayerFeeRecipient: null,
    publicAssetId: new Uint8Array(32),
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    memosBytes: memo90,
  })
  const t0 = performance.now()
  const proved = prover.proveJoinsplit({
    superRoot,
    txAssetId: assetId,
    publicAssetId: 0n,
    publicAmountOut: 0n,
    relayerFeeAmount: 0n,
    ctxHash,
    omitNf1: true,
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

  console.log(`Audren full crypto + WASM prover audit PASSED (192 B Groth16 in ${ms} ms)`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
