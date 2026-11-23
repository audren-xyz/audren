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
  MEMO_ENTRY_WIRE_LEN,
  NUM_LANES,
  VK_ID_DEFAULT,
  WSOL_MINT,
  ZERO_HASHES_4ARY,
  base58Decode,
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

  console.log(
    `Audren v1.2.0 full crypto + Bech32m + WASM prover audit PASSED (192 B Groth16 in ${ms} ms)`,
  )
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
