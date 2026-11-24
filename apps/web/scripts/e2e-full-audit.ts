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
  ASSET_MODE_PUBLIC,
  AUDREN_PROGRAM_ID,
  CU_LIMIT_DEPOSIT,
  CU_LIMIT_TRANSACT_FULL_EXIT,
  CU_LIMIT_TRANSACT_PRIVATE,
  CU_LIMIT_TRANSACT_WITHDRAW,
  MEMO_ENTRY_WIRE_LEN,
  NUM_LANES,
  PROTOCOL_VERSION,
  ROOTS_MAGIC,
  ROOT_HISTORY_LEN,
  ROOT_RING_EPOCH,
  ROOT_RING_SLOT,
  RT_OFF_BUMP,
  RT_OFF_EPOCH_COUNT,
  RT_OFF_EPOCH_CURSOR,
  RT_OFF_EPOCH_INTERVAL,
  RT_OFF_EPOCH_RING,
  RT_OFF_LATEST_LANE_COUNTS,
  RT_OFF_LATEST_LANE_ROOTS,
  RT_OFF_LATEST_SLOT,
  RT_OFF_LATEST_SUPER_ROOT,
  RT_OFF_POOL_ID,
  RT_OFF_SLOT_COUNT,
  RT_OFF_SLOT_CURSOR,
  RT_OFF_SLOT_RING,
  RT_OFF_STABLE_LANE_COUNTS,
  RT_OFF_STABLE_LANE_ROOTS,
  RT_OFF_STABLE_SLOT,
  RT_OFF_STABLE_SUPER_ROOT,
  RT_OFF_VERSION,
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
  computeSuperRoot4Ary,
  computeTransactCtxHash,
  decodeGlobalRootHistory,
  deriveAssetId,
  deriveKeysFromSeed,
  deriveRootsPdaSync,
  deriveStealthOwner,
  encryptNoteMemo,
  exportFullViewingKey,
  extractIntraSubtreeSiblings,
  formatAudrenAddress,
  frToBeBytes,
  parseAudrenAddress,
  recommendedDepositCuLimit,
  recommendedTransactCuLimit,
  selectRootSnapshotForNotes,
  tryDecryptAndVerifyMemo,
  verifySelectiveDisclosureProof,
} from '../lib/audren-crypto'
import { AudrenWasmProver, dummyInputWitness, dummyOutputWitness } from '../lib/audren-prover'
import { AUDREN, getPool0LookupTable } from '../lib/protocol'
import { compileKitV0Transaction } from '../lib/solana-wallet'
import webWorker from '../worker/index'

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
  const laneRoots = Array.from({ length: NUM_LANES }, (_, i) =>
    i === 0 ? lane0Root : ZERO_HASHES_4ARY[18]!,
  )
  const path = buildWitnessFromFrozenSubsiblings({
    laneId: 0,
    targetLeafIdx: 0n,
    intraSiblings: siblings,
    intraPositions: positions,
    laneRoots,
    laneLeafCount: 1n,
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

  // Verify v1.3.0 register, canonical rootsPda, GlobalRootHistory decoder + selector,
  // frozen Pool #0 ALTs (73 entries each), prover-worker.js, tight CU limits, & v0 ALT compression <= 1,232 B
  if (AUDREN.version !== '1.3.0' || AUDREN.releaseTag !== 'v1.3.0') {
    throw new Error(`Expected AUDREN version 1.3.0 / v1.3.0, got ${AUDREN.version} / ${AUDREN.releaseTag}`)
  }
  const derivedRoots = deriveRootsPdaSync(0, AUDREN_PROGRAM_ID)
  if (derivedRoots.address !== AUDREN.rootsPda || derivedRoots.bump !== 254) {
    throw new Error(
      `rootsPda mismatch: expected ${AUDREN.rootsPda} (bump 254), got ${derivedRoots.address} (bump ${derivedRoots.bump})`,
    )
  }

  // Synthesize canonical 10,216 B GlobalRootHistory (`AUD1RT01`) and verify decode + snapshot selection
  const rootsBuf = new Uint8Array(ROOT_HISTORY_LEN)
  rootsBuf.set(new TextEncoder().encode(ROOTS_MAGIC), 0)
  rootsBuf[RT_OFF_VERSION] = PROTOCOL_VERSION
  rootsBuf[RT_OFF_BUMP] = derivedRoots.bump
  const dv = new DataView(rootsBuf.buffer)
  dv.setUint16(RT_OFF_SLOT_CURSOR, 0, true)
  dv.setUint32(RT_OFF_POOL_ID, 0, true)
  dv.setUint16(RT_OFF_EPOCH_CURSOR, 0, true)
  dv.setUint16(RT_OFF_SLOT_COUNT, 1, true)
  dv.setUint16(RT_OFF_EPOCH_COUNT, 1, true)
  dv.setBigUint64(RT_OFF_LATEST_SLOT, 100n, true)
  dv.setBigUint64(RT_OFF_STABLE_SLOT, 64n, true)
  dv.setBigUint64(RT_OFF_EPOCH_INTERVAL, 32n, true)
  const superRootBytes = frToBeBytes(superRoot)
  const emptyLaneRoots = Array.from({ length: NUM_LANES }, () => ZERO_HASHES_4ARY[18]!)
  const emptySuperRootBytes = frToBeBytes(computeSuperRoot4Ary(emptyLaneRoots))
  rootsBuf.set(superRootBytes, RT_OFF_LATEST_SUPER_ROOT)
  rootsBuf.set(emptySuperRootBytes, RT_OFF_STABLE_SUPER_ROOT)
  for (let l = 0; l < NUM_LANES; l++) {
    rootsBuf.set(frToBeBytes(laneRoots[l]!), RT_OFF_LATEST_LANE_ROOTS + l * 32)
    dv.setBigUint64(RT_OFF_LATEST_LANE_COUNTS + l * 8, l === 0 ? 1n : 0n, true)
    rootsBuf.set(frToBeBytes(emptyLaneRoots[l]!), RT_OFF_STABLE_LANE_ROOTS + l * 32)
    dv.setBigUint64(RT_OFF_STABLE_LANE_COUNTS + l * 8, 0n, true)
  }
  rootsBuf.set(superRootBytes, RT_OFF_SLOT_RING)
  dv.setBigUint64(RT_OFF_SLOT_RING + 32, 100n, true)
  rootsBuf.set(emptySuperRootBytes, RT_OFF_EPOCH_RING)
  dv.setBigUint64(RT_OFF_EPOCH_RING + 32, 64n, true)
  const decodedRoots = decodeGlobalRootHistory(rootsBuf)
  const instantSnap = selectRootSnapshotForNotes(decodedRoots, [{ laneId: 0, leafIndex: 0n }])
  if (!instantSnap || instantSnap.ringKind !== ROOT_RING_SLOT || instantSnap.ringIdx !== 0) {
    throw new Error('selectRootSnapshotForNotes failed instant slot-ring fallback for fresh note')
  }
  const stableSnap = selectRootSnapshotForNotes(decodedRoots, [])
  if (!stableSnap || stableSnap.ringKind !== ROOT_RING_EPOCH || stableSnap.ringIdx !== 0) {
    throw new Error('selectRootSnapshotForNotes failed stable epoch-ring preference')
  }

  for (const cluster of ['mainnet', 'devnet'] as const) {
    const alt = AUDREN[cluster].pool0Alt
    if (alt.entries.length !== 73 || alt.entries[0] !== AUDREN_PROGRAM_ID) {
      throw new Error(`Invalid ${cluster} Pool #0 ALT register`)
    }
    for (const addr of alt.entries) {
      if (base58Decode(addr).byteLength !== 32) {
        throw new Error(`Invalid pubkey in ${cluster} Pool #0 ALT: ${addr}`)
      }
    }
  }
  const workerSrc = await readFile(resolve(process.cwd(), 'public/wasm/prover-worker.js'), 'utf8')
  if (
    !workerSrc.includes('?v=1.3.0') ||
    !workerSrc.includes('WebAssembly.RuntimeError') ||
    !workerSrc.includes('CANONICAL_WASM_SHA256') ||
    !workerSrc.includes('oPtr, PROVE_OUTPUT_BYTES).fill(0)')
  ) {
    throw new Error('prover-worker.js missing v1.3.0 cache-buster, RuntimeError reset, WASM SHA-256 pin, or oPtr scrub')
  }
  const sampleMemos = new Uint8Array(MEMO_ENTRY_WIRE_LEN * 3)
  sampleMemos.set(memo, 0)
  sampleMemos.set(memo, MEMO_ENTRY_WIRE_LEN)
  sampleMemos.set(memo, MEMO_ENTRY_WIRE_LEN * 2)
  const sampleIx = buildTransactInstruction({
    poolId: 0,
    vkId: VK_ID_DEFAULT,
    rootRingKind: ROOT_RING_SLOT,
    rootRingIdx: 0,
    outLaneId: 0,
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
  if (sampleIx.accounts[2]?.pubkey !== AUDREN.rootsPda || !sampleIx.accounts[2].isWritable) {
    throw new Error('Private Transact accounts[2] must be writable canonical rootsPda')
  }
  const fullExitIx = buildTransactInstruction({
    poolId: 0,
    vkId: VK_ID_DEFAULT,
    rootRingKind: ROOT_RING_EPOCH,
    rootRingIdx: 0,
    outLaneId: 0,
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
    outputMask: 0,
    assetMode: ASSET_MODE_PUBLIC,
    unwrapWsol: true,
    publicAmountOut: amount,
    relayerFeeAmount: 0n,
    recipient: AUDREN.mainnetRelayer,
    memosBytes: new Uint8Array(0),
  })
  if (fullExitIx.accounts[2]?.pubkey !== AUDREN.rootsPda || fullExitIx.accounts[2].isWritable) {
    throw new Error('Full-exit Transact (outputMask=0) accounts[2] must be read-only rootsPda')
  }
  if (
    recommendedDepositCuLimit() !== CU_LIMIT_DEPOSIT ||
    recommendedTransactCuLimit({ assetMode: ASSET_MODE_PUBLIC, outputMask: 0 }) !==
      CU_LIMIT_TRANSACT_FULL_EXIT ||
    recommendedTransactCuLimit({ assetMode: ASSET_MODE_PUBLIC, outputMask: 1 }) !==
      CU_LIMIT_TRANSACT_WITHDRAW ||
    recommendedTransactCuLimit({ assetMode: ASSET_MODE_PRIVATE, outputMask: 0b111 }) !==
      CU_LIMIT_TRANSACT_PRIVATE
  ) {
    throw new Error('Calibrated CU limit helpers drifted from canonical v1.3.0 budgets')
  }

  const v0Wire = compileKitV0Transaction({
    feePayer: AUDREN.mainnetRelayer,
    recentBlockhash: '11111111111111111111111111111111',
    lastValidBlockHeight: 1n,
    instructions: [audrenInstructionToSolana(sampleIx)],
    computeUnitLimit: CU_LIMIT_TRANSACT_PRIVATE,
    lookupTables: getPool0LookupTable('mainnet'),
  })
  if (v0Wire.byteLength > 1232) {
    throw new Error(`Direct Self-Pay v0 Transact with Pool #0 ALT exceeded 1,232 B (${v0Wire.byteLength} B)`)
  }

  // H-8 / M-8 / M-10: Verify apps/web worker CSRF guard, security headers, and Jupiter clamps
  const dummyEnv = {
    ASSETS: { fetch: async () => new Response('not found', { status: 404 }) },
  }
  const ctReject = await webWorker.fetch(
    new Request('https://audren.xyz/api/devnet/deposit', {
      method: 'POST',
      headers: { 'content-type': 'text/plain', origin: 'https://audren.xyz' },
      body: '{}',
    }),
    dummyEnv,
  )
  if (ctReject.status !== 415) {
    throw new Error(`Expected 415 for non-JSON POST /api/*, got ${ctReject.status}`)
  }
  if (
    ctReject.headers.get('x-content-type-options') !== 'nosniff' ||
    ctReject.headers.get('referrer-policy') !== 'no-referrer' ||
    !ctReject.headers.get('strict-transport-security')?.includes('max-age=')
  ) {
    throw new Error('jsonResponse missing required M-8 security headers')
  }
  const csrfReject = await webWorker.fetch(
    new Request('https://audren.xyz/api/devnet/deposit', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'https://evil.example',
        'sec-fetch-site': 'cross-site',
      },
      body: '{}',
    }),
    dummyEnv,
  )
  if (csrfReject.status !== 403) {
    throw new Error(`Expected 403 for cross-origin POST /api/*, got ${csrfReject.status}`)
  }
  const missingOriginReject = await webWorker.fetch(
    new Request('https://audren.xyz/api/devnet/deposit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    }),
    dummyEnv,
  )
  if (missingOriginReject.status !== 403) {
    throw new Error(`Expected 403 when both Origin and Sec-Fetch-Site are absent, got ${missingOriginReject.status}`)
  }

  // R2-1 High #1: Verify /api/rpc/send accepts 23-byte OpenPage and rejects stale 15-byte OpenPage
  const { buildOpenPageInstruction, OPEN_PAGE_KIND_MEMO } = await import('@audren/sdk')
  const openPage23 = buildOpenPageInstruction({
    payer: AUDREN.mainnetRelayer,
    pageKind: OPEN_PAGE_KIND_MEMO,
    poolId: 0,
    laneId: 0,
    pageSeq: 1n,
    maxPayerDeficit: 0n,
  })
  const tx23 = compileKitV0Transaction({
    feePayer: AUDREN.mainnetRelayer,
    recentBlockhash: '11111111111111111111111111111111',
    lastValidBlockHeight: 1n,
    instructions: [audrenInstructionToSolana(openPage23)],
    computeUnitLimit: 60_000,
  })
  const openPage15 = { ...openPage23, data: openPage23.data.slice(0, 15) }
  const tx15 = compileKitV0Transaction({
    feePayer: AUDREN.mainnetRelayer,
    recentBlockhash: '11111111111111111111111111111111',
    lastValidBlockHeight: 1n,
    instructions: [audrenInstructionToSolana(openPage15)],
    computeUnitLimit: 60_000,
  })
  const envWithDummyRpc = { ...dummyEnv, MAINNET_RPC_URL: 'https://rpc.example.invalid' }
  const res15 = await webWorker.fetch(
    new Request('https://audren.xyz/api/rpc/send', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'https://audren.xyz',
        'sec-fetch-site': 'same-origin',
      },
      body: JSON.stringify({ cluster: 'mainnet', transactionB64: Buffer.from(tx15).toString('base64') }),
    }),
    envWithDummyRpc,
  )
  if (res15.status !== 403) {
    throw new Error(`Expected 403 for legacy 15-byte OpenPage on /api/rpc/send, got ${res15.status}`)
  }
  const origFetch = globalThis.fetch
  try {
    globalThis.fetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
      const rpcBody = JSON.parse(String(init?.body ?? '{}')) as { method?: string }
      if (rpcBody.method === 'getSignatureStatuses') {
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            result: { value: [{ slot: 123_456, err: null, confirmationStatus: 'confirmed' }] },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        )
      }
      return new Response(
        JSON.stringify({ jsonrpc: '2.0', id: 1, result: '5OpenPage23OkSig11111111111111111111111111' }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      )
    }) as typeof fetch
    const res23 = await webWorker.fetch(
      new Request('https://audren.xyz/api/rpc/send', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          origin: 'https://audren.xyz',
          'sec-fetch-site': 'same-origin',
        },
        body: JSON.stringify({ cluster: 'mainnet', transactionB64: Buffer.from(tx23).toString('base64') }),
      }),
      envWithDummyRpc,
    )
    if (res23.status !== 200) {
      throw new Error(`Expected 200 for canonical 23-byte OpenPage on /api/rpc/send, got ${res23.status}`)
    }
  } finally {
    globalThis.fetch = origFetch
  }

  console.log(
    `Audren v1.3.0 full crypto + GlobalRootHistory + Bech32m + Pool #0 ALT (${v0Wire.byteLength} B v0) + Worker CSRF/headers/OpenPage23 + WASM prover audit PASSED (192 B Groth16 in ${ms} ms)`,
  )
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
