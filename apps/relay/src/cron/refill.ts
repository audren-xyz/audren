import { ed25519 } from '@noble/curves/ed25519.js'
import { getAggregatorAdapter, quoteWithSelection } from '../aggregators/registry'
import { getRelayerSecretsB64, type Env, type RelayPolicyConfig } from '../env'
import {
  buildOpenPageSolanaIx,
  buildPublishCheckpointSolanaIx,
  decodeLaneHeader,
  decodePoolState,
  deriveLanePda,
  deriveMemoPda,
  deriveNfPagePda,
  derivePoolPda,
  deriveSubtreePda,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_NULLIFIER,
  OPEN_PAGE_KIND_SUBTREE,
} from '../solana/audren'
import {
  CLASSIC_TOKEN_PROGRAM_ID,
  WSOL_MINT,
  WSOL_MINT_STR,
  base58Decode,
  base58Encode,
  buildAndSignV1Transaction,
  buildCloseTokenAccountIx,
  buildCreateAtaIdempotentIx,
  decodeRelayerSecret,
  deriveAta,
  fromBase64,
  toBase64,
} from '../solana/codec'
import {
  fetchAccountBytes,
  fetchAllOwnedTokenAccounts,
  fetchBalance,
  fetchMintMetas,
  fetchMultipleAccounts,
  rpcCall,
  simulateV1Transaction,
  waitForConfirmation,
} from '../solana/rpc'
import type { Cluster, SolanaInstruction } from '../types'
import { fetchMintPricesUsd } from '../policy/pricing'

/**
 * Permissionless Maintenance Crank:
 *   1. Publishes a fresh `RootCheckpoint` (`PublishCheckpoint`, Tag 5) when `slot >= nextEpoch`.
 *   2. Pre-opens upcoming `SubtreePage`/`MemoPage`/`NullifierPage` PDAs (`OpenPage`, Tag 2)
 *      reimbursed from `LaneRentVault` when any active lane approaches page boundary (`>= 80%` full).
 */
export async function runV2MaintenanceCrank(
  env: Env,
  cluster: Cluster,
): Promise<{ publishedCheckpoint: string | null; openedPages: string[]; notes: string[] }> {
  const rpcUrl = cluster === 'mainnet' ? env.MAINNET_RPC_URL : env.DEVNET_RPC_URL
  const firstSecret = getRelayerSecretsB64(env, cluster)[0] ?? null
  const secret32 = decodeRelayerSecret(firstSecret)
  if (!rpcUrl || !secret32) {
    return { publishedCheckpoint: null, openedPages: [], notes: ['unconfigured'] }
  }
  const relayerPubkey = ed25519.getPublicKey(secret32)
  const relayerB58 = base58Encode(relayerPubkey)
  const poolAcc = await fetchAccountBytes(rpcUrl, base58Encode(derivePoolPda(0).address)).catch(
    () => null,
  )
  if (!poolAcc) return { publishedCheckpoint: null, openedPages: [], notes: ['pool not initialized'] }
  const pool = decodePoolState(poolAcc.bytes)
  if (pool.activeLanes === 0) {
    return { publishedCheckpoint: null, openedPages: [], notes: ['no active lanes'] }
  }

  const slot = await rpcCall<number>(rpcUrl, 'getSlot', [{ commitment: 'confirmed' }])
  const epoch = Math.floor(slot / Number(pool.ckptInterval))
  const slotIdx = epoch % 256
  const notes: string[] = []
  let publishedCheckpoint: string | null = null
  const openedPages: string[] = []

  // Try publishing current epoch RootCheckpoint (simulation skips if already published)
  const ckIx = buildPublishCheckpointSolanaIx({
    payer: relayerB58,
    poolId: 0,
    slotIdx,
    activeLanes: pool.activeLanes,
  })
  const bh = await rpcCall<{ value: { blockhash: string } }>(rpcUrl, 'getLatestBlockhash', [
    { commitment: 'confirmed' },
  ])
  const ckSigned = buildAndSignV1Transaction(secret32, bh.value.blockhash, [ckIx], {
    computeUnitLimit: 120_000,
    priorityFeeLamports: 5_000n,
  })
  const ckSim = await simulateV1Transaction(rpcUrl, ckSigned.wireBytes, [relayerB58])
  if (!ckSim.err) {
    const sig = await rpcCall<string>(rpcUrl, 'sendTransaction', [
      toBase64(ckSigned.wireBytes),
      { encoding: 'base64', preflightCommitment: 'confirmed', maxRetries: 2 },
    ])
    publishedCheckpoint = sig
    notes.push(`Published RootCheckpoint slotIdx=${slotIdx} (${sig})`)
  }

  // Pre-open next SubtreePage / MemoPage / NullifierPage for any lane >= 80% full
  const lanePdas = Array.from({ length: pool.activeLanes }, (_, l) =>
    base58Encode(deriveLanePda(0, l).address),
  )
  const laneAccs = await fetchMultipleAccounts(rpcUrl, lanePdas)
  const openIxs: SolanaInstruction[] = []
  for (let l = 0; l < laneAccs.length; l++) {
    const raw = laneAccs[l]?.bytes
    if (!raw) continue
    const hdr = decodeLaneHeader(raw)
    if (Number(hdr.nextLeaf % 256n) >= 200) {
      const nextSub = hdr.nextLeaf / 256n + 1n
      const [exists] = await fetchMultipleAccounts(rpcUrl, [
        base58Encode(deriveSubtreePda(0, l, nextSub).address),
      ])
      if (!exists) {
        openIxs.push(
          buildOpenPageSolanaIx({
            payer: relayerB58,
            pageKind: OPEN_PAGE_KIND_SUBTREE,
            poolId: 0,
            laneId: l,
            pageSeq: nextSub,
          }),
        )
      }
    }
    if (Number(hdr.nextLeaf % 112n) >= 90) {
      const nextMemo = hdr.nextLeaf / 112n + 1n
      const [exists] = await fetchMultipleAccounts(rpcUrl, [
        base58Encode(deriveMemoPda(0, l, nextMemo).address),
      ])
      if (!exists) {
        openIxs.push(
          buildOpenPageSolanaIx({
            payer: relayerB58,
            pageKind: OPEN_PAGE_KIND_MEMO,
            poolId: 0,
            laneId: l,
            pageSeq: nextMemo,
          }),
        )
      }
    }
    if (Number(hdr.nfCount % 600n) >= 500) {
      const nextNf = hdr.nfCount / 600n + 1n
      const [exists] = await fetchMultipleAccounts(rpcUrl, [
        base58Encode(deriveNfPagePda(0, l, nextNf).address),
      ])
      if (!exists) {
        openIxs.push(
          buildOpenPageSolanaIx({
            payer: relayerB58,
            pageKind: OPEN_PAGE_KIND_NULLIFIER,
            poolId: 0,
            laneId: l,
            pageSeq: nextNf,
          }),
        )
      }
    }
  }
  for (const ix of openIxs.slice(0, 4)) {
    const bh2 = await rpcCall<{ value: { blockhash: string } }>(rpcUrl, 'getLatestBlockhash', [
      { commitment: 'confirmed' },
    ])
    const tx = buildAndSignV1Transaction(secret32, bh2.value.blockhash, [ix], {
      computeUnitLimit: 100_000,
      priorityFeeLamports: 5_000n,
    })
    const sim = await simulateV1Transaction(rpcUrl, tx.wireBytes, [relayerB58])
    if (!sim.err) {
      const sig = await rpcCall<string>(rpcUrl, 'sendTransaction', [
        toBase64(tx.wireBytes),
        { encoding: 'base64', preflightCommitment: 'confirmed', maxRetries: 2 },
      ])
      openedPages.push(sig)
    }
  }

  return { publishedCheckpoint, openedPages, notes }
}

export interface RefillReport {
  checkedAt: string
  relayerPubkey: string
  solBefore: number
  solAfter: number
  minSolThreshold: number
  action: 'healthy' | 'unwrapped_wsol' | 'swapped_fees' | 'no_fees_to_swap' | 'skipped_unconfigured'
  signatures: string[]
  details: string[]
}

/**
 * Self-sustaining Treasury Auto-Refill job (invoked by 15-minute Cron Trigger or admin endpoint).
 *
 * Dynamically scans all Classic SPL & Token-2022 accounts owned by the
 * relayer via Solana RPC `getTokenAccountsByOwner`:
 *   1. Unwraps any accumulated WSOL fee balance into native SOL (and re-opens WSOL ATA).
 *   2. Converts ANY accumulated fee token worth >= `REFILL_MIN_TOKEN_USD` into WSOL via the
 *      active aggregator, then unwraps into native SOL.
 */
export async function runAutoRefill(env: Env, cfg: RelayPolicyConfig): Promise<RefillReport> {
  const checkedAt = new Date().toISOString()
  const secret32 = decodeRelayerSecret(env.MAINNET_RELAYER_SECRET_B64 ?? null)
  const rpcUrl = env.MAINNET_RPC_URL
  if (!secret32 || !rpcUrl) {
    return {
      checkedAt,
      relayerPubkey: '',
      solBefore: 0,
      solAfter: 0,
      minSolThreshold: cfg.refillMinSol,
      action: 'skipped_unconfigured',
      signatures: [],
      details: ['Mainnet relayer secret or RPC URL not configured'],
    }
  }

  const relayerPubkey = ed25519.getPublicKey(secret32)
  const relayerB58 = base58Encode(relayerPubkey)
  const solBefore = (await fetchBalance(rpcUrl, relayerB58)) / 1e9

  if (solBefore >= cfg.refillMinSol) {
    return {
      checkedAt,
      relayerPubkey: relayerB58,
      solBefore,
      solAfter: solBefore,
      minSolThreshold: cfg.refillMinSol,
      action: 'healthy',
      signatures: [],
      details: [`Relayer balance ${solBefore.toFixed(4)} SOL >= ${cfg.refillMinSol} SOL threshold`],
    }
  }

  const signatures: string[] = []
  const details: string[] = []
  const wsolAta = deriveAta(relayerPubkey, CLASSIC_TOKEN_PROGRAM_ID, WSOL_MINT)

  // Dynamically discover ALL token accounts owned by the relayer (Classic SPL + Token-2022)
  const ownedAccounts = await fetchAllOwnedTokenAccounts(rpcUrl, relayerB58)
  const nonZero = ownedAccounts.filter((a) => a.amount > 0n)

  // Step 1: Unwrap existing WSOL balance if >= 0.005 SOL
  const wsolEntry = nonZero.find((a) => a.mint === WSOL_MINT_STR)
  if (wsolEntry && wsolEntry.amount >= 5_000_000n) {
    const [bh, preLamports] = await Promise.all([
      rpcCall<{ value: { blockhash: string } }>(rpcUrl, 'getLatestBlockhash', [
        { commitment: 'confirmed' },
      ]),
      fetchBalance(rpcUrl, relayerB58),
    ])
    const ixs: SolanaInstruction[] = [
      buildCloseTokenAccountIx({
        account: base58Decode(wsolEntry.ata),
        destination: relayerPubkey,
        authority: relayerPubkey,
      }),
      buildCreateAtaIdempotentIx({
        payer: relayerPubkey,
        ata: wsolAta,
        owner: relayerPubkey,
        mint: WSOL_MINT,
        tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
      }),
    ]
    const signed = buildAndSignV1Transaction(secret32, bh.value.blockhash, ixs, {
      computeUnitLimit: 100_000,
      priorityFeeLamports: 10_000n,
    })
    const unwrapSim = await simulateV1Transaction(rpcUrl, signed.wireBytes, [relayerB58])
    const postUnwrapLamports = unwrapSim.accounts[0]?.lamports ?? 0
    if (unwrapSim.err || postUnwrapLamports <= preLamports) {
      details.push(
        `Skipped WSOL unwrap: pre-flight simulation did not increase SOL (${unwrapSim.err ? JSON.stringify(unwrapSim.err) : 'no net SOL gain'})`,
      )
    } else {
      const sig = await rpcCall<string>(rpcUrl, 'sendTransaction', [
        toBase64(signed.wireBytes),
        { encoding: 'base64', preflightCommitment: 'confirmed', maxRetries: 3 },
      ])
      await waitForConfirmation(rpcUrl, sig)
      signatures.push(sig)
      details.push(`Unwrapped ${(Number(wsolEntry.amount) / 1e9).toFixed(4)} WSOL → native SOL (${sig})`)
    }
  }

  let currentSol = (await fetchBalance(rpcUrl, relayerB58)) / 1e9
  if (currentSol >= cfg.refillMinSol) {
    return {
      checkedAt,
      relayerPubkey: relayerB58,
      solBefore,
      solAfter: currentSol,
      minSolThreshold: cfg.refillMinSol,
      action: 'unwrapped_wsol',
      signatures,
      details,
    }
  }

  // Step 2: Dynamically inspect decimals + USD prices for EVERY non-WSOL token owned by the relayer
  const otherTokens = nonZero.filter((a) => a.mint !== WSOL_MINT_STR)
  if (otherTokens.length > 0) {
    const uniqueMints = [...new Set(otherTokens.map((a) => a.mint))]
    const [mintMetas, prices] = await Promise.all([
      fetchMintMetas(rpcUrl, uniqueMints),
      fetchMintPricesUsd(env, [WSOL_MINT_STR, ...uniqueMints]),
    ])

    for (const acc of otherTokens) {
      if (currentSol >= cfg.refillMinSol * 1.5) break
      const meta = mintMetas[acc.mint]
      const price = prices[acc.mint]
      if (!meta || !price) continue
      const usdVal = (Number(acc.amount) / Math.pow(10, meta.decimals)) * price
      if (usdVal < cfg.refillMinTokenUsd) {
        details.push(
          `Skipping ${acc.mint.slice(0, 6)}… ($${usdVal.toFixed(2)} < $${cfg.refillMinTokenUsd})`,
        )
        continue
      }

      try {
        const { winner } = await quoteWithSelection(env, cfg, cfg.defaultAggregator, {
          inputMint: acc.mint,
          outputMint: WSOL_MINT_STR,
          amount: acc.amount.toString(),
          slippageBps: 100,
          onlyDirectRoutes: true,
          maxAccounts: 24,
          platformFeeBps: 0,
          escrowPubkey: relayerB58,
        })
        const adapter = getAggregatorAdapter(winner.provider)
        const built = await adapter.swapInstructions(env, {
          quoteResponse: winner.rawQuote,
          escrowPubkey: relayerB58,
          inputMint: acc.mint,
          outputMint: WSOL_MINT_STR,
        })
        const [bh, preSwapLamports] = await Promise.all([
          rpcCall<{ value: { blockhash: string } }>(rpcUrl, 'getLatestBlockhash', [
            { commitment: 'confirmed' },
          ]),
          fetchBalance(rpcUrl, relayerB58),
        ])
        const ixs: SolanaInstruction[] = [
          buildCreateAtaIdempotentIx({
            payer: relayerPubkey,
            ata: wsolAta,
            owner: relayerPubkey,
            mint: WSOL_MINT,
            tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
          }),
          {
            programId: base58Decode(built.swapInstruction.programId),
            accounts: built.swapInstruction.accounts.map((a) => ({
              pubkey: base58Decode(a.pubkey),
              isSigner: a.isSigner,
              isWritable: a.isWritable,
            })),
            data: fromBase64(built.swapInstruction.data),
          },
          buildCloseTokenAccountIx({
            account: wsolAta,
            destination: relayerPubkey,
            authority: relayerPubkey,
          }),
          buildCreateAtaIdempotentIx({
            payer: relayerPubkey,
            ata: wsolAta,
            owner: relayerPubkey,
            mint: WSOL_MINT,
            tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
          }),
        ]
        const signed = buildAndSignV1Transaction(secret32, bh.value.blockhash, ixs, {
          computeUnitLimit: 600_000,
          priorityFeeLamports: 20_000n,
        })
        const sim = await simulateV1Transaction(rpcUrl, signed.wireBytes, [relayerB58])
        const postSwapLamports = sim.accounts[0]?.lamports ?? 0
        if (sim.err || postSwapLamports <= preSwapLamports) {
          details.push(
            `Skipped refill swap for ${acc.mint.slice(0, 6)}…: pre-flight simulation ${sim.err ? `failed (${JSON.stringify(sim.err)})` : 'did not increase SOL'}`,
          )
          continue
        }
        const sig = await rpcCall<string>(rpcUrl, 'sendTransaction', [
          toBase64(signed.wireBytes),
          { encoding: 'base64', preflightCommitment: 'confirmed', maxRetries: 3 },
        ])
        await waitForConfirmation(rpcUrl, sig)
        signatures.push(sig)
        details.push(
          `Swapped $${usdVal.toFixed(2)} of ${acc.mint.slice(0, 6)}… via ${winner.provider} → native SOL (${sig})`,
        )
        currentSol = (await fetchBalance(rpcUrl, relayerB58)) / 1e9
      } catch (err) {
        details.push(
          `Refill swap failed for ${acc.mint.slice(0, 6)}…: ${err instanceof Error ? err.message : String(err)}`,
        )
      }
    }
  }

  return {
    checkedAt,
    relayerPubkey: relayerB58,
    solBefore,
    solAfter: currentSol,
    minSolThreshold: cfg.refillMinSol,
    action: signatures.length > 0 ? 'swapped_fees' : 'no_fees_to_swap',
    signatures,
    details,
  }
}
