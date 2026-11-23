import { ed25519 } from '@noble/curves/ed25519.js'
import { getAggregatorAdapter, quoteWithSelection } from '../aggregators/registry'
import { getRelayerSecretsB64, type Env, type RelayPolicyConfig } from '../env'
import {
  MEMO_NOTES_PER_PAGE,
  NF_PER_PAGE,
  OPEN_PAGE_KIND_MEMO,
  OPEN_PAGE_KIND_NULLIFIER,
  OPEN_PAGE_KIND_SUBROOT,
  OPEN_PAGE_KIND_SUBTREE,
  SUBROOTS_PER_PAGE,
  SUBTREE_LEAVES,
  buildOpenPageSolanaIx,
  decodeLaneHeader,
  decodePoolState,
  deriveLanePda,
  deriveMemoPda,
  deriveNfPagePda,
  derivePoolPda,
  deriveSubrootPda,
  deriveSubtreePda,
} from '../solana/audren'
import { publishCheckpointIfNeeded, type CheckpointLockAdapter } from '../solana/checkpoint'
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
 * Permissionless Maintenance Crank (every 2 minutes):
 *   1. Publishes a fresh `RootCheckpoint` (`PublishCheckpoint`, Tag 4) when uncheckpointed leaves
 *      (or an expired checkpoint on a non-empty pool) exist and `currentSlot >= nextCkptSlot`.
 *   2. Pre-opens upcoming `SubtreePage`/`SubtreeRootPage`/`MemoPage`/`NullifierPage` PDAs
 *      (`OpenPage`, Tag 2) reimbursed from `LaneRentVault` when any active lane approaches
 *      page boundaries (matching on-chain `OpenPage` lookahead rules).
 */
export async function runMaintenanceCrank(
  env: Env,
  cluster: Cluster,
  checkpointLock?: CheckpointLockAdapter,
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

  const notes: string[] = []
  let publishedCheckpoint: string | null = null
  const openedPages: string[] = []

  // Publish RootCheckpoint only when uncheckpointed leaves (or expired checkpoint) need publishing.
  try {
    const ckptRes = await publishCheckpointIfNeeded({
      rpcUrl,
      cluster,
      poolId: 0,
      relayerSecret32: secret32,
      lock: checkpointLock,
      confirm: false,
    })
    if (ckptRes.status === 'published' && ckptRes.signature) {
      publishedCheckpoint = ckptRes.signature
      notes.push(`Published RootCheckpoint epoch=${ckptRes.epoch} slotIdx=${ckptRes.slotIdx ?? ''} (${ckptRes.signature})`)
    } else if (ckptRes.status === 'cooldown') {
      notes.push(`Checkpoint cooldown (${ckptRes.slotsRemaining ?? 0} slots remaining)`)
    }
  } catch (err) {
    notes.push(`Checkpoint crank skipped: ${err instanceof Error ? err.message : String(err)}`)
  }

  // Ensure current pages exist AND pre-open next SubtreePage / SubtreeRootPage / MemoPage / NullifierPage
  // for any lane approaching page boundaries (>= 80% full).
  const lanePdas = Array.from({ length: pool.activeLanes }, (_, l) =>
    base58Encode(deriveLanePda(0, l).address),
  )
  const laneAccs = await fetchMultipleAccounts(rpcUrl, lanePdas)
  const openIxs: SolanaInstruction[] = []
  for (let l = 0; l < laneAccs.length; l++) {
    const raw = laneAccs[l]?.bytes
    if (!raw) continue
    const hdr = decodeLaneHeader(raw)

    const subSize = BigInt(SUBTREE_LEAVES)
    const srSize = BigInt(SUBROOTS_PER_PAGE)
    const memoSize = BigInt(MEMO_NOTES_PER_PAGE)
    const nfSize = BigInt(NF_PER_PAGE)

    const curSub = hdr.nextLeaf / subSize
    const curSubroot = curSub / srSize
    const curMemo = hdr.nextLeaf / memoSize
    const curNf = hdr.nfCount / nfSize

    const candidates: Array<{ pageKind: number; pageSeq: bigint; pda: string }> = [
      {
        pageKind: OPEN_PAGE_KIND_SUBTREE,
        pageSeq: curSub,
        pda: base58Encode(deriveSubtreePda(0, l, curSub).address),
      },
      {
        pageKind: OPEN_PAGE_KIND_SUBROOT,
        pageSeq: curSubroot,
        pda: base58Encode(deriveSubrootPda(0, l, curSubroot).address),
      },
      {
        pageKind: OPEN_PAGE_KIND_MEMO,
        pageSeq: curMemo,
        pda: base58Encode(deriveMemoPda(0, l, curMemo).address),
      },
      {
        pageKind: OPEN_PAGE_KIND_NULLIFIER,
        pageSeq: curNf,
        pda: base58Encode(deriveNfPagePda(0, l, curNf).address),
      },
    ]

    if (Number(hdr.nextLeaf % subSize) >= 200) {
      const nextSub = curSub + 1n
      candidates.push({
        pageKind: OPEN_PAGE_KIND_SUBTREE,
        pageSeq: nextSub,
        pda: base58Encode(deriveSubtreePda(0, l, nextSub).address),
      })
    }
    // On-chain `OpenPage` permits SUBROOT lookahead strictly when `subroot_slot >= 280`.
    if (Number(curSub % srSize) >= 280) {
      const nextSubroot = curSubroot + 1n
      candidates.push({
        pageKind: OPEN_PAGE_KIND_SUBROOT,
        pageSeq: nextSubroot,
        pda: base58Encode(deriveSubrootPda(0, l, nextSubroot).address),
      })
    }
    if (Number(hdr.nextLeaf % memoSize) >= 77) {
      const nextMemo = curMemo + 1n
      candidates.push({
        pageKind: OPEN_PAGE_KIND_MEMO,
        pageSeq: nextMemo,
        pda: base58Encode(deriveMemoPda(0, l, nextMemo).address),
      })
    }
    if (Number(hdr.nfCount % nfSize) >= 500) {
      const nextNf = curNf + 1n
      candidates.push({
        pageKind: OPEN_PAGE_KIND_NULLIFIER,
        pageSeq: nextNf,
        pda: base58Encode(deriveNfPagePda(0, l, nextNf).address),
      })
    }

    const existing = await fetchMultipleAccounts(
      rpcUrl,
      candidates.map((c) => c.pda),
      { dataSlice: { offset: 0, length: 0 } },
    )
    candidates.forEach((cand, idx) => {
      if (!existing[idx]) {
        openIxs.push(
          buildOpenPageSolanaIx({
            payer: relayerB58,
            pageKind: cand.pageKind,
            poolId: 0,
            laneId: l,
            pageSeq: cand.pageSeq,
          }),
        )
      }
    })
  }
  for (const ix of openIxs.slice(0, 6)) {
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
  payers?: RefillReport[]
}

async function refillSinglePayer(
  env: Env,
  cfg: RelayPolicyConfig,
  rpcUrl: string,
  secret32: Uint8Array,
  checkedAt: string,
): Promise<RefillReport> {

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

/**
 * Self-sustaining Treasury Auto-Refill job (invoked by 2-minute Cron Trigger or admin endpoint).
 *
 * Iterates over ALL configured Mainnet relayer payers (`MAINNET_RELAYER_SECRETS_JSON` or
 * `MAINNET_RELAYER_SECRET_B64`), scanning every Classic SPL & Token-2022 account owned by each
 * payer via Solana RPC `getTokenAccountsByOwner`:
 *   1. Unwraps any accumulated WSOL fee balance into native SOL (and re-opens WSOL ATA).
 *   2. Converts ANY accumulated fee token worth >= `REFILL_MIN_TOKEN_USD` into WSOL via the
 *      active aggregator, then unwraps into native SOL.
 */
export async function runAutoRefill(env: Env, cfg: RelayPolicyConfig): Promise<RefillReport> {
  const checkedAt = new Date().toISOString()
  const rpcUrl = env.MAINNET_RPC_URL
  const secrets = getRelayerSecretsB64(env, 'mainnet')
    .map((s) => decodeRelayerSecret(s))
    .filter((s): s is Uint8Array => s !== null)

  if (secrets.length === 0 || !rpcUrl) {
    return {
      checkedAt,
      relayerPubkey: '',
      solBefore: 0,
      solAfter: 0,
      minSolThreshold: cfg.refillMinSol,
      action: 'skipped_unconfigured',
      signatures: [],
      details: ['Mainnet relayer secret(s) or RPC URL not configured'],
    }
  }

  const reports: RefillReport[] = []
  for (const secret32 of secrets) {
    reports.push(await refillSinglePayer(env, cfg, rpcUrl, secret32, checkedAt))
  }

  if (reports.length === 1) return reports[0]!

  const actionPriority: Record<RefillReport['action'], number> = {
    swapped_fees: 4,
    unwrapped_wsol: 3,
    no_fees_to_swap: 2,
    healthy: 1,
    skipped_unconfigured: 0,
  }
  const topAction = reports.reduce<RefillReport['action']>(
    (best, r) => (actionPriority[r.action] > actionPriority[best] ? r.action : best),
    'healthy',
  )
  return {
    checkedAt,
    relayerPubkey: reports[0]!.relayerPubkey,
    solBefore: reports[0]!.solBefore,
    solAfter: reports[0]!.solAfter,
    minSolThreshold: cfg.refillMinSol,
    action: topAction,
    signatures: reports.flatMap((r) => r.signatures),
    details: reports.flatMap((r) =>
      r.details.map((d) => `[${r.relayerPubkey.slice(0, 6)}] ${d}`),
    ),
    payers: reports,
  }
}
