import { ed25519 } from '@noble/curves/ed25519.js'
import { getAggregatorAdapter, quoteWithSelection } from '../aggregators/registry'
import type { Env, RelayPolicyConfig } from '../env'
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
  fetchAllOwnedTokenAccounts,
  fetchBalance,
  fetchMintMetas,
  rpcCall,
  simulateV1Transaction,
  waitForConfirmation,
} from '../solana/rpc'
import type { SolanaInstruction } from '../types'
import { fetchMintPricesUsd } from '../policy/pricing'

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
    const bh = await rpcCall<{ value: { blockhash: string } }>(rpcUrl, 'getLatestBlockhash', [
      { commitment: 'confirmed' },
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
    const sig = await rpcCall<string>(rpcUrl, 'sendTransaction', [
      toBase64(signed.wireBytes),
      { encoding: 'base64', preflightCommitment: 'confirmed', maxRetries: 3 },
    ])
    await waitForConfirmation(rpcUrl, sig)
    signatures.push(sig)
    details.push(`Unwrapped ${(Number(wsolEntry.amount) / 1e9).toFixed(4)} WSOL → native SOL (${sig})`)
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
        const bh = await rpcCall<{ value: { blockhash: string } }>(rpcUrl, 'getLatestBlockhash', [
          { commitment: 'confirmed' },
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
        const sim = await simulateV1Transaction(rpcUrl, signed.wireBytes, [])
        if (sim.err) {
          details.push(
            `Skipped refill swap for ${acc.mint.slice(0, 6)}…: pre-flight simulation failed (${JSON.stringify(sim.err)})`,
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
