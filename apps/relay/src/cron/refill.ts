import { ed25519 } from '@noble/curves/ed25519.js'
import { getAggregatorAdapter, quoteWithSelection } from '../aggregators/registry'
import { getRelayerSecretsB64, type Env, type RelayPolicyConfig } from '../env'
import {
  CLASSIC_TOKEN_PROGRAM_ID,
  CLASSIC_TOKEN_PROGRAM_ID_STR,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID_STR,
  WSOL_MINT,
  WSOL_MINT_STR,
  base58Decode,
  base58Encode,
  buildAndSignV1Transaction,
  buildCloseTokenAccountIx,
  buildCreateAtaIdempotentIx,
  bytesEqual,
  decodeRelayerSecret,
  deriveAta,
  fromBase64,
  readSplTokenAccountAmount,
  toBase64,
} from '../solana/codec'
import {
  applyToken2022FeeHaircut,
  fetchAllOwnedTokenAccounts,
  fetchBalance,
  fetchCurrentEpoch,
  fetchMintMetasWithData,
  fetchMultipleAccountsWithContext,
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
  const wsolAtaB58 = base58Encode(wsolAta)

  // Dynamically discover ALL token accounts owned by the relayer (Classic SPL + Token-2022)
  const ownedAccounts = await fetchAllOwnedTokenAccounts(rpcUrl, relayerB58)
  const nonZero = ownedAccounts.filter((a) => a.amount > 0n)

  // Step 1: Unwrap existing canonical WSOL ATA balance if >= 0.005 SOL
  // Strictly restrict to canonical `wsolAtaB58` so permissionlessly planted non-ATA WSOL accounts
  // cannot shadow or DoS WSOL unwrapping.
  const wsolEntry = nonZero.find(
    (a) =>
      a.mint === WSOL_MINT_STR &&
      a.tokenProgram === CLASSIC_TOKEN_PROGRAM_ID_STR &&
      a.ata === wsolAtaB58,
  )
  if (wsolEntry && wsolEntry.amount >= 5_000_000n) {
    const [bh, preLamports] = await Promise.all([
      rpcCall<{ value: { blockhash: string } }>(rpcUrl, 'getLatestBlockhash', [
        { commitment: 'confirmed' },
      ]),
      fetchBalance(rpcUrl, relayerB58),
    ])
    const ixs: SolanaInstruction[] = [
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

  // Step 2: Inspect decimals + USD prices ONLY for canonical relayer ATAs of vetted `SELF_PAY_FEE_MINTS`
  const isCanonicalRelayerAta = (a: {
    ata: string
    mint: string
    tokenProgram: string
  }): boolean => {
    if (
      a.tokenProgram !== CLASSIC_TOKEN_PROGRAM_ID_STR &&
      a.tokenProgram !== TOKEN_2022_PROGRAM_ID_STR
    ) {
      return false
    }
    try {
      const tokenProgramBytes = base58Decode(a.tokenProgram)
      const mintBytes = base58Decode(a.mint)
      if (tokenProgramBytes.length !== 32 || mintBytes.length !== 32) return false
      return a.ata === base58Encode(deriveAta(relayerPubkey, tokenProgramBytes, mintBytes))
    } catch {
      return false
    }
  }
  const otherTokens = nonZero.filter(
    (a) =>
      a.mint !== WSOL_MINT_STR &&
      cfg.selfPayFeeMints.has(a.mint) &&
      isCanonicalRelayerAta(a),
  )
  if (otherTokens.length > 0) {
    const uniqueMints = [...new Set(otherTokens.map((a) => a.mint))]
    const [mintMetasWithData, prices] = await Promise.all([
      fetchMintMetasWithData(rpcUrl, uniqueMints),
      fetchMintPricesUsd(env, [WSOL_MINT_STR, ...uniqueMints]),
    ])
    const solUsd = prices[WSOL_MINT_STR]
    if (!solUsd || !Number.isFinite(solUsd) || solUsd <= 0) {
      details.push('Skipped fee token refill swaps: live WSOL USD price unavailable')
    } else {
      const needsEpoch = uniqueMints.some((m) => {
        const entry = mintMetasWithData[m]
        return (
          entry?.meta.tokenProgram === TOKEN_2022_PROGRAM_ID_STR &&
          entry.rawBytes !== null &&
          entry.rawBytes.byteLength > 166
        )
      })
      const currentEpoch = needsEpoch ? await fetchCurrentEpoch(rpcUrl) : 0n
      const parseThreshold = (raw: string): bigint => (/^\d+$/.test(raw) ? BigInt(raw) : 0n)

      // Precompute ALL relayer-owned token accounts: every canonical fee ATA (Classic SPL & Token-2022)
      // across `selfPayFeeMints` plus every fetched owned token account from `getTokenAccountsByOwner`.
      const allRelayerTokenAccounts = new Set<string>()
      const canonicalSelfPayAtas = new Set<string>()
      for (const owned of ownedAccounts) {
        allRelayerTokenAccounts.add(owned.ata)
      }
      for (const feeMint of cfg.selfPayFeeMints) {
        try {
          const mintBytes = base58Decode(feeMint)
          if (mintBytes.length !== 32) continue
          const classicFeeAta = base58Encode(
            deriveAta(relayerPubkey, CLASSIC_TOKEN_PROGRAM_ID, mintBytes),
          )
          const t22FeeAta = base58Encode(deriveAta(relayerPubkey, TOKEN_2022_PROGRAM_ID, mintBytes))
          allRelayerTokenAccounts.add(classicFeeAta)
          allRelayerTokenAccounts.add(t22FeeAta)
          canonicalSelfPayAtas.add(classicFeeAta)
          canonicalSelfPayAtas.add(t22FeeAta)
        } catch {
          // Ignore malformed mint entry in config
        }
      }

      for (const acc of otherTokens) {
        if (currentSol >= cfg.refillMinSol * 1.5) break
        const entry = mintMetasWithData[acc.mint]
        const meta = entry?.meta
        const price = prices[acc.mint]
        if (
          !meta ||
          !meta.isValidMint ||
          meta.hasUnsafeSelfPayExt ||
          !price ||
          !Number.isFinite(price) ||
          price <= 0
        ) {
          continue
        }
        // Account for 1x Token-2022 TransferFeeConfig deducted when transferring `acc.amount`
        // into the DEX pool so 400..=500 bps fee mints are not permanently skipped by the 95%
        // oracle floor (while still quoting the full gross balance `acc.amount` to swap).
        const { netAmount: netAmountForValuation } = applyToken2022FeeHaircut({
          tokenProgram: meta.tokenProgram,
          mintData: entry?.rawBytes ?? null,
          currentEpoch,
          grossAmount: acc.amount,
          hops: 1,
        })
        const usdVal = (Number(netAmountForValuation) / Math.pow(10, meta.decimals)) * price
        if (usdVal < cfg.refillMinTokenUsd) {
          details.push(
            `Skipping ${acc.mint.slice(0, 6)}… ($${usdVal.toFixed(2)} < $${cfg.refillMinTokenUsd})`,
          )
          continue
        }

        const minSolOutLamports = BigInt(Math.floor((usdVal / solUsd) * 1e9 * 0.95))
        if (minSolOutLamports <= 0n) {
          details.push(
            `Skipped refill swap for ${acc.mint.slice(0, 6)}…: computed oracle min SOL floor <= 0`,
          )
          continue
        }

        try {
          let winner: Awaited<ReturnType<typeof quoteWithSelection>>['winner'] | null = null
          try {
            const directRes = await quoteWithSelection(env, cfg, cfg.defaultAggregator, {
              inputMint: acc.mint,
              outputMint: WSOL_MINT_STR,
              amount: acc.amount.toString(),
              slippageBps: 100,
              onlyDirectRoutes: true,
              maxAccounts: 24,
              platformFeeBps: 0,
              escrowPubkey: relayerB58,
            })
            winner = directRes.winner
          } catch {
            winner = null
          }

          if (!winner || parseThreshold(winner.otherAmountThreshold) < minSolOutLamports) {
            // Direct pool may be thin/skewed (e.g. EURC/cbBTC -> WSOL); fall back to multi-hop routes
            const multiRes = await quoteWithSelection(env, cfg, cfg.defaultAggregator, {
              inputMint: acc.mint,
              outputMint: WSOL_MINT_STR,
              amount: acc.amount.toString(),
              slippageBps: 100,
              onlyDirectRoutes: false,
              maxAccounts: 28,
              platformFeeBps: 0,
              escrowPubkey: relayerB58,
            })
            winner = multiRes.winner
          }

          const quotedMinOut = parseThreshold(winner.otherAmountThreshold)
          if (quotedMinOut < minSolOutLamports) {
            details.push(
              `Skipped refill swap for ${acc.mint.slice(0, 6)}…: quoted min SOL output ${quotedMinOut.toString()} < 95% oracle floor ${minSolOutLamports.toString()}`,
            )
            continue
          }

          const adapter = getAggregatorAdapter(winner.provider)
          const built = await adapter.swapInstructions(env, {
            quoteResponse: winner.rawQuote,
            escrowPubkey: relayerB58,
            inputMint: acc.mint,
            outputMint: WSOL_MINT_STR,
          })
          if (!cfg.auditedSwapRouterPrograms.has(built.swapInstruction.programId)) {
            details.push(
              `Skipped refill swap for ${acc.mint.slice(0, 6)}…: router program ${built.swapInstruction.programId} is not in AUDITED_SWAP_ROUTER_PROGRAMS`,
            )
            continue
          }

          // Cross-ATA drain protection: forbid any other relayer-owned token account or extra signer
          // inside `built.swapInstruction.accounts`, and watch all non-zero `otherOwnedAtas` during
          // pinned pre-flight simulation.
          const otherOwnedAtas = new Set<string>(allRelayerTokenAccounts)
          otherOwnedAtas.delete(acc.ata)
          otherOwnedAtas.delete(wsolAtaB58)

          const forbiddenOtherAta = built.swapInstruction.accounts.find((a) =>
            otherOwnedAtas.has(a.pubkey),
          )
          if (forbiddenOtherAta) {
            details.push(
              `Skipped refill swap for ${acc.mint.slice(0, 6)}…: swap instruction references other relayer-owned token account ${forbiddenOtherAta.pubkey}`,
            )
            continue
          }
          const unexpectedSigner = built.swapInstruction.accounts.find(
            (a) => a.isSigner && a.pubkey !== relayerB58,
          )
          if (unexpectedSigner) {
            details.push(
              `Skipped refill swap for ${acc.mint.slice(0, 6)}…: swap instruction marks unexpected signer ${unexpectedSigner.pubkey}`,
            )
            continue
          }

          // Prioritize canonical `selfPayFeeMints` non-zero ATAs first, then remaining non-zero
          // `otherOwnedAtas` (capped at 59 extra accounts so `simulateTransaction` stays <= 62 watch addrs
          // alongside `[relayerB58, wsolAtaB58, acc.ata]`).
          const nonZeroOtherCanonical: string[] = []
          const nonZeroOtherExtra: string[] = []
          const seenWatchedOther = new Set<string>()
          for (const owned of nonZero) {
            if (!otherOwnedAtas.has(owned.ata) || seenWatchedOther.has(owned.ata)) continue
            seenWatchedOther.add(owned.ata)
            if (canonicalSelfPayAtas.has(owned.ata)) {
              nonZeroOtherCanonical.push(owned.ata)
            } else {
              nonZeroOtherExtra.push(owned.ata)
            }
          }
          const watchedOtherAtas = [...nonZeroOtherCanonical, ...nonZeroOtherExtra].slice(0, 59)
          const watchAddresses = [relayerB58, wsolAtaB58, acc.ata, ...watchedOtherAtas]

          const [bh, initialPreCtx] = await Promise.all([
            rpcCall<{ value: { blockhash: string } }>(rpcUrl, 'getLatestBlockhash', [
              { commitment: 'confirmed' },
            ]),
            fetchMultipleAccountsWithContext(rpcUrl, watchAddresses),
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
            computeUnitLimit: Math.min(1_400_000, Math.max(600_000, built.computeUnitLimit)),
            priorityFeeLamports: 20_000n,
          })

          const MAX_SLOT_PIN_ATTEMPTS = 3
          let preCtx = initialPreCtx
          let sim = await simulateV1Transaction(rpcUrl, signed.wireBytes, watchAddresses)
          if (
            !sim.err &&
            (preCtx.slot === null || sim.slot === null || preCtx.slot !== sim.slot)
          ) {
            for (let attempt = 0; attempt < MAX_SLOT_PIN_ATTEMPTS; attempt++) {
              const [pinnedPreCtx, pinnedSim] = await Promise.all([
                fetchMultipleAccountsWithContext(rpcUrl, watchAddresses, {
                  commitment: 'processed',
                }),
                simulateV1Transaction(rpcUrl, signed.wireBytes, watchAddresses, {
                  commitment: 'processed',
                }),
              ])
              preCtx = pinnedPreCtx
              sim = pinnedSim
              if (
                sim.err ||
                (preCtx.slot !== null && sim.slot !== null && preCtx.slot === sim.slot)
              ) {
                break
              }
            }
          }

          if (sim.err) {
            details.push(
              `Skipped refill swap for ${acc.mint.slice(0, 6)}…: pre-flight simulation failed (${JSON.stringify(sim.err)})`,
            )
            continue
          }
          if (preCtx.slot === null || sim.slot === null || preCtx.slot !== sim.slot) {
            details.push(
              `Skipped refill swap for ${acc.mint.slice(0, 6)}…: slot mismatch or missing slot context between pre-read (${preCtx.slot}) and simulation (${sim.slot})`,
            )
            continue
          }

          // Post-simulation input-ATA invariant check: verify `acc.ata` was not closed, hijacked in
          // owner/mint/delegate/state/close_authority/length/lamports, or debited by MORE than the
          // quoted `acc.amount` (defeats live over-debit skim & persistent ATA hijack).
          const preInputAta = preCtx.accounts[2]
          const postInputAta = sim.accounts[2]
          let inputAtaViolation: string | null = null
          if (!preInputAta || !postInputAta) {
            inputAtaViolation = `input fee ATA ${acc.ata} missing or closed in simulation`
          } else if (
            postInputAta.owner !== preInputAta.owner ||
            preInputAta.bytes.length < 72 ||
            postInputAta.bytes.length < 72 ||
            postInputAta.bytes.length !== preInputAta.bytes.length ||
            !bytesEqual(preInputAta.bytes.subarray(0, 64), postInputAta.bytes.subarray(0, 64))
          ) {
            inputAtaViolation = `input fee ATA ${acc.ata} changed owner, length, or token metadata`
          } else if (
            preInputAta.bytes.length >= 165 &&
            (!bytesEqual(preInputAta.bytes.subarray(72, 108), postInputAta.bytes.subarray(72, 108)) ||
              preInputAta.bytes[108] !== postInputAta.bytes[108] ||
              !bytesEqual(preInputAta.bytes.subarray(121, 129), postInputAta.bytes.subarray(121, 129)) ||
              !bytesEqual(preInputAta.bytes.subarray(129, 165), postInputAta.bytes.subarray(129, 165)))
          ) {
            inputAtaViolation = `input fee ATA ${acc.ata} changed delegate, state, or close authority`
          } else if (postInputAta.lamports < preInputAta.lamports) {
            inputAtaViolation = `input fee ATA ${acc.ata} lamports decreased (${preInputAta.lamports} -> ${postInputAta.lamports})`
          } else {
            const preInAmt = readSplTokenAccountAmount(preInputAta.bytes)
            const postInAmt = readSplTokenAccountAmount(postInputAta.bytes)
            const inputDebited = preInAmt > postInAmt ? preInAmt - postInAmt : 0n
            if (inputDebited > acc.amount) {
              inputAtaViolation = `input fee ATA ${acc.ata} over-debited (${inputDebited.toString()} > quoted ${acc.amount.toString()})`
            }
          }
          if (inputAtaViolation) {
            details.push(
              `Skipped refill swap for ${acc.mint.slice(0, 6)}…: input-ATA invariant violated (${inputAtaViolation})`,
            )
            continue
          }

          // Post-simulation cross-ATA invariant check: verify NONE of the watched non-zero
          // `otherOwnedAtas` had their SPL/Token-2022 amount decrease or
          // owner/length/delegate/delegated_amount/state/close_authority/lamports tampered.
          let crossAtaViolation: string | null = null
          for (let i = 0; i < watchedOtherAtas.length; i++) {
            const watchedAta = watchedOtherAtas[i]!
            const preOther = preCtx.accounts[3 + i]
            const postOther = sim.accounts[3 + i]
            if (!preOther || !postOther) {
              crossAtaViolation = `watched relayer ATA ${watchedAta} missing or closed in simulation`
              break
            }
            if (
              postOther.owner !== preOther.owner ||
              preOther.bytes.length < 72 ||
              postOther.bytes.length < 72 ||
              postOther.bytes.length !== preOther.bytes.length ||
              !bytesEqual(preOther.bytes.subarray(0, 64), postOther.bytes.subarray(0, 64))
            ) {
              crossAtaViolation = `watched relayer ATA ${watchedAta} changed owner, length, or token metadata`
              break
            }
            const preAmt = readSplTokenAccountAmount(preOther.bytes)
            const postAmt = readSplTokenAccountAmount(postOther.bytes)
            if (postAmt < preAmt) {
              crossAtaViolation = `watched relayer ATA ${watchedAta} balance decreased (${preAmt.toString()} -> ${postAmt.toString()})`
              break
            }
            if (preOther.bytes.length >= 165) {
              if (
                !bytesEqual(preOther.bytes.subarray(72, 108), postOther.bytes.subarray(72, 108)) ||
                preOther.bytes[108] !== postOther.bytes[108] ||
                !bytesEqual(preOther.bytes.subarray(121, 129), postOther.bytes.subarray(121, 129)) ||
                !bytesEqual(preOther.bytes.subarray(129, 165), postOther.bytes.subarray(129, 165))
              ) {
                crossAtaViolation = `watched relayer ATA ${watchedAta} changed delegate, state, or close authority`
                break
              }
            }
            if (postOther.lamports < preOther.lamports) {
              crossAtaViolation = `watched relayer ATA ${watchedAta} lamports decreased (${preOther.lamports} -> ${postOther.lamports})`
              break
            }
          }
          if (crossAtaViolation) {
            details.push(
              `Skipped refill swap for ${acc.mint.slice(0, 6)}…: cross-ATA invariant violated (${crossAtaViolation})`,
            )
            continue
          }

          const preRelayerAcc = preCtx.accounts[0]
          const preWsolAcc = preCtx.accounts[1]
          const postRelayerAcc = sim.accounts[0]
          const postWsolAcc = sim.accounts[1]
          const preSwapLamports = BigInt(preRelayerAcc?.lamports ?? 0)
          const preWsolLamports = preWsolAcc ? BigInt(preWsolAcc.lamports) : 0n
          const postSwapLamports = postRelayerAcc ? BigInt(postRelayerAcc.lamports) : 0n
          // Ix[3] re-creates an empty 0-balance WSOL ATA; credit only its rent reserve so an
          // already-initialized empty WSOL ATA cancels rent cleanly while 100% of pre-existing WSOL
          // or unsynced lamports in `wsolAta` is deducted from the simulated swap gain.
          const postWsolRentLamports =
            postWsolAcc &&
            postWsolAcc.owner === CLASSIC_TOKEN_PROGRAM_ID_STR &&
            readSplTokenAccountAmount(postWsolAcc.bytes) === 0n &&
            BigInt(postWsolAcc.lamports) <= 3_000_000n
              ? BigInt(postWsolAcc.lamports)
              : 0n
          const netSwapGainLamports =
            postSwapLamports + postWsolRentLamports - preSwapLamports - preWsolLamports
          const minNetLamports = minSolOutLamports > 100_000n ? minSolOutLamports - 100_000n : 0n

          if (
            !postRelayerAcc ||
            postSwapLamports <= preSwapLamports ||
            netSwapGainLamports < minNetLamports
          ) {
            details.push(
              `Skipped refill swap for ${acc.mint.slice(0, 6)}…: simulated net SOL gain ${netSwapGainLamports.toString()} < oracle floor ${minNetLamports.toString()}`,
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
          const rawErr = err instanceof Error ? err.message : String(err)
          const safeErr = rawErr.replace(/https?:\/\/\S+/gi, '[redacted-url]').slice(0, 200)
          details.push(`Refill swap failed for ${acc.mint.slice(0, 6)}…: ${safeErr}`)
        }
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
