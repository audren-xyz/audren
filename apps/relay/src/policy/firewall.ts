import type { FullViewingKey } from '@audren/sdk'
import {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_SOL,
  ASSET_MODE_SPL,
  AUDREN_PROGRAM_ID,
  AUDREN_PROGRAM_ID_STR,
  TAG_DEPOSIT_SOL,
  TAG_DEPOSIT_SPL,
  TAG_EXEC_VIA_ESCROW,
  TAG_JOINSPLIT,
  derivePoolPda,
  deriveSolVaultPda,
  deriveVaultAuthPda,
  extractNullifierPdas,
  parseExecEscrowMeta,
  parseJoinSplitMeta,
  verifyShieldedCm2RelayerFee,
  type ParsedExecEscrowMeta,
  type ParsedJoinSplitMeta,
} from '../solana/audren'
import {
  ASSOCIATED_TOKEN_PROGRAM_ID_STR,
  CLASSIC_TOKEN_PROGRAM_ID,
  CLASSIC_TOKEN_PROGRAM_ID_STR,
  SYSTEM_PROGRAM_ID_STR,
  TOKEN_2022_PROGRAM_ID_STR,
  WSOL_MINT,
  base58Decode,
  base58Encode,
  bytesEqual,
  deriveAta,
  fromBase64,
} from '../solana/codec'
import type {
  AudrenOpKind,
  RelaySubmitRequest,
  SolanaAccountMeta,
  SolanaInstruction,
} from '../types'

export class FirewallError extends Error {
  readonly status: number
  constructor(message: string, status = 400) {
    super(message)
    this.name = 'FirewallError'
    this.status = status
  }
}

export interface ValidatedSetupAta {
  owner: Uint8Array
  mint: Uint8Array
  tokenProgram: Uint8Array
  ata: Uint8Array
}

export interface FirewallVerdict {
  opKind: AudrenOpKind
  tag: number
  ixData: Uint8Array
  decodedAccounts: SolanaAccountMeta[]
  nullifiers: string[]
  outLaneId: number
  setupAtas: ValidatedSetupAta[]
  preInstructions: SolanaInstruction[]
  joinSplitMeta: ParsedJoinSplitMeta | null
  execMeta: ParsedExecEscrowMeta | null
  /** Mode 1 (Private Transfer): shielded `cm2` fee note verified via relayer read-only FVK. */
  shieldedCm2Fee: { mint: string; amount: bigint } | null
  /** Mode 2/3 SPL/Token-2022 fee ATA watched during `simulateV1Transaction`. */
  watchedRelayerFeeAta: string | null
  watchedRelayerFeeMint: string | null
  /** Mode 2/3 Native SOL fee paid directly to `relayerPubkey` (Native SOL or `unwrap_wsol`). */
  nativeSolFeeToRelayer: bigint
}

const MAX_PRE_INSTRUCTIONS = 3
const MAX_PRE_IX_DATA_BYTES = 512
const MAX_PRE_IX_ACCOUNTS = 24

/**
 * Strict Zero-Trust Audren Instruction Firewall.
 *
 * Guarantees the relayer fee-payer keypair can ONLY ever sign:
 *   - Audren Tag 6 (`JoinSplit` — private transfer or public SOL/SPL/WSOL-unwrap withdraw)
 *     and Tag 7 (`ExecViaEscrow` — atomic DeFi CPI with optional `EXEC_FLAG_FEE_ON_OUTPUT`)
 *     on canonical Pool #0 (`audren_v2_pool`).
 *   - Explicitly rejects Tag 3 (`DepositSol`) and Tag 4 (`DepositSpl`) — deposits are public
 *     and signed directly by the depositor's wallet.
 *   - Enforces `accounts[0] === relayerPubkey` (writable signer) and ZERO other signers.
 *   - Enforces strict `preInstructions` allowlist (Tag 7 only, zero signers, never references
 *     relayer or Audren custody accounts) and strict `setupAtas` allowlist.
 *   - Verifies all 3 relayer fee channels:
 *       1. Mode 1 Private Transfer: shielded `cm2` fee note verified via read-only `FullViewingKey`
 *       2. Mode 2 Public Withdraw: Native SOL / `unwrap_wsol` -> `relayerPubkey`, or SPL -> relayer ATA
 *       3. Mode 3 `ExecViaEscrow`: input-leg or `EXEC_FLAG_FEE_ON_OUTPUT` output-leg fee -> relayer
 */
export function validateRelaySubmission(
  body: RelaySubmitRequest,
  relayerPubkey: Uint8Array,
  allowedPreIxPrograms: Set<string>,
  relayerFvk: FullViewingKey | null = null,
): FirewallVerdict {
  if (!body || typeof body !== 'object') {
    throw new FirewallError('Invalid JSON request body', 400)
  }
  if (
    typeof body.instructionDataB64 !== 'string' ||
    body.instructionDataB64.length === 0 ||
    body.instructionDataB64.length > 5_400
  ) {
    throw new FirewallError('Invalid or missing instructionDataB64', 400)
  }
  if (!Array.isArray(body.accounts) || body.accounts.length < 12 || body.accounts.length > 62) {
    throw new FirewallError(`Invalid Audren account count (${body.accounts?.length ?? 0})`, 400)
  }

  let ixData: Uint8Array
  try {
    ixData = fromBase64(body.instructionDataB64)
  } catch {
    throw new FirewallError('instructionDataB64 must be valid base64', 400)
  }
  if (ixData.length < 378) {
    throw new FirewallError('Audren instruction payload too short', 400)
  }

  const tag = ixData[0]!
  if (tag === TAG_DEPOSIT_SOL || tag === TAG_DEPOSIT_SPL) {
    throw new FirewallError(
      'Deposits (DepositSol Tag 3 / DepositSpl Tag 4) are naturally public and are not sponsored by the relay. Sign deposits directly with your wallet.',
      400,
    )
  }
  if (tag !== TAG_JOINSPLIT && tag !== TAG_EXEC_VIA_ESCROW) {
    throw new FirewallError(
      `Audren instruction tag ${tag} is not permitted on this relay. Allowed: JoinSplit (6), ExecViaEscrow (7).`,
      400,
    )
  }

  const relayerB58 = base58Encode(relayerPubkey)
  const decodedAccounts: SolanaAccountMeta[] = body.accounts.map((a, idx) => {
    if (!a || typeof a.pubkey !== 'string') {
      throw new FirewallError(`Missing pubkey at accounts[${idx}]`, 400)
    }
    let pubkey: Uint8Array
    try {
      pubkey = base58Decode(a.pubkey)
    } catch {
      throw new FirewallError(`Invalid base58 pubkey at accounts[${idx}]`, 400)
    }
    if (pubkey.length !== 32) {
      throw new FirewallError(`Account #${idx} is not a 32-byte Solana pubkey`, 400)
    }
    if (idx === 0) {
      if (!bytesEqual(pubkey, relayerPubkey) || !a.isSigner || !a.isWritable) {
        throw new FirewallError(
          `accounts[0] must be relayer ${relayerB58} (writable signer); got ${a.pubkey}`,
          400,
        )
      }
    } else if (a.isSigner) {
      throw new FirewallError(
        `Unexpected extra signer at accounts[${idx}] (${a.pubkey}). Relay transactions must have ONLY the relayer as signer.`,
        400,
      )
    }
    return { pubkey, isSigner: Boolean(a.isSigner), isWritable: Boolean(a.isWritable) }
  })

  const pool0Pda = derivePoolPda(0).address
  const vaultAuthPda = deriveVaultAuthPda(0).address
  const vaultAuthB58 = base58Encode(vaultAuthPda)
  const solVaultPda = deriveSolVaultPda(0).address
  const relayerWsolAta = deriveAta(relayerPubkey, CLASSIC_TOKEN_PROGRAM_ID, WSOL_MINT)

  if (!bytesEqual(decodedAccounts[1]!.pubkey, pool0Pda)) {
    throw new FirewallError(
      `accounts[1] must be canonical Audren Pool #0 (${base58Encode(pool0Pda)})`,
      400,
    )
  }

  const nullifiers = extractNullifierPdas(tag, decodedAccounts)
  if (nullifiers.length === 0) {
    throw new FirewallError('Could not extract nullifier PDA from Audren accounts', 400)
  }

  const joinSplitMeta = tag === TAG_JOINSPLIT ? parseJoinSplitMeta(ixData, decodedAccounts) : null
  if (tag === TAG_JOINSPLIT && !joinSplitMeta) {
    throw new FirewallError('Malformed JoinSplit (Tag 6) instruction or accounts', 400)
  }
  if (joinSplitMeta && joinSplitMeta.poolId !== 0) {
    throw new FirewallError('Only canonical Pool #0 is permitted on this relay', 400)
  }

  const execMeta = tag === TAG_EXEC_VIA_ESCROW ? parseExecEscrowMeta(ixData, decodedAccounts) : null
  if (tag === TAG_EXEC_VIA_ESCROW && !execMeta) {
    throw new FirewallError('Malformed ExecViaEscrow (Tag 7) instruction or accounts', 400)
  }
  if (execMeta && execMeta.poolId !== 0) {
    throw new FirewallError('Only canonical Pool #0 is permitted on this relay', 400)
  }

  const opKind: AudrenOpKind = execMeta ? 'exec_escrow' : joinSplitMeta!.opKind
  const outLaneId = execMeta ? execMeta.outLaneId : joinSplitMeta!.outLaneId

  // Validate strictly allowlisted zero-signer DeFi refresh cranks (`preInstructions`, Tag 7 only).
  const FORBIDDEN_PRE_IX_PROGRAMS = new Set([
    AUDREN_PROGRAM_ID_STR,
    SYSTEM_PROGRAM_ID_STR,
    CLASSIC_TOKEN_PROGRAM_ID_STR,
    TOKEN_2022_PROGRAM_ID_STR,
    ASSOCIATED_TOKEN_PROGRAM_ID_STR,
  ])
  const relayerExecInAta =
    execMeta && execMeta.mintIn && execMeta.tokenProgIn
      ? deriveAta(relayerPubkey, base58Decode(execMeta.tokenProgIn), base58Decode(execMeta.mintIn))
      : null
  const relayerExecOutAta =
    execMeta && execMeta.mintOut && execMeta.tokenProgOut
      ? deriveAta(relayerPubkey, base58Decode(execMeta.tokenProgOut), base58Decode(execMeta.mintOut))
      : null

  const preInstructions: SolanaInstruction[] = []
  if (Array.isArray(body.preInstructions) && body.preInstructions.length > 0) {
    if (tag !== TAG_EXEC_VIA_ESCROW) {
      throw new FirewallError(
        'preInstructions are only permitted immediately before ExecViaEscrow (Tag 7)',
        400,
      )
    }
    if (body.preInstructions.length > MAX_PRE_INSTRUCTIONS) {
      throw new FirewallError(`At most ${MAX_PRE_INSTRUCTIONS} preInstructions are permitted`, 400)
    }
    for (let i = 0; i < body.preInstructions.length; i++) {
      const pre = body.preInstructions[i]
      if (!pre || typeof pre.programId !== 'string' || typeof pre.data !== 'string' || !Array.isArray(pre.accounts)) {
        throw new FirewallError(`Malformed preInstructions[${i}]`, 400)
      }
      if (FORBIDDEN_PRE_IX_PROGRAMS.has(pre.programId) || !allowedPreIxPrograms.has(pre.programId)) {
        throw new FirewallError(
          `preInstructions[${i}] program ${pre.programId} is not in the relay crank allowlist`,
          400,
        )
      }
      let progBytes: Uint8Array
      let dataBytes: Uint8Array
      try {
        progBytes = base58Decode(pre.programId)
        dataBytes = fromBase64(pre.data)
      } catch {
        throw new FirewallError(`Invalid encoding in preInstructions[${i}]`, 400)
      }
      if (progBytes.length !== 32 || dataBytes.length === 0 || dataBytes.length > MAX_PRE_IX_DATA_BYTES) {
        throw new FirewallError(`Invalid programId or data length in preInstructions[${i}]`, 400)
      }
      if (pre.accounts.length > MAX_PRE_IX_ACCOUNTS) {
        throw new FirewallError(`Too many accounts in preInstructions[${i}]`, 400)
      }
      const preAccounts: SolanaAccountMeta[] = pre.accounts.map((acc, j) => {
        if (!acc || typeof acc.pubkey !== 'string') {
          throw new FirewallError(`Missing pubkey at preInstructions[${i}].accounts[${j}]`, 400)
        }
        let pk: Uint8Array
        try {
          pk = base58Decode(acc.pubkey)
        } catch {
          throw new FirewallError(`Invalid pubkey at preInstructions[${i}].accounts[${j}]`, 400)
        }
        if (pk.length !== 32) {
          throw new FirewallError(`Invalid pubkey length at preInstructions[${i}].accounts[${j}]`, 400)
        }
        if (acc.isSigner) {
          throw new FirewallError(
            `preInstructions[${i}].accounts[${j}] must NOT require a signer`,
            400,
          )
        }
        if (
          bytesEqual(pk, relayerPubkey) ||
          bytesEqual(pk, pool0Pda) ||
          bytesEqual(pk, vaultAuthPda) ||
          bytesEqual(pk, solVaultPda) ||
          bytesEqual(pk, relayerWsolAta) ||
          (relayerExecInAta && bytesEqual(pk, relayerExecInAta)) ||
          (relayerExecOutAta && bytesEqual(pk, relayerExecOutAta))
        ) {
          throw new FirewallError(
            `preInstructions[${i}] cannot reference relayer, Audren custody, or fee accounts`,
            400,
          )
        }
        return { pubkey: pk, isSigner: false, isWritable: Boolean(acc.isWritable) }
      })
      preInstructions.push({ programId: progBytes, accounts: preAccounts, data: dataBytes })
    }
  }

  // Validate setupAtas strictly bound to active ExecViaEscrow or SPL JoinSplit Withdraw accounts
  const setupAtas: ValidatedSetupAta[] = []
  const seenSetupAtas = new Set<string>()
  if (Array.isArray(body.setupAtas) && body.setupAtas.length > 0) {
    if (body.setupAtas.length > 6) {
      throw new FirewallError('setupAtas supports at most 6 entries', 400)
    }
    const isSplWithdraw =
      joinSplitMeta !== null &&
      joinSplitMeta.assetMode === ASSET_MODE_SPL &&
      !joinSplitMeta.unwrapWsol

    for (const req of body.setupAtas) {
      if (
        !req ||
        (req.tokenProgram !== CLASSIC_TOKEN_PROGRAM_ID_STR &&
          req.tokenProgram !== TOKEN_2022_PROGRAM_ID_STR)
      ) {
        throw new FirewallError('Unsupported tokenProgram in setupAtas', 400)
      }
      let ownerBytes: Uint8Array
      let mintBytes: Uint8Array
      let tpBytes: Uint8Array
      try {
        ownerBytes = base58Decode(req.owner)
        mintBytes = base58Decode(req.mint)
        tpBytes = base58Decode(req.tokenProgram)
      } catch {
        throw new FirewallError('Invalid base58 pubkey in setupAtas', 400)
      }
      if (ownerBytes.length !== 32 || mintBytes.length !== 32 || tpBytes.length !== 32) {
        throw new FirewallError('Invalid pubkey length in setupAtas', 400)
      }

      const ata = deriveAta(ownerBytes, tpBytes, mintBytes)
      const ataB58 = base58Encode(ata)
      if (seenSetupAtas.has(ataB58)) continue

      const matchesExecMintAndProg =
        execMeta !== null &&
        ((execMeta.mintIn !== null &&
          req.mint === execMeta.mintIn &&
          req.tokenProgram === execMeta.tokenProgIn) ||
          (execMeta.mintOut !== null &&
            req.mint === execMeta.mintOut &&
            req.tokenProgram === execMeta.tokenProgOut))
      const isAllowedPda =
        execMeta !== null &&
        (req.owner === vaultAuthB58 || req.owner === execMeta.escrowPda) &&
        matchesExecMintAndProg
      const isWithdrawRecipientAta =
        isSplWithdraw &&
        ataB58 === joinSplitMeta!.recipientAccount &&
        req.mint === joinSplitMeta!.mint &&
        req.tokenProgram === joinSplitMeta!.tokenProgram
      const isRelayerWithdrawFeeAta =
        isSplWithdraw &&
        joinSplitMeta!.relayerFee > 0n &&
        bytesEqual(ownerBytes, relayerPubkey) &&
        ataB58 === joinSplitMeta!.feeRecipient &&
        req.mint === joinSplitMeta!.mint &&
        req.tokenProgram === joinSplitMeta!.tokenProgram
      const isRelayerExecFeeAta =
        execMeta !== null &&
        bytesEqual(ownerBytes, relayerPubkey) &&
        matchesExecMintAndProg &&
        ((execMeta.relayerFee > 0n && ataB58 === execMeta.feeRecipient) ||
          decodedAccounts
            .slice(execMeta.routerAccountsStartIdx)
            .some((a) => bytesEqual(a.pubkey, ata)))

      if (
        !isAllowedPda &&
        !isWithdrawRecipientAta &&
        !isRelayerWithdrawFeeAta &&
        !isRelayerExecFeeAta
      ) {
        throw new FirewallError(
          'Relayer setupAtas only allowed for active ExecViaEscrow vault/escrow ATAs, referenced relayer fee ATA, or SPL Withdraw recipient ATA',
          400,
        )
      }
      seenSetupAtas.add(ataB58)
      setupAtas.push({ owner: ownerBytes, mint: mintBytes, tokenProgram: tpBytes, ata })
    }
  }

  // Verify the 3 relayer fee channels
  let shieldedCm2Fee: { mint: string; amount: bigint } | null = null
  let watchedRelayerFeeAta: string | null = null
  let watchedRelayerFeeMint: string | null = null
  let nativeSolFeeToRelayer = 0n

  if (joinSplitMeta) {
    if (joinSplitMeta.assetMode === ASSET_MODE_PRIVATE) {
      // Mode 1: Private shielded transfer — verify optional `cm2` fee note using read-only FVK!
      if (relayerFvk) {
        shieldedCm2Fee = verifyShieldedCm2RelayerFee(relayerFvk, joinSplitMeta)
      }
    } else if (joinSplitMeta.relayerFee > 0n) {
      // Mode 2: Public JoinSplit Withdraw (Native SOL, atomic WSOL unwrap, or SPL/Token-2022)
      if (joinSplitMeta.assetMode === ASSET_MODE_SOL || joinSplitMeta.unwrapWsol) {
        if (joinSplitMeta.feeRecipient !== relayerB58) {
          throw new FirewallError(
            `Withdraw relayer_fee > 0 requires relayer_fee_recipient to match relayer (${relayerB58})`,
            400,
          )
        }
        nativeSolFeeToRelayer = joinSplitMeta.relayerFee
      } else if (joinSplitMeta.mint && joinSplitMeta.tokenProgram) {
        const expectedFeeAta = base58Encode(
          deriveAta(
            relayerPubkey,
            base58Decode(joinSplitMeta.tokenProgram),
            base58Decode(joinSplitMeta.mint),
          ),
        )
        if (joinSplitMeta.feeRecipient !== expectedFeeAta) {
          throw new FirewallError(
            `SPL Withdraw relayer_fee > 0 requires relayer_fee_recipient to match relayer ATA (${expectedFeeAta})`,
            400,
          )
        }
        watchedRelayerFeeAta = expectedFeeAta
        watchedRelayerFeeMint = joinSplitMeta.mint
      }
    }
  } else if (execMeta) {
    // Mode 3: ExecViaEscrow (input-leg fee OR `EXEC_FLAG_FEE_ON_OUTPUT` output-leg fee)
    if (execMeta.relayerFee > 0n) {
      if (execMeta.feeIsNativeSol) {
        if (execMeta.feeRecipient !== relayerB58) {
          throw new FirewallError(
            `ExecViaEscrow native SOL relayer_fee > 0 requires relayer_fee_recipient to match relayer (${relayerB58})`,
            400,
          )
        }
        nativeSolFeeToRelayer = execMeta.relayerFee
      } else if (execMeta.feeMint && execMeta.feeTokenProg) {
        const expectedFeeAta = base58Encode(
          deriveAta(
            relayerPubkey,
            base58Decode(execMeta.feeTokenProg),
            base58Decode(execMeta.feeMint),
          ),
        )
        if (execMeta.feeRecipient !== expectedFeeAta) {
          throw new FirewallError(
            `ExecViaEscrow relayer_fee > 0 requires relayer_fee_recipient to match relayer ATA (${expectedFeeAta})`,
            400,
          )
        }
        watchedRelayerFeeAta = expectedFeeAta
        watchedRelayerFeeMint = execMeta.feeMint
      }
    } else {
      const routerSlice = decodedAccounts.slice(execMeta.routerAccountsStartIdx)
      if (relayerExecOutAta && routerSlice.some((a) => bytesEqual(a.pubkey, relayerExecOutAta))) {
        watchedRelayerFeeAta = base58Encode(relayerExecOutAta)
        watchedRelayerFeeMint = execMeta.mintOut
      } else if (relayerExecInAta && routerSlice.some((a) => bytesEqual(a.pubkey, relayerExecInAta))) {
        watchedRelayerFeeAta = base58Encode(relayerExecInAta)
        watchedRelayerFeeMint = execMeta.mintIn
      }
    }
  }

  return {
    opKind,
    tag,
    ixData,
    decodedAccounts,
    nullifiers,
    outLaneId,
    setupAtas,
    preInstructions,
    joinSplitMeta,
    execMeta,
    shieldedCm2Fee,
    watchedRelayerFeeAta,
    watchedRelayerFeeMint,
    nativeSolFeeToRelayer,
  }
}

export { AUDREN_PROGRAM_ID }
