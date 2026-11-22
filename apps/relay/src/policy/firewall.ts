import {
  AUDREN_PROGRAM_ID,
  AUDREN_PROGRAM_ID_STR,
  TAG_DEPOSIT,
  TAG_EXEC_VIA_ESCROW,
  TAG_MERGE,
  TAG_TRANSFER,
  TAG_WITHDRAW,
  derivePoolPda,
  deriveSolVaultPda,
  deriveVaultAuthPda,
  extractNullifierPdas,
  opKindFromTag,
  parseExecEscrowMeta,
  parseWithdrawMeta,
  type ParsedExecEscrowMeta,
  type ParsedWithdrawMeta,
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
  writesOutput: boolean
  setupAtas: ValidatedSetupAta[]
  preInstructions: SolanaInstruction[]
  execMeta: ParsedExecEscrowMeta | null
  withdrawMeta: ParsedWithdrawMeta | null
  /** Relayer fee SPL/Token-2022 ATA to watch during simulation (for Tag 5 native/router fee or SPL Tag 6 native fee). */
  watchedRelayerFeeAta: string | null
  /** Mint of `watchedRelayerFeeAta` (if SPL/Token-2022 fee). */
  watchedRelayerFeeMint: string | null
  /** True when Withdraw pays native SOL `relayer_fee > 0` directly to `relayerPubkey` (Native SOL or `unwrap_wsol`). */
  nativeSolFeeToRelayer: bigint
}

const MAX_PRE_INSTRUCTIONS = 3
const MAX_PRE_IX_DATA_BYTES = 512
const MAX_PRE_IX_ACCOUNTS = 24

/**
 * Strict Zero-Trust Audren Instruction Firewall.
 *
 * Guarantees the relayer keypair can ONLY ever sign:
 *   - Audren Tag 3 (`Transfer`), Tag 4 (`Merge`), Tag 5 (`ExecViaEscrow`), Tag 6 (`Withdraw`) on canonical Pool #0
 *   - Explicitly rejects Tag 2 (`Deposit` — deposits are naturally public, signed by depositor)
 *   - Enforces `accounts[0] === relayerPubkey` (writable signer) and ZERO other signers
 *   - Enforces strict `preInstructions` allowlist: ONLY zero-signer refresh cranks from
 *     `allowedPreIxPrograms` immediately preceding Tag 5 (`ExecViaEscrow`), unconditionally
 *     forbidding `relayerPubkey` and relayer/Audren custody accounts anywhere in `preInstructions`
 *   - Enforces strict `setupAtas` allowlist bound to the active instruction's mints/token programs
 */
export function validateRelaySubmission(
  body: RelaySubmitRequest,
  relayerPubkey: Uint8Array,
  allowedPreIxPrograms: Set<string>,
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
  if (!Array.isArray(body.accounts) || body.accounts.length < 7 || body.accounts.length > 62) {
    throw new FirewallError(`Invalid Audren account count (${body.accounts?.length ?? 0})`, 400)
  }

  let ixData: Uint8Array
  try {
    ixData = fromBase64(body.instructionDataB64)
  } catch {
    throw new FirewallError('instructionDataB64 must be valid base64', 400)
  }
  if (ixData.length < 24) {
    throw new FirewallError('Audren instruction payload too short', 400)
  }

  const tag = ixData[0]!
  if (tag === TAG_DEPOSIT) {
    throw new FirewallError(
      'Deposits (Tag 2 / Go Private) are naturally public and are not sponsored by relay.audren.xyz. Sign deposits directly with your wallet.',
      400,
    )
  }
  const opKind = opKindFromTag(tag)
  if (!opKind) {
    throw new FirewallError(
      `Audren instruction tag ${tag} is not permitted on this relay. Allowed: Transfer (3), Merge (4), ExecViaEscrow (5), Withdraw (6).`,
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

  const execMeta = tag === TAG_EXEC_VIA_ESCROW ? parseExecEscrowMeta(ixData, decodedAccounts) : null
  if (tag === TAG_EXEC_VIA_ESCROW && !execMeta) {
    throw new FirewallError('Malformed ExecViaEscrow (Tag 5) instruction or accounts', 400)
  }

  const withdrawMeta = tag === TAG_WITHDRAW ? parseWithdrawMeta(ixData, decodedAccounts) : null
  if (tag === TAG_WITHDRAW && !withdrawMeta) {
    throw new FirewallError('Malformed Withdraw (Tag 6) instruction or accounts', 400)
  }

  const writesOutput =
    tag === TAG_TRANSFER ||
    tag === TAG_MERGE ||
    tag === TAG_EXEC_VIA_ESCROW ||
    (withdrawMeta !== null && withdrawMeta.hasChange)

  // Validate strictly allowlisted zero-signer DeFi refresh cranks (`preInstructions`).
  // CRITICAL: Because Solana grants `relayerPubkey` transaction-level signer+writable privileges,
  // `relayerPubkey` MUST NEVER appear anywhere in `preInstructions[i].accounts` (even as read-only!).
  const FORBIDDEN_PRE_IX_PROGRAMS = new Set([
    AUDREN_PROGRAM_ID_STR,
    SYSTEM_PROGRAM_ID_STR,
    CLASSIC_TOKEN_PROGRAM_ID_STR,
    TOKEN_2022_PROGRAM_ID_STR,
    ASSOCIATED_TOKEN_PROGRAM_ID_STR,
  ])
  const relayerExecInAta = execMeta
    ? deriveAta(relayerPubkey, base58Decode(execMeta.tokenProgIn), base58Decode(execMeta.mintIn))
    : null
  const relayerExecOutAta = execMeta
    ? deriveAta(relayerPubkey, base58Decode(execMeta.tokenProgOut), base58Decode(execMeta.mintOut))
    : null

  const preInstructions: SolanaInstruction[] = []
  if (Array.isArray(body.preInstructions) && body.preInstructions.length > 0) {
    if (tag !== TAG_EXEC_VIA_ESCROW) {
      throw new FirewallError(
        'preInstructions are only permitted immediately before ExecViaEscrow (Tag 5)',
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
        if (bytesEqual(pk, relayerPubkey)) {
          throw new FirewallError(
            `preInstructions[${i}] cannot reference the relayer pubkey`,
            400,
          )
        }
        if (
          bytesEqual(pk, pool0Pda) ||
          bytesEqual(pk, vaultAuthPda) ||
          bytesEqual(pk, solVaultPda) ||
          bytesEqual(pk, relayerWsolAta) ||
          (relayerExecInAta && bytesEqual(pk, relayerExecInAta)) ||
          (relayerExecOutAta && bytesEqual(pk, relayerExecOutAta))
        ) {
          throw new FirewallError(
            `preInstructions[${i}] cannot reference Audren custody or relayer fee accounts`,
            400,
          )
        }
        return { pubkey: pk, isSigner: false, isWritable: Boolean(acc.isWritable) }
      })
      preInstructions.push({ programId: progBytes, accounts: preAccounts, data: dataBytes })
    }
  }

  const setupAtas: ValidatedSetupAta[] = []
  const seenSetupAtas = new Set<string>()
  if (Array.isArray(body.setupAtas) && body.setupAtas.length > 0) {
    if (body.setupAtas.length > 6) {
      throw new FirewallError('setupAtas supports at most 6 entries', 400)
    }
    const isSplWithdraw =
      withdrawMeta !== null &&
      !withdrawMeta.isNativeSol &&
      !withdrawMeta.unwrapWsol &&
      decodedAccounts.length >= 14

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
        ((req.mint === execMeta.mintIn && req.tokenProgram === execMeta.tokenProgIn) ||
          (req.mint === execMeta.mintOut && req.tokenProgram === execMeta.tokenProgOut))
      const isAllowedPda =
        execMeta !== null &&
        (req.owner === vaultAuthB58 || req.owner === execMeta.escrowPda) &&
        matchesExecMintAndProg
      // SPL Withdraw layout: [7] fee_recipient, [8] vault_auth, [9] mint, [10] vault_ata, [11] recipient_ata, [12] token_prog
      const isWithdrawRecipientAta =
        isSplWithdraw &&
        bytesEqual(ata, decodedAccounts[11]!.pubkey) &&
        bytesEqual(mintBytes, decodedAccounts[9]!.pubkey) &&
        bytesEqual(tpBytes, decodedAccounts[12]!.pubkey)
      const isRelayerWithdrawFeeAta =
        isSplWithdraw &&
        withdrawMeta!.relayerFee > 0n &&
        bytesEqual(ownerBytes, relayerPubkey) &&
        bytesEqual(ata, decodedAccounts[7]!.pubkey) &&
        bytesEqual(mintBytes, decodedAccounts[9]!.pubkey) &&
        bytesEqual(tpBytes, decodedAccounts[12]!.pubkey)
      const isRelayerExecFeeAta =
        execMeta !== null &&
        bytesEqual(ownerBytes, relayerPubkey) &&
        matchesExecMintAndProg &&
        ((execMeta.relayerFee > 0n && ataB58 === execMeta.feeRecipientAta) ||
          decodedAccounts.slice(16).some((a) => bytesEqual(a.pubkey, ata)))

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

  // Detect relayer fee channel to watch during `simulateV1Transaction` and reject spoofed fee recipients:
  //   1. Tag 5 (`ExecViaEscrow`): native `[15] fee_recipient_ata` (in `mintIn` or `mintOut`) OR
  //      aggregator-route fee ATA inside `action_accounts` (`accounts[16..]`).
  //   2. Tag 6 (`Withdraw`):
  //      - Native SOL or `unwrap_wsol`: native SOL lamports directly to `[7] fee_recipient === relayerPubkey`!
  //      - SPL Withdraw: `[7] fee_recipient === relayerFeeAta` for `withdrawMeta.mint`!
  let watchedRelayerFeeAta: string | null = null
  let watchedRelayerFeeMint: string | null = null
  let nativeSolFeeToRelayer = 0n

  if (execMeta) {
    const feeMintBytes = base58Decode(execMeta.feeMint)
    const feeTpBytes = base58Decode(execMeta.feeTokenProg)
    const expectedNativeFeeAta = base58Encode(deriveAta(relayerPubkey, feeTpBytes, feeMintBytes))
    if (execMeta.relayerFee > 0n) {
      if (execMeta.feeRecipientAta !== expectedNativeFeeAta) {
        throw new FirewallError(
          `ExecViaEscrow relayer_fee > 0 requires fee_recipient_ata to match relayer ATA (${expectedNativeFeeAta})`,
          400,
        )
      }
      watchedRelayerFeeAta = expectedNativeFeeAta
      watchedRelayerFeeMint = execMeta.feeMint
    } else {
      // Check aggregator-embedded fee ATA in action_accounts (`accounts[16..]`) on output or input mint
      if (relayerExecOutAta && decodedAccounts.slice(16).some((a) => bytesEqual(a.pubkey, relayerExecOutAta))) {
        watchedRelayerFeeAta = base58Encode(relayerExecOutAta)
        watchedRelayerFeeMint = execMeta.mintOut
      } else if (relayerExecInAta && decodedAccounts.slice(16).some((a) => bytesEqual(a.pubkey, relayerExecInAta))) {
        watchedRelayerFeeAta = base58Encode(relayerExecInAta)
        watchedRelayerFeeMint = execMeta.mintIn
      }
    }
  } else if (withdrawMeta && withdrawMeta.relayerFee > 0n) {
    if (withdrawMeta.isNativeSol || withdrawMeta.unwrapWsol) {
      if (withdrawMeta.feeRecipient !== relayerB58) {
        throw new FirewallError(
          `Withdraw relayer_fee > 0 requires fee_recipient to match relayer wallet (${relayerB58})`,
          400,
        )
      }
      nativeSolFeeToRelayer = withdrawMeta.relayerFee
    } else if (withdrawMeta.mint && withdrawMeta.tokenProgram) {
      const expectedFeeAta = base58Encode(
        deriveAta(
          relayerPubkey,
          base58Decode(withdrawMeta.tokenProgram),
          base58Decode(withdrawMeta.mint),
        ),
      )
      if (withdrawMeta.feeRecipient !== expectedFeeAta) {
        throw new FirewallError(
          `SPL Withdraw relayer_fee > 0 requires fee_recipient to match relayer ATA (${expectedFeeAta})`,
          400,
        )
      }
      watchedRelayerFeeAta = expectedFeeAta
      watchedRelayerFeeMint = withdrawMeta.mint
    }
  }

  return {
    opKind,
    tag,
    ixData,
    decodedAccounts,
    nullifiers,
    writesOutput,
    setupAtas,
    preInstructions,
    execMeta,
    withdrawMeta,
    watchedRelayerFeeAta,
    watchedRelayerFeeMint,
    nativeSolFeeToRelayer,
  }
}

export { AUDREN_PROGRAM_ID }
