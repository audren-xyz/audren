import {
  AUDREN_PROGRAM_ID,
  TAG_DEPOSIT,
  TAG_MERGE,
  TAG_SWAP_VIA_ROUTER,
  TAG_TRANSFER,
  TAG_WITHDRAW,
  extractNullifierPdas,
  isAudrenVaultOrEscrowOwner,
  opKindFromTag,
  parseSwapMeta,
} from '../solana/audren'
import {
  CLASSIC_TOKEN_PROGRAM_ID_STR,
  TOKEN_2022_PROGRAM_ID_STR,
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
  swapMeta: ReturnType<typeof parseSwapMeta>
  /** If this Tag 5 swap includes the relayer's own output-mint fee ATA in router accounts. */
  relayerFeeAtaInRouter: string | null
}

/**
 * Strict Zero-Trust Audren Instruction Firewall.
 *
 * Guarantees the relayer keypair can ONLY ever sign:
 *   - Audren Tag 3 (Transfer), Tag 4 (Merge), Tag 5 (SwapViaRouter), Tag 6 (Withdraw)
 *   - Explicitly rejects Tag 2 (Deposit / Go Private — naturally public, never sponsored)
 *   - Enforces `accounts[0] === relayerPubkey` (writable signer) and ZERO other signers
 *   - Enforces strict `setupAtas` allowlist: ONLY Audren vault_auth, swap_escrow shards (0..15),
 *     relayer swap fee ATA for `mintOut`, or exact SPL Withdraw recipient ATA (`accounts[10]`)
 *
 * Note: Zero hardcoded cost estimates — exact lamport cost and exact fee revenue are
 * measured dynamically via Solana RPC `simulateTransaction` before any lamport is spent.
 */
export function validateRelaySubmission(
  body: RelaySubmitRequest,
  relayerPubkey: Uint8Array,
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
  if (ixData.length < 32) {
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
      `Audren instruction tag ${tag} is not permitted on this relay. Allowed: Transfer (3), Merge (4), SwapViaRouter (5), Withdraw (6).`,
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

  const nullifiers = extractNullifierPdas(tag, decodedAccounts)
  if (nullifiers.length === 0) {
    throw new FirewallError('Could not extract nullifier PDA from Audren accounts', 400)
  }

  const swapMeta = tag === TAG_SWAP_VIA_ROUTER ? parseSwapMeta(ixData, decodedAccounts) : null
  if (tag === TAG_SWAP_VIA_ROUTER && !swapMeta) {
    throw new FirewallError('Malformed SwapViaRouter (Tag 5) instruction or accounts', 400)
  }

  const writesOutput =
    tag === TAG_TRANSFER ||
    tag === TAG_MERGE ||
    tag === TAG_SWAP_VIA_ROUTER ||
    (tag === TAG_WITHDRAW && ixData.length >= 4 && ixData[3] !== 0)

  const setupAtas: ValidatedSetupAta[] = []
  if (Array.isArray(body.setupAtas) && body.setupAtas.length > 0) {
    if (body.setupAtas.length > 5) {
      throw new FirewallError('setupAtas supports at most 5 entries', 400)
    }
    const isSplWithdraw =
      tag === TAG_WITHDRAW && ixData.length >= 3 && ixData[2] === 0 && decodedAccounts.length >= 12

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
      const isAllowedPda = isAudrenVaultOrEscrowOwner(req.owner, 0)
      const isWithdrawRecipientAta =
        isSplWithdraw &&
        bytesEqual(ata, decodedAccounts[10]!.pubkey) &&
        bytesEqual(mintBytes, decodedAccounts[8]!.pubkey) &&
        bytesEqual(tpBytes, decodedAccounts[11]!.pubkey)
      const isRelayerSwapFeeAta =
        swapMeta !== null &&
        bytesEqual(ownerBytes, relayerPubkey) &&
        req.mint === swapMeta.mintOut

      if (!isAllowedPda && !isWithdrawRecipientAta && !isRelayerSwapFeeAta) {
        throw new FirewallError(
          'Relayer setupAtas only allowed for Audren vault/escrow PDAs, relayer swap fee ATA, or SPL Withdraw recipient ATA',
          400,
        )
      }

      setupAtas.push({ owner: ownerBytes, mint: mintBytes, tokenProgram: tpBytes, ata })
    }
  }

  let relayerFeeAtaInRouter: string | null = null
  if (swapMeta) {
    const outMintBytes = base58Decode(swapMeta.mintOut)
    const outTpBytes = base58Decode(swapMeta.tokenProgOut)
    const expectedFeeAta = deriveAta(relayerPubkey, outTpBytes, outMintBytes)
    const expectedFeeAtaB58 = base58Encode(expectedFeeAta)
    const inRouterAccounts = decodedAccounts
      .slice(15)
      .some((a) => bytesEqual(a.pubkey, expectedFeeAta))
    if (inRouterAccounts) {
      relayerFeeAtaInRouter = expectedFeeAtaB58
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
    swapMeta,
    relayerFeeAtaInRouter,
  }
}

export { AUDREN_PROGRAM_ID }
