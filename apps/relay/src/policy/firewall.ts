import type { FullViewingKey } from '@audren/sdk'
import {
  ASSET_MODE_PRIVATE,
  ASSET_MODE_PUBLIC,
  AUDREN_PROGRAM_ID,
  AUDREN_PROGRAM_ID_STR,
  TAG_DEPOSIT,
  TAG_EXEC_VIA_ESCROW,
  TAG_TRANSACT,
  VK_ID_DEFAULT,
  derivePoolPda,
  deriveVaultAuthPda,
  extractNullifierPdas,
  parseExecEscrowMeta,
  parseTransactMeta,
  verifyShieldedCm2RelayerFee,
  type ParsedExecEscrowMeta,
  type ParsedPageAccounts,
  type ParsedTransactMeta,
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
  RelayInstructionPayload,
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

export interface ShieldedCm2Fee {
  mint: string
  amount: bigint
}

export interface ValidatedAudrenInstruction {
  opKind: AudrenOpKind
  tag: number
  ixData: Uint8Array
  decodedAccounts: SolanaAccountMeta[]
  nullifiers: string[]
  poolId: number
  outLaneId: number
  outputCount: number
  pages: ParsedPageAccounts
  transactMeta: ParsedTransactMeta | null
  execMeta: ParsedExecEscrowMeta | null
  shieldedCm2Fee: ShieldedCm2Fee | null
}

export interface FirewallVerdict {
  /** True when submitted via `body.instructions` (1..=4 private `Transact` merge batch). */
  isBatch: boolean
  /** All validated Audren instructions (length 1 for single-ix, length 1..=4 for batch). */
  audrenInstructions: ValidatedAudrenInstruction[]
  opKind: AudrenOpKind
  tag: number
  ixData: Uint8Array
  decodedAccounts: SolanaAccountMeta[]
  /** All unique nullifier PDAs across every instruction in the submission. */
  nullifiers: string[]
  poolId: number
  outLaneId: number
  pages: ParsedPageAccounts
  setupAtas: ValidatedSetupAta[]
  preInstructions: SolanaInstruction[]
  transactMeta: ParsedTransactMeta | null
  execMeta: ParsedExecEscrowMeta | null
  /** Mode 1 (Private Transfer): first verified shielded `cm2` fee note (for single-ix callers). */
  shieldedCm2Fee: ShieldedCm2Fee | null
  /** Mode 1 (Single or Batch Private Transfer): all verified shielded `cm2` fee notes across the submission. */
  shieldedCm2Fees: ShieldedCm2Fee[]
  /** Mode 2/3 SPL/Token-2022 fee ATA watched during `simulateV1Transaction`. */
  watchedRelayerFeeAta: string | null
  watchedRelayerFeeMint: string | null
  /** Mode 2 `WITHDRAW_FLAG_UNWRAP_WSOL` native SOL lamports paid directly to `relayerPubkey`. */
  nativeSolFeeToRelayer: bigint
}

export const MAX_BATCH_INSTRUCTIONS = 4
const MAX_PRE_INSTRUCTIONS = 3
const MAX_PRE_IX_DATA_BYTES = 512
const MAX_PRE_IX_ACCOUNTS = 24

function validateSingleAudrenPayload(
  payload: RelayInstructionPayload,
  relayerPubkey: Uint8Array,
  relayerB58: string,
  pool0Pda: Uint8Array,
  relayerFvk: FullViewingKey | null,
  requirePrivateTransact: boolean,
  labelPrefix = '',
): ValidatedAudrenInstruction {
  if (
    !payload ||
    typeof payload.instructionDataB64 !== 'string' ||
    payload.instructionDataB64.length === 0 ||
    payload.instructionDataB64.length > 5_400
  ) {
    throw new FirewallError(`${labelPrefix}Invalid or missing instructionDataB64`, 400)
  }
  if (!Array.isArray(payload.accounts) || payload.accounts.length < 12 || payload.accounts.length > 62) {
    throw new FirewallError(
      `${labelPrefix}Invalid Audren account count (${payload.accounts?.length ?? 0})`,
      400,
    )
  }

  let ixData: Uint8Array
  try {
    ixData = fromBase64(payload.instructionDataB64)
  } catch {
    throw new FirewallError(`${labelPrefix}instructionDataB64 must be valid base64`, 400)
  }
  if (ixData.length === 0) {
    throw new FirewallError(`${labelPrefix}Audren instruction payload is empty`, 400)
  }

  const tag = ixData[0]!
  if (tag === TAG_DEPOSIT) {
    throw new FirewallError(
      `${labelPrefix}Deposits (Deposit Tag 3) are naturally public and are not sponsored by the relay. Sign deposits directly with your wallet.`,
      400,
    )
  }
  if (requirePrivateTransact) {
    if (tag !== TAG_TRANSACT) {
      throw new FirewallError(
        `${labelPrefix}Multi-instruction batches permit ONLY private Transact (Tag 5) instructions; got tag ${tag}.`,
        400,
      )
    }
  } else if (tag !== TAG_TRANSACT && tag !== TAG_EXEC_VIA_ESCROW) {
    throw new FirewallError(
      `${labelPrefix}Audren instruction tag ${tag} is not permitted on this relay. Allowed: Transact (5), ExecViaEscrow (6).`,
      400,
    )
  }
  if (ixData.length < 378) {
    throw new FirewallError(`${labelPrefix}Audren instruction payload too short`, 400)
  }

  const decodedAccounts: SolanaAccountMeta[] = payload.accounts.map((a, idx) => {
    if (!a || typeof a.pubkey !== 'string') {
      throw new FirewallError(`${labelPrefix}Missing pubkey at accounts[${idx}]`, 400)
    }
    let pubkey: Uint8Array
    try {
      pubkey = base58Decode(a.pubkey)
    } catch {
      throw new FirewallError(`${labelPrefix}Invalid base58 pubkey at accounts[${idx}]`, 400)
    }
    if (pubkey.length !== 32) {
      throw new FirewallError(`${labelPrefix}Account #${idx} is not a 32-byte Solana pubkey`, 400)
    }
    if (idx === 0) {
      if (!bytesEqual(pubkey, relayerPubkey) || !a.isSigner || !a.isWritable) {
        throw new FirewallError(
          `${labelPrefix}accounts[0] must be relayer ${relayerB58} (writable signer); got ${a.pubkey}`,
          400,
        )
      }
    } else if (a.isSigner) {
      throw new FirewallError(
        `${labelPrefix}Unexpected extra signer at accounts[${idx}] (${a.pubkey}). Relay transactions must have ONLY the relayer as signer.`,
        400,
      )
    }
    return { pubkey, isSigner: Boolean(a.isSigner), isWritable: Boolean(a.isWritable) }
  })

  if (!bytesEqual(decodedAccounts[1]!.pubkey, pool0Pda)) {
    throw new FirewallError(
      `${labelPrefix}accounts[1] must be canonical Audren Pool #0 (${base58Encode(pool0Pda)})`,
      400,
    )
  }

  const nullifiers = extractNullifierPdas(tag, decodedAccounts)
  if (nullifiers.length === 0) {
    throw new FirewallError(`${labelPrefix}Could not extract nullifier PDA from Audren accounts`, 400)
  }
  if (nullifiers.length === 2 && nullifiers[0] === nullifiers[1]) {
    throw new FirewallError(`${labelPrefix}Duplicate nullifier PDA within instruction`, 400)
  }

  const transactMeta = tag === TAG_TRANSACT ? parseTransactMeta(ixData, decodedAccounts) : null
  if (tag === TAG_TRANSACT && !transactMeta) {
    throw new FirewallError(`${labelPrefix}Malformed Transact (Tag 5) instruction or accounts`, 400)
  }
  if (transactMeta) {
    if (transactMeta.poolId !== 0) {
      throw new FirewallError(`${labelPrefix}Only canonical Pool #0 is permitted on this relay`, 400)
    }
    if (transactMeta.vkId !== VK_ID_DEFAULT) {
      throw new FirewallError(
        `${labelPrefix}Unsupported vk_id ${transactMeta.vkId} in Transact (expected ${VK_ID_DEFAULT})`,
        400,
      )
    }
    if (requirePrivateTransact && transactMeta.assetMode !== ASSET_MODE_PRIVATE) {
      throw new FirewallError(
        `${labelPrefix}Multi-instruction batches permit ONLY private Transact (ASSET_MODE_PRIVATE) instructions; public outflows cannot be mixed into a batch.`,
        400,
      )
    }
  }

  const execMeta = tag === TAG_EXEC_VIA_ESCROW ? parseExecEscrowMeta(ixData, decodedAccounts) : null
  if (tag === TAG_EXEC_VIA_ESCROW && !execMeta) {
    throw new FirewallError(
      `${labelPrefix}Malformed ExecViaEscrow (Tag 6) instruction or accounts`,
      400,
    )
  }
  if (execMeta) {
    if (execMeta.poolId !== 0) {
      throw new FirewallError(`${labelPrefix}Only canonical Pool #0 is permitted on this relay`, 400)
    }
    if (execMeta.vkId !== VK_ID_DEFAULT) {
      throw new FirewallError(
        `${labelPrefix}Unsupported vk_id ${execMeta.vkId} in ExecViaEscrow (expected ${VK_ID_DEFAULT})`,
        400,
      )
    }
  }

  const opKind: AudrenOpKind = execMeta ? 'exec_escrow' : transactMeta!.opKind
  const poolId = execMeta ? execMeta.poolId : transactMeta!.poolId
  const outLaneId = execMeta ? execMeta.outLaneId : transactMeta!.outLaneId
  const outputCount = execMeta ? execMeta.outputCount : transactMeta!.outputCount
  const pageSrc = execMeta ?? transactMeta!
  const pages: ParsedPageAccounts = {
    outSub: pageSrc.outSub,
    outRoot: pageSrc.outRoot,
    outMemo: pageSrc.outMemo,
    nfPage: pageSrc.nfPage,
    nextSub: pageSrc.nextSub,
    nextMemo: pageSrc.nextMemo,
    nextNf: pageSrc.nextNf,
  }

  let shieldedCm2Fee: ShieldedCm2Fee | null = null
  if (transactMeta && transactMeta.assetMode === ASSET_MODE_PRIVATE && relayerFvk) {
    shieldedCm2Fee = verifyShieldedCm2RelayerFee(relayerFvk, transactMeta)
  }

  return {
    opKind,
    tag,
    ixData,
    decodedAccounts,
    nullifiers,
    poolId,
    outLaneId,
    outputCount,
    pages,
    transactMeta,
    execMeta,
    shieldedCm2Fee,
  }
}

/**
 * Strict Zero-Trust Audren v1 Instruction Firewall.
 *
 * Guarantees the relayer fee-payer keypair can ONLY ever sign:
 *   - Audren Tag 5 (`Transact` — private transfer or public SPL/Token-2022/WSOL-unwrap withdraw,
 *     enforcing `vk_id === 0` and canonical ATAs), OR
 *   - Multi-instruction batch of 1..=4 private `Transact` (`ASSET_MODE_PRIVATE`, `vk_id === 0`)
 *     merges packed atomically into one Solana Transaction v1 (`0x81`, <= 4,096 B), OR
 *   - Audren Tag 6 (`ExecViaEscrow` — SPL/Token-2022 atomic DeFi CPI with optional
 *     `EXEC_FLAG_FEE_ON_OUTPUT`, `vk_id === 0`, and canonical vault/escrow ATAs) on canonical Pool #0
 *     (`audren_pool`), plus strictly allowlisted zero-signer `preInstructions` immediately before Tag 6.
 *   - Explicitly rejects Tag 3 (`Deposit`) — deposits are public and signed directly by the depositor.
 *   - Enforces `accounts[0] === relayerPubkey` (writable signer) and ZERO other signers.
 *   - Verifies all 3 relayer fee channels:
 *       1. Mode 1 Private Transfer (single or batch): shielded `cm2` fee note(s) verified via read-only `FullViewingKey`
 *       2. Mode 2 Public Withdraw: `WITHDRAW_FLAG_UNWRAP_WSOL` -> `relayerPubkey`, or SPL/T22 -> canonical relayer ATA
 *       3. Mode 3 `ExecViaEscrow`: input-leg or `EXEC_FLAG_FEE_ON_OUTPUT` output-leg SPL/T22 fee -> canonical relayer ATA
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

  const relayerB58 = base58Encode(relayerPubkey)
  const pool0Pda = derivePoolPda(0).address
  const vaultAuthPda = deriveVaultAuthPda(0).address
  const vaultAuthB58 = base58Encode(vaultAuthPda)
  const relayerWsolAta = deriveAta(relayerPubkey, CLASSIC_TOKEN_PROGRAM_ID, WSOL_MINT)

  // Multi-instruction private `Transact` merge batch path (`body.instructions`: 1..=4 entries)
  if (body.instructions !== undefined) {
    if (body.instructionDataB64 !== undefined || body.accounts !== undefined) {
      throw new FirewallError(
        'Cannot combine batched instructions with top-level instructionDataB64/accounts',
        400,
      )
    }
    if (!Array.isArray(body.instructions) || body.instructions.length === 0) {
      throw new FirewallError('instructions batch must contain 1 to 4 private Transact instructions', 400)
    }
    if (body.instructions.length > MAX_BATCH_INSTRUCTIONS) {
      throw new FirewallError(
        `instructions batch supports at most ${MAX_BATCH_INSTRUCTIONS} private Transact instructions (got ${body.instructions.length})`,
        400,
      )
    }
    if (Array.isArray(body.preInstructions) && body.preInstructions.length > 0) {
      throw new FirewallError(
        'preInstructions are only permitted immediately before a single ExecViaEscrow (Tag 6)',
        400,
      )
    }
    if (Array.isArray(body.setupAtas) && body.setupAtas.length > 0) {
      throw new FirewallError(
        'setupAtas are not permitted for private Transact batches',
        400,
      )
    }

    const audrenInstructions: ValidatedAudrenInstruction[] = []
    const allNullifiers: string[] = []
    const seenNullifiers = new Set<string>()
    const shieldedCm2Fees: ShieldedCm2Fee[] = []

    for (let i = 0; i < body.instructions.length; i++) {
      const validated = validateSingleAudrenPayload(
        body.instructions[i]!,
        relayerPubkey,
        relayerB58,
        pool0Pda,
        relayerFvk,
        true,
        `instructions[${i}]: `,
      )
      for (const nf of validated.nullifiers) {
        if (seenNullifiers.has(nf)) {
          throw new FirewallError(
            `Duplicate nullifier PDA (${nf}) across multi-instruction batch at instructions[${i}]`,
            400,
          )
        }
        seenNullifiers.add(nf)
        allNullifiers.push(nf)
      }
      if (validated.shieldedCm2Fee) {
        shieldedCm2Fees.push(validated.shieldedCm2Fee)
      }
      audrenInstructions.push(validated)
    }

    const first = audrenInstructions[0]!
    return {
      isBatch: true,
      audrenInstructions,
      opKind: 'transfer',
      tag: TAG_TRANSACT,
      ixData: first.ixData,
      decodedAccounts: first.decodedAccounts,
      nullifiers: allNullifiers,
      poolId: first.poolId,
      outLaneId: first.outLaneId,
      pages: first.pages,
      setupAtas: [],
      preInstructions: [],
      transactMeta: first.transactMeta,
      execMeta: null,
      shieldedCm2Fee: shieldedCm2Fees[0] ?? null,
      shieldedCm2Fees,
      watchedRelayerFeeAta: null,
      watchedRelayerFeeMint: null,
      nativeSolFeeToRelayer: 0n,
    }
  }

  // Single-instruction path (`instructionDataB64` + `accounts`)
  const single = validateSingleAudrenPayload(
    {
      instructionDataB64: body.instructionDataB64 as string,
      accounts: body.accounts as RelayInstructionPayload['accounts'],
    },
    relayerPubkey,
    relayerB58,
    pool0Pda,
    relayerFvk,
    false,
  )

  const { tag, decodedAccounts, transactMeta, execMeta } = single

  // Validate strictly allowlisted zero-signer DeFi refresh cranks (`preInstructions`, Tag 6 only).
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
        'preInstructions are only permitted immediately before ExecViaEscrow (Tag 6)',
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

  // Validate setupAtas strictly bound to active ExecViaEscrow or SPL/T22 Transact Withdraw accounts
  const setupAtas: ValidatedSetupAta[] = []
  const seenSetupAtas = new Set<string>()
  if (Array.isArray(body.setupAtas) && body.setupAtas.length > 0) {
    if (body.setupAtas.length > 6) {
      throw new FirewallError('setupAtas supports at most 6 entries', 400)
    }
    const isTokenWithdraw =
      transactMeta !== null &&
      transactMeta.assetMode === ASSET_MODE_PUBLIC &&
      !transactMeta.unwrapWsol

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
      const isWithdrawRecipientAta =
        isTokenWithdraw &&
        ataB58 === transactMeta!.recipientAccount &&
        req.mint === transactMeta!.mint &&
        req.tokenProgram === transactMeta!.tokenProgram
      const isRelayerWithdrawFeeAta =
        isTokenWithdraw &&
        transactMeta!.relayerFee > 0n &&
        bytesEqual(ownerBytes, relayerPubkey) &&
        ataB58 === transactMeta!.feeRecipient &&
        req.mint === transactMeta!.mint &&
        req.tokenProgram === transactMeta!.tokenProgram
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
          'Relayer setupAtas only allowed for active ExecViaEscrow vault/escrow ATAs, referenced relayer fee ATA, or SPL/Token-2022 Withdraw recipient ATA',
          400,
        )
      }
      seenSetupAtas.add(ataB58)
      setupAtas.push({ owner: ownerBytes, mint: mintBytes, tokenProgram: tpBytes, ata })
    }
  }

  // Verify the 3 relayer fee channels
  let watchedRelayerFeeAta: string | null = null
  let watchedRelayerFeeMint: string | null = null
  let nativeSolFeeToRelayer = 0n

  if (transactMeta) {
    if (transactMeta.assetMode === ASSET_MODE_PUBLIC && transactMeta.relayerFee > 0n) {
      // Mode 2: Public Transact Withdraw (atomic WSOL unwrap -> native SOL, or SPL/Token-2022 -> relayer ATA)
      if (transactMeta.unwrapWsol) {
        if (transactMeta.feeRecipient !== relayerB58) {
          throw new FirewallError(
            `Withdraw (unwrapWsol) relayer_fee > 0 requires relayer_fee_recipient to match relayer (${relayerB58})`,
            400,
          )
        }
        nativeSolFeeToRelayer = transactMeta.relayerFee
      } else if (transactMeta.mint && transactMeta.tokenProgram) {
        const expectedFeeAta = base58Encode(
          deriveAta(
            relayerPubkey,
            base58Decode(transactMeta.tokenProgram),
            base58Decode(transactMeta.mint),
          ),
        )
        if (transactMeta.feeRecipient !== expectedFeeAta) {
          throw new FirewallError(
            `SPL/Token-2022 Withdraw relayer_fee > 0 requires relayer_fee_recipient to match relayer ATA (${expectedFeeAta})`,
            400,
          )
        }
        watchedRelayerFeeAta = expectedFeeAta
        watchedRelayerFeeMint = transactMeta.mint
      }
    }
  } else if (execMeta) {
    // Mode 3: ExecViaEscrow (SPL/Token-2022 input-leg fee OR `EXEC_FLAG_FEE_ON_OUTPUT` output-leg fee)
    if (execMeta.relayerFee > 0n) {
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
    isBatch: false,
    audrenInstructions: [single],
    opKind: single.opKind,
    tag: single.tag,
    ixData: single.ixData,
    decodedAccounts: single.decodedAccounts,
    nullifiers: single.nullifiers,
    poolId: single.poolId,
    outLaneId: single.outLaneId,
    pages: single.pages,
    setupAtas,
    preInstructions,
    transactMeta: single.transactMeta,
    execMeta: single.execMeta,
    shieldedCm2Fee: single.shieldedCm2Fee,
    shieldedCm2Fees: single.shieldedCm2Fee ? [single.shieldedCm2Fee] : [],
    watchedRelayerFeeAta,
    watchedRelayerFeeMint,
    nativeSolFeeToRelayer,
  }
}

export { AUDREN_PROGRAM_ID }
