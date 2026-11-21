/**
 * Browser Wallet Discovery, Signing & Transaction Compilation via `@solana/kit` (anza-xyz/kit)
 * + Wallet Standard (`@wallet-standard/app` & `@solana/wallet-standard-features`).
 *
 * Works natively with Phantom, Solflare, Backpack, Coinbase, Jupiter Wallet, and any
 * Wallet Standard compliant Solana wallet — zero legacy `@solana/web3.js` dependencies.
 */

import {
  AccountRole,
  address,
  appendTransactionMessageInstructions,
  compileTransaction,
  compressTransactionMessageUsingAddressLookupTables,
  createTransactionMessage,
  getTransactionEncoder,
  pipe,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
  type Address,
  type AddressesByLookupTableAddress,
  type Blockhash,
  type Instruction,
} from '@solana/kit'
import { getWallets } from '@wallet-standard/app'
import { SOLANA_DEVNET_CHAIN, SOLANA_MAINNET_CHAIN } from '@solana/wallet-standard-chains'
import {
  SolanaSignMessage,
  SolanaSignTransaction,
  type SolanaSignMessageFeature,
  type SolanaSignTransactionFeature,
} from '@solana/wallet-standard-features'

type Wallet = ReturnType<ReturnType<typeof getWallets>['get']>[number]
type WalletAccount = Wallet['accounts'][number]
import {
  base58Decode,
  base58Encode,
  concatBytes,
  toBase64,
  u32le,
  u64le,
  utf8,
  type SolanaInstruction,
} from './audren-crypto'

export type SolanaCluster = 'mainnet' | 'devnet'

export interface DiscoveredSolanaWallet {
  id: string
  name: string
  icon: string
  wallet: Wallet
  supportsSignMessage: boolean
  supportsSignTransaction: boolean
}

export interface ConnectedSolanaWallet {
  name: string
  icon: string
  address: string
  pubkeyBytes: Uint8Array
  wallet: Wallet
  account: WalletAccount
}

const COMPUTE_BUDGET_PROGRAM_ID = base58Decode('ComputeBudget111111111111111111111111111111')

function isSolanaWallet(w: Wallet): boolean {
  const hasConnect = 'standard:connect' in w.features
  const hasSolanaChain = w.chains.some((c) => c.startsWith('solana:'))
  const hasSignTx = SolanaSignTransaction in w.features
  return hasConnect && hasSolanaChain && hasSignTx
}

function toDiscovered(w: Wallet): DiscoveredSolanaWallet {
  return {
    id: `${w.name}:${w.version}`,
    name: w.name,
    icon: w.icon,
    wallet: w,
    supportsSignMessage: SolanaSignMessage in w.features,
    supportsSignTransaction: SolanaSignTransaction in w.features,
  }
}

function listSolanaWallets(): DiscoveredSolanaWallet[] {
  if (typeof window === 'undefined') return []
  const seen = new Set<string>()
  const out: DiscoveredSolanaWallet[] = []
  for (const w of getWallets().get()) {
    if (!isSolanaWallet(w)) continue
    const key = w.name.toLowerCase()
    if (seen.has(key)) continue
    seen.add(key)
    out.push(toDiscovered(w))
  }
  return out
}

export function subscribeSolanaWallets(
  onChange: (wallets: DiscoveredSolanaWallet[]) => void,
): () => void {
  if (typeof window === 'undefined') return () => {}
  const api = getWallets()
  onChange(listSolanaWallets())
  const offReg = api.on('register', () => onChange(listSolanaWallets()))
  const offUnreg = api.on('unregister', () => onChange(listSolanaWallets()))
  return () => {
    offReg()
    offUnreg()
  }
}

export async function connectSolanaWallet(
  discovered: DiscoveredSolanaWallet,
  opts?: { silent?: boolean },
): Promise<ConnectedSolanaWallet> {
  const pickAccount = (accounts: readonly WalletAccount[]): WalletAccount | undefined =>
    accounts.find((a) => a.chains.some((c) => c.startsWith('solana:'))) ?? accounts[0]

  // If the extension already exposes a trusted Solana account on reload, reuse it immediately.
  if (opts?.silent && discovered.wallet.accounts.length > 0) {
    const existing = pickAccount(discovered.wallet.accounts)
    if (existing) {
      return {
        name: discovered.name,
        icon: discovered.icon,
        address: existing.address,
        pubkeyBytes: new Uint8Array(existing.publicKey),
        wallet: discovered.wallet,
        account: existing,
      }
    }
  }

  const connectFeature = discovered.wallet.features['standard:connect'] as
    | { connect: (input?: { silent?: boolean }) => Promise<{ accounts: readonly WalletAccount[] }> }
    | undefined
  if (!connectFeature) {
    throw new Error(`${discovered.name} does not expose standard:connect`)
  }

  let account: WalletAccount | undefined
  if (opts?.silent) {
    try {
      const res = await connectFeature.connect({ silent: true })
      account = pickAccount(res.accounts) ?? pickAccount(discovered.wallet.accounts)
    } catch {
      account = pickAccount(discovered.wallet.accounts)
    }

    // Phantom fallback: some Chrome versions require waking the injected provider with onlyIfTrusted
    // before Wallet Standard populates accounts on a fresh reload.
    if (!account && typeof window !== 'undefined' && discovered.name.toLowerCase().includes('phantom')) {
      const phantomProvider = (
        window as unknown as {
          phantom?: { solana?: { connect?: (args: { onlyIfTrusted: boolean }) => Promise<unknown> } }
        }
      ).phantom?.solana
      if (phantomProvider?.connect) {
        try {
          await phantomProvider.connect({ onlyIfTrusted: true })
          await new Promise((r) => setTimeout(r, 60))
          account = pickAccount(discovered.wallet.accounts)
          if (!account) {
            const retry = await connectFeature.connect({ silent: true })
            account = pickAccount(retry.accounts) ?? pickAccount(discovered.wallet.accounts)
          }
        } catch {
          // User has not granted trusted auto-connect yet
        }
      }
    }
  } else {
    const res = await connectFeature.connect()
    account = pickAccount(res.accounts) ?? pickAccount(discovered.wallet.accounts)
  }

  if (!account) {
    throw new Error(`No Solana account returned by ${discovered.name}`)
  }
  return {
    name: discovered.name,
    icon: discovered.icon,
    address: account.address,
    pubkeyBytes: new Uint8Array(account.publicKey),
    wallet: discovered.wallet,
    account,
  }
}

export function subscribeWalletStandardAccounts(
  discovered: DiscoveredSolanaWallet,
  onAccount: (conn: ConnectedSolanaWallet) => void,
): () => void {
  const eventsFeature = discovered.wallet.features['standard:events'] as
    | {
        on: (
          event: 'change',
          listener: (props: { accounts?: readonly WalletAccount[] }) => void,
        ) => () => void
      }
    | undefined
  if (!eventsFeature?.on) return () => {}
  return eventsFeature.on('change', ({ accounts }) => {
    const list = accounts ?? discovered.wallet.accounts
    const account = list.find((a) => a.chains.some((c) => c.startsWith('solana:'))) ?? list[0]
    if (!account) return
    onAccount({
      name: discovered.name,
      icon: discovered.icon,
      address: account.address,
      pubkeyBytes: new Uint8Array(account.publicKey),
      wallet: discovered.wallet,
      account,
    })
  })
}

export async function disconnectSolanaWallet(connected: ConnectedSolanaWallet): Promise<void> {
  const disconnectFeature = connected.wallet.features['standard:disconnect'] as
    | { disconnect: () => Promise<void> }
    | undefined
  if (disconnectFeature) {
    await disconnectFeature.disconnect().catch(() => {})
  }
  if (typeof window !== 'undefined' && connected.name.toLowerCase().includes('phantom')) {
    const phantomProvider = (
      window as unknown as { phantom?: { solana?: { disconnect?: () => Promise<void> } } }
    ).phantom?.solana
    await phantomProvider?.disconnect?.().catch(() => {})
  }
}

export async function signUtf8MessageWithWallet(
  connected: ConnectedSolanaWallet,
  message: string,
): Promise<Uint8Array> {
  const feature = connected.wallet.features[SolanaSignMessage] as
    | SolanaSignMessageFeature[typeof SolanaSignMessage]
    | undefined
  if (!feature) {
    throw new Error(`${connected.name} does not support solana:signMessage`)
  }
  const results = await feature.signMessage({
    account: connected.account,
    message: utf8(message),
  })
  const first = results[0]
  if (!first?.signature) {
    throw new Error('Wallet returned an empty signature')
  }
  return new Uint8Array(first.signature)
}

function toKitRole(isSigner: boolean, isWritable: boolean): AccountRole {
  if (isSigner && isWritable) return AccountRole.WRITABLE_SIGNER
  if (isSigner) return AccountRole.READONLY_SIGNER
  if (isWritable) return AccountRole.WRITABLE
  return AccountRole.READONLY
}

function toKitInstruction(ix: SolanaInstruction): Instruction {
  return {
    programAddress: address(base58Encode(ix.programId)),
    accounts: ix.accounts.map((meta) => ({
      address: address(base58Encode(meta.pubkey)),
      role: toKitRole(meta.isSigner, meta.isWritable),
    })),
    data: ix.data,
  }
}

function buildComputeBudgetIxs(
  computeUnitLimit: number,
  microLamportsPerCu: bigint,
): SolanaInstruction[] {
  const ixs: SolanaInstruction[] = [
    {
      programId: COMPUTE_BUDGET_PROGRAM_ID,
      accounts: [],
      data: concatBytes(new Uint8Array([2]), u32le(computeUnitLimit)),
    },
  ]
  if (microLamportsPerCu > 0n) {
    ixs.push({
      programId: COMPUTE_BUDGET_PROGRAM_ID,
      accounts: [],
      data: concatBytes(new Uint8Array([3]), u64le(microLamportsPerCu)),
    })
  }
  return ixs
}

/**
 * Compile a Solana v0 transaction using official `@solana/kit` message builders
 * for direct signing by Wallet Standard browser wallets (Phantom / Solflare / Backpack).
 */
export function compileKitV0Transaction(params: {
  feePayer: string
  recentBlockhash: string
  lastValidBlockHeight: bigint
  instructions: SolanaInstruction[]
  computeUnitLimit?: number
  priorityMicroLamportsPerCu?: bigint
  lookupTables?: Record<string, string[]>
}): Uint8Array {
  const feePayerAddress: Address = address(params.feePayer)
  const budgetIxs =
    params.computeUnitLimit !== undefined
      ? buildComputeBudgetIxs(params.computeUnitLimit, params.priorityMicroLamportsPerCu ?? 10_000n)
      : []

  const kitIxs = [...budgetIxs, ...params.instructions].map(toKitInstruction)

  const baseMessage = pipe(
    createTransactionMessage({ version: 0 }),
    (tx) => setTransactionMessageFeePayer(feePayerAddress, tx),
    (tx) =>
      setTransactionMessageLifetimeUsingBlockhash(
        {
          blockhash: params.recentBlockhash as Blockhash,
          lastValidBlockHeight: params.lastValidBlockHeight,
        },
        tx,
      ),
    (tx) => appendTransactionMessageInstructions(kitIxs, tx),
  )

  let finalMessage = baseMessage
  if (params.lookupTables && Object.keys(params.lookupTables).length > 0) {
    const byAlt: AddressesByLookupTableAddress = {}
    for (const [altAddr, entries] of Object.entries(params.lookupTables)) {
      byAlt[address(altAddr)] = entries.map((e) => address(e))
    }
    finalMessage = compressTransactionMessageUsingAddressLookupTables(baseMessage, byAlt)
  }

  const compiled = compileTransaction(finalMessage)
  return new Uint8Array(getTransactionEncoder().encode(compiled))
}

/**
 * Request the connected browser wallet to sign 1 or more compiled `@solana/kit` transactions
 * in a single Wallet Standard `solana:signTransaction` approval prompt.
 */
export async function signCompiledTransactionsWithWallet(
  connected: ConnectedSolanaWallet,
  cluster: SolanaCluster,
  unsignedTransactions: Uint8Array[],
): Promise<Uint8Array[]> {
  const feature = connected.wallet.features[SolanaSignTransaction] as
    | SolanaSignTransactionFeature[typeof SolanaSignTransaction]
    | undefined
  if (!feature) {
    throw new Error(`${connected.name} does not support solana:signTransaction`)
  }
  const chain: `${string}:${string}` =
    cluster === 'mainnet' ? SOLANA_MAINNET_CHAIN : SOLANA_DEVNET_CHAIN
  const inputs = unsignedTransactions.map((transaction) => ({
    account: connected.account,
    transaction,
    chain,
  }))
  const signedOutputs = await feature.signTransaction(...inputs)
  return signedOutputs.map((out) => new Uint8Array(out.signedTransaction))
}

/**
 * Broadcast signed wire transactions sequentially through the Solana RPC Worker proxy
 * and wait for `confirmed` status on every transaction.
 */
export async function sendAndConfirmSignedTransactions(
  cluster: SolanaCluster,
  signedTransactions: Uint8Array[],
  options?: {
    vaultOutAta?: string
    onProgress?: (idx: number, total: number, signature: string) => void
  },
): Promise<Array<{ signature: string; slot: number; wireBytes: number; actualOut?: string | null }>> {
  const results: Array<{
    signature: string
    slot: number
    wireBytes: number
    actualOut?: string | null
  }> = []
  for (let i = 0; i < signedTransactions.length; i++) {
    const wire = signedTransactions[i]
    const isLast = i === signedTransactions.length - 1
    const sendRes = await fetch('/api/rpc/send', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        cluster,
        transactionB64: toBase64(wire),
        ...(isLast && options?.vaultOutAta ? { vaultOutAta: options.vaultOutAta } : {}),
      }),
    })
    const sendJson = (await sendRes.json()) as {
      signature?: string
      slot?: number
      actualOut?: string | null
      error?: string
    }
    if (!sendRes.ok || !sendJson.signature) {
      throw new Error(sendJson.error ?? `Transaction #${i + 1} failed to send`)
    }
    options?.onProgress?.(i, signedTransactions.length, sendJson.signature)
    results.push({
      signature: sendJson.signature,
      slot: sendJson.slot ?? 0,
      wireBytes: wire.length,
      actualOut: sendJson.actualOut ?? null,
    })
  }
  return results
}
