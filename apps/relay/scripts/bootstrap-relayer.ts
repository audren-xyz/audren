/**
 * Idempotent bootstrap script for self-hosted Audren Relay wallets (Mainnet + Devnet).
 *
 * 1. Generates dedicated Ed25519 keypairs (if not already present) saved at:
 *      - .credentials/relayer-mainnet.json (mode 0600, gitignored)
 *      - .credentials/relayer-devnet.json  (mode 0600, gitignored)
 * 2. Funds Mainnet Relayer to >= 0.10 SOL from AUDREN_KEYPAIR_PATH
 *    and idempotently pre-opens its WSOL + USDC ATAs so common pairs collect fees at 0 ATA rent
 *    (while `audren-relay` dynamically handles ANY SPL / Token-2022 mint).
 * 3. Funds Devnet Relayer to >= 0.25 SOL on Devnet if DEVNET_RPC_URL is set.
 *
 * Usage:
 *   MAINNET_RPC_URL="https://your-mainnet-rpc" \
 *   AUDREN_KEYPAIR_PATH=".credentials/funder.json" \
 *   npx tsx scripts/bootstrap-relayer.ts
 *
 * NEVER prints secret key bytes to stdout/stderr.
 */

import { ed25519 } from '@noble/curves/ed25519.js'
import { randomBytes } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import path, { dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  CLASSIC_TOKEN_PROGRAM_ID,
  SYSTEM_PROGRAM_ID,
  USDC_MAINNET_MINT_STR,
  WSOL_MINT,
  base58Decode,
  base58Encode,
  buildAndSignV1Transaction,
  buildCreateAtaIdempotentIx,
  concatBytes,
  deriveAta,
  toBase64,
  u32le,
  u64le,
} from '../src/solana/codec'
import { fetchBalance, fetchMultipleAccounts, rpcCall, waitForConfirmation } from '../src/solana/rpc'
import type { SolanaInstruction } from '../src/types'

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..')
const CREDS_DIR = process.env.AUDREN_CREDENTIALS_DIR ?? path.join(REPO_ROOT, '.credentials')

function requireEnv(name: string): string {
  const val = process.env[name]?.trim()
  if (!val) throw new Error(`Missing required environment variable: ${name}`)
  return val
}

const MAINNET_RPC = requireEnv('MAINNET_RPC_URL')
const DEVNET_RPC = process.env.DEVNET_RPC_URL?.trim() || null
const FUNDER_PATH = process.env.AUDREN_KEYPAIR_PATH ?? path.join(CREDS_DIR, 'funder.json')
const MAINNET_KEY_PATH = path.join(CREDS_DIR, 'relayer-mainnet.json')
const DEVNET_KEY_PATH = path.join(CREDS_DIR, 'relayer-devnet.json')

function loadOrCreateKeypair(path: string): {
  secret32: Uint8Array
  pubkey: Uint8Array
  pubkeyB58: string
  created: boolean
} {
  if (existsSync(path)) {
    const arr = JSON.parse(readFileSync(path, 'utf8')) as number[]
    const raw = Uint8Array.from(arr)
    const secret32 = raw.subarray(0, 32)
    const pubkey = ed25519.getPublicKey(secret32)
    return { secret32, pubkey, pubkeyB58: base58Encode(pubkey), created: false }
  }
  mkdirSync(dirname(path), { recursive: true })
  const secret32 = new Uint8Array(randomBytes(32))
  const pubkey = ed25519.getPublicKey(secret32)
  const full64 = concatBytes(secret32, pubkey)
  writeFileSync(path, JSON.stringify(Array.from(full64)), { mode: 0o600 })
  chmodSync(path, 0o600)
  return { secret32, pubkey, pubkeyB58: base58Encode(pubkey), created: true }
}

function buildSystemTransferIx(from: Uint8Array, to: Uint8Array, lamports: bigint): SolanaInstruction {
  return {
    programId: SYSTEM_PROGRAM_ID,
    accounts: [
      { pubkey: from, isSigner: true, isWritable: true },
      { pubkey: to, isSigner: false, isWritable: true },
    ],
    data: concatBytes(u32le(2), u64le(lamports)),
  }
}

async function main() {
  const funderRaw = Uint8Array.from(JSON.parse(readFileSync(FUNDER_PATH, 'utf8')) as number[])
  const funderSecret32 = funderRaw.subarray(0, 32)
  const funderPubkey = ed25519.getPublicKey(funderSecret32)
  const funderB58 = base58Encode(funderPubkey)

  const mainnetRelayer = loadOrCreateKeypair(MAINNET_KEY_PATH)
  const devnetRelayer = loadOrCreateKeypair(DEVNET_KEY_PATH)

  console.log('Funder pubkey:         ', funderB58)
  console.log('Mainnet Relayer pubkey:', mainnetRelayer.pubkeyB58, mainnetRelayer.created ? '(NEW)' : '(existing)')
  console.log('Devnet Relayer pubkey: ', devnetRelayer.pubkeyB58, devnetRelayer.created ? '(NEW)' : '(existing)')

  // 1. Mainnet funding + pre-opening WSOL & USDC ATAs on Mainnet Relayer
  const targetMainnetLamports = 100_000_000n // 0.10 SOL
  const usdcMint = base58Decode(USDC_MAINNET_MINT_STR)
  const wsolAta = deriveAta(mainnetRelayer.pubkey, CLASSIC_TOKEN_PROGRAM_ID, WSOL_MINT)
  const usdcAta = deriveAta(mainnetRelayer.pubkey, CLASSIC_TOKEN_PROGRAM_ID, usdcMint)

  const [curMainnetBal, ataInfos] = await Promise.all([
    fetchBalance(MAINNET_RPC, mainnetRelayer.pubkeyB58),
    fetchMultipleAccounts(MAINNET_RPC, [base58Encode(wsolAta), base58Encode(usdcAta)], {
      dataSlice: { offset: 0, length: 0 },
    }),
  ])

  const ixs: SolanaInstruction[] = []
  if (BigInt(curMainnetBal) < targetMainnetLamports) {
    const topUp = targetMainnetLamports - BigInt(curMainnetBal)
    ixs.push(buildSystemTransferIx(funderPubkey, mainnetRelayer.pubkey, topUp))
    console.log(`Topping up Mainnet Relayer by ${(Number(topUp) / 1e9).toFixed(4)} SOL…`)
  }
  if (!ataInfos[0]) {
    ixs.push(
      buildCreateAtaIdempotentIx({
        payer: funderPubkey,
        ata: wsolAta,
        owner: mainnetRelayer.pubkey,
        mint: WSOL_MINT,
        tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
      }),
    )
    console.log('Pre-creating Mainnet Relayer WSOL fee ATA:', base58Encode(wsolAta))
  }
  if (!ataInfos[1]) {
    ixs.push(
      buildCreateAtaIdempotentIx({
        payer: funderPubkey,
        ata: usdcAta,
        owner: mainnetRelayer.pubkey,
        mint: usdcMint,
        tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
      }),
    )
    console.log('Pre-creating Mainnet Relayer USDC fee ATA:', base58Encode(usdcAta))
  }

  if (ixs.length > 0) {
    const bh = await rpcCall<{ value: { blockhash: string } }>(MAINNET_RPC, 'getLatestBlockhash', [
      { commitment: 'confirmed' },
    ])
    const signed = buildAndSignV1Transaction(funderSecret32, bh.value.blockhash, ixs, {
      computeUnitLimit: 120_000,
      priorityFeeLamports: 10_000n,
    })
    const sig = await rpcCall<string>(MAINNET_RPC, 'sendTransaction', [
      toBase64(signed.wireBytes),
      { encoding: 'base64', preflightCommitment: 'confirmed', maxRetries: 3 },
    ])
    const { slot } = await waitForConfirmation(MAINNET_RPC, sig)
    console.log(`Mainnet bootstrap confirmed at slot ${slot}: https://solscan.io/tx/${sig}`)
  } else {
    console.log('Mainnet Relayer already funded & USDC/WSOL ATAs already open.')
  }

  const finalMainnetBal = await fetchBalance(MAINNET_RPC, mainnetRelayer.pubkeyB58)
  console.log(`Mainnet Relayer final balance: ${(finalMainnetBal / 1e9).toFixed(6)} SOL`)

  // 2. Devnet funding (if DEVNET_RPC_URL is configured & funder has devnet SOL)
  if (DEVNET_RPC) {
    const devnetRpc = DEVNET_RPC
    const [curDevBal, funderDevBal] = await Promise.all([
      fetchBalance(devnetRpc, devnetRelayer.pubkeyB58),
      fetchBalance(devnetRpc, funderB58),
    ])
    const targetDevLamports = 250_000_000n // 0.25 SOL
    if (BigInt(curDevBal) < targetDevLamports && BigInt(funderDevBal) > targetDevLamports + 50_000_000n) {
      const topUp = targetDevLamports - BigInt(curDevBal)
      const bh = await rpcCall<{ value: { blockhash: string } }>(devnetRpc, 'getLatestBlockhash', [
        { commitment: 'confirmed' },
      ])
      const signed = buildAndSignV1Transaction(
        funderSecret32,
        bh.value.blockhash,
        [buildSystemTransferIx(funderPubkey, devnetRelayer.pubkey, topUp)],
        { computeUnitLimit: 50_000, priorityFeeLamports: 5_000n },
      )
      const sig = await rpcCall<string>(devnetRpc, 'sendTransaction', [
        toBase64(signed.wireBytes),
        { encoding: 'base64', preflightCommitment: 'confirmed', maxRetries: 3 },
      ])
      const { slot } = await waitForConfirmation(devnetRpc, sig)
      console.log(`Devnet bootstrap confirmed at slot ${slot}: https://solscan.io/tx/${sig}?cluster=devnet`)
    } else {
      console.log(
        `Devnet Relayer balance: ${(curDevBal / 1e9).toFixed(4)} SOL (funder devnet: ${(funderDevBal / 1e9).toFixed(4)} SOL)`,
      )
    }
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
