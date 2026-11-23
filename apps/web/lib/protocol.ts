/**
 * Verified on-chain deployment register, static well-known Solana token metadata,
 * measured compute units, circuit provenance, and open-source repository links for Audren.
 *
 * Cross-checked automatically by `idl/verify-idl.py` against `program/Cargo.toml`,
 * `idl/security.json`, `docs/DEPLOYMENTS.md`, and `spec/test-vectors.json`.
 */

import { CLASSIC_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, WSOL_MINT } from './audren-crypto'

export const AUDREN = {
  version: '1.2.0',
  protocolVersion: 1,
  releaseTag: 'v1.2.0',
  verifiedCommit: 'b60ec029f42551eb4f9678783dee1b73f9ea9f28',
  vkProvenance:
    'Perpetual Powers of Tau (71+ contributors) + Audren BGM17 Phase-2 Ceremony (drand #34194203 · Solana slot 472705896 · pre-audit)',
  circuitConstraints: 17_861,
  circuitFftDomain: 32_768,
  proofBytes: 192,
  merkleArity: 4,
  merkleDepth: 20,
  maxLanes: 16,
  defaultActiveLanes: 4,
  programId: 'AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3',
  programData: 'Gj4hW4KuMTNR9YTPmixRPsNcMNwRvYTXdksxLgoGRiVM',
  pool0Pda: '5Bvt5f5QMfsVb9TyX8bzkRMvAX6JSWwRtnymGveF9U3G',
  vaultAuthPda: '3aMtBvVMatfBvoBWQaTxCPwQ2SWyW5ejceVgLFTtk2WF',
  idlPda: '5QoLwK1C3NpUXjsHEV14RsQE65MaaiT9WxGvoTyxBPsn',
  securityPda: 'GU7K3e7p8zUHoKQuQ1fidi9atxQc3UN1e3Q1Xomzs2Lj',
  otterVerifyPda: 'FUQpuou8R4iDA5iMVTZiCB6X8uMdWdhSXxgo85Viv4Qt',
  elfBytes: 162_552,
  elfSha256: '90ab38268ae434df9aa348784801fd6d4e816cc4d3720b1f7654f6549ef78e7e',
  executableHash: 'f55e117f23ec011365e317518484d292514523a2b1f081cce66506e24925dbcc',
  pkCompressedBytes: 3_927_280,
  pkCompressedSha256: '2b22603e466c79b6710e01898dc8b458b09a3ee905b25db996f0c59e76187ee4',
  securityEmail: 'security@audren.xyz',
  githubOrg: 'https://github.com/audren-xyz',
  githubCore: 'https://github.com/audren-xyz/audren',
  githubRelease: 'https://github.com/audren-xyz/audren/releases/tag/v1.2.0',
  githubExamples: 'https://github.com/audren-xyz/examples',
  osecVerifyStatusUrl: 'https://verify.osec.io/status/AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3',
  relayUrl: 'https://relay.audren.xyz',
  mainnetRelayer: 'H2JcTKgrP5Hqj7v2hTuz5u6Tt1VB8yrznotT62hhp3vY',
  devnetRelayer: 'G3tGgntjaDAcamZX2Jcgn616PrjArKYdGXv5C13MzMP',
  mainnet: {
    slot: '472,795,010',
    deployTx: 'CiAGpgYQcXUhHNDcMk2Dmk3Emm97tFeRUo6NMC9WPcr3hgbnXxjoin91g2VoK791vYiEKsyfamh3HeJhoF8y2eG',
    initPoolTx: '5PXHvSPRzMhXYHzidnoafHe6VVR5GN3ATXBT5Vxw7fovfnzvYnqEPiW1qgRRYXZkwr9L2QT7t1o1qDGKUhv4BJKt',
    depositTx: '5Wtxdh59fT3fjN4s2NqdEyygbvC55cA52iHxkBF1NsTRMGpyK6yjsbBRjiPpkujYEE1Ybs2o2QwiLCP8AkotDFJX',
    transferTx: '5D8dZm8ezjCGGAMSptsLQ358H1pPzo4Xoxkwpn9UiuDVhPQNpKP4sNbu3XBZ2p8UTvVRzT9yDf7hS7vQJCJfnYiW',
    swapTx: '4NQnwFpgmBNwnGXex6jVfZCes2sYpgoeS4xTuzy2dZBBvtxnzXG59V9FrSuDEbuhBz8xHXUwrirtVcD9ZxMDCisu',
    withdrawTx: '3aEs1McMR6Ke6qNytrdcNmnj1GcQzhvaywhcB2LTscdupdqXVsprEKRC9fLTWiNRH9mDiiR5gSUjcNhi8JPHvajK',
  },
  devnet: {
    slot: '525,297,454',
    deployTx: 'GXAPuXJeEPbYqcJ3G7Ki9Ae5CtyKsh6Uc31a9TeNN4DkX6Hxmpf791XSpSCXs9jifawpquJbffbnTzYvixoxK9W',
    transferTx: '5CZr1uhJm7ytY7F9XQA3ToGGK2HA6wej1kzsa9MsR3YVSBUAHdNChhZcHhFZShoDrVonqkprkAaHDpTo2ay9iuzd',
    withdrawTx: 'kLJ3ScMgQDZkFVrQFVY2vCsWFzGCMtnBNZTUU1gVoK1qcNVcK5PjtXvZpmRhS9BVadsavA2skRoPWiADDsCLBHH',
  },
} as const

export interface StaticTokenMeta {
  symbol: string
  name: string
  decimals: number
  tokenProgram: string
}

/**
 * Bundled static metadata for common Solana mints so shielded vault balances render
 * locally with zero `/api/tokens/resolve` requests that could reveal held shielded mints.
 *
 * WSOL (`So1111...1112`) is displayed transparently as `SOL` across the shielded vault.
 */
export const WELL_KNOWN_TOKENS: Record<string, StaticTokenMeta> = {
  [WSOL_MINT]: {
    symbol: 'SOL',
    name: 'Solana',
    decimals: 9,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v: {
    symbol: 'USDC',
    name: 'USD Coin',
    decimals: 6,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU': {
    symbol: 'USDC',
    name: 'USD Coin (Devnet)',
    decimals: 6,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB: {
    symbol: 'USDT',
    name: 'Tether USD',
    decimals: 6,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN: {
    symbol: 'JUP',
    name: 'Jupiter',
    decimals: 6,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn: {
    symbol: 'JitoSOL',
    name: 'Jito Staked SOL',
    decimals: 9,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So: {
    symbol: 'mSOL',
    name: 'Marinade Staked SOL',
    decimals: 9,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  bSo13r4TkiE4KumL71LsHTPpL2euBYLFx6h9HP3piy1: {
    symbol: 'bSOL',
    name: 'BlazeStake Staked SOL',
    decimals: 9,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  jupSoLaHXQiZZTSfEWMTRRgpnyFm8f6sZdosWBjx93v: {
    symbol: 'JupSOL',
    name: 'Jupiter Staked SOL',
    decimals: 9,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263: {
    symbol: 'BONK',
    name: 'Bonk',
    decimals: 5,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  '3NZ9JMVBmGAqocybic2c7LQCJScmgsAZ6vQqTDzcqmJh': {
    symbol: 'WBTC',
    name: 'Wrapped Bitcoin',
    decimals: 8,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  cbbtcf3aa214zXHbiAZQwf4122FBYbraNdFqgw4iMij: {
    symbol: 'cbBTC',
    name: 'Coinbase Wrapped BTC',
    decimals: 8,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  '7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs': {
    symbol: 'WETH',
    name: 'Wrapped Ether',
    decimals: 8,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  '2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo': {
    symbol: 'PYUSD',
    name: 'PayPal USD',
    decimals: 6,
    tokenProgram: TOKEN_2022_PROGRAM_ID,
  },
  HzwqbKZw8HxMN6bF2yFZNrht3c2iXXzpKcFu7uBEDKtr: {
    symbol: 'EURC',
    name: 'Euro Coin',
    decimals: 6,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  USDSwr9ApdHk5bvJKMjzff41FfuX8bSxdKcR81vTwcA: {
    symbol: 'USDS',
    name: 'USDS',
    decimals: 6,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm: {
    symbol: 'WIF',
    name: 'dogwifhat',
    decimals: 6,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  HZ1JovNiVvGrGNiiYvEozEVgZ58xaU3RKwX8eACQBCt3: {
    symbol: 'PYTH',
    name: 'Pyth Network',
    decimals: 6,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  '4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R': {
    symbol: 'RAY',
    name: 'Raydium',
    decimals: 6,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  orcaEKTdK7LKz57vaAYr9QeNsVEPfiu6QeMU1kektZE: {
    symbol: 'ORCA',
    name: 'Orca',
    decimals: 6,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  rndrizKT3MK1iimdxRdWabcF7Zg7AR5T4nud4EkHBof: {
    symbol: 'RENDER',
    name: 'Render Token',
    decimals: 8,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
}

export function solscanAddress(addr: string, cluster: 'mainnet' | 'devnet' = 'mainnet') {
  return cluster === 'devnet'
    ? `https://solscan.io/account/${addr}?cluster=devnet`
    : `https://solscan.io/account/${addr}`
}

export function solscanTx(sig: string, cluster: 'mainnet' | 'devnet' = 'mainnet') {
  return cluster === 'devnet'
    ? `https://solscan.io/tx/${sig}?cluster=devnet`
    : `https://solscan.io/tx/${sig}`
}

export function explorerAddress(
  addr: string,
  tab?: 'verified-build' | 'security' | 'idl',
  cluster: 'mainnet' | 'devnet' = 'mainnet',
) {
  const path = tab ? `${addr}/${tab}` : addr
  return cluster === 'devnet'
    ? `https://explorer.solana.com/address/${path}?cluster=devnet`
    : `https://explorer.solana.com/address/${path}`
}

export function explorerTx(sig: string, cluster: 'mainnet' | 'devnet' = 'mainnet') {
  return cluster === 'devnet'
    ? `https://explorer.solana.com/tx/${sig}?cluster=devnet`
    : `https://explorer.solana.com/tx/${sig}`
}

export function shortHash(value: string, head = 8, tail = 6) {
  if (value.length <= head + tail + 2) return value
  return `${value.slice(0, head)}…${value.slice(-tail)}`
}

export const MEASURED_CU_ROWS = [
  {
    ix: 'PublishCheckpoint (Tag 4)',
    cu: 16_844,
    maxCu: 44_480,
    note: 'Permissionless 256-slot RootCheckpoint ring across 4 (16.8k CU), 8 (23.6k CU), or 16 (44.5k CU) active lanes',
  },
  {
    ix: 'Deposit · SOL & SPL / Token-2022 (Tag 3)',
    cu: 48_100,
    maxCu: 52_885,
    note: 'Unified native SOL (SyncNative WSOL) and SPL / Token-2022 net vault delta solvency · 72 B versioned memo (106 B SoA, 96 notes/page, 10,240 B) · 0 ZK proof',
  },
  {
    ix: 'Transact Withdraw / Unwrap (Tag 5)',
    cu: 102_540,
    maxCu: 148_163,
    note: '192 B BN254 Groth16 via alt_bn128 syscall · atomic WSOL to Native SOL unwrap · full exit bypasses pause',
  },
  {
    ix: 'Transact Private Transfer (Tag 5)',
    cu: 129_731,
    maxCu: 159_798,
    note: 'Global 4^20 MASP (1.099T note capacity) · 2-in/3-out hidden asset, hidden amount, key-separated nullifiers · 72 B versioned memos (106 B SoA, 96 notes/page)',
  },
  {
    ix: 'ExecViaEscrow + Fee-on-Output (Tag 6)',
    cu: 158_460,
    maxCu: 189_200,
    note: 'Protocol-agnostic SPL / Token-2022 CPI via 16 sharded escrows + EXEC_FLAG_FEE_ON_OUTPUT + 72 B AUD1DYN1 dynamic memo · >1.2M CU left for DeFi',
  },
] as const
