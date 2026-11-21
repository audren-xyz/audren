/**
 * Verified on-chain deployment register, real measured compute units,
 * and open-source repository links for Audren v1.
 */

export const AUDREN = {
  programId: 'AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3',
  programData: 'Gj4hW4KuMTNR9YTPmixRPsNcMNwRvYTXdksxLgoGRiVM',
  pool0Pda: '5Bvt5f5QMfsVb9TyX8bzkRMvAX6JSWwRtnymGveF9U3G',
  solVaultPda: 'EhVt54eHXmWzDqngDiBXhw6ePWa9eEoBAHsMfnNCn5nr',
  vaultAuthPda: '7rQ6vQNMwBwzAFK1gcwFuJwK4DybLUGVBfxJfgVw8X9o',
  page0MainnetPda: 'iounHJYNJqhLzSyjcXF5yfyvrVuPgFJ7BwCGqCy1JJg',
  elfBytes: 295_312,
  elfSha256: '22a643a140f7644e190ec54165dcef422d54823758d646bc0245301c0931ab82',
  githubOrg: 'https://github.com/audren-xyz',
  githubCore: 'https://github.com/audren-xyz/audren',
  githubExamples: 'https://github.com/audren-xyz/examples',
  relayUrl: 'https://relay.audren.xyz',
  mainnetRelayer: 'H2JcTKgrP5Hqj7v2hTuz5u6Tt1VB8yrznotT62hhp3vY',
  devnetRelayer: 'G3tGgntjaDAcamZX2Jcgn616PrjArKYdGXv5C13MzMP',
  mainnet: {
    slot: '471,852,922',
    deployTx: '5AvZS2mzBX3VAaxZvuZFDNZBSZXD5GFs2XKbaehRgMttfYnMpzztoFVKcTJWv2vnZ4T1w3U4XabboCEzJfQpAAzd',
    initPoolTx: '5djmyDvUbAuNhxw2FwjeVLijreM7DdLqaSXgA1wCuZ2iuP9xSF5az7RtFsPuGfXwSPRyNnN6Pvhsd62H28vW7wi6',
    depositTx: 'svUmQAcv4X5iU2XkAj3bsDMnZHUTUHsLrErvZUPdBA1qa5tnr5KLDsngTMjjxefGKLZdRzeLkdiXzh8DNaF8Cxo',
    transferTx: '5eXaE1XjAVXKDPgrYXtuRaDGC7Wu6jtZqfmXYKHxADCmJzc5h7T19oKGXre1v5v6Zkky3CpPierd9nGWdnkWpNHs',
    swapTx: '4X6ixG3VmUxb1ZsziUCmJykMPH4gs1QCryyECcr1FaEbSSv3cfm7bUwdCkMvrwpsmqjrY2JtSBscYJMMNZMoSQcG',
    withdrawTx: '5pHwRUNoJBPY4w5nv4PQYLurY9GKBDVstFN3EYsRHgX1mMU9EzbavYN7y1gJxFbzxqA6AE28eHz9zcCpaEXVNg9m',
  },
  devnet: {
    slot: '524,455,742',
    deployTx: 'YRTehuRcpc6BN8UNQXmXCqRTvC5GaNttBU47zUgmxr4rBLzdgqw9ZVbVEawoeLGmXu26ZRKY5ubY3sn12jE3iWE',
    transferTx: 'R1KbSUDuWkv3NeSu14TNL2Y6oPv6z4oDE6JRbMqRJ4Vcy8qALBH6NbW6qbVav13voWYRxZKLWW4847mNXg3c8zj',
    withdrawTx: '2VFPyoDHkAQtuhru42fQ6dyM417pVKHqyYVNrHSPMEf1rrDcS4DYBtyipogSqQMuBGYrCRhnQsRKDZoLg3odFMcS',
  },
} as const

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
  { ix: 'Deposit (Tag 2)', cu: 19_816, maxCu: 40_129, note: 'Native SOL, Classic SPL, or Token-2022 · 0 ZK proof' },
  { ix: 'Withdraw full (Tag 6)', cu: 240_269, maxCu: 370_160, note: 'Read-only PoolState escape hatch · optional shielded change' },
  { ix: 'SwapViaRouter (Tag 5)', cu: 413_109, maxCu: 413_109, note: 'Isolated swap_escrow CPI · leaves ~987k CU for DEX' },
  { ix: 'Transfer m=5 (32 ring)', cu: 454_496, maxCu: 471_744, note: 'Strong Fiat-Shamir Triptych + native Bulletproof U128' },
  { ix: 'Transfer audited (m=5)', cu: 507_029, maxCu: 507_029, note: 'Enforces ElGamal (S₁,S₂) + (M₁,M₂) to K_aud' },
  { ix: 'Merge 2→1 (Tag 4)', cu: 565_486, maxCu: 565_486, note: 'Two m=5 proofs consolidated into 1 output note' },
  { ix: 'Transfer m=6 (64 ring)', cu: 813_083, maxCu: 813_083, note: '2 EpochPages · chunked 8 KiB MSM buffer' },
  { ix: 'Transfer m=7 (128 ring)', cu: 1_102_775, maxCu: 1_102_775, note: '4 EpochPages inside default 32 KiB Solana heap' },
] as const
