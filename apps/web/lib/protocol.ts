/**
 * Verified on-chain deployment register, real measured compute units,
 * and open-source repository links for Audren.
 *
 * Cross-checked automatically by `idl/verify-idl.py` against `program/Cargo.toml`,
 * `idl/security.json`, `docs/DEPLOYMENTS.md`, and live Mainnet verification state.
 */

export const AUDREN = {
  version: '0.2.0',
  releaseTag: 'v0.2.0',
  verifiedCommit: 'c288d5356f58a50fe2e7ac84dce4b84401e3bdf0',
  programId: 'AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3',
  programData: 'Gj4hW4KuMTNR9YTPmixRPsNcMNwRvYTXdksxLgoGRiVM',
  pool0Pda: '5Bvt5f5QMfsVb9TyX8bzkRMvAX6JSWwRtnymGveF9U3G',
  solVaultPda: 'EhVt54eHXmWzDqngDiBXhw6ePWa9eEoBAHsMfnNCn5nr',
  vaultAuthPda: '7rQ6vQNMwBwzAFK1gcwFuJwK4DybLUGVBfxJfgVw8X9o',
  page0MainnetPda: 'iounHJYNJqhLzSyjcXF5yfyvrVuPgFJ7BwCGqCy1JJg',
  idlPda: '5QoLwK1C3NpUXjsHEV14RsQE65MaaiT9WxGvoTyxBPsn',
  securityPda: 'GU7K3e7p8zUHoKQuQ1fidi9atxQc3UN1e3Q1Xomzs2Lj',
  otterVerifyPda: 'FUQpuou8R4iDA5iMVTZiCB6X8uMdWdhSXxgo85Viv4Qt',
  elfBytes: 228_184,
  elfSha256: '76f975f5c68f6b3c51762407df37099bccd4e71dd5bf850c58c8737aa6f985da',
  executableHash: '0aa268a9f2bac5c0f6c08f6eecc199151235d7f056d3b4944f97bf7b1dca0159',
  securityEmail: 'security@audren.xyz',
  githubOrg: 'https://github.com/audren-xyz',
  githubCore: 'https://github.com/audren-xyz/audren',
  githubRelease: 'https://github.com/audren-xyz/audren/releases/tag/v0.2.0',
  githubExamples: 'https://github.com/audren-xyz/examples',
  osecVerifyStatusUrl: 'https://verify.osec.io/status/AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3',
  relayUrl: 'https://relay.audren.xyz',
  mainnetRelayer: 'H2JcTKgrP5Hqj7v2hTuz5u6Tt1VB8yrznotT62hhp3vY',
  devnetRelayer: 'G3tGgntjaDAcamZX2Jcgn616PrjArKYdGXv5C13MzMP',
  mainnet: {
    slot: '472,228,607',
    deployTx: '3LZUEJfxKzzaenYm8BV8hAaEF7ELanQW92MMbs9NjGouYrCf5YcTzVF1BHCfzvskBFDZa66GY3CupLUpq6jkM4QW',
    initPoolTx: '5djmyDvUbAuNhxw2FwjeVLijreM7DdLqaSXgA1wCuZ2iuP9xSF5az7RtFsPuGfXwSPRyNnN6Pvhsd62H28vW7wi6',
    depositTx: 'svUmQAcv4X5iU2XkAj3bsDMnZHUTUHsLrErvZUPdBA1qa5tnr5KLDsngTMjjxefGKLZdRzeLkdiXzh8DNaF8Cxo',
    transferTx: '5eXaE1XjAVXKDPgrYXtuRaDGC7Wu6jtZqfmXYKHxADCmJzc5h7T19oKGXre1v5v6Zkky3CpPierd9nGWdnkWpNHs',
    swapTx: '4X6ixG3VmUxb1ZsziUCmJykMPH4gs1QCryyECcr1FaEbSSv3cfm7bUwdCkMvrwpsmqjrY2JtSBscYJMMNZMoSQcG',
    withdrawTx: '5pHwRUNoJBPY4w5nv4PQYLurY9GKBDVstFN3EYsRHgX1mMU9EzbavYN7y1gJxFbzxqA6AE28eHz9zcCpaEXVNg9m',
  },
  devnet: {
    slot: '524,792,132',
    deployTx: '3oz2HNeb9YVBLkVuiBpkYYAutKNGzJt6HcQgH69xCM1pm3EBm1Q26odQsdcqWvsD2bnECnz754FQjEcAufekkPJ7',
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
  { ix: 'Deposit (Tag 2)', cu: 14_831, maxCu: 22_975, note: 'Native SOL, Classic SPL, or Token-2022 · 0 ZK proof' },
  { ix: 'Withdraw full (Tag 6)', cu: 212_975, maxCu: 350_094, note: 'Read-only PoolState escape hatch · optional shielded change' },
  { ix: 'SwapViaRouter (Tag 5)', cu: 366_823, maxCu: 366_823, note: 'Isolated swap_escrow CPI · leaves ~1.03M CU for DEX' },
  { ix: 'Transfer m=5 (32 ring)', cu: 441_137, maxCu: 457_281, note: 'Strong Fiat-Shamir Triptych + native Bulletproof U128' },
  { ix: 'Transfer audited (m=5)', cu: 494_089, maxCu: 494_089, note: 'Enforces ElGamal (S₁,S₂) + (M₁,M₂) to K_aud' },
  { ix: 'Merge 2→1 (Tag 4)', cu: 549_568, maxCu: 549_568, note: 'Two m=5 proofs consolidated into 1 output note' },
  { ix: 'Transfer m=6 (64 ring)', cu: 798_272, maxCu: 798_272, note: '2 EpochPages · chunked 8 KiB MSM buffer' },
  { ix: 'Transfer m=7 (128 ring)', cu: 1_082_506, maxCu: 1_082_506, note: '4 EpochPages inside default 32 KiB Solana heap' },
] as const
