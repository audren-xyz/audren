/**
 * Verified on-chain deployment register, measured compute units,
 * circuit provenance, and open-source repository links for Audren.
 *
 * Cross-checked automatically by `idl/verify-idl.py` against `program/Cargo.toml`,
 * `idl/security.json`, `docs/DEPLOYMENTS.md`, and `spec/test-vectors.json`.
 */

export const AUDREN = {
  version: '1.0.0',
  protocolVersion: 2,
  releaseTag: 'v1.0.0',
  verifiedCommit: 'pending-verifiable-release',
  vkProvenance: 'DEV_DETERMINISTIC_VK (pre-audit; public Phase-2 MPC ceremony planned)',
  circuitConstraints: 17_861,
  circuitFftDomain: 32_768,
  proofBytes: 192,
  merkleArity: 4,
  merkleDepth: 20,
  maxLanes: 16,
  defaultActiveLanes: 4,
  programId: 'AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3',
  programData: 'Gj4hW4KuMTNR9YTPmixRPsNcMNwRvYTXdksxLgoGRiVM',
  pool0Pda: '8CN7uxRdQGjuAaZQVVcHRZbptSzvgfUv7tg8EarLHztF',
  solVaultPda: 'CEpjPxvw68qVqCGAHmpYxVk6XRBqf6asLpiri8wFiD7K',
  vaultAuthPda: '53H7qJDZxmFbEcBpCJ8GE3LNTL3zjdJwCjwWRKkXE8J7',
  idlPda: '5QoLwK1C3NpUXjsHEV14RsQE65MaaiT9WxGvoTyxBPsn',
  securityPda: 'GU7K3e7p8zUHoKQuQ1fidi9atxQc3UN1e3Q1Xomzs2Lj',
  otterVerifyPda: 'FUQpuou8R4iDA5iMVTZiCB6X8uMdWdhSXxgo85Viv4Qt',
  elfBytes: 150_848,
  elfSha256: 'fd798ef028ed97f60ccd076b10d49e5575db3af3d97a769eb1206b041310c4b5',
  executableHash: 'db1a0a496ed73e7be43a9a6e8b95c3da682d322a2df9c066119aa3fff36c3ba5',
  pkCompressedBytes: 3_927_280,
  pkCompressedSha256: '1864924ae15936afe02242e4fc9179b0d590dea0b71b39d7c3464db034d3e7e4',
  securityEmail: 'security@audren.xyz',
  githubOrg: 'https://github.com/audren-xyz',
  githubCore: 'https://github.com/audren-xyz/audren',
  githubRelease: 'https://github.com/audren-xyz/audren/releases/tag/v1.0.0',
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
    slot: '524,861,233',
    deployTx: 'iATWMbuHhDJYZxWw1tUdgcjrC5mRTEboCbDBM9VHhx9htAzNfJQq54wUYxBiHYMhhZkizMB7CmrHg3WZ8exjEUv',
    transferTx: '2UL1Jy9k5GfMFL7N8sh7HBG2kza2Xp4zYVUDBkvpfQDNT7peDvcNpedcxiuC3aCxEG2nH2VvJENyiogSdufeZkXc',
    withdrawTx: '2yTXobr9BGVG1hxhM2gBFifTdwUkUhqwPyFGNWUdKj1Bv9GZWqVzsJvFajzceASpkWDiDus3Y3PCAyACan8dyimr',
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
  {
    ix: 'PublishCheckpoint (Tag 5)',
    cu: 16_844,
    maxCu: 44_480,
    note: 'Permissionless 256-slot RootCheckpoint ring across 4 (16.8k CU), 8 (23.6k CU), or 16 (44.5k CU) active lanes',
  },
  {
    ix: 'DepositSol / 0-Dust Sweep (Tag 3)',
    cu: 42_491,
    maxCu: 45_200,
    note: '4-ary Poseidon leaf append + 90 B SoA MemoPage + optional DEPOSIT_FLAG_FEE_FROM_AMOUNT sweep · 0 ZK proof',
  },
  {
    ix: 'DepositSpl + TransferHook (Tag 4)',
    cu: 48_100,
    maxCu: 52_885,
    note: 'Classic SPL or Token-2022 net vault delta solvency + TransferFeeConfig & safe TransferHook support',
  },
  {
    ix: 'JoinSplit Withdraw / Unwrap (Tag 6)',
    cu: 102_540,
    maxCu: 148_163,
    note: '192 B BN254 Groth16 via alt_bn128 syscall · atomic WSOL → Native SOL unwrap · full exit bypasses pause',
  },
  {
    ix: 'JoinSplit Private Transfer (Tag 6)',
    cu: 129_731,
    maxCu: 159_798,
    note: 'Global 4^20 MASP (1.099T note capacity) · 2-in/3-out hidden asset, hidden amount, key-separated nullifiers',
  },
  {
    ix: 'ExecViaEscrow + Fee-on-Output (Tag 7)',
    cu: 158_460,
    maxCu: 189_200,
    note: 'Protocol-agnostic Token A → Token B CPI via sharded escrow + EXEC_FLAG_FEE_ON_OUTPUT · >1.2M CU left for DeFi',
  },
] as const
