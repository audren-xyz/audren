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
  verifiedCommit: '6bf007ea99eb72de5f19504ddf9d45084156cecc',
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
    slot: '472,698,949',
    deployTx: '3cwstWFBwDnCev8to6kcifdUpfJno1HW5qWLs3RnuYdHum6NreWPf3ePV4gD6eYypSMufcF6zUFYgw9UXwC5jE5S',
    initPoolTx: '28pu7RhUpAgb93tBpjp8yRnhBKrGgDNKWJnRY2hXaF2n44fuetUvUtvfaoQm7c2iqxtf5i6kFpWCkkaxexZmEnWK',
    depositTx: '29dK2ka1oEyrs9xHbLa3GVQk6hAvhF1f38MX8CbfTpBdoQr2unVc9xTtk5vaKPCmwyjrCDSRnivAUtnVEFuLsnYg',
    transferTx: 'xrVdnaXV74skysxBHrnmQzwFq6DuZdtruuwFifqpCH3W7oj9qUZ34TXAVaFwtkpT4fpYekJYWwMt5WxmmVRULYX',
    swapTx: '2SzCHoaUiJNA6HgSM6FidVt1r5gM8PSMvMddBkT7xdfXtbwN3TqeXzjbW4JkL1RmcoZ41vopDXnPtDqzWWJ7DoNv',
    withdrawTx: '24VK3QHFiY9MBuhFMNJQ4mEEGKwYmXexFD5i7ZMfdn2aDbCnvp1SfurVkJjw2YcdtscxysFCLzdmRWmTEfBEHWe8',
  },
  devnet: {
    slot: '525,212,038',
    deployTx: '5uKonrmFD9k91o2JE6LSJUC26eZ2EitfAPQCWno873k9TCHNXF66MBqkP4RurRSQCBTkkQrALPLTkMNqAHGRnk7y',
    transferTx: '41qkgrLnS3X1A8bhpnzvgFfKVEsCZavrUZCct34ncVbepRRnSEbMMJRZYCLD71y2n1quePhvCJ5pCMjp6BBWYWmT',
    withdrawTx: '1zBjkjHS4ffoJcioTvpxTQQPJ29ViN4sdW5tNaHeiiNefSvCX4LgwtSacxc374rbobuzi7z7MXY81Bd9yboWkKy',
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
