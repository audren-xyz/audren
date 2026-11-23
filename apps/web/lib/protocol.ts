/**
 * Verified on-chain deployment register, measured compute units,
 * circuit provenance, and open-source repository links for Audren.
 *
 * Cross-checked automatically by `idl/verify-idl.py` against `program/Cargo.toml`,
 * `idl/security.json`, `docs/DEPLOYMENTS.md`, and `spec/test-vectors.json`.
 */

export const AUDREN = {
  version: '1.1.1',
  protocolVersion: 2,
  releaseTag: 'v1.1.1',
  verifiedCommit: '936cc659bd6286417a692e7970d3cbd91a49e9bd',
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
  pool0Pda: '8CN7uxRdQGjuAaZQVVcHRZbptSzvgfUv7tg8EarLHztF',
  solVaultPda: 'CEpjPxvw68qVqCGAHmpYxVk6XRBqf6asLpiri8wFiD7K',
  vaultAuthPda: '53H7qJDZxmFbEcBpCJ8GE3LNTL3zjdJwCjwWRKkXE8J7',
  idlPda: '5QoLwK1C3NpUXjsHEV14RsQE65MaaiT9WxGvoTyxBPsn',
  securityPda: 'GU7K3e7p8zUHoKQuQ1fidi9atxQc3UN1e3Q1Xomzs2Lj',
  otterVerifyPda: 'FUQpuou8R4iDA5iMVTZiCB6X8uMdWdhSXxgo85Viv4Qt',
  elfBytes: 151_648,
  elfSha256: 'ce1e5d06247490022fcd75751db566d6eb2f57f840d43ef50a9d31a9197d90ba',
  executableHash: '878f02a19a6cadc6e402b9938bc4276aa9aa29bbd023c271714b754537772f94',
  pkCompressedBytes: 3_927_280,
  pkCompressedSha256: '2b22603e466c79b6710e01898dc8b458b09a3ee905b25db996f0c59e76187ee4',
  securityEmail: 'security@audren.xyz',
  githubOrg: 'https://github.com/audren-xyz',
  githubCore: 'https://github.com/audren-xyz/audren',
  githubRelease: 'https://github.com/audren-xyz/audren/releases/tag/v1.1.1',
  githubExamples: 'https://github.com/audren-xyz/examples',
  osecVerifyStatusUrl: 'https://verify.osec.io/status/AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3',
  relayUrl: 'https://relay.audren.xyz',
  mainnetRelayer: 'H2JcTKgrP5Hqj7v2hTuz5u6Tt1VB8yrznotT62hhp3vY',
  devnetRelayer: 'G3tGgntjaDAcamZX2Jcgn616PrjArKYdGXv5C13MzMP',
  mainnet: {
    slot: '472,733,615',
    deployTx: '3qcXYo3Fv2saVQkNPs21mUS6XCs9mmRuWHhUE2ARvyLdLPXHMgnRUY8dTmse4gryVXDuHbo519W4CJ8whZrRATDe',
    initPoolTx: '28pu7RhUpAgb93tBpjp8yRnhBKrGgDNKWJnRY2hXaF2n44fuetUvUtvfaoQm7c2iqxtf5i6kFpWCkkaxexZmEnWK',
    depositTx: '3wig4kVwvqv9JLPVFSPyg3x2fXK9c1SxhHDGt93qGPrQp9SoskB2jDvKJqCwyXJ9squiTm25ieBXKgCL92TJXmGv',
    transferTx: '49zM3ztG8GGTYEPuob8FwMppD5j3KM1tutdnDdiZ4BUqeEvRidAzKY86HLFmQKyKh5hEgiaLbxn5M6aX7ZngYSqv',
    swapTx: '92MXqdzZ3H6PtskWH727q5eG1pxXfzVV22MkFYbietSQBj5Ao8EuKjC8ztMeL7Bt1VTEXkuU4V7UhR3ubnuiFHa',
    withdrawTx: '4yxiG5BvcJR7bB8SrVfvhkupQciJHVwUsp2Un7jcuDYoBjYq3dWwZ7PWyKjH7HMnkxDCD7Z9eXKhj1tykDf1W53w',
  },
  devnet: {
    slot: '525,243,442',
    deployTx: '3BgYvycgL3LXZjxxMb13JDXZC84ywHeKoXQMjKM2FiVsjVDaQ51Lb2tMoeR6UW3Sh4kqbSLoVrV6fiP8qZSzgUby',
    transferTx: 'WpuUPq3hRfckC78hHSMFyM82Dj226Lh5L3jXs5Bt71xQ3jT63jNqdVWgg6tYPqzNRpn1LU4kUYr8XMQNLUweT1N',
    withdrawTx: '34osxtbwqUPsVLb5hbzmx8TBqd6XPRnr8tdN72SWL2FNUQ5U7YwF3FVn4misE2XbA8BM7UVaxipo41i6DwZgSpen',
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
    ix: 'DepositSpl · SPL & Token-2022 (Tag 4)',
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
