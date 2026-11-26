/**
 * Verified on-chain deployment register, static well-known Solana token metadata,
 * measured compute units, circuit provenance, and open-source repository links for Audren.
 *
 * Cross-checked automatically by `idl/verify-idl.py` against `program/Cargo.toml`,
 * `idl/security.json`, `docs/DEPLOYMENTS.md`, and `spec/test-vectors.json`.
 */

import { CLASSIC_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, WSOL_MINT } from './audren-crypto'

const MAINNET_POOL0_ALT_ENTRIES = [
  'AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3',
  '5Bvt5f5QMfsVb9TyX8bzkRMvAX6JSWwRtnymGveF9U3G',
  '3aMtBvVMatfBvoBWQaTxCPwQ2SWyW5ejceVgLFTtk2WF',
  'DS1YN7kcfP2WVrkcnHB93vEJEdqxSg3MPZwwqVRJeHbK',
  '5WR3qf7wYscZCJhx33EiJtZQe6L2cDQBg1opbriEFHYT',
  '11111111111111111111111111111111',
  'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
  'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
  'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL',
  'ComputeBudget111111111111111111111111111111',
  'So11111111111111111111111111111111111111112',
  'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
  'Gt8hMsfF5A3UepD52wifodYfxgYdSnDpmLvaA6f9aUXr',
  'JBZMSvACBce2j6W7tPxroAB11E9Hujq2DaRnWhNVZwmz',
  'HhCwAZUY3pYLmYVQer3PuytbFVdYzwrtygsYSaUak7ex',
  '7W6DhkuNDzWjaF2wyevZzzSLCtnwX5cCNUKywVPC2E2o',
  'Dm1HP34tohNH2FeXGMttQu8pDmDFzbSsNcv7i25szHY9',
  'HqeWpJUAoxupBZJZskruy7QWVYirsuro2isoRPfvLAHb',
  'AkvqobVhYrJfkVbQb8VWPM1oa8NBhge2kUKo4AeJiByV',
  'GHoEHs4wyfp4WBSydyeFoqEFMFDeT146bxEQVWVhESpW',
  'J3ce6Ps9e5xReqjp5ytfmC96FjMjhWdwR7onrapCG2hK',
  'C558yHEmkU5kyFLugfn1Rwys2MxmZe9x9P7BQ5CbiHoL',
  'A3gE8FEzNfDbwnhNjuXnB5k74HojLduaxEUmrp6xj5Hc',
  'GcSZyqAwq5EpEpC3fv6NLLZQmV9pLahsr49tyj7fNe5r',
  'AJFrTGiSbJsiXfQA5cZQVF566NEU15yBYzLRTU7J2Hay',
  '5ShNay1WsYSC83T3QD9RhiHZip8U22tvPRU439nAXudE',
  'GBspRTkRNmEgxNFBPi5zFDqJ994JMAerZxFe4EjFzJgJ',
  '68jqT6q3eemHXaZD4B3zsbsH3vfmwYRBYvF4WgiCjj1J',
  '3zYiwbQeZaivqqPeXgiszJwY1k4FJVZ59ddd838vAuc4',
  '71QtLeHQRy8DjjMHmD81AyLKPNV19Lj12796JaWJQuK5',
  'GP6nHVaLnVo8qhFaVNdiudfDsrrLQKVzmkSh7jwShuVw',
  'C4HodgHSr2fap3Pchmjk7PNH3q5XHmPkfXS2phCggsiZ',
  '7hSXos52GWSfg44pkq4rAnWRPu7iN6nkhPDDbSKQ35WN',
  'DWzeE42oXKksQ1DdQLw7GrigVdEmB1uNbBSz7ycWitin',
  'EjbXT5ma4zq5voFdeHyRHCU4WgrPPq3RdeEZrLV6usbZ',
  'Ffn7csL3Zo1DnJGN5YTvhBLKbdS7Kv4J3CpYKSyQPF6W',
  'DCMnnPzACohDAE76Kx5fiLnKwbFUv8e3WhzFAaqkR7aW',
  'CivYvThHyhrRVLeADiW7gqDJxFHWVFXyRmoMKkvRLLMw',
  'Bgfd5wRAsJyoL5wzFjvQyNmFq16uDY9poQ6xuFeucd8t',
  '4jcT5jkHjqXeE2uVGu2cEzrzwguUyQj3aFx8B4DGjmRy',
  '249YJTuRtiKAnh346Tc18kF9bHrktdrTzyJMtvUKUgC7',
  'AYgqaqm7JNdxQMQWY4MAHwSWazDc9xtiBboUM7NMmLgJ',
  'EtGkmd1Cfb2eEfiqPXJBtrFir7BGpXSGvaTpVTyVGtxH',
  '9mbMiSbEvd6uuxZyGZvbnyWLJb2vbQzEKUZwVHqjTvWc',
  '2K8P3q2beqLL9SCZi35fGNdw5X11XdowbaGN5u7WozMp',
  '92mmqRnXSchTa86HmDC2mksgCq6Ygg9ui8ECeX3e2vBX',
  '6ffaCV88Tfdj6dzziu5DbdbYaoEuyZvgLwMAomoMCL6M',
  '12U9cbJx97CGaTw2NNhTTe43U9tpLDLHAdJLG5AEahSQ',
  '3n23hYYVLaPhPshijme1BjF2kgGkkSjYLPDGzWwnM6Fs',
  'BiGis9xSwX4iw3eUSZPernSznegZPsbadrHx2eriydp6',
  'AAMMPyCeNA12j8Hs7h6FSCgk3PL68B5jJVpejBUFwpqm',
  '4pDADQdGWcnamrEqWwDVK4WTuhX2PxaV4azLu6h5XGfm',
  '3N68owNn8hJpoH7p87236wzcc21vsCD7WbkNByi8vLAd',
  'Aw9c2EpsQfz2iRzVZZoXQMPUmpGmFBCjkNjqe7k5tnF',
  'ECBkeJJE4HBCgVbQqvFNMp88nRnFEFxcuWR7B89mkKf8',
  '2GTatNwcS1U1Ft5VgMwvq5z9PB4LRmrejx6J3XvNfJXa',
  '3azu13gmjvCWUz6bUvkSiqupNJtxkczGeUuhpB8Gyuxv',
  'FQ7k6LoXRBwUFYrLKhmQfarznW6Xy2fFMGAF1CBPwrDr',
  'BStHbGk6LwTQxJUeKgkhHkbU7cYCnJSWzN53fwJbU5o4',
  '84EqAmdFn7DhhYDvDvVrtPNfVbYqQD4kE4x5QjqfW8ik',
  'CERTHqmoySAo7BEFczVVQpSoVaggi42mzyRa31THTZjS',
  '8jVoiAcgnre5VhSSHErydNRXYkrW6qgLX6TmgAGnuGgA',
  '8j7TeoXVmXwskYCj5UzVis4eTJCB1Xw8u4XMqkAxMmNK',
  'td8xEZenWWbYuvMCCE4LAAcdoBWcRsHYpVzq4YfcXkU',
  '47gcjeExuzHFTBpNAs6ArUhpgdyB74GpV7waEqkiLxRJ',
  'dZdcU6QjwD2p5aC4hev5skhMpvggLm4E7H5XiMA7FFL',
  '2fvwM6iuxi9qnhQztSmKAZa1jPu4wzqUwCvrHfo7sSWg',
  '5RfyTbeHkG7KmowzG83te9sV2GjfTp1X4v1HYmTRswAN',
  '6Dtrn7EVMxAmTTEoiadQJkEXktpXTAFsjx3xvupPE9zT',
  'FYwWC9KNoo7tVSK1va2zZ3dEbLtSpMNjQuvLr5hUFapd',
  'AwEBuQqB2cSoNC4s7EkNzvFLTWqtk79en3aDDLYTrhHo',
  'HSE7V3Fy37S7smGtBC7vfaJdRyPwhQuLnp9h9F4LisZn',
  '7KJS7kjmc9tARYm6PUpB4vooD4Z6fHB7kgdNk8LgfdwV',
] as const

const DEVNET_POOL0_ALT_ENTRIES = [
  'AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3',
  '5Bvt5f5QMfsVb9TyX8bzkRMvAX6JSWwRtnymGveF9U3G',
  '3aMtBvVMatfBvoBWQaTxCPwQ2SWyW5ejceVgLFTtk2WF',
  'DS1YN7kcfP2WVrkcnHB93vEJEdqxSg3MPZwwqVRJeHbK',
  'ANHAcKYiutzcvcgbGWrWZu4NHDcwhy3a4KrX2WK7LD4u',
  '11111111111111111111111111111111',
  'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
  'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
  'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL',
  'ComputeBudget111111111111111111111111111111',
  'So11111111111111111111111111111111111111112',
  '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
  'Gt8hMsfF5A3UepD52wifodYfxgYdSnDpmLvaA6f9aUXr',
  'JBZMSvACBce2j6W7tPxroAB11E9Hujq2DaRnWhNVZwmz',
  'HhCwAZUY3pYLmYVQer3PuytbFVdYzwrtygsYSaUak7ex',
  '7W6DhkuNDzWjaF2wyevZzzSLCtnwX5cCNUKywVPC2E2o',
  'Dm1HP34tohNH2FeXGMttQu8pDmDFzbSsNcv7i25szHY9',
  'HqeWpJUAoxupBZJZskruy7QWVYirsuro2isoRPfvLAHb',
  'AkvqobVhYrJfkVbQb8VWPM1oa8NBhge2kUKo4AeJiByV',
  'GHoEHs4wyfp4WBSydyeFoqEFMFDeT146bxEQVWVhESpW',
  'J3ce6Ps9e5xReqjp5ytfmC96FjMjhWdwR7onrapCG2hK',
  'C558yHEmkU5kyFLugfn1Rwys2MxmZe9x9P7BQ5CbiHoL',
  'A3gE8FEzNfDbwnhNjuXnB5k74HojLduaxEUmrp6xj5Hc',
  'GcSZyqAwq5EpEpC3fv6NLLZQmV9pLahsr49tyj7fNe5r',
  'AJFrTGiSbJsiXfQA5cZQVF566NEU15yBYzLRTU7J2Hay',
  '5ShNay1WsYSC83T3QD9RhiHZip8U22tvPRU439nAXudE',
  'GBspRTkRNmEgxNFBPi5zFDqJ994JMAerZxFe4EjFzJgJ',
  '68jqT6q3eemHXaZD4B3zsbsH3vfmwYRBYvF4WgiCjj1J',
  '3zYiwbQeZaivqqPeXgiszJwY1k4FJVZ59ddd838vAuc4',
  '71QtLeHQRy8DjjMHmD81AyLKPNV19Lj12796JaWJQuK5',
  'GP6nHVaLnVo8qhFaVNdiudfDsrrLQKVzmkSh7jwShuVw',
  'C4HodgHSr2fap3Pchmjk7PNH3q5XHmPkfXS2phCggsiZ',
  '7hSXos52GWSfg44pkq4rAnWRPu7iN6nkhPDDbSKQ35WN',
  'DWzeE42oXKksQ1DdQLw7GrigVdEmB1uNbBSz7ycWitin',
  'EjbXT5ma4zq5voFdeHyRHCU4WgrPPq3RdeEZrLV6usbZ',
  'Ffn7csL3Zo1DnJGN5YTvhBLKbdS7Kv4J3CpYKSyQPF6W',
  'DCMnnPzACohDAE76Kx5fiLnKwbFUv8e3WhzFAaqkR7aW',
  'CivYvThHyhrRVLeADiW7gqDJxFHWVFXyRmoMKkvRLLMw',
  'Bgfd5wRAsJyoL5wzFjvQyNmFq16uDY9poQ6xuFeucd8t',
  '4jcT5jkHjqXeE2uVGu2cEzrzwguUyQj3aFx8B4DGjmRy',
  '249YJTuRtiKAnh346Tc18kF9bHrktdrTzyJMtvUKUgC7',
  'AYgqaqm7JNdxQMQWY4MAHwSWazDc9xtiBboUM7NMmLgJ',
  'EtGkmd1Cfb2eEfiqPXJBtrFir7BGpXSGvaTpVTyVGtxH',
  '9mbMiSbEvd6uuxZyGZvbnyWLJb2vbQzEKUZwVHqjTvWc',
  '2K8P3q2beqLL9SCZi35fGNdw5X11XdowbaGN5u7WozMp',
  '92mmqRnXSchTa86HmDC2mksgCq6Ygg9ui8ECeX3e2vBX',
  '6ffaCV88Tfdj6dzziu5DbdbYaoEuyZvgLwMAomoMCL6M',
  '12U9cbJx97CGaTw2NNhTTe43U9tpLDLHAdJLG5AEahSQ',
  '3n23hYYVLaPhPshijme1BjF2kgGkkSjYLPDGzWwnM6Fs',
  'BiGis9xSwX4iw3eUSZPernSznegZPsbadrHx2eriydp6',
  'AAMMPyCeNA12j8Hs7h6FSCgk3PL68B5jJVpejBUFwpqm',
  '4pDADQdGWcnamrEqWwDVK4WTuhX2PxaV4azLu6h5XGfm',
  '3N68owNn8hJpoH7p87236wzcc21vsCD7WbkNByi8vLAd',
  'Aw9c2EpsQfz2iRzVZZoXQMPUmpGmFBCjkNjqe7k5tnF',
  'ECBkeJJE4HBCgVbQqvFNMp88nRnFEFxcuWR7B89mkKf8',
  '2GTatNwcS1U1Ft5VgMwvq5z9PB4LRmrejx6J3XvNfJXa',
  '3azu13gmjvCWUz6bUvkSiqupNJtxkczGeUuhpB8Gyuxv',
  'Gqy8cEKyx1xoxktjPcuFXyifxBuNFZt8px3NRU6nryRm',
  '4wsQg7DoLmoSbN5ppRZ3A3Z6aYJ9x5b8wmGAFi8jajGb',
  'GcoZhMKRuhNB7Gn1nhVPPwifCGzRm8s52bEQ1nxfUQX',
  '4RbdtAxsSdjCVSCNCEYBxpj7Jbiw8LfZqLMaBSwaHYeB',
  '2En9oY5e5ngGDZQkAWmKEXSEdQhMcGR8c8bE4bkcd7TT',
  '45GucMqtt1pVhbZMn5Lgpu2UyaDkMZw1C5sGYW4xczZJ',
  'ApihKVa4Eo7SKkFspPgATuLacTxngUQCFXWk27PjVhiu',
  'AJWSU1cFUtxZdukbDJod5bRktP6X1kceM6ssUFGtP3E1',
  '8HotADjA5anwzeubrRSpguK1Z5w8xaxF2MkseKGnzRxa',
  'CLhTvE417RuHNjkNX5rPBTSNRdPSvvwxBx3g7DDZSNzd',
  '3Q7RNKXRjRYLJ42HJeS1D7cXY2ZDi9Wvppd1h966xoiB',
  'Fjda34jwhBeh1ePKPAmKPbvq3aiRdsru2GSbmFD7DMop',
  '8zRm7TvYhtHuyBrQFraiiEKYxbh64EHuGJ3W8VxQ1kD7',
  'DKYu9PATjDtseBSmXTpn7UJam2zMeh8FZDWDSKTC9ZDY',
  'G2GtvHYPKPMjxjRnQZvo3TwctEmzNY4Rb5YvFFTK3DwP',
  'AMJ24KLWp57Wa42tarERFG7KjqJnNyaT6n9SA2ADVBkM',
] as const

export const AUDREN = {
  version: '1.3.0',
  protocolVersion: 1,
  releaseTag: 'v1.3.0',
  // The release actually running on Mainnet (the build verifiedCommit / executableHash / elfSha256 describe).
  // It can trail `version` while a newer source release awaits its deploy ceremony.
  deployedReleaseTag: 'v1.3.0',
  deployedReleaseUrl: 'https://github.com/audren-xyz/audren/releases/tag/v1.3.0',
  // Holds both the program upgrade authority and the Pool #0 authority (a single key, not a multisig).
  operatorAuthority: '3WzAUVNX5tm9gJWS2Y2Vg3wMnAtTm23fFX2jHaYy67bV',
  verifiedCommit: '385d032129d90483e4394d7a1f2d5cae012b9d4a',
  vkProvenance:
    'Hermez Perpetual Powers of Tau (54 contributions + beacon) + Audren BGM17 Phase-2 Ceremony (2 contributions · drand #34194203 · Solana slot 472705896 · pre-audit)',
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
  rootsPda: '249YJTuRtiKAnh346Tc18kF9bHrktdrTzyJMtvUKUgC7',
  vaultAuthPda: '3aMtBvVMatfBvoBWQaTxCPwQ2SWyW5ejceVgLFTtk2WF',
  idlPda: '5QoLwK1C3NpUXjsHEV14RsQE65MaaiT9WxGvoTyxBPsn',
  securityPda: 'GU7K3e7p8zUHoKQuQ1fidi9atxQc3UN1e3Q1Xomzs2Lj',
  otterVerifyPda: 'FUQpuou8R4iDA5iMVTZiCB6X8uMdWdhSXxgo85Viv4Qt',
  elfBytes: 158_056,
  sourceElfBytes: 158_056,
  elfSha256: 'b529626e54571b5c244fd85b20db73ff15795c4bdc40329e5721a84e5f672996',
  executableHash: '661bfc0d7582349f8bdd67cc6cf8cde72840322032e3183df819c701c642b100',
  pkCompressedBytes: 3_927_280,
  pkCompressedSha256: '2b22603e466c79b6710e01898dc8b458b09a3ee905b25db996f0c59e76187ee4',
  securityEmail: 'security@audren.xyz',
  githubOrg: 'https://github.com/audren-xyz',
  githubCore: 'https://github.com/audren-xyz/audren',
  githubRelease: 'https://github.com/audren-xyz/audren/releases/tag/v1.3.0',
  githubExamples: 'https://github.com/audren-xyz/examples',
  osecVerifyStatusUrl: 'https://verify.osec.io/status/AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3',
  relayUrl: 'https://relay.audren.xyz',
  mainnetRelayer: 'H2JcTKgrP5Hqj7v2hTuz5u6Tt1VB8yrznotT62hhp3vY',
  devnetRelayer: 'G3tGgntjaDAcamZX2Jcgn616PrjArKYdGXv5C13MzMP',
  mainnet: {
    slot: '474,171,894',
    deployTx: 'Rs8FmnsumQqg1RJbHXuscrKyKxr78SpuaenW3EjKFNu2pCkbXyQTzBD1mFn9Dm74ZN9M3K2m8DaJuL8JCVxLmfN',
    initPoolTx: '5PXHvSPRzMhXYHzidnoafHe6VVR5GN3ATXBT5Vxw7fovfnzvYnqEPiW1qgRRYXZkwr9L2QT7t1o1qDGKUhv4BJKt',
    initRootHistoryTx: '3JLHJn1Bb6CraQeSRKx7x92d2vZAC7qf23Mb39o7k4WLUXDNxu9LB9sgjy6G6UGGxQy1o3n5yYt7yh4XMadXemGE',
    depositTx: '2sxVUPJL4V5EUeXg66jV7Spg4ASMwLE5TCS3Mzyzt37sHuiTFn41B1EwfMevMy9EFVNhgWeeMbdDjYzPTuvnSWPY',
    transferTx: '2tYSzyMcSTJpgYXGiWe1uZJLxjZagQobSsVjcnzm4cy86Mty359VHUKJdHaqG6d5FTqRSYS7qZCECfistrzKtXV3',
    swapTx: '2NDZwvx1uNxhCSYJSZQiodXSWEcaVY6NxPkBDZreDdrcdPtxSXks9PRfSPsKXZFPPHnPNxTMHMrdkkpng2cHj9y6',
    dflowSwapTx: '22NM7tGVsvU78mcWvMqRhxLU8vUuGzpAwaF4XFCvhHa4KPnYz5xqJceLqpQzZLcAP8X7Ypb45774mMPF4D84hLTm',
    lstSwapTx: '44U2GhtPtWT1Z1D9ynMfC2bvfTqte89sHr1K6eLPNMSfXpqcvKVvyAumE1JXdmoS383fZNrPrbEJeUtKSG58gyuX',
    lstUnwindTx: '2aUmfHvrMnioZKReuWGaaRCgvKDxzVPubsR1S2KkkAqq3BMhczvJDVK9BxY32FW2N7H4gDT2dfzCw9HPBs2NWKee',
    jlpSwapTx: '5x5WEQEppNed3EurWLcLABJ7KY9Ugb3o9GVrUxZsHu7Cmfpz7vxt5NdfPF2JDvUP1p4oMwzqPhijLdjxsTwpgaTt',
    jlpUnwindTx: '4VPnUut1CSooEUUFCiEErdBJQzWkekasAMAPcreRcWZEvTEDVfBdHAfkzcJv1ayKaU1Nr6ApTtvb5P9zzweNk6KN',
    lendingSupplyTx: '4CWAS6AexKHc8ZnBDtKXx2teBcfpMA57RkymdRTpxottrF7bVwgTozVwAGpYhUCp9ordizZGZkRe8JtnLXXcUU1J',
    lendingRedeemTx: '5LUiEAPLuouee5jFF2hcdgH4BhLYXS57SxQJr1JP43ScH3JnsHxiBzGJBjdtuqJWy9RiBNgmAXvu9vATRG3Jr1ZD',
    vaultDepositTx: '58owZkFXkZ8a2jG2Ntv3fWYMMnwvpFbyHa5ro3hchNokLj4Ee6kYrjce9ixMJx1vLiKTYDQ84U7Ly1HM61TzvTHh',
    vaultWithdrawTx: '3PsDrm3vabFByqtaxmvBxcefYZwj6s1hGxTNNwzgmFgoMP2PiGR35vvp69jzvV6DoN5KdoHVV3ZQX6yMpsvTvuaq',
    sessionFundTx: '5M9PcjyJjQR8RBk13YhSqZkFoKtRXiVn9E5bGUaAm23QRPmribb3KoVuCQAehF4TKn44YQUULAERXd8oWnYTrZ5v',
    sessionSweepTx: 'SQgWxMmLYHbDGAk2hcTWcHNhQBXxXLUaZ2qjo3P3SyNdFMNfZV1URu2omgCLUmnxf4AJc4aLGsA4HryBkX1Z5Ns',
    withdrawTx: '4mkKXz4cLt5Z3qj5m6xgFoRvtzQ8d5VFYYSkXvnnkxfKn7F9anoBiXa2uTK73DeqwGhC6okfCMxeG7bKr2y5KQc7',
    pool0Alt: {
      address: 'CJgLKw3FTErb3MhmkphyMv28gBxmqSfjfATXypabmL3A',
      entries: MAINNET_POOL0_ALT_ENTRIES,
    },
  },
  devnet: {
    slot: '526,529,051',
    deployTx: '35bKb21GDGDC9JwWjXTj4ZngqzoPeHXsuR7Vwu4m9zUTbY1sGqJpcgF7oroa4i7bns5fj66nfQ49WqDLBiCSedxG',
    initRootHistoryTx: '4omckSRcLCfjoW3WXr9sfDwvdcxsVAPtzpXgPQJDfqdnn1bnCMTNeJfwNJmeUfzfeCVn6CwSngidwczPa686Dwzz',
    transferTx: '3JN8JSiaSdkGkanL8Zv9pmVvpCRNHTjVCuCJTjRsJhXLZMjks6TzPLcKBsy6vumNjQVry1vjoNZZpAq6uStzTYyw',
    withdrawTx: '3f9sdXe5GvTkXJAJ9bbZ4pJM4NsxnNQnxDZxsXmztCS9qxh76SmTGiCP9Q81SifCy9i759sTpqCZgcNgXbvWTtFu',
    pool0Alt: {
      address: '7bwvhuVsmjjXJ1ZPMw2RQpkdwnYKy7upobbdV4FKrCry',
      entries: DEVNET_POOL0_ALT_ENTRIES,
    },
  },
} as const

export function getPool0LookupTable(cluster: 'mainnet' | 'devnet'): Record<string, string[]> {
  const alt = cluster === 'devnet' ? AUDREN.devnet.pool0Alt : AUDREN.mainnet.pool0Alt
  return { [alt.address]: [...alt.entries] }
}

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
  '27G8MtK7VtTcCHkpASjSDdkWWYfoqT6ggEuKidVJidD4': {
    symbol: 'JLP',
    name: 'Jupiter Perps LP',
    decimals: 6,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  B8V6WVjPxW1UGwVDfxH2d2r8SyT4cqn7dQRK6XneVa7D: {
    symbol: 'cUSDC',
    name: 'Kamino Lending USDC Collateral',
    decimals: 6,
    tokenProgram: CLASSIC_TOKEN_PROGRAM_ID,
  },
  FFC3xZPuie63y2iq7WFz8JQg9Dxa5E1kn8FDQpE3GJ31: {
    symbol: 'kPrimeUSDC',
    name: 'Kamino Prime USDC Vault Shares',
    decimals: 6,
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
    ix: 'InitLane (Tag 1)',
    cu: 36_665,
    maxCu: 36_665,
    budgetCu: 75_000,
    note: 'Authority-signed lane activation (4 at launch, expanding monotonically 4 → 8 → 16) · creates LaneTreeState (1,824 B), LaneRentVault, and seq-0 pages',
  },
  {
    ix: 'OpenPage (Tag 2)',
    cu: 13_514,
    maxCu: 13_514,
    budgetCu: 40_000,
    note: 'Idempotent page pre-allocation auto-prepended inline by wallets and relayers · LaneRentVault subsidized · zero background cranks',
  },
  {
    ix: 'InitRootHistory (Tag 4)',
    cu: 17_169,
    maxCu: 41_755,
    budgetCu: 75_000,
    note: 'One-shot GlobalRootHistory (AUD1RT01, 10,216 B) setup across 4 to 16 active lanes (17,169 CU at 4 lanes, 41,755 CU at 16 lanes) · dual ring (64–128 active slots / ~13.8s–27.5s recent + >= 2,848 slots / >= 10.2m stable) updated inline on every deposit and spend',
  },
  {
    ix: 'Deposit · SOL & SPL / Token-2022 (Tag 3)',
    cu: 53_971,
    maxCu: 55_590,
    budgetCu: 75_000,
    note: 'Unified native SOL (SyncNative WSOL) and SPL / Token-2022 net delta solvency + inline GlobalRootHistory update (~160–222 deposits/slot, ~744–1,033 TPS at ~215ms Alpenglow slots under 12M CU/slot lock inside 100M CU blocks) · Token-2022 Fee+Hook 67,117 CU (140k budget) · 0 ZK proof',
  },
  {
    ix: 'Transact Full Exit · RO roots (Tag 5)',
    cu: 115_691,
    maxCu: 121_091,
    budgetCu: 165_000,
    note: '0-output full exit with read-only GlobalRootHistory (zero global write-lock contention across Solana 100M CU blocks) · 192 B BN254 Groth16 · atomic WSOL unwrap · bypasses pool pause',
  },
  {
    ix: 'Transact Withdraw / Unwrap (Tag 5)',
    cu: 144_813,
    maxCu: 217_442,
    budgetCu: 255_000,
    note: '1in/1out to 2in/3out SPL or WSOL unwrap + distinct fee recipient + inline GlobalRootHistory update · Token-2022 + Hook 2in/3out 231,828 CU (295k budget)',
  },
  {
    ix: 'Transact Private Transfer (Tag 5)',
    cu: 204_906,
    maxCu: 204_906,
    budgetCu: 235_000,
    note: 'Global 4^20 MASP (1.099T note capacity) · 2-in/3-out hidden asset, hidden amount + inline GlobalRootHistory update · ~51–58 private transfers/slot (~237–270 TPS at ~215ms Alpenglow slots under Solana 12M CU/slot write-lock cap inside 100M CU blocks)',
  },
  {
    ix: 'ExecViaEscrow + Fee-on-Output (Tag 6)',
    cu: 164_563,
    maxCu: 237_889,
    budgetCu: 285_000,
    note: 'Protocol-agnostic SPL / Token-2022 CPI via 16 sharded escrows + inline root update + 72 B AUD1DYN1 dynamic memo (164,563 1in/0chg mock up to 237,889 2in/2chg+fee 30-acc mock) · 285k base + router CPI (>1.11M CU for DeFi)',
  },
] as const
