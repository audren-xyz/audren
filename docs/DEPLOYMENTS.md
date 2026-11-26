# Audren Canonical Deployments

All addresses below are public on-chain Solana accounts. No private keys or RPC credentials are stored in this repository.

## On-Chain Program (`audren` v1.3.0)

| Field | Value |
|---|---|
| **Program ID (Mainnet & Devnet)** | `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3` |
| **ProgramData Account** | `Gj4hW4KuMTNR9YTPmixRPsNcMNwRvYTXdksxLgoGRiVM` |
| **Protocol Version** | `PROTOCOL_VERSION = 1` (`audren_*` 12-PDA architecture, unified SOL=WSOL, inline `GlobalRootHistory`, `96` memos/page `10,240 B` `MemoPage`) |
| **Pool #0 PDA (`audren_pool`)** | `5Bvt5f5QMfsVb9TyX8bzkRMvAX6JSWwRtnymGveF9U3G` |
| **GlobalRootHistory PDA (`audren_roots`)** | `249YJTuRtiKAnh346Tc18kF9bHrktdrTzyJMtvUKUgC7` (bump `254`, `10,216 B` `AUD1RT01` dual-ring root history) |
| **Upgrade & Pool #0 Authority** | `3WzAUVNX5tm9gJWS2Y2Vg3wMnAtTm23fFX2jHaYy67bV` (one operator key, not a multisig) |
| **Vault Authority PDA (`audren_vault_auth`)** | `3aMtBvVMatfBvoBWQaTxCPwQ2SWyW5ejceVgLFTtk2WF` |
| **Canonical Pool #0 ALT (Mainnet)** | `CJgLKw3FTErb3MhmkphyMv28gBxmqSfjfATXypabmL3A` (`73` entries, frozen) |
| **Canonical Pool #0 ALT (Devnet)** | `7bwvhuVsmjjXJ1ZPMw2RQpkdwnYKy7upobbdV4FKrCry` (`73` entries, frozen) |
| **Instruction Architecture** | Solana sBPFv3 (`pinocchio 0.11.1`, `#![no_std]`) + Transaction v1 (`0x81`, `4,096 B`) |
| **ZK Proof Verification** | `192 B` BN254 Groth16 (`17,861` R1CS, 4-ary Depth-20 global MASP) via `alt_bn128` syscall (`groth16-solana`) |
| **Verifying Key Provenance** | Phase 1: Hermez Perpetual Powers of Tau (`powersOfTau28_hez_final_15.ptau`, 54 contributions plus a beacon) · Phase 2: Audren BGM17 ceremony (drand Quicknet `#34194203` + Solana Mainnet slot `472705896`, [`ceremony/transcript.json`](../ceremony/transcript.json)) · Pre-audit |
| **Proving Key (`audren_joinsplit.pk`)** | `3,927,280 B` · SHA-256 `2b22603e466c79b6710e01898dc8b458b09a3ee905b25db996f0c59e76187ee4` |
| **Compiled sBPFv3 ELF** | `158,056 B` · SHA-256 `b529626e54571b5c244fd85b20db73ff15795c4bdc40329e5721a84e5f672996` · `solana-verify` `661bfc0d7582349f8bdd67cc6cf8cde72840322032e3183df819c701c642b100` |
| **Published IDLs** | [`idl/audren.codama.json`](../idl/audren.codama.json) (Codama v1.8.0) · [`idl/audren.anchor.json`](../idl/audren.anchor.json) (Anchor v0.30+) |
| **Security Policy & Metadata** | [`SECURITY.md`](../SECURITY.md) · [`idl/security.json`](../idl/security.json) (`security@audren.xyz`) |

## On-Chain Program Metadata (`ProgM6JCCvbYkfKqJYHePx4xxSUSqJp7rh8Lyv7nk7S`)

Canonical metadata accounts published via the Solana Foundation Program Metadata standard:

| Seed | Canonical PDA | Source File | Explorer |
|---|---|---|---|
| `idl` | `5QoLwK1C3NpUXjsHEV14RsQE65MaaiT9WxGvoTyxBPsn` | [`idl/audren.codama.json`](../idl/audren.codama.json) | [Mainnet IDL](https://explorer.solana.com/address/AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3/idl) |
| `security` | `GU7K3e7p8zUHoKQuQ1fidi9atxQc3UN1e3Q1Xomzs2Lj` | [`idl/security.json`](../idl/security.json) | [Mainnet Security](https://explorer.solana.com/address/AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3/security) |

## Solana Verified Builds (`verifycLy8mB96wd9wqq3WDXQwM4oU6r42Th37Db9fC`)

Mainnet releases use deterministic Linux/Docker builds via the Solana Foundation [`solana-verifiable-build`](https://github.com/solana-foundation/solana-verifiable-build) pipeline and OtterSec remote verification:

| Field | Value |
|---|---|
| **Base Docker Image** | `solanafoundation/solana-verifiable-build@sha256:12fd4c0a0790f0fc41ef74b0cdb6bccc167ba6137eb1adb749bac649481c86bd` (Agave `4.3.0`, platform-tools `v1.57`) |
| **Target Architecture** | `sBPFv3` (`--arch v3 --cargo-build-sbf-args="--tools-version v1.57"`) |
| **Workspace / Library** | `--workspace-path program --library-name audren` |
| **Otter Verify PDA (Mainnet)** | `FUQpuou8R4iDA5iMVTZiCB6X8uMdWdhSXxgo85Viv4Qt` |
| **Verified Source Commit** | `385d032129d90483e4394d7a1f2d5cae012b9d4a` |
| **Source Repository** | `https://github.com/audren-xyz/audren` |
| **GitHub Release** | [`v1.3.0`](https://github.com/audren-xyz/audren/releases/tag/v1.3.0) |
| **Explorer / OtterSec Status** | [Mainnet Verified Build](https://explorer.solana.com/address/AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3/verified-build) · [`verify.osec.io`](https://verify.osec.io/status/AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3) |

## Empirically Verified Mainnet Transactions (`v1.3.0`)

The latest deterministic `sBPFv3` binary (`385d032129d90483e4394d7a1f2d5cae012b9d4a`, `158,056 B`) was deployed at Mainnet slot `474,171,894` (verified via OtterSec `verify.osec.io` and 14/14 LiteSVM E2E suites against the exact compiled ELF). The 15 empirical DeFi, lending, vault, transfer, withdrawal, and session-wallet transactions below were executed on Solana Mainnet against the prior `v1.3.0` deployment (`842ada95af872735a6daf187223a310bb9629954`, slot `473,476,583`, sharing the same frozen verifying key and instruction wire format) and `https://relay.audren.xyz`:

| Flow | Instruction & Mode | Mainnet Slot | CU | Transaction Signature |
|---|---|---|---|---|
| **Program Upgrade (`v1.3.0`, current `385d032`)** | `BPFLoaderUpgradeable` deterministic ELF (`158,056 B`) | `474,171,894` | — | `Rs8FmnsumQqg1RJbHXuscrKyKxr78SpuaenW3EjKFNu2pCkbXyQTzBD1mFn9Dm74ZN9M3K2m8DaJuL8JCVxLmfN` |
| **Prior Program Upgrade (`v1.3.0`, `842ada9`)** | `BPFLoaderUpgradeable` deterministic ELF (`157,008 B`) | `473,476,583` | — | `cLnyzjJyqs4nPqsFaA4xPV9hd3SSwyVCryVHsaBd6AxujPU2DGhQP6XYjfKe5KMHJ9PR1AUsmFKt4s67tWPLodv` |
| **Native SOL Deposit** | Tag 3 `Deposit` (`DEPOSIT_FLAG_NATIVE_SOL`) | `473,479,958` | `53,950` | `2sxVUPJL4V5EUeXg66jV7Spg4ASMwLE5TCS3Mzyzt37sHuiTFn41B1EwfMevMy9EFVNhgWeeMbdDjYzPTuvnSWPY` |
| **Relayed Private Transfer** | Tag 5 `Transact` (`2-in/3-out`, 0 user signers) | `473,479,987` | `200,561` | `2tYSzyMcSTJpgYXGiWe1uZJLxjZagQobSsVjcnzm4cy86Mty359VHUKJdHaqG6d5FTqRSYS7qZCECfistrzKtXV3` |
| **Relayed Full Exit + WSOL Unwrap** | Tag 5 `Transact` (`WITHDRAW_FLAG_UNWRAP_WSOL`, self-paying) | `473,480,014` | `117,732` | `4mkKXz4cLt5Z3qj5m6xgFoRvtzQ8d5VFYYSkXvnnkxfKn7F9anoBiXa2uTK73DeqwGhC6okfCMxeG7bKr2y5KQc7` |
| **DEX Swap (Jupiter)** | Tag 6 `ExecViaEscrow` (`WSOL -> USDC`, self-paying) | `473,480,325` | `296,516` | `2NDZwvx1uNxhCSYJSZQiodXSWEcaVY6NxPkBDZreDdrcdPtxSXks9PRfSPsKXZFPPHnPNxTMHMrdkkpng2cHj9y6` |
| **DEX Swap (DFlow)** | Tag 6 `ExecViaEscrow` (`USDC -> WSOL`, self-paying) | `473,480,990` | `323,212` | `22NM7tGVsvU78mcWvMqRhxLU8vUuGzpAwaF4XFCvhHa4KPnYz5xqJceLqpQzZLcAP8X7Ypb45774mMPF4D84hLTm` |
| **Liquid Staking (`JitoSOL`) Entry** | Tag 6 `ExecViaEscrow` (`WSOL -> JitoSOL`, self-paying) | `473,480,353` | `289,405` | `44U2GhtPtWT1Z1D9ynMfC2bvfTqte89sHr1K6eLPNMSfXpqcvKVvyAumE1JXdmoS383fZNrPrbEJeUtKSG58gyuX` |
| **Liquid Staking (`JitoSOL`) Unwind** | Tag 6 `ExecViaEscrow` (`JitoSOL -> WSOL`, `EXEC_FLAG_FEE_ON_OUTPUT`) | `473,480,616` | `313,377` | `2aUmfHvrMnioZKReuWGaaRCgvKDxzVPubsR1S2KkkAqq3BMhczvJDVK9BxY32FW2N7H4gDT2dfzCw9HPBs2NWKee` |
| **Perp LP (`JLP`) Entry** | Tag 6 `ExecViaEscrow` (`USDC -> JLP`, self-paying) | `473,480,642` | `271,751` | `5x5WEQEppNed3EurWLcLABJ7KY9Ugb3o9GVrUxZsHu7Cmfpz7vxt5NdfPF2JDvUP1p4oMwzqPhijLdjxsTwpgaTt` |
| **Perp LP (`JLP`) Unwind** | Tag 6 `ExecViaEscrow` (`JLP -> USDC`, `EXEC_FLAG_FEE_ON_OUTPUT`) | `473,480,671` | `212,079` | `4VPnUut1CSooEUUFCiEErdBJQzWkekasAMAPcreRcWZEvTEDVfBdHAfkzcJv1ayKaU1Nr6ApTtvb5P9zzweNk6KN` |
| **Kamino Lending Supply** | Tag 6 `ExecViaEscrow` (`KLend2g3c...` `USDC -> cUSDC`, `refreshReserve` pre-ix) | `473,480,698` | `294,813` | `4CWAS6AexKHc8ZnBDtKXx2teBcfpMA57RkymdRTpxottrF7bVwgTozVwAGpYhUCp9ordizZGZkRe8JtnLXXcUU1J` |
| **Kamino Lending Redeem** | Tag 6 `ExecViaEscrow` (`KLend2g3c...` `cUSDC -> USDC`, `EXEC_FLAG_FEE_ON_OUTPUT`) | `473,480,724` | `227,959` | `5LUiEAPLuouee5jFF2hcdgH4BhLYXS57SxQJr1JP43ScH3JnsHxiBzGJBjdtuqJWy9RiBNgmAXvu9vATRG3Jr1ZD` |
| **Kamino Yield Vault Deposit** | Tag 6 `ExecViaEscrow` (`KvauGMsp...` Prime USDC `USDC -> shares`) | `473,480,927` | `326,306` | `58owZkFXkZ8a2jG2Ntv3fWYMMnwvpFbyHa5ro3hchNokLj4Ee6kYrjce9ixMJx1vLiKTYDQ84U7Ly1HM61TzvTHh` |
| **Kamino Yield Vault Withdraw** | Tag 6 `ExecViaEscrow` (`KvauGMsp...` `withdrawFromAvailable`, `EXEC_FLAG_FEE_ON_OUTPUT`) | `473,480,953` | `268,829` | `3PsDrm3vabFByqtaxmvBxcefYZwj6s1hGxTNNwzgmFgoMP2PiGR35vvp69jzvV6DoN5KdoHVV3ZQX6yMpsvTvuaq` |
| **Session Wallet `B_0` Zero-SOL Fund** | Tag 5 `Transact` (`WITHDRAW_FLAG_UNWRAP_WSOL`, relayed, 0 user signers) | `473,481,297` | `152,960` | `5M9PcjyJjQR8RBk13YhSqZkFoKtRXiVn9E5bGUaAm23QRPmribb3KoVuCQAehF4TKn44YQUULAERXd8oWnYTrZ5v` |
| **Session Wallet `B_0` Zero-Dust Sweep** | Tag 3 `Deposit` (`DEPOSIT_FLAG_NATIVE_SOL \| DEPOSIT_FLAG_FEE_FROM_AMOUNT`, `0` lamports left) | `473,481,303` | `52,964` | `SQgWxMmLYHbDGAk2hcTWcHNhQBXxXLUaZ2qjo3P3SyNdFMNfZV1URu2omgCLUmnxf4AJc4aLGsA4HryBkX1Z5Ns` |

## Deployment, Metadata, Verified Build & Release Workflow

Configure RPC URLs and the upgrade authority keypair in environment variables or gitignored `.credentials/operator.env` (`MAINNET_RPC_URL`, `DEVNET_RPC_URL`, `AUDREN_KEYPAIR_PATH`). Every program upgrade runs through `./scripts/upgrade-program.sh`:

```bash
# 1. Regenerate and verify all cross-repo parity invariants
python3 idl/generate-idl.py && python3 idl/verify-idl.py

# 2. Build deterministic Linux/Docker sBPFv3 artifact (`program/target/deploy/audren.so`)
./scripts/upgrade-program.sh build-verifiable

# 3. Upgrade Devnet (deploys ELF + auto-runs [1c] Pool #0 InitRootHistory + syncs & verifies `security` and `idl` metadata)
./scripts/upgrade-program.sh devnet

# 4. Upgrade Mainnet from a clean, pushed commit (deploys Docker ELF + auto-runs [1c] Pool #0 InitRootHistory + metadata + OtterSec verify + GitHub Release)
./scripts/upgrade-program.sh mainnet

# 5. Update `apps/web/lib/protocol.ts` & `docs/DEPLOYMENTS.md` with the new commit / ELF SHA-256 / release tag,
#    verify cross-repo parity (`python3 idl/verify-idl.py`), deploy `apps/web`, then audit live Mainnet compliance:
./scripts/upgrade-program.sh check mainnet
```

## Public Reference Infrastructure (Optional)

Audren is permissionless and relayer-agnostic — you may use direct self-pay transactions, the reference endpoints below, or deploy your own relayer ([`docs/DEPLOY_YOUR_OWN_RELAY.md`](DEPLOY_YOUR_OWN_RELAY.md)).

| Service | Endpoint | Public Signer Address |
|---|---|---|
| **Reference Web App** | `https://audren.xyz` | — (holds no Mainnet relayer key) |
| **Reference Privacy Relayer (Mainnet)** | `https://relay.audren.xyz` | `H2JcTKgrP5Hqj7v2hTuz5u6Tt1VB8yrznotT62hhp3vY` |
| **Reference Privacy Relayer (Devnet)** | `https://relay.audren.xyz` | `G3tGgntjaDAcamZX2Jcgn616PrjArKYdGXv5C13MzMP` |
