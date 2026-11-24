# Audren Canonical Deployments

All addresses below are public on-chain Solana accounts. No private keys or RPC credentials are stored in this repository.

## On-Chain Program (`audren` v1.2.0)

| Field | Value |
|---|---|
| **Program ID (Mainnet & Devnet)** | `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3` |
| **ProgramData Account** | `Gj4hW4KuMTNR9YTPmixRPsNcMNwRvYTXdksxLgoGRiVM` |
| **Protocol Version** | `PROTOCOL_VERSION = 1` (`audren_*` 12-PDA architecture, unified SOL=WSOL, `96` memos/page `10,240 B` `MemoPage`) |
| **Pool #0 PDA (`audren_pool`)** | `5Bvt5f5QMfsVb9TyX8bzkRMvAX6JSWwRtnymGveF9U3G` |
| **GlobalRootHistory PDA (`audren_roots`, v1.3.0)** | `249YJTuRtiKAnh346Tc18kF9bHrktdrTzyJMtvUKUgC7` (bump `254`, `10,216 B` `AUD1RT01` dual-ring root history) |
| **Upgrade & Pool #0 Authority** | `3WzAUVNX5tm9gJWS2Y2Vg3wMnAtTm23fFX2jHaYy67bV` (one operator key, not a multisig) |
| **Deployed vs. source** | Mainnet currently runs v1.2.0 (commit `b60ec02`). Source `v1.3.0` (`156,832 B` sBPFv3 ELF, SHA-256 `811f011247b85465abc72083cd47bfdeef629335ffdba48edc6968c6042a027d`) adds inline dual-ring `GlobalRootHistory` (`249YJTuRtiKAnh346Tc18kF9bHrktdrTzyJMtvUKUgC7`), one-shot `InitRootHistory` (`Tag 4`), zero-crank auto-`OpenPage`, and calibrated tight CU limits (activated atomically during upgrade via `./scripts/upgrade-program.sh <devnet|mainnet>`). |
| **Vault Authority PDA (`audren_vault_auth`)** | `3aMtBvVMatfBvoBWQaTxCPwQ2SWyW5ejceVgLFTtk2WF` |
| **Canonical Pool #0 ALT (Mainnet)** | `Db1aWwM1Tat54Pm3fHdAwYxL6jDWWJzfe3MUR28M3nZ6` (`40` entries, frozen) |
| **Canonical Pool #0 ALT (Devnet)** | `A5FrkN6y3AcMh6fdyp489gTUhPFvVuhmyHTLN3H8esBe` (`40` entries, frozen) |
| **Instruction Architecture** | Solana sBPFv3 (`pinocchio 0.11.1`, `#![no_std]`) + Transaction v1 (`0x81`, `4,096 B`) |
| **ZK Proof Verification** | `192 B` BN254 Groth16 (`17,861` R1CS, 4-ary Depth-20 global MASP) via `alt_bn128` syscall (`groth16-solana`) |
| **Verifying Key Provenance** | Phase 1: Hermez Perpetual Powers of Tau (`powersOfTau28_hez_final_15.ptau`, 54 contributions plus a beacon) · Phase 2: Audren BGM17 ceremony (drand Quicknet `#34194203` + Solana Mainnet slot `472705896`, [`ceremony/transcript.json`](../ceremony/transcript.json)) · Pre-audit |
| **Proving Key (`audren_joinsplit.pk`)** | `3,927,280 B` · SHA-256 `2b22603e466c79b6710e01898dc8b458b09a3ee905b25db996f0c59e76187ee4` |
| **Compiled sBPFv3 ELF** | `162,552 B` · SHA-256 `90ab38268ae434df9aa348784801fd6d4e816cc4d3720b1f7654f6549ef78e7e` · `solana-verify` `f55e117f23ec011365e317518484d292514523a2b1f081cce66506e24925dbcc` |
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
| **Verified Source Commit** | `b60ec029f42551eb4f9678783dee1b73f9ea9f28` |
| **Source Repository** | `https://github.com/audren-xyz/audren` |
| **GitHub Release** | [`v1.2.0`](https://github.com/audren-xyz/audren/releases/tag/v1.2.0) |
| **Explorer / OtterSec Status** | [Mainnet Verified Build](https://explorer.solana.com/address/AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3/verified-build) · [`verify.osec.io`](https://verify.osec.io/status/AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3) |

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
