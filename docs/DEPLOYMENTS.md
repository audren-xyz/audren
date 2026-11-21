# Audren Canonical Deployments

All addresses below are public on-chain Solana accounts. No private keys or RPC credentials are stored in this repository.

## On-Chain Program (`audren`)

| Field | Value |
|---|---|
| **Program ID (Mainnet & Devnet)** | `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3` |
| **ProgramData Account** | `Gj4hW4KuMTNR9YTPmixRPsNcMNwRvYTXdksxLgoGRiVM` |
| **Mainnet Pool #0 PDA** | `5Bvt5f5QMfsVb9TyX8bzkRMvAX6JSWwRtnymGveF9U3G` |
| **Instruction Architecture** | Solana sBPFv3 (`pinocchio 0.11.1`, `#![no_std]`) + Transaction v1 (`0x81`, `4,096 B`) |
| **ZK Proof Verification** | Multi-Base Triptych (Ristretto255 syscalls) + native Agave `ZkE1Gama1Proof11111111111111111111111111111` Bulletproofs |
| **Published IDLs** | [`idl/audren.codama.json`](../idl/audren.codama.json) (Codama v1.8.0) · [`idl/audren.anchor.json`](../idl/audren.anchor.json) (Anchor v0.30+) |
| **Security Policy & Metadata** | [`SECURITY.md`](../SECURITY.md) · [`idl/security.json`](../idl/security.json) (`security@audren.xyz`) |

## On-Chain Program Metadata (`ProgM6JCCvbYkfKqJYHePx4xxSUSqJp7rh8Lyv7nk7S`)

Canonical metadata accounts published on both **Solana Mainnet** and **Solana Devnet** via the Solana Foundation Program Metadata standard:

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
| **Source Repository** | `https://github.com/audren-xyz/audren` |
| **Explorer / OtterSec Status** | [Mainnet Verified Build](https://explorer.solana.com/address/AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3/verified-build) · [`verify.osec.io`](https://verify.osec.io/status/AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3) |

## Deployment, Metadata & Verified Build Workflow

Configure RPC URLs and the upgrade authority keypair in environment variables or gitignored `.credentials/operator.env` (`MAINNET_RPC_URL`, `DEVNET_RPC_URL`, `AUDREN_KEYPAIR_PATH`).

Every program upgrade must run through `./scripts/upgrade-program.sh` so IDLs, Security metadata, and Mainnet Verified Build attestation stay strictly synchronized with the deployed binary:

```bash
# 1. Regenerate and verify local IDLs, security.json, .security.txt, and toolchain pins
python3 idl/generate-idl.py && python3 idl/verify-idl.py

# 2. Build deterministic Linux/Docker sBPFv3 artifact (`program/target/deploy/audren.so`)
./scripts/upgrade-program.sh build-verifiable

# 3. Upgrade Devnet (deploys ELF + syncs & verifies `security` and `idl` metadata)
./scripts/upgrade-program.sh devnet

# 4. Upgrade Mainnet from a clean, pushed commit (deploys verifiable ELF + syncs `security`
#    and `idl` metadata + updates Otter Verify PDA + submits remote verification job)
./scripts/upgrade-program.sh mainnet

# 5. Audit live cluster compliance (local parity + on-chain `security`/`idl` + Verified Build status)
./scripts/upgrade-program.sh check mainnet
```

## Public Reference Infrastructure (Optional)

Audren is permissionless and relayer-agnostic — you may use direct self-pay transactions, the reference endpoints below, or deploy your own relayer ([`docs/DEPLOY_YOUR_OWN_RELAY.md`](DEPLOY_YOUR_OWN_RELAY.md)).

| Service | Endpoint | Public Signer Address |
|---|---|---|
| **Reference Web App** | `https://audren.xyz` | — (holds no Mainnet relayer key) |
| **Reference Privacy Relayer (Mainnet)** | `https://relay.audren.xyz` | `H2JcTKgrP5Hqj7v2hTuz5u6Tt1VB8yrznotT62hhp3vY` |
| **Reference Privacy Relayer (Devnet)** | `https://relay.audren.xyz` | `G3tGgntjaDAcamZX2Jcgn616PrjArKYdGXv5C13MzMP` |

Verify live relayer balances, rent schedule, and active DEX aggregators at any time:
- `GET https://relay.audren.xyz/v1/info?cluster=mainnet`
- `GET https://relay.audren.xyz/v1/info?cluster=devnet`
