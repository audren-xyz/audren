# Audren

Zero-setup multi-asset shielded pool, router-agnostic private DEX swap engine, and verifiable compliance protocol on Solana (`sBPFv3`, `pinocchio 0.11.1`, `#![no_std]`).

Native SOL, Classic SPL tokens, and transferable Token-2022 mints share a single shielded pool (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`). Users shield assets, send private transfers across 32/64/128-slot proof rings, execute single-transaction private swaps through compatible PDA-signing Solana routers, and produce selective disclosure or institutional audit proofs — with no trusted setup and no off-chain indexer.

## Privacy and accounting boundaries

Public deposits, withdrawals and external DEX trades are intentional boundaries: their accounts, tokens and amounts remain observable. Private proofs conceal input selection within a candidate set; they do not guarantee that outside information cannot reconnect activity. Compatible relayers are permissionless and optional, hold no user spending keys, and can observe request metadata. Direct submission exposes its fee payer.

Ring capacity is not a count of equally plausible notes or independent users. Empty slots, candidate selection and known public records affect effective anonymity. More TVL alone does not guarantee more privacy. Visible vault assets do not independently prove coverage of private liabilities. See [the specification](ARCHITECTURE.md#privacy-boundaries-and-effective-anonymity) for the operation-specific scope and security assumptions.

## How Audren fits together

```text
  Browser / SDK / Rust Client
    │  1. Scans EpochPage dataSlices via standard Solana RPC
    │  2. Builds Ristretto255 Multi-Base Triptych + Agave Bulletproof locally
    ▼
  Optional Pluggable Privacy Relayer (`apps/relay/`, self-hostable or `relay.audren.xyz` — or Direct wallet)
    │  3. Submits single Solana v1 (0x81) tx (or ProofBuffer chunks via v0 wallet)
    ▼
  Audren sBPFv3 Program (`program/`, AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3)
       • `#![no_std]` Pinocchio 0.11.1 zero-copy entrypoint & stack CPIs
       • Verifies Triptych via native `sol_curve_multiscalar_mul` + precomputed NUMS generators
       • Verifies 64-bit Bulletproofs via native `ZkE1Gama1Proof` CPI
       • Enforces NullifierPDA uniqueness & SwapViaRouter escrow isolation
```

## Repository layout

```text
program/              On-chain sBPFv3 Solana program (#![no_std], pinocchio 0.11.1, lto = "fat")
crates/audren-core/   #![no_std] account layouts, PDA seeds, wire sizes, and AudrenError codes
crates/client/        Rust SDK (provers, RPC/WS scanner, router swap builder, LiteSVM & live tests)
idl/                  Published Codama v1.8.0 & Anchor v0.30+ IDLs, security.json, and verifier
packages/sdk/         Zero-dependency TypeScript ESM SDK (@audren/sdk) + bundled IDLs
apps/relay/           Open-source, self-hostable Cloudflare Worker Privacy Relayer
apps/web/             Next.js 16 + Cloudflare Worker web app, Wallet Vault & Devnet sandbox
tests/mock-router/    Isolated Pinocchio sBPFv3 mock router for adversarial SwapViaRouter tests
scripts/              Deterministic sBPFv3 build helper (`build-sbf.py`) & upgrade/metadata script
docs/                 Self-host relayer guide and canonical deployment addresses
ARCHITECTURE.md       Account byte layouts, cryptographic soundness proofs, and runtime specification
SECURITY.md           Responsible disclosure policy (`security@audren.xyz`)
```

## Published IDLs, Security & Documentation

- **Published IDLs & On-Chain Metadata (`idl/`):** Deterministic Codama v1.8.0 ([`idl/audren.codama.json`](idl/audren.codama.json)) and Anchor v0.30+ ([`idl/audren.anchor.json`](idl/audren.anchor.json)) schemas covering all 13 instructions, 7 account layouts, 10 PDA seeds, and 33 errors — mirrored into `@audren/sdk` (`AUDREN_CODAMA_IDL`, `AUDREN_ANCHOR_IDL`) and published on-chain on Mainnet and Devnet via Solana Program Metadata ([`idl/README.md`](idl/README.md)).
- **Security & Disclosure:** [`SECURITY.md`](SECURITY.md) and canonical on-chain security metadata ([`idl/security.json`](idl/security.json), `security@audren.xyz`), published via Solana Program Metadata (`GU7K3e7p8zUHoKQuQ1fidi9atxQc3UN1e3Q1Xomzs2Lj`) and embedded in the sBPFv3 program binary.
- **Verified Builds:** Reproducible Docker sBPFv3 builds pinned to the Solana Foundation Agave `4.3.0` (`v1.57`) verifiable build image (`solana-verify`) with automated PDA attestation and compliance checks via [`scripts/upgrade-program.sh`](scripts/upgrade-program.sh) ([`docs/DEPLOYMENTS.md`](docs/DEPLOYMENTS.md#solana-verified-builds-verifycly8mb96wd9wqq3wdxqwm4ou6r42th37db9fc)).
- **Protocol Architecture:** [`ARCHITECTURE.md`](ARCHITECTURE.md) — account layouts, Ristretto255 Multi-Base Triptych soundness proofs, swap custody isolation, Token-2022 solvency, and sBPFv3 runtime engineering.
- **Deploy Your Own Relayer:** [`docs/DEPLOY_YOUR_OWN_RELAY.md`](docs/DEPLOY_YOUR_OWN_RELAY.md) — step-by-step guide to deploy an independent Audren relayer with zero shared credentials.
- **Canonical Deployments:** [`docs/DEPLOYMENTS.md`](docs/DEPLOYMENTS.md) — Mainnet & Devnet Program ID, Pool #0 PDA, Program Metadata PDAs, and reference endpoints.

## Instruction set

| Tag | Instruction | Description |
| --- | --- | --- |
| `0x00` | `InitPool` | Create `PoolState` (`192 B`), `EpochPage #0` (`6,240 B`), `sol_vault`, `page_rent_vault` |
| `0x01` | `OpenPage` | Permissionless Lane `0` rollover allocating `page_id + 1` funded by `PageRentVault` |
| `0x02` | `Deposit` | Shield Native SOL, Classic SPL, or Token-2022 to any stealth address (zero ZK proof) |
| `0x03` | `Transfer` | Private 1-in → 2-out transfer (`m = 5/6/7`, Triptych + CrossBase2 + `BatchedRangeProofU128`) |
| `0x04` | `Merge` | Consolidate 2 shielded notes of the same hidden asset into 1 note |
| `0x05` | `SwapViaRouter` | Full or partial shielded swap via isolated `swap_escrow` CPI (`flags & 1` shielded change; `flags & 2` refund) |
| `0x06` | `Withdraw` | Unshield exact amount to a public wallet/ATA; full withdrawals keep `PoolState` read-only and bypass `SetPaused` |
| `0x07` | `SetPaused` | Emergency pause toggle by pool authority (zero vault custody) |
| `0x08` | `WriteProofBuffer` | Upload `<= 768 B` payload chunk into ephemeral `ProofBuffer` PDA (`<= 10,032 B`) |
| `0x09` | `ExecBuffered` | Execute buffered instruction zero-copy and atomically refund 100% of buffer rent |
| `0x0A` | `CloseProofBuffer` | Reclaim 100% of rent from an abandoned `ProofBuffer` PDA |
| `0x0B` | `InitLane` | Initialize parallel append lane `1..15` (`AppendLaneState` + `LaneRentVault` + initial page) |
| `0x0C` | `OpenLanePage` | Permissionless self-funding rollover for parallel lane `1..15` with read-only `PoolState` |

## Quickstart: Verification, Build & Testing

### 1. Fast host checks (Rust + IDLs + TypeScript)
```bash
# Rust typechecks (isolated sBPFv3 manifests + host workspace)
cargo check --manifest-path program/Cargo.toml
cargo check --manifest-path program/Cargo.toml --features no-entrypoint
cargo check --manifest-path tests/mock-router/Cargo.toml
cargo check --workspace --tests

# Verify IDLs match crates/audren-core byte-for-byte
python3 idl/verify-idl.py

# TypeScript SDK, Relayer, and Web UI checks
pnpm --dir packages/sdk typecheck && pnpm --dir packages/sdk test
pnpm --dir apps/relay typecheck
pnpm --dir apps/web typecheck
```

### 2. Compile sBPFv3 `.so` artifacts & run LiteSVM E2E tests
```bash
# Build deterministic sBPFv3 artifacts
python3 scripts/build-sbf.py --manifest-path program/Cargo.toml --sbf-out-dir target/deploy
python3 scripts/build-sbf.py --manifest-path tests/mock-router/Cargo.toml --sbf-out-dir target/deploy

# Run all 7 LiteSVM integration & adversarial suites
cargo test --test litesvm_e2e -- --nocapture
```

### 3. Cluster deployment, Program Metadata & Verified Builds
See [`docs/DEPLOYMENTS.md`](docs/DEPLOYMENTS.md) and [`idl/README.md`](idl/README.md) for deployment addresses, atomic program upgrades (`scripts/upgrade-program.sh`), Solana Program Metadata (`idl` & `security`), and Solana Verified Build attestation. Keep local keypairs in gitignored `.credentials/` and private operator Wrangler configs in gitignored `wrangler.prod.jsonc`.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
