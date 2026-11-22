<p>
  <a href="https://audren.xyz">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="assets/brand/audren-wordmark-dark.svg" />
      <source media="(prefers-color-scheme: light)" srcset="assets/brand/audren-wordmark-light.svg" />
      <img alt="Audren — Private money on Solana" src="assets/brand/audren-wordmark-light.svg" height="52" />
    </picture>
  </a>
</p>

<p>
  <a href="https://github.com/audren-xyz/audren/actions/workflows/ci.yml"><img src="https://github.com/audren-xyz/audren/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/audren-xyz/audren/releases/tag/v0.3.0"><img src="https://img.shields.io/badge/release-v0.3.0-121210" alt="Release v0.3.0" /></a>
  <a href="https://explorer.solana.com/address/AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3/verified-build"><img src="https://img.shields.io/badge/Solana%20Verified%20Build-sBPFv3-184433" alt="Solana Verified Build" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-434039" alt="Apache-2.0 License" /></a>
  <a href="https://audren.xyz"><img src="https://img.shields.io/badge/app-audren.xyz-C83E2B" alt="audren.xyz" /></a>
</p>

**Private money on Solana. Existing tokens. One shared pool.**

Audren is an open-source, self-custodial privacy protocol on Solana (`sBPFv3`, `pinocchio 0.11.1`, `#![no_std]`). Native SOL, Classic SPL tokens, and transferable Token-2022 mints share one permissionless pool (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`). Shield assets without wrapper tokens, send private transfers across 32/64/128-slot rings, compose with Solana DeFi via protocol-agnostic `ExecViaEscrow` CPI (DEX swaps, lending supply, yield vaults, liquid staking, perp LP, RWAs), fund 0-SOL wallets or deterministic DeFi session keypairs with self-paying fees & atomic WSOL unwrap, sweep back with zero dust, and generate selective receipts — with local proofs, keys you control, no trusted setup, and no off-chain indexer.

## Privacy and accounting boundaries

Public deposits, withdrawals, external DeFi CPI calls (`ExecViaEscrow`), and stateful positions opened by deterministic session wallets (`B_0, B_1…`) are intentional boundaries: their accounts, programs, tokens and amounts remain observable on Solana. Private proofs conceal input selection within a candidate set; they do not guarantee that outside information cannot reconnect activity. Compatible relayers are permissionless and optional, hold no user spending keys, and can observe request metadata. Direct submission exposes its fee payer.

Ring capacity is not a count of equally plausible notes or independent users. Empty slots, candidate selection and known public records affect effective anonymity. More TVL alone does not guarantee more privacy. Visible vault assets do not independently prove coverage of private liabilities. See [the specification](ARCHITECTURE.md#privacy-boundaries-and-effective-anonymity) for the operation-specific scope and security assumptions.

## How Audren fits together

```text
  Rust / TypeScript / Swift (iOS) / Kotlin (Android) SDK
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
       • Enforces NullifierPDA uniqueness, ExecViaEscrow custody isolation & atomic WSOL unwrap
```

## Official SDKs (4 Languages, 1 Shared Conformance Spec)

All four official Audren SDKs share the exact same **6 standardized building blocks** (`keys`, `pda & layout`, `scanner`, `prover`, `disclosure & audit`, `relayer & idl`), consumed directly from source (zero package-registry lock-in) and proven byte-for-byte in CI against one shared canonical vector suite ([`spec/test-vectors.json`](spec/test-vectors.json)):

| Language | Package Path | Engine | Target Runtime | Local Proof Speed (`m=5`) |
|---|---|---|---|---|
| **Rust** | [`crates/client/`](crates/client/Cargo.toml) | Native `audren-client` | Services, CLIs, bots, validators | ~50 ms |
| **TypeScript** | [`packages/sdk/`](packages/sdk/README.md) (`@audren/sdk` + `@audren/sdk/prover`) | Zero-dep core + pure-TS `@noble/curves` prover | Browsers, Node 22+, Cloudflare Workers | ~0.8–1.5 s |
| **Swift (iOS / macOS)** | [`packages/swift/`](packages/swift/README.md) (`AudrenSDK`) | UniFFI over `crates/audren-ffi` (`audren-client`) | iOS 15+, macOS 13+ (`XCFramework` / SwiftPM) | ~50 ms |
| **Kotlin (Android / JVM)** | [`packages/kotlin/`](packages/kotlin/README.md) (`xyz.audren.sdk`) | UniFFI + JNA over `crates/audren-ffi` (`audren-client`) | Android API 24+ (`jniLibs`), JVM 21+ | ~50 ms |

Runnable examples for all 4 languages — verified in CI for **100% byte-for-byte canonical stdout parity** (`Rust == TypeScript == Swift == Kotlin`) — live in [`audren-xyz/examples`](https://github.com/audren-xyz/examples).

### The 6 Standardized Building Blocks Across All 4 SDKs

1. **Keys** — `deriveKeysFromSeed`, `deriveSubaccountKeys`, `deriveDefiSessionKeypair`, `parseAudrenAddress`, `formatAudrenAddress`, `exportFullViewingKey`, `assetGenerator`
2. **PDAs & Layouts** — all 11 canonical PDAs (`pool`, `epoch_page`, `sol_vault`, `vault_auth`, `page_rent_vault`, `swap_escrow`, `unwrap`, `lane`, `lane_rent_vault`, `nullifier`, `proof_buffer`), `deriveAssociatedTokenAddress`, lane `page_id` bit-packing, `decodePoolState`, `decodeEpochPageHeader`, `decodeAppendLaneState`
3. **Scanner** — `dataSlice: { offset: 64, length: 1056 }` view-tag filtering (`scanPageDataslice`), read-only FVK & spendable note decryption (`scanEpochPage`) with per-slot decoy fault isolation
4. **Prover** — local proof generation & instruction builders (`Deposit` incl. `fee_from_amount`, `Transfer`, `Merge`, `ExecViaEscrow` incl. native `relayer_fee`, `Withdraw` incl. native `relayer_fee` & atomic `unwrap_wsol`, `ProofBuffer`, `CloseProofBuffer`, `OpenPage`, `OpenLanePage`)
5. **Disclosure & Audit** — Mode 1 Selective Disclosure proof (64-bit safe across parallel lanes `1..15`) + standalone/on-page verify, Mode 2 Full Viewing Key, and Institutional Auditor ElGamal decryption
6. **Relayer, Escrow CPI & IDLs** — `DEFAULT_RELAY_URL`, `prepareEscrowAccounts`, `JUPITER_CPI_EXCLUDED_DEXES`, Solana v1 (`0x81`), Codama v1.8.0 & Anchor v0.30+ IDLs (`47` synced UniFFI exports verified by `idl/verify-idl.py`)

## Repository layout

```text
program/              On-chain sBPFv3 Solana program (#![no_std], pinocchio 0.11.1, lto = "fat")
crates/audren-core/   #![no_std] account layouts, PDA seeds, wire sizes, and AudrenError codes
crates/client/        Rust SDK (provers, RPC/WS scanner, router swap builder, LiteSVM & live tests)
crates/audren-ffi/    UniFFI native FFI layer backing the Swift (iOS/macOS) & Kotlin (Android/JVM) SDKs
packages/sdk/         TypeScript SDK (@audren/sdk zero-dep core + @audren/sdk/prover pure-TS prover)
packages/swift/       Swift SDK (AudrenSDK SwiftPM package + iOS XCFramework build script)
packages/kotlin/      Kotlin SDK (xyz.audren.sdk Gradle/JVM + Android jniLibs build script)
spec/                 Canonical cross-language conformance vectors (spec/test-vectors.json)
idl/                  Published Codama v1.8.0 & Anchor v0.30+ IDLs, security.json, and verifier
apps/relay/           Open-source, self-hostable Cloudflare Worker Privacy Relayer
apps/web/             Next.js 16 + Cloudflare Worker web app, Wallet Vault & Devnet sandbox
tests/mock-router/    Isolated Pinocchio sBPFv3 mock router for adversarial ExecViaEscrow tests
scripts/              Deterministic sBPFv3 build helper (`build-sbf.py`), upgrade script & mobile SDK builder
assets/brand/         Canonical Audren SVG/PNG logos, README wordmarks, and social preview cards
docs/                 Self-host relayer guide and canonical deployment addresses
ARCHITECTURE.md       Account byte layouts, cryptographic soundness proofs, and runtime specification
SECURITY.md           Responsible disclosure policy (`security@audren.xyz`)
CONTRIBUTING.md       Contributor workflow and zero-drift verification checklist
```

## Published IDLs, Security & Documentation

- **Published IDLs & On-Chain Metadata (`idl/`):** Deterministic Codama v1.8.0 ([`idl/audren.codama.json`](idl/audren.codama.json)) and Anchor v0.30+ ([`idl/audren.anchor.json`](idl/audren.anchor.json)) schemas covering all 13 instructions, 7 account layouts, 11 PDA seeds, and 33 errors — mirrored into `@audren/sdk` (`AUDREN_CODAMA_IDL`, `AUDREN_ANCHOR_IDL`) and published on-chain on Mainnet and Devnet via Solana Program Metadata ([`idl/README.md`](idl/README.md)).
- **Security & Disclosure:** [`SECURITY.md`](SECURITY.md) and canonical on-chain security metadata ([`idl/security.json`](idl/security.json), `security@audren.xyz`), published via Solana Program Metadata (`GU7K3e7p8zUHoKQuQ1fidi9atxQc3UN1e3Q1Xomzs2Lj`) and embedded in the sBPFv3 program binary.
- **Verified Builds & Releases:** Reproducible Docker sBPFv3 builds pinned to the Solana Foundation Agave `4.3.0` (`v1.57`) verifiable build image (`solana-verify`) with automated PDA attestation, GitHub Releases, and zero-drift CI verification via [`scripts/upgrade-program.sh`](scripts/upgrade-program.sh) and [`.github/workflows/ci.yml`](.github/workflows/ci.yml) ([`docs/DEPLOYMENTS.md`](docs/DEPLOYMENTS.md#solana-verified-builds-verifycly8mb96wd9wqq3wdxqwm4ou6r42th37db9fc)).
- **Protocol Architecture:** [`ARCHITECTURE.md`](ARCHITECTURE.md) — account layouts, Ristretto255 Multi-Base Triptych soundness proofs, swap custody isolation, Token-2022 solvency, and sBPFv3 runtime engineering.
- **Deploy Your Own Relayer:** [`docs/DEPLOY_YOUR_OWN_RELAY.md`](docs/DEPLOY_YOUR_OWN_RELAY.md) — step-by-step guide to deploy an independent Audren relayer with zero shared credentials.
- **Canonical Deployments:** [`docs/DEPLOYMENTS.md`](docs/DEPLOYMENTS.md) — Mainnet & Devnet Program ID, Pool #0 PDA, Program Metadata PDAs, and reference endpoints.

## Instruction set

| Tag | Instruction | Description |
| --- | --- | --- |
| `0x00` | `InitPool` | Create `PoolState` (`192 B`), `EpochPage #0` (`6,240 B`), `sol_vault`, `page_rent_vault` |
| `0x01` | `OpenPage` | Permissionless Lane `0` rollover allocating `page_id + 1` funded by `PageRentVault` |
| `0x02` | `Deposit` | Shield Native SOL, Classic SPL, or Token-2022 to any stealth address (`flags & 2` deducts rent fee from deposit for 0-dust sweeps; zero ZK proof) |
| `0x03` | `Transfer` | Private 1-in → 2-out transfer (`m = 5/6/7`, Triptych + CrossBase2 + `BatchedRangeProofU128`) |
| `0x04` | `Merge` | Consolidate 2 shielded notes of the same hidden asset into 1 note |
| `0x05` | `ExecViaEscrow` | Protocol-agnostic 1-tx Token A → Token B CPI via isolated `swap_escrow` (DEXs, lending supply, yield vaults, LSTs, perp LP, RWAs) with native input/output `relayer_fee` (`flags & 4`), optional shielded change (`flags & 1`), and partial refund (`flags & 2`) |
| `0x06` | `Withdraw` | Unshield exact amount to any wallet/ATA with optional native `relayer_fee`, shielded change (`flags & 2`), and atomic WSOL → Native SOL unwrap (`flags & 4` via `audren_unwrap` PDA); full withdrawals keep `PoolState` read-only and bypass `SetPaused` |
| `0x07` | `SetPaused` | Emergency pause toggle by pool authority (zero vault custody) |
| `0x08` | `WriteProofBuffer` | Upload `<= 768 B` payload chunk into ephemeral `ProofBuffer` PDA (`<= 10,032 B`) |
| `0x09` | `ExecBuffered` | Execute buffered instruction zero-copy and atomically refund 100% of buffer rent |
| `0x0A` | `CloseProofBuffer` | Reclaim 100% of rent from an abandoned `ProofBuffer` PDA |
| `0x0B` | `InitLane` | Initialize parallel append lane `1..15` (`AppendLaneState` + `LaneRentVault` + initial page) |
| `0x0C` | `OpenLanePage` | Permissionless self-funding rollover for parallel lane `1..15` with read-only `PoolState` |

## Quickstart: Verification, Build & Testing

### 1. Fast host checks (Rust, IDLs, TypeScript, Swift & Kotlin)
```bash
# Rust typechecks & canonical conformance tests
cargo check --manifest-path program/Cargo.toml
cargo check --manifest-path program/Cargo.toml --features no-entrypoint
cargo test --manifest-path program/Cargo.toml
cargo check --manifest-path tests/mock-router/Cargo.toml
cargo check --workspace --tests
cargo test -p audren-client --test conformance_vectors
cargo test -p audren-ffi

# Verify IDLs, 4-language SDKs, docs & zero-drift invariants
python3 idl/verify-idl.py

# TypeScript SDK (core + pure-TS prover conformance), Relayer & Web UI
pnpm --dir packages/sdk typecheck && pnpm --dir packages/sdk test
pnpm --dir apps/relay typecheck
pnpm --dir apps/web check

# Mobile SDKs (Swift iOS/macOS & Kotlin Android/JVM conformance + native provers)
./scripts/build-mobile-sdks.sh bindings
(cd packages/swift && swift test)
(cd packages/kotlin && gradle test)
```

### 2. Compile sBPFv3 `.so` artifacts & run LiteSVM E2E tests
```bash
# Build deterministic sBPFv3 artifacts
python3 scripts/build-sbf.py --manifest-path program/Cargo.toml --sbf-out-dir target/deploy
python3 scripts/build-sbf.py --manifest-path tests/mock-router/Cargo.toml --sbf-out-dir target/deploy

# Run all 8 LiteSVM integration & adversarial suites + real-sBPFv3 Cross-SDK LiteSVM suite
cargo test --test litesvm_e2e -- --nocapture
AUDREN_REQUIRE_SBF=1 cargo test -p audren-ffi --test cross_sdk_litesvm -- --nocapture
```

### 3. Cluster deployment, Program Metadata & Verified Builds
See [`docs/DEPLOYMENTS.md`](docs/DEPLOYMENTS.md) and [`idl/README.md`](idl/README.md) for deployment addresses, atomic program upgrades (`scripts/upgrade-program.sh`), Solana Program Metadata (`idl` & `security`), and Solana Verified Build attestation. Keep local keypairs in gitignored `.credentials/` and private operator Wrangler configs in gitignored `wrangler.prod.jsonc`.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
