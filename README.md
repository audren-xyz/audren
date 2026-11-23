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
  <a href="https://github.com/audren-xyz/audren/releases/tag/v1.2.1"><img src="https://img.shields.io/badge/release-v1.2.1-121210" alt="Release v1.2.1" /></a>
  <a href="https://explorer.solana.com/address/AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3/verified-build"><img src="https://img.shields.io/badge/Solana%20Verified%20Build-sBPFv3-184433" alt="Solana Verified Build" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-434039" alt="Apache-2.0 License" /></a>
  <a href="https://audren.xyz"><img src="https://img.shields.io/badge/app-audren.xyz-C83E2B" alt="audren.xyz" /></a>
</p>

**Private money on Solana. Existing tokens. One global multi-asset shielded pool.**

Audren is an open-source, self-custodial privacy protocol on Solana (`sBPFv3`, `pinocchio 0.11.1`, `#![no_std]`, `PROTOCOL_VERSION = 1`). Native SOL (canonically unified as WSOL via atomic `SyncNative`), Classic SPL tokens, and transferable Token-2022 mints share one permissionless global 4-ary Depth-20 Multi-Asset Shielded Pool (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`, capacity $4^{20} \approx 1.099 \times 10^{12}$ notes) verified on-chain via `192 B` BN254 Groth16 proofs (`17,861` R1CS constraints, `alt_bn128` syscall). Shield assets without wrapper tokens using BIP-350 Bech32m `aud1...` stealth addresses, send private 2-in/3-out `Transact` (`Tag 5`) transfers with hidden asset, amount, sender, recipient, and encrypted `14 B` `payment_id`, compose with arbitrary Solana DeFi via isolated `ExecViaEscrow` CPIs (`Tag 6`), fund pseudonymous `DefiSessionKeypair`s with atomic WSOL unwrapping (`WITHDRAW_FLAG_UNWRAP_WSOL`) and zero-dust SOL sweeps (`DEPOSIT_FLAG_NATIVE_SOL | DEPOSIT_FLAG_FEE_FROM_AMOUNT`), and sync wallets directly over ordinary Solana RPC with zero mandatory indexer.

## Privacy, ceremony, and accounting boundaries

- **Groth16 Ceremony & Pre-audit Status:** Audren's `vk_id = 0` parameters are derived from the official Hermez/PSE Perpetual Powers of Tau (`powersOfTau28_hez_final_15.ptau`, **71+ independent public contributors**) plus Audren's verifiable BGM17 Phase-2 ceremony (`ceremony/transcript.json`, zeroized OS CSPRNG + live drand Quicknet `#34194203` & Solana Mainnet finalized blockhash `#472705896` beacon, SHA-256 `2b22603e...7ee4`). Additional independent community Phase-2 contributions remain open via [`ceremony/README.md`](ceremony/README.md), and an independent third-party security audit is pending before freezing BPF upgrade authority.
- **Public boundaries:** Unified deposits (`Tag 3 Deposit`), public withdrawals (`Tag 5 Transact` with `ASSET_MODE_PUBLIC`), external DeFi CPI calls (`Tag 6 ExecViaEscrow`), and stateful positions opened by deterministic session wallets (`DefiSessionKeypair`) are public boundaries on Solana. Cryptographic proofs enforce global pool unlinkability within the active note set; timing, amount matching, asset choice, and network metadata remain operational factors.
- **Permissionless optional relayers:** Relayers hold no user spend or viewing keys, accept only `Transact` (`Tag 5`) and `ExecViaEscrow` (`Tag 6`), and can observe IP/request metadata. Direct submission exposes its fee payer. See [`ARCHITECTURE.md`](ARCHITECTURE.md#5-privacy-boundaries-and-effective-anonymity).

## How Audren fits together

```text
  Rust / TypeScript (WASM) / Swift (iOS) / Kotlin (Android) SDK
    │  1. Syncs SubtreePage, MemoPage (10,240 B, 96 memos) & NullifierPage via ordinary Solana RPC
    │  2. Persists CompactWalletStore locally (freezes 384 B intra-subtree siblings; discards raw pages)
    │  3. Generates 192 B BN254 Groth16 proof locally (17,861 R1CS, 2^15 FFT)
    ▼
  Optional Pluggable Privacy Relayer (`apps/relay/`, self-hostable or `relay.audren.xyz` — or Direct wallet)
    │  4. Submits single Solana Transaction v1 (`0x81`, <= 4,096 B)
    ▼
  Audren sBPFv3 Program (`program/`, AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3)
       • `#![no_std]` Pinocchio 0.11.1 zero-copy entrypoint & disjoint SBF heap arenas
       • Verifies 192 B BN254 Groth16 via `groth16-solana` + `alt_bn128` syscall (~103k–160k CU)
       • 16-lane-capable 4-ary Poseidon Merkle tree (4 active lanes by default, monotonic 4 -> 8 -> 16)
       • Unified canonical `vault_auth` ATAs (SOL=WSOL), NullifierPDA + NullifierPage, ExecViaEscrow firewall & atomic WSOL unwrap
```

## Official SDKs (4 Languages, 1 Shared Conformance Spec)

All four official Audren SDKs share the same canonical building blocks (`keys & Bech32m aud1... addresses`, `12 PDAs & layouts`, `CompactWalletStore & privacy-first RPC scanner`, `BN254 Groth16 prover & 9 instruction builders`, `Mode 1 & Mode 2 disclosure`, `relayer & IDLs`) and are verified byte-for-byte in CI against [`spec/test-vectors.json`](spec/test-vectors.json):

| Language | Package Path | Engine | Target Runtime | Local Proof Speed (`17,861` R1CS) |
|---|---|---|---|---|
| **Rust** | [`crates/client/`](crates/client/Cargo.toml) | Native `audren-circuits` (`ark-groth16`) | Services, CLIs, bots, validators | ~90–140 ms |
| **TypeScript** | [`packages/sdk/`](packages/sdk/README.md) (`@audren/sdk` + `@audren/sdk/prover`) | Zero-WASM pure-TS Poseidon core + `audren_circuits.wasm` (`2.1 MB`) | Browsers, Node 22+, Cloudflare Workers | ~2.0 s |
| **Swift (iOS / macOS)** | [`packages/swift/`](packages/swift/README.md) (`AudrenSDK`) | UniFFI (`46` exports) over `crates/audren-ffi` (`audren-client`) | iOS 15+, macOS 13+ (`XCFramework` / SwiftPM) | ~120 ms |
| **Kotlin (Android / JVM)** | [`packages/kotlin/`](packages/kotlin/README.md) (`xyz.audren.sdk`) | UniFFI + JNA (`46` exports) over `crates/audren-ffi` (`audren-client`) | Android API 24+ (`jniLibs`), JVM 21+ | ~120 ms |

Runnable examples for all 4 languages live in [`audren-xyz/examples`](https://github.com/audren-xyz/examples).

## Repository layout

```text
program/                On-chain sBPFv3 Solana program (#![no_std], pinocchio 0.11.1, groth16-solana)
crates/audren-core/     #![no_std] account layouts, 12 PDA seeds, 9 tags, and 33 AudrenError codes
crates/audren-circuits/ BN254 Groth16 JoinSplit4AryCircuit (17,861 R1CS), VK codegen, & wasm32 prover
crates/client/          Rust SDK (prover, CompactWalletStore, RPC scanner, ExecViaEscrow, LiteSVM E2E)
crates/audren-ffi/      UniFFI native FFI layer (46 exports) backing Swift & Kotlin + cross-SDK LiteSVM harness
packages/sdk/           TypeScript SDK (@audren/sdk zero-WASM core + @audren/sdk/prover WASM prover)
packages/swift/         Swift SDK (AudrenSDK SwiftPM package + iOS XCFramework build script)
packages/kotlin/        Kotlin SDK (xyz.audren.sdk Gradle/JVM + Android jniLibs build script)
spec/                   Canonical cross-language conformance vectors (spec/test-vectors.json)
idl/                    Published Codama v1.8.0 & Anchor v0.30+ IDLs, security.json, and verifier
apps/relay/             Open-source, self-hostable Cloudflare Worker Privacy Relayer (firewall & crank)
apps/web/               Next.js 16 + Cloudflare Worker landing page, Wallet Vault & WASM Sandbox
tests/mock-router/      Isolated Pinocchio sBPFv3 mock router for adversarial ExecViaEscrow tests
tests/mock-hook/        Isolated Pinocchio sBPFv3 TransferHook mock for Token-2022 solvency tests
scripts/                Deterministic sBPFv3 build helper (`build-sbf.py`), upgrade & mobile SDK scripts
assets/brand/           Canonical Audren SVG/PNG logos, README wordmarks, and social preview cards
docs/                   Self-host relayer guide and canonical deployment register
ARCHITECTURE.md         Account byte layouts, BN254 Groth16 equations, and security specification
SECURITY.md             Responsible disclosure policy (`security@audren.xyz`)
CONTRIBUTING.md         Contributor workflow and zero-drift verification checklist
```

## Instruction set (`0x00..=0x08`)

| Tag | Instruction | Description |
| --- | --- | --- |
| `0x00` | `InitPool` | Create `PoolState` (`128 B`), cache `vault_auth` bump, and configure checkpoint interval/age & rent caps |
| `0x01` | `InitLane` | Initialize append lane `0..15` (`LaneTreeState` `1,824 B` + `LaneRentVault`); monotonically expands `active_lanes` (`4 -> 8 -> 16`) |
| `0x02` | `OpenPage` | Permissionlessly allocate next `SubtreePage`, `SubtreeRootPage`, `MemoPage`, or `NullifierPage` funded by `LaneRentVault` |
| `0x03` | `Deposit` | Unified Native SOL (`DEPOSIT_FLAG_NATIVE_SOL` + atomic `SyncNative` WSOL, optional `DEPOSIT_FLAG_FEE_FROM_AMOUNT`) and SPL / Token-2022 net vault delta solvency + safe `TransferHook` execution (`0` ZK proof) |
| `0x04` | `PublishCheckpoint` | Permissionless 256-slot `RootCheckpoint` ring update across all active lanes enforcing strict slot monotonicity and `max_ckpt_age` expiry (`16.8k`–`44.5k` CU) |
| `0x05` | `Transact` | 2-in/3-out global MASP private transfer (`ASSET_MODE_PRIVATE`) or public withdrawal (`ASSET_MODE_PUBLIC`, `192 B` Groth16, `WITHDRAW_FLAG_UNWRAP_WSOL`, pause bypass for full exits) |
| `0x06` | `ExecViaEscrow` | Protocol-agnostic SPL / Token-2022 DeFi CPI via isolated `escrow` shard (`0..16`) with `EXEC_FLAG_FEE_ON_OUTPUT` & `72 B` `AUD1DYN1` dynamic XOR-masked memo |
| `0x07` | `SetPaused` | Emergency pause toggle by pool authority (zero vault custody; full exits remain enabled) |
| `0x08` | `UpdatePool` | Update mutable pool parameters (`max_ckpt_age`, `note_rent_fee`, `nf_rent_fee`; `ckpt_interval` is immutable after `InitPool`), execute 2-step authority transfer (`propose` -> `accept`), or permanently renounce pool authority (forbidden while paused) |

## Quickstart: Verification, Build & Testing

```bash
# 1. Rust program, circuits, host workspace & canonical conformance tests
cargo check --manifest-path program/Cargo.toml
cargo check --manifest-path program/Cargo.toml --features no-entrypoint
cargo test --manifest-path program/Cargo.toml
cargo check --manifest-path tests/mock-router/Cargo.toml
cargo check --manifest-path tests/mock-hook/Cargo.toml
cargo check --workspace --tests
cargo test -p audren-core
cargo test -p audren-circuits --release
cargo test -p audren-client --release --test conformance_vectors
cargo test -p audren-ffi --release --test conformance_ffi

# 2. Verify IDLs, 4-language SDKs, WASM binary parity, docs & zero-drift invariants
python3 idl/verify-idl.py

# 3. TypeScript SDK (WASM prover conformance), Relayer & Web App
pnpm --dir packages/sdk typecheck && pnpm --dir packages/sdk test
pnpm --dir apps/relay typecheck && pnpm --dir apps/relay test
pnpm --dir apps/web check && pnpm --dir apps/web e2e:audit

# 4. Mobile SDKs (Swift iOS/macOS & Kotlin Android/JVM)
./scripts/build-mobile-sdks.sh bindings
(cd packages/swift && swift test)
(cd packages/kotlin && gradle test)

# 5. Deterministic sBPFv3 ELFs & full LiteSVM + Cross-SDK suites
python3 scripts/build-sbf.py --manifest-path program/Cargo.toml --sbf-out-dir target/deploy
python3 scripts/build-sbf.py --manifest-path tests/mock-router/Cargo.toml --sbf-out-dir target/deploy
python3 scripts/build-sbf.py --manifest-path tests/mock-hook/Cargo.toml --sbf-out-dir target/deploy
cargo test -p audren-client --release --test litesvm_e2e -- --nocapture
AUDREN_REQUIRE_SBF=1 cargo test -p audren-ffi --release --test cross_sdk_litesvm -- --nocapture
```

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
