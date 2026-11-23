# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the Audren on-chain program, BN254 Groth16 circuit, SDKs, Privacy Relayer, or web application, please report it privately to:

- **Email:** `security@audren.xyz`
- **Preferred language:** English (`en`)

Please include:
- Affected component and commit hash, tag, or deployed address (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`)
- Clear reproduction steps, proof-of-concept transaction or test case, and impact assessment
- Any suggested remediation if known

Do not open public GitHub issues or disclose active vulnerabilities publicly before coordinated remediation.

## Scope

In-scope components:
- `program/` — Audren on-chain Solana sBPFv3 program (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`)
- `crates/audren-core/` — shared wire layouts, 12 PDA derivations, 9 tags, and 33 error codes
- `crates/audren-circuits/` — BN254 Groth16 `JoinSplit4AryCircuit` (`17,861` R1CS) and `audren_circuits.wasm` prover
- `crates/client/` — Rust SDK (prover, `CompactWalletStore`, RPC scanner, selective disclosure, `ExecViaEscrow` builder, deterministic `DefiSessionKeypair`)
- `crates/audren-ffi/` — zero-panic UniFFI native mobile bridge backing Swift & Kotlin (`46` synced `Result` exports)
- `packages/sdk/` — `@audren/sdk` + `@audren/sdk/prover` TypeScript SDK, WASM prover, and published IDLs
- `packages/swift/` — `AudrenSDK` Swift (iOS 15+ / macOS 13+) SDK
- `packages/kotlin/` — `xyz.audren.sdk` Kotlin (Android API 24+ / JVM 21+) SDK
- `apps/relay/` — standalone Privacy Relayer firewall, FVK fee verification, and crank logic
- `apps/web/` — client-side browser WASM prover, wallet integration, and Worker RPC proxy

## Deployment Status & Boundaries

- **Groth16 ceremony provenance & pre-audit status:** `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3` verifies proofs under the BGM17 Groth16 ceremony keys anchored to the official Hermez Perpetual Powers of Tau (`powersOfTau28_hez_final_15.ptau`, 54 public contributions plus a beacon) + two Audren-generated Phase-2 contributions + live drand Quicknet (`#34194203`) & Solana Mainnet finalized slot `472705896` blockhash beacon ([`ceremony/transcript.json`](ceremony/transcript.json)). Until an independent contributor joins, Phase-2 soundness relies on Audren having destroyed its contribution secrets. Additional community Phase-2 contributions remain open (adopted only through a program upgrade). The program is pre-audit and upgradeable; any decision to revoke the upgrade authority will be announced separately.
- **On-chain security metadata:** Canonical security metadata is published on-chain via Solana Program Metadata (`ProgM6JCCvbYkfKqJYHePx4xxSUSqJp7rh8Lyv7nk7S`, seed `"security"`) from [`idl/security.json`](idl/security.json), and embedded directly in the sBPFv3 program binary as a `.security.txt` section.
- **Reproducible verified builds:** Mainnet releases are built deterministically in the Solana Foundation `solana-verifiable-build` Docker container (`Agave 4.3.0`, `platform-tools v1.57`, `sBPFv3`) and attested on-chain via the Otter Verify PDA (`verifycLy8mB96wd9wqq3WDXQwM4oU6r42Th37Db9fC`) and [`verify.osec.io`](https://verify.osec.io/status/AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3).
- **Protocol & infrastructure security invariants:**
  - **On-chain sBPFv3 (`program/`):** Pure-integer (`u128`) exact IEEE-754 binary64 emulation of Agave's `SysvarRent::minimum_balance` with zero floating-point ops; `>= 1` lamport zero-rent floor preventing PDA/nullifier reaping on zero-rent clusters; immutable `ckpt_interval` after `InitPool` (source `1.2.1`; not yet deployed) paired with strict slot monotonicity and `max_ckpt_age` expiry on `PublishCheckpoint`; post-transfer vault validation and exact outflow delta checks on `!unwrap_wsol` `Transact` and `ExecViaEscrow` input legs; recipient/fee-account anti-aliasing and `TOKEN_2022_ID`-gated TLV validation.
  - **Cryptography & 4-language SDKs:** BIP-350 Bech32m `aud1...` encoding and decoding reject non-canonical BN254 `spend_pk`, whitespace, mixed case, and all-zero / order-8 low-order X25519 `view_pk` points (RFC 7748 probe scalar `[0x09; 32]`); default `'strict'` scanner uses Rendezvous (HRW) wallet-keyed decoys and uniform batched witness reconstruction; zero-panic UniFFI `Result` API across all `46` exports and `extra_writable_pubkeys` writability promotion in `ExecViaEscrow` builders.
  - **Privacy Relayer (`apps/relay/`):** `SELF_PAY_FEE_MINTS` allowlist with on-chain mint safety inspection (rejecting Token-2022 `Pausable`, mutable `TransferFeeConfig`, and untrusted `FreezeAuthority`), audited swap router allowlist (`AUDITED_SWAP_ROUTER_PROGRAMS`) for zero-native-fee `ExecViaEscrow` credit, slot-pinned simulation (`preSlot`/`simSlot`) with deterministic minimum-outflow floor, and ephemeral in-memory UTC-day domain-separated IP-hash salt.
- **Intentional public boundaries (not vulnerabilities):** Unified public deposits (`Tag 3 Deposit`), public withdrawals (`Tag 5 Transact` with `ASSET_MODE_PUBLIC`, including `WITHDRAW_FLAG_UNWRAP_WSOL`), external DeFi CPI execution (`Tag 6 ExecViaEscrow`), stateful DeFi positions opened by deterministic `DefiSessionKeypair` wallets, transaction fee payers, optional 1-input vs 2-input arity selection, and relayer/RPC network metadata are documented public boundaries. See [`ARCHITECTURE.md`](ARCHITECTURE.md#5-privacy-boundaries-and-effective-anonymity) for the complete threat model.
