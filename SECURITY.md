# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the Audren on-chain program, cryptographic implementation, SDKs, Privacy Relayer, or web application, please report it privately to:

- **Email:** `security@audren.xyz`
- **Preferred language:** English (`en`)

Please include:
- Affected component and commit hash, tag, or deployed address (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`)
- Clear reproduction steps, proof-of-concept transaction or test case, and impact assessment
- Any suggested remediation if known

Do not open public GitHub issues or disclose active vulnerabilities publicly before coordinated remediation.

## Scope

In-scope components:
- `program/` — Audren on-chain Solana program (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`)
- `crates/audren-core/` — shared wire layouts, PDA derivations, and error codes
- `crates/client/` — Rust SDK (prover, scanner, selective disclosure, `ExecViaEscrow` builder, deterministic `DefiSessionKeypair`)
- `crates/audren-ffi/` — UniFFI native mobile bridge backing Swift & Kotlin (`47` synced exports)
- `packages/sdk/` — `@audren/sdk` + `@audren/sdk/prover` TypeScript SDK and published IDLs
- `packages/swift/` — `AudrenSDK` Swift (iOS 15+ / macOS 13+) SDK
- `packages/kotlin/` — `xyz.audren.sdk` Kotlin (Android API 24+ / JVM 21+) SDK
- `apps/relay/` — standalone Privacy Relayer firewall, accounting, and guard logic
- `apps/web/` — client-side browser prover, wallet integration, and Worker proxy

## Deployment Status & Boundaries

- **Pre-audit & upgradeable:** `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3` is pre-audit and currently deployed as an upgradeable BPF Loader Upgradeable program.
- **On-chain security metadata:** Canonical security metadata is published on-chain via Solana Program Metadata (`ProgM6JCCvbYkfKqJYHePx4xxSUSqJp7rh8Lyv7nk7S`, seed `"security"`) from [`idl/security.json`](idl/security.json), and embedded directly in the sBPFv3 program binary as a `.security.txt` section.
- **Reproducible verified builds:** Mainnet releases are built deterministically in the Solana Foundation `solana-verifiable-build` Docker container (`Agave 4.3.0`, `platform-tools v1.57`, `sBPFv3`) and attested on-chain via the Otter Verify PDA (`verifycLy8mB96wd9wqq3WDXQwM4oU6r42Th37Db9fC`) and [`verify.osec.io`](https://verify.osec.io/status/AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3).
- **Intentional public boundaries (not vulnerabilities):** Public deposits (`Tag 2`), withdrawals (`Tag 6`, including `unwrap_wsol`), external DeFi CPI execution (`Tag 5 ExecViaEscrow`), stateful DeFi positions opened by deterministic session wallets (`B_0, B_1…`), transaction fee payers, candidate page selection, and relayer/RPC network metadata are documented public boundaries. See [`ARCHITECTURE.md`](ARCHITECTURE.md#privacy-boundaries-and-effective-anonymity) for the complete threat model and security assumptions.
