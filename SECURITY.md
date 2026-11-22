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
- `crates/audren-core/` — shared wire layouts, 13 PDA derivations, 9 tags, and 33 error codes
- `crates/audren-circuits/` — BN254 Groth16 `JoinSplit4AryCircuit` (`17,861` R1CS) and `audren_circuits.wasm` prover
- `crates/client/` — Rust SDK (prover, `CompactWalletStore`, RPC scanner, selective disclosure, `ExecViaEscrow` builder, deterministic `DefiSessionKeypair`)
- `crates/audren-ffi/` — UniFFI native mobile bridge backing Swift & Kotlin (`45` synced exports)
- `packages/sdk/` — `@audren/sdk` + `@audren/sdk/prover` TypeScript SDK, WASM prover, and published IDLs
- `packages/swift/` — `AudrenSDK` Swift (iOS 15+ / macOS 13+) SDK
- `packages/kotlin/` — `xyz.audren.sdk` Kotlin (Android API 24+ / JVM 21+) SDK
- `apps/relay/` — standalone Privacy Relayer firewall, FVK fee verification, and crank logic
- `apps/web/` — client-side browser WASM prover, wallet integration, and Worker RPC proxy

## Deployment Status & Boundaries

- **Groth16 ceremony provenance & pre-audit status:** `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3` verifies proofs under the BGM17 Groth16 ceremony keys anchored to the official Hermez/PSE Perpetual Powers of Tau (`powersOfTau28_hez_final_15.ptau`, 71+ independent public contributors) + zeroized Phase-2 contributions + live drand Quicknet (`#34194203`) & Solana Mainnet finalized blockhash (`#472705896`) beacon ([`ceremony/transcript.json`](ceremony/transcript.json)). Additional community Phase-2 contributions remain open, and the program remains pre-audit and upgradeable until independent third-party audits conclude.
- **On-chain security metadata:** Canonical security metadata is published on-chain via Solana Program Metadata (`ProgM6JCCvbYkfKqJYHePx4xxSUSqJp7rh8Lyv7nk7S`, seed `"security"`) from [`idl/security.json`](idl/security.json), and embedded directly in the sBPFv3 program binary as a `.security.txt` section.
- **Reproducible verified builds:** Mainnet releases are built deterministically in the Solana Foundation `solana-verifiable-build` Docker container (`Agave 4.3.0`, `platform-tools v1.57`, `sBPFv3`) and attested on-chain via the Otter Verify PDA (`verifycLy8mB96wd9wqq3WDXQwM4oU6r42Th37Db9fC`) and [`verify.osec.io`](https://verify.osec.io/status/AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3).
- **Intentional public boundaries (not vulnerabilities):** Public deposits (`Tag 3`/`Tag 4`), withdrawals (`Tag 6`, including `WITHDRAW_FLAG_UNWRAP_WSOL`), external DeFi CPI execution (`Tag 7 ExecViaEscrow`), stateful DeFi positions opened by deterministic `DefiSessionKeypair` wallets, transaction fee payers, optional 1-input vs 2-input arity selection, and relayer/RPC network metadata are documented public boundaries. See [`ARCHITECTURE.md`](ARCHITECTURE.md#privacy-boundaries-and-effective-anonymity) for the complete threat model.
