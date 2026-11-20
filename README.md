# Audren (`audren.xyz`)

**Audren** is a zero-indexer, multi-asset confidential settlement and private execution protocol on Solana (sBPFv3).

## Verified Deployments

| Cluster | Program ID | Pool `#0` (`Permissionless`) PDA | Slot | ELF SHA-256 |
| --- | --- | --- | ---: | --- |
| **Solana Mainnet-Beta** | `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3` | `5Bvt5f5QMfsVb9TyX8bzkRMvAX6JSWwRtnymGveF9U3G` | `471551234` | `3a4b8b2a53dd5c9752fb5423008a5b39f22e5f2b6e530eaa6215a43d3ad9256f` |
| **Solana Devnet** | `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3` | `5Bvt5f5QMfsVb9TyX8bzkRMvAX6JSWwRtnymGveF9U3G` | `524184821` | `3a4b8b2a53dd5c9752fb5423008a5b39f22e5f2b6e530eaa6215a43d3ad9256f` |

- **ProgramData (Mainnet & Devnet):** `Gj4hW4KuMTNR9YTPmixRPsNcMNwRvYTXdksxLgoGRiVM`
- **ELF Size:** `274,672` bytes (`0x430f0`), compiled for `sBPFv3` with zero `unsafe` blocks and zero `curve25519-dalek` runtime overhead.

## Measured On-Chain Compute Units (sBPFv3 / LiteSVM Agave 4.3)

| Instruction | Measured CU | Notes |
| --- | ---: | --- |
| `InitPool` (`Tag 0`) | `35,697 – 47,687 CU` | Creates `PoolState` (`192 B`), `EpochPage #0` (`6,240 B`), `sol_vault`, `page_rent_vault` |
| `OpenPage` (`Tag 1`) | `18,179 – 28,679 CU` | Permissionless rollover (`6,240 B` + `PageRentVault` self-subsidy) |
| `Deposit` (`Tag 2`) | `19,030 – 38,813 CU` | Native SOL, Classic SPL, or safe Token-2022 (`0` ZK proof required) |
| `Transfer` (`m = 5`, 32-note ring) | `451,591 – 485,822 CU` | Multi-Base Triptych + Agave `BatchedRangeProofU128` + `ProofBuffer` auto-close |
| `Transfer` (`m = 5`, `InstitutionalAudited`) | `506,766 CU` | Enforces verifiable ElGamal `(S_1, S_2)` + `(M_1, M_2)` to `K_aud` on-chain |
| `Transfer` (`m = 6`, 64-note ring) | `824,512 CU` | 2-page ring, bounded 8 KiB chunked MSM buffer |
| `Transfer` (`m = 7`, 128-note ring) | `1,113,133 CU` | 4-page ring inside default 32 KiB Solana heap (no `requestHeapFrame`) |
| `Merge` (`Tag 4`, 2x `m = 5`) | `573,054 CU` | Consolidates 2 shielded notes into 1 note |
| `SwapViaRouter` (`Tag 5`) | `405,291 CU` | Isolated `swap_escrow` CPI to any DEX router (Jupiter, Orca, Raydium, Meteora, Phoenix) |
| `Withdraw` (`Tag 6`, full / with change) | `237,386 / 353,280 CU` | Native SOL, Classic SPL, or safe Token-2022 with optional shielded change |
| `WriteProofBuffer` (`Tag 8`) | `2,818 – 9,800 CU` | Parallel `<= 768 B` chunks (`<= 1,071 B` wire tx < `1,232 B` MTU) |
| `CloseProofBuffer` (`Tag 10`) | `982 CU` | 100% rent reclamation for abandoned uploads |

## Architecture Highlights

- **Zero Custom Indexer:** Notes live in fixed-size Structure-of-Arrays (SoA) `EpochPage` PDAs (`32` notes/page, `6,240 B` — safely below Solana's `10 KiB` CPI cap and Direct Mapping `SIMD-0460` compliant). Wallets scan **100 pages (`3,200` notes)** per single standard Solana `getMultipleAccounts(..., { dataSlice: { offset: 64, length: 1056 } })` call (~`106 KB`) or stream live updates via Agave `programSubscribe` `dataSlice`.
- **Zero Groth16 / Zero Trusted Setup:** Pure Ristretto255 Multi-Base Binary Triptych verified via Agave's native `sol_curve_multiscalar_mul` syscall, radix-29 scalar arithmetic (`program/src/scalar.rs`), and native `ZkE1Gama1Proof11111111111111111111111111111` Bulletproofs.
- **Unified Multi-Asset Anonymity Pool:** Native SOL, Classic SPL, and safe Token-2022 mints (automatically rejecting `PermanentDelegate`, `NonTransferable`, active/mutable `TransferHook`, and non-zero/mutable `TransferFeeConfig`) share one global `EpochPage` stream via NUMS per-mint generators `G_mint`.
- **Router-Agnostic 1-Tx Private Swaps (`SwapViaRouter`):** Funds move into an isolated `swap_escrow` shard PDA (`16` shards) that signs the external CPI to any Solana DEX aggregator or AMM router (Jupiter, Orca, Raydium, Meteora, Phoenix, Titan, DFlow, or custom routers). `vault_auth` never signs an external CPI, and output sweeps straight into an unlinkable stealth note.
- **Dual Compliance & Disclosure:** `PoolMode::Permissionless` (per-tx `SelectiveDisclosureProof` + read-only `FullViewingKey`) and `PoolMode::InstitutionalAudited` (cryptographically enforced auditor ciphertext verified inside Triptych on-chain).
- **Strict `1,232 B` MTU Compliance (`ProofBuffer`):** Large proofs upload in parallel `<= 768 B` chunks (`WriteProofBuffer`), execute zero-copy via `ExecBuffered` (`2 B` instruction data), and refund `100%` of buffer rent in the same transaction.

## Repository Layout

- `crates/audren-core/` — `#![no_std]` shared account layouts, PDA seeds, proof wire sizes, and error codes.
- `program/` — Isolated sBPFv3 Solana program (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`).
- `crates/client/` — Rust SDK (`audren-client`): Triptych/Cross-Base/Auditor/Bulletproof provers, pure-RPC/WS scanner, router-agnostic swap builder, and 5-suite LiteSVM integration tests.
- `tests/mock-router/` — Minimal sBPFv3 mock router for adversarial `SwapViaRouter` LiteSVM testing.
- `packages/sdk/` — Zero-dependency TypeScript SDK (`@audren/sdk`).
- `ARCHITECTURE.md` — Formal cryptographic equations, account layouts, and security invariants.

## Running Tests

```bash
# Run offline unit tests
cargo test --workspace --lib

# Build sBPFv3 binaries (requires Agave cargo-build-sbf) and run all 5 LiteSVM E2E suites
cargo test --test litesvm_e2e -- --nocapture

# Run live Devnet E2E against AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3
AUDREN_RPC_URL="https://your-devnet-rpc" \
AUDREN_KEYPAIR_PATH="/path/to/devnet-keypair.json" \
cargo test --test devnet_live test_live_devnet_full_shielded_lifecycle -- --ignored --nocapture
```

## Examples

Runnable Rust and TypeScript examples (pure-RPC `dataSlice` scanning, shielded transfers, Jupiter `SwapViaRouter`, and institutional audit decryption) live in [`audren-xyz/examples`](https://github.com/audren-xyz/examples).
