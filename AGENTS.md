# Audren Engineering Guide (`AGENTS.md`)

Concise architectural rules, invariants, and verification commands for contributors and coding agents working in this repository.

## Workspace Boundaries

- **`crates/audren-core/`** is `#![no_std]` and is the single source of truth for PDA seeds, account offsets, instruction tags, proof wire lengths, and error codes.
- **`program/`** is excluded from the root Cargo workspace so on-chain sBPFv3 dependencies never collide with host SDK crates (`solana-zk-sdk`, `litesvm`). Always check both manifests separately.
- **`crates/client/`** provides the Rust prover, RPC/WS scanner, `SwapViaRouter` helper, and LiteSVM/live test suites.
- **`packages/sdk/`** is a zero-dependency TypeScript/ESM SDK targeting Node 20+ and browser runtimes. Do not introduce runtime npm dependencies.
- **`tests/mock-router/`** is an isolated sBPFv3 test program exercising malicious router behavior against `SwapViaRouter`.

## Mandatory Protocol Invariants

1. **Byte-for-Byte Wire Parity:** Every change to account offsets, PDA seeds, transcript domain separators, instruction tags, or proof layouts in `crates/audren-core/` or `program/src/` must be mirrored in `crates/client/` and `packages/sdk/`.
2. **Swap Custody Isolation (`SwapViaRouter`):**
   - `NullifierPDA` must be written before the external router CPI.
   - `router_program` must be bound inside the Fiat-Shamir `ctx_hash`.
   - `vault_auth` and `payer` must never be marked as signers on the external CPI; only `swap_escrow` signs.
   - No Audren program, `PoolState`, `EpochPage`, `NullifierPDA`, or vault account may appear in `router_accounts`.
   - `swap_escrow` and escrow token accounts (`escrow_in`, `escrow_out`) must pass all pre- and post-CPI owner, delegate, `close_authority`, lamport, and slippage (`actual_out >= min_amount_out`) checks.
3. **Token-2022 Solvency & Hook Isolation:** `Deposit` and `SwapViaRouter` must always commit the measured net vault balance increase (`after - before > 0`) so fee-on-transfer (`TransferFeeConfig`) mints preserve exact 1:1 vault solvency. `Withdraw` must never block withdrawals based on mint extensions. Whenever trailing `TransferHook` accounts are forwarded into `transfer_checked`, `is_signer` must be cleared and Audren-owned accounts and custody vaults must be filtered out.
4. **Solana Transaction Version 1 Only & Atomic Buffer Rent (`ProofBuffer`):** All clients, tests, and examples must use Solana Transaction Version 1 (`0x81`, SIMD-0385, `4,096 B` max size, inline `TransactionConfig` via `v1::Message::try_compile_with_config` + `VersionedTransaction::try_new(VersionedMessage::V1(...))` + `wincode::serialize`) — never legacy transactions or separate `ComputeBudgetInstruction`s. For oversized payloads exceeding `4,096 B`, `ExecBuffered` and `CloseProofBuffer` must zero the buffer magic, shrink to `0 B`, reassign to the System Program, and refund 100% of lamports to `authority`/`payer`.
5. **sBPFv3 Runtime Safety:**
   - Zero `unsafe` blocks in `program/`.
   - Keep large structures (`BatchedRangeProofU64Data`, `BatchedRangeProofU128Data`, ring polynomial vectors) heap-allocated (`Box` / `Vec`) to stay well under Solana's `4,096 B` stack frame limit.
   - Keep MSM batch buffers bounded so `m = 5 / 6 / 7` verification runs within Solana's default `32 KiB` heap without `requestHeapFrame`.
   - `EpochPage` (`6,240 B`) and `ProofBuffer` (`<= 10,032 B`) must stay strictly under Solana's `10,240 B` CPI allocation limit with zero `realloc`.

## Verification Commands

Toolchain is pinned in `rust-toolchain.toml` (`1.98.1`). Run before finishing any change:

```bash
cargo check --workspace --all-targets
cargo check --manifest-path program/Cargo.toml
cargo test --workspace --lib
pnpm --dir packages/sdk typecheck
```

When modifying on-chain logic and compiled `.so` artifacts are updated via Agave `cargo-build-sbf`:

```bash
cargo test --test litesvm_e2e -- --nocapture
```

## Code & Documentation Style

- Write comments, READMEs, and specifications in present tense describing what the protocol does and why an invariant holds.
- Do not write changelogs, patch history, or comparisons against previous implementations in source comments or documentation.
- Never hardcode private RPC API keys, keypair paths, or secrets in code, tests, or docs; read endpoints and credentials from environment variables (`AUDREN_RPC_URL`, `AUDREN_KEYPAIR_PATH`).
