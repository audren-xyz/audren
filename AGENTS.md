# Audren Engineering Guide (`AGENTS.md`)

Concise architectural rules, invariants, and verification commands for contributors and coding agents working in this repository.

## Workspace Boundaries

- **`crates/audren-core/`** is `#![no_std]` and is the single source of truth for PDA seeds, account offsets, instruction tags, proof wire lengths, and error codes.
- **`program/`** is excluded from the root Cargo workspace so on-chain sBPFv3 dependencies never collide with host SDK crates (`solana-zk-sdk`, `litesvm`). Always check both manifests separately.
- **`crates/client/`** provides the Rust prover, RPC/WS scanner, `SwapViaRouter` helper, and LiteSVM/live test suites.
- **`packages/sdk/`** is a zero-dependency TypeScript/ESM SDK targeting Node 22+ and browser runtimes. Do not introduce runtime npm dependencies.
- **`tests/mock-router/`** is an isolated sBPFv3 test program exercising malicious router behavior against `SwapViaRouter`.

## Mandatory Protocol Invariants

1. **Byte-for-Byte Wire Parity:** Every change to account offsets, PDA seeds, transcript domain separators, instruction tags, or proof layouts in `crates/audren-core/` or `program/src/` must be mirrored in `crates/client/` and `packages/sdk/`.
2. **Swap Custody Isolation (`SwapViaRouter`):**
   - `NullifierPDA` must be written before the external router CPI.
   - `router_program` must be bound inside the Fiat-Shamir `ctx_hash`.
   - `vault_auth` and `payer` must never be marked as signers on the external CPI; only `swap_escrow` signs.
   - No Audren program, `PoolState`, `EpochPage`, `NullifierPDA`, or vault account may appear in `router_accounts`.
   - `swap_escrow` and escrow token accounts (`escrow_in`, `escrow_out`) must pass all pre- and post-CPI owner, delegate, `close_authority`, lamport, and slippage (`actual_out >= min_amount_out`) checks.
3. **Token-2022 Solvency & Hook Isolation:** `Deposit` and `SwapViaRouter` must always commit the measured net vault balance increase (`after - before > 0`) so fee-on-transfer (`TransferFeeConfig`) deposits are not credited above the measured net receipt. Do not add a blanket mint-extension denylist; token-program checks and issuer controls still apply. Whenever trailing `TransferHook` accounts are forwarded into `transfer_checked`, `is_signer` must be cleared and Audren-owned accounts and custody vaults must be filtered out.
4. **Transaction framing and buffer rent:** Direct clients use Solana v1 (`0x81`, 4,096 B) with inline TransactionConfig. Browser wallets restricted to v0 and oversized proofs use ProofBuffer uploads and execution. ExecBuffered and CloseProofBuffer clear magic, shrink to zero bytes, reassign to System Program and refund buffer rent to the authorized payer. Keep v1 and browser-buffer paths explicit in docs and tests.
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
pnpm --dir packages/sdk install --frozen-lockfile
pnpm --dir packages/sdk typecheck
pnpm --dir packages/sdk test
```

When modifying on-chain logic and compiled `.so` artifacts are built through `build-sbf.py` with host Rust 1.97.1:

```bash
cargo test --test litesvm_e2e -- --nocapture
```

## Code & Documentation Style

- Write comments, READMEs, and specifications in present tense describing what the protocol does and why an invariant holds.
- Do not write changelogs, patch history, or comparisons against previous implementations in source comments or documentation.
- Never hardcode private RPC API keys, keypair paths, or secrets in code, tests, or docs; read endpoints and credentials from environment variables (`AUDREN_RPC_URL`, `AUDREN_KEYPAIR_PATH`).

## Documentation and publication

Keep README.md, ARCHITECTURE.md and packages/sdk/README.md true together with source changes. Do not commit credentials, generated dist, target output, package archives or local operator configuration. Build SBF through build-sbf.py. Source publication does not imply an on-chain upgrade or reproducible-build attestation.
