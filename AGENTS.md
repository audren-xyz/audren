# Audren — Repository Agent & Engineering Rules

Standalone open-source repository for the **Audren** Solana shielded protocol, published IDLs, TypeScript/Rust SDKs, self-hostable Privacy Relayer, and Web App.

## Workspace boundaries

- **`crates/audren-core/`** is `#![no_std]` and is the single source of truth for PDA seeds, account layouts, instruction tags (`0x00..=0x0C`), proof wire lengths, and `AudrenError` codes.
- **`program/`** is an isolated `#![no_std]` `pinocchio 0.11.1` sBPFv3 program manifest excluded from the root Cargo workspace so sBPFv3 dependencies never collide with host crates (`solana-zk-sdk`, `litesvm`). Always check both manifests independently.
- **`tests/mock-router/`** is an isolated `#![no_std]` `pinocchio 0.11.1` sBPFv3 test router used by `litesvm_e2e` to exercise adversarial router behavior against `SwapViaRouter`.
- **`crates/client/`** provides the Rust prover, RPC/WebSocket scanner, `SwapViaRouter` builder, and LiteSVM / live Solana integration suites.
- **`idl/`** owns deterministic Codama v1.8.0 and Anchor v0.30+ IDL generation (`idl/generate-idl.py`) and drift verification (`idl/verify-idl.py`), mirrored into `packages/sdk/`.
- **`packages/sdk/`** is a zero-dependency TypeScript ESM SDK (`@audren/sdk`) targeting Node 22+ and browser runtimes. Do not add runtime npm dependencies.
- **`apps/relay/`** is the standalone, open-source, self-hostable Cloudflare Worker Privacy Relayer. See [`apps/relay/AGENTS.md`](apps/relay/AGENTS.md).
- **`apps/web/`** is the Next.js 16 + Cloudflare Worker web app, live Wallet Vault, and Devnet sandbox. See [`apps/web/AGENTS.md`](apps/web/AGENTS.md).

## Mandatory protocol invariants

1. **Byte-for-byte wire parity across all layers:** Any change to account offsets, PDA seeds, transcript domain separators, instruction tags, or proof layouts in `crates/audren-core/` or `program/src/` must match `idl/` (re-run `python3 idl/generate-idl.py && python3 idl/verify-idl.py`), `crates/client/`, `packages/sdk/`, `apps/relay/src/solana/`, and `apps/web/lib/`. Keep PDA-CPI Jupiter venue exclusions (`JUPITER_CPI_EXCLUDED_DEXES`) synced across `crates/client/src/router.rs`, `packages/sdk/src/swap.ts`, `apps/relay/src/aggregators/jupiter.ts`, and `apps/web/worker/index.ts`.
2. **Swap custody isolation (`SwapViaRouter`, Tag 5):**
   - `NullifierPDA` is created before the external router CPI.
   - `router_program` is bound inside the Fiat-Shamir `ctx_hash`.
   - `vault_auth` and `payer` are never signers on the external CPI; only the selected `swap_escrow` shard PDA (`0..16`) signs.
   - No Audren program, `PoolState`, `AppendLaneState`, `EpochPage`, `NullifierPDA`, or custody vault may appear in `router_accounts`.
   - `swap_escrow` and escrow token accounts (`escrow_in`, `escrow_out`) pass pre- and post-CPI owner, delegate, `close_authority`, lamport non-drain, and slippage (`actual_out >= min_amount_out`) checks.
3. **Token-2022 solvency and hook isolation:** `Deposit` and `SwapViaRouter` commit the measured net vault balance delta (`after - before > 0`) so fee-on-transfer (`TransferFeeConfig`) deposits are not credited above the measured net receipt. Transfer-hook mints are rejected unless safely validated; trailing accounts have `is_signer` cleared and Audren custody accounts filtered out.
4. **Parallel append lanes (`Tag 11` / `Tag 12`):** Lane `0` uses page IDs `(0 << 56) | seq`; parallel lanes `1..15` use `(lane_id << 56) | seq` with `AppendLaneState` (`64 B`), `LaneRentVault`, and read-only `PoolState`, while sharing the unified custody vaults and canonical `NullifierPDA` namespace.
5. **Solana Transaction Version 1 (`0x81`, `4,096 B`) and atomic `ProofBuffer` rent:** Direct settlement uses Solana Transaction v1 (SIMD-0385) with inline `TransactionConfig`. For oversized payloads or `v0`-only wallets, `WriteProofBuffer` (`Tag 8`) uploads `<= 768 B` chunks and `ExecBuffered` (`Tag 9`) / `CloseProofBuffer` (`Tag 10`) close the buffer atomically and refund 100% of lamports to `authority`/`payer`.
6. **sBPFv3 runtime & Pinocchio discipline:**
   - Keep `program/` and `tests/mock-router/` `#![no_std]` on `pinocchio 0.11.1` with zero `serde`/`bincode`/`core::fmt` overhead and host-only `solana-address/curve25519`.
   - Keep `rent_minimum_balance` reading raw `SysvarRent` (`lamports_per_byte_year` + `exemption_threshold`) so both pre- and post-SIMD-0194 clusters compute exact rent exemption.
   - Keep large CPI stack buffers `#[inline(never)]` and place `TriptychScratch`, `WatchedEscrowBuf`, and `CpiAccount` scratch slices in disjoint compile-time-checked regions of Solana's `32 KiB` SBF heap (`pinocchio::no_allocator!()`, zero `liballoc`) to stay well under Solana's `4,096 B` stack frame limit.
   - `EpochPage` (`6,240 B`) and `ProofBuffer` (`<= 10,032 B`) stay strictly below Solana's `10,240 B` CPI allocation limit with zero `realloc`.

## On-chain upgrade & compliance continuity (MANDATORY)

Every program change and every cluster upgrade MUST keep all four on-chain trust surfaces synchronized atomically — never run raw `solana program deploy` without carrying forward metadata and build verification:

1. **Deterministic sBPFv3 binary & embedded `.security.txt`:** Every Solana program crate (`program/`, `tests/mock-router/`) must keep `[lib] name` explicitly set, `[workspace.metadata.cli] solana` pinned to the exact Agave version in `scripts/build-sbf.py` and `scripts/upgrade-program.sh`, and its `.security.txt` section (`email:security@audren.xyz`) bound to `env!("CARGO_PKG_VERSION")`. Mainnet releases must be built deterministically in Docker via `./scripts/upgrade-program.sh build-verifiable`.
2. **Synchronized IDLs & `@audren/sdk`:** Any protocol or version change must update `idl/audren.codama.json`, `idl/audren.anchor.json`, `idl/audren-mock-router.codama.json`, `idl/security.json`, `packages/sdk/idl/*`, and `packages/sdk/src/idl.ts` via `python3 idl/generate-idl.py`, pass `python3 idl/verify-idl.py`, and keep protocol crate versions (`Cargo.toml`, `crates/audren-core`, `crates/client`, `program`, `tests/mock-router`, `packages/sdk`) aligned.
3. **On-chain Solana Program Metadata (`ProgM6JCCvbYkfKqJYHePx4xxSUSqJp7rh8Lyv7nk7S`):** Every Devnet and Mainnet program upgrade MUST republish and round-trip verify both canonical `security` (`GU7K3e7p8zUHoKQuQ1fidi9atxQc3UN1e3Q1Xomzs2Lj`) and `idl` (`5QoLwK1C3NpUXjsHEV14RsQE65MaaiT9WxGvoTyxBPsn`) accounts. `./scripts/upgrade-program.sh <devnet|mainnet>` performs this automatically after deployment.
4. **Solana Verified Builds (`verifycLy8mB96wd9wqq3WDXQwM4oU6r42Th37Db9fC`):** Every Mainnet upgrade MUST come from a clean, pushed commit on `https://github.com/audren-xyz/audren`, update the on-chain Otter Verify PDA (`solana-verify verify-from-repo`), and submit a fresh OtterSec remote verification job (`solana-verify remote submit-job`). `./scripts/upgrade-program.sh mainnet` enforces this by default; audit live cluster parity anytime with `./scripts/upgrade-program.sh check <devnet|mainnet>`.
5. **Timeless, specification-grade documentation:** Keep READMEs, architecture docs, IDLs, SDKs, and source comments strictly present-tense and authoritative. Never write changelog narratives, migration diaries, or scratchbook notes in documentation or code comments.

## Open-source hygiene & secret safety (MANDATORY)

- **NEVER commit secrets, private RPC URLs, Cloudflare `account_id`s, or operator keypairs.**
- Local operator files live strictly in gitignored paths:
  - `.credentials/` (keypairs, chmod `0700` dir / `0600` files)
  - `apps/relay/wrangler.prod.jsonc` and `apps/web/wrangler.prod.jsonc` (operator custom domains, `account_id`, private service bindings)
  - `apps/relay/.dev.vars` and `apps/web/.dev.vars` (local dev secrets)
- Public tracked `wrangler.jsonc` files must remain 100% self-hostable out of the box.
- Never hardcode or fall back to throttled public Solana RPC endpoints; read RPC URLs from environment variables or Wrangler secrets.
- Never run `solana program close` on `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`.

## Verification commands

```bash
cargo check --manifest-path program/Cargo.toml
cargo check --manifest-path program/Cargo.toml --features no-entrypoint
cargo check --manifest-path program/Cargo.toml --tests
cargo check --manifest-path tests/mock-router/Cargo.toml
cargo check --workspace --tests
python3 idl/verify-idl.py
pnpm --dir packages/sdk typecheck && pnpm --dir packages/sdk test
pnpm --dir apps/relay typecheck
pnpm --dir apps/web typecheck
```
