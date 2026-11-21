# Audren — Repository Agent & Engineering Rules

Standalone open-source repository for the **Audren** Solana shielded protocol, published IDLs, four standardized Apache-2.0 SDKs (Rust, TypeScript, Swift, Kotlin), self-hostable Privacy Relayer, and Web App.

## Workspace boundaries

- **`crates/audren-core/`** is `#![no_std]` and is the single source of truth for PDA seeds, account layouts, instruction tags (`0x00..=0x0C`), proof wire lengths, and `AudrenError` codes.
- **`program/`** is an isolated `#![no_std]` `pinocchio 0.11.1` sBPFv3 program manifest excluded from the root Cargo workspace so sBPFv3 dependencies never collide with host crates (`solana-zk-sdk`, `litesvm`). Always check both manifests independently.
- **`tests/mock-router/`** is an isolated `#![no_std]` `pinocchio 0.11.1` sBPFv3 test router used by `litesvm_e2e` to exercise adversarial router behavior against `SwapViaRouter`.
- **`crates/client/`** provides the Rust SDK (provers, RPC/WebSocket scanner, `SwapViaRouter` builder, selective disclosure, auditor decryptor, and LiteSVM / live Solana integration suites).
- **`crates/audren-ffi/`** is the UniFFI native FFI facade over `crates/client` generating the Swift (`packages/swift/`) and Kotlin (`packages/kotlin/`) mobile SDKs with zero cryptographic re-implementation drift.
- **`spec/test-vectors.json`** is the single canonical cross-language conformance suite verified byte-for-byte by Rust (`audren-client` & `audren-ffi`), TypeScript (`@audren/sdk` & `@audren/sdk/prover`), Swift (`AudrenSDK`), and Kotlin (`xyz.audren.sdk`) on every CI run.
- **`idl/`** owns deterministic Codama v1.8.0 and Anchor v0.30+ IDL generation (`idl/generate-idl.py`) and drift verification (`idl/verify-idl.py`), mirrored into `packages/sdk/`.
- **`packages/sdk/`** is the unified TypeScript ESM SDK: `@audren/sdk` (zero runtime dependencies for PDAs, layouts, scanner payloads, relayer, v1 tx, and IDLs) and `@audren/sdk/prover` (pure-TS Ristretto255 + Multi-Base Triptych + Batched Bulletproofs prover using `@noble/curves` & `@noble/hashes`, shared directly by `apps/web` with zero duplication).
- **`packages/swift/`** is the SwiftPM SDK (`AudrenSDK`) for iOS 15+ and macOS 13+ backed by `crates/audren-ffi`.
- **`packages/kotlin/`** is the Gradle/JNA Kotlin SDK (`xyz.audren.sdk`) for Android API 24+ and JVM 21+ backed by `crates/audren-ffi`.
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

Every program change, release, and cluster upgrade MUST keep all six trust surfaces strictly synchronized with zero drift — never run raw `solana program deploy` without carrying forward metadata, build attestation, GitHub Release, and web register parity:

1. **Deterministic sBPFv3 binary & embedded `.security.txt`:** Every Solana program crate (`program/`, `tests/mock-router/`) must keep `[lib] name` explicitly set, `[workspace.metadata.cli] solana` pinned to the exact Agave version in `scripts/build-sbf.py` and `scripts/upgrade-program.sh`, and its `.security.txt` section (`email:security@audren.xyz`) bound to `env!("CARGO_PKG_VERSION")`. Mainnet releases must be built deterministically in Docker via `./scripts/upgrade-program.sh build-verifiable`.
2. **Zero-drift local parity across IDLs, 4 SDKs, Relayer, Web & Docs:** Any protocol or version change must align all 10 release manifests (`Cargo.toml`, `crates/audren-core`, `crates/client`, `crates/audren-ffi`, `program`, `tests/mock-router`, `packages/sdk`, `packages/kotlin`, `apps/relay`, `apps/web`), regenerate `idl/audren.codama.json`, `idl/audren.anchor.json`, `idl/audren-mock-router.codama.json`, `idl/security.json`, `packages/sdk/idl/*`, and `packages/sdk/src/idl.ts` via `python3 idl/generate-idl.py`, regenerate Swift/Kotlin bindings via `./scripts/build-mobile-sdks.sh bindings` when `crates/audren-ffi` changes, update `apps/web/lib/protocol.ts` and `docs/DEPLOYMENTS.md`, and pass `python3 idl/verify-idl.py` (enforced on every push and PR by `.github/workflows/ci.yml`).
3. **On-chain Solana Program Metadata (`ProgM6JCCvbYkfKqJYHePx4xxSUSqJp7rh8Lyv7nk7S`):** Every Devnet and Mainnet program upgrade MUST republish and round-trip verify both canonical `security` (`GU7K3e7p8zUHoKQuQ1fidi9atxQc3UN1e3Q1Xomzs2Lj`) and `idl` (`5QoLwK1C3NpUXjsHEV14RsQE65MaaiT9WxGvoTyxBPsn`) accounts with zero leaked buffer accounts. `./scripts/upgrade-program.sh <devnet|mainnet>` performs this automatically (including automatic Mainnet buffer recovery).
4. **Solana Verified Builds (`verifycLy8mB96wd9wqq3WDXQwM4oU6r42Th37Db9fC`):** Every Mainnet upgrade MUST come from a clean, pushed commit on `https://github.com/audren-xyz/audren`, update the on-chain Otter Verify PDA (`FUQpuou8R4iDA5iMVTZiCB6X8uMdWdhSXxgo85Viv4Qt`), and verify via OtterSec remote attestation (`verify.osec.io`). `./scripts/upgrade-program.sh mainnet` enforces this by default.
5. **Annotated Git Tag & GitHub Release (`v<version>`):** Every Mainnet program upgrade MUST cut a signed/annotated git tag `v<version>` pointing to the exact verified commit and publish a corresponding GitHub Release attaching `audren.so`, `audren.so.sha256`, `audren.codama.json`, `audren.anchor.json`, and `security.json`. `./scripts/upgrade-program.sh mainnet` (Step 4/4) and `./scripts/upgrade-program.sh release` automate this; `./scripts/upgrade-program.sh check mainnet` audits local parity, on-chain Program Metadata, live OtterSec Verified Build + `apps/web/lib/protocol.ts` hash parity, and the live GitHub Release in one command.
6. **Live Web App & Relayer parity + timeless docs:** After any Mainnet upgrade, update `apps/web/lib/protocol.ts` (ELF size, raw SHA-256, verified executable hash, deployed slot, deploy tx, verified commit, measured CUs), commit and push to `main`, verify CI is green, and redeploy `apps/web` (`pnpm --dir apps/web deploy:prod`) and `apps/relay` (`pnpm --dir apps/relay deploy:prod` when relayer code changes). Keep READMEs, architecture docs, IDLs, SDKs, and source comments strictly present-tense and authoritative — never write changelog diaries or scratchbook prose in docs or code comments.

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
