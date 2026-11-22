# Audren — Repository Agent & Engineering Rules

Standalone open-source repository for the **Audren** Solana shielded protocol, BN254 Groth16 circuit & WASM prover, published IDLs, four standardized Apache-2.0 SDKs (Rust, TypeScript, Swift, Kotlin), self-hostable Privacy Relayer, and Web App.

## Workspace boundaries

- **`crates/audren-core/`** is `#![no_std]` with zero dependencies and is the single source of truth for all 13 canonical PDA seeds (`audren_v2_*`), 8 account layouts, 9 instruction tags (`0x00..=0x08`), proof/memo wire lengths (`192 B` Groth16, `90 B` SoA memo), and 33 `AudrenError` codes.
- **`crates/audren-circuits/`** owns the frozen BN254 Groth16 `JoinSplit4AryCircuit` (`17,861` R1CS, `2^15` FFT domain, 4-ary Depth-20 global MASP, 16-lane-capable), deterministic `gen_vk` / `--dump-ts-poseidon` generators, and the `wasm32-unknown-unknown` `extern "C"` prover compiled to `audren_circuits.wasm` (`2.1 MB`).
- **`program/`** is an isolated `#![no_std]` `pinocchio 0.11.1` sBPFv3 program manifest excluded from the root Cargo workspace so sBPFv3 dependencies never collide with host crates (`ark-groth16`, `litesvm`). Always check both manifests independently.
- **`tests/mock-router/`** and **`tests/mock-hook/`** are isolated `#![no_std]` `pinocchio 0.11.1` sBPFv3 programs used by `litesvm_e2e` to test adversarial `ExecViaEscrow` target routers and Token-2022 `TransferHook` execution.
- **`crates/client/`** provides the Rust SDK (native Groth16 prover, zero-indexer `CompactWalletStore`, ordinary Solana RPC scanner, `ExecViaEscrow` builder, deterministic `DefiSessionKeypair`, Mode 1 `SelectiveDisclosureProof`, Mode 2 `FullViewingKey`, and LiteSVM suites).
- **`crates/audren-ffi/`** is the UniFFI native FFI facade (`45` exported functions) over `crates/client` generating the Swift (`packages/swift/`) and Kotlin (`packages/kotlin/`) mobile SDKs with zero cryptographic re-implementation drift, plus the real-sBPFv3 cross-SDK LiteSVM integration suite (`cross_sdk_litesvm`).
- **`spec/test-vectors.json`** is the single canonical cross-language conformance suite verified byte-for-byte by Rust (`audren-client` & `audren-ffi`), TypeScript (`@audren/sdk` & `@audren/sdk/prover`), Swift (`AudrenSDK`), and Kotlin (`xyz.audren.sdk`) on every CI run.
- **`idl/`** owns deterministic Codama v1.8.0 and Anchor v0.30+ IDL generation (`idl/generate-idl.py`) and zero-drift verification (`idl/verify-idl.py`), mirrored into `packages/sdk/`.
- **`packages/sdk/`** is the unified TypeScript ESM SDK: `@audren/sdk` (zero-WASM core with pure-TS Circom BN254 Poseidon, RFC 8439 ChaCha20-Poly1305, PDAs, layouts, `CompactWalletStore`, relayer client, Transaction v1 `0x81`, and IDLs) and `@audren/sdk/prover` (`audren_circuits.wasm` Groth16 prover shared directly with `apps/web`).
- **`packages/swift/`** is the SwiftPM SDK (`AudrenSDK`) for iOS 15+ and macOS 13+ backed by `crates/audren-ffi`.
- **`packages/kotlin/`** is the Gradle/JNA Kotlin SDK (`xyz.audren.sdk`) for Android API 24+ and JVM 21+ backed by `crates/audren-ffi`.
- **`apps/relay/`** is the standalone, open-source, self-hostable Cloudflare Worker Privacy Relayer. See [`apps/relay/AGENTS.md`](apps/relay/AGENTS.md).
- **`apps/web/`** is the Next.js 16 + Cloudflare Worker web app, live Wallet Vault, and browser WASM Sandbox. See [`apps/web/AGENTS.md`](apps/web/AGENTS.md).

## Mandatory protocol invariants

1. **Byte-for-byte wire parity across all layers:** Any change to account offsets, PDA seeds, transcript domain separators, instruction tags, or proof/memo layouts in `crates/audren-core/` or `program/src/` must match `idl/` (re-run `python3 idl/generate-idl.py && python3 idl/verify-idl.py`), `crates/client/`, `packages/sdk/`, `apps/relay/src/solana/`, and `apps/web/lib/`. Keep `JUPITER_CPI_EXCLUDED_DEXES` synced verbatim across `crates/client/src/router.rs`, `packages/sdk/src/swap.ts`, `apps/relay/src/aggregators/jupiter.ts`, and `apps/web/worker/index.ts`. Keep `packages/sdk/wasm/audren_circuits.wasm` and `apps/web/public/wasm/audren_circuits.wasm` byte-identical.
2. **Escrow custody isolation (`ExecViaEscrow`, Tag 7) & atomic WSOL unwrap (`JoinSplit`, Tag 6):**
   - `NullifierPDA` is created before the external DeFi CPI and appended to `NullifierPage`.
   - `router_prog`, `router_accounts` hash, `router_ix_data`, `relayer_fee`, `fee_on_output`, `relayer_fee_recipient`, `min_amount_out`, `out_stealth_owner`, `out_blinding`, and dynamic XOR-masked memo bytes are bound inside the SHA-256 `ctx_hash`.
   - `vault_auth` and `payer` are never signers on the external CPI; only the selected `escrow` shard PDA (`0..16`) signs.
   - No Audren program, `PoolState`, `LaneTreeState`, pages, checkpoints, `NullifierPDA`, or custody vault may appear in `router_accounts`.
   - `escrow` and escrow token accounts pass pre- and post-CPI owner, delegate, `close_authority`, lamport non-drain, and net slippage (`actual_out >= min_amount_out`) checks; `EXEC_FLAG_FEE_ON_OUTPUT` deducts relayer fee atomically from output proceeds after CPI.
   - `JoinSplit` with `WITHDRAW_FLAG_UNWRAP_WSOL` initializes an ephemeral 1-shot `audren_v2_unwrap` PDA (`["audren_v2_unwrap", pool_id_le4, nf0_32]`), transfers WSOL from `vault_auth`, and closes `audren_v2_unwrap` atomically to `recipient` in the same instruction (preserving full-exit pause bypass).
3. **Token-2022 solvency and hook isolation:** `DepositSpl` and `ExecViaEscrow` commit the measured net vault balance delta (`after - before > 0`) so fee-on-transfer (`TransferFeeConfig`) deposits are never credited above the measured net receipt. Transfer-hook mints execute safely with `is_signer` cleared and Audren custody accounts filtered from trailing accounts.
4. **16-lane-capable global MASP & monotonic expansion (`Tag 1` / `Tag 5`):** The frozen `JoinSplit4AryCircuit` supports 16 lanes (`DEPTH = 20`, 4-ary); `PoolState` starts with `active_lanes = 4` and expands monotonically (`4 -> 8 -> 16`) via `InitLane` without modifying the circuit or breaking historical `RootCheckpoint` spendability. Unified custody vaults (`sol_vault`, `vault_auth` ATAs) and canonical `NullifierPDA`s are shared across all lanes.
5. **Solana Transaction Version 1 (`0x81`, `4,096 B`):** Every instruction including `JoinSplit` (`192 B` proof) and `ExecViaEscrow` fits comfortably in a single Solana Transaction v1 (`0x81`) with inline `TransactionConfig`.
6. **sBPFv3 runtime & Pinocchio discipline:**
   - Keep `program/`, `tests/mock-router/`, and `tests/mock-hook/` `#![no_std]` on `pinocchio 0.11.1` with zero `serde`/`bincode`/`core::fmt` overhead.
   - Keep `rent_minimum_balance` reading raw `SysvarRent` (`lamports_per_byte_year` + `exemption_threshold`) so pre- and post-SIMD-0194 clusters compute exact rent exemption.
   - Keep large CPI/verifier stack buffers `#[inline(never)]` and place scratch regions in disjoint compile-time-checked slices of Solana's `32 KiB` SBF heap (`pinocchio::no_allocator!()`, zero `liballoc`) well under Solana's `4,096 B` stack frame limit.
   - Every on-chain page (`SubtreePage` `8,256 B`, `SubtreeRootPage` `9,664 B`, `MemoPage` `10,144 B`, `NullifierPage` `9,664 B`, `RootCheckpoint` `704 B`) stays strictly below Solana's `10,240 B` CPI allocation limit with zero `realloc`.

## On-chain upgrade & compliance continuity (MANDATORY)

Every program change, release, and cluster upgrade MUST keep all six trust surfaces strictly synchronized with zero drift — never run raw `solana program deploy` without carrying forward metadata, build attestation, GitHub Release, and web register parity:

1. **Deterministic sBPFv3 binary, `.security.txt` & Mainnet MPC VK:** Every Solana program crate (`program/`, `tests/mock-router/`) keeps `[lib] name` explicitly set, `[workspace.metadata.cli] solana` pinned to the exact Agave version in `scripts/build-sbf.py` and `scripts/upgrade-program.sh`, and `.security.txt` (`email:security@audren.xyz`) bound to `env!("CARGO_PKG_VERSION")`. Mainnet releases MUST replace `DEV_DETERMINISTIC_VK` with the Phase-2 MPC ceremony verifying key and build deterministically in Docker via `./scripts/upgrade-program.sh build-verifiable`.
2. **Zero-drift local parity across IDLs, 4 SDKs, WASM prover, Relayer, Web & Docs:** Any protocol or version change must align all 12 release manifests, regenerate `idl/*` and `packages/sdk/src/idl.ts` via `python3 idl/generate-idl.py`, rebuild `audren_circuits.wasm` into `packages/sdk/wasm/` and `apps/web/public/wasm/` when `crates/audren-circuits` changes, regenerate Swift/Kotlin bindings via `./scripts/build-mobile-sdks.sh bindings` when `crates/audren-ffi` changes, update `apps/web/lib/protocol.ts` and `docs/DEPLOYMENTS.md`, and pass `python3 idl/verify-idl.py`.
3. **On-chain Solana Program Metadata (`ProgM6JCCvbYkfKqJYHePx4xxSUSqJp7rh8Lyv7nk7S`):** Every Devnet and Mainnet program upgrade MUST republish and round-trip verify both canonical `security` (`GU7K3e7p8zUHoKQuQ1fidi9atxQc3UN1e3Q1Xomzs2Lj`) and `idl` (`5QoLwK1C3NpUXjsHEV14RsQE65MaaiT9WxGvoTyxBPsn`) accounts via `./scripts/upgrade-program.sh <devnet|mainnet>`.
4. **Solana Verified Builds (`verifycLy8mB96wd9wqq3WDXQwM4oU6r42Th37Db9fC`):** Every Mainnet upgrade MUST come from a clean, pushed commit on `https://github.com/audren-xyz/audren`, update the Otter Verify PDA (`FUQpuou8R4iDA5iMVTZiCB6X8uMdWdhSXxgo85Viv4Qt`), and pass OtterSec remote attestation (`verify.osec.io`).
5. **Annotated Git Tag & GitHub Release (`v<version>`):** Every Mainnet upgrade cuts an annotated git tag `v<version>` and publishes a GitHub Release attaching `audren.so`, `audren.so.sha256`, `audren.codama.json`, `audren.anchor.json`, and `security.json`.
6. **Live Web App & Relayer parity + timeless docs:** Keep `apps/web/lib/protocol.ts`, `apps/web`, and `apps/relay` synced with live deployments. Keep all docs, READMEs, IDLs, and comments strictly present-tense and authoritative.

## Open-source hygiene & secret safety (MANDATORY)

- **NEVER commit secrets, private RPC URLs, Cloudflare `account_id`s, or operator keypairs.**
- Local operator files live strictly in gitignored paths: `.credentials/`, `apps/relay/wrangler.prod.jsonc`, `apps/web/wrangler.prod.jsonc`, `apps/relay/.dev.vars`, `apps/web/.dev.vars`.
- Public tracked `wrangler.jsonc` files must remain 100% self-hostable out of the box.
- Never hardcode or fall back to throttled public Solana RPC endpoints.
- Never run `solana program close` on `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`.

## Verification commands

```bash
cargo check --manifest-path program/Cargo.toml
cargo check --manifest-path program/Cargo.toml --features no-entrypoint
cargo test --manifest-path program/Cargo.toml
cargo check --manifest-path tests/mock-router/Cargo.toml
cargo check --manifest-path tests/mock-hook/Cargo.toml
cargo check --workspace --tests
cargo test -p audren-core
cargo test -p audren-circuits --release
python3 idl/verify-idl.py
pnpm --dir packages/sdk typecheck && pnpm --dir packages/sdk test
pnpm --dir apps/relay typecheck && pnpm --dir apps/relay test
pnpm --dir apps/web check && pnpm --dir apps/web e2e:audit
```
