# Contributing to Audren

Thank you for your interest in contributing to Audren. Every change is verified automatically against on-chain program layouts, IDLs, SDKs, relayer policy, and documentation.

## Before You Start

1. Read [`AGENTS.md`](AGENTS.md) for architecture invariants and zero-drift rules.
2. Read [`ARCHITECTURE.md`](ARCHITECTURE.md) if your change touches `program/`, `crates/audren-core/`, or `crates/client/`.
3. For security vulnerabilities, **do not** open a public issue or pull request — follow [`SECURITY.md`](SECURITY.md) (`security@audren.xyz`).

## Local Verification Checklist

Before opening a pull request, run the full zero-drift and typecheck suite:

```bash
# 1. Zero-drift verification (IDLs, SDK, relayer, web protocol register, docs, manifests)
python3 idl/verify-idl.py

# 2. Rust program, mock router, and workspace checks
cargo check --manifest-path program/Cargo.toml
cargo check --manifest-path program/Cargo.toml --features no-entrypoint
cargo check --manifest-path tests/mock-router/Cargo.toml
cargo check --workspace --tests

# 3. TypeScript SDK, Privacy Relayer, and Web UI checks
pnpm --dir packages/sdk typecheck && pnpm --dir packages/sdk test
pnpm --dir apps/relay typecheck
pnpm --dir apps/web typecheck

# 4. Cross-language conformance suites (Rust, FFI, Swift & Kotlin)
cargo test -p audren-client --test conformance_vectors
cargo test -p audren-ffi --test conformance_ffi
./scripts/build-mobile-sdks.sh bindings
swift test --package-path packages/swift          # macOS
gradle -p packages/kotlin test --rerun-tasks      # JVM 21+ / Android
```

If your change modifies any instruction, account layout, PDA seed, error code, or `security.json`, regenerate the IDLs and SDK mirrors first:

```bash
python3 idl/generate-idl.py && python3 idl/verify-idl.py
```

If your change modifies `program/` or `tests/mock-router/`, build the deterministic sBPFv3 artifacts and run the LiteSVM end-to-end suite:

```bash
python3 scripts/build-sbf.py --manifest-path program/Cargo.toml --sbf-out-dir target/deploy
python3 scripts/build-sbf.py --manifest-path tests/mock-router/Cargo.toml --sbf-out-dir target/deploy
cargo test --test litesvm_e2e -- --nocapture
```

## Pull Request Guidelines

- Keep pull requests focused and include tests for new behavior or bug fixes.
- Never commit private keypairs, `.credentials/`, `wrangler.prod.jsonc`, private RPC URLs, or personal Cloudflare account IDs.
- All changes are licensed under [Apache-2.0](LICENSE).
