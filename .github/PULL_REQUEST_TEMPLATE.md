## Summary

- What changed and why?

## Affected Packages

- [ ] `program/` (on-chain sBPFv3 program)
- [ ] `crates/audren-core/`, `crates/audren-circuits/`, `crates/client/`, or `crates/audren-ffi/`
- [ ] `ceremony/`, `idl/` (Codama / Anchor IDLs or `security.json`), or `spec/test-vectors.json`
- [ ] `packages/sdk/` (`@audren/sdk`), `packages/swift/`, or `packages/kotlin/`
- [ ] `apps/relay/` (Privacy Relayer)
- [ ] `apps/web/` (Web App & Docs)
- [ ] `docs/` or `scripts/`

## Verification

- [ ] `python3 idl/verify-idl.py` passes cleanly
- [ ] `cargo clippy -- -D warnings` and `cargo check` pass for `program/`, `tests/mock-router/`, `tests/mock-hook/`, and `--workspace --tests`, plus `cargo test --manifest-path program/Cargo.toml`
- [ ] `cargo run -p audren-circuits --release --bin ceremony -- verify` passes cleanly
- [ ] `pnpm` typecheck/tests/build pass for touched TypeScript packages (`packages/sdk`, `apps/relay`, `apps/web`)
- [ ] If `crates/audren-ffi/` changed: regenerated Swift/Kotlin bindings and conformance tests pass
- [ ] If `program/` changed: LiteSVM E2E & Cross-SDK suites pass (`litesvm_e2e`, `cross_sdk_litesvm`)
- [ ] No secrets, keypairs, private RPC endpoints, or private Wrangler configs included
