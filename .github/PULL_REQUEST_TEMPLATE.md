## Summary

- What changed and why?

## Affected Packages

- [ ] `program/` (on-chain sBPFv3 program)
- [ ] `crates/audren-core/` or `crates/client/`
- [ ] `idl/` (Codama / Anchor IDLs or `security.json`)
- [ ] `packages/sdk/` (`@audren/sdk`)
- [ ] `apps/relay/` (Privacy Relayer)
- [ ] `apps/web/` (Web App & Docs)
- [ ] `docs/` or scripts

## Verification

- [ ] `python3 idl/verify-idl.py` passes cleanly
- [ ] `cargo check` passes for `program/`, `tests/mock-router/`, and `--workspace --tests`
- [ ] `pnpm` typecheck/tests pass for touched TypeScript packages
- [ ] If `program/` changed: LiteSVM E2E tests pass (`cargo test --test litesvm_e2e`)
- [ ] No secrets, keypairs, private RPC endpoints, or private Wrangler configs included
