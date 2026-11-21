# Audren

Private ownership and payments with existing Solana assets. Spending keys remain with the user; Solana verifies locally generated proofs.

[Try the demo](https://audren.xyz/demo/) · [How it works](https://audren.xyz/how-it-works/) · [Compare privacy models](https://audren.xyz/compare/) · [Specification](ARCHITECTURE.md)

## What you can do

- Deposit native SOL, classic SPL tokens and transferable Token-2022 assets into shared on-chain vaults without an Audren-issued wrapper token.
- Send privately to a reusable Audren receiving address. Private Transfer proofs conceal the spent record; fresh recipient keys and blinded commitments protect recipient linkage, token and amount.
- Merge records, swap through a compatible PDA-signing router, withdraw to a public wallet, or share a selected note receipt.
- Discover records through standard Solana account RPC and WebSocket subscriptions. No protocol-specific indexer or trusted-setup ceremony is required.

Deposits, public withdrawals and external DEX execution expose tokens and amounts. Withdrawals expose the destination. Fee payers and transaction metadata are public; a separate relayer avoids attaching the user's own wallet as fee payer but can observe network metadata. Candidate sets, timing and external information affect unlinkability. Greater TVL alone is not a privacy guarantee.

Assets remain in program-controlled vaults, and the spending key authorizes private records. Vault balances are inspectable; they alone do not prove coverage of all private liabilities. Token issuer controls still apply.

## Start building

| Component | Purpose |
| --- | --- |
| [crates/client](crates/client) | Rust key management, local proving, scanner and transaction builders |
| [packages/sdk](packages/sdk) | Zero-runtime-dependency TypeScript codecs, account readers, RPC helpers, router planning and Solana v1 serialization; built ESM and declarations |
| [crates/audren-core](crates/audren-core) | Shared wire constants, account layouts, instruction tags and errors |
| [program](program) | Isolated on-chain sBPFv3 program |
| [tests/mock-router](tests/mock-router) | Adversarial router fixture for LiteSVM |
| [build-sbf.py](build-sbf.py) | Pinned standalone sBPFv3 builder |

The TypeScript package does **not** include a prover or wallet key management and is not advertised as an npm registry release. Build and pack it from source using its [SDK guide](packages/sdk/README.md). Use the Rust client for full proof generation. [Examples](https://github.com/audren-xyz/examples) distinguish offline planning from live transaction lifecycles.

## Deployment and trust boundaries

Program on Solana Mainnet and Devnet: `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`.

- [Program and current authority](https://solscan.io/account/AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3)
- [Pool 0 configuration](https://solscan.io/account/5Bvt5f5QMfsVb9TyX8bzkRMvAX6JSWwRtnymGveF9U3G)
- [Native SOL vault](https://solscan.io/account/EhVt54eHXmWzDqngDiBXhw6ePWa9eEoBAHsMfnNCn5nr)
- [Token vault authority holdings](https://solscan.io/account/7rQ6vQNMwBwzAFK1gcwFuJwK4DybLUGVBfxJfgVw8X9o#portfolio)

The deployment is pre-audit and upgradeable. The current program lets full-note withdrawals bypass its pool pause; valid proofs, available assets, fees, network operation and applicable token permissions are still required. Partial withdrawals remain pause-gated. Upgrade authority can change program behavior.

This source repository is not a reproducible-build attestation for the deployed binary. A successful source build or a local artifact hash match alone does not establish source-to-deployment equivalence. Independently verify the source revision, pinned build environment, resulting ELF and on-chain ProgramData before relying on such equivalence.

## Build and verify

Host Rust is pinned by `rust-toolchain.toml`; Node 22+ is required for the TypeScript package. From the repository root:

```bash
cargo check --workspace --all-targets --locked
cargo check --manifest-path program/Cargo.toml --locked
cargo test --workspace --lib --locked
pnpm --dir packages/sdk install --frozen-lockfile
pnpm --dir packages/sdk typecheck
pnpm --dir packages/sdk test
```

Compile both SBF fixtures before running LiteSVM. The builder uses host Rust 1.97.1 independently of the host workspace pin. Python 3.11+ and access to the pinned builder/tool downloads are required. Use a dedicated builder for release artifacts.

```bash
rustup toolchain install 1.97.1 --profile minimal
python3 build-sbf.py --manifest-path program/Cargo.toml --sbf-out-dir target/deploy
python3 build-sbf.py --manifest-path tests/mock-router/Cargo.toml --sbf-out-dir target/deploy
cargo test --test litesvm_e2e --locked -- --nocapture
```

The builder pins cargo-build-sbf and platform-tools, checks sBPFv3 ELF headers and writes an artifact stamp. Its stamp is not a source digest or deployment attestation. The Devnet lifecycle test spends Devnet SOL; Mainnet smoke tests spend real assets and network fees. Live tests are opt-in; use a dedicated funded Devnet key and your configured RPC endpoint. Never commit keys or RPC credentials.

## License

Apache-2.0. See [LICENSE](LICENSE). Contributor invariants and checks live in [AGENTS.md](AGENTS.md).
