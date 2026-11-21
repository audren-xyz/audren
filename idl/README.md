# Audren Program IDLs & On-Chain Metadata

Complete, machine-verified Interface Definition Languages (IDLs) and canonical security metadata for every Solana program in this repository.

## Published Files

| File | Standard | Program | Address |
| :--- | :--- | :--- | :--- |
| [`audren.codama.json`](./audren.codama.json) | **Codama v1.8.0** (canonical Solana standard) | `audren` (`program/`) | `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3` |
| [`audren.anchor.json`](./audren.anchor.json) | **Anchor v0.30+ compatible** (`spec: 0.1.0`) | `audren` (`program/`) | `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3` |
| [`security.json`](./security.json) | **Solana Program Metadata (`security`)** | `audren` (`program/`) | `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3` |
| [`audren-mock-router.codama.json`](./audren-mock-router.codama.json) | **Codama v1.8.0** | `audren-mock-router` (`tests/mock-router/`) | Test-only (ephemeral LiteSVM ID) |

Both `audren.codama.json` and `audren.anchor.json` are bundled and exported directly from `@audren/sdk`:

```ts
import { AUDREN_CODAMA_IDL, AUDREN_ANCHOR_IDL } from "@audren/sdk";
```

## Regenerating & Verifying Against Rust Source

IDLs are deterministically derived from `crates/audren-core/src/{lib.rs,instruction.rs,layout.rs}` so instruction tags (`0..=12`), account byte layouts (`PoolState` 192 B, `EpochPage` 6,240 B, `AppendLaneState` 64 B, sentinels 16 B, `ProofBuffer` 48+N B, `NullifierPDA` 0 B), PDA seeds (all 10), and error codes (`1..=33`) remain strictly synchronized with the on-chain sBPFv3 program:

```bash
python3 idl/generate-idl.py
python3 idl/verify-idl.py
```

## On-Chain Solana Program Metadata (`ProgM6JCCvbYkfKqJYHePx4xxSUSqJp7rh8Lyv7nk7S`)

Audren publishes both its canonical **Codama IDL** (`seed: "idl"`, PDA `5QoLwK1C3NpUXjsHEV14RsQE65MaaiT9WxGvoTyxBPsn`) and **Security metadata** (`seed: "security"`, PDA `GU7K3e7p8zUHoKQuQ1fidi9atxQc3UN1e3Q1Xomzs2Lj`) on-chain via the Solana Foundation Program Metadata standard (`@solana-program/program-metadata`), read directly by Solana Explorer, Solscan, and Codama tooling.

### Publishing with the upgrade authority

```bash
# Publish canonical security metadata
npx @solana-program/program-metadata write security \
  AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3 \
  ./idl/security.json \
  --format json \
  --keypair /path/to/upgrade-authority.json \
  --rpc "$SOLANA_RPC_URL"

# Publish canonical Codama IDL
npx @solana-program/program-metadata write idl \
  AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3 \
  ./idl/audren.codama.json \
  --format json \
  --keypair /path/to/upgrade-authority.json \
  --rpc "$SOLANA_RPC_URL"
```

Or publish and round-trip verify both in one step using `./scripts/upgrade-program.sh metadata <devnet|mainnet>`. Every program upgrade through `./scripts/upgrade-program.sh <devnet|mainnet>` automatically republishes both `security` and `idl` metadata (and updates Solana Verified Build attestation on Mainnet) so on-chain metadata never drifts from the deployed program.

Audit live cluster parity anytime with:

```bash
./scripts/upgrade-program.sh check mainnet
./scripts/upgrade-program.sh check devnet
```

### Fetching & verifying on-chain metadata

```bash
npx @solana-program/program-metadata fetch security \
  AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3 \
  --rpc "$SOLANA_RPC_URL"

npx @solana-program/program-metadata fetch idl \
  AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3 \
  --rpc "$SOLANA_RPC_URL"
```

## Generating Clients with Codama

```bash
npx @codama/cli generate --idl ./idl/audren.codama.json
```
