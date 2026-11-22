# Audren Program IDLs & On-Chain Metadata

Complete, machine-verified Interface Definition Languages (IDLs) and canonical security metadata for the Audren Solana programs.

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

IDLs are deterministically derived from `crates/audren-core/src/{lib.rs,instruction.rs,layout.rs}` so all 9 instruction tags (`0..=8`), 8 account byte layouts (`PoolState` 128 B, `LaneRentVault` 16 B, `LaneTreeState` 1,824 B, `SubtreePage` 8,256 B, `SubtreeRootPage` 9,664 B, `MemoPage` 10,144 B, `NullifierPage` 9,664 B, `RootCheckpoint` 704 B), 13 PDA seeds (`audren_v2_*`), and 33 error codes (`6000..=6032`) remain strictly synchronized with the on-chain sBPFv3 program:

```bash
python3 idl/generate-idl.py
python3 idl/verify-idl.py
```

## On-Chain Solana Program Metadata (`ProgM6JCCvbYkfKqJYHePx4xxSUSqJp7rh8Lyv7nk7S`)

Audren publishes both its canonical **Codama IDL** (`seed: "idl"`, PDA `5QoLwK1C3NpUXjsHEV14RsQE65MaaiT9WxGvoTyxBPsn`) and **Security metadata** (`seed: "security"`, PDA `GU7K3e7p8zUHoKQuQ1fidi9atxQc3UN1e3Q1Xomzs2Lj`) on-chain via the Solana Foundation Program Metadata standard (`@solana-program/program-metadata`), read directly by Solana Explorer, Solscan, and Codama tooling.

Use `./scripts/upgrade-program.sh metadata <devnet|mainnet>` to publish and round-trip verify both accounts, or `./scripts/upgrade-program.sh check <devnet|mainnet>` to audit live cluster parity.
