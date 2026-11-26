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

> **Direct IDL vs. Prover/Raw Framing Scope:** `Deposit` (`Tag 3`), `OpenPage` (`Tag 2`), and pool/lane admin instructions are directly callable from the published IDLs alone. Shielded spends (`Tag 5 Transact`) and atomic DeFi CPIs (`Tag 6 ExecViaEscrow`) additionally require local BN254 Groth16 proof generation (`audren_joinsplit.pk`) and raw (un-length-prefixed) binary trailing framing plus conditional rollover/token/router accounts documented in [`crates/audren-core/src/instruction.rs`](../crates/audren-core/src/instruction.rs) and implemented in the optional open-source SDK builders (`audren-client`, `@audren/sdk`, Swift, Kotlin). Anchor's default Borsh serializer prefixes `bytes` fields with a `u32` length, which the on-chain program rejects on `Transact`, `ExecViaEscrow`, and `UpdatePool`.

## Regenerating & Verifying Against Rust Source

IDLs are deterministically derived from `crates/audren-core/src/{lib.rs,instruction.rs,layout.rs}` so all 9 instruction tags (`0..=8`: `InitPool`, `InitLane`, `OpenPage`, `Deposit`, `InitRootHistory`, `Transact`, `ExecViaEscrow`, `SetPaused`, `UpdatePool`), 8 account byte layouts (`PoolState` 128 B, `LaneRentVault` 16 B, `LaneTreeState` 1,824 B, `SubtreePage` 8,256 B, `SubtreeRootPage` 9,664 B, `MemoPage` 10,240 B, `NullifierPage` 9,664 B, `GlobalRootHistory` 10,216 B), 12 PDA seeds (`audren_*`, including `audren_roots` -> `249YJTuRtiKAnh346Tc18kF9bHrktdrTzyJMtvUKUgC7`), and 33 error codes (`6000..=6032`, including `6007 = InvalidRootRing`, `6008 = RootIndexOutOfBounds`, `6009 = RootHistoryMismatch`) remain strictly synchronized with the on-chain sBPFv3 program:

```bash
python3 idl/generate-idl.py
python3 idl/verify-idl.py
```

## On-Chain Solana Program Metadata (`ProgM6JCCvbYkfKqJYHePx4xxSUSqJp7rh8Lyv7nk7S`)

Audren publishes both its canonical **Codama IDL** (`seed: "idl"`, PDA `5QoLwK1C3NpUXjsHEV14RsQE65MaaiT9WxGvoTyxBPsn`) and **Security metadata** (`seed: "security"`, PDA `GU7K3e7p8zUHoKQuQ1fidi9atxQc3UN1e3Q1Xomzs2Lj`) on-chain via the Solana Foundation Program Metadata standard (`@solana-program/program-metadata`), read directly by Solana Explorer, Solscan, and Codama tooling.

Use `./scripts/upgrade-program.sh metadata <devnet|mainnet>` to publish and round-trip verify both accounts, or `./scripts/upgrade-program.sh check <devnet|mainnet>` to audit live cluster parity.
