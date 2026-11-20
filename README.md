# Audren

Private multi-asset settlement, router-agnostic DEX swaps, and verifiable compliance on Solana (`sBPFv3`).

Native SOL, Classic SPL tokens, and transferable Token-2022 mints share one shielded pool. Users can shield assets, send private transfers, execute single-transaction private swaps through any Solana DEX aggregator or AMM router, and produce selective disclosure or institutional audit proofs — with no trusted setup.

## Core Capabilities

- **Unified Multi-Asset Shielded Pool:** Native SOL, Classic SPL (USDC, USDT, EURC, JitoSOL, cbBTC), and transferable Token-2022 mints (including regulated issuers with `PermanentDelegate` such as PYUSD, USDG, and CASH, fee-on-transfer `TransferFeeConfig` via exact post-transfer vault delta accounting, and `TransferHook` mints via sanitized trailing hook accounts) share a single pool. Per-mint Ristretto255 generators (`G_mint`) hide sender, recipient, token mint, and amount inside Pedersen commitments (`V = v * A + r * H`). Soulbound `NonTransferable` mints are rejected natively by Token-2022.
- **Single-Transaction Private DEX Swaps (`SwapViaRouter`):** Route shielded swaps through any Solana DEX aggregator or AMM router — Jupiter, Orca, Raydium, Meteora, Phoenix, Titan, DFlow, or custom routers — without unshielding to a public wallet. Exact `amount_in` moves into one of 16 isolated `swap_escrow` PDA shards that signs the external CPI; `vault_auth` never signs an external CPI, and `actual_out >= min_amount_out` settles directly into an unlinkable stealth note.
- **Selective Disclosure & Institutional Auditability:** Pools initialize as either `Permissionless` (user-controlled per-transaction `SelectiveDisclosureProof` and read-only `FullViewingKey` exports) or `InstitutionalAudited`, where every spend cryptographically proves valid ElGamal encryption of the spent stealth key and hidden mint to `PoolState::auditor_pk` on-chain with zero custody or freeze authority.
- **No Trusted Setup:** Spend authorization, nullifier uniqueness, asset conservation, and optional auditor encryption use pure Ristretto255 Multi-Base Binary Triptych (`32 / 64 / 128`-note rings) verified via Agave's native `sol_curve_multiscalar_mul` syscall and native `ZkE1Gama1Proof` 64-bit Bulletproofs.
- **Standard Solana RPC State Discovery:** Notes append into fixed `6,240 B` Structure-of-Arrays `EpochPage` PDAs (`32` notes/page). Wallets scan up to 100 pages (`3,200` notes) per standard `getMultipleAccounts` call using `dataSlice: { offset: 64, length: 1056 }` (~`106 KB`) or subscribe live via Agave `programSubscribe`, checking spend status through 0-byte `NullifierPDA` existence.
- **Chunked MTU Execution (`ProofBuffer`):** Large proof payloads upload in parallel out-of-order `<= 768 B` chunks (`WriteProofBuffer`, each serialized transaction `<= 1,071 B`), execute zero-copy via `ExecBuffered`, and atomically refund 100% of buffer rent to the payer in the same transaction.

## Deployed Program

Identical `274,672 B` sBPFv3 binary (SHA-256 `3a4b8b2a53dd5c9752fb5423008a5b39f22e5f2b6e530eaa6215a43d3ad9256f`) deployed on Solana Mainnet-Beta and Devnet:

| Cluster | Program ID | Pool `#0` (`Permissionless`) PDA | Slot |
| --- | --- | --- | ---: |
| **Solana Mainnet-Beta** | `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3` | `5Bvt5f5QMfsVb9TyX8bzkRMvAX6JSWwRtnymGveF9U3G` | `471551234` |
| **Solana Devnet** | `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3` | `5Bvt5f5QMfsVb9TyX8bzkRMvAX6JSWwRtnymGveF9U3G` | `524184821` |

- **ProgramData (Mainnet & Devnet):** `Gj4hW4KuMTNR9YTPmixRPsNcMNwRvYTXdksxLgoGRiVM`

## Instruction Set & Measured Compute Units

Measured on sBPFv3 (`LiteSVM`, Agave 4.3):

| Tag | Instruction | Measured CU | Description |
| --- | --- | ---: | --- |
| `0x00` | `InitPool` | `35,697 – 47,687` | Create `PoolState` (`192 B`), `EpochPage #0` (`6,240 B`), `sol_vault`, `page_rent_vault` |
| `0x01` | `OpenPage` | `18,179 – 28,679` | Permissionless rollover allocating `page_id + 1` funded by `PageRentVault` via live `Rent::get()` |
| `0x02` | `Deposit` | `19,030 – 38,813` | Shield Native SOL, Classic SPL, or Token-2022 to any stealth address (no ZK proof required) |
| `0x03` | `Transfer` (`m = 5`, 32-note ring) | `451,591 – 485,822` | Private 1-in -> 2-out transfer (Triptych + CrossBase2 + Agave `BatchedRangeProofU128`) |
| `0x03` | `Transfer` (`m = 5`, audited) | `506,766` | Audited transfer enforcing ElGamal `(S_1, S_2)` + `(M_1, M_2)` under `K_aud` |
| `0x03` | `Transfer` (`m = 6 / m = 7`) | `824,512 / 1,113,133` | 64-note (2-page) / 128-note (4-page) rings inside Solana's default 32 KiB heap |
| `0x04` | `Merge` | `573,054` | Consolidate 2 shielded notes of the same asset into 1 note |
| `0x05` | `SwapViaRouter` | `405,291` | Isolated `swap_escrow` CPI to any Solana DEX router (~`995k CU` left for routing) |
| `0x06` | `Withdraw` (full / with change) | `237,386 / 353,280` | Unshield exact amount to a recipient wallet/ATA with optional stealth change note |
| `0x07` | `SetPaused` | `< 5,000` | Emergency governance pause (zero vault custody) |
| `0x08` | `WriteProofBuffer` | `2,818 – 9,800` | Parallel `<= 768 B` chunk upload (`<= 1,071 B` wire tx) |
| `0x09` | `ExecBuffered` | *(target ix CU)* | Execute buffered instruction zero-copy and refund 100% of buffer rent |
| `0x0A` | `CloseProofBuffer` | `982` | Reclaim 100% of buffer rent from an abandoned upload |

## Repository Structure

```text
crates/audren-core/   #![no_std] account layouts, PDA seeds, wire sizes, and error codes
program/              On-chain sBPFv3 Solana program (isolated from host workspace)
crates/client/        Rust SDK (provers, RPC/WS scanner, router swap builder, LiteSVM tests)
tests/mock-router/    Minimal sBPFv3 router program for adversarial SwapViaRouter tests
packages/sdk/         Zero-dependency TypeScript SDK (@audren/sdk)
ARCHITECTURE.md       Cryptographic equations, binary layouts, and custody invariants
AGENTS.md             Engineering invariants and verification rules for contributors and agents
```

## Verification & Testing

```bash
# Typecheck workspace crates and sBPFv3 program
cargo check --workspace --all-targets
cargo check --manifest-path program/Cargo.toml

# Run unit tests
cargo test --workspace --lib

# Typecheck TypeScript SDK
pnpm --dir packages/sdk typecheck

# Run full LiteSVM integration & adversarial suites (requires compiled sBPFv3 .so artifacts)
cargo test --test litesvm_e2e -- --nocapture

# Run live Devnet lifecycle test against AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3
AUDREN_RPC_URL="https://your-devnet-rpc" \
AUDREN_KEYPAIR_PATH="/path/to/devnet-keypair.json" \
cargo test --test devnet_live test_live_devnet_full_shielded_lifecycle -- --ignored --nocapture
```

## Examples

Runnable Rust and TypeScript integrations (shielded transfers, institutional audit decryption, RPC `dataSlice` scanning, and Jupiter v6 `SwapViaRouter` integration) live in [`audren-xyz/examples`](https://github.com/audren-xyz/examples).

## License

Apache-2.0. See [LICENSE](./LICENSE).
