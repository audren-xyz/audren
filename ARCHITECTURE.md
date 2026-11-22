# Audren Protocol Architecture & Cryptographic Specification

This specification documents the on-chain state machine, account byte layouts, BN254 Groth16 4-ary Depth-20 global MASP equations, `ExecViaEscrow` custody isolation invariants, zero-indexer wallet synchronization, and sBPFv3 runtime engineering implemented by `program/` (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`).

---

## 1. Accounts, PDAs & Binary Layouts

All accounts use `audren_v2_*` PDA seeds, fixed offsets, little-endian integers, 8-byte ASCII magics, and zero `realloc` so every account stays strictly below Solana's `10,240 B` CPI allocation limit and remains compatible with Agave Account Data Direct Mapping.

### PDA Derivation Table (13 Canonical PDAs)

| Account | Seeds | Size | Role |
|---|---|---:|---|
| `PoolState` | `["audren_v2_pool", pool_id_le4]` | `128 B` | Pool authority, pause flag, `active_lanes` (`4 -> 8 -> 16`), checkpoint cadence/max-age, rent caps |
| `sol_vault` | `["audren_v2_sol", pool_id_le4]` | `0 B` | Unified custody PDA holding native SOL across all lanes |
| `vault_auth` | `["audren_v2_vauth", pool_id_le4]` | `0 B` | Unified PDA owner of all SPL / Token-2022 custody ATAs |
| `LaneTreeState` | `["audren_v2_lane", pool_id_le4, lane_u8]` | `1,824 B` | Per-lane (`0..15`) incremental 4-ary Poseidon Merkle frontier (`next_leaf`, `nf_count`, `current_root`) |
| `LaneRentVault` | `["audren_v2_lrent", pool_id_le4, lane_u8]` | `16 B` | Self-funding rent reserve paying permissionless `OpenPage` allocations |
| `SubtreePage` | `["audren_v2_sub", pool_id_le4, lane_u8, seq_le8]` | `8,256 B` | `256` BN254 Fr note commitments (`256 * 32 B`) forming one level-4 4-ary subtree |
| `SubtreeRootPage` | `["audren_v2_sr", pool_id_le4, lane_u8, seq_le8]` | `9,664 B` | `300` finalized level-4 subtree roots (`300 * 32 B`) for stateless witness reconstruction |
| `MemoPage` | `["audren_v2_memo", pool_id_le4, lane_u8, seq_le8]` | `10,144 B` | `112` Structure-of-Arrays encrypted note memos (`2 B` view tags, `32 B` epks, `56 B` AEAD ciphertexts) |
| `NullifierPage` | `["audren_v2_nfpg", pool_id_le4, lane_u8, seq_le8]` | `9,664 B` | `600` sequential `16 B` nullifier prefixes for zero-indexer outbound spend detection |
| `RootCheckpoint` | `["audren_v2_ckpt", pool_id_le4, slot_idx_u8]` | `704 B` | 256-slot bounded ring storing `super_root`, `lane_roots[16]`, `lane_counts[16]`, `epoch_id`, `published_slot` |
| `NullifierPDA` | `["audren_v2_nf", pool_id_le4, nf_32]` | `0 B` | Permanent anti-double-spend marker (account existence = spent) |
| `escrow` | `["audren_v2_escrow", pool_id_le4, shard_u8]` | `0 B` | Isolated CPI signer shard (`0..16`) for `ExecViaEscrow` |
| `unwrap_pda` | `["audren_v2_unwrap", pool_id_le4, nf0_32]` | `165 B` (ephemeral) | 1-shot WSOL token account created & closed atomically to `recipient` during `JoinSplit(unwrap_wsol=true)` |

---

## 2. Cryptographic Construction (BN254 Groth16 + 4-ary Poseidon)

Audren uses a single frozen BN254 Groth16 circuit (`JoinSplit4AryCircuit`, `vk_id = 0`, `17,861` R1CS constraints, `2^15` FFT domain, `192 B` proof) verified on-chain via Solana's native `alt_bn128` pairing syscall (`groth16-solana`). All in-circuit and on-chain hashes use identical Circom / `sol_poseidon` BN254 Poseidon parameters with explicit domain separators:

- **Key derivation:**
  - `spend_sk = HKDF-SHA256(seed, "audren/v2/root", "audren/v2/spend_sk")` (masked to 253-bit BN254 Fr)
  - `spend_pk = Poseidon2(DOMAIN_SPEND_PK, spend_sk)`
  - `nk = Poseidon2(DOMAIN_NULLIFIER_KEY, spend_sk)` (read-only nullifier key shared in Mode 2 `FullViewingKey`)
  - `view_sk = HKDF-SHA256(seed, "audren/v2/root", "audren/v2/view_sk")`, `view_pk = X25519(view_sk)`
- **Stealth ownership & note commitment:**
  - `stealth_owner = Poseidon2(spend_pk, tweak)`
  - `asset_id = Poseidon2(DOMAIN_ASSET_ID, mint_lo16, mint_hi16)`
  - `cm = Poseidon5(DOMAIN_COMMITMENT, stealth_owner, asset_id, amount, blinding)`
- **Key-separated nullifiers:**
  - Real input: `nf = Poseidon4(DOMAIN_NULLIFIER, nk, leaf_idx, tweak)`
  - Dummy input (when spending 1 real note in a 2-in proof): deterministic domain-separated dummy nullifier with optional `omit_nf1` economic 1-input format
- **Global 4-ary Depth-20 MASP tree (`4^20` notes):**
  - 16 parallel lanes occupy the top 2 levels (`4^2 = 16`); each lane owns a Depth-18 4-ary subtree (`4^18` notes).
  - `PublishCheckpoint` (`Tag 5`) hashes all 16 lane roots (empty uninitialized lanes hash deterministically via `ZERO_HASHES_4ARY[18]`) into one `super_root` stored in `RootCheckpoint`.
  - Expanding `active_lanes` monotonically (`4 -> 8 -> 16`) leaves the circuit, verifying key, and all historical checkpoints completely unchanged.
- **Public-input compression & context binding:**
  - All external execution parameters (`pool_id`, `out_lane_id`, `output_mask`, `asset_mode`, `unwrap_wsol`, `recipient`, `relayer_fee_recipient`, `public_asset_id`, `public_amount_out`, `relayer_fee_amount`, `memos`, and for `ExecViaEscrow` also `router_prog`, `hash(router_accounts)`, `router_ix_data`, `min_amount_out`, `fee_on_output`, `out_stealth_owner`, `out_blinding`, dynamic memo header & XOR mask) are hashed via SHA-256 and masked into a 253-bit BN254 Fr `ctx_hash` verified inside the single `public_input_hash` scalar.

---

## 3. Zero-Indexer Wallet Synchronization (`CompactWalletStore`)

Wallets synchronize directly against any ordinary Solana RPC endpoint using batched `getMultipleAccounts` calls — no centralized indexer, CDN, or private query server is required:

1. Fetch `PoolState` + active `LaneTreeState` headers.
2. Fetch unvisited `SubtreePage`, `MemoPage`, and `NullifierPage` PDAs sequentially per lane.
3. Filter `MemoPage` entries by 2-byte `view_tag` (~99.998% skip rate), decrypt matching `56 B` ChaCha20-Poly1305 payloads (or unmask `AUD2DYN2` dynamic swap memos), and **mandatorily** verify `computeNoteCommitment(...) == onchain_leaf` before accepting any note.
4. Freeze the 12 intra-subtree siblings (`384 B` per owned note), store `32 B` finalized level-4 subtree roots, frontier tail leaves, and `16 B` nullifier prefixes in encrypted local storage, and **immediately discard** every sealed `SubtreePage` and `MemoPage`.

---

## 4. `ExecViaEscrow` Custody Isolation & Token-2022 Solvency

1. `NullifierPDA` creation and `NullifierPage` append execute **before** the external router CPI.
2. Only the selected `escrow` shard PDA (`0..16`) signs the external CPI; `vault_auth` and `payer` are never signers.
3. The escrow firewall rejects any `router_accounts` containing the Audren program, `PoolState`, `LaneTreeState`, pages, checkpoints, `NullifierPDA`, `sol_vault`, or `vault_auth` ATAs.
4. Pre- and post-CPI invariants enforce token account owner, delegate = None, `close_authority = None`, zero lamport drain on `escrow` / `escrow_in` / `escrow_out`, and net vault output receipt `actual_out >= min_amount_out` (with optional `EXEC_FLAG_FEE_ON_OUTPUT` deduction after CPI).
5. `DepositSpl` (`Tag 4`) and `ExecViaEscrow` (`Tag 7`) commit the **measured net vault delta** (`after - before > 0`), keeping Token-2022 `TransferFeeConfig` and `TransferHook` mints strictly solvent.

---

## 5. Privacy Boundaries and Effective Anonymity

- **Public boundaries:** Deposits (`Tag 3`/`Tag 4`), withdrawals (`Tag 6`), external DeFi CPI calls (`Tag 7 ExecViaEscrow`), and stateful positions opened by deterministic `DefiSessionKeypair` wallets remain observable on Solana.
- **Input-count & correlation boundaries:** Optional 1-input spends (`omit_nf1 = true`) save one `NullifierPDA` rent allocation while exposing that 1 input rather than 2 was spent; padded 2-input spends conceal arity. Timing, amount matching, asset rarity, and RPC/relayer IP correlation are external operational factors outside cryptographic proof unlinkability.
- **Selective disclosure & institutional auditability:**
  - **Mode 1 (`SelectiveDisclosureProof`):** Discloses one note's `(stealth_owner, mint, amount, blinding)` verifiable against its on-chain `SubtreePage` leaf without exposing spend keys, viewing keys, or unrelated history.
  - **Mode 2 (`FullViewingKey`):** Exports `(spend_pk, nk, view_sk, view_pk)` for read-only inbound and outbound portfolio accounting without spend capability.
- **Ceremony & audit status:** `vk_id = 0` (`program/src/vk_generated.rs` & `audren_joinsplit.pk`, SHA-256 `2b22603e...7ee4`) is anchored to the official Hermez/PSE Perpetual Powers of Tau (`powersOfTau28_hez_final_15.ptau`, 71+ independent public contributors) plus Audren's verifiable BGM17 Phase-2 ceremony with a live drand Quicknet (`#34194203`) and Solana Mainnet finalized blockhash (`#472705896`) beacon (`ceremony/transcript.json`). Additional community Phase-2 contributions remain open, and an independent third-party audit is pending prior to revoking BPF upgrade authority.
