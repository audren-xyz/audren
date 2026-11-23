# Audren Protocol Architecture & Cryptographic Specification

This specification documents the Audren v1 (`PROTOCOL_VERSION = 1`, release `1.2.0`) on-chain state machine, account byte layouts, BN254 Groth16 4-ary Depth-20 global MASP equations, `ExecViaEscrow` custody isolation invariants, zero-indexer wallet synchronization, and sBPFv3 runtime engineering implemented by `program/` (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`).

---

## 1. Accounts, PDAs & Binary Layouts

All accounts use `audren_*` PDA seeds, fixed offsets, little-endian integers, 8-byte ASCII magics (`AUD1*`), and zero `realloc` so every account stays within Solana's `10,240 B` CPI allocation limit (`MAX_CPI_ACCOUNT_ALLOC`) and remains compatible with Agave Account Data Direct Mapping.

### PDA Derivation Table (12 Canonical PDAs)

| Account | Seeds | Size | Role |
|---|---|---:|---|
| `PoolState` | `["audren_pool", pool_id_le4]` | `128 B` | Pool authority, pending authority (2-step transfer / permanent renounce), pause flag, `active_lanes` (`4 -> 8 -> 16`), `vault_auth_bump`, checkpoint cadence/max-age, rent caps (`AUD1PL01`) |
| `vault_auth` | `["audren_vault_auth", pool_id_le4]` | `0 B` | Unified PDA owner of all canonical SPL / Token-2022 custody ATAs, including the canonical WSOL ATA for Native SOL (`SyncNative`) |
| `LaneTreeState` | `["audren_lane", pool_id_le4, lane_u8]` | `1,824 B` | Per-lane (`0..15`) incremental 4-ary Poseidon Merkle frontier (`next_leaf`, `nf_count`, `current_root`) (`AUD1LN01`) |
| `LaneRentVault` | `["audren_lane_rent", pool_id_le4, lane_u8]` | `16 B` | Self-funding rent reserve paying permissionless `OpenPage` allocations (`AUD1RV01`) |
| `SubtreePage` | `["audren_subtree", pool_id_le4, lane_u8, seq_le8]` | `8,256 B` | `256` BN254 Fr note commitments (`256 * 32 B`) forming one level-4 4-ary subtree (`AUD1SB01`) |
| `SubtreeRootPage` | `["audren_subroot", pool_id_le4, lane_u8, seq_le8]` | `9,664 B` | `300` finalized level-4 subtree roots (`300 * 32 B`) for stateless witness reconstruction (`AUD1SR01`) |
| `MemoPage` | `["audren_memo", pool_id_le4, lane_u8, seq_le8]` | `10,240 B` | `96` Structure-of-Arrays versioned note memos (`2 B` view tags at `64..256`, `32 B` X25519 epks at `256..3,328`, `72 B` AEAD ciphertexts at `3,328..10,240`; `106 B` wire entry) (`AUD1MM01`) |
| `NullifierPage` | `["audren_nf_page", pool_id_le4, lane_u8, seq_le8]` | `9,664 B` | `600` sequential `16 B` nullifier prefixes for zero-indexer outbound spend detection (`AUD1NF01`) |
| `RootCheckpoint` | `["audren_ckpt", pool_id_le4, slot_idx_le2]` | `704 B` | 256-slot bounded ring storing `super_root`, `lane_roots[16]`, `lane_counts[16]`, `epoch_id`, `published_slot` (`AUD1CK01`) |
| `NullifierPDA` | `["audren_nf", pool_id_le4, nf_32]` | `0 B` | Permanent anti-double-spend marker (account existence = spent) |
| `escrow` | `["audren_escrow", pool_id_le4, shard_u8]` | `0 B` | Isolated CPI signer shard (`0..16`) for `ExecViaEscrow` |
| `unwrap_pda` | `["audren_unwrap", pool_id_le4, nf0_32]` | `165 B` (ephemeral) | 1-shot WSOL token account created & closed atomically to `payer` (refunding rent + WSOL) while transferring `amount_out` SOL to `recipient` and optional `relayer_fee` SOL to `fee_recipient` during `Transact(WITHDRAW_FLAG_UNWRAP_WSOL)` |

---

## 2. Cryptographic Construction (BN254 Groth16 + 4-ary Poseidon)

Audren uses a single frozen BN254 Groth16 circuit (`JoinSplit4AryCircuit`, `vk_id = 0`, `17,861` R1CS constraints, `2^15` FFT domain, `192 B` proof) verified on-chain via Solana's native `alt_bn128` pairing syscall (`groth16-solana`). All in-circuit and on-chain hashes use identical Circom / `sol_poseidon` BN254 Poseidon parameters with explicit domain separators:

- **Key derivation & BIP-350 Bech32m `aud1...` stealth addresses:**
  - `spend_sk = HKDF-SHA256(seed, "audren/v1/root", "audren/v1/spend_sk")` (masked to 253-bit BN254 Fr)
  - `spend_pk = Poseidon2(DOMAIN_PK, spend_sk)` (`DOMAIN_PK = 1`)
  - `nk = Poseidon2(DOMAIN_NK, spend_sk)` (`DOMAIN_NK = 10`; read-only nullifier key shared in Mode 2 `FullViewingKey`)
  - `view_sk = HKDF-SHA256(seed, "audren/v1/root", "audren/v1/view_sk")`, `view_pk = X25519(view_sk)`
  - Stealth address: 114-character lowercase BIP-350 Bech32m (`hrp = "aud"`, 65-byte payload `0x01 || spend_pk[32] || view_pk[32]`).
- **Stealth ownership, unified asset ID & note commitment:**
  - `stealth_owner = Poseidon3(DOMAIN_STEALTH, spend_pk, tweak)` (`DOMAIN_STEALTH = 2`)
  - `asset_id = mask_to_fr_be(SHA-256("audren/v1/asset" || mint_32))` (Native SOL and WSOL share canonical `WSOL_MINT = So11111111111111111111111111111111111111112`)
  - `cm = Poseidon5(DOMAIN_NOTE, stealth_owner, asset_id, amount, blinding)` (`DOMAIN_NOTE = 3`)
- **Versioned `72 B` encrypted memos (`106 B` SoA wire entry):**
  - Wire format: `view_tag[2] || epk[32] || ct[72]`, stored in Structure-of-Arrays columns inside `MemoPage` (`96` notes/page = `10,240 B`).
  - X25519 ECDH rejects all non-contributory / low-order points (`shared == 0`) across encryption, view-tag filtering, and decryption.
  - Plaintext (`56 B`): `amount_le[8] || mint[32] || memo_ver[1] (=1) || memo_flags[1] (=0) || payment_id[14]`, sealed via RFC 8439 ChaCha20-Poly1305 with `34 B` AEAD AAD (`view_tag[2] || epk[32]`) and `audren/v1/*` KDF labels (`audren/v1/vt`, `audren/v1/key`, `audren/v1/nonce`, `audren/v1/tweak`, `audren/v1/blind`).
  - Dynamic swap memos (`ExecViaEscrow`) use domain-separated `audren/v1/{dyn_tweak,dyn_blind,dyn_mask}` to XOR-mask `72 B` `AUD1DYN1 || actual_out_le8 || out_mint_32 || zero_pad_24`.
- **Key-separated nullifiers:**
  - Real input: `nf = Poseidon4(DOMAIN_NULLIFIER, nk, cm, (lane_id << 36) | leaf_idx)` (`DOMAIN_NULLIFIER = 4`, global leaf index across the 16-lane 4-ary Depth-20 tree)
  - Dummy input (when spending 1 real note in a 2-in proof): `nf = Poseidon3(DOMAIN_DUMMY_NF, nk, blinding)` (`DOMAIN_DUMMY_NF = 5`, with optional `omit_nf1` economic 1-input format)
- **Global 4-ary Depth-20 MASP tree (`4^20` notes):**
  - 16 parallel lanes occupy the top 2 levels (`4^2 = 16`); each lane owns a Depth-18 4-ary subtree (`4^18` notes).
  - `PublishCheckpoint` (`Tag 4`) hashes all 16 lane roots (empty uninitialized lanes hash deterministically via `ZERO_HASHES_4ARY[18]`) into one `super_root` stored in `RootCheckpoint`.
  - Expanding `active_lanes` monotonically (`4 -> 8 -> 16`) leaves the circuit, verifying key, and all historical checkpoints completely unchanged.
- **Public-input compression & context binding:**
  - All external execution parameters (`pool_id`, `vk_id`, `out_lane_id`, `output_mask`, `asset_mode`, `unwrap_wsol`, `recipient`, `relayer_fee_recipient`, `public_asset_id`, `public_amount_out`, `relayer_fee_amount`, `memos`, and for `ExecViaEscrow` also `router_prog`, `hash(router_accounts)`, `router_ix_data`, `min_amount_out`, `fee_on_output`, `out_stealth_owner`, `out_blinding`, `34 B` dynamic memo header & `72 B` XOR mask) are hashed via SHA-256 (`audren/v1/ctx`, `audren/v1/exec_ctx`, `audren/v1/router_accs`) and masked into a 253-bit BN254 Fr `ctx_hash` verified inside the single `public_input_hash` scalar.

---

## 3. Zero-Indexer Wallet Synchronization (`CompactWalletStore`)

Wallets synchronize directly against any ordinary Solana RPC endpoint using batched `getMultipleAccounts` calls — no centralized indexer, CDN, or private query server is required:

1. Fetch `PoolState` + active `LaneTreeState` headers.
2. In default `'strict'` privacy mode, incremental syncs (`<= 25` new `MemoPage`s) fetch full `10,240 B` `MemoPage`s directly in uniform 100-account batches (never issuing hit-correlated single-page re-fetches); large historical catch-ups use deterministic wallet-keyed decoy selection (`SHA-256(view_sk || "audren/v1/decoy" || ...)`) for sealed `SubtreePage` fetches. Opt-in `'fast'` mode enables `[0..3,328]` SoA `dataSlice` pre-filtering on large catch-ups (`> 25` pages) for bandwidth-constrained recovery over trusted/self-hosted RPCs.
3. Filter `MemoPage` entries by 2-byte `view_tag` (~99.998% skip rate, rejecting low-order X25519 epks), decrypt matching `72 B` ChaCha20-Poly1305 ciphertexts with `34 B` AAD (or unmask `72 B` `AUD1DYN1` dynamic swap memos), and **mandatorily** verify `computeNoteCommitment(...) == onchain_leaf` before accepting any note.
4. Pass 2 unconditionally streams all new `NullifierPage`s up to `lane.nf_count` in uniform 100-account batches (zero early-exit when 0 unspent notes exist or after the last unspent note is marked spent), matching against owned unspent notes and immediately discarding stranger prefixes.
5. Freeze the 12 intra-subtree siblings (`384 B` per owned note), store `32 B` finalized level-4 subtree roots and unsealed frontier tail leaves in encrypted local storage, and **immediately discard** every sealed `SubtreePage` and `MemoPage`.

---

## 4. `ExecViaEscrow` Custody Isolation, Canonical ATAs & Pool Governance

1. `NullifierPDA` creation and `NullifierPage` append execute **before** the external router CPI.
2. Only the selected `escrow` shard PDA (`0..16`) signs the external CPI; `vault_auth` and `payer` are never signers.
3. All pool vault ATAs (`vault_auth`) and escrow ATAs (`escrow`) are strictly validated as canonical Associated Token Accounts (`validate_canonical_ata`) across `Deposit` (`Tag 3`), `Transact` (`Tag 5`), and `ExecViaEscrow` (`Tag 6`).
4. The escrow firewall rejects any `router_accounts` containing the Audren program, `PoolState`, `LaneTreeState`, pages, checkpoints, `NullifierPDA`, or `vault_auth` custody ATAs.
5. Pre- and post-CPI invariants enforce token account owner, delegate = None, `close_authority = None`, zero lamport drain on `escrow` / `escrow_in` / `escrow_out`, and net vault output receipt `actual_out >= min_amount_out` (with optional `EXEC_FLAG_FEE_ON_OUTPUT` deduction after CPI).
6. Unified `Deposit` (`Tag 3`, handling Native SOL via atomic `SyncNative` WSOL as well as Classic SPL and Token-2022) and SPL/Token-2022-only `ExecViaEscrow` (`Tag 6`) commit the **measured net vault delta** (`after - before > 0`), keeping Token-2022 `TransferFeeConfig` and `TransferHook` mints strictly solvent.
7. `UpdatePool` (`Tag 8`) allows the current authority to update checkpoint/rent parameters, perform 2-step authority handoff (`propose` -> `accept`), or permanently renounce pool authority (explicitly rejected while `paused == true`).

---

## 5. Privacy Boundaries and Effective Anonymity

- **Public boundaries:** Unified deposits (`Tag 3 Deposit`), public withdrawals (`Tag 5 Transact` with `ASSET_MODE_PUBLIC` and optional `WITHDRAW_FLAG_UNWRAP_WSOL`), external DeFi CPI calls (`Tag 6 ExecViaEscrow`), and stateful positions opened by deterministic `DefiSessionKeypair` wallets remain observable on Solana.
- **Input-count & correlation boundaries:** Optional 1-input spends (`omit_nf1 = true`) save one `NullifierPDA` rent allocation while exposing that 1 input rather than 2 was spent; padded 2-input spends conceal arity. Timing, amount matching, asset rarity, and RPC/relayer IP correlation are external operational factors outside cryptographic proof unlinkability.
- **Selective disclosure & institutional auditability:**
  - **Mode 1 (`SelectiveDisclosureProof`):** Discloses one note's `(stealth_owner, mint, amount, blinding)` verifiable against its on-chain `SubtreePage` leaf without exposing spend keys, viewing keys, or unrelated history.
  - **Mode 2 (`FullViewingKey`):** Exports `(spend_pk, nk, view_sk, view_pk)` for read-only inbound and outbound portfolio accounting without spend capability.
- **Ceremony & audit status:** `vk_id = 0` (`program/src/vk_generated.rs` & `audren_joinsplit.pk`, SHA-256 `2b22603e...7ee4`) is anchored to the official Hermez/PSE Perpetual Powers of Tau (`powersOfTau28_hez_final_15.ptau`, 71+ independent public contributors) plus Audren's verifiable BGM17 Phase-2 ceremony with a live drand Quicknet (`#34194203`) and Solana Mainnet finalized blockhash (`#472705896`) beacon (`ceremony/transcript.json`). Additional community Phase-2 contributions remain open, and an independent third-party audit is pending prior to revoking BPF upgrade authority.
