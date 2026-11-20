# Audren Protocol Architecture & Formal Specification

## 1. Account & Storage Model (Zero Indexer)

### `PoolState` (`192 B`, PDA `["audren_pool", pool_id_le]`)
| Offset | Size | Field | Notes |
|---|---:|---|---|
| `0..8` | 8 | `magic` | `"AUDRNPL1"` |
| `8` | 1 | `version` | `1` (crypto-agile verifier hook for PQ `v2`) |
| `9` | 1 | `bump` | Canonical PDA bump |
| `10` | 1 | `mode` | `0 = Permissionless`, `1 = InstitutionalAudited` |
| `11` | 1 | `paused` | Circuit breaker (never grants authority withdrawal rights) |
| `12..16` | 4 | `pool_id` | `u32 LE` |
| `16..24` | 8 | `current_page_id` | `u64 LE` active append-only `EpochPage` |
| `24..32` | 8 | `total_notes` | `u64 LE` monotonic note counter |
| `32..40` | 8 | `total_spends` | `u64 LE` monotonic nullifier counter |
| `40..48` | 8 | `page_rent_fee_lamports` | Max per-note micro-fee (dynamically capped via live `Rent::get()` for `SIMD-0437` and auto-skipped once `PageRentVault` holds a 2-page buffer) |
| `48..80` | 32 | `authority` | Pause / governance authority (zero custody over vaults) |
| `80..112` | 32 | `auditor_pk` | Compressed Ristretto255 `K_aud` (zero when `Permissionless`) |
| `112..116` | 4 | flags & bumps | `auditor_locked`, `vault_auth_bump`, `sol_vault_bump`, `page_rent_bump` |
| `116..192` | 76 | reserved | Zero-initialized forward-compatibility bytes |

### Structure-of-Arrays `EpochPage` (`6,240 B`, PDA `["audren_page", pool_id_le, page_id_le]`)
Sized strictly under Solana's `10,240 B` (`10 KiB`) per-CPI `system::allocate` limit (`MAX_PERMITTED_DATA_INCREASE`) for atomic 1-CPI `OpenPage` rollovers and zero-copy Agave 4.5 Account Data Direct Mapping (`SIMD-0460`).

| Offset | Size | Slice | Purpose |
|---|---:|---|---|
| `0..64` | 64 | `PageHeader` | `"AUDRNPG1"`, `version`, `bump`, `closed`, `count (0..=32)`, `pool_id`, `page_id`, slots |
| `64..96` | 32 | `view_tags[32]` | 1-byte fast filter (`255/256` rejection per note) |
| `96..1,120` | 1,024 | `ephemeral_pks[32]` | Stealth ECDH ephemeral pubkeys `R = r * G` |
| `1,120..2,144` | 1,024 | `stealth_pks[32]` | One-time spend pubkeys `P = S + H(shared) * G` |
| `2,144..3,168` | 1,024 | `asset_tags[32]` | Re-randomized asset commitments `A = G_mint + a * H` |
| `3,168..4,192` | 1,024 | `commitments[32]` | Value commitments `V = v * A + r * H` |
| `4,192..6,240` | 2,048 | `ciphertexts[32]` | `64 B` AES-256-GCM note memos (`48 B` payload + `16 B` tag) |

**Pure-RPC & WebSocket Scan Bandwidth:** `dataSlice: { offset: 64, length: 1056 }` fetches `view_tags[32] + ephemeral_pks[32]` across **100 pages (`3,200` notes)** in a single `getMultipleAccounts` call (~`106 KB` total), or streams real-time updates via Agave 4.4 `programSubscribe` `dataSlice`.

---

## 2. Cryptographic Verification Surface (~520 LOC Ristretto255)

### Multi-Base Binary Triptych (`verify_triptych`)
For ring size `N = 2^m` (`m = 5` -> 1 page / 32 notes; `m = 6` -> 2 pages / 64 notes; `m = 7` -> 4 pages / 128 notes), the verifier combines all 5 (or 7 in audited mode) verification equations via random batching weights `mu_2..mu_7` into **one single Agave `sol_curve_multiscalar_mul` syscall** (`<= 439` points):

1. **Bit linearity:** `A + xi * B - sum(f_j * H_j) - z_A * H == 0`
2. **Bit booleanity:** `xi * C + D - sum(f_j * (xi - f_j) * H_j) - z_C * H == 0`
3. **Stealth ownership (`P_l = x * G`):** `sum(p_k(xi) * P_k) - sum(xi^j * X_j) - z_x * G == 0`
4. **Unique nullifier (`x * J = U`):** `xi^m * U - sum(xi^j * Y_j) - z_x * J == 0`
   - *Empty slot immunity:* Any unpopulated tail slot has `P_k = IDENTITY`, forcing `x = 0` and `0 * J = U`, which is impossible since `U != IDENTITY`.
5. **Asset & value conservation:** `sum(p_k(xi) * (A_k + alpha * V_k)) - xi^m * (A_spend + alpha * V_spend) - sum(xi^j * W_j) - z_q * H == 0`
6. **Audited ElGamal `S_1 = r_s * G` (when `InstitutionalAudited`):** `xi^m * S_1 - sum(xi^j * T_j) - z_aud * G == 0`
7. **Audited ElGamal `S_2 = P_l + r_s * K_aud` (when `InstitutionalAudited`):** `xi^m * S_2 - sum(p_k(xi) * P_k) - sum(xi^j * E_j) - z_aud * K_aud == 0`

### Cross-Base Bridge & Agave Native Bulletproofs
- `verify_cross_base_1` (`128 B`) and `verify_cross_base_2` (`256 B`, also proving `A_2 - A_1 = (a_2 - a_1) * H` for independent unlinkable output asset tags) link hidden-asset commitments `V = v * A + t * H` to standard Agave Pedersen commitments `C = v * G + s * H`.
- Agave's audited `ZkE1Gama1Proof11111111111111111111111111111` proves `v ∈ [0, 2^64)` via zero-rent CPI (`BatchedRangeProofU64` `672 B` / `BatchedRangeProofU128` `736 B`), eliminating scalar wraparound inflation.

### Ephemeral `ProofBuffer` (`Tags 8 / 9 / 10` — Strict `1,232 B` Solana Packet MTU)
- Because full Multi-Base Triptych (`928–1,728 B`) + Cross-Base + Bulletproof payloads exceed Solana's `1,232 B` UDP/QUIC single-transaction packet MTU, `WriteProofBuffer` (`Tag 8`) accepts out-of-order parallel `<= 768 B` chunks (`~1,059 B` wire tx) tracked by a `u16` `written_mask` inside a `<= 10,032 B` PDA (`["audren_buf", payer, nonce]`).
- `ExecBuffered` (`Tag 9`, `2 B` instruction data) executes `Transfer`, `Merge`, `SwapViaRouter`, or `Withdraw` zero-copy directly from the verified buffer and atomically closes `ProofBuffer`, refunding `100%` of its rent lamports back to `payer` in the same transaction. `CloseProofBuffer` (`Tag 10`) reclaims `100%` rent from any abandoned upload.

---

## 3. Non-Custodial 1-Tx Router-Agnostic Private Swap Invariants (`SwapViaRouter`)

Works natively with any Solana DEX aggregator or AMM router (Jupiter, Raydium, Orca, Meteora, Phoenix, Titan, DFlow, or custom routers):

1. **Nullifier-First Ordering & Router Binding:** `NullifierPDA` is created before the external router CPI, preventing re-entrancy or replay. `router_program` is cryptographically bound inside the Fiat-Shamir `ctx_hash`, preventing relayers from substituting the router.
2. **Custody Isolation:** Exact `amount_in` moves from `vault_in` (`vault_auth` PDA) into isolated `escrow_in` (`swap_escrow` shard PDA). Only `swap_escrow` signs the external router CPI; `vault_auth` and `payer` are NEVER marked signer, and no Audren program/state/vault accounts may be forwarded into `router_accounts`.
3. **Post-CPI Guardrails:** `swap_escrow` is verified to remain System-owned, zero-data, and non-drained (`lamports_after >= lamports_before`); every writable `swap_escrow`-owned token account (`escrow_in`, `escrow_out`) is checked pre- and post-CPI for immutable owner (`swap_escrow`), zero delegate, and unchanged `close_authority`.
4. **Slippage & Stealth Settlement:** `actual_out = post_escrow_out - pre_escrow_out >= min_amount_out` is swept immediately to `vault_out`, committed on-chain as `V_out = actual_out * G_{mint_out}`, and appended to `EpochPage` under the unlinkable stealth pubkey `P_out`. Any unspent input either reverts (`allow_partial_refund == false`) or sweeps back into a stealth refund note (`allow_partial_refund == true`).
