# Audren Protocol Architecture & Specification

## 1. Multi-Asset Pool & On-Chain Accounts

### `PoolState` (`192 B`, PDA `["audren_pool", pool_id_le]`)
| Offset | Size | Field | Description |
|---|---:|---|---|
| `0..8` | 8 | `magic` | `"AUDRNPL1"` |
| `8` | 1 | `version` | `1` (crypto-agile verifier version byte) |
| `9` | 1 | `bump` | Canonical PDA bump |
| `10` | 1 | `mode` | `0 = Permissionless`, `1 = InstitutionalAudited` |
| `11` | 1 | `paused` | Governance circuit breaker (never grants authority vault custody) |
| `12..16` | 4 | `pool_id` | `u32 LE` |
| `16..24` | 8 | `current_page_id` | `u64 LE` active append-only `EpochPage` |
| `24..32` | 8 | `total_notes` | `u64 LE` monotonic note counter |
| `32..40` | 8 | `total_spends` | `u64 LE` monotonic nullifier counter |
| `40..48` | 8 | `page_rent_fee_lamports` | Max per-note rent contribution (dynamically capped via live `Rent::get()` and skipped once `PageRentVault` holds a 2-page rollover buffer) |
| `48..80` | 32 | `authority` | Pause / governance authority (zero custody over vaults) |
| `80..112` | 32 | `auditor_pk` | Compressed Ristretto255 `K_aud` (zero when `Permissionless`) |
| `112..116` | 4 | flags & bumps | `auditor_locked`, `vault_auth_bump`, `sol_vault_bump`, `page_rent_bump` |
| `116..192` | 76 | reserved | Zero-initialized forward-compatibility bytes |

### Structure-of-Arrays `EpochPage` (`6,240 B`, PDA `["audren_page", pool_id_le, page_id_le]`)
Fixed-size column-major page holding up to 32 notes, strictly below Solana's `10,240 B` per-CPI allocation limit (`MAX_PERMITTED_DATA_INCREASE`) with zero `realloc` (compatible with Agave Account Data Direct Mapping, `SIMD-0460`).

| Offset | Size | Slice | Description |
|---|---:|---|---|
| `0..64` | 64 | `PageHeader` | `"AUDRNPG1"`, `version`, `bump`, `closed`, `count (0..=32)`, `pool_id`, `page_id`, open/close slots |
| `64..96` | 32 | `view_tags[32]` | 1-byte fast filter (`255/256` rejection per note) |
| `96..1,120` | 1,024 | `ephemeral_pks[32]` | Stealth ECDH ephemeral pubkeys `R = r * G` |
| `1,120..2,144` | 1,024 | `stealth_pks[32]` | One-time spend pubkeys `P = S + H(shared) * G` |
| `2,144..3,168` | 1,024 | `asset_tags[32]` | Re-randomized asset commitments `A = G_mint + a * H` |
| `3,168..4,192` | 1,024 | `commitments[32]` | Value commitments `V = v * A + r * H` |
| `4,192..6,240` | 2,048 | `ciphertexts[32]` | `64 B` AES-256-GCM encrypted note memos (`48 B` payload + `16 B` tag) |

**Standard RPC & WebSocket Discovery:** Placing `view_tags[32]` and `ephemeral_pks[32]` contiguously at `[64..1,120]` lets wallets scan up to **100 pages (`3,200` notes)** per `getMultipleAccounts` call using `dataSlice: { offset: 64, length: 1056 }` (~`106 KB`), or stream new notes via Agave `programSubscribe` `dataSlice`. Spent status is checked directly via 0-byte `NullifierPDA` (`["audren_null", pool_id_le, nullifier]`) existence.

### Multi-Asset Asset Generators & Token-2022 Support
- Every mint maps deterministically to a NUMS Ristretto255 base `G_mint = HashToRistretto("audren/v1/mint", mint)` (`[0u8; 32]` for Native SOL).
- All supported assets share the same `EpochPage` anonymity sets.
- Audren supports Native SOL, Classic SPL tokens, and all transferable Token-2022 mints:
  - **Exact net-delta accounting (`TransferFeeConfig`):** `Deposit` and `SwapViaRouter` measure the actual vault token balance delta (`after - before > 0`) and commit `V = net_received * G_mint`, preserving exact 1:1 vault solvency even when a mint withholds a non-zero transfer fee (`bps > 0`).
  - **Regulated issuers (`PermanentDelegate`):** Token-2022 stablecoins and RWAs carrying `PermanentDelegate` (such as PYUSD, USDG, and CASH) are accepted natively alongside Classic SPL stablecoins (USDC, USDT, EURC). Note that issuer-level `PermanentDelegate` or `FreezeAuthority` powers remain inherent to the mint itself.
  - **Transfer hooks (`TransferHook`):** Mints with an inactive `TransferHook` (`program_id == None`) take a zero-allocation 5-account CPI fast path. Mints with an active `TransferHook` forward sanitized, non-signer trailing hook accounts while blocking Audren-owned accounts and custody vaults from ever entering the hook CPI.
  - **Withdrawals never blocked:** `Withdraw` never rejects a mint on extensions; soulbound `NonTransferable` mints are rejected natively by Token-2022 at `transfer_checked`.

---

## 2. Cryptographic Verification

### Multi-Base Binary Triptych (`verify_triptych`)
For ring size `N = 2^m` (`m = 5`: 1 page / 32 notes; `m = 6`: 2 pages / 64 notes; `m = 7`: 4 pages / 128 notes), the verifier combines all 5 (or 7 in `InstitutionalAudited` mode) verification equations via Fiat-Shamir batching weights `mu_2..mu_7` into chunked invocations of Agave's native `sol_curve_multiscalar_mul` syscall inside the default `32 KiB` heap:

1. **Bit linearity:** `A + xi * B - sum(f_j * H_j) - z_A * H == 0`
2. **Bit booleanity:** `xi * C + D - sum(f_j * (xi - f_j) * H_j) - z_C * H == 0`
3. **Stealth ownership (`P_l = x * G`):** `sum(p_k(xi) * P_k) - sum(xi^j * X_j) - z_x * G == 0`
4. **Unique nullifier (`x * J = U`):** `xi^m * U - sum(xi^j * Y_j) - z_x * J == 0`
   - Unpopulated tail slots store `P_k = IDENTITY`, forcing `x = 0` and `0 * J = U`, which is impossible because `U != IDENTITY`.
5. **Asset & value conservation:** `sum(p_k(xi) * (A_k + alpha * V_k)) - xi^m * (A_spend + alpha * V_spend) - sum(xi^j * W_j) - z_q * H == 0`
6. **Audited ElGamal `S_1 = r_s * G` (`InstitutionalAudited`):** `xi^m * S_1 - sum(xi^j * T_j) - z_aud * G == 0`
7. **Audited ElGamal `S_2 = P_l + r_s * K_aud` (`InstitutionalAudited`):** `xi^m * S_2 - sum(p_k(xi) * P_k) - sum(xi^j * E_j) - z_aud * K_aud == 0`

### Cross-Base Bridges & Native Agave Bulletproofs
- `verify_cross_base_1` (`128 B`) and `verify_cross_base_2` (`256 B`, also proving `A_2 - A_1 = (a_2 - a_1) * H` for independent unlinkable output asset tags) link hidden-asset commitments `V = v * A + t * H` to standard Agave Pedersen commitments `C = v * G + s * H`.
- Agave's native `ZkE1Gama1Proof11111111111111111111111111111` program verifies `v in [0, 2^64)` via zero-rent CPI (`BatchedRangeProofU64` `672 B` / `BatchedRangeProofU128` `736 B`).

### Solana Transaction Version 1 (`0x81`, 4,096 B) & Optional `ProofBuffer` (`Tags 8 / 9 / 10`)
- Audren uses **Solana Transaction Version 1 (SIMD-0385)** (`4,096 B` max wire size, inline `TransactionConfig` compute budget and priority fee), enabling single-transaction direct execution for `Deposit`, `Transfer` (`m = 5/6/7`), `Merge`, `SwapViaRouter`, and `Withdraw`.
- For oversized multi-hop swap or proof payloads exceeding `4,096 B`, `WriteProofBuffer` (`Tag 8`) writes parallel out-of-order `<= 768 B` chunks tracked by a `u16` `written_mask` inside an ephemeral PDA (`["audren_buf", payer, nonce_le_8]`, `<= 10,032 B`).
- `ExecBuffered` (`Tag 9`, `2 B` instruction data) verifies and executes `Transfer`, `Merge`, `SwapViaRouter`, or `Withdraw` zero-copy from the buffer, then zeroes magic, resizes to `0 B`, reassigns to the System Program, and refunds 100% of rent to `payer` in the same transaction.
- `CloseProofBuffer` (`Tag 10`) reclaims 100% of rent from an abandoned upload back to its authority.

---

## 3. Private DEX Swaps (`SwapViaRouter`, `Tag 5`)

Supports any Solana DEX aggregator or AMM router that accepts a PDA signer (Jupiter, Orca, Raydium, Meteora, Phoenix, Titan, DFlow, or custom routers):

1. **Nullifier-First Ordering & Router Binding:** `NullifierPDA` is created before the external router CPI to prevent re-entrancy and replay. `router_program` is hashed inside the Fiat-Shamir `ctx_hash` so relayers cannot substitute the router.
2. **Custody Isolation:** Exact `amount_in` transfers from `vault_in` (`vault_auth` PDA) into isolated `escrow_in` (`swap_escrow` shard PDA, 16 shards). Only `swap_escrow` signs the external CPI; `vault_auth` and `payer` are never marked signer, and no Audren program/state/vault accounts may appear in `router_accounts`.
3. **Post-CPI Invariants:** `swap_escrow` must remain System-owned, zero-data, and non-drained (`lamports_after >= lamports_before`); every writable `swap_escrow`-owned token account (`escrow_in`, `escrow_out`) is verified pre- and post-CPI for immutable owner (`swap_escrow`), zero delegate, and unchanged `close_authority`.
4. **Slippage & Stealth Settlement:** `actual_out = post_escrow_out - pre_escrow_out >= min_amount_out` sweeps into `vault_out`, commits on-chain as `V_out = actual_out * G_{mint_out}`, and appends to `EpochPage` under the unlinkable stealth pubkey `P_out`. Unspent input either reverts (`allow_partial_refund == false`) or settles into a stealth refund note (`allow_partial_refund == true`).

---

## 4. Selective Disclosure & Institutional Auditability

- **`PoolMode::Permissionless`:**
  - **Mode 1 (`SelectiveDisclosureProof`):** Per-transaction Schnorr/Chaum-Pedersen proof revealing `(amount, mint, recipient)` for a single note to a verifier without sharing any wallet key.
  - **Mode 2 (`FullViewingKey`):** Read-only `(view_secret, spend_pubkey)` export allowing an auditor or accounting system to scan incoming notes with zero spend capability.
- **`PoolMode::InstitutionalAudited`:**
  - Every spend must include ElGamal ciphertexts `(S_1, S_2)` encrypting `P_l` and `(M_1, M_2)` encrypting `G_mint` under `PoolState::auditor_pk`, verified on-chain inside Triptych (Eq 6–7) and `AuditorAssetProof` (`192 B`).
  - The auditor decrypts `P_l = S_2 - k_aud * S_1` and `G_mint = M_2 - k_aud * M_1` offline with zero freeze, pause, or withdrawal authority.
