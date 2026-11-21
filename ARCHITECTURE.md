# Audren Protocol Architecture & Cryptographic Specification

This specification documents the on-chain state machine, account byte layouts, cryptographic soundness proofs, swap custody isolation invariants, and wire framing implemented by this repository (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`).

---

## 1. Accounts, PDAs & Binary Layouts

All accounts use fixed offsets, little-endian integers, 8-byte ASCII magics, and zero `realloc` so they remain compatible with Solana's `10,240 B` CPI allocation cap and Agave Account Data Direct Mapping (`SIMD-0460`).

### PDA Derivation Table

| Account | Seeds | Size | Role |
|---|---|---:|---|
| `PoolState` | `["audren_pool", pool_id_le4]` | `192 B` | Pool configuration, Lane 0 cursor, optional `auditor_pk`, active lane count |
| `EpochPage` | `["audren_page", pool_id_le4, page_id_le8]` | `6,240 B` | Fixed 32-note Structure-of-Arrays anonymity set page |
| `NullifierPDA` | `["audren_null", pool_id_le4, J_32]` | `0 B` | Permanent anti-double-spend marker (existence = spent) |
| `vault_auth` | `["audren_vault", pool_id_le4]` | `0 B` | PDA owner of all SPL / Token-2022 custody ATAs |
| `sol_vault` | `["audren_sol", pool_id_le4]` | `16 B` | Custody PDA holding native SOL (8 B magic `"AUDRNSL1"` + bump) |
| `page_rent_vault` | `["audren_rent", pool_id_le4]` | `16 B` | Self-funding Lane 0 rollover reserve (8 B magic `"AUDRNRN1"` + bump) |
| `swap_escrow` | `["audren_escrow", pool_id_le4, shard_u8]` | `0 B` | Isolated CPI signer shard (`shard_u8 in 0..16`) for `SwapViaRouter` |
| `ProofBuffer` | `["audren_buf", authority_32, nonce_le8]` | `<= 10,032 B` | Ephemeral chunked payload PDA; closed atomically on `ExecBuffered` |
| `AppendLaneState` | `["audren_lane", pool_id_le4, lane_u8]` | `64 B` | Parallel append lane cursor (`lane_u8 in 1..16`) |
| `lane_rent_vault` | `["audren_lrent", pool_id_le4, lane_u8]` | `16 B` | Self-funding rollover reserve for parallel lane `1..15` |

### `PoolState` (`192 B`)

| Offset | Size | Field | Description |
|---|---:|---|---|
| `0..8` | 8 | `magic` | `"AUDRNPL1"` |
| `8` | 1 | `version` | `1` (crypto-agile verifier version byte) |
| `9` | 1 | `bump` | Canonical PDA bump |
| `10` | 1 | `mode` | `0 = Permissionless`, `1 = InstitutionalAudited` |
| `11` | 1 | `paused` | Governance circuit breaker (never grants authority vault custody) |
| `12..16` | 4 | `pool_id` | `u32 LE` |
| `16..24` | 8 | `current_page_id` | `u64 LE` active Lane 0 `EpochPage` |
| `24..32` | 8 | `total_notes` | `u64 LE` monotonic Lane 0 note counter |
| `32..40` | 8 | `total_spends` | `u64 LE` monotonic Lane 0 spend counter |
| `40..48` | 8 | `page_rent_fee_lamports` | Max per-note rent contribution (dynamically capped via live `Rent::get()` and skipped once `PageRentVault` holds a 2-page rollover buffer) |
| `48..80` | 32 | `authority` | Pause / lane-init authority (zero custody over vaults) |
| `80..112` | 32 | `auditor_pk` | Compressed Ristretto255 `K_aud` (zero when `Permissionless`) |
| `112..116` | 4 | flags & bumps | `auditor_locked`, `vault_auth_bump`, `sol_vault_bump`, `page_rent_bump` |
| `116` | 1 | `active_lanes` | `0` or `1` = Lane 0 only; `2..=16` = Lanes `0..active_lanes-1` active |
| `117..192` | 75 | reserved | Zero-initialized forward-compatibility bytes |

### `AppendLaneState` (`64 B`, Lanes `1..15`)

| Offset | Size | Field | Description |
|---|---:|---|---|
| `0..8` | 8 | `magic` | `"AUDRNLN1"` |
| `8..12` | 4 | header bytes | `version`, `lane_id (1..16)`, `bump`, `rent_vault_bump` |
| `12..16` | 4 | `pool_id` | `u32 LE` |
| `16..24` | 8 | `current_page_id` | `u64 LE` encoded as `(lane_id << 56) \| seq` |
| `24..32` | 8 | `created_slot` | `u64 LE` |
| `32..64` | 32 | reserved | Zero-initialized |

Parallel append lanes eliminate global `PoolState` write-lock contention: appends targeting lane `1..15` pass `PoolState` **read-only** while sharing 100% of custody vaults (`sol_vault`, `vault_auth` ATAs) and canonical `NullifierPDA`s. Cross-lane anonymity sets are fully unified: any `EpochPage` from any lane can be combined in an `m = 5/6/7` ring.

### Structure-of-Arrays `EpochPage` (`6,240 B`, `32` notes/page)

| Offset | Size | Slice | Description |
|---|---:|---|---|
| `0..64` | 64 | `PageHeader` | `"AUDRNPG1"`, `version`, `bump`, `closed`, `count (0..=32)`, `pool_id`, `page_id`, `created_slot`, `closed_slot` |
| `64..96` | 32 | `view_tags[32]` | 1-byte fast filter (`255/256` rejection before scalar multiplication) |
| `96..1,120` | 1,024 | `ephemeral_pks[32]` | Stealth ECDH ephemeral pubkeys `R = r * G` |
| `1,120..2,144` | 1,024 | `stealth_pks[32]` | One-time spend pubkeys `P = S + H(shared) * G` |
| `2,144..3,168` | 1,024 | `asset_tags[32]` | Re-randomized asset commitments `A = G_mint + a * H` |
| `3,168..4,192` | 1,024 | `commitments[32]` | Value commitments `V = v * A + r_v * H` |
| `4,192..6,240` | 2,048 | `ciphertexts[32]` | `64 B` AES-256-GCM encrypted note payloads (`48 B` plaintext + `16 B` tag) |

**Indexer-free RPC discovery:** `view_tags[32]` and `ephemeral_pks[32]` sit contiguously at `[64..1,120]`. Wallets scan up to **100 pages (`3,200` notes)** per standard `getMultipleAccounts` call using `dataSlice: { offset: 64, length: 1056 }` (~`106 KB`), or stream updates via Agave `programSubscribe`, and check spend status via `getMultipleAccounts` on 0-byte `NullifierPDA`s.

---

## 2. Cryptographic Construction & Soundness Proof

Audren operates entirely in the **Ristretto255 prime-order group** (`order l = 2^252 + 27742317777372353535851937790883648493`) with **no trusted setup**. Using Ristretto255 eliminates cofactor/small-subgroup attacks, non-canonical point encodings, and torsion-component nullifier malleability by construction (`validate_ristretto` rejects every invalid encoding).

### Fixed NUMS Generators

- `G`: Ristretto255 standard basepoint (`RISTRETTO_BASEPOINT_POINT`), matching Agave's Pedersen value generator.
- `H`: Agave's exact Pedersen blinding generator (`HashToRistretto(SHA3-512(G))`).
- `U`: Nullifier basepoint (`HashToRistretto("audren/v1/U", "nullifier")`).
- `H_j` (`j = 0..7`): Triptych bit-commitment generators (`HashToRistretto("audren/v1/triptych/H", j_le4)`).
- `G_mint`: Deterministic per-mint asset generator (`HashToRistretto("audren/v1/mint", mint_bytes32)`, where Native SOL uses `[0u8; 32]`).

Because every generator is derived via hash-to-Ristretto with distinct domain separators, no discrete log relation among `{G, H, U, H_0..H_6, G_mint_1, G_mint_2, ...}` is known under the Random Oracle Model.

### Stealth Addressing & Encrypted Payloads

A recipient publishes `(S, V_pk)` where `S = s * G` (spend key) and `V_pk = v_sk * G` (view key). To pay them:
1. Sender samples ephemeral scalar `r` and computes `R = r * G` and ECDH shared secret `shared = r * V_pk`.
2. Sender derives `view_tag = SHA-256("audren/v1/view_tag" || shared)[0]` and stealth tweak `h = HashToScalar("audren/v1/stealth_x", shared)`.
3. One-time spend pubkey is `P = S + h * G`. Only the recipient knows `x = s + h` such that `P = x * G`.
4. Note metadata (`mint`, `amount`, `flags`, `memo`) is encrypted with AES-256-GCM under a key and nonce derived via `HKDF-SHA256(salt = "audren/v1/note_kdf", ikm = shared)`, fitting inside `64 B` (`48 B` plaintext + `16 B` tag).

### Multi-Base Binary Triptych (`verify_triptych`)

For ring size `N = 2^m` (`m = 5`: 1 page / 32 notes; `m = 6`: 2 pages / 64 notes; `m = 7`: 4 pages / 128 notes), the prover proves knowledge of secret index `l in [0, N)`, spend secret `x`, and blinding delta `q` across the ring `{(P_k, A_k, V_k)}_{k=0}^{N-1}` without revealing `l`:

- **Strong Fiat-Shamir transcript binding (SHA-256 `hashv`):**
  1. Per-page digest `page_hash_i = SHA-256("audren/v1/ring/page" || page_id_le8 || prefix_u8 || stealth_pks[..prefix] || asset_tags[..prefix] || commitments[..prefix])`, combined into `ring_root = SHA-256("audren/v1/triptych/ring" || m || audited_u8 || aud_bytes_32 || page_hash_0 || ...)`. Each page's `prefix_count in 1..=page.count` is committed inside the proof so concurrent appends to an open page after proving never invalidate the ring.
  2. `ctx_hash` hashes instruction domain, program ID, pool ID, output commitments/ciphertexts, recipient/mint/amount (for `Withdraw`), and `router_program` + `mints` + `amount_in` + `min_amount_out` + `escrow_shard` + `flags` + optional change/refund wires (for `SwapViaRouter`) — preventing relayers from substituting any public parameter.
  3. Challenge `alpha = HashToScalar("triptych/alpha", ctx_hash, ring_root, A_spend, V_spend)` binds the asset/value balance linear combination before `W[..m]`; challenge `xi = HashToScalar("triptych/xi", ring_root, alpha, J, A, B, C, D, X[..m], Y[..m], W[..m], S_1?, S_2?, T[..m]?, E[..m]?)` binds all prover commitments.
  4. Random batching weights `mu_2..mu_7` are derived from `SHA-256("audren/v1/triptych/batch" || xi || full_proof)` so all verification equations collapse into chunked calls to Agave's native `sol_curve_multiscalar_mul` syscall inside Solana's `32 KiB` heap.

**The 5 (or 7 in `InstitutionalAudited` mode) verification equations:**

1. **Bit linearity:** `A + xi * B - sum(f_j * H_j) - z_A * H == 0`
2. **Bit booleanity:** `xi * C + D - sum(f_j * (xi - f_j) * H_j) - z_C * H == 0`
   - Together, Equations 1–2 enforce that each bit polynomial `f_j = l_j * xi + a_j` has `l_j in {0, 1}`, so the Lagrange indicator polynomial `p_k(xi) = prod_j f_{j, k_j}` has degree `m` (leading term `xi^m`) **if and only if** `k == l`, and degree `< m` for all `k != l`.
3. **Stealth ownership (`P_l = x * G`):** `sum(p_k(xi) * P_k) - sum(xi^j * X_j) - z_x * G == 0`
4. **Unique deterministic nullifier (`x * J = U`):** `xi^m * U - sum(xi^j * Y_j) - z_x * J == 0`
   - Because `z_x` is shared across Equations 3 and 4, extraction yields the exact same scalar `x` satisfying `P_l = x * G` AND `x * J = U`, hence `J = x^{-1} * U` is uniquely determined by the spent note.
   - **Empty tail slots are unspendable:** Slots `idx >= prefix_count` read `P_k = IDENTITY`. Spending an empty slot requires `x * G = IDENTITY => x = 0`, which makes `x * J = 0 * J = IDENTITY != U` — mathematically impossible because `validate_nonzero_point(J)` and `U != IDENTITY` hold unconditionally.
   - Creating `NullifierPDA(["audren_null", pool_id, J])` enforces globally that each note is spent at most once.
5. **Hidden asset & value conservation:** `sum(p_k(xi) * (A_k + alpha * V_k)) - xi^m * (A_spend + alpha * V_spend) - sum(xi^j * W_j) - z_q * H == 0`
   - Because `alpha` is chosen after commitments, Schwartz-Zippel guarantees both `(A_l - A_spend) in <H>` (exact same hidden mint `G_mint`) AND `(V_l - V_spend) in <H>` (exact same hidden value `v_in`) simultaneously.
6. **Audited ElGamal `S_1 = r_s * G` (`InstitutionalAudited`):** `xi^m * S_1 - sum(xi^j * T_j) - z_aud * G == 0`
7. **Audited ElGamal `S_2 = P_l + r_s * K_aud` (`InstitutionalAudited`):** `xi^m * S_2 - sum(p_k(xi) * P_k) - sum(xi^j * E_j) - z_aud * K_aud == 0`

### Cross-Base Bridges (`CrossBase1` / `CrossBase2`) & Native Bulletproofs

Why value conservation alone is not sufficient: in `Transfer`, the prover must prove `V_spend == V_pay + V_chg` **and** that neither `v_pay` nor `v_chg` wraps modulo the group order `l` (a negative-value inflation attack).

- **`CrossBase1` (`128 B`, used in `Merge`, `Withdraw` with change, and `SwapViaRouter` with shielded change):** Proves knowledge of `(v, t, s)` such that `V = v * A + t * H` AND `C = v * G + s * H` commit to the exact same `v`.
- **`CrossBase2` (`256 B`, used in `Transfer`):** On-chain `ix_transfer` sets `A_spend = A_pay` and `V_spend = V_pay + V_chg`. Triptych Eq 5 proves `(A_in - A_pay) in <H>` and `(V_in - (V_pay + V_chg)) in <H>`, while `CrossBase2` proves simultaneously:
  1. `A_chg - A_pay = d * H` (both output notes carry independent, unlinkable re-randomized asset tags derived from ECDH, yet strictly bind to the same hidden mint `G_mint` as the spent input — preventing cross-asset minting);
  2. `V_pay = v_pay * A_pay + t_1 * H` matches Agave Pedersen `C_pay = v_pay * G + s_1 * H`;
  3. `V_chg = v_chg * A_chg + t_2 * H` matches Agave Pedersen `C_chg = v_chg * G + s_2 * H`.
- **Agave native Bulletproofs (`ZkE1Gama1Proof11111111111111111111111111111`):** Zero-rent CPI verifying `BatchedRangeProofU64` (`672 B`, proving `v in [0, 2^64)`) or `BatchedRangeProofU128` (`736 B`, proving `v_1, v_2 in [0, 2^64)`). Since `2^64 + 2^64 << l`, modular wraparound is impossible: `v_in = v_pay + v_chg` holds strictly over the integers.

### Selective Disclosure & Institutional Auditability

- **`PoolMode::Permissionless`:**
  - **Selective Disclosure Receipt:** A user proves `(amount, mint, pageId, slotIndex)` for a single note by disclosing the opening `(v, a, r_v)` verified directly against the on-chain `EpochPage` commitment bytes (`V == v * A + r_v * H`, `A == G_mint + a * H`). Tampering with even 1 base unit fails commitment equality immediately.
  - **Scoped Sub-Account & Full Viewing Keys:** Exporting `(view_sk, S)` grants read-only scanning of incoming notes with zero spend capability (`s` stays private). For stream-scoped disclosure (e.g., an isolated invoice or payroll address without exposing a primary treasury), SDK callers derive an independent child seed via `HKDF-SHA256(salt = "audren/v1/subaccount", ikm = master_seed, info = u32_le(index))` (`index >= 1`; `index == 0` is the primary account).
- **`PoolMode::InstitutionalAudited`:**
  - Every spend verifies Triptych Equations 6–7 (`(S_1, S_2)` encrypting `P_l` under `K_aud`); hidden-asset spends (`Transfer` and `Merge`) additionally verify `AuditorAssetProof` (`192 B`, DLEQ proving `(M_1, M_2) = (r_m * G, G_mint + r_m * K_aud)`), whereas `SwapViaRouter` and `Withdraw` carry their mint(s) as public instruction accounts.
  - The auditor decrypts `P_l = S_2 - k_aud * S_1` (and `G_mint = M_2 - k_aud * M_1` on `Transfer`/`Merge`) offline with zero freeze, pause, or withdrawal power.

---

## 3. Private DEX Swaps (`SwapViaRouter`, Tag 5) & Escape Hatch (`Withdraw`, Tag 6)

`SwapViaRouter` executes full or partial shielded swaps through a compatible Solana router accepting its PDA signer and satisfying custody and transaction limits; hosted route availability is separate:

1. **Nullifier-first ordering & router binding:** `NullifierPDA` is created before the router CPI (eliminating re-entrancy/replay). `router_program`, `mint_in`, `mint_out`, `amount_in`, `min_amount_out`, `escrow_shard`, `flags`, and optional change/refund descriptors are hashed into `ctx_hash`.
2. **Optional shielded change (`flags & 1`, partial swaps):** Users can swap any fraction `amount_in < v_in` of a private note; the remainder `v_chg = v_in - amount_in` is proven via `CrossBase1` (`128 B`) + `BatchedRangeProofU64` (`672 B`) and appended as an encrypted change note in the same transaction.
3. **Custody isolation:** Exact `amount_in` moves from `vault_in` (`vault_auth` PDA) into isolated `escrow_in` owned by `swap_escrow` shard `0..16`. Only `swap_escrow` signs the external CPI; `vault_auth` and `payer` are never marked signer; Audren program/state/vault/page/nullifier accounts are forbidden inside `router_accounts`.
4. **Post-CPI verification:** `swap_escrow` must remain System-owned, zero-data, and non-drained (`lamports_after >= lamports_before`); `escrow_in` and `escrow_out` are verified pre- and post-CPI for immutable owner (`swap_escrow`), zero delegate, and unchanged `close_authority`.
5. **Dynamic stealth settlement:** `actual_out = post_escrow_out - pre_escrow_out > 0` sweeps into `vault_out` (using measured vault delta for Token-2022 `TransferFeeConfig` solvency), checks the measured vault receipt `net_out = post_vault_out - pre_vault_out >= min_amount_out`, commits on-chain as `V_out = net_out * G_{mint_out}`, and appends to `EpochPage` under fresh one-time `P_out`. Unspent escrow input either reverts (`flags & 2 == 0`) or sweeps back into a stealth refund note (`flags & 2 != 0`, `allow_partial`).

### Privacy boundaries and effective anonymity

**Public entry and exit by design:** A deposit exposes its funding account, mint, amount and new note location. A withdrawal exposes its destination, mint and amount. External DEX execution exposes trade details and resulting note locations. Deposit and dynamic swap output/refund asset and value commitments are unblinded. Swap and withdrawal change amounts can be blinded while their asset is public. These are expected boundaries for ordinary Solana asset movements, not evidence of a failed proof.

**What a ring conceals:** The proof does not disclose which candidate note is spent. Ring capacity (32/64/128 slots) does not establish that many equally plausible inputs or independent users. Public populated prefixes can be smaller; empty slots provide no anonymity. A valid proof with only one plausible input does not hide that input from inference. Candidate selection, adversary-owned notes, known public values, timing and repeated observations can reduce effective anonymity. TVL is not a measurement of those properties.

**Relayers and observers:** Anyone can operate a compatible relayer. Relayers hold no user spending keys and can pay fees instead of the user; direct submission remains possible and exposes its fee payer. Relayers, RPC providers and web hosts can observe requests and network metadata. User-controlled relayer choice is distinct from anonymity against an observing operator. Clients must assess discovery requests, candidate selection and submission patterns together. Neither a ring-size setting nor relayer use certifies practical anonymity.

**Assurance:** These mechanisms require correct cryptography, implementation and client behavior. Independent cryptographic review and empirical tracing-resistance measurements are not established by successful lifecycle transactions. Public vault balances disclose assets, not a complete independently verified private-liability total.

**Shared custody and privacy boundaries:** Original assets sit in the SOL vault or per-mint token accounts controlled by `vault_auth`. Private Transfer proofs conceal the spent record and blind output asset/value commitments; recipient keys are one-time. Fee payers, candidate pages and transaction metadata remain public. External DEX execution and withdrawals expose tokens and amounts; withdrawals expose their destinations. Timing and other observations can create links. Privacy depends on plausible candidates, not TVL alone. Public holdings do not alone prove coverage of private liabilities.

**Pool pause and withdrawal:** Full-note withdrawals (`has_change == false`) keep `PoolState` read-only and bypass its pause check. Partial withdrawals remain pause-gated. All withdrawals still require valid proofs, available assets, fees, network operation and applicable token permissions. The deployment is pre-audit and upgradeable; upgrades can change these rules.

---

## 4. Token-2022 Solvency & Solana v1 / `ProofBuffer`

- **Token-2022 support:**
  - `TransferFeeConfig`: `Deposit` and `SwapViaRouter` commit the measured post-transfer vault balance delta (`after - before > 0`), crediting the measured net receipt rather than the requested gross amount.
  - `PermanentDelegate`: Regulated stablecoins and RWAs (PYUSD, USDG, CASH) are supported natively alongside Classic SPL mints.
  - `TransferHook`: Inactive hooks take a zero-allocation fast path; active hooks receive sanitized non-signer trailing hook accounts with Audren-owned accounts and custody vaults filtered out.
  - Audren does not impose a blanket mint-extension denylist. Transfers still depend on token-program checks and issuer policies; `NonTransferable` mints cannot be transferred.
- **Solana Transaction Version 1 (`0x81`, `4,096 B`) + `ProofBuffer` (`Tags 8 / 9 / 10`):**
  - Relayers and native SDK clients can settle supported payloads for `Deposit`, `Transfer`, `Merge`, `SwapViaRouter`, and `Withdraw` in **one Solana v1 transaction**, subject to client support and transaction limits (`<= 4,096 B`, inline `TransactionConfig` compute budget and priority fee, zero `ComputeBudgetInstruction`).
  - Browser wallets restricted to `v0` (`1,232 B`) or oversized multi-hop swaps upload `<= 768 B` chunks via `WriteProofBuffer` (`Tag 8`) tracked by a `u16` `written_mask`, execute zero-copy via `ExecBuffered` (`Tag 9`), and atomically zero magic, shrink to `0 B`, reassign to the System Program, and refund 100% of buffer rent to `payer` in the same transaction. `CloseProofBuffer` (`Tag 10`) recovers 100% of rent from abandoned uploads.
