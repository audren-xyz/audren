# apps/relay — agent rules

Read the root [`AGENTS.md`](../../AGENTS.md) first. On-chain wire layouts and instruction tags are owned by `crates/audren-core/` and `program/`.

## Architectural boundaries

- **Standalone, relayer-agnostic service:** `apps/relay` runs as an independent Cloudflare Worker decoupled from `apps/web`. Any web client, mobile wallet, or backend SDK can target a hosted instance or self-host via `wrangler.jsonc` implementing `/v1/info`, `/v1/fee-quote`, `/v1/swap/quote`, `/v1/swap/instructions`, `/v1/checkpoint`, and `/v1/relay/submit`.
- **Zero-trust Audren v1 instruction firewall (`src/policy/firewall.ts`):**
  - Permit **only** Audren `Tag 5` (`Transact` — private transfer or public SPL/Token-2022/WSOL-unwrap withdraw, plus 1..=4 batched parallel `2 -> 1` private `Transact` merges) and `Tag 6` (`ExecViaEscrow` — SPL/Token-2022 atomic DeFi CPI with optional `EXEC_FLAG_FEE_ON_OUTPUT`) targeting `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3` on Pool #0 (`audren_pool`), enforcing `vk_id === 0` and canonical ATAs, plus strictly allowlisted zero-signer `preInstructions` immediately preceding single `Tag 6`.
  - Explicitly reject `Tag 3` (`Deposit`) — deposits are public and signed directly by the depositor's wallet.
  - Require `accounts[0]` to match a configured relayer fee-payer keypair (`isSigner: true, isWritable: true`) and **zero** other signers across all accounts. Rotates advertised fee-payer pubkeys uniformly across configured `*_RELAYER_SECRETS_JSON` pools for zero contention across parallel append lanes.
- **Three-mode dynamic relayer fee verification (`src/policy/firewall.ts`, `src/policy/pricing.ts`):**
  - Default `omitNf1 = false` (2 nullifiers) across ALL ops (`transfer`, `withdraw`, `exec_escrow`) and uniformly random default `shardId` (`0..15`) whenever omitted.
  - Mode 1 (`ASSET_MODE_PRIVATE` transfer, single or 1..=4 merge batch): shielded `cm2` fee note(s) (`106 B` versioned memos) verified cryptographically via the hot Worker's read-only `FullViewingKey` (`*_RELAYER_FVK_JSON`, zero spend authority on hot infrastructure).
  - Mode 2 (`Transact` `ASSET_MODE_PUBLIC` Withdraw): `WITHDRAW_FLAG_UNWRAP_WSOL` lamports directly to `relayerPubkey`, or SPL/Token-2022 to the canonical relayer ATA.
  - Mode 3 (`ExecViaEscrow`): SPL/Token-2022 input-leg fee or `EXEC_FLAG_FEE_ON_OUTPUT` output-leg fee verified via pre-flight `simulateV1Transaction`.
- **Atomic persistent anti-abuse (`src/policy/guard-do.ts`):**
  - SQLite Durable Object `RelayGuard` generates and persists an ephemeral per-day random 32-byte secret IP-hash salt strictly inside DO storage (rotated & purged daily at UTC midnight, never derived from any public key), stores ZERO `ip_hash` on `inflight_nullifiers`, and enforces global daily sponsored SOL caps, per-IP limits, cooldowns, failed-attempt caps, and atomic in-flight nullifier deduplication.
- **Standardized aggregator adapters (`src/aggregators/`):**
  - Keep `JUPITER_CPI_EXCLUDED_DEXES` in `src/aggregators/jupiter.ts` synced with `crates/client/src/router.rs`, `packages/sdk/src/swap.ts`, and `apps/web/worker/index.ts`.
- **Self-sustaining cron refill & maintenance crank (`src/cron/refill.ts`):**
  - Auto-refills SOL from accumulated fee tokens and runs permissionless `PublishCheckpoint` (`Tag 4`) + `LaneRentVault`-subsidized `OpenPage` (`Tag 2`, `96` notes/memo page, `subroot_slot >= 280` lookahead) cranks.
- **Credentials & deployment hygiene:**
  - Read RPC URLs, relayer fee-payer secrets, read-only FVKs, and aggregator keys exclusively from Wrangler secrets or gitignored `.dev.vars`.
  - Keep `wrangler.jsonc` 100% open-source and self-hostable (`wrangler.prod.jsonc` is gitignored).

## Verification

```bash
pnpm typecheck && pnpm test
```
