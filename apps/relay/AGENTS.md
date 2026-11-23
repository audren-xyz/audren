# apps/relay — agent rules

Read the root [`AGENTS.md`](../../AGENTS.md) first. On-chain wire layouts and instruction tags are owned by `crates/audren-core/` and `program/`.

## Architectural boundaries

- **Standalone, relayer-agnostic service:** `apps/relay` runs as an independent Cloudflare Worker decoupled from `apps/web`. Any web client, mobile wallet, or backend SDK can target a hosted instance or self-host via `wrangler.jsonc` implementing `/v1/info`, `/v1/fee-quote`, `/v1/swap/quote`, `/v1/swap/instructions`, `/v1/checkpoint`, and `/v1/relay/submit`.
- **Zero-trust Audren instruction firewall (`src/policy/firewall.ts`):**
  - Permit **only** Audren `Tag 6` (`JoinSplit` — private transfer or public SOL/SPL/WSOL-unwrap withdraw) and `Tag 7` (`ExecViaEscrow` — atomic DeFi CPI with optional `EXEC_FLAG_FEE_ON_OUTPUT`) targeting `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3` on Pool #0 (`audren_v2_pool`), plus strictly allowlisted zero-signer `preInstructions` immediately preceding `Tag 7`.
  - Explicitly reject `Tag 3` (`DepositSol`) and `Tag 4` (`DepositSpl`) — deposits are public and signed directly by the depositor's wallet.
  - Require `accounts[0]` to match a configured relayer fee-payer keypair (`isSigner: true, isWritable: true`) and **zero** other signers across all accounts. Supports rotating fee-payer pools (`*_RELAYER_SECRETS_JSON`) for zero contention across parallel append lanes.
- **Three-mode dynamic relayer fee verification (`src/policy/firewall.ts`, `src/policy/pricing.ts`):**
  - Mode 1 (`ASSET_MODE_PRIVATE` transfer): optional shielded `cm2` fee note verified cryptographically via the hot Worker's read-only `FullViewingKey` (`*_RELAYER_FVK_JSON`, zero spend authority on hot infrastructure).
  - Mode 2 (`JoinSplit` Withdraw): Native SOL / `WITHDRAW_FLAG_UNWRAP_WSOL` lamports directly to `relayerPubkey`, or SPL/Token-2022 to the relayer ATA.
  - Mode 3 (`ExecViaEscrow`): input-leg fee or `EXEC_FLAG_FEE_ON_OUTPUT` output-leg fee verified via pre-flight `simulateV1Transaction`.
- **Atomic persistent anti-abuse (`src/policy/guard-do.ts`):**
  - SQLite Durable Object `RelayGuard` prevents concurrent burst bypasses across global daily sponsored SOL caps, per-IP limits, cooldowns, failed-attempt caps, and in-flight nullifier deduplication.
- **Standardized aggregator adapters (`src/aggregators/`):**
  - Keep `JUPITER_CPI_EXCLUDED_DEXES` in `src/aggregators/jupiter.ts` synced with `crates/client/src/router.rs`, `packages/sdk/src/swap.ts`, and `apps/web/worker/index.ts`.
- **Self-sustaining cron refill & maintenance crank (`src/cron/refill.ts`):**
  - Auto-refills SOL from accumulated fee tokens and runs permissionless `PublishCheckpoint` + `LaneRentVault`-subsidized `OpenPage` cranks.
- **Credentials & deployment hygiene:**
  - Read RPC URLs, relayer fee-payer secrets, read-only FVKs, and aggregator keys exclusively from Wrangler secrets or gitignored `.dev.vars`.
  - Keep `wrangler.jsonc` 100% open-source and self-hostable (`wrangler.prod.jsonc` is gitignored).

## Verification

```bash
pnpm typecheck && pnpm test
```
