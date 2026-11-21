# apps/relay — agent rules

Read the root [`AGENTS.md`](../../AGENTS.md) first. On-chain wire layouts and instruction tags are owned by `crates/audren-core/` and `program/`.

## Architectural boundaries

- **Standalone, relayer-agnostic service:** `apps/relay` runs as an independent Cloudflare Worker decoupled from `apps/web`. Any web client, mobile wallet, or backend SDK can target a hosted instance or self-host via `wrangler.jsonc` implementing `/v1/info`, `/v1/swap/quote`, `/v1/swap/instructions`, and `/v1/relay/submit`.
- **Zero-trust Audren instruction firewall (`src/policy/firewall.ts`):**
  - Permit **only** Audren `Tag 3` (`Transfer`), `Tag 4` (`Merge`), `Tag 5` (`SwapViaRouter`), and `Tag 6` (`Withdraw`) targeting `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`.
  - Explicitly reject `Tag 2` (`Deposit` — deposits are public and signed by the depositor's wallet).
  - Require `accounts[0] === relayerPubkey` (`isSigner: true, isWritable: true`) and **zero** other signers across all accounts.
  - Validate every numeric parameter (`computeUnitLimit`, `priorityFeeLamports`) strictly (`Number.isFinite` / non-negative integer) and reject malformed pubkeys before touching RPC.
- **100% dynamic on-chain accounting (zero hardcoding):**
  - Resolve mint decimals, token program (Classic SPL vs Token-2022), and valid mint status dynamically from RPC (`fetchMintMetas` in `src/solana/rpc.ts`, chunked at 100 accounts per RPC batch).
  - Derive nullifier rent, page rent share, ATA rent, and swap baseline costs dynamically from live `getMinimumBalanceForRentExemption` (`fetchLiveRentSchedule`).
  - Run `simulateV1Transaction` before every spend to measure exact lamport outflow and exact fee-token inflow directly from Solana's runtime; reject forged proofs or unprofitable swaps at zero lamports spent.
- **Atomic persistent anti-abuse (`src/policy/guard-do.ts`):**
  - SQLite Durable Object `RelayGuard` uses an atomic `pending_reservations` table to prevent concurrent burst bypasses across global daily sponsored SOL caps, per-IP hourly/daily windows, per-IP sponsored cooldowns, failed-attempt caps, and in-flight nullifier deduplication.
  - Admin endpoints (`/v1/admin/refill`) verify `x-admin-token` via constant-time SHA-256 comparison.
- **Standardized aggregator adapters (`src/aggregators/`):**
  - Every DEX aggregator (`jupiter`, `bedrock`, `dflow`, `titan`, `okx`) uses explicit API credentials (`<PROVIDER>_API_KEY` / `<PROVIDER>_API_URL`) and checks `isConfigured(env)` uniformly — never fall back to unauthenticated public swap endpoints.
  - `SwapViaRouter` executes aggregator swaps via PDA `invoke_signed` from `AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`. Keep `JUPITER_CPI_EXCLUDED_DEXES` in `src/aggregators/jupiter.ts` synced with `crates/client/src/router.rs`, `packages/sdk/src/swap.ts`, and `apps/web/worker/index.ts`, and keep `programAuthority=true` in `src/aggregators/bedrock.ts`.
- **Self-sustaining cron refill (`src/cron/refill.ts`):**
  - Discover accumulated fee tokens dynamically via `getTokenAccountsByOwner` across both Classic SPL and Token-2022 programs.
  - Always simulate (`simulateV1Transaction`) before broadcasting any unwrap or refill swap.
- **Credentials & deployment hygiene:**
  - Read RPC URLs (`MAINNET_RPC_URL`, `DEVNET_RPC_URL`), relayer keys (`MAINNET_RELAYER_SECRET_B64`, `DEVNET_RELAYER_SECRET_B64`), and aggregator keys exclusively from Wrangler secrets or local `.dev.vars` (gitignored).
  - Keep `wrangler.jsonc` 100% open-source and self-hostable (no `account_id`, no private custom domains). Operator production overrides live in gitignored `wrangler.prod.jsonc` (`pnpm deploy:prod`).

## Verification

```bash
pnpm typecheck
```
