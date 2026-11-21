# `audren-relay`

Standalone, open-source, router-agnostic Cloudflare Worker Privacy Relayer for the **Audren** shielded protocol (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`).

`audren-relay` allows Audren users and integrators to submit private transfers, merges, DEX swaps, and withdrawals in **one Solana Transaction Version 1 (`0x81`, `4,096 B`)** without their public wallet ever signing or appearing as a fee payer on-chain. The protocol is completely relayer-agnostic: anyone can deploy their own instance in under 5 minutes (see [`../../docs/DEPLOY_YOUR_OWN_RELAY.md`](../../docs/DEPLOY_YOUR_OWN_RELAY.md)) and point the Audren Web UI ("Use Your Own Relay") or `@audren/sdk` at it.

## Privacy boundary

Anyone can operate a compatible relay; users can choose a provider or submit directly. A relay supplies the network fee payer without receiving user spending keys. Public deposits, withdrawals and external DEX details remain observable by design. Relaying separates the user wallet from the fee-payer field; it does not guarantee that other evidence cannot link activity.

The service sees connection metadata and public instruction/quote parameters. `src/index.ts` derives IP hashes using the public relay key as salt. `src/policy/guard-do.ts` stores those identifiers with operation times, sponsorship records and temporary in-flight nullifier associations. Its `prune` method removes expired entries during guard operations (`DAY_MS`, `HOUR_MS`, `INFLIGHT_TTL_MS`). Hashing is not anonymization, and infrastructure logs are a separate operator responsibility.

## How it fits together

```text
  Client (Web UI, @audren/sdk, Rust / Swift / Kotlin SDKs, custom wallet)
    │  1. Proves Triptych + Bulletproof locally (spending and viewing keys never leave client)
    │  2. POST /v1/swap/quote & /v1/swap/instructions (for Tag 5 swaps)
    │  3. POST /v1/relay/submit (unsigned Audren instruction bytes + account metas)
    ▼
  audren-relay (Cloudflare Worker + SQLite Durable Object `RelayGuard`)
    │  • Firewall: allows ONLY Audren Tag 3/4/5/6, accounts[0] == relayer, 0 extra signers
    │  • Live RPC pricing: fetches mint decimals/program & live rent schedule via Solana RPC
    │  • Pre-flight simulation: measures exact lamport outflow & exact fee token inflow
    │  • Atomic RelayGuard reservation: enforces daily SOL budget, per-IP caps & nullifier lock
    │  • Signs & broadcasts single Solana v1 (0x81) tx (auto-prepending OpenPage/OpenLanePage if needed)
    ▼
  Solana Mainnet & Devnet RPC
```

## Layout

```text
src/index.ts                  HTTP router, Solana v1 tx assembly, simulation accounting, broadcast
src/env.ts                    Environment & Wrangler var parser (`RelayPolicyConfig`)
src/types.ts                  Wire & internal request/response types
src/policy/firewall.ts        Zero-trust Audren instruction & account-meta firewall
src/policy/pricing.ts         Dynamic SwapFeePlan calculation from live rent & quote outputs
src/policy/guard-do.ts        SQLite Durable Object (`RelayGuard`) atomic rate-limit & budget ledger
src/solana/codec.ts           Base58, PDA derivation, ATA builder, Solana v1 (0x81) serializer
src/solana/audren.ts          Audren PoolState / EpochPage / AppendLaneState decoders & rollover builders
src/solana/rpc.ts             Solana JSON-RPC client (`fetchMintMetas`, `fetchLiveRentSchedule`, `simulateV1Transaction`)
src/aggregators/              Pluggable DEX adapters: `jupiter.ts`, `bedrock.ts`, `dflow.ts`, `titan.ts`, `okx.ts`, `registry.ts`
src/cron/refill.ts            `*/15 * * * *` scheduled treasury refill (dynamic SPL/Token-2022 discovery -> WSOL unwrap / swap to SOL)
scripts/bootstrap-relayer.ts  Idempotent keypair creation, funding & common ATA pre-opening
scripts/e2e-relay.ts          Live Mainnet empirical E2E suite (firewall, multi-aggregator, live Tag 3/5/6 txs)
wrangler.jsonc                Self-hostable open-source Cloudflare Worker configuration
.dev.vars.example             Template for local development & Wrangler secrets
```

## HTTP endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Service liveness check |
| `GET` | `/v1/info?cluster=mainnet\|devnet` | Relayer pubkey, live SOL balance, live on-chain rent schedule, active aggregators, and policy limits |
| `GET` | `/v1/aggregators` | Configured DEX aggregators and per-adapter capabilities |
| `GET` | `/v1/stats` | Daily aggregate relay counts and remaining sponsor budget (zero PII) |
| `GET` | `/v1/fee-quote` | Dynamic native `relayer_fee` quote for self-paying `ExecViaEscrow` (`Tag 5`) & `Withdraw` (`Tag 6`, incl. `unwrap_wsol`) |
| `GET` / `POST` | `/v1/swap/quote` | Multi-aggregator swap quote (`jupiter`, `bedrock`, `dflow`, `titan`, `okx`, or `auto` parallel race) + dynamic `SwapFeePlan` |
| `POST` | `/v1/swap/instructions` | Normalized `swapInstruction`, `missingAtas`, `lookupTables`, and fee-account wiring for `ExecViaEscrow` |
| `POST` | `/v1/relay/submit` | Firewall (incl. allowlisted zero-signer `preInstructions` before Tag 5) -> `simulateV1Transaction` -> atomic `RelayGuard` reserve -> Solana `v1 (0x81)` sign, send & confirm |
| `POST` | `/v1/admin/refill` | Manual treasury auto-refill trigger (authenticated via constant-time `x-admin-token`) |

## Pluggable aggregators & fee economics

- **Standardized multi-aggregator routing:** Every DEX adapter (`jupiter`, `bedrock`, `dflow`, `titan`, `okx`) uses the same credential convention (`<PROVIDER>_API_KEY` and optional `<PROVIDER>_API_URL`). Select `provider` per request or pass `auto` to race all configured adapters in parallel for the highest `outAmount`.
- **Self-paying swaps (`Tag 5`, full or partial with `flags & 1` shielded change):** `src/policy/pricing.ts` calculates the required platform fee bps dynamically from live on-chain rent (`nullifierRent + pageRentPerNote + baseTxFeeLamports + priorityFee`, plus `ataRent` when creating a new fee ATA) times `SELF_PAY_MARGIN_BPS` (default `1.10x`), floored at `BASE_SWAP_FEE_BPS` (`25 bps`) and capped at `MAX_SELF_PAY_BPS` (`450 bps`).
- **Sponsored operations (`Tag 3 / 4 / 6`):** Transfers, merges, and withdrawals are metered against `RelayGuard`'s global daily SOL cap, per-IP sliding-window hourly/daily limits, per-IP cooldown, and atomic in-flight nullifier lock.
- **Self-refill cron (`*/15 * * * *`):** When native SOL drops below `REFILL_MIN_SOL`, `src/cron/refill.ts` scans all Classic SPL and Token-2022 accounts owned by the relayer, unwraps WSOL, and swaps accumulated fee tokens into native SOL after verifying each transaction via `simulateV1Transaction`.

## Secrets & deployment

See [`../../docs/DEPLOY_YOUR_OWN_RELAY.md`](../../docs/DEPLOY_YOUR_OWN_RELAY.md) for the full self-hosting walkthrough.

**Wrangler secrets (`npx wrangler secret put <NAME>`):**
- Required (Mainnet): `MAINNET_RPC_URL`, `MAINNET_RELAYER_SECRET_B64` (32-byte or 64-byte base64 Ed25519 key).
- Optional (Devnet): `DEVNET_RPC_URL`, `DEVNET_RELAYER_SECRET_B64`.
- DEX aggregators (configure any subset you want active): `JUPITER_API_KEY` (+ optional `JUPITER_API_URL`), `BEDROCK_API_URL` / `BEDROCK_API_KEY`, `DFLOW_API_URL` / `DFLOW_API_KEY`, `TITAN_API_URL` / `TITAN_API_KEY`, `OKX_API_URL` / `OKX_API_KEY` / `OKX_SECRET_KEY` / `OKX_PASSPHRASE`.
- Optional admin token: `RELAY_ADMIN_TOKEN`.

**Commands:**

```bash
pnpm install
pnpm typecheck                        # TypeScript strict check
pnpm dev                              # Local Worker + SQLite DO at http://localhost:8788 (reads .dev.vars)
pnpm deploy                           # Deploy open-source wrangler.jsonc to your Cloudflare account
pnpm deploy:prod                      # Deploy operator gitignored wrangler.prod.jsonc (custom domain / account_id)
```

## Empirical end-to-end testing

```bash
MAINNET_RPC_URL="https://your-mainnet-rpc/" \
AUDREN_KEYPAIR_PATH="../../.credentials/funder.json" \
RELAY_BASE="https://your-relay.workers.dev" \
pnpm e2e
```
