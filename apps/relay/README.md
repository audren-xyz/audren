# `audren-relay`

Standalone, open-source, router-agnostic Cloudflare Worker Privacy Relayer for the **Audren** shielded protocol (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`).

`audren-relay` allows Audren users and integrators to submit private transfers (including up to 4 parallel `2 -> 1` private merge batches), withdrawals, atomic WSOL unwraps, and protocol-agnostic DeFi swaps in **one Solana Transaction Version 1 (`0x81`, `4,096 B`)** without their public wallet ever signing or appearing as a fee payer on-chain. The protocol is completely relayer-agnostic: anyone can deploy their own instance in under 5 minutes (see [`../../docs/DEPLOY_YOUR_OWN_RELAY.md`](../../docs/DEPLOY_YOUR_OWN_RELAY.md)) and point the Audren Web UI ("Use Your Own Relay") or `@audren/sdk` at it.

## Privacy boundary

Anyone can operate a compatible relay; users can choose a provider or submit directly. A relay supplies the network fee payer without receiving user spending keys. Public deposits, withdrawals, and external DeFi details remain observable by design. Relaying separates the user wallet from the fee-payer field; it does not guarantee that other evidence cannot link activity.

The service sees connection metadata and public instruction/quote parameters. `src/policy/guard-do.ts` generates a random 32-byte secret salt rotated and purged daily inside `RelayGuard` Durable Object storage (never derived from any public key or environment variable) and hashes client IPs strictly inside the Durable Object. `inflight_nullifiers` stores only `(nullifier, expires_at)` with zero IP-hash linkage. Its `prune` method removes expired entries during guard operations (`DAY_MS`, `HOUR_MS`, `INFLIGHT_TTL_MS`). Hashing is not anonymization, and infrastructure logs are a separate operator responsibility.

## How it fits together

```text
  Client (Web UI, @audren/sdk, Rust / Swift / Kotlin SDKs, custom wallet)
    │  1. Generates 192 B BN254 Groth16 proof locally (spending & viewing keys never leave client)
    │  2. POST /v1/swap/quote & /v1/swap/instructions (for Tag 6 ExecViaEscrow swaps; random shardId 0..15)
    │  3. POST /v1/relay/submit (unsigned Audren Tag 5 / 1..=4 private Tag 5 batch / Tag 6 wire payload)
    ▼
  audren-relay (Cloudflare Worker + SQLite Durable Object `RelayGuard`)
    │  • Firewall: allows ONLY Audren Tag 5 (`Transact`, vk_id=0) & Tag 6 (`ExecViaEscrow`, vk_id=0), canonical ATAs, accounts[0] == relayer, 0 extra signers
    │  • Live RPC pricing: fetches mint decimals/program & live rent schedule (`MemoPage` 10,240 B / 96 notes) via Solana RPC
    │  • Pre-flight simulation: verifies exact lamport outflow, Mode 1 shielded cm2 fee(s) (via read-only FVK), or Mode 2/3 fee inflow
    │  • Atomic RelayGuard reservation: ephemeral daily-salted IP rate limits, daily SOL budget & IP-unlinked nullifier locks
    │  • Signs & broadcasts single Solana Transaction v1 (`0x81`, <= 4,096 B, with deduplicated `OpenPage` / validated `setupAtas` / allowlisted `preInstructions`)
    ▼
  Solana Mainnet & Devnet RPC
```

## Layout

```text
src/index.ts                  HTTP router, relayer rotation, Solana v1 tx assembly (single + 1..=4 batch), simulation accounting, broadcast
src/env.ts                    Environment & Wrangler var parser (`RelayPolicyConfig`, multi-payer & FVK config)
src/types.ts                  Wire & internal request/response types
src/policy/firewall.ts        Zero-trust Audren v1 Tag 5 / Tag 6 / batch & allowlisted preInstruction firewall
src/policy/pricing.ts         Dynamic SwapFeePlan & native fee-quote calculation from live rent (default omitNf1=false)
src/policy/guard-do.ts        SQLite Durable Object (`RelayGuard`) ephemeral daily IP salt, IP-unlinked nullifier locks & budget ledger
src/solana/codec.ts           Base58, ATA builder, Solana Transaction v1 (`0x81`) serializer
src/solana/audren.ts          Audren v1 PoolState / LaneTreeState / Page decoders, canonical ATA checks & batch rollover helpers (via `@audren/sdk`)
src/solana/checkpoint.ts      Permissionless on-demand `PublishCheckpoint` (`Tag 4`) evaluator & publisher
src/solana/rpc.ts             Solana JSON-RPC client (`fetchMintMetasWithData`, `fetchLiveRentSchedule`, Token-2022 fee deduction, `simulateV1Transaction`)
src/aggregators/              Pluggable DEX adapters: `jupiter.ts`, `bedrock.ts`, `dflow.ts`, `titan.ts`, `okx.ts`, `registry.ts`
src/cron/refill.ts            `*/2 * * * *` scheduled treasury refill & permissionless `PublishCheckpoint`/`OpenPage` crank
scripts/bootstrap-relayer.ts  Idempotent keypair creation, funding & common ATA pre-opening
scripts/e2e-relay.ts          Live empirical E2E suite (health, info, multi-aggregator quotes, firewall rejections)
wrangler.jsonc                Self-hostable open-source Cloudflare Worker configuration
.dev.vars.example             Template for local development & Wrangler secrets
```

## HTTP endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Service liveness check |
| `GET` | `/v1/info?cluster=mainnet\|devnet` | Rotated relayer pubkey + full `relayerPubkeys`, live SOL balance, live on-chain rent schedule, optional shielded fee address (`FullViewingKey`), active aggregators, and policy limits |
| `GET` | `/v1/aggregators` | Configured DEX aggregators and per-adapter capabilities |
| `GET` | `/v1/stats` | Daily aggregate relay counts and remaining sponsor budget (zero PII) |
| `GET` | `/v1/fee-quote` | Dynamic `relayer_fee` quote (default `omitNf1=false` across all ops, random `shardId` for `exec_escrow`): flat per-mint shielded `cm2` fee for `transfer` (`amount` omitted/ignored) and self-paying quotes for `withdraw` (`WITHDRAW_FLAG_UNWRAP_WSOL`) & `ExecViaEscrow` (`EXEC_FLAG_FEE_ON_OUTPUT`) |
| `GET` / `POST` | `/v1/swap/quote` | Multi-aggregator swap quote (`jupiter`, `bedrock`, `dflow`, `titan`, `okx`, or `auto` parallel race; random `shardId` when omitted) with Token-2022 `TransferFeeConfig` net input deduction + dynamic `SwapFeePlan` |
| `POST` | `/v1/swap/instructions` | Normalized `swapInstruction`, `missingAtas`, `lookupTables`, and fee-account wiring for `ExecViaEscrow` |
| `POST` | `/v1/checkpoint` | Permissionless on-demand `PublishCheckpoint` (`Tag 4`) signed by the relayer when uncheckpointed leaves exist and cooldown has elapsed (`up_to_date` / `cooldown` / `published`) |
| `POST` | `/v1/relay/submit` | Firewall (single Tag 5 / 1..=4 private Tag 5 batch / Tag 6 + allowlisted zero-signer `preInstructions`) -> deduplicated `OpenPage` prepending -> `simulateV1Transaction` -> atomic `RelayGuard` reserve -> Solana Transaction v1 (`0x81`, `<= 4,096 B`) sign, send & confirm |
| `POST` | `/v1/admin/refill` | Manual treasury auto-refill & maintenance crank trigger (authenticated via constant-time `x-admin-token`) |

## Pluggable aggregators & 3-mode fee economics

- **Standardized multi-aggregator routing:** Every DEX adapter (`jupiter`, `bedrock`, `dflow`, `titan`, `okx`) uses the same credential convention (`<PROVIDER>_API_KEY` and optional `<PROVIDER>_API_URL`). Select `provider` per request or pass `auto` to race all configured adapters in parallel for the highest `outAmount`.
- **Mode 1 — Shielded private transfer & merge batch fee (`Tag 5`, `ASSET_MODE_PRIVATE`):** When `MAINNET_RELAYER_FVK_JSON` / `DEVNET_RELAYER_FVK_JSON` is configured, the hot Worker decrypts `106 B` output memo `cm2` (across single or 1..=4 batched `2 -> 1` merge instructions) using its read-only `FullViewingKey` (zero spend key on the Worker) and verifies `cm2 == Poseidon5(owner, asset_id, fee_amount, blinding)` before relaying.
- **Mode 2 — Public withdraw & atomic WSOL unwrap (`Tag 5`, `ASSET_MODE_PUBLIC`):** Reimburses the relayer via `relayer_fee` (quoted by `/v1/fee-quote`, covering 100% of live gas, rent, and any ATA creation) or atomic `WITHDRAW_FLAG_UNWRAP_WSOL` when funding a 0-SOL wallet or DeFi session keypair.
- **Mode 3 — Self-paying DeFi swaps (`Tag 6`, `ExecViaEscrow`):** SPL/Token-2022 only; supports both input-asset and output-asset (`EXEC_FLAG_FEE_ON_OUTPUT`) relayer fees deducted atomically from swap proceeds after CPI.
- **Self-refill & maintenance cron (`*/2 * * * *`):** Refills native SOL from accumulated fee tokens when below `REFILL_MIN_SOL` and executes permissionless `PublishCheckpoint` (`Tag 4`) + `LaneRentVault`-subsidized `OpenPage` (`Tag 2`) lookahead cranks.

## Secrets & deployment

See [`../../docs/DEPLOY_YOUR_OWN_RELAY.md`](../../docs/DEPLOY_YOUR_OWN_RELAY.md) for the full self-hosting walkthrough.

**Wrangler secrets (`npx wrangler secret put <NAME>`):**
- Required (Mainnet): `MAINNET_RPC_URL`, `MAINNET_RELAYER_SECRET_B64` (32-byte or 64-byte base64 Ed25519 key).
- Optional (Devnet): `DEVNET_RPC_URL`, `DEVNET_RELAYER_SECRET_B64`.
- Optional multi-payer pool & Mode 1 read-only FVK: `MAINNET_RELAYER_SECRETS_JSON`, `DEVNET_RELAYER_SECRETS_JSON`, `MAINNET_RELAYER_FVK_JSON`, `DEVNET_RELAYER_FVK_JSON`.
- DEX aggregators (configure any subset you want active): `JUPITER_API_KEY` (+ optional `JUPITER_API_URL`), `BEDROCK_API_URL` / `BEDROCK_API_KEY`, `DFLOW_API_URL` / `DFLOW_API_KEY`, `TITAN_API_URL` / `TITAN_API_KEY`, `OKX_API_URL` / `OKX_API_KEY` / `OKX_SECRET_KEY` / `OKX_PASSPHRASE`.
- Optional admin token: `RELAY_ADMIN_TOKEN`.

**Commands:**

```bash
pnpm install
pnpm typecheck                        # TypeScript strict check
pnpm test                             # Unit + firewall + RelayGuard + Mode 1/2/3 + batch tests
pnpm dev                              # Local Worker + SQLite DO at http://localhost:8788 (reads .dev.vars)
pnpm deploy                           # Deploy open-source wrangler.jsonc to your Cloudflare account
pnpm deploy:prod                      # Deploy operator gitignored wrangler.prod.jsonc (custom domain / account_id)
```

## Empirical end-to-end testing

```bash
RELAY_BASE="https://relay.audren.xyz" pnpm e2e
```
