# Deploy Your Own Audren Privacy Relayer

Audren is **100% relayer-agnostic**. Anyone can run an independent relayer in under 5 minutes on Cloudflare Workers (free or paid plan) with zero shared credentials, zero trust in `relay.audren.xyz`, and full support for private transfers, merges, DEX swaps (Jupiter, Bedrock, DFlow, Titan, OKX), and withdrawals.

A relayer **never** receives user spending keys or viewing keys — it only pays Solana transaction fees & nullifier/page rent, signs as `accounts[0]`, and optionally earns configurable fees via native `relayer_fee` on `ExecViaEscrow` (`Tag 5`) & `Withdraw` (`Tag 6`) or DEX aggregator platform fees.

---

## Prerequisites

- [Node.js 22+](https://nodejs.org/) & `pnpm` (`corepack enable`)
- [Cloudflare account](https://dash.cloudflare.com/) + `wrangler` (installed via `pnpm install`)
- A dedicated **Solana RPC endpoint** (QuickNode, Helius, Triton, or your own validator — avoid throttled public endpoints)
- A fresh **Solana Ed25519 keypair** funded with ~0.1–0.2 SOL for gas & rent (never reuse your personal wallet!)

---

## Step 1 — Generate & Fund Your Relayer Keypair

Create a dedicated keypair inside `.credentials/` (gitignored by default):

```bash
mkdir -p .credentials && chmod 700 .credentials
solana-keygen new --no-bip39-passphrase -o .credentials/my-relayer-mainnet.json
chmod 600 .credentials/my-relayer-mainnet.json

# Print your relayer's public address (fund this with ~0.10 - 0.25 SOL):
solana-keygen pubkey .credentials/my-relayer-mainnet.json
```

Alternatively, use the idempotent bootstrap script to create keypairs, fund from an existing funder wallet, and pre-open WSOL + USDC fee ATAs:

```bash
cd apps/relay
pnpm install
MAINNET_RPC_URL="https://your-solana-mainnet-rpc/" \
AUDREN_KEYPAIR_PATH="/path/to/your-funder.json" \
npx tsx scripts/bootstrap-relayer.ts
```

Convert the first 32 bytes (Ed25519 seed) to base64 (never commit or paste into logs):

```bash
node -e "const k=JSON.parse(require('fs').readFileSync('.credentials/my-relayer-mainnet.json','utf8')); console.log(Buffer.from(k.slice(0,32)).toString('base64'))"
```

---

## Step 2 — Configure Wrangler Secrets

```bash
cd apps/relay
pnpm install
npx wrangler login

# Required for Mainnet relaying:
npx wrangler secret put MAINNET_RPC_URL
npx wrangler secret put MAINNET_RELAYER_SECRET_B64

# Optional — enable Devnet relaying too:
npx wrangler secret put DEVNET_RPC_URL
npx wrangler secret put DEVNET_RELAYER_SECRET_B64

# Configure at least one DEX aggregator (each follows the standard <PROVIDER>_API_KEY / <PROVIDER>_API_URL pattern):
npx wrangler secret put JUPITER_API_KEY
# Optional Jupiter custom base URL (defaults to https://api.jup.ag):
# npx wrangler secret put JUPITER_API_URL
# Optional additional aggregators:
# npx wrangler secret put DFLOW_API_KEY
# npx wrangler secret put DFLOW_API_URL
# npx wrangler secret put TITAN_API_URL
# npx wrangler secret put TITAN_API_KEY
# npx wrangler secret put BEDROCK_API_URL
# npx wrangler secret put BEDROCK_API_KEY
# npx wrangler secret put OKX_API_URL
# npx wrangler secret put OKX_API_KEY
# npx wrangler secret put OKX_SECRET_KEY
# npx wrangler secret put OKX_PASSPHRASE

# Optional — bearer token for POST /v1/admin/refill:
npx wrangler secret put RELAY_ADMIN_TOKEN
```

---

## Step 3 — Tune Your Economics & Rate Limits (Optional)

Edit the non-secret `vars` in `apps/relay/wrangler.jsonc` (or copy it to gitignored `apps/relay/wrangler.prod.jsonc` if you want to attach a custom domain or `account_id`):

| Variable | Default | Meaning |
|---|---|---|
| `DEFAULT_AGGREGATOR` | `jupiter` | Default DEX aggregator (`jupiter`, `bedrock`, `dflow`, `titan`, `okx`) |
| `ENABLED_AGGREGATORS` | `jupiter,bedrock,dflow,titan,okx` | Aggregators exposed by `/v1/aggregators` & `auto` race |
| `BASE_SWAP_FEE_BPS` | `25` | Minimum swap fee (0.25%) collected to the relayer's output-mint ATA |
| `MAX_SELF_PAY_BPS` | `450` | Maximum dynamic bps cap for self-paying small swaps |
| `SELF_PAY_MARGIN_BPS` | `11000` | Rent + gas reimbursement multiplier (`11000` = 1.10× live cost) |
| `ALLOW_MICRO_SWAP_SUBSIDY` | `true` | If `false`, rejects swaps too small to self-pay (`402 FEE_REQUIRED`) |
| `MAX_DAILY_SPONSORED_SOL_MAINNET` | `0.05` | Global daily cap (SOL) for sponsored Transfers / Merges / Withdrawals |
| `SPONSORED_PER_IP_PER_HOUR_MAINNET` | `12` | Per-IP hourly sponsored cap |
| `SPONSORED_PER_IP_PER_DAY_MAINNET` | `25` | Per-IP daily sponsored cap |
| `SPONSORED_COOLDOWN_SEC_MAINNET` | `12` | Minimum cooldown between sponsored requests from the same IP |
| `REFILL_MIN_SOL` | `0.08` | Cron (`*/15 * * * *`) auto-unwraps WSOL / swaps fee tokens back to SOL below this threshold |
| `CORS_ORIGINS` | `*` | Comma-separated allowed browser origins (lock down to your UI origin if private) |

---

## Step 4 — Deploy & Verify

```bash
cd apps/relay
pnpm typecheck
pnpm deploy
```

Wrangler prints your live Worker URL (e.g. `https://audren-relay.<your-subdomain>.workers.dev`). Verify it immediately:

```bash
RELAY_URL="https://audren-relay.<your-subdomain>.workers.dev"

curl -s "$RELAY_URL/health" | jq .
curl -s "$RELAY_URL/v1/info?cluster=mainnet" | jq .
curl -s "$RELAY_URL/v1/aggregators" | jq .
```

Confirm that `/v1/info?cluster=mainnet` shows:
- `relayerPubkey` matching your keypair
- `balanceSol` > `0.05`
- live `rentSchedule` fetched from your RPC

---

## Step 5 — Connect Clients to Your Relayer

### A. In the Audren Web UI (`https://audren.xyz/demo/` or self-hosted `apps/web`)
1. Open the Wallet Vault (`/demo/`).
2. Click **Relay Settings → Use Your Own Relay**.
3. Paste `https://audren-relay.<your-subdomain>.workers.dev` and save.
4. Or bake your relayer into your own self-hosted Web UI build:
   ```bash
   cd apps/web
   NEXT_PUBLIC_AUDREN_RELAY_URL="https://audren-relay.<your-subdomain>.workers.dev" pnpm build
   pnpm deploy
   ```

### B. In `@audren/sdk`
```ts
import { AudrenRelayClient } from '@audren/sdk';

const RELAY_URL = 'https://audren-relay.<your-subdomain>.workers.dev';
const relay = new AudrenRelayClient(RELAY_URL);
const info = await relay.getInfo('mainnet');
console.log('Relayer fee payer:', info.relayerPubkey);
```

---

## Security Architecture of `audren-relay`

Every `POST /v1/relay/submit` request passes **four zero-trust gates** before your relayer ever signs:

1. **Instruction Firewall (`src/policy/firewall.ts`):** Permits **ONLY** Audren shielded spend tags (`Tag 3 Transfer`, `Tag 4 Merge`, `Tag 5 ExecViaEscrow`, `Tag 6 Withdraw`) plus strictly allowlisted zero-signer `preInstructions` (such as lending reserve refresh or oracle crank) immediately preceding `Tag 5`. Rejects `Deposit`, arbitrary programs, extra signers (`accounts[0]` MUST equal your relayer pubkey and be the ONLY signer), and oversized payloads.
2. **Pre-Flight Simulation (`simulateV1Transaction`):** Simulates the complete Solana v1 (`0x81`) transaction against your RPC and measures exact relayer lamport outflow + exact output-mint fee token inflow — forged proofs fail at **0 lamports spent**.
3. **Atomic SQLite Durable Object (`RelayGuard`):** Enforces per-IP cooldowns, sliding hourly/daily quotas, global daily SOL budget, and atomic in-flight nullifier locking to prevent duplicate concurrent submissions.
4. **Auto-Refill Treasury Cron (`src/cron/refill.ts`):** Every 15 minutes, if native SOL falls below `REFILL_MIN_SOL`, discovers accumulated SPL & Token-2022 fee balances, unwraps WSOL, and swaps fee tokens back to native SOL (simulating every refill transaction before signing).
