# Deploy Your Own Audren Privacy Relayer

Audren is **100% relayer-agnostic**. Anyone can run an independent Privacy Relayer in under 5 minutes on Cloudflare Workers (free or paid plan) with zero shared credentials, zero trust in `relay.audren.xyz`, and full support for all three fee settlement modes:

1. **Private Transfers (`Transact` Tag 5, `ASSET_MODE_PRIVATE`)** — collects an encrypted shielded `cm2` fee note verified instantaneously in the Worker via a read-only `FullViewingKey` (zero spend authority in hot Worker memory).
2. **Public Withdrawals (`Transact` Tag 5, `ASSET_MODE_PUBLIC` + optional `WITHDRAW_FLAG_UNWRAP_WSOL`)** — collects an explicit on-chain `relayer_fee` directly to the relayer fee recipient (or atomic unwrapped Native SOL).
3. **Shielded DeFi Execution (`ExecViaEscrow` Tag 6)** — routes through Jupiter, Bedrock, DFlow, Titan, or OKX via isolated `escrow` shards with input-leg or post-CPI output-leg (`EXEC_FLAG_FEE_ON_OUTPUT`) fee deduction.

A relayer **never** receives user spending keys or viewing keys — its strict firewall rejects `Deposit` (`Tag 3`) and admin instructions (`InitPool`, `InitLane`, `SetPaused`, `UpdatePool`), requires a configured `relayerPool` member to be the sole signer (`accounts[0]`), enforces a configurable `SELF_PAY_FEE_MINTS` allowlist with on-chain mint safety inspection (rejecting Token-2022 `Pausable`, mutable `TransferFeeConfig` authority, and untrusted `FreezeAuthority`), requires an audited swap router allowlist (`AUDITED_SWAP_ROUTER_PROGRAMS`) before crediting zero-native-fee (`relayer_fee == 0`) platform-fee gains on `ExecViaEscrow`, pins pre-state and simulation slots (`preSlot`/`simSlot`) with a deterministic minimum-outflow floor, enforces self-pay (`isSelfPaying`) and `<= 2` outputs/ix on multi-instruction merge batches, keeps its UTC-day domain-separated IP-hash salt strictly in ephemeral DO memory, and runs a permissionless cron (`PublishCheckpoint` Tag 4 + `OpenPage` Tag 2) to keep checkpoints fresh.

---

## Step 1 — Generate Rotating Fee-Payer Keypairs & Read-Only Relayer FVK

Create dedicated keypairs inside `.credentials/` (gitignored):

```bash
mkdir -p .credentials && chmod 700 .credentials
solana-keygen new --no-bip39-passphrase -o .credentials/my-relayer-mainnet.json
chmod 600 .credentials/my-relayer-mainnet.json
solana-keygen pubkey .credentials/my-relayer-mainnet.json
```

Convert the first 32 bytes (Ed25519 seed) to base64:

```bash
node -e "const k=JSON.parse(require('fs').readFileSync('.credentials/my-relayer-mainnet.json','utf8')); console.log(Buffer.from(k.slice(0,32)).toString('base64'))"
```

For Mode 1 shielded `cm2` transfer fees, keep your relayer's Audren master seed **offline** (cold storage) and export **only** its read-only `FullViewingKey` JSON (`{ "spendPkHex": "<hex>", "nkHex": "<hex>", "viewSkHex": "<hex>", "viewPkHex": "<hex>" }`; short aliases `spendPk`/`nk`/`viewSk`/`viewPk` are also accepted) into the Worker secret `MAINNET_RELAYER_FVK_JSON`.

---

## Step 2 — Configure Wrangler Secrets & Policy Vars

```bash
cd apps/relay
pnpm install
npx wrangler login

# Required for Mainnet relaying:
npx wrangler secret put MAINNET_RPC_URL
npx wrangler secret put MAINNET_RELAYER_SECRET_B64
# Optional rotating multi-payer pool (JSON array of base64 seeds):
# npx wrangler secret put MAINNET_RELAYER_SECRETS_JSON
# Optional read-only FVK for shielded cm2 transfer fees:
# npx wrangler secret put MAINNET_RELAYER_FVK_JSON

# Optional — enable Devnet relaying too:
npx wrangler secret put DEVNET_RPC_URL
npx wrangler secret put DEVNET_RELAYER_SECRET_B64

# Configure at least one DEX aggregator:
npx wrangler secret put JUPITER_API_KEY
# Optional additional aggregators:
# DFLOW_API_KEY (+ optional DFLOW_API_URL)
# TITAN_API_URL + TITAN_API_KEY
# BEDROCK_API_URL + BEDROCK_API_KEY
# OKX_API_KEY + OKX_SECRET_KEY + OKX_PASSPHRASE (+ optional OKX_API_URL)
```

Optional non-secret firewall and solvency overrides in `apps/relay/wrangler.jsonc` (`vars`):

- `SELF_PAY_FEE_MINTS` — comma-separated allowlist of liquid self-pay fee mints (defaults to WSOL, USDC, USDT, and verified liquid blue-chips; non-allowlisted mints and unsafe Token-2022 mints never earn self-pay credit).
- `AUDITED_SWAP_ROUTER_PROGRAMS` — comma-separated allowlist of audited DEX router program IDs eligible for zero-native-fee (`relayer_fee == 0`) platform-fee simulation credit on `ExecViaEscrow`.
- `ALLOWED_PRE_IX_PROGRAMS` — comma-separated allowlist of zero-signer DeFi refresh/oracle crank programs permitted in `preInstructions` before `ExecViaEscrow`.

---

## Step 3 — Deploy & Verify

```bash
cd apps/relay
pnpm typecheck && pnpm test
pnpm deploy
```

Verify your live Worker immediately:

```bash
RELAY_URL="https://audren-relay.<your-subdomain>.workers.dev"
curl -s "$RELAY_URL/health" | jq .
curl -s "$RELAY_URL/v1/info?cluster=mainnet" | jq .
```

---

## Step 4 — Connect Clients to Your Relayer

- **In the Audren Web UI (`/demo/`):** Click **Use your own relay**, paste your Worker URL, and save.
- **In `@audren/sdk`:**

```ts
import { AudrenRelayClient } from '@audren/sdk';

const relay = new AudrenRelayClient('https://audren-relay.<your-subdomain>.workers.dev');
const info = await relay.getInfo('mainnet');
console.log('Relayer fee payer:', info.relayerPubkey);
```
