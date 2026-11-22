# `apps/web` (`audren-web`)

Next.js 16 static frontend and Cloudflare Worker API proxy for **Audren**, providing the protocol landing page, technical specification, live Mainnet & Devnet interactive privacy wallet, and no-wallet Devnet test sandbox.

## Pages & UI capabilities

| Route | Component / File | Purpose |
|---|---|---|
| `/` | `components/LandingExperience.tsx`, `components/LandingExperience.module.css` | Three-way public-visibility comparison, four interactive ring-flow diagrams, 6-primitive DeFi rail ledger (`ExecViaEscrow` + Private DeFi Sessions), local-key/on-chain-proof model, Mainnet evidence links and security boundaries |
| `/how-it-works/` | `app/how-it-works/page.tsx`, `components/HowAudrenWorksVisual.tsx` | Address anatomy, four detailed privacy flows (`Deposit`, `Transfer`, `ExecViaEscrow`, `Receipt / Self-Paying Exit & Sessions`) and cryptographic checks |
| `/compare/` | `app/compare/page.tsx` | Sourced native and protocol comparison with explicit operation-specific privacy limits |
| `/developers/` | `app/developers/page.tsx` | Unified 4-language SDK overview (Rust, TypeScript, Swift iOS, Kotlin Android), 6 building blocks, `spec/test-vectors.json` conformance, and copyable code workbench |
| `/demo/` | `components/LiveWalletVault.tsx`, `components/DevnetDemoExperience.tsx` | Full Mainnet & Devnet Wallet Vault (**Go Private** to self or directly to any recipient's `aud1…`, **Private Send**, **Combine Notes**, **Full & Partial Shielded DeFi Swaps** via `ExecViaEscrow` with `25% / 50% / 75% / Max` + shielded change, **Go Public** with atomic `Unwrap WSOL → Native SOL`, native `/v1/fee-quote` self-paying fees & deterministic **DeFi Session `B_0, B_1…`** funding, **Stranger View**, **Encrypted Vault Backup**, **1-Click Selective Disclosure Viewing Receipts**, **Live On-Chain Verification** strip, **Bring Your Own Relayer** + **Direct Self-Pay**) plus a 3-step no-wallet **Free Devnet Sandbox** |
| `/architecture/` | `app/architecture/page.tsx` | On-chain instruction register (`0x00..0x0C`), `EpochPage` SoA layout, Multi-Base Triptych equations, optional pluggable Privacy Relay overview, and measured sBPFv3 Compute Units |
| `/faq/` | `app/faq/page.tsx` | Protocol, privacy model, relayer optionality, and Token-2022 FAQ |
| `/privacy/`, `/terms/` | `app/privacy/page.tsx`, `app/terms/page.tsx` | Privacy notice and open-source protocol terms |

## Privacy claims

The homepage, FAQ and protocol specification distinguish public entry/exit by design from possible correlation across those boundaries. Relayers are permissionless and optional; local key custody does not imply network anonymity. Ring capacities are not guaranteed anonymity counts, TVL is not a privacy metric, and visible vault assets do not independently prove all private liabilities.

## Architecture & wiring

```text
  Browser (Web UI)
    │  • Client-side Ristretto255 + Triptych + Bulletproofs prover (`lib/audren-crypto.ts`, `lib/audren-prover.ts`)
    │  • Wallet Standard connection (`lib/solana-wallet.ts`: Phantom, Solflare, Backpack)
    │
    ├──► audren-web Worker (`worker/index.ts`, same-origin `/api/*`)
    │      • Solana Mainnet & Devnet RPC reads, `dataSlice` scans, nullifier checks, `/api/tx/inspect`, `/api/rpc/send`
    │      • Token metadata/search via optional `GATEWAY` / `GATEWAY_SEARCH` service bindings or Jupiter API (`JUPITER_API_KEY`)
    │      • Direct Self-Pay Jupiter proxy (`/api/jupiter/quote`, `/api/jupiter/swap-instructions`) via `JUPITER_API_KEY`
    │      • Optional no-wallet Devnet Sandbox faucet (`/api/devnet/deposit`, Devnet-only `/api/relay/submit`)
    │
    └──► Pluggable Privacy Relayer (configurable via `NEXT_PUBLIC_AUDREN_RELAY_URL`, default `https://relay.audren.xyz`, or user-supplied HTTPS/localhost URL)
           • `/v1/info`, `/v1/fee-quote`, `/v1/swap/quote`, `/v1/swap/instructions`, `/v1/relay/submit`
           • Signs & submits single Solana v1 (0x81) txs with 0 user wallet signers
```

## Worker API routes (`worker/index.ts`)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/pool?cluster=mainnet\|devnet` (alias `/api/devnet/pool`) | Live `PoolState`, active lanes, and recent `EpochPage` summaries |
| `GET` | `/api/wallet/balances?cluster=...&address=...` | Public SOL, SPL, and Token-2022 balances enriched with token metadata & prices |
| `GET` / `POST` | `/api/tokens/search`, `/api/tokens/resolve`, `/api/tokens/logo/*`, `/api/tokens/mint-logo/*` | Live token search, metadata resolution, and cached token logos |
| `GET` / `POST` | `/api/pages/slices`, `/api/pages/sealed`, `/api/pages/fetch` | Pure-RPC `dataSlice` scanning (`offset: 64, length: 1056`) and full/CDN-cached sealed page fetches |
| `POST` | `/api/buffers/check`, `/api/notes/resolve-dynamic`, `/api/nullifiers` | Abandoned `ProofBuffer` detection, dynamic swap output verification, and batch `NullifierPDA` spend checks |
| `GET` / `POST` | `/api/rpc/blockhash`, `/api/rpc/send` | Fresh blockhash and signed transaction submission + confirmation |
| `GET` | `/api/tx/inspect?cluster=...&signature=...` | Live `getTransaction` (`maxSupportedTransactionVersion: 1`) inspector powering `LIVE ON-CHAIN VERIFICATION` |
| `POST` | `/api/jupiter/quote`, `/api/jupiter/swap-instructions` | Jupiter swap routing used when the user chooses **Direct Self-Pay (NO RELAYER)** on Mainnet |
| `POST` | `/api/devnet/deposit`, `/api/relay/submit` | Free Devnet Sandbox faucet deposit and Devnet sandbox private spend (`DEVNET_DEMO_SECRET_B64`) |

## Self-hosting, secrets & deployment

`wrangler.jsonc` is a clean, self-hostable Cloudflare Worker config with zero private account IDs or bindings:
- **Static assets:** `./out` (`ASSETS`, `run_worker_first: true`)
- **Wrangler secrets (`npx wrangler secret put <NAME>`):**
  - Required: `MAINNET_RPC_URL`
  - Required for Direct Self-Pay swaps & Jupiter token search: `JUPITER_API_KEY` (and optional `JUPITER_API_URL`, defaults to `https://api.jup.ag`)
  - Optional: `DEVNET_RPC_URL`, `DEVNET_DEMO_SECRET_B64`
- **Build-time relayer default:** Set `NEXT_PUBLIC_AUDREN_RELAY_URL="https://your-relay.workers.dev"` before `pnpm build` to point the UI at your own relayer by default.
- **Operator custom domain / private service bindings:** Keep operator overrides in gitignored `wrangler.prod.jsonc` and deploy with `pnpm deploy:prod`.

```bash
pnpm install
pnpm dev          # Local Next.js dev server on http://localhost:3040
pnpm check        # tsc --noEmit && eslint . && next build (exports ./out)
pnpm deploy       # pnpm check && wrangler deploy (open-source wrangler.jsonc)
pnpm deploy:prod  # pnpm check && wrangler deploy --config wrangler.prod.jsonc (gitignored operator config)
```

## Empirical end-to-end testing

All E2E scripts read RPC endpoints and test signer from environment variables (or gitignored `.credentials/`):
- `MAINNET_RPC_URL`
- `DEVNET_RPC_URL`
- `AUDREN_KEYPAIR_PATH` (default `../../.credentials/funder.json`)
- `AUDREN_BASE_URL` (default `https://audren.xyz`)

```bash
pnpm e2e:audit   # 4-part headless Chromium audit across public pages, Devnet, Mainnet, receipts & sandbox
pnpm e2e:ui      # Live Mainnet relayed Web UI lifecycle in headless Chrome
pnpm e2e:api     # Programmatic API, browser prover, dynamic swap resolution & PBKDF2 backup suite
```
