# `apps/web` (`audren-web`)

Next.js 16 static frontend and Cloudflare Worker API proxy for **Audren**, providing the protocol landing page, technical specification, live Mainnet & Devnet interactive privacy wallet, and no-wallet browser WASM Groth16 sandbox.

## Pages & UI capabilities

| Route | Component / File | Purpose |
|---|---|---|
| `/` | `components/LandingExperience.tsx`, `components/LandingExperience.module.css` | Three-way public-visibility comparison, four interactive global MASP flow diagrams, 6-primitive DeFi rail ledger (`ExecViaEscrow` + Private DeFi Sessions), local-key/on-chain-proof model, deployment evidence links, and security boundaries |
| `/how-it-works/` | `app/how-it-works/page.tsx`, `components/HowAudrenWorksVisual.tsx` | Address anatomy (`aud1…`), four detailed privacy flows (`Deposit`, `Private Transfer`, `ExecViaEscrow`, `Self-Paying Exit & Sessions`), and cryptographic checks |
| `/compare/` | `app/compare/page.tsx` | Sourced native and protocol comparison with explicit operation-specific privacy limits |
| `/developers/` | `app/developers/page.tsx` | Unified 4-language SDK overview (Rust, TypeScript, Swift iOS, Kotlin Android), 6 building blocks, `spec/test-vectors.json` conformance, and copyable code workbench |
| `/demo/` | `components/LiveWalletVault.tsx`, `components/DevnetDemoExperience.tsx` | Full Mainnet & Devnet Wallet Vault (**Shield** Native SOL, Classic SPL, and Token-2022 via unified `Deposit` with `DEPOSIT_FLAG_NATIVE_SOL` / `DEPOSIT_FLAG_FEE_FROM_AMOUNT` and zero-crank auto-`OpenPage`, **Private Send** & opportunistic consolidation via `Transact` with inline `GlobalRootHistory` instant spendability on confirmation — `~400ms` today, `~150ms` under Alpenglow, **Shielded DeFi Swaps** via `ExecViaEscrow` with `EXEC_FLAG_FEE_ON_OUTPUT`, **Withdraw** with atomic `WITHDRAW_FLAG_UNWRAP_WSOL` and read-only `GlobalRootHistory` on full exits, **DeFi Session `B_0, B_1…`**, **Stranger View**, **Encrypted Vault Backup Export/Restore** with `birthdaySlot`, **Mode 1 Selective Disclosure Receipts** with on-chain `SubtreePage` verification, **Mode 2 FullViewingKey**, **Bring Your Own Relayer** + **Direct Self-Pay**) plus a no-wallet **Browser WASM Groth16 Sandbox** (dedicated Web Worker `/wasm/prover-worker.js`) with live Devnet `Deposit` & instant `Transact` relay |
| `/architecture/` | `app/architecture/page.tsx` | On-chain instruction register (`0x00..=0x08`), inline dual-ring `GlobalRootHistory` (`10,216 B` `AUD1RT01`), `MemoPage` SoA layout (`10,240 B`, `96` notes/page, `72 B` versioned ciphertexts / `106 B` entries), frozen `17,861`-R1CS BN254 Groth16 circuit spec, optional zero-crank Privacy Relay overview, and measured sBPFv3 Compute Units & tight CU budgets |
| `/faq/` | `app/faq/page.tsx` | Protocol, privacy model, relayer optionality, and Token-2022 FAQ |
| `/privacy/`, `/terms/` | `app/privacy/page.tsx`, `app/terms/page.tsx` | Privacy notice and open-source protocol terms |

## Privacy claims

The homepage, FAQ, and protocol specification distinguish public entry/exit by design from possible correlation across those boundaries. Relayers are permissionless and optional; local key custody does not imply network anonymity. Pool size is not a guaranteed anonymity count, TVL is not a privacy metric, and visible vault assets do not independently prove all private liabilities.

## Architecture & wiring

```text
  Browser (Web UI)
    │  • Client-side BN254 Poseidon + ChaCha20-Poly1305 (`@audren/sdk`) & WASM Groth16 prover (`@audren/sdk/prover` + `/wasm/audren_circuits.wasm`)
    │  • Wallet Standard connection (`lib/solana-wallet.ts`: Phantom, Solflare, Backpack)
    │
    ├──► audren-web Worker (`worker/index.ts`, same-origin `/api/*`)
    │      • Ordinary Solana Mainnet & Devnet RPC reads (`/api/pool`, `/api/rpc/accounts`, `/api/wallet/balances`, `/api/rpc/blockhash`, `/api/rpc/send`)
    │      • Dynamic token metadata & on-chain decimals (`/api/tokens/resolve`) via optional `GATEWAY`, Jupiter API (`JUPITER_API_KEY`), or direct RPC fallback
    │      • Direct Self-Pay Jupiter proxy (`/api/jupiter/quote`, `/api/jupiter/swap-instructions` with resolved ALTs) via `JUPITER_API_KEY`
    │      • Optional no-wallet Devnet Sandbox faucet (`/api/devnet/deposit`, Devnet-only `/api/relay/submit`)
    │
    └──► Pluggable Zero-Crank Privacy Relayer (configurable via `NEXT_PUBLIC_AUDREN_RELAY_URL`, default `https://relay.audren.xyz`, or user-supplied HTTPS/localhost URL)
           • `/v1/info`, `/v1/fee-quote`, `/v1/swap/quote`, `/v1/swap/instructions`, `/v1/relay/submit`
           • Auto-prepends idempotent `OpenPage` if needed & signs/submits single Solana Transaction v1 (`0x81`, `4,096 B`) with 0 user wallet signers
```

## Worker API routes (`worker/index.ts`)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/pool?cluster=mainnet\|devnet` (alias `/api/devnet/pool`) | Live `PoolState` (`rootEpochInterval`), active `LaneTreeState` headers, and live `GlobalRootHistory` (`rootsPda` dual-ring `latest` & `stable` snapshot summaries) |
| `POST` | `/api/rpc/accounts` | Ordinary batched `getMultipleAccounts` proxy powering zero-indexer `CompactWalletStore` sync (`SubtreePage`, `SubtreeRootPage`, `MemoPage`, `NullifierPage`, `GlobalRootHistory`) |
| `GET` | `/api/wallet/balances?cluster=...&owner=...` | Public SOL, Classic SPL, and Token-2022 balances |
| `POST` | `/api/tokens/resolve` | Dynamic token symbol, program, and on-chain `decimals` resolution |
| `GET` / `POST` | `/api/rpc/blockhash`, `/api/rpc/send` | Fresh blockhash and signed transaction submission + confirmation |
| `POST` | `/api/jupiter/quote`, `/api/jupiter/swap-instructions` | Jupiter swap routing + ALT resolution used when the user chooses **Direct Self-Pay (NO RELAYER)** |
| `POST` | `/api/devnet/deposit`, `/api/relay/submit` | Free Devnet Sandbox faucet deposit (with inline `GlobalRootHistory` update) and hardened Devnet sandbox `Transact` relay (`DEVNET_DEMO_SECRET_B64`) |

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

```bash
pnpm e2e:audit                             # Local crypto, CompactWalletStore & WASM Groth16 prover audit
BASE_URL="https://audren.xyz" pnpm e2e:api # Live Worker API smoke suite
BASE_URL="https://audren.xyz" pnpm e2e:ui  # Live static routes, CSP headers & WASM binary check
```
