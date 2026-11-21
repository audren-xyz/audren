# apps/web — agent rules

Read the root [`AGENTS.md`](../../AGENTS.md) first. On-chain wire layouts are owned by `crates/audren-core/` and `program/`; the standalone relayer contract is owned by [`../relay/AGENTS.md`](../relay/AGENTS.md).

## Runtime architecture & boundaries

- **Cloudflare Worker with Static Assets:** Next.js 16 exports static pages to `out/` (`output: 'export'`), served behind `worker/index.ts` (`run_worker_first: true`). Tracked `wrangler.jsonc` is 100% open-source and self-hostable; operator production overrides (custom domains, `account_id`, optional private service bindings, `CANONICAL_HOST`, `TOKEN_GATEWAY_ORIGIN`) live strictly in gitignored `wrangler.prod.jsonc` (`pnpm deploy:prod`).
- **Clear separation between `apps/web` and `apps/relay`:**
  - `apps/web` serves the web UI, Solana RPC read/broadcast proxy (`/api/pool`, `/api/pages/*`, `/api/nullifiers`, `/api/wallet/balances`, `/api/tx/inspect`, `/api/rpc/*`), token search/logo proxy (optional `GATEWAY`/`GATEWAY_SEARCH` service bindings or Jupiter API via `JUPITER_API_KEY`), Direct Self-Pay Jupiter proxy (`/api/jupiter/*` via `JUPITER_API_KEY`), and the optional no-wallet Devnet Sandbox (`/api/devnet/*`, `/api/relay/submit` strictly for Devnet sandbox spends using `DEVNET_DEMO_SECRET_B64`).
  - `apps/web` holds **no** Mainnet relayer private key. Wallet-mode relaying calls the user-configured relayer URL directly from the browser (`NEXT_PUBLIC_AUDREN_RELAY_URL` or custom HTTPS/localhost URL configured via "Use Your Own Relay").
- **Standardized Jupiter API usage:** Always use authenticated `JUPITER_API_URL` (default `https://api.jup.ag`) with `JUPITER_API_KEY` uniformly across Direct Self-Pay swaps (`/api/jupiter/*`) and token metadata fallbacks — never fall back to unauthenticated public endpoints.
- **Single source of truth for protocol metadata & browser prover:**
  - Keep all deployed Program IDs, PDA addresses, ELF byte length & SHA-256, deployment slots, reference transaction signatures, and measured CU benchmarks centralized in `lib/protocol.ts`.
  - Keep `lib/audren-crypto.ts` and `lib/audren-prover.ts` byte-for-byte compatible with `crates/audren-core` and `program/src/`.
  - Keep `JUPITER_CPI_EXCLUDED_DEXES` in `worker/index.ts` synced with `apps/relay/src/aggregators/jupiter.ts`, `packages/sdk/src/swap.ts`, and `crates/client/src/router.rs`.
  - Keep `useCallback` / `useEffect` dependency arrays for live quote fetchers (`LiveWalletVault.tsx`) strictly primitive-only to prevent infinite re-quote loops.
- **Privacy claims:** Public entry/exit and permissionless optional relayers are intentional boundaries. Do not imply unconditional unlinkability, anonymity proportional to TVL, ring slots equal users, or visible assets prove all private liabilities.
- **Security headers, copy & lint hygiene:**
  - Preserve `public/_headers` (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Content-Security-Policy` allowing `connect-src 'self' https: http://localhost:* http://127.0.0.1:*` for pluggable user relayers).
  - Never use `eslint-disable`, `TODO`, or `FIXME` in source files; never default to public Solana RPC; never write "Mainnet-Beta" anywhere.
  - Every code example on `/developers` and `/architecture` must match real SDK signatures in `packages/sdk` and `crates/client`.
  - Maintain clean desktop and mobile (`390px`) layouts with zero horizontal overflow (`docScrollWidth === innerWidth`).

## Verification

```bash
pnpm check   # tsc --noEmit && eslint . && next build
```

<!-- BEGIN:nextjs-agent-rules -->

# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev` — verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->
