# `@audren/sdk` — Audren TypeScript SDK

Unified TypeScript ESM SDK for **Audren** (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`), verified byte-for-byte against [`spec/test-vectors.json`](../../spec/test-vectors.json) on every CI run.

- **`@audren/sdk`** (root entrypoint): Zero-WASM core for Node.js, Browsers, and Cloudflare Workers — pure-TS Circom BN254 Poseidon, BIP-350 Bech32m `aud1...` stealth addresses (rejecting non-canonical `spend_pk`, whitespace, and low-order X25519 `view_pk` points), RFC 8439 ChaCha20-Poly1305 versioned `106 B` SoA memos (`72 B` ciphertext + `34 B` AAD + `14 B` encrypted `paymentId` + X25519 low-order rejection), all 12 canonical PDAs (`audren_*`), zero-copy account decoders, zero-indexer `CompactWalletStore` + Rendezvous (HRW) privacy-first ordinary Solana RPC `getMultipleAccounts` scanner & uniform batched `reconstructWitness`, all 9 instruction builders (`Deposit`, `Transact`, `ExecViaEscrow` with `extraWritablePubkeys`, `UpdatePool`, etc.), Solana Transaction v1 (`0x81`) compiler, multi-payer Privacy Relayer client (with optional `relayerPubkey` pinning), and Codama/Anchor IDLs.
- **`@audren/sdk/prover`**: Exact Rust-compiled WASM BN254 Groth16 prover (`audren_circuits.wasm`, `17,861` R1CS, 4-ary Depth-20 global MASP, `192 B` proof) running natively in Node.js and Browser Web Workers.

## Install

`@audren/sdk` is not yet published to npm. Build it from the repository and add it as a local dependency:

```bash
git clone https://github.com/audren-xyz/audren
pnpm --dir audren/packages/sdk install
pnpm --dir audren/packages/sdk build
pnpm add file:./audren/packages/sdk
```

## Quick Example

```ts
import {
  CompactWalletStore,
  deriveKeysFromSeed,
  derivePoolPdaSync,
  exportFullViewingKey,
  createSolanaRpcBatchFetcher,
  syncCompactStoreWithRpc,
} from '@audren/sdk';
import { AudrenWasmProver } from '@audren/sdk/prover';

const seed = crypto.getRandomValues(new Uint8Array(32));
const keys = deriveKeysFromSeed(seed);
const fvk = exportFullViewingKey(keys);
const pool = derivePoolPdaSync(0);

// Ordinary Solana RPC sync — zero indexer required
const store = new CompactWalletStore(0);
const fetchBatch = createSolanaRpcBatchFetcher(process.env.SOLANA_RPC_URL!);
await syncCompactStoreWithRpc({ store, fvk, fetchBatch });

// Local BN254 Groth16 WASM prover. In Node.js, init() reads the bundled wasm and
// 3.93 MB proving key; in a browser, serve both files and pass their URLs.
const prover = await AudrenWasmProver.init();
// const prover = await AudrenWasmProver.init({ wasmUrl: '/wasm/audren_circuits.wasm', pkUrl: '/wasm/audren_joinsplit.pk' });
```

## Verify Locally

```bash
pnpm --dir packages/sdk typecheck && pnpm --dir packages/sdk test
```
