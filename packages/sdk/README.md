# `@audren/sdk` — Audren TypeScript SDK

Unified TypeScript ESM SDK for **Audren** (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`), verified byte-for-byte against [`spec/test-vectors.json`](../../spec/test-vectors.json) on every CI run.

- **`@audren/sdk`** (root entrypoint): Zero-WASM core for Node.js, Browsers, and Cloudflare Workers — pure-TS Circom BN254 Poseidon, BIP-350 Bech32m `aud1...` stealth addresses, RFC 8439 ChaCha20-Poly1305 versioned `106 B` SoA memos (`72 B` ciphertext + `34 B` AAD + `14 B` encrypted `paymentId` + X25519 low-order rejection), all 12 canonical PDAs (`audren_*`), zero-copy account decoders, zero-indexer `CompactWalletStore` + privacy-first ordinary Solana RPC `getMultipleAccounts` scanner, all 9 instruction builders (`Deposit`, `Transact`, `ExecViaEscrow`, `UpdatePool`, etc.), Solana Transaction v1 (`0x81`) compiler, Privacy Relayer client, and Codama/Anchor IDLs.
- **`@audren/sdk/prover`**: Exact Rust-compiled WASM BN254 Groth16 prover (`audren_circuits.wasm`, `17,861` R1CS, 4-ary Depth-20 global MASP, `192 B` proof) running natively in Node.js and Browser Web Workers.

## Install

```bash
pnpm add @audren/sdk
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

// Local BN254 Groth16 WASM prover (Node.js or Browser Web Worker)
const prover = await AudrenWasmProver.init();
```

## Verify Locally

```bash
pnpm --dir packages/sdk typecheck && pnpm --dir packages/sdk test
```
