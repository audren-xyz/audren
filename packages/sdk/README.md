# `@audren/sdk`

Zero-dependency TypeScript ESM SDK for **Audren v1** (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`), targeting Node.js 22+ and modern browsers with zero runtime npm dependencies.

All constants, account layouts, instruction tags, and error codes match [`crates/audren-core`](../../crates/audren-core/src/lib.rs) byte-for-byte. See [`ARCHITECTURE.md`](../../ARCHITECTURE.md) for the full cryptographic specification and on-chain invariants.

## Modules (`src/index.ts`)

| Module | Exports |
|---|---|
| `src/constants.ts` | `AUDREN_PROGRAM_ID`, PDA seeds, account magics & byte offsets, instruction tags `0x00..0x0C`, `PoolMode`, `AudrenError` (`1..33`), `triptychProofLen`, `inputPagesForM`, `mForInputPages`, lane page-ID helpers (`laneOfPageId`, `seqOfPageId`, `pageIdForLane`) |
| `src/layout.ts` | Zero-copy binary decoders `decodePoolState` (`192 B`), `decodeAppendLaneState` (`64 B`), `decodePageHeader` (`6,240 B`), `readPageNote`, and `decodePageScanSlice` (`1,056 B` `dataSlice`) |
| `src/instructions.ts` | Non-ZK, buffer, and lane wire encoders (`encodeInitPoolData`, `encodeOpenPageData`, `encodeDepositData`, `encodeSetPausedData`, `encodeWriteProofBufferChunks`, `encodeExecBufferedData`, `encodeCloseProofBufferData`, `encodeInitLaneData`, `encodeOpenLanePageData`) plus Token-2022 `TransferFeeConfig` math (`calculateTransferFee`, `netDepositAmount`) |
| `src/scanner.ts` | Standard Solana RPC `getMultipleAccounts` (`dataSlice: { offset: 64, length: 1056 }`, 100 pages / `3,200` notes per call), WebSocket `programSubscribe` payload builder (`buildPageSubscribeWsPayload`), and batched `checkNullifiersSpent` |
| `src/swap.ts` | Router-agnostic `SwapViaRouter` helpers (`fetchAggregatorPrivateSwapRoute`, `resolveRouterEscrowIndices`, `prepareRouterAccountsForAudren`) with default PDA-CPI exclusion list `JUPITER_CPI_EXCLUDED_DEXES` |
| `src/tx-v1.ts` | Zero-dependency Solana Transaction Version 1 (`SIMD-0385`, `0x81`, `<= 4,096 B`) compiler and serializer (`compileV1Message`, `serializeV1Transaction`) with inline `TransactionConfig` |

> Zero-knowledge proving instructions (`Transfer`, `Merge`, `SwapViaRouter`, `Withdraw`) require Ristretto255 Multi-Base Triptych + native Agave Bulletproof generation, available in the Rust SDK ([`crates/client`](../../crates/client/src/lib.rs)); this TypeScript package does not include a prover or wallet key management.

## Build, test and consume

From the protocol repository root, use Node 22+ and pnpm:

```bash
pnpm --dir packages/sdk install --frozen-lockfile
pnpm --dir packages/sdk typecheck
pnpm --dir packages/sdk test
pnpm --dir packages/sdk pack --out /tmp/audren-sdk.tgz
```

Install the resulting archive into a consumer with `npm install /tmp/audren-sdk.tgz`.
The archive includes ESM JavaScript and TypeScript declarations; no experimental Node flags are required.
There is no npm registry release promised by this repository. The package remains private to prevent accidental publication.

```js
import { AUDREN_PROGRAM_ID, encodeInitLaneData } from '@audren/sdk';
console.log(AUDREN_PROGRAM_ID);
const instructionData = encodeInitLaneData(1); // Tag 11; authority-signed lane initialization.
console.log([...instructionData]); // [11, 1]
```

This example only constructs bytes. It does not submit a transaction or create a private transfer.
Use the Rust client for key derivation and proofs. Router helpers prepare compatible accounts; they do not guarantee a provider or route is available.

`test/package.test.mjs` checks built-package imports, lane wire vectors, fee rounding and v1 serialization boundaries.
Generated `dist/`, package archives and `node_modules/` are build outputs and are not committed.

## Privacy responsibilities

Deposits, withdrawals and ordinary DEX execution have public account, asset and amount boundaries by design. Relayers are optional and permissionless; they need no user spending keys but can observe request metadata. Ring slots are not guaranteed anonymous users. Evaluate candidate selection, RPC queries and fee-payer exposure together. Visible vault assets are not an independent proof of all private liabilities. See the [protocol privacy model](../../ARCHITECTURE.md#privacy-boundaries-and-effective-anonymity).
