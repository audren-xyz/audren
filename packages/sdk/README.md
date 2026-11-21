# `@audren/sdk` — Audren TypeScript SDK

Unified TypeScript ESM SDK for **Audren v1** (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`), targeting Node.js 22+ and modern browsers.

Every constant, PDA, account decoder, key derivation, scanner, local zero-knowledge prover, selective disclosure verifier, institutional auditor decryptor, and router helper is verified byte-for-byte against [`spec/test-vectors.json`](../../spec/test-vectors.json) alongside the Rust, Swift, and Kotlin SDKs.

## Entrypoints

| Import | Dependencies | What It Provides |
|---|---|---|
| `@audren/sdk` | **Zero** runtime deps | Constants, all 11 PDAs (incl. `deriveEscrowPda`, `deriveUnwrapPda`), `aud1…` address parser/formatter, binary decoders (`PoolState`, `AppendLaneState`, `EpochPage`), `dataSlice` RPC/WS scanner payloads, escrow/relayer clients, Solana v1 (`0x81`) serializer, Codama 1.8.0 & Anchor IDLs |
| `@audren/sdk/prover` | `@noble/curves`, `@noble/hashes` | Full pure-TypeScript Ristretto255 key hierarchy (`deriveKeysFromSeed`, `deriveSubaccountKeys`, `deriveDefiSessionKeypair`, `exportFullViewingKey`, `assetGenerator`), local `dataSlice` note scanner & decryptor, Multi-Base Binary Triptych (`m=5/6/7`), CrossBase 1/2, Batched Bulletproofs (`U64`/`U128`), `Deposit` (incl. `feeFromAmount`) / `Transfer` / `Merge` / `ExecViaEscrow` (incl. native `relayerFee`) / `Withdraw` (incl. native `relayerFee` & atomic `unwrapWsol`) / `ProofBuffer` builders, Mode 1 Selective Disclosure, and Institutional Auditor ElGamal decryption |

## The 6 Standardized Building Blocks

1. **Keys** — `deriveKeysFromSeed`, `deriveSubaccountKeys`, `deriveDefiSessionKeypair`, `parseAudrenAddress`, `formatAudrenAddress`, `exportFullViewingKey`, `assetGenerator`
2. **PDAs & Layouts** — `derivePoolPda`, `deriveEpochPagePda`, `deriveSolVaultPda`, `deriveVaultAuthPda`, `derivePageRentVaultPda`, `deriveEscrowPda`, `deriveUnwrapPda`, `deriveLanePda`, `deriveLaneRentVaultPda`, `deriveNullifierPda`, `deriveProofBufferPda`, `decodePoolState`, `decodePageHeader`, `decodeAppendLaneState`
3. **Scanner** — `PAGE_SCAN_OFFSET` (`64`), `PAGE_SCAN_LEN` (`1056`), `PAGE_SCAN_DATA_SLICE`, `scanPageScanSlice`, `scanEpochPage` (read-only FVK or spendable), `scanEpochPageSpendable`, `buildPageSubscribeWsPayload`, `checkNullifiersSpent`
4. **Prover** — `buildDepositInstruction`, `buildTransferInstruction`, `buildMergeInstruction`, `buildExecViaEscrowInstruction`, `buildWithdrawInstruction`, `buildBufferedExecutionPlan`, `buildCloseProofBufferInstruction`
5. **Disclosure & Audit** — `createSelectiveDisclosureProof`, `verifySelectiveDisclosureReceipt`, `verifySelectiveDisclosureOnPage`, `deriveAuditorKeypair`, `auditorDecryptNote`
6. **Relayer & IDLs** — `AudrenRelayClient`, `AUDREN_DEFAULT_RELAY_URL`, `JUPITER_CPI_EXCLUDED_DEXES`, `prepareEscrowAccounts`, `prepareEscrowAccountsForAudren`, `compileV1Message`, `serializeV1Transaction`, `AUDREN_CODAMA_IDL`, `AUDREN_ANCHOR_IDL`

## Build, Test & Consume from Source

```bash
pnpm --dir packages/sdk install --frozen-lockfile
pnpm --dir packages/sdk typecheck
pnpm --dir packages/sdk test
```

Consuming directly from a local clone or packed tarball (no npm publication required):

```bash
pnpm --dir packages/sdk pack --out /tmp/audren-sdk.tgz
# In your project:
pnpm add /tmp/audren-sdk.tgz
```

## Quick Example

```ts
import { AUDREN_PROGRAM_ID, PAGE_SCAN_DATA_SLICE, derivePoolPda } from '@audren/sdk';
import { deriveKeysFromSeed, deriveSubaccountKeys, exportFullViewingKey } from '@audren/sdk/prover';

const seed = crypto.getRandomValues(new Uint8Array(32));
const alice = await deriveKeysFromSeed(seed);
const tradingSubaccount = await deriveSubaccountKeys(seed, 1);
const fvk = exportFullViewingKey(tradingSubaccount);
const { address: poolPda } = await derivePoolPda(0, AUDREN_PROGRAM_ID);
console.log({ address: alice.address, poolPda, fvk: fvk.spendPkB58, slice: PAGE_SCAN_DATA_SLICE });
```

## Privacy Responsibilities

Deposits, withdrawals, and external DEX execution have public account, asset, and amount boundaries by design. Relayers are optional and permissionless; they never receive spending keys. See [`ARCHITECTURE.md`](../../ARCHITECTURE.md#privacy-boundaries-and-effective-anonymity).
