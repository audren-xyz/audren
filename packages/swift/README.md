# `AudrenSDK` — Audren Swift SDK (iOS & macOS)

Native Swift Package for **Audren v1** (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`), targeting **iOS 15+** and **macOS 13+**.

Backed by the single audited Rust core (`crates/audren-client` via `crates/audren-ffi` + UniFFI) so mobile apps get native ~50 ms local zero-knowledge proving (Multi-Base Binary Triptych + Batched Bulletproofs) with zero cryptographic re-implementation drift. Verified byte-for-byte against [`spec/test-vectors.json`](../../spec/test-vectors.json) on every CI run.

## The 6 Standardized Building Blocks

1. **Keys** — `deriveKeysFromSeed`, `deriveSubaccountKeys`, `deriveDefiSessionKeypair`, `parseAudrenAddress`, `formatAudrenAddress`, `exportFullViewingKey`, `assetGenerator`
2. **PDAs & Layouts** — `derivePoolPda`, `deriveEpochPagePda`, `deriveSolVaultPda`, `deriveVaultAuthPda`, `derivePageRentVaultPda`, `deriveEscrowPda`, `deriveUnwrapPda`, `deriveLanePda`, `deriveLaneRentVaultPda`, `deriveNullifierPda`, `deriveProofBufferPda`, `deriveAssociatedTokenAddress`, `decodePoolState`, `decodeEpochPageHeader`, `decodeAppendLaneState`, `pageIdForLane`, `laneOfPageId`, `seqOfPageId`, `netDepositAmount`
3. **Scanner** — `pageScanDataSlice` (`offset: 64, length: 1056`), `scanPageDataslice`, `scanEpochPage` (read-only FVK or spendable)
4. **Prover** — `buildDepositInstruction`, `buildTransferInstruction`, `buildMergeInstruction`, `buildExecViaEscrowInstruction`, `buildWithdrawInstruction`, `buildBufferedExecutionPlan`, `buildCloseProofBufferInstruction`, `buildOpenPageInstruction`, `buildOpenLanePageInstruction`
5. **Disclosure & Audit** — `createSelectiveDisclosureProof`, `verifySelectiveDisclosureProof`, `verifySelectiveDisclosureOnPage`, `deriveAuditorKeypair`, `auditorDecryptNote`
6. **Relayer & Escrow CPI** — `jupiterCpiExcludedDexes`, `defaultRelayUrl`, `prepareEscrowAccounts`

## Build & Run Conformance Tests Locally

```bash
# 1. Build native Rust FFI library & refresh Swift bindings (from repo root)
./scripts/build-mobile-sdks.sh bindings

# 2. Run full 6-building-block Swift conformance & ZK prover suite
cd packages/swift && swift test
```

## Packaging for iOS (`XCFramework`)

```bash
# Requires rustup targets: aarch64-apple-ios, aarch64-apple-ios-sim, x86_64-apple-ios
./scripts/build-mobile-sdks.sh ios
# Produces packages/swift/AudrenFFI.xcframework
```

## Quick Example

```swift
import AudrenSDK
import Foundation

let seed = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
let alice = try deriveKeysFromSeed(seed32: seed)
let sub1 = try deriveSubaccountKeys(masterSeed32: seed, accountIndex: 1)
let pool = try derivePoolPda(poolId: 0, programId: programId())
let slice = pageScanDataSlice() // offset: 64, length: 1056
```
