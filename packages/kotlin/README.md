# `xyz.audren.sdk` — Audren Kotlin SDK (Android & JVM)

Native Kotlin SDK for **Audren v1** (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`), targeting **Android (API 24+)** and **JVM 21+**.

Backed by the single audited Rust core (`crates/audren-client` via `crates/audren-ffi` + UniFFI + JNA) so Android wallets and JVM backends run native ~50 ms local zero-knowledge proving (Multi-Base Binary Triptych + Batched Bulletproofs) with zero cryptographic re-implementation drift. Verified byte-for-byte against [`spec/test-vectors.json`](../../spec/test-vectors.json) on every CI run.

## The 6 Standardized Building Blocks

1. **Keys** — `deriveKeysFromSeed`, `deriveSubaccountKeys`, `parseAudrenAddress`, `formatAudrenAddress`, `exportFullViewingKey`, `assetGenerator`
2. **PDAs & Layouts** — `derivePoolPda`, `deriveEpochPagePda`, `deriveSolVaultPda`, `deriveVaultAuthPda`, `derivePageRentVaultPda`, `deriveSwapEscrowPda`, `deriveLanePda`, `deriveLaneRentVaultPda`, `deriveNullifierPda`, `deriveProofBufferPda`, `decodePoolState`, `decodeEpochPageHeader`
3. **Scanner** — `pageScanDataSlice` (`offset: 64, length: 1056`), `scanPageDataslice`, `scanEpochPage`
4. **Prover** — `buildDepositInstruction`, `buildTransferInstruction`, `buildMergeInstruction`, `buildSwapViaRouterInstruction`, `buildWithdrawInstruction`, `buildBufferedExecutionPlan`
5. **Disclosure & Audit** — `createSelectiveDisclosureProof`, `verifySelectiveDisclosureProof`, `verifySelectiveDisclosureOnPage`, `deriveAuditorKeypair`, `auditorDecryptNote`
6. **Relayer & Router** — `jupiterCpiExcludedDexes`, `defaultRelayUrl`, `prepareRouterAccounts`

## Build & Run Conformance Tests Locally

```bash
# 1. Build native Rust FFI library & refresh Kotlin bindings (from repo root)
./scripts/build-mobile-sdks.sh bindings

# 2. Run full 6-building-block Kotlin conformance & ZK prover suite
cd packages/kotlin && gradle test
```

## Packaging for Android (`jniLibs`)

```bash
# Requires Android NDK + `cargo install cargo-ndk` + rustup Android targets
./scripts/build-mobile-sdks.sh android
# Produces packages/kotlin/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}/libaudren_ffi.so
```

In your Android app module's `build.gradle.kts`, depend on JNA's Android AAR alongside `xyz.audren.sdk`:

```kotlin
dependencies {
    implementation("net.java.dev.jna:jna:5.15.0@aar")
}
```

## Quick Example

```kotlin
import xyz.audren.sdk.*
import java.security.SecureRandom

val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
val alice = deriveKeysFromSeed(seed)
val sub1 = deriveSubaccountKeys(seed, 1u)
val pool = derivePoolPda(0u, programId())
val slice = pageScanDataSlice() // offset: 64, length: 1056
```
