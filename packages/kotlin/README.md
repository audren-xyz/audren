# `xyz.audren.sdk` — Audren Kotlin SDK (Android & JVM)

Native Kotlin SDK for **Audren** (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`), targeting **Android (API 24+)** and **JVM 21+**.

Backed by the canonical Rust core (`crates/client` + `crates/audren-circuits` via `crates/audren-ffi` + UniFFI + JNA) with a zero-panic `Result`/`AudrenFfiException` API across all `46` exports (Bech32m low-order X25519 `view_pk` rejection and `extraWritablePubkeys` on `FfiExecCtxHashParams` / `FfiExecViaEscrowParams`) so Android wallets and JVM backends run native local BN254 Groth16 proving (`17,861` R1CS, 4-ary Depth-20 global MASP, 16-lane-capable architecture) with zero cryptographic re-implementation drift. Verified byte-for-byte against [`spec/test-vectors.json`](../../spec/test-vectors.json) on every CI run.

## Core Building Blocks

1. **Keys & Compliance** — `deriveKeysFromSeed`, `deriveSubaccountKeys`, `exportFullViewingKey`, `deriveDefiSessionKeypair` (pseudonymous session keypair for stateful public DeFi), `decodeAudrenAddress`, `deriveAssetIdBytes`
2. **PDAs & Zero-Copy Decoders** — `derivePoolPda`, `deriveVaultAuthPda`, `deriveLanePda`, `deriveLaneRentPda`, `deriveSubtreePda`, `deriveSubrootPda`, `deriveMemoPda`, `deriveNfPagePda`, `deriveCheckpointPda`, `deriveNullifierPda`, `deriveEscrowPda`, `deriveUnwrapPda`, `deriveAta`, `decodePoolStateAccount`, `decodeLaneHeaderAccount`, `decodeRootCheckpointAccount`
3. **Wallet Store Schema & Memos** — `encryptNoteMemo`, `prepareDynamicSwapMemo`, `checkMemoViewTag`, `decryptAndVerifyMemoEntry`, `verifySelectiveDisclosureProof`, `compactStoreNewJson` (initializes the canonical `CompactWalletStore` JSON schema; pair with ordinary Solana RPC `getMultipleAccounts` page fetches)
4. **Local BN254 Groth16 Prover & Builders** — `proveJoinsplitWitnessBytes` (proves canonical `4,611 B` binary witnesses into `192 B` Groth16 proofs), `computeTransactCtxHashFfi`, `computeExecCtxHashFfi`, `deterministicNoteRentFeeFfi`, `computePageRolloversFfi`, `buildInitPoolIx`, `buildInitLaneIx`, `buildOpenPageIx`, `buildDepositIx`, `buildPublishCheckpointIx`, `buildTransactIx`, `buildExecViaEscrowIx`, `buildSetPausedIx`, `buildUpdatePoolIx`
5. **Relayer & Escrow CPI** — `canonicalProgramId`, `protocolVersion`, `defaultRelayUrl`, `jupiterCpiExcludedDexes`

## Build & Run Conformance Tests Locally

```bash
# 1. Build native Rust FFI library & refresh Kotlin bindings (from repo root)
./scripts/build-mobile-sdks.sh bindings

# 2. Run full Kotlin conformance & Groth16 prover suite (requires JDK 21)
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
val fvk = exportFullViewingKey(seed)
val pool = derivePoolPda(canonicalProgramId(), 0u)
val storeJson = compactStoreNewJson(0u, 0uL)
```
