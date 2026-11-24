# `AudrenSDK` — Audren Swift SDK (iOS & macOS)

Native Swift Package for **Audren** (`AUDRBK6kVkQoEGm3EB7swd34SUPqrHZeNEkB5vZWVSv3`), targeting **iOS 15+** and **macOS 13+**.

Backed by the canonical Rust core (`crates/client` + `crates/audren-circuits` via `crates/audren-ffi` + UniFFI) with a zero-panic `Result`/`throws` API across all `52` exports (typed `AudrenFfiError`, Bech32m low-order X25519 `view_pk` rejection, and `extraWritablePubkeys` on `FfiExecCtxHashParams` / `FfiExecViaEscrowParams`) so mobile apps run native local BN254 Groth16 proving (`17,861` R1CS, 4-ary Depth-20 global MASP, 16-lane-capable architecture) with zero cryptographic re-implementation drift. Verified byte-for-byte against [`spec/test-vectors.json`](../../spec/test-vectors.json) on every CI run.

## Core Building Blocks

1. **Keys & Compliance** — `deriveKeysFromSeed`, `deriveSubaccountKeys`, `exportFullViewingKey`, `deriveDefiSessionKeypair` (pseudonymous session keypair for stateful public DeFi), `decodeAudrenAddress`, `deriveAssetIdBytes`
2. **PDAs, Zero-Copy Decoders & Snapshot Selection** — `derivePoolPda`, `deriveVaultAuthPda`, `deriveLanePda`, `deriveLaneRentPda`, `deriveSubtreePda`, `deriveSubrootPda`, `deriveMemoPda`, `deriveNfPagePda`, `deriveRootsPda`, `deriveNullifierPda`, `deriveEscrowPda`, `deriveUnwrapPda`, `deriveAta`, `decodePoolStateAccount`, `decodeLaneHeaderAccount`, `decodeGlobalRootHistoryAccount`, `selectRootSnapshotForNotes`
3. **Wallet Store Schema & Memos** — `encryptNoteMemo`, `prepareDynamicSwapMemo`, `checkMemoViewTag`, `decryptAndVerifyMemoEntry`, `verifySelectiveDisclosureProof`, `compactStoreNewJson` (initializes the canonical `CompactWalletStore` JSON schema; pair with ordinary Solana RPC `getMultipleAccounts` page fetches)
4. **Local BN254 Groth16 Prover, Auto-OpenPage & Builders** — `proveJoinsplitWitnessBytes` (proves canonical `4,611 B` binary witnesses into `192 B` Groth16 proofs), `computeTransactCtxHashFfi`, `computeExecCtxHashFfi`, `deterministicNoteRentFeeFfi`, `computePageRolloversFfi`, `planAutoOpenPages`, `recommendedCuLimitOpenPage`, `recommendedCuLimitDeposit`, `recommendedCuLimitTransact`, `recommendedCuLimitExecViaEscrow`, `buildInitPoolIx`, `buildInitLaneIx`, `buildOpenPageIx`, `buildDepositIx`, `buildInitRootHistoryIx`, `buildTransactIx`, `buildExecViaEscrowIx`, `buildSetPausedIx`, `buildUpdatePoolIx`
5. **Relayer & Escrow CPI** — `canonicalProgramId`, `protocolVersion`, `defaultRelayUrl`, `jupiterCpiExcludedDexes`

## Build & Run Conformance Tests Locally

```bash
# 1. Build native Rust FFI library & refresh Swift bindings (from repo root)
./scripts/build-mobile-sdks.sh bindings

# 2. Run full Swift conformance & Groth16 prover suite
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
let alice = try deriveKeysFromSeed(seed: seed)
let sub1 = try deriveSubaccountKeys(seed: seed, accountIndex: 1)
let fvk = try exportFullViewingKey(seed: seed)
let pool = try derivePoolPda(programId: canonicalProgramId(), poolId: 0)
let storeJson = try compactStoreNewJson(poolId: 0, birthdaySlot: 0)
```
