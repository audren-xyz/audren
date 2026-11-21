#!/usr/bin/env bash
set -euo pipefail

# Build native `audren-ffi` library and regenerate Swift (iOS/macOS) & Kotlin (Android/JVM)
# bindings from the single Rust `audren-client` core via UniFFI.
#
# Usage:
#   ./scripts/build-mobile-sdks.sh bindings     # Build host release lib + regenerate Swift & Kotlin bindings
#   ./scripts/build-mobile-sdks.sh ios          # Build universal AudrenFFI.xcframework (iOS device + simulator + macOS)
#   ./scripts/build-mobile-sdks.sh android      # Build Android jniLibs/{arm64-v8a,armeabi-v7a,x86_64}/libaudren_ffi.so

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CMD="${1:-bindings}"

host_lib_ext() {
  case "$(uname -s)" in
    Darwin) echo "dylib" ;;
    Linux)  echo "so" ;;
    *)      echo "dll" ;;
  esac
}

case "$CMD" in
  bindings)
    echo "==> Building audren-ffi (release)..."
    cargo build -p audren-ffi --release

    EXT="$(host_lib_ext)"
    LIB="target/release/libaudren_ffi.${EXT}"
    TMP_SWIFT="$(mktemp -d)"
    trap 'rm -rf "$TMP_SWIFT"' EXIT

    echo "==> Generating Swift bindings..."
    cargo run -p audren-ffi --features bindgen-cli --bin uniffi-bindgen -- \
      generate --library "$LIB" \
      --language swift \
      --no-format \
      --out-dir "$TMP_SWIFT"

    mkdir -p packages/swift/Sources/AudrenSDK packages/swift/Sources/AudrenFFI/include
    cp "$TMP_SWIFT/AudrenSDK.swift" packages/swift/Sources/AudrenSDK/AudrenSDK.swift
    cp "$TMP_SWIFT/audren_ffiFFI.h" packages/swift/Sources/AudrenFFI/include/audren_ffiFFI.h
    cp "$TMP_SWIFT/audren_ffiFFI.modulemap" packages/swift/Sources/AudrenFFI/include/module.modulemap

    echo "==> Generating Kotlin bindings..."
    mkdir -p packages/kotlin/src/main/kotlin
    cargo run -p audren-ffi --features bindgen-cli --bin uniffi-bindgen -- \
      generate --library "$LIB" \
      --language kotlin \
      --no-format \
      --out-dir packages/kotlin/src/main/kotlin

    echo "==> Done! Swift -> packages/swift/, Kotlin -> packages/kotlin/"
    ;;

  ios)
    echo "==> Building Apple staticlibs (aarch64-apple-ios, aarch64-apple-ios-sim, x86_64-apple-ios)..."
    cargo build -p audren-ffi --release --target aarch64-apple-ios
    cargo build -p audren-ffi --release --target aarch64-apple-ios-sim
    cargo build -p audren-ffi --release --target x86_64-apple-ios

    SIM_DIR="target/ios-sim-universal"
    mkdir -p "$SIM_DIR"
    lipo -create \
      target/aarch64-apple-ios-sim/release/libaudren_ffi.a \
      target/x86_64-apple-ios/release/libaudren_ffi.a \
      -output "$SIM_DIR/libaudren_ffi.a"

    OUT_XC="packages/swift/AudrenFFI.xcframework"
    rm -rf "$OUT_XC"
    xcodebuild -create-xcframework \
      -library target/aarch64-apple-ios/release/libaudren_ffi.a \
      -headers packages/swift/Sources/AudrenFFI/include \
      -library "$SIM_DIR/libaudren_ffi.a" \
      -headers packages/swift/Sources/AudrenFFI/include \
      -output "$OUT_XC"

    echo "==> Built $OUT_XC"
    ;;

  android)
    if ! command -v cargo-ndk >/dev/null 2>&1; then
      echo "error: cargo-ndk is required (install via 'cargo install cargo-ndk')" >&2
      exit 1
    fi
    OUT_JNI="packages/kotlin/src/main/jniLibs"
    mkdir -p "$OUT_JNI"
    echo "==> Building Android jniLibs (arm64-v8a, armeabi-v7a, x86_64)..."
    cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o "$OUT_JNI" \
      build -p audren-ffi --release
    echo "==> Built Android shared libraries under $OUT_JNI"
    ;;

  *)
    echo "Usage: $0 {bindings|ios|android}" >&2
    exit 1
    ;;
esac
