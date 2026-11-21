// swift-tools-version: 5.10
import Foundation
import PackageDescription

// Resolve the compiled native `libaudren_ffi` directory.
// - During local monorepo development / CI: `../../target/release`
// - Override via `AUDREN_FFI_LIB_DIR=/path/to/lib` when linking custom builds
// - For iOS App Store distribution, build `AudrenFFI.xcframework` via `scripts/build-mobile-sdks.sh`.
let packageDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let defaultLibDir = packageDir
    .appendingPathComponent("../../target/release")
    .standardizedFileURL.path
let ffiLibDir = ProcessInfo.processInfo.environment["AUDREN_FFI_LIB_DIR"] ?? defaultLibDir

let package = Package(
    name: "AudrenSDK",
    platforms: [
        .iOS(.v15),
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "AudrenSDK",
            targets: ["AudrenSDK"]
        ),
    ],
    targets: [
        .target(
            name: "AudrenFFI",
            path: "Sources/AudrenFFI",
            publicHeadersPath: "include"
        ),
        .target(
            name: "AudrenSDK",
            dependencies: ["AudrenFFI"],
            path: "Sources/AudrenSDK",
            linkerSettings: [
                .unsafeFlags([
                    "-L\(ffiLibDir)",
                    "-laudren_ffi",
                    "-Xlinker", "-rpath", "-Xlinker", ffiLibDir,
                ]),
            ]
        ),
        .testTarget(
            name: "AudrenSDKTests",
            dependencies: ["AudrenSDK"],
            path: "Tests/AudrenSDKTests"
        ),
    ]
)
