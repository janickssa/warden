// swift-tools-version: 6.0
// WardenCore: everything in the iPhone app that isn't UI. Foundation (+ swift-crypto for SHA-256/P-256 on
// Linux; on iOS it re-exports CryptoKit), so `swift test` runs on the Linux runner.
import PackageDescription

let package = Package(
    name: "WardenCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "WardenCore", targets: ["WardenCore"])],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "5.0.3"),
    ],
    targets: [
        .target(name: "WardenCore", dependencies: [.product(name: "Crypto", package: "swift-crypto")]),
        .testTarget(name: "WardenCoreTests", dependencies: ["WardenCore"]),
    ]
)
