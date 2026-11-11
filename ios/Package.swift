// swift-tools-version: 6.0
// The Warden iPhone app (M8). Built by xtool on the Forgejo `ios` runner (ship.sh); no Xcode files.
// Products: the app (`Warden`) and its notification content extension (`WardenNotify`); both use
// `WardenKit` (iOS-only: Secure Enclave key, keychain, SwiftUI pieces) on top of the Foundation-only
// `WardenCore` package, which `swift test` covers on Linux.
import PackageDescription

let package = Package(
    name: "Warden",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "Warden", targets: ["Warden"]),
        .library(name: "WardenNotify", targets: ["WardenNotify"]),
    ],
    dependencies: [
        .package(path: "Packages/WardenCore"),
    ],
    targets: [
        .target(name: "WardenKit", dependencies: [.product(name: "WardenCore", package: "WardenCore")]),
        .target(name: "Warden", dependencies: ["WardenKit"]),
        .target(name: "WardenNotify", dependencies: ["WardenKit"]),
    ],
    swiftLanguageModes: [.v5]
)
