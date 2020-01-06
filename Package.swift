// swift-tools-version:5.1

import PackageDescription

let package = Package(
    name: "CSRF",
    platforms: [
       .macOS(.v10_14)
    ],
    products: [
        .library(name: "CSRF", targets: ["CSRF"])
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.0.0-beta.2"),
        .package(url: "https://github.com/vapor/open-crypto.git", from: "4.0.0-beta.2")
    ],
    targets: [
        .target(name: "CSRF", dependencies: ["Vapor", "OpenCrypto"], path: "./Sources"),
        .testTarget(name: "CSRFTests", dependencies: ["CSRF", "Vapor"])
    ]
)
