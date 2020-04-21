// swift-tools-version:5.2
import PackageDescription

let package = Package(
    name: "CSRF",
    platforms: [
       .macOS(.v10_15),
    ],
    products: [
        .library(name: "CSRF", targets: ["CSRF"]),
    ],
    dependencies: [
        // 💧 A server-side Swift web framework.
        .package(url: "https://github.com/vapor/vapor.git", from: "4.0.0-rc.1"),
    ],
    targets: [
        .target(name: "CSRF", dependencies: [
            .product(name: "Vapor", package: "vapor"),
        ]),
    ]
)
