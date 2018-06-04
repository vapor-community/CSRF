// swift-tools-version:4.0

import PackageDescription

let package = Package(
    name: "CSRF",
    products: [
        .library(name: "CSRF", targets: ["CSRF"])
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "3.0.0")
    ],
    targets: [
        .target(name: "CSRF", dependencies: ["Vapor"], path: "./Sources"),
        .testTarget(name: "CSRFTests", dependencies: ["CSRF", "Vapor"])
    ]
)
