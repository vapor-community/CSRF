// swift-tools-version:3.1

import PackageDescription

let package = Package(
    name: "CSRF",
    dependencies: [
        .Package(url: "https://github.com/vapor/vapor.git", majorVersion: 2),
        .Package(url: "https://github.com/vapor/json.git", majorVersion: 2),
        .Package(url: "https://github.com/nodes-vapor/flash", majorVersion: 1),
    ]
)
