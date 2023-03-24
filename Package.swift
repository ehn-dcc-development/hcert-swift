// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "hcert",
    platforms: [
        .iOS(.v14),
        .macOS(.v11)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "hcert",
            targets: ["hcert"])
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        .package(url: "git@github.com:unrelentingtech/SwiftCBOR.git", .branch("master")),
        .package(url: "https://github.com/ehn-digital-green-development/base45-swift", .branch("main"))
    ],
    
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "hcert",
            dependencies: [
                "base45-swift",
                .product(name: "SwiftCBOR", package: "SwiftCBOR")
            ]),
        .testTarget(
            name: "hcertTests",
            dependencies: ["hcert"])
    ]
)
