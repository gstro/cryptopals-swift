// swift-tools-version:3.1

import PackageDescription

let package = Package(
    name: "cryptopals",
    dependencies: [
        .Package(url: "https://github.com/IBM-Swift/BlueCryptor.git", majorVersion: 0),
        .Package(url: "https://github.com/JohnSundell/Files.git", majorVersion: 1, minor: 8),
        .Package(url: "https://github.com/SwifterSwift/SwifterSwift.git", majorVersion: 1),
        .Package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", majorVersion: 0)
    ]
)
