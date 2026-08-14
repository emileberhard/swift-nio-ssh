//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import NIOCore
import NIOFoundationCompat
import XCTest
import _CryptoExtras

@testable import NIOSSH

final class HostKeyTests: XCTestCase {
    /// A single 2048-bit RSA key shared by the RSA tests: generating one costs real time, and none of these
    /// tests depend on the key being fresh.
    private static let sharedRSAKey = try! _RSA.Signing.PrivateKey(keySize: .bits2048)

    func testBasicEd25519SigningFlow() throws {
        let edKey = Curve25519.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(ed25519Key: edKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        // Naturally, this should verify.
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testBasicECDSAP256SigningFlow() throws {
        let ecdsaKey = P256.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(p256Key: ecdsaKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        // Naturally, this should verify.
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testBasicECDSAP384SigningFlow() throws {
        let ecdsaKey = P384.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(p384Key: ecdsaKey)

        let digest = SHA384.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        // Naturally, this should verify.
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testBasicECDSAP521SigningFlow() throws {
        let ecdsaKey = P521.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(p521Key: ecdsaKey)

        let digest = SHA512.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        // Naturally, this should verify.
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    private func assertRSASigningFlow(algorithm: Substring?, expectedWireName: String) throws {
        let sshKey = try assertNoThrowWithValue(NIOSSHPrivateKey(rsaKey: Self.sharedRSAKey))

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest, algorithm: algorithm))
        XCTAssertEqual(String(signature.signatureAlgorithmName), expectedWireName)

        // Naturally, this should verify.
        XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: digest))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        // The wire form is `string algorithm-name` then `string signature-blob`, and the blob is exactly as
        // wide as the modulus: no mpint padding.
        var wireCopy = buffer
        XCTAssertEqual(wireCopy.readSSHString().map { String(buffer: $0) }, expectedWireName)
        XCTAssertEqual(wireCopy.readSSHString()?.readableBytes, 256)
        XCTAssertEqual(wireCopy.readableBytes, 0)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertEqual(newSignature, signature)
        XCTAssertTrue(sshKey.publicKey.isValidSignature(newSignature, for: digest))
    }

    func testBasicRSASigningFlowSHA512() throws {
        // No algorithm means the key's preferred algorithm, which is the strongest one.
        try self.assertRSASigningFlow(algorithm: nil, expectedWireName: "rsa-sha2-512")
        try self.assertRSASigningFlow(algorithm: "rsa-sha2-512", expectedWireName: "rsa-sha2-512")
    }

    func testBasicRSASigningFlowSHA256() throws {
        try self.assertRSASigningFlow(algorithm: "rsa-sha2-256", expectedWireName: "rsa-sha2-256")
    }

    func testBasicRSASigningFlowSHA1() throws {
        try self.assertRSASigningFlow(algorithm: "ssh-rsa", expectedWireName: "ssh-rsa")
    }

    func testRSASigningFlowOverUserAuthPayload() throws {
        let sshKey = try assertNoThrowWithValue(NIOSSHPrivateKey(rsaKey: Self.sharedRSAKey))
        var sessionIdentifier = ByteBufferAllocator().buffer(capacity: 32)
        sessionIdentifier.writeString("hello, world!")
        let payload = UserAuthSignablePayload(
            sessionIdentifier: sessionIdentifier,
            userName: "user",
            serviceName: "ssh-connection",
            publicKey: sshKey.publicKey
        )

        for algorithm in sshKey.signatureAlgorithms {
            let signature = try assertNoThrowWithValue(sshKey.sign(payload, algorithm: algorithm[...]))
            XCTAssertEqual(String(signature.signatureAlgorithmName), algorithm)
            XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: payload))
        }
    }

    func testRSAFailsVerificationWithDifferentKeys() throws {
        let sshKey = try assertNoThrowWithValue(NIOSSHPrivateKey(rsaKey: Self.sharedRSAKey))
        let otherSSHKey = try assertNoThrowWithValue(
            NIOSSHPrivateKey(rsaKey: _RSA.Signing.PrivateKey(keySize: .bits2048))
        )

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest))

        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest))
    }

    func testRSASignatureFlavorMismatchFailsVerification() throws {
        // The flavor travels with the signature, and it is what selects the verification hash. Claiming a
        // different flavor for the same bytes must not verify: otherwise a peer could downgrade us to SHA-1
        // just by relabelling.
        let sshKey = try assertNoThrowWithValue(NIOSSHPrivateKey(rsaKey: Self.sharedRSAKey))

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest, algorithm: "rsa-sha2-512"))

        guard case .rsa(_, let rawSignature) = signature.backingSignature else {
            XCTFail("Expected an RSA signature")
            return
        }

        for flavor in [RSASignatureFlavor.sha256, .sha1] {
            let relabelled = NIOSSHSignature(backingSignature: .rsa(flavor: flavor, signature: rawSignature))
            XCTAssertFalse(
                sshKey.publicKey.isValidSignature(relabelled, for: digest),
                "\(String(flavor.wireName)) must not verify a SHA-512 signature"
            )
        }
    }

    func testRSARejectsUnsupportedSignatureAlgorithm() throws {
        let sshKey = try assertNoThrowWithValue(NIOSSHPrivateKey(rsaKey: Self.sharedRSAKey))
        let digest = SHA256.hash(data: Array("hello, world!".utf8))

        // `rsa-sha2-384` is not an SSH signature algorithm, and `_RSA` would trap on an unexpected digest, so
        // this has to be rejected before it reaches the crypto layer.
        XCTAssertThrowsError(try sshKey.sign(digest: digest, algorithm: "rsa-sha2-384")) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .unknownSignature)
        }
    }

    func testNonRSAKeysRejectForeignSignatureAlgorithms() throws {
        let sshKey = NIOSSHPrivateKey(ed25519Key: .init())
        let digest = SHA256.hash(data: Array("hello, world!".utf8))

        XCTAssertThrowsError(try sshKey.sign(digest: digest, algorithm: "rsa-sha2-512")) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .unknownSignature)
        }
        XCTAssertNoThrow(try sshKey.sign(digest: digest, algorithm: "ssh-ed25519"))
    }

    func testSignatureAlgorithmsMatchKeyType() throws {
        XCTAssertEqual(
            try NIOSSHPrivateKey(rsaKey: Self.sharedRSAKey).signatureAlgorithms,
            ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]
        )
        XCTAssertEqual(NIOSSHPrivateKey(ed25519Key: .init()).signatureAlgorithms, ["ssh-ed25519"])
        XCTAssertEqual(NIOSSHPrivateKey(p256Key: .init()).signatureAlgorithms, ["ecdsa-sha2-nistp256"])
        XCTAssertEqual(NIOSSHPrivateKey(p384Key: .init()).signatureAlgorithms, ["ecdsa-sha2-nistp384"])
        XCTAssertEqual(NIOSSHPrivateKey(p521Key: .init()).signatureAlgorithms, ["ecdsa-sha2-nistp521"])
    }

    func testRSAPublicKeyRoundTripsFromPrivateKey() throws {
        let sshKey = try assertNoThrowWithValue(NIOSSHPrivateKey(rsaKey: Self.sharedRSAKey))

        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHHostKey(sshKey.publicKey)

        let recovered = try assertNoThrowWithValue(buffer.readSSHHostKey()!)
        XCTAssertEqual(recovered, sshKey.publicKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))
        XCTAssertTrue(recovered.isValidSignature(signature, for: digest))
    }

    func testEd25519FailsVerificationWithDifferentKeys() throws {
        let edKey = Curve25519.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(ed25519Key: edKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHPrivateKey(ed25519Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testECDASP256FailsVerificationWithDifferentKeys() throws {
        let ecdsaKey = P256.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(p256Key: ecdsaKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHPrivateKey(p256Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testECDASP384FailsVerificationWithDifferentKeys() throws {
        let ecdsaKey = P384.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(p384Key: ecdsaKey)

        let digest = SHA384.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHPrivateKey(p384Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testECDASP521FailsVerificationWithDifferentKeys() throws {
        let ecdsaKey = P521.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(p521Key: ecdsaKey)

        let digest = SHA512.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHPrivateKey(p521Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testEd25519FailsVerificationWithWrongAlgorithms() throws {
        let edKey = Curve25519.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(ed25519Key: edKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHPrivateKey(p256Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testECDASP256FailsVerificationWithWrongAlgorithms() throws {
        let ecdsaKey = P256.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(p256Key: ecdsaKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHPrivateKey(ed25519Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testECDASP384FailsVerificationWithWrongAlgorithms() throws {
        let ecdsaKey = P384.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(p384Key: ecdsaKey)

        let digest = SHA384.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHPrivateKey(ed25519Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testECDASP521FailsVerificationWithWrongAlgorithms() throws {
        let ecdsaKey = P521.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(p521Key: ecdsaKey)

        let digest = SHA512.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHPrivateKey(ed25519Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testUnrecognisedKey() throws {
        // `ssh-rsa` used to stand in here, but this fork supports it. DSA never will.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHString("ssh-dss".utf8)

        XCTAssertThrowsError(try buffer.readSSHHostKey()) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .unknownPublicKey)
        }
    }

    func testInvalidDomainParametersForECDSAP256() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHString("ecdsa-sha2-nistp256".utf8)
        buffer.writeSSHString("nistp384".utf8)  // Surprise!

        XCTAssertThrowsError(try buffer.readSSHHostKey()) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidDomainParametersForKey)
        }
    }

    func testInvalidDomainParametersForECDSAP384() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHString("ecdsa-sha2-nistp384".utf8)
        buffer.writeSSHString("nistp256".utf8)  // Surprise!

        XCTAssertThrowsError(try buffer.readSSHHostKey()) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidDomainParametersForKey)
        }
    }

    func testInvalidDomainParametersForECDSAP521() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHString("ecdsa-sha2-nistp521".utf8)
        buffer.writeSSHString("nistp384".utf8)  // Surprise!

        XCTAssertThrowsError(try buffer.readSSHHostKey()) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidDomainParametersForKey)
        }
    }

    func testUnrecognisedSignature() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        // `ssh-rsa` used to stand in here, but this fork supports it. DSA never will.
        buffer.writeSSHString("ssh-dss".utf8)

        XCTAssertThrowsError(try buffer.readSSHSignature()) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .unknownSignature)
        }
    }

    func testLoadingEd25519KeyFromFileRoundTrips() throws {
        let keyData =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJfkNV4OS33ImTXvorZr72q4v5XhVEQKfvqsxOEJ/XaR lukasa@MacBook-Pro.local"
        XCTAssertNoThrow(
            try self.roundTripKey(keyData: keyData, label: "ssh-ed25519", comment: " lukasa@MacBook-Pro.local")
        )
    }

    func testLoadingP256KeyFromFileRoundTrips() throws {
        let keyData =
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIZS1APJofiPeoATC/VC4kKi7xRPdz934nSkFLTc0whYi3A8hEKHAOX9edgL1UWxRqRGQZq2wvvAIjAO9kCeiQA= lukasa@MacBook-Pro.local"
        XCTAssertNoThrow(
            try self.roundTripKey(keyData: keyData, label: "ecdsa-sha2-nistp256", comment: " lukasa@MacBook-Pro.local")
        )
    }

    func testLoadingP384KeyFromFileRoundTrips() throws {
        let keyData =
            "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBJPOgAXHijSxoZBiyhSDOR3eUELUoc+hqh/SY1Wq4/562jThf6Q+tjVzZTMWZMAP4S6DD2qZswsRvisxXkcZDOw5bvyk0WmezYvjUP6TZII/0BDVTotCf4SxukEtcqBZqg== lukasa@MacBook-Pro.local"
        XCTAssertNoThrow(
            try self.roundTripKey(keyData: keyData, label: "ecdsa-sha2-nistp384", comment: " lukasa@MacBook-Pro.local")
        )
    }

    func testLoadingP521KeyFromFileRoundTrips() throws {
        let keyData =
            "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBACkfM3aZf9sgjAkncWtK6A295sdghn1GG1BKJ+hQfD2VBIJxSQDnPOocNIQQZEo3zs1kvwUXOIgWANJqbOiv77tCACxWRRYmAvM3hzgcEOhPROROG+KGvuDAWW6ZuCkaW0QnseR7Yn0+q/+/jai3tNNDWrbVLDesDj5Aq5xq1yrKDHGEA== lukasa@MacBook-Pro.local"
        XCTAssertNoThrow(
            try self.roundTripKey(keyData: keyData, label: "ecdsa-sha2-nistp521", comment: " lukasa@MacBook-Pro.local")
        )
    }

    func testMissingCommentIsTolerated() throws {
        let keyData = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJfkNV4OS33ImTXvorZr72q4v5XhVEQKfvqsxOEJ/XaR"
        XCTAssertNoThrow(try self.roundTripKey(keyData: keyData, label: "ssh-ed25519", comment: ""))
    }

    func testDripFeedingKey() throws {
        let keyData = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJfkNV4OS33ImTXvorZr72q4v5XhVEQKfvqsxOEJ/XaR"
        for index in keyData.indices.dropLast() {
            XCTAssertThrowsError(try NIOSSHPublicKey(openSSHPublicKey: String(keyData[..<index]))) { error in
                XCTAssertEqual((error as? NIOSSHError)?.type, .invalidOpenSSHPublicKey)
            }
        }
    }

    func testKeyLiesAboutItsType() throws {
        // Secretly P384
        let keyData =
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBJPOgAXHijSxoZBiyhSDOR3eUELUoc+hqh/SY1Wq4/562jThf6Q+tjVzZTMWZMAP4S6DD2qZswsRvisxXkcZDOw5bvyk0WmezYvjUP6TZII/0BDVTotCf4SxukEtcqBZqg== lukasa@MacBook-Pro.local"
        XCTAssertThrowsError(try NIOSSHPublicKey(openSSHPublicKey: keyData)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidOpenSSHPublicKey)
        }
    }

    private func roundTripKey(keyData: String, label: String, comment: String) throws {
        let key = try assertNoThrowWithValue(NIOSSHPublicKey(openSSHPublicKey: keyData))
        var keyBuffer = ByteBufferAllocator().buffer(capacity: 1024)
        keyBuffer.writeSSHHostKey(key)
        let expectedKeyData =
            "\(label) \(keyBuffer.readData(length: keyBuffer.readableBytes)!.base64EncodedString())\(comment)"
        XCTAssertEqual(keyData, expectedKeyData)
    }
}
