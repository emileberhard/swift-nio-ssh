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
import XCTest

@testable import NIOSSH

final class KeyExchangeTests: XCTestCase {
    private func keyExchangeAgreed(_ first: KeyExchangeResult, _ second: KeyExchangeResult) {
        XCTAssertEqual(first.sessionID, second.sessionID)
        XCTAssertEqual(first.keys.initialInboundIV, second.keys.initialOutboundIV)
        XCTAssertEqual(first.keys.initialOutboundIV, second.keys.initialInboundIV)
        XCTAssertEqual(first.keys.inboundEncryptionKey, second.keys.outboundEncryptionKey)
        XCTAssertEqual(first.keys.outboundEncryptionKey, second.keys.inboundEncryptionKey)
        XCTAssertEqual(first.keys.inboundMACKey, second.keys.outboundMACKey)
        XCTAssertEqual(first.keys.outboundMACKey, second.keys.inboundMACKey)
    }

    private func keyExchangeFailed(_ first: KeyExchangeResult, _ second: KeyExchangeResult) {
        // If key exchange fails, we assert that no secrets match. This is a slightly excessive test, but it'll probably be fine.
        XCTAssertNotEqual(first.sessionID, second.sessionID)
        XCTAssertNotEqual(first.keys.initialInboundIV, second.keys.initialOutboundIV)
        XCTAssertNotEqual(first.keys.initialOutboundIV, second.keys.initialInboundIV)
        XCTAssertNotEqual(first.keys.inboundEncryptionKey, second.keys.outboundEncryptionKey)
        XCTAssertNotEqual(first.keys.outboundEncryptionKey, second.keys.inboundEncryptionKey)
        XCTAssertNotEqual(first.keys.inboundMACKey, second.keys.outboundMACKey)
        XCTAssertNotEqual(first.keys.outboundMACKey, second.keys.inboundMACKey)
    }

    func testBasicSuccessfulKeyExchangeNoPreviousSessionCurve25519() throws {
        try self.basicSuccessfulKeyExchangeNoPreviousSession(Curve25519.KeyAgreement.PrivateKey.self)
    }

    func testBasicSuccessfulKeyExchangeNoPreviousSessionP256() throws {
        try self.basicSuccessfulKeyExchangeNoPreviousSession(P256.KeyAgreement.PrivateKey.self)
    }

    func testBasicSuccessfulKeyExchangeNoPreviousSessionP384() throws {
        try self.basicSuccessfulKeyExchangeNoPreviousSession(P384.KeyAgreement.PrivateKey.self)
    }

    func testBasicSuccessfulKeyExchangeNoPreviousSessionP521() throws {
        try self.basicSuccessfulKeyExchangeNoPreviousSession(P521.KeyAgreement.PrivateKey.self)
    }

    private func basicSuccessfulKeyExchangeNoPreviousSession<KeyType: ECDHCompatiblePrivateKey>(
        _: KeyType.Type = KeyType.self
    ) throws {
        var server = EllipticCurveKeyExchange<KeyType>(
            ourRole: .server([.init(ed25519Key: .init())]),
            previousSessionIdentifier: nil
        )
        var client = EllipticCurveKeyExchange<KeyType>(ourRole: .client, previousSessionIdentifier: nil)
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 1024)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        let (serverKeys, serverResponse) = try assertNoThrowWithValue(
            try server.completeKeyExchangeServerSide(
                clientKeyExchangeMessage: clientMessage,
                serverHostKey: serverHostKey,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        )

        initialExchangeBytes.clear()

        let clientKeys = try assertNoThrowWithValue(
            try client.receiveServerKeyExchangePayload(
                serverKeyExchangeMessage: serverResponse,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        )

        // Check we agree on the session ID and the keys.
        self.keyExchangeAgreed(serverKeys, clientKeys)
    }

    func testBasicSuccessfulKeyExchangeWithPreviousSessionCurve25519() throws {
        try self.basicSuccessfulKeyExchangeWithPreviousSession(Curve25519.KeyAgreement.PrivateKey.self)
    }

    func testBasicSuccessfulKeyExchangeWithPreviousSessionP256() throws {
        try self.basicSuccessfulKeyExchangeWithPreviousSession(P256.KeyAgreement.PrivateKey.self)
    }

    func testBasicSuccessfulKeyExchangeWithPreviousSessionP384() throws {
        try self.basicSuccessfulKeyExchangeWithPreviousSession(P384.KeyAgreement.PrivateKey.self)
    }

    func testBasicSuccessfulKeyExchangeWithPreviousSessionP521() throws {
        try self.basicSuccessfulKeyExchangeWithPreviousSession(P521.KeyAgreement.PrivateKey.self)
    }

    func basicSuccessfulKeyExchangeWithPreviousSession<KeyType: ECDHCompatiblePrivateKey>(
        _: KeyType.Type = KeyType.self
    ) throws {
        var previousSessionIdentifier = ByteBufferAllocator().buffer(capacity: 1024)
        previousSessionIdentifier.writeBytes(0...255)

        var server = EllipticCurveKeyExchange<KeyType>(
            ourRole: .server([.init(ed25519Key: .init())]),
            previousSessionIdentifier: previousSessionIdentifier
        )
        var client = EllipticCurveKeyExchange<KeyType>(
            ourRole: .client,
            previousSessionIdentifier: previousSessionIdentifier
        )
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 1024)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        let (serverKeys, serverResponse) = try assertNoThrowWithValue(
            try server.completeKeyExchangeServerSide(
                clientKeyExchangeMessage: clientMessage,
                serverHostKey: serverHostKey,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        )

        initialExchangeBytes.clear()

        let clientKeys = try assertNoThrowWithValue(
            try client.receiveServerKeyExchangePayload(
                serverKeyExchangeMessage: serverResponse,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        )

        // Check we agree on the session ID and the keys.
        self.keyExchangeAgreed(serverKeys, clientKeys)
    }

    func testKeyExchangeWithECDSAP256Signatures() throws {
        var server = EllipticCurveKeyExchange<Curve25519.KeyAgreement.PrivateKey>(
            ourRole: .server([.init(ed25519Key: .init())]),
            previousSessionIdentifier: nil
        )
        var client = EllipticCurveKeyExchange<Curve25519.KeyAgreement.PrivateKey>(
            ourRole: .client,
            previousSessionIdentifier: nil
        )
        let serverHostKey = NIOSSHPrivateKey(p256Key: .init())

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 1024)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        let (serverKeys, serverResponse) = try assertNoThrowWithValue(
            try server.completeKeyExchangeServerSide(
                clientKeyExchangeMessage: clientMessage,
                serverHostKey: serverHostKey,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        )

        initialExchangeBytes.clear()

        let clientKeys = try assertNoThrowWithValue(
            try client.receiveServerKeyExchangePayload(
                serverKeyExchangeMessage: serverResponse,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        )

        // Check we agree on the session ID and the keys.
        self.keyExchangeAgreed(serverKeys, clientKeys)
    }

    func testKeyExchangeWithECDSAP384Signatures() throws {
        var server = EllipticCurveKeyExchange<Curve25519.KeyAgreement.PrivateKey>(
            ourRole: .server([.init(ed25519Key: .init())]),
            previousSessionIdentifier: nil
        )
        var client = EllipticCurveKeyExchange<Curve25519.KeyAgreement.PrivateKey>(
            ourRole: .client,
            previousSessionIdentifier: nil
        )
        let serverHostKey = NIOSSHPrivateKey(p384Key: .init())

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 1024)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        let (serverKeys, serverResponse) = try assertNoThrowWithValue(
            try server.completeKeyExchangeServerSide(
                clientKeyExchangeMessage: clientMessage,
                serverHostKey: serverHostKey,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        )

        initialExchangeBytes.clear()

        let clientKeys = try assertNoThrowWithValue(
            try client.receiveServerKeyExchangePayload(
                serverKeyExchangeMessage: serverResponse,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        )

        // Check we agree on the session ID and the keys.
        self.keyExchangeAgreed(serverKeys, clientKeys)
    }

    func testKeyExchangeWithECDSAP521Signatures() throws {
        var server = EllipticCurveKeyExchange<Curve25519.KeyAgreement.PrivateKey>(
            ourRole: .server([.init(ed25519Key: .init())]),
            previousSessionIdentifier: nil
        )
        var client = EllipticCurveKeyExchange<Curve25519.KeyAgreement.PrivateKey>(
            ourRole: .client,
            previousSessionIdentifier: nil
        )
        let serverHostKey = NIOSSHPrivateKey(p521Key: .init())

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 1024)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        let (serverKeys, serverResponse) = try assertNoThrowWithValue(
            try server.completeKeyExchangeServerSide(
                clientKeyExchangeMessage: clientMessage,
                serverHostKey: serverHostKey,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        )

        initialExchangeBytes.clear()

        let clientKeys = try assertNoThrowWithValue(
            try client.receiveServerKeyExchangePayload(
                serverKeyExchangeMessage: serverResponse,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        )

        // Check we agree on the session ID and the keys.
        self.keyExchangeAgreed(serverKeys, clientKeys)
    }

    func testBasicSuccessfulKeyExchangeWithWiderKeys() throws {
        var server = EllipticCurveKeyExchange<Curve25519.KeyAgreement.PrivateKey>(
            ourRole: .server([.init(ed25519Key: .init())]),
            previousSessionIdentifier: nil
        )
        var client = EllipticCurveKeyExchange<Curve25519.KeyAgreement.PrivateKey>(
            ourRole: .client,
            previousSessionIdentifier: nil
        )
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 1024)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        let (serverKeys, serverResponse) = try assertNoThrowWithValue(
            try server.completeKeyExchangeServerSide(
                clientKeyExchangeMessage: clientMessage,
                serverHostKey: serverHostKey,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES256GCMOpenSSHTransportProtection.keySizes
            )
        )

        initialExchangeBytes.clear()

        let clientKeys = try assertNoThrowWithValue(
            try client.receiveServerKeyExchangePayload(
                serverKeyExchangeMessage: serverResponse,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES256GCMOpenSSHTransportProtection.keySizes
            )
        )

        // Check we agree on the session ID and the keys.
        self.keyExchangeAgreed(serverKeys, clientKeys)
    }

    func testDisagreeingOnInitialExchangeBytesLeadsToFailedKeyExchange() throws {
        var server = EllipticCurveKeyExchange<Curve25519.KeyAgreement.PrivateKey>(
            ourRole: .server([.init(ed25519Key: .init())]),
            previousSessionIdentifier: nil
        )
        var client = EllipticCurveKeyExchange<Curve25519.KeyAgreement.PrivateKey>(
            ourRole: .client,
            previousSessionIdentifier: nil
        )
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())

        var serverInitialBytes = ByteBufferAllocator().buffer(capacity: 1024)
        var clientInitialBytes = serverInitialBytes

        serverInitialBytes.writeBytes(0..<128)
        clientInitialBytes.writeBytes(1..<129)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        let (_, serverResponse) = try assertNoThrowWithValue(
            try server.completeKeyExchangeServerSide(
                clientKeyExchangeMessage: clientMessage,
                serverHostKey: serverHostKey,
                initialExchangeBytes: &serverInitialBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        )

        XCTAssertThrowsError(
            try client.receiveServerKeyExchangePayload(
                serverKeyExchangeMessage: serverResponse,
                initialExchangeBytes: &clientInitialBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        ) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidExchangeHashSignature)
        }
    }

    func testWeValidateTheExchangeHash() throws {
        var server = EllipticCurveKeyExchange<Curve25519.KeyAgreement.PrivateKey>(
            ourRole: .server([.init(ed25519Key: .init())]),
            previousSessionIdentifier: nil
        )
        var client = EllipticCurveKeyExchange<Curve25519.KeyAgreement.PrivateKey>(
            ourRole: .client,
            previousSessionIdentifier: nil
        )
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 1024)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        var (_, serverResponse) = try assertNoThrowWithValue(
            try server.completeKeyExchangeServerSide(
                clientKeyExchangeMessage: clientMessage,
                serverHostKey: serverHostKey,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        )

        initialExchangeBytes.clear()

        // Ok, the server has sent a signature over the exchange hash. Let's change that signature.
        serverResponse.signature = try assertNoThrowWithValue(
            serverHostKey.sign(digest: SHA256.hash(data: [1, 2, 3, 4, 5]))
        )

        XCTAssertThrowsError(
            try client.receiveServerKeyExchangePayload(
                serverKeyExchangeMessage: serverResponse,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        ) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidExchangeHashSignature)
        }
    }

    /// Fixed inputs for the RFC 4253 § 7.2 expansion tests. The 64 leading bytes stand in for `K || H`, which the
    /// base hasher has already absorbed by the time the expansion runs.
    private static let keyExpansionPrefix = Array(UInt8(0)...UInt8(63))
    private static let keyExpansionSessionID = ByteBuffer(bytes: Array(repeating: UInt8(0xAB), count: 32))

    private static func keyExpansionBaseHasher() -> SHA256 {
        var hasher = SHA256()
        hasher.update(data: Self.keyExpansionPrefix)
        return hasher
    }

    func testKeyExpansionBeyondTheDigestLength() {
        // Known-answer vector, reproducible with:
        //
        //     python3 -c "
        //     import hashlib
        //     prefix = bytes(range(64)); sid = b'\xab' * 32
        //     k1 = hashlib.sha256(prefix + b'C' + sid).digest()
        //     k2 = hashlib.sha256(prefix + k1).digest()
        //     print((k1 + k2).hex())"
        let expected =
            "160e60ad39ed1ed41ab5032bf40c266f2149ea49ccb6d83158d7a7a81a76bbe2"
            + "030c757ba789cf718e49f6a66ddee1b054de8b2b83a8a3174f41869064d82e56"

        let material = sshExpandKeyMaterial(
            baseHasher: Self.keyExpansionBaseHasher(),
            discriminatorByte: UInt8(ascii: "C"),
            sessionID: Self.keyExpansionSessionID,
            expectedKeySize: 64
        )

        XCTAssertEqual(material.count, 64)
        XCTAssertEqual(material.map { String(format: "%02x", $0) }.joined(), expected)

        // Independently recompute the vector straight from RFC 4253 § 7.2, without reusing the incremental hasher.
        let firstBlock = Array(
            SHA256.hash(
                data: Self.keyExpansionPrefix + [UInt8(ascii: "C")]
                    + Array(Self.keyExpansionSessionID.readableBytesView)
            )
        )
        let secondBlock = Array(SHA256.hash(data: Self.keyExpansionPrefix + firstBlock))
        XCTAssertEqual(material, firstBlock + secondBlock)
    }

    func testKeyExpansionUpToTheDigestLengthIsATruncatedFirstBlock() {
        // This is the regression proof for the existing AES-GCM key sizes: nothing about them may change.
        let firstBlock = Array(
            SHA256.hash(
                data: Self.keyExpansionPrefix + [UInt8(ascii: "A")]
                    + Array(Self.keyExpansionSessionID.readableBytesView)
            )
        )

        for size in [0, 1, 12, 16, 31, 32] {
            let material = sshExpandKeyMaterial(
                baseHasher: Self.keyExpansionBaseHasher(),
                discriminatorByte: UInt8(ascii: "A"),
                sessionID: Self.keyExpansionSessionID,
                expectedKeySize: size
            )
            XCTAssertEqual(material, Array(firstBlock.prefix(size)), "wrong material for size \(size)")
        }
    }

    func testKeyExchangeWithKeysLongerThanTheDigest() throws {
        // curve25519-sha256 hashes to 32 bytes, so a 64 byte cipher key requires the § 7.2 expansion.
        let wideKeySizes = ExpectedKeySizes(ivSize: 8, encryptionKeySize: 64, macKeySize: 16)

        var server = EllipticCurveKeyExchange<Curve25519.KeyAgreement.PrivateKey>(
            ourRole: .server([.init(ed25519Key: .init())]),
            previousSessionIdentifier: nil
        )
        var client = EllipticCurveKeyExchange<Curve25519.KeyAgreement.PrivateKey>(
            ourRole: .client,
            previousSessionIdentifier: nil
        )
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 1024)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        let (serverKeys, serverResponse) = try assertNoThrowWithValue(
            try server.completeKeyExchangeServerSide(
                clientKeyExchangeMessage: clientMessage,
                serverHostKey: serverHostKey,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: wideKeySizes
            )
        )

        initialExchangeBytes.clear()

        let clientKeys = try assertNoThrowWithValue(
            try client.receiveServerKeyExchangePayload(
                serverKeyExchangeMessage: serverResponse,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: wideKeySizes
            )
        )

        self.keyExchangeAgreed(serverKeys, clientKeys)
        XCTAssertEqual(clientKeys.keys.inboundEncryptionKey.bitCount, 64 * 8)
        XCTAssertEqual(clientKeys.keys.outboundEncryptionKey.bitCount, 64 * 8)
        XCTAssertEqual(clientKeys.keys.initialInboundIV.count, 8)
    }
}

/// This helper extension persists the old way of initializing config for this file.
extension SSHConnectionRole {
    fileprivate static func server(_ hostKeys: [NIOSSHPrivateKey]) -> SSHConnectionRole {
        .server(SSHServerConfiguration(hostKeys: hostKeys, userAuthDelegate: DenyAllServerAuthDelegate()))
    }

    fileprivate static var client: SSHConnectionRole {
        .client(
            SSHClientConfiguration(
                userAuthDelegate: ExplodingAuthDelegate(),
                serverAuthDelegate: AcceptAllHostKeysDelegate()
            )
        )
    }
}
