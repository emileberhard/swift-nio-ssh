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

@preconcurrency import Crypto
import NIOCore
import _CryptoExtras

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// An SSH private key.
///
/// This object identifies a single SSH entity, usually a server. It is used as part of the SSH handshake and key exchange process,
/// and is also presented to clients that want to validate that they are communicating with the appropriate server. Clients use
/// this key to sign data in order to validate their identity as part of user auth.
///
/// Users cannot do much with this key other than construct it, but NIO uses it internally.
public struct NIOSSHPrivateKey: Sendable {
    /// The actual key structure used to perform the key operations.
    internal var backingKey: BackingKey

    private init(backingKey: BackingKey) {
        self.backingKey = backingKey
    }

    public init(ed25519Key key: Curve25519.Signing.PrivateKey) {
        self.backingKey = .ed25519(key)
    }

    public init(p256Key key: P256.Signing.PrivateKey) {
        self.backingKey = .ecdsaP256(key)
    }

    public init(p384Key key: P384.Signing.PrivateKey) {
        self.backingKey = .ecdsaP384(key)
    }

    public init(p521Key key: P521.Signing.PrivateKey) {
        self.backingKey = .ecdsaP521(key)
    }

    #if canImport(Darwin)
    public init(secureEnclaveP256Key key: SecureEnclave.P256.Signing.PrivateKey) {
        self.backingKey = .secureEnclaveP256(key)
    }
    #endif

    /// Construct a private key from an RSA key.
    ///
    /// This throws if the key's primitives cannot be extracted, which in practice means the key is malformed.
    /// The primitives are resolved once, here, so that every later SSH serialization path stays non-throwing.
    public init(rsaKey key: _RSA.Signing.PrivateKey) throws {
        self.backingKey = .rsa(try SSHRSAPrivateKey(key))
    }

    // The algorithms that apply to this host key.
    internal var hostKeyAlgorithms: [Substring] {
        switch self.backingKey {
        case .ed25519:
            return ["ssh-ed25519"]
        case .ecdsaP256:
            return ["ecdsa-sha2-nistp256"]
        case .ecdsaP384:
            return ["ecdsa-sha2-nistp384"]
        case .ecdsaP521:
            return ["ecdsa-sha2-nistp521"]
        case .rsa:
            // RFC 8332: one key type, three signature algorithms, strongest first.
            return ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]
        #if canImport(Darwin)
        case .secureEnclaveP256:
            return ["ecdsa-sha2-nistp256"]
        #endif
        }
    }

    /// The signature algorithm names this key can sign with, in descending order of preference.
    ///
    /// Every key type but RSA has exactly one. RSA keys have three (RFC 8332), and a client that does not know
    /// which the server accepts has to try them in order. The first entry is what ``sign(_:algorithm:)`` uses
    /// when no algorithm is given.
    public var signatureAlgorithms: [String] {
        self.hostKeyAlgorithms.map { String($0) }
    }

    /// Resolves the algorithm name to sign with, defaulting to this key's preferred algorithm.
    private func resolveSignatureAlgorithm(_ algorithm: Substring?) throws -> Substring {
        let supported = self.hostKeyAlgorithms

        guard let algorithm else {
            // `hostKeyAlgorithms` is never empty.
            return supported[0]
        }

        guard supported.contains(algorithm) else {
            throw NIOSSHError.unknownSignature(algorithm: String(algorithm))
        }

        return algorithm
    }
}

extension NIOSSHPrivateKey {
    /// The various key types that can be used with NIOSSH.
    internal enum BackingKey {
        case ed25519(Curve25519.Signing.PrivateKey)
        case ecdsaP256(P256.Signing.PrivateKey)
        case ecdsaP384(P384.Signing.PrivateKey)
        case ecdsaP521(P521.Signing.PrivateKey)
        case rsa(SSHRSAPrivateKey)

        #if canImport(Darwin)
        case secureEnclaveP256(SecureEnclave.P256.Signing.PrivateKey)
        #endif
    }
}

/// An RSA private key, together with its already-resolved public key.
///
/// The public half is derived eagerly for the same reason ``SSHRSAPublicKey`` caches its primitives: deriving
/// it is throwing, but `NIOSSHPrivateKey.publicKey` is not.
internal struct SSHRSAPrivateKey: Sendable {
    internal var key: _RSA.Signing.PrivateKey
    internal var publicKey: SSHRSAPublicKey

    internal init(_ key: _RSA.Signing.PrivateKey) throws {
        self.key = key
        self.publicKey = try SSHRSAPublicKey(key.publicKey)
    }
}

extension NIOSSHPrivateKey {
    /// Signs `digest`, optionally with a specific signature algorithm.
    ///
    /// `algorithm` is `nil` for every caller that does not care, which means "this key's preferred algorithm".
    /// Only RSA keys have more than one, so for every other key type a non-`nil` algorithm is purely validated
    /// and then ignored.
    func sign<DigestBytes: Digest>(digest: DigestBytes, algorithm: Substring? = nil) throws -> NIOSSHSignature {
        let algorithm = try self.resolveSignatureAlgorithm(algorithm)

        switch self.backingKey {
        case .rsa(let key):
            // The digest is itself the signed message: RSASSA-PKCS1-v1_5 hashes what it is given.
            guard let flavor = RSASignatureFlavor(wireName: algorithm.utf8) else {
                throw NIOSSHError.unknownSignature(algorithm: String(algorithm))
            }
            let signature = try flavor.signature(for: Array(digest), with: key.key)
            return NIOSSHSignature(backingSignature: .rsa(flavor: flavor, signature: signature))
        case .ed25519(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ed25519(.data(signature)))
        case .ecdsaP256(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        case .ecdsaP384(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP384(signature))
        case .ecdsaP521(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP521(signature))

        #if canImport(Darwin)
        case .secureEnclaveP256(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        #endif
        }
    }

    /// Signs `payload`, optionally with a specific signature algorithm.
    ///
    /// See ``sign(digest:algorithm:)`` for the meaning of `algorithm`.
    func sign(_ payload: UserAuthSignablePayload, algorithm: Substring? = nil) throws -> NIOSSHSignature {
        let algorithm = try self.resolveSignatureAlgorithm(algorithm)

        switch self.backingKey {
        case .rsa(let key):
            guard let flavor = RSASignatureFlavor(wireName: algorithm.utf8) else {
                throw NIOSSHError.unknownSignature(algorithm: String(algorithm))
            }
            let signature = try flavor.signature(
                for: Array(payload.bytes.readableBytesView),
                with: key.key
            )
            return NIOSSHSignature(backingSignature: .rsa(flavor: flavor, signature: signature))
        case .ed25519(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ed25519(.data(signature)))
        case .ecdsaP256(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        case .ecdsaP384(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP384(signature))
        case .ecdsaP521(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP521(signature))
        #if canImport(Darwin)
        case .secureEnclaveP256(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        #endif
        }
    }
}

extension NIOSSHPrivateKey {
    /// Obtains the public key for a corresponding private key.
    public var publicKey: NIOSSHPublicKey {
        switch self.backingKey {
        case .ed25519(let privateKey):
            return NIOSSHPublicKey(backingKey: .ed25519(privateKey.publicKey))
        case .ecdsaP256(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP256(privateKey.publicKey))
        case .ecdsaP384(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP384(privateKey.publicKey))
        case .ecdsaP521(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP521(privateKey.publicKey))
        case .rsa(let privateKey):
            return NIOSSHPublicKey(backingKey: .rsa(privateKey.publicKey))
        #if canImport(Darwin)
        case .secureEnclaveP256(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP256(privateKey.publicKey))
        #endif
        }
    }
}
