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
import Foundation
import NIOCore
import NIOFoundationCompat
import _CryptoExtras

/// A representation of an SSH signature.
///
/// This type is intentionally highly opaque: we don't expect users to do anything with this directly.
/// Instead, we expect them to work with other APIs available on our opaque types.
public struct NIOSSHSignature: Hashable, Sendable {
    internal var backingSignature: BackingSignature

    internal init(backingSignature: BackingSignature) {
        self.backingSignature = backingSignature
    }

    /// The name of the algorithm that produced this signature, as it appears on the wire.
    ///
    /// For every key type but RSA this is the same as the key type. RSA keys sign with one of three algorithms
    /// (RFC 8332), so the choice has to travel with the signature: it is what the writer emits as the algorithm
    /// name and what the verifier uses to pick a hash.
    internal var signatureAlgorithmName: String.UTF8View {
        switch self.backingSignature {
        case .ed25519:
            return Self.ed25519SignaturePrefix
        case .ecdsaP256:
            return Self.ecdsaP256SignaturePrefix
        case .ecdsaP384:
            return Self.ecdsaP384SignaturePrefix
        case .ecdsaP521:
            return Self.ecdsaP521SignaturePrefix
        case .rsa(let flavor, _):
            return flavor.wireName
        }
    }
}

/// The signature algorithms that can be used with an `ssh-rsa` key, in order of preference.
///
/// RFC 8332 decoupled the RSA key type from the signature algorithm: `ssh-rsa` remains the key type, but a
/// signature over it may use SHA-1, SHA-256, or SHA-512.
internal enum RSASignatureFlavor: Sendable, Hashable, CaseIterable {
    /// RSASSA-PKCS1-v1_5 over SHA-512, i.e. `rsa-sha2-512`.
    case sha512

    /// RSASSA-PKCS1-v1_5 over SHA-256, i.e. `rsa-sha2-256`.
    case sha256

    /// RSASSA-PKCS1-v1_5 over SHA-1, i.e. plain `ssh-rsa`. Deprecated, but the only option on servers that
    /// predate RFC 8332.
    case sha1

    internal var wireName: String.UTF8View {
        switch self {
        case .sha512:
            return "rsa-sha2-512".utf8
        case .sha256:
            return "rsa-sha2-256".utf8
        case .sha1:
            return "ssh-rsa".utf8
        }
    }

    internal init?<Bytes: Collection>(wireName: Bytes) where Bytes.Element == UInt8 {
        guard let flavor = Self.allCases.first(where: { wireName.elementsEqual($0.wireName) }) else {
            return nil
        }
        self = flavor
    }
}

extension RSASignatureFlavor {
    /// Signs `message` with this flavor's hash.
    ///
    /// SSH signs the exchange hash, or the user auth signable payload, as the *message*, and RSASSA-PKCS1-v1_5
    /// hashes its input, so the message is hashed here rather than passed through.
    ///
    /// Only SHA-1, SHA-256 and SHA-512 are used: `_RSA` traps on a digest type it does not recognise, so an
    /// arbitrary `Digest` must never be handed to it.
    internal func signature(
        for message: some DataProtocol,
        with key: _RSA.Signing.PrivateKey
    ) throws -> _RSA.Signing.RSASignature {
        switch self {
        case .sha512:
            return try key.signature(for: SHA512.hash(data: message), padding: .insecurePKCS1v1_5)
        case .sha256:
            return try key.signature(for: SHA256.hash(data: message), padding: .insecurePKCS1v1_5)
        case .sha1:
            return try key.signature(for: Insecure.SHA1.hash(data: message), padding: .insecurePKCS1v1_5)
        }
    }

    internal func isValidSignature(
        _ signature: _RSA.Signing.RSASignature,
        for message: some DataProtocol,
        with key: _RSA.Signing.PublicKey
    ) -> Bool {
        switch self {
        case .sha512:
            return key.isValidSignature(signature, for: SHA512.hash(data: message), padding: .insecurePKCS1v1_5)
        case .sha256:
            return key.isValidSignature(signature, for: SHA256.hash(data: message), padding: .insecurePKCS1v1_5)
        case .sha1:
            return key.isValidSignature(
                signature,
                for: Insecure.SHA1.hash(data: message),
                padding: .insecurePKCS1v1_5
            )
        }
    }
}

// swift-format-ignore: DontRepeatTypeInStaticProperties
extension NIOSSHSignature {
    /// The various signature types that can be used with NIOSSH.
    internal enum BackingSignature: Sendable {
        // There is no structured Signature type for Curve25519, and we may want Data or ByteBuffer.
        case ed25519(RawBytes)

        case ecdsaP256(P256.Signing.ECDSASignature)

        case ecdsaP384(P384.Signing.ECDSASignature)

        case ecdsaP521(P521.Signing.ECDSASignature)

        case rsa(flavor: RSASignatureFlavor, signature: _RSA.Signing.RSASignature)

        internal enum RawBytes {
            case byteBuffer(ByteBuffer)
            case data(Data)
        }
    }

    /// The prefix of an Ed25519 signature.
    fileprivate static let ed25519SignaturePrefix = "ssh-ed25519".utf8

    /// The prefix of a P256 ECDSA public key.
    fileprivate static let ecdsaP256SignaturePrefix = "ecdsa-sha2-nistp256".utf8

    /// The prefix of a P384 ECDSA public key.
    fileprivate static let ecdsaP384SignaturePrefix = "ecdsa-sha2-nistp384".utf8

    /// The prefix of a P521 ECDSA public key.
    fileprivate static let ecdsaP521SignaturePrefix = "ecdsa-sha2-nistp521".utf8
}

extension NIOSSHSignature.BackingSignature.RawBytes: Equatable {
    public static func == (
        lhs: NIOSSHSignature.BackingSignature.RawBytes,
        rhs: NIOSSHSignature.BackingSignature.RawBytes
    ) -> Bool {
        switch (lhs, rhs) {
        case (.byteBuffer(let lhs), .byteBuffer(let rhs)):
            return lhs == rhs
        case (.data(let lhs), .data(let rhs)):
            return lhs == rhs
        case (.byteBuffer(let lhs), .data(let rhs)):
            return lhs.readableBytesView.elementsEqual(rhs)
        case (.data(let lhs), .byteBuffer(let rhs)):
            return rhs.readableBytesView.elementsEqual(lhs)
        }
    }
}

extension NIOSSHSignature.BackingSignature.RawBytes: Hashable {}

extension NIOSSHSignature.BackingSignature: Equatable {
    static func == (lhs: NIOSSHSignature.BackingSignature, rhs: NIOSSHSignature.BackingSignature) -> Bool {
        // We implement equatable in terms of the key representation.
        switch (lhs, rhs) {
        case (.ed25519(let lhs), .ed25519(let rhs)):
            return lhs == rhs
        case (.ecdsaP256(let lhs), .ecdsaP256(let rhs)):
            return lhs.rawRepresentation == rhs.rawRepresentation
        case (.ecdsaP384(let lhs), .ecdsaP384(let rhs)):
            return lhs.rawRepresentation == rhs.rawRepresentation
        case (.ecdsaP521(let lhs), .ecdsaP521(let rhs)):
            return lhs.rawRepresentation == rhs.rawRepresentation
        case (.rsa(let lhsFlavor, let lhsSig), .rsa(let rhsFlavor, let rhsSig)):
            return lhsFlavor == rhsFlavor && lhsSig.rawRepresentation == rhsSig.rawRepresentation
        case (.ed25519, _),
            (.ecdsaP256, _),
            (.ecdsaP384, _),
            (.ecdsaP521, _),
            (.rsa, _):
            return false
        }
    }
}

extension NIOSSHSignature.BackingSignature: Hashable {
    func hash(into hasher: inout Hasher) {
        switch self {
        case .ed25519(let bytes):
            hasher.combine(0)
            hasher.combine(bytes)
        case .ecdsaP256(let sig):
            hasher.combine(1)
            hasher.combine(sig.rawRepresentation)
        case .ecdsaP384(let sig):
            hasher.combine(2)
            hasher.combine(sig.rawRepresentation)
        case .ecdsaP521(let sig):
            hasher.combine(3)
            hasher.combine(sig.rawRepresentation)
        case .rsa(let flavor, let sig):
            hasher.combine(4)
            hasher.combine(flavor)
            hasher.combine(sig.rawRepresentation)
        }
    }
}

extension ByteBuffer {
    /// Writes an SSH host key to this `ByteBuffer`.
    @discardableResult
    mutating func writeSSHSignature(_ sig: NIOSSHSignature) -> Int {
        switch sig.backingSignature {
        case .ed25519(let sig):
            return self.writeEd25519Signature(signatureBytes: sig)
        case .ecdsaP256(let sig):
            return self.writeECDSAP256Signature(baseSignature: sig)
        case .ecdsaP384(let sig):
            return self.writeECDSAP384Signature(baseSignature: sig)
        case .ecdsaP521(let sig):
            return self.writeECDSAP521Signature(baseSignature: sig)
        case .rsa(let flavor, let sig):
            return self.writeRSASignature(flavor: flavor, baseSignature: sig)
        }
    }

    private mutating func writeRSASignature(
        flavor: RSASignatureFlavor,
        baseSignature: _RSA.Signing.RSASignature
    ) -> Int {
        // RFC 4253 § 6.6 and RFC 8332 § 3: the algorithm name, then the raw signature as an SSH string.
        // `RSA_sign` emits exactly `RSA_size` bytes, already left-padded, so there is no mpint encoding here.
        var writtenLength = self.writeSSHString(flavor.wireName)
        writtenLength += self.writeSSHString(baseSignature.rawRepresentation)
        return writtenLength
    }

    private mutating func writeEd25519Signature(signatureBytes: NIOSSHSignature.BackingSignature.RawBytes) -> Int {
        // The Ed25519 signature format is easy: the ed25519 signature prefix, followed by
        // the raw signature bytes.
        var writtenLength = self.writeSSHString(NIOSSHSignature.ed25519SignaturePrefix)

        switch signatureBytes {
        case .byteBuffer(var buf):
            writtenLength += self.writeSSHString(&buf)
        case .data(let d):
            writtenLength += self.writeSSHString(d)
        }

        return writtenLength
    }

    private mutating func writeECDSAP256Signature(baseSignature: P256.Signing.ECDSASignature) -> Int {
        var writtenLength = self.writeSSHString(NIOSSHSignature.ecdsaP256SignaturePrefix)

        // For ECDSA-P256, the key format is `mpint r` followed by `mpint s`. In this context, `r` is the
        // first 32 bytes, and `s` is the second.
        let rawRepresentation = baseSignature.rawRepresentation
        precondition(rawRepresentation.count == 64, "Unexpected size for P256 key")
        let rBytes: Data = rawRepresentation.prefix(32)
        let sBytes: Data = rawRepresentation.dropFirst(32)

        writtenLength += self.writeCompositeSSHString { buffer in
            var written = 0
            written += buffer.writePositiveMPInt(rBytes)
            written += buffer.writePositiveMPInt(sBytes)
            return written
        }

        return writtenLength
    }

    private mutating func writeECDSAP384Signature(baseSignature: P384.Signing.ECDSASignature) -> Int {
        var writtenLength = self.writeSSHString(NIOSSHSignature.ecdsaP384SignaturePrefix)

        // For ECDSA-P384, the key format is `mpint r` followed by `mpint s`. In this context, `r` is the
        // first 48 bytes, and `s` is the second.
        let rawRepresentation = baseSignature.rawRepresentation
        precondition(rawRepresentation.count == 96, "Unexpected size for P384 key")
        let rBytes: Data = rawRepresentation.prefix(48)
        let sBytes: Data = rawRepresentation.dropFirst(48)

        writtenLength += self.writeCompositeSSHString { buffer in
            var written = 0
            written += buffer.writePositiveMPInt(rBytes)
            written += buffer.writePositiveMPInt(sBytes)
            return written
        }

        return writtenLength
    }

    private mutating func writeECDSAP521Signature(baseSignature: P521.Signing.ECDSASignature) -> Int {
        var writtenLength = self.writeSSHString(NIOSSHSignature.ecdsaP521SignaturePrefix)

        // For ECDSA-P521, the key format is `mpint r` followed by `mpint s`. In this context, `r` is the
        // first 66 bytes, and `s` is the second.
        let rawRepresentation = baseSignature.rawRepresentation
        precondition(rawRepresentation.count == 132, "Unexpected size for P521 key")
        let rBytes: Data = rawRepresentation.prefix(66)
        let sBytes: Data = rawRepresentation.dropFirst(66)

        writtenLength += self.writeCompositeSSHString { buffer in
            var written = 0
            written += buffer.writePositiveMPInt(rBytes)
            written += buffer.writePositiveMPInt(sBytes)
            return written
        }

        return writtenLength
    }

    mutating func readSSHSignature() throws -> NIOSSHSignature? {
        try self.rewindOnNilOrError { buffer in
            // The wire format always begins with an SSH string containing the signature format identifier. Let's grab that.
            guard var signatureIdentifierBytes = buffer.readSSHString() else {
                return nil
            }

            // Now we need to check if they match our supported signature algorithms.
            let bytesView = signatureIdentifierBytes.readableBytesView
            if bytesView.elementsEqual(NIOSSHSignature.ed25519SignaturePrefix) {
                return try buffer.readEd25519Signature()
            } else if bytesView.elementsEqual(NIOSSHSignature.ecdsaP256SignaturePrefix) {
                return try buffer.readECDSAP256Signature()
            } else if bytesView.elementsEqual(NIOSSHSignature.ecdsaP384SignaturePrefix) {
                return try buffer.readECDSAP384Signature()
            } else if bytesView.elementsEqual(NIOSSHSignature.ecdsaP521SignaturePrefix) {
                return try buffer.readECDSAP521Signature()
            } else if let flavor = RSASignatureFlavor(wireName: bytesView) {
                return try buffer.readRSASignature(flavor: flavor)
            } else {
                // We don't know this signature type.
                let signature =
                    signatureIdentifierBytes.readString(length: signatureIdentifierBytes.readableBytes)
                    ?? "<unknown signature>"
                throw NIOSSHError.unknownSignature(algorithm: signature)
            }
        }
    }

    /// A helper function that reads an Ed25519 signature.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readEd25519Signature() throws -> NIOSSHSignature? {
        // For ed25519 the signature is just r||s encoded as a String.
        guard let sigBytes = self.readSSHString() else {
            return nil
        }

        return NIOSSHSignature(backingSignature: .ed25519(.byteBuffer(sigBytes)))
    }

    /// A helper function that reads an RSA signature.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readRSASignature(flavor: RSASignatureFlavor) throws -> NIOSSHSignature? {
        // For RSA the signature is a plain SSH string of exactly `RSA_size` bytes: no mpint encoding.
        guard let sigBytes = self.readSSHString() else {
            return nil
        }

        // A signature is as wide as the modulus, and we accept moduli up to 16384 bits, so anything longer is
        // junk. Bound it here so a hostile peer cannot make us allocate on their say-so.
        guard sigBytes.readableBytes > 0, sigBytes.readableBytes <= 2048 else {
            throw NIOSSHError.invalidSSHMessage(reason: "invalid RSA signature length")
        }

        let signature = _RSA.Signing.RSASignature(rawRepresentation: sigBytes.readableBytesView)
        return NIOSSHSignature(backingSignature: .rsa(flavor: flavor, signature: signature))
    }

    /// A helper function that reads an ECDSA P-256 signature.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readECDSAP256Signature() throws -> NIOSSHSignature? {
        // For ECDSA-P256, the key format is `mpint r` followed by `mpint s`.
        // We don't need them as mpints, so let's treat them as strings instead.
        guard var signatureBytes = self.readSSHString(),
            let rBytes = signatureBytes.readSSHString(),
            let sBytes = signatureBytes.readSSHString()
        else {
            return nil
        }

        // Time to put these into the raw format that CryptoKit wants. This is r || s, with each
        // integer explicitly left-padded with zeros.
        return try NIOSSHSignature(
            backingSignature: .ecdsaP256(ECDSASignatureHelper.toECDSASignature(r: rBytes, s: sBytes))
        )
    }

    /// A helper function that reads an ECDSA P-384 signature.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readECDSAP384Signature() throws -> NIOSSHSignature? {
        // For ECDSA-P384, the key format is `mpint r` followed by `mpint s`.
        // We don't need them as mpints, so let's treat them as strings instead.
        guard var signatureBytes = self.readSSHString(),
            let rBytes = signatureBytes.readSSHString(),
            let sBytes = signatureBytes.readSSHString()
        else {
            return nil
        }

        // Time to put these into the raw format that CryptoKit wants. This is r || s, with each
        // integer explicitly left-padded with zeros.
        return try NIOSSHSignature(
            backingSignature: .ecdsaP384(ECDSASignatureHelper.toECDSASignature(r: rBytes, s: sBytes))
        )
    }

    /// A helper function that reads an ECDSA P-521 signature.
    ///
    /// Not safe to call from arbitrary code as this does not return the reader index on failure: it relies on the caller performing
    /// the rewind.
    private mutating func readECDSAP521Signature() throws -> NIOSSHSignature? {
        // For ECDSA-P521, the key format is `mpint r` followed by `mpint s`.
        // We don't need them as mpints, so let's treat them as strings instead.
        guard var signatureBytes = self.readSSHString(),
            let rBytes = signatureBytes.readSSHString(),
            let sBytes = signatureBytes.readSSHString()
        else {
            return nil
        }

        // Time to put these into the raw format that CryptoKit wants. This is r || s, with each
        // integer explicitly left-padded with zeros.
        return try NIOSSHSignature(
            backingSignature: .ecdsaP521(ECDSASignatureHelper.toECDSASignature(r: rBytes, s: sBytes))
        )
    }
}

/// A structure that helps store ECDSA signatures on the stack temporarily to avoid unnecessary memory allocation.
///
/// CryptoKit would like to receive ECDSA signatures in the form of `r || s`, where `r` and `s` are both left-padded
/// with zeros. We know that for P256 the ECDSA signature size is going to be 64 bytes, as each of the P256 points are
/// 32 bytes wide. Similar logic applies up to P521, whose signatures are 132 bytes in size.
///
/// To avoid an unnecessary memory allocation, we use this data structure to provide some heap space to store these in.
/// This structure is wide enough for any of these signatures, and just uses the appropriate amount of space for whatever
/// algorithm is actually in use.
private struct ECDSASignatureHelper {
    private var storage:
        (
            UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
            UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64,
            UInt64
        ) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    private init(r: ByteBuffer, s: ByteBuffer, pointSize: Int) {
        precondition(MemoryLayout<ECDSASignatureHelper>.size >= pointSize, "Invalid width for ECDSA signature helper.")

        let rByteView = r.mpIntView
        let sByteView = s.mpIntView

        let rByteStartingOffset = pointSize - rByteView.count
        let sByteStartingOffset = pointSize - sByteView.count

        withUnsafeMutableBytes(of: &self.storage) { storagePtr in
            let rPtr = UnsafeMutableRawBufferPointer(rebasing: storagePtr[rByteStartingOffset..<pointSize])
            let sPtr = UnsafeMutableRawBufferPointer(
                rebasing: storagePtr[(sByteStartingOffset + pointSize)..<(pointSize * 2)]
            )

            precondition(rPtr.count == rByteView.count)
            precondition(sPtr.count == sByteView.count)

            rPtr.copyBytes(from: rByteView)
            sPtr.copyBytes(from: sByteView)
        }
    }

    static func toECDSASignature<Signature: ECDSASignatureProtocol>(r: ByteBuffer, s: ByteBuffer) throws -> Signature {
        let helper = ECDSASignatureHelper(r: r, s: s, pointSize: Signature.pointSize)
        return try withUnsafeBytes(of: helper.storage) { storagePtr in
            try Signature(
                rawRepresentation: UnsafeRawBufferPointer(rebasing: storagePtr.prefix(Signature.pointSize * 2))
            )
        }
    }
}

extension ByteBuffer {
    // A view onto the mpInt bytes. Strips off a leading 0 if it is present for
    // size reasons.
    fileprivate var mpIntView: ByteBufferView {
        var baseView = self.readableBytesView
        if baseView.first == 0 {
            baseView = baseView.dropFirst()
        }
        return baseView
    }
}

protocol ECDSASignatureProtocol {
    init<D>(rawRepresentation: D) throws where D: DataProtocol

    static var pointSize: Int { get }
}

extension P256.Signing.ECDSASignature: ECDSASignatureProtocol {
    static var pointSize: Int { 32 }
}

extension P384.Signing.ECDSASignature: ECDSASignatureProtocol {
    static var pointSize: Int { 48 }
}

extension P521.Signing.ECDSASignature: ECDSASignatureProtocol {
    static var pointSize: Int { 66 }
}
