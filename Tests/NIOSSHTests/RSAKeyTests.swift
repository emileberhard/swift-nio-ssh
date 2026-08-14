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
import _CryptoExtras

@testable import NIOSSH

/// Tests for the `ssh-rsa` public key wire format.
///
/// The round-trip tests matter more than they look: AgenTTY's trusted host key store compares
/// `String(openSSHPublicKey:)` against the strings `ssh-keyscan` produced during pairing, by literal equality.
/// A single wrong mpint byte becomes a permanent, user-visible host key mismatch, so the fixtures here are real
/// `ssh-keyscan` output rather than something this library generated.
final class RSAKeyTests: XCTestCase {
    /// Fixtures captured by running `ssh-keyscan -t rsa` against a throwaway `sshd` on 127.0.0.1:2299, whose
    /// host keys were generated with `ssh-keygen -t rsa -b {2048,4096}` and, for `e = 3`,
    /// `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_pubexp:3`.
    enum Fixtures {
        /// A throwaway 2048-bit, e = 65537 RSA host key.
        static let rsa2048 =
            "ssh-rsa "
            + "AAAAB3NzaC1yc2EAAAADAQABAAABAQDPmGVQ8m+tCH+WfmF1uvVARlW9qLkDScE0Sho1GSmvsIqSIm26qVuiOTAZNyp7i0Ll"
            + "A7oOyBN98lrlcn7ryhrcbZUzV1LXrPEgM/jVPvSDLKNDO3IGT4+sNF0xH6g+6E79DqkSRL59DSIjAYgDiLrInaYLHujbKKFw"
            + "zYDwUeTI5yO2YnS/lRqYQu1crRLqGKe9KQvc1TpWwzeYEwpfNzj2MzD8mvncUuBN/cVT8FjIurpWPGZVE2ZuZJNePiXIsFHR"
            + "9dmoZKWRvnQA2oAxi50UxkRtNKy66GDfwSs1bBHKF/lGfwdwtBkIqkUITp0/iyney7kDfp6n5cQ5fp4/vRDP"

        /// A throwaway 4096-bit, e = 65537 RSA host key.
        static let rsa4096 =
            "ssh-rsa "
            + "AAAAB3NzaC1yc2EAAAADAQABAAACAQCbaEoLDyyuvgmft+j/Zv81E5Ezza47dcQElNRxU885aKnTz4VqhdI3KSZ3L3HUvN3h"
            + "ni1l9ve+JtJr3MF3Pkq+orW7gIdWz/f6dS+XcJk1fA4JnOWqP1fXtxMAMZNYU/3mMY4+2cdyUNQBCqh7nxw4fPEdov79WB6g"
            + "d5tShuzn7xcOdklO0t/aK0hyF64iBic4S0mdBI8VXNE8gk76lPljBziE1WmwsOXaKRIuiJlxC9iX5yr8lBuUqLyR4Cfn6RHc"
            + "rmpBPtzfsnCsiY5uYG5nI3bqGB44KVQsLGgXMs+GbyVTqwcDF0QGTPBe0IijF427ttOS5Q1xc9nkURVoBnIsngiEiapv7FAc"
            + "c3fOBGW5ETZi1EA7uwk9MFoS23CXBDnLlIceHKNxilIDGlZvTOoVzT+v3pQ0z6E1XEupICMS+GBKmDzqNJSG+UVYE617QB3o"
            + "+p0CRf7gKz/ZTZTOt7jr/4rZLWYM3514tnVRAe53JohK0YhyZeWPXOenPNKGUdi61C7oWtHzWvm1qtjSWXcAaRKn0eNhXdZz"
            + "cGRmc2fi9xoTyfCWSasSUG20fE1RLW+OnxCnWjvyjEeeqS05hMFNbnLtGP+dYCuBSLp25ilKylRjO5ykhiIkQAB1YKBcnF48"
            + "LLsD+MWfGN0DW24ajWHNimBxoUR1qFQANLanp3wWrw=="

        /// A throwaway 2048-bit, e = 3 RSA host key.
        static let rsaExponent3 =
            "ssh-rsa "
            + "AAAAB3NzaC1yc2EAAAABAwAAAQEAreXtdDyauDOB9SRBWmKUUzvlY98o3a+YJ8Tew5KqRXjIGiNjFUUkKsbv2QVeHtJ98s8c"
            + "iKXlF/zlpoW7IZUsZVzliN1kvQ7EMuAFtMyj4I/aX/qDILd+f0wMV65SzoABJGwp4SI2IOWw3AxMy7hV5NuctbmSUeNEPnAa"
            + "MStCnDosiHoApelSPyOaFfLfMEk2y0mf85tCFEV3CCIDewL0qGhnDOb/xwJRMFF5WZEZ03xGQ9Z3FmzKC27WUhTcdlDWzjl8"
            + "lcHKG/68tpP9/zb/yD+SmlQDNUGNex3ZmFyW1DnQlnrfv4mt1jmmw8brD9BA9/GMdKcA+Ey7H0JrfEcNpQ=="

        static let all = [rsa2048, rsa4096, rsaExponent3]
    }

    /// Builds an `ssh-rsa` key blob directly, so that malformed inputs can be constructed.
    private func rsaKeyBlob(e: [UInt8], n: [UInt8]) -> ByteBuffer {
        var buffer = ByteBuffer()
        buffer.writeSSHString("ssh-rsa".utf8)
        buffer.writePositiveMPInt(e)
        buffer.writePositiveMPInt(n)
        return buffer
    }

    /// A modulus of exactly `bits` bits, with the top bit set.
    private func modulus(bits: Int) -> [UInt8] {
        precondition(bits % 8 == 0)
        return [0xFF] + Array(repeating: UInt8(0xA5), count: (bits / 8) - 1)
    }

    // MARK: - Round trips

    func testOpenSSHRoundTripIsByteIdentical() throws {
        for fixture in Fixtures.all {
            let key = try assertNoThrowWithValue(NIOSSHPublicKey(openSSHPublicKey: fixture))
            XCTAssertEqual(String(openSSHPublicKey: key), fixture)
        }
    }

    func testFixtureModuliHaveTheHighBitSet() throws {
        // Every real RSA modulus has its top bit set, which is what forces `writePositiveMPInt` to prepend a
        // sign-preserving zero byte. Assert it here so a regenerated fixture cannot silently stop covering that.
        for fixture in Fixtures.all {
            let key = try assertNoThrowWithValue(NIOSSHPublicKey(openSSHPublicKey: fixture))
            guard case .rsa(let rsaKey) = key.backingKey else {
                XCTFail("Fixture did not parse as RSA")
                return
            }
            XCTAssertGreaterThanOrEqual(rsaKey.modulus.first ?? 0, 0x80)
        }
    }

    func testKeySizesAndExponentsAreParsedCorrectly() throws {
        let expected: [(String, Int, [UInt8])] = [
            (Fixtures.rsa2048, 2048, [0x01, 0x00, 0x01]),
            (Fixtures.rsa4096, 4096, [0x01, 0x00, 0x01]),
            (Fixtures.rsaExponent3, 2048, [0x03]),
        ]

        for (fixture, bits, exponent) in expected {
            let key = try assertNoThrowWithValue(NIOSSHPublicKey(openSSHPublicKey: fixture))
            guard case .rsa(let rsaKey) = key.backingKey else {
                XCTFail("Fixture did not parse as RSA")
                return
            }
            XCTAssertEqual(rsaKey.key.keySizeInBits, bits)
            XCTAssertEqual(Array(rsaKey.publicExponent), exponent)
            XCTAssertEqual(rsaKey.modulus.count, bits / 8)
        }
    }

    func testModulusWithoutTheHighBitSetRoundTrips() throws {
        // Real keys always set the top bit, so build a key that does not in order to cover the other branch of
        // `writePositiveMPInt`: the encoded mpint must have no leading zero byte.
        var modulus = self.modulus(bits: 2048)
        modulus[0] = 0x01

        let key = try _RSA.Signing.PublicKey(n: modulus, e: [0x01, 0x00, 0x01])
        let publicKey = NIOSSHPublicKey(backingKey: .rsa(try SSHRSAPublicKey(key)))

        var buffer = ByteBuffer()
        buffer.writeSSHHostKey(publicKey)

        // 4 byte type length + "ssh-rsa" + 4 + 3 byte exponent + 4 + 256 byte modulus, with no sign-preserving byte.
        XCTAssertEqual(buffer.writerIndex, 4 + 7 + 4 + 3 + 4 + 256)
        XCTAssertEqual(try buffer.readSSHHostKey(), publicKey)
    }

    func testEquatableAndHashable() throws {
        let first = try NIOSSHPublicKey(openSSHPublicKey: Fixtures.rsa2048)
        let second = try NIOSSHPublicKey(openSSHPublicKey: Fixtures.rsa2048)
        let other = try NIOSSHPublicKey(openSSHPublicKey: Fixtures.rsa4096)

        XCTAssertEqual(first, second)
        XCTAssertEqual(first.hashValue, second.hashValue)
        XCTAssertNotEqual(first, other)
        XCTAssertNotEqual(first, NIOSSHPrivateKey(ed25519Key: .init()).publicKey)
    }

    // MARK: - Signature algorithm names

    func testRSAKeysAcceptEveryRFC8332AlgorithmName() throws {
        let key = try NIOSSHPublicKey(openSSHPublicKey: Fixtures.rsa2048)

        for name in ["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"] {
            XCTAssertTrue(key.acceptsSignatureAlgorithm(name.utf8), "rejected \(name)")
        }
        XCTAssertFalse(key.acceptsSignatureAlgorithm("rsa-sha2-384".utf8))
        XCTAssertFalse(key.acceptsSignatureAlgorithm("ssh-ed25519".utf8))
    }

    func testOtherKeyTypesAcceptOnlyTheirOwnAlgorithmName() {
        let key = NIOSSHPrivateKey(ed25519Key: .init()).publicKey
        XCTAssertTrue(key.acceptsSignatureAlgorithm("ssh-ed25519".utf8))
        XCTAssertFalse(key.acceptsSignatureAlgorithm("ssh-rsa".utf8))
    }

    func testKnownAlgorithmsIncludesEveryRSAName() {
        let known = NIOSSHPublicKey.knownAlgorithms.map { String($0) }
        XCTAssertTrue(known.contains("ssh-rsa"))
        XCTAssertTrue(known.contains("rsa-sha2-256"))
        XCTAssertTrue(known.contains("rsa-sha2-512"))
    }

    // MARK: - Rejections

    func testSmallestAcceptableModulusIsAccepted() throws {
        var blob = self.rsaKeyBlob(e: [0x01, 0x00, 0x01], n: self.modulus(bits: 1024))
        XCTAssertNoThrow(try blob.readSSHHostKey())
    }

    func testTooSmallModulusIsRejected() throws {
        var blob = self.rsaKeyBlob(e: [0x01, 0x00, 0x01], n: self.modulus(bits: 1016))
        XCTAssertThrowsError(try blob.readSSHHostKey()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidDomainParametersForKey)
        }
    }

    func testTooLargeModulusIsRejected() throws {
        var blob = self.rsaKeyBlob(e: [0x01, 0x00, 0x01], n: self.modulus(bits: 16392))
        XCTAssertThrowsError(try blob.readSSHHostKey()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidDomainParametersForKey)
        }
    }

    func testZeroExponentIsRejected() throws {
        var blob = self.rsaKeyBlob(e: [0x00], n: self.modulus(bits: 2048))
        XCTAssertThrowsError(try blob.readSSHHostKey()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidDomainParametersForKey)
        }
    }

    func testTruncatedBlobIsIncomplete() throws {
        let blob = self.rsaKeyBlob(e: [0x01, 0x00, 0x01], n: self.modulus(bits: 2048))

        for truncation in [1, 17, 200] {
            var truncated = blob.getSlice(at: blob.readerIndex, length: blob.readableBytes - truncation)!
            XCTAssertNil(try truncated.readSSHHostKey(), "unexpectedly parsed with \(truncation) bytes missing")
        }
    }

    func testTrailingGarbageIsRejected() throws {
        XCTAssertThrowsError(try NIOSSHPublicKey(openSSHPublicKey: Fixtures.rsa2048 + "AAAA")) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidOpenSSHPublicKey)
        }
    }
}
