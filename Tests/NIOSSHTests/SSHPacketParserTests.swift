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

final class SSHPacketParserTests: XCTestCase {
    /// Feed the SSH version to a packet parser and verify the output.
    ///
    /// Usually used to set up an appropriate state.
    private func feedVersion(to parser: inout SSHPacketParser, file: StaticString = #filePath, line: UInt = #line) {
        var version = ByteBuffer.of(string: "SSH-2.0-OpenSSH_7.9\r\n")
        parser.append(bytes: &version)

        var packet: SSHMessage?
        XCTAssertNoThrow(packet = try parser.nextPacket(), file: file, line: line)

        switch packet {
        case .some(.version(let string)):
            XCTAssertEqual(0, parser.sequenceNumber)
            XCTAssertEqual(string, "SSH-2.0-OpenSSH_7.9", file: file, line: line)
        default:
            XCTFail("Expecting .version", file: file, line: line)
        }
    }

    func testReadVersion() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())

        var part1 = ByteBuffer.of(string: "SSH-2.0-")
        parser.append(bytes: &part1)

        XCTAssertNil(try parser.nextPacket())

        var part2 = ByteBuffer.of(string: "OpenSSH_7.9\r\n")
        parser.append(bytes: &part2)

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(0, parser.sequenceNumber)
            XCTAssertEqual(string, "SSH-2.0-OpenSSH_7.9")
        default:
            XCTFail("Expecting .version")
        }
    }

    func testReadVersionWithExtraLinesOnClient() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())

        var part1 = ByteBuffer.of(string: "xxxx\r\nyyyy\r\nSSH-2.0-")
        parser.append(bytes: &part1)

        XCTAssertNil(try parser.nextPacket())

        var part2 = ByteBuffer.of(string: "OpenSSH_7.9\r\n")
        parser.append(bytes: &part2)

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(string, "SSH-2.0-OpenSSH_7.9")
        default:
            XCTFail("Expecting .version")
        }
    }

    func testReadVersionWithExtraLinesOnServer() throws {
        var parser = SSHPacketParser(isServer: true, allocator: ByteBufferAllocator())

        var part1 = ByteBuffer.of(string: "xx")
        parser.append(bytes: &part1)

        XCTAssertNil(try parser.nextPacket())

        var part2 = ByteBuffer.of(string: "xx\r\nyyyy\r\nSSH-2.0-OpenSSH_7.9\r\n")
        parser.append(bytes: &part2)

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(string, "xxxx")
        default:
            XCTFail("Expecting .version")
        }
    }

    func testReadVersionWithoutCarriageReturn() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())

        var part1 = ByteBuffer.of(string: "SSH-2.0-")
        parser.append(bytes: &part1)

        XCTAssertNil(try parser.nextPacket())

        var part2 = ByteBuffer.of(string: "OpenSSH_7.4\n")
        parser.append(bytes: &part2)

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(string, "SSH-2.0-OpenSSH_7.4")
        default:
            XCTFail("Expecting .version")
        }
    }

    func testReadVersionWithExtraLinesWithoutCarriageReturnOnClient() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())

        var part1 = ByteBuffer.of(string: "xxxx\nyyyy\nSSH-2.0-")
        parser.append(bytes: &part1)

        XCTAssertNil(try parser.nextPacket())

        var part2 = ByteBuffer.of(string: "OpenSSH_7.4\n")
        parser.append(bytes: &part2)

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(string, "SSH-2.0-OpenSSH_7.4")
        default:
            XCTFail("Expecting .version")
        }
    }

    func testReadVersionWithExtraLinesWithoutCarriageReturnOnServer() throws {
        var parser = SSHPacketParser(isServer: true, allocator: ByteBufferAllocator())

        var part1 = ByteBuffer.of(string: "xx")
        parser.append(bytes: &part1)

        XCTAssertNil(try parser.nextPacket())

        var part2 = ByteBuffer.of(string: "xx\nyyyy\nSSH-2.0-OpenSSH_7.4\n")
        parser.append(bytes: &part2)

        switch try parser.nextPacket() {
        case .version(let string):
            XCTAssertEqual(string, "xxxx")
        default:
            XCTFail("Expecting .version")
        }
    }

    func testBinaryInParts() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)

        var part1 = ByteBuffer.of(bytes: [0, 0, 0])
        parser.append(bytes: &part1)

        XCTAssertNil(try parser.nextPacket())
        XCTAssertEqual(0, parser.sequenceNumber)

        var part2 = ByteBuffer.of(bytes: [28])
        parser.append(bytes: &part2)

        XCTAssertNil(try parser.nextPacket())
        XCTAssertEqual(0, parser.sequenceNumber)

        var part3 = ByteBuffer.of(bytes: [10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97])
        parser.append(bytes: &part3)
        XCTAssertNil(try parser.nextPacket())
        XCTAssertEqual(0, parser.sequenceNumber)

        var part4 = ByteBuffer.of(bytes: [117, 116, 104, 42, 111, 216, 12, 226, 248, 144, 175, 157, 207])
        parser.append(bytes: &part4)

        switch try parser.nextPacket() {
        case .serviceRequest(let message):
            XCTAssertEqual(1, parser.sequenceNumber)
            XCTAssertEqual(message.service, "ssh-userauth")
        default:
            XCTFail("Expecting .serviceRequest")
        }
    }

    func testBinaryFull() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)

        var part1 = ByteBuffer.of(bytes: [
            0, 0, 0, 28, 10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104, 42, 111, 216, 12,
            226, 248, 144, 175, 157, 207,
        ])
        parser.append(bytes: &part1)

        switch try parser.nextPacket() {
        case .serviceRequest(let message):
            XCTAssertEqual(1, parser.sequenceNumber)
            XCTAssertEqual(message.service, "ssh-userauth")
        default:
            XCTFail("Expecting .serviceRequest")
        }
    }

    func testBinaryTwoMessages() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)

        var part = ByteBuffer.of(bytes: [
            0, 0, 0, 28, 10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104, 42, 111, 216, 12,
            226, 248, 144, 175, 157, 207, 0, 0, 0, 28, 10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97,
            117, 116, 104, 42, 111, 216, 12, 226, 248, 144, 175, 157, 207,
        ])
        parser.append(bytes: &part)

        switch try parser.nextPacket() {
        case .serviceRequest(let message):
            XCTAssertEqual(1, parser.sequenceNumber)
            XCTAssertEqual(message.service, "ssh-userauth")
        default:
            XCTFail("Expecting .serviceRequest")
        }
        switch try parser.nextPacket() {
        case .serviceRequest(let message):
            XCTAssertEqual(2, parser.sequenceNumber)
            XCTAssertEqual(message.service, "ssh-userauth")
        default:
            XCTFail("Expecting .serviceRequest")
        }
    }

    func testWeReclaimStorage() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)
        XCTAssertNoThrow(try parser.nextPacket())

        let part = ByteBuffer.of(bytes: [
            0, 0, 0, 28, 10, 5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114, 97, 117, 116, 104, 42, 111, 216, 12,
            226, 248, 144, 175, 157, 207,
        ])

        let neededParts = 2048 / part.readableBytes

        for _ in 0..<neededParts {
            var partCopy = part
            parser.append(bytes: &partCopy)
        }

        // The version field is in the buffer, and we can't really prevent it being there.
        let startingOffset = parser._discardableBytes
        for i in 0..<(neededParts / 2) {
            XCTAssertEqual(parser._discardableBytes, (i * part.readableBytes) + startingOffset)
            XCTAssertNoThrow(try parser.nextPacket())
        }

        // Now we should have cleared up.
        XCTAssertEqual(parser._discardableBytes, 0)
    }

    @available(iOS 13.2, macOS 10.15, watchOS 6.1, tvOS 13.2, *)
    func testSequencePreservedBetweenPlainAndCypher() throws {
        let allocator = ByteBufferAllocator()
        var parser = SSHPacketParser(isServer: false, allocator: allocator)
        self.feedVersion(to: &parser)

        var part = ByteBuffer(bytes: [0, 0, 0, 12, 10, 21, 41, 114, 125, 250, 3, 79, 3, 217, 166, 136])
        parser.append(bytes: &part)

        switch try parser.nextPacket() {
        case .newKeys:
            XCTAssertEqual(1, parser.sequenceNumber)
        default:
            XCTFail("Expecting .newKeys")
        }

        part = ByteBuffer(bytes: [0, 0, 0, 12, 10, 21, 41, 114, 125, 250, 3, 79, 3, 217, 166, 136])
        parser.append(bytes: &part)

        switch try parser.nextPacket() {
        case .newKeys:
            XCTAssertEqual(2, parser.sequenceNumber)
        default:
            XCTFail("Expecting .newKeys")
        }

        let inboundEncryptionKey = SymmetricKey(size: .bits128)
        let outboundEncryptionKey = inboundEncryptionKey
        let inboundMACKey = SymmetricKey(size: .bits128)
        let outboundMACKey = inboundMACKey
        let protection = TestTransportProtection(
            initialKeys: .init(
                initialInboundIV: [],
                initialOutboundIV: [],
                inboundEncryptionKey: inboundEncryptionKey,
                outboundEncryptionKey: outboundEncryptionKey,
                inboundMACKey: inboundMACKey,
                outboundMACKey: outboundMACKey
            )
        )
        parser.addEncryption(protection)

        part = allocator.buffer(capacity: 1024)
        part.writeSSHPacket(
            message: .newKeys,
            lengthEncrypted: protection.lengthEncrypted,
            blockSize: protection.cipherBlockSize
        )
        XCTAssertNoThrow(try protection.encryptPacket(&part, sequenceNumber: 2))
        var subpart = part.readSlice(length: 2)!
        parser.append(bytes: &subpart)

        XCTAssertNil(try parser.nextPacket())
        XCTAssertEqual(2, parser.sequenceNumber)

        parser.append(bytes: &part)

        switch try parser.nextPacket() {
        case .newKeys:
            XCTAssertEqual(3, parser.sequenceNumber)
        default:
            XCTFail("Expecting .newKeys")
        }

        part = allocator.buffer(capacity: 1024)
        part.writeSSHPacket(
            message: .newKeys,
            lengthEncrypted: protection.lengthEncrypted,
            blockSize: protection.cipherBlockSize
        )
        XCTAssertNoThrow(try protection.encryptPacket(&part, sequenceNumber: 2))
        parser.append(bytes: &part)

        switch try parser.nextPacket() {
        case .newKeys:
            XCTAssertEqual(4, parser.sequenceNumber)
        default:
            XCTFail("Expecting .newKeys")
        }
    }

    func testLengthDecryptionReceivesThePacketSequenceNumber() throws {
        // `chacha20-poly1305@openssh.com` derives the length field's keystream from the packet sequence number,
        // so it cannot decrypt the length without it. The sequence number runs continuously across NEWKEYS,
        // which means the first encrypted packet's number depends on how many cleartext packets preceded it —
        // it is emphatically not zero.
        let allocator = ByteBufferAllocator()
        var parser = SSHPacketParser(isServer: false, allocator: allocator)
        self.feedVersion(to: &parser)

        // Two cleartext packets first, so the sequence number is non-zero by the time encryption starts.
        for expectedSequenceNumber in UInt32(1)...UInt32(2) {
            var part = ByteBuffer(bytes: [0, 0, 0, 12, 10, 21, 41, 114, 125, 250, 3, 79, 3, 217, 166, 136])
            parser.append(bytes: &part)

            switch try parser.nextPacket() {
            case .newKeys:
                XCTAssertEqual(parser.sequenceNumber, expectedSequenceNumber)
            default:
                XCTFail("Expecting .newKeys")
            }
        }

        let encryptionKey = SymmetricKey(size: .bits128)
        let macKey = SymmetricKey(size: .bits128)
        let protection = try SequenceNumberRecordingTransportProtection(
            initialKeys: .init(
                initialInboundIV: [],
                initialOutboundIV: [],
                inboundEncryptionKey: encryptionKey,
                outboundEncryptionKey: encryptionKey,
                inboundMACKey: macKey,
                outboundMACKey: macKey
            )
        )
        parser.addEncryption(protection)

        for expectedSequenceNumber in UInt32(2)...UInt32(4) {
            var part = allocator.buffer(capacity: 1024)
            part.writeSSHPacket(
                message: .newKeys,
                lengthEncrypted: protection.lengthEncrypted,
                blockSize: protection.cipherBlockSize
            )
            XCTAssertNoThrow(try protection.encryptPacket(&part, sequenceNumber: expectedSequenceNumber))
            parser.append(bytes: &part)

            switch try parser.nextPacket() {
            case .newKeys:
                XCTAssertEqual(parser.sequenceNumber, expectedSequenceNumber + 1)
            default:
                XCTFail("Expecting .newKeys")
            }
        }

        // The first post-NEWKEYS packet was decrypted as sequence number 2, not 0.
        XCTAssertEqual(protection.recordedSequenceNumbers, [2, 3, 4])

        // And the parser reached the scheme through the new overload, not the sequence-number-free one.
        XCTAssertEqual(protection.legacyCallCount, 0)
    }

    func testLengthDecryptionDefaultsToTheSequenceNumberFreeOverload() throws {
        // `TestTransportProtection` implements only `decryptFirstBlock(_:)`. It must keep working unchanged,
        // because that is what every existing conformer — in this package and outside it — looks like.
        let allocator = ByteBufferAllocator()
        var parser = SSHPacketParser(isServer: false, allocator: allocator)
        self.feedVersion(to: &parser)

        let encryptionKey = SymmetricKey(size: .bits128)
        let macKey = SymmetricKey(size: .bits128)
        let protection = TestTransportProtection(
            initialKeys: .init(
                initialInboundIV: [],
                initialOutboundIV: [],
                inboundEncryptionKey: encryptionKey,
                outboundEncryptionKey: encryptionKey,
                inboundMACKey: macKey,
                outboundMACKey: macKey
            )
        )
        parser.addEncryption(protection)

        var part = allocator.buffer(capacity: 1024)
        part.writeSSHPacket(
            message: .newKeys,
            lengthEncrypted: protection.lengthEncrypted,
            blockSize: protection.cipherBlockSize
        )
        XCTAssertNoThrow(try protection.encryptPacket(&part, sequenceNumber: 0))
        parser.append(bytes: &part)

        switch try parser.nextPacket() {
        case .newKeys:
            XCTAssertEqual(parser.sequenceNumber, 1)
        default:
            XCTFail("Expecting .newKeys")
        }
    }
}

extension ByteBuffer {
    public static func of(string: String) -> ByteBuffer {
        var buffer = ByteBufferAllocator().buffer(capacity: string.count)
        buffer.writeString(string)
        return buffer
    }

    public static func of(bytes: [UInt8]) -> ByteBuffer {
        var buffer = ByteBufferAllocator().buffer(capacity: bytes.count)
        buffer.writeBytes(bytes)
        return buffer
    }
}
