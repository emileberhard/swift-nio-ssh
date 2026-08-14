//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

/// A `UserAuthSignablePayload` represents the data that needs to be signed as part
/// of key-based user authentication.
///
/// The data is:
///
///     string    session identifier
///     byte      SSH_MSG_USERAUTH_REQUEST
///     string    user name
///     string    service name
///     string    "publickey"
///     boolean   TRUE
///     string    public key algorithm name
///     string    public key to be used for authentication
///
/// This object produces that data and can then be signed or verified.
internal struct UserAuthSignablePayload {
    private(set) var bytes: ByteBuffer

    /// - Parameter algorithmName: The signature algorithm name. For every key type but RSA this is the key type
    ///     itself; RSA keys (RFC 8332) may name `rsa-sha2-512`, `rsa-sha2-256`, or `ssh-rsa` here while the key
    ///     blob below stays `ssh-rsa`. The signature must be produced with the same name, or the server will
    ///     reject it.
    init(
        sessionIdentifier: ByteBuffer,
        userName: String,
        serviceName: String,
        publicKey: NIOSSHPublicKey,
        algorithmName: String.UTF8View
    ) {
        // We use the session identifier as the base buffer and just append to it. We ask for 1kB because it's likely
        // enough for this data.
        var sessionIdentifier = sessionIdentifier
        var newBuffer = sessionIdentifier
        newBuffer.clear(minimumCapacity: 1024)

        newBuffer.writeSSHString(&sessionIdentifier)
        newBuffer.writeInteger(SSHMessage.UserAuthRequestMessage.id)
        newBuffer.writeSSHString(userName.utf8)
        newBuffer.writeSSHString(serviceName.utf8)
        newBuffer.writeSSHString("publickey".utf8)
        newBuffer.writeSSHBoolean(true)
        newBuffer.writeSSHString(algorithmName)
        newBuffer.writeCompositeSSHString { buffer in
            buffer.writeSSHHostKey(publicKey)
        }

        self.bytes = newBuffer
    }
}
