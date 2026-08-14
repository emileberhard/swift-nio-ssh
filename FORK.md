# AgenTTY fork of swift-nio-ssh

This fork exists to let AgenTTY — an iOS SSH client for AI coding agents — connect to the hosts its users
actually have. Upstream `swift-nio-ssh` supports Ed25519 and ECDSA only; a large share of real-world
servers and user keys are RSA, and NIOSSH refuses them outright.

**Base:** `8f33cac67309a13aecc0a4d95044543549b20ffb`, upstream tag `0.12.0`.
**Branch:** `agentty-nio-ssh`. `main` is a clean upstream mirror and is never modified.

Every commit here is independently `swift test`-green on macOS with the Xcode 27 toolchain (Swift 6.4),
which is the toolchain AgenTTY itself builds with. Each commit is one concern, so a bisect lands
somewhere useful. Nothing is rebased once pushed.

## The delta

### 1. Dedupe the negotiated MAC algorithm list

`SSHKeyExchangeStateMachine` built its KEXINIT MAC list with `protectionSchemes.compactMap { $0.macName }`,
which emits one entry per scheme. Upstream ships only two schemes and both report `nil`, so the list is
always empty and hits the `["hmac-sha2-256"]` fallback — the bug is unreachable there. AgenTTY registers
two AES-CTR schemes that both name `hmac-sha2-256`, at which point the same code puts
`hmac-sha2-256,hmac-sha2-256` on the wire. The fix is an order-preserving dedupe; the `isEmpty` fallback is
untouched.

Not upstream because upstream cannot reach the broken path.

### 2. Expose key exchange negotiation diagnostics

`NIOSSHError.keyExchangeNegotiationFailure` carried no information: six distinct failures — key exchange,
host key, cipher, MAC, transport protection, and the version/asymmetric case — all produced the same
opaque error. AgenTTY has to tell a user *why* their host was refused, on a phone, without a log file.

This adds a public `NIOSSHError.diagnostics` string, a `negotiationFailure` error type, and a
`NegotiationFailure` payload carrying the failing component plus both algorithm lists. All six throw
sites are tagged.

Not upstream because upstream's consumers are servers and CLI tools with logs.

### 3. Derive session keys with RFC 4253 § 7.2 expansion

Upstream truncated a single digest to the requested key size, guarded by
`assert(expectedKeySize <= Digest.byteCount)`. With `curve25519-sha256` the digest is 32 bytes, so any
cipher wanting a 64-byte key traps in debug and silently produces a 32-byte key in release. That is
exactly what ChaCha20-Poly1305 (`chacha20-poly1305@openssh.com`, a 64-byte key) needs, and AgenTTY wants
it because it is the only cipher some older Dropbear builds offer.

This replaces six near-identical generators and the truncating helper with one RFC 4253 § 7.2
implementation:

```
K1 = HASH(K || H || X || session_id)
K2 = HASH(K || H || K1)
K3 = HASH(K || H || K1 || K2)     // all material so far, not just the previous block
```

The existing `ECKeyExchangeTests` derivation assertions pass **unmodified** — commit 7 later adds a
parameter to those call sites, but no expected value in that file has ever been touched. That is the
regression proof that short keys still derive byte-identically. An independent 64-byte known-answer test,
computed by hand from the RFC, covers the multi-block path the old code could not reach.

Not upstream because upstream ships no cipher with a key wider than its narrowest hash.

### 4. Add RSA public keys and the `ssh-rsa` wire format

`NIOSSHPublicKey.BackingKey` gains `.rsa`, with RFC 4253 § 6.6 parsing and serialization (mpint `e` then
mpint `n`) on top of `_CryptoExtras`' `_RSA.Signing`.

Design note: `_RSA.Signing.PublicKey.getKeyPrimitives()` throws, but `writeSSHHostKey` is non-throwing and
called from roughly ten places. Rather than make SSH serialization throwing everywhere, `SSHRSAPublicKey`
resolves the modulus and exponent once at construction. The same reasoning makes
`NIOSSHPrivateKey(rsaKey:)` throwing — see below.

Parsing is bounded: the modulus must be 1024–16384 bits and the exponent non-zero, both rejected with
`NIOSSHError.invalidDomainParametersForKey`. `init(openSSHPublicKey:)` now also rejects trailing data
after the key blob, for every key type.

`RSAKeyTests` uses fixtures captured from a real `ssh-keyscan` against a throwaway `sshd`, and asserts
round-trip byte identity. That matters beyond tidiness: AgenTTY's trusted-host store compares
`String(openSSHPublicKey:)` against `ssh-keyscan` output by literal equality, so a differently-padded
mpint would silently break host key pinning.

### 5. Add RSA signatures with `rsa-sha2` flavors

`RSASignatureFlavor` models the three RFC 8332 algorithms (`rsa-sha2-512`, `rsa-sha2-256`, `ssh-rsa`) and
is the single place that maps a wire name to a hash. That indirection is load-bearing: `_RSA` **traps** on
a digest type it does not recognise, so an arbitrary `Digest` must never reach it.

The flavor travels on the signature, which is what lets the writer emit the right algorithm name and the
verifier pick the right hash.

`NIOSSHPrivateKey(rsaKey:)` is `throws`, unlike the sibling initializers, because it eagerly resolves the
public key's primitives. `NIOSSHPrivateKey.signatureAlgorithms` is public so a client can build a user-auth
ladder without duplicating key-type knowledge; it has exactly one entry for every non-RSA key.

### 6. Decouple key type from signature algorithm name (RFC 8332)

An `ssh-rsa` key signs under three different algorithm names while the key blob never changes. Three
places must agree on one name per attempt: the algorithm field on the wire, the same field inside the
signed payload, and the signature itself. They now all derive from one resolved name.

`NIOSSHUserAuthenticationOffer.Offer.PrivateKey.signatureAlgorithm` (`nil` = the key's default) is how a
client picks. Because every non-RSA key has exactly one algorithm, `nil` reproduces upstream's bytes
exactly.

**Deliberate omission: no `SSH_MSG_EXT_INFO` / `server-sig-algs`.** Implementing it would mean a new
message type, a new `SSHMessage` case, routing through three connection states, and special-casing
`ext-info-c` in the key exchange algorithm list — a large permanent delta on the part of the codebase most
likely to conflict with upstream. It is safe to omit: servers send EXT_INFO only when the client
advertised `ext-info-c`, which NIOSSH does not. The cost is at most two extra `USERAUTH_FAILURE` round
trips, and only against pre-RFC-8332 servers; OpenSSH ≥ 7.2 and Dropbear ≥ 2020.79 accept the first rung.

### 7. Negotiate RSA host key algorithms and bind the signature flavor

`supportedServerHostKeyAlgorithms` gains `rsa-sha2-512`, `rsa-sha2-256`, and `ssh-rsa`, in that order,
after the elliptic curve entries.

The negotiated algorithm is threaded into the exchanger in both directions. The server signs the exchange
hash with it; the client requires the server's signature to actually carry it. Without that binding a
server could negotiate `rsa-sha2-512` and return a SHA-1 signature that verifies perfectly well against
the same key, and we would accept the downgrade.

### 8. Give length decryption the packet sequence number

`chacha20-poly1305@openssh.com` encrypts the packet length under a separate key with the sequence number as
the nonce — so a scheme literally cannot decrypt the length field without knowing it. Upstream's
`decryptAndVerifyRemainingPacket` and `encryptPacket` both receive the sequence number; `decryptFirstBlock`
does not, and `SSHPacketParser.sequenceNumber` is internal, so there is no way to get it from outside the
package.

This adds a *new* protocol requirement `decryptFirstBlock(_:sequenceNumber:)` with a default implementation
that forwards to the existing `decryptFirstBlock(_:)`. Existing conformers — in this package and outside it
— compile and behave unchanged; only a scheme that needs the number implements the new method. The shape
mirrors OpenSSH's own `chachapoly_get_length(ctx, plenp, seqnr, cp, len)`.

The number matters specifically because it is *not* zero at that point: the parser's counter runs
continuously across the cleartext-to-encrypted transition, so the first packet after NEWKEYS carries
whatever number the preceding cleartext packets left it on.

**The outbound side needs nothing.** `SSHPacketSerializer.serialize` already calls
`encryptPacket(_:sequenceNumber:)` with `self.sequenceNumber`, and increments that counter in both the
`.cleartext` and `.encrypted` states, so outbound encryption already sees the correct continuous number for
its first post-NEWKEYS packet. Outbound encryption is a single call with no length/body split, so there is
no second entry point to plumb.

Not upstream because upstream ships no cipher that encrypts the length field independently.

### 9. Sign the algorithm name the offer actually sends

`SSHMessage.UserAuthRequestMessage.init(request:sessionID:)` built the signed payload with the public key's
prefix when the offer's `signatureAlgorithm` was `nil`, while `sign(_:algorithm:)` resolved that same `nil`
to the key's *preferred* algorithm — which is also the name that goes on the wire. For RSA those differ
(`ssh-rsa` vs `rsa-sha2-512`), so a defaulted RSA offer produced a signature a real server rejects with
"incorrect signature". Reproduced three ways against OpenSSH 10.2p1 (nil RSA fails, explicit RSA verifies,
nil Ed25519 verifies) before the fix.

The fix resolves the algorithm once — defaulting to `signatureAlgorithms[0]` — and uses that single value
for both the payload and the signature, keeping the certified-key exception (offered under the certificate
prefix) exactly as `offeredAlgorithmName(for:)` defines it. Every explicit-algorithm path is byte-identical
to before; only the previously-broken defaulted RSA path changes.

Not upstream because upstream has no RSA keys, so upstream's `nil` path cannot diverge.

## Deliberate divergences

**`ssh-rsa` (SHA-1) is advertised.** Last, always. Negotiation walks the *client's* preference list and
takes the first entry the server also supports, so SHA-1 is selected only when the server offers nothing
better. That is the entire reason it is here: some older Dropbear and OpenSSH ≤ 8.7 deployments have no
other host key algorithm, and AgenTTY's users have such hosts. Removing it would make those hosts
unreachable; keeping it costs nothing against any modern server.

**`swift-crypto` lower bound raised to 3.15.0.** `_RSA.Signing.PublicKey.init(n:e:)` and
`getKeyPrimitives()` are recent additions and there is no reasonable way to construct an RSA key from SSH
wire primitives without them.

**The host key floor is 1024 bits, not 2048.** A host key is the remote peer's choice, not ours, and
refusing to represent a 1024-bit host key would simply make those hosts unreachable rather than more
secure. The floor exists to bound parsing, not to express a policy; a client that wants a stricter policy
can apply it in its host key validation delegate. Private keys the client generates or imports are a
separate decision made by the client, not here.

**Upstream CI workflows removed.** `main.yml`, `pull_request.yml`, and `pull_request_label.yml` all
`uses:` reusable workflows from `apple/swift-nio` — a Linux 5.10 → nightly matrix, benchmarks, static SDK
builds, and a semver-label check. On a fork they are noise that fails for reasons unrelated to this code.
They are replaced by a single `ci.yml` running `swift build` + `swift test` on `macos-latest`.

**Linux is not tested.** `_CryptoExtras` is BoringSSL-backed on every platform, so RSA behaviour is
identical, and AgenTTY only ever builds this for Apple platforms. If this fork ever needs Linux, add a
matrix job to `ci.yml`.

## Known gaps, left alone on purpose

**`writeUserAuthPKOKMessage` still echoes `key.keyPrefix`.** Strict RFC 8332 says `SSH_MSG_USERAUTH_PK_OK`
should echo the algorithm name the client offered. NIOSSH's client never sends the signature-less probe
that provokes a PK_OK, so no NIOSSH peer can observe the difference, and carrying the offered name on
`UserAuthPKOKMessage` would widen the delta for no behavioural gain. Documented in the code at the write
site.

**Certificates cannot wrap RSA base keys.** There is no `ssh-rsa-cert-v01@openssh.com` entry in the
certificate prefix mapping, so such a key could never round-trip. `NIOSSHCertifiedPublicKey.init` rejects
RSA base keys explicitly rather than trapping later.

## Upstream audit obligation

On each upstream `swift-nio-ssh` release, re-check whether RSA support has landed upstream and whether any
of these eight commits can be dropped. Commits 1, 2, 3, and 8 are the most likely candidates for
upstreaming on their own merits; 4–7 exist only because upstream has made a deliberate choice not to ship
RSA.
