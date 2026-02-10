# CipherLink Cryptographic Limitations

> **Author:** Belkis Aslani
> **Status:** Skeleton / Demo — NOT for high-risk production use

## Current Primitives

| Component | Primitive | Library |
|-----------|----------|---------|
| Identity keypair | X25519 (Curve25519) | libsodium |
| Key exchange | X25519 DH | libsodium `crypto_scalarmult` |
| Key derivation | HKDF-SHA256 | HMAC-SHA-256 via libsodium `crypto_auth_hmacsha256` |
| Encryption | XChaCha20-Poly1305 AEAD | libsodium `crypto_aead_xchacha20poly1305_ietf_*` |
| Nonce generation | 24-byte random | libsodium `randombytes_buf` |
| Message ID | 16-byte random (hex) | libsodium `randombytes_buf` |

These are well-established, peer-reviewed cryptographic primitives. The individual
building blocks are sound. The **limitations are in how they are composed** in this
skeleton.

## Missing Features

### 1. No Forward Secrecy

**What this means:** If Alice's long-term private key is ever compromised (stolen,
leaked, court-ordered), an attacker can decrypt ALL messages ever sent between Alice
and any contact — past, present, and future.

**Why:** We use a static X25519 DH shared secret. The same key pair is used for every
message. There are no ephemeral keys.

**Fix:** Implement the **Double Ratchet Algorithm** (as used in Signal Protocol):
- Each message uses a new ephemeral DH key
- A symmetric ratchet derives fresh keys per message
- Compromising one key does not expose past messages

### 2. No Post-Compromise Security

**What this means:** If an attacker compromises a key and then loses access, they
retain the ability to decrypt future messages until the user generates a new identity.

**Fix:** The Double Ratchet provides post-compromise security through continuous
key rotation via DH ratchet steps.

### 3. No Double Ratchet

**What this means:** We derive one static message key per conversation pair. Every
message between Alice and Bob uses the same encryption key (different nonces prevent
identical ciphertexts, but the key material is static).

**Fix:** Implement the full Double Ratchet:
1. **DH Ratchet**: New ephemeral X25519 keypair on each message send
2. **Symmetric Ratchet**: KDF chain for sending and receiving
3. **Header encryption**: Optionally encrypt message headers

Reference: [Signal Double Ratchet Specification](https://signal.org/docs/specifications/doubleratchet/)

### 4. No Multi-Device Support

**What this means:** One identity keypair per device. Using CipherLink on a second
device requires a separate identity.

**Fix:** Implement **Sesame** (Signal's multi-device protocol) or use **MLS
(Messaging Layer Security)** which natively supports multi-device.

### 5. No Group Messaging

**What this means:** Only pairwise (1:1) conversations are supported.

**Fix:** Options:
- **Sender Keys** (Signal approach): Efficient for large groups
- **MLS (RFC 9420)**: Standards-based, scalable group E2EE
- **Pairwise fan-out**: Simple but O(n) per message

### 6. No Sealed Sender

**What this means:** The server sees `senderPub` in every envelope. The server
knows exactly who is talking to whom.

**Fix:** Implement sealed sender (as in Signal):
- Encrypt the sender identity inside the envelope
- Server routes by recipient key only
- Sender is revealed only after decryption

### 7. No Key Verification Protocol

**What this means:** Users manually copy/paste public keys. There is no
cryptographic verification that a key belongs to the intended person. A MITM
could substitute keys.

**Fix:**
- **Safety numbers**: Hash of both public keys, verified out-of-band
- **QR code scanning**: Encode public keys in QR codes for in-person verification
- **Key transparency**: Public log of key-identity bindings

### 8. No Message Padding

**What this means:** Ciphertext length reveals plaintext length. An observer
can distinguish "yes" from "I'll be there at 3pm at the usual place."

**Fix:** Pad all messages to fixed-size blocks before encryption (e.g., 256-byte
blocks).

### 9. No Secure Backup

**What this means:** If the user loses their device, all messages and their
identity are lost. There is no backup mechanism.

**Fix:** Implement encrypted backup:
- Derive a backup key from a user passphrase (Argon2id)
- Encrypt message history and identity keys
- Store encrypted backup on user-controlled storage

### 10. Limited Replay Protection

**What this means:** While each message has a unique `msgId` and `timestamp`
in the AAD, there is no server-side or client-side deduplication. A network
attacker could replay an envelope.

**Fix:**
- Client-side message ID deduplication
- Monotonic message counters in the ratchet state
- Server-side recent-message-ID cache

## Upgrade Roadmap

### Phase 1: Security Hardening (Priority)
1. TLS everywhere (`wss://`)
2. Client-side message ID deduplication
3. Key verification via safety numbers
4. Message padding

### Phase 2: Forward Secrecy
1. X3DH key agreement (prekeys)
2. Double Ratchet implementation
3. Session management

### Phase 3: Metadata Protection
1. Sealed sender
2. Private contact discovery
3. Traffic padding / constant-rate sending

### Phase 4: Scalability
1. MLS for group messaging
2. Multi-device via Sesame or MLS
3. Encrypted backup/restore

### Phase 5: Production
1. Independent security audit
2. Formal verification of critical paths
3. Bug bounty program
4. Compliance review (GDPR, etc.)

## References

- [Signal Protocol Specifications](https://signal.org/docs/)
- [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [MLS (Messaging Layer Security) RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)
- [libsodium Documentation](https://doc.libsodium.org/)
- [HKDF RFC 5869](https://tools.ietf.org/html/rfc5869)
