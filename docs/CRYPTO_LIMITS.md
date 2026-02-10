# CipherLink Cryptographic Design & Status

> **Author:** Belkis Aslani
> **Status:** Feature-complete E2EE skeleton — audit recommended before high-risk production use

## Cryptographic Primitives

| Component | Primitive | Library |
|-----------|----------|---------|
| Identity keypair | Ed25519 + derived X25519 | libsodium `crypto_sign` / `crypto_sign_ed25519_sk_to_curve25519` |
| Key exchange | X25519 DH | libsodium `crypto_scalarmult` |
| Key agreement | X3DH (Extended Triple Diffie-Hellman) | Custom implementation over libsodium |
| Session management | Double Ratchet (DH + symmetric ratchet) | Custom implementation over libsodium |
| Key derivation | HKDF-SHA256 | HMAC-SHA-256 via libsodium `crypto_auth_hmacsha256` |
| Encryption | XChaCha20-Poly1305 AEAD | libsodium `crypto_aead_xchacha20poly1305_ietf_*` |
| Signing | Ed25519 | libsodium `crypto_sign_detached` |
| Backup KDF | Argon2id | libsodium `crypto_pwhash` |
| Nonce generation | 24-byte random | libsodium `randombytes_buf` |
| Message ID | 16-byte random (hex) | libsodium `randombytes_buf` |

These are well-established, peer-reviewed cryptographic primitives composed following
the Signal Protocol design patterns.

## Implemented Features

### 1. Forward Secrecy — IMPLEMENTED

Each session uses the **Double Ratchet Algorithm** with ephemeral DH key pairs.
Compromising a long-term key does NOT expose past messages because:
- Each DH ratchet step generates a new ephemeral X25519 keypair
- Message keys are derived from a symmetric KDF chain and deleted after use
- Past keys cannot be recovered from the current ratchet state

**Module:** `packages/crypto/src/ratchet.ts`

### 2. Post-Compromise Security — IMPLEMENTED

The Double Ratchet provides automatic healing after key compromise:
- Every DH ratchet step introduces fresh entropy via new ephemeral keypairs
- An attacker who compromises session state loses access after the next DH ratchet
- No manual key rotation required

**Module:** `packages/crypto/src/ratchet.ts`

### 3. Double Ratchet — IMPLEMENTED

Full Double Ratchet implementation with:
1. **DH Ratchet**: New ephemeral X25519 keypair per ratchet step
2. **Symmetric Ratchet**: KDF chains for sending and receiving (HMAC 0x01/0x02)
3. **Root key chain**: HKDF-based root key updates on each DH step
4. **Skipped message keys**: Handles out-of-order delivery (MAX_SKIP = 256)
5. **Message padding**: Automatic 256-byte block padding

**Module:** `packages/crypto/src/ratchet.ts`
**Reference:** [Signal Double Ratchet Specification](https://signal.org/docs/specifications/doubleratchet/)

### 4. X3DH Key Agreement — IMPLEMENTED

Full X3DH (Extended Triple Diffie-Hellman) key agreement:
- **Ed25519 identity keys** with derived X25519 DH keys
- **Signed prekeys** (Ed25519 signature verification)
- **One-time prekeys** for additional forward secrecy
- **Prekey bundles** published to server for asynchronous key exchange
- 3 or 4 DH computations depending on one-time prekey availability

**Module:** `packages/crypto/src/x3dh.ts`
**Reference:** [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)

### 5. Group Messaging (Sender Keys) — IMPLEMENTED

Efficient group messaging using the **Sender Keys** protocol:
- Each member generates a sender key (chain key + Ed25519 signing keypair)
- Sender key distribution messages sent via pairwise E2EE channels
- Chain ratchet derives per-message encryption keys
- Ed25519 signatures authenticate every group message
- `GroupSession` class manages member keys and encryption/decryption

**Module:** `packages/crypto/src/group.ts`
**Server:** Group message fan-out with offline queuing

### 6. Sealed Sender — IMPLEMENTED

Sender identity is hidden from the server:
- Ephemeral X25519 keypair for each sealed message
- DH + KDF between ephemeral key and recipient's public key
- Sender identity encrypted inside the envelope
- Server routes by `recipientPub` + `ephemeralPub` only
- Recipient decrypts to reveal sender identity + payload

**Module:** `packages/crypto/src/sealed-sender.ts`

### 7. Key Verification (Safety Numbers) — IMPLEMENTED

Signal-style safety number protocol for key verification:
- **Fingerprint computation**: 5200 iterations of SHA-512 per identity key
- **Safety numbers**: 60-digit numeric string (12 groups of 5 digits)
- **QR payload**: Binary format for QR code scanning
- Deterministic — keys sorted lexicographically so both parties compute the same number
- Out-of-band verification via comparison or QR scan

**Module:** `packages/crypto/src/safety-numbers.ts`

### 8. Message Padding — IMPLEMENTED

PKCS7-style padding to fixed-size blocks:
- Default block size: 256 bytes
- Prevents ciphertext length from revealing plaintext length
- Integrated into Double Ratchet encrypt/decrypt pipeline
- Configurable block size for different use cases

**Module:** `packages/crypto/src/padding.ts`

### 9. Encrypted Backup — IMPLEMENTED

Secure backup and restore using passphrase-based encryption:
- **Argon2id** key derivation (OPSLIMIT_MODERATE, 256MB memory)
- **XChaCha20-Poly1305** encryption of backup data
- Passphrase minimum length: 8 characters
- `createBackup()` / `restoreBackup()` API
- `estimateKeyDerivationTime()` for UX guidance

**Module:** `packages/crypto/src/backup.ts`

### 10. Replay Protection — IMPLEMENTED

Multi-layer replay protection:
- **Client-side**: `ReplayGuard` with sliding window deduplication (configurable window size)
- **Client-side**: `MonotonicCounter` for sequence enforcement
- **Client-side**: `SessionReplayGuard` combining both mechanisms
- **Server-side**: Recent message ID cache (50,000 entries) rejects duplicate `msgId`
- Export/import support for persistence across restarts

**Module:** `packages/crypto/src/replay.ts`
**Server:** `apps/server/src/index.ts` (`trackMessageId`)

## Remaining Considerations

### Not Yet Implemented

| Feature | Status | Notes |
|---------|--------|-------|
| Multi-device (Sesame/MLS) | NOT IMPLEMENTED | Single keypair per device; X3DH prekeys enable asynchronous setup |
| Header encryption | NOT IMPLEMENTED | Message headers are visible; optional enhancement |
| Private contact discovery | NOT IMPLEMENTED | Server-side PSI not implemented |
| Message deletion / expiry | NOT IMPLEMENTED | No remote wipe or disappearing messages |
| TLS (wss://) | CONFIG ONLY | Must be configured at deployment; dev uses ws:// |

### Production Hardening Recommendations

1. **TLS everywhere** (`wss://`) — required for production deployment
2. **Independent security audit** — critical before real-world use
3. **Formal verification** of critical cryptographic paths
4. **Rate limiting by IP** in addition to per-connection
5. **Certificate pinning** on mobile clients
6. **Multi-device support** via Sesame or MLS (RFC 9420)
7. **Header encryption** for additional metadata protection
8. **Bug bounty program** for ongoing vulnerability discovery
9. **Compliance review** (GDPR, etc.)

## Test Coverage

57 unit tests covering all cryptographic modules:
- Core primitives: 20 tests (keys, KDF, HKDF, AEAD, base64, AAD)
- Message padding: 6 tests
- Replay protection: 5 tests
- Safety numbers: 4 tests
- Encrypted backup: 3 tests
- X3DH key agreement: 5 tests
- Double Ratchet: 5 tests
- Sealed sender: 3 tests
- Group messaging (Sender Keys): 3 tests

## References

- [Signal Protocol Specifications](https://signal.org/docs/)
- [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [MLS (Messaging Layer Security) RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)
- [libsodium Documentation](https://doc.libsodium.org/)
- [HKDF RFC 5869](https://tools.ietf.org/html/rfc5869)
