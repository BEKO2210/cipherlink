# CipherLink Security Model

> **Author:** Belkis Aslani
> **Status:** v3 production-hardened E2EE — audit pack available, independent audit recommended

## Architecture Overview

```
┌───────────────┐          WebSocket           ┌───────────────┐
│               │  (encrypted envelopes only)   │               │
│   Alice's     │◄────────────────────────────►│   CipherLink  │
│   Device      │                               │   Relay       │
│               │                               │   Server      │
│  ┌──────────┐ │                               │               │
│  │SecureStore│ │                               │  ┌─────────┐ │
│  │ Identity  │ │                               │  │ Routing  │ │
│  │ Keys     │ │                               │  │ table    │ │
│  └──────────┘ │                               │  │ (pubkey  │ │
│               │                               │  │  -> ws)  │ │
│  ┌──────────┐ │                               │  └─────────┘ │
│  │libsodium │ │                               │               │
│  │ X3DH     │ │                               │  ┌─────────┐ │
│  │ Ratchet  │ │                               │  │ Prekey   │ │
│  │ Sealed   │ │                               │  │ store    │ │
│  │ Groups   │ │                               │  └─────────┘ │
│  │ Hybrid   │ │                               │               │
│  │ TreeKEM  │ │                               │  ┌─────────┐ │
│  └──────────┘ │                               │  │ Offline  │ │
└───────────────┘                               │  │ queue    │ │
                                                │  │ (10min   │ │
┌───────────────┐          WebSocket            │  │  TTL)    │ │
│               │  (encrypted envelopes only)   │  └─────────┘ │
│   Bob's       │◄────────────────────────────►│               │
│   Device      │                               │  ┌─────────┐ │
│               │                               │  │ Replay   │ │
│  ┌──────────┐ │                               │  │ dedup    │ │
│  │SecureStore│ │                               │  │ (50K)    │ │
│  │ Identity  │ │                               │  └─────────┘ │
│  │ Keys     │ │                               │               │
│  └──────────┘ │                               └───────────────┘
│               │
│  ┌──────────┐ │
│  │libsodium │ │
│  │ X3DH     │ │
│  │ Ratchet  │ │
│  │ Sealed   │ │
│  │ Groups   │ │
│  │ Hybrid   │ │
│  │ TreeKEM  │ │
│  └──────────┘ │
└───────────────┘
```

## Key Design Principles

### 1. Zero-Knowledge Server

The relay server **never** has access to:
- Plaintext message content
- Private keys
- Shared secrets or message keys
- Sender identity (when using sealed sender)
- Group membership details

The server only sees:
- Encrypted ciphertext envelopes
- Public keys used for routing
- Connection metadata (IP, timestamps)

### 2. Signal Protocol Architecture

CipherLink follows the Signal Protocol design:

```
Alice                                              Bob
  │                                                  │
  ├─ Generate Ed25519 identity + X25519 DH keys ──── ├─ Generate Ed25519 identity + X25519 DH keys
  │                                                  │
  ├─ Fetch Bob's prekey bundle from server ────────── ├─ Publish prekey bundle (SPK + OPKs)
  │                                                  │
  ├─ X3DH: 3-4 DH computations ───────────────────── │  (asynchronous — Bob can be offline)
  │  → Initial root key + chain key                  │
  │                                                  │
  ├─ Double Ratchet: encrypt message ──────────────── │
  │  → New ephemeral DH key per ratchet step         │
  │  → KDF chain for per-message keys                │
  │  → Pad to 256-byte blocks                        │
  │  → XChaCha20-Poly1305 AEAD                       │
  │                                                  │
  ├─ Send envelope via relay ──────────────────────── ├─ Receive envelope
  │  (ciphertext only — server learns nothing)       │
  │                                                  ├─ Double Ratchet: decrypt message
  │                                                  │  → Derive matching keys
  │                                                  │  → Verify AEAD tag
  │                                                  │  → Unpad plaintext
```

### 3. Forward Secrecy & Post-Compromise Security

- **X3DH** establishes initial session keys using ephemeral prekeys
- **Double Ratchet** continuously rotates keys:
  - DH ratchet: new ephemeral X25519 keypair per ratchet step
  - Symmetric ratchet: HMAC-based KDF chain per message
  - Message keys are deleted after use
- **Forward secrecy**: Compromising current keys cannot reveal past messages
- **Post-compromise security**: Sessions self-heal after compromise via DH ratchet

### 4. Key Storage

- **Private keys** are stored in the device's secure enclave via `expo-secure-store`
  - iOS: Keychain Services
  - Android: Android Keystore
- **Public keys** are shared openly (base64-encoded)
- **Ratchet state** must be stored securely on device
- Keys never leave the device unencrypted

### 5. Key Verification

- **Safety numbers**: 60-digit numeric strings (12 groups of 5 digits)
- Computed from both parties' identity keys via 5200 iterations of SHA-512
- Deterministic — both parties compute the same number
- **QR code payload** for in-person verification
- Detects MITM attacks when verified out-of-band

### 6. Sealed Sender

- Ephemeral X25519 keypair per message
- Sender identity encrypted inside the envelope
- Server routes by recipient public key only
- Sender revealed only after recipient decrypts

### 7. Group Messaging

- **Sender Keys** protocol for efficient group E2EE
- Each member distributes a sender key via pairwise channels
- Chain ratchet derives per-message encryption keys
- Ed25519 signatures authenticate every group message
- Server handles fan-out to group members

### 8. Server Authentication

- Clients send a `hello` message with their public key
- The server maps `publicKey -> WebSocket connection`
- For standard messages: envelope `senderPub` must match authenticated key
- For sealed messages: no sender verification (by design)
- No passwords, tokens, or sessions — identity is the keypair

### 9. Message Integrity & Replay Protection

- **AEAD authentication**: XChaCha20-Poly1305 provides encryption and authentication
- **Associated data (AAD)**: Binds metadata to ciphertext
- **Message padding**: 256-byte blocks prevent length analysis
- **Client-side replay guard**: Sliding window deduplication + monotonic counters
- **Server-side replay guard**: 50,000 recent message ID cache

### 10. Rate Limiting & Offline Queue

- Token-bucket rate limiter per WebSocket connection (burst: 30, rate: 5/s)
- Messages for offline recipients held with 10-minute TTL (max 100 per recipient)
- Supports standard envelopes, sealed envelopes, and group messages

### 11. v2 Security Hardening

- **Post-Quantum Hybrid KEM** — X25519 + ML-KEM-768 hybrid key encapsulation
- **Cryptographic Agility** — Immutable cipher suite registry with negotiation
- **TreeKEM Groups** — MLS-inspired tree-based group key agreement with O(log n) updates
- **Metadata Resistance** — Uniform 4096-byte envelopes, cover traffic, batching, timing jitter
- **Key Transparency** — Merkle tree-based verifiable key directory with signed tree heads
- **SecureBuffer** — Misuse-resistant key handling with use-after-wipe detection
- **Shamir Key Splitting** — 2-of-3 threshold backup key recovery over GF(256)
- **Protocol State Machine** — Formal session lifecycle (5 states) with invariant enforcement

### 12. v3 Production Hardening

- **TLS Enforcement** — Production guard blocks ws://; mandatory wss:// with configurable cert paths
- **Server Hardening** — IP-based connection limiting (default 10/IP), WebSocket ping/pong keepalive, group fan-out cap (256)
- **Sanitized Logging** — Structured logging with level filtering; no secrets, keys, or ciphertext in logs
- **Dependency Hygiene** — Dependabot for npm + GitHub Actions, lockfile integrity checks in CI, SBOM generation
- **Audit-Ready Documentation** — Threat model (9 adversary classes), attack surface review, protocol state spec, 34 security claims mapped to code/tests
- **Testing Upgrade** — 156 tests: unit, property-based (fast-check), fuzz, adversarial
- **SECURITY.md** — Responsible disclosure policy with severity classification

## What Is NOT Protected

See [THREAT_MODEL.md](./THREAT_MODEL.md) for a full threat analysis,
[CRYPTO_LIMITS.md](./CRYPTO_LIMITS.md) for remaining considerations, and
[Audit Pack](./audit/) for the complete audit-readiness documentation.
