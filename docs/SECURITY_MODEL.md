# CipherLink Security Model

> **Author:** Belkis Aslani
> **Status:** Feature-complete E2EE skeleton — audit recommended before high-risk production use

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
│  └──────────┘ │                               │               │
└───────────────┘                               │  ┌─────────┐ │
                                                │  │ Offline  │ │
┌───────────────┐          WebSocket            │  │ queue    │ │
│               │  (encrypted envelopes only)   │  │ (10min   │ │
│   Bob's       │◄────────────────────────────►│  │  TTL)    │ │
│   Device      │                               │  └─────────┘ │
│               │                               │               │
│  ┌──────────┐ │                               │  ┌─────────┐ │
│  │SecureStore│ │                               │  │ Replay   │ │
│  │ Identity  │ │                               │  │ dedup    │ │
│  │ Keys     │ │                               │  │ (50K)    │ │
│  └──────────┘ │                               │  └─────────┘ │
│               │                               │               │
│  ┌──────────┐ │                               └───────────────┘
│  │libsodium │ │
│  │ X3DH     │ │
│  │ Ratchet  │ │
│  │ Sealed   │ │
│  │ Groups   │ │
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

## What Is NOT Protected

See [THREAT_MODEL.md](./THREAT_MODEL.md) for a full threat analysis and
[CRYPTO_LIMITS.md](./CRYPTO_LIMITS.md) for remaining considerations.
