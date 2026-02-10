# CipherLink Security Model

> **Author:** Belkis Aslani
> **Status:** Skeleton / Demo — NOT for high-risk production use

## Architecture Overview

```
┌───────────────┐          WebSocket           ┌───────────────┐
│               │  (encrypted envelopes only)   │               │
│   Alice's     │◄────────────────────────────►│   CipherLink  │
│   Device      │                               │   Relay       │
│               │                               │   Server      │
│  ┌──────────┐ │                               │               │
│  │SecureStore│ │                               │  ┌─────────┐ │
│  │PrivKey   │ │                               │  │ In-mem   │ │
│  │PubKey    │ │                               │  │ routing  │ │
│  └──────────┘ │                               │  │ table    │ │
│               │                               │  │ (pubkey  │ │
│  ┌──────────┐ │                               │  │  -> ws)  │ │
│  │libsodium │ │                               │  └─────────┘ │
│  │ E2EE     │ │                               │               │
│  └──────────┘ │                               │  ┌─────────┐ │
└───────────────┘                               │  │ Offline  │ │
                                                │  │ queue    │ │
┌───────────────┐          WebSocket            │  │ (10min   │ │
│               │  (encrypted envelopes only)   │  │  TTL)    │ │
│   Bob's       │◄────────────────────────────►│  └─────────┘ │
│   Device      │                               │               │
│               │                               └───────────────┘
│  ┌──────────┐ │
│  │SecureStore│ │
│  │PrivKey   │ │
│  │PubKey    │ │
│  └──────────┘ │
│               │
│  ┌──────────┐ │
│  │libsodium │ │
│  │ E2EE     │ │
│  └──────────┘ │
└───────────────┘
```

## Key Design Principles

### 1. Zero-Knowledge Server

The relay server **never** has access to:
- Plaintext message content
- Private keys
- Shared secrets or message keys

The server only sees:
- Encrypted ciphertext envelopes
- Public keys (used for routing)
- Connection metadata (IP, timestamps)

### 2. End-to-End Encryption Protocol

```
Alice                                              Bob
  │                                                  │
  ├─ Generate X25519 keypair ─────────────────────── ├─ Generate X25519 keypair
  │  (AlicePub, AlicePriv)                           │  (BobPub, BobPriv)
  │                                                  │
  ├─ Shared secret = X25519(AlicePriv, BobPub) ───── ├─ Shared secret = X25519(BobPriv, AlicePub)
  │  (identical on both sides)                       │  (identical on both sides)
  │                                                  │
  ├─ Message key = HKDF-SHA256(shared_secret) ────── ├─ Message key = HKDF-SHA256(shared_secret)
  │                                                  │
  ├─ nonce = random(24 bytes)                        │
  │                                                  │
  ├─ AAD = {senderPub, recipientPub, ts, msgId, v}   │
  │                                                  │
  ├─ ciphertext = XChaCha20-Poly1305(                │
  │    key=messageKey, nonce, plaintext, AAD)         │
  │                                                  │
  ├─ Send envelope {v, msgId, ts, senderPub,         │
  │   recipientPub, nonce, aad, ciphertext}          │
  │   ──────────── via relay ────────────────────►   │
  │                                                  ├─ Verify AAD
  │                                                  ├─ Verify senderPub
  │                                                  ├─ Decrypt with same key
  │                                                  │
```

### 3. Key Storage

- **Private keys** are stored in the device's secure enclave via `expo-secure-store`
  - iOS: Keychain Services
  - Android: Android Keystore
- **Public keys** are shared openly (base64-encoded, copy/paste)
- Keys never leave the device unencrypted

### 4. Server Authentication

- Clients send a `hello` message with their public key
- The server maps `publicKey -> WebSocket connection`
- Envelope `senderPub` must match the authenticated public key
- No passwords, tokens, or sessions — identity is the keypair

### 5. Message Integrity

- **AEAD authentication**: XChaCha20-Poly1305 provides both encryption and authentication
- **Associated data (AAD)** binds metadata to the ciphertext — tampering with senderPub, recipientPub, timestamp, or msgId causes decryption to fail
- **Nonces** are 24-byte random values, ensuring uniqueness per message

### 6. Rate Limiting

- Token-bucket rate limiter per WebSocket connection
- Burst capacity: 30 messages
- Sustained rate: 5 messages/second
- Prevents flooding and basic DoS

### 7. Offline Message Queue

- Messages for offline recipients are held in-memory with a 10-minute TTL
- Maximum 100 messages per recipient in queue
- Messages are delivered when the recipient reconnects
- No persistent storage — messages are lost on server restart

## What Is NOT Protected

See [THREAT_MODEL.md](./THREAT_MODEL.md) for a full threat analysis and
[CRYPTO_LIMITS.md](./CRYPTO_LIMITS.md) for cryptographic limitations.
