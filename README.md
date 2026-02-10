<div align="center">

# CipherLink

**End-to-end encrypted chat app with Signal Protocol architecture**

[![CI](https://github.com/BEKO2210/cipherlink/actions/workflows/ci.yml/badge.svg)](https://github.com/BEKO2210/cipherlink/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-e94560.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6.svg)](https://www.typescriptlang.org/)
[![Node](https://img.shields.io/badge/Node.js-20+-339933.svg)](https://nodejs.org/)
[![Expo](https://img.shields.io/badge/Expo-SDK_52-000020.svg)](https://expo.dev/)
[![libsodium](https://img.shields.io/badge/Crypto-libsodium-7c4dff.svg)](https://doc.libsodium.org/)
[![Tests](https://img.shields.io/badge/Tests-120_passing-4caf50.svg)](#testing)
[![Security Docs](https://img.shields.io/badge/Security-Documented-f5a623.svg)](docs/SECURITY_MODEL.md)

<br />

A security-first E2EE chat implementing the **Signal Protocol** with **v2 security hardening** — post-quantum hybrid KEM, MLS-inspired TreeKEM groups, metadata resistance, key transparency, Shamir key splitting, cryptographic agility, and formal protocol state machines. Zero-knowledge server. 120 passing tests.

[Live Demo](https://beko2210.github.io/cipherlink/) · [Security Model](docs/SECURITY_MODEL.md) · [Threat Model](docs/THREAT_MODEL.md) · [Crypto Design](docs/CRYPTO_LIMITS.md) · [v2 Architecture](docs/SECURITY_ARCHITECTURE_V2.md)

<br />

> **Audit recommended before high-risk production use.**
> See [CRYPTO_LIMITS.md](docs/CRYPTO_LIMITS.md) for full feature status.

</div>

---

## Overview

CipherLink implements a complete Signal Protocol-based E2EE architecture with v2 security hardening:

### v1 Core Protocol
- **X3DH key agreement** — Asynchronous session establishment with signed prekeys
- **Double Ratchet** — Forward secrecy + post-compromise security via continuous key rotation
- **Sealed sender** — Hide sender identity from the server
- **Sender Keys group messaging** — Efficient E2EE for groups with Ed25519 signatures
- **Safety numbers** — Signal-style 60-digit key verification
- **Encrypted backups** — Argon2id + XChaCha20-Poly1305 passphrase-protected backups
- **Message padding** — PKCS7-style fixed blocks prevent length analysis
- **Replay protection** — Client-side dedup + monotonic counters + server-side 50K cache
- **Zero-knowledge server** — Relay never sees plaintext, keys, or sender identity
- **Secure key storage** — iOS Keychain / Android Keystore via expo-secure-store

### v2 Security Hardening
- **Post-Quantum Hybrid KEM** — X25519 + ML-KEM-768 (Kyber) hybrid key encapsulation
- **Cryptographic Agility** — Cipher suite negotiation with immutable suite registry
- **TreeKEM Group Protocol** — MLS-inspired tree-based group key agreement with O(log n) updates
- **Metadata Resistance** — Uniform 4096-byte envelopes, cover traffic, message batching
- **Key Transparency** — Merkle tree-based verifiable key directory with signed tree heads
- **Key Splitting** — Shamir's Secret Sharing (2-of-3) for backup key recovery
- **SecureBuffer** — Misuse-resistant key handling with use-after-wipe detection
- **Protocol State Machine** — Formal session lifecycle with invariant enforcement

## How It Works

CipherLink follows the Signal Protocol architecture:

**1. Key Agreement (X3DH)** — Alice fetches Bob's prekey bundle from the server and performs 3-4 Diffie-Hellman computations to establish an initial shared secret. Bob can be offline.

**2. Session Ratcheting (Double Ratchet)** — Each message advances a symmetric KDF chain. Periodically, a new ephemeral X25519 keypair performs a DH ratchet step, introducing fresh entropy. Past keys are deleted.

**3. Encryption (XChaCha20-Poly1305 AEAD)** — Messages are padded to 256-byte blocks and encrypted with a fresh key derived from the ratchet chain. AAD binds sender, recipient, timestamp, and protocol metadata.

**4. Routing** — The server routes encrypted envelopes by recipient public key. With sealed sender, even the sender identity is encrypted. The server never sees plaintext, keys, or shared secrets.

## Project Structure

```
packages/crypto/             E2EE cryptographic library (libsodium)
  src/                       v1 Core:
    sodium.ts                  Sodium initialization
    keys.ts                    X25519 keypair generation
    kdf.ts                     HKDF-SHA256 key derivation
    envelope.ts                XChaCha20-Poly1305 encrypt/decrypt with AAD
    x3dh.ts                    X3DH key agreement (prekeys, signed prekeys)
    ratchet.ts                 Double Ratchet (DH + symmetric ratchet)
    sealed-sender.ts           Sealed sender (hide sender from server)
    group.ts                   Sender Keys group messaging
    safety-numbers.ts          Safety numbers (key verification)
    padding.ts                 PKCS7-style message padding
    replay.ts                  Replay protection (dedup + counters)
    backup.ts                  Encrypted backup (Argon2id + XChaCha20)
    base64.ts                  Base64 encoding utilities
  src/                       v2 Security Hardening:
    cipher-suite.ts            Cryptographic agility (suite negotiation)
    hybrid-kem.ts              Post-quantum hybrid KEM (X25519 + ML-KEM-768)
    secure-buffer.ts           Misuse-resistant key handling
    protocol-state.ts          Formal protocol state machine
    treekem.ts                 MLS-inspired TreeKEM group protocol
    metadata-resistance.ts     Cover traffic, batching, uniform envelopes
    key-transparency.ts        Merkle tree key directory
    key-splitting.ts           Shamir's Secret Sharing (2-of-3)
  __tests__/                 120 unit tests (vitest)

apps/server/            Zero-knowledge WebSocket relay (Node.js + ws)
  src/index.ts          Routing, auth, sealed sender, groups, replay dedup
  src/schema.ts         Zod validation (all message types)
  src/rate-limit.ts     Token-bucket rate limiter
  src/queue.ts          Offline message TTL queue

apps/mobile/            Expo React Native app
  App.tsx               App entry point
  src/screens/          Setup (key gen) + Chat (E2EE messaging)
  src/lib/              Crypto, SecureStore, WebSocket client

docs/                   Security documentation + GitHub Pages site
```

## Quick Start

### Prerequisites

| Requirement | Version |
|---|---|
| Node.js | >= 20 |
| pnpm | >= 9 |
| Expo Go | Latest (iOS / Android) |

### Install & Run

```bash
# Clone
git clone https://github.com/BEKO2210/cipherlink.git
cd cipherlink

# Install
pnpm install

# Start the relay server (ws://localhost:4200)
pnpm dev:server

# In another terminal — start the Expo app
pnpm dev:mobile
```

Scan the QR code with Expo Go on your phone.

### Testing

```bash
# Run all 120 crypto unit tests (57 v1 + 63 v2)
pnpm test

# Lint all packages
pnpm lint

# Typecheck all packages
pnpm typecheck
```

## Security Posture

### Protected Against

| Threat | How |
|---|---|
| Server reading messages | XChaCha20-Poly1305 E2EE |
| Message tampering | AEAD authentication tag |
| Metadata tampering | AAD binding (sender, recipient, time, id, version) |
| Replay attacks | Client dedup + monotonic counters + server 50K cache |
| Past message exposure | Forward secrecy via Double Ratchet |
| Ongoing key compromise | Post-compromise security via DH ratchet |
| MITM at key exchange | Safety numbers (60-digit verification) |
| Sender identity leakage | Sealed sender (ephemeral DH) |
| Message length analysis | PKCS7 padding (256-byte blocks) + uniform 4096-byte envelopes |
| Group message forgery | Ed25519 signatures (Sender Keys) |
| Backup exposure | Argon2id + XChaCha20-Poly1305 |
| Quantum computing (future) | Post-quantum hybrid KEM (X25519 + ML-KEM-768) |
| Traffic analysis | Cover traffic, message batching, timing jitter |
| Key directory tampering | Merkle tree key transparency with signed tree heads |
| Single point of backup failure | Shamir's Secret Sharing (2-of-3 key splitting) |
| Key material misuse | SecureBuffer with use-after-wipe detection |
| Protocol state confusion | Formal state machine with invariant enforcement |
| Group scalability | TreeKEM with O(log n) update complexity |

### Known Limitations

| Gap | Impact |
|---|---|
| No multi-device | Single keypair per device (X3DH enables async setup) |
| Metadata timing | Mitigated by cover traffic; full mixnet not implemented |
| No TLS in dev | Production must use wss:// |
| No message deletion | No remote wipe or disappearing messages |
| PQ KEM placeholder | ML-KEM-768 wire format ready; uses X25519 internally until native Kyber available |

Full details: **[Threat Model](docs/THREAT_MODEL.md)** · **[Crypto Design](docs/CRYPTO_LIMITS.md)**

## Tech Stack

| Component | Technology | Purpose |
|---|---|---|
| Cryptography | libsodium-wrappers-sumo | X25519, Ed25519, BLAKE2b, HKDF, XChaCha20-Poly1305, Argon2id, ML-KEM-768 (hybrid) |
| Mobile | Expo (React Native) | iOS + Android via managed workflow |
| Server | Node.js + ws | Minimal WebSocket relay |
| Validation | Zod | Schema validation for all messages |
| Key Storage | expo-secure-store | Hardware-backed secure enclave |
| Language | TypeScript (strict) | Type safety everywhere |
| Monorepo | pnpm workspaces | Package management |
| Testing | Vitest | 120 unit tests for crypto |
| CI | GitHub Actions | Lint, typecheck, test on every push |

## Cryptographic Modules

### v1 Core

| Module | Protocol | Description |
|---|---|---|
| `x3dh.ts` | X3DH | Key agreement with signed prekeys + one-time prekeys |
| `ratchet.ts` | Double Ratchet | Forward secrecy + post-compromise security |
| `sealed-sender.ts` | Sealed Sender | Hide sender from server via ephemeral DH |
| `group.ts` | Sender Keys | Group E2EE with chain ratchet + Ed25519 signing |
| `safety-numbers.ts` | Safety Numbers | 60-digit key verification (5200x SHA-512) |
| `padding.ts` | PKCS7 Padding | Fixed 256-byte blocks prevent length analysis |
| `replay.ts` | Replay Guard | Sliding window dedup + monotonic counters |
| `backup.ts` | Encrypted Backup | Argon2id KDF + XChaCha20-Poly1305 |
| `envelope.ts` | V1 Envelope | XChaCha20-Poly1305 AEAD with AAD |
| `kdf.ts` | HKDF-SHA256 | RFC 5869 key derivation |

### v2 Security Hardening

| Module | Protocol | Description |
|---|---|---|
| `cipher-suite.ts` | Cipher Suite | Cryptographic agility with immutable suite registry |
| `hybrid-kem.ts` | Hybrid KEM | Post-quantum X25519 + ML-KEM-768 key encapsulation |
| `secure-buffer.ts` | SecureBuffer | Misuse-resistant key wrapper with auto-wipe |
| `protocol-state.ts` | State Machine | Formal session lifecycle with invariant enforcement |
| `treekem.ts` | TreeKEM | MLS-inspired tree-based group key agreement |
| `metadata-resistance.ts` | Metadata | Uniform envelopes, cover traffic, message batching |
| `key-transparency.ts` | Key Transparency | Merkle tree key directory with signed tree heads |
| `key-splitting.ts` | Key Splitting | Shamir's Secret Sharing over GF(256) |

## Security Documentation

| Document | Description |
|---|---|
| [SECURITY_MODEL.md](docs/SECURITY_MODEL.md) | Architecture, protocol flow, key storage, server role |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | What is protected, what isn't, adversary model |
| [CRYPTO_LIMITS.md](docs/CRYPTO_LIMITS.md) | Full feature status, remaining considerations, test coverage |
| [SECURITY_ARCHITECTURE_V2.md](docs/SECURITY_ARCHITECTURE_V2.md) | v2 threat model, attack surface review, upgrade plan |

## License

[MIT](LICENSE)

## Author

**Belkis Aslani**

---

<div align="center">

**[Live Demo](https://beko2210.github.io/cipherlink/)** · **[GitHub](https://github.com/BEKO2210/cipherlink)** · **[Security Docs](docs/SECURITY_MODEL.md)**

</div>
