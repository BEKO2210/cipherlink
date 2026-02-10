<div align="center">

# CipherLink

**End-to-end encrypted chat app skeleton**

[![CI](https://github.com/BEKO2210/cipherlink/actions/workflows/ci.yml/badge.svg)](https://github.com/BEKO2210/cipherlink/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-e94560.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6.svg)](https://www.typescriptlang.org/)
[![Node](https://img.shields.io/badge/Node.js-20+-339933.svg)](https://nodejs.org/)
[![Expo](https://img.shields.io/badge/Expo-SDK_52-000020.svg)](https://expo.dev/)
[![libsodium](https://img.shields.io/badge/Crypto-libsodium-7c4dff.svg)](https://doc.libsodium.org/)
[![Tests](https://img.shields.io/badge/Tests-20_passing-4caf50.svg)](#testing)
[![Security Docs](https://img.shields.io/badge/Security-Documented-f5a623.svg)](docs/SECURITY_MODEL.md)

<br />

A production-grade, security-first E2EE chat skeleton using **X25519**, **HKDF-SHA256**, and **XChaCha20-Poly1305**. Zero-knowledge server. Best-practice cryptography. Comprehensive security documentation.

[Live Demo](https://beko2210.github.io/cipherlink/) · [Security Model](docs/SECURITY_MODEL.md) · [Threat Model](docs/THREAT_MODEL.md) · [Crypto Limits](docs/CRYPTO_LIMITS.md)

<br />

> **This is a security skeleton for educational and demo purposes.**
> **Not suitable for high-risk production use without significant hardening.**
> See [CRYPTO_LIMITS.md](docs/CRYPTO_LIMITS.md) for what's missing.

</div>

---

## Overview

CipherLink demonstrates best-practice end-to-end encryption in a mobile chat app:

- **Zero-knowledge server** — the relay never sees plaintext messages
- **X25519 key exchange** — Curve25519 elliptic-curve Diffie-Hellman
- **HKDF-SHA256** — RFC 5869 compliant key derivation
- **XChaCha20-Poly1305 AEAD** — encryption with authenticated associated data
- **Expo React Native** — runs on iOS and Android via Expo Go
- **Secure key storage** — iOS Keychain / Android Keystore via expo-secure-store
- **Comprehensive documentation** — threat model, security architecture, crypto limitations

## How It Works

CipherLink uses a three-stage encryption pipeline for every message:

**1. Key Exchange** — Both parties hold X25519 keypairs. They compute a shared secret via elliptic-curve Diffie-Hellman (`AlicePriv × BobPub = BobPriv × AlicePub`), without ever transmitting the secret.

**2. Key Derivation** — The raw shared secret is passed through HKDF-SHA256 (Extract-then-Expand) with a fixed info string to produce a 256-bit message encryption key.

**3. Encryption** — Each message is encrypted with XChaCha20-Poly1305 AEAD using a fresh 24-byte random nonce. Associated data (AAD) binds the sender, recipient, timestamp, message ID, and protocol version to the ciphertext — any tampering causes decryption to fail.

The server only routes encrypted envelopes by recipient public key. It never sees plaintext, keys, or shared secrets.

## Project Structure

```
packages/crypto/        E2EE cryptographic primitives (libsodium)
  src/sodium.ts         Sodium initialization
  src/keys.ts           X25519 keypair generation
  src/kdf.ts            HKDF-SHA256 key derivation
  src/envelope.ts       XChaCha20-Poly1305 encrypt/decrypt with AAD
  src/base64.ts         Base64 encoding utilities
  __tests__/            20 unit tests (vitest)

apps/server/            Zero-knowledge WebSocket relay (Node.js + ws)
  src/index.ts          Server entry, routing, auth
  src/schema.ts         Zod message validation
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
# Run all 20 crypto unit tests
pnpm test

# Lint all packages
pnpm lint

# Typecheck all packages
pnpm typecheck
```

## Testing E2EE End-to-End

1. Start the relay server: `pnpm dev:server`
2. Open the mobile app on **two devices** (or two simulators)
3. On each device, generate an identity keypair on the Setup screen
4. Copy Device A's public key and paste it into Device B's recipient field (and vice versa)
5. Connect to the server on both devices
6. Send a message — encrypted on sender, decrypted on recipient
7. The server only ever sees ciphertext

## Security Posture

### Protected Against

| Threat | How |
|---|---|
| Server reading messages | XChaCha20-Poly1305 E2EE |
| Message tampering | AEAD authentication tag |
| Metadata tampering | AAD binding (sender, recipient, time, id, version) |
| Sender spoofing | Server verifies senderPub matches authenticated key |
| Brute-force keys | 256-bit keys via HKDF-SHA256 |
| Nonce reuse | 24-byte random nonces (XChaCha20) |

### Known Limitations

| Gap | Impact |
|---|---|
| No forward secrecy | Key compromise exposes all past messages |
| No Double Ratchet | Static key per conversation pair |
| Metadata visible to server | Who, when, message sizes, IPs |
| Manual key verification only | No automated TOFU or safety numbers |
| No group messaging | Pairwise (1:1) only |
| No multi-device | Single keypair, single device |

Full details: **[Threat Model](docs/THREAT_MODEL.md)** · **[Crypto Limits](docs/CRYPTO_LIMITS.md)**

## Tech Stack

| Component | Technology | Purpose |
|---|---|---|
| Cryptography | libsodium-wrappers-sumo | X25519, HKDF, XChaCha20-Poly1305 |
| Mobile | Expo (React Native) | iOS + Android via managed workflow |
| Server | Node.js + ws | Minimal WebSocket relay |
| Validation | Zod | Schema validation for all messages |
| Key Storage | expo-secure-store | Hardware-backed secure enclave |
| Language | TypeScript (strict) | Type safety everywhere |
| Monorepo | pnpm workspaces | Package management |
| Testing | Vitest | 20 unit tests for crypto |
| CI | GitHub Actions | Lint, typecheck, test on every push |

## Security Documentation

| Document | Description |
|---|---|
| [SECURITY_MODEL.md](docs/SECURITY_MODEL.md) | Architecture, protocol flow, key storage, server role |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | What is protected, what isn't, adversary model |
| [CRYPTO_LIMITS.md](docs/CRYPTO_LIMITS.md) | Missing features, upgrade roadmap to Signal/MLS |

## License

[MIT](LICENSE)

## Author

**Belkis Aslani**

---

<div align="center">

**[Live Demo](https://beko2210.github.io/cipherlink/)** · **[GitHub](https://github.com/BEKO2210/cipherlink)** · **[Security Docs](docs/SECURITY_MODEL.md)**

</div>
