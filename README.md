# CipherLink

**End-to-end encrypted chat app skeleton** — by **Belkis Aslani**

> **WARNING: This is a security skeleton for educational and demo purposes.
> It is NOT suitable for high-risk production use without significant hardening.
> See [docs/CRYPTO_LIMITS.md](docs/CRYPTO_LIMITS.md) for what's missing.**

## What Is This?

CipherLink is a best-practice, hard-to-break E2EE chat skeleton featuring:

- **Zero-knowledge server** — the relay never sees plaintext messages
- **X25519 key exchange** + **HKDF-SHA256** key derivation
- **XChaCha20-Poly1305 AEAD** encryption with authenticated associated data
- **Expo React Native** mobile app with secure key storage
- **libsodium** for all cryptographic operations
- Comprehensive security documentation

## Architecture

```
┌──────────────┐     ws (ciphertext only)     ┌──────────────┐
│  Mobile App  │◄────────────────────────────►│  Relay Server │
│  (Expo RN)   │                              │  (Node.js ws) │
│  libsodium   │                              │  zero-knowledge│
│  SecureStore  │                              │  rate-limited  │
└──────────────┘                              └──────────────┘
        │                                              │
        │              packages/crypto                 │
        └──────────── (shared E2EE primitives) ───────┘
```

## Project Structure

```
cipherlink/
├── packages/
│   └── crypto/           # E2EE cryptographic primitives (TypeScript)
│       ├── src/
│       │   ├── index.ts      # Public API
│       │   ├── sodium.ts     # libsodium initialization
│       │   ├── keys.ts       # X25519 keypair generation
│       │   ├── kdf.ts        # HKDF-SHA256 key derivation
│       │   ├── envelope.ts   # Encrypt/decrypt message envelopes
│       │   └── base64.ts     # Base64 utilities
│       └── __tests__/
│           └── crypto.test.ts
├── apps/
│   ├── server/           # Zero-knowledge WebSocket relay
│   │   └── src/
│   │       ├── index.ts      # Server entry point
│   │       ├── schema.ts     # Zod message validation
│   │       ├── rate-limit.ts # Token-bucket rate limiter
│   │       └── queue.ts      # Offline message TTL queue
│   └── mobile/           # Expo React Native app
│       ├── App.tsx           # App entry point
│       └── src/
│           ├── screens/
│           │   ├── SetupScreen.tsx  # Identity generation
│           │   └── ChatScreen.tsx   # E2EE messaging
│           └── lib/
│               ├── crypto.ts        # Mobile crypto wrapper
│               ├── secure-storage.ts# SecureStore integration
│               └── ws-client.ts     # WebSocket client
├── docs/
│   ├── SECURITY_MODEL.md    # Architecture & protocol
│   ├── THREAT_MODEL.md      # What's protected, what isn't
│   └── CRYPTO_LIMITS.md     # Missing features & upgrade roadmap
└── .github/
    └── workflows/
        └── ci.yml           # Lint, typecheck, test
```

## Quick Start

### Prerequisites

- Node.js >= 20
- pnpm >= 9
- Expo Go app on your iOS/Android device (for mobile testing)

### Install

```bash
pnpm install
```

### Run the Relay Server

```bash
pnpm dev:server
```

The server starts on `ws://localhost:4200`.

### Run the Mobile App

```bash
pnpm dev:mobile
```

Scan the QR code with Expo Go.

### Run Tests

```bash
pnpm test
```

### Lint & Typecheck

```bash
pnpm lint
pnpm typecheck
```

## How to Test E2EE

1. Start the relay server: `pnpm dev:server`
2. Open the mobile app on **two devices** (or two simulators)
3. On each device, generate an identity keypair on the Setup screen
4. Copy Device A's public key and paste it into Device B's "Recipient Public Key" field (and vice versa)
5. Connect to the server on both devices
6. Send a message — it will be encrypted on the sender's device and decrypted on the recipient's device
7. The server only sees ciphertext envelopes

## Security Documentation

- **[Security Model](docs/SECURITY_MODEL.md)** — Architecture, protocols, key storage
- **[Threat Model](docs/THREAT_MODEL.md)** — What is protected, what isn't
- **[Crypto Limits](docs/CRYPTO_LIMITS.md)** — Missing features, upgrade roadmap

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Crypto | libsodium-wrappers-sumo |
| Mobile | Expo React Native |
| Server | Node.js + ws |
| Validation | zod |
| Key Storage | expo-secure-store |
| Language | TypeScript (strict) |
| Monorepo | pnpm workspaces |
| CI | GitHub Actions |
| Tests | vitest |

## License

MIT — see [LICENSE](LICENSE)

## Author

**Belkis Aslani**
