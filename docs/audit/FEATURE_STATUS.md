# CipherLink Feature Status Table

> **Generated:** 2026-02-10
> **Branch:** `claude/e2ee-chat-app-scaffold-rLdb9`
> **Tests:** 120 passing (57 v1 + 63 v2)

## Status Legend

| Status | Meaning |
|--------|---------|
| **Implemented** | Code exists, tested, integrated |
| **Partial** | Code exists but has known gaps or uses placeholder components |
| **Planned** | Design documented but not implemented |
| **Not implemented** | No code or design exists |

---

## v1 Core Protocol

| Feature | Status | Module | Tests | Notes |
|---------|--------|--------|-------|-------|
| X3DH key agreement | **Implemented** | `x3dh.ts` | 5 | Ed25519 identity keys, signed prekeys, one-time prekeys |
| Double Ratchet | **Implemented** | `ratchet.ts` | 5 | DH + symmetric ratchet, MAX_SKIP=256 |
| Sealed sender | **Implemented** | `sealed-sender.ts` | 3 | Ephemeral X25519 DH, sender inside envelope |
| Sender Keys groups | **Implemented** | `group.ts` | 3 | Chain ratchet + Ed25519 signatures |
| Safety numbers | **Implemented** | `safety-numbers.ts` | 4 | 60-digit, 5200x SHA-512, QR payload |
| Encrypted backup | **Implemented** | `backup.ts` | 3 | Argon2id (256MB) + XChaCha20-Poly1305 |
| Message padding | **Implemented** | `padding.ts` | 6 | PKCS7-style, 256-byte blocks |
| Replay protection | **Implemented** | `replay.ts` | 5 | Client sliding window + monotonic counters |
| AEAD envelope | **Implemented** | `envelope.ts` | Part of core 20 | XChaCha20-Poly1305 with AAD |
| KDF | **Implemented** | `kdf.ts` | Part of core 20 | HKDF-SHA256 (RFC 5869) |

## v2 Security Hardening

| Feature | Status | Module | Tests | Notes |
|---------|--------|--------|-------|-------|
| Cipher suite agility | **Implemented** | `cipher-suite.ts` | 9 | Two suites: classical (0x0001), hybrid PQ (0x0002) |
| Post-quantum hybrid KEM | **Partial** | `hybrid-kem.ts` | 5 | X25519 combiner works. **PQ component is a placeholder** — uses X25519 internally padded to Kyber wire format. Real ML-KEM-768 awaits native library. |
| SecureBuffer | **Implemented** | `secure-buffer.ts` | 10 | Use-after-wipe detection, scope auto-cleanup |
| Protocol state machine | **Implemented** | `protocol-state.ts` | 8 | 5 states, invariant enforcement, immutable states |
| TreeKEM groups | **Partial** | `treekem.ts` | 0 | Tree geometry + key derivation works. **No tests in v2 suite.** Epoch management untested at scale. |
| Metadata resistance | **Partial** | `metadata-resistance.ts` | 7 | Uniform envelopes work. **Cover traffic scheduler uses `setInterval`** — not integrated with server/client. Batching is standalone. |
| Key transparency | **Partial** | `key-transparency.ts` | 6 | Merkle tree + proofs work locally. **No server integration** — server does not serve or sign tree heads. |
| Key splitting (Shamir) | **Implemented** | `key-splitting.ts` | 7 | GF(256) SSS, 2-of-3, recovery codes |

## Server Relay

| Feature | Status | Module | Tests | Notes |
|---------|--------|--------|-------|-------|
| WebSocket relay | **Implemented** | `server/index.ts` | 0 | Routes encrypted envelopes. **No server tests exist.** |
| Auth (hello) | **Partial** | `server/index.ts` | 0 | Public key only — **no challenge-response, no proof of key ownership.** Client just claims a public key. |
| Rate limiting | **Implemented** | `server/rate-limit.ts` | 0 | Token bucket per connection (30 burst, 5/s). **No IP-based limiting.** |
| Replay protection | **Implemented** | `server/index.ts` | 0 | 50K message ID set. Only for v1 envelopes — **sealed sender messages have no replay protection on server.** |
| Offline queue | **Implemented** | `server/queue.ts` | 0 | 10-min TTL, 100 per recipient. |
| Schema validation | **Implemented** | `server/schema.ts` | 0 | Zod discriminated union. |
| TLS/WSS | **Not implemented** | — | — | Server uses `ws://` only. No config option for TLS. |

## Infrastructure

| Feature | Status | Location | Notes |
|---------|--------|----------|-------|
| CI (lint/typecheck/test) | **Implemented** | `.github/workflows/ci.yml` | Runs on push/PR to main and claude/* branches |
| Dependabot | **Not implemented** | — | No `.github/dependabot.yml` |
| SECURITY.md | **Not implemented** | — | No responsible disclosure policy |
| Lockfile integrity | **Partial** | CI | `--frozen-lockfile` used but no hash verification |
| SBOM generation | **Not implemented** | — | No software bill of materials |
| Server tests | **Not implemented** | — | Zero server-side tests |
| Property-based tests | **Not implemented** | — | No fast-check or similar |
| Fuzz testing | **Not implemented** | — | No fuzz harnesses |

## Cross-Cutting Concerns

| Concern | Status | Notes |
|---------|--------|-------|
| Multi-device | **Not implemented** | Single keypair per device |
| Header encryption | **Not implemented** | Ratchet public keys visible in transit |
| Private contact discovery | **Planned** | PSI design in v2 architecture doc, not implemented |
| Deniable authentication | **Planned** | Discussed in v2 architecture doc, not implemented |
| Anonymous credentials | **Planned** | Discussed in v2 architecture doc, not implemented |
| Certificate pinning | **Not implemented** | Mobile client has no pinning config |
| Debug log sanitization | **Not implemented** | Server logs "Client authenticated" but no formal audit of log content |
