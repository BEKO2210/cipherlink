# CipherLink Attack Surface Review

> **Version:** 1.0
> **Date:** 2026-02-10
> **Scope:** Client (crypto + mobile), Server (relay), Network (transport)

## 1. Client Attack Surface

### 1.1 Cryptographic Library (`packages/crypto/`)

| Entry Point | Input | Validation | Risk |
|-------------|-------|-----------|------|
| `envelope.encrypt()` | plaintext, key, AAD | Key length checked by libsodium | Low — AEAD handles auth |
| `envelope.decrypt()` | ciphertext, key, nonce, AAD | AEAD tag verification | Low — tampered data rejected |
| `x3dh.computeX3DHSender()` | Prekey bundle fields | Signature verification on signed prekey | **Medium** — malformed bundle could cause exceptions |
| `ratchet.ratchetEncrypt()` | Ratchet state, plaintext | Implicit via KDF chain | Low |
| `ratchet.ratchetDecrypt()` | Ratchet state, header, ciphertext | Skipped message key bounds (MAX_SKIP=256) | Low — bounded skip window |
| `backup.restoreBackup()` | Encrypted blob, passphrase | AEAD auth + Argon2id | Low — wrong passphrase fails cleanly |
| `key-splitting.reconstructSecret()` | Share array | Threshold check (≥2 shares) | Low |
| `key-splitting.recoveryCodeToShare()` | Human-typed string | Base32 decoding | **Medium** — invalid input could cause index errors |
| `metadata-resistance.parseUniformEnvelope()` | 4096-byte buffer | Length check, version byte | Low |
| `protocol-state.transitionTo()` | Phase enum | Valid transition map | Low — invalid transitions throw |
| `treekem.processUpdate()` | Update message from network | Ed25519 signature verification | **Medium** — tree geometry assumptions could be violated by malformed input |

### 1.2 Mobile App (`apps/mobile/`)

| Entry Point | Risk | Notes |
|-------------|------|-------|
| WebSocket connection | **High** | No TLS pinning, no certificate verification |
| QR code scanning | Low | Safety number verification is display-only |
| Clipboard (copy public key) | Low | Public data only |
| SecureStore access | Low | OS-protected; requires device unlock |

### 1.3 Key Material Exposure Points

| Location | Material | Protection | Risk |
|----------|----------|-----------|------|
| Device memory | Private keys, ratchet state | Process isolation only | **Medium** — memory dump on rooted device |
| SecureStore | Identity keypair | OS Keychain/Keystore | Low (assumes OS security) |
| Console logs | None (currently) | No secrets logged | Low — verify no debug logging adds keys |
| Backup file | Identity + state | Argon2id + XChaCha20-Poly1305 | Low |
| Error messages | None designed | — | **Verify** — stack traces could leak state |

## 2. Server Attack Surface

### 2.1 Network Inputs

| Entry Point | Input | Validation | Risk |
|-------------|-------|-----------|------|
| WebSocket `message` event | Raw JSON | Zod schema validation | Low — invalid messages rejected |
| WebSocket `connection` event | TCP connection | `maxPayload: 128KB` | **Medium** — no connection limit per IP |
| `hello` message | `publicKey` (base64) | Base64 regex + min(1) | **High** — no proof of key ownership |
| `send` envelope | Full envelope object | Zod schema + `senderPub` match | Low |
| `send_sealed` envelope | Sealed envelope | Zod schema only | **Medium** — no replay protection |
| `publish_prekeys` | Prekey bundle | Zod schema + identity key match | Low |
| `fetch_prekeys` | Target public key | Base64 regex | Low |
| `send_group` | Group message + recipients | Zod schema + recipient list | **Medium** — unbounded recipient list |

### 2.2 Server State

| State | Size Bound | Cleanup | Risk |
|-------|-----------|---------|------|
| `clients` Map | Unbounded (one per connected client) | On disconnect | **Medium** — connection flood |
| `prekeyStore` Map | Unbounded (one per registered user) | Never cleaned | **Medium** — memory growth over time |
| `recentMessageIds` Set | 50,000 max | FIFO eviction | Low |
| `offlineQueue` Map | 100 messages per recipient, 10-min TTL | Periodic (60s) | Low |

### 2.3 Server Denial of Service Vectors

| Vector | Current Mitigation | Gap |
|--------|-------------------|-----|
| Message flood (single connection) | Token bucket (30/5s) | Sufficient per-connection |
| Connection flood (single IP) | None | **No IP-based connection limit** |
| Large message | `maxPayload: 128KB` | Sufficient |
| Prekey store growth | None | **No eviction policy** |
| Group fan-out amplification | No limit on recipient count | **Could amplify to many recipients** |
| Slowloris / connection holding | No idle timeout | **No WebSocket ping/pong timeout** |

## 3. Network Attack Surface

| Attack | Current Protection | Gap |
|--------|-------------------|-----|
| Eavesdropping | E2EE (XChaCha20-Poly1305) | **Transport is ws:// — metadata visible** |
| MITM on key exchange | Safety numbers (out-of-band) | **No certificate pinning** |
| Traffic analysis | PKCS7 padding, uniform envelopes (code) | **Not integrated into transport** |
| Replay at network level | Client dedup + server 50K cache | **Sealed sender: no server replay protection** |
| Connection correlation | — | **No Tor/mixnet support** |

## 4. Dependency Attack Surface

| Dependency | Version | Role | Risk |
|------------|---------|------|------|
| `libsodium-wrappers-sumo` | ^0.7.15 | All cryptography | Low — well-audited, WASM |
| `ws` | ^8.18.0 | WebSocket server | Low — mature, minimal |
| `zod` | ^3.23.0 | Input validation | Low — no network access |
| `expo` | ~52.0.0 | Mobile framework | **Medium** — large dependency tree |
| `tsx` | ^4.16.0 | Dev server | Low — dev only |

**Gap:** No Dependabot configured. No automated vulnerability scanning.

## 5. Recommendations (Priority Order)

1. Add challenge-response to server authentication (sign a server-provided nonce)
2. Enforce TLS in production configuration
3. Add IP-based connection limits to server
4. Add server-side replay protection for sealed sender messages
5. Cap group recipient count in schema validation
6. Add WebSocket ping/pong idle timeout
7. Add prekey store eviction (TTL or max entries)
8. Add Dependabot for automated dependency updates
9. Add server integration tests
10. Integrate uniform envelopes into actual transport path
