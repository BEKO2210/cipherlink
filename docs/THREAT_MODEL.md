# CipherLink Threat Model

> **Author:** Belkis Aslani
> **Status:** Feature-complete E2EE skeleton — audit recommended before high-risk production use

## What IS Protected

| Threat | Protection | Notes |
|--------|-----------|-------|
| **Server reading messages** | XChaCha20-Poly1305 E2EE | Server never sees plaintext |
| **Message tampering in transit** | AEAD authentication tag | Any modification causes decryption failure |
| **Metadata tampering** | AAD binding | sender, recipient, timestamp, msgId bound to ciphertext |
| **Replay attacks** | Client-side dedup + monotonic counters + server-side 50K message ID cache | Multi-layer protection |
| **Sender spoofing** | Envelope senderPub verified against authenticated key | Server rejects mismatched senderPub |
| **Brute-force message keys** | 256-bit keys via HKDF-SHA256 | Computationally infeasible |
| **Nonce reuse** | 24-byte random nonces (XChaCha20) | Collision probability negligible (~2^-96 for 2^32 messages) |
| **Past message exposure (key compromise)** | Forward secrecy via Double Ratchet | Ephemeral DH keys + KDF chains |
| **Ongoing compromise** | Post-compromise security via DH ratchet | Sessions self-heal with fresh entropy |
| **MITM at key exchange** | Safety numbers + QR code verification | Out-of-band verification detects MITM |
| **Sender identity leakage to server** | Sealed sender (ephemeral DH) | Server only sees recipientPub + ephemeralPub |
| **Message length analysis** | PKCS7-style padding to 256-byte blocks | Ciphertext length does not reveal plaintext length |
| **Group message forgery** | Ed25519 signatures on all group messages | Sender Keys protocol with per-member signing keys |
| **Backup exposure** | Argon2id + XChaCha20-Poly1305 encrypted backups | Passphrase-based key derivation (256MB memory cost) |

## What Is NOT Protected

### Medium-Risk Gaps

| Threat | Status | Impact |
|--------|--------|--------|
| **Device compromise** | LIMITED | If attacker gains root/jailbreak access, SecureStore may be extractable |
| **No multi-device** | NOT IMPLEMENTED | Single keypair per device; X3DH enables async setup but no Sesame/MLS |
| **No message ordering** | NOT MITIGATED | Messages may arrive out of order; skipped key handling mitigates partially |
| **No delivery receipts** | PARTIAL | Basic ack/queued status but no read receipts |
| **No message deletion** | NOT IMPLEMENTED | No remote wipe or expiring messages |
| **Screenshot/screen recording** | NOT MITIGATED | OS-level threat, cannot prevent |
| **Push notification content** | N/A | No push notifications implemented |
| **Traffic analysis (timing)** | NOT MITIGATED | Connection timing patterns visible to network observer |

### Server-Side Threats

| Threat | Status | Impact |
|--------|--------|--------|
| **Server DoS** | PARTIAL | Token-bucket rate limiting per connection; no IP-based throttling |
| **Connection flooding** | LIMITED | No maximum connection limit per IP |
| **Queue poisoning** | PARTIAL | Queue size capped (100/recipient), TTL enforced (10 min) |
| **TLS termination** | NOT IMPLEMENTED | WebSocket runs over `ws://` in dev; production MUST use `wss://` with TLS |
| **Server compromise** | STRONG | Server cannot read messages (E2EE), cannot learn sender (sealed sender), but can drop/delay/reorder messages |

## Adversary Model

### In Scope (Protected Against)

- **Passive network observer**: Cannot read message contents; message sizes obscured by padding
- **Curious server operator**: Cannot read messages; sender identity hidden via sealed sender
- **Message tamperer**: Cannot modify messages without detection (AEAD)
- **Replay attacker**: Multi-layer deduplication rejects replayed messages
- **Key compromise (historical)**: Forward secrecy protects past messages
- **Key compromise (temporary)**: Post-compromise security restores confidentiality
- **MITM at key exchange**: Detectable via safety number verification

### Out of Scope (NOT Protected Against)

- **Nation-state attacker**: May exploit device, network, or traffic analysis
- **Physical device access**: Device compromise bypasses E2EE
- **Traffic analysis**: Communication patterns (who, when) visible despite sealed sender timing
- **Denial of service**: Server can be overwhelmed; messages can be dropped
- **Compromised client software**: Malicious app build could exfiltrate keys

## Recommendations for Further Hardening

1. **Use TLS (wss://)** for all WebSocket connections in production
2. **Implement multi-device** via Sesame or MLS (RFC 9420)
3. **Add header encryption** to hide ratchet public keys from observers
4. **Implement private contact discovery** (server-side PSI)
5. **Add device attestation** to verify client integrity
6. **Rate limit by IP** in addition to per-connection
7. **Add TLS certificate pinning** on mobile clients
8. **Implement disappearing messages** with client-enforced expiry
9. **Regular security audits** by independent third parties
10. **Bug bounty program** for ongoing vulnerability discovery

See [CRYPTO_LIMITS.md](./CRYPTO_LIMITS.md) for the full feature status and remaining considerations.
