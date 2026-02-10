# CipherLink Threat Model

> **Author:** Belkis Aslani
> **Status:** Skeleton / Demo — NOT for high-risk production use

## What IS Protected

| Threat | Protection | Notes |
|--------|-----------|-------|
| **Server reading messages** | XChaCha20-Poly1305 E2EE | Server never sees plaintext |
| **Message tampering in transit** | AEAD authentication tag | Any modification causes decryption failure |
| **Metadata tampering** | AAD binding | sender, recipient, timestamp, msgId bound to ciphertext |
| **Replay attacks (basic)** | Unique msgId + timestamp in AAD | Exact duplicate detection possible |
| **Sender spoofing** | Envelope senderPub verified against authenticated key | Server rejects mismatched senderPub |
| **Brute-force message keys** | 256-bit keys via HKDF-SHA256 | Computationally infeasible |
| **Nonce reuse** | 24-byte random nonces (XChaCha20) | Collision probability negligible (~2^-96 for 2^32 messages) |

## What Is NOT Protected

### High-Risk Gaps

| Threat | Status | Impact |
|--------|--------|--------|
| **No forward secrecy** | NOT MITIGATED | Compromise of long-term private key decrypts ALL past and future messages with that key |
| **No post-compromise security** | NOT MITIGATED | If a key is compromised, attacker retains access until key rotation |
| **Device compromise** | LIMITED | If attacker gains root/jailbreak access, SecureStore may be extractable |
| **Key verification (MITM)** | MANUAL ONLY | No automated key verification (TOFU, SAS, QR safety numbers) |
| **Metadata leakage** | NOT MITIGATED | Server sees who talks to whom, when, message sizes, IP addresses |

### Medium-Risk Gaps

| Threat | Status | Impact |
|--------|--------|--------|
| **No message ordering** | NOT MITIGATED | Messages may arrive out of order; no sequence numbering |
| **No delivery receipts** | PARTIAL | Basic ack/queued status but no read receipts |
| **No group messaging** | NOT IMPLEMENTED | Only pairwise (1:1) conversations |
| **No multi-device** | NOT IMPLEMENTED | Single keypair, single device |
| **No message deletion** | NOT IMPLEMENTED | No remote wipe or expiring messages |
| **Screenshot/screen recording** | NOT MITIGATED | OS-level threat, cannot prevent |
| **Push notification content** | N/A | No push notifications implemented |
| **Backup exposure** | NOT MITIGATED | Device backups may include SecureStore data |

### Server-Side Threats

| Threat | Status | Impact |
|--------|--------|--------|
| **Server DoS** | PARTIAL | Basic rate limiting only; no IP-based throttling |
| **Connection flooding** | LIMITED | No maximum connection limit per IP |
| **Queue poisoning** | PARTIAL | Queue size capped, TTL enforced |
| **TLS termination** | NOT IMPLEMENTED | WebSocket runs over `ws://` in dev; production MUST use `wss://` with TLS |
| **Server compromise** | PARTIAL | Server cannot read messages, but can drop/delay/reorder them |

## Adversary Model

### In Scope (Protected Against)

- **Passive network observer**: Cannot read message contents
- **Curious server operator**: Cannot read message contents
- **Message tamperer**: Cannot modify messages without detection

### Out of Scope (NOT Protected Against)

- **Nation-state attacker**: May exploit device, network, or metadata analysis
- **Physical device access**: Device compromise bypasses E2EE
- **Compromised long-term key**: No forward secrecy means historical messages are exposed
- **Traffic analysis**: Message timing, sizes, and communication patterns are visible
- **Active MITM at key exchange**: No automated verification; requires manual key comparison

## Recommendations for Production Hardening

1. **Implement Double Ratchet** (Signal Protocol) for forward secrecy
2. **Add key verification** via safety numbers, QR codes, or SAS
3. **Use TLS (wss://)** for all WebSocket connections
4. **Implement sealed sender** to hide sender metadata from server
5. **Add message padding** to prevent length-based analysis
6. **Implement device attestation** to verify client integrity
7. **Add secure backup/restore** with user-owned encryption keys
8. **Rate limit by IP** in addition to per-connection
9. **Add server-side TLS certificate pinning** on the client
10. **Regular security audits** by independent third parties

See [CRYPTO_LIMITS.md](./CRYPTO_LIMITS.md) for the cryptographic upgrade path.
