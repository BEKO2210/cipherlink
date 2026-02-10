# CipherLink Threat Model

> **Author:** Belkis Aslani
> **Status:** v3 production-hardened E2EE — audit pack available, independent audit recommended

## What IS Protected

### v1 Core Protocol

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

### v2 Security Hardening

| Threat | Protection | Notes |
|--------|-----------|-------|
| **Quantum computing (future)** | Post-quantum hybrid KEM (X25519 + ML-KEM-768) | Harvest-now-decrypt-later defense; if EITHER component is secure, combined secret is secure |
| **Algorithm obsolescence** | Cipher suite negotiation with immutable registry | SUITE_CLASSICAL (0x0001) + SUITE_HYBRID_PQ (0x0002); future suites can be added without protocol change |
| **Traffic analysis (message size)** | Uniform 4096-byte envelopes | All messages padded to identical size; REAL/COVER/ACK/HEARTBEAT indistinguishable |
| **Traffic analysis (timing)** | Cover traffic + message batching + timing jitter | Configurable cover levels (OFF/LOW/MEDIUM/HIGH constant-rate) |
| **Key directory tampering** | Merkle tree key transparency with signed tree heads | Client-side proof verification; version rollback prevention |
| **Group key compromise (no FS)** | TreeKEM (MLS-inspired) group protocol | O(log n) updates; per-epoch forward secrecy; replaces Sender Keys for groups needing FS |
| **Single point of backup failure** | Shamir's Secret Sharing (2-of-3 key splitting) | Device + server + recovery code; any 2 shares reconstruct backup key |
| **Key material misuse** | SecureBuffer with use-after-wipe detection | RAII-style scope cleanup; JSON/toString blocked; custom inspect prevents console leaks |
| **Protocol state confusion** | Formal state machine with invariant enforcement | 5 states with validated transitions; epoch monotonicity; immutable state objects |

### v3 Production Hardening

| Threat | Protection | Notes |
|--------|-----------|-------|
| **Insecure transport** | TLS enforcement in production | `ws://` blocked in production mode; mandatory `wss://` with configurable cert paths |
| **Connection flooding** | IP-based connection limiting | Configurable max connections per IP; ping/pong keepalive detects stale connections |
| **Group fan-out abuse** | Group broadcast cap (256 members) | Prevents amplification attacks via oversized groups |
| **Log data leakage** | Sanitized structured logging | No secrets, keys, or ciphertext in logs; level-filtered output |
| **Dependency supply chain** | Dependabot + lockfile integrity checks + SBOM | Automated updates, CI hash verification, software bill of materials |

## What Is NOT Protected

### Medium-Risk Gaps

| Threat | Status | Impact |
|--------|--------|--------|
| **Device compromise** | LIMITED | If attacker gains root/jailbreak access, SecureStore may be extractable |
| **No multi-device** | DESIGN COMPLETE | Single keypair per device; [multi-device design doc](design/MULTI_DEVICE.md) complete, implementation pending |
| **No message ordering** | NOT MITIGATED | Messages may arrive out of order; skipped key handling mitigates partially |
| **No delivery receipts** | PARTIAL | Basic ack/queued status but no read receipts |
| **No message deletion** | NOT IMPLEMENTED | No remote wipe or expiring messages |
| **Screenshot/screen recording** | NOT MITIGATED | OS-level threat, cannot prevent |
| **Push notification content** | N/A | No push notifications implemented |
| **PQ KEM placeholder** | PARTIAL | ML-KEM-768 wire format ready; uses X25519 internally until native Kyber available in libsodium |

### Server-Side Threats

| Threat | Status | Impact |
|--------|--------|--------|
| **Server DoS** | MITIGATED | Token-bucket rate limiting per connection + IP-based connection limiting |
| **Connection flooding** | MITIGATED | IP-based max connection limit + ping/pong keepalive cleanup |
| **Queue poisoning** | MITIGATED | Queue size capped (100/recipient), TTL enforced (10 min) |
| **TLS termination** | ENFORCED | `wss://` mandatory in production; `ws://` blocked by config guard; configurable cert paths |
| **Server compromise** | STRONG | Server cannot read messages (E2EE), cannot learn sender (sealed sender), but can drop/delay/reorder messages |
| **Log exfiltration** | MITIGATED | Sanitized logging — no secrets, private keys, or ciphertext in log output |

## Adversary Model

### In Scope (Protected Against)

- **Passive network observer**: Cannot read message contents; message sizes obscured by padding; traffic patterns obscured by cover traffic
- **Curious server operator**: Cannot read messages; sender identity hidden via sealed sender; key directory verifiable via key transparency
- **Message tamperer**: Cannot modify messages without detection (AEAD)
- **Replay attacker**: Multi-layer deduplication rejects replayed messages (client + server)
- **Key compromise (historical)**: Forward secrecy protects past messages (Double Ratchet + TreeKEM per-epoch)
- **Key compromise (temporary)**: Post-compromise security restores confidentiality via DH ratchet
- **MITM at key exchange**: Detectable via safety number verification + key transparency Merkle proofs
- **Quantum adversary (future)**: Hybrid KEM protects key exchange against harvest-now-decrypt-later attacks
- **Traffic analyst**: Uniform 4096-byte envelopes + cover traffic + batching + timing jitter

### Out of Scope (NOT Protected Against)

- **Nation-state attacker**: May exploit device, OS, or hardware-level vulnerabilities
- **Physical device access**: Device compromise bypasses E2EE (SecureStore provides best-effort protection)
- **Full traffic analysis**: Cover traffic mitigates but full mixnet not implemented
- **Denial of service (protocol-level)**: Rate limiting and connection caps reduce but don't eliminate DoS risk
- **Compromised client software**: Malicious app build could exfiltrate keys
- **Native PQ security**: ML-KEM-768 is wire-format ready but currently uses X25519 internally

## Recommendations for Further Hardening

### Completed (v2 + v3)

1. ~~Use TLS (wss://) for all WebSocket connections in production~~ — **DONE (v3)**
2. ~~Rate limit by IP in addition to per-connection~~ — **DONE (v3)**
3. ~~Post-quantum hybrid KEM~~ — **DONE (v2)** — wire format ready, native Kyber pending
4. ~~Key transparency log~~ — **DONE (v2)**
5. ~~Cover traffic and metadata resistance~~ — **DONE (v2)**
6. ~~Formal protocol state machine~~ — **DONE (v2)**
7. ~~SecureBuffer for memory protection~~ — **DONE (v2)**
8. ~~Shamir key splitting for backups~~ — **DONE (v2)**
9. ~~Audit-ready documentation pack~~ — **DONE (v3)**
10. ~~Property-based + fuzz + adversarial testing~~ — **DONE (v3)**

### Remaining

1. **Implement multi-device** — design doc complete, per-device sessions + device revocation
2. **Add header encryption** to hide ratchet public keys from observers
3. **Implement private contact discovery** (server-side PSI)
4. **Add device attestation** to verify client integrity
5. **Add TLS certificate pinning** on mobile clients
6. **Implement disappearing messages** with client-enforced expiry
7. **Replace PQ KEM placeholder** with native ML-KEM-768 when libsodium ships Kyber
8. **Server integration tests** for relay, routing, rate limiting, replay dedup
9. **Independent security audit** by third party
10. **Bug bounty program** for ongoing vulnerability discovery

See [CRYPTO_LIMITS.md](./CRYPTO_LIMITS.md) for the full feature status and remaining considerations.
