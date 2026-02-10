# CipherLink Threat Model — Audit Pack

> **Version:** 1.0
> **Date:** 2026-02-10
> **Scope:** packages/crypto, apps/server, apps/mobile

## 1. Adversary Classes

| ID | Adversary | Capabilities | Goal |
|----|-----------|-------------|------|
| A1 | **Passive network observer** | Can observe all network traffic (ISP, WiFi) | Read messages, learn communication patterns |
| A2 | **Active network attacker** | Can intercept, modify, replay, drop network traffic | Tamper with messages, inject content, MITM |
| A3 | **Curious server operator** | Full access to server code, memory, and storage | Read messages, identify users, correlate activity |
| A4 | **Malicious server operator** | A3 + willing to modify server behavior | Drop/delay messages, substitute keys, selective censorship |
| A5 | **Device thief (locked)** | Physical access to locked device | Extract keys from storage |
| A6 | **Device thief (unlocked)** | Physical access to unlocked device + app access | Read messages, impersonate user |
| A7 | **Compromised client** | Attacker controls the app binary | Exfiltrate keys and plaintext |
| A8 | **Traffic analyst** | Can observe message timing, size, frequency | De-anonymize users, infer social graph |
| A9 | **Future quantum adversary** | Records ciphertext today, has quantum computer later | Decrypt archived communications |

## 2. Security Properties and Coverage

### Confidentiality

| Property | Protected Against | Evidence | Gaps |
|----------|------------------|----------|------|
| Message content confidentiality | A1, A2, A3, A4 | XChaCha20-Poly1305 AEAD; E2EE — server never sees plaintext | A6, A7 can read plaintext on device |
| Forward secrecy | A1-A4 + key compromise | Double Ratchet DH ratchet step deletes old keys | Depends on client deleting old state |
| Post-compromise security | A1-A4 after temporary compromise | DH ratchet introduces fresh entropy | Requires both parties to send messages |
| PQ resistance | A9 (partial) | Hybrid KEM structure ready | **PQ component is placeholder — no real Kyber** |

### Integrity

| Property | Protected Against | Evidence | Gaps |
|----------|------------------|----------|------|
| Message authenticity | A1, A2 | AEAD authentication tag | A4 can drop messages silently |
| Message ordering | A2 (partial) | Monotonic counters in replay guard | No sequence enforcement in transport |
| Sender authentication | A1, A3 | Sender key in AEAD AAD (v1), Ed25519 signatures (groups) | Server auth is claim-only — no challenge-response |

### Privacy

| Property | Protected Against | Evidence | Gaps |
|----------|------------------|----------|------|
| Sender anonymity (from server) | A3 | Sealed sender with ephemeral DH | Requires auth first — server knows IP |
| Message size privacy | A1, A8 (partial) | PKCS7 padding (256B blocks), uniform envelopes (4096B) | **Envelopes not used in transport yet** |
| Traffic analysis resistance | A8 (limited) | Cover traffic scheduler exists | **Not integrated — standalone code only** |
| Contact privacy | — | — | **No private contact discovery (PSI) implemented** |

### Availability

| Property | Protected Against | Evidence | Gaps |
|----------|------------------|----------|------|
| Basic DoS resistance | A2 (limited) | Token bucket rate limiter (30 burst, 5/s) | **Per-connection only — no IP-based limiting** |
| Offline message delivery | A2 (partial) | Offline queue with 10-min TTL, 100 cap | A4 can simply not deliver |

## 3. Trust Boundaries

```
┌──────────────────────────────────┐
│           USER DEVICE            │
│  ┌────────────────────────────┐  │
│  │      CipherLink App       │  │  Trust boundary: app sandbox
│  │  ┌──────────┐ ┌────────┐  │  │
│  │  │  Crypto  │ │  UI    │  │  │
│  │  │  Library │ │  Layer │  │  │
│  │  └──────────┘ └────────┘  │  │
│  └─────────────┬──────────────┘  │
│                │                 │
│  ┌─────────────▼──────────────┐  │  Trust boundary: OS secure storage
│  │    SecureStore / Keychain  │  │
│  └────────────────────────────┘  │
└────────────────┬─────────────────┘
                 │  WebSocket (ws://)
                 │
    ─ ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ─ ─ ─ ─   Trust boundary: network
                 │
┌────────────────▼─────────────────┐
│         RELAY SERVER             │
│  ┌────────────────────────────┐  │  Trust boundary: server process
│  │  Routing + Queue + Dedup  │  │
│  │  (zero-knowledge)         │  │
│  └────────────────────────────┘  │
└──────────────────────────────────┘
```

## 4. Assumptions

1. **libsodium is correct** — We rely on libsodium-wrappers-sumo for all cryptographic primitives.
2. **OS secure storage works** — expo-secure-store uses platform Keychain/Keystore; we assume these are secure against A5.
3. **Client binary is authentic** — We do not protect against A7 (compromised client). Distribution integrity is assumed.
4. **Time is approximately correct** — Replay protection uses timestamps; clock skew tolerance is not configurable.
5. **Random number generation is secure** — We rely on `crypto.getRandomValues()` / libsodium's CSPRNG.

## 5. Known Weaknesses (Ordered by Severity)

| # | Weakness | Severity | Impact | Mitigation Path |
|---|----------|----------|--------|-----------------|
| 1 | Server auth is claim-only | **High** | Any client can claim any public key; enables impersonation if network is compromised | Add challenge-response (sign server nonce with identity key) |
| 2 | No TLS enforcement | **High** | All traffic (including auth) sent in plaintext over ws:// in default config | Add TLS config guard that prevents ws:// in production |
| 3 | Sealed sender messages have no server-side replay protection | **Medium** | Attacker can replay sealed messages; client must detect | Add message ID to sealed envelope schema |
| 4 | PQ KEM is placeholder | **Medium** | No actual quantum resistance despite claims | Document clearly; swap when native Kyber available |
| 5 | Zero server tests | **Medium** | Server bugs could silently break security properties | Add server integration tests |
| 6 | No IP-based rate limiting | **Medium** | Single IP can open many connections to bypass per-connection limits | Add IP tracking layer |
| 7 | TreeKEM has no tests | **Medium** | Group protocol correctness unverified | Add integration tests |
| 8 | Cover traffic not integrated | **Low** | Metadata resistance is code-only, not functional | Integrate with transport layer |
| 9 | No SBOM or dependency auditing | **Low** | Supply-chain vulnerabilities may go unnoticed | Add Dependabot + SBOM generation |
