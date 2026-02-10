# CipherLink v2 — Security Architecture & Threat Model

> **Author:** Belkis Aslani
> **Classification:** Internal Security Document
> **Status:** Architecture Specification for v2 Hardening

---

## Table of Contents

1. [Threat Model & Adversary Matrix](#1-threat-model--adversary-matrix)
2. [Attack Surface Analysis](#2-attack-surface-analysis)
3. [Cryptographic Architecture v2](#3-cryptographic-architecture-v2)
4. [Metadata Resistance Design](#4-metadata-resistance-design)
5. [Server Zero-Trust Architecture](#5-server-zero-trust-architecture)
6. [Client Security Hardening](#6-client-security-hardening)
7. [Network Layer Security](#7-network-layer-security)
8. [Protocol State Machine](#8-protocol-state-machine)
9. [Top 10 Security Upgrades](#9-top-10-security-upgrades)
10. [Upgrade Plan (Phased)](#10-upgrade-plan-phased)

---

## 1. Threat Model & Adversary Matrix

### Adversary Classes

| ID | Adversary | Capabilities | Goal |
|----|-----------|-------------|------|
| A1 | **Global Passive Adversary (GPA)** | Observes all network traffic between all parties. Cannot inject or modify. Can correlate timing, volume, endpoints. | Map social graph, traffic analysis, content inference via metadata. |
| A2 | **Malicious Server Operator** | Full control of relay server: code, storage, logs, routing. Can inject, delay, drop, reorder, replay messages. Can serve malicious updates. | Read messages, map users, build social graphs, targeted attacks. |
| A3 | **Nation-State Attacker** | GPA + legal compulsion + device access (via warrants) + supply chain influence + hardware backdoors + unlimited compute. | Mass surveillance, targeted decryption, key recovery. |
| A4 | **Supply Chain Attacker** | Compromise build pipeline, inject malicious dependencies, tamper with published packages. | Exfiltrate keys, inject backdoors into crypto primitives. |
| A5 | **Device Thief (Physical)** | Physical access to locked or unlocked device. May have forensic tools. | Extract identity keys, read message history, impersonate user. |
| A6 | **Insider Attacker** | Developer with commit access. Can introduce subtle cryptographic weaknesses. | Weaken protocol without detection. |
| A7 | **Network Attacker (Active)** | MITM position on local network. Can inject, modify, drop packets. | Downgrade attacks, key substitution, session hijacking. |
| A8 | **Quantum Adversary (Future)** | Access to cryptographically relevant quantum computer. | Break X25519/Ed25519 via Shor's algorithm. Decrypt recorded traffic. |
| A9 | **Malicious Contact** | Legitimate user who becomes adversary. Has session keys from prior communication. | Forge messages, prove authorship of deniable messages, frame user. |

### Threat Matrix

| Threat | A1 | A2 | A3 | A4 | A5 | A6 | A7 | A8 | A9 | Current Status | v2 Target |
|--------|----|----|----|----|----|----|----|----|----|----|---|
| Read message content | N | N | N* | Y | Y* | Y | N | Y | N | PROTECTED (E2EE) | PROTECTED + PQ |
| Map social graph | Y | Y | Y | N | N | N | Y | N | N | PARTIAL (sealed sender) | STRONG (traffic analysis resistance) |
| Traffic correlation | Y | Y | Y | N | N | N | Y | N | N | NOT MITIGATED | MITIGATED (cover traffic + batching) |
| Timing analysis | Y | Y | Y | N | N | N | Y | N | N | NOT MITIGATED | MITIGATED (constant-rate option) |
| Message size analysis | N | N | Y | N | N | N | N | N | N | MITIGATED (padding) | STRONG (uniform size) |
| Decrypt past traffic | N | N | Y* | N | N | N | N | Y | N | PROTECTED (ratchet FS) | PROTECTED + PQ hybrid |
| Forge identity | N | Y | Y | Y | N | Y | Y | N | N | PARTIAL (safety numbers) | STRONG (key transparency) |
| Impersonate user | N | N | Y | Y | Y* | Y | N | N | N | PROTECTED (Ed25519) | PROTECTED + PQ sigs |
| Compromise future comms | N | N | Y* | Y | Y* | Y | N | N | N | PROTECTED (PCS ratchet) | STRONG (continuous rotation) |
| Deny service | Y | Y | Y | N | N | N | Y | N | N | PARTIAL (rate limit) | STRONG (abuse resistance) |
| Prove message authorship | N | N | N | N | N | N | N | N | Y | NOT MITIGATED | MITIGATED (deniable auth) |
| Extract keys from device | N | N | Y | N | Y | N | N | N | N | PARTIAL (SecureStore) | STRONG (HSM + encrypted DB) |
| Backdoor crypto | N | N | N | Y | N | Y | N | N | N | NOT MITIGATED | MITIGATED (reproducible builds + API safety) |

**Legend:** Y = achievable, N = not achievable, * = with significant effort/cost

---

## 2. Attack Surface Analysis

### Current Attack Surfaces

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ATTACK SURFACES                               │
├──────────────────┬──────────────────────────────────────────────────┤
│ NETWORK LAYER    │ • WebSocket ws:// (no TLS in dev)               │
│                  │ • No certificate pinning                         │
│                  │ • No PQ protection for recorded traffic           │
│                  │ • Cleartext WebSocket upgrade headers             │
├──────────────────┼──────────────────────────────────────────────────┤
│ SERVER           │ • Plaintext public keys in routing table          │
│                  │ • Social graph inferable from routing             │
│                  │ • Message timing correlation                      │
│                  │ • Prekey bundle storage (identity linkable)        │
│                  │ • In-memory state (no persistence = data loss)     │
│                  │ • No anonymous auth (pubkey = identity)            │
├──────────────────┼──────────────────────────────────────────────────┤
│ PROTOCOL         │ • No crypto agility (hardcoded algorithms)        │
│                  │ • Group Sender Keys: no forward secrecy           │
│                  │ • No deniable authentication                      │
│                  │ • Sealed sender: single-hop (server still sees    │
│                  │   recipient)                                       │
│                  │ • No message franking (abuse reporting)            │
├──────────────────┼──────────────────────────────────────────────────┤
│ CLIENT           │ • Plaintext message storage in memory             │
│                  │ • No encrypted local database                     │
│                  │ • No jailbreak/root detection                     │
│                  │ • No screenshot protection                        │
│                  │ • Mobile crypto.ts is incomplete copy              │
│                  │ • Key material in JS heap (GC-unpredictable)       │
├──────────────────┼──────────────────────────────────────────────────┤
│ CRYPTOGRAPHIC    │ • X25519/Ed25519 vulnerable to quantum attack     │
│                  │ • No hybrid PQ protection                         │
│                  │ • HKDF info strings not versioned for agility      │
│                  │ • Backup: Argon2id only (no key splitting)         │
│                  │ • No formal protocol state machine                 │
├──────────────────┼──────────────────────────────────────────────────┤
│ SUPPLY CHAIN     │ • libsodium-wrappers-sumo: WASM blob             │
│                  │ • No integrity verification of dependencies       │
│                  │ • No reproducible builds                          │
│                  │ • npm ecosystem attack surface                     │
└──────────────────┴──────────────────────────────────────────────────┘
```

---

## 3. Cryptographic Architecture v2

### 3.1 Cipher Suite System (Cryptographic Agility)

```
CipherSuite = {
  id:           uint16,
  kem:          KEM algorithm,
  sig:          Signature algorithm,
  aead:         AEAD algorithm,
  hash:         Hash algorithm,
  kdf:          KDF algorithm,
}

Suite 0x0001 (CLASSICAL):
  KEM   = X25519
  SIG   = Ed25519
  AEAD  = XChaCha20-Poly1305
  HASH  = SHA-512
  KDF   = HKDF-SHA256

Suite 0x0002 (HYBRID PQ):
  KEM   = X25519 + ML-KEM-768 (Kyber)
  SIG   = Ed25519 + ML-DSA-65 (Dilithium) [future]
  AEAD  = XChaCha20-Poly1305
  HASH  = SHA-512
  KDF   = HKDF-SHA256

Suite 0x0003 (FUTURE PQ-ONLY):
  KEM   = ML-KEM-1024
  SIG   = ML-DSA-87
  AEAD  = AES-256-GCM or XChaCha20-Poly1305
  HASH  = SHA3-512
  KDF   = HKDF-SHA3-256
```

### 3.2 Post-Quantum Hybrid KEM

```
HybridKEM.Encapsulate(classicalPub, pqPub):
  (ct1, ss1) = X25519.Encapsulate(classicalPub)
  (ct2, ss2) = ML-KEM-768.Encapsulate(pqPub)
  ss = HKDF-SHA256(
    ikm = ss1 || ss2,
    salt = "CipherLink-v2-hybrid-kem",
    info = ct1 || ct2 || classicalPub || pqPub,
    len = 32
  )
  return (ct1 || ct2, ss)

HybridKEM.Decapsulate(classicalPriv, pqPriv, ct):
  (ct1, ct2) = split(ct)
  ss1 = X25519.Decapsulate(classicalPriv, ct1)
  ss2 = ML-KEM-768.Decapsulate(pqPriv, ct2)
  ss = HKDF-SHA256(
    ikm = ss1 || ss2,
    salt = "CipherLink-v2-hybrid-kem",
    info = ct1 || ct2 || classicalPub || pqPub,
    len = 32
  )
  return ss
```

**Security property:** If EITHER X25519 OR ML-KEM-768 is secure, the combined
shared secret is secure. This is the IND-CCA2 security of a hybrid KEM combiner
with domain separation.

### 3.3 Enhanced X3DH with PQ Hybrid

The X3DH protocol is extended to include post-quantum keying material:

```
Identity = {
  signingKey:    Ed25519 keypair,
  dhKey:         X25519 keypair (derived from Ed25519),
  pqKemKey:      ML-KEM-768 keypair,          // NEW
  cipherSuite:   uint16,                       // NEW
}

PrekeyBundle = {
  identityKey:   Ed25519 public,
  signedPreKey:  X25519 public + Ed25519 signature,
  oneTimePreKey: X25519 public (optional),
  pqPreKey:      ML-KEM-768 public + Ed25519 signature,  // NEW
  cipherSuite:   uint16,                                   // NEW
}
```

X3DH DH computations remain the same. Additionally:
- Alice encapsulates to Bob's `pqPreKey` → `(pqCiphertext, pqSharedSecret)`
- The combined master secret includes the PQ shared secret:
  ```
  masterSecret = HKDF(
    ikm = 0xFF..FF || DH1 || DH2 || DH3 [|| DH4] || pqSharedSecret,
    salt = zeroes,
    info = "CipherLink-v2-x3dh-" + suiteId
  )
  ```

### 3.4 Double Ratchet Enhancements

- **Continuous key rotation**: Ratchet state rotated every N messages OR T seconds
- **PQ ratchet step**: Periodically perform a PQ KEM encapsulation in the DH ratchet
  to introduce post-quantum keying material into the chain
- **Header encryption**: Encrypt ratchet public keys in message headers to prevent
  fingerprinting of ratchet state

### 3.5 MLS-Inspired TreeKEM for Groups

Replace Sender Keys with a tree-based key agreement:

```
                    [Root Key]
                   /          \
             [Node L]        [Node R]
             /     \         /     \
          [Alice] [Bob]  [Carol] [Dave]

Update Path: When Alice updates her key:
  1. Generate new leaf keypair
  2. Compute path secrets up to root
  3. Encrypt path secrets to copath nodes
  4. Broadcast update message
  → All members can derive new epoch key
  → Forward secrecy per epoch
```

**Advantages over Sender Keys:**
- Forward secrecy for groups (Sender Keys lack this)
- Post-compromise security for groups
- Efficient: O(log n) messages per key update

### 3.6 Deniable Authentication

The current X3DH + Double Ratchet already provides offline deniability
(any participant could have forged the transcript). To strengthen:

- **Triple-DH deniability**: Already present in X3DH (DH1 = IK_A × SPK_B)
- **Ring signature option**: For group messages, allow ring signatures over the
  group members' keys → any member could have authored any message
- **Designated verifier proofs**: For safety numbers, use designated-verifier
  proofs so verification transcripts are non-transferable

---

## 4. Metadata Resistance Design

### 4.1 Cover Traffic

```
CoverTrafficScheduler:
  mode: OFF | LOW | MEDIUM | HIGH

  LOW:    1 cover message per 60s when idle
  MEDIUM: 1 cover message per 30s, randomized ±10s
  HIGH:   Constant-rate sending (1 msg/5s, real or cover)

  Cover messages:
    - Encrypted to self (sealed sender to own pubkey)
    - Padded to standard message size (uniform 4096 bytes)
    - Indistinguishable from real messages to any observer
    - Server routes normally (cannot distinguish cover from real)
```

### 4.2 Message Batching

```
BatchingPolicy:
  batchWindow:    500ms - 2000ms
  maxBatchSize:   8 messages
  paddedBatchSize: Always send batches of exactly maxBatchSize
                   (pad with cover messages if < maxBatchSize real messages)

  Result: Observer sees fixed-size batches at regular intervals
          Cannot determine how many real messages exist in a batch
```

### 4.3 Uniform Message Size

All messages padded to a fixed 4096-byte envelope:
```
MessageEnvelope (4096 bytes total):
  [2 bytes]  version + flags
  [2 bytes]  payload length
  [N bytes]  encrypted payload
  [R bytes]  random padding to fill 4096 bytes
```

### 4.4 Private Contact Discovery

PSI (Private Set Intersection) protocol:
```
Client:                              Server:
  contacts = [h(c) for c in phonebook]
  blinded = [r * h(c) for c in contacts]
                    ──────────────►
                                    blinded' = [s * b for b in blinded]
                                    server_set = [s * h(u) for u in users]
                    ◄──────────────
  unblinded = [r^-1 * b' for b' in blinded']
  matches = unblinded ∩ server_set
```

Server learns nothing about non-matching contacts.
Client learns only which contacts are registered.

---

## 5. Server Zero-Trust Architecture

### 5.1 Anonymous Authentication

```
Registration:
  1. Client generates identity keypair
  2. Client computes: token = BlindSign(server_key, commitment)
  3. Server signs without seeing the identity
  4. Client unblinds → anonymous credential

Authentication:
  1. Client presents anonymous credential
  2. Server verifies credential validity (not identity)
  3. Server cannot link sessions or map users

Result: Server can verify "this is a registered user"
        without knowing WHICH user.
```

### 5.2 Key Transparency Log

Append-only Merkle tree of key-identity bindings:

```
KeyTransparencyLog:
  tree: SparseMerkleTree

  publish(userId_hash, publicKey):
    leaf = H(userId_hash || publicKey || timestamp)
    proof = tree.insert(leaf)
    return (tree.root, proof)

  audit(userId_hash, publicKey):
    proof = tree.getProof(userId_hash)
    return verify(tree.root, proof, leaf)

  monitor(userId_hash):
    // Third-party monitors watch for unauthorized key changes
    // Users verify their own entries periodically
```

### 5.3 Verifiable Server Behavior

- Server publishes commitment to its routing policy
- Clients can audit: "did the server deliver my message?"
- Delivery receipts signed by server (server-blind to content)
- Audit log of server actions (anonymous but verifiable)

---

## 6. Client Security Hardening

### 6.1 Encrypted Local Database

```
LocalEncryptedDB:
  masterKey: derived from device PIN + hardware key (if available)
  algorithm: XChaCha20-Poly1305

  Each table row encrypted independently:
    encrypted_row = Encrypt(masterKey, row_data, AAD=table_name||row_id)

  Indexes use deterministic encryption (for searchability)
  or encrypted bloom filters (for privacy)
```

### 6.2 Key Splitting for Backups

```
BackupKeySplitting:
  backupKey = random(32 bytes)

  Split via Shamir's Secret Sharing (2-of-3):
    share1: stored on device (encrypted by device PIN)
    share2: stored on backup server (encrypted by passphrase)
    share3: printed as recovery code (offline)

  Any 2 shares reconstruct backupKey
  Loss of any single share → still recoverable
```

### 6.3 Memory Protection

```
SecureBuffer:
  - Allocate via sodium_malloc (guard pages)
  - Lock in memory (sodium_mlock, prevent swapping)
  - Zero on free (sodium_memzero)
  - No exposure to JS GC heap where possible
  - Ratchet state kept in locked memory
```

### 6.4 Device Integrity

```
DeviceIntegrityCheck:
  - Detect jailbreak/root (SafetyNet/DeviceCheck)
  - Detect debugger attachment
  - Detect app tampering (code signature verification)
  - Warn user but DO NOT prevent operation
    (degraded security is better than no security)
```

---

## 7. Network Layer Security

### 7.1 Transport Security

```
Transport Requirements:
  - TLS 1.3 ONLY (no fallback to 1.2)
  - Certificate pinning (HPKP or manual pin set)
  - OCSP stapling required
  - PQ-ready: X25519Kyber768Draft00 TLS ciphersuite when available
  - Reject renegotiation
  - Minimum DHE parameter sizes enforced
```

### 7.2 WebSocket Hardening

```
WebSocket Policy:
  - Maximum message size: 8192 bytes (matches padded envelope)
  - Maximum frame size: 8192 bytes
  - Connection timeout: 30 seconds idle
  - Heartbeat: every 15 seconds
  - Rate limit: adaptive (based on abuse signals)
  - Per-IP connection limit: 10
  - Binary frames only (no text)
```

### 7.3 Mixnet Compatibility

```
Optional Tor/Mixnet Layer:
  Client → Tor/Mixnet → Server → Tor/Mixnet → Recipient

  Design considerations:
  - All messages same size (4096 bytes)
  - No client IP exposed to server
  - Timing decorrelation via batching
  - Server cannot correlate sender/recipient by timing
```

---

## 8. Protocol State Machine

### 8.1 Session States

```
SessionState:
  UNINITIALIZED → PREKEY_PUBLISHED → KEY_AGREEMENT → RATCHETING → CLOSED

  Transitions:
    UNINITIALIZED → PREKEY_PUBLISHED:
      Action: Publish prekey bundle to server
      Invariant: Identity key is generated and stored

    PREKEY_PUBLISHED → KEY_AGREEMENT:
      Action: X3DH initiated or responded
      Invariant: Shared secret derived, initial ratchet state set

    KEY_AGREEMENT → RATCHETING:
      Action: First message sent or received
      Invariant: Double ratchet advancing

    RATCHETING → RATCHETING:
      Action: Message sent/received, DH ratchet step
      Invariant: Forward secrecy maintained, keys rotated

    RATCHETING → CLOSED:
      Action: Session terminated
      Invariant: All key material zeroed

  INVALID transitions (MUST reject):
    - UNINITIALIZED → RATCHETING (skip key agreement)
    - CLOSED → any state (must create new session)
    - KEY_AGREEMENT → UNINITIALIZED (backward)
```

### 8.2 Invariants

1. **Key material never in plaintext outside secure memory**
2. **Ratchet always advances forward** (no rollback)
3. **Skipped keys have bounded lifetime** (max 256, expire after 24h)
4. **Every message has unique (session, counter) pair**
5. **Group epoch always increases** (no epoch rollback)
6. **Cover traffic indistinguishable from real traffic**

---

## 9. Top 10 Security Upgrades

| # | Upgrade | Impact | Effort | Priority |
|---|---------|--------|--------|----------|
| 1 | **Post-Quantum Hybrid KEM** | Defends against harvest-now-decrypt-later | HIGH | CRITICAL |
| 2 | **Cryptographic Agility Layer** | Future-proofs all algorithms | HIGH | CRITICAL |
| 3 | **TreeKEM Group Protocol** | Forward secrecy for groups (Sender Keys lacks this) | HIGH | HIGH |
| 4 | **Metadata Resistance (cover traffic + uniform size)** | Defeats traffic analysis | HIGH | HIGH |
| 5 | **Key Transparency Log** | Prevents server MITM on key distribution | HIGH | HIGH |
| 6 | **Formal Protocol State Machine** | Prevents undefined state transitions | MEDIUM | HIGH |
| 7 | **Deniable Authentication** | Protects users from transcript proof attacks | MEDIUM | MEDIUM |
| 8 | **Encrypted Local Database** | Protects data at rest | MEDIUM | MEDIUM |
| 9 | **Enhanced Memory Protection (SecureBuffer)** | Prevents key extraction from memory | MEDIUM | MEDIUM |
| 10 | **Security-First Test Suite** | Catches regressions, finds edge cases | HIGH | HIGH |

---

## 10. Upgrade Plan (Phased)

### Phase 1: Critical Infrastructure (Breaking Changes)

- Cipher suite system (algorithm negotiation)
- Post-quantum hybrid KEM
- Enhanced X3DH with PQ keying material
- Protocol state machine
- Uniform 4096-byte message envelopes
- Misuse-resistant API layer (SecureBuffer, safe key types)

### Phase 2: Protocol Upgrades (Breaking Changes)

- TreeKEM group protocol (replaces Sender Keys)
- Deniable authentication
- Enhanced sealed sender
- Key transparency log
- Continuous ratchet rotation policy

### Phase 3: Metadata Resistance (Non-Breaking)

- Cover traffic scheduler
- Message batching
- Private contact discovery (PSI)
- Anonymous authentication framework

### Phase 4: Client & Network Hardening (Non-Breaking)

- TLS 1.3 enforcement + certificate pinning
- Encrypted local database
- Key splitting for backups (Shamir)
- Device integrity detection
- Memory protection (SecureBuffer)

### Phase 5: Testing & Verification (Non-Breaking)

- Property-based testing (fast-check)
- Adversarial protocol tests
- Fuzz testing
- Chaos testing (message loss, reorder, duplication)
- Protocol compliance tests

---

## Breaking vs Non-Breaking Changes

| Change | Breaking? | Migration |
|--------|-----------|-----------|
| Cipher suite negotiation | YES | Version handshake; v1 clients negotiate v1 suite |
| PQ hybrid KEM | YES | New prekey bundle format; backward-compatible negotiation |
| Uniform 4096-byte envelopes | YES | Envelope version field distinguishes v1/v2 |
| TreeKEM groups | YES | New group protocol; existing groups must re-establish |
| Deniable auth | NO | Additive; existing auth still works |
| Cover traffic | NO | Client-only feature |
| Key transparency | NO | Additive server feature; existing key exchange unaffected |
| Encrypted local DB | NO | Client-only; migration encrypts existing data |
| SecureBuffer API | YES | Internal API change; no protocol impact |

---

## References

- [Signal Protocol Specifications](https://signal.org/docs/)
- [MLS RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)
- [ML-KEM (Kyber) FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [Hybrid Key Exchange in TLS 1.3 (draft-ietf-tls-hybrid-design)](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/)
- [Key Transparency (Google)](https://security.googleblog.com/2017/01/security-through-transparency.html)
- [Private Contact Discovery (Signal)](https://signal.org/blog/contact-discovery/)
- [TreeKEM: Asynchronous Decentralized Key Management](https://inria.hal.science/hal-02425247)
