# Security Claims & Evidence Mapping

> **Version:** 1.0
> **Date:** 2026-02-10
> **Purpose:** Map each security claim to the code and tests that back it up.
> Unsubstantiated claims are flagged.

## Claim Evidence Table

### Message Confidentiality

| Claim | Code | Tests | Verified |
|-------|------|-------|----------|
| Messages are encrypted with XChaCha20-Poly1305 | `envelope.ts:encrypt()` L26-40 | `crypto.test.ts`: "should encrypt and decrypt" | Yes |
| Server never sees plaintext | `server/index.ts` — only forwards `envelope` object | No server test | **Partial** — code review only, no integration test |
| AAD binds metadata to ciphertext | `envelope.ts:buildAAD()` | `crypto.test.ts`: "should fail with tampered AAD" | Yes |
| 256-bit message keys via HKDF | `kdf.ts:hkdf()` | `crypto.test.ts`: "should produce correct length" | Yes |
| 24-byte random nonces (negligible collision) | `envelope.ts` — `randombytes_buf(24)` | `crypto.test.ts`: "should produce unique nonces" | Yes |

### Forward Secrecy

| Claim | Code | Tests | Verified |
|-------|------|-------|----------|
| Ephemeral DH keys per ratchet step | `ratchet.ts:ratchetEncrypt()` — generates new keypair | `advanced.test.ts`: "should advance ratchet" | Yes |
| Past keys irrecoverable | `ratchet.ts` — old DH private key overwritten | Code review | **Partial** — no explicit test for key deletion |

### Post-Compromise Security

| Claim | Code | Tests | Verified |
|-------|------|-------|----------|
| Sessions self-heal after DH ratchet | `ratchet.ts` — new DH secret mixed into root key | `advanced.test.ts`: Double Ratchet tests | Yes |

### X3DH Key Agreement

| Claim | Code | Tests | Verified |
|-------|------|-------|----------|
| 3-4 DH computations | `x3dh.ts:computeX3DHSender()` | `advanced.test.ts`: X3DH tests | Yes |
| Signed prekey verification | `x3dh.ts` — `crypto_sign_verify_detached()` | `advanced.test.ts`: "should detect tampered signature" | Yes |
| Asynchronous session setup | `x3dh.ts` — uses published prekey bundle | Architecture review | **Partial** — no end-to-end test |

### Sealed Sender

| Claim | Code | Tests | Verified |
|-------|------|-------|----------|
| Sender identity encrypted in envelope | `sealed-sender.ts:createSealedEnvelope()` | `advanced.test.ts`: sealed sender tests | Yes |
| Server cannot learn sender | `server/index.ts:handleSendSealed()` — no sender field | Code review | **Partial** — no server test |

### Group Messaging

| Claim | Code | Tests | Verified |
|-------|------|-------|----------|
| Ed25519 signatures on all group messages | `group.ts:GroupSession.encrypt()` | `advanced.test.ts`: group tests | Yes |
| Chain ratchet per-message keys | `group.ts` — KDF chain advance | `advanced.test.ts`: "should advance chain" | Yes |

### Replay Protection

| Claim | Code | Tests | Verified |
|-------|------|-------|----------|
| Client sliding window dedup | `replay.ts:ReplayGuard` | `crypto.test.ts`: replay tests | Yes |
| Monotonic counter enforcement | `replay.ts:MonotonicCounter` | `crypto.test.ts`: counter tests | Yes |
| Server 50K message ID cache | `server/index.ts:trackMessageId()` | **No test** | **Unverified** |

### Message Padding

| Claim | Code | Tests | Verified |
|-------|------|-------|----------|
| PKCS7-style 256-byte blocks | `padding.ts:padMessage()` | `crypto.test.ts`: padding tests (6) | Yes |
| Ciphertext length doesn't reveal plaintext | `padding.ts` — fixed block boundaries | `crypto.test.ts`: "aligned to block" | Yes |

### Encrypted Backup

| Claim | Code | Tests | Verified |
|-------|------|-------|----------|
| Argon2id with 256MB memory | `backup.ts` — `ARGON2_MEM_LIMIT = 268435456` | `advanced.test.ts`: backup tests | Yes |
| Wrong passphrase fails cleanly | `backup.ts:restoreBackup()` — AEAD auth fails | `advanced.test.ts`: "should reject wrong passphrase" | Yes |

### v2: Cipher Suite Agility

| Claim | Code | Tests | Verified |
|-------|------|-------|----------|
| Immutable suite registry | `cipher-suite.ts` — `Object.freeze()` | `v2-security.test.ts`: immutability test | Yes |
| Negotiation finds best mutual suite | `cipher-suite.ts:negotiateCipherSuite()` | `v2-security.test.ts`: negotiation tests | Yes |

### v2: Post-Quantum Hybrid KEM

| Claim | Code | Tests | Verified |
|-------|------|-------|----------|
| Hybrid combiner with domain separation | `hybrid-kem.ts:hybridHKDF()` | `v2-security.test.ts`: round-trip test | Yes |
| **PQ security** | `hybrid-kem.ts` — **uses X25519 as placeholder** | — | **NOT VERIFIED — placeholder only** |

### v2: SecureBuffer

| Claim | Code | Tests | Verified |
|-------|------|-------|----------|
| Use-after-wipe detection | `secure-buffer.ts:expose()` — throws `UseAfterWipeError` | `v2-security.test.ts`: 10 tests | Yes |
| JSON serialization prevention | `secure-buffer.ts:toJSON()` — throws | `v2-security.test.ts`: JSON test | Yes |

### v2: Protocol State Machine

| Claim | Code | Tests | Verified |
|-------|------|-------|----------|
| Invalid transitions rejected | `protocol-state.ts:transitionTo()` | `v2-security.test.ts`: 8 tests | Yes |
| State immutability | `protocol-state.ts` — `Object.freeze()` | `v2-security.test.ts`: immutability test | Yes |

### v2: TreeKEM

| Claim | Code | Tests | Verified |
|-------|------|-------|----------|
| O(log n) group updates | `treekem.ts:TreeKEMSession.update()` | **No tests** | **UNVERIFIED** |
| Ed25519 signed updates | `treekem.ts` — signature in update message | **No tests** | **UNVERIFIED** |

### v2: Metadata Resistance

| Claim | Code | Tests | Verified |
|-------|------|-------|----------|
| Uniform 4096-byte envelopes | `metadata-resistance.ts:createUniformEnvelope()` | `v2-security.test.ts`: 7 tests | Yes |
| Cover traffic indistinguishable | `metadata-resistance.ts:generateCoverMessage()` | `v2-security.test.ts`: indistinguishability | Yes |
| **Traffic analysis resistance** | `metadata-resistance.ts:CoverTrafficScheduler` | **No integration test** | **PARTIAL — standalone code only** |

### v2: Key Transparency

| Claim | Code | Tests | Verified |
|-------|------|-------|----------|
| Merkle proof verification | `key-transparency.ts:verifyMerkleProof()` | `v2-security.test.ts`: 6 tests | Yes |
| Version rollback prevention | `key-transparency.ts` — version must increase | `v2-security.test.ts`: rollback test | Yes |
| **Server-integrated transparency** | — | — | **NOT IMPLEMENTED — standalone only** |

### v2: Key Splitting

| Claim | Code | Tests | Verified |
|-------|------|-------|----------|
| 2-of-3 Shamir's Secret Sharing | `key-splitting.ts:splitSecret()` | `v2-security.test.ts`: 7 tests | Yes |
| Recovery code round-trip | `key-splitting.ts:shareToRecoveryCode()` | `v2-security.test.ts`: recovery code test | Yes |

## Summary

| Category | Claims | Verified | Partial | Unverified |
|----------|--------|----------|---------|------------|
| v1 Core | 20 | 15 | 4 | 1 |
| v2 Hardening | 14 | 9 | 2 | 3 |
| **Total** | **34** | **24** | **6** | **4** |

### Unverified Claims Requiring Attention

1. Server replay protection (no server tests)
2. PQ security (placeholder KEM)
3. TreeKEM correctness (no tests)
4. Integrated traffic analysis resistance (standalone code only)
