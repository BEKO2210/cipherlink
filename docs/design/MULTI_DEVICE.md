# Multi-Device Design Document

> **Author:** Belkis Aslani
> **Status:** Design — not yet implemented
> **Prerequisite:** This document must pass checklist review before any code is written.

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Design Goals](#2-design-goals)
3. [Architecture](#3-architecture)
4. [Device Identity Model](#4-device-identity-model)
5. [Device Linking Protocol](#5-device-linking-protocol)
6. [Per-Device Sessions](#6-per-device-sessions)
7. [Device Revocation](#7-device-revocation)
8. [Key Transparency Integration](#8-key-transparency-integration)
9. [Migration Strategy](#9-migration-strategy)
10. [Security Properties](#10-security-properties)
11. [Implementation Plan](#11-implementation-plan)
12. [Design Checklist](#12-design-checklist)

---

## 1. Problem Statement

CipherLink currently uses a **single keypair per user**, tied to one device. Users cannot:
- Use CipherLink on multiple devices simultaneously
- Migrate their identity to a new device without losing sessions
- Revoke a compromised device without losing their identity

Multi-device must be added **without weakening forward secrecy or deniability**.

## 2. Design Goals

| # | Goal | Priority |
|---|------|----------|
| G1 | Each device has its own X25519/Ed25519 keypair — no private key sharing | **Must** |
| G2 | Forward secrecy preserved — per-device Double Ratchet sessions | **Must** |
| G3 | Device linking requires explicit user action (QR code or passphrase) | **Must** |
| G4 | Compromised device can be revoked without losing user identity | **Must** |
| G5 | Key transparency tree tracks all device keys per user | **Must** |
| G6 | Senders establish sessions to all of a recipient's devices | **Must** |
| G7 | Backward-compatible — single-device users unaffected | **Must** |
| G8 | Sealed sender works per-device | **Should** |
| G9 | Group messages fan out per-device transparently | **Should** |
| G10 | Offline devices receive messages when they come online | **Should** |

### Non-Goals (Explicit)

- **No private key sharing** — devices never share long-term private keys
- **No trusted server** — the server must not be required to enforce device sets
- **No session transfer** — Double Ratchet state is non-transferable by design
- **No device sync** — message history sync is a separate feature (not in scope)

## 3. Architecture

```
User Identity (abstract)
├── Device A (phone)
│   ├── Ed25519 signing keypair (device identity)
│   ├── X25519 DH keypair (for X3DH / Double Ratchet)
│   └── Per-contact ratchet sessions
│
├── Device B (tablet)
│   ├── Ed25519 signing keypair (device identity)
│   ├── X25519 DH keypair (for X3DH / Double Ratchet)
│   └── Per-contact ratchet sessions
│
└── Device List (signed by user identity key)
    ├── { deviceId: A, devicePub: ..., addedAt: ..., sig: ... }
    └── { deviceId: B, devicePub: ..., addedAt: ..., sig: ... }
```

### Key Hierarchy

```
User Identity Key (Ed25519) — long-lived, signs device list
  │
  ├── Device A DH Key (X25519) — per-device, used for X3DH
  ├── Device A Signing Key (Ed25519) — per-device, signs messages
  │
  ├── Device B DH Key (X25519) — per-device
  └── Device B Signing Key (Ed25519) — per-device
```

The **User Identity Key** is a long-lived Ed25519 key used **only** to sign the device list. It is generated once when the user first creates their account and stored in the device's secure enclave. The same key is transferred during device linking (see §5).

## 4. Device Identity Model

### 4.1 Data Structures

```typescript
interface UserIdentity {
  /** Long-lived Ed25519 signing key — signs device lists. */
  identitySigningKey: Uint8Array;  // public
  identitySigningPriv: Uint8Array; // private — secure enclave only

  /** Signed device list — append-only, version-monotonic. */
  deviceList: SignedDeviceList;
}

interface DeviceEntry {
  deviceId: string;              // random 16-byte hex
  deviceSigningKey: Uint8Array;  // Ed25519 public
  deviceDHKey: Uint8Array;       // X25519 public
  addedAt: number;               // Unix timestamp
  revokedAt?: number;            // undefined = active
}

interface SignedDeviceList {
  version: number;               // monotonic, starts at 1
  devices: DeviceEntry[];
  signature: Uint8Array;         // Ed25519 sig by identitySigningKey
  timestamp: number;
}
```

### 4.2 Device List Invariants

1. **Version monotonicity** — each update increments `version` by exactly 1
2. **Append-only** — devices are never removed, only marked `revokedAt`
3. **Signed** — every version is signed by the user identity key
4. **Published** — the signed device list is uploaded to the server and registered in key transparency
5. **Max devices** — at most 5 active (non-revoked) devices per user

## 5. Device Linking Protocol

### 5.1 Overview

Linking a new device (Device B) to an existing device (Device A) requires:
1. User initiates linking on Device A
2. Device A displays a QR code (or generates a passphrase)
3. User scans QR / enters passphrase on Device B
4. Devices establish a secure channel and perform key transfer

### 5.2 Protocol Steps

```
Device A (existing)                     Device B (new)
────────────────────                    ─────────────────
1. Generate ephemeral X25519 keypair
2. Encode in QR: { ephemeralPub, userId }
                                        3. Scan QR code
                                        4. Generate ephemeral X25519 keypair
                                        5. Generate device keypairs:
                                           - Ed25519 signing
                                           - X25519 DH
                                        6. Derive shared secret:
                                           DH(ephB_priv, ephA_pub)
                                        7. Encrypt device public keys with shared secret
                                        8. Send to Device A via server relay
                                           { ephBPub, encrypted: { deviceSignPub, deviceDHPub } }

9.  Derive same shared secret:
    DH(ephA_priv, ephB_pub)
10. Decrypt Device B's public keys
11. Create new DeviceEntry for Device B
12. Sign updated device list
13. Encrypt user identity private key:
    XChaCha20-Poly1305(identitySigningPriv, sharedSecret)
14. Send to Device B:
    { encryptedIdentityKey, signedDeviceList }

                                        15. Decrypt identity signing key
                                        16. Store in secure enclave
                                        17. Verify device list signature
                                        18. Publish prekey bundle for new device
                                        19. ACK to Device A

20. Upload updated device list to server
21. Update key transparency tree
```

### 5.3 Security Properties

- **Channel security** — ephemeral ECDH provides confidentiality and forward secrecy
- **User verification** — QR code is shown on a trusted screen, scanned on the new device
- **No server trust** — the server only relays encrypted blobs; cannot extract keys
- **Replay prevention** — ephemeral keys are one-time-use

### 5.4 Alternative: Passphrase-Based Linking

For cases where QR scanning is impractical:
1. Device A generates a 24-word BIP39 mnemonic
2. User manually enters it on Device B
3. Both devices derive shared secret via Argon2id(passphrase, userId)
4. Continue from step 7 above

## 6. Per-Device Sessions

### 6.1 Fan-Out Model

When Alice sends a message to Bob, she must encrypt it for **each of Bob's active devices** separately.

```
Alice                         Server                        Bob
──────                        ──────                        ───
1. Fetch Bob's device list
2. For each device D in Bob's active devices:
   a. Check for existing ratchet session with D
   b. If no session: perform X3DH with D's prekey bundle
   c. Encrypt message with D's ratchet session
   d. Send envelope to server with deviceId
                              3. Route envelope to
                                 correct device by
                                 (recipientPub, deviceId)
                                                            4. Each device decrypts
                                                               with its own ratchet
```

### 6.2 Session Establishment

- Each device publishes its own prekey bundle (SPK + OPKs signed by its device signing key)
- Senders perform X3DH independently with each device
- Each device maintains independent Double Ratchet state

### 6.3 Optimization: Send-to-Primary

To reduce fan-out cost for users with many devices:
- The device list designates one device as "primary"
- Senders can encrypt to primary only, plus a lightweight "notification" to other devices
- Non-primary devices fetch the full message from primary via an intra-user encrypted channel
- **This is an optimization only** — the default is full fan-out

### 6.4 Group Messages

For group messages (Sender Keys / TreeKEM):
- Each device of a group member must be part of the group tree
- Sender keys are distributed per-device via pairwise channels
- TreeKEM leaf nodes represent devices, not users

## 7. Device Revocation

### 7.1 Revocation Steps

```
1. User marks device D as revoked on any active device
2. Active device:
   a. Sets revokedAt on device D's entry
   b. Increments device list version
   c. Signs new device list
   d. Uploads to server
   e. Updates key transparency tree
3. Server:
   a. Stops routing messages to device D
   b. Deletes device D's prekey bundles
   c. Notifies other devices that list was updated
4. Other active devices:
   a. Delete ratchet sessions with device D
   b. For groups: exclude device D from TreeKEM
```

### 7.2 Compromised Device Handling

If a device is lost or stolen:
1. User revokes from another device (requires identity signing key)
2. All contacts are notified of the device list change
3. Contacts delete ratchet sessions with the revoked device
4. Forward secrecy ensures past messages remain protected
5. New messages are only sent to remaining active devices

### 7.3 Last-Device Recovery

If all devices are lost, the user must recover their identity signing key from backup:
- **Shamir key splitting** (2-of-3) enables recovery if at least 2 shares are accessible
- After recovery, the user creates a new device and publishes a new device list
- All previous device sessions are lost — contacts must re-establish

## 8. Key Transparency Integration

### 8.1 Changes to Key Transparency Tree

Current tree entries:
```
{ userIdHash, publicKey, timestamp, version }
```

Multi-device entries:
```
{
  userIdHash,
  identitySigningKey,       // user-level identity
  signedDeviceList,         // full device list with signature
  timestamp,
  version                   // device list version
}
```

### 8.2 Verification

Contacts verify:
1. The device list is signed by the user's identity signing key
2. The identity signing key matches what's in the key transparency tree
3. The tree root is consistent with previous observations (non-equivocation)
4. The device list version is ≥ their last-seen version (anti-rollback)

### 8.3 Safety Numbers

Safety numbers are computed from the **user identity signing key** (not device keys):
- This means safety numbers don't change when devices are added/removed
- Users only need to re-verify if the identity signing key changes (account reset)

## 9. Migration Strategy

### 9.1 Backward Compatibility

- **Single-device users** are unaffected — their existing X25519 key becomes both device DH key and (effectively) user identity key
- **Wire format** — envelopes gain an optional `deviceId` field; absence means single-device
- **Server** — routes by `(recipientPub, deviceId)` if present, falls back to `recipientPub` only
- **Prekey bundles** — gain an optional `deviceId` field

### 9.2 Upgrade Path

1. User installs update on existing device
2. App generates a new Ed25519 identity signing key
3. Creates device list v1 with the current device as the only entry
4. Signs and publishes device list
5. Updates key transparency entry
6. User can now link additional devices

### 9.3 Rollout Phases

| Phase | Scope | Risk |
|-------|-------|------|
| Phase A | Device list data structures + signing | Low — no behavior change |
| Phase B | Device linking protocol (QR + passphrase) | Medium — key transfer |
| Phase C | Per-device session establishment | Medium — fan-out logic |
| Phase D | Device revocation + key transparency updates | Medium — state management |
| Phase E | Group protocol per-device fan-out | High — TreeKEM changes |

## 10. Security Properties

### 10.1 Preserved Properties

| Property | How |
|----------|-----|
| Forward secrecy | Per-device Double Ratchet; compromising one device doesn't reveal other devices' sessions |
| Post-compromise security | DH ratchet per device; revoking a device + rotating keys heals |
| Deniability | Per-device ephemeral keys; no cross-device key correlation |
| Sealed sender | Works per-device; server doesn't learn which device a sealed message targets |
| Zero-knowledge server | Server only sees encrypted blobs + routing metadata (publicKey, deviceId) |

### 10.2 New Attack Surfaces

| Attack | Mitigation |
|--------|------------|
| Malicious device link (attacker adds their device) | QR code or passphrase verified on trusted device |
| Device list rollback (hide revocation) | Monotonic version in key transparency; contacts check version ≥ last-seen |
| Fan-out amplification (many fake devices) | Max 5 active devices per user; server enforces |
| Identity key theft during linking | Ephemeral ECDH channel; forward-secret transfer |
| Stale device list (contact doesn't see revocation) | Contacts fetch latest device list before sending; TTL on cached lists |

### 10.3 Threat Model Updates

New entries for `docs/audit/threat-model.md`:
- **A2 (Malicious Server)**: Server could withhold device list updates → mitigated by key transparency non-equivocation
- **A5 (Device Thief)**: Stolen device can receive messages until revoked → mitigated by prompt revocation + forward secrecy
- **A7 (Network Attacker)**: Could try to intercept linking protocol → mitigated by ephemeral ECDH + QR verification

## 11. Implementation Plan

### Phase A: Data Structures (Low Risk)

**Files to create/modify:**
- `packages/crypto/src/device-identity.ts` — `DeviceEntry`, `SignedDeviceList`, signing/verification
- `packages/crypto/src/index.ts` — export new module
- `packages/crypto/__tests__/device-identity.test.ts` — unit tests for device list CRUD + signatures

**Estimated tests:** 8-10

### Phase B: Device Linking (Medium Risk)

**Files to create/modify:**
- `packages/crypto/src/device-linking.ts` — QR + passphrase linking protocol
- `apps/server/src/schema.ts` — add device linking message types
- `apps/server/src/index.ts` — relay device linking messages
- `packages/crypto/__tests__/device-linking.test.ts` — protocol tests

**Estimated tests:** 10-12

### Phase C: Per-Device Sessions (Medium Risk)

**Files to modify:**
- `packages/crypto/src/x3dh.ts` — per-device prekey bundles
- `packages/crypto/src/envelope.ts` — add optional `deviceId` to envelopes
- `apps/server/src/index.ts` — route by `(recipientPub, deviceId)`
- `apps/server/src/schema.ts` — update envelope schemas
- `apps/mobile/src/lib/crypto.ts` — fan-out sending logic

**Estimated tests:** 8-10

### Phase D: Device Revocation (Medium Risk)

**Files to create/modify:**
- `packages/crypto/src/device-identity.ts` — revocation logic
- `packages/crypto/src/key-transparency.ts` — device list entries
- `apps/server/src/index.ts` — handle revocation notifications
- `packages/crypto/__tests__/device-revocation.test.ts` — revocation tests

**Estimated tests:** 6-8

### Phase E: Group Protocol Updates (High Risk)

**Files to modify:**
- `packages/crypto/src/treekem.ts` — device-level leaf nodes
- `packages/crypto/src/group.ts` — per-device sender key distribution
- `packages/crypto/__tests__/group-multidevice.test.ts` — group + multi-device tests

**Estimated tests:** 8-10

**Total estimated new tests:** 40-50

## 12. Design Checklist

Before implementation begins, all items must be checked:

- [ ] Forward secrecy preserved (per-device ratchets, no shared private keys)
- [ ] Post-compromise security preserved (device revocation + key rotation)
- [ ] Device linking protocol reviewed for MITM resistance
- [ ] Identity key transfer uses forward-secret ephemeral channel
- [ ] Device list signing prevents unauthorized additions
- [ ] Key transparency integration prevents rollback attacks
- [ ] Safety numbers remain stable across device changes
- [ ] Server remains zero-knowledge (no new trust assumptions)
- [ ] Fan-out cost bounded (max 5 devices)
- [ ] Backward compatible with single-device users
- [ ] Sealed sender works per-device
- [ ] Group protocols updated for per-device fan-out
- [ ] Recovery path documented (last-device loss + Shamir backup)
- [ ] Rollout can be phased without breaking existing sessions
- [ ] No new cryptographic primitives introduced (uses existing X25519, Ed25519, XChaCha20)
