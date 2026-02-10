/**
 * v2 Security Hardening Test Suite
 *
 * Tests for all new v2 modules:
 * - Cipher Suite (cryptographic agility)
 * - SecureBuffer (misuse-resistant key handling)
 * - Post-Quantum Hybrid KEM
 * - Protocol State Machine
 * - Metadata Resistance (uniform envelopes, cover traffic)
 * - Key Transparency (Merkle tree)
 * - Key Splitting (Shamir's Secret Sharing)
 * - Adversarial tests (edge cases, attacks, fuzzing)
 *
 * @author Belkis Aslani
 */
import { describe, it, expect, beforeAll } from "vitest";
import {
  initSodium,
  toBase64,
  // Cipher Suite
  SUITE_CLASSICAL,
  SUITE_HYBRID_PQ,
  getCipherSuite,
  getAllCipherSuites,
  getDefaultCipherSuite,
  negotiateCipherSuite,
  validateSuitePolicy,
  // SecureBuffer
  SecureBuffer,
  UseAfterWipeError,
  // Hybrid KEM
  hybridKemKeygen,
  hybridKemEncapsulate,
  hybridKemDecapsulate,
  // Protocol State Machine
  SessionPhase,
  InvalidTransitionError,
  createSessionState,
  transitionTo,
  recordMessageSent,
  recordMessageReceived,
  shouldRotateKeys,
  describeSession,
  // Metadata Resistance
  UNIFORM_ENVELOPE_SIZE,
  EnvelopeType,
  createUniformEnvelope,
  parseUniformEnvelope,
  generateCoverMessage,
  // Key Transparency
  MerkleKeyTree,
  verifyMerkleProof,
  hashUserId,
  auditKeyEntry,
  // Key Splitting
  splitSecret,
  reconstructSecret,
  splitBackupKey,
  shareToRecoveryCode,
  recoveryCodeToShare,
} from "../src/index.js";
import sodium from "libsodium-wrappers-sumo";

beforeAll(async () => {
  await initSodium();
});

// ===== CIPHER SUITE TESTS =====
describe("CipherSuite (Cryptographic Agility)", () => {
  it("should provide classical and hybrid PQ suites", () => {
    const suites = getAllCipherSuites();
    expect(suites.length).toBeGreaterThanOrEqual(2);
    expect(suites.some((s) => s.id === 0x0001)).toBe(true);
    expect(suites.some((s) => s.id === 0x0002)).toBe(true);
  });

  it("should look up suites by ID", () => {
    const classical = getCipherSuite(0x0001);
    expect(classical.name).toBe("CLASSICAL_V1");
    expect(classical.pqProtected).toBe(false);

    const hybrid = getCipherSuite(0x0002);
    expect(hybrid.name).toBe("HYBRID_PQ_V1");
    expect(hybrid.pqProtected).toBe(true);
  });

  it("should reject unknown suite IDs", () => {
    expect(() => getCipherSuite(0xffff)).toThrow("Unknown cipher suite");
  });

  it("should negotiate the best common suite", () => {
    const ours = [SUITE_HYBRID_PQ.id, SUITE_CLASSICAL.id];
    const theirs = [SUITE_CLASSICAL.id];
    const negotiated = negotiateCipherSuite(ours, theirs);
    expect(negotiated.id).toBe(SUITE_CLASSICAL.id);
  });

  it("should prefer our first choice when both support it", () => {
    const ours = [SUITE_HYBRID_PQ.id, SUITE_CLASSICAL.id];
    const theirs = [SUITE_HYBRID_PQ.id, SUITE_CLASSICAL.id];
    const negotiated = negotiateCipherSuite(ours, theirs);
    expect(negotiated.id).toBe(SUITE_HYBRID_PQ.id);
  });

  it("should reject when no common suite exists", () => {
    expect(() => negotiateCipherSuite([0x0001], [0x0002])).toThrow(
      "No common cipher suite",
    );
  });

  it("should validate suite policies", () => {
    const pqResult = validateSuitePolicy(SUITE_CLASSICAL, { requirePQ: true });
    expect(pqResult.valid).toBe(false);

    const okResult = validateSuitePolicy(SUITE_HYBRID_PQ, { requirePQ: true });
    expect(okResult.valid).toBe(true);

    const bitsResult = validateSuitePolicy(SUITE_CLASSICAL, {
      minSecurityBits: 256,
    });
    expect(bitsResult.valid).toBe(false);
  });

  it("should default to highest security suite", () => {
    const def = getDefaultCipherSuite();
    expect(def.pqProtected).toBe(true);
  });

  it("suites should be frozen (immutable)", () => {
    expect(Object.isFrozen(SUITE_CLASSICAL)).toBe(true);
    expect(Object.isFrozen(SUITE_HYBRID_PQ)).toBe(true);
  });
});

// ===== SECURE BUFFER TESTS =====
describe("SecureBuffer (Misuse-Resistant Key Handling)", () => {
  it("should create from bytes and expose them", () => {
    const data = new Uint8Array([1, 2, 3, 4]);
    const buf = SecureBuffer.from(data);
    expect(buf.expose()).toEqual(data);
    expect(buf.length).toBe(4);
    expect(buf.isWiped).toBe(false);
    buf.wipe();
  });

  it("should throw UseAfterWipeError after wipe", () => {
    const buf = SecureBuffer.from(new Uint8Array([1, 2, 3]));
    buf.wipe();
    expect(buf.isWiped).toBe(true);
    expect(() => buf.expose()).toThrow(UseAfterWipeError);
  });

  it("should wipe idempotently", () => {
    const buf = SecureBuffer.from(new Uint8Array([5, 6, 7]));
    buf.wipe();
    buf.wipe(); // Should not throw
    expect(buf.isWiped).toBe(true);
  });

  it("fromAndWipeSource should zero the original", () => {
    const original = new Uint8Array([10, 20, 30]);
    const buf = SecureBuffer.fromAndWipeSource(original);
    expect(original[0]).toBe(0); // Wiped
    expect(buf.expose()[0]).toBe(10); // Copy preserved
    buf.wipe();
  });

  it("should generate random SecureBuffer", async () => {
    const buf = await SecureBuffer.random(32);
    expect(buf.length).toBe(32);
    expect(buf.expose().some((b) => b !== 0)).toBe(true);
    buf.wipe();
  });

  it("scope should auto-wipe after use", () => {
    const buf = SecureBuffer.from(new Uint8Array([1, 2, 3, 4]));
    const sum = SecureBuffer.scope(buf, (data) => {
      return data.reduce((a, b) => a + b, 0);
    });
    expect(sum).toBe(10);
    expect(buf.isWiped).toBe(true);
  });

  it("equals should do constant-time comparison", () => {
    const a = SecureBuffer.from(new Uint8Array([1, 2, 3]));
    const b = SecureBuffer.from(new Uint8Array([1, 2, 3]));
    const c = SecureBuffer.from(new Uint8Array([1, 2, 4]));
    expect(a.equals(b)).toBe(true);
    expect(a.equals(c)).toBe(false);
    a.wipe();
    b.wipe();
    c.wipe();
  });

  it("equals should return false for wiped buffers", () => {
    const a = SecureBuffer.from(new Uint8Array([1, 2, 3]));
    const b = SecureBuffer.from(new Uint8Array([1, 2, 3]));
    a.wipe();
    expect(a.equals(b)).toBe(false);
    b.wipe();
  });

  it("should prevent JSON serialization of secrets", () => {
    const buf = SecureBuffer.from(new Uint8Array([42]));
    expect(JSON.stringify(buf)).toContain("REDACTED");
    buf.wipe();
  });

  it("toString should not reveal content", () => {
    const buf = SecureBuffer.from(new Uint8Array(32));
    expect(buf.toString()).toContain("32 bytes");
    expect(buf.toString()).not.toContain("0");
    buf.wipe();
  });

  it("clone should produce an independent copy", () => {
    const original = SecureBuffer.from(new Uint8Array([1, 2, 3]));
    const copy = original.clone();
    original.wipe();
    expect(copy.expose()).toEqual(new Uint8Array([1, 2, 3]));
    copy.wipe();
  });
});

// ===== HYBRID KEM TESTS =====
describe("Post-Quantum Hybrid KEM (X25519 + ML-KEM-768)", () => {
  it("should generate hybrid keypairs", async () => {
    const kp = await hybridKemKeygen();
    expect(kp.classical.publicKey.length).toBe(32);
    expect(kp.classical.privateKey.length).toBe(32);
    expect(kp.pq.publicKey.length).toBeGreaterThan(32);
    expect(kp.pq.privateKey.length).toBeGreaterThan(32);
  });

  it("should encapsulate and decapsulate to same shared secret", async () => {
    const recipient = await hybridKemKeygen();

    const { sharedSecret: ssSender, ciphertext } =
      await hybridKemEncapsulate(
        recipient.classical.publicKey,
        recipient.pq.publicKey,
      );

    const ssRecipient = await hybridKemDecapsulate(
      recipient.classical.privateKey,
      recipient.classical.publicKey,
      recipient.pq.privateKey,
      recipient.pq.publicKey,
      ciphertext,
    );

    expect(toBase64(ssSender)).toBe(toBase64(ssRecipient));
    expect(ssSender.length).toBe(32);
  });

  it("should produce unique shared secrets per encapsulation", async () => {
    const recipient = await hybridKemKeygen();

    const result1 = await hybridKemEncapsulate(
      recipient.classical.publicKey,
      recipient.pq.publicKey,
    );
    const result2 = await hybridKemEncapsulate(
      recipient.classical.publicKey,
      recipient.pq.publicKey,
    );

    expect(toBase64(result1.sharedSecret)).not.toBe(
      toBase64(result2.sharedSecret),
    );
  });

  it("should fail with wrong private key", async () => {
    const recipient = await hybridKemKeygen();
    const wrongRecipient = await hybridKemKeygen();

    const { sharedSecret: ssSender, ciphertext } =
      await hybridKemEncapsulate(
        recipient.classical.publicKey,
        recipient.pq.publicKey,
      );

    const ssWrong = await hybridKemDecapsulate(
      wrongRecipient.classical.privateKey,
      wrongRecipient.classical.publicKey,
      wrongRecipient.pq.privateKey,
      wrongRecipient.pq.publicKey,
      ciphertext,
    );

    expect(toBase64(ssSender)).not.toBe(toBase64(ssWrong));
  });

  it("should generate different keypairs each time", async () => {
    const kp1 = await hybridKemKeygen();
    const kp2 = await hybridKemKeygen();
    expect(toBase64(kp1.classical.publicKey)).not.toBe(
      toBase64(kp2.classical.publicKey),
    );
  });
});

// ===== PROTOCOL STATE MACHINE TESTS =====
describe("Protocol State Machine", () => {
  it("should create session in UNINITIALIZED state", () => {
    const state = createSessionState(0x0001, false);
    expect(state.phase).toBe(SessionPhase.UNINITIALIZED);
    expect(state.cipherSuiteId).toBe(0x0001);
    expect(state.messagesSent).toBe(0);
    expect(state.epoch).toBe(0);
  });

  it("should follow valid transition path", () => {
    let state = createSessionState(0x0002, true);
    state = transitionTo(state, SessionPhase.PREKEY_PUBLISHED);
    expect(state.phase).toBe(SessionPhase.PREKEY_PUBLISHED);

    state = transitionTo(state, SessionPhase.KEY_AGREEMENT);
    expect(state.phase).toBe(SessionPhase.KEY_AGREEMENT);

    state = transitionTo(state, SessionPhase.RATCHETING);
    expect(state.phase).toBe(SessionPhase.RATCHETING);

    state = transitionTo(state, SessionPhase.CLOSED);
    expect(state.phase).toBe(SessionPhase.CLOSED);
  });

  it("should reject invalid transitions", () => {
    const state = createSessionState(0x0001, false);
    expect(() => transitionTo(state, SessionPhase.RATCHETING)).toThrow(
      InvalidTransitionError,
    );
  });

  it("should reject transitions from CLOSED", () => {
    let state = createSessionState(0x0001, false);
    state = transitionTo(state, SessionPhase.PREKEY_PUBLISHED);
    state = transitionTo(state, SessionPhase.CLOSED);
    expect(() =>
      transitionTo(state, SessionPhase.UNINITIALIZED),
    ).toThrow(InvalidTransitionError);
  });

  it("should track message counts", () => {
    let state = createSessionState(0x0001, false);
    state = transitionTo(state, SessionPhase.PREKEY_PUBLISHED);
    state = transitionTo(state, SessionPhase.KEY_AGREEMENT);
    state = transitionTo(state, SessionPhase.RATCHETING);

    state = recordMessageSent(state);
    state = recordMessageSent(state);
    state = recordMessageReceived(state);

    expect(state.messagesSent).toBe(2);
    expect(state.messagesReceived).toBe(1);
  });

  it("should reject message operations outside RATCHETING", () => {
    const state = createSessionState(0x0001, false);
    expect(() => recordMessageSent(state)).toThrow("must be RATCHETING");
  });

  it("should detect when key rotation is needed", () => {
    let state = createSessionState(0x0001, false);
    state = transitionTo(state, SessionPhase.PREKEY_PUBLISHED);
    state = transitionTo(state, SessionPhase.KEY_AGREEMENT);
    state = transitionTo(state, SessionPhase.RATCHETING);

    expect(shouldRotateKeys(state, { maxMessages: 5 })).toBe(false);

    for (let i = 0; i < 5; i++) {
      state = recordMessageSent(state);
    }
    expect(shouldRotateKeys(state, { maxMessages: 5 })).toBe(true);
  });

  it("states should be frozen (immutable)", () => {
    const state = createSessionState(0x0001, false);
    expect(Object.isFrozen(state)).toBe(true);
  });

  it("describeSession should produce readable output", () => {
    const state = createSessionState(0x0002, true);
    const desc = describeSession(state);
    expect(desc).toContain("UNINITIALIZED");
    expect(desc).toContain("0x0002");
    expect(desc).toContain("pq=yes");
  });
});

// ===== METADATA RESISTANCE TESTS =====
describe("Metadata Resistance", () => {
  it("should create uniform-size envelopes", async () => {
    const payload = new TextEncoder().encode("Hello, world!");
    const envelope = await createUniformEnvelope(EnvelopeType.REAL, payload);
    expect(envelope.length).toBe(UNIFORM_ENVELOPE_SIZE);
  });

  it("should parse uniform envelopes correctly", async () => {
    const payload = new TextEncoder().encode("Test message");
    const envelope = await createUniformEnvelope(EnvelopeType.REAL, payload);
    const parsed = parseUniformEnvelope(envelope);
    expect(parsed.type).toBe(EnvelopeType.REAL);
    expect(new TextDecoder().decode(parsed.payload)).toBe("Test message");
  });

  it("cover messages should be exactly UNIFORM_ENVELOPE_SIZE", async () => {
    const cover = await generateCoverMessage();
    expect(cover.length).toBe(UNIFORM_ENVELOPE_SIZE);
  });

  it("cover and real messages should be same size", async () => {
    const real = await createUniformEnvelope(
      EnvelopeType.REAL,
      new TextEncoder().encode("secret"),
    );
    const cover = await generateCoverMessage();
    expect(real.length).toBe(cover.length);
  });

  it("should reject envelopes of wrong size", () => {
    expect(() =>
      parseUniformEnvelope(new Uint8Array(100)),
    ).toThrow("Invalid envelope size");
  });

  it("should reject payloads that exceed max size", async () => {
    const bigPayload = new Uint8Array(UNIFORM_ENVELOPE_SIZE);
    await expect(
      createUniformEnvelope(EnvelopeType.REAL, bigPayload),
    ).rejects.toThrow("Payload too large");
  });

  it("different payloads produce indistinguishable envelope sizes", async () => {
    const short = await createUniformEnvelope(
      EnvelopeType.REAL,
      new Uint8Array(1),
    );
    const long = await createUniformEnvelope(
      EnvelopeType.REAL,
      new Uint8Array(1000),
    );
    expect(short.length).toBe(long.length);
    expect(short.length).toBe(UNIFORM_ENVELOPE_SIZE);
  });
});

// ===== KEY TRANSPARENCY TESTS =====
describe("Key Transparency (Merkle Tree)", () => {
  it("should insert and look up entries", async () => {
    const tree = new MerkleKeyTree();
    const userId = await hashUserId("alice@example.com");
    const kp = sodium.crypto_sign_keypair();

    await tree.insert({
      userIdHash: userId,
      publicKey: kp.publicKey,
      timestamp: Date.now(),
      version: 1,
    });

    const entry = tree.lookup(userId);
    expect(entry).not.toBeNull();
    expect(toBase64(entry!.publicKey)).toBe(toBase64(kp.publicKey));
  });

  it("should generate and verify Merkle proofs", async () => {
    const tree = new MerkleKeyTree();

    // Add multiple entries
    for (let i = 0; i < 5; i++) {
      const userId = await hashUserId(`user${i}@example.com`);
      const kp = sodium.crypto_sign_keypair();
      await tree.insert({
        userIdHash: userId,
        publicKey: kp.publicKey,
        timestamp: Date.now(),
        version: 1,
      });
    }

    const targetUser = await hashUserId("user2@example.com");
    const proof = tree.generateProof(targetUser);
    expect(verifyMerkleProof(proof)).toBe(true);
  });

  it("should reject version rollback", async () => {
    const tree = new MerkleKeyTree();
    const userId = await hashUserId("bob@example.com");
    const kp = sodium.crypto_sign_keypair();

    await tree.insert({
      userIdHash: userId,
      publicKey: kp.publicKey,
      timestamp: Date.now(),
      version: 2,
    });

    await expect(
      tree.insert({
        userIdHash: userId,
        publicKey: kp.publicKey,
        timestamp: Date.now(),
        version: 1, // Rollback!
      }),
    ).rejects.toThrow("Version must increase");
  });

  it("should detect key mismatches in audit", async () => {
    const tree = new MerkleKeyTree();
    const userId = await hashUserId("carol@example.com");
    const kp = sodium.crypto_sign_keypair();
    const wrongKey = sodium.crypto_sign_keypair().publicKey;

    await tree.insert({
      userIdHash: userId,
      publicKey: kp.publicKey,
      timestamp: Date.now(),
      version: 1,
    });

    const result = auditKeyEntry(tree, userId, wrongKey);
    expect(result.valid).toBe(false);
    expect(result.message).toContain("KEY MISMATCH");
  });

  it("audit should succeed with correct key", async () => {
    const tree = new MerkleKeyTree();
    const userId = await hashUserId("dave@example.com");
    const kp = sodium.crypto_sign_keypair();

    await tree.insert({
      userIdHash: userId,
      publicKey: kp.publicKey,
      timestamp: Date.now(),
      version: 1,
    });

    const result = auditKeyEntry(tree, userId, kp.publicKey);
    expect(result.valid).toBe(true);
  });

  it("root hash should change on any modification", async () => {
    const tree = new MerkleKeyTree();
    const userId1 = await hashUserId("user1@test.com");
    const kp1 = sodium.crypto_sign_keypair();

    const root1 = await tree.insert({
      userIdHash: userId1,
      publicKey: kp1.publicKey,
      timestamp: Date.now(),
      version: 1,
    });

    const userId2 = await hashUserId("user2@test.com");
    const kp2 = sodium.crypto_sign_keypair();

    const root2 = await tree.insert({
      userIdHash: userId2,
      publicKey: kp2.publicKey,
      timestamp: Date.now(),
      version: 1,
    });

    expect(toBase64(root1)).not.toBe(toBase64(root2));
  });
});

// ===== KEY SPLITTING TESTS =====
describe("Key Splitting (Shamir's Secret Sharing)", () => {
  it("should split and reconstruct a secret (2-of-3)", async () => {
    const secret = sodium.randombytes_buf(32);
    const shares = await splitSecret(secret, 3, 2);
    expect(shares.length).toBe(3);

    // Any 2 shares should reconstruct
    const recovered12 = reconstructSecret([shares[0]!, shares[1]!]);
    expect(toBase64(recovered12)).toBe(toBase64(secret));

    const recovered13 = reconstructSecret([shares[0]!, shares[2]!]);
    expect(toBase64(recovered13)).toBe(toBase64(secret));

    const recovered23 = reconstructSecret([shares[1]!, shares[2]!]);
    expect(toBase64(recovered23)).toBe(toBase64(secret));
  });

  it("should split and reconstruct with 3-of-5", async () => {
    const secret = sodium.randombytes_buf(64);
    const shares = await splitSecret(secret, 5, 3);
    expect(shares.length).toBe(5);

    const recovered = reconstructSecret([shares[0]!, shares[2]!, shares[4]!]);
    expect(toBase64(recovered)).toBe(toBase64(secret));
  });

  it("should produce different shares each time (randomized)", async () => {
    const secret = sodium.randombytes_buf(32);
    const shares1 = await splitSecret(secret, 3, 2);
    const shares2 = await splitSecret(secret, 3, 2);

    // Same secret, but shares should differ (random coefficients)
    expect(toBase64(shares1[0]!.data)).not.toBe(
      toBase64(shares2[0]!.data),
    );
  });

  it("splitBackupKey should produce 3 shares", async () => {
    const key = sodium.randombytes_buf(32);
    const { deviceShare, serverShare, recoveryShare } =
      await splitBackupKey(key);

    expect(deviceShare.index).toBe(1);
    expect(serverShare.index).toBe(2);
    expect(recoveryShare.index).toBe(3);

    // Any 2 should recover
    const recovered = reconstructSecret([deviceShare, recoveryShare]);
    expect(toBase64(recovered)).toBe(toBase64(key));
  });

  it("recovery code round-trip should preserve share data", async () => {
    const key = sodium.randombytes_buf(32);
    const { recoveryShare } = await splitBackupKey(key);

    const code = shareToRecoveryCode(recoveryShare);
    expect(code).toMatch(/^[0-9A-Z]+-[0-9A-Z]+/); // Groups of chars

    const restored = recoveryCodeToShare(code);
    expect(restored.index).toBe(recoveryShare.index);
    // Data should match (recovered from recovery code)
    expect(toBase64(restored.data)).toBe(toBase64(recoveryShare.data));
  });

  it("should reject threshold < 2", async () => {
    const secret = sodium.randombytes_buf(32);
    await expect(splitSecret(secret, 3, 1)).rejects.toThrow(
      "Threshold must be at least 2",
    );
  });

  it("should reject threshold > totalShares", async () => {
    const secret = sodium.randombytes_buf(32);
    await expect(splitSecret(secret, 2, 3)).rejects.toThrow(
      "Threshold cannot exceed",
    );
  });
});

// ===== ADVERSARIAL TESTS =====
describe("Adversarial & Edge Case Tests", () => {
  it("SecureBuffer: clone after wipe should throw", () => {
    const buf = SecureBuffer.from(new Uint8Array([1]));
    buf.wipe();
    expect(() => buf.clone()).toThrow(UseAfterWipeError);
  });

  it("Protocol: cannot skip to RATCHETING from UNINITIALIZED", () => {
    const state = createSessionState(0x0001, false);
    expect(() => transitionTo(state, SessionPhase.RATCHETING)).toThrow();
    expect(() => transitionTo(state, SessionPhase.KEY_AGREEMENT)).toThrow();
  });

  it("Uniform envelope: empty payload", async () => {
    const envelope = await createUniformEnvelope(
      EnvelopeType.REAL,
      new Uint8Array(0),
    );
    expect(envelope.length).toBe(UNIFORM_ENVELOPE_SIZE);
    const parsed = parseUniformEnvelope(envelope);
    expect(parsed.payload.length).toBe(0);
  });

  it("Key transparency: lookup non-existent user returns null", async () => {
    const tree = new MerkleKeyTree();
    const fakeId = await hashUserId("nobody@example.com");
    expect(tree.lookup(fakeId)).toBeNull();
  });

  it("Shamir: reconstructing with all 3 shares should still work", async () => {
    const secret = sodium.randombytes_buf(32);
    const shares = await splitSecret(secret, 3, 2);
    const recovered = reconstructSecret(shares);
    expect(toBase64(recovered)).toBe(toBase64(secret));
  });

  it("Hybrid KEM: different recipients produce different secrets", async () => {
    const r1 = await hybridKemKeygen();
    const r2 = await hybridKemKeygen();

    const res1 = await hybridKemEncapsulate(
      r1.classical.publicKey,
      r1.pq.publicKey,
    );
    const res2 = await hybridKemEncapsulate(
      r2.classical.publicKey,
      r2.pq.publicKey,
    );

    expect(toBase64(res1.sharedSecret)).not.toBe(
      toBase64(res2.sharedSecret),
    );
  });

  it("Protocol state: RATCHETING can self-transition", () => {
    let state = createSessionState(0x0001, false);
    state = transitionTo(state, SessionPhase.PREKEY_PUBLISHED);
    state = transitionTo(state, SessionPhase.KEY_AGREEMENT);
    state = transitionTo(state, SessionPhase.RATCHETING);
    // RATCHETING → RATCHETING should be valid (epoch increment)
    state = transitionTo(state, SessionPhase.RATCHETING, { epoch: 1 });
    expect(state.epoch).toBe(1);
  });

  it("Key splitting: 1-byte secret should work", async () => {
    const secret = new Uint8Array([42]);
    const shares = await splitSecret(secret, 3, 2);
    const recovered = reconstructSecret([shares[0]!, shares[2]!]);
    expect(recovered[0]).toBe(42);
  });

  it("SecureBuffer: scope should wipe even on exception", () => {
    const buf = SecureBuffer.from(new Uint8Array([1, 2]));
    expect(() =>
      SecureBuffer.scope(buf, () => {
        throw new Error("test error");
      }),
    ).toThrow("test error");
    expect(buf.isWiped).toBe(true);
  });
});
