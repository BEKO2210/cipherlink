/**
 * Tests for all advanced crypto modules:
 * - Padding, Replay, Safety Numbers, Backup
 * - X3DH, Double Ratchet, Sealed Sender, Group Messaging
 *
 * @author Belkis Aslani
 */
import { describe, it, expect, beforeAll } from "vitest";
import {
  initSodium,
  toBase64,
  // Padding
  padMessage,
  unpadMessage,
  padString,
  unpadToString,
  // Replay
  ReplayGuard,
  MonotonicCounter,
  SessionReplayGuard,
  // Safety Numbers
  generateSafetyNumber,
  generateSafetyNumberQR,
  verifySafetyNumberQR,
  // Backup
  createBackup,
  restoreBackup,
  // X3DH
  generateFullIdentity,
  generateSignedPreKey,
  generateOneTimePreKeys,
  verifySignedPreKey,
  x3dhInitiate,
  x3dhRespond,
  createPrekeyBundle,
  // Double Ratchet
  initSessionAsInitiator,
  initSessionAsResponder,
  ratchetEncrypt,
  ratchetDecrypt,
  // Sealed Sender
  sealMessage,
  unsealMessage,
  // Group
  generateSenderKey,
  createSenderKeyDistribution,
  groupEncrypt,
  groupDecrypt,
  GroupSession,
} from "../src/index.js";

beforeAll(async () => {
  await initSodium();
});

// ===== PADDING =====
describe("padding", () => {
  it("should pad and unpad correctly", () => {
    const data = new TextEncoder().encode("Hello");
    const padded = padMessage(data, 256);
    expect(padded.length).toBe(256);
    const unpadded = unpadMessage(padded, 256);
    expect(new TextDecoder().decode(unpadded)).toBe("Hello");
  });

  it("should pad empty message", () => {
    const data = new Uint8Array(0);
    const padded = padMessage(data, 256);
    expect(padded.length).toBe(256);
    const unpadded = unpadMessage(padded, 256);
    expect(unpadded.length).toBe(0);
  });

  it("should pad exact block size correctly", () => {
    // If message is exactly block size, a full block of padding is added (PKCS7)
    const data = new Uint8Array(256);
    const padded = padMessage(data, 256);
    expect(padded.length).toBe(512); // Full extra block
    const unpadded = unpadMessage(padded, 256);
    expect(unpadded.length).toBe(256);
  });

  it("should round-trip string padding", () => {
    const msg = "This is a secret message!";
    const padded = padString(msg, 128);
    expect(padded.length).toBe(128);
    expect(unpadToString(padded, 128)).toBe(msg);
  });

  it("all padded messages of same block have same length", () => {
    const short = padMessage(new TextEncoder().encode("yes"), 256);
    const long = padMessage(
      new TextEncoder().encode("I'll be there at 3pm at the usual place"),
      256,
    );
    expect(short.length).toBe(long.length); // Both 256
  });

  it("should reject invalid padding", () => {
    const bad = new Uint8Array(256);
    bad[255] = 0; // Invalid: padding byte 0
    expect(() => unpadMessage(bad, 256)).toThrow();
  });
});

// ===== REPLAY PROTECTION =====
describe("replay protection", () => {
  describe("ReplayGuard", () => {
    it("should accept new messages", () => {
      const guard = new ReplayGuard();
      expect(guard.accept("msg-1")).toBe(true);
      expect(guard.accept("msg-2")).toBe(true);
    });

    it("should reject duplicate messages", () => {
      const guard = new ReplayGuard();
      expect(guard.accept("msg-1")).toBe(true);
      expect(guard.accept("msg-1")).toBe(false); // Replay!
    });

    it("should evict old entries", () => {
      const guard = new ReplayGuard(3);
      guard.accept("a");
      guard.accept("b");
      guard.accept("c");
      guard.accept("d"); // Evicts "a"
      expect(guard.hasSeen("a")).toBe(false);
      expect(guard.hasSeen("d")).toBe(true);
    });

    it("should export and import state", () => {
      const guard = new ReplayGuard();
      guard.accept("x");
      guard.accept("y");
      const exported = guard.export();
      const imported = ReplayGuard.import(exported);
      expect(imported.hasSeen("x")).toBe(true);
      expect(imported.hasSeen("y")).toBe(true);
      expect(imported.accept("x")).toBe(false);
    });
  });

  describe("MonotonicCounter", () => {
    it("should accept increasing counters", () => {
      const counter = new MonotonicCounter();
      expect(counter.accept(0)).toBe(true);
      expect(counter.accept(1)).toBe(true);
      expect(counter.accept(5)).toBe(true); // Gaps OK
    });

    it("should reject stale counters", () => {
      const counter = new MonotonicCounter();
      counter.accept(5);
      expect(counter.accept(3)).toBe(false);
      expect(counter.accept(5)).toBe(false); // Equal = replay
    });
  });

  describe("SessionReplayGuard", () => {
    it("should validate messages", () => {
      const guard = new SessionReplayGuard();
      const r1 = guard.validate("msg-1", 0);
      expect(r1.accepted).toBe(true);
      const r2 = guard.validate("msg-1", 1);
      expect(r2.accepted).toBe(false);
      expect(r2.reason).toBe("duplicate_message_id");
    });
  });
});

// ===== SAFETY NUMBERS =====
describe("safety numbers", () => {
  it("should generate deterministic safety numbers", async () => {
    const alice = await generateFullIdentity();
    const bob = await generateFullIdentity();

    const sn1 = await generateSafetyNumber(
      alice.dhPublicKey, toBase64(alice.dhPublicKey),
      bob.dhPublicKey, toBase64(bob.dhPublicKey),
    );
    const sn2 = await generateSafetyNumber(
      alice.dhPublicKey, toBase64(alice.dhPublicKey),
      bob.dhPublicKey, toBase64(bob.dhPublicKey),
    );
    expect(sn1).toBe(sn2);
  });

  it("should produce the same number regardless of order", async () => {
    const alice = await generateFullIdentity();
    const bob = await generateFullIdentity();

    const snAlice = await generateSafetyNumber(
      alice.dhPublicKey, toBase64(alice.dhPublicKey),
      bob.dhPublicKey, toBase64(bob.dhPublicKey),
    );
    const snBob = await generateSafetyNumber(
      bob.dhPublicKey, toBase64(bob.dhPublicKey),
      alice.dhPublicKey, toBase64(alice.dhPublicKey),
    );
    expect(snAlice).toBe(snBob);
  });

  it("should differ for different keys", async () => {
    const alice = await generateFullIdentity();
    const bob = await generateFullIdentity();
    const eve = await generateFullIdentity();

    const snAB = await generateSafetyNumber(
      alice.dhPublicKey, toBase64(alice.dhPublicKey),
      bob.dhPublicKey, toBase64(bob.dhPublicKey),
    );
    const snAE = await generateSafetyNumber(
      alice.dhPublicKey, toBase64(alice.dhPublicKey),
      eve.dhPublicKey, toBase64(eve.dhPublicKey),
    );
    expect(snAB).not.toBe(snAE);
  });

  it("should generate and verify QR payloads", async () => {
    const alice = await generateFullIdentity();
    const bob = await generateFullIdentity();

    const qr1 = await generateSafetyNumberQR(
      alice.dhPublicKey, toBase64(alice.dhPublicKey),
      bob.dhPublicKey, toBase64(bob.dhPublicKey),
    );
    const qr2 = await generateSafetyNumberQR(
      bob.dhPublicKey, toBase64(bob.dhPublicKey),
      alice.dhPublicKey, toBase64(alice.dhPublicKey),
    );
    expect(verifySafetyNumberQR(qr1, qr2)).toBe(true);
  });
});

// ===== BACKUP =====
describe("backup", () => {
  it("should create and restore a backup", async () => {
    const identity = await generateFullIdentity();

    const data = {
      identityPublicKey: toBase64(identity.dhPublicKey),
      identityPrivateKey: toBase64(identity.dhPrivateKey),
      metadata: { createdAt: Date.now() },
    };

    const payload = await createBackup("MyStr0ngPassphrase!", data);
    expect(payload.version).toBe(1);
    expect(typeof payload.salt).toBe("string");
    expect(typeof payload.ciphertext).toBe("string");

    const restored = await restoreBackup("MyStr0ngPassphrase!", payload);
    expect(restored.identityPublicKey).toBe(data.identityPublicKey);
    expect(restored.identityPrivateKey).toBe(data.identityPrivateKey);
  });

  it("should reject wrong passphrase", async () => {
    const data = {
      identityPublicKey: "AAAA",
      identityPrivateKey: "BBBB",
    };
    const payload = await createBackup("CorrectPassword123", data);

    await expect(
      restoreBackup("WrongPassword456", payload),
    ).rejects.toThrow("wrong passphrase");
  });

  it("should reject short passphrase", async () => {
    await expect(
      createBackup("short", { identityPublicKey: "a", identityPrivateKey: "b" }),
    ).rejects.toThrow("at least 8 characters");
  });
});

// ===== X3DH =====
describe("X3DH", () => {
  it("should generate a full identity with signing + DH keys", async () => {
    const id = await generateFullIdentity();
    expect(id.signingPublicKey.length).toBe(32);
    expect(id.signingPrivateKey.length).toBe(64);
    expect(id.dhPublicKey.length).toBe(32);
    expect(id.dhPrivateKey.length).toBe(32);
  });

  it("should generate and verify signed prekeys", async () => {
    const id = await generateFullIdentity();
    const spk = await generateSignedPreKey(id, 1);
    expect(spk.publicKey.length).toBe(32);
    expect(spk.signature.length).toBe(64);

    const valid = await verifySignedPreKey(
      id.signingPublicKey,
      spk.publicKey,
      spk.signature,
    );
    expect(valid).toBe(true);
  });

  it("should reject tampered signed prekey", async () => {
    const id = await generateFullIdentity();
    const spk = await generateSignedPreKey(id, 1);

    // Tamper with the public key
    const tampered = new Uint8Array(spk.publicKey);
    tampered[0] = (tampered[0]! + 1) % 256;
    const valid = await verifySignedPreKey(
      id.signingPublicKey,
      tampered,
      spk.signature,
    );
    expect(valid).toBe(false);
  });

  it("should perform X3DH key agreement (with OPK)", async () => {
    const alice = await generateFullIdentity();
    const bob = await generateFullIdentity();

    const bobSPK = await generateSignedPreKey(bob, 1);
    const bobOPKs = await generateOneTimePreKeys(1, 5);
    const bundle = createPrekeyBundle(bob, bobSPK, bobOPKs[0]);

    // Alice initiates
    const aliceResult = await x3dhInitiate(alice, bundle);
    expect(aliceResult.sharedSecret.length).toBe(32);
    expect(aliceResult.ephemeralPublicKey.length).toBe(32);
    expect(aliceResult.associatedData.length).toBe(64);

    // Bob responds
    const bobResult = await x3dhRespond(
      bob,
      bobSPK,
      bobOPKs[0]!,
      alice.dhPublicKey,
      aliceResult.ephemeralPublicKey,
    );

    // Both should derive the same shared secret
    expect(toBase64(aliceResult.sharedSecret)).toBe(
      toBase64(bobResult.sharedSecret),
    );
    expect(toBase64(aliceResult.associatedData)).toBe(
      toBase64(bobResult.associatedData),
    );
  });

  it("should perform X3DH without OPK", async () => {
    const alice = await generateFullIdentity();
    const bob = await generateFullIdentity();

    const bobSPK = await generateSignedPreKey(bob, 1);
    const bundle = createPrekeyBundle(bob, bobSPK); // No OPK

    const aliceResult = await x3dhInitiate(alice, bundle);
    const bobResult = await x3dhRespond(
      bob,
      bobSPK,
      null,
      alice.dhPublicKey,
      aliceResult.ephemeralPublicKey,
    );

    expect(toBase64(aliceResult.sharedSecret)).toBe(
      toBase64(bobResult.sharedSecret),
    );
  });

  it("should reject invalid SPK signature", async () => {
    const alice = await generateFullIdentity();
    const bob = await generateFullIdentity();

    const bobSPK = await generateSignedPreKey(bob, 1);
    // Corrupt signature
    bobSPK.signature[0] = (bobSPK.signature[0]! + 1) % 256;
    const bundle = createPrekeyBundle(bob, bobSPK);

    await expect(x3dhInitiate(alice, bundle)).rejects.toThrow("MITM");
  });
});

// ===== DOUBLE RATCHET =====
describe("Double Ratchet", () => {
  async function setupRatchetSession() {
    const alice = await generateFullIdentity();
    const bob = await generateFullIdentity();

    const bobSPK = await generateSignedPreKey(bob, 1);
    const bobOPKs = await generateOneTimePreKeys(1, 1);
    const bundle = createPrekeyBundle(bob, bobSPK, bobOPKs[0]);

    const aliceX3DH = await x3dhInitiate(alice, bundle);
    const bobX3DH = await x3dhRespond(
      bob, bobSPK, bobOPKs[0]!, alice.dhPublicKey, aliceX3DH.ephemeralPublicKey,
    );

    const aliceState = await initSessionAsInitiator(
      aliceX3DH.sharedSecret,
      bobSPK.publicKey,
    );
    const bobState = await initSessionAsResponder(
      bobX3DH.sharedSecret,
      { publicKey: bobSPK.publicKey, privateKey: bobSPK.privateKey },
    );

    return { aliceState, bobState, ad: aliceX3DH.associatedData };
  }

  it("should encrypt and decrypt a single message", async () => {
    const { aliceState, bobState, ad } = await setupRatchetSession();

    const plaintext = new TextEncoder().encode("Hello from Alice!");
    const msg = await ratchetEncrypt(aliceState, plaintext, ad);

    expect(msg.header.messageNumber).toBe(0);
    expect(msg.ciphertext.length).toBeGreaterThan(0);

    const decrypted = await ratchetDecrypt(bobState, msg, ad);
    expect(new TextDecoder().decode(decrypted)).toBe("Hello from Alice!");
  });

  it("should handle multiple messages in one direction", async () => {
    const { aliceState, bobState, ad } = await setupRatchetSession();

    for (let i = 0; i < 5; i++) {
      const pt = new TextEncoder().encode(`Message ${i}`);
      const msg = await ratchetEncrypt(aliceState, pt, ad);
      expect(msg.header.messageNumber).toBe(i);
      const dec = await ratchetDecrypt(bobState, msg, ad);
      expect(new TextDecoder().decode(dec)).toBe(`Message ${i}`);
    }
  });

  it("should handle back-and-forth conversation", async () => {
    const { aliceState, bobState, ad } = await setupRatchetSession();

    // Alice sends
    const msg1 = await ratchetEncrypt(
      aliceState,
      new TextEncoder().encode("Hi Bob"),
      ad,
    );
    const dec1 = await ratchetDecrypt(bobState, msg1, ad);
    expect(new TextDecoder().decode(dec1)).toBe("Hi Bob");

    // Bob replies (triggers DH ratchet)
    const msg2 = await ratchetEncrypt(
      bobState,
      new TextEncoder().encode("Hi Alice"),
      ad,
    );
    const dec2 = await ratchetDecrypt(aliceState, msg2, ad);
    expect(new TextDecoder().decode(dec2)).toBe("Hi Alice");

    // Alice replies again (another DH ratchet)
    const msg3 = await ratchetEncrypt(
      aliceState,
      new TextEncoder().encode("How are you?"),
      ad,
    );
    const dec3 = await ratchetDecrypt(bobState, msg3, ad);
    expect(new TextDecoder().decode(dec3)).toBe("How are you?");
  });

  it("should use unique keys per message (forward secrecy)", async () => {
    const { aliceState, bobState, ad } = await setupRatchetSession();

    const msg1 = await ratchetEncrypt(
      aliceState,
      new TextEncoder().encode("Same text"),
      ad,
    );
    const msg2 = await ratchetEncrypt(
      aliceState,
      new TextEncoder().encode("Same text"),
      ad,
    );

    // Different ciphertexts even for same plaintext
    expect(toBase64(msg1.ciphertext)).not.toBe(toBase64(msg2.ciphertext));

    // Both decrypt correctly
    const dec1 = await ratchetDecrypt(bobState, msg1, ad);
    const dec2 = await ratchetDecrypt(bobState, msg2, ad);
    expect(new TextDecoder().decode(dec1)).toBe("Same text");
    expect(new TextDecoder().decode(dec2)).toBe("Same text");
  });

  it("should pad all messages to block size", async () => {
    const { aliceState, ad } = await setupRatchetSession();

    const short = await ratchetEncrypt(
      aliceState,
      new TextEncoder().encode("a"),
      ad,
    );
    const long = await ratchetEncrypt(
      aliceState,
      new TextEncoder().encode("This is a much longer message with more content"),
      ad,
    );

    // Ciphertexts should be the same length (both padded to 256 + auth tag)
    expect(short.ciphertext.length).toBe(long.ciphertext.length);
  });
});

// ===== SEALED SENDER =====
describe("sealed sender", () => {
  it("should seal and unseal a message", async () => {
    const alice = await generateFullIdentity();
    const bob = await generateFullIdentity();

    const innerPayload = new TextEncoder().encode("Secret payload");
    const sealed = await sealMessage(
      alice.dhPublicKey,
      bob.dhPublicKey,
      innerPayload,
    );

    expect(sealed.v).toBe(1);
    // Server sees only recipientPub — no sender info
    expect(sealed.recipientPub).toBe(toBase64(bob.dhPublicKey));

    const unsealed = await unsealMessage(bob.dhPrivateKey, sealed);
    expect(toBase64(unsealed.senderPub)).toBe(toBase64(alice.dhPublicKey));
    expect(new TextDecoder().decode(unsealed.payload)).toBe("Secret payload");
  });

  it("should fail with wrong recipient key", async () => {
    const alice = await generateFullIdentity();
    const bob = await generateFullIdentity();
    const eve = await generateFullIdentity();

    const sealed = await sealMessage(
      alice.dhPublicKey,
      bob.dhPublicKey,
      new TextEncoder().encode("For Bob"),
    );

    await expect(
      unsealMessage(eve.dhPrivateKey, sealed),
    ).rejects.toThrow("decryption failed");
  });

  it("should hide sender identity from envelope", async () => {
    const alice = await generateFullIdentity();
    const bob = await generateFullIdentity();

    const sealed = await sealMessage(
      alice.dhPublicKey,
      bob.dhPublicKey,
      new TextEncoder().encode("test"),
    );

    // The sealed envelope should NOT contain alice's public key in plaintext
    const sealedJson = JSON.stringify(sealed);
    expect(sealedJson).not.toContain(toBase64(alice.dhPublicKey));
  });
});

// ===== GROUP MESSAGING =====
describe("group messaging (Sender Keys)", () => {
  it("should encrypt and decrypt group messages", async () => {
    const alice = await generateFullIdentity();

    // Alice generates her sender key for the group
    const senderKey = await generateSenderKey("group-123");
    expect(senderKey.keyId).toContain("group-123");

    // Create distribution for Bob
    const dist = createSenderKeyDistribution(
      senderKey,
      "group-123",
      alice.dhPublicKey,
    );
    expect(dist.groupId).toBe("group-123");

    // Alice encrypts
    const msg = await groupEncrypt(
      senderKey,
      "group-123",
      new TextEncoder().encode("Hello group!"),
    );
    expect(msg.groupId).toBe("group-123");

    // Bob receives the distribution and decrypts
    const bobKey = {
      keyId: dist.keyId,
      chainKey: (await initSodium()).from_base64(
        dist.chainKey,
        (await initSodium()).base64_variants.ORIGINAL,
      ),
      chainIndex: dist.chainIndex,
      signingKey: (await initSodium()).from_base64(
        dist.signingKey,
        (await initSodium()).base64_variants.ORIGINAL,
      ),
    };
    const dec = await groupDecrypt(bobKey, msg);
    expect(new TextDecoder().decode(dec)).toBe("Hello group!");
  });

  it("should reject tampered group messages", async () => {
    const senderKey = await generateSenderKey("group-456");
    const msg = await groupEncrypt(
      senderKey,
      "group-456",
      new TextEncoder().encode("Tamper test"),
    );

    // Tamper with signature
    const sodium = await initSodium();
    const sigBytes = sodium.from_base64(
      msg.signature,
      sodium.base64_variants.ORIGINAL,
    );
    sigBytes[0] = (sigBytes[0]! + 1) % 256;
    msg.signature = sodium.to_base64(sigBytes, sodium.base64_variants.ORIGINAL);

    const receiverKey = {
      keyId: senderKey.keyId,
      chainKey: new Uint8Array(senderKey.chainKey),
      chainIndex: 0,
      signingKey: senderKey.signingKey,
    };

    await expect(groupDecrypt(receiverKey, msg)).rejects.toThrow(
      "signature verification failed",
    );
  });

  it("should work with GroupSession manager", async () => {
    const session1 = new GroupSession("room-1");
    const session2 = new GroupSession("room-1");

    // Member 1 generates their sender key
    const sk1 = await session1.initOwnKey();
    const alice = await generateFullIdentity();
    const dist1 = createSenderKeyDistribution(sk1, "room-1", alice.dhPublicKey);

    // Member 2 registers member 1's key
    session2.registerMemberKey(dist1);

    // Member 1 sends
    const msg = await session1.encrypt(
      new TextEncoder().encode("Group message!"),
    );

    // Member 2 decrypts
    const dec = await session2.decrypt(msg);
    expect(new TextDecoder().decode(dec)).toBe("Group message!");
  });
});
