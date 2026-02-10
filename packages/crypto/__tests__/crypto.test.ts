/**
 * Unit tests for @cipherlink/crypto.
 * @author Belkis Aslani
 */
import { describe, it, expect, beforeAll } from "vitest";
import {
  initSodium,
  generateIdentityKeypair,
  deriveSharedSecret,
  deriveMessageKey,
  buildAad,
  encryptMessage,
  decryptMessage,
  toBase64,
  fromBase64,
  toBase64Url,
  fromBase64Url,
  PROTOCOL_VERSION,
} from "../src/index.js";

beforeAll(async () => {
  await initSodium();
});

describe("initSodium", () => {
  it("should initialize without error", async () => {
    const sodium = await initSodium();
    expect(sodium).toBeDefined();
    expect(typeof sodium.crypto_box_keypair).toBe("function");
  });

  it("should be idempotent", async () => {
    const a = await initSodium();
    const b = await initSodium();
    expect(a).toBe(b);
  });
});

describe("generateIdentityKeypair", () => {
  it("should produce 32-byte public and private keys", async () => {
    const kp = await generateIdentityKeypair();
    expect(kp.publicKey).toBeInstanceOf(Uint8Array);
    expect(kp.privateKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey.length).toBe(32);
    expect(kp.privateKey.length).toBe(32);
  });

  it("should produce unique keypairs", async () => {
    const a = await generateIdentityKeypair();
    const b = await generateIdentityKeypair();
    expect(toBase64(a.publicKey)).not.toBe(toBase64(b.publicKey));
  });
});

describe("base64 utilities", () => {
  it("should round-trip base64 encoding", () => {
    const data = new Uint8Array([1, 2, 3, 255, 0, 128]);
    const encoded = toBase64(data);
    const decoded = fromBase64(encoded);
    expect(decoded).toEqual(data);
  });

  it("should round-trip base64url encoding", () => {
    const data = new Uint8Array([255, 254, 253, 0, 1, 2]);
    const encoded = toBase64Url(data);
    expect(encoded).not.toContain("+");
    expect(encoded).not.toContain("/");
    expect(encoded).not.toContain("=");
    const decoded = fromBase64Url(encoded);
    expect(decoded).toEqual(data);
  });
});

describe("deriveSharedSecret", () => {
  it("should produce the same shared secret for both parties", async () => {
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();

    const secretAlice = await deriveSharedSecret(
      alice.privateKey,
      bob.publicKey,
    );
    const secretBob = await deriveSharedSecret(bob.privateKey, alice.publicKey);

    expect(toBase64(secretAlice)).toBe(toBase64(secretBob));
  });

  it("should produce a 32-byte shared secret", async () => {
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();
    const secret = await deriveSharedSecret(alice.privateKey, bob.publicKey);
    expect(secret.length).toBe(32);
  });
});

describe("deriveMessageKey", () => {
  it("should produce a 32-byte message key", async () => {
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();
    const secret = await deriveSharedSecret(alice.privateKey, bob.publicKey);
    const key = await deriveMessageKey(secret);
    expect(key.length).toBe(32);
  });

  it("should be deterministic for the same input", async () => {
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();
    const secret1 = await deriveSharedSecret(alice.privateKey, bob.publicKey);
    const secret2 = await deriveSharedSecret(alice.privateKey, bob.publicKey);
    const key1 = await deriveMessageKey(secret1);
    const key2 = await deriveMessageKey(secret2);
    expect(toBase64(key1)).toBe(toBase64(key2));
  });
});

describe("buildAad", () => {
  it("should produce deterministic AAD for the same metadata", async () => {
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();
    const meta = {
      senderPub: alice.publicKey,
      recipientPub: bob.publicKey,
      timestamp: 1700000000000,
      msgId: "test-id",
      protocolVersion: PROTOCOL_VERSION,
    };
    const aad1 = buildAad(meta);
    const aad2 = buildAad(meta);
    expect(toBase64(aad1)).toBe(toBase64(aad2));
  });

  it("should differ for different metadata", async () => {
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();
    const aad1 = buildAad({
      senderPub: alice.publicKey,
      recipientPub: bob.publicKey,
      timestamp: 1,
      msgId: "a",
      protocolVersion: 1,
    });
    const aad2 = buildAad({
      senderPub: alice.publicKey,
      recipientPub: bob.publicKey,
      timestamp: 2,
      msgId: "b",
      protocolVersion: 1,
    });
    expect(toBase64(aad1)).not.toBe(toBase64(aad2));
  });
});

describe("encrypt / decrypt round-trip", () => {
  it("should encrypt and decrypt a message correctly", async () => {
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();
    const plaintext = "Hello, Bob! This is a secret message.";

    const envelope = await encryptMessage({
      senderPriv: alice.privateKey,
      senderPub: alice.publicKey,
      recipientPub: bob.publicKey,
      plaintext,
    });

    // Verify envelope structure
    expect(envelope.v).toBe(PROTOCOL_VERSION);
    expect(typeof envelope.msgId).toBe("string");
    expect(typeof envelope.ts).toBe("number");
    expect(typeof envelope.senderPub).toBe("string");
    expect(typeof envelope.recipientPub).toBe("string");
    expect(typeof envelope.nonce).toBe("string");
    expect(typeof envelope.aad).toBe("string");
    expect(typeof envelope.ciphertext).toBe("string");

    // Ciphertext must differ from plaintext
    expect(envelope.ciphertext).not.toBe(plaintext);

    // Decrypt
    const decrypted = await decryptMessage({
      recipientPriv: bob.privateKey,
      recipientPub: bob.publicKey,
      senderPub: alice.publicKey,
      envelope,
    });

    expect(decrypted).toBe(plaintext);
  });

  it("should handle empty strings", async () => {
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();

    const envelope = await encryptMessage({
      senderPriv: alice.privateKey,
      senderPub: alice.publicKey,
      recipientPub: bob.publicKey,
      plaintext: "",
    });

    const decrypted = await decryptMessage({
      recipientPriv: bob.privateKey,
      recipientPub: bob.publicKey,
      senderPub: alice.publicKey,
      envelope,
    });

    expect(decrypted).toBe("");
  });

  it("should handle unicode and emoji", async () => {
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();
    const plaintext = "Merhaba! \u{1F512}\u{1F510} CipherLink g\u00FCvenli";

    const envelope = await encryptMessage({
      senderPriv: alice.privateKey,
      senderPub: alice.publicKey,
      recipientPub: bob.publicKey,
      plaintext,
    });

    const decrypted = await decryptMessage({
      recipientPriv: bob.privateKey,
      recipientPub: bob.publicKey,
      senderPub: alice.publicKey,
      envelope,
    });

    expect(decrypted).toBe(plaintext);
  });

  it("should produce unique ciphertexts for the same plaintext (random nonce)", async () => {
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();
    const plaintext = "Same message twice";

    const env1 = await encryptMessage({
      senderPriv: alice.privateKey,
      senderPub: alice.publicKey,
      recipientPub: bob.publicKey,
      plaintext,
    });

    const env2 = await encryptMessage({
      senderPriv: alice.privateKey,
      senderPub: alice.publicKey,
      recipientPub: bob.publicKey,
      plaintext,
    });

    expect(env1.ciphertext).not.toBe(env2.ciphertext);
    expect(env1.nonce).not.toBe(env2.nonce);
  });
});

describe("decryption failures", () => {
  it("should reject tampered ciphertext", async () => {
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();

    const envelope = await encryptMessage({
      senderPriv: alice.privateKey,
      senderPub: alice.publicKey,
      recipientPub: bob.publicKey,
      plaintext: "Secret",
    });

    // Tamper with ciphertext
    const tampered = { ...envelope };
    const ctBytes = fromBase64(tampered.ciphertext);
    ctBytes[0] = (ctBytes[0]! + 1) % 256;
    tampered.ciphertext = toBase64(ctBytes);

    await expect(
      decryptMessage({
        recipientPriv: bob.privateKey,
        recipientPub: bob.publicKey,
        senderPub: alice.publicKey,
        envelope: tampered,
      }),
    ).rejects.toThrow();
  });

  it("should reject wrong recipient key", async () => {
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();
    const eve = await generateIdentityKeypair();

    const envelope = await encryptMessage({
      senderPriv: alice.privateKey,
      senderPub: alice.publicKey,
      recipientPub: bob.publicKey,
      plaintext: "For Bob only",
    });

    // Eve tries to decrypt
    await expect(
      decryptMessage({
        recipientPriv: eve.privateKey,
        recipientPub: eve.publicKey,
        senderPub: alice.publicKey,
        envelope,
      }),
    ).rejects.toThrow();
  });

  it("should reject mismatched sender public key", async () => {
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();
    const eve = await generateIdentityKeypair();

    const envelope = await encryptMessage({
      senderPriv: alice.privateKey,
      senderPub: alice.publicKey,
      recipientPub: bob.publicKey,
      plaintext: "From Alice",
    });

    // Claim it's from Eve
    await expect(
      decryptMessage({
        recipientPriv: bob.privateKey,
        recipientPub: bob.publicKey,
        senderPub: eve.publicKey,
        envelope,
      }),
    ).rejects.toThrow("Sender public key mismatch");
  });

  it("should reject tampered AAD (modified timestamp)", async () => {
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();

    const envelope = await encryptMessage({
      senderPriv: alice.privateKey,
      senderPub: alice.publicKey,
      recipientPub: bob.publicKey,
      plaintext: "Timestamp test",
    });

    // Tamper with timestamp
    const tampered = { ...envelope, ts: envelope.ts + 1000 };

    await expect(
      decryptMessage({
        recipientPriv: bob.privateKey,
        recipientPub: bob.publicKey,
        senderPub: alice.publicKey,
        envelope: tampered,
      }),
    ).rejects.toThrow("AAD mismatch");
  });
});
