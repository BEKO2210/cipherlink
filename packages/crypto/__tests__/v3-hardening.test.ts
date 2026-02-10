/**
 * Phase 3 Testing Upgrade — Property-based, fuzz, and adversarial tests.
 *
 * These tests go beyond happy-path verification to test invariants,
 * edge cases, and adversarial inputs that could break security properties.
 *
 * @author Belkis Aslani
 */
import { describe, it, expect, beforeAll } from "vitest";
import fc from "fast-check";
import sodium from "libsodium-wrappers-sumo";

// v1 modules
import { initSodium } from "../src/sodium.js";
import { buildAad, encryptMessage, decryptMessage } from "../src/envelope.js";
import type { EnvelopeMeta } from "../src/envelope.js";
import { padMessage, unpadMessage } from "../src/padding.js";
import { ReplayGuard, MonotonicCounter } from "../src/replay.js";
import { toBase64, fromBase64 } from "../src/base64.js";
import { generateIdentityKeypair } from "../src/keys.js";

// v2 modules
import {
  SessionPhase,
  createSessionState,
  transitionTo,
  recordMessageSent,
  recordMessageReceived,
  InvalidTransitionError,
} from "../src/protocol-state.js";
import {
  createUniformEnvelope,
  parseUniformEnvelope,
  EnvelopeType,
  UNIFORM_ENVELOPE_SIZE,
} from "../src/metadata-resistance.js";
import { SecureBuffer, UseAfterWipeError } from "../src/secure-buffer.js";
import { splitSecret, reconstructSecret } from "../src/key-splitting.js";

beforeAll(async () => {
  await initSodium();
});

// ============================================================================
// PROPERTY-BASED TESTS: Protocol State Machine
// ============================================================================
describe("Property-based: Protocol State Machine", () => {
  it("any valid transition sequence reaches the expected state", () => {
    fc.assert(
      fc.property(fc.boolean(), fc.boolean(), fc.boolean(), fc.boolean(), (a, b, c, d) => {
        let state = createSessionState();
        expect(state.phase).toBe(SessionPhase.UNINITIALIZED);

        if (a) {
          state = transitionTo(state, SessionPhase.PREKEY_PUBLISHED);
          expect(state.phase).toBe(SessionPhase.PREKEY_PUBLISHED);

          if (b) {
            state = transitionTo(state, SessionPhase.KEY_AGREEMENT);
            expect(state.phase).toBe(SessionPhase.KEY_AGREEMENT);

            if (c) {
              state = transitionTo(state, SessionPhase.RATCHETING);
              expect(state.phase).toBe(SessionPhase.RATCHETING);

              if (d) {
                state = transitionTo(state, SessionPhase.CLOSED);
                expect(state.phase).toBe(SessionPhase.CLOSED);
              }
            }
          }
        }
      }),
      { numRuns: 50 },
    );
  });

  it("no random phase can be reached from CLOSED", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(
          SessionPhase.UNINITIALIZED,
          SessionPhase.PREKEY_PUBLISHED,
          SessionPhase.KEY_AGREEMENT,
          SessionPhase.RATCHETING,
          SessionPhase.CLOSED,
        ),
        (targetPhase) => {
          let state = createSessionState();
          state = transitionTo(state, SessionPhase.PREKEY_PUBLISHED);
          state = transitionTo(state, SessionPhase.KEY_AGREEMENT);
          state = transitionTo(state, SessionPhase.RATCHETING);
          state = transitionTo(state, SessionPhase.CLOSED);

          expect(() => transitionTo(state, targetPhase)).toThrow(InvalidTransitionError);
        },
      ),
      { numRuns: 20 },
    );
  });

  it("message counters are always monotonically non-decreasing", () => {
    fc.assert(
      fc.property(
        fc.array(fc.constantFrom("send", "receive"), { minLength: 1, maxLength: 100 }),
        (actions) => {
          let state = createSessionState();
          state = transitionTo(state, SessionPhase.PREKEY_PUBLISHED);
          state = transitionTo(state, SessionPhase.KEY_AGREEMENT);
          state = transitionTo(state, SessionPhase.RATCHETING);

          let prevSent = 0;
          let prevRecv = 0;

          for (const action of actions) {
            if (action === "send") {
              state = recordMessageSent(state);
              expect(state.messagesSent).toBeGreaterThanOrEqual(prevSent);
              prevSent = state.messagesSent;
            } else {
              state = recordMessageReceived(state);
              expect(state.messagesReceived).toBeGreaterThanOrEqual(prevRecv);
              prevRecv = state.messagesReceived;
            }
          }
        },
      ),
      { numRuns: 50 },
    );
  });
});

// ============================================================================
// PROPERTY-BASED TESTS: Envelope encrypt/decrypt via full API
// ============================================================================
describe("Property-based: Envelope encrypt/decrypt", () => {
  it("encrypt then decrypt is identity for any plaintext string", async () => {
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();

    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 500 }),
        async (plaintext) => {
          const envelope = await encryptMessage({
            senderPriv: alice.privateKey,
            senderPub: alice.publicKey,
            recipientPub: bob.publicKey,
            plaintext,
          });

          const recovered = await decryptMessage({
            recipientPriv: bob.privateKey,
            recipientPub: bob.publicKey,
            senderPub: alice.publicKey,
            envelope,
          });

          expect(recovered).toBe(plaintext);
        },
      ),
      { numRuns: 15 },
    );
  });

  it("wrong recipient key fails decryption", async () => {
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();
    const eve = await generateIdentityKeypair();

    const envelope = await encryptMessage({
      senderPriv: alice.privateKey,
      senderPub: alice.publicKey,
      recipientPub: bob.publicKey,
      plaintext: "secret",
    });

    await expect(
      decryptMessage({
        recipientPriv: eve.privateKey,
        recipientPub: bob.publicKey,
        senderPub: alice.publicKey,
        envelope,
      }),
    ).rejects.toThrow();
  });
});

// ============================================================================
// PROPERTY-BASED TESTS: Low-level AEAD (via libsodium directly)
// ============================================================================
describe("Property-based: XChaCha20-Poly1305 AEAD", () => {
  it("any single-bit flip in ciphertext causes decryption failure", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 1, maxLength: 200 }),
        fc.nat(),
        (plaintext, bitIndex) => {
          const key = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
          const nonce = sodium.randombytes_buf(24);
          const aad = new TextEncoder().encode("test-aad");

          const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, aad, null, nonce, key,
          );

          const tampered = new Uint8Array(ciphertext);
          const bytePos = bitIndex % tampered.length;
          const bitPos = bitIndex % 8;
          tampered[bytePos] = (tampered[bytePos] as number) ^ (1 << bitPos);

          expect(() =>
            sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, tampered, aad, nonce, key),
          ).toThrow();
        },
      ),
      { numRuns: 30 },
    );
  });

  it("wrong key always fails", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 1, maxLength: 200 }),
        (plaintext) => {
          const key1 = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
          const key2 = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
          const nonce = sodium.randombytes_buf(24);
          const aad = new TextEncoder().encode("test");

          const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, aad, null, nonce, key1,
          );

          expect(() =>
            sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, aad, nonce, key2),
          ).toThrow();
        },
      ),
      { numRuns: 30 },
    );
  });
});

// ============================================================================
// PROPERTY-BASED TESTS: Message Padding
// ============================================================================
describe("Property-based: Message Padding", () => {
  it("pad then unpad is identity for any plaintext", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 1, maxLength: 2000 }),
        (plaintext) => {
          const padded = padMessage(plaintext);
          const unpadded = unpadMessage(padded);
          expect(unpadded).toEqual(plaintext);
        },
      ),
      { numRuns: 100 },
    );
  });

  it("padded output is always aligned to 256-byte blocks", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 1, maxLength: 2000 }),
        (plaintext) => {
          const padded = padMessage(plaintext);
          expect(padded.length % 256).toBe(0);
        },
      ),
      { numRuns: 100 },
    );
  });

  it("padded output is always longer than input", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 1, maxLength: 2000 }),
        (plaintext) => {
          const padded = padMessage(plaintext);
          expect(padded.length).toBeGreaterThan(plaintext.length);
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ============================================================================
// PROPERTY-BASED TESTS: Uniform Envelopes
// ============================================================================
describe("Property-based: Uniform Envelopes", () => {
  it("create then parse is identity for any non-empty payload", async () => {
    const maxPayload = UNIFORM_ENVELOPE_SIZE - 8;
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: Math.min(maxPayload, 4000) }),
        async (payload) => {
          const envelope = await createUniformEnvelope(EnvelopeType.REAL, payload);
          expect(envelope.length).toBe(UNIFORM_ENVELOPE_SIZE);

          const parsed = parseUniformEnvelope(envelope);
          expect(parsed.type).toBe(EnvelopeType.REAL);
          expect(parsed.payload).toEqual(payload);
        },
      ),
      { numRuns: 30 },
    );
  });

  it("all envelopes are exactly the same size regardless of payload", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 3000 }),
        fc.constantFrom(EnvelopeType.REAL, EnvelopeType.COVER, EnvelopeType.ACK, EnvelopeType.HEARTBEAT),
        async (payload, type) => {
          const envelope = await createUniformEnvelope(type, payload);
          expect(envelope.length).toBe(UNIFORM_ENVELOPE_SIZE);
        },
      ),
      { numRuns: 30 },
    );
  });
});

// ============================================================================
// PROPERTY-BASED TESTS: Key Splitting (Shamir)
// ============================================================================
describe("Property-based: Shamir Secret Sharing", () => {
  it("any K shares from N reconstruct the secret", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 64 }),
        async (secret) => {
          const shares = await splitSecret(secret, 5, 3);
          expect(shares).toHaveLength(5);

          const subset = [shares[0]!, shares[2]!, shares[4]!];
          const recovered = await reconstructSecret(subset);
          expect(recovered).toEqual(secret);
        },
      ),
      { numRuns: 15 },
    );
  });

  it("fewer than K shares produce incorrect output for non-trivial secrets", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 8, maxLength: 32 }),
        async (secret) => {
          const shares = await splitSecret(secret, 5, 3);

          const subset = [shares[0]!, shares[1]!];
          const recovered = await reconstructSecret(subset);

          expect(recovered).not.toEqual(secret);
        },
      ),
      { numRuns: 15 },
    );
  });
});

// ============================================================================
// PROPERTY-BASED TESTS: Base64 round-trip
// ============================================================================
describe("Property-based: Base64 encoding", () => {
  it("toBase64 then fromBase64 is identity", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 0, maxLength: 500 }),
        (data) => {
          const encoded = toBase64(data);
          const decoded = fromBase64(encoded);
          expect(decoded).toEqual(data);
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ============================================================================
// PROPERTY-BASED TESTS: AAD construction
// ============================================================================
describe("Property-based: AAD Construction", () => {
  it("same inputs produce same AAD (deterministic)", () => {
    fc.assert(
      fc.property(
        fc.nat({ max: 1e12 }),
        fc.string({ minLength: 1, maxLength: 64 }),
        (ts, msgId) => {
          const senderPub = sodium.randombytes_buf(32);
          const recipientPub = sodium.randombytes_buf(32);
          const meta: EnvelopeMeta = {
            senderPub,
            recipientPub,
            timestamp: ts,
            msgId,
            protocolVersion: 1,
          };

          const aad1 = buildAad(meta);
          const aad2 = buildAad(meta);
          expect(aad1).toEqual(aad2);
        },
      ),
      { numRuns: 50 },
    );
  });

  it("different msgId produces different AAD", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 32 }),
        fc.string({ minLength: 1, maxLength: 32 }),
        (id1, id2) => {
          fc.pre(id1 !== id2);
          const pub = sodium.randombytes_buf(32);
          const meta1: EnvelopeMeta = { senderPub: pub, recipientPub: pub, timestamp: 0, msgId: id1, protocolVersion: 1 };
          const meta2: EnvelopeMeta = { senderPub: pub, recipientPub: pub, timestamp: 0, msgId: id2, protocolVersion: 1 };

          const aad1 = buildAad(meta1);
          const aad2 = buildAad(meta2);
          expect(aad1).not.toEqual(aad2);
        },
      ),
      { numRuns: 30 },
    );
  });
});

// ============================================================================
// FUZZ TESTS: Server Schema Boundaries
// ============================================================================
describe("Fuzz: Server Schema Validation (Zod)", () => {
  let clientMessageSchema: { safeParse: (d: unknown) => { success: boolean } };

  beforeAll(async () => {
    const mod = await import("../../../apps/server/src/schema.js");
    clientMessageSchema = mod.clientMessageSchema;
  });

  it("random objects do not crash the parser", () => {
    fc.assert(
      fc.property(fc.anything(), (input) => {
        const result = clientMessageSchema.safeParse(input);
        expect(typeof result.success).toBe("boolean");
      }),
      { numRuns: 200 },
    );
  });

  it("deeply nested objects do not crash the parser", () => {
    fc.assert(
      fc.property(
        fc.anything({ maxDepth: 10 }),
        (input) => {
          const result = clientMessageSchema.safeParse(input);
          expect(typeof result.success).toBe("boolean");
        },
      ),
      { numRuns: 100 },
    );
  });

  it("random type strings do not crash the parser", () => {
    fc.assert(
      fc.property(
        fc.record({
          type: fc.string({ minLength: 0, maxLength: 50 }),
          publicKey: fc.string({ minLength: 0, maxLength: 1000 }),
        }),
        (input) => {
          const result = clientMessageSchema.safeParse(input);
          expect(typeof result.success).toBe("boolean");
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ============================================================================
// ADVERSARIAL TESTS: Replay Attacks
// ============================================================================
describe("Adversarial: Replay Protection", () => {
  it("detects replayed message IDs", () => {
    const guard = new ReplayGuard(1000);
    const ids = Array.from({ length: 100 }, () =>
      toBase64(sodium.randombytes_buf(16)),
    );

    for (const id of ids) {
      expect(guard.accept(id)).toBe(true);
    }

    for (const id of ids) {
      expect(guard.accept(id)).toBe(false);
    }
  });

  it("monotonic counter rejects out-of-order messages", () => {
    const counter = new MonotonicCounter();

    expect(counter.accept(1)).toBe(true);
    expect(counter.accept(2)).toBe(true);
    expect(counter.accept(3)).toBe(true);

    expect(counter.accept(2)).toBe(false);
    expect(counter.accept(1)).toBe(false);

    expect(counter.accept(4)).toBe(true);
  });

  it("replay guard handles window boundary correctly", () => {
    const guard = new ReplayGuard(10);

    for (let i = 0; i < 10; i++) {
      expect(guard.accept(`msg-${i}`)).toBe(true);
    }

    expect(guard.accept("msg-5")).toBe(false);

    for (let i = 10; i < 20; i++) {
      expect(guard.accept(`msg-${i}`)).toBe(true);
    }
  });
});

// ============================================================================
// ADVERSARIAL TESTS: Corrupted AEAD Ciphertext
// ============================================================================
describe("Adversarial: Corrupted AEAD Ciphertext", () => {
  it("truncated ciphertext is rejected", () => {
    const key = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
    const nonce = sodium.randombytes_buf(24);
    const plaintext = new TextEncoder().encode("secret message");
    const aad = new TextEncoder().encode("bound-metadata");

    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      plaintext, aad, null, nonce, key,
    );

    for (const len of [0, 1, 5, ciphertext.length - 1]) {
      const truncated = ciphertext.slice(0, len);
      expect(() =>
        sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, truncated, aad, nonce, key),
      ).toThrow();
    }
  });

  it("all-zero ciphertext is rejected", () => {
    const key = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
    const nonce = sodium.randombytes_buf(24);
    const aad = new TextEncoder().encode("bound-metadata");

    const zeroCiphertext = new Uint8Array(100);
    expect(() =>
      sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, zeroCiphertext, aad, nonce, key),
    ).toThrow();
  });

  it("random bytes as ciphertext are rejected", () => {
    const key = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
    const nonce = sodium.randombytes_buf(24);
    const aad = new TextEncoder().encode("bound-metadata");

    for (let i = 0; i < 10; i++) {
      const randomCiphertext = sodium.randombytes_buf(50 + i * 10);
      expect(() =>
        sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, randomCiphertext, aad, nonce, key),
      ).toThrow();
    }
  });

  it("tampered AAD is rejected", () => {
    const key = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
    const nonce = sodium.randombytes_buf(24);
    const plaintext = new TextEncoder().encode("hello");
    const aad1 = new TextEncoder().encode("aad-original");
    const aad2 = new TextEncoder().encode("aad-tampered");

    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      plaintext, aad1, null, nonce, key,
    );

    expect(() =>
      sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, aad2, nonce, key),
    ).toThrow();
  });
});

// ============================================================================
// ADVERSARIAL TESTS: Key Mismatch
// ============================================================================
describe("Adversarial: Key Mismatch", () => {
  it("N different keys all fail to decrypt a message", () => {
    const correctKey = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
    const nonce = sodium.randombytes_buf(24);
    const plaintext = new TextEncoder().encode("sensitive data");
    const aad = new TextEncoder().encode("metadata");

    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      plaintext, aad, null, nonce, correctKey,
    );

    for (let i = 0; i < 20; i++) {
      const wrongKey = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
      expect(() =>
        sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, aad, nonce, wrongKey),
      ).toThrow();
    }
  });

  it("wrong nonce fails decryption", () => {
    const key = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
    const nonce1 = sodium.randombytes_buf(24);
    const nonce2 = sodium.randombytes_buf(24);
    const plaintext = new TextEncoder().encode("hello");
    const aad = new TextEncoder().encode("metadata");

    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      plaintext, aad, null, nonce1, key,
    );

    expect(() =>
      sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, aad, nonce2, key),
    ).toThrow();
  });
});

// ============================================================================
// ADVERSARIAL TESTS: Uniform Envelope Manipulation
// ============================================================================
describe("Adversarial: Uniform Envelope Manipulation", () => {
  it("wrong-size buffer is rejected", () => {
    for (const size of [0, 1, 100, 4095, 4097, 8192]) {
      const buffer = new Uint8Array(size);
      expect(() => parseUniformEnvelope(buffer)).toThrow();
    }
  });

  it("corrupted version byte is detected", async () => {
    const envelope = await createUniformEnvelope(EnvelopeType.REAL, new Uint8Array(100));
    envelope[0] = 0;
    expect(() => parseUniformEnvelope(envelope)).toThrow();
  });

  it("payload length overflow is handled safely", async () => {
    const envelope = await createUniformEnvelope(EnvelopeType.REAL, new Uint8Array(10));
    envelope[2] = 0xff;
    envelope[3] = 0xff;
    expect(() => parseUniformEnvelope(envelope)).toThrow();
  });
});

// ============================================================================
// ADVERSARIAL TESTS: SecureBuffer
// ============================================================================
describe("Adversarial: SecureBuffer Edge Cases", () => {
  it("scope auto-wipes after callback", async () => {
    const buf = await SecureBuffer.random(32);
    SecureBuffer.scope(buf, (data) => {
      expect(data.length).toBe(32);
    });
    expect(() => buf.expose()).toThrow(UseAfterWipeError);
  });

  it("double wipe is safe (idempotent)", async () => {
    const buf = await SecureBuffer.random(32);
    buf.wipe();
    expect(() => buf.wipe()).not.toThrow();
    expect(() => buf.expose()).toThrow(UseAfterWipeError);
  });

  it("clone is independent of original", async () => {
    const buf = await SecureBuffer.random(32);
    const cloned = buf.clone();

    buf.wipe();

    const data = cloned.expose();
    expect(data.length).toBe(32);
    cloned.wipe();
  });

  it("multiple random buffers are unique", async () => {
    const bufs = await Promise.all(
      Array.from({ length: 10 }, () => SecureBuffer.random(32)),
    );

    const exposed = bufs.map((b) => toBase64(b.expose()));
    const unique = new Set(exposed);
    expect(unique.size).toBe(10);

    bufs.forEach((b) => b.wipe());
  });
});
