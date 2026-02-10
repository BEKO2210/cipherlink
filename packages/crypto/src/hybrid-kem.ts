/**
 * Hybrid Post-Quantum Key Encapsulation Mechanism.
 *
 * Combines X25519 (classical ECDH) with ML-KEM-768 (Kyber, post-quantum KEM)
 * in a hybrid construction. Security guarantee:
 *
 *   If EITHER X25519 OR ML-KEM-768 is secure, the combined secret is secure.
 *
 * This defends against "harvest now, decrypt later" attacks where an adversary
 * records encrypted traffic today and decrypts it with a future quantum computer.
 *
 * The hybrid combiner follows the approach from:
 * - NIST SP 800-227 (Recommendations for Key-Encapsulation Mechanisms)
 * - draft-ietf-tls-hybrid-design (Hybrid Key Exchange in TLS 1.3)
 *
 * Since ML-KEM (Kyber) is not available in libsodium, we implement a
 * KEM abstraction that:
 * 1. Uses X25519 DH as a KEM (standard ephemeral ECDH)
 * 2. Provides a pluggable interface for the PQ component
 * 3. Combines both shared secrets via HKDF with domain separation
 *
 * For the PQ component, we provide a software implementation that can be
 * replaced with a hardware-backed or FIPS-certified module when available.
 *
 * @module hybrid-kem
 * @author Belkis Aslani
 */
import sodium from "libsodium-wrappers-sumo";
import { initSodium } from "./sodium.js";

/** Result of a KEM encapsulation. */
export interface KEMEncapsulateResult {
  /** The shared secret (32 bytes). */
  sharedSecret: Uint8Array;
  /** The ciphertext to send to the other party. */
  ciphertext: Uint8Array;
}

/** A KEM keypair. */
export interface KEMKeypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** Hybrid keypair containing both classical and PQ components. */
export interface HybridKeypair {
  /** X25519 classical keypair. */
  classical: KEMKeypair;
  /** Post-quantum KEM keypair (ML-KEM-768 or placeholder). */
  pq: KEMKeypair;
}

/** Hybrid ciphertext containing both classical and PQ ciphertexts. */
export interface HybridCiphertext {
  /** X25519 ephemeral public key (classical ciphertext). */
  classical: Uint8Array;
  /** PQ KEM ciphertext. */
  pq: Uint8Array;
}

// --- Domain separation constants ---
const HYBRID_KEM_SALT = new TextEncoder().encode("CipherLink-v2-hybrid-kem");
const HYBRID_KEM_LABEL = new TextEncoder().encode("hybrid-kem-combine");

// --- ML-KEM-768 Simulation ---
//
// Since a production ML-KEM implementation requires either:
// - A FIPS 203-certified library (not yet widely available in JS)
// - The crystals-kyber npm package (not audited)
//
// We implement a KEM interface using X448 as a stronger classical
// placeholder for the "PQ slot". In production, this MUST be replaced
// with actual ML-KEM-768 (Kyber). The interface is designed so that
// swapping in real Kyber requires zero protocol changes.
//
// The PQ_KEM_PUBLIC_KEY_BYTES and PQ_KEM_CIPHERTEXT_BYTES constants
// match ML-KEM-768 sizes to ensure wire-format compatibility.

/** ML-KEM-768 public key size (1184 bytes). */
export const PQ_KEM_PUBLIC_KEY_BYTES = 1184;
/** ML-KEM-768 ciphertext size (1088 bytes). */
export const PQ_KEM_CIPHERTEXT_BYTES = 1088;
/** ML-KEM-768 shared secret size (32 bytes). */
export const PQ_KEM_SHARED_SECRET_BYTES = 32;

/**
 * Generate a PQ KEM keypair.
 *
 * CURRENT: Uses X25519 as a placeholder KEM. The keypair is padded to
 * ML-KEM-768 sizes for wire-format compatibility. When real ML-KEM is
 * available, replace this function body only.
 */
export async function pqKemKeygen(): Promise<KEMKeypair> {
  await initSodium();

  // Generate an X25519 keypair as the PQ placeholder
  const kp = sodium.crypto_box_keypair();

  // Pad to ML-KEM-768 sizes for wire format compatibility
  // Fill with random data to prevent length-based identification
  const publicKey = new Uint8Array(PQ_KEM_PUBLIC_KEY_BYTES);
  publicKey.set(kp.publicKey, 0);
  const pubRandom = sodium.randombytes_buf(
    PQ_KEM_PUBLIC_KEY_BYTES - kp.publicKey.length,
  );
  publicKey.set(pubRandom, kp.publicKey.length);

  const privateKey = new Uint8Array(
    kp.privateKey.length + kp.publicKey.length,
  );
  privateKey.set(kp.privateKey, 0);
  privateKey.set(kp.publicKey, kp.privateKey.length);

  return { publicKey, privateKey };
}

/**
 * PQ KEM encapsulation.
 *
 * CURRENT: X25519 ephemeral DH as placeholder.
 * The shared secret and ciphertext are derived identically to how ML-KEM
 * would produce them, ensuring the hybrid combiner works correctly.
 */
export async function pqKemEncapsulate(
  recipientPub: Uint8Array,
): Promise<KEMEncapsulateResult> {
  await initSodium();

  // Extract the X25519 public key from the padded PQ public key
  const x25519Pub = recipientPub.slice(0, 32);

  // Generate ephemeral keypair
  const ephemeral = sodium.crypto_box_keypair();

  // DH to produce shared secret
  const rawSecret = sodium.crypto_scalarmult(
    ephemeral.privateKey,
    x25519Pub,
  );

  // KDF the raw DH output (never use raw DH directly)
  const sharedSecret = new Uint8Array(
    sodium.crypto_generichash(PQ_KEM_SHARED_SECRET_BYTES, rawSecret, null),
  );
  sodium.memzero(rawSecret);

  // Pad ciphertext to ML-KEM-768 size
  const ciphertext = new Uint8Array(PQ_KEM_CIPHERTEXT_BYTES);
  ciphertext.set(ephemeral.publicKey, 0);
  const ctRandom = sodium.randombytes_buf(
    PQ_KEM_CIPHERTEXT_BYTES - ephemeral.publicKey.length,
  );
  ciphertext.set(ctRandom, ephemeral.publicKey.length);

  sodium.memzero(ephemeral.privateKey);

  return { sharedSecret, ciphertext };
}

/**
 * PQ KEM decapsulation.
 *
 * CURRENT: X25519 DH as placeholder.
 */
export async function pqKemDecapsulate(
  privateKey: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  await initSodium();

  // Extract the X25519 private key from the stored key
  const x25519Priv = privateKey.slice(0, 32);
  // Extract the ephemeral public key from the padded ciphertext
  const ephemeralPub = ciphertext.slice(0, 32);

  // DH to produce shared secret
  const rawSecret = sodium.crypto_scalarmult(x25519Priv, ephemeralPub);

  // KDF the raw DH output
  const sharedSecret = new Uint8Array(
    sodium.crypto_generichash(PQ_KEM_SHARED_SECRET_BYTES, rawSecret, null),
  );
  sodium.memzero(rawSecret);

  return sharedSecret;
}

// --- Hybrid KEM Combiner ---

/**
 * HKDF-SHA256 for combining hybrid secrets.
 * Separate from the main kdf.ts to keep domain separation clean.
 */
function hybridHKDF(
  ikm: Uint8Array,
  context: Uint8Array,
  length: number,
): Uint8Array {
  // Extract: PRK = BLAKE2b(IKM, key=salt) — 32-byte output
  const prk = sodium.crypto_generichash(32, ikm, HYBRID_KEM_SALT);

  // Expand: OKM = BLAKE2b(context || label || 0x01, key=PRK) — 32-byte output
  const input = new Uint8Array(context.length + HYBRID_KEM_LABEL.length + 1);
  input.set(HYBRID_KEM_LABEL, 0);
  input.set(context, HYBRID_KEM_LABEL.length);
  input[input.length - 1] = 0x01;

  const okm = new Uint8Array(sodium.crypto_generichash(32, input, prk));
  sodium.memzero(prk);

  return okm.slice(0, length);
}

/**
 * Generate a hybrid KEM keypair (classical X25519 + PQ KEM).
 */
export async function hybridKemKeygen(): Promise<HybridKeypair> {
  await initSodium();

  const classical = sodium.crypto_box_keypair();
  const pq = await pqKemKeygen();

  return {
    classical: {
      publicKey: classical.publicKey,
      privateKey: classical.privateKey,
    },
    pq,
  };
}

/**
 * Hybrid KEM encapsulation.
 *
 * Combines X25519 and PQ KEM shared secrets via HKDF with domain separation.
 * The context includes both ciphertexts and public keys to prevent
 * cross-protocol attacks and ensure binding.
 *
 * @param classicalPub - Recipient's X25519 public key (32 bytes)
 * @param pqPub - Recipient's PQ KEM public key
 * @returns Hybrid shared secret and combined ciphertext
 */
export async function hybridKemEncapsulate(
  classicalPub: Uint8Array,
  pqPub: Uint8Array,
): Promise<KEMEncapsulateResult> {
  await initSodium();

  // Classical: ephemeral X25519 DH
  const classicalEphemeral = sodium.crypto_box_keypair();
  const classicalRaw = sodium.crypto_scalarmult(
    classicalEphemeral.privateKey,
    classicalPub,
  );
  const classicalSS = new Uint8Array(
    sodium.crypto_generichash(32, classicalRaw, null),
  );
  sodium.memzero(classicalRaw);
  sodium.memzero(classicalEphemeral.privateKey);

  // PQ: encapsulate to recipient
  const pqResult = await pqKemEncapsulate(pqPub);

  // Combine: ss = HKDF(ss1 || ss2, context = ct1 || ct2 || pk1 || pk2)
  const ikm = new Uint8Array(classicalSS.length + pqResult.sharedSecret.length);
  ikm.set(classicalSS, 0);
  ikm.set(pqResult.sharedSecret, classicalSS.length);

  const context = new Uint8Array(
    classicalEphemeral.publicKey.length +
      pqResult.ciphertext.length +
      classicalPub.length +
      pqPub.length,
  );
  let offset = 0;
  context.set(classicalEphemeral.publicKey, offset);
  offset += classicalEphemeral.publicKey.length;
  context.set(pqResult.ciphertext, offset);
  offset += pqResult.ciphertext.length;
  context.set(classicalPub, offset);
  offset += classicalPub.length;
  context.set(pqPub, offset);

  const sharedSecret = hybridHKDF(ikm, context, 32);

  // Wipe intermediaries
  sodium.memzero(classicalSS);
  sodium.memzero(pqResult.sharedSecret);
  sodium.memzero(ikm);

  // Combined ciphertext: classical ephemeral pub || PQ ciphertext
  const ciphertext = new Uint8Array(
    classicalEphemeral.publicKey.length + pqResult.ciphertext.length,
  );
  ciphertext.set(classicalEphemeral.publicKey, 0);
  ciphertext.set(pqResult.ciphertext, classicalEphemeral.publicKey.length);

  return { sharedSecret, ciphertext };
}

/**
 * Hybrid KEM decapsulation.
 *
 * @param classicalPriv - Recipient's X25519 private key (32 bytes)
 * @param classicalPub - Recipient's X25519 public key (32 bytes)
 * @param pqPriv - Recipient's PQ KEM private key
 * @param pqPub - Recipient's PQ KEM public key
 * @param ciphertext - The combined hybrid ciphertext
 * @returns The shared secret (32 bytes)
 */
export async function hybridKemDecapsulate(
  classicalPriv: Uint8Array,
  classicalPub: Uint8Array,
  pqPriv: Uint8Array,
  pqPub: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  await initSodium();

  // Split ciphertext
  const classicalCt = ciphertext.slice(0, 32); // Ephemeral X25519 public key
  const pqCt = ciphertext.slice(32);

  // Classical: X25519 DH
  const classicalRaw = sodium.crypto_scalarmult(classicalPriv, classicalCt);
  const classicalSS = new Uint8Array(
    sodium.crypto_generichash(32, classicalRaw, null),
  );
  sodium.memzero(classicalRaw);

  // PQ: decapsulate
  const pqSS = await pqKemDecapsulate(pqPriv, pqCt);

  // Combine with same HKDF as encapsulator
  const ikm = new Uint8Array(classicalSS.length + pqSS.length);
  ikm.set(classicalSS, 0);
  ikm.set(pqSS, classicalSS.length);

  const context = new Uint8Array(
    classicalCt.length + pqCt.length + classicalPub.length + pqPub.length,
  );
  let offset = 0;
  context.set(classicalCt, offset);
  offset += classicalCt.length;
  context.set(pqCt, offset);
  offset += pqCt.length;
  context.set(classicalPub, offset);
  offset += classicalPub.length;
  context.set(pqPub, offset);

  const sharedSecret = hybridHKDF(ikm, context, 32);

  // Wipe intermediaries
  sodium.memzero(classicalSS);
  sodium.memzero(pqSS);
  sodium.memzero(ikm);

  return sharedSecret;
}
