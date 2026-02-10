/**
 * E2EE message envelope — encrypt/decrypt with XChaCha20-Poly1305.
 *
 * Envelope format (JSON with base64 fields):
 *   { v, msgId, ts, senderPub, recipientPub, nonce, aad, ciphertext }
 *
 * @module envelope
 * @author Belkis Aslani
 */
import sodium from "libsodium-wrappers-sumo";
import { initSodium } from "./sodium.js";
import { deriveSharedSecret, deriveMessageKey } from "./kdf.js";
import { toBase64, fromBase64 } from "./base64.js";

/** Current protocol version. */
export const PROTOCOL_VERSION = 1;

/** Encrypted message envelope. */
export interface Envelope {
  v: number;
  msgId: string;
  ts: number;
  senderPub: string; // base64
  recipientPub: string; // base64
  nonce: string; // base64
  aad: string; // base64
  ciphertext: string; // base64
}

/** Metadata used in AAD construction. */
export interface EnvelopeMeta {
  senderPub: Uint8Array;
  recipientPub: Uint8Array;
  timestamp: number;
  msgId: string;
  protocolVersion: number;
}

/**
 * Build associated data (AAD) from envelope metadata.
 * AAD is a canonical JSON string encoded as UTF-8 bytes.
 * Bound to sender, recipient, time, message id, and protocol version.
 */
export function buildAad(meta: EnvelopeMeta): Uint8Array {
  const canonical = JSON.stringify({
    senderPub: toBase64(meta.senderPub),
    recipientPub: toBase64(meta.recipientPub),
    timestamp: meta.timestamp,
    msgId: meta.msgId,
    protocolVersion: meta.protocolVersion,
  });
  return new TextEncoder().encode(canonical);
}

/**
 * Generate a random message ID (hex-encoded).
 */
function generateMsgId(): string {
  const bytes = sodium.randombytes_buf(16);
  return sodium.to_hex(bytes);
}

/**
 * Encrypt a plaintext message and produce an Envelope.
 */
export async function encryptMessage(params: {
  senderPriv: Uint8Array;
  senderPub: Uint8Array;
  recipientPub: Uint8Array;
  plaintext: string;
}): Promise<Envelope> {
  await initSodium();

  const { senderPriv, senderPub, recipientPub, plaintext } = params;

  // Derive shared secret and message key
  const rawSecret = await deriveSharedSecret(senderPriv, recipientPub);
  const messageKey = await deriveMessageKey(rawSecret);

  // Envelope metadata
  const msgId = generateMsgId();
  const ts = Date.now();
  const meta: EnvelopeMeta = {
    senderPub,
    recipientPub,
    timestamp: ts,
    msgId,
    protocolVersion: PROTOCOL_VERSION,
  };

  // Build AAD
  const aad = buildAad(meta);

  // Random nonce (24 bytes for XChaCha20-Poly1305)
  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  );

  // Encrypt with XChaCha20-Poly1305 AEAD
  const plaintextBytes = new TextEncoder().encode(plaintext);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintextBytes,
    aad,
    null, // nsec (unused in this AEAD)
    nonce,
    messageKey,
  );

  // Wipe sensitive material from memory
  sodium.memzero(rawSecret);
  sodium.memzero(messageKey);

  return {
    v: PROTOCOL_VERSION,
    msgId,
    ts,
    senderPub: toBase64(senderPub),
    recipientPub: toBase64(recipientPub),
    nonce: toBase64(nonce),
    aad: toBase64(aad),
    ciphertext: toBase64(ciphertext),
  };
}

/**
 * Decrypt an Envelope and return the plaintext string.
 * Verifies AAD integrity and sender identity.
 *
 * @throws If decryption fails, AAD mismatch, or sender mismatch.
 */
export async function decryptMessage(params: {
  recipientPriv: Uint8Array;
  recipientPub: Uint8Array;
  senderPub: Uint8Array;
  envelope: Envelope;
}): Promise<string> {
  await initSodium();

  const { recipientPriv, recipientPub, senderPub, envelope } = params;

  // Verify sender matches envelope claim
  const claimedSender = fromBase64(envelope.senderPub);
  if (
    claimedSender.length !== senderPub.length ||
    !sodium.memcmp(claimedSender, senderPub)
  ) {
    throw new Error(
      "Sender public key mismatch: envelope claims a different sender",
    );
  }

  // Verify recipient matches
  const claimedRecipient = fromBase64(envelope.recipientPub);
  if (
    claimedRecipient.length !== recipientPub.length ||
    !sodium.memcmp(claimedRecipient, recipientPub)
  ) {
    throw new Error(
      "Recipient public key mismatch: envelope is not addressed to us",
    );
  }

  // Reconstruct expected AAD
  const expectedAad = buildAad({
    senderPub,
    recipientPub,
    timestamp: envelope.ts,
    msgId: envelope.msgId,
    protocolVersion: envelope.v,
  });

  // Verify AAD matches what's in the envelope
  const envelopeAad = fromBase64(envelope.aad);
  if (
    expectedAad.length !== envelopeAad.length ||
    !sodium.memcmp(expectedAad, envelopeAad)
  ) {
    throw new Error("AAD mismatch: envelope metadata has been tampered with");
  }

  // Derive shared secret and message key
  const rawSecret = await deriveSharedSecret(recipientPriv, senderPub);
  const messageKey = await deriveMessageKey(rawSecret);

  const nonce = fromBase64(envelope.nonce);
  const ciphertext = fromBase64(envelope.ciphertext);

  // Decrypt
  const plaintextBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null, // nsec (unused)
    ciphertext,
    envelopeAad,
    nonce,
    messageKey,
  );

  // Wipe sensitive material
  sodium.memzero(rawSecret);
  sodium.memzero(messageKey);

  return new TextDecoder().decode(plaintextBytes);
}
