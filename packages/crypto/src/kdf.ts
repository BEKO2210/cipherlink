/**
 * Key derivation: X25519 shared secret -> HKDF-SHA256 -> message key.
 *
 * libsodium does not expose raw HKDF, so we implement HKDF-SHA256
 * using crypto_auth_hmacsha256 (HMAC-SHA-256) per RFC 5869.
 *
 * @module kdf
 * @author Belkis Aslani
 */
import sodium from "libsodium-wrappers-sumo";
import { initSodium } from "./sodium.js";

const HKDF_INFO = new TextEncoder().encode("cipherlink-v1-message-key");
const MESSAGE_KEY_BYTES = 32; // XChaCha20-Poly1305 key size

/**
 * Compute raw X25519 shared secret (AlicePriv × BobPub).
 * This is NOT a usable key — it MUST be passed through a KDF.
 */
export async function deriveSharedSecret(
  senderPriv: Uint8Array,
  recipientPub: Uint8Array,
): Promise<Uint8Array> {
  await initSodium();
  return sodium.crypto_scalarmult(senderPriv, recipientPub);
}

/**
 * HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
 */
function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  // crypto_auth_hmacsha256 computes HMAC-SHA256(key=salt, message=ikm)
  return sodium.crypto_auth_hmacsha256(ikm, salt);
}

/**
 * HKDF-Expand: OKM = T(1) || T(2) || ... truncated to length bytes
 * T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
 */
function hkdfExpand(
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  const hashLen = 32; // SHA-256 output
  const n = Math.ceil(length / hashLen);
  const okm = new Uint8Array(n * hashLen);
  let prev = new Uint8Array(0);

  for (let i = 1; i <= n; i++) {
    const input = new Uint8Array(prev.length + info.length + 1);
    input.set(prev, 0);
    input.set(info, prev.length);
    input[input.length - 1] = i;
    prev = new Uint8Array(sodium.crypto_auth_hmacsha256(input, prk));
    okm.set(prev, (i - 1) * hashLen);
  }

  return okm.slice(0, length);
}

/**
 * Derive a message encryption key from a raw X25519 shared secret.
 * Uses HKDF-SHA256 with an empty salt and fixed info string.
 */
export async function deriveMessageKey(
  rawSharedSecret: Uint8Array,
): Promise<Uint8Array> {
  await initSodium();
  const salt = new Uint8Array(32); // zero-filled (acceptable per RFC 5869)
  const prk = hkdfExtract(salt, rawSharedSecret);
  return hkdfExpand(prk, HKDF_INFO, MESSAGE_KEY_BYTES);
}
