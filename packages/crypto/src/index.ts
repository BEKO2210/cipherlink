/**
 * @cipherlink/crypto — E2EE cryptographic primitives.
 *
 * ⚠️  WARNING: This is a security skeleton for educational/demo purposes.
 *     NOT suitable for high-risk production use without significant hardening.
 *     See docs/CRYPTO_LIMITS.md for missing features.
 *
 * @author Belkis Aslani
 * @license MIT
 */

export { initSodium } from "./sodium.js";
export { generateIdentityKeypair } from "./keys.js";
export type { IdentityKeypair } from "./keys.js";
export { deriveSharedSecret, deriveMessageKey } from "./kdf.js";
export {
  buildAad,
  encryptMessage,
  decryptMessage,
  PROTOCOL_VERSION,
} from "./envelope.js";
export type { Envelope, EnvelopeMeta } from "./envelope.js";
export { toBase64, fromBase64, toBase64Url, fromBase64Url } from "./base64.js";
