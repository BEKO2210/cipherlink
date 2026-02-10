/**
 * @cipherlink/crypto — E2EE cryptographic primitives.
 *
 * Full-featured encryption library with:
 * - X3DH key agreement
 * - Double Ratchet (forward secrecy + post-compromise security)
 * - Sealed Sender (metadata protection)
 * - Sender Keys (group messaging)
 * - Safety Numbers (key verification)
 * - Message Padding (length hiding)
 * - Encrypted Backup (Argon2id)
 * - Replay Protection (deduplication + counters)
 *
 * @author Belkis Aslani
 * @license MIT
 */

// --- Core ---
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

// --- Padding ---
export {
  padMessage,
  unpadMessage,
  padString,
  unpadToString,
} from "./padding.js";

// --- Replay Protection ---
export {
  ReplayGuard,
  MonotonicCounter,
  SessionReplayGuard,
} from "./replay.js";

// --- Safety Numbers (Key Verification) ---
export {
  generateSafetyNumber,
  generateSafetyNumberQR,
  verifySafetyNumberQR,
} from "./safety-numbers.js";

// --- Encrypted Backup ---
export { createBackup, restoreBackup, estimateKeyDerivationTime } from "./backup.js";
export type { BackupPayload, BackupData } from "./backup.js";

// --- X3DH Key Agreement ---
export {
  generateFullIdentity,
  generateSignedPreKey,
  generateOneTimePreKeys,
  verifySignedPreKey,
  x3dhInitiate,
  x3dhRespond,
  createPrekeyBundle,
  serializePrekeyBundle,
} from "./x3dh.js";
export type {
  FullIdentity,
  SignedPreKey,
  OneTimePreKey,
  PrekeyBundle,
  X3DHResult,
} from "./x3dh.js";

// --- Double Ratchet ---
export {
  initSessionAsInitiator,
  initSessionAsResponder,
  ratchetEncrypt,
  ratchetDecrypt,
} from "./ratchet.js";
export type {
  RatchetState,
  RatchetHeader,
  RatchetMessage,
} from "./ratchet.js";

// --- Sealed Sender ---
export { sealMessage, unsealMessage } from "./sealed-sender.js";
export type { SealedEnvelope, SealedContent } from "./sealed-sender.js";

// --- Group Messaging (Sender Keys) ---
export {
  generateSenderKey,
  createSenderKeyDistribution,
  groupEncrypt,
  groupDecrypt,
  GroupSession,
} from "./group.js";
export type {
  SenderKey,
  SenderKeyDistribution,
  GroupMessage,
} from "./group.js";
