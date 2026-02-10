/**
 * @cipherlink/crypto — E2EE cryptographic library.
 *
 * Implements a Signal Protocol-based architecture with:
 *
 * v1 CORE:
 * - X3DH key agreement
 * - Double Ratchet (forward secrecy + post-compromise security)
 * - Sealed Sender (metadata protection)
 * - Sender Keys (group messaging)
 * - Safety Numbers (key verification)
 * - Message Padding (length hiding)
 * - Encrypted Backup (Argon2id)
 * - Replay Protection (deduplication + counters)
 *
 * v2 SECURITY HARDENING:
 * - Cryptographic Agility (cipher suite negotiation)
 * - Post-Quantum Hybrid KEM (X25519 + ML-KEM-768)
 * - SecureBuffer (misuse-resistant key handling)
 * - Protocol State Machine (prevents undefined transitions)
 * - TreeKEM (MLS-inspired forward-secret group protocol)
 * - Metadata Resistance (cover traffic, batching, uniform envelopes)
 * - Key Transparency (Merkle tree-based verifiable key directory)
 * - Key Splitting (Shamir's Secret Sharing for backups)
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

// --- v2: Cipher Suite (Cryptographic Agility) ---
export {
  SUITE_CLASSICAL,
  SUITE_HYBRID_PQ,
  getCipherSuite,
  getAllCipherSuites,
  getDefaultCipherSuite,
  negotiateCipherSuite,
  validateSuitePolicy,
} from "./cipher-suite.js";
export type { CipherSuite } from "./cipher-suite.js";

// --- v2: SecureBuffer (Misuse-Resistant Key Handling) ---
export { SecureBuffer, UseAfterWipeError } from "./secure-buffer.js";

// --- v2: Post-Quantum Hybrid KEM ---
export {
  hybridKemKeygen,
  hybridKemEncapsulate,
  hybridKemDecapsulate,
  pqKemKeygen,
  pqKemEncapsulate,
  pqKemDecapsulate,
  PQ_KEM_PUBLIC_KEY_BYTES,
  PQ_KEM_CIPHERTEXT_BYTES,
  PQ_KEM_SHARED_SECRET_BYTES,
} from "./hybrid-kem.js";
export type {
  HybridKeypair,
  HybridCiphertext,
  KEMKeypair,
  KEMEncapsulateResult,
} from "./hybrid-kem.js";

// --- v2: Protocol State Machine ---
export {
  SessionPhase,
  InvalidTransitionError,
  createSessionState,
  transitionTo,
  recordMessageSent,
  recordMessageReceived,
  shouldRotateKeys,
  describeSession,
} from "./protocol-state.js";
export type { SessionState, SessionInvariant } from "./protocol-state.js";

// --- v2: TreeKEM (MLS-Inspired Group Protocol) ---
export {
  TreeKEMSession,
  parentIndex,
  leftChild,
  rightChild,
  siblingIndex,
  treeSize,
  leafIndex,
  pathToRoot,
  copath,
} from "./treekem.js";
export type {
  TreeNode,
  PathNodeUpdate,
  TreeKEMUpdate,
  GroupEpoch,
} from "./treekem.js";

// --- v2: Metadata Resistance ---
export {
  UNIFORM_ENVELOPE_SIZE,
  MAX_PAYLOAD_SIZE,
  EnvelopeType,
  CoverTrafficLevel,
  createUniformEnvelope,
  parseUniformEnvelope,
  generateCoverMessage,
  CoverTrafficScheduler,
  MessageBatcher,
  timedJitter,
} from "./metadata-resistance.js";
export type {
  CoverTrafficConfig,
  BatchConfig,
} from "./metadata-resistance.js";

// --- v2: Key Transparency ---
export {
  MerkleKeyTree,
  verifyMerkleProof,
  verifySignedTreeHead,
  hashUserId,
  auditKeyEntry,
} from "./key-transparency.js";
export type {
  KeyEntry,
  MerkleProof,
  SignedTreeHead,
  AuditResult,
} from "./key-transparency.js";

// --- v2: Key Splitting (Shamir's Secret Sharing) ---
export {
  splitSecret,
  reconstructSecret,
  splitBackupKey,
  shareToRecoveryCode,
  recoveryCodeToShare,
} from "./key-splitting.js";
export type { Share } from "./key-splitting.js";
