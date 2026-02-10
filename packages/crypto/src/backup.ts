/**
 * Secure encrypted backup — Argon2id key derivation + XChaCha20-Poly1305 encryption.
 *
 * Allows users to back up their identity keys and session state.
 * The backup is encrypted with a key derived from a user-chosen passphrase
 * using Argon2id (memory-hard, resistant to GPU/ASIC attacks).
 *
 * @module backup
 * @author Belkis Aslani
 */
import sodium from "libsodium-wrappers-sumo";
import { initSodium } from "./sodium.js";
import { toBase64, fromBase64 } from "./base64.js";

// Argon2id parameters (OWASP recommended minimum)
const ARGON2_OPS_LIMIT = 3; // crypto_pwhash_OPSLIMIT_MODERATE
const ARGON2_MEM_LIMIT = 268435456; // 256 MB (crypto_pwhash_MEMLIMIT_MODERATE)
const ARGON2_SALT_BYTES = 16;
const BACKUP_KEY_BYTES = 32;

const BACKUP_VERSION = 1;

export interface BackupPayload {
  version: number;
  salt: string; // base64
  nonce: string; // base64
  ciphertext: string; // base64
  argon2Ops: number;
  argon2Mem: number;
}

export interface BackupData {
  identityPublicKey: string; // base64
  identityPrivateKey: string; // base64
  sessions?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

/**
 * Derive a backup encryption key from a passphrase using Argon2id.
 */
async function deriveBackupKey(
  passphrase: string,
  salt: Uint8Array,
  opsLimit: number = ARGON2_OPS_LIMIT,
  memLimit: number = ARGON2_MEM_LIMIT,
): Promise<Uint8Array> {
  await initSodium();

  return sodium.crypto_pwhash(
    BACKUP_KEY_BYTES,
    passphrase,
    salt,
    opsLimit,
    memLimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
}

/**
 * Create an encrypted backup of identity keys and session data.
 *
 * @param passphrase - User-chosen passphrase (should be strong)
 * @param data - Data to back up (identity keys, sessions, metadata)
 * @returns Encrypted backup payload (safe to store on untrusted storage)
 */
export async function createBackup(
  passphrase: string,
  data: BackupData,
): Promise<BackupPayload> {
  await initSodium();

  if (passphrase.length < 8) {
    throw new Error("Passphrase must be at least 8 characters");
  }

  // Generate random salt
  const salt = sodium.randombytes_buf(ARGON2_SALT_BYTES);

  // Derive key from passphrase
  const key = await deriveBackupKey(passphrase, salt);

  // Serialize data
  const plaintext = new TextEncoder().encode(JSON.stringify(data));

  // Encrypt with XChaCha20-Poly1305
  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  );

  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    null, // no AAD needed — the ciphertext is self-authenticating
    null,
    nonce,
    key,
  );

  // Wipe key from memory
  sodium.memzero(key);

  return {
    version: BACKUP_VERSION,
    salt: toBase64(salt),
    nonce: toBase64(nonce),
    ciphertext: toBase64(ciphertext),
    argon2Ops: ARGON2_OPS_LIMIT,
    argon2Mem: ARGON2_MEM_LIMIT,
  };
}

/**
 * Restore identity keys and session data from an encrypted backup.
 *
 * @param passphrase - The passphrase used when creating the backup
 * @param payload - The encrypted backup payload
 * @returns Decrypted backup data
 * @throws If passphrase is wrong or backup is corrupted
 */
export async function restoreBackup(
  passphrase: string,
  payload: BackupPayload,
): Promise<BackupData> {
  await initSodium();

  if (payload.version !== BACKUP_VERSION) {
    throw new Error(`Unsupported backup version: ${payload.version}`);
  }

  const salt = fromBase64(payload.salt);
  const nonce = fromBase64(payload.nonce);
  const ciphertext = fromBase64(payload.ciphertext);

  // Derive key from passphrase with same parameters
  const key = await deriveBackupKey(
    passphrase,
    salt,
    payload.argon2Ops,
    payload.argon2Mem,
  );

  // Decrypt
  let plaintext: Uint8Array;
  try {
    plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ciphertext,
      null,
      nonce,
      key,
    );
  } catch {
    throw new Error(
      "Backup decryption failed — wrong passphrase or corrupted backup",
    );
  } finally {
    sodium.memzero(key);
  }

  const json = new TextDecoder().decode(plaintext);
  return JSON.parse(json) as BackupData;
}

/**
 * Estimate the time needed to derive a backup key.
 * Useful for showing a progress indicator to the user.
 */
export async function estimateKeyDerivationTime(
  opsLimit: number = ARGON2_OPS_LIMIT,
  memLimit: number = ARGON2_MEM_LIMIT,
): Promise<number> {
  await initSodium();

  const salt = sodium.randombytes_buf(ARGON2_SALT_BYTES);
  const start = Date.now();

  const key = sodium.crypto_pwhash(
    BACKUP_KEY_BYTES,
    "benchmark",
    salt,
    opsLimit,
    memLimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );

  sodium.memzero(key);
  return Date.now() - start;
}
