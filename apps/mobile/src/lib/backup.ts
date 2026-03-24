/**
 * Encrypted backup with Argon2id + XChaCha20-Poly1305.
 * Includes Shamir's Secret Sharing for key splitting.
 * @author Belkis Aslani
 */
import { initCrypto, sodium, toBase64, fromBase64 } from "./crypto";

// --- Encrypted Backup ---

export interface BackupPayload {
  version: number;
  salt: string;
  nonce: string;
  ciphertext: string;
  opsLimit: number;
  memLimit: number;
}

/**
 * Create an encrypted backup of identity and chat data.
 * Uses Argon2id for key derivation and XChaCha20-Poly1305 for encryption.
 */
export async function createBackup(
  passphrase: string,
  data: Record<string, unknown>,
): Promise<BackupPayload> {
  await initCrypto();

  const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const opsLimit = sodium.crypto_pwhash_OPSLIMIT_MODERATE;
  const memLimit = sodium.crypto_pwhash_MEMLIMIT_MODERATE;

  // Derive key from passphrase using Argon2id
  const key = sodium.crypto_pwhash(
    32,
    passphrase,
    salt,
    opsLimit,
    memLimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );

  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  );

  const version = 1;

  // AAD binds version + KDF params to ciphertext (prevents param tampering)
  const aad = new TextEncoder().encode(
    JSON.stringify({ version, opsLimit, memLimit }),
  );

  const plaintext = new TextEncoder().encode(JSON.stringify(data));
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    aad,
    null,
    nonce,
    key,
  );

  sodium.memzero(key);

  return {
    version,
    salt: toBase64(salt),
    nonce: toBase64(nonce),
    ciphertext: toBase64(ciphertext),
    opsLimit,
    memLimit,
  };
}

/**
 * Minimum KDF parameters to prevent downgrade attacks.
 * Payloads with weaker parameters are rejected.
 */
const MIN_OPS_LIMIT = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;
const MIN_MEM_LIMIT = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE;

/**
 * Restore a backup from encrypted payload.
 * Enforces minimum KDF parameters to prevent downgrade attacks.
 */
export async function restoreBackup(
  passphrase: string,
  payload: BackupPayload,
): Promise<Record<string, unknown>> {
  await initCrypto();

  // Validate backup version
  if (payload.version !== 1) {
    throw new Error(`Unsupported backup version: ${payload.version}`);
  }

  // Enforce minimum KDF parameters to prevent downgrade
  if (payload.opsLimit < MIN_OPS_LIMIT) {
    throw new Error("Backup KDF opsLimit below minimum security threshold");
  }
  if (payload.memLimit < MIN_MEM_LIMIT) {
    throw new Error("Backup KDF memLimit below minimum security threshold");
  }

  const salt = fromBase64(payload.salt);
  const nonce = fromBase64(payload.nonce);
  const ciphertext = fromBase64(payload.ciphertext);

  const key = sodium.crypto_pwhash(
    32,
    passphrase,
    salt,
    payload.opsLimit,
    payload.memLimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );

  // Reconstruct AAD to verify KDF params haven't been tampered
  const aad = new TextEncoder().encode(
    JSON.stringify({
      version: payload.version,
      opsLimit: payload.opsLimit,
      memLimit: payload.memLimit,
    }),
  );

  const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    aad,
    nonce,
    key,
  );

  sodium.memzero(key);

  return JSON.parse(new TextDecoder().decode(plaintext));
}

// --- Shamir's Secret Sharing over GF(256) ---

export interface Share {
  index: number;
  data: Uint8Array;
}

// GF(256) arithmetic using the AES/Rijndael polynomial x^8 + x^4 + x^3 + x + 1
const GF256_POLY = 0x11b;

function gf256Add(a: number, b: number): number {
  return a ^ b;
}

function gf256Mul(a: number, b: number): number {
  let result = 0;
  let aa = a;
  let bb = b;
  while (bb > 0) {
    if (bb & 1) result ^= aa;
    aa <<= 1;
    if (aa & 0x100) aa ^= GF256_POLY;
    bb >>= 1;
  }
  return result;
}

function gf256Inv(a: number): number {
  if (a === 0) throw new Error("Cannot invert zero in GF(256)");
  // Fermat's little theorem: a^(254) = a^(-1) in GF(256)
  let result = 1;
  let base = a;
  let exp = 254;
  while (exp > 0) {
    if (exp & 1) result = gf256Mul(result, base);
    base = gf256Mul(base, base);
    exp >>= 1;
  }
  return result;
}

function gf256Div(a: number, b: number): number {
  return gf256Mul(a, gf256Inv(b));
}

/**
 * Split a secret into N shares with threshold K.
 * Share indices are GF(256) elements (1-255), so max 255 shares.
 */
export async function splitSecret(
  secret: Uint8Array,
  totalShares: number,
  threshold: number,
): Promise<Share[]> {
  await initCrypto();

  if (totalShares > 255) {
    throw new Error("Maximum 255 shares (GF(256) index limit)");
  }
  if (threshold > totalShares) {
    throw new Error("Threshold cannot exceed total shares");
  }
  if (threshold < 2) {
    throw new Error("Threshold must be at least 2");
  }

  const shares: Share[] = [];
  for (let i = 0; i < totalShares; i++) {
    shares.push({ index: i + 1, data: new Uint8Array(secret.length) });
  }

  // For each byte of the secret, create a random polynomial of degree (threshold-1)
  for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
    // Coefficients: a[0] = secret byte, a[1..threshold-1] = random
    const coeffs = new Uint8Array(threshold);
    coeffs[0] = secret[byteIdx]!;
    const randomCoeffs = sodium.randombytes_buf(threshold - 1);
    for (let i = 1; i < threshold; i++) {
      coeffs[i] = randomCoeffs[i - 1]!;
    }

    // Evaluate polynomial at each share's x-coordinate
    for (let shareIdx = 0; shareIdx < totalShares; shareIdx++) {
      const x = shareIdx + 1;
      let y = 0;
      for (let c = threshold - 1; c >= 0; c--) {
        y = gf256Add(gf256Mul(y, x), coeffs[c]!);
      }
      shares[shareIdx]!.data[byteIdx] = y;
    }
  }

  return shares;
}

/**
 * Reconstruct a secret from K shares using Lagrange interpolation.
 * Validates that all shares have the same data length.
 */
export function reconstructSecret(shares: Share[]): Uint8Array {
  if (shares.length < 2) {
    throw new Error("Need at least 2 shares to reconstruct");
  }
  // Validate all shares have consistent data length
  const expectedLen = shares[0]!.data.length;
  for (const share of shares) {
    if (share.data.length !== expectedLen) {
      throw new Error("Share data length mismatch — corrupted shares");
    }
  }

  const length = shares[0]!.data.length;
  const result = new Uint8Array(length);

  for (let byteIdx = 0; byteIdx < length; byteIdx++) {
    let value = 0;

    for (let i = 0; i < shares.length; i++) {
      const xi = shares[i]!.index;
      let li = 1; // Lagrange basis polynomial at x=0

      for (let j = 0; j < shares.length; j++) {
        if (i === j) continue;
        const xj = shares[j]!.index;
        // li *= (0 - xj) / (xi - xj)
        li = gf256Mul(li, gf256Div(xj, gf256Add(xi, xj)));
      }

      value = gf256Add(value, gf256Mul(li, shares[i]!.data[byteIdx]!));
    }

    result[byteIdx] = value;
  }

  return result;
}

/**
 * Convenience: Split a 32-byte backup key into 2-of-3 shares.
 * Returns device share, server share, and recovery share.
 */
export async function splitBackupKey(key: Uint8Array): Promise<{
  deviceShare: Share;
  serverShare: Share;
  recoveryShare: Share;
}> {
  const shares = await splitSecret(key, 3, 2);
  return {
    deviceShare: shares[0]!,
    serverShare: shares[1]!,
    recoveryShare: shares[2]!,
  };
}

/**
 * Convert a share to a human-readable recovery code (base32-ish).
 */
export function shareToRecoveryCode(share: Share): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = new Uint8Array(share.data.length + 1);
  bytes[0] = share.index;
  bytes.set(share.data, 1);

  let bits = "";
  for (const b of bytes) {
    bits += b.toString(2).padStart(8, "0");
  }

  let code = "";
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, "0");
    code += alphabet[parseInt(chunk, 2)]!;
  }

  // Format as groups of 4
  const groups: string[] = [];
  for (let i = 0; i < code.length; i += 4) {
    groups.push(code.slice(i, i + 4));
  }
  return groups.join("-");
}

/**
 * Parse a recovery code back to a Share.
 */
export function recoveryCodeToShare(code: string): Share {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = code.replace(/-/g, "").toUpperCase();

  let bits = "";
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) throw new Error("Invalid recovery code character");
    bits += idx.toString(2).padStart(5, "0");
  }

  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }

  return {
    index: bytes[0]!,
    data: new Uint8Array(bytes.slice(1)),
  };
}
