/**
 * Shamir's Secret Sharing — threshold key splitting for backups.
 *
 * Splits a secret into N shares where any K shares can reconstruct it,
 * but K-1 shares reveal nothing about the secret.
 *
 * Default: 2-of-3 splitting for backups:
 *   Share 1: Stored on device (encrypted by device PIN)
 *   Share 2: Stored on backup server (encrypted by passphrase)
 *   Share 3: Printed as recovery code (offline)
 *
 * Any 2 shares can reconstruct the backup key.
 * Loss of any single share is recoverable.
 *
 * Implementation uses GF(256) (Galois Field with 256 elements)
 * for byte-level operations, operating on each byte of the secret
 * independently.
 *
 * @module key-splitting
 * @author Belkis Aslani
 */
import sodium from "libsodium-wrappers-sumo";
import { initSodium } from "./sodium.js";

// --- GF(256) Arithmetic ---
// Using the irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)
// Same as AES

/** Precomputed log and exp tables for GF(256). */
const GF256_EXP = new Uint8Array(512);
const GF256_LOG = new Uint8Array(256);

// Initialize lookup tables
(function initGF256() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF256_EXP[i] = x;
    GF256_LOG[x] = i;
    x = x ^ (x << 1);
    if (x >= 256) {
      x ^= 0x11b; // Reduce by AES polynomial
    }
  }
  // Extend exp table for convenience
  for (let i = 255; i < 512; i++) {
    GF256_EXP[i] = GF256_EXP[i - 255] as number;
  }
})();

/** GF(256) addition (XOR). */
function gfAdd(a: number, b: number): number {
  return a ^ b;
}

/** GF(256) multiplication using log/exp tables. */
function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF256_EXP[(GF256_LOG[a] as number) + (GF256_LOG[b] as number)] as number;
}

/** GF(256) division. */
function gfDiv(a: number, b: number): number {
  if (b === 0) throw new Error("Division by zero in GF(256)");
  if (a === 0) return 0;
  return GF256_EXP[((GF256_LOG[a] as number) - (GF256_LOG[b] as number) + 255) % 255] as number;
}

// --- Shamir's Secret Sharing ---

/** A share in a secret sharing scheme. */
export interface Share {
  /** Share index (1-indexed, non-zero). */
  index: number;
  /** Share data (same length as the secret). */
  data: Uint8Array;
}

/**
 * Split a secret into N shares with threshold K.
 *
 * @param secret - The secret to split (arbitrary length)
 * @param totalShares - Total number of shares (N)
 * @param threshold - Minimum shares needed to reconstruct (K)
 * @returns Array of N shares
 * @throws If threshold > totalShares or totalShares > 255
 */
export async function splitSecret(
  secret: Uint8Array,
  totalShares: number,
  threshold: number,
): Promise<Share[]> {
  await initSodium();

  if (threshold < 2) {
    throw new Error("Threshold must be at least 2");
  }
  if (threshold > totalShares) {
    throw new Error("Threshold cannot exceed total shares");
  }
  if (totalShares > 255) {
    throw new Error("Maximum 255 shares");
  }

  const shares: Share[] = [];

  for (let s = 1; s <= totalShares; s++) {
    shares.push({
      index: s,
      data: new Uint8Array(secret.length),
    });
  }

  // For each byte of the secret, create a random polynomial of degree (threshold-1)
  // where the constant term is the secret byte
  for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
    // Generate random coefficients for the polynomial
    // coeff[0] = secret byte, coeff[1..threshold-1] = random
    const coeffs = new Uint8Array(threshold);
    coeffs[0] = secret[byteIdx] as number;

    const randomCoeffs = sodium.randombytes_buf(threshold - 1);
    for (let i = 1; i < threshold; i++) {
      coeffs[i] = randomCoeffs[i - 1] as number;
    }

    // Evaluate polynomial at each share index
    for (let s = 0; s < totalShares; s++) {
      const share = shares[s]!;
      const x = share.index; // 1-indexed
      let y = 0;
      for (let c = threshold - 1; c >= 0; c--) {
        y = gfAdd(gfMul(y, x), coeffs[c] as number);
      }
      share.data[byteIdx] = y;
    }
  }

  return shares;
}

/**
 * Reconstruct a secret from K or more shares.
 *
 * Uses Lagrange interpolation in GF(256) to recover the constant
 * term of the polynomial (the secret).
 *
 * @param shares - At least threshold shares
 * @returns The reconstructed secret
 * @throws If shares are insufficient or inconsistent
 */
export function reconstructSecret(shares: Share[]): Uint8Array {
  if (shares.length < 2) {
    throw new Error("Need at least 2 shares to reconstruct");
  }

  // Verify all shares have the same length
  const firstShare = shares[0];
  if (!firstShare) {
    throw new Error("Empty shares array");
  }
  const secretLen = firstShare.data.length;
  for (const share of shares) {
    if (share.data.length !== secretLen) {
      throw new Error("Share data length mismatch");
    }
  }

  // Verify no duplicate indices
  const indices = new Set(shares.map((s) => s.index));
  if (indices.size !== shares.length) {
    throw new Error("Duplicate share indices");
  }

  const result = new Uint8Array(secretLen);

  // Lagrange interpolation at x=0 for each byte
  for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
    let value = 0;

    for (let i = 0; i < shares.length; i++) {
      const si = shares[i]!;
      const xi = si.index;
      const yi = si.data[byteIdx] as number;

      // Compute Lagrange basis polynomial L_i(0)
      let basis = 1;
      for (let j = 0; j < shares.length; j++) {
        if (i === j) continue;
        const xj = shares[j]!.index;
        // L_i(0) = product((0 - xj) / (xi - xj)) = product(xj / (xi ^ xj))
        basis = gfMul(basis, gfDiv(xj, gfAdd(xi, xj)));
      }

      value = gfAdd(value, gfMul(yi, basis));
    }

    result[byteIdx] = value;
  }

  return result;
}

/**
 * Convenience: Split a 32-byte key into 3 shares with threshold 2.
 * This is the recommended configuration for backup key splitting.
 *
 * Returns:
 *   deviceShare  - Store on device (encrypted by device PIN)
 *   serverShare  - Store on backup server (encrypted by passphrase)
 *   recoveryShare - Print as recovery code (offline)
 */
export async function splitBackupKey(
  key: Uint8Array,
): Promise<{
  deviceShare: Share;
  serverShare: Share;
  recoveryShare: Share;
}> {
  if (key.length !== 32) {
    throw new Error("Backup key must be exactly 32 bytes");
  }

  const shares = await splitSecret(key, 3, 2);

  const s0 = shares[0];
  const s1 = shares[1];
  const s2 = shares[2];
  if (!s0 || !s1 || !s2) {
    throw new Error("splitSecret returned fewer than 3 shares");
  }
  return {
    deviceShare: s0,
    serverShare: s1,
    recoveryShare: s2,
  };
}

/**
 * Format a share as a human-readable recovery code.
 * Groups of 5 characters, base32-encoded for easy transcription.
 */
export function shareToRecoveryCode(share: Share): string {
  // Use base32 (Crockford variant) for human readability
  const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  let bits = "";

  // Encode index as first byte
  const data = new Uint8Array(1 + share.data.length);
  data[0] = share.index;
  data.set(share.data, 1);

  for (const byte of data) {
    bits += byte.toString(2).padStart(8, "0");
  }

  let code = "";
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, "0");
    code += ALPHABET[parseInt(chunk, 2)];
  }

  // Format as groups of 5
  const groups: string[] = [];
  for (let i = 0; i < code.length; i += 5) {
    groups.push(code.slice(i, i + 5));
  }

  return groups.join("-");
}

/**
 * Parse a recovery code back into a share.
 */
export function recoveryCodeToShare(code: string): Share {
  const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const clean = code.replace(/-/g, "").toUpperCase();

  let bits = "";
  for (const char of clean) {
    const idx = ALPHABET.indexOf(char);
    if (idx < 0) {
      throw new Error(`Invalid character in recovery code: '${char}'`);
    }
    bits += idx.toString(2).padStart(5, "0");
  }

  // Decode bytes
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }

  const index = bytes[0];
  if (index === undefined) {
    throw new Error("Recovery code too short");
  }
  const data = new Uint8Array(bytes.slice(1));

  return { index, data };
}
