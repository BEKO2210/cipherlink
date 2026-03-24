/**
 * Safety number generation — Signal-style 60-digit key verification.
 * Uses iterated BLAKE2b hashing for fingerprint generation.
 *
 * Digit extraction follows Signal's NumericFingerprint V1:
 * - 30 digits per party (6 groups of 5 digits)
 * - Each 5-digit group extracted from 2 bytes of hash (big-endian mod 100000)
 * - Ordering by userId for deterministic output
 *
 * @author Belkis Aslani
 */
import { initCrypto, sodium } from "./crypto";

const ITERATIONS = 5200;
const DIGEST_BYTES = 32;

/**
 * Generate a 30-digit fingerprint for one party's key.
 * Extracts 6 groups of 5 digits from independent byte pairs of the hash.
 */
async function fingerprint(
  publicKey: Uint8Array,
  userId: string,
): Promise<string> {
  await initCrypto();
  const userIdBytes = new TextEncoder().encode(userId);

  // Initial: H(version || publicKey || userId)
  const initial = new Uint8Array(2 + publicKey.length + userIdBytes.length);
  initial[0] = 0;
  initial[1] = 0; // version 0
  initial.set(publicKey, 2);
  initial.set(userIdBytes, 2 + publicKey.length);
  let hash: Uint8Array = new Uint8Array(
    sodium.crypto_generichash(DIGEST_BYTES, initial, null),
  );

  // Iterate 5200 times: H(prev_hash || publicKey)
  for (let i = 0; i < ITERATIONS; i++) {
    const input = new Uint8Array(hash.length + publicKey.length);
    input.set(hash, 0);
    input.set(publicKey, hash.length);
    hash = new Uint8Array(
      sodium.crypto_generichash(DIGEST_BYTES, input, null),
    );
  }

  // Extract 6 groups of 5 digits from independent byte pairs
  // Each group uses 2 bytes (big-endian uint16 mod 100000)
  // 6 groups * 2 bytes = 12 bytes used from 32-byte hash
  let digits = "";
  for (let group = 0; group < 6; group++) {
    const byteOffset = group * 2;
    const value = (hash[byteOffset]! << 8) | hash[byteOffset + 1]!;
    // mod 100000 gives 5-digit number (with leading zeros)
    digits += String(value % 100000).padStart(5, "0");
  }
  return digits;
}

/**
 * Generate a 60-digit safety number for a pair of users.
 * Each party's fingerprint is 30 digits; concatenated in userId-sorted order
 * for deterministic output regardless of which party computes it.
 */
export async function generateSafetyNumber(
  localPub: Uint8Array,
  localId: string,
  remotePub: Uint8Array,
  remoteId: string,
): Promise<string> {
  const localFp = await fingerprint(localPub, localId);
  const remoteFp = await fingerprint(remotePub, remoteId);

  // Sort by userId (not fingerprint) for deterministic ordering
  if (localId < remoteId) {
    return localFp + remoteFp;
  }
  return remoteFp + localFp;
}

/**
 * Format safety number as 12 groups of 5 digits for display.
 */
export function formatSafetyNumber(safetyNumber: string): string {
  const groups: string[] = [];
  for (let i = 0; i < safetyNumber.length; i += 5) {
    groups.push(safetyNumber.slice(i, i + 5));
  }
  return groups.join(" ");
}

/**
 * Generate a compact QR-encodable safety number payload.
 */
export async function generateSafetyNumberQR(
  localPub: Uint8Array,
  localId: string,
  remotePub: Uint8Array,
  remoteId: string,
): Promise<string> {
  const sn = await generateSafetyNumber(localPub, localId, remotePub, remoteId);
  return "SN01" + sn;
}
