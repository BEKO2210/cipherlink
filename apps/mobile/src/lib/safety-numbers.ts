/**
 * Safety number generation — Signal-style 60-digit key verification.
 * Uses iterated BLAKE2b hashing for fingerprint generation.
 * @author Belkis Aslani
 */
import { initCrypto, sodium } from "./crypto";

const ITERATIONS = 5200;
const DIGEST_BYTES = 32;

/**
 * Generate a 30-digit fingerprint for one party's key.
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

  // Iterate
  for (let i = 0; i < ITERATIONS; i++) {
    const input = new Uint8Array(hash.length + publicKey.length);
    input.set(hash, 0);
    input.set(publicKey, hash.length);
    hash = new Uint8Array(
      sodium.crypto_generichash(DIGEST_BYTES, input, null),
    );
  }

  // Convert to 30 digits (5 groups of 6)
  let digits = "";
  for (let i = 0; i < 30; i++) {
    const idx = i % hash.length;
    const value =
      (hash[idx]! | (hash[(idx + 1) % hash.length]! << 8)) % 100000;
    digits += String(value % 10);
  }
  return digits;
}

/**
 * Generate a 60-digit safety number for a pair of users.
 * Each party's fingerprint is 30 digits; concatenated in sorted order.
 */
export async function generateSafetyNumber(
  localPub: Uint8Array,
  localId: string,
  remotePub: Uint8Array,
  remoteId: string,
): Promise<string> {
  const localFp = await fingerprint(localPub, localId);
  const remoteFp = await fingerprint(remotePub, remoteId);

  // Consistent ordering: lower fingerprint first
  if (localFp < remoteFp) {
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
  // Version byte + safety number as hex
  return "SN01" + sn;
}
