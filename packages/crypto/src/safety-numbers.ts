/**
 * Safety numbers — key verification protocol.
 *
 * Generates a human-readable "safety number" from two public keys.
 * Both parties compute the same number (keys are sorted lexicographically).
 * Users compare numbers out-of-band (in person, phone call) to verify
 * there is no MITM substituting keys.
 *
 * Inspired by Signal's safety number mechanism.
 *
 * @module safety-numbers
 * @author Belkis Aslani
 */
import sodium from "libsodium-wrappers-sumo";
import { initSodium } from "./sodium.js";
import { toBase64 } from "./base64.js";

const SAFETY_NUMBER_VERSION = new Uint8Array([0x00, 0x01]); // Version prefix
const ITERATIONS = 5200; // Hash iterations per fingerprint

/**
 * Compute a single fingerprint for one party's identity key.
 * Uses iterated SHA-512 for domain separation and security margin.
 *
 * fingerprint = Hash^5200(version || publicKey || stableIdentifier)
 */
async function computeFingerprint(
  publicKey: Uint8Array,
  stableIdentifier: string,
): Promise<Uint8Array> {
  await initSodium();

  const identifierBytes = new TextEncoder().encode(stableIdentifier);

  // Initial hash input: version || publicKey || identifier
  let hash = new Uint8Array(
    SAFETY_NUMBER_VERSION.length + publicKey.length + identifierBytes.length,
  );
  hash.set(SAFETY_NUMBER_VERSION, 0);
  hash.set(publicKey, SAFETY_NUMBER_VERSION.length);
  hash.set(identifierBytes, SAFETY_NUMBER_VERSION.length + publicKey.length);

  // Iterate: hash = SHA-512(hash || publicKey)
  for (let i = 0; i < ITERATIONS; i++) {
    const input = new Uint8Array(hash.length + publicKey.length);
    input.set(hash, 0);
    input.set(publicKey, hash.length);
    hash = new Uint8Array(sodium.crypto_hash(input)); // SHA-512
  }

  return hash;
}

/**
 * Encode a fingerprint as a series of 5-digit numeric groups.
 * Takes the first 30 bytes, interprets each pair as a big-endian uint16,
 * and formats as 5-digit numbers (modulo 100000).
 */
function fingerprintToNumeric(fingerprint: Uint8Array): string {
  const groups: string[] = [];
  for (let i = 0; i < 30; i += 2) {
    const val = (fingerprint[i]! << 8) | fingerprint[i + 1]!;
    groups.push(String(val % 100000).padStart(5, "0"));
  }
  return groups.join(" ");
}

/**
 * Generate a safety number for a pair of identities.
 *
 * The safety number is deterministic: both parties compute the same number
 * because the fingerprints are sorted lexicographically before concatenation.
 *
 * @param localPublicKey - Our X25519 public key
 * @param localIdentifier - Our stable identifier (e.g., public key base64)
 * @param remotePublicKey - Their X25519 public key
 * @param remoteIdentifier - Their stable identifier
 * @returns A human-readable safety number string (60 digits in 12 groups of 5)
 */
export async function generateSafetyNumber(
  localPublicKey: Uint8Array,
  localIdentifier: string,
  remotePublicKey: Uint8Array,
  remoteIdentifier: string,
): Promise<string> {
  const localFp = await computeFingerprint(localPublicKey, localIdentifier);
  const remoteFp = await computeFingerprint(remotePublicKey, remoteIdentifier);

  // Sort fingerprints lexicographically so both parties get the same result
  const localB64 = toBase64(localFp);
  const remoteB64 = toBase64(remoteFp);

  let first: Uint8Array;
  let second: Uint8Array;

  if (localB64 < remoteB64) {
    first = localFp;
    second = remoteFp;
  } else {
    first = remoteFp;
    second = localFp;
  }

  const firstNumeric = fingerprintToNumeric(first);
  const secondNumeric = fingerprintToNumeric(second);

  return `${firstNumeric}\n${secondNumeric}`;
}

/**
 * Generate a QR-encodable safety number payload.
 * Returns a compact binary representation suitable for QR code encoding.
 *
 * Format: version (2 bytes) || fingerprint1 (32 bytes) || fingerprint2 (32 bytes)
 */
export async function generateSafetyNumberQR(
  localPublicKey: Uint8Array,
  localIdentifier: string,
  remotePublicKey: Uint8Array,
  remoteIdentifier: string,
): Promise<Uint8Array> {
  await initSodium();

  const localFp = await computeFingerprint(localPublicKey, localIdentifier);
  const remoteFp = await computeFingerprint(remotePublicKey, remoteIdentifier);

  const localB64 = toBase64(localFp);
  const remoteB64 = toBase64(remoteFp);

  const first = localB64 < remoteB64 ? localFp : remoteFp;
  const second = localB64 < remoteB64 ? remoteFp : localFp;

  // Compact QR payload: version + first 32 bytes of each fingerprint
  const payload = new Uint8Array(2 + 32 + 32);
  payload.set(SAFETY_NUMBER_VERSION, 0);
  payload.set(first.slice(0, 32), 2);
  payload.set(second.slice(0, 32), 34);

  return payload;
}

/**
 * Verify that two QR payloads match (scanned vs. computed).
 */
export function verifySafetyNumberQR(
  scanned: Uint8Array,
  computed: Uint8Array,
): boolean {
  if (scanned.length !== computed.length) return false;
  return sodium.memcmp(scanned, computed);
}
