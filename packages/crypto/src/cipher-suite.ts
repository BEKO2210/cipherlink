/**
 * Cryptographic Agility — Cipher Suite negotiation and registry.
 *
 * Allows algorithm replacement without protocol breaking changes.
 * Each cipher suite defines a complete set of cryptographic primitives.
 * Protocol messages carry a suite ID so both parties agree on algorithms.
 *
 * Design principles:
 * - No algorithm is hardcoded in protocol logic
 * - Suite IDs are immutable once assigned (append-only registry)
 * - Downgrade attacks prevented by binding suite to key agreement
 * - Future suites can be added without protocol version bump
 *
 * @module cipher-suite
 * @author Belkis Aslani
 */

/** Supported KEM (Key Encapsulation Mechanism) algorithms. */
export type KEMAlgorithm = "X25519" | "X25519-Kyber768";

/** Supported signature algorithms. */
export type SignatureAlgorithm = "Ed25519";

/** Supported AEAD algorithms. */
export type AEADAlgorithm = "XChaCha20-Poly1305";

/** Supported hash algorithms. */
export type HashAlgorithm = "SHA-512";

/** Supported KDF algorithms. */
export type KDFAlgorithm = "HKDF-SHA256";

/**
 * A complete cipher suite — defines all algorithms for a session.
 * Once registered, a suite ID MUST NOT be reused with different algorithms.
 */
export interface CipherSuite {
  /** Unique immutable identifier (uint16). */
  readonly id: number;
  /** Human-readable name. */
  readonly name: string;
  /** Key encapsulation mechanism. */
  readonly kem: KEMAlgorithm;
  /** Signature algorithm for authentication. */
  readonly sig: SignatureAlgorithm;
  /** Authenticated encryption with associated data. */
  readonly aead: AEADAlgorithm;
  /** Hash function. */
  readonly hash: HashAlgorithm;
  /** Key derivation function. */
  readonly kdf: KDFAlgorithm;
  /** Whether this suite includes post-quantum protection. */
  readonly pqProtected: boolean;
  /** Minimum security level in bits (classical). */
  readonly securityBits: number;
}

/**
 * Suite 0x0001: Classical (current default).
 * X25519 + Ed25519 + XChaCha20-Poly1305 + SHA-512 + HKDF-SHA256.
 * ~128-bit classical security. No post-quantum protection.
 */
export const SUITE_CLASSICAL: CipherSuite = Object.freeze({
  id: 0x0001,
  name: "CLASSICAL_V1",
  kem: "X25519",
  sig: "Ed25519",
  aead: "XChaCha20-Poly1305",
  hash: "SHA-512",
  kdf: "HKDF-SHA256",
  pqProtected: false,
  securityBits: 128,
});

/**
 * Suite 0x0002: Hybrid post-quantum.
 * X25519 + ML-KEM-768 (Kyber) for key exchange.
 * Ed25519 for signatures (PQ signatures are a future upgrade).
 * Security: If EITHER X25519 OR ML-KEM-768 is secure, session is secure.
 */
export const SUITE_HYBRID_PQ: CipherSuite = Object.freeze({
  id: 0x0002,
  name: "HYBRID_PQ_V1",
  kem: "X25519-Kyber768",
  sig: "Ed25519",
  aead: "XChaCha20-Poly1305",
  hash: "SHA-512",
  kdf: "HKDF-SHA256",
  pqProtected: true,
  securityBits: 192,
});

/** Immutable registry of all known cipher suites. */
const SUITE_REGISTRY: ReadonlyMap<number, CipherSuite> = new Map([
  [SUITE_CLASSICAL.id, SUITE_CLASSICAL],
  [SUITE_HYBRID_PQ.id, SUITE_HYBRID_PQ],
]);

/**
 * Look up a cipher suite by ID.
 * @throws If the suite ID is not registered.
 */
export function getCipherSuite(id: number): CipherSuite {
  const suite = SUITE_REGISTRY.get(id);
  if (!suite) {
    throw new Error(
      `Unknown cipher suite 0x${id.toString(16).padStart(4, "0")}. ` +
        `Known suites: ${[...SUITE_REGISTRY.keys()].map((k) => "0x" + k.toString(16).padStart(4, "0")).join(", ")}`,
    );
  }
  return suite;
}

/**
 * Get all registered cipher suites.
 */
export function getAllCipherSuites(): CipherSuite[] {
  return [...SUITE_REGISTRY.values()];
}

/**
 * Get the default cipher suite for new sessions.
 * Returns the highest-security suite available.
 */
export function getDefaultCipherSuite(): CipherSuite {
  return SUITE_HYBRID_PQ;
}

/**
 * Negotiate the best cipher suite both parties support.
 *
 * @param ourSuites - Suite IDs we support (ordered by preference, best first)
 * @param theirSuites - Suite IDs the other party supports
 * @returns The best mutually-supported suite
 * @throws If no common suite exists
 */
export function negotiateCipherSuite(
  ourSuites: readonly number[],
  theirSuites: readonly number[],
): CipherSuite {
  const theirSet = new Set(theirSuites);
  for (const id of ourSuites) {
    if (theirSet.has(id)) {
      return getCipherSuite(id);
    }
  }
  throw new Error(
    "No common cipher suite. " +
      `Ours: [${ourSuites.map((s) => "0x" + s.toString(16).padStart(4, "0")).join(",")}], ` +
      `Theirs: [${theirSuites.map((s) => "0x" + s.toString(16).padStart(4, "0")).join(",")}]`,
  );
}

/**
 * Validate that a cipher suite meets minimum security requirements.
 */
export function validateSuitePolicy(
  suite: CipherSuite,
  policy: { requirePQ?: boolean; minSecurityBits?: number },
): { valid: boolean; reason?: string } {
  if (policy.requirePQ && !suite.pqProtected) {
    return {
      valid: false,
      reason: `Suite ${suite.name} does not include post-quantum protection`,
    };
  }
  if (
    policy.minSecurityBits &&
    suite.securityBits < policy.minSecurityBits
  ) {
    return {
      valid: false,
      reason: `Suite ${suite.name} provides ${suite.securityBits}-bit security, policy requires ${policy.minSecurityBits}`,
    };
  }
  return { valid: true };
}
