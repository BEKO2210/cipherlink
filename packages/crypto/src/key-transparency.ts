/**
 * Key Transparency — Merkle tree-based verifiable key directory.
 *
 * Prevents the server from performing undetected key substitution (MITM).
 *
 * Design:
 * - Append-only Merkle tree of key-identity bindings
 * - Any key change produces a new tree root
 * - Users can verify their own entry matches their actual key
 * - Third-party monitors can audit the tree for unauthorized changes
 * - Server commits to the tree root (cannot rewrite history)
 *
 * This is a simplified implementation of:
 * - Google Key Transparency
 * - CONIKS (Key Verification for End Users)
 * - Signal's approach to key transparency
 *
 * Properties:
 * - Consistency: The tree root is a binding commitment to all entries
 * - Non-equivocation: Server cannot show different trees to different users
 *   (if monitors verify roots)
 * - Efficiency: O(log n) proof size for inclusion verification
 *
 * @module key-transparency
 * @author Belkis Aslani
 */
import sodium from "libsodium-wrappers-sumo";
import { initSodium } from "./sodium.js";
import { toBase64 } from "./base64.js";

const KT_DOMAIN = new TextEncoder().encode("CipherLink-KeyTransparency-v1");
const KT_LEAF_PREFIX = new Uint8Array([0x00]);
const KT_NODE_PREFIX = new Uint8Array([0x01]);

/** An entry in the key transparency log. */
export interface KeyEntry {
  /** Hash of the user ID (privacy-preserving). */
  userIdHash: Uint8Array;
  /** The user's current public key (Ed25519 signing key). */
  publicKey: Uint8Array;
  /** Timestamp when this key was registered/updated. */
  timestamp: number;
  /** Monotonic version counter (prevents rollback). */
  version: number;
}

/** A Merkle inclusion proof. */
export interface MerkleProof {
  /** The leaf hash being proven. */
  leafHash: Uint8Array;
  /** Sibling hashes along the path from leaf to root. */
  siblings: { hash: Uint8Array; isLeft: boolean }[];
  /** The tree root hash. */
  root: Uint8Array;
  /** Index of the leaf in the tree. */
  leafIndex: number;
  /** Total number of leaves at the time of proof. */
  treeSize: number;
}

/** Signed tree head — server's commitment to the current tree state. */
export interface SignedTreeHead {
  /** The Merkle root hash. */
  root: Uint8Array;
  /** Number of entries in the tree. */
  treeSize: number;
  /** Timestamp of this commitment. */
  timestamp: number;
  /** Server's Ed25519 signature over (root || treeSize || timestamp). */
  signature: Uint8Array;
}

/** Result of a key audit. */
export interface AuditResult {
  /** Whether the key entry is valid and consistent. */
  valid: boolean;
  /** Human-readable description. */
  message: string;
  /** The verified entry (if valid). */
  entry?: KeyEntry;
}

// --- Hash functions with domain separation ---

/** Hash a leaf entry (prefixed to prevent second-preimage attacks). */
function hashLeaf(entry: KeyEntry): Uint8Array {
  const data = new Uint8Array(
    KT_LEAF_PREFIX.length +
      KT_DOMAIN.length +
      entry.userIdHash.length +
      entry.publicKey.length +
      8 + // timestamp (8 bytes)
      4, // version (4 bytes)
  );

  let offset = 0;
  data.set(KT_LEAF_PREFIX, offset);
  offset += KT_LEAF_PREFIX.length;
  data.set(KT_DOMAIN, offset);
  offset += KT_DOMAIN.length;
  data.set(entry.userIdHash, offset);
  offset += entry.userIdHash.length;
  data.set(entry.publicKey, offset);
  offset += entry.publicKey.length;

  // Timestamp (big-endian 8 bytes)
  const ts = entry.timestamp;
  data[offset++] = 0;
  data[offset++] = 0;
  data[offset++] = 0;
  data[offset++] = 0;
  data[offset++] = (ts >>> 24) & 0xff;
  data[offset++] = (ts >>> 16) & 0xff;
  data[offset++] = (ts >>> 8) & 0xff;
  data[offset++] = ts & 0xff;

  // Version (big-endian 4 bytes)
  data[offset++] = (entry.version >>> 24) & 0xff;
  data[offset++] = (entry.version >>> 16) & 0xff;
  data[offset++] = (entry.version >>> 8) & 0xff;
  data[offset++] = entry.version & 0xff;

  return new Uint8Array(sodium.crypto_generichash(32, data, null));
}

/** Hash two child nodes to produce a parent (prefixed). */
function hashNode(left: Uint8Array, right: Uint8Array): Uint8Array {
  const data = new Uint8Array(
    KT_NODE_PREFIX.length + left.length + right.length,
  );
  data.set(KT_NODE_PREFIX, 0);
  data.set(left, KT_NODE_PREFIX.length);
  data.set(right, KT_NODE_PREFIX.length + left.length);
  return new Uint8Array(sodium.crypto_generichash(32, data, null));
}

/** Hash a user ID for privacy (one-way). */
export async function hashUserId(userId: string): Promise<Uint8Array> {
  await initSodium();
  const input = new TextEncoder().encode(userId);
  const salted = new Uint8Array(KT_DOMAIN.length + input.length);
  salted.set(KT_DOMAIN, 0);
  salted.set(input, KT_DOMAIN.length);
  return new Uint8Array(sodium.crypto_generichash(32, salted, null));
}

// --- Merkle Tree ---

/**
 * A verifiable Merkle tree for the key transparency log.
 *
 * Append-only: entries can be added or updated but never removed.
 * Each modification produces a new root hash.
 */
export class MerkleKeyTree {
  private _entries: KeyEntry[] = [];
  private _leafHashes: Uint8Array[] = [];
  private _initialized = false;

  /** Number of entries in the tree. */
  get size(): number {
    return this._entries.length;
  }

  /** Ensure sodium is ready. */
  private async _init(): Promise<void> {
    if (!this._initialized) {
      await initSodium();
      this._initialized = true;
    }
  }

  /**
   * Add or update a key entry.
   *
   * @param entry - The key entry to add/update
   * @returns The new root hash after this change
   */
  async insert(entry: KeyEntry): Promise<Uint8Array> {
    await this._init();

    // Check if this user already has an entry
    const existing = this._entries.findIndex(
      (e) => toBase64(e.userIdHash) === toBase64(entry.userIdHash),
    );

    if (existing >= 0) {
      // Update: version must increase
      const existingEntry = this._entries[existing];
      if (!existingEntry) {
        throw new Error("Internal error: entry not found at expected index");
      }
      if (entry.version <= existingEntry.version) {
        throw new Error(
          `Version must increase: got ${entry.version}, current ${existingEntry.version}`,
        );
      }
      this._entries[existing] = entry;
      this._leafHashes[existing] = hashLeaf(entry);
    } else {
      // Insert new entry
      this._entries.push(entry);
      this._leafHashes.push(hashLeaf(entry));
    }

    return this.computeRoot();
  }

  /**
   * Compute the Merkle root hash.
   */
  computeRoot(): Uint8Array {
    if (this._leafHashes.length === 0) {
      return new Uint8Array(32); // Empty tree
    }

    // Build tree bottom-up
    let level = [...this._leafHashes];

    // Pad to power of 2 with zero hashes
    let size = 1;
    while (size < level.length) size *= 2;
    while (level.length < size) {
      level.push(new Uint8Array(32));
    }

    while (level.length > 1) {
      const nextLevel: Uint8Array[] = [];
      for (let i = 0; i < level.length; i += 2) {
        const left = level[i];
        const right = level[i + 1];
        if (!left || !right) {
          throw new Error("Internal error: tree level not properly padded");
        }
        nextLevel.push(hashNode(left, right));
      }
      level = nextLevel;
    }

    const root = level[0];
    if (!root) {
      throw new Error("Internal error: empty tree after computation");
    }
    return root;
  }

  /**
   * Generate a Merkle inclusion proof for an entry.
   *
   * @param userIdHash - Hash of the user ID to prove
   * @returns A Merkle proof that can be independently verified
   * @throws If the user is not in the tree
   */
  generateProof(userIdHash: Uint8Array): MerkleProof {
    const leafIndex = this._entries.findIndex(
      (e) => toBase64(e.userIdHash) === toBase64(userIdHash),
    );
    if (leafIndex < 0) {
      throw new Error("User not found in key transparency log");
    }

    const leafHash = this._leafHashes[leafIndex];
    if (!leafHash) {
      throw new Error("Internal error: leaf hash not found at index");
    }

    // Build the tree and collect sibling hashes
    let level = [...this._leafHashes];
    let size = 1;
    while (size < level.length) size *= 2;
    while (level.length < size) {
      level.push(new Uint8Array(32));
    }

    const siblings: { hash: Uint8Array; isLeft: boolean }[] = [];
    let idx = leafIndex;

    while (level.length > 1) {
      const nextLevel: Uint8Array[] = [];
      for (let i = 0; i < level.length; i += 2) {
        const left = level[i];
        const right = level[i + 1];
        if (!left || !right) {
          throw new Error("Internal error: tree level not properly padded");
        }
        nextLevel.push(hashNode(left, right));
        // If our index is in this pair, record the sibling
        if (i === idx - (idx % 2)) {
          if (idx % 2 === 0) {
            siblings.push({ hash: right, isLeft: false });
          } else {
            siblings.push({ hash: left, isLeft: true });
          }
        }
      }
      idx = Math.floor(idx / 2);
      level = nextLevel;
    }

    const root = level[0];
    if (!root) {
      throw new Error("Internal error: empty tree after computation");
    }
    return {
      leafHash,
      siblings,
      root,
      leafIndex,
      treeSize: this._entries.length,
    };
  }

  /**
   * Look up an entry by user ID hash.
   */
  lookup(userIdHash: Uint8Array): KeyEntry | null {
    const entry = this._entries.find(
      (e) => toBase64(e.userIdHash) === toBase64(userIdHash),
    );
    return entry ?? null;
  }

  /**
   * Get all entries (for monitoring/auditing).
   */
  getAllEntries(): readonly KeyEntry[] {
    return this._entries;
  }

  /**
   * Create a signed tree head (server signs the current root).
   */
  async signTreeHead(
    serverSigningKey: Uint8Array,
  ): Promise<SignedTreeHead> {
    await this._init();

    const root = this.computeRoot();
    const timestamp = Date.now();

    // Data to sign: root || treeSize (4 bytes) || timestamp (8 bytes)
    const data = new Uint8Array(root.length + 4 + 8);
    data.set(root, 0);
    let offset = root.length;
    data[offset++] = (this._entries.length >>> 24) & 0xff;
    data[offset++] = (this._entries.length >>> 16) & 0xff;
    data[offset++] = (this._entries.length >>> 8) & 0xff;
    data[offset++] = this._entries.length & 0xff;
    // Timestamp (simplified as 4 bytes for now)
    data[offset++] = 0;
    data[offset++] = 0;
    data[offset++] = 0;
    data[offset++] = 0;
    data[offset++] = (timestamp >>> 24) & 0xff;
    data[offset++] = (timestamp >>> 16) & 0xff;
    data[offset++] = (timestamp >>> 8) & 0xff;
    data[offset++] = timestamp & 0xff;

    const signature = sodium.crypto_sign_detached(data, serverSigningKey);

    return { root, treeSize: this._entries.length, timestamp, signature };
  }
}

/**
 * Verify a Merkle inclusion proof (client-side).
 *
 * The client can independently verify that a key entry is in the
 * committed tree without trusting the server.
 */
export function verifyMerkleProof(proof: MerkleProof): boolean {
  let currentHash = proof.leafHash;

  for (const sibling of proof.siblings) {
    if (sibling.isLeft) {
      currentHash = hashNode(sibling.hash, currentHash);
    } else {
      currentHash = hashNode(currentHash, sibling.hash);
    }
  }

  // Compare computed root with provided root (constant time)
  return sodium.memcmp(currentHash, proof.root);
}

/**
 * Verify a signed tree head (client-side).
 *
 * @param sth - The signed tree head from the server
 * @param serverPublicKey - The server's Ed25519 signing public key
 */
export async function verifySignedTreeHead(
  sth: SignedTreeHead,
  serverPublicKey: Uint8Array,
): Promise<boolean> {
  await initSodium();

  const data = new Uint8Array(sth.root.length + 4 + 8);
  data.set(sth.root, 0);
  let offset = sth.root.length;
  data[offset++] = (sth.treeSize >>> 24) & 0xff;
  data[offset++] = (sth.treeSize >>> 16) & 0xff;
  data[offset++] = (sth.treeSize >>> 8) & 0xff;
  data[offset++] = sth.treeSize & 0xff;
  data[offset++] = 0;
  data[offset++] = 0;
  data[offset++] = 0;
  data[offset++] = 0;
  data[offset++] = (sth.timestamp >>> 24) & 0xff;
  data[offset++] = (sth.timestamp >>> 16) & 0xff;
  data[offset++] = (sth.timestamp >>> 8) & 0xff;
  data[offset++] = sth.timestamp & 0xff;

  try {
    return sodium.crypto_sign_verify_detached(
      sth.signature,
      data,
      serverPublicKey,
    );
  } catch {
    return false;
  }
}

/**
 * Audit a key entry — verify it exists in the tree and is consistent.
 *
 * @param tree - The key transparency tree
 * @param userIdHash - Hash of the user ID
 * @param expectedPublicKey - The public key we expect for this user
 */
export function auditKeyEntry(
  tree: MerkleKeyTree,
  userIdHash: Uint8Array,
  expectedPublicKey: Uint8Array,
): AuditResult {
  const entry = tree.lookup(userIdHash);

  if (!entry) {
    return {
      valid: false,
      message: "User not found in key transparency log",
    };
  }

  // Verify the public key matches
  if (!sodium.memcmp(entry.publicKey, expectedPublicKey)) {
    return {
      valid: false,
      message:
        "KEY MISMATCH — the key in the transparency log does not match " +
        "the expected key. This may indicate a MITM attack or unauthorized key change.",
      entry,
    };
  }

  // Verify the inclusion proof is valid
  try {
    const proof = tree.generateProof(userIdHash);
    const proofValid = verifyMerkleProof(proof);

    if (!proofValid) {
      return {
        valid: false,
        message: "Merkle proof verification failed — tree may be corrupted",
        entry,
      };
    }
  } catch {
    return {
      valid: false,
      message: "Could not generate or verify Merkle proof",
      entry,
    };
  }

  return {
    valid: true,
    message: "Key entry verified — consistent with transparency log",
    entry,
  };
}
