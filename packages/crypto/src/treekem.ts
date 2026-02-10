/**
 * TreeKEM — MLS-inspired tree-based group key agreement.
 *
 * Replaces Sender Keys for groups, providing:
 * - Forward secrecy for groups (Sender Keys cannot do this)
 * - Post-compromise security for groups
 * - O(log n) update messages per member key change
 * - Epoch-based group state with clean transitions
 *
 * Tree structure (4 members):
 *
 *                    [Root]  ← group secret
 *                   /      \
 *             [Node L]    [Node R]
 *             /     \     /     \
 *         [Alice] [Bob] [Carol] [Dave]   ← leaf nodes
 *
 * When Alice updates her key:
 * 1. Generate new leaf keypair
 * 2. Compute new path secrets up to root
 * 3. Encrypt path secrets to copath sibling nodes
 * 4. Broadcast update message
 * 5. All members derive new epoch key from new root
 *
 * Based on:
 * - MLS RFC 9420 (simplified)
 * - TreeKEM: Asynchronous Decentralized Key Management for MLS
 *
 * @module treekem
 * @author Belkis Aslani
 */
import sodium from "libsodium-wrappers-sumo";
import { initSodium } from "./sodium.js";
/** A node in the TreeKEM binary tree. */
export interface TreeNode {
  /** Node public key (X25519). */
  publicKey: Uint8Array;
  /** Node private key (only set for nodes we can decrypt). */
  privateKey?: Uint8Array;
  /** Node secret (used to derive child node keys). */
  secret?: Uint8Array;
}

/** Update message for a single path node. */
export interface PathNodeUpdate {
  /** Index of the node in the tree. */
  nodeIndex: number;
  /** New public key for this node. */
  publicKey: Uint8Array;
  /** Encrypted path secret for the copath sibling. */
  encryptedSecret: Uint8Array;
  /** Nonce for the encryption. */
  nonce: Uint8Array;
}

/** A complete TreeKEM update message (broadcast to the group). */
export interface TreeKEMUpdate {
  /** Epoch number after this update. */
  epoch: number;
  /** Index of the leaf that performed the update. */
  senderLeaf: number;
  /** Path updates from leaf to root. */
  path: PathNodeUpdate[];
  /** Signature over the update (Ed25519). */
  signature: Uint8Array;
}

/** Group epoch state (derived from the tree root). */
export interface GroupEpoch {
  /** Epoch number. */
  epoch: number;
  /** Group secret (derived from tree root). */
  groupSecret: Uint8Array;
  /** Application secret (for encrypting messages in this epoch). */
  applicationSecret: Uint8Array;
  /** Confirmation key (for confirming epoch agreement). */
  confirmationKey: Uint8Array;
}

const TREEKEM_EPOCH_LABEL = new TextEncoder().encode("CipherLink-TreeKEM-epoch");
const TREEKEM_APP_LABEL = new TextEncoder().encode("CipherLink-TreeKEM-app");
const TREEKEM_CONFIRM_LABEL = new TextEncoder().encode("CipherLink-TreeKEM-confirm");
const TREEKEM_NODE_LABEL = new TextEncoder().encode("CipherLink-TreeKEM-node");

// --- Tree geometry helpers ---

/** Get the parent index of a node. */
export function parentIndex(nodeIdx: number): number {
  // In a left-balanced binary tree stored as array:
  // parent(i) = floor((i - 1) / 2) for 0-indexed
  if (nodeIdx === 0) throw new Error("Root has no parent");
  return Math.floor((nodeIdx - 1) / 2);
}

/** Get the left child index. */
export function leftChild(nodeIdx: number): number {
  return 2 * nodeIdx + 1;
}

/** Get the right child index. */
export function rightChild(nodeIdx: number): number {
  return 2 * nodeIdx + 2;
}

/** Get the sibling index. */
export function siblingIndex(nodeIdx: number): number {
  if (nodeIdx === 0) throw new Error("Root has no sibling");
  return nodeIdx % 2 === 1 ? nodeIdx + 1 : nodeIdx - 1;
}

/** Compute the total tree size for n leaves (complete binary tree). */
export function treeSize(numLeaves: number): number {
  // Pad to next power of 2 for a complete tree
  let n = 1;
  while (n < numLeaves) n *= 2;
  return 2 * n - 1;
}

/** Compute leaf node index from member index. */
export function leafIndex(memberIdx: number, numLeaves: number): number {
  let n = 1;
  while (n < numLeaves) n *= 2;
  // Leaves are the last n nodes
  return n - 1 + memberIdx;
}

/** Get the path from a node to the root (inclusive). */
export function pathToRoot(nodeIdx: number): number[] {
  const path: number[] = [nodeIdx];
  let current = nodeIdx;
  while (current > 0) {
    current = parentIndex(current);
    path.push(current);
  }
  return path;
}

/** Get the copath (siblings along the path to root). */
export function copath(nodeIdx: number): number[] {
  const result: number[] = [];
  let current = nodeIdx;
  while (current > 0) {
    result.push(siblingIndex(current));
    current = parentIndex(current);
  }
  return result;
}

// --- Cryptographic operations ---

/** Derive a node keypair from a node secret. */
function deriveNodeKeypair(secret: Uint8Array): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  // Hash the secret to get a seed, then derive X25519 keypair
  const seed = new Uint8Array(
    sodium.crypto_generichash(32, secret, TREEKEM_NODE_LABEL),
  );
  // Use seed as X25519 private key (clamped)
  const privateKey = new Uint8Array(32);
  privateKey.set(seed);
  // Clamp per X25519 spec
  privateKey[0] = ((privateKey[0] as number) & 248);
  privateKey[31] = ((privateKey[31] as number) & 127);
  privateKey[31] = ((privateKey[31] as number) | 64);
  const publicKey = sodium.crypto_scalarmult_base(privateKey);
  sodium.memzero(seed);
  return { publicKey, privateKey };
}

/** Derive a path secret from parent secret and position. */
function derivePathSecret(parentSecret: Uint8Array, position: number): Uint8Array {
  const input = new Uint8Array(parentSecret.length + 4);
  input.set(parentSecret, 0);
  // Encode position as 4 bytes (big-endian)
  input[parentSecret.length] = (position >>> 24) & 0xff;
  input[parentSecret.length + 1] = (position >>> 16) & 0xff;
  input[parentSecret.length + 2] = (position >>> 8) & 0xff;
  input[parentSecret.length + 3] = position & 0xff;
  return new Uint8Array(
    sodium.crypto_generichash(32, input, TREEKEM_NODE_LABEL),
  );
}

/** Derive group epoch secrets from the tree root secret. */
function deriveEpochSecrets(rootSecret: Uint8Array, epoch: number): GroupEpoch {
  const epochBytes = new Uint8Array(4);
  epochBytes[0] = (epoch >>> 24) & 0xff;
  epochBytes[1] = (epoch >>> 16) & 0xff;
  epochBytes[2] = (epoch >>> 8) & 0xff;
  epochBytes[3] = epoch & 0xff;

  const input = new Uint8Array(rootSecret.length + epochBytes.length);
  input.set(rootSecret, 0);
  input.set(epochBytes, rootSecret.length);

  const groupSecret = new Uint8Array(
    sodium.crypto_generichash(32, input, TREEKEM_EPOCH_LABEL),
  );
  const applicationSecret = new Uint8Array(
    sodium.crypto_generichash(32, groupSecret, TREEKEM_APP_LABEL),
  );
  const confirmationKey = new Uint8Array(
    sodium.crypto_generichash(32, groupSecret, TREEKEM_CONFIRM_LABEL),
  );

  return { epoch, groupSecret, applicationSecret, confirmationKey };
}

/** Encrypt a secret to a node's public key using X25519 + XChaCha20-Poly1305. */
function encryptToNode(
  secret: Uint8Array,
  recipientPub: Uint8Array,
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  // Generate ephemeral keypair for encryption
  const ephemeral = sodium.crypto_box_keypair();
  const sharedKey = new Uint8Array(
    sodium.crypto_generichash(
      32,
      sodium.crypto_scalarmult(ephemeral.privateKey, recipientPub),
      null,
    ),
  );
  sodium.memzero(ephemeral.privateKey);

  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  );

  // AAD includes the ephemeral public key for binding
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    secret,
    ephemeral.publicKey,
    null,
    nonce,
    sharedKey,
  );
  sodium.memzero(sharedKey);

  // Prepend ephemeral pub to ciphertext
  const result = new Uint8Array(ephemeral.publicKey.length + ciphertext.length);
  result.set(ephemeral.publicKey, 0);
  result.set(ciphertext, ephemeral.publicKey.length);

  return { ciphertext: result, nonce };
}

/** Decrypt a secret encrypted to our node. */
function decryptFromNode(
  encrypted: Uint8Array,
  nonce: Uint8Array,
  recipientPriv: Uint8Array,
): Uint8Array {
  // Extract ephemeral public key
  const ephemeralPub = encrypted.slice(0, 32);
  const ciphertext = encrypted.slice(32);

  const sharedKey = new Uint8Array(
    sodium.crypto_generichash(
      32,
      sodium.crypto_scalarmult(recipientPriv, ephemeralPub),
      null,
    ),
  );

  const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    ephemeralPub,
    nonce,
    sharedKey,
  );
  sodium.memzero(sharedKey);

  return new Uint8Array(plaintext);
}

// --- TreeKEM Session ---

/**
 * A TreeKEM group session managing the tree state for one member.
 *
 * Each member maintains their view of the tree. On updates, members
 * process the update message to derive the new epoch secrets.
 */
export class TreeKEMSession {
  private _tree: (TreeNode | null)[];
  private _numLeaves: number;
  private _myLeaf: number;
  private _epoch: number;
  private _currentEpoch: GroupEpoch | null = null;
  private _signingKey: Uint8Array;

  constructor(
    numMembers: number,
    myMemberIndex: number,
    signingPrivateKey: Uint8Array,
  ) {
    this._numLeaves = numMembers;
    const size = treeSize(numMembers);
    this._tree = new Array(size).fill(null);
    this._myLeaf = leafIndex(myMemberIndex, numMembers);
    this._epoch = 0;
    this._signingKey = signingPrivateKey;
  }

  /** Current epoch number. */
  get epoch(): number {
    return this._epoch;
  }

  /** Current epoch secrets (null if no epoch derived yet). */
  get currentEpoch(): GroupEpoch | null {
    return this._currentEpoch;
  }

  /** Number of members in the group. */
  get memberCount(): number {
    return this._numLeaves;
  }

  /**
   * Initialize our leaf node with a fresh keypair.
   */
  async initLeaf(): Promise<Uint8Array> {
    await initSodium();

    const secret = sodium.randombytes_buf(32);
    const kp = deriveNodeKeypair(secret);

    this._tree[this._myLeaf] = {
      publicKey: kp.publicKey,
      privateKey: kp.privateKey,
      secret,
    };

    return kp.publicKey;
  }

  /**
   * Set a peer member's leaf public key (from their init or update message).
   */
  setMemberKey(memberIndex: number, publicKey: Uint8Array): void {
    const leaf = leafIndex(memberIndex, this._numLeaves);
    this._tree[leaf] = { publicKey };
  }

  /**
   * Perform a key update — generate new leaf secret and compute path to root.
   * Returns a TreeKEMUpdate message to broadcast to the group.
   */
  async update(): Promise<TreeKEMUpdate> {
    await initSodium();

    // Generate new leaf secret
    const newLeafSecret = sodium.randombytes_buf(32);
    const leafKP = deriveNodeKeypair(newLeafSecret);

    this._tree[this._myLeaf] = {
      publicKey: leafKP.publicKey,
      privateKey: leafKP.privateKey,
      secret: newLeafSecret,
    };

    // Compute path secrets up to root
    const path: PathNodeUpdate[] = [];
    const nodePath = pathToRoot(this._myLeaf);
    const cop = copath(this._myLeaf);

    let currentSecret = newLeafSecret;

    for (let i = 1; i < nodePath.length; i++) {
      const nodeIdx = nodePath[i];
      const copathIdx = cop[i - 1];
      if (nodeIdx === undefined || copathIdx === undefined) {
        continue;
      }

      // Derive new path secret
      const pathSecret = derivePathSecret(currentSecret, nodeIdx);
      const nodeKP = deriveNodeKeypair(pathSecret);

      this._tree[nodeIdx] = {
        publicKey: nodeKP.publicKey,
        privateKey: nodeKP.privateKey,
        secret: pathSecret,
      };

      // Encrypt path secret to copath sibling
      const siblingNode = this._tree[copathIdx];
      if (siblingNode) {
        const { ciphertext, nonce } = encryptToNode(
          pathSecret,
          siblingNode.publicKey,
        );
        path.push({
          nodeIndex: nodeIdx,
          publicKey: nodeKP.publicKey,
          encryptedSecret: ciphertext,
          nonce,
        });
      }

      currentSecret = pathSecret;
    }

    // Derive new epoch from root secret
    this._epoch += 1;
    const rootSecret = this._tree[0]?.secret;
    if (rootSecret) {
      this._currentEpoch = deriveEpochSecrets(rootSecret, this._epoch);
    }

    // Sign the update
    const updateData = this._serializeUpdateForSigning(
      this._epoch,
      this._myLeaf,
      path,
    );
    const signature = sodium.crypto_sign_detached(
      updateData,
      this._signingKey,
    );

    return {
      epoch: this._epoch,
      senderLeaf: leafIndexToMember(this._myLeaf, this._numLeaves),
      path,
      signature,
    };
  }

  /**
   * Process an update from another member.
   * Derive new epoch secrets from the update.
   */
  async processUpdate(
    update: TreeKEMUpdate,
    senderSigningKey: Uint8Array,
  ): Promise<GroupEpoch> {
    await initSodium();

    // Verify signature
    const updateData = this._serializeUpdateForSigning(
      update.epoch,
      leafIndex(update.senderLeaf, this._numLeaves),
      update.path,
    );
    const sigValid = sodium.crypto_sign_verify_detached(
      update.signature,
      updateData,
      senderSigningKey,
    );
    if (!sigValid) {
      throw new Error("Invalid TreeKEM update signature");
    }

    // Ensure epoch is strictly increasing
    if (update.epoch <= this._epoch) {
      throw new Error(
        `Epoch must increase: got ${update.epoch}, current ${this._epoch}`,
      );
    }

    // Find the path node where we can decrypt (copath intersection)
    const senderLeafIdx = leafIndex(update.senderLeaf, this._numLeaves);
    const myPath = pathToRoot(this._myLeaf);
    const myPathSet = new Set(myPath);

    // Find the lowest common ancestor's child on our side
    let decryptedSecret: Uint8Array | null = null;

    for (const pathNode of update.path) {
      // Check if the copath sibling of this path node is on our path
      if (pathNode.nodeIndex > 0) {
        const sibling = siblingIndex(pathNode.nodeIndex);
        // The encrypted secret at pathNode is encrypted to sibling's key
        if (myPathSet.has(sibling) || sibling === this._myLeaf) {
          // Try to decrypt using our node's private key
          const ourNode = this._tree[sibling];
          if (ourNode?.privateKey) {
            decryptedSecret = decryptFromNode(
              pathNode.encryptedSecret,
              pathNode.nonce,
              ourNode.privateKey,
            );
            break;
          }
        }
      }
    }

    if (!decryptedSecret) {
      throw new Error("Could not decrypt any path node in TreeKEM update");
    }

    // Recompute path secrets from the decrypted secret up to root
    let currentSecret = decryptedSecret;

    // Find where our path and sender's path merge
    for (const pathNode of update.path) {
      const nodeIdx = pathNode.nodeIndex;
      if (myPathSet.has(nodeIdx) || nodeIdx === 0) {
        // This is on our path — derive the secret
        const nodeKP = deriveNodeKeypair(currentSecret);
        this._tree[nodeIdx] = {
          publicKey: pathNode.publicKey,
          privateKey: nodeKP.privateKey,
          secret: currentSecret,
        };

        if (nodeIdx > 0) {
          currentSecret = derivePathSecret(currentSecret, parentIndex(nodeIdx));
        }
      } else {
        // Not on our path — just update public key
        this._tree[nodeIdx] = { publicKey: pathNode.publicKey };
      }
    }

    // Update sender's leaf
    const senderLeafNode = update.path.length > 0 ? update.path[0] : null;
    if (senderLeafNode) {
      this._tree[senderLeafIdx] = { publicKey: senderLeafNode.publicKey };
    }

    // Derive new epoch
    this._epoch = update.epoch;
    const rootSecret = this._tree[0]?.secret;
    if (rootSecret) {
      this._currentEpoch = deriveEpochSecrets(rootSecret, this._epoch);
    } else {
      throw new Error("Failed to derive root secret after processing update");
    }

    return this._currentEpoch;
  }

  /**
   * Encrypt a message in the current epoch.
   */
  async encryptGroupMessage(plaintext: Uint8Array): Promise<{
    epoch: number;
    nonce: Uint8Array;
    ciphertext: Uint8Array;
  }> {
    await initSodium();

    if (!this._currentEpoch) {
      throw new Error("No epoch established — perform an update first");
    }

    const nonce = sodium.randombytes_buf(
      sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    );

    const epochBytes = new Uint8Array(4);
    epochBytes[0] = (this._epoch >>> 24) & 0xff;
    epochBytes[1] = (this._epoch >>> 16) & 0xff;
    epochBytes[2] = (this._epoch >>> 8) & 0xff;
    epochBytes[3] = this._epoch & 0xff;

    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      plaintext,
      epochBytes,
      null,
      nonce,
      this._currentEpoch.applicationSecret,
    );

    return { epoch: this._epoch, nonce, ciphertext: new Uint8Array(ciphertext) };
  }

  /**
   * Decrypt a message from the current epoch.
   */
  async decryptGroupMessage(
    epoch: number,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
  ): Promise<Uint8Array> {
    await initSodium();

    if (!this._currentEpoch || this._currentEpoch.epoch !== epoch) {
      throw new Error(
        `Epoch mismatch: message epoch=${epoch}, current=${this._currentEpoch?.epoch ?? "none"}`,
      );
    }

    const epochBytes = new Uint8Array(4);
    epochBytes[0] = (epoch >>> 24) & 0xff;
    epochBytes[1] = (epoch >>> 16) & 0xff;
    epochBytes[2] = (epoch >>> 8) & 0xff;
    epochBytes[3] = epoch & 0xff;

    return new Uint8Array(
      sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        ciphertext,
        epochBytes,
        nonce,
        this._currentEpoch.applicationSecret,
      ),
    );
  }

  /** Serialize update data for signing. */
  private _serializeUpdateForSigning(
    epoch: number,
    senderLeaf: number,
    path: PathNodeUpdate[],
  ): Uint8Array {
    const parts: Uint8Array[] = [];

    // Epoch
    const epochBytes = new Uint8Array(4);
    epochBytes[0] = (epoch >>> 24) & 0xff;
    epochBytes[1] = (epoch >>> 16) & 0xff;
    epochBytes[2] = (epoch >>> 8) & 0xff;
    epochBytes[3] = epoch & 0xff;
    parts.push(epochBytes);

    // Sender leaf
    const leafBytes = new Uint8Array(4);
    leafBytes[0] = (senderLeaf >>> 24) & 0xff;
    leafBytes[1] = (senderLeaf >>> 16) & 0xff;
    leafBytes[2] = (senderLeaf >>> 8) & 0xff;
    leafBytes[3] = senderLeaf & 0xff;
    parts.push(leafBytes);

    // Path public keys
    for (const node of path) {
      parts.push(node.publicKey);
    }

    let totalLen = 0;
    for (const p of parts) totalLen += p.length;
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const p of parts) {
      result.set(p, offset);
      offset += p.length;
    }
    return result;
  }
}

/** Convert leaf index back to member index. */
function leafIndexToMember(leaf: number, numLeaves: number): number {
  let n = 1;
  while (n < numLeaves) n *= 2;
  return leaf - (n - 1);
}
