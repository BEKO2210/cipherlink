/**
 * Sender Keys — efficient group messaging protocol.
 *
 * Each group member generates a symmetric "sender key" and distributes it
 * to all other members via pairwise (1:1) encrypted channels. To send to
 * the group, the sender encrypts with their sender key. All members who
 * hold that sender key can decrypt.
 *
 * Advantages over pairwise fan-out:
 * - O(1) encryption per message (not O(n))
 * - Same ciphertext for all recipients
 *
 * Inspired by Signal's Sender Keys protocol.
 *
 * @module group
 * @author Belkis Aslani
 */
import sodium from "libsodium-wrappers-sumo";
import { initSodium } from "./sodium.js";
import { toBase64 } from "./base64.js";
import { padMessage, unpadMessage } from "./padding.js";

const GROUP_PADDING_BLOCK = 256;

/** A sender key for group messaging. */
export interface SenderKey {
  /** Unique key ID. */
  keyId: string;
  /** Symmetric chain key (ratcheted forward per message). */
  chainKey: Uint8Array;
  /** Current chain index (message counter). */
  chainIndex: number;
  /** Signing key for sender authentication within the group. */
  signingKey: Uint8Array;
  /** Signing private key (only held by the sender). */
  signingPrivateKey?: Uint8Array;
}

/** Sender key state for distribution to group members. */
export interface SenderKeyDistribution {
  groupId: string;
  keyId: string;
  chainKey: string; // base64
  chainIndex: number;
  signingKey: string; // base64
  senderPub: string; // base64 — identity of the sender
}

/** Group message (encrypted with sender key). */
export interface GroupMessage {
  groupId: string;
  keyId: string;
  chainIndex: number;
  nonce: string; // base64
  ciphertext: string; // base64
  signature: string; // base64 — Ed25519 signature over (groupId + ciphertext)
}

/**
 * Generate a new sender key for group messaging.
 *
 * @param groupId - The group identifier
 * @returns A sender key to be distributed to group members
 */
export async function generateSenderKey(groupId: string): Promise<SenderKey> {
  await initSodium();

  const chainKey = sodium.randombytes_buf(32);
  const signingKP = sodium.crypto_sign_keypair();
  const keyId = `${groupId}:${sodium.to_hex(sodium.randombytes_buf(8))}`;

  return {
    keyId,
    chainKey,
    chainIndex: 0,
    signingKey: signingKP.publicKey,
    signingPrivateKey: signingKP.privateKey,
  };
}

/**
 * Create a sender key distribution message.
 * This is sent to each group member via pairwise encrypted channel.
 */
export function createSenderKeyDistribution(
  senderKey: SenderKey,
  groupId: string,
  senderPub: Uint8Array,
): SenderKeyDistribution {
  return {
    groupId,
    keyId: senderKey.keyId,
    chainKey: toBase64(senderKey.chainKey),
    chainIndex: senderKey.chainIndex,
    signingKey: toBase64(senderKey.signingKey),
    senderPub: toBase64(senderPub),
  };
}

/**
 * Advance the sender key chain to derive a message key.
 * Uses HMAC-SHA256 chain ratchet (same as Double Ratchet chain step).
 */
function advanceChain(chainKey: Uint8Array): {
  newChainKey: Uint8Array;
  messageKey: Uint8Array;
} {
  const messageKey = new Uint8Array(
    sodium.crypto_auth_hmacsha256(new Uint8Array([0x01]), chainKey),
  );
  const newChainKey = new Uint8Array(
    sodium.crypto_auth_hmacsha256(new Uint8Array([0x02]), chainKey),
  );
  return { newChainKey, messageKey };
}

/**
 * Encrypt a message for a group using the sender's sender key.
 *
 * @param senderKey - The sender's own sender key (must have signingPrivateKey)
 * @param groupId - The group identifier
 * @param plaintext - The message to encrypt
 * @returns A group message (encrypted and signed)
 */
export async function groupEncrypt(
  senderKey: SenderKey,
  groupId: string,
  plaintext: Uint8Array,
): Promise<GroupMessage> {
  await initSodium();

  if (!senderKey.signingPrivateKey) {
    throw new Error("Sender key must have signing private key");
  }

  // Advance chain
  const { newChainKey, messageKey } = advanceChain(senderKey.chainKey);
  const currentIndex = senderKey.chainIndex;
  senderKey.chainKey = newChainKey;
  senderKey.chainIndex += 1;

  // Pad and encrypt
  const padded = padMessage(plaintext, GROUP_PADDING_BLOCK);
  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  );
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    padded,
    null,
    null,
    nonce,
    messageKey,
  );

  sodium.memzero(messageKey);

  // Sign the ciphertext for sender authentication
  const signData = new TextEncoder().encode(`${groupId}:${toBase64(ciphertext)}`);
  const signature = sodium.crypto_sign_detached(
    signData,
    senderKey.signingPrivateKey,
  );

  return {
    groupId,
    keyId: senderKey.keyId,
    chainIndex: currentIndex,
    nonce: toBase64(nonce),
    ciphertext: toBase64(ciphertext),
    signature: toBase64(signature),
  };
}

/**
 * Decrypt a group message using a received sender key.
 *
 * @param senderKey - The sender's key (received via distribution message)
 * @param message - The encrypted group message
 * @returns Decrypted plaintext bytes
 * @throws If decryption or signature verification fails
 */
export async function groupDecrypt(
  senderKey: SenderKey,
  message: GroupMessage,
): Promise<Uint8Array> {
  await initSodium();

  const ciphertextBytes = sodium.from_base64(
    message.ciphertext,
    sodium.base64_variants.ORIGINAL,
  );
  const nonceBytes = sodium.from_base64(
    message.nonce,
    sodium.base64_variants.ORIGINAL,
  );
  const signatureBytes = sodium.from_base64(
    message.signature,
    sodium.base64_variants.ORIGINAL,
  );

  // Verify signature
  const signData = new TextEncoder().encode(
    `${message.groupId}:${message.ciphertext}`,
  );
  const sigValid = sodium.crypto_sign_verify_detached(
    signatureBytes,
    signData,
    senderKey.signingKey,
  );
  if (!sigValid) {
    throw new Error("Group message signature verification failed");
  }

  // Advance chain to the correct index
  let currentKey: Uint8Array = new Uint8Array(senderKey.chainKey);
  let messageKey: Uint8Array | null = null;

  // We need to advance from senderKey.chainIndex to message.chainIndex
  const stepsNeeded = message.chainIndex - senderKey.chainIndex;
  if (stepsNeeded < 0) {
    throw new Error("Message chain index is behind our state — possible replay");
  }

  for (let i = 0; i <= stepsNeeded; i++) {
    const result = advanceChain(currentKey);
    sodium.memzero(currentKey);
    currentKey = new Uint8Array(result.newChainKey);
    if (i === stepsNeeded) {
      messageKey = result.messageKey;
    } else {
      sodium.memzero(result.messageKey);
    }
  }

  // Update sender key state
  senderKey.chainKey = currentKey;
  senderKey.chainIndex = message.chainIndex + 1;

  if (!messageKey) {
    throw new Error("Failed to derive message key");
  }

  // Decrypt
  const padded = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertextBytes,
    null,
    nonceBytes,
    messageKey,
  );

  sodium.memzero(messageKey);

  return unpadMessage(padded, GROUP_PADDING_BLOCK);
}

/**
 * Group session manager — tracks sender keys for all members in a group.
 */
export class GroupSession {
  readonly groupId: string;
  /** Our own sender key. */
  ownSenderKey: SenderKey | null = null;
  /** Sender keys from other group members: keyId -> SenderKey. */
  memberKeys: Map<string, SenderKey> = new Map();

  constructor(groupId: string) {
    this.groupId = groupId;
  }

  /**
   * Initialize our sender key for this group.
   */
  async initOwnKey(): Promise<SenderKey> {
    this.ownSenderKey = await generateSenderKey(this.groupId);
    return this.ownSenderKey;
  }

  /**
   * Register a sender key from another group member.
   */
  registerMemberKey(distribution: SenderKeyDistribution): void {
    this.memberKeys.set(distribution.keyId, {
      keyId: distribution.keyId,
      chainKey: sodium.from_base64(
        distribution.chainKey,
        sodium.base64_variants.ORIGINAL,
      ),
      chainIndex: distribution.chainIndex,
      signingKey: sodium.from_base64(
        distribution.signingKey,
        sodium.base64_variants.ORIGINAL,
      ),
    });
  }

  /**
   * Encrypt a message for the group.
   */
  async encrypt(plaintext: Uint8Array): Promise<GroupMessage> {
    if (!this.ownSenderKey) {
      throw new Error("Own sender key not initialized");
    }
    return groupEncrypt(this.ownSenderKey, this.groupId, plaintext);
  }

  /**
   * Decrypt a message from a group member.
   */
  async decrypt(message: GroupMessage): Promise<Uint8Array> {
    const senderKey = this.memberKeys.get(message.keyId);
    if (!senderKey) {
      throw new Error(`Unknown sender key: ${message.keyId}`);
    }
    return groupDecrypt(senderKey, message);
  }
}
