/**
 * Group E2EE — Sender Keys protocol with Ed25519 signatures.
 * Each member generates a sender key; group messages are encrypted with
 * a chain-ratcheted symmetric key and signed for authenticity.
 *
 * Security fixes:
 * - AAD binding on group messages (prevents cross-group replay)
 * - Chain fast-forward limit (prevents DoS via high chainIndex)
 * - Proper HKDF via deriveKey export from crypto module
 *
 * @author Belkis Aslani
 */
import {
  initCrypto,
  sodium,
  toBase64,
  fromBase64,
  toHex,
  randomBytes,
  deriveKey,
} from "./crypto";

/** Maximum chain fast-forward to prevent DoS */
const MAX_CHAIN_SKIP = 1000;

export interface SenderKey {
  keyId: string;
  chainKey: Uint8Array;
  chainIndex: number;
  signingPublicKey: Uint8Array;
  signingPrivateKey: Uint8Array;
}

export interface SenderKeyDistribution {
  groupId: string;
  senderPub: string;
  keyId: string;
  chainKey: string;
  chainIndex: number;
  signingPublicKey: string;
}

export interface GroupMessage {
  groupId: string;
  keyId: string;
  chainIndex: number;
  nonce: string;
  ciphertext: string;
  signature: string;
}

/**
 * Generate a new sender key for group messaging.
 */
export async function generateSenderKey(_groupId: string): Promise<SenderKey> {
  await initCrypto();
  const chainKey = randomBytes(32);
  const sigKp = sodium.crypto_sign_keypair();
  const keyId = toHex(randomBytes(16));

  return {
    keyId,
    chainKey,
    chainIndex: 0,
    signingPublicKey: sigKp.publicKey,
    signingPrivateKey: sigKp.privateKey,
  };
}

/**
 * Create a distribution message that shares our sender key with group members.
 */
export function createSenderKeyDistribution(
  senderKey: SenderKey,
  groupId: string,
  senderPub: Uint8Array,
): SenderKeyDistribution {
  return {
    groupId,
    senderPub: toBase64(senderPub),
    keyId: senderKey.keyId,
    chainKey: toBase64(senderKey.chainKey),
    chainIndex: senderKey.chainIndex,
    signingPublicKey: toBase64(senderKey.signingPublicKey),
  };
}

/**
 * Derive the next message key and chain key using HKDF with domain separation.
 */
function ratchetChainKey(chainKey: Uint8Array): {
  messageKey: Uint8Array;
  nextChainKey: Uint8Array;
} {
  const messageKey = deriveKey(chainKey, "cipherlink-group-msg-key");
  const nextChainKey = deriveKey(chainKey, "cipherlink-group-chain-next");
  return { messageKey, nextChainKey };
}

/**
 * Build AAD for group messages — binds groupId and keyId to prevent cross-group replay.
 */
function buildGroupAad(groupId: string, keyId: string, chainIndex: number): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({ groupId, keyId, chainIndex, protocol: "cipherlink-group-v1" }),
  );
}

/**
 * Encrypt a message for the group using sender key.
 */
export async function groupEncrypt(
  senderKey: SenderKey,
  groupId: string,
  plaintext: string,
): Promise<{ message: GroupMessage; updatedKey: SenderKey }> {
  await initCrypto();

  const { messageKey, nextChainKey } = ratchetChainKey(senderKey.chainKey);
  const nonce = randomBytes(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  );
  const plaintextBytes = new TextEncoder().encode(plaintext);

  // AAD binds the message to this specific group and chain position
  const aad = buildGroupAad(groupId, senderKey.keyId, senderKey.chainIndex);

  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintextBytes,
    aad,
    null,
    nonce,
    messageKey,
  );

  // Sign the ciphertext for authenticity
  const signature = sodium.crypto_sign_detached(
    ciphertext,
    senderKey.signingPrivateKey,
  );

  sodium.memzero(messageKey);

  const message: GroupMessage = {
    groupId,
    keyId: senderKey.keyId,
    chainIndex: senderKey.chainIndex,
    nonce: toBase64(nonce),
    ciphertext: toBase64(ciphertext),
    signature: toBase64(signature),
  };

  const updatedKey: SenderKey = {
    ...senderKey,
    chainKey: nextChainKey,
    chainIndex: senderKey.chainIndex + 1,
  };

  return { message, updatedKey };
}

/**
 * Decrypt a group message using the sender's key.
 * Chain fast-forward is limited to MAX_CHAIN_SKIP to prevent DoS.
 */
export async function groupDecrypt(
  senderKey: SenderKey,
  message: GroupMessage,
): Promise<string> {
  await initCrypto();

  const ciphertext = fromBase64(message.ciphertext);
  const signature = fromBase64(message.signature);
  const nonce = fromBase64(message.nonce);

  // Verify signature first (before any expensive chain operations)
  const valid = sodium.crypto_sign_verify_detached(
    signature,
    ciphertext,
    senderKey.signingPublicKey,
  );
  if (!valid) {
    throw new Error("Invalid group message signature");
  }

  // Enforce chain skip limit to prevent DoS
  const skip = message.chainIndex - senderKey.chainIndex;
  if (skip < 0) {
    throw new Error("Message chain index is behind current state (possible replay)");
  }
  if (skip > MAX_CHAIN_SKIP) {
    throw new Error(`Chain skip too large: ${skip} > ${MAX_CHAIN_SKIP}`);
  }

  // Advance chain to the right index
  let currentKey = senderKey.chainKey;
  let currentIndex = senderKey.chainIndex;
  while (currentIndex < message.chainIndex) {
    const { nextChainKey } = ratchetChainKey(currentKey);
    currentKey = nextChainKey;
    currentIndex++;
  }

  const { messageKey } = ratchetChainKey(currentKey);

  // Reconstruct AAD for verification
  const aad = buildGroupAad(message.groupId, message.keyId, message.chainIndex);

  const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    aad,
    nonce,
    messageKey,
  );

  sodium.memzero(messageKey);
  return new TextDecoder().decode(plaintext);
}

/**
 * Parse a sender key distribution message from another member.
 */
export function parseSenderKeyDistribution(
  dist: SenderKeyDistribution,
): Omit<SenderKey, "signingPrivateKey"> & { signingPrivateKey: Uint8Array } {
  return {
    keyId: dist.keyId,
    chainKey: fromBase64(dist.chainKey),
    chainIndex: dist.chainIndex,
    signingPublicKey: fromBase64(dist.signingPublicKey),
    signingPrivateKey: new Uint8Array(0),
  };
}
