/**
 * Group E2EE — Sender Keys protocol with Ed25519 signatures.
 * Each member generates a sender key; group messages are encrypted with
 * a chain-ratcheted symmetric key and signed for authenticity.
 * @author Belkis Aslani
 */
import {
  initCrypto,
  sodium,
  toBase64,
  fromBase64,
  toHex,
  randomBytes,
} from "./crypto";

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
 * Derive the next message key from the chain key using HKDF.
 */
function ratchetChainKey(chainKey: Uint8Array): {
  messageKey: Uint8Array;
  nextChainKey: Uint8Array;
} {
  // Message key = HMAC(chainKey, 0x01)
  const msgInput = new Uint8Array([0x01]);
  const messageKey = sodium.crypto_auth_hmacsha256(msgInput, chainKey);

  // Next chain key = HMAC(chainKey, 0x02)
  const chainInput = new Uint8Array([0x02]);
  const nextChainKey = sodium.crypto_auth_hmacsha256(chainInput, chainKey);

  return { messageKey, nextChainKey };
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

  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintextBytes,
    null,
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
 */
export async function groupDecrypt(
  senderKey: SenderKey,
  message: GroupMessage,
): Promise<string> {
  await initCrypto();

  const ciphertext = fromBase64(message.ciphertext);
  const signature = fromBase64(message.signature);
  const nonce = fromBase64(message.nonce);

  // Verify signature
  const valid = sodium.crypto_sign_verify_detached(
    signature,
    ciphertext,
    senderKey.signingPublicKey,
  );
  if (!valid) {
    throw new Error("Invalid group message signature");
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

  const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    null,
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
    signingPrivateKey: new Uint8Array(0), // Not available for remote members
  };
}
