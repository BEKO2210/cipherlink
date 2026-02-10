/**
 * Double Ratchet Algorithm — forward secrecy and post-compromise security.
 *
 * Implements the Signal Double Ratchet protocol:
 * - DH Ratchet: New ephemeral X25519 keypair per turn
 * - Symmetric Ratchet: KDF chains for sending and receiving
 * - Skipped message keys: Handle out-of-order delivery
 *
 * Every message uses a unique encryption key. Compromising one key
 * does NOT expose past or future messages.
 *
 * Reference: https://signal.org/docs/specifications/doubleratchet/
 *
 * @module ratchet
 * @author Belkis Aslani
 */
import sodium from "libsodium-wrappers-sumo";
import { initSodium } from "./sodium.js";
import { toBase64 } from "./base64.js";
import { padMessage, unpadMessage } from "./padding.js";

const MAX_SKIP = 256; // Maximum skipped message keys to store
const MESSAGE_PADDING_BLOCK = 256; // Pad all messages to 256-byte blocks

/** Ratchet message header (sent in cleartext alongside ciphertext). */
export interface RatchetHeader {
  /** Sender's current DH ratchet public key. */
  dhPublicKey: Uint8Array;
  /** Number of messages in previous sending chain. */
  previousChainLength: number;
  /** Message number in current sending chain. */
  messageNumber: number;
}

/** Encrypted message output from the ratchet. */
export interface RatchetMessage {
  header: RatchetHeader;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

/** Serializable ratchet session state. */
export interface RatchetState {
  /** Our current DH ratchet keypair. */
  dhSending: { publicKey: Uint8Array; privateKey: Uint8Array };
  /** Their current DH ratchet public key. */
  dhReceiving: Uint8Array | null;
  /** Root key (used to derive new chain keys on DH ratchet steps). */
  rootKey: Uint8Array;
  /** Current sending chain key. */
  sendingChainKey: Uint8Array | null;
  /** Current receiving chain key. */
  receivingChainKey: Uint8Array | null;
  /** Number of messages sent in current sending chain. */
  sendCount: number;
  /** Number of messages received in current receiving chain. */
  receiveCount: number;
  /** Previous sending chain length (for skip tracking). */
  previousSendCount: number;
  /** Skipped message keys: "base64(dhPub)|msgNum" -> messageKey. */
  skippedKeys: Map<string, Uint8Array>;
}

// --- KDF Functions (per Signal spec) ---

/**
 * KDF_RK: Root key ratchet.
 * Input: root key + DH output
 * Output: (new root key, chain key)
 */
function kdfRK(
  rootKey: Uint8Array,
  dhOutput: Uint8Array,
): { rootKey: Uint8Array; chainKey: Uint8Array } {
  // HKDF with rootKey as salt, dhOutput as IKM
  const prk = new Uint8Array(
    sodium.crypto_auth_hmacsha256(dhOutput, rootKey),
  );

  // Expand: output 64 bytes (32 for new root key + 32 for chain key)
  const info1 = new Uint8Array([0x01]);
  const t1 = new Uint8Array(sodium.crypto_auth_hmacsha256(info1, prk));

  const info2 = new Uint8Array(t1.length + 1);
  info2.set(t1, 0);
  info2[info2.length - 1] = 0x02;
  const t2 = new Uint8Array(sodium.crypto_auth_hmacsha256(info2, prk));

  sodium.memzero(prk);

  return { rootKey: t1, chainKey: t2 };
}

/**
 * KDF_CK: Chain key ratchet.
 * Input: chain key
 * Output: (new chain key, message key)
 */
function kdfCK(
  chainKey: Uint8Array,
): { chainKey: Uint8Array; messageKey: Uint8Array } {
  // message key = HMAC(chainKey, 0x01)
  const messageKey = new Uint8Array(
    sodium.crypto_auth_hmacsha256(new Uint8Array([0x01]), chainKey),
  );
  // new chain key = HMAC(chainKey, 0x02)
  const newChainKey = new Uint8Array(
    sodium.crypto_auth_hmacsha256(new Uint8Array([0x02]), chainKey),
  );

  return { chainKey: newChainKey, messageKey };
}

/**
 * Serialize a header for use as associated data in AEAD.
 */
function serializeHeader(header: RatchetHeader): Uint8Array {
  const json = JSON.stringify({
    dh: toBase64(header.dhPublicKey),
    pn: header.previousChainLength,
    n: header.messageNumber,
  });
  return new TextEncoder().encode(json);
}

// --- Session Initialization ---

/**
 * Initialize a ratchet session as the initiator (Alice).
 * Called after X3DH, with the shared secret as the initial root key.
 *
 * Alice knows Bob's signed prekey (used as initial DH receiving key).
 */
export async function initSessionAsInitiator(
  sharedSecret: Uint8Array,
  bobSignedPreKey: Uint8Array,
): Promise<RatchetState> {
  await initSodium();

  // Generate Alice's initial DH ratchet keypair
  const dhSending = sodium.crypto_box_keypair();

  // Perform initial DH ratchet step
  const dhOutput = sodium.crypto_scalarmult(
    dhSending.privateKey,
    bobSignedPreKey,
  );
  const { rootKey, chainKey } = kdfRK(sharedSecret, dhOutput);
  sodium.memzero(dhOutput);

  return {
    dhSending: { publicKey: dhSending.publicKey, privateKey: dhSending.privateKey },
    dhReceiving: bobSignedPreKey,
    rootKey,
    sendingChainKey: chainKey,
    receivingChainKey: null,
    sendCount: 0,
    receiveCount: 0,
    previousSendCount: 0,
    skippedKeys: new Map(),
  };
}

/**
 * Initialize a ratchet session as the responder (Bob).
 * Called after X3DH, with the shared secret and Bob's signed prekey.
 */
export async function initSessionAsResponder(
  sharedSecret: Uint8Array,
  bobSignedPreKey: { publicKey: Uint8Array; privateKey: Uint8Array },
): Promise<RatchetState> {
  await initSodium();

  return {
    dhSending: bobSignedPreKey,
    dhReceiving: null,
    rootKey: sharedSecret,
    sendingChainKey: null,
    receivingChainKey: null,
    sendCount: 0,
    receiveCount: 0,
    previousSendCount: 0,
    skippedKeys: new Map(),
  };
}

// --- Encrypt / Decrypt ---

/**
 * Encrypt a message using the Double Ratchet.
 *
 * Advances the sending chain by one step, deriving a unique message key.
 * Returns the encrypted message with ratchet header.
 */
export async function ratchetEncrypt(
  state: RatchetState,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
): Promise<RatchetMessage> {
  await initSodium();

  if (!state.sendingChainKey) {
    throw new Error("Sending chain not initialized");
  }

  // Advance sending chain
  const { chainKey, messageKey } = kdfCK(state.sendingChainKey);
  state.sendingChainKey = chainKey;

  // Build header
  const header: RatchetHeader = {
    dhPublicKey: state.dhSending.publicKey,
    previousChainLength: state.previousSendCount,
    messageNumber: state.sendCount,
  };
  state.sendCount += 1;

  // Pad plaintext
  const padded = padMessage(plaintext, MESSAGE_PADDING_BLOCK);

  // AEAD encrypt: associated data = AD || serialized header
  const headerBytes = serializeHeader(header);
  const fullAD = new Uint8Array(associatedData.length + headerBytes.length);
  fullAD.set(associatedData, 0);
  fullAD.set(headerBytes, associatedData.length);

  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  );
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    padded,
    fullAD,
    null,
    nonce,
    messageKey,
  );

  sodium.memzero(messageKey);

  return { header, nonce, ciphertext };
}

/**
 * Skip message keys in the current receiving chain (for out-of-order messages).
 */
function skipMessageKeys(state: RatchetState, until: number): void {
  if (!state.receivingChainKey) return;

  if (until - state.receiveCount > MAX_SKIP) {
    throw new Error("Too many skipped messages");
  }

  while (state.receiveCount < until) {
    const { chainKey, messageKey } = kdfCK(state.receivingChainKey);
    state.receivingChainKey = chainKey;

    const key = `${toBase64(state.dhReceiving!)}|${state.receiveCount}`;
    state.skippedKeys.set(key, messageKey);
    state.receiveCount += 1;

    // Evict oldest skipped keys if too many
    if (state.skippedKeys.size > MAX_SKIP * 2) {
      const firstKey = state.skippedKeys.keys().next().value;
      if (firstKey !== undefined) {
        const removed = state.skippedKeys.get(firstKey);
        if (removed) sodium.memzero(removed);
        state.skippedKeys.delete(firstKey);
      }
    }
  }
}

/**
 * Perform a DH ratchet step (when receiving a new DH key from the other party).
 */
function dhRatchetStep(state: RatchetState, header: RatchetHeader): void {
  state.previousSendCount = state.sendCount;
  state.sendCount = 0;
  state.receiveCount = 0;
  state.dhReceiving = header.dhPublicKey;

  // Derive new receiving chain
  const dhOutput1 = sodium.crypto_scalarmult(
    state.dhSending.privateKey,
    state.dhReceiving,
  );
  const rk1 = kdfRK(state.rootKey, dhOutput1);
  state.rootKey = rk1.rootKey;
  state.receivingChainKey = rk1.chainKey;
  sodium.memzero(dhOutput1);

  // Generate new DH keypair for sending
  const newDH = sodium.crypto_box_keypair();
  state.dhSending = { publicKey: newDH.publicKey, privateKey: newDH.privateKey };

  // Derive new sending chain
  const dhOutput2 = sodium.crypto_scalarmult(
    state.dhSending.privateKey,
    state.dhReceiving,
  );
  const rk2 = kdfRK(state.rootKey, dhOutput2);
  state.rootKey = rk2.rootKey;
  state.sendingChainKey = rk2.chainKey;
  sodium.memzero(dhOutput2);
}

/**
 * Try to decrypt with a skipped message key.
 */
function trySkippedKey(
  state: RatchetState,
  header: RatchetHeader,
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  associatedData: Uint8Array,
): Uint8Array | null {
  const key = `${toBase64(header.dhPublicKey)}|${header.messageNumber}`;
  const messageKey = state.skippedKeys.get(key);
  if (!messageKey) return null;

  state.skippedKeys.delete(key);

  const headerBytes = serializeHeader(header);
  const fullAD = new Uint8Array(associatedData.length + headerBytes.length);
  fullAD.set(associatedData, 0);
  fullAD.set(headerBytes, associatedData.length);

  const padded = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    fullAD,
    nonce,
    messageKey,
  );

  sodium.memzero(messageKey);

  return unpadMessage(padded, MESSAGE_PADDING_BLOCK);
}

/**
 * Decrypt a message using the Double Ratchet.
 *
 * Handles DH ratchet steps and out-of-order messages via skipped keys.
 *
 * @returns The decrypted plaintext bytes
 * @throws If decryption fails (wrong key, tampered, or replay)
 */
export async function ratchetDecrypt(
  state: RatchetState,
  message: RatchetMessage,
  associatedData: Uint8Array,
): Promise<Uint8Array> {
  await initSodium();

  const { header, ciphertext, nonce } = message;

  // Try skipped message keys first
  const skipped = trySkippedKey(
    state,
    header,
    ciphertext,
    nonce,
    associatedData,
  );
  if (skipped) return skipped;

  // Check if we need a DH ratchet step
  const receivingKeyChanged =
    !state.dhReceiving ||
    toBase64(header.dhPublicKey) !== toBase64(state.dhReceiving);

  if (receivingKeyChanged) {
    // Skip messages in the old receiving chain
    if (state.dhReceiving) {
      skipMessageKeys(state, header.previousChainLength);
    }
    // Perform DH ratchet
    dhRatchetStep(state, header);
  }

  // Skip any messages in the new receiving chain
  skipMessageKeys(state, header.messageNumber);

  // Advance receiving chain
  if (!state.receivingChainKey) {
    throw new Error("Receiving chain not initialized");
  }
  const { chainKey, messageKey } = kdfCK(state.receivingChainKey);
  state.receivingChainKey = chainKey;
  state.receiveCount += 1;

  // Decrypt
  const headerBytes = serializeHeader(header);
  const fullAD = new Uint8Array(associatedData.length + headerBytes.length);
  fullAD.set(associatedData, 0);
  fullAD.set(headerBytes, associatedData.length);

  const padded = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    fullAD,
    nonce,
    messageKey,
  );

  sodium.memzero(messageKey);

  return unpadMessage(padded, MESSAGE_PADDING_BLOCK);
}
