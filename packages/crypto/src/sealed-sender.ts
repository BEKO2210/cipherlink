/**
 * Sealed Sender — hide sender identity from the server.
 *
 * The server only sees the recipient's public key. The sender's identity
 * is encrypted inside the envelope and revealed only after decryption.
 *
 * How it works:
 * 1. Alice generates an ephemeral X25519 keypair
 * 2. Alice computes a shared secret: DH(ephemeral, recipientPub)
 * 3. Alice encrypts {senderIdentity, innerMessage} with the shared secret
 * 4. The outer envelope contains: recipientPub + ephemeral public + ciphertext
 * 5. Server sees only recipientPub — no sender information
 * 6. Bob decrypts the outer layer with DH(bobPriv, ephemeral), revealing sender
 *
 * @module sealed-sender
 * @author Belkis Aslani
 */
import sodium from "libsodium-wrappers-sumo";
import { initSodium } from "./sodium.js";
import { toBase64, fromBase64 } from "./base64.js";

const SEALED_VERSION = 1;
const SEALED_KDF_INFO = new TextEncoder().encode("CipherLink_SealedSender_v1");

export interface SealedEnvelope {
  v: number;
  /** Recipient's public key (only visible routing info). */
  recipientPub: string; // base64
  /** Ephemeral public key for DH. */
  ephemeralPub: string; // base64
  /** Nonce for outer encryption. */
  sealNonce: string; // base64
  /** Encrypted blob: contains sender identity + inner payload. */
  sealed: string; // base64
}

export interface SealedContent {
  senderPub: string; // base64
  payload: string; // base64 — the inner encrypted message
}

/**
 * Derive a sealed-sender encryption key from an ephemeral DH.
 */
function sealKDF(dhOutput: Uint8Array): Uint8Array {
  const salt = new Uint8Array(32);
  const prk = new Uint8Array(
    sodium.crypto_auth_hmacsha256(dhOutput, salt),
  );
  const info = new Uint8Array(SEALED_KDF_INFO.length + 1);
  info.set(SEALED_KDF_INFO, 0);
  info[info.length - 1] = 1;
  const key = new Uint8Array(sodium.crypto_auth_hmacsha256(info, prk));
  sodium.memzero(prk);
  return key;
}

/**
 * Seal a message — encrypt the sender's identity along with the inner payload.
 *
 * @param senderPub - Sender's public key (to be hidden from server)
 * @param recipientPub - Recipient's public key (visible to server for routing)
 * @param innerPayload - The pre-encrypted inner message (e.g., ratchet envelope as bytes)
 * @returns A sealed envelope where the sender is hidden
 */
export async function sealMessage(
  senderPub: Uint8Array,
  recipientPub: Uint8Array,
  innerPayload: Uint8Array,
): Promise<SealedEnvelope> {
  await initSodium();

  // Generate ephemeral keypair
  const ephemeral = sodium.crypto_box_keypair();

  // Compute shared secret for the outer encryption
  const dhOutput = sodium.crypto_scalarmult(
    ephemeral.privateKey,
    recipientPub,
  );
  const sealKey = sealKDF(dhOutput);
  sodium.memzero(dhOutput);

  // Build inner content: sender identity + inner payload
  const content: SealedContent = {
    senderPub: toBase64(senderPub),
    payload: toBase64(innerPayload),
  };
  const contentBytes = new TextEncoder().encode(JSON.stringify(content));

  // Encrypt inner content
  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  );
  const sealed = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    contentBytes,
    null,
    null,
    nonce,
    sealKey,
  );

  sodium.memzero(sealKey);
  sodium.memzero(ephemeral.privateKey);

  return {
    v: SEALED_VERSION,
    recipientPub: toBase64(recipientPub),
    ephemeralPub: toBase64(ephemeral.publicKey),
    sealNonce: toBase64(nonce),
    sealed: toBase64(sealed),
  };
}

/**
 * Unseal a message — decrypt to reveal sender identity and inner payload.
 *
 * @param recipientPriv - Recipient's private key
 * @param envelope - The sealed envelope
 * @returns The sender's public key and the inner payload bytes
 * @throws If decryption fails
 */
export async function unsealMessage(
  recipientPriv: Uint8Array,
  envelope: SealedEnvelope,
): Promise<{ senderPub: Uint8Array; payload: Uint8Array }> {
  await initSodium();

  if (envelope.v !== SEALED_VERSION) {
    throw new Error(`Unsupported sealed envelope version: ${envelope.v}`);
  }

  const ephemeralPub = fromBase64(envelope.ephemeralPub);
  const nonce = fromBase64(envelope.sealNonce);
  const sealed = fromBase64(envelope.sealed);

  // Compute shared secret
  const dhOutput = sodium.crypto_scalarmult(recipientPriv, ephemeralPub);
  const sealKey = sealKDF(dhOutput);
  sodium.memzero(dhOutput);

  // Decrypt
  let contentBytes: Uint8Array;
  try {
    contentBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      sealed,
      null,
      nonce,
      sealKey,
    );
  } catch {
    throw new Error("Sealed envelope decryption failed");
  } finally {
    sodium.memzero(sealKey);
  }

  const content = JSON.parse(
    new TextDecoder().decode(contentBytes),
  ) as SealedContent;

  return {
    senderPub: fromBase64(content.senderPub),
    payload: fromBase64(content.payload),
  };
}
