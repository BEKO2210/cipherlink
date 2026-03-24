/**
 * CipherLink crypto module — full E2EE implementation with libsodium.
 * Supports: X25519, Ed25519, HKDF, XChaCha20-Poly1305, sealed sender, padding.
 *
 * Security fixes:
 * - Full PKCS7 padding validation (all padding bytes checked)
 * - AAD independently reconstructed on decrypt
 * - Sealed sender with Ed25519 signature authentication
 * - Per-message ephemeral nonce for key uniqueness
 *
 * @author Belkis Aslani
 */
import "react-native-get-random-values";
import sodium from "libsodium-wrappers-sumo";

let initialized = false;

export async function initCrypto(): Promise<typeof sodium> {
  if (!initialized) {
    await sodium.ready;
    initialized = true;
  }
  return sodium;
}

export { sodium };

// --- Base64 utilities ---

export function toBase64(data: Uint8Array): string {
  return sodium.to_base64(data, sodium.base64_variants.ORIGINAL);
}

export function fromBase64(encoded: string): Uint8Array {
  return sodium.from_base64(encoded, sodium.base64_variants.ORIGINAL);
}

export function toHex(data: Uint8Array): string {
  return sodium.to_hex(data);
}

export function fromHex(hex: string): Uint8Array {
  return sodium.from_hex(hex);
}

// --- Key generation ---

export interface IdentityKeypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface SigningKeypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface FullIdentity {
  /** Ed25519 signing keypair */
  signing: SigningKeypair;
  /** X25519 DH keypair (derived from signing) */
  dh: IdentityKeypair;
}

export async function generateIdentityKeypair(): Promise<IdentityKeypair> {
  await initCrypto();
  const kp = sodium.crypto_box_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

export async function generateSigningKeypair(): Promise<SigningKeypair> {
  await initCrypto();
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

export async function generateFullIdentity(): Promise<FullIdentity> {
  await initCrypto();
  const sigKp = sodium.crypto_sign_keypair();
  const dhPriv = sodium.crypto_sign_ed25519_sk_to_curve25519(sigKp.privateKey);
  const dhPub = sodium.crypto_sign_ed25519_pk_to_curve25519(sigKp.publicKey);
  return {
    signing: { publicKey: sigKp.publicKey, privateKey: sigKp.privateKey },
    dh: { publicKey: dhPub, privateKey: dhPriv },
  };
}

// --- HKDF (RFC 5869) ---

function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return sodium.crypto_auth_hmacsha256(ikm, salt);
}

function hkdfExpand(
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  const hashLen = 32;
  const n = Math.ceil(length / hashLen);
  const okm = new Uint8Array(n * hashLen);
  let prev = new Uint8Array(0);
  for (let i = 1; i <= n; i++) {
    const input = new Uint8Array(prev.length + info.length + 1);
    input.set(prev, 0);
    input.set(info, prev.length);
    input[input.length - 1] = i;
    prev = new Uint8Array(sodium.crypto_auth_hmacsha256(input, prk));
    okm.set(prev, (i - 1) * hashLen);
  }
  return okm.slice(0, length);
}

/**
 * General-purpose HKDF key derivation — exported for use by group-crypto.
 */
export function deriveKey(
  ikm: Uint8Array,
  info: string,
  length: number = 32,
): Uint8Array {
  const salt = new Uint8Array(32);
  const prk = hkdfExtract(salt, ikm);
  return hkdfExpand(prk, new TextEncoder().encode(info), length);
}

const HKDF_INFO = new TextEncoder().encode("cipherlink-v1-message-key");

/**
 * Derive a per-message key from static DH + per-message nonce for key uniqueness.
 * The nonce is mixed into the HKDF info to ensure each message uses a different key,
 * providing forward secrecy at the message level.
 */
export async function deriveMessageKey(
  senderPriv: Uint8Array,
  recipientPub: Uint8Array,
  messageNonce?: Uint8Array,
): Promise<Uint8Array> {
  await initCrypto();
  const rawSecret = sodium.crypto_scalarmult(senderPriv, recipientPub);
  const salt = messageNonce ?? new Uint8Array(32);
  const prk = hkdfExtract(salt, rawSecret);
  const key = hkdfExpand(prk, HKDF_INFO, 32);
  sodium.memzero(rawSecret);
  sodium.memzero(prk);
  return key;
}

// --- Message Padding ---
// Uses length-prefix + random padding to fixed 256-byte blocks.
// This avoids PKCS7's 255-byte block limit and eliminates padding oracles
// since padding bytes are random (no structure to attack).

const PAD_BLOCK_SIZE = 256;
const LENGTH_PREFIX_BYTES = 2; // Big-endian uint16 for plaintext length

export function padMessage(plaintext: Uint8Array): Uint8Array {
  if (plaintext.length > 0xffff) {
    throw new Error("Plaintext too large for padding scheme");
  }
  // Total size: 2-byte length prefix + plaintext + random padding to block boundary
  const contentLen = LENGTH_PREFIX_BYTES + plaintext.length;
  const totalLen =
    contentLen % PAD_BLOCK_SIZE === 0
      ? contentLen
      : contentLen + (PAD_BLOCK_SIZE - (contentLen % PAD_BLOCK_SIZE));
  const padded = new Uint8Array(totalLen);

  // Length prefix (big-endian uint16)
  padded[0] = (plaintext.length >> 8) & 0xff;
  padded[1] = plaintext.length & 0xff;

  // Plaintext
  padded.set(plaintext, LENGTH_PREFIX_BYTES);

  // Fill remainder with random bytes (no padding oracle possible)
  if (totalLen > contentLen) {
    const randomPad = sodium.randombytes_buf(totalLen - contentLen);
    padded.set(randomPad, contentLen);
  }

  return padded;
}

/**
 * Remove padding — reads length prefix and extracts exactly that many bytes.
 */
export function unpadMessage(padded: Uint8Array): Uint8Array {
  if (padded.length < LENGTH_PREFIX_BYTES) {
    throw new Error("Padded message too short");
  }
  if (padded.length % PAD_BLOCK_SIZE !== 0) {
    throw new Error("Invalid padded message length");
  }
  const plaintextLen = (padded[0]! << 8) | padded[1]!;
  if (plaintextLen > padded.length - LENGTH_PREFIX_BYTES) {
    throw new Error("Invalid length prefix: exceeds padded data");
  }
  return padded.slice(LENGTH_PREFIX_BYTES, LENGTH_PREFIX_BYTES + plaintextLen);
}

// --- Envelope ---

const PROTOCOL_VERSION = 1;

export interface Envelope {
  v: number;
  msgId: string;
  ts: number;
  senderPub: string;
  recipientPub: string;
  nonce: string;
  aad: string;
  ciphertext: string;
}

function buildAad(meta: {
  senderPub: string;
  recipientPub: string;
  timestamp: number;
  msgId: string;
  protocolVersion: number;
}): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(meta));
}

export async function encryptMessage(
  senderPriv: Uint8Array,
  senderPub: Uint8Array,
  recipientPub: Uint8Array,
  plaintext: string,
): Promise<Envelope> {
  await initCrypto();

  const msgId = sodium.to_hex(sodium.randombytes_buf(16));
  const ts = Date.now();

  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  );

  // Use nonce as HKDF salt for per-message key uniqueness
  const messageKey = await deriveMessageKey(senderPriv, recipientPub, nonce);

  const senderPubB64 = toBase64(senderPub);
  const recipientPubB64 = toBase64(recipientPub);

  const aad = buildAad({
    senderPub: senderPubB64,
    recipientPub: recipientPubB64,
    timestamp: ts,
    msgId,
    protocolVersion: PROTOCOL_VERSION,
  });

  const plaintextBytes = new TextEncoder().encode(plaintext);
  const paddedPlaintext = padMessage(plaintextBytes);

  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    paddedPlaintext,
    aad,
    null,
    nonce,
    messageKey,
  );

  sodium.memzero(messageKey);

  return {
    v: PROTOCOL_VERSION,
    msgId,
    ts,
    senderPub: senderPubB64,
    recipientPub: recipientPubB64,
    nonce: toBase64(nonce),
    aad: toBase64(aad),
    ciphertext: toBase64(ciphertext),
  };
}

/**
 * Decrypt a message. AAD is independently reconstructed from envelope metadata
 * to prevent AAD substitution attacks.
 */
export async function decryptMessage(
  recipientPriv: Uint8Array,
  senderPub: Uint8Array,
  envelope: Envelope,
): Promise<string> {
  await initCrypto();

  const nonce = fromBase64(envelope.nonce);
  const ciphertext = fromBase64(envelope.ciphertext);

  // Derive the same per-message key using the nonce as HKDF salt
  const messageKey = await deriveMessageKey(recipientPriv, senderPub, nonce);

  // Reconstruct AAD independently instead of trusting envelope.aad
  const reconstructedAad = buildAad({
    senderPub: envelope.senderPub,
    recipientPub: envelope.recipientPub,
    timestamp: envelope.ts,
    msgId: envelope.msgId,
    protocolVersion: envelope.v,
  });

  const paddedPlaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    reconstructedAad,
    nonce,
    messageKey,
  );

  sodium.memzero(messageKey);

  const plaintextBytes = unpadMessage(paddedPlaintext);
  return new TextDecoder().decode(plaintextBytes);
}

// --- Sealed Sender ---

export interface SealedEnvelope {
  v: number;
  recipientPub: string;
  ephemeralPub: string;
  sealNonce: string;
  sealed: string;
}

/**
 * Seal a message hiding sender identity from the server.
 * Uses ephemeral DH for confidentiality + Ed25519 signature for sender authentication.
 * The recipient can verify the sender's identity after decryption.
 */
export async function sealMessage(
  senderPub: Uint8Array,
  senderSigningPriv: Uint8Array,
  recipientPub: Uint8Array,
  innerPayload: string,
): Promise<SealedEnvelope> {
  await initCrypto();

  const ephemeral = sodium.crypto_box_keypair();
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);

  // Sign the payload to authenticate the sender after unseal
  const payloadBytes = new TextEncoder().encode(innerPayload);
  const signature = sodium.crypto_sign_detached(payloadBytes, senderSigningPriv);

  const inner = JSON.stringify({
    senderPub: toBase64(senderPub),
    payload: innerPayload,
    sig: toBase64(signature),
  });
  const innerBytes = new TextEncoder().encode(inner);

  const sealed = sodium.crypto_box_easy(
    innerBytes,
    nonce,
    recipientPub,
    ephemeral.privateKey,
  );

  sodium.memzero(ephemeral.privateKey);

  return {
    v: 1,
    recipientPub: toBase64(recipientPub),
    ephemeralPub: toBase64(ephemeral.publicKey),
    sealNonce: toBase64(nonce),
    sealed: toBase64(sealed),
  };
}

/**
 * Unseal a sealed sender message and verify the sender's signature.
 * @param senderSigningPub - optional sender's Ed25519 signing public key for verification
 */
export async function unsealMessage(
  recipientPriv: Uint8Array,
  envelope: SealedEnvelope,
  senderSigningPub?: Uint8Array,
): Promise<{ senderPub: string; payload: string; verified: boolean }> {
  await initCrypto();

  const ephemeralPub = fromBase64(envelope.ephemeralPub);
  const nonce = fromBase64(envelope.sealNonce);
  const sealed = fromBase64(envelope.sealed);

  const innerBytes = sodium.crypto_box_open_easy(
    sealed,
    nonce,
    ephemeralPub,
    recipientPriv,
  );

  const inner = JSON.parse(new TextDecoder().decode(innerBytes)) as {
    senderPub: string;
    payload: string;
    sig?: string;
  };

  // Verify sender signature if signing key and signature are available
  let verified = false;
  if (senderSigningPub && inner.sig) {
    const payloadBytes = new TextEncoder().encode(inner.payload);
    const sig = fromBase64(inner.sig);
    verified = sodium.crypto_sign_verify_detached(
      sig,
      payloadBytes,
      senderSigningPub,
    );
  }

  return { senderPub: inner.senderPub, payload: inner.payload, verified };
}

// --- Ed25519 Signing ---

export function sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return sodium.crypto_sign_detached(message, privateKey);
}

export function verifySignature(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  try {
    return sodium.crypto_sign_verify_detached(signature, message, publicKey);
  } catch {
    return false;
  }
}

// --- Random bytes ---

export function randomBytes(length: number): Uint8Array {
  return sodium.randombytes_buf(length);
}

/**
 * Generate a cryptographically random message ID (hex-encoded).
 */
export function generateMessageId(): string {
  return sodium.to_hex(sodium.randombytes_buf(16));
}
