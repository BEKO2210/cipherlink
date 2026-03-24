/**
 * CipherLink crypto module — full E2EE implementation with libsodium.
 * Supports: X25519, Ed25519, HKDF, XChaCha20-Poly1305, sealed sender, padding.
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

/**
 * Generate a full identity with Ed25519 signing + X25519 DH keypair.
 */
export async function generateFullIdentity(): Promise<FullIdentity> {
  await initCrypto();
  const sigKp = sodium.crypto_sign_keypair();
  // Derive X25519 key from Ed25519 key
  const dhPriv = sodium.crypto_sign_ed25519_sk_to_curve25519(sigKp.privateKey);
  const dhPub = sodium.crypto_sign_ed25519_pk_to_curve25519(sigKp.publicKey);
  return {
    signing: { publicKey: sigKp.publicKey, privateKey: sigKp.privateKey },
    dh: { publicKey: dhPub, privateKey: dhPriv },
  };
}

// --- KDF ---

const HKDF_INFO = new TextEncoder().encode("cipherlink-v1-message-key");

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

export async function deriveMessageKey(
  senderPriv: Uint8Array,
  recipientPub: Uint8Array,
): Promise<Uint8Array> {
  await initCrypto();
  const rawSecret = sodium.crypto_scalarmult(senderPriv, recipientPub);
  const salt = new Uint8Array(32);
  const prk = hkdfExtract(salt, rawSecret);
  const key = hkdfExpand(prk, HKDF_INFO, 32);
  sodium.memzero(rawSecret);
  return key;
}

// --- Message Padding ---

const PAD_BLOCK_SIZE = 256;

export function padMessage(plaintext: Uint8Array): Uint8Array {
  const padLen = PAD_BLOCK_SIZE - (plaintext.length % PAD_BLOCK_SIZE);
  const padded = new Uint8Array(plaintext.length + padLen);
  padded.set(plaintext, 0);
  // PKCS7: fill with pad length byte
  for (let i = plaintext.length; i < padded.length; i++) {
    padded[i] = padLen;
  }
  return padded;
}

export function unpadMessage(padded: Uint8Array): Uint8Array {
  if (padded.length === 0) return padded;
  const padLen = padded[padded.length - 1]!;
  if (padLen === 0 || padLen > PAD_BLOCK_SIZE) {
    throw new Error("Invalid padding");
  }
  return padded.slice(0, padded.length - padLen);
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

  const messageKey = await deriveMessageKey(senderPriv, recipientPub);
  const msgId = sodium.to_hex(sodium.randombytes_buf(16));
  const ts = Date.now();

  const senderPubB64 = toBase64(senderPub);
  const recipientPubB64 = toBase64(recipientPub);

  const aad = buildAad({
    senderPub: senderPubB64,
    recipientPub: recipientPubB64,
    timestamp: ts,
    msgId,
    protocolVersion: PROTOCOL_VERSION,
  });

  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  );

  // Pad the plaintext before encryption
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

export async function decryptMessage(
  recipientPriv: Uint8Array,
  senderPub: Uint8Array,
  envelope: Envelope,
): Promise<string> {
  await initCrypto();

  const messageKey = await deriveMessageKey(recipientPriv, senderPub);
  const nonce = fromBase64(envelope.nonce);
  const ciphertext = fromBase64(envelope.ciphertext);
  const aad = fromBase64(envelope.aad);

  const paddedPlaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    aad,
    nonce,
    messageKey,
  );

  sodium.memzero(messageKey);

  // Unpad
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
 * Seal a message so the server cannot learn the sender identity.
 * Uses ephemeral DH to encrypt {senderPub, payload} for the recipient.
 */
export async function sealMessage(
  senderPub: Uint8Array,
  recipientPub: Uint8Array,
  innerPayload: string,
): Promise<SealedEnvelope> {
  await initCrypto();

  const ephemeral = sodium.crypto_box_keypair();
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);

  // Inner content: sender identity + payload
  const inner = JSON.stringify({
    senderPub: toBase64(senderPub),
    payload: innerPayload,
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
 * Unseal a sealed sender message.
 */
export async function unsealMessage(
  recipientPriv: Uint8Array,
  envelope: SealedEnvelope,
): Promise<{ senderPub: string; payload: string }> {
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

  const inner = JSON.parse(new TextDecoder().decode(innerBytes));
  return { senderPub: inner.senderPub, payload: inner.payload };
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
  return sodium.crypto_sign_verify_detached(signature, message, publicKey);
}

// --- Random bytes ---

export function randomBytes(length: number): Uint8Array {
  return sodium.randombytes_buf(length);
}
