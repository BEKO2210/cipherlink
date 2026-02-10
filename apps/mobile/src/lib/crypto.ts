/**
 * Crypto wrapper for mobile — initializes libsodium with RN polyfills.
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

// Re-export base64 utilities
export function toBase64(data: Uint8Array): string {
  return sodium.to_base64(data, sodium.base64_variants.ORIGINAL);
}

export function fromBase64(encoded: string): Uint8Array {
  return sodium.from_base64(encoded, sodium.base64_variants.ORIGINAL);
}

// --- Key generation ---

export interface IdentityKeypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export async function generateIdentityKeypair(): Promise<IdentityKeypair> {
  await initCrypto();
  const kp = sodium.crypto_box_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
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

async function deriveMessageKey(
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

  const plaintextBytes = new TextEncoder().encode(plaintext);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintextBytes,
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

  const plaintextBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    aad,
    nonce,
    messageKey,
  );

  sodium.memzero(messageKey);
  return new TextDecoder().decode(plaintextBytes);
}
