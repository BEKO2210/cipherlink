/**
 * X3DH (Extended Triple Diffie-Hellman) — initial key agreement protocol.
 *
 * Establishes a shared secret between two parties who may not be online
 * simultaneously. Uses prekeys stored on the server so Alice can initiate
 * a session with Bob even if Bob is offline.
 *
 * Protocol flow:
 * 1. Bob publishes: IdentityKey (IK_B), SignedPreKey (SPK_B), OneTimePreKeys (OPK_B)
 * 2. Alice fetches Bob's prekey bundle
 * 3. Alice generates ephemeral keypair (EK_A)
 * 4. Alice computes:
 *    DH1 = DH(IK_A, SPK_B)       — identity ↔ signed prekey
 *    DH2 = DH(EK_A, IK_B)        — ephemeral ↔ identity
 *    DH3 = DH(EK_A, SPK_B)       — ephemeral ↔ signed prekey
 *    DH4 = DH(EK_A, OPK_B)       — ephemeral ↔ one-time prekey (optional)
 *    SK = KDF(DH1 || DH2 || DH3 || DH4)
 * 5. Alice sends initial message with EK_A and used OPK_B id
 * 6. Bob computes the same SK using his private keys
 *
 * Reference: https://signal.org/docs/specifications/x3dh/
 *
 * @module x3dh
 * @author Belkis Aslani
 */
import sodium from "libsodium-wrappers-sumo";
import { initSodium } from "./sodium.js";
import { toBase64 } from "./base64.js";

const X3DH_INFO = new TextEncoder().encode("CipherLink_X3DH_v1");

/** A signed prekey: X25519 keypair + Ed25519 signature over the public key. */
export interface SignedPreKey {
  keyId: number;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  signature: Uint8Array; // Ed25519 signature of publicKey
}

/** A one-time prekey. */
export interface OneTimePreKey {
  keyId: number;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** Full identity with both signing (Ed25519) and DH (X25519) capabilities. */
export interface FullIdentity {
  /** Ed25519 signing public key. */
  signingPublicKey: Uint8Array;
  /** Ed25519 signing private key. */
  signingPrivateKey: Uint8Array;
  /** X25519 DH public key (derived from Ed25519). */
  dhPublicKey: Uint8Array;
  /** X25519 DH private key (derived from Ed25519). */
  dhPrivateKey: Uint8Array;
}

/** Prekey bundle published by a user (public parts only). */
export interface PrekeyBundle {
  identityKey: Uint8Array; // X25519 DH public key
  signingKey: Uint8Array; // Ed25519 signing public key
  signedPreKey: Uint8Array; // X25519 public key
  signedPreKeyId: number;
  signedPreKeySignature: Uint8Array; // Ed25519 signature
  oneTimePreKey?: Uint8Array; // X25519 public key (optional)
  oneTimePreKeyId?: number;
}

/** Result of an X3DH key agreement. */
export interface X3DHResult {
  /** The shared secret (used as initial root key for Double Ratchet). */
  sharedSecret: Uint8Array;
  /** Alice's ephemeral public key (sent to Bob). */
  ephemeralPublicKey: Uint8Array;
  /** Associated data: IK_A || IK_B (bound into the session). */
  associatedData: Uint8Array;
}

/**
 * Generate a full identity with Ed25519 signing + X25519 DH keys.
 * The X25519 keys are derived from the Ed25519 keys using libsodium conversion.
 */
export async function generateFullIdentity(): Promise<FullIdentity> {
  await initSodium();

  // Generate Ed25519 signing keypair
  const signingKP = sodium.crypto_sign_keypair();

  // Derive X25519 keys from Ed25519
  const dhPrivateKey = sodium.crypto_sign_ed25519_sk_to_curve25519(
    signingKP.privateKey,
  );
  const dhPublicKey = sodium.crypto_sign_ed25519_pk_to_curve25519(
    signingKP.publicKey,
  );

  return {
    signingPublicKey: signingKP.publicKey,
    signingPrivateKey: signingKP.privateKey,
    dhPublicKey,
    dhPrivateKey,
  };
}

/**
 * Generate a signed prekey (sign the X25519 public key with Ed25519 identity).
 */
export async function generateSignedPreKey(
  identity: FullIdentity,
  keyId: number,
): Promise<SignedPreKey> {
  await initSodium();

  const kp = sodium.crypto_box_keypair();
  const signature = sodium.crypto_sign_detached(
    kp.publicKey,
    identity.signingPrivateKey,
  );

  return {
    keyId,
    publicKey: kp.publicKey,
    privateKey: kp.privateKey,
    signature,
  };
}

/**
 * Generate a batch of one-time prekeys.
 */
export async function generateOneTimePreKeys(
  startId: number,
  count: number,
): Promise<OneTimePreKey[]> {
  await initSodium();

  const keys: OneTimePreKey[] = [];
  for (let i = 0; i < count; i++) {
    const kp = sodium.crypto_box_keypair();
    keys.push({
      keyId: startId + i,
      publicKey: kp.publicKey,
      privateKey: kp.privateKey,
    });
  }
  return keys;
}

/**
 * Verify a signed prekey signature.
 */
export async function verifySignedPreKey(
  signingPublicKey: Uint8Array,
  preKeyPublicKey: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  await initSodium();
  try {
    return sodium.crypto_sign_verify_detached(
      signature,
      preKeyPublicKey,
      signingPublicKey,
    );
  } catch {
    return false;
  }
}

/**
 * Build the X3DH associated data: AD = IK_A || IK_B
 */
function buildX3DHAD(
  initiatorIdentity: Uint8Array,
  responderIdentity: Uint8Array,
): Uint8Array {
  const ad = new Uint8Array(
    initiatorIdentity.length + responderIdentity.length,
  );
  ad.set(initiatorIdentity, 0);
  ad.set(responderIdentity, initiatorIdentity.length);
  return ad;
}

/**
 * HKDF for X3DH: derive shared secret from DH outputs.
 * Uses HMAC-SHA256 as the underlying PRF.
 */
function x3dhKDF(dhOutputs: Uint8Array[]): Uint8Array {
  // Prepend 32 bytes of 0xFF (as per X3DH spec to prevent cross-protocol attacks)
  const prefix = new Uint8Array(32).fill(0xff);

  // Concatenate all DH outputs
  let totalLen = prefix.length;
  for (const dh of dhOutputs) totalLen += dh.length;
  const ikm = new Uint8Array(totalLen);
  let offset = 0;
  ikm.set(prefix, offset);
  offset += prefix.length;
  for (const dh of dhOutputs) {
    ikm.set(dh, offset);
    offset += dh.length;
  }

  // HKDF-Extract with zero salt
  const salt = new Uint8Array(32);
  const prk = sodium.crypto_auth_hmacsha256(ikm, salt);

  // HKDF-Expand with info string, output 32 bytes
  const input = new Uint8Array(X3DH_INFO.length + 1);
  input.set(X3DH_INFO, 0);
  input[input.length - 1] = 1;
  return new Uint8Array(sodium.crypto_auth_hmacsha256(input, prk));
}

/**
 * Alice (initiator) performs X3DH key agreement with Bob's prekey bundle.
 *
 * @param aliceIdentity - Alice's full identity
 * @param bobBundle - Bob's published prekey bundle
 * @returns X3DH result with shared secret, ephemeral key, and associated data
 * @throws If Bob's signed prekey signature is invalid
 */
export async function x3dhInitiate(
  aliceIdentity: FullIdentity,
  bobBundle: PrekeyBundle,
): Promise<X3DHResult> {
  await initSodium();

  // Verify Bob's signed prekey signature
  const sigValid = await verifySignedPreKey(
    bobBundle.signingKey,
    bobBundle.signedPreKey,
    bobBundle.signedPreKeySignature,
  );
  if (!sigValid) {
    throw new Error("Invalid signed prekey signature — possible MITM attack");
  }

  // Generate ephemeral keypair
  const ephemeral = sodium.crypto_box_keypair();

  // Compute DH values
  const dh1 = sodium.crypto_scalarmult(
    aliceIdentity.dhPrivateKey,
    bobBundle.signedPreKey,
  );
  const dh2 = sodium.crypto_scalarmult(
    ephemeral.privateKey,
    bobBundle.identityKey,
  );
  const dh3 = sodium.crypto_scalarmult(
    ephemeral.privateKey,
    bobBundle.signedPreKey,
  );

  const dhOutputs = [dh1, dh2, dh3];

  // DH4 with one-time prekey (if available)
  if (bobBundle.oneTimePreKey) {
    const dh4 = sodium.crypto_scalarmult(
      ephemeral.privateKey,
      bobBundle.oneTimePreKey,
    );
    dhOutputs.push(dh4);
  }

  const sharedSecret = x3dhKDF(dhOutputs);
  const associatedData = buildX3DHAD(
    aliceIdentity.dhPublicKey,
    bobBundle.identityKey,
  );

  // Wipe DH intermediaries
  for (const dh of dhOutputs) sodium.memzero(dh);
  sodium.memzero(ephemeral.privateKey);

  return {
    sharedSecret,
    ephemeralPublicKey: ephemeral.publicKey,
    associatedData,
  };
}

/**
 * Bob (responder) computes the X3DH shared secret from Alice's initial message.
 *
 * @param bobIdentity - Bob's full identity
 * @param bobSignedPreKey - The signed prekey Alice used
 * @param bobOneTimePreKey - The one-time prekey Alice used (if any)
 * @param aliceIdentityKey - Alice's X25519 DH public key
 * @param aliceEphemeralKey - Alice's ephemeral public key (from initial message)
 * @returns X3DH result with shared secret and associated data
 */
export async function x3dhRespond(
  bobIdentity: FullIdentity,
  bobSignedPreKey: SignedPreKey,
  bobOneTimePreKey: OneTimePreKey | null,
  aliceIdentityKey: Uint8Array,
  aliceEphemeralKey: Uint8Array,
): Promise<X3DHResult> {
  await initSodium();

  // Compute DH values (mirror of Alice's computation)
  const dh1 = sodium.crypto_scalarmult(
    bobSignedPreKey.privateKey,
    aliceIdentityKey,
  );
  const dh2 = sodium.crypto_scalarmult(
    bobIdentity.dhPrivateKey,
    aliceEphemeralKey,
  );
  const dh3 = sodium.crypto_scalarmult(
    bobSignedPreKey.privateKey,
    aliceEphemeralKey,
  );

  const dhOutputs = [dh1, dh2, dh3];

  if (bobOneTimePreKey) {
    const dh4 = sodium.crypto_scalarmult(
      bobOneTimePreKey.privateKey,
      aliceEphemeralKey,
    );
    dhOutputs.push(dh4);
  }

  const sharedSecret = x3dhKDF(dhOutputs);
  const associatedData = buildX3DHAD(
    aliceIdentityKey,
    bobIdentity.dhPublicKey,
  );

  // Wipe DH intermediaries
  for (const dh of dhOutputs) sodium.memzero(dh);

  return {
    sharedSecret,
    ephemeralPublicKey: aliceEphemeralKey, // Not used by Bob, but included for symmetry
    associatedData,
  };
}

/**
 * Create a prekey bundle from identity + generated prekeys.
 * This is what gets published to the server.
 */
export function createPrekeyBundle(
  identity: FullIdentity,
  signedPreKey: SignedPreKey,
  oneTimePreKey?: OneTimePreKey,
): PrekeyBundle {
  return {
    identityKey: identity.dhPublicKey,
    signingKey: identity.signingPublicKey,
    signedPreKey: signedPreKey.publicKey,
    signedPreKeyId: signedPreKey.keyId,
    signedPreKeySignature: signedPreKey.signature,
    oneTimePreKey: oneTimePreKey?.publicKey,
    oneTimePreKeyId: oneTimePreKey?.keyId,
  };
}

/**
 * Serialize a prekey bundle for transport (all fields base64-encoded).
 */
export function serializePrekeyBundle(
  bundle: PrekeyBundle,
): Record<string, string | number | undefined> {
  return {
    identityKey: toBase64(bundle.identityKey),
    signingKey: toBase64(bundle.signingKey),
    signedPreKey: toBase64(bundle.signedPreKey),
    signedPreKeyId: bundle.signedPreKeyId,
    signedPreKeySignature: toBase64(bundle.signedPreKeySignature),
    oneTimePreKey: bundle.oneTimePreKey
      ? toBase64(bundle.oneTimePreKey)
      : undefined,
    oneTimePreKeyId: bundle.oneTimePreKeyId,
  };
}
