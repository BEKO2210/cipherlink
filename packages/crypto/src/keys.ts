/**
 * Identity keypair generation using X25519 (Curve25519).
 * @module keys
 * @author Belkis Aslani
 */
import sodium from "libsodium-wrappers-sumo";
import { initSodium } from "./sodium.js";

export interface IdentityKeypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/**
 * Generate a new X25519 identity keypair.
 * The private key MUST be stored in a secure enclave (e.g., expo-secure-store).
 */
export async function generateIdentityKeypair(): Promise<IdentityKeypair> {
  await initSodium();
  const kp = sodium.crypto_box_keypair();
  return {
    publicKey: kp.publicKey,
    privateKey: kp.privateKey,
  };
}
