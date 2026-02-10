/**
 * Secure key storage using expo-secure-store.
 * Private keys are stored encrypted in the device keychain/keystore.
 *
 * @author Belkis Aslani
 */
import * as SecureStore from "expo-secure-store";
import { toBase64, fromBase64 } from "./crypto";

const PRIVATE_KEY_SLOT = "cipherlink_identity_private_key";
const PUBLIC_KEY_SLOT = "cipherlink_identity_public_key";
const RECIPIENT_KEY_PREFIX = "cipherlink_recipient_";

export async function saveKeypair(
  publicKey: Uint8Array,
  privateKey: Uint8Array,
): Promise<void> {
  await SecureStore.setItemAsync(PRIVATE_KEY_SLOT, toBase64(privateKey));
  await SecureStore.setItemAsync(PUBLIC_KEY_SLOT, toBase64(publicKey));
}

export async function loadKeypair(): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} | null> {
  const privB64 = await SecureStore.getItemAsync(PRIVATE_KEY_SLOT);
  const pubB64 = await SecureStore.getItemAsync(PUBLIC_KEY_SLOT);

  if (!privB64 || !pubB64) return null;

  return {
    publicKey: fromBase64(pubB64),
    privateKey: fromBase64(privB64),
  };
}

/**
 * Store last-known recipient public key for key-change detection.
 */
export async function saveRecipientKey(
  recipientId: string,
  publicKey: string,
): Promise<void> {
  await SecureStore.setItemAsync(
    `${RECIPIENT_KEY_PREFIX}${recipientId}`,
    publicKey,
  );
}

/**
 * Load last-known recipient public key.
 */
export async function loadRecipientKey(
  recipientId: string,
): Promise<string | null> {
  return SecureStore.getItemAsync(`${RECIPIENT_KEY_PREFIX}${recipientId}`);
}
