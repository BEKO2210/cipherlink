/**
 * Secure key storage using expo-secure-store.
 * Private keys are stored encrypted in the device keychain/keystore.
 * Extended with contacts, groups, and settings storage.
 * @author Belkis Aslani
 */
import * as SecureStore from "expo-secure-store";
import { toBase64, fromBase64 } from "./crypto";

const PRIVATE_KEY_SLOT = "cipherlink_identity_private_key";
const PUBLIC_KEY_SLOT = "cipherlink_identity_public_key";
const SIGNING_PRIVATE_KEY_SLOT = "cipherlink_signing_private_key";
const SIGNING_PUBLIC_KEY_SLOT = "cipherlink_signing_public_key";
const RECIPIENT_KEY_PREFIX = "cipherlink_recipient_";
const CONTACTS_SLOT = "cipherlink_contacts";
const GROUPS_SLOT = "cipherlink_groups";
const SETTINGS_SLOT = "cipherlink_settings";
const DISPLAY_NAME_SLOT = "cipherlink_display_name";

// --- Identity ---

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

export async function saveSigningKeypair(
  publicKey: Uint8Array,
  privateKey: Uint8Array,
): Promise<void> {
  await SecureStore.setItemAsync(
    SIGNING_PRIVATE_KEY_SLOT,
    toBase64(privateKey),
  );
  await SecureStore.setItemAsync(SIGNING_PUBLIC_KEY_SLOT, toBase64(publicKey));
}

export async function loadSigningKeypair(): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} | null> {
  const privB64 = await SecureStore.getItemAsync(SIGNING_PRIVATE_KEY_SLOT);
  const pubB64 = await SecureStore.getItemAsync(SIGNING_PUBLIC_KEY_SLOT);
  if (!privB64 || !pubB64) return null;
  return {
    publicKey: fromBase64(pubB64),
    privateKey: fromBase64(privB64),
  };
}

export async function deleteIdentity(): Promise<void> {
  await SecureStore.deleteItemAsync(PRIVATE_KEY_SLOT);
  await SecureStore.deleteItemAsync(PUBLIC_KEY_SLOT);
  await SecureStore.deleteItemAsync(SIGNING_PRIVATE_KEY_SLOT);
  await SecureStore.deleteItemAsync(SIGNING_PUBLIC_KEY_SLOT);
}

// --- Display Name ---

export async function saveDisplayName(name: string): Promise<void> {
  await SecureStore.setItemAsync(DISPLAY_NAME_SLOT, name);
}

export async function loadDisplayName(): Promise<string | null> {
  return SecureStore.getItemAsync(DISPLAY_NAME_SLOT);
}

// --- Recipient Keys ---

export async function saveRecipientKey(
  recipientId: string,
  publicKey: string,
): Promise<void> {
  await SecureStore.setItemAsync(
    `${RECIPIENT_KEY_PREFIX}${recipientId}`,
    publicKey,
  );
}

export async function loadRecipientKey(
  recipientId: string,
): Promise<string | null> {
  return SecureStore.getItemAsync(`${RECIPIENT_KEY_PREFIX}${recipientId}`);
}

// --- Contacts ---

export interface StoredContact {
  publicKey: string;
  name: string;
  addedAt: number;
  verified: boolean;
}

export async function saveContacts(
  contacts: StoredContact[],
): Promise<void> {
  await SecureStore.setItemAsync(CONTACTS_SLOT, JSON.stringify(contacts));
}

export async function loadContacts(): Promise<StoredContact[]> {
  const raw = await SecureStore.getItemAsync(CONTACTS_SLOT);
  if (!raw) return [];
  try {
    return JSON.parse(raw) as StoredContact[];
  } catch {
    return [];
  }
}

// --- Groups ---

export interface StoredGroup {
  id: string;
  name: string;
  members: string[];
  createdAt: number;
  myKeyId: string;
}

export async function saveGroups(groups: StoredGroup[]): Promise<void> {
  await SecureStore.setItemAsync(GROUPS_SLOT, JSON.stringify(groups));
}

export async function loadGroups(): Promise<StoredGroup[]> {
  const raw = await SecureStore.getItemAsync(GROUPS_SLOT);
  if (!raw) return [];
  try {
    return JSON.parse(raw) as StoredGroup[];
  } catch {
    return [];
  }
}

// --- Settings ---

export interface AppSettings {
  serverUrl: string;
  sealedSender: boolean;
  quantumResistant: boolean;
  messagePadding: boolean;
}

const DEFAULT_SETTINGS: AppSettings = {
  serverUrl: "ws://localhost:4200",
  sealedSender: true,
  quantumResistant: true,
  messagePadding: true,
};

export async function saveSettings(settings: AppSettings): Promise<void> {
  await SecureStore.setItemAsync(SETTINGS_SLOT, JSON.stringify(settings));
}

export async function loadSettings(): Promise<AppSettings> {
  const raw = await SecureStore.getItemAsync(SETTINGS_SLOT);
  if (!raw) return DEFAULT_SETTINGS;
  try {
    return { ...DEFAULT_SETTINGS, ...(JSON.parse(raw) as Partial<AppSettings>) };
  } catch {
    return DEFAULT_SETTINGS;
  }
}
