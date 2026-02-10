/**
 * Zod schemas for WebSocket message validation.
 * Supports: v1 envelopes, sealed sender, prekey bundles, group messages.
 * @author Belkis Aslani
 */
import { z } from "zod";

const base64Pattern = /^[A-Za-z0-9+/]*={0,2}$/;
const base64String = z.string().regex(base64Pattern, "Invalid base64 string");

// --- Hello (authentication) ---
export const helloSchema = z.object({
  type: z.literal("hello"),
  publicKey: base64String.min(1),
});

// --- V1 Envelope (original pairwise) ---
export const envelopeSchema = z.object({
  v: z.number().int().positive(),
  msgId: z.string().min(1).max(128),
  ts: z.number().int().positive(),
  senderPub: base64String.min(1),
  recipientPub: base64String.min(1),
  nonce: base64String.min(1),
  aad: base64String.min(1),
  ciphertext: base64String.min(1),
});

export const sendSchema = z.object({
  type: z.literal("send"),
  envelope: envelopeSchema,
});

// --- Sealed Sender Envelope ---
export const sealedEnvelopeSchema = z.object({
  v: z.number().int().positive(),
  recipientPub: base64String.min(1),
  ephemeralPub: base64String.min(1),
  sealNonce: base64String.min(1),
  sealed: base64String.min(1),
});

export const sendSealedSchema = z.object({
  type: z.literal("send_sealed"),
  envelope: sealedEnvelopeSchema,
});

// --- Prekey Bundle (publish / fetch) ---
export const prekeyBundleSchema = z.object({
  identityKey: base64String.min(1),
  signingKey: base64String.min(1),
  signedPreKey: base64String.min(1),
  signedPreKeyId: z.number().int(),
  signedPreKeySignature: base64String.min(1),
  oneTimePreKey: base64String.optional(),
  oneTimePreKeyId: z.number().int().optional(),
});

export const publishPrekeysSchema = z.object({
  type: z.literal("publish_prekeys"),
  bundle: prekeyBundleSchema,
});

export const fetchPrekeysSchema = z.object({
  type: z.literal("fetch_prekeys"),
  publicKey: base64String.min(1),
});

// --- Group Messages ---
export const groupMessageSchema = z.object({
  groupId: z.string().min(1).max(128),
  keyId: z.string().min(1).max(256),
  chainIndex: z.number().int().nonnegative(),
  nonce: base64String.min(1),
  ciphertext: base64String.min(1),
  signature: base64String.min(1),
});

export const sendGroupSchema = z.object({
  type: z.literal("send_group"),
  groupId: z.string().min(1).max(128),
  message: groupMessageSchema,
  recipients: z.array(base64String.min(1)),
});

// --- Discriminated union of all message types ---
export const clientMessageSchema = z.discriminatedUnion("type", [
  helloSchema,
  sendSchema,
  sendSealedSchema,
  publishPrekeysSchema,
  fetchPrekeysSchema,
  sendGroupSchema,
]);

export type HelloMessage = z.infer<typeof helloSchema>;
export type SendMessage = z.infer<typeof sendSchema>;
export type SendSealedMessage = z.infer<typeof sendSealedSchema>;
export type PublishPrekeysMessage = z.infer<typeof publishPrekeysSchema>;
export type FetchPrekeysMessage = z.infer<typeof fetchPrekeysSchema>;
export type SendGroupMessage = z.infer<typeof sendGroupSchema>;
export type ClientMessage = z.infer<typeof clientMessageSchema>;
export type Envelope = z.infer<typeof envelopeSchema>;
export type SealedEnvelope = z.infer<typeof sealedEnvelopeSchema>;
export type PrekeyBundle = z.infer<typeof prekeyBundleSchema>;
export type GroupMessage = z.infer<typeof groupMessageSchema>;
