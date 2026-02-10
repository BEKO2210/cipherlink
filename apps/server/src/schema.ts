/**
 * Zod schemas for WebSocket message validation.
 * @author Belkis Aslani
 */
import { z } from "zod";

const base64Pattern = /^[A-Za-z0-9+/]*={0,2}$/;

const base64String = z.string().regex(base64Pattern, "Invalid base64 string");

export const helloSchema = z.object({
  type: z.literal("hello"),
  publicKey: base64String.min(1),
});

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

export const clientMessageSchema = z.discriminatedUnion("type", [
  helloSchema,
  sendSchema,
]);

export type HelloMessage = z.infer<typeof helloSchema>;
export type SendMessage = z.infer<typeof sendSchema>;
export type ClientMessage = z.infer<typeof clientMessageSchema>;
export type Envelope = z.infer<typeof envelopeSchema>;
