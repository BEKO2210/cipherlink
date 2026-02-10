/**
 * Base64 encoding/decoding utilities using libsodium.
 * @module base64
 * @author Belkis Aslani
 */
import sodium from "libsodium-wrappers-sumo";

export function toBase64(data: Uint8Array): string {
  return sodium.to_base64(data, sodium.base64_variants.ORIGINAL);
}

export function fromBase64(encoded: string): Uint8Array {
  return sodium.from_base64(encoded, sodium.base64_variants.ORIGINAL);
}

export function toBase64Url(data: Uint8Array): string {
  return sodium.to_base64(data, sodium.base64_variants.URLSAFE_NO_PADDING);
}

export function fromBase64Url(encoded: string): Uint8Array {
  return sodium.from_base64(encoded, sodium.base64_variants.URLSAFE_NO_PADDING);
}
