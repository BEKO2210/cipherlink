/**
 * Message padding — PKCS7-style padding to fixed-size blocks.
 *
 * Prevents ciphertext length from revealing plaintext length.
 * All messages are padded to the next multiple of BLOCK_SIZE before encryption.
 *
 * @module padding
 * @author Belkis Aslani
 */

const DEFAULT_BLOCK_SIZE = 256;

/**
 * Pad a plaintext message to the next multiple of blockSize.
 * Uses PKCS7-style padding: the padding byte value equals the number of padding bytes.
 *
 * Example: blockSize=256, message is 10 bytes → 246 bytes of padding (value 0xF6 each).
 *
 * This ensures ALL ciphertexts are multiples of blockSize, preventing
 * an observer from distinguishing "yes" from a long message.
 */
export function padMessage(
  plaintext: Uint8Array,
  blockSize: number = DEFAULT_BLOCK_SIZE,
): Uint8Array {
  if (blockSize < 1 || blockSize > 65535) {
    throw new Error("Block size must be between 1 and 65535");
  }

  const paddingNeeded = blockSize - (plaintext.length % blockSize);
  // paddingNeeded is always >= 1 and <= blockSize (PKCS7 always adds padding)
  const padded = new Uint8Array(plaintext.length + paddingNeeded);
  padded.set(plaintext, 0);

  // Fill padding bytes with the padding length value (PKCS7)
  // For lengths > 255, we use the low byte and store the full length in the last 2 bytes
  if (blockSize <= 255) {
    padded.fill(paddingNeeded, plaintext.length);
  } else {
    // For large block sizes, use a 2-byte length suffix
    padded.fill(0, plaintext.length);
    // Store padding length as little-endian uint16 in last 2 bytes
    padded[padded.length - 2] = paddingNeeded & 0xff;
    padded[padded.length - 1] = (paddingNeeded >> 8) & 0xff;
  }

  return padded;
}

/**
 * Remove PKCS7-style padding from a decrypted message.
 *
 * @throws If padding is invalid (possible tampering).
 */
export function unpadMessage(
  padded: Uint8Array,
  blockSize: number = DEFAULT_BLOCK_SIZE,
): Uint8Array {
  if (padded.length === 0 || padded.length % blockSize !== 0) {
    throw new Error("Invalid padded message length");
  }

  let paddingLength: number;

  if (blockSize <= 255) {
    // PKCS7: last byte indicates padding length
    paddingLength = padded[padded.length - 1]!;
    if (paddingLength === 0 || paddingLength > blockSize) {
      throw new Error("Invalid padding value");
    }
    // Verify all padding bytes are the same value
    for (let i = padded.length - paddingLength; i < padded.length; i++) {
      if (padded[i] !== paddingLength) {
        throw new Error("Invalid padding: inconsistent padding bytes");
      }
    }
  } else {
    // Large block: read 2-byte LE length from last 2 bytes
    paddingLength =
      padded[padded.length - 2]! | (padded[padded.length - 1]! << 8);
    if (paddingLength === 0 || paddingLength > blockSize) {
      throw new Error("Invalid padding value");
    }
  }

  return padded.slice(0, padded.length - paddingLength);
}

/**
 * Pad a string message, returning the padded bytes.
 */
export function padString(
  plaintext: string,
  blockSize: number = DEFAULT_BLOCK_SIZE,
): Uint8Array {
  return padMessage(new TextEncoder().encode(plaintext), blockSize);
}

/**
 * Unpad bytes and decode to string.
 */
export function unpadToString(
  padded: Uint8Array,
  blockSize: number = DEFAULT_BLOCK_SIZE,
): string {
  return new TextDecoder().decode(unpadMessage(padded, blockSize));
}
