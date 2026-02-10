/**
 * SecureBuffer — Misuse-resistant wrapper for sensitive cryptographic material.
 *
 * Prevents accidental exposure of key material by:
 * - Tracking whether the buffer has been wiped
 * - Providing explicit .expose() to access raw bytes
 * - Auto-wiping on dispose
 * - Preventing double-free / use-after-free
 * - Constant-time comparison
 *
 * Design principle: Make the secure path the EASIEST path.
 * Developers must explicitly opt-in to unsafe operations.
 *
 * @module secure-buffer
 * @author Belkis Aslani
 */
import sodium from "libsodium-wrappers-sumo";
import { initSodium } from "./sodium.js";

/** Error thrown when attempting to use a wiped buffer. */
export class UseAfterWipeError extends Error {
  constructor() {
    super("Attempted to access wiped SecureBuffer — use-after-free");
    this.name = "UseAfterWipeError";
  }
}

/**
 * A wrapper for sensitive byte arrays (keys, secrets, nonces).
 *
 * Usage:
 *   const key = SecureBuffer.from(rawKeyBytes);
 *   // ... use key.expose() when you need the raw bytes
 *   key.wipe(); // Zeros the memory
 *   // key.expose() will now throw UseAfterWipeError
 *
 * Use SecureBuffer.scope() for automatic cleanup:
 *   const result = SecureBuffer.scope(key, (bytes) => {
 *     return encrypt(bytes, plaintext);
 *   });
 */
export class SecureBuffer {
  private _data: Uint8Array;
  private _wiped: boolean = false;
  private readonly _length: number;

  private constructor(data: Uint8Array) {
    // Copy input so we own the memory
    this._data = new Uint8Array(data.length);
    this._data.set(data);
    this._length = data.length;
  }

  /**
   * Create a SecureBuffer from raw bytes.
   * The input is COPIED — the original is NOT wiped automatically.
   * Caller should wipe the source if it's sensitive.
   */
  static from(data: Uint8Array): SecureBuffer {
    return new SecureBuffer(data);
  }

  /**
   * Create a SecureBuffer from raw bytes and wipe the source.
   * This is the preferred way to wrap key material.
   */
  static fromAndWipeSource(data: Uint8Array): SecureBuffer {
    const buf = new SecureBuffer(data);
    sodium.memzero(data);
    return buf;
  }

  /**
   * Generate a random SecureBuffer of the given length.
   */
  static async random(length: number): Promise<SecureBuffer> {
    await initSodium();
    const data = sodium.randombytes_buf(length);
    const buf = new SecureBuffer(data);
    sodium.memzero(data);
    return buf;
  }

  /**
   * Access the raw bytes. Throws if wiped.
   *
   * IMPORTANT: The returned Uint8Array is the INTERNAL buffer.
   * Do not store references to it beyond the immediate use.
   * The buffer WILL be zeroed when wipe() is called.
   */
  expose(): Uint8Array {
    if (this._wiped) {
      throw new UseAfterWipeError();
    }
    return this._data;
  }

  /**
   * Execute a function with access to the raw bytes, then ensure cleanup.
   * This is the safest way to use sensitive key material.
   */
  static scope<T>(buf: SecureBuffer, fn: (data: Uint8Array) => T): T {
    try {
      return fn(buf.expose());
    } finally {
      buf.wipe();
    }
  }

  /**
   * Execute an async function with access to the raw bytes.
   */
  static async scopeAsync<T>(
    buf: SecureBuffer,
    fn: (data: Uint8Array) => Promise<T>,
  ): Promise<T> {
    try {
      return await fn(buf.expose());
    } finally {
      buf.wipe();
    }
  }

  /**
   * Zero the buffer contents and mark as wiped.
   * Idempotent — safe to call multiple times.
   */
  wipe(): void {
    if (!this._wiped) {
      sodium.memzero(this._data);
      this._wiped = true;
    }
  }

  /** Whether this buffer has been wiped. */
  get isWiped(): boolean {
    return this._wiped;
  }

  /** Length of the buffer in bytes. */
  get length(): number {
    return this._length;
  }

  /**
   * Constant-time comparison with another SecureBuffer.
   * Returns false if either buffer is wiped or lengths differ.
   */
  equals(other: SecureBuffer): boolean {
    if (this._wiped || other._wiped) return false;
    if (this._length !== other._length) return false;
    return sodium.memcmp(this._data, other._data);
  }

  /**
   * Clone this buffer into a new SecureBuffer.
   * @throws UseAfterWipeError if already wiped.
   */
  clone(): SecureBuffer {
    return SecureBuffer.from(this.expose());
  }

  /** Prevent JSON serialization of sensitive data. */
  toJSON(): string {
    return "[SecureBuffer: REDACTED]";
  }

  /** Prevent string conversion of sensitive data. */
  toString(): string {
    return `[SecureBuffer(${this._length} bytes, ${this._wiped ? "wiped" : "active"})]`;
  }

  /** Prevent console.log from dumping key material. */
  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }
}
