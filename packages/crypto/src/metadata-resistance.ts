/**
 * Metadata Resistance — defenses against traffic analysis.
 *
 * Implements:
 * - Uniform message envelopes (fixed 4096-byte size)
 * - Cover traffic scheduling (indistinguishable from real traffic)
 * - Message batching (fixed-size batches at regular intervals)
 * - Traffic timing decorrelation
 *
 * Threat model:
 * A global passive adversary (GPA) can observe all network traffic.
 * Without metadata resistance, they can determine:
 * - Who talks to whom (social graph)
 * - When conversations happen (timing analysis)
 * - How active conversations are (volume analysis)
 * - Message sizes (content type inference)
 *
 * With metadata resistance:
 * - All messages are exactly the same size (4096 bytes)
 * - Cover traffic makes idle periods indistinguishable from active ones
 * - Batching prevents correlation of individual messages
 * - Timing jitter decorrelates send/receive patterns
 *
 * @module metadata-resistance
 * @author Belkis Aslani
 */
import sodium from "libsodium-wrappers-sumo";
import { initSodium } from "./sodium.js";

// --- Constants ---

/**
 * Uniform envelope size in bytes.
 * All messages (real and cover) are exactly this size.
 * Chosen to accommodate most text messages + ratchet headers + padding.
 */
export const UNIFORM_ENVELOPE_SIZE = 4096;

/** Envelope header size (version + type + payload length). */
const ENVELOPE_HEADER_SIZE = 8;

/** Maximum payload size within a uniform envelope. */
export const MAX_PAYLOAD_SIZE = UNIFORM_ENVELOPE_SIZE - ENVELOPE_HEADER_SIZE;

/** Envelope version. */
const ENVELOPE_VERSION = 0x02;

/** Message types within uniform envelopes. */
export enum EnvelopeType {
  /** Real message payload. */
  REAL = 0x01,
  /** Cover traffic (should be silently discarded by recipient). */
  COVER = 0x02,
  /** Acknowledgment. */
  ACK = 0x03,
  /** Heartbeat (keep-alive). */
  HEARTBEAT = 0x04,
}

/** Cover traffic intensity levels. */
export enum CoverTrafficLevel {
  /** No cover traffic. */
  OFF = "OFF",
  /** 1 cover message per 60s when idle. */
  LOW = "LOW",
  /** 1 cover message per 30s, ±10s jitter. */
  MEDIUM = "MEDIUM",
  /** Constant-rate: 1 message per 5s (real or cover). */
  HIGH = "HIGH",
}

// --- Uniform Envelope ---

/**
 * Create a uniform-size envelope.
 *
 * Structure (4096 bytes total):
 *   [1 byte]  version (0x02)
 *   [1 byte]  message type (EnvelopeType)
 *   [2 bytes] payload length (big-endian uint16)
 *   [4 bytes] reserved / flags
 *   [N bytes] payload
 *   [R bytes] random padding to fill UNIFORM_ENVELOPE_SIZE
 *
 * The random padding ensures cover traffic and real messages are
 * indistinguishable at the byte level.
 *
 * @param type - Message type
 * @param payload - The actual payload bytes (must be <= MAX_PAYLOAD_SIZE)
 * @returns Exactly UNIFORM_ENVELOPE_SIZE bytes
 */
export async function createUniformEnvelope(
  type: EnvelopeType,
  payload: Uint8Array,
): Promise<Uint8Array> {
  await initSodium();

  if (payload.length > MAX_PAYLOAD_SIZE) {
    throw new Error(
      `Payload too large: ${payload.length} bytes, max ${MAX_PAYLOAD_SIZE}`,
    );
  }

  const envelope = new Uint8Array(UNIFORM_ENVELOPE_SIZE);

  // Header
  envelope[0] = ENVELOPE_VERSION;
  envelope[1] = type;
  envelope[2] = (payload.length >>> 8) & 0xff;
  envelope[3] = payload.length & 0xff;
  // Reserved bytes (4-7) left as zero

  // Payload
  envelope.set(payload, ENVELOPE_HEADER_SIZE);

  // Random padding for the remainder
  const paddingStart = ENVELOPE_HEADER_SIZE + payload.length;
  const padding = sodium.randombytes_buf(
    UNIFORM_ENVELOPE_SIZE - paddingStart,
  );
  envelope.set(padding, paddingStart);

  return envelope;
}

/**
 * Parse a uniform envelope.
 *
 * @param envelope - Exactly UNIFORM_ENVELOPE_SIZE bytes
 * @returns The message type and extracted payload
 * @throws If the envelope is malformed
 */
export function parseUniformEnvelope(envelope: Uint8Array): {
  type: EnvelopeType;
  payload: Uint8Array;
} {
  if (envelope.length !== UNIFORM_ENVELOPE_SIZE) {
    throw new Error(
      `Invalid envelope size: ${envelope.length}, expected ${UNIFORM_ENVELOPE_SIZE}`,
    );
  }

  const version = envelope[0] as number;
  if (version !== ENVELOPE_VERSION) {
    throw new Error(`Unknown envelope version: 0x${version.toString(16)}`);
  }

  const type = (envelope[1] as number) as EnvelopeType;
  const payloadLen = ((envelope[2] as number) << 8) | (envelope[3] as number);

  if (payloadLen > MAX_PAYLOAD_SIZE) {
    throw new Error(`Invalid payload length: ${payloadLen}`);
  }

  const payload = envelope.slice(
    ENVELOPE_HEADER_SIZE,
    ENVELOPE_HEADER_SIZE + payloadLen,
  );

  return { type, payload };
}

/**
 * Generate a cover traffic message.
 * Indistinguishable from a real message at the byte level.
 */
export async function generateCoverMessage(): Promise<Uint8Array> {
  await initSodium();

  // Random payload of random size (to mimic real traffic patterns)
  const payloadSize = sodium.randombytes_uniform(MAX_PAYLOAD_SIZE) + 1;
  const payload = sodium.randombytes_buf(payloadSize);

  return createUniformEnvelope(EnvelopeType.COVER, payload);
}

// --- Cover Traffic Scheduler ---

/** Configuration for the cover traffic scheduler. */
export interface CoverTrafficConfig {
  /** Cover traffic intensity level. */
  level: CoverTrafficLevel;
  /** Callback to send a message (real or cover). */
  sendCallback: (envelope: Uint8Array) => void | Promise<void>;
}

/**
 * Cover traffic scheduler.
 *
 * When running in HIGH mode, sends messages at a constant rate regardless
 * of whether real messages are available. This makes it impossible for a
 * network observer to distinguish active vs idle periods.
 *
 * In MEDIUM mode, sends periodic cover messages with timing jitter.
 * In LOW mode, sends infrequent cover messages.
 */
export class CoverTrafficScheduler {
  private _config: CoverTrafficConfig;
  private _timer: ReturnType<typeof setInterval> | null = null;
  private _pendingReal: Uint8Array[] = [];
  private _running = false;

  constructor(config: CoverTrafficConfig) {
    this._config = config;
  }

  /** Start the cover traffic scheduler. */
  start(): void {
    if (this._running) return;
    this._running = true;

    const intervalMs = this._getIntervalMs();
    if (intervalMs === 0) return; // OFF mode

    this._timer = setInterval(async () => {
      await this._tick();
    }, intervalMs);
  }

  /** Stop the cover traffic scheduler. */
  stop(): void {
    this._running = false;
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
    this._pendingReal = [];
  }

  /**
   * Queue a real message for sending.
   * In HIGH mode, it replaces the next cover message in the queue.
   * In other modes, it's sent immediately.
   */
  async queueRealMessage(envelope: Uint8Array): Promise<void> {
    if (this._config.level === CoverTrafficLevel.HIGH) {
      this._pendingReal.push(envelope);
    } else {
      await this._config.sendCallback(envelope);
    }
  }

  /** Update the cover traffic level. */
  setLevel(level: CoverTrafficLevel): void {
    this.stop();
    this._config.level = level;
    this.start();
  }

  /** Whether the scheduler is running. */
  get running(): boolean {
    return this._running;
  }

  private _getIntervalMs(): number {
    switch (this._config.level) {
      case CoverTrafficLevel.OFF:
        return 0;
      case CoverTrafficLevel.LOW:
        return 60_000; // 60s
      case CoverTrafficLevel.MEDIUM:
        return 30_000; // 30s base (jitter added in _tick)
      case CoverTrafficLevel.HIGH:
        return 5_000; // 5s constant rate
    }
  }

  private async _tick(): Promise<void> {
    if (!this._running) return;

    let message: Uint8Array;

    if (this._pendingReal.length > 0) {
      // Send a real message from the queue
      message = this._pendingReal.shift()!;
    } else {
      // Send cover traffic
      message = await generateCoverMessage();
    }

    await this._config.sendCallback(message);
  }
}

// --- Message Batching ---

/** Configuration for message batching. */
export interface BatchConfig {
  /** Batch window in milliseconds (default 1000ms). */
  windowMs: number;
  /** Maximum batch size (default 8). */
  maxBatchSize: number;
  /** Callback to send a batch. */
  sendCallback: (batch: Uint8Array[]) => void | Promise<void>;
}

/**
 * Message batcher — accumulates messages and sends them in fixed-size batches.
 *
 * Always sends exactly maxBatchSize messages per batch.
 * If fewer real messages are available, pads with cover traffic.
 * An observer sees uniform batches at regular intervals.
 */
export class MessageBatcher {
  private _config: BatchConfig;
  private _queue: Uint8Array[] = [];
  private _timer: ReturnType<typeof setInterval> | null = null;
  private _running = false;

  constructor(config: BatchConfig) {
    this._config = config;
  }

  /** Start the batcher. */
  start(): void {
    if (this._running) return;
    this._running = true;

    this._timer = setInterval(async () => {
      await this._flush();
    }, this._config.windowMs);
  }

  /** Stop the batcher. */
  stop(): void {
    this._running = false;
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
    this._queue = [];
  }

  /** Add a real message to the batch queue. */
  enqueue(envelope: Uint8Array): void {
    this._queue.push(envelope);

    // If we have enough for a full batch, send immediately
    if (this._queue.length >= this._config.maxBatchSize) {
      void this._flush();
    }
  }

  /** Whether the batcher is running. */
  get running(): boolean {
    return this._running;
  }

  /** Number of messages in the queue. */
  get queueSize(): number {
    return this._queue.length;
  }

  private async _flush(): Promise<void> {
    if (!this._running) return;

    const batch: Uint8Array[] = [];

    // Take up to maxBatchSize real messages
    const realCount = Math.min(
      this._queue.length,
      this._config.maxBatchSize,
    );
    for (let i = 0; i < realCount; i++) {
      batch.push(this._queue.shift()!);
    }

    // Pad with cover traffic to reach exactly maxBatchSize
    while (batch.length < this._config.maxBatchSize) {
      batch.push(await generateCoverMessage());
    }

    // Shuffle to prevent position-based correlation (Fisher-Yates)
    for (let i = batch.length - 1; i > 0; i--) {
      const j = sodium.randombytes_uniform(i + 1);
      const a = batch[i] as Uint8Array;
      const b = batch[j] as Uint8Array;
      batch[i] = b;
      batch[j] = a;
    }

    await this._config.sendCallback(batch);
  }
}

/**
 * Add timing jitter to decorrelate message patterns.
 *
 * @param baseMs - Base delay in milliseconds
 * @param jitterMs - Maximum jitter (±) in milliseconds
 * @returns A promise that resolves after the jittered delay
 */
export async function timedJitter(
  baseMs: number,
  jitterMs: number,
): Promise<void> {
  await initSodium();
  const jitter =
    sodium.randombytes_uniform(jitterMs * 2 + 1) - jitterMs;
  const delay = Math.max(0, baseMs + jitter);
  return new Promise((resolve) => setTimeout(resolve, delay));
}
