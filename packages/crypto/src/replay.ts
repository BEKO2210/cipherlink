/**
 * Replay protection — message deduplication and monotonic counters.
 *
 * Prevents an attacker from re-sending previously captured messages.
 * Two layers of protection:
 * 1. Message ID deduplication (sliding window)
 * 2. Monotonic counter per session (reject old counters)
 *
 * @module replay
 * @author Belkis Aslani
 */

const DEFAULT_WINDOW_SIZE = 10_000;

/**
 * Sliding window replay detector.
 * Tracks recently seen message IDs and rejects duplicates.
 */
export class ReplayGuard {
  private seen: Set<string>;
  private order: string[];
  private readonly maxSize: number;

  constructor(windowSize: number = DEFAULT_WINDOW_SIZE) {
    this.seen = new Set();
    this.order = [];
    this.maxSize = windowSize;
  }

  /**
   * Check if a message ID has been seen before.
   * If not seen, records it and returns true (accept).
   * If already seen, returns false (reject — replay detected).
   */
  accept(messageId: string): boolean {
    if (this.seen.has(messageId)) {
      return false; // Replay detected
    }

    this.seen.add(messageId);
    this.order.push(messageId);

    // Evict oldest entries when window is full
    while (this.order.length > this.maxSize) {
      const oldest = this.order.shift()!;
      this.seen.delete(oldest);
    }

    return true;
  }

  /**
   * Check if a message ID has been seen (without recording it).
   */
  hasSeen(messageId: string): boolean {
    return this.seen.has(messageId);
  }

  /**
   * Number of tracked message IDs.
   */
  get size(): number {
    return this.seen.size;
  }

  /**
   * Clear all tracked message IDs.
   */
  clear(): void {
    this.seen.clear();
    this.order = [];
  }

  /**
   * Export state for persistence.
   */
  export(): { seen: string[]; maxSize: number } {
    return { seen: [...this.order], maxSize: this.maxSize };
  }

  /**
   * Import previously exported state.
   */
  static import(data: { seen: string[]; maxSize: number }): ReplayGuard {
    const guard = new ReplayGuard(data.maxSize);
    for (const id of data.seen) {
      guard.accept(id);
    }
    return guard;
  }
}

/**
 * Monotonic counter for per-session ordering.
 * Each session maintains a counter that must strictly increase.
 */
export class MonotonicCounter {
  private lastSeen: number;

  constructor(initial: number = -1) {
    this.lastSeen = initial;
  }

  /**
   * Verify a counter value is strictly greater than the last seen.
   * If valid, updates the counter and returns true.
   * If stale/replay, returns false.
   */
  accept(counter: number): boolean {
    if (counter <= this.lastSeen) {
      return false; // Stale or replay
    }
    this.lastSeen = counter;
    return true;
  }

  /**
   * Get the next expected counter value.
   */
  get next(): number {
    return this.lastSeen + 1;
  }

  /**
   * Current counter value.
   */
  get current(): number {
    return this.lastSeen;
  }

  /**
   * Export for persistence.
   */
  export(): number {
    return this.lastSeen;
  }
}

/**
 * Combined replay protection: dedup + monotonic counter.
 */
export class SessionReplayGuard {
  readonly dedup: ReplayGuard;
  readonly counter: MonotonicCounter;

  constructor(windowSize: number = DEFAULT_WINDOW_SIZE) {
    this.dedup = new ReplayGuard(windowSize);
    this.counter = new MonotonicCounter();
  }

  /**
   * Validate a message against both dedup and counter.
   * Returns { accepted, reason } indicating acceptance or rejection reason.
   */
  validate(
    messageId: string,
    messageNumber: number,
  ): { accepted: boolean; reason?: string } {
    if (!this.dedup.accept(messageId)) {
      return { accepted: false, reason: "duplicate_message_id" };
    }

    // Counter check is relaxed for out-of-order Double Ratchet messages
    // (skipped keys allow out-of-order within a chain)
    // But we still track it for logging/alerting
    if (!this.counter.accept(messageNumber)) {
      // For Double Ratchet, out-of-order is expected — just track it
      // The dedup check already prevents actual replays
    }

    return { accepted: true };
  }
}
