/**
 * In-memory TTL queue for offline message buffering.
 * Messages are held for a short period and then dropped.
 *
 * @author Belkis Aslani
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type QueueableMessage = Record<string, any>;

interface QueuedMessage {
  envelope: QueueableMessage;
  expiresAt: number;
}

const DEFAULT_TTL_MS = 10 * 60 * 1000; // 10 minutes
const MAX_QUEUE_PER_RECIPIENT = 100;

export class OfflineQueue {
  private queues = new Map<string, QueuedMessage[]>();
  private cleanupInterval: ReturnType<typeof setInterval>;

  constructor(private readonly ttlMs: number = DEFAULT_TTL_MS) {
    // Periodic cleanup every 60 seconds
    this.cleanupInterval = setInterval(() => this.cleanup(), 60_000);
  }

  /**
   * Enqueue a message for an offline recipient.
   */
  enqueue(recipientPub: string, envelope: QueueableMessage): void {
    let queue = this.queues.get(recipientPub);
    if (!queue) {
      queue = [];
      this.queues.set(recipientPub, queue);
    }

    // Cap queue size per recipient
    if (queue.length >= MAX_QUEUE_PER_RECIPIENT) {
      queue.shift(); // drop oldest
    }

    queue.push({
      envelope,
      expiresAt: Date.now() + this.ttlMs,
    });
  }

  /**
   * Drain all queued messages for a recipient.
   */
  drain(recipientPub: string): QueueableMessage[] {
    const queue = this.queues.get(recipientPub);
    if (!queue) return [];

    const now = Date.now();
    const valid = queue
      .filter((m) => m.expiresAt > now)
      .map((m) => m.envelope);

    this.queues.delete(recipientPub);
    return valid;
  }

  /**
   * Remove expired messages from all queues.
   */
  private cleanup(): void {
    const now = Date.now();
    for (const [key, queue] of this.queues.entries()) {
      const filtered = queue.filter((m) => m.expiresAt > now);
      if (filtered.length === 0) {
        this.queues.delete(key);
      } else {
        this.queues.set(key, filtered);
      }
    }
  }

  /**
   * Stop the cleanup interval (for graceful shutdown).
   */
  destroy(): void {
    clearInterval(this.cleanupInterval);
    this.queues.clear();
  }
}
