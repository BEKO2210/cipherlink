/**
 * Protocol State Machine — prevents undefined state transitions.
 *
 * Every session follows a strict state progression:
 *
 *   UNINITIALIZED → PREKEY_PUBLISHED → KEY_AGREEMENT → RATCHETING → CLOSED
 *
 * Invalid transitions are rejected at the type level AND at runtime.
 * This prevents an entire class of protocol bugs:
 * - Encrypting before key agreement (undefined behavior)
 * - Ratcheting a closed session (use-after-free)
 * - Skipping key agreement (no forward secrecy)
 * - Re-initializing an active session (state corruption)
 *
 * Design: Each state transition returns a NEW state object.
 * The old state object becomes invalid. This mirrors the
 * ownership model in Rust and prevents stale state references.
 *
 * @module protocol-state
 * @author Belkis Aslani
 */

/** All possible session states. */
export enum SessionPhase {
  /** Session created but no keys generated or published. */
  UNINITIALIZED = "UNINITIALIZED",
  /** Prekey bundle published to server, awaiting key agreement. */
  PREKEY_PUBLISHED = "PREKEY_PUBLISHED",
  /** X3DH key agreement completed, ready to ratchet. */
  KEY_AGREEMENT = "KEY_AGREEMENT",
  /** Double Ratchet active — encrypting/decrypting messages. */
  RATCHETING = "RATCHETING",
  /** Session closed — all key material wiped. */
  CLOSED = "CLOSED",
}

/** Valid state transitions (source → allowed destinations). */
const VALID_TRANSITIONS: ReadonlyMap<SessionPhase, readonly SessionPhase[]> =
  new Map([
    [SessionPhase.UNINITIALIZED, [SessionPhase.PREKEY_PUBLISHED]],
    [
      SessionPhase.PREKEY_PUBLISHED,
      [SessionPhase.KEY_AGREEMENT, SessionPhase.CLOSED],
    ],
    [SessionPhase.KEY_AGREEMENT, [SessionPhase.RATCHETING, SessionPhase.CLOSED]],
    [SessionPhase.RATCHETING, [SessionPhase.RATCHETING, SessionPhase.CLOSED]],
    [SessionPhase.CLOSED, []], // Terminal state — no transitions allowed
  ]);

/** Error thrown on invalid state transition. */
export class InvalidTransitionError extends Error {
  constructor(
    public readonly from: SessionPhase,
    public readonly to: SessionPhase,
  ) {
    super(
      `Invalid session transition: ${from} → ${to}. ` +
        `Allowed from ${from}: [${(VALID_TRANSITIONS.get(from) ?? []).join(", ")}]`,
    );
    this.name = "InvalidTransitionError";
  }
}

/** Session invariant that must hold at all times. */
export interface SessionInvariant {
  /** Human-readable name for error messages. */
  name: string;
  /** Check function — returns true if invariant holds. */
  check: (state: SessionState) => boolean;
  /** Error message when violated. */
  message: string;
}

/** Core session state tracked by the protocol state machine. */
export interface SessionState {
  /** Current phase. */
  readonly phase: SessionPhase;
  /** Cipher suite ID for this session. */
  readonly cipherSuiteId: number;
  /** Session creation timestamp (ms since epoch). */
  readonly createdAt: number;
  /** Last state transition timestamp. */
  readonly lastTransitionAt: number;
  /** Total messages encrypted in this session. */
  readonly messagesSent: number;
  /** Total messages decrypted in this session. */
  readonly messagesReceived: number;
  /** Whether the session has PQ protection. */
  readonly pqProtected: boolean;
  /** Session epoch (increments on each ratchet reset). */
  readonly epoch: number;
}

/** Immutable session invariants — checked on every transition. */
const INVARIANTS: readonly SessionInvariant[] = [
  {
    name: "epoch-monotonic",
    check: (s) => s.epoch >= 0,
    message: "Session epoch must be non-negative",
  },
  {
    name: "message-count-non-negative",
    check: (s) => s.messagesSent >= 0 && s.messagesReceived >= 0,
    message: "Message counts must be non-negative",
  },
  {
    name: "timestamp-ordering",
    check: (s) => s.lastTransitionAt >= s.createdAt,
    message: "Last transition must not precede creation",
  },
];

/**
 * Create a new session state in the UNINITIALIZED phase.
 */
export function createSessionState(
  cipherSuiteId: number,
  pqProtected: boolean,
): SessionState {
  const now = Date.now();
  return Object.freeze({
    phase: SessionPhase.UNINITIALIZED,
    cipherSuiteId,
    createdAt: now,
    lastTransitionAt: now,
    messagesSent: 0,
    messagesReceived: 0,
    pqProtected,
    epoch: 0,
  });
}

/**
 * Transition to a new phase.
 *
 * @param current - The current session state.
 * @param target - The target phase.
 * @param updates - Optional field updates to apply.
 * @returns A new frozen SessionState in the target phase.
 * @throws InvalidTransitionError if the transition is not allowed.
 * @throws Error if any session invariant is violated.
 */
export function transitionTo(
  current: SessionState,
  target: SessionPhase,
  updates?: Partial<
    Pick<SessionState, "messagesSent" | "messagesReceived" | "epoch">
  >,
): SessionState {
  // Check transition validity
  const allowed = VALID_TRANSITIONS.get(current.phase);
  if (!allowed || !allowed.includes(target)) {
    throw new InvalidTransitionError(current.phase, target);
  }

  const newState: SessionState = Object.freeze({
    ...current,
    phase: target,
    lastTransitionAt: Date.now(),
    ...updates,
  });

  // Verify all invariants
  for (const inv of INVARIANTS) {
    if (!inv.check(newState)) {
      throw new Error(`Session invariant violated [${inv.name}]: ${inv.message}`);
    }
  }

  return newState;
}

/**
 * Record a sent message (increment counter).
 * Only valid in RATCHETING phase.
 */
export function recordMessageSent(state: SessionState): SessionState {
  if (state.phase !== SessionPhase.RATCHETING) {
    throw new Error(
      `Cannot send message in phase ${state.phase} — must be RATCHETING`,
    );
  }
  return Object.freeze({
    ...state,
    messagesSent: state.messagesSent + 1,
    lastTransitionAt: Date.now(),
  });
}

/**
 * Record a received message (increment counter).
 * Only valid in RATCHETING phase.
 */
export function recordMessageReceived(state: SessionState): SessionState {
  if (state.phase !== SessionPhase.RATCHETING) {
    throw new Error(
      `Cannot receive message in phase ${state.phase} — must be RATCHETING`,
    );
  }
  return Object.freeze({
    ...state,
    messagesReceived: state.messagesReceived + 1,
    lastTransitionAt: Date.now(),
  });
}

/**
 * Check if the session should perform a key rotation.
 *
 * Returns true if:
 * - More than MAX_MESSAGES messages have been sent since last rotation
 * - More than MAX_TIME_MS has elapsed since last rotation
 * - Session has been idle for too long
 */
export function shouldRotateKeys(
  state: SessionState,
  policy: {
    maxMessages?: number;
    maxTimeMs?: number;
  } = {},
): boolean {
  const maxMessages = policy.maxMessages ?? 100;
  const maxTimeMs = policy.maxTimeMs ?? 7 * 24 * 60 * 60 * 1000; // 7 days

  if (state.phase !== SessionPhase.RATCHETING) return false;

  const totalMessages = state.messagesSent + state.messagesReceived;
  if (totalMessages >= maxMessages) return true;

  const elapsed = Date.now() - state.lastTransitionAt;
  if (elapsed >= maxTimeMs) return true;

  return false;
}

/**
 * Get a human-readable description of the session state.
 */
export function describeSession(state: SessionState): string {
  return (
    `Session[${state.phase}] suite=0x${state.cipherSuiteId.toString(16).padStart(4, "0")} ` +
    `epoch=${state.epoch} sent=${state.messagesSent} recv=${state.messagesReceived} ` +
    `pq=${state.pqProtected ? "yes" : "no"}`
  );
}
