# Protocol State Machine Specification

> **Version:** 1.0
> **Date:** 2026-02-10
> **Module:** `packages/crypto/src/protocol-state.ts`

## 1. Session Lifecycle

A CipherLink session follows a strict state machine with 5 phases:

```
    ┌──────────────────┐
    │  UNINITIALIZED   │  Initial state: no keys, no session
    └────────┬─────────┘
             │ publishPrekeys()
             ▼
    ┌──────────────────┐
    │ PREKEY_PUBLISHED  │  Identity + prekeys uploaded to server
    └────────┬─────────┘
             │ performX3DH() — sender or receiver
             ▼
    ┌──────────────────┐
    │  KEY_AGREEMENT   │  Shared secret established via X3DH
    └────────┬─────────┘
             │ initializeRatchet()
             ▼
    ┌──────────────────┐
    │    RATCHETING     │  Active session — messages can flow
    │                  │  ← recordMessageSent()
    │                  │  ← recordMessageReceived()
    └────────┬─────────┘
             │ closeSession()
             ▼
    ┌──────────────────┐
    │     CLOSED       │  Terminal — no further transitions
    └──────────────────┘
```

## 2. State Definitions

### UNINITIALIZED
- **Entry condition:** `createSessionState()` called
- **Allowed transitions:** `PREKEY_PUBLISHED`
- **Invariants:** epoch = 0, messagesSent = 0, messagesReceived = 0

### PREKEY_PUBLISHED
- **Entry condition:** Client has generated and uploaded prekey bundle to server
- **Allowed transitions:** `KEY_AGREEMENT`
- **Invariants:** epoch = 0, identity key exists

### KEY_AGREEMENT
- **Entry condition:** X3DH completed (sender computed shared secret from bundle, or receiver processed initial message)
- **Allowed transitions:** `RATCHETING`
- **Invariants:** epoch ≥ 0, shared secret established

### RATCHETING
- **Entry condition:** Double Ratchet initialized with X3DH output
- **Allowed transitions:** `CLOSED`
- **Operations:**
  - `recordMessageSent()` — increments messagesSent counter
  - `recordMessageReceived()` — increments messagesReceived counter
  - Key rotation trigger: when `shouldRotateKeys()` returns true
- **Invariants:**
  - messagesSent ≥ 0
  - messagesReceived ≥ 0
  - epoch monotonically increasing
  - lastActivity timestamp monotonically increasing

### CLOSED
- **Entry condition:** Session explicitly closed (logout, key change, revocation)
- **Allowed transitions:** None (terminal state)
- **Invariants:** No operations permitted

## 3. Valid Transition Table

| From | To | Trigger | Reversible |
|------|----|---------|------------|
| UNINITIALIZED | PREKEY_PUBLISHED | publishPrekeys() | No |
| PREKEY_PUBLISHED | KEY_AGREEMENT | performX3DH() | No |
| KEY_AGREEMENT | RATCHETING | initializeRatchet() | No |
| RATCHETING | CLOSED | closeSession() | No |

**All other transitions are invalid** and throw `InvalidTransitionError`.

## 4. Invariants (Enforced at Every Transition)

1. **Epoch monotonicity:** `newState.epoch >= currentState.epoch`
2. **Counter non-negativity:** `messagesSent >= 0 && messagesReceived >= 0`
3. **Timestamp ordering:** `newState.lastActivity >= currentState.lastActivity`
4. **State immutability:** All state objects are `Object.freeze()`d after creation
5. **Terminal finality:** CLOSED state cannot transition to any other state

## 5. Key Rotation Policy

`shouldRotateKeys(state, config)` returns `true` when:

- `messagesSent + messagesReceived >= maxMessages` (default: 100), OR
- `now - lastActivity >= maxIdleMs` (default: 24 hours)

Key rotation triggers a new DH ratchet step in the Double Ratchet, introducing fresh ephemeral keys.

## 6. Error Handling

| Error | Condition | Recovery |
|-------|-----------|----------|
| `InvalidTransitionError` | Attempted transition not in valid table | Caller must not proceed; log and alert |
| Invariant violation | Counter goes negative, epoch decreases | Implementation bug — must not happen in correct code |

## 7. Test Coverage

8 tests in `v2-security.test.ts` > "Protocol State Machine":
- Initial state creation
- Valid full lifecycle path
- Invalid transition rejection
- CLOSED is terminal
- Message counting
- RATCHETING-only operations
- Key rotation detection
- State immutability
