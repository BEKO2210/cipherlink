/**
 * CipherLink — Zero-knowledge WebSocket relay server.
 *
 * The server NEVER sees plaintext messages. It only routes encrypted
 * envelopes between clients identified by their public keys.
 *
 * ⚠️  WARNING: This is a security skeleton for educational/demo purposes.
 *     NOT suitable for high-risk production use without significant hardening.
 *
 * @author Belkis Aslani
 * @license MIT
 */
import { WebSocketServer, WebSocket } from "ws";
import { clientMessageSchema } from "./schema.js";
import type { Envelope } from "./schema.js";
import { TokenBucket } from "./rate-limit.js";
import { OfflineQueue } from "./queue.js";

const PORT = parseInt(process.env["PORT"] ?? "4200", 10);
const MAX_MESSAGE_SIZE = 64 * 1024; // 64 KB

interface ClientState {
  publicKey: string | null;
  rateLimiter: TokenBucket;
}

// Maps publicKey -> WebSocket connection
const clients = new Map<string, WebSocket>();
const clientState = new WeakMap<WebSocket, ClientState>();
const offlineQueue = new OfflineQueue();

const wss = new WebSocketServer({
  port: PORT,
  maxPayload: MAX_MESSAGE_SIZE,
});

function log(level: "info" | "warn" | "error", msg: string): void {
  const ts = new Date().toISOString();
  // Minimal operational logs only — never log message contents or keys
  console.error(`[${ts}] [${level.toUpperCase()}] ${msg}`);
}

wss.on("connection", (ws) => {
  const state: ClientState = {
    publicKey: null,
    rateLimiter: new TokenBucket({ maxTokens: 30, refillRate: 5 }),
  };
  clientState.set(ws, state);

  log("info", "Client connected");

  ws.on("message", (raw) => {
    const cState = clientState.get(ws);
    if (!cState) return;

    // Rate limiting
    if (!cState.rateLimiter.consume()) {
      ws.send(
        JSON.stringify({
          type: "error",
          code: "RATE_LIMITED",
          message: "Too many messages. Please slow down.",
        }),
      );
      return;
    }

    let data: unknown;
    try {
      data = JSON.parse(raw.toString("utf-8"));
    } catch {
      ws.send(
        JSON.stringify({
          type: "error",
          code: "INVALID_JSON",
          message: "Could not parse JSON",
        }),
      );
      return;
    }

    const parsed = clientMessageSchema.safeParse(data);
    if (!parsed.success) {
      ws.send(
        JSON.stringify({
          type: "error",
          code: "INVALID_MESSAGE",
          message: "Schema validation failed",
        }),
      );
      return;
    }

    const msg = parsed.data;

    if (msg.type === "hello") {
      handleHello(ws, cState, msg.publicKey);
    } else if (msg.type === "send") {
      handleSend(ws, cState, msg.envelope);
    }
  });

  ws.on("close", () => {
    const cState = clientState.get(ws);
    if (cState?.publicKey) {
      clients.delete(cState.publicKey);
      log("info", "Client disconnected");
    }
  });

  ws.on("error", () => {
    // Errors are logged but content is never exposed
    log("error", "WebSocket error on connection");
  });
});

function handleHello(
  ws: WebSocket,
  state: ClientState,
  publicKey: string,
): void {
  // Remove previous registration if reconnecting
  if (state.publicKey) {
    clients.delete(state.publicKey);
  }

  state.publicKey = publicKey;
  clients.set(publicKey, ws);

  log("info", "Client authenticated");

  ws.send(JSON.stringify({ type: "welcome" }));

  // Deliver any queued messages
  const queued = offlineQueue.drain(publicKey);
  for (const envelope of queued) {
    ws.send(JSON.stringify({ type: "message", envelope }));
  }

  if (queued.length > 0) {
    log("info", `Delivered ${queued.length} queued message(s)`);
  }
}

function handleSend(
  ws: WebSocket,
  state: ClientState,
  envelope: Envelope,
): void {
  if (!state.publicKey) {
    ws.send(
      JSON.stringify({
        type: "error",
        code: "NOT_AUTHENTICATED",
        message: "Send a 'hello' message first",
      }),
    );
    return;
  }

  // Verify the sender claim matches the authenticated public key
  if (envelope.senderPub !== state.publicKey) {
    ws.send(
      JSON.stringify({
        type: "error",
        code: "SENDER_MISMATCH",
        message: "Envelope senderPub does not match your authenticated key",
      }),
    );
    return;
  }

  const recipientWs = clients.get(envelope.recipientPub);

  if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
    // Forward to online recipient
    recipientWs.send(JSON.stringify({ type: "message", envelope }));
    ws.send(
      JSON.stringify({ type: "ack", msgId: envelope.msgId, status: "delivered" }),
    );
  } else {
    // Queue for offline recipient
    offlineQueue.enqueue(envelope.recipientPub, envelope);
    ws.send(
      JSON.stringify({ type: "ack", msgId: envelope.msgId, status: "queued" }),
    );
  }
}

log("info", `CipherLink relay server listening on ws://localhost:${PORT}`);
log("info", "Zero-knowledge mode: server never sees plaintext messages");

// Graceful shutdown
function shutdown(): void {
  log("info", "Shutting down...");
  offlineQueue.destroy();
  wss.close(() => {
    process.exit(0);
  });
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
