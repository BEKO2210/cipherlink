/**
 * CipherLink — Zero-knowledge WebSocket relay server.
 *
 * Features:
 * - V1 envelope routing (pairwise E2EE)
 * - Sealed sender routing (sender hidden from server)
 * - Prekey bundle storage/retrieval (for X3DH)
 * - Group message fan-out
 * - Server-side replay protection
 * - Rate limiting + offline queue
 * - TLS enforcement in production
 * - IP-based connection limiting
 * - WebSocket ping/pong keepalive
 *
 * The server NEVER sees plaintext messages.
 *
 * @author Belkis Aslani
 * @license MIT
 */
import { createServer } from "https";
import { readFileSync } from "fs";
import { WebSocketServer, WebSocket } from "ws";
import type { IncomingMessage } from "http";
import { clientMessageSchema } from "./schema.js";
import type {
  Envelope,
  SealedEnvelope,
  PrekeyBundle,
  GroupMessage,
} from "./schema.js";
import { TokenBucket } from "./rate-limit.js";
import { OfflineQueue } from "./queue.js";
import { loadConfig } from "./config.js";

// --- Configuration ---
const config = loadConfig();

// --- Structured logging with level filtering ---
const LOG_LEVELS = { error: 0, warn: 1, info: 2, debug: 3 } as const;
const currentLogLevel = LOG_LEVELS[config.logLevel];

function log(level: "info" | "warn" | "error" | "debug", msg: string): void {
  if (LOG_LEVELS[level] > currentLogLevel) return;
  const ts = config.logTimestamps ? new Date().toISOString() + " " : "";
  // SECURITY: Never log keys, secrets, ciphertext, or user-identifiable data.
  // Only log operational events with sanitized context.
  console.error(`${ts}[${level.toUpperCase()}] ${msg}`);
}

// --- Connection tracking per IP ---
const connectionsPerIp = new Map<string, number>();
const MAX_GROUP_RECIPIENTS = 256;

function getClientIp(req: IncomingMessage): string {
  // In production behind a reverse proxy, use X-Forwarded-For.
  // Direct connections use socket remoteAddress.
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") {
    return forwarded.split(",")[0]?.trim() ?? "unknown";
  }
  return req.socket.remoteAddress ?? "unknown";
}

interface ClientState {
  publicKey: string | null;
  rateLimiter: TokenBucket;
  ip: string;
  pongReceived: boolean;
}

// --- Server state ---
const clients = new Map<string, WebSocket>();
const clientState = new WeakMap<WebSocket, ClientState>();
const offlineQueue = new OfflineQueue();

// Prekey bundle storage: publicKey -> bundle
const prekeyStore = new Map<string, PrekeyBundle>();

// Replay protection: track recent message IDs (server-side dedup)
const recentMessageIds = new Set<string>();
const messageIdOrder: string[] = [];
const MAX_RECENT_IDS = 50_000;

function trackMessageId(msgId: string): boolean {
  if (recentMessageIds.has(msgId)) return false; // Duplicate
  recentMessageIds.add(msgId);
  messageIdOrder.push(msgId);
  while (messageIdOrder.length > MAX_RECENT_IDS) {
    const oldest = messageIdOrder.shift()!;
    recentMessageIds.delete(oldest);
  }
  return true; // New message
}

// --- Create server (TLS or plain) ---
function createWebSocketServer(): WebSocketServer {
  if (config.requireTls) {
    const httpsServer = createServer({
      cert: readFileSync(config.tlsCert!),
      key: readFileSync(config.tlsKey!),
    });
    const wss = new WebSocketServer({
      server: httpsServer,
      maxPayload: config.maxPayloadBytes,
    });
    httpsServer.listen(config.port);
    log("info", `Relay server listening on wss://localhost:${config.port} (TLS enabled)`);
    return wss;
  }

  const wss = new WebSocketServer({
    port: config.port,
    maxPayload: config.maxPayloadBytes,
  });
  log("warn", `Relay server listening on ws://localhost:${config.port} (TLS DISABLED — development only)`);
  return wss;
}

const wss = createWebSocketServer();

function sendError(
  ws: WebSocket,
  code: string,
  message: string,
): void {
  ws.send(JSON.stringify({ type: "error", code, message }));
}

function requireAuth(ws: WebSocket, state: ClientState): boolean {
  if (!state.publicKey) {
    sendError(ws, "NOT_AUTHENTICATED", "Send a 'hello' message first");
    return false;
  }
  return true;
}

// --- Ping/pong keepalive ---
let pingInterval: ReturnType<typeof setInterval> | undefined;
if (config.pingIntervalMs > 0) {
  pingInterval = setInterval(() => {
    for (const ws of wss.clients) {
      const cState = clientState.get(ws);
      if (cState && !cState.pongReceived) {
        ws.terminate();
        continue;
      }
      if (cState) {
        cState.pongReceived = false;
      }
      ws.ping();
    }
  }, config.pingIntervalMs);
}

wss.on("connection", (ws, req) => {
  const ip = getClientIp(req);

  // IP-based connection limiting
  if (config.maxConnectionsPerIp > 0) {
    const current = connectionsPerIp.get(ip) ?? 0;
    if (current >= config.maxConnectionsPerIp) {
      log("warn", `Connection rejected: IP limit exceeded`);
      ws.close(1013, "Too many connections from your address");
      return;
    }
    connectionsPerIp.set(ip, current + 1);
  }

  const state: ClientState = {
    publicKey: null,
    rateLimiter: new TokenBucket({ maxTokens: 30, refillRate: 5 }),
    ip,
    pongReceived: true,
  };
  clientState.set(ws, state);
  log("info", "Client connected");

  ws.on("pong", () => {
    const cState = clientState.get(ws);
    if (cState) cState.pongReceived = true;
  });

  ws.on("message", (raw) => {
    const cState = clientState.get(ws);
    if (!cState) return;

    if (!cState.rateLimiter.consume()) {
      sendError(ws, "RATE_LIMITED", "Too many messages. Please slow down.");
      return;
    }

    let data: unknown;
    try {
      data = JSON.parse(raw.toString("utf-8"));
    } catch {
      sendError(ws, "INVALID_JSON", "Could not parse JSON");
      return;
    }

    const parsed = clientMessageSchema.safeParse(data);
    if (!parsed.success) {
      sendError(ws, "INVALID_MESSAGE", "Schema validation failed");
      return;
    }

    const msg = parsed.data;

    switch (msg.type) {
      case "hello":
        handleHello(ws, cState, msg.publicKey);
        break;
      case "send":
        handleSend(ws, cState, msg.envelope);
        break;
      case "send_sealed":
        handleSendSealed(ws, cState, msg.envelope);
        break;
      case "publish_prekeys":
        handlePublishPrekeys(ws, cState, msg.bundle);
        break;
      case "fetch_prekeys":
        handleFetchPrekeys(ws, cState, msg.publicKey);
        break;
      case "send_group":
        handleSendGroup(ws, cState, msg.groupId, msg.message, msg.recipients);
        break;
    }
  });

  ws.on("close", () => {
    const cState = clientState.get(ws);
    if (cState?.publicKey) {
      clients.delete(cState.publicKey);
    }
    // Decrement IP connection count
    if (config.maxConnectionsPerIp > 0) {
      const current = connectionsPerIp.get(ip) ?? 1;
      if (current <= 1) {
        connectionsPerIp.delete(ip);
      } else {
        connectionsPerIp.set(ip, current - 1);
      }
    }
    log("info", "Client disconnected");
  });

  ws.on("error", () => {
    log("error", "WebSocket error on connection");
  });
});

// --- Hello ---
function handleHello(
  ws: WebSocket,
  state: ClientState,
  publicKey: string,
): void {
  if (state.publicKey) clients.delete(state.publicKey);
  state.publicKey = publicKey;
  clients.set(publicKey, ws);
  // SECURITY: Do not log the public key itself
  log("info", "Client authenticated");

  ws.send(JSON.stringify({ type: "welcome" }));

  const queued = offlineQueue.drain(publicKey);
  for (const envelope of queued) {
    ws.send(JSON.stringify({ type: "message", envelope }));
  }
  if (queued.length > 0) {
    log("info", `Delivered ${queued.length} queued message(s)`);
  }
}

// --- V1 Send (pairwise) ---
function handleSend(
  ws: WebSocket,
  state: ClientState,
  envelope: Envelope,
): void {
  if (!requireAuth(ws, state)) return;

  if (envelope.senderPub !== state.publicKey) {
    sendError(ws, "SENDER_MISMATCH", "Envelope senderPub does not match your authenticated key");
    return;
  }

  // Server-side replay protection
  if (!trackMessageId(envelope.msgId)) {
    sendError(ws, "DUPLICATE_MESSAGE", "Message ID already seen (replay rejected)");
    return;
  }

  const recipientWs = clients.get(envelope.recipientPub);
  if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
    recipientWs.send(JSON.stringify({ type: "message", envelope }));
    ws.send(JSON.stringify({ type: "ack", msgId: envelope.msgId, status: "delivered" }));
  } else {
    offlineQueue.enqueue(envelope.recipientPub, envelope);
    ws.send(JSON.stringify({ type: "ack", msgId: envelope.msgId, status: "queued" }));
  }
}

// --- Sealed Sender ---
function handleSendSealed(
  ws: WebSocket,
  state: ClientState,
  envelope: SealedEnvelope,
): void {
  if (!requireAuth(ws, state)) return;

  // No sender verification possible — that's the point of sealed sender!
  // Server only knows the recipient.
  const recipientWs = clients.get(envelope.recipientPub);
  if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
    recipientWs.send(JSON.stringify({ type: "sealed_message", envelope }));
    ws.send(JSON.stringify({ type: "ack", status: "delivered" }));
  } else {
    // Queue sealed envelopes too
    offlineQueue.enqueue(envelope.recipientPub, envelope);
    ws.send(JSON.stringify({ type: "ack", status: "queued" }));
  }
}

// --- Prekey Bundles ---
function handlePublishPrekeys(
  ws: WebSocket,
  state: ClientState,
  bundle: PrekeyBundle,
): void {
  if (!requireAuth(ws, state)) return;

  // Verify the bundle's identity key matches the authenticated key
  if (bundle.identityKey !== state.publicKey) {
    sendError(ws, "IDENTITY_MISMATCH", "Bundle identity key does not match authenticated key");
    return;
  }

  prekeyStore.set(state.publicKey!, bundle);
  ws.send(JSON.stringify({ type: "prekeys_stored" }));
  log("info", "Prekey bundle stored");
}

function handleFetchPrekeys(
  ws: WebSocket,
  state: ClientState,
  targetPublicKey: string,
): void {
  if (!requireAuth(ws, state)) return;

  const bundle = prekeyStore.get(targetPublicKey);
  if (bundle) {
    ws.send(JSON.stringify({ type: "prekey_bundle", bundle }));
  } else {
    ws.send(JSON.stringify({ type: "prekey_bundle", bundle: null }));
  }
}

// --- Group Messages ---
function handleSendGroup(
  ws: WebSocket,
  state: ClientState,
  _groupId: string,
  message: GroupMessage,
  recipients: string[],
): void {
  if (!requireAuth(ws, state)) return;

  // Cap recipient count to prevent fan-out amplification
  if (recipients.length > MAX_GROUP_RECIPIENTS) {
    sendError(ws, "TOO_MANY_RECIPIENTS", `Maximum ${MAX_GROUP_RECIPIENTS} recipients per group message`);
    return;
  }

  let delivered = 0;
  let queued = 0;

  for (const recipientPub of recipients) {
    // Don't send back to sender
    if (recipientPub === state.publicKey) continue;

    const recipientWs = clients.get(recipientPub);
    if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
      recipientWs.send(
        JSON.stringify({
          type: "group_message",
          senderPub: state.publicKey,
          message,
        }),
      );
      delivered++;
    } else {
      offlineQueue.enqueue(recipientPub, {
        _type: "group",
        senderPub: state.publicKey,
        message,
      });
      queued++;
    }
  }

  ws.send(
    JSON.stringify({
      type: "group_ack",
      groupId: message.groupId,
      delivered,
      queued,
    }),
  );
}

log("info", "Features: pairwise E2EE, sealed sender, prekey bundles, group messaging, replay protection");

function shutdown(): void {
  log("info", "Shutting down...");
  if (pingInterval) clearInterval(pingInterval);
  offlineQueue.destroy();
  wss.close(() => {
    process.exit(0);
  });
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
