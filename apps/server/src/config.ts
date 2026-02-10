/**
 * Server configuration with secure defaults.
 *
 * In production mode (NODE_ENV=production), insecure transport (ws://) is
 * blocked unless explicitly overridden. This prevents accidental deployment
 * without TLS.
 *
 * @module config
 * @author Belkis Aslani
 */

export interface ServerConfig {
  /** Port to listen on. */
  port: number;
  /** Whether to require TLS (wss://). In production, this defaults to true. */
  requireTls: boolean;
  /** Path to TLS certificate file (PEM). Required when requireTls is true. */
  tlsCert?: string;
  /** Path to TLS private key file (PEM). Required when requireTls is true. */
  tlsKey?: string;
  /** Maximum WebSocket payload size in bytes. */
  maxPayloadBytes: number;
  /** Log level: 'error' | 'warn' | 'info' | 'debug'. Production forces 'warn' minimum. */
  logLevel: "error" | "warn" | "info" | "debug";
  /** Whether to include timestamps in structured log output. */
  logTimestamps: boolean;
  /** Maximum connections per IP address (0 = unlimited). */
  maxConnectionsPerIp: number;
  /** WebSocket ping interval in ms (0 = disabled). */
  pingIntervalMs: number;
  /** WebSocket pong timeout in ms. Connection closed if no pong received. */
  pongTimeoutMs: number;
}

const isProduction = process.env["NODE_ENV"] === "production";

function envBool(key: string, defaultVal: boolean): boolean {
  const val = process.env[key];
  if (val === undefined) return defaultVal;
  return val === "1" || val.toLowerCase() === "true";
}

function envInt(key: string, defaultVal: number): number {
  const val = process.env[key];
  if (val === undefined) return defaultVal;
  const parsed = parseInt(val, 10);
  return Number.isNaN(parsed) ? defaultVal : parsed;
}

/**
 * Load server configuration from environment variables with secure defaults.
 * Throws if production mode is active but TLS is not configured.
 */
export function loadConfig(): ServerConfig {
  const requireTls = envBool("REQUIRE_TLS", isProduction);
  const tlsCert = process.env["TLS_CERT"];
  const tlsKey = process.env["TLS_KEY"];

  // Production guard: prevent insecure transport
  if (isProduction && !requireTls) {
    const override = envBool("ALLOW_INSECURE_TRANSPORT", false);
    if (!override) {
      throw new Error(
        "SECURITY: Cannot run insecure transport (ws://) in production.\n" +
          "Set REQUIRE_TLS=true and provide TLS_CERT + TLS_KEY, or set " +
          "ALLOW_INSECURE_TRANSPORT=true to override (NOT RECOMMENDED).",
      );
    }
  }

  if (requireTls && (!tlsCert || !tlsKey)) {
    throw new Error(
      "REQUIRE_TLS is true but TLS_CERT and TLS_KEY are not set.\n" +
        "Provide paths to PEM certificate and key files.",
    );
  }

  // Production guard: force minimum log level
  let logLevel = (process.env["LOG_LEVEL"] ?? (isProduction ? "warn" : "info")) as ServerConfig["logLevel"];
  if (isProduction && (logLevel === "debug" || logLevel === "info")) {
    logLevel = "warn"; // Never verbose logs in production
  }

  return {
    port: envInt("PORT", 4200),
    requireTls,
    tlsCert,
    tlsKey,
    maxPayloadBytes: envInt("MAX_PAYLOAD_BYTES", 128 * 1024),
    logLevel,
    logTimestamps: true,
    maxConnectionsPerIp: envInt("MAX_CONNECTIONS_PER_IP", isProduction ? 10 : 0),
    pingIntervalMs: envInt("PING_INTERVAL_MS", 30_000),
    pongTimeoutMs: envInt("PONG_TIMEOUT_MS", 10_000),
  };
}
