/**
 * WebSocket client for the CipherLink relay server.
 * Supports: pairwise E2EE, sealed sender, prekey bundles, group messaging.
 * @author Belkis Aslani
 */
import type { Envelope, SealedEnvelope } from "./crypto";
import type { GroupMessage } from "./group-crypto";

export type ServerMessage =
  | { type: "welcome" }
  | { type: "message"; envelope: Envelope }
  | { type: "sealed_message"; envelope: SealedEnvelope }
  | { type: "ack"; msgId?: string; status: "delivered" | "queued" }
  | { type: "error"; code: string; message: string }
  | { type: "prekeys_stored" }
  | { type: "prekey_bundle"; bundle: PrekeyBundleData | null }
  | {
      type: "group_message";
      senderPub: string;
      message: GroupMessage;
    }
  | {
      type: "group_ack";
      groupId: string;
      delivered: number;
      queued: number;
    };

export interface PrekeyBundleData {
  identityKey: string;
  signingKey: string;
  signedPreKey: string;
  signedPreKeyId: number;
  signedPreKeySignature: string;
  oneTimePreKey?: string;
  oneTimePreKeyId?: number;
}

export type MessageHandler = (msg: ServerMessage) => void;

const RECONNECT_DELAYS = [1000, 2000, 4000, 8000, 16000];

export class CipherLinkClient {
  private ws: WebSocket | null = null;
  private handler: MessageHandler | null = null;
  private publicKey: string;
  private url: string;
  private reconnectAttempt = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private shouldReconnect = true;
  private onConnectChange: ((connected: boolean) => void) | null = null;

  constructor(url: string, publicKey: string) {
    this.url = url;
    this.publicKey = publicKey;

    // Warn if using unencrypted WebSocket in non-development
    if (!url.startsWith("wss://") && !url.includes("localhost") && !url.includes("127.0.0.1")) {
      console.warn(
        "[CipherLink] WARNING: Using unencrypted ws:// connection. " +
        "Use wss:// for production to prevent traffic interception.",
      );
    }
  }

  onMessage(handler: MessageHandler): void {
    this.handler = handler;
  }

  onConnectionChange(handler: (connected: boolean) => void): void {
    this.onConnectChange = handler;
  }

  connect(): void {
    this.shouldReconnect = true;
    this.doConnect();
  }

  private doConnect(): void {
    try {
      this.ws = new WebSocket(this.url);
    } catch {
      this.scheduleReconnect();
      return;
    }

    this.ws.onopen = () => {
      this.reconnectAttempt = 0;
      this.ws?.send(
        JSON.stringify({
          type: "hello",
          publicKey: this.publicKey,
        }),
      );
    };

    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data as string) as ServerMessage;
        if (data.type === "welcome") {
          this.onConnectChange?.(true);
        }
        this.handler?.(data);
      } catch {
        // Ignore unparseable messages
      }
    };

    this.ws.onerror = () => {
      // Will trigger onclose
    };

    this.ws.onclose = () => {
      this.onConnectChange?.(false);
      if (this.shouldReconnect) {
        this.scheduleReconnect();
      }
    };
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;
    const delay =
      RECONNECT_DELAYS[
        Math.min(this.reconnectAttempt, RECONNECT_DELAYS.length - 1)
      ] ?? 16000;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.reconnectAttempt++;
      this.doConnect();
    }, delay);
  }

  /** Send a standard E2EE envelope. Returns false if not connected. */
  send(envelope: Envelope): boolean {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type: "send", envelope }));
      return true;
    }
    return false;
  }

  /** Send a sealed sender envelope. Returns false if not connected. */
  sendSealed(envelope: SealedEnvelope): boolean {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type: "send_sealed", envelope }));
      return true;
    }
    return false;
  }

  /** Publish prekey bundle for X3DH. Returns false if not connected. */
  publishPrekeys(bundle: PrekeyBundleData): boolean {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type: "publish_prekeys", bundle }));
      return true;
    }
    return false;
  }

  /** Fetch another user's prekey bundle. Returns false if not connected. */
  fetchPrekeys(targetPublicKey: string): boolean {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(
        JSON.stringify({ type: "fetch_prekeys", publicKey: targetPublicKey }),
      );
      return true;
    }
    return false;
  }

  /** Send a group message to all recipients. Returns false if not connected. */
  sendGroup(
    groupId: string,
    message: GroupMessage,
    recipients: string[],
  ): boolean {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(
        JSON.stringify({ type: "send_group", groupId, message, recipients }),
      );
      return true;
    }
    return false;
  }

  disconnect(): void {
    this.shouldReconnect = false;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.ws?.close();
    this.ws = null;
  }

  get connected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  updateUrl(url: string): void {
    this.url = url;
  }

  /**
   * Test if a relay server is reachable. Opens a WebSocket, waits for
   * a "welcome" response, then closes. Returns latency in ms or throws.
   */
  static testConnection(
    url: string,
    timeoutMs = 8000,
  ): Promise<{ ok: true; latencyMs: number }> {
    return new Promise((resolve, reject) => {
      const start = Date.now();
      let ws: WebSocket | null = null;
      const timer = setTimeout(() => {
        ws?.close();
        reject(new Error("Connection timed out"));
      }, timeoutMs);

      try {
        ws = new WebSocket(url);
      } catch (_e: unknown) {
        clearTimeout(timer);
        reject(new Error("Invalid server URL"));
        return;
      }

      ws.onopen = () => {
        // Send a minimal hello with a test key to trigger "welcome"
        ws?.send(
          JSON.stringify({
            type: "hello",
            publicKey: "dGVzdC1jb25uZWN0aW9uLXBpbmc=", // "test-connection-ping" base64
          }),
        );
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data as string);
          if (data.type === "welcome") {
            clearTimeout(timer);
            const latencyMs = Date.now() - start;
            ws?.close();
            resolve({ ok: true, latencyMs });
          }
        } catch {
          // ignore
        }
      };

      ws.onerror = () => {
        clearTimeout(timer);
        reject(new Error("Server unreachable"));
      };

      ws.onclose = () => {
        clearTimeout(timer);
        // Only reject if we haven't resolved yet
      };
    });
  }
}
