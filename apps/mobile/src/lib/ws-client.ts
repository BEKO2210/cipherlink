/**
 * WebSocket client for connecting to the CipherLink relay server.
 * @author Belkis Aslani
 */
import type { Envelope } from "./crypto";

export type ServerMessage =
  | { type: "welcome" }
  | { type: "message"; envelope: Envelope }
  | { type: "ack"; msgId: string; status: "delivered" | "queued" }
  | { type: "error"; code: string; message: string };

export type MessageHandler = (msg: ServerMessage) => void;

export class CipherLinkClient {
  private ws: WebSocket | null = null;
  private handler: MessageHandler | null = null;
  private publicKey: string;
  private url: string;

  constructor(url: string, publicKey: string) {
    this.url = url;
    this.publicKey = publicKey;
  }

  onMessage(handler: MessageHandler): void {
    this.handler = handler;
  }

  connect(): void {
    this.ws = new WebSocket(this.url);

    this.ws.onopen = () => {
      // Authenticate with public key
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
        this.handler?.(data);
      } catch {
        // Ignore unparseable messages
      }
    };

    this.ws.onerror = () => {
      // Connection error — handle reconnect in UI layer
    };

    this.ws.onclose = () => {
      // Connection closed
    };
  }

  send(envelope: Envelope): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type: "send", envelope }));
    }
  }

  disconnect(): void {
    this.ws?.close();
    this.ws = null;
  }

  get connected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}
