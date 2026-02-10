/**
 * Chat screen — pairwise E2EE messaging via the relay server.
 * @author Belkis Aslani
 */
import React, { useState, useCallback, useRef, useEffect } from "react";
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  FlatList,
  StyleSheet,
  Alert,
  KeyboardAvoidingView,
  Platform,
} from "react-native";
import {
  toBase64,
  fromBase64,
  encryptMessage,
  decryptMessage,
} from "../lib/crypto";
import type { Envelope } from "../lib/crypto";
import { CipherLinkClient } from "../lib/ws-client";
import type { ServerMessage } from "../lib/ws-client";
import { saveRecipientKey, loadRecipientKey } from "../lib/secure-storage";

interface ChatScreenProps {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

interface ChatMessage {
  id: string;
  text: string;
  sender: "me" | "them";
  timestamp: number;
}

const DEFAULT_SERVER_URL = "ws://localhost:4200";

export function ChatScreen({ publicKey, privateKey }: ChatScreenProps) {
  const [serverUrl, setServerUrl] = useState(DEFAULT_SERVER_URL);
  const [recipientPubB64, setRecipientPubB64] = useState("");
  const [connected, setConnected] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [draft, setDraft] = useState("");
  const clientRef = useRef<CipherLinkClient | null>(null);
  const flatListRef = useRef<FlatList>(null);

  const handleConnect = useCallback(() => {
    if (!recipientPubB64.trim()) {
      Alert.alert("Error", "Enter the recipient's public key first");
      return;
    }

    // Validate recipient key is valid base64
    try {
      const decoded = fromBase64(recipientPubB64.trim());
      if (decoded.length !== 32) {
        Alert.alert("Error", "Invalid public key length (expected 32 bytes)");
        return;
      }
    } catch {
      Alert.alert("Error", "Invalid base64 public key");
      return;
    }

    const myPubB64 = toBase64(publicKey);
    const client = new CipherLinkClient(serverUrl, myPubB64);

    client.onMessage(async (msg: ServerMessage) => {
      if (msg.type === "welcome") {
        setConnected(true);
      } else if (msg.type === "message") {
        await handleIncomingMessage(msg.envelope);
      } else if (msg.type === "error") {
        Alert.alert("Server Error", msg.message);
      }
    });

    client.connect();
    clientRef.current = client;

    // Check for key change
    checkKeyChange(recipientPubB64.trim());
  }, [serverUrl, recipientPubB64, publicKey, privateKey]);

  const checkKeyChange = async (recipientKey: string) => {
    // Use a short hash of the key as an ID for storage
    const shortId = recipientKey.slice(0, 16);
    const lastKnown = await loadRecipientKey(shortId);

    if (lastKnown && lastKnown !== recipientKey) {
      Alert.alert(
        "Key Changed",
        "The recipient's public key has changed since your last conversation. " +
          "This could indicate a new device or a potential security issue. " +
          "Verify the key with your contact.",
      );
    }

    await saveRecipientKey(shortId, recipientKey);
  };

  const handleIncomingMessage = async (envelope: Envelope) => {
    try {
      const senderPub = fromBase64(envelope.senderPub);
      const plaintext = await decryptMessage(privateKey, senderPub, envelope);

      setMessages((prev) => [
        ...prev,
        {
          id: envelope.msgId,
          text: plaintext,
          sender: "them",
          timestamp: envelope.ts,
        },
      ]);
    } catch {
      // Decryption failed — could be from a different sender
      Alert.alert("Decryption Failed", "Could not decrypt incoming message");
    }
  };

  const handleSend = useCallback(async () => {
    if (!draft.trim() || !clientRef.current?.connected) return;

    try {
      const recipientPub = fromBase64(recipientPubB64.trim());
      const envelope = await encryptMessage(
        privateKey,
        publicKey,
        recipientPub,
        draft.trim(),
      );

      clientRef.current.send(envelope);

      setMessages((prev) => [
        ...prev,
        {
          id: envelope.msgId,
          text: draft.trim(),
          sender: "me",
          timestamp: envelope.ts,
        },
      ]);

      setDraft("");
    } catch {
      Alert.alert("Error", "Failed to encrypt and send message");
    }
  }, [draft, recipientPubB64, privateKey, publicKey]);

  useEffect(() => {
    return () => {
      clientRef.current?.disconnect();
    };
  }, []);

  useEffect(() => {
    if (messages.length > 0) {
      flatListRef.current?.scrollToEnd({ animated: true });
    }
  }, [messages]);

  const renderMessage = ({ item }: { item: ChatMessage }) => (
    <View
      style={[
        styles.messageBubble,
        item.sender === "me" ? styles.myMessage : styles.theirMessage,
      ]}
    >
      <Text style={styles.messageText}>{item.text}</Text>
      <Text style={styles.messageTime}>
        {new Date(item.timestamp).toLocaleTimeString()}
      </Text>
    </View>
  );

  if (!connected) {
    return (
      <View style={styles.container}>
        <Text style={styles.title}>Connect</Text>

        <Text style={styles.label}>Server URL:</Text>
        <TextInput
          style={styles.input}
          value={serverUrl}
          onChangeText={setServerUrl}
          placeholder="ws://localhost:4200"
          placeholderTextColor="#666"
          autoCapitalize="none"
          autoCorrect={false}
        />

        <Text style={styles.label}>Recipient Public Key (base64):</Text>
        <TextInput
          style={[styles.input, styles.keyInput]}
          value={recipientPubB64}
          onChangeText={setRecipientPubB64}
          placeholder="Paste recipient's public key here"
          placeholderTextColor="#666"
          autoCapitalize="none"
          autoCorrect={false}
          multiline
        />

        <TouchableOpacity style={styles.connectButton} onPress={handleConnect}>
          <Text style={styles.buttonText}>Connect & Start Chat</Text>
        </TouchableOpacity>

        <Text style={styles.hint}>
          Your public key: {toBase64(publicKey)}
        </Text>
      </View>
    );
  }

  return (
    <KeyboardAvoidingView
      style={styles.chatContainer}
      behavior={Platform.OS === "ios" ? "padding" : "height"}
      keyboardVerticalOffset={Platform.OS === "ios" ? 88 : 0}
    >
      <View style={styles.chatHeader}>
        <Text style={styles.chatHeaderText}>
          E2EE Chat — {recipientPubB64.slice(0, 12)}...
        </Text>
        <View style={styles.connectedDot} />
      </View>

      <FlatList
        ref={flatListRef}
        data={messages}
        renderItem={renderMessage}
        keyExtractor={(item) => item.id}
        style={styles.messageList}
        contentContainerStyle={styles.messageListContent}
      />

      <View style={styles.inputBar}>
        <TextInput
          style={styles.chatInput}
          value={draft}
          onChangeText={setDraft}
          placeholder="Type a message..."
          placeholderTextColor="#666"
          returnKeyType="send"
          onSubmitEditing={handleSend}
        />
        <TouchableOpacity style={styles.sendButton} onPress={handleSend}>
          <Text style={styles.sendButtonText}>Send</Text>
        </TouchableOpacity>
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 24,
    backgroundColor: "#1a1a2e",
    justifyContent: "center",
  },
  title: {
    fontSize: 24,
    fontWeight: "bold",
    color: "#e94560",
    marginBottom: 24,
    textAlign: "center",
  },
  label: {
    fontSize: 14,
    color: "#aaa",
    marginBottom: 4,
    marginTop: 12,
  },
  input: {
    backgroundColor: "#16213e",
    color: "#fff",
    padding: 12,
    borderRadius: 8,
    fontSize: 14,
    borderWidth: 1,
    borderColor: "#0f3460",
  },
  keyInput: {
    minHeight: 60,
    fontFamily: "monospace",
    fontSize: 12,
  },
  connectButton: {
    backgroundColor: "#e94560",
    padding: 14,
    borderRadius: 8,
    marginTop: 24,
    alignItems: "center",
  },
  buttonText: {
    color: "#fff",
    fontWeight: "bold",
    fontSize: 16,
  },
  hint: {
    fontSize: 10,
    color: "#555",
    marginTop: 16,
    textAlign: "center",
    fontFamily: "monospace",
  },
  chatContainer: {
    flex: 1,
    backgroundColor: "#1a1a2e",
  },
  chatHeader: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    padding: 12,
    backgroundColor: "#16213e",
    borderBottomWidth: 1,
    borderBottomColor: "#0f3460",
  },
  chatHeaderText: {
    color: "#eee",
    fontSize: 14,
    fontFamily: "monospace",
  },
  connectedDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    backgroundColor: "#4caf50",
    marginLeft: 8,
  },
  messageList: {
    flex: 1,
  },
  messageListContent: {
    padding: 12,
  },
  messageBubble: {
    maxWidth: "80%",
    padding: 10,
    borderRadius: 12,
    marginBottom: 8,
  },
  myMessage: {
    alignSelf: "flex-end",
    backgroundColor: "#e94560",
  },
  theirMessage: {
    alignSelf: "flex-start",
    backgroundColor: "#16213e",
    borderWidth: 1,
    borderColor: "#0f3460",
  },
  messageText: {
    color: "#fff",
    fontSize: 15,
  },
  messageTime: {
    color: "rgba(255,255,255,0.5)",
    fontSize: 10,
    marginTop: 4,
    textAlign: "right",
  },
  inputBar: {
    flexDirection: "row",
    padding: 8,
    backgroundColor: "#16213e",
    borderTopWidth: 1,
    borderTopColor: "#0f3460",
  },
  chatInput: {
    flex: 1,
    backgroundColor: "#0f3460",
    color: "#fff",
    padding: 10,
    borderRadius: 20,
    fontSize: 15,
    marginRight: 8,
  },
  sendButton: {
    backgroundColor: "#e94560",
    paddingHorizontal: 20,
    paddingVertical: 10,
    borderRadius: 20,
    justifyContent: "center",
  },
  sendButtonText: {
    color: "#fff",
    fontWeight: "bold",
  },
});
