/**
 * Chat screen — 1:1 E2EE messaging with a contact.
 * Messages are handled via onRawMessage subscription (no duplicate handlers).
 * @author Belkis Aslani
 */
import React, { useState, useCallback, useRef, useEffect, memo } from "react";
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
import { Colors } from "../theme/colors";
import { useApp } from "../context/AppContext";
import type { ChatMessage } from "../context/AppContext";
import { MessageBubble } from "../components/MessageBubble";
import { EncryptionBadge } from "../components/EncryptionBadge";
import {
  fromBase64,
  encryptMessage,
  decryptMessage,
  generateMessageId,
} from "../lib/crypto";
import type { ServerMessage } from "../lib/ws-client";

interface ChatScreenProps {
  contactKey: string;
  contactName: string;
}

/** Memoized message bubble to prevent re-renders of entire list */
const MemoizedBubble = memo(MessageBubble);

export function ChatScreen({ contactKey, contactName }: ChatScreenProps) {
  const {
    identity,
    client,
    connected,
    goBack,
    navigate,
    settings,
    addChatMessage,
    chatMessages,
    onRawMessage,
  } = useApp();

  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [draft, setDraft] = useState("");
  const flatListRef = useRef<FlatList>(null);

  // Load existing messages from context
  useEffect(() => {
    const existing = chatMessages.get(contactKey) ?? [];
    setMessages(existing);
  }, [contactKey, chatMessages]);

  // Subscribe to raw server messages for decryption (single handler, proper cleanup)
  useEffect(() => {
    if (!identity) return;

    const unsubscribe = onRawMessage(async (msg: ServerMessage) => {
      if (msg.type === "message") {
        const envelope = msg.envelope;
        if (envelope.senderPub === contactKey) {
          try {
            const senderPub = fromBase64(envelope.senderPub);
            const plaintext = await decryptMessage(
              identity.dh.privateKey,
              senderPub,
              envelope,
            );
            const chatMsg: ChatMessage = {
              id: envelope.msgId,
              text: plaintext,
              sender: "them",
              timestamp: envelope.ts,
              encrypted: true,
            };
            addChatMessage(contactKey, chatMsg);
          } catch {
            // Decryption may fail if key mismatch
          }
        }
      }
    });

    return unsubscribe;
  }, [identity, contactKey, onRawMessage, addChatMessage]);

  // Auto-scroll on new messages
  useEffect(() => {
    if (messages.length > 0) {
      requestAnimationFrame(() => {
        flatListRef.current?.scrollToEnd({ animated: true });
      });
    }
  }, [messages.length]);

  const handleSend = useCallback(async () => {
    if (!draft.trim() || !client?.connected || !identity) return;

    try {
      const recipientPub = fromBase64(contactKey);
      const envelope = await encryptMessage(
        identity.dh.privateKey,
        identity.dh.publicKey,
        recipientPub,
        draft.trim(),
      );
      client.send(envelope);

      const chatMsg: ChatMessage = {
        id: generateMessageId(),
        text: draft.trim(),
        sender: "me",
        timestamp: Date.now(),
        encrypted: true,
        sealed: settings.sealedSender,
      };
      addChatMessage(contactKey, chatMsg);
      setDraft("");
    } catch {
      Alert.alert("Error", "Failed to encrypt and send message");
    }
  }, [draft, contactKey, identity, client, settings.sealedSender, addChatMessage]);

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === "ios" ? "padding" : undefined}
      keyboardVerticalOffset={Platform.OS === "ios" ? 88 : 0}
    >
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity onPress={goBack} style={styles.backButton}>
          <Text style={styles.backText}>{"<"}</Text>
        </TouchableOpacity>
        <View style={styles.headerCenter}>
          <Text style={styles.headerName} numberOfLines={1}>
            {contactName}
          </Text>
          <EncryptionBadge
            compact
            sealed={settings.sealedSender}
            quantum={settings.quantumResistant}
          />
        </View>
        <View style={styles.headerRight}>
          <View
            style={[
              styles.connectionDot,
              {
                backgroundColor: connected ? Colors.success : Colors.error,
              },
            ]}
          />
          <TouchableOpacity
            onPress={() =>
              navigate({
                name: "safetyNumber",
                contactKey,
                contactName,
              })
            }
          >
            <Text style={styles.verifyButton}>Verify</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* E2EE Banner */}
      <View style={styles.e2eeBanner}>
        <Text style={styles.e2eeText}>
          Messages are end-to-end encrypted. No one outside this chat can read
          them.
        </Text>
      </View>

      {/* Messages */}
      <FlatList
        ref={flatListRef}
        data={messages}
        renderItem={({ item }) => (
          <MemoizedBubble
            text={item.text}
            sender={item.sender}
            timestamp={item.timestamp}
            encrypted={item.encrypted}
          />
        )}
        keyExtractor={(item) => item.id}
        style={styles.messageList}
        contentContainerStyle={styles.messageListContent}
        removeClippedSubviews={Platform.OS === "android"}
        initialNumToRender={20}
        maxToRenderPerBatch={10}
        windowSize={11}
      />

      {/* Input */}
      <View style={styles.inputBar}>
        <TextInput
          style={styles.input}
          value={draft}
          onChangeText={setDraft}
          placeholder="Encrypted message..."
          placeholderTextColor={Colors.textDim}
          returnKeyType="send"
          onSubmitEditing={handleSend}
          multiline
          maxLength={4000}
        />
        <TouchableOpacity
          style={[
            styles.sendButton,
            !draft.trim() && styles.sendButtonDisabled,
          ]}
          onPress={handleSend}
          disabled={!draft.trim()}
        >
          <Text style={styles.sendText}>Send</Text>
        </TouchableOpacity>
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: Colors.bg,
  },
  header: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 12,
    paddingVertical: 12,
    backgroundColor: Colors.bgPrimary,
    borderBottomWidth: 1,
    borderBottomColor: Colors.border,
  },
  backButton: {
    padding: 8,
    marginRight: 4,
  },
  backText: {
    color: Colors.accent,
    fontSize: 22,
    fontWeight: "bold",
  },
  headerCenter: {
    flex: 1,
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
  },
  headerName: {
    color: Colors.textPrimary,
    fontSize: 17,
    fontWeight: "600",
    maxWidth: "60%",
  },
  headerRight: {
    flexDirection: "row",
    alignItems: "center",
    gap: 10,
  },
  connectionDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
  },
  verifyButton: {
    color: Colors.success,
    fontSize: 13,
    fontWeight: "600",
  },
  e2eeBanner: {
    backgroundColor: "rgba(76, 175, 80, 0.06)",
    paddingHorizontal: 16,
    paddingVertical: 6,
    alignItems: "center",
  },
  e2eeText: {
    color: Colors.textDim,
    fontSize: 11,
    textAlign: "center",
  },
  messageList: {
    flex: 1,
  },
  messageListContent: {
    padding: 12,
    paddingBottom: 8,
  },
  inputBar: {
    flexDirection: "row",
    padding: 8,
    backgroundColor: Colors.bgPrimary,
    borderTopWidth: 1,
    borderTopColor: Colors.border,
    alignItems: "flex-end",
  },
  input: {
    flex: 1,
    backgroundColor: Colors.bgCard,
    color: Colors.textPrimary,
    padding: 12,
    borderRadius: 20,
    fontSize: 15,
    marginRight: 8,
    maxHeight: 100,
  },
  sendButton: {
    backgroundColor: Colors.accent,
    paddingHorizontal: 20,
    paddingVertical: 12,
    borderRadius: 20,
  },
  sendButtonDisabled: {
    opacity: 0.4,
  },
  sendText: {
    color: "#fff",
    fontWeight: "bold",
    fontSize: 14,
  },
});
