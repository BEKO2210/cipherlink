/**
 * Group chat screen — E2EE group messaging with Sender Keys.
 * Sender key is persisted via ref to survive re-renders (not regenerated each mount).
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
import { toBase64, generateMessageId } from "../lib/crypto";
import {
  generateSenderKey,
  groupEncrypt,
  createSenderKeyDistribution,
} from "../lib/group-crypto";
import type { SenderKey } from "../lib/group-crypto";

interface GroupChatScreenProps {
  groupId: string;
  groupName: string;
}

const MemoizedBubble = memo(MessageBubble);

/** Persist sender keys across mounts by groupId */
const senderKeyCache = new Map<string, SenderKey>();

export function GroupChatScreen({ groupId, groupName }: GroupChatScreenProps) {
  const {
    identity,
    client,
    goBack,
    groups,
    chatMessages,
    addChatMessage,
    connected,
  } = useApp();

  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [draft, setDraft] = useState("");
  const senderKeyRef = useRef<SenderKey | null>(senderKeyCache.get(groupId) ?? null);
  const flatListRef = useRef<FlatList>(null);

  const group = groups.find((g) => g.id === groupId);

  // Initialize or restore sender key
  useEffect(() => {
    if (senderKeyRef.current) return; // Already have a key

    (async () => {
      const key = await generateSenderKey(groupId);
      senderKeyRef.current = key;
      senderKeyCache.set(groupId, key);

      // Distribute to group members
      if (identity && client?.connected && group) {
        createSenderKeyDistribution(key, groupId, identity.dh.publicKey);
      }
    })();
  }, [groupId, identity, client, group]);

  // Load existing messages from context
  useEffect(() => {
    const key = `group:${groupId}`;
    const existing = chatMessages.get(key) ?? [];
    setMessages(existing);
  }, [groupId, chatMessages]);

  useEffect(() => {
    if (messages.length > 0) {
      requestAnimationFrame(() => {
        flatListRef.current?.scrollToEnd({ animated: true });
      });
    }
  }, [messages.length]);

  const handleSend = useCallback(async () => {
    if (!draft.trim() || !client?.connected || !identity || !senderKeyRef.current || !group)
      return;

    try {
      const { message, updatedKey } = await groupEncrypt(
        senderKeyRef.current,
        groupId,
        draft.trim(),
      );
      senderKeyRef.current = updatedKey;
      senderKeyCache.set(groupId, updatedKey);

      const recipients = group.members.filter(
        (m) => m !== toBase64(identity.dh.publicKey),
      );
      client.sendGroup(groupId, message, recipients);

      const chatMsg: ChatMessage = {
        id: generateMessageId(),
        text: draft.trim(),
        sender: "me",
        timestamp: Date.now(),
        encrypted: true,
      };
      addChatMessage(`group:${groupId}`, chatMsg);
      setDraft("");
    } catch {
      Alert.alert("Error", "Failed to encrypt group message");
    }
  }, [draft, groupId, identity, client, group, addChatMessage]);

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
            {groupName}
          </Text>
          <Text style={styles.memberCount}>
            {group?.members.length ?? 0} members
          </Text>
        </View>
        <View style={styles.headerRight}>
          <View
            style={[
              styles.connectionDot,
              { backgroundColor: connected ? Colors.success : Colors.error },
            ]}
          />
          <EncryptionBadge compact sealed />
        </View>
      </View>

      {/* Group E2EE info */}
      <View style={styles.e2eeBanner}>
        <Text style={styles.e2eeText}>
          Group messages use Sender Keys with Ed25519 signatures.
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
          placeholder="Group message..."
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
  },
  headerName: {
    color: Colors.textPrimary,
    fontSize: 17,
    fontWeight: "600",
  },
  memberCount: {
    color: Colors.textMuted,
    fontSize: 12,
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
  e2eeBanner: {
    backgroundColor: "rgba(124, 77, 255, 0.06)",
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
