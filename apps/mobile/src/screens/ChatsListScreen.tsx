/**
 * Chats list screen — shows all conversations with contacts.
 * @author Belkis Aslani
 */
import React from "react";
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  FlatList,
} from "react-native";
import { Colors } from "../theme/colors";
import { useApp } from "../context/AppContext";
import { ChatListItem } from "../components/ChatListItem";
import { EncryptionBadge } from "../components/EncryptionBadge";

export function ChatsListScreen() {
  const { contacts, navigate, connected, chatMessages } = useApp();

  const getLastMessage = (publicKey: string): { text: string; ts: number } | null => {
    const msgs = chatMessages.get(publicKey);
    if (!msgs || msgs.length === 0) return null;
    const last = msgs[msgs.length - 1]!;
    return { text: last.text || "Encrypted message", ts: last.timestamp };
  };

  return (
    <View style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.headerTitle}>CipherLink</Text>
        <View style={styles.headerRight}>
          <View
            style={[
              styles.connectionDot,
              { backgroundColor: connected ? Colors.success : Colors.error },
            ]}
          />
          <TouchableOpacity
            style={styles.newChatButton}
            onPress={() => navigate({ name: "newChat" })}
          >
            <Text style={styles.newChatText}>+ New</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* Encryption status bar */}
      <View style={styles.encryptionBar}>
        <EncryptionBadge sealed quantum />
        <Text style={styles.encryptionText}>
          All messages are end-to-end encrypted
        </Text>
      </View>

      {/* Chat list */}
      {contacts.length === 0 ? (
        <View style={styles.empty}>
          <Text style={styles.emptyIcon}>{"{ }"}</Text>
          <Text style={styles.emptyTitle}>No Conversations Yet</Text>
          <Text style={styles.emptySubtitle}>
            Add a contact to start an encrypted chat.{"\n"}
            Messages are protected with Signal Protocol encryption.
          </Text>
          <TouchableOpacity
            style={styles.emptyButton}
            onPress={() => navigate({ name: "newChat" })}
          >
            <Text style={styles.emptyButtonText}>Start New Chat</Text>
          </TouchableOpacity>
        </View>
      ) : (
        <FlatList
          data={contacts}
          keyExtractor={(item) => item.publicKey}
          renderItem={({ item }) => {
            const lastMsg = getLastMessage(item.publicKey);
            return (
              <ChatListItem
                name={item.name}
                lastMessage={lastMsg?.text}
                timestamp={lastMsg?.ts}
                verified={item.verified}
                onPress={() =>
                  navigate({
                    name: "chat",
                    contactKey: item.publicKey,
                    contactName: item.name,
                  })
                }
                onLongPress={() =>
                  navigate({
                    name: "safetyNumber",
                    contactKey: item.publicKey,
                    contactName: item.name,
                  })
                }
              />
            );
          }}
          contentContainerStyle={styles.listContent}
        />
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: Colors.bg,
  },
  header: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingHorizontal: 20,
    paddingTop: 16,
    paddingBottom: 12,
    backgroundColor: Colors.bgPrimary,
    borderBottomWidth: 1,
    borderBottomColor: Colors.border,
  },
  headerTitle: {
    fontSize: 24,
    fontWeight: "bold",
    color: Colors.accent,
  },
  headerRight: {
    flexDirection: "row",
    alignItems: "center",
    gap: 12,
  },
  connectionDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
  },
  newChatButton: {
    backgroundColor: Colors.accent,
    paddingHorizontal: 14,
    paddingVertical: 8,
    borderRadius: 8,
  },
  newChatText: {
    color: "#fff",
    fontWeight: "600",
    fontSize: 13,
  },
  encryptionBar: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 20,
    paddingVertical: 8,
    backgroundColor: "rgba(76, 175, 80, 0.08)",
    gap: 8,
  },
  encryptionText: {
    color: Colors.encrypted,
    fontSize: 11,
  },
  listContent: {
    paddingBottom: 100,
  },
  empty: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
    paddingHorizontal: 40,
  },
  emptyIcon: {
    fontSize: 48,
    color: Colors.textDim,
    marginBottom: 16,
    fontFamily: "monospace",
  },
  emptyTitle: {
    fontSize: 20,
    fontWeight: "bold",
    color: Colors.textPrimary,
    marginBottom: 8,
  },
  emptySubtitle: {
    fontSize: 14,
    color: Colors.textMuted,
    textAlign: "center",
    lineHeight: 20,
    marginBottom: 24,
  },
  emptyButton: {
    backgroundColor: Colors.accent,
    paddingHorizontal: 24,
    paddingVertical: 12,
    borderRadius: 10,
  },
  emptyButtonText: {
    color: "#fff",
    fontWeight: "bold",
    fontSize: 15,
  },
});
