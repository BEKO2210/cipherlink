/**
 * Chat list item for the chats/groups screens.
 * @author Belkis Aslani
 */
import React from "react";
import { View, Text, TouchableOpacity, StyleSheet } from "react-native";
import { Colors } from "../theme/colors";
import { EncryptionBadge } from "./EncryptionBadge";

interface ChatListItemProps {
  name: string;
  lastMessage?: string;
  timestamp?: number;
  unread?: number;
  verified?: boolean;
  isGroup?: boolean;
  onPress: () => void;
  onLongPress?: () => void;
}

export function ChatListItem({
  name,
  lastMessage,
  timestamp,
  unread,
  verified,
  isGroup,
  onPress,
  onLongPress,
}: ChatListItemProps) {
  return (
    <TouchableOpacity
      style={styles.container}
      onPress={onPress}
      onLongPress={onLongPress}
      activeOpacity={0.7}
    >
      {/* Avatar */}
      <View style={[styles.avatar, isGroup && styles.groupAvatar]}>
        <Text style={styles.avatarText}>
          {isGroup ? name.slice(0, 2).toUpperCase() : name.charAt(0).toUpperCase()}
        </Text>
        {verified && <View style={styles.verifiedDot} />}
      </View>

      {/* Content */}
      <View style={styles.content}>
        <View style={styles.topRow}>
          <Text style={styles.name} numberOfLines={1}>
            {name}
          </Text>
          <View style={styles.topRight}>
            <EncryptionBadge compact sealed />
            {timestamp != null && (
              <Text style={styles.time}>
                {formatTime(timestamp)}
              </Text>
            )}
          </View>
        </View>
        {lastMessage && (
          <Text style={styles.preview} numberOfLines={1}>
            {lastMessage}
          </Text>
        )}
      </View>

      {/* Unread badge */}
      {unread != null && unread > 0 ? (
        <View style={styles.unreadBadge}>
          <Text style={styles.unreadText}>{unread}</Text>
        </View>
      ) : null}
    </TouchableOpacity>
  );
}

function formatTime(ts: number): string {
  const now = Date.now();
  const diff = now - ts;
  if (diff < 60_000) return "now";
  if (diff < 3600_000)
    return `${Math.floor(diff / 60_000)}m`;
  if (diff < 86400_000)
    return new Date(ts).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });
  return new Date(ts).toLocaleDateString([], {
    month: "short",
    day: "numeric",
  });
}

const styles = StyleSheet.create({
  container: {
    flexDirection: "row",
    alignItems: "center",
    padding: 14,
    borderBottomWidth: 1,
    borderBottomColor: "rgba(255,255,255,0.05)",
  },
  avatar: {
    width: 48,
    height: 48,
    borderRadius: 24,
    backgroundColor: Colors.accent,
    justifyContent: "center",
    alignItems: "center",
    marginRight: 12,
  },
  groupAvatar: {
    backgroundColor: Colors.bgCard,
    borderWidth: 1,
    borderColor: Colors.accent,
  },
  avatarText: {
    color: Colors.textPrimary,
    fontSize: 18,
    fontWeight: "bold",
  },
  verifiedDot: {
    position: "absolute",
    bottom: 0,
    right: 0,
    width: 14,
    height: 14,
    borderRadius: 7,
    backgroundColor: Colors.success,
    borderWidth: 2,
    borderColor: Colors.bgPrimary,
  },
  content: {
    flex: 1,
  },
  topRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 3,
  },
  topRight: {
    flexDirection: "row",
    alignItems: "center",
    gap: 6,
  },
  name: {
    color: Colors.textPrimary,
    fontSize: 16,
    fontWeight: "600",
    flex: 1,
    marginRight: 8,
  },
  time: {
    color: Colors.textMuted,
    fontSize: 11,
  },
  preview: {
    color: Colors.textMuted,
    fontSize: 13,
  },
  unreadBadge: {
    backgroundColor: Colors.accent,
    borderRadius: 10,
    minWidth: 20,
    height: 20,
    justifyContent: "center",
    alignItems: "center",
    paddingHorizontal: 6,
    marginLeft: 8,
  },
  unreadText: {
    color: Colors.textPrimary,
    fontSize: 11,
    fontWeight: "bold",
  },
});
