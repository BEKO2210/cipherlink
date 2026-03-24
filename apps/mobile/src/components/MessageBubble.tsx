/**
 * Chat message bubble component.
 * @author Belkis Aslani
 */
import React from "react";
import { View, Text, StyleSheet } from "react-native";
import { Colors } from "../theme/colors";

interface MessageBubbleProps {
  text: string;
  sender: "me" | "them";
  timestamp: number;
  encrypted?: boolean;
}

export function MessageBubble({
  text,
  sender,
  timestamp,
  encrypted,
}: MessageBubbleProps) {
  const isMe = sender === "me";

  return (
    <View
      style={[
        styles.bubble,
        isMe ? styles.myBubble : styles.theirBubble,
      ]}
    >
      <Text style={styles.text}>{text}</Text>
      <View style={styles.meta}>
        {encrypted && <Text style={styles.lock}>E2EE</Text>}
        <Text style={styles.time}>
          {new Date(timestamp).toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
          })}
        </Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  bubble: {
    maxWidth: "80%",
    padding: 12,
    borderRadius: 16,
    marginBottom: 6,
  },
  myBubble: {
    alignSelf: "flex-end",
    backgroundColor: Colors.accent,
    borderBottomRightRadius: 4,
  },
  theirBubble: {
    alignSelf: "flex-start",
    backgroundColor: Colors.bgSecondary,
    borderWidth: 1,
    borderColor: Colors.border,
    borderBottomLeftRadius: 4,
  },
  text: {
    color: Colors.textPrimary,
    fontSize: 15,
    lineHeight: 20,
  },
  meta: {
    flexDirection: "row",
    justifyContent: "flex-end",
    alignItems: "center",
    marginTop: 4,
    gap: 6,
  },
  lock: {
    color: "rgba(255,255,255,0.4)",
    fontSize: 9,
    fontWeight: "600",
  },
  time: {
    color: "rgba(255,255,255,0.5)",
    fontSize: 10,
  },
});
