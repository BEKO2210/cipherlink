/**
 * Encryption status badge — shows E2EE, sealed sender, and quantum status.
 * @author Belkis Aslani
 */
import React from "react";
import { View, Text, StyleSheet } from "react-native";
import { Colors } from "../theme/colors";

interface EncryptionBadgeProps {
  sealed?: boolean;
  quantum?: boolean;
  compact?: boolean;
}

export function EncryptionBadge({
  sealed,
  quantum,
  compact,
}: EncryptionBadgeProps) {
  if (compact) {
    return (
      <View style={styles.compactRow}>
        <View style={[styles.dot, { backgroundColor: Colors.encrypted }]} />
        {sealed && (
          <View style={[styles.dot, { backgroundColor: Colors.sealed }]} />
        )}
        {quantum && (
          <View style={[styles.dot, { backgroundColor: Colors.quantum }]} />
        )}
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <View style={styles.badge}>
        <View
          style={[styles.indicator, { backgroundColor: Colors.encrypted }]}
        />
        <Text style={styles.text}>E2EE</Text>
      </View>
      {sealed && (
        <View style={styles.badge}>
          <View
            style={[styles.indicator, { backgroundColor: Colors.sealed }]}
          />
          <Text style={styles.text}>Sealed</Text>
        </View>
      )}
      {quantum && (
        <View style={styles.badge}>
          <View
            style={[styles.indicator, { backgroundColor: Colors.quantum }]}
          />
          <Text style={styles.text}>PQ</Text>
        </View>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flexDirection: "row",
    gap: 6,
  },
  badge: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "rgba(255,255,255,0.08)",
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 10,
    gap: 4,
  },
  indicator: {
    width: 6,
    height: 6,
    borderRadius: 3,
  },
  text: {
    color: Colors.textSecondary,
    fontSize: 10,
    fontWeight: "600",
  },
  compactRow: {
    flexDirection: "row",
    gap: 3,
    alignItems: "center",
  },
  dot: {
    width: 5,
    height: 5,
    borderRadius: 2.5,
  },
});
