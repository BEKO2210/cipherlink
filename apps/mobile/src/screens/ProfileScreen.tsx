/**
 * Profile screen — identity info, public key, and security status.
 * @author Belkis Aslani
 */
import React, { useState } from "react";
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  Alert,
  ScrollView,
} from "react-native";
import * as Clipboard from "expo-clipboard";
import { Colors } from "../theme/colors";
import { useApp } from "../context/AppContext";
import { toBase64 } from "../lib/crypto";
import { EncryptionBadge } from "../components/EncryptionBadge";

export function ProfileScreen() {
  const {
    identity,
    displayName,
    setDisplayName,
    navigate,
    connected,
    contacts,
    groups,
    settings,
  } = useApp();

  const [editing, setEditing] = useState(false);
  const [nameInput, setNameInput] = useState(displayName);

  const publicKeyB64 = identity ? toBase64(identity.dh.publicKey) : "—";
  const signingKeyB64 = identity ? toBase64(identity.signing.publicKey) : "—";

  const handleCopyKey = async () => {
    await Clipboard.setStringAsync(publicKeyB64);
    Alert.alert("Copied", "Public key copied to clipboard");
  };

  const handleSaveName = async () => {
    await setDisplayName(nameInput.trim() || "Anonymous");
    setEditing(false);
  };

  return (
    <ScrollView contentContainerStyle={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Security</Text>
      </View>

      {/* Identity card */}
      <View style={styles.card}>
        <View style={styles.avatar}>
          <Text style={styles.avatarText}>
            {displayName.charAt(0).toUpperCase()}
          </Text>
        </View>

        {editing ? (
          <View style={styles.editRow}>
            <TextInput
              style={styles.nameInput}
              value={nameInput}
              onChangeText={setNameInput}
              autoFocus
              returnKeyType="done"
              onSubmitEditing={handleSaveName}
            />
            <TouchableOpacity onPress={handleSaveName}>
              <Text style={styles.saveText}>Save</Text>
            </TouchableOpacity>
          </View>
        ) : (
          <TouchableOpacity onPress={() => setEditing(true)}>
            <Text style={styles.displayName}>{displayName}</Text>
            <Text style={styles.editHint}>Tap to edit</Text>
          </TouchableOpacity>
        )}

        <View style={styles.statusRow}>
          <View
            style={[
              styles.statusDot,
              {
                backgroundColor: connected
                  ? Colors.success
                  : Colors.error,
              },
            ]}
          />
          <Text style={styles.statusText}>
            {connected ? "Connected" : "Disconnected"}
          </Text>
        </View>
      </View>

      {/* Encryption Status */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Encryption Status</Text>
        <View style={styles.encryptionRow}>
          <EncryptionBadge
            sealed={settings.sealedSender}
            quantum={settings.quantumResistant}
          />
        </View>
        <View style={styles.featureList}>
          <FeatureRow label="E2EE" value="XChaCha20-Poly1305" active />
          <FeatureRow
            label="Sealed Sender"
            value={settings.sealedSender ? "Active" : "Off"}
            active={settings.sealedSender}
          />
          <FeatureRow
            label="Post-Quantum"
            value="X25519 + ML-KEM-768"
            active={settings.quantumResistant}
          />
          <FeatureRow label="Message Padding" value="256-byte PKCS7" active />
          <FeatureRow label="Key Derivation" value="HKDF-SHA256" active />
          <FeatureRow
            label="Replay Protection"
            value="Dedup + Monotonic"
            active
          />
        </View>
      </View>

      {/* Public keys */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Your Public Keys</Text>

        <Text style={styles.keyLabel}>DH Public Key (X25519)</Text>
        <TouchableOpacity onPress={handleCopyKey}>
          <Text style={styles.keyValue} selectable>
            {publicKeyB64}
          </Text>
        </TouchableOpacity>
        <Text style={styles.keyHint}>Tap to copy — share with contacts</Text>

        <Text style={[styles.keyLabel, { marginTop: 16 }]}>
          Signing Key (Ed25519)
        </Text>
        <Text style={styles.keyValue} selectable>
          {signingKeyB64}
        </Text>
      </View>

      {/* Stats */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Statistics</Text>
        <View style={styles.statsGrid}>
          <StatBox
            label="Contacts"
            value={contacts.length.toString()}
          />
          <StatBox
            label="Verified"
            value={contacts
              .filter((c) => c.verified)
              .length.toString()}
          />
          <StatBox label="Groups" value={groups.length.toString()} />
        </View>
      </View>

      {/* Quick actions */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Security Actions</Text>
        <TouchableOpacity
          style={styles.actionButton}
          onPress={() => navigate({ name: "backup" })}
        >
          <Text style={styles.actionText}>Encrypted Backup</Text>
          <Text style={styles.actionDesc}>
            Argon2id + Shamir key splitting
          </Text>
        </TouchableOpacity>
      </View>

      {/* Protocol info */}
      <View style={styles.protocolInfo}>
        <Text style={styles.protocolTitle}>Signal Protocol Architecture</Text>
        <Text style={styles.protocolText}>
          X3DH key agreement + Double Ratchet{"\n"}
          Forward secrecy + Post-compromise security{"\n"}
          Zero-knowledge relay server{"\n"}
          156 automated security tests
        </Text>
      </View>
    </ScrollView>
  );
}

function FeatureRow({
  label,
  value,
  active,
}: {
  label: string;
  value: string;
  active: boolean;
}) {
  return (
    <View style={fStyles.row}>
      <View style={fStyles.labelRow}>
        <View
          style={[
            fStyles.dot,
            { backgroundColor: active ? Colors.success : Colors.textDim },
          ]}
        />
        <Text style={fStyles.label}>{label}</Text>
      </View>
      <Text
        style={[
          fStyles.value,
          { color: active ? Colors.textSecondary : Colors.textDim },
        ]}
      >
        {value}
      </Text>
    </View>
  );
}

function StatBox({ label, value }: { label: string; value: string }) {
  return (
    <View style={sStyles.box}>
      <Text style={sStyles.value}>{value}</Text>
      <Text style={sStyles.label}>{label}</Text>
    </View>
  );
}

const fStyles = StyleSheet.create({
  row: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingVertical: 8,
    borderBottomWidth: 1,
    borderBottomColor: "rgba(255,255,255,0.03)",
  },
  labelRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
  },
  dot: {
    width: 6,
    height: 6,
    borderRadius: 3,
  },
  label: {
    color: Colors.textSecondary,
    fontSize: 13,
  },
  value: {
    fontSize: 12,
    fontFamily: "monospace",
  },
});

const sStyles = StyleSheet.create({
  box: {
    flex: 1,
    alignItems: "center",
    padding: 16,
    backgroundColor: Colors.bgSecondary,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  value: {
    color: Colors.accent,
    fontSize: 28,
    fontWeight: "bold",
  },
  label: {
    color: Colors.textMuted,
    fontSize: 12,
    marginTop: 4,
  },
});

const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    backgroundColor: Colors.bg,
    paddingBottom: 40,
  },
  header: {
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
  card: {
    alignItems: "center",
    padding: 24,
    borderBottomWidth: 1,
    borderBottomColor: "rgba(255,255,255,0.05)",
  },
  avatar: {
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: Colors.accent,
    justifyContent: "center",
    alignItems: "center",
    marginBottom: 12,
  },
  avatarText: {
    color: "#fff",
    fontSize: 32,
    fontWeight: "bold",
  },
  displayName: {
    color: Colors.textPrimary,
    fontSize: 22,
    fontWeight: "bold",
    textAlign: "center",
  },
  editHint: {
    color: Colors.textDim,
    fontSize: 11,
    textAlign: "center",
    marginTop: 2,
  },
  editRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: 12,
  },
  nameInput: {
    backgroundColor: Colors.bgSecondary,
    color: Colors.textPrimary,
    padding: 10,
    borderRadius: 8,
    fontSize: 16,
    minWidth: 150,
    borderWidth: 1,
    borderColor: Colors.accent,
  },
  saveText: {
    color: Colors.accent,
    fontSize: 15,
    fontWeight: "bold",
  },
  statusRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: 6,
    marginTop: 8,
  },
  statusDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
  },
  statusText: {
    color: Colors.textMuted,
    fontSize: 13,
  },
  section: {
    padding: 20,
    borderBottomWidth: 1,
    borderBottomColor: "rgba(255,255,255,0.05)",
  },
  sectionTitle: {
    color: Colors.textPrimary,
    fontSize: 16,
    fontWeight: "bold",
    marginBottom: 12,
  },
  encryptionRow: {
    marginBottom: 12,
  },
  featureList: {
    backgroundColor: Colors.bgSecondary,
    borderRadius: 12,
    padding: 12,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  keyLabel: {
    color: Colors.textMuted,
    fontSize: 12,
    marginBottom: 6,
  },
  keyValue: {
    color: Colors.textSecondary,
    fontSize: 11,
    fontFamily: "monospace",
    backgroundColor: Colors.bgSecondary,
    padding: 12,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  keyHint: {
    color: Colors.textDim,
    fontSize: 10,
    marginTop: 4,
    textAlign: "center",
  },
  statsGrid: {
    flexDirection: "row",
    gap: 10,
  },
  actionButton: {
    backgroundColor: Colors.bgSecondary,
    padding: 16,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  actionText: {
    color: Colors.textPrimary,
    fontSize: 15,
    fontWeight: "600",
  },
  actionDesc: {
    color: Colors.textMuted,
    fontSize: 12,
    marginTop: 2,
  },
  protocolInfo: {
    padding: 20,
    alignItems: "center",
  },
  protocolTitle: {
    color: Colors.textDim,
    fontSize: 12,
    fontWeight: "600",
    marginBottom: 6,
  },
  protocolText: {
    color: Colors.textDim,
    fontSize: 11,
    textAlign: "center",
    lineHeight: 18,
  },
});
