/**
 * Settings screen — server URL, encryption options, and account management.
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
  Switch,
} from "react-native";
import { Colors } from "../theme/colors";
import { useApp } from "../context/AppContext";

export function SettingsScreen() {
  const {
    settings,
    updateSettings,
    connected,
    connectToServer,
    disconnectFromServer,
    navigate,
    resetIdentity,
  } = useApp();

  const [serverUrl, setServerUrl] = useState(settings.serverUrl);
  const [editingUrl, setEditingUrl] = useState(false);

  const handleSaveUrl = async () => {
    await updateSettings({ serverUrl: serverUrl.trim() });
    setEditingUrl(false);
  };

  const handleResetIdentity = () => {
    Alert.alert(
      "Reset Identity",
      "This will delete your identity keypair, contacts, and groups. This action cannot be undone.",
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Delete Everything",
          style: "destructive",
          onPress: async () => {
            await resetIdentity();
          },
        },
      ],
    );
  };

  return (
    <ScrollView contentContainerStyle={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Settings</Text>
      </View>

      {/* Connection */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Server Connection</Text>

        <View style={styles.row}>
          <Text style={styles.label}>Status</Text>
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
            <Text
              style={[
                styles.statusText,
                {
                  color: connected ? Colors.success : Colors.error,
                },
              ]}
            >
              {connected ? "Connected" : "Disconnected"}
            </Text>
          </View>
        </View>

        <Text style={styles.label}>Relay Server URL</Text>
        {editingUrl ? (
          <View style={styles.editRow}>
            <TextInput
              style={styles.input}
              value={serverUrl}
              onChangeText={setServerUrl}
              autoCapitalize="none"
              autoCorrect={false}
              placeholder="ws://localhost:4200"
              placeholderTextColor={Colors.textDim}
            />
            <TouchableOpacity
              style={styles.saveButton}
              onPress={handleSaveUrl}
            >
              <Text style={styles.saveText}>Save</Text>
            </TouchableOpacity>
          </View>
        ) : (
          <TouchableOpacity onPress={() => setEditingUrl(true)}>
            <Text style={styles.urlValue}>{settings.serverUrl}</Text>
            <Text style={styles.tapHint}>Tap to edit</Text>
          </TouchableOpacity>
        )}

        <View style={styles.buttonRow}>
          <TouchableOpacity
            style={[
              styles.connectButton,
              connected && styles.disconnectButton,
            ]}
            onPress={connected ? disconnectFromServer : connectToServer}
          >
            <Text style={styles.connectText}>
              {connected ? "Disconnect" : "Connect"}
            </Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* Encryption settings */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Encryption</Text>

        <View style={styles.settingRow}>
          <View style={styles.settingInfo}>
            <Text style={styles.settingLabel}>Sealed Sender</Text>
            <Text style={styles.settingDesc}>
              Hide your identity from the relay server
            </Text>
          </View>
          <Switch
            value={settings.sealedSender}
            onValueChange={(v) => updateSettings({ sealedSender: v })}
            trackColor={{ false: Colors.bgCard, true: Colors.sealed }}
            thumbColor={settings.sealedSender ? "#fff" : Colors.textMuted}
          />
        </View>

        <View style={styles.settingRow}>
          <View style={styles.settingInfo}>
            <Text style={styles.settingLabel}>Quantum-Resistant</Text>
            <Text style={styles.settingDesc}>
              Hybrid X25519 + ML-KEM-768 key encapsulation
            </Text>
          </View>
          <Switch
            value={settings.quantumResistant}
            onValueChange={(v) => updateSettings({ quantumResistant: v })}
            trackColor={{ false: Colors.bgCard, true: Colors.quantum }}
            thumbColor={
              settings.quantumResistant ? "#fff" : Colors.textMuted
            }
          />
        </View>

        <View style={styles.settingRow}>
          <View style={styles.settingInfo}>
            <Text style={styles.settingLabel}>Message Padding</Text>
            <Text style={styles.settingDesc}>
              PKCS7 256-byte blocks prevent length analysis
            </Text>
          </View>
          <Switch
            value={settings.messagePadding}
            onValueChange={(v) => updateSettings({ messagePadding: v })}
            trackColor={{ false: Colors.bgCard, true: Colors.success }}
            thumbColor={
              settings.messagePadding ? "#fff" : Colors.textMuted
            }
          />
        </View>
      </View>

      {/* Security Actions */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Security</Text>

        <TouchableOpacity
          style={styles.actionButton}
          onPress={() => navigate({ name: "backup" })}
        >
          <Text style={styles.actionText}>Encrypted Backup & Restore</Text>
          <Text style={styles.actionDesc}>
            Argon2id KDF + Shamir's Secret Sharing (2-of-3)
          </Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.actionButton}
          onPress={() => navigate({ name: "profile" })}
        >
          <Text style={styles.actionText}>View Public Keys</Text>
          <Text style={styles.actionDesc}>
            DH (X25519) and Signing (Ed25519) keys
          </Text>
        </TouchableOpacity>
      </View>

      {/* About */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>About</Text>
        <View style={styles.aboutGrid}>
          <AboutRow label="Version" value="1.0.0" />
          <AboutRow label="Protocol" value="Signal Protocol (v3)" />
          <AboutRow label="Encryption" value="XChaCha20-Poly1305" />
          <AboutRow label="Key Exchange" value="X3DH + HKDF-SHA256" />
          <AboutRow label="Signatures" value="Ed25519" />
          <AboutRow label="Ratchet" value="Double Ratchet" />
          <AboutRow label="Groups" value="Sender Keys + TreeKEM" />
          <AboutRow label="PQ KEM" value="ML-KEM-768 (Kyber)" />
          <AboutRow label="Backup KDF" value="Argon2id" />
          <AboutRow label="Key Splitting" value="Shamir 2-of-3" />
          <AboutRow label="Tests" value="156 passing" />
          <AboutRow label="License" value="MIT" />
        </View>
      </View>

      {/* Danger zone */}
      <View style={styles.dangerSection}>
        <Text style={styles.dangerTitle}>Danger Zone</Text>
        <TouchableOpacity
          style={styles.dangerButton}
          onPress={handleResetIdentity}
        >
          <Text style={styles.dangerText}>Reset Identity & Delete All Data</Text>
        </TouchableOpacity>
      </View>

      <Text style={styles.footer}>
        CipherLink — by Belkis Aslani{"\n"}
        Open Source (MIT) — github.com/BEKO2210/cipherlink
      </Text>
    </ScrollView>
  );
}

function AboutRow({ label, value }: { label: string; value: string }) {
  return (
    <View style={aStyles.row}>
      <Text style={aStyles.label}>{label}</Text>
      <Text style={aStyles.value}>{value}</Text>
    </View>
  );
}

const aStyles = StyleSheet.create({
  row: {
    flexDirection: "row",
    justifyContent: "space-between",
    paddingVertical: 7,
    borderBottomWidth: 1,
    borderBottomColor: "rgba(255,255,255,0.03)",
  },
  label: {
    color: Colors.textMuted,
    fontSize: 13,
  },
  value: {
    color: Colors.textSecondary,
    fontSize: 13,
    fontFamily: "monospace",
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
  section: {
    padding: 20,
    borderBottomWidth: 1,
    borderBottomColor: "rgba(255,255,255,0.05)",
  },
  sectionTitle: {
    color: Colors.textPrimary,
    fontSize: 16,
    fontWeight: "bold",
    marginBottom: 14,
  },
  row: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 16,
  },
  label: {
    color: Colors.textSecondary,
    fontSize: 13,
    marginBottom: 6,
  },
  statusRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: 6,
  },
  statusDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
  },
  statusText: {
    fontSize: 13,
    fontWeight: "600",
  },
  editRow: {
    flexDirection: "row",
    gap: 8,
    alignItems: "center",
  },
  input: {
    flex: 1,
    backgroundColor: Colors.bgSecondary,
    color: Colors.textPrimary,
    padding: 12,
    borderRadius: 8,
    fontSize: 14,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  saveButton: {
    paddingHorizontal: 16,
    paddingVertical: 10,
    backgroundColor: Colors.accent,
    borderRadius: 8,
  },
  saveText: {
    color: "#fff",
    fontWeight: "bold",
  },
  urlValue: {
    color: Colors.textSecondary,
    fontSize: 14,
    fontFamily: "monospace",
    backgroundColor: Colors.bgSecondary,
    padding: 12,
    borderRadius: 8,
  },
  tapHint: {
    color: Colors.textDim,
    fontSize: 10,
    marginTop: 4,
  },
  buttonRow: {
    marginTop: 12,
  },
  connectButton: {
    backgroundColor: Colors.success,
    padding: 12,
    borderRadius: 8,
    alignItems: "center",
  },
  disconnectButton: {
    backgroundColor: Colors.error,
  },
  connectText: {
    color: "#fff",
    fontWeight: "bold",
    fontSize: 14,
  },
  settingRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: "rgba(255,255,255,0.03)",
  },
  settingInfo: {
    flex: 1,
    marginRight: 12,
  },
  settingLabel: {
    color: Colors.textPrimary,
    fontSize: 15,
    fontWeight: "600",
  },
  settingDesc: {
    color: Colors.textMuted,
    fontSize: 12,
    marginTop: 2,
  },
  actionButton: {
    backgroundColor: Colors.bgSecondary,
    padding: 16,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: Colors.border,
    marginBottom: 10,
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
  aboutGrid: {
    backgroundColor: Colors.bgSecondary,
    borderRadius: 12,
    padding: 12,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  dangerSection: {
    padding: 20,
  },
  dangerTitle: {
    color: Colors.error,
    fontSize: 14,
    fontWeight: "bold",
    marginBottom: 10,
  },
  dangerButton: {
    backgroundColor: "rgba(255, 68, 68, 0.1)",
    padding: 16,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: Colors.error,
    alignItems: "center",
  },
  dangerText: {
    color: Colors.error,
    fontWeight: "bold",
    fontSize: 14,
  },
  footer: {
    textAlign: "center",
    color: Colors.textDim,
    fontSize: 11,
    padding: 20,
    lineHeight: 18,
  },
});
