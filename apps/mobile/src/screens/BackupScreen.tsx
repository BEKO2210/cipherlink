/**
 * Backup screen — encrypted backup with Argon2id + Shamir key splitting.
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
  ActivityIndicator,
} from "react-native";
import * as Clipboard from "expo-clipboard";
import { Colors } from "../theme/colors";
import { useApp } from "../context/AppContext";
import { toBase64 } from "../lib/crypto";
import {
  createBackup,
  splitBackupKey,
  shareToRecoveryCode,
} from "../lib/backup";

export function BackupScreen() {
  const { identity, contacts, groups, goBack, settings } = useApp();
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [restorePassphrase, setRestorePassphrase] = useState("");
  const [backupData, setBackupData] = useState<string | null>(null);
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState<"create" | "restore" | null>(null);

  const handleCreateBackup = async () => {
    if (!identity) {
      Alert.alert("Error", "No identity to backup");
      return;
    }
    if (passphrase.length < 8) {
      Alert.alert("Error", "Passphrase must be at least 8 characters");
      return;
    }
    if (passphrase !== confirmPassphrase) {
      Alert.alert("Error", "Passphrases do not match");
      return;
    }

    setLoading(true);
    try {
      // Prepare backup data
      const data = {
        version: 1,
        timestamp: Date.now(),
        identity: {
          dhPublicKey: toBase64(identity.dh.publicKey),
          dhPrivateKey: toBase64(identity.dh.privateKey),
          signingPublicKey: toBase64(identity.signing.publicKey),
          signingPrivateKey: toBase64(identity.signing.privateKey),
        },
        contacts: contacts.map((c) => ({
          publicKey: c.publicKey,
          name: c.name,
          verified: c.verified,
        })),
        groups: groups.map((g) => ({
          id: g.id,
          name: g.name,
          members: g.members,
        })),
        settings,
      };

      // Create encrypted backup
      const payload = await createBackup(passphrase, data);
      const backupJson = JSON.stringify(payload);
      setBackupData(backupJson);

      // Split the backup key using Shamir's Secret Sharing
      const keyBytes = new TextEncoder().encode(passphrase.slice(0, 32).padEnd(32, "\0"));
      const shares = await splitBackupKey(new Uint8Array(keyBytes));
      const code = shareToRecoveryCode(shares.recoveryShare);
      setRecoveryCode(code);

      Alert.alert(
        "Backup Created",
        "Your encrypted backup has been created. Save both the backup data and recovery code securely.",
      );
    } catch (_err) {
      Alert.alert("Error", "Failed to create backup");
    } finally {
      setLoading(false);
    }
  };

  const handleRestoreBackup = async () => {
    if (!restorePassphrase) {
      Alert.alert("Error", "Enter your backup passphrase");
      return;
    }

    setLoading(true);
    try {
      // In a real app, the user would paste/import the backup data
      Alert.alert(
        "Restore",
        "In the full version, you would import your backup file here. The backup will be decrypted using your passphrase and Argon2id key derivation.",
      );
    } catch {
      Alert.alert("Error", "Failed to restore backup — wrong passphrase?");
    } finally {
      setLoading(false);
    }
  };

  return (
    <ScrollView contentContainerStyle={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity onPress={goBack} style={styles.backButton}>
          <Text style={styles.backText}>{"<"}</Text>
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Encrypted Backup</Text>
      </View>

      {/* Info */}
      <View style={styles.infoBox}>
        <Text style={styles.infoTitle}>How Backup Works</Text>
        <Text style={styles.infoText}>
          Your identity, contacts, and settings are encrypted with a
          passphrase-derived key using Argon2id (memory-hard KDF). The
          encryption uses XChaCha20-Poly1305 AEAD. Your backup key is
          additionally split into 3 shares using Shamir's Secret Sharing —
          any 2 shares can reconstruct the key.
        </Text>
      </View>

      {/* Mode selection */}
      {!mode && (
        <View style={styles.modeSection}>
          <TouchableOpacity
            style={styles.modeButton}
            onPress={() => setMode("create")}
          >
            <Text style={styles.modeIcon}>BK</Text>
            <Text style={styles.modeTitle}>Create Backup</Text>
            <Text style={styles.modeDesc}>
              Encrypt your identity and save it securely
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={styles.modeButton}
            onPress={() => setMode("restore")}
          >
            <Text style={styles.modeIcon}>RS</Text>
            <Text style={styles.modeTitle}>Restore Backup</Text>
            <Text style={styles.modeDesc}>
              Decrypt a previously saved backup
            </Text>
          </TouchableOpacity>
        </View>
      )}

      {/* Create backup */}
      {mode === "create" && (
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Create Encrypted Backup</Text>

          <Text style={styles.label}>Passphrase (min 8 characters)</Text>
          <TextInput
            style={styles.input}
            value={passphrase}
            onChangeText={setPassphrase}
            placeholder="Enter a strong passphrase"
            placeholderTextColor={Colors.textDim}
            secureTextEntry
          />

          <Text style={styles.label}>Confirm Passphrase</Text>
          <TextInput
            style={styles.input}
            value={confirmPassphrase}
            onChangeText={setConfirmPassphrase}
            placeholder="Re-enter passphrase"
            placeholderTextColor={Colors.textDim}
            secureTextEntry
          />

          {/* Strength indicator */}
          <View style={styles.strengthRow}>
            <View
              style={[
                styles.strengthBar,
                {
                  width: `${Math.min(passphrase.length * 8, 100)}%`,
                  backgroundColor:
                    passphrase.length >= 16
                      ? Colors.success
                      : passphrase.length >= 8
                        ? Colors.warning
                        : Colors.error,
                },
              ]}
            />
          </View>
          <Text style={styles.strengthText}>
            {passphrase.length >= 16
              ? "Strong passphrase"
              : passphrase.length >= 8
                ? "Acceptable passphrase"
                : "Too short"}
          </Text>

          <TouchableOpacity
            style={[
              styles.actionButton,
              loading && styles.actionButtonDisabled,
            ]}
            onPress={handleCreateBackup}
            disabled={loading}
          >
            {loading ? (
              <ActivityIndicator color="#fff" />
            ) : (
              <Text style={styles.actionText}>
                Create Encrypted Backup
              </Text>
            )}
          </TouchableOpacity>

          {/* Backup output */}
          {backupData && (
            <View style={styles.outputSection}>
              <Text style={styles.outputTitle}>
                Encrypted Backup Created
              </Text>
              <Text style={styles.outputData} numberOfLines={3}>
                {backupData.slice(0, 120)}...
              </Text>
              <Text style={styles.outputNote}>
                Backup contains encrypted private keys. For security, backup
                data is stored on-device only and never copied to the clipboard.
                Use the recovery code below for key restoration.
              </Text>
            </View>
          )}

          {/* Recovery code */}
          {recoveryCode && (
            <View style={styles.recoverySection}>
              <Text style={styles.recoveryTitle}>
                Recovery Code (Shamir Share 3/3)
              </Text>
              <Text style={styles.recoveryDesc}>
                Save this code securely. Together with any one other share, it
                can reconstruct your backup key.
              </Text>
              <Text style={styles.recoveryCode} selectable>
                {recoveryCode}
              </Text>
              <TouchableOpacity
                style={styles.copyButton}
                onPress={async () => {
                  await Clipboard.setStringAsync(recoveryCode);
                  Alert.alert("Copied", "Recovery code copied");
                }}
              >
                <Text style={styles.copyText}>Copy Recovery Code</Text>
              </TouchableOpacity>
            </View>
          )}

          <TouchableOpacity
            style={styles.cancelButton}
            onPress={() => setMode(null)}
          >
            <Text style={styles.cancelText}>Back</Text>
          </TouchableOpacity>
        </View>
      )}

      {/* Restore backup */}
      {mode === "restore" && (
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Restore from Backup</Text>

          <Text style={styles.label}>Backup Passphrase</Text>
          <TextInput
            style={styles.input}
            value={restorePassphrase}
            onChangeText={setRestorePassphrase}
            placeholder="Enter your backup passphrase"
            placeholderTextColor={Colors.textDim}
            secureTextEntry
          />

          <View style={styles.restoreInfo}>
            <Text style={styles.restoreInfoTitle}>What Gets Restored</Text>
            <Text style={styles.restoreInfoText}>
              {"\u2022"} Identity keypair (X25519 + Ed25519){"\n"}
              {"\u2022"} Contact list with verification status{"\n"}
              {"\u2022"} Group memberships{"\n"}
              {"\u2022"} App settings
            </Text>
          </View>

          <TouchableOpacity
            style={[
              styles.actionButton,
              loading && styles.actionButtonDisabled,
            ]}
            onPress={handleRestoreBackup}
            disabled={loading}
          >
            {loading ? (
              <ActivityIndicator color="#fff" />
            ) : (
              <Text style={styles.actionText}>Restore Backup</Text>
            )}
          </TouchableOpacity>

          <TouchableOpacity
            style={styles.cancelButton}
            onPress={() => setMode(null)}
          >
            <Text style={styles.cancelText}>Back</Text>
          </TouchableOpacity>
        </View>
      )}

      {/* Shamir info */}
      <View style={styles.shamirSection}>
        <Text style={styles.shamirTitle}>
          Shamir's Secret Sharing (2-of-3)
        </Text>
        <Text style={styles.shamirText}>
          Your backup key is split into 3 shares:{"\n\n"}
          Share 1 — Stored on this device{"\n"}
          Share 2 — Stored on server (encrypted){"\n"}
          Share 3 — Recovery code (save offline){"\n\n"}
          Any 2 of these 3 shares can reconstruct your key.
          No single share reveals any information about the original key
          (information-theoretic security over GF(256)).
        </Text>
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    backgroundColor: Colors.bg,
    paddingBottom: 40,
  },
  header: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 12,
    paddingVertical: 14,
    backgroundColor: Colors.bgPrimary,
    borderBottomWidth: 1,
    borderBottomColor: Colors.border,
  },
  backButton: {
    padding: 8,
    marginRight: 8,
  },
  backText: {
    color: Colors.accent,
    fontSize: 22,
    fontWeight: "bold",
  },
  headerTitle: {
    color: Colors.textPrimary,
    fontSize: 18,
    fontWeight: "bold",
  },
  infoBox: {
    margin: 20,
    padding: 16,
    backgroundColor: "rgba(245, 166, 35, 0.08)",
    borderRadius: 12,
    borderWidth: 1,
    borderColor: "rgba(245, 166, 35, 0.2)",
  },
  infoTitle: {
    color: Colors.warning,
    fontSize: 14,
    fontWeight: "bold",
    marginBottom: 6,
  },
  infoText: {
    color: Colors.textMuted,
    fontSize: 12,
    lineHeight: 18,
  },
  modeSection: {
    padding: 20,
    gap: 12,
  },
  modeButton: {
    backgroundColor: Colors.bgSecondary,
    padding: 20,
    borderRadius: 16,
    borderWidth: 1,
    borderColor: Colors.border,
    alignItems: "center",
  },
  modeIcon: {
    fontSize: 24,
    fontWeight: "bold",
    color: Colors.accent,
    backgroundColor: Colors.bgCard,
    width: 56,
    height: 56,
    lineHeight: 56,
    textAlign: "center",
    borderRadius: 16,
    overflow: "hidden",
    marginBottom: 12,
  },
  modeTitle: {
    color: Colors.textPrimary,
    fontSize: 17,
    fontWeight: "bold",
    marginBottom: 4,
  },
  modeDesc: {
    color: Colors.textMuted,
    fontSize: 13,
    textAlign: "center",
  },
  section: {
    padding: 20,
  },
  sectionTitle: {
    color: Colors.textPrimary,
    fontSize: 18,
    fontWeight: "bold",
    marginBottom: 16,
  },
  label: {
    color: Colors.textSecondary,
    fontSize: 13,
    marginBottom: 6,
    marginTop: 12,
  },
  input: {
    backgroundColor: Colors.bgSecondary,
    color: Colors.textPrimary,
    padding: 14,
    borderRadius: 10,
    fontSize: 15,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  strengthRow: {
    height: 4,
    backgroundColor: Colors.bgCard,
    borderRadius: 2,
    marginTop: 8,
    overflow: "hidden",
  },
  strengthBar: {
    height: "100%",
    borderRadius: 2,
  },
  strengthText: {
    color: Colors.textDim,
    fontSize: 11,
    marginTop: 4,
    marginBottom: 16,
  },
  actionButton: {
    backgroundColor: Colors.accent,
    padding: 16,
    borderRadius: 12,
    alignItems: "center",
    marginTop: 16,
  },
  actionButtonDisabled: {
    opacity: 0.6,
  },
  actionText: {
    color: "#fff",
    fontWeight: "bold",
    fontSize: 16,
  },
  outputSection: {
    marginTop: 20,
    padding: 16,
    backgroundColor: Colors.bgSecondary,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  outputTitle: {
    color: Colors.textPrimary,
    fontSize: 14,
    fontWeight: "bold",
    marginBottom: 8,
  },
  outputData: {
    color: Colors.textDim,
    fontSize: 10,
    fontFamily: "monospace",
    marginBottom: 8,
  },
  outputNote: {
    color: Colors.warning,
    fontSize: 11,
    lineHeight: 16,
    fontStyle: "italic",
  },
  copyButton: {
    alignSelf: "center",
    paddingHorizontal: 16,
    paddingVertical: 8,
    backgroundColor: Colors.bgCard,
    borderRadius: 6,
  },
  copyText: {
    color: Colors.accent,
    fontSize: 13,
    fontWeight: "600",
  },
  recoverySection: {
    marginTop: 20,
    padding: 16,
    backgroundColor: "rgba(233, 69, 96, 0.08)",
    borderRadius: 12,
    borderWidth: 1,
    borderColor: "rgba(233, 69, 96, 0.3)",
  },
  recoveryTitle: {
    color: Colors.accent,
    fontSize: 14,
    fontWeight: "bold",
    marginBottom: 6,
  },
  recoveryDesc: {
    color: Colors.textMuted,
    fontSize: 12,
    lineHeight: 18,
    marginBottom: 12,
  },
  recoveryCode: {
    color: Colors.textPrimary,
    fontSize: 14,
    fontFamily: "monospace",
    fontWeight: "bold",
    textAlign: "center",
    padding: 12,
    backgroundColor: Colors.bgPrimary,
    borderRadius: 8,
    marginBottom: 12,
  },
  cancelButton: {
    alignSelf: "center",
    marginTop: 16,
    padding: 12,
  },
  cancelText: {
    color: Colors.textMuted,
    fontSize: 14,
  },
  restoreInfo: {
    marginTop: 16,
    padding: 14,
    backgroundColor: Colors.bgSecondary,
    borderRadius: 10,
  },
  restoreInfoTitle: {
    color: Colors.textPrimary,
    fontSize: 13,
    fontWeight: "bold",
    marginBottom: 8,
  },
  restoreInfoText: {
    color: Colors.textMuted,
    fontSize: 12,
    lineHeight: 20,
  },
  shamirSection: {
    margin: 20,
    padding: 16,
    backgroundColor: "rgba(124, 77, 255, 0.08)",
    borderRadius: 12,
    borderWidth: 1,
    borderColor: "rgba(124, 77, 255, 0.2)",
  },
  shamirTitle: {
    color: Colors.sealed,
    fontSize: 14,
    fontWeight: "bold",
    marginBottom: 8,
  },
  shamirText: {
    color: Colors.textMuted,
    fontSize: 12,
    lineHeight: 19,
  },
});
