/**
 * Settings screen — server connection, encryption options, diagnostics, and account management.
 * Premium UI with icon indicators, connection test, and encryption verification.
 * @author Belkis Aslani
 */
import React, { useState, useCallback } from "react";
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  Alert,
  ScrollView,
  Switch,
  ActivityIndicator,
} from "react-native";
import { Colors } from "../theme/colors";
import { useApp } from "../context/AppContext";
import { CipherLinkClient } from "../lib/ws-client";

// ---------------------------------------------------------------------------
// Minimal Icon Components (no external deps)
// ---------------------------------------------------------------------------

function IconDot({ color, size = 10, glow }: { color: string; size?: number; glow?: boolean }) {
  return (
    <View
      style={{
        width: size,
        height: size,
        borderRadius: size / 2,
        backgroundColor: color,
        ...(glow
          ? {
              shadowColor: color,
              shadowOffset: { width: 0, height: 0 },
              shadowOpacity: 0.7,
              shadowRadius: 6,
              elevation: 4,
            }
          : {}),
      }}
    />
  );
}

function IconBadge({
  color,
  label,
  size = 32,
}: {
  color: string;
  label: string;
  size?: number;
}) {
  return (
    <View
      style={{
        width: size,
        height: size,
        borderRadius: size / 2.5,
        backgroundColor: color + "18",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      <Text
        style={{
          color,
          fontSize: size * 0.4,
          fontWeight: "800",
          lineHeight: size * 0.5,
        }}
      >
        {label}
      </Text>
    </View>
  );
}

function ChevronRight() {
  return (
    <Text style={{ color: Colors.textDim, fontSize: 18, fontWeight: "300" }}>
      {"\u203A"}
    </Text>
  );
}

// ---------------------------------------------------------------------------
// Main Screen
// ---------------------------------------------------------------------------

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
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{
    status: "idle" | "success" | "error";
    message: string;
    latency?: number;
  }>({ status: "idle", message: "" });
  const [encTestResult, setEncTestResult] = useState<{
    status: "idle" | "running" | "success" | "error";
    message: string;
  }>({ status: "idle", message: "" });

  const handleSaveUrl = async () => {
    const trimmed = serverUrl.trim();
    if (!trimmed) return;
    await updateSettings({ serverUrl: trimmed });
    setEditingUrl(false);
    setTestResult({ status: "idle", message: "" });
  };

  const handleTestConnection = useCallback(async () => {
    setTesting(true);
    setTestResult({ status: "idle", message: "Testing..." });
    try {
      const result = await CipherLinkClient.testConnection(settings.serverUrl);
      setTestResult({
        status: "success",
        message: `Server reachable — ${result.latencyMs}ms`,
        latency: result.latencyMs,
      });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Unknown error";
      setTestResult({ status: "error", message: msg });
    } finally {
      setTesting(false);
    }
  }, [settings.serverUrl]);

  const handleEncryptionTest = useCallback(async () => {
    setEncTestResult({ status: "running", message: "Running..." });
    try {
      const { initCrypto, encryptMessage, decryptMessage, generateFullIdentity } =
        await import("../lib/crypto");
      await initCrypto();

      const alice = await generateFullIdentity();
      const bob = await generateFullIdentity();

      const plaintext = "CipherLink encryption test — " + Date.now();

      // Encrypt: (senderPriv, senderPub, recipientPub, plaintext)
      const envelope = await encryptMessage(
        alice.dh.privateKey,
        alice.dh.publicKey,
        bob.dh.publicKey,
        plaintext,
      );

      // Decrypt: (recipientPriv, senderPub, envelope)
      const decrypted = await decryptMessage(
        bob.dh.privateKey,
        alice.dh.publicKey,
        envelope,
      );

      if (decrypted === plaintext) {
        setEncTestResult({
          status: "success",
          message: "XChaCha20-Poly1305 + HKDF — all checks passed",
        });
      } else {
        setEncTestResult({
          status: "error",
          message: "Decrypted text does not match plaintext",
        });
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Unknown error";
      setEncTestResult({ status: "error", message: msg });
    }
  }, []);

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
        <Text style={styles.headerSub}>Server, encryption & diagnostics</Text>
      </View>

      {/* ───────── Server Connection ───────── */}
      <View style={styles.section}>
        <View style={styles.sectionHeader}>
          <IconBadge color={Colors.accent} label="S" />
          <Text style={styles.sectionTitle}>Server Connection</Text>
        </View>

        {/* Status Card */}
        <View style={styles.card}>
          <View style={styles.statusCard}>
            <View style={styles.statusLeft}>
              <IconDot
                color={connected ? Colors.success : Colors.error}
                size={14}
                glow={connected}
              />
              <View>
                <Text
                  style={[
                    styles.statusText,
                    { color: connected ? Colors.success : Colors.error },
                  ]}
                >
                  {connected ? "Connected" : "Disconnected"}
                </Text>
                <Text style={styles.statusSub}>
                  {connected ? "Relay server active" : "Tap Connect to establish"}
                </Text>
              </View>
            </View>
            <TouchableOpacity
              style={[styles.connectBtn, connected && styles.disconnectBtn]}
              onPress={connected ? disconnectFromServer : connectToServer}
            >
              <Text style={styles.connectBtnText}>
                {connected ? "Disconnect" : "Connect"}
              </Text>
            </TouchableOpacity>
          </View>
        </View>

        {/* Server URL */}
        <View style={styles.card}>
          <Text style={styles.cardLabel}>Relay Server URL</Text>
          {editingUrl ? (
            <View style={styles.editRow}>
              <TextInput
                style={styles.urlInput}
                value={serverUrl}
                onChangeText={setServerUrl}
                autoCapitalize="none"
                autoCorrect={false}
                placeholder="wss://relay.example.com"
                placeholderTextColor={Colors.textDim}
                keyboardType="url"
              />
              <TouchableOpacity style={styles.saveBtn} onPress={handleSaveUrl}>
                <Text style={styles.saveBtnText}>Save</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.cancelBtn}
                onPress={() => {
                  setServerUrl(settings.serverUrl);
                  setEditingUrl(false);
                }}
              >
                <Text style={styles.cancelBtnText}>Cancel</Text>
              </TouchableOpacity>
            </View>
          ) : (
            <TouchableOpacity
              style={styles.urlDisplay}
              onPress={() => setEditingUrl(true)}
            >
              <Text style={styles.urlText} numberOfLines={1}>
                {settings.serverUrl}
              </Text>
              <Text style={styles.urlHint}>Tap to change</Text>
            </TouchableOpacity>
          )}
          <Text style={styles.cardNote}>
            Default: wss://relay.cipherlink.app{"\n"}
            You can host your own relay server
          </Text>
        </View>

        {/* Connection Test */}
        <TouchableOpacity
          style={[styles.card, styles.testCard]}
          onPress={handleTestConnection}
          disabled={testing}
          activeOpacity={0.7}
        >
          <View style={styles.testRow}>
            <IconBadge
              color={
                testResult.status === "success"
                  ? Colors.success
                  : testResult.status === "error"
                    ? Colors.error
                    : Colors.info
              }
              label={testing ? "..." : testResult.status === "success" ? "\u2713" : "\u2197"}
              size={36}
            />
            <View style={styles.testInfo}>
              <Text style={styles.testLabel}>Test Connection</Text>
              <Text style={styles.testDesc}>
                Ping relay server and measure latency
              </Text>
              {testResult.status !== "idle" && (
                <Text
                  style={[
                    styles.testResult,
                    {
                      color:
                        testResult.status === "success"
                          ? Colors.success
                          : testResult.status === "error"
                            ? Colors.error
                            : Colors.textMuted,
                    },
                  ]}
                >
                  {testing ? "Connecting..." : testResult.message}
                </Text>
              )}
            </View>
            {!testing && <ChevronRight />}
            {testing && <ActivityIndicator size="small" color={Colors.info} />}
          </View>
        </TouchableOpacity>
      </View>

      {/* ───────── Encryption Settings ───────── */}
      <View style={styles.section}>
        <View style={styles.sectionHeader}>
          <IconBadge color={Colors.accent} label={"\u2622"} />
          <Text style={styles.sectionTitle}>Encryption</Text>
        </View>

        <View style={styles.card}>
          {/* Sealed Sender */}
          <View style={styles.settingRow}>
            <IconBadge color={Colors.sealed} label="SS" size={36} />
            <View style={styles.settingInfo}>
              <Text style={styles.settingLabel}>Sealed Sender</Text>
              <Text style={styles.settingDesc}>
                Hide your identity from the relay server
              </Text>
            </View>
            <Switch
              value={settings.sealedSender}
              onValueChange={(v) => updateSettings({ sealedSender: v })}
              trackColor={{ false: "rgba(255,255,255,0.1)", true: Colors.sealed }}
              thumbColor={settings.sealedSender ? "#fff" : Colors.textDim}
            />
          </View>

          <View style={styles.settingDivider} />

          {/* Quantum-Resistant */}
          <View style={styles.settingRow}>
            <IconBadge color={Colors.quantum} label="PQ" size={36} />
            <View style={styles.settingInfo}>
              <Text style={styles.settingLabel}>Quantum-Resistant</Text>
              <Text style={styles.settingDesc}>
                Hybrid X25519 + ML-KEM-768 key encapsulation
              </Text>
            </View>
            <Switch
              value={settings.quantumResistant}
              onValueChange={(v) => updateSettings({ quantumResistant: v })}
              trackColor={{ false: "rgba(255,255,255,0.1)", true: Colors.quantum }}
              thumbColor={settings.quantumResistant ? "#fff" : Colors.textDim}
            />
          </View>

          <View style={styles.settingDivider} />

          {/* Message Padding */}
          <View style={styles.settingRow}>
            <IconBadge color={Colors.success} label="P7" size={36} />
            <View style={styles.settingInfo}>
              <Text style={styles.settingLabel}>Message Padding</Text>
              <Text style={styles.settingDesc}>
                PKCS7 256-byte blocks prevent length analysis
              </Text>
            </View>
            <Switch
              value={settings.messagePadding}
              onValueChange={(v) => updateSettings({ messagePadding: v })}
              trackColor={{ false: "rgba(255,255,255,0.1)", true: Colors.success }}
              thumbColor={settings.messagePadding ? "#fff" : Colors.textDim}
            />
          </View>
        </View>
      </View>

      {/* ───────── Diagnostics ───────── */}
      <View style={styles.section}>
        <View style={styles.sectionHeader}>
          <IconBadge color={Colors.info} label={"\u2713"} />
          <Text style={styles.sectionTitle}>Diagnostics</Text>
        </View>

        <TouchableOpacity
          style={[styles.card, styles.testCard]}
          onPress={handleEncryptionTest}
          disabled={encTestResult.status === "running"}
          activeOpacity={0.7}
        >
          <View style={styles.testRow}>
            <IconBadge
              color={
                encTestResult.status === "success"
                  ? Colors.success
                  : encTestResult.status === "error"
                    ? Colors.error
                    : Colors.accent
              }
              label={
                encTestResult.status === "running"
                  ? "..."
                  : encTestResult.status === "success"
                    ? "\u2713"
                    : "E2E"
              }
              size={36}
            />
            <View style={styles.testInfo}>
              <Text style={styles.testLabel}>Encryption Self-Test</Text>
              <Text style={styles.testDesc}>
                Generate keys, encrypt, decrypt, verify
              </Text>
              {encTestResult.status !== "idle" && (
                <Text
                  style={[
                    styles.testResult,
                    {
                      color:
                        encTestResult.status === "success"
                          ? Colors.success
                          : encTestResult.status === "error"
                            ? Colors.error
                            : Colors.textMuted,
                    },
                  ]}
                >
                  {encTestResult.status === "running"
                    ? "Running crypto tests..."
                    : encTestResult.message}
                </Text>
              )}
            </View>
            {encTestResult.status === "running" ? (
              <ActivityIndicator size="small" color={Colors.info} />
            ) : (
              <ChevronRight />
            )}
          </View>
        </TouchableOpacity>
      </View>

      {/* ───────── Security Actions ───────── */}
      <View style={styles.section}>
        <View style={styles.sectionHeader}>
          <IconBadge color={Colors.accent} label={"\u26BF"} />
          <Text style={styles.sectionTitle}>Security</Text>
        </View>

        <TouchableOpacity
          style={[styles.card, styles.actionCard]}
          onPress={() => navigate({ name: "backup" })}
          activeOpacity={0.7}
        >
          <View style={styles.actionRow}>
            <IconBadge color={Colors.accent} label="BK" size={36} />
            <View style={styles.actionInfo}>
              <Text style={styles.actionText}>Encrypted Backup & Restore</Text>
              <Text style={styles.actionDesc}>
                Argon2id KDF + Shamir's Secret Sharing (2-of-3)
              </Text>
            </View>
            <ChevronRight />
          </View>
        </TouchableOpacity>

        <TouchableOpacity
          style={[styles.card, styles.actionCard]}
          onPress={() => navigate({ name: "profile" })}
          activeOpacity={0.7}
        >
          <View style={styles.actionRow}>
            <IconBadge color={Colors.accent} label="PK" size={36} />
            <View style={styles.actionInfo}>
              <Text style={styles.actionText}>View Public Keys</Text>
              <Text style={styles.actionDesc}>
                DH (X25519) and Signing (Ed25519) keys
              </Text>
            </View>
            <ChevronRight />
          </View>
        </TouchableOpacity>
      </View>

      {/* ───────── About ───────── */}
      <View style={styles.section}>
        <View style={styles.sectionHeader}>
          <IconBadge color={Colors.textMuted} label="i" />
          <Text style={styles.sectionTitle}>About</Text>
        </View>

        <View style={styles.card}>
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
          <AboutRow label="License" value="MIT" last />
        </View>
      </View>

      {/* ───────── Danger Zone ───────── */}
      <View style={styles.section}>
        <View style={styles.sectionHeader}>
          <IconDot color={Colors.error} size={10} />
          <Text style={[styles.sectionTitle, { color: Colors.error }]}>
            Danger Zone
          </Text>
        </View>

        <TouchableOpacity
          style={styles.dangerCard}
          onPress={handleResetIdentity}
          activeOpacity={0.7}
        >
          <IconBadge color={Colors.error} label={"\u2717"} size={36} />
          <Text style={styles.dangerText}>Reset Identity & Delete All Data</Text>
        </TouchableOpacity>
      </View>

      {/* Footer */}
      <View style={styles.footer}>
        <Text style={styles.footerText}>CipherLink — by Belkis Aslani</Text>
        <Text style={styles.footerSub}>
          Open Source (MIT) — github.com/BEKO2210/cipherlink
        </Text>
      </View>
    </ScrollView>
  );
}

// ---------------------------------------------------------------------------
// About Row
// ---------------------------------------------------------------------------

function AboutRow({
  label,
  value,
  last,
}: {
  label: string;
  value: string;
  last?: boolean;
}) {
  return (
    <View style={[aboutStyles.row, !last && aboutStyles.rowBorder]}>
      <Text style={aboutStyles.label}>{label}</Text>
      <Text style={aboutStyles.value}>{value}</Text>
    </View>
  );
}

const aboutStyles = StyleSheet.create({
  row: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingVertical: 10,
    paddingHorizontal: 2,
  },
  rowBorder: {
    borderBottomWidth: 1,
    borderBottomColor: "rgba(255,255,255,0.04)",
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

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    backgroundColor: Colors.bg,
    paddingBottom: 48,
  },

  // Header
  header: {
    paddingHorizontal: 24,
    paddingTop: 20,
    paddingBottom: 16,
    backgroundColor: Colors.bgPrimary,
    borderBottomWidth: 1,
    borderBottomColor: Colors.border,
  },
  headerTitle: {
    fontSize: 26,
    fontWeight: "800",
    color: Colors.accent,
    letterSpacing: -0.5,
  },
  headerSub: {
    color: Colors.textMuted,
    fontSize: 13,
    marginTop: 2,
  },

  // Sections
  section: {
    paddingHorizontal: 20,
    paddingTop: 28,
    paddingBottom: 4,
  },
  sectionHeader: {
    flexDirection: "row",
    alignItems: "center",
    gap: 12,
    marginBottom: 16,
  },
  sectionTitle: {
    color: Colors.textPrimary,
    fontSize: 16,
    fontWeight: "700",
    letterSpacing: -0.2,
  },

  // Cards
  card: {
    backgroundColor: Colors.bgSecondary,
    borderRadius: 14,
    borderWidth: 1,
    borderColor: Colors.border,
    padding: 16,
    marginBottom: 12,
  },
  cardLabel: {
    color: Colors.textMuted,
    fontSize: 11,
    fontWeight: "700",
    textTransform: "uppercase",
    letterSpacing: 1.5,
    marginBottom: 10,
  },
  cardNote: {
    color: Colors.textDim,
    fontSize: 11,
    marginTop: 12,
    lineHeight: 17,
  },

  // Status
  statusCard: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
  },
  statusLeft: {
    flexDirection: "row",
    alignItems: "center",
    gap: 14,
  },
  statusText: {
    fontSize: 15,
    fontWeight: "700",
  },
  statusSub: {
    color: Colors.textDim,
    fontSize: 11,
    marginTop: 1,
  },
  connectBtn: {
    paddingHorizontal: 20,
    paddingVertical: 10,
    backgroundColor: Colors.success,
    borderRadius: 10,
  },
  disconnectBtn: {
    backgroundColor: Colors.error,
  },
  connectBtnText: {
    color: "#fff",
    fontWeight: "700",
    fontSize: 13,
  },

  // URL
  editRow: {
    flexDirection: "row",
    gap: 8,
    alignItems: "center",
  },
  urlInput: {
    flex: 1,
    backgroundColor: "rgba(255,255,255,0.04)",
    color: Colors.textPrimary,
    paddingHorizontal: 14,
    paddingVertical: 12,
    borderRadius: 10,
    fontSize: 13,
    fontFamily: "monospace",
    borderWidth: 1,
    borderColor: Colors.accent,
  },
  saveBtn: {
    paddingHorizontal: 16,
    paddingVertical: 12,
    backgroundColor: Colors.accent,
    borderRadius: 10,
  },
  saveBtnText: {
    color: "#fff",
    fontWeight: "700",
    fontSize: 13,
  },
  cancelBtn: {
    paddingHorizontal: 12,
    paddingVertical: 12,
  },
  cancelBtnText: {
    color: Colors.textMuted,
    fontSize: 13,
  },
  urlDisplay: {
    backgroundColor: "rgba(255,255,255,0.03)",
    paddingHorizontal: 14,
    paddingVertical: 12,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: "rgba(255,255,255,0.06)",
  },
  urlText: {
    color: Colors.textSecondary,
    fontSize: 13,
    fontFamily: "monospace",
  },
  urlHint: {
    color: Colors.textDim,
    fontSize: 10,
    marginTop: 4,
  },

  // Test
  testCard: {
    padding: 16,
  },
  testRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: 14,
  },
  testInfo: {
    flex: 1,
  },
  testLabel: {
    color: Colors.textPrimary,
    fontSize: 14,
    fontWeight: "600",
  },
  testDesc: {
    color: Colors.textDim,
    fontSize: 11,
    marginTop: 2,
  },
  testResult: {
    fontSize: 12,
    fontWeight: "600",
    marginTop: 6,
  },

  // Settings toggles
  settingRow: {
    flexDirection: "row",
    alignItems: "center",
    paddingVertical: 14,
    gap: 14,
  },
  settingInfo: {
    flex: 1,
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
    lineHeight: 17,
  },
  settingDivider: {
    height: 1,
    backgroundColor: "rgba(255,255,255,0.04)",
    marginLeft: 50,
  },

  // Action cards
  actionCard: {
    padding: 16,
  },
  actionRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: 14,
  },
  actionInfo: {
    flex: 1,
  },
  actionText: {
    color: Colors.textPrimary,
    fontSize: 14,
    fontWeight: "600",
  },
  actionDesc: {
    color: Colors.textMuted,
    fontSize: 11,
    marginTop: 2,
  },

  // Danger
  dangerCard: {
    backgroundColor: "rgba(255, 68, 68, 0.06)",
    borderRadius: 14,
    borderWidth: 1,
    borderColor: "rgba(255, 68, 68, 0.2)",
    padding: 16,
    flexDirection: "row",
    alignItems: "center",
    gap: 14,
    marginBottom: 12,
  },
  dangerText: {
    color: Colors.error,
    fontWeight: "700",
    fontSize: 14,
    flex: 1,
  },

  // Footer
  footer: {
    paddingHorizontal: 24,
    paddingVertical: 28,
    alignItems: "center",
  },
  footerText: {
    color: Colors.textDim,
    fontSize: 12,
    fontWeight: "600",
  },
  footerSub: {
    color: Colors.textDim,
    fontSize: 11,
    marginTop: 4,
    opacity: 0.6,
  },
});
