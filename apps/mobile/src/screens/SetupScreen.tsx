/**
 * Setup / Identity screen — generate or load E2EE identity keypair.
 * @author Belkis Aslani
 */
import React, { useEffect, useState, useCallback } from "react";
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  Alert,
  ScrollView,
} from "react-native";
import * as Clipboard from "expo-clipboard";
import {
  generateIdentityKeypair,
  initCrypto,
  toBase64,
} from "../lib/crypto";
import { saveKeypair, loadKeypair } from "../lib/secure-storage";

interface SetupScreenProps {
  onReady: (publicKey: Uint8Array, privateKey: Uint8Array) => void;
}

export function SetupScreen({ onReady }: SetupScreenProps) {
  const [publicKeyB64, setPublicKeyB64] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      await initCrypto();
      const existing = await loadKeypair();
      if (existing) {
        setPublicKeyB64(toBase64(existing.publicKey));
        onReady(existing.publicKey, existing.privateKey);
      }
      setLoading(false);
    })();
  }, [onReady]);

  const handleGenerate = useCallback(async () => {
    setLoading(true);
    try {
      const kp = await generateIdentityKeypair();
      await saveKeypair(kp.publicKey, kp.privateKey);
      setPublicKeyB64(toBase64(kp.publicKey));
      onReady(kp.publicKey, kp.privateKey);
    } catch (_err) {
      Alert.alert("Error", "Failed to generate keypair");
    } finally {
      setLoading(false);
    }
  }, [onReady]);

  const handleCopy = useCallback(async () => {
    if (publicKeyB64) {
      await Clipboard.setStringAsync(publicKeyB64);
      Alert.alert("Copied", "Public key copied to clipboard");
    }
  }, [publicKeyB64]);

  if (loading) {
    return (
      <View style={styles.container}>
        <Text style={styles.title}>CipherLink</Text>
        <Text style={styles.subtitle}>Initializing encryption...</Text>
      </View>
    );
  }

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.title}>CipherLink</Text>
      <Text style={styles.subtitle}>End-to-End Encrypted Chat</Text>
      <Text style={styles.warning}>
        DEMO / SKELETON — Not for high-risk production use
      </Text>

      {publicKeyB64 ? (
        <View style={styles.keySection}>
          <Text style={styles.label}>Your Public Key:</Text>
          <Text style={styles.keyText} selectable>
            {publicKeyB64}
          </Text>
          <TouchableOpacity style={styles.button} onPress={handleCopy}>
            <Text style={styles.buttonText}>Copy Public Key</Text>
          </TouchableOpacity>
          <Text style={styles.hint}>
            Share this key with your chat partner. Keep your private key secret
            — it never leaves this device.
          </Text>
        </View>
      ) : (
        <View style={styles.keySection}>
          <Text style={styles.label}>No identity found.</Text>
          <TouchableOpacity style={styles.button} onPress={handleGenerate}>
            <Text style={styles.buttonText}>Generate Identity Keypair</Text>
          </TouchableOpacity>
        </View>
      )}

      <Text style={styles.footer}>By Belkis Aslani</Text>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    justifyContent: "center",
    alignItems: "center",
    padding: 24,
    backgroundColor: "#1a1a2e",
  },
  title: {
    fontSize: 32,
    fontWeight: "bold",
    color: "#e94560",
    marginBottom: 4,
  },
  subtitle: {
    fontSize: 16,
    color: "#eee",
    marginBottom: 8,
  },
  warning: {
    fontSize: 12,
    color: "#f5a623",
    marginBottom: 24,
    textAlign: "center",
    fontStyle: "italic",
  },
  keySection: {
    width: "100%",
    alignItems: "center",
    marginTop: 16,
  },
  label: {
    fontSize: 14,
    color: "#aaa",
    marginBottom: 8,
  },
  keyText: {
    fontSize: 12,
    color: "#0f3460",
    backgroundColor: "#e0e0e0",
    padding: 12,
    borderRadius: 8,
    fontFamily: "monospace",
    textAlign: "center",
    width: "100%",
    marginBottom: 12,
  },
  button: {
    backgroundColor: "#e94560",
    paddingHorizontal: 24,
    paddingVertical: 12,
    borderRadius: 8,
    marginBottom: 12,
  },
  buttonText: {
    color: "#fff",
    fontWeight: "bold",
    fontSize: 16,
  },
  hint: {
    fontSize: 12,
    color: "#888",
    textAlign: "center",
    marginTop: 8,
    paddingHorizontal: 16,
  },
  footer: {
    marginTop: 40,
    fontSize: 12,
    color: "#555",
  },
});
