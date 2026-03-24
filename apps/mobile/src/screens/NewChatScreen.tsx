/**
 * New Chat screen — add a contact and start an encrypted conversation.
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
import { toBase64, fromBase64 } from "../lib/crypto";

export function NewChatScreen() {
  const { identity, goBack, navigate, addContact } = useApp();
  const [recipientKey, setRecipientKey] = useState("");
  const [contactName, setContactName] = useState("");

  const handlePaste = async () => {
    const text = await Clipboard.getStringAsync();
    if (text) setRecipientKey(text.trim());
  };

  const handleStart = async () => {
    if (!recipientKey.trim()) {
      Alert.alert("Error", "Enter the recipient's public key");
      return;
    }
    if (!contactName.trim()) {
      Alert.alert("Error", "Enter a name for this contact");
      return;
    }

    try {
      const decoded = fromBase64(recipientKey.trim());
      if (decoded.length !== 32) {
        Alert.alert("Error", "Invalid public key length (expected 32 bytes)");
        return;
      }
    } catch {
      Alert.alert("Error", "Invalid base64 public key");
      return;
    }

    // Check not adding self
    if (identity && recipientKey.trim() === toBase64(identity.dh.publicKey)) {
      Alert.alert("Error", "You cannot chat with yourself");
      return;
    }

    const added = await addContact(recipientKey.trim(), contactName.trim());
    if (!added) return; // Contact already exists, alert shown by addContact
    navigate({
      name: "chat",
      contactKey: recipientKey.trim(),
      contactName: contactName.trim(),
    });
  };

  return (
    <ScrollView contentContainerStyle={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity onPress={goBack} style={styles.backButton}>
          <Text style={styles.backText}>{"<"}</Text>
        </TouchableOpacity>
        <Text style={styles.headerTitle}>New Encrypted Chat</Text>
      </View>

      {/* Your key */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Your Public Key</Text>
        <Text style={styles.hint}>
          Share this with your contact so they can message you
        </Text>
        <View style={styles.keyBox}>
          <Text style={styles.keyText} selectable>
            {identity ? toBase64(identity.dh.publicKey) : "—"}
          </Text>
        </View>
        <TouchableOpacity
          style={styles.copyButton}
          onPress={async () => {
            if (identity) {
              await Clipboard.setStringAsync(
                toBase64(identity.dh.publicKey),
              );
              Alert.alert("Copied", "Public key copied to clipboard");
            }
          }}
        >
          <Text style={styles.copyText}>Copy My Key</Text>
        </TouchableOpacity>
      </View>

      {/* Contact details */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Contact Details</Text>

        <Text style={styles.label}>Contact Name</Text>
        <TextInput
          style={styles.input}
          value={contactName}
          onChangeText={setContactName}
          placeholder="e.g. Alice"
          placeholderTextColor={Colors.textDim}
          autoCapitalize="words"
        />

        <Text style={styles.label}>Recipient's Public Key (Base64)</Text>
        <TextInput
          style={[styles.input, styles.keyInput]}
          value={recipientKey}
          onChangeText={setRecipientKey}
          placeholder="Paste the recipient's public key"
          placeholderTextColor={Colors.textDim}
          autoCapitalize="none"
          autoCorrect={false}
          multiline
        />
        <TouchableOpacity style={styles.pasteButton} onPress={handlePaste}>
          <Text style={styles.pasteText}>Paste from Clipboard</Text>
        </TouchableOpacity>
      </View>

      {/* Info */}
      <View style={styles.infoBox}>
        <Text style={styles.infoTitle}>How key exchange works</Text>
        <Text style={styles.infoText}>
          CipherLink uses X3DH (Extended Triple Diffie-Hellman) to establish a
          shared secret. Both parties need each other's public keys. A shared
          secret is derived using HKDF-SHA256 and used for XChaCha20-Poly1305
          AEAD encryption.
        </Text>
      </View>

      {/* Start button */}
      <TouchableOpacity style={styles.startButton} onPress={handleStart}>
        <Text style={styles.startText}>Start Encrypted Chat</Text>
      </TouchableOpacity>
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
  section: {
    padding: 20,
    borderBottomWidth: 1,
    borderBottomColor: "rgba(255,255,255,0.05)",
  },
  sectionTitle: {
    color: Colors.accent,
    fontSize: 16,
    fontWeight: "bold",
    marginBottom: 4,
  },
  hint: {
    color: Colors.textMuted,
    fontSize: 12,
    marginBottom: 12,
  },
  keyBox: {
    backgroundColor: Colors.bgSecondary,
    padding: 12,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  keyText: {
    color: Colors.textSecondary,
    fontSize: 11,
    fontFamily: "monospace",
    textAlign: "center",
  },
  copyButton: {
    alignSelf: "center",
    marginTop: 10,
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
  label: {
    color: Colors.textSecondary,
    fontSize: 13,
    marginBottom: 6,
    marginTop: 14,
  },
  input: {
    backgroundColor: Colors.bgSecondary,
    color: Colors.textPrimary,
    padding: 12,
    borderRadius: 8,
    fontSize: 14,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  keyInput: {
    minHeight: 64,
    fontFamily: "monospace",
    fontSize: 12,
  },
  pasteButton: {
    alignSelf: "center",
    marginTop: 10,
    paddingHorizontal: 16,
    paddingVertical: 8,
  },
  pasteText: {
    color: Colors.info,
    fontSize: 13,
  },
  infoBox: {
    margin: 20,
    padding: 16,
    backgroundColor: "rgba(33, 150, 243, 0.08)",
    borderRadius: 12,
    borderWidth: 1,
    borderColor: "rgba(33, 150, 243, 0.2)",
  },
  infoTitle: {
    color: Colors.info,
    fontSize: 13,
    fontWeight: "bold",
    marginBottom: 6,
  },
  infoText: {
    color: Colors.textMuted,
    fontSize: 12,
    lineHeight: 18,
  },
  startButton: {
    backgroundColor: Colors.accent,
    marginHorizontal: 20,
    padding: 16,
    borderRadius: 12,
    alignItems: "center",
  },
  startText: {
    color: "#fff",
    fontWeight: "bold",
    fontSize: 16,
  },
});
