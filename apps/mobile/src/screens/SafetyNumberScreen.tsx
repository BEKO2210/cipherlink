/**
 * Safety Number screen — 60-digit key verification for contacts.
 * @author Belkis Aslani
 */
import React, { useState, useEffect } from "react";
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  Alert,
  ScrollView,
  ActivityIndicator,
} from "react-native";
import { Colors } from "../theme/colors";
import { useApp } from "../context/AppContext";
import { toBase64, fromBase64 } from "../lib/crypto";
import {
  generateSafetyNumber,
  formatSafetyNumber,
} from "../lib/safety-numbers";

interface SafetyNumberScreenProps {
  contactKey: string;
  contactName: string;
}

export function SafetyNumberScreen({
  contactKey,
  contactName,
}: SafetyNumberScreenProps) {
  const { identity, goBack, verifyContact, contacts } = useApp();
  const [safetyNumber, setSafetyNumber] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const contact = contacts.find((c) => c.publicKey === contactKey);
  const isVerified = contact?.verified ?? false;

  useEffect(() => {
    (async () => {
      if (!identity) return;

      try {
        const localPub = identity.dh.publicKey;
        const remotePub = fromBase64(contactKey);
        const localId = toBase64(localPub);
        const remoteId = contactKey;

        const sn = await generateSafetyNumber(
          localPub,
          localId,
          remotePub,
          remoteId,
        );
        setSafetyNumber(sn);
      } catch {
        Alert.alert("Error", "Failed to generate safety number");
      } finally {
        setLoading(false);
      }
    })();
  }, [identity, contactKey]);

  const handleVerify = async () => {
    Alert.alert(
      "Verify Contact",
      "Have you compared the safety number with your contact in person or via a trusted channel?",
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Mark as Verified",
          onPress: async () => {
            await verifyContact(contactKey);
            Alert.alert(
              "Verified",
              `${contactName} has been marked as verified.`,
            );
          },
        },
      ],
    );
  };

  // Render safety number as colored blocks
  const renderSafetyNumberBlocks = () => {
    if (!safetyNumber) return null;

    const formatted = formatSafetyNumber(safetyNumber);
    const groups = formatted.split(" ");

    return (
      <View style={styles.numberGrid}>
        {groups.map((group, i) => (
          <View key={i} style={styles.numberBlock}>
            <Text style={styles.numberText}>{group}</Text>
          </View>
        ))}
      </View>
    );
  };

  return (
    <ScrollView contentContainerStyle={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity onPress={goBack} style={styles.backButton}>
          <Text style={styles.backText}>{"<"}</Text>
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Safety Number</Text>
      </View>

      <View style={styles.content}>
        {/* Contact info */}
        <View style={styles.contactInfo}>
          <View
            style={[
              styles.avatar,
              isVerified && styles.avatarVerified,
            ]}
          >
            <Text style={styles.avatarText}>
              {contactName.charAt(0).toUpperCase()}
            </Text>
          </View>
          <Text style={styles.contactName}>{contactName}</Text>
          <View style={styles.statusBadge}>
            <View
              style={[
                styles.statusDot,
                {
                  backgroundColor: isVerified
                    ? Colors.success
                    : Colors.warning,
                },
              ]}
            />
            <Text
              style={[
                styles.statusText,
                { color: isVerified ? Colors.success : Colors.warning },
              ]}
            >
              {isVerified ? "Verified" : "Unverified"}
            </Text>
          </View>
        </View>

        {/* Safety number */}
        {loading ? (
          <ActivityIndicator
            color={Colors.accent}
            style={styles.loader}
            size="large"
          />
        ) : (
          <>
            <Text style={styles.sectionTitle}>
              Safety Number Fingerprint
            </Text>
            <Text style={styles.description}>
              Compare this number with your contact. If they match, you can be
              confident your messages are end-to-end encrypted with the right
              person.
            </Text>

            {renderSafetyNumberBlocks()}

            {/* QR data */}
            <View style={styles.qrSection}>
              <Text style={styles.qrTitle}>QR Verification Data</Text>
              <Text style={styles.qrData} selectable>
                SN01{safetyNumber}
              </Text>
              <Text style={styles.qrHint}>
                In a future update, scan this via camera for instant
                verification.
              </Text>
            </View>
          </>
        )}

        {/* Security info */}
        <View style={styles.infoBox}>
          <Text style={styles.infoTitle}>How Safety Numbers Work</Text>
          <Text style={styles.infoText}>
            Safety numbers are computed by iterating BLAKE2b 5,200 times over
            each party's public key and user ID. The resulting 60-digit number
            is unique to your conversation. If a third party intercepts
            messages (MITM attack), the safety numbers will not match.
          </Text>
        </View>

        {/* Public key display */}
        <View style={styles.keySection}>
          <Text style={styles.keyLabel}>Contact's Public Key</Text>
          <Text style={styles.keyValue} selectable>
            {contactKey}
          </Text>
        </View>

        {/* Verify button */}
        {!isVerified && (
          <TouchableOpacity
            style={styles.verifyButton}
            onPress={handleVerify}
          >
            <Text style={styles.verifyText}>
              Mark as Verified
            </Text>
          </TouchableOpacity>
        )}

        {isVerified && (
          <View style={styles.verifiedBanner}>
            <Text style={styles.verifiedText}>
              This contact is verified. You've confirmed their identity
              through safety number comparison.
            </Text>
          </View>
        )}
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    backgroundColor: Colors.bg,
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
  content: {
    padding: 20,
    paddingBottom: 40,
  },
  contactInfo: {
    alignItems: "center",
    marginBottom: 24,
  },
  avatar: {
    width: 72,
    height: 72,
    borderRadius: 36,
    backgroundColor: Colors.accent,
    justifyContent: "center",
    alignItems: "center",
    marginBottom: 12,
  },
  avatarVerified: {
    borderWidth: 3,
    borderColor: Colors.success,
  },
  avatarText: {
    color: "#fff",
    fontSize: 28,
    fontWeight: "bold",
  },
  contactName: {
    color: Colors.textPrimary,
    fontSize: 20,
    fontWeight: "bold",
    marginBottom: 6,
  },
  statusBadge: {
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
  loader: {
    marginVertical: 40,
  },
  sectionTitle: {
    color: Colors.textPrimary,
    fontSize: 16,
    fontWeight: "bold",
    textAlign: "center",
    marginBottom: 8,
  },
  description: {
    color: Colors.textMuted,
    fontSize: 13,
    textAlign: "center",
    lineHeight: 19,
    marginBottom: 20,
  },
  numberGrid: {
    flexDirection: "row",
    flexWrap: "wrap",
    justifyContent: "center",
    gap: 8,
    marginBottom: 24,
  },
  numberBlock: {
    backgroundColor: Colors.bgSecondary,
    paddingHorizontal: 14,
    paddingVertical: 10,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: Colors.border,
    minWidth: 80,
    alignItems: "center",
  },
  numberText: {
    color: Colors.textPrimary,
    fontSize: 18,
    fontWeight: "bold",
    fontFamily: "monospace",
    letterSpacing: 2,
  },
  qrSection: {
    alignItems: "center",
    marginBottom: 24,
    padding: 16,
    backgroundColor: Colors.bgSecondary,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  qrTitle: {
    color: Colors.textSecondary,
    fontSize: 13,
    fontWeight: "600",
    marginBottom: 8,
  },
  qrData: {
    color: Colors.textPrimary,
    fontSize: 10,
    fontFamily: "monospace",
    textAlign: "center",
    marginBottom: 8,
  },
  qrHint: {
    color: Colors.textDim,
    fontSize: 11,
    fontStyle: "italic",
  },
  infoBox: {
    padding: 16,
    backgroundColor: "rgba(76, 175, 80, 0.08)",
    borderRadius: 12,
    borderWidth: 1,
    borderColor: "rgba(76, 175, 80, 0.2)",
    marginBottom: 24,
  },
  infoTitle: {
    color: Colors.success,
    fontSize: 13,
    fontWeight: "bold",
    marginBottom: 6,
  },
  infoText: {
    color: Colors.textMuted,
    fontSize: 12,
    lineHeight: 18,
  },
  keySection: {
    marginBottom: 24,
  },
  keyLabel: {
    color: Colors.textMuted,
    fontSize: 12,
    marginBottom: 6,
  },
  keyValue: {
    color: Colors.textDim,
    fontSize: 10,
    fontFamily: "monospace",
    backgroundColor: Colors.bgSecondary,
    padding: 10,
    borderRadius: 6,
  },
  verifyButton: {
    backgroundColor: Colors.success,
    padding: 16,
    borderRadius: 12,
    alignItems: "center",
  },
  verifyText: {
    color: "#fff",
    fontWeight: "bold",
    fontSize: 16,
  },
  verifiedBanner: {
    padding: 16,
    backgroundColor: "rgba(76, 175, 80, 0.12)",
    borderRadius: 12,
    borderWidth: 1,
    borderColor: Colors.success,
  },
  verifiedText: {
    color: Colors.success,
    fontSize: 13,
    textAlign: "center",
    lineHeight: 19,
  },
});
