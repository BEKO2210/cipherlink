/**
 * Onboarding screen — identity generation with logo and feature overview.
 * @author Belkis Aslani
 */
import React, { useState } from "react";
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  ScrollView,
  Image,
  ActivityIndicator,
} from "react-native";
import { Colors } from "../theme/colors";
import { useApp } from "../context/AppContext";

export function OnboardingScreen() {
  const { generateNewIdentity } = useApp();
  const [loading, setLoading] = useState(false);

  const handleGenerate = async () => {
    setLoading(true);
    try {
      await generateNewIdentity();
    } catch {
      setLoading(false);
    }
  };

  return (
    <ScrollView
      contentContainerStyle={styles.container}
      showsVerticalScrollIndicator={false}
    >
      {/* Logo */}
      <Image
        source={require("../../assets/icon.png")}
        style={styles.logo}
        resizeMode="contain"
      />

      <Text style={styles.title}>CipherLink</Text>
      <Text style={styles.subtitle}>End-to-End Encrypted Messenger</Text>
      <Text style={styles.tagline}>
        Messages that only you can read
      </Text>

      {/* Features */}
      <View style={styles.features}>
        <FeatureItem
          icon="E2E"
          color={Colors.encrypted}
          title="End-to-End Encryption"
          desc="XChaCha20-Poly1305 AEAD encryption"
        />
        <FeatureItem
          icon="SS"
          color={Colors.sealed}
          title="Anonymous Messaging"
          desc="Sealed Sender hides your identity"
        />
        <FeatureItem
          icon="PQ"
          color={Colors.quantum}
          title="Quantum-Resistant"
          desc="Hybrid X25519 + ML-KEM-768"
        />
        <FeatureItem
          icon="GRP"
          color={Colors.accent}
          title="Secure Groups"
          desc="TreeKEM group key agreement"
        />
        <FeatureItem
          icon="BK"
          color={Colors.warning}
          title="Encrypted Backups"
          desc="Argon2id + Shamir key splitting"
        />
        <FeatureItem
          icon="VER"
          color={Colors.success}
          title="Verify Contacts"
          desc="60-digit safety number verification"
        />
      </View>

      {/* Generate button */}
      <TouchableOpacity
        style={[styles.button, loading && styles.buttonDisabled]}
        onPress={handleGenerate}
        disabled={loading}
        activeOpacity={0.8}
      >
        {loading ? (
          <ActivityIndicator color="#fff" />
        ) : (
          <Text style={styles.buttonText}>Create Identity</Text>
        )}
      </TouchableOpacity>

      <Text style={styles.hint}>
        A unique cryptographic identity will be generated and stored securely
        on your device. Your private key never leaves this device.
      </Text>

      <Text style={styles.footer}>
        Signal Protocol Architecture{"\n"}
        Open Source (MIT) — by Belkis Aslani
      </Text>
    </ScrollView>
  );
}

function FeatureItem({
  icon,
  color,
  title,
  desc,
}: {
  icon: string;
  color: string;
  title: string;
  desc: string;
}) {
  return (
    <View style={styles.featureItem}>
      <View style={[styles.featureIcon, { backgroundColor: color }]}>
        <Text style={styles.featureIconText}>{icon}</Text>
      </View>
      <View style={styles.featureContent}>
        <Text style={styles.featureTitle}>{title}</Text>
        <Text style={styles.featureDesc}>{desc}</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    alignItems: "center",
    padding: 24,
    paddingTop: 60,
    backgroundColor: Colors.bg,
  },
  logo: {
    width: 100,
    height: 100,
    marginBottom: 16,
    borderRadius: 24,
  },
  title: {
    fontSize: 36,
    fontWeight: "bold",
    color: Colors.accent,
    letterSpacing: 1,
  },
  subtitle: {
    fontSize: 16,
    color: Colors.textSecondary,
    marginTop: 4,
  },
  tagline: {
    fontSize: 13,
    color: Colors.textMuted,
    marginTop: 4,
    fontStyle: "italic",
  },
  features: {
    width: "100%",
    marginTop: 32,
    marginBottom: 32,
    gap: 12,
  },
  featureItem: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: Colors.bgSecondary,
    padding: 14,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  featureIcon: {
    width: 40,
    height: 40,
    borderRadius: 10,
    justifyContent: "center",
    alignItems: "center",
    marginRight: 12,
  },
  featureIconText: {
    color: "#fff",
    fontSize: 11,
    fontWeight: "bold",
  },
  featureContent: {
    flex: 1,
  },
  featureTitle: {
    color: Colors.textPrimary,
    fontSize: 15,
    fontWeight: "600",
  },
  featureDesc: {
    color: Colors.textMuted,
    fontSize: 12,
    marginTop: 2,
  },
  button: {
    backgroundColor: Colors.accent,
    paddingHorizontal: 48,
    paddingVertical: 16,
    borderRadius: 12,
    width: "100%",
    alignItems: "center",
  },
  buttonDisabled: {
    opacity: 0.7,
  },
  buttonText: {
    color: "#fff",
    fontWeight: "bold",
    fontSize: 18,
  },
  hint: {
    fontSize: 12,
    color: Colors.textMuted,
    textAlign: "center",
    marginTop: 16,
    paddingHorizontal: 16,
    lineHeight: 18,
  },
  footer: {
    marginTop: 32,
    fontSize: 11,
    color: Colors.textDim,
    textAlign: "center",
    lineHeight: 18,
  },
});
