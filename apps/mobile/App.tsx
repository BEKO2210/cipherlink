/**
 * CipherLink — E2EE Chat App.
 *
 * WARNING: This is a security skeleton for educational/demo purposes.
 * NOT suitable for high-risk production use without significant hardening.
 * See docs/CRYPTO_LIMITS.md for missing features.
 *
 * @author Belkis Aslani
 * @license MIT
 */
import "react-native-get-random-values";
import React, { useState, useCallback } from "react";
import { SafeAreaView, StyleSheet } from "react-native";
import { StatusBar } from "expo-status-bar";
import { SetupScreen } from "./src/screens/SetupScreen";
import { ChatScreen } from "./src/screens/ChatScreen";

export default function App() {
  const [identity, setIdentity] = useState<{
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  } | null>(null);

  const handleReady = useCallback(
    (publicKey: Uint8Array, privateKey: Uint8Array) => {
      setIdentity({ publicKey, privateKey });
    },
    [],
  );

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar style="light" />
      {identity ? (
        <ChatScreen
          publicKey={identity.publicKey}
          privateKey={identity.privateKey}
        />
      ) : (
        <SetupScreen onReady={handleReady} />
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#1a1a2e",
  },
});
