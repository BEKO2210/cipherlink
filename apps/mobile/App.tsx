/**
 * CipherLink — E2EE Chat App.
 *
 * Full-featured encrypted messenger with Signal Protocol architecture:
 * - X3DH key agreement + Double Ratchet
 * - XChaCha20-Poly1305 AEAD encryption
 * - Sealed sender (anonymous messaging)
 * - Post-quantum hybrid KEM (X25519 + ML-KEM-768)
 * - Sender Keys group messaging with Ed25519 signatures
 * - Safety number verification (60-digit fingerprints)
 * - Encrypted backups with Argon2id + Shamir key splitting
 * - Zero-knowledge relay server
 *
 * @author Belkis Aslani
 * @license MIT
 */
import "react-native-get-random-values";
import React, { useEffect, useCallback } from "react";
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
  BackHandler,
  Platform,
  StatusBar as RNStatusBar,
} from "react-native";
import {
  SafeAreaProvider,
  SafeAreaView,
  useSafeAreaInsets,
} from "react-native-safe-area-context";
import { StatusBar } from "expo-status-bar";
import { AppProvider, useApp } from "./src/context/AppContext";
import type { Tab } from "./src/context/AppContext";
import { Colors } from "./src/theme/colors";

// Screens
import { OnboardingScreen } from "./src/screens/OnboardingScreen";
import { ChatsListScreen } from "./src/screens/ChatsListScreen";
import { ChatScreen } from "./src/screens/ChatScreen";
import { NewChatScreen } from "./src/screens/NewChatScreen";
import { GroupsScreen } from "./src/screens/GroupsScreen";
import { GroupChatScreen } from "./src/screens/GroupChatScreen";
import { CreateGroupScreen } from "./src/screens/CreateGroupScreen";
import { SafetyNumberScreen } from "./src/screens/SafetyNumberScreen";
import { SettingsScreen } from "./src/screens/SettingsScreen";
import { BackupScreen } from "./src/screens/BackupScreen";
import { ProfileScreen } from "./src/screens/ProfileScreen";

/** Android status bar height for screens that need manual padding */
export const STATUSBAR_HEIGHT =
  Platform.OS === "android" ? (RNStatusBar.currentHeight ?? 24) : 0;

function AppContent() {
  const { currentScreen, currentTab, setTab, isInitialized, identity, goBack } =
    useApp();

  // Android hardware back button support
  useEffect(() => {
    const handler = () => {
      const isTabScreen = ["chats", "groups", "profile", "settings"].includes(
        currentScreen.name,
      );
      if (currentScreen.name === "onboarding" || isTabScreen) {
        return false; // Let system handle (exit app)
      }
      goBack();
      return true; // Prevent default
    };
    const sub = BackHandler.addEventListener("hardwareBackPress", handler);
    return () => sub.remove();
  }, [currentScreen.name, goBack]);

  if (!isInitialized) {
    return (
      <View style={styles.loading}>
        <ActivityIndicator size="large" color={Colors.accent} />
        <Text style={styles.loadingText}>Initializing encryption...</Text>
      </View>
    );
  }

  const renderScreen = () => {
    switch (currentScreen.name) {
      case "onboarding":
        return <OnboardingScreen />;
      case "chats":
        return <ChatsListScreen />;
      case "chat":
        return (
          <ChatScreen
            contactKey={currentScreen.contactKey}
            contactName={currentScreen.contactName}
          />
        );
      case "newChat":
        return <NewChatScreen />;
      case "groups":
        return <GroupsScreen />;
      case "groupChat":
        return (
          <GroupChatScreen
            groupId={currentScreen.groupId}
            groupName={currentScreen.groupName}
          />
        );
      case "createGroup":
        return <CreateGroupScreen />;
      case "safetyNumber":
        return (
          <SafetyNumberScreen
            contactKey={currentScreen.contactKey}
            contactName={currentScreen.contactName}
          />
        );
      case "settings":
        return <SettingsScreen />;
      case "backup":
        return <BackupScreen />;
      case "profile":
        return <ProfileScreen />;
      default:
        return <ChatsListScreen />;
    }
  };

  const showTabBar =
    identity !== null &&
    ["chats", "groups", "profile", "settings"].includes(currentScreen.name);

  return (
    <View style={styles.root}>
      <View style={styles.screenContainer}>{renderScreen()}</View>
      {showTabBar && <TabBar currentTab={currentTab} onTabPress={setTab} />}
    </View>
  );
}

// --- Tab Bar with bottom safe area ---

interface TabBarProps {
  currentTab: Tab;
  onTabPress: (tab: Tab) => void;
}

const TABS: { key: Tab; label: string; icon: string }[] = [
  { key: "chats", label: "Chats", icon: "MSG" },
  { key: "groups", label: "Groups", icon: "GRP" },
  { key: "security", label: "Security", icon: "KEY" },
  { key: "settings", label: "Settings", icon: "SET" },
];

function TabBar({ currentTab, onTabPress }: TabBarProps) {
  const insets = useSafeAreaInsets();

  return (
    <View
      style={[
        tabStyles.container,
        { paddingBottom: Math.max(insets.bottom, 8) },
      ]}
    >
      {TABS.map((tab) => {
        const isActive = currentTab === tab.key;
        return (
          <TouchableOpacity
            key={tab.key}
            style={tabStyles.tab}
            onPress={() => onTabPress(tab.key)}
            activeOpacity={0.7}
            accessibilityRole="tab"
            accessibilityLabel={tab.label}
            accessibilityState={{ selected: isActive }}
          >
            <View
              style={[
                tabStyles.iconContainer,
                isActive && tabStyles.iconActive,
              ]}
            >
              <Text
                style={[
                  tabStyles.icon,
                  isActive && tabStyles.iconTextActive,
                ]}
              >
                {tab.icon}
              </Text>
            </View>
            <Text
              style={[tabStyles.label, isActive && tabStyles.labelActive]}
            >
              {tab.label}
            </Text>
          </TouchableOpacity>
        );
      })}
    </View>
  );
}

// --- Root App ---

export default function App() {
  return (
    <SafeAreaProvider>
      <SafeAreaView style={styles.safeArea} edges={["top"]}>
        <StatusBar style="light" />
        <AppProvider>
          <AppContent />
        </AppProvider>
      </SafeAreaView>
    </SafeAreaProvider>
  );
}

// --- Styles ---

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: Colors.bg,
  },
  root: {
    flex: 1,
    backgroundColor: Colors.bg,
  },
  screenContainer: {
    flex: 1,
  },
  loading: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
    backgroundColor: Colors.bg,
  },
  loadingText: {
    color: Colors.textMuted,
    fontSize: 14,
    marginTop: 12,
  },
});

const tabStyles = StyleSheet.create({
  container: {
    flexDirection: "row",
    backgroundColor: Colors.bgPrimary,
    borderTopWidth: 1,
    borderTopColor: Colors.border,
    paddingTop: 6,
  },
  tab: {
    flex: 1,
    alignItems: "center",
    paddingVertical: 4,
  },
  iconContainer: {
    width: 36,
    height: 28,
    borderRadius: 14,
    justifyContent: "center",
    alignItems: "center",
    marginBottom: 2,
  },
  iconActive: {
    backgroundColor: "rgba(233, 69, 96, 0.15)",
  },
  icon: {
    fontSize: 11,
    fontWeight: "bold",
    color: Colors.textMuted,
  },
  iconTextActive: {
    color: Colors.accent,
  },
  label: {
    fontSize: 10,
    color: Colors.textMuted,
    fontWeight: "500",
  },
  labelActive: {
    color: Colors.accent,
    fontWeight: "700",
  },
});
