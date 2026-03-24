/**
 * CipherLink global application context.
 * Manages identity, contacts, groups, connection, and navigation.
 * @author Belkis Aslani
 */
import React, {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  useRef,
} from "react";
import { Alert } from "react-native";
import {
  initCrypto,
  toBase64,
  generateFullIdentity,
} from "../lib/crypto";
import type { FullIdentity } from "../lib/crypto";
import {
  saveKeypair,
  loadKeypair,
  saveSigningKeypair,
  loadSigningKeypair,
  saveContacts,
  loadContacts,
  saveGroups,
  loadGroups,
  saveSettings,
  loadSettings,
  saveDisplayName,
  loadDisplayName,
  deleteIdentity,
} from "../lib/secure-storage";
import type {
  StoredContact,
  StoredGroup,
  AppSettings,
} from "../lib/secure-storage";
import { CipherLinkClient } from "../lib/ws-client";
import type { ServerMessage } from "../lib/ws-client";

// --- Navigation ---

export type Screen =
  | { name: "onboarding" }
  | { name: "chats" }
  | { name: "chat"; contactKey: string; contactName: string }
  | { name: "newChat" }
  | { name: "groups" }
  | { name: "groupChat"; groupId: string; groupName: string }
  | { name: "createGroup" }
  | { name: "safetyNumber"; contactKey: string; contactName: string }
  | { name: "settings" }
  | { name: "backup" }
  | { name: "profile" };

export type Tab = "chats" | "groups" | "security" | "settings";

// --- Chat Messages ---

export interface ChatMessage {
  id: string;
  text: string;
  sender: "me" | "them";
  timestamp: number;
  encrypted: boolean;
  sealed?: boolean;
}

// --- Context type ---

interface AppContextType {
  // Identity
  identity: FullIdentity | null;
  displayName: string;
  setDisplayName: (name: string) => Promise<void>;
  generateNewIdentity: () => Promise<void>;
  resetIdentity: () => Promise<void>;
  isInitialized: boolean;

  // Navigation
  currentScreen: Screen;
  currentTab: Tab;
  navigate: (screen: Screen) => void;
  setTab: (tab: Tab) => void;
  goBack: () => void;

  // Connection
  connected: boolean;
  connectToServer: () => void;
  disconnectFromServer: () => void;
  client: CipherLinkClient | null;

  // Contacts
  contacts: StoredContact[];
  addContact: (publicKey: string, name: string) => Promise<void>;
  removeContact: (publicKey: string) => Promise<void>;
  verifyContact: (publicKey: string) => Promise<void>;

  // Groups
  groups: StoredGroup[];
  createGroup: (name: string, members: string[]) => Promise<string>;
  leaveGroup: (groupId: string) => Promise<void>;

  // Messages
  chatMessages: Map<string, ChatMessage[]>;
  addChatMessage: (contactKey: string, message: ChatMessage) => void;

  // Settings
  settings: AppSettings;
  updateSettings: (settings: Partial<AppSettings>) => Promise<void>;
}

const AppContext = createContext<AppContextType | null>(null);

export function useApp(): AppContextType {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error("useApp must be inside AppProvider");
  return ctx;
}

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [identity, setIdentity] = useState<FullIdentity | null>(null);
  const [displayName, setDisplayNameState] = useState("Anonymous");
  const [isInitialized, setIsInitialized] = useState(false);
  const [currentScreen, setCurrentScreen] = useState<Screen>({
    name: "onboarding",
  });
  const [currentTab, setCurrentTab] = useState<Tab>("chats");
  const [connected, setConnected] = useState(false);
  const [contacts, setContacts] = useState<StoredContact[]>([]);
  const [groups, setGroups] = useState<StoredGroup[]>([]);
  const [settings, setSettings] = useState<AppSettings>({
    serverUrl: "ws://localhost:4200",
    sealedSender: true,
    quantumResistant: true,
    messagePadding: true,
  });
  const [chatMessages, setChatMessages] = useState<
    Map<string, ChatMessage[]>
  >(new Map());

  const clientRef = useRef<CipherLinkClient | null>(null);
  const screenHistory = useRef<Screen[]>([]);

  // --- Initialize ---
  useEffect(() => {
    (async () => {
      await initCrypto();

      // Load stored data
      const [kp, sigKp, storedContacts, storedGroups, storedSettings, name] =
        await Promise.all([
          loadKeypair(),
          loadSigningKeypair(),
          loadContacts(),
          loadGroups(),
          loadSettings(),
          loadDisplayName(),
        ]);

      if (kp && sigKp) {
        setIdentity({
          signing: { publicKey: sigKp.publicKey, privateKey: sigKp.privateKey },
          dh: { publicKey: kp.publicKey, privateKey: kp.privateKey },
        });
        setCurrentScreen({ name: "chats" });
        setCurrentTab("chats");
      }

      setContacts(storedContacts);
      setGroups(storedGroups);
      setSettings(storedSettings);
      if (name) setDisplayNameState(name);
      setIsInitialized(true);
    })();
  }, []);

  // --- Identity ---

  const generateNewIdentity = useCallback(async () => {
    const fullId = await generateFullIdentity();
    await saveKeypair(fullId.dh.publicKey, fullId.dh.privateKey);
    await saveSigningKeypair(
      fullId.signing.publicKey,
      fullId.signing.privateKey,
    );
    setIdentity(fullId);
    setCurrentScreen({ name: "chats" });
    setCurrentTab("chats");
  }, []);

  const resetIdentity = useCallback(async () => {
    await deleteIdentity();
    clientRef.current?.disconnect();
    clientRef.current = null;
    setIdentity(null);
    setConnected(false);
    setContacts([]);
    setGroups([]);
    setChatMessages(new Map());
    setCurrentScreen({ name: "onboarding" });
  }, []);

  const handleSetDisplayName = useCallback(async (name: string) => {
    await saveDisplayName(name);
    setDisplayNameState(name);
  }, []);

  // --- Navigation ---

  const navigate = useCallback(
    (screen: Screen) => {
      screenHistory.current.push(currentScreen);
      setCurrentScreen(screen);
    },
    [currentScreen],
  );

  const goBack = useCallback(() => {
    const prev = screenHistory.current.pop();
    if (prev) {
      setCurrentScreen(prev);
    }
  }, []);

  const setTab = useCallback((tab: Tab) => {
    setCurrentTab(tab);
    screenHistory.current = [];
    switch (tab) {
      case "chats":
        setCurrentScreen({ name: "chats" });
        break;
      case "groups":
        setCurrentScreen({ name: "groups" });
        break;
      case "security":
        setCurrentScreen({ name: "profile" });
        break;
      case "settings":
        setCurrentScreen({ name: "settings" });
        break;
    }
  }, []);

  // --- Connection ---

  const handleServerMessage = useCallback(
    (msg: ServerMessage) => {
      if (msg.type === "message" && identity) {
        const senderKey = msg.envelope.senderPub;
        const chatMsg: ChatMessage = {
          id: msg.envelope.msgId,
          text: "", // Will be decrypted by chat screen
          sender: "them",
          timestamp: msg.envelope.ts,
          encrypted: true,
        };
        setChatMessages((prev) => {
          const newMap = new Map(prev);
          const existing = newMap.get(senderKey) ?? [];
          newMap.set(senderKey, [...existing, chatMsg]);
          return newMap;
        });
      } else if (msg.type === "group_message") {
        // Handle group messages
        const groupMsg: ChatMessage = {
          id: Date.now().toString(),
          text: "",
          sender: "them",
          timestamp: Date.now(),
          encrypted: true,
        };
        setChatMessages((prev) => {
          const newMap = new Map(prev);
          const key = `group:${msg.message.groupId}`;
          const existing = newMap.get(key) ?? [];
          newMap.set(key, [...existing, groupMsg]);
          return newMap;
        });
      } else if (msg.type === "error") {
        Alert.alert("Server Error", msg.message);
      }
    },
    [identity],
  );

  const connectToServer = useCallback(() => {
    if (!identity) return;
    if (clientRef.current?.connected) return;

    const pubB64 = toBase64(identity.dh.publicKey);
    const client = new CipherLinkClient(settings.serverUrl, pubB64);
    client.onMessage(handleServerMessage);
    client.onConnectionChange(setConnected);
    client.connect();
    clientRef.current = client;
  }, [identity, settings.serverUrl, handleServerMessage]);

  const disconnectFromServer = useCallback(() => {
    clientRef.current?.disconnect();
    clientRef.current = null;
    setConnected(false);
  }, []);

  // Auto-connect when identity is available
  useEffect(() => {
    if (identity && isInitialized && !clientRef.current) {
      connectToServer();
    }
    return () => {
      clientRef.current?.disconnect();
    };
  }, [identity, isInitialized]);

  // --- Contacts ---

  const addContact = useCallback(
    async (publicKey: string, name: string) => {
      const exists = contacts.find((c) => c.publicKey === publicKey);
      if (exists) {
        Alert.alert("Contact Exists", "This contact is already added.");
        return;
      }
      const updated = [
        ...contacts,
        { publicKey, name, addedAt: Date.now(), verified: false },
      ];
      setContacts(updated);
      await saveContacts(updated);
    },
    [contacts],
  );

  const removeContact = useCallback(
    async (publicKey: string) => {
      const updated = contacts.filter((c) => c.publicKey !== publicKey);
      setContacts(updated);
      await saveContacts(updated);
    },
    [contacts],
  );

  const verifyContact = useCallback(
    async (publicKey: string) => {
      const updated = contacts.map((c) =>
        c.publicKey === publicKey ? { ...c, verified: true } : c,
      );
      setContacts(updated);
      await saveContacts(updated);
    },
    [contacts],
  );

  // --- Groups ---

  const handleCreateGroup = useCallback(
    async (name: string, members: string[]) => {
      const groupId = toBase64(
        (await initCrypto()).randombytes_buf(16),
      );
      const newGroup: StoredGroup = {
        id: groupId,
        name,
        members,
        createdAt: Date.now(),
        myKeyId: "",
      };
      const updated = [...groups, newGroup];
      setGroups(updated);
      await saveGroups(updated);
      return groupId;
    },
    [groups],
  );

  const leaveGroup = useCallback(
    async (groupId: string) => {
      const updated = groups.filter((g) => g.id !== groupId);
      setGroups(updated);
      await saveGroups(updated);
    },
    [groups],
  );

  // --- Messages ---

  const addChatMessage = useCallback(
    (contactKey: string, message: ChatMessage) => {
      setChatMessages((prev) => {
        const newMap = new Map(prev);
        const existing = newMap.get(contactKey) ?? [];
        newMap.set(contactKey, [...existing, message]);
        return newMap;
      });
    },
    [],
  );

  // --- Settings ---

  const updateSettings = useCallback(
    async (updates: Partial<AppSettings>) => {
      const updated = { ...settings, ...updates };
      setSettings(updated);
      await saveSettings(updated);

      // Update client URL if changed
      if (updates.serverUrl && clientRef.current) {
        clientRef.current.disconnect();
        clientRef.current.updateUrl(updates.serverUrl);
        if (identity) {
          clientRef.current.connect();
        }
      }
    },
    [settings, identity],
  );

  return (
    <AppContext.Provider
      value={{
        identity,
        displayName,
        setDisplayName: handleSetDisplayName,
        generateNewIdentity,
        resetIdentity,
        isInitialized,
        currentScreen,
        currentTab,
        navigate,
        setTab,
        goBack,
        connected,
        connectToServer,
        disconnectFromServer,
        client: clientRef.current,
        contacts,
        addContact,
        removeContact,
        verifyContact,
        groups,
        createGroup: handleCreateGroup,
        leaveGroup,
        chatMessages,
        addChatMessage,
        settings,
        updateSettings,
      }}
    >
      {children}
    </AppContext.Provider>
  );
}
