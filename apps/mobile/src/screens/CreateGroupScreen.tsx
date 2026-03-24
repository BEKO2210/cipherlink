/**
 * Create Group screen — set up an encrypted group chat.
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
import { Colors } from "../theme/colors";
import { useApp } from "../context/AppContext";

export function CreateGroupScreen() {
  const { goBack, navigate, contacts, createGroup } = useApp();
  const [groupName, setGroupName] = useState("");
  const [selectedMembers, setSelectedMembers] = useState<Set<string>>(
    new Set(),
  );

  const toggleMember = (publicKey: string) => {
    setSelectedMembers((prev) => {
      const next = new Set(prev);
      if (next.has(publicKey)) {
        next.delete(publicKey);
      } else {
        next.add(publicKey);
      }
      return next;
    });
  };

  const handleCreate = async () => {
    if (!groupName.trim()) {
      Alert.alert("Error", "Enter a group name");
      return;
    }
    if (selectedMembers.size === 0) {
      Alert.alert("Error", "Select at least one member");
      return;
    }

    const members = Array.from(selectedMembers);
    const groupId = await createGroup(groupName.trim(), members);
    navigate({
      name: "groupChat",
      groupId,
      groupName: groupName.trim(),
    });
  };

  return (
    <View style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity onPress={goBack} style={styles.backButton}>
          <Text style={styles.backText}>{"<"}</Text>
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Create Group</Text>
      </View>

      <ScrollView contentContainerStyle={styles.content}>
        {/* Group name */}
        <View style={styles.section}>
          <Text style={styles.label}>Group Name</Text>
          <TextInput
            style={styles.input}
            value={groupName}
            onChangeText={setGroupName}
            placeholder="e.g. Team Alpha"
            placeholderTextColor={Colors.textDim}
            autoCapitalize="words"
          />
        </View>

        {/* Members */}
        <View style={styles.section}>
          <Text style={styles.label}>
            Select Members ({selectedMembers.size} selected)
          </Text>
          {contacts.length === 0 ? (
            <Text style={styles.noContacts}>
              No contacts yet. Add contacts first to create a group.
            </Text>
          ) : (
            contacts.map((contact) => (
              <TouchableOpacity
                key={contact.publicKey}
                style={[
                  styles.memberItem,
                  selectedMembers.has(contact.publicKey) &&
                    styles.memberSelected,
                ]}
                onPress={() => toggleMember(contact.publicKey)}
              >
                <View style={styles.memberAvatar}>
                  <Text style={styles.memberAvatarText}>
                    {contact.name.charAt(0).toUpperCase()}
                  </Text>
                </View>
                <View style={styles.memberInfo}>
                  <Text style={styles.memberName}>{contact.name}</Text>
                  <Text style={styles.memberKey} numberOfLines={1}>
                    {contact.publicKey.slice(0, 24)}...
                  </Text>
                </View>
                <View
                  style={[
                    styles.checkbox,
                    selectedMembers.has(contact.publicKey) &&
                      styles.checkboxChecked,
                  ]}
                >
                  {selectedMembers.has(contact.publicKey) && (
                    <Text style={styles.checkmark}>OK</Text>
                  )}
                </View>
              </TouchableOpacity>
            ))
          )}
        </View>

        {/* Info */}
        <View style={styles.infoBox}>
          <Text style={styles.infoTitle}>Group Encryption</Text>
          <Text style={styles.infoText}>
            Group messages use the Sender Keys protocol. Each member generates
            their own sender key and distributes it to the group. Messages are
            encrypted with a chain-ratcheted symmetric key and signed with
            Ed25519 for authenticity. Maximum 256 members per group.
          </Text>
        </View>

        {/* Create button */}
        <TouchableOpacity
          style={[
            styles.createButton,
            (selectedMembers.size === 0 || !groupName.trim()) &&
              styles.createButtonDisabled,
          ]}
          onPress={handleCreate}
          disabled={selectedMembers.size === 0 || !groupName.trim()}
        >
          <Text style={styles.createText}>Create Encrypted Group</Text>
        </TouchableOpacity>
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
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
  section: {
    marginBottom: 24,
  },
  label: {
    color: Colors.textSecondary,
    fontSize: 14,
    fontWeight: "600",
    marginBottom: 10,
  },
  input: {
    backgroundColor: Colors.bgSecondary,
    color: Colors.textPrimary,
    padding: 14,
    borderRadius: 10,
    fontSize: 16,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  noContacts: {
    color: Colors.textMuted,
    fontSize: 13,
    textAlign: "center",
    padding: 20,
  },
  memberItem: {
    flexDirection: "row",
    alignItems: "center",
    padding: 12,
    borderRadius: 10,
    backgroundColor: Colors.bgSecondary,
    marginBottom: 8,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  memberSelected: {
    borderColor: Colors.accent,
    backgroundColor: "rgba(233, 69, 96, 0.08)",
  },
  memberAvatar: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: Colors.accent,
    justifyContent: "center",
    alignItems: "center",
    marginRight: 12,
  },
  memberAvatarText: {
    color: "#fff",
    fontSize: 16,
    fontWeight: "bold",
  },
  memberInfo: {
    flex: 1,
  },
  memberName: {
    color: Colors.textPrimary,
    fontSize: 15,
    fontWeight: "600",
  },
  memberKey: {
    color: Colors.textDim,
    fontSize: 11,
    fontFamily: "monospace",
    marginTop: 2,
  },
  checkbox: {
    width: 24,
    height: 24,
    borderRadius: 12,
    borderWidth: 2,
    borderColor: Colors.textDim,
    justifyContent: "center",
    alignItems: "center",
  },
  checkboxChecked: {
    borderColor: Colors.accent,
    backgroundColor: Colors.accent,
  },
  checkmark: {
    color: "#fff",
    fontSize: 10,
    fontWeight: "bold",
  },
  infoBox: {
    padding: 16,
    backgroundColor: "rgba(124, 77, 255, 0.08)",
    borderRadius: 12,
    borderWidth: 1,
    borderColor: "rgba(124, 77, 255, 0.2)",
    marginBottom: 24,
  },
  infoTitle: {
    color: Colors.sealed,
    fontSize: 13,
    fontWeight: "bold",
    marginBottom: 6,
  },
  infoText: {
    color: Colors.textMuted,
    fontSize: 12,
    lineHeight: 18,
  },
  createButton: {
    backgroundColor: Colors.accent,
    padding: 16,
    borderRadius: 12,
    alignItems: "center",
  },
  createButtonDisabled: {
    opacity: 0.4,
  },
  createText: {
    color: "#fff",
    fontWeight: "bold",
    fontSize: 16,
  },
});
