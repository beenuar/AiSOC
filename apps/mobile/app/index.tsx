import { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, FlatList, Pressable, RefreshControl, StyleSheet, Text, View } from "react-native";
import { router } from "expo-router";

import { actionLine, queueOrder, type ApprovalLike } from "../src/lib/approvals";
import { useResponder } from "../src/hooks/useResponder";

/**
 * The approvals queue.
 *
 * Empty is the expected state, and it is stated as such rather than left
 * blank. An ambiguous empty screen is how the pre-v9.0 build hid the fact
 * that nothing in the platform ever created an approval: a queue with no
 * producer and a queue with no pending work look identical.
 */
export default function ApprovalsQueue() {
  const { client, ready, signedIn } = useResponder();
  const [approvals, setApprovals] = useState<ApprovalLike[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    if (!client) return;
    try {
      const page = await client.approvals.list({ status: "pending" });
      setApprovals([...(page.items as unknown as ApprovalLike[])].sort(queueOrder));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load approvals.");
    }
  }, [client]);

  useEffect(() => {
    if (ready && !signedIn) router.replace("/login");
  }, [ready, signedIn]);

  useEffect(() => {
    void load();
  }, [load]);

  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    await load();
    setRefreshing(false);
  }, [load]);

  if (!ready || (signedIn && approvals === null && !error)) {
    return (
      <View style={styles.centre}>
        <ActivityIndicator color="#f8fafc" />
      </View>
    );
  }

  if (error) {
    return (
      <View style={styles.centre}>
        <Text style={styles.errorTitle}>Could not load approvals</Text>
        <Text style={styles.muted}>{error}</Text>
      </View>
    );
  }

  return (
    <FlatList
      data={approvals ?? []}
      keyExtractor={(item) => item.id}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#f8fafc" />}
      ListEmptyComponent={
        <View style={styles.centre}>
          <Text style={styles.emptyTitle}>Nothing waiting on you</Text>
          <Text style={styles.muted}>
            Approvals appear here when an agent proposes an action that needs human sign-off.
          </Text>
        </View>
      }
      renderItem={({ item }) => (
        <Pressable style={styles.row} onPress={() => router.push(`/approval/${item.id}`)}>
          <View style={[styles.riskDot, riskStyle(item.risk_level)]} />
          <View style={styles.rowBody}>
            <Text style={styles.rowTitle}>{actionLine(item)}</Text>
            <Text style={styles.muted} numberOfLines={2}>
              {item.summary}
            </Text>
          </View>
        </Pressable>
      )}
    />
  );
}

function riskStyle(risk: string) {
  switch (risk) {
    case "critical":
      return { backgroundColor: "#f87171" };
    case "high":
      return { backgroundColor: "#fb923c" };
    case "medium":
      return { backgroundColor: "#fbbf24" };
    default:
      return { backgroundColor: "#64748b" };
  }
}

const styles = StyleSheet.create({
  centre: { flex: 1, alignItems: "center", justifyContent: "center", padding: 32, gap: 8 },
  emptyTitle: { color: "#f8fafc", fontSize: 18, fontWeight: "600" },
  errorTitle: { color: "#f87171", fontSize: 18, fontWeight: "600" },
  muted: { color: "#94a3b8", fontSize: 14, textAlign: "center" },
  row: { flexDirection: "row", gap: 12, padding: 16, borderBottomWidth: 1, borderBottomColor: "#1e293b" },
  riskDot: { width: 10, height: 10, borderRadius: 5, marginTop: 6 },
  rowBody: { flex: 1, gap: 4 },
  rowTitle: { color: "#f8fafc", fontSize: 16, fontWeight: "600" },
});
