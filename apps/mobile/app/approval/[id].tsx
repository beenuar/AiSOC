import { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, Alert, Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import { router, useLocalSearchParams } from "expo-router";
import * as LocalAuthentication from "expo-local-authentication";

import { actionLine, outcomeOf, type ApprovalLike } from "../../src/lib/approvals";
import { useResponder } from "../../src/hooks/useResponder";

/**
 * Decide one approval.
 *
 * Two behaviours here are deliberate and neither is cosmetic.
 *
 * **Approving asks for biometrics; denying does not.** A phone that has been
 * picked up off a desk should not be able to take a production host off the
 * network. Denying is the safe direction and adding friction to it means an
 * analyst who wants to stop an action has to fight the UI to do it.
 *
 * **The result is read back from the row, not from the button.** The API
 * carries the decision through to the execution service and records whether
 * it ran. A screen that shows "Approved" for a dispatch that failed tells an
 * analyst the host is contained when it is not.
 */
export default function DecideApproval() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const { client } = useResponder();
  const [approval, setApproval] = useState<ApprovalLike | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!client || !id) return;
    void (async () => {
      try {
        setApproval((await client.approvals.get(id)) as unknown as ApprovalLike);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Could not load this approval.");
      }
    })();
  }, [client, id]);

  const decide = useCallback(
    async (decision: "approve" | "deny") => {
      if (!client || !id) return;

      if (decision === "approve") {
        const hardware = await LocalAuthentication.hasHardwareAsync();
        const enrolled = await LocalAuthentication.isEnrolledAsync();
        if (hardware && enrolled) {
          const check = await LocalAuthentication.authenticateAsync({
            promptMessage: `Approve: ${approval ? actionLine(approval) : "this action"}`,
          });
          if (!check.success) return;
        }
      }

      setBusy(true);
      try {
        const updated = (await client.approvals.decide(id, decision)) as unknown as ApprovalLike;
        setApproval(updated);
      } catch (err) {
        // A non-2xx can mean "your decision was recorded and the action was
        // refused" rather than "nothing happened". Say the message verbatim
        // rather than paraphrasing it into something reassuring.
        Alert.alert("Decision not completed", err instanceof Error ? err.message : "Unknown error");
        try {
          setApproval((await client.approvals.get(id)) as unknown as ApprovalLike);
        } catch {
          /* leave the previous state; the alert already told the truth */
        }
      } finally {
        setBusy(false);
      }
    },
    [approval, client, id],
  );

  if (error) {
    return (
      <View style={styles.centre}>
        <Text style={styles.errorTitle}>Could not load this approval</Text>
        <Text style={styles.muted}>{error}</Text>
      </View>
    );
  }

  if (!approval) {
    return (
      <View style={styles.centre}>
        <ActivityIndicator color="#f8fafc" />
      </View>
    );
  }

  const outcome = outcomeOf(approval);
  const decided = approval.status !== "pending";

  return (
    <ScrollView contentContainerStyle={styles.page}>
      <Text style={styles.headline}>{actionLine(approval)}</Text>
      <Text style={styles.risk}>{approval.risk_level.toUpperCase()} RISK</Text>
      <Text style={styles.summary}>{approval.summary}</Text>

      {decided ? (
        <View style={[styles.outcome, outcome.kind === "failed" && styles.outcomeFailed]}>
          <Text style={styles.outcomeLabel}>{outcome.label}</Text>
          {outcome.detail ? <Text style={styles.muted}>{outcome.detail}</Text> : null}
          <Pressable style={styles.secondary} onPress={() => router.back()}>
            <Text style={styles.secondaryText}>Back to queue</Text>
          </Pressable>
        </View>
      ) : (
        <View style={styles.actions}>
          <Pressable
            style={[styles.button, styles.deny]}
            disabled={busy}
            onPress={() => void decide("deny")}
          >
            <Text style={styles.buttonText}>Deny</Text>
          </Pressable>
          <Pressable
            style={[styles.button, styles.approve]}
            disabled={busy}
            onPress={() => void decide("approve")}
          >
            <Text style={styles.buttonText}>Approve</Text>
          </Pressable>
        </View>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  page: { padding: 20, gap: 12 },
  centre: { flex: 1, alignItems: "center", justifyContent: "center", padding: 32, gap: 8 },
  headline: { color: "#f8fafc", fontSize: 22, fontWeight: "700" },
  risk: { color: "#fb923c", fontSize: 12, fontWeight: "700", letterSpacing: 1 },
  summary: { color: "#cbd5e1", fontSize: 15, lineHeight: 22 },
  actions: { flexDirection: "row", gap: 12, marginTop: 24 },
  button: { flex: 1, paddingVertical: 16, borderRadius: 10, alignItems: "center" },
  approve: { backgroundColor: "#dc2626" },
  deny: { backgroundColor: "#334155" },
  buttonText: { color: "#f8fafc", fontSize: 16, fontWeight: "700" },
  outcome: { marginTop: 24, gap: 8, padding: 16, borderRadius: 10, backgroundColor: "#1e293b" },
  outcomeFailed: { backgroundColor: "#450a0a" },
  outcomeLabel: { color: "#f8fafc", fontSize: 16, fontWeight: "700" },
  secondary: { marginTop: 12, paddingVertical: 12, alignItems: "center" },
  secondaryText: { color: "#93c5fd", fontSize: 15, fontWeight: "600" },
  errorTitle: { color: "#f87171", fontSize: 18, fontWeight: "600" },
  muted: { color: "#94a3b8", fontSize: 14 },
});
