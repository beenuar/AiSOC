import { useCallback, useState } from "react";
import { ActivityIndicator, Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import { router } from "expo-router";

import { useResponder } from "../src/hooks/useResponder";

/**
 * Sign in.
 *
 * Email and password against `POST /api/v1/auth/login`. Passkeys are the
 * better answer on a phone and the API already supports them
 * (`/api/v1/passkeys/*`, which the responder PWA uses), but WebAuthn from a
 * React Native context needs a native credential-manager bridge that is not
 * wired here yet. Saying so is better than a "Sign in with passkey" button
 * that fails when tapped.
 */
export default function Login() {
  const { baseUrl, signIn } = useResponder();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch(`${baseUrl.replace(/\/$/, "")}/api/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      if (!response.ok) {
        setError(response.status === 401 ? "Email or password is wrong." : `Sign-in failed (${response.status}).`);
        return;
      }
      const body = (await response.json()) as { access_token?: string };
      if (!body.access_token) {
        setError("The server did not return a token.");
        return;
      }
      await signIn(body.access_token);
      router.replace("/");
    } catch {
      setError(`Could not reach ${baseUrl}.`);
    } finally {
      setBusy(false);
    }
  }, [baseUrl, email, password, signIn]);

  return (
    <View style={styles.page}>
      <Text style={styles.headline}>AiSOC</Text>
      <Text style={styles.muted}>Approve or deny a containment from your phone.</Text>

      <TextInput
        style={styles.input}
        placeholder="Email"
        placeholderTextColor="#64748b"
        autoCapitalize="none"
        autoCorrect={false}
        keyboardType="email-address"
        value={email}
        onChangeText={setEmail}
      />
      <TextInput
        style={styles.input}
        placeholder="Password"
        placeholderTextColor="#64748b"
        secureTextEntry
        value={password}
        onChangeText={setPassword}
      />

      {error ? <Text style={styles.error}>{error}</Text> : null}

      <Pressable style={styles.button} disabled={busy} onPress={() => void submit()}>
        {busy ? <ActivityIndicator color="#f8fafc" /> : <Text style={styles.buttonText}>Sign in</Text>}
      </Pressable>

      <Text style={styles.footnote}>Connecting to {baseUrl}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  page: { flex: 1, justifyContent: "center", padding: 24, gap: 12 },
  headline: { color: "#f8fafc", fontSize: 32, fontWeight: "700" },
  muted: { color: "#94a3b8", fontSize: 15, marginBottom: 12 },
  input: {
    backgroundColor: "#1e293b",
    color: "#f8fafc",
    borderRadius: 10,
    paddingHorizontal: 14,
    paddingVertical: 14,
    fontSize: 16,
  },
  button: { backgroundColor: "#dc2626", borderRadius: 10, paddingVertical: 16, alignItems: "center", marginTop: 8 },
  buttonText: { color: "#f8fafc", fontSize: 16, fontWeight: "700" },
  error: { color: "#f87171", fontSize: 14 },
  footnote: { color: "#475569", fontSize: 12, textAlign: "center", marginTop: 16 },
});
