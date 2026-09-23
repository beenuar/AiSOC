import { Stack } from "expo-router";
import { StatusBar } from "expo-status-bar";
import { SafeAreaProvider } from "react-native-safe-area-context";

/**
 * Two screens deep, on purpose.
 *
 * This app has one job: let an on-call analyst decide an approval from a
 * phone. A queue and a detail view is the whole surface. Everything else a
 * SOC does — hunting, rule authoring, case management — is work for a desk,
 * and the responder PWA at `/responder` already covers the middle ground.
 */
export default function RootLayout() {
  return (
    <SafeAreaProvider>
      <StatusBar style="light" />
      <Stack
        screenOptions={{
          headerStyle: { backgroundColor: "#0b1020" },
          headerTintColor: "#f8fafc",
          contentStyle: { backgroundColor: "#0b1020" },
        }}
      >
        <Stack.Screen name="index" options={{ title: "Approvals" }} />
        <Stack.Screen name="approval/[id]" options={{ title: "Decide" }} />
        <Stack.Screen name="login" options={{ title: "Sign in", headerBackVisible: false }} />
      </Stack>
    </SafeAreaProvider>
  );
}
