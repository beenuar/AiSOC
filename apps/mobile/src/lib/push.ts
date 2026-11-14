/**
 * Native push registration — the one thing the PWA genuinely cannot do well.
 *
 * The responder PWA already implements Web Push with VAPID end to end, and on
 * Android it works. On iOS, Web Push requires the PWA to have been installed
 * to the home screen, and delivery has historically been unreliable even then.
 * For a product whose whole promise is "approve a containment from your
 * phone", a notification that sometimes does not arrive is the same as the
 * feature not existing.
 *
 * So this is the reason the native app exists. Everything else it does, the
 * PWA already did.
 *
 * The device token goes to the same `/api/v1/push/subscribe` endpoint the
 * browser uses. The server stores an endpoint and a pair of keys; for a native
 * token there is no keypair, so the token occupies the endpoint slot and the
 * key fields carry the platform. That keeps one subscription table rather than
 * two, and `services/realtime` already prunes dead endpoints on 404/410, which
 * is exactly what APNs and FCM return for an uninstalled app.
 */

export type PushPlatform = "ios" | "android";

export interface DeviceTokenProvider {
  /** Ask the OS. Returns null when the user declines, which is not an error. */
  requestToken(): Promise<string | null>;
}

export interface PushRegistrar {
  subscribe(payload: {
    endpoint: string;
    keys: { p256dh: string; auth: string };
    topics?: string[];
  }): Promise<unknown>;
  unsubscribe(endpoint: string): Promise<unknown>;
}

/** Topics a responder cares about. Anything else is noise on a phone. */
export const RESPONDER_TOPICS = ["p0_alert", "agent_approval", "oncall_handoff"] as const;

export interface RegistrationResult {
  registered: boolean;
  /** Why not, when not. Shown in Settings so a silent phone is explicable. */
  reason?: string;
  endpoint?: string;
}

/**
 * Register this device for push, or explain why it did not.
 *
 * Declining notifications is a normal choice, not a failure, and it must not
 * throw: the app is still usable, and the Settings screen needs to be able to
 * say "notifications are off" rather than showing a crash.
 */
export async function registerForPush(
  provider: DeviceTokenProvider,
  registrar: PushRegistrar,
  platform: PushPlatform,
  topics: readonly string[] = RESPONDER_TOPICS,
): Promise<RegistrationResult> {
  let token: string | null;
  try {
    token = await provider.requestToken();
  } catch (error) {
    return { registered: false, reason: describe(error) };
  }

  if (!token) {
    return { registered: false, reason: "Notification permission was not granted." };
  }

  try {
    await registrar.subscribe({
      endpoint: token,
      // No keypair exists for a native token; the platform is carried here so
      // the sender knows which transport to use for this row.
      keys: { p256dh: platform, auth: "native" },
      topics: [...topics],
    });
  } catch (error) {
    return { registered: false, reason: describe(error) };
  }

  return { registered: true, endpoint: token };
}

/** Best-effort, because an uninstall cannot wait on the network anyway. */
export async function unregisterFromPush(registrar: PushRegistrar, endpoint: string): Promise<boolean> {
  try {
    await registrar.unsubscribe(endpoint);
    return true;
  } catch {
    return false;
  }
}

function describe(error: unknown): string {
  if (error instanceof Error && error.message) return error.message;
  return "Push registration failed.";
}
