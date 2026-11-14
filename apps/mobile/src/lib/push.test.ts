import { describe, expect, it, vi } from "vitest";
import {
  RESPONDER_TOPICS,
  registerForPush,
  unregisterFromPush,
  type DeviceTokenProvider,
  type PushRegistrar,
} from "./push.js";

function provider(token: string | null, throws?: Error): DeviceTokenProvider {
  return {
    requestToken: async () => {
      if (throws) throw throws;
      return token;
    },
  };
}

function registrar(overrides: Partial<PushRegistrar> = {}): PushRegistrar {
  return {
    subscribe: vi.fn().mockResolvedValue({ status: "ok" }),
    unsubscribe: vi.fn().mockResolvedValue({ status: "ok" }),
    ...overrides,
  };
}

describe("registerForPush", () => {
  it("sends the device token to the same endpoint the browser uses", async () => {
    // One subscription table, not two. services/realtime already prunes dead
    // endpoints on 404/410, which is what APNs and FCM return for an
    // uninstalled app.
    const target = registrar();
    const result = await registerForPush(provider("apns-token-1"), target, "ios");

    expect(result.registered).toBe(true);
    expect(target.subscribe).toHaveBeenCalledWith({
      endpoint: "apns-token-1",
      keys: { p256dh: "ios", auth: "native" },
      topics: [...RESPONDER_TOPICS],
    });
  });

  it("carries the platform so the sender knows the transport", async () => {
    const target = registrar();
    await registerForPush(provider("fcm-token-1"), target, "android");

    const payload = (target.subscribe as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(payload.keys.p256dh).toBe("android");
  });

  it("treats a declined permission as a reason, not a crash", async () => {
    // Declining notifications is a normal choice. The app is still usable and
    // Settings needs to be able to explain a silent phone.
    const result = await registerForPush(provider(null), registrar(), "ios");

    expect(result.registered).toBe(false);
    expect(result.reason).toContain("permission");
  });

  it("does not throw when the OS call fails", async () => {
    const result = await registerForPush(provider(null, new Error("no APNs entitlement")), registrar(), "ios");

    expect(result.registered).toBe(false);
    expect(result.reason).toBe("no APNs entitlement");
  });

  it("does not throw when the server refuses the subscription", async () => {
    const target = registrar({ subscribe: vi.fn().mockRejectedValue(new Error("401")) });
    const result = await registerForPush(provider("t"), target, "ios");

    expect(result.registered).toBe(false);
    expect(result.reason).toBe("401");
  });

  it("subscribes only to topics a responder acts on", async () => {
    // Anything else is noise on a phone, and noise is how notifications get
    // switched off entirely.
    expect([...RESPONDER_TOPICS]).toEqual(["p0_alert", "agent_approval", "oncall_handoff"]);
  });
});

describe("unregisterFromPush", () => {
  it("reports success", async () => {
    expect(await unregisterFromPush(registrar(), "t")).toBe(true);
  });

  it("is best-effort — an uninstall cannot wait on the network", async () => {
    const target = registrar({ unsubscribe: vi.fn().mockRejectedValue(new Error("offline")) });
    expect(await unregisterFromPush(target, "t")).toBe(false);
  });
});
