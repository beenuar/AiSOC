import Constants from "expo-constants";
import * as SecureStore from "expo-secure-store";
import { useCallback, useEffect, useMemo, useState } from "react";

import type { AiSOCClient } from "@aisoc/sdk";
import { createClient } from "../lib/client";
import { Session } from "../lib/session";

/**
 * Session plus client, resolved once for the whole app.
 *
 * `ready` and `signedIn` are separate because they are different questions.
 * Before the secure store has been read, the app does not know whether it is
 * signed in — rendering the login screen during that window would bounce a
 * signed-in analyst back to a password prompt every cold start, which on a
 * phone is the difference between deciding in ten seconds and not deciding.
 */
export function useResponder() {
  const [token, setToken] = useState<string | null>(null);
  const [ready, setReady] = useState(false);

  const session = useMemo(() => new Session(SecureStore), []);

  const baseUrl = useMemo(() => {
    const configured = Constants.expoConfig?.extra?.apiBaseUrl;
    return typeof configured === "string" && configured ? configured : "http://localhost:8000";
  }, []);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const current = await session.current();
      if (!cancelled) {
        setToken(current);
        setReady(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [session]);

  const signIn = useCallback(
    async (newToken: string) => {
      await session.save(newToken);
      setToken(newToken);
    },
    [session],
  );

  const signOut = useCallback(async () => {
    await session.clear();
    setToken(null);
  }, [session]);

  const client: AiSOCClient | null = useMemo(
    () => (token ? createClient({ baseUrl, token }) : null),
    [baseUrl, token],
  );

  return { client, ready, signedIn: Boolean(token), baseUrl, signIn, signOut };
}
