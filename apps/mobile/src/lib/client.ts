/**
 * The app's one API client.
 *
 * `@aisoc/sdk` is React-Native-safe by construction: one runtime dependency,
 * no Node builtins, and `fetch`/`URL` taken from the global scope. The one
 * thing it needed was for the injected `fetch` to actually be used — it was
 * documented and never threaded through — which v9.0 fixed, and which matters
 * here because React Native's `fetch` is not the object the SDK module closed
 * over at import time.
 */

import { AiSOCClient } from "@aisoc/sdk";

export interface ClientConfig {
  baseUrl: string;
  token: string;
}

export function createClient({ baseUrl, token }: ClientConfig): AiSOCClient {
  return new AiSOCClient({
    baseUrl,
    token,
    // Explicit rather than relying on the default, so a future Hermes or
    // polyfill change is a one-line fix here instead of a silent regression.
    fetch: globalThis.fetch,
    headers: { "X-AiSOC-Client": "aisoc-mobile" },
  });
}
