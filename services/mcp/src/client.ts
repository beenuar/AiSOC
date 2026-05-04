/**
 * Minimal HTTP client for the AiSOC REST API.
 *
 * Why we hand-roll a fetch wrapper instead of pulling in `openapi-fetch`
 * (which `packages/sdk-ts` already uses):
 *
 *   1. The MCP server publishes to npm and is launched by `npx`. Each extra
 *      dependency widens the surface IDE hosts have to download on first
 *      run, which lengthens the "claude desktop says aisoc is loading"
 *      window. The native `fetch` in Node 18+ is enough.
 *   2. Static `openapi-fetch` typings would lock the MCP server to a
 *      specific OpenAPI snapshot at build time. Real MCP deployments may
 *      hit older AiSOC instances, and we'd rather degrade by tolerating an
 *      unknown field than crash on a parse error.
 *   3. We can centralise auth, timeout, retry, and error mapping in one
 *      place that matches the typed errors in `./errors.ts`.
 *
 * Auth model: the user provides a JWT or an `aisoc_*` API key; we send it
 * verbatim as `Authorization: Bearer <token>`. Both paths are handled by
 * the FastAPI dep `app.api.v1.deps.get_current_user`.
 */
import { ApiError, MissingApiKeyError, TransportError } from "./errors.js";
import type { Logger, ServerConfig } from "./config.js";

export interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  /** JSON body — automatically serialised + Content-Type set. */
  body?: unknown;
  /** Query string params; arrays are repeated, undefined values dropped. */
  query?: Record<string, string | number | boolean | undefined | string[]>;
  /** Override the per-request timeout. */
  timeoutMs?: number;
  /** Accept header; defaults to `application/json`. */
  accept?: string;
  /** Skip JSON parsing — used for `.md` / `.html` / `.pdf` report pulls. */
  raw?: boolean;
}

/** AiSOC client surface used by the tool layer. */
export class AisocClient {
  constructor(
    private readonly cfg: ServerConfig,
    private readonly log: Logger,
  ) {}

  /** GET helper that decodes JSON. */
  async get<T>(path: string, opts: Omit<RequestOptions, "method" | "body"> = {}): Promise<T> {
    return this.request<T>(path, { ...opts, method: "GET" });
  }

  /** POST helper that decodes JSON. */
  async post<T>(path: string, body: unknown, opts: Omit<RequestOptions, "method" | "body"> = {}): Promise<T> {
    return this.request<T>(path, { ...opts, method: "POST", body });
  }

  /** PATCH helper that decodes JSON. */
  async patch<T>(path: string, body: unknown, opts: Omit<RequestOptions, "method" | "body"> = {}): Promise<T> {
    return this.request<T>(path, { ...opts, method: "PATCH", body });
  }

  /**
   * Health probe — used by `aisoc-mcp doctor`. We hit `/health` rather than
   * `/api/v1/...` because the unauthenticated health endpoint exists on
   * every AiSOC build and lets `doctor` validate the URL even when the key
   * is missing or wrong.
   */
  async health(): Promise<{ status: string; reachable: boolean; raw?: unknown }> {
    try {
      const url = `${this.cfg.aisocUrl}/health`;
      const res = await this.fetchWithTimeout(url, {
        method: "GET",
        headers: { Accept: "application/json", "User-Agent": this.cfg.userAgent },
      });
      const json = await res.json().catch(() => ({}));
      return { status: String((json as { status?: unknown }).status ?? res.status), reachable: res.ok, raw: json };
    } catch (err) {
      return { status: "unreachable", reachable: false, raw: { error: String(err) } };
    }
  }

  // ------------------------------------------------------------------
  // Internals
  // ------------------------------------------------------------------

  private async request<T>(path: string, opts: RequestOptions): Promise<T> {
    if (!this.cfg.apiKey) {
      throw new MissingApiKeyError();
    }

    const url = this.buildUrl(path, opts.query);
    const headers: Record<string, string> = {
      Accept: opts.accept ?? "application/json",
      "User-Agent": this.cfg.userAgent,
      Authorization: `Bearer ${this.cfg.apiKey}`,
    };
    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
    }

    this.log.info(`→ ${opts.method ?? "GET"} ${path}`);

    const res = await this.fetchWithTimeout(url, {
      method: opts.method ?? "GET",
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    }, opts.timeoutMs);

    if (!res.ok) {
      let detail: string;
      try {
        const txt = await res.text();
        // FastAPI emits `{"detail": "..."}` for HTTPException; surface the
        // human message verbatim, fall back to the raw body otherwise.
        try {
          const parsed = JSON.parse(txt) as { detail?: unknown };
          detail = typeof parsed.detail === "string" ? parsed.detail : txt;
        } catch {
          detail = txt;
        }
      } catch {
        detail = `(no body)`;
      }
      throw new ApiError(res.status, path, detail);
    }

    if (opts.raw) {
      // Return raw text — used for report.md / report.html / report.pdf.
      return (await res.text()) as unknown as T;
    }
    if (res.status === 204) {
      return undefined as unknown as T;
    }
    return (await res.json()) as T;
  }

  private buildUrl(path: string, query?: RequestOptions["query"]): string {
    const base = this.cfg.aisocUrl;
    const normalisedPath = path.startsWith("/") ? path : `/${path}`;
    const url = new URL(`${base}${normalisedPath}`);
    if (query) {
      for (const [key, val] of Object.entries(query)) {
        if (val === undefined || val === null) continue;
        if (Array.isArray(val)) {
          for (const v of val) url.searchParams.append(key, String(v));
        } else {
          url.searchParams.set(key, String(val));
        }
      }
    }
    return url.toString();
  }

  private async fetchWithTimeout(
    url: string,
    init: RequestInit,
    timeoutMs?: number,
  ): Promise<Response> {
    const controller = new AbortController();
    const ms = timeoutMs ?? this.cfg.timeoutMs;
    const timer = setTimeout(() => controller.abort(), ms);
    try {
      return await fetch(url, { ...init, signal: controller.signal });
    } catch (err) {
      throw new TransportError(url, err);
    } finally {
      clearTimeout(timer);
    }
  }
}
