/**
 * Hot-reloading local dev server for connector authors.
 *
 * Run via the CLI:
 *
 *     npx aisoc-connector dev ./src/my-connector.ts
 *
 * What it does:
 *
 *   1. Imports the file and pulls the default export (a
 *      ConnectorDefinition).
 *   2. Validates the manifest at boot.
 *   3. Stands up a tiny Node HTTP server on $PORT (default 7311) with
 *      these routes:
 *
 *        GET  /healthz             { ok: true, vendor, kind }
 *        GET  /manifest            JSON manifest (used by the platform
 *                                  to register the connector with the
 *                                  Python registry).
 *        POST /actions/<name>      Execute action with body
 *                                  { tenant_id, idempotency_key, input,
 *                                    config } and return the validated
 *                                  output.
 *        GET  /events              Server-Sent Events stream emitting
 *                                  reload events the platform listens
 *                                  for.
 *
 *   4. Watches the source tree with chokidar and re-imports the entry
 *      file (with a cache-busting query string) on each change. The
 *      fresh definition replaces the previous one atomically, and
 *      `/events` emits `{type: "reload"}` so the platform can
 *      re-register.
 *
 * The whole thing is intentionally tiny — no Express, no nodemon. We
 * want a contributor to read this file and understand the dev loop.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { pathToFileURL } from 'node:url';
import { resolve, dirname } from 'node:path';
import chokidar from 'chokidar';

import {
  type ConnectorDefinition,
  manifestForConnector,
  RiskClass,
} from './index.js';
import { z, type ZodTypeAny } from 'zod/v3';

interface DevState {
  def: ConnectorDefinition<ZodTypeAny> | null;
  filePath: string;
  reloadVersion: number;
  errors: string[];
}

async function importFresh(filePath: string): Promise<ConnectorDefinition<ZodTypeAny>> {
  const url = pathToFileURL(filePath).href + `?v=${Date.now()}`;
  const mod = (await import(url)) as { default?: ConnectorDefinition<ZodTypeAny> };
  if (!mod.default || typeof mod.default !== 'object') {
    throw new Error(
      `dev-server: ${filePath} must default-export a defineConnector() result`,
    );
  }
  return mod.default;
}

function jsonResponse(res: ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(body));
}

async function readJsonBody<T>(req: IncomingMessage): Promise<T> {
  return new Promise((resolveBody, rejectBody) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf-8') || '{}';
      try {
        resolveBody(JSON.parse(raw) as T);
      } catch (err) {
        rejectBody(err);
      }
    });
    req.on('error', rejectBody);
  });
}

function logFromCtx(invocationId: string): (level: string, msg: string, extra?: Record<string, unknown>) => void {
  return (level, msg, extra) => {
    const stamp = new Date().toISOString();
    const tag = level.toUpperCase().padStart(5);
    const payload = extra ? ' ' + JSON.stringify(extra) : '';
    process.stderr.write(`[${stamp}] ${tag} [${invocationId}] ${msg}${payload}\n`);
  };
}

interface ActionRequestBody {
  tenant_id: string;
  idempotency_key?: string;
  input?: unknown;
  config?: unknown;
}

export interface DevServerOptions {
  filePath: string;
  port: number;
  watch: boolean;
}

export async function startDevServer(opts: DevServerOptions): Promise<{ close: () => Promise<void> }> {
  const state: DevState = {
    def: null,
    filePath: resolve(opts.filePath),
    reloadVersion: 0,
    errors: [],
  };

  const sseClients = new Set<ServerResponse>();
  const broadcast = (event: Record<string, unknown>): void => {
    const payload = `data: ${JSON.stringify(event)}\n\n`;
    for (const client of sseClients) {
      try {
        client.write(payload);
      } catch {
        sseClients.delete(client);
      }
    }
  };

  async function reload(): Promise<void> {
    state.errors = [];
    try {
      state.def = await importFresh(state.filePath);
      state.reloadVersion += 1;
      process.stderr.write(
        `[aisoc-connector] loaded ${state.def.kind}/${state.def.vendor} v${state.def.version}` +
          ` (reload #${state.reloadVersion})\n`,
      );
      broadcast({ type: 'reload', version: state.reloadVersion, vendor: state.def.vendor });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      state.errors.push(msg);
      process.stderr.write(`[aisoc-connector] reload FAILED: ${msg}\n`);
      broadcast({ type: 'error', message: msg });
    }
  }

  await reload();

  const server = createServer(async (req, res) => {
    const url = req.url ?? '/';
    res.setHeader('access-control-allow-origin', '*');
    res.setHeader('access-control-allow-headers', 'content-type');
    if (req.method === 'OPTIONS') {
      res.statusCode = 204;
      res.end();
      return;
    }

    if (req.method === 'GET' && url === '/healthz') {
      jsonResponse(res, 200, {
        ok: state.def !== null,
        kind: state.def?.kind ?? null,
        vendor: state.def?.vendor ?? null,
        reload_version: state.reloadVersion,
        errors: state.errors,
      });
      return;
    }

    if (req.method === 'GET' && url === '/manifest') {
      if (!state.def) {
        jsonResponse(res, 503, { error: 'connector not loaded', errors: state.errors });
        return;
      }
      jsonResponse(res, 200, manifestForConnector(state.def));
      return;
    }

    if (req.method === 'GET' && url === '/events') {
      res.statusCode = 200;
      res.setHeader('content-type', 'text/event-stream');
      res.setHeader('cache-control', 'no-cache');
      res.setHeader('connection', 'keep-alive');
      res.write('retry: 2000\n\n');
      sseClients.add(res);
      req.on('close', () => sseClients.delete(res));
      return;
    }

    if (req.method === 'POST' && url.startsWith('/actions/')) {
      const actionName = url.slice('/actions/'.length).split('?')[0]!;
      if (!state.def) {
        jsonResponse(res, 503, { error: 'connector not loaded' });
        return;
      }
      const action = state.def.actions[actionName];
      if (!action) {
        jsonResponse(res, 404, { error: `unknown action ${actionName}` });
        return;
      }
      let body: ActionRequestBody;
      try {
        body = await readJsonBody<ActionRequestBody>(req);
      } catch {
        jsonResponse(res, 400, { error: 'invalid JSON body' });
        return;
      }
      if (!body.tenant_id) {
        jsonResponse(res, 400, { error: 'tenant_id required' });
        return;
      }
      let parsedInput: unknown;
      let parsedConfig: unknown;
      try {
        parsedInput = action.input.parse(body.input ?? {});
      } catch (err) {
        jsonResponse(res, 422, {
          error: 'input validation failed',
          detail: err instanceof Error ? err.message : String(err),
        });
        return;
      }
      try {
        parsedConfig = state.def.configSchema.parse(body.config ?? {});
      } catch (err) {
        jsonResponse(res, 422, {
          error: 'config validation failed',
          detail: err instanceof Error ? err.message : String(err),
        });
        return;
      }

      const invocationId = `inv_${Math.random().toString(36).slice(2, 10)}`;
      const ac = new AbortController();
      const baseUrl = String((parsedConfig as { baseUrl?: string }).baseUrl ?? '');
      const http = makeHttpClient(baseUrl, parsedConfig as Record<string, unknown>, ac.signal);

      try {
        const result = await action.handler({
          input: parsedInput as never,
          ctx: {
            config: parsedConfig as never,
            http,
            tenantId: body.tenant_id,
            idempotencyKey: body.idempotency_key ?? `auto_${invocationId}`,
            invocationId,
            log: logFromCtx(invocationId),
            signal: ac.signal,
          },
        });
        let output: unknown;
        try {
          output = action.output.parse(result);
        } catch (err) {
          jsonResponse(res, 500, {
            error: 'handler returned an output that does not match the schema',
            detail: err instanceof Error ? err.message : String(err),
          });
          return;
        }
        jsonResponse(res, 200, { output, invocation_id: invocationId });
      } catch (err) {
        jsonResponse(res, 500, {
          error: 'handler threw',
          detail: err instanceof Error ? err.message : String(err),
        });
      }
      return;
    }

    res.statusCode = 404;
    res.end();
  });

  await new Promise<void>((resolveServe, rejectServe) => {
    server.once('error', rejectServe);
    server.listen(opts.port, () => {
      process.stderr.write(
        `[aisoc-connector] dev server listening on http://localhost:${opts.port}\n`,
      );
      resolveServe();
    });
  });

  let watcher: chokidar.FSWatcher | null = null;
  if (opts.watch) {
    watcher = chokidar.watch(dirname(state.filePath), {
      ignored: ['**/node_modules/**', '**/dist/**'],
      ignoreInitial: true,
    });
    watcher.on('change', (path) => {
      process.stderr.write(`[aisoc-connector] file changed: ${path}\n`);
      void reload();
    });
  }

  return {
    close: async () => {
      if (watcher) await watcher.close();
      await new Promise<void>((r) => server.close(() => r()));
    },
  };
}

function makeHttpClient(
  baseUrl: string,
  config: Record<string, unknown>,
  signal: AbortSignal,
): {
  get: <T>(p: string, init?: RequestInit) => Promise<T>;
  post: <T>(p: string, body?: unknown, init?: RequestInit) => Promise<T>;
  put: <T>(p: string, body?: unknown, init?: RequestInit) => Promise<T>;
  delete: <T>(p: string, init?: RequestInit) => Promise<T>;
  fetch: (p: string, init?: RequestInit) => Promise<Response>;
} {
  const join = (p: string): string => {
    if (/^https?:/.test(p)) return p;
    if (!baseUrl) return p;
    return baseUrl.replace(/\/$/, '') + (p.startsWith('/') ? p : '/' + p);
  };
  const authHeaders: Record<string, string> = {};
  if (typeof config.token === 'string') {
    authHeaders['authorization'] = `Bearer ${config.token}`;
  } else if (typeof config.apiKey === 'string') {
    authHeaders['x-api-key'] = String(config.apiKey);
  }

  async function call<T>(method: string, path: string, body?: unknown, init?: RequestInit): Promise<T> {
    const headers: Record<string, string> = {
      ...authHeaders,
      ...((init?.headers as Record<string, string>) ?? {}),
    };
    if (body !== undefined && headers['content-type'] === undefined) {
      headers['content-type'] = 'application/json';
    }
    const r = await fetch(join(path), {
      ...init,
      method,
      signal,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!r.ok) {
      const text = await r.text().catch(() => '');
      throw new Error(`http ${method} ${path} failed: ${r.status} ${text.slice(0, 200)}`);
    }
    const ct = r.headers.get('content-type') ?? '';
    if (ct.includes('application/json')) {
      return (await r.json()) as T;
    }
    return (await r.text()) as unknown as T;
  }

  return {
    get: <T>(p: string, init?: RequestInit) => call<T>('GET', p, undefined, init),
    post: <T>(p: string, body?: unknown, init?: RequestInit) => call<T>('POST', p, body, init),
    put: <T>(p: string, body?: unknown, init?: RequestInit) => call<T>('PUT', p, body, init),
    delete: <T>(p: string, init?: RequestInit) => call<T>('DELETE', p, undefined, init),
    fetch: (p: string, init?: RequestInit) =>
      fetch(join(p), {
        ...init,
        signal,
        headers: { ...authHeaders, ...((init?.headers as Record<string, string>) ?? {}) },
      }),
  };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  // Allow `tsx src/dev.ts ./examples/echo/index.ts` to just work.
  const [, , file, portArg] = process.argv;
  if (!file) {
    process.stderr.write(
      'usage: aisoc-connector dev <file.ts> [--port=7311] [--no-watch]\n',
    );
    process.exit(2);
  }
  const port = Number(portArg?.replace(/^--port=/, '') ?? process.env.PORT ?? 7311);
  const noWatch = process.argv.includes('--no-watch');
  await startDevServer({ filePath: file, port, watch: !noWatch });
}

// Re-export RiskClass so consumers don't need a second import.
export { RiskClass };
