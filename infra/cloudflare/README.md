# Cloudflare Tunnel for `tryaisoc.com`

This directory contains everything needed to expose a local AiSOC stack to the
public internet through a Cloudflare Tunnel, anchored at the domain
[`tryaisoc.com`](https://tryaisoc.com).

It is the canonical way to host a **public, read-only demo** of AiSOC on your
own machine without opening a single inbound port on your router or firewall.

> **Why a tunnel and not a direct LAN bind?**
> Compose binds every service port to `127.0.0.1` by default (see
> `docker-compose.yml` and `docker-compose.demo.yml`). That keeps the dev
> passwords that ship with the repo from leaking onto your LAN. The tunnel
> punches a single outbound TLS connection to Cloudflare and lets us route
> traffic in front of `cloudflared` instead of in front of Compose.

## Prerequisites

1. **`cloudflared` installed** — `brew install cloudflared` (macOS) or
   [follow the upstream install guide](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/install-and-setup/installation/).
2. **A Cloudflare account that owns `tryaisoc.com`** (or any other zone you
   control — point `tunnel.sh` at it via the `DOMAIN` env var; no source edits
   required).
3. **One auth method** (see *Two auth modes* below).
4. **A running stack** — the demo profile from `pnpm aisoc:demo` is the
   intended target. The wrapper `pnpm demo:public` (see below) brings the
   stack up and the tunnel up in one command.

## Two auth modes

`tunnel.sh` accepts either of the two auth shapes Cloudflare supports today.
The script auto-detects which one is in use; you only need to supply one.

### (A) Origin-cert mode — default

Run `cloudflared tunnel login` once. It opens a browser, you pick the zone, and
`cloudflared` writes `~/.cloudflared/cert.pem`. From there, `tunnel.sh` will:

1. Create / reuse the named tunnel (`TUNNEL_NAME`, default `aisoc-tryaisoc`).
2. Render `config.yml` from `config.yml.example`.
3. Add DNS routes for the apex + each subdomain in `SUBDOMAINS`.
4. Run `cloudflared tunnel run` against the rendered config.

Choose this mode when you want one command to provision the tunnel,
ingress, and DNS records.

### (B) Tunnel-token mode — for headless / restricted-browser hosts

If `cloudflared tunnel login` won't write a cert (corporate browsers, locked-down
machines, headless servers, etc), create the tunnel in the [Cloudflare Zero Trust
dashboard](https://one.dash.cloudflare.com/) instead:

1. **Networks → Tunnels → Create a tunnel → Cloudflared.**
2. Name the tunnel (e.g. `aisoc-tryaisoc`) and copy the long `--token ey…` value
   the dashboard hands you.
3. **Public Hostnames** tab — add four entries on the zone you control:

   | Subdomain | Type   | URL                       |
   | --------- | ------ | ------------------------- |
   | *(apex)*  | `HTTP` | `localhost:3000`          |
   | `api`     | `HTTP` | `localhost:8000`          |
   | `ws`      | `HTTP` | `localhost:8086`          |
   | `docs`    | `HTTP` | `localhost:3001`          |

4. Export the token and run the wrapper:

   ```sh
   export CLOUDFLARE_TUNNEL_TOKEN='ey…'
   pnpm demo:public            # or: pnpm demo:public:tunnel-only
   ```

When `CLOUDFLARE_TUNNEL_TOKEN` is set, `tunnel.sh` skips `cert.pem`, the local
`config.yml` render, and the DNS-route step — the dashboard owns all of that —
and execs `cloudflared tunnel run --token <token>` directly. `TUNNEL_NAME` and
`SUBDOMAINS` are ignored in this mode (the dashboard already knows them).

## Topology

```
  ┌──────────────────────────┐         ┌─────────────────────────────────┐
  │  Visitor (browser)       │  TLS →  │  Cloudflare edge (tryaisoc.com) │
  └──────────────────────────┘         └─────────────────────────────────┘
                                                       │
                                                       │  outbound-only
                                                       │  QUIC / HTTP/2
                                                       ▼
                                              ┌────────────────────┐
                                              │  cloudflared       │
                                              │  (this machine)    │
                                              └────────────────────┘
                                                  │       │       │
                                  127.0.0.1:3000  │       │  127.0.0.1:8000
                                  (web)           │       │  (api)
                                                  ▼       ▼
                                          ┌───────────────────────┐
                                          │  Docker Compose stack │
                                          │  (postgres, kafka,    │
                                          │   api, web, agents,   │
                                          │   realtime…)          │
                                          └───────────────────────┘
```

The four hostnames the tunnel publishes:

| Hostname                 | Routes to                  | Service                   |
| ------------------------ | -------------------------- | ------------------------- |
| `tryaisoc.com`           | `http://localhost:3000`    | Next.js web app           |
| `api.tryaisoc.com`       | `http://localhost:8000`    | FastAPI core API          |
| `ws.tryaisoc.com`        | `http://localhost:8086`    | Realtime WebSocket gateway|
| `docs.tryaisoc.com`      | `http://localhost:3001`    | Docusaurus (optional)     |

Cloudflare terminates TLS and gives you HTTPS for free. The web app inside the
container still talks to `localhost:8000` for its server-side fetches because
that's where `cloudflared` lives, not where browsers are pointing — the
browser hits `api.tryaisoc.com`, which `cloudflared` rewrites to
`localhost:8000`.

## Quick start

There are three pnpm wrappers for the common shapes:

```sh
# Stack + tunnel, all-in-one (this is what most people want):
pnpm demo:public

# Stack already up — just bring the tunnel online:
pnpm demo:public:tunnel-only

# Provision the tunnel + DNS, but DON'T run it
# (handy before `cloudflared service install` for a 24/7 deployment):
SKIP_RUN=1 pnpm demo:public:setup
```

Under the hood:

- `pnpm demo:public` → [`scripts/demo-public.sh`](../../scripts/demo-public.sh) → runs
  `pnpm aisoc:demo --no-open`, then execs `infra/cloudflare/tunnel.sh`.
- `pnpm demo:public:tunnel-only` → same wrapper with `--skip-stack`.
- `pnpm demo:public:setup` → `bash infra/cloudflare/tunnel.sh` directly, with
  no stack management.

If you'd rather drive the pieces yourself:

```sh
# 1. Make sure the stack is up.
pnpm aisoc:demo            # or: docker compose -f docker-compose.demo.yml up -d

# 2. Bring up the tunnel.
bash infra/cloudflare/tunnel.sh
```

`tunnel.sh` in **origin-cert mode** (default, no token set) will:

1. Verify `cloudflared` is installed and authenticated (`~/.cloudflared/cert.pem`).
2. Create a tunnel named `aisoc-tryaisoc` (configurable via `TUNNEL_NAME`) if
   it doesn't already exist.
3. Render `config.yml` from `config.yml.example`, substituting the tunnel
   UUID, the credentials path, and the apex domain (`DOMAIN`, default
   `tryaisoc.com`).
4. Validate the rendered config with `cloudflared tunnel ingress validate`.
5. Create / update DNS routes for the apex and each subdomain in
   `SUBDOMAINS` (default `"api ws docs"`).
6. Run `cloudflared tunnel --config <generated-config> run`.

`tunnel.sh` in **token mode** (`CLOUDFLARE_TUNNEL_TOKEN` set) will:

1. Verify `cloudflared` is installed.
2. Skip everything cert-bound (no `cert.pem` check, no `config.yml` render, no
   DNS routes, no `TUNNEL_NAME` lookup) — the dashboard owns all of that.
3. Exec `cloudflared tunnel run --token "$CLOUDFLARE_TUNNEL_TOKEN"`.

The first run takes ~10 seconds for DNS propagation; subsequent runs are
instant.

### Environment variables

Both `pnpm demo:public*` and `bash infra/cloudflare/tunnel.sh` honour the
same set:

| Var                       | Default          | Purpose                                                  |
| ------------------------- | ---------------- | -------------------------------------------------------- |
| `DOMAIN`                  | `tryaisoc.com`   | Apex domain. In **origin-cert mode** the script routes `DOMAIN` and each subdomain in `SUBDOMAINS` to the tunnel. In **token mode** it's used purely for log/banner output (the dashboard already knows the hostnames). |
| `TUNNEL_NAME`             | `aisoc-tryaisoc` | Cloudflare tunnel name. Reused if it already exists. **Ignored in token mode** — the dashboard owns the tunnel name. |
| `SUBDOMAINS`              | `"api ws docs"`  | Space-separated list of subdomains to route in addition to the apex. **Ignored in token mode** — the dashboard already routes them. |
| `SKIP_DNS`                | *(unset)*        | If set to `1`, don't touch DNS records (assume they exist). **No-op in token mode** — DNS is already managed by the dashboard. |
| `SKIP_RUN`                | *(unset)*        | If set to `1`, set everything up but don't run the tunnel — pair with `cloudflared service install` for a 24/7 setup. Honoured in both modes. |
| `CFD_DIR`                 | `~/.cloudflared` | Where `cloudflared`'s `cert.pem`, credentials JSONs, and rendered configs live. **Only consulted in origin-cert mode.** |
| `CLOUDFLARE_TUNNEL_TOKEN` | *(unset)*        | If set, switches the script to **token mode**: skips `cert.pem` / tunnel-create / DNS / config-render and execs `cloudflared tunnel run --token <value>` directly. Use the long `ey…` token from the Cloudflare Zero Trust dashboard (Networks → Tunnels → Install connector → Docker tab). |

`scripts/demo-public.sh --help` documents the wrapper-level flags
(`--skip-stack`, `--no-open`, etc.) on top of these.

## Files

| File                  | Purpose                                                                                      |
| --------------------- | -------------------------------------------------------------------------------------------- |
| `tunnel.sh`           | Idempotent helper that creates the tunnel, sets DNS routes, and runs `cloudflared`.          |
| `config.yml.example`  | Ingress template. The script renders this into `~/.cloudflared/aisoc-tryaisoc.yml`.           |
| `README.md`           | This file.                                                                                   |

The rendered `aisoc-tryaisoc.yml` and the `*-credentials.json` file live in
`~/.cloudflared/` — they are **not** stored in the repo. The credentials JSON
is what proves to Cloudflare that this machine is allowed to run the tunnel.

## Hosting your own demo on a different domain

You don't need to edit any files. Both `tunnel.sh` and `config.yml.example`
were written to be domain-agnostic — the script renders the template, and the
template uses placeholders that the script substitutes at run time.

```sh
# Apex + the same default subdomains (api, ws, docs) on a zone you own:
DOMAIN=aisoc.example.com pnpm demo:public

# Custom tunnel name + a different set of subdomains:
DOMAIN=aisoc.example.com \
TUNNEL_NAME=acme-aisoc \
SUBDOMAINS="api ws" \
  pnpm demo:public

# Set everything up against your zone, but don't run cloudflared yet
# (e.g. so you can install it as a system service afterwards):
DOMAIN=aisoc.example.com SKIP_RUN=1 pnpm demo:public:setup
```

Cloudflare needs to manage DNS for the zone, and you need to have run
`cloudflared tunnel login` once for that account (origin-cert mode) — *or* set
`CLOUDFLARE_TUNNEL_TOKEN` from the dashboard (token mode). Everything else is
parameterised.

## Stopping

`Ctrl+C` in the foreground tunnel — that's it. The Compose stack keeps
running. To take everything down:

```sh
# Bring the local stack down (works in either auth mode):
pnpm aisoc:demo:down

# Origin-cert mode only — release the tunnel + DNS records the script created:
cloudflared tunnel delete aisoc-tryaisoc

# Token mode — delete the tunnel from the Cloudflare Zero Trust dashboard
# (Networks → Tunnels → … → Delete). The CLI command above won't work here
# because this machine has no cert.pem to authorise the delete.
```

## Production-grade extras (optional)

If you want to leave the demo up 24/7 without a terminal window pinned, run
`cloudflared` as a launchd / systemd service.

**Origin-cert mode** — point the service at the rendered config:

```sh
# macOS
sudo cloudflared service install \
  --config "$HOME/.cloudflared/aisoc-tryaisoc.yml"

# Linux
sudo cloudflared service install
```

**Token mode** — install the service with the dashboard token. The command the
Cloudflare dashboard hands you on the *Install connector → Docker* tab also
works for `service install`:

```sh
# macOS / Linux
sudo cloudflared service install ey…   # paste the same token you use locally
```

`cloudflared service uninstall` reverses either flavour.

## What the tunnel does NOT do

- **It does not change auth.** The demo profile still uses the seeded
  `aisoc:aisoc_dev_secret` credentials. Treat the public demo as a sandbox.
- **It does not protect the API.** Anyone with the URL can hit
  `api.tryaisoc.com`. If you need access control, wire up Cloudflare Access
  in front of the hostnames — `tunnel.sh` is intentionally Access-agnostic so
  you can layer it on without rewriting the script.
- **It does not seed data.** Run `pnpm seed:demo` after the stack is up to
  populate sample incidents.
