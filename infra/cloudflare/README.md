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
3. **Login once** — `cloudflared tunnel login`. This drops a `cert.pem` in
   `~/.cloudflared/` that authorises this machine to manage tunnels and DNS
   for the zone.
4. **A running stack** — the demo profile from `pnpm aisoc:demo` is the
   intended target. The wrapper `pnpm demo:public` (see below) brings the
   stack up and the tunnel up in one command.

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

`tunnel.sh` will:

1. Verify `cloudflared` is installed and authenticated.
2. Create a tunnel named `aisoc-tryaisoc` (configurable via `TUNNEL_NAME`) if
   it doesn't already exist.
3. Render `config.yml` from `config.yml.example`, substituting the tunnel
   UUID, the credentials path, and the apex domain (`DOMAIN`, default
   `tryaisoc.com`).
4. Validate the rendered config with `cloudflared tunnel ingress validate`.
5. Create / update DNS routes for the apex and each subdomain in
   `SUBDOMAINS` (default `"api ws docs"`).
6. Run `cloudflared tunnel --config <generated-config> run`.

The first run takes ~10 seconds for DNS propagation; subsequent runs are
instant.

### Environment variables

Both `pnpm demo:public*` and `bash infra/cloudflare/tunnel.sh` honour the
same set:

| Var           | Default          | Purpose                                                  |
| ------------- | ---------------- | -------------------------------------------------------- |
| `DOMAIN`      | `tryaisoc.com`   | Apex domain. The script routes `DOMAIN` and each subdomain in `SUBDOMAINS` to the tunnel. |
| `TUNNEL_NAME` | `aisoc-tryaisoc` | Cloudflare tunnel name. Reused if it already exists.     |
| `SUBDOMAINS`  | `"api ws docs"`  | Space-separated list of subdomains to route in addition to the apex. |
| `SKIP_DNS`    | *(unset)*        | If set to `1`, don't touch DNS records (assume they exist). |
| `SKIP_RUN`    | *(unset)*        | If set to `1`, set everything up but don't run the tunnel — pair with `cloudflared service install` for a 24/7 setup. |
| `CFD_DIR`     | `~/.cloudflared` | Where `cloudflared`'s `cert.pem`, credentials JSONs, and rendered configs live. |

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
`cloudflared tunnel login` once for that account. Everything else is
parameterised.

## Stopping

`Ctrl+C` in the foreground tunnel — that's it. The Compose stack keeps
running. To take everything down:

```sh
pnpm aisoc:demo:down
cloudflared tunnel delete aisoc-tryaisoc   # only if you want to release the tunnel + DNS
```

## Production-grade extras (optional)

If you want to leave the demo up 24/7 without a terminal window pinned, run
`cloudflared` as a launchd / systemd service:

```sh
# macOS
sudo cloudflared service install \
  --config "$HOME/.cloudflared/aisoc-tryaisoc.yml"

# Linux
sudo cloudflared service install
```

`cloudflared service uninstall` reverses it.

## What the tunnel does NOT do

- **It does not change auth.** The demo profile still uses the seeded
  `aisoc:aisoc_dev_secret` credentials. Treat the public demo as a sandbox.
- **It does not protect the API.** Anyone with the URL can hit
  `api.tryaisoc.com`. If you need access control, wire up Cloudflare Access
  in front of the hostnames — `tunnel.sh` is intentionally Access-agnostic so
  you can layer it on without rewriting the script.
- **It does not seed data.** Run `pnpm seed:demo` after the stack is up to
  populate sample incidents.
