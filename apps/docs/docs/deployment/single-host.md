---
id: single-host
title: Single-host deployment
sidebar_label: Single host
---

# Running AiSOC on one server

This is the path for a server you reach over the network — a VM, a NUC in a
rack, a cloud instance — as opposed to `make up` on a laptop. It is also the
usual step before moving to Kubernetes.

Two things differ from a laptop install, and both are deliberate choices you
have to make rather than defaults you inherit.

If you would rather watch one being done end to end first, the
[deployment walkthrough](./walkthrough.md) records exactly this path — console
published on a LAN address, real threat-intel data, an event pushed through to
an AI verdict.

## 1. Publish the console

Every host port ships bound to `127.0.0.1`. That is correct for a laptop and
useless for a server: the stack comes up healthy and nothing outside the
machine can reach it, including the browser you intended to use.

One variable changes that:

```bash
# .env
AISOC_CONSOLE_BIND_ADDR=0.0.0.0
```

The console is the **only** port a browser needs. The bundle it serves calls
same-origin paths — `/api/v1/alerts`, `/ws/…` — and the Next.js server
forwards them to the API, the agents service and the realtime gateway over the
internal Docker network. Publishing one port therefore exposes one service,
and Postgres, Redis, Kafka and Neo4j stay on loopback with the development
passwords this repository ships in `.env.example`.

```bash
docker compose up -d
curl http://<your-host>:3000/api/health     # {"status":"ok"}
```

:::warning Put TLS in front of it
`0.0.0.0` means every interface the host has. On anything that is not a
trusted network, terminate TLS in a reverse proxy (nginx, Caddy, Traefik,
Cloudflare Tunnel) and point it at `127.0.0.1:3000` instead of publishing the
console directly. Sessions are bearer tokens; over plain HTTP they are
readable by anything on the path.
:::

There is a second variable, `AISOC_BIND_ADDR`, which moves **every** binding
including the datastores. It exists for an isolated network where you want
`psql` from another machine. On a routable network it hands out the shipped
development passwords, so rotate them first, or leave it alone and use an SSH
tunnel.

### Also set the console's own address

`make bootstrap` prints the URL to sign in at, and it defaults to
`http://localhost:3000`, which is the wrong instruction on a server:

```bash
# .env
AISOC_CONSOLE_URL=http://aisoc.internal:3000
```

## 2. Point the console at your services

If you run the bundled `docker-compose.yml` unchanged you can skip this —
the defaults already name the Compose services.

If your API lives somewhere else — a different Compose project, a separate
host, an existing deployment — set the addresses the console proxies to:

```bash
# .env
AISOC_API_URL=http://api.internal:8000
AISOC_AGENTS_URL=http://agents.internal:8084
AISOC_REALTIME_URL=http://realtime.internal:4000
```

These are read when the container starts. You do not need to rebuild the
image, and there is no CORS configuration, because the browser never talks to
these addresses — only the console's Node process does.

:::danger `NEXT_PUBLIC_*` cannot do this
Next.js inlines every `NEXT_PUBLIC_*` value into the JavaScript bundle when the
image is **built**. Setting `NEXT_PUBLIC_API_URL` on a container running a
*pulled* image is read by nothing, changes nothing, and reports nothing.

If you find that advice elsewhere, it predates this page. Use the
`AISOC_*_URL` variables above. To make the browser call a different origin
directly you have to rebuild:
`docker compose build --build-arg NEXT_PUBLIC_API_URL=https://api.example.com web`
— and then configure CORS on the API, which same-origin proxying exists to
avoid.
:::

## 3. Confirm what the deployment thinks it is

```bash
curl http://<your-host>:3000/api/runtime-config
```

```json
{ "demoMode": false, "demoModeSource": "runtime", "consoleVersion": "11.0.0" }
```

`demoMode` is the deployment's own answer rather than something to infer from
the page. `demoModeSource` says where it came from:

| `demoModeSource` | Meaning |
| --- | --- |
| `runtime` | `AISOC_DEMO_MODE` is set on the console container. |
| `build` | `NEXT_PUBLIC_DEMO_MODE` was compiled into the image; `AISOC_DEMO_MODE` is unset. |
| `default` | Neither is set. Not a demo. |

A `build` source on a self-hosted deployment means the image was built as a
demo. Set `AISOC_DEMO_MODE=false` to override it without rebuilding.

`consoleVersion` is the version the **image** was built from, which is not
necessarily the version of the repository you cloned: `latest` is a moving tag
and can lag a release. If it disagrees with `VERSION`, pull:

```bash
docker compose pull && docker compose up -d
```

The Compose file uses `pull_policy: missing`, so an image already on the host
is never refreshed on its own — a host that first pulled `latest` months ago
keeps running that build until you pull explicitly.

## Moving to Kubernetes

The Helm chart under `infra/helm/aisoc` sets the same three upstream addresses
on the console Deployment, derived from the release's own Services
(`<release>-api`, `<release>-agents`, `<release>-realtime`). Override them
through values when the API is outside the release:

```yaml
services:
  web:
    env:
      API_URL: http://api.aisoc.svc.cluster.local:80
```

This requires a console image built with the runtime entrypoint (AiSOC 11.1.0
or later). An older image ignores these variables and dials the addresses it
was built with — `http://api:8000` — which resolves to nothing in a cluster,
so the console loads and every panel stays empty.

Ingress hostnames, TLS and replica counts are covered in
[Kubernetes](./kubernetes.md).
