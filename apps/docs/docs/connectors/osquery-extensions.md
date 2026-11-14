---
sidebar_position: 20
title: osquery Extensions
description: Custom osquery virtual tables that surface AiSOC data directly in the osquery shell.
---

# AiSOC osquery Extensions

The `aisoc-extension` binary adds five osquery virtual tables that surface
AiSOC operational data directly inside any osquery query, scheduled pack, or
live investigation session.

| Virtual table | Description |
|---|---|
| `aisoc_pending_actions` | HITL response actions queued for this host |
| `aisoc_alert_cache` | Alerts fired against this host (last 24 h) |
| `aisoc_attck_persistence` | Approved persistence baseline (MITRE T1547) |
| `aisoc_kernel_modules_verified` | Loaded kernel modules with signing status (Linux) |
| `aisoc_browser_extensions` | Installed browser extensions per user profile |

---

## Prerequisites

- osquery ≥ 5.10
- Network access from the host to the AiSOC osquery-tls service
- An API token with the `extensions:read` scope

---

## Installation

### 1 — Download the binary

Pre-built binaries are published to GitHub Releases for every tag matching
`ext-v*`.  Binaries are signed with [cosign](https://docs.sigstore.dev/)
keyless signing; signatures and certificates are released alongside each
binary.

```bash
# Example: Linux amd64
VERSION=ext-v1.0.0
curl -fsSL -o /opt/aisoc/aisoc-extension \
  "https://github.com/beenuar/AiSOC/releases/download/${VERSION}/aisoc-extension-linux-amd64"

# Verify the signature (optional but recommended)
cosign verify-blob \
  --certificate    "aisoc-extension-linux-amd64.pem" \
  --signature      "aisoc-extension-linux-amd64.sig" \
  --certificate-identity-regexp "https://github.com/beenuar/AiSOC" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "aisoc-extension-linux-amd64"

chmod +x /opt/aisoc/aisoc-extension
```

### 2 — Configure environment variables

| Variable | Default | Purpose |
|---|---|---|
| `AISOC_API_URL` | `http://localhost:8000` | Base URL of the osquery-tls service |
| `AISOC_API_TOKEN` | _(empty)_ | Bearer token for authentication |
| `AISOC_HOST_ID` | system hostname | Identifies the host in API calls |

### 3a — Launch with osquery flags (daemon mode)

Add the following to `/etc/osquery/osquery.flags` (or your equivalent):

```
--extensions_autoload=/opt/aisoc/extensions.load
--extensions_timeout=10
--extensions_interval=3
```

Create `/opt/aisoc/extensions.load` containing the absolute path to the binary:

```
/opt/aisoc/aisoc-extension
```

The extension is passed `--socket <path>` automatically by osqueryd.

### 3b — Launch as a systemd service (Linux)

```ini
# /etc/systemd/system/aisoc-extension.service
[Unit]
Description=AiSOC osquery extension
After=osqueryd.service
Requires=osqueryd.service

[Service]
EnvironmentFile=/etc/aisoc/extension.env
ExecStartPre=/bin/sleep 3
ExecStart=/opt/aisoc/aisoc-extension \
    --socket /var/osquery/osquery.em \
    --timeout 30
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/aisoc/extension.env
AISOC_API_URL=https://osquery-tls.internal.example.com
AISOC_API_TOKEN=eyJ...
AISOC_HOST_ID=web-prod-01
```

```bash
systemctl daemon-reload
systemctl enable --now aisoc-extension
```

### 3c — macOS (launchd)

```xml
<!-- /Library/LaunchDaemons/com.aisoc.extension.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>             <string>com.aisoc.extension</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/aisoc/aisoc-extension</string>
    <string>--socket</string>
    <string>/private/var/osquery/osquery.em</string>
    <string>--timeout</string>
    <string>30</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>AISOC_API_URL</key>   <string>https://osquery-tls.example.com</string>
    <key>AISOC_API_TOKEN</key> <string>eyJ...</string>
  </dict>
  <key>RunAtLoad</key>         <true/>
  <key>KeepAlive</key>         <true/>
</dict>
</plist>
```

```bash
launchctl load /Library/LaunchDaemons/com.aisoc.extension.plist
```

---

## Example queries

```sql
-- What response actions are waiting for this host?
SELECT * FROM aisoc_pending_actions;

-- High-severity alerts in the last 24 hours
SELECT alert_id, severity, summary, fired_at
FROM   aisoc_alert_cache
WHERE  severity IN ('high', 'critical')
ORDER BY fired_at DESC;

-- Persistence entries not on the approved baseline
SELECT s.name, s.path, s.args
FROM   startup_items s
LEFT JOIN aisoc_attck_persistence p ON s.path = p.path
WHERE  p.entry_id IS NULL;

-- Unsigned kernel modules (Linux)
SELECT name, path
FROM   aisoc_kernel_modules_verified
WHERE  signed = 0;

-- Browser extensions installed across all profiles
SELECT browser, profile, name, version, extension_id
FROM   aisoc_browser_extensions
ORDER BY browser, profile, name;
```

---

## API endpoints

The extension communicates with the following read-only endpoints on the
osquery-tls service:

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/osquery/extensions/pending-actions` | HITL action queue |
| GET | `/api/v1/osquery/extensions/alert-cache` | Recent alert cache |
| GET | `/api/v1/osquery/extensions/persistence-baseline` | Approved baseline |

All endpoints accept `?host_identifier=<string>` and, for the alert cache,
`?since=<ISO-8601>`.

---

## Building from source

```bash
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC/services/osquery-extensions

# Run tests
make test

# Build for the current platform
make build

# Cross-platform release binaries (dist/)
make release
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Extension not appearing in osquery | Socket path wrong | Verify `--extensions_autoload` path and socket location |
| All tables return zero rows | API unreachable | Check `AISOC_API_URL`, firewall, and token |
| `aisoc_kernel_modules_verified` empty | Non-Linux host | Expected; the table reads `/proc/modules` |
| Slow query times | High `AISOC_HTTP_TIMEOUT` default | Set a shorter `HTTPTimeout` in config |

---

## Security notes

- The extension binary should be owned `root:root` and mode `0755`.
- Store `AISOC_API_TOKEN` in the systemd/launchd environment file with mode
  `0600`, not in the unit file or command line.
- Release binaries are signed with cosign keyless signing; verify before
  deploying in production.
- The extension communicates **outbound only**; it does not listen on any
  port.
