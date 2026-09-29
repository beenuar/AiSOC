# AiSOC auditd profile

A drop-in `audit.rules` profile that gives the [`auditd`](../../services/connectors/app/connectors/auditd.py)
connector enough signal to drive the bundled Linux endpoint detection
rules (`detections/endpoint/linux-*.yaml`) **without** running a
host-side AiSOC agent.

The connector tails `/var/log/audit/audit.log` directly and matches on
the `key=` field every rule attaches via `-k aisoc_*`. The connector's
severity heuristic is a pure function of the key prefix:

| Key prefix            | Severity   |
| --------------------- | ---------- |
| `aisoc_critical_*`    | `critical` |
| `aisoc_priv_esc_*`    | `high`     |
| `aisoc_persistence_*` | `medium`   |
| `aisoc_exec`          | `medium`   |
| `aisoc_watch_*`       | `low`      |
| `aisoc_audit_*`       | `low`      |

Highest-priority match wins, so an explicit `aisoc_critical_*` key beats the
generic `aisoc_exec` bucket. The table above is `_KEY_SEVERITY_PREFIXES` in
[`auditd.py`](../../services/connectors/app/connectors/auditd.py); a
modification of a path in `_HIGH_RISK_PATHS` (`/etc/passwd` and friends) is
lifted to `high` regardless of the key.

This means the SOC analyst sees the same severity in the AiSOC console
as the rule author intended at policy-write time — no second-guessing.

## Install

> Tested on Ubuntu 22.04, Debian 12, RHEL 9, Amazon Linux 2023.

```bash
# 1. Install auditd if it isn't already.
sudo apt-get install -y auditd        # Debian / Ubuntu
sudo dnf install -y audit             # RHEL / Fedora / Amazon Linux

# 2. Drop the profile into rules.d (NOT directly into audit.rules —
#    augenrules will compose the final ruleset for you).
sudo install -m 0640 -o root -g root \
    aisoc.rules /etc/audit/rules.d/99-aisoc.rules

# 3. Reload the kernel ruleset.
sudo augenrules --load

# 4. Confirm the rules are live.
sudo auditctl -l | grep aisoc_
```

You should see 47 rules with `key=aisoc_*` attached. If you see zero,
re-check that `audit.rules.d` isn't being clobbered by a CIS / STIG
benchmark profile and that `auditd` itself is running
(`systemctl status auditd`).

## Connect AiSOC

Add the connector instance from the AiSOC console (or the API):

| Field           | Value (example)              |
| --------------- | ---------------------------- |
| Host label      | `web-prod-01.eu-west-1`      |
| Audit log path  | `/var/log/audit/audit.log`   |
| Cursor path     | _(leave blank — defaults to `<audit_log_path>.aisoc-cursor`)_ |

The connector needs **read** on the audit log and **read/write** on the
cursor file. The cleanest fit is to add the AiSOC service account to
the local `adm` group (which already owns `/var/log/audit/`):

```bash
sudo usermod -aG adm aisoc
```

…and re-login the AiSOC service so the new group takes effect.

## What gets detected, end-to-end

The profile emits 47 rules across 22 distinct `aisoc_*` keys. The Linux
endpoint detections that consume this telemetry live under
`detections/endpoint/`; the ones most directly tied to the keys in this
profile are:

| `audit.rules` key prefix    | Related detections in `detections/endpoint/`                                          |
| --------------------------- | ------------------------------------------------------------------------------------- |
| `aisoc_critical_memfd`      | `linux-memfd-create-then-execve.yaml`, `linux-fileless-via-procfd.yaml`                 |
| `aisoc_critical_exec_tmp`   | `linux-chmod-plus-x-tmp.yaml`, `linux-large-stage-tmp.yaml`, `linux-ld-preload-set-tmp.yaml` |
| `aisoc_critical_identity_write` | `linux-passwd-modified.yaml`, `linux-shadow-read.yaml`                              |
| `aisoc_critical_sudoers_write`  | `linux-auditd-sudoers-tampering.yaml`, `linux-sudoers-d-add.yaml`, `linux-nopasswd-sudo-line.yaml` |
| `aisoc_critical_pam_write`  | `linux-pam-d-modified.yaml`                                                             |
| `aisoc_critical_ssh_config` | `linux-auditd-ssh-config-tampering.yaml`, `linux-ssh-config-permitrootlogin-yes.yaml`   |
| `aisoc_critical_authorized_keys` | `linux-authorized-keys-bulk-append.yaml`, `fim-ssh-authorized-keys-changed.yaml`   |
| `aisoc_persistence_cron`    | `linux-cron-d-write.yaml`, `linux-anacron-job-add.yaml`, `linux-at-job-create.yaml`     |
| `aisoc_persistence_systemd` | `linux-auditd-systemd-persistence.yaml`, `linux-systemd-timer-create.yaml`              |
| `aisoc_persistence_initd`   | `linux-initd-script-add.yaml`                                                           |
| `aisoc_priv_esc_module_load`| `linux-auditd-kernel-module-load.yaml`, `linux-kernel-module-load-insmod.yaml`          |
| `aisoc_audit_self_tamper`   | `linux-auditctl-disable.yaml`, `linux-auditd-stopped.yaml`                              |
| `aisoc_watch_nss`           | `linux-nss-module-installed.yaml`                                                       |

This is a topical index, not a wiring contract: a detection fires on the
normalised event, not on the audit key, so enabling a key does not guarantee
a specific rule matches on your hosts. `docs/detections/truth-table.md` is
the generated record of which rules the engine actually loads.

If you author a new rule against this profile, follow the same
convention — pick a key with a documented prefix, and the rest of the
pipeline (severity, console grouping, eval grading) lights up for free.

## Tuning

The profile is intentionally conservative. Two knobs you'll want to
consider on real hosts:

1. **Backlog limits.** `-b 8192` is enough for a quiet web tier, way
   too small for a busy database. Bump it to 32768 if you see
   `audit_lost > 0` in `/var/log/audit/audit.log`.
2. **Lockdown.** The trailing `-e 2` is commented out so you can
   iterate. Once stable, uncomment it; an attacker can no longer
   `auditctl -e 0` you without a reboot, and the reboot itself becomes
   a high-confidence signal.

## Why no host-agent?

This profile + the file-tail connector exists because **a host-agent
is a 5–7 day Go project we deferred to a later release.** The trade-off:

* ✅ Zero net-new code on the customer host. Stock `auditd` only.
* ✅ Works on any distro with `auditd` (RHEL family, Debian family, Amazon Linux, SUSE).
* ✅ The connector is the only AiSOC-specific surface, and it lives on the AiSOC side.
* ⚠️ Requires the AiSOC service to read `/var/log/audit/audit.log`,
  which means either group membership in `adm` or a sidecar
  shipper (rsyslog/Vector/Fluent Bit forwarding the file).
* ⚠️ Sub-second latency depends on poll interval; default is 5 minutes.
  Drop the per-instance `poll_interval_seconds` to `30` for tier-1 hosts.

When the host-agent ships, this profile stays exactly the same — the
agent will read the same log file, parse it with the same library
the connector uses, and emit identical normalized events.
