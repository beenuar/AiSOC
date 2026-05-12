# AiSOC auditd profile

A drop-in `audit.rules` profile that gives the [`auditd`](../../services/connectors/app/connectors/auditd.py)
connector enough signal to drive the bundled Linux endpoint detection
rules (`detections/endpoint/linux-*.yaml`) **without** running a
host-side AiSOC agent.

The connector tails `/var/log/audit/audit.log` directly and matches on
the `key=` field every rule attaches via `-k aisoc_*`. The connector's
severity heuristic is a pure function of the key prefix:

| Key prefix          | Severity |
| ------------------- | -------- |
| `aisoc_critical_*`  | `high`   |
| `aisoc_priv_esc_*`  | `medium` |
| `aisoc_persistence_*` | `medium` |
| `aisoc_exec`        | `medium` |
| `aisoc_watch_*`     | `low`    |
| `aisoc_audit_*`     | `low`    |

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

You should see ~30 rules with `key=aisoc_*` attached. If you see zero,
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

Every rule in `aisoc.rules` is wired into at least one detection rule
that already ships with AiSOC. The full mapping:

| `audit.rules` key                | Detection rule(s)                                                                 |
| -------------------------------- | --------------------------------------------------------------------------------- |
| `aisoc_critical_exec_tmp`        | `detections/endpoint/linux-exec-from-tmp.yaml`                                    |
| `aisoc_critical_memfd`           | `detections/endpoint/linux-memfd-create.yaml`                                     |
| `aisoc_critical_identity_write`  | `detections/endpoint/linux-passwd-shadow-write.yaml`                              |
| `aisoc_critical_sudoers_write`   | `detections/endpoint/linux-sudoers-modification.yaml`                             |
| `aisoc_critical_pam_write`       | `detections/endpoint/linux-pam-modification.yaml`                                 |
| `aisoc_critical_ssh_config`      | `detections/endpoint/linux-sshd-config-modification.yaml`                         |
| `aisoc_critical_authorized_keys` | `detections/endpoint/linux-authorized-keys-write.yaml`                            |
| `aisoc_persistence_cron`         | `detections/endpoint/linux-cron-persistence.yaml`                                 |
| `aisoc_persistence_systemd`      | `detections/endpoint/linux-systemd-persistence.yaml`                              |
| `aisoc_priv_esc_module_load`     | `detections/endpoint/linux-kernel-module-load.yaml`                               |
| `aisoc_audit_self_tamper`        | `detections/endpoint/linux-auditctl-disable.yaml`                                 |

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
