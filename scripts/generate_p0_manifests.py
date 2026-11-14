#!/usr/bin/env python3
"""Generate marketplace plugin.yaml manifests for the WS3 P0 connector batch.

Walks each P0 connector's `schema()` and emits a `plugins/<dash-id>/plugin.yaml`
that mirrors the live schema fields. Idempotent — re-running overwrites
in-place so the manifest stays in sync with the connector class.

Usage:
    python3 scripts/generate_p0_manifests.py
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "services" / "connectors"))

from app.connectors import CONNECTOR_REGISTRY  # noqa: E402

# (registry-id, marketplace-slug, friendly-name, tags, homepage-suffix)
P0_BATCH: list[tuple[str, str, str, list[str], str]] = [
    (
        "carbon_black",
        "carbon-black",
        "Carbon Black Cloud Connector",
        ["edr", "carbon-black", "vmware", "endpoint"],
        "carbon_black.py",
    ),
    (
        "trend_vision_one",
        "trend-vision-one",
        "Trend Vision One Connector",
        ["edr", "xdr", "trend-micro", "endpoint"],
        "trend_vision_one.py",
    ),
    (
        "cortex_xsiam",
        "cortex-xsiam",
        "Palo Alto Cortex XSIAM Connector",
        ["siem", "xsiam", "palo-alto", "cortex"],
        "cortex_xsiam.py",
    ),
    (
        "rapid7_insightidr",
        "rapid7-insightidr",
        "Rapid7 InsightIDR Connector",
        ["siem", "rapid7", "insightidr", "udba"],
        "rapid7_insightidr.py",
    ),
    (
        "sumo_logic",
        "sumo-logic",
        "Sumo Logic Cloud SIEM Connector",
        ["siem", "sumo-logic", "cloud-siem"],
        "sumo_logic.py",
    ),
    (
        "chronicle",
        "chronicle",
        "Google Chronicle SecOps Connector",
        ["siem", "google", "chronicle", "secops"],
        "chronicle.py",
    ),
    (
        "datadog_cloud_siem",
        "datadog-cloud-siem",
        "Datadog Cloud SIEM Connector",
        ["siem", "datadog", "cloud-siem"],
        "datadog_cloud_siem.py",
    ),
    (
        "lacework",
        "lacework",
        "Lacework / Fortinet FortiCNAPP Connector",
        ["cloud", "lacework", "cnapp", "compliance"],
        "lacework.py",
    ),
    (
        "tenable_io",
        "tenable-io",
        "Tenable Vulnerability Management Connector",
        ["vuln", "tenable", "vulnerability-management"],
        "tenable.py",
    ),
    (
        "mimecast",
        "mimecast",
        "Mimecast Email Security Connector",
        ["email", "mimecast", "saas", "phishing"],
        "mimecast.py",
    ),
    (
        "slack_audit",
        "slack-audit",
        "Slack Enterprise Audit Logs Connector",
        ["saas", "slack", "audit", "collaboration"],
        "slack_audit.py",
    ),
    (
        "salesforce",
        "salesforce",
        "Salesforce Event Monitoring Connector",
        ["saas", "salesforce", "crm", "audit"],
        "salesforce.py",
    ),
    (
        "auth0",
        "auth0",
        "Auth0 Tenant Logs Connector",
        ["iam", "auth0", "okta", "identity"],
        "auth0.py",
    ),
    (
        "cisco_umbrella",
        "cisco-umbrella",
        "Cisco Umbrella DNS Connector",
        ["network", "cisco", "umbrella", "dns"],
        "cisco_umbrella.py",
    ),
]


def _yaml_quote(value: str) -> str:
    """Quote a value for safe YAML embedding."""
    if any(c in value for c in ":#\n\"'") or value != value.strip():
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return value


def _render_manifest(
    *,
    slug: str,
    name: str,
    tags: list[str],
    homepage_suffix: str,
    description: str,
    required_fields: list[str],
    field_lines: list[str],
) -> str:
    tags_yaml = "[" + ", ".join(tags) + "]"
    lines = [
        f"id: {slug}",
        f"name: {_yaml_quote(name)}",
        'version: "1.0.0"',
        "plugin_type: connector",
        "tier: stable",
        "description: >",
    ]
    # Wrap description across lines
    chunk_size = 78
    desc_words = description.split()
    line: list[str] = []
    width = 0
    desc_lines: list[str] = []
    for word in desc_words:
        if width + len(word) + 1 > chunk_size and line:
            desc_lines.append(" ".join(line))
            line = [word]
            width = len(word)
        else:
            line.append(word)
            width += len(word) + 1
    if line:
        desc_lines.append(" ".join(line))
    for dl in desc_lines:
        lines.append(f"  {dl}")

    lines += [
        "author: AiSOC Core Team",
        f"tags: {tags_yaml}",
        f"homepage: https://github.com/beenuar/AiSOC/tree/main/services/connectors/app/connectors/{homepage_suffix}",
        "license: MIT",
        'min_aisoc_version: "4.0.0"',
        "config_schema:",
        "  type: object",
    ]
    if required_fields:
        req = ", ".join(required_fields)
        lines.append(f"  required: [{req}]")
    lines.append("  properties:")
    lines.extend(field_lines)
    return "\n".join(lines) + "\n"


def main() -> int:
    out_dir = REPO_ROOT / "plugins"
    written: list[str] = []

    for registry_id, slug, name, tags, homepage_suffix in P0_BATCH:
        cls = CONNECTOR_REGISTRY.get(registry_id)
        if cls is None:
            print(f"  WARN: connector '{registry_id}' not registered", file=sys.stderr)
            continue

        schema = cls.schema()
        required: list[str] = []
        field_lines: list[str] = []

        for f in schema.fields:
            if f.required:
                required.append(f.name)
            field_lines.append(f"    {f.name}:")
            yaml_type = "string"  # everything serializes as string in YAML schema
            field_lines.append(f"      type: {yaml_type}")
            help_text = f.help_text or f.label or f.name
            field_lines.append(f"      description: {_yaml_quote(help_text)}")
            if f.type == "secret":
                field_lines.append("      secret: true")

        manifest = _render_manifest(
            slug=slug,
            name=name,
            tags=tags,
            homepage_suffix=homepage_suffix,
            description=schema.description.replace("\n", " ").strip(),
            required_fields=required,
            field_lines=field_lines,
        )

        target = out_dir / slug / "plugin.yaml"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(manifest, encoding="utf-8")
        written.append(slug)
        print(f"  WROTE plugins/{slug}/plugin.yaml")

    print(f"\nGenerated {len(written)} P0 plugin manifests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
