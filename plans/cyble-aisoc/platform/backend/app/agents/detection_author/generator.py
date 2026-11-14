"""Sigma rule generator + synthetic test event author.

This module owns the rule-shape templates. It turns the
``ThreatReport`` + extracted signals (techniques, IOCs, logsource)
into:

- a Sigma rule dict that round-trips through ``SigmaRule.from_dict``
- a pretty-printed YAML string for the GitOps PR
- a set of synthetic events that exercise the rule

We deliberately keep the rule body small and field-targeted. A noisy
"match anything" rule is worse than no rule, so when in doubt the
generator emits an extremely specific selection (URL exact-match,
hash exact-match) rather than a contains-everything pattern.

Template selection priority:

1. IOC-driven (URL/hash/domain present)
2. Logsource-driven (okta admin grant, cloud assume-role, etc.)
3. Generic fallback (regex match on the most distinctive keyword)

Rule ids are deterministic: ``aisoc-author-<slug-of-title>``. Re-running
the same report produces the same rule id, which is what makes the
GitOps workflow idempotent — the second PR updates the same file
instead of creating a duplicate.
"""

from __future__ import annotations

import re
from typing import Any

import yaml

from .extractor import (
    classify_ioc,
    extract_iocs,
    extract_mitre,
    guess_logsource,
    guess_severity,
)
from .models import SyntheticEvent, ThreatReport

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(text: str, *, max_len: int = 60) -> str:
    """Return a kebab-case slug suitable for a Sigma rule id suffix.

    We strip everything outside ``[a-z0-9]`` and collapse runs of
    non-alphanum to a single hyphen. Length is bounded so a 500-char
    narrative doesn't blow out the filename later.
    """
    s = _SLUG_RE.sub("-", text.lower()).strip("-")
    if not s:
        s = "untitled"
    if len(s) > max_len:
        # Truncate on a hyphen boundary if we can; otherwise hard cut.
        cut = s.rfind("-", 0, max_len)
        s = s[: cut if cut > 20 else max_len]
    return s.strip("-") or "untitled"


def _derive_title(report: ThreatReport) -> str:
    """Pick a rule title from analyst input or the first sentence of the prose."""
    if report.rule_title:
        return report.rule_title.strip()
    # First sentence, capped at 90 chars.
    first = re.split(r"[.!?\n]", report.narrative.strip(), maxsplit=1)[0].strip()
    if not first:
        first = "Custom Threat Detection"
    if len(first) > 90:
        first = first[:87].rstrip() + "..."
    return first


# --------------------------------------------------------------------------- #
# Synthetic event templates
# --------------------------------------------------------------------------- #


def _logsource_event_skeleton(ls: dict[str, str]) -> dict[str, Any]:
    """Return a baseline event for the given logsource.

    The event includes the logsource-identifying fields the detection
    runtime expects (``event.module`` for vendor, ``event.dataset`` for
    service/category) so a rule that scopes ``event.module: okta`` can
    actually match. Without this, a positive event would be missing
    the very fields the rule keys off and would falsely fail self-test.
    """
    product = ls.get("product", "")
    service = ls.get("service", "")
    category = ls.get("category", "")

    base: dict[str, Any] = {
        "@timestamp": "2026-06-01T12:00:00Z",
        "event": {
            "module": product or category or "application",
            "dataset": f"{product}.{service}" if (product and service) else service or category or "generic",
            "action": "observed",
        },
    }
    # Logsource-specific spines so rule bodies that key off common
    # vendor fields (okta.target.role, aws.cloudtrail.event_name, etc.)
    # have a sensible place to land in the synthetic event.
    if product == "okta":
        base["okta"] = {"actor": {"id": "u-1"}, "target": {"id": "t-1"}}
        base["user"] = {"name": "alice@example.com"}
    elif product == "aws":
        base["aws"] = {
            "cloudtrail": {
                "event_name": "ConsoleLogin",
                "user_identity": {"type": "IAMUser", "user_name": "alice"},
            }
        }
        base["source"] = {"ip": "203.0.113.10"}
    elif product == "windows":
        base["winlog"] = {
            "event_id": 4625 if service == "security" else 1,
            "channel": service or "Security",
        }
        base["process"] = {"name": "explorer.exe"}
    elif product == "github":
        base["github"] = {"actor": "alice", "action": "repo.add_member"}
    return base


# --------------------------------------------------------------------------- #
# Template strategies
# --------------------------------------------------------------------------- #


def _ioc_selection(
    iocs: tuple[str, ...],
) -> tuple[dict[str, Any], list[SyntheticEvent]] | None:
    """If we have IOCs we can pin a rule to, build an exact-match selection.

    Returns ``(selection_dict, sample_events)`` or ``None`` if the IOC
    set isn't actionable for an exact-match rule (e.g. only generic
    file paths).

    We pick exactly ONE IOC per category to keep the rule tight; the
    rest stay in the description as context. Wildcarding multiple
    IOCs into a single rule is a false-positive risk we'd rather avoid
    in auto-generated content.
    """
    urls: list[str] = []
    domains: list[str] = []
    ips: list[str] = []
    hashes: list[str] = []
    paths: list[str] = []
    for v in iocs:
        cat = classify_ioc(v)
        if cat == "url":
            urls.append(v)
        elif cat == "domain":
            domains.append(v)
        elif cat == "ipv4":
            ips.append(v)
        elif cat == "hash":
            hashes.append(v)
        elif cat == "path":
            paths.append(v)

    if hashes:
        h = hashes[0]
        sel: dict[str, Any] = {"hash.sha256|all": [h]} if len(h) == 64 else {"hash.value": [h]}
        positive = {
            "@timestamp": "2026-06-01T12:00:00Z",
            "event": {"module": "endpoint", "dataset": "endpoint.process"},
            "hash": {"sha256": h, "value": h},
            "process": {"name": "evil.exe"},
        }
        negative = {
            "@timestamp": "2026-06-01T12:00:00Z",
            "event": {"module": "endpoint", "dataset": "endpoint.process"},
            "hash": {"sha256": "0" * 64, "value": "0" * 32},
            "process": {"name": "explorer.exe"},
        }
        return sel, [
            SyntheticEvent(label="positive", description=f"File matching hash {h[:12]}...", payload=positive),
            SyntheticEvent(label="negative", description="Unrelated benign process", payload=negative),
        ]

    if urls:
        u = urls[0]
        sel = {"url.full": [u]}
        positive = {
            "@timestamp": "2026-06-01T12:00:00Z",
            "event": {"module": "network", "dataset": "network.http"},
            "url": {"full": u},
            "source": {"ip": "10.0.0.5"},
        }
        negative = {
            "@timestamp": "2026-06-01T12:00:00Z",
            "event": {"module": "network", "dataset": "network.http"},
            "url": {"full": "https://example.com/legit"},
            "source": {"ip": "10.0.0.5"},
        }
        return sel, [
            SyntheticEvent(label="positive", description=f"HTTP request to malicious URL {u}", payload=positive),
            SyntheticEvent(label="negative", description="HTTP request to a benign URL", payload=negative),
        ]

    if domains:
        d = domains[0]
        sel = {"dns.question.name": [d]}
        positive = {
            "@timestamp": "2026-06-01T12:00:00Z",
            "event": {"module": "network", "dataset": "network.dns"},
            "dns": {"question": {"name": d}},
        }
        negative = {
            "@timestamp": "2026-06-01T12:00:00Z",
            "event": {"module": "network", "dataset": "network.dns"},
            "dns": {"question": {"name": "good.example"}},
        }
        return sel, [
            SyntheticEvent(label="positive", description=f"DNS query for malicious domain {d}", payload=positive),
            SyntheticEvent(label="negative", description="DNS query to a benign domain", payload=negative),
        ]

    if ips:
        ip = ips[0]
        sel = {"destination.ip": [ip]}
        positive = {
            "@timestamp": "2026-06-01T12:00:00Z",
            "event": {"module": "network", "dataset": "network.conn"},
            "destination": {"ip": ip},
            "source": {"ip": "10.0.0.5"},
        }
        negative = {
            "@timestamp": "2026-06-01T12:00:00Z",
            "event": {"module": "network", "dataset": "network.conn"},
            "destination": {"ip": "8.8.8.8"},
            "source": {"ip": "10.0.0.5"},
        }
        return sel, [
            SyntheticEvent(label="positive", description=f"Outbound connection to {ip}", payload=positive),
            SyntheticEvent(label="negative", description="Outbound DNS to Google", payload=negative),
        ]

    return None


def _logsource_template(
    report: ThreatReport,
    logsource: dict[str, str],
) -> tuple[dict[str, Any], list[SyntheticEvent]] | None:
    """Pre-canned rule bodies for high-signal logsource shapes.

    These are scenarios the SOC sees often enough that we'd rather
    encode the exact selection than let the generic fallback build a
    looser keyword rule.
    """
    low = report.narrative.lower()
    product = logsource.get("product", "")

    if product == "okta" and any(k in low for k in ("super_admin", "super admin", "role grant", "privilege")):
        sel = {
            "event.module": "okta",
            "event.action|contains": "privilege.grant",
            "okta.target.role": ["SUPER_ADMIN", "ORG_ADMIN"],
        }
        skel = _logsource_event_skeleton(logsource)
        positive = {
            **skel,
            "event": {**skel["event"], "action": "user.account.privilege.grant"},
            "okta": {**skel.get("okta", {}), "target": {"role": "SUPER_ADMIN", "id": "t-1"}},
        }
        negative = {
            **skel,
            "event": {**skel["event"], "action": "user.account.update"},
            "okta": {**skel.get("okta", {}), "target": {"role": "REPORT_ADMIN", "id": "t-1"}},
        }
        return sel, [
            SyntheticEvent(label="positive", description="Okta SUPER_ADMIN role grant", payload=positive),
            SyntheticEvent(label="negative", description="Non-privileged role update", payload=negative),
        ]

    if product == "aws" and "assumerole" in low:
        sel = {
            "event.module": "aws",
            "aws.cloudtrail.event_name|contains": "AssumeRole",
        }
        skel = _logsource_event_skeleton(logsource)
        positive = {
            **skel,
            "aws": {**skel["aws"], "cloudtrail": {**skel["aws"]["cloudtrail"], "event_name": "AssumeRole"}},
        }
        negative = {
            **skel,
            "aws": {**skel["aws"], "cloudtrail": {**skel["aws"]["cloudtrail"], "event_name": "DescribeInstances"}},
        }
        return sel, [
            SyntheticEvent(label="positive", description="STS AssumeRole call", payload=positive),
            SyntheticEvent(label="negative", description="Benign EC2 DescribeInstances", payload=negative),
        ]

    if product == "windows" and ("lsass" in low or "credential dump" in low or "secretsdump" in low):
        sel = {
            "event.module": "windows",
            "process.name|contains": ["lsass.exe"],
        }
        skel = _logsource_event_skeleton(logsource)
        positive = {
            **skel,
            "process": {"name": "lsass.exe", "command_line": "C:\\Windows\\System32\\lsass.exe"},
        }
        negative = {
            **skel,
            "process": {"name": "explorer.exe", "command_line": "C:\\Windows\\explorer.exe"},
        }
        return sel, [
            SyntheticEvent(label="positive", description="lsass.exe activity", payload=positive),
            SyntheticEvent(label="negative", description="Benign explorer.exe", payload=negative),
        ]

    return None


def _generic_template(
    report: ThreatReport,
    logsource: dict[str, str],
) -> tuple[dict[str, Any], list[SyntheticEvent]]:
    """Final fallback: match on the most distinctive noun in the narrative.

    We pick the longest content word from the narrative (>= 5 chars,
    not in a stoplist) and use it as a ``contains`` match against
    ``event.action``. This is intentionally weak — it's a "we couldn't
    do better, please refine" signal that the analyst sees in the PR.
    """
    stop = {
        "alert", "alerts", "actor", "actors", "agent", "agents", "attack",
        "attacker", "attackers", "client", "clients", "could", "event",
        "events", "false", "false-positive", "from", "host", "hosts",
        "incident", "incidents", "investigation", "logsource", "network",
        "process", "processes", "report", "should", "source", "system",
        "systems", "target", "targets", "their", "there", "these", "those",
        "threat", "through", "vendor", "vendors", "which", "would",
    }
    tokens = re.findall(r"[A-Za-z][A-Za-z_\-\.]{4,}", report.narrative)
    pick = next(
        (t for t in sorted(tokens, key=len, reverse=True) if t.lower() not in stop),
        "anomaly",
    )
    sel = {"event.action|contains": [pick]}

    skel = _logsource_event_skeleton(logsource)
    positive = {**skel, "event": {**skel["event"], "action": f"observed.{pick}"}}
    negative = {**skel, "event": {**skel["event"], "action": "observed.heartbeat"}}
    return sel, [
        SyntheticEvent(label="positive", description=f"Event matching keyword '{pick}'", payload=positive),
        SyntheticEvent(label="negative", description="Unrelated heartbeat event", payload=negative),
    ]


# --------------------------------------------------------------------------- #
# Top-level
# --------------------------------------------------------------------------- #


_YAML_HEADER = (
    "# Auto-generated by Cyble AiSOC Detection Author Agent.\n"
    "# Review the synthetic test events alongside this rule before merging.\n"
)


def generate(
    report: ThreatReport,
) -> tuple[dict[str, Any], str, tuple[SyntheticEvent, ...], tuple[str, ...], tuple[str, ...]]:
    """Produce (sigma_dict, yaml_text, synthetic_events, techniques, iocs).

    The dict and the YAML are equivalent — we return both so callers
    can introspect without re-parsing. ``techniques`` and ``iocs`` are
    the actual values used (post-extraction), which may extend the
    analyst's hints.
    """
    title = _derive_title(report)
    rule_id = f"aisoc-author-{_slugify(title)}"

    techniques = extract_mitre(report.narrative, hints=report.mitre_techniques)
    iocs = extract_iocs(report.narrative, hints=report.iocs)
    logsource = dict(report.logsource) if report.logsource else guess_logsource(report.narrative)
    severity = report.severity or guess_severity(report.narrative)

    # Pick template by priority: IOC > logsource > generic.
    chosen = _ioc_selection(iocs) or _logsource_template(report, logsource)
    if chosen is None:
        chosen = _generic_template(report, logsource)
    selection, events = chosen

    tags = [f"attack.{t.lower()}" for t in techniques] + ["aisoc.author"]

    sigma_dict: dict[str, Any] = {
        "title": title,
        "id": rule_id,
        "status": "experimental",
        "description": report.narrative.strip(),
        "author": report.author,
        "level": severity,
        "logsource": logsource,
        "tags": tags,
        "detection": {
            "selection": selection,
            "condition": "selection",
        },
        "falsepositives": [
            "Legitimate administrative activity — confirm against change management.",
        ],
    }
    yaml_text = _YAML_HEADER + yaml.safe_dump(
        sigma_dict,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=100,
    )
    if not yaml_text.endswith("\n"):
        yaml_text += "\n"

    return sigma_dict, yaml_text, tuple(events), techniques, iocs
