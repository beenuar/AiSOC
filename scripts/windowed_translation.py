#!/usr/bin/env python3
"""The `det-*` rules that need a window, and what became of each one.

Why this file exists
--------------------
``scripts/check_detection_fields.py`` attributes 74 engine-loaded rules to a
"windowed evaluator" family. The windowed engine has existed since Wave 2 and
the exporter beside this file has shipped rules into it, but the two corpora
were disjoint: not one ``wd-*`` id corresponded to a ``det-*`` rule, so
building the engine moved none of these rules and the unreachable count never
changed. Each of the 74 still names a counter no connector emits
(``fail_count``, ``events_per_minute``, ``distinct_secrets_per_minute``),
reads ``None`` on its first clause, and can never fire — while being loaded by
the engine and counted toward the published executable total.

This module records one decision per rule, and the decision is the unit of
work: either the rule is translated into windowed form, or it is refused with
a reason. Nothing may simply disappear. ``scripts/check_windowed_translation.py``
enforces that, and ``scripts/export_detection_ruleset.py`` reads it so a
decided rule leaves the stateless corpus it could never fire in.

How a translation is derived
----------------------------
**From the rule's own clauses, never invented.** A rule like

    {"event_type": "user.session.start", "outcome": "FAILURE",
     "fail_count_gt": 20, "time_window_minutes_lt": 10}

already carries everything a windowed rule needs: the selector is what is left
after the counting and window clauses are removed, the threshold is the ``_gt``
bound plus one, and the window is the time clause. :func:`derive` computes all
three, so a translated rule cannot drift from the number its author chose, and
``check_windowed_translation.py`` re-derives them to prove it.

The one thing the clauses do not always carry is the entity the count
accumulates against. ``request_count_per_src`` names it; ``fail_count`` does
not. Where the name carries no entity the table below supplies one, and the
choice is a field the rule's own source emits rather than a plausible-looking
name — a ``group_by`` nothing emits is the same defect in a new place, because
``fields.get(group_by)`` returns ``None`` and the engine skips the event.

Why some rules are refused
--------------------------
The windowed engine is deliberately narrow: match, group by one entity, count
events or distinct values, threshold, window. It computes no sums, no means,
no variances, and it fires when a count is **high**. A rule that needs any of
those cannot be expressed here, and half-translating it — keeping the count
and dropping the mean — ships something that detects a different thing under
the original's name and severity. Those are refused with the reason stated, and
the refusal travels into the rule's YAML and its marketplace entry so a reader
of the catalogue sees why the rule does not run.

Refusal is not deletion. A refused rule keeps its id, its YAML and its place
in the corpus; it stops being counted as executable, which it never was.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

__all__ = [
    "DECISIONS",
    "Covered",
    "Refusal",
    "Translation",
    "WindowShape",
    "decided_keys",
    "derive",
    "parse_shape",
    "translated_rules",
]


# --------------------------------------------------------------------------
# Decisions
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Translation:
    """This rule becomes a `wd-*` rule.

    ``group_by`` and ``distinct_by`` are the only parts a human chooses; the
    threshold, the window and the residual selector are derived from the
    ``det-*`` spec by :func:`derive`.
    """

    group_by: str
    distinct_by: str = ""
    #: Set only where the default `wd-<slug>` id would collide with a rule the
    #: windowed corpus already ships.
    wd_id: str = ""
    #: Why this entity field, when the counter's name does not name one. Also
    #: the place to record which connector key it comes from.
    entity_note: str = ""


@dataclass(frozen=True)
class Refusal:
    """This rule cannot be expressed as a count over a window.

    ``kind`` groups the reasons so the gate can report them as families rather
    than as 19 unrelated sentences, and so a later phase can find the ones it
    unblocks.
    """

    kind: str
    reason: str


@dataclass(frozen=True)
class Covered:
    """A windowed rule the corpus already ships detects this.

    Distinct from a refusal: the detection exists and runs, so retiring the
    `det-*` loses nothing. The link is what stops it being re-authored.
    """

    by: str
    reason: str


#: Refusal kinds. Named so the gate's summary and a later phase's search agree.
AGGREGATE = "aggregate"  # needs a sum, mean or variance over the window
NOT_WINDOWED = "not-windowed"  # the field is a per-event property, not a counter
RARITY = "rarity"  # fires when a count is LOW; needs the baseline/first-seen store
MULTI_DISTINCT = "multi-distinct"  # two independent distinct counts in one rule
OPERAND_NOT_EMITTED = "operand-not-emitted"  # nothing surfaces the thing to count distinctly

REFUSAL_KINDS = frozenset({AGGREGATE, NOT_WINDOWED, RARITY, MULTI_DISTINCT, OPERAND_NOT_EMITTED})


#: One entry per rule the reachability gate attributes to the windowed family,
#: keyed ``<category>/<slug>`` the way `detections/rule-ids.lock.json` is.
#:
#: Ordered by category then slug so a diff reads as content rather than as
#: churn.
DECISIONS: dict[str, Translation | Refusal | Covered] = {
    # ---------------------------------------------------------------- application
    "application/rate-limit-burst": Translation(group_by="src_ip"),
    "application/api-mass-enumeration-ids": Refusal(
        OPERAND_NOT_EMITTED,
        "counts distinct object ids per source, and no WAF or application source "
        "in this tree surfaces the requested object id as a field — the engine "
        "would count nothing. Revisit when the activity projection lands a "
        "`resource` field (depth plan 2.2).",
    ),
    "application/saas-mass-share-public": Translation(
        group_by="actor_email",
        entity_note="google_workspace.normalize emits actor_email; `user` is not in its output",
    ),
    "application/app-account-enum-reset": Translation(group_by="src_ip"),
    "application/app-docker-insecure-registry-flag": Refusal(
        NOT_WINDOWED,
        "`insecure_registries_count` is the length of a list inside one daemon "
        "config event, not a count over a window. The reachability gate reads it "
        "as windowed because the name ends in `_count`.",
    ),
    "application/app-salesforce-mass-export": Refusal(
        NOT_WINDOWED,
        "`row_count` is a per-event field of one export record, not a count over a window. The Salesforce connector does not surface it.",
    ),
    "application/app-box-public-link-mass-create": Translation(
        group_by="actor_email",
        entity_note="box.normalize emits actor_email",
    ),
    "application/app-servicenow-record-export-bulk": Refusal(
        NOT_WINDOWED,
        "`row_count` is a per-event field of one export record, not a count over a window. The ServiceNow connector does not surface it.",
    ),
    # ---------------------------------------------------------------------- cloud
    "cloud/aws-iam-enumeration": Translation(
        group_by="user_arn",
        distinct_by="event_name",
        entity_note="aws_cloudtrail.normalize emits both user_arn and event_name",
    ),
    "cloud/aws-s3-mass-getobject": Translation(group_by="user_arn"),
    "cloud/azure-resource-mass-delete": Translation(
        group_by="actor",
        entity_note="azure_activity.normalize emits actor; `principal` is not in its output",
    ),
    "cloud/gcp-secret-manager-mass-export": Translation(
        group_by="actor",
        entity_note="gcp_cloud_audit.normalize emits actor",
    ),
    "cloud/aws-iam-create-user-burst": Translation(group_by="user_arn"),
    "cloud/aws-iam-account-summary-recon": Translation(group_by="user_arn"),
    "cloud/aws-iam-list-keys-recon": Refusal(
        OPERAND_NOT_EMITTED,
        "counts distinct *target* users of ListAccessKeys. CloudTrail carries "
        "that in `requestParameters.UserName`, and the matcher has no dotted-path "
        "traversal, so the connector's `user_name` is the caller rather than the "
        "target. Counting the caller would be a different detection.",
    ),
    "cloud/aws-s3-mass-deleteobject": Translation(group_by="user_arn"),
    "cloud/aws-secretsmanager-mass-getsecret": Refusal(
        OPERAND_NOT_EMITTED,
        "counts distinct secrets, which CloudTrail carries in "
        "`requestParameters.SecretId`; the connector surfaces no secret "
        "identifier, so the engine has nothing to be distinct about.",
    ),
    "cloud/azure-ad-bulk-user-creation": Translation(group_by="actor"),
    "cloud/azure-ad-bulk-license-assignment": Translation(group_by="actor"),
    "cloud/azure-arm-locks-removed-bulk": Translation(group_by="actor"),
    "cloud/azure-arm-mass-resource-modify": Translation(group_by="actor"),
    "cloud/azure-keyvault-secret-mass-get": Translation(
        group_by="actor",
        distinct_by="resource",
        entity_note="azure_activity.normalize emits `resource`, which for a Key Vault operation is the secret",
    ),
    "cloud/gcp-iam-service-account-key-mass-create": Translation(group_by="actor"),
    "cloud/gcp-iam-impersonation-burst": Refusal(
        OPERAND_NOT_EMITTED,
        "counts distinct impersonation *targets*. The GCP audit connector emits "
        "the caller (`actor`) and no target service account, so nothing "
        "identifies what is being impersonated.",
    ),
    "cloud/gcp-gcs-mass-delete": Translation(group_by="actor"),
    "cloud/gcp-bq-mass-export": Translation(group_by="actor"),
    "cloud/k8s-secret-mass-get": Translation(
        group_by="k8s_user",
        distinct_by="k8s_object_name",
        entity_note="kubernetes_audit.normalize emits both; k8s_object_name is the secret's name",
    ),
    "cloud/cloud-multi-cross-cloud-mass-egress": Refusal(
        AGGREGATE,
        "`bytes_out_per_minute` is a sum of a numeric field over the window. The "
        "engine counts occurrences and distinct values; it adds nothing up, so "
        "a gigabyte in one transfer and a gigabyte in a thousand are the same "
        "count to it.",
    ),
    # ----------------------------------------------------------------- data-exfil
    "data-exfil/large-egress-personal-cloud": Refusal(
        NOT_WINDOWED,
        "carries a `time_window_minutes_lt` clause and no counter at all, so "
        "there is nothing to accumulate. `bytes_out` is a per-event proxy field; "
        "the window clause is vestigial and is what makes the rule unreachable. "
        "Deleting that one clause is a content decision, not a translation.",
    ),
    "data-exfil/egress-spike-baseline": Refusal(
        AGGREGATE,
        "needs a sum of `bytes_out` per source and a z-score against a learned "
        "baseline. Both are out of scope for a counting engine (the baseline "
        "arrives with depth plan 3.4).",
    ),
    "data-exfil/salesforce-bulk-export": Refusal(
        NOT_WINDOWED,
        "`row_count` is a per-event field of one export record, not a count over a window. The Salesforce connector does not surface it.",
    ),
    "data-exfil/db-mass-row-read": Refusal(
        AGGREGATE,
        "needs a sum of rows read per session and a z-score against a learned baseline; the engine computes neither.",
    ),
    "data-exfil/printer-mass-print-confidential": Refusal(
        AGGREGATE,
        "`page_count_per_user` sums pages across print jobs. Counting jobs "
        "instead would fire on 500 one-page prints and miss one 1,500-page "
        "print, which inverts what the rule is for.",
    ),
    "data-exfil/container-mass-image-export": Translation(
        group_by="actor",
        entity_note="the registry-push sources in this tree normalize the pusher to actor",
    ),
    "data-exfil/secrets-mass-fetch": Translation(
        group_by="actor",
        entity_note="vendor-neutral rule; `actor` is the field every cloud connector here emits",
    ),
    # ------------------------------------------------------------------- endpoint
    "endpoint/ransomware-file-extension-change": Translation(
        group_by="process_name",
        entity_note="EDR connectors normalize the acting binary to process_name",
    ),
    # ------------------------------------------------------------------- identity
    "identity/brute-force-login": Translation(
        group_by="actor_email",
        entity_note="okta.normalize emits actor_email as the account; `user` is not in its output",
    ),
    "identity/password-spray": Translation(
        group_by="src_ip",
        distinct_by="actor_email",
        wd_id="wd-okta-password-spray",
        entity_note=("id overridden because `wd-password-spray` already ships and counts events rather than distinct accounts"),
    ),
    "identity/mfa-fatigue": Translation(
        group_by="actor_email",
        wd_id="wd-okta-mfa-push-bombing",
        entity_note="id overridden because `wd-mfa-fatigue` already ships against a different source shape",
    ),
    "identity/shared-account-login-spike": Translation(group_by="actor_email", distinct_by="src_ip"),
    "identity/kerberoasting": Refusal(
        OPERAND_NOT_EMITTED,
        "counts distinct service principal names requested per account. Windows "
        "4769 carries the SPN in `ServiceName`, which no source in this tree "
        "lifts, so there is nothing to be distinct about.",
    ),
    "identity/ident-password-spray-many-targets": Refusal(
        AGGREGATE,
        "pairs a distinct-user count with a `tries_per_user` ceiling, which is a "
        "mean inside the window. Keeping only the distinct half would widen the "
        "rule into a brute-force detection `wd-bruteforce-auth` already covers.",
    ),
    "identity/ident-password-spray-distributed": Translation(group_by="user", distinct_by="src_ip"),
    "identity/ident-credstuffing-known-breached-list": Translation(group_by="src_ip"),
    "identity/ident-mfa-fatigue-burst": Translation(group_by="user"),
    "identity/ident-account-locked-many-times": Translation(group_by="user"),
    "identity/ident-totp-skewed-clock": Translation(group_by="user"),
    "identity/ident-priv-role-burst-granted": Translation(group_by="actor"),
    "identity/ident-priv-role-removed-bulk": Translation(group_by="actor"),
    "identity/ident-orphan-svc-acct-many-keys": Refusal(
        NOT_WINDOWED,
        "`active_keys_per_account` is the state of an account at one moment, "
        "reported by an inventory event. A window counts what happened, not what "
        "is true; this needs the posture snapshot (depth plan 2.5).",
    ),
    "identity/ident-ad-machine-account-quota-abuse": Translation(group_by="user"),
    "identity/ident-kerberos-failure-spike-from-host": Translation(group_by="hostname"),
    "identity/ident-okta-admin-app-assigned-many-users": Translation(group_by="actor"),
    "identity/ident-okta-mass-deactivate-users": Translation(group_by="actor"),
    "identity/ident-ping-admin-role-burst": Translation(group_by="actor"),
    "identity/ident-oidc-many-clients-from-single-actor": Translation(group_by="actor"),
    "identity/ident-github-org-collaborator-removed-bulk": Translation(group_by="actor"),
    "identity/ident-github-deploy-key-added-org-wide": Translation(group_by="actor", distinct_by="repository"),
    # -------------------------------------------------------------------- network
    "network/c2-beacon-high-frequency": Refusal(
        AGGREGATE,
        "`interval_consistency` is the regularity of inter-arrival times across "
        "the window — a variance, not a count. Keeping only the connection count "
        "turns a beacon detection into a chatty-host detection.",
    ),
    "network/dns-data-exfiltration": Refusal(
        AGGREGATE,
        "`avg_subdomain_len` is a mean over the window. Dropping it leaves "
        "'100 DNS queries in 30 minutes', which every workstation clears.",
    ),
    "network/port-scan-internal": Refusal(
        MULTI_DISTINCT,
        "requires distinct destination ports *and* distinct destinations per "
        "source. The engine holds one distinct operand per rule; splitting this "
        "into two rules would fire twice on one scan and once on neither half.",
    ),
    "network/ssh-failed-from-internet": Translation(group_by="src_ip"),
    "network/smb-lateral-movement": Translation(group_by="src", distinct_by="dst_ip"),
    "network/dns-fast-flux": Refusal(
        OPERAND_NOT_EMITTED,
        "counts distinct A records, which live as a list inside a single DNS "
        "response rather than one per event. The engine counts distinct values "
        "of one field per event, so it cannot see inside the answer set.",
    ),
    "network/icmp-tunnel": Refusal(
        AGGREGATE,
        "`avg_payload_bytes` is a mean over the window, and `packet_count` is a per-flow sum. Counting flow records measures neither.",
    ),
    "network/egress-to-rare-asn": Refusal(
        RARITY,
        "fires when a destination ASN has been seen *fewer* than five times in "
        "thirty days. The engine fires when a count is high; a rarity signal "
        "needs the first-seen store (depth plan 3.3) and the baseline module "
        "(3.4).",
    ),
    "network/ldap-bind-anomaly": Translation(group_by="src_ip"),
    "network/ddos-syn-flood": Translation(group_by="dst_ip"),
    "network/internal-host-spamming-mail": Translation(group_by="src_ip"),
    "network/net-dns-nxdomain-spike": Translation(group_by="src_ip"),
    "network/net-dns-any-query-spike": Translation(group_by="src_ip"),
    "network/net-dns-tunnel-pattern-len": Refusal(
        NOT_WINDOWED,
        "`subdomain_hex_ratio` is a property of one query name, not a count over "
        "a window; the reachability gate reads it as windowed because the name "
        "ends in `_ratio`. It is cheap to derive from the query name and belongs "
        "with the derived fields, not here.",
    ),
    "network/net-dns-fast-flux": Refusal(
        NOT_WINDOWED,
        "`answer_count` is the number of records in one DNS response, a per-event field, not a count over a window.",
    ),
    "network/net-dhcp-starvation": Translation(
        group_by="src_ip",
        entity_note="the relay is identified by the source address on the DHCP event",
    ),
}


# --------------------------------------------------------------------------
# Derivation
# --------------------------------------------------------------------------

#: Clause fields that declare the window rather than the count.
_TIME_UNITS: dict[str, int] = {
    "time_window_minutes": 60,
    "time_window_hours": 3600,
    "time_window_days": 86400,
}

#: Suffixes on the counter's own name that imply a window when no time clause
#: is present. `events_per_minute_gt: 10` is a rate, and the rate names its
#: own denominator.
_NAME_WINDOWS: tuple[tuple[str, int], ...] = (
    ("_per_second", 1),
    ("_per_minute", 60),
    ("_per_hour", 3600),
    ("_per_day", 86400),
)

#: Operator suffixes a counting clause may carry, longest first.
_BOUNDS: tuple[str, ...] = ("gte", "gt", "lte", "lt")

#: Names a counter uses for an entity, mapped to nothing here on purpose: the
#: entity always comes from the decision table, because the alias a rule author
#: wrote ("principal", "src") is not necessarily a field any source emits.
_ENTITY_IN_NAME = re.compile(r"_per_(?P<entity>[a-z0-9]+)$")

#: Matches the counter half of a clause, mirroring the "windowed evaluator"
#: family in `scripts/check_detection_fields.py`. Kept as its own copy rather
#: than imported because that module is a gate with a ratchet and importing it
#: here would make the exporter depend on a CI threshold.
_COUNTER = re.compile(r"_count$|^count_|_per_|time_window|_window_|_5min|_ratio$")


class ShapeError(ValueError):
    """The spec does not have the shape a windowed rule is derived from."""


@dataclass(frozen=True)
class WindowShape:
    """The windowed half of a `det-*` rule, recovered from its clauses."""

    threshold: int
    window_seconds: int
    residual: dict[str, Any]
    #: Clause keys consumed to produce the above, so the gate can prove that
    #: everything else survived into the translated rule untouched.
    consumed: tuple[str, ...] = field(default_factory=tuple)


def _split_bound(key: str) -> tuple[str, str]:
    for bound in _BOUNDS:
        if key.endswith("_" + bound):
            return key[: -len(bound) - 1], bound
    return key, ""


def parse_shape(match_when: dict[str, Any]) -> WindowShape:
    """Recover threshold, window and residual selector from a `det-*` clause set.

    Raises :class:`ShapeError` when the rule carries no counter, two counters,
    or a counter with no upper bound — each of which means the decision table
    should hold a :class:`Refusal` rather than a :class:`Translation`.
    """
    counters: list[tuple[str, str, Any]] = []
    times: list[tuple[str, str, Any]] = []
    for key, value in match_when.items():
        base, bound = _split_bound(key)
        if base in _TIME_UNITS:
            times.append((key, base, value))
        elif _COUNTER.search(base):
            counters.append((key, bound, value))

    if not counters:
        raise ShapeError("no counting clause")
    if len(counters) > 1:
        raise ShapeError(f"{len(counters)} counting clauses; a windowed rule holds one")
    if len(times) > 1:
        raise ShapeError(f"{len(times)} window clauses; a windowed rule holds one")

    counter_key, bound, raw_bound = counters[0]
    if bound == "gt":
        threshold = int(raw_bound) + 1
    elif bound == "gte":
        threshold = int(raw_bound)
    else:
        raise ShapeError(f"counter {counter_key!r} has no lower bound — it fires when the count is low")

    if times:
        time_key, unit, raw_window = times[0]
        window_seconds = int(float(raw_window) * _TIME_UNITS[unit])
    else:
        time_key = ""
        window_seconds = 0
        base, _ = _split_bound(counter_key)
        for suffix, seconds in _NAME_WINDOWS:
            if suffix in base:
                window_seconds = seconds
                break
        if "_5min" in base:
            window_seconds = 300
        if not window_seconds:
            raise ShapeError(f"counter {counter_key!r} declares no window and carries no rate suffix")

    consumed = tuple(k for k in (counter_key, time_key) if k)
    residual = {k: v for k, v in match_when.items() if k not in consumed}
    if threshold < 1 or window_seconds < 1:
        raise ShapeError(f"derived threshold {threshold} / window {window_seconds}s is not a window")
    return WindowShape(threshold=threshold, window_seconds=window_seconds, residual=residual, consumed=consumed)


def derive(category: str, spec: dict[str, Any], decision: Translation) -> dict[str, Any]:
    """Build the `wd-*` rule for one `det-*` spec."""
    shape = parse_shape(spec["match_when"])
    rule = {
        "id": decision.wd_id or f"wd-{spec['slug']}",
        "name": spec["name"],
        "severity": spec["severity"],
        "category": category,
        "mitre": [str(m).upper() for m in spec.get("mitre") or []],
        "match_when": shape.residual,
        "group_by": decision.group_by,
        "threshold": shape.threshold,
        "window_seconds": shape.window_seconds,
        "translated_from": spec["slug"],
    }
    if decision.distinct_by:
        rule["distinct_by"] = decision.distinct_by
    return rule


def decided_keys() -> frozenset[str]:
    """`<category>/<slug>` for every rule this module has decided."""
    return frozenset(DECISIONS)


def _load_specs() -> dict[str, tuple[str, dict[str, Any]]]:
    from detection_specs_index import all_specs  # noqa: PLC0415

    return {f"{category}/{spec['slug']}": (category, spec) for category, spec in all_specs()}


def translated_rules() -> list[dict[str, Any]]:
    """Every `wd-*` rule derived from a decided `det-*` spec, in table order."""
    specs = _load_specs()
    out: list[dict[str, Any]] = []
    for key, decision in DECISIONS.items():
        if not isinstance(decision, Translation):
            continue
        if key not in specs:
            raise SystemExit(
                f"windowed_translation: {key!r} is decided but no spec declares it. "
                "A slug was renamed or removed; update DECISIONS in the same change."
            )
        category, spec = specs[key]
        out.append(derive(category, spec, decision))
    return out


def retirement_reason(key: str) -> str:
    """Catalogue-facing sentence for a decided rule, or '' when undecided."""
    decision = DECISIONS.get(key)
    if isinstance(decision, Translation):
        wd_id = decision.wd_id or f"wd-{key.split('/', 1)[1]}"
        return f"superseded by the windowed rule {wd_id}; this stateless form named a counter no source emits"
    if isinstance(decision, Covered):
        return f"already detected by the windowed rule {decision.by}; {decision.reason}"
    if isinstance(decision, Refusal):
        return f"not executable ({decision.kind}): {decision.reason}"
    return ""
