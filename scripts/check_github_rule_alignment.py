#!/usr/bin/env python3
"""CI gate: GitHub detection rules fire on what the GitHub connector emits.

Issue #1545 measured ten of the twelve GitHub-product rules unable to fire on
real connector output, for three distinct reasons the field-reachability gate
cannot see:

* the connector emits ``event_type=github.{action}`` while rules matched the
  unprefixed value — a *value* mismatch over a field that exists;
* rules named audit actions that are not in GitHub's vocabulary at all
  (``deploy_key.create``, ``repo.visibility_change``, ``runner_register`` —
  GitHub logs a deploy-key add as ``public_key.create`` and a visibility
  change as ``repo.access``);
* rules read fields no GitHub telemetry carries (``diff_text``,
  ``approver_role``, a created token's ``scopes``).

Fixture replay cannot catch any of this because fixtures are synthesized from
the rule they test. This gate replays a **real-shaped org audit-log entry**
(field names per GitHub's audit-log event reference) through the real
``GitHubConnector.normalize()`` — out of process, because ``services/fusion``
and ``services/connectors`` both name their package ``app`` — and the real
``DetectionEngine``, and fails unless the rule fires.

Every enabled GitHub-product rule must carry a proof entry in
``PROOF_EVENTS``; a new GitHub rule without one fails here with instructions,
which is the regression protection the issue asked for. Rules whose only
stateful clause is a behavioural-baseline score are proven on their
deterministic clauses (the baseline is Redis-backed and not replayable here)
plus a pin that the baseline enrichment actually publishes those fields.
Windowed-translated rules are proven against the real windowed engine's own
namespace builder: the selector must match and the group-by / distinct-by
fields must be present, because a distinct-by naming a field the entry does
not carry never counts anything.

Usage:
    python3 scripts/check_github_rule_alignment.py --check
    python3 scripts/check_github_rule_alignment.py --self-test
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main

ROOT = repo_root()
WORKER = ROOT / "scripts" / "connector_normalize_worker.py"
RULESET = ROOT / "services" / "fusion" / "app" / "data" / "detection_ruleset.json"
WINDOWED_RULESET = ROOT / "services" / "fusion" / "app" / "data" / "windowed_ruleset.json"
BASELINES_MODULE = ROOT / "services" / "fusion" / "app" / "services" / "baselines.py"

#: Fields the behavioural-baseline enrichment (`app/services/baselines.py`,
#: depth plan 3.4) merges into the namespace at evaluate_async time. Pinned by
#: name and re-checked against the module's own source below, so a renamed
#: baseline output fails here rather than leaving a rule proven against a
#: field nothing publishes any more.
BASELINE_FIELDS = frozenset({"baseline_action_rarity", "baseline_principal_volume_z"})

_PROOF_TS = 1761670000000  # ms epoch, matches the audit log's integer form


def _entry(action: str, **extra: Any) -> dict[str, Any]:
    """A real-shaped org audit-log entry for ``action``.

    Field names follow GitHub's audit-log event reference: every entry
    carries ``action`` / ``actor`` / ``org`` / ``created_at`` (ms epoch) /
    ``@timestamp`` / ``_document_id``; repo-scoped events carry ``repo`` as
    the full ``org/name`` slug; ``actor_ip`` appears when the org discloses
    IPs. Addresses are RFC 5737 documentation ranges.
    """
    base: dict[str, Any] = {
        "_aisoc_stream": "audit_log",
        "_document_id": f"proof-{action}",
        "@timestamp": _PROOF_TS,
        "created_at": _PROOF_TS,
        "action": action,
        "actor": "proof-actor",
        "actor_ip": "203.0.113.5",
        "org": "example-org",
        "user": "proof-actor",
    }
    base.update(extra)
    return base


#: One real-shaped audit entry per GitHub rule slug. The entry is what GitHub
#: documents for that action, NOT what the rule happens to match — the whole
#: point is that the two must agree through the real connector and engine.
PROOF_EVENTS: dict[str, dict[str, Any]] = {
    # A deploy-key add is logged as public_key.create with the repo slug
    # ("An SSH key was added to a user account or a deploy key was added to
    # a repository" — the repo field is what marks the deploy-key case).
    "app-deploy-key-added-github": _entry("public_key.create", repo="example-org/payments-core"),
    "app-protected-branch-disabled": _entry("protected_branch.policy_override", repo="example-org/payments-core", branch="main"),
    # 203.0.113.5 is outside every RFC 1918 / loopback / link-local range,
    # so the derived ip_is_internal is False — the external-IP case.
    "app-self-hosted-runner-external": _entry("org.register_self_hosted_runner"),
    "github-public-repo-flip": _entry("repo.access", repo="example-org/internal-tooling", public_repo=True, previous_visibility="private"),
    "ident-github-org-2fa-disabled": _entry("org.disable_two_factor_requirement"),
    "ta-github-rare-action-on-org-settings": _entry("org.update_default_repository_permission"),
    "ta-github-clone-volume-spike": _entry("git.clone", repo="example-org/payments-core", transport_protocol_name="ssh"),
    # Windowed-translated rules: the selector and the group-by/distinct-by
    # fields are proven against the same entries.
    "ident-github-org-collaborator-removed-bulk": _entry("org.remove_member", user="departed-user"),
    "ident-github-deploy-key-added-org-wide": _entry("public_key.create", repo="example-org/payments-core"),
}


def _github_specs() -> list[tuple[str, dict[str, Any]]]:
    from detection_specs_index import all_specs  # noqa: PLC0415 — scripts/ sibling, path set above

    return [(category, spec) for category, spec in all_specs() if (spec.get("log_source") or {}).get("product") == "github"]


def _normalize_batch(raws: list[dict[str, Any]]) -> list[dict[str, Any] | None]:
    """Each raw entry through the real GitHubConnector.normalize(), one process.

    Out of process for the reason `connector_normalize_worker.py` documents:
    both services name their package ``app``, so the connector and the engine
    cannot be imported side by side.
    """
    lines = "\n".join(json.dumps({"emitter": "github", "raw": raw}) for raw in raws)
    done = subprocess.run(  # noqa: S603
        [sys.executable, str(WORKER)],
        input=lines,
        capture_output=True,
        text=True,
        check=True,
    )
    out: list[dict[str, Any] | None] = []
    for line in done.stdout.strip().splitlines():
        if not line.strip():
            continue
        res = json.loads(line)
        out.append(res["normalized"] if res.get("ok") else None)
    if len(out) != len(raws):
        raise SystemExit(f"connector worker returned {len(out)} results for {len(raws)} inputs")
    return out


def _message(normalized: dict[str, Any]) -> dict[str, Any]:
    return {"ocsf_event": {"raw_data": json.dumps(normalized, default=str)}}


def _split_stateful(match_when: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """(deterministic clauses, baseline clauses) of one ``match_when``."""
    from detection_specs_part3_helpers import split_op  # noqa: PLC0415 — scripts/ sibling

    deterministic: dict[str, Any] = {}
    stateful: dict[str, Any] = {}
    for key, value in match_when.items():
        field, _ = split_op(key)
        (stateful if field in BASELINE_FIELDS else deterministic)[key] = value
    return deterministic, stateful


def check(
    specs: list[tuple[str, dict[str, Any]]],
    proof_events: dict[str, dict[str, Any]],
    engine_rules: dict[str, dict[str, Any]],
    windowed_rules: dict[str, dict[str, Any]],
    retired: dict[str, str],
) -> list[str]:
    """Every problem that stops a GitHub rule being proven against the connector."""
    sys.path.insert(0, str(ROOT / "services" / "fusion"))
    from app.services.detection_engine import DetectionEngine  # noqa: PLC0415 — package collision, see module docstring
    from app.services.detection_matcher import matches  # noqa: PLC0415
    from app.services.windowed_detection import WindowedDetectionEngine  # noqa: PLC0415

    problems: list[str] = []

    baselines_source = BASELINES_MODULE.read_text(encoding="utf-8") if BASELINES_MODULE.exists() else ""
    for field in sorted(BASELINE_FIELDS):
        if field not in baselines_source:
            problems.append(f"baseline field {field!r} is not published by app/services/baselines.py — the pin above is stale")

    # Normalize every proof entry once, through the real connector.
    slugs = sorted(proof_events)
    normalized_by_slug: dict[str, dict[str, Any] | None] = dict(zip(slugs, _normalize_batch([proof_events[s] for s in slugs]), strict=True))
    for slug, normalized in normalized_by_slug.items():
        if normalized is None:
            problems.append(f"{slug}: the connector rejected its proof entry")

    for category, spec in specs:
        slug = str(spec["slug"])
        key = f"{category}/{slug}"
        reason = retired.get(key, "")
        windowed = windowed_rules.get(f"wd-{slug}")

        if reason and windowed is None:
            # Retired with a reason and genuinely gone from both corpora:
            # nothing to prove, but it must actually be gone.
            if slug in engine_rules:
                problems.append(f"{slug}: retired ({reason[:80]}…) but still loaded by the stateless engine")
            continue

        proof = proof_events.get(slug)
        if proof is None:
            problems.append(
                f"{slug}: enabled GitHub rule with no proof entry — add a real-shaped audit entry for it to "
                f"PROOF_EVENTS in {Path(__file__).name} (field names per GitHub's audit-log event reference)"
            )
            continue
        normalized = normalized_by_slug.get(slug)
        if normalized is None:
            continue  # already reported above

        if windowed is not None:
            # Proven against the real windowed engine's own namespace builder.
            fields = WindowedDetectionEngine._fields(_message(normalized))
            if not matches(windowed.get("match_when") or {}, fields):
                selector = json.dumps(windowed.get("match_when"))
                problems.append(f"wd-{slug}: selector {selector} does not match the connector's output for its proof entry")
            for role in ("group_by", "distinct_by"):
                name = windowed.get(role)
                if name and fields.get(name) in (None, ""):
                    problems.append(
                        f"wd-{slug}: {role}={name!r} is not present in the connector's output — "
                        "a window keyed on a missing field never counts"
                    )
            continue

        rule = engine_rules.get(slug)
        if rule is None:
            problems.append(f"{slug}: GitHub spec is neither loaded by the engine nor retired with a reason")
            continue

        deterministic, stateful = _split_stateful(rule.get("match_when") or {})
        if stateful:
            # The baseline score is Redis-backed state this gate cannot
            # replay; the deterministic clauses are what alignment with the
            # connector means for these rules.
            fields = DetectionEngine._raw_fields({"raw_data": json.dumps(normalized, default=str)})
            if not matches(deterministic, fields):
                problems.append(
                    f"{slug}: deterministic clauses {json.dumps(deterministic)} do not match the connector's output for its proof entry"
                )
            continue

        engine = DetectionEngine(rules=[rule])
        if not any(hit.rule_id == rule["id"] for hit in engine.evaluate(_message(normalized))):
            fields = DetectionEngine._raw_fields({"raw_data": json.dumps(normalized, default=str)})
            visible = {k: fields.get(k) for k in sorted(set((rule.get("match_when") or {}).keys()))}
            problems.append(
                f"{slug}: did not fire on the connector's output for its proof entry "
                f"(match_when={json.dumps(rule.get('match_when'))}; the clause keys read {json.dumps(visible, default=str)})"
            )

    return problems


def _load_inputs() -> tuple[list[tuple[str, dict[str, Any]]], dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, str]]:
    from rule_retirement import retired  # noqa: PLC0415 — scripts/ sibling

    for path in (RULESET, WINDOWED_RULESET, WORKER):
        if not path.exists():
            raise SystemExit(f"{Path(sys.argv[0]).name}: missing {path.relative_to(ROOT)} — nothing to verify against")
    ruleset = json.loads(RULESET.read_text(encoding="utf-8"))
    engine_rules = {str(r.get("slug")): r for r in ruleset.get("rules", [])}
    windowed = json.loads(WINDOWED_RULESET.read_text(encoding="utf-8"))
    windowed_rules = {str(r.get("id")): r for r in windowed.get("rules", [])}
    specs = _github_specs()
    if not specs:
        raise SystemExit(f"{Path(sys.argv[0]).name}: found no GitHub-product specs — the spec tables moved; refusing to pass on nothing")
    return specs, engine_rules, windowed_rules, retired()


def _self_test() -> int:
    # The self-test proves the *checker* can fail, over a synthetic corpus it
    # controls; the real tree's inputs are exercised by `--check`, which CI
    # runs immediately before this.

    # A rule matching the unprefixed event_type — the exact defect shape of
    # issue #1545 — must be reported, through the real connector and engine.
    slug = "selftest-unprefixed-event-type"
    broken_rule: dict[str, Any] = {
        "id": "det-selftest-000",
        "slug": slug,
        "name": "self-test: unprefixed event_type",
        "severity": "low",
        "category": "application",
        "mitre": [],
        "match_when": {"event_type": "public_key.create"},
    }
    broken_specs: list[tuple[str, dict[str, Any]]] = [("application", {"slug": slug, "log_source": {"product": "github"}})]
    broken_proof = {slug: _entry("public_key.create", repo="example-org/payments-core")}
    caught = check(broken_specs, broken_proof, {slug: broken_rule}, {}, {})
    results = [
        (
            "reports a rule matching the unprefixed event_type (the issue #1545 defect shape)",
            any("did not fire" in p for p in caught),
        )
    ]

    # The aligned form of the same rule must pass, so the detection above is
    # the gate seeing the defect rather than the gate failing everything.
    aligned_rule = dict(broken_rule, match_when={"action": "public_key.create", "repo_contains": "/"})
    clean = check(broken_specs, broken_proof, {slug: aligned_rule}, {}, {})
    results.append(("accepts the same rule claused on the connector's real output", not clean))

    # A windowed rule whose distinct_by names a field the entry does not
    # carry must be reported — that window never counts anything.
    wd: dict[str, Any] = {
        "id": f"wd-{slug}",
        "match_when": {"action": "public_key.create"},
        "group_by": "actor",
        "distinct_by": "repository_full_slug_that_nothing_emits",
    }
    wd_caught = check(broken_specs, broken_proof, {}, {f"wd-{slug}": wd}, {})
    results.append(
        ("reports a windowed distinct_by naming a field the connector does not emit", any("never counts" in p for p in wd_caught))
    )

    results.append(
        (
            "an enabled GitHub rule without a proof entry is reported",
            any("no proof entry" in p for p in check(broken_specs, {}, {slug: aligned_rule}, {}, {})),
        )
    )

    return self_test_main(Path(__file__).name, ["--check"], extra=results)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify and exit nonzero on any problem")
    parser.add_argument("--self-test", action="store_true", help="prove the gate can fail")
    args = parser.parse_args()

    if args.self_test:
        return _self_test()

    specs, engine_rules, windowed_rules, retired = _load_inputs()
    problems = check(specs, PROOF_EVENTS, engine_rules, windowed_rules, retired)
    checked = len(specs)
    if problems:
        print(f"github rule alignment: {len(problems)} problem(s) across {checked} GitHub-product specs", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(f"github rule alignment: OK — {checked} GitHub-product specs proven against the real connector and engine")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
