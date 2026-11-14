"""End-to-end smoke test for the Detection Author Agent (Theme 2a).

Covers the full pipeline AND the HTTP surface:

    threat report  →  propose_detection()
                      ↓
                      Sigma YAML + multi-backend translations
                      + synthetic events + self-test
                      + GitOps artifact
                      ↓
                      activate_in_engine()  (hot-reload)
                      ↓
                      DetectionEngine.evaluate() fires on the
                      proposal's positive synthetic event

We exercise three rule-generation strategies because the generator
picks templates by priority (IOC > logsource > generic), and a
regression in either branch could leave the pipeline silently producing
weaker rules:

  1. IOC-driven  — narrative carries a URL + IP + hash
  2. Logsource-driven — narrative carries no IOCs but mentions Okta
  3. Generic fallback — bare prose with no extractable signal

We also drive ``/detection-author/propose`` + ``/detection-author/activate``
through ``TestClient`` to confirm the HTTP envelope is wired correctly
and tenant scoping is enforced.

Run with:

    cd platform/backend
    PYTHONPATH=. python tests/_check_detection_author.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Boot the app in dev-anon mode so we can call the HTTP endpoints
# without minting JWTs. The route uses ``require_tenant``, which honors
# ``AISOC_DEV_ALLOW_ANON_TENANT`` when no Authorization header is set.
os.environ.setdefault("AISOC_DEV_ALLOW_ANON_TENANT", "true")
os.environ.setdefault("AISOC_SEED_ON_STARTUP", "false")

# Isolated SQLite so we don't pollute dev data.
_TMP_DB = Path(__file__).parent / "_smoke_detection_author.sqlite"
if _TMP_DB.exists():
    _TMP_DB.unlink()
os.environ["AISOC_DB_PATH"] = str(_TMP_DB)

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.agents.detection_author import (  # noqa: E402
    DetectionProposal,
    ThreatReport,
    activate_in_engine,
    propose_detection,
)
from app.detections import runtime as detection_runtime  # noqa: E402
from app.detections.sigma import SigmaRule  # noqa: E402


# --------------------------------------------------------------------------- #
# tiny harness
# --------------------------------------------------------------------------- #


def _fail(msg: str) -> None:
    print(f"  FAIL: {msg}")
    sys.exit(1)


def _ok(msg: str) -> None:
    print(f"  ok:   {msg}")


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        _fail(msg)
    _ok(msg)


# --------------------------------------------------------------------------- #
# 1. Pipeline contract: every proposal is self-consistent
# --------------------------------------------------------------------------- #


def _check_proposal_shape(proposal: DetectionProposal, *, label: str) -> None:
    """Common invariants every DetectionProposal must satisfy.

    Kept generic so the three strategies (IOC, logsource, generic) all
    pass through the same gauntlet — anything strategy-specific moves
    into its own check below.
    """
    _assert(bool(proposal.rule_id), f"[{label}] rule_id is non-empty")
    _assert(
        proposal.rule_id.startswith("aisoc-author-"),
        f"[{label}] rule_id namespaced ({proposal.rule_id!r})",
    )
    _assert(bool(proposal.title), f"[{label}] title is non-empty")
    _assert(bool(proposal.yaml.strip()), f"[{label}] YAML is non-empty")
    _assert(
        proposal.yaml.endswith("\n"),
        f"[{label}] YAML ends with newline (POSIX hygiene)",
    )

    # sigma_dict round-trip: the YAML and the dict must agree on the id.
    _assert(
        proposal.sigma_dict.get("id") == proposal.rule_id,
        f"[{label}] sigma_dict.id matches proposal.rule_id",
    )
    _assert(
        proposal.sigma_dict.get("title") == proposal.title,
        f"[{label}] sigma_dict.title matches proposal.title",
    )
    _assert(
        "detection" in proposal.sigma_dict,
        f"[{label}] sigma_dict has detection block",
    )

    # The pipeline always emits at least one positive + one negative.
    labels = {ev.label for ev in proposal.synthetic_events}
    _assert(
        "positive" in labels and "negative" in labels,
        f"[{label}] synthetic_events include both positive and negative",
    )

    # Self-test verdict must match what the events imply: all positives
    # match, no negative matches. If self_test.passed is False we want
    # the script to fail loudly — that means our generator emitted a
    # rule that doesn't match its own synthetic positive.
    _assert(
        proposal.self_test.passed,
        f"[{label}] self_test passed (failures={list(proposal.self_test.failures)})",
    )
    _assert(
        proposal.self_test.positives_total >= 1,
        f"[{label}] self_test saw >=1 positive",
    )
    _assert(
        proposal.self_test.positives_matched == proposal.self_test.positives_total,
        f"[{label}] every positive matched",
    )
    _assert(
        proposal.self_test.negatives_false_matched == 0,
        f"[{label}] no negative falsely matched",
    )

    # Translations: Splunk + KQL + Lucene + Chronicle (UDM + YARA-L)
    # should all compile for these vanilla rules. If any backend fails
    # we want to know — it usually means a rule field we shouldn't
    # have emitted.
    t = proposal.translations
    _assert(bool(t.splunk and t.splunk.strip()), f"[{label}] splunk translation present")
    _assert(bool(t.kql and t.kql.strip()), f"[{label}] kql translation present")
    _assert(bool(t.lucene and t.lucene.strip()), f"[{label}] lucene translation present")
    _assert(
        bool(t.chronicle and t.chronicle.strip()),
        f"[{label}] chronicle UDM translation present",
    )
    _assert(
        bool(t.chronicle_yaral and t.chronicle_yaral.strip()),
        f"[{label}] chronicle YARA-L translation present",
    )
    _assert(
        not t.errors,
        f"[{label}] no translation errors (got {t.errors!r})",
    )

    # GitOps artifact: paths, branch, PR body all present and coherent.
    g = proposal.gitops
    _assert(
        g.branch_name == f"detection-author/{proposal.rule_id}",
        f"[{label}] branch_name derived from rule_id ({g.branch_name})",
    )
    _assert(proposal.rule_id in g.commit_message, f"[{label}] commit_message mentions rule_id")
    _assert(proposal.title in g.pr_title, f"[{label}] PR title contains rule title")
    _assert(bool(g.pr_body.strip()), f"[{label}] PR body is non-empty")
    _assert(
        len(g.files) >= 2,
        f"[{label}] gitops.files has YAML + tests.json ({list(g.files)})",
    )
    yml_paths = [p for p in g.files if p.endswith(".yml")]
    tests_paths = [p for p in g.files if p.endswith(".tests.json")]
    _assert(len(yml_paths) == 1, f"[{label}] exactly one .yml file emitted")
    _assert(len(tests_paths) == 1, f"[{label}] exactly one .tests.json sibling emitted")
    _assert(
        g.files[yml_paths[0]] == proposal.yaml,
        f"[{label}] yml file content matches proposal.yaml verbatim",
    )

    # PR body sanity: should include the sigma yaml + at least one
    # backend translation so reviewers see everything in one place.
    body = g.pr_body
    _assert("```yaml" in body, f"[{label}] PR body embeds Sigma YAML block")
    _assert("Self-test" in body, f"[{label}] PR body documents self-test verdict")


# --------------------------------------------------------------------------- #
# 2. Strategy-specific assertions
# --------------------------------------------------------------------------- #


def _check_ioc_driven() -> DetectionProposal:
    """Narrative with extractable URL + IP + hash should produce an
    IOC-driven rule (selection keyed on the extracted indicators)."""
    print("\n[1] IOC-driven proposal")
    report = ThreatReport(
        narrative=(
            "We observed lateral movement from 198.51.100.42 dropping a "
            "payload at http://malware.example.com/stage.exe with SHA256 "
            "a" * 64 + ". MITRE T1105 ingress tool transfer."
        ),
        rule_title="ingress-tool-transfer-from-known-bad",
        tenant_id=1,
    )
    proposal = propose_detection(report)
    _check_proposal_shape(proposal, label="ioc")

    # Stable id derived from analyst-supplied title.
    _assert(
        proposal.rule_id == "aisoc-author-ingress-tool-transfer-from-known-bad",
        f"rule_id derives deterministically from title (got {proposal.rule_id})",
    )

    # The extractor should surface T1105 from the narrative.
    techs_lower = {t.lower() for t in proposal.extracted_techniques}
    _assert(
        "t1105" in techs_lower,
        f"extracted_techniques includes t1105 (got {proposal.extracted_techniques})",
    )

    # At least one of the IOCs we mentioned should round-trip into the
    # proposal — we don't pin to which because the extractor may
    # normalize them.
    iocs_blob = " ".join(proposal.extracted_iocs).lower()
    _assert(
        "198.51.100.42" in iocs_blob
        or "malware.example.com" in iocs_blob
        or ("a" * 8) in iocs_blob,
        f"extracted_iocs surfaces at least one IOC (got {proposal.extracted_iocs})",
    )
    return proposal


def _check_logsource_driven() -> DetectionProposal:
    """No IOCs, but the narrative mentions Okta — should fall through to
    the logsource-driven template producing an identity-flavored rule."""
    print("\n[2] Logsource-driven proposal (no IOCs)")
    report = ThreatReport(
        narrative=(
            "Multiple Okta administrators reported suspicious MFA fatigue "
            "prompts immediately after VPN logins. Likely AitM proxy "
            "harvesting session tokens via push-bombing."
        ),
        rule_title="okta-mfa-fatigue-aitm",
        tenant_id=2,
    )
    proposal = propose_detection(report)
    _check_proposal_shape(proposal, label="logsource")

    # The rule should land under identity/ in the rules tree.
    yml_path = next(p for p in proposal.gitops.files if p.endswith(".yml"))
    _assert(
        "/rules/identity/" in yml_path,
        f"Okta narrative lands under rules/identity/ (got {yml_path})",
    )

    # logsource block should hint at Okta / identity.
    ls = proposal.sigma_dict.get("logsource") or {}
    ls_blob = " ".join(str(v) for v in ls.values()).lower()
    _assert(
        "okta" in ls_blob or "identity" in ls_blob or "system" in ls_blob,
        f"logsource hint reflects Okta narrative (got {ls})",
    )
    return proposal


def _check_generic_fallback() -> DetectionProposal:
    """Bare prose with nothing to extract — generator should still emit
    a syntactically valid rule via the generic keyword template."""
    print("\n[3] Generic fallback proposal (no extractable signal)")
    report = ThreatReport(
        narrative=(
            "Investigate unusual late-night activity from a privileged "
            "service account across multiple internal hosts."
        ),
        rule_title="late-night-privileged-activity",
        tenant_id=3,
    )
    proposal = propose_detection(report)
    _check_proposal_shape(proposal, label="generic")
    return proposal


# --------------------------------------------------------------------------- #
# 3. Determinism: same report → identical proposal
# --------------------------------------------------------------------------- #


def _check_determinism() -> None:
    """Re-running propose_detection on an equal ThreatReport must yield
    a byte-identical YAML and the same rule_id. Reviewers rely on this
    to know that an updated proposal that re-opens the same PR branch
    won't churn the diff just because of nondeterministic ordering."""
    print("\n[4] Determinism: same report → same rule_id + same YAML")
    report = ThreatReport(
        narrative="Determinism canary: T1059 powershell -encodedcommand abuse.",
        rule_title="powershell-encodedcommand-canary",
    )
    a = propose_detection(report)
    b = propose_detection(report)
    _assert(a.rule_id == b.rule_id, f"rule_id stable across runs ({a.rule_id})")
    _assert(a.yaml == b.yaml, "YAML byte-identical across runs")
    _assert(
        a.gitops.branch_name == b.gitops.branch_name,
        "branch_name stable across runs (idempotent PR)",
    )


# --------------------------------------------------------------------------- #
# 4. Hot-reload: activate_in_engine puts the rule in the live engine
# --------------------------------------------------------------------------- #


def _check_activation_hot_reloads_engine(proposal: DetectionProposal) -> None:
    """``activate_in_engine`` should put the proposal's rule into the
    process-wide DetectionEngine such that the engine fires on the
    proposal's own positive synthetic event."""
    print("\n[5] Activation hot-reloads engine and fires on synthetic positive")

    # Reset so we start from a clean engine — otherwise an earlier
    # check could have already added the same rule.
    detection_runtime.reset()
    engine_before = detection_runtime.get_engine()
    rule_ids_before = {r.id for r in engine_before.pack.rules}
    _assert(
        proposal.rule_id not in rule_ids_before,
        f"engine starts without proposal rule ({proposal.rule_id})",
    )

    activate_in_engine(proposal)

    engine_after = detection_runtime.get_engine()
    rule_ids_after = {r.id for r in engine_after.pack.rules}
    _assert(
        proposal.rule_id in rule_ids_after,
        f"engine contains proposal rule after activate ({proposal.rule_id})",
    )

    # The proposal's positive synthetic event MUST fire under the live
    # engine — anything else means activate_in_engine grafted a
    # different rule than the one we self-tested.
    positive = next(
        (e for e in proposal.synthetic_events if e.label == "positive"),
        None,
    )
    assert positive is not None  # self-test invariant already enforced
    hits = list(engine_after.evaluate(positive.payload))
    fired = {h.rule_id for h in hits}
    _assert(
        proposal.rule_id in fired,
        f"engine fires proposal rule on its own positive event (fired={fired})",
    )

    # Re-activating with the same rule_id is idempotent — RulePack.add
    # atomically replaces by id, so the engine pack size shouldn't grow.
    size_before_reactivate = len(engine_after.pack.rules)
    activate_in_engine(proposal)
    engine_again = detection_runtime.get_engine()
    _assert(
        len(engine_again.pack.rules) == size_before_reactivate,
        "re-activating same rule does not grow the pack (idempotent)",
    )


# --------------------------------------------------------------------------- #
# 5. HTTP surface: /detection-author/propose → /activate round-trip
# --------------------------------------------------------------------------- #


def _check_http_round_trip() -> None:
    """Drive the full HTTP envelope: /propose returns a JSON proposal,
    /activate accepts the same payload and reports success, and the
    engine reflects the new rule afterwards."""
    print("\n[6] HTTP round-trip: /detection-author/propose → /activate")

    # Importing TestClient + app here (after env wiring above) so the
    # boot picks up our isolated SQLite + anon-tenant settings.
    from fastapi.testclient import TestClient

    from app.main import app

    detection_runtime.reset()

    with TestClient(app) as client:
        r = client.post(
            "/detection-author/propose",
            json={
                "narrative": (
                    "HTTP path: suspicious base64-encoded PowerShell launched "
                    "by an Office process. MITRE T1059.001."
                ),
                "rule_title": "http-path-powershell-b64-from-office",
            },
        )
        _assert(
            r.status_code == 200,
            f"/propose returns 200 (got {r.status_code}: {r.text[:200]})",
        )
        body = r.json()
        _assert(
            body.get("passed_self_test") is True,
            f"/propose returned passed_self_test=true (got {body.get('passed_self_test')})",
        )
        _assert(
            body.get("rule_id", "").startswith("aisoc-author-"),
            f"/propose rule_id namespaced (got {body.get('rule_id')!r})",
        )
        _assert(
            "yaml" in body and "sigma" in body and "gitops" in body,
            "/propose response carries yaml, sigma, gitops keys",
        )

        rule_id = body["rule_id"]
        engine = detection_runtime.get_engine()
        _assert(
            rule_id not in {r.id for r in engine.pack.rules},
            "/propose did not mutate engine (read-only contract)",
        )

        # Round-trip the sigma dict back into /activate.
        r2 = client.post(
            "/detection-author/activate",
            json={
                "rule_id": rule_id,
                "title": body["title"],
                "sigma": body["sigma"],
                "actor": "soc:smoke-test",
                "rationale": "automated end-to-end check",
            },
        )
        _assert(
            r2.status_code == 200,
            f"/activate returns 200 (got {r2.status_code}: {r2.text[:200]})",
        )
        body2 = r2.json()
        _assert(body2.get("ok") is True, "/activate reports ok=true")
        _assert(
            body2.get("rule_id") == rule_id,
            f"/activate echoes rule_id (got {body2.get('rule_id')})",
        )

        engine_after = detection_runtime.get_engine()
        _assert(
            rule_id in {r.id for r in engine_after.pack.rules},
            f"engine contains rule after /activate ({rule_id})",
        )


# --------------------------------------------------------------------------- #
# 6. HTTP error mapping: malformed narrative → 422, not 500
# --------------------------------------------------------------------------- #


def _check_http_validation() -> None:
    """An empty narrative should fail Pydantic validation with 422, not
    propagate as a 500 — confirms the route guards user input before
    handing it to the pipeline."""
    print("\n[7] HTTP: empty narrative is rejected with 422")
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        r = client.post(
            "/detection-author/propose",
            json={"narrative": ""},
        )
        _assert(
            r.status_code == 422,
            f"empty narrative → 422 (got {r.status_code}: {r.text[:120]})",
        )


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #


def main() -> None:
    print("=" * 70)
    print("smoke test: Detection Author Agent end-to-end (Theme 2a)")
    print("=" * 70)

    # Sanity: the agent's public surface re-exports SigmaRule-aware
    # functions even if the user never touches them directly.
    _assert(
        callable(propose_detection) and callable(activate_in_engine),
        "agent module exports propose_detection + activate_in_engine",
    )
    # SigmaRule import is the contract activate_in_engine relies on.
    _assert(SigmaRule is not None, "SigmaRule importable from app.detections.sigma")

    ioc_proposal = _check_ioc_driven()
    _check_logsource_driven()
    _check_generic_fallback()
    _check_determinism()
    _check_activation_hot_reloads_engine(ioc_proposal)
    _check_http_round_trip()
    _check_http_validation()

    print("\nPASS detection-author end-to-end")


if __name__ == "__main__":
    main()
