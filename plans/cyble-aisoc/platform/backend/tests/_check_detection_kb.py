"""Smoke test for the Detection Knowledge Base (fourth memory layer).

Covers:
1. The bundled rule pack loads from ``app/detections/rules/`` and the
   singleton survives a reload.
2. Free-text search returns relevant rules (semantic + keyword hybrid)
   for queries the index never saw verbatim.
3. Filters (severity, tag, logsource) narrow the result set without
   breaking ranking.
4. Browse-by-tag / browse-by-logsource short-circuit the embedding
   path and still return a stable ordering.
5. ``by_id`` round-trips a known rule and ``add_rule`` overrides the
   built-in by id without duplicating it.
6. Empty query is treated as a filter-only browse.

Run with:
    cd platform/backend
    python -m tests._check_detection_kb
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


def _bootstrap() -> None:
    """Force a fresh settings load with a clean SQLite path."""
    tmp = Path(tempfile.mkdtemp(prefix="aisoc-dkb-"))
    os.environ["AISOC_DB_PATH"] = str(tmp / "aisoc.db")
    os.environ["AISOC_SEED_ON_STARTUP"] = "false"
    # Keep embeddings deterministic — no network calls during smoke tests.
    os.environ["AISOC_EMBEDDING_PROVIDER"] = "hashbag"
    # Memory backend (the default) — but be explicit so a stray
    # `AISOC_DETECTION_KB_BACKEND=elasticsearch` from a dev shell can't
    # poison the smoke run.
    os.environ["AISOC_DETECTION_KB_BACKEND"] = "memory"
    for mod in [m for m in list(sys.modules) if m.startswith("app.")]:
        sys.modules.pop(mod, None)


def main() -> int:  # noqa: C901 - linear smoke test, complexity is fine
    _bootstrap()

    # Defer imports until after env bootstrap so settings sees our values.
    from app.detections.sigma import Severity, SigmaRule  # noqa: E402
    from app.memory import (  # noqa: E402
        detection_by_id,
        detection_count,
        detection_kb_backend_name,
        detection_search,
        get_detection_kb,
        reset_detection_kb,
    )

    print(f"backend={detection_kb_backend_name()}")
    total = detection_count()
    print(f"rules_loaded={total}")
    assert total > 0, "expected the bundled rule pack to load at least one rule"

    # ---- 1. Reload survives -----------------------------------------------
    reset_detection_kb()
    again = detection_count()
    assert again == total, f"reload changed rule count: {total} -> {again}"
    print("ok: reset_detection_kb() reloads to the same count")

    # ---- 2. Free-text semantic+keyword search -----------------------------
    # Pick a query that's almost certainly present in the bundled pack.
    # We don't assert a specific rule_id (the pack evolves), only that
    # *something* relevant came back and the score is non-trivial.
    queries = [
        "azure ad multi factor authentication method removed",
        "suspicious powershell child process",
        "okta failed login brute force",
        "lateral movement smb",
    ]
    matched_at_least_one = 0
    for q in queries:
        hits = detection_search(q, k=5)
        if not hits:
            continue
        top = hits[0]
        # Hybrid score must be non-zero for at least one query.
        if top.score > 0.0 and top.matched_terms:
            matched_at_least_one += 1
        # Ordering invariant: monotonic decreasing.
        scores = [h.score for h in hits]
        assert scores == sorted(scores, reverse=True), f"results out of order for {q!r}"
    assert matched_at_least_one >= 1, (
        "at least one of the seeded queries should have produced a "
        "scoring hit against the bundled detection content"
    )
    print(f"ok: free-text search produced scoring hits for {matched_at_least_one}/{len(queries)} queries")

    # ---- 3. Severity / tag filters narrow the result set ------------------
    all_hits = detection_search("login", k=50)
    high_only = detection_search("login", k=50, severity="high")
    for h in high_only:
        assert h.severity is Severity.HIGH, f"severity filter leaked {h.severity}"
    assert len(high_only) <= len(all_hits)
    print(
        f"ok: severity=high filter shrinks {len(all_hits)} -> {len(high_only)} "
        f"and every result is HIGH"
    )

    # Pick a tag that occurs somewhere in the bundled pack and verify the
    # filter is enforced. We probe a handful of common ATT&CK techniques.
    sample_rule = next(iter(get_detection_kb().all_rules()), None)
    assert sample_rule is not None
    if sample_rule.tags:
        probe_tag = sample_rule.tags[0]
        tagged = detection_search("", k=20, tag=probe_tag)
        for h in tagged:
            assert any(probe_tag.lower() in t.lower() for t in h.tags), (
                f"tag filter leaked: {probe_tag} not in {h.tags}"
            )
        print(f"ok: tag={probe_tag!r} filter returned {len(tagged)} rules, all match")

    # ---- 4. Logsource filter (browse path) --------------------------------
    # Find any rule with a category and check we can filter to it.
    cat_rule = next(
        (r for r in get_detection_kb().all_rules() if (r.logsource or {}).get("category")),
        None,
    )
    if cat_rule:
        category = cat_rule.logsource["category"]
        cat_hits = get_detection_kb().search_by_logsource(category=category)
        assert len(cat_hits) >= 1
        for h in cat_hits:
            assert h.logsource.get("category", "").lower() == str(category).lower()
        print(f"ok: logsource category={category!r} → {len(cat_hits)} rules")

    # ---- 5. by_id round-trip + add_rule override --------------------------
    probe_rule = next(iter(get_detection_kb().all_rules()))
    fetched = detection_by_id(probe_rule.id)
    assert fetched is not None and fetched.id == probe_rule.id
    print(f"ok: by_id({probe_rule.id!r}) round-trips")

    override_yaml = f"""
title: '{probe_rule.title} (smoke override)'
id: {probe_rule.id}
status: experimental
description: Smoke-test override of an existing rule
level: critical
logsource:
  category: process_creation
detection:
  selection:
    EventID: 4688
  condition: selection
"""
    overridden = SigmaRule.from_yaml(override_yaml, source="<smoke>")
    before = detection_count()
    get_detection_kb().add_rule(overridden)
    after = detection_count()
    assert after == before, (
        f"add_rule() with existing id should not grow the index: {before} -> {after}"
    )
    refetched = detection_by_id(probe_rule.id)
    assert refetched is not None
    assert refetched.severity is Severity.CRITICAL, (
        f"override did not replace: got severity {refetched.severity}"
    )
    print(f"ok: add_rule() override replaced by id (count stays {after}, severity now CRITICAL)")

    # ---- 6. Empty query is a filter-only browse ---------------------------
    browse = detection_search("", k=3, severity="critical")
    for h in browse:
        assert h.severity is Severity.CRITICAL
        assert h.score == 0.0  # browse path emits zero scores
    print(f"ok: empty query browse returned {len(browse)} CRITICAL rules with zero scores")

    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
