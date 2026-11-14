"""Tests for the fabricated-data gate, `scripts/check_mock_data_gated.py`.

The gate's first two checks only recognise mock data that announces itself:
they need a `MOCK_` / `DEMO_` name *and* an assignment through a state setter
or SWR `fallbackData`. `MSSPDashboardView.tsx` had neither — `const TENANTS =
[...]` passed straight to `useState`, with no API call anywhere in the file —
so six invented companies with invented ARR shipped under a green gate.

Two properties matter for the replacement check and both are asserted here:
it catches that shape, and it stays quiet on the UI configuration that makes
up the large majority of module-scope object arrays in this console. A gate
that flags every filter list gets deleted, which is worse than the gap.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "scripts"))

import check_mock_data_gated as gate  # noqa: E402


def _tree(tmp_path: Path, relative: str, source: str) -> Path:
    """A fake `apps/web/src` so `find_inline_records` reports real-looking paths."""
    root = tmp_path / "apps" / "web" / "src"
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return root


# The verbatim shape that shipped.
FABRICATED_TENANTS = """\
'use client';
import { useState } from 'react';

const TENANTS: Tenant[] = [
  { name: 'Acme Financial',    activeAlerts: 12, openCases: 3,  mttr: 28, arr: 185000 },
  { name: 'GlobalRetail Corp', activeAlerts: 47, openCases: 11, mttr: 65, arr: 320000 },
  { name: 'MedSecure Health',  activeAlerts: 8,  openCases: 2,  mttr: 19, arr: 140000 },
];

export default function View() {
  const [tenants] = useState(TENANTS);
  return <div>{tenants.length}</div>;
}
"""


def test_it_catches_a_fabricated_table_that_never_calls_an_api(tmp_path):
    root = _tree(tmp_path, "components/mssp/View.tsx", FABRICATED_TENANTS)
    problems = gate.scan(root)
    assert len(problems) == 1
    assert "TENANTS" in problems[0]


def test_the_older_name_based_checks_alone_would_have_missed_it(tmp_path):
    """Why the third check had to be name-agnostic.

    Nothing here is called `MOCK_*`, nothing is assigned through a setter, and
    nothing reaches `fallbackData` — so every pattern the gate shipped with
    finds zero.
    """
    root = _tree(tmp_path, "components/mssp/View.tsx", FABRICATED_TENANTS)
    text = (root / "components/mssp/View.tsx").read_text(encoding="utf-8")
    for line in text.split("\n"):
        assert not gate.FALLBACK_WITH_MOCK.search(line)
        assert not gate.MOCK_ASSIGN.search(line)
        assert not gate.MOCK_FACTORY_ASSIGN.search(line)


def test_the_same_records_pass_once_demo_gated(tmp_path):
    gated = FABRICATED_TENANTS.replace(
        "const [tenants] = useState(TENANTS);",
        "const [tenants] = useState(canUseDemoData() ? TENANTS : []);",
    )
    root = _tree(tmp_path, "components/mssp/View.tsx", gated)
    assert gate.scan(root) == []


#: A file that gates its SWR fallback correctly and then bypasses the gate one
#: line later. `ThreatIntelView.tsx` shipped this shape: with demo mode off and
#: the indicators API returning 404, `data` is undefined and the `??` renders
#: five invented IOCs under a "3 Added Today" counter, on a deployment that had
#: never ingested one. The gate reported everything gated.
GATED_THEN_BYPASSED = """\
const MOCK_INDICATORS: ThreatIndicator[] = [
  { id: 'ioc-001', type: 'ip', value: '185.220.101.45', confidence: 95 },
];

export function ThreatIntelView() {
  const { data } = useSWR(
    'threat-intel-indicators',
    () => threatIntelApi.list(),
    { fallbackData: demoFallback({ indicators: MOCK_INDICATORS }) },
  );
  const allIndicators = data?.indicators ?? MOCK_INDICATORS;
  return <IndicatorTable rows={allIndicators} />;
}
"""


def test_a_gated_fallback_bypassed_at_render_is_caught(tmp_path):
    root = _tree(tmp_path, "components/threat-intel/View.tsx", GATED_THEN_BYPASSED)
    problems = gate.scan(root)
    assert len(problems) == 1
    assert "MOCK_INDICATORS" in (root / "components/threat-intel/View.tsx").read_text()
    assert "`??`/`||` fallback" in problems[0]


def test_the_three_older_patterns_alone_would_have_missed_the_bypass(tmp_path):
    """Why the render-fallback check had to exist separately.

    The `fallbackData:` line is correctly wrapped in `demoFallback(`, so the
    first check passes it — as it should. Nothing is assigned through a setter.
    The bypass is on a line none of the three shipped patterns describe.
    """
    root = _tree(tmp_path, "components/threat-intel/View.tsx", GATED_THEN_BYPASSED)
    text = (root / "components/threat-intel/View.tsx").read_text(encoding="utf-8")
    for line in text.split("\n"):
        assert not (gate.FALLBACK_WITH_MOCK.search(line) and "demoFallback(" not in line)
        assert not gate.MOCK_ASSIGN.search(line)
        assert not gate.MOCK_FACTORY_ASSIGN.search(line)


def test_an_empty_fallback_passes(tmp_path):
    fixed = GATED_THEN_BYPASSED.replace("data?.indicators ?? MOCK_INDICATORS", "data?.indicators ?? []")
    root = _tree(tmp_path, "components/threat-intel/View.tsx", fixed)
    assert gate.scan(root) == []


def test_a_demo_guarded_file_may_still_use_a_render_fallback(tmp_path):
    guarded = GATED_THEN_BYPASSED.replace(
        "data?.indicators ?? MOCK_INDICATORS",
        "data?.indicators ?? (canUseDemoData() ? MOCK_INDICATORS : [])",
    )
    root = _tree(tmp_path, "components/threat-intel/View.tsx", guarded)
    assert gate.scan(root) == []


def test_documented_ui_configuration_is_exempt(tmp_path, monkeypatch):
    """The exemption is keyed on file *and* constant, not the file alone."""
    monkeypatch.setattr(
        gate,
        "RENDER_FALLBACK_EXEMPT",
        {("identity/Perms.tsx", "DEMO_PROVIDERS"): "provider capability list, not tenant data"},
    )
    exempt = "const providers = info?.providers ?? DEMO_PROVIDERS;\n"
    assert gate.scan(_tree(tmp_path, "identity/Perms.tsx", exempt)) == []

    # A different constant in the same exempted file is still reported.
    other = "const rows = data?.rows ?? MOCK_FINDINGS;\n"
    assert len(gate.scan(_tree(tmp_path, "identity/Perms.tsx", other))) == 1


def test_named_people_with_scores_are_caught(tmp_path):
    """The second live instance: an analyst leaderboard with no backend."""
    root = _tree(
        tmp_path,
        "components/analytics/Team.tsx",
        """\
const ANALYSTS: Analyst[] = [
  { name: 'Sarah Chen',    casesClosed: 47, accuracy: 96.2, score: 945 },
  { name: 'Marcus Rivera', casesClosed: 42, accuracy: 94.8, score: 892 },
  { name: 'Aisha Patel',   casesClosed: 39, accuracy: 97.1, score: 878 },
];
""",
    )
    assert len(gate.scan(root)) == 1


def test_estate_identifiers_count_as_identities(tmp_path):
    """A hostname or an address is as recognisable as a company name."""
    root = _tree(
        tmp_path,
        "components/alerts/Hosts.tsx",
        """\
const ROWS = [
  { host: 'WIN-DC01', alerts: 4, risk: 88 },
  { host: 'WIN-SQL02', alerts: 2, risk: 61 },
  { host: 'WIN-APP07', alerts: 9, risk: 94 },
];
""",
    )
    assert len(gate.scan(root)) == 1


# ── Must stay quiet on UI configuration ─────────────────────────────────────


@pytest.mark.parametrize(
    "name,source",
    [
        (
            "filter buttons",
            "const SEVERITY_FILTERS = [\n"
            "  { value: 'critical', label: 'Critical' },\n"
            "  { value: 'high', label: 'High' },\n"
            "  { value: 'low', label: 'Low' },\n"
            "];\n",
        ),
        (
            "a graph stylesheet",
            "const STYLE = [\n"
            "  { selector: 'node', width: 40, height: 40, shape: 'ellipse' },\n"
            "  { selector: 'edge', width: 2, height: 2, shape: 'line' },\n"
            "  { selector: 'core', width: 1, height: 1, shape: 'none' },\n"
            "];\n",
        ),
        (
            "decorative svg coordinates",
            "const nodes = [\n  { x: 10, y: 20, delay: 0 },\n  { x: 30, y: 45, delay: 1 },\n  { x: 55, y: 70, delay: 2 },\n];\n",
        ),
        (
            "pricing copy",
            "const TIERS = [\n"
            "  { name: 'Starter', price: 0, seats: 3 },\n"
            "  { name: 'Growth', price: 499, seats: 25 },\n"
            "  { name: 'Enterprise', price: 1999, seats: 100 },\n"
            "];\n",
        ),
    ],
)
def test_ui_configuration_is_not_flagged(tmp_path, name, source):
    root = _tree(tmp_path, "components/misc/Config.tsx", source)
    assert gate.scan(root) == [], f"{name} is configuration, not a tenant's state"


def test_an_array_inside_a_component_body_is_out_of_scope(tmp_path):
    """Indented declarations are local view state, not a baked-in dataset."""
    root = _tree(
        tmp_path,
        "components/misc/Local.tsx",
        """\
export function View({ rows }) {
  const derived = [
    { name: 'Acme Financial', alerts: 3, cases: 1 },
    { name: 'Globex Systems', alerts: 5, cases: 2 },
    { name: 'Initech Holdings', alerts: 1, cases: 0 },
  ];
  return <div>{derived.length}{rows}</div>;
}
""",
    )
    assert gate.scan(root) == []


# ── The allow-list is checked in both directions ────────────────────────────


def test_a_stale_allowlist_entry_fails(tmp_path, monkeypatch):
    """An exemption that outlives its code is cover for whatever is written
    next under that name, so it has to be removed rather than left."""
    root = _tree(tmp_path, "components/misc/Config.tsx", "const OPTIONS = [{ a: 1 }];\n")
    monkeypatch.setattr(gate, "ALLOWED_ILLUSTRATIVE", {("components/gone/Removed.tsx", "GHOSTS"): "no longer exists"})
    stale = gate.stale_allowlist_entries(root)
    assert stale == ["components/gone/Removed.tsx :: GHOSTS"]


def test_a_live_allowlist_entry_is_not_stale(tmp_path, monkeypatch):
    root = _tree(
        tmp_path,
        "components/landing/Strip.tsx",
        """\
const TACTICS = [
  { name: 'Initial Access', covered: 9, total: 11 },
  { name: 'Defense Evasion', covered: 27, total: 42 },
  { name: 'Lateral Movement', covered: 8, total: 9 },
];
""",
    )
    monkeypatch.setattr(gate, "ALLOWED_ILLUSTRATIVE", {("components/landing/Strip.tsx", "TACTICS"): "illustrative"})
    assert gate.stale_allowlist_entries(root) == []
    assert gate.scan(root) == []


def test_the_shipped_allowlist_entries_all_still_match():
    """Run against the real tree, not a fixture."""
    assert gate.stale_allowlist_entries(_REPO / "apps" / "web" / "src") == []


def test_the_render_fallback_exemptions_all_still_match():
    """The other allow-list, in the direction it had no check for.

    `ALLOWED_ILLUSTRATIVE` was verified both ways from the start and
    `RENDER_FALLBACK_EXEMPT` was not, so an entry here could outlive the code
    it excused and go on excusing whatever was written next under that name.
    """
    assert gate.stale_render_exempt_entries(_REPO / "apps" / "web" / "src") == []


# ── The blind spots the relaxed detector closes ─────────────────────────────
#
# One test per shape, each naming what it would have missed. The fixtures are
# reduced from the live sites, so a regression fails here with the same
# sentence a reviewer would need anyway.


def _rules(tmp_path: Path, relative: str, source: str) -> list[str]:
    """The *rule names* a fixture produces, not just how many findings.

    Several of these rules overlap by construction — a parenthesised
    `?? (flag ? DEMO_X : [])` satisfies both conditional rules — so asserting
    a count would let a case pass with the fix it names reverted.
    """
    root = _tree(tmp_path, relative, source)
    return [finding.rule for finding in gate.inspect(root).findings]


def test_a_dataset_of_pure_strings_is_fabricated_without_any_number(tmp_path):
    """(a) The dominant blind spot.

    Fifteen invented ATT&CK coverage verdicts with no number anywhere in the
    literal; the view derives and prints "Coverage 50%" from them, so the
    headline figure never exists as something the gate could have matched.
    Requiring two numeric keys asked for the symptom rather than the claim.
    """
    source = (
        "const TECHNIQUES = [\n"
        "  { id: 'T1071', name: 'Application Layer Protocol', status: 'partial', priority: 'medium' },\n"
        "  { id: 'T1078', name: 'Valid Accounts', status: 'gap', priority: 'high' },\n"
        "];\nexport function V() { return <b>{TECHNIQUES.length}</b>; }\n"
    )
    assert _rules(tmp_path, "components/coverage/View.tsx", source) == ["inline-records"]
    assert not gate._asserts_state("{ name: 'Valid Accounts', href: '/x' }"), "a label with a link asserts nothing"


def test_a_ternary_is_the_same_bypass_as_a_nullish_coalesce(tmp_path):
    """(b) `cond ? real : MOCK_X` — identical meaning, and it matched nothing."""
    source = "const metrics = isValidMetrics ? rawMetrics : MOCK_SLA_METRICS;\n"
    assert _rules(tmp_path, "components/sla/View.tsx", source) == ["ternary-fallback"]


def test_a_demo_factory_reached_by_return_is_caught(tmp_path):
    """(c) The factory rule was widened for `setTimeline(makeDemoTimeline())`
    and the `return` form was never covered, so a whole fabricated case was
    substituted for any id the API failed on."""
    source = "function pick() {\n  if (useFallback) return buildDemoCase(caseId);\n  return undefined;\n}\n"
    assert _rules(tmp_path, "components/cases/View.tsx", source) == ["returned-sample"]


def test_an_inline_object_assigned_in_a_catch_is_caught(tmp_path):
    """(d) The docstring always promised this and the pattern never delivered
    it: `MOCK_ASSIGN` needs a bare named identifier, so an invented
    investigation written directly into the setter escaped."""
    source = (
        "async function run() {\n  try {\n    await go();\n  } catch (e) {\n"
        "    setInvestigationData({\n      host: 'WIN-FIN-DB01',\n      domain: 'c2.evil-corp.io',\n"
        "      confidence: 0.88,\n    });\n  }\n}\n"
    )
    assert _rules(tmp_path, "components/cases/View.tsx", source) == ["catch-inline-object"]


def test_an_ordinary_state_object_in_a_catch_is_not_a_finding(tmp_path):
    """The other direction for (d): the rule is about fabricated records, not
    about every object literal that reaches a setter from an error path."""
    source = "async function run() {\n  try {\n    await go();\n  } catch (e) {\n    setPage({ size: 20, index: 0 });\n  }\n}\n"
    assert _rules(tmp_path, "components/misc/View.tsx", source) == []


def test_an_object_literal_is_scanned_like_an_array(tmp_path):
    """(e) `MODULE_ARRAY` only matched `= [`, so a fabricated alert, an audit
    page and a chat context written `= {` were all invisible."""
    source = "const CONTEXT = { caseId: 'CS-2187', alertCount: 7 };\nexport function V() { return <b>{CONTEXT.caseId}</b>; }\n"
    assert _rules(tmp_path, "components/copilot/View.tsx", source) == ["inline-records"]


def test_a_mock_seeding_usestate_is_caught(tmp_path):
    """(f) `useState(MOCK_X)` renders on first paint with no fetch behind it."""
    source = "const [items] = useState(MOCK_HANDOFF_ITEMS);\n"
    assert _rules(tmp_path, "components/shifts/View.tsx", source) == ["state-seed"]


def test_a_single_record_is_enough(tmp_path):
    """(g) `blob.count("{") < 3` short-circuited a one-row array, which is the
    shape of a dataset asserting a corpus size."""
    source = "const ROWS = [{ host: 'WIN-DC01', user: 'svc_admin' }];\nexport function V() { return <b>{ROWS.length}</b>; }\n"
    assert _rules(tmp_path, "components/alerts/View.tsx", source) == ["inline-records"]


def test_a_parenthesised_nullish_fallback_is_caught(tmp_path):
    """(h) `\\s*` cannot cross a `(`, so one character defeated the rule."""
    source = "const saved = savedState.data ?? (demoMode ? DEMO_SAVED : []);\n"
    assert _rules(tmp_path, "components/hunt/View.tsx", source) == ["render-fallback"]


def test_gating_is_decided_per_constant_not_per_file(tmp_path):
    """(i) One `demoFallback` anywhere marked *every* module-scope array in
    the file as gated, so a correctly-gated constant beside an ungated one
    read clean."""
    source = (
        "const MOCK_GOOD = [{ host: 'WIN-DC01', risk: 1, score: 2 }];\n"
        "const MOCK_BAD = [{ host: 'WIN-SQL02', risk: 3, score: 4 }];\n"
        "export function V() {\n"
        "  const { data } = useSWR(k, f, { fallbackData: demoFallback(MOCK_GOOD) });\n"
        "  return <b>{data?.length}{MOCK_BAD.length}</b>;\n}\n"
    )
    root = _tree(tmp_path, "components/misc/View.tsx", source)
    records = {record.name: record.gated for record in gate.find_inline_records(root)}
    assert records == {"MOCK_GOOD": True, "MOCK_BAD": False}


def test_a_fabricated_dataset_in_a_ts_module_is_visible(tmp_path):
    """(j) The record glob was `*.tsx` only, so moving a dataset into the
    `lib/` module beside the component hid it — which is exactly where a
    dataset ends up the first time two components need it."""
    source = "export const ROWS = [{ host: 'WIN-DC01', risk: 91, score: 12 }];\nexport const used = ROWS.length;\n"
    assert _rules(tmp_path, "lib/rows.ts", source) == ["inline-records"]


def test_an_exempt_placeholder_does_not_excuse_the_rest_of_its_line(tmp_path):
    """(j) `_is_exempt_name` was a substring test against the whole line, so
    any line mentioning an exempt name was skipped — including one that also
    carried a real violation."""
    source = "const q = saved ?? SAMPLE_KQL; const rows = data ?? MOCK_ALERTS;\n"
    assert _rules(tmp_path, "components/hunt/View.tsx", source) == ["render-fallback"]


def test_an_exempt_placeholder_alone_is_still_exempt(tmp_path):
    source = "const q = saved ?? SAMPLE_KQL;\n"
    assert _rules(tmp_path, "components/hunt/View.tsx", source) == []


# ── Quiet on the idioms the project documents ───────────────────────────────


def test_a_demo_predicate_bound_to_a_name_still_gates(tmp_path):
    """`const useFallback = !!error && canUseDemoData()` is how two live views
    gate correctly. A gate reading only the literal call reports them."""
    source = "const useFallback = !!error && canUseDemoData();\nconst rules = data?.rules ?? (useFallback ? DEMO_RULES : []);\n"
    assert _rules(tmp_path, "components/detections/View.tsx", source) == []


def test_a_component_that_withholds_itself_is_gated_throughout(tmp_path):
    """`if (!canUseDemoData()) return <Empty />` covers the whole component,
    including the `useState` seeded six lines above it."""
    source = (
        "const MOCK_ASSETS = [{ ip: '203.0.113.42', status: 'critical' }];\n"
        "export function V() {\n  const [rows] = useState(MOCK_ASSETS);\n"
        "  if (!canUseDemoData()) {\n    return <Empty />;\n  }\n  return <b>{rows.length}</b>;\n}\n"
    )
    assert _rules(tmp_path, "components/easm/View.tsx", source) == []


def test_a_guard_that_does_not_leave_gates_nothing(tmp_path):
    """The other direction: a `!canUseDemoData()` that logs and continues
    withholds nothing, so it must not credit the file."""
    source = (
        "const MOCK_ASSETS = [{ ip: '203.0.113.42', status: 'critical' }];\n"
        "export function V() {\n  if (!canUseDemoData()) {\n    console.warn('no demo');\n  }\n"
        "  return <b>{MOCK_ASSETS.length}</b>;\n}\n"
    )
    assert _rules(tmp_path, "components/easm/View.tsx", source) == ["inline-records"]


def test_a_comment_about_a_mock_is_not_a_use_of_it(tmp_path):
    """Three live components carry a comment explaining why the mock is *not*
    reached at render. Counting that sentence as a use site made the gate
    report the files whose authors had already written down the fix."""
    source = (
        "const MOCK_INDICATORS = [{ ip: '185.220.101.45', confidence: 95, score: 3 }];\n"
        "export function V() {\n  const { data } = useSWR(k, f, { fallbackData: demoFallback(MOCK_INDICATORS) });\n"
        "  // Not `?? MOCK_INDICATORS`: the fallbackData above already withholds it.\n"
        "  return <b>{data?.length ?? 0}</b>;\n}\n"
    )
    assert _rules(tmp_path, "components/threat-intel/View.tsx", source) == []


def test_a_mailbox_beside_a_link_is_contact_information(tmp_path):
    """The one place relaxing the identity test over-reached: the marketing
    pages publish the project's own disclosure and sales addresses."""
    source = (
        "const FACTS = [{ label: 'Security disclosures', value: 'security@example.com', href: 'https://example.com' }];\n"
        "export function V() { return <b>{FACTS.length}</b>; }\n"
    )
    assert _rules(tmp_path, "app/(marketing)/about/page.tsx", source) == []


def test_a_mailbox_with_no_link_is_still_estate_data(tmp_path):
    """And the direction that keeps it honest: an audit row naming a user."""
    source = (
        "const DEMO_AUDIT = [{ user: 'sasha.lin@example.com', action: 'login' }];\n"
        "export function V() { return <b>{DEMO_AUDIT.length}</b>; }\n"
    )
    assert _rules(tmp_path, "components/settings/View.tsx", source) == ["inline-records"]


# ── The corpus floor ────────────────────────────────────────────────────────


def test_an_empty_corpus_is_refused_rather_than_certified(tmp_path):
    """Found nothing and scanned nothing print the same word.

    A renamed console directory or a changed suffix produces zero findings
    over zero files, and the gate must not call that clean.
    """
    root = tmp_path / "apps" / "web" / "src"
    root.mkdir(parents=True)
    report = gate.inspect(root)
    assert report.files == 0
    assert report.problems == []
    assert gate.main(["--root", str(root)]) == 2


def test_an_absent_corpus_is_refused(tmp_path):
    assert gate.main(["--root", str(tmp_path / "nope")]) == 2


# ── The known-ungated ledger, in both directions ────────────────────────────


def _finding() -> gate.Finding:
    """A fresh object per call. A self-test elsewhere in this tree shared one
    mutable baseline across cases and every later case inherited the first
    case's state."""
    return gate.Finding("returned-sample", "apps/web/src/components/cases/CaseWorkspace.tsx", 329, "detail")


def test_a_recorded_site_that_is_still_present_is_not_stale(monkeypatch):
    monkeypatch.setattr(gate, "KNOWN_UNGATED", {("components/cases/CaseWorkspace.tsx", "returned-sample"): (1, "why")})
    assert gate.stale_known_ungated_entries([_finding()]) == []


def test_a_recorded_site_that_has_been_fixed_must_be_deleted(monkeypatch):
    monkeypatch.setattr(gate, "KNOWN_UNGATED", {("components/cases/CaseWorkspace.tsx", "returned-sample"): (1, "why")})
    stale = gate.stale_known_ungated_entries([])
    assert len(stale) == 1 and "has been fixed" in stale[0]


def test_a_second_violation_cannot_hide_behind_a_recorded_one(monkeypatch):
    monkeypatch.setattr(gate, "KNOWN_UNGATED", {("components/cases/CaseWorkspace.tsx", "returned-sample"): (1, "why")})
    stale = gate.stale_known_ungated_entries([_finding(), _finding()])
    assert len(stale) == 1 and "has grown" in stale[0]


def test_the_recorded_ledger_matches_the_tree_exactly():
    """Run against the real tree. Every recorded site must still be reported
    by the detector, and no recorded site may have grown."""
    findings = gate.inspect(_REPO / "apps" / "web" / "src").findings
    assert gate.stale_known_ungated_entries(findings) == []


def test_every_recorded_entry_carries_a_reason():
    for key, (count, reason) in gate.KNOWN_UNGATED.items():
        assert count > 0, key
        assert reason.strip(), key
