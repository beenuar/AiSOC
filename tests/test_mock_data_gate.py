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
