"""The deferral gate detects each orphan shape it claims to, and only those.

Proven against the two shapes that were live on `main` when the gate was
written — a follow-up in an ADR naming `Phase 6b`, and a module docstring
saying a migration is "tracked as 8b", neither with a section in the tracker
and both still pointing at a file that was never committed — plus the near
misses that would make the gate a nuisance: the other plan's uppercase
`Phase 4B`, a model tag ending in `8b`, a hex digest, and prose that names
the dead tracker only to say it is gone.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE = REPO_ROOT / "scripts" / "check_deferral_tracker.py"

sys.path.insert(0, str(REPO_ROOT / "scripts"))

from gate_toolkit import refuses_an_empty_tree  # noqa: E402

TRACKER = "docs/audit/DEFERRED_SUBPHASES.md"
DEAD = "docs/audit/PROGRESS.md"

TRACKER_BODY = """# The lettered deferrals

## 5b — backfill and replay-from-offset

**Status: open.**

## 7b+ — posture collection

**Status: partially closed.**
"""

#: One line naming both sections in deferral language, the way `ROADMAP.md`
#: does — `7b+` only ever appears next to "scoped in", never "tracked as",
#: which is why the reference direction is the generous one.
ROADMAP = "- [x] Phase 5 — Data spine (backfill/replay tracked as 5b)\n- [x] Phase 7 — 7b+ (posture) scoped in the tracker\n"

#: The excluded surface has to exist or the exclusion reads as stale, which
#: is a finding in its own right and would mask the one under test.
HISTORICAL = {"CHANGELOG.md": "append-only release history"}


def _load():
    spec = importlib.util.spec_from_file_location("check_deferral_tracker", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _tree(tmp_path: Path, files: dict[str, str] | None = None, *, tracker: str | None = None) -> Path:
    """A staged git tree holding a tracker, a roadmap and whatever else is asked for.

    Staged, because the gate takes its corpus from `git ls-files` and an
    unstaged file is invisible to it — the same trap that makes a gate run
    before `git add` skip the files it is meant to judge.
    """
    root = tmp_path / "tree"
    root.mkdir(exist_ok=True)
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    payload = {
        TRACKER: TRACKER_BODY if tracker is None else tracker,
        "ROADMAP.md": ROADMAP,
        "CHANGELOG.md": "## [Unreleased]\n",
        **(files or {}),
    }
    for rel, body in payload.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    return root


def _run(root: Path, module, *, landed: dict[str, str] | None = None) -> int:
    return module.main(["--repo-root", str(root)], landed=landed or {}, historical=HISTORICAL)


# ─── The extraction halves, read directly ────────────────────────────────────


def test_the_section_parser_reads_the_real_tracker() -> None:
    """The eight identifiers this repository actually carries, from the file."""
    module = _load()
    declared = module.sections((REPO_ROOT / TRACKER).read_text(encoding="utf-8"))
    assert set(declared) == {"3.5+", "5b", "6b", "7b+", "8b", "9b", "10b", "11b"}


def test_every_way_the_tree_writes_a_deferral_is_recognised() -> None:
    module = _load()
    assert module.named_as_deferral("backfill/replay-from-offset tracked as 5b)") == {"5b"}
    assert module.named_as_deferral("demo-timing gate tracked as non-blocking 3.5+)") == {"3.5+"}
    assert module.named_as_deferral("- **Follow-up (Phase 6b, tracked in x).**") == {"6b"}
    assert module.named_as_deferral("prompts is tracked as 8b; this seeds the registry") == {"8b"}
    # A sentence-ending full stop is the most ordinary way of writing it, and
    # an earlier lookahead excluded every following `.` — which lost both
    # real orphans at once.
    assert module.named_as_deferral("Deferred to Phase 12c.") == {"12c"}


def test_the_other_plans_uppercase_phases_are_a_different_vocabulary() -> None:
    """`Phase 1A` / `Phase 4B` belong to the 90-day plan and all landed."""
    module = _load()
    assert module.named_as_deferral("ORM models for the Phase 4B mobile responder PWA.") == set()
    assert module.named_as_deferral("Persistent agent decision ledger (Phase 1A).") == set()


def test_a_model_tag_a_digest_and_a_version_are_not_identifiers() -> None:
    module = _load()
    assert module.mentioned("phase notes: llama3.1:8b") == set()
    assert module.mentioned("tracked at commit c8b9d670") == set()
    assert module.mentioned("phase shipped in v8.1.0") == set()


def test_a_reference_only_counts_on_a_line_that_is_talking_about_phases() -> None:
    """The generous direction is still not "any occurrence anywhere"."""
    module = _load()
    assert module.mentioned("- [x] Phase 7 — 7b+ (posture) scoped in the tracker") == {"7b+"}
    assert module.mentioned("if head -c 2 /tmp/a.enc | od -An -tx1 | grep -q '1f 8b'; then") == set()


def test_prose_placing_the_dead_tracker_in_the_past_is_not_a_pointer() -> None:
    module = _load()
    assert module.dead_tracker_pointers([f"Scope lives in `{DEAD}`."]) == [1]
    assert module.dead_tracker_pointers([f"`{DEAD}` is in `.gitignore` and was never committed."]) == []
    # The tracker's own preamble puts the qualifier in the next paragraph.
    assert module.dead_tracker_pointers([f"See `{DEAD}`.", "", "That file was never committed."]) == []


# ─── untracked-deferral ──────────────────────────────────────────────────────


def test_the_adr_shape_that_was_live_on_main_fails(tmp_path, capsys) -> None:
    """`docs/decisions/0005-storage-consolidation.md`, verbatim in shape."""
    module = _load()
    adr = f"- **Follow-up (Phase 6b, tracked in `{DEAD}`).** Wire the model in.\n"
    root = _tree(tmp_path, {"docs/decisions/0005.md": adr})
    assert _run(root, module) == 1
    out = capsys.readouterr().out
    assert "untracked-deferral: 6b" in out
    assert "dangling-tracker-pointer" in out


def test_the_docstring_shape_that_was_live_on_main_fails(tmp_path, capsys) -> None:
    """A deferral named in source, which is why the corpus is the whole tree."""
    module = _load()
    root = _tree(tmp_path, {"services/a/p.py": '"""Migration of the inline prompts is tracked as 8b."""\n'})
    assert _run(root, module) == 1
    out = capsys.readouterr().out
    assert "untracked-deferral: 8b" in out
    assert "services/a/p.py:1" in out


def test_a_bare_phase_reference_with_no_section_fails(tmp_path, capsys) -> None:
    module = _load()
    root = _tree(tmp_path, {"docs/x.md": "The rest is deferred to Phase 12c.\n"})
    assert _run(root, module) == 1
    assert "untracked-deferral: 12c" in capsys.readouterr().out


def test_a_sub_phase_recorded_as_landed_is_not_an_orphan(tmp_path, capsys) -> None:
    module = _load()
    root = _tree(tmp_path, {"docs/x.md": "Phase 4c closed that row.\n"})
    assert _run(root, module, landed={"4c": "shipped — ROADMAP.md Phase 4"}) == 0
    assert "4c: recorded as landed" in capsys.readouterr().out


# ─── the exemption list, read back ───────────────────────────────────────────


def test_a_landed_record_nothing_in_the_tree_names_fails(tmp_path, capsys) -> None:
    """An exemption nobody needs is where a real one goes to hide."""
    module = _load()
    root = _tree(tmp_path)
    assert _run(root, module, landed={"4c": "shipped"}) == 1
    assert "stale-landed-record" in capsys.readouterr().out


def test_a_landed_record_the_tracker_also_holds_a_section_for_fails(tmp_path, capsys) -> None:
    module = _load()
    root = _tree(tmp_path)
    assert _run(root, module, landed={"5b": "shipped"}) == 1
    assert "stale-landed-record: LANDED_SUBPHASES records 5b" in capsys.readouterr().out


def test_an_excluded_path_matching_no_tracked_file_fails(tmp_path, capsys) -> None:
    module = _load()
    root = tmp_path / "tree"
    root.mkdir()
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    for rel, body in {TRACKER: TRACKER_BODY, "ROADMAP.md": ROADMAP}.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(body, encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    assert _run(root, module) == 1
    assert "stale-exclusion: 'CHANGELOG.md'" in capsys.readouterr().out


def test_every_exclusion_is_printed_even_on_a_clean_run(tmp_path, capsys) -> None:
    """An exclusion nobody reads is indistinguishable from a gate that did not look."""
    module = _load()
    assert _run(_tree(tmp_path), module) == 0
    assert "excluded: CHANGELOG.md" in capsys.readouterr().out


# ─── unreferenced-section ────────────────────────────────────────────────────


def test_a_section_nothing_outside_the_tracker_mentions_fails(tmp_path, capsys) -> None:
    module = _load()
    root = _tree(tmp_path, {"ROADMAP.md": "- [x] Phase 5 — Data spine (tracked as 5b)\n"})
    assert _run(root, module) == 1
    out = capsys.readouterr().out
    assert "unreferenced-section" in out
    assert "7b+" in out


def test_the_tracker_is_not_its_own_evidence(tmp_path, capsys) -> None:
    """A section citing itself is how an entry outlives the work it describes."""
    module = _load()
    root = _tree(tmp_path, {"ROADMAP.md": "nothing here\n"})
    assert _run(root, module) == 1
    out = capsys.readouterr().out
    assert "unreferenced-section" in out and "5b" in out


# ─── historical surfaces ─────────────────────────────────────────────────────


def test_a_historical_surface_naming_a_deferral_is_not_a_finding(tmp_path) -> None:
    """Editing a shipped changelog entry to name a different path is revisionism."""
    module = _load()
    root = _tree(tmp_path, {"CHANGELOG.md": f"- tracked as 9b in `{DEAD}`\n"})
    assert _run(root, module) == 0


# ─── non-vacuity ─────────────────────────────────────────────────────────────


def test_a_tracker_with_no_sections_is_refused_rather_than_called_clean(tmp_path, capsys) -> None:
    module = _load()
    root = _tree(tmp_path, tracker="# The lettered deferrals\n")
    assert _run(root, module) == 2
    assert "REFUSED" in capsys.readouterr().out


def test_a_missing_tracker_is_refused(tmp_path, capsys) -> None:
    module = _load()
    root = tmp_path / "bare"
    root.mkdir()
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    assert _run(root, module) == 2
    assert f"{TRACKER} is missing" in capsys.readouterr().out


def test_the_empty_tree_refusal_holds_for_a_copy_of_the_script() -> None:
    """The toolkit's probe: `scripts/` copied into a tree with no content."""
    refused, detail = refuses_an_empty_tree(GATE.name, [])
    assert refused, detail


# ─── the gate, end to end ────────────────────────────────────────────────────


def test_the_gate_answers_the_self_test_flag() -> None:
    result = subprocess.run([sys.executable, str(GATE), "--self-test"], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_live_repository_passes() -> None:
    """The regression this gate exists for, asserted against the real tree."""
    result = subprocess.run([sys.executable, str(GATE)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_live_run_credits_a_reference_for_every_section() -> None:
    """A credit nobody reads is a verdict nobody can check."""
    result = subprocess.run([sys.executable, str(GATE)], capture_output=True, text=True)
    for identifier in ("3.5+", "5b", "6b", "7b+", "8b", "9b", "10b", "11b"):
        assert f"{identifier}: section at {TRACKER}:" in result.stdout, result.stdout
