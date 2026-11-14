#!/usr/bin/env python3
"""A chart version is a coordinate, and a coordinate may mean one thing only.

Why this exists
---------------
``infra/helm/aisoc/Chart.yaml`` carries two versions and only one of them was
ever gated. ``appVersion`` becomes an image tag, so
``check_published_images.py`` reads it and fails when it names a tag no image
carries. ``version`` — the chart's own — was read by nothing at all.

v13.0.0 is what that cost. The release bumped ``appVersion`` from ``v12.3.2``
to ``v13.0.0`` and left ``version`` at ``5.9.2``, which v12.3.2 had already
published. ``helm push`` does not refuse an existing version, so
``oci://ghcr.io/beenuar/charts/aisoc:5.9.2`` was republished pointing at a
different application. The registry still shows it: ``5.9.2`` reads
``appVersion: v13.0.0`` today, and the bytes v12.3.2 published are gone. An
operator who pinned ``--version 5.9.2`` got one application in September and
a different one afterwards, from a coordinate the ecosystem treats as
immutable.

The property enforced
---------------------
**A chart version is never reused for different content.** Not "the two
numbers moved together" — that is a proxy, and a proxy passes whenever
someone bumps the wrong one. This asks the registry what it already holds and
asks git what each release declared, and it fails when one version means two
things.

Four checks, three of which need no network:

``appversion-moved-alone``
    ``appVersion`` changed between the baseline and this tree while
    ``version`` did not. Always wrong: ``appVersion`` is the application the
    chart installs, so a consumer running ``helm upgrade`` against an
    unchanged chart version gets a different application and has no way to
    have known. This is the v13.0.0 defect, and it fires on that tree.

``content-moved-alone``
    Any tracked file under the chart directory changed while ``version`` did
    not. ``Chart.yaml``'s own ``version:`` field is masked out of that
    comparison, so bumping the version cannot be the change that justifies
    itself.

``version-went-backward``
    ``version`` moved, but not forward. A lower version is a coordinate an
    earlier release may already hold.

``reused-across-releases``
    One chart version declared at two release tags with different chart
    content. This is the only check that can see an overwrite *after* it
    happened, because the registry cannot: republishing replaces the bytes,
    so the registry and the tree that overwrote it agree afterwards. Recorded
    collisions live in ``KNOWN_COLLISIONS`` and are checked in both
    directions — an entry that has stopped being detectable fails the build
    rather than sitting there.

And one that does:

``published-with-different-content``
    This tree's ``version`` already exists in GHCR carrying content this tree
    does not. That is the incident itself, caught before the push rather than
    after. Also fires when the tree's version is *behind* something already
    published, since the next release would then be reaching backwards.

What this deliberately does not check
-------------------------------------
* **Whether the bump is the right size.** Nothing in a diff decides whether a
  renamed ``values.yaml`` key is a patch or a breaking change for somebody's
  values file. The gate enforces that the version moved forward, never that
  it moved forward by the correct amount. A human still chooses major.
* **The bytes that were already overwritten.** ``charts/aisoc:5.9.2`` cannot
  be un-published and the content v12.3.2 shipped is not recoverable from
  anywhere. ``published-with-different-content`` compares the v13.0.0 tree
  against today's ``5.9.2`` and finds them *identical*, because the overwrite
  made them so. That is measured, not assumed, and it is exactly why
  ``reused-across-releases`` reads git instead.
* **Whether a published chart installs.** ``helm lint`` and the kind install
  in ``helm.yml`` answer that. This gate is about identity only.
* **Subchart provenance.** ``charts/*.tgz`` are compared as the bytes this
  repository tracks. That they are the upstream Bitnami charts they claim to
  be is `helm dependency build`'s business, not this gate's.

Comparing a published chart to a tree
-------------------------------------
``helm package`` output is **not** byte-reproducible — gzip timestamps and tar
headers move on every run — so comparing layer digests would report a
difference every time and mean nothing. The comparison is on *unpacked
content*: every tracked chart file against its counterpart inside the
published tarball, with two structural facts handled rather than papered over.

* ``helm package`` re-serialises ``Chart.yaml``, dropping comments and
  reordering keys, so that one file is compared **parsed**. Byte-comparing it
  reports a difference on a chart nobody touched.
* The tracked ``charts/postgresql-13.4.4.tgz`` and ``charts/redis-18.19.4.tgz``
  are expanded by ``helm package`` into ``charts/postgresql/…`` and
  ``charts/redis/…``, so they are expanded here too. Against the published
  ``5.9.2`` that mapping is exact: 60 and 64 files, zero differing bytes.

Usage
-----
    python3 scripts/check_chart_version.py --check
    python3 scripts/check_chart_version.py --check --require-network
    python3 scripts/check_chart_version.py --baseline v12.3.2
    python3 scripts/check_chart_version.py --self-test

Exit codes: 0 clean, 1 finding, 2 the gate could not read what it judges.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

# `scripts/` is on sys.path when this runs as a program, but not when a test
# loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main

try:
    import yaml
except ImportError:  # pragma: no cover - the message matters more than the path
    print(
        "check_chart_version.py: PyYAML is required to read Chart.yaml (pip install pyyaml). Refusing rather than guessing at the file.",
        file=sys.stderr,
    )
    raise SystemExit(2) from None

CHART_REL = "infra/helm/aisoc"
REGISTRY = "ghcr.io"
CHART_REPOSITORY = "beenuar/charts/aisoc"
_TIMEOUT = 30
_MANIFEST_TYPES = (
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)

#: Chart versions this repository has already declared at more than one
#: release tag. Shrink-only, and verified in both directions: an entry the
#: history no longer shows is a finding, because it means either the history
#: was rewritten or this list describes a different tree.
#:
#: Neither can be repaired. They are recorded so the gate reports what is new
#: rather than re-reporting what is known, and so the next reader learns what
#: the gate exists to prevent.
KNOWN_COLLISIONS: dict[str, tuple[tuple[str, ...], str]] = {
    "5.2.0": (
        ("v7.2.0", "v11.0.0"),
        "Declared unchanged across thirteen releases from v7.2.0 to v11.0.0, "
        "with values.yaml differing along the way. Nothing was overwritten: "
        "chart publishing did not exist yet and the registry's oldest tag is "
        "5.6.0, pushed by v12.0.0. The appVersion was 5.2.0 throughout, a tag "
        "no image ever carried, which is the defect check_published_images.py "
        "was written for.",
    ),
    "5.9.2": (
        ("v12.3.2", "v13.0.0"),
        "The incident this gate exists for. v12.3.2 published 5.9.2 with "
        "appVersion v12.3.2; v13.0.0 republished the same version with "
        "appVersion v13.0.0 and GHCR reads v13.0.0 today. The bytes v12.3.2 "
        "published are gone and cannot be restored.",
    ),
}


class ChartError(Exception):
    """The gate cannot read what it is meant to judge. Exit 2, never 0."""


class Offline(Exception):
    """The registry could not be reached. A skip or a hard failure, by flag."""


@dataclass
class Finding:
    code: str
    detail: str


@dataclass
class Report:
    """Everything one run learned, so the printer and the self-test share a shape."""

    version: str = ""
    app_version: str = ""
    baseline: str = ""
    baseline_version: str = ""
    baseline_app_version: str = ""
    changed_files: list[str] = field(default_factory=list)
    collisions: dict[str, tuple[str, ...]] = field(default_factory=dict)
    published: list[str] = field(default_factory=list)
    published_differences: list[str] = field(default_factory=list)
    files_compared: int = 0
    skipped: str = ""


# --------------------------------------------------------------------------
# Reading the chart, from the working tree or from a commit
# --------------------------------------------------------------------------
def _git(root: Path, *args: str) -> bytes | None:
    """stdout, or None when git declined. Never raises on a missing object."""
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", *args],
        cwd=root,
        capture_output=True,
        check=False,
    )
    return out.stdout if out.returncode == 0 else None


def tracked_chart_paths(root: Path, rev: str | None = None) -> list[str]:
    """Chart files git knows about, repository-relative.

    ``rev=None`` reads the index, so a staged-but-uncommitted file counts —
    ``git ls-files`` skips untracked ones, and a gate run before ``git add``
    would silently judge a smaller tree than CI does.
    """
    if rev is None:
        out = _git(root, "ls-files", "--", CHART_REL)
    else:
        out = _git(root, "ls-tree", "-r", "--name-only", rev, "--", CHART_REL)
    if out is None:
        return []
    return sorted(p for p in out.decode("utf-8", "replace").split("\n") if p.strip())


def _blob(root: Path, path: str, rev: str | None) -> bytes:
    if rev is None:
        return (root / path).read_bytes()
    out = _git(root, "show", f"{rev}:{path}")
    if out is None:
        raise ChartError(f"{path} is not readable at {rev}")
    return out


def chart_content(root: Path, rev: str | None = None) -> dict[str, bytes]:
    """The chart as ``helm package`` would lay it out, from tracked files.

    Keyed on the path inside the chart, so it compares directly against a
    published tarball. Subchart archives are expanded because helm expands
    them; leaving them packed would compare a ``.tgz`` against 60 files and
    report every one of them missing.
    """
    paths = tracked_chart_paths(root, rev)
    if not paths:
        raise ChartError(f"no tracked files under {CHART_REL}" + (f" at {rev}" if rev else "") + " — there is no chart here to judge")
    content: dict[str, bytes] = {}
    for path in paths:
        rel = path[len(CHART_REL) + 1 :]
        raw = _blob(root, path, rev)
        if rel.startswith("charts/") and rel.endswith(".tgz"):
            content.update(_expand_subchart(rel, raw))
            continue
        content[rel] = raw
    return content


def _expand_subchart(rel: str, raw: bytes) -> dict[str, bytes]:
    """``charts/redis-18.19.4.tgz`` -> the ``charts/redis/…`` files helm unpacks."""
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        return {
            f"charts/{member.name}": archive.extractfile(member).read()  # type: ignore[union-attr]
            for member in archive.getmembers()
            if member.isfile()
        }


def metadata(content: dict[str, bytes]) -> dict:
    """Chart.yaml, parsed. Raises rather than returning a guess."""
    raw = content.get("Chart.yaml")
    if raw is None:
        raise ChartError("the chart has no Chart.yaml")
    parsed = yaml.safe_load(raw)
    if not isinstance(parsed, dict):
        raise ChartError("Chart.yaml did not parse to a mapping")
    return parsed


# --------------------------------------------------------------------------
# Pure comparison — the self-test drives all of this without a network or a git
# --------------------------------------------------------------------------
_SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")


def semver_key(version: str) -> tuple[int, int, int]:
    match = _SEMVER.match((version or "").strip())
    if not match:
        raise ChartError(f"{version!r} is not a semantic version; the chart's version must be X.Y.Z")
    return (int(match[1]), int(match[2]), int(match[3]))


def _mask_chart_version(raw: bytes) -> bytes:
    """Chart.yaml with its own ``version:`` line blanked.

    Without this, bumping the version is itself a content change, so
    ``content-moved-alone`` would be satisfied by the very edit it is meant to
    require justification for.
    """
    return re.sub(rb"(?m)^version:.*$", b"version: <masked>", raw)


def content_differences(expected: dict[str, bytes], actual: dict[str, bytes]) -> list[str]:
    """How ``actual`` differs from ``expected``, as sentences. Pure.

    ``Chart.yaml`` is compared parsed because ``helm package`` re-serialises
    it; every other file is compared byte for byte.
    """
    differences: list[str] = []
    for name in sorted(set(expected) - set(actual)):
        differences.append(f"{name}: present in the tree, absent from the published chart")
    for name in sorted(set(actual) - set(expected)):
        differences.append(f"{name}: present in the published chart, absent from the tree")
    for name in sorted(set(expected) & set(actual)):
        if expected[name] == actual[name]:
            continue
        if name == "Chart.yaml":
            try:
                if yaml.safe_load(expected[name]) == yaml.safe_load(actual[name]):
                    continue
            except yaml.YAMLError:
                pass  # unparseable on either side is a real difference, reported below
        differences.append(f"{name}: differs")
    return differences


def changed_chart_files(baseline: dict[str, bytes], tree: dict[str, bytes]) -> list[str]:
    """Chart files that moved between two trees, ignoring the version field itself."""
    changed: list[str] = []
    for name in sorted(set(baseline) | set(tree)):
        before, after = baseline.get(name), tree.get(name)
        if name == "Chart.yaml" and before is not None and after is not None:
            before, after = _mask_chart_version(before), _mask_chart_version(after)
        if before != after:
            changed.append(name)
    return changed


def baseline_findings(report: Report) -> list[Finding]:
    """The three checks that need only two trees. Pure, so the self-test drives them."""
    findings: list[Finding] = []
    moved = report.version != report.baseline_version

    if report.app_version != report.baseline_app_version and not moved:
        findings.append(
            Finding(
                "appversion-moved-alone",
                f"appVersion moved {report.baseline_app_version!r} -> {report.app_version!r} "
                f"while the chart's own version stayed {report.version!r}. "
                f"{CHART_REPOSITORY.rsplit('/', 1)[-1]}:{report.version} would be republished naming a "
                "different application — the v13.0.0 defect exactly.",
            )
        )
    if report.changed_files and not moved:
        findings.append(
            Finding(
                "content-moved-alone",
                f"{len(report.changed_files)} chart file(s) changed while version stayed {report.version!r}: "
                + ", ".join(report.changed_files[:6])
                + (" …" if len(report.changed_files) > 6 else ""),
            )
        )
    if moved and semver_key(report.version) <= semver_key(report.baseline_version):
        findings.append(
            Finding(
                "version-went-backward",
                f"version moved {report.baseline_version!r} -> {report.version!r}, which is not forward.",
            )
        )
    return findings


def collision_findings(observed: dict[str, tuple[str, ...]]) -> list[Finding]:
    """Reuse across release tags, against the recorded list, in both directions."""
    findings: list[Finding] = []
    for version, tags in sorted(observed.items()):
        if version in KNOWN_COLLISIONS:
            continue
        findings.append(
            Finding(
                "reused-across-releases",
                f"chart version {version} is declared at {', '.join(tags)} with different content. "
                "Whichever release published last overwrote the other.",
            )
        )
    for version, (tags, _reason) in sorted(KNOWN_COLLISIONS.items()):
        if version not in observed:
            findings.append(
                Finding(
                    "recorded-collision-not-found",
                    f"{version} is recorded as declared at {', '.join(tags)}, and this tree's history does not "
                    "show it. Either the history was rewritten or this record describes another repository; "
                    "delete the entry deliberately rather than letting it rot.",
                )
            )
    return findings


# --------------------------------------------------------------------------
# History
# --------------------------------------------------------------------------
def declared_versions(root: Path) -> dict[str, dict[str, bytes]]:
    """``{release tag: chart content}`` for every ``v*`` tag reachable from HEAD.

    Refuses a checkout with no tags rather than concluding that no release
    ever declared a chart version. ``actions/checkout`` fetches depth 1 and no
    tags by default, and a gate that reads a truncated history reports on a
    repository nobody has: every recorded collision would look deleted and
    every new one invisible.
    """
    out = _git(root, "tag", "--list", "v*", "--merged", "HEAD", "--sort=v:refname")
    tags = [t for t in (out or b"").decode("utf-8", "replace").split("\n") if t.strip()]
    if not tags:
        raise ChartError(
            "no v* release tags are reachable from HEAD — this checkout cannot say what any release "
            "declared. Fetch the full history (actions/checkout with fetch-depth: 0)."
        )
    trees: dict[str, dict[str, bytes]] = {}
    for tag in tags:
        try:
            trees[tag] = chart_content(root, tag)
        except (ChartError, tarfile.TarError):
            continue  # a tag from before the chart existed is not a finding
    return trees


def collisions(trees: dict[str, dict[str, bytes]]) -> dict[str, tuple[str, ...]]:
    """Chart versions declared at two or more tags with content that differs."""
    by_version: dict[str, list[tuple[str, dict[str, bytes]]]] = {}
    for tag, content in trees.items():
        try:
            version = str(metadata(content).get("version") or "")
        except ChartError:
            continue
        if version:
            by_version.setdefault(version, []).append((tag, content))

    found: dict[str, tuple[str, ...]] = {}
    for version, entries in by_version.items():
        if len(entries) < 2:
            continue
        first = entries[0][1]
        if any(content_differences(first, other) for _tag, other in entries[1:]):
            found[version] = tuple(tag for tag, _ in entries)
    return found


def resolve_baseline(root: Path, explicit: str | None) -> str:
    """What this tree is being compared against.

    A pull request is compared to where it forked, so a two-commit branch that
    bumps ``appVersion`` in one commit and ``version`` in the other is judged
    whole. A push to an already-merged ``main`` has no such fork point, so the
    parent commit is the only honest answer.
    """
    if explicit:
        resolved = _git(root, "rev-parse", "--verify", f"{explicit}^{{commit}}")
        if resolved is None:
            raise ChartError(f"--baseline {explicit!r} does not resolve to a commit")
        return explicit
    head = (_git(root, "rev-parse", "HEAD") or b"").decode().strip()
    base = _git(root, "merge-base", "HEAD", "origin/main")
    if base and base.decode().strip() not in ("", head):
        return base.decode().strip()
    # Deliberately not a local ``main``: a worktree's copy of it is whatever
    # that worktree last fetched, so the baseline would move with something
    # unrelated to the change under judgement.
    parent = _git(root, "rev-parse", "--verify", "HEAD~1")
    if parent is None:
        raise ChartError("no baseline to compare against: HEAD has no parent and origin/main is unknown")
    return parent.decode().strip()


# --------------------------------------------------------------------------
# Asking the registry
# --------------------------------------------------------------------------
class ChartRegistry:
    """Anonymous reads against GHCR. The chart package is public."""

    def __init__(self, timeout: int = _TIMEOUT) -> None:
        self._timeout = timeout
        self._token: str | None = None

    def _get(self, url: str, headers: dict[str, str]) -> bytes:
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310 - fixed https host
                return response.read()
        except urllib.error.HTTPError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise Offline(f"{REGISTRY} unreachable: {exc}") from exc

    def _auth(self) -> dict[str, str]:
        if self._token is None:
            url = f"https://{REGISTRY}/token?scope=repository:{CHART_REPOSITORY}:pull&service={REGISTRY}"
            payload = json.loads(self._get(url, {"Accept": "application/json"}))
            self._token = str(payload.get("token") or "")
        return {"Authorization": f"Bearer {self._token}", "Accept": ", ".join(_MANIFEST_TYPES)}

    def tags(self) -> list[str]:
        try:
            payload = json.loads(self._get(f"https://{REGISTRY}/v2/{CHART_REPOSITORY}/tags/list?n=500", self._auth()))
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 404):
                return []  # never published at all
            raise Offline(f"tags/list returned {exc.code}") from exc
        return [str(t) for t in (payload.get("tags") or [])]

    def content(self, tag: str) -> dict[str, bytes]:
        """The published chart's files, keyed the way ``chart_content`` keys them."""
        headers = self._auth()
        manifest = json.loads(self._get(f"https://{REGISTRY}/v2/{CHART_REPOSITORY}/manifests/{tag}", headers))
        layers = manifest.get("layers") or []
        if not layers:
            raise Offline(f"the manifest for {tag} carries no layer to compare")
        blob = self._get(f"https://{REGISTRY}/v2/{CHART_REPOSITORY}/blobs/{layers[0]['digest']}", headers)
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
            return {
                member.name.split("/", 1)[1]: archive.extractfile(member).read()  # type: ignore[union-attr]
                for member in archive.getmembers()
                if member.isfile() and "/" in member.name
            }


def registry_findings(report: Report, tree: dict[str, bytes], registry: ChartRegistry) -> list[Finding]:
    findings: list[Finding] = []
    report.published = sorted(registry.tags(), key=lambda t: semver_key(t) if _SEMVER.match(t) else (0, 0, 0))

    if report.version in report.published:
        published = registry.content(report.version)
        differences = content_differences(tree, published)
        report.published_differences = differences
        report.files_compared = len(published)
        if differences:
            findings.append(
                Finding(
                    "published-with-different-content",
                    f"oci://{REGISTRY}/{CHART_REPOSITORY.rsplit('/', 1)[0]}/aisoc:{report.version} already exists "
                    f"and holds different content ({len(differences)} difference(s)): "
                    + "; ".join(differences[:5])
                    + (" …" if len(differences) > 5 else "")
                    + ". Pushing would overwrite an immutable coordinate; bump the chart version instead.",
                )
            )
    else:
        behind = [t for t in report.published if _SEMVER.match(t) and semver_key(t) >= semver_key(report.version)]
        if behind:
            findings.append(
                Finding(
                    "behind-the-registry",
                    f"the tree's chart version {report.version} is at or below {', '.join(behind)}, which "
                    "the registry already holds. The next release would publish backwards.",
                )
            )
    return findings


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------
def scan(root: Path, *, baseline: str | None, registry: ChartRegistry | None) -> tuple[Report, list[Finding]]:
    tree = chart_content(root)
    meta = metadata(tree)
    report = Report(version=str(meta.get("version") or ""), app_version=str(meta.get("appVersion") or ""))
    if not report.version:
        raise ChartError("Chart.yaml declares no version")
    semver_key(report.version)

    report.baseline = resolve_baseline(root, baseline)
    base = chart_content(root, report.baseline)
    base_meta = metadata(base)
    report.baseline_version = str(base_meta.get("version") or "")
    report.baseline_app_version = str(base_meta.get("appVersion") or "")
    report.changed_files = changed_chart_files(base, tree)

    findings = baseline_findings(report)

    report.collisions = collisions(declared_versions(root))
    findings.extend(collision_findings(report.collisions))

    if registry is not None:
        try:
            findings.extend(registry_findings(report, tree, registry))
        except Offline as exc:
            report.skipped = str(exc)
    return report, findings


def _self_test() -> int:
    """Prove each check still detects what it claims, without a network."""
    tree = {
        "Chart.yaml": b'# a comment\nversion: 6.0.0\nappVersion: "v13.0.0"\n',
        "values.yaml": b"replicas: 1\n",
        "templates/deployment.yaml": b"kind: Deployment\n",
    }

    def probe(**overrides: object) -> set[str]:
        report = Report(
            version="6.0.0",
            app_version="v13.0.0",
            baseline_version="6.0.0",
            baseline_app_version="v13.0.0",
        )
        for key, value in overrides.items():
            setattr(report, key, value)
        return {f.code for f in baseline_findings(report)}

    prefix_v13 = probe(version="5.9.2", baseline_version="5.9.2", baseline_app_version="v12.3.2")
    fixed_v13 = probe(version="6.0.0", baseline_version="5.9.2", baseline_app_version="v12.3.2")

    resorted = dict(sorted({"redis/values.yaml": b"x"}.items()))
    cases: list[tuple[str, bool]] = [
        (
            "the v13.0.0 pre-fix pair (5.9.2/v12.3.2 -> 5.9.2/v13.0.0) is reported",
            prefix_v13 == {"appversion-moved-alone"},
        ),
        ("the v13.0.0 fix (5.9.2 -> 6.0.0) is not reported", fixed_v13 == set()),
        (
            "a template change with no version bump is reported",
            probe(changed_files=["templates/deployment.yaml"]) == {"content-moved-alone"},
        ),
        (
            "a version bump on its own is not a content change",
            changed_chart_files(
                {"Chart.yaml": b'version: 5.9.2\nappVersion: "v13.0.0"\n'},
                {"Chart.yaml": b'version: 6.0.0\nappVersion: "v13.0.0"\n'},
            )
            == [],
        ),
        (
            "an appVersion change is a content change even with version masked",
            changed_chart_files(
                {"Chart.yaml": b'version: 5.9.2\nappVersion: "v12.3.2"\n'},
                {"Chart.yaml": b'version: 5.9.2\nappVersion: "v13.0.0"\n'},
            )
            == ["Chart.yaml"],
        ),
        (
            "a version that moves backward is reported",
            probe(version="5.8.0", baseline_version="5.9.2") == {"version-went-backward"},
        ),
        (
            "a comment-only Chart.yaml difference is not a content difference",
            content_differences(tree, {**tree, "Chart.yaml": b'version: 6.0.0\nappVersion: "v13.0.0"\n'}) == [],
        ),
        (
            "a changed template is a content difference",
            content_differences(tree, {**tree, "templates/deployment.yaml": b"kind: StatefulSet\n"})
            == ["templates/deployment.yaml: differs"],
        ),
        (
            "a file only the tree has is a content difference",
            content_differences(tree, {k: v for k, v in tree.items() if k != "values.yaml"})
            == ["values.yaml: present in the tree, absent from the published chart"],
        ),
        (
            "a file only the registry has is a content difference",
            content_differences(tree, {**tree, "templates/extra.yaml": b"x\n"})
            == ["templates/extra.yaml: present in the published chart, absent from the tree"],
        ),
        (
            "a differing appVersion in a published Chart.yaml is a content difference",
            content_differences(tree, {**tree, "Chart.yaml": b'version: 6.0.0\nappVersion: "v12.3.2"\n'}) == ["Chart.yaml: differs"],
        ),
        (
            "an unrecorded reuse across releases is reported",
            {f.code for f in collision_findings({**_recorded(), "7.1.0": ("v14.0.0", "v14.1.0")})} == {"reused-across-releases"},
        ),
        ("a recorded reuse is not re-reported", collision_findings(_recorded()) == []),
        (
            "a recorded reuse the history no longer shows is reported",
            {f.code for f in collision_findings({})} == {"recorded-collision-not-found"},
        ),
        ("a non-semver chart version is refused rather than ordered", _refuses_semver("6.0")),
        ("file order does not change a comparison", content_differences(resorted, dict(reversed(list(resorted.items())))) == []),
    ]
    return self_test_main(Path(__file__).name, ["--check"], cases)


def _recorded() -> dict[str, tuple[str, ...]]:
    """``KNOWN_COLLISIONS`` shaped the way an observation of it would look."""
    return {version: tags for version, (tags, _reason) in KNOWN_COLLISIONS.items()}


def _refuses_semver(version: str) -> bool:
    try:
        semver_key(version)
    except ChartError:
        return True
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A chart version may mean one thing only.")
    parser.add_argument("--check", action="store_true", help="render a verdict (the default)")
    parser.add_argument("--baseline", help="commit-ish to compare this tree against")
    parser.add_argument(
        "--require-network",
        action="store_true",
        help="an unreachable registry is a failure, not a skip — use this on a release",
    )
    parser.add_argument("--no-network", action="store_true", help="skip the registry comparison entirely")
    parser.add_argument(SELF_TEST_FLAG, action="store_true", dest="self_test")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    root = repo_root()
    registry = None if args.no_network else ChartRegistry()
    try:
        report, findings = scan(root, baseline=args.baseline, registry=registry)
    except ChartError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(f"chart {CHART_REL}: version {report.version}, appVersion {report.app_version}")
    print(f"  baseline {report.baseline[:12]}: version {report.baseline_version}, appVersion {report.baseline_app_version}")
    print(f"  {len(report.changed_files)} chart file(s) changed since the baseline")
    if report.published:
        print(f"  registry holds: {', '.join(report.published)}")
        if report.files_compared:
            print(f"  compared {report.files_compared} published file(s) against the tree")
    if report.collisions:
        for version, tags in sorted(report.collisions.items()):
            note = "recorded" if version in KNOWN_COLLISIONS else "NEW"
            print(f"  {version} declared at {', '.join(tags)} with differing content [{note}]")
    if report.skipped:
        if args.require_network:
            print(f"ERROR: --require-network and the registry could not answer: {report.skipped}", file=sys.stderr)
            return 1
        print(f"  registry comparison skipped: {report.skipped}")

    if findings:
        print()
        for finding in findings:
            print(f"FAIL [{finding.code}] {finding.detail}", file=sys.stderr)
        print(f"\n{len(findings)} finding(s). A chart version must never name two different charts.", file=sys.stderr)
        return 1

    print("\nOK: the chart's version moves with its content and collides with nothing published.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
