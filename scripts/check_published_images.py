#!/usr/bin/env python3
"""An image the deployment files tell an operator to pull has to exist.

Why this exists
---------------
Nothing in this repository checked that. The result was not a hypothetical:

* ``ghcr.io/beenuar/aisoc-web:latest`` — what ``docker compose up`` pulls for
  the console — was built from a commit two releases behind ``main``, so every
  honest-state fix, fabrication removal and first-run improvement of the week
  was invisible to anyone following the documented quickstart. The publish
  workflow was green throughout, because it *was* green: the web job was
  repeatedly killed by ``cancel-in-progress`` and the run reported cancelled,
  not failed, while the other twelve images published normally.
* ``aisoc-web:v11.0.0`` was never pushed at all, while the same release's
  ``aisoc-core-api``, ``aisoc-fusion`` and ``aisoc-ingest`` tags all were. A
  partial release is not a state any workflow noticed.
* ``aisoc-honeytokens``, ``aisoc-purple-team`` and ``aisoc-osquery-tls`` were
  named by ``docker-compose.yml`` and had never been published *once*. Compose
  falls back to a local build, so this was a silent twenty-minute first run
  rather than an error — but the Helm chart has no such fallback, and named
  two of the same three.
* The chart's images all default to ``Chart.AppVersion``, which read ``5.2.0``
  — a tag that exists for no image in the registry. ``helm install`` could
  only ever have produced ``ImagePullBackOff`` on every pod.

A green workflow proves a job ran. It does not prove the registry holds what
the README, the compose file and the chart tell people to pull. Only the
registry can answer that, so this asks it.

What it checks
--------------
``exists``
    Every first-party image reference in ``docker-compose.yml`` and the Helm
    chart resolves, at the tag an operator will actually request — the
    ``${AISOC_VERSION:-latest}`` default for compose, ``Chart.AppVersion`` for
    a chart value left empty. Resolving the tag is half the check: a reference
    read literally is a reference nobody pulls.

``fresh`` (``--require-fresh``)
    And the version *inside* it matches the tree. Read from
    ``org.opencontainers.image.revision`` — the commit the image was built
    from — then ``git show <commit>:VERSION``. That is the check that would
    have caught the state above, since existence alone would have passed:
    ``:latest`` was present the whole time, just old.

    Off by default because a release commit bumps ``VERSION`` and the images
    for it cannot exist until that commit has merged and published. Enforcing
    freshness on a pull request would fail every release PR for being a
    release PR. It is a scheduled question, asked of ``main``, where a stale
    ``:latest`` is a real defect and not a race.

Third-party references — ``postgres:16-alpine``, ``redis:7-alpine``,
``ghcr.io/berriai/litellm`` — are counted and named but not resolved. This
gate exists to check the images *this project publishes*; upstream
availability is not a claim this repository makes, and anonymous pulls against
a third-party registry are rate-limited per runner IP, which would make the
answer depend on who else shares the runner.

Offline
-------
A skip is not a pass, and the output says which happened every time. Without
``--require-network`` an unreachable registry prints ``SKIPPED`` and never
``OK``, so a contributor with no network is not told the tree is wrong; with
it, unreachable is a hard failure, which is what the scheduled job uses.

The empty-tree refusal happens before the first request, so the answer does
not depend on whether the probe running it had a network at all.

Usage
-----
    python3 scripts/check_published_images.py
    python3 scripts/check_published_images.py --require-fresh --require-network
    python3 scripts/check_published_images.py --list
    python3 scripts/check_published_images.py --json
    python3 scripts/check_published_images.py --self-test

Exit codes: 0 clean (or an announced skip), 1 findings, 2 the scan could not run.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import refuses_an_empty_tree, repo_root, scratch_tree  # noqa: E402

COMPOSE_REL = Path("docker-compose.yml")
CHART_REL = Path("infra/helm/aisoc")
VERSION_REL = Path("VERSION")

#: The registry this project publishes to. A reference anywhere else belongs
#: to somebody else and is reported rather than resolved — see the docstring.
REGISTRY = "ghcr.io"

#: Tags that move. Their content is whatever the last successful publish put
#: there, so "does it exist" and "is it current" are different questions and
#: only the first is asked on a pull request.
MOVING_TAGS = frozenset({"latest", "main", "edge", "nightly", "demo"})

#: ``${AISOC_VERSION:-latest}`` and friends. Compose expands these at up time;
#: read literally the tag is a string no registry has ever held.
_INTERPOLATION = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}")

#: A fully-written first-party image reference in prose. Deliberately not
#: matching a placeholder registry or an unresolved variable: those are
#: illustrations, and resolving them would test the example rather than
#: anything an operator would run.
_DOCS_IMAGE = re.compile(r"(ghcr\.io/beenuar/[a-z0-9._-]+):([A-Za-z0-9][A-Za-z0-9._-]*)")

_TIMEOUT = 20

_MANIFEST_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)

PRESENT = "present"
ABSENT = "absent"
UNREACHABLE = "unreachable"


class Offline(RuntimeError):
    """The registry could not be reached, which is not the same as absent."""


class ScanError(RuntimeError):
    """An input could not be read. Never downgraded to a passing result."""


@dataclass(frozen=True)
class Reference:
    """One image an operator is told to pull, with its tag already resolved."""

    source: str
    service: str
    repository: str
    tag: str
    #: How the tag was arrived at, so a finding can say what to edit.
    tag_origin: str
    #: Whether this reference is expected to track the tree. A deployment file
    #: is; prose naming an older release is not wrong for naming it.
    tracks_tree: bool = True

    @property
    def ref(self) -> str:
        return f"{self.repository}:{self.tag}"

    @property
    def first_party(self) -> bool:
        return self.repository.startswith(f"{REGISTRY}/beenuar/")

    @property
    def moving(self) -> bool:
        return self.tag in MOVING_TAGS


@dataclass
class Resolution:
    """What the registry said about one reference."""

    state: str
    #: ``org.opencontainers.image.revision`` — the commit it was built from.
    revision: str = ""
    detail: str = ""


# --------------------------------------------------------------------------
# Reading the deployment files
# --------------------------------------------------------------------------
def _expand(value: str) -> tuple[str, bool]:
    """``${VAR:-default}`` -> ``default``. Returns (expanded, was_interpolated).

    The default is what an operator who sets nothing gets, and setting nothing
    is the documented path. A variable with no default expands to empty, which
    is not a tag anybody can pull, and is reported as such rather than guessed.
    """
    interpolated = bool(_INTERPOLATION.search(value))
    return _INTERPOLATION.sub(lambda m: m.group(2) or "", value), interpolated


def _split(image: str) -> tuple[str, str]:
    """``repo:tag`` -> (repo, tag), tolerating a port in the registry host."""
    if "@" in image:
        repository, _, digest = image.partition("@")
        return repository, digest
    head, sep, tail = image.rpartition(":")
    if sep and "/" not in tail:
        return head, tail
    return image, "latest"


def collect_compose_references(root: Path) -> list[Reference]:
    """Every ``image:`` under ``services:``, at the tag ``docker compose up`` requests."""
    path = root / COMPOSE_REL
    if not path.is_file():
        raise ScanError(f"no {COMPOSE_REL} to read: {path}")
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ScanError(f"{COMPOSE_REL} is not readable as YAML: {exc}") from exc

    references: list[Reference] = []
    for name, service in sorted((document.get("services") or {}).items()):
        if not isinstance(service, dict) or not isinstance(service.get("image"), str):
            continue
        expanded, interpolated = _expand(service["image"])
        repository, tag = _split(expanded)
        origin = "the default in ${AISOC_VERSION:-…}" if interpolated else "written literally"
        references.append(Reference(str(COMPOSE_REL), name, repository, tag, origin))
    return references


def collect_helm_references(root: Path) -> list[Reference]:
    """Every ``{repository, tag}`` pair in the chart's values, tag resolved.

    Found by walking the document rather than by naming the six places they
    live today: ``services.*``, ``ueba``, ``honeytokens``, ``purpleTeam`` and
    ``backup`` are five different shapes already, and a sixth added next to
    them must not be able to arrive unchecked.
    """
    values = root / CHART_REL / "values.yaml"
    chart = root / CHART_REL / "Chart.yaml"
    if not values.is_file() or not chart.is_file():
        raise ScanError(f"no Helm chart to read at {CHART_REL}")
    try:
        document = yaml.safe_load(values.read_text(encoding="utf-8")) or {}
        metadata = yaml.safe_load(chart.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ScanError(f"the Helm chart is not readable as YAML: {exc}") from exc

    app_version = str(metadata.get("appVersion") or "")
    references: list[Reference] = []

    def walk(node: object, trail: str) -> None:
        if not isinstance(node, dict):
            if isinstance(node, list):
                for index, item in enumerate(node):
                    walk(item, f"{trail}[{index}]")
            return
        repository = node.get("repository")
        if isinstance(repository, str) and "tag" in node:
            declared = str(node.get("tag") or "")
            # `tag: ""` is not "no tag": every template that reads one of these
            # writes `| default .Chart.AppVersion`, so an empty value in
            # values.yaml is a live reference to whatever the chart calls its
            # app version — which is exactly how the chart came to request a
            # tag that had never been published.
            tag = declared or app_version
            origin = "written literally" if declared else f"empty, so Chart.AppVersion ({app_version or 'unset'})"
            references.append(Reference(f"{CHART_REL}/values.yaml", trail, repository, tag, origin))
            return
        for key, value in sorted(node.items()):
            walk(value, f"{trail}.{key}" if trail else str(key))

    walk(document, "")
    return references


def collect_docs_references(root: Path) -> list[Reference]:
    """Fully-written ``ghcr.io/beenuar/<image>:<tag>`` strings in tracked prose.

    A published page telling somebody to pull an image is the same claim the
    compose file makes, and it was wrong in the same way:
    ``apps/docs/docs/deployment/kubernetes.md`` listed seven images at ``v5.2.0``, a
    no image carries, and two of the names — ``aisoc-api`` and ``aisoc-mcp`` —
    have never existed under any tag at all.

    Existence only. A release note naming an older image is describing history
    rather than instructing anybody, so freshness is not asked of prose.
    Placeholders like ``my-registry/aisoc-core-api`` are outside the pattern
    and are not resolved.

    Only a complete ``repository:tag`` matches, which is also the escape for
    prose *about* a broken reference: naming the repository alone
    (``aisoc-api``) describes it without telling anybody to pull it. This
    changelog entry needed that, which is the sort of thing a gate discovers
    about itself the first time it reads its own release notes.
    """
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "ls-files", "-z", "*.md", "*.mdx"],
        capture_output=True,
        text=True,
        check=False,
        cwd=root,
    )
    if out.returncode != 0:
        # Not a git checkout, or git is absent. The deployment files are the
        # gate's subject either way, so this degrades to "prose not scanned"
        # rather than failing the run — and says so in the summary.
        return []
    references: list[Reference] = []
    seen: set[tuple[str, str, str]] = set()
    for name in filter(None, out.stdout.split("\0")):
        path = root / name
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in _DOCS_IMAGE.finditer(text):
            repository, tag = match.group(1), match.group(2)
            key = (name, repository, tag)
            if key in seen:
                continue
            seen.add(key)
            references.append(Reference(name, "prose", repository, tag, "written literally", tracks_tree=False))
    return references


def tree_version(root: Path) -> str:
    path = root / VERSION_REL
    if not path.is_file():
        raise ScanError(f"no {VERSION_REL} to compare against: {path}")
    return path.read_text(encoding="utf-8").strip()


def version_from_tag(tag: str) -> str:
    """The version a tag name promises, or "" when it promises none.

    ``v11.0.0`` claims a version; ``latest`` and ``16-alpine`` do not. Read
    from the name rather than from the image because that is the claim an
    operator pinning the tag is relying on — and because release images pushed
    before this workflow attached OCI labels carry nothing else to read.
    """
    return tag[1:] if re.fullmatch(r"v\d+\.\d+\.\d+(?:[-+].*)?", tag or "") else ""


def version_at(root: Path, commit: str) -> str:
    """``VERSION`` as of ``commit``, or "" when this checkout cannot say.

    A shallow clone genuinely does not know, and answering anyway would be
    inventing the number this gate exists to verify.
    """
    if not re.fullmatch(r"[0-9a-f]{7,40}", commit or ""):
        return ""
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "show", f"{commit}:{VERSION_REL}"],
        capture_output=True,
        text=True,
        check=False,
        cwd=root,
    )
    return out.stdout.strip() if out.returncode == 0 else ""


# --------------------------------------------------------------------------
# Asking the registry
# --------------------------------------------------------------------------
class GhcrClient:
    """Anonymous reads against GHCR. Public packages need no credential."""

    def __init__(self, timeout: int = _TIMEOUT) -> None:
        self._timeout = timeout
        self._tokens: dict[str, str | None] = {}

    def _get(self, url: str, headers: dict[str, str]) -> object:
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310 - fixed https host
            return json.load(response)

    def _token(self, repository: str) -> str | None:
        """A pull token, or None when the package does not exist at all.

        GHCR refuses to mint an anonymous token for a repository nobody has
        ever pushed, which is how a never-published image is distinguished
        from a published one missing a tag. Both are findings; they need
        different sentences.
        """
        if repository not in self._tokens:
            url = f"https://{REGISTRY}/token?scope=repository:{repository}:pull&service={REGISTRY}"
            try:
                payload = self._get(url, {"Accept": "application/json"})
            except urllib.error.HTTPError:
                self._tokens[repository] = None
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                raise Offline(f"{REGISTRY} unreachable: {exc}") from exc
            else:
                self._tokens[repository] = (payload or {}).get("token") if isinstance(payload, dict) else None
        return self._tokens[repository]

    def resolve(self, reference: Reference) -> Resolution:
        repository = reference.repository.split("/", 1)[1]
        if not reference.tag:
            return Resolution(ABSENT, detail="the reference carries no tag at all")
        token = self._token(repository)
        if token is None:
            return Resolution(ABSENT, detail="no such package in the registry — it has never been published")
        headers = {"Authorization": f"Bearer {token}", "Accept": ", ".join(_MANIFEST_TYPES)}
        url = f"https://{REGISTRY}/v2/{repository}/manifests/{reference.tag}"
        try:
            manifest = self._get(url, headers)
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 403):
                return Resolution(ABSENT, detail=f"the package exists but has no {reference.tag!r} tag")
            raise Offline(f"{reference.ref} returned {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise Offline(f"{reference.ref} unreachable: {exc}") from exc
        return Resolution(PRESENT, revision=self._revision(repository, manifest, headers))

    def _revision(self, repository: str, manifest: object, headers: dict[str, str]) -> str:
        """``org.opencontainers.image.revision``, from wherever this image carries it.

        A multi-arch push records it three ways depending on how the manifest
        was assembled — index annotations, the per-platform manifest's
        annotations, or the image config's labels — so all three are tried
        before reporting that the image does not say.
        """
        if not isinstance(manifest, dict):
            return ""
        key = "org.opencontainers.image.revision"
        annotated = (manifest.get("annotations") or {}).get(key)
        if annotated:
            return str(annotated)
        try:
            if "manifests" in manifest:
                for entry in manifest.get("manifests") or []:
                    platform = (entry.get("platform") or {}).get("architecture")
                    if platform in (None, "unknown"):
                        continue
                    child = self._get(f"https://{REGISTRY}/v2/{repository}/manifests/{entry['digest']}", headers)
                    found = self._revision(repository, child, headers)
                    if found:
                        return found
                return ""
            digest = (manifest.get("config") or {}).get("digest")
            if not digest:
                return ""
            config = self._get(
                f"https://{REGISTRY}/v2/{repository}/blobs/{digest}",
                {**headers, "Accept": "application/json"},
            )
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
            return ""
        if not isinstance(config, dict):
            return ""
        labels = (config.get("config") or {}).get("Labels") or {}
        return str(labels.get(key) or "")


# --------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------
@dataclass
class Report:
    """Everything one run learned, so the printer and the tests share a shape."""

    references: list[Reference] = field(default_factory=list)
    resolutions: dict[str, Resolution] = field(default_factory=dict)
    versions: dict[str, str] = field(default_factory=dict)
    tree: str = ""
    skipped: str = ""

    @property
    def first_party(self) -> list[Reference]:
        return [r for r in self.references if r.first_party]

    @property
    def third_party(self) -> list[Reference]:
        return [r for r in self.references if not r.first_party]


def evaluate(report: Report, *, require_fresh: bool) -> list[tuple[str, str]]:
    """Every finding, as (code, detail). Pure, so the self-test can drive it."""
    findings: list[tuple[str, str]] = []
    for reference in report.first_party:
        resolution = report.resolutions.get(reference.ref)
        if resolution is None or resolution.state == UNREACHABLE:
            continue
        where = f"{reference.source} ({reference.service})"
        if resolution.state == ABSENT:
            kind = "A deployment file" if reference.tracks_tree else "A published page"
            findings.append(
                (
                    "image-missing",
                    f"{where} tells an operator to pull {reference.ref} — tag {reference.tag} from "
                    f"{reference.tag_origin} — and {resolution.detail}. Either publish it or stop naming it: "
                    f"{kind.lower()} pointing at an image that has never existed is a false claim whether "
                    "or not something else quietly covers for it.",
                )
            )
            continue
        if not require_fresh or not reference.tracks_tree:
            continue
        # Two independent sources, and which one exists depends on the tag.
        # `claimed` is what the tag name promises — the whole point of a
        # pinned tag, and the only source for release images pushed before
        # this workflow started applying OCI labels. `built` is what the image
        # records about the commit behind it, which is all a moving tag has.
        claimed = version_from_tag(reference.tag)
        built = report.versions.get(reference.ref, "")
        if claimed and built and claimed != built:
            findings.append(
                (
                    "version-mismatch",
                    f"{where}: {reference.ref} is tagged as {claimed} and was built from a commit carrying "
                    f"version {built}. The tag does not describe its own contents, so pinning to it pins to "
                    "something other than what it says.",
                )
            )
            continue
        effective = claimed or built
        if not effective:
            findings.append(
                (
                    "version-unreadable",
                    f"{where}: {reference.ref} is published, its tag names no version, and it does not record "
                    "which commit it was built from — or that commit is not in this checkout. Whether it "
                    "matches the tree is unverified, and unverified is reported rather than assumed clean.",
                )
            )
        elif effective != report.tree:
            stale = "is a moving tag and has fallen behind" if reference.moving else "is pinned to an older release"
            findings.append(
                (
                    "version-stale",
                    f"{where}: {reference.ref} holds version {effective} while the tree is {report.tree}. The "
                    f"tag {stale} ({reference.tag_origin}). Anyone following the documented deployment path "
                    f"gets {effective}, not what this repository says it is.",
                )
            )
    return findings


def scan(root: Path, client: GhcrClient | None, *, require_fresh: bool) -> Report:
    """Read the deployment files, then ask the registry about what they name.

    The deployment files are read before ``VERSION`` and long before the first
    request, so a refusal names the subject that is missing and the answer does
    not depend on whether the caller had a network.
    """
    report = Report()
    report.references = collect_compose_references(root) + collect_helm_references(root) + collect_docs_references(root)
    if not report.first_party:
        raise ScanError(
            f"{COMPOSE_REL} and {CHART_REL} name no {REGISTRY}/beenuar image at all. Found nothing and scanned "
            "nothing print the same word, so this is a refusal rather than a clean result."
        )
    report.tree = tree_version(root)
    if client is None:
        return report
    for reference in report.first_party:
        if reference.ref in report.resolutions:
            continue
        resolution = client.resolve(reference)
        report.resolutions[reference.ref] = resolution
        if require_fresh and resolution.state == PRESENT:
            report.versions[reference.ref] = version_at(root, resolution.revision)
    return report


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=None, help="the tree to inspect (default: git rev-parse)")
    parser.add_argument(
        "--require-fresh",
        action="store_true",
        help="also require the version inside each image to match the tree",
    )
    parser.add_argument(
        "--require-network",
        action="store_true",
        help="fail instead of skipping when the registry cannot be reached",
    )
    parser.add_argument("--list", action="store_true", help="print every reference with its state")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true", help="prove this gate detects the drift it claims to")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    root = (args.repo_root or repo_root()).resolve()
    client = GhcrClient()
    try:
        report = scan(root, client, require_fresh=args.require_fresh)
    except ScanError as exc:
        print(f"check_published_images: FAILED to run the scan: {exc}", file=sys.stderr)
        return 2
    except Offline as exc:
        if args.require_network:
            print(f"check_published_images: FAILED — {exc}", file=sys.stderr)
            return 2
        # Deliberately not "OK". The registry was never asked, so nothing here
        # was verified, and the word for that is SKIPPED.
        print(f"SKIPPED — the registry was not reachable, so nothing was verified: {exc}")
        print("         Re-run with --require-network to make this a failure instead.")
        return 0

    findings = evaluate(report, require_fresh=args.require_fresh)

    if args.json:
        print(
            json.dumps(
                {
                    "repo_root": str(root),
                    "tree_version": report.tree,
                    "references": [asdict(r) for r in report.references],
                    "resolutions": {k: asdict(v) for k, v in report.resolutions.items()},
                    "versions": report.versions,
                    "findings": [{"code": c, "detail": d} for c, d in findings],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1 if findings else 0

    print(f"repo root        {root}")
    print(f"tree version     {report.tree}")
    prose = sum(1 for r in report.first_party if not r.tracks_tree)
    print(f"sources          {COMPOSE_REL}, {CHART_REL}/values.yaml, and {prose} reference(s) in tracked prose")
    print(
        f"references       {len(report.first_party)} first-party ({REGISTRY}/beenuar), {len(report.third_party)} third-party not resolved"
    )
    print(f"freshness        {'enforced' if args.require_fresh else 'reported only (pass --require-fresh to enforce)'}")
    print()

    if args.list:
        width = max((len(r.ref) for r in report.first_party), default=10)
        for reference in report.first_party:
            resolution = report.resolutions.get(reference.ref, Resolution(UNREACHABLE))
            built = report.versions.get(reference.ref)
            suffix = f"  holds {built}" if built else ""
            print(f"  {resolution.state:<10} {reference.ref:{width}}  {reference.source} ({reference.service}){suffix}")
        if report.third_party:
            print()
            print(f"  not resolved (published by somebody else): {', '.join(sorted({r.ref for r in report.third_party}))}")
        print()

    if findings:
        print(f"PUBLISHED-IMAGES GATE FAILED — {len(findings)} finding(s):", file=sys.stderr)
        for code, detail in findings:
            print(f"  [{code}] {detail}", file=sys.stderr)
        return 1

    checked = len(report.first_party)
    verified = "and the version inside each matches the tree" if args.require_fresh else "(freshness not enforced on this run)"
    print(f"OK — all {checked} first-party image reference(s) resolve in {REGISTRY} {verified}.")
    return 0


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------
def _reference(**overrides: object) -> Reference:
    base: dict[str, object] = {
        "source": "docker-compose.yml",
        "service": "web",
        "repository": f"{REGISTRY}/beenuar/aisoc-web",
        "tag": "latest",
        "tag_origin": "the default in ${AISOC_VERSION:-…}",
    }
    base.update(overrides)
    return Reference(**base)  # type: ignore[arg-type]


def _report(resolution: Resolution, *, built: str = "11.0.0", tree: str = "11.0.0", **overrides: object) -> Report:
    reference = _reference(**overrides)
    return Report(
        references=[reference],
        resolutions={reference.ref: resolution},
        versions={reference.ref: built},
        tree=tree,
    )


def self_test() -> int:
    """Inject each defect this gate exists to catch and require it to be caught."""

    def codes(report: Report, *, fresh: bool = True) -> set[str]:
        return {code for code, _ in evaluate(report, require_fresh=fresh)}

    print("check_published_images self-test")
    print("baseline: one published, current image — 0 findings (every case below perturbs exactly that)\n")

    checks: list[tuple[str, bool]] = []

    def record(description: str, passed: bool, detail: str = "") -> None:
        checks.append((description, passed))
        print(f"  {'PASS' if passed else 'FAIL'}  {description}")
        if detail:
            print(f"        {detail}")

    baseline = codes(_report(Resolution(PRESENT, revision="abc1234")))
    record("the unperturbed baseline reports nothing", not baseline, f"got {sorted(baseline) or 'nothing'}")

    # The three states today's registry is actually in.
    cases: list[tuple[str, str, set[str]]] = [
        (
            "a tag the compose file names that the registry does not hold",
            "image-missing",
            codes(_report(Resolution(ABSENT, detail="the package exists but has no 'v11.0.0' tag"), tag="v11.0.0")),
        ),
        (
            "an image name that has never been published at all",
            "image-missing",
            codes(
                _report(
                    Resolution(ABSENT, detail="no such package in the registry — it has never been published"),
                    repository=f"{REGISTRY}/beenuar/aisoc-honeytokens",
                )
            ),
        ),
        (
            "prose telling an operator to pull an image that does not exist",
            "image-missing",
            codes(
                _report(
                    Resolution(ABSENT, detail="no such package in the registry — it has never been published"),
                    source="apps/docs/docs/deployment/kubernetes.md",
                    service="prose",
                    repository=f"{REGISTRY}/beenuar/aisoc-api",
                    tag="v5.2.0",
                    tracks_tree=False,
                )
            ),
        ),
        (
            "a published image whose version is behind the tree — green workflow, stale artefact",
            "version-stale",
            codes(_report(Resolution(PRESENT, revision="d704c25b"), built="10.0.0", tree="11.0.0")),
        ),
        (
            "a chart pinned to a release older than the tree",
            "version-stale",
            codes(
                _report(
                    Resolution(PRESENT, revision="aaaaaaa"),
                    built="",
                    tree="11.0.0",
                    source="infra/helm/aisoc/values.yaml",
                    tag="v5.2.0",
                    tag_origin="empty, so Chart.AppVersion (v5.2.0)",
                )
            ),
        ),
        (
            "a tag that does not describe its own contents",
            "version-mismatch",
            codes(_report(Resolution(PRESENT, revision="d704c25b"), built="10.0.0", tree="11.0.0", tag="v11.0.0")),
        ),
        (
            "a moving tag on an image that does not say which commit built it is unverified, not clean",
            "version-unreadable",
            codes(_report(Resolution(PRESENT, revision=""), built="")),
        ),
    ]
    for description, expected, found in cases:
        record(description, expected in found, f"expected [{expected}]  got {sorted(found) or 'nothing'}")

    # Things that must NOT be findings.
    quiet: list[tuple[str, set[str]]] = [
        (
            "a stale image is not a finding when freshness is not being enforced",
            codes(_report(Resolution(PRESENT, revision="d704c25b"), built="10.0.0", tree="11.0.0"), fresh=False),
        ),
        (
            "a third-party reference is neither resolved nor credited",
            codes(_report(Resolution(ABSENT), repository="docker.io/library/postgres", tag="16-alpine")),
        ),
        (
            "an unreachable registry is never read as a missing image",
            codes(_report(Resolution(UNREACHABLE, detail="timed out"))),
        ),
        (
            "a pinned tag answers for itself when the image carries no OCI label",
            codes(_report(Resolution(PRESENT, revision=""), built="", tree="11.0.0", tag="v11.0.0")),
        ),
        (
            "prose naming an older release is describing history, not instructing anybody",
            codes(
                _report(
                    Resolution(PRESENT, revision="aaaaaaa"),
                    built="9.0.0",
                    tree="11.0.0",
                    source="RELEASES.md",
                    service="prose",
                    tag="v9.0.0",
                    tracks_tree=False,
                )
            ),
        ),
    ]
    for description, found in quiet:
        record(description, not found, f"got {sorted(found) or 'nothing'}")

    # The readers. Every case above is only as good as the claim that a tag was
    # resolved the way an operator's tooling resolves it.
    readers: list[tuple[str, object, object]] = [
        (
            "${AISOC_VERSION:-latest} resolves to the default an operator gets",
            _expand("ghcr.io/x:${AISOC_VERSION:-latest}")[0],
            "ghcr.io/x:latest",
        ),
        ("a variable with no default resolves to no tag, not to a guess", _expand("ghcr.io/x:${AISOC_VERSION}")[0], "ghcr.io/x:"),
        ("a literal tag is left alone", _expand("postgres:16-alpine"), ("postgres:16-alpine", False)),
        ("a tagless reference means latest", _split("ghcr.io/beenuar/aisoc-web"), ("ghcr.io/beenuar/aisoc-web", "latest")),
        ("a registry port is not mistaken for a tag", _split("localhost:5000/aisoc-web"), ("localhost:5000/aisoc-web", "latest")),
        ("a digest reference keeps its digest", _split("ghcr.io/x@sha256:abc")[1], "sha256:abc"),
        ("ghcr.io/beenuar is first-party", _reference().first_party, True),
        ("ghcr.io/berriai is not", _reference(repository="ghcr.io/berriai/litellm").first_party, False),
        ("latest is a moving tag", _reference().moving, True),
        ("v11.0.0 is not", _reference(tag="v11.0.0").moving, False),
        ("v11.0.0 names a version", version_from_tag("v11.0.0"), "11.0.0"),
        ("a prerelease tag names one too", version_from_tag("v11.1.0-rc.1"), "11.1.0-rc.1"),
        ("latest names none", version_from_tag("latest"), ""),
        ("an upstream tag that merely looks numeric names none", version_from_tag("16-alpine"), ""),
    ]
    for description, got, want in readers:
        record(f"READER: {description}", got == want, f"expected {want!r}  got {got!r}")

    # And the chart reader, against the shape that made the chart uninstallable:
    # a tag left empty is a live reference to Chart.AppVersion, not to nothing.
    with scratch_tree() as tree:
        chart = tree / CHART_REL
        chart.mkdir(parents=True)
        (chart / "Chart.yaml").write_text('appVersion: "9.9.9"\n', encoding="utf-8")
        (chart / "values.yaml").write_text(
            'services:\n  api:\n    image:\n      repository: ghcr.io/beenuar/aisoc-core-api\n      tag: ""\n'
            'ueba:\n  image:\n    repository: ghcr.io/beenuar/aisoc-ueba\n    tag: "1.2.3"\n',
            encoding="utf-8",
        )
        parsed = {r.service: (r.repository, r.tag) for r in collect_helm_references(tree)}
    record(
        "CHART: an empty tag resolves to Chart.AppVersion rather than to nothing",
        parsed.get("services.api.image") == ("ghcr.io/beenuar/aisoc-core-api", "9.9.9"),
        f"got {parsed.get('services.api.image')!r}",
    )
    record(
        "CHART: a nested block outside services/ is found by walking, not by being named",
        parsed.get("ueba.image") == ("ghcr.io/beenuar/aisoc-ueba", "1.2.3"),
        f"got {parsed.get('ueba.image')!r}",
    )

    # The shared floor every gate here answers to, run the way CI runs this one.
    refused, detail = refuses_an_empty_tree(Path(__file__).name, ["--require-fresh"])
    record("refuses a tree with no content rather than reporting it clean", refused, detail.replace("\n", " | "))

    print()
    if not all(passed for _description, passed in checks):
        print("check_published_images.py: self-test FAILED — this gate did not catch drift it claims to catch")
        return 1
    print(f"check_published_images.py: self-test OK ({len(checks)} assertions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
