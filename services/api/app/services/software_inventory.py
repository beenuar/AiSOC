"""Package-level software inventory, and the end-of-life question.

Wave 2, Phase 5.4.

What this answers that nothing could
------------------------------------
"Where does package P at version V run?" `assets` is host-level: it records
that a host exists and that a CVE applies to it, never what is installed.
The osquery baseline pack already enumerated Debian, RPM and Homebrew
packages — and not Windows `programs`, so the largest estate in most tenants
was never queried — and nothing consumed the rows. They came back from the
endpoint and there was nowhere to put them.

Two sources, deliberately not merged
------------------------------------
An endpoint agent reports what is *installed on a running host*. A code
platform's SBOM reports what a *repository declares*. Both are packages and
the rows share a shape, but the remediation differs and an operator deciding
where to patch must not have them silently combined — so `source` is part of
the identity, and an SBOM row carries no `asset_id` because inventing a host
for it would be a fabricated location on the one surface whose whole job is
to say where something runs.

End-of-life is a dated table, and says so
-----------------------------------------
There is no live feed here. :data:`RUNTIME_EOL` is a small hand-maintained
table with an explicit `as_of` date, and every answer it produces carries
that date. A runtime it does not list returns **unknown**, never "supported":
the honest-state rule applies to a lookup exactly as it does to a panel, and
"we have no end-of-life data for this" is a different fact from "this is
fine".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from typing import Any

#: Ecosystems the inventory recognises, and the osquery table each comes from.
#:
#: `programs` is the Windows one, and its absence from the shipped pack is
#: the recorded gap this phase closes — a Windows estate produced no rows at
#: all, which is indistinguishable from a Windows estate with nothing on it.
OSQUERY_TABLES: dict[str, str] = {
    "deb_packages": "deb",
    "rpm_packages": "rpm",
    "homebrew_packages": "homebrew",
    "programs": "windows",
}

#: SPDX `externalRefs` purl prefixes → ecosystem.
_PURL_ECOSYSTEM = re.compile(r"^pkg:([a-z0-9._-]+)/")


@dataclass(frozen=True)
class PackageRow:
    """One normalised package observation, ready to upsert."""

    source: str
    location: str
    name: str
    version: str
    ecosystem: str
    purl: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class InventoryError(ValueError):
    """A payload that cannot be normalised into package rows."""


def _clean(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def from_osquery(table: str, rows: list[dict[str, Any]], *, host: str) -> list[PackageRow]:
    """Normalise one osquery package table's results.

    Rows missing a name or a version are **dropped rather than defaulted**.
    A package recorded with an empty version answers "where does P at V run?"
    for every V, which is worse than not recording it: it would put a host on
    a patch list for a version it may not have.
    """
    ecosystem = OSQUERY_TABLES.get(table)
    if ecosystem is None:
        raise InventoryError(f"{table!r} is not a package table this inventory reads; expected one of {sorted(OSQUERY_TABLES)}")

    host_name = _clean(host)
    if not host_name:
        raise InventoryError("an osquery package row needs the host it came from")

    out: list[PackageRow] = []
    for raw in rows:
        name = _clean(raw.get("name"))
        version = _clean(raw.get("version"))
        if not name or not version:
            continue
        metadata = {k: raw[k] for k in ("arch", "source", "vendor", "publisher", "install_location") if raw.get(k)}
        out.append(
            PackageRow(
                source="osquery",
                location=host_name,
                name=name,
                version=version,
                ecosystem=ecosystem,
                metadata=metadata,
            )
        )
    return out


def from_spdx(document: dict[str, Any], *, repository: str) -> list[PackageRow]:
    """Normalise an SPDX SBOM into package rows.

    SPDX is what a code platform's dependency-graph endpoint returns. The
    document's own root element describes the repository rather than a
    dependency, so it is skipped — counting it would add a package named
    after the repo to every inventory.

    A purl is carried only when the document supplies one. Synthesising it
    would produce an identifier matched against advisories that key on a real
    one, and a wrong match here sends somebody to patch the wrong thing.
    """
    repo = _clean(repository)
    if not repo:
        raise InventoryError("an SBOM needs the repository it describes")

    sbom = document.get("sbom") if isinstance(document.get("sbom"), dict) else document
    packages = sbom.get("packages")
    if not isinstance(packages, list):
        raise InventoryError("SPDX document has no 'packages' list")

    # The element the document describes is the repository itself.
    root_ids = {
        _clean(rel.get("relatedSpdxElement"))
        for rel in sbom.get("relationships", [])
        if isinstance(rel, dict) and _clean(rel.get("relationshipType")) == "DESCRIBES"
    }

    out: list[PackageRow] = []
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        if _clean(entry.get("SPDXID")) in root_ids:
            continue
        name = _clean(entry.get("name"))
        version = _clean(entry.get("versionInfo"))
        if not name or not version:
            # NOASSERTION is SPDX's own "unknown"; recording it as a version
            # would make every version query match.
            continue
        if version.upper() == "NOASSERTION":
            continue

        purl: str | None = None
        for ref in entry.get("externalRefs", []) or []:
            if isinstance(ref, dict) and _clean(ref.get("referenceType")) == "purl":
                purl = _clean(ref.get("referenceLocator")) or None
                break

        ecosystem = "unknown"
        if purl:
            match = _PURL_ECOSYSTEM.match(purl)
            if match:
                ecosystem = match.group(1)
        elif ":" in name:
            ecosystem = name.split(":", 1)[0]

        # A code platform namespaces by ecosystem, e.g. "npm:lodash".
        bare = name.split(":", 1)[1] if ":" in name else name
        out.append(
            PackageRow(
                source="sbom",
                location=repo,
                name=bare,
                version=version,
                ecosystem=ecosystem,
                purl=purl,
            )
        )
    return out


# ── End of life ─────────────────────────────────────────────────────────────

#: When the table below was last checked against vendor announcements.
#:
#: Published with every answer. A date an operator can see is what makes an
#: "unknown" believable and a "supported" checkable; a lookup table with no
#: date quietly becomes a claim about today.
RUNTIME_EOL_AS_OF = date(2026, 11, 1)

#: Runtime major versions and the date vendor support ends.
#:
#: Deliberately small and hand-maintained. The alternative — scraping a feed
#: at query time — would make an inventory answer depend on a network call,
#: and an unreachable feed would have to answer either "unknown" (this, with
#: more moving parts) or "supported" (a fabricated reassurance).
RUNTIME_EOL: dict[str, dict[str, date]] = {
    "python": {
        "3.8": date(2024, 10, 7),
        "3.9": date(2025, 10, 31),
        "3.10": date(2026, 10, 31),
        "3.11": date(2027, 10, 31),
        "3.12": date(2028, 10, 31),
    },
    "node": {
        "16": date(2023, 9, 11),
        "18": date(2025, 4, 30),
        "20": date(2026, 4, 30),
        "22": date(2027, 4, 30),
    },
    "openjdk": {"8": date(2026, 11, 1), "11": date(2026, 10, 31), "17": date(2029, 9, 30), "21": date(2031, 9, 30)},
    "php": {"7.4": date(2022, 11, 28), "8.0": date(2023, 11, 26), "8.1": date(2025, 12, 31), "8.2": date(2026, 12, 31)},
    "ruby": {"2.7": date(2023, 3, 31), "3.0": date(2024, 4, 23), "3.1": date(2025, 3, 31), "3.2": date(2026, 3, 31)},
}

#: Package names that are the runtime, per ecosystem naming.
_RUNTIME_ALIASES: dict[str, str] = {
    "python": "python",
    "python3": "python",
    "nodejs": "node",
    "node": "node",
    "openjdk": "openjdk",
    "java": "openjdk",
    "php": "php",
    "ruby": "ruby",
}


@dataclass(frozen=True)
class EolVerdict:
    """Whether a package is a runtime past vendor support.

    ``supported`` is three-valued and the third value is the point: ``None``
    means this inventory has no end-of-life data for the package, which is a
    different fact from "it is supported".
    """

    runtime: str | None
    major: str | None
    supported: bool | None
    end_of_life: date | None
    as_of: date = RUNTIME_EOL_AS_OF
    reason: str | None = None


def _major(version: str, runtime: str) -> str | None:
    parts = re.findall(r"\d+", version)
    if not parts:
        return None
    # Python and PHP are keyed on two components, the rest on one. Keyed off
    # the runtime rather than guessed from the string, because "3.11" and
    # "3" are both plausible readings of the same version.
    if runtime in {"python", "php", "ruby"}:
        return ".".join(parts[:2]) if len(parts) >= 2 else parts[0]
    return parts[0]


def end_of_life(name: str, version: str, *, today: date | None = None) -> EolVerdict:
    """Whether ``name``@``version`` is a runtime past vendor support."""
    runtime = _RUNTIME_ALIASES.get(_clean(name).lower())
    if runtime is None:
        return EolVerdict(None, None, None, None, reason="not a runtime this inventory tracks")

    table = RUNTIME_EOL.get(runtime, {})
    major = _major(_clean(version), runtime)
    if major is None:
        return EolVerdict(runtime, None, None, None, reason=f"could not read a major version from {version!r}")

    eol = table.get(major)
    if eol is None:
        return EolVerdict(
            runtime,
            major,
            None,
            None,
            reason=f"no end-of-life date recorded for {runtime} {major} as of {RUNTIME_EOL_AS_OF.isoformat()}",
        )

    now = today or date.today()
    return EolVerdict(runtime, major, eol > now, eol)


__all__ = [
    "OSQUERY_TABLES",
    "RUNTIME_EOL",
    "RUNTIME_EOL_AS_OF",
    "EolVerdict",
    "InventoryError",
    "PackageRow",
    "end_of_life",
    "from_osquery",
    "from_spdx",
]
