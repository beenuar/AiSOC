"""Package-level inventory: "where does package P at version V run?"

Wave 2, Phase 5.4.

`assets` is host-level and cannot answer that. The osquery baseline pack
already enumerated Debian, RPM and Homebrew packages, did **not** query the
Windows `programs` table, and nothing consumed any of the rows.

The properties under test are all about refusing to answer rather than
answering wrongly, because every wrong answer on this surface sends somebody
to patch something:

* a package with no version is **dropped**, not defaulted — an empty version
  matches every version query;
* SPDX's own `NOASSERTION` is treated as unknown for the same reason;
* a purl is carried only when the source supplies one, because a synthesised
  identifier gets matched against advisories keyed on a real one;
* an SBOM package has no host, and inventing one would be a fabricated
  location on the surface whose entire job is to say where something runs;
* end-of-life returns **unknown** for a runtime it has no data for, never
  "supported", and every answer carries the date the table was checked.
"""

from __future__ import annotations

from datetime import date

import pytest
from app.services.software_inventory import (
    OSQUERY_TABLES,
    RUNTIME_EOL_AS_OF,
    InventoryError,
    end_of_life,
    from_osquery,
    from_spdx,
)

# ── osquery ─────────────────────────────────────────────────────────────────


def test_the_windows_table_is_one_the_inventory_reads():
    """The recorded gap: a Windows estate produced no rows at all."""
    assert OSQUERY_TABLES["programs"] == "windows"


def test_debian_packages_normalise():
    rows = from_osquery(
        "deb_packages",
        [{"name": "openssl", "version": "3.0.11-1", "arch": "amd64"}],
        host="web-01",
    )
    assert len(rows) == 1
    assert rows[0].source == "osquery"
    assert rows[0].location == "web-01"
    assert rows[0].ecosystem == "deb"
    assert rows[0].metadata["arch"] == "amd64"


def test_windows_programs_normalise():
    rows = from_osquery(
        "programs",
        [{"name": "7-Zip", "version": "23.01", "publisher": "Igor Pavlov"}],
        host="DESKTOP-7",
    )
    assert rows[0].ecosystem == "windows"
    assert rows[0].metadata["publisher"] == "Igor Pavlov"


def test_a_package_with_no_version_is_dropped_not_defaulted():
    """An empty version matches every version query.

    Recording it would put a host on a patch list for a version it may not
    have, which is worse than not recording the package at all.
    """
    rows = from_osquery(
        "deb_packages",
        [{"name": "openssl", "version": ""}, {"name": "", "version": "1.0"}, {"name": "curl", "version": "8.4.0"}],
        host="web-01",
    )
    assert [r.name for r in rows] == ["curl"]


def test_an_unknown_table_is_refused_with_the_vocabulary():
    with pytest.raises(InventoryError, match="not a package table"):
        from_osquery("processes", [], host="web-01")


def test_a_row_with_no_host_is_refused():
    """The host *is* the answer this table exists to give."""
    with pytest.raises(InventoryError, match="needs the host"):
        from_osquery("deb_packages", [{"name": "curl", "version": "8"}], host="  ")


# ── SBOM ────────────────────────────────────────────────────────────────────


SPDX = {
    "sbom": {
        "SPDXID": "SPDXRef-DOCUMENT",
        "packages": [
            {"SPDXID": "SPDXRef-Repo", "name": "acme/api", "versionInfo": "1.0"},
            {
                "SPDXID": "SPDXRef-1",
                "name": "npm:lodash",
                "versionInfo": "4.17.21",
                "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.21"}],
            },
            {"SPDXID": "SPDXRef-2", "name": "pip:requests", "versionInfo": "NOASSERTION"},
            {"SPDXID": "SPDXRef-3", "name": "pip:urllib3", "versionInfo": "2.0.7"},
        ],
        "relationships": [
            {"relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Repo"},
        ],
    }
}


def test_sbom_packages_normalise_and_carry_their_purl():
    rows = from_spdx(SPDX, repository="acme/api")
    by_name = {r.name: r for r in rows}
    assert by_name["lodash"].purl == "pkg:npm/lodash@4.17.21"
    assert by_name["lodash"].ecosystem == "npm"
    assert by_name["lodash"].source == "sbom"
    assert by_name["lodash"].location == "acme/api"


def test_the_repository_itself_is_not_counted_as_a_dependency():
    """Otherwise every inventory gains a package named after the repo."""
    names = {r.name for r in from_spdx(SPDX, repository="acme/api")}
    assert "acme/api" not in names


def test_noassertion_is_not_recorded_as_a_version():
    """SPDX's own "unknown" would otherwise match every version query."""
    names = {r.name for r in from_spdx(SPDX, repository="acme/api")}
    assert "requests" not in names
    assert "urllib3" in names


def test_a_purl_is_never_synthesised():
    """A made-up identifier gets matched against advisories keyed on a real one."""
    rows = from_spdx(SPDX, repository="acme/api")
    urllib3 = next(r for r in rows if r.name == "urllib3")
    assert urllib3.purl is None
    # The ecosystem is still readable from the platform's namespacing.
    assert urllib3.ecosystem == "pip"


def test_an_sbom_row_has_no_host():
    """Inventing one would be a fabricated location."""
    rows = from_spdx(SPDX, repository="acme/api")
    assert all(r.source == "sbom" for r in rows)
    # `location` is the repository, which is the true answer to "where".
    assert {r.location for r in rows} == {"acme/api"}


def test_a_document_without_packages_is_refused():
    with pytest.raises(InventoryError, match="no 'packages' list"):
        from_spdx({"sbom": {}}, repository="acme/api")


# ── End of life ─────────────────────────────────────────────────────────────


def test_an_unsupported_runtime_is_reported_with_its_date():
    verdict = end_of_life("python", "3.8.18", today=date(2026, 11, 1))
    assert verdict.runtime == "python"
    assert verdict.major == "3.8"
    assert verdict.supported is False
    assert verdict.end_of_life == date(2024, 10, 7)
    assert verdict.as_of == RUNTIME_EOL_AS_OF


def test_a_supported_runtime_is_reported_as_supported():
    verdict = end_of_life("nodejs", "22.9.0", today=date(2026, 11, 1))
    assert verdict.runtime == "node"
    assert verdict.supported is True


def test_a_runtime_with_no_recorded_date_is_unknown_not_supported():
    """The honest-state rule, applied to a lookup.

    "We have no end-of-life data for this" and "this is fine" are different
    facts, and answering the second from the first is how somebody stops
    looking at a runtime nobody has checked.
    """
    verdict = end_of_life("python", "3.99.0", today=date(2026, 11, 1))
    assert verdict.supported is None
    assert "no end-of-life date recorded" in (verdict.reason or "")
    assert RUNTIME_EOL_AS_OF.isoformat() in (verdict.reason or "")


def test_a_package_that_is_not_a_runtime_is_unknown():
    verdict = end_of_life("lodash", "4.17.21")
    assert verdict.supported is None
    assert verdict.runtime is None


def test_a_version_string_with_no_digits_is_unknown_not_a_guess():
    verdict = end_of_life("python", "unstable")
    assert verdict.supported is None
    assert "could not read a major version" in (verdict.reason or "")


def test_major_version_is_read_per_runtime_rather_than_guessed():
    """ "3" and "3.11" are both plausible readings of one version string."""
    assert end_of_life("python", "3.11.6").major == "3.11"
    assert end_of_life("nodejs", "20.11.1").major == "20"


def test_every_verdict_carries_the_date_the_table_was_checked():
    """A lookup table with no date quietly becomes a claim about today."""
    for name, version in (("python", "3.8"), ("nodejs", "22"), ("lodash", "4"), ("python", "9.9")):
        assert end_of_life(name, version).as_of == RUNTIME_EOL_AS_OF
