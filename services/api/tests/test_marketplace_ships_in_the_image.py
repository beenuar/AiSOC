"""The marketplace must work where the API actually runs.

Discussion #374 reported a 503 when downloading a plugin from the marketplace
on an on-premise Docker Compose deployment. It reproduced against the
published image on every release since the endpoint was written, for two
reasons that stack:

  1. `_resolve_index_path()` looked in four places, all of them outside the
     API's Docker build context. The image is built from `services/api`, so
     `COPY . .` never saw the repository-root `marketplace/` directory and the
     index did not exist at runtime — a flat 503 on browse *and* install.

  2. Even with an index, `install` hashed the item's file under `detections/`,
     `playbooks/` or `plugins/`. The image contains none of those trees, so it
     would then have 404'd on a file it could never ship.

Neither was visible to a test suite that runs from a source checkout, where
all six paths resolve. These assertions are written to fail there too: they
simulate the container by pointing the resolver at the packaged copy and
hiding the content trees, rather than by requiring Docker.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from app.api.v1.endpoints import marketplace
from fastapi import HTTPException

REPO_ROOT = Path(__file__).resolve().parents[3]


class TestTheIndexTravelsWithTheImage:
    def test_the_packaged_copy_exists(self) -> None:
        """Without this the published image has no catalogue at all."""
        assert marketplace._PACKAGED_INDEX.is_file(), (
            f"{marketplace._PACKAGED_INDEX} is missing — the API image is built from "
            "`services/api`, so this is the only copy that travels with it. "
            "Run `pnpm marketplace:sync`."
        )

    def test_it_is_inside_the_build_context(self) -> None:
        """A path outside `services/api` is one `COPY . .` cannot see.

        This is the assertion that would have caught the original defect: all
        four original candidates were outside it, and nothing said so.
        """
        context = REPO_ROOT / "services" / "api"
        assert marketplace._PACKAGED_INDEX.resolve().is_relative_to(context.resolve())

    def test_it_matches_the_generated_original(self) -> None:
        original = REPO_ROOT / "marketplace" / "index.json"
        assert hashlib.sha256(marketplace._PACKAGED_INDEX.read_bytes()).hexdigest() == (
            hashlib.sha256(original.read_bytes()).hexdigest()
        ), "the packaged index differs from the generated one; run `pnpm marketplace:sync`"

    def test_the_resolver_finds_it_when_nothing_else_is_there(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Simulates the container: only the packaged copy exists."""
        monkeypatch.setattr(marketplace, "_CANDIDATE_PATHS", [marketplace._PACKAGED_INDEX])
        assert marketplace._resolve_index_path() == marketplace._PACKAGED_INDEX


class TestInstallDoesNotNeedTheContentTrees:
    """The image ships no `detections/`, `playbooks/` or `plugins/`."""

    @pytest.fixture
    def item(self) -> dict:
        index = json.loads((REPO_ROOT / "marketplace" / "index.json").read_text(encoding="utf-8"))
        wazuh = [i for i in index["items"] if i["id"] == "wazuh"]
        assert wazuh, "the Wazuh connector is no longer in the marketplace index"
        return wazuh[0]

    def test_every_item_carries_a_digest(self) -> None:
        index = json.loads((REPO_ROOT / "marketplace" / "index.json").read_text(encoding="utf-8"))
        missing = [i.get("id") for i in index["items"] if not i.get("sha256")]
        assert not missing, f"{len(missing)} item(s) would 404 on install from a container: {missing[:5]}"

    def test_the_recorded_digest_is_the_file_it_describes(self, item: dict) -> None:
        """A wrong digest is worse than none: it reports success for content
        nobody verified."""
        on_disk = hashlib.sha256((REPO_ROOT / item["path"]).read_bytes()).hexdigest()
        assert item["sha256"] == on_disk

    def test_install_resolves_a_digest_with_no_file_present(self, item: dict, monkeypatch: pytest.MonkeyPatch) -> None:
        """The container case. `_resolve_item_path` raises 404 there, and the
        index digest is what makes the install succeed anyway."""

        def _no_file(_item: dict) -> Path:
            raise HTTPException(status_code=404, detail="Marketplace item file missing on disk")

        monkeypatch.setattr(marketplace, "_resolve_item_path", _no_file)
        assert marketplace._content_sha256(item) == item["sha256"]

    def test_it_still_prefers_the_file_in_a_checkout(self, item: dict) -> None:
        """So a contributor editing a rule gets the digest of what they edited,
        not the one the index was generated from."""
        assert marketplace._content_sha256(item) == (hashlib.sha256((REPO_ROOT / item["path"]).read_bytes()).hexdigest())

    def test_an_item_with_neither_file_nor_digest_still_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The fallback must not invent a hash for something that does not exist.

        Without this, a malformed index entry would install cleanly and report
        a digest for content nobody has.
        """

        def _no_file(_item: dict) -> Path:
            raise HTTPException(status_code=404, detail="missing")

        monkeypatch.setattr(marketplace, "_resolve_item_path", _no_file)
        with pytest.raises(HTTPException):
            marketplace._content_sha256({"id": "ghost", "path": "detections/nope.yaml"})
