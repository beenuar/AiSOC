"""One live call to OrcaRouter, skipped unless a key is configured.

Everything else in this suite is hermetic. This pair exists because a catalog
parser and a PKCE exchange can both be right while the origin, the auth header
or the model-naming convention is wrong — the only way to know is to ask.

The key is read from the environment and never written anywhere: no assertion
prints it, no failure detail can contain it, and the fallback-seed ids are not
what this test selects from. It runs the same ``fetch_catalog`` and
``probe_credential`` paths the settings panel uses, so a pass here means the
provider is wired end to end, not that three HTTP calls happen to work.

Enable with ``ORCAROUTER_API_KEY`` in the environment (CI leaves it unset).
"""

from __future__ import annotations

import os

import pytest
from app.services import orcarouter
from app.services.llm_credential_probe import probe_credential

pytestmark = pytest.mark.skipif(
    not os.environ.get("ORCAROUTER_API_KEY"),
    reason="live OrcaRouter credentials are not configured",
)


async def test_live_catalog_answers_at_the_inference_origin() -> None:
    catalog = await orcarouter.fetch_catalog(os.environ["ORCAROUTER_API_KEY"])
    assert catalog.source == "live", catalog.detail
    assert catalog.models, "the live catalog returned no chat-capable model"
    # A live answer is the provider's, not our constant: at least one entry has
    # to be something the seed does not contain.
    seed_ids = {entry["id"] for entry in orcarouter.VERIFIED_CHAT_SEED}
    assert not {m.id for m in catalog.models} <= seed_ids


async def test_live_completion_through_the_configured_provider_path() -> None:
    key = os.environ["ORCAROUTER_API_KEY"]
    catalog = await orcarouter.fetch_catalog(key)
    assert catalog.source == "live", catalog.detail

    # Prefer a dedicated cyber model when this account is entitled to one;
    # otherwise complete against whatever the account's own catalog offers.
    advertised = [m.id for m in catalog.models]
    preferred = [model for model in advertised if model.startswith("orcacyber-")]
    candidates = preferred or advertised[:1]

    refusal = None
    for model in candidates:
        result = await probe_credential(
            provider=orcarouter.API_KEY_PROVIDER,
            base_url=orcarouter.api_base(),
            model=model,
            api_key=key,
        )
        if result.outcome == "ok":
            return
        refusal = result
        # 403/404 on a preferred model means this account is not entitled to
        # it, not that the credential is broken; the next candidate decides.
        if result.status_code not in (403, 404):
            break

    assert refusal is not None
    pytest.fail(f"live completion failed: {refusal.outcome}: {refusal.detail}")
