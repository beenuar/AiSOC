"""Sandbox and air-gap configuration reaches the API, and absence is said out loud.

Fix pass item 5.4. See `plans/aisoc_fix_pass_plan.plan.md`.

Three defects, one theme: the deployment could not configure file analysis, and
when it was unconfigured the product did not say so.

1. **Compose passed neither `AISOC_AIRGAPPED` nor any sandbox provider
   setting to the `api` service.** Compose passes only the variables it names,
   so an operator with a CAPEv2 appliance had no way to point the product at
   it, and an operator running air-gapped had no way to tell the API.

2. **The air-gap overlay set the flag on `agents` alone.** `AISOC_AIRGAPPED`
   is read by seventeen modules across four services, including the API's own
   `airgap.py`, `llm_status.py`, `stix_taxii.py` and the sandbox registry. A
   deployment that believed it was air-gapped had one service that knew.

3. **With only the mock provider, phishing recorded nothing.**
   `_attachment_indicators` does `if not block: continue`, so an unconfigured
   deployment produced a verdict with no attachment indicator at all -- which a
   reader takes as "the attachment was checked and was clean". The honest
   output is "no analysis provider is configured", which is not a verdict.

A fourth, in the agent's tool: a 403 was reported as *"Air-gapped mode permits
local analysis providers only"* whatever the cause. A 403 is also what an
expired token, a revoked scope or a tenant-policy refusal returns, so the model
and the analyst were told the deployment's networking posture when the real
answer was an authorisation problem they could fix.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]


def _env(compose: Path, service: str) -> set[str]:
    doc = yaml.safe_load(compose.read_text(encoding="utf-8"))
    block = (doc.get("services") or {}).get(service) or {}
    env = block.get("environment") or {}
    return set(env) if isinstance(env, dict) else {e.split("=", 1)[0] for e in env}


class TestTheDeploymentCanConfigureFileAnalysis:
    def test_compose_passes_the_airgap_flag_to_the_api(self) -> None:
        names = _env(REPO_ROOT / "docker-compose.yml", "api")

        assert "AISOC_AIRGAPPED" in names, (
            "docker-compose.yml does not pass AISOC_AIRGAPPED to the api service, so an "
            "air-gapped deployment has no way to tell the service that reads it in nine modules"
        )

    @pytest.mark.parametrize(
        "variable",
        ["AISOC_CAPEV2_BASE_URL", "MALWAREANALYZER_BASE_URL", "MALWAREANALYZER_API_KEY"],
    )
    def test_compose_passes_the_sandbox_provider_settings(self, variable: str) -> None:
        """Without these an operator with a real sandbox cannot point the
        product at it, and the registry falls back to the mock, which knows
        nothing."""
        names = _env(REPO_ROOT / "docker-compose.yml", "api")

        assert variable in names, f"docker-compose.yml does not pass {variable} to the api service"

    def test_the_airgap_overlay_sets_the_flag_on_every_service_that_reads_it(self) -> None:
        overlay = REPO_ROOT / "infra" / "compose" / "docker-compose.airgap.yml"
        doc = yaml.safe_load(overlay.read_text(encoding="utf-8"))
        services = doc.get("services") or {}

        carrying = {name for name, block in services.items() if "AISOC_AIRGAPPED" in ((block or {}).get("environment") or {})}

        # The API reads it in `core/airgap.py`, `llm_status.py`, `stix_taxii.py`,
        # `translation.py`, the sandbox registry and three runners.
        assert "api" in carrying, (
            f"the air-gap overlay sets AISOC_AIRGAPPED on {sorted(carrying)} only; the API reads it "
            "in nine modules and would not know the deployment is air-gapped"
        )


class TestAnUnconfiguredDeploymentSaysSo:
    def test_an_empty_analysis_block_is_recorded_not_skipped(self) -> None:
        """`if not block: continue` produced a verdict with no attachment
        indicator, which reads as "checked and clean" rather than "not
        checked"."""
        source = (REPO_ROOT / "services" / "api" / "app" / "api" / "v1" / "endpoints" / "phishing.py").read_text(encoding="utf-8")

        assert "if not block:\n            continue" not in source, (
            "phishing still skips an empty analysis block, so an unconfigured deployment "
            "returns a phishing verdict that looks like the attachment was cleared"
        )


class TestTheAgentToolDoesNotGuessWhyItWasRefused:
    def test_a_403_is_not_reported_as_air_gap_mode(self) -> None:
        source = (REPO_ROOT / "services" / "agents" / "app" / "tools" / "sandbox.py").read_text(encoding="utf-8")

        offending = "Air-gapped mode permits local analysis providers only, and none is configured."
        assert offending not in source, (
            "a 403 is still reported as air-gap mode. A 403 is also an expired token, a revoked "
            "scope or a tenant-policy refusal, and naming the wrong one sends an analyst to debug "
            "networking when the fix is a credential"
        )
