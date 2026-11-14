"""Retro-hunts can be switched on by a deployment and by a tenant.

Fix pass item 5.1. See `plans/aisoc_fix_pass_plan.plan.md`.

What was wrong
--------------
Two halves of one switch, and neither could be reached.

The *operator* half is `RETRO_HUNT_ENABLED`, which `main.py` consults to decide
whether to start `retro_hunt_consumer.run_forever`. It appeared in **no compose
file and no `.env.example`**, and compose passes only the variables it names --
so on every `make up` deployment the consumer did not start and no amount of
setting the variable in a shell could change that.

The *tenant* half is `retro_hunt_settings.enabled`, which migration 070 creates
with `DEFAULT FALSE` under a comment reading "Off until a tenant asks". There
was no route and no console surface through which a tenant could ask, so the
only way to turn it on was an UPDATE against the database by hand.

A feature that needs a direct SQL statement to enable is not a feature a
customer has.

What this file asserts
----------------------
Both halves, from the artefacts a deployment actually reads: the compose file
and the API's own route table.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]


def _compose_service(name: str) -> dict:
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    service = compose["services"].get(name)
    assert service is not None, f"docker-compose.yml has no `{name}` service"
    return service


class TestTheOperatorHalf:
    def test_compose_passes_the_switch_through_to_the_api(self) -> None:
        """Compose passes only what it names, so an unnamed variable is
        unreachable however the host environment is set."""
        env = _compose_service("api").get("environment") or {}
        names = set(env) if isinstance(env, dict) else {entry.split("=", 1)[0] for entry in env}

        assert "RETRO_HUNT_ENABLED" in names, (
            "docker-compose.yml does not pass RETRO_HUNT_ENABLED to the api service, "
            "so the retro-hunt consumer can never start on a compose deployment"
        )

    def test_env_example_documents_it(self) -> None:
        """`.env.example` is where an operator looks for what can be set. A
        switch absent from it is a switch nobody knows exists."""
        text = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")

        assert "RETRO_HUNT_ENABLED" in text, ".env.example does not mention RETRO_HUNT_ENABLED"

    def test_it_defaults_off(self) -> None:
        """The negative control. A sweep over a tenant's history is a cost and
        a privacy decision, so the fix must not turn it on for everyone."""
        env = _compose_service("api").get("environment") or {}
        raw = env["RETRO_HUNT_ENABLED"] if isinstance(env, dict) else ""

        assert ":-false}" in str(raw) or str(raw).strip() in {"false", "${RETRO_HUNT_ENABLED:-false}"}, (
            f"RETRO_HUNT_ENABLED defaults to {raw!r}; it must default off"
        )


class TestTheTenantHalf:
    @pytest.fixture(scope="class")
    def paths(self) -> dict:
        from app.main import app

        return app.openapi()["paths"]

    def test_a_tenant_can_read_its_retro_hunt_settings(self, paths: dict) -> None:
        assert "/api/v1/retro-hunts/settings" in paths, (
            "no route exposes retro_hunt_settings, so a tenant's only way to opt in is an UPDATE against the database by hand"
        )
        assert "get" in paths["/api/v1/retro-hunts/settings"]

    def test_a_tenant_can_change_them(self, paths: dict) -> None:
        operations = paths.get("/api/v1/retro-hunts/settings", {})

        assert "put" in operations, "the settings route is read-only, so opting in is still impossible"
