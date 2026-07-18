"""Contract test for the LiteLLM gateway config (issue #478).

`infra/litellm/config.yaml` is the single place that maps AiSOC's logical task
aliases to real models. These assertions keep that file honest:

* the shipped alias set is exactly AiSOC's seven workloads,
* every alias resolves a `model` and a credential (env-based, never inline),
* the prometheus observability callback stays wired (the /metrics contract that
  `infra/docker/prometheus.yml` scrapes as job `aisoc-litellm`),
* the master key is read from the environment, not committed, and
* every logical role pinned in `app.llm.model_pins` has a matching gateway alias
  (subset today, tightened to equality once PR2 pins all seven roles).
"""

from __future__ import annotations

import pathlib

import yaml
from app.llm.model_pins import all_roles

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
CONFIG_PATH = REPO_ROOT / "infra" / "litellm" / "config.yaml"

# AiSOC's distinct LLM workloads (issue #478). Keep in lockstep with the alias
# table in apps/docs/docs/operations/llm-gateway.md.
EXPECTED_ALIASES = {
    "aisoc-triage",
    "aisoc-recon",
    "aisoc-investigation",
    "aisoc-copilot",
    "aisoc-summary",
    "aisoc-report",
    "aisoc-nl",
}


def _load() -> dict:
    assert CONFIG_PATH.is_file(), f"missing LiteLLM config at {CONFIG_PATH}"
    with CONFIG_PATH.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def test_config_parses_and_has_model_list():
    cfg = _load()
    assert isinstance(cfg, dict)
    assert isinstance(cfg.get("model_list"), list) and cfg["model_list"], "model_list must be a non-empty list"


def test_shipped_aliases_are_the_seven_workloads():
    cfg = _load()
    aliases = {entry["model_name"] for entry in cfg["model_list"]}
    assert aliases == EXPECTED_ALIASES, f"alias drift: {aliases ^ EXPECTED_ALIASES}"


def test_every_alias_resolves_a_model_and_env_credential():
    cfg = _load()
    for entry in cfg["model_list"]:
        params = entry.get("litellm_params", {})
        assert params.get("model"), f"{entry['model_name']} has no model"
        # A credential must be present, and if it's an inline api_key it MUST be
        # an env reference — never a committed secret. api_base-only backends
        # (local Ollama/vLLM) legitimately need no key.
        api_key = params.get("api_key")
        if api_key is not None:
            assert str(api_key).startswith("os.environ/"), f"{entry['model_name']} inlines a non-env api_key"
        assert api_key is not None or params.get("api_base"), f"{entry['model_name']} has neither api_key nor api_base"


def test_prometheus_observability_is_wired():
    cfg = _load()
    callbacks = cfg.get("litellm_settings", {}).get("callbacks", [])
    assert "prometheus" in callbacks, "prometheus callback missing — /metrics observability would be off"


def test_master_key_comes_from_env():
    cfg = _load()
    master_key = cfg.get("general_settings", {}).get("master_key", "")
    assert str(master_key).startswith("os.environ/"), "master_key must be an env reference, not a committed secret"


def test_model_pins_roles_match_gateway_aliases_exactly():
    # Ties the code's logical roles to the gateway config: every pinned role has
    # an ``aisoc-<role>`` alias in the config, and vice versa — no drift either way.
    assert {f"aisoc-{role}" for role in all_roles()} == EXPECTED_ALIASES
