"""Gateway launch contract: blank options must not override native auth."""

from __future__ import annotations

import os
import runpy
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
START = ROOT / "infra/litellm/start.py"
CONFIG = ROOT / "infra/litellm/config.yaml"


def launch(env: dict[str, str]) -> tuple[list[str], dict[str, str]]:
    captured: list[tuple[str, list[str], dict[str, str]]] = []

    def execv(path: str, args: list[str]) -> None:
        captured.append((path, args, dict(os.environ)))

    with (
        patch.dict(os.environ, env, clear=True),
        patch("sys.argv", [str(START), "--config", "/etc/litellm/config.yaml", "--port", "4000"]),
        patch("os.execv", execv),
    ):
        runpy.run_path(str(START), run_name="__main__")
    assert len(captured) == 1
    path, args, captured_env = captured[0]
    assert path == "/app/docker/prod_entrypoint.sh"
    return args, captured_env


@pytest.mark.parametrize("blank", ["", " ", "\t\n"])
def test_blank_optional_settings_are_absent_at_proxy_start(blank):
    names = runpy.run_path(str(START))["OPTIONAL_ENV"]
    _, env = launch(dict.fromkeys(names, blank))
    assert not (set(names) & env.keys())


@pytest.mark.parametrize("blank", ["", " ", "\t\n"])
def test_blank_provider_keys_preserve_explicit_empty_auth(blank):
    _, env = launch({"OPENAI_API_KEY": blank, "ANTHROPIC_API_KEY": blank})
    assert env == {"OPENAI_API_KEY": "", "ANTHROPIC_API_KEY": ""}


def test_absent_provider_keys_are_not_created():
    _, env = launch({})
    assert "OPENAI_API_KEY" not in env
    assert "ANTHROPIC_API_KEY" not in env


def test_cli_and_nonempty_settings_survive_unchanged():
    original = {
        "AISOC_LLM_API_BASE": "https://bedrock-runtime.us-east-1.amazonaws.com",
        "AWS_BEARER_TOKEN_BEDROCK": "fixture-bearer",
        "AWS_REGION": "us-east-1",
        "AWS_PROFILE": "existing-profile",
        "AWS_CONFIG_FILE": "/root/.aws/config",
        "AWS_SHARED_CREDENTIALS_FILE": "/root/.aws/credentials",
        "AWS_ACCESS_KEY_ID": "fixture-access",
        "AWS_SECRET_ACCESS_KEY": "fixture-secret",
        "AWS_SESSION_TOKEN": "fixture-session",
        "USE_DDTRACE": "true",
        "LITELLM_MASTER_KEY": "fixture-gateway",
        "OPENAI_API_KEY": "fixture-openai",
        "ANTHROPIC_API_KEY": "fixture-anthropic",
    }
    args, env = launch(original)
    assert env == original
    assert args == ["/app/docker/prod_entrypoint.sh", "--config", "/etc/litellm/config.yaml", "--port", "4000"]


@pytest.mark.parametrize("disabled", ["true", "false"])
def test_metadata_flag_is_independent_of_bearer(disabled):
    _, env = launch({"AWS_EC2_METADATA_DISABLED": disabled, "AWS_BEARER_TOKEN_BEDROCK": "fixture-bearer"})
    assert env["AWS_EC2_METADATA_DISABLED"] == disabled
    assert env["AWS_BEARER_TOKEN_BEDROCK"] == "fixture-bearer"


def test_instance_role_needs_no_explicit_keys_or_profile():
    _, env = launch({"AWS_PROFILE": "", "AWS_ACCESS_KEY_ID": "", "AWS_SECRET_ACCESS_KEY": "", "AWS_EC2_METADATA_DISABLED": "false"})
    assert env == {"AWS_EC2_METADATA_DISABLED": "false"}


def test_compose_uses_wrapper_and_passes_native_aws_configuration_only_to_gateway():
    services = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]
    gateway = services["litellm"]
    assert gateway["entrypoint"] == ["python", "/etc/litellm/start.py"]
    assert "./infra/litellm/start.py:/etc/litellm/start.py:ro" in gateway["volumes"]
    for name in runpy.run_path(str(START))["OPTIONAL_ENV"]:
        assert name in gateway["environment"], name
    assert gateway["environment"]["AWS_EC2_METADATA_DISABLED"] == "${AWS_EC2_METADATA_DISABLED:-false}"
    for service in ("api", "agents"):
        assert "AWS_BEARER_TOKEN_BEDROCK" not in services[service]["environment"]


def test_local_default_and_provider_native_auth_are_preserved():
    cfg = yaml.safe_load(CONFIG.read_text())
    for entry in cfg["model_list"]:
        assert "api_key" not in entry["litellm_params"], entry["model_name"]
        assert entry["litellm_params"]["api_base"] == "os.environ/AISOC_LLM_API_BASE"
    gateway = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]["litellm"]
    env = gateway["environment"]
    assert env["AISOC_LLM_API_BASE"] == "${AISOC_LLM_API_BASE-http://ollama:11434}"
    for tier in ("FAST", "DEEP"):
        assert "ollama_chat/llama3.2:3b-instruct-q4_K_M" in env[f"AISOC_LLM_MODEL_{tier}"]
    _, normalized = launch({"AISOC_LLM_API_BASE": "http://ollama:11434"})
    assert normalized["AISOC_LLM_API_BASE"] == "http://ollama:11434"


def test_host_profiles_are_an_explicit_readonly_mount():
    overlay = yaml.safe_load((ROOT / "infra/compose/docker-compose.aws-profile.yml").read_text())
    assert set(overlay["services"]) == {"litellm"}
    mount = overlay["services"]["litellm"]["volumes"][0]
    assert mount["target"] == "/root/.aws"
    assert mount["read_only"] is True
    assert mount["bind"]["create_host_path"] is False
