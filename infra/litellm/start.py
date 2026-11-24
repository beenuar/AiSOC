"""Normalize optional environment values before the pinned LiteLLM entrypoint.

Compose interpolates optional values as empty strings. LiteLLM distinguishes
empty from absent for Bedrock endpoints, bearer tokens and AWS profiles.
Keep the SDK's native credential/region chain by removing only blank values.
Provider keys retain explicit empty strings for keyless compatible endpoints;
normalize whitespace-only keys to that same value instead of unsetting them.
No credentials are copied into the YAML or printed.
"""

from __future__ import annotations

import os
import sys

OPTIONAL_ENV = (
    "AISOC_LLM_API_BASE",
    "AWS_BEARER_TOKEN_BEDROCK",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_PROFILE_NAME",
    "AWS_REGION",
    "AWS_REGION_NAME",
    "AWS_DEFAULT_REGION",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_EC2_METADATA_DISABLED",
)


MODEL_TIERS = {
    "AISOC_LLM_MODEL_TRIAGE": "AISOC_LLM_MODEL_FAST",
    "AISOC_LLM_MODEL_RECON": "AISOC_LLM_MODEL_FAST",
    "AISOC_LLM_MODEL_INVESTIGATION": "AISOC_LLM_MODEL_DEEP",
    "AISOC_LLM_MODEL_COPILOT": "AISOC_LLM_MODEL_FAST",
    "AISOC_LLM_MODEL_SUMMARY": "AISOC_LLM_MODEL_FAST",
    "AISOC_LLM_MODEL_REPORT": "AISOC_LLM_MODEL_DEEP",
    "AISOC_LLM_MODEL_NL": "AISOC_LLM_MODEL_FAST",
    "AISOC_LLM_MODEL_HUNT": "AISOC_LLM_MODEL_FAST",
    "AISOC_LLM_MODEL_DETECTION": "AISOC_LLM_MODEL_FAST",
}


# These provider routes already have documented deployments in this repository.
# Match by full provider prefix: an arbitrary or bare model name is not proof
# that changing it would preserve provider routing.
MODEL_PROVIDERS = frozenset({"anthropic", "bedrock", "ollama", "ollama_chat", "openai"})


def _provider(model: str) -> str | None:
    prefix, slash, name = model.partition("/")
    if slash and name.strip() and prefix in MODEL_PROVIDERS:
        return prefix
    return None


def main() -> None:
    # Read the effective container environment after Compose overlays. Nested
    # host-side interpolation would miss the GPU and host-LLM tier defaults.
    for name, tier in MODEL_TIERS.items():
        override = os.environ.get(name, "").strip()
        inherited = os.environ.get(tier)
        provider = _provider(override)
        if override and inherited is not None and (override == inherited or (provider is not None and provider == _provider(inherited))):
            os.environ[name] = override
            continue
        if override:
            # Never print the operator's model string or endpoint.
            print(f"Ignoring {name}: use the same recognized provider prefix as {tier}.", file=sys.stderr)
        if inherited is not None:
            os.environ[name] = inherited
        else:
            os.environ.pop(name, None)
    for name in OPTIONAL_ENV:
        if name in os.environ and not os.environ[name].strip():
            del os.environ[name]
    # Provider clients accept an explicit empty key for keyless endpoints but
    # reject an absent key. Do not turn a working custom endpoint into an error.
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        if name in os.environ and not os.environ[name].strip():
            os.environ[name] = ""
    # Preserve the image's own CLI / optional tracing setup and signal handling.
    entrypoint = "/app/docker/prod_entrypoint.sh"
    os.execv(entrypoint, [entrypoint, *sys.argv[1:]])


if __name__ == "__main__":
    main()
