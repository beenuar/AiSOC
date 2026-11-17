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


def main() -> None:
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
