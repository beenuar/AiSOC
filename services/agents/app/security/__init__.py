"""Security primitives for the agents microservice.

Currently exposes a vendored read-path :class:`CredentialVault` and a
tenant-aware LLM credential resolver used by the explain endpoint to honour
per-tenant Bring-Your-Own-Key overrides (WS-H2).
"""
