"""
Contract tests for connector schemas.

These run against every connector registered in
``app.connectors.CONNECTOR_REGISTRY`` so a new connector cannot land
without a well-formed schema.
"""

from __future__ import annotations

import pytest
from app.connectors import CONNECTOR_REGISTRY, list_connector_schemas
from app.connectors.base import BaseConnector, ConnectorSchema, Field

ALLOWED_CATEGORIES = {"siem", "edr", "cloud", "iam", "saas", "audit", "vcs", "ndr"}
ALLOWED_FIELD_TYPES = {"string", "secret", "select", "textarea", "boolean", "number"}


@pytest.fixture(scope="module")
def registry() -> dict[str, type[BaseConnector]]:
    assert CONNECTOR_REGISTRY, "registry is empty — no connectors registered"
    return CONNECTOR_REGISTRY


def test_registry_has_expected_baseline_connectors(registry):
    # These five existed before the housekeeping pass; protect against accidental removal.
    for required in (
        "crowdstrike",
        "splunk",
        "aws_security_hub",
        "okta",
        "microsoft_sentinel",
    ):
        assert required in registry, f"baseline connector '{required}' missing from registry"


def test_every_connector_returns_a_schema(registry):
    for connector_id, cls in registry.items():
        schema = cls.schema()
        assert isinstance(schema, ConnectorSchema), f"{cls.__name__}.schema() must return ConnectorSchema, got {type(schema).__name__}"
        assert schema.connector_id == connector_id, (
            f"{cls.__name__}.schema().connector_id ({schema.connector_id!r}) does not match registry key ({connector_id!r})"
        )


def test_schema_metadata_is_well_formed(registry):
    for cls in registry.values():
        schema = cls.schema()
        assert schema.connector_name, f"{cls.__name__}: connector_name is empty"
        assert schema.category in ALLOWED_CATEGORIES, f"{cls.__name__}: category {schema.category!r} not in {ALLOWED_CATEGORIES}"
        assert schema.description, f"{cls.__name__}: description is empty"
        assert schema.fields, f"{cls.__name__}: at least one field is required"


def test_schema_fields_are_well_formed(registry):
    for cls in registry.values():
        schema = cls.schema()
        seen_names: set[str] = set()
        for field in schema.fields:
            assert isinstance(field, Field)
            assert field.name, f"{cls.__name__}: field with empty name"
            assert field.name not in seen_names, f"{cls.__name__}: duplicate field name {field.name!r}"
            seen_names.add(field.name)
            assert field.label, f"{cls.__name__}.{field.name}: label is empty"
            assert field.type in ALLOWED_FIELD_TYPES, f"{cls.__name__}.{field.name}: unknown field type {field.type!r}"
            if field.type == "select":
                assert field.options, f"{cls.__name__}.{field.name}: select fields require options"


def test_schemas_are_json_serialisable():
    import json

    payload = list_connector_schemas()
    # Will raise if any value can't be serialised.
    json.dumps(payload)
    assert isinstance(payload, list)
    assert all(isinstance(entry, dict) for entry in payload)


def test_schema_to_dict_round_trips_required_keys(registry):
    for cls in registry.values():
        d = cls.schema().to_dict()
        for key in ("connector_id", "connector_name", "category", "description", "fields"):
            assert key in d, f"{cls.__name__}: schema dict missing '{key}'"
        assert isinstance(d["fields"], list)


def test_secret_fields_are_marked_secret(registry):
    """Belt-and-braces check: anything whose name screams 'credential' should
    be a secret field so the wizard renders a masked input and the vault
    encrypts it."""
    suspicious = ("password", "secret", "token", "private_key", "api_key")
    for cls in registry.values():
        for field in cls.schema().fields:
            if any(s in field.name.lower() for s in suspicious):
                assert field.type == "secret", (
                    f"{cls.__name__}.{field.name}: looks like a credential but type is {field.type!r}, expected 'secret'"
                )
