"""Phase 11 — OpenAPI breaking-change detector tests.

Proves the detector flags every breaking class from an existing client's
perspective and, crucially, does NOT flag safe additive changes (a breaking-
change gate that cries wolf on every additive PR gets disabled).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import openapi_diff as od  # noqa: E402


def _spec(paths=None, schemas=None):
    return {
        "openapi": "3.1.0",
        "paths": paths or {},
        "components": {"schemas": schemas or {}},
    }


def _kinds(changes):
    return {c.kind for c in changes if c.breaking}


# ── Breaking classes ─────────────────────────────────────────────────────────


def test_removed_path_is_breaking():
    old = _spec(paths={"/a": {"get": {}}})
    new = _spec(paths={})
    assert "path_removed" in _kinds(od.diff(old, new))


def test_removed_operation_is_breaking():
    old = _spec(paths={"/a": {"get": {}, "post": {}}})
    new = _spec(paths={"/a": {"get": {}}})
    assert "operation_removed" in _kinds(od.diff(old, new))


def test_removed_schema_is_breaking():
    old = _spec(schemas={"User": {"properties": {"id": {"type": "string"}}}})
    new = _spec(schemas={})
    assert "schema_removed" in _kinds(od.diff(old, new))


def test_removed_property_is_breaking():
    old = _spec(schemas={"User": {"properties": {"id": {"type": "string"}, "email": {"type": "string"}}}})
    new = _spec(schemas={"User": {"properties": {"id": {"type": "string"}}}})
    assert "property_removed" in _kinds(od.diff(old, new))


def test_property_type_change_is_breaking():
    old = _spec(schemas={"User": {"properties": {"id": {"type": "string"}}}})
    new = _spec(schemas={"User": {"properties": {"id": {"type": "integer"}}}})
    assert "property_type_changed" in _kinds(od.diff(old, new))


def test_optional_to_required_is_breaking():
    old = _spec(schemas={"User": {"properties": {"name": {"type": "string"}}, "required": []}})
    new = _spec(schemas={"User": {"properties": {"name": {"type": "string"}}, "required": ["name"]}})
    assert "property_now_required" in _kinds(od.diff(old, new))


def test_new_required_field_on_request_schema_is_breaking():
    old = _spec(schemas={"LoginRequest": {"properties": {"email": {"type": "string"}}, "required": ["email"]}})
    new = _spec(
        schemas={"LoginRequest": {"properties": {"email": {"type": "string"}, "otp": {"type": "string"}}, "required": ["email", "otp"]}}
    )
    assert "required_property_added" in _kinds(od.diff(old, new))


def test_enum_value_removal_is_breaking():
    old = _spec(schemas={"Sev": {"properties": {"level": {"enum": ["low", "high", "critical"]}}}})
    new = _spec(schemas={"Sev": {"properties": {"level": {"enum": ["low", "high"]}}}})
    assert "enum_value_removed" in _kinds(od.diff(old, new))


def test_new_required_parameter_is_breaking():
    old = _spec(paths={"/a": {"get": {"parameters": []}}})
    new = _spec(paths={"/a": {"get": {"parameters": [{"name": "tenant", "required": True}]}}})
    assert "required_param_added" in _kinds(od.diff(old, new))


# ── Safe additive changes must NOT be flagged ────────────────────────────────


def test_added_path_is_not_breaking():
    old = _spec(paths={"/a": {"get": {}}})
    new = _spec(paths={"/a": {"get": {}}, "/b": {"get": {}}})
    assert _kinds(od.diff(old, new)) == set()


def test_added_optional_property_is_not_breaking():
    old = _spec(schemas={"User": {"properties": {"id": {"type": "string"}}, "required": ["id"]}})
    new = _spec(schemas={"User": {"properties": {"id": {"type": "string"}, "nickname": {"type": "string"}}, "required": ["id"]}})
    assert _kinds(od.diff(old, new)) == set()


def test_new_required_field_on_response_schema_is_not_breaking():
    # A response gaining a field doesn't break a consumer; only request-shaped
    # schemas tighten callers.
    old = _spec(schemas={"UserResponse": {"properties": {"id": {"type": "string"}}, "required": ["id"]}})
    new = _spec(
        schemas={"UserResponse": {"properties": {"id": {"type": "string"}, "created": {"type": "string"}}, "required": ["id", "created"]}}
    )
    assert "required_property_added" not in _kinds(od.diff(old, new))


def test_added_enum_value_is_not_breaking():
    old = _spec(schemas={"Sev": {"properties": {"level": {"enum": ["low", "high"]}}}})
    new = _spec(schemas={"Sev": {"properties": {"level": {"enum": ["low", "high", "critical"]}}}})
    assert _kinds(od.diff(old, new)) == set()


def test_ref_type_signature_change_is_breaking():
    old = _spec(schemas={"Case": {"properties": {"owner": {"$ref": "#/components/schemas/User"}}}})
    new = _spec(schemas={"Case": {"properties": {"owner": {"$ref": "#/components/schemas/Actor"}}}})
    assert "property_type_changed" in _kinds(od.diff(old, new))


def test_identical_specs_have_no_changes():
    s = _spec(paths={"/a": {"get": {}}}, schemas={"User": {"properties": {"id": {"type": "string"}}}})
    assert od.diff(s, s) == []
