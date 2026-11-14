"""The alert row names the object that changed, not the service that changed it.

Issue #1718, reported by gdncomm-dika-wibowo and measured across ten alerts
from one Entra tenant (414 events): none carried the affected account, group
or device as an entity. ``affected_users`` held the actor — and for a
directory audit the actor is routinely a Microsoft service, so an analyst
opening "Add member to group" saw ``["Microsoft Teams Services"]`` and
neither the member added nor the group.

Four layers had to move for one column to change, which is why a fix in any
one of them reaches nothing:

* the connector lifts the target out of ``targetResources``
  (``services/connectors/tests/connectors/test_entra_target_fields_issue_1718.py``);
* the ingest normalizer maps it onto an OCSF slot
  (``services/ingest/internal/normalizer/issue_1718_test.go``);
* the promoter and the detection-alert builder carry it onto the alert;
* ``_affected``/``_entities`` here read it.

This file drives the last two against the **real** promoter, the **real**
``DetectionEngine.build_alert`` and the **real** sink helpers. The OCSF
below is what the Go test above pins ``Normalize()`` produces for the
connector envelope the connector test pins ``normalize()`` produces. The
three are separate files because ``services/connectors`` and
``services/fusion`` both name their top-level package ``app`` — importing
one inside the other's interpreter shadows it — and because the middle
layer is Go.

Not exercised against a live Entra tenant: the shapes are transcribed from
the report and from Graph's published schema.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from app.models.alert import FusedAlert, FusionDecision, RawAlert
from app.services.alert_sink import _affected, _entities
from app.services.detection_engine import DetectionEngine, DetectionHit, _load_ruleset
from app.services.detection_matcher import matches
from app.services.promoter import promote_normalized_event

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")


def _ocsf(
    *,
    actor: str,
    severity_id: int = 1,
    severity: str = "info",
    target_user: str | None = None,
    device_name: str | None = None,
    envelope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """An Entra directory audit as ``services/ingest`` publishes it.

    Class 3002 (Authentication, category 3) is what
    ``ocsfClassForConnector("azure_entra")`` returns, and ``raw_data`` is the
    connector envelope JSON-encoded, which is how ingest writes it.
    """
    ocsf: dict[str, Any] = {
        "class_uid": 3002,
        "class_name": "Authentication",
        "category_uid": 3,
        "activity_id": 1,
        "severity_id": severity_id,
        "severity": severity,
        "time": "2026-11-03T09:12:44Z",
        "message": "Add member to group",
        "actor": {"user": {"name": actor}},
        "metadata": {"product": {"name": "azure_entra", "vendor_name": "azure_entra"}, "tenant_uid": str(TENANT)},
        "tenant_uid": str(TENANT),
        "raw_data": json.dumps(envelope or {}),
    }
    if target_user is not None:
        ocsf["target_user"] = {"name": target_user}
    if device_name is not None:
        ocsf["device"] = {"name": device_name}
    return ocsf


GROUP_ADD_OCSF = _ocsf(
    actor="user-c@example.com",
    target_user="user-b@example.com",
    envelope={
        "source": "azure_entra",
        "activity": "Add member to group",
        "actor": "user-c@example.com",
        "actor_display_name": "Microsoft Teams Services",
        "initiator_type": "user",
        "target_user": "user-b@example.com",
        "target_group_name": "Group A",
        "modified_properties": {"Group.DisplayName": "Group A"},
    },
)

DEVICE_UPDATE_OCSF = _ocsf(
    actor="Intune Compliance Client Prod",
    device_name="HOST-01",
    envelope={
        "source": "azure_entra",
        "activity": "Update device",
        "actor": "Intune Compliance Client Prod",
        "initiator_type": "app",
        "target_hostname": "HOST-01",
        "target_device_os": "Windows",
    },
)


def _message(ocsf: dict[str, Any]) -> dict[str, Any]:
    return {"tenant_id": str(TENANT), "ocsf_event": ocsf, "connector_id": str(uuid.uuid4())}


def _fused(alert: RawAlert) -> FusedAlert:
    alert.id = alert.deterministic_id()
    return FusedAlert(id=alert.id, tenant_id=TENANT, fusion_decision=FusionDecision.NEW_ALERT, alert=alert)


def _detection_alert(ocsf: dict[str, Any]) -> RawAlert:
    """The path the reported alerts actually took.

    An Entra directory audit is OCSF category 3 at info severity, so
    ``should_promote`` does not promote it; it becomes an alert when a
    detection rule fires. ``build_alert`` is that production path.
    """
    hit = DetectionHit(
        rule_id="det-identity-210",
        name="Entra User Password Reset By An Administrator",
        severity="high",
        category="identity",
        mitre=["t1098"],
    )
    alert = DetectionEngine.build_alert(DetectionEngine.__new__(DetectionEngine), _message(ocsf), hit)
    assert alert is not None
    return alert


# ─── Cause 1: the affected user is an entity ────────────────────────────


def test_detection_alert_names_the_member_added_not_the_client() -> None:
    fused = _fused(_detection_alert(GROUP_ADD_OCSF))

    hosts, users, _ips = _affected(fused)

    assert "user-b@example.com" in users, "the member added must be an affected user"
    assert "user-c@example.com" in users, "the human who did it is still an affected user"
    assert hosts == []


def test_entities_and_affected_users_agree() -> None:
    """They are derived from one source, so the row cannot disagree with itself."""
    fused = _fused(_detection_alert(GROUP_ADD_OCSF))

    _hosts, users, _ips = _affected(fused)
    entity_users = [e["value"] for e in _entities(fused) if e["type"] == "user"]

    assert sorted(entity_users) == sorted(users)


def test_promoted_alert_carries_the_target_too() -> None:
    """The other way an Entra audit becomes an alert: vendor severity."""
    alert = promote_normalized_event(
        _message(_ocsf(actor="user-c@example.com", target_user="user-b@example.com", severity_id=4, severity="high"))
    )
    assert alert is not None

    _hosts, users, _ips = _affected(_fused(alert))

    assert "user-b@example.com" in users


def test_a_target_equal_to_the_actor_is_listed_once() -> None:
    fused = _fused(_detection_alert(_ocsf(actor="user-a@example.com", target_user="user-a@example.com")))

    _hosts, users, _ips = _affected(fused)

    assert users == ["user-a@example.com"]


def test_an_alert_with_no_target_is_unchanged() -> None:
    fused = _fused(_detection_alert(_ocsf(actor="user-c@example.com")))

    hosts, users, ips = _affected(fused)

    assert users == ["user-c@example.com"]
    assert hosts == []
    assert ips == []


# ─── Cause 5: a device target is a host ─────────────────────────────────


def test_device_update_names_the_device_as_the_affected_host() -> None:
    alert = _detection_alert(DEVICE_UPDATE_OCSF)
    hosts, users, _ips = _affected(_fused(alert))

    assert hosts == ["HOST-01"]
    assert users == ["Intune Compliance Client Prod"]
    assert {"type": "host", "value": "HOST-01"} in _entities(_fused(alert))


# ─── Cause 6: a self-service reset is not an administrator's ────────────


def _shipped_rule(rule_id: str) -> dict[str, Any]:
    for rule in _load_ruleset():
        if rule["id"] == rule_id:
            return rule
    raise AssertionError(f"{rule_id} is not in the shipped ruleset")


def _match_namespace(envelope: dict[str, Any]) -> dict[str, Any]:
    """What the engine really hands the matcher for a connector envelope."""
    return DetectionEngine._raw_fields({"raw_data": json.dumps(envelope)})


#: `AzureEntraConnector.normalize()` output for the two resets, trimmed to
#: the keys the rule reads. The connector test pins the full mapping against
#: the real class, so a connector change that stops emitting `initiator_type`
#: reds that file rather than silently passing this one.
ADMIN_RESET_ENVELOPE = {
    "source": "azure_entra",
    "activity": "Reset user password",
    "actor": "helpdesk@example.com",
    "initiator_type": "user",
    "target_user": "user-a@example.com",
}
SELF_SERVICE_RESET_ENVELOPE = {
    "source": "azure_entra",
    "activity": "Reset user password",
    "actor": "Microsoft password reset service",
    "actor_app": "Microsoft password reset service",
    "initiator_type": "app",
    "target_user": "user-a@example.com",
}


def test_an_administrator_reset_still_fires_the_admin_rule() -> None:
    rule = _shipped_rule("det-identity-210")

    assert matches(rule["match_when"], _match_namespace(ADMIN_RESET_ENVELOPE))
    assert rule["severity"] == "high"


def test_a_self_service_reset_does_not_fire_the_admin_rule() -> None:
    """The whole of issue #1718's sixth cause, in one assertion.

    Every SSPR in the tenant raised a high-severity "reset by an
    administrator" because the rule's only condition was the activity name.
    """
    rule = _shipped_rule("det-identity-210")

    assert not matches(rule["match_when"], _match_namespace(SELF_SERVICE_RESET_ENVELOPE))


def test_no_shipped_rule_rates_a_self_service_reset_high() -> None:
    """The issue's acceptance criterion, over the whole corpus.

    Scoping one rule is worth nothing if a sibling rates the same event high,
    so this asks the question of every rule rather than of `det-identity-210`.
    It deliberately does not require that *nothing* fires: a future
    low-severity SSPR-volume rule is a reasonable thing to ship, and rating an
    SSPR as an administrator's reset is not.
    """
    namespace = _match_namespace(SELF_SERVICE_RESET_ENVELOPE)
    loud = [r["id"] for r in _load_ruleset() if r["severity"] in ("high", "critical") and matches(r["match_when"], namespace)]

    assert loud == []


def test_two_devices_no_longer_correlate_into_one_incident() -> None:
    """Every device update used to correlate onto the Intune client.

    ``correlation_key`` picks its entity as src_ip → hostname → username, so
    with no hostname every device event in the tenant shared one entity and
    collapsed into a single incident whatever happened to which machine.
    """
    alert = _detection_alert(DEVICE_UPDATE_OCSF)
    other = _detection_alert(_ocsf(actor="Intune Compliance Client Prod", device_name="HOST-02"))

    assert "HOST-01" in alert.correlation_key()
    assert alert.correlation_key() != other.correlation_key()
