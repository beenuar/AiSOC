"""A DLP alert normalizes into one finding, whatever vendor raised it.

What was wrong
--------------
Three sources already deliver DLP alerts — Netskope's DLP alert feed, Purview
DLP and insider-risk alerts riding Defender's `alerts_v2`, and the M365 audit
trail's `DlpRuleMatch` events — and each arrived as its vendor shaped it,
readable only through `raw_event`. There was no normalized finding: nothing a
triage prompt, the data-handling strategy or a console panel could read that
says *policy, rule, data classes, file, channel, destination and its class,
what the DLP product itself did, who and on which device* in one vocabulary.

What this asserts
-----------------
* Each per-source profile maps **only fields the vendor documents** (the
  fixtures below are the vendors' own published shapes, cited) — an absent
  vendor field stays ``None``/empty, never invented. That is the phishing
  intake's rule, applied to DLP.
* The vendor's enforcement collapses onto one vocabulary:
  ``blocked | warned | allowed | audited`` — and an enforcement the vendor
  did not state stays ``None``.
* ``destination_class`` is derived only from explicit vendor facts
  (Netskope's ``managed_app``); when the vendor said nothing, it is ``None``
  — "unmanaged" is a claim, not a default.
* The dispatcher keys on the alert's source and answers ``None`` for a
  non-DLP alert — a finding is never synthesized from an alert that is not
  one.
* The route answers the finding, or an honest ``finding: null``.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.services import dlp_finding as svc

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")

# The vendor's own published DLP alert sample (docs.netskope.com, "Netskope
# Tenant Plugin" — GET /api/v2/events/dataexport/alerts/dlp), trimmed to the
# fields the profile reads plus bystanders proving selectivity.
NETSKOPE_DLP = {
    "alert_type": "DLP",
    "alert_name": "GDrive Customer metadata shared externally",
    "policy": "GDrive Customer metadata shared externally",
    "dlp_profile": "Customer PII",
    "dlp_rule": "SSN-and-account-pairs",
    "dlp_rule_severity": "High",
    "dlp_incident_id": 4711,
    "object": "Tenant Migration across MPs",
    "file_size": 196869,
    "file_type": "application/vnd.google-apps.document",
    "md5": "4bf7680195ecaed55e3edabb5d95ca01",
    "local_sha256": "edd7df8bb5a774a7531a389287a3bd71cf8e62197d93a205860003ed8339a4de",
    "app": "Google Drive",
    "appcategory": "Cloud Storage",
    "managed_app": "no",
    "action": "block",
    "exposure": "organisation_wide_link",
    "url": "https://drive.google.com/open?id=14WLYNjJ",
    "user": "j.doe@example.com",
    "device": "Mac Device",
    "ext_labels": [
        {"name": "encryption_level_11", "vendor": "pym"},
    ],
}

# Office 365 Management Activity API schema, "DLP schema" (DlpRuleMatch):
# PolicyDetails[].Rules[] with Actions, SharePointMetaData, EndpointMetaData
# whose EnforcementMode ladder the vendor defines as 1=audit, 2=warn (block
# with override), 3=warn and bypass, 4=block, 5=allow (audit without alerts).
M365_DLP_SHAREPOINT = {
    "Operation": "DlpRuleMatch",
    "Workload": "SharePoint",
    "UserId": "j.doe@example.com",
    "PolicyDetails": [
        {
            "PolicyId": "9d8c7f6e",
            "PolicyName": "Customer PII policy",
            "Rules": [
                {
                    "RuleId": "r-1",
                    "RuleName": "Block external PII shares",
                    "Severity": "High",
                    "Actions": ["BlockAccess"],
                    "ConditionsMatched": {
                        "SensitiveInformation": [
                            {"SensitiveInformationTypeName": "U.S. Social Security Number (SSN)"},
                            {"SensitiveInformationTypeName": "Credit Card Number"},
                        ]
                    },
                }
            ],
        }
    ],
    "SharePointMetaData": {
        "FileName": "customers-q4.xlsx",
        "FilePathUrl": "https://contoso.sharepoint.com/sites/finance/customers-q4.xlsx",
        "SiteCollectionUrl": "https://contoso.sharepoint.com/sites/finance",
        "FileOwner": "j.doe@example.com",
        "IsViewableByExternalUsers": True,
    },
}

M365_DLP_ENDPOINT = {
    "Operation": "DlpRuleMatch",
    "Workload": "Endpoint",
    "UserId": "j.doe@example.com",
    "PolicyDetails": [
        {
            "PolicyName": "Endpoint exfil policy",
            "Rules": [{"RuleName": "USB copy of source", "Actions": []}],
        }
    ],
    "EndpointMetaData": {
        "EnforcementMode": 2,
        "FileExtension": ".py",
        "FileType": "Source code",
        "DeviceName": "FIN-WS-07",
        "SensitiveInformation": [{"SensitiveInformationTypeName": "Source Code"}],
    },
}

# Microsoft Graph security/alerts_v2 with serviceSource
# microsoftDataLossPrevention; evidence[] shapes per the Graph alertEvidence
# vocabulary (fileEvidence/userEvidence/deviceEvidence).
DEFENDER_PURVIEW = {
    "serviceSource": "microsoftDataLossPrevention",
    "category": "dataLossPrevention",
    "title": "DLP policy (Customer PII policy) matched",
    "evidence": [
        {
            "@odata.type": "#microsoft.graph.security.fileEvidence",
            "fileDetails": {
                "fileName": "customers-q4.xlsx",
                "filePath": "https://contoso.sharepoint.com/sites/finance",
                "fileSize": 240128,
                "sha256": "ab" * 32,
            },
        },
        {
            "@odata.type": "#microsoft.graph.security.userEvidence",
            "userAccount": {"accountName": "j.doe", "userPrincipalName": "j.doe@example.com"},
        },
        {
            "@odata.type": "#microsoft.graph.security.deviceEvidence",
            "deviceDnsName": "fin-ws-07.example.com",
        },
    ],
}


class TestNetskopeProfile:
    def test_documented_fields_map_and_bystanders_stay_out(self) -> None:
        finding = svc.from_netskope(NETSKOPE_DLP)
        assert finding is not None
        assert finding.source == "netskope"
        assert finding.policy == "GDrive Customer metadata shared externally"
        assert finding.rule == "SSN-and-account-pairs"
        assert finding.file_name == "Tenant Migration across MPs"
        assert finding.file_size == 196869
        assert finding.file_hash == NETSKOPE_DLP["local_sha256"]
        assert finding.user == "j.doe@example.com"
        assert finding.device == "Mac Device"
        assert finding.channel == "Cloud Storage"
        assert finding.destination == "Google Drive"
        assert finding.enforcement == "blocked"
        assert "encryption_level_11" in finding.data_classes

    def test_managed_app_no_means_unmanaged_saas(self) -> None:
        finding = svc.from_netskope(NETSKOPE_DLP)
        assert finding is not None
        assert finding.destination_class == "unmanaged_saas"

    def test_managed_app_yes_means_corporate_tenant(self) -> None:
        raw = dict(NETSKOPE_DLP, managed_app="yes")
        finding = svc.from_netskope(raw)
        assert finding is not None
        assert finding.destination_class == "corporate_tenant"

    def test_absent_vendor_facts_stay_absent(self) -> None:
        raw = {"alert_type": "DLP", "action": "alert"}
        finding = svc.from_netskope(raw)
        assert finding is not None
        assert finding.policy is None
        assert finding.file_name is None
        assert finding.destination_class is None, "no managed_app fact => no class claim"
        assert finding.enforcement == "audited"
        assert finding.data_classes == ()

    def test_a_non_dlp_netskope_alert_is_not_a_finding(self) -> None:
        assert svc.from_netskope({"alert_type": "Malware", "action": "block"}) is None


class TestM365Profile:
    def test_sharepoint_rule_match_maps_the_schema_fields(self) -> None:
        finding = svc.from_m365_audit(M365_DLP_SHAREPOINT)
        assert finding is not None
        assert finding.policy == "Customer PII policy"
        assert finding.rule == "Block external PII shares"
        assert finding.enforcement == "blocked"  # Actions: BlockAccess
        assert finding.file_name == "customers-q4.xlsx"
        assert finding.channel == "SharePoint"
        assert finding.destination == "https://contoso.sharepoint.com/sites/finance"
        assert set(finding.data_classes) == {
            "U.S. Social Security Number (SSN)",
            "Credit Card Number",
        }
        assert finding.user == "j.doe@example.com"

    def test_endpoint_enforcement_mode_ladder(self) -> None:
        # The vendor defines 1=audit, 2=warn(block with override),
        # 3=warn and bypass, 4=block, 5=allow(audit without alerts).
        finding = svc.from_m365_audit(M365_DLP_ENDPOINT)
        assert finding is not None
        assert finding.enforcement == "warned"
        assert finding.device == "FIN-WS-07"
        assert finding.channel == "Endpoint"
        assert "Source Code" in finding.data_classes

    def test_non_dlp_operations_are_not_findings(self) -> None:
        assert svc.from_m365_audit({"Operation": "FileAccessed", "Workload": "SharePoint"}) is None


class TestDefenderProfile:
    def test_purview_alert_maps_evidence(self) -> None:
        finding = svc.from_defender(DEFENDER_PURVIEW)
        assert finding is not None
        assert finding.file_name == "customers-q4.xlsx"
        assert finding.file_size == 240128
        assert finding.file_hash == "ab" * 32
        assert finding.user == "j.doe@example.com"
        assert finding.device == "fin-ws-07.example.com"
        assert finding.policy == "DLP policy (Customer PII policy) matched"
        # Purview's alert does not state the enforcement outcome: None, not
        # a guess.
        assert finding.enforcement is None

    def test_non_dlp_service_sources_are_not_findings(self) -> None:
        assert svc.from_defender({"serviceSource": "microsoftDefenderForEndpoint"}) is None


class TestDispatcher:
    @pytest.mark.parametrize(
        ("connector_type", "raw", "expect"),
        [
            ("netskope", NETSKOPE_DLP, True),
            ("m365_audit", M365_DLP_SHAREPOINT, True),
            ("azure_defender", DEFENDER_PURVIEW, True),
            ("crowdstrike", {"alert_type": "DLP"}, False),
        ],
    )
    def test_dispatch_keys_on_the_source(self, connector_type: str, raw: dict[str, Any], expect: bool) -> None:
        finding = svc.normalise(connector_type, raw)
        assert (finding is not None) is expect


@pytest.mark.asyncio
class TestRoute:
    async def test_the_route_answers_the_finding_or_an_honest_null(self) -> None:
        from app.api.v1.endpoints import alerts as alerts_ep

        row = MagicMock()
        row.connector_type = "netskope"
        row.raw_event = dict(NETSKOPE_DLP)
        result = MagicMock()
        result.fetchone.return_value = row
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)
        user = MagicMock()
        user.tenant_id = TENANT

        out = await alerts_ep.get_alert_dlp_finding(alert_id=uuid.uuid4(), db=db, current_user=user)
        assert out["finding"] is not None
        assert out["finding"]["enforcement"] == "blocked"

        row.connector_type = "crowdstrike"
        out2 = await alerts_ep.get_alert_dlp_finding(alert_id=uuid.uuid4(), db=db, current_user=user)
        assert out2["finding"] is None
