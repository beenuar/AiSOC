"""Tests for the Sigma → OCSF logsource mapper.

The mapper is the smaller of the two WS-B1 modules — pure functions,
no I/O, no DB. The tests below pin the *contract* the import service
relies on:

* known logsource buckets resolve to the expected OCSF class
* unknown / empty logsource always resolves to DETECTION_FINDING
* the precedence rules (product+category > product+service > category)
  hold so a malformed cloud rule doesn't fall through to an endpoint
  category by accident.
"""

from __future__ import annotations

import pytest
from app.services.detections.ocsf_mapping import (
    OcsfClassUid,
    map_logsource_to_ocsf,
)


class TestProductCategoryMapping:
    """Most Sigma rules carry product + category; this is the hot path."""

    def test_windows_process_creation_maps_to_process_activity(self) -> None:
        ref = map_logsource_to_ocsf({"product": "windows", "category": "process_creation"})
        assert ref.class_uid == OcsfClassUid.PROCESS_ACTIVITY
        assert ref.class_name == "Process Activity"

    def test_linux_file_event_maps_to_file_activity(self) -> None:
        ref = map_logsource_to_ocsf({"product": "linux", "category": "file_event"})
        assert ref.class_uid == OcsfClassUid.FILE_ACTIVITY

    def test_windows_dns_query_maps_to_dns_activity(self) -> None:
        ref = map_logsource_to_ocsf({"product": "windows", "category": "dns_query"})
        assert ref.class_uid == OcsfClassUid.DNS_ACTIVITY

    def test_case_insensitive(self) -> None:
        ref = map_logsource_to_ocsf({"product": "WINDOWS", "category": "PROCESS_CREATION"})
        assert ref.class_uid == OcsfClassUid.PROCESS_ACTIVITY


class TestProductServiceMapping:
    """Cloud / SaaS rules typically use product + service (no category)."""

    def test_aws_cloudtrail_maps_to_security_finding(self) -> None:
        ref = map_logsource_to_ocsf({"product": "aws", "service": "cloudtrail"})
        assert ref.class_uid == OcsfClassUid.SECURITY_FINDING

    def test_azure_signinlogs_maps_to_authentication(self) -> None:
        ref = map_logsource_to_ocsf({"product": "azure", "service": "signinlogs"})
        assert ref.class_uid == OcsfClassUid.AUTHENTICATION

    def test_okta_maps_to_authentication(self) -> None:
        ref = map_logsource_to_ocsf({"product": "okta", "service": "okta"})
        assert ref.class_uid == OcsfClassUid.AUTHENTICATION

    def test_windows_security_maps_to_authentication(self) -> None:
        # 4624/4625/4672 are auth events — important they don't fall
        # through to PROCESS_ACTIVITY by accident.
        ref = map_logsource_to_ocsf({"product": "windows", "service": "security"})
        assert ref.class_uid == OcsfClassUid.AUTHENTICATION


class TestCategoryFallback:
    """When product is missing but category is descriptive enough."""

    def test_proxy_maps_to_http_activity(self) -> None:
        ref = map_logsource_to_ocsf({"category": "proxy"})
        assert ref.class_uid == OcsfClassUid.HTTP_ACTIVITY

    def test_authentication_maps_to_authentication(self) -> None:
        ref = map_logsource_to_ocsf({"category": "authentication"})
        assert ref.class_uid == OcsfClassUid.AUTHENTICATION


class TestPrecedence:
    """Product+category beats product+service beats category alone."""

    def test_product_category_wins_over_service(self) -> None:
        # product+category=PROCESS_ACTIVITY; product+service=AUTHENTICATION
        # The (product, category) lookup should win.
        ref = map_logsource_to_ocsf({"product": "windows", "category": "process_creation", "service": "security"})
        assert ref.class_uid == OcsfClassUid.PROCESS_ACTIVITY


class TestFallback:
    @pytest.mark.parametrize("logsource", [None, {}, {"product": "weirdvendor"}])
    def test_unknown_logsource_falls_back_to_detection_finding(self, logsource: dict | None) -> None:
        ref = map_logsource_to_ocsf(logsource)
        assert ref.class_uid == OcsfClassUid.DETECTION_FINDING
        assert ref.class_name == "Detection Finding"

    def test_non_dict_input_does_not_raise(self) -> None:
        # Sigma in the wild has produced strings here. We must not
        # crash an entire bulk import on one malformed rule.
        assert map_logsource_to_ocsf("garbage").class_uid == OcsfClassUid.DETECTION_FINDING  # type: ignore[arg-type]


class TestSerialisation:
    def test_to_dict_shape(self) -> None:
        ref = map_logsource_to_ocsf({"product": "windows", "category": "process_creation"})
        d = ref.to_dict()
        assert set(d.keys()) == {"class_uid", "class_name", "category_uid", "category_name"}
        assert d["class_uid"] == OcsfClassUid.PROCESS_ACTIVITY
