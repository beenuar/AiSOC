"""The archive destination cannot be a server-side request forgery vector.

GHSA-98q5-87mq-9979: `s3_endpoint` was shape-validated only, then bound
into ClickHouse's `s3()` table function — which issues the request from
the lake, outside the API's egress guard. A tenant admin could point the
archive at cloud metadata or internal HTTP services and read the
response-length oracle off the export error.

The remedy mirrors `destinations._guard_url`: resolve the host and
classify every address. Link-local (the metadata range), loopback,
reserved, multicast and unspecified addresses are refused always;
RFC1918/ULA private ranges are refused unless the operator deliberately
set `AISOC_ARCHIVE_ALLOW_PRIVATE_ENDPOINTS=1`, because an in-network
MinIO is this feature's most common legitimate destination and that is
an operator-level trust decision, not a tenant-level one.
"""

from __future__ import annotations

import socket
from unittest.mock import patch

import pytest
from app.services import lake_archive


def _addrinfo(ip: str):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]


def _validate(endpoint: str, *, allow_private: bool = False) -> None:
    lake_archive.validate_destination(endpoint, "legit-bucket", allow_private=allow_private)


class TestAddressClassification:
    def test_link_local_metadata_endpoint_is_refused_even_with_private_allowed(self):
        with patch.object(socket, "getaddrinfo", return_value=_addrinfo("169.254.169.254")):
            for allow in (False, True):
                with pytest.raises(lake_archive.ArchiveConfigError, match="disallowed address"):
                    _validate("http://metadata.internal", allow_private=allow)

    def test_literal_metadata_ip_is_refused(self):
        with pytest.raises(lake_archive.ArchiveConfigError, match="disallowed address"):
            _validate("http://169.254.169.254")

    def test_loopback_is_refused_even_with_private_allowed(self):
        for allow in (False, True):
            with pytest.raises(lake_archive.ArchiveConfigError, match="disallowed address"):
                _validate("http://127.0.0.1:9000", allow_private=allow)

    def test_private_range_is_refused_by_default_naming_the_env(self):
        with patch.object(socket, "getaddrinfo", return_value=_addrinfo("10.1.2.3")):
            with pytest.raises(
                lake_archive.ArchiveConfigError,
                match="AISOC_ARCHIVE_ALLOW_PRIVATE_ENDPOINTS",
            ):
                _validate("http://minio.internal:9000")

    def test_private_range_is_accepted_when_the_operator_allowed_it(self):
        with patch.object(socket, "getaddrinfo", return_value=_addrinfo("10.1.2.3")):
            _validate("http://minio.internal:9000", allow_private=True)

    def test_public_endpoint_passes_without_any_allowance(self):
        with patch.object(socket, "getaddrinfo", return_value=_addrinfo("52.216.0.1")):
            _validate("https://s3.us-east-1.amazonaws.com")

    def test_one_bad_record_among_good_ones_refuses(self):
        """A split-horizon name with any disallowed address is refused —
        ClickHouse's resolver choice is not ours to predict."""
        records = _addrinfo("52.216.0.1") + _addrinfo("169.254.169.254")
        with patch.object(socket, "getaddrinfo", return_value=records):
            with pytest.raises(lake_archive.ArchiveConfigError, match="disallowed address"):
                _validate("https://split.example.com")

    def test_unresolvable_host_is_refused_not_passed(self):
        def boom(*a, **k):
            raise socket.gaierror("no such host")

        with patch.object(socket, "getaddrinfo", side_effect=boom):
            with pytest.raises(lake_archive.ArchiveConfigError, match="cannot resolve"):
                _validate("https://does-not-exist.invalid")


class TestUseTimeChokepoint:
    def test_destination_from_row_applies_the_same_classification(self):
        """A stored row written before this fix is refused at use time."""
        row = {
            "s3_endpoint": "http://169.254.169.254",
            "s3_bucket": "meta-bucket",
            "s3_region": "us-east-1",
            "s3_access_key": "k",
            "s3_secret_key": "s",
        }
        with pytest.raises(lake_archive.ArchiveConfigError, match="disallowed address"):
            lake_archive.destination_from_policy(row)
