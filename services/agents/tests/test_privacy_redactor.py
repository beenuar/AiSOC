"""Tests for the evidence pseudonymizer (Phase 1.4).

Pure/offline: app.privacy.redactor is stdlib-only, so this imports directly.
Gated in the CI agents job.
"""

from __future__ import annotations

from app.privacy.redactor import Pseudonymizer, RedactionConfig, default_pseudonymizer

# Realistic mixed evidence: customer PII + public threat indicators.
GOLDEN = (
    "User ACME\\alice logged in from 10.0.0.5 to DC01.acme.local, "
    "opened C:\\Users\\alice\\secret.docx, emailed alice@acme.corp, "
    "then beaconed to evil-c2.example (8.8.8.8) using key AKIAIOSFODNN7EXAMPLE."
)

# Raw customer values that must NEVER survive redaction.
CUSTOMER_PII = [
    "ACME\\alice",
    "10.0.0.5",
    "DC01.acme.local",
    "C:\\Users\\alice\\secret.docx",
    "alice@acme.corp",
    "AKIAIOSFODNN7EXAMPLE",
]

# Public threat indicators that SHOULD survive (they are IOCs, not PII).
PUBLIC_IOCS = ["evil-c2.example", "8.8.8.8"]


def test_zero_raw_customer_pii_survives_redaction():
    p = default_pseudonymizer(tenant_id="t1")
    redacted = p.redact(GOLDEN)
    for pii in CUSTOMER_PII:
        assert pii not in redacted, f"raw PII leaked into outbound payload: {pii!r} in {redacted!r}"


def test_public_iocs_are_preserved_for_analysis():
    p = default_pseudonymizer()
    redacted = p.redact(GOLDEN)
    for ioc in PUBLIC_IOCS:
        assert ioc in redacted, f"public IOC was over-redacted: {ioc!r}"


def test_tokens_are_typed_and_present():
    p = default_pseudonymizer()
    redacted = p.redact(GOLDEN)
    assert "IP_1" in redacted  # internal IP
    assert any(t in redacted for t in ("EMAIL_1", "EMAIL_2"))
    assert any(t in redacted for t in ("PATH_1", "PATH_2"))
    assert any(t.startswith("SECRET_") for t in p.mapping)
    assert any(t.startswith("USER_") for t in p.mapping)


def test_rehydrate_round_trips():
    p = default_pseudonymizer()
    redacted = p.redact(GOLDEN)
    assert p.rehydrate(redacted) == GOLDEN


def test_tokens_are_stable_within_a_run():
    p = default_pseudonymizer()
    a = p.redact("host 10.0.0.5 and again 10.0.0.5")
    # Same original -> same token, both occurrences.
    assert a.count("IP_1") == 2


def test_public_ip_not_redacted_internal_ip_is():
    p = default_pseudonymizer()
    out = p.redact("internal 192.168.1.9 external 1.1.1.1")
    assert "192.168.1.9" not in out
    assert "1.1.1.1" in out


def test_structured_username_field_is_pseudonymized():
    p = default_pseudonymizer()
    out = p.redact_value({"username": "bob", "action": "login", "src_ip": "10.1.2.3"})
    assert out["username"].startswith("USER_")
    assert out["action"] == "login"
    assert out["src_ip"] != "10.1.2.3"  # internal IP redacted inside string value


def test_config_can_disable_a_category():
    # Disable emails + internal hostnames so the full address survives; IPs stay on.
    p = Pseudonymizer(config=RedactionConfig(redact_emails=False, redact_internal_hostnames=False))
    out = p.redact("mail alice@acme.corp from 10.0.0.5")
    assert "alice@acme.corp" in out  # emails off (and host off, so domain survives)
    assert "10.0.0.5" not in out  # ips still on


def test_mapping_is_per_instance():
    p1 = default_pseudonymizer()
    p2 = default_pseudonymizer()
    p1.redact("10.0.0.5")
    assert p1.mapping  # p1 learned a mapping
    assert not p2.mapping  # p2 is independent (per-run isolation)


def test_default_config_is_all_on():
    cfg = RedactionConfig()
    assert cfg.redact_internal_ips
    assert cfg.redact_emails
    assert cfg.redact_paths
    assert cfg.redact_secrets
    assert cfg.redact_internal_hostnames
    assert cfg.redact_usernames
