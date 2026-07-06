from app.federated.query import Indicator, UnifiedQuery
from app.federated.translators import to_kql


def test_kql_translator_aliases_user_name_for_signinlogs():
    q = UnifiedQuery(
        indicators=(
            Indicator(
                field="user.name",
                operator="eq",
                value="alice@example.com",
            ),
        ),
    )

    kql = to_kql(q, table="SigninLogs")

    assert "UserPrincipalName" in kql
    assert "user.name" not in kql


def test_kql_translator_aliases_securityincident_fields():
    q = UnifiedQuery(
        indicators=(
            Indicator(
                field="device.name",
                operator="eq",
                value="host01",
            ),
            Indicator(
                field="severity",
                operator="eq",
                value="High",
            ),
            Indicator(
                field="message",
                operator="contains",
                value="mimikatz",
            ),
        ),
    )

    kql = to_kql(q, table="SecurityIncident")

    assert "CompromisedEntity" in kql
    assert "Severity" in kql
    assert "AlertName" in kql

    assert "device.name" not in kql
    assert "severity" not in kql
    assert "message" not in kql


def test_kql_translator_unknown_fields_pass_through():
    q = UnifiedQuery(
        indicators=(
            Indicator(
                field="source.ip",
                operator="eq",
                value="10.0.0.5",
            ),
        ),
    )

    kql = to_kql(q, table="SigninLogs")

    assert "source.ip" in kql


def test_kql_translator_unknown_tables_pass_through():
    q = UnifiedQuery(
        indicators=(
            Indicator(
                field="user.name",
                operator="eq",
                value="alice",
            ),
        ),
    )

    kql = to_kql(q, table="SomeFutureTable")

    assert "user.name" in kql
